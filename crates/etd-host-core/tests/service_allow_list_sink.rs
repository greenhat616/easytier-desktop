mod common;

use common::*;
use etd_contract::v1::*;
use etd_host_core::{service::AllowListSink, stub::host_service_server::HostService};
use etd_sysfx::Ledger;
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Default)]
struct Sink {
    entries: Mutex<Vec<AllowEntry>>,
    fail: AtomicBool,
    reject: AtomicBool,
}
impl AllowListSink for Sink {
    fn validate(&self, _: &[AllowEntry]) -> io::Result<()> {
        if self.reject.load(Ordering::SeqCst) {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid policy",
            ))
        } else {
            Ok(())
        }
    }
    fn apply(&self, entries: &[AllowEntry]) -> io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected ACL failure"));
        }
        *self.entries.lock().unwrap() = entries.to_vec();
        Ok(())
    }
}

#[tokio::test]
async fn deterministic_acl_validation_failure_does_not_commit() {
    let sink = Arc::new(Sink::default());
    let f = Fixture::with_allow_list_sink(Some(sink.clone())).await;
    sink.reject.store(true, Ordering::SeqCst);
    assert!(
        f.service
            .set_allow_list(request(replacement(), Role::Admin))
            .await
            .is_err()
    );
    assert_eq!(f.ledger.desired().await.unwrap().0, 1);
    assert!(
        f.service
            .snapshot(request(SnapshotRequest {}, Role::Viewer))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn unavailable_native_adapter_rejects_new_start_before_commit() {
    let mut fixture = Fixture::new().await;
    fixture.service = fixture
        .service
        .with_start_blocker(Some("native adapters unavailable".into()));
    let response = fixture
        .service
        .apply(request(
            ApplyRequest {
                header: Some(MutationHeader {
                    request_id: "blocked-apply".into(),
                    expected_revision: 1,
                }),
                instance_id: INSTANCE.into(),
                spec: Some(NetworkSpec::default()),
                desired: Desired::Running as i32,
            },
            Role::Admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(code(response), ErrorCode::FeatureRejected);
    assert_eq!(fixture.ledger.desired().await.unwrap().0, 1);
    assert!(
        fixture
            .service
            .snapshot(request(SnapshotRequest {}, Role::Admin))
            .await
            .is_ok()
    );
}

fn replacement() -> SetAllowListRequest {
    SetAllowListRequest {
        header: Some(MutationHeader {
            request_id: "acl-change".into(),
            expected_revision: 1,
        }),
        entries: vec![entry(0, Role::Admin), entry(20, Role::Control)],
    }
}

#[tokio::test]
async fn acl_is_applied_before_the_receipt() {
    let sink = Arc::new(Sink::default());
    let f = Fixture::with_allow_list_sink(Some(sink.clone())).await;
    let body = replacement();
    f.service
        .set_allow_list(request(body.clone(), Role::Admin))
        .await
        .unwrap();
    assert_eq!(*sink.entries.lock().unwrap(), body.entries);
    assert_eq!(f.ledger.settings().await.unwrap().allow_list, body.entries);
    assert_eq!(
        code(
            f.service
                .snapshot(request(SnapshotRequest {}, Role::Viewer))
                .await
                .unwrap_err()
        ),
        ErrorCode::PermissionDenied
    );
}

#[tokio::test]
async fn acl_failure_denies_everyone_until_reload_reconciles() {
    let sink = Arc::new(Sink::default());
    let f = Fixture::with_allow_list_sink(Some(sink.clone())).await;
    sink.fail.store(true, Ordering::SeqCst);
    let body = replacement();
    let err = f
        .service
        .set_allow_list(request(body.clone(), Role::Admin))
        .await
        .unwrap_err();
    assert_eq!(code(err), ErrorCode::HostNotServing);
    assert_eq!(f.ledger.settings().await.unwrap().allow_list, body.entries);
    for role in [Role::Admin, Role::Control, Role::Viewer] {
        assert_eq!(
            code(
                f.service
                    .snapshot(request(SnapshotRequest {}, role))
                    .await
                    .unwrap_err()
            ),
            ErrorCode::PermissionDenied
        );
    }
    sink.fail.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if f.service
                .snapshot(request(SnapshotRequest {}, Role::Admin))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(*sink.entries.lock().unwrap(), body.entries);
    assert_eq!(
        code(
            f.service
                .snapshot(request(SnapshotRequest {}, Role::Viewer))
                .await
                .unwrap_err()
        ),
        ErrorCode::PermissionDenied
    );
    assert!(
        f.service
            .set_allow_list(request(body, Role::Admin))
            .await
            .is_ok()
    );
    assert_eq!(f.ledger.desired().await.unwrap().0, 2);
}
