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
}
impl AllowListSink for Sink {
    fn apply(&self, entries: &[AllowEntry]) -> io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected ACL failure"));
        }
        *self.entries.lock().unwrap() = entries.to_vec();
        Ok(())
    }
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
