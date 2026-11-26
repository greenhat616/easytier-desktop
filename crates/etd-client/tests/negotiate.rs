//! Handshake, "upgrade the service", capability gating, per-call version
//! metadata and typed rejections.
mod common;

use common::*;
use etd_client::{CallError, ConnectionState, HostClient};
use etd_contract::{
    ErrorCode, ErrorDetail, HostMode, Role, VERSION_MAJOR, capability, version_metadata_value,
};
use etd_testkit::scripted_server::{ScriptedHost, rejection};
use tonic::{Code, Status};

fn version_mismatch(major: u32, minor: u32) -> Status {
    rejection(
        Code::FailedPrecondition,
        ErrorDetail {
            code: ErrorCode::VersionMismatch as i32,
            host_major: major,
            host_minor: minor,
            ..Default::default()
        },
    )
}

fn upgrade_required(state: &ConnectionState) -> bool {
    matches!(state, ConnectionState::UpgradeRequired { .. })
}

async fn assert_upgrade_flow(host: &ScriptedHost, client: &etd_client::grpc::GrpcHostClient) {
    let state = wait_state(client, upgrade_required).await;
    assert_eq!(
        state,
        ConnectionState::UpgradeRequired {
            host_major: 2,
            host_minor: 3
        }
    );
    assert!(client.negotiated().is_none());
    assert!(matches!(
        client.snapshot().await,
        Err(CallError::VersionMismatch {
            host_major: 2,
            host_minor: 3
        })
    ));
    let mut events = client.subscribe(None);
    assert!(matches!(
        next(&mut events).await,
        Some(Err(CallError::VersionMismatch { .. }))
    ));
    assert!(next(&mut events).await.is_none());
    assert!(
        host.calls().iter().all(|call| call.method == "Handshake"),
        "nothing but handshakes may reach a host of another major version"
    );
}

#[tokio::test]
async fn a_welcome_with_another_major_requires_a_service_upgrade() {
    let host = ScriptedHost::start();
    host.edit_welcome(|welcome| (welcome.major, welcome.minor) = (2, 3));
    let client = client_with(&host, options());
    assert_upgrade_flow(&host, &client).await;

    // The client keeps trying, so upgrading the service is enough.
    host.edit_welcome(|welcome| (welcome.major, welcome.minor) = (VERSION_MAJOR, 0));
    wait_connected(&client).await;
    client.snapshot().await.unwrap();
}

#[tokio::test]
async fn a_version_mismatch_rejection_requires_a_service_upgrade() {
    let host = ScriptedHost::start();
    for _ in 0..1000 {
        host.fail_next("Handshake", version_mismatch(2, 3));
    }
    let client = client_with(&host, options());
    assert_upgrade_flow(&host, &client).await;
}

#[tokio::test]
async fn features_follow_the_capability_list_and_not_the_version() {
    for minor in [0, 99] {
        let host = ScriptedHost::start();
        host.edit_welcome(|welcome| welcome.minor = minor);
        host.set_capabilities(&["something.from.the.future"]);
        let client = connected(&host).await;
        for name in CALLS.into_iter().chain(["PurgeAllData"]) {
            if name == "Subscribe" {
                let mut events = client.subscribe(None);
                assert!(matches!(
                    next(&mut events).await,
                    Some(Err(CallError::Unsupported(_)))
                ));
                assert!(next(&mut events).await.is_none());
                continue;
            }
            let result = call(&client, &host, name).await;
            assert!(
                matches!(result, Err(CallError::Unsupported(_))),
                "{name} with minor {minor}: {result:?}"
            );
        }
        assert!(host.calls().iter().all(|call| call.method == "Handshake"));
    }
}

#[tokio::test]
async fn each_capability_opens_exactly_its_own_calls() {
    let table: [(&str, &[&str]); 11] = [
        (
            capability::INSTANCES,
            &[
                "Snapshot",
                "Subscribe",
                "Apply",
                "SetDesired",
                "RemoveInstance",
                "GetReceipt",
                "RetryStart",
            ],
        ),
        (capability::QUERY_NODES, &["QueryNodes"]),
        (capability::QUERY_ROUTES, &["QueryRoutes"]),
        (capability::QUERY_TRAFFIC, &["QueryTraffic"]),
        (capability::LOGS, &["StreamLogs"]),
        (capability::RECLAIM, &["GetReclaimReport", "RetryReclaim"]),
        (capability::RECLAIM_CANDIDATES, &["ResolveCandidates"]),
        (capability::LEASE, &["ReleaseLease"]),
        (
            capability::ADMIN_ALLOW_LIST,
            &["GetAllowList", "SetAllowList"],
        ),
        (capability::ADMIN_CORES, &["ListCores", "SelectCore"]),
        (capability::ADMIN_PURGE, &["PurgeAllData"]),
    ];
    for (name, open) in table {
        let host = ScriptedHost::start();
        host.set_capabilities(&[name]);
        let client = connected(&host).await;
        for rpc in CALLS.into_iter().chain(["PurgeAllData"]) {
            let result = call(&client, &host, rpc).await;
            if open.contains(&rpc) {
                assert!(result.is_ok(), "{rpc} with {name}: {result:?}");
            } else {
                assert!(
                    matches!(result, Err(CallError::Unsupported(_))),
                    "{rpc} with only {name}: {result:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn capabilities_are_renegotiated_after_a_reconnect() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    call(&client, &host, "QueryNodes").await.unwrap();

    host.set_capabilities(&[capability::INSTANCES]);
    host.edit_welcome(|welcome| {
        welcome.role = Role::Viewer as i32;
        welcome.host_mode = HostMode::User as i32;
    });
    host.disconnect();
    wait_state(
        &client,
        |state| matches!(state, ConnectionState::Connected(n) if n.role == Role::Viewer),
    )
    .await;

    let negotiated = client.negotiated().unwrap();
    assert_eq!(negotiated.host_mode, HostMode::User);
    assert!(matches!(
        call(&client, &host, "QueryNodes").await,
        Err(CallError::Unsupported(name)) if name == capability::QUERY_NODES
    ));
}

#[tokio::test]
async fn every_call_carries_the_version_metadata_once() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    for name in CALLS.into_iter().chain(["PurgeAllData"]) {
        call(&client, &host, name)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    let calls = host.calls();
    // The handshake, one request per entry, and the purge.
    assert_eq!(calls.len(), 1 + CALLS.len() + 1);
    for call in calls {
        assert_eq!(
            call.version_metadata,
            [version_metadata_value()],
            "{}",
            call.method
        );
    }
}

#[tokio::test]
async fn host_rejections_become_typed_errors() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    let cases = [
        (ErrorCode::PermissionDenied, Code::PermissionDenied),
        (ErrorCode::ElevationRequired, Code::PermissionDenied),
        (ErrorCode::RevisionConflict, Code::Aborted),
        (ErrorCode::RequestIdReused, Code::InvalidArgument),
        (ErrorCode::HostNotServing, Code::FailedPrecondition),
        (ErrorCode::LedgerUnavailable, Code::Unavailable),
    ];
    for (code, status) in cases {
        host.fail_next(
            "Apply",
            rejection(
                status,
                ErrorDetail {
                    code: code as i32,
                    message: "no".into(),
                    current_revision: 7,
                    ..Default::default()
                },
            ),
        );
        let error = client.apply(apply("a", 0)).await.unwrap_err();
        let matched = match code {
            ErrorCode::PermissionDenied => matches!(
                error,
                CallError::PermissionDenied {
                    required: Role::Control
                }
            ),
            ErrorCode::ElevationRequired => matches!(error, CallError::ElevationRequired),
            ErrorCode::RevisionConflict => matches!(error, CallError::Conflict { current: 7 }),
            ErrorCode::RequestIdReused => matches!(error, CallError::RequestIdReused),
            _ => matches!(&error, CallError::Rejected(detail) if detail.code() == code),
        };
        assert!(matched, "{code:?}: {error:?}");
    }
    // A rejection is an answer: nothing to recover, the connection stays.
    assert_eq!(host.count("GetReceipt"), 0);
    assert_eq!(host.dials().len(), 1);
}

#[tokio::test]
async fn an_impostor_is_reported_and_never_spoken_to() {
    let host = ScriptedHost::start();
    host.set_impostor(true);
    let client = client_with(&host, options());
    wait_state(&client, |state| {
        matches!(state, ConnectionState::Reconnecting { .. })
    })
    .await;
    assert!(matches!(
        client.snapshot().await,
        Err(CallError::HostNotVerified(_))
    ));
    assert!(host.calls().is_empty());

    host.set_impostor(false);
    wait_connected(&client).await;
}
