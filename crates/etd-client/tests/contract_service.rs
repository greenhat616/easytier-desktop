//! The client against the real contract service of `etd-host-core`: the
//! scripted host must not be the only thing it agrees with.
mod common;

use common::*;
use etd_client::{CallError, HostClient, grpc::GrpcHostClient};
use etd_contract::{
    ErrorCode, EventCursor, RequestId, Role, capability,
    v1::{PurgeAllDataRequest, RemoveInstanceRequest, SetAllowListRequest, event},
};
use etd_testkit::scripted_server::{ContractHost, ScriptedHost, all_capabilities};

async fn start() -> (ContractHost, GrpcHostClient) {
    let host = ContractHost::start(all_capabilities()).await;
    let client = GrpcHostClient::new(host.connector(), ScriptedHost::endpoint(), options());
    wait_connected(&client).await;
    (host, client)
}

fn purge(id: &str, expected_revision: u64, confirm: bool) -> PurgeAllDataRequest {
    PurgeAllDataRequest {
        header: header(id, expected_revision),
        confirm,
    }
}

#[tokio::test]
async fn handshake_and_capabilities_match_the_host_form() {
    let (_host, client) = start().await;
    let negotiated = client.negotiated().unwrap();
    assert_eq!(negotiated.role, Role::Admin);
    // The user host withholds these two.
    assert!(!negotiated.has_capability(capability::TUN));
    assert!(matches!(
        client.set_allow_list(SetAllowListRequest::default()).await,
        Err(CallError::Unsupported(_))
    ));
    client.snapshot().await.unwrap();
}

#[tokio::test]
async fn mutations_and_receipts_follow_the_host_semantics() {
    let (_host, client) = start().await;
    let revision = client.snapshot().await.unwrap().revision;
    assert_eq!(
        client.receipt(RequestId("unknown".into())).await.unwrap(),
        None
    );

    let receipt = client
        .purge_all_data(purge("request-1", revision, true))
        .await
        .unwrap();
    assert_eq!(
        client.receipt(RequestId("request-1".into())).await.unwrap(),
        Some(receipt.clone())
    );
    assert_eq!(
        client
            .purge_all_data(purge("request-1", revision, true))
            .await
            .unwrap(),
        receipt
    );
    assert!(matches!(
        client
            .purge_all_data(purge("request-1", revision + 1, true))
            .await,
        Err(CallError::RequestIdReused)
    ));
    assert!(matches!(
        client
            .purge_all_data(purge("request-2", revision, true))
            .await,
        Err(CallError::Conflict { current }) if current == receipt.revision
    ));
    assert!(matches!(
        client
            .remove_instance(RemoveInstanceRequest {
                header: header("request-3", receipt.revision),
                instance_id: "00000000-0000-4000-8000-000000000001".into(),
            })
            .await,
        Err(CallError::Rejected(detail)) if detail.code() == ErrorCode::UnknownInstance
    ));
}

#[tokio::test]
async fn the_event_stream_resumes_and_asks_for_a_resync() {
    let (host, client) = start().await;
    let after = client.snapshot().await.unwrap().cursor.unwrap();
    let mut events = client.subscribe(Some(after.clone()));
    host.emit(1);
    host.emit(2);
    assert_eq!(next_seq(&mut events).await, 1);
    assert_eq!(next_seq(&mut events).await, 2);

    host.disconnect();
    host.emit(3);
    assert_eq!(next_seq(&mut events).await, 3);

    // The journal of this host keeps four events.
    for seq in 4..=9 {
        host.emit(seq);
    }
    // The journal fills asynchronously: wait until event 9 is in it.
    let mut caught_up = client.subscribe(Some(EventCursor {
        stream_id: after.stream_id.clone(),
        seq: 8,
    }));
    assert_eq!(next_seq(&mut caught_up).await, 9);
    for stale in [
        after,
        EventCursor {
            stream_id: "another run".into(),
            seq: 9,
        },
    ] {
        let mut events = client.subscribe(Some(stale));
        let event = next(&mut events).await.unwrap().unwrap();
        assert!(
            matches!(event.payload, Some(event::Payload::ResyncRequired(_))),
            "{event:?}"
        );
        assert!(next(&mut events).await.is_none());
    }
}
