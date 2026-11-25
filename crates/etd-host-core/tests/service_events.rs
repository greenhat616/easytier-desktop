mod common;
use common::*;
use etd_contract::{v1::*, *};
use etd_host_core::{api::HostEvent, stub::host_service_server::HostService};
use futures_util::StreamExt;
#[tokio::test]
async fn resume_contiguous_events_and_wrong_stream_resync() {
    let f = Fixture::new().await;
    let cursor = f
        .service
        .snapshot(request(SnapshotRequest {}, Role::Viewer))
        .await
        .unwrap()
        .into_inner()
        .cursor
        .unwrap();
    let mut stream = f
        .service
        .subscribe(request(
            SubscribeRequest {
                after: Some(cursor.clone()),
            },
            Role::Viewer,
        ))
        .await
        .unwrap()
        .into_inner();
    for seq in 1..=3 {
        f.port
            .events
            .send(HostEvent {
                seq,
                at_unix_ms: 0,
                payload: event::Payload::Notice(Notice::default()),
            })
            .unwrap();
    }
    let first = stream.next().await.unwrap().unwrap().cursor.unwrap();
    assert_eq!(first.seq, 1);
    drop(stream);
    let mut resumed = f
        .service
        .subscribe(request(
            SubscribeRequest { after: Some(first) },
            Role::Viewer,
        ))
        .await
        .unwrap()
        .into_inner();
    for seq in 2..=3 {
        assert_eq!(
            resumed.next().await.unwrap().unwrap().cursor.unwrap().seq,
            seq
        );
    }
    let wrong = EventCursor {
        stream_id: "old-run".into(),
        seq: 0,
    };
    let mut stream = f
        .service
        .subscribe(request(
            SubscribeRequest { after: Some(wrong) },
            Role::Viewer,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        stream.next().await.unwrap().unwrap().payload,
        Some(event::Payload::ResyncRequired(_))
    ));
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn retained_cursor_gap_resyncs_and_secret_is_redacted() {
    let f = Fixture::new().await;
    let cursor = f
        .service
        .snapshot(request(SnapshotRequest {}, Role::Viewer))
        .await
        .unwrap()
        .into_inner()
        .cursor
        .unwrap();
    let mut stream = f
        .service
        .subscribe(request(
            SubscribeRequest {
                after: Some(cursor.clone()),
            },
            Role::Viewer,
        ))
        .await
        .unwrap()
        .into_inner();
    let desired = DesiredInstance {
        instance_id: INSTANCE.into(),
        desired: Desired::Stopped as i32,
        spec: Some(NetworkSpec {
            network_secret: Some("test-only".into()),
            ..Default::default()
        }),
    };
    f.port
        .events
        .send(HostEvent {
            seq: 1,
            at_unix_ms: 0,
            payload: event::Payload::DesiredChanged(DesiredChanged {
                revision: 2,
                instance: Some(desired),
                ..Default::default()
            }),
        })
        .unwrap();
    let event = stream.next().await.unwrap().unwrap();
    let Some(event::Payload::DesiredChanged(change)) = event.payload else {
        panic!("expected desired event")
    };
    let spec = change.instance.unwrap().spec.unwrap();
    assert!(spec.network_secret.is_none());
    assert!(spec.network_secret_set);
    f.port
        .events
        .send(HostEvent {
            seq: 3,
            at_unix_ms: 0,
            payload: event::Payload::Notice(Notice::default()),
        })
        .unwrap();
    assert!(matches!(
        stream.next().await.unwrap().unwrap().payload,
        Some(event::Payload::ResyncRequired(_))
    ));
}
