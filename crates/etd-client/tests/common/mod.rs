//! Shared helpers of the client tests.
#![allow(dead_code)] // each test binary uses a different subset

use etd_client::{
    CallError, ConnectionState, HostClient,
    grpc::{ClientOptions, GrpcHostClient},
};
use etd_contract::{
    Desired, Event, InstanceId, NetworkSpec, QueryKind, RequestId,
    v1::{
        ApplyRequest, LeaseRelease, MutationHeader, PurgeAllDataRequest, RemoveInstanceRequest,
        ResolveCandidatesRequest, RetryReclaimRequest, RetryStartRequest, SelectCoreRequest,
        SetAllowListRequest, SetDesiredRequest, StreamLogsRequest,
    },
};
use etd_testkit::scripted_server::ScriptedHost;
use futures_util::{StreamExt, stream::BoxStream};
use std::{future::Future, time::Duration};

/// Generous: only a hung test reaches it.
const DEADLINE: Duration = Duration::from_secs(20);

pub fn options() -> ClientOptions {
    ClientOptions {
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(40),
        stable_after: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
        recovery_timeout: Duration::from_secs(5),
        ..Default::default()
    }
}

pub fn client_with(host: &ScriptedHost, options: ClientOptions) -> GrpcHostClient {
    GrpcHostClient::new(host.connector(), ScriptedHost::endpoint(), options)
}

pub async fn connected(host: &ScriptedHost) -> GrpcHostClient {
    let client = client_with(host, options());
    wait_connected(&client).await;
    client
}

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("test deadline")
}

pub async fn wait_state(
    client: &GrpcHostClient,
    wanted: impl FnMut(&ConnectionState) -> bool,
) -> ConnectionState {
    let mut state = client.connection();
    within(state.wait_for(wanted))
        .await
        .expect("client is alive")
        .clone()
}

pub async fn wait_connected(client: &GrpcHostClient) {
    wait_state(client, |state| {
        matches!(state, ConnectionState::Connected(_))
    })
    .await;
}

pub async fn until(mut condition: impl FnMut() -> bool) {
    within(async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
}

pub type Events = BoxStream<'static, Result<Event, CallError>>;

pub async fn next<T>(stream: &mut BoxStream<'static, T>) -> Option<T> {
    within(stream.next()).await
}

pub async fn next_seq(events: &mut Events) -> u64 {
    let event = next(events)
        .await
        .expect("stream is open")
        .expect("an event");
    event.cursor.expect("a cursor").seq
}

pub fn header(request_id: &str, expected_revision: u64) -> Option<MutationHeader> {
    Some(MutationHeader {
        request_id: request_id.into(),
        expected_revision,
    })
}

pub fn apply(request_id: &str, expected_revision: u64) -> ApplyRequest {
    ApplyRequest {
        header: header(request_id, expected_revision),
        instance_id: "00000000-0000-4000-8000-000000000001".into(),
        spec: Some(NetworkSpec::default()),
        desired: Desired::Running as i32,
    }
}

/// The nine mutations that answer with a receipt.
pub const MUTATIONS: [&str; 9] = [
    "Apply",
    "SetDesired",
    "RemoveInstance",
    "RetryReclaim",
    "RetryStart",
    "ResolveCandidates",
    "SetAllowList",
    "SelectCore",
    "PurgeAllData",
];

pub async fn mutate(
    client: &GrpcHostClient,
    method: &str,
    id: &str,
    revision: u64,
) -> Result<etd_contract::Receipt, CallError> {
    let header = header(id, revision);
    match method {
        "Apply" => client.apply(apply(id, revision)).await,
        "SetDesired" => {
            client
                .set_desired(SetDesiredRequest {
                    header,
                    ..Default::default()
                })
                .await
        }
        "RemoveInstance" => {
            client
                .remove_instance(RemoveInstanceRequest {
                    header,
                    ..Default::default()
                })
                .await
        }
        "RetryReclaim" => {
            client
                .retry_reclaim(RetryReclaimRequest {
                    header,
                    ..Default::default()
                })
                .await
        }
        "RetryStart" => {
            client
                .retry_start(RetryStartRequest {
                    header,
                    ..Default::default()
                })
                .await
        }
        "ResolveCandidates" => {
            client
                .resolve_candidates(ResolveCandidatesRequest {
                    header,
                    ..Default::default()
                })
                .await
        }
        "SetAllowList" => {
            client
                .set_allow_list(SetAllowListRequest {
                    header,
                    ..Default::default()
                })
                .await
        }
        "SelectCore" => {
            client
                .select_core(SelectCoreRequest {
                    header,
                    ..Default::default()
                })
                .await
        }
        "PurgeAllData" => {
            client
                .purge_all_data(PurgeAllDataRequest {
                    header,
                    confirm: true,
                })
                .await
        }
        other => panic!("not a mutation: {other}"),
    }
}

/// Every RPC the client can issue after the handshake.
pub const CALLS: [&str; 19] = [
    "Snapshot",
    "Subscribe",
    "Apply",
    "SetDesired",
    "RemoveInstance",
    "GetReceipt",
    "QueryNodes",
    "QueryRoutes",
    "QueryTraffic",
    "StreamLogs",
    "GetReclaimReport",
    "RetryReclaim",
    "RetryStart",
    "ResolveCandidates",
    "ReleaseLease",
    "GetAllowList",
    "SetAllowList",
    "ListCores",
    "SelectCore",
];

/// Issues `name` (one of [`CALLS`] or `"PurgeAllData"`) once.
pub async fn call(
    client: &GrpcHostClient,
    host: &ScriptedHost,
    name: &str,
) -> Result<(), CallError> {
    let id = || InstanceId("instance".into());
    match name {
        "Snapshot" => client.snapshot().await.map(drop),
        "Subscribe" => {
            // From a cursor, so that no Snapshot is needed to place it.
            let seq = host.emit_notice();
            let mut events = client.subscribe(Some(etd_contract::EventCursor {
                stream_id: client.negotiated().expect("negotiated").stream_id,
                seq: seq - 1,
            }));
            next(&mut events).await.expect("an item").map(drop)
        }
        "GetReceipt" => client.receipt(RequestId("unknown".into())).await.map(drop),
        "QueryNodes" => client.query(id(), QueryKind::Nodes).await.map(drop),
        "QueryRoutes" => client.query(id(), QueryKind::Routes).await.map(drop),
        "QueryTraffic" => client.query(id(), QueryKind::Traffic).await.map(drop),
        "StreamLogs" => {
            let mut lines = client.logs(StreamLogsRequest::default());
            match next(&mut lines).await {
                Some(line) => line.map(drop),
                None => Ok(()),
            }
        }
        "GetReclaimReport" => client.reclaim_report().await.map(drop),
        "ReleaseLease" => client
            .release_lease(LeaseRelease::StopInstances)
            .await
            .map(drop),
        "GetAllowList" => client.allow_list().await.map(drop),
        "ListCores" => client.cores().await.map(drop),
        mutation => {
            let request_id = format!("{mutation}-{}", host.revision());
            mutate(client, mutation, &request_id, host.revision())
                .await
                .map(drop)
        }
    }
}
