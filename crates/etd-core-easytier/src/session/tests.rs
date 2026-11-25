//! Exercise upstream's in-process ring tunnel with generated RPC stubs.
use super::*;
use easytier_core::{
    rpc::bidirect::BidirectRpcManager,
    tunnel::{Tunnel, ring::create_ring_tunnel_pair},
};
use etd_contract::v1::query_response::Result as QueryResult;
use etd_core_api::CoreEventKind;
use std::sync::{Arc, Mutex as StdMutex};
use url::Url;
#[path = "../../tests/session_support/mod.rs"]
mod support;
struct Ring(StdMutex<Option<Box<dyn Tunnel>>>);
#[async_trait::async_trait]
impl TunnelDialer for Ring {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow::anyhow!("ring closed"))
    }
    fn remote_url(&self) -> Url {
        "ring://stub".parse().unwrap()
    }
}

fn fixture(
    ids: Vec<Uuid>,
) -> (
    BidirectRpcManager,
    Ring,
    Arc<StdMutex<NetworkInstanceRunningInfo>>,
) {
    let (client, server) = create_ring_tunnel_pair();
    let (manager, info) = support::server(ids, server);
    (manager, Ring(StdMutex::new(Some(client))), info)
}

#[tokio::test]
async fn ring_session_full_roundtrip() {
    let (_server, dialer, snapshot) = fixture(vec![Uuid::from_u128(1)]);
    let session = Session::connect(dialer).await.unwrap();
    let ready = session
        .wait_ready(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(ready.interface_name.as_deref(), Some("utun7"));
    assert_eq!(ready.ipv4_cidr.as_deref(), Some("10.10.10.1/24"));
    assert_eq!(ready.peer_id, Some(1));
    let QueryResult::Nodes(nodes) = session
        .query(QueryKind::Nodes)
        .await
        .unwrap()
        .result
        .unwrap()
    else {
        panic!("expected nodes");
    };
    assert_eq!(nodes.nodes.len(), 2);
    assert!(nodes.nodes[0].is_self);
    assert_eq!(nodes.nodes[1].tunnels, ["tcp"]);
    let QueryResult::Routes(routes) = session
        .query(QueryKind::Routes)
        .await
        .unwrap()
        .result
        .unwrap()
    else {
        panic!("expected routes");
    };
    assert_eq!(routes.routes[0].path_latency_us, 3000);
    let QueryResult::Traffic(stats) = session
        .query(QueryKind::Traffic)
        .await
        .unwrap()
        .result
        .unwrap()
    else {
        panic!("expected traffic");
    };
    assert_eq!(
        (
            stats.rx_bytes,
            stats.tx_bytes,
            stats.rx_packets,
            stats.tx_packets
        ),
        (10, 20, 1, 2)
    );
    assert_eq!(stats.peers[0].peer_id, 2);
    let events = session.poll_events(None).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].kind, CoreEventKind::PeerAdded { peer_id: 2 });
    assert_eq!(
        events[1]
            .at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1795643522
    );
    let cursor = events[1].cursor;
    assert!(session.poll_events(Some(cursor)).await.unwrap().is_empty());
    snapshot
        .lock()
        .unwrap()
        .events
        .insert(0, r#"{"event":{"PeerRemoved":2}}"#.into());
    let next = session.poll_events(Some(cursor)).await.unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].kind, CoreEventKind::PeerRemoved { peer_id: 2 });
    assert!(next[0].cursor > cursor);
}

#[tokio::test]
async fn refuses_ambiguous_instances_and_times_out_if_not_ready() {
    let (_server, dialer, _snapshot) = fixture(vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
    assert!(matches!(
        Session::connect(dialer).await,
        Err(CoreError::Rpc(_))
    ));
    let (_server, dialer, snapshot) = fixture(vec![Uuid::from_u128(1)]);
    snapshot.lock().unwrap().running = false;
    let session = Session::connect(dialer).await.unwrap();
    assert_eq!(
        session
            .wait_ready(Instant::now() + Duration::from_millis(150))
            .await,
        Err(CoreError::Timeout)
    );
}
