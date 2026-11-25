use easytier_proto::{
    api::{
        instance::{PeerInfo, Route as WireRoute},
        manage::{MyNodeInfo, NetworkInstanceRunningInfo},
    },
    common::{Ipv4Inet, Ipv6Inet, NatType, StunInfo},
};
use etd_contract::{
    QueryKind, QueryResponse,
    v1::{
        Node, NodeList, PeerTraffic, Route, RouteList, TrafficStats,
        query_response::Result as QueryResult,
    },
};
use etd_core_api::{CoreError, CoreRuntimeInfo};
use std::collections::{BTreeMap, BTreeSet};

fn nonempty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

// Avoid upstream Display for inet messages: malformed prefix lengths would panic.
fn ipv4(ip: Option<Ipv4Inet>) -> Option<String> {
    let ip = ip?;
    (ip.network_length <= 32).then_some(())?;
    Some(format!("{}/{}", ip.address?, ip.network_length))
}
fn ipv6(ip: Option<Ipv6Inet>) -> Option<String> {
    let ip = ip?;
    (ip.network_length <= 128).then_some(())?;
    Some(format!("{}/{}", ip.address?, ip.network_length))
}
fn nat(stun: Option<&StunInfo>) -> String {
    stun.and_then(|s| NatType::try_from(s.udp_nat_type).ok())
        .map(|n| n.as_str_name().to_owned())
        .unwrap_or_default()
}
fn latency(ms: i32) -> u32 {
    u32::try_from(ms).unwrap_or_default().saturating_mul(1000)
}

pub(super) fn runtime(dev_name: String, node: MyNodeInfo) -> CoreRuntimeInfo {
    CoreRuntimeInfo {
        interface_name: nonempty(dev_name),
        ipv4_cidr: ipv4(node.virtual_ipv4),
        peer_id: Some(node.peer_id),
        hostname: nonempty(node.hostname),
        version: nonempty(node.version),
    }
}

fn route(r: &WireRoute) -> Route {
    Route {
        peer_id: r.peer_id,
        hostname: r.hostname.clone(),
        ipv4_cidr: ipv4(r.ipv4_addr).unwrap_or_default(),
        proxy_cidrs: r.proxy_cidrs.clone(),
        next_hop_peer_id: r.next_hop_peer_id,
        cost: u32::try_from(r.cost).unwrap_or_default(),
        path_latency_us: latency(r.path_latency),
    }
}

#[derive(Default)]
struct PeerStats {
    rx: u64,
    tx: u64,
    rx_packets: u64,
    tx_packets: u64,
    latency: Option<u32>,
    loss: Option<f64>,
    tunnels: BTreeSet<String>,
}

fn peer_stats(peer: &PeerInfo) -> PeerStats {
    let mut result = PeerStats::default();
    for conn in peer.conns.iter().filter(|c| !c.is_closed) {
        if let Some(stats) = &conn.stats {
            result.rx = result.rx.saturating_add(stats.rx_bytes);
            result.tx = result.tx.saturating_add(stats.tx_bytes);
            result.rx_packets = result.rx_packets.saturating_add(stats.rx_packets);
            result.tx_packets = result.tx_packets.saturating_add(stats.tx_packets);
            let latency = u32::try_from(stats.latency_us).unwrap_or(u32::MAX);
            result.latency = Some(result.latency.map_or(latency, |old| old.min(latency)));
        }
        if conn.loss_rate.is_finite() {
            let loss = f64::from(conn.loss_rate.clamp(0.0, 1.0));
            result.loss = Some(result.loss.map_or(loss, |old| old.min(loss)));
        }
        if let Some(tunnel) = &conn.tunnel
            && !tunnel.tunnel_type.is_empty()
        {
            result.tunnels.insert(tunnel.tunnel_type.clone());
        }
    }
    result
}

fn nodes(info: NetworkInstanceRunningInfo) -> NodeList {
    let mut nodes = BTreeMap::<u32, Node>::new();
    for r in info.routes {
        nodes.insert(
            r.peer_id,
            Node {
                peer_id: r.peer_id,
                hostname: r.hostname,
                ipv4_cidr: ipv4(r.ipv4_addr).unwrap_or_default(),
                ipv6_cidr: ipv6(r.ipv6_addr).unwrap_or_default(),
                version: r.version,
                nat_type: nat(r.stun_info.as_ref()),
                cost: u32::try_from(r.cost).unwrap_or_default(),
                latency_us: latency(r.path_latency),
                ..Default::default()
            },
        );
    }
    for p in info.peers {
        let stats = peer_stats(&p);
        let node = nodes.entry(p.peer_id).or_insert_with(|| Node {
            peer_id: p.peer_id,
            ..Default::default()
        });
        if let Some(latency) = stats.latency {
            node.latency_us = latency;
        }
        node.rx_bytes = stats.rx;
        node.tx_bytes = stats.tx;
        node.loss_rate = stats.loss.unwrap_or_default();
        node.tunnels = stats.tunnels.into_iter().collect();
    }
    if let Some(me) = info.my_node_info {
        nodes.insert(
            me.peer_id,
            Node {
                peer_id: me.peer_id,
                hostname: me.hostname,
                ipv4_cidr: ipv4(me.virtual_ipv4).unwrap_or_default(),
                ipv6_cidr: ipv6(me.virtual_ipv6).unwrap_or_default(),
                version: me.version,
                nat_type: nat(me.stun_info.as_ref()),
                is_self: true,
                ..Default::default()
            },
        );
    }
    NodeList {
        nodes: nodes.into_values().collect(),
    }
}

// Current peer-connection counters, not a fabricated lifetime total. A closed
// connection is no longer represented by the upstream snapshot.
fn traffic(info: NetworkInstanceRunningInfo) -> TrafficStats {
    let mut total = TrafficStats::default();
    for peer in info.peers {
        let stats = peer_stats(&peer);
        total.rx_bytes = total.rx_bytes.saturating_add(stats.rx);
        total.tx_bytes = total.tx_bytes.saturating_add(stats.tx);
        total.rx_packets = total.rx_packets.saturating_add(stats.rx_packets);
        total.tx_packets = total.tx_packets.saturating_add(stats.tx_packets);
        total.peers.push(PeerTraffic {
            peer_id: peer.peer_id,
            rx_bytes: stats.rx,
            tx_bytes: stats.tx,
        });
    }
    total.peers.sort_by_key(|p| p.peer_id);
    total
}

pub(super) fn query(
    kind: QueryKind,
    info: NetworkInstanceRunningInfo,
) -> Result<QueryResponse, CoreError> {
    let result = match kind {
        QueryKind::Nodes => QueryResult::Nodes(nodes(info)),
        QueryKind::Routes => QueryResult::Routes(RouteList {
            routes: info.routes.iter().map(route).collect(),
        }),
        QueryKind::Traffic => QueryResult::Traffic(traffic(info)),
        _ => return Err(CoreError::Unsupported("unspecified query kind".into())),
    };
    Ok(QueryResponse {
        result: Some(result),
        at_unix_ms: jiff::Timestamp::now().as_millisecond(),
    })
}
