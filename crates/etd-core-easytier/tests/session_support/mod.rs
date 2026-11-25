use easytier_core::{rpc::bidirect::BidirectRpcManager, tunnel::Tunnel};
use easytier_proto::{
    api::{
        instance::{PeerConnInfo, PeerConnStats, PeerInfo, Route},
        manage::*,
    },
    common::TunnelInfo,
    rpc_types::{
        controller::BaseController,
        error::{Error, Result as RpcResult},
    },
};
use std::sync::{Arc, Mutex as StdMutex};
use uuid::Uuid;
#[derive(Clone)]
struct Stub {
    ids: Vec<Uuid>,
    info: Arc<StdMutex<NetworkInstanceRunningInfo>>,
}

#[async_trait::async_trait]
impl WebClientService for Stub {
    type Controller = BaseController;
    async fn list_network_instance(
        &self,
        _: BaseController,
        _: ListNetworkInstanceRequest,
    ) -> RpcResult<ListNetworkInstanceResponse> {
        Ok(ListNetworkInstanceResponse {
            inst_ids: self.ids.iter().copied().map(Into::into).collect(),
        })
    }
    async fn collect_network_info(
        &self,
        _: BaseController,
        input: CollectNetworkInfoRequest,
    ) -> RpcResult<CollectNetworkInfoResponse> {
        assert_eq!(input.inst_ids, vec![self.ids[0].into()]);
        Ok(CollectNetworkInfoResponse {
            info: Some(NetworkInstanceRunningInfoMap {
                map: [(self.ids[0].to_string(), self.info.lock().unwrap().clone())]
                    .into_iter()
                    .collect(),
            }),
        })
    }
    async fn validate_config(
        &self,
        _: BaseController,
        _: ValidateConfigRequest,
    ) -> RpcResult<ValidateConfigResponse> {
        Err(Error::Shutdown)
    }
    async fn run_network_instance(
        &self,
        _: BaseController,
        _: RunNetworkInstanceRequest,
    ) -> RpcResult<RunNetworkInstanceResponse> {
        Err(Error::Shutdown)
    }
    async fn retain_network_instance(
        &self,
        _: BaseController,
        _: RetainNetworkInstanceRequest,
    ) -> RpcResult<RetainNetworkInstanceResponse> {
        Err(Error::Shutdown)
    }
    async fn delete_network_instance(
        &self,
        _: BaseController,
        _: DeleteNetworkInstanceRequest,
    ) -> RpcResult<DeleteNetworkInstanceResponse> {
        Err(Error::Shutdown)
    }
    async fn get_network_instance_config(
        &self,
        _: BaseController,
        _: GetNetworkInstanceConfigRequest,
    ) -> RpcResult<GetNetworkInstanceConfigResponse> {
        Err(Error::Shutdown)
    }
    async fn list_network_instance_meta(
        &self,
        _: BaseController,
        _: ListNetworkInstanceMetaRequest,
    ) -> RpcResult<ListNetworkInstanceMetaResponse> {
        Err(Error::Shutdown)
    }
}

pub fn server(
    ids: Vec<Uuid>,
    server: Box<dyn Tunnel>,
) -> (
    BidirectRpcManager,
    Arc<StdMutex<NetworkInstanceRunningInfo>>,
) {
    let info = Arc::new(StdMutex::new(NetworkInstanceRunningInfo {
        running: true,
        my_node_info: Some(MyNodeInfo {
            peer_id: 1,
            hostname: "local".into(),
            virtual_ipv4: Some("10.10.10.1/24".parse().unwrap()),
            version: "2.7.1".into(),
            ..Default::default()
        }),
        routes: vec![Route {
            peer_id: 2,
            hostname: "remote".into(),
            ipv4_addr: Some("10.10.10.2/24".parse().unwrap()),
            next_hop_peer_id: 2,
            cost: 1,
            path_latency: 3,
            ..Default::default()
        }],
        peers: vec![PeerInfo {
            peer_id: 2,
            conns: vec![PeerConnInfo {
                peer_id: 2,
                stats: Some(PeerConnStats {
                    rx_bytes: 10,
                    tx_bytes: 20,
                    rx_packets: 1,
                    tx_packets: 2,
                    latency_us: 3000,
                }),
                tunnel: Some(TunnelInfo {
                    tunnel_type: "tcp".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        events: vec![
            r#"{"time":"2026-11-26T05:52:02+08:00","event":{"PeerAdded":2}}"#.into(),
            r#"{"time":"2026-11-26T05:52:01+08:00","event":{"TunDeviceReady":"utun7"}}"#.into(),
        ],
        ..Default::default()
    }));
    let manager = BidirectRpcManager::new();
    manager.rpc_server().registry().register(
        WebClientServiceServer::new(Stub {
            ids,
            info: info.clone(),
        }),
        "",
    );
    manager.run_with_tunnel(server);
    (manager, info)
}
