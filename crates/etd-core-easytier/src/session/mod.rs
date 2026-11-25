//! Management session over the kernel's loopback RPC (`StandAloneClient`
//! over a `TcpStream` tunnel); maps queries and events to contract types.
//! Owned by E2.
mod events;
mod mapping;
#[cfg(test)]
mod tests;
mod transport;

use easytier_core::{connectivity::protocol::raw::TunnelDialer, rpc::standalone::StandAloneClient};
use easytier_proto::{
    api::manage::{
        CollectNetworkInfoRequest, ListNetworkInstanceRequest, NetworkInstanceRunningInfo,
        WebClientService, WebClientServiceClientFactory,
    },
    rpc_types::controller::BaseController,
};
use etd_contract::{QueryKind, QueryResponse};
use etd_core_api::{
    CoreDescriptor, CoreEndpoint, CoreError, CoreEvent, CoreEventCursor, CoreRuntimeInfo,
    CoreSession,
};
use std::time::{Duration, Instant};
use tokio::{
    sync::Mutex,
    time::{sleep, timeout, timeout_at},
};
use uuid::Uuid;

const RPC_TIMEOUT: Duration = Duration::from_secs(6);

pub async fn attach(
    ep: &CoreEndpoint,
    core: &CoreDescriptor,
) -> Result<Box<dyn CoreSession>, CoreError> {
    if crate::profiles::find(core).is_none() {
        return Err(CoreError::NoProfile {
            version: core.version.clone(),
        });
    }
    if !ep.0.ip().is_loopback()
        || ep.0.port() == 0
        || matches!(ep.0, std::net::SocketAddr::V6(addr) if addr.scope_id() != 0)
    {
        return Err(CoreError::Connect(
            "management endpoint must be a concrete loopback address".into(),
        ));
    }
    Ok(Box::new(
        Session::connect(transport::LoopbackDialer(ep.0)).await?,
    ))
}

struct Session<D: TunnelDialer> {
    state: Mutex<State<D>>,
    instance: Uuid,
}

struct State<D: TunnelDialer> {
    client: StandAloneClient<D>,
    events: events::Journal,
}

impl<D: TunnelDialer> Session<D> {
    async fn connect(dialer: D) -> Result<Self, CoreError> {
        let mut client = StandAloneClient::new(dialer);
        let instance = timeout(RPC_TIMEOUT, async {
            let rpc = client
                .scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
                .await
                .map_err(|_| CoreError::Connect("cannot open management RPC".into()))?;
            let listed = rpc
                .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
                .await
                .map_err(|_| CoreError::Rpc("list network instances failed".into()))?;
            let [id] = listed.inst_ids.as_slice() else {
                return Err(CoreError::Rpc(
                    "expected exactly one kernel instance".into(),
                ));
            };
            Ok::<Uuid, CoreError>((*id).into())
        })
        .await
        .map_err(|_| CoreError::Timeout)??;
        Ok(Self {
            state: Mutex::new(State {
                client,
                events: events::Journal::default(),
            }),
            instance,
        })
    }
}

impl<D: TunnelDialer> State<D> {
    async fn snapshot(&mut self, instance: Uuid) -> Result<NetworkInstanceRunningInfo, CoreError> {
        let rpc = self
            .client
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
            .await
            .map_err(|_| CoreError::Connect("cannot open management RPC".into()))?;
        let response = rpc
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: vec![instance.into()],
                },
            )
            .await
            .map_err(|_| CoreError::Rpc("collect network info failed".into()))?;
        let mut map = response
            .info
            .ok_or_else(|| CoreError::Rpc("missing network info".into()))?
            .map;
        if map.len() != 1 {
            return Err(CoreError::Rpc(
                "expected exactly one scoped network snapshot".into(),
            ));
        }
        let info = map
            .remove(&instance.to_string())
            .ok_or_else(|| CoreError::Rpc("kernel instance no longer present".into()))?;
        if info
            .error_msg
            .as_ref()
            .is_some_and(|error| !error.is_empty())
        {
            // Upstream diagnostic strings can include configuration; keep our errors typed and redacted.
            return Err(CoreError::Rpc("kernel reported an instance error".into()));
        }
        Ok(info)
    }
}

#[async_trait::async_trait]
impl<D: TunnelDialer> CoreSession for Session<D> {
    async fn wait_ready(&self, deadline: Instant) -> Result<CoreRuntimeInfo, CoreError> {
        timeout_at(deadline.into(), async {
            loop {
                let info = self.state.lock().await.snapshot(self.instance).await;
                if let Ok(info) = info
                    && info.running
                    && let Some(node) = info.my_node_info
                {
                    let dev_name = events::latest_interface(&info.events).unwrap_or(info.dev_name);
                    return Ok(mapping::runtime(dev_name, node));
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| CoreError::Timeout)?
    }

    async fn query(&self, kind: QueryKind) -> Result<QueryResponse, CoreError> {
        if kind == QueryKind::Unspecified {
            return Err(CoreError::Unsupported("unspecified query kind".into()));
        }
        timeout(RPC_TIMEOUT, async {
            let info = self.state.lock().await.snapshot(self.instance).await?;
            if !info.running || info.my_node_info.is_none() {
                return Err(CoreError::Rpc("kernel is not fully ready".into()));
            }
            mapping::query(kind, info)
        })
        .await
        .map_err(|_| CoreError::Timeout)?
    }

    async fn poll_events(
        &self,
        since: Option<CoreEventCursor>,
    ) -> Result<Vec<CoreEvent>, CoreError> {
        timeout(RPC_TIMEOUT, async {
            let mut state = self.state.lock().await;
            let snapshot = state.snapshot(self.instance).await?;
            if !snapshot.running || snapshot.my_node_info.is_none() {
                return Err(CoreError::Rpc("kernel is not fully ready".into()));
            }
            state.events.ingest(snapshot.events);
            state.events.after(since)
        })
        .await
        .map_err(|_| CoreError::Timeout)?
    }
}
