use async_trait::async_trait;
use etd_contract::*;
use futures_util::stream::BoxStream;

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("host call not implemented")]
    NotImplemented,
}
#[async_trait]
pub trait HostClient: Send + Sync {
    fn negotiated(&self) -> &Negotiated;
    async fn snapshot(&self) -> Result<HostSnapshot, CallError>;
    fn subscribe(&self, from: Option<EventCursor>) -> BoxStream<'static, Result<Event, CallError>>;
    async fn apply(&self, req: Mutation<NetworkSpec>) -> Result<Receipt, CallError>;
    async fn set_desired(&self, req: Mutation<Desired>) -> Result<Receipt, CallError>;
    async fn receipt(&self, request_id: RequestId) -> Result<Option<Receipt>, CallError>;
    async fn query(&self, id: InstanceId, q: Query) -> Result<QueryReply, CallError>;
    async fn reclaim_report(&self) -> Result<ReclaimReport, CallError>;
}

/// Placeholder for negotiated gRPC transport and reconnect logic.
pub struct GrpcHostClient {
    pub negotiated: Negotiated,
    pub connector: std::sync::Arc<dyn etd_ipc::Connector>,
}
#[async_trait]
impl HostClient for GrpcHostClient {
    fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }
    async fn snapshot(&self) -> Result<HostSnapshot, CallError> {
        Err(CallError::NotImplemented)
    }
    fn subscribe(&self, _: Option<EventCursor>) -> BoxStream<'static, Result<Event, CallError>> {
        Box::pin(futures_util::stream::once(async {
            Err(CallError::NotImplemented)
        }))
    }
    async fn apply(&self, _: Mutation<NetworkSpec>) -> Result<Receipt, CallError> {
        Err(CallError::NotImplemented)
    }
    async fn set_desired(&self, _: Mutation<Desired>) -> Result<Receipt, CallError> {
        Err(CallError::NotImplemented)
    }
    async fn receipt(&self, _: RequestId) -> Result<Option<Receipt>, CallError> {
        Err(CallError::NotImplemented)
    }
    async fn query(&self, _: InstanceId, _: Query) -> Result<QueryReply, CallError> {
        Err(CallError::NotImplemented)
    }
    async fn reclaim_report(&self) -> Result<ReclaimReport, CallError> {
        Err(CallError::NotImplemented)
    }
}
