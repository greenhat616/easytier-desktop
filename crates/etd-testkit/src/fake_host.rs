use etd_client::{CallError, HostClient};
use etd_contract::*;
use futures_util::stream::BoxStream;

/// Minimal deterministic host test double.
pub struct FakeHost {
    pub negotiated: Negotiated,
    pub snapshot: HostSnapshot,
}
#[async_trait::async_trait]
impl HostClient for FakeHost {
    fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }
    async fn snapshot(&self) -> Result<HostSnapshot, CallError> {
        Ok(self.snapshot.clone())
    }
    fn subscribe(&self, _: Option<EventCursor>) -> BoxStream<'static, Result<Event, CallError>> {
        Box::pin(futures_util::stream::empty())
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
