use crate::*;
use async_trait::async_trait;
use etd_contract::{EventCursor, NetworkSpec, Query, QueryReply};
use std::{path::Path, time::Instant};

#[async_trait]
pub trait CoreDriver: Send + Sync {
    async fn identify(&self, binary: &Path) -> Result<CoreDescriptor, CoreError>;
    fn plan_launch(&self, spec: &NetworkSpec, dirs: &RuntimeDirs) -> Result<LaunchPlan, CoreError>;
    async fn attach(&self, ep: &CoreEndpoint) -> Result<Box<dyn CoreSession>, CoreError>;
}
#[async_trait]
pub trait CoreSession: Send + Sync {
    async fn wait_ready(&self, deadline: Instant) -> Result<CoreRuntimeInfo, CoreError>;
    async fn query(&self, q: Query) -> Result<QueryReply, CoreError>;
    async fn poll_events(&self, since: EventCursor) -> Result<Vec<CoreEvent>, CoreError>;
}
