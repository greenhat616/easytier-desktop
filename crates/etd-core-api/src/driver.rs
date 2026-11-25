//! Frozen kernel-adapter interface (F0). The only real implementation is in
//! etd-core-easytier.
use crate::*;
use async_trait::async_trait;
use etd_contract::{NetworkSpec, QueryKind, QueryResponse};
use std::{path::Path, time::Instant};

#[async_trait]
pub trait CoreDriver: Send + Sync {
    /// Ask a binary what it is (version, proto revision).
    async fn identify(&self, binary: &Path) -> Result<CoreDescriptor, CoreError>;
    /// The adapter profile paired with this exact kernel, if any. Privileged
    /// hosts refuse kernels without one; user hosts run them lifecycle-only.
    fn profile(&self, core: &CoreDescriptor) -> Option<AdapterProfile>;
    /// Pure: command line, files to write, readiness, and the side effects
    /// this kernel version will cause with this configuration. Returns
    /// `Err(UnmodelledEffects)` for features whose write set is unknown or
    /// decided at run time, `Err(FeatureRejected)` for disabled features.
    fn plan_launch(&self, spec: &NetworkSpec, ctx: &LaunchContext)
    -> Result<LaunchPlan, CoreError>;
    /// Open a management session; RPC method numbers come from the profile
    /// of `core`, never guessed.
    async fn attach(
        &self,
        ep: &CoreEndpoint,
        core: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError>;
}

#[async_trait]
pub trait CoreSession: Send + Sync {
    /// Full readiness (management RPC answers, node info read back). Basic
    /// readiness is judged by the host from `LaunchPlan::readiness` with
    /// system observation and never goes through here.
    async fn wait_ready(&self, deadline: Instant) -> Result<CoreRuntimeInfo, CoreError>;
    async fn query(&self, kind: QueryKind) -> Result<QueryResponse, CoreError>;
    /// Kernel events after `since` (from the start when `None`). The kernel
    /// has no streaming RPC; the host polls (about 1 s with subscribers,
    /// 30 s health checks without).
    async fn poll_events(
        &self,
        since: Option<CoreEventCursor>,
    ) -> Result<Vec<CoreEvent>, CoreError>;
}
