//! Frozen process engine interface (F0). The only real implementation wraps
//! ProcessKit (`processkit_engine.rs`, P1).
use crate::*;
use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::mpsc;

#[async_trait]
pub trait ProcessEngine: Send + Sync + 'static {
    /// Spawn inside a fresh containment (job object, cgroup or group).
    async fn spawn(&self, cmd: Command) -> Result<Box<dyn ProcessHandle>, ProcessError>;
    /// Verdict on a persisted identity. `Uncertain` is never equivalent to
    /// gone.
    async fn liveness(&self, id: &ProcessIdentity) -> Liveness;
    /// Kill the process tree only if the identity still matches; never by
    /// pid alone.
    async fn kill_verified(&self, id: &ProcessIdentity) -> Result<KillOutcome, ProcessError>;
    /// Processes matching the marker (orphan sweep at self-check).
    async fn find_marked(
        &self,
        marker: &ProcessMarker,
    ) -> Result<Vec<ProcessIdentity>, ProcessError>;
}

#[async_trait]
pub trait ProcessHandle: Send {
    fn identity(&self) -> &ProcessIdentity;
    fn containment(&self) -> Containment;
    /// Output and exit events; `Some` exactly once.
    fn take_events(&mut self) -> Option<mpsc::Receiver<ProcessEvent>>;
    /// Graceful stop (Windows: console-ctrl helper, Unix: SIGTERM), then
    /// tree kill after `grace`.
    async fn stop(&self, grace: Duration) -> Result<Exit, ProcessError>;
    /// Immediate tree kill.
    async fn kill(&self) -> Result<Exit, ProcessError>;
    async fn wait(&self) -> Exit;
}
