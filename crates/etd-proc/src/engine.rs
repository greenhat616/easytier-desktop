use crate::*;
use async_trait::async_trait;
use std::{path::Path, time::Duration};
use tokio::sync::mpsc;

#[async_trait]
pub trait ProcessEngine: Send + Sync + 'static {
    async fn spawn(&self, cmd: Command) -> Result<Box<dyn ProcessHandle>, ProcessError>;
    /// Uncertain is never equivalent to gone.
    async fn liveness(&self, id: &ProcessIdentity) -> Liveness;
    async fn kill_verified(&self, id: &ProcessIdentity) -> Result<KillOutcome, ProcessError>;
    async fn find_marked(&self, exe_root: &Path) -> Vec<ProcessIdentity>;
}
#[async_trait]
pub trait ProcessHandle: Send {
    fn identity(&self) -> &ProcessIdentity;
    fn containment(&self) -> Containment;
    fn take_events(&mut self) -> mpsc::Receiver<ProcessEvent>;
    async fn stop(&self, grace: Duration) -> Result<Exit, ProcessError>;
    async fn wait(&self) -> Exit;
}
