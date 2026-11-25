use crate::*;
use async_trait::async_trait;
use std::path::Path;

/// Real adapter seam; does not spawn or terminate processes yet.
pub struct ProcessKitEngine;
#[async_trait]
impl ProcessEngine for ProcessKitEngine {
    async fn spawn(&self, _: Command) -> Result<Box<dyn ProcessHandle>, ProcessError> {
        Err(ProcessError::NotImplemented)
    }
    async fn liveness(&self, _: &ProcessIdentity) -> Liveness {
        Liveness::Uncertain
    }
    async fn kill_verified(&self, _: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
        Err(ProcessError::NotImplemented)
    }
    async fn find_marked(&self, _: &Path) -> Vec<ProcessIdentity> {
        todo!("native enumeration")
    }
}

/// Keep the backend type private to this module as implementation evolves.
#[allow(dead_code)]
struct GroupBackend(processkit::ProcessGroup);
