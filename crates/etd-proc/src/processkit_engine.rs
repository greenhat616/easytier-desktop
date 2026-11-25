//! The only file that imports processkit. Owned by P1.
use crate::*;
use async_trait::async_trait;

/// Real adapter seam; does not spawn or terminate processes yet.
pub struct ProcessKitEngine;

#[async_trait]
impl ProcessEngine for ProcessKitEngine {
    async fn spawn(&self, cmd: Command) -> Result<Box<dyn ProcessHandle>, ProcessError> {
        Err(ProcessError::Spawn {
            executable: cmd.executable,
            message: "process engine not implemented".into(),
        })
    }
    async fn liveness(&self, _: &ProcessIdentity) -> Liveness {
        Liveness::Uncertain
    }
    async fn kill_verified(&self, _: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
        Ok(KillOutcome::Uncertain)
    }
    async fn find_marked(&self, _: &ProcessMarker) -> Result<Vec<ProcessIdentity>, ProcessError> {
        Err(ProcessError::Enumeration("not implemented".into()))
    }
}

/// Keep the backend type private to this module as implementation evolves.
#[allow(dead_code)]
struct GroupBackend(processkit::ProcessGroup);
