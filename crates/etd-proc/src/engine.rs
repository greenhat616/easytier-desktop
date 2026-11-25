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
    ///
    /// Recovery (H1): inspect liveness first. `Same` permits
    /// `kill_verified` (on macOS discover the exact identity with
    /// `find_marked` and its generation marker first). `Gone`/`Reused` is
    /// only a root verdict: close the process record when the original
    /// containment guarantees the tree is dead (Windows job object), when
    /// the Linux cgroup is independently confirmed empty, or, for Linux
    /// process-group fallback/macOS, when a fresh successful marker sweep
    /// finds no marked survivors. Otherwise keep the generation quarantined.
    /// An in-process cleanup-uncertain tombstone answers `Uncertain` until
    /// that actual containment is confirmed empty; after host restart the
    /// durable ledger must keep the unresolved record open/quarantined.
    /// An explicit cleanup retry may call `kill_verified` on the tombstone;
    /// only its retained, originally registered containment is used.
    async fn liveness(&self, id: &ProcessIdentity) -> Liveness;
    /// Kill the process tree only if the identity still matches; never by
    /// pid alone. Without a live containment, macOS is the explicit
    /// human-approved exception: verify token/image/owner/marker immediately
    /// before signalling, with a narrow verify-to-signal TOCTOU window.
    /// A prior root `Gone` or `Reused` with no verified containment is not
    /// itself a successful tree-kill outcome; see the recovery convention.
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
