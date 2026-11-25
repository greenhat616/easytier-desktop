//! Frozen process model (F0).
use std::{ffi::OsString, path::PathBuf};

/// A kernel launch. The executable always comes from the host's protected
/// kernel store; the arguments point into the epoch's runtime directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    /// Extra environment; the engine starts from a minimal environment.
    pub env: Vec<(OsString, OsString)>,
    pub cwd: Option<PathBuf>,
}

/// A process identity that survives pid reuse: pid plus an OS start token
/// (start time) plus the image path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Opaque, platform-specific start token; equal tokens mean the same
    /// process.
    pub start_token: String,
    pub exe: PathBuf,
}

/// Second identity for processes without a record (crash between spawn and
/// pid write): running as the host's own user, image under `exe_root`, and a
/// command line that references a path under `cmdline_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMarker {
    pub exe_root: PathBuf,
    pub cmdline_root: PathBuf,
}

/// Verdict on a recorded identity. `Uncertain` is never treated as `Gone`.
/// Deliberately exhaustive: a new verdict must be handled by every caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Same,
    /// The pid now belongs to another process (start token differs).
    Reused,
    Gone,
    Uncertain,
}

/// How the process tree is contained; tests assert the actual value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Containment {
    JobObject,
    CgroupV2,
    ProcessGroup,
}

/// Outcome of [`crate::ProcessEngine::kill_verified`]. Exhaustive like
/// [`Liveness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    Killed,
    Gone,
    /// Not killed: the pid belongs to another process.
    Reused,
    /// Not killed: identity could not be confirmed.
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitCause {
    /// The process ended on its own (crash, kill by a third party, normal
    /// return): counts against the restart policy.
    Exited,
    /// Ended after the host requested a graceful stop.
    Stopped,
    /// Ended because the host killed the tree (stop timeout or kill).
    Killed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    pub code: Option<i32>,
    /// Unix signal number, if terminated by a signal.
    pub signal: Option<i32>,
    pub cause: ExitCause,
}

impl Exit {
    /// Not requested by the host.
    pub fn abnormal(&self) -> bool {
        self.cause == ExitCause::Exited
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited(Exit),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProcessError {
    #[error("executable not found: {0}")]
    NotFound(PathBuf),
    #[error("failed to spawn {executable}: {message}")]
    Spawn {
        executable: PathBuf,
        message: String,
    },
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// The child could not be placed in its job object / cgroup / group.
    #[error("containment failed: {0}")]
    Containment(String),
    #[error("signal delivery failed: {0}")]
    Signal(String),
    #[error("operation timed out")]
    Timeout,
    #[error("process enumeration failed: {0}")]
    Enumeration(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
