//! Frozen interface (F0): how the UI finds or starts a host.
use async_trait::async_trait;
use etd_contract::HostMode;
use etd_ipc::{Endpoint, ServerExpectation};

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum LaunchError {
    #[error("no host service is installed")]
    NotInstalled,
    #[error("the user declined or cancelled elevation")]
    ElevationDenied,
    #[error("host form {0:?} is not supported on this platform or build")]
    Unsupported(HostMode),
    #[error("failed to start the host: {0}")]
    Spawn(String),
    #[error("the host did not come up in time")]
    Timeout,
    #[error("launcher I/O error: {0}")]
    Io(String),
    /// The elevated session host started and refused to serve.
    #[error("the elevated session host refused to start: {0}")]
    SessionRefused(SessionRefusal),
}

/// Why an elevated session host refused to serve (its exit codes 3 to 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionRefusal {
    /// The system service is registered: use it instead.
    #[error("the system service is installed; use it instead")]
    ServiceInstalled,
    /// The user's protected session directory exists but does not conform;
    /// an administrator has to delete it.
    #[error("the session directory does not conform; an administrator has to delete it")]
    NotConforming,
    /// Other users' elevated sessions left system changes behind.
    #[error("elevated sessions of other users left system changes behind")]
    OtherUsersLeftovers,
    /// Another process holds the session pipe name.
    #[error("another process holds the session endpoint")]
    EndpointOccupied,
}

/// A host a client can connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTarget {
    pub mode: HostMode,
    pub endpoint: Endpoint,
    /// What the connector must verify about the server process.
    pub expectation: ServerExpectation,
}

/// Decides which host form to use and, when needed, starts it (user host as
/// a child process, elevated session) or triggers installation.
#[async_trait]
pub trait HostLauncher: Send + Sync {
    /// A host that is already reachable or installed, without starting
    /// anything or prompting.
    async fn probe(&self) -> Result<Option<HostTarget>, LaunchError>;
    /// Find or start a host of the wanted form.
    async fn ensure(&self, want: HostMode) -> Result<HostTarget, LaunchError>;
}
