//! Frozen transport interface (F0). Platform implementations live in
//! `platform/` (I1); the tonic adapters in `tonic_io.rs` (I1).
use async_trait::async_trait;
use std::{io, path::PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

/// Windows named pipe of the installed service host.
pub const SERVICE_PIPE_NAME: &str = r"\\.\pipe\easytier-desk-host";
/// Unix socket of the installed service host; its directory is root-owned.
pub const SERVICE_SOCKET_PATH: &str = "/run/easytier-desk/host.sock";
/// Unix group whose members may connect to the service socket (mode 0660).
pub const SERVICE_SOCKET_GROUP: &str = "easytier-desk";

/// Where a host listens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Endpoint {
    NamedPipe(String),
    UnixSocket(PathBuf),
}

/// An operating-system user.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OsUserId {
    WindowsSid(String),
    UnixUid(u32),
}

/// An operating-system group.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OsGroupId {
    WindowsSid(String),
    UnixGid(u32),
}

/// Who is on the other end of an accepted connection, as reported by the OS
/// (Windows: client process token; Unix: peer credentials). Never derived
/// from anything the client sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub user: OsUserId,
    /// Enabled group memberships (Windows token groups, Unix supplementary
    /// groups plus the primary group).
    pub groups: Vec<OsGroupId>,
    pub pid: u32,
    /// Windows logon session id; `None` on Unix.
    pub session: Option<u32>,
    /// Windows: the token is elevated. Unix: uid 0.
    pub elevated: bool,
}

/// The server end as verified by a client before it sends anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentity {
    pub peer: PeerIdentity,
    /// Image path of the server process.
    pub exe: PathBuf,
}

/// Access policy applied when a listener creates its endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListenerPolicy {
    /// Users and groups granted read/write (never change-permission) access
    /// in addition to SYSTEM / Administrators (Windows) or root (Unix).
    pub allow_users: Vec<OsUserId>,
    pub allow_groups: Vec<OsGroupId>,
    /// Unix socket group (mode 0660); `None` keeps the socket root-only.
    pub unix_group: Option<String>,
}

/// What a client requires of the server before trusting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerExpectation {
    /// The server executable must live under this directory.
    pub exe_dir: PathBuf,
    /// The server must run as this user (`None`: any user in `privileged`).
    pub user: Option<OsUserId>,
    /// Require SYSTEM / root (service host) rather than the current user.
    pub privileged: bool,
}

pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Connection for T {}
pub type BoxConn = Box<dyn Connection>;

/// Server side. Implementations create the endpoint as its first instance
/// (fail if the name is taken), apply a [`ListenerPolicy`] and reject remote
/// clients.
#[async_trait]
pub trait Listener: Send {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)>;
}

/// Client side. Implementations verify the server process against a
/// [`ServerExpectation`] and fail with `PermissionDenied` before returning a
/// connection to an impostor.
#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self, ep: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)>;
}
