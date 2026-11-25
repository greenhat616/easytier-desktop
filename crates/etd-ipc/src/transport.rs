use async_trait::async_trait;
use std::{io, path::PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    NamedPipe(String),
    UnixSocket(PathBuf),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsUserId {
    WindowsSid(String),
    UnixUid(u32),
}
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub user: OsUserId,
    pub pid: u32,
    pub session: Option<u32>,
}
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    pub peer: PeerIdentity,
}
pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Connection for T {}
pub type BoxConn = Box<dyn Connection>;

#[async_trait]
pub trait Listener: Send {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)>;
}
#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self, ep: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)>;
}
