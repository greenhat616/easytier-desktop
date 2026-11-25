//! Native named pipe / Unix-domain socket adapters. Owned by I1.
use crate::{
    BoxConn, Connector, Endpoint, Listener, ListenerPolicy, PeerIdentity, ServerExpectation,
    ServerIdentity,
};
use std::io;

/// Placeholder until I1 lands the platform listener.
pub struct LocalListener {
    pub endpoint: Endpoint,
    pub policy: ListenerPolicy,
}

/// Placeholder until I1 lands the platform connector.
pub struct LocalConnector {
    pub expectation: ServerExpectation,
}

#[async_trait::async_trait]
impl Connector for LocalConnector {
    async fn connect(&self, _: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local IPC not implemented",
        ))
    }
}

#[async_trait::async_trait]
impl Listener for LocalListener {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local IPC not implemented",
        ))
    }
}
