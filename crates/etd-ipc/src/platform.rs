//! Native named pipe / Unix-domain socket adapter placeholders.
pub struct LocalConnector;
pub struct LocalListener;

#[async_trait::async_trait]
impl crate::Connector for LocalConnector {
    async fn connect(
        &self,
        _: &crate::Endpoint,
    ) -> std::io::Result<(crate::BoxConn, crate::ServerIdentity)> {
        Err(std::io::Error::other("local IPC not implemented"))
    }
}
#[async_trait::async_trait]
impl crate::Listener for LocalListener {
    async fn accept(&mut self) -> std::io::Result<(crate::BoxConn, crate::PeerIdentity)> {
        Err(std::io::Error::other("local IPC not implemented"))
    }
}
