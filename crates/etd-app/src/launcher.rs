use async_trait::async_trait;
use etd_contract::HostMode;
use etd_ipc::Endpoint;

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("host launch not implemented")]
    NotImplemented,
}
#[async_trait]
pub trait HostLauncher: Send + Sync {
    async fn ensure(&self, want: HostMode) -> Result<Endpoint, LaunchError>;
}
