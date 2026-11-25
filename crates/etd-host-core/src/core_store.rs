use etd_core_api::CoreDescriptor;
use std::path::PathBuf;
#[derive(Debug, Clone)]
pub struct CoreSelector {
    pub version: String,
}
#[derive(Debug, Clone)]
pub struct VerifiedCore {
    pub binary: PathBuf,
    pub descriptor: CoreDescriptor,
}
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("core store not implemented")]
    NotImplemented,
}
pub trait CoreStore: Send + Sync {
    fn resolve(&self, want: &CoreSelector) -> Result<VerifiedCore, StoreError>;
}
