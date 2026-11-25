//! Identify a kernel binary (version, proto revision). Owned by E1.
use etd_core_api::{CoreDescriptor, CoreError};
use std::path::Path;

pub async fn identify(_binary: &Path) -> Result<CoreDescriptor, CoreError> {
    Err(CoreError::Unsupported("identify not implemented".into()))
}
