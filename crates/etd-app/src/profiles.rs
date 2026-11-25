//! Frozen interface (F0): the user's own configuration library. Lives in the
//! user's directory; the host never reads it.
use etd_contract::{InstanceId, NetworkSpec};

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    #[error("profile store I/O error: {0}")]
    Io(String),
    #[error("profile store is corrupt: {0}")]
    Corrupt(String),
    #[error("profile store version {found} is newer than supported {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
}

/// One saved network configuration. `spec.network_secret` is never stored
/// by the first release (secret storage is undecided; see doc#7).
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub instance_id: InstanceId,
    pub spec: NetworkSpec,
    pub updated_at: jiff::Timestamp,
}

pub trait ProfileStore: Send + Sync {
    fn load(&self) -> Result<Vec<Profile>, ProfileError>;
    /// Atomically replaces the whole library; on failure the previous file
    /// stays intact.
    fn save(&self, profiles: &[Profile]) -> Result<(), ProfileError>;
}
