//! Frozen kernel-store interface (F0). The manifest-backed implementation
//! (manifest with version, SHA-256 and proto revision; hash checked before
//! every use) is `core_store/manifest.rs` (H2).
use etd_contract::v1::CoreEntry;
use etd_core_api::{AdapterProfile, CoreDescriptor};
use std::path::PathBuf;

pub mod manifest;

/// Which kernel to use. Clients can only name a version present in the
/// store, never a path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoreSelector {
    /// `None`: the selected default.
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreUsage {
    /// Adapter profile available: full features.
    Profiled(AdapterProfile),
    /// No profile, user host only: start/stop and logs, no RPC.
    LifecycleOnly,
}

/// A kernel whose hash matched its manifest entry just now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCore {
    pub binary: PathBuf,
    pub descriptor: CoreDescriptor,
    pub sha256: [u8; 32],
    pub usage: CoreUsage,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("no kernel matching {0:?} in the store")]
    NotFound(CoreSelector),
    #[error("kernel {version}: hash mismatch")]
    HashMismatch { version: String },
    /// Privileged host and no adapter profile for this version.
    #[error("no adapter profile for kernel {version}")]
    NoProfile { version: String },
    #[error("invalid store manifest: {0}")]
    Manifest(String),
    #[error("kernel store I/O error: {0}")]
    Io(String),
}

/// Async because resolving hashes the binary (blocking I/O must run off the
/// executor). Implementations derive `VerifiedCore::usage` from
/// `CoreDriver::profile` of the identified descriptor; the orchestrator
/// treats `usage` as the single source for launches.
#[async_trait::async_trait]
pub trait CoreStore: Send + Sync {
    /// Verify and return the kernel to launch.
    async fn resolve(&self, want: &CoreSelector) -> Result<VerifiedCore, StoreError>;
    /// Every kernel in the store with its support level, for ListCores.
    async fn list(&self) -> Result<Vec<CoreEntry>, StoreError>;
}
