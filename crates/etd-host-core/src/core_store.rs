//! Frozen kernel-store interface (F0). The manifest-backed implementation
//! (manifest with version, SHA-256 and proto revision; hash checked before
//! every use) is `core_store/manifest.rs` (H2).
//!
//! Layout: one directory per binary, named by its SHA-256 (lower-case hex),
//! under `HostDirs::core_store_dir`; a binary is never replaced in place.
//! The kernel path (which the program firewall rule names contain) is
//! therefore unique per hash, and `EffectScope::CoreBinary` records of
//! different binaries never share a key.
//!
//! Removing a kernel (v7: changing kernel versions is a one-time elevated
//! `etd-host` subcommand) requires the service to be stopped: the
//! maintenance subcommand takes the machine-wide singleton lock (so it is
//! the only ledger writer and no generation can start meanwhile), runs
//! `ReclaimEngine::reclaim_core`, deletes the binary via
//! [`CoreStore::remove`], releases the lock; the service is then started
//! again. There is no contract call for it.
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
    /// An open generation still uses this kernel.
    #[error("kernel {version} is in use")]
    InUse { version: String },
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
    /// Configured store default without executing or hashing a kernel. Callers
    /// validate support against `list`; older implementations report no default.
    async fn default_version(&self) -> Result<Option<String>, StoreError> {
        Ok(None)
    }
    /// Remove a kernel from the store (maintenance subcommand under the
    /// singleton lock, see the module docs). The caller first runs
    /// `ReclaimEngine::reclaim_core(sha256)`, which removes the binary's
    /// program firewall rules and refuses while an open generation uses it;
    /// the binary is deleted only if that report shows no pending
    /// core-binary record. A selected default that is removed falls back to
    /// no selection.
    async fn remove(&self, version: &str) -> Result<(), StoreError>;
}
