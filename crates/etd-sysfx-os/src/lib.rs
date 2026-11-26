//! OS side-effect adapters: the only crate that changes system networking,
//! firewall, registry or DNS on the host's behalf.
//!
//! This file (F0) only dispatches to the platform directory: `windows/`
//! (O1), `linux/` (O2), `macos/` (O3); `service/` belongs to HR.
use etd_sysfx::{BootIdSource, PortFence, Reclaimer, Sweeper, SystemObserver};
use std::{path::PathBuf, sync::Arc};

pub mod appearance;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod service;
#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
use self::windows as platform;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    pub(crate) fn adapters(_: &crate::OsConfig) -> Result<crate::OsAdapters, crate::OsError> {
        Err(crate::OsError::Unsupported("unsupported platform".into()))
    }
}

/// Host directories the adapters need to know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsConfig {
    /// Ledger and repair index (`%ProgramData%\EasyTierDesk`,
    /// `/var/lib/easytier-desk`).
    pub state_dir: PathBuf,
    /// Root of `run/<instance>/<epoch>/`.
    pub run_dir: PathBuf,
    /// Protected kernel store (program firewall rules name these paths).
    pub core_store_dir: PathBuf,
}

/// The platform's implementations of every etd-sysfx interface.
pub struct OsAdapters {
    /// One per effect kind this platform produces.
    pub reclaimers: Vec<Arc<dyn Reclaimer>>,
    pub sweeper: Arc<dyn Sweeper>,
    pub boot_id: Arc<dyn BootIdSource>,
    pub observer: Arc<dyn SystemObserver>,
    /// `None`: this platform cannot fence (privileged instances only with a
    /// verified deny-all profile, otherwise none).
    pub fence: Option<Arc<dyn PortFence>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OsError {
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("access denied: {0}")]
    PermissionDenied(String),
    #[error("operating system error {code}: {message}")]
    Os { code: i64, message: String },
}

/// Build the adapters for the running platform.
pub fn adapters(config: &OsConfig) -> Result<OsAdapters, OsError> {
    platform::adapters(config)
}

/// Uninstall of the service form: remove the volatile boot marker the
/// service host keeps (Windows `HKLM\SOFTWARE\EasyTierDesk\Volatile`;
/// elsewhere nothing to remove). Missing is fine; idempotent.
#[cfg(windows)]
pub use windows::remove_service_boot_marker;
#[cfg(not(windows))]
pub fn remove_service_boot_marker() -> Result<(), OsError> {
    Ok(())
}

/// Check whether a system driver references a protected kernel bundle.
#[cfg(windows)]
pub use windows::driver_refs::{driver_bundle_reference, driver_bundle_referenced};
#[cfg(not(windows))]
pub fn driver_bundle_referenced(_: &std::path::Path) -> Result<bool, OsError> {
    Ok(false)
}

#[cfg(not(windows))]
pub fn driver_bundle_reference(_: &std::path::Path) -> Result<Option<String>, OsError> {
    Ok(None)
}

/// The longest [`shutdown_helpers`] can take.
#[cfg(windows)]
pub const HELPERS_SHUTDOWN_WORST: std::time::Duration = windows::HELPERS_SHUTDOWN_WORST;
/// The longest [`shutdown_helpers`] can take.
#[cfg(not(windows))]
pub const HELPERS_SHUTDOWN_WORST: std::time::Duration = std::time::Duration::ZERO;

/// Host shutdown: end every system-management helper process (Windows: the
/// warm PowerShell workers) and confirm they are gone, so none outlives the
/// host's singleton lock. Admission closes first: no helper starts in this
/// process afterwards. Takes at most [`HELPERS_SHUTDOWN_WORST`]. `Err`: some
/// could not be confirmed gone; whatever they were reclaiming stays open in
/// the ledger. Elsewhere there is nothing to end.
pub fn shutdown_helpers() -> Result<(), OsError> {
    #[cfg(windows)]
    {
        windows::shutdown_helpers()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}
