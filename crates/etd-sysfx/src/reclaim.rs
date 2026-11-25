//! Frozen reclaim interfaces (F0). The engine that drives them is `engine/`
//! (R1); OS implementations are in etd-sysfx-os (O1-O3).
use crate::*;
use async_trait::async_trait;
use futures_util::future::BoxFuture;

/// Consecutive reclaim failures after which a generation is quarantined.
pub const QUARANTINE_AFTER: u32 = 5;

/// Reclaim order: lower ranks first (reverse dependency order). DNS and
/// firewall -> registry -> interface -> routes check -> runtime directory ->
/// process record; fences only after the kernel is verified dead.
pub mod rank {
    pub const DNS_AND_FIREWALL: u8 = 10;
    pub const REGISTRY: u8 = 20;
    pub const INTERFACE: u8 = 30;
    pub const ROUTES: u8 = 35;
    pub const RUNTIME_DIR: u8 = 40;
    pub const PROCESS: u8 = 50;
    /// After the process record: the fence comes down last.
    pub const FENCE: u8 = 60;
    /// Product scope: only on uninstall / purge.
    pub const PRODUCT: u8 = 90;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReclaimError {
    #[error("access denied: {0}")]
    PermissionDenied(String),
    /// The object is in use; retry later.
    #[error("object busy: {0}")]
    Busy(String),
    #[error("operating system error {code}: {message}")]
    Os { code: i64, message: String },
    /// The present object does not match the recorded credential; it is not
    /// ours and was not touched.
    #[error("credential mismatch")]
    CredentialMismatch,
    #[error("no reclaimer for {0}")]
    Unsupported(EffectKind),
    #[error("timed out")]
    Timeout,
    #[error("indeterminate: {0}")]
    Indeterminate(String),
}

/// Probe, delete, verify for one [`EffectKind`]. Every method is idempotent:
/// "absent" is success.
#[async_trait]
pub trait Reclaimer: Send + Sync {
    fn kind(&self) -> EffectKind;
    /// Usually [`EffectKind::default_rank`].
    fn rank(&self) -> u8;
    /// Look for the recorded object by its key; report its current
    /// credential. Never deletes.
    async fn probe(&self, e: &Effect) -> Probe;
    /// Undo the effect. The caller has already matched the probe against the
    /// recorded credential (or the key names an exclusive container).
    /// Absent is `Ok(AlreadyAbsent)`.
    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError>;
}

/// Finds product-marked objects outside the ledger (lost ledger, crash
/// between action and record).
pub trait Sweeper: Send + Sync {
    /// `known` are instances from the repair index, used to re-derive names.
    fn find_marked<'a>(
        &'a self,
        key: Option<&'a InstallKey>,
        known: &'a [etd_contract::InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>>;
}

pub trait BootIdSource: Send + Sync {
    fn current(&self) -> Result<BootId, ReclaimError>;
}
