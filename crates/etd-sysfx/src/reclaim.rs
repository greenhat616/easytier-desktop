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
    /// Proven held by another owner (named here), so not ours to undo now:
    /// the record becomes a conflict, left in place and reported, and
    /// closes once the object is gone. Only for a positive proof; an
    /// unprovable holder is [`ReclaimError::Busy`]. The engine honours it
    /// only on a record's first reclaim attempt; after an earlier one it is
    /// a failure like `Busy`.
    #[error("held by {0}")]
    HeldBy(String),
    /// Ours, but this reclaimer never deletes it (the reason is given): the
    /// record becomes a candidate, listed and never retried towards
    /// quarantine, and closes once the object is gone.
    #[error("not deletable: {0}")]
    NotDeletable(String),
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

/// Everything the reclaim engine needs; assembled by the composition root.
/// `reclaimers` holds one per kind: OS kinds from etd-sysfx-os, `Process`
/// and `RuntimeDir` from etd-host-core (`reclaimers`, H1).
pub struct ReclaimDeps {
    pub ledger: std::sync::Arc<dyn Ledger>,
    pub reclaimers: Vec<std::sync::Arc<dyn Reclaimer>>,
    pub sweeper: std::sync::Arc<dyn Sweeper>,
    pub boot_id: std::sync::Arc<dyn BootIdSource>,
    pub repair_index: std::sync::Arc<dyn RepairIndexStore>,
}

/// What a whole-ledger reclaim covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReclaimScope {
    /// Every open instance generation (startup self-check).
    Instances,
    /// Instances plus product and core-binary scope (`reclaim --all
    /// --purge`, uninstall).
    Everything,
}

/// The reclaim engine's entry points, as called by the orchestrator (H1).
/// Implementation: `engine::ReclaimEngineImpl` (R1), built with
/// [`ReclaimDeps`]. Every entry point is idempotent: running the same
/// recovery twice performs no system write the second time.
#[async_trait]
pub trait ReclaimEngine: Send + Sync {
    /// After a generation's process has exited (or was verified dead):
    /// probe, delete, verify its open records in rank order. `Closed` means
    /// the next epoch may start.
    async fn reclaim_generation(
        &self,
        instance: &etd_contract::InstanceId,
        epoch: Epoch,
    ) -> Result<GenerationReport, LedgerError>;
    /// Startup self-check step 4: boot-id comparison (volatile records closed
    /// unprobed), every open record in rank order, exclusive-container sweep,
    /// candidates. One failing generation never stops the others.
    async fn reclaim_all(&self, scope: ReclaimScope) -> Result<ReclaimReport, LedgerError>;
    /// RetryReclaim: reset failure counters of a quarantined generation and
    /// run it again.
    async fn retry(
        &self,
        instance: &etd_contract::InstanceId,
    ) -> Result<GenerationReport, LedgerError>;
    /// Apply administrator decisions on candidate / conflict ids.
    async fn resolve(
        &self,
        decisions: &[etd_contract::CandidateDecision],
    ) -> Result<ReclaimReport, LedgerError>;
    /// Ledger unavailable, corrupt or lost (cannot be opened or written,
    /// but not newer than this version): clean exclusive containers only and
    /// list everything else as candidates, using the repair index if
    /// present.
    async fn recover_without_ledger(&self) -> Result<ReclaimReport, ReclaimError>;
    /// Ledger written by a newer version or unreadable
    /// ([`LedgerError::SchemaTooNew`] / [`LedgerError::Unreadable`]):
    /// read-only diagnosis. Never deletes or changes anything, not even in
    /// exclusive containers; lists candidates only. In this mode the
    /// startup self-check also leaves orphan kernel processes alone (it
    /// lists them, never kills them) and starts no instance.
    async fn diagnose(&self) -> Result<ReclaimReport, ReclaimError>;
    /// Before a kernel leaves the store: reclaim every core-binary-scope
    /// record of that binary (program firewall rules). Fails with
    /// [`LedgerError::EpochOpen`] while an open generation still uses it.
    /// Runs only in the maintenance subcommand that holds the singleton lock
    /// (service stopped; see `CoreStore::remove`). The binary may be deleted
    /// only if the returned report shows no pending (quarantined,
    /// candidate or conflict) core-binary record for it.
    async fn reclaim_core(&self, sha256: &str) -> Result<ReclaimReport, LedgerError>;
    /// The latest report (for snapshots and GetReclaimReport).
    async fn report(&self) -> Result<ReclaimReport, LedgerError>;
}
