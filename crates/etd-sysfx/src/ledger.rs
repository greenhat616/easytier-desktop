//! Frozen ledger interface (F0). SQLite implementation: `sqlite/` (L1);
//! in-memory implementation: `etd-testkit` `fakes::ledger` (L1).
//!
//! The ledger is the only source of desired state. It is written by one
//! host (machine-wide singleton lock) and every method returns only after
//! its transaction is durable.
use crate::*;
use async_trait::async_trait;
use etd_contract::{
    AllowEntry, CandidateDecision, DesiredInstance, InstanceId, Receipt, RequestId, Revision,
};

/// Content digest of a request (SHA-256 over its canonical encoding, all
/// fields included). Same request id + same digest = idempotent retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestDigest(pub [u8; 32]);

/// The client request that caused a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRecord {
    pub request_id: RequestId,
    /// Caller principal, as display text (SID or uid).
    pub caller: String,
    pub digest: RequestDigest,
}

/// One state change inside a [`ChangeSet`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Change {
    /// Create or replace an instance (spec including its secret, desired).
    PutInstance(Box<DesiredInstance>),
    SetDesired {
        instance: InstanceId,
        desired: etd_contract::Desired,
    },
    /// Drop the configuration once the instance's last epoch is closed.
    RemoveInstance(InstanceId),
    /// Ticketed operation without desired-state change.
    RetryReclaim(InstanceId),
    ResolveCandidates(Vec<CandidateDecision>),
    SetAllowList(Vec<AllowEntry>),
    /// `None`: back to the store's default.
    SelectCore(Option<String>),
    PurgeAll,
}

/// Everything one client mutation persists, atomically: request record,
/// changes, new revision and the operation ticket.
#[derive(Debug, Clone, PartialEq)]
pub struct ChangeSet {
    pub request: RequestRecord,
    pub changes: Vec<Change>,
}

/// Host settings kept in the ledger next to desired state.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HostSettings {
    pub allow_list: Vec<AllowEntry>,
    pub selected_core: Option<String>,
}

/// An accepted operation awaiting execution by the orchestrator.
#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    pub receipt: Receipt,
    pub changes: Vec<Change>,
    pub done: bool,
}

/// Storage-level fault; new commits are refused while it lasts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageFault {
    DiskFull,
    ReadOnly,
    Locked,
    Corrupt(String),
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// `expected` differs from the current revision.
    #[error("revision conflict: current revision is {current}")]
    Conflict { current: Revision },
    /// Same request id, different digest.
    #[error("request id {0} reused with different content")]
    RequestReused(RequestId),
    /// An older epoch of the instance still has open records.
    #[error("epoch {open:?} of instance {instance} is still open")]
    EpochOpen { instance: InstanceId, open: Epoch },
    #[error("unknown instance {0}")]
    UnknownInstance(InstanceId),
    #[error("unknown effect {0:?}")]
    UnknownEffect(EffectId),
    #[error("invalid transition {from:?} -> {to:?}")]
    InvalidTransition { from: EffectState, to: EffectState },
    #[error("ledger storage unavailable: {0:?}")]
    Unavailable(StorageFault),
    /// Written by a newer version; the host may only diagnose.
    #[error("ledger schema {found} is newer than supported {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    /// Stored data this version cannot interpret (e.g. unknown effect kind).
    #[error("unreadable ledger record: {0}")]
    Unreadable(String),
}

#[async_trait]
pub trait Ledger: Send + Sync {
    /// One transaction: request record + changes + new revision + ticket.
    /// Returns only once durable. `expected` != current revision ->
    /// [`LedgerError::Conflict`]; a known request id with the same digest
    /// returns the original receipt; with a different digest ->
    /// [`LedgerError::RequestReused`].
    async fn commit(&self, expected: Revision, change: ChangeSet) -> Result<Receipt, LedgerError>;

    /// Receipt of an earlier commit, by request id.
    async fn receipt(&self, request: &RequestId) -> Result<Option<Receipt>, LedgerError>;

    /// Accepted operations not yet marked done (for replay after restart).
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError>;
    async fn complete_ticket(&self, ticket: &str) -> Result<(), LedgerError>;

    /// Desired state; the only input for starting instances after boot.
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError>;
    async fn settings(&self) -> Result<HostSettings, LedgerError>;

    /// Allocate the next epoch of `instance` and record its planned effects,
    /// in one transaction, before anything is spawned. Fails with
    /// [`LedgerError::EpochOpen`] while an older epoch has open records.
    async fn begin_epoch(
        &self,
        instance: &InstanceId,
        effects: Vec<EffectIntent>,
    ) -> Result<(Epoch, Vec<Effect>), LedgerError>;

    /// Record one more planned effect (e.g. discovered during start-up).
    /// Must be called before the action that creates the object.
    async fn record(&self, intent: EffectIntent) -> Result<Effect, LedgerError>;

    /// Move a record along the record state machine, attaching the latest
    /// observation (credential read back, or what a probe saw).
    async fn transition(
        &self,
        id: &EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError>;

    /// Count a failed reclaim attempt; returns the consecutive failure count.
    async fn record_failure(&self, id: &EffectId, error: &str) -> Result<u32, LedgerError>;

    /// Records not yet closed, matching the filter.
    async fn open_effects(&self, filter: &ScopeFilter) -> Result<Vec<Effect>, LedgerError>;

    /// Remove closed records; returns how many.
    async fn compact(&self) -> Result<usize, LedgerError>;
}

/// The single out-of-ledger file: which instances existed and the install
/// key. It can only re-derive names to find candidates; it never starts an
/// instance and never authorises a deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairIndex {
    pub install_key: InstallKey,
    pub instances: Vec<InstanceId>,
}

pub trait RepairIndexStore: Send + Sync {
    fn load(&self) -> Result<Option<RepairIndex>, LedgerError>;
    /// Atomic replace.
    fn store(&self, index: &RepairIndex) -> Result<(), LedgerError>;
}
