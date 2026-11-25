//! Frozen ledger interface (F0). SQLite implementation: `sqlite/` (L1);
//! in-memory implementation: `etd-testkit` `fakes::ledger` (L1).
//!
//! The ledger is the only source of desired state. It is written by one
//! host (machine-wide singleton lock) and every method returns only after
//! its transaction is durable.
//!
//! Generations (epochs). Every instance has a persisted epoch high-water mark
//! that never goes down and survives [`Ledger::compact`]. A generation is
//! reserved by recording its planned effects with epoch `high-water + 1`:
//! - when a client mutation starts it: inside [`Ledger::commit`], in the same
//!   transaction as the request, desired state, revision and ticket
//!   ([`ChangeSet::generations`]);
//! - when the supervisor restarts an instance on its own (after a crash and
//!   reclaim, after a deny-all re-plan): [`Ledger::begin_epoch`].
//!
//! The planner reads the epoch it must use from [`Ledger::next_epoch`]. Both
//! paths refuse an epoch that is not exactly the next one
//! ([`LedgerError::EpochNotNext`]) and refuse while an older generation of
//! the instance still has open records ([`LedgerError::EpochOpen`]).
//! Concurrent planners cannot both succeed: the single writer serialises
//! commits, and the loser gets a revision conflict or `EpochNotNext`.
use crate::*;
use async_trait::async_trait;
use etd_contract::{
    AllowEntry, CandidateDecision, Desired, DesiredInstance, InstanceId, Receipt, RequestId,
    Revision,
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
    /// `claims` are the single-writer resources its configuration needs
    /// (`LaunchPlan::exclusive`, e.g. Windows Magic DNS).
    PutInstance {
        instance: Box<DesiredInstance>,
        claims: Vec<String>,
    },
    SetDesired {
        instance: InstanceId,
        desired: Desired,
    },
    /// Drop the configuration once the instance's last epoch is closed.
    RemoveInstance(InstanceId),
    /// Ticketed operations without desired-state change.
    RetryReclaim(InstanceId),
    /// Manual restart after GAVE_UP: the orchestrator resets the restart
    /// policy.
    RetryStart(InstanceId),
    /// Decisions on candidate and conflict ids.
    ResolveCandidates(Vec<CandidateDecision>),
    SetAllowList(Vec<AllowEntry>),
    /// `None`: back to the store's default.
    SelectCore(Option<String>),
    PurgeAll,
}

/// The planned effects of one new generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationPlan {
    pub instance: InstanceId,
    /// Must equal [`Ledger::next_epoch`] for `instance`.
    pub epoch: Epoch,
    /// Every effect of the generation: the kernel's predicted effects
    /// (`LaunchPlan::effects`) plus the host's own (process record, runtime
    /// directory, fence). Each intent's scope must be this generation, or a
    /// product / core-binary scope (recorded once per kind + key; an existing
    /// open record with the same kind and key is reused, not duplicated).
    pub effects: Vec<EffectIntent>,
}

/// Everything one client mutation persists, atomically: request record,
/// changes, new revision, operation ticket, and the reserved epoch and
/// planned effects of every generation the mutation starts.
///
/// Single-writer check, inside the transaction: after applying `changes`,
/// no claim may be held by two instances whose desired state is running
/// ([`LedgerError::ExclusiveTaken`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ChangeSet {
    pub request: RequestRecord,
    pub changes: Vec<Change>,
    pub generations: Vec<GenerationPlan>,
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
    /// Generations reserved by this ticket (instance, epoch).
    pub generations: Vec<(InstanceId, Epoch)>,
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
    /// The planned epoch is not `high-water + 1`.
    #[error("epoch {got:?} of instance {instance} is not the next epoch {next:?}")]
    EpochNotNext {
        instance: InstanceId,
        next: Epoch,
        got: Epoch,
    },
    /// A single-writer resource is already claimed by a running instance.
    #[error("{resource} is already used by instance {holder}")]
    ExclusiveTaken {
        resource: String,
        holder: InstanceId,
    },
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
    /// One transaction: request record + changes + new revision + ticket +
    /// every generation in `change.generations` (epoch reservation and
    /// planned effects). Returns only once durable. `expected` != current
    /// revision -> [`LedgerError::Conflict`]; a known request id with the
    /// same digest returns the original receipt; with a different digest ->
    /// [`LedgerError::RequestReused`]; generation and claim checks as
    /// described on [`ChangeSet`] and in the module docs.
    async fn commit(&self, expected: Revision, change: ChangeSet) -> Result<Receipt, LedgerError>;

    /// Receipt of an earlier commit, by request id.
    async fn receipt(&self, request: &RequestId) -> Result<Option<Receipt>, LedgerError>;

    /// Accepted operations not yet marked done (for replay after restart).
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError>;
    async fn complete_ticket(&self, ticket: &str) -> Result<(), LedgerError>;

    /// Desired state; the only input for starting instances after boot.
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError>;
    async fn settings(&self) -> Result<HostSettings, LedgerError>;
    /// Single-writer claims of every instance, as last committed.
    async fn claims(&self) -> Result<Vec<(InstanceId, Vec<String>)>, LedgerError>;

    /// The epoch the next generation of `instance` must use
    /// (`high-water + 1`; `Epoch(1)` for a new instance). Read-only.
    async fn next_epoch(&self, instance: &InstanceId) -> Result<Epoch, LedgerError>;

    /// Supervisor-initiated generation (no client request): reserve `epoch`
    /// and record its planned effects in one transaction, before anything is
    /// spawned. Same checks as a generation inside [`Ledger::commit`].
    async fn begin_epoch(
        &self,
        instance: &InstanceId,
        epoch: Epoch,
        effects: Vec<EffectIntent>,
    ) -> Result<Vec<Effect>, LedgerError>;

    /// Open records of a generation as committed, e.g. to read back the
    /// effects a commit planned. Equivalent to `open_effects` with
    /// [`ScopeFilter::epoch`].
    async fn generation(
        &self,
        instance: &InstanceId,
        epoch: Epoch,
    ) -> Result<Vec<Effect>, LedgerError>;

    /// Record one more planned effect of an existing open generation (or a
    /// product / core-binary effect). Must be called before the action that
    /// creates the object.
    async fn record(&self, intent: EffectIntent) -> Result<Effect, LedgerError>;

    /// Move a record along the record state machine, attaching the latest
    /// observation (credential and concrete key read back, or what a probe
    /// saw). Moving to `Reclaimed`, or out of `Quarantined`, resets the
    /// failure counter.
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

    /// Remove closed records; returns how many. Epoch high-water marks are
    /// kept.
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
