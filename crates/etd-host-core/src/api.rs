//! Frozen host-internal orchestration handle (F0): the interface between
//! the lifecycle orchestrator (H1: `lifecycle/`, `supervisor`, `boot`,
//! `poller`, `fence_seq`) and the contract service (H2: `service/`, `auth`,
//! `negotiate`, `events`, `core_store`).
//!
//! Division of work:
//! - H2 authenticates and authorises, asks H1 to plan ([`Command::Plan`]),
//!   commits the mutation together with the returned generation plan in one
//!   ledger transaction (`ChangeSet::generations`; single-writer claims are
//!   checked by the ledger inside that transaction against committed state)
//!   and answers with the receipt; then it tells H1 with
//!   [`Command::Committed`]. H1 executes accepted tickets
//!   (`Ledger::pending_tickets`), spawns committed generations (re-running
//!   the pure `plan_launch` with the same inputs and checking the result
//!   against `Ledger::generation`), and reconciles actual toward desired
//!   state. Supervised restarts use `Ledger::begin_epoch` directly.
//! - A stale plan cannot commit: the commit carries the revision the plan
//!   was made against, and the ledger checks the epoch.
//! - H1 publishes every state change as a [`HostEvent`] with a gap-free
//!   sequence number and keeps a [`HostView`] reflecting all events up to
//!   `HostView::seq`. H2 turns `seq` into contract cursors (with its
//!   `stream_id`), journals events for resumption, and serves snapshots.
//! - Commands flow in, events broadcast out, snapshots are read.
use crate::{auth::Authorizer, core_store::CoreStore};
use etd_contract::v1::{LeaseRelease, StreamLogsRequest, event};
use etd_contract::{
    ErrorDetail, HostMode, HostSnapshot, InstanceId, LogLine, NetworkSpec, QueryKind,
    QueryResponse, Receipt, Revision,
};
use etd_core_api::CoreDriver;
use etd_proc::{Clock, ProcessEngine, RestartPolicy};
use etd_sysfx::{
    BootIdSource, GenerationPlan, InstallKey, Ledger, PortFence, ReclaimEngine, RepairIndexStore,
    SystemObserver,
};
use futures_util::stream::BoxStream;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

/// Reply channel; the error is the contract's structured rejection.
pub type Reply<T> = oneshot::Sender<Result<T, ErrorDetail>>;

/// Kernel or host log lines for one `StreamLogs` call.
pub type LogStream = BoxStream<'static, LogLine>;

/// Who is connected, for the poll rate (about 1 s with subscribers, 30 s
/// health checks without) and for session-form host lifetime (leases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientPresence {
    pub connections: usize,
    pub subscribers: usize,
    pub lease_holders: usize,
}

/// H2 -> H1.
#[non_exhaustive]
pub enum Command {
    /// Before committing Apply, SetDesired(RUNNING) or RetryStart: plan the
    /// instance under this host form and the selected kernel. `spec` is the
    /// new configuration (Apply) or `None` for the stored one; `start` says
    /// whether desired state will be running after the mutation. Rejections
    /// (feature classes, guard, kernel) come back as `ErrorDetail`; nothing
    /// commits then.
    Plan {
        instance: InstanceId,
        spec: Option<Box<NetworkSpec>>,
        start: bool,
        reply: Reply<Planned>,
    },
    /// A mutation is durable; its ticket is pending in the ledger.
    Committed {
        receipt: Receipt,
    },
    /// A stop could not be committed (ledger unavailable). Cutting traffic
    /// does not depend on the ledger: kill the kernel anyway and show the
    /// instance as CUT_UNCONFIRMED until a retried stop commits. No receipt
    /// exists for this.
    Cut {
        instance: InstanceId,
        reply: Reply<()>,
    },
    Query {
        instance: InstanceId,
        kind: QueryKind,
        reply: Reply<QueryResponse>,
    },
    Logs {
        request: StreamLogsRequest,
        reply: Reply<LogStream>,
    },
    Clients(ClientPresence),
    /// A client handed back its lease. Replies whether the host will exit.
    ReleaseLease {
        instances: LeaseRelease,
        reply: Reply<bool>,
    },
    /// Stop accepting work, stop instances, reclaim, then reply.
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// Result of [`Command::Plan`].
#[derive(Debug, Clone, PartialEq)]
pub struct Planned {
    /// Single-writer claims of the configuration, for `Change::PutInstance`.
    pub claims: Vec<String>,
    /// The generation the mutation starts, to commit in the same
    /// transaction: present when `start` and the instance has no live or
    /// open generation; `None` when the start must wait (the running
    /// generation is stopped and reclaimed first, then the supervisor uses
    /// `Ledger::begin_epoch`).
    pub generation: Option<GenerationPlan>,
    /// Ledger revision the plan was computed against; H2 commits with this
    /// expected revision.
    pub revision: Revision,
}

/// H1 -> H2: one state change. `seq` increases by exactly one per event
/// within a host run.
#[derive(Debug, Clone, PartialEq)]
pub struct HostEvent {
    pub seq: u64,
    pub at_unix_ms: i64,
    pub payload: event::Payload,
}

/// H1's current state. `snapshot.cursor` is left unset; H2 fills it from
/// `seq` and its stream id. Secrets are already redacted.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HostView {
    /// Sequence number of the last event reflected in `snapshot`.
    pub seq: u64,
    pub snapshot: HostSnapshot,
}

/// The orchestrator went away (host shutting down).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("orchestrator closed")]
pub struct OrchestratorClosed;

/// H2's side.
#[derive(Clone)]
pub struct OrchestratorHandle {
    commands: mpsc::Sender<Command>,
    events: broadcast::Sender<HostEvent>,
    view: watch::Receiver<Arc<HostView>>,
}

impl OrchestratorHandle {
    pub async fn send(&self, command: Command) -> Result<(), OrchestratorClosed> {
        self.commands
            .send(command)
            .await
            .map_err(|_| OrchestratorClosed)
    }
    /// Events published after this call. A lagging receiver must resync.
    pub fn subscribe(&self) -> broadcast::Receiver<HostEvent> {
        self.events.subscribe()
    }
    pub fn view(&self) -> Arc<HostView> {
        self.view.borrow().clone()
    }
    pub fn watch_view(&self) -> watch::Receiver<Arc<HostView>> {
        self.view.clone()
    }
}

/// H1's side.
pub struct OrchestratorPort {
    pub commands: mpsc::Receiver<Command>,
    pub events: broadcast::Sender<HostEvent>,
    pub view: watch::Sender<Arc<HostView>>,
}

/// Connect H1 and H2. `capacity` bounds both the command queue and the
/// event broadcast buffer.
pub fn orchestrator_channel(
    capacity: usize,
    initial: HostView,
) -> (OrchestratorHandle, OrchestratorPort) {
    let (command_tx, command_rx) = mpsc::channel(capacity);
    let (event_tx, _) = broadcast::channel(capacity);
    let (view_tx, view_rx) = watch::channel(Arc::new(initial));
    (
        OrchestratorHandle {
            commands: command_tx,
            events: event_tx.clone(),
            view: view_rx,
        },
        OrchestratorPort {
            commands: command_rx,
            events: event_tx,
            view: view_tx,
        },
    )
}

/// New restart policy per instance.
pub type RestartPolicyFactory = Arc<dyn Fn() -> Box<dyn RestartPolicy> + Send + Sync>;

/// Host directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDirs {
    /// Ledger, repair index.
    pub state_dir: PathBuf,
    /// Root of `run/<instance>/<epoch>/`.
    pub run_dir: PathBuf,
    /// Protected kernel store.
    pub core_store_dir: PathBuf,
}

/// Every dependency of the host core, supplied by the composition root
/// (etd-host, HR) or by tests. Only trait objects: no adapter crate here.
pub struct HostDeps {
    pub mode: HostMode,
    pub dirs: HostDirs,
    pub process: Arc<dyn ProcessEngine>,
    pub restart_policy: RestartPolicyFactory,
    pub clock: Arc<dyn Clock>,
    pub ledger: Arc<dyn Ledger>,
    pub repair_index: Arc<dyn RepairIndexStore>,
    /// Built from `etd_sysfx::ReclaimDeps` (OS reclaimers plus this crate's
    /// `reclaimers` for Process and RuntimeDir).
    pub reclaim: Arc<dyn ReclaimEngine>,
    pub boot_id: Arc<dyn BootIdSource>,
    /// For `etd_sysfx::naming::interface_name`.
    pub install_key: InstallKey,
    pub observer: Arc<dyn SystemObserver>,
    /// `None` when the platform cannot fence.
    pub fence: Option<Arc<dyn PortFence>>,
    pub core: Arc<dyn CoreDriver>,
    pub core_store: Arc<dyn CoreStore>,
    pub authorizer: Arc<dyn Authorizer>,
}
