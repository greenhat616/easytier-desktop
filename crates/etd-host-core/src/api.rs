//! Frozen host-internal orchestration handle (F0): the interface between
//! the lifecycle orchestrator (H1: `lifecycle/`, `supervisor`, `boot`,
//! `poller`, `fence_seq`) and the contract service (H2: `service/`, `auth`,
//! `negotiate`, `events`, `core_store`).
//!
//! Division of work:
//! - H2 authenticates, authorises, validates (via [`Command::Validate`]),
//!   commits mutations to the ledger and answers with the receipt; then it
//!   tells H1 with [`Command::Committed`]. H1 executes accepted tickets
//!   (`Ledger::pending_tickets`) and reconciles actual toward desired state.
//! - H1 publishes every state change as a [`HostEvent`] with a gap-free
//!   sequence number and keeps a [`HostView`] reflecting all events up to
//!   `HostView::seq`. H2 turns `seq` into contract cursors (with its
//!   `stream_id`), journals events for resumption, and serves snapshots.
//! - Commands flow in, events broadcast out, snapshots are read.
use crate::{auth::Authorizer, core_store::CoreStore};
use etd_contract::v1::{LeaseRelease, StreamLogsRequest, event};
use etd_contract::{
    ErrorDetail, HostMode, HostSnapshot, InstanceId, LogLine, NetworkSpec, QueryKind,
    QueryResponse, Receipt,
};
use etd_core_api::CoreDriver;
use etd_proc::{Clock, ProcessEngine, RestartPolicy};
use etd_sysfx::{
    BootIdSource, Ledger, PortFence, Reclaimer, RepairIndexStore, Sweeper, SystemObserver,
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
    /// Before committing an Apply: classify the spec for this host form and
    /// selected kernel (plan_launch feature classes, single-writer claims
    /// against other instances). Unsupported -> rejection, nothing commits.
    Validate {
        instance: InstanceId,
        spec: Box<NetworkSpec>,
        reply: Reply<()>,
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
    pub reclaimers: Vec<Arc<dyn Reclaimer>>,
    pub sweeper: Arc<dyn Sweeper>,
    pub boot_id: Arc<dyn BootIdSource>,
    pub observer: Arc<dyn SystemObserver>,
    /// `None` when the platform cannot fence.
    pub fence: Option<Arc<dyn PortFence>>,
    pub core: Arc<dyn CoreDriver>,
    pub core_store: Arc<dyn CoreStore>,
    pub authorizer: Arc<dyn Authorizer>,
}
