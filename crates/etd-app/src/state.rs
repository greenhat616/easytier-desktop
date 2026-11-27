//! State store fed by snapshots and the event stream. Owned by A1.
//!
//! [`StateStore`] is the whole read model of the UI: views bind to it and
//! never talk to the host themselves. It never holds a network secret.
use crate::{LaunchError, Profile, SessionRefusal};
use etd_client::CallError;
use etd_contract::v1::{InstanceExited, ManagementAccess, Node, Notice, Route, TrafficStats};
use etd_contract::{
    Desired, DesiredInstance, ErrorCode, EventCursor, HostMode, HostPhase, InstanceId,
    InstanceState, InstanceStatus, Negotiated, NetworkSpec, QueryKind, Receipt, ReclaimReport,
    RequestId, Revision, capability,
};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

/// Notices kept for display; older ones are dropped.
pub const NOTICE_LIMIT: usize = 64;
/// Finished operations kept for display; unfinished ones are never dropped.
pub const FINISHED_OPERATION_LIMIT: usize = 32;

/// Upstream's default listener set (base port 11010 plus the per-scheme
/// offset), offered by the UI as a suggestion. A new configuration starts
/// with no listeners: the instance only dials out and hole-punches.
/// `faketcp` is left out because it installs a packet-filter driver.
pub const SUGGESTED_LISTENERS: [&str; 6] = [
    "tcp://0.0.0.0:11010",
    "udp://0.0.0.0:11010",
    "wg://0.0.0.0:11011",
    "quic://0.0.0.0:11012",
    "ws://0.0.0.0:11011",
    "wss://0.0.0.0:11012",
];

/// A fresh client-side instance id (canonical UUID v4, as the host requires).
pub fn new_instance_id() -> InstanceId {
    InstanceId(uuid::Uuid::new_v4().to_string())
}

/// Removes everything secret-related from a spec before it is kept anywhere.
pub fn scrub_secret(spec: &mut NetworkSpec) {
    spec.network_secret = None;
}

/// A network secret on its way to the host. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// What an Apply does with the secret. The UI never stores secrets, so the
/// view has to choose on every create or edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretInput {
    /// Keep what the host already holds (editing an existing instance).
    Keep,
    /// Remove the secret held by the host.
    Clear,
    /// Replace it with what the user just typed.
    Set(Secret),
}

/// How the UI currently relates to a host.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HostLink {
    /// Nothing was tried yet.
    #[default]
    Idle,
    /// A probe found no host: offer to install the service or start a user
    /// host.
    NoHost,
    /// Finding or starting a host of this form.
    Launching(HostMode),
    LaunchFailed(LaunchFailure),
    Connecting,
    Connected,
    /// "Host reconnecting": the data shown is the last known one.
    Reconnecting {
        attempt: u32,
    },
    UpgradeRequired {
        host_major: u32,
        host_minor: u32,
    },
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchFailureKind {
    NotInstalled,
    ElevationDenied,
    Unsupported,
    Spawn,
    Timeout,
    /// The elevated session host refused: the system service is installed.
    ServiceInstalled,
    /// The elevated session host refused: the user's session directory does
    /// not conform; an administrator has to delete it.
    SessionDirectory,
    /// The elevated session host refused: other users' sessions left system
    /// changes behind; offer the all-users clean-up.
    OtherUsersLeftovers,
    /// The session pipe name is held by a process that is not our elevated
    /// host (also: identity check of the session endpoint failed).
    EndpointOccupied,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchFailure {
    /// `None` when a probe (not a request for one form) failed.
    pub mode: Option<HostMode>,
    pub kind: LaunchFailureKind,
    pub message: String,
}

impl LaunchFailure {
    pub fn new(mode: Option<HostMode>, error: &LaunchError) -> Self {
        let kind = match error {
            LaunchError::NotInstalled => LaunchFailureKind::NotInstalled,
            LaunchError::ElevationDenied => LaunchFailureKind::ElevationDenied,
            LaunchError::Unsupported(_) => LaunchFailureKind::Unsupported,
            LaunchError::Spawn(_) => LaunchFailureKind::Spawn,
            LaunchError::Timeout => LaunchFailureKind::Timeout,
            LaunchError::SessionRefused(SessionRefusal::ServiceInstalled) => {
                LaunchFailureKind::ServiceInstalled
            }
            LaunchError::SessionRefused(SessionRefusal::NotConforming) => {
                LaunchFailureKind::SessionDirectory
            }
            LaunchError::SessionRefused(SessionRefusal::OtherUsersLeftovers) => {
                LaunchFailureKind::OtherUsersLeftovers
            }
            LaunchError::SessionRefused(SessionRefusal::EndpointOccupied) => {
                LaunchFailureKind::EndpointOccupied
            }
            _ => LaunchFailureKind::Other,
        };
        Self {
            mode,
            kind,
            message: error.to_string(),
        }
    }
}

impl LaunchFailure {
    /// What the user can do about it, in words they know (doc#13 #ipc: each
    /// failure told apart with an action). `None`: the message says it all.
    pub fn guidance(&self) -> Option<&'static str> {
        Some(match self.kind {
            LaunchFailureKind::ElevationDenied => {
                "Administrator permission was not given. Press Connect to be asked again."
            }
            LaunchFailureKind::ServiceInstalled => {
                "The EasyTier system service is installed on this computer. Connect through the service instead."
            }
            LaunchFailureKind::SessionDirectory => {
                "Your EasyTier session folder under %ProgramData%\\EasyTierDesk.session has the wrong owner or permissions. Ask an administrator to delete your folder there, then connect again."
            }
            LaunchFailureKind::OtherUsersLeftovers => {
                "Another user's EasyTier session left network changes behind. Clean them up (asks for administrator permission), then connect again."
            }
            LaunchFailureKind::EndpointOccupied => {
                "Another program is using EasyTier's connection name, or the program answering is not EasyTier. Restart the computer, or ask an administrator to find the program."
            }
            LaunchFailureKind::Unsupported if self.mode == Some(HostMode::ElevatedSession) => {
                "This account is not an administrator. Install the EasyTier system service (needs an administrator's password once)."
            }
            LaunchFailureKind::Spawn if self.mode == Some(HostMode::ElevatedSession) => {
                "The EasyTier host did not start. Press Connect to try again."
            }
            _ => return None,
        })
    }
}

/// Text for an operation the host refused with `ELEVATION_REQUIRED`: admin
/// operations need an elevated UI (msg#1408 ruling 3).
pub const ELEVATION_REQUIRED_GUIDANCE: &str = "Run EasyTier Desktop as administrator to do this.";

/// Whether the instance data can take further events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncState {
    /// No snapshot from this host yet.
    #[default]
    Empty,
    Synced,
    /// A new snapshot is needed; events are ignored until it arrives.
    Stale,
}

/// What the UI shows for an instance. [`Self::CutUnconfirmed`] is never
/// folded into [`Self::Stopped`]: the stop is not durable yet and the
/// instance may come back after a host restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstanceCondition {
    /// No status yet, or a state this build does not know.
    Unknown,
    Stopped,
    Starting,
    RunningBasic,
    Running,
    Stopping,
    Reclaiming,
    Backoff,
    GaveUp,
    Quarantined,
    CutUnconfirmed,
    /// The start is deferred until another instance frees a single-writer
    /// resource.
    Waiting,
}

impl From<InstanceState> for InstanceCondition {
    fn from(state: InstanceState) -> Self {
        match state {
            InstanceState::Stopped => Self::Stopped,
            InstanceState::Starting => Self::Starting,
            InstanceState::ReadyBasic => Self::RunningBasic,
            InstanceState::ReadyFull => Self::Running,
            InstanceState::Stopping => Self::Stopping,
            InstanceState::Reclaiming => Self::Reclaiming,
            InstanceState::Backoff => Self::Backoff,
            InstanceState::GaveUp => Self::GaveUp,
            InstanceState::Quarantined => Self::Quarantined,
            InstanceState::CutUnconfirmed => Self::CutUnconfirmed,
            InstanceState::Waiting => Self::Waiting,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstanceEntry {
    pub id: InstanceId,
    /// Desired configuration as the host reports it; never holds a secret.
    pub desired: Option<DesiredInstance>,
    pub status: Option<InstanceStatus>,
    pub last_exit: Option<InstanceExited>,
    /// Latest notice about this instance (e.g. why its start is deferred).
    pub notice: Option<Notice>,
}

impl InstanceEntry {
    pub fn new(id: InstanceId) -> Self {
        Self {
            id,
            desired: None,
            status: None,
            last_exit: None,
            notice: None,
        }
    }

    pub fn condition(&self) -> InstanceCondition {
        // An unknown wire value reads as `Unspecified`, never as stopped.
        self.status
            .as_ref()
            .map_or(InstanceCondition::Unknown, |status| status.state().into())
    }

    pub fn desired_state(&self) -> Desired {
        self.desired
            .as_ref()
            .map_or(Desired::Unspecified, DesiredInstance::desired)
    }

    pub fn display_name(&self) -> &str {
        self.desired
            .as_ref()
            .and_then(|desired| desired.spec.as_ref())
            .map(|spec| {
                if spec.display_name.is_empty() {
                    spec.network_name.as_str()
                } else {
                    spec.display_name.as_str()
                }
            })
            .filter(|name| !name.is_empty())
            .unwrap_or(self.id.as_str())
    }

    /// False for deny-all and lifecycle-only instances: the management pages
    /// are shown as unavailable.
    pub fn management_available(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|status| status.management() == ManagementAccess::Available)
    }

    /// Offer "retry confirm" for the stop that is not durable yet.
    pub fn needs_stop_confirm(&self) -> bool {
        self.condition() == InstanceCondition::CutUnconfirmed
    }

    pub fn can_retry_start(&self) -> bool {
        self.condition() == InstanceCondition::GaveUp
    }

    pub fn can_retry_reclaim(&self) -> bool {
        self.condition() == InstanceCondition::Quarantined
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NoticeEntry {
    pub at_unix_ms: i64,
    pub notice: Notice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Apply,
    Start,
    Stop,
    Remove,
    RetryStart,
    RetryReclaim,
    ResolveCandidates,
}

/// A host rejection or call failure, kept for display.
#[derive(Debug, Clone)]
pub struct Failure(pub CallError);

impl Failure {
    /// The contract error code, when the host sent one.
    pub fn code(&self) -> Option<ErrorCode> {
        match &self.0 {
            CallError::Rejected(detail) => Some(detail.code()),
            CallError::Conflict { .. } => Some(ErrorCode::RevisionConflict),
            CallError::RequestIdReused => Some(ErrorCode::RequestIdReused),
            CallError::ElevationRequired => Some(ErrorCode::ElevationRequired),
            CallError::PermissionDenied { .. } => Some(ErrorCode::PermissionDenied),
            _ => None,
        }
    }

    /// What the user can do about it, when there is something.
    pub fn guidance(&self) -> Option<&'static str> {
        (self.code() == Some(ErrorCode::ElevationRequired)).then_some(ELEVATION_REQUIRED_GUIDANCE)
    }
}

impl PartialEq for Failure {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.0) == format!("{:?}", other.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationStatus {
    Queued,
    Sending,
    /// The host durably accepted it; progress arrives as events.
    Accepted(Receipt),
    Failed(Failure),
    /// The reply was lost and the outcome is still unknown. Retrying resends
    /// the identical request, so it cannot take effect twice.
    Unconfirmed(Failure),
}

impl OperationStatus {
    pub fn is_finished(&self) -> bool {
        matches!(self, Self::Accepted(_) | Self::Failed(_))
    }
}

/// One mutation the user asked for.
#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub request_id: RequestId,
    pub kind: OperationKind,
    pub instance: Option<InstanceId>,
    pub status: OperationStatus,
}

/// Management data of the instance the user is looking at.
#[derive(Debug, Clone, PartialEq)]
pub struct WatchedInstance {
    pub id: InstanceId,
    pub nodes: Option<Vec<Node>>,
    pub routes: Option<Vec<Route>>,
    pub traffic: Option<TrafficStats>,
    /// Last failure per kind; cleared by the next success.
    pub errors: Vec<(QueryKind, Failure)>,
}

impl WatchedInstance {
    pub fn new(id: InstanceId) -> Self {
        Self {
            id,
            nodes: None,
            routes: None,
            traffic: None,
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct StateStore {
    pub link: HostLink,
    /// Last successful handshake; kept while reconnecting.
    pub negotiated: Option<Negotiated>,
    /// Set while the endpoint is served by a process that failed server
    /// verification. Nothing is sent to it.
    pub unverified_host: Option<String>,
    /// Set when restarting a vanished user host failed.
    pub relaunch_failure: Option<LaunchFailure>,
    /// The elevated session host this UI was connected to is gone (doc#13
    /// #sequence outcome 3). It is never restarted automatically: the user
    /// presses Connect (one UAC prompt) or cleans up the leftovers.
    pub session_host_exited: bool,
    pub sync: SyncState,
    /// Last event (or snapshot) reflected in the instance data.
    pub cursor: Option<EventCursor>,
    /// Latest revision observed; the next mutation expects it.
    pub revision: Revision,
    pub phase: HostPhase,
    pub default_core_version: String,
    pub instances: BTreeMap<InstanceId, InstanceEntry>,
    pub reclaim: ReclaimReport,
    pub notices: VecDeque<NoticeEntry>,
    pub operations: Vec<Operation>,
    pub profiles: Vec<Profile>,
    /// Loading or saving the profile library failed.
    pub profile_error: Option<String>,
    pub watched: Option<WatchedInstance>,
}

impl StateStore {
    /// "Host reconnecting" banner.
    pub fn is_reconnecting(&self) -> bool {
        matches!(self.link, HostLink::Reconnecting { .. })
    }

    pub fn has_capability(&self, name: &str) -> bool {
        self.negotiated
            .as_ref()
            .is_some_and(|negotiated| negotiated.has_capability(name))
    }

    /// Management pages to show: those the host's capability list offers.
    /// Whether one instance can fill them is
    /// [`InstanceEntry::management_available`].
    pub fn query_pages(&self) -> Vec<QueryKind> {
        [
            (QueryKind::Nodes, capability::QUERY_NODES),
            (QueryKind::Routes, capability::QUERY_ROUTES),
            (QueryKind::Traffic, capability::QUERY_TRAFFIC),
        ]
        .into_iter()
        .filter_map(|(kind, name)| self.has_capability(name).then_some(kind))
        .collect()
    }

    pub fn instance(&self, id: &InstanceId) -> Option<&InstanceEntry> {
        self.instances.get(id)
    }

    pub fn operation(&self, id: &RequestId) -> Option<&Operation> {
        self.operations.iter().find(|op| &op.request_id == id)
    }

    /// Adds or replaces an operation and trims old finished ones.
    pub(crate) fn put_operation(&mut self, operation: Operation) {
        match self
            .operations
            .iter_mut()
            .find(|op| op.request_id == operation.request_id)
        {
            Some(existing) => *existing = operation,
            None => self.operations.push(operation),
        }
        self.trim_operations();
    }

    pub(crate) fn set_operation_status(&mut self, id: &RequestId, status: OperationStatus) {
        if let Some(op) = self.operations.iter_mut().find(|op| &op.request_id == id) {
            op.status = status;
        }
        self.trim_operations();
    }

    fn trim_operations(&mut self) {
        let finished = self
            .operations
            .iter()
            .filter(|op| op.status.is_finished())
            .count();
        let mut excess = finished.saturating_sub(FINISHED_OPERATION_LIMIT);
        self.operations.retain(|op| {
            let drop = excess > 0 && op.status.is_finished();
            if drop {
                excess -= 1;
            }
            !drop
        });
    }

    /// Forgets everything learned from the current host, keeping what belongs
    /// to the user (profiles).
    pub(crate) fn reset_host_data(&mut self) {
        *self = Self {
            profiles: std::mem::take(&mut self.profiles),
            profile_error: self.profile_error.take(),
            ..Self::default()
        };
    }
}

/// Creates the client for a host the launcher found. Supplied by the
/// composition root; called on the background tokio runtime.
pub trait HostClientFactory: Send + Sync {
    fn connect(&self, target: &crate::HostTarget) -> std::sync::Arc<dyn etd_client::HostClient>;
}

/// UI-independent dependencies of the background application runtime.
pub struct AppServices {
    pub clients: std::sync::Arc<dyn HostClientFactory>,
    pub launcher: std::sync::Arc<dyn crate::HostLauncher>,
    pub profiles: std::sync::Arc<dyn crate::ProfileStore>,
}
