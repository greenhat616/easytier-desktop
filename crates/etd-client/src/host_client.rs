//! Frozen client interface (F0): everything the UI and the CLI see of a host.
//! The gRPC implementation lives in `grpc.rs`, `reconnect.rs` and
//! `negotiate.rs` (C1).
use async_trait::async_trait;
use etd_contract::v1::{
    ApplyRequest, GetAllowListResponse, LeaseRelease, ListCoresResponse, PurgeAllDataRequest,
    ReleaseLeaseResponse, RemoveInstanceRequest, ResolveCandidatesRequest, RetryReclaimRequest,
    RetryStartRequest, SelectCoreRequest, SetAllowListRequest, SetDesiredRequest,
    StreamLogsRequest,
};
use etd_contract::{
    ErrorDetail, Event, EventCursor, HostSnapshot, InstanceId, LogLine, Negotiated, QueryKind,
    QueryResponse, Receipt, ReclaimReport, RequestId, Revision, Role,
};
use futures_util::stream::BoxStream;
use tokio::sync::watch;

/// Typed failure of a host call.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum CallError {
    /// Major versions differ: the UI enters its "upgrade the service" flow.
    #[error("host speaks contract {host_major}.{host_minor}; the service must be upgraded")]
    VersionMismatch { host_major: u32, host_minor: u32 },
    /// The host's Welcome did not list the capability this call needs.
    #[error("host does not offer capability {0}")]
    Unsupported(String),
    /// No connection (yet); the client keeps reconnecting in the background.
    #[error("host unavailable: {0}")]
    Unavailable(String),
    /// The endpoint is served by a process that failed server verification.
    #[error("host process failed verification: {0}")]
    HostNotVerified(String),
    #[error("caller lacks role {required:?}")]
    PermissionDenied { required: Role },
    #[error("administration requires an elevated token")]
    ElevationRequired,
    #[error("revision conflict; current revision is {current}")]
    Conflict { current: Revision },
    #[error("request id reused with different content")]
    RequestIdReused,
    /// Any other rejection, with the host's structured detail.
    #[error("rejected by host: {}", .0.message)]
    Rejected(ErrorDetail),
    /// The call or stream was cancelled locally (shutdown).
    #[error("cancelled")]
    Cancelled,
    /// gRPC or framing failure not covered above.
    #[error("transport error: {0}")]
    Transport(String),
}

/// Connection state, for "host reconnecting" and "upgrade required" hints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    Connecting,
    Connected(Box<Negotiated>),
    Reconnecting { attempt: u32 },
    UpgradeRequired { host_major: u32, host_minor: u32 },
    Closed,
}

/// The UI's whole world. Mutations take the contract request messages; the
/// caller fills `MutationHeader` (a fresh [`new_request_id`] per logical
/// request, reused verbatim on retry).
#[async_trait]
pub trait HostClient: Send + Sync {
    /// Result of the most recent handshake.
    fn negotiated(&self) -> Option<Negotiated>;
    fn connection(&self) -> watch::Receiver<ConnectionState>;
    async fn snapshot(&self) -> Result<HostSnapshot, CallError>;
    /// Events after `after` (or from now). Implementations reconnect and
    /// resume from the last delivered cursor without gaps or duplicates.
    fn subscribe(&self, after: Option<EventCursor>)
    -> BoxStream<'static, Result<Event, CallError>>;
    async fn apply(&self, req: ApplyRequest) -> Result<Receipt, CallError>;
    async fn set_desired(&self, req: SetDesiredRequest) -> Result<Receipt, CallError>;
    async fn remove_instance(&self, req: RemoveInstanceRequest) -> Result<Receipt, CallError>;
    /// Recovers the receipt of a mutation whose reply was lost.
    async fn receipt(&self, request_id: RequestId) -> Result<Option<Receipt>, CallError>;
    async fn query(&self, id: InstanceId, kind: QueryKind) -> Result<QueryResponse, CallError>;
    fn logs(&self, req: StreamLogsRequest) -> BoxStream<'static, Result<LogLine, CallError>>;
    async fn reclaim_report(&self) -> Result<ReclaimReport, CallError>;
    async fn retry_reclaim(&self, req: RetryReclaimRequest) -> Result<Receipt, CallError>;
    /// Manual restart of a GAVE_UP instance (resets the circuit breaker).
    async fn retry_start(&self, req: RetryStartRequest) -> Result<Receipt, CallError>;
    async fn resolve_candidates(&self, req: ResolveCandidatesRequest)
    -> Result<Receipt, CallError>;
    async fn release_lease(
        &self,
        instances: LeaseRelease,
    ) -> Result<ReleaseLeaseResponse, CallError>;
    async fn allow_list(&self) -> Result<GetAllowListResponse, CallError>;
    async fn set_allow_list(&self, req: SetAllowListRequest) -> Result<Receipt, CallError>;
    async fn cores(&self) -> Result<ListCoresResponse, CallError>;
    async fn select_core(&self, req: SelectCoreRequest) -> Result<Receipt, CallError>;
    async fn purge_all_data(&self, req: PurgeAllDataRequest) -> Result<Receipt, CallError>;
}

/// A fresh client-side request id (UUID v4).
pub fn new_request_id() -> RequestId {
    RequestId(uuid::Uuid::new_v4().to_string())
}
