//! `GrpcHostClient`: the [`crate::HostClient`] implementation over tonic and
//! an [`etd_ipc::Connector`]; per-call version metadata. Owned by C1.
use crate::{
    CallError, ConnectionState, HostClient, negotiate,
    reconnect::{self, Session, Shared},
    stub::host_service_client::HostServiceClient,
};
use async_trait::async_trait;
use etd_contract::{
    ErrorCode, ErrorDetail, Event, EventCursor, HostSnapshot, InstanceId, LogLine, Negotiated,
    QueryKind, QueryResponse, Receipt, ReclaimReport, RequestId, Role, SERVICE_NAME,
    VERSION_METADATA_KEY, capability, required_role, v1::*, version_metadata_value,
};
use etd_ipc::{Connector, Endpoint};
use futures_util::{
    future::{Either, select},
    stream::{self, BoxStream},
};
use std::{error::Error as _, future::Future, pin::pin, sync::Arc, time::Duration};
use tokio::{sync::watch, time::timeout};
use tonic::{
    Code, Request, Response, Status, Streaming, metadata::MetadataValue,
    service::interceptor::InterceptedService, transport::Channel,
};
use tonic_prost::prost::Message;

/// Tuning of a [`GrpcHostClient`].
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub client_kind: ClientKind,
    /// Client build string, informational only.
    pub build: String,
    /// First reconnect delay; later ones double (plus jitter).
    pub backoff_min: Duration,
    /// Delay ceiling before jitter, which can at most double a delay.
    pub backoff_max: Duration,
    /// A connection that lasted this long resets the backoff.
    pub stable_after: Duration,
    /// Limit for connecting, verifying the host and the handshake together.
    pub connect_timeout: Duration,
    /// Limit for one unary call, and for opening a stream.
    pub request_timeout: Duration,
    /// How long a mutation with a lost reply waits to fetch its receipt.
    pub recovery_timeout: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            client_kind: ClientKind::Desktop,
            build: env!("CARGO_PKG_VERSION").into(),
            backoff_min: Duration::from_millis(200),
            backoff_max: Duration::from_secs(5),
            stable_after: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            recovery_timeout: Duration::from_secs(15),
        }
    }
}

/// Adds the contract version metadata to every call.
#[derive(Clone, Copy)]
pub(crate) struct VersionMetadata;

impl tonic::service::Interceptor for VersionMetadata {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let value = MetadataValue::try_from(version_metadata_value())
            .map_err(|_| Status::internal("invalid contract version metadata"))?;
        request.metadata_mut().insert(VERSION_METADATA_KEY, value);
        Ok(request)
    }
}

pub(crate) type Stub = HostServiceClient<InterceptedService<Channel, VersionMetadata>>;

/// How a call failed, as far as its effect on the host is concerned.
pub(crate) enum Failure {
    /// Never sent, or answered by the host: the outcome is known.
    Definite(CallError),
    /// The reply is missing: the host may or may not have acted.
    Ambiguous(CallError),
}

impl From<Failure> for CallError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Definite(error) | Failure::Ambiguous(error) => error,
        }
    }
}

fn error_detail(status: &Status) -> Option<ErrorDetail> {
    ErrorDetail::decode(status.details())
        .ok()
        .filter(|detail| detail.code() != ErrorCode::Unspecified)
}

/// True for a status which tells of a broken connection or a missing reply
/// rather than of a decision: it carries no [`ErrorDetail`].
pub(crate) fn is_transport(status: &Status) -> bool {
    error_detail(status).is_none()
        && matches!(
            status.code(),
            Code::Unavailable
                | Code::Unknown
                | Code::Internal
                | Code::Cancelled
                | Code::Aborted
                | Code::DeadlineExceeded
        )
}

pub(crate) fn call_error(method: &str, status: &Status) -> CallError {
    let Some(detail) = error_detail(status) else {
        // A connection that breaks under a call surfaces as `Unknown` with
        // the I/O error as its source.
        let broken = status.code() == Code::Unavailable
            || (status.code() == Code::Unknown && status.source().is_some());
        return if broken {
            CallError::Unavailable(status.message().to_owned())
        } else {
            CallError::Transport(format!("{:?}: {}", status.code(), status.message()))
        };
    };
    match detail.code() {
        ErrorCode::VersionMismatch => CallError::VersionMismatch {
            host_major: detail.host_major,
            host_minor: detail.host_minor,
        },
        ErrorCode::PermissionDenied => CallError::PermissionDenied {
            required: required_role(&format!("/{SERVICE_NAME}/{method}"))
                .unwrap_or(Role::Unspecified),
        },
        ErrorCode::ElevationRequired => CallError::ElevationRequired,
        ErrorCode::RevisionConflict => CallError::Conflict {
            current: detail.current_revision,
        },
        ErrorCode::RequestIdReused => CallError::RequestIdReused,
        _ => CallError::Rejected(detail),
    }
}

/// Runs one call on `session` under the request timeout and the client's
/// lifetime. A transport failure retires the session.
pub(crate) async fn bounded<T>(
    shared: &Shared,
    session: &Session,
    method: &str,
    call: impl Future<Output = Result<Response<T>, Status>>,
) -> Result<T, Failure> {
    let limited = timeout(shared.options.request_timeout, call);
    match shared.closed.run_until_cancelled(limited).await {
        None => Err(Failure::Definite(CallError::Cancelled)),
        Some(Err(_)) => Err(Failure::Ambiguous(CallError::Unavailable(format!(
            "{method} timed out"
        )))),
        Some(Ok(Ok(response))) => Ok(response.into_inner()),
        Some(Ok(Err(status))) => {
            let error = call_error(method, &status);
            if error_detail(&status).is_some() {
                return Err(Failure::Definite(error));
            }
            if matches!(status.code(), Code::Unavailable | Code::Unknown) {
                session.lost.cancel();
            }
            Err(if is_transport(&status) {
                Failure::Ambiguous(error)
            } else {
                Failure::Definite(error)
            })
        }
    }
}

/// The [`HostClient`] talking to a real host. It connects in the background
/// and keeps reconnecting until [`close`](Self::close) or drop.
///
/// While there is no connection, calls fail at once; watch
/// [`HostClient::connection`] to wait for one. The event stream instead rides
/// over reconnects. A mutation whose reply is lost fetches its receipt by
/// request id before giving up; it is never re-sent. After an error that
/// leaves the outcome unknown (`Unavailable`, `Transport`), retry with the
/// same request.
pub struct GrpcHostClient {
    shared: Arc<Shared>,
}

macro_rules! unary {
    ($self:ident, $method:literal, $capability:expr, $rpc:ident, $request:expr) => {{
        let session = $self.session($capability)?;
        let mut client = session.client.clone();
        bounded(&$self.shared, &session, $method, client.$rpc($request)).await
    }};
}

macro_rules! mutation {
    ($self:ident, $method:literal, $capability:expr, $rpc:ident, $request:ident) => {{
        let request_id = $request
            .header
            .as_ref()
            .map(|header| RequestId(header.request_id.clone()))
            .unwrap_or_else(|| RequestId(String::new()));
        let reply = unary!($self, $method, Some($capability), $rpc, $request);
        $self
            .settle(request_id, reply.map(|reply| reply.receipt))
            .await
    }};
}

impl GrpcHostClient {
    /// Starts connecting to `endpoint`. `connector` verifies the host's
    /// identity on every connection it opens.
    ///
    /// # Panics
    /// Outside a Tokio runtime.
    pub fn new(connector: Arc<dyn Connector>, endpoint: Endpoint, options: ClientOptions) -> Self {
        let shared = Arc::new(Shared::new(options));
        let task = shared.clone();
        tokio::spawn(async move {
            let closed = task.closed.clone();
            closed
                .run_until_cancelled(reconnect::supervise(task, connector, endpoint))
                .await;
        });
        Self { shared }
    }

    /// Ends every stream and pending call with [`CallError::Cancelled`] and
    /// drops the connection.
    pub fn close(&self) {
        self.shared.close();
    }

    fn session(&self, capability: Option<&str>) -> Result<Arc<Session>, CallError> {
        let session = self.shared.current()?;
        if let Some(name) = capability {
            negotiate::require(&session.negotiated, name)?;
        }
        Ok(session)
    }

    async fn settle(
        &self,
        request_id: RequestId,
        reply: Result<Option<Receipt>, Failure>,
    ) -> Result<Receipt, CallError> {
        match reply {
            Ok(receipt) => {
                receipt.ok_or_else(|| CallError::Transport("reply carried no receipt".to_owned()))
            }
            Err(Failure::Definite(error)) => Err(error),
            Err(Failure::Ambiguous(error)) => reconnect::recover_receipt(&self.shared, &request_id)
                .await
                .ok_or(error),
        }
    }
}

impl Drop for GrpcHostClient {
    fn drop(&mut self) {
        self.close();
    }
}

#[async_trait]
impl HostClient for GrpcHostClient {
    fn negotiated(&self) -> Option<Negotiated> {
        self.shared.negotiated.lock().unwrap().clone()
    }

    fn connection(&self) -> watch::Receiver<ConnectionState> {
        self.shared.state.subscribe()
    }

    async fn snapshot(&self) -> Result<HostSnapshot, CallError> {
        let reply = unary!(
            self,
            "Snapshot",
            Some(capability::INSTANCES),
            snapshot,
            SnapshotRequest {}
        );
        Ok(reply?)
    }

    fn subscribe(
        &self,
        after: Option<EventCursor>,
    ) -> BoxStream<'static, Result<Event, CallError>> {
        reconnect::subscribe(self.shared.clone(), after)
    }

    async fn apply(&self, req: ApplyRequest) -> Result<Receipt, CallError> {
        mutation!(self, "Apply", capability::INSTANCES, apply, req)
    }

    async fn set_desired(&self, req: SetDesiredRequest) -> Result<Receipt, CallError> {
        mutation!(self, "SetDesired", capability::INSTANCES, set_desired, req)
    }

    async fn remove_instance(&self, req: RemoveInstanceRequest) -> Result<Receipt, CallError> {
        mutation!(
            self,
            "RemoveInstance",
            capability::INSTANCES,
            remove_instance,
            req
        )
    }

    async fn receipt(&self, request_id: RequestId) -> Result<Option<Receipt>, CallError> {
        let request = GetReceiptRequest {
            request_id: request_id.0,
        };
        let reply = unary!(
            self,
            "GetReceipt",
            Some(capability::INSTANCES),
            get_receipt,
            request
        );
        Ok(reply?.receipt)
    }

    async fn query(&self, id: InstanceId, kind: QueryKind) -> Result<QueryResponse, CallError> {
        let request = QueryRequest {
            instance_id: id.0,
            kind: kind as i32,
        };
        let reply = unary!(
            self,
            "Query",
            negotiate::query_capability(kind),
            query,
            request
        );
        Ok(reply?)
    }

    // Log lines have no cursor, so a broken stream is reported instead of
    // being resumed: resuming would repeat or drop lines.
    fn logs(&self, req: StreamLogsRequest) -> BoxStream<'static, Result<LogLine, CallError>> {
        let start = self.session(Some(capability::LOGS));
        let logs = Logs::Opening(start, Box::new(req));
        let shared = self.shared.clone();
        Box::pin(stream::unfold(Some(logs), move |state| {
            let shared = shared.clone();
            async move { next_log(shared, state?).await }
        }))
    }

    async fn reclaim_report(&self) -> Result<ReclaimReport, CallError> {
        let reply = unary!(
            self,
            "GetReclaimReport",
            Some(capability::RECLAIM),
            get_reclaim_report,
            GetReclaimReportRequest {}
        );
        Ok(reply?)
    }

    async fn retry_reclaim(&self, req: RetryReclaimRequest) -> Result<Receipt, CallError> {
        mutation!(
            self,
            "RetryReclaim",
            capability::RECLAIM,
            retry_reclaim,
            req
        )
    }

    async fn retry_start(&self, req: RetryStartRequest) -> Result<Receipt, CallError> {
        mutation!(self, "RetryStart", capability::INSTANCES, retry_start, req)
    }

    async fn resolve_candidates(
        &self,
        req: ResolveCandidatesRequest,
    ) -> Result<Receipt, CallError> {
        mutation!(
            self,
            "ResolveCandidates",
            capability::RECLAIM_CANDIDATES,
            resolve_candidates,
            req
        )
    }

    async fn release_lease(
        &self,
        instances: LeaseRelease,
    ) -> Result<ReleaseLeaseResponse, CallError> {
        let request = ReleaseLeaseRequest {
            instances: instances as i32,
        };
        let reply = unary!(
            self,
            "ReleaseLease",
            Some(capability::LEASE),
            release_lease,
            request
        );
        Ok(reply?)
    }

    async fn allow_list(&self) -> Result<GetAllowListResponse, CallError> {
        let reply = unary!(
            self,
            "GetAllowList",
            Some(capability::ADMIN_ALLOW_LIST),
            get_allow_list,
            GetAllowListRequest {}
        );
        Ok(reply?)
    }

    async fn set_allow_list(&self, req: SetAllowListRequest) -> Result<Receipt, CallError> {
        mutation!(
            self,
            "SetAllowList",
            capability::ADMIN_ALLOW_LIST,
            set_allow_list,
            req
        )
    }

    async fn cores(&self) -> Result<ListCoresResponse, CallError> {
        let reply = unary!(
            self,
            "ListCores",
            Some(capability::ADMIN_CORES),
            list_cores,
            ListCoresRequest {}
        );
        Ok(reply?)
    }

    async fn select_core(&self, req: SelectCoreRequest) -> Result<Receipt, CallError> {
        mutation!(
            self,
            "SelectCore",
            capability::ADMIN_CORES,
            select_core,
            req
        )
    }

    async fn purge_all_data(&self, req: PurgeAllDataRequest) -> Result<Receipt, CallError> {
        mutation!(
            self,
            "PurgeAllData",
            capability::ADMIN_PURGE,
            purge_all_data,
            req
        )
    }
}

enum Logs {
    Opening(Result<Arc<Session>, CallError>, Box<StreamLogsRequest>),
    Open(Arc<Session>, Box<Streaming<LogLine>>),
}

async fn next_log(
    shared: Arc<Shared>,
    mut logs: Logs,
) -> Option<(Result<LogLine, CallError>, Option<Logs>)> {
    loop {
        logs = match logs {
            Logs::Opening(Err(error), _) => return Some((Err(error), None)),
            Logs::Opening(Ok(session), request) => {
                let mut client = session.client.clone();
                let call = client.stream_logs(*request);
                match bounded(&shared, &session, "StreamLogs", call).await {
                    Ok(lines) => Logs::Open(session, Box::new(lines)),
                    Err(failure) => return Some((Err(failure.into()), None)),
                }
            }
            Logs::Open(session, mut lines) => {
                let received = {
                    let message = pin!(lines.message());
                    let closed = pin!(shared.closed.cancelled());
                    match select(closed, message).await {
                        Either::Left(_) => return Some((Err(CallError::Cancelled), None)),
                        Either::Right((received, _)) => received,
                    }
                };
                return match received {
                    Ok(Some(line)) => Some((Ok(line), Some(Logs::Open(session, lines)))),
                    Ok(None) => None,
                    Err(status) => {
                        let error = if is_transport(&status) {
                            CallError::Unavailable(status.message().to_owned())
                        } else {
                            call_error("StreamLogs", &status)
                        };
                        Some((Err(error), None))
                    }
                };
            }
        };
    }
}
