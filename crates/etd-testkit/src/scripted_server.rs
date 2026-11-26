//! Scripted `etd.v1.HostService` server for client tests. Owned by C1.
//!
//! [`ScriptedHost`] runs the real tonic server stubs over in-memory
//! connections obtained from [`ScriptedHost::connector`]. It keeps the parts
//! of the host semantics a client depends on (version metadata, idempotent
//! mutations by request id, receipts, event resume by cursor with
//! `ResyncRequired`) and lets a test script the rest: the Welcome, canned
//! replies and rejections, lost replies, dropped connections and an
//! unreachable or impostor host.
//!
//! [`ContractHost`] puts the real contract service on the same in-memory
//! connections, to hold the client against the host's own semantics.
use crate::fakes::{ledger::MemoryLedger, store::FakeCoreStore};
use async_trait::async_trait;
use etd_contract::{
    ErrorCode, ErrorDetail, Event, EventCursor, HostMode, HostPhase, HostSnapshot, LogLine, Role,
    VERSION_MAJOR, VERSION_METADATA_KEY, VERSION_MINOR, Welcome, capability,
    parse_version_metadata, v1::*,
};
use etd_host_core::{
    api::{HostEvent, HostView, OrchestratorPort, orchestrator_channel},
    auth::allow_list::AllowListAuthorizer,
    service::ContractService,
    stub::host_service_server::{HostService, HostServiceServer},
};
use etd_ipc::{
    BoxConn, Connector, Endpoint, Listener, OsUserId, PeerIdentity, ServerIdentity,
    tonic_io::incoming,
};
use etd_sysfx::InstallKey;
use futures_util::{
    StreamExt,
    stream::{self, BoxStream},
};
use prost::Message;
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::{
    io::copy_bidirectional,
    sync::{mpsc, watch},
    time::Instant,
};
use tonic::{Code, Request, Response, Status, transport::Server};

const BUFFER: usize = 64 * 1024;

/// Every capability of contract 1.0.
pub fn all_capabilities() -> Vec<String> {
    [
        capability::INSTANCES,
        capability::QUERY_NODES,
        capability::QUERY_ROUTES,
        capability::QUERY_TRAFFIC,
        capability::LOGS,
        capability::RECLAIM,
        capability::RECLAIM_CANDIDATES,
        capability::LEASE,
        capability::ADMIN_ALLOW_LIST,
        capability::ADMIN_CORES,
        capability::ADMIN_PURGE,
        capability::TUN,
    ]
    .map(str::to_owned)
    .to_vec()
}

/// A rejection encoded the way a host encodes it.
pub fn rejection(code: Code, detail: ErrorDetail) -> Status {
    Status::with_details(code, detail.message.clone(), detail.encode_to_vec().into())
}

fn rejected(code: Code, error: ErrorCode) -> Status {
    rejection(
        code,
        ErrorDetail {
            code: error as i32,
            message: format!("scripted {error:?}"),
            ..Default::default()
        },
    )
}

/// One request as the server received it.
#[derive(Debug, Clone)]
pub struct Call {
    /// RPC name, e.g. `"Apply"`.
    pub method: &'static str,
    /// Every value of the version metadata entry.
    pub version_metadata: Vec<String>,
}

/// What happens to the reply of the next call of a method.
#[derive(Debug, Clone)]
enum Fault {
    /// Answer with this status; nothing is executed.
    Fail(Status),
    /// Act on the request, then drop every connection instead of answering.
    LoseReply,
    /// Drop every connection before acting on the request.
    DropRequest,
    /// Never answer.
    Hang,
}

struct Accepted {
    method: &'static str,
    content: Vec<u8>,
    receipt: etd_contract::Receipt,
}

struct Script {
    welcome: Welcome,
    snapshot: HostSnapshot,
    /// Every event emitted on the current stream id, in order.
    events: Vec<Event>,
    seq: u64,
    /// Cursors older than this can no longer be resumed.
    oldest_resumable: u64,
    /// Events sent again on resume, before the new ones.
    replay_overlap: u64,
    /// Bumped to end every open event stream cleanly.
    stream_epoch: u64,
    subscriptions: Vec<Option<EventCursor>>,
    revision: u64,
    receipts: HashMap<String, Accepted>,
    executed: Vec<String>,
    logs: Vec<LogLine>,
    calls: Vec<Call>,
    faults: HashMap<&'static str, VecDeque<Fault>>,
    refusing: bool,
    impostor: bool,
    /// Refuse every connection after the next reply is lost.
    stay_down_after_loss: bool,
    dials: Vec<Instant>,
}

struct Shared {
    script: Mutex<Script>,
    changed: watch::Sender<u64>,
    wire: Wire,
}

impl Shared {
    fn script(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap()
    }

    fn notify(&self) {
        self.changed.send_modify(|version| *version += 1);
    }
}

/// A scripted host. Cloning gives another handle to the same host.
#[derive(Clone)]
pub struct ScriptedHost {
    shared: Arc<Shared>,
}

impl ScriptedHost {
    /// Starts serving with every capability, the admin role and an empty
    /// state. Must be called inside a Tokio runtime.
    pub fn start() -> Self {
        let (wire, listener) = Wire::new();
        let welcome = Welcome {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            capabilities: all_capabilities(),
            role: Role::Admin as i32,
            host_build: "scripted".into(),
            host_mode: HostMode::Service as i32,
            phase: HostPhase::Serving as i32,
            stream_id: "stream-1".into(),
        };
        let host = Self {
            shared: Arc::new(Shared {
                script: Mutex::new(Script {
                    welcome,
                    snapshot: HostSnapshot {
                        phase: HostPhase::Serving as i32,
                        ..Default::default()
                    },
                    events: Vec::new(),
                    seq: 0,
                    oldest_resumable: 0,
                    replay_overlap: 0,
                    stream_epoch: 0,
                    subscriptions: Vec::new(),
                    revision: 0,
                    receipts: HashMap::new(),
                    executed: Vec::new(),
                    logs: Vec::new(),
                    calls: Vec::new(),
                    faults: HashMap::new(),
                    refusing: false,
                    impostor: false,
                    stay_down_after_loss: false,
                    dials: Vec::new(),
                }),
                changed: watch::Sender::new(0),
                wire,
            }),
        };
        let service = host.service();
        tokio::spawn(
            Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming(listener)),
        );
        host
    }

    /// The service itself, to serve it over a real listener. The faults and
    /// connection switches act on the in-memory connections only.
    pub fn service(&self) -> HostServiceServer<ScriptedService> {
        HostServiceServer::new(ScriptedService {
            shared: Arc::downgrade(&self.shared),
        })
    }

    /// Opens in-memory connections to this host.
    pub fn connector(&self) -> Arc<dyn Connector> {
        Arc::new(MemoryConnector(self.shared.clone()))
    }

    /// A placeholder; the in-memory connector ignores the endpoint.
    pub fn endpoint() -> Endpoint {
        Endpoint::NamedPipe("scripted-host".into())
    }

    /// Changes what the next handshakes answer.
    pub fn edit_welcome(&self, edit: impl FnOnce(&mut Welcome)) {
        edit(&mut self.shared.script().welcome);
    }

    pub fn set_capabilities(&self, names: &[&str]) {
        self.edit_welcome(|welcome| {
            welcome.capabilities = names.iter().map(|name| (*name).to_owned()).collect();
        });
    }

    /// Sets the snapshot; its cursor and revision are filled in per request.
    pub fn set_snapshot(&self, snapshot: HostSnapshot) {
        self.shared.script().snapshot = snapshot;
    }

    pub fn set_logs(&self, lines: Vec<LogLine>) {
        self.shared.script().logs = lines;
    }

    /// Emits the next event of the stream and returns its sequence number.
    pub fn emit(&self, payload: etd_contract::v1::event::Payload) -> u64 {
        let seq = {
            let mut script = self.shared.script();
            script.seq += 1;
            let event = Event {
                cursor: Some(EventCursor {
                    stream_id: script.welcome.stream_id.clone(),
                    seq: script.seq,
                }),
                at_unix_ms: script.seq as i64,
                payload: Some(payload),
            };
            script.events.push(event);
            script.seq
        };
        self.shared.notify();
        seq
    }

    /// Emits a numbered informational notice.
    pub fn emit_notice(&self) -> u64 {
        self.emit(etd_contract::v1::event::Payload::Notice(Notice {
            level: NoticeLevel::Info as i32,
            code: "scripted".into(),
            ..Default::default()
        }))
    }

    /// Forgets history: cursors before `seq` now require a resync.
    pub fn retain_from(&self, seq: u64) {
        self.shared.script().oldest_resumable = seq;
    }

    /// Makes every resumed stream send the last `events` events again.
    pub fn replay_overlap(&self, events: u64) {
        self.shared.script().replay_overlap = events;
    }

    /// Ends every open event stream cleanly, keeping connections up.
    pub fn end_streams(&self) {
        self.shared.script().stream_epoch += 1;
        self.shared.notify();
    }

    /// A new host run: new stream id, empty journal, connections dropped.
    /// Receipts and the revision survive, as they live in the ledger.
    pub fn restart(&self, stream_id: &str) {
        {
            let mut script = self.shared.script();
            script.welcome.stream_id = stream_id.to_owned();
            script.events.clear();
            script.seq = 0;
            script.oldest_resumable = 0;
        }
        self.shared.wire.cut();
    }

    /// Drops every current connection; new ones are accepted.
    pub fn disconnect(&self) {
        self.shared.wire.cut();
    }

    /// While refusing, connecting fails like a missing or restarting host.
    pub fn set_refusing(&self, refusing: bool) {
        self.shared.script().refusing = refusing;
    }

    /// While set, connecting fails like a failed server verification.
    pub fn set_impostor(&self, impostor: bool) {
        self.shared.script().impostor = impostor;
    }

    fn push_fault(&self, method: &'static str, fault: Fault) {
        self.shared
            .script()
            .faults
            .entry(method)
            .or_default()
            .push_back(fault);
    }

    /// The next `method` call is rejected with `status`.
    pub fn fail_next(&self, method: &'static str, status: Status) {
        self.push_fault(method, Fault::Fail(status));
    }

    /// The next `method` call takes effect, but the connection drops instead
    /// of the reply.
    pub fn lose_next_reply(&self, method: &'static str) {
        self.push_fault(method, Fault::LoseReply);
    }

    /// The connection drops before the next `method` call takes effect.
    pub fn drop_next_request(&self, method: &'static str) {
        self.push_fault(method, Fault::DropRequest);
    }

    /// The next `method` call is never answered.
    pub fn hang_next(&self, method: &'static str) {
        self.push_fault(method, Fault::Hang);
    }

    /// With the next lost reply the host also becomes unreachable, until
    /// `set_refusing(false)`.
    pub fn stay_down_after_loss(&self) {
        self.shared.script().stay_down_after_loss = true;
    }

    pub fn calls(&self) -> Vec<Call> {
        self.shared.script().calls.clone()
    }

    pub fn count(&self, method: &str) -> usize {
        self.shared
            .script()
            .calls
            .iter()
            .filter(|call| call.method == method)
            .count()
    }

    /// Request ids of the mutations that took effect, in order.
    pub fn executed(&self) -> Vec<String> {
        self.shared.script().executed.clone()
    }

    /// The `after` cursor of every Subscribe request.
    pub fn subscriptions(&self) -> Vec<Option<EventCursor>> {
        self.shared.script().subscriptions.clone()
    }

    /// When each connection attempt was made.
    pub fn dials(&self) -> Vec<Instant> {
        self.shared.script().dials.clone()
    }

    pub fn revision(&self) -> u64 {
        self.shared.script().revision
    }
}

/// The in-memory endpoint: all its connections can be cut at once.
struct Wire {
    accept: mpsc::UnboundedSender<BoxConn>,
    /// Set and replaced to drop every current connection.
    cut: Mutex<watch::Sender<bool>>,
}

impl Wire {
    fn new() -> (Self, MemoryListener) {
        let (accept, incoming) = mpsc::unbounded_channel();
        let wire = Self {
            accept,
            cut: Mutex::new(watch::Sender::new(false)),
        };
        (wire, MemoryListener(incoming))
    }

    fn open(&self) -> io::Result<(BoxConn, ServerIdentity)> {
        let mut cut = self.cut.lock().unwrap().subscribe();
        let (client, mut near) = tokio::io::duplex(BUFFER);
        let (mut far, server) = tokio::io::duplex(BUFFER);
        // Dropping the relay's two ends is how a connection gets cut.
        tokio::spawn(async move {
            tokio::select! {
                _ = cut.wait_for(|cut| *cut) => {}
                _ = copy_bidirectional(&mut near, &mut far) => {}
            }
        });
        self.accept
            .send(Box::new(server))
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionRefused, "host stopped"))?;
        Ok((
            Box::new(client),
            ServerIdentity {
                peer: local_peer(),
                exe: "scripted-host".into(),
            },
        ))
    }

    fn cut(&self) {
        std::mem::replace(&mut *self.cut.lock().unwrap(), watch::Sender::new(false))
            .send_replace(true);
    }
}

struct MemoryListener(mpsc::UnboundedReceiver<BoxConn>);

fn local_user() -> OsUserId {
    OsUserId::UnixUid(1000)
}

fn local_peer() -> PeerIdentity {
    PeerIdentity {
        user: local_user(),
        groups: Vec::new(),
        pid: 1,
        session: None,
        elevated: true,
    }
}

#[async_trait]
impl Listener for MemoryListener {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)> {
        match self.0.recv().await {
            Some(conn) => Ok((conn, local_peer())),
            None => std::future::pending().await,
        }
    }
}

struct MemoryConnector(Arc<Shared>);

#[async_trait]
impl Connector for MemoryConnector {
    async fn connect(&self, _: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)> {
        {
            let mut script = self.0.script();
            script.dials.push(Instant::now());
            if script.impostor {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "scripted impostor",
                ));
            }
            if script.refusing {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "scripted refusal",
                ));
            }
        }
        self.0.wire.open()
    }
}

/// The real [`ContractService`] of a user host, with the in-memory ledger,
/// reachable through in-memory connections. The test plays the orchestrator.
pub struct ContractHost {
    wire: Arc<Wire>,
    port: OrchestratorPort,
}

impl ContractHost {
    /// Must be called inside a Tokio runtime.
    pub async fn start(capabilities: Vec<String>) -> Self {
        let ledger = Arc::new(MemoryLedger::default());
        let authorizer = Arc::new(AllowListAuthorizer::new(HostMode::User, Some(local_user())));
        authorizer
            .load(ledger.as_ref())
            .await
            .expect("an empty ledger loads");
        let view = HostView {
            seq: 0,
            snapshot: HostSnapshot {
                phase: HostPhase::Serving as i32,
                ..Default::default()
            },
        };
        let (handle, port) = orchestrator_channel(64, view);
        let service = ContractService::new(
            HostMode::User,
            ledger,
            InstallKey([0; 32]),
            authorizer,
            Arc::new(FakeCoreStore::default()),
            handle,
            capabilities,
            4,
        );
        let (wire, listener) = Wire::new();
        tokio::spawn(
            Server::builder()
                .add_service(HostServiceServer::new(service))
                .serve_with_incoming(incoming(listener)),
        );
        Self {
            wire: Arc::new(wire),
            port,
        }
    }

    pub fn connector(&self) -> Arc<dyn Connector> {
        Arc::new(WireConnector(self.wire.clone()))
    }

    pub fn disconnect(&self) {
        self.wire.cut();
    }

    /// Publishes event `seq` the way the orchestrator does. The service's
    /// journal keeps the last four.
    pub fn emit(&self, seq: u64) {
        let _ = self.port.events.send(HostEvent {
            seq,
            at_unix_ms: seq as i64,
            payload: event::Payload::Notice(Notice::default()),
        });
        self.port
            .view
            .send_modify(|view| Arc::make_mut(view).seq = seq);
    }
}

struct WireConnector(Arc<Wire>);

#[async_trait]
impl Connector for WireConnector {
    async fn connect(&self, _: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)> {
        self.0.open()
    }
}

/// The `HostService` implementation behind a [`ScriptedHost`].
pub struct ScriptedService {
    shared: std::sync::Weak<Shared>,
}

/// Loses the reply the way a broken connection does.
async fn lose_reply<T>(shared: &Shared) -> T {
    if std::mem::take(&mut shared.script().stay_down_after_loss) {
        shared.script().refusing = true;
    }
    shared.wire.cut();
    std::future::pending().await
}

/// What a handler must still do once it has acted.
enum Reply {
    Send,
    Lose(Arc<Shared>),
}

impl Reply {
    async fn deliver<T>(self, reply: Result<T, Status>) -> Result<Response<T>, Status> {
        match self {
            Self::Send => reply.map(Response::new),
            Self::Lose(shared) => lose_reply(&shared).await,
        }
    }
}

impl ScriptedService {
    fn shared(&self) -> Result<Arc<Shared>, Status> {
        self.shared
            .upgrade()
            .ok_or_else(|| Status::unavailable("scripted host is gone"))
    }

    /// Records the call, applies a scripted fault and checks the version.
    async fn enter<T>(
        &self,
        method: &'static str,
        request: &Request<T>,
    ) -> Result<(Arc<Shared>, Reply), Status> {
        let shared = self.shared()?;
        let values: Vec<String> = request
            .metadata()
            .get_all(VERSION_METADATA_KEY)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect();
        let fault = {
            let mut script = shared.script();
            script.calls.push(Call {
                method,
                version_metadata: values.clone(),
            });
            script.faults.get_mut(method).and_then(VecDeque::pop_front)
        };
        let lose = match fault {
            Some(Fault::Fail(status)) => return Err(status),
            Some(Fault::Hang) => std::future::pending().await,
            Some(Fault::DropRequest) => lose_reply(&shared).await,
            Some(Fault::LoseReply) => true,
            None => false,
        };
        check_metadata(&values)?;
        let reply = if lose {
            Reply::Lose(shared.clone())
        } else {
            Reply::Send
        };
        Ok((shared, reply))
    }

    /// Idempotent by request id, as the host's ledger is.
    async fn mutate<T: Message + Clone, R>(
        &self,
        method: &'static str,
        request: Request<T>,
        header: impl FnOnce(&T) -> Option<MutationHeader>,
        wrap: impl FnOnce(Option<etd_contract::Receipt>) -> R,
    ) -> Result<Response<R>, Status> {
        let (shared, reply) = self.enter(method, &request).await?;
        let body = request.into_inner();
        let outcome = header(&body)
            .ok_or_else(|| rejected(Code::InvalidArgument, ErrorCode::InvalidSpec))
            .and_then(|header| commit(&mut shared.script(), method, header, body.encode_to_vec()));
        reply
            .deliver(outcome.map(|receipt| wrap(Some(receipt))))
            .await
    }

    async fn answer<T, R>(
        &self,
        method: &'static str,
        request: Request<T>,
        make: impl FnOnce(&mut Script, T) -> Result<R, Status>,
    ) -> Result<Response<R>, Status> {
        let (shared, reply) = self.enter(method, &request).await?;
        let outcome = make(&mut shared.script(), request.into_inner());
        reply.deliver(outcome).await
    }
}

fn check_metadata(values: &[String]) -> Result<(), Status> {
    let [value] = values else {
        return Err(rejected(Code::InvalidArgument, ErrorCode::VersionMetadata));
    };
    match parse_version_metadata(value) {
        Some((major, _)) if major == VERSION_MAJOR => Ok(()),
        Some(_) => Err(rejected(
            Code::FailedPrecondition,
            ErrorCode::VersionMismatch,
        )),
        None => Err(rejected(Code::InvalidArgument, ErrorCode::VersionMetadata)),
    }
}

fn commit(
    script: &mut Script,
    method: &'static str,
    header: MutationHeader,
    content: Vec<u8>,
) -> Result<etd_contract::Receipt, Status> {
    if let Some(accepted) = script.receipts.get(&header.request_id) {
        return if accepted.method == method && accepted.content == content {
            Ok(accepted.receipt.clone())
        } else {
            Err(rejected(Code::InvalidArgument, ErrorCode::RequestIdReused))
        };
    }
    if header.expected_revision != script.revision {
        return Err(rejection(
            Code::Aborted,
            ErrorDetail {
                code: ErrorCode::RevisionConflict as i32,
                message: "scripted conflict".into(),
                current_revision: script.revision,
                ..Default::default()
            },
        ));
    }
    script.revision += 1;
    let receipt = etd_contract::Receipt {
        request_id: header.request_id.clone(),
        revision: script.revision,
        ticket: format!("ticket-{}", script.revision),
        accepted_unix_ms: script.revision as i64,
    };
    script.executed.push(header.request_id.clone());
    script.receipts.insert(
        header.request_id,
        Accepted {
            method,
            content,
            receipt: receipt.clone(),
        },
    );
    Ok(receipt)
}

/// Sends the events after `after`, then follows the journal.
fn event_stream(
    shared: &Arc<Shared>,
    after: Option<EventCursor>,
) -> BoxStream<'static, Result<Event, Status>> {
    let (start, resync, stream_id, epoch) = {
        let mut script = shared.script();
        script.subscriptions.push(after.clone());
        let stream_id = script.welcome.stream_id.clone();
        let (start, resync) = match &after {
            None => (script.seq, false),
            Some(cursor) => (
                cursor.seq.saturating_sub(script.replay_overlap),
                cursor.stream_id != stream_id
                    || cursor.seq > script.seq
                    || cursor.seq < script.oldest_resumable,
            ),
        };
        (start, resync, stream_id, script.stream_epoch)
    };
    if resync {
        let seq = shared.script().seq;
        let event = Event {
            cursor: Some(EventCursor { stream_id, seq }),
            at_unix_ms: 0,
            payload: Some(event::Payload::ResyncRequired(ResyncRequired {
                reason: "scripted".into(),
            })),
        };
        return stream::iter([Ok(event)]).boxed();
    }
    let weak = Arc::downgrade(shared);
    let changed = shared.changed.subscribe();
    stream::unfold(
        (weak, changed, start),
        move |(weak, mut changed, last)| async move {
            loop {
                changed.borrow_and_update();
                let next = {
                    let shared = weak.upgrade()?;
                    let script = shared.script();
                    if script.stream_epoch != epoch {
                        return None;
                    }
                    script.events.iter().find_map(|event| {
                        let seq = event.cursor.as_ref()?.seq;
                        (seq > last).then(|| (event.clone(), seq))
                    })
                };
                if let Some((event, seq)) = next {
                    return Some((Ok(event), (weak, changed, seq)));
                }
                changed.changed().await.ok()?;
            }
        },
    )
    .boxed()
}

#[tonic::async_trait]
impl HostService for ScriptedService {
    async fn handshake(&self, request: Request<Hello>) -> Result<Response<Welcome>, Status> {
        self.answer("Handshake", request, |script, _| Ok(script.welcome.clone()))
            .await
    }

    async fn snapshot(
        &self,
        request: Request<SnapshotRequest>,
    ) -> Result<Response<HostSnapshot>, Status> {
        self.answer("Snapshot", request, |script, _| {
            let mut snapshot = script.snapshot.clone();
            snapshot.revision = script.revision;
            snapshot.cursor = Some(EventCursor {
                stream_id: script.welcome.stream_id.clone(),
                seq: script.seq,
            });
            Ok(snapshot)
        })
        .await
    }

    type SubscribeStream = BoxStream<'static, Result<Event, Status>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (shared, reply) = self.enter("Subscribe", &request).await?;
        let events = event_stream(&shared, request.into_inner().after);
        reply.deliver(Ok(events)).await
    }

    async fn apply(
        &self,
        request: Request<ApplyRequest>,
    ) -> Result<Response<ApplyResponse>, Status> {
        self.mutate(
            "Apply",
            request,
            |body| body.header.clone(),
            |receipt| ApplyResponse { receipt },
        )
        .await
    }

    async fn set_desired(
        &self,
        request: Request<SetDesiredRequest>,
    ) -> Result<Response<SetDesiredResponse>, Status> {
        self.mutate(
            "SetDesired",
            request,
            |body| body.header.clone(),
            |receipt| SetDesiredResponse { receipt },
        )
        .await
    }

    async fn remove_instance(
        &self,
        request: Request<RemoveInstanceRequest>,
    ) -> Result<Response<RemoveInstanceResponse>, Status> {
        self.mutate(
            "RemoveInstance",
            request,
            |body| body.header.clone(),
            |receipt| RemoveInstanceResponse { receipt },
        )
        .await
    }

    async fn get_receipt(
        &self,
        request: Request<GetReceiptRequest>,
    ) -> Result<Response<GetReceiptResponse>, Status> {
        self.answer("GetReceipt", request, |script, body| {
            Ok(GetReceiptResponse {
                receipt: script
                    .receipts
                    .get(&body.request_id)
                    .map(|accepted| accepted.receipt.clone()),
            })
        })
        .await
    }

    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        self.answer("Query", request, |_, body| {
            use query_response::Result as Answer;
            let result = match body.kind() {
                QueryKind::Nodes => Answer::Nodes(NodeList::default()),
                QueryKind::Routes => Answer::Routes(RouteList::default()),
                QueryKind::Traffic => Answer::Traffic(TrafficStats::default()),
                QueryKind::Unspecified => {
                    return Err(rejected(Code::InvalidArgument, ErrorCode::InvalidSpec));
                }
            };
            Ok(QueryResponse {
                result: Some(result),
                at_unix_ms: 0,
            })
        })
        .await
    }

    type StreamLogsStream = BoxStream<'static, Result<LogLine, Status>>;

    async fn stream_logs(
        &self,
        request: Request<StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        self.answer("StreamLogs", request, |script, body| {
            let past = stream::iter(script.logs.clone().into_iter().map(Ok));
            Ok(if body.follow {
                past.chain(stream::pending()).boxed()
            } else {
                past.boxed()
            })
        })
        .await
    }

    async fn get_reclaim_report(
        &self,
        request: Request<GetReclaimReportRequest>,
    ) -> Result<Response<ReclaimReport>, Status> {
        self.answer("GetReclaimReport", request, |script, _| {
            Ok(script.snapshot.reclaim.clone().unwrap_or_default())
        })
        .await
    }

    async fn retry_reclaim(
        &self,
        request: Request<RetryReclaimRequest>,
    ) -> Result<Response<RetryReclaimResponse>, Status> {
        self.mutate(
            "RetryReclaim",
            request,
            |body| body.header.clone(),
            |receipt| RetryReclaimResponse { receipt },
        )
        .await
    }

    async fn retry_start(
        &self,
        request: Request<RetryStartRequest>,
    ) -> Result<Response<RetryStartResponse>, Status> {
        self.mutate(
            "RetryStart",
            request,
            |body| body.header.clone(),
            |receipt| RetryStartResponse { receipt },
        )
        .await
    }

    async fn resolve_candidates(
        &self,
        request: Request<ResolveCandidatesRequest>,
    ) -> Result<Response<ResolveCandidatesResponse>, Status> {
        self.mutate(
            "ResolveCandidates",
            request,
            |body| body.header.clone(),
            |receipt| ResolveCandidatesResponse { receipt },
        )
        .await
    }

    async fn release_lease(
        &self,
        request: Request<ReleaseLeaseRequest>,
    ) -> Result<Response<ReleaseLeaseResponse>, Status> {
        self.answer("ReleaseLease", request, |_, _| {
            Ok(ReleaseLeaseResponse { host_exiting: true })
        })
        .await
    }

    async fn get_allow_list(
        &self,
        request: Request<GetAllowListRequest>,
    ) -> Result<Response<GetAllowListResponse>, Status> {
        self.answer("GetAllowList", request, |script, _| {
            Ok(GetAllowListResponse {
                entries: Vec::new(),
                revision: script.revision,
            })
        })
        .await
    }

    async fn set_allow_list(
        &self,
        request: Request<SetAllowListRequest>,
    ) -> Result<Response<SetAllowListResponse>, Status> {
        self.mutate(
            "SetAllowList",
            request,
            |body| body.header.clone(),
            |receipt| SetAllowListResponse { receipt },
        )
        .await
    }

    async fn list_cores(
        &self,
        request: Request<ListCoresRequest>,
    ) -> Result<Response<ListCoresResponse>, Status> {
        self.answer(
            "ListCores",
            request,
            |_, _| Ok(ListCoresResponse::default()),
        )
        .await
    }

    async fn select_core(
        &self,
        request: Request<SelectCoreRequest>,
    ) -> Result<Response<SelectCoreResponse>, Status> {
        self.mutate(
            "SelectCore",
            request,
            |body| body.header.clone(),
            |receipt| SelectCoreResponse { receipt },
        )
        .await
    }

    async fn purge_all_data(
        &self,
        request: Request<PurgeAllDataRequest>,
    ) -> Result<Response<PurgeAllDataResponse>, Status> {
        self.mutate(
            "PurgeAllData",
            request,
            |body| body.header.clone(),
            |receipt| PurgeAllDataResponse { receipt },
        )
        .await
    }
}
