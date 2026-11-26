//! Fake `etd_client::HostClient`. Owned by A1.
//!
//! Behaves like the real client where application logic depends on it:
//! calls fail at once without a connection, mutations are idempotent by
//! request id and check the expected revision, and the event stream resumes
//! from a cursor. Tests script lost replies and rejections, and may inject
//! events the real host would never send (duplicates, gaps).
use async_trait::async_trait;
use etd_client::{CallError, ConnectionState, HostClient};
use etd_contract::v1::{event, *};
use etd_contract::{
    Event, EventCursor, HostMode, HostPhase, HostSnapshot, InstanceId, LogLine, Negotiated,
    QueryKind, QueryResponse, Receipt, ReclaimReport, RequestId, Role, VERSION_MAJOR,
    VERSION_MINOR, capability,
};
use futures_util::stream::{self, BoxStream, StreamExt};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Mutex, MutexGuard},
};
use tokio::sync::{mpsc, watch};

/// A call the fake received. Contains whatever the caller sent, secrets
/// included, so that tests can assert on them.
#[derive(Debug, Clone, PartialEq)]
pub enum HostCall {
    Snapshot,
    Subscribe(Option<EventCursor>),
    Apply(Box<ApplyRequest>),
    SetDesired(SetDesiredRequest),
    RemoveInstance(RemoveInstanceRequest),
    RetryReclaim(RetryReclaimRequest),
    RetryStart(RetryStartRequest),
    ResolveCandidates(ResolveCandidatesRequest),
    Receipt(RequestId),
    Query(InstanceId, QueryKind),
    ReleaseLease(LeaseRelease),
}

impl HostCall {
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::Apply(_)
                | Self::SetDesired(_)
                | Self::RemoveInstance(_)
                | Self::RetryReclaim(_)
                | Self::RetryStart(_)
                | Self::ResolveCandidates(_)
        )
    }
}

/// What happens to the next new mutation.
#[derive(Debug, Clone)]
pub enum MutationReply {
    Accept,
    /// Nothing commits; the caller gets the error.
    Reject(CallError),
    /// The change commits but the caller only gets the error.
    LoseReply(CallError),
    /// No answer at all.
    Hang,
}

struct Inner {
    negotiated: Negotiated,
    /// Why calls fail while not connected.
    down_reason: CallError,
    snapshot: HostSnapshot,
    seq: u64,
    journal: Vec<Event>,
    subscribers: Vec<mpsc::UnboundedSender<Result<Event, CallError>>>,
    replies: VecDeque<MutationReply>,
    receipt_errors: VecDeque<CallError>,
    /// Request id to the encoded request and its receipt.
    committed: BTreeMap<String, (String, Receipt)>,
    queries: BTreeMap<i32, Result<QueryResponse, CallError>>,
    release: Result<bool, CallError>,
    release_hangs: bool,
    calls: Vec<HostCall>,
}

pub struct FakeHostClient {
    inner: Mutex<Inner>,
    connection: watch::Sender<ConnectionState>,
}

fn negotiated(mode: HostMode, stream_id: &str) -> Negotiated {
    let mut capabilities = vec![
        capability::INSTANCES,
        capability::QUERY_NODES,
        capability::QUERY_ROUTES,
        capability::QUERY_TRAFFIC,
        capability::LOGS,
        capability::RECLAIM,
        capability::RECLAIM_CANDIDATES,
    ];
    if mode == HostMode::Service {
        capabilities.push(capability::TUN);
    } else {
        capabilities.push(capability::LEASE);
    }
    Negotiated {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        capabilities: capabilities.into_iter().map(str::to_owned).collect(),
        role: Role::Control,
        host_mode: mode,
        host_phase: HostPhase::Serving,
        host_build: "fake".into(),
        stream_id: stream_id.into(),
    }
}

impl FakeHostClient {
    /// A connected host of this form with an empty snapshot at revision 1.
    pub fn new(mode: HostMode) -> Self {
        let negotiated = negotiated(mode, "fake-stream-1");
        let connection =
            watch::Sender::new(ConnectionState::Connected(Box::new(negotiated.clone())));
        Self {
            inner: Mutex::new(Inner {
                negotiated,
                down_reason: CallError::Unavailable("fake host is not connected".into()),
                snapshot: HostSnapshot {
                    revision: 1,
                    phase: HostPhase::Serving as i32,
                    ..HostSnapshot::default()
                },
                seq: 0,
                journal: Vec::new(),
                subscribers: Vec::new(),
                replies: VecDeque::new(),
                receipt_errors: VecDeque::new(),
                committed: BTreeMap::new(),
                queries: BTreeMap::new(),
                release: Ok(true),
                release_hangs: false,
                calls: Vec::new(),
            }),
            connection,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("fake host lock")
    }

    // ------------------------------------------------------------ script

    /// The state `snapshot` reports; its cursor is filled in by the fake.
    pub fn set_snapshot(&self, snapshot: HostSnapshot) {
        self.lock().snapshot = snapshot;
    }

    pub fn update_snapshot(&self, update: impl FnOnce(&mut HostSnapshot)) {
        update(&mut self.lock().snapshot);
    }

    pub fn revision(&self) -> u64 {
        self.lock().snapshot.revision
    }

    pub fn cursor(&self) -> EventCursor {
        let inner = self.lock();
        EventCursor {
            stream_id: inner.negotiated.stream_id.clone(),
            seq: inner.seq,
        }
    }

    /// Publishes the next event. The snapshot is not changed.
    pub fn emit(&self, payload: event::Payload) -> Event {
        let mut inner = self.lock();
        inner.seq += 1;
        let event = Event {
            cursor: Some(EventCursor {
                stream_id: inner.negotiated.stream_id.clone(),
                seq: inner.seq,
            }),
            at_unix_ms: inner.seq as i64,
            payload: Some(payload),
        };
        inner.journal.push(event.clone());
        inner
            .subscribers
            .retain(|tx| tx.send(Ok(event.clone())).is_ok());
        event
    }

    /// Consumes a sequence number without delivering the event, so that
    /// subscribers see a gap.
    pub fn skip_event(&self) {
        self.lock().seq += 1;
    }

    /// Hands subscribers an arbitrary event.
    pub fn deliver_raw(&self, event: Event) {
        self.lock()
            .subscribers
            .retain(|tx| tx.send(Ok(event.clone())).is_ok());
    }

    /// Ends every event stream with an error.
    pub fn fail_streams(&self, error: CallError) {
        for tx in self.lock().subscribers.drain(..) {
            let _ = tx.send(Err(error.clone()));
        }
    }

    /// Streams the consumer has not dropped.
    pub fn subscriber_count(&self) -> usize {
        let mut inner = self.lock();
        inner.subscribers.retain(|tx| !tx.is_closed());
        inner.subscribers.len()
    }

    pub fn set_connection(&self, state: ConnectionState) {
        if let ConnectionState::Connected(negotiated) = &state {
            self.lock().negotiated = (**negotiated).clone();
        }
        self.connection.send_replace(state);
    }

    pub fn reconnecting(&self, attempt: u32) {
        self.set_connection(ConnectionState::Reconnecting { attempt });
    }

    pub fn reconnected(&self) {
        let negotiated = self.lock().negotiated.clone();
        self.set_connection(ConnectionState::Connected(Box::new(negotiated)));
    }

    /// A new host run: new stream id, empty journal; connects again.
    pub fn restart_host(&self, stream_id: &str) {
        let negotiated = {
            let mut inner = self.lock();
            inner.negotiated.stream_id = stream_id.into();
            inner.seq = 0;
            inner.journal.clear();
            inner.negotiated.clone()
        };
        self.set_connection(ConnectionState::Connected(Box::new(negotiated)));
    }

    /// The error calls return while not connected.
    pub fn set_down_reason(&self, reason: CallError) {
        self.lock().down_reason = reason;
    }

    /// Queued replies are used once each, in order; then mutations succeed.
    pub fn script(&self, reply: MutationReply) {
        self.lock().replies.push_back(reply);
    }

    /// The next receipt lookups fail with these errors.
    pub fn fail_receipt_lookup(&self, error: CallError) {
        self.lock().receipt_errors.push_back(error);
    }

    pub fn set_query(&self, kind: QueryKind, reply: Result<QueryResponse, CallError>) {
        self.lock().queries.insert(kind as i32, reply);
    }

    /// The reply to `release_lease`: whether the host exits, or an error.
    pub fn set_release(&self, reply: Result<bool, CallError>) {
        self.lock().release = reply;
    }

    pub fn hang_release(&self) {
        self.lock().release_hangs = true;
    }

    pub fn calls(&self) -> Vec<HostCall> {
        self.lock().calls.clone()
    }

    pub fn mutations(&self) -> Vec<HostCall> {
        self.calls()
            .into_iter()
            .filter(HostCall::is_mutation)
            .collect()
    }

    /// Number of changes that took effect.
    pub fn committed_count(&self) -> usize {
        self.lock().committed.len()
    }

    // ----------------------------------------------------------- helpers

    fn connected(&self, call: HostCall) -> Result<(), CallError> {
        let up = matches!(*self.connection.borrow(), ConnectionState::Connected(_));
        let mut inner = self.lock();
        inner.calls.push(call);
        if up {
            Ok(())
        } else {
            Err(inner.down_reason.clone())
        }
    }

    async fn mutate(
        &self,
        call: HostCall,
        header: Option<MutationHeader>,
    ) -> Result<Receipt, CallError> {
        let content = format!("{call:?}");
        self.connected(call)?;
        let header = header.ok_or_else(|| CallError::Transport("missing header".into()))?;
        let reply = {
            let mut inner = self.lock();
            if let Some((known, receipt)) = inner.committed.get(&header.request_id) {
                return if *known == content {
                    Ok(receipt.clone())
                } else {
                    Err(CallError::RequestIdReused)
                };
            }
            inner.replies.pop_front().unwrap_or(MutationReply::Accept)
        };
        let lost = match reply {
            MutationReply::Accept => None,
            MutationReply::LoseReply(error) => Some(error),
            MutationReply::Reject(error) => return Err(error),
            MutationReply::Hang => return std::future::pending().await,
        };
        let receipt = {
            let mut inner = self.lock();
            let current = inner.snapshot.revision;
            if header.expected_revision != current {
                return Err(CallError::Conflict { current });
            }
            inner.snapshot.revision += 1;
            let receipt = Receipt {
                request_id: header.request_id.clone(),
                revision: inner.snapshot.revision,
                ticket: format!("ticket-{}", inner.committed.len() + 1),
                accepted_unix_ms: 0,
            };
            inner
                .committed
                .insert(header.request_id, (content, receipt.clone()));
            receipt
        };
        match lost {
            Some(error) => Err(error),
            None => Ok(receipt),
        }
    }

    fn unscripted(what: &str) -> CallError {
        CallError::Unsupported(format!("the fake host does not implement {what}"))
    }
}

#[async_trait]
impl HostClient for FakeHostClient {
    fn negotiated(&self) -> Option<Negotiated> {
        Some(self.lock().negotiated.clone())
    }

    fn connection(&self) -> watch::Receiver<ConnectionState> {
        self.connection.subscribe()
    }

    async fn snapshot(&self) -> Result<HostSnapshot, CallError> {
        self.connected(HostCall::Snapshot)?;
        let inner = self.lock();
        let mut snapshot = inner.snapshot.clone();
        snapshot.cursor = Some(EventCursor {
            stream_id: inner.negotiated.stream_id.clone(),
            seq: inner.seq,
        });
        Ok(snapshot)
    }

    fn subscribe(
        &self,
        after: Option<EventCursor>,
    ) -> BoxStream<'static, Result<Event, CallError>> {
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut inner = self.lock();
            inner.calls.push(HostCall::Subscribe(after.clone()));
            if let Some(after) = after {
                if after.stream_id != inner.negotiated.stream_id {
                    let resync = Event {
                        payload: Some(event::Payload::ResyncRequired(ResyncRequired {
                            reason: "another host run".into(),
                        })),
                        ..Event::default()
                    };
                    return stream::iter([Ok(resync)]).boxed();
                }
                for event in &inner.journal {
                    if event.cursor.as_ref().is_some_and(|c| c.seq > after.seq) {
                        let _ = tx.send(Ok(event.clone()));
                    }
                }
            }
            inner.subscribers.push(tx);
        }
        stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        })
        .boxed()
    }

    async fn apply(&self, req: ApplyRequest) -> Result<Receipt, CallError> {
        let header = req.header.clone();
        self.mutate(HostCall::Apply(Box::new(req)), header).await
    }

    async fn set_desired(&self, req: SetDesiredRequest) -> Result<Receipt, CallError> {
        let header = req.header.clone();
        self.mutate(HostCall::SetDesired(req), header).await
    }

    async fn remove_instance(&self, req: RemoveInstanceRequest) -> Result<Receipt, CallError> {
        let header = req.header.clone();
        self.mutate(HostCall::RemoveInstance(req), header).await
    }

    async fn receipt(&self, request_id: RequestId) -> Result<Option<Receipt>, CallError> {
        self.connected(HostCall::Receipt(request_id.clone()))?;
        let mut inner = self.lock();
        if let Some(error) = inner.receipt_errors.pop_front() {
            return Err(error);
        }
        Ok(inner
            .committed
            .get(&request_id.0)
            .map(|(_, receipt)| receipt.clone()))
    }

    async fn query(&self, id: InstanceId, kind: QueryKind) -> Result<QueryResponse, CallError> {
        self.connected(HostCall::Query(id, kind))?;
        self.lock()
            .queries
            .get(&(kind as i32))
            .cloned()
            .unwrap_or_else(|| Ok(QueryResponse::default()))
    }

    fn logs(&self, _: StreamLogsRequest) -> BoxStream<'static, Result<LogLine, CallError>> {
        stream::iter([Err(Self::unscripted("logs"))]).boxed()
    }

    async fn reclaim_report(&self) -> Result<ReclaimReport, CallError> {
        Ok(self.lock().snapshot.reclaim.clone().unwrap_or_default())
    }

    async fn retry_reclaim(&self, req: RetryReclaimRequest) -> Result<Receipt, CallError> {
        let header = req.header.clone();
        self.mutate(HostCall::RetryReclaim(req), header).await
    }

    async fn retry_start(&self, req: RetryStartRequest) -> Result<Receipt, CallError> {
        let header = req.header.clone();
        self.mutate(HostCall::RetryStart(req), header).await
    }

    async fn resolve_candidates(
        &self,
        req: ResolveCandidatesRequest,
    ) -> Result<Receipt, CallError> {
        let header = req.header.clone();
        self.mutate(HostCall::ResolveCandidates(req), header).await
    }

    async fn release_lease(
        &self,
        instances: LeaseRelease,
    ) -> Result<ReleaseLeaseResponse, CallError> {
        self.connected(HostCall::ReleaseLease(instances))?;
        let (reply, hangs) = {
            let inner = self.lock();
            (inner.release.clone(), inner.release_hangs)
        };
        if hangs {
            std::future::pending::<()>().await;
        }
        reply.map(|host_exiting| ReleaseLeaseResponse { host_exiting })
    }

    async fn allow_list(&self) -> Result<GetAllowListResponse, CallError> {
        Err(Self::unscripted("allow_list"))
    }

    async fn set_allow_list(&self, _: SetAllowListRequest) -> Result<Receipt, CallError> {
        Err(Self::unscripted("set_allow_list"))
    }

    async fn cores(&self) -> Result<ListCoresResponse, CallError> {
        Err(Self::unscripted("cores"))
    }

    async fn select_core(&self, _: SelectCoreRequest) -> Result<Receipt, CallError> {
        Err(Self::unscripted("select_core"))
    }

    async fn purge_all_data(&self, _: PurgeAllDataRequest) -> Result<Receipt, CallError> {
        Err(Self::unscripted("purge_all_data"))
    }
}
