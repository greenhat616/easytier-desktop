//! Backoff reconnect and gap-free resubscription from the last cursor;
//! receipt recovery by request id. Owned by C1.
//!
//! One [`Session`] is one authenticated connection plus the handshake made on
//! it. A session's channel never dials twice: when its connection is gone the
//! supervisor builds a new session, so server verification and the handshake
//! (capabilities, role, stream id) are always redone together.
use crate::{
    CallError, ConnectionState,
    grpc::{ClientOptions, Failure, Stub, VersionMetadata, bounded, call_error, is_transport},
    negotiate,
    stub::host_service_client::HostServiceClient,
};
use async_trait::async_trait;
use backon::{BackoffBuilder, ExponentialBackoff, ExponentialBuilder};
use etd_contract::{
    Event, EventCursor, Negotiated, Receipt, RequestId, capability,
    v1::{GetReceiptRequest, SnapshotRequest, SubscribeRequest, event},
};
use etd_ipc::{BoxConn, Connector, Endpoint, ServerIdentity, tonic_io::ClientIo};
use futures_util::{
    future::{Either, select},
    stream::{self, BoxStream},
};
use std::{
    io,
    pin::{Pin, pin},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::{CancellationToken, DropGuard};
use tonic::{Streaming, transport::Endpoint as ChannelEndpoint};

pub(crate) struct Session {
    pub(crate) client: Stub,
    pub(crate) negotiated: Negotiated,
    /// Cancelled when the connection is gone or was found unusable.
    pub(crate) lost: CancellationToken,
}

#[derive(Clone)]
pub(crate) enum Link {
    /// Why calls fail right now.
    Down(CallError),
    Up(Arc<Session>),
}

/// State shared by the client, its supervisor task and its streams.
pub(crate) struct Shared {
    pub(crate) options: ClientOptions,
    pub(crate) link: watch::Sender<Link>,
    pub(crate) state: watch::Sender<ConnectionState>,
    pub(crate) negotiated: Mutex<Option<Negotiated>>,
    /// Cancelled when the client is closed or dropped.
    pub(crate) closed: CancellationToken,
}

impl Shared {
    pub(crate) fn new(options: ClientOptions) -> Self {
        Self {
            options,
            link: watch::Sender::new(Link::Down(CallError::Unavailable("connecting".into()))),
            state: watch::Sender::new(ConnectionState::Connecting),
            negotiated: Mutex::new(None),
            closed: CancellationToken::new(),
        }
    }

    pub(crate) fn close(&self) {
        self.closed.cancel();
        self.link.send_replace(Link::Down(CallError::Cancelled));
        self.state.send_replace(ConnectionState::Closed);
    }

    // `Closed` is final, even against a supervisor still running on another
    // worker thread.
    fn publish_link(&self, next: Link) {
        self.link.send_if_modified(|link| {
            if self.closed.is_cancelled() {
                return false;
            }
            *link = next;
            true
        });
    }

    fn publish_state(&self, next: ConnectionState) {
        self.state.send_if_modified(|state| {
            if self.closed.is_cancelled() || *state == next {
                return false;
            }
            *state = next;
            true
        });
    }

    /// The live session, or the reason there is none. Never waits.
    pub(crate) fn current(&self) -> Result<Arc<Session>, CallError> {
        if self.closed.is_cancelled() {
            return Err(CallError::Cancelled);
        }
        match &*self.link.borrow() {
            Link::Up(session) if !session.lost.is_cancelled() => Ok(session.clone()),
            Link::Up(_) => Err(CallError::Unavailable("connection lost".into())),
            Link::Down(reason) => Err(reason.clone()),
        }
    }

    /// Waits for a live session. Gives up only when the client is closed or
    /// the host speaks another major version.
    async fn live_session(&self) -> Result<Arc<Session>, CallError> {
        let mut link = self.link.subscribe();
        let wait = link.wait_for(|link| match link {
            Link::Up(session) => !session.lost.is_cancelled(),
            Link::Down(reason) => matches!(
                reason,
                CallError::VersionMismatch { .. } | CallError::Cancelled
            ),
        });
        match self.closed.run_until_cancelled(wait).await {
            Some(Ok(link)) => match &*link {
                Link::Up(session) => Ok(session.clone()),
                Link::Down(reason) => Err(reason.clone()),
            },
            _ => Err(CallError::Cancelled),
        }
    }
}

fn backoff(options: &ClientOptions) -> ExponentialBackoff {
    ExponentialBuilder::new()
        .with_min_delay(options.backoff_min)
        .with_max_delay(options.backoff_max)
        .with_jitter()
        .without_max_times()
        .build()
}

/// Keeps one session alive until the client closes.
pub(crate) async fn supervise(shared: Arc<Shared>, connector: Arc<dyn Connector>, ep: Endpoint) {
    let mut delays = backoff(&shared.options);
    let mut attempt = 0u32;
    loop {
        match establish(&shared.options, connector.clone(), ep.clone()).await {
            Ok(session) => {
                let session = Arc::new(session);
                // Ends the session if this task is dropped.
                let _guard = session.lost.clone().drop_guard();
                let negotiated = session.negotiated.clone();
                *shared.negotiated.lock().unwrap() = Some(negotiated.clone());
                let since = Instant::now();
                let lost = session.lost.clone();
                shared.publish_link(Link::Up(session));
                shared.publish_state(ConnectionState::Connected(Box::new(negotiated)));
                lost.cancelled().await;
                shared.publish_link(Link::Down(CallError::Unavailable("connection lost".into())));
                // A connection that dies right away keeps backing off.
                if since.elapsed() >= shared.options.stable_after {
                    delays = backoff(&shared.options);
                    attempt = 0;
                }
                attempt = attempt.saturating_add(1);
                shared.publish_state(ConnectionState::Reconnecting { attempt });
            }
            Err(reason) => {
                tracing::debug!(%reason, "host connection attempt failed");
                attempt = attempt.saturating_add(1);
                let state = match reason {
                    CallError::VersionMismatch {
                        host_major,
                        host_minor,
                    } => {
                        *shared.negotiated.lock().unwrap() = None;
                        ConnectionState::UpgradeRequired {
                            host_major,
                            host_minor,
                        }
                    }
                    _ => ConnectionState::Reconnecting { attempt },
                };
                // Calls must already see the reason when the state changes.
                shared.publish_link(Link::Down(reason));
                shared.publish_state(state);
            }
        }
        sleep(delays.next().unwrap_or(shared.options.backoff_max)).await;
    }
}

async fn establish(
    options: &ClientOptions,
    connector: Arc<dyn Connector>,
    endpoint: Endpoint,
) -> Result<Session, CallError> {
    let lost = CancellationToken::new();
    let dial = Arc::new(SingleDial {
        inner: connector,
        used: AtomicBool::new(false),
        failure: Mutex::new(None),
        lost: lost.clone(),
    });
    let attempt = async {
        let channel = ChannelEndpoint::from_static("http://localhost")
            .connect_with_connector(ClientIo::new(dial.clone(), endpoint))
            .await
            .map_err(|error| {
                dial.failure
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or_else(|| CallError::Unavailable(error.to_string()))
            })?;
        let mut client = HostServiceClient::with_interceptor(channel, VersionMetadata);
        let negotiated =
            negotiate::handshake(&mut client, options.client_kind, &options.build).await?;
        Ok(Session {
            client,
            negotiated,
            lost: lost.clone(),
        })
    };
    timeout(options.connect_timeout, attempt)
        .await
        .unwrap_or_else(|_| Err(CallError::Unavailable("connecting timed out".into())))
}

/// Lets a channel open exactly one verified connection and reports its end.
struct SingleDial {
    inner: Arc<dyn Connector>,
    used: AtomicBool,
    failure: Mutex<Option<CallError>>,
    lost: CancellationToken,
}

#[async_trait]
impl Connector for SingleDial {
    async fn connect(&self, ep: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)> {
        if self.used.swap(true, Ordering::AcqRel) {
            self.lost.cancel();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection lost",
            ));
        }
        match self.inner.connect(ep).await {
            Ok((stream, server)) => {
                let stream = Tracked {
                    stream,
                    _lost: self.lost.clone().drop_guard(),
                };
                Ok((Box::new(stream), server))
            }
            Err(error) => {
                *self.failure.lock().unwrap() = Some(connect_error(&error));
                Err(error)
            }
        }
    }
}

// `PermissionDenied` is how a connector refuses an impostor. With an OS error
// code it is the system refusing us access to the endpoint instead.
fn connect_error(error: &io::Error) -> CallError {
    if error.kind() == io::ErrorKind::PermissionDenied && error.raw_os_error().is_none() {
        CallError::HostNotVerified(error.to_string())
    } else {
        CallError::Unavailable(error.to_string())
    }
}

/// A connection which cancels its session when the HTTP/2 stack drops it,
/// so that an idle client notices a lost host at once.
struct Tracked {
    stream: BoxConn,
    _lost: DropGuard,
}

impl AsyncRead for Tracked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tracked {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Looks up the receipt of a mutation whose reply was lost, waiting for the
/// host to come back for at most the recovery timeout. It only reads: the
/// mutation is never sent again. `None` leaves the outcome unknown.
pub(crate) async fn recover_receipt(shared: &Shared, request_id: &RequestId) -> Option<Receipt> {
    if request_id.0.is_empty() {
        return None;
    }
    let lookup = async {
        loop {
            let session = shared.live_session().await.ok()?;
            negotiate::require(&session.negotiated, capability::INSTANCES).ok()?;
            let mut client = session.client.clone();
            let request = GetReceiptRequest {
                request_id: request_id.0.clone(),
            };
            match bounded(shared, &session, "GetReceipt", client.get_receipt(request)).await {
                Ok(reply) => {
                    return reply
                        .receipt
                        .filter(|receipt| receipt.request_id == request_id.0);
                }
                // Only a broken connection is worth another try.
                Err(Failure::Ambiguous(_)) if session.lost.is_cancelled() => {}
                Err(_) => return None,
            }
        }
    };
    timeout(shared.options.recovery_timeout, lookup)
        .await
        .ok()
        .flatten()
}

struct Subscription {
    shared: Arc<Shared>,
    /// Position of the last event handed to the consumer, or where to start.
    cursor: Option<EventCursor>,
    live: Option<(Arc<Session>, Streaming<Event>)>,
}

enum Step {
    Event(Box<Event>),
    /// Nothing to hand out yet: call again.
    Continue,
    Fail(CallError),
}

impl Subscription {
    async fn next(&mut self) -> Step {
        let Some((session, events)) = self.live.as_mut() else {
            return self.open().await;
        };
        // Buffered events are drained before the loss of the session counts.
        let received = {
            let message = pin!(events.message());
            let lost = pin!(session.lost.cancelled());
            match select(message, lost).await {
                Either::Left((received, _)) => Some(received),
                Either::Right(_) => None,
            }
        };
        match received {
            Some(Ok(Some(event))) => Step::Event(Box::new(event)),
            Some(Err(status)) if !is_transport(&status) => {
                Step::Fail(call_error("Subscribe", &status))
            }
            // Lost, broken, or ended by a host that is going away.
            _ => {
                session.lost.cancel();
                self.live = None;
                Step::Continue
            }
        }
    }

    async fn open(&mut self) -> Step {
        let session = match self.shared.live_session().await {
            Ok(session) => session,
            Err(error) => return Step::Fail(error),
        };
        if let Err(error) = negotiate::require(&session.negotiated, capability::INSTANCES) {
            return Step::Fail(error);
        }
        let mut client = session.client.clone();
        // "From now on" still needs a position to resume from if the
        // connection breaks before the first event.
        if self.cursor.is_none() {
            let call = client.snapshot(SnapshotRequest {});
            match bounded(&self.shared, &session, "Snapshot", call).await {
                Ok(snapshot) => self.cursor = snapshot.cursor,
                Err(failure) => return retry_or_fail(&session, failure),
            }
        }
        let request = SubscribeRequest {
            after: self.cursor.clone(),
        };
        let call = client.subscribe(request);
        match bounded(&self.shared, &session, "Subscribe", call).await {
            Ok(events) => {
                self.live = Some((session, events));
                Step::Continue
            }
            Err(failure) => retry_or_fail(&session, failure),
        }
    }

    /// True for an event the consumer has already seen.
    fn is_duplicate(&self, event: &Event) -> bool {
        if matches!(event.payload, Some(event::Payload::ResyncRequired(_))) {
            return false;
        }
        match (&self.cursor, &event.cursor) {
            (Some(last), Some(next)) => last.stream_id == next.stream_id && next.seq <= last.seq,
            _ => false,
        }
    }
}

fn retry_or_fail(session: &Session, failure: Failure) -> Step {
    match failure {
        Failure::Ambiguous(_) => {
            session.lost.cancel();
            Step::Continue
        }
        Failure::Definite(error) => Step::Fail(error),
    }
}

/// The resumable event stream. It ends after `ResyncRequired` or after
/// yielding an error; connection loss is not an error here.
pub(crate) fn subscribe(
    shared: Arc<Shared>,
    after: Option<EventCursor>,
) -> BoxStream<'static, Result<Event, CallError>> {
    let subscription = Subscription {
        shared,
        cursor: after,
        live: None,
    };
    Box::pin(stream::unfold(Some(subscription), |state| async move {
        let mut subscription = state?;
        let closed = subscription.shared.closed.clone();
        loop {
            let step = closed
                .run_until_cancelled(subscription.next())
                .await
                .unwrap_or(Step::Fail(CallError::Cancelled));
            match step {
                Step::Continue => {}
                Step::Fail(error) => return Some((Err(error), None)),
                Step::Event(event) => {
                    if subscription.is_duplicate(&event) {
                        continue;
                    }
                    // The consumer must take a new snapshot; nothing after
                    // this event can be trusted to be complete.
                    if matches!(event.payload, Some(event::Payload::ResyncRequired(_))) {
                        return Some((Ok(*event), None));
                    }
                    if event.cursor.is_some() {
                        subscription.cursor.clone_from(&event.cursor);
                    }
                    return Some((Ok(*event), Some(subscription)));
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_connectors_own_refusal_reads_as_an_impostor() {
        let impostor = io::Error::new(io::ErrorKind::PermissionDenied, "unexpected host account");
        assert!(matches!(
            connect_error(&impostor),
            CallError::HostNotVerified(_)
        ));
        // ERROR_ACCESS_DENIED / EACCES: the endpoint's access list said no.
        let code = if cfg!(windows) { 5 } else { 13 };
        let access_list = io::Error::from_raw_os_error(code);
        assert_eq!(access_list.kind(), io::ErrorKind::PermissionDenied);
        for error in [
            access_list,
            io::Error::from(io::ErrorKind::ConnectionRefused),
            io::Error::from(io::ErrorKind::ConnectionReset),
        ] {
            assert!(matches!(connect_error(&error), CallError::Unavailable(_)));
        }
    }
}
