//! Native listener and host lifecycle shared by the product and integration fixtures.
use anyhow::{Context, Result};
use etd_contract::{
    AllowEntry, HostMode, capability,
    v1::{self, os_principal::Id},
};
use etd_host_core::{
    api::{Command, HostDeps, HostView, orchestrator_channel},
    auth::allow_list::AllowListAuthorizer,
    lifecycle::Orchestrator,
    negotiate::VersionInterceptor,
    service::{AllowListSink, ContractService},
    stub::host_service_server::HostServiceServer,
};
use etd_ipc::{
    BoxConn, Endpoint, HostForm, Listener, ListenerPolicy, OsGroupId, OsUserId, PeerIdentity,
    platform::{self, HeldHostLock, LocalListener, PolicyHandle},
    tonic_io,
};
use etd_sysfx_os::service::HostLock;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{oneshot, watch},
};

const CAPACITY: usize = 256;
/// Past the orchestrator's own `shutdown_budget`, how long the listener
/// still waits for it before abandoning it.
const SHUTDOWN_BACKSTOP_MARGIN: Duration = Duration::from_secs(5);
/// How long final replies may take to reach clients once the orchestrator
/// has ended.
const SERVER_DRAIN: Duration = Duration::from_secs(3);
/// How long aborted supervisor tasks may take to end.
const TASK_ABORT_WAIT: Duration = Duration::from_secs(2);
/// Past the helpers' own bound, how long their blocking task may take to be
/// scheduled and joined.
const HELPER_JOIN_MARGIN: Duration = Duration::from_secs(1);
/// How long closing the ledger (joining its writer thread) may take.
pub(crate) const LEDGER_CLOSE: Duration = Duration::from_secs(3);
/// How long a finished host waits for blocking work still running in its
/// runtime (a system call past its own deadline) before exiting anyway.
pub(crate) const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(2);

/// The longest a host stop can take once asked, everything included:
/// within the uninstaller's 60 s wait for STOPPED.
pub(crate) fn stop_worst_case() -> Duration {
    WindDown::new(etd_host_core::lifecycle::LifecycleConfig::default().shutdown_budget).total()
        + LEDGER_CLOSE
        + RUNTIME_SHUTDOWN
}

/// A host that has stopped serving. Its singleton lock is handed back, to
/// be released only once nothing of the host can act any more (ledger
/// closed, runtime shut down).
pub(crate) struct Stopped {
    pub(crate) lock: LayoutLock,
    pub(crate) result: Result<()>,
    /// Every task and helper process of the host is confirmed ended.
    /// Otherwise the lock must stay held until the process exits.
    pub(crate) quiescent: bool,
}

/// The bounds of a host's wind-down once it is asked to stop. Each stage
/// ends at an absolute deadline, so a stage that overruns (a task that does
/// not end once aborted, a helper join never scheduled) eats into the next
/// ones and never extends the whole: it all ends by [`WindDown::total`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct WindDown {
    /// The orchestrator's own budget plus the backstop margin.
    pub(crate) orchestrator: Duration,
    pub(crate) server: Duration,
    pub(crate) supervisors: Duration,
    pub(crate) helpers: Duration,
}

impl WindDown {
    pub(crate) fn new(budget: Duration) -> Self {
        Self {
            orchestrator: budget + SHUTDOWN_BACKSTOP_MARGIN,
            server: SERVER_DRAIN,
            supervisors: TASK_ABORT_WAIT,
            helpers: etd_sysfx_os::HELPERS_SHUTDOWN_WORST + HELPER_JOIN_MARGIN,
        }
    }

    pub(crate) fn total(&self) -> Duration {
        self.orchestrator + self.server + self.supervisors + self.helpers
    }
}

/// Abort `task` and wait for it to end until `deadline`. `false`: it did
/// not end (stuck without reaching an await).
async fn abort_join<T>(
    task: &mut tokio::task::JoinHandle<T>,
    deadline: tokio::time::Instant,
) -> bool {
    // A finished task is not awaited again: its handle may already have
    // been polled to completion.
    if task.is_finished() {
        return true;
    }
    task.abort();
    tokio::time::timeout_at(deadline, task).await.is_ok()
}

/// Everything after the host is asked to stop (or its orchestrator ended
/// by itself), within `bounds.total()`: ask the orchestrator to stop
/// (`ask`, then its end), close the server, end the supervisors and every
/// system helper process. Returns the orchestrator's failure, if any, and
/// whether everything is confirmed ended (quiescent).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn wind_down<O, S, A, P, PF, H, HE>(
    bounds: WindDown,
    ask: Option<A>,
    mut orchestration: tokio::task::JoinHandle<O>,
    stop_server: oneshot::Sender<()>,
    mut server: tokio::task::JoinHandle<S>,
    supervisors: P,
    helpers: H,
) -> (Result<()>, bool)
where
    O: std::fmt::Debug,
    A: std::future::Future<Output = ()>,
    P: FnOnce(Duration) -> PF,
    PF: std::future::Future<Output = Result<usize, usize>>,
    H: FnOnce() -> std::result::Result<(), HE> + Send + 'static,
    HE: std::fmt::Display + Send + 'static,
{
    let started = Instant::now();
    let now = tokio::time::Instant::now();
    let orchestrated_by = now + bounds.orchestrator;
    let served_by = orchestrated_by + bounds.server;
    let supervised_by = served_by + bounds.supervisors;
    let helped_by = supervised_by + bounds.helpers;
    let mut result: Result<()> = Ok(());
    let mut quiescent = true;
    let abandoned = |what: &str| {
        tracing::error!(
            stage = "shutdown.not_quiescent",
            task = what,
            "host shutdown: an aborted task did not end in time; the lock stays held until the process exits"
        );
        false
    };
    match ask {
        Some(ask) => {
            // The orchestrator bounds its own wind-down (`shutdown_budget`);
            // this backstop also covers an actor stuck inside an await.
            // Open records stay in the ledger either way.
            let drained = tokio::time::timeout_at(orchestrated_by, async {
                ask.await;
                (&mut orchestration).await
            })
            .await;
            match drained {
                Ok(Ok(run)) => tracing::info!(
                    stage = "shutdown.orchestrator_joined",
                    outcome = ?run,
                    elapsed_ms = millis(started.elapsed()),
                    "host shutdown: orchestrator ended"
                ),
                Ok(Err(e)) => result = Err(e.into()),
                Err(_) => {
                    tracing::warn!(
                        stage = "shutdown.backstop",
                        backstop_ms = millis(bounds.orchestrator),
                        "host shutdown: orchestrator did not end in time; abandoning it, open records stay in the ledger"
                    );
                    if !abort_join(&mut orchestration, served_by).await {
                        quiescent = abandoned("orchestrator");
                    }
                }
            }
        }
        None => {
            if !abort_join(&mut orchestration, served_by).await {
                quiescent = abandoned("orchestrator");
            }
        }
    }
    let _ = stop_server.send(());
    // Give the final ReleaseLease/Shutdown reply time to reach the client
    // after the orchestrator exits. Long-lived subscriptions must not pin
    // the listener or singleton lock indefinitely.
    if !server.is_finished()
        && tokio::time::timeout_at(served_by, &mut server)
            .await
            .is_err()
        && !abort_join(&mut server, supervised_by).await
    {
        quiescent = abandoned("server");
    }
    // Nothing of this host may still act on the ledger or the system once
    // another process can take the lock: end the supervisors the
    // orchestrator stopped waiting for, then every system helper process.
    let wait = supervised_by.saturating_duration_since(tokio::time::Instant::now());
    match tokio::time::timeout_at(supervised_by, supervisors(wait)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(aborted)) => tracing::warn!(
            stage = "shutdown.supervisors_aborted",
            aborted,
            "host shutdown: unfinished supervisors aborted; their open records stay in the ledger"
        ),
        Ok(Err(running)) => {
            tracing::error!(
                stage = "shutdown.supervisors_aborted",
                running,
                "host shutdown: aborted supervisors did not end in time"
            );
            quiescent = false;
        }
        Err(_) => quiescent = abandoned("supervisors"),
    }
    match tokio::time::timeout_at(helped_by, tokio::task::spawn_blocking(helpers)).await {
        Ok(Ok(Ok(()))) => tracing::info!(
            stage = "shutdown.helpers_ended",
            elapsed_ms = millis(started.elapsed()),
            "host shutdown: system helper processes ended"
        ),
        Ok(Ok(Err(e))) => {
            tracing::error!(
                stage = "shutdown.helpers_ended",
                error = %e,
                "host shutdown: system helper processes not confirmed gone; their records stay open"
            );
            quiescent = false;
        }
        Ok(Err(e)) => {
            tracing::error!(
                stage = "shutdown.helpers_ended",
                error = %e,
                "host shutdown: helper shutdown failed"
            );
            quiescent = false;
        }
        Err(_) => {
            tracing::error!(
                stage = "shutdown.helpers_ended",
                "host shutdown: helper shutdown did not return in time"
            );
            quiescent = false;
        }
    }
    (result, quiescent)
}

pub(crate) struct LayoutLock {
    _guard: HostLock,
    endpoint: Endpoint,
    form: HostForm,
}
impl LayoutLock {
    pub(crate) fn new(guard: HostLock, endpoint: Endpoint, form: HostForm) -> Self {
        Self {
            _guard: guard,
            endpoint,
            form,
        }
    }
}
impl HeldHostLock for LayoutLock {
    fn form(&self) -> HostForm {
        self.form
    }
    fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

#[cfg(windows)]
pub(crate) fn valid_sid(sid: &str) -> bool {
    let mut parts = sid.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return false;
    }
    let Some(authority) = parts.next().and_then(|text| {
        text.parse::<u64>()
            .ok()
            .filter(|value| value.to_string() == text)
    }) else {
        return false;
    };
    let subauthorities: Vec<_> = parts.collect();
    authority < (1u64 << 48)
        && !subauthorities.is_empty()
        && subauthorities.len() <= 15
        && subauthorities.iter().all(|value| {
            value
                .parse::<u32>()
                .is_ok_and(|number| number.to_string() == *value)
        })
}

/// Binding the host's endpoint failed: another process holds its name, or
/// it cannot be published. Context of the bind error.
#[derive(Debug)]
pub(crate) struct EndpointUnavailable;
impl std::fmt::Display for EndpointUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the host endpoint cannot be published")
    }
}

/// The account a host form serves and, for the elevated session, its own
/// Windows session (its peers must be in the same one). Without the
/// session no peer is authorized.
pub(crate) fn host_owner(mode: HostMode) -> io::Result<(Option<OsUserId>, Option<u32>)> {
    Ok(match mode {
        HostMode::User => (Some(platform::current_user()?), None),
        HostMode::ElevatedSession => {
            #[cfg(windows)]
            let session = etd_sysfx_os::service::elevated_session_token()
                .ok()
                .map(|token| token.session);
            #[cfg(unix)]
            let session = None;
            (Some(platform::current_user()?), session)
        }
        HostMode::Service | HostMode::Unspecified => (None, None),
    })
}

pub(crate) fn policy(mode: HostMode, entries: &[AllowEntry]) -> io::Result<ListenerPolicy> {
    let mut policy = ListenerPolicy::default();
    match mode {
        // Owner-only pipes: no allow list.
        HostMode::User | HostMode::ElevatedSession => return Ok(policy),
        HostMode::Service => (),
        HostMode::Unspecified => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported host mode",
            ));
        }
    }
    for entry in entries {
        let id = entry
            .principal
            .as_ref()
            .and_then(|principal| principal.id.as_ref())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing allow-list principal")
            })?;
        match id {
            #[cfg(windows)]
            Id::WindowsUserSid(sid) if valid_sid(sid) => {
                policy.allow_users.push(OsUserId::WindowsSid(sid.clone()))
            }
            #[cfg(windows)]
            Id::WindowsGroupSid(sid) if valid_sid(sid) => {
                policy.allow_groups.push(OsGroupId::WindowsSid(sid.clone()))
            }
            #[cfg(unix)]
            Id::UnixUid(uid) if *uid != u32::MAX => {
                policy.allow_users.push(OsUserId::UnixUid(*uid))
            }
            #[cfg(unix)]
            Id::UnixGid(gid) if *gid != u32::MAX => {
                policy.allow_groups.push(OsGroupId::UnixGid(*gid))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid allow-list principal for this platform",
                ));
            }
        }
    }
    Ok(policy)
}

struct AclSink(PolicyHandle);
impl AllowListSink for AclSink {
    fn validate(&self, entries: &[AllowEntry]) -> io::Result<()> {
        policy(HostMode::Service, entries).map(|_| ())
    }
    fn apply(&self, entries: &[AllowEntry]) -> io::Result<()> {
        self.0.update(&policy(HostMode::Service, entries)?)
    }
}

fn capabilities(mode: HostMode) -> Vec<String> {
    let mut values = vec![
        capability::INSTANCES,
        capability::LOGS,
        capability::RECLAIM,
        capability::RECLAIM_CANDIDATES,
        capability::ADMIN_CORES,
        capability::ADMIN_PURGE,
        capability::QUERY_NODES,
        capability::QUERY_ROUTES,
        capability::QUERY_TRAFFIC,
    ];
    match mode {
        HostMode::Service => values.extend([capability::TUN, capability::ADMIN_ALLOW_LIST]),
        HostMode::ElevatedSession => values.extend([capability::TUN, capability::LEASE]),
        HostMode::User => values.push(capability::LEASE),
        HostMode::Unspecified => values.clear(),
    }
    values.into_iter().map(str::to_owned).collect()
}

/// The listener, lease tracking and service lifecycle are shared by the
/// production binary and native-transport composition tests.
#[allow(dead_code)] // the tier-2 composition tests include this file
pub(crate) async fn serve_with_deps(
    mode: HostMode,
    guard: LayoutLock,
    deps: Arc<HostDeps>,
    managed_stop: Option<watch::Receiver<bool>>,
    start_blocker: Option<String>,
) -> Result<Stopped> {
    serve_with_deps_and(mode, guard, deps, managed_stop, start_blocker, None).await
}

/// [`serve_with_deps`], running `on_serving` once the startup self-check
/// reaches Serving (not when it ends in diagnostics-only or shutdown).
pub(crate) async fn serve_with_deps_and(
    mode: HostMode,
    guard: LayoutLock,
    deps: Arc<HostDeps>,
    mut managed_stop: Option<watch::Receiver<bool>>,
    start_blocker: Option<String>,
    on_serving: Option<Box<dyn FnOnce() + Send>>,
) -> Result<Stopped> {
    // Load the exact durable settings before publishing the endpoint; no
    // mutation task exists until the new listener is bound with that policy.
    let entries = deps.ledger.settings().await?.allow_list;
    let (owner, session) = host_owner(mode)?;
    let auth = Arc::new(AllowListAuthorizer::new(mode, owner).with_session(session));
    auth.load(deps.ledger.as_ref()).await?;
    let lease = LeaseRule::of(mode)?;
    let listener =
        LocalListener::bind_replacing_stale(guard.listener_claim(), &policy(mode, &entries)?)
            .context(EndpointUnavailable)?;
    let sink = Arc::new(AclSink(listener.policy_handle()));
    let mut deps = Arc::into_inner(deps).context("unexpected host dependency sharing")?;
    deps.authorizer = auth.clone();
    let deps = Arc::new(deps);
    let (handle, port) = orchestrator_channel(
        CAPACITY,
        HostView {
            seq: 0,
            snapshot: v1::HostSnapshot {
                phase: v1::HostPhase::SelfCheck as i32,
                ..Default::default()
            },
        },
    );
    if let Some(on_serving) = on_serving {
        let mut view = handle.watch_view();
        tokio::spawn(async move {
            loop {
                let phase = view.borrow_and_update().snapshot.phase;
                match v1::HostPhase::try_from(phase) {
                    Ok(v1::HostPhase::Serving) => {
                        let _ = tokio::task::spawn_blocking(on_serving).await;
                        return;
                    }
                    Ok(v1::HostPhase::DiagnosticOnly | v1::HostPhase::ShuttingDown) => return,
                    _ => {}
                }
                if view.changed().await.is_err() {
                    return;
                }
            }
        });
    }
    let svc = ContractService::with_allow_list_sink(
        mode,
        deps.ledger.clone(),
        deps.install_key.clone(),
        auth,
        deps.core_store.clone(),
        handle.clone(),
        capabilities(mode),
        CAPACITY,
        sink,
    )
    .with_start_blocker(start_blocker);
    let incoming = tonic_io::incoming(TrackedListener::new(listener, svc.clone(), lease));
    let orchestrator = Orchestrator::new(deps, port);
    let budget = orchestrator.shutdown_budget();
    let supervisors = orchestrator.supervisor_tasks();
    let mut orchestration = tokio::spawn(orchestrator.run());
    let (stop_server, stop_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(
        tonic::transport::Server::builder()
            // Incompatible version metadata is refused before the body is
            // decoded; the handlers check it again.
            .add_service(HostServiceServer::with_interceptor(svc, VersionInterceptor))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stop_rx.await;
            }),
    );
    // Every way out below runs the same cleanup before the lock goes.
    let mut result: Result<()> = Ok(());
    let outcome = tokio::select! {
        joined = &mut orchestration => {
            if let Err(e) = joined {
                result = Err(e.into());
            }
            None
        },
        served = &mut server => Some(match served {
            Ok(served) => served.map_err(anyhow::Error::from),
            Err(e) => Err(e.into()),
        }),
        signal = shutdown_signal(&mut managed_stop) => Some(signal.map_err(anyhow::Error::from)),
    };
    let started = Instant::now();
    let bounds = WindDown::new(budget);
    let ask = outcome.is_some().then(|| {
        tracing::info!(
            stage = "shutdown.requested",
            worst_case_ms = millis(stop_worst_case()),
            "host shutdown: asking the orchestrator to stop"
        );
        let handle = handle.clone();
        async move {
            let (reply, acknowledged) = oneshot::channel();
            if handle.send(Command::Shutdown { reply }).await.is_ok() {
                let _ = acknowledged.await;
            }
        }
    });
    let (wound, quiescent) = wind_down(
        bounds,
        ask,
        orchestration,
        stop_server,
        server,
        move |wait| async move { supervisors.abort_and_wait(wait).await },
        etd_sysfx_os::shutdown_helpers,
    )
    .await;
    result = result.and(wound);
    if let Some(Err(e)) = outcome {
        result = result.and(Err(e));
    }
    tracing::info!(
        stage = "shutdown.served",
        elapsed_ms = millis(started.elapsed()),
        quiescent,
        "host shutdown: listener closed; the lock is released once the runtime is down"
    );
    Ok(Stopped {
        lock: guard,
        result,
        quiescent,
    })
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

async fn shutdown_signal(managed: &mut Option<watch::Receiver<bool>>) -> io::Result<()> {
    if let Some(stop) = managed {
        if !*stop.borrow() {
            let _ = stop.changed().await;
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c().await
    }
}

/// Which connections hold the lease that keeps a user or elevated session
/// host alive.
enum LeaseRule {
    /// The service: no lease.
    None,
    /// The user host: every connection (all are the owner's).
    Every,
    /// The elevated session host: connections whose client process image,
    /// read from a handle opened on the client pid at accept and kept for
    /// the connection's life, is the `etd-ui.exe` beside the host image
    /// (compared canonically, case-insensitively). This does not
    /// authenticate the UI: any program of the same user at that path
    /// counts. Protecting that path is the installer's job (accepted risk,
    /// issue #2). Other clients (the CLI) are connections, not holders.
    UiImage(Option<std::path::PathBuf>),
}

impl LeaseRule {
    fn of(mode: HostMode) -> io::Result<Self> {
        Ok(match mode {
            HostMode::Service | HostMode::Unspecified => Self::None,
            HostMode::User => Self::Every,
            HostMode::ElevatedSession => Self::UiImage(sibling_ui()),
        })
    }

    /// Whether the client `peer` holds the lease, and the process pin that
    /// keeps that answer true while the connection lives.
    fn holds(&self, peer: &PeerIdentity) -> (bool, Option<ClientPin>) {
        match self {
            Self::None => (false, None),
            Self::Every => (true, None),
            #[cfg(windows)]
            Self::UiImage(Some(ui)) => match etd_sysfx_os::service::ProcessPin::open(peer.pid) {
                Ok(pin) => {
                    let holds = pin
                        .image()
                        .and_then(std::fs::canonicalize)
                        .is_ok_and(|image| same_path(&image, ui));
                    (holds, Some(pin))
                }
                Err(error) => {
                    tracing::warn!(pid = peer.pid, %error, "client process not inspectable; not a lease holder");
                    (false, None)
                }
            },
            // No elevated session host on Unix.
            #[cfg(unix)]
            Self::UiImage(_) => {
                let _ = peer;
                (false, None)
            }
            #[cfg(windows)]
            Self::UiImage(None) => (false, None),
        }
    }
}

/// The canonical `etd-ui.exe` beside this host's image, if there is one.
fn sibling_ui() -> Option<std::path::PathBuf> {
    let host = std::env::current_exe().ok()?.canonicalize().ok()?;
    let ui = host
        .parent()?
        .join(format!("etd-ui{}", std::env::consts::EXE_SUFFIX));
    match ui.canonicalize() {
        Ok(ui) => Some(ui),
        Err(error) => {
            tracing::warn!(path = %ui.display(), %error, "no desktop UI beside the host; no connection holds the lease");
            None
        }
    }
}

#[cfg(windows)]
fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    a.as_os_str()
        .to_string_lossy()
        .to_lowercase()
        .eq(&b.as_os_str().to_string_lossy().to_lowercase())
}

/// Keeps the client process object (and so its pid) alive.
#[cfg(windows)]
type ClientPin = etd_sysfx_os::service::ProcessPin;
#[cfg(unix)]
type ClientPin = std::convert::Infallible;

#[derive(Default)]
struct Counts {
    connections: usize,
    holders: usize,
}
struct Presence {
    counts: Mutex<Counts>,
    service: ContractService,
}
impl Presence {
    fn change(&self, add: bool, holder: bool) {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if add {
            counts.connections += 1;
            counts.holders += usize::from(holder);
        } else {
            counts.connections = counts.connections.saturating_sub(1);
            if holder {
                counts.holders = counts.holders.saturating_sub(1);
            }
        }
        self.service
            .set_connection_presence(counts.connections, counts.holders);
    }
}
struct TrackedListener {
    listener: LocalListener,
    lease: LeaseRule,
    presence: Arc<Presence>,
}
impl TrackedListener {
    fn new(listener: LocalListener, service: ContractService, lease: LeaseRule) -> Self {
        Self {
            listener,
            lease,
            presence: Arc::new(Presence {
                counts: Mutex::new(Counts::default()),
                service,
            }),
        }
    }
}
#[async_trait::async_trait]
impl Listener for TrackedListener {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)> {
        let (conn, peer) = self.listener.accept().await?;
        let (holder, pin) = self.lease.holds(&peer);
        self.presence.change(true, holder);
        Ok((
            Box::new(TrackedConnection {
                conn,
                presence: self.presence.clone(),
                holder,
                _pin: pin,
            }),
            peer,
        ))
    }
}
struct TrackedConnection {
    conn: BoxConn,
    presence: Arc<Presence>,
    holder: bool,
    _pin: Option<ClientPin>,
}
impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.presence.change(false, self.holder);
    }
}
impl AsyncRead for TrackedConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}
impl AsyncWrite for TrackedConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.conn).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;

    fn peer(pid: u32) -> PeerIdentity {
        PeerIdentity {
            user: OsUserId::UnixUid(1),
            groups: vec![],
            pid,
            session: None,
            elevated: false,
        }
    }

    #[test]
    fn only_the_rule_of_the_form_decides_the_lease() {
        let me = peer(std::process::id());
        assert!(!LeaseRule::None.holds(&me).0, "the service has no lease");
        assert!(LeaseRule::Every.holds(&me).0, "every user host connection");
        assert!(
            !LeaseRule::UiImage(None).holds(&me).0,
            "no UI beside the host: no holder"
        );
        assert!(matches!(
            LeaseRule::of(HostMode::Service).unwrap(),
            LeaseRule::None
        ));
        assert!(matches!(
            LeaseRule::of(HostMode::User).unwrap(),
            LeaseRule::Every
        ));
        assert!(matches!(
            LeaseRule::of(HostMode::ElevatedSession).unwrap(),
            LeaseRule::UiImage(_)
        ));
    }

    /// The client's image, read from a handle on its pid, must be exactly
    /// the UI path (here this test process stands in for the UI).
    #[cfg(windows)]
    #[test]
    fn an_elevated_session_lease_needs_the_ui_image() {
        let me = peer(std::process::id());
        let image = std::env::current_exe().unwrap().canonicalize().unwrap();
        let (holds, pin) = LeaseRule::UiImage(Some(image.clone())).holds(&me);
        assert!(holds);
        assert!(pin.is_some(), "the client process stays pinned");
        let upper = std::path::PathBuf::from(image.to_string_lossy().to_uppercase());
        assert!(
            LeaseRule::UiImage(Some(upper)).holds(&me).0,
            "case-insensitive"
        );
        let other = image.with_file_name("etd-ui.exe");
        assert!(!LeaseRule::UiImage(Some(other)).holds(&me).0);
        // A pid that cannot be opened holds nothing.
        assert!(!LeaseRule::UiImage(Some(image)).holds(&peer(0)).0);
    }
}

#[cfg(test)]
mod stop_bound_tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    }

    fn short() -> WindDown {
        WindDown {
            orchestrator: Duration::from_millis(300),
            server: Duration::from_millis(200),
            supervisors: Duration::from_millis(200),
            helpers: Duration::from_millis(200),
        }
    }

    /// Every stage stalls: tasks that never reach an await once aborted, a
    /// supervisor wait and a helper call that never return. The wind-down
    /// still ends by its total and reports the host not quiescent.
    #[test]
    fn a_stalled_wind_down_still_ends_by_its_total() {
        let runtime = runtime();
        let (release, stalled) = std::sync::mpsc::channel::<()>();
        let stalled = Arc::new(Mutex::new(stalled));
        let stall = {
            let stalled = stalled.clone();
            move || {
                let _ = stalled
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30));
            }
        };
        let bounds = short();
        let (took, quiescent) = runtime.block_on(async {
            // Blocks its worker thread: abort cannot reach it.
            let orchestration = tokio::spawn({
                let stall = stall.clone();
                async move { stall() }
            });
            let server = tokio::spawn({
                let stall = stall.clone();
                async move { stall() }
            });
            let (stop_server, _) = oneshot::channel();
            let started = Instant::now();
            let (_, quiescent) = wind_down(
                bounds,
                Some(std::future::pending::<()>()),
                orchestration,
                stop_server,
                server,
                |_| std::future::pending::<Result<usize, usize>>(),
                move || -> std::result::Result<(), String> {
                    stall();
                    Ok(())
                },
            )
            .await;
            (started.elapsed(), quiescent)
        });
        drop(release);
        runtime.shutdown_background();
        assert!(!quiescent);
        assert!(
            took < bounds.total() + Duration::from_millis(500),
            "took {took:?}, bound {:?}",
            bounds.total()
        );
    }

    #[test]
    fn a_clean_wind_down_is_quiescent() {
        let runtime = runtime();
        let (result, quiescent) = runtime.block_on(async {
            let orchestration = tokio::spawn(async { 1 });
            let (stop_server, stopped) = oneshot::channel::<()>();
            let server = tokio::spawn(async move {
                let _ = stopped.await;
            });
            wind_down(
                short(),
                Some(async {}),
                orchestration,
                stop_server,
                server,
                |_| async { Ok(0) },
                || -> std::result::Result<(), String> { Ok(()) },
            )
            .await
        });
        assert!(result.is_ok() && quiescent);
    }

    /// The orchestrator or the server ended first: its handle was already
    /// polled to completion and must not be awaited again.
    #[test]
    fn handles_already_joined_are_not_awaited_again() {
        let runtime = runtime();
        let (_, quiescent) = runtime.block_on(async {
            let mut orchestration = tokio::spawn(async {});
            let mut server = tokio::spawn(async {});
            (&mut orchestration).await.unwrap();
            (&mut server).await.unwrap();
            let (stop_server, _) = oneshot::channel::<()>();
            wind_down(
                short(),
                None::<std::future::Ready<()>>,
                orchestration,
                stop_server,
                server,
                |_| async { Ok(0) },
                || -> std::result::Result<(), String> { Ok(()) },
            )
            .await
        });
        assert!(quiescent);
    }

    #[test]
    fn unconfirmed_helpers_leave_the_host_not_quiescent() {
        let runtime = runtime();
        let (_, quiescent) = runtime.block_on(async {
            let (stop_server, _) = oneshot::channel::<()>();
            wind_down(
                short(),
                None::<std::future::Ready<()>>,
                tokio::spawn(async {}),
                stop_server,
                tokio::spawn(async {}),
                |_| async { Ok(0) },
                || -> std::result::Result<(), String> { Err("still alive".into()) },
            )
            .await
        });
        assert!(!quiescent);
    }

    #[test]
    fn a_host_stop_fits_the_uninstaller_wait() {
        let worst = stop_worst_case();
        // The uninstaller waits 60 s for STOPPED after its STOP; keep a
        // margin for the SCM and the service thread.
        assert!(
            worst <= Duration::from_secs(55),
            "worst-case host stop {worst:?} exceeds 55 s"
        );
    }
}
