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

pub(crate) fn policy(mode: HostMode, entries: &[AllowEntry]) -> io::Result<ListenerPolicy> {
    let mut policy = ListenerPolicy::default();
    if mode == HostMode::User {
        return Ok(policy);
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
    if mode == HostMode::Service {
        values.extend([capability::TUN, capability::ADMIN_ALLOW_LIST]);
    } else {
        values.push(capability::LEASE);
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
    let owner = if mode == HostMode::User {
        Some(platform::current_user()?)
    } else {
        None
    };
    let auth = Arc::new(AllowListAuthorizer::new(mode, owner));
    auth.load(deps.ledger.as_ref()).await?;
    let listener =
        LocalListener::bind_replacing_stale(guard.listener_claim(), &policy(mode, &entries)?)?;
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
    let incoming = tonic_io::incoming(TrackedListener::new(listener, svc.clone(), mode));
    let orchestrator = Orchestrator::new(deps, port);
    let budget = orchestrator.shutdown_budget();
    let supervisors = orchestrator.supervisor_tasks();
    let mut orchestration = tokio::spawn(orchestrator.run());
    let (stop_server, stop_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(HostServiceServer::new(svc))
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

struct Presence {
    count: Mutex<usize>,
    service: ContractService,
    user: bool,
}
impl Presence {
    fn change(&self, add: bool) {
        let mut count = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if add {
            *count += 1;
        } else {
            *count = count.saturating_sub(1);
        }
        self.service
            .set_connection_presence(*count, if self.user { *count } else { 0 });
    }
}
struct TrackedListener {
    listener: LocalListener,
    presence: Arc<Presence>,
}
impl TrackedListener {
    fn new(listener: LocalListener, service: ContractService, mode: HostMode) -> Self {
        Self {
            listener,
            presence: Arc::new(Presence {
                count: Mutex::new(0),
                service,
                user: mode == HostMode::User,
            }),
        }
    }
}
#[async_trait::async_trait]
impl Listener for TrackedListener {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)> {
        let (conn, peer) = self.listener.accept().await?;
        self.presence.change(true);
        Ok((
            Box::new(TrackedConnection {
                conn,
                presence: self.presence.clone(),
            }),
            peer,
        ))
    }
}
struct TrackedConnection {
    conn: BoxConn,
    presence: Arc<Presence>,
}
impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.presence.change(false);
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
