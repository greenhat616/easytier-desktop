//! Composition root: all OS work is performed by the adapters it assembles.
use crate::storage::{self, FileIndex};
use crate::unavailable::{BlockedDriver, MissingNative};
use anyhow::{Context, Result, bail, ensure};
use etd_contract::{
    AllowEntry, HostMode, Role, capability,
    v1::{self, OsPrincipal, os_principal::Id},
};
use etd_core_api::CoreDriver;
use etd_core_easytier::EasyTierDriver;
use etd_host_core::{
    api::{Command, HostDeps, HostDirs, HostView, orchestrator_channel},
    auth::allow_list::AllowListAuthorizer,
    core_store::manifest::ManifestCoreStore,
    lifecycle::Orchestrator,
    reclaimers::host_reclaimers,
    service::{AllowListSink, ContractService},
    stub::host_service_server::HostServiceServer,
};
use etd_ipc::{
    BoxConn, Endpoint, HostForm, Listener, ListenerPolicy, OsGroupId, OsUserId, PeerIdentity,
    platform::{self, HeldHostLock, LocalListener, PolicyHandle},
    tonic_io,
};
use etd_proc::{
    Clock, ProcessEngine,
    backoff::{BackoffPolicy, SystemClock},
    processkit_engine::ProcessKitEngine,
};
use etd_sysfx::{
    BootId, Change, ChangeSet, EffectScope, GenerationOutcome, Ledger, ReclaimDeps, ReclaimReport,
    ReclaimScope, RepairIndexStore, RequestDigest, RequestRecord, ScopeFilter,
    engine::ReclaimEngineImpl, sqlite::SqliteLedger,
};
use etd_sysfx_os::{
    OsConfig, OsError,
    service::{
        HostFilesystem, HostLayout, HostLock, NativeHostFilesystem, NativeServiceManager,
        ServiceManager,
    },
};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{oneshot, watch},
};

const CAPACITY: usize = 256;
const LEDGER: &str = "ledger.sqlite3";

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

fn layout(mode: HostMode) -> Result<HostLayout> {
    match mode {
        HostMode::Service => Ok(NativeHostFilesystem.service_layout()?),
        HostMode::User => {
            #[cfg(target_os = "linux")]
            let runtime = Some(platform::user_runtime_dir());
            #[cfg(target_os = "macos")]
            let runtime = Some(etd_sysfx_os::service::user_temp_runtime()?);
            #[cfg(windows)]
            let runtime: Option<std::path::PathBuf> = None;
            Ok(NativeHostFilesystem.user_layout(None, runtime.as_deref())?)
        }
        _ => bail!("unsupported host mode"),
    }
}

fn endpoint(mode: HostMode, layout: &HostLayout) -> Result<Endpoint> {
    #[cfg(windows)]
    {
        let _ = layout;
        if mode == HostMode::Service {
            return Ok(Endpoint::NamedPipe(etd_ipc::SERVICE_PIPE_NAME.into()));
        }
        let OsUserId::WindowsSid(sid) = platform::current_user()? else {
            bail!("Windows user SID unavailable")
        };
        Ok(Endpoint::NamedPipe(format!(
            r"\\.\pipe\easytier-desk-user-{sid}"
        )))
    }
    #[cfg(unix)]
    {
        let _ = mode;
        Ok(Endpoint::UnixSocket(
            layout
                .socket_dir
                .as_ref()
                .context("missing socket directory")?
                .join("host.sock"),
        ))
    }
}

fn os_config(layout: &HostLayout) -> OsConfig {
    OsConfig {
        state_dir: layout.state.clone(),
        run_dir: layout.run.clone(),
        core_store_dir: layout.cores.clone(),
    }
}

fn prepare(mode: HostMode, layout: &HostLayout) -> Result<()> {
    match mode {
        HostMode::User => {
            ensure!(
                !NativeServiceManager.entry_is_elevated()?,
                "an elevated token cannot operate a user host; use the installed system service instead"
            );
            NativeHostFilesystem.prepare_user(layout)?;
        }
        HostMode::Service => NativeHostFilesystem.validate_service(layout)?,
        _ => bail!("unsupported host mode"),
    }
    Ok(())
}

#[cfg(windows)]
fn valid_sid(sid: &str) -> bool {
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

fn policy(mode: HostMode, entries: &[AllowEntry]) -> io::Result<ListenerPolicy> {
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

struct Dependencies {
    host: Arc<HostDeps>,
    missing: Option<String>,
    sqlite: Arc<SqliteLedger>,
}
impl Dependencies {
    async fn close(self) -> Result<()> {
        drop(self.host);
        Arc::try_unwrap(self.sqlite)
            .map_err(|_| anyhow::anyhow!("ledger still has active owners"))?
            .close()
            .await?;
        Ok(())
    }
}

async fn dependencies(mode: HostMode, layout: &HostLayout) -> Result<Dependencies> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let process: Arc<dyn ProcessEngine> = Arc::new(ProcessKitEngine::with_console_helper(
        layout.executable.clone(),
    ));
    let index = Arc::new(FileIndex::new(&layout.state));
    let ledger_exists = storage::ledger_exists(&layout.state)?;
    let fresh = !ledger_exists && index.load()?.is_none();
    let (os, missing) = match etd_sysfx_os::adapters(&os_config(layout)) {
        Ok(os) => {
            storage::native_history(&layout.state, true, fresh)?;
            (os, None)
        }
        Err(OsError::Unsupported(reason)) => {
            let never_enabled = storage::native_history(&layout.state, false, fresh)?;
            let reason = format!("native system adapters unavailable: {reason}");
            (
                MissingNative {
                    reason: reason.clone(),
                    never_enabled,
                }
                .adapters(),
                Some(reason),
            )
        }
        Err(error) => return Err(error.into()),
    };
    let boot = if missing.is_some() {
        BootId("native-adapter-unavailable".into())
    } else {
        os.boot_id.current()?
    };
    let install_key = index.initialize(ledger_exists)?;
    let sqlite = Arc::new(SqliteLedger::open(layout.state.join(LEDGER), boot).await?);
    let ledger: Arc<dyn Ledger> = sqlite.clone();
    storage::initialize_manifest(&layout.cores)?;
    let driver: Arc<dyn CoreDriver> = match &missing {
        Some(reason) => Arc::new(BlockedDriver(reason.clone())),
        None => Arc::new(EasyTierDriver),
    };
    let store = Arc::new(ManifestCoreStore::new(
        layout.cores.clone(),
        mode,
        driver.clone(),
    )?);
    let mut reclaimers = os.reclaimers;
    reclaimers.extend(host_reclaimers(
        process.clone(),
        clock.clone(),
        layout.run.clone(),
    ));
    let reclaim = Arc::new(ReclaimEngineImpl::new(ReclaimDeps {
        ledger: ledger.clone(),
        reclaimers,
        sweeper: os.sweeper,
        boot_id: os.boot_id.clone(),
        repair_index: index.clone(),
    }));
    let owner = if mode == HostMode::User {
        Some(platform::current_user()?)
    } else {
        None
    };
    let authorizer = Arc::new(AllowListAuthorizer::new(mode, owner));
    authorizer.load(ledger.as_ref()).await?;
    let host = Arc::new(HostDeps {
        mode,
        dirs: HostDirs {
            state_dir: layout.state.clone(),
            run_dir: layout.run.clone(),
            core_store_dir: layout.cores.clone(),
        },
        process,
        restart_policy: Arc::new(|| Box::new(BackoffPolicy::new())),
        clock,
        ledger,
        repair_index: index,
        reclaim,
        boot_id: os.boot_id,
        install_key,
        observer: os.observer,
        fence: if mode == HostMode::Service {
            os.fence
        } else {
            None
        },
        core: driver,
        core_store: store,
        authorizer,
    });
    Ok(Dependencies {
        host,
        missing,
        sqlite,
    })
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

pub async fn run(mode: HostMode) -> Result<()> {
    run_until(mode, None).await
}

pub async fn run_until(mode: HostMode, managed_stop: Option<watch::Receiver<bool>>) -> Result<()> {
    let layout = layout(mode)?;
    prepare(mode, &layout)?;
    if mode == HostMode::Service {
        ensure!(
            NativeHostFilesystem.is_installed_image(&layout)?,
            "service must run from the protected installed executable"
        );
        #[cfg(windows)]
        ensure!(
            matches!(platform::current_user()?, OsUserId::WindowsSid(ref sid) if sid == "S-1-5-18"),
            "service requires LocalSystem"
        );
        #[cfg(unix)]
        ensure!(
            matches!(platform::current_user()?, OsUserId::UnixUid(0)),
            "service requires root"
        );
    }
    let form = if mode == HostMode::Service {
        HostForm::Service
    } else {
        HostForm::User
    };
    let guard = LayoutLock::new(
        NativeHostFilesystem.lock(&layout)?,
        endpoint(mode, &layout)?,
        form,
    );
    let _logging = logging(&layout)?;
    let deps = dependencies(mode, &layout).await?;
    serve_with_deps(mode, guard, deps.host, managed_stop, deps.missing).await
}

/// The listener, lease tracking and service lifecycle are shared by the
/// production binary and native-transport composition tests.
pub(crate) async fn serve_with_deps(
    mode: HostMode,
    guard: LayoutLock,
    deps: Arc<HostDeps>,
    mut managed_stop: Option<watch::Receiver<bool>>,
    start_blocker: Option<String>,
) -> Result<()> {
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
    let mut orchestration = tokio::spawn(orchestrator.run());
    let (stop_server, stop_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(HostServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stop_rx.await;
            }),
    );
    let outcome = tokio::select! {
        result = &mut orchestration => { result?; None },
        result = &mut server => { Some(result?.map_err(anyhow::Error::from)) },
        result = shutdown_signal(&mut managed_stop) => { result?; Some(Ok(())) },
    };
    if let Some(outcome) = outcome {
        let (reply, acknowledged) = oneshot::channel();
        if handle.send(Command::Shutdown { reply }).await.is_ok() {
            let _ = acknowledged.await;
        }
        orchestration.await?;
        outcome?;
    }
    let _ = stop_server.send(());
    if !server.is_finished() {
        // Give the final ReleaseLease/Shutdown reply time to reach the
        // client after the orchestrator exits. Long-lived subscriptions must
        // not pin the listener or singleton lock indefinitely.
        if tokio::time::timeout(std::time::Duration::from_secs(3), &mut server)
            .await
            .is_err()
        {
            server.abort();
            let _ = server.await;
        }
    }
    drop(guard);
    Ok(())
}

fn logging(layout: &HostLayout) -> Result<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::util::SubscriberInitExt;
    let appender = tracing_appender::rolling::daily(&layout.state, "host.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer)
        .with_max_level(tracing::Level::INFO)
        .finish()
        .try_init()
        .context("host logging initialization")?;
    Ok(guard)
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

pub fn doctor() -> Result<()> {
    println!("EasyTier Desktop host {}", env!("CARGO_PKG_VERSION"));
    for mode in [HostMode::User, HostMode::Service] {
        let layout = layout(mode)?;
        println!(
            "{mode:?}: state={}, core store={}",
            layout.state.display(),
            layout.cores.display()
        );
        match etd_sysfx_os::adapters(&os_config(&layout)) {
            Ok(_) => println!("  platform adapters available"),
            Err(error) => println!("  platform adapters unavailable: {error}"),
        }
    }
    Ok(())
}

fn entry(id: Id, role: Role) -> AllowEntry {
    AllowEntry {
        principal: Some(OsPrincipal { id: Some(id) }),
        role: role as i32,
        display_name: String::new(),
    }
}

fn enrolled_users(users: &[String]) -> Result<Vec<AllowEntry>> {
    let mut entries = Vec::new();
    for user in users {
        #[cfg(windows)]
        let id = {
            ensure!(valid_sid(user), "expected a numeric SID");
            Id::WindowsUserSid(user.clone())
        };
        #[cfg(unix)]
        let id = {
            let uid = user.parse::<u32>().context("expected a numeric UID")?;
            ensure!(uid != u32::MAX, "invalid UID");
            Id::UnixUid(uid)
        };
        let item = entry(id, Role::Admin);
        if !entries.contains(&item) {
            entries.push(item);
        }
    }
    Ok(entries)
}

fn seed_entries(users: Vec<AllowEntry>) -> Result<Vec<AllowEntry>> {
    #[cfg(windows)]
    let mut entries = vec![
        entry(Id::WindowsUserSid("S-1-5-18".into()), Role::Admin),
        entry(Id::WindowsGroupSid("S-1-5-32-544".into()), Role::Admin),
    ];
    #[cfg(unix)]
    let mut entries = vec![
        entry(Id::UnixUid(0), Role::Admin),
        entry(
            Id::UnixGid(etd_sysfx_os::service::service_group_id()?),
            Role::Control,
        ),
    ];
    for item in users {
        if !entries.contains(&item) {
            entries.push(item);
        }
    }
    Ok(entries)
}

async fn maintenance_change(ledger: &dyn Ledger, change: Change) -> Result<v1::Receipt> {
    let revision = ledger.desired().await?.0;
    Ok(ledger
        .commit(
            revision,
            ChangeSet {
                request: RequestRecord {
                    request_id: uuid::Uuid::new_v4().to_string().into(),
                    caller: "local maintenance".into(),
                    digest: RequestDigest(rand::random()),
                },
                changes: vec![change],
                generations: vec![],
            },
        )
        .await?)
}

pub async fn install(users: &[String]) -> Result<()> {
    let users = enrolled_users(users)?;
    let mode = HostMode::Service;
    let layout = layout(mode)?;
    ensure!(
        NativeServiceManager.entry_is_elevated()?,
        "administrator privileges required"
    );
    NativeServiceManager.prepare_install(&layout)?;
    let guard = NativeHostFilesystem.lock(&layout)?;
    let deps = dependencies(mode, &layout).await?;
    let entries = seed_entries(users)?;
    policy(mode, &entries)?;
    maintenance_change(deps.host.ledger.as_ref(), Change::SetAllowList(entries)).await?;
    deps.close().await?;
    drop(guard);
    NativeServiceManager.register(&layout)?;
    Ok(())
}

async fn reclaim_locked(deps: &HostDeps, purge: bool) -> Result<()> {
    let scope = if purge {
        ReclaimScope::Everything
    } else {
        ReclaimScope::Instances
    };
    let receipt = if purge {
        Some(maintenance_change(deps.ledger.as_ref(), Change::PurgeAll).await?)
    } else {
        None
    };
    let report = deps.reclaim.reclaim_all(scope).await?;
    print_report(&report);
    let filter = if purge {
        ScopeFilter::all()
    } else {
        ScopeFilter::default()
    };
    ensure!(
        deps.ledger.open_effects(&filter).await?.is_empty()
            && report.candidates.is_empty()
            && report.conflicts.is_empty()
            && report
                .generations
                .iter()
                .all(|item| item.outcome == GenerationOutcome::Closed)
            && !report
                .notes
                .iter()
                .any(|note| note.starts_with("sweep failed:")),
        "reclaim incomplete; keeping ownership data for retry"
    );
    if let Some(receipt) = receipt {
        deps.ledger.complete_ticket(&receipt.ticket).await?;
    }
    deps.ledger.compact().await?;
    Ok(())
}

fn print_report(report: &ReclaimReport) {
    println!(
        "Reclaim: {} generations, {} candidates, {} conflicts",
        report.generations.len(),
        report.candidates.len(),
        report.conflicts.len()
    );
    for note in &report.notes {
        println!("  {note}");
    }
}

pub async fn reclaim(mode: HostMode, _all: bool, purge: bool) -> Result<()> {
    let layout = layout(mode)?;
    prepare(mode, &layout)?;
    let _guard = NativeHostFilesystem.lock(&layout)?;
    let deps = dependencies(mode, &layout).await?;
    reclaim_locked(&deps.host, purge).await?;
    deps.close().await
}

pub async fn uninstall() -> Result<()> {
    let mode = HostMode::Service;
    let layout = layout(mode)?;
    ensure!(
        NativeServiceManager.entry_is_elevated()?,
        "administrator privileges required"
    );
    NativeServiceManager.stop_and_disable(&layout)?;
    let _guard = NativeHostFilesystem.lock(&layout)?;
    // Exactly the reclaim --all --purge path, whilst holding the same lock.
    // Unregister and remove only after all ownership records are closed.
    let deps = dependencies(mode, &layout).await?;
    reclaim_locked(&deps.host, true).await?;
    deps.close().await?;
    NativeServiceManager.remove(&layout)?;
    Ok(())
}

pub async fn remove_core(mode: HostMode, version: &str) -> Result<()> {
    let layout = layout(mode)?;
    prepare(mode, &layout)?;
    let _guard = NativeHostFilesystem.lock(&layout)?;
    let resources = dependencies(mode, &layout).await?;
    let deps = &resources.host;
    let core = deps
        .core_store
        .list()
        .await?
        .into_iter()
        .find(|core| core.version == version)
        .context("unknown kernel version")?;
    let report = deps.reclaim.reclaim_core(&core.sha256).await?;
    print_report(&report);
    ensure!(
        report.candidates.is_empty() && report.conflicts.is_empty(),
        "kernel has unresolved reclaim candidates or conflicts"
    );
    ensure!(!deps.ledger.open_effects(&ScopeFilter { core_binary: true, ..Default::default() }).await?.iter().any(|effect| matches!(&effect.scope, EffectScope::CoreBinary { sha256 } if sha256 == &core.sha256)), "kernel still has open core-binary records");
    if deps.ledger.settings().await?.selected_core.as_deref() == Some(version) {
        let receipt = maintenance_change(deps.ledger.as_ref(), Change::SelectCore(None)).await?;
        deps.ledger.complete_ticket(&receipt.ticket).await?;
    }
    deps.core_store.remove(version).await?;
    resources.close().await
}
