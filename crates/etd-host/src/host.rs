//! Composition root: all OS work is performed by the adapters it assembles.
use crate::storage::{self, FileIndex};
use crate::unavailable::{BlockedDriver, MissingNative, NoNewEffects};
use anyhow::{Context, Result, bail, ensure};
use etd_contract::{
    AllowEntry, HostMode, Role,
    v1::{self, OsPrincipal, os_principal::Id},
};
use etd_core_api::CoreDriver;
use etd_core_easytier::EasyTierDriver;
use etd_host_core::{
    api::{HostDeps, HostDirs},
    auth::allow_list::AllowListAuthorizer,
    core_store::manifest::ManifestCoreStore,
    reclaimers::host_reclaimers,
};
use etd_ipc::{
    Endpoint, HostForm, ListenerPolicy, OsUserId,
    platform::{self, HeldHostLock, LocalListener},
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
        DeferredOutcome, HostFilesystem, HostLayout, LifecycleJournal, MaintenanceLock,
        NativeHostFilesystem, NativeServiceManager, Phase, Resource, ServiceManager,
    },
};
#[cfg(windows)]
use std::io;
use std::sync::Arc;
use tokio::sync::watch;

#[path = "serving.rs"]
mod serving;
use serving::policy;
#[cfg(windows)]
use serving::valid_sid;
pub(crate) use serving::{LayoutLock, serve_with_deps};
/// See [`serving::RUNTIME_SHUTDOWN`].
pub(crate) const RUNTIME_SHUTDOWN: std::time::Duration = serving::RUNTIME_SHUTDOWN;
const LEDGER: &str = "ledger.sqlite3";

fn layout(mode: HostMode) -> Result<HostLayout> {
    match mode {
        HostMode::Service => Ok(NativeHostFilesystem.service_layout()?),
        HostMode::User => {
            #[cfg(target_os = "linux")]
            let runtime = Some(platform::user_runtime_dir());
            #[cfg(target_os = "macos")]
            let runtime = Some(platform::user_runtime_dir()?);
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
    let ledger: Arc<dyn Ledger> = if missing.is_some() {
        Arc::new(NoNewEffects(sqlite.clone()))
    } else {
        sqlite.clone()
    };
    if mode == HostMode::User {
        storage::cleanup_user_core_orphans(&layout.cores)?;
    }
    if mode == HostMode::User && !storage::manifest_exists(&layout.cores)? {
        storage::install_bundled_cores(
            layout
                .executable
                .parent()
                .context("missing user host image directory")?,
            &layout.cores,
            mode,
        )
        .await?;
    } else {
        storage::initialize_manifest(&layout.cores)?;
    }
    let driver: Arc<dyn CoreDriver> = match &missing {
        Some(reason) => Arc::new(BlockedDriver(reason.clone())),
        None => Arc::new(EasyTierDriver),
    };
    let store = ManifestCoreStore::new(
        layout.cores.clone(),
        mode,
        driver.clone(),
        storage::trusted_cores(),
    )?;
    let store = Arc::new(if mode == HostMode::Service {
        store.with_removal_guard(|dir| {
            etd_sysfx_os::driver_bundle_referenced(dir)
                .map_err(|error| etd_host_core::core_store::StoreError::Io(error.to_string()))
        })
    } else {
        store
    });
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

pub async fn run(mode: HostMode) -> HostExit {
    run_until(mode, None).await
}

/// How a host run ended. The singleton lock stays held until [`HostExit::finish`],
/// which the caller runs only after shutting the runtime down, so no task or
/// blocking call of this host can still act once another process takes it.
pub struct HostExit {
    lock: Option<LayoutLock>,
    result: Result<()>,
}

impl HostExit {
    pub fn finish(self) -> Result<()> {
        drop(self.lock);
        self.result
    }
}

pub async fn run_until(mode: HostMode, managed_stop: Option<watch::Receiver<bool>>) -> HostExit {
    match serve_until(mode, managed_stop).await {
        Ok(exit) => exit,
        Err(error) => HostExit {
            lock: None,
            result: Err(error),
        },
    }
}

async fn serve_until(
    mode: HostMode,
    managed_stop: Option<watch::Receiver<bool>>,
) -> Result<HostExit> {
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
    if mode == HostMode::Service {
        ensure!(
            LifecycleJournal::open(&layout)?
                .is_some_and(|journal| journal.phase() == Phase::Installed),
            "service installation is incomplete or disabled for uninstall; retry maintenance"
        );
    }
    let _logging = logging(&layout)?;
    let Dependencies {
        host,
        missing,
        sqlite,
    } = dependencies(mode, &layout).await?;
    let stopped = serve_with_deps(mode, guard, host, managed_stop, missing).await?;
    // The ledger's writer thread is joined before the lock can go: no
    // queued transition lands after another process owns the ledger.
    let closed = tokio::time::timeout(serving::LEDGER_CLOSE, async {
        Arc::try_unwrap(sqlite)
            .map_err(|_| anyhow::anyhow!("ledger still has active owners"))?
            .close()
            .await
            .map_err(anyhow::Error::from)
    })
    .await;
    match closed {
        Ok(Ok(())) => tracing::info!(
            stage = "shutdown.ledger_closed",
            "host shutdown: ledger closed"
        ),
        Ok(Err(error)) => tracing::error!(
            stage = "shutdown.ledger_closed",
            error = %error,
            "host shutdown: ledger not closed; open records stay as they are"
        ),
        Err(_) => tracing::error!(
            stage = "shutdown.ledger_closed",
            "host shutdown: ledger close timed out; open records stay as they are"
        ),
    }
    Ok(HostExit {
        lock: Some(stopped.lock),
        result: stopped.result,
    })
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
    let command = lock_install_command(&layout).await?;
    if let Some(journal) = LifecycleJournal::open(&layout)? {
        ensure!(
            journal.phase() == Phase::Installing,
            "service already installed or uninstall incomplete; run uninstall --status or retry uninstall first"
        );
    }
    let guard = LayoutLock::new(
        NativeHostFilesystem.lock(&layout)?,
        endpoint(mode, &layout)?,
        HostForm::Service,
    );
    if let Some(journal) = LifecycleJournal::open(&layout)? {
        ensure!(
            journal.phase() == Phase::Installing,
            "service already installed or uninstall incomplete; run uninstall first"
        );
        rollback_install(&layout, &guard, journal)?;
    }
    NativeServiceManager.preflight_install(&layout)?;
    let mut journal = LifecycleJournal::begin(&layout)?;
    let result: Result<()> = async {
        NativeServiceManager.prepare_install(&layout, &mut journal)?;
        journal.plan(Resource::Data)?;
        let source = etd_sysfx_os::service::current_exe()?;
        storage::install_bundled_cores(
            source.parent().context("missing installer directory")?,
            &layout.cores,
            mode,
        )
        .await?;
        let deps = dependencies(mode, &layout).await?;
        let seed: Result<()> = async {
            let entries = seed_entries(users)?;
            policy(mode, &entries)?;
            maintenance_change(deps.host.ledger.as_ref(), Change::SetAllowList(entries)).await?;
            Ok(())
        }
        .await;
        let closed = deps.close().await;
        seed?;
        closed?;
        journal.complete(Resource::Data)?;
        NativeServiceManager.register(&layout, &mut journal)?;
        journal.advance(Phase::Installed)?;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        if let Err(rollback) = rollback_install(&layout, &guard, journal) {
            bail!(
                "install failed: {error:#}; rollback incomplete: {rollback:#}; retry uninstall to resume cleanup"
            );
        }
        return Err(error.context("install rolled back"));
    }
    // Register under the stable lock; the newly launched service must acquire
    // it itself, so release only after the journal records Installed.
    drop(guard);
    let install_id = journal.install_id().to_owned();
    finish_install_handoff(command, start_and_verify(&layout, &install_id), || {
        uninstall_locked(&layout, Some(&install_id))
    })
    .await
}

async fn finish_install_handoff<F, Fut>(
    _command: MaintenanceLock,
    verify: impl std::future::Future<Output = Result<()>>,
    rollback: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if let Err(error) = verify.await {
        if let Err(rollback) = rollback().await {
            bail!(
                "service start failed: {error:#}; rollback incomplete: {rollback:#}; retry uninstall"
            );
        }
        return Err(error.context("install rolled back after start failure"));
    }
    Ok(())
}

async fn lock_install_command(layout: &HostLayout) -> Result<MaintenanceLock> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let guard = NativeHostFilesystem.lock_maintenance(layout)?;
        let pending = LifecycleJournal::open(layout)?.is_some_and(|journal| {
            journal.phase() == Phase::StateRemoved && matches!(journal.deferred(), Some(DeferredOutcome::Pending { pid }) if NativeServiceManager.deferred_worker_alive(*pid).unwrap_or(false))
        });
        if !pending || std::time::Instant::now() >= deadline {
            return Ok(guard);
        }
        // The worker requires this mutex to finish; do not wait while holding it.
        drop(guard);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

fn require_journal(layout: &HostLayout, install_id: &str) -> Result<LifecycleJournal> {
    let journal = LifecycleJournal::open(layout)?.context("maintenance journal disappeared")?;
    ensure!(
        journal.install_id() == install_id,
        "maintenance transaction changed"
    );
    Ok(journal)
}

async fn start_and_verify(layout: &HostLayout, install_id: &str) -> Result<()> {
    use etd_ipc::{Connector, ServerExpectation, platform::LocalConnector};
    ensure!(
        require_journal(layout, install_id)?.phase() == Phase::Installed,
        "service is not in the installed phase"
    );
    NativeServiceManager.start(layout)?;
    let connector = LocalConnector {
        expectation: ServerExpectation {
            exe_dir: layout
                .executable
                .parent()
                .context("missing installed image directory")?
                .to_owned(),
            user: None,
            privileged: true,
        },
    };
    let endpoint = endpoint(HostMode::Service, layout)?;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if connector.connect(&endpoint).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .context("registered service never published a verified endpoint")?;
    require_journal(layout, install_id)?;
    Ok(())
}

fn clean_ipc(layout: &HostLayout, guard: &LayoutLock) -> Result<()> {
    if NativeServiceManager.ipc_dir_exists(layout)? {
        // Reuse I1's stale-endpoint and staging-directory ownership/liveness
        // checks while holding the very same exclusive listener claim.
        drop(LocalListener::bind_replacing_stale(
            guard.listener_claim(),
            &ListenerPolicy::default(),
        )?);
        NativeServiceManager.remove_ipc_dir(layout)?;
    }
    Ok(())
}

fn rollback_install(
    layout: &HostLayout,
    guard: &LayoutLock,
    journal: LifecycleJournal,
) -> Result<()> {
    ensure!(
        require_journal(layout, journal.install_id())?.phase() == Phase::Installing,
        "cannot roll back a different or committed installation"
    );
    for resource in journal.rollback_resources() {
        match resource {
            Resource::Registration => NativeServiceManager.unregister(layout, true)?,
            Resource::SocketDir => clean_ipc(layout, guard)?,
            Resource::Group => NativeServiceManager.remove_group(layout, journal.group_gid())?,
            Resource::StateDir => NativeServiceManager.remove_state(layout)?,
            Resource::InstallDir => NativeServiceManager.remove_install(layout)?,
            _ => unreachable!("only top-level rollback resources"),
        }
    }
    journal.clear()?;
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
    let _command = if mode == HostMode::Service {
        Some(NativeHostFilesystem.lock_maintenance(&layout)?)
    } else {
        None
    };
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
    let _command = NativeHostFilesystem.lock_maintenance(&layout)?;
    uninstall_locked(&layout, None).await
}

/// Caller holds the maintenance-command mutex until this returns, including
/// if this is the rollback of install's start/verification handoff.
async fn uninstall_locked(layout: &HostLayout, expected_id: Option<&str>) -> Result<()> {
    let mode = HostMode::Service;
    let first = LifecycleJournal::open(layout)?;
    if let Some(id) = expected_id {
        ensure!(
            first
                .as_ref()
                .is_some_and(|journal| journal.install_id() == id),
            "rollback transaction changed"
        );
    }
    // The running service itself holds the machine lock. Stopping and
    // disabling it is the only step that must precede acquiring that lock.
    if let Some(journal) = &first
        && journal.phase() == Phase::Installed
    {
        require_journal(layout, journal.install_id())?;
        NativeServiceManager.stop_and_disable(layout)?;
    }
    let guard = LayoutLock::new(
        NativeHostFilesystem.lock(layout)?,
        endpoint(mode, layout)?,
        HostForm::Service,
    );
    let Some(mut journal) = LifecycleJournal::open(layout)? else {
        ensure!(first.is_none(), "maintenance journal disappeared");
        // A second uninstall is success only if there are no foreign or
        // unjournaled resources; never adopt a name merely because it exists.
        NativeServiceManager.preflight_install(layout)?;
        return Ok(());
    };
    ensure!(
        first
            .as_ref()
            .is_some_and(|first| first.install_id() == journal.install_id()),
        "maintenance transaction changed during stop"
    );
    if journal.phase() == Phase::Installing {
        return rollback_install(layout, &guard, journal);
    }
    journal.step(Phase::Disabled, || {
        NativeServiceManager.stop_and_disable(layout)
    })?;
    if journal.phase() < Phase::Reclaimed {
        let result: Result<()> = async {
            NativeHostFilesystem.validate_service(layout)?;
            ensure!(
                storage::ledger_exists(&layout.state)?,
                "ownership ledger missing; refusing unverified purge"
            );
            let deps = dependencies(mode, layout).await?;
            reclaim_locked(&deps.host, true).await?;
            deps.close().await?;
            Ok(())
        }
        .await;
        result.context("service is disabled and ownership data retained; retry etd-host uninstall, or etd-host resume-service to re-enable before completed reclaim")?;
        journal.advance(Phase::Reclaimed)?;
    }
    journal.step(Phase::Unregistered, || {
        NativeServiceManager.unregister(layout, false)
    })?;
    if journal.phase() < Phase::IpcRemoved {
        clean_ipc(layout, &guard)?;
        journal.advance(Phase::IpcRemoved)?;
    }
    let gid = journal.group_gid();
    journal.step(Phase::GroupRemoved, || {
        NativeServiceManager.remove_group(layout, gid)
    })?;
    journal.step(Phase::StateRemoved, || {
        NativeServiceManager.remove_state(layout)
    })?;
    if journal.phase() < Phase::InstallRemoved {
        let deferred = NativeServiceManager.defer_install_removal(layout, journal.install_id());
        let deferred = match deferred {
            Ok(value) => value,
            Err(error) => {
                journal.set_deferred(DeferredOutcome::Failed {
                    error: error.to_string(),
                })?;
                return Err(error.into());
            }
        };
        if let Some(pid) = deferred {
            journal.set_deferred(DeferredOutcome::Pending { pid })?;
            println!(
                "service and data removed; protected helper will finish after this process exits; check etd-host uninstall --status (uninstall is complete when the journal is gone)"
            );
            return Ok(());
        }
        if let Err(error) = NativeServiceManager.remove_install(layout) {
            journal.set_deferred(DeferredOutcome::Failed {
                error: error.to_string(),
            })?;
            return Err(anyhow::Error::from(error).context("uninstall incomplete"));
        }
        journal.advance(Phase::InstallRemoved)?;
    }
    journal.clear()?;
    Ok(())
}

#[cfg(windows)]
pub fn finish_deferred_uninstall(parent: u32, install_id: &str) -> Result<()> {
    ensure!(
        NativeServiceManager.entry_is_elevated()?,
        "administrator privileges required"
    );
    let waited = etd_sysfx_os::service::wait_uninstall_parent(parent);
    let layout = layout(HostMode::Service)?;
    let _command = NativeHostFilesystem.lock_maintenance(&layout)?;
    let Some(mut journal) = LifecycleJournal::open(&layout)? else {
        return Ok(()); // another maintenance process already completed it
    };
    ensure!(
        journal.can_finish_deferred(install_id),
        "deferred uninstall no longer matches its transaction and final phase"
    );
    let guard = waited.and_then(|_| NativeHostFilesystem.lock(&layout));
    let result = match &guard {
        Ok(_) => journal.step(Phase::InstallRemoved, || {
            NativeServiceManager.remove_install(&layout)
        }),
        Err(error) => Err(io::Error::other(error.to_string())),
    };
    if let Err(error) = result {
        journal.set_deferred(DeferredOutcome::Failed {
            error: error.to_string(),
        })?;
        return Err(error.into());
    }
    if let Err(error) = journal.clear() {
        // If the marker remains, keep the failure observable; if deletion
        // succeeded and only its directory sync failed, report that error.
        if LifecycleJournal::open(&layout)?.is_some() {
            journal.set_deferred(DeferredOutcome::Failed {
                error: error.to_string(),
            })?;
        }
        return Err(error.into());
    }
    Ok(())
}

pub async fn resume_service() -> Result<()> {
    ensure!(
        NativeServiceManager.entry_is_elevated()?,
        "administrator privileges required"
    );
    let layout = layout(HostMode::Service)?;
    let _command = NativeHostFilesystem.lock_maintenance(&layout)?;
    let guard = NativeHostFilesystem.lock(&layout)?;
    NativeHostFilesystem.validate_service(&layout)?;
    let mut journal = LifecycleJournal::open(&layout)?.context("no service installation")?;
    let install_id = journal.install_id().to_owned();
    journal.resume_service()?;
    drop(guard);
    start_and_verify(&layout, &install_id).await
}

pub fn uninstall_status() -> Result<()> {
    ensure!(
        NativeServiceManager.entry_is_elevated()?,
        "administrator privileges required"
    );
    let layout = layout(HostMode::Service)?;
    NativeHostFilesystem.prepare_maintenance(&layout)?;
    match LifecycleJournal::open(&layout)? {
        None => println!("No maintenance journal: uninstall complete (or never installed)"),
        Some(journal) => {
            println!("Uninstall not complete: phase {:?}", journal.phase());
            match journal.deferred() {
                Some(DeferredOutcome::Pending { pid }) => println!(
                    "Deferred helper {pid}: {}",
                    if NativeServiceManager.deferred_worker_alive(*pid)? {
                        "running"
                    } else {
                        "exited without completing; retry uninstall"
                    }
                ),
                Some(DeferredOutcome::Failed { error }) => {
                    println!("Deferred helper failed: {error}; retry uninstall")
                }
                None => (),
            }
        }
    }
    Ok(())
}

pub async fn remove_core(mode: HostMode, version: &str) -> Result<()> {
    let layout = layout(mode)?;
    let _command = if mode == HostMode::Service {
        Some(NativeHostFilesystem.lock_maintenance(&layout)?)
    } else {
        None
    };
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

#[cfg(test)]
mod maintenance_handoff_tests {
    use super::*;
    #[tokio::test]
    async fn failed_verification_rolls_back_before_waiting_maintenance_can_enter() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let guard = MaintenanceLock::acquire(dir.path()).unwrap();
        let lifetime = etd_sysfx_os::service::HostLock::acquire(dir.path()).unwrap();
        // The host can take its own lock independently during the handoff.
        drop(lifetime);
        let cleaned = Arc::new(AtomicBool::new(false));
        let witness = cleaned.clone();
        let path = dir.path().to_owned();
        let (started_tx, started_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _command = MaintenanceLock::acquire(&path).unwrap();
            entered_tx.send(witness.load(Ordering::SeqCst)).unwrap();
        });
        started_rx.recv().unwrap();
        let result = finish_install_handoff(
            guard,
            async {
                assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());
                bail!("injected verification failure")
            },
            || async {
                assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());
                cleaned.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert!(entered_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        waiter.join().unwrap();
    }
}
