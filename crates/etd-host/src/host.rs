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
    BootId, Candidate, CandidateSource, Change, ChangeSet, Effect, EffectId, EffectKind,
    EffectScope, EffectState, GenerationOutcome, Ledger, ObjectKey, Observation, ReclaimDeps,
    ReclaimEngine, ReclaimReport, ReclaimScope, RepairIndexStore, RequestDigest, RequestRecord,
    ScopeFilter, SystemObserver, engine::ReclaimEngineImpl, sqlite::SqliteLedger,
};
use etd_sysfx_os::{
    OsConfig, OsError,
    service::{
        DeferredOutcome, HostFilesystem, HostLayout, LifecycleJournal, MaintenanceLock,
        NativeHostFilesystem, NativeServiceManager, Phase, Resource, ServiceManager, UpgradeStage,
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
pub(crate) use serving::{LayoutLock, serve_with_deps_and};
#[path = "session.rs"]
mod session;
#[path = "upgrade.rs"]
pub(crate) mod upgrade;
// Used by main.rs; tests that include this file do not.
#[cfg_attr(test, allow(unused_imports))]
pub(crate) use session::SessionRefusal;
/// See [`serving::RUNTIME_SHUTDOWN`].
pub(crate) const RUNTIME_SHUTDOWN: std::time::Duration = serving::RUNTIME_SHUTDOWN;
/// See [`serving::stop_worst_case`].
#[cfg(windows)]
pub(crate) fn stop_worst_case() -> std::time::Duration {
    serving::stop_worst_case()
}
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
        // Only an elevated administrator's token gets a layout: the
        // directories come from ProgramData and the token's own SID.
        HostMode::ElevatedSession => {
            #[cfg(windows)]
            {
                let token = etd_sysfx_os::service::elevated_session_token()?;
                Ok(NativeHostFilesystem.session_layout(&token.sid)?)
            }
            #[cfg(unix)]
            bail!("the elevated session host is Windows-only")
        }
        HostMode::Unspecified => bail!("unsupported host mode"),
    }
}

/// How a host form owns its listener.
fn host_form(mode: HostMode) -> Result<HostForm> {
    Ok(match mode {
        HostMode::Service => HostForm::Service,
        HostMode::User => HostForm::User,
        HostMode::ElevatedSession => HostForm::ElevatedSession,
        HostMode::Unspecified => bail!("unsupported host mode"),
    })
}

fn endpoint(mode: HostMode, layout: &HostLayout) -> Result<Endpoint> {
    #[cfg(windows)]
    {
        let _ = layout;
        let user_sid = || match platform::current_user()? {
            OsUserId::WindowsSid(sid) => Ok(sid),
            _ => bail!("Windows user SID unavailable"),
        };
        match mode {
            HostMode::Service => Ok(Endpoint::NamedPipe(etd_ipc::SERVICE_PIPE_NAME.into())),
            HostMode::User => Ok(Endpoint::NamedPipe(format!(
                r"\\.\pipe\easytier-desk-user-{}",
                user_sid()?
            ))),
            HostMode::ElevatedSession => {
                Ok(Endpoint::NamedPipe(session::endpoint_name(&user_sid()?)))
            }
            HostMode::Unspecified => bail!("unsupported host mode"),
        }
    }
    #[cfg(unix)]
    {
        ensure!(
            matches!(mode, HostMode::Service | HostMode::User),
            "unsupported host mode on this platform"
        );
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
        // Prepared under its locks by `session::acquire` / `reclaim_own`.
        HostMode::ElevatedSession => {
            bail!("the elevated session host is prepared under its locks")
        }
        HostMode::Unspecified => bail!("unsupported host mode"),
    }
    Ok(())
}

/// The kernel's profile variables under the elevated session host: the
/// protected, empty `<SID>\profile`, never the user's own profile.
fn profile_env(profile: &std::path::Path) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut env: Vec<(std::ffi::OsString, std::ffi::OsString)> =
        ["USERPROFILE", "APPDATA", "LOCALAPPDATA"]
            .into_iter()
            .map(|name| (name.into(), profile.as_os_str().to_owned()))
            .collect();
    let mut components = profile.components();
    if let Some(std::path::Component::Prefix(drive)) = components.next() {
        env.push(("HOMEDRIVE".into(), drive.as_os_str().to_owned()));
        env.push((
            "HOMEPATH".into(),
            components.as_path().as_os_str().to_owned(),
        ));
    }
    env
}

/// The account a host form serves and, for the elevated session, its
/// Windows session (peers must share it).
fn host_owner(mode: HostMode) -> Result<(Option<OsUserId>, Option<u32>)> {
    serving::host_owner(mode).map_err(Into::into)
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
    let mut engine = ProcessKitEngine::with_console_helper(layout.executable.clone());
    if let Some(profile) = &layout.profile {
        engine = engine.with_env(profile_env(profile));
    }
    let process: Arc<dyn ProcessEngine> = Arc::new(engine);
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
    // Privileged hosts may load drivers from a kernel directory.
    let privileged = match mode {
        HostMode::Service | HostMode::ElevatedSession => true,
        HostMode::User | HostMode::Unspecified => false,
    };
    let store = Arc::new(if privileged {
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
    let (owner, session) = host_owner(mode)?;
    let authorizer = Arc::new(AllowListAuthorizer::new(mode, owner).with_session(session));
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
        fence: if privileged { os.fence } else { None },
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
    /// Every task, helper process and the ledger's writer confirmed ended.
    quiescent: bool,
    _logging: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl HostExit {
    /// `runtime_settled`: the runtime shut down before its timeout, so no
    /// blocking task of this host still runs. Unless both that and the
    /// host's own wind-down are confirmed, the lock is not released here:
    /// only the process's exit releases it, so nothing of this host can
    /// act once another process owns the ledger.
    pub fn finish(self, runtime_settled: bool) -> Result<()> {
        let quiescent = self.quiescent && runtime_settled;
        if let Some(lock) = self.lock {
            if !quiescent {
                tracing::error!(
                    stage = "shutdown.lock_kept",
                    host_quiescent = self.quiescent,
                    runtime_settled,
                    "host shutdown: not confirmed quiescent; the singleton lock is released only when the process exits"
                );
            }
            release(lock, quiescent);
        }
        self.result
    }
}

/// Release `lock` now if `quiescent`; otherwise keep it until the process
/// exits (the OS releases it then).
fn release<L>(lock: L, quiescent: bool) {
    if quiescent {
        drop(lock);
    } else {
        std::mem::forget(lock);
    }
}

pub async fn run_until(mode: HostMode, managed_stop: Option<watch::Receiver<bool>>) -> HostExit {
    match serve_until(mode, managed_stop).await {
        Ok(exit) => exit,
        Err(error) => HostExit {
            lock: None,
            result: Err(error),
            quiescent: true,
            _logging: None,
        },
    }
}

async fn serve_until(
    mode: HostMode,
    managed_stop: Option<watch::Receiver<bool>>,
) -> Result<HostExit> {
    let layout = layout(mode)?;
    let guard = if mode == HostMode::ElevatedSession {
        session::acquire(&layout).await?
    } else {
        lock_service_or_user(mode, &layout)?
    };
    let mut on_serving: Option<Box<dyn FnOnce() + Send>> = None;
    if mode == HostMode::Service {
        let journal = LifecycleJournal::open(&layout)?
            .filter(|journal| journal.phase() == Phase::Installed)
            .context(
                "service installation is incomplete or disabled for uninstall; retry maintenance",
            )?;
        match journal.upgrade_stage() {
            // `Disabling` changed nothing yet: this is still the old host.
            None | Some(UpgradeStage::Disabling) => {}
            Some(UpgradeStage::Replacing | UpgradeStage::RollingBack) => bail!(
                "an upgrade of this service is incomplete; run etd-host upgrade from the new payload again, or etd-host uninstall"
            ),
            Some(UpgradeStage::Starting) => {
                ensure!(
                    !etd_sysfx_os::service::ci_upgrade_fault(&layout, "new-host-unready"),
                    "CI fault: the new host does not become ready"
                );
                // This is the new host: serving commits the upgrade.
                let layout = layout.clone();
                let install_id = journal.install_id().to_owned();
                on_serving = Some(Box::new(move || {
                    upgrade::commit_by_new_host(&layout, &install_id)
                }));
            }
        }
    }
    serve_locked(mode, layout, guard, managed_stop, on_serving).await
}

/// The service and user forms: prepare, then the host lock.
fn lock_service_or_user(mode: HostMode, layout: &HostLayout) -> Result<LayoutLock> {
    prepare(mode, layout)?;
    if mode == HostMode::Service {
        ensure!(
            NativeHostFilesystem.is_installed_image(layout)?,
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
    Ok(LayoutLock::new(
        NativeHostFilesystem.lock(layout)?,
        endpoint(mode, layout)?,
        host_form(mode)?,
    ))
}

/// Serve holding `guard` until stopped, then close the ledger.
async fn serve_locked(
    mode: HostMode,
    layout: HostLayout,
    guard: LayoutLock,
    managed_stop: Option<watch::Receiver<bool>>,
    on_serving: Option<Box<dyn FnOnce() + Send>>,
) -> Result<HostExit> {
    let logging = logging(&layout)?;
    let Dependencies {
        host,
        missing,
        sqlite,
    } = dependencies(mode, &layout).await?;
    let stopped = serve_with_deps_and(mode, guard, host, managed_stop, missing, on_serving).await?;
    // The ledger's writer thread is joined before the lock can go: no
    // queued transition lands after another process owns the ledger.
    let closed = tokio::time::timeout(serving::LEDGER_CLOSE, async {
        sole_owner(sqlite)
            .await
            .close()
            .await
            .map_err(anyhow::Error::from)
    })
    .await;
    let ledger_closed = match closed {
        Ok(Ok(())) => {
            tracing::info!(
                stage = "shutdown.ledger_closed",
                "host shutdown: ledger closed"
            );
            true
        }
        Ok(Err(error)) => {
            tracing::error!(
                stage = "shutdown.ledger_closed",
                error = %error,
                "host shutdown: ledger not closed; open records stay as they are"
            );
            false
        }
        Err(_) => {
            tracing::error!(
                stage = "shutdown.ledger_closed",
                "host shutdown: ledger still shared or its close timed out; open records stay as they are"
            );
            false
        }
    };
    Ok(HostExit {
        lock: Some(stopped.lock),
        result: stopped.result,
        quiescent: stopped.quiescent && ledger_closed,
        _logging: Some(logging),
    })
}

/// Wait until `shared` has no other owner. A mutation that was committing
/// when its client went away runs on in a detached task holding the
/// service, so the ledger; it ends once the orchestrator is gone. The
/// caller bounds the wait.
async fn sole_owner<T>(mut shared: Arc<T>) -> T {
    loop {
        match Arc::try_unwrap(shared) {
            Ok(owned) => return owned,
            Err(still) => shared = still,
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
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
    // Under the maintenance and host locks no elevated session runs:
    // reclaim and purge every session root first (doc#13), refusing with
    // the report if anything is left.
    session::drain(true)
        .await
        .context("leftover elevated sessions could not be reclaimed; install refused")?;
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
    use etd_ipc::{Connector, ServerExpectation, ServerRequirement, platform::LocalConnector};
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
            requirement: ServerRequirement::Service,
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
    reclaim_with(
        deps.ledger.as_ref(),
        deps.reclaim.as_ref(),
        deps.observer.as_ref(),
        purge,
    )
    .await
}

/// [`reclaim_locked`] over its three dependencies (testable with fakes).
async fn reclaim_with(
    ledger: &dyn Ledger,
    reclaim: &dyn ReclaimEngine,
    observer: &dyn SystemObserver,
    purge: bool,
) -> Result<()> {
    let scope = if purge {
        ReclaimScope::Everything
    } else {
        ReclaimScope::Instances
    };
    let receipt = if purge {
        Some(maintenance_change(ledger, Change::PurgeAll).await?)
    } else {
        None
    };
    let report = reclaim.reclaim_all(scope).await?;
    print_report(&report);
    let filter = if purge {
        ScopeFilter::all()
    } else {
        ScopeFilter::default()
    };
    let open = ledger.open_effects(&filter).await?;
    let left = reclaim_outcome(&report, &open, purge)?;
    for item in &left {
        let line = left_in_place(item, observer).await;
        println!("  {line}");
    }
    // Their records close: the drivers stay, never ours to delete. A
    // swept driver has no record (nothing to close; found again next time
    // and again left in place).
    let decisions: Vec<_> = left
        .iter()
        .filter_map(|item| item.record.clone())
        .map(|id| etd_contract::CandidateDecision {
            candidate_id: id,
            action: etd_contract::v1::CandidateAction::Keep as i32,
        })
        .collect();
    if !decisions.is_empty() {
        reclaim.resolve(&decisions).await?;
    }
    ensure!(
        ledger.open_effects(&filter).await?.is_empty(),
        "reclaim incomplete; keeping ownership data for retry"
    );
    if let Some(receipt) = receipt {
        ledger.complete_ticket(&receipt.ticket).await?;
    }
    ledger.compact().await?;
    Ok(())
}

/// A driver service every kernel shares (wintun, WinDivert; product scope).
/// The host never deletes one; a purge can only list it.
fn shared_driver(kind: EffectKind, scope: Option<&EffectScope>) -> bool {
    kind == EffectKind::Driver && scope == Some(&EffectScope::Product)
}

/// The image path in a driver observation (the Windows observer's detail,
/// read from SCM).
fn image_path(observation: Option<&Observation>) -> Option<String> {
    observation
        .and_then(|o| o.detail.as_deref())
        .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
        .and_then(|v| v["image_path"].as_str().map(str::to_owned))
}

/// A shared driver service a purge leaves in place: a candidate (ours to
/// list, never to delete), or a conflict (it already existed or belongs to
/// other software).
#[derive(Debug, Clone, PartialEq)]
struct LeftInPlace {
    /// Candidate or conflict id of its record, for closing it (KEEP);
    /// `None` for a driver the sweep found without a record.
    record: Option<String>,
    key: ObjectKey,
    observation: Option<Observation>,
    preexisting: bool,
}

/// What to tell about a shared driver left in place. The image path comes
/// from what was recorded, else from asking the observer now (SCM
/// `QueryServiceConfig`), so a record read back without one still names
/// its file (topic#40 msg#1390).
async fn left_in_place(item: &LeftInPlace, observer: &dyn SystemObserver) -> String {
    let (key, observation) = (&item.key, item.observation.as_ref());
    let name = match key {
        ObjectKey::Service { name } => name.clone(),
        other => format!("{other:?}"),
    };
    // Informational only, a point-in-time observation: never authority
    // to delete anything (topic#40 msg#1450). The notice waits at most
    // IMAGE_LOOKUP_DEADLINE; an SCM read stuck in spawn_blocking keeps
    // running after that, and main's run_bounded shuts the runtime down
    // within RUNTIME_SHUTDOWN regardless, so it cannot hold process exit.
    let image = match image_path(observation) {
        Some(image) => format!("{image} (as recorded)"),
        None => match tokio::time::timeout(
            IMAGE_LOOKUP_DEADLINE,
            observer.observe(EffectKind::Driver, key),
        )
        .await
        {
            Ok(Ok(Some(now))) => image_path(Some(&now)).map_or_else(
                || "unknown (not reported by the system)".into(),
                |image| format!("{image} (from SCM, now)"),
            ),
            Ok(Ok(None)) => "unknown (the service is no longer registered)".into(),
            Ok(Err(e)) => format!("unknown (query failed: {e})"),
            Err(_) => "unknown (query timed out)".into(),
        },
    };
    if item.preexisting {
        format!(
            "left in place: pre-existing shared driver service {name} image {image}; it belongs to other software"
        )
    } else {
        format!(
            "left in place: shared driver service {name} image {image}; remove it yourself if no other software uses it"
        )
    }
}

/// How long the uninstall notice waits for a driver's image path (the
/// notice only: see the TODO in `left_in_place`).
const IMAGE_LOOKUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether a reclaim is complete, and which shared driver services it
/// leaves in place. A purge (uninstall) does not wait on shared driver
/// services (Product scope): we never delete one, so a candidate (ruling
/// topic#40 msg#1279) and a conflict, a driver that already existed or
/// belongs to other software (msg#1453), are listed and their records
/// closed. Any other candidate, any other conflict, any other open record,
/// an unclosed generation or a failed sweep still blocks, so ownership data
/// stays for a retry.
fn reclaim_outcome(
    report: &ReclaimReport,
    open: &[Effect],
    purge: bool,
) -> Result<Vec<LeftInPlace>> {
    let record = |id: &EffectId| open.iter().find(|e| &e.id == id);
    let (shared, candidates): (Vec<_>, Vec<_>) = report.candidates.iter().partition(|c| {
        purge && (shared_driver(c.kind, c.scope.as_ref()) || swept_shared_driver(c))
    });
    let (preexisting, conflicts): (Vec<_>, Vec<_>) = report.conflicts.iter().partition(|c| {
        purge
            && record(&c.effect).is_some_and(|e| {
                e.state == EffectState::Conflict && shared_driver(e.kind, Some(&e.scope))
            })
    });
    let open_blocking = open.iter().any(|e| {
        !(purge
            && matches!(e.state, EffectState::Candidate | EffectState::Conflict)
            && shared_driver(e.kind, Some(&e.scope)))
    });
    ensure!(
        !open_blocking
            && candidates.is_empty()
            && conflicts.is_empty()
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
    let mut left: Vec<LeftInPlace> = preexisting
        .iter()
        .map(|c| LeftInPlace {
            record: Some(c.id.clone()),
            key: c.key.clone(),
            observation: record(&c.effect).and_then(|e| e.observation.clone()),
            preexisting: true,
        })
        .collect();
    for c in shared {
        let item = LeftInPlace {
            record: matches!(c.source, CandidateSource::PlannedRecord { .. }).then(|| c.id.clone()),
            key: c.key.clone(),
            observation: c.observation.clone(),
            preexisting: false,
        };
        // A swept driver that a record already names is told once (service
        // names are case-insensitive).
        let named = |k: &ObjectKey| service_name(k).map(str::to_ascii_lowercase);
        if item.record.is_none() && left.iter().any(|l| named(&l.key) == named(&item.key)) {
            continue;
        }
        left.push(item);
    }
    Ok(left)
}

fn service_name(key: &ObjectKey) -> Option<&str> {
    match key {
        ObjectKey::Service { name } => Some(name),
        _ => None,
    }
}

/// A shared driver service (wintun, WinDivert) the sweep found without an
/// open record: after its record was closed (KEEP), or under a name whose
/// case differs from the record's. The sweep reports them for exactly this
/// list of names (`etd-sysfx-os` Windows sweeper) and never deletes them.
fn swept_shared_driver(c: &Candidate) -> bool {
    c.kind == EffectKind::Driver
        && c.scope.is_none()
        && matches!(c.source, CandidateSource::Swept(_))
        && service_name(&c.key).is_some_and(|name| {
            ["wintun", "WinDivert"]
                .iter()
                .any(|shared| shared.eq_ignore_ascii_case(name))
        })
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

pub async fn reclaim(mode: HostMode, _all: bool, purge: bool, all_users: bool) -> Result<()> {
    ensure!(
        !all_users || mode == HostMode::ElevatedSession,
        "--all-users applies only to --mode elevated-session"
    );
    let layout = layout(mode)?;
    match mode {
        HostMode::ElevatedSession if all_users => {
            return session::reclaim_all_users(&layout, purge).await;
        }
        HostMode::ElevatedSession => return session::reclaim_own(&layout, purge).await,
        HostMode::Service | HostMode::User | HostMode::Unspecified => (),
    }
    let _command = service_maintenance(mode, &layout)?;
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
/// How long the uninstaller waits for the host lock after the service
/// reported STOPPED.
const STOPPED_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Take the host lock right after the service reported STOPPED. A host that
/// could not confirm its wind-down keeps the lock until its process exits,
/// which comes just after STOPPED: a held lock then means the service is
/// still exiting. Wait up to `wait` for it, then fail with a retryable
/// message.
async fn lock_after_stop<T>(
    wait: std::time::Duration,
    mut lock: impl FnMut() -> std::io::Result<T>,
) -> Result<T> {
    let until = tokio::time::Instant::now() + wait;
    loop {
        match lock() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if tokio::time::Instant::now() >= until {
                    bail!(
                        "the service reported STOPPED but its process is still exiting and holds the host lock; retry in a moment"
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            other => return Ok(other?),
        }
    }
}

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
    let lock = if let Some(journal) = &first
        && journal.phase() == Phase::Installed
    {
        require_journal(layout, journal.install_id())?;
        NativeServiceManager.stop_and_disable(layout)?;
        lock_after_stop(STOPPED_LOCK_WAIT, || NativeHostFilesystem.lock(layout)).await?
    } else {
        NativeHostFilesystem.lock(layout)?
    };
    let guard = LayoutLock::new(lock, endpoint(mode, layout)?, HostForm::Service);
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
    if journal.upgrade_stage().is_some() {
        upgrade::roll_back_for_uninstall(layout, &mut journal)
            .context("cannot restore an interrupted upgrade before uninstall")?;
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
        // The service host's volatile boot marker (Windows HKLM; gone at
        // the next boot anyway). Idempotent: a retry repeats it.
        etd_sysfx_os::remove_service_boot_marker()
            .map_err(anyhow::Error::from)
            .context(
                "uninstall incomplete: cannot remove the service boot marker \
                 HKLM\\SOFTWARE\\EasyTierDesk\\Volatile; retry etd-host uninstall",
            )?;
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
    upgrade::ensure_no_upgrade(&journal)?;
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

/// The maintenance lock for a service-mode `reclaim` / `remove-core`,
/// refused while an upgrade is uncommitted.
fn service_maintenance(mode: HostMode, layout: &HostLayout) -> Result<Option<MaintenanceLock>> {
    if mode != HostMode::Service {
        return Ok(None);
    }
    let command = NativeHostFilesystem.lock_maintenance(layout)?;
    if let Some(journal) = LifecycleJournal::open(layout)? {
        upgrade::ensure_no_upgrade(&journal)?;
    }
    Ok(Some(command))
}

pub async fn remove_core(mode: HostMode, version: &str) -> Result<()> {
    ensure!(
        mode != HostMode::ElevatedSession,
        "remove-core is not available for the elevated session host"
    );
    let layout = layout(mode)?;
    let _command = service_maintenance(mode, &layout)?;
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

#[cfg(test)]
mod reclaim_outcome_tests {
    use super::*;
    use etd_sysfx::{
        Candidate, CandidateSource, Conflict, EffectId, InterfaceInfo, ListenerInfo, ObserveError,
        Persistence, SystemClass, SystemEntry, Undo,
    };

    fn driver(name: &str) -> ObjectKey {
        ObjectKey::Service { name: name.into() }
    }

    fn found(image: &str) -> Observation {
        Observation {
            credential: None,
            key: None,
            observed_at: "1970-01-01T00:00:00Z".parse().unwrap(),
            detail: Some(serde_json::json!({ "image_path": image }).to_string()),
        }
    }

    fn candidate(id: &str, kind: EffectKind, key: ObjectKey, scope: EffectScope) -> Candidate {
        Candidate {
            id: id.into(),
            kind,
            key,
            scope: Some(scope),
            observation: Some(found(r"\SystemRoot\System32\drivers\wintun.sys")),
            source: CandidateSource::PlannedRecord {
                effect: EffectId(id.into()),
            },
        }
    }

    fn record(id: &str, kind: EffectKind, key: ObjectKey, scope: EffectScope) -> Effect {
        Effect {
            id: EffectId(id.into()),
            scope,
            kind,
            key,
            undo: Undo::EnsureAbsent,
            persistence: Persistence::Persistent,
            state: EffectState::Candidate,
            boot: BootId("boot".into()),
            observation: Some(found(r"\SystemRoot\System32\drivers\wintun.sys")),
            failures: 0,
            last_error: None,
            recorded_at: "1970-01-01T00:00:00Z".parse().unwrap(),
        }
    }

    fn report(candidates: Vec<Candidate>) -> ReclaimReport {
        ReclaimReport {
            generated_at: "1970-01-01T00:00:00Z".parse().unwrap(),
            generations: Vec::new(),
            candidates,
            conflicts: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn an_uninstall_with_only_a_shared_driver_candidate_completes() {
        let wintun = driver("wintun");
        let report = report(vec![candidate(
            "1",
            EffectKind::Driver,
            wintun.clone(),
            EffectScope::Product,
        )]);
        let open = [record(
            "1",
            EffectKind::Driver,
            wintun,
            EffectScope::Product,
        )];
        let left = reclaim_outcome(&report, &open, true).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].key, driver("wintun"));
        assert_eq!(left[0].record.as_deref(), Some("1"));
        assert!(!left[0].preexisting);
    }

    /// An observer that only answers driver lookups, as told (`None`:
    /// never answers).
    struct Drivers(Option<Result<Option<Observation>, ObserveError>>);

    #[async_trait::async_trait]
    impl SystemObserver for Drivers {
        async fn observe(
            &self,
            kind: EffectKind,
            _key: &ObjectKey,
        ) -> Result<Option<Observation>, ObserveError> {
            assert_eq!(kind, EffectKind::Driver);
            match &self.0 {
                Some(answer) => answer.clone(),
                None => std::future::pending().await,
            }
        }
        async fn interface(&self, _: &ObjectKey) -> Result<Option<InterfaceInfo>, ObserveError> {
            unreachable!()
        }
        async fn listener(
            &self,
            _: std::net::SocketAddr,
        ) -> Result<Option<ListenerInfo>, ObserveError> {
            unreachable!()
        }
        async fn interfaces_owned_by(&self, _: u32) -> Result<Vec<InterfaceInfo>, ObserveError> {
            unreachable!()
        }
        async fn enumerate(&self, _: SystemClass) -> Result<Vec<SystemEntry>, ObserveError> {
            unreachable!()
        }
    }

    fn item(observation: Option<Observation>, preexisting: bool) -> LeftInPlace {
        LeftInPlace {
            record: Some("1".into()),
            key: driver("wintun"),
            observation,
            preexisting,
        }
    }

    const IMAGE: &str = r"\SystemRoot\System32\drivers\wintun.sys";

    #[tokio::test]
    async fn the_image_comes_from_the_record_or_else_from_the_system_now() {
        let line = |image: &str| {
            format!(
                "left in place: shared driver service wintun image {image}; remove it yourself if no other software uses it"
            )
        };
        // Recorded.
        let unused = Drivers(Some(Err(ObserveError::Os {
            code: 1,
            message: "not asked".into(),
        })));
        assert_eq!(
            left_in_place(&item(Some(found(IMAGE)), false), &unused).await,
            line(&format!("{IMAGE} (as recorded)"))
        );
        // Read back without one: asked now.
        let bare = Observation {
            detail: None,
            ..found(IMAGE)
        };
        let now = line(&format!("{IMAGE} (from SCM, now)"));
        assert_eq!(
            left_in_place(
                &item(Some(bare.clone()), false),
                &Drivers(Some(Ok(Some(found(IMAGE)))))
            )
            .await,
            now
        );
        assert_eq!(
            left_in_place(&item(None, false), &Drivers(Some(Ok(Some(found(IMAGE)))))).await,
            now
        );
        // The query fails: said so, with the reason.
        let failed = Drivers(Some(Err(ObserveError::Os {
            code: 5,
            message: "access denied".into(),
        })));
        let text = left_in_place(&item(Some(bare.clone()), false), &failed).await;
        assert!(text.contains("image unknown (query failed: "), "{text}");
        assert!(text.contains("access denied"), "{text}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_never_answers_times_out() {
        let bare = Observation {
            detail: None,
            ..found(IMAGE)
        };
        let text = left_in_place(&item(Some(bare), false), &Drivers(None)).await;
        assert!(text.contains("image unknown (query timed out)"), "{text}");
    }

    #[tokio::test]
    async fn a_pre_existing_shared_driver_conflict_does_not_block_and_is_named_as_foreign() {
        let wintun = driver("wintun");
        let mut held = record(
            "7",
            EffectKind::Driver,
            wintun.clone(),
            EffectScope::Product,
        );
        held.state = EffectState::Conflict;
        let mut report = report(Vec::new());
        report.conflicts.push(Conflict {
            id: "c7".into(),
            effect: EffectId("7".into()),
            kind: EffectKind::Driver,
            key: wintun.clone(),
            expected: None,
            found: None,
        });
        let left = reclaim_outcome(&report, std::slice::from_ref(&held), true).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(
            left[0].record.as_deref(),
            Some("c7"),
            "closed through its conflict id"
        );
        assert!(left[0].preexisting);
        let unused = Drivers(Some(Err(ObserveError::Os {
            code: 1,
            message: "not asked".into(),
        })));
        assert_eq!(
            left_in_place(&left[0], &unused).await,
            format!(
                "left in place: pre-existing shared driver service wintun image {IMAGE} (as recorded); it belongs to other software"
            )
        );
        // Outside a purge it still blocks.
        assert!(reclaim_outcome(&report, &[held], false).is_err());
    }

    #[test]
    fn any_other_candidate_conflict_or_open_record_still_blocks() {
        let wintun = driver("wintun");
        let shared = candidate(
            "1",
            EffectKind::Driver,
            wintun.clone(),
            EffectScope::Product,
        );
        let shared_open = record(
            "1",
            EffectKind::Driver,
            wintun.clone(),
            EffectScope::Product,
        );

        // Another kind of candidate.
        let rule = ObjectKey::Rule {
            name: "EasyTier x (Inbound)".into(),
            group: Some("EasyTier".into()),
        };
        let core = EffectScope::CoreBinary {
            sha256: "00".into(),
        };
        let other = candidate(
            "2",
            EffectKind::WinProgramFirewallRule,
            rule.clone(),
            core.clone(),
        );
        let other_open = record("2", EffectKind::WinProgramFirewallRule, rule, core);
        assert!(
            reclaim_outcome(
                &report(vec![shared.clone(), other]),
                &[shared_open.clone(), other_open.clone()],
                true
            )
            .is_err()
        );

        // A driver record in an instance's scope is not a shared driver.
        let instance = EffectScope::Instance {
            instance: etd_contract::InstanceId::from("a"),
            epoch: etd_sysfx::Epoch(1),
        };
        let scoped = candidate("3", EffectKind::Driver, wintun.clone(), instance.clone());
        assert!(
            reclaim_outcome(
                &report(vec![scoped]),
                &[record("3", EffectKind::Driver, wintun.clone(), instance)],
                true
            )
            .is_err()
        );

        // A conflict (e.g. a driver registered before we started).
        let mut with_conflict = report(vec![shared.clone()]);
        with_conflict.conflicts.push(Conflict {
            id: "c".into(),
            effect: EffectId("4".into()),
            kind: EffectKind::Driver,
            key: wintun.clone(),
            expected: None,
            found: None,
        });
        assert!(reclaim_outcome(&with_conflict, std::slice::from_ref(&shared_open), true).is_err());

        // An open record that is not a shared-driver candidate.
        let mut applied = shared_open.clone();
        applied.state = EffectState::Applied;
        assert!(reclaim_outcome(&report(vec![shared.clone()]), &[applied], true).is_err());

        // Outside a purge, even a shared driver candidate blocks.
        assert!(reclaim_outcome(&report(vec![shared]), &[shared_open], false).is_err());
    }

    #[test]
    fn a_swept_shared_driver_is_left_in_place_once_and_never_kept() {
        let swept = |name: &str| Candidate {
            id: format!("swept-{name}"),
            kind: EffectKind::Driver,
            key: driver(name),
            scope: None,
            observation: None,
            source: CandidateSource::Swept(etd_sysfx::FoundBy::PrefixOnly),
        };
        // Its record was closed earlier (KEEP): nothing to close now.
        let left = reclaim_outcome(&report(vec![swept("wintun")]), &[], true).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].record, None);
        // A record names it already (another case): told once.
        let mut held = record(
            "7",
            EffectKind::Driver,
            driver("WinDivert"),
            EffectScope::Product,
        );
        held.state = EffectState::Conflict;
        let mut both = report(vec![swept("windivert")]);
        both.conflicts.push(Conflict {
            id: "c7".into(),
            effect: EffectId("7".into()),
            kind: EffectKind::Driver,
            key: driver("WinDivert"),
            expected: None,
            found: None,
        });
        let left = reclaim_outcome(&both, std::slice::from_ref(&held), true).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].record.as_deref(), Some("c7"));
        // Only the shared names, only in a purge.
        assert!(reclaim_outcome(&report(vec![swept("tap0901")]), &[], true).is_err());
        assert!(reclaim_outcome(&report(vec![swept("wintun")]), &[], false).is_err());
    }
}

/// The purge/uninstall path end to end over the real engine and a fake
/// machine (topic#40 msg#1503, msg#1506, msg#1507): shared driver services
/// are left in place, their records closed, and a repeated purge or an
/// uninstall after a purge succeeds too.
#[cfg(test)]
mod purge_flow_tests {
    use super::*;
    use etd_contract::InstanceId;
    use etd_sysfx::{
        EffectIntent, FoundBy, FoundObject, InstallKey, LedgerError, Persistence, Probe,
        ReclaimError, Reclaimed, Reclaimer, RepairIndex, Sweeper, Undo,
    };
    use etd_testkit::fakes::{ledger::MemoryLedger, system::FakeSystem};
    use futures_util::future::BoxFuture;
    use std::sync::Mutex;

    /// The Windows sweeper's view of shared drivers: every wintun/WinDivert
    /// service, without a credential, besides what the fake marks.
    struct Sweep(FakeSystem);
    impl Sweeper for Sweep {
        fn find_marked<'a>(
            &'a self,
            key: Option<&'a InstallKey>,
            known: &'a [InstanceId],
        ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
            Box::pin(async move {
                let mut found = self.0.find_marked(key, known).await?;
                for o in self.0.objects() {
                    if o.kind == EffectKind::Driver
                        && service_name(&o.key).is_some_and(|n| {
                            ["wintun", "WinDivert"]
                                .iter()
                                .any(|s| s.eq_ignore_ascii_case(n))
                        })
                    {
                        found.push(FoundObject {
                            kind: o.kind,
                            key: o.key.clone(),
                            observation: Observation {
                                credential: None,
                                key: Some(o.key.clone()),
                                observed_at: self.0.now(),
                                detail: None,
                            },
                            origin: FoundBy::PrefixOnly,
                        });
                    }
                }
                Ok(found)
            })
        }
    }

    /// Like the Windows driver reclaimer: probes, never deletes.
    struct NoDelete(Arc<dyn Reclaimer>);
    #[async_trait::async_trait]
    impl Reclaimer for NoDelete {
        fn kind(&self) -> EffectKind {
            self.0.kind()
        }
        fn rank(&self) -> u8 {
            self.0.rank()
        }
        async fn probe(&self, e: &Effect) -> Probe {
            self.0.probe(e).await
        }
        async fn reclaim(&self, _: &Effect) -> Result<Reclaimed, ReclaimError> {
            Err(ReclaimError::Unsupported(EffectKind::Driver))
        }
    }

    #[derive(Default)]
    struct Index(Mutex<Option<RepairIndex>>);
    impl RepairIndexStore for Index {
        fn load(&self) -> Result<Option<RepairIndex>, LedgerError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn store(&self, index: &RepairIndex) -> Result<(), LedgerError> {
            *self.0.lock().unwrap() = Some(index.clone());
            Ok(())
        }
    }

    struct Machine {
        sys: FakeSystem,
        ledger: Arc<MemoryLedger>,
        engine: ReclaimEngineImpl,
    }

    impl Machine {
        fn new() -> Self {
            let sys = FakeSystem::new();
            let ledger = Arc::new(MemoryLedger::new(sys.boot()));
            let reclaimers = EffectKind::ALL
                .iter()
                .map(|k| match k {
                    EffectKind::Driver => {
                        Arc::new(NoDelete(sys.reclaimer(*k))) as Arc<dyn Reclaimer>
                    }
                    k => sys.reclaimer(*k),
                })
                .collect();
            let engine = ReclaimEngineImpl::new(ReclaimDeps {
                ledger: ledger.clone(),
                reclaimers,
                sweeper: Arc::new(Sweep(sys.clone())),
                boot_id: sys.boot_id_source(),
                repair_index: Arc::new(Index::default()),
            });
            Self {
                sys,
                ledger,
                engine,
            }
        }

        fn intent(name: &str) -> EffectIntent {
            EffectIntent {
                scope: EffectScope::Product,
                kind: EffectKind::Driver,
                key: driver(name),
                undo: Undo::EnsureAbsent,
                persistence: Persistence::Persistent,
            }
        }

        /// A kernel created the driver; read back without a credential.
        async fn created(&self, name: &str) {
            self.sys.create_ours(EffectKind::Driver, driver(name));
            let e = self.ledger.record(Self::intent(name)).await.unwrap();
            let read_back = Observation {
                credential: None,
                key: Some(driver(name)),
                observed_at: self.sys.now(),
                detail: None,
            };
            self.ledger
                .transition(&e.id, EffectState::Applied, Some(read_back))
                .await
                .unwrap();
        }

        /// Other software registered it first (`system_name`, which may
        /// differ in case); the start flagged our planned record.
        async fn preexisting(&self, name: &str, system_name: &str) {
            self.sys
                .create_foreign(EffectKind::Driver, driver(system_name));
            let e = self.ledger.record(Self::intent(name)).await.unwrap();
            let found = Observation {
                credential: None,
                key: Some(driver(system_name)),
                observed_at: self.sys.now(),
                detail: None,
            };
            self.ledger
                .transition(&e.id, EffectState::Reclaiming, None)
                .await
                .unwrap();
            self.ledger
                .transition(&e.id, EffectState::Conflict, Some(found))
                .await
                .unwrap();
        }

        /// Recorded before the spawn and never read back (the kernel died
        /// first or never loaded it), like the planned WinDivert record in
        /// the takeover ledger dumps. `registered`: the service exists.
        async fn planned(&self, name: &str, registered: bool) {
            if registered {
                self.sys.create_ours(EffectKind::Driver, driver(name));
            }
            self.ledger.record(Self::intent(name)).await.unwrap();
        }

        async fn purge(&self) -> Result<()> {
            let observer = self.sys.observer();
            reclaim_with(self.ledger.as_ref(), &self.engine, observer.as_ref(), true).await
        }

        /// The reclaim a host start runs (instances only).
        async fn startup(&self) -> Result<()> {
            let observer = self.sys.observer();
            reclaim_with(self.ledger.as_ref(), &self.engine, observer.as_ref(), false).await
        }

        async fn open(&self) -> Vec<Effect> {
            self.ledger.open_effects(&ScopeFilter::all()).await.unwrap()
        }

        fn untouched(&self, names: &[&str]) {
            assert!(self.sys.deleted().is_empty(), "{:?}", self.sys.deleted());
            for name in names {
                assert!(
                    self.sys.find(EffectKind::Driver, &driver(name)).is_some(),
                    "{name} still registered"
                );
            }
        }
    }

    fn driver(name: &str) -> ObjectKey {
        ObjectKey::Service { name: name.into() }
    }

    #[tokio::test]
    async fn purge_then_uninstall_both_succeed_and_leave_the_driver() {
        let m = Machine::new();
        m.created("wintun").await;
        m.purge().await.unwrap();
        assert!(m.open().await.is_empty());
        // The uninstall's purge finds it again by the sweep only.
        m.purge().await.unwrap();
        m.purge().await.unwrap();
        assert!(m.open().await.is_empty());
        m.untouched(&["wintun"]);
    }

    #[tokio::test]
    async fn preexisting_drivers_do_not_block_an_uninstall_without_a_prior_purge() {
        let m = Machine::new();
        m.preexisting("wintun", "wintun").await;
        // Same service, another case than our planned key.
        m.preexisting("WinDivert", "windivert").await;
        m.purge().await.unwrap();
        assert!(m.open().await.is_empty());
        m.purge().await.unwrap();
        m.untouched(&["wintun", "windivert"]);
    }

    #[tokio::test]
    async fn planned_shared_driver_records_are_kept_or_closed_by_a_purge() {
        let m = Machine::new();
        m.planned("WinDivert", true).await;
        m.planned("wintun", false).await;
        m.purge().await.unwrap();
        assert!(m.open().await.is_empty());
        m.purge().await.unwrap();
        m.untouched(&["WinDivert"]);
    }

    #[tokio::test]
    async fn startup_reclaims_never_quarantine_shared_driver_records() {
        let m = Machine::new();
        m.created("wintun").await;
        m.planned("WinDivert", true).await;
        for _ in 0..=etd_sysfx::QUARANTINE_AFTER {
            m.startup().await.unwrap();
        }
        let open = m.open().await;
        assert_eq!(open.len(), 2, "{open:?}");
        assert!(
            open.iter()
                .all(|e| e.state != EffectState::Quarantined && e.failures == 0),
            "{open:?}"
        );
        // The uninstall's purge still completes and leaves both in place.
        m.purge().await.unwrap();
        assert!(m.open().await.is_empty());
        m.untouched(&["wintun", "WinDivert"]);
    }

    #[tokio::test]
    async fn any_other_leftover_still_blocks_the_purge() {
        let m = Machine::new();
        m.created("wintun").await;
        // A non-shared object the sweep reports, with no record.
        m.sys.create_foreign(
            EffectKind::WinTunAdapter,
            ObjectKey::Interface {
                name: Some(format!("{}stray", etd_sysfx::naming::INTERFACE_PREFIX)),
                guid: None,
            },
        );
        assert!(m.purge().await.is_err());
        m.untouched(&["wintun"]);
    }
}

#[cfg(test)]
mod release_tests {
    use super::{release, sole_owner};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Lock<'a>(&'a AtomicBool);
    impl Drop for Lock<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn the_lock_is_released_only_when_quiescent() {
        let released = AtomicBool::new(false);
        release(Lock(&released), true);
        assert!(released.load(Ordering::SeqCst));
        let released = AtomicBool::new(false);
        release(Lock(&released), false);
        assert!(
            !released.load(Ordering::SeqCst),
            "kept until the process exits"
        );
    }

    #[tokio::test]
    async fn the_ledger_closes_once_a_detached_owner_ends() {
        let shared = std::sync::Arc::new(5);
        let detached = shared.clone();
        let (owned, ()) = tokio::join!(sole_owner(shared), async move {
            tokio::task::yield_now().await;
            drop(detached);
        });
        assert_eq!(owned, 5);
    }
}

#[cfg(test)]
mod lock_after_stop_tests {
    use super::lock_after_stop;
    use std::{io, time::Duration};

    fn held() -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "held"))
    }

    #[tokio::test(start_paused = true)]
    async fn a_lock_freed_by_the_exiting_service_is_taken() {
        let mut tries = 0;
        lock_after_stop(Duration::from_secs(10), || {
            tries += 1;
            if tries < 5 { held() } else { Ok(()) }
        })
        .await
        .unwrap();
        assert_eq!(tries, 5);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lock_still_held_after_the_wait_is_a_retryable_error() {
        let started = tokio::time::Instant::now();
        let error = lock_after_stop(Duration::from_secs(10), held)
            .await
            .unwrap_err();
        assert!(started.elapsed() >= Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(11));
        assert!(error.to_string().contains("retry in a moment"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn other_lock_errors_are_not_retried() {
        let mut tries = 0;
        let error = lock_after_stop(Duration::from_secs(10), || -> io::Result<()> {
            tries += 1;
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        })
        .await
        .unwrap_err();
        assert_eq!(tries, 1);
        assert!(error.to_string().contains("denied"));
    }
}
