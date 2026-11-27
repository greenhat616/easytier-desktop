//! Real subprocesses, native transport, SQLite and host serving loop. Fake
//! core driver/store, OS observations and repair-index storage; no OS changes.
use super::serving::{LayoutLock, serve_with_deps};
use etd_client::stub::host_service_client::HostServiceClient;
use etd_contract::{
    VERSION_MAJOR, VERSION_METADATA_KEY, VERSION_MINOR, v1::*, version_metadata_value,
};
use etd_core_api::*;
use etd_host_core::{
    api::{HostDeps, HostDirs},
    auth::allow_list::AllowListAuthorizer,
    core_store::{CoreUsage, VerifiedCore},
    reclaimers::host_reclaimers,
};
use etd_ipc::{
    Endpoint, HostForm, OsUserId, ServerExpectation, ServerRequirement,
    platform::{LocalConnector, current_user},
    tonic_io::ClientIo,
};
use etd_proc::{
    Clock, KillOutcome, Liveness, ProcessEngine, ProcessError, ProcessHandle, ProcessIdentity,
    ProcessMarker,
    backoff::{BackoffPolicy, SystemClock},
    processkit_engine::ProcessKitEngine,
};
use etd_sysfx::{
    BootId, Change, ChangeSet, Credential, EffectKind, InstallKey, Ledger, LedgerError, ObjectKey,
    Probe, ReclaimDeps, ReclaimError, Reclaimed, Reclaimer, RepairIndex, RepairIndexStore,
    RequestDigest, RequestRecord, ScopeFilter,
    engine::ReclaimEngineImpl,
    sqlite::{OpenOptions, SqliteLedger},
};
use etd_sysfx_os::service::HostLock;
use etd_testkit::fakes::{core::FakeCoreDriver, store::FakeCoreStore, system::FakeSystem};
use etd_testkit::no_window::NoWindow;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::{
    process::{Child, Command},
    time::{sleep, timeout},
};
use tonic::transport::Channel;

const BOOT: &str = "boot-1";
const SECRET: &str = "fake-core ready";
const FIXTURE: &str = "ETD_G1_FIXTURE";
const SERVICE: &str = "ETD_G1_SERVICE";
const LIMIT: Duration = Duration::from_secs(20);
type Client = HostServiceClient<Channel>;

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

#[derive(Default)]
struct Driver(FakeCoreDriver);

// Interrupt after the real runtime-dir undo but before its ledger transition.
struct GatedReclaimer {
    inner: Arc<dyn Reclaimer>,
    root: PathBuf,
}
#[async_trait::async_trait]
impl Reclaimer for GatedReclaimer {
    fn kind(&self) -> EffectKind {
        self.inner.kind()
    }
    fn rank(&self) -> u8 {
        self.inner.rank()
    }
    async fn probe(&self, e: &etd_sysfx::Effect) -> Probe {
        self.inner.probe(e).await
    }
    async fn reclaim(&self, e: &etd_sysfx::Effect) -> Result<Reclaimed, ReclaimError> {
        let result = self.inner.reclaim(e).await?;
        if self.root.join("block-reclaim").exists() {
            std::fs::write(self.root.join("reclaim-waiting"), "ready").unwrap();
            while self.root.join("block-reclaim").exists() {
                sleep(Duration::from_millis(25)).await;
            }
        }
        Ok(result)
    }
}

// Deterministic test-only barrier at the real process-engine boundary. All
// methods and actual launches still use the production engine.
struct GatedProcess {
    engine: ProcessKitEngine,
    root: PathBuf,
}
#[async_trait::async_trait]
impl ProcessEngine for GatedProcess {
    async fn spawn(&self, cmd: etd_proc::Command) -> Result<Box<dyn ProcessHandle>, ProcessError> {
        if self.root.join("block-spawn").exists() {
            std::fs::write(self.root.join("spawn-waiting"), "ready").unwrap();
            while self.root.join("block-spawn").exists() {
                sleep(Duration::from_millis(25)).await;
            }
        }
        self.engine.spawn(cmd).await
    }
    async fn liveness(&self, id: &ProcessIdentity) -> Liveness {
        self.engine.liveness(id).await
    }
    async fn kill_verified(&self, id: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
        self.engine.kill_verified(id).await
    }
    async fn find_marked(
        &self,
        marker: &ProcessMarker,
    ) -> Result<Vec<ProcessIdentity>, ProcessError> {
        self.engine.find_marked(marker).await
    }
}
#[async_trait::async_trait]
impl CoreDriver for Driver {
    async fn identify(&self, path: &Path) -> Result<CoreDescriptor, CoreError> {
        self.0.identify(path).await
    }
    fn profile(&self, desc: &CoreDescriptor) -> Option<AdapterProfile> {
        self.0.profile(desc)
    }
    fn plan_launch(&self, ctx: &LaunchContext) -> Result<LaunchPlan, CoreError> {
        let mut plan = self.0.plan_launch(ctx)?;
        plan.command.args = vec![
            "--ready-file".into(),
            ctx.inputs.runtime_dir.join("ready").into_os_string(),
            "-c".into(),
            ctx.inputs.runtime_dir.join("config.toml").into_os_string(),
            "--exit-after-ms".into(),
            "120000".into(),
            "--exit-code".into(),
            "37".into(),
            "--exit-file".into(),
            ctx.inputs.runtime_dir.join("exit-now").into_os_string(),
        ];
        Ok(plan)
    }
    async fn attach(
        &self,
        ep: &CoreEndpoint,
        desc: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError> {
        self.0.attach(ep, desc).await
    }
}
fn request<T>(body: T) -> tonic::Request<T> {
    let mut r = tonic::Request::new(body);
    r.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    r
}
fn private(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
fn endpoint(root: &Path) -> Endpoint {
    #[cfg(windows)]
    {
        Endpoint::NamedPipe(format!(
            r"\\.\pipe\etd-g1-{}",
            root.file_name().unwrap().to_string_lossy()
        ))
    }
    #[cfg(unix)]
    {
        Endpoint::UnixSocket(root.join("host.sock"))
    }
}
fn binary(root: &Path, name: &str) -> PathBuf {
    root.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}
async fn ledger(root: &Path) -> Arc<SqliteLedger> {
    Arc::new(
        SqliteLedger::open(root.join("state/ledger.sqlite3"), BootId(BOOT.into()))
            .await
            .unwrap(),
    )
}

// Re-exec the test harness under the expected native host filename; this is
// not a product binary, and no fixture switch is present in product builds.
#[tokio::test]
async fn fixture_host() {
    let Some(root) = std::env::var_os(FIXTURE) else {
        return;
    };
    let root = PathBuf::from(root);
    let service = std::env::var_os(SERVICE).is_some();
    let mode = if service {
        HostMode::Service
    } else {
        HostMode::User
    };
    let state = root.join("state");
    let run = state.join("run");
    let cores = state.join("cores");
    let guard = LayoutLock::new(
        HostLock::acquire(&state).unwrap(),
        endpoint(&root),
        if service {
            HostForm::Service
        } else {
            HostForm::User
        },
    );
    let fake = FakeSystem::new();
    let boot_id = fake.boot_id_source();
    let ledger = ledger(&root).await;
    if service && ledger.settings().await.unwrap().allow_list.is_empty() {
        let principal = match current_user().unwrap() {
            OsUserId::WindowsSid(sid) => os_principal::Id::WindowsUserSid(sid),
            OsUserId::UnixUid(uid) => os_principal::Id::UnixUid(uid),
            _ => panic!("unsupported fixture user principal"),
        };
        ledger
            .commit(
                ledger.desired().await.unwrap().0,
                ChangeSet {
                    request: RequestRecord {
                        request_id: "fixture-enroll".into(),
                        caller: "tier2 fixture".into(),
                        digest: RequestDigest([1; 32]),
                    },
                    changes: vec![Change::SetAllowList(vec![AllowEntry {
                        principal: Some(OsPrincipal {
                            id: Some(principal),
                        }),
                        role: Role::Admin as i32,
                        display_name: "fixture".into(),
                    }])],
                    generations: vec![],
                },
            )
            .await
            .unwrap();
    }
    let index = Arc::new(Index::default());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let process: Arc<dyn ProcessEngine> = Arc::new(GatedProcess {
        engine: ProcessKitEngine::with_console_helper(binary(&cores, "fake-core")),
        root: root.clone(),
    });
    let driver = Arc::new(Driver::default());
    let descriptor = driver.0.descriptor();
    let store = Arc::new(FakeCoreStore::new(
        Some(descriptor.version.clone()),
        vec![VerifiedCore {
            binary: binary(&cores, "fake-core"),
            descriptor,
            sha256: [9; 32],
            usage: CoreUsage::Profiled(driver.0.profile_of().unwrap()),
        }],
    ));
    let reclaim = Arc::new(ReclaimEngineImpl::new(ReclaimDeps {
        ledger: ledger.clone(),
        reclaimers: host_reclaimers(process.clone(), clock.clone(), run.clone())
            .into_iter()
            .map(|inner| {
                if inner.kind() == EffectKind::RuntimeDir {
                    Arc::new(GatedReclaimer {
                        inner,
                        root: root.clone(),
                    }) as Arc<dyn Reclaimer>
                } else {
                    inner
                }
            })
            .collect(),
        sweeper: fake.sweeper(),
        boot_id: boot_id.clone(),
        repair_index: index.clone(),
    }));
    let auth = Arc::new(AllowListAuthorizer::new(
        mode,
        Some(current_user().unwrap()),
    ));
    // The fake observer only reports a listener after the real child has
    // published its ready-file (the kernel RPC/session itself is simulated).
    let (l, f) = (ledger.clone(), fake.clone());
    let observations = tokio::spawn(async move {
        loop {
            for e in l.open_effects(&ScopeFilter::default()).await.unwrap() {
                if let (EffectKind::Process, Some(Credential::Process { pid, .. })) = (
                    &e.kind,
                    e.observation.as_ref().and_then(|o| o.credential.as_ref()),
                ) {
                    let (instance, epoch) = e.scope.generation().unwrap();
                    let g = l.generation(instance, epoch).await.unwrap().unwrap();
                    if std::fs::read_to_string(g.inputs.runtime_dir.join("ready"))
                        .is_ok_and(|s| s == pid.to_string())
                    {
                        f.set_listener(g.inputs.management, *pid);
                    }
                }
            }
            sleep(Duration::from_millis(25)).await;
        }
    });
    let deps = Arc::new(HostDeps {
        mode,
        dirs: HostDirs {
            state_dir: state,
            run_dir: run,
            core_store_dir: cores,
        },
        process,
        restart_policy: Arc::new(|| Box::new(BackoffPolicy::new())),
        clock,
        ledger,
        repair_index: index,
        reclaim,
        boot_id,
        install_key: InstallKey([7; 32]),
        observer: fake.observer(),
        fence: None,
        core: driver,
        core_store: store,
        authorizer: auth,
    });
    let stopped = serve_with_deps(mode, guard, deps, None, None)
        .await
        .unwrap();
    observations.abort();
    // As in etd-host: the singleton lock goes now only if the host's
    // wind-down is confirmed; otherwise the process exit releases it.
    if stopped.quiescent {
        drop(stopped.lock);
    } else {
        std::mem::forget(stopped.lock);
    }
    if let Err(error) = &stopped.result {
        eprintln!("fixture host stopped with an error: {error:#}");
    }
}

#[cfg(unix)]
fn isolated_unix(test: &str) -> bool {
    if std::env::var_os("ETD_G1_RUNTIME").is_some() {
        return false;
    }
    // Use a short canonical path to respect AF_UNIX length and avoid /var
    // symlinks on macOS. Linux authenticates against the process runtime dir.
    let runtime = tempfile::tempdir_in(std::fs::canonicalize("/tmp").unwrap()).unwrap();
    private(runtime.path());
    // no-window: Unix only
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("ETD_G1_RUNTIME", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .status()
        .unwrap();
    assert!(status.success());
    true
}
struct Fixture {
    host: Child,
    root: TempDir,
    service: bool,
}
impl Fixture {
    fn new() -> Self {
        Self::new_mode(false)
    }
    fn new_mode(service: bool) -> Self {
        let runtime = if service {
            Some(std::env::var_os("ETD_G1_SERVICE_RUNTIME").expect(
                "set ETD_G1_SERVICE_RUNTIME to a private directory on the privileged runner",
            ))
        } else {
            std::env::var_os("ETD_G1_RUNTIME")
        };
        let root = match runtime {
            Some(runtime) => tempfile::tempdir_in(runtime).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        private(root.path());
        for sub in ["state", "state/run", "state/cores"] {
            private(&root.path().join(sub));
        }
        std::fs::copy(
            std::env::current_exe().unwrap(),
            binary(root.path(), "etd-host"),
        )
        .unwrap();
        std::fs::copy(
            super::executable(),
            binary(&root.path().join("state/cores"), "fake-core"),
        )
        .unwrap();
        let host = Self::spawn(root.path(), service);
        Self {
            root,
            host,
            service,
        }
    }
    fn spawn(root: &Path, service: bool) -> Child {
        let mut cmd = Command::new(binary(root, "etd-host"));
        cmd.no_window();
        if service {
            cmd.env(SERVICE, "1");
        } else {
            cmd.env_remove(SERVICE);
        }
        cmd.args(["--exact", "host_process::fixture_host", "--nocapture"])
            .env(FIXTURE, root)
            .env("XDG_RUNTIME_DIR", root)
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }
    async fn connect(&self) -> Client {
        connect(self.root.path(), self.service).await
    }
    async fn restart(&mut self) {
        self.host.kill().await.unwrap();
        self.host = Self::spawn(self.root.path(), self.service);
    }
}
async fn connect(root: &Path, service: bool) -> Client {
    let connector = Arc::new(LocalConnector {
        expectation: ServerExpectation {
            exe_dir: root.to_owned(),
            requirement: if service {
                ServerRequirement::Service
            } else {
                ServerRequirement::CurrentUser
            },
        },
    });
    timeout(LIMIT, async {
        loop {
            if let Ok(channel) = tonic::transport::Endpoint::from_static("http://localhost")
                .connect_with_connector(ClientIo::new(connector.clone(), endpoint(root)))
                .await
            {
                let mut client = HostServiceClient::new(channel);
                let hello = client
                    .handshake(request(Hello {
                        major: VERSION_MAJOR,
                        minor: VERSION_MINOR,
                        client_kind: ClientKind::Desktop as i32,
                        ..Default::default()
                    }))
                    .await
                    .unwrap()
                    .into_inner();
                assert_eq!(
                    hello.host_mode(),
                    if service {
                        HostMode::Service
                    } else {
                        HostMode::User
                    }
                );
                if service {
                    assert!(matches!(hello.role(), Role::Admin | Role::Control));
                } else {
                    assert_eq!(hello.role(), Role::Admin);
                }
                loop {
                    let snapshot = client
                        .snapshot(request(SnapshotRequest {}))
                        .await
                        .unwrap()
                        .into_inner();
                    if snapshot.phase() == HostPhase::Serving {
                        return client;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("host did not enter Serving")
}
fn mutation(id: &str, request_id: &str, desired: Desired, revision: u64) -> ApplyRequest {
    ApplyRequest {
        header: Some(MutationHeader {
            request_id: request_id.into(),
            expected_revision: revision,
        }),
        instance_id: id.into(),
        spec: Some(NetworkSpec {
            network_name: "tier2".into(),
            network_secret: Some(SECRET.into()),
            no_tun: true,
            ..Default::default()
        }),
        desired: desired as i32,
    }
}
async fn apply(client: &mut Client, id: &str, request_id: &str, desired: Desired) -> Receipt {
    let revision = client
        .snapshot(request(SnapshotRequest {}))
        .await
        .unwrap()
        .into_inner()
        .revision;
    client
        .apply(request(mutation(id, request_id, desired, revision)))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap()
}
async fn read_ledger(root: &Path) -> SqliteLedger {
    // Open fresh, read-only snapshots: the product ledger caches its state
    // on the single writer and a persistent second worker would be stale.
    // A concurrent write can straddle the reader's initial load; retry only
    // until the bounded test deadline, never open a second writer.
    timeout(LIMIT, async {
        loop {
            match SqliteLedger::open_with_options(
                root.join("state/ledger.sqlite3"),
                BootId(BOOT.into()),
                OpenOptions {
                    read_only: true,
                    ..Default::default()
                },
            )
            .await
            {
                Ok(db) => return db,
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .expect("cannot inspect fixture ledger")
}
async fn identity(root: &Path) -> ProcessIdentity {
    identity_after(root, None).await
}
async fn identity_after(root: &Path, previous: Option<&ProcessIdentity>) -> ProcessIdentity {
    timeout(LIMIT, async {
        loop {
            let ledger = read_ledger(root).await;
            for e in ledger.open_effects(&ScopeFilter::default()).await.unwrap() {
                if let (
                    ObjectKey::Process { exe, .. },
                    Some(Credential::Process { pid, start_token }),
                ) = (
                    &e.key,
                    e.observation.as_ref().and_then(|o| o.credential.as_ref()),
                ) {
                    let (instance, epoch) = e.scope.generation().unwrap();
                    let g = ledger.generation(instance, epoch).await.unwrap().unwrap();
                    if std::fs::read_to_string(g.inputs.runtime_dir.join("ready"))
                        .is_ok_and(|s| s == pid.to_string())
                    {
                        let id = ProcessIdentity {
                            pid: *pid,
                            start_token: start_token.clone(),
                            exe: exe.clone(),
                        };
                        if previous != Some(&id) {
                            return id;
                        }
                    }
                }
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("no recorded live core")
}

#[tokio::test]
async fn killed_host_reclaims_previous_generation_on_restart() {
    #[cfg(unix)]
    if isolated_unix("host_process::killed_host_reclaims_previous_generation_on_restart") {
        return;
    }
    let mut f = Fixture::new();
    let mut client = f.connect().await;
    let id = uuid::Uuid::new_v4().to_string();
    apply(&mut client, &id, "start", Desired::Running).await;
    let old = identity(f.root.path()).await;
    let engine = super::engine();
    assert_eq!(engine.liveness(&old).await, Liveness::Same);
    let ledger = read_ledger(f.root.path()).await;
    let previous = ledger.open_effects(&ScopeFilter::default()).await.unwrap();
    assert!(!previous.is_empty());
    ledger.close().await.unwrap();
    drop(client);
    f.host.kill().await.unwrap();
    #[cfg(any(windows, target_os = "linux"))]
    super::gone(&engine, &old).await;
    f.host = Fixture::spawn(f.root.path(), false);
    let mut client = f.connect().await;
    super::gone(&engine, &old).await;
    wait_open(
        f.root.path(),
        "old generation still open after self-check",
        |open| {
            previous
                .iter()
                .all(|old| !open.iter().any(|new| new.id == old.id))
        },
    )
    .await;
    assert_runtime_dirs_gone(&previous);
    finish_user(&mut f, &mut client).await;
}

#[tokio::test]
async fn receipt_survives_lost_client_reply_and_host_restart() {
    #[cfg(unix)]
    if isolated_unix("host_process::receipt_survives_lost_client_reply_and_host_restart") {
        return;
    }
    let mut f = Fixture::new();
    let mut client = f.connect().await;
    let id = uuid::Uuid::new_v4().to_string();
    let revision = client
        .snapshot(request(SnapshotRequest {}))
        .await
        .unwrap()
        .into_inner()
        .revision;
    let body = mutation(&id, "lost-reply", Desired::Stopped, revision);
    let sent = body.clone();
    // The UI gives up its in-flight response; the result is deliberately
    // never exposed to the test client. The durable receipt is sampled from
    // an independent read-only SQLite connection, then the host is killed.
    let call = tokio::spawn(async move {
        let _ = client.apply(request(sent)).await;
    });
    let original = timeout(LIMIT, async {
        loop {
            let db = read_ledger(f.root.path()).await;
            let receipt = db.receipt(&"lost-reply".into()).await.unwrap();
            db.close().await.unwrap();
            if let Some(receipt) = receipt {
                return receipt;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("mutation not committed");
    call.abort();
    let _ = call.await;
    f.restart().await;
    let mut client = f.connect().await;
    let recovered = client
        .get_receipt(request(GetReceiptRequest {
            request_id: "lost-reply".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(original, recovered);
    let retried = client
        .apply(request(body))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(original, retried);
    let snapshot = client
        .snapshot(request(SnapshotRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(snapshot.revision, original.revision);
    assert_eq!(snapshot.instances.len(), 1);
    finish_user(&mut f, &mut client).await;
}

#[tokio::test]
async fn kernel_stderr_is_redacted_on_native_log_stream() {
    #[cfg(unix)]
    if isolated_unix("host_process::kernel_stderr_is_redacted_on_native_log_stream") {
        return;
    }
    let mut f = Fixture::new();
    let mut client = f.connect().await;
    let id = uuid::Uuid::new_v4().to_string();
    apply(&mut client, &id, "start", Desired::Running).await;
    let mut logs = client
        .stream_logs(request(StreamLogsRequest {
            instance_id: id,
            tail_lines: 100,
            follow: true,
        }))
        .await
        .unwrap()
        .into_inner();
    timeout(LIMIT, async {
        loop {
            let line = logs.message().await.unwrap().unwrap();
            assert!(!line.text.contains(SECRET));
            if line.source() == LogSource::CoreStderr && line.text.contains("<redacted>") {
                break;
            }
        }
    })
    .await
    .expect("no redacted fake-core stderr line");
    drop(logs);
    finish_user(&mut f, &mut client).await;
}

#[tokio::test]
async fn fixture_ui() {
    let Some(root) = std::env::var_os("ETD_G1_UI") else {
        return;
    };
    let root = PathBuf::from(root);
    let mut client = connect(&root, std::env::var_os(SERVICE).is_some()).await;
    let id = uuid::Uuid::new_v4().to_string();
    apply(&mut client, &id, "ui-start", Desired::Running).await;
    if !root.join("block-spawn").exists() {
        wait_ready(&mut client).await;
    }
    std::fs::write(root.join("ui-ready"), "ready").unwrap();
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn killed_ui_leaves_user_host_running_until_lease_grace() {
    #[cfg(unix)]
    if isolated_unix("host_process::killed_ui_leaves_user_host_running_until_lease_grace") {
        return;
    }
    let mut f = Fixture::new();
    let mut ui = Command::new(std::env::current_exe().unwrap())
        .no_window()
        .args(["--exact", "host_process::fixture_ui", "--nocapture"])
        .env("ETD_G1_UI", f.root.path())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    super::file(&f.root.path().join("ui-ready")).await;
    let core = identity(f.root.path()).await;
    let engine = super::engine();
    assert_eq!(engine.liveness(&core).await, Liveness::Same);
    ui.kill().await.unwrap();
    let disconnected = Instant::now();
    sleep(Duration::from_secs(2)).await;
    assert!(
        f.host.try_wait().unwrap().is_none(),
        "host exited before lease grace"
    );
    assert_eq!(engine.liveness(&core).await, Liveness::Same);
    let exit = timeout(Duration::from_secs(50), f.host.wait())
        .await
        .expect("user host did not exit after lease grace")
        .unwrap();
    assert!(exit.success());
    assert!(
        disconnected.elapsed() >= Duration::from_secs(28),
        "lease grace expired prematurely"
    );
    super::gone(&engine, &core).await;
    let ledger = read_ledger(f.root.path()).await;
    assert!(
        ledger
            .open_effects(&ScopeFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    ledger.close().await.unwrap();
}

fn assert_runtime_dirs_gone(records: &[etd_sysfx::Effect]) {
    for e in records {
        if e.kind == EffectKind::RuntimeDir
            && let ObjectKey::Path { path } = &e.key
        {
            assert!(
                !path.exists(),
                "closed generation runtime directory still exists: {}",
                path.display()
            );
        }
    }
}
/// Sends request bodies as given bytes, so a test can send one that is not
/// a valid protobuf message.
#[derive(Clone, Copy, Default)]
struct RawCodec;
impl tonic::codec::Codec for RawCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = RawCodec;
    type Decoder = RawCodec;
    fn encoder(&mut self) -> Self::Encoder {
        RawCodec
    }
    fn decoder(&mut self) -> Self::Decoder {
        RawCodec
    }
}
impl tonic::codec::Encoder for RawCodec {
    type Item = Vec<u8>;
    type Error = tonic::Status;
    fn encode(
        &mut self,
        item: Vec<u8>,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), tonic::Status> {
        prost::bytes::BufMut::put_slice(dst, &item);
        Ok(())
    }
}
impl tonic::codec::Decoder for RawCodec {
    type Item = Vec<u8>;
    type Error = tonic::Status;
    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Vec<u8>>, tonic::Status> {
        let n = prost::bytes::Buf::remaining(src);
        Ok(Some(prost::bytes::Buf::copy_to_bytes(src, n).to_vec()))
    }
}

#[tokio::test]
async fn incompatible_version_metadata_is_refused_before_decoding() {
    #[cfg(unix)]
    if isolated_unix("host_process::incompatible_version_metadata_is_refused_before_decoding") {
        return;
    }
    let mut f = Fixture::new();
    let mut client = f.connect().await;
    let connector = Arc::new(LocalConnector {
        expectation: ServerExpectation {
            exe_dir: f.root.path().to_owned(),
            requirement: ServerRequirement::CurrentUser,
        },
    });
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(ClientIo::new(connector, endpoint(f.root.path())))
        .await
        .unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    // Not a protobuf message: a handler would fail to decode it first.
    let mut body = tonic::Request::new(vec![0xff; 8]);
    body.metadata_mut().insert(
        VERSION_METADATA_KEY,
        format!("{}.0", VERSION_MAJOR + 1).parse().unwrap(),
    );
    let status = grpc
        .unary::<Vec<u8>, Vec<u8>, _>(
            body,
            tonic::codegen::http::uri::PathAndQuery::from_static("/etd.v1.HostService/Snapshot"),
            RawCodec,
        )
        .await
        .unwrap_err();
    let detail = <etd_contract::ErrorDetail as prost::Message>::decode(status.details())
        .unwrap_or_else(|_| panic!("no contract error detail: {status:?}"));
    assert_eq!(
        detail.code(),
        etd_contract::ErrorCode::VersionMismatch,
        "{status:?}"
    );
    finish_user(&mut f, &mut client).await;
}

async fn finish_user(f: &mut Fixture, client: &mut Client) {
    client
        .release_lease(request(ReleaseLeaseRequest {
            instances: LeaseRelease::StopInstances as i32,
        }))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_secs(20), f.host.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

// Requires root on Unix / LocalSystem on Windows, with a private protected
// directory (not /tmp on Unix). No OS service installation or TUN is done.
#[tokio::test]
#[ignore = "requires privileged native service IPC (root/LocalSystem) and ETD_G1_SERVICE_RUNTIME"]
async fn killed_ui_does_not_stop_service_host_after_lease_grace() {
    let mut f = Fixture::new_mode(true);
    let mut ui = Command::new(std::env::current_exe().unwrap())
        .no_window()
        .args(["--exact", "host_process::fixture_ui", "--nocapture"])
        .env("ETD_G1_UI", f.root.path())
        .env(SERVICE, "1")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    super::file(&f.root.path().join("ui-ready")).await;
    let old = identity(f.root.path()).await;
    ui.kill().await.unwrap();
    sleep(Duration::from_secs(35)).await;
    assert!(f.host.try_wait().unwrap().is_none());
    assert_eq!(super::engine().liveness(&old).await, Liveness::Same);
    let mut client = f.connect().await;
    let snapshot = client
        .snapshot(request(SnapshotRequest {}))
        .await
        .unwrap()
        .into_inner();
    let desired = snapshot.instances[0].desired.as_ref().unwrap();
    client
        .set_desired(request(SetDesiredRequest {
            header: Some(MutationHeader {
                request_id: "stop".into(),
                expected_revision: snapshot.revision,
            }),
            instance_id: desired.instance_id.clone(),
            desired: Desired::Stopped as i32,
        }))
        .await
        .unwrap();
    super::gone(&super::engine(), &old).await;
    f.host.kill().await.unwrap();
}

#[tokio::test]
async fn host_death_after_intent_before_spawn_closes_empty_generation() {
    #[cfg(unix)]
    if isolated_unix("host_process::host_death_after_intent_before_spawn_closes_empty_generation") {
        return;
    }
    let mut f = Fixture::new();
    let mut client = f.connect().await;
    std::fs::write(f.root.path().join("block-spawn"), "block").unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    apply(&mut client, &id, "start", Desired::Running).await;
    super::file(&f.root.path().join("spawn-waiting")).await;
    let db = read_ledger(f.root.path()).await;
    let records = db.open_effects(&ScopeFilter::default()).await.unwrap();
    let process = records
        .iter()
        .find(|e| e.kind == EffectKind::Process)
        .expect("committed process intent");
    assert!(
        process
            .observation
            .as_ref()
            .and_then(|o| o.credential.as_ref())
            .is_none()
    );
    db.close().await.unwrap();
    let marker = ProcessMarker {
        exe_root: f.root.path().join("state/cores"),
        cmdline_root: f.root.path().join("state/run"),
    };
    assert!(
        super::engine()
            .find_marked(&marker)
            .await
            .unwrap()
            .is_empty()
    );
    drop(client);
    f.host.kill().await.unwrap();
    std::fs::remove_file(f.root.path().join("block-spawn")).unwrap();
    f.host = Fixture::spawn(f.root.path(), false);
    let mut client = f.connect().await;
    let new = identity(f.root.path()).await;
    assert_eq!(super::engine().liveness(&new).await, Liveness::Same);
    let db = read_ledger(f.root.path()).await;
    let open = db.open_effects(&ScopeFilter::default()).await.unwrap();
    assert!(
        records
            .iter()
            .all(|old| !open.iter().any(|new| new.id == old.id))
    );
    assert_runtime_dirs_gone(&records);
    db.close().await.unwrap();
    finish_user(&mut f, &mut client).await;
}

#[tokio::test]
async fn abnormal_core_exit_reclaims_then_launches_new_generation() {
    #[cfg(unix)]
    if isolated_unix("host_process::abnormal_core_exit_reclaims_then_launches_new_generation") {
        return;
    }
    let mut f = Fixture::new();
    let mut client = f.connect().await;
    let id = uuid::Uuid::new_v4().to_string();
    apply(&mut client, &id, "start", Desired::Running).await;
    let old = identity(f.root.path()).await;
    let db = read_ledger(f.root.path()).await;
    let records = db.open_effects(&ScopeFilter::default()).await.unwrap();
    db.close().await.unwrap();
    let engine = super::engine();
    let marker = ProcessMarker {
        exe_root: f.root.path().join("state/cores"),
        cmdline_root: f.root.path().join("state/run"),
    };
    assert!(engine.find_marked(&marker).await.unwrap().contains(&old));
    let runtime = records
        .iter()
        .find_map(|e| match &e.key {
            ObjectKey::Process { cmdline_marker, .. } => Some(cmdline_marker),
            _ => None,
        })
        .unwrap();
    // Fake-core exits with code 37 in response to its own file trigger;
    // the process engine receives the real OS exit, not a simulated event.
    std::fs::write(runtime.join("exit-now"), "exit").unwrap();
    super::gone(&engine, &old).await;
    let new = identity_after(f.root.path(), Some(&old)).await;
    assert_eq!(engine.liveness(&new).await, Liveness::Same);
    let db = read_ledger(f.root.path()).await;
    let open = db.open_effects(&ScopeFilter::default()).await.unwrap();
    assert!(
        records
            .iter()
            .all(|old| !open.iter().any(|new| new.id == old.id))
    );
    assert_runtime_dirs_gone(&records);
    db.close().await.unwrap();
    finish_user(&mut f, &mut client).await;
}

#[tokio::test]
async fn host_death_mid_reclaim_replays_completed_undo() {
    #[cfg(unix)]
    if isolated_unix("host_process::host_death_mid_reclaim_replays_completed_undo") {
        return;
    }
    let mut f = Fixture::new();
    let mut client = f.connect().await;
    let id = uuid::Uuid::new_v4().to_string();
    let started = apply(&mut client, &id, "start", Desired::Running).await;
    let old = identity(f.root.path()).await;
    let db = read_ledger(f.root.path()).await;
    let records = db.open_effects(&ScopeFilter::default()).await.unwrap();
    db.close().await.unwrap();
    std::fs::write(f.root.path().join("block-reclaim"), "block").unwrap();
    client
        .set_desired(request(SetDesiredRequest {
            header: Some(MutationHeader {
                request_id: "stop".into(),
                expected_revision: started.revision,
            }),
            instance_id: id,
            desired: Desired::Stopped as i32,
        }))
        .await
        .unwrap();
    super::file(&f.root.path().join("reclaim-waiting")).await;
    super::gone(&super::engine(), &old).await;
    assert_runtime_dirs_gone(&records);
    let db = read_ledger(f.root.path()).await;
    assert!(
        db.open_effects(&ScopeFilter::default())
            .await
            .unwrap()
            .iter()
            .any(|e| e.kind == EffectKind::RuntimeDir)
    );
    db.close().await.unwrap();
    drop(client);
    f.host.kill().await.unwrap();
    std::fs::remove_file(f.root.path().join("block-reclaim")).unwrap();
    f.host = Fixture::spawn(f.root.path(), false);
    let mut client = f.connect().await;
    wait_open(
        f.root.path(),
        "the interrupted undo was not replayed",
        <[etd_sysfx::Effect]>::is_empty,
    )
    .await;
    assert_runtime_dirs_gone(&records);
    finish_user(&mut f, &mut client).await;
}

/// Wait, bounded, until the ledger's open records satisfy `done`. Serving
/// does not mean reclaimed: a self-check whose machine-wide kernel sweep
/// cannot account for every process (parallel tests start and end many)
/// holds the reclaim, fail closed, and the host re-sweeps and reclaims
/// `reclaim_retry` later.
async fn wait_open(root: &Path, what: &str, done: impl Fn(&[etd_sysfx::Effect]) -> bool) {
    let mut last = Vec::new();
    let settled = timeout(LIMIT, async {
        loop {
            let db = read_ledger(root).await;
            last = db.open_effects(&ScopeFilter::default()).await.unwrap();
            db.close().await.unwrap();
            if done(&last) {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(settled.is_ok(), "{what}; open records: {last:#?}");
}

async fn wait_ready(client: &mut Client) {
    timeout(LIMIT, async {
        loop {
            let snapshot = client
                .snapshot(request(SnapshotRequest {}))
                .await
                .unwrap()
                .into_inner();
            if snapshot.instances.iter().any(|i| {
                i.status.as_ref().is_some_and(|s| {
                    matches!(
                        s.state(),
                        InstanceState::ReadyBasic | InstanceState::ReadyFull
                    )
                })
            }) {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("fake-core did not reach readiness");
}

#[tokio::test]
async fn ui_death_after_intent_does_not_prevent_launch() {
    #[cfg(unix)]
    if isolated_unix("host_process::ui_death_after_intent_does_not_prevent_launch") {
        return;
    }
    let mut f = Fixture::new();
    std::fs::write(f.root.path().join("block-spawn"), "block").unwrap();
    let mut ui = Command::new(std::env::current_exe().unwrap())
        .no_window()
        .args(["--exact", "host_process::fixture_ui", "--nocapture"])
        .env("ETD_G1_UI", f.root.path())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    super::file(&f.root.path().join("spawn-waiting")).await;
    super::file(&f.root.path().join("ui-ready")).await;
    ui.kill().await.unwrap();
    assert!(f.host.try_wait().unwrap().is_none());
    std::fs::remove_file(f.root.path().join("block-spawn")).unwrap();
    let mut client = f.connect().await;
    let core = identity(f.root.path()).await;
    assert_eq!(super::engine().liveness(&core).await, Liveness::Same);
    wait_ready(&mut client).await;
    finish_user(&mut f, &mut client).await;
}
