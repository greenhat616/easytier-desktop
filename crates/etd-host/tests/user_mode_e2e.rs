//! Native IPC, the production composition/lease loop, real child containment,
//! and scripted kernel/OS observations. No privileged system objects are used.
#[allow(dead_code)]
#[path = "../src/host.rs"]
mod host;
#[allow(dead_code)]
#[path = "../src/storage.rs"]
mod storage;
#[allow(dead_code)]
#[path = "../src/unavailable.rs"]
mod unavailable;

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
    Endpoint, HostForm, ServerExpectation,
    platform::{LocalConnector, current_user},
    tonic_io::ClientIo,
};
use etd_proc::{
    Clock, ProcessEngine,
    backoff::{BackoffPolicy, SystemClock},
    processkit_engine::ProcessKitEngine,
};
use etd_sysfx::{
    Credential, EffectKind, InstallKey, Ledger, ReclaimDeps, ScopeFilter,
    engine::ReclaimEngineImpl, sqlite::SqliteLedger,
};
use etd_sysfx_os::service::HostLock;
use etd_testkit::fakes::{core::FakeCoreDriver, store::FakeCoreStore, system::FakeSystem};
use etd_testkit::no_window::NoWindow;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Default)]
struct TestDriver(FakeCoreDriver);
#[async_trait::async_trait]
impl CoreDriver for TestDriver {
    async fn identify(&self, path: &Path) -> Result<CoreDescriptor, CoreError> {
        self.0.identify(path).await
    }
    fn profile(&self, desc: &CoreDescriptor) -> Option<AdapterProfile> {
        self.0.profile(desc)
    }
    fn plan_launch(&self, ctx: &LaunchContext) -> Result<LaunchPlan, CoreError> {
        let mut plan = self.0.plan_launch(ctx)?;
        // Use the test harness itself as a real, long-lived fake kernel. The
        // skipped filter contains the epoch marker for ProcessEngine recovery.
        plan.command.args = vec![
            "--exact".into(),
            "fake_core_child".into(),
            "--nocapture".into(),
            "--skip".into(),
            ctx.inputs.runtime_dir.clone().into_os_string(),
        ];
        plan.command.env = vec![(
            "ETD_HR_FAKE_BIND".into(),
            ctx.inputs.management.to_string().into(),
        )];
        Ok(plan)
    }
    async fn attach(
        &self,
        ep: &CoreEndpoint,
        core: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError> {
        self.0.attach(ep, core).await
    }
}

#[test]
fn fake_core_child() {
    let Ok(address) = std::env::var("ETD_HR_FAKE_BIND") else {
        return;
    };
    let _listener = std::net::TcpListener::bind(address).unwrap();
    // The real process engine stops/kills this child, including on failure.
    std::thread::sleep(Duration::from_secs(60));
}

fn request<T>(body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    request
}

fn private(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[tokio::test]
async fn apply_ready_stop_and_reclaim_over_real_transport() {
    // Run in a copy with the real host filename so LocalConnector exercises
    // its production image verifier, not an unverified test connector.
    let host_name = format!("etd-host{}", std::env::consts::EXE_SUFFIX);
    let exe = std::env::current_exe().unwrap();
    if exe.file_name().unwrap() != host_name.as_str() {
        let dir = tempfile::tempdir().unwrap();
        private(dir.path());
        let copy = dir.path().join(host_name);
        std::fs::copy(exe, &copy).unwrap();
        let output = std::process::Command::new(copy)
            .no_window()
            .args([
                "--exact",
                "apply_ready_stop_and_reclaim_over_real_transport",
                "--nocapture",
            ])
            .env("XDG_RUNTIME_DIR", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = exe.parent().unwrap().canonicalize().unwrap();
    let state = dir.join("state");
    let run = state.join("run");
    let cores = state.join("cores");
    for path in [&state, &run, &cores] {
        private(path);
    }
    let core = cores.join(format!("fake-core{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(&exe, &core).unwrap();
    let core = core.canonicalize().unwrap();
    #[cfg(windows)]
    let endpoint = Endpoint::NamedPipe(format!(r"\\.\pipe\etd-hr-test-{}", std::process::id()));
    #[cfg(unix)]
    let endpoint = Endpoint::UnixSocket(dir.join("host.sock"));
    let guard = host::LayoutLock::new(
        HostLock::acquire(&state).unwrap(),
        endpoint.clone(),
        HostForm::User,
    );
    let fake = FakeSystem::new();
    let boot_id = fake.boot_id_source();
    let ledger = Arc::new(
        SqliteLedger::open(state.join("ledger.sqlite3"), boot_id.current().unwrap())
            .await
            .unwrap(),
    );
    let index = Arc::new(storage::FileIndex::new(&state));
    let key = InstallKey([7; 32]);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let process: Arc<dyn ProcessEngine> = Arc::new(ProcessKitEngine::with_console_helper(
        PathBuf::from(env!("CARGO_BIN_EXE_etd-host")),
    ));
    let driver = Arc::new(TestDriver::default());
    let descriptor = driver.0.descriptor();
    let store = Arc::new(FakeCoreStore::new(
        Some(descriptor.version.clone()),
        vec![VerifiedCore {
            binary: core,
            descriptor,
            sha256: [9; 32],
            usage: CoreUsage::Profiled(driver.0.profile_of().unwrap()),
        }],
    ));
    let reclaim = Arc::new(ReclaimEngineImpl::new(ReclaimDeps {
        ledger: ledger.clone(),
        reclaimers: host_reclaimers(process.clone(), clock.clone(), run.clone()),
        sweeper: fake.sweeper(),
        boot_id: boot_id.clone(),
        repair_index: index.clone(),
    }));
    let auth = Arc::new(AllowListAuthorizer::new(
        HostMode::User,
        Some(current_user().unwrap()),
    ));
    auth.load(ledger.as_ref()).await.unwrap();
    let deps = Arc::new(HostDeps {
        mode: HostMode::User,
        dirs: HostDirs {
            state_dir: state,
            run_dir: run,
            core_store_dir: cores,
        },
        process,
        restart_policy: Arc::new(|| Box::new(BackoffPolicy::new())),
        clock,
        ledger: ledger.clone(),
        repair_index: index,
        reclaim,
        boot_id,
        install_key: key,
        observer: fake.observer(),
        fence: None,
        core: driver,
        core_store: store,
        authorizer: auth,
    });
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(host::serve_with_deps(
        HostMode::User,
        guard,
        deps,
        Some(stop_rx),
        None,
    ));
    let connector = Arc::new(LocalConnector {
        expectation: ServerExpectation {
            exe_dir: dir,
            user: None,
            privileged: false,
        },
    });
    let channel = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(channel) = tonic::transport::Endpoint::from_static("http://localhost")
                .connect_with_connector(ClientIo::new(connector.clone(), endpoint.clone()))
                .await
            {
                break channel;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let mut client = HostServiceClient::new(channel);
    let hello = client
        .handshake(request(Hello {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(hello.role(), Role::Admin);
    assert!(
        hello
            .capabilities
            .iter()
            .any(|capability| capability == etd_contract::capability::LEASE)
    );
    let snapshot = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = client
                .snapshot(request(SnapshotRequest {}))
                .await
                .unwrap()
                .into_inner();
            if snapshot.phase() == HostPhase::Serving {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let mut events = client
        .subscribe(request(SubscribeRequest {
            after: snapshot.cursor.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let instance = uuid::Uuid::new_v4().to_string();
    let receipt = client
        .apply(request(ApplyRequest {
            header: Some(MutationHeader {
                request_id: "apply".into(),
                expected_revision: snapshot.revision,
            }),
            instance_id: instance.clone(),
            spec: Some(NetworkSpec {
                network_name: "test".into(),
                no_tun: true,
                ..Default::default()
            }),
            desired: Desired::Running as i32,
        }))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    // Induce readiness only after the real process bound its listener.
    let (address, pid) = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            for effect in ledger.open_effects(&ScopeFilter::default()).await.unwrap() {
                if effect.kind != EffectKind::Process {
                    continue;
                }
                if let Some(Credential::Process { pid, .. }) = effect
                    .observation
                    .as_ref()
                    .and_then(|observation| observation.credential.as_ref())
                {
                    let (instance, epoch) = effect.scope.generation().unwrap();
                    let generation = ledger.generation(instance, epoch).await.unwrap().unwrap();
                    let address = generation.inputs.management;
                    if tokio::net::TcpStream::connect(address).await.is_ok() {
                        return (address, *pid);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    fake.set_listener(address, pid);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let event = events.message().await.unwrap().unwrap();
            if matches!(event.payload, Some(event::Payload::InstanceStatus(status)) if matches!(status.state(), InstanceState::ReadyBasic | InstanceState::ReadyFull)) { break; }
        }
    }).await.unwrap();
    client
        .set_desired(request(SetDesiredRequest {
            header: Some(MutationHeader {
                request_id: "stop".into(),
                expected_revision: receipt.revision,
            }),
            instance_id: instance,
            desired: Desired::Stopped as i32,
        }))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let event = events.message().await.unwrap().unwrap();
            if matches!(event.payload, Some(event::Payload::InstanceStatus(status)) if status.state() == InstanceState::Stopped) { break; }
        }
    }).await.unwrap();
    fake.clear_listener(address);
    assert!(
        ledger
            .open_effects(&ScopeFilter::all())
            .await
            .unwrap()
            .is_empty()
    );
    drop(events);
    drop(client);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .result
        .unwrap();
}
