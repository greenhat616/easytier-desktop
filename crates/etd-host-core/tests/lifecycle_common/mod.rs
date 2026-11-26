//! Shared harness of the H1 lifecycle acceptance tests: the orchestrator
//! wired to the in-memory ledger, the real reclaim engine over the fake
//! system, a scripted process engine whose "kernel" creates exactly the
//! objects its plan predicted, and an H2 stand-in that plans, commits and
//! reports `Committed` like the contract service does.
//!
//! Time is virtual ([`FakeClock`]); [`Host::until`] advances it in small
//! steps while letting the orchestrator's tasks run.
#![allow(dead_code)]

use async_trait::async_trait;
use etd_contract::v1::{LeaseRelease, StreamLogsRequest};
use etd_contract::{
    Desired, DesiredInstance, ErrorDetail, HostMode, HostPhase, HostSnapshot, InstanceId,
    InstanceState, InstanceStatus, NetworkSpec, QueryKind, QueryResponse, Receipt, RequestId, Role,
};
use etd_core_api::{
    CoreDescriptor, CoreDriver, CoreEndpoint, CoreError, CoreSession, LaunchContext, LaunchPlan,
    ReadinessCondition,
};
use etd_host_core::api::{
    ClientPresence, Command, HostDeps, HostDirs, HostEvent, OrchestratorHandle, Planned,
    orchestrator_channel,
};
use etd_host_core::auth::Authorizer;
use etd_host_core::core_store::{CoreSelector, CoreStore, CoreUsage, StoreError, VerifiedCore};
use etd_host_core::lifecycle::{LifecycleConfig, Orchestrator, RunOutcome};
use etd_host_core::reclaimers::host_reclaimers;
use etd_proc::{
    Command as ProcCommand, KillOutcome, Liveness, ProcessEngine, ProcessError, ProcessHandle,
    ProcessIdentity, ProcessMarker,
};
use etd_sysfx::engine::ReclaimEngineImpl;
use etd_sysfx::*;
use etd_testkit::fakes::{
    clock::FakeClock, core::FakeCoreDriver, ledger::MemoryLedger, process::FakeProcessEngine,
    system::FakeSystem,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};

pub const SHA: [u8; 32] = [0x5a; 32];

pub fn sha_hex() -> String {
    SHA.iter().map(|b| format!("{b:02x}")).collect()
}

/// A unique scratch directory, removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new() -> Self {
        let p = std::env::temp_dir().join(format!("etd-h1-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = make_tree_writable(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_tree_writable(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            make_tree_writable(&entry.path())?;
        } else {
            let mut p = entry.metadata()?.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(false);
            let _ = std::fs::set_permissions(entry.path(), p);
        }
    }
    Ok(())
}

// ----- doubles ---------------------------------------------------------------

/// One kernel in the store, verified against [`SHA`]; usage follows the
/// fake driver's profile and the host form.
pub struct TestCoreStore {
    pub binary: PathBuf,
    pub driver: FakeCoreDriver,
    pub mode: HostMode,
    /// The stored hash no longer matches (replay must refuse).
    pub tampered: AtomicBool,
}

#[async_trait]
impl CoreStore for TestCoreStore {
    async fn resolve(&self, _want: &CoreSelector) -> Result<VerifiedCore, StoreError> {
        let descriptor = self.driver.descriptor();
        let usage = match (self.driver.profile_of(), self.mode) {
            (Some(p), _) => CoreUsage::Profiled(p),
            (None, HostMode::User) => CoreUsage::LifecycleOnly,
            (None, _) => {
                return Err(StoreError::NoProfile {
                    version: descriptor.version,
                });
            }
        };
        let mut sha256 = SHA;
        if self.tampered.load(Ordering::SeqCst) {
            sha256[0] ^= 1;
        }
        Ok(VerifiedCore {
            binary: self.binary.clone(),
            descriptor,
            sha256,
            usage,
        })
    }
    async fn list(&self) -> Result<Vec<etd_contract::v1::CoreEntry>, StoreError> {
        Ok(Vec::new())
    }
    async fn remove(&self, _version: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemIndex(pub Mutex<Option<RepairIndex>>);

impl RepairIndexStore for MemIndex {
    fn load(&self) -> Result<Option<RepairIndex>, LedgerError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn store(&self, index: &RepairIndex) -> Result<(), LedgerError> {
        *self.0.lock().unwrap() = Some(index.clone());
        Ok(())
    }
}

pub struct AllowAll;

impl Authorizer for AllowAll {
    fn role_of(&self, _peer: &etd_ipc::PeerIdentity) -> Option<Role> {
        Some(Role::Admin)
    }
}

/// Plan shapes the fake driver does not produce on its own.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanExtras {
    /// Windows: the two program firewall rules named after the kernel
    /// binary (core-binary scope), which upstream deletes and recreates on
    /// every start.
    pub program_rules: bool,
    /// macOS: a system-assigned interface name (utun), found via the
    /// kernel's pid, with the routes recorded via that interface.
    pub assigned_name: bool,
    /// Windows: the driver services every kernel shares (product scope),
    /// which upstream reports without a creation credential.
    pub shared_drivers: bool,
}

/// Keys of the shared driver services (as upstream names them).
pub fn shared_driver_keys() -> Vec<ObjectKey> {
    ["wintun", "WinDivert"]
        .iter()
        .map(|n| ObjectKey::Service { name: (*n).into() })
        .collect()
}

/// Group of the program firewall rules (as upstream names it).
pub const FIREWALL_GROUP: &str = "EasyTier";

/// Keys of the program firewall rules of a kernel binary.
pub fn program_rule_keys(binary: &Path) -> Vec<ObjectKey> {
    ["Inbound", "Outbound"]
        .iter()
        .map(|d| ObjectKey::Rule {
            name: format!("EasyTier {} ({d})", binary.display()),
            group: Some(FIREWALL_GROUP.into()),
        })
        .collect()
}

/// [`FakeCoreDriver`] plus [`PlanExtras`]; remembers the plans it made for
/// the simulated kernel.
pub struct TestDriver {
    pub inner: FakeCoreDriver,
    pub extras: Mutex<PlanExtras>,
    plans: Mutex<HashMap<PathBuf, LaunchPlan>>,
}

impl TestDriver {
    pub fn plan_for(&self, runtime_dir: &Path) -> Option<LaunchPlan> {
        self.plans.lock().unwrap().get(runtime_dir).cloned()
    }
}

#[async_trait]
impl CoreDriver for TestDriver {
    async fn identify(&self, binary: &Path) -> Result<CoreDescriptor, CoreError> {
        self.inner.identify(binary).await
    }
    fn profile(&self, core: &CoreDescriptor) -> Option<etd_core_api::AdapterProfile> {
        self.inner.profile(core)
    }
    fn plan_launch(&self, ctx: &LaunchContext) -> Result<LaunchPlan, CoreError> {
        let mut plan = self.inner.plan_launch(ctx)?;
        let extras = *self.extras.lock().unwrap();
        if !ctx.inputs.spec.no_tun {
            if extras.assigned_name {
                for e in &mut plan.effects {
                    if let ObjectKey::Interface { name, .. } = &mut e.key {
                        *name = None;
                    }
                }
                plan.effects.push(EffectIntent {
                    scope: EffectScope::Instance {
                        instance: ctx.instance.clone(),
                        epoch: ctx.epoch,
                    },
                    kind: EffectKind::Route,
                    key: ObjectKey::RoutesVia { interface: None },
                    undo: Undo::EnsureAbsent,
                    persistence: Persistence::WithProcess,
                });
                plan.readiness.condition = ReadinessCondition::OwnedInterfaceAddress;
            }
            if extras.program_rules {
                let sha256: String = ctx
                    .inputs
                    .core
                    .sha256
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                for key in program_rule_keys(&ctx.inputs.core.binary) {
                    plan.effects.push(EffectIntent {
                        scope: EffectScope::CoreBinary {
                            sha256: sha256.clone(),
                        },
                        kind: EffectKind::WinProgramFirewallRule,
                        key,
                        undo: Undo::EnsureAbsent,
                        persistence: Persistence::Persistent,
                    });
                }
            }
        }
        if extras.shared_drivers {
            for key in shared_driver_keys() {
                plan.effects.push(EffectIntent {
                    scope: EffectScope::Product,
                    kind: EffectKind::Driver,
                    key,
                    undo: Undo::EnsureAbsent,
                    persistence: Persistence::Persistent,
                });
            }
        }
        self.plans
            .lock()
            .unwrap()
            .insert(ctx.inputs.runtime_dir.clone(), plan.clone());
        Ok(plan)
    }
    async fn attach(
        &self,
        ep: &CoreEndpoint,
        core: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError> {
        self.inner.attach(ep, core).await
    }
}

/// How the simulated kernel behaves once spawned.
#[derive(Debug, Clone, Copy)]
pub struct KernelBehaviour {
    /// Create the predicted objects (interfaces, rules).
    pub create_objects: bool,
    /// Give its interfaces an address (basic readiness).
    pub address: bool,
    /// Listen on its management address.
    pub listen: bool,
    /// Someone else (this pid) holds the management address instead.
    pub squatter: Option<u32>,
    /// The created objects show no creation credential.
    pub no_credentials: bool,
    /// A third party adds a second rule of the same name right after the
    /// kernel recreated each program firewall rule.
    pub duplicate_program_rules: bool,
}

impl Default for KernelBehaviour {
    fn default() -> Self {
        Self {
            create_objects: true,
            address: true,
            listen: true,
            squatter: None,
            no_credentials: false,
            duplicate_program_rules: false,
        }
    }
}

/// The scripted process engine plus what a kernel does to the system when
/// it starts: the objects its plan predicted, held by its pid.
pub struct KernelSim {
    pub engine: FakeProcessEngine,
    pub sys: FakeSystem,
    pub driver: Arc<TestDriver>,
    pub behaviour: Mutex<KernelBehaviour>,
    pub spawned: Mutex<Vec<(ProcessIdentity, ProcCommand)>>,
    /// The system's objects as each spawn saw them.
    pub objects_at_spawn: Mutex<Vec<Vec<etd_testkit::fakes::system::FakeObject>>>,
    /// Injected into the system right after the next spawn (after the
    /// host's checks before it).
    pub faults_after_spawn: Mutex<Vec<etd_testkit::fakes::system::Fault>>,
}

impl KernelSim {
    /// Whether the host ever tried to kill this kernel.
    pub fn calls_kill(&self, id: &ProcessIdentity) -> bool {
        use etd_testkit::fakes::process::Call;
        self.engine.calls().iter().any(
            |c| matches!(c, Call::KillVerified(k) | Call::Kill(k) | Call::Stop(k, _) if k == id),
        )
    }
}

#[async_trait]
impl ProcessEngine for KernelSim {
    async fn spawn(&self, cmd: ProcCommand) -> Result<Box<dyn ProcessHandle>, ProcessError> {
        self.objects_at_spawn
            .lock()
            .unwrap()
            .push(self.sys.objects());
        let handle = self.engine.spawn(cmd.clone()).await?;
        let id = handle.identity().clone();
        self.spawned.lock().unwrap().push((id.clone(), cmd.clone()));
        let b = *self.behaviour.lock().unwrap();
        if let Some(plan) = cmd.cwd.as_deref().and_then(|d| self.driver.plan_for(d)) {
            if b.create_objects {
                for intent in &plan.effects {
                    // Routes via a system-assigned interface go with it.
                    if intent.key == (ObjectKey::RoutesVia { interface: None }) {
                        continue;
                    }
                    // Upstream deletes every rule of that name, then adds
                    // its own (a fresh GUID on every start).
                    if intent.kind == EffectKind::WinProgramFirewallRule {
                        while self.sys.vanish(intent.kind, &intent.key) {}
                    }
                    // A driver service already registered is used as it is.
                    if intent.kind == EffectKind::Driver
                        && self.sys.find(intent.kind, &intent.key).is_some()
                    {
                        continue;
                    }
                    let obs = self.sys.apply_intent_with_pid(intent, Some(id.pid));
                    if b.duplicate_program_rules
                        && intent.kind == EffectKind::WinProgramFirewallRule
                    {
                        self.sys.create_foreign(intent.kind, intent.key.clone());
                    }
                    if (b.no_credentials || intent.kind == EffectKind::Driver)
                        && let Some(mut o) = self.sys.find(intent.kind, &intent.key)
                    {
                        self.sys.vanish(intent.kind, &intent.key);
                        o.credential = None;
                        self.sys.insert(o);
                    }
                    if b.address && matches!(intent.key, ObjectKey::Interface { .. }) {
                        self.sys.set_addresses(
                            intent.kind,
                            obs.key.as_ref().unwrap_or(&intent.key),
                            vec![(IpAddr::V4(Ipv4Addr::new(10, 144, 0, 1)), 24)],
                        );
                    }
                }
            }
            if let Some(pid) = b.squatter {
                self.sys.set_listener(plan.endpoint.0, pid);
            } else if b.listen {
                self.sys.set_listener(plan.endpoint.0, id.pid);
            }
        }
        for fault in self.faults_after_spawn.lock().unwrap().drain(..) {
            self.sys.inject(fault);
        }
        Ok(handle)
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

/// The in-memory ledger with switchable faults and a write counter.
pub struct TestLedger {
    pub inner: Arc<MemoryLedger>,
    /// Committed (once) right after the next `generation()` read of this
    /// instance: a concurrent mutation landing just before a launch.
    pub on_generation_read: Mutex<Option<(InstanceId, Change)>>,
    /// `desired()` fails with this error.
    pub desired_error: Mutex<Option<LedgerError>>,
    /// Every write fails as unavailable.
    pub writes_fail: AtomicBool,
    /// The next N `begin_epoch` calls fail (storage unavailable).
    pub fail_begin: AtomicUsize,
    /// The next N `generation()` reads of this instance fail.
    pub fail_generation: Mutex<Option<(InstanceId, usize)>>,
    pub writes: AtomicU64,
}

impl TestLedger {
    fn write(&self) -> Result<(), LedgerError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.writes_fail.load(Ordering::SeqCst) {
            return Err(LedgerError::Unavailable(StorageFault::DiskFull));
        }
        Ok(())
    }
}

#[async_trait]
impl Ledger for TestLedger {
    async fn commit(
        &self,
        expected: etd_contract::Revision,
        change: ChangeSet,
    ) -> Result<Receipt, LedgerError> {
        self.write()?;
        self.inner.commit(expected, change).await
    }
    async fn request_status(&self, r: &RequestRecord) -> Result<RequestStatus, LedgerError> {
        self.inner.request_status(r).await
    }
    async fn receipt(&self, r: &RequestId) -> Result<Option<Receipt>, LedgerError> {
        self.inner.receipt(r).await
    }
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError> {
        self.inner.pending_tickets().await
    }
    async fn complete_ticket(&self, t: &str) -> Result<(), LedgerError> {
        self.write()?;
        self.inner.complete_ticket(t).await
    }
    async fn desired(&self) -> Result<(etd_contract::Revision, Vec<DesiredInstance>), LedgerError> {
        if let Some(e) = self.desired_error.lock().unwrap().clone() {
            return Err(e);
        }
        self.inner.desired().await
    }
    async fn spec_revision(&self, i: &InstanceId) -> Result<etd_contract::Revision, LedgerError> {
        self.inner.spec_revision(i).await
    }
    async fn settings(&self) -> Result<HostSettings, LedgerError> {
        self.inner.settings().await
    }
    async fn claims(&self) -> Result<Vec<ClaimHold>, LedgerError> {
        self.inner.claims().await
    }
    async fn next_epoch(&self, i: &InstanceId) -> Result<Epoch, LedgerError> {
        self.inner.next_epoch(i).await
    }
    async fn begin_epoch(&self, plan: GenerationPlan) -> Result<Vec<Effect>, LedgerError> {
        self.write()?;
        if self
            .fail_begin
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(LedgerError::Unavailable(StorageFault::DiskFull));
        }
        self.inner.begin_epoch(plan).await
    }
    async fn generation(
        &self,
        i: &InstanceId,
        e: Epoch,
    ) -> Result<Option<StoredGeneration>, LedgerError> {
        {
            let mut f = self.fail_generation.lock().unwrap();
            if let Some((id, n)) = f.as_mut()
                && id == i
                && *n > 0
            {
                *n -= 1;
                return Err(LedgerError::Unavailable(StorageFault::DiskFull));
            }
        }
        let read = self.inner.generation(i, e).await;
        let hook = {
            let mut h = self.on_generation_read.lock().unwrap();
            match h.as_ref() {
                Some((id, _)) if id == i => h.take(),
                _ => None,
            }
        };
        if let Some((_, change)) = hook {
            let revision = self.inner.desired().await?.0;
            self.inner
                .commit(
                    revision,
                    ChangeSet {
                        request: RequestRecord {
                            request_id: RequestId(format!("concurrent-{}", uuid::Uuid::new_v4())),
                            caller: "test".into(),
                            digest: RequestDigest([9; 32]),
                        },
                        changes: vec![change],
                        generations: Vec::new(),
                    },
                )
                .await?;
        }
        read
    }
    async fn record(&self, intent: EffectIntent) -> Result<Effect, LedgerError> {
        self.write()?;
        self.inner.record(intent).await
    }
    async fn transition(
        &self,
        id: &EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError> {
        self.write()?;
        self.inner.transition(id, to, obs).await
    }
    async fn record_failure(&self, id: &EffectId, error: &str) -> Result<u32, LedgerError> {
        self.write()?;
        self.inner.record_failure(id, error).await
    }
    async fn open_effects(&self, f: &ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        self.inner.open_effects(f).await
    }
    async fn compact(&self) -> Result<usize, LedgerError> {
        self.inner.compact().await
    }
}

// ----- the world -----------------------------------------------------------

/// Everything that survives a host restart: the machine, the ledger, the
/// kernel store and the running (fake) processes.
pub struct World {
    pub scratch: Scratch,
    pub clock: FakeClock,
    pub sys: FakeSystem,
    pub engine: FakeProcessEngine,
    pub driver: FakeCoreDriver,
    /// What the host plans with: `driver` plus [`PlanExtras`].
    pub test_driver: Arc<TestDriver>,
    pub kernel: Arc<KernelSim>,
    pub ledger: Arc<TestLedger>,
    pub index: Arc<MemIndex>,
    pub store: Arc<TestCoreStore>,
    pub dirs: HostDirs,
    pub mode: HostMode,
    pub fence: bool,
    pub config: LifecycleConfig,
}

impl World {
    /// A privileged service host with a fence.
    pub fn new() -> Self {
        Self::with_mode(HostMode::Service, true)
    }

    pub fn with_mode(mode: HostMode, fence: bool) -> Self {
        let scratch = Scratch::new();
        let dirs = HostDirs {
            state_dir: scratch.0.join("state"),
            run_dir: scratch.0.join("run"),
            core_store_dir: scratch.0.join("store"),
        };
        let bin_dir = dirs.core_store_dir.join(sha_hex());
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&dirs.run_dir).unwrap();
        std::fs::create_dir_all(&dirs.state_dir).unwrap();
        let binary = bin_dir.join("easytier-core");
        std::fs::write(&binary, b"fake kernel").unwrap();
        // The store hands out canonical paths, like the planner records.
        let dirs = HostDirs {
            state_dir: std::fs::canonicalize(&dirs.state_dir).unwrap(),
            run_dir: std::fs::canonicalize(&dirs.run_dir).unwrap(),
            core_store_dir: std::fs::canonicalize(&dirs.core_store_dir).unwrap(),
        };
        let binary = std::fs::canonicalize(&binary).unwrap();
        let clock = FakeClock::new(jiff::Timestamp::from_second(1_800_000_000).unwrap());
        let sys = FakeSystem::new();
        let engine = FakeProcessEngine::new(clock.clone());
        let driver = FakeCoreDriver::new();
        let test_driver = Arc::new(TestDriver {
            inner: driver.clone(),
            extras: Mutex::new(PlanExtras::default()),
            plans: Mutex::new(HashMap::new()),
        });
        let kernel = Arc::new(KernelSim {
            engine: engine.clone(),
            sys: sys.clone(),
            driver: test_driver.clone(),
            behaviour: Mutex::new(KernelBehaviour::default()),
            spawned: Mutex::new(Vec::new()),
            objects_at_spawn: Mutex::new(Vec::new()),
            faults_after_spawn: Mutex::new(Vec::new()),
        });
        let ledger = Arc::new(TestLedger {
            inner: Arc::new(MemoryLedger::new(sys.boot())),
            on_generation_read: Mutex::new(None),
            desired_error: Mutex::new(None),
            fail_begin: AtomicUsize::new(0),
            fail_generation: Mutex::new(None),
            writes_fail: AtomicBool::new(false),
            writes: AtomicU64::new(0),
        });
        let store = Arc::new(TestCoreStore {
            binary,
            driver: driver.clone(),
            mode,
            tampered: AtomicBool::new(false),
        });
        let config = LifecycleConfig {
            stop_grace: Duration::from_secs(2),
            readiness_tick: Duration::from_millis(100),
            start_timeout: Duration::from_secs(10),
            full_ready_timeout: Duration::from_secs(1),
            reclaim_retry: Duration::from_millis(500),
            log_lines: 100,
            lease_grace: Duration::from_secs(30),
            fence_recheck: Duration::from_secs(30),
            fence_retry: Duration::from_secs(2),
            fence_unverifiable_retry: Duration::from_secs(10),
        };
        Self {
            scratch,
            clock,
            sys,
            engine,
            driver,
            test_driver,
            kernel,
            ledger,
            index: Arc::new(MemIndex::default()),
            store,
            dirs,
            mode,
            fence,
            config,
        }
    }

    pub fn fence_kind() -> EffectKind {
        EffectKind::LinuxFenceRule
    }

    pub fn reclaim_engine(&self) -> Arc<dyn ReclaimEngine> {
        let mut reclaimers: Vec<Arc<dyn Reclaimer>> = self.sys.reclaimers_for(
            &EffectKind::ALL
                .iter()
                .copied()
                .filter(|k| !matches!(k, EffectKind::Process | EffectKind::RuntimeDir))
                .collect::<Vec<_>>(),
        );
        reclaimers.extend(host_reclaimers(
            self.kernel.clone(),
            Arc::new(self.clock.clone()),
            self.dirs.run_dir.clone(),
        ));
        Arc::new(ReclaimEngineImpl::new(ReclaimDeps {
            ledger: self.ledger.clone(),
            reclaimers,
            sweeper: self.sys.sweeper(),
            boot_id: self.sys.boot_id_source(),
            repair_index: self.index.clone(),
        }))
    }

    pub fn deps(&self) -> Arc<HostDeps> {
        Arc::new(HostDeps {
            mode: self.mode,
            dirs: self.dirs.clone(),
            process: self.kernel.clone(),
            restart_policy: Arc::new(|| Box::new(etd_proc::backoff::BackoffPolicy::new())),
            clock: Arc::new(self.clock.clone()),
            ledger: self.ledger.clone(),
            repair_index: self.index.clone(),
            reclaim: self.reclaim_engine(),
            boot_id: self.sys.boot_id_source(),
            install_key: InstallKey([7; 32]),
            observer: self.sys.observer(),
            fence: self.fence.then(|| self.sys.fence(Self::fence_kind())),
            core: self.test_driver.clone() as Arc<dyn CoreDriver>,
            core_store: self.store.clone(),
            authorizer: Arc::new(AllowAll),
        })
    }

    /// Start a host on this world.
    pub fn start(&self) -> Host<'_> {
        let (handle, port) = orchestrator_channel(1024, Default::default());
        let events = handle.subscribe();
        let orchestrator = Orchestrator::with_config(self.deps(), port, self.config.clone());
        // The host gets its own runtime, so a crash can drop every task of
        // it (orchestrator and supervisors) without any cleanup.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let task = rt.spawn(orchestrator.run());
        Host {
            world: self,
            handle,
            events,
            log: Vec::new(),
            task: Some(task),
            rt: Some(rt),
            requests: 0,
            hold_notify: false,
            held: Vec::new(),
        }
    }

    pub fn interface_key(&self, instance: &str) -> ObjectKey {
        ObjectKey::Interface {
            name: Some(naming::interface_name(
                &InstallKey([7; 32]),
                &InstanceId::from(instance),
            )),
            guid: None,
        }
    }

    /// The latest kernel spawned for this instance.
    pub fn kernel_of(&self, instance: &str) -> ProcessIdentity {
        let dir = self.dirs.run_dir.join(instance);
        self.kernel
            .spawned
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(_, cmd)| cmd.cwd.as_ref().is_some_and(|c| c.starts_with(&dir)))
            .map(|(id, _)| id.clone())
            .expect("a kernel of this instance was spawned")
    }

    /// Power loss while the host was down: the machine reboots, every
    /// process is gone, volatile objects vanish, the boot id changes.
    pub fn power_loss(&self) {
        for id in self.spawned() {
            self.engine.exit(
                &id,
                etd_proc::Exit {
                    code: None,
                    signal: None,
                    cause: etd_proc::ExitCause::Exited,
                },
            );
        }
        let boot = self.sys.reboot();
        self.ledger.inner.set_boot_id(boot);
    }

    pub fn extras(&self, extras: PlanExtras) {
        *self.test_driver.extras.lock().unwrap() = extras;
    }

    pub fn behave(&self, b: KernelBehaviour) {
        *self.kernel.behaviour.lock().unwrap() = b;
    }

    /// Identities of every kernel spawned so far, oldest first.
    pub fn spawned(&self) -> Vec<ProcessIdentity> {
        self.kernel
            .spawned
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn last_kernel(&self) -> ProcessIdentity {
        self.spawned()
            .last()
            .cloned()
            .expect("a kernel was spawned")
    }

    pub async fn open_records(&self, instance: &str) -> Vec<Effect> {
        self.ledger
            .inner
            .open_effects(&ScopeFilter::instance(instance.into()))
            .await
            .unwrap()
    }
}

pub fn spec(name: &str) -> NetworkSpec {
    NetworkSpec {
        network_name: name.into(),
        network_secret: Some("s3cret".into()),
        ..Default::default()
    }
}

// ----- the host and the H2 stand-in ----------------------------------------

pub struct Host<'w> {
    pub world: &'w World,
    pub handle: OrchestratorHandle,
    pub events: broadcast::Receiver<HostEvent>,
    /// Every event received so far.
    pub log: Vec<HostEvent>,
    task: Option<tokio::task::JoinHandle<RunOutcome>>,
    rt: Option<tokio::runtime::Runtime>,
    requests: u64,
    hold_notify: bool,
    held: Vec<Receipt>,
}

impl Host<'_> {
    fn drain(&mut self) {
        while let Ok(e) = self.events.try_recv() {
            self.log.push(e);
        }
    }

    /// Collect the events received so far into [`Host::log`].
    pub fn settle_sync(&mut self) {
        self.drain();
    }

    /// Let spawned tasks run (real time) without moving the fake clock.
    pub async fn settle(&mut self) {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
        self.drain();
    }

    /// Advance virtual time in `step`s until `pred` holds; panics after
    /// `limit` of virtual time.
    pub async fn until_by(
        &mut self,
        what: &str,
        step: Duration,
        limit: Duration,
        mut pred: impl FnMut(&mut Self) -> bool,
    ) {
        let mut spent = Duration::ZERO;
        loop {
            // Let the host finish what it is doing before time moves on: a
            // loaded machine must not see virtual timeouts fire early.
            for _ in 0..50 {
                let seen = self.log.len();
                self.settle().await;
                if self.log.len() == seen {
                    break;
                }
            }
            if pred(self) {
                return;
            }
            assert!(
                spent < limit,
                "timed out waiting for {what}; last statuses: {:#?}",
                self.statuses()
            );
            self.world.clock.advance(step);
            spent += step;
        }
    }

    /// Let `total` of virtual time pass in `step`s.
    pub async fn idle(&mut self, step: Duration, total: Duration) {
        let mut spent = Duration::ZERO;
        while spent < total {
            self.world.clock.advance(step);
            spent += step;
            self.settle().await;
        }
    }

    pub async fn until(&mut self, what: &str, pred: impl FnMut(&mut Self) -> bool) {
        self.until_by(
            what,
            Duration::from_millis(100),
            Duration::from_secs(120),
            pred,
        )
        .await;
    }

    /// Real-time wait (the fake clock stands still).
    pub async fn until_still(&mut self, what: &str, mut pred: impl FnMut(&mut Self) -> bool) {
        for _ in 0..2000 {
            self.settle().await;
            if pred(self) {
                return;
            }
        }
        panic!(
            "timed out waiting for {what}; statuses {:#?}",
            self.statuses()
        );
    }

    pub fn snapshot(&self) -> HostSnapshot {
        self.handle.view().snapshot.clone()
    }

    pub fn phase(&self) -> HostPhase {
        self.snapshot().phase()
    }

    pub fn statuses(&self) -> Vec<InstanceStatus> {
        self.snapshot()
            .instances
            .into_iter()
            .filter_map(|v| v.status)
            .collect()
    }

    pub fn status(&self, instance: &str) -> Option<InstanceStatus> {
        self.statuses()
            .into_iter()
            .find(|s| s.instance_id == instance)
    }

    pub fn state(&self, instance: &str) -> InstanceState {
        self.status(instance)
            .map_or(InstanceState::Unspecified, |s| s.state())
    }

    pub async fn wait_state(&mut self, instance: &str, state: InstanceState) {
        let what = format!("{instance} in {state:?}");
        self.until(&what, |h| h.state(instance) == state).await;
    }

    pub async fn wait_serving(&mut self) {
        self.until_still("serving", |h| h.phase() == HostPhase::Serving)
            .await;
    }

    /// The states an instance went through, from the event log.
    pub fn history(&mut self, instance: &str) -> Vec<InstanceState> {
        self.drain();
        let mut out: Vec<InstanceState> = Vec::new();
        for e in &self.log {
            if let etd_contract::v1::event::Payload::InstanceStatus(s) = &e.payload
                && s.instance_id == instance
                && out.last() != Some(&s.state())
            {
                out.push(s.state());
            }
        }
        out
    }

    /// Every state-machine edge the instances took, from the event log
    /// (the first status of an instance leaves `UNSPECIFIED`).
    pub fn edges(&mut self) -> std::collections::BTreeSet<(InstanceState, InstanceState)> {
        self.drain();
        let mut last: std::collections::BTreeMap<String, InstanceState> = Default::default();
        let mut out = std::collections::BTreeSet::new();
        for e in &self.log {
            if let etd_contract::v1::event::Payload::InstanceStatus(s) = &e.payload {
                let from = last
                    .insert(s.instance_id.clone(), s.state())
                    .unwrap_or(InstanceState::Unspecified);
                if from != s.state() {
                    out.insert((from, s.state()));
                }
            }
        }
        out
    }

    pub fn events_seq_gap_free(&mut self) -> bool {
        self.drain();
        self.log.windows(2).all(|w| w[1].seq == w[0].seq + 1)
    }

    // ----- H2 stand-in ---------------------------------------------------

    pub async fn plan(
        &self,
        instance: &str,
        spec: Option<NetworkSpec>,
        start: bool,
    ) -> Result<Planned, ErrorDetail> {
        let (tx, rx) = oneshot::channel();
        self.handle
            .send(Command::Plan {
                instance: instance.into(),
                spec: spec.map(Box::new),
                start,
                reply: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }

    fn request(&mut self) -> RequestRecord {
        self.requests += 1;
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&self.requests.to_le_bytes());
        RequestRecord {
            request_id: RequestId(format!("req-{}", uuid::Uuid::new_v4())),
            caller: "test".into(),
            digest: RequestDigest(digest),
        }
    }

    async fn commit(
        &mut self,
        planned: Planned,
        changes: Vec<Change>,
    ) -> Result<Receipt, LedgerError> {
        let change = ChangeSet {
            request: self.request(),
            changes,
            generations: planned.generation.into_iter().collect(),
        };
        let receipt = self.world.ledger.commit(planned.revision, change).await?;
        if self.hold_notify {
            self.held.push(receipt.clone());
            return Ok(receipt);
        }
        self.handle
            .send(Command::Committed {
                receipt: receipt.clone(),
            })
            .await
            .unwrap();
        Ok(receipt)
    }

    /// Commit without telling the host yet (`notify` sends them): lets a
    /// test change the world between a commit and its execution.
    pub fn hold(&mut self) {
        self.hold_notify = true;
    }

    pub async fn notify(&mut self) {
        self.hold_notify = false;
        for receipt in std::mem::take(&mut self.held) {
            self.handle
                .send(Command::Committed { receipt })
                .await
                .unwrap();
        }
    }

    /// Apply: put the configuration with a desired state.
    pub async fn apply(&mut self, instance: &str, spec: NetworkSpec, desired: Desired) -> Receipt {
        let start = desired == Desired::Running;
        let planned = self
            .plan(instance, Some(spec.clone()), start)
            .await
            .unwrap_or_else(|e| panic!("plan of {instance} refused: {e:?}"));
        let committed_spec = planned
            .generation
            .as_ref()
            .map_or(spec, |g| g.inputs.spec.clone());
        let mut d = DesiredInstance {
            instance_id: instance.into(),
            spec: Some(committed_spec),
            ..Default::default()
        };
        d.set_desired(desired);
        let claims = planned.claims.clone();
        self.commit(
            planned,
            vec![Change::PutInstance {
                instance: Box::new(d),
                claims,
            }],
        )
        .await
        .unwrap()
    }

    pub async fn set_desired(
        &mut self,
        instance: &str,
        desired: Desired,
    ) -> Result<Receipt, LedgerError> {
        let planned = self
            .plan(instance, None, desired == Desired::Running)
            .await
            .unwrap();
        self.commit(
            planned,
            vec![Change::SetDesired {
                instance: instance.into(),
                desired,
            }],
        )
        .await
    }

    pub async fn retry_start(&mut self, instance: &str) -> Receipt {
        let planned = self.plan(instance, None, true).await.unwrap();
        self.commit(planned, vec![Change::RetryStart(instance.into())])
            .await
            .unwrap()
    }

    pub async fn retry_reclaim(&mut self, instance: &str) -> Receipt {
        let revision = self.world.ledger.inner.desired().await.unwrap().0;
        let planned = Planned {
            claims: Vec::new(),
            generation: None,
            revision,
        };
        self.commit(planned, vec![Change::RetryReclaim(instance.into())])
            .await
            .unwrap()
    }

    pub async fn purge(&mut self) -> Receipt {
        let revision = self.world.ledger.inner.desired().await.unwrap().0;
        let planned = Planned {
            claims: Vec::new(),
            generation: None,
            revision,
        };
        self.commit(planned, vec![Change::PurgeAll]).await.unwrap()
    }

    pub async fn remove(&mut self, instance: &str) -> Receipt {
        let revision = self.world.ledger.inner.desired().await.unwrap().0;
        let planned = Planned {
            claims: Vec::new(),
            generation: None,
            revision,
        };
        self.commit(planned, vec![Change::RemoveInstance(instance.into())])
            .await
            .unwrap()
    }

    pub async fn cut(&self, instance: &str) -> Result<(), ErrorDetail> {
        let (tx, rx) = oneshot::channel();
        self.handle
            .send(Command::Cut {
                instance: instance.into(),
                reply: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }

    pub async fn query(&self, instance: &str) -> Result<QueryResponse, ErrorDetail> {
        let (tx, rx) = oneshot::channel();
        self.handle
            .send(Command::Query {
                instance: instance.into(),
                kind: QueryKind::Nodes,
                reply: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }

    pub async fn leases(&self, lease_holders: usize) {
        self.handle
            .send(Command::Clients(ClientPresence {
                connections: lease_holders,
                subscribers: lease_holders,
                lease_holders,
            }))
            .await
            .unwrap();
    }

    /// Whether the orchestrator has returned, and how.
    pub async fn finished(&mut self) -> Option<RunOutcome> {
        if self.task.as_ref().is_some_and(|t| t.is_finished()) {
            return Some(self.task.take().unwrap().await.unwrap());
        }
        None
    }

    pub async fn clients(&self, subscribers: usize) {
        self.handle
            .send(Command::Clients(ClientPresence {
                connections: subscribers,
                subscribers,
                lease_holders: 0,
            }))
            .await
            .unwrap();
    }

    pub async fn logs(&self, instance: &str) -> Result<etd_host_core::api::LogStream, ErrorDetail> {
        let (tx, rx) = oneshot::channel();
        self.handle
            .send(Command::Logs {
                request: StreamLogsRequest {
                    instance_id: instance.into(),
                    tail_lines: 100,
                    follow: false,
                },
                reply: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }

    pub async fn release_lease(&self, release: LeaseRelease) -> bool {
        let (tx, rx) = oneshot::channel();
        self.handle
            .send(Command::ReleaseLease {
                instances: release,
                reply: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap().unwrap()
    }

    /// Shut the host down; returns once it has stopped and reclaimed.
    pub async fn shutdown(mut self) -> RunOutcome {
        let (tx, rx) = oneshot::channel();
        self.handle
            .send(Command::Shutdown { reply: tx })
            .await
            .unwrap();
        let mut rx = rx;
        for _ in 0..100_000 {
            self.settle().await;
            if let Ok(()) = rx.try_recv() {
                break;
            }
            self.world.clock.advance(Duration::from_millis(100));
        }
        self.task.take().unwrap().await.unwrap()
    }

    /// The host process dies: every task is dropped, nothing is cleaned up.
    pub fn crash(mut self) {
        self.task.take();
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl Drop for Host<'_> {
    fn drop(&mut self) {
        self.task.take();
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}
