//! Shared harness of the reclaim acceptance tests (R1): a fake system, the
//! in-memory ledger, a repair index and helpers to build generations.
#![allow(dead_code)]

use etd_contract::{Desired, InstanceId, NetworkSpec};
use etd_sysfx::{engine::ReclaimEngineImpl, naming, *};
use etd_testkit::{
    conformance::ledger::{changes, put},
    fakes::{ledger::MemoryLedger, system::FakeSystem},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

pub const CORE_SHA: [u8; 32] = [0xab; 32];

pub fn core_hex() -> String {
    CORE_SHA.iter().map(|b| format!("{b:02x}")).collect()
}

/// In-memory repair index.
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

/// Ledger wrapper that panics with the fake system's crash marker at the
/// n-th write (transition / record_failure), before or after it lands.
pub struct CrashLedger {
    pub inner: Arc<MemoryLedger>,
    writes: AtomicU64,
    crash: Mutex<Option<(u64, bool)>>,
}

impl CrashLedger {
    pub fn new(inner: Arc<MemoryLedger>) -> Self {
        Self {
            inner,
            writes: AtomicU64::new(0),
            crash: Mutex::new(None),
        }
    }
    pub fn crash_at(&self, write: u64, after: bool) {
        *self.crash.lock().unwrap() = Some((write, after));
    }
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::SeqCst)
    }
    /// Returns whether to crash after the write.
    fn enter(&self) -> bool {
        let n = self.writes.fetch_add(1, Ordering::SeqCst);
        let hit = {
            let mut c = self.crash.lock().unwrap();
            match *c {
                Some((at, after)) if at == n => {
                    *c = None;
                    Some(after)
                }
                _ => None,
            }
        };
        match hit {
            Some(false) => panic!("{}", etd_testkit::fakes::system::CRASH),
            Some(true) => true,
            None => false,
        }
    }
}

#[async_trait::async_trait]
impl Ledger for CrashLedger {
    async fn commit(
        &self,
        expected: etd_contract::Revision,
        change: ChangeSet,
    ) -> Result<etd_contract::Receipt, LedgerError> {
        self.inner.commit(expected, change).await
    }
    async fn request_status(&self, r: &RequestRecord) -> Result<RequestStatus, LedgerError> {
        self.inner.request_status(r).await
    }
    async fn receipt(
        &self,
        r: &etd_contract::RequestId,
    ) -> Result<Option<etd_contract::Receipt>, LedgerError> {
        self.inner.receipt(r).await
    }
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError> {
        self.inner.pending_tickets().await
    }
    async fn complete_ticket(&self, t: &str) -> Result<(), LedgerError> {
        self.inner.complete_ticket(t).await
    }
    async fn desired(
        &self,
    ) -> Result<(etd_contract::Revision, Vec<etd_contract::DesiredInstance>), LedgerError> {
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
        self.inner.begin_epoch(plan).await
    }
    async fn generation(
        &self,
        i: &InstanceId,
        e: Epoch,
    ) -> Result<Option<StoredGeneration>, LedgerError> {
        self.inner.generation(i, e).await
    }
    async fn record(&self, intent: EffectIntent) -> Result<Effect, LedgerError> {
        self.inner.record(intent).await
    }
    async fn transition(
        &self,
        id: &EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError> {
        let after = self.enter();
        let r = self.inner.transition(id, to, obs).await;
        if after {
            panic!("{}", etd_testkit::fakes::system::CRASH);
        }
        r
    }
    async fn record_failure(&self, id: &EffectId, error: &str) -> Result<u32, LedgerError> {
        let after = self.enter();
        let r = self.inner.record_failure(id, error).await;
        if after {
            panic!("{}", etd_testkit::fakes::system::CRASH);
        }
        r
    }
    async fn open_effects(&self, f: &ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        self.inner.open_effects(f).await
    }
    async fn compact(&self) -> Result<usize, LedgerError> {
        self.inner.compact().await
    }
}

/// How a planned effect is left before the reclaim run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Object created, credential read back (`Applied`).
    Applied,
    /// Object created, record still `Planned` (crash before read-back).
    PlannedPresent,
    /// Nothing created, record `Planned`.
    PlannedAbsent,
}

pub struct World {
    pub sys: FakeSystem,
    pub memory: Arc<MemoryLedger>,
    pub ledger: Arc<dyn Ledger>,
    pub index: Arc<MemIndex>,
    pub key: InstallKey,
}

impl World {
    pub fn new() -> Self {
        let sys = FakeSystem::new();
        let memory = Arc::new(MemoryLedger::new(sys.boot()));
        Self::with_ledger(sys, memory.clone(), memory)
    }

    /// A world whose engine writes through a [`CrashLedger`].
    pub fn crashing() -> (Self, Arc<CrashLedger>) {
        let sys = FakeSystem::new();
        let memory = Arc::new(MemoryLedger::new(sys.boot()));
        let crash = Arc::new(CrashLedger::new(memory.clone()));
        (Self::with_ledger(sys, memory, crash.clone()), crash)
    }

    fn with_ledger(sys: FakeSystem, memory: Arc<MemoryLedger>, ledger: Arc<dyn Ledger>) -> Self {
        let key = InstallKey([9; 32]);
        let index = Arc::new(MemIndex::default());
        index
            .store(&RepairIndex {
                install_key: key.clone(),
                instances: Vec::new(),
            })
            .unwrap();
        Self {
            sys,
            memory,
            ledger,
            index,
            key,
        }
    }

    /// A fresh engine over the same ledger and system (a host restart).
    pub fn engine(&self) -> ReclaimEngineImpl {
        ReclaimEngineImpl::new(ReclaimDeps {
            ledger: self.ledger.clone(),
            reclaimers: self.sys.reclaimers(),
            sweeper: self.sys.sweeper(),
            boot_id: self.sys.boot_id_source(),
            repair_index: self.index.clone(),
        })
    }

    pub fn name(&self, id: &str) -> String {
        naming::interface_name(&self.key, &InstanceId::from(id))
    }

    /// Register an instance (desired running) and in the repair index.
    pub async fn add_instance(&self, id: &str) {
        let (rev, _) = self.memory.desired().await.unwrap();
        let req = format!("put-{id}");
        self.memory
            .commit(
                rev,
                changes(&req, 1, vec![put(id, Desired::Running, &[])], vec![]),
            )
            .await
            .unwrap();
        let mut index = self.index.load().unwrap().unwrap();
        index.instances.push(InstanceId::from(id));
        self.index.store(&index).unwrap();
    }

    /// The full Windows-shaped set of effects of one generation.
    pub fn windows_intents(&self, id: &str, epoch: u64) -> Vec<EffectIntent> {
        let scope = EffectScope::Instance {
            instance: InstanceId::from(id),
            epoch: Epoch(epoch),
        };
        let name = self.name(id);
        let i = |kind, key, undo, persistence| EffectIntent {
            scope: scope.clone(),
            kind,
            key,
            undo,
            persistence,
        };
        let ensure = || Undo::EnsureAbsent;
        vec![
            self.process_intent(id, epoch),
            i(
                EffectKind::WinFenceFilter,
                ObjectKey::Fence {
                    container: "etd-fence".into(),
                    rule: format!("{id}-{epoch}"),
                    port: 15888,
                },
                ensure(),
                Persistence::Persistent,
            ),
            i(
                EffectKind::RuntimeDir,
                ObjectKey::Path {
                    path: format!("run/{id}/{epoch}").into(),
                },
                ensure(),
                Persistence::Persistent,
            ),
            i(
                EffectKind::WinTunAdapter,
                ObjectKey::Interface {
                    name: Some(name.clone()),
                    guid: Some(naming::wintun_guid(&name).to_string()),
                },
                ensure(),
                Persistence::Persistent,
            ),
            i(
                EffectKind::Route,
                ObjectKey::RoutesVia {
                    interface: Some(name.clone()),
                },
                ensure(),
                Persistence::WithProcess,
            ),
            i(
                EffectKind::WinRegistryValue,
                ObjectKey::Registry {
                    key: format!(
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}",
                        naming::wintun_guid(&name)
                    ),
                    value: Some("EnableDHCP".into()),
                },
                Undo::RestoreIfOurs {
                    ours: SettingValue::U32(0),
                    original: SettingValue::Absent,
                },
                Persistence::Persistent,
            ),
            i(
                EffectKind::WinFirewallRule,
                ObjectKey::Rule {
                    name: format!("EasyTier {name} - TCP Protocol (Inbound)"),
                    group: Some("EasyTier".into()),
                },
                ensure(),
                Persistence::Persistent,
            ),
            i(
                EffectKind::WinFirewallRule,
                ObjectKey::Rule {
                    name: format!("EasyTier {name} - UDP Protocol (Inbound)"),
                    group: Some("EasyTier".into()),
                },
                ensure(),
                Persistence::Persistent,
            ),
        ]
    }

    /// The kernel process record of a generation (every plan carries one).
    pub fn process_intent(&self, id: &str, epoch: u64) -> EffectIntent {
        EffectIntent {
            scope: EffectScope::Instance {
                instance: InstanceId::from(id),
                epoch: Epoch(epoch),
            },
            kind: EffectKind::Process,
            key: ObjectKey::Process {
                exe: "store/core".into(),
                cmdline_marker: format!("run/{id}/{epoch}").into(),
            },
            undo: Undo::EnsureAbsent,
            persistence: Persistence::WithProcess,
        }
    }

    /// Reserve the next generation of `id` with these effects (a process
    /// record is added if missing), against the current desired revision.
    pub async fn begin(&self, id: &str, mut effects: Vec<EffectIntent>) -> Vec<Effect> {
        let instance = InstanceId::from(id);
        let epoch = self.memory.next_epoch(&instance).await.unwrap();
        if !effects.iter().any(|e| e.kind == EffectKind::Process) {
            effects.push(self.process_intent(id, epoch.0));
        }
        let spec_revision = self.memory.spec_revision(&instance).await.unwrap();
        let plan = GenerationPlan {
            instance: instance.clone(),
            epoch,
            claims: vec![],
            inputs: LaunchInputs {
                spec: NetworkSpec {
                    network_name: id.into(),
                    ..Default::default()
                },
                spec_revision,
                runtime_dir: format!("run/{id}/{}", epoch.0).into(),
                interface_name: self.name(id),
                management: "127.0.0.1:15888".parse().unwrap(),
                privilege: Privilege::System,
                guard: ManagementGuard::Fence,
                core: CoreRef {
                    version: "2.7.1".into(),
                    proto_revision: "c97f36b".into(),
                    sha256: CORE_SHA,
                    binary: "store/core".into(),
                    profile: Some("2.7.1-c97f36b".into()),
                },
            },
            effects,
        };
        self.memory.begin_epoch(plan).await.unwrap()
    }

    /// Act on a recorded effect as the kernel / host would.
    pub async fn settle(&self, e: &Effect, fate: Fate) {
        let intent = EffectIntent {
            scope: e.scope.clone(),
            kind: e.kind,
            key: e.key.clone(),
            undo: e.undo.clone(),
            persistence: e.persistence,
        };
        match fate {
            Fate::Applied => {
                let obs = self.sys.apply_intent(&intent);
                self.memory
                    .transition(&e.id, EffectState::Applied, Some(obs))
                    .await
                    .unwrap();
            }
            Fate::PlannedPresent => {
                self.sys.apply_intent(&intent);
            }
            Fate::PlannedAbsent => {}
        }
    }

    /// Instance `id` with one generation of the Windows set, every record
    /// applied.
    pub async fn running(&self, id: &str) -> Vec<Effect> {
        self.add_instance(id).await;
        let epoch = self.memory.next_epoch(&InstanceId::from(id)).await.unwrap();
        let effects = self.begin(id, self.windows_intents(id, epoch.0)).await;
        for e in &effects {
            self.settle(e, Fate::Applied).await;
        }
        effects
    }

    pub async fn open(&self) -> Vec<Effect> {
        self.memory.open_effects(&ScopeFilter::all()).await.unwrap()
    }

    /// The system holds nothing of ours and nothing foreign was deleted.
    pub fn assert_clean(&self) {
        assert!(
            self.sys.ours().is_empty(),
            "left over: {:#?}",
            self.sys.ours()
        );
        assert!(
            self.sys.foreign_deleted().is_empty(),
            "foreign deleted: {:#?}",
            self.sys.foreign_deleted()
        );
    }
}

/// Whether a task ended with the injected crash.
pub fn crashed(r: Result<impl Sized, tokio::task::JoinError>) -> bool {
    match r {
        Ok(_) => false,
        Err(e) => {
            let payload = e.into_panic();
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            assert_eq!(msg, etd_testkit::fakes::system::CRASH, "unexpected panic");
            true
        }
    }
}
