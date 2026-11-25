//! Non-operational test seams for later deterministic component scenarios.
use async_trait::async_trait;
use etd_app::{HostLauncher, LaunchError, ProfileError, ProfileStore};
use etd_contract::{DesiredInstance, HostMode, NetworkSpec, Receipt, Revision, Role};
use etd_core_api::*;
use etd_host_core::{auth::Authorizer, core_store::*};
use etd_ipc::{Endpoint, PeerIdentity};
use etd_proc::*;
use etd_sysfx::*;
use futures_util::future::BoxFuture;
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub struct MemoryLedger;
#[async_trait]
impl Ledger for MemoryLedger {
    async fn commit(&self, _: Revision, _: ChangeSet) -> Result<Receipt, LedgerError> {
        Err(LedgerError::NotImplemented)
    }
    async fn transition(
        &self,
        _: EffectId,
        _: EffectState,
        _: Option<Observation>,
    ) -> Result<(), LedgerError> {
        Err(LedgerError::NotImplemented)
    }
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError> {
        Err(LedgerError::NotImplemented)
    }
    async fn open_effects(&self, _: ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        Err(LedgerError::NotImplemented)
    }
}

pub struct FakeSystem {
    pub kind: EffectKind,
    pub boot: BootId,
}
#[async_trait]
impl Reclaimer for FakeSystem {
    fn kind(&self) -> EffectKind {
        self.kind
    }
    fn rank(&self) -> u8 {
        todo!("scripted rank")
    }
    async fn probe(&self, _: &Effect) -> Probe {
        Probe::Indeterminate
    }
    async fn reclaim(&self, _: &Effect) -> Result<Reclaimed, ReclaimError> {
        Err(ReclaimError::NotImplemented)
    }
}
impl Sweeper for FakeSystem {
    fn find_marked(&self) -> BoxFuture<'_, Vec<FoundObject>> {
        todo!("scripted observations")
    }
}
impl BootIdSource for FakeSystem {
    fn current(&self) -> BootId {
        self.boot.clone()
    }
}

pub struct FakeProcessEngine;
#[async_trait]
impl ProcessEngine for FakeProcessEngine {
    async fn spawn(&self, _: Command) -> Result<Box<dyn ProcessHandle>, ProcessError> {
        Err(ProcessError::NotImplemented)
    }
    async fn liveness(&self, _: &ProcessIdentity) -> Liveness {
        Liveness::Uncertain
    }
    async fn kill_verified(&self, _: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
        Err(ProcessError::NotImplemented)
    }
    async fn find_marked(&self, _: &Path) -> Vec<ProcessIdentity> {
        todo!("scripted process identity")
    }
}

pub struct FakeClock {
    pub now: Instant,
}
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.now
    }
    fn sleep(&self, _: Duration) -> BoxFuture<'static, ()> {
        todo!("virtual clock")
    }
}

pub struct FakeCoreDriver;
#[async_trait]
impl CoreDriver for FakeCoreDriver {
    async fn identify(&self, _: &Path) -> Result<CoreDescriptor, CoreError> {
        Err(CoreError::NotImplemented)
    }
    fn plan_launch(&self, _: &NetworkSpec, _: &RuntimeDirs) -> Result<LaunchPlan, CoreError> {
        Err(CoreError::NotImplemented)
    }
    async fn attach(&self, _: &CoreEndpoint) -> Result<Box<dyn CoreSession>, CoreError> {
        Err(CoreError::NotImplemented)
    }
}
pub struct FakeAuthorizer;
impl Authorizer for FakeAuthorizer {
    fn role_of(&self, _: &PeerIdentity) -> Option<Role> {
        None
    }
}
pub struct FakeCoreStore;
impl CoreStore for FakeCoreStore {
    fn resolve(&self, _: &CoreSelector) -> Result<VerifiedCore, StoreError> {
        Err(StoreError::NotImplemented)
    }
}
pub struct FakeHostLauncher;
#[async_trait]
impl HostLauncher for FakeHostLauncher {
    async fn ensure(&self, _: HostMode) -> Result<Endpoint, LaunchError> {
        Err(LaunchError::NotImplemented)
    }
}
pub struct FakeProfileStore;
impl ProfileStore for FakeProfileStore {
    fn load(&self) -> Result<Vec<NetworkSpec>, ProfileError> {
        Err(ProfileError::NotImplemented)
    }
    fn save(&self, _: &[NetworkSpec]) -> Result<(), ProfileError> {
        Err(ProfileError::NotImplemented)
    }
}
