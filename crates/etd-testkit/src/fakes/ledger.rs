//! In-memory Ledger with the same transactional state machine as SQLite.
use async_trait::async_trait;
use etd_contract::{DesiredInstance, InstanceId, Receipt, RequestId, Revision};
use etd_sysfx::{sqlite::LedgerState, *};
use std::sync::Mutex;

/// A fresh, empty ledger. Reuse this object across simulated host restarts.
pub struct MemoryLedger {
    state: Mutex<LedgerState>,
    boot: Mutex<BootId>,
}
impl Default for MemoryLedger {
    fn default() -> Self {
        Self::new(BootId("test-boot".into()))
    }
}
impl MemoryLedger {
    pub fn new(boot: BootId) -> Self {
        Self {
            state: Mutex::new(LedgerState::default()),
            boot: Mutex::new(boot),
        }
    }
    pub fn set_boot_id(&self, boot: BootId) {
        *self.boot.lock().expect("boot lock poisoned") = boot;
    }
    fn boot(&self) -> BootId {
        self.boot.lock().expect("boot lock poisoned").clone()
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, LedgerState>, LedgerError> {
        self.state.lock().map_err(|_| {
            LedgerError::Unavailable(StorageFault::Io("memory ledger poisoned".into()))
        })
    }
    fn read<T>(
        &self,
        f: impl FnOnce(&LedgerState) -> Result<T, LedgerError>,
    ) -> Result<T, LedgerError> {
        f(&*self.lock()?)
    }
    fn write<T>(
        &self,
        f: impl FnOnce(&mut LedgerState) -> Result<T, LedgerError>,
    ) -> Result<T, LedgerError> {
        let mut guard = self.lock()?;
        let mut staged = guard.clone();
        let value = f(&mut staged)?;
        *guard = staged;
        Ok(value)
    }
}
#[async_trait]
impl Ledger for MemoryLedger {
    async fn commit(&self, expected: Revision, change: ChangeSet) -> Result<Receipt, LedgerError> {
        self.write(|s| s.commit(expected, change, &self.boot(), jiff::Timestamp::now()))
    }
    async fn request_status(&self, request: &RequestRecord) -> Result<RequestStatus, LedgerError> {
        self.read(|s| Ok(s.request_status(request)))
    }
    async fn receipt(&self, request: &RequestId) -> Result<Option<Receipt>, LedgerError> {
        self.read(|s| Ok(s.receipt(request)))
    }
    async fn receipt_for(
        &self,
        request: &RequestId,
        caller: Option<&str>,
    ) -> Result<Option<Receipt>, LedgerError> {
        self.read(|s| Ok(s.receipt_for(request, caller)))
    }
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError> {
        self.read(|s| Ok(s.pending_tickets()))
    }
    async fn complete_ticket(&self, ticket: &str) -> Result<(), LedgerError> {
        self.write(|s| s.complete_ticket(ticket))
    }
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError> {
        self.read(|s| Ok(s.desired()))
    }
    async fn spec_revision(&self, instance: &InstanceId) -> Result<Revision, LedgerError> {
        self.read(|s| s.spec_revision(instance))
    }
    async fn settings(&self) -> Result<HostSettings, LedgerError> {
        self.read(|s| Ok(s.settings()))
    }
    async fn claims(&self) -> Result<Vec<ClaimHold>, LedgerError> {
        self.read(|s| Ok(s.claims()))
    }
    async fn next_epoch(&self, instance: &InstanceId) -> Result<Epoch, LedgerError> {
        self.read(|s| s.next_epoch(instance))
    }
    async fn begin_epoch(&self, plan: GenerationPlan) -> Result<Vec<Effect>, LedgerError> {
        self.write(|s| s.begin_epoch(plan, &self.boot(), jiff::Timestamp::now()))
    }
    async fn generation(
        &self,
        instance: &InstanceId,
        epoch: Epoch,
    ) -> Result<Option<StoredGeneration>, LedgerError> {
        self.read(|s| Ok(s.generation(instance, epoch)))
    }
    async fn record(&self, intent: EffectIntent) -> Result<Effect, LedgerError> {
        self.write(|s| s.record(intent, &self.boot(), jiff::Timestamp::now()))
    }
    async fn transition(
        &self,
        id: &EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError> {
        self.write(|s| s.transition(id, to, obs))
    }
    async fn record_failure(&self, id: &EffectId, error: &str) -> Result<u32, LedgerError> {
        self.write(|s| s.record_failure(id, error))
    }
    async fn open_effects(&self, filter: &ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        self.read(|s| Ok(s.open_effects(filter)))
    }
    async fn compact(&self) -> Result<usize, LedgerError> {
        self.write(|s| Ok(s.compact()))
    }
}
