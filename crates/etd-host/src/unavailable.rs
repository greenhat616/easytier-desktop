//! Conservative adapters for an installation whose native effect adapters
//! have not landed. No observation can imply absence and no OS effect is
//! reclaimed. A fresh installation that has never enabled native adapters
//! has no adapter-owned objects to sweep; all other sweeps fail closed.
use etd_contract::{DesiredInstance, InstanceId, Receipt, RequestId, Revision};
use etd_core_api::*;
use etd_core_easytier::EasyTierDriver;
use etd_sysfx::*;
use etd_sysfx_os::OsAdapters;
use futures_util::future::BoxFuture;
use std::{net::SocketAddr, path::Path, sync::Arc};

pub struct MissingNative {
    pub reason: String,
    pub never_enabled: bool,
}

impl MissingNative {
    fn reclaim_error(&self) -> ReclaimError {
        ReclaimError::Indeterminate(self.reason.clone())
    }
    fn observe_error(&self) -> ObserveError {
        ObserveError::Os {
            code: -1,
            message: self.reason.clone(),
        }
    }
    pub fn adapters(self) -> OsAdapters {
        let native = Arc::new(self);
        OsAdapters {
            reclaimers: vec![],
            sweeper: native.clone(),
            boot_id: native.clone(),
            observer: native,
            fence: None,
        }
    }
}
impl BootIdSource for MissingNative {
    fn current(&self) -> Result<BootId, ReclaimError> {
        Err(self.reclaim_error())
    }
}
impl Sweeper for MissingNative {
    fn find_marked<'a>(
        &'a self,
        _: Option<&'a InstallKey>,
        known: &'a [etd_contract::InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
        Box::pin(async move {
            if self.never_enabled && known.is_empty() {
                Ok(vec![])
            } else {
                Err(self.reclaim_error())
            }
        })
    }
}
#[async_trait::async_trait]
impl SystemObserver for MissingNative {
    async fn observe(
        &self,
        _: EffectKind,
        _: &ObjectKey,
    ) -> Result<Option<Observation>, ObserveError> {
        Err(self.observe_error())
    }
    async fn interface(&self, _: &ObjectKey) -> Result<Option<InterfaceInfo>, ObserveError> {
        Err(self.observe_error())
    }
    async fn listener(&self, _: SocketAddr) -> Result<Option<ListenerInfo>, ObserveError> {
        Err(self.observe_error())
    }
    async fn interfaces_owned_by(&self, _: u32) -> Result<Vec<InterfaceInfo>, ObserveError> {
        Err(self.observe_error())
    }
    async fn enumerate(&self, _: SystemClass) -> Result<Vec<SystemEntry>, ObserveError> {
        Err(self.observe_error())
    }
}

/// Defend the autonomous boot/retry path independently of the RPC guard.
pub struct BlockedDriver(pub String);
#[async_trait::async_trait]
impl CoreDriver for BlockedDriver {
    async fn identify(&self, binary: &Path) -> Result<CoreDescriptor, CoreError> {
        EasyTierDriver.identify(binary).await
    }
    fn profile(&self, descriptor: &CoreDescriptor) -> Option<AdapterProfile> {
        EasyTierDriver.profile(descriptor)
    }
    fn plan_launch(&self, _: &LaunchContext) -> Result<LaunchPlan, CoreError> {
        Err(CoreError::FeatureRejected {
            feature: "native adapters".into(),
            reason: self.0.clone(),
        })
    }
    async fn attach(
        &self,
        _: &CoreEndpoint,
        _: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError> {
        Err(CoreError::FeatureRejected {
            feature: "native adapters".into(),
            reason: self.0.clone(),
        })
    }
}

/// Windows hosts whose firewall cleanup is not available (an unlisted build
/// whose self-check failed, doc#17 v2, msg#1989): a launch whose plan has
/// firewall rule effects is refused before any record is written, so no
/// firewall record can be created that the host could not reclaim.
pub struct FirewallGated<D> {
    pub inner: D,
    /// `Err(reason)` when firewall cleanup is unavailable on this host.
    pub supported: fn() -> Result<(), String>,
}
#[async_trait::async_trait]
impl<D: CoreDriver> CoreDriver for FirewallGated<D> {
    async fn identify(&self, binary: &Path) -> Result<CoreDescriptor, CoreError> {
        self.inner.identify(binary).await
    }
    fn profile(&self, descriptor: &CoreDescriptor) -> Option<AdapterProfile> {
        self.inner.profile(descriptor)
    }
    fn plan_launch(&self, ctx: &LaunchContext) -> Result<LaunchPlan, CoreError> {
        let plan = self.inner.plan_launch(ctx)?;
        if plan
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WinFirewallRule)
            && let Err(reason) = (self.supported)()
        {
            return Err(CoreError::FeatureRejected {
                feature: "firewall".into(),
                reason,
            });
        }
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

/// Last line of defence: neither a newly committed generation nor a direct
/// record/begin_epoch can reach the real ledger while native adapters are
/// unavailable. Existing records still support transition/reclaim and
/// diagnostics; no new ownership claims may be invented by the fallback.
pub struct NoNewEffects(pub Arc<dyn Ledger>);
fn unavailable_write() -> LedgerError {
    LedgerError::Unavailable(StorageFault::Io(
        "native adapters unavailable; creation records refused".into(),
    ))
}
#[async_trait::async_trait]
impl Ledger for NoNewEffects {
    async fn commit(&self, expected: Revision, change: ChangeSet) -> Result<Receipt, LedgerError> {
        if !change.generations.is_empty() {
            return Err(unavailable_write());
        }
        self.0.commit(expected, change).await
    }
    async fn request_status(&self, request: &RequestRecord) -> Result<RequestStatus, LedgerError> {
        self.0.request_status(request).await
    }
    async fn receipt(&self, request: &RequestId) -> Result<Option<Receipt>, LedgerError> {
        self.0.receipt(request).await
    }
    async fn receipt_for(
        &self,
        request: &RequestId,
        caller: Option<&str>,
    ) -> Result<Option<Receipt>, LedgerError> {
        self.0.receipt_for(request, caller).await
    }
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError> {
        self.0.pending_tickets().await
    }
    async fn complete_ticket(&self, ticket: &str) -> Result<(), LedgerError> {
        self.0.complete_ticket(ticket).await
    }
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError> {
        self.0.desired().await
    }
    async fn spec_revision(&self, instance: &InstanceId) -> Result<Revision, LedgerError> {
        self.0.spec_revision(instance).await
    }
    async fn settings(&self) -> Result<HostSettings, LedgerError> {
        self.0.settings().await
    }
    async fn claims(&self) -> Result<Vec<ClaimHold>, LedgerError> {
        self.0.claims().await
    }
    async fn next_epoch(&self, instance: &InstanceId) -> Result<Epoch, LedgerError> {
        self.0.next_epoch(instance).await
    }
    async fn begin_epoch(&self, _: GenerationPlan) -> Result<Vec<Effect>, LedgerError> {
        Err(unavailable_write())
    }
    async fn generation(
        &self,
        instance: &InstanceId,
        epoch: Epoch,
    ) -> Result<Option<StoredGeneration>, LedgerError> {
        self.0.generation(instance, epoch).await
    }
    async fn record(&self, _: EffectIntent) -> Result<Effect, LedgerError> {
        Err(unavailable_write())
    }
    async fn transition(
        &self,
        id: &EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError> {
        self.0.transition(id, to, obs).await
    }
    async fn record_failure(&self, id: &EffectId, error: &str) -> Result<u32, LedgerError> {
        self.0.record_failure(id, error).await
    }
    async fn open_effects(&self, filter: &ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        self.0.open_effects(filter).await
    }
    async fn compact(&self) -> Result<usize, LedgerError> {
        self.0.compact().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn only_never_enabled_empty_installations_can_skip_native_sweep() {
        let missing = MissingNative {
            reason: "test adapter unavailable".into(),
            never_enabled: true,
        };
        assert!(missing.find_marked(None, &[]).await.unwrap().is_empty());
        assert!(
            missing
                .find_marked(None, &[etd_contract::InstanceId("known".into())])
                .await
                .is_err()
        );
        assert!(missing.current().is_err());
        let missing = MissingNative {
            never_enabled: false,
            ..missing
        };
        assert!(missing.find_marked(None, &[]).await.is_err());
        assert!(
            missing
                .listener("127.0.0.1:1234".parse().unwrap())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn all_effect_creation_entry_points_refuse_without_native_adapters() {
        let inner = Arc::new(etd_testkit::fakes::ledger::MemoryLedger::default());
        let ledger = NoNewEffects(inner.clone());
        let plan = etd_testkit::conformance::ledger::plan_at("fixture", 1, &[], 1);
        assert!(ledger.begin_epoch(plan.clone()).await.is_err());
        assert!(
            ledger
                .commit(
                    0,
                    ChangeSet {
                        request: RequestRecord {
                            request_id: "fixture".into(),
                            caller: "fixture".into(),
                            digest: RequestDigest([1; 32])
                        },
                        changes: vec![],
                        generations: vec![plan]
                    }
                )
                .await
                .is_err()
        );
        assert!(
            ledger
                .record(EffectIntent {
                    scope: EffectScope::Product,
                    kind: EffectKind::ServiceRegistration,
                    key: ObjectKey::Service {
                        name: "fixture".into()
                    },
                    undo: Undo::EnsureAbsent,
                    persistence: Persistence::Persistent
                })
                .await
                .is_err()
        );
        assert!(
            inner
                .open_effects(&ScopeFilter::all())
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(inner.desired().await.unwrap().0, 0);
    }
}
