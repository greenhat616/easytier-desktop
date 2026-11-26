//! Conservative adapters for an installation whose native effect adapters
//! have not landed. No observation can imply absence and no OS effect is
//! reclaimed. A fresh installation that has never enabled native adapters
//! has no adapter-owned objects to sweep; all other sweeps fail closed.
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
}
