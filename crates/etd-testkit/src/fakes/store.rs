//! Fake store with controllable verified kernels.
use etd_contract::v1::{CoreEntry, CoreSupport};
use etd_host_core::core_store::{CoreSelector, CoreStore, CoreUsage, StoreError, VerifiedCore};
use std::sync::Mutex;

#[derive(Default)]
pub struct FakeCoreStore {
    state: Mutex<(Option<String>, Vec<VerifiedCore>)>,
}
impl FakeCoreStore {
    pub fn new(default: Option<String>, cores: Vec<VerifiedCore>) -> Self {
        Self {
            state: Mutex::new((default, cores)),
        }
    }
}
#[async_trait::async_trait]
impl CoreStore for FakeCoreStore {
    async fn resolve(&self, want: &CoreSelector) -> Result<VerifiedCore, StoreError> {
        let state = self.state.lock().unwrap();
        let version = want.version.as_ref().or(state.0.as_ref());
        state
            .1
            .iter()
            .find(|c| Some(&c.descriptor.version) == version)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(want.clone()))
    }
    async fn list(&self) -> Result<Vec<CoreEntry>, StoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .1
            .iter()
            .map(|c| CoreEntry {
                version: c.descriptor.version.clone(),
                proto_revision: c.descriptor.proto_revision.clone(),
                sha256: c.sha256.iter().map(|b| format!("{b:02x}")).collect(),
                support: match c.usage {
                    CoreUsage::Profiled(_) => CoreSupport::Profiled,
                    CoreUsage::LifecycleOnly => CoreSupport::LifecycleOnly,
                    _ => CoreSupport::Rejected,
                } as i32,
            })
            .collect())
    }
    async fn remove(&self, version: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().unwrap();
        let pos = state
            .1
            .iter()
            .position(|c| c.descriptor.version == version)
            .ok_or_else(|| {
                StoreError::NotFound(CoreSelector {
                    version: Some(version.into()),
                })
            })?;
        state.1.remove(pos);
        if state.0.as_deref() == Some(version) {
            state.0 = None;
        }
        Ok(())
    }
}
