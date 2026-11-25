//! EasyTier-specific adapter; the only crate permitted to depend on EasyTier.
// Compile the pinned backend dependencies without exposing upstream types.
use easytier_core as _;
use easytier_proto as _;
use etd_contract::NetworkSpec;
use etd_core_api::*;
use std::path::Path;

pub const PROTOTYPE_REVISION: &str = "c97f36b8d40f3bde7a95cc9ec99fe95fe35a6ff0";

pub struct EasyTierDriver;
#[async_trait::async_trait]
impl CoreDriver for EasyTierDriver {
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
