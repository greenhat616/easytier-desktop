//! EasyTier adapter; the only crate permitted to depend on EasyTier.
//!
//! This file (F0) only wires the frozen [`CoreDriver`] to the package files:
//! `identify` and `plan/`, `profiles/` (E1), `session/` (E2).
use etd_contract::NetworkSpec;
use etd_core_api::*;
use std::path::Path;

// Compile the pinned upstream crates without exposing their types.
use easytier_core as _;
use easytier_proto as _;

pub mod identify;
pub mod plan;
pub mod profiles;
pub mod session;

/// Upstream revision of the first adapter profile.
pub const PROTOTYPE_REVISION: &str = "c97f36b8d40f3bde7a95cc9ec99fe95fe35a6ff0";

pub struct EasyTierDriver;

#[async_trait::async_trait]
impl CoreDriver for EasyTierDriver {
    async fn identify(&self, binary: &Path) -> Result<CoreDescriptor, CoreError> {
        identify::identify(binary).await
    }
    fn profile(&self, core: &CoreDescriptor) -> Option<AdapterProfile> {
        profiles::profile_for(core)
    }
    fn plan_launch(
        &self,
        spec: &NetworkSpec,
        ctx: &LaunchContext,
    ) -> Result<LaunchPlan, CoreError> {
        plan::plan_launch(spec, ctx)
    }
    async fn attach(
        &self,
        ep: &CoreEndpoint,
        core: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError> {
        session::attach(ep, core).await
    }
}
