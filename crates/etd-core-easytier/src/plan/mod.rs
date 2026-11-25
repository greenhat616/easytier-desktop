//! `plan_launch`: TOML and command line from typed parameters (interface
//! name and loopback RPC port forced, no `rpc_portal` in TOML, `-c` only
//! to the epoch directory), side-effect prediction per adapter profile,
//! feature classification. Owned by E1.
use etd_contract::NetworkSpec;
use etd_core_api::{CoreError, LaunchContext, LaunchPlan};

pub fn plan_launch(_spec: &NetworkSpec, ctx: &LaunchContext) -> Result<LaunchPlan, CoreError> {
    Err(CoreError::NoProfile {
        version: ctx.core.version.clone(),
    })
}
