//! Planning a generation (for H2's `Command::Plan` and for the supervisor's
//! own `begin_epoch`), and replaying a committed one from its persisted
//! inputs. H1 is the only planner.
use super::Ctx;
use crate::core_store::{CoreSelector, CoreUsage, StoreError, VerifiedCore};
use etd_contract::{ErrorCode, ErrorDetail, HostMode, InstanceId, NetworkSpec, Revision};
use etd_core_api::{CoreError, LaunchContext, LaunchPlan};
use etd_sysfx::{
    CoreRef, EffectIntent, EffectKind, EffectScope, Epoch, FenceSpec, GenerationPlan,
    LaunchInputs, LedgerError, ManagementGuard, ObjectKey, Persistence, Privilege,
    StoredGeneration, Undo, naming,
};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;

/// Why a generation could not be planned or replayed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PlanFailure {
    Store(StoreError),
    Core(CoreError),
    Ledger(LedgerError),
    /// The committed generation no longer matches what replay produces
    /// (kernel binary, effects, fence availability).
    Replay(String),
    /// No loopback port could be reserved.
    Port(String),
}

impl PlanFailure {
    pub(crate) fn message(&self) -> String {
        match self {
            PlanFailure::Store(e) => e.to_string(),
            PlanFailure::Core(e) => e.to_string(),
            PlanFailure::Ledger(e) => e.to_string(),
            PlanFailure::Replay(m) => format!("replay refused: {m}"),
            PlanFailure::Port(m) => format!("no management port: {m}"),
        }
    }

    /// The contract rejection for a client request.
    pub(crate) fn detail(&self, instance: &InstanceId) -> ErrorDetail {
        let mut d = ErrorDetail {
            message: self.message(),
            instance_id: instance.to_string(),
            ..Default::default()
        };
        let code = match self {
            PlanFailure::Store(_) | PlanFailure::Replay(_) => ErrorCode::CoreUnavailable,
            PlanFailure::Core(CoreError::UnmodelledEffects { features }) => {
                d.features = features.clone();
                ErrorCode::UnmodelledEffects
            }
            PlanFailure::Core(CoreError::FeatureRejected { feature, .. }) => {
                d.features = vec![feature.clone()];
                ErrorCode::FeatureRejected
            }
            PlanFailure::Core(CoreError::InvalidSpec(_)) => ErrorCode::InvalidSpec,
            PlanFailure::Core(_) => ErrorCode::CoreUnavailable,
            PlanFailure::Ledger(e) => return ledger_detail(e, instance),
            PlanFailure::Port(_) => ErrorCode::HostNotServing,
        };
        d.set_code(code);
        d
    }
}

pub(crate) fn ledger_detail(e: &LedgerError, instance: &InstanceId) -> ErrorDetail {
    let mut d = ErrorDetail {
        message: e.to_string(),
        instance_id: instance.to_string(),
        ..Default::default()
    };
    match e {
        LedgerError::UnknownInstance(_) => d.set_code(ErrorCode::UnknownInstance),
        LedgerError::Conflict { current } => {
            d.current_revision = *current;
            d.set_code(ErrorCode::RevisionConflict)
        }
        LedgerError::ExclusiveTaken { resource, .. } => {
            d.features = vec![resource.clone()];
            d.set_code(ErrorCode::SingleWriterTaken)
        }
        LedgerError::EpochOpen { .. } => d.set_code(ErrorCode::InstanceBusy),
        _ => d.set_code(ErrorCode::LedgerUnavailable),
    }
    d
}

pub(crate) fn error(code: ErrorCode, message: impl Into<String>, instance: &str) -> ErrorDetail {
    let mut d = ErrorDetail {
        message: message.into(),
        instance_id: instance.into(),
        ..Default::default()
    };
    d.set_code(code);
    d
}

/// A planned (not yet committed) generation.
#[derive(Debug, Clone)]
pub(crate) struct PlannedGeneration {
    pub generation: GenerationPlan,
    pub launch: LaunchPlan,
}

pub(crate) fn privilege(mode: HostMode) -> Privilege {
    match mode {
        HostMode::User => Privilege::User,
        _ => Privilege::System,
    }
}

/// The guard to ask for. `fence_failed`: the previous generation's fence
/// could not be installed or verified (v7 fence step 4).
pub(crate) fn choose_guard(
    mode: HostMode,
    usage: &CoreUsage,
    fence_available: bool,
    fence_failed: bool,
) -> Result<ManagementGuard, PlanFailure> {
    match (privilege(mode), usage) {
        (Privilege::User, CoreUsage::Profiled(_)) => Ok(ManagementGuard::Unguarded),
        (Privilege::User, _) => Ok(ManagementGuard::LifecycleOnly),
        (_, CoreUsage::Profiled(_)) if fence_available && !fence_failed => {
            Ok(ManagementGuard::Fence)
        }
        // The driver refuses DenyAll unless the profile marks it verified.
        (_, CoreUsage::Profiled(_)) => Ok(ManagementGuard::DenyAll),
        (_, _) => Err(PlanFailure::Store(StoreError::NoProfile {
            version: String::new(),
        })),
    }
}

/// `run/<instance>/<epoch>/`.
pub(crate) fn runtime_dir(ctx: &Ctx, instance: &InstanceId, epoch: Epoch) -> PathBuf {
    ctx.deps
        .dirs
        .run_dir
        .join(instance.as_str())
        .join(epoch.0.to_string())
}

/// A free loopback port for the kernel's management RPC. The fence check
/// (listener must be the spawned process) catches a port taken meanwhile.
fn management_address() -> Result<SocketAddr, PlanFailure> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| PlanFailure::Port(e.to_string()))?;
    listener
        .local_addr()
        .map_err(|e| PlanFailure::Port(e.to_string()))
}

pub(crate) fn fence_spec(instance: &InstanceId, epoch: Epoch, inputs: &LaunchInputs) -> FenceSpec {
    FenceSpec {
        instance: instance.clone(),
        epoch,
        address: inputs.management,
    }
}

/// Every effect of a generation: the kernel's predicted effects plus the
/// host's own (runtime directory, process record, fence). Deterministic in
/// its inputs, so replay can rebuild and compare it.
pub(crate) fn generation_effects(
    ctx: &Ctx,
    lctx: &LaunchContext,
    plan: &LaunchPlan,
) -> Result<Vec<EffectIntent>, PlanFailure> {
    let scope = EffectScope::Instance {
        instance: lctx.instance.clone(),
        epoch: lctx.epoch,
    };
    let mut effects = plan.effects.clone();
    effects.push(EffectIntent {
        scope: scope.clone(),
        kind: EffectKind::RuntimeDir,
        key: ObjectKey::Path {
            path: lctx.inputs.runtime_dir.clone(),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    });
    effects.push(EffectIntent {
        scope,
        kind: EffectKind::Process,
        key: ObjectKey::Process {
            exe: plan.command.executable.clone(),
            cmdline_marker: lctx.inputs.runtime_dir.clone(),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::WithProcess,
    });
    if lctx.inputs.guard == ManagementGuard::Fence {
        let fence = ctx.deps.fence.as_ref().ok_or_else(|| {
            PlanFailure::Replay("generation needs a fence but this host has none".into())
        })?;
        effects.push(fence.plan(&fence_spec(&lctx.instance, lctx.epoch, &lctx.inputs)));
    }
    Ok(effects)
}

async fn resolve_core(ctx: &Ctx, version: Option<String>) -> Result<VerifiedCore, PlanFailure> {
    ctx.deps
        .core_store
        .resolve(&CoreSelector { version })
        .await
        .map_err(PlanFailure::Store)
}

/// Plan generation `epoch` of `instance` with `spec` under the current
/// settings and kernel selection.
pub(crate) async fn plan_generation(
    ctx: &Ctx,
    instance: &InstanceId,
    spec: &NetworkSpec,
    spec_revision: Revision,
    epoch: Epoch,
    fence_failed: bool,
) -> Result<PlannedGeneration, PlanFailure> {
    let settings = ctx.deps.ledger.settings().await.map_err(PlanFailure::Ledger)?;
    let core = resolve_core(ctx, settings.selected_core).await?;
    let guard = choose_guard(
        ctx.deps.mode,
        &core.usage,
        ctx.deps.fence.is_some(),
        fence_failed,
    )
    .map_err(|e| match e {
        PlanFailure::Store(StoreError::NoProfile { .. }) => {
            PlanFailure::Store(StoreError::NoProfile {
                version: core.descriptor.version.clone(),
            })
        }
        e => e,
    })?;
    let profile = match &core.usage {
        CoreUsage::Profiled(p) => Some(p.id.clone()),
        _ => None,
    };
    let inputs = LaunchInputs {
        spec: spec.clone(),
        spec_revision,
        runtime_dir: runtime_dir(ctx, instance, epoch),
        interface_name: naming::interface_name(&ctx.deps.install_key, instance),
        management: management_address()?,
        privilege: privilege(ctx.deps.mode),
        guard,
        core: CoreRef {
            version: core.descriptor.version.clone(),
            proto_revision: core.descriptor.proto_revision.clone(),
            sha256: core.sha256,
            binary: core.binary.clone(),
            profile,
        },
    };
    let lctx = LaunchContext {
        instance: instance.clone(),
        epoch,
        inputs,
    };
    let launch = ctx.deps.core.plan_launch(&lctx).map_err(PlanFailure::Core)?;
    let effects = generation_effects(ctx, &lctx, &launch)?;
    Ok(PlannedGeneration {
        generation: GenerationPlan {
            instance: instance.clone(),
            epoch,
            claims: launch.exclusive.clone(),
            inputs: lctx.inputs,
            effects,
        },
        launch,
    })
}

/// Replay a committed generation: re-verify the kernel hash, re-run the
/// pure plan on the stored inputs and require the stored effects.
pub(crate) async fn replay(
    ctx: &Ctx,
    instance: &InstanceId,
    epoch: Epoch,
    stored: &StoredGeneration,
) -> Result<LaunchPlan, PlanFailure> {
    let want = &stored.inputs.core;
    let core = resolve_core(ctx, Some(want.version.clone())).await?;
    if core.sha256 != want.sha256 || core.binary != want.binary {
        return Err(PlanFailure::Replay(format!(
            "kernel {} no longer matches the committed hash",
            want.version
        )));
    }
    let lctx = LaunchContext {
        instance: instance.clone(),
        epoch,
        inputs: stored.inputs.clone(),
    };
    let launch = ctx.deps.core.plan_launch(&lctx).map_err(PlanFailure::Core)?;
    let expected = generation_effects(ctx, &lctx, &launch)?;
    if !same_effects(&expected, stored) {
        return Err(PlanFailure::Replay(
            "planned effects differ from the committed generation".into(),
        ));
    }
    if launch.command.executable != want.binary {
        return Err(PlanFailure::Replay(
            "plan launches a binary outside the kernel store".into(),
        ));
    }
    Ok(launch)
}

fn same_effects(expected: &[EffectIntent], stored: &StoredGeneration) -> bool {
    let mut left: Vec<&etd_sysfx::Effect> = stored.effects.iter().collect();
    for intent in expected {
        let Some(at) = left.iter().position(|e| {
            e.scope == intent.scope
                && e.kind == intent.kind
                && e.key == intent.key
                && e.undo == intent.undo
                && e.persistence == intent.persistence
        }) else {
            return false;
        };
        left.swap_remove(at);
    }
    left.is_empty()
}

/// Spec equality as the kernel sees it: the UI label never reaches it.
pub(crate) fn same_kernel_spec(a: &NetworkSpec, b: &NetworkSpec) -> bool {
    let strip = |s: &NetworkSpec| NetworkSpec {
        display_name: String::new(),
        network_secret_set: false,
        ..s.clone()
    };
    strip(a) == strip(b)
}

/// Apply semantics of the secret: absent keeps the stored one, `""` clears.
pub(crate) fn merge_secret(mut new: NetworkSpec, stored: Option<&NetworkSpec>) -> NetworkSpec {
    if new.network_secret.is_none() {
        new.network_secret = stored.and_then(|s| s.network_secret.clone());
    }
    new.network_secret_set = false;
    new
}
