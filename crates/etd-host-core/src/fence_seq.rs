//! Fence sequence: install -> spawn -> verify listener -> probe both ways
//! -> expose management; remove only after the kernel is verified dead.
//! Owned by H1.
//!
//! How the steps map onto the orchestrator (doc#2 v7, "内核自己的管理端口"):
//! 1. The fence record is part of the generation, committed (planned)
//!    before anything happens; [`install`] puts the persistent rule in place
//!    and marks the record applied. Spawning is refused if this fails.
//! 2. (and 3.) After the spawn, [`check`] runs on every readiness tick: the
//!    listener on the management address must be the process just spawned,
//!    then both directions are probed against that live listener. Basic
//!    readiness of a fenced instance waits for [`FenceCheck::Verified`];
//!    management (the RPC session) is opened only after it. Any mismatch is
//!    [`FenceCheck::Failed`]: the supervisor kills the kernel and reclaims.
//!    While the kernel runs, the supervisor repeats [`check`] every
//!    `LifecycleConfig::fence_recheck` (a firewall reload can drop the
//!    rule); two misses in a row (failed or not verifiable) end the
//!    management session, kill the kernel and reclaim, and the restart
//!    policy brings a new generation with a new fence.
//! 4. The fallback is a new generation planned with
//!    `ManagementGuard::DenyAll`; the kernel driver accepts it only when the
//!    adapter profile marks its deny-all configuration verified, otherwise
//!    no privileged instance starts.
//! 5. The rule is a ledger record of rank `rank::FENCE`, after the process
//!    record: the reclaim engine removes it only once the process record is
//!    closed (kernel verified dead). The orchestrator never calls
//!    `PortFence::remove` itself, and never reclaims a generation whose
//!    process liveness is uncertain.
use etd_sysfx::{
    DirectionResult, Effect, EffectState, FenceError, FenceSpec, Ledger, ListenerCheck, PortFence,
    SystemObserver,
};

/// Step 1: install the rule recorded by `record` and mark it applied.
pub(crate) async fn install(
    fence: &dyn PortFence,
    ledger: &dyn Ledger,
    record: &Effect,
    spec: &FenceSpec,
) -> Result<(), String> {
    let observation = fence
        .install(spec)
        .await
        .map_err(|e| format!("fence install failed: {e}"))?;
    ledger
        .transition(&record.id, EffectState::Applied, Some(observation))
        .await
        .map_err(|e| format!("fence record not applied: {e}"))
}

/// Outcome of steps 2-3 at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FenceCheck {
    /// Nothing listening yet (or the observation failed): look again.
    Pending,
    /// The spawned process listens and the fence holds both ways.
    Verified,
    /// Never trust this port: kill and reclaim.
    Failed(String),
}

/// Steps 2-3 against the process `pid` just spawned.
pub(crate) async fn check(
    observer: &dyn SystemObserver,
    fence: &dyn PortFence,
    spec: &FenceSpec,
    pid: u32,
) -> FenceCheck {
    match observer.listener(spec.address).await {
        Err(e) => {
            tracing::debug!(error = %e, "management listener not observable yet");
            return FenceCheck::Pending;
        }
        Ok(None) => return FenceCheck::Pending,
        Ok(Some(l)) if l.pid != pid => {
            return FenceCheck::Failed(format!(
                "management port {} is held by pid {}, not the kernel (pid {pid})",
                spec.address, l.pid
            ));
        }
        Ok(Some(_)) => {}
    }
    match fence.verify(spec, pid).await {
        Ok(v) if v.passed() => FenceCheck::Verified,
        // A refusal on an empty port proves nothing: look again.
        Ok(v)
            if v.listener == ListenerCheck::NotListening
                || (v.host == DirectionResult::NoListener
                    && v.unprivileged == DirectionResult::NoListener) =>
        {
            FenceCheck::Pending
        }
        Ok(v) => FenceCheck::Failed(format!("fence verification failed: {v:?}")),
        Err(FenceError::Probe(m)) => FenceCheck::Failed(format!("fence probe failed: {m}")),
        Err(e) => FenceCheck::Failed(format!("fence verification failed: {e}")),
    }
}
