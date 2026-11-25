//! The management-port fence on a privileged host (doc#2 v7, five steps):
//! the rule exists before the kernel spawns; the listener must be the
//! kernel; both directions are probed; any mismatch kills the kernel and
//! reclaims, and the next generation falls back to deny-all only when the
//! adapter profile marks it verified; the rule goes only after the kernel
//! is verified dead.
mod lifecycle_common;

use etd_contract::v1::ManagementAccess;
use etd_contract::{Desired, InstanceState as S};
use etd_proc::{Exit, ExitCause, Liveness, ProcessEngine};
use etd_sysfx::{DirectionResult, EffectKind, EffectState, FenceVerification, ListenerCheck};
use lifecycle_common::*;

fn fences(world: &World) -> usize {
    world
        .sys
        .objects()
        .iter()
        .filter(|o| o.kind == World::fence_kind())
        .count()
}

#[tokio::test]
async fn fence_exists_before_spawn_and_gates_management() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    let seen = world.kernel.objects_at_spawn.lock().unwrap().clone();
    assert!(
        seen[0].iter().any(|o| o.kind == World::fence_kind()),
        "the fence rule is installed before the kernel spawns"
    );
    let status = h.status("a").unwrap();
    assert_eq!(status.management(), ManagementAccess::Available);
    // The fence record is applied in the ledger, ranked after the process.
    let open = world.open_records("a").await;
    let fence = open.iter().find(|e| e.kind == World::fence_kind()).unwrap();
    assert_eq!(fence.state, EffectState::Applied);
    assert!(world.driver.attach_calls() >= 1);
}

#[tokio::test]
async fn foreign_listener_kills_and_falls_back_to_deny_all() {
    let world = World::new();
    world.behave(KernelBehaviour {
        squatter: Some(4242),
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.until("deny-all generation", |h| {
        h.status("a").is_some_and(|s| {
            s.epoch == 2
                && s.management() == ManagementAccess::DenyAll
                && s.state() == S::ReadyBasic
        })
    })
    .await;
    // No RPC was ever attempted against the untrusted port.
    assert_eq!(world.driver.attach_calls(), 0);
    // The first kernel was killed and its generation (fence included) closed.
    let first = world.spawned()[0].clone();
    assert_eq!(world.engine.liveness(&first).await, Liveness::Gone);
    assert!(
        world
            .open_records("a")
            .await
            .iter()
            .all(|e| e.scope.generation().is_some_and(|(_, ep)| ep.0 == 2))
    );
    assert_eq!(fences(&world), 0, "deny-all generations have no fence rule");
}

#[tokio::test]
async fn probe_mismatch_in_either_direction_kills() {
    for unprivileged in [
        DirectionResult::Connected,
        DirectionResult::Error("x".into()),
    ] {
        let world = World::new();
        world.sys.set_fence_verification(Some(FenceVerification {
            listener: ListenerCheck::Expected,
            host: DirectionResult::Connected,
            unprivileged: unprivileged.clone(),
        }));
        let mut h = world.start();
        h.wait_serving().await;
        h.apply("a", spec("net"), Desired::Running).await;
        h.until("fallback", |h| h.status("a").is_some_and(|s| s.epoch == 2))
            .await;
        assert_eq!(world.driver.attach_calls(), 0, "{unprivileged:?}");
        assert_eq!(
            world.engine.liveness(&world.spawned()[0]).await,
            Liveness::Gone
        );
    }
    // The host direction failing is a mismatch too.
    let world = World::new();
    world.sys.set_fence_verification(Some(FenceVerification {
        listener: ListenerCheck::Expected,
        host: DirectionResult::Refused,
        unprivileged: DirectionResult::Refused,
    }));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.until("fallback", |h| h.status("a").is_some_and(|s| s.epoch == 2))
        .await;
    assert_eq!(world.driver.attach_calls(), 0);
}

#[tokio::test]
async fn no_fallback_without_a_verified_deny_all() {
    let world = World::new();
    world.driver.set_deny_all_verified(false);
    world.behave(KernelBehaviour {
        squatter: Some(4242),
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::GaveUp).await;
    assert_eq!(
        world.spawned().len(),
        1,
        "no privileged instance starts unguarded"
    );
    assert!(world.open_records("a").await.is_empty());
    assert_eq!(fences(&world), 0);
}

#[tokio::test]
async fn fence_stays_while_the_kernel_is_not_verified_dead() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let kernel = world.last_kernel();
    world.engine.exit(
        &kernel,
        Exit {
            code: Some(1),
            signal: None,
            cause: ExitCause::Exited,
        },
    );
    // Its liveness cannot be established any more.
    world
        .engine
        .set_liveness(&kernel, Some(Liveness::Uncertain));
    h.wait_state("a", S::Quarantined).await;
    assert_eq!(
        fences(&world),
        1,
        "the fence is never removed before the kernel"
    );
    let open = world.open_records("a").await;
    assert!(open.iter().any(|e| e.kind == World::fence_kind()));
    assert!(
        open.iter()
            .any(|e| e.kind == EffectKind::Process && e.state == EffectState::Quarantined)
    );
    assert_eq!(
        world.spawned().len(),
        1,
        "a quarantined instance never restarts"
    );

    // Once the kernel is verifiably gone, a retry reclaims the fence too.
    world.engine.set_liveness(&kernel, None);
    h.retry_reclaim("a").await;
    h.until("epoch 2", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(fences(&world), 1, "only epoch 2's fence remains");
}
