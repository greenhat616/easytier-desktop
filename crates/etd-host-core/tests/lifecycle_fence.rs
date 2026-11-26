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
async fn a_restarted_instance_rechecks_the_management_listener_before_attach() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    let trusted_attaches = world.driver.attach_calls();
    assert!(trusted_attaches > 0);

    // Change only the listener identity returned by the in-memory system.
    world.behave(KernelBehaviour {
        squatter: Some(4242),
        ..KernelBehaviour::default()
    });
    h.set_desired("a", Desired::Running).await.unwrap();
    h.until(
        "ready with management disabled after rejecting epoch 2",
        |h| {
            h.status("a").is_some_and(|s| {
                s.epoch == 3
                    && s.state() == S::ReadyBasic
                    && s.management() == ManagementAccess::DenyAll
            })
        },
    )
    .await;
    assert_eq!(world.driver.attach_calls(), trusted_attaches);
    let kernels = world.spawned();
    assert_eq!(kernels.len(), 3);
    assert_eq!(world.engine.liveness(&kernels[1]).await, Liveness::Gone);
    let open = world.open_records("a").await;
    assert!(!open.is_empty());
    assert!(
        open.iter()
            .all(|e| e.scope.generation().is_some_and(|(_, ep)| ep.0 == 3))
    );
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
    // Its liveness cannot be established any more. Set before the exit is
    // delivered: the host's runtime reclaims as soon as it sees the exit,
    // and a probe that ran before this would find the kernel gone.
    world
        .engine
        .set_liveness(&kernel, Some(Liveness::Uncertain));
    world.engine.exit(
        &kernel,
        Exit {
            code: Some(1),
            signal: None,
            cause: ExitCause::Exited,
        },
    );
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

fn notices(h: &mut Host<'_>, code: &str) -> usize {
    h.settle_sync();
    h.log
        .iter()
        .filter(|e| {
            matches!(&e.payload,
                etd_contract::v1::event::Payload::Notice(n) if n.code == code)
        })
        .count()
}

#[tokio::test]
async fn a_fence_lost_while_the_kernel_runs_kills_reclaims_and_restarts() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let first = world.last_kernel();
    let attaches = world.driver.attach_calls();

    // A firewall reload drops the rule under the running kernel.
    let rule = world
        .sys
        .objects()
        .into_iter()
        .find(|o| o.kind == World::fence_kind())
        .expect("the fence rule");
    assert!(world.sys.vanish(rule.kind, &rule.key));

    h.until("restarted with a new fence", |h| {
        h.status("a").is_some_and(|s| {
            s.epoch == 2
                && s.state() == S::ReadyFull
                && s.management() == ManagementAccess::Available
        })
    })
    .await;
    assert_eq!(world.engine.liveness(&first).await, Liveness::Gone);
    assert_eq!(notices(&mut h, "fence.lost"), 1);
    assert!(
        h.history("a").contains(&S::Reclaiming),
        "the killed generation was reclaimed"
    );
    // Only the new generation is open, with its own fence.
    let open = world.open_records("a").await;
    assert!(
        open.iter()
            .all(|e| e.scope.generation().is_some_and(|(_, ep)| ep.0 == 2))
    );
    assert_eq!(fences(&world), 1);
    assert!(
        world.driver.attach_calls() > attaches,
        "management reopened"
    );
}

#[tokio::test]
async fn a_single_missed_fence_check_is_retried_without_action() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let kernel = world.last_kernel();

    // The next re-verification fails once (transient), the retry passes.
    world.sys.inject(
        etd_testkit::fakes::system::Fault::on(etd_testkit::fakes::system::Step::FenceVerify).once(),
    );
    h.idle(
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(70),
    )
    .await;
    assert_eq!(world.engine.liveness(&kernel).await, Liveness::Same);
    assert_eq!(world.spawned().len(), 1);
    assert_eq!(h.state("a"), S::ReadyFull);
    assert_eq!(h.status("a").unwrap().epoch, 1);
    assert_eq!(notices(&mut h, "fence.lost"), 0);
}

#[tokio::test]
async fn unverifiable_fence_checks_never_kill_and_are_reported_once() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let kernel = world.last_kernel();

    // Every re-verification from now on proves nothing either way (e.g. the
    // firewall is busy): retried every 10 s, never a kill.
    world.sys.inject(
        etd_testkit::fakes::system::Fault::on(etd_testkit::fakes::system::Step::FenceVerify).fail(
            etd_sysfx::ReclaimError::Os {
                code: 16,
                message: "PF writer is busy".into(),
            },
        ),
    );
    // 30 s to the first re-check, then 10 s apart: well past five in a row.
    h.idle(
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(150),
    )
    .await;
    assert_eq!(world.engine.liveness(&kernel).await, Liveness::Same);
    assert_eq!(world.spawned().len(), 1);
    assert_eq!(h.state("a"), S::ReadyFull);
    assert_eq!(notices(&mut h, "fence.lost"), 0);
    assert_eq!(notices(&mut h, "fence.unverifiable"), 1, "reported once");

    // Verifiable again: nothing else happens.
    world.sys.clear_faults();
    h.idle(
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(30),
    )
    .await;
    assert_eq!(world.engine.liveness(&kernel).await, Liveness::Same);
    assert_eq!(notices(&mut h, "fence.unverifiable"), 1);
}

#[tokio::test]
async fn a_fence_the_adapter_reports_missing_twice_kills_and_restarts() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let kernel = world.last_kernel();

    // The adapter's query succeeds and shows our fence gone, twice in a row.
    world.verify_errors.lock().unwrap().extend([
        etd_sysfx::FenceError::Missing("filter gone".into()),
        etd_sysfx::FenceError::Missing("filter gone".into()),
    ]);
    h.until("restarted", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert!(world.kernel.calls_kill(&kernel));
    assert_eq!(notices(&mut h, "fence.lost"), 1);
    assert_eq!(notices(&mut h, "fence.unverifiable"), 0);
}
