//! Every way a kernel ends, judged by which (instance, epoch) pairs exited
//! and which generations are closed afterwards:
//! 1. requested stop (desired STOPPED) -> graceful stop, reclaim, STOPPED;
//! 2. crash -> reclaim, backoff, the next epoch starts;
//! 3. never ready -> killed at the start timeout, reclaim, backoff;
//! 4. exit before its identity was captured -> abnormal exit, reclaim;
//! 5. removal -> stop, reclaim, configuration dropped, INSTANCE_REMOVED;
//! 6. UI crash (session host, no lease for the grace period) -> instances
//!    stopped and reclaimed, the host exits, desired state untouched;
//! 7. host crash -> the next host kills the orphan kernel and restores the
//!    instance in the next epoch;
//! 8. power loss -> boot id changed, volatile records closed unprobed, the
//!    instance restored from desired state.
mod lifecycle_common;

use etd_contract::v1::event::Payload;
use etd_contract::{Desired, InstanceState as S};
use etd_proc::{Exit, ExitCause, ProcessError};
use etd_sysfx::Ledger;
use lifecycle_common::*;
use std::collections::BTreeSet;

fn exits(h: &mut Host<'_>) -> BTreeSet<(String, u64, bool)> {
    h.settle_sync();
    h.log
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::InstanceExited(x) => Some((
                x.instance_id.clone(),
                x.epoch,
                x.exit.as_ref().is_some_and(|i| i.abnormal),
            )),
            _ => None,
        })
        .collect()
}

fn crash() -> Exit {
    Exit {
        code: Some(101),
        signal: None,
        cause: ExitCause::Exited,
    }
}

async fn ready(world: &World) -> Host<'_> {
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h
}

#[tokio::test]
async fn requested_stop_reclaims_and_stops() {
    let world = World::new();
    let mut h = ready(&world).await;
    let iface = world.interface_key("a");
    assert!(
        world
            .sys
            .find(etd_sysfx::EffectKind::LinuxTun, &iface)
            .is_some()
    );

    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;

    assert_eq!(exits(&mut h), BTreeSet::from([("a".into(), 1, false)]));
    assert!(world.open_records("a").await.is_empty());
    assert!(
        world
            .sys
            .find(etd_sysfx::EffectKind::LinuxTun, &iface)
            .is_none()
    );
    assert!(!world.dirs.run_dir.join("a").join("1").exists());
    assert!(h.events_seq_gap_free());
}

#[tokio::test]
async fn crash_reclaims_then_restarts_next_epoch() {
    let world = World::new();
    let mut h = ready(&world).await;
    let first = world.last_kernel();
    world.engine.exit(&first, crash());
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(exits(&mut h), BTreeSet::from([("a".into(), 1, true)]));
    let history = h.history("a");
    let reclaiming = history.iter().position(|s| *s == S::Reclaiming).unwrap();
    let backoff = history.iter().position(|s| *s == S::Backoff).unwrap();
    assert!(
        reclaiming < backoff,
        "reclaim precedes the restart delay: {history:?}"
    );
    // Epoch 1 is closed; only epoch 2 is open.
    let open = world.open_records("a").await;
    assert!(
        open.iter()
            .all(|e| e.scope.generation().is_some_and(|(_, ep)| ep.0 == 2))
    );
}

#[tokio::test]
async fn never_ready_is_killed_at_the_start_timeout() {
    let world = World::new();
    world.behave(KernelBehaviour {
        address: false,
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::Starting).await;
    h.until("killed and backing off", |h| h.state("a") == S::Backoff)
        .await;
    assert_eq!(exits(&mut h), BTreeSet::from([("a".into(), 1, true)]));
    assert!(
        world
            .engine
            .calls()
            .iter()
            .any(|c| matches!(c, etd_testkit::fakes::process::Call::Kill(_)))
    );
    assert!(
        world
            .open_records("a")
            .await
            .iter()
            .all(|e| e.scope.generation().is_some_and(|(_, ep)| ep.0 != 1))
    );
}

#[tokio::test]
async fn exit_before_identity_counts_as_abnormal() {
    let world = World::new();
    world
        .engine
        .push_spawn(Err(ProcessError::ExitedBeforeIdentity(crash())));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(exits(&mut h), BTreeSet::from([("a".into(), 1, true)]));
    assert_eq!(h.status("a").unwrap().restart_attempt, 1);
}

#[tokio::test]
async fn removal_stops_reclaims_and_drops_the_instance() {
    let world = World::new();
    let mut h = ready(&world).await;
    h.remove("a").await;
    h.until("removed", |h| {
        h.log
            .iter()
            .any(|e| matches!(&e.payload, Payload::InstanceRemoved(r) if r.instance_id == "a"))
    })
    .await;
    assert_eq!(exits(&mut h), BTreeSet::from([("a".into(), 1, false)]));
    assert!(world.open_records("a").await.is_empty());
    assert!(h.snapshot().instances.is_empty());
    let (_, desired) = world.ledger.inner.desired().await.unwrap();
    assert!(desired.is_empty());
}

/// Open generations of the ledger, as (instance, epoch).
async fn open_generations(world: &World) -> BTreeSet<(String, u64)> {
    world
        .ledger
        .inner
        .open_effects(&etd_sysfx::ScopeFilter::default())
        .await
        .unwrap()
        .iter()
        .filter_map(|e| e.scope.generation().map(|(i, ep)| (i.to_string(), ep.0)))
        .collect()
}

#[tokio::test]
async fn ui_crash_lets_the_session_host_wind_down() {
    let world = World::with_mode(etd_contract::HostMode::User, false);
    let mut h = world.start();
    h.wait_serving().await;
    h.leases(1).await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    // The UI dies: its connection and lease are gone.
    h.leases(0).await;
    h.idle(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(20),
    )
    .await;
    assert_eq!(h.state("a"), S::ReadyFull, "still inside the grace period");
    let mut outcome = None;
    for _ in 0..200 {
        h.idle(
            std::time::Duration::from_millis(500),
            std::time::Duration::from_millis(500),
        )
        .await;
        if let Some(o) = h.finished().await {
            outcome = Some(o);
            break;
        }
    }
    assert_eq!(
        outcome,
        Some(etd_host_core::lifecycle::RunOutcome::LeaseReleased)
    );
    assert_eq!(exits(&mut h), BTreeSet::from([("a".into(), 1, false)]));
    assert!(open_generations(&world).await.is_empty());
    let (_, desired) = world.ledger.inner.desired().await.unwrap();
    assert_eq!(
        desired[0].desired(),
        Desired::Running,
        "the stop is not a desired change"
    );
}

#[tokio::test]
async fn user_host_exits_when_no_client_ever_connects() {
    use std::time::Duration;
    let world = World::with_mode(etd_contract::HostMode::User, false);
    let mut host = world.start();
    host.wait_serving().await;
    host.idle(Duration::from_secs(1), Duration::from_secs(20))
        .await;
    assert!(
        host.finished().await.is_none(),
        "initial lease grace must elapse first"
    );
    let mut outcome = None;
    for _ in 0..100 {
        host.idle(Duration::from_millis(500), Duration::from_millis(500))
            .await;
        if let Some(finished) = host.finished().await {
            outcome = Some(finished);
            break;
        }
    }
    assert_eq!(
        outcome,
        Some(etd_host_core::lifecycle::RunOutcome::LeaseReleased)
    );
    assert!(open_generations(&world).await.is_empty());
}

#[tokio::test]
async fn a_returning_ui_cancels_the_wind_down() {
    let world = World::with_mode(etd_contract::HostMode::User, false);
    let mut h = world.start();
    h.wait_serving().await;
    h.leases(1).await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.leases(0).await;
    h.idle(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(20),
    )
    .await;
    h.leases(1).await;
    h.idle(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(60),
    )
    .await;
    assert!(h.finished().await.is_none());
    assert_eq!(h.state("a"), S::ReadyFull);
}

#[tokio::test]
async fn service_host_ignores_leases() {
    let world = World::new();
    let mut h = ready(&world).await;
    h.leases(0).await;
    h.idle(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(90),
    )
    .await;
    assert!(h.finished().await.is_none());
    assert_eq!(h.state("a"), S::ReadyFull);
}

#[tokio::test]
async fn host_crash_restores_the_instance_in_the_next_epoch() {
    let world = World::new();
    let h = ready(&world).await;
    let old = world.last_kernel();
    h.crash();
    let mut h = world.start();
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert!(
        world.kernel.calls_kill(&old),
        "the orphan kernel was killed"
    );
    assert_eq!(
        open_generations(&world).await,
        BTreeSet::from([("a".to_string(), 2)])
    );
}

#[tokio::test]
async fn power_loss_closes_volatile_records_and_restores() {
    let world = World::new();
    let h = ready(&world).await;
    let old = world.last_kernel();
    h.crash();
    world.power_loss();
    let calls = world.engine.calls().len();
    let mut h = world.start();
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    // The old kernel's record closed with the reboot, unprobed.
    let after: Vec<_> = world.engine.calls()[calls..].to_vec();
    assert!(!after.iter().any(|c| matches!(c,
        etd_testkit::fakes::process::Call::Liveness(id)
        | etd_testkit::fakes::process::Call::KillVerified(id) if *id == old)));
    assert_eq!(
        open_generations(&world).await,
        BTreeSet::from([("a".to_string(), 2)])
    );
    assert!(world.sys.foreign_deleted().is_empty());
}
