//! Every way a kernel ends, judged by which (instance, epoch) pairs exited
//! and which generations are closed afterwards:
//! 1. requested stop (desired STOPPED) -> graceful stop, reclaim, STOPPED;
//! 2. crash -> reclaim, backoff, the next epoch starts;
//! 3. never ready -> killed at the start timeout, reclaim, backoff;
//! 4. exit before its identity was captured -> abnormal exit, reclaim;
//! 5. removal -> stop, reclaim, configuration dropped, INSTANCE_REMOVED.
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
