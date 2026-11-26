//! Host shutdown always ends (topic#45): the Windows service stop waited on
//! a serial, slow generation reclaim with no bound, past the uninstaller's
//! 60 s stop wait.
//! 1. a generation reclaim that never returns: the host still ends within
//!    its shutdown budget, the kernel is stopped, nothing is deleted
//!    blindly; the open records stay in the ledger and the next start
//!    reclaims them;
//! 2. a normal shutdown with a running instance ends before the budget with
//!    the generation closed;
//! 3. a shutdown received during the startup self-check also stops the
//!    instances the self-check goes on to start.
mod lifecycle_common;

use etd_contract::{Desired, InstanceState as S};
use etd_host_core::lifecycle::RunOutcome;
use etd_proc::ProcessEngine;
use etd_testkit::fakes::process::Call;
use lifecycle_common::*;
use std::sync::atomic::Ordering;

async fn ready(world: &World) -> Host<'_> {
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h
}

fn stopped(world: &World, kernel: &etd_proc::ProcessIdentity) -> bool {
    world
        .engine
        .calls()
        .iter()
        .any(|c| matches!(c, Call::Stop(id, _) | Call::Kill(id) if id == kernel))
}

#[tokio::test]
async fn shutdown_is_bounded_when_the_reclaim_never_returns() {
    let world = World::new();
    let h = ready(&world).await;
    let kernel = world.last_kernel();
    let open_before = world.open_records("a").await.len();
    assert!(open_before > 0);
    world.reclaim_hangs.store(true, Ordering::SeqCst);

    let started = world.clock.now();
    assert_eq!(h.shutdown().await, RunOutcome::Shutdown);
    let took = world.clock.now().saturating_duration_since(started);
    let budget = world.config.shutdown_budget;
    assert!(
        took >= budget,
        "the hanging reclaim cannot have finished early ({took:?})"
    );
    assert!(
        took <= budget + std::time::Duration::from_secs(1),
        "shutdown overran its budget: {took:?} > {budget:?}"
    );
    assert!(stopped(&world, &kernel), "the kernel was stopped");
    // Nothing closed or deleted behind the stuck reclaim: every record of
    // the generation is left for the next start.
    assert_eq!(world.open_records("a").await.len(), open_before);
    assert!(world.sys.foreign_deleted().is_empty());

    // The next start reclaims the generation left open and runs the
    // instance again in the next epoch.
    world.reclaim_hangs.store(false, Ordering::SeqCst);
    let mut h = world.start();
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert!(
        world
            .open_records("a")
            .await
            .iter()
            .all(|e| e.scope.generation().is_some_and(|(_, ep)| ep.0 == 2)),
        "the generation left open by the bounded shutdown was reclaimed"
    );
}

#[tokio::test]
async fn shutdown_stops_and_reclaims_within_the_budget() {
    let world = World::new();
    let h = ready(&world).await;
    let kernel = world.last_kernel();
    let started = world.clock.now();
    assert_eq!(h.shutdown().await, RunOutcome::Shutdown);
    let took = world.clock.now().saturating_duration_since(started);
    assert!(took < world.config.shutdown_budget, "took {took:?}");
    assert!(stopped(&world, &kernel));
    assert!(world.open_records("a").await.is_empty());
}

#[tokio::test]
async fn shutdown_during_the_self_check_stops_what_it_starts() {
    let world = World::new();
    let h = ready(&world).await;
    h.crash();
    // Shutdown queued before the new host's self-check has run: it is
    // received while the self-check is still in progress.
    let h = world.start();
    let started = world.clock.now();
    assert_eq!(h.shutdown().await, RunOutcome::Shutdown);
    let took = world.clock.now().saturating_duration_since(started);
    assert!(took < world.config.shutdown_budget, "took {took:?}");
    for kernel in world.spawned() {
        assert_ne!(
            world.engine.liveness(&kernel).await,
            etd_proc::Liveness::Same,
            "kernel {} still runs after shutdown",
            kernel.pid
        );
    }
}
