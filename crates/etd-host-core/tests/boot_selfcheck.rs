//! Startup self-check after a host crash: the six steps in order, a failed
//! reclaim quarantines only its own instance, running the same recovery
//! twice writes nothing the second time, and the ledger-less modes start
//! nothing.
mod lifecycle_common;

use etd_contract::v1::event::Payload;
use etd_contract::{Desired, ErrorCode, HostPhase, InstanceState as S};
use etd_proc::{Command, Liveness, ProcessEngine};
use etd_sysfx::{EffectKind, EffectState, Ledger, LedgerError, StorageFault};
use etd_testkit::fakes::process::Call;
use lifecycle_common::*;
use std::sync::atomic::Ordering;

/// An instance running, then the host dies; its kernel keeps running.
async fn crashed_with(world: &World, instances: &[&str]) {
    let mut h = world.start();
    h.wait_serving().await;
    for i in instances {
        h.apply(i, spec(i), Desired::Running).await;
    }
    for i in instances {
        h.wait_state(i, S::ReadyFull).await;
    }
    h.crash();
}

fn phases(h: &mut Host<'_>) -> Vec<HostPhase> {
    h.settle_sync();
    h.log
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::HostPhase(p) => Some(p.phase()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn six_steps_after_a_crash() {
    let world = World::new();
    crashed_with(&world, &["a"]).await;
    let old = world.last_kernel();
    assert_eq!(world.kernel.liveness(&old).await, Liveness::Same);
    // A kernel nobody recorded (crash between spawn and recording its pid).
    let stray = world
        .engine
        .spawn(Command {
            executable: world.store.binary.clone(),
            args: vec![
                world
                    .dirs
                    .run_dir
                    .join("a")
                    .join("9")
                    .join("config.toml")
                    .into(),
            ],
            env: Vec::new(),
            cwd: None,
        })
        .await
        .unwrap()
        .identity()
        .clone();
    let calls_before = world.engine.calls().len();

    let mut h = world.start();
    h.until("a restarted", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    // Steps 1 and 6: self-check, then serving.
    assert_eq!(
        phases(&mut h),
        vec![HostPhase::SelfCheck, HostPhase::Serving]
    );
    // Step 3: both orphans killed, the recorded one by its identity first.
    let calls: Vec<Call> = world.engine.calls()[calls_before..].to_vec();
    let kill_old = calls
        .iter()
        .position(|c| *c == Call::KillVerified(old.clone()))
        .expect("recorded kernel killed");
    let sweep = calls
        .iter()
        .position(|c| matches!(c, Call::FindMarked(m) if m.exe_root == world.dirs.core_store_dir))
        .expect("marker sweep");
    assert!(kill_old < sweep);
    assert!(calls.contains(&Call::KillVerified(stray.clone())));
    assert_eq!(world.kernel.liveness(&stray).await, Liveness::Gone);
    // Step 4: epoch 1 reclaimed before epoch 2 was spawned.
    let seen = world.kernel.objects_at_spawn.lock().unwrap().clone();
    assert!(
        !seen[1].iter().any(|o| o.kind == EffectKind::LinuxTun),
        "epoch 1's interface was gone before epoch 2 spawned"
    );
    // Step 5: the report is published.
    assert!(h.snapshot().reclaim.is_some());
}

#[tokio::test]
async fn a_failed_reclaim_quarantines_only_its_instance() {
    let world = World::new();
    crashed_with(&world, &["a", "b"]).await;
    let kernels = world.spawned();
    // a's kernel can no longer be identified.
    world
        .engine
        .set_liveness(&kernels[0], Some(Liveness::Uncertain));
    let mut h = world.start();
    h.until("b restarted", |h| {
        h.status("b")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    h.wait_state("a", S::Quarantined).await;
    let open = world.open_records("a").await;
    assert!(
        open.iter()
            .any(|e| e.kind == EffectKind::Process && e.state == EffectState::Quarantined)
    );
    assert!(open.iter().all(|e| e.scope.generation().unwrap().1.0 == 1));
    assert!(!world.kernel.calls_kill(&kernels[0]));
}

#[tokio::test]
async fn recovery_after_a_crash_is_idempotent() {
    let world = World::new();
    crashed_with(&world, &["a"]).await;
    // Stop intent committed while the host was down (no new start).
    let revision = world.ledger.inner.desired().await.unwrap().0;
    world
        .ledger
        .inner
        .commit(
            revision,
            etd_sysfx::ChangeSet {
                request: etd_sysfx::RequestRecord {
                    request_id: "stop-offline".into(),
                    caller: "test".into(),
                    digest: etd_sysfx::RequestDigest([1; 32]),
                },
                changes: vec![etd_sysfx::Change::SetDesired {
                    instance: "a".into(),
                    desired: Desired::Stopped,
                }],
                generations: Vec::new(),
            },
        )
        .await
        .unwrap();
    // Recovery 1 does the work.
    let mut h = world.start();
    h.wait_serving().await;
    h.wait_state("a", S::Stopped).await;
    h.crash();
    let sys_writes = world.sys.stats().write_calls;
    let ledger_writes = world.ledger.writes.load(Ordering::SeqCst);
    let deleted = world.sys.deleted().len();
    // Recovery 2 finds nothing to do.
    let mut h = world.start();
    h.wait_serving().await;
    h.wait_state("a", S::Stopped).await;
    h.settle().await;
    assert_eq!(world.sys.stats().write_calls, sys_writes);
    assert_eq!(world.ledger.writes.load(Ordering::SeqCst), ledger_writes);
    assert_eq!(world.sys.deleted().len(), deleted);
    assert!(world.open_records("a").await.is_empty());
}

#[tokio::test]
async fn diagnose_only_kills_nothing_and_starts_nothing() {
    let world = World::new();
    crashed_with(&world, &["a"]).await;
    let old = world.last_kernel();
    *world.ledger.desired_error.lock().unwrap() = Some(LedgerError::SchemaTooNew {
        found: 99,
        supported: 1,
    });
    let writes = world.sys.stats().write_calls;
    let mut h = world.start();
    h.until_still("diagnose only", |h| h.phase() == HostPhase::DiagnosticOnly)
        .await;
    assert_eq!(world.kernel.liveness(&old).await, Liveness::Same);
    assert!(!world.kernel.calls_kill(&old));
    assert_eq!(world.spawned().len(), 1);
    let err = h.plan("a", None, true).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::HostNotServing);
    assert_eq!(
        world.sys.stats().write_calls,
        writes,
        "diagnosis writes nothing"
    );
}

#[tokio::test]
async fn ledger_unavailable_recovers_containers_only() {
    let world = World::new();
    crashed_with(&world, &["a"]).await;
    *world.ledger.desired_error.lock().unwrap() =
        Some(LedgerError::Unavailable(StorageFault::Locked));
    let mut h = world.start();
    h.until_still("diagnose only", |h| h.phase() == HostPhase::DiagnosticOnly)
        .await;
    assert_eq!(
        world.spawned().len(),
        1,
        "no instance starts without the ledger"
    );
    assert!(world.sys.foreign_deleted().is_empty());
}

fn notices(h: &mut Host<'_>, code: &str) -> Vec<etd_contract::v1::Notice> {
    h.settle_sync();
    h.log
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::Notice(n) if n.code == code => Some(n.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_failed_sweep_holds_every_start_until_a_retry_succeeds() {
    let world = World::new();
    crashed_with(&world, &["a"]).await;
    // Both sweeps of this boot fail (per generation and whole run dir).
    for _ in 0..2 {
        world
            .engine
            .fail_next_enumeration(etd_proc::ProcessError::Enumeration("denied".into()));
    }
    let mut h = world.start();
    h.wait_serving().await;
    h.until_still("waiting", |h| h.state("a") == S::Waiting)
        .await;
    assert_eq!(notices(&mut h, "selfcheck.incomplete").len(), 1);
    assert_eq!(
        world.spawned().len(),
        1,
        "nothing starts while the sweep failed"
    );
    // Retries run every reclaim period; the enumeration recovers.
    h.until("a restarted", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(notices(&mut h, "selfcheck.complete").len(), 1);
}

#[tokio::test]
async fn an_unkillable_orphan_quarantines_its_instance_only() {
    let world = World::new();
    crashed_with(&world, &["a", "b"]).await;
    // An unrecorded kernel of a's (closed) generation 9 that cannot be killed.
    let stray = world
        .engine
        .spawn(Command {
            executable: world.store.binary.clone(),
            args: vec![
                world
                    .dirs
                    .run_dir
                    .join("a")
                    .join("9")
                    .join("config.toml")
                    .into(),
            ],
            env: Vec::new(),
            cwd: None,
        })
        .await
        .unwrap()
        .identity()
        .clone();
    std::fs::create_dir_all(world.dirs.run_dir.join("a").join("9")).unwrap();
    world.engine.set_liveness(&stray, Some(Liveness::Uncertain));

    let mut h = world.start();
    h.until("b restarted", |h| {
        h.status("b")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    h.wait_state("a", S::Quarantined).await;
    let n = notices(&mut h, "selfcheck.quarantined");
    assert!(n.iter().any(|n| n.instance_id == "a"), "{n:?}");
    assert_eq!(world.spawned().len(), 3, "only b got a new kernel");

    // A retry while it still cannot be killed changes nothing ...
    h.retry_reclaim("a").await;
    h.idle(
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(5),
    )
    .await;
    assert_eq!(h.state("a"), S::Quarantined);
    // ... once it can, the instance comes back.
    world.engine.set_liveness(&stray, None);
    h.retry_reclaim("a").await;
    h.until("a restarted", |h| h.state("a") == S::ReadyFull)
        .await;
    assert_eq!(world.kernel.liveness(&stray).await, Liveness::Gone);
}

#[tokio::test]
async fn an_unrecordable_quarantine_reclaims_nothing() {
    let world = World::new();
    crashed_with(&world, &["a"]).await;
    let kernel = world.last_kernel();
    world
        .engine
        .set_liveness(&kernel, Some(Liveness::Uncertain));
    world.ledger.writes_fail.store(true, Ordering::SeqCst);
    let mut h = world.start();
    h.wait_serving().await;
    h.wait_state("a", S::Quarantined).await;
    world.ledger.writes_fail.store(false, Ordering::SeqCst);
    h.idle(
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(10),
    )
    .await;
    // Its objects are all still there, and nothing restarted.
    assert!(
        world
            .sys
            .find(EffectKind::LinuxTun, &world.interface_key("a"))
            .is_some()
    );
    assert!(world.sys.deleted().is_empty());
    assert_eq!(world.spawned().len(), 1);
    assert_eq!(h.state("a"), S::Quarantined);
}
