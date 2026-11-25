//! Generations never overlap: a generation that is not closed blocks the
//! next one, and after a crash the old generation is reclaimed before the
//! restart delay even starts.
mod lifecycle_common;

use etd_contract::{Desired, InstanceState as S};
use etd_proc::{Exit, ExitCause};
use etd_sysfx::{EffectKind, Epoch, Ledger, LedgerError, ReclaimError};
use etd_testkit::fakes::system::{Fault, Step};
use lifecycle_common::*;

fn crash() -> Exit {
    Exit {
        code: Some(3),
        signal: None,
        cause: ExitCause::Exited,
    }
}

#[tokio::test]
async fn an_open_generation_blocks_the_next() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    // The interface cannot be deleted for now: epoch 1 stays open.
    world.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::LinuxTun)
            .times(3)
            .fail(ReclaimError::Busy("in use".into())),
    );
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.until("reclaim failing", |h| {
        h.state("a") == S::Reclaiming && h.status("a").unwrap().open_residues > 0
    })
    .await;

    // A start committed meanwhile carries no generation of its own ...
    let planned = h.plan("a", None, true).await.unwrap();
    assert!(planned.generation.is_none(), "epoch 1 is still open");
    // ... and the ledger refuses one anyway.
    let next = world.ledger.inner.next_epoch(&"a".into()).await.unwrap();
    assert_eq!(next, Epoch(2));
    h.set_desired("a", Desired::Running).await.unwrap();
    h.settle().await;
    assert_eq!(world.spawned().len(), 1, "no kernel while epoch 1 is open");

    // Once the interface goes, epoch 1 closes and epoch 2 starts.
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(world.spawned().len(), 2);
}

#[tokio::test]
async fn begin_epoch_is_refused_while_a_generation_is_open() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let stored = world
        .ledger
        .inner
        .generation(&"a".into(), Epoch(1))
        .await
        .unwrap()
        .unwrap();
    let mut plan = etd_sysfx::GenerationPlan {
        instance: "a".into(),
        epoch: Epoch(2),
        inputs: stored.inputs.clone(),
        claims: stored.claims.clone(),
        effects: Vec::new(),
    };
    plan.effects = stored
        .effects
        .iter()
        .map(|e| etd_sysfx::EffectIntent {
            scope: etd_sysfx::EffectScope::Instance {
                instance: "a".into(),
                epoch: Epoch(2),
            },
            kind: e.kind,
            key: e.key.clone(),
            undo: e.undo.clone(),
            persistence: e.persistence,
        })
        .collect();
    assert!(matches!(
        world.ledger.inner.begin_epoch(plan).await,
        Err(LedgerError::EpochOpen { .. } | LedgerError::InvalidPlan { .. })
    ));
}

#[tokio::test]
async fn crash_reclaims_before_the_backoff_starts() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let iface = world.interface_key("a");

    world.engine.exit(&world.last_kernel(), crash());
    h.until_still("backoff", |h| h.state("a") == S::Backoff)
        .await;
    // In backoff: epoch 1 is fully reclaimed, nothing new is running.
    assert!(world.open_records("a").await.is_empty());
    assert!(world.sys.find(EffectKind::LinuxTun, &iface).is_none());
    assert_eq!(world.spawned().len(), 1);
    let status = h.status("a").unwrap();
    assert_eq!(status.restart_attempt, 1);
    assert!(status.next_restart_unix_ms > 0);

    // The delay (1 s for the first failure) then the next epoch.
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    let history = h.history("a");
    let pos = |s: S| history.iter().position(|x| *x == s).unwrap();
    assert!(pos(S::Reclaiming) < pos(S::Backoff), "{history:?}");
}

#[tokio::test]
async fn reclaim_retries_until_closed_before_restarting() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    world.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::LinuxTun)
            .times(2)
            .fail(ReclaimError::Busy("in use".into())),
    );
    world.engine.exit(&world.last_kernel(), crash());
    h.until("epoch 2 ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    // Epoch 2's kernel was spawned only after epoch 1's interface was gone.
    let seen = world.kernel.objects_at_spawn.lock().unwrap().clone();
    let iface = world.interface_key("a");
    assert!(
        !seen[1].iter().any(|o| o.kind == EffectKind::LinuxTun
            && etd_testkit::fakes::system::locates(&iface, &o.key)),
        "the old interface was still there when epoch 2 spawned"
    );
}
