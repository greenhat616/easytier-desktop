//! The Windows driver services every kernel shares (wintun, WinDivert;
//! product scope, no creation credential upstream). If one is already
//! registered before the start, its record becomes a conflict: never
//! claimed, never removed. A driver the kernel loads is read back after the
//! spawn, so the next start does not take it for a third party's (ruling
//! topic#36 msg#932, G2 finding topic#42 msg#1143).
mod lifecycle_common;

use etd_contract::v1::event::Payload;
use etd_contract::{Desired, InstanceState as S};
use etd_sysfx::{Effect, EffectKind, EffectState, Ledger, ObjectKey, ScopeFilter};
use lifecycle_common::*;
use std::time::Duration;

const DRIVER: EffectKind = EffectKind::Driver;

fn with_drivers() -> World {
    let world = World::new();
    world.extras(PlanExtras {
        shared_drivers: true,
        ..PlanExtras::default()
    });
    world
}

/// The driver records in the ledger, by key order of [`shared_driver_keys`].
async fn records(world: &World) -> Vec<Effect> {
    let open = world
        .ledger
        .inner
        .open_effects(&ScopeFilter {
            product: true,
            kinds: vec![DRIVER],
            ..ScopeFilter::default()
        })
        .await
        .unwrap();
    shared_driver_keys()
        .iter()
        .map(|k| {
            let mine: Vec<_> = open.iter().filter(|e| &e.key == k).collect();
            assert_eq!(mine.len(), 1, "one record per driver {k:?}");
            mine[0].clone()
        })
        .collect()
}

/// The driver records once none waits for a read-back any more.
async fn settled(world: &World, h: &mut Host<'_>) -> Vec<Effect> {
    for _ in 0..100 {
        let now = records(world).await;
        if now.iter().all(|e| e.state != EffectState::Planned) {
            return now;
        }
        h.idle(Duration::from_millis(100), Duration::from_millis(100))
            .await;
    }
    panic!("driver records still planned: {:?}", records(world).await);
}

fn preexisting(h: &mut Host<'_>) -> usize {
    h.settle_sync();
    h.log
        .iter()
        .filter(|e| matches!(&e.payload, Payload::Notice(n) if n.code == "start.preexisting"))
        .count()
}

fn drivers_present(world: &World) -> usize {
    shared_driver_keys()
        .iter()
        .filter(|k| world.sys.find(DRIVER, k).is_some())
        .count()
}

#[tokio::test]
async fn drivers_the_kernel_loads_are_read_back_and_stay_ours() {
    let world = with_drivers();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let first = settled(&world, &mut h).await;
    for e in &first {
        assert_eq!(e.state, EffectState::Applied, "{:?}", e.key);
        let obs = e.observation.as_ref().expect("what was found is recorded");
        assert_eq!(obs.credential, None, "upstream has no driver credential");
    }

    // A normal stop leaves the shared drivers and their records.
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    assert_eq!(drivers_present(&world), 2);
    let after_stop = records(&world).await;
    assert!(after_stop.iter().all(|e| e.state == EffectState::Applied));

    // The next start finds our own drivers: not a third party's.
    h.set_desired("a", Desired::Running).await.unwrap();
    h.until("second generation ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(preexisting(&mut h), 0);
    let second = records(&world).await;
    for (a, b) in first.iter().zip(&second) {
        assert_eq!(a.id, b.id, "the same shared record");
        assert_eq!(b.state, EffectState::Applied);
    }
    assert!(world.sys.deleted().iter().all(|d| d.object.kind != DRIVER));
}

#[tokio::test]
async fn a_driver_registered_before_the_start_is_a_conflict_never_claimed() {
    let world = with_drivers();
    let wintun = ObjectKey::Service {
        name: "wintun".into(),
    };
    let foreign = world.sys.create_foreign(DRIVER, wintun.clone());
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    let [wintun_record, windivert_record] =
        <[Effect; 2]>::try_from(settled(&world, &mut h).await).unwrap();
    assert_eq!(wintun_record.key, wintun);
    assert_eq!(wintun_record.state, EffectState::Conflict);
    assert_eq!(preexisting(&mut h), 1);
    // The one the kernel loaded itself is read back as usual.
    assert_eq!(windivert_record.state, EffectState::Applied);

    // Stopping, and starting again, never claims or removes it.
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    h.set_desired("a", Desired::Running).await.unwrap();
    h.until("second generation ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    let again = records(&world).await;
    assert_eq!(again[0].id, wintun_record.id);
    assert_eq!(again[0].state, EffectState::Conflict);
    assert!(
        world.sys.get(foreign).is_some(),
        "the third party's driver stays"
    );
    assert!(world.sys.deleted().iter().all(|d| d.object.kind != DRIVER));
}
