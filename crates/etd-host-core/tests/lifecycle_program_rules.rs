//! The Windows program firewall rules a kernel deletes and recreates on
//! every start (core-binary scope, ruling topic#36 msg#931): before the
//! spawn they must be absent or exactly as recorded, else the start is
//! refused (the kernel would overwrite a third-party rule); after basic
//! readiness the record takes the new credential only from a single rule
//! of that name, else it becomes a conflict and nothing is deleted. Starts
//! of one kernel that replace them take turns. Also: the routes record of a
//! system-assigned interface carries that interface's credential.
mod lifecycle_common;

use etd_contract::v1::event::Payload;
use etd_contract::{Desired, InstanceState as S};
use etd_proc::{Liveness, ProcessEngine};
use etd_sysfx::{
    Credential, Effect, EffectKind, EffectState, Ledger, ObjectKey, ReclaimError, ScopeFilter,
};
use etd_testkit::fakes::system::{Fault, Owner, Step};
use lifecycle_common::*;
use std::time::Duration;

const RULE: EffectKind = EffectKind::WinProgramFirewallRule;

fn with_rules() -> World {
    let world = World::new();
    world.extras(PlanExtras {
        program_rules: true,
        ..PlanExtras::default()
    });
    world
}

fn keys(world: &World) -> Vec<ObjectKey> {
    program_rule_keys(&world.store.binary)
}

/// The program-rule records in the ledger, by key order of [`keys`].
async fn records(world: &World) -> Vec<Effect> {
    let open = world
        .ledger
        .inner
        .open_effects(&ScopeFilter {
            core_binary: true,
            kinds: vec![RULE],
            ..ScopeFilter::default()
        })
        .await
        .unwrap();
    keys(world)
        .iter()
        .map(|k| {
            open.iter()
                .find(|e| &e.key == k)
                .cloned()
                .expect("a record per rule")
        })
        .collect()
}

fn credential(e: &Effect) -> Option<Credential> {
    e.observation.as_ref().and_then(|o| o.credential.clone())
}

/// The rules of that name in the fake system, oldest first.
fn rules_named(world: &World, key: &ObjectKey) -> Vec<etd_testkit::fakes::system::FakeObject> {
    world
        .sys
        .objects()
        .into_iter()
        .filter(|o| o.kind == RULE && &o.key == key)
        .collect()
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

/// Every record holds exactly the credential of the single rule now there.
async fn assert_records_current(world: &World) {
    for (e, key) in records(world).await.iter().zip(keys(world)) {
        let found = rules_named(world, &key);
        assert_eq!(found.len(), 1, "one rule named {key:?}");
        assert_eq!(e.state, EffectState::Applied, "{key:?}");
        assert_eq!(credential(e), found[0].credential, "{key:?}");
    }
}

/// The program-rule records once `done` holds for all of them (fake time
/// moves on meanwhile).
async fn until_records(
    world: &World,
    h: &mut Host<'_>,
    done: impl Fn(&Effect) -> bool,
) -> Vec<Effect> {
    for _ in 0..200 {
        let now = records(world).await;
        if now.iter().all(&done) {
            return now;
        }
        h.idle(Duration::from_millis(100), Duration::from_millis(100))
            .await;
    }
    panic!(
        "program rule records never settled: {:?}",
        records(world).await
    );
}

/// The observer fails for program rules (transiently: `times`, or until
/// cleared) from right after the next spawn on.
fn observer_fails_after_spawn(world: &World, times: Option<u32>) {
    let fault = Fault::on(Step::Observe).kind(RULE);
    let fault = match times {
        Some(n) => fault.times(n),
        None => fault,
    };
    world
        .kernel
        .faults_after_spawn
        .lock()
        .unwrap()
        .push(fault.fail(ReclaimError::Os {
            code: 1460,
            message: "timeout".into(),
        }));
}

fn host_deleted_a_rule(world: &World) -> bool {
    world.sys.deleted().iter().any(|d| d.object.kind == RULE)
}

#[tokio::test]
async fn absent_rules_are_read_back_after_readiness() {
    let world = with_rules();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    assert_records_current(&world).await;
    assert!(!host_deleted_a_rule(&world));
}

#[tokio::test]
async fn our_rules_are_refreshed_when_the_next_start_replaces_them() {
    let world = with_rules();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let first: Vec<_> = records(&world).await.iter().map(credential).collect();

    // Stopping reclaims the generation; the shared rules stay.
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    assert_eq!(
        records(&world)
            .await
            .iter()
            .map(credential)
            .collect::<Vec<_>>(),
        first
    );

    // The next start is ours to replace them: the kernel recreates them with
    // new identities, and the records follow.
    h.set_desired("a", Desired::Running).await.unwrap();
    h.until("second generation ready", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    let second: Vec<_> = records(&world).await.iter().map(credential).collect();
    for (a, b) in first.iter().zip(&second) {
        assert!(a.is_some() && b.is_some());
        assert_ne!(a, b, "the stale credential was refreshed");
    }
    assert_records_current(&world).await;
    assert!(!host_deleted_a_rule(&world));
    assert!(notices(&mut h, "start.refused").is_empty());
}

#[tokio::test]
async fn a_rule_we_never_recorded_refuses_the_start() {
    let world = with_rules();
    let foreign = world.sys.create_foreign(RULE, keys(&world)[1].clone());
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::GaveUp).await;

    assert!(world.spawned().is_empty(), "nothing was spawned");
    assert!(
        world.sys.get(foreign).is_some(),
        "the third-party rule is left alone"
    );
    assert!(!notices(&mut h, "start.refused").is_empty());
    assert!(
        records(&world)
            .await
            .iter()
            .all(|e| e.state == EffectState::Planned),
        "nothing is claimed"
    );

    // Once the administrator removed it, a retry starts.
    world.sys.vanish(RULE, &keys(&world)[1]);
    h.retry_start("a").await;
    h.wait_state("a", S::ReadyFull).await;
    assert_records_current(&world).await;
}

#[tokio::test]
async fn a_rule_with_another_identity_than_recorded_refuses_the_start() {
    let world = with_rules();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;

    // Someone replaced our rule while the kernel was stopped.
    let foreign = world.sys.replace_with_foreign(RULE, &keys(&world)[0]);
    h.set_desired("a", Desired::Running).await.unwrap();
    h.wait_state("a", S::GaveUp).await;

    assert_eq!(world.spawned().len(), 1, "no second kernel");
    assert_eq!(world.sys.get(foreign).unwrap().owner, Owner::Foreign);
    assert!(!notices(&mut h, "start.refused").is_empty());
}

#[tokio::test]
async fn several_rules_of_the_name_after_readiness_are_a_conflict() {
    let world = with_rules();
    world.behave(KernelBehaviour {
        duplicate_program_rules: true,
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    // Foreign only once a second snapshot, `reclaim_retry` later, agrees.
    let settled = until_records(&world, &mut h, |e| e.state != EffectState::Planned).await;
    for (e, key) in settled.iter().zip(keys(&world)) {
        assert_eq!(e.state, EffectState::Conflict, "{key:?}");
        assert_eq!(credential(e), None, "nothing of theirs is recorded as ours");
        assert_eq!(rules_named(&world, &key).len(), 2, "both rules stay");
    }
    assert!(!host_deleted_a_rule(&world));
    assert_eq!(notices(&mut h, "program_rule.conflict").len(), 2);
    // The kernel itself keeps running.
    assert_eq!(
        world.engine.liveness(&world.last_kernel()).await,
        Liveness::Same
    );
    assert_eq!(h.state("a"), S::ReadyFull);
}

#[tokio::test]
async fn starts_of_one_kernel_take_turns() {
    let world = with_rules();
    let mut h = world.start();
    h.wait_serving().await;
    for round in 1..=2u64 {
        h.apply("a", spec("net-a"), Desired::Running).await;
        h.apply("b", spec("net-b"), Desired::Running).await;
        h.until("both ready", |h| {
            ["a", "b"].iter().all(|i| h.state(i) == S::ReadyFull)
        })
        .await;
        assert_records_current(&world).await;
        assert!(notices(&mut h, "start.refused").is_empty(), "round {round}");
        assert!(notices(&mut h, "program_rule.conflict").is_empty());
        h.set_desired("a", Desired::Stopped).await.unwrap();
        h.set_desired("b", Desired::Stopped).await.unwrap();
        h.until("both stopped", |h| {
            ["a", "b"].iter().all(|i| h.state(i) == S::Stopped)
        })
        .await;
    }
    assert_eq!(world.spawned().len(), 4);
    assert!(!host_deleted_a_rule(&world));
}

#[tokio::test]
async fn an_unreadable_rule_before_the_start_is_retried_not_taken_as_absent() {
    let world = with_rules();
    world.sys.inject(
        Fault::on(Step::Observe)
            .kind(RULE)
            .once()
            .fail(ReclaimError::Os {
                code: 5,
                message: "transient".into(),
            }),
    );
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.until("ready after a retry", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(
        world.spawned().len(),
        1,
        "the first attempt spawned nothing"
    );
    assert!(notices(&mut h, "start.refused").is_empty());
    assert_records_current(&world).await;
}

#[tokio::test]
async fn routes_of_an_assigned_interface_carry_its_credential() {
    let world = World::new();
    world.driver.set_interface_kind(EffectKind::MacUtun);
    world.extras(PlanExtras {
        assigned_name: true,
        ..PlanExtras::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    let utun = world
        .sys
        .objects()
        .into_iter()
        .find(|o| o.kind == EffectKind::MacUtun)
        .expect("the kernel's utun");
    let ObjectKey::Interface {
        name: Some(name), ..
    } = &utun.key
    else {
        panic!("utun without a name: {:?}", utun.key);
    };
    let open = world.open_records("a").await;
    let routes = open
        .iter()
        .find(|e| e.kind == EffectKind::Route)
        .expect("routes record");
    assert_eq!(routes.state, EffectState::Applied);
    let obs = routes.observation.as_ref().unwrap();
    assert_eq!(
        obs.key,
        Some(ObjectKey::RoutesVia {
            interface: Some(name.clone())
        })
    );
    assert!(utun.credential.is_some());
    assert_eq!(
        obs.credential, utun.credential,
        "the interface's credential"
    );
}

#[tokio::test]
async fn a_read_back_that_errs_once_is_retried_not_a_conflict() {
    let world = with_rules();
    observer_fails_after_spawn(&world, Some(1));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    until_records(&world, &mut h, |e| e.state == EffectState::Applied).await;
    assert_records_current(&world).await;
    assert!(notices(&mut h, "program_rule.conflict").is_empty());
}

#[tokio::test]
async fn our_rule_that_errs_once_before_the_start_backs_off_then_starts() {
    let world = with_rules();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    until_records(&world, &mut h, |e| e.state == EffectState::Applied).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;

    // Our rules are there; the observer fails once on the way.
    world.sys.inject(
        Fault::on(Step::Observe)
            .kind(RULE)
            .once()
            .fail(ReclaimError::Os {
                code: 1460,
                message: "timeout".into(),
            }),
    );
    h.set_desired("a", Desired::Running).await.unwrap();
    h.until("ready after a backoff", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch >= 3 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(
        world.spawned().len(),
        2,
        "the failed attempt spawned nothing"
    );
    assert!(notices(&mut h, "start.refused").is_empty());
    assert!(notices(&mut h, "program_rule.conflict").is_empty());
    until_records(&world, &mut h, |e| e.state == EffectState::Applied).await;
    assert_records_current(&world).await;
}

#[tokio::test]
async fn another_start_waits_while_rules_are_unsettled() {
    let world = with_rules();
    observer_fails_after_spawn(&world, None);
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net-a"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;

    // a cannot read its rules back yet: b's start waits for the gate.
    h.apply("b", spec("net-b"), Desired::Running).await;
    h.idle(Duration::from_millis(250), Duration::from_secs(3))
        .await;
    assert_eq!(world.spawned().len(), 1, "b waits");
    assert!(
        h.status("b")
            .is_some_and(|s| s.message.contains("waiting for another start")),
        "{:?}",
        h.status("b")
    );

    // Once a's rules are read back, b goes ahead.
    world.sys.clear_faults();
    h.until("both ready", |h| {
        ["a", "b"].iter().all(|i| h.state(i) == S::ReadyFull)
    })
    .await;
    until_records(&world, &mut h, |e| e.state == EffectState::Applied).await;
    assert_records_current(&world).await;
    assert!(notices(&mut h, "start.refused").is_empty());
    assert!(notices(&mut h, "program_rule.conflict").is_empty());
}

#[tokio::test]
async fn rules_still_unknown_at_the_deadline_are_left_as_they_were() {
    let world = with_rules();
    observer_fails_after_spawn(&world, None);
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net-a"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    // start_timeout (10 s) after basic readiness.
    h.idle(Duration::from_millis(500), Duration::from_secs(12))
        .await;

    assert_eq!(notices(&mut h, "program_rule.unsettled").len(), 1);
    assert!(notices(&mut h, "program_rule.conflict").is_empty());
    assert!(
        records(&world)
            .await
            .iter()
            .all(|e| e.state == EffectState::Planned),
        "nothing claimed, nothing refreshed"
    );
    assert_eq!(h.state("a"), S::ReadyFull, "the kernel keeps running");

    // The gate is free again: the next start is decided, not kept waiting
    // (refused: the rules there are not the ones recorded).
    world.sys.clear_faults();
    h.apply("b", spec("net-b"), Desired::Running).await;
    h.wait_state("b", S::GaveUp).await;
    assert!(!notices(&mut h, "start.refused").is_empty());
    assert_eq!(world.spawned().len(), 1);
    assert!(!host_deleted_a_rule(&world));
}

#[tokio::test]
async fn a_cut_while_waiting_for_the_gate_spawns_nothing() {
    let world = with_rules();
    observer_fails_after_spawn(&world, None);
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net-a"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.apply("b", spec("net-b"), Desired::Running).await;
    h.idle(Duration::from_millis(250), Duration::from_secs(1))
        .await;

    h.cut("b").await.unwrap();
    world.sys.clear_faults();
    h.idle(Duration::from_millis(250), Duration::from_secs(3))
        .await;
    assert_eq!(world.spawned().len(), 1, "b never spawned");
    until_records(&world, &mut h, |e| e.state == EffectState::Applied).await;
    assert_records_current(&world).await;
}

#[tokio::test]
async fn a_shutdown_while_waiting_for_the_gate_completes() {
    let world = with_rules();
    observer_fails_after_spawn(&world, None);
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net-a"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.apply("b", spec("net-b"), Desired::Running).await;
    h.idle(Duration::from_millis(250), Duration::from_secs(1))
        .await;

    h.shutdown().await;
    assert_eq!(world.spawned().len(), 1, "b never spawned");
}
