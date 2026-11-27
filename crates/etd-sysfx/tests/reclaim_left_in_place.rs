//! A reclaimer's answer that an object stays where it is, without a failure:
//! `HeldBy` (proven held by another owner) makes the record a conflict,
//! `NotDeletable` (ours, never deleted by that reclaimer) a candidate. Both
//! close by themselves once the object is gone, never count towards
//! quarantine, and keep the generation open exactly as any other conflict or
//! candidate does (topic#59 msg#1766, msg#1768).
mod reclaim_support;

use etd_contract::{CandidateDecision, InstanceId, v1::CandidateAction};
use etd_sysfx::*;
use etd_testkit::fakes::system::{Fault, Step};
use reclaim_support::{Fate, World};

fn scope() -> EffectScope {
    EffectScope::Instance {
        instance: InstanceId::from("a"),
        epoch: Epoch(1),
    }
}

fn magic_dns_key() -> ObjectKey {
    ObjectKey::Registry {
        key: r"HKLM\SOFTWARE\EasyTier\MagicDNS".into(),
        value: None,
    }
}

fn tun_key(w: &World) -> ObjectKey {
    let name = w.name("a");
    ObjectKey::Interface {
        guid: Some(naming::wintun_guid(&name).to_string()),
        name: Some(name),
    }
}

/// Instance `a`, epoch 1, with one applied record.
async fn applied(w: &World, kind: EffectKind, key: ObjectKey, undo: Undo) -> Effect {
    w.add_instance("a").await;
    let effects = w
        .begin(
            "a",
            vec![EffectIntent {
                scope: scope(),
                kind,
                key,
                undo,
                persistence: Persistence::Persistent,
            }],
        )
        .await;
    w.settle(&effects[0], Fate::Applied).await;
    effects[0].clone()
}

async fn record(w: &World, e: &Effect) -> Effect {
    w.open()
        .await
        .into_iter()
        .find(|r| r.id == e.id)
        .expect("record still open")
}

#[tokio::test]
async fn held_by_is_a_conflict_that_closes_once_the_object_is_gone() {
    let w = World::new();
    let e = applied(
        &w,
        EffectKind::WinMagicDnsRecovery,
        magic_dns_key(),
        Undo::ReplayUpstreamRecovery,
    )
    .await;
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinMagicDnsRecovery)
            .fail(ReclaimError::HeldBy(
                r"easytier-core.exe pid=7 image C:\Other\easytier-core.exe".into(),
            )),
    );
    let engine = w.engine();
    let a = InstanceId::from("a");
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    // Left in place and reported with its holder; the generation stays open
    // as for any conflict.
    assert_eq!(w.sys.ours().len(), 1);
    assert_eq!(report.conflicts.len(), 1, "{report:?}");
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains(r"held by easytier-core.exe pid=7 image C:\Other")),
        "{:?}",
        report.notes
    );
    assert!(matches!(
        report.generations[0].outcome,
        GenerationOutcome::Quarantined(ref why) if why.contains("conflict")
    ));
    let held = record(&w, &e).await;
    assert_eq!(held.state, EffectState::Conflict);
    assert_eq!(held.failures, 0);

    // Re-probed on every run, never handed to the reclaimer again, never
    // counted.
    let writes = w.sys.stats().write_calls;
    for _ in 0..=QUARANTINE_AFTER {
        engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    }
    assert_eq!(w.sys.stats().write_calls, writes);
    let held = record(&w, &e).await;
    assert_eq!(held.state, EffectState::Conflict);
    assert_eq!(held.failures, 0);

    // The holder cleaned the key: the record closes by itself.
    assert!(
        w.sys
            .vanish(EffectKind::WinMagicDnsRecovery, &magic_dns_key())
    );
    let report = engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed);
    assert!(w.open().await.is_empty());
}

/// Once an attempt began, the ledger cannot prove the object unchanged,
/// whatever the reclaimer observes now (a value changed, then restored by
/// someone else, looks untouched): HeldBy then counts as a failure.
#[tokio::test]
async fn held_by_after_an_earlier_attempt_is_a_failure() {
    let w = World::new();
    let e = applied(
        &w,
        EffectKind::WinMagicDnsRecovery,
        magic_dns_key(),
        Undo::ReplayUpstreamRecovery,
    )
    .await;
    let engine = w.engine();
    let a = InstanceId::from("a");
    // An earlier attempt: refused part-way (a crash would leave the same
    // durable mark, `Reclaiming`, without a failure).
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinMagicDnsRecovery)
            .once()
            .fail(ReclaimError::Busy("replay interrupted".into())),
    );
    engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    assert_eq!(record(&w, &e).await.state, EffectState::Reclaiming);
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinMagicDnsRecovery)
            .fail(ReclaimError::HeldBy("easytier-core.exe pid=7".into())),
    );
    for _ in 1..QUARANTINE_AFTER {
        engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    }
    let held = record(&w, &e).await;
    assert_eq!(held.state, EffectState::Quarantined);
    assert_eq!(held.failures, QUARANTINE_AFTER);
    assert!(
        held.last_error
            .as_deref()
            .is_some_and(|m| m.contains("an earlier attempt may have changed it")),
        "{held:?}"
    );
}

#[tokio::test]
async fn not_deletable_is_a_candidate_never_retried_towards_quarantine() {
    let w = World::new();
    let e = applied(
        &w,
        EffectKind::WinTunAdapter,
        tun_key(&w),
        Undo::EnsureAbsent,
    )
    .await;
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinTunAdapter)
            .fail(ReclaimError::NotDeletable("live adapter".into())),
    );
    let engine = w.engine();
    let a = InstanceId::from("a");
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert_eq!(w.sys.ours().len(), 1);
    assert!(report.conflicts.is_empty(), "{report:?}");
    assert_eq!(report.candidates.len(), 1, "{report:?}");
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("not deleted (live adapter)")),
        "{:?}",
        report.notes
    );
    assert!(matches!(
        report.generations[0].outcome,
        GenerationOutcome::Quarantined(ref why) if why.contains("candidate")
    ));
    let held = record(&w, &e).await;
    assert_eq!(held.state, EffectState::Candidate);
    assert_eq!(held.failures, 0);
    // Our credential stays out of the record's authority: only the detail
    // carries it, for an administrator's decision.
    assert!(held.observation.as_ref().unwrap().credential.is_none());

    let writes = w.sys.stats().write_calls;
    for _ in 0..=QUARANTINE_AFTER {
        engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    }
    assert_eq!(w.sys.stats().write_calls, writes);
    assert_eq!(record(&w, &e).await.state, EffectState::Candidate);

    // An administrator's DELETE meets the same answer: the record stays a
    // candidate, with a note and without a failure.
    let delete = CandidateDecision {
        candidate_id: report.candidates[0].id.clone(),
        action: CandidateAction::Delete as i32,
    };
    let report = engine.resolve(&[delete]).await.unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("delete refused, not deletable: live adapter")),
        "{:?}",
        report.notes
    );
    assert_eq!(w.sys.ours().len(), 1);
    let held = record(&w, &e).await;
    assert_eq!(held.state, EffectState::Candidate);
    assert_eq!(held.failures, 0);
    assert_eq!(report.candidates.len(), 1, "{report:?}");

    // Gone: the record closes by itself.
    assert!(w.sys.vanish(EffectKind::WinTunAdapter, &tun_key(&w)));
    let report = engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed);
    assert!(w.open().await.is_empty());
}

#[tokio::test]
async fn other_reclaim_errors_still_count_towards_quarantine() {
    let w = World::new();
    let e = applied(
        &w,
        EffectKind::WinMagicDnsRecovery,
        magic_dns_key(),
        Undo::ReplayUpstreamRecovery,
    )
    .await;
    // An unprovable holder stays Busy.
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinMagicDnsRecovery)
            .fail(ReclaimError::Busy("cannot read candidate".into())),
    );
    let engine = w.engine();
    let a = InstanceId::from("a");
    for _ in 0..QUARANTINE_AFTER {
        engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    }
    let held = record(&w, &e).await;
    assert_eq!(held.state, EffectState::Quarantined);
    assert_eq!(held.failures, QUARANTINE_AFTER);
}
