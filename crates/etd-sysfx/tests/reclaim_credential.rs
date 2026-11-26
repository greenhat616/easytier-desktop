//! R1 acceptance: a third-party object created with our full derived name
//! is never deleted and is reported, in all three cases: ledger record with
//! the credential read back, ledger record still planned, ledger lost.
//!
//! With a credential on record, a different identity is a conflict (doc#2
//! v7: "名字相同但身份不符，记为冲突并报告"; F0's `EffectState::Conflict`); the
//! other two cases are candidates.
mod reclaim_support;

use etd_contract::{CandidateDecision, InstanceId, v1::CandidateAction};
use etd_sysfx::*;
use reclaim_support::{Fate, World};

fn tun_key(w: &World) -> ObjectKey {
    let name = w.name("a");
    ObjectKey::Interface {
        guid: Some(naming::wintun_guid(&name).to_string()),
        name: Some(name),
    }
}

fn tun_intent(w: &World) -> EffectIntent {
    EffectIntent {
        scope: EffectScope::Instance {
            instance: InstanceId::from("a"),
            epoch: Epoch(1),
        },
        kind: EffectKind::WinTunAdapter,
        key: tun_key(w),
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    }
}

#[tokio::test]
async fn recorded_credential_mismatch_is_a_conflict() {
    let w = World::new();
    w.add_instance("a").await;
    let effects = w.begin("a", vec![tun_intent(&w)]).await;
    w.settle(&effects[0], Fate::Applied).await;
    // Ours vanished; someone recreated the adapter with our exact name.
    w.sys
        .replace_with_foreign(EffectKind::WinTunAdapter, &tun_key(&w));
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert_eq!(w.sys.foreign().len(), 1);
    assert_eq!(report.conflicts.len(), 1);
    let conflict = &report.conflicts[0];
    assert!(conflict.expected.is_some());
    assert!(conflict.found.is_some());
    assert_ne!(conflict.expected, conflict.found);
    assert!(matches!(
        report.generations[0].outcome,
        GenerationOutcome::Quarantined(_)
    ));
    // The swept view does not list it a second time.
    assert!(report.candidates.is_empty());

    // A conflict can only be kept; KEEP releases the record.
    let delete = CandidateDecision {
        candidate_id: conflict.id.clone(),
        action: CandidateAction::Delete as i32,
    };
    engine.resolve(&[delete]).await.unwrap();
    assert_eq!(w.sys.foreign().len(), 1);
    assert_eq!(w.open().await.len(), 1);
    let keep = CandidateDecision {
        candidate_id: conflict.id.clone(),
        action: CandidateAction::Keep as i32,
    };
    engine.resolve(&[keep]).await.unwrap();
    assert!(w.open().await.is_empty());
    assert_eq!(w.sys.foreign().len(), 1);
}

#[tokio::test]
async fn a_foreign_utun_at_the_old_name_survives_reclaim_and_the_next_epoch() {
    let w = World::new();
    w.add_instance("a").await;
    let instance = InstanceId::from("a");
    let utun = |epoch| EffectIntent {
        scope: EffectScope::Instance {
            instance: instance.clone(),
            epoch: Epoch(epoch),
        },
        kind: EffectKind::MacUtun,
        key: ObjectKey::Interface {
            name: None,
            guid: None,
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::WithProcess,
    };
    let first = w.begin("a", vec![utun(1)]).await;
    w.settle(&first[0], Fate::Applied).await;
    let original = w.sys.ours().pop().unwrap();
    let replacement = w
        .sys
        .replace_with_foreign(EffectKind::MacUtun, &original.key);
    let foreign = w.sys.get(replacement).unwrap();
    assert_eq!(original.key, foreign.key);
    assert_ne!(original.credential, foreign.credential);

    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let [conflict] = report.conflicts.as_slice() else {
        panic!(
            "expected one interface identity conflict: {:?}",
            report.conflicts
        );
    };
    assert_eq!(conflict.expected, original.credential);
    assert_eq!(conflict.found, foreign.credential);
    assert_eq!(w.sys.objects().as_slice(), std::slice::from_ref(&foreign));
    engine
        .resolve(&[CandidateDecision {
            candidate_id: conflict.id.clone(),
            action: CandidateAction::Keep as i32,
        }])
        .await
        .unwrap();
    assert!(w.open().await.is_empty());

    let second = w.begin("a", vec![utun(2)]).await;
    w.settle(&second[0], Fate::Applied).await;
    let fresh = w.sys.ours().pop().unwrap();
    assert_ne!(fresh.key, foreign.key);
    assert_ne!(fresh.credential, foreign.credential);
    let reclaimed = engine
        .reclaim_generation(&instance, Epoch(2))
        .await
        .unwrap();
    assert_eq!(reclaimed.outcome, GenerationOutcome::Closed);
    assert_eq!(w.sys.objects(), [foreign]);
    assert!(w.sys.foreign_deleted().is_empty());
}

#[tokio::test]
async fn planned_record_with_foreign_object_is_a_candidate() {
    let w = World::new();
    w.add_instance("a").await;
    w.begin("a", vec![tun_intent(&w)]).await;
    // The record never got past "planned"; meanwhile someone else created
    // an adapter with the full derived name.
    w.sys.create_foreign(EffectKind::WinTunAdapter, tun_key(&w));
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert!(matches!(
        candidate.source,
        CandidateSource::PlannedRecord { .. }
    ));
    // Nothing the probe saw is stored as a deletion credential.
    assert_eq!(
        candidate
            .observation
            .as_ref()
            .and_then(|o| o.credential.clone()),
        None
    );
    // Re-running never deletes it either.
    engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    engine
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(w.sys.foreign().len(), 1);

    // The administrator says "not ours": the record is released.
    let keep = CandidateDecision {
        candidate_id: candidate.id.clone(),
        action: CandidateAction::Keep as i32,
    };
    let report = engine.resolve(&[keep]).await.unwrap();
    assert!(report.candidates.is_empty());
    assert!(w.open().await.is_empty());
    assert_eq!(w.sys.foreign().len(), 1);
}

#[tokio::test]
async fn ledger_lost_derived_name_is_a_candidate() {
    let w = World::new();
    w.add_instance("a").await;
    w.sys.create_foreign(EffectKind::WinTunAdapter, tun_key(&w));
    let report = w.engine().recover_without_ledger().await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(
        report.candidates[0].source,
        CandidateSource::Swept(FoundBy::DerivedName {
            instance: InstanceId::from("a")
        })
    );
}

#[tokio::test]
async fn planned_record_with_our_object_needs_a_decision() {
    // Even our own object is only a candidate while its record is planned:
    // the engine cannot tell it apart from a foreign one.
    let w = World::new();
    w.add_instance("a").await;
    let effects = w.begin("a", vec![tun_intent(&w)]).await;
    w.settle(&effects[0], Fate::PlannedPresent).await;
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert_eq!(w.sys.ours().len(), 1);
    assert_eq!(report.candidates.len(), 1);
    let delete = CandidateDecision {
        candidate_id: report.candidates[0].id.clone(),
        action: CandidateAction::Delete as i32,
    };
    let report = engine.resolve(&[delete]).await.unwrap();
    assert!(report.candidates.is_empty());
    w.assert_clean();
    assert!(w.open().await.is_empty());
}
