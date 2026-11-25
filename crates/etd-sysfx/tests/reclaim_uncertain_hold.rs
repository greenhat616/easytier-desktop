//! Rulings msg#557 / msg#567: the process record is reclaimed first, and while
//! it is not closed (quarantined, indeterminate, pending or a candidate) no
//! other rank of that generation is touched (the kernel may still own its
//! objects and would fight or recreate them). A retry once the kernel is
//! verified dead reclaims everything.
mod reclaim_support;

use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_testkit::fakes::system::{Fault, Step};
use reclaim_support::World;

#[tokio::test]
async fn uncertain_process_holds_every_rank() {
    let w = World::new();
    w.running("a").await;
    let a = InstanceId::from("a");
    let before = w.sys.ours().len();
    let writes = w.sys.stats().write_calls;
    w.sys
        .inject(Fault::on(Step::Probe).kind(EffectKind::Process));
    let engine = w.engine();

    let report = engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    assert!(
        matches!(report.outcome, GenerationOutcome::Quarantined(_)),
        "{report:?}"
    );
    // Nothing of the generation was touched, not even the lowest rank.
    assert_eq!(w.sys.stats().write_calls, writes);
    assert!(w.sys.deleted().is_empty());
    assert_eq!(w.sys.ours().len(), before);
    let open = w
        .memory
        .open_effects(&ScopeFilter::epoch(a.clone(), Epoch(1)))
        .await
        .unwrap();
    assert!(
        open.iter()
            .any(|e| e.kind == EffectKind::Process && e.state == EffectState::Quarantined)
    );
    assert!(
        open.iter()
            .filter(|e| e.kind != EffectKind::Process)
            .all(|e| e.state == EffectState::Applied),
        "lower ranks are not even moved to reclaiming: {open:?}"
    );
    let notes = engine.report().await.unwrap().notes;
    assert!(
        notes
            .iter()
            .any(|n| n.contains("waiting for the kernel process")),
        "{notes:?}"
    );

    // Quarantined: still held on the next run and in a full pass.
    w.sys.clear_faults();
    engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert_eq!(w.sys.stats().write_calls, writes);

    // Kernel verified dead: a retry reclaims the whole generation.
    let report = engine.retry(&a).await.unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed, "{report:?}");
    w.assert_clean();
}

#[tokio::test]
async fn manual_delete_waits_for_the_process_record() {
    let w = World::new();
    w.running("a").await;
    let a = InstanceId::from("a");
    w.sys
        .inject(Fault::on(Step::Probe).kind(EffectKind::Process));
    let engine = w.engine();
    engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    w.sys.clear_faults();

    // Another record of the generation turned candidate (by hand: the
    // automatic path never reaches it while the process is held).
    let open = w
        .memory
        .open_effects(&ScopeFilter::epoch(a.clone(), Epoch(1)))
        .await
        .unwrap();
    let (record, found) = open
        .iter()
        .filter(|e| e.kind != EffectKind::Process)
        .find_map(|e| w.sys.find(e.kind, &e.key).map(|o| (e.clone(), o)))
        .expect("an object of the generation");
    w.memory
        .transition(&record.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    w.memory
        .transition(
            &record.id,
            EffectState::Candidate,
            Some(Observation {
                credential: None,
                key: Some(found.key.clone()),
                observed_at: jiff::Timestamp::now(),
                detail: None,
            }),
        )
        .await
        .unwrap();
    let id = engine
        .report()
        .await
        .unwrap()
        .candidates
        .iter()
        .find(|c| c.kind == record.kind)
        .unwrap()
        .id
        .clone();
    let writes = w.sys.stats().write_calls;
    let report = engine
        .resolve(&[etd_contract::CandidateDecision {
            candidate_id: id,
            action: etd_contract::v1::CandidateAction::Delete as i32,
        }])
        .await
        .unwrap();
    assert!(
        report.notes.iter().any(|n| n.contains("not verified dead")),
        "{:?}",
        report.notes
    );
    assert_eq!(w.sys.stats().write_calls, writes);
    assert!(w.sys.find(record.kind, &record.key).is_some());
}
