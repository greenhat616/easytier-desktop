//! R1 acceptance: five consecutive failures quarantine the record and the
//! generation stays open; an uncertain process quarantines at once; a retry
//! resets and runs again.
mod reclaim_support;

use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_testkit::fakes::system::{Fault, Step};
use reclaim_support::World;

#[tokio::test]
async fn five_failures_quarantine_and_keep_the_epoch_open() {
    let w = World::new();
    w.running("a").await;
    let a = InstanceId::from("a");
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinTunAdapter)
            .fail(ReclaimError::Busy("in use".into())),
    );
    let engine = w.engine();
    for run in 1..=QUARANTINE_AFTER {
        let report = engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
        if run < QUARANTINE_AFTER {
            assert_eq!(report.outcome, GenerationOutcome::Pending, "run {run}");
        } else {
            assert!(
                matches!(report.outcome, GenerationOutcome::Quarantined(_)),
                "run {run}: {report:?}"
            );
        }
    }
    let quarantined = w
        .memory
        .open_effects(&ScopeFilter {
            states: vec![EffectState::Quarantined],
            ..ScopeFilter::all()
        })
        .await
        .unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].failures, QUARANTINE_AFTER);

    // The generation is not closed: the next one may not start.
    let next = w.memory.next_epoch(&a).await.unwrap();
    assert_eq!(next, Epoch(2));
    let inputs = w
        .memory
        .generation(&a, Epoch(1))
        .await
        .unwrap()
        .unwrap()
        .inputs;
    let err = w
        .memory
        .begin_epoch(GenerationPlan {
            instance: a.clone(),
            epoch: next,
            inputs,
            claims: vec![],
            effects: vec![w.process_intent("a", next.0)],
        })
        .await
        .unwrap_err();
    assert!(matches!(err, LedgerError::EpochOpen { .. }), "{err:?}");

    // Quarantined records are left alone until a retry.
    let writes = w.sys.stats().write_calls;
    engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    assert_eq!(w.sys.stats().write_calls, writes);
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert!(matches!(
        report.generations[0].outcome,
        GenerationOutcome::Quarantined(_)
    ));

    w.sys.clear_faults();
    let report = engine.retry(&a).await.unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed);
    w.assert_clean();
}

#[tokio::test]
async fn uncertain_process_liveness_quarantines_at_once() {
    let w = World::new();
    w.running("a").await;
    w.sys
        .inject(Fault::on(Step::Probe).kind(EffectKind::Process));
    let report = w
        .engine()
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert!(matches!(report.outcome, GenerationOutcome::Quarantined(_)));
    // The fence never comes down while the kernel may be alive.
    assert!(
        w.sys
            .ours()
            .iter()
            .any(|o| o.kind == EffectKind::WinFenceFilter)
    );
    let residue = report
        .residues
        .iter()
        .find(|r| r.kind == EffectKind::Process)
        .unwrap();
    assert!(matches!(residue.reason, ResidueReason::Indeterminate(_)));
}
