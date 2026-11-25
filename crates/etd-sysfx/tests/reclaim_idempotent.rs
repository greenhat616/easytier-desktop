//! R1 acceptance: the same recovery twice writes nothing the second time;
//! after a boot-id change volatile records close without a probe.
mod reclaim_support;

use etd_sysfx::*;
use etd_testkit::fakes::system::{Fault, Step};
use reclaim_support::{Fate, World};

#[tokio::test]
async fn second_recovery_performs_no_system_write() {
    let w = World::new();
    w.running("a").await;
    w.running("b").await;
    let first = w
        .engine()
        .reclaim_all(ReclaimScope::Instances)
        .await
        .unwrap();
    assert_eq!(first.generations.len(), 2);
    assert!(
        first
            .generations
            .iter()
            .all(|g| g.outcome == GenerationOutcome::Closed)
    );
    w.assert_clean();
    let writes = w.sys.stats().write_calls;
    let mutations = w.sys.stats().mutations;
    let second = w
        .engine()
        .reclaim_all(ReclaimScope::Instances)
        .await
        .unwrap();
    assert_eq!(w.sys.stats().write_calls, writes);
    assert_eq!(w.sys.stats().mutations, mutations);
    assert!(second.generations.is_empty());
    assert!(second.candidates.is_empty());
}

#[tokio::test]
async fn reboot_closes_volatile_records_unprobed() {
    let w = World::new();
    w.add_instance("a").await;
    let effects = w.begin("a", w.windows_intents("a", 1)).await;
    for e in &effects {
        w.settle(e, Fate::Applied).await;
    }
    w.sys.reboot();
    // Any probe of a volatile kind would now be indeterminate.
    for kind in [EffectKind::Process, EffectKind::Route] {
        w.sys.inject(Fault::on(Step::Probe).kind(kind));
    }
    let report = w
        .engine()
        .reclaim_all(ReclaimScope::Instances)
        .await
        .unwrap();
    assert_eq!(report.generations[0].outcome, GenerationOutcome::Closed);
    let probed: Vec<_> = w
        .sys
        .ops()
        .into_iter()
        .filter(|o| o.step == Step::Probe)
        .filter_map(|o| o.kind)
        .collect();
    assert!(!probed.contains(&EffectKind::Process));
    assert!(!probed.contains(&EffectKind::Route));
    // Persistent ones were probed and removed.
    assert!(probed.contains(&EffectKind::WinFirewallRule));
    w.assert_clean();
    assert!(w.open().await.is_empty());
}
