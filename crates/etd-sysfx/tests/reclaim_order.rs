//! R1 acceptance: reclaim order is DNS and firewall -> registry -> interface
//! -> routes -> runtime directory -> process record -> fence, and the fence
//! waits for the kernel process record.
mod reclaim_support;

use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_testkit::fakes::system::{Fault, Step};
use reclaim_support::World;

#[tokio::test]
async fn ranks_are_reclaimed_in_dependency_order() {
    let w = World::new();
    w.running("a").await;
    let report = w
        .engine()
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed);
    use EffectKind::*;
    assert_eq!(
        w.sys.reclaim_order(),
        vec![
            WinFirewallRule,
            WinFirewallRule,
            WinRegistryValue,
            WinTunAdapter,
            Route,
            RuntimeDir,
            Process,
            WinFenceFilter
        ]
    );
    w.assert_clean();
    assert!(w.open().await.is_empty());
}

#[tokio::test]
async fn fence_stays_until_the_process_record_closes() {
    let w = World::new();
    w.running("a").await;
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::Process)
            .fail(ReclaimError::Busy("still running".into())),
    );
    let engine = w.engine();
    let report = engine
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Pending);
    assert!(!w.sys.reclaim_order().contains(&EffectKind::WinFenceFilter));
    let left: Vec<_> = w.sys.ours().iter().map(|o| o.kind).collect();
    assert_eq!(left, vec![EffectKind::Process, EffectKind::WinFenceFilter]);

    w.sys.clear_faults();
    let report = engine
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed);
    w.assert_clean();
}

#[tokio::test]
async fn a_failing_rank_holds_back_higher_ranks() {
    let w = World::new();
    w.running("a").await;
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinRegistryValue)
            .fail(ReclaimError::PermissionDenied("x".into())),
    );
    let report = w
        .engine()
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Pending);
    use EffectKind::*;
    assert_eq!(
        w.sys.reclaim_order(),
        vec![WinFirewallRule, WinFirewallRule, WinRegistryValue]
    );
    // Registry, interface, route, runtime dir, process, fence remain.
    assert_eq!(report.residues.len(), 6);
}
