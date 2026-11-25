//! R1 acceptance: third-party objects carrying the product prefix are never
//! deleted, with or without a ledger, and show up as candidates.
mod reclaim_support;

use etd_sysfx::*;
use etd_testkit::fakes::system::FENCE_CONTAINER;
use reclaim_support::World;

fn foreign_set(w: &World) {
    w.sys.create_foreign(
        EffectKind::WinTunAdapter,
        ObjectKey::Interface {
            name: Some("etd-0badf00d".into()),
            guid: None,
        },
    );
    w.sys.create_foreign(
        EffectKind::WinFirewallRule,
        ObjectKey::Rule {
            name: "EasyTier etd-0badf00d - TCP Protocol (Inbound)".into(),
            group: Some("EasyTier".into()),
        },
    );
    w.sys.create_foreign(
        EffectKind::LinuxResolvedLink,
        ObjectKey::ResolvedLink {
            interface: "etd-0badf00d".into(),
        },
    );
}

#[tokio::test]
async fn ledger_lost_zero_foreign_deletions() {
    let w = World::new();
    w.add_instance("a").await;
    foreign_set(&w);
    // An orphan of ours in an exclusive container is cleaned.
    w.sys.create_ours(
        EffectKind::WinFenceFilter,
        ObjectKey::Fence {
            container: FENCE_CONTAINER.into(),
            rule: "a-1".into(),
            port: 15888,
        },
    );
    let report = w.engine().recover_without_ledger().await.unwrap();
    w.assert_clean();
    assert_eq!(w.sys.foreign().len(), 3);
    assert_eq!(report.candidates.len(), 3);
    assert!(
        report
            .candidates
            .iter()
            .all(|c| matches!(c.source, CandidateSource::Swept(FoundBy::PrefixOnly)))
    );
}

#[tokio::test]
async fn startup_reclaim_leaves_foreign_prefix_objects() {
    let w = World::new();
    w.running("a").await;
    foreign_set(&w);
    let report = w
        .engine()
        .reclaim_all(ReclaimScope::Everything)
        .await
        .unwrap();
    w.assert_clean();
    assert_eq!(w.sys.foreign().len(), 3);
    assert_eq!(report.candidates.len(), 3);
    assert_eq!(report.generations[0].outcome, GenerationOutcome::Closed);
}

#[tokio::test]
async fn diagnose_lists_and_never_writes() {
    let w = World::new();
    w.add_instance("a").await;
    foreign_set(&w);
    w.sys.create_ours(
        EffectKind::WinFenceFilter,
        ObjectKey::Fence {
            container: FENCE_CONTAINER.into(),
            rule: "a-1".into(),
            port: 15888,
        },
    );
    let report = w.engine().diagnose().await.unwrap();
    assert_eq!(w.sys.stats().write_calls, 0);
    assert_eq!(w.sys.objects().len(), 4);
    assert_eq!(report.candidates.len(), 4);
    assert!(report.candidates.iter().any(|c| matches!(
        c.source,
        CandidateSource::Swept(FoundBy::ExclusiveContainer)
    )));
}
