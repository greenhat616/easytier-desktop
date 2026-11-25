//! R1: core-binary and product scope. `reclaim_core` refuses while an open
//! generation uses the binary, then removes that binary's program firewall
//! rules only; instance reclaim never touches either scope.
mod reclaim_support;

use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_testkit::fakes::system::{Fault, Step};
use reclaim_support::{World, core_hex};

fn program_rule(sha: &str, dir: &str) -> EffectIntent {
    EffectIntent {
        scope: EffectScope::CoreBinary {
            sha256: sha.to_owned(),
        },
        kind: EffectKind::WinProgramFirewallRule,
        key: ObjectKey::Rule {
            name: format!("EasyTier store\\{sha}\\core.exe ({dir})"),
            group: Some("EasyTier".into()),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    }
}

async fn record_applied(w: &World, intent: EffectIntent) -> Effect {
    let e = w.memory.record(intent.clone()).await.unwrap();
    let obs = w.sys.apply_intent(&intent);
    w.memory
        .transition(&e.id, EffectState::Applied, Some(obs))
        .await
        .unwrap();
    e
}

#[tokio::test]
async fn reclaim_core_waits_for_generations_then_removes_its_rules() {
    let w = World::new();
    w.running("a").await;
    let sha = core_hex();
    record_applied(&w, program_rule(&sha, "in")).await;
    record_applied(&w, program_rule(&sha, "out")).await;
    let other = "cd".repeat(32);
    record_applied(&w, program_rule(&other, "in")).await;
    let engine = w.engine();

    let err = engine.reclaim_core(&sha).await.unwrap_err();
    assert_eq!(
        err,
        LedgerError::EpochOpen {
            instance: InstanceId::from("a"),
            open: Epoch(1)
        }
    );
    assert_eq!(w.sys.stats().write_calls, 0);

    // Instance reclaim leaves core-binary records alone.
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert_eq!(report.generations[0].outcome, GenerationOutcome::Closed);
    assert_eq!(w.sys.ours().len(), 3);

    let report = engine.reclaim_core(&sha.to_uppercase()).await.unwrap();
    assert!(report.candidates.is_empty() && report.conflicts.is_empty());
    let left = w.sys.ours();
    assert_eq!(left.len(), 1);
    assert!(format!("{:?}", left[0].key).contains(&other));
    assert_eq!(w.open().await.len(), 1);
}

#[tokio::test]
async fn reclaim_core_reports_pending_rules() {
    let w = World::new();
    let sha = core_hex();
    record_applied(&w, program_rule(&sha, "in")).await;
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinProgramFirewallRule)
            .fail(ReclaimError::PermissionDenied("x".into())),
    );
    let report = w.engine().reclaim_core(&sha).await.unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains(&format!("core binary {sha}"))),
        "{:?}",
        report.notes
    );
    assert_eq!(w.open().await.len(), 1);
}

#[tokio::test]
async fn everything_scope_covers_product_and_core_records() {
    let w = World::new();
    w.running("a").await;
    record_applied(&w, program_rule(&core_hex(), "in")).await;
    record_applied(
        &w,
        EffectIntent {
            scope: EffectScope::Product,
            kind: EffectKind::Driver,
            key: ObjectKey::Service {
                name: "wintun".into(),
            },
            undo: Undo::EnsureAbsent,
            persistence: Persistence::Persistent,
        },
    )
    .await;
    let report = w
        .engine()
        .reclaim_all(ReclaimScope::Everything)
        .await
        .unwrap();
    assert!(report.notes.iter().all(|n| !n.contains("still open")));
    w.assert_clean();
    assert!(w.open().await.is_empty());
}
