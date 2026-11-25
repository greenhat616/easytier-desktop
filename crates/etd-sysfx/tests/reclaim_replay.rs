//! R1 acceptance (proptest): crash at any step of a reclaim run, system call
//! or ledger write, before or after it lands; a fresh engine then replays.
//! The ledger ends with no open record and the fake system holds no object
//! of ours; nothing foreign is ever deleted.
mod reclaim_support;

use etd_sysfx::*;
use proptest::prelude::*;
use reclaim_support::{Fate, World, crashed};
use std::sync::Arc;

/// Two instances; one generation fully applied, one with mixed fates
/// (planned records whose object never appeared), plus a foreign object
/// with a product prefix.
async fn scenario(w: &World) {
    w.running("a").await;
    w.add_instance("b").await;
    let effects = w.begin("b", w.windows_intents("b", 1)).await;
    for (i, e) in effects.iter().enumerate() {
        let fate = if i % 3 == 0 {
            Fate::PlannedAbsent
        } else {
            Fate::Applied
        };
        w.settle(e, fate).await;
    }
    w.sys.create_foreign(
        EffectKind::WinFirewallRule,
        ObjectKey::Rule {
            name: "EasyTier etd-0badf00d - TCP Protocol (Inbound)".into(),
            group: None,
        },
    );
}

#[derive(Debug, Clone, Copy)]
enum CrashAt {
    System { op: u64, after: bool },
    Ledger { write: u64, after: bool },
}

/// Returns whether the first run actually crashed.
fn run(crash: CrashAt) -> bool {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let (w, ledger) = World::crashing();
        scenario(&w).await;
        match crash {
            CrashAt::System { op, after } => w.sys.crash_at(w.sys.stats().calls + op, after),
            CrashAt::Ledger { write, after } => ledger.crash_at(write, after),
        }
        let engine = Arc::new(w.engine());
        let first = tokio::spawn({
            let engine = engine.clone();
            async move { engine.reclaim_all(ReclaimScope::Instances).await }
        })
        .await;
        let did_crash = crashed(first);
        drop(engine);
        w.sys.clear_faults();
        // Host restarts: a fresh engine over the same ledger and system.
        let report = w
            .engine()
            .reclaim_all(ReclaimScope::Instances)
            .await
            .unwrap();
        assert!(
            w.open().await.is_empty(),
            "crash {crash:?} (crashed: {did_crash}): open records {:#?}",
            w.open().await
        );
        w.assert_clean();
        assert_eq!(w.sys.foreign().len(), 1);
        assert!(
            report
                .generations
                .iter()
                .all(|g| g.outcome == GenerationOutcome::Closed)
        );
        did_crash
    })
}

/// Calls of an uninterrupted run, to bound the crash points.
fn budget() -> (u64, u64) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (w, ledger) = World::crashing();
        scenario(&w).await;
        let before = w.sys.stats().calls;
        w.engine()
            .reclaim_all(ReclaimScope::Instances)
            .await
            .unwrap();
        (w.sys.stats().calls - before, ledger.writes())
    })
}

#[test]
fn uninterrupted_run_is_clean() {
    let (ops, writes) = budget();
    assert!(ops > 10 && writes > 10, "ops {ops}, writes {writes}");
    assert!(!run(CrashAt::System {
        op: u64::MAX / 2,
        after: false,
    }));
}

#[test]
fn every_system_crash_point_converges() {
    let (ops, _) = budget();
    for op in 0..ops {
        for after in [false, true] {
            assert!(run(CrashAt::System { op, after }), "op {op} not reached");
        }
    }
}

#[test]
fn every_ledger_crash_point_converges() {
    let (_, writes) = budget();
    for write in 0..writes {
        for after in [false, true] {
            assert!(
                run(CrashAt::Ledger { write, after }),
                "write {write} not reached"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Two crashes in a row (one in each layer), then a clean replay.
    #[test]
    fn double_crash_converges(op in 0u64..60, write in 0u64..40, a1: bool, a2: bool) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let (w, ledger) = World::crashing();
            scenario(&w).await;
            w.sys.crash_at(w.sys.stats().calls + op, a1);
            for _ in 0..2 {
                let engine = Arc::new(w.engine());
                let _ = crashed(tokio::spawn({
                    let engine = engine.clone();
                    async move { engine.reclaim_all(ReclaimScope::Instances).await }
                })
                .await);
                ledger.crash_at(ledger.writes() + write, a2);
            }
            ledger.crash_at(u64::MAX, false);
            w.sys.clear_faults();
            w.engine().reclaim_all(ReclaimScope::Instances).await.unwrap();
            assert!(w.open().await.is_empty());
            w.assert_clean();
        });
    }
}
