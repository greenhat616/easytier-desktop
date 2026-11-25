use etd_testkit::{conformance::ledger, fakes::ledger::MemoryLedger};

#[tokio::test]
async fn memory_idempotency() {
    ledger::idempotency(&MemoryLedger::default()).await;
}

#[tokio::test]
async fn memory_revision_and_atomicity() {
    ledger::revision_and_atomicity(&MemoryLedger::default()).await;
}

#[tokio::test]
async fn memory_claims_replacement_while_reclaiming() {
    ledger::claims_while_reclaiming(&MemoryLedger::default(), true).await;
}

#[tokio::test]
async fn memory_claims_stop_while_reclaiming() {
    ledger::claims_while_reclaiming(&MemoryLedger::default(), false).await;
}

#[tokio::test]
async fn memory_epochs_and_compaction() {
    ledger::epochs_and_compaction(&MemoryLedger::default()).await;
}

#[tokio::test]
async fn memory_concurrent_revision() {
    ledger::concurrent_revision(&MemoryLedger::default()).await;
}

use etd_sysfx::{BootId, sqlite::SqliteLedger};

async fn sqlite_case(
    test: impl for<'a> FnOnce(
        &'a SqliteLedger,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let ledger = SqliteLedger::open(&path, BootId("test-boot".into()))
        .await
        .unwrap();
    test(&ledger).await;
    ledger.close().await.unwrap();
}
#[tokio::test]
async fn sqlite_idempotency() {
    sqlite_case(|l| Box::pin(ledger::idempotency(l))).await;
}
#[tokio::test]
async fn sqlite_revision_and_atomicity() {
    sqlite_case(|l| Box::pin(ledger::revision_and_atomicity(l))).await;
}
#[tokio::test]
async fn sqlite_claims_replacement_while_reclaiming() {
    sqlite_case(|l| Box::pin(ledger::claims_while_reclaiming(l, true))).await;
}
#[tokio::test]
async fn sqlite_claims_stop_while_reclaiming() {
    sqlite_case(|l| Box::pin(ledger::claims_while_reclaiming(l, false))).await;
}
#[tokio::test]
async fn sqlite_epochs_and_compaction() {
    sqlite_case(|l| Box::pin(ledger::epochs_and_compaction(l))).await;
}
#[tokio::test]
async fn sqlite_concurrent_revision() {
    sqlite_case(|l| Box::pin(ledger::concurrent_revision(l))).await;
}

#[tokio::test]
async fn memory_shared_effects() {
    ledger::shared_effects(&MemoryLedger::default()).await;
}

#[tokio::test]
async fn sqlite_shared_effects() {
    sqlite_case(|l| Box::pin(ledger::shared_effects(l))).await;
}

#[tokio::test]
async fn memory_remove_while_reclaiming() {
    ledger::remove_while_reclaiming(&MemoryLedger::default()).await;
}

#[tokio::test]
async fn sqlite_remove_while_reclaiming() {
    sqlite_case(|l| Box::pin(ledger::remove_while_reclaiming(l))).await;
}

#[tokio::test]
async fn sqlite_pending_removal_survives_reopen() {
    use etd_contract::Desired;
    use etd_sysfx::*;
    use etd_testkit::conformance::ledger::{changes, plan, put};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let boot = BootId("boot".into());
    let l = SqliteLedger::open(&path, boot.clone()).await.unwrap();
    l.commit(
        0,
        changes(
            "start",
            1,
            vec![put("a", Desired::Running, &["X"])],
            vec![plan("a", 1, &["X"])],
        ),
    )
    .await
    .unwrap();
    l.commit(
        1,
        changes(
            "remove",
            2,
            vec![Change::RemoveInstance("a".into())],
            vec![],
        ),
    )
    .await
    .unwrap();
    l.close().await.unwrap();
    let l = SqliteLedger::open(&path, boot.clone()).await.unwrap();
    assert!(matches!(
        l.commit(
            2,
            changes("revive", 3, vec![put("a", Desired::Running, &[])], vec![])
        )
        .await,
        Err(LedgerError::EpochOpen { .. })
    ));
    let id = l
        .open_effects(&ScopeFilter::all())
        .await
        .unwrap()
        .remove(0)
        .id;
    l.transition(&id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    l.close().await.unwrap();
    let l = SqliteLedger::open(&path, boot).await.unwrap();
    assert_eq!(l.desired().await.unwrap(), (3, vec![]));
    assert!(l.claims().await.unwrap().is_empty());
    l.close().await.unwrap();
}
