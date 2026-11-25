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
