use etd_contract::Desired;
use etd_sysfx::{
    sqlite::{OpenOptions, SqliteLedger},
    *,
};
use etd_testkit::conformance::ledger::{changes, plan, put};

#[tokio::test]
async fn full_disk_refuses_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let boot = BootId("test".into());
    SqliteLedger::open(&path, boot.clone())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    let page_count: u32 = {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap()
    };
    let ledger = SqliteLedger::open_with_options(
        &path,
        boot.clone(),
        OpenOptions {
            max_page_count: Some(page_count),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut change = put("a", Desired::Running, &[]);
    let mut generation = plan("a", 1, &[]);
    if let Change::PutInstance { instance, .. } = &mut change {
        instance.spec.as_mut().unwrap().network_name = "x".repeat(1024 * 1024);
        generation.inputs.spec = instance.spec.clone().unwrap();
    }
    let request = changes("a", 1, vec![change], vec![generation]);
    assert_eq!(
        ledger.commit(0, request.clone()).await,
        Err(LedgerError::Unavailable(StorageFault::DiskFull))
    );
    assert_eq!(ledger.desired().await.unwrap(), (0, vec![]));
    assert_eq!(
        ledger.request_status(&request.request).await.unwrap(),
        RequestStatus::New
    );
    assert!(ledger.pending_tickets().await.unwrap().is_empty());
    assert!(
        ledger
            .open_effects(&ScopeFilter::all())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(ledger.next_epoch(&"a".into()).await.unwrap(), Epoch(1));
    ledger.close().await.unwrap();
    let ledger = SqliteLedger::open(&path, boot).await.unwrap();
    assert_eq!(ledger.commit(0, request).await.unwrap().revision, 1);
    ledger.close().await.unwrap();
}

#[tokio::test]
async fn read_only_refuses_new_transactions_but_returns_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let boot = BootId("test".into());
    let ledger = SqliteLedger::open(&path, boot.clone()).await.unwrap();
    let request = changes(
        "a",
        1,
        vec![put("a", Desired::Running, &[])],
        vec![plan("a", 1, &[])],
    );
    let receipt = ledger.commit(0, request.clone()).await.unwrap();
    ledger.close().await.unwrap();
    let ledger = SqliteLedger::open_with_options(
        &path,
        boot,
        OpenOptions {
            read_only: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(ledger.commit(0, request).await.unwrap(), receipt);
    assert_eq!(
        ledger
            .commit(
                1,
                changes("b", 2, vec![put("b", Desired::Stopped, &[])], vec![])
            )
            .await,
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    );
    assert_eq!(ledger.desired().await.unwrap().0, 1);
    ledger.close().await.unwrap();
}

#[tokio::test]
async fn corrupt_database_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    std::fs::write(&path, b"not SQLite").unwrap();
    assert!(matches!(
        SqliteLedger::open(&path, BootId("test".into())).await,
        Err(LedgerError::Unavailable(StorageFault::Corrupt(_)))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"not SQLite");
}
