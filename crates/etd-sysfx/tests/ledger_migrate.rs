use etd_sysfx::{sqlite::SqliteLedger, *};

const FIXTURE: &str = r#"-- Hand-authored v0 database fixture: a prior boot left a planned product
-- effect and a compacted instance's epoch high-water mark.
UPDATE meta SET next_effect='1' WHERE singleton=1;
INSERT INTO high_water VALUES ('old-instance','17');
INSERT INTO effects VALUES ('00000000000000000001', CAST('{"scope":"product","kind":"driver","key":{"type":"service","name":"fixture-driver"},"undo":{"type":"ensure_absent"},"persistence":"persistent","state":"planned","boot":"previous-boot","observation":null,"failures":0,"last_error":null,"recorded_at":"2025-01-01T00:00:00Z"}' AS BLOB));
"#;

#[tokio::test]
async fn migrate_v0_preserves_open_record_and_high_water() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(include_str!("../migrations/000_baseline.sql"))
            .unwrap();
        conn.execute_batch(FIXTURE).unwrap();
    }
    let ledger = SqliteLedger::open(&path, BootId("current-boot".into()))
        .await
        .unwrap();
    assert_eq!(ledger.settings().await.unwrap(), HostSettings::default());
    assert_eq!(
        ledger.next_epoch(&"old-instance".into()).await.unwrap(),
        Epoch(18)
    );
    let effects = ledger.open_effects(&ScopeFilter::all()).await.unwrap();
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].boot, BootId("previous-boot".into()));
    assert_eq!(effects[0].kind, EffectKind::Driver);
    ledger
        .transition(&effects[0].id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    ledger.close().await.unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn newer_schema_not_modified() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE new_data (payload TEXT); INSERT INTO new_data VALUES ('fixture'); PRAGMA user_version=99;").unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        SqliteLedger::open(&path, BootId("boot".into())).await,
        Err(LedgerError::SchemaTooNew {
            found: 99,
            supported: 1
        })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn unknown_effect_kind_not_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(include_str!("../migrations/000_baseline.sql"))
            .unwrap();
        let fixture = FIXTURE.replace("\"kind\":\"driver\"", "\"kind\":\"future.effect\"");
        conn.execute_batch(&fixture).unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        SqliteLedger::open(&path, BootId("boot".into())).await,
        Err(LedgerError::Unreadable(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
