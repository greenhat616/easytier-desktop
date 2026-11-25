use etd_contract::{Desired, v1};
use etd_sysfx::{sqlite::SqliteLedger, *};
use etd_testkit::conformance::ledger::{changes, plan, put};

#[tokio::test]
async fn pragmas_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let old_boot = BootId("boot-a".into());
    let ledger = SqliteLedger::open(&path, old_boot.clone()).await.unwrap();
    let pragmas = ledger.pragmas().await.unwrap();
    assert_eq!(pragmas.journal_mode, "wal");
    assert_eq!(pragmas.synchronous, 2);
    assert!(pragmas.secure_delete);
    #[cfg(target_os = "macos")]
    assert!(pragmas.fullfsync);

    let mut generation = plan("a", 1, &["X"]);
    generation.inputs.spec = etd_contract::NetworkSpec {
        display_name: "A".into(),
        network_name: "network".into(),
        network_secret: Some("test-fixture".into()),
        network_secret_set: true,
        hostname: "host".into(),
        peers: vec!["tcp://localhost:11010".into()],
        listeners: vec!["udp://localhost:0".into()],
        no_listener: true,
        proxy_cidrs: vec!["10.0.0.0/8".into()],
        exit_nodes: vec!["10.2.3.4".into()],
        enable_exit_node: true,
        mtu: 1300,
        no_tun: true,
        socks5_port: 1080,
        port_forwards: vec![v1::PortForward {
            protocol: 1,
            bind: "127.0.0.1:90".into(),
            destination: "10.0.0.1:90".into(),
        }],
        magic_dns: true,
        public_ipv6_provider: true,
        flags: Some(v1::NetworkFlags {
            private_mode: true,
            compression: "test".into(),
            ..Default::default()
        }),
        ipv4: Some(v1::network_spec::Ipv4::Dhcp(true)),
    };
    let mut change = put("a", Desired::Running, &["X"]);
    if let Change::PutInstance { instance, .. } = &mut change {
        instance.spec = Some(generation.inputs.spec.clone());
    }
    let allow = etd_contract::AllowEntry {
        principal: Some(etd_contract::OsPrincipal {
            id: Some(v1::os_principal::Id::UnixUid(1001)),
        }),
        role: 2,
        display_name: "test".into(),
    };
    let request = changes(
        "a",
        1,
        vec![
            change,
            Change::SetAllowList(vec![allow]),
            Change::SelectCore(Some("test-core".into())),
        ],
        vec![generation.clone()],
    );
    let receipt = ledger.commit(0, request.clone()).await.unwrap();
    let effect = ledger
        .open_effects(&ScopeFilter::all())
        .await
        .unwrap()
        .remove(0);
    let observation = Observation {
        credential: Some(Credential::Process {
            pid: 123,
            start_token: "fixture".into(),
        }),
        key: Some(effect.key.clone()),
        observed_at: jiff::Timestamp::now(),
        detail: Some("created".into()),
    };
    ledger
        .transition(&effect.id, EffectState::Applied, Some(observation))
        .await
        .unwrap();
    ledger
        .record_failure(&effect.id, "test error")
        .await
        .unwrap();
    let stored = ledger
        .generation(&"a".into(), Epoch(1))
        .await
        .unwrap()
        .unwrap();
    let desired = ledger.desired().await.unwrap();
    let tickets = ledger.pending_tickets().await.unwrap();
    let settings = ledger.settings().await.unwrap();
    assert_eq!(stored.inputs, generation.inputs);
    ledger.close().await.unwrap();
    let ledger = SqliteLedger::open(&path, BootId("boot-b".into()))
        .await
        .unwrap();
    assert_eq!(
        ledger.generation(&"a".into(), Epoch(1)).await.unwrap(),
        Some(stored.clone())
    );
    assert_eq!(ledger.settings().await.unwrap(), settings);
    assert_eq!(ledger.desired().await.unwrap(), desired);
    assert_eq!(ledger.pending_tickets().await.unwrap(), tickets);
    assert_eq!(ledger.commit(0, request).await.unwrap(), receipt);
    assert_eq!(stored.effects[0].boot, old_boot);
    ledger
        .transition(&effect.id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    ledger.compact().await.unwrap();
    ledger.close().await.unwrap();
    let ledger = SqliteLedger::open(&path, BootId("boot-b".into()))
        .await
        .unwrap();
    assert_eq!(ledger.next_epoch(&"a".into()).await.unwrap(), Epoch(2));
    assert!(
        ledger
            .generation(&"a".into(), Epoch(1))
            .await
            .unwrap()
            .is_none()
    );
    let mut next = plan("a", 2, &["X"]);
    next.inputs.spec = generation.inputs.spec;
    assert_eq!(
        ledger.begin_epoch(next).await.unwrap()[0].boot,
        BootId("boot-b".into())
    );
    ledger.close().await.unwrap();
}

#[tokio::test]
async fn completed_ticket_and_purge_remove_historical_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let boot = BootId("boot".into());
    let ledger = SqliteLedger::open(&path, boot.clone()).await.unwrap();
    let mut change = put("a", Desired::Stopped, &[]);
    if let Change::PutInstance { instance, .. } = &mut change {
        instance.spec.as_mut().unwrap().network_secret = Some("synthetic-history-fixture".into());
    }
    let receipt = ledger
        .commit(0, changes("first", 1, vec![change], vec![]))
        .await
        .unwrap();
    ledger.complete_ticket(&receipt.ticket).await.unwrap();
    // Current config retains the secret, completed request payload does not.
    assert_eq!(
        ledger.desired().await.unwrap().1[0]
            .spec
            .as_ref()
            .unwrap()
            .network_secret
            .as_deref(),
        Some("synthetic-history-fixture")
    );
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let payload: Vec<u8> = conn
            .query_row("SELECT payload FROM requests WHERE id='first'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            !String::from_utf8(payload)
                .unwrap()
                .contains("synthetic-history-fixture")
        );
    }
    let purge = ledger
        .commit(1, changes("purge", 2, vec![Change::PurgeAll], vec![]))
        .await
        .unwrap();
    assert_eq!(ledger.desired().await.unwrap(), (2, vec![]));
    assert_eq!(
        std::fs::metadata(path.with_extension("sqlite-wal"))
            .unwrap()
            .len(),
        0
    );
    let db = std::fs::read(&path).unwrap();
    assert!(
        !db.windows(b"synthetic-history-fixture".len())
            .any(|s| s == b"synthetic-history-fixture")
    );
    ledger.close().await.unwrap();
    let ledger = SqliteLedger::open(&path, boot).await.unwrap();
    assert_eq!(ledger.receipt(&"purge".into()).await.unwrap(), Some(purge));
    assert!(ledger.receipt(&"first".into()).await.unwrap().is_none());
    ledger.close().await.unwrap();
}
