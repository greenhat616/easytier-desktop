#![cfg(windows)]
//! Runs only on disposable, elevated Windows CI workers.
use etd_contract::InstanceId;
use etd_sysfx::{engine::ReclaimEngineImpl, *};
use etd_sysfx_os::{OsConfig, adapters};
use etd_testkit::fakes::ledger::MemoryLedger;
use std::{process::Command, sync::Arc};

fn ps(script: &str) -> String {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}
#[derive(Default)]
struct Index;
impl RepairIndexStore for Index {
    fn load(&self) -> Result<Option<RepairIndex>, LedgerError> {
        Ok(None)
    }
    fn store(&self, _: &RepairIndex) -> Result<(), LedgerError> {
        Ok(())
    }
}
struct Rule(String);
impl Drop for Rule {
    fn drop(&mut self) {
        let _ = ps(&format!(
            "Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -eq '{}' | Remove-NetFirewallRule",
            self.0
        ));
    }
}

#[tokio::test]
#[ignore = "creates real local firewall rules on disposable CI"]
async fn reclaim_and_conflict() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let dir = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let name = format!("ETD O1 test {}", uuid::Uuid::new_v4());
    let key = ObjectKey::Rule {
        name: name.clone(),
        group: Some("ETD O1 test".into()),
    };
    let create = || {
        let id = uuid::Uuid::new_v4().to_string();
        ps(&format!(
            "$ErrorActionPreference='Stop'; New-NetFirewallRule -Name '{id}' -DisplayName '{name}' -Group 'ETD O1 test' -Direction Outbound -Action Block -Protocol TCP -RemotePort 65534 | Out-Null"
        ));
        Rule(id)
    };
    let original = create();
    let observation = os
        .observer
        .observe(EffectKind::WinFirewallRule, &key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        observation.credential,
        Some(Credential::Opaque {
            value: original.0.clone()
        })
    );
    let ledger = Arc::new(MemoryLedger::new(os.boot_id.current().unwrap()));
    let intent = EffectIntent {
        scope: EffectScope::Instance {
            instance: InstanceId::from("o1-test"),
            epoch: Epoch(1),
        },
        kind: EffectKind::WinFirewallRule,
        key: key.clone(),
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    };
    let e = ledger.record(intent.clone()).await.unwrap();
    ledger
        .transition(&e.id, EffectState::Applied, Some(observation.clone()))
        .await
        .unwrap();
    let reclaimer = os
        .reclaimers
        .iter()
        .find(|r| r.kind() == EffectKind::WinFirewallRule)
        .unwrap();
    let record = ledger
        .open_effects(&ScopeFilter::all())
        .await
        .unwrap()
        .remove(0);
    assert!(matches!(reclaimer.probe(&record).await, Probe::Present(_)));
    assert_eq!(
        reclaimer.reclaim(&record).await.unwrap(),
        Reclaimed::Removed
    );
    assert!(
        os.observer
            .enumerate(SystemClass::FirewallRules)
            .await
            .unwrap()
            .iter()
            .all(|r| r.key != key)
    );
    println!("REAL firewall reclaimed by credential; independent enumeration clean");
    let foreign = create();
    let current = os
        .observer
        .observe(EffectKind::WinFirewallRule, &key)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(observation.credential, current.credential);
    assert_eq!(
        reclaimer.reclaim(&record).await.unwrap_err(),
        ReclaimError::CredentialMismatch
    );
    let engine = ReclaimEngineImpl::new(ReclaimDeps {
        ledger,
        reclaimers: os.reclaimers,
        sweeper: os.sweeper,
        boot_id: os.boot_id,
        repair_index: Arc::new(Index),
    });
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert_eq!(report.conflicts.len(), 1, "{report:?}");
    assert_eq!(
        os.observer
            .observe(EffectKind::WinFirewallRule, &key)
            .await
            .unwrap()
            .unwrap()
            .credential,
        current.credential
    );
    println!(
        "CONFLICT same display name, different rule ID {}; third-party rule preserved",
        foreign.0
    );
}
