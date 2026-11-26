#![cfg(windows)]
//! Runs only on disposable, elevated Windows CI workers.
use etd_contract::{Desired, InstanceId};
use etd_sysfx::{engine::ReclaimEngineImpl, *};
use etd_sysfx_os::{OsConfig, adapters};
use etd_testkit::{
    conformance::ledger::{changes, plan, put},
    fakes::ledger::MemoryLedger,
};
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
    let mut generation = plan("o1-test", 1, &[]);
    generation.effects.push(intent);
    ledger
        .commit(
            0,
            changes(
                "o1-test",
                1,
                vec![put("o1-test", Desired::Running, &[])],
                vec![generation],
            ),
        )
        .await
        .unwrap();
    let records = ledger.open_effects(&ScopeFilter::all()).await.unwrap();
    let process = records
        .iter()
        .find(|r| r.kind == EffectKind::Process)
        .unwrap();
    // No process was launched in this fixture. Close the process record
    // before exercising the same generation's OS effect.
    ledger
        .transition(&process.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    ledger
        .transition(&process.id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    let e = records
        .iter()
        .find(|r| r.kind == EffectKind::WinFirewallRule)
        .unwrap();
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

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "runs a real wintun core and changes networking only on CI"]
async fn real_wintun_after_kill() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant};
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let exe = std::path::PathBuf::from(std::env::var_os("ETD_O1_CORE").expect("S2-pinned CI core"));
    let dir = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: exe.parent().unwrap().into(),
    })
    .unwrap();
    let name = format!("etd-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let guid = format!(
        "{{{}}}",
        naming::wintun_guid(&name).to_string().to_uppercase()
    );
    let key = ObjectKey::Interface {
        name: Some(name.clone()),
        guid: Some(guid.clone()),
    };
    assert!(
        os.observer
            .observe(EffectKind::WinTunAdapter, &key)
            .await
            .unwrap()
            .is_none()
    );
    let profile_key = ObjectKey::NetworkProfile {
        profile_name: name.clone(),
    };
    assert!(
        os.observer
            .observe(EffectKind::WinNetworkProfile, &profile_key)
            .await
            .unwrap()
            .is_none()
    );
    let management = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut core = Child(
        Command::new(&exe)
            .current_dir(exe.parent().unwrap())
            .args([
                "--network-name",
                &name,
                "--ipv4",
                "10.144.144.1/24",
                "--dev-name",
                &name,
                "--no-listener",
                "--manual-routes",
                "10.200.77.0/24",
                "--rpc-portal",
                &management.to_string(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let adapter_obs = loop {
        assert!(
            core.0.try_wait().unwrap().is_none(),
            "core exited before interface readback"
        );
        if let Ok(Some(info)) = os.observer.interface(&key).await
            && info
                .addresses
                .iter()
                .any(|(ip, _)| ip.to_string() == "10.144.144.1")
        {
            break os
                .observer
                .observe(EffectKind::WinTunAdapter, &key)
                .await
                .unwrap()
                .unwrap();
        }
        assert!(Instant::now() < deadline, "wintun never became ready");
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert!(matches!(
        adapter_obs.credential,
        Some(Credential::WinAdapter { .. })
    ));
    let scope = EffectScope::Instance {
        instance: InstanceId::from("wintun-test"),
        epoch: Epoch(1),
    };
    let boot = os.boot_id.current().unwrap();
    let effect = |kind, key, undo, observation, scope| Effect {
        id: EffectId(uuid::Uuid::new_v4().to_string()),
        scope,
        kind,
        key,
        undo,
        persistence: Persistence::Persistent,
        state: EffectState::Applied,
        boot: boot.clone(),
        observation: Some(observation),
        failures: 0,
        last_error: None,
        recorded_at: jiff::Timestamp::now(),
    };
    let adapter = effect(
        EffectKind::WinTunAdapter,
        key.clone(),
        Undo::EnsureAbsent,
        adapter_obs,
        scope.clone(),
    );
    let reclaimer = |kind| os.reclaimers.iter().find(|r| r.kind() == kind).unwrap();
    assert!(matches!(
        reclaimer(adapter.kind).reclaim(&adapter).await,
        Err(ReclaimError::Busy(_))
    ));
    let mut effects = Vec::new();
    for protocol in ["TCP", "UDP", "ICMP", "ALL"] {
        for direction in ["Inbound", "Outbound"] {
            let key = ObjectKey::Rule {
                name: format!("EasyTier {name} - {protocol} Protocol ({direction})"),
                group: Some("EasyTier".into()),
            };
            let obs = os
                .observer
                .observe(EffectKind::WinFirewallRule, &key)
                .await
                .unwrap()
                .expect("expected upstream firewall rule");
            effects.push(effect(
                EffectKind::WinFirewallRule,
                key,
                Undo::EnsureAbsent,
                obs,
                scope.clone(),
            ));
        }
    }
    let sha256: String = Sha256::digest(std::fs::read(&exe).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for direction in ["Inbound", "Outbound"] {
        let key = ObjectKey::Rule {
            name: format!(
                "EasyTier {} ({direction})",
                exe.to_string_lossy().replace(r"\\?\", "")
            ),
            group: Some("EasyTier".into()),
        };
        let obs = os
            .observer
            .observe(EffectKind::WinProgramFirewallRule, &key)
            .await
            .unwrap()
            .expect("expected upstream program firewall rule");
        effects.push(effect(
            EffectKind::WinProgramFirewallRule,
            key,
            Undo::EnsureAbsent,
            obs,
            EffectScope::CoreBinary {
                sha256: sha256.clone(),
            },
        ));
    }
    if let Some(obs) = os
        .observer
        .observe(EffectKind::WinNetworkProfile, &profile_key)
        .await
        .unwrap()
    {
        effects.push(effect(
            EffectKind::WinNetworkProfile,
            profile_key,
            Undo::EnsureAbsent,
            obs,
            scope.clone(),
        ));
    }
    for prefix in ["Tcpip", "Tcpip6", "NetBT"] {
        let path = if prefix == "NetBT" {
            format!(
                r"HKLM\SYSTEM\CurrentControlSet\Services\{prefix}\Parameters\Interfaces\Tcpip_{guid}"
            )
        } else {
            format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{prefix}\Parameters\Interfaces\{guid}")
        };
        let values = if prefix == "NetBT" {
            vec![("NetbiosOptions", 2)]
        } else {
            vec![
                ("RegistrationEnabled", 0),
                ("DisableDynamicUpdate", 1),
                ("MaxNumberOfAddressesToRegister", 0),
            ]
        };
        for (value, data) in values {
            let key = ObjectKey::Registry {
                key: path.clone(),
                value: Some(value.into()),
            };
            if let Some(obs) = os
                .observer
                .observe(EffectKind::WinRegistryValue, &key)
                .await
                .unwrap()
            {
                effects.push(effect(
                    EffectKind::WinRegistryValue,
                    key,
                    Undo::RestoreIfOurs {
                        ours: SettingValue::U32(data),
                        original: SettingValue::Absent,
                    },
                    obs,
                    scope.clone(),
                ));
            }
        }
    }
    core.0.kill().unwrap();
    core.0.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if matches!(reclaimer(adapter.kind).probe(&adapter).await, Probe::Absent) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "live adapter lingered after kernel death"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        reclaimer(adapter.kind).reclaim(&adapter).await.unwrap(),
        Reclaimed::AlreadyAbsent
    );
    assert!(
        os.observer
            .enumerate(SystemClass::Interfaces)
            .await
            .unwrap()
            .iter()
            .all(|r| r.key != key)
    );
    for e in effects {
        let outcome = reclaimer(e.kind).reclaim(&e).await.unwrap();
        assert!(
            matches!(
                outcome,
                Reclaimed::Removed | Reclaimed::Restored | Reclaimed::AlreadyAbsent
            ),
            "unexpected {outcome:?} for {:?}",
            e.key
        );
        assert!(matches!(reclaimer(e.kind).probe(&e).await, Probe::Absent));
    }
    let routes = ObjectKey::RoutesVia {
        interface: Some(name.clone()),
    };
    assert!(
        os.observer
            .observe(EffectKind::Route, &routes)
            .await
            .unwrap()
            .is_none()
    );
    println!(
        "REAL wintun {name}: credential observed; live removal refused; after hard kill phantom excluded, routes gone, interface and program firewall rules reclaimed"
    );
}
