#![cfg(windows)]
//! Runs only on disposable, elevated Windows CI workers.
use etd_contract::{Desired, InstanceId};
use etd_sysfx::{engine::ReclaimEngineImpl, *};
use etd_sysfx_os::{OsConfig, adapters};
use etd_testkit::{
    conformance::ledger::{changes, plan, put},
    fakes::ledger::MemoryLedger,
    no_window::NoWindow,
};
use std::{process::Command, sync::Arc};

fn ps(script: &str) -> String {
    let output = Command::new("powershell.exe")
        .no_window()
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
        let _ = Command::new("powershell.exe").no_window().args(["-NoProfile","-NonInteractive","-Command",&format!("Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -eq '{}' | Remove-NetFirewallRule",self.0)]).output();
    }
}

struct RegistryFixture(Vec<String>);
impl Drop for RegistryFixture {
    fn drop(&mut self) {
        for path in &self.0 {
            let _=Command::new("powershell.exe").no_window().args(["-NoProfile","-NonInteractive","-Command",&format!("Remove-Item -LiteralPath '{path}' -Recurse -Force -ErrorAction SilentlyContinue")]).output();
        }
    }
}

#[test]
#[ignore = "creates native volatile machine boot marker on disposable CI"]
fn boot_marker_stable_and_volatile() {
    use ::windows::{
        Win32::{Foundation::ERROR_CHILD_MUST_BE_VOLATILE, System::Registry::*},
        core::{HSTRING, PCWSTR},
    };
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let dir = tempfile::tempdir().unwrap();
    let config = OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    };
    let first = adapters(&config).unwrap().boot_id.current().unwrap();
    let second = adapters(&config).unwrap().boot_id.current().unwrap();
    assert_eq!(first, second);
    assert!(uuid::Uuid::parse_str(&first.0).is_ok());
    // The Win32 registry rejects a nonvolatile child of a volatile key.
    // Query the actual production marker, not just the creation flag.
    unsafe {
        let mut key = HKEY::default();
        assert_eq!(
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                &HSTRING::from(r"SOFTWARE\EasyTierDesk\Volatile"),
                None,
                KEY_READ | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
                &mut key
            )
            .0,
            0
        );
        let name = HSTRING::from(format!("proof-{}", uuid::Uuid::new_v4()));
        let mut child = HKEY::default();
        let rc = RegCreateKeyExW(
            key,
            &name,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ,
            None,
            &mut child,
            None,
        );
        if rc.0 == 0 {
            let _ = RegCloseKey(child);
            let _ = RegDeleteKeyW(key, &name);
        }
        let _ = RegCloseKey(key);
        assert_eq!(rc, ERROR_CHILD_MUST_BE_VOLATILE);
    }
    println!("BOOT marker stable UUID; actual registry key rejects nonvolatile child");
}

#[tokio::test]
#[ignore = "creates isolated network profile and signature fixtures on disposable CI"]
async fn profile_signature_cleanup() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let dir = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let id = format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_uppercase());
    let foreign_id = format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_uppercase());
    let name = format!("etd-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let profile =
        format!(r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{id}");
    let signature = format!(
        r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\{}",
        uuid::Uuid::new_v4().simple()
    );
    let foreign = format!(
        r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\{}",
        uuid::Uuid::new_v4().simple()
    );
    let _fixture = RegistryFixture(vec![profile.clone(), signature.clone(), foreign.clone()]);
    ps(&format!(
        "$ErrorActionPreference='Stop'; New-Item -Path '{profile}' -Force | Out-Null; New-ItemProperty -Path '{profile}' -Name ProfileName -Value '{name}' -PropertyType String | Out-Null; New-Item -Path '{signature}' -Force | Out-Null; New-ItemProperty -Path '{signature}' -Name ProfileGuid -Value '{id}' -PropertyType String | Out-Null; New-Item -Path '{foreign}' -Force | Out-Null; New-ItemProperty -Path '{foreign}' -Name ProfileGuid -Value '{foreign_id}' -PropertyType String | Out-Null"
    ));
    let key = ObjectKey::NetworkProfile { profile_name: name };
    let observation = os
        .observer
        .observe(EffectKind::WinNetworkProfile, &key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        observation.credential,
        Some(Credential::Opaque { value: id })
    );
    let effect = Effect {
        id: EffectId(uuid::Uuid::new_v4().to_string()),
        scope: EffectScope::Instance {
            instance: InstanceId::from("profile-test"),
            epoch: Epoch(1),
        },
        kind: EffectKind::WinNetworkProfile,
        key: key.clone(),
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
        state: EffectState::Applied,
        boot: os.boot_id.current().unwrap(),
        observation: Some(observation),
        failures: 0,
        last_error: None,
        recorded_at: jiff::Timestamp::now(),
    };
    let reclaim = os
        .reclaimers
        .iter()
        .find(|r| r.kind() == effect.kind)
        .unwrap();
    assert_eq!(reclaim.reclaim(&effect).await.unwrap(), Reclaimed::Removed);
    assert!(
        os.observer
            .observe(effect.kind, &key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ps(&format!("Test-Path -LiteralPath '{signature}'")),
        "False"
    );
    assert_eq!(ps(&format!("Test-Path -LiteralPath '{foreign}'")), "True");
    println!("PROFILE matching signature removed, foreign ProfileGuid untouched");
}

#[tokio::test]
#[ignore = "creates isolated registry, NRPT, and Magic DNS recovery fixtures on CI"]
async fn registry_and_magic_dns() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let dir = tempfile::tempdir().unwrap();
    let core_store = dir.path().join("core");
    std::fs::create_dir(&core_store).unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: core_store.clone(),
    })
    .unwrap();
    let guid = format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_uppercase());
    let id = format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_uppercase());
    let tcpip =
        format!(r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}");
    let nrpt = format!(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{id}"
    );
    let magic = r"HKLM:\SOFTWARE\EasyTier\MagicDNS";
    assert_eq!(
        ps(&format!("Test-Path -LiteralPath '{magic}'")),
        "False",
        "don't touch a preexisting shared recovery record"
    );
    let _fixture = RegistryFixture(vec![tcpip.clone(), nrpt.clone(), magic.into()]);
    ps(&format!(
        "$ErrorActionPreference='Stop'; New-Item -Path '{tcpip}' -Force | Out-Null; New-ItemProperty -Path '{tcpip}' -Name RegistrationEnabled -Value 0 -PropertyType DWord | Out-Null; New-ItemProperty -Path '{tcpip}' -Name DisableDynamicUpdate -Value 5 -PropertyType DWord | Out-Null; New-ItemProperty -Path '{tcpip}' -Name SearchList -Value 'current.invalid' -PropertyType String | Out-Null"
    ));
    let boot = os.boot_id.current().unwrap();
    let make = |kind, key, undo, observation| Effect {
        id: EffectId(uuid::Uuid::new_v4().to_string()),
        scope: EffectScope::Instance {
            instance: InstanceId::from("registry-test"),
            epoch: Epoch(1),
        },
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
    let reclaimer = |kind| os.reclaimers.iter().find(|r| r.kind() == kind).unwrap();
    let key = ObjectKey::Registry {
        key: tcpip.replace("HKLM:", "HKLM"),
        value: Some("RegistrationEnabled".into()),
    };
    let obs = os
        .observer
        .observe(EffectKind::WinRegistryValue, &key)
        .await
        .unwrap()
        .unwrap();
    let effect = make(
        EffectKind::WinRegistryValue,
        key.clone(),
        Undo::RestoreIfOurs {
            ours: SettingValue::U32(0),
            original: SettingValue::Absent,
        },
        obs,
    );
    assert_eq!(
        reclaimer(effect.kind).reclaim(&effect).await.unwrap(),
        Reclaimed::Restored
    );
    assert!(
        os.observer
            .observe(effect.kind, &key)
            .await
            .unwrap()
            .is_none()
    );
    let key = ObjectKey::Registry {
        key: tcpip.replace("HKLM:", "HKLM"),
        value: Some("DisableDynamicUpdate".into()),
    };
    let obs = os
        .observer
        .observe(EffectKind::WinRegistryValue, &key)
        .await
        .unwrap()
        .unwrap();
    let effect = make(
        EffectKind::WinRegistryValue,
        key.clone(),
        Undo::RestoreIfOurs {
            ours: SettingValue::U32(1),
            original: SettingValue::Absent,
        },
        obs,
    );
    assert_eq!(
        reclaimer(effect.kind).reclaim(&effect).await.unwrap(),
        Reclaimed::LeftModified
    );
    assert_eq!(
        ps(&format!(
            "(Get-ItemProperty -LiteralPath '{tcpip}').DisableDynamicUpdate"
        )),
        "5"
    );

    // The same schema used by upstream c97f36b. Only the exact random NRPT
    // id and saved SearchList are authorised by this recovery key.
    ps(&format!(
        "$ErrorActionPreference='Stop'; New-Item -Path '{nrpt}' -Force | Out-Null; New-ItemProperty -Path '{nrpt}' -Name Comment -Value 'EasyTier Magic DNS' -PropertyType String | Out-Null; New-Item -Path '{magic}' -Force | Out-Null; New-ItemProperty -Path '{magic}' -Name NRPTRuleIDs -Value @('{id}') -PropertyType MultiString | Out-Null; $saved='{magic}\\SearchLists\\{guid}\\IPv4'; New-Item -Path $saved -Force | Out-Null; New-ItemProperty -Path $saved -Name Ready -Value 1 -PropertyType DWord | Out-Null; New-ItemProperty -Path $saved -Name OriginalSearchList -Value 'original.invalid' -PropertyType String | Out-Null"
    ));
    let nrpt_key = ObjectKey::Rule {
        name: id,
        group: Some("EasyTier Magic DNS".into()),
    };
    assert!(
        os.observer
            .observe(EffectKind::WinNrptRule, &nrpt_key)
            .await
            .unwrap()
            .is_some()
    );
    let magic_key = ObjectKey::Registry {
        key: magic.replace("HKLM:", "HKLM"),
        value: None,
    };
    let obs = os
        .observer
        .observe(EffectKind::WinMagicDnsRecovery, &magic_key)
        .await
        .unwrap()
        .unwrap();
    let effect = make(
        EffectKind::WinMagicDnsRecovery,
        magic_key.clone(),
        Undo::ReplayUpstreamRecovery,
        obs,
    );
    // A candidate outside the protected store blocks the shared record.
    // A candidate opened under the actual store directory is ignored. Use
    // an inert renamed command interpreter, not an actual external VPN.
    let fixture = |location: &std::path::Path| {
        let image = location.join("easytier-gate-fixture.exe");
        std::fs::copy(
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32/cmd.exe"),
            &image,
        )
        .unwrap();
        let mut child = Child(
            Command::new(image)
                .no_window()
                .args(["/d", "/c", "pause"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "gate fixture must still be running"
        );
        child
    };
    let foreign = fixture(dir.path());
    assert!(matches!(
        reclaimer(effect.kind).reclaim(&effect).await,
        Err(ReclaimError::Busy(_))
    ));
    assert!(
        os.observer
            .observe(effect.kind, &magic_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        os.observer
            .observe(EffectKind::WinNrptRule, &nrpt_key)
            .await
            .unwrap()
            .is_some()
    );
    drop(foreign);
    let own = fixture(&core_store);
    assert_eq!(
        reclaimer(effect.kind).reclaim(&effect).await.unwrap(),
        Reclaimed::Removed
    );
    drop(own);
    assert!(
        os.observer
            .observe(effect.kind, &magic_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        os.observer
            .observe(EffectKind::WinNrptRule, &nrpt_key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ps(&format!(
            "(Get-ItemProperty -LiteralPath '{tcpip}').SearchList"
        )),
        "original.invalid"
    );
    assert!(
        os.observer
            .enumerate(SystemClass::DnsPolicy)
            .await
            .unwrap()
            .iter()
            .all(|r| r.key != magic_key && r.key != nrpt_key)
    );
    println!(
        "REAL registry: RestoreIfOurs restored own value, preserved modified value; Magic DNS NRPT id removed then SearchList restored then recovery key removed"
    );
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
            .no_window()
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

/// `sc.exe`, never with a console window (memory channel/windows-processes).
fn sc(args: &[&str]) -> std::process::Output {
    use std::os::windows::process::CommandExt;
    Command::new("sc.exe")
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .unwrap()
}

struct DriverService(String);
impl Drop for DriverService {
    fn drop(&mut self) {
        let _ = sc(&["delete", &self.0]);
    }
}

// Shared drivers (topic#40 msg#1179): a driver service registered before
// the host starts must be seen whatever its start type and whether or not
// its file exists (WMI Win32_SystemDriver omits a disabled one without a
// file). Uses a random name; never touches wintun or WinDivert.
#[tokio::test]
#[ignore = "registers a disabled kernel driver service on disposable CI"]
async fn a_disabled_driver_service_without_a_file_is_observed() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let dir = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let name = format!("etdh1f{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let key = ObjectKey::Service { name: name.clone() };
    assert_eq!(
        os.observer.observe(EffectKind::Driver, &key).await.unwrap(),
        None
    );

    let missing = dir.path().join(format!("{name}.sys"));
    assert!(!missing.exists());
    let created = sc(&[
        "create",
        &name,
        "type=",
        "kernel",
        "start=",
        "disabled",
        "binPath=",
        missing.to_str().unwrap(),
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stdout)
    );
    let fixture = DriverService(name.clone());

    let found = os
        .observer
        .observe(EffectKind::Driver, &key)
        .await
        .unwrap()
        .expect("a registered driver service is present");
    assert_eq!(found.credential, None, "no creation credential upstream");
    assert_eq!(found.key, Some(key.clone()));
    let detail: serde_json::Value = serde_json::from_str(found.detail.as_deref().unwrap()).unwrap();
    println!("observed: {detail}");
    assert_eq!(detail["name"], name.as_str());
    assert_eq!(detail["driver"], true);
    assert_eq!(detail["start_type"], "disabled");
    assert_eq!(detail["state"], "stopped");
    assert!(
        detail["image_path"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .ends_with(&format!("{name}.sys").to_lowercase()),
        "{detail}"
    );

    let deleted = sc(&["delete", &name]);
    assert!(deleted.status.success());
    std::mem::forget(fixture);
    let mut gone = None;
    for _ in 0..50 {
        match os.observer.observe(EffectKind::Driver, &key).await {
            Ok(None) => {
                gone = Some(());
                break;
            }
            // Marked for deletion meanwhile: SCM and the registry may
            // disagree for a moment, which is an error, never absent.
            Ok(Some(_)) | Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    assert!(gone.is_some(), "the deleted service is absent");
}

/// PowerShell, never with a console window (memory channel/windows-processes).
fn ps_hidden(script: &str) -> String {
    use std::os::windows::process::CommandExt;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}

// A program rule named after our kernel binary but for another program (or
// group, or direction) is a definite third-party object: observed as found,
// with its own identity, under the key its condition names (topic#40
// msg#1199), never an error.
#[tokio::test]
#[ignore = "creates a real local program firewall rule on disposable CI"]
async fn a_foreign_program_rule_is_observed_not_an_error() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let dir = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let ours = dir.path().join(format!(
        "core-{}.exe",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let other = dir.path().join("someone-else.exe");
    let name = format!("EasyTier {} (Inbound)", ours.display());
    let key = ObjectKey::Rule {
        name: name.clone(),
        group: Some("EasyTier".into()),
    };
    assert_eq!(
        os.observer
            .observe(EffectKind::WinProgramFirewallRule, &key)
            .await
            .unwrap(),
        None
    );
    let id = uuid::Uuid::new_v4().to_string();
    ps_hidden(&format!(
        "$ErrorActionPreference='Stop'; New-NetFirewallRule -Name '{id}' -DisplayName '{name}' -Group 'EasyTier' -Direction Inbound -Action Allow -Program '{}' | Out-Null",
        other.display()
    ));
    let _rule = Rule(id.clone());

    let found = os
        .observer
        .observe(EffectKind::WinProgramFirewallRule, &key)
        .await
        .expect("a definite foreign rule is not an error")
        .expect("it is there");
    println!("observed: {found:?}");
    let Some(Credential::Opaque { value }) = &found.credential else {
        panic!("its identity: {found:?}");
    };
    assert!(value.contains(&id), "{value}");
    let Some(ObjectKey::Rule {
        name: found_name, ..
    }) = &found.key
    else {
        panic!("the key its condition names: {found:?}");
    };
    assert!(
        found_name
            .to_lowercase()
            .contains(&other.display().to_string().to_lowercase()),
        "{found_name}"
    );
    assert_ne!(found.key, Some(key));
}
