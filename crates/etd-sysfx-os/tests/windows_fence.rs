#![cfg(windows)]
//! The host is LocalSystem, not merely an elevated administrator. The
//! nextest parent starts its own child under a scheduled SYSTEM task.
use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_sysfx_os::{OsConfig, adapters};
use std::{
    process::Command,
    time::{Duration, Instant},
};

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
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn assert_wfp_container_absent() {
    use ::windows::{
        Win32::{
            Foundation::{FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE},
            NetworkManagement::WindowsFilteringPlatform::*,
        },
        core::{GUID, PCWSTR},
    };
    // Independent BFE handle and direct queries for both container keys.
    unsafe {
        let mut handle = HANDLE::default();
        assert_eq!(
            FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &mut handle),
            0
        );
        let mut provider = std::ptr::null_mut();
        let mut sublayer = std::ptr::null_mut();
        let p = FwpmProviderGetByKey0(
            handle,
            &GUID::from_u128(0x51e7d001_7bc3_43b9_a795_7b80c196382f),
            &mut provider,
        );
        let s = FwpmSubLayerGetByKey0(
            handle,
            &GUID::from_u128(0x51e7d002_7bc3_43b9_a795_7b80c196382f),
            &mut sublayer,
        );
        if !provider.is_null() {
            FwpmFreeMemory0((&mut provider as *mut *mut FWPM_PROVIDER0).cast());
        }
        if !sublayer.is_null() {
            FwpmFreeMemory0((&mut sublayer as *mut *mut FWPM_SUBLAYER0).cast());
        }
        FwpmEngineClose0(handle);
        assert_eq!(p, FWP_E_PROVIDER_NOT_FOUND.0 as u32);
        assert_eq!(s, FWP_E_SUBLAYER_NOT_FOUND.0 as u32);
    }
}

#[tokio::test]
#[ignore = "requires LocalSystem and a disposable Windows CI runner"]
async fn privileged_fence() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let sid = ps("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value");
    if sid != "S-1-5-18" {
        let exe = std::env::current_exe().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("child.log");
        let result = dir.path().join("exit.txt");
        let script = dir.path().join("run.ps1");
        let second_dir = std::env::var("ETD_O1_SECOND_DIR").unwrap();
        std::fs::write(&script,format!("$env:CI='true'\n$env:ETD_O1_SECOND_DIR={}\n& {} --exact privileged_fence --ignored --nocapture *> {}\n$LASTEXITCODE | Set-Content {}",quote(&second_dir),quote(&exe.to_string_lossy()),quote(&log.to_string_lossy()),quote(&result.to_string_lossy()))).unwrap();
        let task = format!("ETD-O1-System-{}", uuid::Uuid::new_v4());
        ps(&format!(
            "$ErrorActionPreference='Stop'; $a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"'; $p=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest; Register-ScheduledTask -TaskName '{task}' -Action $a -Principal $p | Out-Null; Start-ScheduledTask -TaskName '{task}'",
            script.display()
        ));
        let deadline = Instant::now() + Duration::from_secs(240);
        while !result.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
        ps(&format!(
            "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false"
        ));
        let output = std::fs::read(&log).unwrap_or_default();
        // PowerShell 5 redirects native stdout to a UTF-16 LE file.
        let log = if output.starts_with(&[255, 254]) {
            String::from_utf16_lossy(
                &output[2..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::from_utf8_lossy(&output).into_owned()
        };
        println!("{log}");
        assert_eq!(std::fs::read_to_string(&result).unwrap().trim(), "0");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let fence = os.fence.unwrap();
    for loopback in ["127.0.0.1:0", "[::1]:0"] {
        let listener = tokio::net::TcpListener::bind(loopback).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let spec = FenceSpec {
            instance: InstanceId::from("o1-fence"),
            epoch: Epoch(1),
            address: addr,
        };
        let intent = fence.plan(&spec);
        let second = || {
            let folder = std::path::PathBuf::from(std::env::var("ETD_O1_SECOND_DIR").unwrap());
            let file = folder.join("results/verdict.txt");
            let _ = std::fs::remove_file(&file);
            std::fs::write(folder.join("endpoint.tmp"), addr.to_string()).unwrap();
            std::fs::rename(folder.join("endpoint.tmp"), folder.join("endpoint.txt")).unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Ok(s) = std::fs::read_to_string(&file)
                    && !s.trim().is_empty()
                {
                    return s.trim().to_owned();
                }
                assert!(Instant::now() < deadline, "second account probe timed out");
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        assert_eq!(second(), "connected");
        let observation = fence.install(&spec).await.unwrap();
        assert!(matches!(
            observation.credential,
            Some(Credential::ExclusiveContainer { .. })
        ));
        let reclaim = os
            .reclaimers
            .iter()
            .find(|r| r.kind() == EffectKind::WinFenceFilter)
            .unwrap();
        let effect = Effect {
            id: EffectId("fence".into()),
            scope: intent.scope,
            kind: intent.kind,
            key: intent.key.clone(),
            undo: intent.undo,
            persistence: intent.persistence,
            state: EffectState::Applied,
            boot: os.boot_id.current().unwrap(),
            observation: Some(observation),
            failures: 0,
            last_error: None,
            recorded_at: jiff::Timestamp::now(),
        };
        assert!(matches!(reclaim.probe(&effect).await, Probe::Present(_)));
        let verification = fence.verify(&spec, std::process::id()).await;
        let verdict = second();
        drop(listener);
        assert_eq!(reclaim.reclaim(&effect).await.unwrap(), Reclaimed::Removed);
        assert!(matches!(reclaim.probe(&effect).await, Probe::Absent));
        assert_wfp_container_absent();
        assert!(
            os.observer
                .enumerate(SystemClass::FirewallRules)
                .await
                .unwrap()
                .iter()
                .all(|r| r.key != intent.key)
        );
        assert_eq!(verdict, "refused");
        let verification = verification.unwrap();
        assert!(verification.passed(), "{verification:?}");
        println!(
            "WFP {addr}: SYSTEM connected, independent second account refused; persistent filters reclaimed: {verification:?}"
        );
    }
}
