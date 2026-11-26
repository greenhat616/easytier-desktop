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
        let second_task = std::env::var("ETD_O1_SECOND_TASK").unwrap();
        std::fs::write(&script,format!("$env:CI='true'\n$env:ETD_O1_SECOND_DIR={}\n$env:ETD_O1_SECOND_TASK={}\n& {} --exact privileged_fence --ignored --nocapture *> {}\n$LASTEXITCODE | Set-Content {}",quote(&second_dir),quote(&second_task),quote(&exe.to_string_lossy()),quote(&log.to_string_lossy()),quote(&result.to_string_lossy()))).unwrap();
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
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
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
            let file = folder.join("verdict.txt");
            let _ = std::fs::remove_file(&file);
            std::fs::write(folder.join("endpoint.txt"), addr.to_string()).unwrap();
            let task = std::env::var("ETD_O1_SECOND_TASK").unwrap();
            ps(&format!("Start-ScheduledTask -TaskName {}", quote(&task)));
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
