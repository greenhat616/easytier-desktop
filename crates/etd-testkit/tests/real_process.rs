use etd_proc::{
    Command, Containment, ExitCause, KillOutcome, Liveness, ProcessEngine, ProcessError,
    ProcessEvent, ProcessIdentity, ProcessMarker, processkit_engine::ProcessKitEngine,
};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

fn executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake-core"))
}
fn engine() -> ProcessKitEngine {
    ProcessKitEngine::with_console_helper(executable())
}
fn command(args: Vec<OsString>) -> Command {
    Command {
        executable: executable(),
        args,
        env: vec![],
        cwd: None,
    }
}
fn marker(dir: &TempDir) -> ProcessMarker {
    ProcessMarker {
        exe_root: executable().parent().unwrap().into(),
        cmdline_root: dir.path().into(),
    }
}
async fn file(path: &Path) -> String {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(text) = std::fs::read_to_string(path)
                && !text.is_empty()
            {
                return text;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fake-core did not become ready")
}
async fn gone(engine: &ProcessKitEngine, id: &ProcessIdentity) {
    timeout(Duration::from_secs(10), async {
        loop {
            if matches!(engine.liveness(id).await, Liveness::Gone | Liveness::Reused) {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("process still exists or cannot be verified");
}
#[tokio::test]
async fn graceful_stop_has_exit_code_and_single_exit_event() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let engine = engine();
    let mut args = vec![
        "--ready-file".into(),
        ready.clone().into_os_string(),
        "--exit-code".into(),
        "23".into(),
    ];
    if cfg!(windows) {
        args.extend([OsString::from("--check-windows-env"), "yes".into()]);
    }
    let mut handle = engine.spawn(command(args)).await.unwrap();
    #[cfg(windows)]
    assert_eq!(handle.containment(), Containment::JobObject);
    #[cfg(target_os = "linux")]
    {
        let cgroup =
            std::fs::read_to_string(format!("/proc/{}/cgroup", handle.identity().pid)).unwrap();
        let parent = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let expected =
            if cgroup != parent && cgroup.lines().any(|line| line.contains("/processkit-")) {
                Containment::CgroupV2
            } else {
                let stat = std::fs::read_to_string(format!("/proc/{}/stat", handle.identity().pid))
                    .unwrap();
                let pgid: u32 = stat
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .split_whitespace()
                    .nth(2)
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(pgid, handle.identity().pid);
                Containment::ProcessGroup
            };
        assert_eq!(handle.containment(), expected);
    }
    #[cfg(target_os = "macos")]
    assert_eq!(handle.containment(), Containment::ProcessGroup);
    let _ = file(&ready).await;
    let mut events = handle.take_events().unwrap();
    assert!(handle.take_events().is_none());
    let exit = timeout(Duration::from_secs(10), handle.stop(Duration::from_secs(3)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.cause, ExitCause::Stopped);
    assert_eq!(exit.code, Some(23));
    assert_eq!(handle.wait().await, exit);
    let mut exited = 0;
    let mut stdout = Vec::new();
    while let Some(event) = timeout(Duration::from_secs(3), events.recv())
        .await
        .unwrap()
    {
        match event {
            ProcessEvent::Exited(actual) => {
                assert_eq!(actual, exit);
                exited += 1;
            }
            ProcessEvent::Stdout(bytes) => stdout.extend(bytes),
            _ => {}
        }
    }
    assert_eq!(exited, 1);
    assert!(String::from_utf8_lossy(&stdout).contains("READY"));
    gone(&engine, handle.identity()).await;
}

#[tokio::test]
async fn fast_exit_preserves_exit_code_for_restart_policy() {
    let engine = engine();
    let result = engine
        .spawn(command(vec![
            "--exit-after-ms".into(),
            "0".into(),
            "--exit-code".into(),
            "37".into(),
        ]))
        .await;
    let exit = match result {
        Ok(handle) => timeout(Duration::from_secs(10), handle.wait())
            .await
            .unwrap(),
        Err(ProcessError::ExitedBeforeIdentity(exit)) => exit,
        Err(error) => panic!("unexpected launch failure: {error}"),
    };
    assert!(exit.abnormal());
    assert_eq!(exit.code, Some(37));
}
#[tokio::test]
async fn timeout_kills_tree_and_never_kills_reused_pid() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let child = dir.path().join("child");
    let config = dir.path().join("config");
    std::fs::write(&config, "").unwrap();
    let engine = engine();
    let handle = engine
        .spawn(command(vec![
            "--mode".into(),
            "ignore".into(),
            "--ready-file".into(),
            ready.clone().into_os_string(),
            "--spawn-child".into(),
            child.clone().into_os_string(),
            "-c".into(),
            config.into_os_string(),
        ]))
        .await
        .unwrap();
    file(&ready).await;
    let child_pid = file(&child).await.parse::<u32>().unwrap();
    let found = engine.find_marked(&marker(&dir)).await.unwrap();
    let child_id = found
        .iter()
        .find(|id| id.pid == child_pid)
        .expect("grandchild must be enumerated")
        .clone();
    assert!(found.contains(handle.identity()));
    let mut stale = handle.identity().clone();
    stale.start_token.push_str("-stale");
    assert_eq!(engine.liveness(&stale).await, Liveness::Reused);
    assert_eq!(
        engine.kill_verified(&stale).await.unwrap(),
        KillOutcome::Uncertain
    );
    assert_eq!(engine.liveness(handle.identity()).await, Liveness::Same);
    let exit = timeout(
        Duration::from_secs(10),
        handle.stop(Duration::from_millis(100)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(exit.cause, ExitCause::Killed);
    gone(&engine, handle.identity()).await;
    gone(&engine, &child_id).await;
}

#[tokio::test]
async fn unsolicited_root_exit_does_not_leave_its_descendant_or_block_wait() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let child = dir.path().join("child");
    let exit_file = dir.path().join("exit");
    let engine = engine();
    let handle = engine
        .spawn(command(vec![
            "--mode".into(),
            "ignore".into(),
            "--ready-file".into(),
            ready.into_os_string(),
            "--spawn-child".into(),
            child.clone().into_os_string(),
            "--exit-file".into(),
            exit_file.clone().into_os_string(),
            "--exit-code".into(),
            "17".into(),
        ]))
        .await
        .unwrap();
    let child_pid = file(&child).await.parse::<u32>().unwrap();
    let child_id = engine
        .find_marked(&marker(&dir))
        .await
        .unwrap()
        .into_iter()
        .find(|id| id.pid == child_pid)
        .unwrap();
    std::fs::write(exit_file, "exit").unwrap();
    let exit = timeout(Duration::from_secs(10), handle.wait())
        .await
        .unwrap();
    assert_eq!(exit.cause, ExitCause::Exited);
    assert_eq!(exit.code, Some(17));
    assert_eq!(handle.stop(Duration::ZERO).await.unwrap(), exit);
    gone(&engine, &child_id).await;
}
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn unrecorded_marked_process_is_pinned_before_termination() {
    marked_orphan_fixture().await;
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_orphan_verify_then_signal_has_explicit_toctou_window() {
    marked_orphan_fixture().await;
}

async fn marked_orphan_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let config = dir.path().join("config");
    std::fs::write(&config, "").unwrap();
    let mut child = tokio::process::Command::new(executable())
        .args(["--mode", "ignore", "--ready-file"])
        .arg(&ready)
        .arg("-c")
        .arg(&config)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    file(&ready).await;
    let engine = engine();
    let found = engine.find_marked(&marker(&dir)).await.unwrap();
    let id = found
        .into_iter()
        .find(|id| Some(id.pid) == child.id())
        .expect("marked orphan");
    // Discovery and recovery can use distinct facade instances; the exact
    // identity-to-marker binding is process-global.
    let outcome = ProcessKitEngine::new().kill_verified(&id).await.unwrap();
    assert_eq!(outcome, KillOutcome::Killed);
    timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    gone(&engine, &id).await;
}

#[cfg(any(windows, target_os = "linux"))]
#[tokio::test]
async fn orphan_with_uncontained_descendant_is_quarantined_before_root_kill() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let child_ready = dir.path().join("child");
    let mut root = tokio::process::Command::new(executable())
        .args(["--mode", "ignore", "--ready-file"])
        .arg(&ready)
        .arg("--spawn-child")
        .arg(&child_ready)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    file(&ready).await;
    let child_pid = file(&child_ready).await.parse::<u32>().unwrap();
    let engine = engine();
    let found = engine.find_marked(&marker(&dir)).await.unwrap();
    let root_id = found.iter().find(|id| Some(id.pid) == root.id()).unwrap();
    let child_id = found.iter().find(|id| id.pid == child_pid).unwrap();
    assert_eq!(
        engine.kill_verified(root_id).await.unwrap(),
        KillOutcome::Uncertain
    );
    assert_eq!(engine.liveness(root_id).await, Liveness::Same);
    assert_eq!(engine.liveness(child_id).await, Liveness::Same);
    // Individually established marker + pin for both leaves allows test
    // cleanup without a bare PID operation or a guessed tree identity.
    assert_eq!(
        engine.kill_verified(child_id).await.unwrap(),
        KillOutcome::Killed
    );
    gone(&engine, child_id).await;
    timeout(Duration::from_secs(5), async {
        loop {
            match engine.kill_verified(root_id).await.unwrap() {
                KillOutcome::Killed | KillOutcome::Gone => break,
                KillOutcome::Uncertain => sleep(Duration::from_millis(50)).await,
                other => panic!("unexpected root status: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    root.wait().await.unwrap();
}
/// Regression for the macOS abrupt-parent-death flake: a host killed before
/// the fake core's first write left it writing to a pipe with no reader, so
/// it died on EPIPE and the marker sweep correctly no longer listed it. The
/// read ends are closed before spawn, so this fails deterministically if any
/// startup output can still terminate the fake core.
#[tokio::test]
async fn fake_core_outlives_closed_output_pipes() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut child = tokio::process::Command::new(executable())
        .args([
            "--mode",
            "ignore",
            "--exit-after-ms",
            "30000",
            "--ready-file",
        ])
        .arg(&ready)
        .stdout(writer.try_clone().unwrap())
        .stderr(writer)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    file(&ready).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "fake-core exited after writing to a closed pipe"
    );
    child.kill().await.unwrap();
}

#[tokio::test]
async fn abrupt_parent_death_platform_guarantee() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("identity");
    let mut host = tokio::process::Command::new(executable())
        .arg("--host-probe")
        .arg(&record)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let text = file(&record).await;
    let mut parts = text.lines();
    let id = ProcessIdentity {
        pid: parts.next().unwrap().parse().unwrap(),
        start_token: parts.next().unwrap().into(),
        exe: parts.next().unwrap().into(),
    };
    let engine = engine();
    assert_eq!(engine.liveness(&id).await, Liveness::Same);
    host.kill().await.unwrap();
    #[cfg(any(windows, target_os = "linux"))]
    gone(&engine, &id).await;
    #[cfg(target_os = "macos")]
    {
        // No cached marker: quarantine rather than signal by persisted PID.
        assert_eq!(
            engine.kill_verified(&id).await.unwrap(),
            KillOutcome::Uncertain
        );
        let found = engine.find_marked(&marker(&dir)).await.unwrap();
        assert!(found.contains(&id));
        // Human-approved verify-then-signal path: unlike Windows/Linux,
        // macOS retains a narrow TOCTOU between verification and delivery.
        assert_eq!(
            engine.kill_verified(&id).await.unwrap(),
            KillOutcome::Killed
        );
        gone(&engine, &id).await;
    }
}
