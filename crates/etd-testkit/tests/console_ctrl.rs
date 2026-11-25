#![cfg(windows)]
use etd_proc::{Command, ExitCause, ProcessEngine, processkit_engine::ProcessKitEngine};
use std::{path::PathBuf, time::Duration};

#[tokio::test]
async fn hidden_console_helper_delivers_ctrl_c_once() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let count = dir.path().join("signals");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_fake-core"));
    let engine = ProcessKitEngine::with_console_helper(executable.clone());
    let handle = engine
        .spawn(Command {
            executable,
            args: vec![
                "--mode".into(),
                "ignore".into(),
                "--ready-file".into(),
                ready.clone().into_os_string(),
                "--signal-log".into(),
                count.clone().into_os_string(),
            ],
            env: vec![],
            cwd: None,
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let grace = Duration::from_secs(2);
    let (a, b) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(handle.stop(grace), handle.stop(grace))
    })
    .await
    .unwrap();
    let a = a.unwrap();
    assert_eq!(a, b.unwrap());
    assert_eq!(a.cause, ExitCause::Killed);
    assert_eq!(std::fs::read_to_string(count).unwrap(), "1");
}
