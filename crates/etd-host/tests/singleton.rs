use etd_sysfx_os::service::HostLock;
use std::{io, path::PathBuf, process::Command};

#[test]
fn second_process_cannot_acquire_and_later_can() {
    let dir = tempfile::tempdir().unwrap();
    let guard = HostLock::acquire(dir.path()).unwrap();
    assert_eq!(
        HostLock::acquire(dir.path()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lock_contender", "--nocapture"])
        .env("ETD_LOCK_TEST_DIRECTORY", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(guard);
    assert!(HostLock::acquire(dir.path()).is_ok());
}

#[test]
fn lock_contender() {
    let Some(dir) = std::env::var_os("ETD_LOCK_TEST_DIRECTORY") else {
        return;
    };
    let result = HostLock::acquire(&PathBuf::from(dir));
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::WouldBlock);
}
