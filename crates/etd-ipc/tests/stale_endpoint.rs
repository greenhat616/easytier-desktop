#![cfg(unix)]
mod common;

use common::{Fixture, endpoint_arg, run_as_host};
use etd_ipc::{
    Endpoint, HostForm, Listener, ListenerPolicy, OsUserId,
    platform::{HeldHostLock, LocalListener},
};
use std::{
    fs::{self, DirBuilder, File},
    io::{self, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt},
        net::UnixListener as StdListener,
        process::ExitStatusExt,
    },
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

struct HostLock {
    _lock: File,
    endpoint: Endpoint,
}

impl HostLock {
    fn acquire(path: &Path) -> Self {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("lock"))
            .unwrap();
        file.try_lock().unwrap();
        Self {
            _lock: file,
            endpoint: Endpoint::UnixSocket(path.to_owned()),
        }
    }

    fn bind(&self) -> io::Result<LocalListener> {
        LocalListener::bind_replacing_stale(self.listener_claim(), &ListenerPolicy::default())
    }
}

impl HeldHostLock for HostLock {
    fn form(&self) -> HostForm {
        HostForm::User
    }
    fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

#[tokio::test]
async fn killed_host_can_recover_under_its_session_lock() {
    const NAME: &str = "killed_host_can_recover_under_its_session_lock";
    if let Some(path) = std::env::var_os("ETD_TEST_CHILD_SOCKET") {
        let path = Path::new(&path);
        let lock = HostLock::acquire(path);
        let _listener = lock.bind().unwrap();
        // Model death during the private staging phase alongside the real
        // published listener. The child's exit leaves both socket nodes.
        let stage = path
            .parent()
            .unwrap()
            .join(format!(".i{:x}.1", std::process::id()));
        DirBuilder::new().mode(0o700).create(&stage).unwrap();
        let _staged = StdListener::bind(stage.join("s")).unwrap();
        println!("ETD_TEST_READY");
        io::stdout().flush().unwrap();
        std::future::pending::<()>().await;
        return;
    }
    if !run_as_host(NAME) {
        return;
    }
    let f = Fixture::new();
    let path = endpoint_arg(&f.ep);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("ETD_TEST_CHILD_SOCKET", path)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    let stage = path.parent().unwrap().join(format!(".i{pid:x}.1"));
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("child exited before binding");
            if line.contains("ETD_TEST_READY") {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(path.exists() && stage.exists());
    child.start_kill().unwrap();
    assert_eq!(child.wait().await.unwrap().signal(), Some(libc::SIGKILL));
    assert_eq!(
        LocalListener::bind(HostForm::User, &f.ep, &ListenerPolicy::default())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    let lock = HostLock::acquire(path);
    let mut listener = lock.bind().unwrap();
    assert!(!stage.exists());
    let _client = tokio::net::UnixStream::connect(path).await.unwrap();
    let (_, peer) = listener.accept().await.unwrap();
    assert_eq!(
        peer.user,
        OsUserId::UnixUid(nix::unistd::Uid::effective().as_raw())
    );

    let before = fs::symlink_metadata(path).unwrap();
    assert_eq!(lock.bind().err().unwrap().kind(), io::ErrorKind::AddrInUse);
    assert_eq!(fs::symlink_metadata(path).unwrap().ino(), before.ino());
}

#[tokio::test]
async fn ordinary_files_and_symlinks_are_preserved() {
    if !run_as_host("ordinary_files_and_symlinks_are_preserved") {
        return;
    }
    let f = Fixture::new();
    let path = endpoint_arg(&f.ep);
    let lock = HostLock::acquire(path);
    fs::write(path, b"keep").unwrap();
    assert_eq!(
        lock.bind().err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(fs::read(path).unwrap(), b"keep");
    let saved = path.with_extension("saved");
    fs::rename(path, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, path).unwrap();
    assert_eq!(
        lock.bind().err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(fs::read_link(path).unwrap(), saved);
}

#[tokio::test]
#[ignore = "privileged: requires changing the socket inode owner to a second user"]
async fn foreign_owned_stale_socket_is_preserved() {
    if !run_as_host("foreign_owned_stale_socket_is_preserved") {
        return;
    }
    let f = Fixture::new();
    let path = endpoint_arg(&f.ep);
    let lock = HostLock::acquire(path);
    drop(StdListener::bind(path).unwrap());
    let user = nix::unistd::User::from_name("nobody").unwrap().unwrap();
    nix::unistd::chown(path, Some(user.uid), None).unwrap();
    let before = fs::symlink_metadata(path).unwrap();
    assert_eq!(
        lock.bind().err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(fs::symlink_metadata(path).unwrap().ino(), before.ino());
}
