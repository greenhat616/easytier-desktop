#![cfg(unix)]
mod common;
use common::*;
use etd_ipc::{ListenerPolicy, OsUserId};
use nix::unistd::{Uid, User};
use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::Command,
};

#[tokio::test]
#[ignore = "privileged: root drops to a second local account to test the kernel socket ACL"]
async fn privileged_second_account_denied_then_granted_then_revoked() {
    assert!(Uid::effective().is_root());
    let user = User::from_name("nobody").unwrap().unwrap();
    let f = Fixture::new();
    fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let listener = f.listener();
    let probe = || {
        let status=Command::new("python3").arg("-c").arg(
            "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect(sys.argv[1])\nexcept PermissionError: sys.exit(77)"
        ).arg(endpoint_arg(&f.ep)).uid(user.uid.as_raw()).gid(user.gid.as_raw()).status().unwrap();
        status.code().unwrap()
    };
    assert_eq!(probe(), 77);
    let policy = listener.policy_handle();
    policy
        .update(&ListenerPolicy {
            allow_users: vec![OsUserId::UnixUid(user.uid.as_raw())],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(probe(), 0);
    policy.update(&ListenerPolicy::default()).unwrap();
    assert_eq!(probe(), 77);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use etd_ipc::{Connector, Endpoint, Listener, platform::LocalListener};
    use nix::unistd::chown;
    use std::process::Stdio;
    use std::{io::ErrorKind, os::unix::fs::symlink};
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[tokio::test]
    async fn writable_service_ancestor_refused() {
        let f = Fixture::new();
        let _listener = f.listener();
        let mut c = connector();
        c.expectation.privileged = true;
        assert_eq!(
            c.connect(&f.ep).await.err().unwrap().kind(),
            ErrorKind::PermissionDenied
        );
    }
    #[tokio::test]
    #[ignore = "privileged: requires root and a root-owned /run directory"]
    async fn privileged_service_proves_directory_inode_and_peer() {
        assert!(Uid::effective().is_root());
        let dir = tempfile::tempdir_in("/run").unwrap();
        let socket = dir.path().join("host.sock");
        let ep = Endpoint::UnixSocket(socket.clone());
        let listener = LocalListener::bind(&ep, &ListenerPolicy::default()).unwrap();
        let mut c = connector();
        c.expectation.privileged = true;
        let alias = dir.path().join("alias");
        symlink(dir.path(), &alias).unwrap();
        assert_eq!(
            c.connect(&Endpoint::UnixSocket(alias.join("host.sock")))
                .await
                .err()
                .unwrap()
                .kind(),
            ErrorKind::PermissionDenied
        );
        let user = User::from_name("nobody").unwrap().unwrap();
        chown(&socket, Some(user.uid), None).unwrap();
        assert_eq!(
            c.connect(&ep).await.err().unwrap().kind(),
            ErrorKind::PermissionDenied
        );
        drop(listener);

        // Even a genuine root-owned socket inode in a protected directory
        // cannot vouch for a listener originally created by another uid.
        let tmp = tempfile::tempdir_in("/run").unwrap();
        chown(tmp.path(), Some(user.uid), None).unwrap();
        let untrusted = tmp.path().join("other");
        let mut cmd = Command::new("python3");
        cmd.arg("-u").arg("-c").arg("import socket,sys\ns=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen();print('ready');s.accept()")
            .arg(&untrusted).uid(user.uid.as_raw()).gid(user.gid.as_raw()).stdout(Stdio::piped());
        let mut child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .await
            .unwrap();
        assert_eq!(line.trim(), "ready");
        fs::rename(untrusted, &socket).unwrap();
        chown(&socket, Some(Uid::from_raw(0)), None).unwrap();
        assert_eq!(
            c.connect(&ep).await.err().unwrap().kind(),
            ErrorKind::PermissionDenied
        );
        assert!(child.wait().await.unwrap().success());
    }

    #[tokio::test]
    #[ignore = "privileged: verifies an unprivileged client connecting to the root service"]
    async fn privileged_root_service_accepts_non_root_ui() {
        if let Some(path) = std::env::var_os("ETD_SERVICE_SOCKET") {
            let mut c = connector();
            c.expectation.privileged = true;
            let (_, host) = c.connect(&Endpoint::UnixSocket(path.into())).await.unwrap();
            assert_eq!(host.peer.user, OsUserId::UnixUid(0));
            return;
        }
        if !run_as_host("linux::privileged_root_service_accepts_non_root_ui") {
            return;
        }
        assert!(Uid::effective().is_root());
        let user = User::from_name("nobody").unwrap().unwrap();
        let dir = tempfile::tempdir_in("/run").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let socket = dir.path().join("service.sock");
        let mut listener = LocalListener::bind(
            &Endpoint::UnixSocket(socket.clone()),
            &ListenerPolicy {
                allow_users: vec![OsUserId::UnixUid(user.uid.as_raw())],
                ..Default::default()
            },
        )
        .unwrap();
        let exe = std::env::current_exe().unwrap();
        // The unprivileged child needs a traversable directory. Keep the installed
        // image read-only to that user and place the UI fixture alongside it.
        fs::set_permissions(exe.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        let mut cmd = Command::new(exe);
        cmd.args([
            "--ignored",
            "--exact",
            "linux::privileged_root_service_accepts_non_root_ui",
        ])
        .uid(user.uid.as_raw())
        .gid(user.gid.as_raw())
        .env("ETD_SERVICE_SOCKET", socket);
        let mut child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (accepted, exit) = tokio::join!(listener.accept(), child.wait());
        assert!(exit.unwrap().success());
        assert_eq!(
            accepted.unwrap().1.user,
            OsUserId::UnixUid(user.uid.as_raw())
        );
    }
}
