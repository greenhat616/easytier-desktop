mod common;
use common::*;
use etd_ipc::{Connector, Listener, ListenerPolicy, OsUserId};

#[tokio::test]
async fn kernel_identity_matches_process() {
    if !run_as_host("kernel_identity_matches_process") {
        return;
    }
    let f = Fixture::new();
    let mut listener = f.listener();
    let policy = listener.policy_handle();
    policy.update(&ListenerPolicy::default()).unwrap();
    let connector = connector();
    let (accepted, connected) = tokio::join!(listener.accept(), connector.connect(&f.ep));
    let (_, server) = connected.unwrap();
    let (_, peer) = accepted.unwrap();
    assert_eq!(peer.pid, std::process::id());
    assert_eq!(peer, server.peer);
    if verifies_user_image() {
        assert_eq!(
            server.exe,
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    } else {
        assert!(server.exe.as_os_str().is_empty());
    }
    #[cfg(unix)]
    {
        use nix::unistd::{Gid, Uid};
        assert_eq!(peer.user, OsUserId::UnixUid(Uid::effective().as_raw()));
        assert_eq!(peer.elevated, Uid::effective().is_root());
        assert_eq!(peer.session, None);
        assert!(
            peer.groups
                .contains(&etd_ipc::OsGroupId::UnixGid(Gid::effective().as_raw()))
        );
        #[cfg(target_os = "linux")]
        for group in nix::unistd::getgroups().unwrap() {
            assert!(
                peer.groups
                    .contains(&etd_ipc::OsGroupId::UnixGid(group.as_raw()))
            );
        }
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        let line = String::from_utf8_lossy(&out.stdout);
        let sid = line
            .trim()
            .trim_end_matches('"')
            .rsplit('"')
            .next()
            .unwrap();
        assert_eq!(peer.user, OsUserId::WindowsSid(sid.into()));
        assert!(peer.session.is_some());
        assert!(!peer.groups.is_empty());
    }
    drop(listener);
    assert!(policy.update(&ListenerPolicy::default()).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn socket_policy_replacement_and_exclusive_name() {
    use nix::unistd::{Gid, Group};
    use std::{fs, os::unix::fs::MetadataExt};
    let f = Fixture::new();
    let listener = f.listener();
    let path = endpoint_arg(&f.ep);
    let old = fs::symlink_metadata(path).unwrap();
    assert_eq!(old.mode() & 0o777, 0o600);
    assert!(etd_ipc::platform::LocalListener::bind(&f.ep, &ListenerPolicy::default()).is_err());
    let group = Group::from_gid(Gid::effective()).unwrap().unwrap();
    listener
        .policy_handle()
        .update(&ListenerPolicy {
            unix_group: Some(group.name),
            ..Default::default()
        })
        .unwrap();
    let new = fs::symlink_metadata(path).unwrap();
    assert_ne!(old.ino(), new.ino());
    assert_eq!(new.gid(), group.gid.as_raw());
    assert_eq!(new.mode() & 0o777, 0o660);
    assert!(
        listener
            .policy_handle()
            .update(&ListenerPolicy {
                unix_group: Some("etd-missing-group-fixture".into()),
                ..Default::default()
            })
            .is_err()
    );
    assert_eq!(fs::symlink_metadata(path).unwrap().ino(), new.ino());
    drop(listener);
    assert!(!path.exists());
}
