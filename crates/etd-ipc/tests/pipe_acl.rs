#![cfg(windows)]
mod common;
#[path = "common/windows_account.rs"]
mod windows_account;
use common::*;
use etd_ipc::{
    ListenerPolicy, OsUserId,
    platform::{LocalListener, current_user},
};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{Authorization::*, *},
        Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, READ_CONTROL, SYNCHRONIZE,
        },
    },
    core::PWSTR,
};

fn entries(f: &File) -> BTreeMap<String, u32> {
    let mut acl = ptr::null_mut();
    let mut desc = PSECURITY_DESCRIPTOR::default();
    let mut result = BTreeMap::new();
    unsafe {
        GetSecurityInfo(
            HANDLE(f.as_raw_handle()),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            Some(&mut desc),
        )
        .ok()
        .unwrap();
        assert!(!acl.is_null());
        for i in 0..(*acl).AceCount {
            let mut p = ptr::null_mut();
            GetAce(acl, i as u32, &mut p).unwrap();
            let ace = &*p.cast::<ACCESS_ALLOWED_ACE>();
            assert_eq!(ace.Header.AceType, 0);
            let mut text = PWSTR::null();
            ConvertSidToStringSidW(PSID((&raw const ace.SidStart).cast_mut().cast()), &mut text)
                .unwrap();
            let sid = text.to_string().unwrap();
            LocalFree(Some(HLOCAL(text.0.cast())));
            *result.entry(sid).or_default() |= ace.Mask;
        }
        LocalFree(Some(HLOCAL(desc.0)));
    }
    result
}
#[tokio::test]
async fn first_instance_local_only_and_live_kernel_dacl() {
    let f = Fixture::new();
    let local = endpoint_arg(&f.ep);
    let listed = "S-1-5-21-11111-22222-33333-44444";
    let policy = ListenerPolicy {
        allow_users: vec![OsUserId::WindowsSid(listed.into())],
        ..Default::default()
    };
    let listener = LocalListener::bind(etd_ipc::HostForm::Service, &f.ep, &policy).unwrap();
    assert!(LocalListener::bind(etd_ipc::HostForm::Service, &f.ep, &policy).is_err());
    let remote = local
        .to_str()
        .unwrap()
        .replacen(r"\\.\", r"\\localhost\", 1);
    assert!(
        OpenOptions::new()
            .access_mode(FILE_READ_DATA.0 | FILE_WRITE_DATA.0)
            .read(true)
            .open(remote)
            .is_err()
    );
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL.0)
        .read(true)
        .open(local)
        .unwrap();
    let rw =
        (FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE).0;
    let OsUserId::WindowsSid(host) = current_user().unwrap() else {
        unreachable!()
    };
    let mut expected = BTreeMap::from([
        ("S-1-5-18".into(), rw),
        ("S-1-5-32-544".into(), rw),
        (listed.into(), rw),
    ]);
    expected.insert(host, 0x0016019f);
    assert_eq!(entries(&file), expected);
    listener
        .policy_handle()
        .update(&ListenerPolicy::default())
        .unwrap();
    expected.remove(listed);
    assert_eq!(entries(&file), expected);
}

#[tokio::test]
async fn user_form_dacl_is_owner_only_and_cannot_be_widened() {
    let f = Fixture::new();
    let listener =
        LocalListener::bind(etd_ipc::HostForm::User, &f.ep, &ListenerPolicy::default()).unwrap();
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL.0)
        .read(true)
        .open(endpoint_arg(&f.ep))
        .unwrap();
    let OsUserId::WindowsSid(owner) = current_user().unwrap() else {
        unreachable!()
    };
    let expected = BTreeMap::from([(owner, 0x0016019f)]);
    assert_eq!(entries(&file), expected);
    assert!(
        listener
            .policy_handle()
            .update(&ListenerPolicy {
                allow_groups: vec![etd_ipc::OsGroupId::WindowsSid("S-1-5-32-544".into())],
                ..Default::default()
            })
            .is_err()
    );
    assert_eq!(entries(&file), expected);
}

fn elevated() -> bool {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h).unwrap();
        let token = OwnedHandle::from_raw_handle(h.0);
        let mut info = TOKEN_ELEVATION::default();
        let mut len = 0;
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenElevation,
            Some((&raw mut info).cast()),
            size_of_val(&info) as u32,
            &mut len,
        )
        .unwrap();
        info.TokenIsElevated != 0
    }
}
#[tokio::test]
async fn second_account_denied_allowed_and_revoked_on_real_pipe() {
    use etd_ipc::Listener;
    use std::io::Write;
    let reason =
        if std::env::var_os("ETD_IPC_CI_ACCOUNTS").as_deref() != Some(std::ffi::OsStr::new("1")) {
            Some("set ETD_IPC_CI_ACCOUNTS=1 to allow creating a temporary standard user")
        } else if !elevated() {
            Some("requires an elevated Windows token to create the temporary second account")
        } else {
            None
        };
    if let Some(reason) = reason {
        assert!(
            std::env::var_os("GITHUB_ACTIONS").is_none(),
            "{reason}: CI must exercise the real ACL"
        );
        eprintln!("skipped: {reason}");
        return;
    }
    let f = Fixture::new();
    let mut listener = LocalListener::bind(
        etd_ipc::HostForm::Service,
        &f.ep,
        &ListenerPolicy::default(),
    )
    .unwrap();
    let (token, second_user) = windows_account::logon();
    let open = |ep: &etd_ipc::Endpoint| {
        unsafe {
            ImpersonateLoggedOnUser(HANDLE(token.as_raw_handle())).unwrap();
        }
        let opened = OpenOptions::new()
            .read(true)
            .access_mode(FILE_READ_DATA.0 | FILE_WRITE_DATA.0)
            .security_qos_flags(windows::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION.0)
            .open(endpoint_arg(ep));
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
        opened
    };
    let policy = listener.policy_handle();
    assert_eq!(
        open(&f.ep).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    policy
        .update(&ListenerPolicy {
            allow_users: vec![second_user.clone()],
            ..Default::default()
        })
        .unwrap();
    let mut allowed = open(&f.ep).unwrap();
    allowed.write_all(&[1]).unwrap();
    let (stream, peer) = listener.accept().await.unwrap();
    assert_eq!(peer.user, second_user);
    policy.update(&ListenerPolicy::default()).unwrap();
    assert_eq!(
        open(&f.ep).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    drop(stream);
    drop(allowed);
    drop(listener);
    // Tokio may retain overlapped named-pipe handles briefly after drop;
    // this is a separate user-host endpoint, not a service-name takeover.
    let user_fixture = Fixture::new();
    let user = LocalListener::bind(
        etd_ipc::HostForm::User,
        &user_fixture.ep,
        &ListenerPolicy::default(),
    )
    .unwrap();
    assert_eq!(
        open(&user_fixture.ep).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    drop(user);
}
