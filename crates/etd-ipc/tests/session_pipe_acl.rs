//! Kernel access policy of the elevated session pipe (ES1).
#![cfg(windows)]
mod common;
#[path = "session_support/mod.rs"]
mod session_support;
use common::*;
use etd_ipc::{
    HostForm, Listener, ListenerPolicy, OsGroupId, OsUserId,
    platform::{LocalListener, current_user},
};
use session_support::*;
use std::{fs::File, io::ErrorKind, os::windows::io::AsRawHandle, ptr};
use tokio::net::windows::named_pipe::ServerOptions;
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{Authorization::*, *},
        Storage::FileSystem::{READ_CONTROL, WRITE_DAC, WRITE_OWNER},
    },
    core::PWSTR,
};

const OWNER_RIGHTS: &str = "S-1-3-4";
const ADMINISTRATORS: &str = "S-1-5-32-544";
/// FILE_CREATE_PIPE_INSTANCE | FILE_READ_EA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES.
const HOST_EXTRA: u32 = 0x11c;

fn sid_text(sid: PSID) -> String {
    unsafe {
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut text).unwrap();
        let value = text.to_string().unwrap();
        LocalFree(Some(HLOCAL(text.0.cast())));
        value
    }
}

/// A DACL entry: ACE type, SID, mask.
type Allowed = (u8, String, u32);
/// A label SACL entry: ACE type, ACE flags, SID, mask.
type Label = (u8, u8, String, u32);

/// The pipe's owner, every ACE of its DACL and of its label SACL.
fn security(f: &File) -> (String, Vec<Allowed>, Vec<Label>) {
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut();
    let mut sacl = ptr::null_mut();
    let mut desc = PSECURITY_DESCRIPTOR::default();
    let mut allowed = Vec::new();
    let mut labels = Vec::new();
    unsafe {
        GetSecurityInfo(
            HANDLE(f.as_raw_handle()),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            Some(&mut sacl),
            Some(&mut desc),
        )
        .ok()
        .unwrap();
        assert!(!dacl.is_null() && !sacl.is_null());
        for i in 0..(*dacl).AceCount {
            let mut p = ptr::null_mut();
            GetAce(dacl, i as u32, &mut p).unwrap();
            let ace = &*p.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_text(PSID((&raw const ace.SidStart).cast_mut().cast()));
            allowed.push((ace.Header.AceType, sid, ace.Mask));
        }
        for i in 0..(*sacl).AceCount {
            let mut p = ptr::null_mut();
            GetAce(sacl, i as u32, &mut p).unwrap();
            let ace = &*p.cast::<SYSTEM_MANDATORY_LABEL_ACE>();
            let sid = sid_text(PSID((&raw const ace.SidStart).cast_mut().cast()));
            labels.push((ace.Header.AceType, ace.Header.AceFlags, sid, ace.Mask));
        }
        let owner = sid_text(owner);
        LocalFree(Some(HLOCAL(desc.0)));
        (owner, allowed, labels)
    }
}

#[tokio::test]
#[ignore = "Windows administrator CI runner: restricted and low-box token copies"]
async fn session_pipe_is_owner_only_medium_no_write_up_and_first_instance() {
    let f = Fixture::new();
    let pipe = endpoint_arg(&f.ep);
    let name = pipe.to_str().unwrap();
    let mut listener =
        LocalListener::bind(HostForm::ElevatedSession, &f.ep, &ListenerPolicy::default()).unwrap();

    // First instance only, and never for another policy or a remote client.
    assert!(
        LocalListener::bind(HostForm::ElevatedSession, &f.ep, &ListenerPolicy::default()).is_err()
    );
    let remote = name.replacen(r"\\.\", r"\\localhost\", 1);
    assert!(open(remote.as_ref(), client_mask()).is_err());
    let other = Fixture::new();
    for policy in [
        ListenerPolicy {
            allow_users: vec![OsUserId::WindowsSid("S-1-5-21-1-2-3-4".into())],
            ..Default::default()
        },
        ListenerPolicy {
            allow_groups: vec![OsGroupId::WindowsSid(ADMINISTRATORS.into())],
            ..Default::default()
        },
        ListenerPolicy {
            unix_group: Some("easytier-desk".into()),
            ..Default::default()
        },
    ] {
        let error = LocalListener::bind(HostForm::ElevatedSession, &other.ep, &policy)
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(listener.policy_handle().update(&policy).is_err());
    }
    listener
        .policy_handle()
        .update(&ListenerPolicy::default())
        .unwrap();

    // Read the descriptor through the host's own client handle, then let
    // the listener drop that connection and publish the next instance.
    let file = open(pipe, READ_CONTROL.0).unwrap();
    let (owner, dacl, sacl) = security(&file);
    drop(file);
    assert!(listener.accept().await.is_err());
    let OsUserId::WindowsSid(host) = current_user().unwrap() else {
        unreachable!()
    };
    let shown = format!("owner {owner}, DACL {dacl:x?}, SACL {sacl:x?}");
    assert_eq!(owner, host, "{shown}");
    let mut entries: Vec<_> = dacl
        .into_iter()
        .map(|(kind, sid, mask)| {
            assert_eq!(kind, 0, "only access-allowed ACEs: {shown}");
            (sid, mask)
        })
        .collect();
    entries.sort();
    let mut expected = vec![
        (host, client_mask()),
        (OWNER_RIGHTS.to_owned(), client_mask()),
        (ADMINISTRATORS.to_owned(), HOST_EXTRA),
    ];
    expected.sort();
    assert_eq!(entries, expected, "{shown}");
    // SYSTEM_MANDATORY_LABEL_ACE_TYPE, no inheritance flags, Medium,
    // SYSTEM_MANDATORY_LABEL_NO_WRITE_UP.
    assert_eq!(
        sacl,
        vec![(0x11, 0, "S-1-16-8192".to_owned(), 0x1)],
        "{shown}"
    );

    // A same-user, non-elevated Medium token may open for client access
    // only: never WRITE_DAC, WRITE_OWNER or a new server instance. A client
    // open requesting FILE_APPEND_DATA succeeds on the runner although no
    // ACE grants it; that bit means FILE_CREATE_PIPE_INSTANCE only to
    // CreateNamedPipe, which is probed below with a real instance.
    let medium = restricted_token(MEDIUM);
    let mut granted = Vec::new();
    for access in [WRITE_DAC.0, WRITE_OWNER.0] {
        match impersonating(&medium, || open(pipe, access | READ_CONTROL.0)) {
            Err(error) => assert_eq!(error.kind(), ErrorKind::PermissionDenied, "{access:#x}"),
            Ok(file) => {
                granted.push(format!("{access:#x}: {:x?}", security(&file)));
                drop(file);
                assert!(listener.accept().await.is_err());
            }
        }
    }
    assert!(granted.is_empty(), "Medium copy was granted {granted:?}");
    let instance = impersonating(&medium, || ServerOptions::new().create(name));
    assert_eq!(instance.err().unwrap().kind(), ErrorKind::PermissionDenied);
    let squat = impersonating(&medium, || {
        ServerOptions::new().first_pipe_instance(true).create(name)
    });
    assert!(squat.is_err());

    // Low integrity and AppContainer tokens cannot open it for writing.
    for token in [restricted_token(LOW), app_container_token()] {
        let error = impersonating(&token, || open(pipe, client_mask())).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    // The Medium copy can open it as a client.
    let client = impersonating(&medium, || open(pipe, client_mask()));
    assert!(client.is_ok(), "{client:?}");
}
