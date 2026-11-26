//! Who can connect to the elevated session pipe and what the listener
//! reports for them (ES1).
#![cfg(windows)]
mod common;
#[path = "session_support/mod.rs"]
mod session_support;
#[path = "common/windows_account.rs"]
mod windows_account;
use common::*;
use etd_ipc::{
    HostForm, Listener, ListenerPolicy,
    platform::{LocalListener, current_user},
};
use session_support::*;
use std::{io::ErrorKind, io::Write};

fn bind() -> (Fixture, LocalListener) {
    let f = Fixture::new();
    let listener =
        LocalListener::bind(HostForm::ElevatedSession, &f.ep, &ListenerPolicy::default()).unwrap();
    (f, listener)
}

#[tokio::test]
#[ignore = "Windows administrator CI runner: restricted token copy of the runner"]
async fn non_elevated_medium_copy_is_admitted_as_not_elevated() {
    let (f, mut listener) = bind();
    let medium = restricted_token(MEDIUM);
    let mut client = impersonating(&medium, || open(endpoint_arg(&f.ep), client_mask())).unwrap();
    client.write_all(&[1]).unwrap();
    let (_conn, peer) = listener.accept().await.unwrap();
    assert_eq!(peer.user, current_user().unwrap());
    assert_eq!(peer.pid, std::process::id());
    assert!(
        !peer.elevated,
        "Administrators deny-only copy reported elevated"
    );
    // Admission rejects anything below Medium, so being admitted is the
    // proof of integrity >= Medium.
    assert!(peer.session.is_some());
}

#[tokio::test]
#[ignore = "Windows administrator CI runner: elevated runner token"]
async fn elevated_same_user_client_is_admitted_as_elevated() {
    let (f, mut listener) = bind();
    let mut client = open(endpoint_arg(&f.ep), client_mask()).unwrap();
    client.write_all(&[1]).unwrap();
    let (_conn, peer) = listener.accept().await.unwrap();
    assert_eq!(peer.user, current_user().unwrap());
    assert!(peer.elevated);
}

#[tokio::test]
#[ignore = "Windows administrator CI runner: low integrity token copy"]
async fn low_integrity_copy_is_refused_at_open() {
    let (f, _listener) = bind();
    let low = restricted_token(LOW);
    let error = impersonating(&low, || open(endpoint_arg(&f.ep), client_mask())).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

/// The admission predicate itself is unit-tested in
/// `platform::windows::identity`; a low-box token cannot get past the DACL
/// and label to reach it.
#[tokio::test]
#[ignore = "Windows administrator CI runner: low-box token copy"]
async fn app_container_copy_is_refused_at_open() {
    let (f, _listener) = bind();
    let boxed = app_container_token();
    let error = impersonating(&boxed, || open(endpoint_arg(&f.ep), client_mask())).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[tokio::test]
#[ignore = "Windows administrator CI runner with ETD_IPC_CI_ACCOUNTS=1: temporary second account"]
async fn second_account_is_refused_at_open() {
    assert_eq!(
        std::env::var_os("ETD_IPC_CI_ACCOUNTS").as_deref(),
        Some(std::ffi::OsStr::new("1")),
        "set ETD_IPC_CI_ACCOUNTS=1 (CI only) to create a temporary standard user"
    );
    let (f, _listener) = bind();
    let (token, _second) = windows_account::logon();
    let error = impersonating(&token, || open(endpoint_arg(&f.ep), client_mask())).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}
