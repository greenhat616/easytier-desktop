//! Where each host form listens and what its server process must prove.
use crate::{cli::HostKind, error::CtlError};
use etd_ipc::{Endpoint, ServerExpectation};
use std::path::PathBuf;

pub fn endpoint(host: HostKind, custom: Option<String>) -> Result<Endpoint, CtlError> {
    if let Some(value) = custom {
        return Ok(local_endpoint(value));
    }
    match host {
        HostKind::Service => Ok(local_endpoint(service_endpoint().to_owned())),
        HostKind::User => user_endpoint(),
    }
}

#[cfg(windows)]
fn local_endpoint(value: String) -> Endpoint {
    Endpoint::NamedPipe(value)
}
#[cfg(unix)]
fn local_endpoint(value: String) -> Endpoint {
    Endpoint::UnixSocket(value.into())
}

#[cfg(windows)]
fn service_endpoint() -> &'static str {
    etd_ipc::SERVICE_PIPE_NAME
}
#[cfg(unix)]
fn service_endpoint() -> &'static str {
    etd_ipc::SERVICE_SOCKET_PATH
}

#[cfg(target_os = "linux")]
fn user_endpoint() -> Result<Endpoint, CtlError> {
    Ok(Endpoint::UnixSocket(
        etd_ipc::platform::user_runtime_dir().join("host.sock"),
    ))
}

#[cfg(not(target_os = "linux"))]
fn user_endpoint() -> Result<Endpoint, CtlError> {
    use etd_ipc::OsUserId;
    let user = etd_ipc::platform::current_user().map_err(|error| {
        CtlError::internal(format!("cannot identify the current user: {error}"))
    })?;
    match user {
        #[cfg(windows)]
        OsUserId::WindowsSid(sid) => Ok(Endpoint::NamedPipe(format!(
            r"\\.\pipe\easytier-desk-user-{sid}"
        ))),
        #[cfg(target_os = "macos")]
        OsUserId::UnixUid(uid) => Ok(Endpoint::UnixSocket(
            format!("/private/tmp/easytier-desk-{uid}/host.sock").into(),
        )),
        _ => Err(CtlError::internal("unexpected kind of user id".to_owned())),
    }
}

pub fn expectation(host: HostKind, dir: Option<PathBuf>) -> Result<ServerExpectation, CtlError> {
    let exe_dir = match (dir, host) {
        (Some(dir), _) => dir,
        (None, HostKind::Service) => service_install_dir()?,
        (None, HostKind::User) => own_dir()?,
    };
    Ok(ServerExpectation {
        exe_dir,
        user: None,
        privileged: host == HostKind::Service,
    })
}

fn own_dir() -> Result<PathBuf, CtlError> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
        .ok_or_else(|| CtlError::internal("cannot locate etd-ctl's own directory".to_owned()))
}

// These mirror the layout the host installer uses.
#[cfg(windows)]
fn service_install_dir() -> Result<PathBuf, CtlError> {
    // A forged variable cannot widen trust: the service form also requires
    // the pipe to be owned by SYSTEM.
    std::env::var_os("ProgramFiles")
        .map(|root| PathBuf::from(root).join("EasyTierDesk"))
        .ok_or_else(|| CtlError::internal("ProgramFiles is not set; pass --host-dir".to_owned()))
}
#[cfg(target_os = "linux")]
fn service_install_dir() -> Result<PathBuf, CtlError> {
    Ok("/usr/local/lib/easytier-desk".into())
}
#[cfg(target_os = "macos")]
fn service_install_dir() -> Result<PathBuf, CtlError> {
    Ok("/Library/Application Support/easytier-desk".into())
}
