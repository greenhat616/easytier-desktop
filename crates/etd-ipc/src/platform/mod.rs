//! Local authenticated transports. Hold a policy handle in the host composition
//! root before handing the listener to `tonic_io::incoming`.
use crate::{
    BoxConn, Connector, Endpoint, ListenerPolicy, OsUserId, ServerExpectation, ServerIdentity,
};
use std::{
    io,
    path::{Path, PathBuf},
};

#[cfg(windows)]
#[path = "windows/mod.rs"]
mod native;
#[cfg(unix)]
#[path = "unix/mod.rs"]
mod native;
#[cfg(target_os = "linux")]
pub use native::user_runtime_dir;
pub use native::{LocalListener, PolicyHandle};

/// Account of the process running the user host or client.
pub fn current_user() -> io::Result<OsUserId> {
    native::current_user()
}

pub struct LocalConnector {
    pub expectation: ServerExpectation,
}

pub(super) fn denied(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_string())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl LocalListener {
    /// Publish an endpoint with its initial kernel access policy. An existing
    /// endpoint (including a stale Unix socket) is never claimed or unlinked.
    pub fn bind(endpoint: &Endpoint, policy: &ListenerPolicy) -> io::Result<Self> {
        Self::bind_native(endpoint, policy)
    }
}

#[async_trait::async_trait]
impl Connector for LocalConnector {
    async fn connect(&self, endpoint: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)> {
        native::connect(endpoint, &self.expectation).await
    }
}

fn verify_user(
    expect: &ServerExpectation,
    actual: &OsUserId,
    current: OsUserId,
    service: OsUserId,
) -> io::Result<()> {
    let default = if expect.privileged {
        &service
    } else {
        &current
    };
    if actual != expect.user.as_ref().unwrap_or(default)
        || (expect.privileged && actual != &service)
    {
        return Err(denied("unexpected host account"));
    }
    Ok(())
}

fn verify_image(directory: &Path, image: &Path) -> io::Result<PathBuf> {
    let directory = directory.canonicalize().map_err(denied)?;
    let host = directory.join(format!("etd-host{}", std::env::consts::EXE_SUFFIX));
    // Compare the kernel's image name directly. Resolving a peer-controlled
    // path could follow a symlink installed after the process was inspected.
    #[cfg(windows)]
    let matches = native::image_matches(image, &host)?;
    #[cfg(unix)]
    let matches = image == host;
    if !matches || !host.is_file() || host.canonicalize().map_err(denied)? != host {
        return Err(denied(format!(
            "unexpected host executable {} (expected {})",
            image.display(),
            host.display()
        )));
    }
    Ok(host)
}
