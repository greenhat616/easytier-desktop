//! Local authenticated transports. Hold a policy handle in the host composition
//! root before handing the listener to `tonic_io::incoming`.
use crate::{
    BoxConn, Connector, Endpoint, HostForm, ListenerPolicy, OsUserId, ServerExpectation,
    ServerIdentity,
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

/// Implement on the guard returned by HR's exclusive machine (service) or
/// session (user host) lock. All publishers of its endpoint must participate
/// in that lock. Hold it until after the listener is dropped.
pub trait HeldHostLock {
    fn form(&self) -> HostForm;
    fn endpoint(&self) -> &Endpoint;

    fn listener_claim(&self) -> ListenerClaim<'_>
    where
        Self: Sized,
    {
        ListenerClaim(self)
    }
}

/// A borrow of the acquired lock which authorizes recovery of its endpoint.
#[must_use]
pub struct ListenerClaim<'a>(&'a dyn HeldHostLock);

impl LocalListener {
    /// Recover an abandoned endpoint under the host's exclusive lock. Only
    /// a refused, owned Unix socket can be removed. Windows reclaims pipe
    /// names in the kernel and uses its normal first-instance bind.
    pub fn bind_replacing_stale(
        claim: ListenerClaim<'_>,
        policy: &ListenerPolicy,
    ) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Self::bind_locked(claim.0.form(), claim.0.endpoint(), policy)
        }
        #[cfg(windows)]
        {
            Self::bind(claim.0.form(), claim.0.endpoint(), policy)
        }
    }
    /// Publish an endpoint with its initial kernel access policy. An existing
    /// endpoint (including a stale Unix socket) is never claimed or unlinked.
    pub fn bind(form: HostForm, endpoint: &Endpoint, policy: &ListenerPolicy) -> io::Result<Self> {
        Self::bind_native(form, endpoint, policy)
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
