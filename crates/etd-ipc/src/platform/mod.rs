//! Local authenticated transports. Hold a policy handle in the host composition
//! root before handing the listener to `tonic_io::incoming`.
use crate::{
    BoxConn, Connector, Endpoint, HostForm, ListenerPolicy, OsUserId, ServerExpectation,
    ServerIdentity, ServerRequirement,
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
#[cfg(unix)]
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

/// The account proof a [`ServerRequirement`] asks for.
#[derive(Clone, Copy)]
pub(super) struct Proof<'a> {
    /// The service-host proof (SYSTEM / root, endpoint owner) rather than
    /// the user-host proof.
    pub privileged: bool,
    /// The expected account; `None` means SYSTEM / root when `privileged`,
    /// else the current user.
    pub user: Option<&'a OsUserId>,
    /// The current user's elevated session host (Windows): the server
    /// token must be readable, be the current user's and be elevated.
    #[cfg_attr(unix, expect(dead_code, reason = "Unix never sets it"))]
    pub elevated: bool,
}

/// Call before opening the endpoint. The elevated session host exists only
/// on Windows; elsewhere that requirement fails with `Unsupported`.
pub(super) fn proof(expect: &ServerExpectation) -> io::Result<Proof<'_>> {
    let (privileged, user, elevated) = match &expect.requirement {
        ServerRequirement::Service => (true, None, false),
        ServerRequirement::ServiceAccount(user) => (true, Some(user), false),
        ServerRequirement::CurrentUser => (false, None, false),
        ServerRequirement::UserAccount(user) => (false, Some(user), false),
        #[cfg(windows)]
        ServerRequirement::CurrentUserElevated => (false, None, true),
        #[cfg(unix)]
        ServerRequirement::CurrentUserElevated => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the elevated session host is Windows-only",
            ));
        }
    };
    Ok(Proof {
        privileged,
        user,
        elevated,
    })
}

fn verify_user(
    proof: Proof<'_>,
    actual: &OsUserId,
    current: OsUserId,
    service: OsUserId,
) -> io::Result<()> {
    let default = if proof.privileged { &service } else { &current };
    if actual != proof.user.unwrap_or(default) || (proof.privileged && actual != &service) {
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

// Windows implements both; the session tests in `tests/session_*.rs` cover it.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn unused_endpoint() -> Endpoint {
        let leaf = format!("etd-ipc-no-elevated-{}", std::process::id());
        Endpoint::UnixSocket(std::env::temp_dir().join(leaf).join("host.sock"))
    }

    #[tokio::test]
    async fn an_elevated_session_requirement_is_unsupported() {
        let connector = LocalConnector {
            expectation: ServerExpectation {
                exe_dir: PathBuf::new(),
                requirement: ServerRequirement::CurrentUserElevated,
            },
        };
        let error = connector.connect(&unused_endpoint()).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn an_elevated_session_listener_is_unsupported() {
        let error = LocalListener::bind(
            HostForm::ElevatedSession,
            &unused_endpoint(),
            &ListenerPolicy::default(),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
