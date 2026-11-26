#![allow(dead_code)]
use etd_ipc::{
    Endpoint, ListenerPolicy, ServerExpectation, ServerRequirement,
    platform::{LocalConnector, LocalListener},
};
use etd_testkit::no_window::NoWindow;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

pub struct Fixture {
    pub dir: TempDir,
    pub ep: Endpoint,
}
impl Fixture {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        let dir = match std::env::var_os("ETD_TEST_RUNTIME") {
            Some(root) => tempfile::tempdir_in(root).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        #[cfg(not(target_os = "linux"))]
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(unix)]
        let ep = Endpoint::UnixSocket(dir.path().canonicalize().unwrap().join("host.sock"));
        #[cfg(windows)]
        let ep = Endpoint::NamedPipe(format!(
            r"\\.\pipe\etd-{}-{}",
            std::process::id(),
            dir.path().file_name().unwrap().to_string_lossy()
        ));
        Self { dir, ep }
    }
    pub fn listener(&self) -> LocalListener {
        LocalListener::bind(
            etd_ipc::HostForm::User,
            &self.ep,
            &ListenerPolicy::default(),
        )
        .unwrap()
    }
}
pub fn connector() -> LocalConnector {
    LocalConnector {
        expectation: ServerExpectation {
            exe_dir: std::env::current_exe().unwrap().parent().unwrap().into(),
            requirement: ServerRequirement::CurrentUser,
        },
    }
}

pub fn host_name() -> String {
    format!("etd-host{}", std::env::consts::EXE_SUFFIX)
}

// Run the same test in a copy bearing the installed host filename, so
// acceptance tests go through the full production image verifier.
pub fn run_as_host(test: &str) -> bool {
    let exe = std::env::current_exe().unwrap();
    if exe.file_name().unwrap() == host_name().as_str() {
        return true;
    }
    let install = tempfile::tempdir().unwrap();
    let host = install.path().join(host_name());
    std::fs::copy(exe, &host).unwrap();
    let mut cmd = Command::new(host);
    cmd.no_window();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(install.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        cmd.env("ETD_TEST_RUNTIME", install.path())
            .env("XDG_RUNTIME_DIR", install.path());
    }
    let result = cmd
        .args(["--include-ignored", "--exact", test, "--nocapture"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    false
}

pub fn endpoint_arg(ep: &Endpoint) -> &Path {
    match ep {
        Endpoint::UnixSocket(p) => p,
        Endpoint::NamedPipe(p) => Path::new(p),
        _ => unreachable!(),
    }
}
pub fn from_arg(arg: PathBuf) -> Endpoint {
    #[cfg(windows)]
    {
        Endpoint::NamedPipe(arg.to_str().unwrap().to_owned())
    }
    #[cfg(unix)]
    {
        Endpoint::UnixSocket(arg)
    }
}

/// Pre-6.5 Linux authenticates a user host by its private directory and uid.
/// Probe the actual running kernel rather than its release string.
pub fn verifies_user_image() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut fd = -1i32;
        let mut len = size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                a.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&raw mut fd).cast(),
                &mut len,
            )
        } != 0
        {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOPROTOOPT)
            );
            return false;
        }
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    true
}
