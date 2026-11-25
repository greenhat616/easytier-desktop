#![allow(dead_code)]
use etd_ipc::{
    Endpoint, ListenerPolicy, ServerExpectation,
    platform::{LocalConnector, LocalListener},
};
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
        let dir = tempfile::tempdir().unwrap();
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
        LocalListener::bind(&self.ep, &ListenerPolicy::default()).unwrap()
    }
}
pub fn connector() -> LocalConnector {
    LocalConnector {
        expectation: ServerExpectation {
            exe_dir: std::env::current_exe().unwrap().parent().unwrap().into(),
            user: None,
            privileged: false,
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
    let result = Command::new(host)
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
