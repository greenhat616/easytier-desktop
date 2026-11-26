//! A [`ScriptedHost`] on a real local listener, and `etd-ctl` run against it.
//!
//! `etd-ctl` verifies the host process, so the serving process must be an
//! executable named `etd-host`: each test runs itself again from such a copy.
use assert_cmd::Command;
use etd_ipc::{Endpoint, HostForm, ListenerPolicy, platform::LocalListener, tonic_io::incoming};
use etd_testkit::scripted_server::ScriptedHost;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tonic::transport::Server;

pub const CTL: &str = env!("CARGO_BIN_EXE_etd-ctl");
/// No output of any command may contain it.
pub const SECRET: &str = "hunter2-network-secret";

fn host_name() -> String {
    format!("etd-host{}", std::env::consts::EXE_SUFFIX)
}

/// True inside the `etd-host` copy. Otherwise runs `test` there and checks
/// that it passed.
pub fn run_as_host(test: &str) -> bool {
    let exe = std::env::current_exe().unwrap();
    if exe.file_name().unwrap() == host_name().as_str() {
        return true;
    }
    let install = tempfile::tempdir().unwrap();
    let host = install.path().join(host_name());
    std::fs::copy(exe, &host).unwrap();
    let mut command = std::process::Command::new(host);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(install.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        command
            .env("ETD_TEST_RUNTIME", install.path())
            .env("XDG_RUNTIME_DIR", install.path());
    }
    let result = command
        .args(["--exact", test, "--nocapture"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&result.stderr)
    );
    false
}

/// A private directory and an endpoint inside it that nothing serves yet.
pub fn free_endpoint() -> (TempDir, Endpoint) {
    #[cfg(target_os = "linux")]
    let dir = match std::env::var_os("ETD_TEST_RUNTIME") {
        Some(root) => tempfile::tempdir_in(root).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    #[cfg(not(target_os = "linux"))]
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let endpoint = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Endpoint::UnixSocket(dir.path().canonicalize().unwrap().join("host.sock"))
    };
    #[cfg(windows)]
    let endpoint = Endpoint::NamedPipe(format!(
        r"\\.\pipe\etd-ctl-test-{}-{}",
        std::process::id(),
        dir.path().file_name().unwrap().to_string_lossy()
    ));
    (dir, endpoint)
}

pub fn endpoint_arg(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::NamedPipe(name) => name.clone(),
        Endpoint::UnixSocket(path) => path.to_str().unwrap().to_owned(),
        other => panic!("unexpected endpoint {other:?}"),
    }
}

pub fn own_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().into()
}

pub struct Host {
    pub script: ScriptedHost,
    pub endpoint: String,
    pub dir: TempDir,
}

/// Must be called on a multi-thread runtime: running `etd-ctl` blocks the
/// calling thread while the workers serve it.
pub fn serve() -> Host {
    let script = ScriptedHost::start();
    let (dir, endpoint) = free_endpoint();
    let listener =
        LocalListener::bind(HostForm::User, &endpoint, &ListenerPolicy::default()).unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(script.service())
            .serve_with_incoming(incoming(listener)),
    );
    Host {
        script,
        endpoint: endpoint_arg(&endpoint),
        dir,
    }
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("{error}: {:?} / {}", self.stdout, self.stderr))
    }

    /// The `error` object of a `--json` failure.
    pub fn error(&self) -> Value {
        let body: Value = serde_json::from_str(&self.stderr)
            .unwrap_or_else(|error| panic!("{error}: {:?}", self.stderr));
        body["error"].clone()
    }

    #[track_caller]
    pub fn expect(self, code: i32) -> Self {
        assert_eq!(
            self.code, code,
            "stdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        self
    }
}

/// Runs `etd-ctl` with exactly `args`, feeding it `stdin`.
pub fn ctl(args: &[&str], stdin: &str) -> Run {
    let output = Command::new(CTL)
        .args(args)
        .env_remove("RUST_LOG")
        .write_stdin(stdin)
        .timeout(std::time::Duration::from_secs(60))
        .output()
        .unwrap();
    let run = Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    };
    assert!(!run.stdout.contains(SECRET), "{}", run.stdout);
    assert!(!run.stderr.contains(SECRET), "{}", run.stderr);
    run
}

impl Host {
    /// The flags that point `etd-ctl` at this host.
    pub fn flags(&self) -> Vec<String> {
        let dir = own_dir();
        [
            "--host",
            "user",
            "--endpoint",
            &self.endpoint,
            "--host-dir",
            dir.to_str().unwrap(),
        ]
        .map(str::to_owned)
        .to_vec()
    }

    pub fn run_with(&self, args: &[&str], stdin: &str) -> Run {
        let flags = self.flags();
        let mut all: Vec<&str> = flags.iter().map(String::as_str).collect();
        all.extend_from_slice(args);
        ctl(&all, stdin)
    }

    pub fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, "")
    }

    pub fn file(&self, name: &str, content: &str) -> String {
        let path: &Path = self.dir.path();
        let path = path.join(name);
        std::fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_owned()
    }
}

/// Defines a test that runs inside the `etd-host` copy with a served host.
macro_rules! host_test {
    ($name:ident, |$host:ident| $body:block) => {
        #[test]
        fn $name() {
            if !crate::common::run_as_host(stringify!($name)) {
                return;
            }
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let $host = crate::common::serve();
                $body
            });
        }
    };
}
pub(crate) use host_test;
