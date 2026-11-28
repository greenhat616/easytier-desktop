//! ES4 privileged acceptance (doc#13 #choose, "UI already elevated"): the
//! real starter starts `etd-host run --mode elevated-session` directly (no
//! inherited handles, minimal environment, no window), the real connector
//! verifies it as the current user's elevated host, and the host, holding no
//! UI lease, winds down on its own. Elevated Windows CI runner only (its
//! token is already elevated, so this is the one real-process path CI can
//! run; the UAC prompt itself is the human smoke test). Also the clean-up
//! after a killed host, through `runas` (shown no prompt on that token) and
//! directly.
#![cfg(windows)]

use etd_app::launcher_session::{
    ElevatedSessionConfig, ElevationStarter, RECLAIM_ARGS, SESSION_HOST_ARGS, StartError,
    StartedProcess, UiElevation, reclaim_session_leftovers, start_elevated,
};
use etd_ipc::{Connector, platform::LocalConnector};
use etd_ui::composition::WindowsElevationStarter;
use std::{
    io,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

/// Every console child sets it (no console window flashes).
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `target\<profile>\etd-host.exe`, built before this test. Test binaries
/// sit somewhere below the profile directory (`deps\`, or `build\<crate>\…`
/// with the newer build-dir layout), so look in each ancestor.
fn host_program() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.ancestors()
        .skip(1)
        .map(|dir| dir.join("etd-host.exe"))
        .find(|program| program.is_file())
        .unwrap_or_else(|| panic!("build etd-host first (looked above {})", exe.display()))
}

/// Waits until the session host answers as the current user's elevated
/// host; fails if it exits first.
fn connect(
    config: &ElevatedSessionConfig,
    host: &mut dyn StartedProcess,
) -> etd_ipc::ServerIdentity {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let connector = LocalConnector {
        expectation: config.expectation.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok((_, identity)) = runtime.block_on(connector.connect(&config.endpoint)) {
            return identity;
        }
        assert_eq!(
            host.exit_code().unwrap(),
            None,
            "the session host exited during start-up"
        );
        assert!(Instant::now() < deadline, "the session host never answered");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The UI's path on an unelevated administrator (the smoke test's): every
/// start through `ShellExecuteEx runas`. The runner's token is already
/// elevated, so no prompt is shown.
struct ThroughConsent;

impl ElevationStarter for ThroughConsent {
    fn elevation(&self) -> io::Result<UiElevation> {
        Ok(UiElevation::Limited)
    }

    fn start_with_consent(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<Box<dyn StartedProcess>, StartError> {
        WindowsElevationStarter.start_with_consent(program, args)
    }

    fn start_direct(&self, _: &Path, _: &[&str]) -> Result<Box<dyn StartedProcess>, StartError> {
        Err(StartError::Failed(io::Error::other(
            "an unelevated UI never starts directly",
        )))
    }
}

fn system32(program: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .join(program)
}

/// Runs a System32 tool, without a window, and requires it to succeed.
fn system_tool(program: &str, args: &[&str]) {
    let output = Command::new(system32(program))
        .creation_flags(CREATE_NO_WINDOW)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{program} {args:?}: {output:?}");
}

/// `HKLM\SOFTWARE\EasyTier\MagicDNS`: upstream EasyTier's key.
const MAGIC_DNS: &str = r"HKLM\SOFTWARE\EasyTier\MagicDNS";

/// What other software leaves on a real machine and no ledger of ours
/// records (the smoke test's machine, msg#2290): a `wintun` driver service
/// (shared with upstream EasyTier and other VPNs; registered here, never
/// started, its image absent) and upstream EasyTier's MagicDNS key. Removed
/// again on drop.
struct ForeignObjects;

impl ForeignObjects {
    fn plant() -> Self {
        let image = system32(r"drivers\etd-ci-absent-wintun.sys");
        system_tool(
            "sc.exe",
            &[
                "create",
                "wintun",
                "type=",
                "kernel",
                "start=",
                "demand",
                "binPath=",
                image.to_str().unwrap(),
            ],
        );
        system_tool("reg.exe", &["add", MAGIC_DNS, "/f"]);
        Self
    }
}

impl Drop for ForeignObjects {
    fn drop(&mut self) {
        for (program, args) in [
            ("sc.exe", &["delete", "wintun"][..]),
            ("reg.exe", &["delete", MAGIC_DNS, "/f"][..]),
        ] {
            let _ = Command::new(system32(program))
                .creation_flags(CREATE_NO_WINDOW)
                .args(args)
                .output();
        }
    }
}

/// `etd-host reclaim --mode elevated-session`, its output captured (the
/// UI's hidden start cannot capture it).
fn reclaim_captured(program: &Path) -> std::process::Output {
    Command::new(program)
        .creation_flags(CREATE_NO_WINDOW)
        .args(RECLAIM_ARGS)
        .output()
        .unwrap()
}

fn describe(output: &std::process::Output) -> String {
    format!(
        "{}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

/// The smoke test's steps 3 and 4 (msg#2290) on a machine with other
/// software's EasyTier-looking objects: the session host is killed (Task
/// Manager's End task), then the UI's Clean Up runs
/// `etd-host reclaim --mode elevated-session` the same way, through runas
/// and, from an elevated UI, directly. The foreign objects are not this
/// ledger's: they are listed, left in place, and do not fail the clean-up.
/// A failure carries the reclaim's own output.
#[test]
#[ignore = "elevated Windows CI runner only"]
fn a_killed_session_host_is_cleaned_up_like_the_ui_does() {
    let config = ElevatedSessionConfig::standard(host_program()).unwrap();
    let _foreign = ForeignObjects::plant();
    let starters: [(&str, &dyn ElevationStarter); 2] = [
        ("runas", &ThroughConsent),
        ("direct", &WindowsElevationStarter),
    ];
    for (how, starter) in starters {
        let mut host = start_elevated(starter, &config.program, &SESSION_HOST_ARGS)
            .unwrap_or_else(|error| panic!("{how}: start: {error}"));
        let pid = connect(&config, host.as_mut()).peer.pid;
        let killed = Command::new(system32("taskkill.exe"))
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/F", "/PID", &pid.to_string()])
            .output()
            .unwrap();
        assert!(killed.status.success(), "{how}: taskkill: {killed:?}");
        let deadline = Instant::now() + Duration::from_secs(30);
        while host.exit_code().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "{how}: the host survived the kill"
            );
            std::thread::sleep(Duration::from_millis(200));
        }

        if let Err(error) =
            reclaim_session_leftovers(starter, &config.program, false, Duration::from_secs(120))
        {
            panic!(
                "{how}: Clean Up after a killed host failed: {error:?}\n\
                 the same reclaim run again from the test: {}",
                describe(&reclaim_captured(&config.program)),
            );
        }
        eprintln!("{how}: Clean Up after a killed host succeeded");
    }

    // The CLI lists what it left in place.
    let listed = reclaim_captured(&config.program);
    let stdout = String::from_utf8_lossy(&listed.stdout).to_ascii_lowercase();
    assert!(listed.status.success(), "{}", describe(&listed));
    for name in ["wintun", r"easytier\magicdns"] {
        assert!(
            stdout.contains("not proven ours") && stdout.contains(name),
            "{name} not listed: {}",
            describe(&listed)
        );
    }
}

#[test]
#[ignore = "elevated Windows CI runner only"]
fn an_elevated_ui_starts_the_session_host_directly_and_connects() {
    let starter = WindowsElevationStarter;
    assert_eq!(starter.elevation().unwrap(), UiElevation::Elevated);
    let config = ElevatedSessionConfig::standard(host_program()).unwrap();
    let mut host = start_elevated(&starter, &config.program, &SESSION_HOST_ARGS).unwrap();
    let identity = connect(&config, host.as_mut());
    assert!(identity.peer.elevated, "{identity:?}");
    assert_eq!(
        identity.exe.file_name().unwrap().to_ascii_lowercase(),
        "etd-host.exe"
    );

    // No UI lease was ever taken: the host winds down after its grace.
    let deadline = Instant::now() + Duration::from_secs(120);
    let code = loop {
        if let Some(code) = host.exit_code().unwrap() {
            break code;
        }
        assert!(
            Instant::now() < deadline,
            "the session host did not wind down"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert_eq!(code, 0, "the session host's exit code");
}
