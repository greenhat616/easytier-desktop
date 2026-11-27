//! ES4 privileged acceptance (doc#13 #choose, "UI already elevated"): the
//! real starter starts `etd-host run --mode elevated-session` directly (no
//! inherited handles, minimal environment, no window), the real connector
//! verifies it as the current user's elevated host, and the host, holding no
//! UI lease, winds down on its own. Elevated Windows CI runner only (its
//! token is already elevated, so this is the one real-process path CI can
//! run; the UAC prompt itself is the human smoke test).
#![cfg(windows)]

use etd_app::launcher_session::{
    ElevatedSessionConfig, ElevationStarter, SESSION_HOST_ARGS, UiElevation, start_elevated,
};
use etd_ipc::{Connector, platform::LocalConnector};
use etd_ui::composition::WindowsElevationStarter;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

/// `target\<profile>\etd-host.exe`, built before this test.
fn host_program() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().and_then(|deps| deps.parent()).unwrap();
    let program = profile_dir.join("etd-host.exe");
    assert!(
        program.is_file(),
        "build etd-host first: {}",
        program.display()
    );
    program
}

#[test]
#[ignore = "elevated Windows CI runner only"]
fn an_elevated_ui_starts_the_session_host_directly_and_connects() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let starter = WindowsElevationStarter;
    assert_eq!(starter.elevation().unwrap(), UiElevation::Elevated);
    let config = ElevatedSessionConfig::standard(host_program()).unwrap();
    let mut host = start_elevated(&starter, &config.program, &SESSION_HOST_ARGS).unwrap();
    let connector = LocalConnector {
        expectation: config.expectation.clone(),
    };

    let deadline = Instant::now() + Duration::from_secs(90);
    let identity = loop {
        if let Ok((_, identity)) = runtime.block_on(connector.connect(&config.endpoint)) {
            break identity;
        }
        assert_eq!(
            host.exit_code().unwrap(),
            None,
            "the session host exited during start-up"
        );
        assert!(Instant::now() < deadline, "the session host never answered");
        std::thread::sleep(Duration::from_millis(250));
    };
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
