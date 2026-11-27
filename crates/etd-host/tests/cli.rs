use etd_testkit::no_window::NoWindow;
use predicates::prelude::*;

fn etd_host() -> assert_cmd::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_etd-host"));
    command.no_window();
    assert_cmd::Command::from_std(command)
}

#[test]
fn help_and_doctor_are_unprivileged() {
    etd_host()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("reclaim"));
    etd_host()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("EasyTier Desktop host"));
}

#[test]
fn rejects_unknown_command_and_partial_purge() {
    etd_host().arg("unknown-command").assert().failure();
    etd_host().args(["reclaim", "--purge"]).assert().failure();
}

/// The mode parses everywhere; no command takes a directory, path or state
/// option for it. Never actually starts a host (CI runners are elevated).
#[test]
fn elevated_session_mode_parses_without_path_options() {
    for args in [
        &["run", "--mode", "elevated-session", "--state", "x"][..],
        &["run", "--mode", "elevated-session", "--dir", "x"],
        &["run", "--mode", "elevated-session", "--path", "x"],
        &["run", "--mode", "elevated-session", "x"],
        &["reclaim", "--mode", "elevated-session", "--state", "x"],
    ] {
        etd_host()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid value").not())
            .stderr(predicate::str::contains("unexpected argument"));
    }
    etd_host()
        .args(["run", "--mode", "elevated-sessions"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
    // --all-users belongs to the elevated session mode only.
    etd_host()
        .args(["reclaim", "--mode", "user", "--all-users"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--all-users applies only"));
}

#[cfg(unix)]
#[test]
fn elevated_session_mode_is_windows_only() {
    for args in [
        &["run", "--mode", "elevated-session"][..],
        &["reclaim", "--mode", "elevated-session"],
        &["reclaim", "--mode", "elevated-session", "--all-users"],
    ] {
        etd_host()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Windows-only"));
    }
}
