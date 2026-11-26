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
    etd_host()
        .args(["run", "--mode", "elevated-session"])
        .assert()
        .failure();
}
