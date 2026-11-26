use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

#[test]
fn help_and_doctor_are_unprivileged() {
    cargo_bin_cmd!("etd-host")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("reclaim"));
    cargo_bin_cmd!("etd-host")
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("EasyTier Desktop host"));
}

#[test]
fn rejects_unknown_command_and_partial_purge() {
    cargo_bin_cmd!("etd-host")
        .arg("unknown-command")
        .assert()
        .failure();
    cargo_bin_cmd!("etd-host")
        .args(["reclaim", "--purge"])
        .assert()
        .failure();
    cargo_bin_cmd!("etd-host")
        .args(["run", "--mode", "elevated-session"])
        .assert()
        .failure();
}
