//! Each case uses the installed product service on a fresh hosted runner.
use etd_testkit::no_window::NoWindow;
use std::{path::Path, process::Command};
mod desktop;
mod takeover_management;
#[cfg(target_os = "macos")]
mod takeover_utun;

fn require_runner() {
    for (key, expected) in [
        ("ETD_G2_CI", "1"),
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
    ] {
        assert_eq!(std::env::var(key).as_deref(), Ok(expected), "{key}");
    }
    let directory = |key| std::fs::canonicalize(std::env::var_os(key).expect(key)).expect(key);
    let temp = directory("RUNNER_TEMP");
    let workspace = directory("GITHUB_WORKSPACE");
    assert_eq!(temp.file_name(), Some(std::ffi::OsStr::new("_temp")));
    assert!(workspace.starts_with(temp.parent().expect("runner work directory")));
}

fn run_case(case: &str) {
    run_script("product.py", case);
}

fn run_script(script: &str, case: &str) {
    require_runner();
    let mut command = Command::new(std::env::var_os("ETD_G2_PYTHON").expect("CI Python"));
    command
        .no_window()
        .env("ETD_G2_TEST_IMAGE", std::env::current_exe().unwrap());
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/tier3")
        .join(script);
    let status = command.args(["-B", "-u"]).arg(script).arg(case).status();
    assert!(status.expect("launch tier 3 case").success(), "{case}");
}

#[test]
#[ignore = "installs the privileged service on a disposable hosted runner"]
fn installed_kernel_and_host_crash_recovery() {
    run_case("recovery");
}

#[test]
#[ignore = "plants native fixtures only on a disposable hosted runner"]
fn independent_inventory_detects_native_foreign_objects() {
    run_case("inventory");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "uses the installed service and native /etc/resolver on hosted macOS"]
fn installed_host_refuses_magic_dns_and_preserves_resolvers() {
    run_case("magic_dns");
}

#[cfg(windows)]
#[test]
#[ignore = "requires fresh, disposable Windows SCM registrations"]
fn preexisting_shared_drivers_are_conflicts() {
    run_case("driver_conflict");
}

#[cfg(windows)]
#[test]
#[ignore = "holds disabled foreign SCM drivers from before install through completed uninstall"]
fn preexisting_shared_drivers_survive_uninstall() {
    run_case("driver_uninstall");
}

#[cfg(windows)]
#[test]
#[ignore = "requires a fresh Windows runner for the full pre-install to post-uninstall comparison"]
fn installed_network_uninstall_restores_machine() {
    run_case("clean_install");
}

#[cfg(windows)]
#[test]
#[ignore = "requires a disposable Windows runner with an independent program firewall rule"]
fn preexisting_program_rule_blocks_start() {
    run_case("program_rule_conflict");
}

#[cfg(windows)]
#[test]
#[ignore = "installs the privileged service on a disposable hosted runner"]
fn service_stop_with_a_running_network_is_bounded() {
    run_case("stop_running");
}

#[cfg(windows)]
#[test]
#[ignore = "runs the elevated session host with a real kernel on a disposable hosted runner"]
fn session_host_crash_recovery_and_purge() {
    run_script("session.py", "session_recovery");
}

#[cfg(windows)]
#[test]
#[ignore = "runs the elevated session host, then installs the service, on a disposable hosted runner"]
fn session_and_service_exclude_each_other() {
    run_script("session.py", "session_exclusion");
}

#[test]
#[ignore = "installs and upgrades the privileged service on a disposable hosted runner"]
fn installed_network_survives_upgrade() {
    run_case("upgrade_running");
}

#[cfg(windows)]
#[test]
#[ignore = "installs, upgrades and removes the Windows MSI on a disposable hosted runner"]
fn msi_installs_upgrades_rolls_back_and_uninstalls() {
    run_script("package.py", "msi_lifecycle");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "installs, upgrades and purges the Debian package on a disposable hosted runner"]
fn deb_installs_upgrades_rolls_back_and_purges() {
    run_script("deb.py", "deb_lifecycle");
}
