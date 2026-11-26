//! Each case uses the installed product service on a fresh hosted runner.
use std::{path::Path, process::Command};
mod desktop;

fn run_case(case: &str) {
    for (key, expected) in [
        ("ETD_G2_CI", "1"),
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
    ] {
        assert_eq!(std::env::var(key).as_deref(), Ok(expected), "{key}");
    }
    let mut command = Command::new(std::env::var_os("ETD_G2_PYTHON").expect("CI Python"));
    command.env("ETD_G2_TEST_IMAGE", std::env::current_exe().unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tier3/product.py");
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
#[ignore = "requires a fresh Windows runner for the full pre-install to post-uninstall comparison"]
fn installed_network_uninstall_restores_machine() {
    run_case("clean_install");
}

#[cfg(windows)]
#[test]
#[ignore = "pending topic 40: H1 must reject a foreign same-name program firewall rule before spawn"]
fn preexisting_program_rule_blocks_start() {
    run_case("program_rule_conflict");
}
