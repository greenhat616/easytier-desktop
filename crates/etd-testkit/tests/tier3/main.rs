//! Each case uses the installed product service on a fresh hosted runner.
use std::{path::Path, process::Command};

fn run_case(case: &str) {
    for (key, expected) in [
        ("ETD_G2_CI", "1"),
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
    ] {
        assert_eq!(std::env::var(key).as_deref(), Ok(expected), "{key}");
    }
    let mut command = Command::new(std::env::var_os("ETD_G2_PYTHON").expect("CI Python"));
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

#[cfg(target_os = "macos")]
#[test]
#[ignore = "uses the installed service and native /etc/resolver on hosted macOS"]
fn installed_host_refuses_magic_dns_and_preserves_resolvers() {
    run_case("magic_dns");
}
