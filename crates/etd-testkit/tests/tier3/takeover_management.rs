//! A test-owned process takes the kernel's loopback management port of the
//! installed service: the crashed generation's port before the restart, and
//! the next generation's port between plan and kernel bind (doc#7).

#[test]
#[ignore = "installs the privileged service and takes its management port on a disposable hosted runner"]
fn installed_host_never_talks_to_a_management_port_impostor() {
    super::run_script("takeover.py", "management_port");
}
