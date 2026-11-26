//! A test-owned process reopens a utun the installed service released, and
//! takes the running generation's utun the moment its kernel dies (doc#7).

#[test]
#[ignore = "installs the privileged service and holds utun devices on disposable hosted macOS"]
fn reclaim_and_next_generations_leave_a_reused_utun_alone() {
    super::run_script("takeover.py", "utun_reuse");
}
