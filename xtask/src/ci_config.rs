//! Checks on the CI configuration that X1 owns.
//!
//! Nextest has no profile setting for `--run-ignored`, so the `privileged`
//! profile selects only ignored tests because every command that uses it says
//! `--run-ignored only`. These tests keep both halves in place.

use std::fs;
use std::path::PathBuf;

fn repository(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

fn uses_privileged_profile(line: &str) -> bool {
    !line.trim_start().starts_with('#')
        && (line.contains("--profile privileged") || line.contains("--profile=privileged"))
}

/// Workflow lines that use the privileged profile without selecting ignored
/// tests only.
fn unselective_commands(workflow: &str) -> Vec<&str> {
    workflow
        .lines()
        .filter(|line| uses_privileged_profile(line) && !line.contains("--run-ignored only"))
        .collect()
}

#[test]
fn the_privileged_profile_exists() {
    let config = fs::read_to_string(repository(".config/nextest.toml")).unwrap();
    assert!(
        config
            .lines()
            .any(|line| line.trim() == "[profile.privileged]")
    );
}

#[test]
fn every_workflow_selects_only_ignored_tests_with_the_privileged_profile() {
    let mut uses = 0;
    for entry in fs::read_dir(repository(".github/workflows")).unwrap() {
        let path = entry.unwrap().path();
        let workflow = fs::read_to_string(&path).unwrap();
        uses += workflow
            .lines()
            .filter(|line| uses_privileged_profile(line))
            .count();
        assert_eq!(
            unselective_commands(&workflow),
            Vec::<&str>::new(),
            "{}",
            path.display()
        );
    }
    assert!(uses > 0, "no workflow runs the privileged tests");
}

#[test]
fn a_privileged_command_without_the_selection_is_found() {
    let workflow = "\
      # cargo nextest run --profile privileged
      run: cargo nextest run --profile privileged --run-ignored only
      run: cargo nextest run --profile privileged -p etd-host
      run: cargo nextest run --profile=privileged --run-ignored all
";
    assert_eq!(unselective_commands(workflow).len(), 2);
}
