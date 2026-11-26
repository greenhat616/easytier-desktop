//! Windows children never open a console window: every command built under
//! `crates/` sets `CREATE_NO_WINDOW`.
//!
//! This is a text check. A `Command::new(` must be followed, within a few lines
//! and before the next one, by one of [`FLAGS`]. Files that never build for
//! Windows are skipped. A single site that needs no flag where it is built
//! says why in a `// no-window: <reason>` comment on the line above: it is not
//! built on Windows, or a helper sets the flag.

use std::fs;
use std::path::{Path, PathBuf};

const SPAWN: &str = "Command::new(";
const FLAGS: [&str; 3] = [".no_window()", "creation_flags(", ".create_no_window()"];
/// `assert_cmd` constructors that leave no way to set creation flags.
const UNFLAGGABLE: [&str; 2] = ["cargo_bin_cmd!", "cargo_bin("];
const MARKER: &str = "// no-window:";
/// How many lines, counting the constructor's, may hold the flag.
const REACH: usize = 24;

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn spawns(line: &str) -> bool {
    !is_comment(line) && line.contains(SPAWN)
}

/// 1-based numbers of the lines that build a command without the flag.
fn unflagged(source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if is_comment(line) {
            continue;
        }
        if UNFLAGGABLE.iter().any(|name| line.contains(name)) {
            found.push(index + 1);
        }
        let marked = index > 0 && lines[index - 1].trim_start().starts_with(MARKER);
        if !spawns(line) || marked {
            continue;
        }
        let flagged = lines[index..]
            .iter()
            .take(REACH)
            .enumerate()
            .take_while(|(offset, next)| *offset == 0 || !spawns(next))
            .any(|(_, next)| !is_comment(next) && FLAGS.iter().any(|flag| next.contains(flag)));
        if !flagged {
            found.push(index + 1);
        }
    }
    found
}

/// Whether the whole file is left out of Windows builds, by its path or by a
/// crate-level attribute.
fn never_on_windows(path: &Path, source: &str) -> bool {
    path.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some("linux" | "macos" | "unix" | "unix.rs")
        )
    }) || source.lines().any(|line| {
        matches!(
            line.trim(),
            r"#![cfg(unix)]"
                | r#"#![cfg(target_os = "linux")]"#
                | r#"#![cfg(target_os = "macos")]"#
        )
    })
}

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn every_command_that_can_run_on_windows_opens_no_window() {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../crates");
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(!files.is_empty());
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).unwrap();
        let relative = path.strip_prefix(&crates).unwrap();
        if !never_on_windows(relative, &source) {
            for line in unflagged(&source) {
                violations.push(format!("crates/{}:{line}", relative.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "commands that may open a window on Windows; call `.no_window()` in tests \
         or set CREATE_NO_WINDOW in product code:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_check_reports_a_missing_flag() {
    assert_eq!(unflagged("let a = Command::new(x).output();"), [1]);
    assert_eq!(unflagged(r#"cargo_bin_cmd!("etd-host")"#), [1]);
    // A neighbour's flag does not count.
    assert_eq!(
        unflagged("Command::new(a);\nCommand::new(b)\n    .no_window();"),
        [1]
    );
    assert_eq!(unflagged("Command::new(a);\n// .no_window()"), [1]);
}

#[test]
fn the_check_accepts_flags_markers_and_comments() {
    assert!(unflagged("Command::new(a)\n    .create_no_window();").is_empty());
    assert!(unflagged("let mut c = Command::new(a);\nc.creation_flags(F);").is_empty());
    assert!(unflagged("// no-window: Linux only\nCommand::new(a);").is_empty());
    assert!(unflagged("// Command::new(a)").is_empty());
}
