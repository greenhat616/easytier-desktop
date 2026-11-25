//! Identify a kernel binary (version, proto revision). Owned by E1.
//!
//! Runs `<binary> --version` and parses what clap prints for upstream's
//! `EASYTIER_VERSION` (`easytier/src/common/constants.rs`):
//! `easytier-core <CARGO_PKG_VERSION>-<git describe --abbrev=8 --always
//! --dirty=~><-YYYYMMDD commit date>`, e.g. `easytier-core
//! 2.7.1-c97f36b8-20261124`, or `2.7.1-v2.7.0-12-gc97f36b8-20261124` when a
//! tag is reachable, or the bare package version when built outside git.
use etd_core_api::{CoreDescriptor, CoreError};
use std::{path::Path, process::Stdio, time::Duration};

/// How long `--version` may take before the binary is declared unusable.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
/// Program name clap prints first.
const PROGRAM: &str = "easytier-core";
/// Output beyond this is not a version line.
const MAX_OUTPUT: usize = 4096;

pub async fn identify(binary: &Path) -> Result<CoreDescriptor, CoreError> {
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // The C runtime and Winsock need SystemRoot even for `--version`.
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let output = tokio::time::timeout(VERSION_TIMEOUT, command.output())
        .await
        .map_err(|_| CoreError::Identify(format!("{} --version timed out", binary.display())))?
        .map_err(|error| CoreError::Identify(format!("cannot run {}: {error}", binary.display())))?;
    if !output.status.success() {
        return Err(CoreError::Identify(format!(
            "{} --version exited with {}",
            binary.display(),
            output.status
        )));
    }
    if output.stdout.len() > MAX_OUTPUT {
        return Err(CoreError::Identify("--version output too long".into()));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| CoreError::Identify("--version output is not UTF-8".into()))?;
    parse_version_output(&text)
}

/// Parses the `--version` line. A dirty or git-less build yields an empty or
/// non-hex revision, which no profile matches.
pub fn parse_version_output(text: &str) -> Result<CoreDescriptor, CoreError> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| CoreError::Identify("empty --version output".into()))?;
    let full = line
        .strip_prefix(PROGRAM)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(|| CoreError::Identify(format!("not an {PROGRAM} binary: {line:?}")))?
        .trim();
    let (version, describe) = match full.split_once('-') {
        Some((version, describe)) => (version, describe),
        None => (full, ""),
    };
    let is_version = !version.is_empty()
        && version.split('.').count() == 3
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if !is_version {
        return Err(CoreError::Identify(format!(
            "unrecognised version {version:?}"
        )));
    }
    Ok(CoreDescriptor {
        version: version.to_owned(),
        proto_revision: revision_of(describe),
    })
}

/// The commit hash inside a `git describe` output (`<hash>` or
/// `<tag>-<n>-g<hash>`), followed by an optional `-YYYYMMDD`. A dirty build
/// (`~`) keeps its marker so that it matches no profile.
fn revision_of(describe: &str) -> String {
    let is_hash = |s: &str| s.len() >= 7 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let dirty = describe.contains('~');
    let tokens: Vec<&str> = describe.split('-').map(|t| t.trim_end_matches('~')).collect();
    let hash = tokens
        .iter()
        .rev()
        .find_map(|token| token.strip_prefix('g').filter(|h| is_hash(h)))
        .or_else(|| {
            tokens
                .iter()
                .copied()
                // An 8-digit all-numeric token is the commit date suffix.
                .find(|token| is_hash(token) && !token.bytes().all(|b| b.is_ascii_digit()))
        });
    match hash {
        Some(hash) if dirty => format!("{}~", hash.to_ascii_lowercase()),
        Some(hash) => hash.to_ascii_lowercase(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> (String, String) {
        let core = parse_version_output(text).unwrap();
        (core.version, core.proto_revision)
    }

    #[test]
    fn parses_upstream_shapes() {
        assert_eq!(
            parse("easytier-core 2.7.1-c97f36b8-20261124\n"),
            ("2.7.1".into(), "c97f36b8".into())
        );
        assert_eq!(
            parse("easytier-core 2.7.1-v2.7.0-12-gc97f36b8-20261124\n"),
            ("2.7.1".into(), "c97f36b8".into())
        );
        assert_eq!(
            parse("easytier-core 2.7.1-c97f36b8"),
            ("2.7.1".into(), "c97f36b8".into())
        );
        assert_eq!(parse("easytier-core 2.7.1\n"), ("2.7.1".into(), String::new()));
        assert_eq!(
            parse("easytier-core 2.7.1-c97f36b8~-20261124"),
            ("2.7.1".into(), "c97f36b8~".into())
        );
    }

    #[test]
    fn dirty_and_gitless_builds_get_no_profile() {
        for text in [
            "easytier-core 2.7.1-c97f36b8~-20261124",
            "easytier-core 2.7.1",
        ] {
            assert!(crate::profiles::profile_for(&parse_version_output(text).unwrap()).is_none());
        }
        assert!(
            crate::profiles::profile_for(
                &parse_version_output("easytier-core 2.7.1-c97f36b8-20261124").unwrap()
            )
            .is_some()
        );
    }

    #[test]
    fn rejects_other_programs_and_garbage() {
        for text in ["", "easytier-cli 2.7.1-c97f36b8", "easytier-core", "easytier-core x.y"] {
            assert!(matches!(
                parse_version_output(text),
                Err(CoreError::Identify(_))
            ));
        }
    }
}
