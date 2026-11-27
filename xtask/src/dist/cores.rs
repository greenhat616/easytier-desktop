//! The kernel bundle a package carries, checked against `cores.lock`.

use crate::core_lock;
use crate::fetch_cores::{LOCK, sha256};
use anyhow::{Context, Result, anyhow, ensure};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Check that `dir` holds exactly the `triple` `version` bundle of `lock`:
/// the executable and every companion, with their digests, and nothing
/// else. Returns the file names, the executable first.
pub(super) fn verify(
    lock: &str,
    triple: &str,
    version: &str,
    executable: &str,
    dir: &Path,
) -> Result<Vec<String>> {
    let table = core_lock::parse(lock).map_err(anyhow::Error::msg)?;
    let row = table.get(&(triple, version)).with_context(|| {
        format!(
            "{LOCK} has no {triple} {version} rows; run `cargo xtask fetch-cores --update-lock`"
        )
    })?;
    let pinned = row
        .exe
        .with_context(|| format!("{LOCK} has no {triple} {version} executable row"))?;

    let mut found = BTreeMap::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| anyhow!("{}: non-UTF-8 file name {name:?}", dir.display()))?;
        ensure!(
            entry.file_type()?.is_file(),
            "{}: {name} is not a regular file",
            dir.display()
        );
        found.insert(name, sha256(&fs::read(entry.path())?));
    }

    let exe = found
        .remove(executable)
        .with_context(|| format!("{}: no {executable}", dir.display()))?;
    ensure!(
        exe == pinned,
        "{executable}: SHA-256 {exe} differs from {LOCK} ({pinned})"
    );
    for (name, digest) in &row.files {
        let actual = found
            .get(*name)
            .with_context(|| format!("{}: no {name}, listed in {LOCK}", dir.display()))?;
        ensure!(
            actual == digest,
            "{name}: SHA-256 {actual} differs from {LOCK} ({digest})"
        );
    }
    if let Some(extra) = found
        .keys()
        .find(|name| !row.files.contains_key(name.as_str()))
    {
        anyhow::bail!("{}: {extra} is not listed in {LOCK}", dir.display());
    }
    let mut names = vec![executable.to_owned()];
    names.extend(found.into_keys());
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRIPLE: &str = "x86_64-pc-windows-msvc";
    type Files<'a> = &'a [(&'a str, &'a [u8])];

    fn lock(core: &[u8], dll: &[u8]) -> String {
        format!(
            "{TRIPLE} 2.7.1 {}\n{TRIPLE} 2.7.1 file:wintun.dll {}\n",
            sha256(core),
            sha256(dll)
        )
    }

    fn bundle(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in files {
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        dir
    }

    fn check(lock: &str, dir: &tempfile::TempDir) -> Result<Vec<String>> {
        verify(lock, TRIPLE, "2.7.1", "easytier-core.exe", dir.path())
    }

    #[test]
    fn a_bundle_matching_the_lock_is_accepted_executable_first() {
        let dir = bundle(&[("wintun.dll", b"tun"), ("easytier-core.exe", b"core")]);
        assert_eq!(
            check(&lock(b"core", b"tun"), &dir).unwrap(),
            ["easytier-core.exe", "wintun.dll"]
        );
    }

    #[test]
    fn a_missing_extra_or_changed_file_is_refused() {
        let table = lock(b"core", b"tun");
        let cases: [(Files, &str); 4] = [
            (&[("easytier-core.exe", b"core")], "no wintun.dll"),
            (&[("wintun.dll", b"tun")], "no easytier-core.exe"),
            (
                &[
                    ("easytier-core.exe", b"core"),
                    ("wintun.dll", b"tun"),
                    ("extra.dll", b"x"),
                ],
                "extra.dll is not listed",
            ),
            (
                &[("easytier-core.exe", b"core"), ("wintun.dll", b"other")],
                "wintun.dll: SHA-256",
            ),
        ];
        for (files, expected) in cases {
            let error = check(&table, &bundle(files)).unwrap_err();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        let changed = bundle(&[("easytier-core.exe", b"patched"), ("wintun.dll", b"tun")]);
        let error = check(&table, &changed).unwrap_err();
        assert!(
            format!("{error:#}").contains("easytier-core.exe: SHA-256"),
            "{error:#}"
        );
    }

    #[test]
    fn a_target_or_version_without_rows_is_refused() {
        let dir = bundle(&[("easytier-core.exe", b"core")]);
        let error = verify(
            &lock(b"core", b"tun"),
            TRIPLE,
            "2.7.2",
            "easytier-core.exe",
            dir.path(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("has no"), "{error:#}");
    }
}
