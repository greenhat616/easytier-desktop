//! Host image replacement for `etd-host upgrade` (PK1). The new image is
//! copied beside the installed one and verified before two renames swap it
//! in; the old image stays as `<image>.prev` until the upgrade commits.
//! The platform adapters supply the copy (from the running image, see
//! `running`), `seal` (final permissions) and `check` (protected
//! ownership), so the sequence itself is testable without root.
use super::running::sha256_file;
use super::*;

pub(super) struct ImagePaths {
    pub executable: PathBuf,
    /// Copy of the new image before it is swapped in.
    pub staging: PathBuf,
    /// The previous image, kept until the upgrade commits.
    pub backup: PathBuf,
    /// A failed new image moved aside on restore (Windows may still map it).
    pub failed: PathBuf,
}

impl ImagePaths {
    pub fn of(executable: &Path) -> Self {
        Self {
            executable: executable.to_owned(),
            staging: executable.with_extension("new"),
            backup: executable.with_extension("prev"),
            failed: executable.with_extension("failed"),
        }
    }
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Remove a leftover only after it passes the ownership check.
fn remove_checked(path: &Path, check: &impl Fn(&Path) -> io::Result<()>) -> io::Result<()> {
    if exists(path)? {
        check(path)?;
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Windows scanners can briefly hold a name without delete sharing; retry
/// only the rename itself.
fn rename(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempts = 0;
    loop {
        match fs::rename(from, to) {
            Err(error)
                if cfg!(windows)
                    && matches!(error.raw_os_error(), Some(5 | 32 | 33))
                    && attempts < 40 =>
            {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            result => return result,
        }
    }
}

fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

/// Swap a new image in as the executable. `copy` writes the new image into
/// the staging file and returns the SHA-256 of the bytes it wrote; the
/// sealed staging file must read back with that digest. Refuses while a
/// backup exists: the caller restores or discards an earlier attempt first.
pub(super) fn replace(
    paths: &ImagePaths,
    copy: impl FnOnce(&mut File) -> io::Result<[u8; 32]>,
    seal: impl Fn(&Path) -> io::Result<()>,
    check: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if exists(&paths.backup)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a previous host image backup is still present",
        ));
    }
    check(&paths.executable)?;
    remove_checked(&paths.staging, &check)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut output = options.open(&paths.staging)?;
    let staged = (|| {
        let digest = copy(&mut output)?;
        output.sync_all()?;
        seal(&paths.staging)?;
        check(&paths.staging)?;
        if sha256_file(&paths.staging)? != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the staged host image differs from the bytes copied",
            ));
        }
        Ok(())
    })();
    drop(output);
    if let Err(error) = staged {
        let _ = fs::remove_file(&paths.staging);
        return Err(error);
    }
    // Renaming a running or just-stopped image is allowed on every
    // platform; the name is free for the new image afterwards.
    rename(&paths.executable, &paths.backup)?;
    if let Err(error) = rename(&paths.staging, &paths.executable) {
        let _ = rename(&paths.backup, &paths.executable);
        return Err(error);
    }
    sync_dir(&paths.executable)
}

/// Put the backup back as the executable. `Ok(false)`: there is no backup
/// (nothing was swapped); a leftover staging copy is removed either way.
pub(super) fn restore(
    paths: &ImagePaths,
    check: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<bool> {
    remove_checked(&paths.staging, &check)?;
    if !exists(&paths.backup)? {
        return Ok(false);
    }
    check(&paths.backup)?;
    if exists(&paths.executable)? {
        check(&paths.executable)?;
        remove_checked(&paths.failed, &check)?;
        // Move rather than delete: Windows cannot delete a mapped image.
        rename(&paths.executable, &paths.failed)?;
    }
    rename(&paths.backup, &paths.executable)?;
    sync_dir(&paths.executable)?;
    let _ = remove_checked(&paths.failed, &check);
    Ok(true)
}

/// Drop the backup and any leftovers after a committed upgrade.
pub(super) fn discard(
    paths: &ImagePaths,
    check: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<()> {
    for path in [&paths.staging, &paths.failed, &paths.backup] {
        remove_checked(path, &check)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, ImagePaths, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let install = root.path().join("install");
        fs::create_dir(&install).unwrap();
        let paths = ImagePaths::of(&install.join("etd-host.exe"));
        fs::write(&paths.executable, b"old image").unwrap();
        let source = root.path().join("payload-etd-host");
        fs::write(&source, b"new image").unwrap();
        (root, paths, source)
    }
    fn ok(_: &Path) -> io::Result<()> {
        Ok(())
    }
    /// The copy as the adapters make it: one read of the source, hashed
    /// while written.
    fn from(source: &Path) -> impl FnOnce(&mut File) -> io::Result<[u8; 32]> {
        let source = source.to_owned();
        move |out| super::super::running::copy_hashing(File::open(source)?, out)
    }

    #[test]
    fn replace_keeps_the_old_image_until_discarded() {
        let (_root, paths, source) = fixture();
        fs::write(&paths.staging, b"partial copy of a crashed attempt").unwrap();
        replace(&paths, from(&source), ok, ok).unwrap();
        assert_eq!(fs::read(&paths.executable).unwrap(), b"new image");
        assert_eq!(fs::read(&paths.backup).unwrap(), b"old image");
        assert!(!paths.staging.exists());
        // A second swap would lose the only good copy.
        let error = replace(&paths, from(&source), ok, ok).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&paths.backup).unwrap(), b"old image");
        discard(&paths, ok).unwrap();
        assert!(!paths.backup.exists());
        assert_eq!(fs::read(&paths.executable).unwrap(), b"new image");
    }

    #[test]
    fn restore_brings_back_the_old_image_after_any_interruption() {
        // After both renames.
        let (_root, paths, source) = fixture();
        replace(&paths, from(&source), ok, ok).unwrap();
        assert!(restore(&paths, ok).unwrap());
        assert_eq!(fs::read(&paths.executable).unwrap(), b"old image");
        assert!(!paths.backup.exists() && !paths.failed.exists());
        // Between the two renames: no executable, only the backup.
        let (_root, paths, _) = fixture();
        fs::rename(&paths.executable, &paths.backup).unwrap();
        fs::write(&paths.staging, b"new image").unwrap();
        assert!(restore(&paths, ok).unwrap());
        assert_eq!(fs::read(&paths.executable).unwrap(), b"old image");
        assert!(!paths.staging.exists());
        // Before the first rename: nothing to restore.
        let (_root, paths, _) = fixture();
        fs::write(&paths.staging, b"new image").unwrap();
        assert!(!restore(&paths, ok).unwrap());
        assert_eq!(fs::read(&paths.executable).unwrap(), b"old image");
        assert!(!paths.staging.exists());
    }

    #[test]
    fn a_failed_check_or_seal_changes_nothing() {
        let (_root, paths, source) = fixture();
        let refuse = |_: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(replace(&paths, from(&source), refuse, ok).is_err());
        assert!(replace(&paths, from(&source), ok, refuse).is_err());
        assert_eq!(fs::read(&paths.executable).unwrap(), b"old image");
        assert!(!paths.staging.exists() && !paths.backup.exists());
        replace(&paths, from(&source), ok, ok).unwrap();
        assert!(restore(&paths, refuse).is_err());
        assert!(discard(&paths, refuse).is_err());
        assert_eq!(fs::read(&paths.backup).unwrap(), b"old image");
    }

    #[test]
    fn between_the_two_renames_no_image_is_the_installed_one() {
        let (_root, paths, source) = fixture();
        let source = source.canonicalize().unwrap();
        fs::rename(&paths.executable, &paths.backup).unwrap();
        // Missing executable, backup present: not installed, not an error.
        assert!(!super::super::is_image(&source, &paths.executable).unwrap());
        fs::write(&paths.executable, b"new image").unwrap();
        let installed = paths.executable.canonicalize().unwrap();
        assert!(super::super::is_image(&installed, &paths.executable).unwrap());
        assert!(!super::super::is_image(&source, &paths.executable).unwrap());
    }

    #[test]
    fn a_copy_that_does_not_match_its_digest_changes_nothing() {
        // The digest is of the bytes read; a staged file that reads back
        // differently (here: a copy that lies) is never swapped in.
        use sha2::Digest;
        let (_root, paths, _) = fixture();
        let lying = |out: &mut File| {
            use std::io::Write;
            out.write_all(b"attacker image")?;
            Ok(<[u8; 32]>::from(sha2::Sha256::digest(b"new image")))
        };
        let error = replace(&paths, lying, ok, ok).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&paths.executable).unwrap(), b"old image");
        assert!(!paths.staging.exists() && !paths.backup.exists());
    }
}
