//! Host image replacement for `etd-host upgrade` (PK1). The new image is
//! copied beside the installed one and verified before two renames swap it
//! in; the old image stays as `<image>.prev` until the upgrade commits.
//! The platform adapters supply `seal` (final permissions) and `check`
//! (protected ownership) so the sequence itself is testable without root.
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

fn same_bytes(left: &Path, right: &Path) -> io::Result<bool> {
    use sha2::{Digest, Sha256};
    fn hash(path: &Path) -> io::Result<[u8; 32]> {
        use std::io::Read;
        let mut file = File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        Ok(hash.finalize().into())
    }
    Ok(hash(left)? == hash(right)?)
}

/// Swap `source` in as the executable. Refuses while a backup exists: the
/// caller restores or discards an earlier attempt first.
pub(super) fn replace(
    paths: &ImagePaths,
    source: &Path,
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
    {
        let mut input = File::open(source)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut output = options.open(&paths.staging)?;
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
    }
    let staged = (|| {
        seal(&paths.staging)?;
        check(&paths.staging)?;
        if !same_bytes(source, &paths.staging)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "copied host image differs from its source",
            ));
        }
        Ok(())
    })();
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

    #[test]
    fn replace_keeps_the_old_image_until_discarded() {
        let (_root, paths, source) = fixture();
        fs::write(&paths.staging, b"partial copy of a crashed attempt").unwrap();
        replace(&paths, &source, ok, ok).unwrap();
        assert_eq!(fs::read(&paths.executable).unwrap(), b"new image");
        assert_eq!(fs::read(&paths.backup).unwrap(), b"old image");
        assert!(!paths.staging.exists());
        // A second swap would lose the only good copy.
        let error = replace(&paths, &source, ok, ok).unwrap_err();
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
        replace(&paths, &source, ok, ok).unwrap();
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
        assert!(replace(&paths, &source, refuse, ok).is_err());
        assert!(replace(&paths, &source, ok, refuse).is_err());
        assert_eq!(fs::read(&paths.executable).unwrap(), b"old image");
        assert!(!paths.staging.exists() && !paths.backup.exists());
        replace(&paths, &source, ok, ok).unwrap();
        assert!(restore(&paths, refuse).is_err());
        assert!(discard(&paths, refuse).is_err());
        assert_eq!(fs::read(&paths.backup).unwrap(), b"old image");
    }
}
