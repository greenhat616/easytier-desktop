//! The repair index and manifest filesystem adapter. Index data is a hint,
//! never authorization for reclaim or kernel launch.
use anyhow::{Context, Result, bail};
use etd_contract::InstanceId;
use etd_sysfx::{InstallKey, LedgerError, RepairIndex, RepairIndexStore, StorageFault};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use etd_host_core::core_store::manifest::{CORE_FILE, TrustedBundle, check_bundle_directory};

include!(concat!(env!("OUT_DIR"), "/trusted_cores.rs"));

pub fn trusted_cores() -> HashMap<String, TrustedBundle> {
    TRUSTED_CORES
        .iter()
        .map(|&(version, hash, files)| (version.to_string(), trusted_bundle(hash, files)))
        .collect()
}

fn trusted_bundle(hash: &str, files: &[(&str, &str)]) -> TrustedBundle {
    TrustedBundle {
        sha256: hash.into(),
        companions: files
            .iter()
            .map(|&(name, digest)| (name.into(), digest.into()))
            .collect(),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    install_key: [u8; 32],
    instances: Vec<String>,
}

pub struct FileIndex(PathBuf);
impl FileIndex {
    pub fn new(state: &Path) -> Self {
        Self(state.join("repair-index.json"))
    }
    pub fn initialize(&self, ledger_exists: bool) -> Result<InstallKey> {
        if let Some(index) = self.load()? {
            return Ok(index.install_key);
        }
        if ledger_exists {
            bail!(
                "repair index is missing from an existing installation; refusing to generate a replacement install key"
            );
        }
        let install_key = InstallKey(rand::random());
        self.store(&RepairIndex {
            install_key: install_key.clone(),
            instances: vec![],
        })?;
        Ok(install_key)
    }
}

fn ledger_io(error: impl std::fmt::Display) -> LedgerError {
    LedgerError::Unavailable(StorageFault::Io(error.to_string()))
}
impl RepairIndexStore for FileIndex {
    fn load(&self) -> Result<Option<RepairIndex>, LedgerError> {
        let file = match fs::File::open(&self.0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ledger_io(error)),
        };
        let index: Index = serde_json::from_reader(file)
            .map_err(|_| LedgerError::Unreadable("invalid repair index".into()))?;
        Ok(Some(RepairIndex {
            install_key: InstallKey(index.install_key),
            instances: index.instances.into_iter().map(InstanceId).collect(),
        }))
    }
    fn store(&self, index: &RepairIndex) -> Result<(), LedgerError> {
        let wire = Index {
            install_key: index.install_key.0,
            instances: index
                .instances
                .iter()
                .map(|instance| instance.0.clone())
                .collect(),
        };
        atomic_json(&self.0, &wire).map_err(ledger_io)
    }
}

fn atomic_json(path: &Path, data: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("missing storage parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut file, data)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn initialize_manifest(root: &Path) -> Result<()> {
    use etd_host_core::core_store::manifest::{MANIFEST_FILE, Manifest};
    let path = root.join(MANIFEST_FILE);
    if !path.try_exists()? {
        atomic_json(&path, &Manifest::default())?;
    }
    Ok(())
}

/// Install only the target-specific build-time release inventory. Hash the
/// bytes inside the protected destination before identifying or publishing
/// the kernel. A caller's local manifest is never a trust source.
pub async fn install_bundled_cores(bundle_root: &Path, target: &Path) -> Result<()> {
    install_bundles(
        bundle_root,
        target,
        TRUSTED_CORES,
        &etd_core_easytier::EasyTierDriver,
    )
    .await
}

async fn install_bundles(
    bundle_root: &Path,
    target: &Path,
    table: &[TrustedCoreRow],
    driver: &dyn etd_core_api::CoreDriver,
) -> Result<()> {
    use etd_host_core::core_store::manifest::{MANIFEST_FILE, Manifest, ManifestEntry};
    let manifest_path = target.join(MANIFEST_FILE);
    anyhow::ensure!(
        !manifest_path.try_exists()?,
        "kernel inventory already exists"
    );
    let mut manifest = Manifest::default();
    let mut published = Vec::new();
    let result = async {
        for &(version, expected, files) in table {
            let source = bundle_root.join("cores").join(version);
            let bundle = trusted_bundle(expected, files);
            let (staged, created) = stage_bundle_core(&source, target, &bundle)
                .with_context(|| format!("bundled core {version}"))?;
            if created {
                published.push(target.join(expected));
            }
            let descriptor = driver.identify(&staged).await?;
            if descriptor.version != version {
                bail!("bundled kernel version differs from embedded release table");
            }
            verify_directory(staged.parent().context("missing SHA directory")?, &bundle)?;
            manifest.cores.push(ManifestEntry {
                version: version.into(),
                proto_revision: descriptor.proto_revision,
                sha256: expected.into(),
            });
        }
        manifest.default_version = manifest.cores.first().map(|entry| entry.version.clone());
        atomic_json(&manifest_path, &manifest)
    }
    .await;
    if let Err(error) = result {
        // The manifest rename may have succeeded before a subsequent sync
        // failed. Do not leave a published inventory pointing at rolled-back
        // directories. This installer only operates on an absent inventory.
        if manifest_path.try_exists()? {
            fs::remove_file(&manifest_path).with_context(|| {
                format!("bundle install failed: {error:#}; could not roll back manifest")
            })?;
        }
        for dir in published.iter().rev() {
            // --version should not register a driver. Still, never remove a
            // newly published driver-bearing bundle if the OS cannot rule
            // out a shared driver reference.
            if fs::read_dir(dir)?.any(|item| {
                item.map_or(true, |item| {
                    item.file_name()
                        .to_str()
                        .is_none_or(|name| name.to_ascii_lowercase().ends_with(".sys"))
                })
            }) {
                if let Some(reference) =
                    etd_sysfx_os::driver_bundle_reference(dir).with_context(|| {
                        format!(
                            "bundle install failed: {error:#}; cannot determine driver references"
                        )
                    })?
                {
                    bail!("bundle install failed: {error:#}; bundle retained: {reference}");
                }
            }
            fs::remove_dir_all(dir).with_context(|| {
                format!(
                    "bundle install failed: {error:#}; could not roll back {}",
                    dir.display()
                )
            })?;
        }
        return Err(error);
    }
    Ok(())
}

fn is_hash_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn plain_directory(path: &Path) -> Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Ok(false);
        }
    }
    Ok(metadata.is_dir())
}

fn verify_directory(dir: &Path, bundle: &TrustedBundle) -> Result<()> {
    check_bundle_directory(dir, bundle)?;
    for (name, expected) in bundle.files() {
        anyhow::ensure!(
            hash_file(&dir.join(name))? == expected,
            "hash differs from embedded release table: {name}"
        );
    }
    Ok(())
}

/// Reuse only exact, verified bundles after interruption. Validate the source
/// even on retry; never repair or delete an unexpected published directory.
fn stage_bundle_core(
    source: &Path,
    target: &Path,
    bundle: &TrustedBundle,
) -> Result<(PathBuf, bool)> {
    anyhow::ensure!(is_hash_name(&bundle.sha256), "invalid embedded hash");
    check_bundle_directory(source, bundle)?;
    let final_dir = target.join(&bundle.sha256);
    let final_file = final_dir.join(CORE_FILE);
    let stage = tempfile::tempdir_in(target)?;
    for (name, expected) in bundle.files() {
        copy_verified_core(&source.join(name), &stage.path().join(name), expected)?;
    }
    verify_directory(stage.path(), bundle)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            stage.path().join(CORE_FILE),
            fs::Permissions::from_mode(0o755),
        )?;
        fs::File::open(stage.path())?.sync_all()?;
    }
    match fs::symlink_metadata(&final_dir) {
        Ok(_) => {
            verify_directory(&final_dir, bundle)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&final_file, fs::Permissions::from_mode(0o755))?;
            }
            return Ok((final_file, false));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    fs::rename(stage.path(), &final_dir)?;
    let _ = stage.keep();
    Ok((final_file, true))
}

/// User-only startup recovery, under the user host lock. Keep manifest
/// members (or the embedded bundle candidates before first commit), remove
/// only unreferenced ordinary SHA directories.
pub fn cleanup_user_core_orphans(root: &Path) -> Result<()> {
    use etd_host_core::core_store::manifest::{MANIFEST_FILE, Manifest};
    let live: std::collections::HashSet<String> = match fs::File::open(root.join(MANIFEST_FILE)) {
        Ok(file) => serde_json::from_reader::<_, Manifest>(file)?
            .cores
            .into_iter()
            .map(|entry| entry.sha256)
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => TRUSTED_CORES
            .iter()
            .map(|(_, hash, _)| hash.to_string())
            .collect(),
        Err(error) => return Err(error.into()),
    };
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(name) = name.to_str()
            && is_hash_name(name)
            && !live.contains(name)
        {
            anyhow::ensure!(
                plain_directory(&entry.path())?,
                "untrusted orphan kernel directory"
            );
            // Never garbage-collect a driver-bearing orphan without knowing
            // whether a driver is loaded or registered against it. User-only
            // recovery has no required SCM access, so preserve these orphans.
            if fs::read_dir(entry.path())?.any(|item| {
                item.map_or(true, |item| {
                    item.file_name()
                        .to_str()
                        .is_none_or(|name| name.to_ascii_lowercase().ends_with(".sys"))
                })
            }) {
                continue;
            }
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

fn copy_verified_core(source: &Path, staged: &Path, expected: &str) -> Result<()> {
    let mut input = fs::File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staged)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    drop(output);
    if hash_file(staged)? != expected {
        bail!("hash differs from embedded release table");
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn manifest_exists(root: &Path) -> Result<bool> {
    Ok(root
        .join(etd_host_core::core_store::manifest::MANIFEST_FILE)
        .try_exists()?)
}

pub fn ledger_exists(state: &Path) -> Result<bool> {
    Ok(state.join("ledger.sqlite3").try_exists()?)
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum NativeHistory {
    NeverEnabled,
    EnabledOrUnknown,
}

/// Monotonic per-installation history. After native adapters have been enabled,
/// the durable tombstone can never be reset by opening/losing the ledger.
/// Absence in an existing installation is conservatively unknown.
pub fn native_history(state: &Path, available: bool, fresh: bool) -> Result<bool> {
    let path = state.join("native-adapter-history.json");
    let was = match fs::File::open(&path) {
        Ok(file) => Some(
            serde_json::from_reader::<_, NativeHistory>(file)
                .context("invalid native adapter history")?,
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let next =
        if available || was == Some(NativeHistory::EnabledOrUnknown) || (was.is_none() && !fresh) {
            NativeHistory::EnabledOrUnknown
        } else {
            NativeHistory::NeverEnabled
        };
    if was.as_ref() != Some(&next) {
        atomic_json(&path, &next)?;
    }
    Ok(next == NativeHistory::NeverEnabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, TrustedBundle) {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("bundle");
        let target = root.path().join("cores");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join(CORE_FILE), b"verified fixture").unwrap();
        fs::write(source.join("runtime.dll"), b"verified companion").unwrap();
        let hash = hash_file(&source.join(CORE_FILE)).unwrap();
        let companion = hash_file(&source.join("runtime.dll")).unwrap();
        (
            root,
            source,
            target,
            trusted_bundle(&hash, &[("runtime.dll", &companion)]),
        )
    }

    #[test]
    fn retry_after_hash_directory_publish_before_manifest_commit() {
        let (_root, source, target, bundle) = fixture();
        let (staged, created) = stage_bundle_core(&source, &target, &bundle).unwrap();
        assert!(created);
        assert_eq!(
            fs::read(staged.parent().unwrap().join("runtime.dll")).unwrap(),
            b"verified companion"
        );
        assert_eq!(
            stage_bundle_core(&source, &target, &bundle).unwrap(),
            (staged.clone(), false)
        );
        fs::write(&staged, b"corrupt").unwrap();
        assert!(stage_bundle_core(&source, &target, &bundle).is_err());
        assert_eq!(fs::read(staged).unwrap(), b"corrupt");
        initialize_manifest(&target).unwrap();
        cleanup_user_core_orphans(&target).unwrap();
        assert!(!target.join(bundle.sha256).exists());
    }

    #[test]
    fn missing_extra_or_tampered_source_never_publishes() {
        for variant in 0..3 {
            let (_root, source, target, bundle) = fixture();
            match variant {
                0 => fs::remove_file(source.join("runtime.dll")).unwrap(),
                1 => fs::write(source.join("extra.dll"), b"extra").unwrap(),
                _ => fs::write(source.join("runtime.dll"), b"tampered").unwrap(),
            }
            assert!(stage_bundle_core(&source, &target, &bundle).is_err());
            assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        }
    }

    #[test]
    fn published_bundle_missing_extra_or_tampered_companion_is_rejected() {
        for variant in 0..3 {
            let (_root, source, target, bundle) = fixture();
            let (binary, _) = stage_bundle_core(&source, &target, &bundle).unwrap();
            let dir = binary.parent().unwrap();
            match variant {
                0 => fs::remove_file(dir.join("runtime.dll")).unwrap(),
                1 => fs::write(dir.join("extra.dll"), b"extra").unwrap(),
                _ => fs::write(dir.join("runtime.dll"), b"tampered").unwrap(),
            }
            assert!(stage_bundle_core(&source, &target, &bundle).is_err());
            assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
        }
    }
    #[tokio::test]
    async fn install_commits_complete_bundle_only_and_rolls_back_on_failure() {
        let root = tempfile::tempdir().unwrap();
        let bundle_root = root.path().join("image");
        let source = bundle_root.join("cores").join("9.9.9");
        let target = root.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join(CORE_FILE), b"verified fixture").unwrap();
        fs::write(source.join("runtime.dll"), b"verified companion").unwrap();
        const TABLE: &[TrustedCoreRow] = &[(
            "9.9.9",
            "f9adb7d924ed98c558040c910600d7363d749e7d20e8d355626edd53b4fb929f",
            &[(
                "runtime.dll",
                "5a76891725f3b6a5325dc17f0cef622fffb0b38794e1b0c7d9f2537ff73ad1fb",
            )],
        )];
        let driver = etd_testkit::fakes::core::FakeCoreDriver::new();
        // The second, unavailable bundle forces rollback of the first bundle
        // before the manifest can be committed.
        let mut invalid = TABLE.to_vec();
        invalid.push((
            "another",
            "5a2fb8a8a81676b585a828720640469131e1bef8750f45304506f2615d9389ad",
            &[],
        ));
        assert!(
            install_bundles(&bundle_root, &target, &invalid, &driver)
                .await
                .is_err()
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        assert!(
            install_bundles(&bundle_root, &target, TABLE, &driver)
                .await
                .is_ok()
        );
        assert_eq!(
            fs::read(target.join(TABLE[0].1).join("runtime.dll")).unwrap(),
            b"verified companion"
        );
        assert!(manifest_exists(&target).unwrap());
    }

    #[test]
    fn bundle_copy_requires_the_embedded_hash() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("bundle");
        let staged = root.path().join("staged");
        std::fs::write(&source, b"trusted core fixture").unwrap();
        let hash = super::hash_file(&source).unwrap();
        super::copy_verified_core(&source, &staged, &hash).unwrap();
        assert_eq!(std::fs::read(&staged).unwrap(), b"trusted core fixture");
        std::fs::write(&source, b"modified core fixture").unwrap();
        assert!(super::copy_verified_core(&source, &root.path().join("bad"), &hash).is_err());
    }

    #[test]
    fn native_adapter_history_is_monotonic() {
        let state = tempfile::tempdir().unwrap();
        assert!(super::native_history(state.path(), false, true).unwrap());
        assert!(!super::native_history(state.path(), true, false).unwrap());
        assert!(!super::native_history(state.path(), false, true).unwrap());
        let state = tempfile::tempdir().unwrap();
        assert!(!super::native_history(state.path(), false, false).unwrap());
        assert!(!super::native_history(state.path(), false, true).unwrap());
    }
}
