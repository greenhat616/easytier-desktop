//! The repair index and manifest filesystem adapter. Index data is a hint,
//! never authorization for reclaim or kernel launch.
use anyhow::{Context, Result, bail};
use etd_contract::{HostMode, InstanceId};
use etd_sysfx::{InstallKey, LedgerError, RepairIndex, RepairIndexStore, StorageFault};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use etd_host_core::core_store::manifest::{
    CORE_FILE, TrustedBundle, check_bundle_directory, check_user_bundle_removal,
};

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
pub async fn install_bundled_cores(
    bundle_root: &Path,
    target: &Path,
    mode: HostMode,
) -> Result<()> {
    install_bundles(
        bundle_root,
        target,
        TRUSTED_CORES,
        mode,
        &etd_core_easytier::EasyTierDriver,
        etd_sysfx_os::driver_bundle_reference,
    )
    .await
}

async fn install_bundles(
    bundle_root: &Path,
    target: &Path,
    table: &[TrustedCoreRow],
    mode: HostMode,
    driver: &dyn etd_core_api::CoreDriver,
    driver_ref: impl Fn(&Path) -> Result<Option<String>, etd_sysfx_os::OsError>,
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
            // --version should not register a driver. Still, never remove
            // a published bundle if the OS cannot rule out a shared reference.
            if mode == HostMode::User {
                check_user_bundle_removal(dir).with_context(|| {
                    format!("bundle install failed: {error:#}; bundle retained")
                })?;
            } else if let Some(reference) = driver_ref(dir).with_context(|| {
                format!("bundle install failed: {error:#}; cannot determine driver references")
            })? {
                bail!("bundle install failed: {error:#}; bundle retained: {reference}");
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

/// What an upgrade changed in the kernel store.
pub struct CoreMerge {
    /// SHA directories this upgrade created; removed again on rollback.
    pub published: Vec<PathBuf>,
    /// Versions dropped from the manifest because this build no longer
    /// trusts them. Their directories stay: live records may name them.
    pub dropped: Vec<String>,
}

/// `etd-host upgrade`: merge this build's release table into an existing
/// service kernel store. Kept entries must still match the embedded table;
/// rows already present are verified in place, missing ones are staged from
/// `<bundle_root>/cores/<version>/`. No SHA directory is ever deleted here.
/// The previous manifest is saved to `backup` before the new one is
/// committed, so [`restore_manifest`] can undo the commit.
pub async fn upgrade_bundled_cores(
    bundle_root: &Path,
    target: &Path,
    backup: &Path,
) -> Result<CoreMerge> {
    merge_bundles(
        bundle_root,
        target,
        backup,
        TRUSTED_CORES,
        &etd_core_easytier::EasyTierDriver,
        etd_sysfx_os::driver_bundle_reference,
    )
    .await
}

fn read_manifest(target: &Path) -> Result<etd_host_core::core_store::manifest::Manifest> {
    use etd_host_core::core_store::manifest::MANIFEST_FILE;
    let file = fs::File::open(target.join(MANIFEST_FILE))
        .context("kernel inventory missing; reinstall the service")?;
    serde_json::from_reader(file).context("invalid kernel inventory")
}

/// The manifest an upgrade with `table` commits, or `None` if a row must
/// first be staged. Untrusted entries are dropped; the default becomes the
/// table's first version.
fn merged_manifest(
    old: &etd_host_core::core_store::manifest::Manifest,
    table: &[TrustedCoreRow],
) -> (etd_host_core::core_store::manifest::Manifest, Vec<String>) {
    use etd_host_core::core_store::manifest::Manifest;
    let trusted = |version: &str, sha: &str| {
        table
            .iter()
            .any(|&(row, expected, _)| row == version && expected == sha)
    };
    let (cores, dropped): (Vec<_>, Vec<_>) = old
        .cores
        .iter()
        .cloned()
        .partition(|entry| trusted(&entry.version, &entry.sha256));
    let default_version = table
        .first()
        .map(|&(version, _, _)| version.to_owned())
        .or_else(|| {
            old.default_version
                .clone()
                .filter(|version| cores.iter().any(|entry| &entry.version == version))
        });
    (
        Manifest {
            default_version,
            cores,
        },
        dropped.into_iter().map(|entry| entry.version).collect(),
    )
}

/// The store already holds exactly this build's release table, verified.
pub fn cores_current(target: &Path) -> Result<bool> {
    current_with(target, TRUSTED_CORES)
}

fn current_with(target: &Path, table: &[TrustedCoreRow]) -> Result<bool> {
    let old = read_manifest(target)?;
    let (merged, dropped) = merged_manifest(&old, table);
    let present = |&(version, expected, _): &TrustedCoreRow| {
        merged
            .cores
            .iter()
            .any(|entry| entry.version == version && entry.sha256 == expected)
    };
    if !dropped.is_empty()
        || merged.default_version != old.default_version
        || !table.iter().all(present)
    {
        return Ok(false);
    }
    for &(_, expected, files) in table {
        if verify_directory(&target.join(expected), &trusted_bundle(expected, files)).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn merge_bundles(
    bundle_root: &Path,
    target: &Path,
    backup: &Path,
    table: &[TrustedCoreRow],
    driver: &dyn etd_core_api::CoreDriver,
    driver_ref: impl Fn(&Path) -> Result<Option<String>, etd_sysfx_os::OsError>,
) -> Result<CoreMerge> {
    use etd_host_core::core_store::manifest::{MANIFEST_FILE, ManifestEntry};
    let old = read_manifest(target)?;
    let (mut manifest, dropped) = merged_manifest(&old, table);
    let mut published = Vec::new();
    let result = async {
        for &(version, expected, files) in table {
            let bundle = trusted_bundle(expected, files);
            if manifest
                .cores
                .iter()
                .any(|entry| entry.version == version && entry.sha256 == expected)
            {
                verify_directory(&target.join(expected), &bundle)
                    .with_context(|| format!("installed core {version}"))?;
                continue;
            }
            let source = bundle_root.join("cores").join(version);
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
            manifest.cores.retain(|entry| entry.version != version);
            manifest.cores.push(ManifestEntry {
                version: version.into(),
                proto_revision: descriptor.proto_revision,
                sha256: expected.into(),
            });
        }
        if serde_json::to_value(&manifest)? != serde_json::to_value(&old)? {
            atomic_json(backup, &old)?;
            atomic_json(&target.join(MANIFEST_FILE), &manifest)?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        // The manifest is the last write; a failure before it leaves the
        // previous inventory in place, a failure during it is undone here.
        restore_manifest(target, backup)
            .with_context(|| format!("upgrade failed: {error:#}; could not restore manifest"))?;
        remove_published(&published, &driver_ref)
            .with_context(|| format!("upgrade failed: {error:#}"))?;
        return Err(error);
    }
    Ok(CoreMerge { published, dropped })
}

/// Put back the manifest saved by an upgrade, if any, and drop the backup.
pub fn restore_manifest(target: &Path, backup: &Path) -> Result<bool> {
    use etd_host_core::core_store::manifest::{MANIFEST_FILE, Manifest};
    let file = match fs::File::open(backup) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let manifest: Manifest =
        serde_json::from_reader(file).context("invalid saved kernel inventory")?;
    atomic_json(&target.join(MANIFEST_FILE), &manifest)?;
    discard_manifest_backup(backup)?;
    Ok(true)
}

pub fn discard_manifest_backup(backup: &Path) -> Result<()> {
    match fs::remove_file(backup) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// The SQLite header fields of the ledger that tell whether a host
/// migrated it: `user_version` is the schema version, and a non-empty WAL
/// means the main file's header may not be current yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerHeader {
    pub user_version: u32,
    pub wal_pending: bool,
}

/// Read without opening the database, so no migration can run. `None` if
/// there is no readable SQLite ledger.
pub fn ledger_header(state: &Path) -> Option<LedgerHeader> {
    use std::io::Read;
    let path = state.join("ledger.sqlite3");
    let mut header = [0u8; 64];
    fs::File::open(&path).ok()?.read_exact(&mut header).ok()?;
    if &header[..16] != b"SQLite format 3\0" {
        return None;
    }
    let user_version = u32::from_be_bytes([header[60], header[61], header[62], header[63]]);
    let wal_pending = fs::metadata(state.join("ledger.sqlite3-wal")).is_ok_and(|m| m.len() > 0);
    Some(LedgerHeader {
        user_version,
        wal_pending,
    })
}

/// What an upgrade that dropped `dropped` kernels must tell the user about
/// the host's kernel selection. Reads the ledger read-only (never migrates
/// it); if that is not possible the notice names no instances.
pub async fn kernel_selection_notice(state: &Path, dropped: &[String]) -> Option<String> {
    use etd_sysfx::{
        BootId, Ledger,
        sqlite::{OpenOptions, SqliteLedger},
    };
    if dropped.is_empty() {
        return None;
    }
    let generic = format!(
        "if the selected kernel was {}, instances will not start until another kernel is selected",
        dropped.join(" or ")
    );
    if !ledger_exists(state).unwrap_or(false) {
        return None;
    }
    let Ok(ledger) = SqliteLedger::open_with_options(
        state.join("ledger.sqlite3"),
        BootId("upgrade-diagnosis".into()),
        OpenOptions {
            read_only: true,
            ..Default::default()
        },
    )
    .await
    else {
        return Some(generic);
    };
    let read = async {
        let settings = ledger.settings().await?;
        let (_, desired) = ledger.desired().await?;
        Ok::<_, LedgerError>((settings.selected_core, desired))
    }
    .await;
    let _ = ledger.close().await;
    let Ok((selected, desired)) = read else {
        return Some(generic);
    };
    let selected = selected.filter(|version| dropped.contains(version))?;
    let running: Vec<String> = desired
        .iter()
        .filter(|instance| instance.desired == etd_contract::v1::Desired::Running as i32)
        .map(|instance| {
            let name = instance
                .spec
                .as_ref()
                .map(|spec| spec.display_name.as_str())
                .unwrap_or_default();
            if name.is_empty() {
                instance.instance_id.clone()
            } else {
                format!("{name} ({})", instance.instance_id)
            }
        })
        .collect();
    Some(if running.is_empty() {
        format!(
            "the selected kernel {selected} is no longer trusted; select another kernel before starting an instance"
        )
    } else {
        format!(
            "the selected kernel {selected} is no longer trusted; these instances will not start until another kernel is selected: {}",
            running.join(", ")
        )
    })
}

/// Remove SHA directories an upgrade created, newest first. A directory the
/// OS cannot rule out as a driver image source is kept and reported.
pub fn remove_published(
    published: &[PathBuf],
    driver_ref: &impl Fn(&Path) -> Result<Option<String>, etd_sysfx_os::OsError>,
) -> Result<()> {
    for dir in published.iter().rev() {
        if !dir.try_exists()? {
            continue;
        }
        if let Some(reference) = driver_ref(dir)
            .with_context(|| format!("cannot determine driver references of {}", dir.display()))?
        {
            bail!("kernel bundle {} retained: {reference}", dir.display());
        }
        fs::remove_dir_all(dir).with_context(|| format!("could not remove {}", dir.display()))?;
    }
    Ok(())
}

/// [`remove_published`] with the native driver reference query.
pub fn remove_published_bundles(published: &[PathBuf]) -> Result<()> {
    remove_published(published, &etd_sysfx_os::driver_bundle_reference)
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
            if let Err(error) = check_user_bundle_removal(&entry.path()) {
                tracing::warn!(path = %entry.path().display(), %error, "retaining orphan kernel bundle");
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

    #[cfg(windows)]
    #[test]
    fn orphan_cleanup_preserves_nested_drivers_and_removes_ordinary_tree() {
        let (_root, _source, target, bundle) = fixture();
        let dir = target.join(&bundle.sha256);
        let nested = dir.join("nested").join("driver.SYS");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&nested, b"fixture").unwrap();
        initialize_manifest(&target).unwrap();
        cleanup_user_core_orphans(&target).unwrap();
        assert!(nested.exists());
        fs::remove_file(&nested).unwrap();
        fs::write(nested.with_extension("dll"), b"fixture").unwrap();
        cleanup_user_core_orphans(&target).unwrap();
        assert!(!dir.exists());
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
            install_bundles(
                &bundle_root,
                &target,
                &invalid,
                HostMode::Service,
                &driver,
                |_| Ok(None)
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        assert!(
            install_bundles(
                &bundle_root,
                &target,
                &invalid,
                HostMode::User,
                &driver,
                |_| panic!("user rollback must not query drivers")
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        assert!(
            install_bundles(
                &bundle_root,
                &target,
                TABLE,
                HostMode::Service,
                &driver,
                |_| Ok(None)
            )
            .await
            .is_ok()
        );
        assert_eq!(
            fs::read(target.join(TABLE[0].1).join("runtime.dll")).unwrap(),
            b"verified companion"
        );
        assert!(manifest_exists(&target).unwrap());
    }

    const CORE_SHA: &str = "f9adb7d924ed98c558040c910600d7363d749e7d20e8d355626edd53b4fb929f";
    const COMPANION_SHA: &str = "5a76891725f3b6a5325dc17f0cef622fffb0b38794e1b0c7d9f2537ff73ad1fb";
    const OLD_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// An installed store with one old entry and a payload carrying 9.9.9.
    fn upgrade_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        use etd_host_core::core_store::manifest::{MANIFEST_FILE, Manifest, ManifestEntry};
        let root = tempfile::tempdir().unwrap();
        let bundle_root = root.path().join("payload");
        let source = bundle_root.join("cores").join("9.9.9");
        let target = root.path().join("cores");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(target.join(OLD_SHA)).unwrap();
        fs::write(target.join(OLD_SHA).join(CORE_FILE), b"old kernel").unwrap();
        fs::write(source.join(CORE_FILE), b"verified fixture").unwrap();
        fs::write(source.join("runtime.dll"), b"verified companion").unwrap();
        atomic_json(
            &target.join(MANIFEST_FILE),
            &Manifest {
                default_version: Some("1.0.0".into()),
                cores: vec![ManifestEntry {
                    version: "1.0.0".into(),
                    proto_revision: "0000000".into(),
                    sha256: OLD_SHA.into(),
                }],
            },
        )
        .unwrap();
        let backup = root
            .path()
            .join("maintenance")
            .join("upgrade-manifest.json");
        fs::create_dir(backup.parent().unwrap()).unwrap();
        (root, bundle_root, target, backup)
    }

    fn manifest_text(target: &Path) -> String {
        fs::read_to_string(target.join(etd_host_core::core_store::manifest::MANIFEST_FILE)).unwrap()
    }

    #[tokio::test]
    async fn upgrade_merges_new_kernels_and_keeps_old_directories() {
        const TABLE: &[TrustedCoreRow] = &[("9.9.9", CORE_SHA, &[("runtime.dll", COMPANION_SHA)])];
        let (_root, bundle_root, target, backup) = upgrade_fixture();
        let before = manifest_text(&target);
        assert!(!current_with(&target, TABLE).unwrap());
        let driver = etd_testkit::fakes::core::FakeCoreDriver::new();
        let merge = merge_bundles(&bundle_root, &target, &backup, TABLE, &driver, |_| Ok(None))
            .await
            .unwrap();
        assert_eq!(merge.published, [target.join(CORE_SHA)]);
        assert_eq!(merge.dropped, ["1.0.0"]);
        let manifest = read_manifest(&target).unwrap();
        assert_eq!(manifest.default_version.as_deref(), Some("9.9.9"));
        assert_eq!(manifest.cores.len(), 1);
        assert_eq!(manifest.cores[0].sha256, CORE_SHA);
        // The untrusted old bundle is no longer listed but never deleted.
        assert!(target.join(OLD_SHA).join(CORE_FILE).is_file());
        assert!(current_with(&target, TABLE).unwrap());
        // A second merge changes nothing and saves no new backup.
        fs::remove_file(&backup).unwrap();
        let again = merge_bundles(&bundle_root, &target, &backup, TABLE, &driver, |_| Ok(None))
            .await
            .unwrap();
        assert!(again.published.is_empty() && again.dropped.is_empty());
        assert!(!backup.exists());
        // Restoring brings back the pre-upgrade manifest exactly once.
        atomic_json(
            &backup,
            &serde_json::from_str::<serde_json::Value>(&before).unwrap(),
        )
        .unwrap();
        assert!(restore_manifest(&target, &backup).unwrap());
        assert_eq!(read_manifest(&target).unwrap().cores[0].sha256, OLD_SHA);
        assert!(!backup.exists());
        assert!(!restore_manifest(&target, &backup).unwrap());
        remove_published(&merge.published, &|_| Ok(None)).unwrap();
        assert!(!target.join(CORE_SHA).exists());
    }

    #[tokio::test]
    async fn failed_upgrade_merge_leaves_the_store_as_it_was() {
        // The second row has no bundle in the payload.
        const TABLE: &[TrustedCoreRow] = &[
            ("9.9.9", CORE_SHA, &[("runtime.dll", COMPANION_SHA)]),
            (
                "another",
                "5a2fb8a8a81676b585a828720640469131e1bef8750f45304506f2615d9389ad",
                &[],
            ),
        ];
        let (_root, bundle_root, target, backup) = upgrade_fixture();
        let before = manifest_text(&target);
        let driver = etd_testkit::fakes::core::FakeCoreDriver::new();
        assert!(
            merge_bundles(&bundle_root, &target, &backup, TABLE, &driver, |_| Ok(None))
                .await
                .is_err()
        );
        assert_eq!(manifest_text(&target), before);
        assert!(!target.join(CORE_SHA).exists());
        assert!(!backup.exists());
        // A bundle the OS may still reference as a driver source is kept.
        let referenced = target.join(OLD_SHA);
        let error = remove_published(std::slice::from_ref(&referenced), &|_| {
            Ok(Some("driver fixture".into()))
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("driver fixture"));
        assert!(referenced.exists());
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

    #[test]
    fn the_ledger_header_shows_a_migration_without_opening_the_database() {
        let state = tempfile::tempdir().unwrap();
        assert_eq!(super::ledger_header(state.path()), None);
        let mut page = b"SQLite format 3\0".to_vec();
        page.resize(100, 0);
        page[60..64].copy_from_slice(&7u32.to_be_bytes());
        std::fs::write(state.path().join("ledger.sqlite3"), &page).unwrap();
        let header = super::ledger_header(state.path()).unwrap();
        assert_eq!(header.user_version, 7);
        assert!(!header.wal_pending);
        std::fs::write(state.path().join("ledger.sqlite3-wal"), b"").unwrap();
        assert!(!super::ledger_header(state.path()).unwrap().wal_pending);
        std::fs::write(state.path().join("ledger.sqlite3-wal"), b"frames").unwrap();
        assert!(super::ledger_header(state.path()).unwrap().wal_pending);
        std::fs::write(state.path().join("ledger.sqlite3"), b"not a database").unwrap();
        assert_eq!(super::ledger_header(state.path()), None);
    }
}
