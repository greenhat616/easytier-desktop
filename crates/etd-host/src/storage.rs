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

include!(concat!(env!("OUT_DIR"), "/trusted_cores.rs"));

pub fn trusted_cores() -> HashMap<String, String> {
    TRUSTED_CORES
        .iter()
        .map(|(version, hash)| (version.to_string(), hash.to_string()))
        .collect()
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
    use etd_core_api::CoreDriver;
    use etd_host_core::core_store::manifest::{CORE_FILE, MANIFEST_FILE, Manifest, ManifestEntry};
    let mut manifest = Manifest::default();
    for &(version, expected) in TRUSTED_CORES {
        let source = bundle_root.join("cores").join(version).join(CORE_FILE);
        let final_dir = target.join(expected);
        if final_dir.try_exists()? {
            bail!("kernel hash directory already exists");
        }
        let stage = tempfile::tempdir_in(target)?;
        let staged = stage.path().join(CORE_FILE);
        copy_verified_core(&source, &staged, expected)
            .with_context(|| format!("bundled core {version}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        }
        let descriptor = etd_core_easytier::EasyTierDriver.identify(&staged).await?;
        if descriptor.version != version {
            bail!("bundled kernel version differs from embedded release table");
        }
        fs::rename(stage.path(), &final_dir)?;
        let _ = stage.keep();
        manifest.cores.push(ManifestEntry {
            version: version.into(),
            proto_revision: descriptor.proto_revision,
            sha256: expected.into(),
        });
    }
    manifest.default_version = manifest.cores.first().map(|entry| entry.version.clone());
    atomic_json(&target.join(MANIFEST_FILE), &manifest)
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
