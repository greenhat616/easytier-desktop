//! Manifest-backed kernel store. The composition root installs the manifest
//! and binaries in a directory writable only by the host administrator (or
//! the user, for a user host). No client-supplied path is ever used.
use super::{CoreSelector, CoreStore, CoreUsage, StoreError, VerifiedCore};
use etd_contract::{
    HostMode,
    v1::{CoreEntry, CoreSupport},
};
use etd_core_api::{CoreDescriptor, CoreDriver};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const CORE_FILE: &str = if cfg!(windows) {
    "easytier-core.exe"
} else {
    "easytier-core"
};

/// Installation manifest, written by the maintenance command under the
/// machine singleton lock. Entries map versions to immutable SHA directories.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub default_version: Option<String>,
    pub cores: Vec<ManifestEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub version: String,
    /// Empty for a git-less kernel; never profiled, but usable under a user host.
    pub proto_revision: String,
    pub sha256: String,
}
impl Manifest {
    fn validate(&self) -> Result<(), StoreError> {
        let mut versions = HashSet::new();
        let mut hashes = HashSet::new();
        for entry in &self.cores {
            if entry.version.is_empty()
                || !versions.insert(&entry.version)
                || !hashes.insert(&entry.sha256)
                || parse_hash(&entry.sha256).is_none()
            {
                return Err(StoreError::Manifest(
                    "Invalid or duplicate core entry".into(),
                ));
            }
        }
        if self
            .default_version
            .as_ref()
            .is_some_and(|v| !versions.contains(v))
        {
            return Err(StoreError::Manifest("Default kernel not present".into()));
        }
        Ok(())
    }
    fn select(&self, want: &CoreSelector) -> Result<&ManifestEntry, StoreError> {
        let version = want.version.as_ref().or(self.default_version.as_ref());
        self.cores
            .iter()
            .find(|entry| version == Some(&entry.version))
            .ok_or_else(|| StoreError::NotFound(want.clone()))
    }
}
pub struct ManifestCoreStore {
    root: PathBuf,
    mode: HostMode,
    driver: Arc<dyn CoreDriver>,
    // Avoid resolving across an in-process removal. The singleton lock is
    // still mandatory across processes; this is not a substitute for it.
    operations: Mutex<()>,
}
impl ManifestCoreStore {
    pub fn new(root: PathBuf, mode: HostMode, driver: Arc<dyn CoreDriver>) -> Self {
        Self {
            root,
            mode,
            driver,
            operations: Mutex::new(()),
        }
    }
    async fn manifest(&self) -> Result<Manifest, StoreError> {
        let root = self.root.clone();
        blocking(move || read_manifest(&root)).await
    }
    async fn verify(&self, entry: ManifestEntry) -> Result<VerifiedCore, StoreError> {
        let root = self.root.clone();
        let item = entry.clone();
        let (binary, sha256) = blocking(move || verify_file(&root, &item)).await?;
        let declared = CoreDescriptor {
            version: entry.version.clone(),
            proto_revision: entry.proto_revision.clone(),
        };
        // Never execute an unprofiled binary even for identification in a
        // privileged host. The manifest is from the protected store.
        if self.mode != HostMode::User && self.driver.profile(&declared).is_none() {
            return Err(StoreError::NoProfile {
                version: entry.version,
            });
        }
        let descriptor = self
            .driver
            .identify(&binary)
            .await
            .map_err(|_| StoreError::Manifest("Kernel identification failed".into()))?;
        if descriptor
            != (CoreDescriptor {
                version: entry.version.clone(),
                proto_revision: entry.proto_revision,
            })
        {
            return Err(StoreError::Manifest(
                "Kernel descriptor differs from manifest".into(),
            ));
        }
        let usage = match self.driver.profile(&descriptor) {
            Some(profile) => CoreUsage::Profiled(profile),
            None if self.mode == HostMode::User => CoreUsage::LifecycleOnly,
            None => {
                return Err(StoreError::NoProfile {
                    version: entry.version,
                });
            }
        };
        Ok(VerifiedCore {
            binary,
            descriptor,
            sha256,
            usage,
        })
    }
}
#[async_trait::async_trait]
impl CoreStore for ManifestCoreStore {
    async fn resolve(&self, want: &CoreSelector) -> Result<VerifiedCore, StoreError> {
        let _guard = self.operations.lock().await;
        self.verify(self.manifest().await?.select(want)?.clone())
            .await
    }
    async fn list(&self) -> Result<Vec<CoreEntry>, StoreError> {
        let _guard = self.operations.lock().await;
        let mut cores = Vec::new();
        for entry in self.manifest().await?.cores {
            let support = match self.verify(entry.clone()).await {
                Ok(VerifiedCore {
                    usage: CoreUsage::Profiled(_),
                    ..
                }) => CoreSupport::Profiled,
                Ok(VerifiedCore {
                    usage: CoreUsage::LifecycleOnly,
                    ..
                }) => CoreSupport::LifecycleOnly,
                _ => CoreSupport::Rejected,
            };
            cores.push(CoreEntry {
                version: entry.version,
                proto_revision: entry.proto_revision,
                sha256: entry.sha256,
                support: support as i32,
            });
        }
        Ok(cores)
    }
    async fn remove(&self, version: &str) -> Result<(), StoreError> {
        let _guard = self.operations.lock().await;
        let root = self.root.clone();
        let version = version.to_owned();
        blocking(move || remove_entry(&root, &version)).await
    }
}
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| StoreError::Io("Kernel store worker failed".into()))?
}
fn io_error(e: io::Error) -> StoreError {
    StoreError::Io(e.to_string())
}
fn parse_hash(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut result = [0; 32];
    for (i, value) in result.iter_mut().enumerate() {
        *value = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(result)
}
fn check_type(path: &Path, directory: bool) -> Result<(), StoreError> {
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = meta.file_type().is_symlink();
    if reparse
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        }
    {
        return Err(StoreError::Manifest(
            "Unexpected file type in kernel store".into(),
        ));
    }
    Ok(())
}
fn read_manifest(root: &Path) -> Result<Manifest, StoreError> {
    check_type(root, true)?;
    let file = root.join(MANIFEST_FILE);
    check_type(&file, false)?;
    let manifest: Manifest = serde_json::from_reader(fs::File::open(file).map_err(io_error)?)
        .map_err(|_| StoreError::Manifest("Invalid manifest JSON".into()))?;
    manifest.validate()?;
    Ok(manifest)
}
fn verify_file(root: &Path, entry: &ManifestEntry) -> Result<(PathBuf, [u8; 32]), StoreError> {
    let expected =
        parse_hash(&entry.sha256).ok_or_else(|| StoreError::Manifest("Invalid SHA-256".into()))?;
    check_type(root, true)?;
    let dir = root.join(&entry.sha256);
    check_type(&dir, true)?;
    let binary = dir.join(CORE_FILE);
    check_type(&binary, false)?;
    let mut file = fs::File::open(&binary).map_err(io_error)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(io_error)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    let actual: [u8; 32] = hash.finalize().into();
    if actual != expected {
        return Err(StoreError::HashMismatch {
            version: entry.version.clone(),
        });
    }
    Ok((binary, actual))
}
fn remove_entry(root: &Path, version: &str) -> Result<(), StoreError> {
    let mut manifest = read_manifest(root)?;
    let entry = manifest
        .select(&CoreSelector {
            version: Some(version.into()),
        })?
        .clone();
    // Caller already holds the machine singleton lock and has run reclaim_core.
    // Only remove the registered hash directory and its known binary; never
    // recursively delete unknown store contents. Missing binary/dir permits
    // retry after interruption between deletion and manifest replacement.
    let dir = root.join(&entry.sha256);
    match fs::symlink_metadata(&dir) {
        Ok(_) => {
            check_type(&dir, true)?;
            for item in fs::read_dir(&dir).map_err(io_error)? {
                if item.map_err(io_error)?.file_name() != CORE_FILE {
                    return Err(StoreError::Manifest(
                        "Unexpected file in kernel SHA directory".into(),
                    ));
                }
            }
            let binary = dir.join(CORE_FILE);
            match fs::symlink_metadata(&binary) {
                Ok(_) => {
                    verify_file(root, &entry)?;
                    fs::remove_file(&binary).map_err(io_error)?;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_error(e)),
            }
            fs::remove_dir(&dir).map_err(io_error)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(e)),
    }
    manifest.cores.retain(|entry| entry.version != version);
    if manifest.default_version.as_deref() == Some(version) {
        manifest.default_version = None;
    }
    let tmp = root.join(format!(".manifest-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io_error)?;
        serde_json::to_writer_pretty(&mut file, &manifest)
            .map_err(|_| StoreError::Io("Could not serialize manifest".into()))?;
        file.write_all(b"\n").map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        fs::rename(&tmp, root.join(MANIFEST_FILE)).map_err(io_error)?;
        #[cfg(unix)]
        fs::File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
