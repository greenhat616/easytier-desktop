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
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex as SyncMutex},
    time::SystemTime,
};
use tokio::sync::Mutex;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const CORE_FILE: &str = if cfg!(windows) {
    "easytier-core.exe"
} else {
    "easytier-core"
};

/// Build-time trust entry. Companion digests never come from the inventory.
#[derive(Debug, Clone)]
pub struct TrustedBundle {
    pub sha256: String,
    pub companions: BTreeMap<String, String>,
}

impl From<String> for TrustedBundle {
    fn from(sha256: String) -> Self {
        Self {
            sha256,
            companions: BTreeMap::new(),
        }
    }
}
impl TrustedBundle {
    pub fn files(&self) -> impl Iterator<Item = (&str, &str)> {
        std::iter::once((CORE_FILE, self.sha256.as_str())).chain(
            self.companions
                .iter()
                .map(|(name, hash)| (name.as_str(), hash.as_str())),
        )
    }
}

/// Read-only platform consultation before deleting a driver-bearing bundle.
type RemovalGuard = dyn Fn(&Path) -> Result<bool, StoreError> + Send + Sync;

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
// Keep the opened file identity, not a pathname-derived surrogate. The
// cached handle prevents reuse of its file id while the entry is retained.
#[derive(PartialEq, Eq)]
struct FileStamp {
    size: u64,
    modified: SystemTime,
    identity: same_file::Handle,
}
struct OpenCore {
    binary: PathBuf,
    stamps: BTreeMap<String, Arc<FileStamp>>,
}
struct CachedCore {
    stamps: BTreeMap<String, Arc<FileStamp>>,
    descriptor: CoreDescriptor,
    support: CoreSupport,
}

pub struct ManifestCoreStore {
    root: PathBuf,
    mode: HostMode,
    driver: Arc<dyn CoreDriver>,
    trusted: Arc<HashMap<String, TrustedBundle>>,
    removal_guard: Option<Arc<RemovalGuard>>,
    // Short manifest/removal critical sections only: hashing and identify
    // never hold this lock during normal resolution or ListCores.
    operations: Mutex<()>,
    cache: SyncMutex<HashMap<String, CachedCore>>,
    list_verification: Mutex<()>,
}
impl ManifestCoreStore {
    pub fn new<B: Into<TrustedBundle>>(
        root: PathBuf,
        mode: HostMode,
        driver: Arc<dyn CoreDriver>,
        trusted: HashMap<String, B>,
    ) -> Result<Self, StoreError> {
        check_type(&root, true)?;
        let root = fs::canonicalize(root).map_err(io_error)?;
        check_type(&root, true)?;
        Ok(Self {
            root,
            mode,
            driver,
            trusted: Arc::new(
                trusted
                    .into_iter()
                    .map(|(version, bundle)| (version, bundle.into()))
                    .collect(),
            ),
            removal_guard: None,
            operations: Mutex::new(()),
            cache: SyncMutex::new(HashMap::new()),
            list_verification: Mutex::new(()),
        })
    }
    pub fn with_removal_guard(
        mut self,
        guard: impl Fn(&Path) -> Result<bool, StoreError> + Send + Sync + 'static,
    ) -> Self {
        self.removal_guard = Some(Arc::new(guard));
        self
    }
    async fn manifest(&self) -> Result<Manifest, StoreError> {
        let _guard = self.operations.lock().await;
        let root = self.root.clone();
        let trusted = self.trusted.clone();
        blocking(move || read_trusted_manifest(&root, &trusted)).await
    }
    async fn open(&self, entry: &ManifestEntry) -> Result<OpenCore, StoreError> {
        let root = self.root.clone();
        let entry = entry.clone();
        let trusted = self.trusted.clone();
        blocking(move || open_core(&root, &entry, &trusted[&entry.version])).await
    }
    async fn verify(
        &self,
        entry: &ManifestEntry,
        open: OpenCore,
    ) -> Result<VerifiedCore, StoreError> {
        let item = entry.clone();
        let trusted = self.trusted.clone();
        let (open, sha256) = blocking(move || {
            let sha256 = hash_core(&open, &item, &trusted[&item.version])?;
            Ok((open, sha256))
        })
        .await?;
        let declared = entry.descriptor();
        // Verify the protected hash before asking the binary to identify itself.
        if self.mode != HostMode::User && self.driver.profile(&declared).is_none() {
            return Err(StoreError::NoProfile {
                version: entry.version.clone(),
            });
        }
        let descriptor = self
            .driver
            .identify(&open.binary)
            .await
            .map_err(|_| StoreError::Manifest("Kernel identification failed".into()))?;
        if descriptor != declared {
            return Err(StoreError::Manifest(
                "Kernel descriptor differs from manifest".into(),
            ));
        }
        // Detect replacement between opening, hashing and identification.
        let current = self.open(entry).await?;
        if current.stamps != open.stamps || current.binary != open.binary {
            return Err(StoreError::Manifest(
                "Kernel changed during verification".into(),
            ));
        }
        let usage = match self.driver.profile(&descriptor) {
            Some(profile) => CoreUsage::Profiled(profile),
            None if self.mode == HostMode::User => CoreUsage::LifecycleOnly,
            None => {
                return Err(StoreError::NoProfile {
                    version: entry.version.clone(),
                });
            }
        };
        Ok(VerifiedCore {
            binary: open.binary,
            descriptor,
            sha256,
            usage,
        })
    }
    async fn support(&self, entry: &ManifestEntry) -> CoreSupport {
        // Single-flight cache misses, without holding the operations lock.
        let _verification = self.list_verification.lock().await;
        let open = match self.open(entry).await {
            Ok(open) => open,
            Err(_) => {
                self.cache.lock().unwrap().remove(&entry.sha256);
                return CoreSupport::Rejected;
            }
        };
        let descriptor = entry.descriptor();
        if let Some(support) = self
            .cache
            .lock()
            .unwrap()
            .get(&entry.sha256)
            .filter(|cached| cached.stamps == open.stamps && cached.descriptor == descriptor)
            .map(|cached| cached.support)
        {
            return support;
        }
        let stamps = open.stamps.clone();
        let support = match self.verify(entry, open).await {
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
        self.cache.lock().unwrap().insert(
            entry.sha256.clone(),
            CachedCore {
                stamps,
                descriptor,
                support,
            },
        );
        support
    }
}
impl ManifestEntry {
    fn descriptor(&self) -> CoreDescriptor {
        CoreDescriptor {
            version: self.version.clone(),
            proto_revision: self.proto_revision.clone(),
        }
    }
}
#[async_trait::async_trait]
impl CoreStore for ManifestCoreStore {
    async fn resolve(&self, want: &CoreSelector) -> Result<VerifiedCore, StoreError> {
        let entry = self.manifest().await?.select(want)?.clone();
        // Launch resolution always re-hashes, even if ListCores cached support.
        let open = self.open(&entry).await?;
        self.verify(&entry, open).await
    }
    async fn list(&self) -> Result<Vec<CoreEntry>, StoreError> {
        let manifest = self.manifest().await?;
        self.cache
            .lock()
            .unwrap()
            .retain(|hash, _| manifest.cores.iter().any(|entry| &entry.sha256 == hash));
        let mut cores = Vec::new();
        for entry in manifest.cores {
            let support = self.support(&entry).await;
            cores.push(CoreEntry {
                version: entry.version,
                proto_revision: entry.proto_revision,
                sha256: entry.sha256,
                support: support as i32,
            });
        }
        Ok(cores)
    }
    async fn default_version(&self) -> Result<Option<String>, StoreError> {
        Ok(self.manifest().await?.default_version)
    }
    async fn remove(&self, version: &str) -> Result<(), StoreError> {
        let _guard = self.operations.lock().await;
        // Release retained file handles before the maintenance deletion.
        self.cache.lock().unwrap().clear();
        let root = self.root.clone();
        let version = version.to_owned();
        let trusted = self.trusted.clone();
        let guard = self.removal_guard.clone();
        let mode = self.mode;
        blocking(move || remove_entry(&root, &version, &trusted, mode, guard.as_deref())).await
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
fn read_trusted_manifest(
    root: &Path,
    trusted: &HashMap<String, TrustedBundle>,
) -> Result<Manifest, StoreError> {
    let manifest = read_manifest(root)?;
    // The on-disk manifest is only an installation inventory, never the
    // source of trust. The composition root supplies the build-time table.
    if manifest.cores.iter().any(|entry| {
        trusted.get(&entry.version).map(|bundle| &bundle.sha256) != Some(&entry.sha256)
    }) {
        return Err(StoreError::Manifest(
            "kernel inventory is not in the embedded release hash table".into(),
        ));
    }
    Ok(manifest)
}
/// Require exactly the pinned ordinary files; no extra entries, symlinks or
/// reparse points. Used both by installation and launch resolution.
pub fn check_bundle_directory(dir: &Path, bundle: &TrustedBundle) -> Result<(), StoreError> {
    check_type(dir, true)?;
    let mut expected: HashSet<_> = bundle.files().map(|(name, _)| name).collect();
    for item in fs::read_dir(dir).map_err(io_error)? {
        let item = item.map_err(io_error)?;
        let name = item.file_name();
        if !name.to_str().is_some_and(|name| expected.remove(name)) {
            return Err(StoreError::Manifest(
                "Unexpected file in kernel SHA directory".into(),
            ));
        }
        check_type(&item.path(), false)?;
    }
    if !expected.is_empty() {
        return Err(StoreError::Manifest("Missing file in kernel bundle".into()));
    }
    Ok(())
}

fn open_core(
    root: &Path,
    entry: &ManifestEntry,
    bundle: &TrustedBundle,
) -> Result<OpenCore, StoreError> {
    if parse_hash(&entry.sha256).is_none() {
        return Err(StoreError::Manifest("Invalid SHA-256".into()));
    }
    check_type(root, true)?;
    let dir = root.join(&entry.sha256);
    check_bundle_directory(&dir, bundle)?;
    let mut stamps = BTreeMap::new();
    let mut binary = None;
    for (name, _) in bundle.files() {
        let path = fs::canonicalize(dir.join(name)).map_err(io_error)?;
        if !path.starts_with(root) || path.parent() != Some(dir.as_path()) {
            return Err(StoreError::Manifest(
                "Kernel file escapes its SHA directory".into(),
            ));
        }
        let identity = same_file::Handle::from_file(fs::File::open(&path).map_err(io_error)?)
            .map_err(io_error)?;
        let meta = identity.as_file().metadata().map_err(io_error)?;
        stamps.insert(
            name.to_string(),
            Arc::new(FileStamp {
                size: meta.len(),
                modified: meta.modified().map_err(io_error)?,
                identity,
            }),
        );
        if name == CORE_FILE {
            binary = Some(path);
        }
    }
    Ok(OpenCore {
        binary: binary.expect("bundle includes executable"),
        stamps,
    })
}

fn hash_matches(
    mut file: &fs::File,
    expected: &str,
    version: &str,
) -> Result<[u8; 32], StoreError> {
    let expected =
        parse_hash(expected).ok_or_else(|| StoreError::Manifest("Invalid SHA-256".into()))?;
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
            version: version.to_owned(),
        });
    }
    Ok(actual)
}

fn hash_core(
    open: &OpenCore,
    entry: &ManifestEntry,
    bundle: &TrustedBundle,
) -> Result<[u8; 32], StoreError> {
    for (name, digest) in bundle.files() {
        hash_matches(open.stamps[name].identity.as_file(), digest, &entry.version)?;
    }
    Ok(parse_hash(&entry.sha256).expect("verified executable hash"))
}

/// User stores are not a privileged trust boundary. A non-elevated user
/// may remove an ordinary tree only if it contains no Windows driver image.
fn check_user_tree(dir: &Path) -> Result<(), StoreError> {
    check_type(dir, true)?;
    for entry in fs::read_dir(dir).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            StoreError::Manifest("Unexpected non-Unicode kernel file name".into())
        })?;
        if name.ends_with('.') || name.ends_with(' ') {
            return Err(StoreError::Manifest(
                "Unexpected aliased kernel file name".into(),
            ));
        }
        if name.to_ascii_lowercase().ends_with(".sys") {
            return Err(StoreError::Manifest(
                "Driver-bearing bundle: remove it from the system service or ask an administrator"
                    .into(),
            ));
        }
        let file_type = entry.file_type().map_err(io_error)?;
        if file_type.is_dir() {
            check_user_tree(&entry.path())?;
        } else {
            check_type(&entry.path(), false)?;
        }
    }
    Ok(())
}

pub fn check_user_bundle_removal(dir: &Path) -> Result<(), StoreError> {
    check_user_tree(dir)
}

fn remove_entry(
    root: &Path,
    version: &str,
    trusted: &HashMap<String, TrustedBundle>,
    mode: HostMode,
    guard: Option<&RemovalGuard>,
) -> Result<(), StoreError> {
    let mut manifest = read_trusted_manifest(root, trusted)?;
    let entry = manifest
        .select(&CoreSelector {
            version: Some(version.into()),
        })?
        .clone();
    // Caller holds the singleton lock and has run reclaim_core. Do not
    // delete a driver image still referenced by the system, even if stopped.
    // Validate all remaining members before deleting any; missing members
    // permit retry after a crash during removal.
    let bundle = &trusted[version];
    let dir = root.join(&entry.sha256);
    match fs::symlink_metadata(&dir) {
        Ok(_) => {
            check_type(&dir, true)?;
            if mode == HostMode::User {
                if bundle
                    .companions
                    .keys()
                    .any(|name| name.to_ascii_lowercase().ends_with(".sys"))
                {
                    return Err(StoreError::Manifest("Driver-bearing bundle: remove it from the system service or ask an administrator".into()));
                }
                check_user_bundle_removal(&dir)?;
            } else {
                let guard = guard.ok_or_else(|| {
                    StoreError::Manifest("Driver reference check unavailable".into())
                })?;
                if guard(&dir)? {
                    return Err(StoreError::InUse {
                        version: version.into(),
                    });
                }
            }
            let expected: HashMap<_, _> = bundle.files().collect();
            let mut remaining = Vec::new();
            for item in fs::read_dir(&dir).map_err(io_error)? {
                let item = item.map_err(io_error)?;
                let name = item.file_name();
                let digest = name
                    .to_str()
                    .and_then(|name| expected.get(name))
                    .ok_or_else(|| {
                        StoreError::Manifest("Unexpected file in kernel SHA directory".into())
                    })?;
                let path = item.path();
                check_type(&path, false)?;
                hash_matches(&fs::File::open(&path).map_err(io_error)?, digest, version)?;
                remaining.push(path);
            }
            for path in remaining {
                fs::remove_file(path).map_err(io_error)?;
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
