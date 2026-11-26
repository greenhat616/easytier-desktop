use etd_contract::HostMode;
use etd_core_api::*;
use etd_host_core::core_store::{
    CoreSelector, CoreStore, CoreUsage, StoreError,
    manifest::{
        CORE_FILE, MANIFEST_FILE, Manifest, ManifestCoreStore, ManifestEntry, TrustedBundle,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

struct Driver(bool, &'static str, std::sync::atomic::AtomicUsize);
impl Driver {
    fn new(profiled: bool, revision: &'static str) -> Self {
        Self(profiled, revision, 0.into())
    }
}
#[async_trait::async_trait]
impl CoreDriver for Driver {
    async fn identify(&self, _: &Path) -> Result<CoreDescriptor, CoreError> {
        self.2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(CoreDescriptor {
            version: "1.2.3".into(),
            proto_revision: self.1.into(),
        })
    }
    fn profile(&self, _: &CoreDescriptor) -> Option<AdapterProfile> {
        self.0.then(|| AdapterProfile {
            id: "profile".into(),
            deny_all_verified: false,
        })
    }
    fn plan_launch(&self, _: &LaunchContext) -> Result<LaunchPlan, CoreError> {
        unreachable!()
    }
    async fn attach(
        &self,
        _: &CoreEndpoint,
        _: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError> {
        unreachable!()
    }
}
struct Root(PathBuf);
fn trusted() -> std::collections::HashMap<String, String> {
    let hash = Sha256::digest(b"test binary bytes")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    std::collections::HashMap::from([("1.2.3".into(), hash)])
}
impl Root {
    fn new() -> (Self, PathBuf) {
        let root = std::env::temp_dir().join(format!("etd-h2-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let data = b"test binary bytes";
        let hash = Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let dir = root.join(&hash);
        fs::create_dir(&dir).unwrap();
        let binary = dir.join(CORE_FILE);
        fs::write(&binary, data).unwrap();
        let manifest = Manifest {
            default_version: Some("1.2.3".into()),
            cores: vec![ManifestEntry {
                version: "1.2.3".into(),
                proto_revision: "rev".into(),
                sha256: hash,
            }],
        };
        fs::write(
            root.join(MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        (Self(root), binary)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[tokio::test]
async fn hash_is_checked_every_time() {
    let (root, binary) = Root::new();
    let store = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::Service,
        Arc::new(Driver::new(true, "rev")),
        trusted(),
    )
    .unwrap();
    assert!(matches!(
        store.resolve(&CoreSelector::default()).await.unwrap().usage,
        CoreUsage::Profiled(_)
    ));
    fs::write(binary, b"changed").unwrap();
    assert!(matches!(
        store.resolve(&CoreSelector::default()).await,
        Err(StoreError::HashMismatch { .. })
    ));
    assert_eq!(
        store.list().await.unwrap()[0].support(),
        etd_contract::v1::CoreSupport::Rejected
    );
}

#[tokio::test]
async fn edited_inventory_cannot_authorize_a_new_hash() {
    use std::sync::atomic::Ordering;
    let (root, _) = Root::new();
    let path = root.0.join(MANIFEST_FILE);
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let bytes = b"not a bundled core";
    let hash = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let directory = root.0.join(&hash);
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join(CORE_FILE), bytes).unwrap();
    manifest.cores[0].sha256 = hash;
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let driver = Arc::new(Driver::new(true, "rev"));
    let store =
        ManifestCoreStore::new(root.0.clone(), HostMode::Service, driver.clone(), trusted())
            .unwrap();
    assert!(matches!(
        store.resolve(&CoreSelector::default()).await,
        Err(StoreError::Manifest(_))
    ));
    assert!(store.list().await.is_err());
    assert!(store.remove("1.2.3").await.is_err());
    assert_eq!(driver.2.load(Ordering::SeqCst), 0);
    assert!(directory.exists());
}
#[tokio::test]
async fn profile_required_for_privileged_host() {
    let (root, _) = Root::new();
    let service = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::Service,
        Arc::new(Driver::new(false, "rev")),
        trusted(),
    )
    .unwrap();
    assert!(matches!(
        service.resolve(&CoreSelector::default()).await,
        Err(StoreError::NoProfile { .. })
    ));
    let user = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::User,
        Arc::new(Driver::new(false, "rev")),
        trusted(),
    )
    .unwrap();
    assert_eq!(
        user.resolve(&CoreSelector::default()).await.unwrap().usage,
        CoreUsage::LifecycleOnly
    );
}
#[tokio::test]
async fn remove_only_selected_hash_directory_and_clear_default() {
    let (root, binary) = Root::new();
    let other = root.0.join("unrelated");
    fs::write(&other, b"keep").unwrap();
    let store = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::Service,
        Arc::new(Driver::new(true, "rev")),
        trusted(),
    )
    .unwrap()
    .with_removal_guard(|_| Ok(false));
    store.remove("1.2.3").await.unwrap();
    assert!(!binary.exists());
    assert!(!binary.parent().unwrap().exists());
    assert_eq!(fs::read(other).unwrap(), b"keep");
    assert!(store.list().await.unwrap().is_empty());
    assert!(matches!(
        store.resolve(&CoreSelector::default()).await,
        Err(StoreError::NotFound(_))
    ));
}

#[tokio::test]
async fn gitless_core_is_user_lifecycle_only_and_privileged_refuses() {
    let (root, _) = Root::new();
    let path = root.0.join(MANIFEST_FILE);
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest.cores[0].proto_revision.clear();
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let user = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::User,
        Arc::new(Driver::new(false, "")),
        trusted(),
    )
    .unwrap();
    assert_eq!(
        user.resolve(&CoreSelector::default()).await.unwrap().usage,
        CoreUsage::LifecycleOnly
    );
    let privileged = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::Service,
        Arc::new(Driver::new(false, "")),
        trusted(),
    )
    .unwrap();
    assert!(matches!(
        privileged.resolve(&CoreSelector::default()).await,
        Err(StoreError::NoProfile { .. })
    ));
}

#[tokio::test]
async fn list_caches_identity_and_resolve_returns_canonical_path() {
    use std::sync::atomic::Ordering;
    let (root, binary) = Root::new();
    let driver = Arc::new(Driver::new(true, "rev"));
    let store =
        ManifestCoreStore::new(root.0.clone(), HostMode::Service, driver.clone(), trusted())
            .unwrap();
    assert_eq!(
        store.default_version().await.unwrap().as_deref(),
        Some("1.2.3")
    );
    for _ in 0..3 {
        assert_eq!(
            store.list().await.unwrap()[0].support(),
            etd_contract::v1::CoreSupport::Profiled
        );
    }
    assert_eq!(driver.2.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .resolve(&CoreSelector::default())
            .await
            .unwrap()
            .binary,
        fs::canonicalize(&binary).unwrap()
    );
    assert_eq!(driver.2.load(Ordering::SeqCst), 2);
    // Replace with a distinct file identity, preserving size and mtime.
    let metadata = fs::metadata(&binary).unwrap();
    let replacement = binary.with_extension("replacement");
    fs::write(&replacement, vec![b'x'; metadata.len() as usize]).unwrap();
    fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_modified(metadata.modified().unwrap())
        .unwrap();
    fs::rename(&replacement, &binary).unwrap();
    assert_eq!(
        store.list().await.unwrap()[0].support(),
        etd_contract::v1::CoreSupport::Rejected
    );
    assert_eq!(driver.2.load(Ordering::SeqCst), 2); // Failed hash never executes identify.
}

#[tokio::test]
async fn list_cores_rpc_never_resolves_default_for_each_call() {
    use etd_contract::{HostPhase, HostSnapshot, Role, v1::ListCoresRequest};
    use etd_host_core::{
        api::{HostView, orchestrator_channel},
        service::ContractService,
        stub::host_service_server::HostService,
    };
    use std::sync::atomic::Ordering;
    let f = common::Fixture::new().await;
    let (root, _) = Root::new();
    let driver = Arc::new(Driver::new(true, "rev"));
    let store = Arc::new(
        ManifestCoreStore::new(root.0.clone(), HostMode::Service, driver.clone(), trusted())
            .unwrap(),
    );
    let (handle, _port) = orchestrator_channel(
        8,
        HostView {
            seq: 0,
            snapshot: HostSnapshot {
                phase: HostPhase::Serving as i32,
                ..Default::default()
            },
        },
    );
    let service = ContractService::new(
        HostMode::Service,
        f.ledger,
        etd_sysfx::InstallKey([7; 32]),
        f.auth,
        store,
        handle,
        vec![],
        8,
    );
    for _ in 0..3 {
        let list = service
            .list_cores(common::request(ListCoresRequest {}, Role::Viewer))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(list.default_version, "1.2.3");
        assert_eq!(list.cores.len(), 1);
    }
    assert_eq!(driver.2.load(Ordering::SeqCst), 1);
}
mod common;

fn companion_bundle(binary: &Path, name: &str) -> std::collections::HashMap<String, TrustedBundle> {
    let mut bundle = TrustedBundle::from(trusted().remove("1.2.3").unwrap());
    fs::write(binary.parent().unwrap().join(name), b"trusted companion").unwrap();
    let digest = Sha256::digest(b"trusted companion")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    bundle.companions.insert(name.to_owned(), digest);
    std::collections::HashMap::from([("1.2.3".to_owned(), bundle)])
}

#[tokio::test]
async fn launch_revalidates_all_companions_and_exact_inventory() {
    use std::sync::atomic::Ordering;
    for variant in 0..3 {
        let (root, binary) = Root::new();
        let dir = binary.parent().unwrap();
        let trust = companion_bundle(&binary, "runtime.dll");
        let driver = Arc::new(Driver::new(true, "rev"));
        let store =
            ManifestCoreStore::new(root.0.clone(), HostMode::Service, driver.clone(), trust)
                .unwrap();
        assert!(store.resolve(&CoreSelector::default()).await.is_ok());
        assert_eq!(
            store.list().await.unwrap()[0].support(),
            etd_contract::v1::CoreSupport::Profiled
        );
        match variant {
            0 => fs::remove_file(dir.join("runtime.dll")).unwrap(),
            1 => fs::write(dir.join("unexpected.dll"), b"not trusted").unwrap(),
            _ => fs::write(dir.join("runtime.dll"), b"tampered companion").unwrap(),
        }
        let calls = driver.2.load(Ordering::SeqCst);
        assert!(store.resolve(&CoreSelector::default()).await.is_err());
        assert_eq!(
            store.list().await.unwrap()[0].support(),
            etd_contract::v1::CoreSupport::Rejected
        );
        assert_eq!(driver.2.load(Ordering::SeqCst), calls);
    }
}

#[tokio::test]
async fn bundle_removal_refuses_driver_reference_and_query_failure() {
    let (root, binary) = Root::new();
    let trust = companion_bundle(&binary, "driver.sys");
    let driver = Arc::new(Driver::new(true, "rev"));
    let dir = fs::canonicalize(binary.parent().unwrap()).unwrap();
    let expected = dir.clone();
    let busy = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::Service,
        driver.clone(),
        trust.clone(),
    )
    .unwrap()
    .with_removal_guard(move |actual| {
        assert_eq!(actual, expected);
        Ok(true)
    });
    assert!(matches!(
        busy.remove("1.2.3").await,
        Err(StoreError::InUse { .. })
    ));
    assert!(binary.exists());
    assert!(dir.join("driver.sys").exists());
    assert_eq!(busy.list().await.unwrap().len(), 1);
    drop(busy);
    let unknown = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::Service,
        driver.clone(),
        trust.clone(),
    )
    .unwrap()
    .with_removal_guard(|_| Err(StoreError::Io("enumeration failed".into())));
    assert!(unknown.remove("1.2.3").await.is_err());
    assert!(binary.exists());
    drop(unknown);
    let free = ManifestCoreStore::new(root.0.clone(), HostMode::Service, driver, trust)
        .unwrap()
        .with_removal_guard(|_| Ok(false));
    free.remove("1.2.3").await.unwrap();
    assert!(!dir.exists());
    assert!(free.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn user_executable_only_removes_without_privileged_driver_query() {
    let (root, binary) = Root::new();
    let store = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::User,
        Arc::new(Driver::new(true, "rev")),
        trusted(),
    )
    .unwrap()
    .with_removal_guard(|_| Err(StoreError::Io("user cannot query drivers".into())));
    store.remove("1.2.3").await.unwrap();
    assert!(!binary.exists());
}

#[cfg(windows)]
#[tokio::test]
async fn user_driver_bundle_removal_is_refused_even_without_guard() {
    let (root, binary) = Root::new();
    let trust = companion_bundle(&binary, "driver.sys");
    let store = ManifestCoreStore::new(
        root.0.clone(),
        HostMode::User,
        Arc::new(Driver::new(true, "rev")),
        trust,
    )
    .unwrap();
    assert!(
        store
            .remove("1.2.3")
            .await
            .unwrap_err()
            .to_string()
            .contains("ask an administrator")
    );
    assert!(binary.exists());
}
