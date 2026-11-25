use etd_contract::HostMode;
use etd_core_api::*;
use etd_host_core::core_store::{
    CoreSelector, CoreStore, CoreUsage, StoreError,
    manifest::{CORE_FILE, MANIFEST_FILE, Manifest, ManifestCoreStore, ManifestEntry},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

struct Driver(bool);
#[async_trait::async_trait]
impl CoreDriver for Driver {
    async fn identify(&self, _: &Path) -> Result<CoreDescriptor, CoreError> {
        Ok(CoreDescriptor {
            version: "1.2.3".into(),
            proto_revision: "rev".into(),
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
    let store = ManifestCoreStore::new(root.0.clone(), HostMode::Service, Arc::new(Driver(true)));
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
async fn profile_required_for_privileged_host() {
    let (root, _) = Root::new();
    let service =
        ManifestCoreStore::new(root.0.clone(), HostMode::Service, Arc::new(Driver(false)));
    assert!(matches!(
        service.resolve(&CoreSelector::default()).await,
        Err(StoreError::NoProfile { .. })
    ));
    let user = ManifestCoreStore::new(root.0.clone(), HostMode::User, Arc::new(Driver(false)));
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
    let store = ManifestCoreStore::new(root.0.clone(), HostMode::Service, Arc::new(Driver(true)));
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
