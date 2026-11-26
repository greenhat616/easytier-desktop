//! Only the dedicated, elevated CI job may install a machine-wide service.
use etd_client::stub::host_service_client::HostServiceClient;
use etd_contract::{
    VERSION_MAJOR, VERSION_METADATA_KEY, VERSION_MINOR,
    v1::{Hello, HostMode, HostPhase, HostSnapshot, Role, SnapshotRequest},
    version_metadata_value,
};
use etd_ipc::{
    Connector, Endpoint, ServerExpectation, platform::LocalConnector, tonic_io::ClientIo,
};
use etd_sysfx_os::service::{
    HostFilesystem, NativeHostFilesystem, NativeServiceManager, ServiceManager,
};
use etd_testkit::no_window::NoWindow;
use std::{
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

#[cfg(windows)]
use etd_sysfx_os::service::ci_fixture::{StandardAccount, assert_query_only};

fn command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.no_window();
    command
}

#[cfg(windows)]
fn standard_user_handshake(
    account: &StandardAccount,
    connector: Arc<LocalConnector>,
    endpoint: Endpoint,
) -> anyhow::Result<(etd_ipc::ServerIdentity, etd_contract::v1::Welcome)> {
    account.run(move || -> anyhow::Result<_> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(15), async {
                let (_, identity) = connector.connect(&endpoint).await?;
                assert_query_only(identity.peer.pid)?;
                let channel = tonic::transport::Endpoint::from_static("http://localhost")
                    .connect_with_connector(ClientIo::new(connector, endpoint))
                    .await?;
                let mut client = HostServiceClient::new(channel);
                let mut request = tonic::Request::new(Hello {
                    major: VERSION_MAJOR,
                    minor: VERSION_MINOR,
                    ..Default::default()
                });
                request.metadata_mut().insert(
                    VERSION_METADATA_KEY,
                    version_metadata_value().parse().unwrap(),
                );
                let welcome = client.handshake(request).await?.into_inner();
                Ok::<_, anyhow::Error>((identity, welcome))
            })
            .await?
        })
    })?
}

#[cfg(windows)]
async fn revoke_user(
    connector: Arc<LocalConnector>,
    endpoint: Endpoint,
    sid: &str,
) -> anyhow::Result<()> {
    use etd_contract::v1::{
        GetAllowListRequest, MutationHeader, SetAllowListRequest, os_principal::Id,
    };
    fn request<T>(body: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(body);
        request.metadata_mut().insert(
            VERSION_METADATA_KEY,
            version_metadata_value().parse().unwrap(),
        );
        request
    }
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(ClientIo::new(connector, endpoint))
        .await?;
    let mut client = HostServiceClient::new(channel);
    let existing = client
        .get_allow_list(request(GetAllowListRequest {}))
        .await?
        .into_inner();
    let mut entries = existing.entries;
    let prior = entries.len();
    entries.retain(|entry| !matches!(entry.principal.as_ref().and_then(|principal| principal.id.as_ref()), Some(Id::WindowsUserSid(user)) if user == sid));
    anyhow::ensure!(
        entries.len() + 1 == prior,
        "initial durable enrollment is absent or duplicated"
    );
    let response = client
        .set_allow_list(request(SetAllowListRequest {
            header: Some(MutationHeader {
                request_id: "ci-revoke-user".into(),
                expected_revision: existing.revision,
            }),
            entries: entries.clone(),
        }))
        .await?
        .into_inner();
    anyhow::ensure!(
        response.receipt.is_some(),
        "allow-list change has no durable receipt"
    );
    let actual = client
        .get_allow_list(request(GetAllowListRequest {}))
        .await?
        .into_inner();
    anyhow::ensure!(
        actual.entries == entries,
        "post-update ledger and RPC allow-list differ"
    );
    Ok(())
}

/// The service did not reach Serving in time: print where it stood and the
/// tail of its log, so the cause survives the cleanup that removes them.
fn report_unserved(layout: &etd_sysfx_os::service::HostLayout, last: Option<HostSnapshot>) {
    match &last {
        Some(snapshot) => {
            eprintln!("last snapshot phase: {:?}", snapshot.phase());
            if let Some(reclaim) = &snapshot.reclaim {
                for note in &reclaim.notes {
                    eprintln!("reclaim note: {} {}", note.code, note.message);
                }
                eprintln!(
                    "reclaim: {} instance(s), {} candidate(s), {} conflict(s)",
                    reclaim.instances.len(),
                    reclaim.candidates.len(),
                    reclaim.conflicts.len()
                );
            }
        }
        None => eprintln!("no snapshot was received"),
    }
    let mut logs: Vec<_> = std::fs::read_dir(&layout.state)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("host.log"))
        })
        .collect();
    logs.sort();
    for path in logs {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        eprintln!(
            "--- {} (last {} lines)",
            path.display(),
            lines.len().min(200)
        );
        for line in &lines[lines.len().saturating_sub(200)..] {
            eprintln!("{line}");
        }
    }
}

#[tokio::test]
#[ignore = "requires a disposable elevated CI runner and ETD_HOST_CI_INSTALL=1"]
async fn install_connect_uninstall() {
    if std::env::var("ETD_HOST_CI_INSTALL").as_deref() != Ok("1")
        || std::env::var("CI").as_deref() != Ok("true")
    {
        eprintln!("skipped: privileged service installation is CI-only");
        return;
    }
    assert!(NativeServiceManager.entry_is_elevated().unwrap());
    let binary = env!("CARGO_BIN_EXE_etd-host");
    let layout = NativeHostFilesystem.service_layout().unwrap();
    assert!(!layout.state.exists());
    assert!(!layout.executable.exists());
    let mut install = command(binary);
    install.arg("install");
    #[cfg(windows)]
    let account = {
        let account = StandardAccount::create().unwrap();
        install.args(["--allow-user", account.sid()]);
        account
    };
    let result = install.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let installed_image = layout.executable.canonicalize().unwrap();
    #[cfg(windows)]
    let endpoint = Endpoint::NamedPipe(etd_ipc::SERVICE_PIPE_NAME.into());
    #[cfg(unix)]
    let endpoint = Endpoint::UnixSocket(etd_ipc::SERVICE_SOCKET_PATH.into());
    let connector = Arc::new(LocalConnector {
        expectation: ServerExpectation {
            exe_dir: layout.executable.parent().unwrap().to_owned(),
            user: None,
            privileged: true,
        },
    });
    let connection = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(connection) = connector.connect(&endpoint).await {
                break connection;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    // Always attempt cleanup before asserting connection evidence.
    let identity = connection.map(|(connection, identity)| {
        drop(connection);
        identity
    });
    // The latest snapshot seen while waiting for Serving, reported with the
    // host log if the service never gets there (before cleanup removes it).
    let last = Arc::new(std::sync::Mutex::new(None::<HostSnapshot>));
    let seen = last.clone();
    let handshake = tokio::time::timeout(Duration::from_secs(30), async {
        let channel = tonic::transport::Endpoint::from_static("http://localhost")
            .connect_with_connector(ClientIo::new(connector.clone(), endpoint.clone()))
            .await?;
        let mut client = HostServiceClient::new(channel);
        let mut request = tonic::Request::new(Hello {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            ..Default::default()
        });
        request.metadata_mut().insert(
            VERSION_METADATA_KEY,
            version_metadata_value().parse().unwrap(),
        );
        let welcome = client.handshake(request).await?.into_inner();
        loop {
            let mut request = tonic::Request::new(SnapshotRequest {});
            request.metadata_mut().insert(
                VERSION_METADATA_KEY,
                version_metadata_value().parse().unwrap(),
            );
            let snapshot = client.snapshot(request).await?.into_inner();
            let serving = snapshot.phase() == HostPhase::Serving;
            *seen.lock().unwrap() = Some(snapshot);
            if serving {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, Box<dyn std::error::Error>>(welcome)
    })
    .await;
    if !matches!(handshake, Ok(Ok(_))) {
        report_unserved(&layout, last.lock().unwrap().take());
    }
    #[cfg(windows)]
    let standard = standard_user_handshake(&account, connector.clone(), endpoint.clone());
    #[cfg(windows)]
    let revoked = tokio::time::timeout(
        Duration::from_secs(15),
        revoke_user(connector.clone(), endpoint.clone(), account.sid()),
    )
    .await;
    #[cfg(windows)]
    let after_revoke = standard_user_handshake(&account, connector.clone(), endpoint.clone());
    #[cfg(windows)]
    let cleanup = command(&installed_image).arg("uninstall").output().unwrap();
    #[cfg(unix)]
    let cleanup = command(binary).arg("uninstall").output().unwrap();
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    tokio::time::timeout(Duration::from_secs(45), async {
        while layout.state.exists()
            || layout.executable.parent().unwrap().exists()
            || etd_sysfx_os::service::LifecycleJournal::open(&layout)
                .unwrap()
                .is_some()
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("uninstall helper did not finish removing product directories");
    let replay = command(binary).arg("uninstall").output().unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        layout.maintenance.join("host.lock").is_file(),
        "stable lock must survive uninstall"
    );
    let identity = identity.expect("installed service never accepted a verified local connection");
    let welcome = handshake
        .expect("service did not serve within timeout")
        .expect("authenticated service handshake failed");
    assert_eq!(welcome.host_mode(), HostMode::Service);
    assert_eq!(welcome.role(), Role::Admin);
    assert_eq!(identity.exe, installed_image);
    println!(
        "verified service image {:?}, owner {:?}, pid {}; handshake Admin/Service",
        installed_image, identity.peer.user, identity.peer.pid
    );
    #[cfg(windows)]
    assert_eq!(
        identity.peer.user,
        etd_ipc::OsUserId::WindowsSid("S-1-5-18".into())
    );
    #[cfg(windows)]
    {
        let (server, welcome) =
            standard.expect("standard account must authenticate using the enrolled SID");
        assert_eq!(server.exe, installed_image);
        assert_eq!(
            server.peer.user,
            etd_ipc::OsUserId::WindowsSid("S-1-5-18".into())
        );
        assert_eq!(
            welcome.role(),
            Role::Control,
            "a non-elevated enrolled SID is not Admin"
        );
        println!(
            "standard user verified LocalSystem pipe and protected image; role Control while elevated admin role Admin"
        );
        revoked
            .expect("live ACL update timed out")
            .expect("SetAllowList failed to revoke the enrolled SID");
        let denied = after_revoke
            .expect_err("revoked user connected after the durable SetAllowList receipt");
        assert_eq!(
            denied
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::PermissionDenied),
            "expected kernel pipe ACL denial, got {denied:#}"
        );
        println!(
            "SetAllowList receipt returned with the durable snapshot and live pipe ACL updated; revoked standard user refused"
        );
    }
    assert!(!layout.state.exists());
    assert!(!layout.executable.parent().unwrap().exists());
    #[cfg(unix)]
    assert!(etd_sysfx_os::service::service_group_id().is_err());
    #[cfg(target_os = "linux")]
    assert!(!std::path::Path::new("/etc/systemd/system/easytier-desk-host.service").exists());
    #[cfg(target_os = "macos")]
    assert!(!std::path::Path::new("/Library/LaunchDaemons/easytier-desk-host.plist").exists());
    #[cfg(windows)]
    assert_eq!(
        command("sc.exe")
            .args(["query", "easytier-desk-host"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(1060)
    );
    println!(
        "uninstall reclaimed the ledger and removed service registration, owned directories and group"
    );
    let spawn_install = || {
        command(binary)
            .arg("install")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = spawn_install();
    let second = spawn_install();
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert!(
        first.status.success() ^ second.status.success(),
        "exactly one racing install must succeed: first {}, second {}",
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&second.stderr)
    );
    let cleanup = command(binary).arg("uninstall").output().unwrap();
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert!(!layout.state.exists() && !layout.executable.parent().unwrap().exists());
    assert!(layout.maintenance.join("host.lock").is_file());
    let install = spawn_install();
    tokio::time::timeout(Duration::from_secs(20), async {
        while etd_sysfx_os::service::LifecycleJournal::open(&layout)
            .unwrap()
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("racing install never began");
    let uninstall = command(binary).arg("uninstall").output().unwrap();
    let installed = install.wait_with_output().unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(
        uninstall.status.success(),
        "{}",
        String::from_utf8_lossy(&uninstall.stderr)
    );
    assert!(!layout.state.exists() && !layout.executable.parent().unwrap().exists());
    let status = command(binary)
        .args(["uninstall", "--status"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("No maintenance journal"));
    assert!(
        layout
            .maintenance
            .join("maintenance-command.lock")
            .is_file()
    );
    println!(
        "racing installs serialized; uninstall waited for installing handoff; completion status and stable locks verified"
    );
}

#[cfg(windows)]
#[test]
#[ignore = "requires a disposable elevated CI runner and ETD_HOST_CI_INSTALL=1"]
fn driver_reference_inventory_and_registered_fixture() {
    use etd_sysfx_os::{driver_bundle_reference, windows::driver_refs::ci_short_path};
    use std::{
        ffi::OsStr,
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
    };

    if std::env::var("ETD_HOST_CI_INSTALL").as_deref() != Ok("1")
        || std::env::var("CI").as_deref() != Ok("true")
    {
        eprintln!("skipped: privileged driver registration is CI-only");
        return;
    }
    assert!(NativeServiceManager.entry_is_elevated().unwrap());

    fn sc(args: &[&OsStr]) -> std::process::Output {
        let sc = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"))
            .join("System32")
            .join("sc.exe");
        Command::new(sc)
            .args(args)
            .creation_flags(0x0800_0000)
            .output()
            .unwrap()
    }

    // RAII cleanup deletes only the randomly named, non-started fixture
    // registration. The fixture is inert bytes, never a loadable driver.
    struct Registration(String);
    impl Drop for Registration {
        fn drop(&mut self) {
            let result = sc(&[OsStr::new("delete"), OsStr::new(&self.0)]);
            if !result.status.success() && !std::thread::panicking() {
                panic!(
                    "fixture registration cleanup failed: {}",
                    String::from_utf8_lossy(&result.stdout)
                );
            }
        }
    }

    fn assert_registered(bundle: &Path, image: &OsStr) {
        let name = format!("etd-cb-ci-{}", uuid::Uuid::new_v4().simple());
        let result = sc(&[
            OsStr::new("create"),
            OsStr::new(&name),
            OsStr::new("type="),
            OsStr::new("kernel"),
            OsStr::new("start="),
            OsStr::new("demand"),
            OsStr::new("binPath="),
            image,
        ]);
        assert!(
            result.status.success(),
            "inert driver registration: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        let guard = Registration(name.clone());
        let reference = driver_bundle_reference(bundle)
            .unwrap()
            .expect("registered driver reference");
        assert!(reference.contains(&name), "{reference}");
        drop(guard);
    }

    let fixture = tempfile::Builder::new()
        .prefix("etd-cb-driver-fixture-")
        .tempdir()
        .unwrap();
    let image = fixture.path().join("fixture-driver-long-name.sys");
    std::fs::write(&image, b"inert driver service fixture, never load").unwrap();
    assert_eq!(driver_bundle_reference(fixture.path()).unwrap(), None);

    assert_registered(fixture.path(), image.as_os_str());
    let absolute = image.to_str().unwrap();
    let nt = format!(r"\??\{absolute}");
    assert_registered(fixture.path(), OsStr::new(&nt));
    let short = ci_short_path(&image).unwrap();
    if short != image {
        assert_registered(fixture.path(), short.as_os_str());
    } else {
        eprintln!(
            "8.3 alias not enabled for the fixture volume; short-path query returned the long name"
        );
    }
    assert_eq!(driver_bundle_reference(fixture.path()).unwrap(), None);
}

/// The admin view of the durable allow list, over the verified service pipe.
async fn admin_allow_list(
    connector: Arc<LocalConnector>,
    endpoint: Endpoint,
) -> anyhow::Result<etd_contract::v1::GetAllowListResponse> {
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(ClientIo::new(connector, endpoint))
        .await?;
    let mut client = HostServiceClient::new(channel);
    let mut request = tonic::Request::new(etd_contract::v1::GetAllowListRequest {});
    request.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    Ok(client.get_allow_list(request).await?.into_inner())
}

fn ci_install_enabled() -> bool {
    let enabled = std::env::var("ETD_HOST_CI_INSTALL").as_deref() == Ok("1")
        && std::env::var("CI").as_deref() == Ok("true");
    if !enabled {
        eprintln!("skipped: privileged service upgrade is CI-only");
    }
    enabled
}

/// What an upgrade must keep, as the running service and its state show it.
#[derive(Debug, PartialEq)]
struct Kept {
    allow_list: etd_contract::v1::GetAllowListResponse,
    install_id: String,
    install_key: serde_json::Value,
}

/// An installed service under test.
struct Installed {
    binary: std::path::PathBuf,
    layout: etd_sysfx_os::service::HostLayout,
    connector: Arc<LocalConnector>,
    endpoint: Endpoint,
    /// The installed image path and its bytes right after install.
    image: std::path::PathBuf,
    original: Vec<u8>,
}

impl Installed {
    fn install() -> Self {
        assert!(NativeServiceManager.entry_is_elevated().unwrap());
        let binary = std::path::PathBuf::from(env!("CARGO_BIN_EXE_etd-host"));
        let layout = NativeHostFilesystem.service_layout().unwrap();
        assert!(!layout.state.exists() && !layout.executable.exists());
        let installed = command(&binary).arg("install").output().unwrap();
        assert!(
            installed.status.success(),
            "{}",
            String::from_utf8_lossy(&installed.stderr)
        );
        #[cfg(windows)]
        let endpoint = Endpoint::NamedPipe(etd_ipc::SERVICE_PIPE_NAME.into());
        #[cfg(unix)]
        let endpoint = Endpoint::UnixSocket(etd_ipc::SERVICE_SOCKET_PATH.into());
        let connector = Arc::new(LocalConnector {
            expectation: ServerExpectation {
                exe_dir: layout.executable.parent().unwrap().to_owned(),
                user: None,
                privileged: true,
            },
        });
        let image = layout.executable.canonicalize().unwrap();
        let original = std::fs::read(&image).unwrap();
        Self {
            binary,
            layout,
            connector,
            endpoint,
            image,
            original,
        }
    }

    /// Wait for the service to answer, then read what must be kept.
    async fn served(&self) -> (etd_ipc::ServerIdentity, Kept) {
        let (identity, allow_list) = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Ok((connection, identity)) = self.connector.connect(&self.endpoint).await {
                    drop(connection);
                    if let Ok(list) =
                        admin_allow_list(self.connector.clone(), self.endpoint.clone()).await
                    {
                        break (identity, list);
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("installed service never answered GetAllowList");
        let index: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.layout.state.join("repair-index.json")).unwrap(),
        )
        .unwrap();
        let kept = Kept {
            allow_list,
            install_id: self.journal().install_id().to_owned(),
            install_key: index["install_key"].clone(),
        };
        (identity, kept)
    }

    fn journal(&self) -> etd_sysfx_os::service::LifecycleJournal {
        etd_sysfx_os::service::LifecycleJournal::open(&self.layout)
            .unwrap()
            .unwrap()
    }

    /// The CI fault the next upgrade or host start reads (`ci-test-fixtures`).
    fn fault(&self, point: Option<&str>) {
        let path = self.layout.maintenance.join("ci-upgrade-fault");
        match point {
            Some(point) => std::fs::write(path, point).unwrap(),
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn leftovers(&self) -> Vec<std::path::PathBuf> {
        ["prev", "new", "failed"]
            .into_iter()
            .map(|extension| self.layout.executable.with_extension(extension))
            .chain([
                self.layout.maintenance.join("upgrade-manifest.json"),
                self.layout.maintenance.join("upgrade-registration"),
            ])
            .filter(|path| path.exists())
            .collect()
    }

    /// Uninstall with `program` and wait until nothing is left.
    async fn uninstall(&self, program: &std::path::Path) {
        self.fault(None);
        let result = command(program).arg("uninstall").output().unwrap();
        let layout = &self.layout;
        tokio::time::timeout(Duration::from_secs(60), async {
            while layout.state.exists()
                || layout.executable.parent().unwrap().exists()
                || etd_sysfx_os::service::LifecycleJournal::open(layout)
                    .unwrap()
                    .is_some()
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("uninstall did not finish");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

/// This build as a new installation payload in its own directory: a
/// distinct image (appended bytes; on macOS an ad-hoc re-signature, since
/// appended bytes break the code signature) and the bundled kernels.
fn payload(
    binary: &std::path::Path,
    tag: &str,
) -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
    let directory = tempfile::Builder::new()
        .prefix("etd-upgrade-payload-")
        .tempdir()
        .unwrap();
    let image = directory.path().join(binary.file_name().unwrap());
    std::fs::copy(binary, &image).unwrap();
    if cfg!(target_os = "macos") {
        let signed = command("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--identifier"])
            .arg(format!("etd-upgrade-ci-{tag}"))
            .arg(&image)
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
    } else {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&image)
            .unwrap();
        file.write_all(format!("\0etd-upgrade-ci-{tag}").as_bytes())
            .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cores = binary.parent().unwrap().join("cores");
    if cores.is_dir() {
        copy_tree(&cores, &directory.path().join("cores"));
    }
    let bytes = std::fs::read(&image).unwrap();
    assert_ne!(
        bytes,
        std::fs::read(binary).unwrap(),
        "payload image must differ"
    );
    (directory, image, bytes)
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn text(output: &std::process::Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[tokio::test]
#[ignore = "requires a disposable elevated CI runner and ETD_HOST_CI_INSTALL=1"]
async fn upgrade_replaces_the_image_and_keeps_state() {
    if !ci_install_enabled() {
        return;
    }
    let service = Installed::install();
    let (_, before) = service.served().await;
    let (_payload, new_image, bytes) = payload(&service.binary, "a");

    let refused = command(&service.image).arg("upgrade").output().unwrap();
    let upgraded = command(&new_image).arg("upgrade").output().unwrap();
    let again = command(&new_image).arg("upgrade").output().unwrap();
    let (identity, after) = service.served().await;
    let image_after = std::fs::read(&service.layout.executable).unwrap();
    let stage = service.journal().upgrade_stage();
    let leftovers = service.leftovers();

    // Windows: uninstall from the upgraded installed image (deferred removal).
    #[cfg(windows)]
    service.uninstall(&service.image).await;
    #[cfg(unix)]
    service.uninstall(&service.binary).await;

    assert!(!refused.status.success(), "{}", text(&refused));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("payload"),
        "{}",
        text(&refused)
    );
    assert!(upgraded.status.success(), "{}", text(&upgraded));
    println!("{}", String::from_utf8_lossy(&upgraded.stdout).trim());
    assert!(again.status.success(), "{}", text(&again));
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("already up to date"),
        "{}",
        text(&again)
    );
    assert!(image_after == bytes, "installed image is not the payload's");
    assert_eq!(
        identity.exe, service.image,
        "service runs the installed image"
    );
    assert!(leftovers.is_empty(), "upgrade left {leftovers:?}");
    assert_eq!(stage, None);
    assert_eq!(
        after, before,
        "upgrade changed install id, install key or allow list"
    );
    println!(
        "upgrade replaced the image, kept install id, install key and allow list; the second run was a no-op; uninstall clean"
    );
}

#[tokio::test]
#[ignore = "requires a disposable elevated CI runner and ETD_HOST_CI_INSTALL=1"]
async fn upgrade_rolls_back_when_the_new_host_is_not_ready() {
    if !ci_install_enabled() {
        return;
    }
    let service = Installed::install();
    let (_, before) = service.served().await;
    let (_payload, new_image, _) = payload(&service.binary, "unready");
    // The new host refuses to serve; the upgrade must restore the old one.
    service.fault(Some("new-host-unready"));
    let upgraded = command(&new_image).arg("upgrade").output().unwrap();
    service.fault(None);
    let (identity, after) = service.served().await;
    let image_after = std::fs::read(&service.layout.executable).unwrap();
    let stage = service.journal().upgrade_stage();
    let leftovers = service.leftovers();
    service.uninstall(&service.binary).await;

    assert!(!upgraded.status.success(), "{}", text(&upgraded));
    assert!(
        String::from_utf8_lossy(&upgraded.stderr).contains("upgrade rolled back"),
        "{}",
        text(&upgraded)
    );
    println!("{}", String::from_utf8_lossy(&upgraded.stderr).trim());
    assert!(
        image_after == service.original,
        "the previous image was not restored"
    );
    assert_eq!(
        identity.exe, service.image,
        "the previous service runs again"
    );
    assert!(leftovers.is_empty(), "rollback left {leftovers:?}");
    assert_eq!(stage, None);
    assert_eq!(
        after, before,
        "rollback changed install id, install key or allow list"
    );
    println!("a new host that never served was rolled back; the previous service runs; state kept");
}

#[tokio::test]
#[ignore = "requires a disposable elevated CI runner and ETD_HOST_CI_INSTALL=1"]
async fn an_interrupted_upgrade_is_restored_by_upgrade_and_by_uninstall() {
    use etd_sysfx_os::service::UpgradeStage;
    if !ci_install_enabled() {
        return;
    }
    let service = Installed::install();
    let (_, before) = service.served().await;
    let (_first, first_image, first_bytes) = payload(&service.binary, "first");
    let (_second, second_image, _) = payload(&service.binary, "second");

    // Crash with the new image in place and the service disabled.
    service.fault(Some("crash-after-replace"));
    let crashed = command(&first_image).arg("upgrade").output().unwrap();
    service.fault(None);
    let crashed_stage = service.journal().upgrade_stage();
    let backup_kept = service.layout.executable.with_extension("prev").exists();
    let resume = command(&service.binary)
        .arg("resume-service")
        .output()
        .unwrap();
    // The next upgrade restores the old state first, then completes.
    let recovered = command(&first_image).arg("upgrade").output().unwrap();
    let (identity, after) = service.served().await;
    let image_after = std::fs::read(&service.layout.executable).unwrap();
    let stage_after = service.journal().upgrade_stage();
    let leftovers = service.leftovers();
    // Crash again; this time uninstall restores and removes everything.
    service.fault(Some("crash-after-replace"));
    let crashed_again = command(&second_image).arg("upgrade").output().unwrap();
    service.fault(None);
    let crashed_again_stage = service.journal().upgrade_stage();
    service.uninstall(&service.binary).await;

    assert_eq!(crashed.status.code(), Some(86), "{}", text(&crashed));
    assert_eq!(crashed_stage, Some(UpgradeStage::Replacing));
    assert!(backup_kept, "the previous image must be kept until commit");
    assert!(!resume.status.success(), "{}", text(&resume));
    assert!(
        String::from_utf8_lossy(&resume.stderr).contains("upgrade of this service is incomplete"),
        "{}",
        text(&resume)
    );
    assert!(recovered.status.success(), "{}", text(&recovered));
    assert!(
        String::from_utf8_lossy(&recovered.stdout).contains("restoring an interrupted upgrade"),
        "{}",
        text(&recovered)
    );
    assert!(
        image_after == first_bytes,
        "installed image is not the payload's"
    );
    assert_eq!(identity.exe, service.image);
    assert_eq!(stage_after, None);
    assert!(leftovers.is_empty(), "upgrade left {leftovers:?}");
    assert_eq!(
        after, before,
        "recovery changed install id, install key or allow list"
    );
    assert_eq!(
        crashed_again.status.code(),
        Some(86),
        "{}",
        text(&crashed_again)
    );
    assert_eq!(crashed_again_stage, Some(UpgradeStage::Replacing));
    println!(
        "an upgrade interrupted at Replacing was refused by resume-service, restored by the next upgrade, and by uninstall"
    );
}
