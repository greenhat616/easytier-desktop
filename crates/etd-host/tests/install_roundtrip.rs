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

/// Wait for the installed service to answer, then read its allow list.
async fn served_allow_list(
    connector: &Arc<LocalConnector>,
    endpoint: &Endpoint,
) -> (
    etd_ipc::ServerIdentity,
    etd_contract::v1::GetAllowListResponse,
) {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Ok((connection, identity)) = connector.connect(endpoint).await {
                drop(connection);
                if let Ok(list) = admin_allow_list(connector.clone(), endpoint.clone()).await {
                    break (identity, list);
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("installed service never answered GetAllowList")
}

fn install_key(layout: &etd_sysfx_os::service::HostLayout) -> serde_json::Value {
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout.state.join("repair-index.json")).unwrap())
            .unwrap();
    index["install_key"].clone()
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

#[tokio::test]
#[ignore = "requires a disposable elevated CI runner and ETD_HOST_CI_INSTALL=1"]
async fn upgrade_replaces_the_image_and_keeps_state() {
    use etd_sysfx_os::service::LifecycleJournal;
    use std::path::Path;
    if std::env::var("ETD_HOST_CI_INSTALL").as_deref() != Ok("1")
        || std::env::var("CI").as_deref() != Ok("true")
    {
        eprintln!("skipped: privileged service upgrade is CI-only");
        return;
    }
    assert!(NativeServiceManager.entry_is_elevated().unwrap());
    let binary = Path::new(env!("CARGO_BIN_EXE_etd-host"));
    let layout = NativeHostFilesystem.service_layout().unwrap();
    assert!(!layout.state.exists() && !layout.executable.exists());
    let installed = command(binary).arg("install").output().unwrap();
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
    let (_, allow_before) = served_allow_list(&connector, &endpoint).await;
    let install_id = LifecycleJournal::open(&layout)
        .unwrap()
        .unwrap()
        .install_id()
        .to_owned();
    let key_before = install_key(&layout);
    let image = layout.executable.canonicalize().unwrap();

    // A payload directory like the MSI / package one: this build, with a
    // distinct image (loaders ignore appended bytes; macOS would reject
    // them as a broken code signature) and its bundled kernels.
    let payload = tempfile::Builder::new()
        .prefix("etd-upgrade-payload-")
        .tempdir()
        .unwrap();
    let new_image = payload.path().join(binary.file_name().unwrap());
    let mut bytes = std::fs::read(binary).unwrap();
    let distinct = cfg!(not(target_os = "macos"));
    if distinct {
        bytes.extend_from_slice(b"\0etd-upgrade-ci-payload");
    }
    std::fs::write(&new_image, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_image, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cores = binary.parent().unwrap().join("cores");
    if cores.is_dir() {
        copy_tree(&cores, &payload.path().join("cores"));
    }

    let refused = command(&image).arg("upgrade").output().unwrap();
    let upgraded = command(&new_image).arg("upgrade").output().unwrap();
    let again = command(&new_image).arg("upgrade").output().unwrap();
    let (identity, allow_after) = served_allow_list(&connector, &endpoint).await;
    let image_after = std::fs::read(&layout.executable).unwrap();
    let journal = LifecycleJournal::open(&layout).unwrap().unwrap();
    let key_after = install_key(&layout);
    let leftovers: Vec<_> = ["prev", "new", "failed"]
        .into_iter()
        .map(|extension| layout.executable.with_extension(extension))
        .chain([layout.maintenance.join("upgrade-manifest.json")])
        .filter(|path| path.exists())
        .collect();

    // Clean up before asserting.
    #[cfg(windows)]
    let cleanup = command(&image).arg("uninstall").output().unwrap();
    #[cfg(unix)]
    let cleanup = command(binary).arg("uninstall").output().unwrap();
    tokio::time::timeout(Duration::from_secs(45), async {
        while layout.state.exists()
            || layout.executable.parent().unwrap().exists()
            || LifecycleJournal::open(&layout).unwrap().is_some()
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("uninstall after upgrade did not finish");
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
    );

    assert!(
        !refused.status.success(),
        "upgrade from the installed image"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("payload"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        upgraded.status.success(),
        "{}{}",
        String::from_utf8_lossy(&upgraded.stdout),
        String::from_utf8_lossy(&upgraded.stderr)
    );
    println!("{}", String::from_utf8_lossy(&upgraded.stdout).trim());
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("already up to date"),
        "{}",
        String::from_utf8_lossy(&again.stdout)
    );
    assert!(image_after == bytes, "installed image is not the payload's");
    assert_eq!(identity.exe, image, "service runs the installed image");
    assert!(leftovers.is_empty(), "upgrade left {leftovers:?}");
    assert_eq!(journal.install_id(), install_id);
    assert!(!journal.upgrading());
    assert_eq!(key_after, key_before, "install key changed");
    assert_eq!(allow_after, allow_before, "allow list changed");
    println!(
        "upgrade {} the image, kept install id, install key and allow list; the second run was a no-op; uninstall clean",
        if distinct {
            "replaced"
        } else {
            "kept (identical on macOS)"
        }
    );
}
