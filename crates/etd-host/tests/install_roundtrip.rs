//! Only the dedicated, elevated CI job may install a machine-wide service.
use etd_client::stub::host_service_client::HostServiceClient;
use etd_contract::{
    VERSION_MAJOR, VERSION_METADATA_KEY, VERSION_MINOR,
    v1::{Hello, HostMode, HostPhase, Role, SnapshotRequest},
    version_metadata_value,
};
use etd_ipc::{
    Connector, Endpoint, ServerExpectation, platform::LocalConnector, tonic_io::ClientIo,
};
use etd_sysfx_os::service::{
    HostFilesystem, NativeHostFilesystem, NativeServiceManager, ServiceManager,
};
use std::{process::Command, sync::Arc, time::Duration};

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
    let result = Command::new(binary).arg("install").output().unwrap();
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
    let handshake = tokio::time::timeout(Duration::from_secs(30), async {
        let channel = tonic::transport::Endpoint::from_static("http://localhost")
            .connect_with_connector(ClientIo::new(connector, endpoint.clone()))
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
            if snapshot.phase() == HostPhase::Serving {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, Box<dyn std::error::Error>>(welcome)
    })
    .await;
    let cleanup = Command::new(binary).arg("uninstall").output().unwrap();
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
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
        Command::new("sc.exe")
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
}
