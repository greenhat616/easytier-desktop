//! Native desktop peer used by the crash test. No product dependencies are replaced.
use etd_client::stub::host_service_client::HostServiceClient;
use etd_contract::{
    VERSION_MAJOR, VERSION_METADATA_KEY, VERSION_MINOR,
    v1::{
        ApplyRequest, ClientKind, Desired, GetReceiptRequest, Hello, HostMode, MutationHeader,
        NetworkFlags, NetworkSpec, StreamLogsRequest, network_spec::Ipv4,
    },
    version_metadata_value,
};
use etd_ipc::{
    Endpoint, ServerExpectation, ServerRequirement, platform::LocalConnector, tonic_io::ClientIo,
};
use serde_json::json;
use std::{env, fs, path::PathBuf, sync::Arc};

fn request<T>(body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    request
}

// Invoked directly by the test binary. Ordinary nextest discovery does no IO.
#[tokio::test]
async fn peer() -> anyhow::Result<()> {
    let Ok(action) = env::var("ETD_G2_DESKTOP") else {
        return Ok(());
    };
    super::require_runner();
    // ETD_G2_SESSION_DIR: talk to the elevated session host run from that
    // directory (this image copied there as etd-ui.exe holds its lease).
    let session = env::var_os("ETD_G2_SESSION_DIR").map(PathBuf::from);
    let (expectation, endpoint, mode) = match session {
        #[cfg(windows)]
        Some(dir) => {
            let etd_ipc::OsUserId::WindowsSid(sid) = etd_ipc::platform::current_user()? else {
                anyhow::bail!("unexpected kind of user id");
            };
            (
                ServerExpectation {
                    exe_dir: dir,
                    requirement: ServerRequirement::CurrentUserElevated,
                },
                Endpoint::NamedPipe(format!(r"\\.\pipe\easytier-desk-session-{sid}")),
                HostMode::ElevatedSession,
            )
        }
        #[cfg(unix)]
        Some(_) => anyhow::bail!("the elevated session host is Windows-only"),
        None => (
            ServerExpectation {
                exe_dir: etd_sysfx_os::service::installed_host_dir()?,
                requirement: ServerRequirement::Service,
            },
            #[cfg(windows)]
            Endpoint::NamedPipe(etd_ipc::SERVICE_PIPE_NAME.into()),
            #[cfg(unix)]
            Endpoint::UnixSocket(etd_ipc::SERVICE_SOCKET_PATH.into()),
            HostMode::Service,
        ),
    };
    let connector = Arc::new(LocalConnector { expectation });
    // A session host started just before this peer publishes its pipe only
    // after its start-up checks: keep trying for a minute, like the UI.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let channel = loop {
        let attempt = tonic::transport::Endpoint::from_static("http://localhost")
            .connect_with_connector(ClientIo::new(connector.clone(), endpoint.clone()))
            .await;
        match attempt {
            Ok(channel) => break channel,
            Err(error)
                if mode != HostMode::ElevatedSession || std::time::Instant::now() >= deadline =>
            {
                return Err(error.into());
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    };
    let mut client = HostServiceClient::new(channel);
    let hello = client
        .handshake(request(Hello {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            client_kind: ClientKind::Desktop as i32,
            ..Default::default()
        }))
        .await?
        .into_inner();
    assert_eq!(hello.host_mode(), mode);
    let instance = env::var("ETD_G2_INSTANCE")?;
    let tag = env::var("ETD_G2_REQUEST")?;
    let reply = PathBuf::from(env::var_os("ETD_G2_REPLY").unwrap());
    let receipt = match action.as_str() {
        "apply" | "replay" => {
            let apply = ApplyRequest {
                header: Some(MutationHeader {
                    request_id: tag,
                    expected_revision: env::var("ETD_G2_REVISION")?.parse()?,
                }),
                instance_id: instance.clone(),
                spec: Some(NetworkSpec {
                    display_name: "G2".into(),
                    network_name: "g2-ci".into(),
                    network_secret: Some(format!("g2-log-probe-{instance}")),
                    ipv4: Some(Ipv4::Ipv4Cidr("192.0.2.41/28".into())),
                    no_listener: true,
                    flags: Some(NetworkFlags {
                        disable_ipv6: true,
                        disable_udp_hole_punching: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                desired: Desired::Running as i32,
            };
            let result = client.apply(request(apply)).await?.into_inner();
            if action == "apply" {
                // The parent sees the durable commit independently and kills
                // this client. It never receives a receipt from this process.
                std::future::pending::<()>().await;
            }
            result.receipt
        }
        "receipt" => {
            client
                .get_receipt(request(GetReceiptRequest { request_id: tag }))
                .await?
                .into_inner()
                .receipt
        }
        "logs" => {
            let mut lines = client
                .stream_logs(request(StreamLogsRequest {
                    instance_id: instance.clone(),
                    tail_lines: 1000,
                    follow: false,
                }))
                .await?
                .into_inner();
            let mut core_lines = 0;
            while let Some(line) = lines.message().await? {
                assert!(
                    !line.text.contains(&format!("g2-log-probe-{instance}")),
                    "unredacted native log line"
                );
                if matches!(
                    line.source(),
                    etd_contract::v1::LogSource::CoreStdout
                        | etd_contract::v1::LogSource::CoreStderr
                ) {
                    core_lines += 1;
                }
            }
            assert!(core_lines > 0, "no real kernel logs received");
            fs::write(reply, core_lines.to_string())?;
            return Ok(());
        }
        "hold" => {
            fs::write(reply, "connected")?;
            std::future::pending::<()>().await;
            return Ok(());
        }
        _ => anyhow::bail!("unknown desktop test operation"),
    }
    .expect("durable receipt");
    fs::write(
        reply,
        serde_json::to_vec(&json!({
            "request_id":receipt.request_id, "ticket":receipt.ticket,
            "revision":receipt.revision, "accepted_unix_ms":receipt.accepted_unix_ms
        }))?,
    )?;
    Ok(())
}
