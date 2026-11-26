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
use etd_ipc::{Endpoint, ServerExpectation, platform::LocalConnector, tonic_io::ClientIo};
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
    assert_eq!(
        env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    assert_eq!(env::var("ETD_G2_CI").as_deref(), Ok("1"));
    let connector = Arc::new(LocalConnector {
        expectation: ServerExpectation {
            exe_dir: etd_sysfx_os::service::installed_host_dir()?,
            user: None,
            privileged: true,
        },
    });
    #[cfg(windows)]
    let endpoint = Endpoint::NamedPipe(etd_ipc::SERVICE_PIPE_NAME.into());
    #[cfg(unix)]
    let endpoint = Endpoint::UnixSocket(etd_ipc::SERVICE_SOCKET_PATH.into());
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(ClientIo::new(connector, endpoint))
        .await?;
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
    assert_eq!(hello.host_mode(), HostMode::Service);
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
