//! In-process stub over a real loopback TCP socket. The library's separate
//! ring-tunnel tests exercise the same RPC methods with no OS sockets.
mod session_support;

use easytier_core::tunnel::{
    SplitTunnel, Tunnel,
    framed::{FramedReader, FramedWriter, TCP_MTU_BYTES},
};
use easytier_proto::common::TunnelInfo;
use etd_contract::{QueryKind, v1::query_response::Result as QueryResult};
use etd_core_api::{CoreDescriptor, CoreDriver, CoreEndpoint, CoreError};
use etd_core_easytier::EasyTierDriver;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

struct ServerTunnel(Mutex<Option<TcpStream>>);
impl Tunnel for ServerTunnel {
    fn split(&self) -> SplitTunnel {
        let (reader, writer) = self.0.lock().unwrap().take().unwrap().into_split();
        (
            Box::pin(FramedReader::new(reader, TCP_MTU_BYTES)),
            Box::pin(FramedWriter::new(writer)),
        )
    }
    fn info(&self) -> Option<TunnelInfo> {
        None
    }
}

fn descriptor() -> CoreDescriptor {
    CoreDescriptor {
        version: "2.7.1".into(),
        proto_revision: "c97f36b8".into(),
    }
}

#[tokio::test]
async fn attach_tcp_ready_queries_events() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = CoreEndpoint(listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        session_support::server(
            vec![Uuid::from_u128(1)],
            Box::new(ServerTunnel(Mutex::new(Some(socket)))),
        )
    });
    let session = EasyTierDriver
        .attach(&endpoint, &descriptor())
        .await
        .unwrap();
    let (_server, _snapshot) = server.await.unwrap();
    let ready = session
        .wait_ready(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(ready.interface_name.as_deref(), Some("utun7"));
    assert!(matches!(
        session.query(QueryKind::Nodes).await.unwrap().result,
        Some(QueryResult::Nodes(_))
    ));
    assert!(matches!(
        session.query(QueryKind::Routes).await.unwrap().result,
        Some(QueryResult::Routes(_))
    ));
    assert!(matches!(
        session.query(QueryKind::Traffic).await.unwrap().result,
        Some(QueryResult::Traffic(_))
    ));
    assert_eq!(session.poll_events(None).await.unwrap().len(), 2);
}

#[tokio::test]
async fn rejects_unknown_profile_and_non_loopback_without_dialing() {
    let endpoint = CoreEndpoint("127.0.0.1:1".parse().unwrap());
    let unknown = CoreDescriptor {
        proto_revision: "0000000".into(),
        ..descriptor()
    };
    assert!(matches!(
        EasyTierDriver.attach(&endpoint, &unknown).await,
        Err(CoreError::NoProfile { .. })
    ));
    let endpoint = CoreEndpoint("192.0.2.1:1".parse().unwrap());
    assert!(matches!(
        EasyTierDriver.attach(&endpoint, &descriptor()).await,
        Err(CoreError::Connect(_))
    ));
}
