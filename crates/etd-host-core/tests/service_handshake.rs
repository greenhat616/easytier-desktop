mod common;
use common::*;
use etd_contract::*;
use etd_host_core::stub::host_service_server::HostService;
#[tokio::test]
async fn handshake_role_capabilities_and_major() {
    let f = Fixture::new().await;
    let hello = Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    };
    let welcome = f
        .service
        .handshake(request(hello.clone(), Role::Viewer))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(welcome.role(), Role::Viewer);
    assert!(
        welcome
            .capabilities
            .contains(&capability::INSTANCES.to_owned())
    );
    assert!(!welcome.stream_id.is_empty());
    let wrong = Hello {
        major: VERSION_MAJOR + 1,
        ..hello
    };
    assert_eq!(
        code(
            f.service
                .handshake(request(wrong, Role::Viewer))
                .await
                .unwrap_err()
        ),
        ErrorCode::VersionMismatch
    );
}

// In-process gRPC transport: the generated server receives HTTP/gRPC frames,
// decodes protobuf and emits gRPC status/details. Only IPC identity insertion
// is substituted; I1's real duplex adapter is tested by its own package.
#[tokio::test]
async fn generated_server_in_memory_grpc_roundtrip() {
    use etd_host_core::{
        negotiate::VersionInterceptor, service::ContractService,
        stub::host_service_server::HostServiceServer,
    };
    use etd_ipc::PeerIdentity;
    use std::task::{Context, Poll};
    use tonic::{
        body::Body,
        client::Grpc,
        codegen::{Service, http},
    };
    struct PeerServer<S> {
        server: S,
        peer: PeerIdentity,
    }
    impl<S> Service<http::Request<Body>> for PeerServer<S>
    where
        S: Service<http::Request<Body>>,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = S::Future;
        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.server.poll_ready(cx)
        }
        fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
            request.extensions_mut().insert(self.peer.clone());
            self.server.call(request)
        }
    }
    let f = Fixture::new().await;
    let server =
        HostServiceServer::<ContractService>::with_interceptor(f.service, VersionInterceptor);
    let mut client = Grpc::new(PeerServer {
        server,
        peer: peer(Role::Viewer),
    });
    client.ready().await.unwrap();
    let path = http::uri::PathAndQuery::from_static("/etd.v1.HostService/Handshake");
    let mut req = tonic::Request::new(Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    });
    req.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    let response: tonic::Response<Welcome> = client
        .unary(req, path.clone(), tonic_prost::ProstCodec::default())
        .await
        .unwrap();
    assert_eq!(response.into_inner().role(), Role::Viewer);
    let missing = tonic::Request::new(Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    });
    client.ready().await.unwrap();
    let result: Result<tonic::Response<Welcome>, _> = client
        .unary(missing, path, tonic_prost::ProstCodec::default())
        .await;
    assert_eq!(code(result.unwrap_err()), ErrorCode::VersionMetadata);
}

#[tokio::test]
async fn tonic_duplex_preserves_os_connect_info_and_checks_version() {
    use etd_host_core::{
        negotiate::VersionInterceptor, stub::host_service_server::HostServiceServer,
    };
    use etd_ipc::PeerIdentity;
    use futures_util::StreamExt;
    use hyper_util::rt::TokioIo;
    use std::{
        future::{Ready, ready},
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tonic::{
        client::Grpc,
        codegen::{Service, http},
        transport::{Endpoint, Server, server::Connected},
    };

    struct ServerIo {
        stream: DuplexStream,
        peer: PeerIdentity,
    }
    impl Connected for ServerIo {
        type ConnectInfo = PeerIdentity;
        fn connect_info(&self) -> PeerIdentity {
            self.peer.clone()
        }
    }
    impl AsyncRead for ServerIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for ServerIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }
    struct Connector(Option<DuplexStream>);
    impl Service<http::Uri> for Connector {
        type Response = TokioIo<DuplexStream>;
        type Error = io::Error;
        type Future = Ready<Result<Self::Response, Self::Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: http::Uri) -> Self::Future {
            ready(self.0.take().map(TokioIo::new).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "duplex connection already taken",
                )
            }))
        }
    }
    let f = Fixture::new().await;
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (shutdown, terminated) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        Server::builder()
            .add_service(HostServiceServer::with_interceptor(
                f.service.clone(),
                VersionInterceptor,
            ))
            .serve_with_incoming_shutdown(
                futures_util::stream::once(async move {
                    Ok::<_, io::Error>(ServerIo {
                        stream: server_stream,
                        peer: peer(Role::Viewer),
                    })
                })
                .chain(futures_util::stream::pending()),
                async {
                    let _ = terminated.await;
                },
            ),
    );
    let channel = Endpoint::from_static("http://[::1]:50051")
        .connect_with_connector(Connector(Some(client_stream)))
        .await
        .unwrap();
    let mut client = Grpc::new(channel);
    client.ready().await.unwrap();
    let path = http::uri::PathAndQuery::from_static("/etd.v1.HostService/Handshake");
    // The client supplies no peer extension. The accepted stream supplies it.
    let mut req = tonic::Request::new(Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    });
    req.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    let response: tonic::Response<Welcome> = client
        .unary(req, path.clone(), tonic_prost::ProstCodec::default())
        .await
        .unwrap();
    assert_eq!(response.into_inner().role(), Role::Viewer);
    let req = tonic::Request::new(Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    });
    client.ready().await.unwrap();
    let result: Result<tonic::Response<Welcome>, _> = client
        .unary(req, path, tonic_prost::ProstCodec::default())
        .await;
    assert_eq!(code(result.unwrap_err()), ErrorCode::VersionMetadata);
    drop(client);
    let _ = shutdown.send(());
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
