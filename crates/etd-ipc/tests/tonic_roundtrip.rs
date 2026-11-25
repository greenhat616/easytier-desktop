mod common;
use common::*;
use etd_ipc::{
    platform::current_user,
    tonic_io::{ClientIo, incoming},
};
use std::sync::Arc;
use tonic::{
    client::Grpc,
    transport::{Endpoint, Server},
};

#[tokio::test]
async fn handshake_uses_native_connect_info() {
    if !run_as_host("handshake_uses_native_connect_info") {
        return;
    }
    let f = Fixture::new();
    let listener = f.listener();
    let host = etd_testkit::transport::user_host(current_user().unwrap()).await;
    let (quiesce, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        Server::builder()
            .add_service(host)
            .serve_with_incoming_shutdown(incoming(listener), async {
                let _ = shutdown.await;
            }),
    );
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(ClientIo::new(Arc::new(connector()), f.ep))
        .await
        .unwrap();
    let mut grpc = Grpc::new(channel);
    grpc.ready().await.unwrap();
    let mut hello = tonic::Request::new(etd_contract::Hello {
        major: etd_contract::VERSION_MAJOR,
        minor: etd_contract::VERSION_MINOR,
        ..Default::default()
    });
    hello.metadata_mut().insert(
        etd_contract::VERSION_METADATA_KEY,
        etd_contract::version_metadata_value().parse().unwrap(),
    );
    let welcome: tonic::Response<etd_contract::Welcome> = grpc
        .unary(
            hello,
            tonic::codegen::http::uri::PathAndQuery::from_static("/etd.v1.HostService/Handshake"),
            tonic_prost::ProstCodec::default(),
        )
        .await
        .unwrap();
    assert_eq!(welcome.into_inner().role(), etd_contract::Role::Admin);
    drop(grpc);
    quiesce.send(()).unwrap();
    server.await.unwrap().unwrap();
}
