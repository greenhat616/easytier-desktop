//! The UI side of the elevated session pipe: `CurrentUserElevated` accepts
//! only the current user's elevated etd-host and writes nothing to anything
//! else (ES1). The unreadable-token case is a unit test of the seam
//! `elevated_session_peer` in `platform::windows::identity`.
#![cfg(windows)]
mod common;
#[path = "session_support/mod.rs"]
mod session_support;
use common::*;
use etd_ipc::{
    Connector, HostForm, ListenerPolicy, ServerExpectation, ServerRequirement,
    platform::{LocalConnector, LocalListener, current_user},
    tonic_io::{ClientIo, incoming},
};
use session_support::*;
use std::{
    io::{BufRead, BufReader, ErrorKind},
    sync::Arc,
};
use tokio::io::AsyncReadExt;

fn elevated_connector() -> LocalConnector {
    LocalConnector {
        expectation: ServerExpectation {
            exe_dir: std::env::current_exe().unwrap().parent().unwrap().into(),
            requirement: ServerRequirement::CurrentUserElevated,
        },
    }
}

fn session_listener(f: &Fixture) -> LocalListener {
    LocalListener::bind(HostForm::ElevatedSession, &f.ep, &ListenerPolicy::default()).unwrap()
}

#[tokio::test]
#[ignore = "Windows administrator CI runner: elevated runner token"]
async fn genuine_elevated_host_is_accepted() {
    if !run_as_host("genuine_elevated_host_is_accepted") {
        return;
    }
    let f = Fixture::new();
    let _listener = session_listener(&f);
    let (_conn, server) = elevated_connector().connect(&f.ep).await.unwrap();
    assert_eq!(server.peer.user, current_user().unwrap());
    assert!(server.peer.elevated);
    assert_eq!(server.peer.pid, std::process::id());
    assert_eq!(
        server.exe,
        std::env::current_exe().unwrap().canonicalize().unwrap()
    );
}

/// The production case: a non-elevated Medium UI of the same account
/// inspects the elevated host (process, image, token) and accepts it.
#[tokio::test]
#[ignore = "Windows administrator CI runner: restricted token copy of the runner"]
async fn medium_ui_accepts_the_genuine_elevated_host() {
    if !run_as_host("medium_ui_accepts_the_genuine_elevated_host") {
        return;
    }
    let f = Fixture::new();
    let _listener = session_listener(&f);
    let server = connect_as(restricted_token(MEDIUM), elevated_connector(), f.ep.clone())
        .expect("a Medium UI must be able to verify the elevated host");
    assert_eq!(server.peer.user, current_user().unwrap());
    assert!(server.peer.elevated);
    assert_eq!(server.peer.pid, std::process::id());
}

#[tokio::test]
#[ignore = "Windows administrator CI runner: elevated runner token"]
async fn handshake_round_trip_over_the_session_pipe() {
    if !run_as_host("handshake_round_trip_over_the_session_pipe") {
        return;
    }
    let f = Fixture::new();
    let listener = session_listener(&f);
    let host = etd_testkit::transport::user_host(current_user().unwrap()).await;
    let (quiesce, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(host)
            .serve_with_incoming_shutdown(incoming(listener), async {
                let _ = shutdown.await;
            }),
    );
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(ClientIo::new(Arc::new(elevated_connector()), f.ep.clone()))
        .await
        .unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
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

const SQUAT: &str = "ETD_TEST_SESSION_SQUAT";
const LIVE: &str = "ETD_TEST_SESSION_LIVE";

/// Child side of `non_elevated_squatter_is_refused_before_any_write`, run
/// from the same etd-host image the client trusts, with a copy of the
/// runner's token lowered to Medium: it still reports `TokenElevation`, so
/// only the integrity rule tells it apart from the genuine host. A token
/// without `TokenElevation` is covered by the unit tests of
/// `elevated_session_peer`.
#[tokio::test]
async fn session_squatter_process() {
    let (Some(squat), Some(live)) = (std::env::var_os(SQUAT), std::env::var_os(LIVE)) else {
        return;
    };
    use tokio::net::windows::named_pipe::ServerOptions;
    // Another process cannot take the name of a live session pipe. (This
    // token keeps Administrators enabled, so it may add instances; the
    // deny-only Medium copy cannot, see `session_pipe_acl`.)
    assert!(
        ServerOptions::new()
            .first_pipe_instance(true)
            .create(&live)
            .is_err()
    );
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&squat)
        .unwrap();
    println!("listening");
    pipe.connect().await.unwrap();
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).await.unwrap();
    assert!(
        bytes.is_empty(),
        "client wrote {bytes:?} to a non-elevated host"
    );
    println!("read 0 bytes");
}

#[tokio::test]
#[ignore = "Windows administrator CI runner: restricted token child process"]
async fn non_elevated_squatter_is_refused_before_any_write() {
    if !run_as_host("non_elevated_squatter_is_refused_before_any_write") {
        return;
    }
    let live = Fixture::new();
    let _listener = session_listener(&live);
    let squat = Fixture::new();
    let exe = std::env::current_exe().unwrap();
    let mut child = Child::spawn(
        &lowered_token(MEDIUM),
        &exe,
        &[
            "--include-ignored",
            "--exact",
            "session_squatter_process",
            "--nocapture",
        ],
        &[
            (SQUAT, endpoint_arg(&squat.ep).as_os_str()),
            (LIVE, endpoint_arg(&live.ep).as_os_str()),
        ],
    );
    let output = child.output();
    let (ready, seen, rest) = tokio::task::spawn_blocking(move || {
        let mut lines = BufReader::new(output).lines();
        let mut seen = Vec::new();
        for line in lines.by_ref() {
            let line = line.unwrap();
            let ready = line.contains("listening");
            seen.push(line);
            if ready {
                return (true, seen, lines);
            }
        }
        (false, seen, lines)
    })
    .await
    .unwrap();
    if !ready {
        let code = tokio::task::spawn_blocking(move || child.wait())
            .await
            .unwrap();
        panic!(
            "squatter exited with {code:#x} before listening:
{}",
            seen.join(
                "
"
            )
        );
    }

    // The squatter runs the trusted image as the same user; only the
    // missing elevation identifies it. The client is a Medium UI.
    let error = connect_as(
        restricted_token(MEDIUM),
        elevated_connector(),
        squat.ep.clone(),
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("not elevated"), "{error}");

    let log = tokio::task::spawn_blocking(move || {
        rest.map(|line| line.unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    })
    .await
    .unwrap();
    let code = tokio::task::spawn_blocking(move || child.wait())
        .await
        .unwrap();
    assert_eq!(code, 0, "squatter failed:\n{log}");
    assert!(log.contains("read 0 bytes"), "{log}");
}
