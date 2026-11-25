mod common;
use common::*;
use etd_ipc::{Connector, Endpoint};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

#[tokio::test]
async fn impostor_process() {
    let Some(arg) = std::env::var_os("ETD_TEST_IMPOSTOR_SOCKET") else {
        return;
    };
    let ep = from_arg(arg.into());
    #[cfg(unix)]
    let mut pipe = {
        let Endpoint::UnixSocket(p) = ep else {
            unreachable!()
        };
        let listener = tokio::net::UnixListener::bind(p).unwrap();
        println!("listening");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        listener.accept().await.unwrap().0
    };
    #[cfg(windows)]
    let mut pipe = {
        let Endpoint::NamedPipe(name) = ep else {
            unreachable!()
        };
        let pipe = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(name)
            .unwrap();
        println!("listening");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        pipe.connect().await.unwrap();
        pipe
    };
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty(), "client sent bytes to unverified endpoint");
}

#[tokio::test]
async fn rejects_another_process_before_writing() {
    if !run_as_host("rejects_another_process_before_writing") {
        return;
    }
    let f = Fixture::new();
    let decoy = f
        .dir
        .path()
        .join(format!("impostor{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(std::env::current_exe().unwrap(), &decoy).unwrap();
    let mut child = Command::new(decoy)
        .args(["--exact", "impostor_process", "--nocapture"])
        .env("ETD_TEST_IMPOSTOR_SOCKET", endpoint_arg(&f.ep))
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stdout.read_line(&mut line)
            )
            .await
            .unwrap()
            .unwrap(),
            0,
            "child exited before bind"
        );
        if line.contains("listening") {
            break;
        }
    }
    let mut expected = connector();
    // On old Linux, a matching uid inside its 0700 runtime directory is
    // the full identity proof. Exercise the account mismatch on that kernel.
    if !verifies_user_image() {
        expected.expectation.user = Some(etd_ipc::OsUserId::UnixUid(u32::MAX));
    }
    let result = expected.connect(&f.ep).await;
    assert_eq!(
        result.err().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
