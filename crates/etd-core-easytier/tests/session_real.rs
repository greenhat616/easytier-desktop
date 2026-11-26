//! Opt-in check against the pinned native binary (not the portable library).
//! Set ETD_EASYTIER_CORE to the absolute path of the bundled release kernel
//! (`cargo xtask fetch-cores --target host`); CI runs this on all three OSes.
#[path = "plan_fixtures.rs"]
mod fixtures;

use etd_contract::{QueryKind, v1::query_response::Result as QueryResult};
use etd_core_api::CoreDriver;
use etd_core_easytier::EasyTierDriver;
use std::{
    net::TcpListener,
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::process::Command;

#[tokio::test]
#[ignore = "requires ETD_EASYTIER_CORE pointing to the pinned native kernel"]
async fn real_kernel_identify_launch_ready_query() {
    let binary = PathBuf::from(
        std::env::var_os("ETD_EASYTIER_CORE")
            .expect("set ETD_EASYTIER_CORE to the pinned native binary"),
    );
    assert!(binary.is_absolute() && binary.is_file());
    let driver = EasyTierDriver;
    let descriptor = driver.identify(&binary).await.unwrap();
    let profile = driver
        .profile(&descriptor)
        .expect("kernel revision must match the adapter");
    let temp = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0").unwrap();
    let management = port.local_addr().unwrap();
    let mut spec = fixtures::basic();
    spec.peers.clear();
    spec.no_listener = true;
    spec.no_tun = true;
    let mut ctx = fixtures::user_ctx(spec);
    ctx.inputs.runtime_dir = temp.path().to_owned();
    ctx.inputs.management = management;
    ctx.inputs.core.binary = binary;
    ctx.inputs.core.version = descriptor.version.clone();
    ctx.inputs.core.proto_revision = descriptor.proto_revision.clone();
    ctx.inputs.core.profile = Some(profile.id);
    let plan = driver.plan_launch(&ctx).unwrap();
    for file in plan.files {
        std::fs::write(file.path, file.contents).unwrap();
    }
    let mut command = Command::new(plan.command.executable);
    command
        .args(plan.command.args)
        .current_dir(temp.path())
        .env_clear()
        .envs(plan.command.env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    #[cfg(windows)]
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    drop(port);
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let session = loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "kernel exited before management was ready"
        );
        if let Ok(session) = driver.attach(&plan.endpoint, &descriptor).await {
            break session;
        }
        assert!(Instant::now() < deadline, "management attachment timed out");
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let info = session.wait_ready(deadline).await.unwrap();
    assert_eq!(info.hostname.as_deref(), Some("laptop"));
    let QueryResult::Nodes(nodes) = session
        .query(QueryKind::Nodes)
        .await
        .unwrap()
        .result
        .unwrap()
    else {
        panic!("expected nodes");
    };
    assert!(
        nodes
            .nodes
            .iter()
            .any(|n| n.is_self && Some(n.peer_id) == info.peer_id)
    );
    assert!(matches!(
        session.query(QueryKind::Routes).await.unwrap().result,
        Some(QueryResult::Routes(_))
    ));
    assert!(matches!(
        session.query(QueryKind::Traffic).await.unwrap().result,
        Some(QueryResult::Traffic(_))
    ));
    session.poll_events(None).await.unwrap();
    drop(session);
    child.kill().await.unwrap();
}
