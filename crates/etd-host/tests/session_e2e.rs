//! The elevated session host end to end, on the elevated Windows CI runner
//! only (an administrator token, not SYSTEM). Machine-wide state: every
//! stage runs in one test, in order.
#![cfg(windows)]

use etd_client::stub::host_service_client::HostServiceClient;
use etd_contract::{
    Desired, VERSION_MAJOR, VERSION_METADATA_KEY, VERSION_MINOR, capability,
    v1::{Hello, HostMode, LeaseRelease, ReleaseLeaseRequest, Role},
    version_metadata_value,
};
use etd_ipc::{
    Endpoint, OsUserId, ServerExpectation, ServerRequirement,
    platform::{LocalConnector, current_user},
    tonic_io::ClientIo,
};
use etd_sysfx::{
    BootId, EffectIntent, EffectKind, EffectScope, Ledger, ObjectKey, Persistence, Undo,
    sqlite::SqliteLedger,
};
use etd_sysfx_os::service::{HostFilesystem, NativeHostFilesystem, session_root};
use etd_testkit::{
    conformance::ledger::{changes, plan, put},
    no_window::NoWindow,
};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

const EXIT_SERVICE_INSTALLED: i32 = 3;
const EXIT_NOT_CONFORMING: i32 = 4;
const EXIT_OTHER_USERS_LEFTOVERS: i32 = 5;
/// Not a real account: a second user's session root made by the test.
const OTHER_SID: &str = "S-1-5-21-1000-2000-3000-1999";
const PLANTED_INSTANCE: &str = "0f661e50-b9a6-4525-9583-9538fe01e928";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_etd-host"))
}

fn host(args: &[&str]) -> Command {
    let mut command = Command::new(binary());
    command.no_window().args(args);
    command
}

fn output(args: &[&str]) -> Output {
    host(args).output().unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn sc(args: &[&str]) -> Output {
    let mut command = Command::new(r"C:\Windows\System32\sc.exe");
    command.no_window().args(args);
    command.output().unwrap()
}

fn sid() -> String {
    match current_user().unwrap() {
        OsUserId::WindowsSid(sid) => sid,
        other => panic!("{other:?}"),
    }
}

fn program_data() -> PathBuf {
    session_root().unwrap().parent().unwrap().to_owned()
}

fn refused(code: i32) {
    let result = output(&["run", "--mode", "elevated-session"]);
    assert_eq!(result.status.code(), Some(code), "{}", text(&result));
}

fn tree(path: &Path) -> Vec<PathBuf> {
    let mut entries = vec![path.to_owned()];
    if path.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            entries.extend(tree(&entry.unwrap().path()));
        }
    }
    entries.sort();
    entries
}

fn connector() -> Arc<LocalConnector> {
    Arc::new(LocalConnector {
        expectation: ServerExpectation {
            exe_dir: binary().parent().unwrap().to_owned(),
            requirement: ServerRequirement::CurrentUserElevated,
        },
    })
}

fn request<T>(body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    request
}

async fn client(endpoint: &Endpoint) -> HostServiceClient<tonic::transport::Channel> {
    let connector = connector();
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let channel = tonic::transport::Endpoint::from_static("http://localhost")
                .connect_with_connector(ClientIo::new(connector.clone(), endpoint.clone()))
                .await;
            if let Ok(channel) = channel {
                break HostServiceClient::new(channel);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the elevated session host never published a verified endpoint")
}

fn wait_exit(child: &mut std::process::Child, within: Duration) -> std::process::ExitStatus {
    let until = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < until,
            "the host did not exit in {within:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A second user's session root, created as protected as the host makes
/// its own, holding an open instance record that a reclaim can close (the
/// process it names never ran).
async fn plant_leftover() {
    let layout = NativeHostFilesystem.session_layout(OTHER_SID).unwrap();
    NativeHostFilesystem.prepare_session(&layout).unwrap();
    // The repair index every existing ledger has (its install key).
    std::fs::write(
        layout.state.join("repair-index.json"),
        serde_json::json!({
            "install_key": vec![7u8; 32],
            "instances": [PLANTED_INSTANCE],
        })
        .to_string(),
    )
    .unwrap();
    let boot = BootId("planted".into());
    let ledger = SqliteLedger::open(layout.state.join("ledger.sqlite3"), boot)
        .await
        .unwrap();
    // A stopped instance whose first generation is still open: its kernel
    // process record, planned but never confirmed dead (the image, in the
    // planted root, does not exist), as a crashed session leaves it.
    let id = PLANTED_INSTANCE;
    let instance = etd_contract::InstanceId(id.into());
    let scope = EffectScope::Instance {
        instance,
        epoch: etd_sysfx::Epoch(1),
    };
    let mut generation = plan(id, 1, &[]);
    generation.effects = vec![EffectIntent {
        scope,
        kind: EffectKind::Process,
        key: ObjectKey::Process {
            exe: layout.cores.join("absent").join("easytier-core.exe"),
            cmdline_marker: layout.run.join(id).join("1"),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::WithProcess,
    }];
    ledger
        .commit(
            0,
            changes(
                id,
                1,
                vec![put(id, Desired::Stopped, &[])],
                vec![generation],
            ),
        )
        .await
        .unwrap();
    ledger.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "privileged: elevated Windows CI runner with ETD_HOST_CI_INSTALL=1"]
async fn elevated_session_host_end_to_end() {
    if std::env::var("ETD_HOST_CI_INSTALL").as_deref() != Ok("1")
        || std::env::var("CI").as_deref() != Ok("true")
    {
        eprintln!("skipped: the elevated session host test is CI-only");
        return;
    }
    let root = session_root().unwrap();
    assert!(!root.exists(), "a clean runner has no session root");
    let own = NativeHostFilesystem.session_layout(&sid()).unwrap();

    // 1. A pre-existing EasyTierDesk.session that the host did not make
    // (inherited ProgramData access: users may write) is refused, untouched.
    std::fs::create_dir(&root).unwrap();
    let before = tree(&root);
    refused(EXIT_NOT_CONFORMING);
    assert_eq!(tree(&root), before);
    std::fs::remove_dir(&root).unwrap();

    // 2. The service's state directory left behind: finish uninstall first.
    let service_state = program_data().join("EasyTierDesk");
    std::fs::create_dir(&service_state).unwrap();
    refused(EXIT_SERVICE_INSTALLED);
    std::fs::remove_dir(&service_state).unwrap();

    // 3. The service registered (whatever it runs): the service wins.
    let created = sc(&[
        "create",
        "easytier-desk-host",
        "binPath=",
        r"C:\Windows\System32\svchost.exe",
        "start=",
        "demand",
    ]);
    assert!(created.status.success(), "{}", text(&created));
    refused(EXIT_SERVICE_INSTALLED);
    let deleted = sc(&["delete", "easytier-desk-host"]);
    assert!(deleted.status.success(), "{}", text(&deleted));
    assert!(!root.exists(), "refusals create nothing");

    // 4. A real run: protected tree, verified elevated server, handshake.
    let mut child = host(&["run", "--mode", "elevated-session"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let endpoint = Endpoint::NamedPipe(format!(r"\\.\pipe\easytier-desk-session-{}", sid()));
    let mut session = client(&endpoint).await;
    let welcome = session
        .handshake(request(Hello {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(welcome.host_mode(), HostMode::ElevatedSession);
    assert_eq!(welcome.role(), Role::Admin, "the runner token is elevated");
    for present in [capability::TUN, capability::LEASE, capability::INSTANCES] {
        assert!(
            welcome.capabilities.iter().any(|c| c == present),
            "{present}"
        );
    }
    assert!(
        !welcome
            .capabilities
            .iter()
            .any(|c| c == capability::ADMIN_ALLOW_LIST)
    );
    NativeHostFilesystem.validate_session(&own).unwrap();
    for dir in [&own.state, &own.run, &own.cores] {
        assert!(dir.is_dir(), "{}", dir.display());
    }
    assert!(own.profile.as_ref().unwrap().is_dir());

    // While it runs: install and the user's reclaim fail at once on the
    // shared host lock, and nothing is registered.
    let started = Instant::now();
    let install = output(&["install"]);
    assert!(!install.status.success(), "{}", text(&install));
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "install must not hang"
    );
    let query = sc(&["query", "easytier-desk-host"]);
    assert!(!query.status.success(), "install registered nothing");
    let reclaim = output(&["reclaim", "--mode", "elevated-session"]);
    assert!(!reclaim.status.success(), "{}", text(&reclaim));

    // 5. This test client is not the etd-ui.exe beside the host: it holds
    // no lease, so the host ends by itself after the 30 s grace although
    // the connection stays open.
    let status = tokio::task::block_in_place(|| wait_exit(&mut child, Duration::from_secs(120)));
    assert!(
        status.success(),
        "lease expiry is a normal exit: {status:?}"
    );
    drop(session);

    // The lock and ledger are free again: the user's own reclaim succeeds.
    let reclaim = output(&["reclaim", "--mode", "elevated-session"]);
    assert!(reclaim.status.success(), "{}", text(&reclaim));

    // 6. ReleaseLease(stop) ends a running host.
    let mut child = host(&["run", "--mode", "elevated-session"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut session = client(&endpoint).await;
    // The pipe is up before the self-check ends; until then lease calls
    // answer FailedPrecondition.
    let deadline = Instant::now() + Duration::from_secs(30);
    let released = loop {
        match session
            .release_lease(request(ReleaseLeaseRequest {
                instances: LeaseRelease::StopInstances as i32,
            }))
            .await
        {
            Ok(response) => break response.into_inner(),
            Err(status)
                if status.code() == tonic::Code::FailedPrecondition
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            Err(status) => panic!("release lease: {status:?}"),
        }
    };
    assert!(released.host_exiting);
    let status = tokio::task::block_in_place(|| wait_exit(&mut child, Duration::from_secs(60)));
    assert!(status.success(), "{status:?}");
    drop(session);

    // 7. A junction inside the protected tree is refused.
    let junction = own.cores.join("planted-junction");
    let mut mklink = Command::new(r"C:\Windows\System32\cmd.exe");
    mklink
        .no_window()
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(r"C:\Windows\Temp");
    let made = mklink.output().unwrap();
    assert!(made.status.success(), "{}", text(&made));
    refused(EXIT_NOT_CONFORMING);
    std::fs::remove_dir(&junction).unwrap();

    // The profile directory the system workers redirect to must be a
    // directory: a file in its place is refused, never replaced.
    let profile = own.profile.clone().unwrap();
    std::fs::remove_dir(&profile).unwrap();
    std::fs::write(&profile, b"not a directory").unwrap();
    refused(EXIT_NOT_CONFORMING);
    assert!(profile.is_file(), "left untouched");
    std::fs::remove_file(&profile).unwrap();

    // 8. Another user's crashed session blocks this one until
    // `reclaim --all-users` closes its records.
    plant_leftover().await;
    let result = output(&["run", "--mode", "elevated-session"]);
    assert_eq!(
        result.status.code(),
        Some(EXIT_OTHER_USERS_LEFTOVERS),
        "{}",
        text(&result)
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains(OTHER_SID));
    let reclaim = output(&["reclaim", "--mode", "elevated-session", "--all-users"]);
    assert!(reclaim.status.success(), "{}", text(&reclaim));
    let mut child = host(&["run", "--mode", "elevated-session"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut session = client(&endpoint).await;
    session
        .release_lease(request(ReleaseLeaseRequest {
            instances: LeaseRelease::StopInstances as i32,
        }))
        .await
        .unwrap();
    let status = tokio::task::block_in_place(|| wait_exit(&mut child, Duration::from_secs(60)));
    assert!(status.success(), "{status:?}");
    drop(session);

    // 9. The app uninstaller's purge removes every session root.
    let purge = output(&[
        "reclaim",
        "--mode",
        "elevated-session",
        "--all-users",
        "--all",
        "--purge",
    ]);
    assert!(purge.status.success(), "{}", text(&purge));
    assert!(!root.exists());

    // 10. `etd-host install` drains leftover session ledgers first, then
    // installs; the service uninstall afterwards is clean.
    plant_leftover().await;
    let installed = output(&["install"]);
    assert!(installed.status.success(), "{}", text(&installed));
    assert!(!root.exists(), "install removed the drained session roots");
    let uninstalled = output(&["uninstall"]);
    assert!(uninstalled.status.success(), "{}", text(&uninstalled));
}
