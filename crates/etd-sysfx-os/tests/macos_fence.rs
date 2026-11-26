#![cfg(target_os = "macos")]

use etd_sysfx::{
    Credential, Effect, EffectId, EffectKind, EffectState, Epoch, FenceSpec, PortFence,
    ReclaimError, Reclaimed,
};
use etd_sysfx_os::{OsConfig, adapters};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Child, Command},
    sync::Arc,
    time::{Duration, Instant},
};

fn system(path: &Path) -> etd_sysfx_os::OsAdapters {
    adapters(&OsConfig {
        state_dir: path.into(),
        run_dir: path.join("run"),
        core_store_dir: path.join("cores"),
    })
    .unwrap()
}
struct Fixture(Child);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spec(port: u16, instance: &str, epoch: u64) -> FenceSpec {
    FenceSpec {
        instance: instance.into(),
        epoch: Epoch(epoch),
        address: SocketAddr::from(([127, 0, 0, 1], port)),
    }
}
fn allowed_user(addr: SocketAddr, allow: bool) {
    let out = Command::new("/usr/bin/sudo")
        .args([
            "-n",
            "-u",
            "etd_o3_probe",
            "--",
            "/usr/bin/nc",
            "-nvz",
            "-G",
            "2",
            "-w",
            "2",
            &addr.ip().to_string(),
            &addr.port().to_string(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if allow {
        assert!(out.status.success(), "{stderr}");
    } else {
        assert!(
            !out.status.success()
                && (stderr.contains("timed out")
                    || stderr.contains("Connection refused")
                    || stderr.contains("Operation not permitted")),
            "{stderr}"
        );
    }
}
fn pf(args: &[&str]) -> String {
    let out = Command::new("/sbin/pfctl").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
#[tokio::test]
#[ignore = "disposable privileged macOS runner"]
async fn fence_survives_host_death_and_reclaims_only_one_generation() {
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    if let Ok(marker) = std::env::var("ETD_O3_CHILD") {
        let port = std::env::var("ETD_O3_PORT").unwrap().parse().unwrap();
        let observed = system(Path::new(&marker))
            .fence
            .unwrap()
            .install(&spec(port, "a", 1))
            .await
            .unwrap();
        assert!(matches!(
            observed.credential,
            Some(Credential::ExclusiveContainer { .. })
        ));
        fs::write(marker, b"installed").unwrap();
        loop {
            std::thread::park();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let fence: Arc<dyn PortFence> = system(dir.path()).fence.unwrap();
    let reserve = || TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let first = spec(reserve().local_addr().unwrap().port(), "a", 1);
    let marker = dir.path().join("ready");
    let mut writer = Fixture(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "fence_survives_host_death_and_reclaims_only_one_generation",
            ])
            .env("ETD_O3_CHILD", &marker)
            .env("ETD_O3_PORT", first.address.port().to_string())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(25);
    while !marker.exists() {
        assert!(
            writer.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "fence installation helper failed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let v4 = TcpListener::bind(first.address).unwrap();
    let v6 = TcpListener::bind(("::1", first.address.port())).unwrap();
    let control = reserve();
    allowed_user(control.local_addr().unwrap(), true);
    let control6 = TcpListener::bind(("::1", control.local_addr().unwrap().port())).unwrap();
    allowed_user(control6.local_addr().unwrap(), true);
    let second_port = reserve();
    let second = spec(second_port.local_addr().unwrap().port(), "b", 2);
    let spare = reserve();
    let third = spec(spare.local_addr().unwrap().port(), "c", 3);
    drop((second_port, spare));
    let (b, c) = tokio::join!(fence.install(&second), fence.install(&third));
    b.unwrap();
    c.unwrap();
    assert_eq!(fence.remove(&third).await.unwrap(), Reclaimed::Removed);
    let other = TcpListener::bind(second.address).unwrap();
    let mut ipv6 = first.clone();
    ipv6.address = v6.local_addr().unwrap();
    for phase in ["installed", "host killed"] {
        if phase == "host killed" {
            writer.0.kill().unwrap();
            writer.0.wait().unwrap();
        }
        for s in [&first, &ipv6, &second] {
            let check = fence.verify(s, std::process::id()).await.unwrap();
            assert!(check.passed(), "{phase} {} {check:?}", s.address);
            allowed_user(s.address, false);
            println!(
                "{phase} {}: host connected, separate local account blocked, PID {}",
                s.address,
                std::process::id()
            );
        }
    }
    let recovery = system(dir.path());
    let swept = recovery.sweeper.find_marked(None, &[]).await.unwrap();
    let plan = fence.plan(&first);
    let observation = swept
        .into_iter()
        .find(|o| o.key == plan.key)
        .unwrap()
        .observation;
    let mut effect = Effect {
        id: EffectId("test".into()),
        scope: plan.scope,
        kind: plan.kind,
        key: plan.key,
        undo: plan.undo,
        persistence: plan.persistence,
        state: EffectState::Applied,
        boot: recovery.boot_id.current().unwrap(),
        observation: Some(observation),
        failures: 0,
        last_error: None,
        recorded_at: jiff::Timestamp::now(),
    };
    let reclaim = recovery
        .reclaimers
        .iter()
        .find(|r| r.kind() == EffectKind::MacFenceRule)
        .unwrap();
    drop((v4, v6));
    let original = effect.observation.as_ref().unwrap().credential.clone();
    effect.observation.as_mut().unwrap().credential = Some(Credential::ExclusiveContainer {
        container: "foreign".into(),
    });
    assert_eq!(
        reclaim.reclaim(&effect).await,
        Err(ReclaimError::CredentialMismatch)
    );
    effect.observation.as_mut().unwrap().credential = original;
    let (anchor, label) = match fence.plan(&first).key {
        etd_sysfx::ObjectKey::Fence {
            container, rule, ..
        } => (container, rule),
        _ => panic!(),
    };
    assert_eq!(reclaim.reclaim(&effect).await.unwrap(), Reclaimed::Removed);
    assert_eq!(
        fence.remove(&first).await.unwrap(),
        Reclaimed::AlreadyAbsent
    );
    let remaining = pf(&["-a", &anchor, "-sr"]);
    assert!(!remaining.contains(&label));
    assert_eq!(remaining.lines().count(), 2);
    assert!(
        fence
            .verify(&second, std::process::id())
            .await
            .unwrap()
            .passed()
    );
    drop(other);
    fence.remove(&second).await.unwrap();
    let parents = pf(&["-a", "com.apple", "-s", "Anchors"]);
    if parents.contains("easytier-desk") {
        for args in [&["-sr"][..], &["-sn"], &["-s", "Tables"]] {
            let mut query = vec!["-a", &anchor];
            query.extend_from_slice(args);
            assert!(pf(&query).trim().is_empty());
        }
    }
    assert!(!pf(&["-a", "*", "-sr"]).contains(&label));
    println!(
        "Independent PF enumeration: zero product rules, translations or tables after reclaim"
    );
}

#[tokio::test]
#[ignore = "disposable macOS runner with a second account"]
async fn removal_checks_store_image_and_effective_uid() {
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    if let Ok(port) = std::env::var("ETD_O3_HOLDER_PORT") {
        let listener = TcpListener::bind(("0.0.0.0", port.parse::<u16>().unwrap())).unwrap();
        for stream in listener.incoming() {
            drop(stream.unwrap());
        }
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("etd-o3-store")
        .tempdir_in("/private/tmp")
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let store = dir.path().join("cores");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
    let image = store.join("listener");
    fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
    fs::set_permissions(&image, fs::Permissions::from_mode(0o755)).unwrap();
    let account = nix::unistd::User::from_name("etd_o3_probe")
        .unwrap()
        .unwrap();
    assert!(!account.uid.is_root());
    let fence = system(dir.path()).fence.unwrap();
    for (epoch, uid, gid) in [(1, 0, 0), (2, account.uid.as_raw(), account.gid.as_raw())] {
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let s = spec(port, "holders", epoch);
        fence.install(&s).await.unwrap();
        let mut child = Fixture(
            Command::new(&image)
                .args([
                    "--ignored",
                    "--exact",
                    "removal_checks_store_image_and_effective_uid",
                ])
                .env("ETD_O3_HOLDER_PORT", port.to_string())
                .uid(uid)
                .gid(gid)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        while std::net::TcpStream::connect(s.address).is_err() {
            assert!(child.0.try_wait().unwrap().is_none() && Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(30));
        }
        let outcome = fence.remove(&s).await;
        if uid == 0 {
            assert!(
                outcome
                    .unwrap_err()
                    .to_string()
                    .contains("protected kernel still listens")
            );
            drop(child);
            assert_eq!(fence.remove(&s).await.unwrap(), Reclaimed::Removed);
        } else {
            assert_eq!(outcome.unwrap(), Reclaimed::Removed);
            assert!(std::net::TcpStream::connect(s.address).is_ok());
        }
        println!(
            "store image wildcard listener euid={uid}: protected={}",
            uid == 0
        );
    }
}

#[tokio::test]
#[ignore = "isolated PF anchor on a disposable macOS runner"]
async fn incomplete_pair_fails_verification_and_sweep_still_reports_intact_generation() {
    use std::io::Write;
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    let dir = tempfile::tempdir().unwrap();
    let os = system(dir.path());
    let fence = os.fence.unwrap();
    let v4 = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = v4.local_addr().unwrap().port();
    let second_port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let a = spec(port, "partial", 9);
    let b = spec(second_port, "intact", 10);
    fence.install(&a).await.unwrap();
    fence.install(&b).await.unwrap();
    let key_a = fence.plan(&a).key;
    let key_b = fence.plan(&b).key;
    let etd_sysfx::ObjectKey::Fence {
        container, rule, ..
    } = &key_a
    else {
        panic!()
    };
    let original = pf(&["-a", container, "-sr"]);
    assert_eq!(original.lines().count(), 4);
    let load = |rules: &str| {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(rules.as_bytes()).unwrap();
        let result = Command::new("/sbin/pfctl")
            .args(["-a", container, "-R", "-f"])
            .arg(f.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    let missing = format!("{rule}-v6");
    let mut partial = original
        .lines()
        .filter(|l| !l.contains(&missing))
        .collect::<Vec<_>>()
        .join("\n");
    partial.push_str("\nblock return out quick on lo0 inet proto tcp from any to 127.0.0.1 port = 7 label \"fixture-unrecognized\"\n");
    load(&partial);
    let verified = fence.verify(&a, std::process::id()).await;
    let swept = os.sweeper.find_marked(None, &[]).await;
    // Restore the private fixture before assertions, including on error paths.
    load(&original);
    drop(v4);
    fence.remove(&a).await.unwrap();
    fence.remove(&b).await.unwrap();
    assert!(verified.is_err());
    let swept = swept.unwrap();
    assert_eq!(swept.len(), 1);
    assert_eq!(swept[0].key, key_b);
    println!(
        "Incomplete dual-stack generation rejected; sweep retained only the intact generation"
    );
}
