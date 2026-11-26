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
    assert!(
        reclaim.reclaim(&effect).await.is_err(),
        "orphan still holds listener"
    );
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
