#![cfg(target_os = "linux")]
use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_sysfx_os::{OsConfig, adapters};
use std::{
    net::{SocketAddr, TcpListener},
    path::Path,
    process::Command,
    time::Duration,
};
fn adapter(dir: &Path) -> etd_sysfx_os::OsAdapters {
    adapters(&OsConfig {
        run_dir: dir.into(),
        state_dir: dir.into(),
        core_store_dir: dir.into(),
    })
    .unwrap()
}
fn spec(port: u16) -> FenceSpec {
    FenceSpec {
        instance: InstanceId::from("linux-ci"),
        epoch: Epoch(29),
        address: ([127, 0, 0, 1], port).into(),
    }
}
#[tokio::test]
#[ignore = "child host for the fence crash test"]
async fn installing_host() {
    let Some(dir) = std::env::var_os("ETD_O2_HOST_DIR") else {
        return;
    };
    assert_eq!(std::env::var("ETD_O2_PRIVILEGED").as_deref(), Ok("1"));
    let dir = Path::new(&dir);
    let port = std::env::var("ETD_O2_PORT").unwrap().parse().unwrap();
    let f = adapter(dir).fence.unwrap();
    let spec = spec(port);
    let installed = f.install(&spec).await;
    let ObjectKey::Fence { container, .. } = f.plan(&spec).key else {
        panic!()
    };
    assert!(
        Command::new("nft")
            .args(["-j", "-a", "-n", "list", "table", "inet", &container])
            .status()
            .unwrap()
            .success()
    );
    installed.unwrap();
    std::fs::write(dir.join("installed"), "ready").unwrap();
    std::future::pending::<()>().await;
}
fn second(addr: SocketAddr, allowed: bool) {
    let script = "import socket,sys,errno,os; assert os.geteuid()!=0; s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET); s.settimeout(2); rc=s.connect_ex((sys.argv[1],int(sys.argv[2]))); print('uid',os.geteuid(),'endpoint',sys.argv[1:], 'errno',rc); sys.exit(0 if rc==int(sys.argv[3]) else 1)";
    assert!(
        Command::new("sudo")
            .args([
                "-u",
                "etd_o2_probe",
                "--",
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                script,
                &addr.ip().to_string(),
                &addr.port().to_string(),
                &if allowed { 0 } else { libc::ECONNREFUSED }.to_string()
            ])
            .status()
            .unwrap()
            .success()
    );
}
#[tokio::test]
#[ignore = "changes nftables on a disposable runner with the CI probe account"]
async fn fence_survives_host_death() {
    assert_eq!(std::env::var("ETD_O2_PRIVILEGED").as_deref(), Ok("1"));
    let dir = tempfile::tempdir().unwrap();
    let os = adapter(dir.path());
    let f = os.fence.unwrap();
    let v4 = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let v4addr = v4.local_addr().unwrap();
    let v6 = TcpListener::bind(("::1", v4addr.port())).unwrap();
    let v6addr = v6.local_addr().unwrap();
    for addr in [v4addr, v6addr] {
        second(addr, true);
    }
    let spec4 = spec(v4addr.port());
    let intent = f.plan(&spec4);
    let ObjectKey::Fence {
        container: name, ..
    } = &intent.key
    else {
        panic!()
    };
    assert!(
        Command::new("nft")
            .args(["create", "table", "inet", name])
            .status()
            .unwrap()
            .success()
    );
    assert!(f.install(&spec4).await.is_err());
    assert!(f.remove(&spec4).await.is_err());
    assert!(
        Command::new("nft")
            .args(["delete", "table", "inet", name])
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "installing_host", "--nocapture"])
        .env("ETD_O2_HOST_DIR", dir.path())
        .env("ETD_O2_PORT", v4addr.port().to_string())
        .spawn()
        .unwrap();
    for _ in 0..150 {
        if dir.path().join("installed").exists() {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "installing host exited"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(dir.path().join("installed").exists());
    let obs = os
        .observer
        .observe(intent.kind, &intent.key)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        obs.credential,
        Some(Credential::ExclusiveContainer { .. })
    ));
    println!("Independent fence readback {:?}", obs.detail);
    assert!(f.remove(&spec4).await.is_err());
    for killed in [false, true] {
        if killed {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        for address in [v4addr, v6addr] {
            let spec = FenceSpec {
                address,
                ..spec4.clone()
            };
            let verification = f.verify(&spec, std::process::id()).await.unwrap();
            assert!(verification.passed(), "{verification:?}");
            assert!(matches!(
                f.verify(&spec, 1).await.unwrap().listener,
                ListenerCheck::Other { .. }
            ));
            second(address, false);
            println!("installer_killed={killed} {address} {verification:?}");
        }
    }
    drop(v4);
    drop(v6);
    let marked = os.sweeper.find_marked(None, &[]).await.unwrap();
    assert!(
        marked
            .iter()
            .any(|o| o.key == intent.key && o.origin == FoundBy::ExclusiveContainer)
    );
    assert_eq!(f.remove(&spec4).await.unwrap(), Reclaimed::Removed);
    assert_eq!(f.remove(&spec4).await.unwrap(), Reclaimed::AlreadyAbsent);
    let ObjectKey::Fence { container, .. } = intent.key else {
        panic!()
    };
    let tables = Command::new("nft")
        .args(["list", "tables"])
        .output()
        .unwrap();
    assert!(tables.status.success());
    assert!(
        !String::from_utf8(tables.stdout)
            .unwrap()
            .contains(&container)
    );
    println!("Independent nft list tables: generation table absent");
}
