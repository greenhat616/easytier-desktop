#![cfg(target_os = "macos")]

use etd_sysfx::*;
use etd_sysfx_os::{OsConfig, adapters};
use std::{
    ffi::CStr,
    io,
    mem::{size_of, size_of_val},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::Command,
    time::Duration,
};

fn utun() -> (OwnedFd, String) {
    // SAFETY: Darwin's kernel-control socket owns its freshly returned fd.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    assert!(raw >= 0, "{}", io::Error::last_os_error());
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (dst, src) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
        *dst = *src as _;
    }
    // SAFETY: addresses and sizes are from the Darwin libc ABI. Unit zero
    // asks the kernel to allocate a new tunnel. Closing the fd releases it.
    unsafe {
        assert_eq!(
            libc::ioctl(raw, libc::CTLIOCGINFO, &mut info),
            0,
            "{}",
            io::Error::last_os_error()
        );
        let mut addr: libc::sockaddr_ctl = std::mem::zeroed();
        addr.sc_len = size_of_val(&addr) as _;
        addr.sc_family = libc::AF_SYSTEM as _;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as _;
        addr.sc_id = info.ctl_id;
        assert_eq!(
            libc::connect(
                raw,
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_ctl>() as _
            ),
            0,
            "{}",
            io::Error::last_os_error()
        );
        let mut name = [0i8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        assert_eq!(
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len
            ),
            0
        );
        let name = CStr::from_bytes_until_nul(&name.map(|b| b as u8))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        (socket, name)
    }
}

#[tokio::test]
#[ignore = "disposable macOS runner with allocated utun"]
async fn owned_control_socket_and_verify_only_reclaim() {
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    let dir = tempfile::tempdir().unwrap();
    let adapters = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().into(),
        core_store_dir: dir.path().into(),
    })
    .unwrap();
    let (socket, name) = utun();
    for class in [
        SystemClass::Processes,
        SystemClass::Services,
        SystemClass::Routes,
        SystemClass::Interfaces,
        SystemClass::FirewallRules,
        SystemClass::RuntimeDirs,
        SystemClass::RegistryValues,
    ] {
        let entries = adapters.observer.enumerate(class).await.unwrap();
        assert!(entries.iter().all(|e| e.class == class));
        if class == SystemClass::Processes {
            assert!(entries.iter().any(|e|matches!(e.identity,Some(Credential::Process{pid,..}) if pid==std::process::id())));
        }
    }
    assert!(
        Command::new("/sbin/ifconfig")
            .args([&name, "inet", "192.0.2.41", "192.0.2.42", "up"])
            .status()
            .unwrap()
            .success()
    );
    let owned = adapters
        .observer
        .interfaces_owned_by(std::process::id())
        .await
        .unwrap();
    let iface = owned
        .iter()
        .find(|i| i.name == name)
        .expect("allocated tunnel owned by this pid");
    assert!(
        iface.up
            && iface
                .addresses
                .iter()
                .any(|(a, _)| a.to_string() == "192.0.2.41")
    );
    let mut effects = vec![];
    for (kind, key) in [
        (
            EffectKind::MacUtun,
            ObjectKey::Interface {
                name: Some(name.clone()),
                guid: None,
            },
        ),
        (
            EffectKind::Route,
            ObjectKey::RoutesVia {
                interface: Some(name.clone()),
            },
        ),
    ] {
        let reclaimer = adapters
            .reclaimers
            .iter()
            .find(|r| r.kind() == kind)
            .unwrap();
        let observed = adapters
            .observer
            .observe(kind, &key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.credential.as_ref(), Some(&iface.credential));
        let mut e = Effect {
            id: EffectId(kind.to_string()),
            kind,
            key,
            scope: EffectScope::Instance {
                instance: "ci".into(),
                epoch: Epoch(1),
            },
            undo: Undo::EnsureAbsent,
            persistence: Persistence::WithProcess,
            state: EffectState::Applied,
            boot: adapters.boot_id.current().unwrap(),
            observation: Some(observed.clone()),
            failures: 0,
            last_error: None,
            recorded_at: jiff::Timestamp::now(),
        };
        e.observation.as_mut().unwrap().credential = Some(Credential::UnixInterface {
            index: 0,
            boot: e.boot.clone(),
        });
        assert_eq!(
            reclaimer.reclaim(&e).await,
            Err(ReclaimError::CredentialMismatch)
        );
        e.observation = Some(observed);
        assert!(matches!(
            reclaimer.reclaim(&e).await,
            Err(ReclaimError::Busy(_))
        ));
        assert!(matches!(reclaimer.probe(&e).await, Probe::Present(_)));
        effects.push((reclaimer, e));
    }
    drop(socket);
    for (r, e) in effects {
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while !matches!(r.probe(&e).await, Probe::Absent) {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(r.reclaim(&e).await.unwrap(), Reclaimed::AlreadyAbsent);
    }
    println!(
        "Observed {name} via PID, verified identity conflicts; kernel reclaimed interface and route after close"
    );
}
