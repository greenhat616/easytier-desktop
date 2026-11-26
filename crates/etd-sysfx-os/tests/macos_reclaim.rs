#![cfg(target_os = "macos")]

use async_trait::async_trait;
use etd_contract::{Desired, InstanceId};
use etd_sysfx::{engine::ReclaimEngineImpl, *};
use etd_sysfx_os::{OsAdapters, OsConfig, adapters};
use etd_testkit::{
    conformance::ledger::{changes, plan, put},
    fakes::ledger::MemoryLedger,
};
use std::{
    ffi::CStr,
    io,
    mem::{size_of, size_of_val},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::Command,
    sync::Arc,
    time::Duration,
};

fn utun(unit: u32) -> (OwnedFd, String) {
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
        addr.sc_unit = unit;
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
    if let Some(marker) = std::env::var_os("ETD_O3_UTUN_CHILD") {
        let (_socket, name) = utun(std::env::var("ETD_O3_UNIT").unwrap().parse().unwrap());
        assert!(
            Command::new("/sbin/ifconfig")
                .args([&name, "inet", "192.0.2.41", "192.0.2.42", "up"])
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(marker, name).unwrap();
        loop {
            std::thread::park();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let adapters = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().into(),
        core_store_dir: std::env::current_exe().unwrap().parent().unwrap().into(),
    })
    .unwrap();
    let (socket, name) = utun(0);
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
    let original_identity = iface.credential.clone();
    drop(socket);
    for (r, e) in &effects {
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while !matches!(r.probe(e).await, Probe::Absent) {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(r.reclaim(e).await.unwrap(), Reclaimed::AlreadyAbsent);
    }
    let unit = name.strip_prefix("utun").unwrap().parse::<u32>().unwrap() + 1;
    let other = dir.path().join("foreign-vpn");
    std::fs::copy(std::env::current_exe().unwrap(), &other).unwrap();
    let marker = dir.path().join("ready");
    struct Fixture(std::process::Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut replacement = Fixture(
        Command::new(other)
            .args([
                "--ignored",
                "--exact",
                "owned_control_socket_and_verify_only_reclaim",
            ])
            .env("ETD_O3_UTUN_CHILD", &marker)
            .env("ETD_O3_UNIT", unit.to_string())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            replacement.0.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let next_name = std::fs::read_to_string(marker).unwrap();
    assert_eq!(next_name, name);
    let next = adapters
        .observer
        .interfaces_owned_by(replacement.0.id())
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == next_name)
        .unwrap();
    println!(
        "Reopened control socket {name} -> {next_name}, old {original_identity:?}, new {:?}, reused ifindex={}",
        next.credential,
        next.credential == original_identity
    );
    if next.credential == original_identity {
        for (r, e) in &effects {
            assert!(matches!(r.probe(e).await, Probe::Absent));
            assert_eq!(r.reclaim(e).await.unwrap(), Reclaimed::AlreadyAbsent);
            assert!(
                adapters
                    .observer
                    .observe(e.kind, &e.key)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        println!(
            "Foreign PID {} kept its replacement utun and route; old generation reclaimed",
            replacement.0.id()
        );
    }
    println!(
        "Observed {name} via PID, verified identity conflicts; kernel reclaimed interface and route after close"
    );
}

struct NoIndex;
impl RepairIndexStore for NoIndex {
    fn load(&self) -> Result<Option<RepairIndex>, LedgerError> {
        Ok(None)
    }
    fn store(&self, _: &RepairIndex) -> Result<(), LedgerError> {
        Ok(())
    }
}

/// Stands in for the host's process reclaimer: reports the generation's
/// kernel as the fixture says and never kills anything.
struct KernelProcess(Probe);
#[async_trait]
impl Reclaimer for KernelProcess {
    fn kind(&self) -> EffectKind {
        EffectKind::Process
    }
    fn rank(&self) -> u8 {
        EffectKind::Process.default_rank()
    }
    async fn probe(&self, _: &Effect) -> Probe {
        self.0.clone()
    }
    async fn reclaim(&self, _: &Effect) -> Result<Reclaimed, ReclaimError> {
        Err(ReclaimError::Busy("kernel still running".into()))
    }
}

const INSTANCE: &str = "mf-unnamed";

fn unnamed_utun_intents() -> Vec<EffectIntent> {
    let scope = EffectScope::Instance {
        instance: InstanceId::from(INSTANCE),
        epoch: Epoch(1),
    };
    [
        (
            EffectKind::MacUtun,
            ObjectKey::Interface {
                name: None,
                guid: None,
            },
        ),
        (EffectKind::Route, ObjectKey::RoutesVia { interface: None }),
    ]
    .into_iter()
    .map(|(kind, key)| EffectIntent {
        scope: scope.clone(),
        kind,
        key,
        undo: Undo::EnsureAbsent,
        persistence: Persistence::WithProcess,
    })
    .collect()
}

/// A generation planned with its kernel, utun and route, all still
/// `Planned`: the kernel exited before its utun name was read back.
async fn planned_generation(os: &OsAdapters) -> Arc<MemoryLedger> {
    let ledger = Arc::new(MemoryLedger::new(os.boot_id.current().unwrap()));
    let mut generation = plan(INSTANCE, 1, &[]);
    generation.effects.extend(unnamed_utun_intents());
    ledger
        .commit(
            0,
            changes(
                INSTANCE,
                1,
                vec![put(INSTANCE, Desired::Running, &[])],
                vec![generation],
            ),
        )
        .await
        .unwrap();
    ledger
}

fn engine(os: OsAdapters, ledger: Arc<MemoryLedger>, kernel: Probe) -> ReclaimEngineImpl {
    let mut reclaimers = os.reclaimers;
    reclaimers.push(Arc::new(KernelProcess(kernel)));
    ReclaimEngineImpl::new(ReclaimDeps {
        ledger,
        reclaimers,
        sweeper: os.sweeper,
        boot_id: os.boot_id,
        repair_index: Arc::new(NoIndex),
    })
}

fn os_adapters(dir: &tempfile::TempDir) -> OsAdapters {
    adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: std::env::current_exe().unwrap().parent().unwrap().into(),
    })
    .unwrap()
}

/// G2 (topic#42 msg#1081): the kernel died before readiness, leaving a
/// MacUtun and a route record with no name and no credential. Once its
/// process record closes, both close as already absent; an unrelated utun
/// held by another process is left alone.
#[tokio::test]
#[ignore = "disposable macOS runner with allocated utun"]
async fn unnamed_utun_records_close_after_the_kernel_died_before_readiness() {
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    let dir = tempfile::tempdir().unwrap();
    let os = os_adapters(&dir);
    let ledger = planned_generation(&os).await;
    let (_unrelated, name) = utun(0);
    let observer = os.observer.clone();
    let engine = engine(os, ledger.clone(), Probe::Absent);
    let report = engine
        .reclaim_generation(&InstanceId::from(INSTANCE), Epoch(1))
        .await
        .unwrap();
    let open = ledger.open_effects(&ScopeFilter::all()).await.unwrap();
    assert!(open.is_empty(), "{report:?} {open:?}");
    assert!(
        observer
            .interface(&ObjectKey::Interface {
                name: Some(name.clone()),
                guid: None,
            })
            .await
            .unwrap()
            .is_some(),
        "unrelated {name} must survive"
    );
    println!("Unnamed utun and route records closed after the kernel died; {name} untouched");
}

/// While the generation's kernel process record is still open (kernel may
/// be alive), the unnamed utun and route records are not touched.
#[tokio::test]
#[ignore = "disposable macOS runner with allocated utun"]
async fn unnamed_utun_records_wait_while_the_kernel_may_be_alive() {
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    let dir = tempfile::tempdir().unwrap();
    let os = os_adapters(&dir);
    let ledger = planned_generation(&os).await;
    let engine = engine(
        os,
        ledger.clone(),
        Probe::Indeterminate("liveness unknown".into()),
    );
    engine
        .reclaim_generation(&InstanceId::from(INSTANCE), Epoch(1))
        .await
        .unwrap();
    let open = ledger.open_effects(&ScopeFilter::all()).await.unwrap();
    for kind in [EffectKind::MacUtun, EffectKind::Route] {
        let e = open.iter().find(|e| e.kind == kind).unwrap();
        assert_eq!((e.state, e.failures), (EffectState::Planned, 0), "{e:?}");
    }
    println!("Unnamed utun and route records untouched while the kernel record is open");
}

/// Independent of the engine's order: a live process of the generation
/// (its `-c` configuration lies in the generation's runtime directory) that
/// holds a utun control socket keeps the unnamed records indeterminate;
/// once it is gone they probe absent.
#[tokio::test]
#[ignore = "disposable macOS runner with allocated utun"]
async fn unnamed_utun_held_by_a_live_generation_process_is_indeterminate() {
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    if let Some(marker) = std::env::var_os("ETD_MF_UTUN_HOLDER") {
        let (_socket, name) = utun(0);
        std::fs::write(marker, name).unwrap();
        loop {
            std::thread::park();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let os = os_adapters(&dir);
    let epoch_dir = dir.path().join("run").join(INSTANCE).join("1");
    std::fs::create_dir_all(&epoch_dir).unwrap();
    let marker = dir.path().join("holder-ready");
    struct Fixture(std::process::Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // Arguments after `--` are extra test-name filters to libtest; the
    // kernel-style `-c <config>` pair is what identifies the generation.
    let mut holder = Fixture(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "unnamed_utun_held_by_a_live_generation_process_is_indeterminate",
                "--",
                "-c",
            ])
            .arg(epoch_dir.join("config.toml"))
            .env("ETD_MF_UTUN_HOLDER", &marker)
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(holder.0.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(25));
    }
    let name = std::fs::read_to_string(&marker).unwrap();
    let pid = holder.0.id().to_string();
    let effects: Vec<Effect> = unnamed_utun_intents()
        .into_iter()
        .map(|i| Effect {
            id: EffectId(i.kind.to_string()),
            kind: i.kind,
            key: i.key,
            scope: i.scope,
            undo: i.undo,
            persistence: i.persistence,
            state: EffectState::Reclaiming,
            boot: os.boot_id.current().unwrap(),
            observation: None,
            failures: 0,
            last_error: None,
            recorded_at: jiff::Timestamp::now(),
        })
        .collect();
    for e in &effects {
        let r = os.reclaimers.iter().find(|r| r.kind() == e.kind).unwrap();
        let probe = r.probe(e).await;
        assert!(
            matches!(&probe, Probe::Indeterminate(m) if m.contains(&pid)),
            "{} while PID {pid} holds {name}: {probe:?}",
            e.kind
        );
        assert!(matches!(
            r.reclaim(e).await,
            Err(ReclaimError::Indeterminate(_))
        ));
    }
    holder.0.kill().unwrap();
    holder.0.wait().unwrap();
    for e in &effects {
        let r = os.reclaimers.iter().find(|r| r.kind() == e.kind).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while !matches!(r.probe(e).await, Probe::Absent) {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(r.reclaim(e).await.unwrap(), Reclaimed::AlreadyAbsent);
    }
    println!(
        "Live generation holder of {name} kept unnamed records indeterminate; absent after it exited"
    );
}
