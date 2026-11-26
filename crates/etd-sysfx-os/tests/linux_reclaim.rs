#![cfg(target_os = "linux")]
use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_sysfx_os::{OsConfig, adapters};
use std::process::Command;

fn command(exe: &str, args: &[&str]) -> String {
    let out = Command::new(exe).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{exe} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn record(kind: EffectKind, key: ObjectKey, obs: Observation) -> Effect {
    Effect {
        id: EffectId("o2".into()),
        scope: EffectScope::Instance {
            instance: InstanceId::from("integration"),
            epoch: Epoch(1),
        },
        kind,
        key,
        undo: Undo::EnsureAbsent,
        persistence: Persistence::WithProcess,
        state: EffectState::Applied,
        boot: BootId(
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim()
                .into(),
        ),
        observation: Some(obs),
        failures: 0,
        last_error: None,
        recorded_at: jiff::Timestamp::now(),
    }
}

#[tokio::test]
#[ignore = "changes Linux networking and resolved on a disposable runner"]
async fn reclaim_real_link_route_and_dns() {
    assert_eq!(std::env::var("ETD_O2_PRIVILEGED").as_deref(), Ok("1"));
    let temp = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: temp.path().into(),
        run_dir: temp.path().into(),
        core_store_dir: temp.path().into(),
    })
    .unwrap();
    let name = naming::interface_name(&InstallKey([3; 32]), &InstanceId::from("integration"));
    let foreign = "etd-0badf00d";
    for name in [name.as_str(), foreign] {
        command("ip", &["tuntap", "add", "dev", name, "mode", "tun"]);
        command("ip", &["link", "set", name, "up"]);
    }
    command("ip", &["addr", "add", "192.0.2.1/30", "dev", &name]);
    let key = ObjectKey::Interface {
        name: Some(name.clone()),
        guid: None,
    };
    let obs = os
        .observer
        .observe(EffectKind::LinuxTun, &key)
        .await
        .unwrap()
        .unwrap();
    let tun = record(EffectKind::LinuxTun, key.clone(), obs.clone());
    let reclaim = |kind| {
        os.reclaimers
            .iter()
            .find(|r| r.kind() == kind)
            .unwrap()
            .as_ref()
    };
    let rc = reclaim(tun.kind);
    for wrong in [
        None,
        Some(Credential::UnixInterface {
            index: 999999,
            boot: tun.boot.clone(),
        }),
        obs.credential.as_ref().map(|c| {
            let Credential::UnixInterface { index, .. } = c else {
                panic!()
            };
            Credential::UnixInterface {
                index: *index,
                boot: BootId("other boot".into()),
            }
        }),
    ] {
        let mut stale = tun.clone();
        stale.observation.as_mut().unwrap().credential = wrong;
        assert_eq!(
            rc.reclaim(&stale).await,
            Err(ReclaimError::CredentialMismatch)
        );
        assert!(os.observer.interface(&key).await.unwrap().is_some());
    }
    let route_key = ObjectKey::RoutesVia {
        interface: Some(name.clone()),
    };
    let routes = record(
        EffectKind::Route,
        route_key.clone(),
        os.observer
            .observe(EffectKind::Route, &route_key)
            .await
            .unwrap()
            .unwrap(),
    );
    let marked = os
        .sweeper
        .find_marked(
            Some(&InstallKey([3; 32])),
            &[InstanceId::from("integration")],
        )
        .await
        .unwrap();
    assert!(
        marked
            .iter()
            .any(|m| m.key == key && matches!(m.origin, FoundBy::DerivedName { .. }))
    );
    assert!(marked.iter().any(|m| m.key
        == ObjectKey::Interface {
            name: Some(foreign.into()),
            guid: None
        }
        && m.origin == FoundBy::PrefixOnly));

    let dns_key = ObjectKey::ResolvedLink {
        interface: name.clone(),
    };
    let dns_kind = EffectKind::LinuxResolvedLink;
    if std::env::var_os("ETD_O2_NO_RESOLVED").is_some() {
        assert!(
            os.observer
                .observe(dns_kind, &dns_key)
                .await
                .unwrap()
                .is_none()
        );
        println!("No resolve1 owner on private bus: live TUN has no resolved effect");
    } else {
        command("resolvectl", &["dns", &name, "192.0.2.53"]);
        command("resolvectl", &["domain", &name, "~o2.invalid"]);
        let mut dns = record(
            dns_kind,
            dns_key.clone(),
            os.observer
                .observe(dns_kind, &dns_key)
                .await
                .unwrap()
                .unwrap(),
        );
        let value = |s: &str| SettingValue::MultiString(vec![s.into()]);
        dns.undo = Undo::RestoreIfOurs {
            ours: value("192.0.2.54"),
            original: value("192.0.2.55"),
        };
        assert_eq!(
            reclaim(dns_kind).reclaim(&dns).await.unwrap(),
            Reclaimed::LeftModified
        );
        assert!(command("resolvectl", &["dns", &name]).contains("192.0.2.53"));
        dns.undo = Undo::RestoreIfOurs {
            ours: value("192.0.2.53"),
            original: value("192.0.2.55"),
        };
        assert_eq!(
            reclaim(dns_kind).reclaim(&dns).await.unwrap(),
            Reclaimed::Restored
        );
        assert!(command("resolvectl", &["dns", &name]).contains("192.0.2.55"));
        assert!(command("resolvectl", &["domain", &name]).contains("~o2.invalid"));
        dns.undo = Undo::EnsureAbsent;
        assert_eq!(
            reclaim(dns_kind).reclaim(&dns).await.unwrap(),
            Reclaimed::Removed
        );
        assert_eq!(reclaim(dns_kind).probe(&dns).await, Probe::Absent);
        println!(
            "resolve1 readback, preserve changed DNS, conditional restore and per-link revert passed"
        );
    }
    assert_eq!(rc.reclaim(&tun).await.unwrap(), Reclaimed::Removed);
    assert_eq!(rc.reclaim(&tun).await.unwrap(), Reclaimed::AlreadyAbsent);
    assert_eq!(reclaim(routes.kind).probe(&routes).await, Probe::Absent);
    let links = command("ip", &["-o", "link", "show"]);
    assert!(!links.contains(&name));
    assert!(links.contains(foreign));
    for family in ["-4", "-6"] {
        assert!(!command("ip", &[family, "route", "show", "table", "all"]).contains(&name));
    }
    command("ip", &["link", "del", foreign]);
    println!(
        "Matched ifindex + boot; missing/stale credentials refused; independent ip link/route dumps clean, foreign same-prefix TUN survived"
    );
}
