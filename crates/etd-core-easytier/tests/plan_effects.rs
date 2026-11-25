//! Predicted side effects per platform, checked against upstream c97f36b:
//! - Windows: `arch/windows.rs` (8 interface rules, 2 program rules),
//!   `common/ifcfg/windows.rs` (Tcpip/Tcpip6/NetBT values),
//!   `dns_server/system_config/windows.rs` (NRPT, recovery key, SearchList);
//! - Linux: TUN, routes, systemd-resolved link;
//! - macOS: utun (name read back), routes.
#[path = "plan_fixtures.rs"]
mod fixtures;

use etd_core_api::LaunchPlan;
use etd_core_easytier::plan::{Platform, effects, plan_for};
use etd_sysfx::{
    EffectIntent, EffectKind, EffectScope, Epoch, ObjectKey, Persistence, SettingValue, Undo,
};
use fixtures::*;
use std::path::PathBuf;

fn of(plan: &LaunchPlan, kind: EffectKind) -> Vec<&EffectIntent> {
    plan.effects.iter().filter(|e| e.kind == kind).collect()
}

fn rule_name(effect: &EffectIntent) -> (&str, Option<&str>) {
    match &effect.key {
        ObjectKey::Rule { name, group } => (name, group.as_deref()),
        other => panic!("not a rule: {other:?}"),
    }
}

fn instance_scope() -> EffectScope {
    EffectScope::Instance {
        instance: instance(),
        epoch: Epoch(EPOCH),
    }
}

fn kinds(plan: &LaunchPlan) -> Vec<EffectKind> {
    let mut kinds: Vec<_> = plan.effects.iter().map(|e| e.kind).collect();
    kinds.sort();
    kinds
}

#[test]
fn windows_interface_rules_verbatim() {
    let name = interface_name();
    let plan = plan_for(&ctx(basic()), Platform::Windows).unwrap();
    let rules = of(&plan, EffectKind::WinFirewallRule);
    let names: Vec<_> = rules.iter().map(|e| rule_name(e)).collect();
    let expected: Vec<String> = [
        "TCP Protocol (Inbound)",
        "TCP Protocol (Outbound)",
        "UDP Protocol (Inbound)",
        "UDP Protocol (Outbound)",
        "ICMP Protocol (Inbound)",
        "ICMP Protocol (Outbound)",
        "ALL Protocol (Inbound)",
        "ALL Protocol (Outbound)",
    ]
    .iter()
    .map(|suffix| format!("EasyTier {name} - {suffix}"))
    .collect();
    assert_eq!(
        names,
        expected
            .iter()
            .map(|n| (n.as_str(), Some("EasyTier")))
            .collect::<Vec<_>>()
    );
    for rule in rules {
        assert_eq!(rule.scope, instance_scope());
        assert_eq!(rule.undo, Undo::EnsureAbsent);
        assert_eq!(rule.persistence, Persistence::Persistent);
    }
}

#[test]
fn windows_program_rules_are_scoped_to_the_kernel_binary() {
    let mut ctx = ctx(basic());
    // Upstream names them after `current_exe()` with `\\?\` removed.
    ctx.inputs.core.binary = PathBuf::from(
        r"\\?\C:\Program Files\EasyTier Desktop\cores\2.7.1-c97f36b\easytier-core.exe",
    );
    let plan = plan_for(&ctx, Platform::Windows).unwrap();
    let rules = of(&plan, EffectKind::WinProgramFirewallRule);
    let names: Vec<_> = rules.iter().map(|e| rule_name(e)).collect();
    assert_eq!(
        names,
        vec![
            (
                r"EasyTier C:\Program Files\EasyTier Desktop\cores\2.7.1-c97f36b\easytier-core.exe (Inbound)",
                Some("EasyTier")
            ),
            (
                r"EasyTier C:\Program Files\EasyTier Desktop\cores\2.7.1-c97f36b\easytier-core.exe (Outbound)",
                Some("EasyTier")
            ),
        ]
    );
    for rule in rules {
        assert_eq!(
            rule.scope,
            EffectScope::CoreBinary {
                sha256: "ab".repeat(32)
            }
        );
        assert_eq!(rule.persistence, Persistence::Persistent);
    }
}

#[test]
fn windows_registry_values() {
    let guid = effects::adapter_guid(&interface_name());
    let plan = plan_for(&ctx(basic()), Platform::Windows).unwrap();
    let values: Vec<_> = of(&plan, EffectKind::WinRegistryValue)
        .into_iter()
        .map(|e| match (&e.key, &e.undo) {
            (ObjectKey::Registry { key, value }, Undo::RestoreIfOurs { ours, original }) => {
                assert_eq!(original, &SettingValue::Absent);
                assert_eq!(e.persistence, Persistence::Persistent);
                assert_eq!(e.scope, instance_scope());
                (key.clone(), value.clone().unwrap(), ours.clone())
            }
            other => panic!("unexpected registry record {other:?}"),
        })
        .collect();
    let tcpip = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}");
    let tcpip6 =
        format!(r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{guid}");
    let netbt =
        format!(r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{guid}");
    let mut expected = Vec::new();
    for key in [&tcpip, &tcpip6] {
        expected.push((key.clone(), "RegistrationEnabled".into(), SettingValue::U32(0)));
        expected.push((key.clone(), "DisableDynamicUpdate".into(), SettingValue::U32(1)));
        expected.push((
            key.clone(),
            "MaxNumberOfAddressesToRegister".into(),
            SettingValue::U32(0),
        ));
    }
    expected.push((netbt, "NetbiosOptions".into(), SettingValue::U32(2)));
    assert_eq!(values, expected);
}

#[test]
fn windows_full_set() {
    let name = interface_name();
    let plan = plan_for(&ctx(basic()), Platform::Windows).unwrap();
    let mut expected = vec![EffectKind::Driver, EffectKind::Driver, EffectKind::WinTunAdapter];
    expected.push(EffectKind::Route);
    expected.extend([EffectKind::WinProgramFirewallRule; 2]);
    expected.extend([EffectKind::WinFirewallRule; 8]);
    expected.extend([EffectKind::WinRegistryValue; 7]);
    expected.push(EffectKind::UpnpMapping);
    expected.sort();
    assert_eq!(kinds(&plan), expected);

    let drivers: Vec<_> = of(&plan, EffectKind::Driver)
        .into_iter()
        .map(|e| {
            assert_eq!(e.scope, EffectScope::Product);
            e.key.clone()
        })
        .collect();
    assert!(drivers.contains(&ObjectKey::Service {
        name: "wintun".into()
    }));
    assert!(drivers.contains(&ObjectKey::Service {
        name: "WinDivert".into()
    }));
    assert_eq!(
        of(&plan, EffectKind::Route)[0].key,
        ObjectKey::RoutesVia {
            interface: Some(name)
        }
    );
    // The adapter is probed like a persistent object until spike S2 says
    // it vanishes with the process.
    assert_eq!(
        of(&plan, EffectKind::WinTunAdapter)[0].persistence,
        Persistence::Persistent
    );
}

#[test]
fn windows_magic_dns_records() {
    let guid = effects::adapter_guid(&interface_name());
    let plan = plan_for(&ctx(magic_dns()), Platform::Windows).unwrap();
    let nrpt: Vec<_> = of(&plan, EffectKind::WinNrptRule)
        .iter()
        .map(|e| rule_name(e))
        .collect();
    assert_eq!(
        nrpt,
        vec![
            ("et.net", Some("EasyTier Magic DNS")),
            (".et.net", Some("EasyTier Magic DNS"))
        ]
    );
    let registry: Vec<_> = of(&plan, EffectKind::WinRegistryValue)
        .into_iter()
        .map(|e| e.key.clone())
        .collect();
    assert!(registry.contains(&ObjectKey::Registry {
        key: r"HKLM\SOFTWARE\EasyTier\MagicDNS".into(),
        value: Some("NRPTRuleIDs".into()),
    }));
    assert!(registry.contains(&ObjectKey::Registry {
        key: format!(r"HKLM\SOFTWARE\EasyTier\MagicDNS\SearchLists\{guid}"),
        value: None,
    }));
    let search: Vec<_> = of(&plan, EffectKind::WinRegistryValue)
        .into_iter()
        .filter(|e| matches!(&e.key, ObjectKey::Registry { value: Some(v), .. } if v == "SearchList"))
        .collect();
    assert_eq!(search.len(), 2);
    for value in search {
        assert_eq!(
            value.undo,
            Undo::RestoreIfOurs {
                ours: SettingValue::String("et.net".into()),
                original: SettingValue::Absent
            }
        );
    }
    assert_eq!(plan.exclusive, vec!["windows.magic_dns".to_owned()]);
    assert_eq!(kinds(&plan).len(), 22 + 6);
}

#[test]
fn windows_without_tun() {
    let plan = plan_for(&ctx(no_tun()), Platform::Windows).unwrap();
    assert_eq!(kinds(&plan), vec![EffectKind::UpnpMapping, EffectKind::Driver].tap_sort());
}

#[test]
fn linux_set() {
    let name = interface_name();
    let plan = plan_for(&ctx(basic()), Platform::Linux).unwrap();
    assert_eq!(
        kinds(&plan),
        vec![EffectKind::LinuxTun, EffectKind::Route, EffectKind::UpnpMapping].tap_sort()
    );
    for effect in &plan.effects {
        if effect.kind != EffectKind::UpnpMapping {
            assert_eq!(effect.persistence, Persistence::WithProcess);
        }
    }
    let dns = plan_for(&ctx(magic_dns()), Platform::Linux).unwrap();
    let link = of(&dns, EffectKind::LinuxResolvedLink);
    assert_eq!(link.len(), 1);
    assert_eq!(link[0].key, ObjectKey::ResolvedLink { interface: name });
    assert!(dns.exclusive.is_empty());
    let tunless = plan_for(&ctx(no_tun()), Platform::Linux).unwrap();
    assert_eq!(kinds(&tunless), vec![EffectKind::UpnpMapping]);
}

#[test]
fn macos_set() {
    let plan = plan_for(&ctx(basic()), Platform::MacOs).unwrap();
    assert_eq!(
        kinds(&plan),
        vec![EffectKind::MacUtun, EffectKind::Route, EffectKind::UpnpMapping].tap_sort()
    );
    assert_eq!(
        of(&plan, EffectKind::Route)[0].key,
        ObjectKey::RoutesVia { interface: None }
    );
}

#[test]
fn upnp_mapping_is_recorded_everywhere() {
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOs] {
        for plan in [
            plan_for(&ctx(basic()), platform).unwrap(),
            plan_for(&user_ctx(no_tun()), platform).unwrap(),
        ] {
            let upnp = of(&plan, EffectKind::UpnpMapping);
            assert_eq!(upnp.len(), 1);
            assert_eq!(
                upnp[0].key,
                ObjectKey::PortMapping {
                    protocol: "udp".into(),
                    internal_port: 0,
                    external_port: None,
                    description: "EasyTier udp hole punch".into(),
                }
            );
        }
    }
}

#[test]
fn user_host_records_only_the_router_mapping() {
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOs] {
        let plan = plan_for(&user_ctx(no_tun()), platform).unwrap();
        assert_eq!(kinds(&plan), vec![EffectKind::UpnpMapping]);
    }
}

#[test]
fn driver_never_plans_host_records_and_scopes_its_own() {
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOs] {
        for spec in [basic(), dhcp(), full(), magic_dns()] {
            let Ok(plan) = plan_for(&ctx(spec), platform) else {
                continue;
            };
            for effect in &plan.effects {
                assert!(!matches!(
                    effect.kind,
                    EffectKind::Process
                        | EffectKind::RuntimeDir
                        | EffectKind::WinFenceFilter
                        | EffectKind::LinuxFenceRule
                        | EffectKind::MacFenceRule
                        | EffectKind::ServiceRegistration
                ));
                match &effect.scope {
                    EffectScope::Instance { instance: i, epoch } => {
                        assert_eq!(i, &instance());
                        assert_eq!(*epoch, Epoch(EPOCH));
                    }
                    EffectScope::Product => assert_eq!(effect.kind, EffectKind::Driver),
                    EffectScope::CoreBinary { .. } => {
                        assert_eq!(effect.kind, EffectKind::WinProgramFirewallRule)
                    }
                    other => panic!("unexpected scope {other:?}"),
                }
            }
        }
    }
}

trait TapSort {
    fn tap_sort(self) -> Self;
}

impl TapSort for Vec<EffectKind> {
    fn tap_sort(mut self) -> Self {
        self.sort();
        self
    }
}
