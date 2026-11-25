//! Side effects `easytier-core` c97f36b causes, per platform, recorded
//! before spawn. Every entry cites the upstream code that creates it; the
//! host adds its own records (process, runtime directory, fence).
//!
//! Not an effect of ours: Linux `mknod /dev/net/tun` (`virtual_nic.rs`
//! `ensure_tun_device_node`) happens only when the node is missing. A
//! privileged Linux TUN launch requires the node to exist: H1 checks
//! `/dev/net/tun` before planning and refuses the start otherwise (the plan
//! inputs cannot carry the fact; the plan stays pure). It is never deleted.
use super::{Platform, classify::magic_dns_active, spec::Settings};
use etd_core_api::LaunchContext;
use etd_sysfx::{
    EffectIntent, EffectKind, EffectScope, ObjectKey, Persistence, SettingValue, Undo, naming,
};

/// Group of every firewall rule upstream creates (`arch/windows.rs`).
pub const FIREWALL_GROUP: &str = "EasyTier";
/// Protocols of the per-interface rules, in creation order
/// (`add_interface_to_firewall_allowlist`).
pub const FIREWALL_PROTOCOLS: [&str; 4] = ["TCP", "UDP", "ICMP", "ALL"];
pub const FIREWALL_DIRECTIONS: [&str; 2] = ["Inbound", "Outbound"];

const TCPIP: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";
const TCPIP6: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\";
const NETBT: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_";

/// Magic DNS (`dns_server/system_config/windows.rs`).
pub const MAGIC_DNS_RECOVERY_KEY: &str = r"HKLM\SOFTWARE\EasyTier\MagicDNS";

/// UPnP / NAT-PMP mapping description and lease (`common/upnp.rs`).
pub const UPNP_DESCRIPTION: &str = "EasyTier udp hole punch";
pub const UPNP_LEASE_SECONDS: u32 = 300;

/// Driver services (product scope, removed only on uninstall).
pub const WINTUN_DRIVER: &str = "wintun";
pub const WINDIVERT_DRIVER: &str = "WinDivert";

/// Windows adapter GUID as the registry spells it: braced, upper case.
pub fn adapter_guid(interface_name: &str) -> String {
    format!(
        "{{{}}}",
        naming::wintun_guid(interface_name)
            .hyphenated()
            .to_string()
            .to_ascii_uppercase()
    )
}

/// Natural key of the TUN interface.
pub fn interface_key(platform: Platform, interface_name: &str) -> ObjectKey {
    match platform {
        Platform::Windows => ObjectKey::Interface {
            name: Some(interface_name.to_owned()),
            guid: Some(adapter_guid(interface_name)),
        },
        Platform::Linux => ObjectKey::Interface {
            name: Some(interface_name.to_owned()),
            guid: None,
        },
        // utunN, assigned by the system and read back once ready.
        Platform::MacOs => ObjectKey::Interface {
            name: None,
            guid: None,
        },
    }
}

/// The eight per-interface rule names (`add_protocol_firewall_rules`):
/// `EasyTier <if> - <proto> Protocol (<direction>)`.
pub fn interface_rule_names(interface_name: &str) -> Vec<String> {
    FIREWALL_PROTOCOLS
        .iter()
        .flat_map(|protocol| {
            FIREWALL_DIRECTIONS.iter().map(move |direction| {
                format!("EasyTier {interface_name} - {protocol} Protocol ({direction})")
            })
        })
        .collect()
}

/// The two per-program rule names (`do_add_self_to_firewall_allowlist`):
/// `EasyTier <current_exe without \\?\> (<direction>)`.
///
/// Upstream uses the kernel's `current_exe()`, which is the canonical path
/// the process engine launched. `LaunchInputs.core.binary` must therefore
/// already be canonical (H1 canonicalizes it before planning); the plan is
/// pure and cannot resolve links itself.
pub fn program_rule_names(binary: &std::path::Path) -> Vec<String> {
    let exe = binary.to_string_lossy().replace(r"\\?\", "");
    ["Inbound", "Outbound"]
        .iter()
        .map(|direction| format!("EasyTier {exe} ({direction})"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Builder<'a> {
    ctx: &'a LaunchContext,
    out: Vec<EffectIntent>,
}

impl Builder<'_> {
    fn instance_scope(&self) -> EffectScope {
        EffectScope::Instance {
            instance: self.ctx.instance.clone(),
            epoch: self.ctx.epoch,
        }
    }

    fn push(
        &mut self,
        scope: EffectScope,
        kind: EffectKind,
        key: ObjectKey,
        undo: Undo,
        persistence: Persistence,
    ) {
        self.out.push(EffectIntent {
            scope,
            kind,
            key,
            undo,
            persistence,
        });
    }

    fn instance(&mut self, kind: EffectKind, key: ObjectKey, undo: Undo, persistence: Persistence) {
        let scope = self.instance_scope();
        self.push(scope, kind, key, undo, persistence);
    }

    fn absent(&mut self, kind: EffectKind, key: ObjectKey, persistence: Persistence) {
        self.instance(kind, key, Undo::EnsureAbsent, persistence);
    }

    fn registry_value(&mut self, key: String, value: &str, ours: SettingValue) {
        self.instance(
            EffectKind::WinRegistryValue,
            ObjectKey::Registry {
                key,
                value: Some(value.to_owned()),
            },
            Undo::RestoreIfOurs {
                ours,
                // The keys are named by the derived adapter GUID: nothing
                // but this product's adapter ever set them.
                original: SettingValue::Absent,
            },
            Persistence::Persistent,
        );
    }

    /// Router mapping for UDP hole punching: on by default (`disable_upnp`
    /// false), port chosen at run time, so the key names the description
    /// and leaves the port open (0). Lease 300 s, renewed every 240 s.
    fn upnp(&mut self) {
        self.absent(
            EffectKind::UpnpMapping,
            ObjectKey::PortMapping {
                protocol: "udp".into(),
                internal_port: 0,
                external_port: None,
                description: UPNP_DESCRIPTION.into(),
            },
            // Record only: the router drops it one lease after the process.
            Persistence::Lease {
                seconds: UPNP_LEASE_SECONDS,
            },
        );
    }

    fn routes(&mut self, interface: Option<String>) {
        // Proxy CIDRs, peers' public IPv6 /128s, the Magic DNS fake IP: all
        // on the TUN, gone with it (`virtual_nic.rs`, `server_instance.rs`).
        self.absent(
            EffectKind::Route,
            ObjectKey::RoutesVia { interface },
            Persistence::WithProcess,
        );
    }

    fn windows(&mut self, settings: &Settings) {
        let inputs = &self.ctx.inputs;
        // WinDivert: faketcp (also dialled at run time when a peer
        // advertises it) and the UDP broadcast relay load the driver
        // (`socket/fake_tcp/netfilter/windivert.rs`). Product scope.
        self.push(
            EffectScope::Product,
            EffectKind::Driver,
            ObjectKey::Service {
                name: WINDIVERT_DRIVER.into(),
            },
            Undo::EnsureAbsent,
            Persistence::Persistent,
        );
        if settings.no_tun {
            return;
        }
        let name = inputs.interface_name.clone();
        let guid = adapter_guid(&name);
        self.push(
            EffectScope::Product,
            EffectKind::Driver,
            ObjectKey::Service {
                name: WINTUN_DRIVER.into(),
            },
            Undo::EnsureAbsent,
            Persistence::Persistent,
        );
        // Explicit dev_name, GUID = UUIDv5 of it (`tun_name.rs`). Whether the
        // adapter vanishes with the process is spike S2's question; until it
        // is answered the record is probed like any persistent object.
        self.absent(
            EffectKind::WinTunAdapter,
            interface_key(Platform::Windows, &name),
            Persistence::Persistent,
        );
        self.routes(Some(name.clone()));
        // `create_tun` → `add_self_to_firewall_allowlist`: rules named by the
        // kernel binary, shared by every instance launched from it.
        let binary = EffectScope::CoreBinary {
            sha256: hex(&inputs.core.sha256),
        };
        for rule in program_rule_names(&inputs.core.binary) {
            self.push(
                binary.clone(),
                EffectKind::WinProgramFirewallRule,
                ObjectKey::Rule {
                    name: rule,
                    group: Some(FIREWALL_GROUP.into()),
                },
                Undo::EnsureAbsent,
                Persistence::Persistent,
            );
        }
        // `create_dev` → `add_interface_to_firewall_allowlist`. Upstream
        // removes them in `VirtualNic::drop`, which a kill skips.
        for rule in interface_rule_names(&name) {
            self.absent(
                EffectKind::WinFirewallRule,
                ObjectKey::Rule {
                    name: rule,
                    group: Some(FIREWALL_GROUP.into()),
                },
                Persistence::Persistent,
            );
        }
        // `create_dev` → `RegistryManager::disable_dynamic_updates` and
        // `disable_netbios` (`common/ifcfg/windows.rs`); never restored.
        for prefix in [TCPIP, TCPIP6] {
            for (value, data) in [
                ("RegistrationEnabled", 0),
                ("DisableDynamicUpdate", 1),
                ("MaxNumberOfAddressesToRegister", 0),
            ] {
                self.registry_value(format!("{prefix}{guid}"), value, SettingValue::U32(data));
            }
        }
        self.registry_value(
            format!("{NETBT}{guid}"),
            "NetbiosOptions",
            SettingValue::U32(2),
        );
        // `NicCtx::run` -> `reg_change_catrgory_in_profile`: sets Category=1
        // on the NetworkList profile named after the interface. The profile
        // only exists because our adapter appeared; the reclaimer deletes it
        // by the profile GUID read back as credential, never by name.
        self.absent(
            EffectKind::WinNetworkProfile,
            ObjectKey::NetworkProfile {
                profile_name: name.clone(),
            },
            Persistence::Persistent,
        );

        if magic_dns_active(settings) {
            // One record for the whole machine-wide Magic DNS: the NRPT rules
            // (`DnsPolicyConfig\{random id}`, one pair per zone, including
            // zones learned from peers or other EasyTier processes at run
            // time) and the adapter SearchList values are all listed in
            // upstream's own recovery record, which `clean()` replays
            // (`dns_server/system_config/windows.rs` `WindowsDNSRecovery`).
            self.instance(
                EffectKind::WinMagicDnsRecovery,
                ObjectKey::Registry {
                    key: MAGIC_DNS_RECOVERY_KEY.into(),
                    value: None,
                },
                Undo::ReplayUpstreamRecovery,
                Persistence::Persistent,
            );
        }
    }

    fn linux(&mut self, settings: &Settings) {
        if settings.no_tun {
            return;
        }
        let name = self.ctx.inputs.interface_name.clone();
        self.absent(
            EffectKind::LinuxTun,
            interface_key(Platform::Linux, &name),
            Persistence::WithProcess,
        );
        self.routes(Some(name.clone()));
        if magic_dns_active(settings) {
            // systemd-resolved per-link DNS/domains on the TUN
            // (`system_config/linux.rs`); restored on graceful stop.
            self.absent(
                EffectKind::LinuxResolvedLink,
                ObjectKey::ResolvedLink { interface: name },
                Persistence::WithProcess,
            );
        }
    }

    fn macos(&mut self, settings: &Settings) {
        if settings.no_tun {
            return;
        }
        self.absent(
            EffectKind::MacUtun,
            interface_key(Platform::MacOs, &self.ctx.inputs.interface_name),
            Persistence::WithProcess,
        );
        self.routes(None);
    }
}

/// Effects of a privileged launch.
pub fn predict(ctx: &LaunchContext, settings: &Settings, platform: Platform) -> Vec<EffectIntent> {
    let mut builder = Builder {
        ctx,
        out: Vec::new(),
    };
    match platform {
        Platform::Windows => builder.windows(settings),
        Platform::Linux => builder.linux(settings),
        Platform::MacOs => builder.macos(settings),
    }
    builder.upnp();
    builder.out
}

/// Effects of a user-host launch: the kernel cannot change the system, but
/// still asks the router for a mapping.
pub fn predict_unprivileged(ctx: &LaunchContext, _settings: &Settings) -> Vec<EffectIntent> {
    let mut builder = Builder {
        ctx,
        out: Vec::new(),
    };
    builder.upnp();
    builder.out
}
