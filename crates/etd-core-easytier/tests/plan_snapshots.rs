//! NetworkSpec fixture matrix → command line and TOML (insta snapshots),
//! plus the invariants: no `rpc_portal` in the TOML, `-c` only into the
//! epoch directory, and upstream's own loader accepts every file.
#[path = "plan_fixtures.rs"]
mod fixtures;

use easytier_core::config::toml::{ConfigLoader, TomlConfigLoader};
use etd_contract::NetworkSpec;
use etd_core_api::{LaunchContext, LaunchPlan};
use etd_core_easytier::plan::{Platform, plan_for};
use fixtures::*;

fn render(plan: &LaunchPlan) -> String {
    let mut out = String::from("command:\n");
    out.push_str(&format!("  exe: {}\n", plan.command.executable.display()));
    for arg in &plan.command.args {
        out.push_str(&format!("  arg: {}\n", arg.to_string_lossy()));
    }
    out.push_str(&format!(
        "  cwd: {}\n  env: {:?}\n",
        plan.command.cwd.as_ref().unwrap().display(),
        plan.command.env
    ));
    for file in &plan.files {
        out.push_str(&format!("file {}:\n", file.path.display()));
        out.push_str(std::str::from_utf8(&file.contents).unwrap());
    }
    scrub(&out)
}

fn plan(ctx: &LaunchContext, platform: Platform) -> LaunchPlan {
    plan_for(ctx, platform).unwrap_or_else(|e| panic!("plan failed: {e}"))
}

fn toml_of(plan: &LaunchPlan) -> String {
    assert_eq!(plan.files.len(), 1);
    String::from_utf8(plan.files[0].contents.clone()).unwrap()
}

/// The invariants every plan must keep.
fn check_invariants(ctx: &LaunchContext, plan: &LaunchPlan) {
    let toml = toml_of(plan);
    assert!(!toml.contains("rpc_portal"), "TOML must not set rpc_portal");
    let config = ctx.inputs.runtime_dir.join("config.toml");
    assert_eq!(plan.files[0].path, config);
    let args: Vec<_> = plan.command.args.iter().map(|a| a.to_owned()).collect();
    let c = args.iter().position(|a| a == "-c").expect("-c present");
    assert_eq!(
        args[c + 1],
        config.as_os_str(),
        "-c points at the epoch file"
    );
    assert_eq!(
        args.iter()
            .filter(|a| *a == "-c" || *a == "--config-file")
            .count(),
        1
    );
    assert!(std::path::Path::new(&args[c + 1]).starts_with(&ctx.inputs.runtime_dir));
    // No network option on the command line: upstream would merge it.
    for arg in &args {
        let arg = arg.to_string_lossy();
        if arg.starts_with('-') {
            assert!(
                [
                    "-c",
                    "--rpc-portal",
                    "--rpc-portal-whitelist",
                    "--disable-env-parsing",
                    "--console-log-level",
                    "--file-log-dir",
                ]
                .contains(&arg.as_ref()),
                "unexpected option {arg}"
            );
        }
    }
    let portal = args.iter().position(|a| a == "--rpc-portal").unwrap();
    assert_eq!(args[portal + 1], "127.0.0.1:15999");
    assert!(plan.command.env.is_empty());
    assert_eq!(
        plan.command.cwd.as_deref(),
        Some(ctx.inputs.runtime_dir.as_path())
    );
    assert_eq!(plan.command.executable, ctx.inputs.core.binary);
    // Upstream's loader reads the file back.
    let loaded = TomlConfigLoader::new_from_str(&toml).expect("upstream parses the TOML");
    let spec = &ctx.inputs.spec;
    assert_eq!(
        loaded.get_network_identity().network_name,
        spec.network_name
    );
    // Upstream reads an absent secret as the empty one.
    assert_eq!(
        loaded
            .get_network_identity()
            .network_secret
            .unwrap_or_default(),
        spec.network_secret.clone().unwrap_or_default()
    );
    assert_eq!(loaded.get_flags().no_tun, spec.no_tun);
    assert_eq!(loaded.get_flags().accept_dns, spec.magic_dns);
}

fn snapshot(name: &str, spec: NetworkSpec, platform: Platform) -> LaunchPlan {
    let ctx = ctx(spec);
    let plan = plan(&ctx, platform);
    check_invariants(&ctx, &plan);
    insta::assert_snapshot!(name, render(&plan));
    plan
}

#[test]
fn basic_windows() {
    let plan = snapshot("basic_windows", basic(), Platform::Windows);
    let loaded = TomlConfigLoader::new_from_str(&toml_of(&plan)).unwrap();
    assert_eq!(loaded.get_flags().dev_name, interface_name());
    assert_eq!(
        loaded.get_ipv4().map(|i| i.to_string()),
        Some("10.144.144.2/24".into())
    );
    assert_eq!(loaded.get_hostname(), "laptop");
    assert_eq!(loaded.get_peers().len(), 1);
    // No listeners named: none at all (ruling msg#477), never the
    // colliding 11010 set.
    assert_eq!(loaded.get_listeners(), Some(Vec::new()));
}

#[test]
fn basic_linux() {
    snapshot("basic_linux", basic(), Platform::Linux);
}

#[test]
fn basic_macos_leaves_the_name_to_the_system() {
    let plan = snapshot("basic_macos", basic(), Platform::MacOs);
    let loaded = TomlConfigLoader::new_from_str(&toml_of(&plan)).unwrap();
    assert_eq!(loaded.get_flags().dev_name, "");
}

#[test]
fn dhcp_with_listeners() {
    let plan = snapshot("dhcp_windows", dhcp(), Platform::Windows);
    let loaded = TomlConfigLoader::new_from_str(&toml_of(&plan)).unwrap();
    assert!(loaded.get_dhcp_config().enabled());
    assert_eq!(loaded.get_listeners().unwrap().len(), 2);
}

#[test]
fn full_spec() {
    let plan = snapshot("full_linux", full(), Platform::Linux);
    let loaded = TomlConfigLoader::new_from_str(&toml_of(&plan)).unwrap();
    let flags = loaded.get_flags();
    assert_eq!(flags.mtu, 1300);
    assert!(flags.latency_first && flags.enable_kcp_proxy && flags.enable_quic_proxy);
    assert!(flags.disable_udp_hole_punching && flags.relay_all_peer_rpc);
    assert!(flags.private_mode && flags.use_smoltcp && flags.enable_exit_node);
    assert!(!flags.enable_ipv6 && flags.enable_encryption);
    assert_eq!(flags.data_compress_algo, 2, "Zstd");
    assert_eq!(loaded.get_proxy_cidrs().len(), 2);
    assert_eq!(loaded.get_exit_nodes().len(), 1);
    assert_eq!(loaded.get_port_forwards().len(), 2);
    assert_eq!(
        loaded.get_socks5_portal().map(|u| u.to_string()),
        Some("socks5://0.0.0.0:1080".into())
    );
    assert_eq!(loaded.get_peers().len(), 3);
}

#[test]
fn no_tun_user_host() {
    let ctx = user_ctx(no_tun());
    let plan = plan(&ctx, Platform::Windows);
    check_invariants(&ctx, &plan);
    insta::assert_snapshot!("no_tun_user_windows", render(&plan));
    let loaded = TomlConfigLoader::new_from_str(&toml_of(&plan)).unwrap();
    assert!(loaded.get_listeners().unwrap().is_empty());
}

#[test]
fn magic_dns_linux() {
    snapshot("magic_dns_linux", magic_dns(), Platform::Linux);
}

#[test]
fn without_secret() {
    let plan = snapshot("no_secret_linux", no_secret(), Platform::Linux);
    assert!(!toml_of(&plan).contains("network_secret"));
}

#[test]
fn deterministic_for_replay() {
    for spec in [basic(), dhcp(), full(), magic_dns()] {
        let ctx = ctx(spec);
        for platform in [Platform::Windows, Platform::Linux, Platform::MacOs] {
            // Refusals (macOS Magic DNS) must be just as repeatable.
            assert_eq!(plan_for(&ctx, platform), plan_for(&ctx, platform));
        }
    }
}

/// Upstream's top-level `Config` has no `deny_unknown_fields`: a misspelt
/// key would be ignored silently, so every key written is read back.
#[test]
fn every_written_key_reads_back() {
    use etd_contract::v1::{TransportProtocol, network_spec::Ipv4};
    const KEYS: &[&str] = &[
        "instance_name",
        "instance_id",
        "hostname",
        "ipv4",
        "dhcp",
        "ipv6_public_addr_provider",
        "listeners",
        "exit_nodes",
        "socks5_proxy",
        "network_identity",
        "peer",
        "proxy_network",
        "port_forward",
        "flags",
    ];
    const FLAG_KEYS: &[&str] = &[
        "dev_name",
        "mtu",
        "no_tun",
        "latency_first",
        "enable_encryption",
        "enable_ipv6",
        "enable_exit_node",
        "use_smoltcp",
        "disable_p2p",
        "relay_all_peer_rpc",
        "disable_udp_hole_punching",
        "multi_thread",
        "bind_device",
        "enable_kcp_proxy",
        "enable_quic_proxy",
        "accept_dns",
        "private_mode",
        "data_compress_algo",
    ];
    let mut seen = std::collections::BTreeSet::new();
    let mut seen_flags = std::collections::BTreeSet::new();
    let mut with_provider = dhcp();
    with_provider.public_ipv6_provider = true;
    for (spec, platform) in [
        (full(), Platform::Linux),
        (with_provider, Platform::Windows),
        (no_tun(), Platform::MacOs),
    ] {
        let ctx = ctx(spec.clone());
        let plan = plan(&ctx, platform);
        let text = toml_of(&plan);
        let table: toml::Table = toml::from_str(&text).unwrap();
        let loaded = TomlConfigLoader::new_from_str(&text).unwrap();
        for key in table.keys() {
            assert!(KEYS.contains(&key.as_str()), "unexpected key {key}");
            seen.insert(key.clone());
        }
        for key in table["flags"].as_table().unwrap().keys() {
            assert!(FLAG_KEYS.contains(&key.as_str()), "unexpected flag {key}");
            seen_flags.insert(key.clone());
        }
        assert_eq!(loaded.get_inst_name(), format!("etd-{INSTANCE}"));
        assert_eq!(loaded.get_id().to_string(), INSTANCE);
        assert_eq!(loaded.get_hostname(), spec.hostname);
        match &spec.ipv4 {
            Some(Ipv4::Ipv4Cidr(cidr)) => {
                assert_eq!(loaded.get_ipv4().unwrap().to_string(), *cidr);
                assert!(!loaded.get_dhcp_config().enabled());
            }
            Some(Ipv4::Dhcp(true)) => {
                assert!(loaded.get_ipv4().is_none());
                assert!(loaded.get_dhcp_config().enabled());
            }
            _ => assert!(loaded.get_ipv4().is_none()),
        }
        assert_eq!(
            loaded.get_ipv6_public_addr_provider(),
            spec.public_ipv6_provider
        );
        let listeners: Vec<String> = loaded
            .get_listeners()
            .unwrap()
            .iter()
            .map(|u| u.to_string().trim_end_matches('/').to_owned())
            .collect();
        let expected: Vec<String> = spec
            .listeners
            .iter()
            .map(|l| l.trim_end_matches('/').to_owned())
            .collect();
        assert_eq!(listeners, expected);
        let exits: Vec<String> = loaded
            .get_exit_nodes()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(exits, spec.exit_nodes);
        assert_eq!(
            loaded.get_socks5_portal().and_then(|u| u.port()),
            (spec.socks5_port != 0).then_some(spec.socks5_port as u16)
        );
        let peers: Vec<String> = loaded
            .get_peers()
            .iter()
            .map(|p| p.uri.to_string())
            .collect();
        assert_eq!(peers.len(), spec.peers.len());
        for (got, want) in peers.iter().zip(&spec.peers) {
            // `url` drops a scheme's default port.
            let want = want.replace("wss://relay.example.org:443/", "wss://relay.example.org/");
            assert!(
                got.starts_with(want.as_str().trim_end_matches('/')),
                "{got} vs {want}"
            );
        }
        let proxies: Vec<String> = loaded
            .get_proxy_cidrs()
            .iter()
            .map(|p| p.cidr.to_string())
            .collect();
        assert_eq!(proxies, spec.proxy_cidrs);
        let forwards: Vec<(String, String, String)> = loaded
            .get_port_forwards()
            .iter()
            .map(|f| {
                (
                    f.bind_addr.to_string(),
                    f.dst_addr.to_string(),
                    f.proto.clone(),
                )
            })
            .collect();
        let want: Vec<(String, String, String)> = spec
            .port_forwards
            .iter()
            .map(|f| {
                let proto = if f.protocol == TransportProtocol::Tcp as i32 {
                    "tcp"
                } else {
                    "udp"
                };
                (f.bind.clone(), f.destination.clone(), proto.to_owned())
            })
            .collect();
        assert_eq!(forwards, want);
        let flags = loaded.get_flags();
        let sf = spec.flags.clone().unwrap_or_default();
        assert_eq!(flags.no_tun, spec.no_tun);
        assert_eq!(flags.latency_first, sf.latency_first);
        assert_eq!(flags.enable_encryption, !sf.disable_encryption);
        assert_eq!(flags.enable_ipv6, !sf.disable_ipv6);
        assert_eq!(flags.enable_exit_node, spec.enable_exit_node);
        assert_eq!(flags.use_smoltcp, sf.use_smoltcp);
        assert_eq!(flags.disable_p2p, sf.disable_p2p);
        assert_eq!(flags.relay_all_peer_rpc, sf.relay_all_peer_rpc);
        assert_eq!(
            flags.disable_udp_hole_punching,
            sf.disable_udp_hole_punching
        );
        assert_eq!(flags.multi_thread, sf.multi_thread);
        assert_eq!(flags.bind_device, sf.bind_device);
        assert_eq!(flags.enable_kcp_proxy, sf.enable_kcp_proxy);
        assert_eq!(flags.enable_quic_proxy, sf.enable_quic_proxy);
        assert_eq!(flags.accept_dns, spec.magic_dns);
        assert_eq!(flags.private_mode, sf.private_mode);
        if spec.mtu != 0 {
            assert_eq!(flags.mtu, spec.mtu);
        }
    }
    // The three fixtures together write every key.
    assert_eq!(seen.len(), KEYS.len(), "{seen:?}");
    assert_eq!(seen_flags.len(), FLAG_KEYS.len(), "{seen_flags:?}");
}
