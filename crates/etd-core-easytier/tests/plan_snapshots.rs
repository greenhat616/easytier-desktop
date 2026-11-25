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
    // Default listeners: upstream's 11010 expansion without faketcp.
    let listeners: Vec<String> = loaded
        .get_listeners()
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(listeners.len(), 6);
    assert!(listeners.iter().all(|l| !l.starts_with("faketcp")));
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
