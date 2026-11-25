//! Feature classification and refusals: macOS Magic DNS refused, Linux
//! public IPv6 provider unmodelled, Windows Magic DNS single writer, a
//! kernel without a profile refused on a privileged host, guards per host.
#[path = "plan_fixtures.rs"]
mod fixtures;

use etd_contract::v1::network_spec::Ipv4;
use etd_core_api::{CoreError, FeatureClass, ManagementGuard, Privilege};
use etd_core_easytier::plan::{Platform, plan_for};
use fixtures::*;

fn class_of(plan: &etd_core_api::LaunchPlan, feature: &str) -> FeatureClass {
    plan.features
        .iter()
        .find(|v| v.feature == feature)
        .unwrap_or_else(|| panic!("no verdict for {feature}"))
        .class
        .clone()
}

#[test]
fn macos_magic_dns_is_refused_on_a_privileged_host() {
    match plan_for(&ctx(magic_dns()), Platform::MacOs) {
        Err(CoreError::FeatureRejected { feature, .. }) => assert_eq!(feature, "magic_dns"),
        other => panic!("expected FeatureRejected, got {other:?}"),
    }
}

#[test]
fn linux_public_ipv6_is_unmodelled_on_a_privileged_host() {
    match plan_for(&ctx(public_ipv6()), Platform::Linux) {
        Err(CoreError::UnmodelledEffects { features }) => {
            assert_eq!(features, vec!["public_ipv6_provider".to_owned()])
        }
        other => panic!("expected UnmodelledEffects, got {other:?}"),
    }
}

#[test]
fn windows_magic_dns_is_single_writer() {
    let plan = plan_for(&ctx(magic_dns()), Platform::Windows).unwrap();
    assert_eq!(
        class_of(&plan, "magic_dns"),
        FeatureClass::SingleWriter {
            resource: "windows.magic_dns".into()
        }
    );
    assert_eq!(plan.exclusive, vec!["windows.magic_dns".to_owned()]);
    // Without Magic DNS nothing is claimed.
    assert!(
        plan_for(&ctx(basic()), Platform::Windows)
            .unwrap()
            .exclusive
            .is_empty()
    );
}

#[test]
fn linux_magic_dns_is_supported_per_link() {
    let plan = plan_for(&ctx(magic_dns()), Platform::Linux).unwrap();
    assert_eq!(class_of(&plan, "magic_dns"), FeatureClass::Supported);
}

#[test]
fn public_ipv6_elsewhere_changes_nothing() {
    for platform in [Platform::Windows, Platform::MacOs] {
        let plan = plan_for(&ctx(public_ipv6()), platform).unwrap();
        assert_eq!(class_of(&plan, "public_ipv6_provider"), FeatureClass::Supported);
    }
}

#[test]
fn kernel_without_profile_is_refused_on_a_privileged_host() {
    let ctx = ctx_with(basic(), Privilege::System, ManagementGuard::Fence, None);
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOs] {
        assert!(matches!(
            plan_for(&ctx, platform),
            Err(CoreError::NoProfile { version }) if version == "2.7.1"
        ));
    }
    // A profile id this adapter does not ship, or one paired with another
    // kernel, is no profile either.
    for profile in ["9.9.9-0000000", "2.7.1-c97f36b"] {
        let mut ctx = ctx_with(basic(), Privilege::System, ManagementGuard::Fence, Some(profile));
        ctx.inputs.core.proto_revision = "0123456".into();
        assert!(matches!(
            plan_for(&ctx, Platform::Windows),
            Err(CoreError::NoProfile { .. })
        ));
    }
}

#[test]
fn user_host_runs_unknown_kernels_lifecycle_only() {
    let ctx = ctx_with(no_tun(), Privilege::User, ManagementGuard::LifecycleOnly, None);
    let plan = plan_for(&ctx, Platform::Linux).unwrap();
    assert_eq!(plan.management, ManagementGuard::LifecycleOnly);
    let ctx = ctx_with(no_tun(), Privilege::User, ManagementGuard::Unguarded, None);
    assert!(matches!(
        plan_for(&ctx, Platform::Linux),
        Err(CoreError::GuardUnavailable(ManagementGuard::Unguarded))
    ));
}

#[test]
fn guards_per_host() {
    let cases = [
        (Privilege::System, ManagementGuard::Fence, true),
        // Deny-all is not verified for 2.7.1 yet.
        (Privilege::System, ManagementGuard::DenyAll, false),
        (Privilege::System, ManagementGuard::Unguarded, false),
        (Privilege::System, ManagementGuard::LifecycleOnly, false),
        (Privilege::User, ManagementGuard::Unguarded, true),
        (Privilege::User, ManagementGuard::LifecycleOnly, true),
        (Privilege::User, ManagementGuard::Fence, false),
        (Privilege::User, ManagementGuard::DenyAll, false),
    ];
    for (privilege, guard, ok) in cases {
        let spec = if privilege == Privilege::System { basic() } else { no_tun() };
        let ctx = ctx_with(spec, privilege, guard, Some("2.7.1-c97f36b"));
        let result = plan_for(&ctx, Platform::Windows);
        if ok {
            assert_eq!(result.unwrap().management, guard);
        } else {
            assert_eq!(
                result.unwrap_err(),
                CoreError::GuardUnavailable(guard),
                "{privilege:?} {guard:?}"
            );
        }
    }
}

#[test]
fn deny_all_whitelist_admits_no_client() {
    // Planned through the command builder directly: the profile has not
    // verified deny-all, so plan_for refuses it.
    let cmd = etd_core_easytier::plan::command::command(
        &binary(),
        &runtime_dir(),
        "127.0.0.1:15999".parse().unwrap(),
        ManagementGuard::DenyAll,
    );
    let args: Vec<_> = cmd.args.iter().map(|a| a.to_string_lossy()).collect();
    let i = args.iter().position(|a| a == "--rpc-portal-whitelist").unwrap();
    assert_eq!(args[i + 1], "255.255.255.255/32");
}

#[test]
fn user_host_cannot_run_a_tun() {
    match plan_for(&user_ctx(basic()), Platform::Windows) {
        Err(CoreError::FeatureRejected { feature, .. }) => assert_eq!(feature, "no_tun"),
        other => panic!("expected FeatureRejected, got {other:?}"),
    }
    // Features that need rights are harmless there.
    let mut spec = no_tun();
    spec.magic_dns = true;
    spec.public_ipv6_provider = true;
    let plan = plan_for(&user_ctx(spec), Platform::Linux).unwrap();
    assert_eq!(class_of(&plan, "magic_dns"), FeatureClass::Supported);
    assert_eq!(class_of(&plan, "public_ipv6_provider"), FeatureClass::Supported);
}

#[test]
fn every_configured_feature_has_a_verdict() {
    let plan = plan_for(&ctx(full()), Platform::Linux).unwrap();
    for feature in [
        "no_tun",
        "peers",
        "listeners",
        "proxy_cidrs",
        "exit_nodes",
        "enable_exit_node",
        "socks5_port",
        "port_forwards",
    ] {
        assert_eq!(class_of(&plan, feature), FeatureClass::Supported, "{feature}");
    }
}

#[test]
fn invalid_specs() {
    let mut cases = Vec::new();
    let mut spec = basic();
    spec.ipv4 = None;
    cases.push(("tun without address", spec));
    let mut spec = basic();
    spec.ipv4 = Some(Ipv4::Ipv4Cidr("10.0.0.1".into()));
    cases.push(("address without length", spec));
    let mut spec = basic();
    spec.proxy_cidrs = vec!["192.168.1.1/24".into()];
    cases.push(("proxy cidr with host bits", spec));
    let mut spec = basic();
    spec.peers = vec!["public.example.org:11010".into()];
    cases.push(("peer without scheme", spec));
    let mut spec = basic();
    spec.peers = vec!["ftp://example.org:21".into()];
    cases.push(("peer with unknown scheme", spec));
    let mut spec = basic();
    spec.listeners = vec!["tcp://example.org:11010".into()];
    cases.push(("listener on a name", spec));
    let mut spec = basic();
    spec.listeners = vec!["tcp://0.0.0.0:11010".into()];
    spec.no_listener = true;
    cases.push(("listeners with no_listener", spec));
    let mut spec = basic();
    spec.network_name = " ".into();
    cases.push(("empty network name", spec));
    let mut spec = basic();
    spec.socks5_port = 70000;
    cases.push(("socks5 port", spec));
    let mut spec = basic();
    spec.flags = Some(etd_contract::v1::NetworkFlags {
        compression: "brotli".into(),
        ..Default::default()
    });
    cases.push(("compression", spec));
    let mut spec = basic();
    spec.exit_nodes = vec!["exit".into()];
    cases.push(("exit node", spec));
    for (name, spec) in cases {
        assert!(
            matches!(plan_for(&ctx(spec), Platform::Linux), Err(CoreError::InvalidSpec(_))),
            "{name}"
        );
    }
    // Host-chosen inputs are checked too.
    let mut bad = ctx(basic());
    bad.inputs.management = "0.0.0.0:15999".parse().unwrap();
    assert!(matches!(plan_for(&bad, Platform::Linux), Err(CoreError::InvalidSpec(_))));
    let mut bad = ctx(basic());
    bad.inputs.management = "127.0.0.1:0".parse().unwrap();
    assert!(matches!(plan_for(&bad, Platform::Linux), Err(CoreError::InvalidSpec(_))));
    let mut bad = ctx(basic());
    bad.inputs.runtime_dir = "run/x/7".into();
    assert!(matches!(plan_for(&bad, Platform::Linux), Err(CoreError::InvalidSpec(_))));
}
