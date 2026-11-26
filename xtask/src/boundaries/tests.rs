//! The rules over synthetic workspaces. `cargo metadata` runs on generated
//! path crates, offline, so third-party names such as `processkit` resolve to
//! empty local stand-ins and the metadata has Cargo's real shape.

use super::*;
use cargo_metadata::MetadataCommand;
use std::collections::BTreeMap;
use std::fs;

const NORMAL: &str = "dependencies";
const DEV: &str = "dev-dependencies";
const BUILD: &str = "build-dependencies";
const WINDOWS: &str = "target.'cfg(windows)'.dependencies";
const LINUX_DEV: &str = "target.'cfg(target_os = \"linux\")'.dev-dependencies";
const MACOS_BUILD: &str = "target.'cfg(target_os = \"macos\")'.build-dependencies";
const EVERY_SECTION: [&str; 6] = [NORMAL, DEV, BUILD, WINDOWS, LINUX_DEV, MACOS_BUILD];

/// Present in every fixture because the rules require them.
const REQUIRED: [&str; 4] = ["etd-ui", "etd-app", "etd-client", "etd-host-core"];

#[derive(Clone, Copy)]
struct Edge {
    from: &'static str,
    section: &'static str,
    to: &'static str,
}

fn edge(from: &'static str, section: &'static str, to: &'static str) -> Edge {
    Edge { from, section, to }
}

fn check_edges(edges: &[Edge]) -> Vec<String> {
    check_manifests(edges, "")
}

/// Generates the packages that `edges` name and checks them, giving each
/// dependency line the `extra` attributes. `etd-*` crates are workspace
/// members; every other name is a third-party crate outside the workspace.
fn check_manifests(edges: &[Edge], extra: &str) -> Vec<String> {
    let mut packages: BTreeMap<&str, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for name in REQUIRED {
        packages.entry(name).or_default();
    }
    for edge in edges {
        packages.entry(edge.to).or_default();
        packages
            .entry(edge.from)
            .or_default()
            .entry(edge.section)
            .or_default()
            .push(edge.to);
    }
    let directory = |name: &str| {
        if name.starts_with("etd-") {
            format!("workspace/{name}")
        } else {
            format!("external/{name}")
        }
    };

    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    for (name, sections) in &packages {
        let package = root.join(directory(name));
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(package.join("src/lib.rs"), "").unwrap();
        let mut manifest =
            format!("[package]\nname = '{name}'\nversion = '0.1.0'\nedition = '2024'\n");
        for (section, dependencies) in sections {
            manifest.push_str(&format!("[{section}]\n"));
            for dependency in dependencies {
                // Renamed, so that no rule can rely on the alias.
                manifest.push_str(&format!(
                    "alias-{dependency} = {{ package = '{dependency}', \
                     path = '../../{}'{extra} }}\n",
                    directory(dependency)
                ));
            }
        }
        fs::write(package.join("Cargo.toml"), manifest).unwrap();
    }
    let members: Vec<_> = packages
        .keys()
        .filter(|name| name.starts_with("etd-"))
        .collect();
    fs::write(
        root.join("workspace/Cargo.toml"),
        format!("[workspace]\nresolver = '3'\nmembers = {members:?}\n"),
    )
    .unwrap();

    let metadata = MetadataCommand::new()
        .current_dir(root.join("workspace"))
        .other_options(vec!["--offline".into(), "--all-features".into()])
        .exec()
        .unwrap();
    check(&metadata)
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn of_rule<'a>(violations: &'a [String], rule: &str) -> Vec<&'a str> {
    let prefix = format!("{rule}: ");
    violations
        .iter()
        .filter_map(|violation| violation.strip_prefix(&prefix))
        .collect()
}

const NONE: [&str; 0] = [];

#[test]
fn the_intended_architecture_passes() {
    let violations = check_edges(&[
        edge("etd-ui", NORMAL, "etd-app"),
        edge("etd-app", NORMAL, "etd-client"),
        edge("etd-app", DEV, "etd-testkit"),
        edge("etd-client", NORMAL, "etd-ipc"),
        edge("etd-proc", NORMAL, "processkit"),
        edge("etd-proc", WINDOWS, "windows"),
        edge("etd-ipc", WINDOWS, "windows"),
        edge("etd-sysfx-os", LINUX_DEV, "netlink-sys"),
        edge("etd-sysfx-os", MACOS_BUILD, "system-configuration"),
        edge("etd-host-core", NORMAL, "etd-proc"),
        edge("etd-host-core", NORMAL, "etd-core-api"),
        edge("etd-host-core", DEV, "etd-testkit"),
        edge("etd-testkit", NORMAL, "etd-sysfx-os"),
        edge("etd-host", NORMAL, "etd-core-easytier"),
        edge("etd-host", NORMAL, "etd-host-core"),
        edge("etd-core-easytier", NORMAL, "easytier-core"),
    ]);
    assert_eq!(violations, NONE);
}

#[test]
fn rule_1_covers_every_root_kind_and_target() {
    for root in UI_ROOTS {
        for section in EVERY_SECTION {
            let violations = check_edges(&[
                edge(root, section, "bridge"),
                edge("bridge", NORMAL, "easytier-proto"),
            ]);
            let expected = format!("{root} -> bridge -> easytier-proto");
            assert!(
                of_rule(&violations, "rule 1").contains(&expected.as_str()),
                "{root} [{section}] {violations:?}"
            );
        }
    }
}

#[test]
fn rule_1_follows_build_and_target_edges_of_dependencies() {
    for section in [BUILD, WINDOWS, MACOS_BUILD] {
        let violations = check_edges(&[
            edge("etd-app", NORMAL, "bridge"),
            edge("bridge", section, "etd-core-easytier"),
        ]);
        assert_eq!(
            of_rule(&violations, "rule 1"),
            ["etd-app -> bridge -> etd-core-easytier"],
            "[{section}]"
        );
    }
}

#[test]
fn rule_1_ignores_dev_dependencies_of_dependencies() {
    // `etd-contract` tests are not part of building `etd-ui` or its tests.
    let violations = check_edges(&[
        edge("etd-ui", NORMAL, "etd-contract"),
        edge("etd-contract", DEV, "etd-core-easytier"),
    ]);
    assert_eq!(violations, NONE);
}

#[test]
fn rule_1_sees_disabled_optional_dependencies() {
    let violations = check_manifests(
        &[edge("etd-client", NORMAL, "easytier-core")],
        ", optional = true",
    );
    assert_eq!(
        of_rule(&violations, "rule 1"),
        ["etd-client -> easytier-core"]
    );
}

#[test]
fn rule_2_keeps_processkit_in_etd_proc() {
    for section in EVERY_SECTION {
        let violations = check_edges(&[edge("etd-sysfx-os", section, "processkit")]);
        let found = of_rule(&violations, "rule 2");
        assert_eq!(found.len(), 1, "[{section}] {violations:?}");
        assert!(
            found[0].starts_with("etd-sysfx-os directly depends on processkit"),
            "{found:?}"
        );
    }
}

#[test]
fn rule_2_keeps_system_crates_in_the_adapters() {
    for system in [
        "windows",
        "windows-sys",
        "winapi",
        "netlink-packet-route",
        "rtnetlink",
        "libc",
        "nix",
        "nftables",
        "zbus",
        "system-configuration",
    ] {
        let violations = check_edges(&[edge("etd-host", NORMAL, system)]);
        assert_eq!(
            violations,
            [format!("rule 2: etd-host directly depends on {system}")]
        );
        let violations = check_edges(&SYSTEM_CRATE_OWNERS.map(|owner| edge(owner, NORMAL, system)));
        assert_eq!(violations, NONE, "{system}");
    }
}

#[test]
fn rule_2_reports_the_dependency_kind_and_target() {
    for (section, qualifier) in [
        (DEV, "(dev-dependency)"),
        (BUILD, "(build-dependency)"),
        (WINDOWS, "(target cfg(windows))"),
        (
            LINUX_DEV,
            "(dev-dependency, target cfg(target_os = \"linux\"))",
        ),
        (
            MACOS_BUILD,
            "(build-dependency, target cfg(target_os = \"macos\"))",
        ),
    ] {
        let violations = check_edges(&[edge("etd-ui", section, "windows")]);
        assert_eq!(
            violations,
            [format!(
                "rule 2: etd-ui directly depends on windows {qualifier}"
            )]
        );
    }
}

#[test]
fn rule_2_leaves_third_party_internals_alone() {
    let violations = check_edges(&[
        edge("etd-ui", NORMAL, "gui-toolkit"),
        edge("gui-toolkit", WINDOWS, "windows"),
    ]);
    assert_eq!(violations, NONE);
}

#[test]
fn rule_3_rejects_adapters_of_every_kind_and_target() {
    for adapter in ["etd-sysfx-os", "etd-core-easytier", "easytier-core"] {
        for section in EVERY_SECTION {
            let violations = check_edges(&[edge("etd-host-core", section, adapter)]);
            let found = of_rule(&violations, "rule 3");
            assert_eq!(found.len(), 1, "{adapter} [{section}] {violations:?}");
            assert!(
                found[0].starts_with(&format!("etd-host-core directly depends on {adapter}")),
                "{found:?}"
            );
        }
    }
}

#[test]
fn rule_3_allows_the_testkit_as_a_dev_dependency_only() {
    for section in [DEV, LINUX_DEV] {
        let violations = check_edges(&[edge("etd-host-core", section, "etd-testkit")]);
        assert_eq!(violations, NONE);
    }
    for section in [NORMAL, BUILD, WINDOWS, MACOS_BUILD] {
        let violations = check_edges(&[edge("etd-host-core", section, "etd-testkit")]);
        assert_eq!(of_rule(&violations, "rule 3").len(), 1, "{violations:?}");
        assert_eq!(of_rule(&violations, "test isolation").len(), 1);
    }
}

#[test]
fn rule_3_rejects_an_adapter_behind_an_interface_crate() {
    for section in [NORMAL, BUILD, WINDOWS] {
        let violations = check_edges(&[
            edge("etd-host-core", NORMAL, "etd-sysfx"),
            edge("etd-sysfx", section, "etd-sysfx-os"),
        ]);
        assert_eq!(
            violations,
            ["rule 3: etd-host-core -> etd-sysfx -> etd-sysfx-os"],
            "[{section}]"
        );
    }
}

#[test]
fn rule_3_keeps_the_kernel_out_of_host_core_tests() {
    let violations = check_edges(&[
        edge("etd-host-core", DEV, "etd-testkit"),
        edge("etd-testkit", NORMAL, "etd-core-easytier"),
    ]);
    assert_eq!(
        violations,
        ["rule 3: etd-host-core -> etd-testkit -> etd-core-easytier"]
    );
}

#[test]
fn supporting_isolation_rules() {
    let violations = check_edges(&[
        edge("etd-host", BUILD, "etd-testkit"),
        edge("etd-contract", BUILD, "tonic"),
        edge("etd-contract", NORMAL, "prost"),
        edge("etd-contract", DEV, "prost-types"),
        edge("etd-host", DEV, "easytier-proto"),
    ]);
    assert_eq!(
        violations,
        [
            "test isolation: etd-host directly depends on etd-testkit (build-dependency)",
            "contract isolation: etd-contract directly depends on tonic (build-dependency)",
            "kernel isolation: etd-host directly depends on easytier-proto (dev-dependency)",
        ]
    );
}
