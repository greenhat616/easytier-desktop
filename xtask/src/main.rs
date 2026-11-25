use anyhow::{Context, Result, bail};
use cargo_metadata::{DependencyKind, Metadata, MetadataCommand};
use std::collections::{HashMap, HashSet, VecDeque};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("check-boundaries"), None) => {
            let metadata = MetadataCommand::new()
                .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
                .other_options(vec!["--locked".into(), "--all-features".into()])
                .exec()
                .context("cargo metadata failed")?;
            let violations = check_boundaries(&metadata)?;
            if !violations.is_empty() {
                for violation in &violations {
                    eprintln!("{violation}");
                }
                bail!("{} architecture boundary violation(s)", violations.len());
            }
            println!("All architecture boundaries passed.");
            Ok(())
        }
        _ => bail!("usage: cargo xtask check-boundaries"),
    }
}

const UI_ROOTS: [&str; 3] = ["etd-ui", "etd-app", "etd-client"];
const HOST_CORE_ALLOWED: [&str; 5] = [
    "etd-contract",
    "etd-ipc",
    "etd-proc",
    "etd-sysfx",
    "etd-core-api",
];

fn is_easytier(name: &str) -> bool {
    name == "etd-core-easytier" || name.starts_with("easytier")
}

fn is_system(name: &str) -> bool {
    name == "windows"
        || name.starts_with("windows-")
        || name.starts_with("netlink")
        || name == "rtnetlink"
        || matches!(
            name,
            "nix" | "libc" | "nftables" | "zbus" | "system-configuration"
        )
}

fn direct_violation(owner: &str, dependency: &str, dev: bool) -> Option<String> {
    // Platform SDKs that are private implementation details of third-party
    // crates (GPUI, Tokio, etc.) are not direct product dependencies.
    if dependency == "processkit" && owner != "etd-proc" {
        return Some(format!("2: {owner} directly depends on processkit"));
    }
    if is_system(dependency) && !matches!(owner, "etd-proc" | "etd-ipc" | "etd-sysfx-os") {
        return Some(format!(
            "2: {owner} directly depends on system crate {dependency}"
        ));
    }
    if owner == "etd-host-core"
        && (dependency.starts_with("etd-") || is_easytier(dependency))
        && !HOST_CORE_ALLOWED.contains(&dependency)
        && !(dev && dependency == "etd-testkit")
    {
        return Some(format!("3: {owner} depends on non-interface {dependency}"));
    }
    if dependency == "etd-testkit" && !dev {
        return Some(format!(
            "test isolation: {owner} has a non-dev dependency on etd-testkit"
        ));
    }
    if owner == "etd-contract" && !dev && !matches!(dependency, "prost" | "prost-build") {
        return Some(format!(
            "contract isolation: {owner} depends on {dependency}"
        ));
    }
    if is_easytier(dependency) && dependency != "etd-core-easytier" && owner != "etd-core-easytier"
    {
        return Some(format!(
            "kernel isolation: {owner} directly depends on {dependency}"
        ));
    }
    None
}

fn check_boundaries(metadata: &Metadata) -> Result<Vec<String>> {
    let members: HashSet<_> = metadata.workspace_members.iter().collect();
    let packages: HashMap<_, _> = metadata
        .packages
        .iter()
        .map(|package| (&package.id, package))
        .collect();
    let resolve = metadata
        .resolve
        .as_ref()
        .context("metadata has no resolve graph")?;
    let nodes: HashMap<_, _> = resolve.nodes.iter().map(|node| (&node.id, node)).collect();
    let mut violations = Vec::new();

    // Use declarations for direct rules (including renamed, disabled optional,
    // build, dev and platform-specific dependencies).
    for package in metadata.packages.iter().filter(|p| members.contains(&p.id)) {
        for dep in &package.dependencies {
            if let Some(violation) = direct_violation(
                package.name.as_str(),
                &dep.name,
                dep.kind == DependencyKind::Development,
            ) {
                violations.push(violation);
            }
        }
    }

    // Resolve IDs rather than dependency aliases. Walk all platform edges and
    // feature-enabled dependencies, recording one shortest path to each offender.
    for name in UI_ROOTS {
        let root = metadata
            .packages
            .iter()
            .find(|package| members.contains(&package.id) && package.name.as_str() == name)
            .with_context(|| format!("missing workspace package {name}"))?;
        let mut queue = VecDeque::from([(&root.id, vec![name.to_owned()])]);
        let mut seen = HashSet::new();
        while let Some((id, path)) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            let package = packages
                .get(id)
                .context("missing package in resolve graph")?;
            if is_easytier(package.name.as_str()) {
                violations.push(format!("1: {}", path.join(" -> ")));
            }
            let node = nodes.get(id).context("missing node in resolve graph")?;
            for dep in &node.deps {
                let package = packages
                    .get(&dep.pkg)
                    .context("missing dependency package")?;
                let mut next = path.clone();
                next.push(package.name.to_string());
                queue.push_back((&dep.pkg, next));
            }
        }
    }
    violations.sort();
    violations.dedup();
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_rules() {
        assert!(direct_violation("etd-proc", "processkit", false).is_none());
        assert!(direct_violation("etd-app", "processkit", false).is_some());
        assert!(direct_violation("etd-ipc", "windows", false).is_none());
        assert!(direct_violation("etd-ui", "netlink-packet-route", false).is_some());
        assert!(direct_violation("etd-host-core", "etd-core-api", false).is_none());
        assert!(direct_violation("etd-host-core", "etd-sysfx-os", false).is_some());
        assert!(direct_violation("etd-host-core", "etd-core-easytier", false).is_some());
        assert!(direct_violation("etd-host-core", "etd-testkit", true).is_none());
        assert!(direct_violation("etd-host", "etd-testkit", false).is_some());
        assert!(direct_violation("etd-contract", "tonic", false).is_some());
    }

    #[test]
    fn kernel_names() {
        assert!(is_easytier("easytier-proto"));
        assert!(is_easytier("etd-core-easytier"));
        assert!(!is_easytier("etd-core-api"));
    }

    #[test]
    fn detects_transitive_renamed_kernel_dependency() {
        use std::fs;

        // A real Cargo metadata graph with no registry dependencies.
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let names = [
            "etd-ui",
            "etd-app",
            "etd-client",
            "bridge",
            "easytier-fixture",
        ];
        fs::write(
            root.join("Cargo.toml"),
            format!("[workspace]\nresolver = '3'\nmembers = {:?}\n", names),
        )
        .unwrap();
        for (index, name) in names.iter().enumerate() {
            let package = root.join(name);
            fs::create_dir_all(package.join("src")).unwrap();
            let edge = if index + 1 < names.len() {
                let next = names[index + 1];
                format!("renamed = {{ package = '{next}', path = '../{next}' }}\n")
            } else {
                String::new()
            };
            fs::write(
                package.join("Cargo.toml"),
                format!(
                    "[package]\nname = '{name}'\nversion = '0.1.0'\nedition = '2024'\n[dependencies]\n{edge}"
                ),
            )
            .unwrap();
            fs::write(package.join("src/lib.rs"), "").unwrap();
        }
        let metadata = MetadataCommand::new()
            .current_dir(root)
            .other_options(vec!["--offline".into()])
            .exec()
            .unwrap();
        let violations = check_boundaries(&metadata).unwrap();
        assert!(
            violations.iter().any(|message| message
                == "1: etd-ui -> etd-app -> etd-client -> bridge -> easytier-fixture")
        );
    }
}
