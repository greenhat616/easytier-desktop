//! Architecture dependency boundaries, read from `cargo metadata`.
//!
//! The numbered rules are the three in the architecture document:
//!
//! 1. The dependency closure of `etd-ui`, `etd-app` and `etd-client` contains
//!    neither `etd-core-easytier` nor any `easytier*` crate.
//! 2. Only `etd-proc` depends on `processkit`; Windows, netlink and other
//!    system crates appear only in `etd-sysfx-os`, `etd-ipc` and `etd-proc`.
//! 3. `etd-host-core` depends on trait crates and no adapter, so its tests
//!    never compile EasyTier.
//!
//! Every dependency kind (normal, dev, build) and every target `cfg` counts.
//! A closure is what building a package and its own tests pulls in: the root's
//! dependencies of every kind, then normal and build dependencies only, because
//! Cargo never builds the dev-dependencies of a dependency.

use anyhow::{Context, Result};
use cargo_metadata::{Dependency, DependencyKind, Metadata, NodeDep, PackageId};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// Rule 1: no kernel in the UI closure.
    UiClosure,
    /// Rule 2: process and system crates stay in their adapters.
    SystemCrates,
    /// Rule 3: host orchestration sees interfaces only.
    HostCore,
    TestIsolation,
    ContractIsolation,
    KernelIsolation,
}

impl fmt::Display for Rule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UiClosure => "rule 1",
            Self::SystemCrates => "rule 2",
            Self::HostCore => "rule 3",
            Self::TestIsolation => "test isolation",
            Self::ContractIsolation => "contract isolation",
            Self::KernelIsolation => "kernel isolation",
        })
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub rule: Rule,
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.rule, self.detail)
    }
}

const UI_ROOTS: [&str; 3] = ["etd-ui", "etd-app", "etd-client"];
const HOST_CORE: &str = "etd-host-core";
const HOST_CORE_ALLOWED: [&str; 5] = [
    "etd-contract",
    "etd-ipc",
    "etd-proc",
    "etd-sysfx",
    "etd-core-api",
];
const SYSTEM_CRATE_OWNERS: [&str; 3] = ["etd-sysfx-os", "etd-ipc", "etd-proc"];

fn is_easytier(name: &str) -> bool {
    name == "etd-core-easytier" || name.starts_with("easytier")
}

fn is_system(name: &str) -> bool {
    ["windows-", "winapi-", "netlink"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || matches!(
            name,
            "windows"
                | "winapi"
                | "rtnetlink"
                | "nix"
                | "libc"
                | "nftables"
                | "zbus"
                | "system-configuration"
        )
}

/// A workspace crate or kernel crate that `etd-host-core` must not see.
fn is_foreign_to_host_core(name: &str) -> bool {
    (name.starts_with("etd-") || is_easytier(name))
        && name != HOST_CORE
        && !HOST_CORE_ALLOWED.contains(&name)
}

/// Rules about one declared dependency of one workspace package.
fn direct_violations(owner: &str, dependency: &Dependency) -> Vec<Violation> {
    let name = dependency.name.as_str();
    let dev = dependency.kind == DependencyKind::Development;
    let mut broken = Vec::new();
    if (name == "processkit" && owner != "etd-proc")
        || (is_system(name) && !SYSTEM_CRATE_OWNERS.contains(&owner))
    {
        broken.push(Rule::SystemCrates);
    }
    if owner == HOST_CORE && is_foreign_to_host_core(name) && !(dev && name == "etd-testkit") {
        broken.push(Rule::HostCore);
    }
    if name == "etd-testkit" && !dev {
        broken.push(Rule::TestIsolation);
    }
    if owner == "etd-contract" && !dev && !matches!(name, "prost" | "prost-build") {
        broken.push(Rule::ContractIsolation);
    }
    if name.starts_with("easytier") && owner != "etd-core-easytier" {
        broken.push(Rule::KernelIsolation);
    }

    let mut qualifiers = Vec::new();
    match dependency.kind {
        DependencyKind::Development => qualifiers.push("dev-dependency".to_owned()),
        DependencyKind::Build => qualifiers.push("build-dependency".to_owned()),
        _ => {}
    }
    if let Some(target) = &dependency.target {
        qualifiers.push(format!("target {target}"));
    }
    let mut detail = format!("{owner} directly depends on {name}");
    if !qualifiers.is_empty() {
        detail = format!("{detail} ({})", qualifiers.join(", "));
    }
    broken
        .into_iter()
        .map(|rule| Violation {
            rule,
            detail: detail.clone(),
        })
        .collect()
}

fn is_dev_only(edge: &NodeDep) -> bool {
    !edge.dep_kinds.is_empty()
        && edge
            .dep_kinds
            .iter()
            .all(|info| info.kind == DependencyKind::Development)
}

struct Graph<'a> {
    names: HashMap<&'a PackageId, &'a str>,
    edges: HashMap<&'a PackageId, &'a [NodeDep]>,
}

impl<'a> Graph<'a> {
    fn name(&self, id: &PackageId) -> Result<&'a str> {
        self.names
            .get(id)
            .copied()
            .context("missing package in resolve graph")
    }

    /// Walks the closure of `root` breadth first and returns one shortest
    /// path, as package names, to each package that `offends`. The root's own
    /// dev-dependencies are included only with `root_dev`.
    fn offending_paths(
        &self,
        root: &'a PackageId,
        root_dev: bool,
        offends: impl Fn(&str) -> bool,
    ) -> Result<Vec<Vec<&'a str>>> {
        let mut found = Vec::new();
        let mut seen = HashSet::from([root]);
        let mut queue = VecDeque::from([(root, vec![self.name(root)?])]);
        while let Some((id, path)) = queue.pop_front() {
            let edges = self
                .edges
                .get(id)
                .context("missing node in resolve graph")?;
            for edge in *edges {
                if is_dev_only(edge) && !(root_dev && id == root) {
                    continue;
                }
                if !seen.insert(&edge.pkg) {
                    continue;
                }
                let name = self.name(&edge.pkg)?;
                let mut next = path.clone();
                next.push(name);
                if offends(name) {
                    found.push(next.clone());
                }
                queue.push_back((&edge.pkg, next));
            }
        }
        Ok(found)
    }
}

/// Checks `metadata`, which must cover all targets (no `--filter-platform`)
/// and all features. Returns the violations sorted by rule.
pub fn check(metadata: &Metadata) -> Result<Vec<Violation>> {
    let members: HashSet<_> = metadata.workspace_members.iter().collect();
    let resolve = metadata
        .resolve
        .as_ref()
        .context("metadata has no resolve graph")?;
    let graph = Graph {
        names: metadata
            .packages
            .iter()
            .map(|package| (&package.id, package.name.as_str()))
            .collect(),
        edges: resolve
            .nodes
            .iter()
            .map(|node| (&node.id, node.deps.as_slice()))
            .collect(),
    };
    let member = |name: &str| {
        metadata
            .packages
            .iter()
            .find(|package| members.contains(&package.id) && package.name.as_str() == name)
            .map(|package| &package.id)
            .with_context(|| format!("missing workspace package {name}"))
    };
    let mut violations = BTreeSet::new();

    // Declarations, so that renamed and platform-specific dependencies are
    // judged by their real package name.
    for package in metadata.packages.iter().filter(|p| members.contains(&p.id)) {
        for dependency in &package.dependencies {
            violations.extend(direct_violations(package.name.as_str(), dependency));
        }
    }

    for root in UI_ROOTS {
        for path in graph.offending_paths(member(root)?, true, is_easytier)? {
            violations.insert(Violation {
                rule: Rule::UiClosure,
                detail: path.join(" -> "),
            });
        }
    }

    // Direct dependencies of `etd-host-core` are reported above; these are the
    // ones that arrive through another crate. Its tests may use the testkit,
    // which reaches other adapters, but never the kernel.
    let host_core = member(HOST_CORE)?;
    let library = graph.offending_paths(host_core, false, is_foreign_to_host_core)?;
    let tests = graph.offending_paths(host_core, true, is_easytier)?;
    for path in library.into_iter().chain(tests) {
        if path.len() > 2 {
            violations.insert(Violation {
                rule: Rule::HostCore,
                detail: path.join(" -> "),
            });
        }
    }

    Ok(violations.into_iter().collect())
}

#[cfg(test)]
mod tests;
