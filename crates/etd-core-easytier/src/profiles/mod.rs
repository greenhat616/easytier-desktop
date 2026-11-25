//! Adapter profiles (first: 2.7.1-c97f36b). Owned by E1.
//!
//! A profile pairs one exact kernel build with what the adapter knows about
//! it: how its configuration is written, which side effects it causes and
//! whether its deny-all management configuration has been verified. A kernel
//! that matches no profile runs lifecycle-only on a user host and is refused
//! on a privileged one.
use etd_core_api::{AdapterProfile, CoreDescriptor};

/// What this crate knows about one kernel build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Stable id, `<version>-<short revision>`; persisted in `CoreRef`.
    pub id: &'static str,
    /// Kernel version as `--version` prints it (`CARGO_PKG_VERSION`).
    pub version: &'static str,
    /// Upstream commit the build comes from (full hash).
    pub revision: &'static str,
    /// Deny-all management whitelist verified by privileged tests. Until
    /// then a `DenyAll` guard cannot be planned (v7 fence step 4).
    pub deny_all_verified: bool,
}

/// Upstream `c97f36b` (2026-11-24, workspace version 2.7.1).
pub const EASYTIER_2_7_1_C97F36B: Profile = Profile {
    id: "2.7.1-c97f36b",
    version: "2.7.1",
    revision: crate::PROTOTYPE_REVISION,
    deny_all_verified: false,
};

/// Every profile this adapter ships, newest last.
pub const ALL: &[Profile] = &[EASYTIER_2_7_1_C97F36B];

/// Shortest revision prefix accepted as a match (git's default abbreviation).
const MIN_REVISION_PREFIX: usize = 7;

impl Profile {
    /// Exact pairing: same version, and the descriptor's revision is a
    /// prefix (at least seven hex digits) of the profile's full revision.
    pub fn matches(&self, core: &CoreDescriptor) -> bool {
        let revision = core.proto_revision.to_ascii_lowercase();
        core.version == self.version
            && revision.len() >= MIN_REVISION_PREFIX
            && revision.bytes().all(|b| b.is_ascii_hexdigit())
            && self.revision.starts_with(&revision)
    }

    pub fn adapter_profile(&self) -> AdapterProfile {
        AdapterProfile {
            id: self.id.to_owned(),
            deny_all_verified: self.deny_all_verified,
        }
    }
}

/// The profile paired with exactly this kernel, if any.
pub fn profile_for(core: &CoreDescriptor) -> Option<AdapterProfile> {
    find(core).map(|profile| profile.adapter_profile())
}

/// Profile matching a descriptor.
pub fn find(core: &CoreDescriptor) -> Option<&'static Profile> {
    ALL.iter().find(|profile| profile.matches(core))
}

/// Profile by its persisted id.
pub fn by_id(id: &str) -> Option<&'static Profile> {
    ALL.iter().find(|profile| profile.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(version: &str, revision: &str) -> CoreDescriptor {
        CoreDescriptor {
            version: version.into(),
            proto_revision: revision.into(),
        }
    }

    #[test]
    fn pairs_exact_build_only() {
        assert_eq!(
            profile_for(&core("2.7.1", "c97f36b")).map(|p| p.id),
            Some("2.7.1-c97f36b".to_owned())
        );
        assert!(profile_for(&core("2.7.1", "C97F36B8")).is_some());
        assert!(profile_for(&core("2.7.1", "c97f36")).is_none());
        assert!(profile_for(&core("2.7.2", "c97f36b")).is_none());
        assert!(profile_for(&core("2.7.1", "0123456")).is_none());
        assert!(profile_for(&core("2.7.1", "")).is_none());
    }

    #[test]
    fn deny_all_is_unverified_until_privileged_tests_pass() {
        assert!(!profile_for(&core("2.7.1", "c97f36b")).unwrap().deny_all_verified);
    }

    #[test]
    fn ids_resolve() {
        for profile in ALL {
            assert_eq!(by_id(profile.id), Some(profile));
        }
        assert!(by_id("9.9.9-0000000").is_none());
    }
}
