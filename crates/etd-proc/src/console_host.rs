//! The one exception to "an uncontained descendant blocks an orphan kill".
//!
//! A Windows console program that has its own console, as the engine starts the
//! core (`CREATE_NO_WINDOW`), has the system's console host as a child. It
//! belongs to no containment of ours, so it would block every orphan kill.
//! Anything not proven to be exactly that process still blocks.

use std::path::{Path, PathBuf};

/// What was observed about a child while a handle on it was held. `None` means
/// the fact could not be read.
#[derive(Clone, Debug)]
pub(crate) struct Observed {
    /// Canonical image path, from the native process API.
    pub(crate) image: Option<PathBuf>,
    pub(crate) parent: Option<u32>,
    /// Creation time, in the units of a process start token.
    pub(crate) created: Option<u64>,
    /// Whether any live process is a child of this one.
    pub(crate) has_children: Option<bool>,
}

/// Canonical path of the console host in the machine's Windows directory.
pub(crate) fn system_image() -> std::io::Result<PathBuf> {
    PathBuf::from(crate::trusted_system_root()?)
        .join("System32")
        .join("conhost.exe")
        .canonicalize()
}

/// Whether the child is the console host of the process being killed.
///
/// Windows records a parent's PID but not its start time. The caller therefore
/// holds a handle on the parent it identified as `(parent, parent_created)`, so
/// the PID cannot be reused while it asks; a child that is older than that
/// process was left by an earlier holder of the PID.
pub(crate) fn is_console_host_of(
    child: &Observed,
    parent: u32,
    parent_created: u64,
    system_image: &Path,
) -> bool {
    child.image.as_deref() == Some(system_image)
        && child.parent == Some(parent)
        && child
            .created
            .is_some_and(|created| created >= parent_created)
        && child.has_children == Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARENT: u32 = 40;
    const STARTED: u64 = 1_000;

    fn host() -> Observed {
        Observed {
            image: Some(system_image().unwrap()),
            parent: Some(PARENT),
            created: Some(STARTED + 1),
            has_children: Some(false),
        }
    }

    fn accepted(child: &Observed) -> bool {
        is_console_host_of(child, PARENT, STARTED, &system_image().unwrap())
    }

    #[test]
    fn the_console_host_of_the_target_is_accepted() {
        assert!(accepted(&host()));
        assert!(accepted(&Observed {
            created: Some(STARTED),
            ..host()
        }));
    }

    #[test]
    fn another_image_blocks() {
        let root = PathBuf::from(crate::trusted_system_root().unwrap());
        let other = root.join("System32").join("cmd.exe");
        assert!(!accepted(&Observed {
            image: Some(other.canonicalize().unwrap()),
            ..host()
        }));
    }

    #[test]
    fn a_program_only_named_like_the_console_host_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("conhost.exe");
        std::fs::write(&fake, b"not the console host").unwrap();
        assert!(!accepted(&Observed {
            image: Some(fake.canonicalize().unwrap()),
            ..host()
        }));
    }

    #[test]
    fn an_unreadable_image_blocks() {
        assert!(!accepted(&Observed {
            image: None,
            ..host()
        }));
    }

    #[test]
    fn another_or_unreadable_parent_blocks() {
        for parent in [Some(PARENT + 1), None] {
            assert!(!accepted(&Observed { parent, ..host() }));
        }
    }

    #[test]
    fn a_host_older_than_the_target_or_of_unknown_age_blocks() {
        for created in [Some(STARTED - 1), None] {
            assert!(!accepted(&Observed { created, ..host() }));
        }
    }

    #[test]
    fn a_host_with_children_or_unknown_children_blocks() {
        for has_children in [Some(true), None] {
            assert!(!accepted(&Observed {
                has_children,
                ..host()
            }));
        }
    }
}
