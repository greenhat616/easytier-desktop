use super::{observation, observe::MacObserver, pf};
use async_trait::async_trait;
use etd_sysfx::*;
use futures_util::future::BoxFuture;
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) struct MacReclaimer {
    pub(super) kind: EffectKind,
    pub(super) observer: Arc<MacObserver>,
    pub(super) cores: Arc<super::holders::CoreIdentity>,
}

fn concrete(effect: &Effect) -> &ObjectKey {
    effect
        .observation
        .as_ref()
        .and_then(|o| o.key.as_ref())
        .unwrap_or(&effect.key)
}

#[async_trait]
impl Reclaimer for MacReclaimer {
    fn kind(&self) -> EffectKind {
        self.kind
    }
    fn rank(&self) -> u8 {
        self.kind.default_rank()
    }
    async fn probe(&self, e: &Effect) -> Probe {
        if e.kind != self.kind {
            return Probe::Indeterminate("wrong effect kind".into());
        }
        if let Some(probe) = self.never_read_back(e).await {
            return probe;
        }
        match self.observer.observe(self.kind, concrete(e)).await {
            Ok(Some(observed)) => self.check_utun_owner(e, observed).await,
            Ok(None) => Probe::Absent,
            Err(err) => Probe::Indeterminate(err.to_string()),
        }
    }
    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        if self.kind != e.kind || e.undo != Undo::EnsureAbsent {
            return Err(ReclaimError::Unsupported(e.kind));
        }
        let current = match self.probe(e).await {
            Probe::Absent => return Ok(Reclaimed::AlreadyAbsent),
            Probe::Indeterminate(err) => return Err(ReclaimError::Indeterminate(err)),
            Probe::Present(o) => o,
        };
        let expected = e.observation.as_ref().and_then(|o| o.credential.as_ref());
        if expected.is_some() && current.credential.as_ref() != expected {
            return Err(ReclaimError::CredentialMismatch);
        }
        if self.kind == EffectKind::MacFenceRule {
            let key = concrete(e);
            let rule =
                pf::Rule::from_key(key).map_err(|e| ReclaimError::Indeterminate(e.to_string()))?;
            if let EffectScope::Instance { instance, epoch } = &e.scope {
                let spec = FenceSpec {
                    instance: instance.clone(),
                    epoch: *epoch,
                    address: ([127, 0, 0, 1], rule.port).into(),
                };
                if pf::Rule::for_spec(&spec) != rule {
                    return Err(ReclaimError::CredentialMismatch);
                }
            }
            if e.key != *key
                || current.credential
                    != Some(Credential::ExclusiveContainer {
                        container: pf::ANCHOR.into(),
                    })
            {
                return Err(ReclaimError::CredentialMismatch);
            }
            let cores = self.cores.clone();
            let changed = tokio::task::spawn_blocking(move || pf::change(rule, false, &cores))
                .await
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?;
            return Ok(if changed {
                Reclaimed::Removed
            } else {
                Reclaimed::AlreadyAbsent
            });
        }
        if expected.is_none() {
            return Err(ReclaimError::CredentialMismatch);
        }
        // Darwin tears down the utun and its routes after the last control
        // socket closes. Deleting a route by CIDR can hit an unrelated LAN.
        Err(ReclaimError::Busy(
            "waiting for macOS to release the utun and its routes".into(),
        ))
    }
}

/// A MacUtun or route record whose utun name was never read back: the
/// kernel died before readiness, so the record holds neither a name nor a
/// credential.
fn unnamed_utun(kind: EffectKind, e: &Effect) -> bool {
    let unnamed = matches!(
        (kind, concrete(e)),
        (
            EffectKind::MacUtun,
            ObjectKey::Interface {
                name: None,
                guid: None,
            },
        ) | (EffectKind::Route, ObjectKey::RoutesVia { interface: None })
    );
    unnamed
        && e.observation
            .as_ref()
            .is_none_or(|o| o.credential.is_none())
}

/// Short-lived programs the pinned kernel (EasyTier c97f36b) runs while its
/// utun is open. The utun control socket is not close-on-exec (rust-tun
/// 43621f7 src/platform/macos/device.rs:108 opens it with a plain
/// socket(); its only fcntl is O_NONBLOCK, src/platform/posix/fd.rs:37-42),
/// so each of them holds the utun until it exits:
/// - `sh -c "ifconfig|route ..."`: easytier/src/common/ifcfg/mod.rs:165-171,
///   commands in ifcfg/darwin.rs;
/// - `networksetup -listallhardwareports`: easytier/src/common/network.rs:189;
/// - `sw_vers -productVersion`: easytier/src/common/os_info.rs:33,117.
///
/// All are awaited to completion; upstream never calls setsid, sets a
/// process group or daemonizes a child. These are the only inheritors, and
/// none outlives its command. A kernel-identity holder running one of these
/// images may be an orphan of a dead kernel, so it keeps an unnamed record
/// indeterminate until it exits.
///
/// `/bin/sh` re-executes the shell selected by /private/var/select/sh, so the
/// shells it may become are listed too.
const KERNEL_HELPERS: [&str; 8] = [
    "/bin/sh",
    "/bin/zsh",
    "/bin/bash",
    "/bin/dash",
    "/sbin/ifconfig",
    "/sbin/route",
    "/usr/sbin/networksetup",
    "/usr/bin/sw_vers",
];

/// Identity of a process that survives PID reuse: effective UID and start
/// time. `None`: the process is gone.
fn stamp(pid: i32) -> io::Result<Option<(u32, (u64, u64))>> {
    // SAFETY: proc_bsdinfo is plain old data; require a full kernel read.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    let got =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if got == size {
        return Ok(Some((
            info.pbi_uid,
            (info.pbi_start_tvsec, info.pbi_start_tvusec),
        )));
    }
    let err = io::Error::last_os_error();
    if got <= 0 && err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(None);
    }
    Err(io::Error::other(format!(
        "cannot identify utun holder {pid}: {err}"
    )))
}

type Stamps = BTreeMap<i32, (u32, (u64, u64))>;

/// Live holders of any utun control socket that run as the kernel's UID.
/// Another user's process cannot be our kernel or one of its helpers.
fn kernel_holders(uid: u32) -> io::Result<Stamps> {
    let mut found = BTreeMap::new();
    for pid in super::observe::utun_control_pids()? {
        if let Some(identity) = stamp(pid)?
            && identity.0 == uid
        {
            found.insert(pid, identity);
        }
    }
    Ok(found)
}

/// `path` with every existing ancestor resolved (symlinks such as /var ->
/// /private/var); missing trailing components are appended as they are.
fn resolved(path: &Path) -> io::Result<PathBuf> {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match std::fs::canonicalize(current) {
            Ok(mut base) => {
                base.extend(missing.iter().rev());
                return Ok(base);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // A dangling symlink exists but points nowhere; what it
                // would name cannot be decided.
                if std::fs::symlink_metadata(current).is_ok() {
                    return Err(io::Error::other(format!(
                        "{} is a dangling symlink",
                        current.display()
                    )));
                }
                let (Some(name), Some(parent)) = (current.file_name(), current.parent()) else {
                    return Err(err);
                };
                missing.push(name.to_owned());
                current = parent;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Why a live utun holder may belong to the generation whose runtime
/// directory is `epoch_dir`; `None` when none can. Only holders running as
/// the kernel's UID are examined: one of the kernel helpers above, or a
/// process whose absolute `-c` configuration resolves inside `epoch_dir`.
/// A holder that exits during the check holds nothing; one whose image or
/// arguments cannot be read while it lives is an error; the holder set must
/// be the same (PID and start time) before and after.
///
/// Limit: a child that inherited the socket, then left the kernel's
/// process group (setsid, daemonized) and exec'd an image not listed above
/// is seen neither here nor by the engine's process-group check. The pinned
/// kernel does neither (see [`KERNEL_HELPERS`]).
fn generation_holder(epoch_dir: &Path, uid: u32) -> io::Result<Option<String>> {
    let epoch_dir = resolved(epoch_dir)?;
    let helpers: Vec<PathBuf> = KERNEL_HELPERS
        .iter()
        .map(|h| std::fs::canonicalize(h).unwrap_or_else(|_| h.into()))
        .collect();
    let first = kernel_holders(uid)?;
    for (&pid, &identity) in &first {
        let gone = || stamp(pid).map(|now| now != Some(identity));
        let image = match super::holders::image_path(pid) {
            Ok(image) => image,
            Err(_) if gone()? => continue,
            Err(err) => {
                return Err(io::Error::other(format!(
                    "cannot read image of utun holder {pid}: {err}"
                )));
            }
        };
        // The PID may have been reused between listing and reading.
        let config = match super::holders::generation_config(pid) {
            Ok(config) => config,
            Err(_) if gone()? => continue,
            Err(err) => {
                return Err(io::Error::other(format!(
                    "cannot read arguments of utun holder {pid}: {err}"
                )));
            }
        };
        if gone()? {
            continue;
        }
        if helpers.contains(&image) {
            return Ok(Some(format!(
                "PID {pid} ({}) holds a utun and may have inherited it from this generation's kernel",
                image.display()
            )));
        }
        // The planner always passes an absolute path; a relative one is
        // not our kernel's.
        if let Some(config) = config.filter(|c| c.is_absolute())
            && resolved(&config)?.starts_with(&epoch_dir)
        {
            return Ok(Some(format!(
                "PID {pid} of this generation still holds a utun"
            )));
        }
    }
    let second = kernel_holders(uid)?;
    if second.iter().any(|(pid, s)| first.get(pid) != Some(s)) {
        return Err(io::Error::other("utun holders changed during the check"));
    }
    Ok(None)
}

impl MacReclaimer {
    /// Darwin destroys a utun, and every route through it, when its last
    /// control socket closes. A record that never learned its utun's name
    /// is reached only once every kernel process record of its generation is
    /// closed (kernel and process group verified dead): the reclaim engine
    /// handles process records before any other record of a generation
    /// (ruling msg#567; `run_group` and `delete_gate` in etd-sysfx). As an
    /// independent check ([`generation_holder`]), a live utun control socket
    /// that may belong to this generation keeps the record indeterminate.
    /// Nothing is deleted here and no name is guessed.
    async fn never_read_back(&self, e: &Effect) -> Option<Probe> {
        if !unnamed_utun(self.kind, e) {
            return None;
        }
        let Some((instance, epoch)) = e.scope.generation() else {
            return Some(Probe::Indeterminate(
                "unnamed utun record has no generation".into(),
            ));
        };
        let marker = self
            .observer
            .run_dir
            .join(instance.as_str())
            .join(epoch.0.to_string());
        let check = marker.clone();
        let uid = self.cores.uid;
        let held = tokio::task::spawn_blocking(move || generation_holder(&check, uid)).await;
        Some(match held {
            Ok(Ok(None)) => {
                tracing::warn!(
                    effect = %e.id.0,
                    kind = %self.kind,
                    instance = instance.as_str(),
                    epoch = epoch.0,
                    runtime_dir = %marker.display(),
                    "utun name was never read back and no process of the generation holds a utun control socket; the utun and its routes are gone"
                );
                Probe::Absent
            }
            Ok(Ok(Some(why))) => {
                Probe::Indeterminate(format!("utun name was never read back and {why}"))
            }
            Ok(Err(err)) => Probe::Indeterminate(err.to_string()),
            Err(err) => Probe::Indeterminate(err.to_string()),
        })
    }

    async fn check_utun_owner(&self, e: &Effect, observed: Observation) -> Probe {
        let name = match (self.kind, concrete(e)) {
            (
                EffectKind::MacUtun,
                ObjectKey::Interface {
                    name: Some(name), ..
                },
            )
            | (
                EffectKind::Route,
                ObjectKey::RoutesVia {
                    interface: Some(name),
                },
            ) => name.clone(),
            _ => return Probe::Present(observed),
        };
        let expected = e.observation.as_ref().and_then(|o| o.credential.as_ref());
        let Some(cred @ Credential::UnixInterface { .. }) = expected else {
            return Probe::Present(observed);
        };
        if observed.credential.as_ref() != Some(cred) {
            return Probe::Present(observed);
        }
        let Some((instance, epoch)) = e.scope.generation() else {
            return Probe::Indeterminate("utun record has no generation".into());
        };
        let cores = self.cores.clone();
        let run = self.observer.run_dir.clone();
        let marker = run.join(instance.as_str()).join(epoch.0.to_string());
        let cred = cred.clone();
        match tokio::task::spawn_blocking(move || cores.foreign_utun(&name, &cred, &run, &marker))
            .await
        {
            Ok(Ok(true)) => Probe::Absent,
            Ok(Ok(false)) => Probe::Present(observed),
            Ok(Err(e)) => Probe::Indeterminate(e.to_string()),
            Err(e) => Probe::Indeterminate(e.to_string()),
        }
    }
}

pub(super) struct MacSweep;
impl Sweeper for MacSweep {
    fn find_marked<'a>(
        &'a self,
        _: Option<&'a InstallKey>,
        _: &'a [etd_contract::InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
        Box::pin(async {
            // User hosts have no privileged system effects of their own.
            if !nix::unistd::Uid::effective().is_root() {
                return Ok(vec![]);
            }
            let rules = tokio::task::spawn_blocking(pf::sweep_rules)
                .await
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?;
            Ok(rules
                .into_iter()
                .map(|rule| {
                    let key = rule.key();
                    FoundObject {
                        kind: EffectKind::MacFenceRule,
                        observation: observation(
                            &key,
                            Credential::ExclusiveContainer {
                                container: pf::ANCHOR.into(),
                            },
                        ),
                        key,
                        origin: FoundBy::ExclusiveContainer,
                    }
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_paths_compare_after_resolving_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canonical = std::fs::canonicalize(&real).unwrap();
        // Missing tail components are kept as they are.
        assert_eq!(
            resolved(&link.join("run/i/1/config.toml")).unwrap(),
            canonical.join("run/i/1/config.toml")
        );
        assert!(
            resolved(&real.join("run/i/1/config.toml"))
                .unwrap()
                .starts_with(resolved(&link.join("run/i/1")).unwrap())
        );
        assert!(
            !resolved(&real.join("run/i/12/config.toml"))
                .unwrap()
                .starts_with(resolved(&link.join("run/i/1")).unwrap())
        );
        // A missing component followed by `..` cannot be resolved.
        assert!(resolved(&link.join("missing/..")).is_err());
        // Nor can a path through a dangling symlink.
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(resolved(&dangling.join("run/i/1")).is_err());
        assert!(resolved(&dangling).is_err());
    }
}
