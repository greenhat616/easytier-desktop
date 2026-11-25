//! Reclaimers for the host's own records, which need the process engine and
//! so cannot live in etd-sysfx-os: `EffectKind::Process` (verified kill via
//! `ProcessEngine::kill_verified`, never by pid alone; `Uncertain` is never
//! absent) and `EffectKind::RuntimeDir` (exclusive container under the run
//! directory). Owned by H1.
//!
//! The composition root adds [`host_reclaimers`] to the OS reclaimers when
//! it builds `etd_sysfx::ReclaimDeps`.
use async_trait::async_trait;
use etd_proc::{Clock, KillOutcome, Liveness, ProcessEngine, ProcessIdentity, ProcessMarker};
use etd_sysfx::{
    Credential, Effect, EffectKind, ObjectKey, Observation, Probe, ReclaimError, Reclaimed,
    Reclaimer,
};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// The Process and RuntimeDir reclaimers.
pub fn host_reclaimers(
    process: Arc<dyn ProcessEngine>,
    clock: Arc<dyn Clock>,
    run_dir: PathBuf,
) -> Vec<Arc<dyn Reclaimer>> {
    vec![
        Arc::new(ProcessReclaimer {
            process,
            clock: clock.clone(),
        }),
        Arc::new(RuntimeDirReclaimer { run_dir, clock }),
    ]
}

/// Kernel process records. Deletion is a verified tree kill: the recorded
/// pid and start token must still name the same process.
pub struct ProcessReclaimer {
    process: Arc<dyn ProcessEngine>,
    clock: Arc<dyn Clock>,
}

impl ProcessReclaimer {
    pub fn new(process: Arc<dyn ProcessEngine>, clock: Arc<dyn Clock>) -> Self {
        Self { process, clock }
    }

    fn observation(&self, key: &ObjectKey, id: &ProcessIdentity) -> Observation {
        Observation {
            credential: Some(Credential::Process {
                pid: id.pid,
                start_token: id.start_token.clone(),
            }),
            key: Some(key.clone()),
            observed_at: self.clock.wall_now(),
            detail: Some(format!("pid {}", id.pid)),
        }
    }
}

/// The identity recorded for a process record, if its credential was read
/// back after the spawn.
pub fn recorded_identity(e: &Effect) -> Option<ProcessIdentity> {
    let ObjectKey::Process { exe, .. } = &e.key else {
        return None;
    };
    match e.observation.as_ref()?.credential.as_ref()? {
        Credential::Process { pid, start_token } => Some(ProcessIdentity {
            pid: *pid,
            start_token: start_token.clone(),
            exe: exe.clone(),
        }),
        _ => None,
    }
}

fn marker(key: &ObjectKey) -> Option<ProcessMarker> {
    match key {
        ObjectKey::Process {
            exe,
            cmdline_marker,
        } => Some(ProcessMarker {
            exe_root: exe.clone(),
            cmdline_root: cmdline_marker.clone(),
        }),
        _ => None,
    }
}

fn kill_result(outcome: KillOutcome) -> Result<Reclaimed, ReclaimError> {
    match outcome {
        KillOutcome::Killed => Ok(Reclaimed::Removed),
        // Reused: our process is gone, the pid belongs to someone else now.
        KillOutcome::Gone | KillOutcome::Reused => Ok(Reclaimed::AlreadyAbsent),
        KillOutcome::Uncertain => Err(ReclaimError::Indeterminate(
            "process identity could not be confirmed".into(),
        )),
    }
}

#[async_trait]
impl Reclaimer for ProcessReclaimer {
    fn kind(&self) -> EffectKind {
        EffectKind::Process
    }
    fn rank(&self) -> u8 {
        EffectKind::Process.default_rank()
    }

    async fn probe(&self, e: &Effect) -> Probe {
        if let Some(id) = recorded_identity(e) {
            return match self.process.liveness(&id).await {
                Liveness::Same => Probe::Present(self.observation(&e.key, &id)),
                Liveness::Gone | Liveness::Reused => Probe::Absent,
                Liveness::Uncertain => {
                    Probe::Indeterminate(format!("liveness of pid {} is uncertain", id.pid))
                }
            };
        }
        // Planned only (crash between spawn and recording the pid): the
        // second identity is image + command-line marker.
        let Some(marker) = marker(&e.key) else {
            return Probe::Indeterminate("not a process key".into());
        };
        match self.process.find_marked(&marker).await {
            Err(err) => Probe::Indeterminate(err.to_string()),
            Ok(found) => match found.first() {
                None => Probe::Absent,
                Some(id) => Probe::Present(self.observation(&e.key, id)),
            },
        }
    }

    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        if let Some(id) = recorded_identity(e) {
            let outcome = self
                .process
                .kill_verified(&id)
                .await
                .map_err(|err| ReclaimError::Indeterminate(err.to_string()))?;
            return kill_result(outcome);
        }
        let marker = marker(&e.key).ok_or(ReclaimError::Unsupported(EffectKind::Process))?;
        let found = self
            .process
            .find_marked(&marker)
            .await
            .map_err(|err| ReclaimError::Indeterminate(err.to_string()))?;
        let mut result = Reclaimed::AlreadyAbsent;
        for id in found {
            let outcome = self
                .process
                .kill_verified(&id)
                .await
                .map_err(|err| ReclaimError::Indeterminate(err.to_string()))?;
            if kill_result(outcome)? == Reclaimed::Removed {
                result = Reclaimed::Removed;
            }
        }
        Ok(result)
    }
}

/// `run/<instance>/<epoch>/`: an exclusive container (only the host can
/// write under the run directory), so it is deletable by key. Paths outside
/// the run directory are never touched.
pub struct RuntimeDirReclaimer {
    run_dir: PathBuf,
    clock: Arc<dyn Clock>,
}

impl RuntimeDirReclaimer {
    pub fn new(run_dir: PathBuf, clock: Arc<dyn Clock>) -> Self {
        Self { run_dir, clock }
    }

    fn target<'a>(&self, e: &'a Effect) -> Result<&'a Path, ReclaimError> {
        let ObjectKey::Path { path } = &e.key else {
            return Err(ReclaimError::Unsupported(EffectKind::RuntimeDir));
        };
        if !inside(&self.run_dir, path) {
            return Err(ReclaimError::PermissionDenied(format!(
                "{} is outside the run directory",
                path.display()
            )));
        }
        Ok(path)
    }
}

/// `path` lies strictly below `root`, lexically, without `..`.
pub(crate) fn inside(root: &Path, path: &Path) -> bool {
    path != root
        && path.starts_with(root)
        && path
            .components()
            .all(|c| !matches!(c, Component::ParentDir | Component::CurDir))
}

fn io_error(e: std::io::Error) -> ReclaimError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => ReclaimError::PermissionDenied(e.to_string()),
        _ => ReclaimError::Os {
            code: e.raw_os_error().map_or(-1, i64::from),
            message: e.to_string(),
        },
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T, ReclaimError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?
        .map_err(io_error)
}

#[async_trait]
impl Reclaimer for RuntimeDirReclaimer {
    fn kind(&self) -> EffectKind {
        EffectKind::RuntimeDir
    }
    fn rank(&self) -> u8 {
        EffectKind::RuntimeDir.default_rank()
    }

    async fn probe(&self, e: &Effect) -> Probe {
        let path = match self.target(e) {
            Ok(p) => p.to_path_buf(),
            Err(err) => return Probe::Indeterminate(err.to_string()),
        };
        let probe_path = path.clone();
        match blocking(move || match std::fs::symlink_metadata(&probe_path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        })
        .await
        {
            Ok(false) => Probe::Absent,
            Ok(true) => Probe::Present(Observation {
                credential: Some(Credential::ExclusiveContainer {
                    container: self.run_dir.display().to_string(),
                }),
                key: Some(ObjectKey::Path { path }),
                observed_at: self.clock.wall_now(),
                detail: None,
            }),
            Err(err) => Probe::Indeterminate(err.to_string()),
        }
    }

    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        let path = self.target(e)?.to_path_buf();
        let root = self.run_dir.clone();
        blocking(move || {
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Reclaimed::AlreadyAbsent);
                }
                Err(e) => return Err(e),
            };
            // A link is removed itself, never followed.
            if meta.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
            // `run/<instance>/` goes once its last epoch directory is gone.
            if let Some(parent) = path.parent()
                && inside(&root, parent)
            {
                let _ = std::fs::remove_dir(parent);
            }
            Ok(Reclaimed::Removed)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inside_is_strict_and_lexical() {
        let root = Path::new("/var/lib/etd/run");
        assert!(inside(root, Path::new("/var/lib/etd/run/a/1")));
        assert!(!inside(root, root));
        assert!(!inside(root, Path::new("/var/lib/etd/runx/a")));
        assert!(!inside(root, Path::new("/var/lib/etd/run/../state")));
        assert!(!inside(root, Path::new("/tmp/a")));
    }
}
