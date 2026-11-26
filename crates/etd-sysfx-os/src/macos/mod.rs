//! Darwin observations, verify-only utun/route reclaim and the PF fence.
mod fence;
mod observe;
mod pf;
mod reclaim;

use crate::{OsAdapters, OsConfig, OsError};
use etd_sysfx::*;
use std::{io, process::Command, sync::Arc};

pub(crate) use pf::{install_anchor, uninstall_anchor};

fn command(path: &str) -> Command {
    let mut cmd = Command::new(path);
    cmd.env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd
}

fn output(cmd: &mut Command) -> io::Result<String> {
    let result = cmd.output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "{}: {}: {}",
            cmd.get_program().to_string_lossy(),
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    String::from_utf8(result.stdout).map_err(io::Error::other)
}

fn observation(key: &ObjectKey, credential: Credential) -> Observation {
    Observation {
        credential: Some(credential),
        key: Some(key.clone()),
        observed_at: jiff::Timestamp::now(),
        detail: None,
    }
}

fn boot() -> io::Result<BootId> {
    let value = output(command("/usr/sbin/sysctl").args(["-n", "kern.bootsessionuuid"]))?;
    let id = uuid::Uuid::parse_str(value.trim()).map_err(io::Error::other)?;
    Ok(BootId(id.to_string()))
}

fn observe_error(e: io::Error) -> ObserveError {
    ObserveError::Os {
        code: i64::from(e.raw_os_error().unwrap_or(-1)),
        message: e.to_string(),
    }
}

struct MacBoot;
impl BootIdSource for MacBoot {
    fn current(&self) -> Result<BootId, ReclaimError> {
        boot().map_err(|e| ReclaimError::Indeterminate(e.to_string()))
    }
}

pub(crate) fn adapters(config: &OsConfig) -> Result<OsAdapters, OsError> {
    let observer = Arc::new(observe::MacObserver {
        run_dir: config.run_dir.clone(),
    });
    let reclaimers = [
        EffectKind::MacUtun,
        EffectKind::Route,
        EffectKind::MacFenceRule,
    ]
    .into_iter()
    .map(|kind| {
        Arc::new(reclaim::MacReclaimer {
            kind,
            observer: observer.clone(),
        }) as Arc<dyn Reclaimer>
    })
    .collect();
    Ok(OsAdapters {
        reclaimers,
        observer,
        sweeper: Arc::new(reclaim::MacSweep),
        boot_id: Arc::new(MacBoot),
        fence: nix::unistd::Uid::effective()
            .is_root()
            .then(|| Arc::new(fence::MacFence) as Arc<dyn PortFence>),
    })
}
