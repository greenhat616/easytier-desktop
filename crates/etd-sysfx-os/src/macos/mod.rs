//! Darwin observations, verify-only utun/route reclaim and the PF fence.
mod fence;
mod holders;
mod observe;
mod pf;
mod reclaim;

use crate::{OsAdapters, OsConfig, OsError};
use etd_sysfx::*;
use std::{
    io::{self, Read, Seek},
    os::unix::process::CommandExt,
    process::{Command, ExitStatus, Output},
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) use pf::{install_anchor, uninstall_anchor};

fn command(path: &str) -> Command {
    let mut cmd = Command::new(path);
    cmd.env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd
}

fn status(cmd: &mut Command, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    let mut child = cmd.process_group(0).spawn()?;
    let err = loop {
        match child.try_wait() {
            Ok(Some(s)) => return Ok(s),
            Err(e) => break e,
            Ok(None) if Instant::now() >= deadline => {
                break io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} timed out", cmd.get_program().to_string_lossy()),
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    // The unreaped child pins its PID and group. Terminate helpers as well;
    // wait for the actual pfctl before letting the caller drop its writer lock.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    child.wait()?;
    Err(err)
}
const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
fn capture(cmd: &mut Command) -> io::Result<Output> {
    // File-backed output cannot fill a pipe while we poll the deadline or
    // keep us blocked on a descendant's copy of the write end.
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let status = status(
        cmd.stdout(stdout.try_clone()?).stderr(stderr.try_clone()?),
        COMMAND_TIMEOUT,
    )?;
    stdout.rewind()?;
    stderr.rewind()?;
    let mut out = Output {
        status,
        stdout: vec![],
        stderr: vec![],
    };
    stdout.read_to_end(&mut out.stdout)?;
    stderr.read_to_end(&mut out.stderr)?;
    Ok(out)
}
fn output(cmd: &mut Command) -> io::Result<String> {
    let result = capture(cmd)?;
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
    let mut buf = [0u8; 64];
    let mut size = buf.len();
    // SAFETY: bounded output and size, no new value supplied.
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let value = std::ffi::CStr::from_bytes_until_nul(&buf[..size])
        .map_err(io::Error::other)?
        .to_str()
        .map_err(io::Error::other)?;
    let id = uuid::Uuid::parse_str(value).map_err(io::Error::other)?;
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
    // The kernel runs with this host's effective UID: 0 for the service,
    // the user's own UID for a user host.
    let uid = nix::unistd::Uid::effective();
    let cores = Arc::new(holders::CoreIdentity {
        store: config.core_store_dir.clone(),
        uid: uid.as_raw(),
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
            cores: cores.clone(),
        }) as Arc<dyn Reclaimer>
    })
    .collect();
    Ok(OsAdapters {
        reclaimers,
        observer,
        sweeper: Arc::new(reclaim::MacSweep),
        boot_id: Arc::new(MacBoot),
        fence: uid
            .is_root()
            .then(|| Arc::new(fence::MacFence(cores)) as Arc<dyn PortFence>),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timed_out_child_is_reaped_before_return() {
        let mut cmd = command("/bin/sleep");
        let err = status(cmd.arg("30"), Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
