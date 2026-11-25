//! Start-token based process identity and liveness checks. Owned by P1.
use crate::ProcessError;
use std::{
    io,
    path::{Path, PathBuf},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Fresh snapshot; do not reuse cached path, owner, or argv data after PID reuse.
pub(crate) fn snapshot(pids: ProcessesToUpdate<'_>) -> Result<System, ProcessError> {
    let mut system = System::new().map_err(|e| ProcessError::Enumeration(e.to_string()))?;
    system.refresh_processes_specifics(
        pids,
        true,
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );
    Ok(system)
}

pub(crate) fn pid(n: u32) -> Pid {
    Pid::from_u32(n)
}

pub(crate) fn normalized(path: &Path) -> io::Result<PathBuf> {
    path.canonicalize()
}

/// Require a path component boundary; a substring, a sibling with a common
/// prefix, or an unresolved `..` never qualifies as a marker.
pub(crate) fn under(path: &Path, root: &Path) -> bool {
    if !path.is_absolute() || !root.is_absolute() {
        return false;
    }
    match (normalized(path), normalized(root)) {
        (Ok(path), Ok(root)) => path.starts_with(root),
        _ => {
            !path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
                && path.starts_with(root)
        }
    }
}

pub(crate) fn token(raw: u64) -> io::Result<String> {
    // Linux start ticks restart at boot: include the boot identifier.
    #[cfg(target_os = "linux")]
    {
        Ok(format!(
            "{}:{raw}",
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(raw.to_string())
    }
}

#[cfg(unix)]
pub(crate) fn process_group(pid: u32) -> io::Result<i32> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    if pid <= 0 {
        return Err(io::Error::other("invalid process id"));
    }
    // SAFETY: read-only query of this positive process ID.
    let pgid = unsafe { libc::getpgid(pid) };
    if pgid < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(pgid)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn signal_verified_orphan(pid: u32, group: bool) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    if pid <= 1 {
        return Err(io::Error::other("invalid orphan target"));
    }
    // SAFETY: caller has just verified start time, image, owner, argv and
    // (for group=true) the kernel's own process group. macOS has no pidfd;
    // the human-approved verify-to-signal TOCTOU remains Apple-only.
    if unsafe { libc::kill(if group { -pid } else { pid }, libc::SIGKILL) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn group_absent(group: i32) -> io::Result<bool> {
    if group <= 1 {
        return Err(io::Error::other("invalid group"));
    }
    // SAFETY: signal 0 is only a read-only existence/permission probe.
    if unsafe { libc::kill(-group, 0) } == 0 {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(true),
        Some(libc::EPERM) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(unix)]
pub(crate) fn pid_absent(pid: u32) -> io::Result<bool> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    if pid <= 0 {
        return Err(io::Error::other("invalid process id"));
    }
    // SAFETY: signal 0 is an existence/permission probe; it delivers no signal.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(true),
        Some(libc::EPERM) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(windows)]
pub(crate) struct Pin(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Pin {
    pub(crate) fn open(pid: u32, terminate: bool) -> io::Result<Self> {
        use windows::Win32::System::Threading::*;
        let mut rights = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
        if terminate {
            rights |= PROCESS_TERMINATE;
        }
        // SAFETY: requested rights are limited to query / termination of this object.
        unsafe { OpenProcess(rights, false, pid) }
            .map(Self)
            .map_err(io::Error::from)
    }
    pub(crate) fn stop(&self) -> io::Result<()> {
        // SAFETY: the caller verified this pinned process; the handle is owned.
        unsafe { windows::Win32::System::Threading::TerminateProcess(self.0, 1) }
            .map_err(io::Error::from)
    }
    pub(crate) fn gone(&self) -> bool {
        // SAFETY: we hold a process handle with SYNCHRONIZE access.
        (unsafe { windows::Win32::System::Threading::WaitForSingleObject(self.0, 0) })
            == windows::Win32::Foundation::WAIT_OBJECT_0
    }
}

#[cfg(windows)]
impl Drop for Pin {
    fn drop(&mut self) {
        // SAFETY: OpenProcess returned this unique owned handle.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Pin(std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl Pin {
    pub(crate) fn open(pid: u32, _terminate: bool) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        let pid = i32::try_from(pid).map_err(io::Error::other)?;
        if pid <= 0 {
            return Err(io::Error::other("invalid process id"));
        }
        // SAFETY: pidfd_open takes an integer PID, flags=0 and returns a new fd.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful pidfd_open returns a unique owned descriptor.
        Ok(Self(unsafe {
            std::os::fd::OwnedFd::from_raw_fd(fd as i32)
        }))
    }
    pub(crate) fn stop(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: own pidfd; no siginfo supplied, flags=0. Never targets a new PID occupant.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(crate) fn gone(&self) -> bool {
        use std::os::fd::AsRawFd;
        let mut fd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, non-blocking poll.
        (unsafe { libc::poll(&mut fd, 1, 0) }) > 0 && fd.revents & libc::POLLIN != 0
    }
}
