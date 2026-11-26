//! Start-token based process identity and liveness checks. Owned by P1.
use crate::ProcessError;
use std::{
    io,
    path::{Path, PathBuf},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Fresh snapshot; do not reuse cached path, owner, or argv data after PID reuse.
///
/// Processes only: on Linux sysinfo would also list every thread as a process
/// of its own, and a thread exiting mid-scan (its `/proc/<tid>` gone while
/// its process lives) cannot be verified like a process.
pub(crate) fn snapshot(pids: ProcessesToUpdate<'_>) -> Result<System, ProcessError> {
    let mut system = System::new().map_err(|e| ProcessError::Enumeration(e.to_string()))?;
    system.refresh_processes_specifics(
        pids,
        true,
        ProcessRefreshKind::nothing()
            .without_tasks()
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

// Only kernel-defined minimal processes may bypass the unobservable-candidate
// rule. An ordinary user process is never excluded merely for a missing image.
#[cfg(any(target_os = "linux", test))]
fn linux_minimal(pid: u32, parent: Option<u32>, flags: Option<u64>) -> bool {
    const PF_KTHREAD: u64 = 0x0020_0000;
    match flags {
        Some(flags) => flags & PF_KTHREAD != 0,
        None => pid == 2 || parent == Some(2),
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_minimal(pid: u32) -> bool {
    pid == 0
}

#[cfg(any(windows, test))]
fn windows_minimal(
    pid: u32,
    name: &str,
    system_or_unknown: bool,
    image_observed: bool,
    argv_observed: bool,
) -> bool {
    if matches!(pid, 0 | 4) {
        return true;
    }
    !image_observed
        && !argv_observed
        && system_or_unknown
        && [
            "System",
            "Registry",
            "Memory Compression",
            "MemCompression",
            "Secure System",
            "System Idle Process",
            "Idle",
            "Pico Process",
            "Vmmem",
            "VmmemWSL",
        ]
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}

#[cfg(windows)]
pub(crate) fn query_access_denied(pid: u32) -> bool {
    use windows::Win32::{
        Foundation::{CloseHandle, ERROR_ACCESS_DENIED},
        System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    // SAFETY: query-only access, no synchronization/termination privileges.
    // A child spawned under this host's token is queryable; a denied query
    // is evidence of a different security context, unlike missing metadata.
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => {
            // SAFETY: unique handle from OpenProcess, closed once.
            let _ = unsafe { CloseHandle(handle) };
            false
        }
        Err(error) => error.code() == ERROR_ACCESS_DENIED.to_hresult(),
    }
}

/// Linux: a zombie thread-group leader whose other threads still run (it
/// left with `pthread_exit`). The process is not gone, and the snapshot lists
/// no threads, so it must stay a candidate.
#[cfg(target_os = "linux")]
pub(crate) fn leader_outlived(pid: u32) -> bool {
    std::fs::read_dir(format!("/proc/{pid}/task")).is_ok_and(|tasks| tasks.count() > 1)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn leader_outlived(_pid: u32) -> bool {
    false
}

pub(crate) fn minimal_process(process: &sysinfo::Process) -> bool {
    let pid = process.pid().as_u32();
    #[cfg(target_os = "linux")]
    {
        if process.exe().is_some() || !process.cmd().is_empty() {
            return false;
        }
        let flags = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(')')?
                    .1
                    .split_whitespace()
                    .nth(6)?
                    .parse()
                    .ok()
            });
        linux_minimal(pid, process.parent().map(|p| p.as_u32()), flags)
    }
    #[cfg(target_os = "macos")]
    {
        macos_minimal(pid)
    }
    #[cfg(windows)]
    {
        let system = "S-1-5-18".parse::<sysinfo::Uid>().ok();
        let system_or_unknown = process.user_id().is_none() || process.user_id() == system.as_ref();
        let name = process.name().to_string_lossy();
        if !windows_minimal(pid, &name, system_or_unknown, false, false) {
            return false;
        }
        // PID 0/4 are kernel-defined even when sysinfo returns pseudo-image
        // or argv labels (observed on the elevated Windows CI runner).
        // For named minimal/pico processes distinguish those labels from
        // actual paths/argv; never exclude an ordinary executable by name.
        let image_observed = process.exe().is_some_and(Path::is_absolute);
        // A space-separated kernel label (e.g. Memory Compression) can
        // be split into several tokens; a label alone is not a real argv.
        let argv_observed = !process.cmd().is_empty()
            && (process.cmd().iter().any(|arg| Path::new(arg).is_absolute())
                || !process
                    .cmd()
                    .iter()
                    .map(|arg| arg.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .eq_ignore_ascii_case(&name));
        windows_minimal(pid, &name, system_or_unknown, image_observed, argv_observed)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        false
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn cgroup_v2(pid: u32) -> io::Result<Option<PathBuf>> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    Ok(contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(PathBuf::from))
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn processkit_cgroup(path: &Path) -> Option<PathBuf> {
    let mut current = PathBuf::new();
    let mut domain = None;
    for component in path.components() {
        current.push(component.as_os_str());
        if component
            .as_os_str()
            .to_string_lossy()
            .starts_with("processkit-")
        {
            domain = Some(current.clone());
        }
    }
    domain
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

/// Independent kernel PID list. sysinfo silently omits a listed PID whose
/// image and argv it cannot read, so the marker sweep reconciles against it.
#[cfg(target_os = "macos")]
pub(crate) fn all_pids() -> io::Result<Vec<u32>> {
    list_pids_with(
        |buffer| match buffer {
            // SAFETY: a null buffer only asks for the current PID count estimate.
            None => unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) },
            Some(pids) => {
                let Ok(bytes) = libc::c_int::try_from(std::mem::size_of_val(pids)) else {
                    return -1;
                };
                // SAFETY: the kernel writes at most `bytes` bytes into `pids`.
                unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) }
            }
        },
        std::process::id(),
    )
}

/// Seam over libproc's `proc_listallpids` (`None` = sizing call). libproc
/// turns a failed `__proc_info` into 0, so a count <= 0 from either call is an
/// enumeration failure, never an empty system; a list without our own PID is
/// equally not a full list.
#[cfg(any(target_os = "macos", test))]
fn list_pids_with(
    mut list: impl FnMut(Option<&mut [i32]>) -> i32,
    own: u32,
) -> io::Result<Vec<u32>> {
    let failed = |call: &str, count: i32| {
        io::Error::other(format!(
            "proc_listallpids {call} returned {count}: {}",
            io::Error::last_os_error()
        ))
    };
    let mut capacity = list(None);
    if capacity <= 0 {
        return Err(failed("sizing", capacity));
    }
    loop {
        let mut pids = vec![0i32; usize::try_from(capacity).unwrap_or(0) + 64];
        let count = list(Some(&mut pids));
        if count <= 0 {
            return Err(failed("fill", count));
        }
        let count = usize::try_from(count).map_err(io::Error::other)?;
        // A full buffer may be truncated; never return a short list.
        if count < pids.len() {
            pids.truncate(count);
            let pids: Vec<u32> = pids
                .into_iter()
                .filter_map(|pid| u32::try_from(pid).ok())
                .collect();
            if !pids.contains(&own) {
                return Err(io::Error::other(
                    "kernel PID list does not contain the host process",
                ));
            }
            return Ok(pids);
        }
        capacity = i32::try_from(count.saturating_mul(2)).map_err(io::Error::other)?;
    }
}

/// Kernel state of a PID that the sysinfo snapshot omitted.
#[cfg(target_os = "macos")]
pub(crate) struct BsdState {
    pub(crate) zombie: bool,
    pub(crate) ruid: libc::uid_t,
    /// Kernel short name (`pbsi_comm`), for diagnostics only.
    pub(crate) name: String,
}

/// `Ok(None)` only for ESRCH; any other failure is "cannot look", not absence.
/// The short BSD info flavor carries no same-user check, so another user's
/// process yields its owner rather than EPERM. It does not look up zombies:
/// an unreaped zombie reports ESRCH (observed on macOS CI), i.e. `Ok(None)`.
#[cfg(target_os = "macos")]
pub(crate) fn bsd_state(pid: u32) -> io::Result<Option<BsdState>> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: proc_bsdshortinfo is plain old data; all-zero is a valid value.
    let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    let want = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdshortinfo>())
        .map_err(io::Error::other)?;
    // SAFETY: errno is thread-local; clear it so a short fill is not judged
    // by a stale value. proc_pidinfo writes at most `want` bytes into `info`.
    let got = unsafe {
        *libc::__error() = 0;
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDT_SHORTBSDINFO,
            0,
            std::ptr::addr_of_mut!(info).cast(),
            want,
        )
    };
    if got == want {
        return Ok(Some(BsdState {
            zombie: info.pbsi_status == libc::SZOMB,
            ruid: info.pbsi_ruid,
            name: info
                .pbsi_comm
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| char::from(c as u8))
                .collect(),
        }));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(None),
        Some(0) | None => Err(io::Error::other("short proc_bsdshortinfo read")),
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
    /// Image path of the pinned process, from the native API.
    pub(crate) fn image(&self) -> io::Result<PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        use windows::Win32::System::Threading::{PROCESS_NAME_WIN32, QueryFullProcessImageNameW};
        let mut buffer = vec![0u16; 32768];
        let mut length = 32768;
        // SAFETY: the buffer holds `length` UTF-16 units; the handle is owned
        // and grants limited query access.
        unsafe {
            QueryFullProcessImageNameW(
                self.0,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        }
        .map_err(io::Error::from)?;
        Ok(std::ffi::OsString::from_wide(&buffer[..length as usize]).into())
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

#[cfg(test)]
mod minimal_snapshot_tests {
    use super::*;

    #[test]
    fn linux_kernel_threads_do_not_become_unobservable_core_candidates() {
        assert!(linux_minimal(9, Some(2), Some(0x0020_0000)));
        assert!(linux_minimal(2, Some(0), None));
        assert!(linux_minimal(10, Some(2), None));
        // A PID namespace's PID 2 need not actually be a kernel thread.
        assert!(!linux_minimal(2, Some(1), Some(0)));
        assert!(!linux_minimal(99, Some(1), None));
    }

    #[test]
    fn macos_kernel_task_is_not_a_user_process() {
        assert!(macos_minimal(0));
        assert!(!macos_minimal(1));
        assert!(!macos_minimal(99));
    }

    #[test]
    fn windows_system_minimal_and_pico_snapshots_are_excluded() {
        for name in [
            "System",
            "Registry",
            "Memory Compression",
            "Secure System",
            "VmmemWSL",
            "Pico Process",
        ] {
            assert!(windows_minimal(14, name, true, false, false));
            assert!(!windows_minimal(14, name, false, false, false));
            assert!(!windows_minimal(14, name, true, true, false));
            assert!(!windows_minimal(14, name, true, false, true));
        }
        assert!(windows_minimal(4, "System", true, true, true));
        assert!(windows_minimal(0, "Idle", true, false, true));
        assert!(!windows_minimal(99, "System.exe", true, false, false));
        assert!(!windows_minimal(
            99,
            "easytier-core.exe",
            true,
            false,
            false
        ));
    }

    #[cfg(windows)]
    #[test]
    fn query_denial_is_not_inferred_from_own_process_or_absent_pid() {
        assert!(!query_access_denied(std::process::id()));
        assert!(!query_access_denied(2_000_000_000));
    }

    /// Scripted libproc: the sizing answer, then one answer per fill call.
    fn scripted(
        sizing: i32,
        fills: Vec<Vec<i32>>,
        fill_counts: Vec<i32>,
    ) -> impl FnMut(Option<&mut [i32]>) -> i32 {
        let mut call = 0;
        move |buffer| match buffer {
            None => sizing,
            Some(buffer) => {
                let pids = &fills[call];
                let n = pids.len().min(buffer.len());
                buffer[..n].copy_from_slice(&pids[..n]);
                call += 1;
                fill_counts[call - 1]
            }
        }
    }

    #[test]
    fn failed_or_empty_kernel_pid_list_is_an_error_not_an_empty_system() {
        // libproc reports a failed __proc_info as 0, not -1.
        for sizing in [0, -1] {
            assert!(list_pids_with(scripted(sizing, vec![], vec![]), 7).is_err());
        }
        for count in [0, -1] {
            assert!(list_pids_with(scripted(3, vec![vec![]], vec![count]), 7).is_err());
        }
        // A list that lacks the host itself is not a full list.
        assert!(list_pids_with(scripted(3, vec![vec![1, 5]], vec![2]), 7).is_err());
    }

    #[test]
    fn kernel_pid_list_retries_a_full_buffer_and_keeps_every_pid() {
        // The first buffer (3 + 64 slots) comes back full: possibly truncated.
        let full: Vec<i32> = (1..=67).collect();
        let pids = list_pids_with(scripted(3, vec![full, vec![1, 7, 99]], vec![67, 3]), 7).unwrap();
        assert_eq!(pids, vec![1, 7, 99]);
    }

    #[test]
    fn cgroup_membership_uses_processkit_subtree_not_ui_pgid() {
        let path = Path::new("/user.slice/processkit-12-abcd-1/nested");
        assert_eq!(
            processkit_cgroup(path).unwrap(),
            Path::new("/user.slice/processkit-12-abcd-1")
        );
        assert!(processkit_cgroup(Path::new("/user.slice/app.scope")).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshots_list_processes_not_threads() {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            // SAFETY: gettid has no preconditions and only reads the caller's id.
            let tid = unsafe { libc::gettid() };
            tid_tx.send(u32::try_from(tid).unwrap()).unwrap();
            let _ = done_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        let system = snapshot(ProcessesToUpdate::All).unwrap();
        // The worker runs beside the main thread: more than one task.
        assert!(leader_outlived(std::process::id()));
        done_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_ne!(tid, std::process::id());
        assert!(system.process(pid(std::process::id())).is_some());
        assert!(
            system.process(pid(tid)).is_none(),
            "thread {tid} listed as a process"
        );
    }
}
