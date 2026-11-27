//! One protected PowerShell execution environment. The management script is
//! constant; only JSON requests reach it, one per line on its standard input.
//!
//! The environment is explicit, never inherited. Under an elevated host that
//! is not SYSTEM (the elevated session) every user profile, HKCU and
//! environment input is untrusted (doc#13#untrusted): the profile variables
//! point at the protected, empty profile directory of the session tree,
//! the script imports its modules by absolute path with autoloading off,
//! and the CLR profiler is switched off in the environment.
//!
//! The last is defence in depth, not a fix: the .NET Framework runtime also
//! reads its settings from the user's HKCU\Software\Microsoft\.NETFramework,
//! which the user's non-elevated processes can write. The environment takes
//! precedence, which neutralises the profiler (shown on the CI runner: with
//! the HKCU profiler settings an elevated PowerShell tries to load the
//! profiler DLL, with COR_ENABLE_PROFILING=0 it does not). Other runtime
//! settings in HKCU are not neutralised; that list is not closed.
use super::{
    WinError, encoded_command,
    token::{self, HostToken},
};
use serde_json::Value;
use std::os::windows::io::AsRawHandle;
use std::{
    ffi::OsString,
    io::{Read, Seek, SeekFrom},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf, Prefix},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The protected directory the children of an elevated non-SYSTEM host get
/// as their profile; set by `adapters()`.
static WORKER_PROFILE: std::sync::RwLock<Option<PathBuf>> = std::sync::RwLock::new(None);

pub(super) fn set_worker_profile(profile: Option<PathBuf>) {
    *WORKER_PROFILE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = profile;
}

/// FILE_ATTRIBUTE_REPARSE_POINT.
const REPARSE_POINT: u32 = 0x400;

/// Access rights that let a principal change a directory, its security or
/// its entries: FILE_WRITE_DATA (add file), FILE_APPEND_DATA (add
/// subdirectory), FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
/// DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
const WRITE_RIGHTS: u32 = 0x0002
    | 0x0004
    | 0x0010
    | 0x0040
    | 0x0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;

/// The protection of `path`: whether its owner is SYSTEM or Administrators
/// (a non-elevated process cannot arrange that), and whether its DACL lets
/// only SYSTEM and Administrators write. Any allow entry with a write right
/// for another principal, a null DACL or an entry of another type refuses.
fn protection(path: &Path) -> Result<(bool, bool), WinError> {
    use ::windows::{
        Win32::{
            Foundation::{HLOCAL, LocalFree},
            Security::{
                ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
                Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
                DACL_SECURITY_INFORMATION, GetAce, IsValidSid, IsWellKnownSid,
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
                WinBuiltinAdministratorsSid, WinLocalSystemSid,
            },
        },
        core::HSTRING,
    };
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the out pointers are valid; the owner SID and the DACL point
    // into the descriptor the call allocates, freed after their last use.
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
        .ok()
        .map_err(WinError::windows)?;
        let privileged = |sid: PSID| {
            IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
        };
        let owner_privileged = !owner.0.is_null() && privileged(owner);
        let mut admin_writes = !dacl.is_null();
        if admin_writes {
            for index in 0..(*dacl).AceCount as u32 {
                let mut ace = std::ptr::null_mut();
                if GetAce(dacl, index, &mut ace).is_err() {
                    admin_writes = false;
                    break;
                }
                let header = ace.cast::<ACE_HEADER>().read_unaligned();
                match header.AceType {
                    // ACCESS_DENIED: never grants anything.
                    1 => {}
                    // ACCESS_ALLOWED: write rights only for SYSTEM and
                    // Administrators.
                    0 if usize::from(header.AceSize) >= size_of::<ACCESS_ALLOWED_ACE>() => {
                        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>().read_unaligned();
                        let sid = PSID(
                            ace.cast::<u8>()
                                .add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                                .cast(),
                        );
                        if !IsValidSid(sid).as_bool()
                            || (allowed.Mask & WRITE_RIGHTS != 0 && !privileged(sid))
                        {
                            admin_writes = false;
                            break;
                        }
                    }
                    _ => {
                        admin_writes = false;
                        break;
                    }
                }
            }
        }
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        Ok((owner_privileged, admin_writes))
    }
}

/// Whether `path` is owned by SYSTEM or Administrators.
#[cfg(test)]
fn privileged_owner(path: &Path) -> Result<bool, WinError> {
    Ok(protection(path)?.0)
}

/// `path` without a `\\?\` prefix, for comparing paths.
fn plain(path: &Path) -> String {
    let text = path.to_string_lossy();
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
}

/// `path` with every short (8.3) component expanded. Links and junctions
/// are not followed.
fn long_path(path: &Path) -> Result<PathBuf, WinError> {
    use ::windows::{Win32::Storage::FileSystem::GetLongPathNameW, core::HSTRING};
    use std::os::windows::ffi::OsStringExt;
    let wide = HSTRING::from(path.as_os_str());
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: `wide` is NUL-terminated; the buffer is writable for its
        // length.
        let n = unsafe { GetLongPathNameW(&wide, Some(&mut buffer)) } as usize;
        if n == 0 {
            return Err(WinError::windows(::windows::core::Error::from_thread()));
        }
        if n < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..n])));
        }
        buffer.resize(n, 0);
    }
}

/// The protected profile directory, or why it is refused: a plain
/// directory owned by SYSTEM or Administrators whose DACL lets no one else
/// write, and whose final path (all links and junctions resolved) is the
/// path itself, so no ancestor redirects it.
fn protected_profile_vars(profile: &Path) -> Result<Vec<(OsString, OsString)>, WinError> {
    let vars = profile_vars(profile)?;
    let refused = |why: &str| {
        WinError::invalid(format!(
            "worker profile directory {}: {why}",
            profile.display()
        ))
    };
    let (owner, writes) = protection(profile)?;
    if !owner {
        return Err(refused("not owned by SYSTEM or Administrators"));
    }
    if !writes {
        return Err(refused("writable by others than SYSTEM and Administrators"));
    }
    let resolved = std::fs::canonicalize(profile).map_err(|e| refused(&e.to_string()))?;
    // Short (8.3) names are aliases, not links: compare long forms.
    let long = long_path(profile).map_err(|e| refused(&e.message))?;
    if !plain(&resolved).eq_ignore_ascii_case(&plain(&long)) {
        return Err(refused(&format!(
            "resolves to {} (a link or junction on the path)",
            resolved.display()
        )));
    }
    Ok(vars)
}

/// The profile variables pointing at `profile`, which must be an existing
/// plain directory (not a reparse point) on an absolute drive path. It is
/// neither created nor repaired here; the composition root made and
/// verified it. The module analysis cache is turned off (an invalid path,
/// as documented in about_Environment_Variables) rather than redirected.
fn profile_vars(profile: &Path) -> Result<Vec<(OsString, OsString)>, WinError> {
    use std::os::windows::fs::MetadataExt;
    let refused = |why: &str| {
        WinError::invalid(format!(
            "worker profile directory {}: {why}",
            profile.display()
        ))
    };
    let mut components = profile.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                format!("{}:", char::from(letter))
            }
            _ => return Err(refused("not on a drive path")),
        },
        _ => return Err(refused("not absolute")),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(refused("not absolute"));
    }
    let mut rest = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(name) => rest.push(name),
            _ => return Err(refused("not a normalised path")),
        }
    }
    if rest.as_os_str().is_empty() {
        return Err(refused("a drive root"));
    }
    let metadata = std::fs::symlink_metadata(profile).map_err(|e| refused(&e.to_string()))?;
    if !metadata.is_dir() || metadata.file_attributes() & REPARSE_POINT != 0 {
        return Err(refused("not a plain directory"));
    }
    let full = PathBuf::from(format!("{drive}\\")).join(&rest);
    let mut home = OsString::from("\\");
    home.push(rest.as_os_str());
    Ok(vec![
        ("APPDATA".into(), full.clone().into_os_string()),
        ("HOMEDRIVE".into(), drive.into()),
        ("HOMEPATH".into(), home),
        ("LOCALAPPDATA".into(), full.clone().into_os_string()),
        ("PSModuleAnalysisCachePath".into(), "NUL".into()),
        ("USERPROFILE".into(), full.into_os_string()),
    ])
}

pub(super) struct Environment {
    pub exe: PathBuf,
    pub cwd: PathBuf,
    vars: Vec<(OsString, OsString)>,
}
impl Environment {
    pub fn new() -> Result<Self, WinError> {
        Self::for_host(token::host_token()?)
    }
    fn for_host(host: HostToken) -> Result<Self, WinError> {
        let mut buf = [0u16; 32768];
        let n = unsafe {
            ::windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut buf))
        } as usize;
        if n == 0 || n >= buf.len() {
            return Err(WinError::invalid("GetSystemDirectoryW failed"));
        }
        let cwd = PathBuf::from(OsString::from_wide(&buf[..n]));
        let root = cwd
            .parent()
            .ok_or_else(|| WinError::invalid("invalid system directory"))?;
        let ps = cwd.join("WindowsPowerShell/v1.0");
        let path =
            std::env::join_paths([&cwd, &ps]).map_err(|e| WinError::invalid(e.to_string()))?;
        let mut vars: Vec<(OsString, OsString)> = vec![
            ("ComSpec".into(), cwd.join("cmd.exe").into_os_string()),
            ("Path".into(), path),
            ("PSModulePath".into(), ps.join("Modules").into_os_string()),
            ("SystemRoot".into(), root.as_os_str().to_owned()),
            ("TEMP".into(), root.join("Temp").into_os_string()),
            ("TMP".into(), root.join("Temp").into_os_string()),
            ("windir".into(), root.as_os_str().to_owned()),
        ];
        if host == HostToken::Elevated {
            vars.push(("COR_ENABLE_PROFILING".into(), "0".into()));
            let profile = WORKER_PROFILE
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(profile) = profile {
                match std::fs::symlink_metadata(&profile) {
                    // No session tree. Meant only for an elevated
                    // administrator's command over the service layout (for
                    // example `etd-host uninstall`): no profile variables
                    // at all, as before; never the user's own profile. The
                    // elevated session host never gets here: it refuses to
                    // start, before adapters(), unless <SID>\profile exists
                    // and passes verify_tree (ES3, topic#51 msg#1722).
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    // Present: it must be the protected directory, or fail
                    // closed. A non-elevated process cannot make a
                    // directory owned by SYSTEM or Administrators.
                    _ => {
                        vars.extend(protected_profile_vars(&profile)?);
                    }
                }
            }
        }
        // The block for CreateProcessAsUserW must be sorted.
        vars.sort_by_key(|(name, _)| name.to_ascii_uppercase());
        Ok(Self {
            exe: ps.join("powershell.exe"),
            cwd,
            vars,
        })
    }
    pub fn block(&self) -> Vec<u16> {
        // Windows requires a case-insensitively sorted, double-NUL terminated
        // Unicode environment block for CreateProcessAsUserW.
        let mut out = Vec::new();
        for (name, value) in &self.vars {
            out.extend(name.encode_wide());
            out.push(b'=' as u16);
            out.extend(value.encode_wide());
            out.push(0);
        }
        out.push(0);
        out
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.exe);
        cmd.env_clear()
            .envs(self.vars.iter().map(|(k, v)| (k, v)))
            .current_dir(&self.cwd)
            .creation_flags(0x08000000);
        cmd
    }
}

/// The management script as it is sent: without whole-line comments,
/// indentation and blank lines, none of which PowerShell needs (the script
/// has no here-strings or line continuations). The encoded command line is
/// limited to 32767 characters.
fn script() -> String {
    include_str!("system.ps1")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn io_error(e: std::io::Error) -> WinError {
    WinError::new(e.raw_os_error().unwrap_or(-1) as i64, e.to_string())
}

/// Deadline of one management request, from handing it to the worker to its
/// whole response line.
const DEADLINE: Duration = Duration::from_secs(60);
/// An idle worker is ended after this long.
const IDLE: Duration = Duration::from_secs(3);
/// Idle workers kept at most.
const POOL_MAX: usize = 4;
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;
/// How long [`shutdown`] lets calls in progress finish.
const DRAIN: Duration = Duration::from_secs(2);
/// How long [`shutdown`] waits, after terminating the job, for every worker
/// process to be gone.
const CONFIRM: Duration = Duration::from_secs(5);
/// The longest [`shutdown`] can take: one deadline for the whole wind-down.
pub(crate) const SHUTDOWN_WORST: Duration =
    Duration::from_secs(DRAIN.as_secs() + CONFIRM.as_secs());

/// The host-owned job every worker runs in. KILL_ON_JOB_CLOSE: no worker
/// outlives the host process, whatever way it ends.
struct Job(::windows::Win32::Foundation::HANDLE);
// SAFETY: a job handle is a kernel handle, usable from any thread.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}
impl Job {
    fn new() -> Result<Self, WinError> {
        use ::windows::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        let job = Self(
            unsafe { CreateJobObjectW(None, ::windows::core::PCWSTR::null()) }
                .map_err(WinError::windows)?,
        );
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(WinError::windows)?;
        Ok(job)
    }

    fn assign(&self, child: &std::process::Child) -> Result<(), WinError> {
        unsafe {
            ::windows::Win32::System::JobObjects::AssignProcessToJobObject(
                self.0,
                ::windows::Win32::Foundation::HANDLE(child.as_raw_handle()),
            )
        }
        .map_err(|e| {
            WinError::new(
                e.code().0 as i64,
                format!(
                    "cannot place the management PowerShell in the host's job object \
                     (is the host itself in a job that forbids nested jobs?): {}",
                    e.message()
                ),
            )
        })
    }

    fn active(&self) -> Result<u32, WinError> {
        use ::windows::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                Some(self.0),
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
        }
        .map_err(WinError::windows)?;
        Ok(info.ActiveProcesses)
    }

    /// Terminate every process of the job and wait, until `until`, for
    /// none to be left.
    fn terminate(&self, until: Instant) -> Result<(), WinError> {
        unsafe { ::windows::Win32::System::JobObjects::TerminateJobObject(self.0, 1) }
            .map_err(WinError::windows)?;
        loop {
            let active = self.active()?;
            if active == 0 {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(WinError::invalid(format!(
                    "{active} management process(es) still alive after termination"
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        let _ = unsafe { ::windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// What the worker's I/O threads report.
enum Event {
    Line(String),
    /// The request could not be written: it never reached the script.
    WriteFailed(WinError),
    ReadFailed(WinError),
    /// stdout closed: the worker exited.
    Eof,
}

/// A warm management PowerShell: the constant script in serve mode, one
/// JSON request per stdin line and one JSON response per stdout line.
/// Starting PowerShell and loading its networking modules costs seconds per
/// process; a reclaim or sweep issues dozens of requests, so a request
/// reuses an idle worker instead of starting a process of its own.
struct Worker {
    child: std::process::Child,
    /// To the writer thread, which owns stdin; dropping it closes stdin.
    requests: Option<std::sync::mpsc::Sender<String>>,
    events: std::sync::mpsc::Receiver<Event>,
    stderr: std::fs::File,
    idle_since: Instant,
    /// The job generation the worker runs in.
    generation: u64,
    /// Served a request before (taken from the pool).
    reused: bool,
}

/// Why a call failed.
struct Failure {
    error: WinError,
    /// The worker may serve again (the script refused the request).
    healthy: bool,
    /// The request reached the script (or may have).
    delivered: bool,
}

#[derive(Default)]
struct Pool {
    idle: Vec<Worker>,
    /// Calls in progress.
    busy: usize,
    /// The job new workers join.
    job: Option<std::sync::Arc<Job>>,
    generation: u64,
    /// Set first by [`shutdown`]: no worker or job is created any more.
    closed: bool,
}

static POOL: std::sync::Mutex<Pool> = std::sync::Mutex::new(Pool {
    idle: Vec::new(),
    busy: 0,
    job: None,
    generation: 0,
    closed: false,
});
static CALLS_DONE: std::sync::Condvar = std::sync::Condvar::new();

fn pool() -> std::sync::MutexGuard<'static, Pool> {
    POOL.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Ends idle workers past [`IDLE`]; started with the first worker.
fn start_reaper() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("etd-ps-reaper".into())
            .spawn(|| {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    let expired: Vec<Worker> = {
                        let mut pool = pool();
                        let (old, keep) = std::mem::take(&mut pool.idle)
                            .into_iter()
                            .partition(|w| w.idle_since.elapsed() >= IDLE);
                        pool.idle = keep;
                        old
                    };
                    for worker in expired {
                        worker.end();
                    }
                }
            });
    });
}

impl Worker {
    fn spawn(job: &Job, generation: u64) -> Result<Self, WinError> {
        let env = Environment::new()?;
        // stderr stays file-backed: nothing has to drain it.
        let stderr = tempfile::tempfile().map_err(io_error)?;
        let mut cmd = env.command();
        cmd.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_command(&script()),
        ])
        .env("ETD_OS_SERVE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr.try_clone().map_err(io_error)?));
        let mut child = cmd.spawn().map_err(io_error)?;
        // Until it is in the job, the worker could outlive a host that dies
        // right now. Nothing can be delivered to it in that window: its stdin
        // is handed to the writer thread only below, so it would read EOF
        // and exit without doing anything.
        if let Err(e) = job.assign(&child) {
            let _ = reap(&mut child);
            return Err(e);
        }
        let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = reap(&mut child);
            return Err(WinError::invalid("management worker pipes missing"));
        };
        let (events_tx, events) = std::sync::mpsc::channel();
        let (requests, requests_rx) = std::sync::mpsc::channel::<String>();
        let failed = events_tx.clone();
        // A blocking write (the script not reading) holds only this thread;
        // the caller's deadline still runs.
        let writer = std::thread::Builder::new()
            .name("etd-ps-writer".into())
            .spawn(move || {
                use std::io::Write;
                for line in requests_rx {
                    let written = stdin
                        .write_all(line.as_bytes())
                        .and_then(|()| stdin.write_all(b"\n"))
                        .and_then(|()| stdin.flush());
                    if let Err(e) = written {
                        let _ = failed.send(Event::WriteFailed(io_error(e)));
                        return;
                    }
                }
            });
        // Ends with the pipe: when the worker exits or is killed.
        let reader = std::thread::Builder::new()
            .name("etd-ps-reader".into())
            .spawn(move || {
                use std::io::BufRead;
                let mut reader = std::io::BufReader::new(stdout);
                loop {
                    let mut line = Vec::new();
                    let read = (&mut reader)
                        .take(MAX_OUTPUT + 1)
                        .read_until(b'\n', &mut line);
                    let event = match read {
                        Ok(0) => Event::Eof,
                        Ok(_) if line.len() as u64 > MAX_OUTPUT => {
                            Event::ReadFailed(WinError::invalid("management response too large"))
                        }
                        Ok(_) => Event::Line(String::from_utf8_lossy(&line).into_owned()),
                        Err(e) => Event::ReadFailed(io_error(e)),
                    };
                    let last = !matches!(event, Event::Line(_));
                    if events_tx.send(event).is_err() || last {
                        break;
                    }
                }
            });
        if let Err(e) = writer.and(reader) {
            let _ = reap(&mut child);
            return Err(io_error(e));
        }
        start_reaper();
        Ok(Self {
            child,
            requests: Some(requests),
            events,
            stderr,
            idle_since: Instant::now(),
            generation,
            reused: false,
        })
    }

    fn call(&mut self, request: &Value, deadline: Duration) -> Result<Vec<Value>, Failure> {
        let unhealthy = |error, delivered| Failure {
            error,
            healthy: false,
            delivered,
        };
        // A worker that died while idle never sees the request.
        if !matches!(self.child.try_wait(), Ok(None)) {
            return Err(unhealthy(
                WinError::invalid("management worker exited while idle"),
                false,
            ));
        }
        let sent = self
            .requests
            .as_ref()
            .is_some_and(|requests| requests.send(ascii_json(request)).is_ok());
        if !sent {
            return Err(unhealthy(
                WinError::invalid("management worker closed"),
                false,
            ));
        }
        let response = match self.events.recv_timeout(deadline) {
            Ok(Event::Line(line)) => line,
            Ok(Event::WriteFailed(e)) => return Err(unhealthy(e, false)),
            Ok(Event::ReadFailed(e)) => return Err(unhealthy(e, true)),
            Ok(Event::Eof) => {
                return Err(unhealthy(
                    WinError::invalid("management worker exited"),
                    true,
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(unhealthy(
                    WinError::invalid("management worker exited"),
                    true,
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(unhealthy(
                    WinError::invalid(
                        "Windows management query timed out; child killed and reaped",
                    ),
                    true,
                ));
            }
        };
        let mut response: Value = serde_json::from_str(&response).map_err(|e| {
            unhealthy(
                WinError::invalid(format!("invalid management response: {e}")),
                true,
            )
        })?;
        if let Some(message) = response["error"].as_str() {
            return Err(Failure {
                error: WinError::new(1, message.trim()),
                healthy: true,
                delivered: true,
            });
        }
        response["result"]
            .as_array_mut()
            .map(std::mem::take)
            .ok_or_else(|| unhealthy(WinError::invalid("missing management result"), true))
    }

    /// The only way a broken worker goes: killed and reaped, and the error
    /// completed with what it wrote to stderr. Reaping that cannot be
    /// confirmed replaces the error (the job still ends it with the host).
    fn discard(mut self, error: WinError) -> WinError {
        self.requests = None;
        if let Err(e) = reap(&mut self.child) {
            return e;
        }
        let mut text = String::new();
        let _ = self.stderr.seek(SeekFrom::Start(0));
        let _ = (&mut self.stderr).take(64 * 1024).read_to_string(&mut text);
        match text.trim() {
            "" => error,
            text => WinError::new(error.code, format!("{}: {text}", error.message)),
        }
    }

    /// An idle worker goes: closing stdin ends its serve loop; it is killed
    /// and reaped in case it does not.
    fn end(mut self) {
        self.requests = None;
        if let Err(e) = reap(&mut self.child) {
            tracing::warn!(error = %e.message, "idle management worker not reaped");
        }
    }
}

/// Kill and reap within a bounded wait.
fn reap(child: &mut std::process::Child) -> Result<(), WinError> {
    let killed = child.kill();
    let wait = unsafe {
        ::windows::Win32::System::Threading::WaitForSingleObject(
            ::windows::Win32::Foundation::HANDLE(child.as_raw_handle()),
            5000,
        )
    };
    if wait != ::windows::Win32::Foundation::WAIT_OBJECT_0 {
        return Err(WinError::invalid(format!(
            "PowerShell termination unconfirmed after deadline: {killed:?}"
        )));
    }
    child.wait().map(|_| ()).map_err(io_error)
}

/// The request as one line of pure ASCII JSON (non-ASCII as `\uXXXX`), so
/// the console input encoding of the worker cannot alter it.
fn ascii_json(request: &Value) -> String {
    let text = request.to_string();
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// An idle worker, or a new one in the current job.
fn checkout() -> Result<Worker, WinError> {
    let (job, generation) = {
        let mut pool = pool();
        if pool.closed {
            return Err(WinError::invalid(
                "system management is shut down: the host is stopping",
            ));
        }
        pool.busy += 1;
        if let Some(mut worker) = pool.idle.pop() {
            worker.reused = true;
            return Ok(worker);
        }
        if pool.job.is_none() {
            match Job::new() {
                Ok(job) => pool.job = Some(std::sync::Arc::new(job)),
                Err(e) => {
                    pool.busy -= 1;
                    CALLS_DONE.notify_all();
                    return Err(e);
                }
            }
        }
        (pool.job.clone(), pool.generation)
    };
    // Counted busy from here: shutdown waits for this spawn too.
    let spawned = match job {
        Some(job) => Worker::spawn(&job, generation),
        None => Err(WinError::invalid("management job missing")),
    };
    let worker = match spawned {
        Ok(worker) => worker,
        Err(e) => {
            let mut pool = pool();
            pool.busy -= 1;
            CALLS_DONE.notify_all();
            return Err(e);
        }
    };
    if admits(&pool(), &worker) {
        return Ok(worker);
    }
    // Shutdown began while it was starting: it serves nothing. It is ended
    // before the call counts as done, so shutdown's wait covers it.
    let _ = worker.discard(WinError::invalid("shut down"));
    let mut pool = pool();
    pool.busy -= 1;
    CALLS_DONE.notify_all();
    Err(WinError::invalid(
        "system management is shut down: the host is stopping",
    ))
}

/// A freshly started worker serves only if shutdown has not begun since
/// it was admitted (same generation, admission still open).
fn admits(pool: &Pool, worker: &Worker) -> bool {
    !pool.closed && worker.generation == pool.generation
}

/// Back to the pool (healthy, current job, room left) or ended.
fn checkin(worker: Option<Worker>) {
    let mut pool = pool();
    pool.busy -= 1;
    CALLS_DONE.notify_all();
    let Some(mut worker) = worker else {
        return;
    };
    worker.idle_since = Instant::now();
    if worker.generation == pool.generation && pool.idle.len() < POOL_MAX {
        pool.idle.push(worker);
    } else {
        drop(pool);
        worker.end();
    }
}

pub fn run(request: Value) -> Result<Vec<Value>, WinError> {
    // The script's diagnostics report exists for the CI fixtures only.
    if !cfg!(feature = "ci-test-fixtures") && request["op"] == "diagnostics" {
        return Err(WinError::invalid(
            "the diagnostics request is only for CI fixtures",
        ));
    }
    // One retry, only for a request that never reached a reused worker
    // (it died while idle): delivering it to a fresh one is safe.
    let mut retried = false;
    loop {
        let mut worker = checkout()?;
        match worker.call(&request, DEADLINE) {
            Ok(rows) => {
                checkin(Some(worker));
                return Ok(rows);
            }
            Err(Failure {
                error,
                healthy: true,
                ..
            }) => {
                checkin(Some(worker));
                return Err(error);
            }
            Err(Failure {
                error, delivered, ..
            }) => {
                let reused = worker.reused;
                let error = worker.discard(error);
                checkin(None);
                if delivered || !reused || retried {
                    return Err(error);
                }
                retried = true;
            }
        }
    }
}

/// Host shutdown: end every management worker before the host gives up its
/// singleton lock, within [`SHUTDOWN_WORST`] in all. Admission closes first:
/// no request starts a worker or a job afterwards, and none is retried.
/// Idle workers have stdin closed and are killed; calls in progress get
/// [`DRAIN`] to finish; then the job is terminated and the exit of every
/// process in it confirmed, and every admitted call (a worker still
/// starting included) must have returned. `Err`: some may still run (the
/// caller keeps the affected records open, as they are, and its lock).
pub fn shutdown() -> Result<(), WinError> {
    let started = Instant::now();
    let (idle, job) = {
        let mut pool = pool();
        pool.closed = true;
        pool.generation += 1;
        (std::mem::take(&mut pool.idle), pool.job.take())
    };
    // No waiting per worker: the job's termination below confirms them all
    // under the one deadline.
    for mut worker in idle {
        worker.requests = None;
        let _ = worker.child.kill();
    }
    let drained = started + DRAIN;
    let mut pool = pool();
    while pool.busy > 0 {
        let left = drained.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        pool = CALLS_DONE
            .wait_timeout(pool, left)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
    let busy = pool.busy;
    drop(pool);
    let deadline = started + SHUTDOWN_WORST;
    let result = match job {
        Some(job) => job.terminate(deadline),
        None => Ok(()),
    }
    .and_then(|()| settle(deadline));
    match (&result, busy) {
        (Ok(()), 0) => {}
        (Ok(()), n) => tracing::warn!(
            calls = n,
            "management calls still running at shutdown were terminated"
        ),
        (Err(e), _) => tracing::error!(
            error = %e.message,
            "management workers could not be confirmed gone; open records stay open"
        ),
    }
    result
}

/// Wait until `deadline` for every admitted call to return: a call whose
/// worker was terminated returns at once, a worker still starting ends
/// itself (see [`admits`]).
fn settle(deadline: Instant) -> Result<(), WinError> {
    let mut pool = pool();
    while pool.busy > 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(WinError::invalid(format!(
                "{} management call(s) still in progress at shutdown",
                pool.busy
            )));
        }
        pool = CALLS_DONE
            .wait_timeout(pool, left)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Workers of an elevated test process (the CI runner) need a profile
    /// directory, as under the elevated session host.
    fn test_profile() {
        static PROFILE: std::sync::OnceLock<(tempfile::TempDir, PathBuf)> =
            std::sync::OnceLock::new();
        let (_, path) = PROFILE.get_or_init(protected_dir);
        set_worker_profile(Some(path.clone()));
    }

    /// A temporary directory under its final path, with the session tree's
    /// DACL (SYSTEM and Administrators only) when this process is elevated:
    /// only then is it owned by Administrators and can keep access.
    fn protected_dir() -> (tempfile::TempDir, PathBuf) {
        use ::windows::{
            Win32::{
                Foundation::{HLOCAL, LocalFree},
                Security::{
                    Authorization::{
                        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                        SE_FILE_OBJECT, SetNamedSecurityInfoW,
                    },
                    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
                    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
                },
            },
            core::HSTRING,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = PathBuf::from(plain(&std::fs::canonicalize(dir.path()).unwrap()));
        if privileged_owner(&path).unwrap() {
            unsafe {
                let mut sd = PSECURITY_DESCRIPTOR::default();
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    &HSTRING::from("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )
                .unwrap();
                let mut present = false.into();
                let mut defaulted = false.into();
                let mut dacl = std::ptr::null_mut();
                GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).unwrap();
                SetNamedSecurityInfoW(
                    &HSTRING::from(path.as_os_str()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(dacl),
                    None,
                )
                .ok()
                .unwrap();
                let _ = LocalFree(Some(HLOCAL(sd.0)));
            }
        }
        (dir, path)
    }

    fn fresh() -> Worker {
        test_profile();
        let job = Job::new().unwrap();
        let worker = Worker::spawn(&job, u64::MAX).unwrap();
        // The test keeps the job alive by leaking it with the worker.
        std::mem::forget(job);
        worker
    }

    #[test]
    fn management_timeout_kills_and_reaps() {
        let mut worker = fresh();
        // PowerShell cannot even start within 1 ms.
        let failure = worker
            .call(&serde_json::json!({"op":"magic"}), Duration::from_millis(1))
            .unwrap_err();
        assert!(!failure.healthy && failure.delivered);
        assert!(
            failure.error.message.contains("killed and reaped"),
            "{}",
            failure.error.message
        );
        let error = worker.discard(failure.error);
        assert!(
            error.message.contains("killed and reaped"),
            "{}",
            error.message
        );
    }

    #[test]
    fn worker_serves_requests_in_order_and_reports_errors() {
        let mut worker = fresh();
        for _ in 0..3 {
            let rows = worker
                .call(&serde_json::json!({"op":"magic"}), DEADLINE)
                .unwrap_or_else(|f| panic!("{}", f.error.message));
            assert_eq!(rows.len(), 1);
        }
        let failure = worker
            .call(&serde_json::json!({"op":"no-such-op"}), DEADLINE)
            .unwrap_err();
        assert!(
            failure.healthy,
            "a refused request leaves the worker usable"
        );
        assert!(
            failure.error.message.contains("Unknown OS operation"),
            "{}",
            failure.error.message
        );
        let absent = serde_json::json!({
            "op": "registry",
            "key": "HKLM\\SOFTWARE\\EasyTier-\u{e9}t\u{e9}-absent",
            "value": "x",
        });
        let rows = worker
            .call(&absent, DEADLINE)
            .unwrap_or_else(|f| panic!("{}", f.error.message));
        assert_eq!(rows[0]["type"], "absent");
        worker.end();
    }

    #[test]
    fn a_worker_dead_while_idle_never_receives_the_request() {
        let mut worker = fresh();
        worker.child.kill().unwrap();
        worker.child.wait().unwrap();
        let failure = worker
            .call(&serde_json::json!({"op":"magic"}), DEADLINE)
            .unwrap_err();
        assert!(!failure.healthy && !failure.delivered);
    }

    // The only test of this binary using the process-wide pool: shutdown
    // closes it for good.
    #[test]
    fn shutdown_ends_every_worker_and_admits_no_more() {
        test_profile();
        assert_eq!(run(serde_json::json!({"op":"magic"})).unwrap().len(), 1);
        let job = pool().job.clone().expect("a job for the first worker");
        assert!(job.active().unwrap() > 0, "the idle worker runs in the job");
        // A call admitted before shutdown that returns only after the
        // drain (and the job's termination): shutdown waits for it.
        pool().busy += 1;
        let late = std::thread::spawn(|| {
            std::thread::sleep(DRAIN + Duration::from_secs(1));
            checkin(None);
        });
        let started = Instant::now();
        shutdown().unwrap();
        let took = started.elapsed();
        assert!(took >= DRAIN + Duration::from_secs(1), "{took:?}");
        assert!(took <= SHUTDOWN_WORST, "{took:?}");
        late.join().unwrap();
        assert_eq!(job.active().unwrap(), 0);
        assert!(pool().idle.is_empty());
        // No new worker or job after shutdown.
        let refused = run(serde_json::json!({"op":"magic"})).unwrap_err();
        assert!(refused.message.contains("shut down"), "{}", refused.message);
        assert!(pool().job.is_none());
        // A call that never returns: shutdown reports it at its deadline.
        pool().busy += 1;
        let started = Instant::now();
        let stuck = shutdown().unwrap_err();
        assert!(
            stuck.message.contains("still in progress"),
            "{}",
            stuck.message
        );
        assert!(started.elapsed() <= SHUTDOWN_WORST + Duration::from_millis(500));
        checkin(None);
        shutdown().unwrap();
    }

    #[test]
    fn a_worker_started_across_shutdown_is_not_admitted() {
        let worker = fresh();
        let closed = Pool {
            closed: true,
            generation: worker.generation,
            ..Pool::default()
        };
        assert!(!admits(&closed, &worker), "refused once closed");
        // A new generation (shutdown ran) refuses it too.
        let newer = Pool {
            generation: worker.generation.wrapping_add(1),
            ..Pool::default()
        };
        assert!(!admits(&newer, &worker), "refused: stale generation");
        // The same generation, admission open: it serves.
        let current = Pool {
            generation: worker.generation,
            ..Pool::default()
        };
        assert!(admits(&current, &worker));
        worker.end();
    }

    #[test]
    fn a_worker_that_exits_is_seen_at_once() {
        let mut worker = fresh();
        // Close stdin: the serve loop ends, stdout reaches EOF.
        worker.requests = None;
        let started = Instant::now();
        assert!(matches!(
            worker.events.recv_timeout(DEADLINE),
            Ok(Event::Eof)
        ));
        assert!(started.elapsed() < DEADLINE);
        worker.end();
    }

    fn value<'a>(vars: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsString> {
        vars.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    #[test]
    fn profile_variables_point_at_the_profile_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vars = profile_vars(dir.path()).unwrap();
        for name in ["USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
            assert_eq!(Path::new(value(&vars, name).unwrap()), dir.path(), "{name}");
        }
        let mut home = value(&vars, "HOMEDRIVE").unwrap().clone();
        home.push(value(&vars, "HOMEPATH").unwrap());
        assert_eq!(Path::new(&home), dir.path());
        assert_eq!(value(&vars, "PSModuleAnalysisCachePath").unwrap(), "NUL");
        assert_eq!(vars.len(), 6);
    }

    #[test]
    fn a_profile_that_is_not_a_plain_absolute_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        for refused in [
            dir.path().join("missing"),
            file,
            dir.path().join("..").join(dir.path().file_name().unwrap()),
            PathBuf::from(r"relative\profile"),
            PathBuf::from(r"\profile"),
            PathBuf::from(r"C:\"),
            PathBuf::from(r"\\server\share\profile"),
        ] {
            assert!(profile_vars(&refused).is_err(), "{}", refused.display());
        }
    }

    #[test]
    fn only_an_elevated_host_that_is_not_system_redirects() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        // No session tree: no profile variables, the profiler still off.
        for profile in [None, Some(dir.path().join("missing"))] {
            set_worker_profile(profile);
            let environment = Environment::for_host(HostToken::Elevated).unwrap();
            assert!(value(&environment.vars, "USERPROFILE").is_none());
            assert_eq!(
                value(&environment.vars, "COR_ENABLE_PROFILING").unwrap(),
                "0"
            );
        }
        // Present but not a plain directory: fail closed.
        set_worker_profile(Some(file));
        assert!(Environment::for_host(HostToken::Elevated).is_err());
        // Neither SYSTEM nor a standard host changes its environment.
        set_worker_profile(Some(dir.path().to_owned()));
        for host in [HostToken::System, HostToken::Standard] {
            let environment = Environment::for_host(host).unwrap();
            assert!(
                value(&environment.vars, "USERPROFILE").is_none(),
                "{host:?}"
            );
            assert!(
                value(&environment.vars, "COR_ENABLE_PROFILING").is_none(),
                "{host:?}"
            );
        }
        // A directory an elevated process created is owned by
        // Administrators; a standard user's is not, and is refused.
        let result = Environment::for_host(HostToken::Elevated);
        if privileged_owner(dir.path()).unwrap() {
            // Owned by Administrators but writable by the user (the
            // inherited temp DACL): refused.
            let refused = result.err().unwrap();
            assert!(refused.message.contains("writable"), "{}", refused.message);
            let (_protected, path) = protected_dir();
            set_worker_profile(Some(path.clone()));
            let environment = Environment::for_host(HostToken::Elevated).unwrap();
            assert_eq!(
                Path::new(value(&environment.vars, "USERPROFILE").unwrap()),
                path
            );
            let names: Vec<_> = environment
                .vars
                .iter()
                .map(|(name, _)| name.to_ascii_uppercase())
                .collect();
            assert!(names.is_sorted(), "{names:?}");
        } else {
            assert!(result.err().unwrap().message.contains("not owned"));
        }
    }

    #[test]
    fn the_encoded_script_fits_a_command_line() {
        let raw = include_str!("system.ps1");
        // Trimming lines is only safe without here-strings and continuations.
        assert!(!raw.contains("@\"") && !raw.contains("@'"));
        assert!(raw.lines().all(|line| !line.trim_end().ends_with('`')));
        // 32767 characters, less the executable path and the other arguments.
        let encoded = encoded_command(&script()).len();
        assert!(encoded < 30_000, "{encoded}");
        assert!(script().starts_with("$PSModuleAutoLoadingPreference = 'None'"));
    }

    #[cfg(not(feature = "ci-test-fixtures"))]
    #[test]
    fn the_diagnostics_request_is_refused_without_the_ci_fixtures() {
        let refused = run(serde_json::json!({"op": "diagnostics"})).unwrap_err();
        assert!(
            refused.message.contains("CI fixtures"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn requests_are_ascii_lines() {
        let line = ascii_json(&serde_json::json!({"name": "Caf\u{e9} \u{1f600}\n"}));
        assert!(line.is_ascii() && !line.contains('\n'));
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["name"],
            "Caf\u{e9} \u{1f600}\n"
        );
    }
}
