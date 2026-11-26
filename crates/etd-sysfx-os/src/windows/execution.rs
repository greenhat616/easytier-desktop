//! One protected PowerShell execution environment. The management script is
//! constant; only JSON requests reach it, one per line on its standard input.
use super::{WinError, encoded_command};
use serde_json::Value;
use std::os::windows::io::AsRawHandle;
use std::{
    ffi::OsString,
    io::{Read, Seek, SeekFrom},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        process::CommandExt,
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(super) struct Environment {
    pub exe: PathBuf,
    pub cwd: PathBuf,
    vars: Vec<(OsString, OsString)>,
}
impl Environment {
    pub fn new() -> Result<Self, WinError> {
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
        let vars = vec![
            ("ComSpec".into(), cwd.join("cmd.exe").into_os_string()),
            ("Path".into(), path),
            ("PSModulePath".into(), ps.join("Modules").into_os_string()),
            ("SystemRoot".into(), root.as_os_str().to_owned()),
            ("TEMP".into(), root.join("Temp").into_os_string()),
            ("TMP".into(), root.join("Temp").into_os_string()),
            ("windir".into(), root.as_os_str().to_owned()),
        ];
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
/// How long [`shutdown`] waits for every worker process to be gone after
/// terminating them.
const CONFIRM: Duration = Duration::from_secs(5);

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
        .map_err(WinError::windows)
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

    /// Terminate every process of the job and wait until none is left.
    fn terminate(&self, confirm: Duration) -> Result<(), WinError> {
        unsafe { ::windows::Win32::System::JobObjects::TerminateJobObject(self.0, 1) }
            .map_err(WinError::windows)?;
        let until = Instant::now() + confirm;
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
    /// The job new workers join; replaced after every [`shutdown`].
    job: Option<std::sync::Arc<Job>>,
    generation: u64,
}

static POOL: std::sync::Mutex<Pool> = std::sync::Mutex::new(Pool {
    idle: Vec::new(),
    busy: 0,
    job: None,
    generation: 0,
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
            &encoded_command(include_str!("system.ps1")),
        ])
        .env("ETD_OS_SERVE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr.try_clone().map_err(io_error)?));
        let mut child = cmd.spawn().map_err(io_error)?;
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
                        Ok(0) => break,
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
    let spawned = match job {
        Some(job) => Worker::spawn(&job, generation),
        None => Err(WinError::invalid("management job missing")),
    };
    if spawned.is_err() {
        let mut pool = pool();
        pool.busy -= 1;
        CALLS_DONE.notify_all();
    }
    spawned
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
/// singleton lock. Idle workers have stdin closed; calls in progress get
/// `drain` to finish; then the whole job is terminated and the exit of its
/// every process confirmed. `Err`: some may still run (the caller keeps the
/// affected records open, as they are). Later requests start a new job.
pub fn shutdown(drain: Duration) -> Result<(), WinError> {
    let (idle, job) = {
        let mut pool = pool();
        pool.generation += 1;
        (std::mem::take(&mut pool.idle), pool.job.take())
    };
    for mut worker in idle {
        worker.requests = None;
        let _ = reap(&mut worker.child);
    }
    let until = Instant::now() + drain;
    let mut pool = pool();
    while pool.busy > 0 {
        let left = until.saturating_duration_since(Instant::now());
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
    let Some(job) = job else {
        return Ok(());
    };
    let result = job.terminate(CONFIRM);
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
#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Worker {
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

    #[test]
    fn shutdown_ends_every_worker_and_the_pool_recovers() {
        assert_eq!(run(serde_json::json!({"op":"magic"})).unwrap().len(), 1);
        let job = pool().job.clone().expect("a job for the first worker");
        assert!(job.active().unwrap() > 0, "the idle worker runs in the job");
        shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(job.active().unwrap(), 0);
        assert!(pool().idle.is_empty());
        // A later request starts a new job.
        assert_eq!(run(serde_json::json!({"op":"magic"})).unwrap().len(), 1);
        shutdown(Duration::from_secs(5)).unwrap();
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
