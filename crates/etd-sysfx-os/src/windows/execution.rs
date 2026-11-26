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

/// Deadline of one management request, as before the worker pool.
const DEADLINE: Duration = Duration::from_secs(60);
/// An idle worker is ended after this long.
const IDLE: Duration = Duration::from_secs(3);
/// Idle workers kept at most.
const POOL_MAX: usize = 4;
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;

/// A warm management PowerShell: the constant script in serve mode, one
/// JSON request per stdin line and one JSON response per stdout line.
/// Starting PowerShell and loading its networking modules costs seconds per
/// process; a reclaim or sweep issues dozens of requests, so a request
/// reuses an idle worker instead of starting a process of its own.
struct Worker {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: std::sync::mpsc::Receiver<Result<String, WinError>>,
    stderr: std::fs::File,
    idle_since: Instant,
}

static POOL: std::sync::Mutex<Vec<Worker>> = std::sync::Mutex::new(Vec::new());

fn pool() -> std::sync::MutexGuard<'static, Vec<Worker>> {
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
                        let (old, keep) = std::mem::take(&mut *pool)
                            .into_iter()
                            .partition(|w| w.idle_since.elapsed() >= IDLE);
                        *pool = keep;
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
    fn spawn() -> Result<Self, WinError> {
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
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = reap(&mut child);
            return Err(WinError::invalid("management worker pipes missing"));
        };
        let (tx, lines) = std::sync::mpsc::channel();
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
                    let sent = match read {
                        Ok(0) => break,
                        Ok(_) if line.len() as u64 > MAX_OUTPUT => {
                            let _ =
                                tx.send(Err(WinError::invalid("management response too large")));
                            break;
                        }
                        Ok(_) => tx.send(Ok(String::from_utf8_lossy(&line).into_owned())),
                        Err(e) => {
                            let _ = tx.send(Err(io_error(e)));
                            break;
                        }
                    };
                    if sent.is_err() {
                        break;
                    }
                }
            });
        if let Err(e) = reader {
            let _ = reap(&mut child);
            return Err(io_error(e));
        }
        start_reaper();
        Ok(Self {
            child,
            stdin: Some(stdin),
            lines,
            stderr,
            idle_since: Instant::now(),
        })
    }

    /// `Err((error, healthy))`: whether the worker may serve again.
    fn call(
        &mut self,
        request: &Value,
        deadline: Duration,
    ) -> Result<Vec<Value>, (WinError, bool)> {
        use std::io::Write;
        let line = ascii_json(request);
        let written = match self.stdin.as_mut() {
            Some(stdin) => stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .map_err(io_error),
            None => Err(WinError::invalid("management worker closed")),
        };
        if let Err(e) = written {
            return Err((self.failure(e), false));
        }
        let response = match self.lines.recv_timeout(deadline) {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => return Err((self.failure(e), false)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let e = WinError::invalid("management worker exited");
                return Err((self.failure(e), false));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let error = match reap(&mut self.child) {
                    Ok(()) => WinError::invalid(
                        "Windows management query timed out; child killed and reaped",
                    ),
                    Err(e) => e,
                };
                return Err((error, false));
            }
        };
        let mut response: Value = serde_json::from_str(&response).map_err(|e| {
            (
                WinError::invalid(format!("invalid management response: {e}")),
                false,
            )
        })?;
        if let Some(message) = response["error"].as_str() {
            return Err((WinError::new(1, message.trim()), true));
        }
        response["result"]
            .as_array_mut()
            .map(std::mem::take)
            .ok_or_else(|| (WinError::invalid("missing management result"), false))
    }

    /// The worker broke: end it and prefer what it wrote to stderr.
    fn failure(&mut self, error: WinError) -> WinError {
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

    fn end(mut self) {
        // Closing stdin ends the serve loop; kill in case it is stuck.
        self.stdin = None;
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

pub fn run(request: Value) -> Result<Vec<Value>, WinError> {
    let pooled = pool().pop();
    let mut worker = match pooled {
        Some(worker) => worker,
        None => Worker::spawn()?,
    };
    match worker.call(&request, DEADLINE) {
        Ok(rows) => {
            release(worker);
            Ok(rows)
        }
        Err((error, true)) => {
            release(worker);
            Err(error)
        }
        Err((error, false)) => Err(error),
    }
}

fn release(mut worker: Worker) {
    worker.idle_since = Instant::now();
    let mut pool = pool();
    if pool.len() < POOL_MAX {
        pool.push(worker);
    } else {
        drop(pool);
        worker.end();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_timeout_kills_and_reaps() {
        let mut worker = Worker::spawn().unwrap();
        // PowerShell cannot even start within 1 ms.
        let (error, healthy) = worker
            .call(&serde_json::json!({"op":"magic"}), Duration::from_millis(1))
            .unwrap_err();
        assert!(!healthy);
        assert!(
            error.message.contains("killed and reaped"),
            "{}",
            error.message
        );
        assert!(worker.child.try_wait().unwrap().is_some());
    }

    #[test]
    fn worker_serves_requests_in_order_and_reports_errors() {
        let mut worker = Worker::spawn().unwrap();
        for _ in 0..3 {
            let rows = worker
                .call(&serde_json::json!({"op":"magic"}), DEADLINE)
                .unwrap();
            assert_eq!(rows.len(), 1);
        }
        let (error, healthy) = worker
            .call(&serde_json::json!({"op":"no-such-op"}), DEADLINE)
            .unwrap_err();
        assert!(healthy, "a refused request leaves the worker usable");
        assert!(
            error.message.contains("Unknown OS operation"),
            "{}",
            error.message
        );
        let absent = serde_json::json!({
            "op": "registry",
            "key": "HKLM\\SOFTWARE\\EasyTier-\u{e9}t\u{e9}-absent",
            "value": "x",
        });
        let rows = worker.call(&absent, DEADLINE).unwrap();
        assert_eq!(rows[0]["type"], "absent");
        worker.end();
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
