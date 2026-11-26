//! One protected PowerShell execution environment. The management script is
//! constant; only a JSON request is supplied through the child environment.
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

pub fn run(request: Value) -> Result<Vec<Value>, WinError> {
    let env = Environment::new()?;
    // File-backed output avoids pipe backpressure and reader threads that
    // could remain stuck past our deadline. The child gets handles, not paths.
    let mut stdout = tempfile::tempfile().map_err(io_error)?;
    let mut stderr = tempfile::tempfile().map_err(io_error)?;
    let mut cmd = env.command();
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        &encoded_command(include_str!("system.ps1")),
    ])
    .env("ETD_OS_REQUEST", request.to_string())
    .stdin(Stdio::null())
    .stdout(Stdio::from(stdout.try_clone().map_err(io_error)?))
    .stderr(Stdio::from(stderr.try_clone().map_err(io_error)?));
    let mut child = cmd.spawn().map_err(io_error)?;
    let status = wait_bounded(&mut child, Duration::from_secs(60))?;
    const MAX_OUTPUT: u64 = 64 * 1024 * 1024;
    let read = |file: &mut std::fs::File| -> Result<Vec<u8>, WinError> {
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut buf = Vec::new();
        file.take(MAX_OUTPUT + 1)
            .read_to_end(&mut buf)
            .map_err(io_error)?;
        if buf.len() as u64 > MAX_OUTPUT {
            return Err(WinError::invalid("management response too large"));
        }
        Ok(buf)
    };
    if !status.success() {
        return Err(WinError::new(
            status.code().unwrap_or(-1) as i64,
            String::from_utf8_lossy(&read(&mut stderr)?).trim(),
        ));
    }
    let mut response: Value = serde_json::from_slice(&read(&mut stdout)?)
        .map_err(|e| WinError::invalid(format!("invalid management response: {e}")))?;
    response["result"]
        .as_array_mut()
        .map(std::mem::take)
        .ok_or_else(|| WinError::invalid("missing management result"))
}
fn wait_bounded(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, WinError> {
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            outcome => {
                // Reap on every abnormal exit path, including a wait error.
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
                let reaped = child.wait();
                if let Err(e) = reaped {
                    return Err(io_error(e));
                }
                if let Err(e) = killed
                    && outcome.is_ok()
                {
                    tracing::warn!(error=%e,"PowerShell timeout kill raced with exit");
                }
                return Err(match outcome {
                    Err(e) => io_error(e),
                    _ => WinError::invalid(
                        "Windows management query timed out; child killed and reaped",
                    ),
                });
            }
        }
    };
    Ok(status)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_timeout_kills_and_reaps() {
        let env = Environment::new().unwrap();
        let mut child = env
            .command()
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded_command("Start-Sleep -Seconds 30"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let error = wait_bounded(&mut child, Duration::from_millis(100)).unwrap_err();
        assert!(error.message.contains("killed and reaped"));
        assert!(child.try_wait().unwrap().is_some());
    }
}
