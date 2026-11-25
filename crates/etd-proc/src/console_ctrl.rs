//! Windows graceful stop: the host re-executes itself as
//! `--console-ctrl <pid>`, attaches to the kernel's hidden console and sends
//! CTRL_C exactly once. Owned by P1.

use crate::ProcessError;

/// Entry point for the host's dedicated `--console-ctrl <pid>` invocation.
/// Never call this inside the ordinary host: attaching/detaching and handler
/// changes affect the whole calling process. The engine holds a process pin
/// while the helper runs.
#[cfg(windows)]
pub fn send_ctrl_c(pid: u32) -> Result<(), ProcessError> {
    use windows::Win32::System::Console::*;
    let own_pid = std::process::id();
    if pid == 0 || pid == own_pid {
        return Err(ProcessError::Signal("invalid console target".into()));
    }
    let signal_error = |e: windows::core::Error| ProcessError::Signal(e.to_string());
    // SAFETY: this is an isolated helper process. We refuse to broadcast
    // into a shared console or one that does not contain the requested PID.
    unsafe {
        let _ = FreeConsole();
        AttachConsole(pid).map_err(signal_error)?;
        let result = (|| {
            let mut members = [0u32; 3];
            let count = GetConsoleProcessList(&mut members);
            if count != 2 || !members[..2].contains(&own_pid) || !members[..2].contains(&pid) {
                return Err(ProcessError::Signal(
                    "target does not have an exclusive console".into(),
                ));
            }
            SetConsoleCtrlHandler(None, true).map_err(signal_error)?;
            GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0).map_err(signal_error)
        })();
        let _ = FreeConsole();
        result
    }
}

#[cfg(not(windows))]
pub fn send_ctrl_c(_: u32) -> Result<(), ProcessError> {
    Err(ProcessError::Signal(
        "console control is Windows-only".into(),
    ))
}
