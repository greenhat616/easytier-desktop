//! Probe a live listener from a different, non-privileged service identity.
//! No saved account password, arbitrary executable, or caller-provided script.
use super::{WinError, encoded_command, system_powershell};
use ::windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
        Security::{LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, LogonUserW},
        System::Threading::{
            CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetExitCodeProcess,
            PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
};
use etd_sysfx::{BootId, DirectionResult, FenceError};
use std::{net::SocketAddr, os::windows::process::CommandExt};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub fn unprivileged_connect(address: SocketAddr) -> Result<DirectionResult, FenceError> {
    // A transient local socket/resource error is not evidence of denial.
    // Retry it once, but never retry a successful unauthorized connection.
    let first = connect_once(address)?;
    if let DirectionResult::Error(first_error) = first {
        std::thread::sleep(std::time::Duration::from_millis(100));
        match connect_once(address)? {
            DirectionResult::Error(second_error) => Ok(DirectionResult::Error(format!(
                "initial probe: {first_error}; retry: {second_error}"
            ))),
            verdict => Ok(verdict),
        }
    } else {
        Ok(first)
    }
}

fn connect_once(address: SocketAddr) -> Result<DirectionResult, FenceError> {
    let error = |e: ::windows::core::Error| FenceError::Probe(e.to_string());
    let mut token = HANDLE::default();
    // LogonUserW documents this exact built-in LocalService logon, which
    // provides an identity distinct from SYSTEM without storing credentials.
    // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-logonuserw
    unsafe {
        LogonUserW(
            &HSTRING::from("LocalService"),
            &HSTRING::from("NT AUTHORITY"),
            PCWSTR::null(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
        .map_err(error)?;
    }
    let token = Handle(token);
    let exe = system_powershell().map_err(WinError::fence)?;
    let family = if address.is_ipv6() {
        "InterNetworkV6"
    } else {
        "InterNetwork"
    };
    let code = format!(
        "$ErrorActionPreference='Stop'; if ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-19') {{ exit 3 }}; $s=$null; try {{ $s=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::{family},[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp); $s.Connect([ipaddress]'{}',{}); exit 0 }} catch {{ $e=$_.Exception; while ($e -and $e -isnot [Net.Sockets.SocketException]) {{ $e=$e.InnerException }}; if ($e) {{ exit ([int]$e.NativeErrorCode) }}; exit 2 }} finally {{ if ($s) {{ $s.Dispose() }} }}",
        address.ip(),
        address.port()
    );
    let command = format!(
        "\"{}\" -NoProfile -NonInteractive -EncodedCommand {}",
        exe.display(),
        encoded_command(&code)
    );
    let mut command: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    // Never pass the privileged host's environment to the low-privilege
    // probe. Give it only the system directory and fixed Windows paths.
    let system_dir = exe
        .ancestors()
        .nth(3)
        .ok_or_else(|| FenceError::Probe("invalid system PowerShell path".into()))?;
    let system_root = system_dir.parent().unwrap();
    let environment = format!(
        "Path={}\0SystemRoot={}\0windir={}\0\0",
        system_dir.display(),
        system_root.display(),
        system_root.display()
    );
    let environment: Vec<u16> = environment.encode_utf16().collect();
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessAsUserW(
            Some(token.0),
            &HSTRING::from(exe.as_os_str()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast()),
            &HSTRING::from(system_dir.as_os_str()),
            &startup,
            &mut process,
        )
        .map_err(error)?;
    }
    let process_handle = Handle(process.hProcess);
    let _thread = Handle(process.hThread);
    unsafe {
        if WaitForSingleObject(process_handle.0, 10000) != WAIT_OBJECT_0 {
            let _ = TerminateProcess(process_handle.0, 2);
            return Err(FenceError::Probe("probe timed out".into()));
        }
        let mut rc = 0;
        GetExitCodeProcess(process_handle.0, &mut rc).map_err(error)?;
        match rc {
            0 => Ok(DirectionResult::Connected),
            10013 | 10061 => Ok(DirectionResult::Refused),
            _ => Ok(DirectionResult::Error(format!(
                "unprivileged probe exit {rc}"
            ))),
        }
    }
}
pub fn boot_id() -> Result<BootId, WinError> {
    // CIM's LastBootUpTime is the actual boot timestamp, not a wall-clock
    // minus uptime approximation that changes on clock adjustments.
    let output=std::process::Command::new(system_powershell()?).args(["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()"]).creation_flags(0x08000000).output().map_err(|e|WinError::invalid(e.to_string()))?;
    if !output.status.success() {
        return Err(WinError::invalid("boot timestamp query failed"));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.parse::<u64>().is_err() {
        return Err(WinError::invalid("invalid boot timestamp"));
    }
    Ok(BootId(value))
}
