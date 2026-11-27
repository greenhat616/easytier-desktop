//! Probe a live listener from an identity the fence must refuse: LocalService
//! under the system service, a restricted Medium copy of the host's own token
//! under the elevated session. No saved account password, arbitrary
//! executable, or caller-provided script.
use super::{
    FenceForm, WinError, encoded_command, execution::Environment, registry::Handle, token,
};
use ::windows::{
    Win32::{
        Foundation::{HANDLE, WAIT_OBJECT_0},
        Security::{LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, LogonUserW},
        System::Threading::{
            CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetExitCodeProcess,
            PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
};
use etd_sysfx::{DirectionResult, FenceError};
use std::net::SocketAddr;

pub fn unprivileged_connect(
    address: SocketAddr,
    form: FenceForm,
) -> Result<DirectionResult, FenceError> {
    // A transient local socket/resource error is not evidence of denial.
    // Retry it once, but never retry a successful unauthorized connection.
    let first = connect_once(address, form)?;
    if let DirectionResult::Error(first_error) = first {
        tracing::warn!(error=%first_error,%address,"unprivileged probe first attempt failed; retrying once");
        std::thread::sleep(std::time::Duration::from_millis(100));
        match connect_once(address, form)? {
            DirectionResult::Error(second_error) => Ok(DirectionResult::Error(format!(
                "initial probe: {first_error}; retry: {second_error}"
            ))),
            verdict => Ok(verdict),
        }
    } else {
        Ok(first)
    }
}

/// The probe identity and the script line that exits 3 unless the probe
/// really runs as that identity.
fn identity(form: FenceForm) -> Result<(Handle, String), FenceError> {
    let error = |e: ::windows::core::Error| FenceError::Probe(e.to_string());
    match form {
        FenceForm::Service => {
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
            Ok((
                Handle(token),
                "if ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-19') { exit 3 }".into(),
            ))
        }
        FenceForm::Session => {
            let probe = |e: WinError| FenceError::Probe(e.to_string());
            let token = token::restricted_copy().map_err(probe)?;
            let user = token::host_user().map_err(probe)?;
            // The SID comes from our own token; refuse anything else before
            // it reaches script text.
            if !user.starts_with("S-1-")
                || !user[4..].chars().all(|c| c.is_ascii_digit() || c == '-')
            {
                return Err(FenceError::Probe(format!("unexpected host SID {user}")));
            }
            // Same user, and BUILTIN\Administrators not usable: the identity a
            // non-elevated process of this user has at the fence.
            Ok((
                token,
                format!(
                    "$i=[System.Security.Principal.WindowsIdentity]::GetCurrent(); if ($i.User.Value -ne '{user}' -or ([System.Security.Principal.WindowsPrincipal]$i).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {{ exit 3 }}"
                ),
            ))
        }
    }
}

fn connect_once(address: SocketAddr, form: FenceForm) -> Result<DirectionResult, FenceError> {
    let error = |e: ::windows::core::Error| FenceError::Probe(e.to_string());
    let (token, check) = identity(form)?;
    let environment = Environment::new().map_err(WinError::fence)?;
    let exe = &environment.exe;
    let family = if address.is_ipv6() {
        "InterNetworkV6"
    } else {
        "InterNetwork"
    };
    let code = format!(
        "$ErrorActionPreference='Stop'; {check}; $s=$null; try {{ $s=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::{family},[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp); $s.Connect([ipaddress]'{}',{}); exit 0 }} catch {{ $e=$_.Exception; while ($e -and $e -isnot [Net.Sockets.SocketException]) {{ $e=$e.InnerException }}; if ($e) {{ exit ([int]$e.NativeErrorCode) }}; exit 2 }} finally {{ if ($s) {{ $s.Dispose() }} }}",
        address.ip(),
        address.port()
    );
    let command = format!(
        "\"{}\" -NoProfile -NonInteractive -EncodedCommand {}",
        exe.display(),
        encoded_command(&code)
    );
    let mut command: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    let block = environment.block();
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
            Some(block.as_ptr().cast()),
            &HSTRING::from(environment.cwd.as_os_str()),
            &startup,
            &mut process,
        )
        .map_err(error)?;
    }
    let process_handle = Handle(process.hProcess);
    let _thread = Handle(process.hThread);
    unsafe {
        if WaitForSingleObject(process_handle.0, 10000) != WAIT_OBJECT_0 {
            // Reap the process even when the deadline expired. Termination
            // can race normal exit, so wait for the actual process object.
            let killed = TerminateProcess(process_handle.0, 2);
            if WaitForSingleObject(process_handle.0, 5000) != WAIT_OBJECT_0 {
                return Err(FenceError::Probe(format!(
                    "probe timed out; termination not confirmed: {killed:?}"
                )));
            }
            return Err(FenceError::Probe("probe timed out; child reaped".into()));
        }
        let mut rc = 0;
        GetExitCodeProcess(process_handle.0, &mut rc).map_err(error)?;
        match rc {
            0 => Ok(DirectionResult::Connected),
            10013 => Ok(DirectionResult::Refused),
            _ => Ok(DirectionResult::Error(format!(
                "unprivileged probe exit {rc}"
            ))),
        }
    }
}
