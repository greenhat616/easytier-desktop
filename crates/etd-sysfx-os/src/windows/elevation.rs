//! What the desktop UI needs to start the elevated session host (doc#13
//! #choose): the elevation of the UI's own token, a UAC `runas` start for a
//! split-token administrator and the direct start from a UI that is already
//! elevated. Nothing here elevates the calling process.
//!
//! Both starts take an absolute program path and fixed, quote-free
//! arguments, use System32 as working directory, and return the process so
//! the caller can see an early exit and its exit code. What else each one
//! controls differs:
//!
//! - [`start_direct`] (`CreateProcessW`) controls everything a child gets:
//!   `bInheritHandles = FALSE`, an explicit environment of `SystemRoot` and
//!   `windir` only, `CREATE_NO_WINDOW`.
//! - [`start_with_consent`] (`ShellExecuteExW runas`) has no environment,
//!   handle-inheritance or creation-flag parameters. The elevated process is
//!   created by Windows' Application Information service after consent, not
//!   by this process; in practice it inherits none of our handles and gets
//!   an environment built for the elevated token, but that is OS behaviour,
//!   not something this call sets or the API guarantees. `nShow = SW_HIDE`
//!   asks for no visible window. The host must not trust its environment
//!   either way (doc#13 #untrusted).
use std::{
    ffi::OsStr,
    io,
    num::NonZeroIsize,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};

use ::windows::{
    Win32::{
        Foundation::{HANDLE, HWND, WAIT_OBJECT_0},
        Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation, TokenElevationType},
        System::{
            Com::{
                COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
            },
            SystemInformation::GetSystemWindowsDirectoryW,
            Threading::{
                CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetCurrentProcess,
                GetCurrentProcessId, GetExitCodeProcess, OpenProcessToken, PROCESS_INFORMATION,
                STARTUPINFOW, WaitForSingleObject,
            },
        },
        UI::{
            Shell::{
                SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
                ShellExecuteExW,
            },
            WindowsAndMessaging::{GetWindowThreadProcessId, IsWindow, SW_HIDE},
        },
    },
    core::{HRESULT, PCWSTR, PWSTR, w},
};

/// `ERROR_CANCELLED`: the user declined the UAC prompt.
pub const ERROR_CANCELLED: i32 = 1223;

/// The elevation of the calling process's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// A split-token administrator running unelevated: `runas` prompts.
    Limited,
    /// Elevated: the full token of a split-token administrator, or an
    /// administrator with UAC off.
    Elevated,
    /// A standard account (no linked administrator token).
    Standard,
}

/// The elevation of this process's token.
pub fn elevation() -> io::Result<Elevation> {
    let mut token = HANDLE::default();
    // SAFETY: our own process token; the handle is owned and closed.
    let token = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(other)?;
        OwnedHandle::from_raw_handle(token.0)
    };
    let handle = HANDLE(token.as_raw_handle());
    Ok(match token_dword(handle, TokenElevationType)? {
        // TokenElevationTypeFull
        2 => Elevation::Elevated,
        // TokenElevationTypeLimited
        3 => Elevation::Limited,
        // TokenElevationTypeDefault: no split token; elevated only when
        // UAC is off for an administrator.
        _ if token_dword(handle, TokenElevation)? != 0 => Elevation::Elevated,
        _ => Elevation::Standard,
    })
}

/// A host process started here.
#[derive(Debug)]
pub struct HostProcess(OwnedHandle);

impl HostProcess {
    /// The exit code once the process has ended, `None` while it runs.
    pub fn exit_code(&self) -> io::Result<Option<u32>> {
        let handle = HANDLE(self.0.as_raw_handle());
        // SAFETY: a live process handle owned by `self`.
        if unsafe { WaitForSingleObject(handle, 0) } != WAIT_OBJECT_0 {
            return Ok(None);
        }
        let mut code = 0u32;
        // SAFETY: as above; `code` is writable.
        unsafe { GetExitCodeProcess(handle, &mut code) }.map_err(other)?;
        Ok(Some(code))
    }
}

/// Start `program` elevated through the UAC consent prompt (`runas`),
/// asking for no window (`SW_HIDE`). It sets no environment and no handle
/// inheritance: `ShellExecuteExW` has no such parameters (see the module
/// documentation). `owner`, the UI's main window while it is open, lets the
/// prompt come to the foreground. A declined prompt is an error whose raw OS
/// code is [`ERROR_CANCELLED`].
///
/// Blocks until the user answered the prompt and cannot be cancelled. Call it
/// on a thread of its own: it makes that thread a COM single-threaded
/// apartment, as `ShellExecuteEx` requires, and refuses a thread that is
/// already multithreaded.
pub fn start_with_consent(
    owner: Option<NonZeroIsize>,
    program: &Path,
    args: &[&str],
) -> io::Result<HostProcess> {
    let file = absolute_program(program)?;
    // A window that is gone (closed to the tray meanwhile), or whose handle
    // value now belongs to another process's window, is no owner.
    let owner = owner
        .map(|hwnd| HWND(hwnd.get() as *mut _))
        .filter(|hwnd| {
            let mut process = 0u32;
            // SAFETY: both calls only test the handle value; `process` is
            // writable.
            unsafe {
                IsWindow(Some(*hwnd)).as_bool()
                    && GetWindowThreadProcessId(*hwnd, Some(&mut process)) != 0
                    && process == GetCurrentProcessId()
            }
        })
        .unwrap_or_default();
    let parameters = wide(command_arguments(args)?);
    let directory = wide(system_directory()?.as_os_str());
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        hwnd: owner,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(directory.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // ShellExecuteEx needs a single-threaded apartment on this thread.
    // SAFETY: plain apartment initialisation, undone below.
    let apartment =
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if apartment.is_err() {
        // RPC_E_CHANGED_MODE: already a multithreaded apartment.
        return Err(io::Error::other(format!(
            "the UAC start needs a single-threaded COM apartment: {}",
            ::windows::core::Error::from(apartment)
        )));
    }
    // SAFETY: `info` and the strings it points to outlive the call.
    let result = unsafe { ShellExecuteExW(&mut info) };
    // SAFETY: balances the successful CoInitializeEx above (S_OK or S_FALSE).
    unsafe { CoUninitialize() };
    if let Err(error) = result {
        return Err(
            if error.code() == HRESULT::from_win32(ERROR_CANCELLED as u32) {
                io::Error::from_raw_os_error(ERROR_CANCELLED)
            } else {
                other(error)
            },
        );
    }
    if info.hProcess.is_invalid() {
        return Err(io::Error::other("the elevated start returned no process"));
    }
    // SAFETY: SEE_MASK_NOCLOSEPROCESS hands the process handle to us.
    Ok(HostProcess(unsafe {
        OwnedHandle::from_raw_handle(info.hProcess.0)
    }))
}

/// Start `program` from an already elevated process: no handle inheritance,
/// an environment of `SystemRoot` and `windir` only (the user's environment
/// is untrusted under an elevated token, doc#13 #untrusted), the System32
/// working directory and no window.
pub fn start_direct(program: &Path, args: &[&str]) -> io::Result<HostProcess> {
    let file = absolute_program(program)?;
    let mut command_line = wide(format!(
        "\"{}\" {}",
        program.display(),
        command_arguments(args)?
    ));
    let windows = windows_directory()?;
    let mut environment: Vec<u16> = Vec::new();
    for key in ["SystemRoot", "windir"] {
        environment.extend(OsStr::new(key).encode_wide());
        environment.push(u16::from(b'='));
        environment.extend(windows.as_os_str().encode_wide());
        environment.push(0);
    }
    environment.push(0);
    let directory = wide(system_directory()?.as_os_str());
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every buffer outlives the call; the command line is mutable as
    // CreateProcessW requires; the returned handles are taken over below.
    unsafe {
        CreateProcessW(
            PCWSTR(file.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast()),
            PCWSTR(directory.as_ptr()),
            &startup,
            &mut info,
        )
    }
    .map_err(other)?;
    // SAFETY: CreateProcessW returned both handles to us.
    unsafe { drop(OwnedHandle::from_raw_handle(info.hThread.0)) };
    // SAFETY: as above.
    Ok(HostProcess(unsafe {
        OwnedHandle::from_raw_handle(info.hProcess.0)
    }))
}

/// Only fixed, simple arguments: nothing that needs quoting.
fn command_arguments(args: &[&str]) -> io::Result<String> {
    if let Some(bad) = args
        .iter()
        .find(|a| a.is_empty() || a.chars().any(|c| c.is_whitespace() || c == '"'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("argument {bad:?} needs quoting"),
        ));
    }
    Ok(args.join(" "))
}

fn absolute_program(program: &Path) -> io::Result<Vec<u16>> {
    if !program.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute path", program.display()),
        ));
    }
    if program
        .as_os_str()
        .encode_wide()
        .any(|c| c == u16::from(b'"'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the program path holds a quote",
        ));
    }
    Ok(wide(program.as_os_str()))
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn windows_directory() -> io::Result<std::path::PathBuf> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: the buffer is writable.
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
    if n == 0 || n >= buffer.len() {
        return Err(io::Error::other("cannot determine the Windows directory"));
    }
    Ok(std::path::PathBuf::from(String::from_utf16_lossy(
        &buffer[..n],
    )))
}

fn system_directory() -> io::Result<std::path::PathBuf> {
    Ok(windows_directory()?.join("System32"))
}

fn token_dword(
    token: HANDLE,
    class: ::windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> io::Result<u32> {
    let mut value = 0u32;
    let mut size = 0;
    // SAFETY: a live token handle and a DWORD-sized output buffer.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some((&raw mut value).cast()),
            size_of::<u32>() as u32,
            &mut size,
        )
    }
    .map_err(other)?;
    Ok(value)
}

fn other(error: ::windows::core::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_simple_fixed_arguments_are_passed() {
        assert_eq!(
            command_arguments(&["run", "--mode", "elevated-session"]).unwrap(),
            "run --mode elevated-session"
        );
        for bad in [&["a b"][..], &["\"x"], &[""]] {
            assert!(command_arguments(bad).is_err());
        }
    }

    #[test]
    fn the_program_must_be_absolute_and_unquoted() {
        assert!(absolute_program(Path::new(r"etd-host.exe")).is_err());
        assert!(absolute_program(Path::new(r#"C:\a"b\etd-host.exe"#)).is_err());
        assert!(absolute_program(Path::new(r"C:\Program Files\x\etd-host.exe")).is_ok());
    }

    #[test]
    fn this_process_has_an_elevation() {
        elevation().unwrap();
    }
}
