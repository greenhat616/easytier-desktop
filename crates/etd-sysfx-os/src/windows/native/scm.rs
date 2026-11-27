//! Services and drivers from the service control manager, processes from a
//! ToolHelp snapshot, in the rows the PowerShell worker produced
//! (Win32_Service, Win32_SystemDriver, Win32_Process).
use super::super::{WinError, registry::Handle};
use ::windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, FILETIME},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Services::{
                CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE,
                EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
                QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE,
                SERVICE_DRIVER, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
            },
            Threading::{
                GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};
use serde_json::{Value, json};

struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW/OpenServiceW.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

/// The text at `p`, or "" for a null pointer.
///
/// SAFETY: `p` is null or points at a NUL-terminated string that stays
/// valid for the call.
unsafe fn wide(p: PWSTR) -> Result<String, WinError> {
    if p.is_null() {
        return Ok(String::new());
    }
    // SAFETY: per the contract above.
    unsafe { p.to_string() }.map_err(|_| WinError::invalid("invalid service text"))
}

/// Win32_Service's StartMode for a start type.
fn start_mode(start: u32) -> &'static str {
    match start {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

/// Win32_Service's State for a current state.
fn state(current: u32) -> &'static str {
    match current {
        1 => "Stopped",
        2 => "Start Pending",
        3 => "Stop Pending",
        4 => "Running",
        5 => "Continue Pending",
        6 => "Pause Pending",
        7 => "Paused",
        _ => "Unknown",
    }
}

/// Every service of `kind`, with its configuration: `{name, description}`
/// with `"{path}|{start mode}|{state}"`. A service that cannot be opened or
/// that disappears between enumeration and query has an empty path and
/// start mode "Unknown".
fn services(kind: ENUM_SERVICE_TYPE) -> Result<Vec<Value>, WinError> {
    // SAFETY: local machine, the active database.
    let scm = Service(
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) }
            .map_err(WinError::windows)?,
    );
    let mut buf: Vec<u8> = Vec::new();
    let mut needed = 0u32;
    let mut count = 0u32;
    let mut resume = 0u32;
    let mut out = Vec::new();
    for _ in 0..64 {
        buf.resize(buf.len().max(needed as usize), 0);
        // SAFETY: the buffer and out pointers are valid for the call.
        let rc = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                kind,
                SERVICE_STATE_ALL,
                (!buf.is_empty()).then_some(buf.as_mut_slice()),
                &mut needed,
                &mut count,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };
        let more = match rc {
            Ok(()) => false,
            Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => true,
            Err(e) => return Err(WinError::windows(e)),
        };
        let size = size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
        if count as usize * size > buf.len() {
            return Err(WinError::invalid("service count exceeds the buffer"));
        }
        for i in 0..count as usize {
            // SAFETY: `count` entries were written at the start of the
            // buffer; their strings point into the same buffer.
            let entry = unsafe {
                buf.as_ptr()
                    .add(i * size)
                    .cast::<ENUM_SERVICE_STATUS_PROCESSW>()
                    .read_unaligned()
            };
            // SAFETY: as above.
            let name = unsafe { wide(entry.lpServiceName) }?;
            let (path, start) = config(&scm, entry.lpServiceName)?;
            out.push(json!({
                "name": name,
                "description": format!(
                    "{path}|{start}|{}",
                    state(entry.ServiceStatusProcess.dwCurrentState.0)
                ),
            }));
        }
        if !more {
            return Ok(out);
        }
    }
    Err(WinError::invalid("the service list kept growing"))
}

/// The binary path and start mode of a service.
fn config(scm: &Service, name: PWSTR) -> Result<(String, &'static str), WinError> {
    // SAFETY: `name` is the entry's NUL-terminated service name.
    let Ok(service) = (unsafe { OpenServiceW(scm.0, PCWSTR(name.0), SERVICE_QUERY_CONFIG) }) else {
        return Ok((String::new(), "Unknown"));
    };
    let service = Service(service);
    let mut needed = 0u32;
    // SAFETY: asks for the size only.
    let first = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
    match first {
        Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
        _ => return Ok((String::new(), "Unknown")),
    }
    // 8 KiB is QueryServiceConfigW's documented maximum.
    if needed as usize > 8 * 1024 {
        return Err(WinError::invalid("service configuration too large"));
    }
    // A u64 buffer keeps the struct aligned.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let config = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: the buffer holds `needed` bytes, aligned for the struct.
    if unsafe { QueryServiceConfigW(service.0, Some(config), needed, &mut needed) }.is_err() {
        return Ok((String::new(), "Unknown"));
    }
    // SAFETY: filled by the call; its strings point into `buf`.
    let config = unsafe { &*config };
    Ok((
        // SAFETY: as above.
        unsafe { wide(config.lpBinaryPathName) }?,
        start_mode(config.dwStartType.0),
    ))
}

pub(super) fn win32_services() -> Result<Vec<Value>, WinError> {
    services(SERVICE_WIN32)
}

pub(super) fn drivers() -> Result<Vec<Value>, WinError> {
    services(SERVICE_DRIVER)
}

/// .NET ticks (100 ns since 0001-01-01 UTC) of a FILETIME, at the
/// microsecond precision of WMI's CreationDate.
fn ticks(time: FILETIME) -> u64 {
    let filetime = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    filetime / 10 * 10 + 504_911_232_000_000_000
}

/// The image path and start time of a process, where it can be opened.
fn process_details(pid: u32) -> (Option<String>, Option<u64>) {
    // SAFETY: plain query access to a process by id.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return (None, None);
    };
    let handle = Handle(handle);
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    // SAFETY: the buffer holds `len` characters.
    let path = unsafe {
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .ok()
    .and_then(|()| String::from_utf16(&buf[..len as usize]).ok());
    let mut times = [FILETIME::default(); 4];
    let [created, exited, kernel, user] = &mut times;
    // SAFETY: four valid FILETIME outputs.
    let start = unsafe { GetProcessTimes(handle.0, created, exited, kernel, user) }
        .ok()
        .map(|()| ticks(times[0]));
    (path, start)
}

/// `{pid, name, path, start}` for every process.
pub(super) fn processes() -> Result<Vec<Value>, WinError> {
    // SAFETY: a snapshot of all processes.
    let snapshot = Handle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(WinError::windows)?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: `entry` is sized for the call.
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while next.is_ok() {
        let end = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
        let (path, start) = process_details(entry.th32ProcessID);
        out.push(json!({
            "pid": entry.th32ProcessID,
            "name": name,
            "path": path,
            "start": start.map(|t| t.to_string()).unwrap_or_default(),
        }));
        // SAFETY: as above.
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_and_states_are_wmi_words() {
        assert_eq!(start_mode(2), "Auto");
        assert_eq!(start_mode(9), "Unknown");
        assert_eq!(state(4), "Running");
        assert_eq!(state(0), "Unknown");
    }

    #[test]
    fn ticks_are_dotnet_ticks_at_microseconds() {
        // 1601-01-01 plus 15 hundred-nanosecond units.
        let t = FILETIME {
            dwLowDateTime: 15,
            dwHighDateTime: 0,
        };
        assert_eq!(ticks(t), 504_911_232_000_000_010);
    }
}
