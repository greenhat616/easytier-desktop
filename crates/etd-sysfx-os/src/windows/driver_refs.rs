use super::{WinError, registry::Key};
use crate::OsError;
use ::windows::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NOT_ALL_ASSIGNED,
            ERROR_SERVICE_DOES_NOT_EXIST, GetLastError, HANDLE, LUID, STATUS_INFO_LENGTH_MISMATCH,
        },
        Globalization::{CP_ACP, MB_ERR_INVALID_CHARS, MultiByteToWideChar},
        Security::{
            AdjustTokenPrivileges, ImpersonateSelf, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
            RevertToSelf, SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        Storage::FileSystem::{
            FILE_ID_INFO, FILE_READ_ATTRIBUTES, FileIdInfo, GetFileInformationByHandleEx,
            GetLogicalDriveStringsW, QueryDosDeviceW,
        },
        System::{
            ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW},
            Registry::{
                HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
            },
            Services::*,
            SystemInformation::GetSystemWindowsDirectoryW,
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    },
    core::{PCWSTR, w},
};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    fs, io,
    os::windows::io::AsRawHandle,
    path::{Component, Path, PathBuf, Prefix},
};

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: this handle is owned by the wrapper.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

fn error(message: impl Into<String>) -> WinError {
    WinError::invalid(message)
}
fn io_error(e: io::Error) -> WinError {
    error(e.to_string())
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn decode(value: &[u16]) -> Result<String, WinError> {
    String::from_utf16(value).map_err(|_| error("invalid driver path encoding"))
}
fn nul_string(value: &[u16]) -> Result<String, WinError> {
    decode(
        &value[..value
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| error("unterminated driver path"))?],
    )
}

// SCM returns pointers into its caller-owned buffer. Validate bounds and
// alignment before reading them.
fn buffer_string(buf: &[usize], ptr: *const u16) -> Result<String, WinError> {
    let begin = buf.as_ptr() as usize;
    let bytes = std::mem::size_of_val(buf);
    let offset = (ptr as usize)
        .checked_sub(begin)
        .ok_or_else(|| error("invalid SCM string pointer"))?;
    if offset >= bytes || !offset.is_multiple_of(2) {
        return Err(error("invalid SCM string pointer"));
    }
    // SAFETY: the checked pointer/range lies within the initialized buffer.
    let slice = unsafe { std::slice::from_raw_parts(ptr, (bytes - offset) / 2) };
    nul_string(slice)
}

fn service_image(manager: SC_HANDLE, name: &str) -> Result<String, WinError> {
    let name = wide(name);
    // SAFETY: name is NUL-terminated and the manager is live.
    let service = ServiceHandle(
        unsafe { OpenServiceW(manager, PCWSTR(name.as_ptr()), SERVICE_QUERY_CONFIG) }
            .map_err(WinError::windows)?,
    );
    Ok(service_config(&service)?.image)
}

/// The SCM configuration of an open service.
struct ServiceConfig {
    service_type: u32,
    start_type: u32,
    image: String,
}

fn service_config(service: &ServiceHandle) -> Result<ServiceConfig, WinError> {
    let mut needed = 0;
    // SAFETY: documented size query with a valid output pointer.
    let first = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
    if !first.is_err_and(|e| e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()) || needed == 0 {
        return Err(error("cannot query driver service configuration size"));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: buffer is aligned, initialized and large enough for the reported size.
    unsafe {
        QueryServiceConfigW(
            service.0,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(WinError::windows)?;
    // SAFETY: successful query wrote a QUERY_SERVICE_CONFIGW to the aligned buffer.
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let image = if config.lpBinaryPathName.0.is_null() {
        String::new()
    } else {
        buffer_string(&buffer, config.lpBinaryPathName.0)?
    };
    Ok(ServiceConfig {
        service_type: config.dwServiceType.0,
        start_type: config.dwStartType.0,
        image,
    })
}

/// One registered service as the shared-driver observer reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DriverService {
    pub name: String,
    pub service_type: u32,
    pub start_type: u32,
    /// As registered (may be relative or unexpanded); the file need not
    /// exist.
    pub image: String,
    pub state: u32,
}

impl DriverService {
    /// Canonical detail recorded with the observation.
    pub fn detail(&self) -> String {
        let start = match self.start_type {
            0 => "boot",
            1 => "system",
            2 => "auto",
            3 => "demand",
            4 => "disabled",
            _ => "other",
        };
        let state = match self.state {
            1 => "stopped",
            2 => "start_pending",
            3 => "stop_pending",
            4 => "running",
            5 => "continue_pending",
            6 => "pause_pending",
            7 => "paused",
            _ => "other",
        };
        serde_json::json!({
            "name": self.name,
            "service_type": self.service_type,
            "driver": self.service_type & SERVICE_DRIVER.0 != 0,
            "start_type": start,
            "image_path": self.image,
            "state": state,
        })
        .to_string()
    }
}

/// A service registration by name, from SCM (`OpenServiceW` +
/// `QueryServiceConfigW` + `QueryServiceStatus`), whatever its start type
/// and whether or not its image file exists, cross-checked with
/// `HKLM\SYSTEM\CurrentControlSet\Services\<name>`. Absent from both:
/// `None`. Present in only one, a type that differs, or SCM refusing the
/// query: an error, never `None` (WMI `Win32_SystemDriver` omits disabled
/// drivers without a file, G2 topic#42 msg#1126).
pub(super) fn driver_service(name: &str) -> Result<Option<DriverService>, WinError> {
    // SAFETY: null names select the local active SCM database.
    let manager = ServiceHandle(
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map_err(WinError::windows)?,
    );
    let wide_name = wide(name);
    // SAFETY: the name is NUL-terminated and the manager is live.
    let opened = unsafe {
        OpenServiceW(
            manager.0,
            PCWSTR(wide_name.as_ptr()),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    let scm = match opened {
        Ok(handle) => {
            let service = ServiceHandle(handle);
            let config = service_config(&service)?;
            let mut status = SERVICE_STATUS::default();
            // SAFETY: the handle is live and `status` is a valid output.
            unsafe { QueryServiceStatus(service.0, &mut status) }.map_err(WinError::windows)?;
            Some((config, status.dwCurrentState.0))
        }
        Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => None,
        Err(e) => return Err(WinError::windows(e)),
    };
    let services = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services",
        KEY_READ,
    )?
    .ok_or_else(|| error("SCM registry database unavailable"))?;
    let registered = match Key::open(services.0, name, KEY_QUERY_VALUE)? {
        None => None,
        Some(key) => match key.read("Type")? {
            Some(kind) if kind.ty == REG_DWORD && kind.bytes.len() == 4 => Some(
                u32::from_le_bytes(kind.bytes.try_into().expect("checked size")),
            ),
            _ => {
                return Err(error(format!(
                    "service registration {name} has no valid Type"
                )));
            }
        },
    };
    match (scm, registered) {
        (None, None) => Ok(None),
        (Some((config, state)), Some(kind)) if kind == config.service_type => {
            Ok(Some(DriverService {
                name: name.into(),
                service_type: config.service_type,
                start_type: config.start_type,
                image: config.image,
                state,
            }))
        }
        (Some((config, _)), Some(kind)) => Err(error(format!(
            "service {name}: SCM type {:#x}, registry Type {kind:#x}",
            config.service_type
        ))),
        (Some(_), None) => Err(error(format!(
            "service {name} is known to SCM but has no registry key"
        ))),
        (None, Some(_)) => Err(error(format!(
            "service {name} has a registry key but SCM does not know it (pending deletion or reboot)"
        ))),
    }
}

type ImageResult = Result<Option<String>, WinError>;
type Images = BTreeMap<String, (String, ImageResult)>;

fn registered_images() -> Result<Images, WinError> {
    // SAFETY: null names select the local active SCM database.
    let manager = ServiceHandle(
        unsafe {
            OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
            )
        }
        .map_err(WinError::windows)?,
    );
    let mut resume = 0;
    let mut images = Images::new();
    // SCM limits this call to 256 KiB; resume handles paginate larger inventories.
    let mut buffer = vec![0usize; 256 * 1024 / std::mem::size_of::<usize>()];
    loop {
        let previous = resume;
        let mut needed = 0;
        let mut count = 0;
        // SAFETY: initialized, aligned buffer stays live throughout the call.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                buffer.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(buffer.as_slice()),
            )
        };
        let result = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                Some(bytes),
                &mut needed,
                &mut count,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };
        let more = match result {
            Ok(()) => false,
            Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => true,
            Err(e) => return Err(WinError::windows(e)),
        };
        if count as usize
            > std::mem::size_of_val(buffer.as_slice())
                / std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>()
        {
            return Err(error("invalid SCM driver enumeration count"));
        }
        // SAFETY: checked count and aligned buffer; SCM wrote count entries.
        let entries = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                count as usize,
            )
        };
        for entry in entries {
            let name = buffer_string(&buffer, entry.lpServiceName.0)?;
            let image = service_image(manager.0, &name).map(|image| {
                Some(if image.is_empty() {
                    format!(r"System32\Drivers\{name}.sys")
                } else {
                    image
                })
            });
            images.insert(name.to_uppercase(), (name, image));
        }
        if !more {
            return Ok(images);
        }
        if count == 0 || previous == resume {
            return Err(error("incomplete SCM driver enumeration"));
        }
    }
}

// SCM silently omits services whose query-status ACL denies access. Check
// the native Services registration inventory too; never treat that omission
// as proof that no stopped driver points into the store.
fn registry_image(services: &Key, name: &str) -> ImageResult {
    let key = Key::open(services.0, name, KEY_QUERY_VALUE)?
        .ok_or_else(|| error("service registration changed during enumeration"))?;
    let Some(kind) = key.read("Type")? else {
        return Ok(None);
    };
    // When a stale key has a malformed type, still resolve its image path:
    // an image provably outside the bundle poses no risk regardless of type.
    if kind.ty == REG_DWORD && kind.bytes.len() == 4 {
        let kind = u32::from_le_bytes(kind.bytes.try_into().expect("checked size"));
        if kind & SERVICE_DRIVER.0 == 0 {
            return Ok(None);
        }
    }
    let default = || format!(r"System32\Drivers\{name}.sys");
    let path = match key.read("ImagePath")? {
        None => default(),
        Some(value) => {
            if !matches!(value.ty, REG_SZ | REG_EXPAND_SZ) || !value.bytes.len().is_multiple_of(2) {
                return Err(error(format!("invalid driver ImagePath for {name}")));
            }
            let units: Vec<_> = value
                .bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_le_bytes(*chunk))
                .collect();
            // RegQueryValueEx does not promise a terminator, even for REG_SZ.
            let end = units
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(units.len());
            if units[end..].iter().any(|unit| *unit != 0) {
                return Err(error(format!("ambiguous driver ImagePath for {name}")));
            }
            let path = decode(&units[..end])?;
            if path.is_empty() { default() } else { path }
        }
    };
    Ok(Some(path))
}

fn registry_images() -> Result<Images, WinError> {
    let services = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services",
        KEY_READ,
    )?
    .ok_or_else(|| error("SCM registry database unavailable"))?;
    let mut images = Images::new();
    for name in services.children()? {
        let result = registry_image(&services, &name);
        images.insert(name.to_uppercase(), (name, result));
    }
    Ok(images)
}

/// Image paths of every loaded driver. SeDebugPrivilege comes first; a token
/// that cannot enable it, such as a Windows Installer custom action (the
/// msiserver service's RequiredPrivileges omit it), reads the kernel module
/// list instead. Either way an incomplete list fails closed.
fn loaded_images() -> Result<Vec<String>, WinError> {
    match debug_images()? {
        Some(images) => Ok(images),
        None => module_images(),
    }
}

/// Number of loaded drivers. Without SeDebugPrivilege the bases come back
/// null, but the count is still the kernel's.
fn driver_count() -> Result<usize, WinError> {
    let mut bases = vec![std::ptr::null_mut::<c_void>(); 1024];
    loop {
        let mut needed = 0;
        let capacity = u32::try_from(std::mem::size_of_val(bases.as_slice()))
            .map_err(|_| error("too many loaded drivers"))?;
        // SAFETY: bases has capacity bytes of initialized writable memory.
        unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), capacity, &mut needed) }
            .map_err(WinError::windows)?;
        if needed > capacity {
            bases.resize(
                (needed as usize).div_ceil(std::mem::size_of::<*mut c_void>()),
                std::ptr::null_mut(),
            );
            continue;
        }
        if needed == 0 || !(needed as usize).is_multiple_of(std::mem::size_of::<*mut c_void>()) {
            return Err(error("invalid loaded driver enumeration"));
        }
        return Ok(needed as usize / std::mem::size_of::<*mut c_void>());
    }
}

const SYSTEM_MODULE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(11);
/// `RTL_PROCESS_MODULES`: a ULONG count padded to pointer alignment, then
/// `RTL_PROCESS_MODULE_INFORMATION` entries: Section, MappedBase and
/// ImageBase pointers, ImageSize, Flags, four USHORTs (the last is
/// OffsetToFileName), then `FullPathName`, 256 ANSI bytes, NUL-terminated.
const MODULES_HEADER: usize = std::mem::size_of::<usize>();
const MODULE_NAME: usize = 3 * std::mem::size_of::<usize>() + 16;
const MODULE_NAME_LEN: usize = 256;
const MODULE_ENTRY: usize = MODULE_NAME + MODULE_NAME_LEN;

/// Whether `path` is a complete absolute native image path: `\SystemRoot\`,
/// `\??\` with a drive, `UNC\` or `Volume{...}` root, `\Device\`, or a drive
/// root, followed by non-empty components (no `.` or `..`). A bare name or a
/// relative path is not, though the registered-image normalizer would place
/// it under the Windows directory.
fn native_absolute(path: &str) -> bool {
    fn drive(path: &str) -> Option<&str> {
        let bytes = path.as_bytes();
        (bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\")
            .then(|| &path[3..])
    }
    let tail = if let Some(tail) = strip_prefix_ci(path, r"\SystemRoot\") {
        Some(tail)
    } else if let Some(tail) = strip_prefix_ci(path, r"\Device\") {
        Some(tail)
    } else if let Some(rest) = strip_prefix_ci(path, r"\??\") {
        drive(rest)
            .or_else(|| {
                // UNC\<server>\<share>\<file...>: server and share are checked
                // as components below; a file must follow them.
                strip_prefix_ci(rest, r"UNC\").filter(|unc| unc.split('\\').count() >= 3)
            })
            .or_else(|| {
                strip_prefix_ci(rest, "Volume{")
                    .and_then(|volume| volume.split_once("}\\"))
                    .filter(|(guid, _)| volume_guid(guid))
                    .map(|(_, tail)| tail)
            })
    } else {
        drive(path)
    };
    tail.is_some_and(|tail| {
        !tail.is_empty()
            && tail
                .split('\\')
                .all(|part| !part.is_empty() && part != "." && part != "..")
    })
}

/// `8-4-4-4-12` hexadecimal digits, the GUID of a `Volume{...}` name.
fn volume_guid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The paths in a `SystemModuleInformation` buffer. Any entry whose path is
/// empty, unterminated, possibly truncated (255 bytes fill the field), not a
/// complete absolute native path, whose file-name offset is not exactly
/// past its last separator, not decodable, or holding a `?` past a leading
/// `\??\` (a character the kernel could not convert) fails the whole list.
fn parse_modules(
    bytes: &[u8],
    ansi: impl Fn(&[u8]) -> Result<String, WinError>,
) -> Result<Vec<String>, WinError> {
    let count = bytes
        .get(..4)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("checked size")) as usize)
        .ok_or_else(|| error("short kernel module list"))?;
    let end = count
        .checked_mul(MODULE_ENTRY)
        .and_then(|size| size.checked_add(MODULES_HEADER))
        .ok_or_else(|| error("invalid kernel module count"))?;
    if count == 0 || end > bytes.len() {
        return Err(error("invalid kernel module count"));
    }
    let mut images = Vec::with_capacity(count);
    for entry in bytes[MODULES_HEADER..end].as_chunks::<MODULE_ENTRY>().0 {
        let name = &entry[MODULE_NAME..];
        let offset = u16::from_le_bytes([entry[MODULE_NAME - 2], entry[MODULE_NAME - 1]]) as usize;
        let len = name
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| error("unterminated kernel module path"))?;
        if len == 0 {
            return Err(error("empty kernel module path"));
        }
        if len >= MODULE_NAME_LEN - 1 {
            return Err(error("kernel module path may be truncated"));
        }
        // The file name starts right after the last separator. A DBCS trail
        // byte equal to '\' in the name fails here, closed.
        let separator = name[..len].iter().rposition(|byte| *byte == b'\\');
        if offset == 0 || offset >= len || separator != Some(offset - 1) {
            return Err(error("inconsistent kernel module path"));
        }
        let path = ansi(&name[..len])?;
        if strip_prefix_ci(&path, r"\??\")
            .unwrap_or(&path)
            .contains('?')
        {
            return Err(error(format!(
                "kernel module path not representable: {path}"
            )));
        }
        if !native_absolute(&path) {
            return Err(error(format!(
                "kernel module path is not a complete absolute path: {path}"
            )));
        }
        images.push(path);
    }
    Ok(images)
}

/// Decode a path in the system ANSI code page; invalid bytes fail.
fn ansi_path(bytes: &[u8]) -> Result<String, WinError> {
    if bytes.is_ascii() {
        return Ok(String::from_utf8(bytes.to_vec()).expect("ASCII"));
    }
    let mut wide = vec![0u16; bytes.len()];
    // SAFETY: both buffers are valid for their lengths.
    let n = unsafe { MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, bytes, Some(&mut wide)) };
    if n <= 0 {
        return Err(error(
            "kernel module path is not valid in the ANSI code page",
        ));
    }
    decode(&wide[..n as usize])
}

/// Loaded-driver paths from `NtQuerySystemInformation(SystemModuleInformation)`,
/// which reports paths without SeDebugPrivilege (only the bases are hidden).
/// The list must have exactly as many entries as `EnumDeviceDrivers`
/// reports; a driver loading or unloading in between retries, a persistent
/// difference fails.
fn module_images() -> Result<Vec<String>, WinError> {
    for _ in 0..4 {
        let expected = driver_count()?;
        let mut buffer = vec![0u64; 64 * 1024 / 8];
        let images = loop {
            let length = u32::try_from(std::mem::size_of_val(buffer.as_slice()))
                .map_err(|_| error("kernel module list too large"))?;
            let mut written = 0u32;
            // SAFETY: buffer is writable for `length` bytes; written is a valid output.
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_MODULE_INFORMATION,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut written,
                )
            };
            if status == STATUS_INFO_LENGTH_MISMATCH {
                if written <= length || written > 64 << 20 {
                    return Err(error("invalid kernel module list size"));
                }
                // Leave room for a driver that loads before the next call.
                buffer.resize((written as usize).div_ceil(8) + 1024, 0);
                continue;
            }
            if status.is_err() {
                return Err(error(format!(
                    "kernel module list unavailable: NTSTATUS {:#010x}",
                    status.0
                )));
            }
            if written == 0 || written > length {
                return Err(error("inconsistent kernel module list size"));
            }
            let written = written as usize;
            // SAFETY: the buffer is initialized; read its first `written` bytes.
            let bytes =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), written) };
            break parse_modules(bytes, ansi_path)?;
        };
        if images.len() == expected {
            return Ok(images);
        }
    }
    Err(error(
        "kernel module list and loaded driver count keep disagreeing",
    ))
}

// Recent Windows releases require SeDebugPrivilege for non-null loaded-driver
// bases. Enable only on a private impersonation token of this worker thread,
// never on the process token. Revert before returning to the caller. `None`:
// this token cannot enable the privilege.
fn debug_images() -> Result<Option<Vec<String>>, WinError> {
    // SAFETY: creates a thread token derived from the current process token.
    unsafe { ImpersonateSelf(SecurityImpersonation) }.map_err(WinError::windows)?;
    let result = (|| {
        let mut token = HANDLE::default();
        // SAFETY: valid thread pseudo-handle and output pointer.
        unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                true,
                &mut token,
            )
        }
        .map_err(WinError::windows)?;
        let privilege = (|| {
            let mut luid = LUID::default();
            // SAFETY: valid NUL-terminated privilege name and output pointer.
            unsafe { LookupPrivilegeValueW(PCWSTR::null(), w!("SeDebugPrivilege"), &mut luid) }
                .map_err(WinError::windows)?;
            let state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            // SAFETY: owned token and initialized privilege struct.
            unsafe { AdjustTokenPrivileges(token, false, Some(&state), 0, None, None) }
                .map_err(WinError::windows)?;
            Ok(unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED)
        })();
        // SAFETY: owned token.
        let _ = unsafe { CloseHandle(token) };
        if !privilege? {
            return Ok(None);
        }
        let mut bases = vec![std::ptr::null_mut::<c_void>(); 1024];
        loop {
            let mut needed = 0;
            let capacity = u32::try_from(std::mem::size_of_val(bases.as_slice()))
                .map_err(|_| error("too many loaded drivers"))?;
            // SAFETY: bases has capacity bytes of initialized writable memory.
            unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), capacity, &mut needed) }
                .map_err(WinError::windows)?;
            if needed > capacity {
                bases.resize(
                    (needed as usize).div_ceil(std::mem::size_of::<*mut c_void>()),
                    std::ptr::null_mut(),
                );
                continue;
            }
            if needed == 0 || !(needed as usize).is_multiple_of(std::mem::size_of::<*mut c_void>())
            {
                return Err(error("invalid loaded driver enumeration"));
            }
            bases.truncate(needed as usize / std::mem::size_of::<*mut c_void>());
            let mut images = Vec::with_capacity(bases.len());
            for base in bases {
                if base.is_null() {
                    return Err(error("loaded driver enumeration returned a hidden address"));
                }
                let mut path = vec![0u16; 32768];
                // SAFETY: base is an address returned by EnumDeviceDrivers; path is writable.
                let n = unsafe { GetDeviceDriverFileNameW(base, &mut path) } as usize;
                if n == 0 || n >= path.len() - 1 {
                    return Err(error("cannot determine a loaded driver image path"));
                }
                images.push(decode(&path[..n])?);
            }
            return Ok(Some(images));
        }
    })();
    // SAFETY: discard this worker's temporary impersonation token.
    // Continuing on a privileged impersonation token after a failed revert
    // would be unsafe; abort instead.
    if unsafe { RevertToSelf() }.is_err() {
        std::process::abort();
    }
    result
}

fn windows_dir() -> Result<PathBuf, WinError> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: buffer is writable.
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
    if n == 0 || n >= buffer.len() {
        return Err(error("cannot determine Windows directory"));
    }
    Ok(PathBuf::from(decode(&buffer[..n])?))
}

fn strip_prefix_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|part| part.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

// Translate NT volume names into mounted DOS drive names when available.
fn device_path(value: &str) -> Result<PathBuf, WinError> {
    let mut drives = vec![0u16; 32768];
    // SAFETY: writable buffer.
    let n = unsafe { GetLogicalDriveStringsW(Some(&mut drives)) } as usize;
    if n == 0 || n >= drives.len() {
        return Err(error("cannot enumerate drive aliases"));
    }
    for drive in drives[..n].split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let drive = decode(drive)?;
        let letter = wide(drive.trim_end_matches('\\'));
        let mut target = vec![0u16; 32768];
        // SAFETY: letter is NUL-terminated, target is writable.
        let n = unsafe { QueryDosDeviceW(PCWSTR(letter.as_ptr()), Some(&mut target)) };
        if n == 0 {
            continue;
        }
        let target = nul_string(&target)?;
        if let Some(tail) = strip_prefix_ci(value, &target).and_then(|tail| tail.strip_prefix('\\'))
        {
            return Ok(PathBuf::from(drive).join(tail));
        }
    }
    // Unmounted volumes still have a global NT namespace. Canonicalization
    // must succeed there; otherwise the caller cannot rule out an alias.
    Ok(PathBuf::from(format!(r"\\?\GLOBALROOT{value}")))
}

fn machine_var(name: &str) -> Result<String, WinError> {
    let environment = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        KEY_QUERY_VALUE,
    )?
    .ok_or_else(|| error("machine environment registry unavailable"))?;
    let value = environment
        .read(name)?
        .ok_or_else(|| error(format!("unknown machine environment variable {name}")))?;
    if !matches!(value.ty, REG_SZ | REG_EXPAND_SZ) || !value.bytes.len().is_multiple_of(2) {
        return Err(error(format!(
            "invalid machine environment variable {name}"
        )));
    }
    let units: Vec<_> = value
        .bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .collect();
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    if units[end..].iter().any(|unit| *unit != 0) {
        return Err(error(format!(
            "ambiguous machine environment variable {name}"
        )));
    }
    decode(&units[..end])
}

fn expand_vars(value: &str, system_root: &Path) -> Result<String, WinError> {
    let mut value = value.to_owned();
    // Expand Windows environment syntax (case-insensitive on Windows).
    // Bound recursion to fail closed on a cyclic environment value.
    for _ in 0..16 {
        let Some(start) = value.find('%') else {
            return Ok(value);
        };
        let Some(end) = value[start + 1..].find('%').map(|n| start + 1 + n) else {
            return Ok(value); // an unmatched percent is an ordinary filename character
        };
        let name = &value[start + 1..end];
        let replacement =
            if name.eq_ignore_ascii_case("SystemRoot") || name.eq_ignore_ascii_case("windir") {
                system_root.to_string_lossy().into_owned()
            } else if name.eq_ignore_ascii_case("SystemDrive") {
                system_root
                    .ancestors()
                    .last()
                    .ok_or_else(|| error("invalid Windows directory"))?
                    .to_string_lossy()
                    .trim_end_matches('\\')
                    .to_owned()
            } else {
                machine_var(name)?
            };
        value.replace_range(start..=end, &replacement);
    }
    Err(error("cyclic driver path environment expansion"))
}

fn image_path(raw: &str, system_root: &Path) -> Result<PathBuf, WinError> {
    let raw = raw.trim();
    let raw = if let Some(quoted) = raw.strip_prefix('"') {
        quoted
            .strip_suffix('"')
            .ok_or_else(|| error("ambiguous quoted driver image path"))?
    } else {
        raw
    };
    let value = raw.replace('/', "\\");
    let value = strip_prefix_ci(&value, r"\??\").unwrap_or(&value);
    let path = if let Some(tail) = strip_prefix_ci(value, r"\SystemRoot\") {
        system_root.join(tail)
    } else if strip_prefix_ci(value, r"\Device\").is_some() {
        device_path(value)?
    } else if strip_prefix_ci(value, "Volume{").is_some() {
        PathBuf::from(format!(r"\\?\{value}"))
    } else if let Some(tail) = strip_prefix_ci(value, r"UNC\") {
        PathBuf::from(format!(r"\\{tail}"))
    } else {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            path
        } else if path.has_root() || matches!(path.components().next(), Some(Component::Prefix(_)))
        {
            return Err(error(format!("ambiguous driver image path: {raw}")));
        } else {
            system_root.join(path)
        }
    };
    if !path.is_absolute() {
        return Err(error(format!("cannot normalize driver image path: {raw}")));
    }
    // Canonicalize dot components, without resolving filesystem aliases yet.
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => (),
            Component::ParentDir => {
                if !normalized.pop() || !normalized.is_absolute() {
                    return Err(error(format!("driver path escapes its volume: {raw}")));
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn normalized(path: &Path) -> Result<String, WinError> {
    let path = path
        .to_str()
        .ok_or_else(|| error("non-Unicode driver path"))?;
    let path = if let Some(tail) = strip_prefix_ci(path, r"\\?\UNC\") {
        format!(r"\\{tail}")
    } else {
        strip_prefix_ci(path, r"\\?\").unwrap_or(path).to_owned()
    };
    Ok(path.to_uppercase())
}
fn inside(path: &str, dir: &str) -> bool {
    path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|tail| tail.starts_with('\\'))
}

type FileIdentity = (u64, [u8; 16]);

fn identity(path: &Path) -> Result<FileIdentity, WinError> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .open(path)
        .map_err(io_error)?;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: file owns the live handle and info is writable.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(WinError::windows)?;
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

fn unavailable_volume(path: &Path) -> bool {
    // A local drive or NT volume which no longer exists cannot contain the
    // existing store. Do not classify access denied/network failures as absent.
    let root = match path.components().next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
        {
            path.ancestors().last()
        }
        _ => None,
    };
    root.is_some_and(|root| {
        fs::metadata(root).is_err_and(|e| {
            e.kind() == io::ErrorKind::NotFound || matches!(e.raw_os_error(), Some(15 | 21))
        })
    })
}

// If the image is missing, canonicalize its closest existing ancestor to
// account for directory junctions; any error other than NotFound is ambiguous.
fn canonical_even_missing(
    path: &Path,
    allow_missing_volume: bool,
) -> Result<Option<PathBuf>, WinError> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(Some(path)),
        Err(e)
            if (e.kind() == io::ErrorKind::NotFound
                || matches!(e.raw_os_error(), Some(15 | 21)))
                && unavailable_volume(path) =>
        {
            if allow_missing_volume {
                Ok(None)
            } else {
                Err(error(format!(
                    "loaded driver volume is no longer available: {}",
                    path.display()
                )))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| io_error(e))?;
            let name = path
                .file_name()
                .ok_or_else(|| error("missing driver path name"))?;
            Ok(canonical_even_missing(parent, allow_missing_volume)?
                .map(|parent| parent.join(name)))
        }
        Err(e) => Err(io_error(e)),
    }
}

fn collect_identities(dir: &Path, identities: &mut Vec<FileIdentity>) -> Result<(), WinError> {
    use std::os::windows::fs::MetadataExt;
    let meta = fs::symlink_metadata(dir).map_err(io_error)?;
    if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
        return Err(error("not a plain kernel store directory"));
    }
    for entry in fs::read_dir(dir).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(io_error)?;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(error("reparse point inside kernel store"));
        }
        if meta.is_dir() {
            collect_identities(&path, identities)?;
        } else if meta.is_file() {
            identities.push(identity(&path)?);
        } else {
            return Err(error("unexpected kernel store file type"));
        }
    }
    Ok(())
}

fn referenced(dir: &Path) -> Result<Option<String>, WinError> {
    if !super::registry::elevated()? {
        return Err(error(
            "driver reference check requires an elevated administrator",
        ));
    }
    let mut identities = Vec::new();
    collect_identities(dir, &mut identities)?;
    let dir = fs::canonicalize(dir).map_err(io_error)?;
    let normalized_dir = normalized(&dir)?;
    let system_root = windows_dir()?;
    // Check SCM first: a stopped driver registration is also a reference.
    let check_path = |raw: &str, allow_missing_volume: bool| -> Result<bool, WinError> {
        let path = image_path(raw, &system_root)?;
        if inside(&normalized(&path)?, &normalized_dir) {
            return Ok(true);
        }
        let Some(canonical) = canonical_even_missing(&path, allow_missing_volume)? else {
            return Ok(false);
        };
        if inside(&normalized(&canonical)?, &normalized_dir) {
            return Ok(true);
        }
        match fs::metadata(&canonical) {
            Ok(_) => Ok(identities.contains(&identity(&canonical)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_error(e)),
        }
    };
    let check = |raw: &str| -> Result<bool, WinError> {
        // The kernel understands NT paths and \SystemRoot, not arbitrary
        // percent variables. The literal registered path is authoritative.
        // Also consider any machine-environment expansion conservatively.
        let literal = check_path(raw, true);
        if matches!(literal, Ok(true)) {
            return Ok(true);
        }
        if !raw.contains('%') {
            return literal;
        }
        let expanded = expand_vars(raw, &system_root).and_then(|path| check_path(&path, true));
        match (literal, expanded) {
            (Ok(true), _) | (_, Ok(true)) => Ok(true),
            (Ok(false), _) | (_, Ok(false)) => Ok(false),
            (Err(error), Err(_)) => Err(error),
        }
    };
    let mut unresolved = None;
    let mut scm = registered_images()?;
    let registry = registry_images()?;
    // Merge by case-insensitive service name. One failed query is not
    // indeterminate if the other inventory has a parseable driver entry.
    for (key, (name, reg)) in registry {
        let other = scm.remove(&key).map(|(_, result)| result);
        let mut paths = Vec::new();
        let mut failure = None;
        for result in std::iter::once(reg).chain(other) {
            match result {
                Ok(Some(path)) => paths.push(path),
                Ok(None) => (),
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        if paths.is_empty() {
            if let Some(e) = failure {
                unresolved.get_or_insert(e);
            }
            continue;
        }
        for raw in paths {
            match check(&raw) {
                Ok(true) => return Ok(Some(format!("driver service {name} references {raw}"))),
                Ok(false) => (),
                Err(e) => {
                    unresolved.get_or_insert(error(format!("driver service {name} ({raw}): {e}")));
                }
            }
        }
    }
    for (_, (name, result)) in scm {
        match result {
            Ok(Some(raw)) => match check(&raw) {
                Ok(true) => return Ok(Some(format!("driver service {name} references {raw}"))),
                Ok(false) => (),
                Err(e) => {
                    unresolved.get_or_insert(error(format!("driver service {name} ({raw}): {e}")));
                }
            },
            Ok(None) => (),
            Err(e) => {
                unresolved.get_or_insert(error(format!("driver service {name}: {e}")));
            }
        }
    }
    for raw in loaded_images()? {
        match check_path(&raw, false) {
            Ok(true) => return Ok(Some(format!("loaded driver image {raw}"))),
            Ok(false) => (),
            Err(e) => {
                unresolved.get_or_insert(e);
            }
        }
    }
    if let Some(e) = unresolved {
        return Err(e);
    }
    Ok(None)
}

/// Read-only driver reference check. Never deletes/stops a driver. Any
/// incomplete enumeration or ambiguous image path fails closed.
pub fn driver_bundle_referenced(dir: &Path) -> Result<bool, OsError> {
    driver_bundle_reference(dir).map(|reference| reference.is_some())
}

/// A diagnostic for the driver reference, including its registered service
/// name when present, and the image path. No driver state is changed.
pub fn driver_bundle_reference(dir: &Path) -> Result<Option<String>, OsError> {
    referenced(dir).map_err(|e| OsError::Os {
        code: e.code,
        message: e.message,
    })
}

#[cfg(feature = "ci-test-fixtures")]
pub fn ci_short_path(path: &Path) -> Result<PathBuf, OsError> {
    use ::windows::{Win32::Storage::FileSystem::GetShortPathNameW, core::HSTRING};
    let mut buffer = vec![0u16; 32768];
    let n =
        unsafe { GetShortPathNameW(&HSTRING::from(path.as_os_str()), Some(&mut buffer)) } as usize;
    if n == 0 || n >= buffer.len() {
        return Err(OsError::Os {
            code: -1,
            message: "cannot query fixture short path".into(),
        });
    }
    use std::os::windows::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..n])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_missing_volume_is_absent_but_loaded_volume_is_unknown() {
        let missing = (b'A'..=b'Z')
            .map(|letter| PathBuf::from(format!(r"{}:\unused-driver.sys", char::from(letter))))
            .find(|path| unavailable_volume(path));
        if let Some(path) = missing {
            assert_eq!(canonical_even_missing(&path, true).unwrap(), None);
            assert!(canonical_even_missing(&path, false).is_err());
        }
    }

    #[test]
    fn resolves_supported_driver_path_forms_and_rejects_ambiguity() {
        let root = Path::new(r"C:\Windows");
        for raw in [
            r"\SystemRoot\System32\Drivers\Example.sys",
            r"system32\drivers\example.sys",
            r"\??\C:\Windows\System32\Drivers\Example.sys",
            r#""C:\Windows\System32\Drivers\Example.sys""#,
        ] {
            let path = image_path(raw, root).unwrap();
            assert_eq!(
                normalized(&path).unwrap(),
                r"C:\WINDOWS\SYSTEM32\DRIVERS\EXAMPLE.SYS"
            );
        }
        for raw in [
            r"..\..\example.sys",
            r"C:example.sys",
            r#" "C:\example.sys" arguments "#,
        ] {
            assert!(image_path(raw, root).is_err(), "{raw}");
        }
        assert_eq!(
            normalized(&image_path(r"drivers\example.sys", root).unwrap()).unwrap(),
            r"C:\WINDOWS\DRIVERS\EXAMPLE.SYS"
        );
        let variable = r"%SystemRoot%\System32\Drivers\Example.sys";
        assert_eq!(
            normalized(&image_path(variable, root).unwrap()).unwrap(),
            r"C:\WINDOWS\%SYSTEMROOT%\SYSTEM32\DRIVERS\EXAMPLE.SYS"
        );
        let expanded = expand_vars(variable, root).unwrap();
        assert_eq!(
            normalized(&image_path(&expanded, root).unwrap()).unwrap(),
            r"C:\WINDOWS\SYSTEM32\DRIVERS\EXAMPLE.SYS"
        );
        assert!(expand_vars(r"%ETD_CB_UNKNOWN_TEST_ENV_VAR%\example.sys", root).is_err());

        assert!(inside(r"C:\STORE\HASH\DRIVER.SYS", r"C:\STORE\HASH"));
        assert!(!inside(r"C:\STORE\HASH2\DRIVER.SYS", r"C:\STORE\HASH"));
    }

    /// A `SystemModuleInformation` buffer with one entry per path.
    fn modules(paths: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![0u8; MODULES_HEADER];
        bytes[..4].copy_from_slice(&(paths.len() as u32).to_le_bytes());
        for path in paths {
            let mut entry = vec![0u8; MODULE_ENTRY];
            let offset = path
                .iter()
                .rposition(|byte| *byte == b'\\')
                .map_or(0, |slash| slash + 1) as u16;
            entry[MODULE_NAME - 2..MODULE_NAME].copy_from_slice(&offset.to_le_bytes());
            let len = path.len().min(MODULE_NAME_LEN);
            entry[MODULE_NAME..MODULE_NAME + len].copy_from_slice(&path[..len]);
            bytes.extend(entry);
        }
        bytes
    }

    /// One module whose file-name offset is `offset`, whatever the path.
    fn offset_at(path: &[u8], offset: u16) -> Vec<u8> {
        let mut bytes = modules(&[path]);
        bytes[MODULES_HEADER + MODULE_NAME - 2..MODULES_HEADER + MODULE_NAME]
            .copy_from_slice(&offset.to_le_bytes());
        bytes
    }

    #[test]
    fn the_kernel_module_list_yields_complete_paths_or_fails() {
        let paths: [&[u8]; 6] = [
            br"\SystemRoot\system32\ntoskrnl.exe",
            br"\SystemRoot\System32\drivers\wintun.sys",
            br"\??\C:\Program Files\EasyTierDesk\cores\abc\WinDivert64.sys",
            br"\??\UNC\server\share\x.sys",
            br"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\x.sys",
            br"\Device\HarddiskVolume3\Windows\x.sys",
        ];
        let parsed = parse_modules(&modules(&paths), ansi_path).unwrap();
        assert_eq!(
            parsed,
            paths
                .iter()
                .map(|path| String::from_utf8(path.to_vec()).unwrap())
                .collect::<Vec<_>>()
        );

        let long = [b'a'; MODULE_NAME_LEN - 1];
        let mut unterminated = modules(&[br"\SystemRoot\x.sys"]);
        unterminated[MODULES_HEADER + MODULE_NAME..MODULES_HEADER + MODULE_ENTRY].fill(b'a');
        let mut bad_offset = modules(&[br"\SystemRoot\x.sys"]);
        bad_offset[MODULES_HEADER + MODULE_NAME - 2] = 3;
        let mut short = modules(&[br"\SystemRoot\x.sys", br"\SystemRoot\y.sys"]);
        short.truncate(short.len() - 1);
        let mut none = modules(&[]);
        none.resize(MODULES_HEADER + MODULE_ENTRY, 0);
        for (bytes, expected) in [
            (modules(&[b""]), "empty"),
            (modules(&[&long]), "truncated"),
            (unterminated, "unterminated"),
            (bad_offset, "inconsistent"),
            (modules(&[br"\??\C:\Drivers\caf?.sys"]), "not representable"),
            (modules(&[b"ntoskrnl.exe"]), "inconsistent"),
            (
                modules(&[br"system32\drivers\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\Windows\System32\drivers\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\??\C:\Drivers\.\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\??\C:\Drivers\\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\??\Drivers\x.sys"]),
                "not a complete absolute path",
            ),
            (modules(&[br"\SystemRoot\"]), "inconsistent"),
            (
                modules(&[br"\??\UNC\server\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\??\UNC\\share\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\??\Volume{01234567-89ab-cdef-0123}\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\??\Volume{0123456g-89ab-cdef-0123-456789abcdef}\x.sys"]),
                "not a complete absolute path",
            ),
            (
                modules(&[br"\??\Volume{}\x.sys"]),
                "not a complete absolute path",
            ),
            (
                offset_at(br"\SystemRoot\System32\drivers\x.sys", 0),
                "inconsistent",
            ),
            (
                offset_at(br"\SystemRoot\System32\drivers\x.sys", 12),
                "inconsistent",
            ),
            (
                offset_at(br"\SystemRoot\System32\drivers\x.sys", 31),
                "inconsistent",
            ),
            (short, "count"),
            (none, "count"),
            (vec![1, 0], "short"),
        ] {
            let error = parse_modules(&bytes, ansi_path).unwrap_err();
            assert!(error.message.contains(expected), "{}", error.message);
        }
        let error = parse_modules(&modules(&[b"\\SystemRoot\\\xff.sys"]), |_| {
            Err(error("not valid in the ANSI code page"))
        })
        .unwrap_err();
        assert!(error.message.contains("ANSI"), "{}", error.message);
    }

    #[test]
    fn module_paths_normalize_like_registered_ones() {
        let root = Path::new(r"C:\Windows");
        for raw in [
            r"\SystemRoot\System32\drivers\WinDivert64.sys",
            r"\??\C:\Windows\System32\drivers\WinDivert64.sys",
        ] {
            assert_eq!(
                normalized(&image_path(raw, root).unwrap()).unwrap(),
                r"C:\WINDOWS\SYSTEM32\DRIVERS\WINDIVERT64.SYS"
            );
        }

        // An 8.3 alias of a store file resolves inside the store, as the
        // existing comparison canonicalizes before comparing.
        use ::windows::{Win32::Storage::FileSystem::GetShortPathNameW, core::HSTRING};
        let base = tempfile::Builder::new()
            .prefix("etd driver store long name ")
            .tempdir()
            .unwrap();
        let store = base.path().join("kernel store directory");
        fs::create_dir_all(&store).unwrap();
        let file = store.join("WinDivert64-long-name.sys");
        fs::write(&file, b"driver").unwrap();
        let mut buffer = vec![0u16; 32768];
        let n = unsafe { GetShortPathNameW(&HSTRING::from(file.as_os_str()), Some(&mut buffer)) }
            as usize;
        assert!(n > 0 && n < buffer.len());
        let short = decode(&buffer[..n]).unwrap();
        let store_dir = normalized(&fs::canonicalize(&store).unwrap()).unwrap();
        let path = image_path(&format!(r"\??\{short}"), root).unwrap();
        let canonical = canonical_even_missing(&path, false).unwrap().unwrap();
        assert!(
            inside(&normalized(&canonical).unwrap(), &store_dir),
            "{short} -> {} not inside {store_dir}",
            canonical.display()
        );
        if short.eq_ignore_ascii_case(file.to_str().unwrap()) {
            println!("8.3 names are disabled on this volume; checked the long form only");
        }
    }
}
