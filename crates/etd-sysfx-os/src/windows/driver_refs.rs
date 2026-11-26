use super::{WinError, registry::Key};
use crate::OsError;
use ::windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NOT_ALL_ASSIGNED,
            GetLastError, HANDLE, LUID,
        },
        Security::{
            AdjustTokenPrivileges, ImpersonateSelf, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
            RevertToSelf, SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, GetLogicalDriveStringsW,
            QueryDosDeviceW,
        },
        System::{
            ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW},
            Registry::{
                HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
            },
            Services::*,
            SystemInformation::GetWindowsDirectoryW,
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    },
    core::{PCWSTR, w},
};
use std::{
    ffi::c_void,
    fs, io,
    os::windows::io::AsRawHandle,
    path::{Component, Path, PathBuf},
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
    buffer_string(&buffer, config.lpBinaryPathName.0)
}

fn registered_images() -> Result<Vec<(String, String)>, WinError> {
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
    let mut images = Vec::new();
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
            let image = service_image(manager.0, &name)?;
            if image.is_empty() {
                // The documented default SCM driver image path.
                images.push((name.clone(), format!(r"System32\Drivers\{name}.sys")));
            } else {
                images.push((name, image));
            }
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
fn registry_images() -> Result<Vec<(String, String)>, WinError> {
    let services = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services",
        KEY_READ,
    )?
    .ok_or_else(|| error("SCM registry database unavailable"))?;
    let mut images = Vec::new();
    for name in services.children()? {
        let key = Key::open(services.0, &name, KEY_QUERY_VALUE)?
            .ok_or_else(|| error("service registration changed during enumeration"))?;
        let Some(kind) = key.read("Type")? else {
            continue;
        };
        if kind.ty != REG_DWORD || kind.bytes.len() != 4 {
            return Err(error(format!("invalid service type for {name}")));
        }
        let kind = u32::from_le_bytes(kind.bytes.try_into().expect("checked size"));
        if kind & SERVICE_DRIVER.0 == 0 {
            continue;
        }
        let path = match key.read("ImagePath")? {
            None => format!(r"System32\Drivers\{name}.sys"),
            Some(value) => {
                if !matches!(value.ty, REG_SZ | REG_EXPAND_SZ)
                    || !value.bytes.len().is_multiple_of(2)
                {
                    return Err(error(format!("invalid driver ImagePath for {name}")));
                }
                let units: Vec<_> = value
                    .bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|chunk| u16::from_le_bytes(*chunk))
                    .collect();
                let path = nul_string(&units)?;
                if path.is_empty() {
                    format!(r"System32\Drivers\{name}.sys")
                } else {
                    path
                }
            }
        };
        images.push((name, path));
    }
    Ok(images)
}

// Recent Windows releases require SeDebugPrivilege for non-null loaded-driver
// bases. Enable only on a private impersonation token of this worker thread,
// never on the process token. Revert before returning to the caller.
fn loaded_images() -> Result<Vec<String>, WinError> {
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
            if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
                return Err(error("loaded driver enumeration privilege unavailable"));
            }
            Ok(())
        })();
        // SAFETY: owned token.
        let _ = unsafe { CloseHandle(token) };
        privilege?;
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
            return Ok(images);
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
    let n = unsafe { GetWindowsDirectoryW(Some(&mut buffer)) } as usize;
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
    fs::canonicalize(format!(r"\\?\GLOBALROOT{value}")).map_err(io_error)
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
    let path = if let Some(tail) = strip_prefix_ci(value, r"\SystemRoot\")
        .or_else(|| strip_prefix_ci(value, r"%SystemRoot%\"))
        .or_else(|| strip_prefix_ci(value, r"%windir%\"))
    {
        system_root.join(tail)
    } else if strip_prefix_ci(value, r"System32\").is_some() {
        system_root.join(value)
    } else if strip_prefix_ci(value, r"\Device\").is_some() {
        device_path(value)?
    } else if let Some(tail) = strip_prefix_ci(value, r"%SystemDrive%\") {
        let root = system_root
            .ancestors()
            .last()
            .ok_or_else(|| error("invalid Windows directory"))?;
        root.join(tail)
    } else if strip_prefix_ci(value, "Volume{").is_some() {
        PathBuf::from(format!(r"\\?\{value}"))
    } else if strip_prefix_ci(value, r"UNC\").is_some() {
        PathBuf::from(format!(r"\\{}", &value[4..]))
    } else {
        PathBuf::from(value)
    };
    if !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || path.to_str().is_none_or(|path| path.contains('%'))
    {
        return Err(error(format!("cannot normalize driver image path: {raw}")));
    }
    Ok(path)
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

fn identity(path: &Path) -> Result<(u32, u64), WinError> {
    use std::os::windows::fs::OpenOptionsExt;
    // Query only metadata: reading another driver image is unnecessary.
    let file = fs::OpenOptions::new()
        .access_mode(0)
        .open(path)
        .map_err(io_error)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns the live handle and info is writable.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(WinError::windows)?;
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

// If the image is missing, canonicalize its closest existing ancestor to
// account for directory junctions; any error other than NotFound is ambiguous.
fn canonical_even_missing(path: &Path) -> Result<PathBuf, WinError> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| io_error(e))?;
            let name = path
                .file_name()
                .ok_or_else(|| error("missing driver path name"))?;
            Ok(canonical_even_missing(parent)?.join(name))
        }
        Err(e) => Err(io_error(e)),
    }
}

fn collect_identities(dir: &Path, identities: &mut Vec<(u32, u64)>) -> Result<(), WinError> {
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
    let check = |raw: &str| -> Result<bool, WinError> {
        let path = image_path(raw, &system_root)?;
        if inside(&normalized(&path)?, &normalized_dir) {
            return Ok(true);
        }
        let canonical = canonical_even_missing(&path)?;
        if inside(&normalized(&canonical)?, &normalized_dir) {
            return Ok(true);
        }
        match fs::metadata(&canonical) {
            Ok(_) => Ok(identities.contains(&identity(&canonical)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_error(e)),
        }
    };
    let mut unresolved = None;
    let mut registered = registered_images()?;
    registered.extend(registry_images()?);
    for (name, raw) in registered {
        match check(&raw) {
            Ok(true) => return Ok(Some(format!("driver service {name} references {raw}"))),
            Ok(false) => (),
            Err(e) => {
                unresolved.get_or_insert(e);
            }
        }
    }
    for raw in loaded_images()? {
        match check(&raw) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_supported_driver_path_forms_and_rejects_ambiguity() {
        let root = Path::new(r"C:\Windows");
        for raw in [
            r"\SystemRoot\System32\Drivers\Example.sys",
            r"%SystemRoot%\System32\Drivers\Example.sys",
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
            r"..\example.sys",
            r"%Unknown%\example.sys",
            r"C:example.sys",
            r"\SystemRoot\..\example.sys",
            r#" "C:\example.sys" arguments "#,
        ] {
            assert!(image_path(raw, root).is_err(), "{raw}");
        }
        assert!(inside(r"C:\STORE\HASH\DRIVER.SYS", r"C:\STORE\HASH"));
        assert!(!inside(r"C:\STORE\HASH2\DRIVER.SYS", r"C:\STORE\HASH"));
    }
}
