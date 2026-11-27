//! Native registry helpers, including the volatile boot/session marker.
use super::{WinError, wfp::trusted_acl};
use ::windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_CHILD_MUST_BE_VOLATILE, ERROR_FILE_NOT_FOUND,
            ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, HANDLE, HLOCAL,
            LocalFree, WAIT_ABANDONED, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_KERNEL_OBJECT,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
            GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
            WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
        System::{
            Registry::*,
            Threading::{
                CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex,
                WaitForSingleObject,
            },
        },
    },
    core::{BOOL, HSTRING, PCWSTR, PWSTR},
};
use etd_sysfx::BootId;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

pub(super) struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
pub(super) fn check(
    code: ::windows::Win32::Foundation::WIN32_ERROR,
    operation: &str,
) -> Result<(), WinError> {
    if code.0 == 0 {
        Ok(())
    } else {
        Err(WinError::new(code.0 as i64, operation))
    }
}

pub(super) struct Key(pub HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawValue {
    pub ty: REG_VALUE_TYPE,
    pub bytes: Vec<u8>,
}
impl Key {
    pub fn open(root: HKEY, path: &str, access: REG_SAM_FLAGS) -> Result<Option<Self>, WinError> {
        let mut key = HKEY::default();
        let rc = unsafe {
            RegOpenKeyExW(
                root,
                &HSTRING::from(path),
                None,
                access | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(rc, "open registry key")?;
        Ok(Some(Self(key)))
    }
    fn create(
        root: HKEY,
        path: &str,
        options: REG_OPEN_CREATE_OPTIONS,
        access: REG_SAM_FLAGS,
        security: Option<&SECURITY_ATTRIBUTES>,
    ) -> Result<Self, WinError> {
        let mut key = HKEY::default();
        let rc = unsafe {
            RegCreateKeyExW(
                root,
                &HSTRING::from(path),
                None,
                PCWSTR::null(),
                options,
                access | KEY_WOW64_64KEY,
                security.map(|s| s as *const _),
                &mut key,
                None,
            )
        };
        check(rc, "create registry key")?;
        Ok(Self(key))
    }
    pub fn read(&self, name: &str) -> Result<Option<RawValue>, WinError> {
        let name = HSTRING::from(name);
        let mut ty = REG_VALUE_TYPE::default();
        let mut len = 0;
        let rc =
            unsafe { RegQueryValueExW(self.0, &name, None, Some(&mut ty), None, Some(&mut len)) };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(rc, "query registry value length")?;
        // A shared recovery record is untrusted data. Do not allocate without a bound.
        if len > 16 * 1024 * 1024 {
            return Err(WinError::invalid("registry value too large"));
        }
        let mut bytes = vec![0u8; len as usize];
        let rc = unsafe {
            RegQueryValueExW(
                self.0,
                &name,
                None,
                Some(&mut ty),
                Some(bytes.as_mut_ptr()),
                Some(&mut len),
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(rc, "query registry value")?;
        bytes.truncate(len as usize);
        Ok(Some(RawValue { ty, bytes }))
    }
    pub fn set(&self, name: &str, value: &RawValue) -> Result<(), WinError> {
        check(
            unsafe {
                RegSetValueExW(
                    self.0,
                    &HSTRING::from(name),
                    None,
                    value.ty,
                    Some(&value.bytes),
                )
            },
            "set registry value",
        )
    }
    pub fn delete_value(&self, name: &str) -> Result<(), WinError> {
        let rc = unsafe { RegDeleteValueW(self.0, &HSTRING::from(name)) };
        if rc == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            check(rc, "delete registry value")
        }
    }
    pub fn children(&self) -> Result<Vec<String>, WinError> {
        let mut out = Vec::new();
        let mut index = 0;
        loop {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    Some(PWSTR(buf.as_mut_ptr())),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            check(rc, "enumerate registry children")?;
            out.push(
                String::from_utf16(&buf[..len as usize])
                    .map_err(|_| WinError::invalid("invalid registry key name"))?,
            );
            index += 1;
        }
        Ok(out)
    }
    pub fn delete_child(&self, name: &str) -> Result<(), WinError> {
        delete_key(self.0, name, false)
    }
}
pub(super) fn delete_key(root: HKEY, path: &str, recursive: bool) -> Result<(), WinError> {
    let rc = unsafe {
        if recursive {
            RegDeleteTreeW(root, &HSTRING::from(path))
        } else {
            RegDeleteKeyW(root, &HSTRING::from(path))
        }
    };
    if rc == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        check(rc, "delete registry key")
    }
}
pub(super) fn utf16(value: &RawValue) -> Result<Vec<u16>, WinError> {
    if !value.bytes.len().is_multiple_of(2) {
        return Err(WinError::invalid("invalid UTF-16 registry value"));
    }
    Ok(value
        .bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|x| u16::from_le_bytes(*x))
        .collect())
}
fn text(value: &RawValue) -> Result<String, WinError> {
    if value.ty != REG_SZ {
        return Err(WinError::invalid("unexpected registry marker type"));
    }
    let mut buf = utf16(value)?;
    if buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf16(&buf).map_err(|_| WinError::invalid("invalid registry text"))
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}
impl Descriptor {
    fn from_sddl(sddl: &str) -> Result<Self, WinError> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .map_err(WinError::windows)?;
        }
        Ok(Self(sd))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: BOOL(0),
        }
    }
}

pub(super) fn elevated() -> Result<bool, WinError> {
    unsafe {
        let mut raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw).map_err(WinError::windows)?;
        let token = Handle(raw);
        let mut value = TOKEN_ELEVATION::default();
        let mut size = 0;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut value as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .map_err(WinError::windows)?;
        Ok(value.TokenIsElevated != 0)
    }
}

fn machine_descriptor(sd: PSECURITY_DESCRIPTOR, label: &str) -> Result<(), WinError> {
    unsafe {
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl = std::ptr::null_mut();
        let mut owner = PSID::default();
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted)
            .map_err(WinError::windows)?;
        GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted).map_err(WinError::windows)?;
        if !present.as_bool()
            || !trusted_acl(dacl)?
            || owner.0.is_null()
            || !(IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool())
        {
            return Err(WinError::invalid(format!(
                "untrusted machine boot {label} ACL/owner; expected SYSTEM/Administrators only"
            )));
        }
        Ok(())
    }
}
fn machine_acl(key: &Key, label: &str) -> Result<(), WinError> {
    unsafe {
        let info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
        let mut len = 0;
        let rc = RegGetKeySecurity(key.0, info, None, &mut len);
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_MORE_DATA {
            check(rc, "query boot marker security size")?;
        }
        if len == 0 {
            return Err(WinError::invalid("empty boot marker security descriptor"));
        }
        let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
        let sd = PSECURITY_DESCRIPTOR(buf.as_mut_ptr().cast());
        check(
            RegGetKeySecurity(key.0, info, Some(sd), &mut len),
            "read boot marker security",
        )?;
        machine_descriptor(sd, label)
    }
}

fn machine_mutex_acl(handle: &Handle) -> Result<(), WinError> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let rc = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    check(rc, "read machine boot Global mutex security")?;
    if sd.0.is_null() {
        return Err(WinError::invalid(
            "empty machine boot Global mutex security descriptor",
        ));
    }
    let sd = Descriptor(sd);
    machine_descriptor(sd.0, "Global mutex")
}

struct MutexGuard(Handle);
impl Drop for MutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.0.0);
        }
    }
}
fn marker_lock(machine: bool) -> Result<MutexGuard, WinError> {
    // The host has a per-mode singleton. This mutex additionally protects
    // first creation against concurrent maintenance/reader processes.
    let name = if machine {
        r"Global\EasyTierDesk-BootMarker-v1"
    } else {
        r"Local\EasyTierDesk-UserSessionMarker-v1"
    };
    let sd = if machine {
        Some(Descriptor::from_sddl("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")?)
    } else {
        None
    };
    let attrs = sd.as_ref().map(Descriptor::attributes);
    let raw = unsafe {
        CreateMutexW(
            attrs.as_ref().map(|a| a as *const _),
            false,
            &HSTRING::from(name),
        )
        .map_err(|e| WinError::invalid(format!("boot-marker mutex open/creation failed: {e}")))?
    };
    let handle = Handle(raw);
    // CreateMutexW ignores the supplied security attributes if the named
    // object already exists. Never wait on an untrusted machine mutex.
    if machine {
        machine_mutex_acl(&handle)?;
    }
    let wait = unsafe { WaitForSingleObject(handle.0, 5000) };
    if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
        return Err(WinError::invalid("boot-marker lock unavailable"));
    }
    Ok(MutexGuard(handle))
}

pub(super) fn boot_id(machine: bool) -> Result<BootId, WinError> {
    static MACHINE: OnceLock<BootId> = OnceLock::new();
    static USER: OnceLock<BootId> = OnceLock::new();
    static INIT: Mutex<()> = Mutex::new(());
    let cache = if machine { &MACHINE } else { &USER };
    if let Some(id) = cache.get() {
        return Ok(id.clone());
    }
    let _init = INIT
        .lock()
        .map_err(|_| WinError::invalid("boot marker initialization lock poisoned"))?;
    if let Some(id) = cache.get() {
        return Ok(id.clone());
    }
    let id = read_or_create_boot_id(machine)?;
    // Cache only after all ACL, volatility and UUID checks succeeded.
    let _ = cache.set(id.clone());
    Ok(id)
}
/// Uninstall (topic#40 msg#1290): remove the service host's volatile boot
/// marker `HKLM\SOFTWARE\EasyTierDesk\Volatile`, then that parent only if it
/// is left with no subkey and no value. Nothing else is touched; a missing
/// key is fine. Non-recursive: an unexpected subkey under the marker makes
/// this fail rather than delete it.
pub(super) fn remove_machine_boot_marker() -> Result<(), WinError> {
    let _lock = marker_lock(true)?;
    let Some(parent) = Key::open(HKEY_LOCAL_MACHINE, r"SOFTWARE\EasyTierDesk", KEY_READ)? else {
        return Ok(());
    };
    delete_key(parent.0, "Volatile", false)?;
    let mut subkeys = 0u32;
    let mut values = 0u32;
    check(
        unsafe {
            RegQueryInfoKeyW(
                parent.0,
                None,
                None,
                None,
                Some(&raw mut subkeys),
                None,
                None,
                Some(&raw mut values),
                None,
                None,
                None,
                None,
            )
        },
        "query registry key",
    )?;
    drop(parent);
    if subkeys == 0 && values == 0 {
        delete_key(HKEY_LOCAL_MACHINE, r"SOFTWARE\EasyTierDesk", false)?;
    }
    Ok(())
}
fn read_or_create_boot_id(machine: bool) -> Result<BootId, WinError> {
    let _lock = marker_lock(machine)?;
    // HostMode::User rejects elevated entry tokens; it always uses HKCU.
    // This marker ends when that user's hive unloads (user session/logoff),
    // not when a service is subsequently installed. No privileged effects
    // belong to the user ledger. HKLM survives until a full system shutdown.
    let root = if machine {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let sd = if machine {
        Some(Descriptor::from_sddl("O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)")?)
    } else {
        None
    };
    let attrs = sd.as_ref().map(Descriptor::attributes);
    let parent = Key::create(
        root,
        r"SOFTWARE\EasyTierDesk",
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_CREATE_SUB_KEY,
        attrs.as_ref(),
    )?;
    if machine {
        machine_acl(&parent, "parent registry key")?;
    }
    let key = Key::create(
        parent.0,
        "Volatile",
        REG_OPTION_VOLATILE,
        KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
        attrs.as_ref(),
    )?;
    if machine {
        machine_acl(&key, "volatile marker key")?;
    }
    // RegCreateKeyEx ignores REG_OPTION_VOLATILE for an already-existing
    // key. Prove the existing marker is volatile before trusting its UUID.
    // A nonvolatile child cannot be created beneath a volatile key.
    let proof = HSTRING::from(format!("volatility-proof-{}", Uuid::new_v4()));
    let mut child = HKEY::default();
    let rc = unsafe {
        RegCreateKeyExW(
            key.0,
            &proof,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ,
            None,
            &mut child,
            None,
        )
    };
    if rc.0 == 0 {
        drop(Key(child));
        check(
            unsafe { RegDeleteKeyW(key.0, &proof) },
            "remove nonvolatile marker proof",
        )?;
        return Err(WinError::invalid("existing boot marker is not volatile"));
    }
    if rc != ERROR_CHILD_MUST_BE_VOLATILE {
        check(rc, "verify volatile boot marker")?;
    }
    if let Some(v) = key.read("BootId")? {
        let id = Uuid::parse_str(&text(&v)?)
            .map_err(|_| WinError::invalid("invalid stored boot marker UUID"))?;
        return Ok(BootId(id.to_string()));
    }
    let id = Uuid::new_v4();
    let bytes = id
        .to_string()
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    key.set("BootId", &RawValue { ty: REG_SZ, bytes })?;
    Ok(BootId(id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn machine_descriptor_rejects_foreign_owner_or_acl() {
        let trusted = Descriptor::from_sddl("O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)").unwrap();
        machine_descriptor(trusted.0, "parent registry key").unwrap();
        for sddl in [
            "O:BUD:P(A;;KA;;;SY)(A;;KA;;;BA)",
            "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;WD)",
        ] {
            let sd = Descriptor::from_sddl(sddl).unwrap();
            assert!(
                machine_descriptor(sd.0, "parent registry key")
                    .unwrap_err()
                    .message
                    .contains("untrusted machine boot parent registry key")
            );
        }
    }
    #[test]
    fn existing_named_mutex_does_not_inherit_new_security_attributes() {
        let name = HSTRING::from(format!(r"Local\etd-test-mutex-{}", Uuid::new_v4()));
        let unsafe_sd = Descriptor::from_sddl("D:P(A;;GA;;;WD)").unwrap();
        let attrs = unsafe_sd.attributes();
        let _first = Handle(unsafe { CreateMutexW(Some(&attrs), false, &name).unwrap() });
        let secure_sd = Descriptor::from_sddl("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)").unwrap();
        let attrs = secure_sd.attributes();
        let reopened = Handle(unsafe { CreateMutexW(Some(&attrs), false, &name).unwrap() });
        let error = machine_mutex_acl(&reopened).unwrap_err();
        assert!(
            error
                .message
                .contains("untrusted machine boot Global mutex")
        );
    }
}
