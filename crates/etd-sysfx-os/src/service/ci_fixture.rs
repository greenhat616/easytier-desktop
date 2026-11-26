//! Test-only Windows identity fixture. This module is not compiled in a
//! normal product build. Every entry point is also gated to the dedicated
//! privileged install CI job; no account is created on a developer machine.
use ::windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_ACCESS_DENIED, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, ImpersonateLoggedOnUser,
            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW, RevertToSelf,
            TOKEN_USER, TokenUser,
        },
        System::Threading::{
            OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_TERMINATE, PROCESS_VM_READ,
        },
    },
    core::{PCWSTR, PWSTR, w},
};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};

fn ci_only() -> io::Result<()> {
    if std::env::var("CI").as_deref() == Ok("true")
        && std::env::var("ETD_HOST_CI_INSTALL").as_deref() == Ok("1")
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privileged installation CI fixture is disabled",
        ))
    }
}
fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

// The same ephemeral standard-user strategy as I1's pipe ACL fixture.
// The OS creates and immediately removes the account; its live token stays
// valid for the tests. Neither credentials nor account creation reach a
// production build or any command line.
#[repr(C)]
struct UserInfo {
    name: *const u16,
    password: *const u16,
    password_age: u32,
    privilege: u32,
    home: *const u16,
    comment: *const u16,
    flags: u32,
    script: *const u16,
}
#[link(name = "netapi32")]
unsafe extern "system" {
    fn NetUserAdd(server: *const u16, level: u32, info: *const UserInfo, error: *mut u32) -> u32;
    fn NetUserDel(server: *const u16, name: *const u16) -> u32;
}
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut std::ffi::c_void,
        buffer: *mut u8,
        length: u32,
        flags: u32,
    ) -> i32;
}

pub struct StandardAccount {
    token: OwnedHandle,
    sid: String,
}
impl StandardAccount {
    pub fn create() -> io::Result<Self> {
        ci_only()?;
        if !super::windows::elevated()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "elevated CI token required",
            ));
        }
        let mut random = [0u8; 40];
        if unsafe { BCryptGenRandom(ptr::null_mut(), random.as_mut_ptr(), random.len() as u32, 2) }
            != 0
        {
            return Err(io::Error::other("CI random generation failed"));
        }
        let suffix = u64::from_le_bytes(random[..8].try_into().expect("eight bytes"));
        let name: Vec<_> = format!("etdh{suffix:016x}")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut password = Vec::from([b'A' as u16, b'a' as u16, b'9' as u16, b'!' as u16]);
        for &byte in &random[8..] {
            for digit in [byte >> 4, byte & 15] {
                password.push(u16::from(b'A' + digit));
            }
        }
        password.push(0);
        let info = UserInfo {
            name: name.as_ptr(),
            password: password.as_ptr(),
            password_age: 0,
            privilege: 1,
            home: ptr::null(),
            comment: ptr::null(),
            flags: 0x201,
            script: ptr::null(),
        };
        let created = unsafe { NetUserAdd(ptr::null(), 1, &info, ptr::null_mut()) };
        let mut token = HANDLE::default();
        let logon = if created == 0 {
            unsafe {
                LogonUserW(
                    PCWSTR(name.as_ptr()),
                    w!("."),
                    PCWSTR(password.as_ptr()),
                    LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT,
                    &mut token,
                )
            }
            .map_err(other)
        } else {
            Err(io::Error::from_raw_os_error(created as i32))
        };
        for ch in &mut password {
            unsafe {
                ptr::write_volatile(ch, 0);
            }
        }
        for byte in &mut random {
            unsafe {
                ptr::write_volatile(byte, 0);
            }
        }
        let token = logon.map(|()| unsafe { OwnedHandle::from_raw_handle(token.0) });
        if created == 0 {
            let removed = unsafe { NetUserDel(ptr::null(), name.as_ptr()) };
            if removed != 0 {
                return Err(io::Error::other(format!(
                    "could not remove CI standard-account fixture: OS error {removed}"
                )));
            }
        }
        let token = token?;
        let mut size = 0u32;
        let handle = HANDLE(token.as_raw_handle());
        unsafe {
            let _ = GetTokenInformation(handle, TokenUser, None, 0, &mut size);
        }
        let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        let sid = unsafe {
            GetTokenInformation(
                handle,
                TokenUser,
                Some(data.as_mut_ptr().cast()),
                size,
                &mut size,
            )
            .map_err(other)?;
            if (size as usize) < size_of::<TOKEN_USER>() {
                return Err(io::Error::other("invalid CI token user data"));
            }
            let user = &*data.as_ptr().cast::<TOKEN_USER>();
            let mut text = PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut text).map_err(other)?;
            let sid = text.to_string().map_err(other);
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            sid?
        };
        Ok(Self { token, sid })
    }
    pub fn sid(&self) -> &str {
        &self.sid
    }

    /// Run the test closure on a dedicated thread. No unrelated work can
    /// inherit the temporary account's thread identity.
    pub fn run<T: Send + 'static>(
        &self,
        body: impl FnOnce() -> T + Send + 'static,
    ) -> io::Result<T> {
        ci_only()?;
        let token = self.token.try_clone()?;
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() }.is_err() {
                    std::process::abort();
                }
            }
        }
        std::thread::spawn(move || {
            unsafe {
                ImpersonateLoggedOnUser(HANDLE(token.as_raw_handle())).map_err(other)?;
            }
            let _revert = Revert;
            Ok::<_, io::Error>(body())
        })
        .join()
        .map_err(|_| io::Error::other("CI standard-account thread panicked"))?
    }
}

/// From the standard-account thread, prove that only the process metadata
/// handle may be opened. Merely opening or denying a handle is tested; no
/// sensitive operation is performed.
pub fn assert_query_only(pid: u32) -> io::Result<()> {
    ci_only()?;
    let query =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.map_err(other)?;
    unsafe {
        CloseHandle(query).map_err(other)?;
    }
    for access in [
        PROCESS_TERMINATE,
        PROCESS_VM_READ,
        PROCESS_ACCESS_RIGHTS(0x0004_0000),
    ] {
        match unsafe { OpenProcess(access, false, pid) } {
            Ok(handle) => {
                let _ = unsafe { CloseHandle(handle) };
                return Err(io::Error::other(format!(
                    "standard token unexpectedly acquired process right {:#x}",
                    access.0
                )));
            }
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => (),
            Err(error) => return Err(other(error)),
        }
    }
    Ok(())
}
