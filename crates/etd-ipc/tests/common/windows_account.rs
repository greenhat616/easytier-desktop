//! Elevated Windows test fixture. Keep the new account only long enough to
//! obtain its logon token. The password never enters a file or command line.
use etd_ipc::OsUserId;
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT, LogonUserW, TOKEN_USER, TokenUser,
        },
    },
    core::{PCWSTR, PWSTR, w},
};

// NetAPI's level-1 USER_INFO_1 and the system-preferred BCrypt RNG.
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

struct Account(Vec<u16>);
impl Drop for Account {
    fn drop(&mut self) {
        let rc = unsafe { NetUserDel(ptr::null(), self.0.as_ptr()) };
        assert_eq!(rc, 0, "could not remove temporary IPC test account: {rc}");
    }
}

pub fn logon() -> (OwnedHandle, OsUserId) {
    let mut random = [0u8; 40];
    assert_eq!(
        unsafe { BCryptGenRandom(ptr::null_mut(), random.as_mut_ptr(), random.len() as u32, 2) },
        0
    );
    let suffix = u64::from_le_bytes(random[..8].try_into().unwrap());
    let name: Vec<_> = format!("etdi{suffix:016x}")
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
    let rc = unsafe { NetUserAdd(ptr::null(), 1, &info, ptr::null_mut()) };
    assert_eq!(
        rc,
        0,
        "create temporary standard user: {}",
        io::Error::from_raw_os_error(rc as i32)
    );
    let account = Account(name);
    let mut token = HANDLE::default();
    let result = unsafe {
        LogonUserW(
            PCWSTR(account.0.as_ptr()),
            w!("."),
            PCWSTR(password.as_ptr()),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    for ch in &mut password {
        unsafe {
            ptr::write_volatile(ch, 0);
        }
    }
    for b in &mut random {
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
    drop(account);
    result.unwrap();
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    // TOKEN_USER contains a pointer into its own variable-sized buffer.
    let mut data = vec![0usize; 128];
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some(data.as_mut_ptr().cast()),
            size_of_val(data.as_slice()) as u32,
            &mut size,
        )
        .unwrap();
        let user = &*data.as_ptr().cast::<TOKEN_USER>();
        let mut sid = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid).unwrap();
        let value = sid.to_string().unwrap();
        LocalFree(Some(HLOCAL(sid.0.cast())));
        (token, OsUserId::WindowsSid(value))
    }
}
