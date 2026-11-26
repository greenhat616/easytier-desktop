//! Tokens for the elevated session pipe tests: restricted copies of the
//! runner's own token (Administrators deny-only, chosen integrity level) and
//! an AppContainer (low-box) copy, used by impersonating them on the test
//! thread or by starting a child process with them.
#![allow(dead_code)]
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows::{
    Win32::{
        Foundation::{
            HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree, SetHandleInformation, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::ConvertStringSidToSidW, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE,
            ImpersonateLoggedOnUser, PSID, RevertToSelf, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES,
            SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_MANDATORY_LABEL, TokenIntegrityLevel,
        },
        Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, READ_CONTROL,
            SECURITY_IDENTIFICATION, SYNCHRONIZE,
        },
        System::{
            Pipes::CreatePipe,
            SystemServices::SE_GROUP_INTEGRITY,
            Threading::{
                CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateEventW, CreateProcessAsUserW,
                GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, PROCESS_INFORMATION,
                STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

pub const LOW: u32 = 0x1000;
pub const MEDIUM: u32 = 0x2000;

/// The access mask `LocalConnector` requests.
pub fn client_mask() -> u32 {
    (FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE).0
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// A SID allocated by `ConvertStringSidToSidW`.
struct Sid(PSID);
impl Sid {
    fn parse(text: &str) -> Self {
        let mut sid = PSID::default();
        unsafe { ConvertStringSidToSidW(PCWSTR(wide(text).as_ptr()), &mut sid).unwrap() };
        Self(sid)
    }
}
impl Drop for Sid {
    fn drop(&mut self) {
        unsafe {
            LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

fn own_token() -> OwnedHandle {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token).unwrap();
        OwnedHandle::from_raw_handle(token.0)
    }
}

/// A primary token like the one a non-elevated UI of the runner's account
/// would have: Administrators deny-only, no privileges beyond the minimum,
/// and integrity `rid` (for example [`MEDIUM`] or [`LOW`]). It still
/// reports `TokenElevation`, as every copy of an elevated token does.
pub fn restricted_token(rid: u32) -> OwnedHandle {
    copy_token(rid, true)
}

/// A copy of the runner's elevated token lowered to integrity `rid`, with
/// minimal privileges but Administrators still enabled. A process started
/// with a deny-only copy fails user32 initialisation (0xC0000142) on the
/// runner's window station, so child processes use this one.
pub fn lowered_token(rid: u32) -> OwnedHandle {
    copy_token(rid, false)
}

fn copy_token(rid: u32, deny_admins: bool) -> OwnedHandle {
    let own = own_token();
    let admins = Sid::parse("S-1-5-32-544");
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admins.0,
        Attributes: 0,
    }];
    let mut token = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            HANDLE(own.as_raw_handle()),
            DISABLE_MAX_PRIVILEGE,
            deny_admins.then_some(&disable[..]),
            None,
            None,
            &mut token,
        )
        .unwrap();
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let level = Sid::parse(&format!("S-1-16-{rid}"));
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: level.0,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    unsafe {
        SetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size_of_val(&label) as u32,
        )
        .unwrap();
    }
    token
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: HANDLE,
    name: *const core::ffi::c_void,
    attributes: u32,
    descriptor: *const core::ffi::c_void,
    qos: *const core::ffi::c_void,
}
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
/// SECURITY_QUALITY_OF_SERVICE.
#[repr(C)]
struct Qos {
    length: u32,
    level: u32,
    tracking: u8,
    effective_only: u8,
}
#[repr(C)]
#[derive(Default)]
struct IoStatus {
    status: usize,
    information: usize,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        handle: *mut HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        io: *mut IoStatus,
        allocation: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const core::ffi::c_void,
        ea_length: u32,
    ) -> i32;
    fn NtWriteFile(
        handle: HANDLE,
        event: HANDLE,
        apc: *const core::ffi::c_void,
        apc_context: *const core::ffi::c_void,
        io: *mut IoStatus,
        buffer: *const u8,
        length: u32,
        offset: *const i64,
        key: *const u32,
    ) -> i32;
    fn NtQueryObject(
        handle: HANDLE,
        class: u32,
        info: *mut core::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtCreateLowBoxToken(
        token: *mut HANDLE,
        existing: HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        package: PSID,
        capability_count: u32,
        capabilities: *const SID_AND_ATTRIBUTES,
        handle_count: u32,
        handles: *const HANDLE,
    ) -> i32;
}

/// An AppContainer (low-box) copy of the runner's token, with no
/// capabilities, for a made-up package SID.
pub fn app_container_token() -> OwnedHandle {
    let own = own_token();
    let package = Sid::parse("S-1-15-2-1-2-3-4-5-6-7");
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: HANDLE::default(),
        name: ptr::null(),
        attributes: 0,
        descriptor: ptr::null(),
        qos: ptr::null(),
    };
    let mut token = HANDLE::default();
    let status = unsafe {
        NtCreateLowBoxToken(
            &mut token,
            HANDLE(own.as_raw_handle()),
            TOKEN_ALL_ACCESS.0,
            &attributes,
            package.0,
            0,
            ptr::null(),
            0,
            ptr::null(),
        )
    };
    assert_eq!(status, 0, "NtCreateLowBoxToken: {status:#x}");
    unsafe { OwnedHandle::from_raw_handle(token.0) }
}

/// OBJECT_BASIC_INFORMATION.
#[repr(C)]
#[derive(Default)]
struct ObjectBasicInformation {
    attributes: u32,
    granted_access: u32,
    handle_count: u32,
    pointer_count: u32,
    reserved: [u32; 10],
}

/// The access the kernel actually granted to `file`'s handle.
pub fn granted_access(file: &File) -> u32 {
    let mut info = ObjectBasicInformation::default();
    let status = unsafe {
        NtQueryObject(
            HANDLE(file.as_raw_handle()),
            0, // ObjectBasicInformation
            (&raw mut info).cast(),
            size_of_val(&info) as u32,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, 0, "NtQueryObject: {status:#x}");
    info.granted_access
}

/// Open `\\.\pipe\<leaf>` with exactly `access`, nothing added (CreateFile
/// always adds SYNCHRONIZE and FILE_READ_ATTRIBUTES), identifying the
/// caller. Returns the NTSTATUS on failure.
pub fn nt_open(leaf: &str, access: u32) -> Result<OwnedHandle, i32> {
    let path = wide(&format!(r"\??\pipe\{leaf}"));
    let name = UnicodeString {
        length: ((path.len() - 1) * 2) as u16,
        maximum: (path.len() * 2) as u16,
        buffer: path.as_ptr(),
    };
    let qos = Qos {
        length: size_of::<Qos>() as u32,
        level: 1, // SecurityIdentification
        tracking: 0,
        effective_only: 0,
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: HANDLE::default(),
        name: (&raw const name).cast(),
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        descriptor: ptr::null(),
        qos: (&raw const qos).cast(),
    };
    let mut handle = HANDLE::default();
    let mut io = IoStatus::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut io,
            ptr::null(),
            0,
            3,    // FILE_SHARE_READ | FILE_SHARE_WRITE
            1,    // FILE_OPEN
            0x40, // FILE_NON_DIRECTORY_FILE; asynchronous, no SYNCHRONIZE needed
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(status);
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}

/// Write `bytes` to an asynchronous handle opened by [`nt_open`] and wait
/// for the result. Returns the final NTSTATUS.
pub fn nt_write(handle: &OwnedHandle, bytes: &[u8]) -> i32 {
    let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()).unwrap() };
    let event = unsafe { OwnedHandle::from_raw_handle(event.0) };
    let mut io = IoStatus::default();
    let offset = 0i64;
    let mut status = unsafe {
        NtWriteFile(
            HANDLE(handle.as_raw_handle()),
            HANDLE(event.as_raw_handle()),
            ptr::null(),
            ptr::null(),
            &mut io,
            bytes.as_ptr(),
            bytes.len() as u32,
            &offset,
            ptr::null(),
        )
    };
    if status == 0x103 {
        // STATUS_PENDING
        unsafe { WaitForSingleObject(HANDLE(event.as_raw_handle()), 10_000) };
        status = io.status as i32;
    }
    status
}

/// Connect with `connector` from a dedicated thread that impersonates
/// `token` for the whole connection, as a UI process with that token would.
pub fn connect_as(
    token: OwnedHandle,
    connector: etd_ipc::platform::LocalConnector,
    endpoint: etd_ipc::Endpoint,
) -> io::Result<etd_ipc::ServerIdentity> {
    use etd_ipc::Connector;
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        impersonating(&token, || {
            runtime
                .block_on(connector.connect(&endpoint))
                .map(|(_, server)| server)
        })
    })
    .join()
    .unwrap()
}

/// Run `f` on this thread while impersonating `token`. `f` must not hand
/// work to another thread (no await on a shared runtime), so the
/// impersonation applies to everything it does.
pub fn impersonating<T>(token: &OwnedHandle, f: impl FnOnce() -> T) -> T {
    unsafe { ImpersonateLoggedOnUser(HANDLE(token.as_raw_handle())).unwrap() };
    let result = f();
    if unsafe { RevertToSelf() }.is_err() {
        std::process::abort();
    }
    result
}

/// Open a local pipe with `access`, identifying (not delegating) the caller
/// as `LocalConnector` does.
pub fn open(pipe: &Path, access: u32) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
        .security_qos_flags(SECURITY_IDENTIFICATION.0)
        .open(pipe)
}

/// A child process started with `token`, its stdout and stderr captured.
pub struct Child {
    process: OwnedHandle,
    output: Option<File>,
}

impl Child {
    /// Start `exe args...` with the primary `token`, the current environment
    /// plus `env`, and CREATE_NO_WINDOW.
    pub fn spawn(token: &OwnedHandle, exe: &Path, args: &[&str], env: &[(&str, &OsStr)]) -> Self {
        let mut command_line = format!("\"{}\"", exe.display());
        for arg in args {
            command_line.push(' ');
            command_line.push_str(arg);
        }
        let mut command_line = wide(&command_line);
        let mut block: Vec<u16> = Vec::new();
        for (key, value) in std::env::vars_os().filter(|(key, _)| {
            !env.iter()
                .any(|(name, _)| key.eq_ignore_ascii_case(OsStr::new(name)))
        }) {
            block.extend(key.encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        for (key, value) in env {
            block.extend(OsStr::new(key).encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        block.push(0);
        let inherit = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
        unsafe {
            CreatePipe(&mut read, &mut write, Some(&inherit), 0).unwrap();
            SetHandleInformation(read, HANDLE_FLAG_INHERIT.0, Default::default()).unwrap();
        }
        let read = unsafe { File::from_raw_handle(read.0) };
        let write = unsafe { OwnedHandle::from_raw_handle(write.0) };
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdOutput: HANDLE(write.as_raw_handle()),
            hStdError: HANDLE(write.as_raw_handle()),
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessAsUserW(
                Some(HANDLE(token.as_raw_handle())),
                PCWSTR::null(),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                Some(block.as_ptr().cast()),
                PCWSTR::null(),
                &startup,
                &mut info,
            )
            .unwrap();
            drop(OwnedHandle::from_raw_handle(info.hThread.0));
        }
        // Only the child holds the write end now, so reads end at its exit.
        drop(write);
        Self {
            process: unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) },
            output: Some(read),
        }
    }

    /// The child's output, to read until a readiness line or the end.
    pub fn output(&mut self) -> File {
        self.output.take().expect("output taken once")
    }

    /// Wait (at most 60 s) for the child to exit and return its exit code.
    pub fn wait(self) -> u32 {
        let mut code = 0;
        unsafe {
            let waited = WaitForSingleObject(HANDLE(self.process.as_raw_handle()), 60_000);
            assert_eq!(waited, WAIT_OBJECT_0, "child did not exit within 60 s");
            GetExitCodeProcess(HANDLE(self.process.as_raw_handle()), &mut code).unwrap();
        }
        code
    }
}
