use super::*;
use std::{ffi::OsString, os::windows::ffi::OsStringExt};
use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, HLOCAL, LocalFree},
        Security::{Authorization::ConvertSidToStringSidW, *},
        System::{
            Pipes::ImpersonateNamedPipeClient,
            SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY},
            Threading::*,
        },
    },
    core::PWSTR,
};

pub(super) struct Allocation(pub HLOCAL);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(Some(self.0));
        }
    }
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut ptr = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut ptr).map_err(win_error)? };
    let _owner = Allocation(HLOCAL(ptr.0.cast()));
    unsafe { ptr.to_string() }.map_err(io::Error::other)
}

fn process_token(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token)
            .map_err(|e| io::Error::other(format!("OpenProcessToken: {e}")))?;
        Ok(OwnedHandle::from_raw_handle(token.0))
    }
}

fn info(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut len = 0;
    let handle = HANDLE(token.as_raw_handle());
    let err = unsafe { GetTokenInformation(handle, class, None, 0, &mut len) }.unwrap_err();
    if err.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() || len == 0 {
        return Err(io::Error::other(format!("token info {class:?}: {err}")));
    }
    // Token structures contain pointers. Allocate pointer-aligned storage and
    // retain it while dereferencing any SID returned inside the buffer.
    let mut data = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
    unsafe {
        GetTokenInformation(handle, class, Some(data.as_mut_ptr().cast()), len, &mut len)
            .map_err(|e| io::Error::other(format!("GetTokenInformation: {e}")))?;
    }
    Ok(data)
}

fn token_user(token: &OwnedHandle) -> io::Result<OsUserId> {
    let data = info(token, TokenUser)?;
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    Ok(OsUserId::WindowsSid(sid_string(user.User.Sid)?))
}

pub(super) fn current_user() -> io::Result<OsUserId> {
    token_user(&process_token(unsafe { GetCurrentProcess() })?)
}

fn token_peer(token: &OwnedHandle, pid: u32) -> io::Result<PeerIdentity> {
    let user = token_user(token)?;
    let data = info(token, TokenGroups)?;
    // TOKEN_GROUPS has a variable-length trailing array, possibly empty.
    // Address it through raw pointers without borrowing a fictitious first entry.
    let ptr = data.as_ptr().cast::<TOKEN_GROUPS>();
    let entries = unsafe {
        let count = (*ptr).GroupCount as usize;
        std::slice::from_raw_parts(
            (&raw const (*ptr).Groups).cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let groups = entries
        .iter()
        .filter(|g| {
            g.Attributes & SE_GROUP_ENABLED as u32 != 0
                && g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
        })
        .map(|g| sid_string(g.Sid).map(OsGroupId::WindowsSid))
        .collect::<io::Result<_>>()?;
    let mut session = 0u32;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0;
    unsafe {
        let h = HANDLE(token.as_raw_handle());
        GetTokenInformation(
            h,
            TokenSessionId,
            Some((&raw mut session).cast()),
            size_of_val(&session) as u32,
            &mut len,
        )
        .map_err(win_error)?;
        GetTokenInformation(
            h,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            size_of_val(&elevation) as u32,
            &mut len,
        )
        .map_err(win_error)?;
    }
    let elevated = elevation.TokenIsElevated != 0;
    Ok(PeerIdentity {
        user,
        groups,
        pid,
        session: Some(session),
        elevated,
    })
}

/// Obtain the effective security context on this pipe. A PID can outlive
/// its process, and a connecting thread may be impersonating a different user.
pub(super) fn client_peer(pipe: &NamedPipeServer) -> io::Result<PeerIdentity> {
    let handle = HANDLE(pipe.as_raw_handle());
    let mut pid = 0;
    let mut token = HANDLE::default();
    unsafe {
        GetNamedPipeClientProcessId(handle, &mut pid).map_err(win_error)?;
        ImpersonateNamedPipeClient(handle).map_err(win_error)?;
        // No await or fallible early return while impersonating.
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token);
        if RevertToSelf().is_err() {
            std::process::abort();
        }
        opened.map_err(win_error)?;
        token_peer(&OwnedHandle::from_raw_handle(token.0), pid)
    }
}

pub(super) fn server_identity(
    pipe: &NamedPipeClient,
    expect: &ServerExpectation,
    opened_after: std::time::SystemTime,
) -> io::Result<ServerIdentity> {
    let mut pid = 0;
    unsafe {
        GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut pid)
            .map_err(|e| io::Error::other(format!("GetNamedPipeServerProcessId: {e}")))?;
    }
    let process = unsafe {
        OwnedHandle::from_raw_handle(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|e| io::Error::other(format!("OpenProcess: {e}")))?
                .0,
        )
    };
    let handle = HANDLE(process.as_raw_handle());
    // A replacement process that acquired a recycled server PID after we
    // started opening this pipe cannot vouch for its former owner.
    let (mut created, mut exit, mut kernel, mut user) = Default::default();
    unsafe {
        GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user)
            .map_err(|e| io::Error::other(format!("GetProcessTimes: {e}")))?;
    }
    let ticks = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
    let unix_ticks = ticks
        .checked_sub(116444736000000000)
        .ok_or_else(|| denied("invalid process creation time"))?;
    let created_at = std::time::UNIX_EPOCH
        + std::time::Duration::from_secs(unix_ticks / 10_000_000)
        + std::time::Duration::from_nanos((unix_ticks % 10_000_000) * 100);
    if created_at > opened_after || exit.dwHighDateTime != 0 || exit.dwLowDateTime != 0 {
        return Err(denied("server process changed"));
    }
    let peer = token_peer(&process_token(handle)?, pid)?;
    verify_user(
        expect,
        &peer.user,
        current_user()?,
        OsUserId::WindowsSid("S-1-5-18".into()),
    )?;
    let mut path = vec![0u16; 32768];
    let mut len = path.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut len,
        )
        .map_err(|e| io::Error::other(format!("QueryFullProcessImageNameW: {e}")))?;
    }
    let path = PathBuf::from(OsString::from_wide(&path[..len as usize]));
    Ok(ServerIdentity {
        peer,
        exe: verify_image(&expect.exe_dir, &path)?,
    })
}
