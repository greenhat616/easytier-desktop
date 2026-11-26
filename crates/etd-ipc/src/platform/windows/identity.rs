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

fn token_dword(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<u32> {
    let mut value = 0u32;
    let mut len = 0;
    // SAFETY: the buffer is a live, writable u32 of the stated size, and the
    // handle is an open token with TOKEN_QUERY.
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            class,
            Some((&raw mut value).cast()),
            size_of_val(&value) as u32,
            &mut len,
        )
        .map_err(|e| io::Error::other(format!("token info {class:?}: {e}")))?;
    }
    Ok(value)
}

/// The last subauthority of the token's mandatory label, e.g. 0x2000 for
/// Medium.
fn token_integrity(token: &OwnedHandle) -> io::Result<u32> {
    let data = info(token, TokenIntegrityLevel)?;
    // SAFETY: `data` holds a TOKEN_MANDATORY_LABEL written by the kernel,
    // pointer-aligned, whose SID points into `data`, which outlives every
    // use here. The kernel only returns valid SIDs, so the subauthority
    // index below is in bounds.
    unsafe {
        let label = &*data.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return Err(io::Error::other("integrity label without a level"));
        }
        Ok(*GetSidSubAuthority(label.Label.Sid, u32::from(count) - 1))
    }
}

/// SECURITY_MANDATORY_MEDIUM_RID.
const MEDIUM_INTEGRITY: u32 = 0x2000;
/// SECURITY_MANDATORY_HIGH_RID.
const HIGH_INTEGRITY: u32 = 0x3000;

/// Whether a token can act with its elevation. `TokenElevation` alone is not
/// enough: a restricted or lowered copy of an elevated token (Administrators
/// deny-only, integrity Medium) still reports elevated, but cannot write
/// to anything labelled High. The elevated session counts such a token as
/// not elevated.
fn effectively_elevated(token_elevated: bool, integrity: u32) -> bool {
    token_elevated && integrity >= HIGH_INTEGRITY
}

/// The elevated session host's own account and Windows session, read once
/// from its process token when the listener binds.
#[derive(Debug, Clone)]
pub(super) struct SessionOwner {
    user: OsUserId,
    session: u32,
}

pub(super) fn session_owner() -> io::Result<SessionOwner> {
    // SAFETY: the pseudo handle of the current process needs no closing.
    let token = process_token(unsafe { GetCurrentProcess() })?;
    Ok(SessionOwner {
        user: token_user(&token)?,
        session: token_dword(&token, TokenSessionId)?,
    })
}

/// Admission to the elevated session pipe: the host's own account in the
/// host's Windows session, at least Medium integrity, not an AppContainer.
/// The returned identity reports `elevated` only for an elevated token at
/// High integrity or above ([`effectively_elevated`]). Which role the client
/// then gets is the host's decision.
fn admit_session_client(
    mut peer: PeerIdentity,
    integrity: u32,
    app_container: bool,
    owner: &SessionOwner,
) -> io::Result<PeerIdentity> {
    if app_container {
        return Err(denied("AppContainer client refused"));
    }
    if integrity < MEDIUM_INTEGRITY {
        return Err(denied("client integrity below Medium refused"));
    }
    if peer.user != owner.user {
        return Err(denied("client is not the session host's account"));
    }
    if peer.session != Some(owner.session) {
        return Err(denied(
            "client is not in the session host's Windows session",
        ));
    }
    peer.elevated = effectively_elevated(peer.elevated, integrity);
    Ok(peer)
}

/// [`client_peer`] for the elevated session pipe, with every fact read from
/// the same token and checked by [`admit_session_client`].
pub(super) fn session_client_peer(
    pipe: &NamedPipeServer,
    owner: &SessionOwner,
) -> io::Result<PeerIdentity> {
    let mut pid = 0;
    // SAFETY: the pipe handle is open for the duration of the call.
    unsafe {
        GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid).map_err(win_error)?
    };
    let token = pipe_token(pipe)?;
    let peer = token_peer(&token, pid)?;
    let integrity = token_integrity(&token)?;
    let app_container = token_dword(&token, TokenIsAppContainer)? != 0;
    admit_session_client(peer, integrity, app_container, owner)
}

/// Duplicate the pipe's effective thread token before restoring the host
/// identity. No user code runs and no await is possible while impersonating.
fn pipe_token(pipe: &NamedPipeServer) -> io::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    unsafe {
        ImpersonateNamedPipeClient(HANDLE(pipe.as_raw_handle())).map_err(win_error)?;
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token);
        if RevertToSelf().is_err() {
            std::process::abort();
        }
        opened.map_err(win_error)?;
        Ok(OwnedHandle::from_raw_handle(token.0))
    }
}

/// Our connector requests static identification at open time. The kernel
/// can identify that account even while the connector verifies the server.
pub(super) fn admission_user(pipe: &NamedPipeServer) -> io::Result<OsUserId> {
    token_user(&pipe_token(pipe)?)
}

/// Read again after the marker to authenticate the actual writer, including
/// impersonating clients. The process's primary token need not match.
pub(super) fn client_peer(pipe: &NamedPipeServer) -> io::Result<PeerIdentity> {
    let mut pid = 0;
    unsafe {
        GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid).map_err(win_error)?
    };
    token_peer(&pipe_token(pipe)?, pid)
}

fn pipe_owner(pipe: HANDLE) -> io::Result<String> {
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    let mut sid = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut sid),
            None,
            None,
            None,
            Some(&mut sd),
        )
        .ok()
        .map_err(win_error)?;
    }
    let _allocation = Allocation(HLOCAL(sd.0));
    sid_string(sid)
}

fn service_peer(
    expected: &OsUserId,
    owner: String,
    pid: u32,
    session: Option<u32>,
    token: io::Result<PeerIdentity>,
) -> io::Result<PeerIdentity> {
    let OsUserId::WindowsSid(expected) = expected else {
        return Err(denied("expected a Windows service SID"));
    };
    if !owner.eq_ignore_ascii_case(expected) {
        return Err(denied("unexpected pipe owner SID"));
    }
    if let Ok(peer) = token {
        let is_account =
            matches!(&peer.user,OsUserId::WindowsSid(sid) if sid.eq_ignore_ascii_case(expected));
        let is_service_group = peer
            .groups
            .iter()
            .any(|g| matches!(g,OsGroupId::WindowsSid(sid) if sid.eq_ignore_ascii_case(expected)));
        if !is_account && !is_service_group {
            return Err(denied("service token does not contain the expected SID"));
        }
        return Ok(peer);
    }
    // Standard UIs can read the kernel pipe owner and process image while
    // TOKEN_QUERY on LocalSystem is denied. Leave optional token evidence
    // empty/conservative. No server-side RPC is authorized from these fields.
    Ok(PeerIdentity {
        user: OsUserId::WindowsSid(owner),
        groups: vec![],
        pid,
        session,
        elevated: false,
    })
}

/// The server token's identity and integrity level.
fn server_token(process: HANDLE, pid: u32) -> io::Result<(PeerIdentity, u32)> {
    let token = process_token(process)?;
    Ok((token_peer(&token, pid)?, token_integrity(&token)?))
}

/// The elevated session host proof: the current user's elevated token at
/// High integrity or above. Unlike the service proof there is no fallback:
/// a server token that cannot be read is refused.
fn elevated_session_peer(
    token: io::Result<(PeerIdentity, u32)>,
    current: &OsUserId,
) -> io::Result<PeerIdentity> {
    let (peer, integrity) =
        token.map_err(|e| denied(format!("unreadable session host token: {e}")))?;
    if &peer.user != current {
        return Err(denied("unexpected host account"));
    }
    if !effectively_elevated(peer.elevated, integrity) {
        return Err(denied("session host token is not elevated"));
    }
    Ok(peer)
}

pub(super) fn server_identity(
    pipe: &NamedPipeClient,
    exe_dir: &Path,
    proof: Proof<'_>,
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
    if created_at > opened_after {
        return Err(denied("server process changed"));
    }
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
    let exe = verify_image(exe_dir, &path)?;
    let pipe_handle = HANDLE(pipe.as_raw_handle());
    let system = OsUserId::WindowsSid("S-1-5-18".into());
    let token = process_token(handle).and_then(|token| token_peer(&token, pid));
    let peer = if proof.privileged {
        let owner = pipe_owner(pipe_handle)?;
        let mut session = 0;
        let session = unsafe {
            windows::Win32::System::Pipes::GetNamedPipeServerSessionId(pipe_handle, &mut session)
        }
        .ok()
        .map(|_| session);
        service_peer(proof.user.unwrap_or(&system), owner, pid, session, token)?
    } else if proof.elevated {
        elevated_session_peer(server_token(handle, pid), &current_user()?)?
    } else {
        let peer = token?;
        verify_user(proof, &peer.user, current_user()?, system)?;
        peer
    };
    // Keep the process object pinned through image and owner verification.
    let mut final_pid = 0;
    let mut exit_code = 0;
    unsafe {
        GetNamedPipeServerProcessId(pipe_handle, &mut final_pid).map_err(win_error)?;
        GetExitCodeProcess(handle, &mut exit_code).map_err(win_error)?;
    }
    if final_pid != pid || exit_code != windows::Win32::Foundation::STILL_ACTIVE.0 as u32 {
        return Err(denied("pipe server process changed"));
    }
    Ok(ServerIdentity { peer, exe })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_owner_proof_survives_token_access_denied() {
        let system = OsUserId::WindowsSid("S-1-5-18".into());
        let peer = service_peer(
            &system,
            "S-1-5-18".into(),
            123,
            Some(0),
            Err(io::ErrorKind::PermissionDenied.into()),
        )
        .unwrap();
        assert_eq!(peer.user, system);
        assert_eq!(peer.pid, 123);
        assert!(peer.groups.is_empty());
        assert!(!peer.elevated);
        assert!(service_peer(&system, "S-1-5-19".into(), 123, Some(0), Ok(peer)).is_err());
    }

    fn peer(user: &str, session: u32, elevated: bool) -> PeerIdentity {
        PeerIdentity {
            user: OsUserId::WindowsSid(user.into()),
            groups: vec![],
            pid: 7,
            session: Some(session),
            elevated,
        }
    }

    const ME: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";

    #[test]
    fn session_server_with_unreadable_token_is_refused() {
        let me = OsUserId::WindowsSid(ME.into());
        for error in [
            io::ErrorKind::PermissionDenied.into(),
            io::Error::other("TokenElevation failed"),
            io::Error::other("TokenIntegrityLevel failed"),
        ] {
            let refused = elevated_session_peer(Err(error), &me).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn session_server_must_be_the_current_user_and_elevated() {
        let me = OsUserId::WindowsSid(ME.into());
        let high = HIGH_INTEGRITY;
        let accepted = elevated_session_peer(Ok((peer(ME, 1, true), high)), &me).unwrap();
        assert_eq!(accepted.user, me);
        assert!(accepted.elevated);
        elevated_session_peer(Ok((peer(ME, 1, true), 0x4000)), &me).unwrap();
        for (wrong, integrity) in [
            (peer(ME, 1, false), high),
            // A Medium copy of an elevated token still reports elevated.
            (peer(ME, 1, true), MEDIUM_INTEGRITY),
            (peer(OTHER, 1, true), high),
            (peer("S-1-5-18", 0, true), 0x4000),
        ] {
            let refused = elevated_session_peer(Ok((wrong, integrity)), &me).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn session_admission_requires_owner_session_medium_and_no_app_container() {
        let owner = SessionOwner {
            user: OsUserId::WindowsSid(ME.into()),
            session: 1,
        };
        let admit = |client: &PeerIdentity, integrity, app_container| {
            admit_session_client(client.clone(), integrity, app_container, &owner)
        };
        let ok = peer(ME, 1, false);
        assert!(!admit(&ok, MEDIUM_INTEGRITY, false).unwrap().elevated);
        assert!(!admit(&ok, 0x2100, false).unwrap().elevated); // Medium Plus
        let elevated = peer(ME, 1, true);
        assert!(admit(&elevated, HIGH_INTEGRITY, false).unwrap().elevated);
        // An elevated token lowered to Medium is admitted, as not elevated.
        assert!(!admit(&elevated, MEDIUM_INTEGRITY, false).unwrap().elevated);
        let no_session = PeerIdentity {
            session: None,
            ..ok.clone()
        };
        let refused = [
            (&ok, 0x1000, false), // Low
            (&ok, 0, false),      // Untrusted
            (&ok, MEDIUM_INTEGRITY, true),
            (&elevated, HIGH_INTEGRITY, true),
            (&peer(OTHER, 1, false), MEDIUM_INTEGRITY, false),
            (&peer(ME, 2, false), MEDIUM_INTEGRITY, false),
            (&no_session, MEDIUM_INTEGRITY, false),
        ];
        for (client, integrity, app_container) in refused {
            let error = admit(client, integrity, app_container).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }
}
