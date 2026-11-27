//! The host process's own token: which host form it is (decides the fence
//! and the worker environment), and the restricted copy the session fence
//! probe runs with. Nothing here is configured: it is read from the token.
use super::{WinError, registry::Handle};
use ::windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
            GetSecurityDescriptorDacl, GetTokenInformation, IsWellKnownSid, PSECURITY_DESCRIPTOR,
            PSID, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, SetTokenInformation,
            TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE,
            TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
            TokenDefaultDacl, TokenElevation, TokenIntegrityLevel, TokenOwner, TokenUser,
            WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalSystemSid, WinMediumLabelSid,
        },
        System::{
            SystemServices::SE_GROUP_INTEGRITY,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
    core::{HSTRING, PWSTR},
};

/// Which host the current process is, from its own token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostToken {
    /// LocalSystem: the system service.
    System,
    /// Any other elevated token: the elevated session host (or an
    /// administrator's command running the adapters).
    Elevated,
    /// A standard token: the user host, which holds no privileged objects.
    Standard,
}

fn own_token(access: ::windows::Win32::Security::TOKEN_ACCESS_MASK) -> Result<Handle, WinError> {
    let mut raw = HANDLE::default();
    // SAFETY: the pseudo handle of the current process is always valid and
    // `raw` receives a token handle that `Handle` closes.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut raw) }
        .map_err(WinError::windows)?;
    Ok(Handle(raw))
}

/// The token user, kept in the buffer `GetTokenInformation` filled.
struct TokenUserBuffer(Vec<u64>);
impl TokenUserBuffer {
    fn read(token: &Handle) -> Result<Self, WinError> {
        let mut size = 0;
        // SAFETY: a size query with no buffer; the expected error is
        // ERROR_INSUFFICIENT_BUFFER, and `size` receives the needed length.
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut size) };
        if size == 0 {
            return Err(WinError::invalid("TokenUser size query failed"));
        }
        // u64 elements keep TOKEN_USER and the SID after it aligned.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer is at least `size` bytes and writable.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                size,
                &mut size,
            )
        }
        .map_err(WinError::windows)?;
        Ok(Self(buffer))
    }
    fn sid(&self) -> PSID {
        // SAFETY: the buffer was filled with a TOKEN_USER by `read`; its SID
        // points into the same buffer, which lives as long as `self`.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn sid_string(sid: PSID) -> Result<String, WinError> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` is a valid SID; the string is freed with LocalFree.
    unsafe {
        ConvertSidToStringSidW(sid, &mut text).map_err(WinError::windows)?;
        let value = text.to_string();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        value.map_err(|_| WinError::invalid("SID string is not UTF-16"))
    }
}

fn token_elevated(token: &Handle) -> Result<bool, WinError> {
    let mut value = TOKEN_ELEVATION::default();
    let mut size = 0;
    // SAFETY: the output buffer is a TOKEN_ELEVATION of the stated size.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&raw mut value).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    }
    .map_err(WinError::windows)?;
    Ok(value.TokenIsElevated != 0)
}

/// The host form of the current process. SYSTEM is decided by the token
/// user, never by a path or setting; any other elevated token is the
/// session form.
pub(super) fn host_token() -> Result<HostToken, WinError> {
    let token = own_token(TOKEN_QUERY)?;
    let user = TokenUserBuffer::read(&token)?;
    // SAFETY: `user.sid()` is a valid SID inside `user`.
    if unsafe { IsWellKnownSid(user.sid(), WinLocalSystemSid) }.as_bool() {
        return Ok(HostToken::System);
    }
    Ok(if token_elevated(&token)? {
        HostToken::Elevated
    } else {
        HostToken::Standard
    })
}

/// The current process's user SID in string form.
pub(super) fn host_user() -> Result<String, WinError> {
    sid_string(TokenUserBuffer::read(&own_token(TOKEN_QUERY)?)?.sid())
}

/// A well-known SID in a buffer of the maximum SID size.
struct WellKnown([u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)]);
impl WellKnown {
    fn new(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, WinError> {
        let mut sid = Self([0; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)]);
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: the buffer holds SECURITY_MAX_SID_SIZE bytes.
        unsafe { CreateWellKnownSid(kind, None, Some(PSID(sid.0.as_mut_ptr().cast())), &mut size) }
            .map_err(WinError::windows)?;
        Ok(sid)
    }
    fn psid(&self) -> PSID {
        PSID(self.0.as_ptr().cast_mut().cast())
    }
}

/// The negative probe identity of the session form: a restricted copy of
/// the host's own primary token with BUILTIN\Administrators deny-only, no
/// privileges beyond the minimum, and Medium integrity. On the access check
/// the session fence's permit makes (SYSTEM or enabled Administrators) this
/// is equivalent to the same user's real non-elevated token. A restricted
/// copy of the caller's own token can be started with CreateProcessAsUserW
/// without SeAssignPrimaryTokenPrivilege. TokenLinkedToken is not used: it
/// is identification-level without SeTcbPrivilege.
///
/// Like a non-elevated token, the copy owns what it creates as the user and
/// its default DACL grants the user and SYSTEM. The elevated token's owner
/// and default DACL name Administrators, which are deny-only here, so the
/// child could not open the objects it creates while it starts.
pub(super) fn restricted_copy() -> Result<Handle, WinError> {
    let own =
        own_token(TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT)?;
    let user = TokenUserBuffer::read(&own)?;
    let admins = WellKnown::new(WinBuiltinAdministratorsSid)?;
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admins.psid(),
        Attributes: 0,
    }];
    let mut raw = HANDLE::default();
    // SAFETY: `own` is a primary token opened with TOKEN_DUPLICATE; the SID
    // array outlives the call; `raw` receives a token `Handle` closes.
    unsafe {
        CreateRestrictedToken(
            own.0,
            DISABLE_MAX_PRIVILEGE,
            Some(&disable),
            None,
            None,
            &mut raw,
        )
    }
    .map_err(WinError::windows)?;
    let copy = Handle(raw);
    let medium = WellKnown::new(WinMediumLabelSid)?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: medium.psid(),
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    // SAFETY: each structure matches its information class and outlives the
    // call; the token handle carries TOKEN_ADJUST_DEFAULT from `own`.
    unsafe {
        SetTokenInformation(
            copy.0,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        )
        .map_err(WinError::windows)?;
        let owner = TOKEN_OWNER { Owner: user.sid() };
        SetTokenInformation(
            copy.0,
            TokenOwner,
            (&raw const owner).cast(),
            size_of::<TOKEN_OWNER>() as u32,
        )
        .map_err(WinError::windows)?;
    }
    let sddl = format!("D:(A;;GA;;;{})(A;;GA;;;SY)", sid_string(user.sid())?);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the descriptor is allocated by the conversion and freed below;
    // the DACL pointer points into it and is used only before the free.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(WinError::windows)?;
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut dacl = std::ptr::null_mut();
        let result = GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            .and_then(|()| {
                let default = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
                SetTokenInformation(
                    copy.0,
                    TokenDefaultDacl,
                    (&raw const default).cast(),
                    size_of::<TOKEN_DEFAULT_DACL>() as u32,
                )
            });
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        result.map_err(WinError::windows)?;
    }
    Ok(copy)
}
