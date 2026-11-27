//! The host process's own token: which host form it is (decides the fence
//! and the worker environment), the restricted copy the session fence probe
//! impersonates, and the identity the probing thread checks it really has.
//! Nothing here is configured: it is read from the token.
use super::{WinError, registry::Handle};
use ::windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx,
            GetSecurityDescriptorDacl, GetSidSubAuthority, GetSidSubAuthorityCount,
            GetTokenInformation, IsWellKnownSid, PSECURITY_DESCRIPTOR, PSID,
            SECURITY_IMPERSONATION_LEVEL, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
            SecurityImpersonation, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
            TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_IMPERSONATE,
            TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
            TokenDefaultDacl, TokenElevation, TokenGroups, TokenImpersonation,
            TokenImpersonationLevel, TokenIntegrityLevel, TokenOwner, TokenUser,
            WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalSystemSid, WinMediumLabelSid,
        },
        System::{
            SystemServices::{SE_GROUP_ENABLED, SE_GROUP_INTEGRITY, SE_GROUP_USE_FOR_DENY_ONLY},
            Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
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

/// A variable-size token information class, in u64 elements so that the
/// structure and the SIDs after it stay aligned.
fn token_info(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, WinError> {
    let mut size = 0;
    // SAFETY: a size query with no buffer; the expected error is
    // ERROR_INSUFFICIENT_BUFFER, and `size` receives the needed length.
    let _ = unsafe { GetTokenInformation(token.0, class, None, 0, &mut size) };
    if size == 0 {
        return Err(WinError::invalid("token information size query failed"));
    }
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: the buffer is at least `size` bytes and writable.
    unsafe {
        GetTokenInformation(
            token.0,
            class,
            Some(buffer.as_mut_ptr().cast()),
            size,
            &mut size,
        )
    }
    .map_err(WinError::windows)?;
    Ok(buffer)
}

/// The token user, kept in the buffer `GetTokenInformation` filled.
struct TokenUserBuffer(Vec<u64>);
impl TokenUserBuffer {
    fn read(token: &Handle) -> Result<Self, WinError> {
        Ok(Self(token_info(token, TokenUser)?))
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

/// An impersonation token of [`restricted_copy`], for the session probe
/// thread. Same user as the host and a lower integrity level, so the host
/// impersonates it fully without SeImpersonatePrivilege.
pub(super) fn restricted_impersonation() -> Result<Handle, WinError> {
    let primary = restricted_copy()?;
    let mut raw = HANDLE::default();
    // SAFETY: `primary` carries TOKEN_DUPLICATE; `raw` receives a token
    // handle that `Handle` closes.
    unsafe {
        DuplicateTokenEx(
            primary.0,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut raw,
        )
    }
    .map_err(WinError::windows)?;
    Ok(Handle(raw))
}

/// What the probing thread sees in its effective token: whether it is the
/// identity a non-elevated process of the host's user has at the fence.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ProbeIdentity {
    pub user: String,
    /// BUILTIN\Administrators is present, deny-only and not enabled.
    pub admins_deny_only: bool,
    /// The mandatory integrity level RID.
    pub integrity: u32,
    /// The thread impersonates at SecurityImpersonation (not merely
    /// identification, which the network stack would not act as).
    pub impersonating: bool,
}
impl ProbeIdentity {
    /// SECURITY_MANDATORY_MEDIUM_RID.
    pub const MEDIUM: u32 = 0x2000;
    pub fn is_non_elevated(&self, user: &str) -> bool {
        self.impersonating
            && self.user == user
            && self.admins_deny_only
            && self.integrity == Self::MEDIUM
    }
}

/// The current thread's impersonation token, as the probe sees it.
pub(super) fn thread_identity() -> Result<ProbeIdentity, WinError> {
    let mut raw = HANDLE::default();
    // SAFETY: the pseudo handle of the current thread is valid; opened as
    // self so the query does not depend on the impersonated identity.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut raw) }
        .map_err(WinError::windows)?;
    let token = Handle(raw);
    let user = sid_string(TokenUserBuffer::read(&token)?.sid())?;
    let groups = token_info(&token, TokenGroups)?;
    // SAFETY: the buffer holds a TOKEN_GROUPS with GroupCount entries; the
    // SIDs point into the same buffer.
    let admins_deny_only = unsafe {
        let groups = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
        std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
            .iter()
            .filter(|g| IsWellKnownSid(g.Sid, WinBuiltinAdministratorsSid).as_bool())
            .any(|g| {
                g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0
                    && g.Attributes & SE_GROUP_ENABLED as u32 == 0
            })
    };
    let label = token_info(&token, TokenIntegrityLevel)?;
    // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL whose SID points into
    // it; the last sub-authority is the integrity RID.
    let integrity = unsafe {
        let sid = (*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return Err(WinError::invalid("integrity label without a RID"));
        }
        *GetSidSubAuthority(sid, u32::from(count) - 1)
    };
    let mut level = SECURITY_IMPERSONATION_LEVEL::default();
    let mut size = 0;
    // SAFETY: the output is a SECURITY_IMPERSONATION_LEVEL of the stated size.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenImpersonationLevel,
            Some((&raw mut level).cast()),
            size_of::<SECURITY_IMPERSONATION_LEVEL>() as u32,
            &mut size,
        )
    }
    .map_err(WinError::windows)?;
    Ok(ProbeIdentity {
        user,
        admins_deny_only,
        integrity,
        impersonating: level == SecurityImpersonation,
    })
}
