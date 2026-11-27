//! WFP fences. Each logical rule is four filters, all in our protected
//! provider/sublayer. Transactions ensure no half-installed fence.
//!
//! The host form decides two things ([`FenceForm`]): who the permit filters
//! let through, and whether filters and container are persistent. The
//! system service's fence is persistent and permits SYSTEM; the elevated
//! session's is non-persistent (gone at the next BFE start, so at reboot)
//! and permits SYSTEM and enabled Administrators. An existing fence is read
//! back as one of exactly these two shapes, whichever host installed it.
use super::{FenceForm, WinError, observation};
use ::windows::{
    Win32::{
        Foundation::{
            FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
            HLOCAL, LocalFree,
        },
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl, IsValidSid,
            IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
    },
    core::{BOOL, GUID, HSTRING, PCWSTR, PWSTR},
};
use etd_sysfx::{Credential, FenceSpec, ObjectKey, Observation, Reclaimed};
use std::ptr::null_mut;
use uuid::Uuid;

const PROVIDER: GUID = GUID::from_u128(0x51e7d001_7bc3_43b9_a795_7b80c196382f);
const SUBLAYER: GUID = GUID::from_u128(0x51e7d002_7bc3_43b9_a795_7b80c196382f);
pub const CONTAINER: &str = "51e7d002-7bc3-43b9-a795-7b80c196382f";

/// The ALE_USER_ID condition of the permit filters. The condition is an
/// access check of the connecting token against this DACL.
///
/// Session: an allow ACE for BUILTIN\Administrators matches only a token in
/// which that group is ENABLED, that is an elevated token. In a filtered
/// (non-elevated) token the group is deny-only, and a deny-only group never
/// matches an allow ACE. So the permitted set is SYSTEM and elevated
/// administrator processes, which can already do anything the kernel port
/// allows. Never add the user's SID or any group a non-elevated token has
/// enabled (Users, Authenticated Users, INTERACTIVE, ...): a non-elevated
/// process of the same user would reach an unauthenticated kernel running
/// as administrator.
fn permit_sddl(form: FenceForm) -> &'static str {
    match form {
        FenceForm::Service => "D:P(A;;0x1;;;SY)",
        FenceForm::Session => "D:P(A;;0x1;;;SY)(A;;0x1;;;BA)",
    }
}
/// The descriptor of our provider, sublayer and filters. Only SYSTEM can
/// name SYSTEM as owner; an elevated session host names Administrators.
fn protected_sddl(form: FenceForm) -> &'static str {
    match form {
        FenceForm::Service => "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
        FenceForm::Session => "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",
    }
}
/// Whether a form's filters and container are persistent. Session objects
/// are added in a non-dynamic engine session, so they outlive the host
/// process (and with it a kernel that might still run) until BFE stops.
fn persistent(form: FenceForm) -> bool {
    form == FenceForm::Service
}
fn form_of(persistent: bool) -> FenceForm {
    if persistent {
        FenceForm::Service
    } else {
        FenceForm::Session
    }
}

fn check(code: u32, operation: &str) -> Result<(), WinError> {
    if code == 0 {
        Ok(())
    } else {
        Err(WinError::new(code as i64, operation))
    }
}

struct Engine(HANDLE);
impl Engine {
    fn open() -> Result<Self, WinError> {
        let mut handle = HANDLE::default();
        // Null session is deliberately NOT a dynamic session.
        unsafe {
            check(
                FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &mut handle),
                "open WFP",
            )?;
        }
        Ok(Self(handle))
    }
    fn transaction<T>(&self, f: impl FnOnce() -> Result<T, WinError>) -> Result<T, WinError> {
        unsafe {
            check(FwpmTransactionBegin0(self.0, 0), "begin WFP transaction")?;
        }
        let result = f().and_then(|value| {
            unsafe {
                check(FwpmTransactionCommit0(self.0), "commit WFP transaction")?;
            }
            Ok(value)
        });
        if result.is_err() {
            unsafe {
                FwpmTransactionAbort0(self.0);
            }
        }
        result
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

struct Sd(PSECURITY_DESCRIPTOR, u32);
impl Sd {
    fn new(sddl: &str) -> Result<Self, WinError> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut size = 0;
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut sd,
                Some(&mut size),
            )
            .map_err(WinError::windows)?;
        }
        Ok(Self(sd, size))
    }
}
impl Drop for Sd {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn key(spec: &FenceSpec) -> ObjectKey {
    let id = Uuid::new_v5(
        &Uuid::from_u128(SUBLAYER.to_u128()),
        format!(
            "{}:{}:{}",
            spec.instance.as_str(),
            spec.epoch.0,
            spec.address.port()
        )
        .as_bytes(),
    );
    ObjectKey::Fence {
        container: CONTAINER.into(),
        rule: id.to_string(),
        port: spec.address.port(),
    }
}

fn parts(key: &ObjectKey) -> Result<(Uuid, u16), WinError> {
    if let ObjectKey::Fence {
        container,
        rule,
        port,
    } = key
        && container == CONTAINER
        && *port != 0
    {
        return Ok((
            Uuid::parse_str(rule).map_err(|_| WinError::invalid("invalid fence id"))?,
            *port,
        ));
    }
    Err(WinError::invalid("invalid fence key"))
}

fn child(id: Uuid, i: u8) -> GUID {
    GUID::from_u128(Uuid::new_v5(&id, &[i]).as_u128())
}
fn label(id: Uuid, port: u16) -> String {
    format!("etd-fence:{id}:{port}")
}

unsafe fn display_name(ptr: PWSTR) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { ptr.to_string().unwrap_or_default() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Principal {
    System,
    Administrators,
}

// BFE owns and validates the security descriptors returned by its APIs.
/// The DACL's entries when every one is a well-formed ACCESS_ALLOWED ACE
/// for SYSTEM or BUILTIN\Administrators, in order; `None` for anything else.
unsafe fn allowed_aces(dacl: *const ACL) -> Result<Option<Vec<(Principal, u32)>>, WinError> {
    if dacl.is_null() {
        return Ok(None);
    }
    let start = dacl as usize;
    let size = unsafe { (*dacl).AclSize } as usize;
    if size < size_of::<ACL>() {
        return Ok(None);
    }
    let Some(end) = start.checked_add(size) else {
        return Ok(None);
    };
    let mut aces = Vec::new();
    for index in 0..unsafe { (*dacl).AceCount } as u32 {
        let mut ptr = null_mut();
        unsafe {
            GetAce(dacl, index, &mut ptr).map_err(WinError::windows)?;
        }
        let ace_start = ptr as usize;
        if ptr.is_null()
            || ace_start < start + size_of::<ACL>()
            || ace_start
                .checked_add(size_of::<ACE_HEADER>())
                .is_none_or(|p| p > end)
        {
            return Ok(None);
        }
        // Inspect only the generic header before interpreting the ACE body.
        let header = unsafe { ptr.cast::<ACE_HEADER>().read_unaligned() };
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let ace_size = header.AceSize as usize;
        if header.AceType != 0
            || ace_size < sid_offset + 8
            || ace_start.checked_add(ace_size).is_none_or(|p| p > end)
        {
            return Ok(None);
        }
        let sid_ptr = unsafe { ptr.cast::<u8>().add(sid_offset) };
        let count = unsafe { *sid_ptr.add(1) } as usize;
        if sid_offset + 8 + count * 4 > ace_size {
            return Ok(None);
        }
        let sid = PSID(sid_ptr.cast());
        if !unsafe { IsValidSid(sid).as_bool() } {
            return Ok(None);
        }
        let ace = unsafe { ptr.cast::<ACCESS_ALLOWED_ACE>().read_unaligned() };
        let principal = if unsafe { IsWellKnownSid(sid, WinLocalSystemSid).as_bool() } {
            Principal::System
        } else if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() } {
            Principal::Administrators
        } else {
            return Ok(None);
        };
        aces.push((principal, ace.Mask));
    }
    Ok(Some(aces))
}

/// Never treat a container as exclusive if its ACL admits an ordinary user:
/// only SYSTEM and Administrators entries, and both present.
pub(super) unsafe fn trusted_acl(dacl: *const ACL) -> Result<bool, WinError> {
    let Some(aces) = (unsafe { allowed_aces(dacl) })? else {
        return Ok(false);
    };
    Ok(aces.iter().any(|(p, _)| *p == Principal::System)
        && aces.iter().any(|(p, _)| *p == Principal::Administrators))
}

/// The form whose permit condition is exactly this ACE list.
fn permit_form(aces: &[(Principal, u32)]) -> Option<FenceForm> {
    match aces {
        [(Principal::System, 1)] => Some(FenceForm::Service),
        [(Principal::System, 1), (Principal::Administrators, 1)] => Some(FenceForm::Session),
        _ => None,
    }
}

fn check_acl(e: &Engine, key: GUID, kind: &str) -> Result<(), WinError> {
    let mut dacl = null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    unsafe {
        let getter = match kind {
            "provider" => FwpmProviderGetSecurityInfoByKey0,
            "sublayer" => FwpmSubLayerGetSecurityInfoByKey0,
            _ => FwpmFilterGetSecurityInfoByKey0,
        };
        check(
            getter(
                e.0,
                Some(&key),
                DACL_SECURITY_INFORMATION.0 | OWNER_SECURITY_INFORMATION.0,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            ),
            "read WFP security descriptor",
        )?;
        let trusted = trusted_acl(dacl);
        let trusted_owner = !owner.0.is_null()
            && (IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool());
        FwpmFreeMemory0(&mut sd.0);
        if !trusted? || !trusted_owner {
            return Err(WinError::invalid(format!("untrusted {kind} WFP ACL")));
        }
    }
    Ok(())
}

/// Whether `filter` is exactly filter `i` of a `form` fence on `port`.
unsafe fn exact_conditions(
    filter: &FWPM_FILTER0,
    i: u8,
    port: u16,
    form: FenceForm,
) -> Result<bool, WinError> {
    let v6 = i >= 2;
    let permit = i % 2 == 1;
    if filter.layerKey
        != if v6 {
            FWPM_LAYER_ALE_AUTH_CONNECT_V6
        } else {
            FWPM_LAYER_ALE_AUTH_CONNECT_V4
        }
        || filter.action.r#type
            != if permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            }
        || filter.flags.contains(FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) == permit
        || filter.flags.contains(FWPM_FILTER_FLAG_DISABLED)
        || filter.numFilterConditions != if permit { 4 } else { 3 }
        || filter.filterCondition.is_null()
    {
        return Ok(false);
    }
    if filter.weight.r#type != FWP_UINT8
        || unsafe { filter.weight.Anonymous.uint8 } != if permit { 15 } else { 14 }
    {
        return Ok(false);
    }
    let mut address = false;
    let mut protocol = false;
    let mut remote_port = false;
    let mut identity = false;
    for c in unsafe {
        std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
    } {
        if c.matchType != FWP_MATCH_EQUAL {
            return Ok(false);
        }
        let value = &c.conditionValue;
        unsafe {
            if c.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS && !address {
                if v6 {
                    let expected = std::net::Ipv6Addr::LOCALHOST.octets();
                    if value.r#type != FWP_BYTE_ARRAY16_TYPE
                        || value.Anonymous.byteArray16.is_null()
                        || (*value.Anonymous.byteArray16).byteArray16 != expected
                    {
                        return Ok(false);
                    }
                } else if value.r#type != FWP_UINT32 || value.Anonymous.uint32 != 0x7f000001 {
                    return Ok(false);
                }
                address = true;
            } else if c.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT && !remote_port {
                if value.r#type != FWP_UINT16 || value.Anonymous.uint16 != port {
                    return Ok(false);
                }
                remote_port = true;
            } else if c.fieldKey == FWPM_CONDITION_IP_PROTOCOL && !protocol {
                if value.r#type != FWP_UINT8 || value.Anonymous.uint8 != 6 {
                    return Ok(false);
                }
                protocol = true;
            } else if permit && c.fieldKey == FWPM_CONDITION_ALE_USER_ID && !identity {
                if value.r#type != FWP_SECURITY_DESCRIPTOR_TYPE || value.Anonymous.sd.is_null() {
                    return Ok(false);
                }
                let blob = &*value.Anonymous.sd;
                if blob.data.is_null() || blob.size < 20 {
                    return Ok(false);
                }
                let mut present = BOOL(0);
                let mut defaulted = BOOL(0);
                let mut dacl = null_mut();
                GetSecurityDescriptorDacl(
                    PSECURITY_DESCRIPTOR(blob.data.cast()),
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                )
                .map_err(WinError::windows)?;
                if !present.as_bool()
                    || permit_form(&allowed_aces(dacl)?.unwrap_or_default()) != Some(form)
                {
                    return Ok(false);
                }
                identity = true;
            } else {
                return Ok(false);
            }
        }
    }
    Ok(address && remote_port && protocol && identity == permit)
}

#[derive(Debug)]
struct Filter {
    key: GUID,
    label: String,
    persistent: bool,
    owned: bool,
}
impl Filter {
    /// The form a filter with this persistence belongs to; its conditions
    /// must then be that form's ([`exact_conditions`]).
    fn form(&self) -> FenceForm {
        form_of(self.persistent)
    }
}

fn filters(e: &Engine) -> Result<Vec<Filter>, WinError> {
    let mut handle = HANDLE::default();
    unsafe {
        check(
            FwpmFilterCreateEnumHandle0(e.0, None, &mut handle),
            "enumerate WFP filters",
        )?;
    }
    let result = (|| {
        let mut out = Vec::new();
        loop {
            let mut entries = null_mut();
            let mut count = 0;
            unsafe {
                check(
                    FwpmFilterEnum0(e.0, handle, 128, &mut entries, &mut count),
                    "read WFP filters",
                )?;
                for i in 0..count as usize {
                    let f = &**entries.add(i);
                    let owned = f.subLayerKey == SUBLAYER
                        && !f.providerKey.is_null()
                        && *f.providerKey == PROVIDER;
                    if f.subLayerKey == SUBLAYER
                        || (!f.providerKey.is_null() && *f.providerKey == PROVIDER)
                    {
                        out.push(Filter {
                            key: f.filterKey,
                            label: display_name(f.displayData.name),
                            persistent: f.flags.contains(FWPM_FILTER_FLAG_PERSISTENT),
                            owned,
                        });
                    }
                }
                FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_FILTER0).cast());
            }
            if count == 0 {
                break;
            }
        }
        Ok(out)
    })();
    unsafe {
        FwpmFilterDestroyEnumHandle0(e.0, handle);
    }
    result
}

fn matching(e: &Engine, id: Uuid, port: u16) -> Result<Vec<Filter>, WinError> {
    let mut out = Vec::new();
    for i in 0..4 {
        let mut f = null_mut();
        unsafe {
            let rc = FwpmFilterGetByKey0(e.0, &child(id, i), &mut f);
            if rc == FWP_E_FILTER_NOT_FOUND.0 as u32 {
                continue;
            }
            check(rc, "lookup WFP filter")?;
            let value = &*f;
            let found = Filter {
                key: value.filterKey,
                label: display_name(value.displayData.name),
                persistent: value.flags.contains(FWPM_FILTER_FLAG_PERSISTENT),
                owned: value.subLayerKey == SUBLAYER
                    && !value.providerKey.is_null()
                    && *value.providerKey == PROVIDER,
            };
            let valid_conditions = exact_conditions(value, i, port, found.form());
            FwpmFreeMemory0((&mut f as *mut *mut FWPM_FILTER0).cast());
            // All four filters of one fence have the same form.
            if !found.owned
                || found.label != label(id, port)
                || !valid_conditions?
                || out
                    .first()
                    .is_some_and(|first: &Filter| first.persistent != found.persistent)
            {
                return Err(WinError::invalid("WFP filter identity mismatch"));
            }
            check_acl(e, found.key, "filter")?;
            out.push(found);
        }
    }
    if !out.is_empty() {
        check_acl(e, PROVIDER, "provider")?;
        check_acl(e, SUBLAYER, "sublayer")?;
    }
    Ok(out)
}

/// Delete our provider and sublayer if they have the other form's
/// persistence and hold no filter at all: an empty container another form
/// left (it holds no fence, so nothing depends on it). One with filters is
/// left alone and fails the identity check that follows.
fn replace_empty_other_form(e: &Engine, form: FenceForm) -> Result<(), WinError> {
    unsafe {
        let mut p = null_mut();
        let rc = FwpmProviderGetByKey0(e.0, &PROVIDER, &mut p);
        if rc == FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            return Ok(());
        }
        check(rc, "lookup WFP provider")?;
        let other = ((*p).flags & FWPM_PROVIDER_FLAG_PERSISTENT != 0) != persistent(form)
            && display_name((*p).displayData.name) == "EasyTier Desktop fence provider";
        FwpmFreeMemory0((&mut p as *mut *mut FWPM_PROVIDER0).cast());
        if !other || !filters(e)?.is_empty() {
            return Ok(());
        }
        check_acl(e, PROVIDER, "provider")?;
        let mut s = null_mut();
        let rc = FwpmSubLayerGetByKey0(e.0, &SUBLAYER, &mut s);
        if rc != FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            check(rc, "lookup WFP sublayer")?;
            FwpmFreeMemory0((&mut s as *mut *mut FWPM_SUBLAYER0).cast());
            check_acl(e, SUBLAYER, "sublayer")?;
            check(
                FwpmSubLayerDeleteByKey0(e.0, &SUBLAYER),
                "delete the empty WFP sublayer of the other form",
            )?;
        }
        check(
            FwpmProviderDeleteByKey0(e.0, &PROVIDER),
            "delete the empty WFP provider of the other form",
        )?;
    }
    Ok(())
}

/// Add our provider and sublayer for `form` if absent; an existing one must
/// have our identity and the form's persistence (an empty one of the other
/// form is replaced).
fn ensure_container(e: &Engine, form: FenceForm, sd: &Sd) -> Result<(), WinError> {
    replace_empty_other_form(e, form)?;
    unsafe {
        let mut p = null_mut();
        let rc = FwpmProviderGetByKey0(e.0, &PROVIDER, &mut p);
        if rc == FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            let mut name = wide("EasyTier Desktop fence provider");
            let p = FWPM_PROVIDER0 {
                providerKey: PROVIDER,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    ..Default::default()
                },
                flags: if persistent(form) {
                    FWPM_PROVIDER_FLAG_PERSISTENT
                } else {
                    0
                },
                ..Default::default()
            };
            check(FwpmProviderAdd0(e.0, &p, Some(sd.0)), "add WFP provider")?;
        } else {
            check(rc, "lookup WFP provider")?;
            let valid = ((*p).flags & FWPM_PROVIDER_FLAG_PERSISTENT != 0) == persistent(form)
                && display_name((*p).displayData.name) == "EasyTier Desktop fence provider";
            FwpmFreeMemory0((&mut p as *mut *mut FWPM_PROVIDER0).cast());
            if !valid {
                return Err(WinError::invalid("WFP provider identity mismatch"));
            }
            check_acl(e, PROVIDER, "provider")?;
        }
        let mut s = null_mut();
        let rc = FwpmSubLayerGetByKey0(e.0, &SUBLAYER, &mut s);
        if rc == FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            let mut name = wide("EasyTier Desktop fence sublayer");
            let mut provider = PROVIDER;
            let s = FWPM_SUBLAYER0 {
                subLayerKey: SUBLAYER,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    ..Default::default()
                },
                flags: if persistent(form) {
                    FWPM_SUBLAYER_FLAG_PERSISTENT
                } else {
                    0
                },
                providerKey: &mut provider,
                weight: 0xffff,
                ..Default::default()
            };
            check(FwpmSubLayerAdd0(e.0, &s, Some(sd.0)), "add WFP sublayer")?;
        } else {
            check(rc, "lookup WFP sublayer")?;
            let valid = ((*s).flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0) == persistent(form)
                && !(*s).providerKey.is_null()
                && *(*s).providerKey == PROVIDER
                && display_name((*s).displayData.name) == "EasyTier Desktop fence sublayer";
            FwpmFreeMemory0((&mut s as *mut *mut FWPM_SUBLAYER0).cast());
            if !valid {
                return Err(WinError::invalid("WFP sublayer identity mismatch"));
            }
            check_acl(e, SUBLAYER, "sublayer")?;
        }
    }
    Ok(())
}

fn condition(
    field: GUID,
    ty: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: ty,
            Anonymous: value,
        },
    }
}

pub fn install(key: &ObjectKey, form: FenceForm) -> Result<Observation, WinError> {
    let (id, port) = parts(key)?;
    let e = Engine::open()?;
    let permit = Sd::new(permit_sddl(form))?;
    let protected = Sd::new(protected_sddl(form))?;
    e.transaction(|| {
        ensure_container(&e, form, &protected)?;
        let existing = matching(&e, id, port)?;
        if !existing.is_empty() {
            return Err(WinError::invalid("fence already exists"));
        }
        if filters(&e)?
            .iter()
            .any(|f| f.label.ends_with(&format!(":{port}")))
        {
            return Err(WinError::invalid("port already fenced"));
        }
        let mut blob = FWP_BYTE_BLOB {
            size: permit.1,
            data: permit.0.0.cast(),
        };
        let mut provider = PROVIDER;
        for v6 in [false, true] {
            for permit in [false, true] {
                let i = u8::from(v6) * 2 + u8::from(permit);
                let mut addr6 = FWP_BYTE_ARRAY16 {
                    byteArray16: [0; 16],
                };
                addr6.byteArray16[15] = 1;
                let mut conds = vec![
                    if v6 {
                        condition(
                            FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            FWP_BYTE_ARRAY16_TYPE,
                            FWP_CONDITION_VALUE0_0 {
                                byteArray16: &mut addr6,
                            },
                        )
                    } else {
                        condition(
                            FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            FWP_UINT32,
                            FWP_CONDITION_VALUE0_0 { uint32: 0x7f000001 },
                        )
                    },
                    condition(
                        FWPM_CONDITION_IP_REMOTE_PORT,
                        FWP_UINT16,
                        FWP_CONDITION_VALUE0_0 { uint16: port },
                    ),
                    condition(
                        FWPM_CONDITION_IP_PROTOCOL,
                        FWP_UINT8,
                        FWP_CONDITION_VALUE0_0 { uint8: 6 },
                    ),
                ];
                if permit {
                    conds.push(condition(
                        FWPM_CONDITION_ALE_USER_ID,
                        FWP_SECURITY_DESCRIPTOR_TYPE,
                        FWP_CONDITION_VALUE0_0 { sd: &mut blob },
                    ));
                }
                let mut name = wide(&label(id, port));
                let filter = FWPM_FILTER0 {
                    filterKey: child(id, i),
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: PWSTR(name.as_mut_ptr()),
                        ..Default::default()
                    },
                    flags: if persistent(form) {
                        FWPM_FILTER_FLAG_PERSISTENT
                    } else {
                        FWPM_FILTER_FLAGS(0)
                    } | if permit {
                        FWPM_FILTER_FLAGS(0)
                    } else {
                        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
                    },
                    providerKey: &mut provider,
                    subLayerKey: SUBLAYER,
                    layerKey: if v6 {
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6
                    } else {
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4
                    },
                    weight: FWP_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_VALUE0_0 {
                            uint8: if permit { 15 } else { 14 },
                        },
                    },
                    numFilterConditions: conds.len() as u32,
                    filterCondition: conds.as_mut_ptr(),
                    action: FWPM_ACTION0 {
                        r#type: if permit {
                            FWP_ACTION_PERMIT
                        } else {
                            FWP_ACTION_BLOCK
                        },
                        ..Default::default()
                    },
                    ..Default::default()
                };
                unsafe {
                    check(
                        FwpmFilterAdd0(e.0, &filter, Some(protected.0), None),
                        "add WFP filter",
                    )?;
                }
            }
        }
        Ok(())
    })?;
    observe(key)?.ok_or_else(|| WinError::invalid("fence not observed after installation"))
}

pub fn observe(key: &ObjectKey) -> Result<Option<Observation>, WinError> {
    observe_on(&Engine::open()?, key)
}
fn observe_on(e: &Engine, key: &ObjectKey) -> Result<Option<Observation>, WinError> {
    let (id, port) = parts(key)?;
    let matching = matching(e, id, port)?;
    if matching.is_empty() {
        return Ok(None);
    }
    let persistence = if matching[0].persistent {
        "persistent"
    } else {
        "non-persistent"
    };
    Ok(Some(observation(
        Some(Credential::ExclusiveContainer {
            container: CONTAINER.into(),
        }),
        key.clone(),
        format!("{} {persistence} WFP filters", matching.len()),
    )))
}

/// Whether all four filters of `key` are present with `form`, the form of
/// the generation being verified. A fence of the other form is ours and can
/// be reclaimed, but it is not this generation's fence.
pub fn complete(key: &ObjectKey, form: FenceForm) -> Result<bool, WinError> {
    let (id, port) = parts(key)?;
    Ok(complete_as(&matching(&Engine::open()?, id, port)?, form))
}
fn complete_as(filters: &[Filter], form: FenceForm) -> bool {
    filters.len() == 4 && filters.iter().all(|f| f.form() == form)
}

pub fn remove(key: &ObjectKey) -> Result<Reclaimed, WinError> {
    let (id, port) = parts(key)?;
    let e = Engine::open()?;
    e.transaction(|| {
        let found = matching(&e, id, port)?;
        if found.is_empty() {
            return Ok(Reclaimed::AlreadyAbsent);
        }
        // Confirm parent identities as well as each filter's membership,
        // for the form the found filters have, whoever removes them.
        let form = found[0].form();
        let protected = Sd::new(protected_sddl(form))?;
        ensure_container(&e, form, &protected)?;
        // Only delete the shared container when this is its entire filter
        // population; enumerate before removing because BFE can snapshot an
        // enumeration at transaction start.
        let all = filters(&e)?;
        let last = all
            .iter()
            .all(|f| found.iter().any(|ours| ours.key == f.key));
        for filter in found {
            unsafe {
                check(
                    FwpmFilterDeleteByKey0(e.0, &filter.key),
                    "delete WFP filter",
                )?;
            }
        }
        // Shared container stays while other logical fences exist.
        if last {
            unsafe {
                check(
                    FwpmSubLayerDeleteByKey0(e.0, &SUBLAYER),
                    "delete WFP sublayer",
                )?;
                check(
                    FwpmProviderDeleteByKey0(e.0, &PROVIDER),
                    "delete WFP provider",
                )?;
            }
        }
        Ok(Reclaimed::Removed)
    })
}

pub fn enumerate() -> Result<Vec<(ObjectKey, Observation)>, WinError> {
    enumerate_impl(false)
}
pub fn sweep() -> Result<Vec<(ObjectKey, Observation)>, WinError> {
    enumerate_impl(true)
}
fn filter_key(f: &Filter) -> Result<ObjectKey, WinError> {
    let rest = f
        .label
        .strip_prefix("etd-fence:")
        .ok_or_else(|| WinError::invalid("unrecognized object in WFP product container"))?;
    let (id, port) = rest
        .split_once(':')
        .ok_or_else(|| WinError::invalid("unrecognized WFP fence label"))?;
    let (Ok(id), Ok(port)) = (Uuid::parse_str(id), port.parse::<u16>()) else {
        return Err(WinError::invalid("unrecognized WFP fence identifier"));
    };
    if !f.owned || !(0..4).any(|i| child(id, i) == f.key) {
        return Err(WinError::invalid("unrecognized WFP filter identity"));
    }
    Ok(ObjectKey::Fence {
        container: CONTAINER.into(),
        rule: id.to_string(),
        port,
    })
}
fn enumerate_impl(tolerant: bool) -> Result<Vec<(ObjectKey, Observation)>, WinError> {
    let e = Engine::open()?;
    let mut out = Vec::new();
    for f in filters(&e)? {
        let key = match filter_key(&f) {
            Ok(key) => key,
            Err(e) if tolerant => {
                tracing::warn!(class="wfp",filter=?f.key,label=%f.label,error=%e,"skipping unrecognized WFP object");
                continue;
            }
            Err(e) => return Err(e),
        };
        if out.iter().any(|(k, _)| k == &key) {
            continue;
        }
        match observe_on(&e, &key) {
            Ok(Some(obs)) => out.push((key, obs)),
            Ok(None) => {}
            Err(e) if tolerant => {
                tracing::warn!(class="wfp",key=?key,error=%e,"skipping unconfirmed WFP fence")
            }
            Err(e) => return Err(e),
        }
    }
    if out.is_empty() {
        // Both parent objects are added/deleted transactionally with the
        // filters. An empty but existing parent is unexpected residue, not
        // evidence of a clean system; don't silently hide it from sysdiff.
        let parent_result = (|| unsafe {
            let mut provider = null_mut();
            let rc = FwpmProviderGetByKey0(e.0, &PROVIDER, &mut provider);
            if rc == 0 {
                FwpmFreeMemory0((&mut provider as *mut *mut FWPM_PROVIDER0).cast());
                return Err(WinError::invalid("orphan WFP provider"));
            }
            if rc != FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
                check(rc, "look up WFP provider")?;
            }
            let mut sublayer = null_mut();
            let rc = FwpmSubLayerGetByKey0(e.0, &SUBLAYER, &mut sublayer);
            if rc == 0 {
                FwpmFreeMemory0((&mut sublayer as *mut *mut FWPM_SUBLAYER0).cast());
                return Err(WinError::invalid("orphan WFP sublayer"));
            }
            if rc != FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
                check(rc, "look up WFP sublayer")?;
            }
            Ok(())
        })();
        if let Err(e) = parent_result {
            if tolerant {
                tracing::warn!(class="wfp",error=%e,"unconfirmed WFP parent residue");
            } else {
                return Err(e);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aces(sddl: &str) -> Option<Vec<(Principal, u32)>> {
        let sd = Sd::new(sddl).unwrap();
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl = null_mut();
        unsafe {
            GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted).unwrap();
            assert!(present.as_bool(), "{sddl}");
            allowed_aces(dacl).unwrap()
        }
    }

    #[test]
    fn each_form_reads_back_only_its_own_permit() {
        for form in [FenceForm::Service, FenceForm::Session] {
            assert_eq!(permit_form(&aces(permit_sddl(form)).unwrap()), Some(form));
        }
        for sddl in [
            // Groups a non-elevated token has enabled, and a user SID.
            "D:P(A;;0x1;;;SY)(A;;0x1;;;BU)",
            "D:P(A;;0x1;;;SY)(A;;0x1;;;AU)",
            "D:P(A;;0x1;;;SY)(A;;0x1;;;IU)",
            "D:P(A;;0x1;;;SY)(A;;0x1;;;WD)",
            "D:P(A;;0x1;;;SY)(A;;0x1;;;S-1-5-21-1-2-3-1001)",
            "D:P(A;;0x1;;;SY)(A;;0x1;;;BA)(A;;0x1;;;S-1-5-21-1-2-3-1001)",
            // Not exactly one of the two shapes.
            "D:P(A;;0x1;;;BA)(A;;0x1;;;SY)",
            "D:P(A;;0x1;;;BA)",
            "D:P(A;;0x3;;;SY)",
            "D:P(A;;0x1;;;SY)(A;;0x3;;;BA)",
            "D:P(A;;0x1;;;SY)(A;;0x1;;;BA)(A;;0x1;;;BA)",
            "D:P(D;;0x1;;;BU)(A;;0x1;;;SY)",
            "D:P",
        ] {
            assert_eq!(aces(sddl).and_then(|a| permit_form(&a)), None, "{sddl}");
        }
    }

    #[test]
    fn a_container_acl_admits_only_system_and_administrators() {
        let trusted = |sddl: &str| {
            let sd = Sd::new(sddl).unwrap();
            let mut present = BOOL(0);
            let mut defaulted = BOOL(0);
            let mut dacl = null_mut();
            unsafe {
                GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted).unwrap();
                trusted_acl(dacl).unwrap()
            }
        };
        for form in [FenceForm::Service, FenceForm::Session] {
            assert!(trusted(protected_sddl(form)), "{form:?}");
        }
        assert!(!trusted("D:P(A;;GA;;;SY)"));
        assert!(!trusted("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)"));
        assert!(!trusted(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)"
        ));
    }

    #[test]
    fn only_four_filters_of_the_expected_form_are_complete() {
        let filters = |persistent: bool, n: usize| -> Vec<Filter> {
            (0..n)
                .map(|_| Filter {
                    key: GUID::zeroed(),
                    label: String::new(),
                    persistent,
                    owned: true,
                })
                .collect()
        };
        assert!(complete_as(&filters(true, 4), FenceForm::Service));
        assert!(complete_as(&filters(false, 4), FenceForm::Session));
        // A fence of the other form is not this generation's fence.
        assert!(!complete_as(&filters(true, 4), FenceForm::Session));
        assert!(!complete_as(&filters(false, 4), FenceForm::Service));
        assert!(!complete_as(&filters(false, 3), FenceForm::Session));
    }

    #[test]
    fn persistence_decides_the_form_a_filter_is_read_as() {
        for form in [FenceForm::Service, FenceForm::Session] {
            assert_eq!(form_of(persistent(form)), form);
        }
        assert!(persistent(FenceForm::Service));
        assert!(!persistent(FenceForm::Session));
    }
}
