//! Persistent WFP fences. Each logical rule is four filters, all in our
//! protected provider/sublayer. Transactions ensure no half-installed fence.
use super::{WinError, observation};
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

// BFE owns and validates the security descriptors returned by its APIs.
// Never treat a container as exclusive if its ACL admits an ordinary user.
pub(super) unsafe fn trusted_acl(dacl: *const ACL, system_only: bool) -> Result<bool, WinError> {
    if dacl.is_null() {
        return Ok(false);
    }
    let mut system = false;
    let mut admin = false;
    let start = dacl as usize;
    let size = unsafe { (*dacl).AclSize } as usize;
    if size < size_of::<ACL>() {
        return Ok(false);
    }
    let Some(end) = start.checked_add(size) else {
        return Ok(false);
    };
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
            return Ok(false);
        }
        // Inspect only the generic header before interpreting the ACE body.
        let header = unsafe { ptr.cast::<ACE_HEADER>().read_unaligned() };
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let ace_size = header.AceSize as usize;
        if header.AceType != 0
            || ace_size < sid_offset + 8
            || ace_start.checked_add(ace_size).is_none_or(|p| p > end)
        {
            return Ok(false);
        }
        let sid_ptr = unsafe { ptr.cast::<u8>().add(sid_offset) };
        let count = unsafe { *sid_ptr.add(1) } as usize;
        if sid_offset + 8 + count * 4 > ace_size {
            return Ok(false);
        }
        let sid = PSID(sid_ptr.cast());
        if !unsafe { IsValidSid(sid).as_bool() } {
            return Ok(false);
        }
        let ace = unsafe { ptr.cast::<ACCESS_ALLOWED_ACE>().read_unaligned() };
        if unsafe { IsWellKnownSid(sid, WinLocalSystemSid).as_bool() } {
            if system_only && ace.Mask != 1 {
                return Ok(false);
            }
            system = true;
        } else if !system_only
            && unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() }
        {
            admin = true;
        } else {
            return Ok(false);
        }
    }
    Ok(system && (system_only || admin))
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
        let trusted = trusted_acl(dacl, false);
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

unsafe fn exact_conditions(filter: &FWPM_FILTER0, i: u8, port: u16) -> Result<bool, WinError> {
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
                if !present.as_bool() || !trusted_acl(dacl, true)? {
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
            let valid_conditions = exact_conditions(value, i, port);
            FwpmFreeMemory0((&mut f as *mut *mut FWPM_FILTER0).cast());
            if !found.owned
                || !found.persistent
                || found.label != label(id, port)
                || !valid_conditions?
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

fn ensure_container(e: &Engine, sd: &Sd) -> Result<(), WinError> {
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
                flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                ..Default::default()
            };
            check(FwpmProviderAdd0(e.0, &p, Some(sd.0)), "add WFP provider")?;
        } else {
            check(rc, "lookup WFP provider")?;
            let valid = (*p).flags & FWPM_PROVIDER_FLAG_PERSISTENT != 0
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
                flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey: &mut provider,
                weight: 0xffff,
                ..Default::default()
            };
            check(FwpmSubLayerAdd0(e.0, &s, Some(sd.0)), "add WFP sublayer")?;
        } else {
            check(rc, "lookup WFP sublayer")?;
            let valid = (*s).flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0
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

pub fn install(key: &ObjectKey) -> Result<Observation, WinError> {
    let (id, port) = parts(key)?;
    let e = Engine::open()?;
    let match_system = Sd::new("D:P(A;;0x1;;;SY)")?;
    let protected = Sd::new("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
    e.transaction(|| {
        ensure_container(&e, &protected)?;
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
            size: match_system.1,
            data: match_system.0.0.cast(),
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
                    flags: FWPM_FILTER_FLAG_PERSISTENT
                        | if permit {
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
                        "add persistent WFP filter",
                    )?;
                }
            }
        }
        Ok(())
    })?;
    observe(key)?.ok_or_else(|| WinError::invalid("fence not observed after installation"))
}

pub fn observe(key: &ObjectKey) -> Result<Option<Observation>, WinError> {
    let (id, port) = parts(key)?;
    let e = Engine::open()?;
    let matching = matching(&e, id, port)?;
    if matching.is_empty() {
        return Ok(None);
    }
    Ok(Some(observation(
        Some(Credential::ExclusiveContainer {
            container: CONTAINER.into(),
        }),
        key.clone(),
        format!("{} persistent WFP filters", matching.len()),
    )))
}

pub fn complete(key: &ObjectKey) -> Result<bool, WinError> {
    let (id, port) = parts(key)?;
    Ok(matching(&Engine::open()?, id, port)?.len() == 4)
}

pub fn remove(key: &ObjectKey) -> Result<Reclaimed, WinError> {
    let (id, port) = parts(key)?;
    let e = Engine::open()?;
    e.transaction(|| {
        let found = matching(&e, id, port)?;
        if found.is_empty() {
            return Ok(Reclaimed::AlreadyAbsent);
        }
        // Confirm parent identities as well as each filter's membership.
        let protected = Sd::new("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
        ensure_container(&e, &protected)?;
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
    if !f.owned || !f.persistent || !(0..4).any(|i| child(id, i) == f.key) {
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
        match observe(&key) {
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
