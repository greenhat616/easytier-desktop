#![cfg(windows)]
use std::{
    env, fs,
    ptr::{null, null_mut},
    thread,
    time::Duration,
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{LocalFree, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
    },
};

const PROVIDER: GUID = GUID::from_u128(0x51e7d001_7bc3_43b9_a795_7b80c196382f);
const SUBLAYER: GUID = GUID::from_u128(0x51e7d002_7bc3_43b9_a795_7b80c196382f);
fn key(i: usize) -> GUID {
    GUID::from_u128(0x51e7d010_7bc3_43b9_a795_7b80c196382f + i as u128)
}
fn equal(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn check(code: u32, what: &str) {
    assert_eq!(code, 0, "{what}: 0x{code:08x}");
}
struct Engine(HANDLE);
impl Engine {
    fn open() -> Self {
        let mut handle = null_mut();
        // RPC_C_AUTHN_WINNT; null session is NOT a dynamic session.
        unsafe {
            check(
                FwpmEngineOpen0(null(), 10, null(), null(), &mut handle),
                "open BFE",
            );
        }
        Self(handle)
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

fn condition(
    field_key: GUID,
    r#type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type,
            Anonymous: value,
        },
    }
}

// The permit is soft and scoped to this sublayer; it does not override external
// policy. The default block within our sublayer catches all other identities.
unsafe fn install(e: HANDLE, port: u16) {
    let mut pname = wide("ETD S1 fence provider");
    let mut sname = wide("ETD S1 fence sublayer");
    let mut provider = PROVIDER;
    let mut p = FWPM_PROVIDER0::default();
    p.providerKey = PROVIDER;
    p.displayData.name = pname.as_mut_ptr();
    p.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    let mut sub = FWPM_SUBLAYER0::default();
    sub.subLayerKey = SUBLAYER;
    sub.displayData.name = sname.as_mut_ptr();
    sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sub.providerKey = &mut provider;
    sub.weight = 0xffff;

    // ALE_USER_ID is an access check for FWP_ACTRL_MATCH_FILTER (bit 1).
    let mut sd = null_mut();
    let mut size = 0;
    let sddl = wide("D:P(A;;0x1;;;SY)");
    assert_ne!(
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, &mut size),
        0
    );
    let mut blob = FWP_BYTE_BLOB {
        size,
        data: sd.cast(),
    };
    check(FwpmTransactionBegin0(e, 0), "begin");
    check(FwpmProviderAdd0(e, &p, null_mut()), "provider add");
    check(FwpmSubLayerAdd0(e, &sub, null_mut()), "sublayer add");
    for v6 in [false, true] {
        for permit in [false, true] {
            let idx = (v6 as usize) * 2 + permit as usize;
            let mut loopback6 = [0u8; 16];
            loopback6[15] = 1;
            let mut addr6 = FWP_BYTE_ARRAY16 {
                byteArray16: loopback6,
            };
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
            let mut fname = wide(if permit {
                "ETD S1 system permit"
            } else {
                "ETD S1 deny others"
            });
            let mut filter = FWPM_FILTER0::default();
            filter.filterKey = key(idx);
            filter.displayData.name = fname.as_mut_ptr();
            filter.flags = FWPM_FILTER_FLAG_PERSISTENT
                | if permit {
                    0
                } else {
                    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
                };
            filter.providerKey = &mut provider;
            filter.layerKey = if v6 {
                FWPM_LAYER_ALE_AUTH_CONNECT_V6
            } else {
                FWPM_LAYER_ALE_AUTH_CONNECT_V4
            };
            filter.subLayerKey = SUBLAYER;
            filter.weight = FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: if permit { 15 } else { 14 },
                },
            };
            filter.numFilterConditions = conds.len() as u32;
            filter.filterCondition = conds.as_mut_ptr();
            filter.action.r#type = if permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            };
            let mut id = 0;
            check(
                FwpmFilterAdd0(e, &filter, null_mut(), &mut id),
                "filter add",
            );
            println!("ADD filter={idx} v6={v6} permit={permit} id={id}");
        }
    }
    check(FwpmTransactionCommit0(e), "commit");
    LocalFree(sd);
}

unsafe fn remove(e: HANDLE) {
    // This exact four-key container was created by the test's transaction.
    check(FwpmTransactionBegin0(e, 0), "begin remove");
    for i in 0..4 {
        check(FwpmFilterDeleteByKey0(e, &key(i)), "filter delete");
    }
    check(FwpmSubLayerDeleteByKey0(e, &SUBLAYER), "sublayer delete");
    check(FwpmProviderDeleteByKey0(e, &PROVIDER), "provider delete");
    check(FwpmTransactionCommit0(e), "commit remove");
}

// Fresh unfiltered enumeration handles, independent from installation/deletion.
unsafe fn verify(e: HANDLE, present: bool) {
    let expected = if present { 4 } else { 0 };
    let mut filters = 0;
    let mut sublayers = 0;
    let mut providers = 0;
    macro_rules! enumerate {
        ($create:ident, $enum:ident, $destroy:ident, $t:ty, $item:ident, $body:block) => {{
            let mut cursor = null_mut();
            check($create(e, null(), &mut cursor), stringify!($create));
            loop {
                let mut entries: *mut *mut $t = null_mut();
                let mut count = 0;
                check(
                    $enum(e, cursor, 128, &mut entries, &mut count),
                    stringify!($enum),
                );
                if count == 0 {
                    break;
                }
                for i in 0..count as usize {
                    let $item = &**entries.add(i);
                    $body
                }
                FwpmFreeMemory0((&mut entries as *mut *mut *mut $t).cast());
            }
            check($destroy(e, cursor), stringify!($destroy));
        }};
    }
    enumerate!(
        FwpmFilterCreateEnumHandle0,
        FwpmFilterEnum0,
        FwpmFilterDestroyEnumHandle0,
        FWPM_FILTER0,
        f,
        {
            if equal(&f.subLayerKey, &SUBLAYER) || (0..4).any(|i| equal(&f.filterKey, &key(i))) {
                filters += 1;
                println!("ENUM filter id={} flags=0x{:x}", f.filterId, f.flags);
                assert_ne!(f.flags & FWPM_FILTER_FLAG_PERSISTENT, 0);
            }
        }
    );
    enumerate!(
        FwpmSubLayerCreateEnumHandle0,
        FwpmSubLayerEnum0,
        FwpmSubLayerDestroyEnumHandle0,
        FWPM_SUBLAYER0,
        s,
        {
            if equal(&s.subLayerKey, &SUBLAYER) {
                sublayers += 1;
                assert_ne!(s.flags & FWPM_SUBLAYER_FLAG_PERSISTENT, 0);
            }
        }
    );
    enumerate!(
        FwpmProviderCreateEnumHandle0,
        FwpmProviderEnum0,
        FwpmProviderDestroyEnumHandle0,
        FWPM_PROVIDER0,
        p,
        {
            if equal(&p.providerKey, &PROVIDER) {
                providers += 1;
                assert_ne!(p.flags & FWPM_PROVIDER_FLAG_PERSISTENT, 0);
            }
        }
    );
    println!("ENUM filters={filters} sublayers={sublayers} providers={providers}");
    assert_eq!(filters, expected);
    assert_eq!(sublayers, present as usize);
    assert_eq!(providers, present as usize);
}

fn main() {
    let a: Vec<_> = env::args().collect();
    let e = Engine::open();
    unsafe {
        match a[1].as_str() {
            "install" => {
                install(e.0, a[2].parse().unwrap());
                fs::write(&a[3], std::process::id().to_string()).unwrap();
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
            "remove" => remove(e.0),
            "present" => verify(e.0, true),
            "absent" => verify(e.0, false),
            _ => panic!("unknown command"),
        }
    }
}
