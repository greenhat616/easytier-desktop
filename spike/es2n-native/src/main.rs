//! ES2N step-0 spike (doc#17), CI only: the native paths with no COM
//! import at all, so a Process Monitor capture of this process shows only
//! what these calls (and the DLLs they load) read. The HKCU plants are made
//! and removed by the workflow, in other processes.
//!
//! Usage: es2n-native-spike <expected-count> <fwapi|natives>, rule ids in
//! ETD_SPIKE_A and ETD_SPIKE_B.
use std::{io::Write, time::Instant};
use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::{
            LibraryLoader::GetModuleHandleW,
            Registry::{HKEY, HKEY_LOCAL_MACHINE, RRF_RT_ANY, RegGetValueW},
        },
    },
    core::{HSTRING, PCWSTR},
};

const RULES: &str =
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
const PLANTED: [&str; 8] = [
    "locator.dll", "context.dll", "bogus.dll", "fwpolicy.dll", "proxy0.dll", "proxy1.dll", "proxy2.dll", "proxy3.dll",
];

fn step(what: &str) {
    println!("  .. {what}");
    let _ = std::io::stdout().flush();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let expected: usize = args[1].parse().unwrap();
    let mode = args[2].as_str();
    println!("=== native mode {mode}");
    let (a, b) = (std::env::var("ETD_SPIKE_A").unwrap_or_default(), std::env::var("ETD_SPIKE_B").unwrap_or_default());
    let mut failures = Vec::new();
    unsafe {
        match mode {
            "fwapi" => flat(expected, &a, &b, &mut failures),
            "natives" => natives(&mut failures),
            _ => panic!("unknown mode"),
        }
    }
    for module in ["combase.dll", "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "shell32.dll", "user32.dll"] {
        println!("module {module} loaded: {}", unsafe { GetModuleHandleW(&HSTRING::from(module)) }.is_ok());
    }
    if failures.is_empty() {
        println!("NATIVE PASS ({mode})");
    } else {
        println!("NATIVE FAIL ({mode}): {failures:?}");
        std::process::exit(1);
    }
}

fn loaded_planted(failures: &mut Vec<String>) {
    for dll in PLANTED {
        if unsafe { GetModuleHandleW(&HSTRING::from(dll)) }.is_ok() {
            failures.push(format!("planted {dll} loaded"));
        }
    }
}

unsafe fn open_key(root: HKEY, path: &str) -> bool {
    use windows::Win32::System::Registry::{KEY_READ, RegCloseKey, RegOpenKeyExW};
    let mut key = HKEY::default();
    let status = unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, KEY_READ, &mut key) };
    if status == ERROR_SUCCESS {
        let _ = unsafe { RegCloseKey(key) };
        true
    } else {
        false
    }
}

fn rule_value(id: &str) -> bool {
    let mut size = 0u32;
    let status = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, &HSTRING::from(RULES), &HSTRING::from(id), RRF_RT_ANY, None, None, Some(&mut size))
    };
    status == ERROR_SUCCESS
}

#[repr(C)]
#[derive(Clone, Copy)]
struct List {
    n: u32,
    p: *mut core::ffi::c_void,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct FwPorts {
    keywords: u16,
    ports: List,
}
#[repr(C)]
union PortsOrIcmp {
    ports: [FwPorts; 2],
    icmp: [List; 2],
}
#[repr(C)]
struct FwAddresses {
    v4_keywords: u32,
    v6_keywords: u32,
    lists: [List; 4],
}
/// FW_RULE at binary version 2.27 (learn.microsoft.com
/// windows/win32/ics/firewall/ns-firewall-fw_rule). Only read.
#[repr(C)]
struct FwRule {
    next: *mut FwRule,
    schema_version: u16,
    rule_id: *const u16,
    name: *const u16,
    description: *const u16,
    profiles: u32,
    direction: i32,
    ip_protocol: u16,
    ports: PortsOrIcmp,
    local_addresses: FwAddresses,
    remote_addresses: FwAddresses,
    local_interface_ids: List,
    local_interface_types: u32,
    local_application: *const u16,
    local_service: *const u16,
    action: i32,
    flags: u16,
    remote_machine_authorization: *const u16,
    remote_user_authorization: *const u16,
    embedded_context: *const u16,
    platform_validity: List,
    status: u32,
    origin: i32,
    gpo_name: *const u16,
    reserved: u32,
    metadata: *mut core::ffi::c_void,
    local_user_authorization: *const u16,
    package_id: *const u16,
    local_user_owner: *const u16,
    trust_tuple_keywords: u32,
    on_network_names: List,
    security_realm_id: *const u16,
    flags2: u16,
    remote_out_server_names: List,
    fqbn: *const u16,
    compartment_id: u32,
}

type OpenStore = unsafe extern "system" fn(u16, PCWSTR, i32, i32, u32, *mut windows::Win32::Foundation::HANDLE) -> u32;
type CloseStore = unsafe extern "system" fn(windows::Win32::Foundation::HANDLE) -> u32;
type EnumRules = unsafe extern "system" fn(windows::Win32::Foundation::HANDLE, u32, u32, u16, *mut u32, *mut *mut FwRule) -> u32;
type DeleteRule = unsafe extern "system" fn(windows::Win32::Foundation::HANDLE, PCWSTR) -> u32;
type FreeRules = unsafe extern "system" fn(*mut FwRule) -> u32;

const FW_BINARY_2_27: u16 = 0x021B;
const FW_STORE_TYPE_LOCAL: i32 = 2;
const FW_POLICY_ACCESS_RIGHT_READ_WRITE: i32 = 2;
const FW_RULE_STATUS_CLASS_ALL: u32 = 0xFFFF_0000;
const FW_PROFILE_TYPE_ALL: u32 = 0x7FFF_FFFF;

fn wstr(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)))
    }
}

struct FlatApi {
    open: OpenStore,
    close: CloseStore,
    enumerate: EnumRules,
    delete: DeleteRule,
    free: FreeRules,
}

unsafe fn flat_api() -> windows::core::Result<FlatApi> {
    use windows::{
        Win32::System::{
            LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW},
            SystemInformation::GetSystemDirectoryW,
        },
        core::{HRESULT, PCSTR},
    };
    let mut system = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(Some(&mut system)) } as usize;
    let path = format!(r"{}\FirewallAPI.dll", String::from_utf16_lossy(&system[..n]));
    println!("FirewallAPI.dll: {path} version {:?}", file_version(&path));
    unsafe {
        let module = LoadLibraryExW(&HSTRING::from(path.as_str()), None, LOAD_WITH_ALTERED_SEARCH_PATH)?;
        let get = |name: &std::ffi::CStr| {
            GetProcAddress(module, PCSTR(name.as_ptr().cast()))
                .ok_or_else(|| windows::core::Error::new(HRESULT(-1), format!("no {name:?}")))
        };
        Ok(FlatApi {
            open: std::mem::transmute(get(c"FWOpenPolicyStore")?),
            close: std::mem::transmute(get(c"FWClosePolicyStore")?),
            enumerate: std::mem::transmute(get(c"FWEnumFirewallRules")?),
            delete: std::mem::transmute(get(c"FWDeleteFirewallRule")?),
            free: std::mem::transmute(get(c"FWFreeFirewallRules")?),
        })
    }
}

/// (id, name, direction, application, group, schema, status, origin) of
/// every rule in the store.
type Row = (String, Option<String>, i32, Option<String>, Option<String>, u16, u32, i32);

unsafe fn flat_rows(api: &FlatApi, store: windows::Win32::Foundation::HANDLE, flags: u16) -> Result<Vec<Row>, u32> {
    let mut count = 0u32;
    let mut head: *mut FwRule = std::ptr::null_mut();
    step("FWEnumFirewallRules call");
    let status = unsafe {
        (api.enumerate)(store, FW_RULE_STATUS_CLASS_ALL, FW_PROFILE_TYPE_ALL, flags, &mut count, &mut head)
    };
    step(&format!("FWEnumFirewallRules returned {status}, count {count}, head {head:p}"));
    if status != 0 {
        return Err(status);
    }
    if !head.is_null() {
        let r = unsafe { &*head };
        step(&format!("first: schema {:#x} id ptr {:p} next {:p}", r.schema_version, r.rule_id, r.next));
        step(&format!("first id {:?}", wstr(r.rule_id)));
    }
    let mut rows = Vec::new();
    let mut at = head;
    while !at.is_null() {
        let r = unsafe { &*at };
        rows.push((
            wstr(r.rule_id).unwrap_or_default(),
            wstr(r.name),
            r.direction,
            wstr(r.local_application),
            wstr(r.embedded_context),
            r.schema_version,
            r.status,
            r.origin,
        ));
        at = r.next;
    }
    if rows.len() != count as usize {
        println!("list length {} != count {count}", rows.len());
    }
    step("FWFreeFirewallRules call");
    if !head.is_null() {
        let freed = unsafe { (api.free)(head) };
        if freed != 0 {
            println!("FWFreeFirewallRules: {freed}");
        }
    }
    Ok(rows)
}

unsafe fn flat(expected: usize, a: &str, b: &str, failures: &mut Vec<String>) {
    let api = match unsafe { flat_api() } {
        Ok(api) => api,
        Err(e) => {
            failures.push(format!("FirewallAPI.dll exports: {e}"));
            return;
        }
    };
    let mut store = windows::Win32::Foundation::HANDLE::default();
    let started = Instant::now();
    let status = unsafe {
        (api.open)(FW_BINARY_2_27, PCWSTR::null(), FW_STORE_TYPE_LOCAL, FW_POLICY_ACCESS_RIGHT_READ_WRITE, 0, &mut store)
    };
    println!("FWOpenPolicyStore(2.27, LOCAL, READ_WRITE): {status} in {} ms", started.elapsed().as_millis());
    if status != 0 {
        failures.push(format!("FWOpenPolicyStore: {status}"));
        return;
    }
    let started = Instant::now();
    match unsafe { flat_rows(&api, store, 0) } {
        Ok(rows) => {
            println!("FWEnumFirewallRules: {} rules (PowerShell persistent: {expected}) in {} ms", rows.len(), started.elapsed().as_millis());
            if rows.len() != expected {
                failures.push(format!("count {} != {expected}", rows.len()));
            }
            let mut schemas: Vec<u16> = rows.iter().map(|r| r.5).collect();
            schemas.sort();
            schemas.dedup();
            println!("schema versions: {:x?}", schemas);
            let mut statuses: Vec<u32> = rows.iter().map(|r| r.6).collect();
            statuses.sort();
            statuses.dedup();
            println!("statuses: {:x?}", statuses);
            for r in rows.iter().filter(|r| r.0 == a || r.0 == b) {
                println!("fixture: {r:?}");
            }
            if let Some(r) = rows.iter().find(|r| r.1.as_deref().is_some_and(|n| n.starts_with('@'))) {
                println!("an indirect name, unresolved: {r:?}");
            }
            if rows.iter().filter(|r| r.0 == a).count() != 1 {
                failures.push("rule a not exactly once".into());
            }
        }
        Err(status) => failures.push(format!("FWEnumFirewallRules: {status}")),
    }
    if let Ok(rows) = unsafe { flat_rows(&api, store, 0x0001 | 0x0004) } {
        if let Some(r) = rows.iter().find(|r| r.0.starts_with("CoreNet") || r.0.starts_with("FPS")) {
            println!("with RESOLVE_NAME|RESOLVE_APPLICATION: {r:?}");
        }
    }
    println!("registry a present: {}, b present: {}", rule_value(a), rule_value(b));
    let started = Instant::now();
    let deleted = unsafe { (api.delete)(store, PCWSTR(HSTRING::from(a).as_ptr())) };
    println!("FWDeleteFirewallRule(a): {deleted} in {} ms", started.elapsed().as_millis());
    if deleted != 0 {
        failures.push(format!("FWDeleteFirewallRule: {deleted}"));
    }
    match unsafe { flat_rows(&api, store, 0) } {
        Ok(rows) => {
            let (ra, rb) = (rows.iter().filter(|r| r.0 == a).count(), rows.iter().filter(|r| r.0 == b).count());
            let (ga, gb) = (rule_value(a), rule_value(b));
            println!("after: enum a={ra} b={rb}; registry a={ga} b={gb}");
            if ra != 0 || ga {
                failures.push("rule a still present after delete".into());
            }
            if rb != 1 || !gb {
                failures.push("same-name rule b was touched".into());
            }
        }
        Err(status) => failures.push(format!("re-enumerate: {status}")),
    }
    println!("second FWDeleteFirewallRule(a): {}", unsafe { (api.delete)(store, PCWSTR(HSTRING::from(a).as_ptr())) });
    println!("FWClosePolicyStore: {}", unsafe { (api.close)(store) });
    loaded_planted(failures);
    for module in ["combase.dll", "ole32.dll", "oleaut32.dll", "wbemprox.dll", "fastprox.dll", "shell32.dll"] {
        println!("module {module} loaded: {}", unsafe { GetModuleHandleW(&HSTRING::from(module)) }.is_ok());
    }
}

fn file_version(path: &str) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW};
    unsafe {
        let size = GetFileVersionInfoSizeW(&HSTRING::from(path), None);
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        GetFileVersionInfoW(&HSTRING::from(path), None, size, data.as_mut_ptr().cast()).ok()?;
        let mut info: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if !VerQueryValueW(data.as_ptr().cast(), &HSTRING::from("\\"), &mut info, &mut len).as_bool() {
            return None;
        }
        let f = &*(info as *const VS_FIXEDFILEINFO);
        Some(format!(
            "{}.{}.{}.{}",
            f.dwFileVersionMS >> 16,
            f.dwFileVersionMS & 0xffff,
            f.dwFileVersionLS >> 16,
            f.dwFileVersionLS & 0xffff
        ))
    }
}

/// One call of each native API the non-firewall ops use, under the plants.
unsafe fn natives(failures: &mut Vec<String>) {
    use windows::Win32::{
        NetworkManagement::IpHelper::{
            ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, FreeMibTable, GetExtendedTcpTable,
            GetIpForwardTable2, GetUnicastIpAddressTable, MIB_IPFORWARD_TABLE2, MIB_UNICASTIPADDRESS_TABLE,
            TCP_TABLE_OWNER_PID_LISTENER,
        },
        NetworkManagement::Ndis::NET_LUID_LH,
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
        System::{
            Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS},
            Services::{
                ENUM_SERVICE_STATE, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO,
                SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER, SERVICE_STATE_ALL, SERVICE_WIN32, CloseServiceHandle,
            },
            Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
        },
    };
    unsafe {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        let st = GetUnicastIpAddressTable(AF_UNSPEC, &mut table);
        println!("GetUnicastIpAddressTable: {st:?} rows {}", if table.is_null() { 0 } else { (*table).NumEntries });
        if !table.is_null() {
            FreeMibTable(table.cast());
        }
        let mut routes: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let st = GetIpForwardTable2(AF_UNSPEC, &mut routes);
        println!("GetIpForwardTable2: {st:?} rows {}", if routes.is_null() { 0 } else { (*routes).NumEntries });
        if !routes.is_null() {
            FreeMibTable(routes.cast());
        }
        let mut luid = NET_LUID_LH::default();
        if ConvertInterfaceIndexToLuid(1, &mut luid).is_ok() {
            let mut alias = [0u16; 257];
            let st = ConvertInterfaceLuidToAlias(&luid, &mut alias);
            println!("ConvertInterfaceLuidToAlias(1): {st:?} {}", String::from_utf16_lossy(&alias[..alias.iter().position(|&c| c == 0).unwrap_or(0)]));
        }
        for family in [AF_INET, AF_INET6] {
            let mut size = 0u32;
            let _ = GetExtendedTcpTable(None, &mut size, false, family.0 as u32, TCP_TABLE_OWNER_PID_LISTENER, 0);
            let mut buf = vec![0u8; size as usize + 1024];
            let st = GetExtendedTcpTable(Some(buf.as_mut_ptr().cast()), &mut size, false, family.0 as u32, TCP_TABLE_OWNER_PID_LISTENER, 0);
            println!("GetExtendedTcpTable({}): {st} rows {}", family.0, u32::from_ne_bytes(buf[..4].try_into().unwrap()));
        }
        match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) {
            Ok(scm) => {
                for (label, kind) in [("win32", SERVICE_WIN32), ("driver", SERVICE_DRIVER)] {
                    let mut needed = 0u32;
                    let mut count = 0u32;
                    let mut resume = 0u32;
                    let _ = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, kind, SERVICE_STATE_ALL, None, &mut needed, &mut count, Some(&mut resume), PCWSTR::null());
                    let mut buf = vec![0u8; needed as usize + 4096];
                    resume = 0;
                    let r = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, kind, SERVICE_STATE_ALL, Some(&mut buf), &mut needed, &mut count, Some(&mut resume), PCWSTR::null());
                    println!("EnumServicesStatusExW({label}): {:?} count {count}", r.map(|_| ()));
                }
                let _ = CloseServiceHandle(scm);
                let _ = ENUM_SERVICE_STATE(0);
            }
            Err(e) => failures.push(format!("OpenSCManagerW: {e}")),
        }
        match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(snap) => {
                let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
                let mut n = 0;
                let mut paths = 0;
                if Process32FirstW(snap, &mut entry).is_ok() {
                    loop {
                        n += 1;
                        if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, entry.th32ProcessID) {
                            let mut buf = [0u16; 1024];
                            let mut len = buf.len() as u32;
                            if QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, windows::core::PWSTR(buf.as_mut_ptr()), &mut len).is_ok() {
                                paths += 1;
                            }
                            let _ = windows::Win32::Foundation::CloseHandle(h);
                        }
                        if Process32NextW(snap, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = windows::Win32::Foundation::CloseHandle(snap);
                println!("ToolHelp: {n} processes, {paths} paths");
            }
            Err(e) => failures.push(format!("CreateToolhelp32Snapshot: {e}")),
        }
        for key in [
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        ] {
            println!("HKLM {key} opens: {}", open_key(HKEY_LOCAL_MACHINE, key));
        }
        loaded_planted(failures);
        for module in ["combase.dll", "ole32.dll", "oleaut32.dll", "shell32.dll"] {
            println!("module {module} loaded: {}", GetModuleHandleW(&HSTRING::from(module)).is_ok());
        }
    }
}
