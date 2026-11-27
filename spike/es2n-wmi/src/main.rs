//! ES2N step-0 spike (doc#17, conditions msg#1820 and msg#1833), CI only.
//! From native code in an elevated process, proves or refutes:
//! 1. HKCU class overrides for every class and proxy/stub this path uses
//!    (CLSID_WbemLocator and CLSID_WbemContext InprocServer32, TreatAs,
//!    AutoTreatAs; Interface\{IID}\ProxyStubClsid32 for every remoted IID;
//!    the real proxy/stub CLSIDs' InprocServer32) redirect nothing: every
//!    call succeeds and no planted DLL is loaded. The merged HKCR view is
//!    printed as the control that the plants are visible;
//! 2. MSFT_NetFirewallRule with the context PolicyStore=PersistentStore
//!    lists as many rules as Get-NetFirewallRule -PolicyStore
//!    PersistentStore (count passed in);
//! 3. an id holding ', \ and " survives WQL escaping; GetObject(__PATH)
//!    returns exactly that InstanceID; DeleteInstance on it removes exactly
//!    that id (WMI and the HKLM FirewallRules value) and not a same-name
//!    sibling; every wait is bounded.
//!
//! Usage: es2n-wmi-spike <expected-count> <mode>, ids in ETD_SPIKE_A and
//! ETD_SPIKE_B. Modes, one process each (COM caches lookups):
//! - none: no plants; the full list/GetObject/delete flow;
//! - inproc: InprocServer32 plants for the two classes only;
//! - treatas: TreatAs and AutoTreatAs plants only;
//! - proxy: ProxyStubClsid32 and proxy/stub InprocServer32 plants only;
//! - dgco: every plant; the two classes from DllGetClassObject of their
//!   HKLM-registered System32 DLLs, loaded by absolute path;
//! - fw: plants for CLSID_NetFwPolicy2; INetFwPolicy2 from
//!   DllGetClassObject of System32\FirewallAPI.dll; rule count.
//! Exit 0 only if every expectation holds; every finding is printed.
use std::time::Instant;
use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoSetProxyBlanket, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            },
            LibraryLoader::GetModuleHandleW,
            Registry::{
                HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_SZ, RRF_RT_ANY,
                RRF_RT_REG_SZ, RegDeleteTreeW, RegGetValueW, RegSetKeyValueW,
            },
            Variant::{VARIANT, VT_BOOL, VT_BSTR, VT_I4, VT_NULL, VT_UI2, VariantClear},
            Wmi::{
                IEnumWbemClassObject, IWbemCallResult, IWbemClassObject, IWbemContext,
                IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
                WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_FLAG_RETURN_WBEM_COMPLETE, WbemContext,
                WbemLocator,
            },
        },
    },
    core::{BSTR, HSTRING, IUnknown, Interface, PCWSTR},
};

const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;
const WAIT_MS: i32 = 30_000;
const WBEM_S_TIMEDOUT: i32 = 0x0004_0004;
const RULES: &str =
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
const EVIL_DIR: &str = r"C:\etd-es2n-spike-planted";
const LOCATOR: &str = "{4590F811-1D3A-11D0-891F-00AA004B2E24}";
const CONTEXT: &str = "{674B6698-EE92-11D0-AD71-00C04FD8FDFF}";
/// A CLSID nothing registers, as the TreatAs/AutoTreatAs and fake
/// ProxyStubClsid32 target.
const BOGUS: &str = "{E7D0E5A1-2B4C-4F6D-9E8A-0123456789AB}";
const FWPOLICY: &str = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
/// Every interface that crosses to winmgmt on this path.
const IIDS: [(&str, &str); 6] = [
    ("IWbemServices", "{9556DC99-828C-11CF-A37E-00AA003240C7}"),
    ("IEnumWbemClassObject", "{027947E1-D731-11CE-A357-000000000001}"),
    ("IWbemClassObject", "{DC12A681-737F-11CF-884D-00AA004B2E24}"),
    ("IWbemContext", "{44ACA674-E8FC-11D0-A07C-00C04FB68820}"),
    ("IWbemCallResult", "{44ACA675-E8FC-11D0-A07C-00C04FB68820}"),
    ("IWbemLevel1Login", "{F309AD18-D86A-11D0-A075-00C04FB68820}"),
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let expected: usize = args[1].parse().unwrap();
    let mode = args[2].clone();
    println!("=== mode {mode}; EnableLUA = {:?}", lua());
    let (a, b) = (std::env::var("ETD_SPIKE_A").unwrap(), std::env::var("ETD_SPIKE_B").unwrap());
    let mut failures = Vec::new();
    let planted = plant(&mode, &mut failures);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        if mode == "fw" {
            firewall(expected, &planted, &mut failures)
        } else {
            run(expected, &mode, &a, &b, &planted, &mut failures)
        }
    }));
    unplant(&planted);
    if let Err(panic) = result {
        failures.push(format!("panic: {panic:?}"));
    }
    if failures.is_empty() {
        println!("SPIKE PASS ({mode})");
    } else {
        println!("SPIKE FAIL ({mode}): {failures:?}");
        std::process::exit(1);
    }
}

/// Top-level HKCU keys this run created (deleted at the end), and the DLL
/// file names it planted.
struct Planted {
    keys: Vec<String>,
    dlls: Vec<String>,
}

fn plant(mode: &str, failures: &mut Vec<String>) -> Planted {
    let classes = matches!(mode, "inproc" | "dgco");
    let treat = matches!(mode, "treatas" | "dgco");
    let proxy = matches!(mode, "proxy" | "dgco");
    let mut planted = Planted { keys: Vec::new(), dlls: Vec::new() };
    let mut set = |key: &str, name: Option<&str>, value: &str| {
        let status = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                &HSTRING::from(format!(r"Software\Classes\{key}")),
                &HSTRING::from(name.unwrap_or("")),
                REG_SZ.0,
                Some(wide(value).as_ptr().cast()),
                (wide(value).len() * 2) as u32,
            )
        };
        if status != ERROR_SUCCESS {
            failures.push(format!("plant {key}: {status:?}"));
        }
    };
    let top = |key: String, keys: &mut Vec<String>| {
        if exists(HKEY_CURRENT_USER, &format!(r"Software\Classes\{key}")) {
            panic!("HKCU already has {key}; refusing to plant over it");
        }
        keys.push(key);
    };
    let dll = |label: &str, dlls: &mut Vec<String>| {
        dlls.push(format!("{label}.dll"));
        format!(r"{EVIL_DIR}\{label}.dll")
    };
    if mode == "fw" {
        let clsid = FWPOLICY;
        top(format!(r"CLSID\{clsid}"), &mut planted.keys);
        let path = dll("fwpolicy", &mut planted.dlls);
        set(&format!(r"CLSID\{clsid}\InprocServer32"), None, &path);
        set(&format!(r"CLSID\{clsid}\InprocServer32"), Some("ThreadingModel"), "Both");
        set(&format!(r"CLSID\{clsid}\TreatAs"), None, BOGUS);
        set(&format!(r"CLSID\{clsid}\AutoTreatAs"), None, BOGUS);
    }
    if classes || treat {
        for (label, clsid) in [("locator", LOCATOR), ("context", CONTEXT)] {
            top(format!(r"CLSID\{clsid}"), &mut planted.keys);
            if classes {
                let path = dll(label, &mut planted.dlls);
                set(&format!(r"CLSID\{clsid}\InprocServer32"), None, &path);
                set(&format!(r"CLSID\{clsid}\InprocServer32"), Some("ThreadingModel"), "Both");
            }
            if treat {
                set(&format!(r"CLSID\{clsid}\TreatAs"), None, BOGUS);
                set(&format!(r"CLSID\{clsid}\AutoTreatAs"), None, BOGUS);
            }
        }
    }
    if treat || proxy || mode == "fw" {
        top(format!(r"CLSID\{BOGUS}"), &mut planted.keys);
        let path = dll("bogus", &mut planted.dlls);
        set(&format!(r"CLSID\{BOGUS}\InprocServer32"), None, &path);
        set(&format!(r"CLSID\{BOGUS}\InprocServer32"), Some("ThreadingModel"), "Both");
    }
    if !proxy {
        return planted;
    }
    let mut proxies = Vec::new();
    for (name, iid) in IIDS {
        let real = reg_sz(HKEY_LOCAL_MACHINE, &format!(r"SOFTWARE\Classes\Interface\{iid}\ProxyStubClsid32"));
        println!("HKLM {name} ProxyStubClsid32 = {real:?}");
        top(format!(r"Interface\{iid}"), &mut planted.keys);
        set(&format!(r"Interface\{iid}\ProxyStubClsid32"), None, BOGUS);
        if let Some(real) = real
            && !proxies.contains(&real)
        {
            proxies.push(real);
        }
    }
    for (n, clsid) in proxies.iter().enumerate() {
        if clsid.eq_ignore_ascii_case(LOCATOR) || clsid.eq_ignore_ascii_case(CONTEXT) {
            continue;
        }
        top(format!(r"CLSID\{clsid}"), &mut planted.keys);
        let path = dll(&format!("proxy{n}"), &mut planted.dlls);
        set(&format!(r"CLSID\{clsid}\InprocServer32"), None, &path);
        set(&format!(r"CLSID\{clsid}\InprocServer32"), Some("ThreadingModel"), "Both");
    }
    planted
}

fn unplant(planted: &Planted) {
    for key in &planted.keys {
        let status = unsafe {
            RegDeleteTreeW(HKEY_CURRENT_USER, &HSTRING::from(format!(r"Software\Classes\{key}")))
        };
        println!("unplant {key}: {status:?}");
    }
}

unsafe fn run(expected: usize, mode: &str, a: &str, b: &str, planted: &Planted, failures: &mut Vec<String>) {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok().unwrap();
        // Control: the merged HKCR view an unprotected lookup would use.
        for key in &planted.keys {
            for sub in ["InprocServer32", "ProxyStubClsid32"] {
                if let Some(v) = reg_sz(HKEY_CLASSES_ROOT, &format!(r"{key}\{sub}")) {
                    println!("merged HKCR {key}\\{sub} = {v}");
                }
            }
        }

        let started = Instant::now();
        let located = if mode == "dgco" {
            from_dll(LOCATOR)
        } else {
            CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
        };
        let locator: IWbemLocator = match located {
            Ok(l) => l,
            Err(e) => {
                failures.push(format!("WbemLocator activation under the plants: {e}"));
                return;
            }
        };
        let services: IWbemServices = match locator.ConnectServer(
            &BSTR::from(r"ROOT\StandardCimv2"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("ConnectServer under the plants: {e}"));
                return;
            }
        };
        blanket(&services);
        let context = if mode == "dgco" {
            from_dll(CONTEXT)
        } else {
            CoCreateInstance(&WbemContext, None, CLSCTX_INPROC_SERVER)
        };
        let context: IWbemContext = match context {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("WbemContext activation under the plants: {e}"));
                return;
            }
        };
        let mut store = VARIANT::default();
        (*store.Anonymous.Anonymous).vt = VT_BSTR;
        (*store.Anonymous.Anonymous).Anonymous.bstrVal =
            std::mem::ManuallyDrop::new(BSTR::from("PersistentStore"));
        context.SetValue(&HSTRING::from("PolicyStore"), 0, &store).unwrap();
        let _ = VariantClear(&mut store);
        println!("connect: {} ms", started.elapsed().as_millis());

        // 2. Count.
        let started = Instant::now();
        let all = match query(&services, Some(&context), "SELECT InstanceID FROM MSFT_NetFirewallRule") {
            Ok(rows) => rows,
            Err(e) => {
                failures.push(format!("rule query under the plants: {e}"));
                return;
            }
        };
        println!(
            "persistent rules: {} (PowerShell: {expected}) in {} ms",
            all.len(),
            started.elapsed().as_millis()
        );
        if all.len() != expected {
            failures.push(format!("count {} != {expected}", all.len()));
        }
        match query(&services, None, "SELECT InstanceID FROM MSFT_NetFirewallRule") {
            Ok(rows) => println!("rules without the context (provider default store): {}", rows.len()),
            Err(e) => println!("rules without the context: {e}"),
        }

        if mode != "none" {
            planted_loaded(planted, failures);
            return;
        }
        // 3. Escaped lookup, exact GetObject, delete by path.
        let wql = format!(
            "SELECT * FROM MSFT_NetFirewallRule WHERE InstanceID = '{}'",
            wql_string(a)
        );
        println!("wql: {wql}");
        let rows = query(&services, Some(&context), &wql).unwrap_or_default();
        if rows.len() != 1 {
            failures.push(format!("rule a by escaped id: {} rows", rows.len()));
        }
        if let Some(row) = rows.first() {
            println!("--- rule a MOF:\n{}", row.GetObjectText(0).unwrap());
            let path = text(row, "__PATH").unwrap_or_default();
            println!("rule a __PATH = {path}");
            let relpath = text(row, "__RELPATH").unwrap_or_default();
            match query(
                &services,
                Some(&context),
                &format!("ASSOCIATORS OF {{{relpath}}} WHERE ResultClass = MSFT_NetFirewallApplicationFilter"),
            ) {
                Ok(filters) => {
                    println!("rule a application filters: {}", filters.len());
                    for f in &filters {
                        println!("--- filter MOF:\n{}", f.GetObjectText(0).unwrap());
                    }
                }
                Err(e) => failures.push(format!("application filter association: {e}")),
            }
            let mut object = None;
            match services.GetObject(&BSTR::from(path.as_str()), WBEM_FLAG_RETURN_WBEM_COMPLETE, &context, Some(&mut object), None) {
                Ok(()) => {
                    let id = object.as_ref().and_then(|o| text(o, "InstanceID"));
                    println!("GetObject InstanceID = {id:?}");
                    if id.as_deref() != Some(a) {
                        failures.push(format!("GetObject returned {id:?}, expected {a:?}"));
                    }
                }
                Err(e) => failures.push(format!("GetObject(__PATH): {e}")),
            }
            println!("registry a present: {}", rule_value(a));
            println!("registry b present: {}", rule_value(b));
            let started = Instant::now();
            match delete(&services, &context, &path) {
                Ok(status) => println!("DeleteInstance status {status:#x} in {} ms", started.elapsed().as_millis()),
                Err(e) => failures.push(format!("DeleteInstance: {e}")),
            }
            let gone = query(&services, Some(&context), &wql).map(|r| r.len());
            let sibling = query(
                &services,
                Some(&context),
                &format!("SELECT InstanceID FROM MSFT_NetFirewallRule WHERE InstanceID = '{}'", wql_string(b)),
            )
            .map(|r| r.len());
            let (reg_a, reg_b) = (rule_value(a), rule_value(b));
            println!("after: wmi a={gone:?} b={sibling:?}; registry a={reg_a} b={reg_b}");
            if gone != Ok(0) || reg_a {
                failures.push("rule a still present after delete".to_owned());
            }
            if sibling != Ok(1) || !reg_b {
                failures.push("same-name rule b was touched".to_owned());
            }
            println!("second delete of a: {:?}", delete(&services, &context, &path));
            let mut again = None;
            println!(
                "GetObject of the deleted path: {:?}",
                services.GetObject(&BSTR::from(path.as_str()), WBEM_FLAG_RETURN_WBEM_COMPLETE, &context, Some(&mut again), None)
            );
        }

        planted_loaded(planted, failures);
        for module in ["wbemprox.dll", "fastprox.dll", "wbemsvc.dll", "firewallapi.dll"] {
            println!("module {module} loaded: {}", GetModuleHandleW(&HSTRING::from(module)).is_ok());
        }
    }
}

/// Impersonate on every proxy, the enumerators and call results included.
unsafe fn blanket(proxy: &impl Interface) {
    let unknown: IUnknown = proxy.cast().unwrap();
    unsafe {
        CoSetProxyBlanket(
            &unknown,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
        .unwrap();
    }
}

/// A WQL string literal body: backslash and single quote escaped.
fn wql_string(value: &str) -> String {
    value.replace('\\', r"\\").replace('\'', r"\'")
}

unsafe fn delete(services: &IWbemServices, context: &IWbemContext, path: &str) -> windows::core::Result<i32> {
    unsafe {
        let mut call: Option<IWbemCallResult> = None;
        services.DeleteInstance(
            &BSTR::from(path),
            WBEM_FLAG_RETURN_IMMEDIATELY,
            context,
            Some(&mut call),
        )?;
        let call = call.unwrap();
        blanket(&call);
        let status = call.GetCallStatus(WAIT_MS)?;
        if status == WBEM_S_TIMEDOUT {
            return Err(windows::core::Error::new(windows::core::HRESULT(status), "timed out"));
        }
        windows::core::HRESULT(status).ok()?;
        Ok(status)
    }
}

unsafe fn query(
    services: &IWbemServices,
    context: Option<&IWbemContext>,
    wql: &str,
) -> windows::core::Result<Vec<IWbemClassObject>> {
    unsafe {
        let rows: IEnumWbemClassObject = services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(wql),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            context,
        )?;
        blanket(&rows);
        let mut out = Vec::new();
        loop {
            let mut slot = [None];
            let mut returned = 0;
            let hr = rows.Next(WAIT_MS, &mut slot, &mut returned);
            if hr.0 == WBEM_S_TIMEDOUT {
                return Err(windows::core::Error::new(hr, "enumeration timed out"));
            }
            hr.ok()?;
            if returned == 0 {
                break;
            }
            out.push(slot[0].take().unwrap());
        }
        Ok(out)
    }
}

unsafe fn text(row: &IWbemClassObject, name: &str) -> Option<String> {
    unsafe {
        let mut v = VARIANT::default();
        row.Get(&HSTRING::from(name), 0, &mut v, None, None).ok()?;
        let inner = &*v.Anonymous.Anonymous;
        let out = match inner.vt {
            VT_BSTR => Some(inner.Anonymous.bstrVal.to_string()),
            VT_I4 => Some(format!("i4 {}", inner.Anonymous.lVal)),
            VT_UI2 => Some(format!("ui2 {}", inner.Anonymous.uiVal)),
            VT_BOOL => Some(format!("bool {}", inner.Anonymous.boolVal.0)),
            VT_NULL => None,
            other => Some(format!("<vt {}>", other.0)),
        };
        let _ = VariantClear(&mut v);
        out
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn exists(root: HKEY, path: &str) -> bool {
    unsafe { open_key(root, path) }
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

fn reg_sz(root: HKEY, path: &str) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            &HSTRING::from(path),
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then(|| String::from_utf16_lossy(&buf[..(size as usize / 2).saturating_sub(1)]))
}

fn rule_value(id: &str) -> bool {
    let mut size = 0u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(RULES),
            &HSTRING::from(id),
            RRF_RT_ANY,
            None,
            None,
            Some(&mut size),
        )
    };
    status == ERROR_SUCCESS
}

unsafe fn planted_loaded(planted: &Planted, failures: &mut Vec<String>) {
    for dll in &planted.dlls {
        let loaded = unsafe { GetModuleHandleW(&HSTRING::from(dll.as_str())) }.is_ok();
        println!("planted {dll} loaded: {loaded}");
        if loaded {
            failures.push(format!("planted {dll} loaded"));
        }
    }
}

/// The class from DllGetClassObject of the DLL HKLM registers for it,
/// loaded by absolute path under the system directory.
unsafe fn from_dll<T: Interface>(clsid: &str) -> windows::core::Result<T> {
    use windows::{
        Win32::System::{
            Com::IClassFactory,
            LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW},
            SystemInformation::GetSystemDirectoryW,
        },
        core::{GUID, HRESULT, PCSTR},
    };
    let registered = reg_expand(HKEY_LOCAL_MACHINE, &format!(r"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32"))
        .ok_or_else(|| windows::core::Error::new(HRESULT(-1), "no HKLM InprocServer32"))?;
    let mut system = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(Some(&mut system)) } as usize;
    let system = String::from_utf16_lossy(&system[..n]);
    let lower = registered.to_ascii_lowercase();
    let tail = [r"%systemroot%\system32\", r"%windir%\system32\", r"c:\windows\system32\"]
        .iter()
        .find_map(|p| lower.strip_prefix(p).map(|_| &registered[p.len()..]))
        .ok_or_else(|| windows::core::Error::new(HRESULT(-1), "not under System32"))?;
    let path = format!(r"{system}\{tail}");
    println!("DllGetClassObject {clsid} from {path} (HKLM: {registered})");
    unsafe {
        let module = LoadLibraryExW(&HSTRING::from(path.as_str()), None, LOAD_WITH_ALTERED_SEARCH_PATH)?;
        let proc = GetProcAddress(module, PCSTR(c"DllGetClassObject".as_ptr().cast()))
            .ok_or_else(|| windows::core::Error::new(HRESULT(-1), "no DllGetClassObject"))?;
        type GetClassObject =
            unsafe extern "system" fn(*const GUID, *const GUID, *mut *mut core::ffi::c_void) -> HRESULT;
        let get: GetClassObject = std::mem::transmute(proc);
        let class = GUID::try_from(clsid.trim_matches(['{', '}'])).unwrap();
        let mut factory = std::ptr::null_mut();
        get(&class, &IClassFactory::IID, &mut factory).ok()?;
        let factory = IClassFactory::from_raw(factory);
        factory.CreateInstance(None)
    }
}

unsafe fn firewall(expected: usize, planted: &Planted, failures: &mut Vec<String>) {
    use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, NetFwPolicy2};
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok().unwrap();
        let plain: windows::core::Result<INetFwPolicy2> =
            CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER);
        println!("CoCreateInstance(NetFwPolicy2) under the plants: {:?}", plain.as_ref().map(|_| ()));
        match from_dll::<INetFwPolicy2>(FWPOLICY) {
            Ok(policy) => match policy.Rules().and_then(|r| r.Count()) {
                Ok(n) => println!("INetFwPolicy2 rules: {n} (PowerShell persistent: {expected})"),
                Err(e) => failures.push(format!("INetFwPolicy2 rules: {e}")),
            },
            Err(e) => failures.push(format!("INetFwPolicy2 from FirewallAPI.dll: {e}")),
        }
        planted_loaded(planted, failures);
    }
}

fn lua() -> Option<u32> {
    let mut value = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            &HSTRING::from("EnableLUA"),
            windows::Win32::System::Registry::RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then_some(value)
}

fn reg_expand(root: HKEY, path: &str) -> Option<String> {
    use windows::Win32::System::Registry::{RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ};
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            &HSTRING::from(path),
            PCWSTR::null(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then(|| String::from_utf16_lossy(&buf[..(size as usize / 2).saturating_sub(1)]))
}
