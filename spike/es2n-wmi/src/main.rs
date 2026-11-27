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
//!   DllGetClassObject of System32\FirewallAPI.dll; rule count;
//! - fwapi: every plant of every mode; FirewallAPI.dll's flat API (no COM)
//!   from its absolute System32 path: open the local store at binary
//!   version 2.27, enumerate, delete rule a by id, verify;
//! - natives: every plant; one call of each native API the other ops use
//!   (IP Helper, SCM, ToolHelp, registry), for the Process Monitor capture.
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
        } else if mode == "fwapi" {
            flat(expected, &a, &b, &planted, &mut failures)
        } else if mode == "natives" {
            natives(&planted, &mut failures)
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
    let all = matches!(mode, "fwapi" | "natives");
    let classes = all || matches!(mode, "inproc" | "dgco");
    let treat = all || matches!(mode, "treatas" | "dgco");
    let proxy = all || matches!(mode, "proxy" | "dgco");
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
    if all || mode == "fw" {
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
    if treat || proxy || all || mode == "fw" {
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
    let status = unsafe {
        (api.enumerate)(store, FW_RULE_STATUS_CLASS_ALL, FW_PROFILE_TYPE_ALL, flags, &mut count, &mut head)
    };
    if status != 0 {
        return Err(status);
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
    if !head.is_null() {
        let freed = unsafe { (api.free)(head) };
        if freed != 0 {
            println!("FWFreeFirewallRules: {freed}");
        }
    }
    Ok(rows)
}

unsafe fn flat(expected: usize, a: &str, b: &str, planted: &Planted, failures: &mut Vec<String>) {
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
    unsafe { planted_loaded(planted, failures) };
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
unsafe fn natives(planted: &Planted, failures: &mut Vec<String>) {
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
        planted_loaded(planted, failures);
        for module in ["combase.dll", "ole32.dll", "oleaut32.dll", "shell32.dll"] {
            println!("module {module} loaded: {}", GetModuleHandleW(&HSTRING::from(module)).is_ok());
        }
    }
}
