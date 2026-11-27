//! Firewall rules through FirewallAPI.dll's flat functions: no COM, local
//! RPC to the firewall service, rules listed and deleted by rule id.
//!
//! Pinned (doc#17 v2, msg#1959): the store is opened at binary version 2.27
//! and every rule list is freed with `FWFreeFirewallRulesByHandle` (the
//! newest-layout `FWFreeFirewallRules` corrupts a 2.27 list). The DLL is
//! loaded from System32 only, its dependencies too. Only Windows builds the
//! parity gate has passed on are used; anything unexpected (another build,
//! a missing export, a non-zero status, a rule whose status is not OK, a
//! list that disagrees with its count) fails closed. No `RESOLVE_*` flag is
//! ever passed: both resolve through the process environment.
//!
//! Every call runs on one module-owned thread ([`call`]). A caller waits at
//! most [`CALL_BOUND`]; a call that outlives it stays on that thread, and
//! [`shutdown`] reports it, so the host keeps its lock until the process
//! ends (doc#17 v2 #firewall).
use super::super::{
    WinError,
    registry::{Key, RawValue, utf16},
};
use super::Sweep;
use ::windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ};
use serde_json::{Value, json};
use std::{
    ffi::c_void,
    sync::{Condvar, Mutex, OnceLock, PoisonError, mpsc},
    time::{Duration, Instant},
};

/// Windows builds (major 10, minor 0) accepted without the self-check: the
/// ones the parity gate has run on, and 26200 (an enablement package over
/// 26100, same binaries). Any other build is accepted only if
/// [`self_check`] passes (human ruling msg#1980).
const SUPPORTED_BUILDS: &[u32] = &[20348, 26100, 26200];
/// FW_VERSION(2, 27).
const BINARY_VERSION: u16 = 0x021B;
const FW_STORE_TYPE_LOCAL: i32 = 2;
const FW_POLICY_ACCESS_RIGHT_READ: i32 = 1;
const FW_POLICY_ACCESS_RIGHT_READ_WRITE: i32 = 2;
const FW_RULE_STATUS_CLASS_ALL: u32 = 0xFFFF_0000;
const FW_RULE_STATUS_OK: u32 = 0x0001_0000;
const FW_PROFILE_TYPE_ALL: u32 = 0x7FFF_FFFF;
/// FW_ENUM_RULES_FLAG_NONE: no name or application resolution.
const FW_ENUM_RULES_FLAG_NONE: u16 = 0;
const FW_DIR_IN: i32 = 1;
const FW_DIR_OUT: i32 = 2;
/// More rules than this is not a firewall store we understand.
const MAX_RULES: u32 = 1_000_000;
/// Longest string read from a rule, in UTF-16 units.
const MAX_TEXT: usize = 32 * 1024;
/// How long a caller waits for one firewall call.
const CALL_BOUND: Duration = Duration::from_secs(10);
/// How long [`shutdown`] waits for a call in flight: the host's helper
/// budget (etd-host `stop_worst_case`, within the uninstaller's wait).
pub(crate) const SHUTDOWN_WAIT: Duration = Duration::from_secs(7);
const RULES_KEY: &str =
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
const ERROR_NOT_SUPPORTED: i64 = 50;
/// The message of the error an untested Windows build gets.
pub const UNSUPPORTED_BUILD: &str = "firewall cleanup not supported on this Windows build";

// ---- FW_RULE, binary version 2.27 ([MS-FASP] revision 36.1) ----

/// Any `{ unsigned long count; T* items; }` list of [MS-FASP] (2.2.13,
/// 2.2.17, 2.2.18, 2.2.31, 2.2.101 and the address lists of 2.2.22).
#[repr(C)]
#[derive(Clone, Copy)]
struct List {
    count: u32,
    items: *mut c_void,
}
/// FW_PORTS.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ports {
    keywords: u16,
    ports: List,
}
/// The anonymous union after wIpProtocol: the two FW_PORTS, or an
/// FW_ICMP_TYPE_CODE_LIST.
#[repr(C)]
#[derive(Clone, Copy)]
union PortsOrIcmp {
    ports: [Ports; 2],
    icmp: List,
}
/// FW_ADDRESSES.
#[repr(C)]
#[derive(Clone, Copy)]
struct Addresses {
    v4_keywords: u32,
    v6_keywords: u32,
    v4_subnets: List,
    v4_ranges: List,
    v6_subnets: List,
    v6_ranges: List,
}
/// FW_RULE as of binary version 2.27: `FW_RULE2_27`, [MS-FASP] 2.2.107, the
/// members of `FW_RULE` (2.2.37) up to `compartmentId`.
#[repr(C)]
struct Rule {
    next: *mut Rule,
    schema_version: u16,
    rule_id: *const u16,
    name: *const u16,
    description: *const u16,
    profiles: u32,
    direction: i32,
    ip_protocol: u16,
    ports: PortsOrIcmp,
    local_addresses: Addresses,
    remote_addresses: Addresses,
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
    metadata: *mut c_void,
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

/// The x64/ARM64 C layout (natural alignment) of `FW_RULE2_27` ([MS-FASP]
/// 2.2.107) and the structures it references: 2.2.13 FW_PORT_RANGE_LIST,
/// 2.2.15 FW_PORTS, 2.2.17 FW_ICMP_TYPE_CODE_LIST, 2.2.18
/// FW_INTERFACE_LUIDS, 2.2.22 FW_ADDRESSES, 2.2.31 FW_OS_PLATFORM_LIST,
/// 2.2.101 FW_NETWORK_NAMES; cross-checked with learn.microsoft.com's
/// FW_RULE page. No public SDK header declares it. At run time the parity
/// gate reads id, name, group, application, direction and status through
/// these offsets on each runner image and compares them with PowerShell.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<List>() == 16 && align_of::<List>() == 8);
    assert!(size_of::<Ports>() == 24 && offset_of!(Ports, ports) == 8);
    assert!(size_of::<PortsOrIcmp>() == 48 && align_of::<PortsOrIcmp>() == 8);
    assert!(size_of::<Addresses>() == 72 && offset_of!(Addresses, v4_subnets) == 8);
    assert!(offset_of!(Rule, next) == 0);
    assert!(offset_of!(Rule, schema_version) == 8);
    assert!(offset_of!(Rule, rule_id) == 16);
    assert!(offset_of!(Rule, name) == 24);
    assert!(offset_of!(Rule, description) == 32);
    assert!(offset_of!(Rule, profiles) == 40);
    assert!(offset_of!(Rule, direction) == 44);
    assert!(offset_of!(Rule, ip_protocol) == 48);
    assert!(offset_of!(Rule, ports) == 56);
    assert!(offset_of!(Rule, local_addresses) == 104);
    assert!(offset_of!(Rule, remote_addresses) == 176);
    assert!(offset_of!(Rule, local_interface_ids) == 248);
    assert!(offset_of!(Rule, local_interface_types) == 264);
    assert!(offset_of!(Rule, local_application) == 272);
    assert!(offset_of!(Rule, local_service) == 280);
    assert!(offset_of!(Rule, action) == 288);
    assert!(offset_of!(Rule, flags) == 292);
    assert!(offset_of!(Rule, remote_machine_authorization) == 296);
    assert!(offset_of!(Rule, remote_user_authorization) == 304);
    assert!(offset_of!(Rule, embedded_context) == 312);
    assert!(offset_of!(Rule, platform_validity) == 320);
    assert!(offset_of!(Rule, status) == 336);
    assert!(offset_of!(Rule, origin) == 340);
    assert!(offset_of!(Rule, gpo_name) == 344);
    assert!(offset_of!(Rule, reserved) == 352);
    assert!(offset_of!(Rule, metadata) == 360);
    assert!(offset_of!(Rule, local_user_authorization) == 368);
    assert!(offset_of!(Rule, package_id) == 376);
    assert!(offset_of!(Rule, local_user_owner) == 384);
    assert!(offset_of!(Rule, trust_tuple_keywords) == 392);
    assert!(offset_of!(Rule, on_network_names) == 400);
    assert!(offset_of!(Rule, security_realm_id) == 416);
    assert!(offset_of!(Rule, flags2) == 424);
    assert!(offset_of!(Rule, remote_out_server_names) == 432);
    assert!(offset_of!(Rule, fqbn) == 448);
    assert!(offset_of!(Rule, compartment_id) == 456);
    assert!(size_of::<Rule>() == 464 && align_of::<Rule>() == 8);
};

// ---- The flat API ----

type Open = unsafe extern "system" fn(u16, *const u16, i32, i32, u32, *mut *mut c_void) -> u32;
type Close = unsafe extern "system" fn(*mut c_void) -> u32;
type Enumerate =
    unsafe extern "system" fn(*mut c_void, u32, u32, u16, *mut u32, *mut *mut Rule) -> u32;
type Delete = unsafe extern "system" fn(*mut c_void, *const u16) -> u32;
type Free = unsafe extern "system" fn(*mut c_void, *mut Rule) -> u32;

/// The five functions, from FirewallAPI.dll (or a test's fakes).
#[derive(Clone, Copy)]
struct Api {
    open: Open,
    close: Close,
    enumerate: Enumerate,
    delete: Delete,
    free: Free,
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetModuleFileNameW(module: *mut c_void, buf: *mut u16, size: u32) -> u32;
}
/// LOAD_LIBRARY_SEARCH_SYSTEM32: the DLL and its dependencies from System32
/// only.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

fn unsupported(what: impl std::fmt::Display) -> WinError {
    WinError::new(ERROR_NOT_SUPPORTED, format!("{UNSUPPORTED_BUILD}: {what}"))
}

/// The running Windows build, from the kernel (not the compatibility shim).
fn build() -> Result<(u32, u32, u32), WinError> {
    use ::windows::{
        Wdk::System::SystemServices::RtlGetVersion,
        Win32::System::SystemInformation::OSVERSIONINFOW,
    };
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is sized for the call.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status.0 != 0 {
        return Err(WinError::new(i64::from(status.0), "RtlGetVersion"));
    }
    Ok((info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber))
}

/// How this Windows build was accepted for firewall cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// On [`SUPPORTED_BUILDS`].
    Listed,
    /// Not listed; the read-only self-check passed at load.
    SelfChecked,
}
impl Acceptance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Listed => "listed",
            Self::SelfChecked => "self-checked",
        }
    }
}

/// `Ok(true)`: a listed build. `Ok(false)`: the self-check decides. `Err`:
/// never (not Windows 10/11, or a 32-bit build whose layout is unchecked).
fn check_build((major, minor, build): (u32, u32, u32)) -> Result<bool, WinError> {
    if !cfg!(target_pointer_width = "64") || (major, minor) != (10, 0) {
        return Err(unsupported(format_args!("{major}.{minor}.{build}")));
    }
    Ok(SUPPORTED_BUILDS.contains(&build))
}

/// The read-only self-check of an unlisted build: open the store at 2.27,
/// enumerate every rule, each status OK and the list matching its count
/// (the layout asserts hold at compile time). Nothing is changed.
fn self_check(api: Api) -> Result<usize, WinError> {
    let store = Store::open(api, false)?;
    Ok(checked_rules(&store)?.len())
}

/// FirewallAPI.dll from System32, after the build check. Loaded once per
/// process, never unloaded.
fn load() -> Result<(Api, Acceptance), WinError> {
    let version = build()?;
    let listed = check_build(version)?;
    let name: Vec<u16> = "FirewallAPI.dll\0".encode_utf16().collect();
    // SAFETY: a NUL-terminated name; System32-only search.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(WinError::new(
            i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)),
            "load FirewallAPI.dll",
        ));
    }
    let mut path = vec![0u16; 32768];
    // SAFETY: the buffer holds `path.len()` characters.
    let n = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
    let loaded = String::from_utf16_lossy(&path[..n.min(path.len())]);
    let system = super::super::driver_refs::windows_dir()?.join("System32");
    let expected = system.join("FirewallAPI.dll");
    if n == 0 || !loaded.eq_ignore_ascii_case(&expected.to_string_lossy()) {
        return Err(WinError::invalid(format!(
            "FirewallAPI.dll loaded from an unexpected path: {loaded}"
        )));
    }
    let get = |symbol: &std::ffi::CStr| -> Result<*mut c_void, WinError> {
        // SAFETY: a loaded module and a NUL-terminated export name.
        let p = unsafe { GetProcAddress(module, symbol.as_ptr().cast()) };
        if p.is_null() {
            Err(unsupported(format_args!("missing export {symbol:?}")))
        } else {
            Ok(p)
        }
    };
    // SAFETY: each export has the prototype of its type (learn.microsoft.com
    // firewall API pages, and
    // FWFreeFirewallRulesByHandle as observed in the spike).
    let api = unsafe {
        Api {
            open: std::mem::transmute::<*mut c_void, Open>(get(c"FWOpenPolicyStore")?),
            close: std::mem::transmute::<*mut c_void, Close>(get(c"FWClosePolicyStore")?),
            enumerate: std::mem::transmute::<*mut c_void, Enumerate>(get(c"FWEnumFirewallRules")?),
            delete: std::mem::transmute::<*mut c_void, Delete>(get(c"FWDeleteFirewallRule")?),
            free: std::mem::transmute::<*mut c_void, Free>(get(c"FWFreeFirewallRulesByHandle")?),
        }
    };
    let (major, minor, build) = version;
    let acceptance = if listed {
        Acceptance::Listed
    } else {
        let rules = self_check(api).map_err(|e| {
            unsupported(format_args!(
                "{major}.{minor}.{build} is not listed and its self-check failed: {} (status {})",
                e.message, e.code
            ))
        })?;
        tracing::info!(
            stage = "firewall.self_check",
            build,
            rules,
            "unlisted Windows build passed the firewall self-check"
        );
        Acceptance::SelfChecked
    };
    tracing::info!(
        stage = "firewall.accepted",
        version = %format_args!("{major}.{minor}.{build}"),
        accepted_by = acceptance.as_str(),
        "firewall cleanup accepted for this Windows build"
    );
    Ok((api, acceptance))
}

fn status(code: u32, what: &str) -> Result<(), WinError> {
    if code == 0 {
        Ok(())
    } else {
        Err(WinError::new(i64::from(code), what))
    }
}

/// An open local policy store, closed on drop.
struct Store {
    api: Api,
    handle: *mut c_void,
}
impl Store {
    /// `write`: READ_WRITE (deletion); otherwise READ (listing, self-check).
    fn open(api: Api, write: bool) -> Result<Self, WinError> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: local store (no machine name), out pointer valid.
        status(
            unsafe {
                (api.open)(
                    BINARY_VERSION,
                    std::ptr::null(),
                    FW_STORE_TYPE_LOCAL,
                    if write {
                        FW_POLICY_ACCESS_RIGHT_READ_WRITE
                    } else {
                        FW_POLICY_ACCESS_RIGHT_READ
                    },
                    0,
                    &mut handle,
                )
            },
            "FWOpenPolicyStore",
        )?;
        if handle.is_null() {
            return Err(WinError::invalid("FWOpenPolicyStore returned no store"));
        }
        Ok(Self { api, handle })
    }

    /// Every rule of the store, copied out; the list is freed exactly once
    /// before this returns, whatever happens while reading it.
    fn rules(&self) -> Result<Vec<RuleRow>, WinError> {
        let mut count = 0u32;
        let mut head: *mut Rule = std::ptr::null_mut();
        // SAFETY: an open store and valid out pointers; no resolve flag.
        let rc = unsafe {
            (self.api.enumerate)(
                self.handle,
                FW_RULE_STATUS_CLASS_ALL,
                FW_PROFILE_TYPE_ALL,
                FW_ENUM_RULES_FLAG_NONE,
                &mut count,
                &mut head,
            )
        };
        let list = RuleList { store: self, head };
        status(rc, "FWEnumFirewallRules")?;
        list.read(count)
    }

    fn delete(&self, id: &str) -> Result<(), WinError> {
        let id: Vec<u16> = id.encode_utf16().chain([0]).collect();
        // SAFETY: an open store and a NUL-terminated id.
        status(
            unsafe { (self.api.delete)(self.handle, id.as_ptr()) },
            "FWDeleteFirewallRule",
        )
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: opened by FWOpenPolicyStore, closed once.
        unsafe {
            (self.api.close)(self.handle);
        }
    }
}

/// A rule list from FWEnumFirewallRules, freed by its store on drop.
struct RuleList<'a> {
    store: &'a Store,
    head: *mut Rule,
}
impl RuleList<'_> {
    /// The rules, walking at most `count` links; the list must end exactly
    /// there.
    fn read(&self, count: u32) -> Result<Vec<RuleRow>, WinError> {
        if count > MAX_RULES {
            return Err(unsupported(format_args!("{count} rules")));
        }
        let mut out = Vec::with_capacity(count as usize);
        let mut at = self.head;
        for _ in 0..count {
            if at.is_null() {
                return Err(unsupported("the rule list is shorter than its count"));
            }
            // SAFETY: a non-null link of the list the store returned, valid
            // until the list is freed.
            let rule = unsafe { &*at };
            out.push(RuleRow::read(rule)?);
            at = rule.next;
        }
        if !at.is_null() {
            return Err(unsupported("the rule list is longer than its count"));
        }
        Ok(out)
    }
}
impl Drop for RuleList<'_> {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: the head of a list this store returned, freed once.
            unsafe {
                (self.store.api.free)(self.store.handle, self.head);
            }
        }
    }
}

/// The text at `p`, at most [`MAX_TEXT`] units; `None` for null.
///
/// SAFETY: `p` is null or points at a NUL-terminated string that stays
/// valid for the call.
unsafe fn text(p: *const u16) -> Result<Option<String>, WinError> {
    if p.is_null() {
        return Ok(None);
    }
    let mut len = 0;
    // SAFETY: per the contract, every unit up to the terminator is readable.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
        if len > MAX_TEXT {
            return Err(unsupported("a rule string exceeds its bound"));
        }
    }
    // SAFETY: `len` units were just read.
    let units = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16(units)
        .map(Some)
        .map_err(|_| WinError::invalid("invalid UTF-16 in a firewall rule"))
}

/// What is read from one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleRow {
    id: String,
    name: Option<String>,
    group: Option<String>,
    application: Option<String>,
    direction: i32,
    status: u32,
}
impl RuleRow {
    fn read(rule: &Rule) -> Result<Self, WinError> {
        // SAFETY: the string fields of a rule in a live list.
        unsafe {
            Ok(Self {
                id: text(rule.rule_id)?.ok_or_else(|| unsupported("a rule without an id"))?,
                name: text(rule.name)?,
                group: text(rule.embedded_context)?,
                application: text(rule.local_application)?,
                direction: rule.direction,
                status: rule.status,
            })
        }
    }
    fn direction(&self) -> Result<&'static str, WinError> {
        match self.direction {
            FW_DIR_IN => Ok("Inbound"),
            FW_DIR_OUT => Ok("Outbound"),
            d => Err(unsupported(format_args!("rule direction {d}"))),
        }
    }
    /// The application condition as Get-NetFirewallApplicationFilter shows
    /// it: the stored path, or "Any".
    fn program(&self) -> &str {
        self.application.as_deref().unwrap_or("Any")
    }
}

/// Rules of the store; fails closed if any rule's status is not OK.
fn checked_rules(store: &Store) -> Result<Vec<RuleRow>, WinError> {
    let rules = store.rules()?;
    if let Some(bad) = rules.iter().find(|r| r.status != FW_RULE_STATUS_OK) {
        return Err(unsupported(format_args!(
            "rule {} has status {:#x}",
            bad.id, bad.status
        )));
    }
    Ok(rules)
}

// ---- The module-owned thread ----

type Job = Box<dyn FnOnce() + Send>;
struct Worker {
    queue: Mutex<Option<mpsc::Sender<Job>>>,
    busy: Mutex<Busy>,
    idle: Condvar,
}
#[derive(Default)]
struct Busy {
    in_flight: bool,
    closed: bool,
}
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
fn worker() -> &'static Worker {
    static WORKER: OnceLock<Worker> = OnceLock::new();
    WORKER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        let spawned = std::thread::Builder::new()
            .name("etd-firewall".into())
            .spawn(move || {
                for job in rx {
                    let w = worker();
                    {
                        let mut busy = lock(&w.busy);
                        if busy.closed {
                            continue;
                        }
                        busy.in_flight = true;
                    }
                    job();
                    lock(&w.busy).in_flight = false;
                    w.idle.notify_all();
                }
            });
        Worker {
            queue: Mutex::new(spawned.ok().map(|_| tx)),
            busy: Mutex::new(Busy::default()),
            idle: Condvar::new(),
        }
    })
}

/// FirewallAPI, loaded on the firewall thread the first time.
/// FirewallAPI and how the build was accepted, decided once per process
/// (host start) before any firewall call; a failed load stays failed.
static LOADED: OnceLock<Result<(Api, Acceptance), WinError>> = OnceLock::new();
fn loaded() -> Result<(Api, Acceptance), WinError> {
    LOADED.get_or_init(|| {
        load().inspect_err(|e| {
            tracing::warn!(stage = "firewall.unsupported", error = %e, "firewall cleanup is not available");
        })
    })
    .clone()
}
fn api() -> Result<Api, WinError> {
    loaded().map(|(api, _)| api)
}

/// Run `work` on the firewall thread, waiting at most [`CALL_BOUND`].
fn call<R: Send + 'static>(
    work: impl FnOnce(Api) -> Result<R, WinError> + Send + 'static,
) -> Result<R, WinError> {
    let w = worker();
    let (tx, rx) = mpsc::sync_channel(1);
    {
        let queue = lock(&w.queue);
        let Some(queue) = queue.as_ref() else {
            return Err(WinError::invalid("the firewall thread is shut down"));
        };
        queue
            .send(Box::new(move || {
                let _ = tx.send(api().and_then(work));
            }))
            .map_err(|_| WinError::invalid("the firewall thread is gone"))?;
    }
    match rx.recv_timeout(CALL_BOUND) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(WinError::invalid(format!(
            "a firewall call exceeded {}s; its outcome is indeterminate",
            CALL_BOUND.as_secs()
        ))),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(WinError::invalid(
            "the firewall call was not run (shutting down)",
        )),
    }
}

/// Host shutdown: admit no further call, drop queued ones, and wait up to
/// [`SHUTDOWN_WAIT`] for the call in flight. `Err`: one is still in flight;
/// the host then keeps its lock until the process ends.
pub(crate) fn shutdown() -> Result<(), WinError> {
    let w = worker();
    lock(&w.queue).take();
    let deadline = Instant::now() + SHUTDOWN_WAIT;
    let mut busy = lock(&w.busy);
    busy.closed = true;
    while busy.in_flight {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(WinError::invalid(
                "a firewall call is still in flight at shutdown",
            ));
        }
        busy = w
            .idle
            .wait_timeout(busy, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
    Ok(())
}

// ---- Operations ----

/// The raw HKLM FirewallRules value of `id`, if present.
fn stored(key: Option<&Key>, id: &str) -> Result<Option<RawValue>, WinError> {
    key.map(|k| k.read(id)).transpose().map(Option::flatten)
}

fn stored_text(value: &RawValue) -> Result<String, WinError> {
    if value.ty != REG_SZ {
        return Err(WinError::invalid("unexpected firewall rule value type"));
    }
    let mut buf = utf16(value)?;
    if buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf16(&buf).map_err(|_| WinError::invalid("invalid firewall rule value"))
}

/// Upstream program rules: `EasyTier <absolute path> (Inbound|Outbound)`.
fn program_rule_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("EasyTier ") else {
        return false;
    };
    let Some(path) = rest
        .strip_suffix(" (Inbound)")
        .or_else(|| rest.strip_suffix(" (Outbound)"))
    else {
        return false;
    };
    let b = path.as_bytes();
    let drive = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let unc = b.len() > 2 && b.starts_with(br"\\");
    drive || unc
}

fn same(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// One row per persistent rule (optionally only those named `name`):
/// `{name, group, id, program, direction, description}`, the description
/// being the rule's raw registry string.
pub(super) fn rows(name: Option<String>, sweep: Sweep) -> Result<Vec<Value>, WinError> {
    call(move |api| {
        let store = Store::open(api, false)?;
        let rules = checked_rules(&store)?;
        drop(store);
        let key = Key::open(HKEY_LOCAL_MACHINE, RULES_KEY, KEY_READ)?;
        let mut out = Vec::new();
        for rule in rules {
            let row = (|| -> Result<Option<Value>, WinError> {
                let display = rule.name.clone().unwrap_or_default();
                if name.as_deref().is_some_and(|n| !same(n, &display)) {
                    return Ok(None);
                }
                let program = program_rule_name(&display).then(|| rule.program().to_owned());
                let description = match stored(key.as_ref(), &rule.id)? {
                    Some(v) => stored_text(&v)?,
                    None => json!({
                        "DisplayName": display,
                        "Group": rule.group,
                        "Direction": rule.direction()?,
                    })
                    .to_string(),
                };
                Ok(Some(json!({
                    "name": display,
                    "group": rule.group,
                    "id": rule.id,
                    "program": program,
                    "direction": rule.direction()?,
                    "description": description,
                })))
            })();
            match row {
                Ok(Some(v)) => out.push(v),
                Ok(None) => {}
                Err(e) if sweep.0 => out.push(json!({"warning": e.message, "object": rule.id})),
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    })
}

/// What a deletion must find before it deletes.
#[derive(Debug, Clone)]
pub(super) struct Credential {
    pub id: String,
    pub name: String,
    pub group: Option<String>,
    /// Program rules: the application path and direction.
    pub program: Option<(String, String)>,
}

/// Delete the one rule with `c.id` after checking `c` on it, then verify it
/// is gone from a fresh enumeration and from the registry.
pub(super) fn delete(c: Credential) -> Result<&'static str, WinError> {
    call(move |api| delete_with(api, &c, present_in_registry))
}

fn present_in_registry(id: &str) -> Result<bool, WinError> {
    let key = Key::open(HKEY_LOCAL_MACHINE, RULES_KEY, KEY_READ)?;
    Ok(stored(key.as_ref(), id)?.is_some())
}

fn delete_with(
    api: Api,
    c: &Credential,
    registry: impl Fn(&str) -> Result<bool, WinError>,
) -> Result<&'static str, WinError> {
    let store = Store::open(api, true)?;
    let before = checked_rules(&store)?;
    let matching: Vec<&RuleRow> = before
        .iter()
        .filter(|r| {
            same(&r.id, &c.id)
                && same(r.name.as_deref().unwrap_or(""), &c.name)
                && c.group
                    .as_deref()
                    .filter(|g| !g.is_empty())
                    .is_none_or(|g| same(r.group.as_deref().unwrap_or(""), g))
        })
        .collect();
    let [rule] = matching.as_slice() else {
        return Err(WinError::invalid(
            "Credential changed before firewall deletion",
        ));
    };
    if let Some((program, direction)) = &c.program {
        let actual = rule.program().replace(r"\\?\", "");
        if !same(&actual, program) || !same(rule.direction()?, direction) {
            return Err(WinError::invalid("Program firewall credential changed"));
        }
    }
    let id = rule.id.clone();
    store.delete(&id)?;
    let after = checked_rules(&store)?;
    if after.iter().any(|r| same(&r.id, &id)) || registry(&id)? {
        return Err(WinError::invalid(
            "firewall rule still present after deletion",
        ));
    }
    Ok("removed")
}

/// The build check alone, for doctor and the gate.
/// Queue [`loaded`] on the firewall thread without waiting for it.
pub(super) fn warm() {
    if let Some(queue) = lock(&worker().queue).as_ref() {
        let _ = queue.send(Box::new(|| {
            let _ = loaded();
        }));
    }
}

/// Whether firewall cleanup is available here and how the build was
/// accepted, for doctor: loads FirewallAPI (and self-checks) on the firewall
/// thread if no call has yet.
pub(super) fn supported() -> Result<Acceptance, WinError> {
    // Decided once: answer from the cache without queueing behind a call.
    if let Some(decided) = LOADED.get() {
        return decided.clone().map(|(_, acceptance)| acceptance);
    }
    call(|_| loaded().map(|(_, acceptance)| acceptance))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static FREED: Cell<u32> = const { Cell::new(0) };
        static CLOSED: Cell<u32> = const { Cell::new(0) };
        static DELETED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static RULES: RefCell<Vec<(String, String, u32)>> = const { RefCell::new(Vec::new()) };
        /// What the fake enumeration reports as the count, relative to the
        /// list it builds.
        static SKEW: Cell<i64> = const { Cell::new(0) };
        static HEADS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static ACCESS: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
    }

    fn wide(s: &str) -> *const u16 {
        Box::leak(
            s.encode_utf16()
                .chain([0])
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
        .as_ptr()
    }
    fn blank() -> Rule {
        // SAFETY: an all-zero Rule is valid (null pointers, zero numbers).
        unsafe { std::mem::zeroed() }
    }
    unsafe extern "system" fn open(
        version: u16,
        machine: *const u16,
        store: i32,
        access: i32,
        _: u32,
        out: *mut *mut c_void,
    ) -> u32 {
        assert_eq!(version, BINARY_VERSION);
        assert!(machine.is_null());
        assert_eq!(store, 2);
        ACCESS.with_borrow_mut(|a| a.push(access));
        // SAFETY: the caller's out pointer.
        unsafe { *out = std::ptr::dangling_mut::<c_void>() };
        0
    }
    unsafe extern "system" fn close(_: *mut c_void) -> u32 {
        CLOSED.set(CLOSED.get() + 1);
        0
    }
    unsafe extern "system" fn enumerate(
        _: *mut c_void,
        status: u32,
        profiles: u32,
        flags: u16,
        count: *mut u32,
        head: *mut *mut Rule,
    ) -> u32 {
        assert_eq!((status, profiles, flags), (0xFFFF_0000, 0x7FFF_FFFF, 0));
        let rules = RULES.with_borrow(Clone::clone);
        let mut next: *mut Rule = std::ptr::null_mut();
        for (id, name, st) in rules.iter().rev() {
            let mut r = blank();
            r.next = next;
            r.rule_id = wide(id);
            r.name = wide(name);
            r.direction = 1;
            r.status = *st;
            r.local_application = wide(r"C:\x\core.exe");
            next = Box::into_raw(Box::new(r));
        }
        // SAFETY: the caller's out pointers.
        unsafe {
            *count = (rules.len() as i64 + SKEW.get()) as u32;
            *head = next;
        }
        HEADS.with_borrow_mut(|h| h.push(next as usize));
        0
    }
    unsafe extern "system" fn delete(_: *mut c_void, id: *const u16) -> u32 {
        // SAFETY: the caller's NUL-terminated id.
        let id = unsafe { text(id) }.unwrap().unwrap();
        RULES.with_borrow_mut(|r| r.retain(|(i, _, _)| *i != id));
        DELETED.with_borrow_mut(|d| d.push(id));
        0
    }
    unsafe extern "system" fn free(_: *mut c_void, head: *mut Rule) -> u32 {
        assert!(HEADS.with_borrow(|h| h.contains(&(head as usize))));
        FREED.set(FREED.get() + 1);
        0
    }
    fn fake(rules: &[(&str, &str, u32)], skew: i64) -> Api {
        FREED.set(0);
        CLOSED.set(0);
        SKEW.set(skew);
        DELETED.with_borrow_mut(Vec::clear);
        HEADS.with_borrow_mut(Vec::clear);
        ACCESS.with_borrow_mut(Vec::clear);
        RULES.set(
            rules
                .iter()
                .map(|(i, n, s)| ((*i).to_owned(), (*n).to_owned(), *s))
                .collect(),
        );
        Api {
            open,
            close,
            enumerate,
            delete,
            free,
        }
    }
    fn credential(id: &str) -> Credential {
        Credential {
            id: id.into(),
            name: "EasyTier rule".into(),
            group: None,
            program: Some((r"c:\x\core.exe".into(), "inbound".into())),
        }
    }

    #[test]
    fn a_rule_is_deleted_by_id_and_verified() {
        let api = fake(
            &[
                ("a'q\\b\"c", "EasyTier rule", FW_RULE_STATUS_OK),
                ("b", "EasyTier rule", FW_RULE_STATUS_OK),
            ],
            0,
        );
        assert_eq!(
            delete_with(api, &credential("a'q\\b\"c"), |_| Ok(false)).unwrap(),
            "removed"
        );
        assert_eq!(DELETED.with_borrow(Clone::clone), ["a'q\\b\"c"]);
        // Deletion opens the store for writing.
        assert_eq!(ACCESS.with_borrow(Clone::clone), [2]);
        // Two enumerations, each freed once; the store closed once.
        assert_eq!((FREED.get(), CLOSED.get()), (2, 1));
    }

    #[test]
    fn errors_after_enumeration_free_the_list_exactly_once() {
        for skew in [1, -1] {
            let api = fake(&[("a", "EasyTier rule", FW_RULE_STATUS_OK)], skew);
            assert!(delete_with(api, &credential("a"), |_| Ok(false)).is_err());
            assert_eq!((FREED.get(), CLOSED.get()), (1, 1), "skew {skew}");
            assert!(DELETED.with_borrow(Vec::is_empty));
        }
        let api = fake(&[("a", "EasyTier rule", 0x0002_0000)], 0);
        assert!(delete_with(api, &credential("a"), |_| Ok(false)).is_err());
        assert_eq!((FREED.get(), CLOSED.get()), (1, 1));
        let api = fake(&[("a", "EasyTier other", FW_RULE_STATUS_OK)], 0);
        assert!(delete_with(api, &credential("a"), |_| Ok(false)).is_err());
        assert_eq!((FREED.get(), CLOSED.get()), (1, 1));
        assert!(DELETED.with_borrow(Vec::is_empty));
    }

    #[test]
    fn a_rule_left_in_the_registry_is_not_removed() {
        let api = fake(&[("a", "EasyTier rule", FW_RULE_STATUS_OK)], 0);
        assert!(delete_with(api, &credential("a"), |_| Ok(true)).is_err());
        // The second enumeration is empty: a null list, nothing to free.
        assert_eq!((FREED.get(), CLOSED.get()), (1, 1));
    }

    #[test]
    fn a_changed_program_is_never_deleted() {
        let api = fake(&[("a", "EasyTier rule", FW_RULE_STATUS_OK)], 0);
        let mut c = credential("a");
        c.program = Some((r"c:\y\core.exe".into(), "inbound".into()));
        assert!(delete_with(api, &c, |_| Ok(false)).is_err());
        assert!(DELETED.with_borrow(Vec::is_empty));
    }

    #[test]
    fn listed_builds_skip_the_self_check() {
        for build in [20348, 26100, 26200] {
            assert!(check_build((10, 0, build)).unwrap());
        }
        assert!(!check_build((10, 0, 22631)).unwrap());
        assert!(!check_build((10, 0, 19045)).unwrap());
        let e = check_build((6, 3, 26100)).unwrap_err();
        assert!(e.message.starts_with(UNSUPPORTED_BUILD), "{}", e.message);
    }

    #[test]
    fn the_self_check_is_read_only_and_fails_closed() {
        let api = fake(
            &[("a", "x", FW_RULE_STATUS_OK), ("b", "y", FW_RULE_STATUS_OK)],
            0,
        );
        assert_eq!(self_check(api).unwrap(), 2);
        // Read-only: an unelevated doctor can run it.
        assert_eq!(ACCESS.with_borrow(Clone::clone), [1]);
        assert!(DELETED.with_borrow(Vec::is_empty));
        assert_eq!((FREED.get(), CLOSED.get()), (1, 1));
        let api = fake(&[("a", "x", 0x0002_0000)], 0);
        assert!(self_check(api).is_err());
        let api = fake(&[("a", "x", FW_RULE_STATUS_OK)], 1);
        assert!(self_check(api).is_err());
        assert_eq!((FREED.get(), CLOSED.get()), (1, 1));
    }

    #[test]
    fn program_rule_names() {
        assert!(program_rule_name(r"EasyTier C:\a\b.exe (Inbound)"));
        assert!(program_rule_name(r"EasyTier \\srv\b.exe (Outbound)"));
        assert!(!program_rule_name(r"EasyTier relative.exe (Inbound)"));
        assert!(!program_rule_name(r"EasyTier C:\a\b.exe (Both)"));
    }
}
