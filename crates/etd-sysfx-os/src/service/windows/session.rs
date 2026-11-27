//! Elevated session host (doc#13): the protected per-user tree under
//! `%ProgramData%\EasyTierDesk.session`, the host token precondition, the
//! service registration query, DLL search hardening, the UI-image check for
//! lease holders and the session-end window.
use super::*;
use ::windows::{
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        Security::{
            GetSecurityDescriptorControl, GetSidSubAuthority, GetSidSubAuthorityCount,
            SE_DACL_PROTECTED, TOKEN_MANDATORY_LABEL, TokenIntegrityLevel, TokenSessionId,
        },
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        System::{
            LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories},
            Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy},
            Threading::{
                OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
        },
        UI::WindowsAndMessaging::{
            CallWindowProcW, CreateWindowExW, DestroyWindow, DispatchMessageW, GWLP_WNDPROC,
            GetMessageW, MSG, PostMessageW, PostQuitMessage, SetWindowLongPtrW, TranslateMessage,
            WINDOW_EX_STYLE, WM_CLOSE, WM_DESTROY, WM_ENDSESSION, WM_QUERYENDSESSION, WNDPROC,
            WS_OVERLAPPED,
        },
    },
    core::w,
};
use std::{
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    sync::{Arc, Condvar, Mutex, OnceLock},
};

const SESSION_DIR: &str = "EasyTierDesk.session";
const SYSTEM: &str = "S-1-5-18";
/// SECURITY_MANDATORY_HIGH_RID.
const HIGH_INTEGRITY: u32 = 0x3000;

fn not_conforming(path: &Path, why: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        NotConforming {
            path: path.to_owned(),
            reason: why.to_string(),
        },
    )
}

/// A numeric SID string (`S-1-<authority>-<sub>...`), nothing else.
fn valid_sid(sid: &str) -> bool {
    let mut parts = sid.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return false;
    }
    let number = |text: &str, max: u64| {
        text.parse::<u64>()
            .is_ok_and(|value| value <= max && value.to_string() == text)
    };
    let Some(authority) = parts.next() else {
        return false;
    };
    let subauthorities: Vec<_> = parts.collect();
    number(authority, (1 << 48) - 1)
        && !subauthorities.is_empty()
        && subauthorities.len() <= 15
        && subauthorities
            .iter()
            .all(|value| number(value, u32::MAX.into()))
}

pub(in crate::service) fn session_root() -> io::Result<PathBuf> {
    absolute(program_data()?.join(SESSION_DIR))
}

pub(in crate::service) fn session_layout(sid: &str) -> io::Result<HostLayout> {
    if !valid_sid(sid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a numeric Windows SID",
        ));
    }
    let root = session_root()?.join(sid);
    Ok(HostLayout {
        state: root.join("state"),
        run: root.join("run"),
        cores: root.join("cores"),
        profile: Some(root.join("profile")),
        executable: current_exe()?,
        socket_dir: None,
        // The service's maintenance directory: the same maintenance and
        // host locks serialize every privileged host and command.
        maintenance: program_data()?.join("EasyTierDesk.maintenance"),
        user_host: false,
    })
}

/// `<SID>` directory of a session layout.
fn user_root(layout: &HostLayout) -> io::Result<&Path> {
    layout
        .profile
        .as_deref()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a session layout"))
}

/// Create a missing directory with the protected descriptor, or validate an
/// existing one. Never repaired or adopted: a non-conforming one is refused.
fn ensure_protected(path: &Path) -> io::Result<()> {
    let exists = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if !exists {
        match create_protected(path, false) {
            Ok(()) => return Ok(()),
            // Created concurrently: validate it like any existing one.
            Err(error) if error.raw_os_error() == Some(183) => (),
            Err(error) => return Err(not_conforming(path, error)),
        }
    }
    validate_protected(path)?;
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(not_conforming(path, "not a directory"));
    }
    Ok(())
}

/// The per-user tree has every directory, `profile` included: the system
/// workers redirect their profile variables there only if it exists (ES2),
/// so a session host never runs without it.
fn require_dirs(layout: &HostLayout) -> io::Result<()> {
    let profile = layout.profile.as_deref().ok_or_else(denied)?;
    for dir in [&layout.state, &layout.run, &layout.cores, profile] {
        let present = fs::symlink_metadata(dir).is_ok_and(|metadata| metadata.is_dir());
        if !present {
            return Err(not_conforming(dir, "missing, or not a directory"));
        }
        protected_dacl(dir)?;
    }
    Ok(())
}

/// The protected descriptor on a directory the tree is rooted at: owner
/// SYSTEM or Administrators, only SYSTEM and Administrators granted, and
/// the whole DACL protected from inheritance (as `create_protected` sets
/// it), so no change to a parent can reach into the tree.
fn validate_protected(path: &Path) -> io::Result<()> {
    validate_acl(path, false, true).map_err(|error| not_conforming(path, error))?;
    protected_dacl(path)
}

fn protected_dacl(path: &Path) -> io::Result<()> {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: the descriptor is allocated by the call and released by
    // `Allocation`; the outputs are owned locals.
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(|error| not_conforming(path, error))?;
        let _allocation = Allocation(HLOCAL(sd.0));
        GetSecurityDescriptorControl(sd, &mut control, &mut revision).map_err(other)?;
    }
    if control & SE_DACL_PROTECTED.0 == 0 {
        return Err(not_conforming(
            path,
            "access control inherited, not protected",
        ));
    }
    Ok(())
}

/// Every entry below `path`: the protected access control, no reparse
/// point (checked by `validate_acl`), no file with a second hard link.
fn verify_session_tree(path: &Path) -> io::Result<()> {
    validate_acl(path, false, false).map_err(|error| not_conforming(path, error))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_file() && links(path)? != 1 {
        return Err(not_conforming(path, "file has more than one hard link"));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            verify_session_tree(&entry?.path())?;
        }
    }
    Ok(())
}

fn links(path: &Path) -> io::Result<u32> {
    // FILE_READ_ATTRIBUTES; FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    let file = fs::OpenOptions::new()
        .access_mode(0x80)
        .share_mode(0x7)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: a live file handle and an owned output structure.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(other)?;
    Ok(info.nNumberOfLinks)
}

pub(in crate::service) fn prepare_session(layout: &HostLayout) -> io::Result<()> {
    let root = session_root()?;
    let user = user_root(layout)?;
    if user.parent() != Some(root.as_path()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a session layout",
        ));
    }
    ensure_protected(&root)?;
    ensure_protected(user)?;
    for dir in [&layout.state, &layout.run, &layout.cores] {
        ensure_protected(dir)?;
    }
    ensure_protected(layout.profile.as_deref().ok_or_else(denied)?)?;
    verify_session_tree(user)?;
    require_dirs(layout)
}

pub(in crate::service) fn validate_session(layout: &HostLayout) -> io::Result<()> {
    let root = session_root()?;
    validate_protected(&root)?;
    let user = user_root(layout)?;
    validate_protected(user)?;
    verify_session_tree(user)?;
    require_dirs(layout)
}

pub(in crate::service) fn session_layouts() -> io::Result<Vec<HostLayout>> {
    let root = session_root()?;
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(error) => return Err(error),
        Ok(_) => (),
    }
    validate_protected(&root)?;
    let mut layouts = Vec::new();
    for entry in fs::read_dir(&root)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str());
        let Some(sid) = name.filter(|name| valid_sid(name)) else {
            return Err(not_conforming(&path, "not a per-user session directory"));
        };
        let layout = session_layout(sid)?;
        validate_session(&layout)?;
        layouts.push(layout);
    }
    layouts.sort_by(|a, b| a.state.cmp(&b.state));
    Ok(layouts)
}

pub(in crate::service) fn remove_session_roots() -> io::Result<()> {
    let root = session_root()?;
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => (),
    }
    validate_protected(&root)?;
    verify_session_tree(&root)?;
    fs::remove_dir_all(root)
}

pub(in crate::service) fn service_registered() -> io::Result<bool> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(other)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(_) => Ok(true),
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            Ok(false)
        }
        Err(error) => Err(other(error)),
    }
}

fn token_dword(
    token: HANDLE,
    class: ::windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> io::Result<u32> {
    let mut value = 0u32;
    let mut size = 0;
    // SAFETY: a live token handle and a DWORD-sized output buffer.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some((&raw mut value).cast()),
            size_of::<u32>() as u32,
            &mut size,
        )
    }
    .map_err(other)?;
    Ok(value)
}

fn integrity(token: HANDLE) -> io::Result<u32> {
    let mut size = 0;
    // SAFETY: size query, then a pointer-aligned buffer kept alive while the
    // label SID inside it is read.
    unsafe {
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut size);
        let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(data.as_mut_ptr().cast()),
            size,
            &mut size,
        )
        .map_err(other)?;
        if (size as usize) < size_of::<TOKEN_MANDATORY_LABEL>() {
            return Err(denied());
        }
        let sid = (*data.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return Err(denied());
        }
        Ok(*GetSidSubAuthority(sid, u32::from(count) - 1))
    }
}

/// The elevated session host's own token facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub sid: String,
    pub session: u32,
}

/// Only an elevated administrator may run the elevated session host:
/// `TokenElevation` set, integrity at least High (a restricted Medium copy
/// keeps `TokenElevation`, msg#1651), and not SYSTEM (that is the service).
pub fn elevated_session_token() -> io::Result<SessionToken> {
    let mut token = HANDLE::default();
    // SAFETY: query our own process token; the handle is owned and closed.
    let token = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(other)?;
        OwnedHandle::from_raw_handle(token.0)
    };
    let handle = HANDLE(token.as_raw_handle());
    let sid = current_sid()?;
    if !eligible(handle, &sid)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the elevated session host requires an elevated administrator (not SYSTEM)",
        ));
    }
    Ok(SessionToken {
        sid,
        session: token_dword(handle, TokenSessionId)?,
    })
}

fn eligible(token: HANDLE, sid: &str) -> io::Result<bool> {
    Ok(token_dword(token, TokenElevation)? != 0
        && integrity(token)? >= HIGH_INTEGRITY
        && sid != SYSTEM)
}

/// Load DLLs only from System32 unless a call names another directory.
pub fn harden_dll_search() -> io::Result<()> {
    // SAFETY: process-wide loader setting, no pointers involved.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) }.map_err(other)
}

/// A handle on a client process, opened at accept and kept for the life of
/// its connection so its pid cannot be reused meanwhile.
pub struct ProcessPin(OwnedHandle);

impl ProcessPin {
    pub fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: the returned handle is owned and closed on drop.
        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(other)?;
            Ok(Self(OwnedHandle::from_raw_handle(handle.0)))
        }
    }

    /// The pinned process's image. Not an authentication: any program the
    /// same user places at a path has that path (doc#13, issue #2).
    pub fn image(&self) -> io::Result<PathBuf> {
        let mut path = vec![0u16; 32768];
        let mut len = path.len() as u32;
        // SAFETY: a live process handle and a buffer of `len` UTF-16 units.
        unsafe {
            QueryFullProcessImageNameW(
                HANDLE(self.0.as_raw_handle()),
                PROCESS_NAME_WIN32,
                ::windows::core::PWSTR(path.as_mut_ptr()),
                &mut len,
            )
        }
        .map_err(other)?;
        Ok(PathBuf::from(OsString::from_wide(&path[..len as usize])))
    }
}

struct EndState {
    on_end: Box<dyn Fn() + Send + Sync>,
    budget: Duration,
    done: Mutex<bool>,
    finished: Condvar,
}

static END_STATE: OnceLock<Arc<EndState>> = OnceLock::new();
/// The STATIC class's own window procedure, replaced by [`window_proc`].
static ORIGINAL_PROC: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

/// The hidden top-level window that hears the session end (logoff,
/// shutdown) and holds it, within a budget, while the host winds down.
pub struct SessionEnd {
    window: isize,
    state: Arc<EndState>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SessionEnd {
    /// Start watching. `on_end` runs once the session starts ending; the
    /// end is held until [`SessionEnd::finished`] or `budget`. One watcher
    /// per process.
    pub fn watch(on_end: Box<dyn Fn() + Send + Sync>, budget: Duration) -> io::Result<Self> {
        let state = Arc::new(EndState {
            on_end,
            budget,
            done: Mutex::new(false),
            finished: Condvar::new(),
        });
        END_STATE
            .set(state.clone())
            .map_err(|_| io::Error::other("a session-end watcher already exists"))?;
        let (created, window) = std::sync::mpsc::channel();
        let thread = thread::Builder::new()
            .name("session-end".into())
            .spawn(move || pump(created))
            .map_err(other)?;
        let window = window
            .recv()
            .map_err(|_| io::Error::other("session-end window thread ended"))??;
        Ok(Self {
            window,
            state,
            thread: Some(thread),
        })
    }

    /// The host is done: release a held session end and close the window.
    pub fn finished(&mut self) {
        *self
            .state
            .done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.state.finished.notify_all();
        // SAFETY: posting to our own window; a destroyed one fails harmlessly.
        let _ = unsafe {
            PostMessageW(
                Some(HWND(self.window as *mut _)),
                WM_CLOSE,
                WPARAM(0),
                LPARAM(0),
            )
        };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SessionEnd {
    fn drop(&mut self) {
        self.finished();
    }
}

fn pump(created: std::sync::mpsc::Sender<io::Result<isize>>) {
    // SAFETY: the window is created, subclassed and pumped on this thread;
    // the message loop runs until WM_DESTROY posts the quit message.
    unsafe {
        // Hidden (never shown) but top-level: message-only windows do not
        // receive WM_QUERYENDSESSION. A system STATIC window, subclassed,
        // needs no class registration.
        let window = match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("STATIC"),
            w!("EasyTier Desktop host"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
        ) {
            Ok(window) => window,
            Err(error) => {
                let _ = created.send(Err(other(error)));
                return;
            }
        };
        let replacement: WNDPROC = Some(window_proc);
        let replacement = replacement.map_or(0, |procedure| procedure as usize as isize);
        let original = SetWindowLongPtrW(window, GWLP_WNDPROC, replacement);
        if original == 0 {
            let error = io::Error::last_os_error();
            let _ = DestroyWindow(window);
            let _ = created.send(Err(error));
            return;
        }
        ORIGINAL_PROC.store(original, std::sync::atomic::Ordering::SeqCst);
        let _ = created.send(Ok(window.0 as isize));
        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: the value stored is the STATIC class's window procedure
    // returned by SetWindowLongPtrW before this procedure was installed.
    let original: WNDPROC = unsafe {
        std::mem::transmute::<isize, WNDPROC>(
            ORIGINAL_PROC.load(std::sync::atomic::Ordering::SeqCst),
        )
    };
    let Some(state) = END_STATE.get() else {
        // SAFETY: default handling of a message for our own window.
        return unsafe { CallWindowProcW(original, window, message, wparam, lparam) };
    };
    match message {
        WM_QUERYENDSESSION => {
            // SAFETY: our own window; the reason string is static.
            let _ = unsafe {
                ShutdownBlockReasonCreate(window, w!("Removing EasyTier network changes"))
            };
            (state.on_end)();
            LRESULT(1)
        }
        WM_ENDSESSION => {
            if wparam.0 != 0 {
                let done = state
                    .done
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = state
                    .finished
                    .wait_timeout_while(done, state.budget, |done| !*done);
            }
            // SAFETY: our own window.
            let _ = unsafe { ShutdownBlockReasonDestroy(window) };
            LRESULT(0)
        }
        WM_CLOSE => {
            // SAFETY: our own window, destroyed on its own thread.
            let _ = unsafe { DestroyWindow(window) };
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: ends this thread's message loop.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        // SAFETY: default handling of a message for our own window.
        _ => unsafe { CallWindowProcW(original, window, message, wparam, lparam) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A restricted Medium copy of an elevated administrator token (what a
    /// non-elevated UI of the same admin looks like on the runner, where
    /// UAC is off) keeps TokenElevation but is not eligible; the token
    /// itself is. Needs the elevated runner for the positive half.
    #[test]
    #[ignore = "privileged: needs an elevated administrator token"]
    fn a_restricted_medium_copy_of_the_admin_token_is_refused() {
        use ::windows::Win32::Security::{
            CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES,
            SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
            WinBuiltinAdministratorsSid, WinMediumLabelSid,
        };
        let sid = current_sid().unwrap();
        let mut own = HANDLE::default();
        // SAFETY: test-only token manipulation on handles owned here.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                &mut own,
            )
            .unwrap();
            let own = OwnedHandle::from_raw_handle(own.0);
            let own = HANDLE(own.as_raw_handle());
            assert!(
                eligible(own, &sid).unwrap(),
                "the runner token is an elevated admin"
            );
            let mut admins = [0u8; 68];
            let mut size = admins.len() as u32;
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                None,
                Some(PSID(admins.as_mut_ptr().cast())),
                &mut size,
            )
            .unwrap();
            let deny = [SID_AND_ATTRIBUTES {
                Sid: PSID(admins.as_mut_ptr().cast()),
                Attributes: 0,
            }];
            let mut restricted = HANDLE::default();
            CreateRestrictedToken(
                own,
                DISABLE_MAX_PRIVILEGE,
                Some(&deny),
                None,
                None,
                &mut restricted,
            )
            .unwrap();
            let restricted = OwnedHandle::from_raw_handle(restricted.0);
            let restricted = HANDLE(restricted.as_raw_handle());
            let mut medium = [0u8; 68];
            let mut size = medium.len() as u32;
            CreateWellKnownSid(
                WinMediumLabelSid,
                None,
                Some(PSID(medium.as_mut_ptr().cast())),
                &mut size,
            )
            .unwrap();
            let label = TOKEN_MANDATORY_LABEL {
                Label: SID_AND_ATTRIBUTES {
                    Sid: PSID(medium.as_mut_ptr().cast()),
                    Attributes: ::windows::Win32::System::SystemServices::SE_GROUP_INTEGRITY as u32,
                },
            };
            SetTokenInformation(
                restricted,
                TokenIntegrityLevel,
                (&raw const label).cast(),
                (size_of::<TOKEN_MANDATORY_LABEL>() + size as usize) as u32,
            )
            .unwrap();
            assert_ne!(token_dword(restricted, TokenElevation).unwrap(), 0);
            assert!(!eligible(restricted, &sid).unwrap());
        }
    }

    #[test]
    fn only_numeric_sids_name_a_session_root() {
        assert!(valid_sid("S-1-5-21-1-2-3-1001"));
        assert!(valid_sid("S-1-5-18"));
        for bad in [
            "",
            "S-1-5",
            "S-1-5-21-..",
            "S-1-5-21-1-2-3-1001\\..",
            "s-1-5-18",
            "S-1-5-018",
            "S-1-5-4294967296",
            "S-1-5-21-a",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
        ] {
            assert!(!valid_sid(bad), "{bad}");
        }
    }

    #[test]
    fn the_session_layout_lives_under_one_protected_root() {
        let layout = session_layout("S-1-5-21-1-2-3-1001").unwrap();
        let root = session_root().unwrap().join("S-1-5-21-1-2-3-1001");
        assert_eq!(layout.state, root.join("state"));
        assert_eq!(layout.run, root.join("run"));
        assert_eq!(layout.cores, root.join("cores"));
        assert_eq!(layout.profile, Some(root.join("profile")));
        assert_eq!(
            layout.state.parent().unwrap().join("profile"),
            root.join("profile")
        );
        assert!(layout.maintenance.ends_with("EasyTierDesk.maintenance"));
        assert!(session_layout("S-1-5-21-1-2-3-1001\\..").is_err());
    }
}
