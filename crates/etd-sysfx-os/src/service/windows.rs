//! Windows service filesystem and SCM adapter. No shell or caller-supplied
//! search path is involved in registering the LocalSystem executable.
use super::*;
use ::windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACL,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
            TokenElevation,
        },
        Storage::FileSystem::CreateDirectoryW,
        System::{
            Com::CoTaskMemFree,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{
            FOLDERID_LocalAppData, FOLDERID_ProgramData, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT,
            SHGetKnownFolderPath,
        },
    },
    core::{GUID, HSTRING, PWSTR},
};
use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    thread,
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "untrusted service directory or access control",
    )
}

fn known(id: &GUID) -> io::Result<PathBuf> {
    // SAFETY: the returned NUL-terminated COM allocation lives until freed.
    unsafe {
        let ptr = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).map_err(other)?;
        let value = PathBuf::from(OsString::from_wide(ptr.as_wide()));
        CoTaskMemFree(Some(ptr.0.cast()));
        Ok(value)
    }
}
pub(super) fn local_app_data() -> io::Result<PathBuf> {
    known(&FOLDERID_LocalAppData)
}
pub(super) fn program_data() -> io::Result<PathBuf> {
    known(&FOLDERID_ProgramData)
}
pub(super) fn program_files() -> io::Result<PathBuf> {
    known(&FOLDERID_ProgramFiles)
}
pub(super) fn user_temp_runtime() -> io::Result<PathBuf> {
    Ok(local_app_data()?.join("EasyTierDesk"))
}

pub(super) fn elevated() -> io::Result<bool> {
    let mut token = HANDLE::default();
    // SAFETY: query our live process token, and free its handle afterwards.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(other)?;
        let mut value = TOKEN_ELEVATION::default();
        let mut size = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut value as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = CloseHandle(token);
        result.map_err(other)?;
        Ok(value.TokenIsElevated != 0)
    }
}

struct Allocation(HLOCAL);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(self.0));
        }
    }
}

fn create_protected(path: &Path, readable: bool) -> io::Result<()> {
    // Explicit owner and protected inheritable DACL. Owner Rights restricts
    // an installer account that later runs with its unelevated token from
    // changing the DACL of files it created inside the directory.
    let sddl = if readable {
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;RC;;;OW)"
    } else {
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)"
    };
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(other)?;
        let _allocation = Allocation(HLOCAL(sd.0));
        let attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        // Atomic directory publication: an attacker-created path is refused,
        // not opened and subsequently granted trusted permissions.
        CreateDirectoryW(&HSTRING::from(path.as_os_str()), Some(&attrs)).map_err(other)?;
    }
    validate_acl(path, readable, true)
}

fn sid_text(sid: PSID) -> io::Result<String> {
    let mut value = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut value).map_err(other)?;
        let _allocation = Allocation(HLOCAL(value.0.cast()));
        value.to_string().map_err(other)
    }
}

fn current_sid() -> io::Result<String> {
    use ::windows::Win32::Security::{TOKEN_USER, TokenUser};
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(other)?;
        let mut size = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(data.as_mut_ptr().cast()),
            size,
            &mut size,
        );
        let _ = CloseHandle(token);
        result.map_err(other)?;
        if (size as usize) < size_of::<TOKEN_USER>() {
            return Err(denied());
        }
        sid_text((*data.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}

pub(super) fn private_user_dir(path: &Path) -> io::Result<()> {
    let user = current_sid()?;
    if !path.try_exists()? {
        let sddl = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .map_err(other)?;
            let _allocation = Allocation(HLOCAL(sd.0));
            let attrs = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            match CreateDirectoryW(&HSTRING::from(path.as_os_str()), Some(&attrs)) {
                Ok(()) => (),
                Err(error) if error.code().0 == 0x800700b7u32 as i32 => (), // another same-user host created it
                Err(error) => return Err(other(error)),
            }
        }
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || super::related_path(&m) {
        return Err(denied());
    }
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(other)?;
        let _allocation = Allocation(HLOCAL(sd.0));
        if sid_text(owner)? != user || dacl.is_null() {
            return Err(denied());
        }
        let mut own = false;
        for index in 0..(*dacl).AceCount as u32 {
            let mut ptr = std::ptr::null_mut();
            GetAce(dacl, index, &mut ptr).map_err(other)?;
            let header = &*ptr.cast::<::windows::Win32::Security::ACE_HEADER>();
            if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(denied());
            }
            let ace = &*ptr.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_text(PSID((&raw const ace.SidStart).cast_mut().cast()))?;
            if sid == user {
                own |= ace.Mask == 0x001f01ff;
            } else if !matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544") {
                return Err(denied());
            }
        }
        if !own {
            return Err(denied());
        }
    }
    Ok(())
}

fn validate_acl(path: &Path, readable: bool, require_root_owner: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if super::related_path(&metadata) || !(metadata.is_dir() || metadata.is_file()) {
        return Err(denied());
    }
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(other)?;
        let _allocation = Allocation(HLOCAL(sd.0));
        if dacl.is_null() {
            return Err(denied());
        }
        let owner = sid_text(owner)?;
        let privileged_owner = matches!(owner.as_str(), "S-1-5-18" | "S-1-5-32-544");
        if require_root_owner && !privileged_owner {
            return Err(denied());
        }
        let mut system = false;
        let mut admins = false;
        let mut owner_restricted = false;
        for n in 0..(*dacl).AceCount as u32 {
            let mut ptr = std::ptr::null_mut();
            GetAce(dacl, n, &mut ptr).map_err(other)?;
            // Only the standard access-allowed ACEs produced by our installer
            // are accepted. No broad or unevaluated access masks.
            let header = &*ptr.cast::<::windows::Win32::Security::ACE_HEADER>();
            if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(denied());
            }
            let ace = &*ptr.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_text(PSID((&raw const ace.SidStart).cast_mut().cast()))?;
            match sid.as_str() {
                "S-1-5-18" => system |= ace.Mask == 0x001f01ff,
                "S-1-5-32-544" => admins |= ace.Mask == 0x001f01ff,
                "S-1-5-32-545" if readable && ace.Mask & !0x001200a9 == 0 => (),
                "S-1-3-4" if ace.Mask & !0x00020000 == 0 => owner_restricted = true,
                _ => return Err(denied()),
            }
        }
        if !system || !admins || (!privileged_owner && !owner_restricted) {
            return Err(denied());
        }
    }
    Ok(())
}

fn verify_tree(path: &Path, readable: bool) -> io::Result<()> {
    validate_acl(path, readable, false)?;
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            verify_tree(&entry?.path(), readable)?;
        }
    }
    Ok(())
}

pub(super) fn validate_service(layout: &HostLayout) -> io::Result<()> {
    let install = layout.executable.parent().ok_or_else(denied)?;
    validate_acl(install, true, true)?;
    validate_acl(&layout.state, false, true)?;
    verify_tree(&layout.state, false)?;
    verify_tree(install, true)?;
    if !layout.executable.is_file() || !layout.cores.is_dir() || !layout.run.is_dir() {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn prepare_install(layout: &HostLayout) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(other)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "service name already registered; refusing to overwrite",
            ));
        }
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => (),
        Err(error) => return Err(other(error)),
    }
    let install = layout.executable.parent().ok_or_else(denied)?;
    if layout.state.try_exists()? || install.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service directories already exist; refusing to overwrite",
        ));
    }
    create_protected(&layout.state, false)?;
    create_protected(install, true)?;
    fs::create_dir(&layout.run)?;
    fs::create_dir(&layout.cores)?;
    // Copy before service registration; do not run an executable in an
    // installer download directory as LocalSystem.
    let mut source = File::open(super::current_exe()?)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&layout.executable)?;
    io::copy(&mut source, &mut destination)?;
    destination.sync_all()?;
    drop(destination);
    validate_service(layout)
}

fn info(layout: &HostLayout, start_type: ServiceStartType) -> ServiceInfo {
    ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "EasyTier Desktop Host".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: layout.executable.clone(),
        launch_arguments: vec!["run".into(), "--mode".into(), "service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    }
}

fn open_service(access: ServiceAccess) -> io::Result<Service> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(other)?
        .open_service(SERVICE_NAME, access)
        .map_err(other)
}

pub(super) fn register(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(other)?;
    let svc = mgr
        .create_service(
            &info(layout, ServiceStartType::AutoStart),
            ServiceAccess::START | ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(other)?;
    use windows_service::service::{
        ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(300)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(2),
        }]),
    })
    .map_err(other)?;
    svc.start::<&str>(&[]).map_err(other)
}

fn verify_service(svc: &Service, layout: &HostLayout) -> io::Result<()> {
    let config = svc.query_config().map_err(other)?;
    let expected = format!("\"{}\" run --mode service", layout.executable.display());
    // The service crate quotes the path if it contains spaces. Refuse to
    // delete registrations not demonstrably installed by this product.
    let raw = config.executable_path.to_string_lossy();
    let direct = format!("{} run --mode service", layout.executable.display());
    if raw != expected && raw != direct {
        return Err(denied());
    }
    if config.service_type != ServiceType::OWN_PROCESS
        || !config.account_name.as_ref().is_some_and(|a| {
            a.to_string_lossy().eq_ignore_ascii_case("LocalSystem")
                || a.to_string_lossy()
                    .eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM")
        })
    {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn stop_and_disable(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    let svc = open_service(
        ServiceAccess::QUERY_CONFIG
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::STOP
            | ServiceAccess::QUERY_STATUS,
    )?;
    verify_service(&svc, layout)?;
    svc.change_config(&info(layout, ServiceStartType::Disabled))
        .map_err(other)?;
    if svc.query_status().map_err(other)?.current_state != ServiceState::Stopped {
        svc.stop().map_err(other)?;
    }
    let limit = Instant::now() + Duration::from_secs(60);
    while svc.query_status().map_err(other)?.current_state != ServiceState::Stopped {
        if Instant::now() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service did not stop",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

pub(super) fn remove(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    let svc = open_service(
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    )?;
    verify_service(&svc, layout)?;
    if svc.query_status().map_err(other)?.current_state != ServiceState::Stopped {
        return Err(denied());
    }
    svc.delete().map_err(other)?;
    drop(svc);
    fs::remove_dir_all(layout.executable.parent().ok_or_else(denied)?)?;
    fs::remove_dir_all(&layout.state)
}

type ServiceBody = Box<dyn FnOnce(tokio::sync::watch::Receiver<bool>) -> io::Result<()> + Send>;
static SERVICE_BODY: std::sync::OnceLock<std::sync::Mutex<Option<ServiceBody>>> =
    std::sync::OnceLock::new();
static SERVICE_RESULT: std::sync::OnceLock<io::Result<()>> = std::sync::OnceLock::new();

/// Enter the SCM dispatcher; the body is invoked only by the service manager.
pub fn dispatch_service(
    body: impl FnOnce(tokio::sync::watch::Receiver<bool>) -> io::Result<()> + Send + 'static,
) -> io::Result<()> {
    SERVICE_BODY
        .set(std::sync::Mutex::new(Some(Box::new(body))))
        .map_err(|_| io::Error::other("service already dispatched"))?;
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(other)?;
    match SERVICE_RESULT.get() {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => Err(io::Error::new(error.kind(), error.to_string())),
        None => Err(io::Error::other(
            "service dispatcher returned without a result",
        )),
    }
}

windows_service::define_windows_service!(ffi_service_main, service_main);
fn service_main(_: Vec<OsString>) {
    let _ = SERVICE_RESULT.set(run_service());
}
fn run_service() -> io::Result<()> {
    use windows_service::{
        service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceStatus},
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop.send_replace(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(other)?;
    let status = |state, exit| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    handle
        .set_service_status(status(ServiceState::Running, 0))
        .map_err(other)?;
    let body = SERVICE_BODY
        .get()
        .and_then(|body| body.lock().ok()?.take())
        .ok_or_else(|| io::Error::other("no service body"))?;
    let result = body(receiver);
    handle
        .set_service_status(status(
            ServiceState::Stopped,
            if result.is_ok() { 0 } else { 1 },
        ))
        .map_err(other)?;
    result
}
