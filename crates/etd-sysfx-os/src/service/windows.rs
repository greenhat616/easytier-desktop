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

mod session;
pub use session::{
    ProcessPin, SessionEnd, SessionToken, elevated_session_token, harden_dll_search,
};
pub(super) use session::{
    prepare_session, remove_session_roots, service_registered, session_layout, session_layouts,
    session_root, validate_session,
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
        CreateDirectoryW(&HSTRING::from(path.as_os_str()), Some(&attrs))
            .map_err(|error| io::Error::from_raw_os_error(error.code().0 & 0xffff))?;
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

pub(super) fn prepare_maintenance(layout: &HostLayout) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    if !layout.maintenance.try_exists()?
        && let Err(error) = create_protected(&layout.maintenance, false)
        && !layout.maintenance.try_exists()?
    {
        return Err(error);
    }
    validate_acl(&layout.maintenance, false, true)?;
    Ok(())
}

pub(super) fn preflight_install(layout: &HostLayout) -> io::Result<()> {
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
    Ok(())
}

pub(super) fn prepare_install(
    layout: &HostLayout,
    journal: &mut LifecycleJournal,
) -> io::Result<()> {
    preflight_install(layout)?;
    let install = layout.executable.parent().ok_or_else(denied)?;
    // Held open from here: the payload cannot be renamed or rewritten.
    let mut source = super::running::RunningImage::open()?;
    journal.create(Resource::InstallDir, || create_protected(install, true))?;
    journal.create(Resource::StateDir, || {
        create_protected(&layout.state, false)
    })?;
    journal.create(Resource::RunDir, || fs::create_dir(&layout.run))?;
    journal.create(Resource::CoreDir, || fs::create_dir(&layout.cores))?;
    // Copy before service registration; do not run an executable in an
    // installer download directory as LocalSystem.
    journal.create(Resource::HostImage, || {
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&layout.executable)?;
        let digest = source.copy_to(&mut destination)?;
        destination.sync_all()?;
        drop(destination);
        if super::running::sha256_file(&layout.executable)? != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the installed host image differs from the bytes copied",
            ));
        }
        Ok(())
    })?;
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
        .map_err(|error| match error {
            windows_service::Error::Winapi(inner) => inner,
            error => other(error),
        })
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
        .map_err(|error| match error {
            windows_service::Error::Winapi(inner) if inner.raw_os_error() == Some(1073) => {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "service name already registered",
                )
            }
            error => other(error),
        })?;
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
    Ok(())
}

pub(super) fn start(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    let svc = open_service(
        ServiceAccess::QUERY_CONFIG
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::START
            | ServiceAccess::QUERY_STATUS,
    )?;
    verify_service(&svc, layout)?;
    svc.change_config(&info(layout, ServiceStartType::AutoStart))
        .map_err(other)?;
    if svc.query_status().map_err(other)?.current_state == ServiceState::Stopped {
        svc.start::<&str>(&[]).map_err(other)?;
    }
    Ok(())
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
    if !elevated()? {
        return Err(denied());
    }
    let svc = match open_service(
        ServiceAccess::QUERY_CONFIG
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::STOP
            | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(svc) => svc,
        Err(error) if matches!(error.raw_os_error(), Some(1060 | 1072)) => return Ok(()),
        Err(error) => return Err(error),
    };
    verify_service(&svc, layout)?;
    svc.change_config(&info(layout, ServiceStartType::Disabled))
        .map_err(other)?;
    if !matches!(
        svc.query_status().map_err(other)?.current_state,
        ServiceState::Stopped | ServiceState::StopPending
    ) {
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

pub(super) fn unregister(layout: &HostLayout, _: bool) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    stop_and_disable(layout)?;
    let svc = match open_service(
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    ) {
        Ok(svc) => Some(svc),
        Err(error) if matches!(error.raw_os_error(), Some(1060 | 1072)) => None,
        Err(error) => return Err(error),
    };
    if let Some(svc) = svc {
        verify_service(&svc, layout)?;
        if svc.query_status().map_err(other)?.current_state != ServiceState::Stopped {
            return Err(denied());
        }
        svc.delete().map_err(other)?;
        drop(svc);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match open_service(ServiceAccess::QUERY_STATUS) {
            Err(error) if error.raw_os_error() == Some(1060) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(1072) => (),
            Err(error) => return Err(error),
            Ok(_) => (),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service registration still present",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
pub(super) fn remove_ipc_dir(_: &HostLayout) -> io::Result<()> {
    Ok(())
}
pub(super) fn remove_group(_: &HostLayout, _: Option<u32>) -> io::Result<()> {
    Ok(())
}
fn remove_owned_tree(path: &Path, readable: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(_) => (),
    }
    validate_acl(path, readable, true)?;
    verify_tree(path, readable)?;
    fs::remove_dir_all(path)
}
pub(super) fn remove_state(layout: &HostLayout) -> io::Result<()> {
    remove_owned_tree(&layout.state, false)
}
// The final install-image deletion is shared by fresh-install rollback,
// normal uninstall, and the deferred helper. Keep the tree and journal if
// a driver references it, or if the query is inconclusive.
fn check_install_driver_references(
    core_dir: &Path,
    query: impl FnOnce(&Path) -> Result<Option<String>, crate::OsError>,
) -> io::Result<()> {
    match fs::symlink_metadata(core_dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(_) => (),
    }
    // Even an empty or irregular store must pass the same driver check.
    // The adapter rejects links, reparse points and unknown file types.
    match query(core_dir) {
        Ok(None) => Ok(()),
        Ok(Some(reference)) => Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!(
                "kernel store retained: {reference}; remove the shared driver separately, then retry uninstall"
            ),
        )),
        Err(error) => Err(io::Error::other(format!(
            "kernel store retained: cannot determine driver references: {error}; retry uninstall"
        ))),
    }
}

fn guarded_install_removal(
    core_dir: &Path,
    query: impl FnOnce(&Path) -> Result<Option<String>, crate::OsError>,
    remove: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    check_install_driver_references(core_dir, query)?;
    remove()
}

pub(super) fn remove_install(layout: &HostLayout) -> io::Result<()> {
    let install = layout.executable.parent().ok_or_else(denied)?;
    // Verify protected ownership before asking the adapter to inspect files.
    match fs::symlink_metadata(install) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(_) => (),
    }
    validate_acl(install, true, true)?;
    verify_tree(install, true)?;
    guarded_install_removal(&layout.cores, crate::driver_bundle_reference, || {
        fs::remove_dir_all(install)
    })
}

// Upgrade (PK1). Files created in the install directory inherit its
// protected DACL; accept exactly what `validate_service` accepts there.
fn image_acl(path: &Path) -> io::Result<()> {
    validate_acl(path, true, false)
}
fn image_paths(layout: &HostLayout) -> io::Result<super::image::ImagePaths> {
    validate_acl(layout.executable.parent().ok_or_else(denied)?, true, true)?;
    Ok(super::image::ImagePaths::of(&layout.executable))
}
pub(super) fn replace_host_image(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    let mut source = super::running::RunningImage::open()?;
    super::image::replace(
        &image_paths(layout)?,
        |out| source.copy_to(out),
        image_acl,
        image_acl,
    )?;
    validate_service(layout)
}
pub(super) fn restore_host_image(layout: &HostLayout) -> io::Result<bool> {
    super::image::restore(&image_paths(layout)?, image_acl)
}
pub(super) fn discard_host_backup(layout: &HostLayout) -> io::Result<()> {
    super::image::discard(&image_paths(layout)?, image_acl)
}
pub(super) fn refresh_registration(_: &HostLayout, _: &mut LifecycleJournal) -> io::Result<()> {
    Ok(())
}
pub(super) fn restore_registration(_: &HostLayout, _: &LifecycleJournal) -> io::Result<bool> {
    Ok(false)
}

pub(super) fn defer_install_removal(
    layout: &HostLayout,
    install_id: &str,
) -> io::Result<Option<u32>> {
    use ::windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
    use ::windows::core::PCWSTR;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek};
    if !layout.executable.try_exists()?
        || super::current_exe()? != layout.executable.canonicalize()?
    {
        return Ok(None);
    }
    // Report a driver reference synchronously instead of scheduling a known
    // blocked helper. The actual deferred deletion checks again.
    validate_acl(layout.executable.parent().ok_or_else(denied)?, true, true)?;
    verify_tree(layout.executable.parent().ok_or_else(denied)?, true)?;
    check_install_driver_references(&layout.cores, crate::driver_bundle_reference)?;
    // The copy is made inside the protected, persistent maintenance root,
    // never in the invoking user's temp directory.
    let dir = tempfile::Builder::new()
        .prefix("uninstall-")
        .tempdir_in(&layout.maintenance)?;
    validate_acl(dir.path(), false, false)?;
    let helper = dir.path().join("etd-host.exe");
    let mut source = File::open(&layout.executable)?;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&helper)?;
    io::copy(&mut source, &mut target)?;
    target.sync_all()?;
    drop(target);
    // Verify the transferred image bytes before executing any helper.
    fn hash(mut reader: impl Read) -> io::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        Ok(hash.finalize().into())
    }
    source.rewind()?;
    if hash(source)? != hash(File::open(&helper)?)? {
        return Err(denied());
    }
    validate_acl(&helper, false, false)?;
    // The helper resumes only the final stage after this process exits.
    // Windows cannot remove its own executing image; schedule only this
    // temporary helper and directory for reboot cleanup.
    unsafe {
        MoveFileExW(
            &HSTRING::from(helper.as_os_str()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
        .map_err(other)?;
        MoveFileExW(
            &HSTRING::from(dir.path().as_os_str()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
        .map_err(other)?;
    }
    let _keep = dir.keep();
    let mut command = std::process::Command::new(&helper);
    // CREATE_NO_WINDOW
    std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000);
    let child = command
        .args([
            "uninstall",
            "--wait-parent",
            &std::process::id().to_string(),
            "--install-id",
            install_id,
        ])
        .spawn()?;
    Ok(Some(child.id()))
}

pub(super) fn deferred_worker_alive(pid: u32) -> io::Result<bool> {
    use ::windows::Win32::{
        Foundation::{ERROR_INVALID_PARAMETER, WAIT_TIMEOUT},
        System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, WaitForSingleObject},
    };
    let handle = match unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(0x0010_0000), false, pid) } {
        Ok(handle) => handle,
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(false),
        Err(error) => return Err(other(error)),
    };
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    let _ = unsafe { CloseHandle(handle) };
    Ok(wait == WAIT_TIMEOUT)
}

pub fn wait_uninstall_parent(pid: u32) -> io::Result<()> {
    use ::windows::Win32::{
        Foundation::{ERROR_INVALID_PARAMETER, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, WaitForSingleObject},
    };
    if !elevated()? {
        return Err(denied());
    }
    if pid == std::process::id() || pid == 0 {
        return Err(denied());
    }
    let handle = match unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(0x0010_0000), false, pid) } {
        Ok(handle) => handle,
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(()),
        Err(error) => return Err(other(error)),
    };
    let result = unsafe { WaitForSingleObject(handle, 30_000) };
    let _ = unsafe { CloseHandle(handle) };
    if result != WAIT_OBJECT_0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "installed uninstall parent did not exit",
        ));
    }
    Ok(())
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

/// A standard UI must be able to verify the image path and creation time
/// of the LocalSystem process named by its pipe. Extend the existing process
/// DACL by exactly QUERY_LIMITED_INFORMATION, not token, VM or control access.
/// This grants no pipe/contract role and expires when this process exits.
fn allow_identity_query() -> io::Result<()> {
    use ::windows::{
        Win32::{
            Security::{
                Authorization::{
                    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo,
                    SE_KERNEL_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID,
                    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
                },
                NO_INHERITANCE,
            },
            System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
        },
        core::w,
    };
    if current_sid()? != "S-1-5-18" {
        return Err(denied());
    }
    unsafe {
        let process = GetCurrentProcess();
        let mut old_acl = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        GetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_acl),
            None,
            Some(&mut descriptor),
        )
        .ok()
        .map_err(other)?;
        let _descriptor = Allocation(HLOCAL(descriptor.0));
        if old_acl.is_null() {
            return Err(denied());
        }
        let mut sid = PSID::default();
        ConvertStringSidToSidW(w!("S-1-5-11"), &mut sid).map_err(other)?; // Authenticated Users
        let _sid = Allocation(HLOCAL(sid.0));
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: PROCESS_QUERY_LIMITED_INFORMATION.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.0.cast()),
                ..Default::default()
            },
        };
        let mut acl = std::ptr::null_mut();
        SetEntriesInAclW(Some(&[access]), Some(old_acl), &mut acl)
            .ok()
            .map_err(other)?;
        let _acl = Allocation(HLOCAL(acl.cast()));
        SetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
        .ok()
        .map_err(other)?;
    }
    Ok(())
}

/// While stopping, the SCM is told every [`STOP_HEARTBEAT`] that the stop
/// progresses (STOP_PENDING with an increasing checkpoint and a wait hint),
/// for at most [`STOP_PROGRESS_LIMIT`]. The host bounds its own wind-down
/// well below that; past the limit the checkpoint stops moving, so the SCM
/// sees a hung stop instead of endless progress.
const STOP_HEARTBEAT: Duration = Duration::from_secs(2);
const STOP_WAIT_HINT: Duration = Duration::from_secs(10);
const STOP_PROGRESS_LIMIT: Duration = Duration::from_secs(120);

/// Status reports shared by the heartbeat thread and the service thread:
/// once `finished`, no STOP_PENDING may follow the final STOPPED.
struct StopProgress {
    finished: bool,
    checkpoint: u32,
}

fn service_status(
    state: ServiceState,
    exit: u32,
    checkpoint: u32,
    wait_hint: Duration,
) -> windows_service::service::ServiceStatus {
    use windows_service::service::{ServiceControlAccept, ServiceExitCode, ServiceStatus};
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

/// Report STOP_PENDING progress from the moment a stop is requested until
/// the service thread reports STOPPED.
fn stop_heartbeat(
    handle: windows_service::service_control_handler::ServiceStatusHandle,
    requested: std::sync::mpsc::Receiver<()>,
    progress: std::sync::Arc<std::sync::Mutex<StopProgress>>,
) {
    let finished = || {
        progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .finished
    };
    loop {
        match requested.recv_timeout(Duration::from_secs(1)) {
            Ok(()) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if !finished() => {}
            Err(_) => return,
        }
    }
    let since = Instant::now();
    loop {
        {
            let mut p = progress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if p.finished {
                return;
            }
            if since.elapsed() < STOP_PROGRESS_LIMIT || p.checkpoint == 0 {
                p.checkpoint += 1;
                let _ = handle.set_service_status(service_status(
                    ServiceState::StopPending,
                    0,
                    p.checkpoint,
                    STOP_WAIT_HINT,
                ));
            }
        }
        std::thread::sleep(STOP_HEARTBEAT);
    }
}

fn run_service() -> io::Result<()> {
    use windows_service::{
        service::ServiceControl,
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let (requested, heard) = std::sync::mpsc::channel::<()>();
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop.send_replace(true);
            let _ = requested.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(other)?;
    let status = |state, exit| service_status(state, exit, 0, Duration::ZERO);
    if let Err(error) = allow_identity_query() {
        let _ = handle.set_service_status(status(ServiceState::Stopped, 1));
        return Err(error);
    }
    handle
        .set_service_status(status(ServiceState::Running, 0))
        .map_err(other)?;
    let body = SERVICE_BODY
        .get()
        .and_then(|body| body.lock().ok()?.take())
        .ok_or_else(|| io::Error::other("no service body"))?;
    let progress = std::sync::Arc::new(std::sync::Mutex::new(StopProgress {
        finished: false,
        checkpoint: 0,
    }));
    // Without the thread the stop is still bounded; it only goes
    // unreported until STOPPED.
    let heartbeat = {
        let progress = progress.clone();
        std::thread::Builder::new()
            .name("etd-service-stop".into())
            .spawn(move || stop_heartbeat(handle, heard, progress))
            .ok()
    };
    let result = body(receiver);
    let stopped = {
        let mut p = progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        p.finished = true;
        handle.set_service_status(status(
            ServiceState::Stopped,
            if result.is_ok() { 0 } else { 1 },
        ))
    };
    // The thread checks `finished` at least every second; not waiting for
    // it cannot delay STOPPED, which is already reported.
    drop(heartbeat);
    stopped.map_err(other)?;
    result
}

#[cfg(test)]
mod driver_removal_tests {
    use super::*;

    #[test]
    fn unexpected_flat_store_entry_still_requires_driver_guard() {
        let root = tempfile::tempdir().unwrap();
        let cores = root.path().join("cores");
        fs::create_dir(&cores).unwrap();
        fs::write(cores.join("manifest.json"), b"fixture").unwrap();
        check_install_driver_references(&cores, |_| Ok(None)).unwrap();
        let image = cores.join("bad.bin");
        fs::write(&image, b"fixture").unwrap();
        let err = guarded_install_removal(
            &cores,
            |_| Err(crate::OsError::Unsupported("no access".into())),
            || panic!("must not delete"),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot determine driver references")
        );
        assert!(image.exists());
    }

    #[test]
    fn rollback_and_uninstall_keep_tree_for_driver_reference_or_query_failure() {
        // Both paths use guarded_install_removal. Use only a private fixture
        // directory and fake query; never register/stop a system driver.
        for rollback in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let cores = root.path().join("cores");
            fs::create_dir_all(cores.join("bundle")).unwrap();
            let image = cores.join("bundle").join("driver.sys");
            fs::write(&image, b"fixture").unwrap();
            let query = |_: &Path| {
                Ok(Some(format!(
                    "driver service fixture references {}",
                    image.display()
                )))
            };
            let remove = || fs::remove_dir_all(&cores);
            let err = guarded_install_removal(&cores, query, remove).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ResourceBusy);
            assert!(err.to_string().contains("driver service fixture"));
            assert!(image.exists(), "rollback={rollback}");
            let err = guarded_install_removal(
                &cores,
                |_| Err(crate::OsError::Unsupported("unavailable".into())),
                remove,
            )
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains("cannot determine driver references")
            );
            assert!(image.exists());
            guarded_install_removal(&cores, |_| Ok(None), remove).unwrap();
            assert!(!cores.exists());
            // Retry after successful removal remains idempotent.
            guarded_install_removal(&cores, |_| panic!("missing tree needs no query"), || Ok(()))
                .unwrap();
        }
    }
}
