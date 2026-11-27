//! Service installation: copy binaries to an admin-only location, register
//! allowed SIDs, create the easytier-desk group, SCM / systemd / launchd
//! registration. Owned by HR.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[cfg(all(windows, feature = "ci-test-fixtures"))]
pub mod ci_fixture;
mod image;
mod running;
pub use running::running_image_matches;
mod journal;
#[cfg(unix)]
mod unix;
pub use journal::{DeferredOutcome, LifecycleJournal, Phase, Resource, UpgradeStage};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use self::windows as native;
#[cfg(unix)]
use unix as native;

pub const SERVICE_NAME: &str = "easytier-desk-host";

/// Host directories. Service paths come from the OS, not from RPC clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLayout {
    pub state: PathBuf,
    pub run: PathBuf,
    pub cores: PathBuf,
    pub executable: PathBuf,
    pub socket_dir: Option<PathBuf>,
    /// Stable protected directory never removed by install/uninstall.
    pub maintenance: PathBuf,
    /// Elevated session only: the protected, empty directory the kernel's
    /// and the system workers' profile variables point at
    /// (`<state>\..\profile`).
    pub profile: Option<PathBuf>,
    user_host: bool,
}

/// A protected host directory that exists but does not conform (owner,
/// access control, reparse point, hard link). It is refused, never repaired
/// or adopted. Carried inside the `io::Error` of the session operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("session directory not conforming: {} ({reason})", path.display())]
pub struct NotConforming {
    pub path: PathBuf,
    pub reason: String,
}

impl NotConforming {
    /// The refusal inside `error`, if that is what it is.
    pub fn of(error: &io::Error) -> Option<&Self> {
        error.get_ref().and_then(|inner| inner.downcast_ref())
    }
}

/// A cross-process exclusive OS lock. Keep the lock file: deleting it while
/// a holder or waiter exists would permit a second independent lock inode.
pub struct HostLock {
    files: Vec<File>,
}
impl HostLock {
    pub fn acquire(directory: &Path) -> io::Result<Self> {
        let file = open_lock(directory, "host.lock")?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "host already running; stop it before maintenance",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        Ok(Self { files: vec![file] })
    }
}

/// Serialize whole maintenance commands, including the interval when the
/// host lifetime lock must be released before starting the service.
#[must_use]
pub struct MaintenanceLock {
    _file: File,
}
impl MaintenanceLock {
    pub fn acquire(directory: &Path) -> io::Result<Self> {
        let file = open_lock(directory, "maintenance-command.lock")?;
        file.lock()?;
        Ok(Self { _file: file })
    }
}

fn open_lock(directory: &Path, name: &str) -> io::Result<File> {
    let path = directory.join(name);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || related_path(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid host lock file",
        ));
    }
    Ok(file)
}

fn related_path(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Filesystem layout and lock operations used by the host composition root.
pub trait HostFilesystem {
    fn user_layout(
        &self,
        state_override: Option<&Path>,
        runtime_dir: Option<&Path>,
    ) -> io::Result<HostLayout>;
    fn service_layout(&self) -> io::Result<HostLayout>;
    fn prepare_user(&self, layout: &HostLayout) -> io::Result<()>;
    fn validate_service(&self, layout: &HostLayout) -> io::Result<()>;
    fn prepare_maintenance(&self, layout: &HostLayout) -> io::Result<()>;
    fn is_installed_image(&self, layout: &HostLayout) -> io::Result<bool>;
    fn lock(&self, layout: &HostLayout) -> io::Result<HostLock>;
    fn lock_maintenance(&self, layout: &HostLayout) -> io::Result<MaintenanceLock>;
    /// Elevated session host of user `sid` (Windows only): everything under
    /// `%ProgramData%\EasyTierDesk.session\<SID>`, locks shared with the
    /// service.
    fn session_layout(&self, _sid: &str) -> io::Result<HostLayout> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Create the missing protected session directories, then verify the
    /// whole per-user tree. Fails with [`NotConforming`] inside the error
    /// for anything that exists but does not conform.
    fn prepare_session(&self, _layout: &HostLayout) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Verify a session tree without creating anything.
    fn validate_session(&self, _layout: &HostLayout) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Every per-user session root, each verified; one that does not
    /// conform fails the whole call. Ownership is never inferred from a
    /// directory's name.
    fn session_layouts(&self) -> io::Result<Vec<HostLayout>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Remove `EasyTierDesk.session` after verifying it (install drained
    /// every ledger in it first).
    fn remove_session_roots(&self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Privileged changes are deliberately separated from composition. Only the
/// installer invokes these methods; ordinary user hosts never do.
pub trait ServiceManager {
    /// Create *fresh*, protected directories; copy the host before any
    /// registration. Refuse pre-existing product paths rather than claiming
    /// objects that may belong to someone else.
    fn preflight_install(&self, layout: &HostLayout) -> io::Result<()>;
    fn prepare_install(
        &self,
        layout: &HostLayout,
        journal: &mut LifecycleJournal,
    ) -> io::Result<()>;
    /// Register with the service manager using the protected executable.
    fn register(&self, layout: &HostLayout, journal: &mut LifecycleJournal) -> io::Result<()>;
    fn start(&self, layout: &HostLayout) -> io::Result<()>;
    /// Disable restart and stop before invoking maintenance reclaim.
    fn stop_and_disable(&self, layout: &HostLayout) -> io::Result<()>;
    /// Remove registration and validated product directories after reclaim.
    fn unregister(&self, layout: &HostLayout, partial_install: bool) -> io::Result<()>;
    fn ipc_dir_exists(&self, layout: &HostLayout) -> io::Result<bool>;
    fn remove_ipc_dir(&self, layout: &HostLayout) -> io::Result<()>;
    fn remove_group(&self, layout: &HostLayout, gid: Option<u32>) -> io::Result<()>;
    fn remove_state(&self, layout: &HostLayout) -> io::Result<()>;
    fn remove_install(&self, layout: &HostLayout) -> io::Result<()>;
    /// Windows installed executable handoff for the last uninstall stage.
    fn defer_install_removal(
        &self,
        layout: &HostLayout,
        install_id: &str,
    ) -> io::Result<Option<u32>>;
    fn deferred_worker_alive(&self, pid: u32) -> io::Result<bool>;
    fn entry_is_elevated(&self) -> io::Result<bool>;
    /// The service is registered with the service manager (whatever its
    /// state).
    fn is_registered(&self) -> io::Result<bool> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// `etd-host upgrade`: copy the running image (bound to the running
    /// process, not to its path) beside the installed host image, verify
    /// it, then swap it in, keeping the previous image as a backup until
    /// [`Self::discard_host_backup`]. The service must be stopped.
    fn replace_host_image(&self, _layout: &HostLayout) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Put the backed-up host image back; `Ok(false)` if there is none.
    fn restore_host_image(&self, _layout: &HostLayout) -> io::Result<bool> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Remove the image and registration backups and leftovers of a
    /// committed upgrade.
    fn discard_host_backup(&self, _layout: &HostLayout) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Rewrite the service registration if this build's differs, saving
    /// the previous one in the maintenance directory first. On Windows the
    /// SCM configuration this build writes ([`Self::start`]) is the same
    /// for every build, so there is nothing to save.
    /// The backup is written atomically and bound to the active upgrade by
    /// its digest in `journal`.
    fn refresh_registration(
        &self,
        _layout: &HostLayout,
        _journal: &mut LifecycleJournal,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Put a registration saved by [`Self::refresh_registration`] back;
    /// `Ok(false)` if none was saved. A backup `journal` does not bind is
    /// never restored.
    fn restore_registration(
        &self,
        _layout: &HostLayout,
        _journal: &LifecycleJournal,
    ) -> io::Result<bool> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

pub struct NativeServiceManager;
impl ServiceManager for NativeServiceManager {
    fn preflight_install(&self, layout: &HostLayout) -> io::Result<()> {
        native::preflight_install(layout)
    }
    fn prepare_install(
        &self,
        layout: &HostLayout,
        journal: &mut LifecycleJournal,
    ) -> io::Result<()> {
        native::prepare_install(layout, journal)
    }
    fn register(&self, layout: &HostLayout, journal: &mut LifecycleJournal) -> io::Result<()> {
        journal.create(Resource::Registration, || native::register(layout))
    }
    fn start(&self, layout: &HostLayout) -> io::Result<()> {
        native::start(layout)
    }
    fn stop_and_disable(&self, layout: &HostLayout) -> io::Result<()> {
        native::stop_and_disable(layout)
    }
    fn unregister(&self, layout: &HostLayout, partial_install: bool) -> io::Result<()> {
        native::unregister(layout, partial_install)
    }
    fn ipc_dir_exists(&self, layout: &HostLayout) -> io::Result<bool> {
        layout
            .socket_dir
            .as_ref()
            .map_or(Ok(false), |path| path.try_exists())
    }
    fn remove_ipc_dir(&self, layout: &HostLayout) -> io::Result<()> {
        native::remove_ipc_dir(layout)
    }
    fn remove_group(&self, layout: &HostLayout, gid: Option<u32>) -> io::Result<()> {
        native::remove_group(layout, gid)
    }
    fn remove_state(&self, layout: &HostLayout) -> io::Result<()> {
        native::remove_state(layout)
    }
    fn remove_install(&self, layout: &HostLayout) -> io::Result<()> {
        native::remove_install(layout)
    }
    fn defer_install_removal(
        &self,
        layout: &HostLayout,
        install_id: &str,
    ) -> io::Result<Option<u32>> {
        native::defer_install_removal(layout, install_id)
    }
    fn deferred_worker_alive(&self, pid: u32) -> io::Result<bool> {
        native::deferred_worker_alive(pid)
    }
    fn entry_is_elevated(&self) -> io::Result<bool> {
        native::elevated()
    }
    #[cfg(windows)]
    fn is_registered(&self) -> io::Result<bool> {
        native::service_registered()
    }
    fn replace_host_image(&self, layout: &HostLayout) -> io::Result<()> {
        native::replace_host_image(layout)
    }
    fn restore_host_image(&self, layout: &HostLayout) -> io::Result<bool> {
        native::restore_host_image(layout)
    }
    fn discard_host_backup(&self, layout: &HostLayout) -> io::Result<()> {
        native::discard_host_backup(layout)
    }
    fn refresh_registration(
        &self,
        layout: &HostLayout,
        journal: &mut LifecycleJournal,
    ) -> io::Result<()> {
        native::refresh_registration(layout, journal)
    }
    fn restore_registration(
        &self,
        layout: &HostLayout,
        journal: &LifecycleJournal,
    ) -> io::Result<bool> {
        native::restore_registration(layout, journal)
    }
}

/// CI fault injection for the privileged upgrade tests. Compiled only with
/// the `ci-test-fixtures` feature (never in a product build): true when
/// the protected maintenance directory holds `ci-upgrade-fault` with a
/// line naming `point`. Only an administrator can create that file.
#[cfg(feature = "ci-test-fixtures")]
pub fn ci_upgrade_fault(layout: &HostLayout, point: &str) -> bool {
    fs::read_to_string(layout.maintenance.join("ci-upgrade-fault"))
        .is_ok_and(|faults| faults.lines().any(|fault| fault.trim() == point))
}
#[cfg(not(feature = "ci-test-fixtures"))]
pub fn ci_upgrade_fault(_: &HostLayout, _: &str) -> bool {
    false
}

/// Whether `current` (canonical) is `executable`. A missing executable is
/// not the running image: between an upgrade's two renames there is none,
/// and the next upgrade must still be able to restore it.
pub(super) fn is_image(current: &Path, executable: &Path) -> io::Result<bool> {
    match executable.canonicalize() {
        Ok(installed) => Ok(current == installed),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// The service's state directory exists (installed, or an uninstall that
/// has not removed it yet).
pub fn service_state_exists() -> io::Result<bool> {
    service_layout()?.state.try_exists()
}

/// `%ProgramData%\EasyTierDesk.session` (Windows only).
#[cfg(windows)]
pub fn session_root() -> io::Result<PathBuf> {
    native::session_root()
}

pub fn current_exe() -> io::Result<PathBuf> {
    std::env::current_exe()?.canonicalize()
}
/// Shared client-side executable directory for authenticating an installed
/// service. The Windows location comes from Known Folders, not environment.
pub fn installed_host_dir() -> io::Result<PathBuf> {
    service_layout()?
        .executable
        .parent()
        .map(Path::to_owned)
        .ok_or_else(|| io::Error::other("installed host directory missing"))
}
#[cfg(unix)]
pub use unix::group_id as service_group_id;
#[cfg(windows)]
pub use windows::{
    ProcessPin, SessionEnd, SessionToken, dispatch_service, elevated_session_token,
    harden_dll_search, wait_uninstall_parent,
};

#[derive(Default)]
pub struct NativeHostFilesystem;

#[cfg(unix)]
fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{name} not configured"))
}
fn absolute(path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        Ok(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host directory must be absolute without parent traversal",
        ))
    }
}

#[cfg(unix)]
fn private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.uid() != nix::unistd::Uid::effective().as_raw()
        || m.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host directory must be owned by current user and mode 0700",
        ));
    }
    Ok(())
}
#[cfg(windows)]
fn private_dir(path: &Path) -> io::Result<()> {
    native::private_user_dir(path)
}

impl HostFilesystem for NativeHostFilesystem {
    fn user_layout(
        &self,
        state_override: Option<&Path>,
        runtime_dir: Option<&Path>,
    ) -> io::Result<HostLayout> {
        let state = if let Some(p) = state_override {
            p.to_owned()
        } else {
            user_state()?
        };
        let state = absolute(state)?;
        let socket_dir = runtime_dir.map(|p| absolute(p.to_owned())).transpose()?;
        Ok(HostLayout {
            run: state.join("run"),
            cores: state.join("cores"),
            executable: std::env::current_exe()?.canonicalize()?,
            maintenance: state.clone(),
            state,
            socket_dir,
            profile: None,
            user_host: true,
        })
    }
    fn service_layout(&self) -> io::Result<HostLayout> {
        service_layout()
    }
    fn prepare_user(&self, layout: &HostLayout) -> io::Result<()> {
        if let Some(parent) = layout.state.parent() {
            fs::create_dir_all(parent)?;
        }
        private_dir(&layout.state)?;
        private_dir(&layout.run)?;
        private_dir(&layout.cores)?;
        if let Some(path) = &layout.socket_dir {
            private_dir(path)?;
        }
        Ok(())
    }
    fn validate_service(&self, layout: &HostLayout) -> io::Result<()> {
        native::validate_service(layout)
    }
    fn prepare_maintenance(&self, layout: &HostLayout) -> io::Result<()> {
        native::prepare_maintenance(layout)
    }
    fn is_installed_image(&self, layout: &HostLayout) -> io::Result<bool> {
        is_image(&current_exe()?, &layout.executable)
    }
    fn lock(&self, layout: &HostLayout) -> io::Result<HostLock> {
        if !layout.user_host {
            native::prepare_maintenance(layout)?;
        }
        let mut guard = HostLock::acquire(&layout.maintenance)?;
        // A different XDG state directory must not permit a second claim
        // for the same user endpoint.
        if layout.user_host
            && let Some(runtime) = &layout.socket_dir
            && runtime != &layout.state
        {
            guard.files.extend(HostLock::acquire(runtime)?.files);
        }
        Ok(guard)
    }
    fn lock_maintenance(&self, layout: &HostLayout) -> io::Result<MaintenanceLock> {
        native::prepare_maintenance(layout)?;
        MaintenanceLock::acquire(&layout.maintenance)
    }
    #[cfg(windows)]
    fn session_layout(&self, sid: &str) -> io::Result<HostLayout> {
        native::session_layout(sid)
    }
    #[cfg(windows)]
    fn prepare_session(&self, layout: &HostLayout) -> io::Result<()> {
        native::prepare_session(layout)
    }
    #[cfg(windows)]
    fn validate_session(&self, layout: &HostLayout) -> io::Result<()> {
        native::validate_session(layout)
    }
    #[cfg(windows)]
    fn session_layouts(&self) -> io::Result<Vec<HostLayout>> {
        native::session_layouts()
    }
    /// Unix has no elevated session host, so no session roots.
    #[cfg(unix)]
    fn session_layouts(&self) -> io::Result<Vec<HostLayout>> {
        Ok(vec![])
    }
    #[cfg(windows)]
    fn remove_session_roots(&self) -> io::Result<()> {
        native::remove_session_roots()
    }
    #[cfg(unix)]
    fn remove_session_roots(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
fn user_state() -> io::Result<PathBuf> {
    Ok(native::local_app_data()?.join("EasyTierDesk"))
}
#[cfg(target_os = "macos")]
fn user_state() -> io::Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| missing("HOME"))?)
            .join("Library/Application Support/easytier-desk"),
    )
}
#[cfg(target_os = "linux")]
fn user_state() -> io::Result<PathBuf> {
    let root = if let Some(root) = std::env::var_os("XDG_STATE_HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(root)
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| missing("HOME"))?).join(".local/state")
    };
    Ok(root.join("easytier-desk"))
}

#[cfg(windows)]
fn service_layout() -> io::Result<HostLayout> {
    let state = absolute(native::program_data()?.join("EasyTierDesk"))?;
    let install = absolute(native::program_files()?.join("EasyTierDesk"))?;
    Ok(HostLayout {
        run: state.join("run"),
        cores: install.join("cores"),
        executable: install.join("etd-host.exe"),
        state,
        socket_dir: None,
        maintenance: native::program_data()?.join("EasyTierDesk.maintenance"),
        profile: None,
        user_host: false,
    })
}
#[cfg(target_os = "linux")]
fn service_layout() -> io::Result<HostLayout> {
    let state = PathBuf::from("/var/lib/easytier-desk");
    let install = PathBuf::from("/usr/local/lib/easytier-desk");
    Ok(HostLayout {
        run: state.join("run"),
        cores: install.join("cores"),
        executable: install.join("etd-host"),
        state,
        socket_dir: Some(PathBuf::from("/run/easytier-desk")),
        maintenance: PathBuf::from("/var/lib/easytier-desk-maintenance"),
        profile: None,
        user_host: false,
    })
}
#[cfg(target_os = "macos")]
fn service_layout() -> io::Result<HostLayout> {
    let install = PathBuf::from("/Library/Application Support/easytier-desk");
    let state = install.join("state");
    Ok(HostLayout {
        run: state.join("run"),
        cores: install.join("cores"),
        executable: install.join("etd-host"),
        state,
        socket_dir: Some(install.join("run")),
        maintenance: PathBuf::from("/Library/Application Support/easytier-desk-maintenance"),
        profile: None,
        user_host: false,
    })
}
