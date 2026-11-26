use super::*;
use nix::unistd::{Group, Uid};
use std::{
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    process::Command,
};

const GROUP: &str = "easytier-desk";
const GROUP_RECORD: &str = "installed-group";

#[cfg(target_os = "linux")]
const UNIT: &str = "/etc/systemd/system/easytier-desk-host.service";
#[cfg(target_os = "linux")]
const UNIT_CONTENT: &str = "[Unit]\nDescription=EasyTier Desktop Host\nAfter=network.target\n[Service]\nType=simple\nExecStart=/usr/local/lib/easytier-desk/etd-host run --mode service\nRestart=on-failure\nRuntimeDirectory=easytier-desk\nRuntimeDirectoryMode=0755\nRuntimeDirectoryPreserve=yes\nKillMode=control-group\nDelegate=yes\n[Install]\nWantedBy=multi-user.target\n";
#[cfg(target_os = "macos")]
const UNIT: &str = "/Library/LaunchDaemons/easytier-desk-host.plist";
#[cfg(target_os = "macos")]
const UNIT_CONTENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>easytier-desk-host</string><key>ProgramArguments</key><array><string>/Library/Application Support/easytier-desk/etd-host</string><string>run</string><string>--mode</string><string>service</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n";

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "untrusted service path or account",
    )
}
fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn protect_creation() {
    // Service state is private even when the installer inherited a permissive
    // user-session umask. The explicitly public install/run directories get
    // their exact mode in make(), after creation inside a trusted parent.
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
}

pub(super) fn elevated() -> io::Result<bool> {
    Ok(Uid::effective().is_root())
}
fn check(path: &Path, directory: bool) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || (if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "untrusted service path {} (uid {}, gid {}, mode {:04o}, expected {})",
                path.display(),
                meta.uid(),
                meta.gid(),
                meta.mode() & 0o7777,
                if directory {
                    "directory"
                } else {
                    "regular file"
                }
            ),
        ));
    }
    Ok(())
}
fn verify_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(denied)?.canonicalize()?;
    for ancestor in parent.ancestors() {
        check(ancestor, true)?;
    }
    Ok(())
}
fn make(path: &Path, mode: u32) -> io::Result<()> {
    verify_parent(path)?;
    let mut builder = fs::DirBuilder::new();
    builder.mode(mode).create(path)?;
    // A newly created directory in a validated root-owned parent is ours.
    // Set its exact final group and mode rather than inheriting an installer
    // session umask or the parent directory's group (e.g. macOS admin).
    nix::unistd::chown(
        path,
        Some(Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    )
    .map_err(other)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    check(path, true)
}
fn verify_tree(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        check(path, true)?;
        for entry in fs::read_dir(path)? {
            verify_tree(&entry?.path())?;
        }
    } else {
        check(path, false)?;
    }
    Ok(())
}

fn invoke(program: &str, args: &[&str]) -> io::Result<()> {
    let status = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(other(format!("{program} returned {status}")))
    }
}

#[cfg(target_os = "linux")]
pub fn group_id() -> io::Result<u32> {
    let group = Group::from_name(GROUP)
        .map_err(other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service group missing"))?;
    Ok(group.gid.as_raw())
}

#[cfg(target_os = "macos")]
pub fn group_id() -> io::Result<u32> {
    // Query the local directory node itself, not libc's potentially stale
    // positive/negative cache. A successful listing without our exact name
    // proves absence; a failed lookup does not.
    let result = Command::new("/usr/bin/dscl")
        .args(["/Local/Default", "-list", "/Groups", "PrimaryGroupID"])
        .env_clear()
        .output()?;
    if !result.status.success() {
        return Err(other(format!(
            "local DirectoryService group listing failed: {}",
            result.status
        )));
    }
    let listing = String::from_utf8(result.stdout).map_err(other)?;
    let mut found = None;
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some(GROUP) {
            continue;
        }
        let gid = fields
            .next()
            .ok_or_else(|| other("service group has no PrimaryGroupID"))?
            .parse::<u32>()
            .map_err(other)?;
        if found.replace(gid).is_some() {
            return Err(other("duplicate service group record"));
        }
    }
    found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service group missing"))
}

fn group_exists() -> io::Result<bool> {
    match group_id() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

// DirectoryService may acknowledge a macOS group change before libc's
// group lookup cache observes it. Poll the actual identity rather than
// assuming acknowledgement means success or weakening group verification.
#[cfg(target_os = "macos")]
fn await_group(present: bool) -> io::Result<Option<u32>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let local = match group_id() {
            Ok(gid) => Some(gid),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if !present && local.is_none() {
            return Ok(None);
        }
        if present
            && local.is_some()
            && Group::from_name(GROUP)
                .map_err(other)?
                .map(|group| group.gid.as_raw())
                == local
        {
            return Ok(local);
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DirectoryService did not publish the service group change",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn create_group(layout: &HostLayout, gid: u32) -> io::Result<()> {
    if group_exists()? || Group::from_name(GROUP).map_err(other)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service group already exists",
        ));
    }
    #[cfg(target_os = "linux")]
    invoke(
        "/usr/sbin/groupadd",
        &["--system", "--gid", &gid.to_string(), GROUP],
    )?;
    #[cfg(target_os = "macos")]
    invoke(
        "/usr/sbin/dseditgroup",
        &[
            "-o",
            "create",
            "-n",
            "/Local/Default",
            "-i",
            &gid.to_string(),
            GROUP,
        ],
    )?;
    #[cfg(target_os = "macos")]
    let observed = await_group(true)?.ok_or_else(denied)?;
    #[cfg(target_os = "linux")]
    let observed = group_id()?;
    if observed != gid {
        return Err(denied());
    }
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut record = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(layout.state.join(GROUP_RECORD))?;
    write!(record, "{gid}")?;
    record.sync_all()?;
    Ok(())
}

fn verify_group(layout: &HostLayout) -> io::Result<()> {
    let path = layout.state.join(GROUP_RECORD);
    check(&path, false)?;
    let recorded = fs::read_to_string(path)?.parse::<u32>().map_err(other)?;
    if recorded != group_id()? {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn prepare_maintenance(layout: &HostLayout) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    protect_creation();
    if let Some(parent) = layout.maintenance.parent()
        && !parent.try_exists()?
    {
        make(parent, 0o755)?;
    }
    if !layout.maintenance.try_exists()? {
        match make(&layout.maintenance, 0o700) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
    }
    verify_parent(&layout.maintenance)?;
    check(&layout.maintenance, true)?;
    if fs::symlink_metadata(&layout.maintenance)?.mode() & 0o7777 != 0o700 {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn preflight_install(layout: &HostLayout) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    let install = layout.executable.parent().ok_or_else(denied)?;
    let socket = layout.socket_dir.as_ref().ok_or_else(denied)?;
    // Check collisions before any creation. On macOS /var/lib may not exist.
    if layout.state.try_exists()?
        || install.try_exists()?
        || socket.try_exists()?
        || Path::new(UNIT).try_exists()?
        || group_exists()?
        || Group::from_name(GROUP).map_err(other)?.is_some()
        || service_loaded()?
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service installation paths or group already exist",
        ));
    }
    Ok(())
}

pub(super) fn prepare_install(
    layout: &HostLayout,
    journal: &mut LifecycleJournal,
) -> io::Result<()> {
    preflight_install(layout)?;
    protect_creation();
    #[cfg(target_os = "linux")]
    let mut source = File::open("/proc/self/exe")?;
    #[cfg(target_os = "macos")]
    let mut source = File::open(super::current_exe()?)?;
    let install = layout.executable.parent().ok_or_else(denied)?;
    let socket = layout.socket_dir.as_ref().ok_or_else(denied)?;
    journal.create(Resource::InstallDir, || make(install, 0o755))?;
    journal.create(Resource::StateDir, || make(&layout.state, 0o700))?;
    journal.create(Resource::RunDir, || make(&layout.run, 0o700))?;
    journal.create(Resource::CoreDir, || make(&layout.cores, 0o755))?;
    journal.create(Resource::SocketDir, || make(socket, 0o755))?;
    use std::os::unix::fs::OpenOptionsExt;
    journal.create(Resource::HostImage, || {
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&layout.executable)?;
        io::copy(&mut source, &mut target)?;
        target.sync_all()?;
        drop(target);
        fs::set_permissions(&layout.executable, fs::Permissions::from_mode(0o755))
    })?;
    // Reserve a concrete unused gid before group creation. A crash in the
    // create/record window can be rolled back only if both name and gid match.
    let mut gid = None;
    for candidate in 60000..65000 {
        if Group::from_gid(nix::unistd::Gid::from_raw(candidate))
            .map_err(other)?
            .is_none()
        {
            gid = Some(candidate);
            break;
        }
    }
    let gid = gid.ok_or_else(|| other("no available service group ID"))?;
    journal.set_group_gid(gid)?;
    journal.create(Resource::Group, || create_group(layout, gid))?;
    validate_service(layout)
}

pub(super) fn validate_service(layout: &HostLayout) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    protect_creation();
    let install = layout.executable.parent().ok_or_else(denied)?;
    verify_parent(&layout.state)?;
    verify_parent(install)?;
    verify_tree(&layout.state)?;
    // The socket directory is managed by systemd/launchd and may contain
    // a live socket rather than ordinary files. Validate it separately.
    check(install, true)?;
    check(&layout.executable, false)?;
    verify_tree(&layout.cores)?;
    verify_group(layout)?;
    if let Some(socket) = &layout.socket_dir
        && socket.try_exists()?
    {
        verify_parent(socket)?;
        check(socket, true)?;
    }
    Ok(())
}

fn verify_unit(partial_install: bool) -> io::Result<()> {
    let path = Path::new(UNIT);
    check(path, false)?;
    let content = fs::read_to_string(path)?;
    if content != UNIT_CONTENT && !(partial_install && UNIT_CONTENT.starts_with(&content)) {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn register(layout: &HostLayout) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    validate_service(layout)?;
    let path = Path::new(UNIT);
    verify_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(UNIT_CONTENT.as_bytes())?;
    file.sync_all()?;
    #[cfg(target_os = "linux")]
    {
        invoke("/usr/bin/systemctl", &["daemon-reload"])?;
        invoke(
            "/usr/bin/systemctl",
            &["enable", "easytier-desk-host.service"],
        )
    }
    #[cfg(target_os = "macos")]
    Ok(())
}

fn service_loaded() -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=LoadState",
                "--value",
                "easytier-desk-host.service",
            ])
            .env_clear()
            .output()?;
        if !output.status.success() {
            return Err(other(format!("systemctl query failed: {}", output.status)));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim() != "not-found")
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/bin/launchctl")
            .args(["print", "system/easytier-desk-host"])
            .env_clear()
            .output()?;
        if output.status.success() {
            return Ok(true);
        }
        if output.status.code() == Some(113)
            || String::from_utf8_lossy(&output.stderr).contains("Could not find service")
        {
            return Ok(false);
        }
        Err(other(format!("launchctl query failed: {}", output.status)))
    }
}

pub(super) fn start(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    verify_unit(false)?;
    #[cfg(target_os = "linux")]
    {
        invoke(
            "/usr/bin/systemctl",
            &["enable", "--now", "easytier-desk-host.service"],
        )
    }
    #[cfg(target_os = "macos")]
    {
        if service_loaded()? {
            Ok(())
        } else {
            invoke("/bin/launchctl", &["bootstrap", "system", UNIT])
        }
    }
}

pub(super) fn stop_and_disable(_: &HostLayout) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    if !Path::new(UNIT).try_exists()? {
        return if service_loaded()? {
            Err(denied())
        } else {
            Ok(())
        };
    }
    verify_unit(false)?;
    #[cfg(target_os = "linux")]
    {
        invoke(
            "/usr/bin/systemctl",
            &["disable", "--now", "easytier-desk-host.service"],
        )
    }
    #[cfg(target_os = "macos")]
    {
        if service_loaded()? {
            invoke("/bin/launchctl", &["bootout", "system", UNIT])
        } else {
            Ok(())
        }
    }
}

pub(super) fn unregister(layout: &HostLayout, partial_install: bool) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
    if Path::new(UNIT).try_exists()? {
        verify_unit(partial_install)?;
        if fs::read_to_string(UNIT)? == UNIT_CONTENT {
            stop_and_disable(layout)?;
        }
        fs::remove_file(UNIT)?;
    }
    #[cfg(target_os = "linux")]
    invoke("/usr/bin/systemctl", &["daemon-reload"])?;
    Ok(())
}

pub(super) fn remove_ipc_dir(layout: &HostLayout) -> io::Result<()> {
    if let Some(socket) = &layout.socket_dir
        && socket.try_exists()?
    {
        verify_parent(socket)?;
        check(socket, true)?;
        // The IPC adapter has already removed only proven stale sockets and
        // stages. Do not recursively delete any unrecognized leftover.
        fs::remove_dir(socket)?;
    }
    Ok(())
}
pub(super) fn remove_group(_: &HostLayout, gid: Option<u32>) -> io::Result<()> {
    let observed = match group_id() {
        Ok(value) => value,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if Some(observed) != gid {
        return Err(denied());
    }
    #[cfg(target_os = "linux")]
    invoke("/usr/sbin/groupdel", &[GROUP])?;
    #[cfg(target_os = "macos")]
    {
        invoke(
            "/usr/sbin/dseditgroup",
            &["-o", "delete", "-q", "-n", "/Local/Default", GROUP],
        )?;
        let _ = await_group(false)?;
    }
    Ok(())
}
fn remove_owned_tree(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    verify_parent(path)?;
    verify_tree(path)?;
    fs::remove_dir_all(path)
}
pub(super) fn remove_state(layout: &HostLayout) -> io::Result<()> {
    remove_owned_tree(&layout.state)
}
pub(super) fn remove_install(layout: &HostLayout) -> io::Result<()> {
    remove_owned_tree(layout.executable.parent().ok_or_else(denied)?)
}
pub(super) fn defer_install_removal(_: &HostLayout, _: &str) -> io::Result<bool> {
    Ok(false)
}
