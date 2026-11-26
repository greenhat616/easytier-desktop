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
const UNIT_CONTENT: &str = "[Unit]\nDescription=EasyTier Desktop Host\nAfter=network.target\n[Service]\nType=simple\nExecStart=/usr/local/lib/easytier-desk/etd-host run --mode service\nRestart=on-failure\nRuntimeDirectory=easytier-desk\nRuntimeDirectoryMode=0755\nKillMode=control-group\n[Install]\nWantedBy=multi-user.target\n";
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

pub(super) fn elevated() -> io::Result<bool> {
    Ok(Uid::effective().is_root())
}
pub(super) fn user_temp_runtime() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    let base = "/private/tmp";
    #[cfg(target_os = "linux")]
    let base = "/tmp";
    Ok(PathBuf::from(base).join(format!("easytier-desk-{}", Uid::effective().as_raw())))
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
        return Err(denied());
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

pub fn group_id() -> io::Result<u32> {
    let group = Group::from_name(GROUP)
        .map_err(other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service group missing"))?;
    Ok(group.gid.as_raw())
}

fn create_group(layout: &HostLayout) -> io::Result<()> {
    if Group::from_name(GROUP).map_err(other)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service group already exists",
        ));
    }
    #[cfg(target_os = "linux")]
    invoke("/usr/sbin/groupadd", &["--system", GROUP])?;
    #[cfg(target_os = "macos")]
    invoke(
        "/usr/sbin/dseditgroup",
        &["-o", "create", "-n", "/Local/Default", GROUP],
    )?;
    fs::write(layout.state.join(GROUP_RECORD), group_id()?.to_string())?;
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

pub(super) fn prepare_install(layout: &HostLayout) -> io::Result<()> {
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
        || Group::from_name(GROUP).map_err(other)?.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service installation paths or group already exist",
        ));
    }
    if let Some(parent) = layout.state.parent()
        && !parent.try_exists()?
    {
        make(parent, 0o755)?;
    }
    make(&layout.state, 0o700)?;
    make(install, 0o755)?;
    make(&layout.run, 0o700)?;
    make(&layout.cores, 0o755)?;
    make(socket, 0o755)?;
    fs::copy(super::current_exe()?, &layout.executable)?;
    fs::set_permissions(&layout.executable, fs::Permissions::from_mode(0o755))?;
    create_group(layout)?;
    validate_service(layout)
}

pub(super) fn validate_service(layout: &HostLayout) -> io::Result<()> {
    if !elevated()? {
        return Err(denied());
    }
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

fn verify_unit() -> io::Result<()> {
    let path = Path::new(UNIT);
    check(path, false)?;
    if fs::read_to_string(path)? != UNIT_CONTENT {
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
            &["enable", "--now", "easytier-desk-host.service"],
        )
    }
    #[cfg(target_os = "macos")]
    {
        invoke("/bin/launchctl", &["bootstrap", "system", UNIT])
    }
}

pub(super) fn stop_and_disable(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    verify_unit()?;
    #[cfg(target_os = "linux")]
    {
        invoke(
            "/usr/bin/systemctl",
            &["disable", "--now", "easytier-desk-host.service"],
        )
    }
    #[cfg(target_os = "macos")]
    {
        invoke("/bin/launchctl", &["bootout", "system", UNIT])
    }
}

pub(super) fn remove(layout: &HostLayout) -> io::Result<()> {
    validate_service(layout)?;
    verify_unit()?;
    verify_group(layout)?;
    fs::remove_file(UNIT)?;
    #[cfg(target_os = "linux")]
    {
        invoke("/usr/bin/systemctl", &["daemon-reload"])?;
        invoke("/usr/sbin/groupdel", &[GROUP])?;
    }
    #[cfg(target_os = "macos")]
    invoke(
        "/usr/sbin/dseditgroup",
        &["-o", "delete", "-n", "/Local/Default", GROUP],
    )?;
    if let Some(socket) = &layout.socket_dir
        && socket.try_exists()?
    {
        fs::remove_dir(socket)?;
    }
    fs::remove_dir_all(layout.executable.parent().ok_or_else(denied)?)?;
    fs::remove_dir_all(&layout.state)
}
