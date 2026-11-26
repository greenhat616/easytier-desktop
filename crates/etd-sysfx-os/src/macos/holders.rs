use super::observe::fields;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    net::IpAddr,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

pub(super) struct CoreIdentity {
    pub store: PathBuf,
    pub uid: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Holder {
    pub pid: i32,
    pub uid: u32,
    started: (u64, u64),
    pub image: Option<PathBuf>,
    vnode: Option<(u64, u64)>,
    mapped: bool,
    sockets: BTreeSet<String>,
    pub protected: bool,
}

// Both scans are ordered by PID. Only core-UID listeners require a stable
// executable identity; other users can change their own executable paths.
fn same_listeners(before: &[Holder], after: &[Holder], core_uid: u32) -> bool {
    before.len() == after.len()
        && before.iter().zip(after).all(|(a, b)| {
            if a.uid == core_uid {
                a == b
            } else {
                a.pid == b.pid && a.uid == b.uid && a.started == b.started && a.sockets == b.sockets
            }
        })
}

// Include wildcard sockets in either family and retain every owner of a
// shared socket. Strict listener verification has a separate exact-bind rule.
fn sockets(port: u16) -> io::Result<BTreeMap<i32, BTreeSet<String>>> {
    let mut owners = BTreeMap::<i32, BTreeSet<String>>::new();
    let mut pid = None;
    let selector = format!("-iTCP:{port}");
    for f in fields(&["-nP", &selector, "-sTCP:LISTEN", "-F0pfn"], true)? {
        if let Some(p) = f.strip_prefix('p') {
            pid = Some(p.parse().map_err(io::Error::other)?);
        }
        if let Some(n) = f.strip_prefix('n') {
            let (host, service) = n
                .rsplit_once(':')
                .ok_or_else(|| io::Error::other("invalid TCP listener endpoint"))?;
            if service.parse::<u16>().map_err(io::Error::other)? != port {
                continue;
            }
            let relevant = if host == "*" {
                true
            } else {
                let host = host.trim_matches(['[', ']']);
                let ip = host
                    .split('%')
                    .next()
                    .unwrap_or(host)
                    .parse::<IpAddr>()
                    .map_err(io::Error::other)?
                    .to_canonical();
                ip.is_loopback() || ip.is_unspecified()
            };
            if relevant {
                owners
                    .entry(pid.ok_or_else(|| io::Error::other("listener has no PID"))?)
                    .or_default()
                    .insert(n.into());
            }
        }
    }
    Ok(owners)
}

fn image_path(pid: i32) -> io::Result<PathBuf> {
    let mut path = [0; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: libproc receives the length of the writable array.
    let got = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if got <= 0 {
        return Err(io::Error::last_os_error());
    }
    Path::new(std::ffi::OsStr::from_bytes(&path[..got as usize])).canonicalize()
}

fn bsd(pid: i32) -> io::Result<libc::proc_bsdinfo> {
    // SAFETY: proc_bsdinfo is POD; require a full kernel read.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    if unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) }
        != size
    {
        return Err(io::Error::other(format!(
            "cannot identify listening PID {pid}"
        )));
    }
    Ok(info)
}

fn check_mapped_vnode(pid: i32, (device, inode): (u64, u64)) -> io::Result<()> {
    // proc_pidpath locates the executable. Independently match the vnode
    // actually mapped as text, so replacing its pathname cannot confer ownership.
    let mut dev = None;
    let mut ino = None;
    let mut matched = false;
    for field in fields(
        &["-nP", "-a", "-p", &pid.to_string(), "-d", "txt", "-F0fDin"],
        false,
    )? {
        let (tag, value) = field.split_at(1);
        match tag {
            "f" => {
                dev = None;
                ino = None;
            }
            "D" => dev = u64::from_str_radix(value.trim_start_matches("0x"), 16).ok(),
            "i" => ino = value.parse::<u64>().ok(),
            _ => {}
        }
        if dev == Some(device) && ino == Some(inode) {
            matched = true;
        }
    }
    if !matched {
        return Err(io::Error::other(format!(
            "PID {pid} executable path and mapped vnode differ"
        )));
    }
    Ok(())
}

fn image_field<T>(required: bool, field: io::Result<T>) -> io::Result<Option<T>> {
    if required {
        field.map(Some)
    } else {
        Ok(field.ok())
    }
}

enum ImageCheck {
    Listener,
    UtunOwner,
}

fn holder(
    pid: i32,
    sockets: BTreeSet<String>,
    root: &Path,
    core_uid: u32,
    check: ImageCheck,
) -> io::Result<Holder> {
    let info = bsd(pid)?;
    let core_user = info.pbi_uid == core_uid;
    let required = core_user || matches!(check, ImageCheck::UtunOwner);
    // Only a process with the core's effective UID can own a protected listener.
    // Other listeners' image fields are best-effort diagnostics.
    let image = image_field(required, image_path(pid))?;
    let vnode = match &image {
        Some(path) => image_field(required, fs::metadata(path).map(|m| (m.dev(), m.ino())))?,
        None => None,
    };
    let mapped = match vnode {
        Some(id) => image_field(required, check_mapped_vnode(pid, id))?.is_some(),
        None => false,
    };
    let protected = if core_user {
        let store = root.canonicalize()?;
        image.as_ref().is_some_and(|p| p.starts_with(store))
    } else {
        false
    };
    Ok(Holder {
        pid,
        uid: info.pbi_uid,
        started: (info.pbi_start_tvsec, info.pbi_start_tvusec),
        image,
        vnode,
        mapped,
        sockets,
        protected,
    })
}

impl CoreIdentity {
    fn control_owners(
        &self,
        name: &str,
        credential: &etd_sysfx::Credential,
        run: &Path,
        epoch: &Path,
    ) -> io::Result<Vec<Holder>> {
        let pids = super::observe::utun_holders(name)?;
        if pids.is_empty() {
            return Err(io::Error::other(
                "present utun has no observable control socket owner",
            ));
        }
        let mut owners = vec![];
        for pid in pids {
            let mut owner = holder(
                pid,
                BTreeSet::new(),
                &self.store,
                self.uid,
                ImageCheck::UtunOwner,
            )?;
            if !super::observe::owned(pid as u32)?
                .iter()
                .any(|i| i.name == name && &i.credential == credential)
            {
                return Err(io::Error::other("utun or control socket owner changed"));
            }
            if owner.protected
                && let Some(config) = generation_config(pid)?
            {
                // An unrecognized profile stays protected. A -c file under
                // another instance/epoch of this host identifies a replacement.
                if let Some(parent) = config.parent()
                    && parent.starts_with(run)
                    && parent != epoch
                {
                    owner.protected = false;
                }
            }
            owners.push(owner);
        }
        Ok(owners)
    }
    pub(super) fn foreign_utun(
        &self,
        name: &str,
        credential: &etd_sysfx::Credential,
        run: &Path,
        epoch: &Path,
    ) -> io::Result<bool> {
        let first = self.control_owners(name, credential, run, epoch)?;
        if first.iter().any(|p| p.protected) {
            return Ok(false);
        }
        if self.control_owners(name, credential, run, epoch)? != first {
            return Err(io::Error::other("utun changed during ownership check"));
        }
        for h in first {
            tracing::warn!(interface=name,pid=h.pid,euid=h.uid,image=?h.image,"previous utun is gone; replacement left untouched");
        }
        Ok(true)
    }
    fn scan(&self, port: u16) -> io::Result<Vec<Holder>> {
        let owners = sockets(port)?;
        if owners.is_empty() {
            return Ok(vec![]);
        }
        owners
            .into_iter()
            .map(|(pid, sockets)| holder(pid, sockets, &self.store, self.uid, ImageCheck::Listener))
            .collect()
    }
    pub(super) fn confirm_removal(&self, port: u16, before: &[Holder]) -> io::Result<()> {
        if !same_listeners(before, &self.scan(port)?, self.uid) {
            return Err(io::Error::other(
                "listener identity changed before fence removal",
            ));
        }
        Ok(())
    }
    pub(super) fn before_removal(&self, port: u16) -> io::Result<Vec<Holder>> {
        let first = self.scan(port)?;
        if first.iter().any(|h| h.protected) {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "protected kernel still listens on the management port",
            ));
        }
        Ok(first)
    }
}

// The launch planner passes an absolute configuration path with -c. Read
// exactly argc arguments, never interpret environment strings as arguments.
pub(super) fn generation_config(pid: i32) -> io::Result<Option<PathBuf>> {
    let mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = 0usize;
    // SAFETY: read-only sysctl, first size then a buffer of that size.
    if unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = vec![0; size];
    if unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            3,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let invalid = || io::Error::other("invalid kernel argv snapshot");
    let (argc, data) = bytes[..size].split_at_checked(4).ok_or_else(invalid)?;
    let argc =
        usize::try_from(i32::from_ne_bytes(argc.try_into().unwrap())).map_err(io::Error::other)?;
    let data = &data[data.iter().position(|&b| b == 0).ok_or_else(invalid)?..];
    let mut args = &data[data.iter().position(|&b| b != 0).ok_or_else(invalid)?..];
    let mut config = false;
    for _ in 0..argc {
        let end = args.iter().position(|&b| b == 0).ok_or_else(invalid)?;
        let arg = &args[..end];
        if config {
            return Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(arg))));
        }
        config = arg == b"-c";
        args = &args[end + 1..];
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};

    #[test]
    fn listener_rescan_requires_stable_image_only_for_core_uid() {
        let core_uid = 501;
        let snapshot = |uid| Holder {
            pid: 42,
            uid,
            started: (1000, 3),
            image: Some("listener".into()),
            vnode: Some((4, 12)),
            mapped: true,
            sockets: BTreeSet::from(["127.0.0.1:8080".into()]),
            protected: false,
        };
        let before = [snapshot(502)];
        let mut after = [snapshot(502)];
        after[0].image = None;
        after[0].vnode = None;
        after[0].mapped = false;
        assert!(same_listeners(&before, &after, core_uid));
        after[0].pid += 1;
        assert!(!same_listeners(&before, &after, core_uid));
        after[0].pid = before[0].pid;
        after[0].started.1 += 1;
        assert!(!same_listeners(&before, &after, core_uid));
        after[0].started = before[0].started;
        after[0].uid = core_uid;
        assert!(!same_listeners(&before, &after, core_uid));
        after[0].uid = 502;
        after[0].sockets.clear();
        assert!(!same_listeners(&before, &after, core_uid));
        assert!(!same_listeners(&before, &[], core_uid));

        let before = [snapshot(core_uid)];
        let mut after = [snapshot(core_uid)];
        assert!(same_listeners(&before, &after, core_uid));
        after[0].mapped = false;
        assert!(!same_listeners(&before, &after, core_uid));
    }

    #[test]
    #[ignore = "disposable macOS runner with a second account"]
    fn missing_image_preserves_foreign_identity_and_fails_closed_for_core_uid() {
        assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
        let user = nix::unistd::User::from_name("etd_o3_probe")
            .unwrap()
            .unwrap();
        assert!(!user.uid.is_root());
        let store = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = store.path().join("sleeper");
        fs::copy("/bin/sleep", &path).unwrap();
        let mut child = std::process::Command::new(&path)
            .arg("60")
            .uid(user.uid.as_raw())
            .gid(user.gid.as_raw())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        fs::remove_file(path).unwrap();
        let snapshot = |core_uid| {
            holder(
                pid,
                BTreeSet::new(),
                store.path(),
                core_uid,
                ImageCheck::Listener,
            )
        };
        let first = snapshot(0);
        let second = snapshot(0);
        let required = snapshot(user.uid.as_raw());
        child.kill().unwrap();
        child.wait().unwrap();

        let first = first.unwrap();
        assert_eq!(first.uid, user.uid.as_raw());
        assert!(!first.mapped && !first.protected);
        assert_eq!(first, second.unwrap());
        assert!(required.is_err());
    }
}
