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
    pub image: PathBuf,
    device: u64,
    inode: u64,
    sockets: BTreeSet<String>,
    pub protected: bool,
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

fn holder(pid: i32, sockets: BTreeSet<String>, root: &Path, core_uid: u32) -> io::Result<Holder> {
    let info = bsd(pid)?;
    let image = image_path(pid)?;
    let named = fs::metadata(&image)?;
    let device = named.dev();
    let inode = named.ino();
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
    let protected = info.pbi_uid == core_uid && image.starts_with(root);
    Ok(Holder {
        pid,
        uid: info.pbi_uid,
        started: (info.pbi_start_tvsec, info.pbi_start_tvusec),
        image,
        device,
        inode,
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
        let root = self.store.canonicalize()?;
        let mut owners = vec![];
        for pid in pids {
            let mut owner = holder(pid, BTreeSet::new(), &root, self.uid)?;
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
            tracing::warn!(interface=name,pid=h.pid,euid=h.uid,image=%h.image.display(),"previous utun is gone; replacement left untouched");
        }
        Ok(true)
    }
    pub(super) fn scan(&self, port: u16) -> io::Result<Vec<Holder>> {
        let owners = sockets(port)?;
        if owners.is_empty() {
            return Ok(vec![]);
        }
        let root = self.store.canonicalize()?;
        owners
            .into_iter()
            .map(|(pid, sockets)| holder(pid, sockets, &root, self.uid))
            .collect()
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
fn generation_config(pid: i32) -> io::Result<Option<PathBuf>> {
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
