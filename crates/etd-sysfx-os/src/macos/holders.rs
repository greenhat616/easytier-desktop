use super::observe::fields;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    net::SocketAddr,
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
            let relevant = if let Some(p) = n.strip_prefix("*:") {
                p.parse::<u16>().map_err(io::Error::other)? == port
            } else {
                let addr = n.parse::<SocketAddr>().map_err(io::Error::other)?;
                addr.port() == port && (addr.ip().is_loopback() || addr.ip().is_unspecified())
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
    fn scan(&self, port: u16) -> io::Result<Vec<Holder>> {
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
        if self.scan(port)? != first {
            return Err(io::Error::other(
                "listener identity changed before fence removal",
            ));
        }
        Ok(first)
    }
}
