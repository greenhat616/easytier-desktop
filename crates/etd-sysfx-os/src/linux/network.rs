use super::*;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

const IP: &str = "ip";
#[derive(Deserialize)]
struct Address {
    local: IpAddr,
    prefixlen: u8,
}
#[derive(Deserialize)]
struct Link {
    ifname: String,
    ifindex: u32,
    flags: Vec<String>,
    addr_info: Vec<Address>,
}

pub(super) fn key(name: &str) -> ObjectKey {
    ObjectKey::Interface {
        name: Some(name.to_owned()),
        guid: None,
    }
}
pub(super) async fn links() -> io::Result<Vec<InterfaceInfo>> {
    let boot = blocking(boot).await?;
    let links: Vec<Link> =
        serde_json::from_str(&run(IP, &["-j", "address", "show"]).await?).map_err(other)?;
    Ok(links
        .into_iter()
        .map(|l| InterfaceInfo {
            name: l.ifname,
            credential: Credential::UnixInterface {
                index: l.ifindex,
                boot: boot.clone(),
            },
            addresses: l
                .addr_info
                .into_iter()
                .map(|a| (a.local, a.prefixlen))
                .collect(),
            up: l.flags.iter().any(|f| f == "UP"),
        })
        .collect())
}
pub(super) async fn routes() -> io::Result<Vec<Value>> {
    let mut all = Vec::new();
    for family in ["-4", "-6"] {
        for route in rows(&json(IP, &["-j", family, "route", "show", "table", "all"]).await?)? {
            let mut route = route.clone();
            route["family"] = family.into();
            all.push(route);
        }
    }
    Ok(all)
}
pub(super) fn via(route: &Value, name: &str) -> bool {
    route["dev"] == name
        || route["nexthops"]
            .as_array()
            .is_some_and(|hops| hops.iter().any(|h| h["dev"] == name))
}
pub(super) async fn delete(index: u32) -> io::Result<Reclaimed> {
    // Verify type before handing RTM_DELLINK the already credential-checked
    // index. The kernel never resolves the human-readable name for deletion.
    let dump = json(IP, &["-j", "-d", "link", "show"]).await?;
    let Some(link) = rows(&dump)?.iter().find(|l| l["ifindex"] == index) else {
        return Ok(Reclaimed::AlreadyAbsent);
    };
    if link["linkinfo"]["info_kind"] != "tun" || link["linkinfo"]["info_data"]["type"] != "tun" {
        return Err(other("link is not a Linux TUN"));
    }
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    match handle.link().del(index).execute().await {
        Ok(()) => Ok(Reclaimed::Removed),
        Err(rtnetlink::Error::NetlinkError(e))
            if e.code.is_some_and(|n| n.get() == -libc::ENODEV) =>
        {
            Ok(Reclaimed::AlreadyAbsent)
        }
        Err(e) => Err(other(e)),
    }
}

// /proc/net/tcp{,6} encodes each 32-bit address word in native byte order.
fn endpoint(raw: &str) -> io::Result<SocketAddr> {
    let (addr, port) = raw
        .split_once(':')
        .ok_or_else(|| other("invalid TCP endpoint"))?;
    let mut octets = Vec::new();
    for word in addr.as_bytes().as_chunks::<8>().0 {
        octets.extend(
            u32::from_str_radix(std::str::from_utf8(word).map_err(other)?, 16)
                .map_err(other)?
                .to_ne_bytes(),
        );
    }
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(octets).map_err(|_| other("invalid IPv4"))?,
        )),
        32 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(octets).map_err(|_| other("invalid IPv6"))?,
        )),
        _ => return Err(other("invalid TCP address")),
    };
    Ok(SocketAddr::new(
        ip,
        u16::from_str_radix(port, 16).map_err(other)?,
    ))
}

fn sockets(address: SocketAddr, include_wildcard: bool) -> io::Result<BTreeSet<u64>> {
    let mut inodes = BTreeSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let table = match fs::read_to_string(path) {
            Err(e) if path.ends_with('6') && e.kind() == io::ErrorKind::NotFound => continue,
            result => result?,
        };
        for row in table.lines().skip(1) {
            let cols: Vec<_> = row.split_whitespace().collect();
            if cols.len() < 10 {
                return Err(other("short /proc TCP row"));
            }
            if cols[3] != "0A" {
                continue;
            }
            let bound = endpoint(cols[1])?;
            if bound.port() != address.port() {
                continue;
            }
            let bound_ip = bound.ip().to_canonical();
            if bound_ip == address.ip() {
                inodes.insert(cols[9].parse().map_err(other)?);
            } else if bound_ip.is_unspecified() && (bound.is_ipv6() || address.is_ipv4()) {
                if !include_wildcard {
                    return Err(other("wildcard listener on management port"));
                }
                inodes.insert(cols[9].parse().map_err(other)?);
            }
        }
    }
    Ok(inodes)
}

// Pin each process directory during the descriptor scan. Its procfs magic
// links continue to refer to that process even if a numeric PID is recycled.
struct Owner {
    pid: u32,
    proc_dir: fs::File,
}
fn owners(inodes: &BTreeSet<u64>) -> io::Result<Vec<Owner>> {
    use std::os::fd::AsRawFd;
    let targets: BTreeMap<_, _> = inodes
        .iter()
        .map(|i| (PathBuf::from(format!("socket:[{i}]")), *i))
        .collect();
    let mut seen = BTreeSet::new();
    let mut owners = Vec::new();
    for p in fs::read_dir("/proc")? {
        let p = p?;
        let Some(pid) = p.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let proc_dir = match fs::File::open(p.path()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            r => r?,
        };
        let fds = match fs::read_dir(format!("/proc/self/fd/{}/fd", proc_dir.as_raw_fd())) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    && !nix::unistd::Uid::effective().is_root() =>
            {
                continue;
            }
            r => r?,
        };
        let mut holds = false;
        for fd in fds {
            let dest = match fs::read_link(fd?.path()) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e)
                    if e.kind() == io::ErrorKind::PermissionDenied
                        && !nix::unistd::Uid::effective().is_root() =>
                {
                    continue;
                }
                r => r?,
            };
            if let Some(index) = targets.get(&dest) {
                seen.insert(*index);
                holds = true;
            }
        }
        if holds {
            owners.push(Owner { pid, proc_dir });
        }
    }
    if &seen != inodes {
        return Err(other("listener owner is not visible"));
    }
    Ok(owners)
}
pub(super) fn listener(address: SocketAddr) -> io::Result<Option<ListenerInfo>> {
    let inodes = sockets(address, false)?;
    if inodes.is_empty() {
        return Ok(None);
    }
    if inodes.len() != 1 {
        return Err(other("multiple listening sockets"));
    }
    let owners = owners(&inodes)?;
    if owners.len() != 1 || sockets(address, false)? != inodes {
        return Err(other("listener ownership indeterminate"));
    }
    Ok(Some(ListenerInfo {
        address,
        pid: owners[0].pid,
    }))
}

pub(super) struct ListenerImage {
    pub pid: u32,
    pub exe: PathBuf,
    pub in_store: bool,
}
pub(super) fn listener_images(
    port: u16,
    store: &std::path::Path,
) -> io::Result<Vec<ListenerImage>> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let snapshot = || -> io::Result<_> {
        let mut inodes = sockets((Ipv4Addr::LOCALHOST, port).into(), true)?;
        inodes.extend(sockets((Ipv6Addr::LOCALHOST, port).into(), true)?);
        Ok(inodes)
    };
    let inodes = snapshot()?;
    if inodes.is_empty() {
        return Ok(Vec::new());
    }
    let root = store.canonicalize()?;
    let mut images = Vec::new();
    for owner in owners(&inodes)? {
        let magic = PathBuf::from(format!("/proc/self/fd/{}/exe", owner.proc_dir.as_raw_fd()));
        // Pin the running image and compare (device,inode) at its canonical
        // store path. argv[0], comm and the executable basename are irrelevant.
        let image = fs::File::open(&magic)?;
        let exe = fs::read_link(format!("/proc/self/fd/{}", image.as_raw_fd()))?;
        let in_store = exe.starts_with(&root);
        if in_store {
            let path = exe.canonicalize()?;
            let named = fs::metadata(&path)?;
            let running = image.metadata()?;
            if !path.starts_with(&root)
                || (named.dev(), named.ino()) != (running.dev(), running.ino())
            {
                return Err(other("core store path no longer names the listening image"));
            }
        }
        images.push(ListenerImage {
            pid: owner.pid,
            exe,
            in_store,
        });
    }
    if snapshot()? != inodes {
        return Err(other("listening sockets changed during image lookup"));
    }
    Ok(images)
}

pub(super) fn tun_names(pid: u32) -> io::Result<Vec<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fdinfo"))? {
        let data = match fs::read_to_string(entry?.path()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            result => result?,
        };
        names.extend(
            data.lines()
                .filter_map(|line| line.strip_prefix("iff:"))
                .map(|n| n.trim().to_owned()),
        );
    }
    Ok(names.into_iter().collect())
}
