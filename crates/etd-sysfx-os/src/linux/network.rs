use super::*;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

const IP: &str = "/usr/sbin/ip";
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
    let boot = boot()?;
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
pub(super) async fn delete(index: u32) -> io::Result<()> {
    // Verify type before handing RTM_DELLINK the already credential-checked
    // index. The kernel never resolves the human-readable name for deletion.
    let dump = json(IP, &["-j", "-d", "link", "show"]).await?;
    let Some(link) = rows(&dump)?.iter().find(|l| l["ifindex"] == index) else {
        return Ok(());
    };
    if link["linkinfo"]["info_kind"] != "tun" || link["linkinfo"]["info_data"]["type"] != "tun" {
        return Err(other("link is not a Linux TUN"));
    }
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    handle.link().del(index).execute().await.map_err(other)
}

// /proc/net/tcp{,6} encodes each 32-bit address word in native byte order.
fn endpoint(raw: &str) -> io::Result<SocketAddr> {
    let (addr, port) = raw
        .split_once(':')
        .ok_or_else(|| other("invalid TCP endpoint"))?;
    let mut octets = Vec::new();
    for word in addr.as_bytes().chunks_exact(8) {
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

pub(super) fn sockets(address: SocketAddr) -> io::Result<BTreeSet<u64>> {
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
                return Err(other("wildcard listener on management port"));
            }
        }
    }
    Ok(inodes)
}

pub(super) fn listener(address: SocketAddr) -> io::Result<Option<ListenerInfo>> {
    let inodes = sockets(address)?;
    if inodes.is_empty() {
        return Ok(None);
    }
    if inodes.len() != 1 {
        return Err(other("multiple listening sockets"));
    }
    let target = PathBuf::from(format!("socket:[{}]", inodes.first().unwrap()));
    let mut owners = BTreeSet::new();
    let mut inaccessible = false;
    for p in fs::read_dir("/proc")? {
        let p = p?;
        let Some(pid) = p.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let fds = match fs::read_dir(p.path().join("fd")) {
            Ok(fds) => fds,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                inaccessible = true;
                continue;
            }
            Err(e) => return Err(e),
        };
        for fd in fds {
            match fs::read_link(fd?.path()) {
                Ok(v) if v == target => {
                    owners.insert(pid);
                    break;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    inaccessible = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
    if owners.len() != 1
        || (inaccessible && nix::unistd::Uid::effective().is_root())
        || sockets(address)? != inodes
    {
        return Err(other("listener ownership indeterminate"));
    }
    Ok(Some(ListenerInfo {
        address,
        pid: *owners.first().unwrap(),
    }))
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
