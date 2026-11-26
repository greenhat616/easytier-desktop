use super::{boot, command, observation, observe_error, output, pf};
use async_trait::async_trait;
use etd_sysfx::*;
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags, sys::socket::SockaddrStorage};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self},
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) struct MacObserver {
    pub(super) run_dir: PathBuf,
}

fn ip(addr: Option<&SockaddrStorage>) -> Option<IpAddr> {
    let addr = addr?;
    addr.as_sockaddr_in()
        .map(|a| IpAddr::V4(a.ip()))
        .or_else(|| addr.as_sockaddr_in6().map(|a| IpAddr::V6(a.ip())))
}
fn interfaces() -> io::Result<BTreeMap<String, InterfaceInfo>> {
    let boot = boot()?;
    let mut addresses = BTreeMap::<String, Vec<(IpAddr, u8)>>::new();
    let mut found = BTreeMap::new();
    for addr in getifaddrs()? {
        let name = addr.interface_name;
        if let Some(link) = addr.address.as_ref().and_then(|a| a.as_link_addr()) {
            found.insert(
                name.clone(),
                InterfaceInfo {
                    name,
                    credential: Credential::UnixInterface {
                        index: u32::try_from(link.ifindex()).map_err(io::Error::other)?,
                        boot: boot.clone(),
                    },
                    addresses: Vec::new(),
                    up: addr.flags.contains(InterfaceFlags::IFF_UP),
                },
            );
        } else if let (Some(ip), Some(mask)) =
            (ip(addr.address.as_ref()), ip(addr.netmask.as_ref()))
        {
            let bits = match mask {
                IpAddr::V4(a) => a.to_bits().count_ones(),
                IpAddr::V6(a) => a.to_bits().count_ones(),
            };
            addresses.entry(name).or_default().push((ip, bits as u8));
        }
    }
    for (name, mut ips) in addresses {
        ips.sort();
        ips.dedup();
        if let Some(iface) = found.get_mut(&name) {
            iface.addresses = ips;
        }
    }
    Ok(found)
}

fn fields(args: &[&str], empty_ok: bool) -> io::Result<Vec<String>> {
    let result = command("/usr/sbin/lsof").args(args).output()?;
    if !result.stderr.is_empty() || !result.status.success() {
        if empty_ok
            && result.status.code() == Some(1)
            && result.stdout.is_empty()
            && result.stderr.is_empty()
        {
            return Ok(vec![]);
        }
        return Err(io::Error::other(format!(
            "lsof {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        )));
    }
    // -F0 terminates fields with NUL and adds a newline between records.
    Ok(result
        .stdout
        .split(|b| *b == 0)
        .filter_map(|field| {
            let field = field.strip_prefix(b"\n").unwrap_or(field);
            (!field.is_empty()).then(|| String::from_utf8_lossy(field).into_owned())
        })
        .collect())
}
fn owned(pid: u32) -> io::Result<Vec<InterfaceInfo>> {
    // Darwin lsof decodes proc_pidinfo/PROC_PIDFDSOCKETINFO. Check the file
    // type as well as the control name; a pathname is never a control socket.
    let pid = pid.to_string();
    let mut system = false;
    let mut names = BTreeSet::new();
    for field in fields(&["-nP", "-p", &pid, "-F0pftn"], false)? {
        match field.as_bytes()[0] {
            b'f' | b'p' => system = false,
            b't' => system = field[1..].eq_ignore_ascii_case("systm"),
            b'n' if system => {
                if let Some(tail) = field.strip_prefix("n[ctl com.apple.net.utun_control id ") {
                    let unit = tail
                        .strip_suffix(']')
                        .and_then(|s| s.split_once(" unit "))
                        .and_then(|(id, n)| {
                            id.parse::<u32>().ok()?;
                            n.parse::<u32>().ok()?.checked_sub(1)
                        })
                        .ok_or_else(|| io::Error::other("invalid utun control unit"))?;
                    names.insert(format!("utun{unit}"));
                }
            }
            _ => {}
        }
    }
    let mut all = interfaces()?;
    Ok(names.iter().filter_map(|n| all.remove(n)).collect())
}
pub(super) fn listener(address: SocketAddr) -> io::Result<Option<ListenerInfo>> {
    let selector = format!(
        "-i{}TCP:{}",
        if address.is_ipv6() { 6 } else { 4 },
        address.port()
    );
    let mut pid = None;
    let mut matched = None;
    for field in fields(&["-nP", &selector, "-sTCP:LISTEN", "-F0pfn"], true)? {
        if let Some(p) = field.strip_prefix('p') {
            pid = Some(p.parse::<u32>().map_err(io::Error::other)?);
        }
        if let Some(n) = field.strip_prefix('n') {
            if n.starts_with("*:") {
                return Err(io::Error::other("wildcard management listener"));
            }
            let addr = n.parse::<SocketAddr>().map_err(io::Error::other)?;
            if addr == address {
                let p = pid.ok_or_else(|| io::Error::other("missing listener PID"))?;
                if matched.replace(p).is_some_and(|previous| previous != p) {
                    return Err(io::Error::other("ambiguous listener owner"));
                }
            }
        }
    }
    Ok(matched.map(|pid| ListenerInfo { address, pid }))
}

fn interface_key(name: &str) -> ObjectKey {
    ObjectKey::Interface {
        name: Some(name.into()),
        guid: None,
    }
}

fn routes() -> io::Result<Vec<(String, String)>> {
    let mut result = vec![];
    for family in ["inet", "inet6"] {
        let table = output(command("/usr/sbin/netstat").args(["-rn", "-f", family]))?;
        let mut lines = table.lines();
        let idx = lines
            .find(|s| s.starts_with("Destination"))
            .and_then(|s| s.split_whitespace().position(|f| f == "Netif"))
            .ok_or_else(|| io::Error::other("unknown netstat route table"))?;
        for line in lines.filter(|l| !l.trim().is_empty()) {
            let fields: Vec<_> = line.split_whitespace().collect();
            let iface = fields
                .get(idx)
                .ok_or_else(|| io::Error::other("missing route interface"))?;
            // Exclude the changing expiration countdown from consistency diffs.
            result.push((
                iface.to_string(),
                format!("{family} {}", fields[..=idx].join(" ")),
            ));
        }
    }
    Ok(result)
}
impl MacObserver {
    pub(super) fn read(
        kind: EffectKind,
        key: &ObjectKey,
    ) -> Result<Option<Observation>, ObserveError> {
        match (kind, key) {
            (EffectKind::MacFenceRule, ObjectKey::Fence { .. }) => {
                let rule = pf::Rule::from_key(key).map_err(observe_error)?;
                Ok(pf::rules()
                    .map_err(observe_error)?
                    .contains(&rule)
                    .then(|| {
                        observation(
                            key,
                            Credential::ExclusiveContainer {
                                container: pf::ANCHOR.into(),
                            },
                        )
                    }))
            }
            (
                EffectKind::MacUtun,
                ObjectKey::Interface {
                    name: Some(n),
                    guid: None,
                },
            )
            | (EffectKind::Route, ObjectKey::RoutesVia { interface: Some(n) })
                if n.strip_prefix("utun")
                    .is_some_and(|n| n.parse::<u32>().is_ok()) =>
            {
                if kind == EffectKind::Route
                    && !routes()
                        .map_err(observe_error)?
                        .iter()
                        .any(|(iface, _)| iface == n)
                {
                    return Ok(None);
                }
                let found = interfaces().map_err(observe_error)?.remove(n);
                if kind == EffectKind::Route && found.is_none() {
                    return Err(observe_error(io::Error::other(
                        "route exists without observable interface",
                    )));
                }
                Ok(found.map(|i| observation(key, i.credential)))
            }
            _ => Err(ObserveError::Unsupported(kind)),
        }
    }
}

fn entry(
    class: SystemClass,
    key: ObjectKey,
    identity: Option<Credential>,
    description: String,
) -> SystemEntry {
    SystemEntry {
        class,
        key,
        identity,
        description,
    }
}
fn file_id(m: &fs::Metadata) -> Credential {
    Credential::File {
        file_id: m.ino(),
        device: m.dev(),
    }
}
fn children(path: &Path) -> io::Result<Vec<PathBuf>> {
    match fs::read_dir(path) {
        Ok(entries) => entries.map(|e| e.map(|e| e.path())).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e),
    }
}
fn path_entry(
    class: SystemClass,
    path: PathBuf,
    m: &fs::Metadata,
    description: String,
) -> SystemEntry {
    entry(
        class,
        ObjectKey::Path { path },
        Some(file_id(m)),
        description,
    )
}
fn group_entry(class: SystemClass, group: &str, name: &str, description: String) -> SystemEntry {
    entry(
        class,
        ObjectKey::Rule {
            name: name.into(),
            group: Some(group.into()),
        },
        None,
        description,
    )
}

fn enumerate(class: SystemClass, run_dir: &Path) -> io::Result<Vec<SystemEntry>> {
    let mut result = vec![];
    match class {
        SystemClass::Interfaces => {
            for (name, iface) in interfaces()? {
                result.push(entry(
                    class,
                    interface_key(&name),
                    Some(iface.credential),
                    format!("up={} {:?}", iface.up, iface.addresses),
                ));
            }
        }
        SystemClass::Routes => {
            for (iface, desc) in routes()? {
                result.push(entry(
                    class,
                    ObjectKey::RoutesVia {
                        interface: Some(iface),
                    },
                    None,
                    desc,
                ));
            }
        }
        SystemClass::FirewallRules => {
            // Enumerate global and recursive rules as well as product identities.
            for anchor in ["", "*"] {
                for kind in ["rules", "nat", "Tables"] {
                    let mut cmd = command("/sbin/pfctl");
                    if !anchor.is_empty() {
                        cmd.args(["-a", anchor]);
                    }
                    for (i, line) in output(cmd.args(["-s", kind]))?.lines().enumerate() {
                        result.push(group_entry(
                            class,
                            anchor,
                            &format!("{kind}-{i}"),
                            line.into(),
                        ));
                    }
                }
            }
            for rule in pf::rules()? {
                result.push(entry(
                    class,
                    rule.key(),
                    Some(Credential::ExclusiveContainer {
                        container: pf::ANCHOR.into(),
                    }),
                    "IPv4 + IPv6 block non-root".into(),
                ));
            }
        }
        SystemClass::DnsPolicy => {
            result.push(group_entry(
                class,
                "SystemConfiguration",
                "dns",
                output(command("/usr/sbin/scutil").arg("--dns"))?,
            ));
            for path in children(Path::new("/etc/resolver"))? {
                let m = fs::symlink_metadata(&path)?;
                let desc = if m.is_file() {
                    let mut f = fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(&path)?;
                    if file_id(&f.metadata()?) != file_id(&m) {
                        return Err(io::Error::other("resolver changed during enumeration"));
                    }
                    let mut hash = Sha256::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        let n = std::io::Read::read(&mut f, &mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hash.update(&buf[..n]);
                    }
                    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
                } else if m.is_symlink() {
                    format!("symlink {:?}", fs::read_link(&path)?)
                } else {
                    format!("mode {}", m.mode())
                };
                result.push(path_entry(class, path, &m, desc));
            }
        }
        SystemClass::RuntimeDirs => {
            for instance in children(run_dir)? {
                if fs::symlink_metadata(&instance)?.is_dir() {
                    for epoch in children(&instance)? {
                        let m = fs::symlink_metadata(&epoch)?;
                        result.push(path_entry(class, epoch, &m, format!("mode {:o}", m.mode())));
                    }
                }
            }
        }
        SystemClass::Processes => {
            // comm contains the executable, not the potentially secret argv.
            for line in output(command("/bin/ps").args(["-axo", "pid=,lstart=,comm="]))?.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 7 {
                    return Err(io::Error::other("malformed process row"));
                }
                let pid = fields[0].parse::<u32>().map_err(io::Error::other)?;
                result.push(entry(
                    class,
                    ObjectKey::Process {
                        exe: PathBuf::from(fields[6..].join(" ")),
                        cmdline_marker: PathBuf::new(),
                    },
                    Some(Credential::Process {
                        pid,
                        start_token: fields[1..6].join(" "),
                    }),
                    fields[6..].join(" "),
                ));
            }
        }
        SystemClass::Services => {
            for line in output(command("/bin/launchctl").arg("list"))?
                .lines()
                .skip(1)
            {
                let label = line
                    .split_whitespace()
                    .nth(2)
                    .ok_or_else(|| io::Error::other("malformed service row"))?;
                result.push(entry(
                    class,
                    ObjectKey::Service { name: label.into() },
                    None,
                    label.into(),
                ));
            }
        }
        SystemClass::RegistryValues => {}
        _ => return Err(io::Error::other("unknown macOS enumeration class")),
    }
    Ok(result)
}

#[async_trait]
impl SystemObserver for MacObserver {
    async fn observe(
        &self,
        kind: EffectKind,
        key: &ObjectKey,
    ) -> Result<Option<Observation>, ObserveError> {
        let key = key.clone();
        tokio::task::spawn_blocking(move || Self::read(kind, &key))
            .await
            .map_err(|e| observe_error(io::Error::other(e)))?
    }
    async fn interface(&self, key: &ObjectKey) -> Result<Option<InterfaceInfo>, ObserveError> {
        let ObjectKey::Interface {
            name: Some(n),
            guid: None,
        } = key
        else {
            return Err(ObserveError::Unsupported(EffectKind::MacUtun));
        };
        let n = n.clone();
        blocking(move || Ok(interfaces()?.remove(&n))).await
    }
    async fn listener(&self, address: SocketAddr) -> Result<Option<ListenerInfo>, ObserveError> {
        blocking(move || listener(address)).await
    }
    async fn interfaces_owned_by(&self, pid: u32) -> Result<Vec<InterfaceInfo>, ObserveError> {
        blocking(move || owned(pid)).await
    }
    async fn enumerate(&self, class: SystemClass) -> Result<Vec<SystemEntry>, ObserveError> {
        let run_dir = self.run_dir.clone();
        blocking(move || enumerate(class, &run_dir)).await
    }
}
async fn blocking<T: Send + 'static>(
    task: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T, ObserveError> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|e| observe_error(io::Error::other(e)))?
        .map_err(observe_error)
}
