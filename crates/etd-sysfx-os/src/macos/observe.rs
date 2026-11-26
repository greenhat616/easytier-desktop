use super::{boot, command, observation, observe_error, output, pf};
use async_trait::async_trait;
use etd_sysfx::*;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) struct MacObserver {
    pub(super) run_dir: PathBuf,
}

// Darwin shortens netmasks by omitting trailing zeroes and can leave
// sa_family unspecified. Decode the prefix using the address's family.
fn address_bytes(sa: &[u8], family: i32) -> Option<IpAddr> {
    match family {
        libc::AF_INET => Some(IpAddr::from(<[u8; 4]>::try_from(sa.get(4..8)?).ok()?)),
        libc::AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(sa.get(8..24)?).ok()?)),
        _ => None,
    }
}
fn interfaces() -> io::Result<BTreeMap<String, InterfaceInfo>> {
    let boot = boot()?;
    let mut addresses = BTreeMap::<String, Vec<(IpAddr, u8)>>::new();
    let mut found = BTreeMap::new();
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes head on success. All pointers below
    // stay within that snapshot, which the guard releases on every exit.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Snapshot(*mut libc::ifaddrs);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Snapshot(head);
    while !head.is_null() {
        let row = unsafe { &*head };
        head = row.ifa_next;
        if row.ifa_addr.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(row.ifa_name) }
            .to_str()
            .map_err(io::Error::other)?
            .to_owned();
        let len = unsafe { usize::from(*row.ifa_addr.cast::<u8>()) };
        // Read exactly sa_len bytes, including for compressed sockaddr_dl.
        let bytes = unsafe { std::slice::from_raw_parts(row.ifa_addr.cast::<u8>(), len) };
        let Some(&family) = bytes.get(1) else {
            continue;
        };
        if i32::from(family) == libc::AF_LINK {
            let index = u16::from_ne_bytes(
                bytes
                    .get(2..4)
                    .ok_or_else(|| io::Error::other("short link address"))?
                    .try_into()
                    .unwrap(),
            );
            found.insert(
                name.clone(),
                InterfaceInfo {
                    name,
                    credential: Credential::UnixInterface {
                        index: u32::from(index),
                        boot: boot.clone(),
                    },
                    addresses: vec![],
                    up: row.ifa_flags & libc::IFF_UP as u32 != 0,
                },
            );
        } else if let Some(ip) = address_bytes(bytes, i32::from(family)) {
            if row.ifa_netmask.is_null() {
                return Err(io::Error::other("missing interface netmask"));
            }
            let len = unsafe { usize::from(*row.ifa_netmask.cast::<u8>()) };
            let input = unsafe { std::slice::from_raw_parts(row.ifa_netmask.cast::<u8>(), len) };
            let mut padded = [0u8; std::mem::size_of::<libc::sockaddr_storage>()];
            padded
                .get_mut(..len)
                .ok_or_else(|| io::Error::other("invalid netmask length"))?
                .copy_from_slice(input);
            let bits = match address_bytes(&padded, i32::from(family)).unwrap() {
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

pub(super) fn fields(args: &[&str], empty_ok: bool) -> io::Result<Vec<String>> {
    let result = super::capture(command("/usr/sbin/lsof").args(["-b", "-w"]).args(args))?;
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

// Read process identities from libproc. Starting a short-lived ps would
// introduce an extra process in every before/after system diff.
fn processes() -> io::Result<Vec<SystemEntry>> {
    let mut capacity = 512usize;
    let pids = loop {
        let mut pids = vec![0i32; capacity];
        let bytes =
            i32::try_from(std::mem::size_of_val(pids.as_slice())).map_err(io::Error::other)?;
        // SAFETY: libproc writes at most bytes to the initialized pid buffer.
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        if (count as usize) < capacity {
            pids.truncate(count as usize);
            break pids;
        }
        capacity = capacity
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("PID list too large"))?;
    };
    let mut entries = Vec::new();
    for pid in pids.into_iter().filter(|&pid| pid > 0) {
        // SAFETY: proc_bsdinfo consists of integer and fixed-size array fields.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        let count = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if count != size {
            let e = io::Error::last_os_error();
            if count <= 0 && e.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(io::Error::other(format!(
                "cannot read process identity for {pid}: {e}"
            )));
        }
        let name = if info.pbi_name[0] == 0 {
            &info.pbi_comm[..]
        } else {
            &info.pbi_name[..]
        };
        let bytes: Vec<_> = name
            .iter()
            .copied()
            .take_while(|&c| c != 0)
            .map(|c| c as u8)
            .collect();
        let name = String::from_utf8_lossy(&bytes).into_owned();
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let got = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        let exe = if got > 0 {
            use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
            PathBuf::from(OsStr::from_bytes(&path[..got as usize]))
        } else {
            PathBuf::from(&name)
        };
        let start = info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec;
        entries.push(entry(
            SystemClass::Processes,
            ObjectKey::Process {
                exe,
                cmdline_marker: PathBuf::new(),
            },
            Some(Credential::Process {
                pid: pid as u32,
                start_token: start.to_string(),
            }),
            name,
        ));
    }
    Ok(entries)
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
            let links = interfaces()?;
            for (iface, desc) in routes()? {
                let identity = links.get(&iface).map(|i| i.credential.clone());
                result.push(entry(
                    class,
                    ObjectKey::RoutesVia {
                        interface: Some(iface),
                    },
                    identity,
                    desc,
                ));
            }
        }
        SystemClass::FirewallRules => {
            // Include each anchor's actual table membership in consistency diffs.
            let anchors = output(command("/sbin/pfctl").args(["-v", "-s", "Anchors"]))?;
            for anchor in
                std::iter::once("").chain(anchors.lines().map(str::trim).filter(|s| !s.is_empty()))
            {
                for kind in ["rules", "nat", "Tables"] {
                    let mut cmd = command("/sbin/pfctl");
                    if !anchor.is_empty() {
                        cmd.args(["-a", anchor]);
                    }
                    for (i, line) in output(cmd.args(["-s", kind]))?.lines().enumerate() {
                        if kind == "Tables" {
                            let table = line.trim();
                            let mut query = command("/sbin/pfctl");
                            if !anchor.is_empty() {
                                query.args(["-a", anchor]);
                            }
                            let mut addresses: Vec<_> =
                                output(query.args(["-t", table, "-T", "show"]))?
                                    .lines()
                                    .map(|s| s.trim().to_owned())
                                    .collect();
                            addresses.sort();
                            result.push(group_entry(
                                class,
                                anchor,
                                &format!("table-{table}"),
                                addresses.join("\n"),
                            ));
                            continue;
                        }
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
        SystemClass::Processes => return processes(),
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
