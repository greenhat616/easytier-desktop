//! Per-link DNS over resolve1. A missing service (other resolver) owns no
//! resolve1 link state. Bus failures are errors; never rewrite resolv.conf.
use super::*;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zbus::{Connection, OwnedObjectPath, Proxy};

const SERVICE: &str = "org.freedesktop.resolve1";
const MANAGER: &str = "org.freedesktop.resolve1.Manager";
type Server = (i32, Vec<u8>, u16, String);

#[derive(Serialize, Deserialize)]
pub(super) struct Settings {
    dns: Vec<Server>,
    domains: Vec<(String, bool)>,
    default_route: bool,
    dns_over_tls: String,
    dnssec: String,
}
impl Settings {
    pub(super) fn empty(&self) -> bool {
        self.dns.is_empty() && self.domains.is_empty()
    }
}

async fn bounded<T>(operation: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resolve1 operation timed out"))?
}

pub(super) async fn manager(previously_seen: bool) -> io::Result<Option<Proxy<'static>>> {
    bounded(connect(previously_seen)).await
}
async fn connect(previously_seen: bool) -> io::Result<Option<Proxy<'static>>> {
    let conn = match Connection::system().await {
        Ok(conn) => conn,
        Err(zbus::Error::InputOutput(e) | zbus::Error::Connection(e, _))
            if e.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(e) => return Err(other(e)),
    };
    let bus = zbus::fdo::DBusProxy::new(&conn).await.map_err(other)?;
    // Pin the daemon for the entire read/compare/write operation. If it
    // restarts, a stale snapshot cannot authorize a call to the new owner.
    let owner = match bus.get_name_owner(SERVICE.try_into().map_err(other)?).await {
        Ok(owner) => owner,
        Err(zbus::fdo::Error::NameHasNoOwner(_)) => {
            if previously_seen
                || bus
                    .list_activatable_names()
                    .await
                    .map_err(other)?
                    .iter()
                    .any(|n| n.as_str() == SERVICE)
            {
                return Err(other("resolve1 has no current owner; retry after restart"));
            }
            return Ok(None);
        }
        Err(err) => return Err(other(err)),
    };
    Ok(Some(
        Proxy::new(&conn, owner, "/org/freedesktop/resolve1", MANAGER)
            .await
            .map_err(other)?,
    ))
}
async fn snapshot(manager: &Proxy<'_>, index: i32) -> io::Result<Option<Settings>> {
    let path: OwnedObjectPath = match manager.call("GetLink", &(index,)).await {
        Err(zbus::Error::MethodError(name, _, _))
            if name.as_str() == "org.freedesktop.resolve1.NoSuchLink" =>
        {
            return Ok(None);
        }
        r => r.map_err(other)?,
    };
    let link = Proxy::new(
        manager.connection(),
        manager.destination().clone(),
        path,
        "org.freedesktop.resolve1.Link",
    )
    .await
    .map_err(other)?;
    Ok(Some(Settings {
        dns: link.get_property("DNSEx").await.map_err(other)?,
        domains: link.get_property("Domains").await.map_err(other)?,
        default_route: link.get_property("DefaultRoute").await.map_err(other)?,
        dns_over_tls: link.get_property("DNSOverTLS").await.map_err(other)?,
        dnssec: link.get_property("DNSSEC").await.map_err(other)?,
    }))
}

pub(super) async fn read_from(
    manager: Option<&Proxy<'_>>,
    index: u32,
) -> io::Result<Option<Settings>> {
    let Some(m) = manager else { return Ok(None) };
    bounded(snapshot(m, index.try_into().map_err(other)?)).await
}

// RestoreIfOurs identifies just the ordered list of plain DNS servers.
// An extended endpoint (port or TLS name) is a different value.
fn dns_value(settings: &Settings) -> Option<SettingValue> {
    if settings.dns.is_empty() {
        return Some(SettingValue::Absent);
    }
    let mut values = Vec::new();
    for (family, bytes, port, name) in &settings.dns {
        if *port != 0 || !name.is_empty() {
            return None;
        }
        let addr: IpAddr = match *family {
            libc::AF_INET => Ipv4Addr::from(<[u8; 4]>::try_from(bytes.as_slice()).ok()?).into(),
            libc::AF_INET6 => Ipv6Addr::from(<[u8; 16]>::try_from(bytes.as_slice()).ok()?).into(),
            _ => return None,
        };
        values.push(addr.to_string());
    }
    Some(SettingValue::MultiString(values))
}
fn servers(v: &SettingValue) -> io::Result<Vec<(i32, Vec<u8>)>> {
    let list = match v {
        SettingValue::Absent => return Ok(Vec::new()),
        SettingValue::MultiString(list) => list,
        _ => return Err(other("expected DNS server list")),
    };
    list.iter()
        .map(|value| {
            Ok(match value.parse::<IpAddr>().map_err(other)? {
                IpAddr::V4(a) => (libc::AF_INET, a.octets().to_vec()),
                IpAddr::V6(a) => (libc::AF_INET6, a.octets().to_vec()),
            })
        })
        .collect()
}
pub(super) async fn restore(index: u32, undo: &Undo) -> Result<Reclaimed, ReclaimError> {
    tokio::time::timeout(Duration::from_secs(10), restore_link(index, undo))
        .await
        .map_err(|_| ReclaimError::Timeout)?
}
async fn restore_link(index: u32, undo: &Undo) -> Result<Reclaimed, ReclaimError> {
    let index = i32::try_from(index).map_err(uncertain)?;
    let Some(m) = manager(true).await.map_err(uncertain)? else {
        return Ok(Reclaimed::AlreadyAbsent);
    };
    let Some(now) = snapshot(&m, index).await.map_err(uncertain)? else {
        return Ok(Reclaimed::AlreadyAbsent);
    };
    match undo {
        Undo::EnsureAbsent => {
            if now.empty() {
                return Ok(Reclaimed::AlreadyAbsent);
            }
            m.call::<_, _, ()>("RevertLink", &(index,))
                .await
                .map_err(uncertain)?;
            Ok(Reclaimed::Removed)
        }
        Undo::RestoreIfOurs { ours, original } => {
            if dns_value(&now).as_ref() != Some(ours) {
                return Ok(Reclaimed::LeftModified);
            }
            let previous = servers(original).map_err(uncertain)?;
            m.call::<_, _, ()>("SetLinkDNS", &(index, previous))
                .await
                .map_err(uncertain)?;
            let after = snapshot(&m, index).await.map_err(uncertain)?;
            if after.as_ref().and_then(dns_value).as_ref() != Some(original) {
                return Err(uncertain("restored DNS did not read back"));
            }
            Ok(Reclaimed::Restored)
        }
        _ => Err(ReclaimError::Unsupported(EffectKind::LinuxResolvedLink)),
    }
}
