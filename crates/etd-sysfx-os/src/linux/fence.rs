use super::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

pub(super) const NFT: &str = "nft";
const PREFIX: &str = "etd_f_";
const MARK: &str = "easytier-desk rpc fence v1";
const CHAIN: &str = "output";
fn object(spec: &FenceSpec) -> ObjectKey {
    let generation = format!("{}:{}", spec.instance.as_str(), spec.epoch.0);
    let id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, generation.as_bytes()).simple();
    let port = spec.address.port();
    ObjectKey::Fence {
        container: format!("{PREFIX}{id}_{port}"),
        rule: CHAIN.into(),
        port,
    }
}
fn parse_table(name: &str) -> Option<u16> {
    let (id, suffix) = name.strip_prefix(PREFIX)?.split_once('_')?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let port = suffix.parse::<u16>().ok()?;
    (port > 0 && port.to_string() == suffix).then_some(port)
}
fn parts(key: &ObjectKey) -> io::Result<(&str, u16)> {
    match key {
        ObjectKey::Fence {
            container,
            rule,
            port,
        } if rule == CHAIN && parse_table(container) == Some(*port) => Ok((container, *port)),
        _ => Err(other("invalid Linux fence key")),
    }
}
fn validate(spec: &FenceSpec) -> Result<(), FenceError> {
    if spec.address.port() == 0
        || ![
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            Ipv6Addr::LOCALHOST.into(),
        ]
        .contains(&spec.address.ip())
    {
        return Err(FenceError::Unsupported(
            "expected a canonical loopback endpoint with a fixed port".into(),
        ));
    }
    Ok(())
}

pub(super) async fn ruleset() -> io::Result<Vec<Value>> {
    let value = json(NFT, &["-j", "-a", "-n", "list", "ruleset"]).await?;
    Ok(rows(&value["nftables"])?.clone())
}
struct Table {
    handle: u64,
    rules: [u64; 2],
    packets: [u64; 2],
}
impl Table {
    fn observation(&self, key: &ObjectKey, name: &str) -> Observation {
        observed(
            key,
            Credential::ExclusiveContainer {
                container: name.into(),
            },
            Some(format!(
                "inet table handle {}, IPv4/IPv6 rule handles {:?}",
                self.handle, self.rules
            )),
        )
    }
}
/// Our generation table without its chain or both rules, in a listing
/// that succeeded.
#[derive(Debug)]
struct Incomplete;
impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("incomplete fence table")
    }
}
impl std::error::Error for Incomplete {}

/// The fence as a successful listing shows it: an absent table, or one
/// without its chain or rules, is positively missing
/// ([`FenceError::Missing`]); a listing that failed stays an OS error.
fn present(found: io::Result<Option<Table>>) -> Result<Table, FenceError> {
    match found {
        Ok(Some(table)) => Ok(table),
        Ok(None) => Err(FenceError::Missing("fence table absent".into())),
        Err(e) if e.get_ref().is_some_and(|inner| inner.is::<Incomplete>()) => {
            Err(FenceError::Missing(e.to_string()))
        }
        Err(e) => Err(error(e)),
    }
}

fn header<'a>(all: &'a [Value], name: &str) -> Option<&'a Value> {
    all.iter()
        .map(|row| &row["table"])
        .find(|t| t["family"] == "inet" && t["name"] == name)
}

// Debian 12 nft 1.0.6 omits table userdata from JSON. Its native listing
// exposes the table comment. Bind that read to the same kernel handle and
// accept only the marker in the table declaration (never a rule comment).
fn native_marker(text: &str, name: &str, handle: u64) -> bool {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let heading = format!("table inet {name} {{ # handle {handle}");
    let marker = format!("comment \"{MARK}\"");
    lines.next() == Some(heading.as_str())
        && lines
            .next()
            .is_some_and(|l| l.trim_end_matches(';') == marker)
        && lines
            .next()
            .is_some_and(|l| l.starts_with("chain output { # handle "))
}

async fn lookup(all: &[Value], name: &str) -> io::Result<Option<Table>> {
    let native = if header(all, name).is_some_and(|h| h["comment"].is_null()) {
        Some(run(NFT, &["-a", "-n", "list", "table", "inet", name]).await?)
    } else {
        None
    };
    inspect(all, name, native.as_deref())
}
fn inspect(all: &[Value], name: &str, native: Option<&str>) -> io::Result<Option<Table>> {
    let port = parse_table(name).ok_or_else(|| other("invalid generation table"))?;
    let Some(table) = header(all, name) else {
        return Ok(None);
    };
    let handle = table["handle"]
        .as_u64()
        .ok_or_else(|| other("missing table handle"))?;
    let marked = match table["comment"].as_str() {
        Some(comment) => comment == MARK,
        None if table["comment"].is_null() => {
            native.is_some_and(|s| native_marker(s, name, handle))
        }
        _ => false,
    };
    if !marked || table["flags"].as_array().is_some_and(|f| !f.is_empty()) {
        return Err(other("nft table ownership marker differs"));
    }
    let mut rules = [0; 2];
    let mut packets = [0; 2];
    let mut chain = false;
    for row in all {
        let (kind, item) = row
            .as_object()
            .and_then(|o| o.iter().next())
            .ok_or_else(|| other("invalid nft object"))?;
        if item["family"] != "inet" || item["table"] != name {
            continue;
        }
        match kind.as_str() {
            "chain"
                if item["name"] == CHAIN
                    && item["type"] == "filter"
                    && item["hook"] == "output"
                    && item["prio"] == -150
                    && item["policy"] == "accept" =>
            {
                chain = true
            }
            "rule" if item["chain"] == CHAIN => {
                let slot = match item["comment"].as_str() {
                    Some("etd-rpc-v4") => 0,
                    Some("etd-rpc-v6") => 1,
                    _ => return Err(other("unexpected nft rule")),
                };
                if rules[slot] != 0 {
                    return Err(other("duplicate nft rule"));
                }
                let (protocol, address) = if slot == 0 {
                    ("ip", "127.0.0.1")
                } else {
                    ("ip6", "::1")
                };
                let expressions = rows(&item["expr"])?;
                let [dst, dport, skuid, count, verdict] = expressions.as_slice() else {
                    return Err(other("unexpected fence expression count"));
                };
                let payload = |protocol, field, right: Value| {
                    serde_json::json!({
                        "match":{"op":"==","left":{"payload":{"protocol":protocol,"field":field}},"right":right}
                    })
                };
                if *dst != payload(protocol, "daddr", address.into())
                    || *dport != payload("tcp", "dport", port.into())
                    || *skuid
                        != serde_json::json!({"match":{"op":"!=","left":{"meta":{"key":"skuid"}},"right":0}})
                    || verdict["reject"]["type"] != "tcp reset"
                {
                    return Err(other("generation rule differs from the planned fence"));
                }
                rules[slot] = item["handle"]
                    .as_u64()
                    .ok_or_else(|| other("missing nft rule handle"))?;
                packets[slot] = count["counter"]["packets"]
                    .as_u64()
                    .ok_or_else(|| other("missing nft counter"))?;
            }
            _ => return Err(other("foreign object in fence table")),
        }
    }
    if !chain || rules.contains(&0) {
        return Err(io::Error::other(Incomplete));
    }
    Ok(Some(Table {
        handle,
        rules,
        packets,
    }))
}
pub(super) async fn observe(key: &ObjectKey) -> io::Result<Option<Observation>> {
    let (name, _) = parts(key)?;
    Ok(lookup(&ruleset().await?, name)
        .await?
        .map(|t| t.observation(key, name)))
}
pub(super) async fn sweep() -> io::Result<Vec<FoundObject>> {
    let all = ruleset().await?;
    let mut found = Vec::new();
    for row in &all {
        let t = &row["table"];
        if t["family"] != "inet" {
            continue;
        }
        let Some(name) = t["name"].as_str() else {
            continue;
        };
        let Some(port) = parse_table(name) else {
            continue;
        };
        if t["comment"].as_str().is_some_and(|c| c != MARK) {
            continue;
        }
        let table = match lookup(&all, name).await {
            Ok(t) => t,
            Err(error) => {
                tracing::warn!(table=name,port,%error,"skipped unverified fence table during sweep");
                continue;
            }
        };
        if let Some(table) = table {
            let key = ObjectKey::Fence {
                container: name.into(),
                rule: CHAIN.into(),
                port,
            };
            found.push(FoundObject {
                kind: EffectKind::LinuxFenceRule,
                observation: table.observation(&key, name),
                key,
                origin: FoundBy::ExclusiveContainer,
            });
        }
    }
    Ok(found)
}
// Service-mode cores run as root. Keep this separate from the identity of
// the caller so that a dedicated core account can be supplied in the future.
const SERVICE_CORE_UID: u32 = 0;

fn listeners_for_removal(
    port: u16,
    mut scan: impl FnMut() -> io::Result<Vec<network::ListenerImage>>,
) -> Result<Vec<network::ListenerImage>, ReclaimError> {
    let first = scan().map_err(uncertain)?;
    if let Some(core) = first.iter().find(|l| l.protected) {
        return Err(ReclaimError::Busy(format!(
            "protected core PID {} still listens on {port}",
            core.pid
        )));
    }
    // A listener can survive exec or be inherited by another process without
    // its socket inode changing. Reopen procfs and compare every holder.
    if scan().map_err(uncertain)? != first {
        return Err(uncertain("listener identity changed before fence removal"));
    }
    Ok(first)
}

impl Linux {
    pub(super) async fn remove_fence(
        &self,
        key: &ObjectKey,
        generation: Option<(&InstanceId, Epoch)>,
    ) -> Result<Reclaimed, ReclaimError> {
        let (table, port) = parts(key).map_err(uncertain)?;
        let Some(t) = lookup(&ruleset().await.map_err(uncertain)?, table)
            .await
            .map_err(uncertain)?
        else {
            return Ok(Reclaimed::AlreadyAbsent);
        };
        let store = self.core_store_dir.clone();
        let listeners = tokio::task::spawn_blocking(move || {
            listeners_for_removal(port, || {
                network::listener_images(port, &store, SERVICE_CORE_UID)
            })
        })
        .await
        .map_err(uncertain)??;
        run(
            NFT,
            &["delete", "table", "inet", "handle", &t.handle.to_string()],
        )
        .await
        .map_err(uncertain)?;
        for listener in listeners {
            tracing::warn!(instance=generation.map(|(i,_)|i.as_str()),epoch=generation.map(|(_,e)|e.0),
            port,pid=listener.pid,euid=listener.euid,exe=%listener.exe.display(),table,"reclaimed fence; unrelated listener left running");
        }
        Ok(Reclaimed::Removed)
    }
}
fn error(e: impl std::fmt::Display) -> FenceError {
    FenceError::Os {
        code: -1,
        message: e.to_string(),
    }
}
async fn host(addr: SocketAddr) -> DirectionResult {
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => DirectionResult::Connected,
        Ok(Err(e)) => DirectionResult::Error(e.to_string()),
        Err(_) => DirectionResult::Error("timeout".into()),
    }
}
// nft meta skuid reads the fsuid captured by the socket file at creation.
async fn dropped(addr: SocketAddr) -> Result<DirectionResult, FenceError> {
    use nix::unistd::{Uid, setfsuid};
    use tokio::net::TcpSocket;
    let (send, recv) = tokio::sync::oneshot::channel();
    // Never lend a runtime worker altered credentials, even on cancellation.
    std::thread::Builder::new()
        .name("etd-fence-probe".into())
        .spawn(move || {
            let probe = Uid::from_raw(65534);
            let prior = setfsuid(probe);
            let result = if setfsuid(probe) != probe || !prior.is_root() {
                Err(other("could not establish the probe fsuid"))
            } else if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            };
            setfsuid(prior);
            let result = if setfsuid(prior) == prior {
                result
            } else {
                Err(other("could not restore probe thread fsuid"))
            };
            let _ = send.send(result);
        })
        .map_err(|e| FenceError::Probe(e.to_string()))?;
    let socket = recv
        .await
        .map_err(|e| FenceError::Probe(e.to_string()))?
        .map_err(|e| FenceError::Probe(e.to_string()))?;
    Ok(
        match tokio::time::timeout(Duration::from_secs(2), socket.connect(addr)).await {
            Ok(Ok(_)) => DirectionResult::Connected,
            Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) => DirectionResult::Refused,
            Ok(Err(e)) => DirectionResult::Error(e.to_string()),
            Err(_) => DirectionResult::Error("timeout".into()),
        },
    )
}

#[async_trait]
impl PortFence for Linux {
    fn plan(&self, spec: &FenceSpec) -> EffectIntent {
        EffectIntent {
            scope: EffectScope::Instance {
                instance: spec.instance.clone(),
                epoch: spec.epoch,
            },
            kind: EffectKind::LinuxFenceRule,
            key: object(spec),
            undo: Undo::EnsureAbsent,
            persistence: Persistence::Persistent,
        }
    }
    async fn install(&self, spec: &FenceSpec) -> Result<Observation, FenceError> {
        validate(spec)?;
        if !nix::unistd::Uid::effective().is_root() {
            return Err(FenceError::PermissionDenied(
                "RPC fence requires the root host identity".into(),
            ));
        }
        let key = object(spec);
        let (name, port) = parts(&key).map_err(error)?;
        // create (exclusive), chain and rules are one netlink transaction.
        // A retry after a successful install adopts only a marked container.
        let transaction = format!(
            r#"create table inet {name} {{ comment "{MARK}"; }}
add chain inet {name} output {{ type filter hook output priority -150; policy accept; }}
add rule inet {name} output ip daddr 127.0.0.1 tcp dport {port} meta skuid != 0 counter reject with tcp reset comment "etd-rpc-v4"
add rule inet {name} output ip6 daddr ::1 tcp dport {port} meta skuid != 0 counter reject with tcp reset comment "etd-rpc-v6""#
        );
        let result = run(NFT, &[&transaction]).await;
        observe(&key).await.map_err(error)?.ok_or_else(|| {
            error(result.err().map_or_else(
                || "fence missing after install".to_string(),
                |e| e.to_string(),
            ))
        })
    }
    async fn verify(&self, spec: &FenceSpec, pid: u32) -> Result<FenceVerification, FenceError> {
        validate(spec)?;
        let addr = spec.address;
        let key = object(spec);
        let (name, _) = parts(&key).map_err(error)?;
        let before = present(lookup(&ruleset().await.map_err(error)?, name).await)?;
        let check = |found: io::Result<Option<ListenerInfo>>| match found {
            Ok(Some(l)) if l.pid == pid => ListenerCheck::Expected,
            Ok(Some(l)) => ListenerCheck::Other { pid: l.pid },
            Ok(None) => ListenerCheck::NotListening,
            Err(e) => ListenerCheck::Indeterminate(e.to_string()),
        };
        let mut result = FenceVerification {
            listener: check(blocking(move || network::listener(addr)).await),
            host: DirectionResult::NoListener,
            unprivileged: DirectionResult::NoListener,
        };
        if result.listener != ListenerCheck::Expected {
            return Ok(result);
        }
        result.host = host(addr).await;
        if result.host != DirectionResult::Connected {
            return Ok(result);
        }
        result.unprivileged = dropped(addr).await?;
        result.listener = check(blocking(move || network::listener(addr)).await);
        result.host = host(addr).await;
        let after = present(lookup(&ruleset().await.map_err(error)?, name).await)?;
        let slot = usize::from(addr.is_ipv6());
        if before.handle != after.handle
            || before.rules != after.rules
            || (result.unprivileged == DirectionResult::Refused
                && after.packets[slot] <= before.packets[slot])
        {
            return Err(FenceError::Probe(
                "refusal not confirmed by this fence".into(),
            ));
        }
        Ok(result)
    }
    async fn remove(&self, spec: &FenceSpec) -> Result<Reclaimed, FenceError> {
        validate(spec)?;
        self.remove_fence(&object(spec), Some((&spec.instance, spec.epoch)))
            .await
            .map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_without_our_fence_is_missing_not_a_failed_query() {
        let spec = FenceSpec {
            instance: InstanceId::from("missing"),
            epoch: Epoch(1),
            address: ([127, 0, 0, 1], 15888).into(),
        };
        let key = object(&spec);
        let (name, _) = parts(&key).unwrap();
        // No table of ours in a successful listing.
        assert!(matches!(
            present(inspect(&[], name, None)),
            Err(FenceError::Missing(_))
        ));
        // Our table, but its chain and rules are gone.
        let header_only = vec![serde_json::json!({
            "table": {"family": "inet", "name": name, "handle": 7, "comment": MARK}
        })];
        assert!(matches!(
            present(inspect(&header_only, name, None)),
            Err(FenceError::Missing(_))
        ));
        // A listing that failed proves nothing.
        assert!(matches!(
            present(Err(io::Error::other("nft exited with status 1"))),
            Err(FenceError::Os { .. })
        ));
    }

    #[test]
    fn removal_rechecks_holders_of_the_same_socket() {
        use std::{net::TcpListener, os::fd::OwnedFd};
        let store = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = None;
        let result = listeners_for_removal(port, || {
            let images = network::listener_images(port, store.path(), SERVICE_CORE_UID)?;
            if child.is_none() {
                // The parent retains its descriptor. Only the set of holders
                // changes between the two independent procfs scans.
                child = Some(
                    std::process::Command::new("/bin/sleep")
                        .arg("60")
                        .stdin(OwnedFd::from(listener.try_clone()?))
                        .spawn()?,
                );
            }
            Ok(images)
        });
        let mut child = child.expect("completed initial scan");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            matches!(result, Err(ReclaimError::Indeterminate(ref why)) if why.contains("listener identity changed"))
        );
    }

    #[tokio::test]
    #[ignore = "populates the private CI network namespace for distro nft to enumerate"]
    async fn install_distribution_fixture() {
        assert_eq!(std::env::var("ETD_O2_DISTRO_FIXTURE").as_deref(), Ok("1"));
        let dir = tempfile::tempdir().unwrap();
        let os = Linux {
            run_dir: dir.path().into(),
            core_store_dir: dir.path().into(),
        };
        let s = FenceSpec {
            instance: InstanceId::from("distribution-parser"),
            epoch: Epoch(1),
            address: ([127, 0, 0, 1], 15888).into(),
        };
        os.install(&s).await.unwrap();
    }
    #[test]
    #[ignore = "reads the nft JSON produced by a distribution compatibility job"]
    fn parse_distribution_ruleset() {
        let file = std::env::var_os("ETD_O2_RULESET").expect("CI ruleset path");
        let value: Value = serde_json::from_reader(std::fs::File::open(file).unwrap()).unwrap();
        let all = rows(&value["nftables"]).unwrap();
        let tables: Vec<_> = all
            .iter()
            .filter_map(|r| r["table"]["name"].as_str())
            .filter(|n| parse_table(n).is_some())
            .collect();
        assert_eq!(tables.len(), 1);
        let native =
            std::fs::read_to_string(std::env::var_os("ETD_O2_TABLE_LIST").unwrap()).unwrap();
        if header(all, tables[0]).unwrap()["comment"].is_null() {
            assert!(inspect(all, tables[0], None).is_err());
            assert!(inspect(all, tables[0], Some(&native.replace(MARK, "foreign"))).is_err());
        }
        let table = inspect(all, tables[0], Some(&native)).unwrap().unwrap();
        println!(
            "parsed {} with table handle {} and two rule handles {:?}",
            tables[0], table.handle, table.rules
        );
    }
    #[test]
    fn fence_names_are_generation_bound_and_grammar_checked() {
        let mut s = FenceSpec {
            instance: InstanceId::from("a"),
            epoch: Epoch(1),
            address: "[::1]:12345".parse().unwrap(),
        };
        let first = object(&s);
        assert!(parts(&first).is_ok());
        s.epoch = Epoch(2);
        assert_ne!(first, object(&s));
        for name in [
            "etd_f_123_123",
            "etd_f_00000000000000000000000000000000_01",
            "inet filter",
        ] {
            assert!(parse_table(name).is_none());
        }
    }
}
