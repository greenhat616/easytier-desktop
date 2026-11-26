use super::{
    command, observation, observe, output,
    pf::{self, Rule},
};
use async_trait::async_trait;
use etd_sysfx::*;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    time::Duration,
};

pub(super) struct MacFence;

fn validate(spec: &FenceSpec) -> Result<(), FenceError> {
    if !matches!(spec.address.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST)
        && spec.address.ip() != IpAddr::V6(Ipv6Addr::LOCALHOST)
        || spec.address.port() == 0
    {
        return Err(FenceError::Unsupported(
            "expected 127.0.0.1 or ::1 and a nonzero port".into(),
        ));
    }
    Ok(())
}
fn os(e: io::Error) -> FenceError {
    FenceError::Os {
        code: i64::from(e.raw_os_error().unwrap_or(-1)),
        message: e.to_string(),
    }
}
fn host(address: SocketAddr) -> DirectionResult {
    match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
        Ok(_) => DirectionResult::Connected,
        Err(e) => DirectionResult::Error(e.to_string()),
    }
}

fn packets(rule: &Rule, v6: bool) -> io::Result<u64> {
    let label = format!("{}-{}", rule.label, if v6 { "v6" } else { "v4" });
    for line in output(command("/sbin/pfctl").args(["-a", pf::ANCHOR, "-s", "labels"]))?.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(label.as_str()) {
            return fields
                .nth(1)
                .and_then(|p| p.parse().ok())
                .ok_or_else(|| io::Error::other("invalid PF packet counter"));
        }
    }
    Err(io::Error::other("PF label missing"))
}

fn verify(spec: FenceSpec, pid: u32) -> Result<FenceVerification, FenceError> {
    let address = spec.address;
    let listener = || -> Result<ListenerCheck, FenceError> {
        Ok(match observe::listener(address).map_err(os)? {
            Some(found) if found.pid == pid => ListenerCheck::Expected,
            Some(found) => ListenerCheck::Other { pid: found.pid },
            None => ListenerCheck::NotListening,
        })
    };
    let initial = listener()?;
    let mut result = FenceVerification {
        listener: initial,
        host: DirectionResult::NoListener,
        unprivileged: DirectionResult::NoListener,
    };
    if result.listener != ListenerCheck::Expected {
        return Ok(result);
    }
    result.host = host(address);
    if result.host != DirectionResult::Connected {
        return Ok(result);
    }
    let rule = Rule::for_spec(&spec);
    let before = packets(&rule, address.is_ipv6()).map_err(os)?;
    let nobody = nix::unistd::User::from_name("nobody")
        .map_err(|e| FenceError::Probe(e.to_string()))?
        .filter(|u| !u.uid.is_root())
        .ok_or_else(|| FenceError::Probe("unprivileged account unavailable".into()))?;
    let probe = command("/usr/bin/sudo")
        .args([
            "-n",
            "-u",
            &format!("#{}", nobody.uid),
            "--",
            "/usr/bin/nc",
            "-n",
            "-v",
            "-z",
            "-G",
            "2",
            "-w",
            "2",
            &address.ip().to_string(),
            &address.port().to_string(),
        ])
        .output()
        .map_err(os)?;
    // A timeout alone proves nothing. Require a packet matching this actual PF
    // block, plus the same live listener and a second successful host connect.
    let message = String::from_utf8_lossy(&probe.stderr);
    result.unprivileged = if probe.status.success() {
        DirectionResult::Connected
    } else if probe.status.code() == Some(1)
        && packets(&rule, address.is_ipv6()).map_err(os)? > before
        && (message.contains("timed out") || message.contains("Connection refused"))
    {
        DirectionResult::Refused
    } else {
        DirectionResult::Error(message.into_owned())
    };
    result.host = host(address);
    result.listener = listener()?;
    Ok(result)
}
#[async_trait]
impl PortFence for MacFence {
    fn plan(&self, spec: &FenceSpec) -> EffectIntent {
        EffectIntent {
            scope: EffectScope::Instance {
                instance: spec.instance.clone(),
                epoch: spec.epoch,
            },
            kind: EffectKind::MacFenceRule,
            key: Rule::for_spec(spec).key(),
            undo: Undo::EnsureAbsent,
            persistence: Persistence::UntilReboot,
        }
    }
    async fn install(&self, spec: &FenceSpec) -> Result<Observation, FenceError> {
        validate(spec)?;
        let rule = Rule::for_spec(spec);
        let key = rule.key();
        tokio::task::spawn_blocking(move || pf::change(rule, true))
            .await
            .map_err(|e| FenceError::Probe(e.to_string()))?
            .map_err(os)?;
        Ok(observation(
            &key,
            Credential::ExclusiveContainer {
                container: pf::ANCHOR.into(),
            },
        ))
    }
    async fn verify(
        &self,
        spec: &FenceSpec,
        listener_pid: u32,
    ) -> Result<FenceVerification, FenceError> {
        validate(spec)?;
        let spec = spec.clone();
        tokio::task::spawn_blocking(move || verify(spec, listener_pid))
            .await
            .map_err(|e| FenceError::Probe(e.to_string()))?
    }
    async fn remove(&self, spec: &FenceSpec) -> Result<Reclaimed, FenceError> {
        validate(spec)?;
        let rule = Rule::for_spec(spec);
        let changed = tokio::task::spawn_blocking(move || pf::change(rule, false))
            .await
            .map_err(|e| FenceError::Probe(e.to_string()))?
            .map_err(os)?;
        Ok(if changed {
            Reclaimed::Removed
        } else {
            Reclaimed::AlreadyAbsent
        })
    }
}
