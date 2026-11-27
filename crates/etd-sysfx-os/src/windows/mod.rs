//! Windows system effects, using a persistent native WFP fence and independent
//! Windows management provider queries. No request data is executed as code.
pub mod appearance;
pub mod driver_refs;

/// Uninstall: remove the service host's volatile boot marker (see
/// `registry::remove_machine_boot_marker`).
pub fn remove_service_boot_marker() -> Result<(), crate::OsError> {
    registry::remove_machine_boot_marker().map_err(|e| crate::OsError::Os {
        code: e.code,
        message: e.message,
    })
}
mod execution;
mod interfaces;
mod magic;
mod probe;
mod registry;
mod wfp;

use crate::{OsAdapters, OsConfig, OsError};
use async_trait::async_trait;
use etd_contract::InstanceId;
use etd_sysfx::*;
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[error("Windows error {code}: {message}")]
struct WinError {
    code: i64,
    message: String,
}
impl WinError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn invalid(message: impl Into<String>) -> Self {
        Self::new(-1, message)
    }
    fn windows(e: ::windows::core::Error) -> Self {
        Self::new(e.code().0 as i64, e.message())
    }
    fn observe(self) -> ObserveError {
        ObserveError::Os {
            code: self.code,
            message: self.message,
        }
    }
    fn reclaim(self) -> ReclaimError {
        if let Some(holder) = self.message.strip_prefix(HELD_BY) {
            ReclaimError::HeldBy(holder.to_owned())
        } else if self.message.contains("BUSY:") {
            ReclaimError::Busy(self.message)
        } else {
            ReclaimError::Os {
                code: self.code,
                message: self.message,
            }
        }
    }
    fn fence(self) -> FenceError {
        FenceError::Os {
            code: self.code,
            message: self.message,
        }
    }
}
/// Message prefix of a [`WinError`] that is a proven foreign holder.
const HELD_BY: &str = "HELD_BY: ";
fn observation(credential: Option<Credential>, key: ObjectKey, detail: String) -> Observation {
    Observation {
        credential,
        key: Some(key),
        detail: Some(detail),
        observed_at: jiff::Timestamp::now(),
    }
}
fn opaque(value: impl Into<String>) -> Credential {
    Credential::Opaque {
        value: value.into(),
    }
}
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, WinError> + Send + 'static,
) -> Result<T, WinError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| WinError::invalid(format!("Windows blocking worker: {e}")))?
}
// Windows PowerShell expects UTF-16LE for -EncodedCommand. Encoding the
// constant script avoids command-line quoting and newline ambiguities.
fn encoded_command(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(alphabet[(a >> 2) as usize] as char);
        out.push(alphabet[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            alphabet[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            alphabet[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
/// See [`crate::shutdown_helpers`].
pub(crate) const HELPERS_SHUTDOWN_WORST: Duration = execution::SHUTDOWN_WORST;
/// See [`crate::shutdown_helpers`].
pub(crate) fn shutdown_helpers() -> Result<(), crate::OsError> {
    execution::shutdown().map_err(|e| crate::OsError::Os {
        code: e.code,
        message: e.message,
    })
}
async fn query(request: Value) -> Result<Vec<Value>, WinError> {
    blocking(move || execution::run(request)).await
}
async fn single(request: Value) -> Result<Value, WinError> {
    let mut rows = query(request).await?;
    if rows.len() != 1 {
        return Err(WinError::invalid("expected exactly one result"));
    }
    Ok(rows.remove(0))
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str, WinError> {
    v[key]
        .as_str()
        .ok_or_else(|| WinError::invalid(format!("missing {key}")))
}
fn owned_name(s: &str) -> bool {
    s.strip_prefix(naming::INTERFACE_PREFIX)
        .is_some_and(|tail| {
            tail.len() == 8
                && tail
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
}
fn registry_value_key(key: &ObjectKey) -> Result<(&str, &str), WinError> {
    let ObjectKey::Registry {
        key,
        value: Some(value),
    } = key
    else {
        return Err(WinError::invalid("expected registry value key"));
    };
    let lower = key.to_ascii_lowercase();
    let valid = [
        (
            r"hklm\system\currentcontrolset\services\tcpip\parameters\interfaces\",
            false,
        ),
        (
            r"hklm\system\currentcontrolset\services\tcpip6\parameters\interfaces\",
            false,
        ),
        (
            r"hklm\system\currentcontrolset\services\netbt\parameters\interfaces\tcpip_",
            true,
        ),
    ]
    .into_iter()
    .any(|(prefix, netbt)| {
        lower.strip_prefix(prefix).is_some_and(|guid| {
            Uuid::parse_str(guid).is_ok()
                && if netbt {
                    value.eq_ignore_ascii_case("NetbiosOptions")
                } else {
                    [
                        "RegistrationEnabled",
                        "DisableDynamicUpdate",
                        "MaxNumberOfAddressesToRegister",
                    ]
                    .iter()
                    .any(|name| value.eq_ignore_ascii_case(name))
                }
        })
    });
    if !valid {
        return Err(WinError::invalid("not an adapter-owned registry value"));
    }
    Ok((key, value))
}
fn magic_key(key: &ObjectKey) -> bool {
    matches!(key, ObjectKey::Registry { key, value: None } if key.eq_ignore_ascii_case(r"HKLM\SOFTWARE\EasyTier\MagicDNS"))
}
fn rule_query(kind: EffectKind) -> Option<&'static str> {
    match kind {
        EffectKind::WinFirewallRule | EffectKind::WinProgramFirewallRule => Some("firewall"),
        EffectKind::WinNrptRule => Some("nrpt"),
        EffectKind::WinNetworkProfile => Some("profiles"),
        _ => None,
    }
}
fn rule_match(key: &ObjectKey, row: &Value) -> bool {
    let Some(actual) = row["name"].as_str() else {
        return false;
    };
    match key {
        ObjectKey::Rule { name, group } => {
            name.eq_ignore_ascii_case(actual)
                && group.as_ref().is_none_or(|g| {
                    row["group"]
                        .as_str()
                        .is_some_and(|s| g.eq_ignore_ascii_case(s))
                })
        }
        ObjectKey::NetworkProfile { profile_name } => profile_name.eq_ignore_ascii_case(actual),
        _ => false,
    }
}
fn rule_name(key: &ObjectKey) -> Result<&str, WinError> {
    match key {
        ObjectKey::Rule { name, .. } => Ok(name),
        ObjectKey::NetworkProfile { profile_name } => Ok(profile_name),
        _ => Err(WinError::invalid("not a named rule")),
    }
}

fn program_name(name: &str) -> Option<(&str, &str)> {
    let body = name.strip_prefix("EasyTier ")?;
    ["Inbound", "Outbound"].into_iter().find_map(|direction| {
        let path = body.strip_suffix(&format!(" ({direction})"))?;
        std::path::Path::new(path)
            .is_absolute()
            .then_some((path, direction))
    })
}
fn normalize_program(path: &str) -> String {
    path.strip_prefix(r"\\?\").unwrap_or(path).to_lowercase()
}
fn program_identity(row: &Value) -> Result<Credential, WinError> {
    Ok(opaque(json!({"id":string(row,"id")?,"name":string(row,"name")?.to_lowercase(),"program":normalize_program(row["program"].as_str().unwrap_or("")),"direction":string(row,"direction")?.to_lowercase(),"group":row["group"].as_str().unwrap_or("").to_lowercase()}).to_string()))
}
fn program_credential_matches(key: &ObjectKey, observation: &Observation) -> bool {
    let ObjectKey::Rule { name, group } = key else {
        return false;
    };
    let Some((path, direction)) = program_name(name) else {
        return false;
    };
    let Some(Credential::Opaque { value }) = &observation.credential else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<Value>(value) else {
        return false;
    };
    v["name"].as_str() == Some(name.to_lowercase().as_str())
        && v["program"].as_str() == Some(normalize_program(path).as_str())
        && v["direction"].as_str() == Some(direction.to_lowercase().as_str())
        && group
            .as_ref()
            .is_none_or(|g| v["group"].as_str() == Some(g.to_lowercase().as_str()))
}
/// Our WFP filters as a successful enumeration shows them: not all four
/// present is positively missing (`FenceError::Missing`); an enumeration
/// that failed stays an OS error.
fn fence_presence(complete: bool) -> Result<(), FenceError> {
    if complete {
        Ok(())
    } else {
        Err(FenceError::Missing(
            "persistent fence is incomplete: our WFP filters are not all present".into(),
        ))
    }
}
/// A program rule under the key's name whose application condition, group
/// or direction differ from what the name says: its identity stays the
/// credential, and the observation's key is the one its actual condition
/// names (`EasyTier <program> (<Direction>)` in its group), so a caller
/// comparing it with the key it asked for sees a different object.
fn foreign_program_rule(o: &Observation) -> Observation {
    let found = match &o.credential {
        Some(Credential::Opaque { value }) => serde_json::from_str::<Value>(value).ok(),
        _ => None,
    };
    let key = found.and_then(|v| {
        let direction = match v["direction"].as_str()? {
            "inbound" => "Inbound",
            "outbound" => "Outbound",
            other => other,
        }
        .to_owned();
        Some(ObjectKey::Rule {
            name: format!("EasyTier {} ({direction})", v["program"].as_str()?),
            group: v["group"]
                .as_str()
                .filter(|g| !g.is_empty())
                .map(str::to_owned),
        })
    });
    Observation { key, ..o.clone() }
}
async fn observe_kind(kind: EffectKind, key: &ObjectKey) -> Result<Option<Observation>, WinError> {
    if let Some(op) = rule_query(kind) {
        let name = rule_name(key)?;
        let mut rows = query(json!({"op":op,"name":name}))
            .await?
            .into_iter()
            .filter(|v| {
                v["name"]
                    .as_str()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(name))
            });
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        if rows.next().is_some() {
            return Err(WinError::invalid("ambiguous same-name system objects"));
        }
        let identity = if kind == EffectKind::WinProgramFirewallRule {
            program_identity(&row)?
        } else if rule_match(key, &row) {
            opaque(string(&row, "id")?)
        } else {
            opaque(format!("foreign-group:{}", string(&row, "id")?))
        };
        return Ok(Some(observation(
            Some(identity),
            key.clone(),
            string(&row, "description")?.into(),
        )));
    }
    match kind {
        EffectKind::WinFenceFilter => {
            let key = key.clone();
            blocking(move || wfp::observe(&key)).await
        }
        EffectKind::WinTunAdapter => {
            let key = key.clone();
            blocking(move || interfaces::observe(&key)).await
        }
        EffectKind::WinRegistryValue => {
            let (key_path, value) = registry_value_key(key)?;
            let current: SettingValue = serde_json::from_value(
                single(json!({"op":"registry","key":key_path,"value":value})).await?,
            )
            .map_err(|e| WinError::invalid(e.to_string()))?;
            if current == SettingValue::Absent {
                Ok(None)
            } else {
                Ok(Some(observation(None, key.clone(), format!("{current:?}"))))
            }
        }
        EffectKind::WinMagicDnsRecovery => {
            if !magic_key(key) {
                return Err(WinError::invalid("unexpected Magic DNS key"));
            }
            if single(json!({"op":"magic"})).await?.as_bool() == Some(true) {
                Ok(Some(observation(
                    None,
                    key.clone(),
                    "upstream recovery record".into(),
                )))
            } else {
                Ok(None)
            }
        }
        EffectKind::Route => {
            let ObjectKey::RoutesVia {
                interface: Some(name),
            } = key
            else {
                return Err(WinError::invalid("missing route interface"));
            };
            let count = query(json!({"op":"routes"}))
                .await?
                .into_iter()
                .filter(|r| {
                    r["name"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(name))
                })
                .count();
            if count == 0 {
                Ok(None)
            } else {
                Ok(Some(observation(
                    None,
                    key.clone(),
                    format!("{count} routes remain"),
                )))
            }
        }
        EffectKind::Driver => {
            let ObjectKey::Service { name } = key else {
                return Err(WinError::invalid("expected driver service key"));
            };
            // From SCM, cross-checked with the Services registry key: WMI
            // omits disabled drivers without a file (topic#40 msg#1179).
            // Shared drivers have no creation credential in the upstream API.
            let name = name.clone();
            let found = blocking(move || driver_refs::driver_service(&name)).await?;
            Ok(found.map(|d| observation(None, key.clone(), d.detail())))
        }
        _ => Err(WinError::invalid(format!(
            "unsupported Windows effect {kind}"
        ))),
    }
}
fn matching_credential(e: &Effect, found: &Observation) -> Result<(), ReclaimError> {
    let recorded = e.observation.as_ref().and_then(|o| o.credential.as_ref());
    if recorded.is_some() && recorded == found.credential.as_ref() {
        Ok(())
    } else {
        Err(ReclaimError::CredentialMismatch)
    }
}
struct WindowsReclaimer(EffectKind, PathBuf);
#[async_trait]
impl Reclaimer for WindowsReclaimer {
    fn kind(&self) -> EffectKind {
        self.0
    }
    fn rank(&self) -> u8 {
        self.0.default_rank()
    }
    async fn probe(&self, e: &Effect) -> Probe {
        match observe_kind(self.0, &e.key).await {
            Ok(Some(o)) => Probe::Present(o),
            Ok(None) => Probe::Absent,
            Err(e) => Probe::Indeterminate(e.to_string()),
        }
    }
    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        if e.kind != self.0 {
            return Err(ReclaimError::CredentialMismatch);
        }
        let Some(found) = observe_kind(self.0, &e.key)
            .await
            .map_err(WinError::reclaim)?
        else {
            return Ok(Reclaimed::AlreadyAbsent);
        };
        let response = match self.0 {
            EffectKind::WinFenceFilter => {let key=e.key.clone();return blocking(move||wfp::remove(&key)).await.map_err(WinError::reclaim);},
            // Ours (same credential) but never uninstalled live: listed as a
            // candidate, closed once gone (topic#59 msg#1766).
            EffectKind::WinTunAdapter => return Err(ReclaimError::NotDeletable("live adapter; never uninstall live wintun".into())),
            EffectKind::Route => return Err(ReclaimError::Busy("routes still present; never delete routes blindly".into())),
            EffectKind::WinRegistryValue => {
                let (path,value) = registry_value_key(&e.key).map_err(WinError::reclaim)?;
                let Undo::RestoreIfOurs { ours, original } = &e.undo else { return Err(ReclaimError::CredentialMismatch); };
                single(json!({"op":"restore_registry","key":path,"value":value,"ours":ours,"original":original})).await
            }
            EffectKind::WinMagicDnsRecovery => {
                if e.undo != Undo::ReplayUpstreamRecovery { return Err(ReclaimError::CredentialMismatch); }
                let root=self.1.clone();return blocking(move||magic::replay(&root)).await.map_err(WinError::reclaim);
            }
            EffectKind::WinFirewallRule | EffectKind::WinProgramFirewallRule | EffectKind::WinNrptRule | EffectKind::WinNetworkProfile => {
                if e.undo != Undo::EnsureAbsent { return Err(ReclaimError::CredentialMismatch); }
                matching_credential(e,&found)?;
                let Some(Credential::Opaque { value:id }) = &found.credential else { return Err(ReclaimError::CredentialMismatch); };
                let request = match (&e.kind,&e.key) {
                    (EffectKind::WinFirewallRule,ObjectKey::Rule { name,group }) => {
                        if id.starts_with("foreign-group:") {return Err(ReclaimError::CredentialMismatch);}
                        json!({"op":"delete_firewall","name":name,"group":group,"id":id})
                    }
                    (EffectKind::WinProgramFirewallRule,ObjectKey::Rule { name,group }) => {
                        if !matches!(e.scope, EffectScope::CoreBinary { .. }) || !program_credential_matches(&e.key,&found) {return Err(ReclaimError::CredentialMismatch);}
                        let v:Value=serde_json::from_str(id).map_err(|_|ReclaimError::CredentialMismatch)?;
                        json!({"op":"delete_firewall","name":name,"group":group,"id":v["id"],"program":v["program"],"direction":v["direction"]})
                    }
                    (EffectKind::WinNrptRule,ObjectKey::Rule { name,group }) => {
                        if id.starts_with("foreign-group:") {return Err(ReclaimError::CredentialMismatch);}
                        json!({"op":"delete_nrpt","name":name,"group":group,"id":id})
                    }
                    (EffectKind::WinNetworkProfile,ObjectKey::NetworkProfile { profile_name }) => json!({"op":"delete_profile","name":profile_name,"id":id}),
                    _ => return Err(ReclaimError::CredentialMismatch),
                };
                single(request).await
            }
            _ => return Err(ReclaimError::Unsupported(self.0)),
        }.map_err(WinError::reclaim)?;
        match response.as_str() {
            Some("absent") => Ok(Reclaimed::AlreadyAbsent),
            Some("removed") => Ok(Reclaimed::Removed),
            Some("restored") => Ok(Reclaimed::Restored),
            Some("modified") => Ok(Reclaimed::LeftModified),
            _ => Err(ReclaimError::Indeterminate(
                "unknown management outcome".into(),
            )),
        }
    }
}
struct WindowsObserver {
    run_dir: PathBuf,
}
#[async_trait]
impl SystemObserver for WindowsObserver {
    async fn observe(
        &self,
        kind: EffectKind,
        key: &ObjectKey,
    ) -> Result<Option<Observation>, ObserveError> {
        let found = observe_kind(kind, key).await.map_err(WinError::observe)?;
        if let Some(o) = &found {
            if kind == EffectKind::WinTunAdapter
                && !matches!(o.credential, Some(Credential::WinAdapter { .. }))
            {
                return Err(WinError::invalid(
                    "same-name interface is not a confirmed Wintun device",
                )
                .observe());
            }
            if kind == EffectKind::WinProgramFirewallRule && !program_credential_matches(key, o) {
                // Definite foreign (the query succeeded): reported as found,
                // never as an error (ruling topic#40 msg#1199).
                return Ok(Some(foreign_program_rule(o)));
            }
            if matches!(&o.credential,Some(Credential::Opaque{value}) if value.starts_with("foreign-group:"))
            {
                return Err(WinError::invalid("same-name rule has a different group").observe());
            }
        }
        Ok(found)
    }
    async fn interface(&self, key: &ObjectKey) -> Result<Option<InterfaceInfo>, ObserveError> {
        interfaces::info(key).await.map_err(WinError::observe)
    }
    async fn listener(&self, address: SocketAddr) -> Result<Option<ListenerInfo>, ObserveError> {
        listener(address).await.map_err(WinError::observe)
    }
    async fn interfaces_owned_by(&self, _pid: u32) -> Result<Vec<InterfaceInfo>, ObserveError> {
        Ok(Vec::new())
    }
    async fn enumerate(&self, class: SystemClass) -> Result<Vec<SystemEntry>, ObserveError> {
        enumerate(class, &self.run_dir)
            .await
            .map_err(WinError::observe)
    }
}
async fn listener(address: SocketAddr) -> Result<Option<ListenerInfo>, WinError> {
    let rows = query(json!({"op":"listeners"})).await?;
    listener_rows(address, &rows)
}
fn listener_rows(address: SocketAddr, rows: &[Value]) -> Result<Option<ListenerInfo>, WinError> {
    let mut found = None;
    for row in rows
        .iter()
        .filter(|r| r["port"].as_u64() == Some(address.port() as u64))
    {
        let ip = row["address"]
            .as_str()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .ok_or_else(|| WinError::invalid("unreadable listener address on management port"))?;
        if ip != address.ip() {
            return Err(WinError::invalid(format!(
                "wildcard or unexpected listener address {ip} on management port"
            )));
        }
        if found.is_some() {
            return Err(WinError::invalid("multiple listeners on management port"));
        }
        let pid = row["pid"]
            .as_u64()
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| WinError::invalid("missing listener PID"))?;
        found = Some(ListenerInfo { address, pid });
    }
    Ok(found)
}
async fn listener_check(address: SocketAddr, pid: u32) -> ListenerCheck {
    match listener(address).await {
        Ok(Some(l)) if l.pid == pid => ListenerCheck::Expected,
        Ok(Some(l)) => ListenerCheck::Other { pid: l.pid },
        Ok(None) => ListenerCheck::NotListening,
        Err(e) => ListenerCheck::Indeterminate(e.to_string()),
    }
}
async fn host_connect(address: SocketAddr) -> DirectionResult {
    match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(address),
    )
    .await
    {
        Ok(Ok(_)) => DirectionResult::Connected,
        Ok(Err(e)) => DirectionResult::Error(e.to_string()),
        Err(_) => DirectionResult::Error("host connection timed out".into()),
    }
}
async fn enumerate(
    class: SystemClass,
    run_dir: &std::path::Path,
) -> Result<Vec<SystemEntry>, WinError> {
    let mut entries = Vec::new();
    let mut push = |key, identity, description| {
        entries.push(SystemEntry {
            class,
            key,
            identity,
            description,
        })
    };
    match class {
        SystemClass::Interfaces => {
            for (key, info) in interfaces::enumerate().await? {
                push(
                    key,
                    Some(info.credential),
                    format!("up={} addresses={:?}", info.up, info.addresses),
                );
            }
        }
        SystemClass::FirewallRules => {
            for r in query(json!({"op":"firewall"})).await? {
                push(
                    ObjectKey::Rule {
                        name: string(&r, "name")?.into(),
                        group: r["group"].as_str().map(str::to_owned),
                    },
                    Some(if program_name(string(&r, "name")?).is_some() {
                        program_identity(&r)?
                    } else {
                        opaque(string(&r, "id")?)
                    }),
                    string(&r, "description")?.into(),
                );
            }
            for (key, o) in blocking(wfp::enumerate).await? {
                push(key, o.credential, o.detail.unwrap_or_default());
            }
        }
        SystemClass::DnsPolicy => {
            for r in query(json!({"op":"nrpt"})).await? {
                push(
                    ObjectKey::Rule {
                        name: string(&r, "name")?.into(),
                        group: r["group"].as_str().map(str::to_owned),
                    },
                    Some(opaque(string(&r, "id")?)),
                    string(&r, "description")?.into(),
                );
            }
            let key = ObjectKey::Registry {
                key: r"HKLM\SOFTWARE\EasyTier\MagicDNS".into(),
                value: None,
            };
            if let Some(o) = observe_kind(EffectKind::WinMagicDnsRecovery, &key).await? {
                push(key, o.credential, o.detail.unwrap_or_default());
            }
        }
        SystemClass::RegistryValues => {
            for r in query(json!({"op":"registry_rows"})).await? {
                push(
                    ObjectKey::Registry {
                        key: string(&r, "key")?.into(),
                        value: Some(string(&r, "value")?.into()),
                    },
                    None,
                    string(&r, "description")?.into(),
                );
            }
            for r in query(json!({"op":"profiles"})).await? {
                push(
                    ObjectKey::NetworkProfile {
                        profile_name: string(&r, "name")?.into(),
                    },
                    Some(opaque(string(&r, "id")?)),
                    string(&r, "description")?.into(),
                );
            }
        }
        SystemClass::Routes => {
            for r in query(json!({"op":"routes"})).await? {
                push(
                    ObjectKey::RoutesVia {
                        interface: Some(string(&r, "name")?.into()),
                    },
                    None,
                    string(&r, "description")?.into(),
                );
            }
        }
        SystemClass::Services => {
            for op in ["services", "drivers"] {
                for r in query(json!({"op":op})).await? {
                    push(
                        ObjectKey::Service {
                            name: string(&r, "name")?.into(),
                        },
                        None,
                        string(&r, "description")?.into(),
                    );
                }
            }
        }
        SystemClass::Processes => {
            for r in query(json!({"op":"processes"})).await? {
                let pid = r["pid"]
                    .as_u64()
                    .and_then(|p| u32::try_from(p).ok())
                    .ok_or_else(|| WinError::invalid("process PID missing"))?;
                push(
                    ObjectKey::Process {
                        exe: PathBuf::from(r["path"].as_str().unwrap_or(string(&r, "name")?)),
                        cmdline_marker: PathBuf::new(),
                    },
                    Some(Credential::Process {
                        pid,
                        start_token: string(&r, "start")?.into(),
                    }),
                    string(&r, "name")?.into(),
                );
            }
        }
        SystemClass::RuntimeDirs => {
            let mut instances = match tokio::fs::read_dir(run_dir).await {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
                Err(e) => return Err(WinError::invalid(e.to_string())),
            };
            while let Some(instance) = instances
                .next_entry()
                .await
                .map_err(|e| WinError::invalid(e.to_string()))?
            {
                if !instance
                    .file_type()
                    .await
                    .map_err(|e| WinError::invalid(e.to_string()))?
                    .is_dir()
                {
                    continue;
                }
                let mut epochs = tokio::fs::read_dir(instance.path())
                    .await
                    .map_err(|e| WinError::invalid(e.to_string()))?;
                while let Some(epoch) = epochs
                    .next_entry()
                    .await
                    .map_err(|e| WinError::invalid(e.to_string()))?
                {
                    push(
                        ObjectKey::Path { path: epoch.path() },
                        None,
                        "runtime entry".into(),
                    );
                }
            }
        }
        _ => return Err(WinError::invalid("unsupported system class")),
    }
    Ok(entries)
}
struct WindowsBoot {
    machine: bool,
}
impl BootIdSource for WindowsBoot {
    fn current(&self) -> Result<BootId, ReclaimError> {
        registry::boot_id(self.machine).map_err(WinError::reclaim)
    }
}
struct WindowsSweeper<S = NativeSweep> {
    core_store_dir: PathBuf,
    source: S,
}
#[async_trait]
trait SweepSource: Send + Sync {
    async fn wfp(&self) -> Result<Vec<(ObjectKey, Observation)>, WinError>;
    async fn interfaces(&self) -> Result<Vec<(ObjectKey, InterfaceInfo)>, WinError>;
    async fn rows(&self, class: &str) -> Result<Vec<Value>, WinError>;
    async fn magic(&self, key: &ObjectKey) -> Result<Option<Observation>, WinError>;
}
struct NativeSweep;
#[async_trait]
impl SweepSource for NativeSweep {
    async fn wfp(&self) -> Result<Vec<(ObjectKey, Observation)>, WinError> {
        blocking(wfp::sweep).await
    }
    async fn interfaces(&self) -> Result<Vec<(ObjectKey, InterfaceInfo)>, WinError> {
        interfaces::sweep().await
    }
    async fn rows(&self, class: &str) -> Result<Vec<Value>, WinError> {
        query(json!({"op":class,"sweep":true})).await
    }
    async fn magic(&self, key: &ObjectKey) -> Result<Option<Observation>, WinError> {
        observe_kind(EffectKind::WinMagicDnsRecovery, key).await
    }
}
fn class_result<T>(class: &str, result: Result<T, WinError>) -> Result<T, ReclaimError> {
    result.map_err(|e| {
        ReclaimError::Indeterminate(format!("Windows sweep class {class} failed: {e}"))
    })
}
async fn sweep_rows(source: &impl SweepSource, class: &str) -> Result<Vec<Value>, ReclaimError> {
    Ok(class_result(class,source.rows(class).await)?.into_iter().filter(|row|{
        if let Some(warning)=row["warning"].as_str(){tracing::warn!(%class,object=?row["object"],error=%warning,"sweep object query failed; continuing");false}else{true}
    }).collect())
}
fn sweep_field<'a>(class: &str, row: &'a Value, field: &str) -> Option<&'a str> {
    match string(row, field) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(%class,object=?row["id"],error=%e,"skipping malformed sweep object");
            None
        }
    }
}
impl<S: SweepSource> Sweeper for WindowsSweeper<S> {
    fn find_marked<'a>(
        &'a self,
        key: Option<&'a InstallKey>,
        known: &'a [InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
        Box::pin(async move {
            let mut found = Vec::new();
            let magic = ObjectKey::Registry {
                key: r"HKLM\SOFTWARE\EasyTier\MagicDNS".into(),
                value: None,
            };
            // Each class is one independent, read-only system query (most of
            // them a PowerShell process): run them together, not one after
            // another, then interpret them in the fixed order below. The
            // first failing class, in that order, still fails the sweep.
            let started = std::time::Instant::now();
            let (wfp, interfaces, firewall, profiles, registry, magic_found, drivers) = tokio::join!(
                self.source.wfp(),
                self.source.interfaces(),
                sweep_rows(&self.source, "firewall"),
                sweep_rows(&self.source, "profiles"),
                async {
                    match key {
                        Some(_) => sweep_rows(&self.source, "registry_rows").await.map(Some),
                        None => Ok(None),
                    }
                },
                self.source.magic(&magic),
                sweep_rows(&self.source, "drivers"),
            );
            tracing::info!(
                stage = "reclaim.sweep_queries",
                elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "Windows sweep queries finished"
            );
            for (key, observation) in class_result("wfp", wfp)? {
                found.push(FoundObject {
                    kind: EffectKind::WinFenceFilter,
                    key,
                    observation,
                    origin: FoundBy::ExclusiveContainer,
                });
            }
            let origin = |name: &str| {
                key.and_then(|k| known.iter().find(|i| naming::interface_name(k, i) == name))
                    .map(|i| FoundBy::DerivedName {
                        instance: i.clone(),
                    })
                    .unwrap_or(FoundBy::PrefixOnly)
            };
            for (object, info) in class_result("interfaces", interfaces)? {
                if !owned_name(&info.name) {
                    continue;
                }
                found.push(FoundObject {
                    kind: EffectKind::WinTunAdapter,
                    key: object.clone(),
                    observation: observation(
                        Some(info.credential),
                        object,
                        "live interface".into(),
                    ),
                    origin: origin(&info.name),
                });
            }
            for row in firewall? {
                let Some(name) = sweep_field("firewall", &row, "name") else {
                    continue;
                };
                if let Some((program, _)) = program_name(name) {
                    let root = format!(
                        "{}\\",
                        normalize_program(&self.core_store_dir.to_string_lossy())
                            .trim_end_matches('\\')
                    );
                    if normalize_program(program).starts_with(&root) {
                        let object = ObjectKey::Rule {
                            name: name.into(),
                            group: row["group"].as_str().map(str::to_owned),
                        };
                        let credential = match program_identity(&row) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(class="firewall",%name,error=%e,"skipping unconfirmed program rule");
                                continue;
                            }
                        };
                        found.push(FoundObject {
                            kind: EffectKind::WinProgramFirewallRule,
                            key: object.clone(),
                            observation: observation(
                                Some(credential),
                                object,
                                "program rule under protected core store".into(),
                            ),
                            origin: FoundBy::PrefixOnly,
                        });
                    }
                    continue;
                }
                let Some(iface) = name
                    .strip_prefix("EasyTier ")
                    .and_then(|s| s.split_once(" - "))
                    .map(|(s, _)| s)
                else {
                    continue;
                };
                if !owned_name(iface) {
                    continue;
                }
                let object = ObjectKey::Rule {
                    name: name.into(),
                    group: row["group"].as_str().map(str::to_owned),
                };
                let Some(id) = sweep_field("firewall", &row, "id") else {
                    continue;
                };
                found.push(FoundObject {
                    kind: EffectKind::WinFirewallRule,
                    key: object.clone(),
                    observation: observation(
                        Some(opaque(id)),
                        object,
                        "marked firewall rule".into(),
                    ),
                    origin: origin(iface),
                });
            }
            for row in profiles? {
                let Some(name) = sweep_field("profiles", &row, "name") else {
                    continue;
                };
                if !owned_name(name) {
                    continue;
                }
                let object = ObjectKey::NetworkProfile {
                    profile_name: name.into(),
                };
                let Some(id) = sweep_field("profiles", &row, "id") else {
                    continue;
                };
                found.push(FoundObject {
                    kind: EffectKind::WinNetworkProfile,
                    key: object.clone(),
                    observation: observation(
                        Some(opaque(id)),
                        object,
                        "marked profile; ownership not proved".into(),
                    ),
                    origin: origin(name),
                });
            }
            if let Some(install_key) = key {
                let names: Vec<_> = known
                    .iter()
                    .map(|instance| {
                        (
                            instance,
                            naming::wintun_guid(&naming::interface_name(install_key, instance))
                                .to_string(),
                        )
                    })
                    .collect();
                for row in registry?.unwrap_or_default() {
                    let Some(path) = sweep_field("registry_rows", &row, "key") else {
                        continue;
                    };
                    let Some((instance, _)) = names.iter().find(|(_, guid)| {
                        path.to_ascii_lowercase().ends_with(&format!("{{{guid}}}"))
                    }) else {
                        continue;
                    };
                    let Some(value) = sweep_field("registry_rows", &row, "value") else {
                        continue;
                    };
                    let object = ObjectKey::Registry {
                        key: path.into(),
                        value: Some(value.into()),
                    };
                    if registry_value_key(&object).is_err() {
                        continue;
                    }
                    found.push(FoundObject {
                        kind: EffectKind::WinRegistryValue,
                        key: object.clone(),
                        observation: observation(
                            None,
                            object,
                            "derived registry value; original not known".into(),
                        ),
                        origin: FoundBy::DerivedName {
                            instance: (*instance).clone(),
                        },
                    });
                }
            }
            // Shared upstream objects may have been made by another EasyTier
            // installation. Surface them as candidates, never exclusive.
            if let Some(obs) = class_result("magic", magic_found)? {
                found.push(FoundObject {
                    kind: EffectKind::WinMagicDnsRecovery,
                    key: magic,
                    observation: obs,
                    origin: FoundBy::PrefixOnly,
                });
            }
            for row in drivers? {
                let Some(name) = sweep_field("drivers", &row, "name") else {
                    continue;
                };
                if !["wintun", "WinDivert"]
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(name))
                {
                    continue;
                }
                let object = ObjectKey::Service { name: name.into() };
                found.push(FoundObject {
                    kind: EffectKind::Driver,
                    key: object.clone(),
                    observation: observation(None, object, "shared EasyTier driver".into()),
                    origin: FoundBy::PrefixOnly,
                });
            }
            Ok(found)
        })
    }
}
struct WindowsFence;
#[async_trait]
impl PortFence for WindowsFence {
    fn plan(&self, spec: &FenceSpec) -> EffectIntent {
        EffectIntent {
            scope: EffectScope::Instance {
                instance: spec.instance.clone(),
                epoch: spec.epoch,
            },
            kind: EffectKind::WinFenceFilter,
            key: wfp::key(spec),
            undo: Undo::EnsureAbsent,
            persistence: Persistence::Persistent,
        }
    }
    async fn install(&self, spec: &FenceSpec) -> Result<Observation, FenceError> {
        if !matches!(spec.address.ip(),std::net::IpAddr::V4(ip) if ip == std::net::Ipv4Addr::LOCALHOST)
            && !matches!(spec.address.ip(),std::net::IpAddr::V6(ip) if ip == std::net::Ipv6Addr::LOCALHOST)
        {
            return Err(FenceError::Unsupported(
                "only exact loopback endpoints can be fenced".into(),
            ));
        }
        let key = wfp::key(spec);
        blocking(move || wfp::install(&key))
            .await
            .map_err(WinError::fence)
    }
    async fn verify(
        &self,
        spec: &FenceSpec,
        listener_pid: u32,
    ) -> Result<FenceVerification, FenceError> {
        let key = wfp::key(spec);
        fence_presence(
            blocking(move || wfp::complete(&key))
                .await
                .map_err(WinError::fence)?,
        )?;
        let check = listener_check(spec.address, listener_pid).await;
        if check != ListenerCheck::Expected {
            return Ok(FenceVerification {
                listener: check,
                host: DirectionResult::NoListener,
                unprivileged: DirectionResult::NoListener,
            });
        }
        let mut host = host_connect(spec.address).await;
        let address = spec.address;
        let unprivileged =
            tokio::task::spawn_blocking(move || probe::unprivileged_connect(address))
                .await
                .map_err(|e| FenceError::Probe(e.to_string()))??;
        let check = listener_check(spec.address, listener_pid).await;
        let key = wfp::key(spec);
        if !blocking(move || wfp::complete(&key))
            .await
            .map_err(WinError::fence)?
        {
            return Err(FenceError::Probe(
                "persistent fence changed during verification".into(),
            ));
        }
        if host == DirectionResult::Connected && check == ListenerCheck::Expected {
            host = host_connect(spec.address).await;
        }
        Ok(FenceVerification {
            listener: check,
            host,
            unprivileged,
        })
    }
    async fn remove(&self, spec: &FenceSpec) -> Result<Reclaimed, FenceError> {
        let key = wfp::key(spec);
        blocking(move || wfp::remove(&key))
            .await
            .map_err(WinError::fence)
    }
}
pub(crate) fn adapters(config: &OsConfig) -> Result<OsAdapters, OsError> {
    let reclaimers: Vec<Arc<dyn Reclaimer>> = [
        EffectKind::WinFenceFilter,
        EffectKind::WinTunAdapter,
        EffectKind::WinFirewallRule,
        EffectKind::WinProgramFirewallRule,
        EffectKind::WinRegistryValue,
        EffectKind::WinNrptRule,
        EffectKind::WinMagicDnsRecovery,
        EffectKind::WinNetworkProfile,
        EffectKind::Route,
        EffectKind::Driver,
    ]
    .into_iter()
    .map(|kind| {
        Arc::new(WindowsReclaimer(kind, config.core_store_dir.clone())) as Arc<dyn Reclaimer>
    })
    .collect();
    Ok(OsAdapters {
        reclaimers,
        sweeper: Arc::new(WindowsSweeper {
            core_store_dir: config.core_store_dir.clone(),
            source: NativeSweep,
        }),
        boot_id: Arc::new(WindowsBoot {
            // Frozen OsConfig carries paths only, not HostForm. The host's
            // prepare(User) rejects an elevated entry token, so use the
            // existing composition-root invariant until HostForm is passed.
            machine: registry::elevated().map_err(|e| OsError::Os {
                code: e.code,
                message: e.message,
            })?,
        }),
        observer: Arc::new(WindowsObserver {
            run_dir: config.run_dir.clone(),
        }),
        fence: Some(Arc::new(WindowsFence)),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    struct SweepFixture {
        fail: Option<&'static str>,
    }
    impl SweepFixture {
        fn check(&self, class: &str) -> Result<(), WinError> {
            if self.fail == Some(class) {
                Err(WinError::invalid("fixture class failure"))
            } else {
                Ok(())
            }
        }
    }
    #[async_trait]
    impl SweepSource for SweepFixture {
        async fn wfp(&self) -> Result<Vec<(ObjectKey, Observation)>, WinError> {
            self.check("wfp")?;
            Ok(Vec::new())
        }
        async fn interfaces(&self) -> Result<Vec<(ObjectKey, InterfaceInfo)>, WinError> {
            self.check("interfaces")?;
            Ok(Vec::new())
        }
        async fn rows(&self, class: &str) -> Result<Vec<Value>, WinError> {
            self.check(class)?;
            Ok(match class {
                "firewall" => vec![
                    json!({"object":"bad-id","warning":"ambiguous application filter"}),
                    json!({"id":"valid-id","name":"EasyTier etd-1234abcd - TCP Protocol (Inbound)","group":"EasyTier"}),
                ],
                "drivers" => vec![json!({"name":"wintun"})],
                _ => Vec::new(),
            })
        }
        async fn magic(&self, _: &ObjectKey) -> Result<Option<Observation>, WinError> {
            self.check("magic")?;
            Ok(None)
        }
    }
    #[tokio::test]
    async fn sweep_class_failure_is_indeterminate_not_empty() {
        for class in [
            "wfp",
            "interfaces",
            "firewall",
            "profiles",
            "registry_rows",
            "magic",
            "drivers",
        ] {
            let sweeper = WindowsSweeper {
                core_store_dir: PathBuf::from(r"C:\fixture"),
                source: SweepFixture { fail: Some(class) },
            };
            let error = sweeper
                .find_marked(Some(&InstallKey([0; 32])), &[])
                .await
                .unwrap_err();
            assert!(
                matches!(error,ReclaimError::Indeterminate(message) if message.contains(class))
            );
        }
    }
    #[tokio::test]
    async fn sweep_single_object_failure_keeps_other_objects() {
        let sweeper = WindowsSweeper {
            core_store_dir: PathBuf::from(r"C:\fixture"),
            source: SweepFixture { fail: None },
        };
        let found = sweeper.find_marked(None, &[]).await.unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|e| e.kind == EffectKind::WinFirewallRule));
        assert!(found.iter().any(|e| e.kind == EffectKind::Driver));
    }
    #[test]
    fn listener_rejects_wildcards_and_unexpected_addresses() {
        let addr: SocketAddr = "127.0.0.1:23456".parse().unwrap();
        let expected = json!({"address":"127.0.0.1","port":23456,"pid":42});
        assert_eq!(
            listener_rows(addr, std::slice::from_ref(&expected))
                .unwrap()
                .unwrap()
                .pid,
            42
        );
        for unexpected in ["0.0.0.0", "::", "::1", "127.0.0.2", "invalid"] {
            assert!(
                listener_rows(
                    addr,
                    &[
                        expected.clone(),
                        json!({"address":unexpected,"port":23456,"pid":99})
                    ]
                )
                .is_err()
            );
        }
    }
    #[test]
    fn names() {
        assert!(owned_name("etd-1234abcd"));
        assert!(!owned_name("etd-1234ABCD"));
        assert!(!owned_name("etd-1234abcd-more"));
    }
    #[test]
    fn exact_identity_match() {
        let key = ObjectKey::Rule {
            name: "rule".into(),
            group: Some("EasyTier".into()),
        };
        assert!(rule_match(&key, &json!({"name":"rule","group":"EasyTier"})));
        assert!(!rule_match(
            &key,
            &json!({"name":"rule2","group":"EasyTier"})
        ));
        assert!(!rule_match(&key, &json!({"name":"rule","group":"Foreign"})));
    }
    #[test]
    fn program_identity_includes_real_application() {
        let name = r"EasyTier C:\store\core.exe (Inbound)";
        let key = ObjectKey::Rule {
            name: name.into(),
            group: Some("EasyTier".into()),
        };
        let row = json!({"id":"rule-guid","name":name,"group":"EasyTier","program":r"c:\store\core.exe","direction":"Inbound"});
        let obs = observation(
            Some(program_identity(&row).unwrap()),
            key.clone(),
            String::new(),
        );
        assert!(program_credential_matches(&key, &obs));
        let mut foreign = row;
        foreign["program"] = json!(r"C:\other\core.exe");
        let other = observation(
            Some(program_identity(&foreign).unwrap()),
            key.clone(),
            String::new(),
        );
        assert!(!program_credential_matches(&key, &other));
        assert_ne!(obs.credential, other.credential);
    }
    #[test]
    fn incomplete_filters_in_a_successful_enumeration_are_missing() {
        assert_eq!(fence_presence(true), Ok(()));
        assert!(matches!(fence_presence(false), Err(FenceError::Missing(_))));
        // A failed enumeration is not a verdict.
        assert!(matches!(
            WinError::new(5, "access denied").fence(),
            FenceError::Os { .. }
        ));
    }
    #[test]
    fn a_foreign_program_rule_is_reported_under_the_key_its_condition_names() {
        let name = r"EasyTier C:\store\core.exe (Inbound)";
        let key = ObjectKey::Rule {
            name: name.into(),
            group: Some("EasyTier".into()),
        };
        let row = json!({"id":"other-guid","name":name,"group":"Other","program":r"C:\other\core.exe","direction":"Outbound"});
        let found = observation(
            Some(program_identity(&row).unwrap()),
            key.clone(),
            "d".into(),
        );
        assert!(!program_credential_matches(&key, &found));
        let reported = foreign_program_rule(&found);
        assert_eq!(reported.credential, found.credential, "its own identity");
        assert_eq!(
            reported.key,
            Some(ObjectKey::Rule {
                name: r"EasyTier c:\other\core.exe (Outbound)".into(),
                group: Some("other".into()),
            })
        );
        assert_ne!(reported.key, Some(key));
        // Not even a readable identity: still a different object, never ours.
        let unreadable = Observation {
            credential: Some(opaque("garbage")),
            ..found
        };
        assert_eq!(foreign_program_rule(&unreadable).key, None);
    }
    #[test]
    fn powershell_encoding() {
        assert_eq!(encoded_command("abc"), "YQBiAGMA");
    }
}
