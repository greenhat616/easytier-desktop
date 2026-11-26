//! Windows system effects, using a persistent native WFP fence and independent
//! Windows management provider queries. No request data is executed as code.
mod interfaces;
mod probe;
mod wfp;

use crate::{OsAdapters, OsConfig, OsError};
use async_trait::async_trait;
use etd_contract::InstanceId;
use etd_sysfx::*;
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::process::Command;
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
        if self.message.contains("BUSY:") {
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
fn system_powershell() -> Result<PathBuf, WinError> {
    let mut buf = [0u16; 32768];
    let n =
        unsafe { ::windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut buf)) }
            as usize;
    if n == 0 || n >= buf.len() {
        return Err(WinError::invalid("GetSystemDirectoryW failed"));
    }
    use std::os::windows::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]))
        .join("WindowsPowerShell/v1.0/powershell.exe"))
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
async fn query(request: Value) -> Result<Vec<Value>, WinError> {
    let exe = system_powershell()?;
    let modules = exe
        .parent()
        .ok_or_else(|| WinError::invalid("invalid system PowerShell path"))?
        .join("Modules");
    let mut cmd = Command::new(&exe);
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        &encoded_command(include_str!("system.ps1")),
    ])
    .env("ETD_OS_REQUEST", request.to_string())
    .env("PSModulePath", modules)
    .current_dir(exe.parent().unwrap())
    .kill_on_drop(true)
    .creation_flags(0x08000000);
    let output = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .map_err(|_| WinError::invalid("Windows management query timed out"))?
        .map_err(|e| WinError::new(e.raw_os_error().unwrap_or(-1) as i64, e.to_string()))?;
    if !output.status.success() {
        return Err(WinError::new(
            output.status.code().unwrap_or(-1) as i64,
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }
    let mut response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| WinError::invalid(format!("invalid management response: {e}")))?;
    response["result"]
        .as_array_mut()
        .map(std::mem::take)
        .ok_or_else(|| WinError::invalid("missing management result"))
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
        EffectKind::WinFenceFilter => wfp::observe(key),
        EffectKind::WinTunAdapter => interfaces::observe(key),
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
            let rows = query(json!({"op":"drivers"})).await?;
            // Shared drivers have no creation credential in the upstream API.
            Ok(rows
                .iter()
                .find(|r| {
                    r["name"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(name))
                })
                .map(|r| observation(None, key.clone(), r["description"].to_string())))
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
            EffectKind::WinFenceFilter => return wfp::remove(&e.key).map_err(WinError::reclaim),
            EffectKind::WinTunAdapter => return Err(ReclaimError::Busy("live adapter; never uninstall live wintun".into())),
            EffectKind::Route => return Err(ReclaimError::Busy("routes still present; never delete routes blindly".into())),
            EffectKind::WinRegistryValue => {
                let (path,value) = registry_value_key(&e.key).map_err(WinError::reclaim)?;
                let Undo::RestoreIfOurs { ours, original } = &e.undo else { return Err(ReclaimError::CredentialMismatch); };
                single(json!({"op":"restore_registry","key":path,"value":value,"ours":ours,"original":original})).await
            }
            EffectKind::WinMagicDnsRecovery => {
                if e.undo != Undo::ReplayUpstreamRecovery { return Err(ReclaimError::CredentialMismatch); }
                single(json!({"op":"replay_magic","core_store":self.1})).await
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
            if kind == EffectKind::WinProgramFirewallRule && !program_credential_matches(key, o) {
                return Err(WinError::invalid("same-name program rule has a different application condition, group or direction").observe());
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
    let mut matches = rows.iter().filter(|r| {
        r["port"].as_u64() == Some(address.port() as u64)
            && r["address"]
                .as_str()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip == address.ip())
    });
    let Some(row) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(WinError::invalid("multiple listeners"));
    }
    let pid = row["pid"]
        .as_u64()
        .and_then(|p| u32::try_from(p).ok())
        .ok_or_else(|| WinError::invalid("missing listener PID"))?;
    Ok(Some(ListenerInfo { address, pid }))
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
            for (key, o) in wfp::enumerate()? {
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
struct WindowsBoot;
impl BootIdSource for WindowsBoot {
    fn current(&self) -> Result<BootId, ReclaimError> {
        probe::boot_id().map_err(WinError::reclaim)
    }
}
struct WindowsSweeper {
    core_store_dir: PathBuf,
}
impl Sweeper for WindowsSweeper {
    fn find_marked<'a>(
        &'a self,
        key: Option<&'a InstallKey>,
        known: &'a [InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
        Box::pin(async move {
            let mut found = Vec::new();
            for (key, observation) in wfp::enumerate().map_err(WinError::reclaim)? {
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
            for (object, info) in interfaces::enumerate().await.map_err(WinError::reclaim)? {
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
            for row in query(json!({"op":"firewall"}))
                .await
                .map_err(WinError::reclaim)?
            {
                let name = string(&row, "name").map_err(WinError::reclaim)?;
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
                        found.push(FoundObject {
                            kind: EffectKind::WinProgramFirewallRule,
                            key: object.clone(),
                            observation: observation(
                                Some(program_identity(&row).map_err(WinError::reclaim)?),
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
                found.push(FoundObject {
                    kind: EffectKind::WinFirewallRule,
                    key: object.clone(),
                    observation: observation(
                        Some(opaque(string(&row, "id").map_err(WinError::reclaim)?)),
                        object,
                        "marked firewall rule".into(),
                    ),
                    origin: origin(iface),
                });
            }
            for row in query(json!({"op":"profiles"}))
                .await
                .map_err(WinError::reclaim)?
            {
                let name = string(&row, "name").map_err(WinError::reclaim)?;
                if !owned_name(name) {
                    continue;
                }
                let object = ObjectKey::NetworkProfile {
                    profile_name: name.into(),
                };
                found.push(FoundObject {
                    kind: EffectKind::WinNetworkProfile,
                    key: object.clone(),
                    observation: observation(
                        Some(opaque(string(&row, "id").map_err(WinError::reclaim)?)),
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
                for row in query(json!({"op":"registry_rows"}))
                    .await
                    .map_err(WinError::reclaim)?
                {
                    let path = string(&row, "key").map_err(WinError::reclaim)?;
                    let Some((instance, _)) = names.iter().find(|(_, guid)| {
                        path.to_ascii_lowercase().ends_with(&format!("{{{guid}}}"))
                    }) else {
                        continue;
                    };
                    let object = ObjectKey::Registry {
                        key: path.into(),
                        value: Some(string(&row, "value").map_err(WinError::reclaim)?.into()),
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
            let magic = ObjectKey::Registry {
                key: r"HKLM\SOFTWARE\EasyTier\MagicDNS".into(),
                value: None,
            };
            if let Some(obs) = observe_kind(EffectKind::WinMagicDnsRecovery, &magic)
                .await
                .map_err(WinError::reclaim)?
            {
                found.push(FoundObject {
                    kind: EffectKind::WinMagicDnsRecovery,
                    key: magic,
                    observation: obs,
                    origin: FoundBy::PrefixOnly,
                });
            }
            for row in query(json!({"op":"drivers"}))
                .await
                .map_err(WinError::reclaim)?
            {
                let name = string(&row, "name").map_err(WinError::reclaim)?;
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
        wfp::install(&wfp::key(spec)).map_err(WinError::fence)
    }
    async fn verify(
        &self,
        spec: &FenceSpec,
        listener_pid: u32,
    ) -> Result<FenceVerification, FenceError> {
        if !wfp::complete(&wfp::key(spec)).map_err(WinError::fence)? {
            return Err(FenceError::Probe("persistent fence is incomplete".into()));
        }
        let before = listener(spec.address).await.map_err(WinError::fence)?;
        let check = match before {
            Some(l) if l.pid == listener_pid => ListenerCheck::Expected,
            Some(l) => ListenerCheck::Other { pid: l.pid },
            None => ListenerCheck::NotListening,
        };
        if check != ListenerCheck::Expected {
            return Ok(FenceVerification {
                listener: check,
                host: DirectionResult::NoListener,
                unprivileged: DirectionResult::NoListener,
            });
        }
        let host = match tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(spec.address),
        )
        .await
        {
            Ok(Ok(_)) => DirectionResult::Connected,
            Ok(Err(e)) => DirectionResult::Error(e.to_string()),
            Err(_) => DirectionResult::Error("host connection timed out".into()),
        };
        let address = spec.address;
        let unprivileged =
            tokio::task::spawn_blocking(move || probe::unprivileged_connect(address))
                .await
                .map_err(|e| FenceError::Probe(e.to_string()))??;
        let after = listener(spec.address).await.map_err(WinError::fence)?;
        if !wfp::complete(&wfp::key(spec)).map_err(WinError::fence)? {
            return Err(FenceError::Probe(
                "persistent fence changed during verification".into(),
            ));
        }
        let check = match after {
            Some(l) if l.pid == listener_pid => ListenerCheck::Expected,
            Some(l) => ListenerCheck::Other { pid: l.pid },
            None => ListenerCheck::NotListening,
        };
        Ok(FenceVerification {
            listener: check,
            host,
            unprivileged,
        })
    }
    async fn remove(&self, spec: &FenceSpec) -> Result<Reclaimed, FenceError> {
        wfp::remove(&wfp::key(spec)).map_err(WinError::fence)
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
        }),
        boot_id: Arc::new(WindowsBoot),
        observer: Arc::new(WindowsObserver {
            run_dir: config.run_dir.clone(),
        }),
        fence: Some(Arc::new(WindowsFence)),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
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
    fn powershell_encoding() {
        assert_eq!(encoded_command("abc"), "YQBiAGMA");
    }
}
