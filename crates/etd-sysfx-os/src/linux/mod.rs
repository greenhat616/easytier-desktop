//! Linux host adapters. iproute2 supplies netlink snapshots, rtnetlink
//! addresses mutations by interface index, and nft commits one transaction per fence.
mod fence;
mod network;
mod observe;
mod resolved;

use async_trait::async_trait;
use etd_contract::InstanceId;
use etd_sysfx::*;
use futures_util::future::BoxFuture;
use serde_json::Value;
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use tokio::process::Command;

#[derive(Clone)]
struct Linux {
    run_dir: PathBuf,
}
struct LinuxReclaimer(EffectKind, Arc<Linux>);

impl LinuxReclaimer {
    async fn current(&self, e: &Effect) -> Result<Option<Observation>, ObserveError> {
        if let (
            EffectKind::LinuxResolvedLink,
            ObjectKey::ResolvedLink { interface },
            Undo::RestoreIfOurs { .. },
        ) = (e.kind, &e.key, &e.undo)
        {
            // An empty list can be the value a RestoreIfOurs record wrote.
            return self.1.resolved_observation(&e.key, interface, true).await;
        }
        self.1.observe(e.kind, &e.key).await
    }
}

pub(crate) fn adapters(config: &crate::OsConfig) -> Result<crate::OsAdapters, crate::OsError> {
    let linux = Arc::new(Linux {
        run_dir: config.run_dir.clone(),
    });
    Ok(crate::OsAdapters {
        reclaimers: [
            EffectKind::LinuxTun,
            EffectKind::LinuxResolvedLink,
            EffectKind::Route,
            EffectKind::LinuxFenceRule,
        ]
        .into_iter()
        .map(|kind| Arc::new(LinuxReclaimer(kind, linux.clone())) as Arc<dyn Reclaimer>)
        .collect(),
        sweeper: linux.clone(),
        boot_id: linux.clone(),
        observer: linux.clone(),
        fence: Some(linux),
    })
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
fn os(error: io::Error) -> ObserveError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        return ObserveError::PermissionDenied(error.to_string());
    }
    ObserveError::Os {
        code: i64::from(error.raw_os_error().unwrap_or(-1)),
        message: error.to_string(),
    }
}
fn uncertain(error: impl std::fmt::Display) -> ReclaimError {
    ReclaimError::Indeterminate(error.to_string())
}

async fn output(program: &str, args: &[&str]) -> io::Result<std::process::Output> {
    tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(program)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .current_dir("/")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(other)?
}
async fn run(program: &str, args: &[&str]) -> io::Result<String> {
    let out = output(program, args).await?;
    if !out.status.success() {
        return Err(other(format!(
            "{program} {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    String::from_utf8(out.stdout).map_err(other)
}
async fn json(program: &str, args: &[&str]) -> io::Result<Value> {
    serde_json::from_str(&run(program, args).await?).map_err(other)
}
fn rows(value: &Value) -> io::Result<&Vec<Value>> {
    value.as_array().ok_or_else(|| other("expected an array"))
}
fn observed(key: &ObjectKey, credential: Credential, detail: Option<String>) -> Observation {
    Observation {
        key: Some(key.clone()),
        credential: Some(credential),
        observed_at: jiff::Timestamp::now(),
        detail,
    }
}
fn boot() -> io::Result<BootId> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Ok(BootId(
        uuid::Uuid::parse_str(value.trim())
            .map_err(other)?
            .to_string(),
    ))
}
impl BootIdSource for Linux {
    fn current(&self) -> Result<BootId, ReclaimError> {
        boot().map_err(uncertain)
    }
}

fn checked_index(
    expected: Option<&Credential>,
    current: Option<&Credential>,
) -> Result<u32, ReclaimError> {
    match current {
        Some(Credential::UnixInterface { index, .. }) if *index != 0 && current == expected => {
            Ok(*index)
        }
        _ => Err(ReclaimError::CredentialMismatch),
    }
}

#[async_trait]
impl Reclaimer for LinuxReclaimer {
    fn kind(&self) -> EffectKind {
        self.0
    }
    fn rank(&self) -> u8 {
        self.0.default_rank()
    }
    async fn probe(&self, e: &Effect) -> Probe {
        if self.0 != e.kind {
            return Probe::Indeterminate("wrong reclaimer".into());
        }
        match self.current(e).await {
            Ok(Some(o)) => Probe::Present(o),
            Ok(None) => Probe::Absent,
            Err(err) => Probe::Indeterminate(err.to_string()),
        }
    }
    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        if self.0 != e.kind {
            return Err(ReclaimError::Unsupported(e.kind));
        }
        let Some(current) = self.current(e).await.map_err(uncertain)? else {
            return Ok(Reclaimed::AlreadyAbsent);
        };
        let expected = e.observation.as_ref().and_then(|o| o.credential.as_ref());
        match (e.kind, &e.undo) {
            (EffectKind::LinuxFenceRule, Undo::EnsureAbsent) => {
                if expected.is_some() && expected != current.credential.as_ref() {
                    return Err(ReclaimError::CredentialMismatch);
                }
                fence::remove(&e.key).await
            }
            (EffectKind::LinuxTun, Undo::EnsureAbsent) => {
                let index = checked_index(expected, current.credential.as_ref())?;
                network::delete(index).await.map_err(uncertain)?;
                Ok(Reclaimed::Removed)
            }
            (EffectKind::LinuxResolvedLink, _) => {
                let index = checked_index(expected, current.credential.as_ref())?;
                resolved::restore(index, &e.undo).await
            }
            // Linux drops these routes with the link. A route that survived is
            // reported; no route is deleted using a name or destination alone.
            (EffectKind::Route, Undo::EnsureAbsent) => {
                Err(ReclaimError::Busy("routes still use this link".into()))
            }
            _ => Err(ReclaimError::Unsupported(e.kind)),
        }
    }
}

impl Sweeper for Linux {
    fn find_marked<'a>(
        &'a self,
        key: Option<&'a InstallKey>,
        known: &'a [InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
        Box::pin(async move {
            let mut found = observe::runtime_objects(&self.run_dir).map_err(uncertain)?;
            for link in network::links().await.map_err(uncertain)? {
                if !link.name.starts_with(naming::INTERFACE_PREFIX) {
                    continue;
                }
                let origin = key
                    .and_then(|k| {
                        known
                            .iter()
                            .find(|id| naming::interface_name(k, id) == link.name)
                    })
                    .map_or(FoundBy::PrefixOnly, |id| FoundBy::DerivedName {
                        instance: id.clone(),
                    });
                let object = network::key(&link.name);
                for (kind, key) in [
                    (
                        EffectKind::Route,
                        ObjectKey::RoutesVia {
                            interface: Some(link.name.clone()),
                        },
                    ),
                    (
                        EffectKind::LinuxResolvedLink,
                        ObjectKey::ResolvedLink {
                            interface: link.name.clone(),
                        },
                    ),
                ] {
                    if let Some(observation) = self.observe(kind, &key).await.map_err(uncertain)? {
                        found.push(FoundObject {
                            kind,
                            key,
                            observation,
                            origin: origin.clone(),
                        });
                    }
                }
                found.push(FoundObject {
                    kind: EffectKind::LinuxTun,
                    observation: observed(&object, link.credential, None),
                    key: object,
                    origin,
                });
            }
            // An unprivileged user host cannot own a kernel nftables table.
            if nix::unistd::Uid::effective().is_root() {
                found.extend(fence::sweep().await.map_err(uncertain)?);
            }
            Ok(found)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interface_requires_both_index_and_boot() {
        let id = |index, boot: &str| Credential::UnixInterface {
            index,
            boot: BootId(boot.into()),
        };
        let expected = id(2, "a");
        assert_eq!(checked_index(Some(&expected), Some(&expected)), Ok(2));
        for found in [None, Some(id(2, "b")), Some(id(3, "a"))] {
            assert_eq!(
                checked_index(Some(&expected), found.as_ref()),
                Err(ReclaimError::CredentialMismatch)
            );
        }
        assert!(checked_index(None, Some(&expected)).is_err());
    }
}
