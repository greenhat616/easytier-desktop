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
    core_store_dir: PathBuf,
}
struct LinuxReclaimer(EffectKind, Arc<Linux>);

impl LinuxReclaimer {
    async fn current(&self, e: &Effect) -> Result<Option<Observation>, ObserveError> {
        if let (EffectKind::LinuxResolvedLink, ObjectKey::ResolvedLink { interface }) =
            (e.kind, &e.key)
        {
            let include_empty = matches!(e.undo, Undo::RestoreIfOurs { .. });
            let previously_seen = e
                .observation
                .as_ref()
                .is_some_and(|o| o.credential.is_some());
            return self
                .1
                .resolved_observation(&e.key, interface, include_empty, previously_seen)
                .await;
        }
        self.1.observe(e.kind, &e.key).await
    }
}

pub(crate) fn adapters(config: &crate::OsConfig) -> Result<crate::OsAdapters, crate::OsError> {
    let linux = Arc::new(Linux {
        run_dir: config.run_dir.clone(),
        core_store_dir: config.core_store_dir.clone(),
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

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(other)?
}

async fn output(program: &str, args: &[&str]) -> io::Result<std::process::Output> {
    for directory in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        let executable = std::path::Path::new(directory).join(program);
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            Command::new(&executable)
                .args(args)
                .env_clear()
                .env("LC_ALL", "C")
                .current_dir("/")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(other)?;
        match result {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // execve also returns ENOENT for a missing interpreter.
                match tokio::fs::symlink_metadata(&executable).await {
                    Err(missing) if missing.kind() == io::ErrorKind::NotFound => continue,
                    Err(inspect) => return Err(inspect),
                    Ok(_) => {
                        return Err(io::Error::new(
                            e.kind(),
                            format!("could not execute {}: {e}", executable.display()),
                        ));
                    }
                }
            }
            other => return other,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{program} missing from system executable directories"),
    ))
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
                self.1.remove_fence(&e.key, e.scope.generation()).await
            }
            (EffectKind::LinuxTun, Undo::EnsureAbsent) => {
                let index = checked_index(expected, current.credential.as_ref())?;
                network::delete(index).await.map_err(uncertain)
            }
            (EffectKind::LinuxResolvedLink, _) => {
                let index = checked_index(expected, current.credential.as_ref())?;
                // R1 ruling (msg#940): the verified TUN owns its resolve1 link settings.
                // Only this credential-checked path may authorize RevertLink.
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
            let root = self.run_dir.clone();
            let mut found = blocking(move || observe::runtime_objects(&root))
                .await
                .map_err(uncertain)?;
            let links: Vec<_> = network::links()
                .await
                .map_err(uncertain)?
                .into_iter()
                .filter(|l| l.name.starts_with(naming::INTERFACE_PREFIX))
                .collect();
            if !links.is_empty() {
                let routes = network::routes().await;
                let manager = resolved::manager(false).await;
                for link in links {
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
                    let mut related = |kind, key, detail| {
                        found.push(FoundObject {
                            kind,
                            observation: observed(&key, link.credential.clone(), detail),
                            key,
                            origin: origin.clone(),
                        })
                    };
                    match &routes {
                        Ok(routes) if routes.iter().any(|r| network::via(r, &link.name)) => {
                            related(
                                EffectKind::Route,
                                ObjectKey::RoutesVia {
                                    interface: Some(link.name.clone()),
                                },
                                None,
                            )
                        }
                        Err(error) => {
                            tracing::warn!(interface=%link.name,%error,"skipped route inspection during sweep")
                        }
                        _ => {}
                    }
                    if let Credential::UnixInterface { index, .. } = link.credential {
                        let dns = match &manager {
                            Ok(m) => resolved::read_from(m.as_ref(), index).await,
                            Err(error) => Err(other(error)),
                        };
                        match dns {
                            Ok(Some(settings)) if !settings.empty() => related(
                                EffectKind::LinuxResolvedLink,
                                ObjectKey::ResolvedLink {
                                    interface: link.name.clone(),
                                },
                                serde_json::to_string(&settings).ok(),
                            ),
                            Err(error) => {
                                tracing::warn!(interface=%link.name,index,%error,"skipped resolve1 link during sweep")
                            }
                            _ => {}
                        }
                    }
                    found.push(FoundObject {
                        kind: EffectKind::LinuxTun,
                        observation: observed(&object, link.credential, None),
                        key: object,
                        origin,
                    });
                }
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
