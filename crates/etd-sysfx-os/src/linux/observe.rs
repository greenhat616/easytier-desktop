use super::*;
use std::{fs, net::SocketAddr, os::unix::fs::MetadataExt, path::Path};

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

#[async_trait]
impl SystemObserver for Linux {
    async fn observe(
        &self,
        kind: EffectKind,
        key: &ObjectKey,
    ) -> Result<Option<Observation>, ObserveError> {
        match (kind, key) {
            (EffectKind::LinuxFenceRule, _) => fence::observe(key).await.map_err(os),
            (EffectKind::LinuxTun, ObjectKey::Interface { .. }) => Ok(self
                .interface(key)
                .await?
                .map(|l| observed(key, l.credential, None))),
            (
                EffectKind::Route,
                ObjectKey::RoutesVia {
                    interface: Some(name),
                },
            ) => {
                let Some(l) = self.interface(&network::key(name)).await? else {
                    return Ok(None);
                };
                let routes = network::routes().await.map_err(os)?;
                Ok(routes
                    .iter()
                    .any(|r| network::via(r, name))
                    .then(|| observed(key, l.credential, None)))
            }
            (EffectKind::LinuxResolvedLink, ObjectKey::ResolvedLink { interface }) => {
                let Some(l) = self.interface(&network::key(interface)).await? else {
                    return Ok(None);
                };
                let Credential::UnixInterface { index, .. } = &l.credential else {
                    return Err(os(other("missing link index")));
                };
                Ok(resolved::read(*index)
                    .await
                    .map_err(os)?
                    .filter(|s| !s.empty())
                    .map(|s| observed(key, l.credential, serde_json::to_string(&s).ok())))
            }
            (EffectKind::RuntimeDir, ObjectKey::Path { path }) => {
                match fs::symlink_metadata(path) {
                    Ok(m) => Ok(Some(observed(key, file(&m), None))),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(os(e)),
                }
            }
            (
                EffectKind::Process,
                ObjectKey::Process {
                    exe,
                    cmdline_marker,
                },
            ) => {
                let mut found = None;
                use std::os::unix::ffi::OsStrExt;
                for p in processes().map_err(os)? {
                    if let ObjectKey::Process { exe: current, .. } = &p.key
                        && current == exe
                        && let Some(Credential::Process { pid, .. }) = &p.identity
                    {
                        let cmd = match fs::read(format!("/proc/{pid}/cmdline")) {
                            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                            r => r.map_err(os)?,
                        };
                        if cmd.split(|b| *b == 0).any(|a| {
                            Path::new(std::ffi::OsStr::from_bytes(a)).starts_with(cmdline_marker)
                        }) {
                            if found.is_some() {
                                return Err(os(other("ambiguous process key")));
                            }
                            found = Some(observed(key, p.identity.unwrap(), None));
                        }
                    }
                }
                Ok(found)
            }
            _ => Err(ObserveError::Unsupported(kind)),
        }
    }
    async fn interface(&self, key: &ObjectKey) -> Result<Option<InterfaceInfo>, ObserveError> {
        match key {
            ObjectKey::Interface {
                name: Some(name),
                guid: None,
            } => Ok(network::links()
                .await
                .map_err(os)?
                .into_iter()
                .find(|l| &l.name == name)),
            _ => Err(ObserveError::Unsupported(EffectKind::LinuxTun)),
        }
    }
    async fn listener(&self, address: SocketAddr) -> Result<Option<ListenerInfo>, ObserveError> {
        tokio::task::spawn_blocking(move || network::listener(address))
            .await
            .map_err(|e| os(other(e)))?
            .map_err(os)
    }
    async fn interfaces_owned_by(&self, pid: u32) -> Result<Vec<InterfaceInfo>, ObserveError> {
        let names = network::tun_names(pid).map_err(os)?;
        Ok(network::links()
            .await
            .map_err(os)?
            .into_iter()
            .filter(|l| names.contains(&l.name))
            .collect())
    }
    async fn enumerate(&self, class: SystemClass) -> Result<Vec<SystemEntry>, ObserveError> {
        self.entries(class).await.map_err(os)
    }
}
fn file(m: &fs::Metadata) -> Credential {
    Credential::File {
        file_id: m.ino(),
        device: m.dev(),
    }
}
fn dirs(path: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        r => r?,
    };
    let mut paths = Vec::new();
    for item in entries {
        let e = item?;
        if e.file_type()?.is_dir() {
            paths.push(e.path());
        }
    }
    Ok(paths)
}

fn processes() -> io::Result<Vec<SystemEntry>> {
    let mut entries = Vec::new();
    let boot = boot()?;
    for item in fs::read_dir("/proc")? {
        let p = item?;
        let Some(pid) = p.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let stat = match fs::read_to_string(p.path().join("stat")) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            r => r?,
        };
        let ticks = stat
            .rsplit_once(')')
            .and_then(|(_, s)| s.split_whitespace().nth(19))
            .ok_or_else(|| other("missing proc start ticks"))?;
        let exe = match fs::read_link(p.path().join("exe")) {
            Ok(path) => path,
            // Kernel threads and zombies have no executable. Their comm is
            // still useful for independent process enumeration.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                PathBuf::new()
            }
            Err(e) => return Err(e),
        };
        let key = ObjectKey::Process {
            exe,
            cmdline_marker: PathBuf::new(),
        };
        entries.push(entry(
            SystemClass::Processes,
            key,
            Some(Credential::Process {
                pid,
                start_token: format!("{}:{ticks}", boot.0),
            }),
            stat.split_once('(')
                .and_then(|(_, s)| s.rsplit_once(')'))
                .map(|(name, _)| name.to_owned())
                .unwrap_or_default(),
        ));
    }
    Ok(entries)
}
impl Linux {
    async fn entries(&self, class: SystemClass) -> io::Result<Vec<SystemEntry>> {
        let mut entries = Vec::new();
        match class {
            SystemClass::Interfaces => {
                for l in network::links().await? {
                    entries.push(entry(
                        class,
                        network::key(&l.name),
                        Some(l.credential),
                        format!("up={} addresses={:?}", l.up, l.addresses),
                    ));
                }
            }
            SystemClass::Routes => {
                for r in network::routes().await? {
                    entries.push(entry(
                        class,
                        ObjectKey::RoutesVia {
                            interface: r["dev"].as_str().map(str::to_owned),
                        },
                        None,
                        r.to_string(),
                    ));
                }
            }
            SystemClass::DnsPolicy => {
                let path = Path::new("/etc/resolv.conf");
                match fs::read_to_string(path) {
                    Ok(content) => entries.push(entry(
                        class,
                        ObjectKey::Path { path: path.into() },
                        Some(file(&fs::metadata(path)?)),
                        content,
                    )),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
                for l in network::links().await? {
                    if let Credential::UnixInterface { index, .. } = l.credential
                        && let Some(s) = resolved::read(index).await?
                        && !s.empty()
                    {
                        entries.push(entry(
                            class,
                            ObjectKey::ResolvedLink { interface: l.name },
                            Some(l.credential),
                            serde_json::to_string(&s).map_err(other)?,
                        ));
                    }
                }
            }
            SystemClass::FirewallRules => {
                for row in fence::ruleset().await? {
                    let Some((kind, v)) = row.as_object().and_then(|o| o.iter().next()) else {
                        return Err(other("invalid nft entry"));
                    };
                    if kind == "metainfo" {
                        continue;
                    }
                    let group = format!(
                        "{}:{}",
                        v["family"],
                        v["table"].as_str().or(v["name"].as_str()).unwrap_or("")
                    );
                    let key = ObjectKey::Rule {
                        name: format!("{kind}/{}", v["handle"]),
                        group: Some(group),
                    };
                    entries.push(entry(
                        class,
                        key,
                        v["handle"].as_u64().map(|h| Credential::Opaque {
                            value: h.to_string(),
                        }),
                        row.to_string(),
                    ));
                }
            }
            SystemClass::Services => {
                let units = json(
                    "/usr/bin/systemctl",
                    &[
                        "list-unit-files",
                        "--type=service",
                        "--output=json",
                        "--no-pager",
                    ],
                )
                .await?;
                for v in rows(&units)? {
                    let name = v["unit_file"]
                        .as_str()
                        .ok_or_else(|| other("systemctl unit file missing name"))?;
                    entries.push(entry(
                        class,
                        ObjectKey::Service { name: name.into() },
                        None,
                        v.to_string(),
                    ));
                }
            }
            SystemClass::RuntimeDirs => {
                for instance in dirs(&self.run_dir)? {
                    for path in dirs(&instance)? {
                        let m = fs::symlink_metadata(&path)?;
                        entries.push(entry(
                            class,
                            ObjectKey::Path { path },
                            Some(file(&m)),
                            format!("mode={:o} uid={} gid={}", m.mode(), m.uid(), m.gid()),
                        ));
                    }
                }
            }
            SystemClass::Processes => return processes(),
            SystemClass::RegistryValues => {}
            _ => return Err(other("unsupported system class")),
        }
        Ok(entries)
    }
}
