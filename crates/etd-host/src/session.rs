//! The elevated session host (doc#13): a privileged host run by the
//! current user's elevated administrator token instead of the service. It
//! shares the service's maintenance and host locks, keeps its state in the
//! protected tree `%ProgramData%\EasyTierDesk.session\<SID>`, and refuses to
//! start while the service is installed or another user's session left
//! system changes behind.
use super::*;
use etd_sysfx::{
    Persistence,
    sqlite::{OpenOptions, SqliteLedger},
};
use etd_sysfx_os::service::NotConforming;
use std::{
    fmt,
    path::{Path, PathBuf},
};

/// Why an elevated session host refused to start or reclaim. Each has its
/// own process exit code so the UI (ES4) can tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRefusal {
    /// The system service is registered, or its state directory is left.
    ServiceInstalled,
    /// A protected session directory exists but does not conform.
    NotConforming(NotConforming),
    /// Other users' session ledgers still hold open records (their SIDs).
    OtherUsersLeftovers(Vec<String>),
    /// The session pipe name is taken by another process.
    EndpointUnavailable,
}

impl SessionRefusal {
    pub const EXIT_SERVICE_INSTALLED: u8 = 3;
    pub const EXIT_NOT_CONFORMING: u8 = 4;
    pub const EXIT_OTHER_USERS_LEFTOVERS: u8 = 5;
    pub const EXIT_ENDPOINT_UNAVAILABLE: u8 = 6;

    pub fn exit_code(&self) -> u8 {
        match self {
            Self::ServiceInstalled => Self::EXIT_SERVICE_INSTALLED,
            Self::NotConforming(_) => Self::EXIT_NOT_CONFORMING,
            Self::OtherUsersLeftovers(_) => Self::EXIT_OTHER_USERS_LEFTOVERS,
            Self::EndpointUnavailable => Self::EXIT_ENDPOINT_UNAVAILABLE,
        }
    }

    /// The refusal anywhere in `error`'s chain.
    pub fn find(error: &anyhow::Error) -> Option<Self> {
        // A context value is found through the error, not its chain.
        if error
            .downcast_ref::<serving::EndpointUnavailable>()
            .is_some()
        {
            return Some(Self::EndpointUnavailable);
        }
        error.chain().find_map(|cause| {
            if let Some(refusal) = cause.downcast_ref::<Self>() {
                return Some(refusal.clone());
            }
            let io = cause.downcast_ref::<std::io::Error>()?;
            NotConforming::of(io).map(|found| Self::NotConforming(found.clone()))
        })
    }
}

impl fmt::Display for SessionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceInstalled => f.write_str(
                "the system service is installed (or its uninstall is unfinished); use the service, or finish etd-host uninstall first",
            ),
            Self::NotConforming(found) => write!(f, "{found}; it is left untouched"),
            Self::OtherUsersLeftovers(sids) => write!(
                f,
                "elevated sessions of other users left system changes behind ({}); run etd-host reclaim --mode elevated-session --all-users as administrator",
                sids.join(", ")
            ),
            Self::EndpointUnavailable => f.write_str(
                "the elevated session endpoint is taken by another process",
            ),
        }
    }
}

impl std::error::Error for SessionRefusal {}

/// `\\.\pipe\easytier-desk-session-<SID>`.
#[cfg(windows)]
pub(super) fn endpoint_name(sid: &str) -> String {
    format!(r"\\.\pipe\easytier-desk-session-{sid}")
}

fn refusal(error: std::io::Error) -> anyhow::Error {
    match NotConforming::of(&error) {
        Some(found) => SessionRefusal::NotConforming(found.clone()).into(),
        None => error.into(),
    }
}

/// `<SID>` of a session layout, from its directory.
fn owner_sid(layout: &HostLayout) -> String {
    layout
        .state
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The first step of every elevated session entry (run and both reclaim
/// forms): the maintenance lock, then, inside it, the service must be
/// neither registered nor leave its state directory (doc#13 #ownership).
fn enter(layout: &HostLayout) -> Result<MaintenanceLock> {
    let command = NativeHostFilesystem.lock_maintenance(layout)?;
    if NativeServiceManager.is_registered()? || etd_sysfx_os::service::service_state_exists()? {
        bail!(SessionRefusal::ServiceInstalled);
    }
    Ok(command)
}

/// Whether an open record of another user's session root blocks this
/// session (doc#13 #ownership). `root`: that root; `stores`: the kernel
/// stores of every verified session root.
///
/// - Any scope: a record that ended with a reboot since never blocks
///   (`UntilReboot` and `WithProcess` written in another boot).
/// - Instance scope: blocks. A normal exit closes these; open ones are a
///   crashed session's leftovers.
/// - Outside instance scope only two reviewed classes are ignored
///   (lead-approved, topic#51 msg#1824), because every host re-ensures
///   them and none deletes them, so nothing another root's host does acts
///   on them:
///   1. Product `Driver` records of the shared `WinDivert` / `wintun`
///      services whose observed image path is in the system driver
///      directory or inside a verified `<SID>\cores` (the removal of a
///      store is guarded by the driver-reference check). Without an
///      observation only a `Planned` record (never loaded by that root's
///      kernels) or a `Conflict` one (another program's, found before the
///      spawn) is ignored.
///   2. CoreBinary `WinProgramFirewallRule` records in our firewall group
///      whose program path lies inside that root's own `<SID>\cores`.
///
///   Anything else blocks: other kinds or names, other paths, unknown or
///   unreadable values.
fn blocks(effect: &Effect, boot: &BootId, root: &HostLayout, stores: &[PathBuf]) -> bool {
    let ended_with_reboot = matches!(
        effect.persistence,
        Persistence::UntilReboot | Persistence::WithProcess
    ) && &effect.boot != boot;
    if ended_with_reboot {
        return false;
    }
    match &effect.scope {
        EffectScope::Instance { .. } => true,
        EffectScope::Product => !shared_driver_elsewhere(effect, stores),
        EffectScope::CoreBinary { .. } => !program_rule_of(effect, root),
        // A scope this build does not know: unknown ownership.
        _ => true,
    }
}

/// Reviewed class 1 of [`blocks`].
fn shared_driver_elsewhere(effect: &Effect, stores: &[PathBuf]) -> bool {
    use etd_core_easytier::plan::effects::{WINDIVERT_DRIVER, WINTUN_DRIVER};
    let named = matches!(&effect.key, ObjectKey::Service { name }
        if name == WINDIVERT_DRIVER || name == WINTUN_DRIVER);
    if !(shared_driver(effect.kind, Some(&effect.scope)) && named) {
        return false;
    }
    match image_path(effect.observation.as_ref()) {
        Some(image) => driver_image_allowed(&image, stores),
        None => {
            effect.observation.is_none()
                && matches!(effect.state, EffectState::Planned | EffectState::Conflict)
        }
    }
}

/// Reviewed class 2 of [`blocks`].
fn program_rule_of(effect: &Effect, root: &HostLayout) -> bool {
    use etd_core_easytier::plan::effects::FIREWALL_GROUP;
    let ObjectKey::Rule {
        name,
        group: Some(group),
    } = &effect.key
    else {
        return false;
    };
    if effect.kind != EffectKind::WinProgramFirewallRule || group != FIREWALL_GROUP {
        return false;
    }
    // `EasyTier <program> (Inbound|Outbound)`, as the plan names them.
    let program = name
        .strip_prefix("EasyTier ")
        .and_then(|rest| {
            rest.strip_suffix(" (Inbound)")
                .or_else(|| rest.strip_suffix(" (Outbound)"))
        })
        .map(Path::new);
    let recorded = effect
        .observation
        .as_ref()
        .and_then(|observation| match &observation.credential {
            Some(etd_sysfx::Credential::Opaque { value }) => {
                serde_json::from_str::<serde_json::Value>(value).ok()
            }
            _ => None,
        })
        .map(|credential| credential["program"].as_str().map(PathBuf::from));
    let inside = |path: &Path| path_inside(path, &root.cores);
    match (program, recorded) {
        (Some(program), None) => inside(program),
        (Some(program), Some(Some(recorded))) => inside(program) && inside(&recorded),
        // A credential without a program, or a name of another form.
        _ => false,
    }
}

#[cfg(windows)]
fn driver_image_allowed(image: &str, stores: &[PathBuf]) -> bool {
    etd_sysfx_os::service::driver_image_allowed(image, stores)
}
#[cfg(windows)]
fn path_inside(path: &Path, dir: &Path) -> bool {
    etd_sysfx_os::service::path_inside(path, dir)
}
// No session roots outside Windows: nothing is ever ignored there.
#[cfg(unix)]
fn driver_image_allowed(_: &str, _: &[PathBuf]) -> bool {
    false
}
#[cfg(unix)]
fn path_inside(_: &Path, _: &Path) -> bool {
    false
}

/// Whether another user's session root holds anything that blocks this
/// session, read without changing it. Fails closed: a ledger that cannot
/// be read blocks, and so does a root with no ledger but with what a host
/// leaves before it (a repair index, logs, runtime directories): its
/// ownership is unknown.
async fn leftovers(root: &HostLayout, stores: &[PathBuf], boot: &BootId) -> bool {
    match storage::ledger_exists(&root.state) {
        Ok(false) => return unknown_owner(&root.state, &root.run),
        Ok(true) => (),
        Err(_) => return true,
    }
    let Ok(ledger) = SqliteLedger::open_with_options(
        root.state.join(LEDGER),
        boot.clone(),
        OpenOptions {
            read_only: true,
            ..Default::default()
        },
    )
    .await
    else {
        return true;
    };
    let open = ledger.open_effects(&ScopeFilter::all()).await;
    let _ = ledger.close().await;
    open.map_or(true, |effects| {
        effects
            .iter()
            .any(|effect| blocks(effect, boot, root, stores))
    })
}

/// A root without a ledger whose state or run directory is not empty (or
/// cannot be read): a host got that far, so its ownership is unknown.
fn unknown_owner(state: &Path, run: &Path) -> bool {
    let empty =
        |dir: &Path| std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none());
    !(empty(state) && empty(run))
}

/// Machine-wide reconciliation (doc#13 #ownership, under the maintenance
/// and host locks): no other verified session root may hold anything that
/// [`blocks`]. The user's own ledger never blocks; its startup self-check
/// reclaims it.
async fn reconcile(own: &HostLayout, boot: &BootId) -> Result<()> {
    let roots = NativeHostFilesystem.session_layouts().map_err(refusal)?;
    let stores: Vec<PathBuf> = roots.iter().map(|root| root.cores.clone()).collect();
    let mut blocked = Vec::new();
    for other in &roots {
        if other.state != own.state && leftovers(other, &stores, boot).await {
            blocked.push(owner_sid(other));
        }
    }
    if !blocked.is_empty() {
        bail!(SessionRefusal::OtherUsersLeftovers(blocked));
    }
    Ok(())
}

fn current_boot(layout: &HostLayout) -> Result<BootId> {
    Ok(etd_sysfx_os::adapters(&os_config(layout))?
        .boot_id
        .current()?)
}

/// The kernel store: the bundled kernels beside the host image, copied
/// into the protected `<SID>\cores` and hashed there; merged again when this
/// build's release table changed. A merge never deletes a SHA directory, so
/// kernels open records may name stay.
async fn prepare_cores(layout: &HostLayout) -> Result<()> {
    let bundle = layout
        .executable
        .parent()
        .context("missing host image directory")?;
    if !storage::manifest_exists(&layout.cores)? {
        return storage::install_bundled_cores(bundle, &layout.cores, HostMode::ElevatedSession)
            .await;
    }
    if !storage::cores_current(&layout.cores)? {
        let backup = layout.state.join("core-merge-manifest.json");
        storage::upgrade_bundled_cores(bundle, &layout.cores, &backup).await?;
        storage::discard_manifest_backup(&backup)?;
    }
    Ok(())
}

/// The run's lock order (doc#13 #ownership): maintenance lock; inside it the
/// service checks, the protected tree, the host lock (the service's), then
/// machine-wide reconciliation and the kernel store; then the maintenance
/// lock goes and the host serves holding the host lock. Reconciling under
/// the host lock as well means no other privileged host is writing the
/// ledgers it reads, and a running one is reported as such, not as
/// leftovers.
pub(super) async fn acquire(layout: &HostLayout) -> Result<LayoutLock> {
    let command = enter(layout)?;
    NativeHostFilesystem
        .prepare_session(layout)
        .map_err(refusal)?;
    // The system workers redirect their profile variables to this directory
    // only if it exists (ES2): never reach the adapters without it.
    let profile = layout
        .profile
        .as_deref()
        .context("missing session profile directory")?;
    ensure!(
        profile.is_dir(),
        "the session profile directory {} is missing",
        profile.display()
    );
    std::env::set_current_dir(layout.state.parent().context("missing session root")?)?;
    let guard = LayoutLock::new(
        NativeHostFilesystem.lock(layout)?,
        endpoint(HostMode::ElevatedSession, layout)?,
        HostForm::ElevatedSession,
    );
    let boot = current_boot(layout)?;
    reconcile(layout, &boot).await?;
    prepare_cores(layout).await?;
    drop(command);
    Ok(guard)
}

/// `reclaim --mode elevated-session`: the current user's own root.
pub(super) async fn reclaim_own(layout: &HostLayout, purge: bool) -> Result<()> {
    let _command = enter(layout)?;
    if !layout.state.try_exists()? {
        println!("No elevated session state for this user; nothing to reclaim");
        return Ok(());
    }
    NativeHostFilesystem
        .validate_session(layout)
        .map_err(refusal)?;
    let _guard = NativeHostFilesystem.lock(layout)?;
    let deps = dependencies(HostMode::ElevatedSession, layout).await?;
    let result = reclaim_locked(&deps.host, purge).await;
    let closed = deps.close().await;
    result?;
    closed
}

/// `reclaim --mode elevated-session --all-users`: every user's root, under
/// the same locks.
/// `locks`: any layout with the shared maintenance directory; only its
/// locks are taken.
pub(super) async fn reclaim_all_users(locks: &HostLayout, purge: bool) -> Result<()> {
    let _command = enter(locks)?;
    let _guard = NativeHostFilesystem.lock(locks)?;
    drain(purge).await
}

/// Reclaim every verified session root; with `purge`, everything, then
/// remove `EasyTierDesk.session`. A candidate or conflict stops it with the
/// report and keeps the ownership data. The caller holds the maintenance
/// and host locks.
pub(super) async fn drain(purge: bool) -> Result<()> {
    for layout in NativeHostFilesystem.session_layouts().map_err(refusal)? {
        if !storage::ledger_exists(&layout.state)? {
            continue;
        }
        let sid = owner_sid(&layout);
        println!("Elevated session of {sid}:");
        let deps = dependencies(HostMode::ElevatedSession, &layout).await?;
        let result = reclaim_locked(&deps.host, purge).await;
        let closed = deps.close().await;
        result.with_context(|| format!("elevated session of {sid}"))?;
        closed?;
    }
    if purge {
        NativeHostFilesystem
            .remove_session_roots()
            .map_err(refusal)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use etd_sysfx::{EffectId, Undo};

    fn effect(persistence: Persistence, boot: &str) -> Effect {
        Effect {
            id: EffectId("e".into()),
            scope: EffectScope::Instance {
                instance: etd_contract::InstanceId("i".into()),
                epoch: etd_sysfx::Epoch(1),
            },
            kind: EffectKind::WinFirewallRule,
            key: ObjectKey::Service { name: "x".into() },
            undo: Undo::EnsureAbsent,
            persistence,
            state: EffectState::Applied,
            boot: BootId(boot.into()),
            observation: None,
            failures: 0,
            last_error: None,
            recorded_at: "1970-01-01T00:00:00Z".parse().unwrap(),
        }
    }

    #[cfg(windows)]
    fn root() -> HostLayout {
        NativeHostFilesystem
            .session_layout("S-1-5-21-1-2-3-1002")
            .unwrap()
    }

    #[cfg(windows)]
    fn observed(
        detail: Option<serde_json::Value>,
        credential: Option<serde_json::Value>,
    ) -> Option<etd_sysfx::Observation> {
        Some(etd_sysfx::Observation {
            credential: credential.map(|value| etd_sysfx::Credential::Opaque {
                value: value.to_string(),
            }),
            key: None,
            observed_at: "1970-01-01T00:00:00Z".parse().unwrap(),
            detail: detail.map(|detail| detail.to_string()),
        })
    }

    #[cfg(windows)]
    #[test]
    fn instance_records_block_unless_they_ended_with_a_reboot() {
        let (now, root) = (BootId("now".into()), root());
        let blocked = |persistence, boot| blocks(&effect(persistence, boot), &now, &root, &[]);
        assert!(!blocked(Persistence::UntilReboot, "before"));
        assert!(!blocked(Persistence::WithProcess, "before"));
        assert!(blocked(Persistence::UntilReboot, "now"));
        assert!(blocked(Persistence::WithProcess, "now"));
        assert!(blocked(Persistence::Persistent, "before"));
        assert!(blocked(Persistence::Persistent, "now"));
    }

    #[cfg(windows)]
    #[test]
    fn only_shared_drivers_loaded_from_the_system_or_a_session_store_are_ignored() {
        let (now, root) = (BootId("now".into()), root());
        let stores = [root.cores.clone()];
        let driver = |name: &str, state, image: Option<String>| Effect {
            scope: EffectScope::Product,
            kind: EffectKind::Driver,
            key: ObjectKey::Service { name: name.into() },
            state,
            observation: image
                .and_then(|image| observed(Some(serde_json::json!({ "image_path": image })), None)),
            ..effect(Persistence::Persistent, "now")
        };
        let blocked = |effect: Effect| blocks(&effect, &now, &root, &stores);
        let in_store = root
            .cores
            .join("0a")
            .join("wintun.sys")
            .display()
            .to_string();
        assert!(!blocked(driver(
            "wintun",
            EffectState::Applied,
            Some(in_store.clone())
        )));
        assert!(!blocked(driver(
            "WinDivert",
            EffectState::Applied,
            Some(r"\SystemRoot\System32\drivers\WinDivert64.sys".into())
        )));
        assert!(blocked(driver(
            "wintun",
            EffectState::Applied,
            Some(r"C:\Temp\wintun.sys".into())
        )));
        assert!(blocked(driver(
            "other",
            EffectState::Applied,
            Some(in_store)
        )));
        // Never observed: ignored only if never loaded, or another program's.
        assert!(!blocked(driver("wintun", EffectState::Planned, None)));
        assert!(!blocked(driver("wintun", EffectState::Conflict, None)));
        assert!(blocked(driver("wintun", EffectState::Applied, None)));
        assert!(blocked(Effect {
            kind: EffectKind::ServiceRegistration,
            ..driver("wintun", EffectState::Planned, None)
        }));
    }

    #[cfg(windows)]
    #[test]
    fn only_our_program_rules_on_that_roots_own_kernels_are_ignored() {
        let (now, root) = (BootId("now".into()), root());
        let kernel = root.cores.join("0a").join("easytier-core.exe");
        let rule = |program: &Path, group: Option<&str>, recorded: Option<&Path>| Effect {
            scope: EffectScope::CoreBinary {
                sha256: "0a".into(),
            },
            kind: EffectKind::WinProgramFirewallRule,
            key: ObjectKey::Rule {
                name: format!("EasyTier {} (Inbound)", program.display()),
                group: group.map(Into::into),
            },
            observation: recorded.and_then(|recorded| {
                observed(
                    None,
                    Some(serde_json::json!({ "program": recorded.display().to_string() })),
                )
            }),
            ..effect(Persistence::Persistent, "now")
        };
        let blocked = |effect: Effect| blocks(&effect, &now, &root, &[]);
        assert!(!blocked(rule(&kernel, Some("EasyTier"), None)));
        assert!(!blocked(rule(&kernel, Some("EasyTier"), Some(&kernel))));
        assert!(blocked(rule(&kernel, None, None)));
        assert!(blocked(rule(&kernel, Some("Other"), None)));
        let elsewhere = Path::new(r"C:\Temp\easytier-core.exe");
        assert!(blocked(rule(elsewhere, Some("EasyTier"), None)));
        assert!(blocked(rule(&kernel, Some("EasyTier"), Some(elsewhere))));
        let other_root = NativeHostFilesystem
            .session_layout("S-1-5-21-1-2-3-1003")
            .unwrap()
            .cores
            .join("0a")
            .join("easytier-core.exe");
        assert!(blocked(rule(&other_root, Some("EasyTier"), None)));
    }

    #[test]
    fn a_root_without_a_ledger_blocks_once_a_host_got_further() {
        let dir = tempfile::tempdir().unwrap();
        let (state, run) = (dir.path().join("state"), dir.path().join("run"));
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        assert!(!unknown_owner(&state, &run));
        std::fs::write(state.join("repair-index.json"), b"{}").unwrap();
        assert!(unknown_owner(&state, &run));
        std::fs::remove_file(state.join("repair-index.json")).unwrap();
        std::fs::create_dir(run.join("i")).unwrap();
        assert!(unknown_owner(&state, &run));
        assert!(unknown_owner(&dir.path().join("missing"), &run));
    }

    #[test]
    fn every_refusal_has_its_own_exit_code_and_is_found_in_the_chain() {
        let refusals = [
            SessionRefusal::ServiceInstalled,
            SessionRefusal::NotConforming(NotConforming {
                path: "p".into(),
                reason: "r".into(),
            }),
            SessionRefusal::OtherUsersLeftovers(vec!["S-1-5-21-1".into()]),
            SessionRefusal::EndpointUnavailable,
        ];
        let mut codes: Vec<_> = refusals.iter().map(SessionRefusal::exit_code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), refusals.len());
        assert!(!codes.contains(&0) && !codes.contains(&1));
        for refusal in refusals {
            let error = anyhow::Error::new(refusal.clone()).context("outer");
            assert_eq!(SessionRefusal::find(&error), Some(refusal));
        }
        let io = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            NotConforming {
                path: "q".into(),
                reason: "owner".into(),
            },
        );
        assert!(matches!(
            SessionRefusal::find(&anyhow::Error::new(io).context("prepare")),
            Some(SessionRefusal::NotConforming(_))
        ));
        assert_eq!(
            SessionRefusal::find(
                &anyhow::anyhow!("pipe busy")
                    .context(serving::EndpointUnavailable)
                    .context("serve")
            ),
            Some(SessionRefusal::EndpointUnavailable)
        );
        assert_eq!(SessionRefusal::find(&anyhow::anyhow!("other")), None);
    }

    #[cfg(windows)]
    #[test]
    fn the_session_pipe_is_named_after_the_owner() {
        assert_eq!(
            endpoint_name("S-1-5-21-1-2-3-1001"),
            r"\\.\pipe\easytier-desk-session-S-1-5-21-1-2-3-1001"
        );
    }
}
