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
use std::{fmt, path::Path};

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

/// Of a ledger's open instance records, those that block another user's
/// session: all but records that ended with a reboot since.
fn blocking(effects: &[Effect], boot: &BootId) -> bool {
    effects
        .iter()
        .any(|effect| !(effect.persistence == Persistence::UntilReboot && &effect.boot != boot))
}

/// Read another user's session ledger without changing it. A ledger that
/// cannot be read counts as blocking (fail closed).
async fn leftovers(state: &Path, boot: &BootId) -> bool {
    match storage::ledger_exists(state) {
        Ok(false) => return false,
        Ok(true) => (),
        Err(_) => return true,
    }
    let Ok(ledger) = SqliteLedger::open_with_options(
        state.join(LEDGER),
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
    // Instance records only: a normal exit closes them, so open ones are a
    // crashed session's leftovers. Product records (shared drivers, the
    // WFP provider and sublayer, which only the lock holder manages) and
    // kernel-binary records (program rules on that root's own kernel
    // paths) do not cross roots (doc#13 #ownership) and stay until purge.
    // `reclaim --all-users` without --purge clears exactly these.
    let open = ledger.open_effects(&ScopeFilter::default()).await;
    let _ = ledger.close().await;
    open.map_or(true, |effects| blocking(&effects, boot))
}

/// Machine-wide reconciliation (doc#13 #ownership, under the maintenance
/// lock): every other verified session root must hold no open record. The
/// user's own ledger never blocks; the startup self-check reclaims it.
async fn reconcile(own: &HostLayout, boot: &BootId) -> Result<()> {
    let mut blocked = Vec::new();
    for other in NativeHostFilesystem.session_layouts().map_err(refusal)? {
        if other.state != own.state && leftovers(&other.state, boot).await {
            blocked.push(owner_sid(&other));
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
pub(super) async fn reclaim_all_users(own: &HostLayout, purge: bool) -> Result<()> {
    let _command = enter(own)?;
    let _guard = NativeHostFilesystem.lock(own)?;
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

    #[test]
    fn only_records_from_an_earlier_boot_that_ended_with_it_do_not_block() {
        let now = BootId("now".into());
        assert!(!blocking(&[], &now));
        assert!(!blocking(
            &[effect(Persistence::UntilReboot, "before")],
            &now
        ));
        assert!(blocking(&[effect(Persistence::UntilReboot, "now")], &now));
        assert!(blocking(&[effect(Persistence::Persistent, "before")], &now));
        assert!(blocking(
            &[effect(Persistence::WithProcess, "before")],
            &now
        ));
        assert!(blocking(
            &[
                effect(Persistence::UntilReboot, "before"),
                effect(Persistence::Persistent, "now")
            ],
            &now
        ));
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
