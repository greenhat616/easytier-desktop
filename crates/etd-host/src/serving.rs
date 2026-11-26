//! Native listener and host lifecycle shared by the product and integration fixtures.
use anyhow::{Context, Result};
use etd_contract::{
    AllowEntry, HostMode, capability,
    v1::{self, os_principal::Id},
};
use etd_host_core::{
    api::{Command, HostDeps, HostView, orchestrator_channel},
    auth::allow_list::AllowListAuthorizer,
    lifecycle::Orchestrator,
    service::{AllowListSink, ContractService},
    stub::host_service_server::HostServiceServer,
};
use etd_ipc::{
    BoxConn, Endpoint, HostForm, Listener, ListenerPolicy, OsGroupId, OsUserId, PeerIdentity,
    platform::{self, HeldHostLock, LocalListener, PolicyHandle},
    tonic_io,
};
use etd_sysfx_os::service::HostLock;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{oneshot, watch},
};

const CAPACITY: usize = 256;

pub(crate) struct LayoutLock {
    _guard: HostLock,
    endpoint: Endpoint,
    form: HostForm,
}
impl LayoutLock {
    pub(crate) fn new(guard: HostLock, endpoint: Endpoint, form: HostForm) -> Self {
        Self {
            _guard: guard,
            endpoint,
            form,
        }
    }
}
impl HeldHostLock for LayoutLock {
    fn form(&self) -> HostForm {
        self.form
    }
    fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

#[cfg(windows)]
pub(crate) fn valid_sid(sid: &str) -> bool {
    let mut parts = sid.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return false;
    }
    let Some(authority) = parts.next().and_then(|text| {
        text.parse::<u64>()
            .ok()
            .filter(|value| value.to_string() == text)
    }) else {
        return false;
    };
    let subauthorities: Vec<_> = parts.collect();
    authority < (1u64 << 48)
        && !subauthorities.is_empty()
        && subauthorities.len() <= 15
        && subauthorities.iter().all(|value| {
            value
                .parse::<u32>()
                .is_ok_and(|number| number.to_string() == *value)
        })
}

pub(crate) fn policy(mode: HostMode, entries: &[AllowEntry]) -> io::Result<ListenerPolicy> {
    let mut policy = ListenerPolicy::default();
    if mode == HostMode::User {
        return Ok(policy);
    }
    for entry in entries {
        let id = entry
            .principal
            .as_ref()
            .and_then(|principal| principal.id.as_ref())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing allow-list principal")
            })?;
        match id {
            #[cfg(windows)]
            Id::WindowsUserSid(sid) if valid_sid(sid) => {
                policy.allow_users.push(OsUserId::WindowsSid(sid.clone()))
            }
            #[cfg(windows)]
            Id::WindowsGroupSid(sid) if valid_sid(sid) => {
                policy.allow_groups.push(OsGroupId::WindowsSid(sid.clone()))
            }
            #[cfg(unix)]
            Id::UnixUid(uid) if *uid != u32::MAX => {
                policy.allow_users.push(OsUserId::UnixUid(*uid))
            }
            #[cfg(unix)]
            Id::UnixGid(gid) if *gid != u32::MAX => {
                policy.allow_groups.push(OsGroupId::UnixGid(*gid))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid allow-list principal for this platform",
                ));
            }
        }
    }
    Ok(policy)
}

struct AclSink(PolicyHandle);
impl AllowListSink for AclSink {
    fn validate(&self, entries: &[AllowEntry]) -> io::Result<()> {
        policy(HostMode::Service, entries).map(|_| ())
    }
    fn apply(&self, entries: &[AllowEntry]) -> io::Result<()> {
        self.0.update(&policy(HostMode::Service, entries)?)
    }
}

fn capabilities(mode: HostMode) -> Vec<String> {
    let mut values = vec![
        capability::INSTANCES,
        capability::LOGS,
        capability::RECLAIM,
        capability::RECLAIM_CANDIDATES,
        capability::ADMIN_CORES,
        capability::ADMIN_PURGE,
        capability::QUERY_NODES,
        capability::QUERY_ROUTES,
        capability::QUERY_TRAFFIC,
    ];
    if mode == HostMode::Service {
        values.extend([capability::TUN, capability::ADMIN_ALLOW_LIST]);
    } else {
        values.push(capability::LEASE);
    }
    values.into_iter().map(str::to_owned).collect()
}

/// The listener, lease tracking and service lifecycle are shared by the
/// production binary and native-transport composition tests.
pub(crate) async fn serve_with_deps(
    mode: HostMode,
    guard: LayoutLock,
    deps: Arc<HostDeps>,
    mut managed_stop: Option<watch::Receiver<bool>>,
    start_blocker: Option<String>,
) -> Result<()> {
    // Load the exact durable settings before publishing the endpoint; no
    // mutation task exists until the new listener is bound with that policy.
    let entries = deps.ledger.settings().await?.allow_list;
    let owner = if mode == HostMode::User {
        Some(platform::current_user()?)
    } else {
        None
    };
    let auth = Arc::new(AllowListAuthorizer::new(mode, owner));
    auth.load(deps.ledger.as_ref()).await?;
    let listener =
        LocalListener::bind_replacing_stale(guard.listener_claim(), &policy(mode, &entries)?)?;
    let sink = Arc::new(AclSink(listener.policy_handle()));
    let mut deps = Arc::into_inner(deps).context("unexpected host dependency sharing")?;
    deps.authorizer = auth.clone();
    let deps = Arc::new(deps);
    let (handle, port) = orchestrator_channel(
        CAPACITY,
        HostView {
            seq: 0,
            snapshot: v1::HostSnapshot {
                phase: v1::HostPhase::SelfCheck as i32,
                ..Default::default()
            },
        },
    );
    let svc = ContractService::with_allow_list_sink(
        mode,
        deps.ledger.clone(),
        deps.install_key.clone(),
        auth,
        deps.core_store.clone(),
        handle.clone(),
        capabilities(mode),
        CAPACITY,
        sink,
    )
    .with_start_blocker(start_blocker);
    let incoming = tonic_io::incoming(TrackedListener::new(listener, svc.clone(), mode));
    let orchestrator = Orchestrator::new(deps, port);
    let mut orchestration = tokio::spawn(orchestrator.run());
    let (stop_server, stop_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(HostServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stop_rx.await;
            }),
    );
    let outcome = tokio::select! {
        result = &mut orchestration => { result?; None },
        result = &mut server => { Some(result?.map_err(anyhow::Error::from)) },
        result = shutdown_signal(&mut managed_stop) => { result?; Some(Ok(())) },
    };
    if let Some(outcome) = outcome {
        let (reply, acknowledged) = oneshot::channel();
        if handle.send(Command::Shutdown { reply }).await.is_ok() {
            let _ = acknowledged.await;
        }
        orchestration.await?;
        outcome?;
    }
    let _ = stop_server.send(());
    if !server.is_finished() {
        // Give the final ReleaseLease/Shutdown reply time to reach the
        // client after the orchestrator exits. Long-lived subscriptions must
        // not pin the listener or singleton lock indefinitely.
        if tokio::time::timeout(std::time::Duration::from_secs(3), &mut server)
            .await
            .is_err()
        {
            server.abort();
            let _ = server.await;
        }
    }
    drop(guard);
    Ok(())
}

async fn shutdown_signal(managed: &mut Option<watch::Receiver<bool>>) -> io::Result<()> {
    if let Some(stop) = managed {
        if !*stop.borrow() {
            let _ = stop.changed().await;
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c().await
    }
}

struct Presence {
    count: Mutex<usize>,
    service: ContractService,
    user: bool,
}
impl Presence {
    fn change(&self, add: bool) {
        let mut count = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if add {
            *count += 1;
        } else {
            *count = count.saturating_sub(1);
        }
        self.service
            .set_connection_presence(*count, if self.user { *count } else { 0 });
    }
}
struct TrackedListener {
    listener: LocalListener,
    presence: Arc<Presence>,
}
impl TrackedListener {
    fn new(listener: LocalListener, service: ContractService, mode: HostMode) -> Self {
        Self {
            listener,
            presence: Arc::new(Presence {
                count: Mutex::new(0),
                service,
                user: mode == HostMode::User,
            }),
        }
    }
}
#[async_trait::async_trait]
impl Listener for TrackedListener {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)> {
        let (conn, peer) = self.listener.accept().await?;
        self.presence.change(true);
        Ok((
            Box::new(TrackedConnection {
                conn,
                presence: self.presence.clone(),
            }),
            peer,
        ))
    }
}
struct TrackedConnection {
    conn: BoxConn,
    presence: Arc<Presence>,
}
impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.presence.change(false);
    }
}
impl AsyncRead for TrackedConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}
impl AsyncWrite for TrackedConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.conn).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}
