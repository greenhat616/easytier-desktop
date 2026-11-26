//! Contract RPC service. All methods, including streaming methods, share
//! the same version and role guard; identities come from IPC connect info.
use crate::{
    api::{ClientPresence, Command, OrchestratorHandle, Planned},
    auth::{Authorizer, allow_list::AllowListAuthorizer, role_allows},
    core_store::{CoreSelector, CoreStore},
    events::EventJournal,
    negotiate::{check_version, rejection, status, version_mismatch},
    stub::host_service_server::HostService,
};
use etd_contract::{v1::*, *};
use etd_ipc::{OsUserId, PeerIdentity};
use etd_sysfx::{
    Change, ChangeSet, InstallKey, Ledger, LedgerError, RequestDigest, RequestRecord, RequestStatus,
};
use futures_util::{
    StreamExt,
    stream::{self, BoxStream},
};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct ContractService {
    inner: Arc<Inner>,
}

/// The composition root supplies the real listener ACL updater. Applying an
/// allow-list is synchronous: a successful reply must never precede the ACL
/// update. An error leaves contract authorization disabled until recovery.
pub trait AllowListSink: Send + Sync {
    /// Check deterministic policy errors before committing the mutation.
    /// OS publication can still fail afterwards and is retried fail-closed.
    fn validate(&self, _entries: &[AllowEntry]) -> std::io::Result<()> {
        Ok(())
    }
    fn apply(&self, entries: &[AllowEntry]) -> std::io::Result<()>;
}

struct NoopAllowListSink;
impl AllowListSink for NoopAllowListSink {
    fn apply(&self, _: &[AllowEntry]) -> std::io::Result<()> {
        Ok(())
    }
}

struct Inner {
    mode: HostMode,
    ledger: Arc<dyn Ledger>,
    install_key: InstallKey,
    authorizer: Arc<AllowListAuthorizer>,
    allow_list_sink: Arc<dyn AllowListSink>,
    start_blocker: Option<String>,
    store: Arc<dyn CoreStore>,
    handle: OrchestratorHandle,
    journal: EventJournal,
    mutations: Mutex<()>,
    presence: watch::Sender<ClientPresence>,
    capabilities: Vec<String>,
}
impl Inner {
    fn apply_authorization(&self, entries: Vec<AllowEntry>) -> std::io::Result<()> {
        // Stop authorization before an external ACL change, including on
        // already-open HTTP/2 connections. Re-enable only once both agree.
        self.authorizer.invalidate();
        if self.mode == HostMode::Service {
            self.allow_list_sink.apply(&entries)?;
        }
        self.authorizer.replace(entries);
        Ok(())
    }

    async fn reload_authorization(&self) -> Result<(), ()> {
        self.authorizer.invalidate();
        let settings = self.ledger.settings().await.map_err(|_| ())?;
        self.apply_authorization(settings.allow_list)
            .map_err(|_| ())
    }
}
impl ContractService {
    /// The composition root must initialize the authorizer from the ledger
    /// before accepting requests. The same authorizer is shared with HostDeps.
    #[allow(clippy::too_many_arguments)] // composition root injects independent dependencies
    pub fn new(
        mode: HostMode,
        ledger: Arc<dyn Ledger>,
        install_key: InstallKey,
        authorizer: Arc<AllowListAuthorizer>,
        store: Arc<dyn CoreStore>,
        handle: OrchestratorHandle,
        capabilities: Vec<String>,
        event_capacity: usize,
    ) -> Self {
        Self::with_allow_list_sink(
            mode,
            ledger,
            install_key,
            authorizer,
            store,
            handle,
            capabilities,
            event_capacity,
            Arc::new(NoopAllowListSink),
        )
    }

    /// For real service listeners. Initialize both the listener ACL and the
    /// authorizer from the same ledger settings under the host lock before
    /// passing this service to the transport.
    #[allow(clippy::too_many_arguments)]
    pub fn with_allow_list_sink(
        mode: HostMode,
        ledger: Arc<dyn Ledger>,
        install_key: InstallKey,
        authorizer: Arc<AllowListAuthorizer>,
        store: Arc<dyn CoreStore>,
        handle: OrchestratorHandle,
        capabilities: Vec<String>,
        event_capacity: usize,
        allow_list_sink: Arc<dyn AllowListSink>,
    ) -> Self {
        let journal = EventJournal::new(&handle, event_capacity);
        let (presence, mut updates) = watch::channel(ClientPresence::default());
        let publisher = handle.clone();
        tokio::spawn(async move {
            while updates.changed().await.is_ok() {
                let value = *updates.borrow_and_update();
                if publisher.send(Command::Clients(value)).await.is_err() {
                    break;
                }
            }
        });
        Self {
            inner: Arc::new(Inner {
                mode,
                ledger,
                install_key,
                authorizer,
                allow_list_sink,
                start_blocker: None,
                store,
                handle,
                journal,
                mutations: Mutex::new(()),
                presence,
                capabilities,
            }),
        }
    }
    /// The composition root may expose diagnostics and maintenance while
    /// refusing new starts if required native effect adapters are absent.
    pub fn with_start_blocker(mut self, reason: Option<String>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("configure before cloning the contract service")
            .start_blocker = reason;
        self
    }
    /// Called by the composition root when IPC connections or user-host
    /// leases change. Subscribe streams track their own presence.
    pub fn set_connection_presence(&self, connections: usize, lease_holders: usize) {
        self.inner.presence.send_modify(|value| {
            value.connections = connections;
            value.lease_holders = lease_holders;
        });
    }
    fn guard<T>(&self, request: &Request<T>, method: &str) -> Result<(PeerIdentity, Role), Status> {
        check_version(request)?;
        if self.inner.mode == HostMode::ElevatedSession {
            return Err(rejection(
                ErrorCode::FeatureRejected,
                "elevated session mode is not available in this version",
            ));
        }
        let peer = request
            .extensions()
            .get::<PeerIdentity>()
            .ok_or_else(|| rejection(ErrorCode::PermissionDenied, "No trusted peer credentials"))?;
        let role = self
            .inner
            .authorizer
            .role_of(peer)
            .ok_or_else(|| rejection(ErrorCode::PermissionDenied, "Peer is not authorized"))?;
        let need = required_role(&format!("/{SERVICE_NAME}/{method}"))
            .ok_or_else(|| rejection(ErrorCode::PermissionDenied, "Method has no role"))?;
        if !role_allows(role, need) {
            let code = if need == Role::Admin
                && role == Role::Control
                && self.inner.mode == HostMode::Service
                && !peer.elevated
            {
                ErrorCode::ElevationRequired
            } else {
                ErrorCode::PermissionDenied
            };
            return Err(rejection(code, "Insufficient role for this method"));
        }
        Ok((peer.clone(), role))
    }
    fn snapshot_value(&self) -> HostSnapshot {
        let view = self.inner.handle.view();
        let mut snapshot = view.snapshot.clone();
        snapshot.cursor = Some(self.inner.journal.cursor(view.seq));
        for view in &mut snapshot.instances {
            redact(view.desired.as_mut());
        }
        snapshot
    }
    async fn ask<T>(
        &self,
        command: impl FnOnce(crate::api::Reply<T>) -> Command,
    ) -> Result<T, Status> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .handle
            .send(command(tx))
            .await
            .map_err(|_| host_closed())?;
        rx.await.map_err(|_| host_closed())?.map_err(status)
    }
    async fn submit<T: DigestMessage + Send + 'static>(
        &self,
        request: Request<T>,
        method: &'static str,
        header: Option<MutationHeader>,
        mutation: Mutation,
    ) -> Result<Receipt, Status> {
        self.guard(&request, method)?;
        // Keep the owned operation alive if the client disconnects during commit.
        let service = self.clone();
        tokio::spawn(async move {
            let _lock = service.inner.mutations.lock().await;
            let (peer, _) = service.guard(&request, method)?;
            let header = header.ok_or_else(|| invalid("Missing mutation header"))?;
            if header.request_id.is_empty() || header.request_id.len() > 256 {
                return Err(invalid("Invalid request id"));
            }
            let caller = canonical_caller(&peer)?;
            let digest = request_digest(
                method,
                &caller,
                header.expected_revision,
                request.get_ref(),
                &service.inner.install_key,
            );
            let record = RequestRecord {
                request_id: RequestId(header.request_id),
                caller,
                digest,
            };
            service
                .commit(header.expected_revision, record, mutation)
                .await
        })
        .await
        .map_err(|_| host_closed())?
    }
    async fn commit(
        &self,
        expected: Revision,
        record: RequestRecord,
        mutation: Mutation,
    ) -> Result<Receipt, Status> {
        if self.inner.mode == HostMode::User && matches!(mutation, Mutation::AllowList(_)) {
            return Err(rejection(
                ErrorCode::FeatureRejected,
                "User host has no allow list",
            ));
        }
        let known = self.inner.ledger.request_status(&record).await;
        match known {
            Ok(RequestStatus::Done(receipt)) => return Ok(receipt),
            Ok(RequestStatus::Reused) => {
                return Err(rejection(
                    ErrorCode::RequestIdReused,
                    "Request id already used with different content",
                ));
            }
            Ok(RequestStatus::New) => {}
            Ok(_) => return Err(host_closed()),
            Err(e) => return self.on_ledger_failure(e, &mutation).await,
        }
        if self.inner.handle.view().snapshot.phase() != HostPhase::Serving {
            return Err(host_closed());
        }
        for _ in 0..8 {
            let (revision, desired) = match self.inner.ledger.desired().await {
                Ok(v) => v,
                Err(e) => return self.on_ledger_failure(e, &mutation).await,
            };
            if revision != expected {
                return Err(ledger_error(LedgerError::Conflict { current: revision }));
            }
            let (change, planned) = self.prepare(&mutation, &desired).await?;
            let mut generations = Vec::new();
            if let Some(plan) = planned {
                if plan.revision != expected {
                    return Err(ledger_error(LedgerError::Conflict {
                        current: plan.revision,
                    }));
                }
                generations.extend(plan.generation);
            }
            if self.inner.handle.view().snapshot.phase() != HostPhase::Serving {
                return Err(host_closed());
            }
            let has_generation = !generations.is_empty();
            let changes = ChangeSet {
                request: record.clone(),
                changes: vec![change],
                generations,
            };
            match self.inner.ledger.commit(expected, changes).await {
                Ok(receipt) => {
                    let acl_ok = match &mutation {
                        Mutation::AllowList(entries) => {
                            self.inner.apply_authorization(entries.clone()).is_ok()
                        }
                        _ => true,
                    };
                    // Durable tickets are also replayed by H1 after restart.
                    let _ = self
                        .inner
                        .handle
                        .send(Command::Committed {
                            receipt: receipt.clone(),
                        })
                        .await;
                    if !acl_ok {
                        self.retry_authorization_reload();
                        // The mutation is durable. Its receipt is recoverable
                        // once the listener and authorization agree again.
                        return Err(host_closed());
                    }
                    return Ok(receipt);
                }
                Err(LedgerError::EpochOpen { .. } | LedgerError::EpochNotNext { .. })
                    if has_generation =>
                {
                    continue;
                }
                Err(LedgerError::ExclusiveTaken { .. }) if has_generation => continue,
                Err(e) => return self.on_ledger_failure(e, &mutation).await,
            }
        }
        Err(rejection(
            ErrorCode::InstanceBusy,
            "Generation changed while planning; retry",
        ))
    }
    async fn on_ledger_failure(
        &self,
        error: LedgerError,
        mutation: &Mutation,
    ) -> Result<Receipt, Status> {
        if matches!(mutation, Mutation::AllowList(_) | Mutation::Purge(true)) {
            // A storage error may follow a durable transaction (e.g. the
            // purge checkpoint). No old authorization may survive ambiguity.
            self.inner.authorizer.invalidate();
            if self.inner.reload_authorization().await.is_err() {
                self.retry_authorization_reload();
            }
        }
        if matches!(error, LedgerError::Unavailable(_))
            && let Mutation::Desired(id, Desired::Stopped) = mutation
        {
            let instance = instance_id(id)?;
            self.ask(|reply| Command::Cut { instance, reply }).await?;
        }
        Err(ledger_error(error))
    }
    // An ambiguous commit may coincide with an unavailable ledger. Keep the
    // invalid snapshot until a committed settings read succeeds; synchronize
    // retries with mutations and do not retain the service after shutdown.
    fn retry_authorization_reload(&self) {
        let inner = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                let _lock = inner.mutations.lock().await;
                if inner.authorizer.is_loaded() || inner.reload_authorization().await.is_ok() {
                    return;
                }
            }
        });
    }
    async fn plan(
        &self,
        id: InstanceId,
        spec: Option<NetworkSpec>,
        start: bool,
    ) -> Result<Planned, Status> {
        self.ask(|reply| Command::Plan {
            instance: id,
            spec: spec.map(Box::new),
            start,
            reply,
        })
        .await
    }
    async fn prepare(
        &self,
        m: &Mutation,
        desired: &[DesiredInstance],
    ) -> Result<(Change, Option<Planned>), Status> {
        if let Some(reason) = &self.inner.start_blocker
            && matches!(
                m,
                Mutation::Apply(..)
                    | Mutation::Desired(_, Desired::Running)
                    | Mutation::RetryStart(_)
            )
        {
            return Err(rejection(ErrorCode::FeatureRejected, reason.clone()));
        }
        let find = |id: &str| desired.iter().find(|v| v.instance_id == id);
        let known = |id: &str| -> Result<InstanceId, Status> {
            let instance = instance_id(id)?;
            if find(id).is_none() {
                return Err(rejection(ErrorCode::UnknownInstance, "Unknown instance"));
            }
            Ok(instance)
        };
        Ok(match m {
            Mutation::Apply(id, spec, state) => {
                let instance = instance_id(id)?;
                let mut spec = *spec
                    .clone()
                    .ok_or_else(|| invalid("Missing network specification"))?;
                let old = find(id);
                if spec.network_secret.is_none() {
                    spec.network_secret = old
                        .and_then(|v| v.spec.as_ref())
                        .and_then(|v| v.network_secret.clone());
                }
                // This is an output-only redaction hint, never a durable
                // launch input. H1 plans from the canonical unredacted spec.
                spec.network_secret_set = false;
                let state =
                    Desired::try_from(*state).map_err(|_| invalid("Invalid desired state"))?;
                let state = if state == Desired::Unspecified {
                    old.map_or(Desired::Stopped, |v| v.desired())
                } else {
                    state
                };
                let plan = self
                    .plan(instance, Some(spec.clone()), state == Desired::Running)
                    .await?;
                if let Some(generation) = &plan.generation {
                    // L1 requires exact equality of PutInstance and the
                    // persisted generation inputs for deterministic replay.
                    spec = generation.inputs.spec.clone();
                    if spec.network_secret_set {
                        return Err(host_closed());
                    }
                }
                (
                    Change::PutInstance {
                        instance: Box::new(DesiredInstance {
                            instance_id: id.clone(),
                            spec: Some(spec),
                            desired: state as i32,
                        }),
                        claims: plan.claims.clone(),
                    },
                    Some(plan),
                )
            }
            Mutation::Desired(id, state) => {
                let instance = known(id)?;
                if *state == Desired::Unspecified {
                    return Err(invalid("Desired state must be running or stopped"));
                }
                let plan = if *state == Desired::Running
                    && find(id).is_some_and(|v| v.desired() != *state)
                {
                    Some(self.plan(instance.clone(), None, true).await?)
                } else {
                    None
                };
                (
                    Change::SetDesired {
                        instance,
                        desired: *state,
                    },
                    plan,
                )
            }
            Mutation::Remove(id) => (Change::RemoveInstance(known(id)?), None),
            Mutation::RetryReclaim(id) => (Change::RetryReclaim(known(id)?), None),
            Mutation::RetryStart(id) => {
                let instance = known(id)?;
                if !self.snapshot_value().instances.iter().any(|v| {
                    v.status
                        .as_ref()
                        .is_some_and(|s| s.instance_id == *id && s.state() == InstanceState::GaveUp)
                }) {
                    return Err(rejection(
                        ErrorCode::InstanceBusy,
                        "Instance is not in GAVE_UP",
                    ));
                }
                let plan = self.plan(instance.clone(), None, true).await?;
                (Change::RetryStart(instance), Some(plan))
            }
            Mutation::Resolve(decisions) => {
                let report = self.snapshot_value().reclaim.unwrap_or_default();
                let mut seen = std::collections::HashSet::new();
                for decision in decisions {
                    let candidate = report
                        .candidates
                        .iter()
                        .any(|c| c.candidate_id == decision.candidate_id);
                    let conflict = report
                        .conflicts
                        .iter()
                        .any(|c| c.conflict_id == decision.candidate_id);
                    if !seen.insert(&decision.candidate_id)
                        || decision.action() == CandidateAction::Unspecified
                        || !(candidate || (conflict && decision.action() == CandidateAction::Keep))
                    {
                        return Err(rejection(
                            ErrorCode::UnknownCandidate,
                            "Unknown or invalid candidate decision",
                        ));
                    }
                }
                (Change::ResolveCandidates(decisions.clone()), None)
            }
            Mutation::AllowList(entries) => {
                if entries.iter().any(|e| {
                    e.principal.as_ref().and_then(|p| p.id.as_ref()).is_none()
                        || e.role() == Role::Unspecified
                }) {
                    return Err(invalid("Invalid allow-list entry"));
                }
                self.inner
                    .allow_list_sink
                    .validate(entries)
                    .map_err(|_| invalid("Invalid listener allow-list policy"))?;
                (Change::SetAllowList(entries.clone()), None)
            }
            Mutation::Select(version) => {
                if version.is_empty() {
                    return Err(invalid("Missing core version"));
                }
                self.inner
                    .store
                    .resolve(&CoreSelector {
                        version: Some(version.clone()),
                    })
                    .await
                    .map_err(|_| {
                        rejection(ErrorCode::CoreUnavailable, "Selected kernel is unavailable")
                    })?;
                (Change::SelectCore(Some(version.clone())), None)
            }
            Mutation::Purge(confirm) => {
                if !confirm {
                    return Err(invalid("Purge requires confirmation"));
                }
                (Change::PurgeAll, None)
            }
        })
    }
}
fn redact(instance: Option<&mut DesiredInstance>) {
    if let Some(spec) = instance.and_then(|v| v.spec.as_mut())
        && let Some(secret) = spec.network_secret.take()
    {
        spec.network_secret_set = !secret.is_empty();
    }
}
fn instance_id(s: &str) -> Result<InstanceId, Status> {
    if uuid::Uuid::parse_str(s).is_err() {
        return Err(invalid("Instance id must be a UUID"));
    }
    // Do not let alternate UUID spellings create distinct path identities.
    if uuid::Uuid::parse_str(s).unwrap().to_string() != s {
        return Err(invalid("Instance id must use canonical UUID syntax"));
    }
    Ok(InstanceId(s.into()))
}
fn invalid(message: &str) -> Status {
    rejection(ErrorCode::InvalidSpec, message)
}
fn host_closed() -> Status {
    rejection(
        ErrorCode::HostNotServing,
        "Host is not serving control requests",
    )
}
fn canonical_caller(peer: &PeerIdentity) -> Result<String, Status> {
    match &peer.user {
        OsUserId::WindowsSid(s) => Ok(s.to_ascii_uppercase()),
        OsUserId::UnixUid(uid) => Ok(uid.to_string()),
        _ => Err(rejection(
            ErrorCode::PermissionDenied,
            "Unsupported peer identity",
        )),
    }
}

trait DigestMessage: Message + Sized {
    fn digest_bytes(&self, _key: &InstallKey) -> Vec<u8> {
        self.encode_to_vec()
    }
}
macro_rules! digest_messages {
    ($($ty:ty),+ $(,)?) => { $(impl DigestMessage for $ty {})+ };
}
digest_messages!(
    SetDesiredRequest,
    RemoveInstanceRequest,
    RetryReclaimRequest,
    RetryStartRequest,
    ResolveCandidatesRequest,
    SetAllowListRequest,
    SelectCoreRequest,
    PurgeAllDataRequest
);
impl DigestMessage for ApplyRequest {
    fn digest_bytes(&self, key: &InstallKey) -> Vec<u8> {
        let mut canonical = self.clone();
        if let Some(secret) = canonical
            .spec
            .as_mut()
            .and_then(|spec| spec.network_secret.as_mut())
        {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key.0).expect("HMAC accepts any key length");
            mac.update(secret.as_bytes());
            *secret = mac
                .finalize()
                .into_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
        }
        canonical.encode_to_vec()
    }
}

/// Hash the canonical decoded protobuf, not its received wire spelling. The
/// contract has no maps, so prost's field-order encoding is deterministic and
/// includes optional presence, repeated order and every known field. Frame
/// each component and bind the authenticated principal and revision as well.
fn request_digest<T: DigestMessage>(
    method: &str,
    caller: &str,
    expected_revision: Revision,
    request: &T,
    install_key: &InstallKey,
) -> RequestDigest {
    let mut digest = Sha256::new();
    digest.update(b"etd.v1/request/v2\0");
    for bytes in [method.as_bytes(), caller.as_bytes()] {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.update(expected_revision.to_be_bytes());
    let body = request.digest_bytes(install_key);
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    RequestDigest(digest.finalize().into())
}
fn ledger_error(error: LedgerError) -> Status {
    match error {
        LedgerError::Conflict { current } => status(ErrorDetail {
            code: ErrorCode::RevisionConflict as i32,
            message: "Revision conflict".into(),
            current_revision: current,
            ..Default::default()
        }),
        LedgerError::RequestReused(_) => rejection(ErrorCode::RequestIdReused, "Request id reused"),
        LedgerError::UnknownInstance(_) => {
            rejection(ErrorCode::UnknownInstance, "Unknown instance")
        }
        LedgerError::ExclusiveTaken { resource, holder } => status(ErrorDetail {
            code: ErrorCode::SingleWriterTaken as i32,
            message: "Single-writer feature already in use".into(),
            features: vec![resource],
            instance_id: holder.0,
            ..Default::default()
        }),
        LedgerError::EpochOpen { .. } | LedgerError::EpochNotNext { .. } => {
            rejection(ErrorCode::InstanceBusy, "Instance generation still open")
        }
        LedgerError::RemovalPending { .. } => {
            rejection(ErrorCode::InstanceBusy, "Instance removal pending")
        }
        LedgerError::InvalidPlan { .. } => rejection(
            ErrorCode::HostNotServing,
            "Orchestrator returned an invalid generation plan",
        ),
        _ => rejection(ErrorCode::LedgerUnavailable, "Ledger unavailable"),
    }
}
struct SubscriptionPresence(watch::Sender<ClientPresence>);
impl SubscriptionPresence {
    fn new(presence: watch::Sender<ClientPresence>) -> Self {
        presence.send_modify(|value| value.subscribers += 1);
        Self(presence)
    }
}
impl Drop for SubscriptionPresence {
    fn drop(&mut self) {
        self.0.send_modify(|value| value.subscribers -= 1);
    }
}
/// A bounded pump watches authorization independently of the consumer's
/// polling (including HTTP/2 backpressure). Revocation closes the source and
/// presence immediately; buffered data is discarded, never delivered afterward.
fn authorized_stream<T: Send + 'static>(
    mut source: BoxStream<'static, T>,
    authorizer: Arc<AllowListAuthorizer>,
    peer: PeerIdentity,
    presence: Option<SubscriptionPresence>,
) -> BoxStream<'static, Result<T, Status>> {
    let mut updates = authorizer.watch();
    let (tx, rx) = mpsc::channel(1);
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_by_pump = revoked.clone();
    let pump_auth = authorizer.clone();
    let pump_peer = peer.clone();
    tokio::spawn(async move {
        let _presence = presence;
        let authorized = || {
            pump_auth
                .role_of(&pump_peer)
                .is_some_and(|role| role_allows(role, Role::Viewer))
        };
        'pump: loop {
            if !authorized() {
                revoked_by_pump.store(true, Ordering::Release);
                break;
            }
            let item = tokio::select! {
                biased;
                updated = updates.changed() => {
                    if updated.is_err() { revoked_by_pump.store(true, Ordering::Release); break; }
                    continue;
                }
                _ = tx.closed() => break,
                item = source.next() => { let Some(item) = item else { break; }; item }
            };
            // A full output buffer must not postpone an authorization change.
            loop {
                if !authorized() {
                    revoked_by_pump.store(true, Ordering::Release);
                    break 'pump;
                }
                tokio::select! {
                    biased;
                    updated = updates.changed() => {
                        if updated.is_err() { revoked_by_pump.store(true, Ordering::Release); break 'pump; }
                    }
                    permit = tx.reserve() => {
                        let Ok(permit) = permit else { break 'pump; };
                        permit.send(item);
                        break;
                    }
                }
            }
        }
    });
    Box::pin(stream::unfold(
        Some((rx, revoked, authorizer, peer)),
        |state| async move {
            let (mut rx, revoked, authorizer, peer) = state?;
            let unauthorized = || {
                revoked.load(Ordering::Acquire)
                    || !authorizer
                        .role_of(&peer)
                        .is_some_and(|role| role_allows(role, Role::Viewer))
            };
            if unauthorized() {
                return Some((
                    Err(rejection(
                        ErrorCode::PermissionDenied,
                        "Peer authorization revoked",
                    )),
                    None,
                ));
            }
            let item = rx.recv().await;
            if unauthorized() {
                return Some((
                    Err(rejection(
                        ErrorCode::PermissionDenied,
                        "Peer authorization revoked",
                    )),
                    None,
                ));
            }
            item.map(|item| (Ok(item), Some((rx, revoked, authorizer, peer))))
        },
    ))
}
enum Mutation {
    Apply(String, Option<Box<NetworkSpec>>, i32),
    Desired(String, Desired),
    Remove(String),
    RetryReclaim(String),
    RetryStart(String),
    Resolve(Vec<CandidateDecision>),
    AllowList(Vec<AllowEntry>),
    Select(String),
    Purge(bool),
}

#[tonic::async_trait]
impl HostService for ContractService {
    async fn handshake(&self, request: Request<Hello>) -> Result<Response<Welcome>, Status> {
        let (_, role) = self.guard(&request, "Handshake")?;
        let version = check_version(&request)?;
        if request.get_ref().major != VERSION_MAJOR {
            return Err(version_mismatch());
        }
        if (request.get_ref().major, request.get_ref().minor) != version {
            return Err(rejection(
                ErrorCode::VersionMetadata,
                "Hello version differs from metadata",
            ));
        }
        let capabilities = self
            .inner
            .capabilities
            .iter()
            .filter(|c| {
                if self.inner.mode == HostMode::User
                    && matches!(c.as_str(), capability::TUN | capability::ADMIN_ALLOW_LIST)
                {
                    return false;
                }
                if self.inner.mode == HostMode::Service && c.as_str() == capability::LEASE {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        Ok(Response::new(Welcome {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            capabilities,
            role: role as i32,
            host_build: env!("CARGO_PKG_VERSION").into(),
            host_mode: self.inner.mode as i32,
            phase: self.inner.handle.view().snapshot.phase,
            stream_id: self.inner.journal.stream_id().into(),
        }))
    }
    async fn snapshot(
        &self,
        request: Request<SnapshotRequest>,
    ) -> Result<Response<HostSnapshot>, Status> {
        self.guard(&request, "Snapshot")?;
        Ok(Response::new(self.snapshot_value()))
    }
    type SubscribeStream = BoxStream<'static, Result<Event, Status>>;
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (peer, _) = self.guard(&request, "Subscribe")?;
        let authorizer = self.inner.authorizer.clone();
        let presence = SubscriptionPresence::new(self.inner.presence.clone());
        let stream = self
            .inner
            .journal
            .subscribe(request.into_inner().after, self.inner.handle.view().seq)
            .map(|mut event| {
                if let Some(v1::event::Payload::DesiredChanged(change)) = event.payload.as_mut() {
                    redact(change.instance.as_mut());
                }
                event
            });
        Ok(Response::new(authorized_stream(
            Box::pin(stream),
            authorizer,
            peer,
            Some(presence),
        )))
    }
    async fn apply(
        &self,
        request: Request<ApplyRequest>,
    ) -> Result<Response<ApplyResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::Apply(
            body.instance_id.clone(),
            body.spec.clone().map(Box::new),
            body.desired,
        );
        let receipt = self.submit(request, "Apply", header, mutation).await?;
        Ok(Response::new(ApplyResponse {
            receipt: Some(receipt),
        }))
    }
    async fn set_desired(
        &self,
        request: Request<SetDesiredRequest>,
    ) -> Result<Response<SetDesiredResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::Desired(body.instance_id.clone(), body.desired());
        let receipt = self.submit(request, "SetDesired", header, mutation).await?;
        Ok(Response::new(SetDesiredResponse {
            receipt: Some(receipt),
        }))
    }
    async fn remove_instance(
        &self,
        request: Request<RemoveInstanceRequest>,
    ) -> Result<Response<RemoveInstanceResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::Remove(body.instance_id.clone());
        let receipt = self
            .submit(request, "RemoveInstance", header, mutation)
            .await?;
        Ok(Response::new(RemoveInstanceResponse {
            receipt: Some(receipt),
        }))
    }
    async fn retry_reclaim(
        &self,
        request: Request<RetryReclaimRequest>,
    ) -> Result<Response<RetryReclaimResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::RetryReclaim(body.instance_id.clone());
        let receipt = self
            .submit(request, "RetryReclaim", header, mutation)
            .await?;
        Ok(Response::new(RetryReclaimResponse {
            receipt: Some(receipt),
        }))
    }
    async fn retry_start(
        &self,
        request: Request<RetryStartRequest>,
    ) -> Result<Response<RetryStartResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::RetryStart(body.instance_id.clone());
        let receipt = self.submit(request, "RetryStart", header, mutation).await?;
        Ok(Response::new(RetryStartResponse {
            receipt: Some(receipt),
        }))
    }
    async fn resolve_candidates(
        &self,
        request: Request<ResolveCandidatesRequest>,
    ) -> Result<Response<ResolveCandidatesResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::Resolve(body.decisions.clone());
        let receipt = self
            .submit(request, "ResolveCandidates", header, mutation)
            .await?;
        Ok(Response::new(ResolveCandidatesResponse {
            receipt: Some(receipt),
        }))
    }
    async fn set_allow_list(
        &self,
        request: Request<SetAllowListRequest>,
    ) -> Result<Response<SetAllowListResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::AllowList(body.entries.clone());
        let receipt = self
            .submit(request, "SetAllowList", header, mutation)
            .await?;
        Ok(Response::new(SetAllowListResponse {
            receipt: Some(receipt),
        }))
    }
    async fn select_core(
        &self,
        request: Request<SelectCoreRequest>,
    ) -> Result<Response<SelectCoreResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::Select(body.version.clone());
        let receipt = self.submit(request, "SelectCore", header, mutation).await?;
        Ok(Response::new(SelectCoreResponse {
            receipt: Some(receipt),
        }))
    }
    async fn purge_all_data(
        &self,
        request: Request<PurgeAllDataRequest>,
    ) -> Result<Response<PurgeAllDataResponse>, Status> {
        let body = request.get_ref();
        let header = body.header.clone();
        let mutation = Mutation::Purge(body.confirm);
        let receipt = self
            .submit(request, "PurgeAllData", header, mutation)
            .await?;
        Ok(Response::new(PurgeAllDataResponse {
            receipt: Some(receipt),
        }))
    }
    async fn get_receipt(
        &self,
        request: Request<GetReceiptRequest>,
    ) -> Result<Response<GetReceiptResponse>, Status> {
        let (peer, role) = self.guard(&request, "GetReceipt")?;
        let caller = canonical_caller(&peer)?;
        let receipt = self
            .inner
            .ledger
            .receipt_for(
                &RequestId(request.into_inner().request_id),
                (role != Role::Admin).then_some(caller.as_str()),
            )
            .await
            .map_err(ledger_error)?;
        Ok(Response::new(GetReceiptResponse { receipt }))
    }
    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        self.guard(&request, "Query")?;
        let body = request.into_inner();
        let instance = instance_id(&body.instance_id)?;
        if body.kind() == QueryKind::Unspecified {
            return Err(invalid("Unknown query kind"));
        }
        let kind = body.kind();
        Ok(Response::new(
            self.ask(|reply| Command::Query {
                instance,
                kind,
                reply,
            })
            .await?,
        ))
    }
    type StreamLogsStream = BoxStream<'static, Result<LogLine, Status>>;
    async fn stream_logs(
        &self,
        request: Request<StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        let (peer, _) = self.guard(&request, "StreamLogs")?;
        let authorizer = self.inner.authorizer.clone();
        let request = request.into_inner();
        let stream = self.ask(|reply| Command::Logs { request, reply }).await?;
        let presence = SubscriptionPresence::new(self.inner.presence.clone());
        Ok(Response::new(authorized_stream(
            stream,
            authorizer,
            peer,
            Some(presence),
        )))
    }
    async fn get_reclaim_report(
        &self,
        request: Request<GetReclaimReportRequest>,
    ) -> Result<Response<ReclaimReport>, Status> {
        self.guard(&request, "GetReclaimReport")?;
        Ok(Response::new(
            self.snapshot_value().reclaim.unwrap_or_default(),
        ))
    }
    async fn release_lease(
        &self,
        request: Request<ReleaseLeaseRequest>,
    ) -> Result<Response<ReleaseLeaseResponse>, Status> {
        self.guard(&request, "ReleaseLease")?;
        if self.inner.mode == HostMode::Service {
            return Ok(Response::new(ReleaseLeaseResponse {
                host_exiting: false,
            }));
        }
        let instances = request.get_ref().instances();
        let instances = if instances == LeaseRelease::Unspecified {
            LeaseRelease::StopInstances
        } else {
            instances
        };
        let host_exiting = self
            .ask(|reply| Command::ReleaseLease { instances, reply })
            .await?;
        Ok(Response::new(ReleaseLeaseResponse { host_exiting }))
    }
    async fn get_allow_list(
        &self,
        request: Request<GetAllowListRequest>,
    ) -> Result<Response<GetAllowListResponse>, Status> {
        let _lock = self.inner.mutations.lock().await;
        self.guard(&request, "GetAllowList")?;
        if self.inner.mode == HostMode::User {
            return Err(rejection(
                ErrorCode::FeatureRejected,
                "User host has no allow list",
            ));
        }
        let (revision, _) = self.inner.ledger.desired().await.map_err(ledger_error)?;
        let entries = self
            .inner
            .ledger
            .settings()
            .await
            .map_err(ledger_error)?
            .allow_list;
        Ok(Response::new(GetAllowListResponse { entries, revision }))
    }
    async fn list_cores(
        &self,
        request: Request<ListCoresRequest>,
    ) -> Result<Response<ListCoresResponse>, Status> {
        self.guard(&request, "ListCores")?;
        let cores = self
            .inner
            .store
            .list()
            .await
            .map_err(|_| rejection(ErrorCode::CoreUnavailable, "Kernel store unavailable"))?;
        let settings = self.inner.ledger.settings().await.map_err(ledger_error)?;
        let selected =
            match settings.selected_core {
                Some(version) => Some(version),
                None => self.inner.store.default_version().await.map_err(|_| {
                    rejection(ErrorCode::CoreUnavailable, "Kernel store unavailable")
                })?,
            };
        let default_version = selected
            .filter(|version| {
                cores.iter().any(|entry| {
                    entry.version == *version
                        && matches!(
                            entry.support(),
                            CoreSupport::Profiled | CoreSupport::LifecycleOnly
                        )
                })
            })
            .unwrap_or_default();
        Ok(Response::new(ListCoresResponse {
            cores,
            default_version,
        }))
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn apply_digest_replaces_secret_with_keyed_mac_and_preserves_presence() {
        let mut body = ApplyRequest {
            spec: Some(NetworkSpec {
                network_secret: Some("synthetic-test".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let key = InstallKey([7; 32]);
        let canonical = ApplyRequest::decode(body.digest_bytes(&key).as_slice()).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).unwrap();
        mac.update(b"synthetic-test");
        let expected: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(canonical.spec.unwrap().network_secret, Some(expected));
        assert_eq!(
            body.spec.as_ref().unwrap().network_secret.as_deref(),
            Some("synthetic-test")
        );
        let original = request_digest("Apply", "20", 1, &body, &key);
        assert_ne!(
            original,
            request_digest("Apply", "20", 1, &body, &InstallKey([8; 32]))
        );
        body.spec.as_mut().unwrap().network_secret = Some(String::new());
        let clear = request_digest("Apply", "20", 1, &body, &key);
        body.spec.as_mut().unwrap().network_secret = None;
        assert_ne!(clear, request_digest("Apply", "20", 1, &body, &key));
        assert_ne!(clear, original);
    }
}
