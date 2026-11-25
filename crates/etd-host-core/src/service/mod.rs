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
    Change, ChangeSet, Ledger, LedgerError, RequestDigest, RequestRecord, RequestStatus,
};
use futures_util::{StreamExt, stream::BoxStream};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot, watch};
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct ContractService {
    inner: Arc<Inner>,
}
struct Inner {
    mode: HostMode,
    ledger: Arc<dyn Ledger>,
    authorizer: Arc<AllowListAuthorizer>,
    store: Arc<dyn CoreStore>,
    handle: OrchestratorHandle,
    journal: EventJournal,
    mutations: Mutex<()>,
    presence: watch::Sender<ClientPresence>,
    capabilities: Vec<String>,
}
impl ContractService {
    /// The composition root must initialize the authorizer from the ledger
    /// before accepting requests. The same authorizer is shared with HostDeps.
    pub fn new(
        mode: HostMode,
        ledger: Arc<dyn Ledger>,
        authorizer: Arc<AllowListAuthorizer>,
        store: Arc<dyn CoreStore>,
        handle: OrchestratorHandle,
        capabilities: Vec<String>,
        event_capacity: usize,
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
                authorizer,
                store,
                handle,
                journal,
                mutations: Mutex::new(()),
                presence,
                capabilities,
            }),
        }
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
    async fn submit<T: Message + Send + 'static>(
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
            let mut digest = Sha256::new();
            digest.update(method.as_bytes());
            digest.update([0]);
            digest.update(request.get_ref().encode_to_vec());
            let caller = match peer.user {
                OsUserId::WindowsSid(s) => s,
                OsUserId::UnixUid(uid) => uid.to_string(),
                _ => {
                    return Err(rejection(
                        ErrorCode::PermissionDenied,
                        "Unsupported peer identity",
                    ));
                }
            };
            let record = RequestRecord {
                request_id: RequestId(header.request_id),
                caller,
                digest: RequestDigest(digest.finalize().into()),
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
                    match &mutation {
                        Mutation::AllowList(entries) => {
                            self.inner.authorizer.replace(entries.clone())
                        }
                        Mutation::Purge(true) => self.inner.authorizer.replace(Vec::new()),
                        _ => {}
                    }
                    // Durable tickets are also replayed by H1 after restart.
                    let _ = self
                        .inner
                        .handle
                        .send(Command::Committed {
                            receipt: receipt.clone(),
                        })
                        .await;
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
        if matches!(error, LedgerError::Unavailable(_))
            && let Mutation::Desired(id, Desired::Stopped) = mutation
        {
            let instance = instance_id(id)?;
            self.ask(|reply| Command::Cut { instance, reply }).await?;
        }
        Err(ledger_error(error))
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
                spec.network_secret_set =
                    spec.network_secret.as_ref().is_some_and(|s| !s.is_empty());
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
    if let Some(spec) = instance.and_then(|v| v.spec.as_mut()) {
        if let Some(secret) = spec.network_secret.take() {
            spec.network_secret_set = !secret.is_empty();
        }
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
            .map(move |mut event| {
                let _presence = &presence;
                if !authorizer
                    .role_of(&peer)
                    .is_some_and(|role| role_allows(role, Role::Viewer))
                {
                    return Err(rejection(
                        ErrorCode::PermissionDenied,
                        "Peer authorization revoked",
                    ));
                }
                if let Some(v1::event::Payload::DesiredChanged(change)) = event.payload.as_mut() {
                    redact(change.instance.as_mut());
                }
                Ok(event)
            });
        Ok(Response::new(Box::pin(stream)))
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
        self.guard(&request, "GetReceipt")?;
        let receipt = self
            .inner
            .ledger
            .receipt(&RequestId(request.into_inner().request_id))
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
        let stream = self
            .ask(|reply| Command::Logs { request, reply })
            .await?
            .map(move |line| {
                if authorizer
                    .role_of(&peer)
                    .is_some_and(|role| role_allows(role, Role::Viewer))
                {
                    Ok(line)
                } else {
                    Err(rejection(
                        ErrorCode::PermissionDenied,
                        "Peer authorization revoked",
                    ))
                }
            });
        Ok(Response::new(Box::pin(stream)))
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
        let default_version = match self
            .inner
            .store
            .resolve(&CoreSelector {
                version: settings.selected_core,
            })
            .await
        {
            Ok(core) => core.descriptor.version,
            Err(_) => String::new(),
        };
        Ok(Response::new(ListCoresResponse {
            cores,
            default_version,
        }))
    }
}
