use etd_sysfx::*;
mod common;
use common::*;
use etd_contract::{v1::*, *};
use etd_host_core::{
    auth::{Authorizer, role_allows},
    service::ContractService,
    stub::host_service_server::HostService,
};
async fn call(service: &ContractService, method: &str, role: Role) -> Option<tonic::Status> {
    match method {
        "Handshake" => service
            .handshake(request(Hello::default(), role))
            .await
            .err(),
        "Snapshot" => service
            .snapshot(request(SnapshotRequest::default(), role))
            .await
            .err(),
        "Subscribe" => service
            .subscribe(request(SubscribeRequest::default(), role))
            .await
            .err(),
        "Apply" => service
            .apply(request(ApplyRequest::default(), role))
            .await
            .err(),
        "SetDesired" => service
            .set_desired(request(SetDesiredRequest::default(), role))
            .await
            .err(),
        "RemoveInstance" => service
            .remove_instance(request(RemoveInstanceRequest::default(), role))
            .await
            .err(),
        "GetReceipt" => service
            .get_receipt(request(GetReceiptRequest::default(), role))
            .await
            .err(),
        "Query" => service
            .query(request(QueryRequest::default(), role))
            .await
            .err(),
        "StreamLogs" => service
            .stream_logs(request(StreamLogsRequest::default(), role))
            .await
            .err(),
        "GetReclaimReport" => service
            .get_reclaim_report(request(GetReclaimReportRequest::default(), role))
            .await
            .err(),
        "RetryReclaim" => service
            .retry_reclaim(request(RetryReclaimRequest::default(), role))
            .await
            .err(),
        "RetryStart" => service
            .retry_start(request(RetryStartRequest::default(), role))
            .await
            .err(),
        "ResolveCandidates" => service
            .resolve_candidates(request(ResolveCandidatesRequest::default(), role))
            .await
            .err(),
        "ReleaseLease" => service
            .release_lease(request(ReleaseLeaseRequest::default(), role))
            .await
            .err(),
        "GetAllowList" => service
            .get_allow_list(request(GetAllowListRequest::default(), role))
            .await
            .err(),
        "SetAllowList" => service
            .set_allow_list(request(SetAllowListRequest::default(), role))
            .await
            .err(),
        "ListCores" => service
            .list_cores(request(ListCoresRequest::default(), role))
            .await
            .err(),
        "SelectCore" => service
            .select_core(request(SelectCoreRequest::default(), role))
            .await
            .err(),
        "PurgeAllData" => service
            .purge_all_data(request(PurgeAllDataRequest::default(), role))
            .await
            .err(),
        _ => panic!("New method missing in test: {method}"),
    }
}
#[tokio::test]
async fn descriptor_roles_cover_every_method() {
    let mut f = Fixture::new().await;
    f.start_commands();
    for method in method_roles() {
        for role in [Role::Viewer, Role::Control, Role::Admin] {
            let error = call(&f.service, method.path.rsplit('/').next().unwrap(), role).await;
            let denied = error.is_some_and(|e| {
                matches!(
                    code(e),
                    ErrorCode::PermissionDenied | ErrorCode::ElevationRequired
                )
            });
            assert_eq!(
                denied,
                !role_allows(role, method.role.unwrap()),
                "{} {role:?}",
                method.path
            );
        }
    }
}
#[tokio::test]
async fn revoke_applies_before_receipt_and_unloaded_fails_closed() {
    let f = Fixture::new().await;
    let auth = etd_host_core::auth::allow_list::AllowListAuthorizer::new(HostMode::Service, None);
    assert_eq!(auth.role_of(&peer(Role::Admin)), None);
    let revoked = SetAllowListRequest {
        header: Some(MutationHeader {
            request_id: "revoke".into(),
            expected_revision: 1,
        }),
        entries: vec![entry(0, Role::Admin)],
    };
    f.service
        .set_allow_list(request(revoked, Role::Admin))
        .await
        .unwrap();
    let denied = f
        .service
        .snapshot(request(SnapshotRequest {}, Role::Viewer))
        .await
        .unwrap_err();
    assert_eq!(code(denied), ErrorCode::PermissionDenied);
}
#[tokio::test]
async fn service_admin_requires_elevation() {
    let f = Fixture::new().await;
    let mut req = request(GetAllowListRequest {}, Role::Admin);
    let p = req
        .extensions_mut()
        .get_mut::<etd_ipc::PeerIdentity>()
        .unwrap();
    p.elevated = false;
    assert_eq!(
        code(f.service.get_allow_list(req).await.unwrap_err()),
        ErrorCode::ElevationRequired
    );
}

struct UnreadableLedger;
#[async_trait::async_trait]
impl etd_sysfx::Ledger for UnreadableLedger {
    async fn commit(&self, _: Revision, _: ChangeSet) -> Result<Receipt, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn request_status(&self, _: &RequestRecord) -> Result<RequestStatus, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn receipt(&self, _: &RequestId) -> Result<Option<Receipt>, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn complete_ticket(&self, _: &str) -> Result<(), LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn settings(&self) -> Result<HostSettings, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn claims(&self) -> Result<Vec<ClaimHold>, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn next_epoch(&self, _: &InstanceId) -> Result<Epoch, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn begin_epoch(&self, _: GenerationPlan) -> Result<Vec<Effect>, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn generation(
        &self,
        _: &InstanceId,
        _: Epoch,
    ) -> Result<Option<StoredGeneration>, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn record(&self, _: EffectIntent) -> Result<Effect, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn transition(
        &self,
        _: &EffectId,
        _: EffectState,
        _: Option<Observation>,
    ) -> Result<(), LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn record_failure(&self, _: &EffectId, _: &str) -> Result<u32, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn open_effects(&self, _: &ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
    async fn compact(&self) -> Result<usize, LedgerError> {
        Err(LedgerError::Unavailable(StorageFault::ReadOnly))
    }
}
#[tokio::test]
async fn failed_boot_or_reload_denies_all_peers() {
    let f = Fixture::new().await;
    assert_eq!(f.auth.role_of(&peer(Role::Admin)), Some(Role::Admin));
    assert!(f.auth.load(&UnreadableLedger).await.is_err());
    assert_eq!(f.auth.role_of(&peer(Role::Admin)), None);
    assert_eq!(
        code(
            f.service
                .snapshot(request(SnapshotRequest {}, Role::Admin))
                .await
                .unwrap_err()
        ),
        ErrorCode::PermissionDenied
    );
}

#[tokio::test]
async fn user_host_owner_admin_is_unprivileged_and_allow_list_unavailable() {
    use etd_host_core::{
        api::{HostView, orchestrator_channel},
        auth::allow_list::AllowListAuthorizer,
    };
    use std::sync::Arc;
    let f = Fixture::new().await;
    let owner = peer(Role::Control);
    let auth = Arc::new(AllowListAuthorizer::new(
        HostMode::User,
        Some(owner.user.clone()),
    ));
    auth.load(f.ledger.as_ref()).await.unwrap();
    assert_eq!(auth.role_of(&owner), Some(Role::Admin));
    assert_eq!(auth.role_of(&peer(Role::Viewer)), None);
    let (handle, _port) = orchestrator_channel(
        16,
        HostView {
            seq: 0,
            snapshot: HostSnapshot {
                phase: HostPhase::Serving as i32,
                ..Default::default()
            },
        },
    );
    let svc = ContractService::new(
        HostMode::User,
        f.ledger.clone(),
        etd_sysfx::InstallKey([7; 32]),
        auth,
        Arc::new(etd_testkit::fakes::store::FakeCoreStore::default()),
        handle,
        vec![
            capability::TUN.into(),
            capability::ADMIN_ALLOW_LIST.into(),
            capability::ADMIN_PURGE.into(),
        ],
        8,
    );
    let hello = Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    };
    let welcome = svc
        .handshake(request(hello, Role::Control))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(welcome.role(), Role::Admin);
    assert_eq!(welcome.capabilities, vec![capability::ADMIN_PURGE]);
    let set = SetAllowListRequest {
        header: Some(MutationHeader {
            expected_revision: 1,
            request_id: "not-available".into(),
        }),
        entries: vec![],
    };
    assert_eq!(
        code(
            svc.set_allow_list(request(set, Role::Control))
                .await
                .unwrap_err()
        ),
        ErrorCode::FeatureRejected
    );
}

#[tokio::test]
async fn purge_keeps_allow_list_and_elevated_admin_still_connects() {
    use etd_sysfx::Ledger;
    let f = Fixture::new().await;
    let expected = f.ledger.settings().await.unwrap().allow_list;
    f.service
        .purge_all_data(request(
            PurgeAllDataRequest {
                header: Some(MutationHeader {
                    expected_revision: 1,
                    request_id: "purge".into(),
                }),
                confirm: true,
            },
            Role::Admin,
        ))
        .await
        .unwrap();
    assert_eq!(f.ledger.settings().await.unwrap().allow_list, expected);
    let hello = Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    };
    assert_eq!(
        f.service
            .handshake(request(hello, Role::Admin))
            .await
            .unwrap()
            .into_inner()
            .role(),
        Role::Admin
    );
    // Restart/reload covers persisted list, not merely the running snapshot.
    f.auth.load(f.ledger.as_ref()).await.unwrap();
    assert_eq!(f.auth.role_of(&peer(Role::Admin)), Some(Role::Admin));
}

use etd_host_core::api::{HostView, orchestrator_channel};
use etd_testkit::fakes::ledger::MemoryLedger;
use etd_testkit::fakes::store::FakeCoreStore;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct AmbiguousLedger {
    inner: Arc<MemoryLedger>,
    post_commit_error: AtomicBool,
    settings_failure: AtomicBool,
}
fn storage_error() -> LedgerError {
    LedgerError::Unavailable(StorageFault::Io("injected".into()))
}
#[async_trait::async_trait]
impl Ledger for AmbiguousLedger {
    async fn commit(&self, expected: Revision, changes: ChangeSet) -> Result<Receipt, LedgerError> {
        let receipt = self.inner.commit(expected, changes).await?;
        if self.post_commit_error.swap(false, Ordering::SeqCst) {
            return Err(storage_error());
        }
        Ok(receipt)
    }
    async fn settings(&self) -> Result<HostSettings, LedgerError> {
        if self.settings_failure.load(Ordering::SeqCst) {
            return Err(storage_error());
        }
        self.inner.settings().await
    }
    async fn request_status(&self, request: &RequestRecord) -> Result<RequestStatus, LedgerError> {
        self.inner.request_status(request).await
    }
    async fn receipt(&self, request: &RequestId) -> Result<Option<Receipt>, LedgerError> {
        self.inner.receipt(request).await
    }
    async fn receipt_for(
        &self,
        request: &RequestId,
        caller: Option<&str>,
    ) -> Result<Option<Receipt>, LedgerError> {
        self.inner.receipt_for(request, caller).await
    }
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError> {
        self.inner.pending_tickets().await
    }
    async fn complete_ticket(&self, ticket: &str) -> Result<(), LedgerError> {
        self.inner.complete_ticket(ticket).await
    }
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError> {
        self.inner.desired().await
    }
    async fn spec_revision(&self, instance: &InstanceId) -> Result<Revision, LedgerError> {
        self.inner.spec_revision(instance).await
    }
    async fn claims(&self) -> Result<Vec<ClaimHold>, LedgerError> {
        self.inner.claims().await
    }
    async fn next_epoch(&self, instance: &InstanceId) -> Result<Epoch, LedgerError> {
        self.inner.next_epoch(instance).await
    }
    async fn begin_epoch(&self, plan: GenerationPlan) -> Result<Vec<Effect>, LedgerError> {
        self.inner.begin_epoch(plan).await
    }
    async fn generation(
        &self,
        instance: &InstanceId,
        epoch: Epoch,
    ) -> Result<Option<StoredGeneration>, LedgerError> {
        self.inner.generation(instance, epoch).await
    }
    async fn record(&self, intent: EffectIntent) -> Result<Effect, LedgerError> {
        self.inner.record(intent).await
    }
    async fn transition(
        &self,
        id: &EffectId,
        to: EffectState,
        observation: Option<Observation>,
    ) -> Result<(), LedgerError> {
        self.inner.transition(id, to, observation).await
    }
    async fn record_failure(&self, id: &EffectId, error: &str) -> Result<u32, LedgerError> {
        self.inner.record_failure(id, error).await
    }
    async fn open_effects(&self, filter: &ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        self.inner.open_effects(filter).await
    }
    async fn compact(&self) -> Result<usize, LedgerError> {
        self.inner.compact().await
    }
}
async fn ambiguous_service() -> (
    ContractService,
    Arc<AmbiguousLedger>,
    etd_host_core::api::OrchestratorPort,
) {
    let f = Fixture::new().await;
    let ledger = Arc::new(AmbiguousLedger {
        inner: f.ledger,
        post_commit_error: true.into(),
        settings_failure: false.into(),
    });
    let (handle, port) = orchestrator_channel(
        64,
        HostView {
            seq: 0,
            snapshot: HostSnapshot {
                phase: HostPhase::Serving as i32,
                ..Default::default()
            },
        },
    );
    let service = ContractService::new(
        HostMode::Service,
        ledger.clone(),
        InstallKey([7; 32]),
        f.auth,
        Arc::new(FakeCoreStore::default()),
        handle,
        vec![],
        16,
    );
    (service, ledger, port)
}
fn revoke_request() -> SetAllowListRequest {
    SetAllowListRequest {
        header: Some(MutationHeader {
            request_id: "ambiguous".into(),
            expected_revision: 1,
        }),
        entries: vec![entry(0, Role::Admin)],
    }
}
#[tokio::test]
async fn ambiguous_allow_list_commit_rebuilds_snapshot_from_disk() {
    let (service, ledger, _port) = ambiguous_service().await;
    let req = revoke_request();
    assert_eq!(
        code(
            service
                .set_allow_list(request(req.clone(), Role::Admin))
                .await
                .unwrap_err()
        ),
        ErrorCode::LedgerUnavailable
    );
    assert_eq!(ledger.settings().await.unwrap().allow_list, req.entries);
    assert_eq!(
        code(
            service
                .snapshot(request(SnapshotRequest {}, Role::Viewer))
                .await
                .unwrap_err()
        ),
        ErrorCode::PermissionDenied
    );
    assert!(
        service
            .snapshot(request(SnapshotRequest {}, Role::Admin))
            .await
            .is_ok()
    );
    assert!(
        service
            .set_allow_list(request(req, Role::Admin))
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn ambiguous_allow_list_commit_denies_all_until_settings_recover() {
    use std::time::Duration;
    let (service, ledger, _port) = ambiguous_service().await;
    ledger.settings_failure.store(true, Ordering::SeqCst);
    assert_eq!(
        code(
            service
                .set_allow_list(request(revoke_request(), Role::Admin))
                .await
                .unwrap_err()
        ),
        ErrorCode::LedgerUnavailable
    );
    for role in [Role::Admin, Role::Control, Role::Viewer] {
        assert_eq!(
            code(
                service
                    .snapshot(request(SnapshotRequest {}, role))
                    .await
                    .unwrap_err()
            ),
            ErrorCode::PermissionDenied
        );
    }
    ledger.settings_failure.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if service
                .snapshot(request(SnapshotRequest {}, Role::Admin))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        code(
            service
                .snapshot(request(SnapshotRequest {}, Role::Viewer))
                .await
                .unwrap_err()
        ),
        ErrorCode::PermissionDenied
    );
}
#[tokio::test]
async fn ambiguous_purge_commit_keeps_admin_authorized() {
    let (service, ledger, _port) = ambiguous_service().await;
    let expected = ledger.settings().await.unwrap().allow_list;
    let req = PurgeAllDataRequest {
        header: Some(MutationHeader {
            request_id: "purge-ambiguous".into(),
            expected_revision: 1,
        }),
        confirm: true,
    };
    assert_eq!(
        code(
            service
                .purge_all_data(request(req.clone(), Role::Admin))
                .await
                .unwrap_err()
        ),
        ErrorCode::LedgerUnavailable
    );
    assert_eq!(ledger.settings().await.unwrap().allow_list, expected);
    assert!(
        service
            .snapshot(request(SnapshotRequest {}, Role::Admin))
            .await
            .is_ok()
    );
    assert!(
        service
            .purge_all_data(request(req, Role::Admin))
            .await
            .is_ok()
    );
}
const SESSION_OWNER: &str = "S-1-5-21-1-2-3-1001";

fn session_peer(user: &str, session: Option<u32>, elevated: bool) -> etd_ipc::PeerIdentity {
    etd_ipc::PeerIdentity {
        user: etd_ipc::OsUserId::WindowsSid(user.into()),
        groups: vec![],
        pid: 1,
        session,
        elevated,
    }
}

fn session_request<T>(body: T, peer: etd_ipc::PeerIdentity) -> tonic::Request<T> {
    let mut req = request(body, Role::Viewer);
    req.extensions_mut().insert(peer);
    req
}

async fn session_service(
    ledger: Arc<MemoryLedger>,
) -> (
    ContractService,
    Arc<etd_host_core::auth::allow_list::AllowListAuthorizer>,
) {
    let auth = Arc::new(
        etd_host_core::auth::allow_list::AllowListAuthorizer::new(
            HostMode::ElevatedSession,
            Some(etd_ipc::OsUserId::WindowsSid(SESSION_OWNER.into())),
        )
        .with_session(Some(1)),
    );
    auth.load(ledger.as_ref()).await.unwrap();
    let (handle, _port) = orchestrator_channel(8, HostView::default());
    let service = ContractService::new(
        HostMode::ElevatedSession,
        ledger,
        InstallKey([7; 32]),
        auth.clone(),
        Arc::new(FakeCoreStore::default()),
        handle,
        vec![
            capability::INSTANCES.into(),
            capability::TUN.into(),
            capability::LEASE.into(),
            capability::ADMIN_ALLOW_LIST.into(),
            capability::ADMIN_PURGE.into(),
        ],
        8,
    );
    (service, auth)
}

#[tokio::test]
async fn elevated_session_roles_follow_owner_session_and_elevation() {
    let f = Fixture::new().await;
    let (_, auth) = session_service(f.ledger).await;
    let other = "S-1-5-21-1-2-3-1002";
    for (peer, role) in [
        (
            session_peer(SESSION_OWNER, Some(1), false),
            Some(Role::Control),
        ),
        (
            session_peer(SESSION_OWNER, Some(1), true),
            Some(Role::Admin),
        ),
        (
            session_peer(&SESSION_OWNER.to_lowercase(), Some(1), false),
            Some(Role::Control),
        ),
        (session_peer(other, Some(1), false), None),
        (session_peer(other, Some(1), true), None),
        (session_peer(SESSION_OWNER, Some(2), true), None),
        (session_peer(SESSION_OWNER, None, true), None),
        (session_peer("S-1-5-18", Some(1), true), None),
    ] {
        assert_eq!(auth.role_of(&peer), role, "{peer:?}");
    }
    // Without the host's own session nobody is authorized.
    let unset = etd_host_core::auth::allow_list::AllowListAuthorizer::new(
        HostMode::ElevatedSession,
        Some(etd_ipc::OsUserId::WindowsSid(SESSION_OWNER.into())),
    );
    unset.load(&MemoryLedger::default()).await.unwrap();
    assert_eq!(
        unset.role_of(&session_peer(SESSION_OWNER, Some(1), true)),
        None
    );
}

#[tokio::test]
async fn elevated_session_handshake_capabilities_and_elevation_required() {
    let f = Fixture::new().await;
    let (service, _) = session_service(f.ledger).await;
    let hello = Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        ..Default::default()
    };
    let welcome = service
        .handshake(session_request(
            hello.clone(),
            session_peer(SESSION_OWNER, Some(1), false),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(welcome.role(), Role::Control);
    assert_eq!(welcome.host_mode(), HostMode::ElevatedSession);
    assert_eq!(
        welcome.capabilities,
        vec![
            capability::INSTANCES,
            capability::TUN,
            capability::LEASE,
            capability::ADMIN_PURGE
        ]
    );
    let welcome = service
        .handshake(session_request(
            hello.clone(),
            session_peer(SESSION_OWNER, Some(1), true),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(welcome.role(), Role::Admin);
    assert_eq!(
        code(
            service
                .handshake(session_request(
                    hello,
                    session_peer("S-1-5-21-1-2-3-1002", Some(1), true)
                ))
                .await
                .unwrap_err()
        ),
        ErrorCode::PermissionDenied
    );
    // An Admin method from the non-elevated owner asks for elevation.
    assert_eq!(
        code(
            service
                .purge_all_data(session_request(
                    PurgeAllDataRequest::default(),
                    session_peer(SESSION_OWNER, Some(1), false)
                ))
                .await
                .unwrap_err()
        ),
        ErrorCode::ElevationRequired
    );
    // There is no allow list, even for the elevated owner.
    assert_eq!(
        code(
            service
                .get_allow_list(session_request(
                    GetAllowListRequest {},
                    session_peer(SESSION_OWNER, Some(1), true)
                ))
                .await
                .unwrap_err()
        ),
        ErrorCode::FeatureRejected
    );
}
