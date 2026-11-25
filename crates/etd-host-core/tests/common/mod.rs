#![allow(dead_code)]
use etd_contract::{v1::*, *};
use etd_host_core::{
    api::{Command, HostView, OrchestratorPort, Planned, orchestrator_channel},
    auth::allow_list::AllowListAuthorizer,
    service::ContractService,
};
use etd_ipc::{OsUserId, PeerIdentity};
use etd_sysfx::{Change, ChangeSet, Ledger, RequestDigest, RequestRecord};
use etd_testkit::fakes::{ledger::MemoryLedger, store::FakeCoreStore};
use prost::Message;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tonic::{Request, Status};

pub const INSTANCE: &str = "0f661e50-b9a6-4525-9583-9538fe01e928";
pub fn entry(uid: u32, role: Role) -> AllowEntry {
    AllowEntry {
        principal: Some(OsPrincipal {
            id: Some(os_principal::Id::UnixUid(uid)),
        }),
        role: role as i32,
        display_name: String::new(),
    }
}
pub fn peer(role: Role) -> PeerIdentity {
    PeerIdentity {
        user: OsUserId::UnixUid(match role {
            Role::Viewer => 10,
            Role::Control => 20,
            Role::Admin => 0,
            _ => 99,
        }),
        groups: vec![],
        pid: 1,
        session: None,
        elevated: role == Role::Admin,
    }
}
pub fn request<T>(body: T, role: Role) -> Request<T> {
    let mut req = Request::new(body);
    req.metadata_mut().insert(
        VERSION_METADATA_KEY,
        version_metadata_value().parse().unwrap(),
    );
    req.extensions_mut().insert(peer(role));
    req
}
pub fn code(status: Status) -> ErrorCode {
    ErrorDetail::decode(status.details()).unwrap().code()
}
pub struct Fixture {
    pub service: ContractService,
    pub ledger: Arc<MemoryLedger>,
    pub port: OrchestratorPort,
    pub auth: Arc<AllowListAuthorizer>,
}
impl Fixture {
    pub async fn new() -> Self {
        let ledger = Arc::new(MemoryLedger::default());
        ledger
            .commit(
                0,
                ChangeSet {
                    request: RequestRecord {
                        request_id: "seed".into(),
                        caller: "installer".into(),
                        digest: RequestDigest([8; 32]),
                    },
                    changes: vec![Change::SetAllowList(vec![
                        entry(10, Role::Viewer),
                        entry(20, Role::Control),
                        entry(0, Role::Admin),
                    ])],
                    generations: vec![],
                },
            )
            .await
            .unwrap();
        let auth = Arc::new(AllowListAuthorizer::new(HostMode::Service, None));
        auth.load(ledger.as_ref()).await.unwrap();
        let (handle, port) = orchestrator_channel(
            64,
            HostView {
                seq: 0,
                snapshot: HostSnapshot {
                    phase: HostPhase::Serving as i32,
                    revision: 1,
                    ..Default::default()
                },
            },
        );
        let service = ContractService::new(
            HostMode::Service,
            ledger.clone(),
            auth.clone(),
            Arc::new(FakeCoreStore::default()),
            handle,
            vec![capability::INSTANCES.into(), capability::RECLAIM.into()],
            16,
        );
        Self {
            service,
            ledger,
            port,
            auth,
        }
    }
    pub fn start_commands(&mut self) -> Arc<AtomicUsize> {
        let (_, replacement) = orchestrator_channel(1, HostView::default());
        let mut port = std::mem::replace(&mut self.port, replacement);
        let ledger = self.ledger.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let plans = count.clone();
        tokio::spawn(async move {
            while let Some(cmd) = port.commands.recv().await {
                match cmd {
                    Command::Plan {
                        instance,
                        spec,
                        start,
                        reply,
                    } => {
                        plans.fetch_add(1, Ordering::SeqCst);
                        let (revision, desired) = ledger.desired().await.unwrap();
                        let generation = if start {
                            let (spec, spec_revision) = if let Some(spec) = spec {
                                (*spec, revision + 1)
                            } else {
                                (
                                    desired
                                        .iter()
                                        .find(|v| v.instance_id == instance.0)
                                        .unwrap()
                                        .spec
                                        .clone()
                                        .unwrap(),
                                    ledger.spec_revision(&instance).await.unwrap(),
                                )
                            };
                            let epoch = ledger.next_epoch(&instance).await.unwrap();
                            let mut plan = etd_testkit::conformance::ledger::plan_at(
                                &instance.0,
                                epoch.0,
                                &[],
                                spec_revision,
                            );
                            plan.inputs.spec = spec;
                            Some(plan)
                        } else {
                            None
                        };
                        let _ = reply.send(Ok(Planned {
                            claims: vec![],
                            generation,
                            revision,
                        }));
                    }
                    Command::Query { reply, .. } => {
                        let _ = reply.send(Err(ErrorDetail {
                            code: ErrorCode::ManagementUnavailable as i32,
                            ..Default::default()
                        }));
                    }
                    Command::Logs { reply, .. } => {
                        let _ = reply.send(Ok(Box::pin(futures_util::stream::empty())));
                    }
                    _ => {}
                }
            }
        });
        count
    }
}
