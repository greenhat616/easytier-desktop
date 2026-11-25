//! In-memory duplex transport for component tests. Owned by I1.
use etd_ipc::BoxConn;
pub fn duplex(capacity: usize) -> (BoxConn, BoxConn) {
    let (left, right) = tokio::io::duplex(capacity);
    (Box::new(left), Box::new(right))
}

/// Real contract service, backed by the in-memory ledger and a user-host
/// authorizer. Handshake can only succeed with the owner's ConnectInfo.
pub async fn user_host(
    owner: etd_ipc::OsUserId,
) -> etd_host_core::stub::host_service_server::HostServiceServer<
    etd_host_core::service::ContractService,
> {
    use crate::fakes::{ledger::MemoryLedger, store::FakeCoreStore};
    use etd_contract::HostMode;
    use etd_host_core::{
        api::{HostView, orchestrator_channel},
        auth::allow_list::AllowListAuthorizer,
        service::ContractService,
        stub::host_service_server::HostServiceServer,
    };
    use std::sync::Arc;
    let ledger = Arc::new(MemoryLedger::default());
    let auth = Arc::new(AllowListAuthorizer::new(HostMode::User, Some(owner)));
    auth.load(ledger.as_ref()).await.unwrap();
    let (handle, _port) = orchestrator_channel(4, HostView::default());
    HostServiceServer::new(ContractService::new(
        HostMode::User,
        ledger,
        etd_sysfx::InstallKey([0; 32]),
        auth,
        Arc::new(FakeCoreStore::default()),
        handle,
        vec![],
        4,
    ))
}
