//! Stub service deliberately rejects calls until authentication and orchestration exist.
use crate::grpc::host_service_server::HostService;
use etd_contract::{Hello, HostSnapshot, Welcome, v1::SnapshotRequest};
use tonic::{Request, Response, Status};

pub struct HostServiceStub;

#[tonic::async_trait]
impl HostService for HostServiceStub {
    async fn handshake(&self, _: Request<Hello>) -> Result<Response<Welcome>, Status> {
        Err(Status::unimplemented("host scaffold"))
    }

    async fn snapshot(
        &self,
        _: Request<SnapshotRequest>,
    ) -> Result<Response<HostSnapshot>, Status> {
        Err(Status::unimplemented("host scaffold"))
    }
}
