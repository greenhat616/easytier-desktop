mod common;
use common::*;
use etd_contract::{v1::*, *};
use etd_host_core::stub::host_service_server::HostService;
#[tokio::test]
async fn missing_and_mismatched_version_checked_for_unary_and_streams() {
    let f = Fixture::new().await;
    let mut req = request(SnapshotRequest {}, Role::Viewer);
    req.metadata_mut().remove(VERSION_METADATA_KEY);
    assert_eq!(
        code(f.service.snapshot(req).await.unwrap_err()),
        ErrorCode::VersionMetadata
    );
    let mut req = request(SubscribeRequest::default(), Role::Viewer);
    req.metadata_mut()
        .insert(VERSION_METADATA_KEY, "42.0".parse().unwrap());
    assert_eq!(
        code(f.service.subscribe(req).await.err().unwrap()),
        ErrorCode::VersionMismatch
    );
    let mut req = request(StreamLogsRequest::default(), Role::Viewer);
    req.metadata_mut().remove(VERSION_METADATA_KEY);
    assert_eq!(
        code(f.service.stream_logs(req).await.err().unwrap()),
        ErrorCode::VersionMetadata
    );
    let mut req = request(SnapshotRequest {}, Role::Viewer);
    req.extensions_mut().clear();
    assert_eq!(
        code(f.service.snapshot(req).await.unwrap_err()),
        ErrorCode::PermissionDenied
    );
}
