//! Version checks shared by unary and streaming RPC handlers.
use etd_contract::{
    ErrorCode, ErrorDetail, VERSION_MAJOR, VERSION_METADATA_KEY, VERSION_MINOR,
    parse_version_metadata,
};
use prost::Message;
use tonic::{Code, Request, Status};

pub(crate) fn rejection(code: ErrorCode, message: impl Into<String>) -> Status {
    status(ErrorDetail {
        code: code as i32,
        message: message.into(),
        ..Default::default()
    })
}
pub(crate) fn status(detail: ErrorDetail) -> Status {
    let code = match detail.code() {
        ErrorCode::PermissionDenied | ErrorCode::ElevationRequired => Code::PermissionDenied,
        ErrorCode::RevisionConflict => Code::Aborted,
        ErrorCode::UnknownInstance | ErrorCode::UnknownCandidate => Code::NotFound,
        ErrorCode::InvalidSpec | ErrorCode::RequestIdReused | ErrorCode::VersionMetadata => {
            Code::InvalidArgument
        }
        ErrorCode::LedgerUnavailable => Code::Unavailable,
        _ => Code::FailedPrecondition,
    };
    Status::with_details(code, detail.message.clone(), detail.encode_to_vec().into())
}
pub fn version_mismatch() -> Status {
    status(ErrorDetail {
        code: ErrorCode::VersionMismatch as i32,
        message: "Contract major version differs; upgrade the host or client".into(),
        host_major: VERSION_MAJOR,
        host_minor: VERSION_MINOR,
        ..Default::default()
    })
}
pub fn check_version<T>(request: &Request<T>) -> Result<(u32, u32), Status> {
    let values = request.metadata().get_all(VERSION_METADATA_KEY);
    let mut entries = values.iter();
    let value = entries
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(parse_version_metadata);
    let Some((major, minor)) = value.filter(|_| entries.next().is_none()) else {
        return Err(rejection(
            ErrorCode::VersionMetadata,
            "Missing or malformed contract version metadata",
        ));
    };
    if major != VERSION_MAJOR {
        return Err(version_mismatch());
    }
    Ok((major, minor))
}

/// Can be installed at the tonic transport boundary to reject incompatible
/// metadata before protobuf decoding. Handlers also check it, so bare generated
/// servers and direct calls cannot skip the guard.
#[derive(Clone, Copy, Debug, Default)]
pub struct VersionInterceptor;
impl tonic::service::Interceptor for VersionInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        check_version(&request)?;
        Ok(request)
    }
}
