//! Handshake and capability gating ("upgrade the service" on major
//! mismatch; features by capability name, never by version). Owned by C1.
use crate::{CallError, grpc::Stub, grpc::call_error};
use etd_contract::{
    Hello, Negotiated, QueryKind, VERSION_MAJOR, VERSION_MINOR, capability, v1::ClientKind,
};

pub(crate) async fn handshake(
    client: &mut Stub,
    client_kind: ClientKind,
    build: &str,
) -> Result<Negotiated, CallError> {
    let hello = Hello {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        build: build.to_owned(),
        client_kind: client_kind as i32,
    };
    let welcome = client
        .handshake(hello)
        .await
        .map_err(|status| call_error("Handshake", &status))?
        .into_inner();
    // The host is expected to reject a foreign major itself; a Welcome that
    // carries one is refused all the same. The minor version is never
    // compared: it only adds, and features are announced by name.
    if welcome.major != VERSION_MAJOR {
        return Err(CallError::VersionMismatch {
            host_major: welcome.major,
            host_minor: welcome.minor,
        });
    }
    Ok(welcome.into())
}

/// Fails with [`CallError::Unsupported`] unless the Welcome listed `name`.
pub(crate) fn require(negotiated: &Negotiated, name: &str) -> Result<(), CallError> {
    if negotiated.has_capability(name) {
        Ok(())
    } else {
        Err(CallError::Unsupported(name.to_owned()))
    }
}

/// The capability a query needs. An unspecified kind needs none: the host
/// rejects it as an invalid request.
pub(crate) fn query_capability(kind: QueryKind) -> Option<&'static str> {
    match kind {
        QueryKind::Nodes => Some(capability::QUERY_NODES),
        QueryKind::Routes => Some(capability::QUERY_ROUTES),
        QueryKind::Traffic => Some(capability::QUERY_TRAFFIC),
        QueryKind::Unspecified => None,
    }
}
