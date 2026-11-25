//! Management session over the kernel's loopback RPC (`StandAloneClient`
//! over a `TcpStream` tunnel); maps queries and events to contract types.
//! Owned by E2.
use etd_core_api::{CoreDescriptor, CoreEndpoint, CoreError, CoreSession};

pub async fn attach(
    _ep: &CoreEndpoint,
    _core: &CoreDescriptor,
) -> Result<Box<dyn CoreSession>, CoreError> {
    Err(CoreError::Unsupported(
        "management session not implemented".into(),
    ))
}
