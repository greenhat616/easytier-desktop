//! Provisional Rust models for methods not yet defined in the wire contract.
use crate::Role;

pub type Revision = u64;
pub type EventCursor = u64;
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstanceId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(pub String);

#[derive(Debug, Clone)]
pub struct Negotiated {
    pub major: u32,
    pub minor: u32,
    pub capabilities: Vec<String>,
    pub role: Role,
}
#[derive(Debug, Clone)]
pub struct Mutation<T> {
    pub request_id: RequestId,
    pub instance_id: InstanceId,
    pub expected_revision: Revision,
    pub value: T,
}
#[derive(Debug, Clone)]
pub struct Receipt {
    pub request_id: RequestId,
    pub revision: Revision,
    pub ticket: String,
}
#[derive(Debug, Clone)]
pub enum Query {
    Nodes,
    Routes,
    Traffic,
}
#[derive(Debug, Clone)]
pub struct QueryReply;
#[derive(Debug, Clone)]
pub struct Event {
    pub cursor: EventCursor,
}
#[derive(Debug, Clone)]
pub struct ReclaimReport;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMode {
    User,
    Elevated,
    Service,
}
