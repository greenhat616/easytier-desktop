//! Configurable fake authorizer for orchestration tests.
use etd_contract::Role;
use etd_host_core::auth::Authorizer;
use etd_ipc::PeerIdentity;
use std::sync::RwLock;

pub struct FakeAuthorizer(pub RwLock<Option<Role>>);
impl FakeAuthorizer {
    pub fn new(role: Option<Role>) -> Self {
        Self(RwLock::new(role))
    }
}
impl Authorizer for FakeAuthorizer {
    fn role_of(&self, _: &PeerIdentity) -> Option<Role> {
        *self.0.read().unwrap()
    }
}
