use etd_contract::Role;
use etd_ipc::PeerIdentity;
pub trait Authorizer: Send + Sync {
    fn role_of(&self, peer: &PeerIdentity) -> Option<Role>;
}
