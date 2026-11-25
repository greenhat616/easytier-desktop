//! Frozen authorisation interface (F0). The allow-list implementation is
//! `auth/allow_list.rs` (H2).
use etd_contract::Role;
use etd_ipc::PeerIdentity;

pub mod allow_list;

/// Maps OS peer credentials to a contract role using the allow list kept in
/// the ledger (`HostSettings::allow_list`). Returns `None` for unknown
/// peers. Implementations grant [`Role::Admin`] only to elevated tokens on
/// Windows (administration re-elevates every time).
pub trait Authorizer: Send + Sync {
    fn role_of(&self, peer: &PeerIdentity) -> Option<Role>;
}

/// Roles are ordered: admin includes control includes viewer.
pub fn role_allows(have: Role, need: Role) -> bool {
    fn level(role: Role) -> u8 {
        match role {
            Role::Unspecified => 0,
            Role::Viewer => 1,
            Role::Control => 2,
            Role::Admin => 3,
        }
    }
    need != Role::Unspecified && level(have) >= level(need)
}
