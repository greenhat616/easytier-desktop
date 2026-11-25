//! Allow-list snapshot populated from the ledger before serving.
use crate::auth::Authorizer;
use etd_contract::{AllowEntry, HostMode, Role, v1::os_principal::Id};
use etd_ipc::{OsGroupId, OsUserId, PeerIdentity};
use etd_sysfx::{Ledger, LedgerError};
use std::sync::RwLock;

/// Fail-closed until initialized. The contract service serializes mutations
/// and replaces this snapshot before returning an allow-list receipt.
pub struct AllowListAuthorizer {
    mode: HostMode,
    owner: Option<OsUserId>,
    entries: RwLock<Option<Vec<AllowEntry>>>,
}
impl AllowListAuthorizer {
    pub fn new(mode: HostMode, owner: Option<OsUserId>) -> Self {
        Self {
            mode,
            owner,
            entries: RwLock::new(None),
        }
    }
    pub async fn load(&self, ledger: &dyn Ledger) -> Result<(), LedgerError> {
        let settings = ledger.settings().await;
        match settings {
            Ok(settings) => {
                self.replace(settings.allow_list);
                Ok(())
            }
            Err(e) => {
                *self.entries.write().unwrap_or_else(|e| e.into_inner()) = None;
                Err(e)
            }
        }
    }
    pub(crate) fn replace(&self, entries: Vec<AllowEntry>) {
        *self.entries.write().unwrap_or_else(|e| e.into_inner()) = Some(entries);
    }
}
impl Authorizer for AllowListAuthorizer {
    fn role_of(&self, peer: &PeerIdentity) -> Option<Role> {
        let guard = self.entries.read().ok()?;
        let entries = guard.as_ref()?;
        if self.mode == HostMode::User {
            let owner = match (&self.owner, &peer.user) {
                (Some(OsUserId::WindowsSid(a)), OsUserId::WindowsSid(b)) => {
                    a.eq_ignore_ascii_case(b)
                }
                (Some(OsUserId::UnixUid(a)), OsUserId::UnixUid(b)) => a == b,
                _ => false,
            };
            return owner.then_some(Role::Admin);
        }
        if self.mode != HostMode::Service {
            return None;
        }
        let mut role = Role::Unspecified;
        for entry in entries {
            let Some(id) = entry.principal.as_ref().and_then(|p| p.id.as_ref()) else {
                continue;
            };
            let matches = match id {
                Id::WindowsUserSid(sid) => {
                    matches!(&peer.user, OsUserId::WindowsSid(s) if s.eq_ignore_ascii_case(sid))
                }
                Id::WindowsGroupSid(sid) => peer
                    .groups
                    .iter()
                    .any(|g| matches!(g, OsGroupId::WindowsSid(s) if s.eq_ignore_ascii_case(sid))),
                Id::UnixUid(uid) => matches!(peer.user, OsUserId::UnixUid(u) if u == *uid),
                Id::UnixGid(gid) => peer.groups.contains(&OsGroupId::UnixGid(*gid)),
            };
            if matches
                && (role == Role::Unspecified || crate::auth::role_allows(entry.role(), role))
            {
                role = entry.role();
            }
        }
        if role == Role::Admin && !peer.elevated {
            role = Role::Control;
        }
        (role != Role::Unspecified).then_some(role)
    }
}
