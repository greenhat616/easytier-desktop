//! Allow-list snapshot populated from the ledger before serving.
use crate::auth::Authorizer;
use etd_contract::{AllowEntry, HostMode, Role, v1::os_principal::Id};
use etd_ipc::{OsGroupId, OsUserId, PeerIdentity};
use etd_sysfx::{Ledger, LedgerError};
use tokio::sync::watch;

/// Fail-closed until initialized. The contract service serializes mutations
/// and replaces this snapshot before returning an allow-list receipt.
pub struct AllowListAuthorizer {
    mode: HostMode,
    owner: Option<OsUserId>,
    /// The elevated session host's own Windows session.
    session: Option<u32>,
    entries: watch::Sender<Option<Vec<AllowEntry>>>,
}
impl AllowListAuthorizer {
    pub fn new(mode: HostMode, owner: Option<OsUserId>) -> Self {
        Self {
            mode,
            owner,
            session: None,
            entries: watch::channel(None).0,
        }
    }
    /// The Windows session the elevated session host runs in. Its peers
    /// must be in the same one; without it no peer is authorized.
    pub fn with_session(mut self, session: Option<u32>) -> Self {
        self.session = session;
        self
    }
    fn is_owner(&self, peer: &PeerIdentity) -> bool {
        match (&self.owner, &peer.user) {
            (Some(OsUserId::WindowsSid(a)), OsUserId::WindowsSid(b)) => a.eq_ignore_ascii_case(b),
            (Some(OsUserId::UnixUid(a)), OsUserId::UnixUid(b)) => a == b,
            _ => false,
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
                self.invalidate();
                Err(e)
            }
        }
    }
    pub(crate) fn replace(&self, entries: Vec<AllowEntry>) {
        self.entries.send_replace(Some(entries));
    }
    pub(crate) fn invalidate(&self) {
        self.entries.send_replace(None);
    }
    pub(crate) fn is_loaded(&self) -> bool {
        self.entries.borrow().is_some()
    }
    pub(crate) fn watch(&self) -> watch::Receiver<Option<Vec<AllowEntry>>> {
        self.entries.subscribe()
    }
}
impl Authorizer for AllowListAuthorizer {
    fn role_of(&self, peer: &PeerIdentity) -> Option<Role> {
        let guard = self.entries.borrow();
        let entries = guard.as_ref()?;
        match self.mode {
            HostMode::User => return self.is_owner(peer).then_some(Role::Admin),
            // The owner in the host's own Windows session controls it;
            // only an elevated owner administers it (doc#13).
            HostMode::ElevatedSession => {
                let same_session = self.session.is_some() && peer.session == self.session;
                if !(self.is_owner(peer) && same_session) {
                    return None;
                }
                return Some(if peer.elevated {
                    Role::Admin
                } else {
                    Role::Control
                });
            }
            HostMode::Service => (),
            HostMode::Unspecified => return None,
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
