use crate::*;
use etd_contract::{DesiredInstance, Receipt, Revision};
use std::sync::Mutex;

/// The connection will be owned by the ledger's single writer.
pub struct SqliteLedger {
    #[allow(dead_code)]
    connection: Mutex<rusqlite::Connection>,
}
#[async_trait::async_trait]
impl Ledger for SqliteLedger {
    async fn commit(&self, _: Revision, _: ChangeSet) -> Result<Receipt, LedgerError> {
        Err(LedgerError::NotImplemented)
    }
    async fn transition(
        &self,
        _: EffectId,
        _: EffectState,
        _: Option<Observation>,
    ) -> Result<(), LedgerError> {
        Err(LedgerError::NotImplemented)
    }
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError> {
        Err(LedgerError::NotImplemented)
    }
    async fn open_effects(&self, _: ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        Err(LedgerError::NotImplemented)
    }
}
