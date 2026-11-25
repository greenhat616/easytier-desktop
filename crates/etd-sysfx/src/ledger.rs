use crate::*;
use async_trait::async_trait;
use etd_contract::{DesiredInstance, Receipt, Revision};

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("revision conflict")]
    Conflict,
    #[error("ledger not implemented")]
    NotImplemented,
}
#[async_trait]
pub trait Ledger: Send + Sync {
    /// Persist request, desired state, receipt and effects in one transaction.
    async fn commit(&self, expected: Revision, change: ChangeSet) -> Result<Receipt, LedgerError>;
    async fn transition(
        &self,
        id: EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError>;
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError>;
    async fn open_effects(&self, filter: ScopeFilter) -> Result<Vec<Effect>, LedgerError>;
}
