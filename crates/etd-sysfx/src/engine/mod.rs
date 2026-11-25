//! Reclaim engine: probe -> delete -> verify in rank order; delete only on a
//! matching credential or exclusive container, otherwise candidate; conflicts
//! stay open; quarantine after five failures; boot-id change closes volatile
//! records unprobed; repair-index name re-derivation after ledger loss.
//! Owned by R1. The type name and `new(ReclaimDeps)` are frozen (F0); the
//! body is R1's.
use crate::*;
use async_trait::async_trait;
use etd_contract::{CandidateDecision, InstanceId};

pub struct ReclaimEngineImpl {
    #[allow(dead_code)]
    deps: ReclaimDeps,
}

impl ReclaimEngineImpl {
    pub fn new(deps: ReclaimDeps) -> Self {
        Self { deps }
    }
}

fn not_implemented() -> LedgerError {
    LedgerError::Unavailable(StorageFault::Io("reclaim engine not implemented".into()))
}

#[async_trait]
impl ReclaimEngine for ReclaimEngineImpl {
    async fn reclaim_generation(
        &self,
        _: &InstanceId,
        _: Epoch,
    ) -> Result<GenerationReport, LedgerError> {
        Err(not_implemented())
    }
    async fn reclaim_all(&self, _: ReclaimScope) -> Result<ReclaimReport, LedgerError> {
        Err(not_implemented())
    }
    async fn retry(&self, _: &InstanceId) -> Result<GenerationReport, LedgerError> {
        Err(not_implemented())
    }
    async fn resolve(&self, _: &[CandidateDecision]) -> Result<ReclaimReport, LedgerError> {
        Err(not_implemented())
    }
    async fn sweep_without_ledger(&self) -> Result<ReclaimReport, ReclaimError> {
        Err(ReclaimError::Indeterminate(
            "reclaim engine not implemented".into(),
        ))
    }
    async fn report(&self) -> Result<ReclaimReport, LedgerError> {
        Err(not_implemented())
    }
}
