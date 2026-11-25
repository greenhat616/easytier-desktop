//! OS side-effect adapters; deliberately non-operational.
use etd_sysfx::*;

pub struct OsReclaimer {
    pub kind: EffectKind,
    pub rank: u8,
}
#[async_trait::async_trait]
impl Reclaimer for OsReclaimer {
    fn kind(&self) -> EffectKind {
        self.kind
    }
    fn rank(&self) -> u8 {
        self.rank
    }
    async fn probe(&self, _: &Effect) -> Probe {
        Probe::Indeterminate
    }
    async fn reclaim(&self, _: &Effect) -> Result<Reclaimed, ReclaimError> {
        Err(ReclaimError::NotImplemented)
    }
}
pub struct OsSweeper;
pub struct OsBootIdSource;

impl Sweeper for OsSweeper {
    fn find_marked(&self) -> futures_util::future::BoxFuture<'_, Vec<FoundObject>> {
        todo!("OS adapter")
    }
}
impl BootIdSource for OsBootIdSource {
    fn current(&self) -> BootId {
        todo!("OS adapter")
    }
}
