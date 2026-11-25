use crate::*;
use async_trait::async_trait;
use futures_util::future::BoxFuture;

#[derive(Debug, thiserror::Error)]
pub enum ReclaimError {
    #[error("reclaim not implemented")]
    NotImplemented,
}
#[async_trait]
pub trait Reclaimer: Send + Sync {
    fn kind(&self) -> EffectKind;
    fn rank(&self) -> u8;
    async fn probe(&self, e: &Effect) -> Probe;
    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError>;
}
pub trait Sweeper: Send + Sync {
    fn find_marked(&self) -> BoxFuture<'_, Vec<FoundObject>>;
}
pub trait BootIdSource: Send + Sync {
    fn current(&self) -> BootId;
}
