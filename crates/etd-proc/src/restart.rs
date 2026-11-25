use crate::Exit;
use futures_util::future::BoxFuture;
use std::time::{Duration, Instant};

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()>;
}
#[derive(Debug, Clone)]
pub enum RestartDecision {
    After(Duration),
    GiveUp(String),
    Stay,
}
pub trait RestartPolicy: Send {
    fn on_exit(&mut self, now: Instant, exit: &Exit) -> RestartDecision;
}
