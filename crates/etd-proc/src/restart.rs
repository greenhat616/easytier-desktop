//! Frozen clock and restart-policy interfaces (F0). Policy implementation:
//! `backoff.rs` (P1).
use crate::Exit;
use futures_util::future::BoxFuture;
use std::time::{Duration, Instant};

/// First restart delay after an abnormal exit.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Window for the circuit breaker.
pub const GIVE_UP_WINDOW: Duration = Duration::from_secs(5 * 60);
/// The n-th abnormal exit inside [`GIVE_UP_WINDOW`] gives up.
pub const GIVE_UP_AFTER: u32 = 5;

/// Monotonic time source; faked in tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()>;
}

/// Deliberately exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDecision {
    After(Duration),
    /// Circuit breaker tripped; the reason is shown to the user.
    GiveUp(String),
    /// Exit was requested or desired state is stopped: no restart.
    Stay,
}

pub trait RestartPolicy: Send {
    fn on_exit(&mut self, now: Instant, exit: &Exit) -> RestartDecision;
    /// Manual retry after giving up: forget the exit history.
    fn reset(&mut self);
}
