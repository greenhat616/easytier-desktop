//! [`crate::RestartPolicy`] implementation: backoff from 1 s, give up on the
//! fifth abnormal exit within five minutes. Owned by P1.
use crate::*;
use futures_util::future::BoxFuture;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

#[derive(Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        let deadline = Instant::now() + d;
        Box::pin(async move { tokio::time::sleep_until(deadline.into()).await })
    }
}

/// Rolling-window circuit breaker. Once open, only a manual retry resets it.
#[derive(Default)]
pub struct BackoffPolicy {
    failures: VecDeque<Instant>,
    gave_up: bool,
}

impl BackoffPolicy {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RestartPolicy for BackoffPolicy {
    fn on_exit(&mut self, now: Instant, exit: &Exit) -> RestartDecision {
        if !exit.abnormal() {
            return RestartDecision::Stay;
        }
        if self.gave_up {
            return RestartDecision::GiveUp("five abnormal exits within five minutes".into());
        }
        while self
            .failures
            .front()
            .is_some_and(|old| now.saturating_duration_since(*old) >= GIVE_UP_WINDOW)
        {
            self.failures.pop_front();
        }
        self.failures.push_back(now);
        if self.failures.len() >= GIVE_UP_AFTER as usize {
            self.gave_up = true;
            RestartDecision::GiveUp("five abnormal exits within five minutes".into())
        } else {
            RestartDecision::After(BACKOFF_INITIAL * (1 << (self.failures.len() - 1)))
        }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etd_testkit::fakes::clock::FakeClock;

    #[test]
    fn rolling_window_and_manual_retry() {
        let clock = FakeClock::default();
        let mut policy = BackoffPolicy::new();
        let crash = Exit {
            code: Some(1),
            signal: None,
            cause: ExitCause::Exited,
        };
        let stopped = Exit {
            cause: ExitCause::Stopped,
            ..crash.clone()
        };
        for secs in [1, 2, 4, 8] {
            assert_eq!(
                policy.on_exit(clock.now(), &crash),
                RestartDecision::After(Duration::from_secs(secs))
            );
            clock.advance(Duration::from_secs(secs));
            assert_eq!(policy.on_exit(clock.now(), &stopped), RestartDecision::Stay);
        }
        assert!(matches!(
            policy.on_exit(clock.now(), &crash),
            RestartDecision::GiveUp(_)
        ));
        clock.advance(GIVE_UP_WINDOW);
        assert!(matches!(
            policy.on_exit(clock.now(), &crash),
            RestartDecision::GiveUp(_)
        ));
        policy.reset();
        assert_eq!(
            policy.on_exit(clock.now(), &crash),
            RestartDecision::After(BACKOFF_INITIAL)
        );
        clock.advance(GIVE_UP_WINDOW);
        assert_eq!(
            policy.on_exit(clock.now(), &crash),
            RestartDecision::After(BACKOFF_INITIAL)
        );
    }
}
