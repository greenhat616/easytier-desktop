//! Virtual `etd_proc::Clock`. Owned by P1.
use etd_proc::Clock;
use futures_util::future::BoxFuture;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Manually advanced monotonic and wall time, shared by all clones.
#[derive(Clone)]
pub struct FakeClock {
    origin: Instant,
    time: watch::Sender<(Duration, jiff::Timestamp)>,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new(jiff::Timestamp::UNIX_EPOCH)
    }
}

impl FakeClock {
    pub fn new(wall: jiff::Timestamp) -> Self {
        Self {
            origin: Instant::now(),
            time: watch::channel((Duration::ZERO, wall)).0,
        }
    }

    /// Advance both clocks and wake every sleep whose deadline was reached.
    pub fn advance(&self, by: Duration) {
        self.time.send_modify(|(elapsed, wall)| {
            *elapsed += by;
            *wall = wall.checked_add(by).expect("fake wall time overflow");
        });
    }

    /// Model a wall-clock correction without affecting monotonic deadlines.
    pub fn set_wall(&self, wall: jiff::Timestamp) {
        self.time.send_modify(|(_, current)| *current = wall);
    }

    /// Inherent access also works in etd-proc's own unit tests, where Cargo
    /// links the testkit against the non-test copy of the Clock trait.
    pub fn now(&self) -> Instant {
        self.origin + self.time.borrow().0
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        FakeClock::now(self)
    }

    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        let mut rx = self.time.subscribe();
        let deadline = rx.borrow().0 + d;
        // Retain a sender: sleeps remain pending even if the clock is dropped.
        let clock = self.clone();
        Box::pin(async move {
            let _clock = clock;
            let _ = rx.wait_for(|(elapsed, _)| *elapsed >= deadline).await;
        })
    }

    fn wall_now(&self) -> jiff::Timestamp {
        self.time.borrow().1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    #[tokio::test]
    async fn controls_waiters_and_wall_independently() {
        let clock = FakeClock::default();
        let start = clock.now();
        let mut sleep = clock.sleep(Duration::from_secs(2));
        clock.advance(Duration::from_secs(1));
        assert!((&mut sleep).now_or_never().is_none());
        assert_eq!(clock.now() - start, Duration::from_secs(1));
        assert_eq!(clock.wall_now().as_second(), 1);
        clock.set_wall(jiff::Timestamp::UNIX_EPOCH);
        assert!((&mut sleep).now_or_never().is_none());
        clock.advance(Duration::from_secs(1));
        sleep.await;
        assert_eq!(clock.wall_now().as_second(), 1);
    }
}
