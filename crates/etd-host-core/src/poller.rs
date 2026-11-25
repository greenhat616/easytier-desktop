//! Kernel polling: about 1 s with subscribers, 30 s health checks without.
//! Owned by H1.
//!
//! EasyTier has no streaming RPC, so the host polls the management session
//! of every fully ready instance and turns what changed into contract
//! events; clients get a real push stream. The supervisor calls
//! [`poll_round`] whenever [`Poller::due`] says so and re-arms it with the
//! current [`crate::api::ClientPresence`].
use crate::api::ClientPresence;
use etd_core_api::{CoreError, CoreEvent, CoreEventCursor, CoreSession};
use std::time::{Duration, Instant};

/// Poll period while at least one client subscribes to events.
pub const SUBSCRIBED_INTERVAL: Duration = Duration::from_secs(1);
/// Health-check period without subscribers.
pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

pub fn interval(presence: &ClientPresence) -> Duration {
    if presence.subscribers > 0 {
        SUBSCRIBED_INTERVAL
    } else {
        HEALTH_CHECK_INTERVAL
    }
}

/// Next poll deadline of one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poller {
    next: Instant,
    period: Duration,
}

impl Poller {
    /// First round one period after the session became ready.
    pub fn new(now: Instant, presence: &ClientPresence) -> Self {
        let period = interval(presence);
        Self {
            next: now + period,
            period,
        }
    }

    pub fn deadline(&self) -> Instant {
        self.next
    }

    pub fn due(&self, now: Instant) -> bool {
        now >= self.next
    }

    /// After a round.
    pub fn rearm(&mut self, now: Instant, presence: &ClientPresence) {
        self.period = interval(presence);
        self.next = now + self.period;
    }

    /// Presence changed: a new subscriber is served within one second, a
    /// departing one stretches the period from the last round.
    pub fn presence_changed(&mut self, now: Instant, presence: &ClientPresence) {
        let period = interval(presence);
        if period == self.period {
            return;
        }
        let last = self.next.checked_sub(self.period).unwrap_or(now);
        self.period = period;
        self.next = (last + period).max(now);
    }
}

/// One round: kernel events after `cursor`. With subscribers this is the
/// event feed; without, its success is the health check.
pub async fn poll_round(
    session: &dyn CoreSession,
    cursor: Option<CoreEventCursor>,
) -> Result<(Vec<CoreEvent>, Option<CoreEventCursor>), CoreError> {
    let events = session.poll_events(cursor).await?;
    let next = events.iter().map(|e| e.cursor).max().or(cursor);
    Ok((events, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presence(subscribers: usize) -> ClientPresence {
        ClientPresence {
            connections: subscribers,
            subscribers,
            lease_holders: 0,
        }
    }

    #[test]
    fn interval_follows_subscribers() {
        assert_eq!(interval(&presence(0)), HEALTH_CHECK_INTERVAL);
        assert_eq!(interval(&presence(2)), SUBSCRIBED_INTERVAL);
    }

    #[test]
    fn new_subscriber_shortens_the_wait() {
        let t0 = Instant::now();
        let mut p = Poller::new(t0, &presence(0));
        assert_eq!(p.deadline(), t0 + HEALTH_CHECK_INTERVAL);
        p.presence_changed(t0 + Duration::from_secs(10), &presence(1));
        // Last round was at t0; one second later is already past: poll now.
        assert_eq!(p.deadline(), t0 + Duration::from_secs(10));
        p.rearm(t0 + Duration::from_secs(10), &presence(1));
        assert_eq!(p.deadline(), t0 + Duration::from_secs(11));
        p.presence_changed(t0 + Duration::from_millis(10_500), &presence(0));
        assert_eq!(p.deadline(), t0 + Duration::from_secs(40));
        assert!(!p.due(t0 + Duration::from_secs(39)));
        assert!(p.due(t0 + Duration::from_secs(40)));
    }
}
