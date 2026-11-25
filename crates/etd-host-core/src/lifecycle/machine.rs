//! The instance state machine as data: every edge the supervisor may take.
//!
//! The supervisor (`crate::supervisor`) moves an instance only along these
//! edges ([`allowed`]); an edge missing here is a bug and is refused (logged,
//! state left unchanged). Keeping the table pure makes "every edge has a
//! test" checkable: the unit tests below walk [`EDGES`] and the lifecycle
//! integration tests drive each path through the fakes.
//!
//! Invariants the table encodes (doc#2 v7, "生命周期"):
//! - every process exit passes through `Reclaiming`; the only ways out of a
//!   live state are `Stopping`, `Reclaiming` and `CutUnconfirmed`;
//! - a new generation (`Starting`) is reached only from states whose last
//!   generation is closed (`Stopped`, `Reclaiming` once closed, `Backoff`,
//!   `GaveUp`, `Waiting`, `CutUnconfirmed` without an open generation);
//! - `Quarantined` is left only through `Reclaiming` (retry or a resolved
//!   candidate), never straight to a start.
use etd_contract::InstanceState;

use InstanceState as S;

/// Every allowed `(from, to)` pair. `Unspecified` is the state of a
/// supervisor that has not published yet (fresh instance or host start).
pub const EDGES: &[(InstanceState, InstanceState)] = &[
    // Host start / new instance.
    (S::Unspecified, S::Stopped),
    (S::Unspecified, S::Starting),
    (S::Unspecified, S::Reclaiming),
    (S::Unspecified, S::Quarantined),
    (S::Unspecified, S::Waiting),
    (S::Unspecified, S::GaveUp),
    (S::Unspecified, S::Backoff),
    (S::Unspecified, S::CutUnconfirmed),
    // Stopped: desired running starts; a superseded or leftover generation
    // is reclaimed first; a start may be refused or deferred.
    (S::Stopped, S::Starting),
    (S::Stopped, S::Reclaiming),
    (S::Stopped, S::Waiting),
    (S::Stopped, S::Backoff),
    (S::Stopped, S::GaveUp),
    (S::Stopped, S::CutUnconfirmed),
    // Starting: fence, spawn, enumeration, basic readiness.
    (S::Starting, S::ReadyBasic),
    (S::Starting, S::Stopping),
    (S::Starting, S::Reclaiming),
    (S::Starting, S::CutUnconfirmed),
    // Basic readiness: process alive long enough, interface observed.
    (S::ReadyBasic, S::ReadyFull),
    (S::ReadyBasic, S::Stopping),
    (S::ReadyBasic, S::Reclaiming),
    (S::ReadyBasic, S::CutUnconfirmed),
    // Full readiness: management session answered.
    (S::ReadyFull, S::ReadyBasic),
    (S::ReadyFull, S::Stopping),
    (S::ReadyFull, S::Reclaiming),
    (S::ReadyFull, S::CutUnconfirmed),
    // Stopping: graceful stop, tree kill on timeout.
    (S::Stopping, S::Reclaiming),
    (S::Stopping, S::CutUnconfirmed),
    // Reclaiming: the generation is closed, pending or quarantined.
    (S::Reclaiming, S::Stopped),
    (S::Reclaiming, S::Starting),
    (S::Reclaiming, S::Backoff),
    (S::Reclaiming, S::GaveUp),
    (S::Reclaiming, S::Quarantined),
    (S::Reclaiming, S::Waiting),
    (S::Reclaiming, S::CutUnconfirmed),
    // Backoff: restart delay.
    (S::Backoff, S::Starting),
    (S::Backoff, S::Stopped),
    (S::Backoff, S::Waiting),
    (S::Backoff, S::GaveUp),
    (S::Backoff, S::Reclaiming),
    (S::Backoff, S::CutUnconfirmed),
    // Gave up: only RetryStart (or a stop) moves it.
    (S::GaveUp, S::Starting),
    (S::GaveUp, S::Stopped),
    (S::GaveUp, S::Waiting),
    (S::GaveUp, S::Reclaiming),
    (S::GaveUp, S::CutUnconfirmed),
    // Quarantined: only a reclaim retry leaves it.
    (S::Quarantined, S::Reclaiming),
    // Cut, unconfirmed: a committed desired state (or retry) reclaims.
    (S::CutUnconfirmed, S::Reclaiming),
    (S::CutUnconfirmed, S::Stopped),
    (S::CutUnconfirmed, S::Starting),
    (S::CutUnconfirmed, S::Waiting),
    // Waiting for a single-writer claim.
    (S::Waiting, S::Starting),
    (S::Waiting, S::Stopped),
    (S::Waiting, S::Reclaiming),
    (S::Waiting, S::Backoff),
    (S::Waiting, S::GaveUp),
    (S::Waiting, S::CutUnconfirmed),
];

/// Whether the supervisor may move an instance from `from` to `to`.
/// Staying in the same state (a new message or epoch) is always allowed.
pub fn allowed(from: InstanceState, to: InstanceState) -> bool {
    from == to || EDGES.contains(&(from, to))
}

/// States in which the instance has a live kernel process.
pub fn is_live(state: InstanceState) -> bool {
    matches!(
        state,
        S::Starting | S::ReadyBasic | S::ReadyFull | S::Stopping
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [InstanceState; 12] = [
        S::Unspecified,
        S::Stopped,
        S::Starting,
        S::ReadyBasic,
        S::ReadyFull,
        S::Stopping,
        S::Reclaiming,
        S::Backoff,
        S::GaveUp,
        S::Quarantined,
        S::CutUnconfirmed,
        S::Waiting,
    ];

    #[test]
    fn edges_are_unique_and_never_return_to_unspecified() {
        for (i, edge) in EDGES.iter().enumerate() {
            assert!(!EDGES[i + 1..].contains(edge), "duplicate edge {edge:?}");
            assert_ne!(edge.1, S::Unspecified);
            assert_ne!(edge.0, edge.1);
        }
    }

    #[test]
    fn every_listed_edge_is_allowed_and_nothing_else() {
        for from in ALL {
            for to in ALL {
                assert_eq!(
                    allowed(from, to),
                    from == to || EDGES.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn live_states_leave_only_through_stop_reclaim_or_cut() {
        for &(from, to) in EDGES {
            if is_live(from) && !is_live(to) {
                assert!(
                    matches!(to, S::Reclaiming | S::CutUnconfirmed),
                    "{from:?} -> {to:?} skips reclaim"
                );
            }
        }
    }

    #[test]
    fn a_process_exit_always_reclaims_before_anything_else() {
        // From a live state the only non-live successors are Reclaiming and
        // CutUnconfirmed; CutUnconfirmed in turn only leaves via Reclaiming
        // or (when no generation is open) Stopped / Starting / Waiting.
        for &(from, to) in EDGES {
            if from == S::Stopping {
                assert!(matches!(to, S::Reclaiming | S::CutUnconfirmed));
            }
        }
    }

    #[test]
    fn quarantine_is_left_only_through_reclaim() {
        let outs: Vec<_> = EDGES
            .iter()
            .filter(|(f, _)| *f == S::Quarantined)
            .map(|(_, t)| *t)
            .collect();
        assert_eq!(outs, vec![S::Reclaiming]);
    }

    #[test]
    fn starting_is_reached_only_from_closed_generations() {
        for &(from, to) in EDGES {
            if to == S::Starting {
                assert!(
                    matches!(
                        from,
                        S::Unspecified
                            | S::Stopped
                            | S::Reclaiming
                            | S::Backoff
                            | S::GaveUp
                            | S::Waiting
                            | S::CutUnconfirmed
                    ),
                    "{from:?} -> Starting"
                );
                assert!(!is_live(from));
            }
        }
    }

    #[test]
    fn forbidden_shortcuts() {
        // Never restart without reclaiming, never leave quarantine directly.
        assert!(!allowed(S::ReadyFull, S::Starting));
        assert!(!allowed(S::ReadyBasic, S::Backoff));
        assert!(!allowed(S::Stopping, S::Stopped));
        assert!(!allowed(S::Quarantined, S::Starting));
        assert!(!allowed(S::Quarantined, S::Stopped));
        assert!(!allowed(S::Starting, S::Stopped));
        assert!(!allowed(S::Reclaiming, S::ReadyBasic));
    }
}
