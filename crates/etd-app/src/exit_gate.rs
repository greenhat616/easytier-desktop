//! Exit gate: every exit path funnels here, fixed order: settle instances
//! (disconnect or release lease) -> stop subscriptions -> stop tokio -> quit
//! gpui. Owned by A1.
pub struct ExitGate;
