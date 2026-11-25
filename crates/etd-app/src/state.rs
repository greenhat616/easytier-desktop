//! State store fed by snapshots and the event stream. Owned by A1.
use etd_contract::HostSnapshot;

#[derive(Debug, Default, Clone)]
pub struct StateStore {
    pub snapshot: Option<HostSnapshot>,
}

/// UI-independent dependencies of the background application runtime.
pub struct AppServices {
    pub host: std::sync::Arc<dyn etd_client::HostClient>,
    pub launcher: std::sync::Arc<dyn crate::HostLauncher>,
    pub profiles: std::sync::Arc<dyn crate::ProfileStore>,
}
