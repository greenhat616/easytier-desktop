use etd_contract::{HostMode, HostSnapshot};

#[derive(Debug, Default, Clone)]
pub struct StateStore {
    pub snapshot: Option<HostSnapshot>,
}
#[derive(Debug, Clone)]
pub enum UserCommand {
    Refresh,
    Connect(HostMode),
    Exit,
}
pub struct AppBridge {
    pub commands: async_channel::Sender<UserCommand>,
    pub states: async_channel::Receiver<StateStore>,
}
pub struct ExitGate;

/// UI-independent dependencies for a future background application runtime.
pub struct AppServices {
    pub host: std::sync::Arc<dyn etd_client::HostClient>,
    pub launcher: std::sync::Arc<dyn crate::HostLauncher>,
    pub profiles: std::sync::Arc<dyn crate::ProfileStore>,
}
