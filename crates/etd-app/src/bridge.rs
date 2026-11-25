//! Channel bridge between the gpui main thread and the background tokio
//! runtime; no task is shared between executors. Owned by A1.
use etd_contract::HostMode;

#[derive(Debug, Clone)]
pub enum UserCommand {
    Refresh,
    Connect(HostMode),
    Exit,
}

pub struct AppBridge {
    pub commands: async_channel::Sender<UserCommand>,
    pub states: async_channel::Receiver<crate::StateStore>,
}
