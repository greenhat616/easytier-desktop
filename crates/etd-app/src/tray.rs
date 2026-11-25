#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    Visible,
    Hidden,
    Unavailable,
}
pub trait TrayBackend {
    fn set_state(&mut self, state: TrayState);
}
