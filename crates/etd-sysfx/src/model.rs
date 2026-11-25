use etd_contract::{DesiredInstance, RequestId};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectId(pub String);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootId(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectKind {
    Interface,
    Route,
    Firewall,
    Dns,
    File,
    Fence,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectState {
    Planned,
    Applied,
    Reclaiming,
    Reclaimed,
    Quarantined,
    Candidate,
}
#[derive(Debug, Clone)]
pub struct Observation {
    pub identity: String,
}
#[derive(Debug, Clone)]
pub struct Effect {
    pub id: EffectId,
    pub kind: EffectKind,
    pub state: EffectState,
    pub boot: BootId,
    pub observation: Option<Observation>,
    pub recorded_at: jiff::Timestamp,
}
#[derive(Debug, Clone)]
pub struct ChangeSet {
    pub request_id: RequestId,
    pub desired: Vec<DesiredInstance>,
    pub effects: Vec<Effect>,
}
#[derive(Debug, Clone, Default)]
pub struct ScopeFilter;
#[derive(Debug, Clone)]
pub struct FoundObject {
    pub kind: EffectKind,
    pub observation: Observation,
}
#[derive(Debug, Clone)]
pub enum Probe {
    Present(Observation),
    Absent,
    Indeterminate,
}
#[derive(Debug, Clone)]
pub struct Reclaimed;
