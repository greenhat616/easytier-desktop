use etd_contract::NetworkSpec;
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("profile store not implemented")]
    NotImplemented,
}
pub trait ProfileStore: Send + Sync {
    fn load(&self) -> Result<Vec<NetworkSpec>, ProfileError>;
    fn save(&self, profiles: &[NetworkSpec]) -> Result<(), ProfileError>;
}
