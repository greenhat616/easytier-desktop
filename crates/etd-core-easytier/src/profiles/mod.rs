//! Adapter profiles (first: 2.7.1-c97f36b). Owned by E1.
use etd_core_api::{AdapterProfile, CoreDescriptor};

pub fn profile_for(_core: &CoreDescriptor) -> Option<AdapterProfile> {
    None
}
