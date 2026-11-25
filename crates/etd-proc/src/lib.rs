//! Process lifecycle abstractions and the ProcessKit adapter.
//!
//! Frozen interfaces (F0): `engine`, `model`, `restart`. The rest is owned by
//! P1.
mod engine;
mod model;
mod restart;
pub use engine::*;
pub use model::*;
pub use restart::*;

pub mod backoff;
pub mod console_ctrl;
pub mod identity;
pub mod parent_death;
pub mod processkit_engine;
