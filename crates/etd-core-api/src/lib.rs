//! Kernel-independent adapter API (frozen, F0). Never exposes EasyTier
//! types; the only implementation is etd-core-easytier.
mod driver;
mod model;
pub use driver::*;
pub use model::*;
