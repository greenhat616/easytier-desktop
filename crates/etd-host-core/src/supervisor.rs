use crate::{auth::Authorizer, core_store::CoreStore};
use etd_core_api::CoreDriver;
use etd_proc::{Clock, ProcessEngine};
use etd_sysfx::{BootIdSource, Ledger, Reclaimer, Sweeper};
use std::sync::Arc;

/// Dependencies are supplied by composition roots or tests.
pub struct HostServices {
    pub process: Arc<dyn ProcessEngine>,
    pub ledger: Arc<dyn Ledger>,
    pub reclaimers: Vec<Arc<dyn Reclaimer>>,
    pub sweeper: Arc<dyn Sweeper>,
    pub boot_id: Arc<dyn BootIdSource>,
    pub core: Arc<dyn CoreDriver>,
    pub clock: Arc<dyn Clock>,
    pub authorizer: Arc<dyn Authorizer>,
    pub core_store: Arc<dyn CoreStore>,
}
pub struct HostSupervisor {
    pub services: HostServices,
}
