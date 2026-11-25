//! SQLite ledger: a dedicated blocking single-writer thread owns the only
//! connection, with WAL + synchronous=FULL (macOS fullfsync). Every mutation
//! is staged and published only after its transaction has committed.
mod codec;
mod state;
mod storage;

use crate::*;
use async_trait::async_trait;
use etd_contract::{DesiredInstance, InstanceId, Receipt, RequestId, Revision};
use rusqlite::Connection;
#[doc(hidden)]
pub use state::LedgerState;
use std::{path::Path, sync::Arc, thread::JoinHandle};
use tokio::sync::{mpsc, oneshot};

/// Observable durability stages, used by crash-recovery tests. The callback
/// runs on the SQLite worker and must not call the ledger recursively.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStage {
    Begin,
    Requests,
    Desired,
    Generations,
    Effects,
    Committed,
}

/// Optional read-only inspection and deterministic storage fault injection.
#[derive(Default)]
pub struct OpenOptions {
    pub read_only: bool,
    pub max_page_count: Option<u32>,
    #[doc(hidden)]
    pub commit_observer: Option<Arc<dyn Fn(CommitStage) + Send + Sync>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerPragmas {
    pub journal_mode: String,
    pub synchronous: i64,
    pub fullfsync: bool,
    pub secure_delete: bool,
}

type Job = Box<dyn FnOnce(&mut Worker) + Send>;

/// Open the ledger once per machine-singleton host. The caller must protect
/// the database directory and supply the current boot id.
pub struct SqliteLedger {
    sender: mpsc::Sender<Job>,
    thread: JoinHandle<()>,
}

struct Worker {
    conn: Connection,
    state: LedgerState,
    boot: BootId,
    options: OpenOptions,
    // A failed transaction never publishes a staged state. If commit failed
    // ambiguously, reload the durable state before accepting the next call.
    reload: bool,
    pending_checkpoint: bool,
}

fn worker_gone() -> LedgerError {
    LedgerError::Unavailable(StorageFault::Io("SQLite worker unavailable".into()))
}

impl Worker {
    fn refresh(&mut self) -> Result<(), LedgerError> {
        if self.reload {
            self.state = storage::reload(&self.conn)?;
            self.pending_checkpoint |= self.state.has_pending_purge();
            self.reload = false;
        }
        // A reader pinning WAL frames must not block unrelated operations.
        // Only the purge's own receipt and completion require success.
        let _ = self.finish_checkpoint();
        Ok(())
    }

    fn finish_checkpoint(&mut self) -> Result<(), LedgerError> {
        if self.pending_checkpoint {
            if self.options.read_only {
                return Err(LedgerError::Unavailable(StorageFault::ReadOnly));
            }
            storage::checkpoint_truncate(&self.conn)?;
            self.pending_checkpoint = false;
        }
        Ok(())
    }

    fn write<T>(
        &mut self,
        f: impl FnOnce(&mut LedgerState, &BootId) -> Result<T, LedgerError>,
    ) -> Result<T, LedgerError> {
        self.refresh()?;
        if self.options.read_only {
            return Err(LedgerError::Unavailable(StorageFault::ReadOnly));
        }
        let mut staged = self.state.clone();
        let value = f(&mut staged, &self.boot)?;
        let observer = |stage| {
            if let Some(callback) = &self.options.commit_observer {
                callback(stage);
            }
        };
        if let Err(error) = storage::persist(&mut self.conn, &self.state, &staged, &observer) {
            self.reload = true;
            return Err(error);
        }
        // A purge's transaction can delete historical credentials from the
        // main database, but older WAL frames must also be removed. A
        // pending purge ticket survives crashes and forces this checkpoint
        // on reopen before its receipt can be returned.
        self.pending_checkpoint |= self.state.has_pending_purge() || staged.has_pending_purge();
        self.state = staged;
        let _ = self.finish_checkpoint();
        Ok(value)
    }
}

impl SqliteLedger {
    pub async fn open(path: impl AsRef<Path>, boot: BootId) -> Result<Self, LedgerError> {
        Self::open_with_options(path, boot, OpenOptions::default()).await
    }

    pub async fn open_with_options(
        path: impl AsRef<Path>,
        boot: BootId,
        options: OpenOptions,
    ) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_owned();
        let (sender, mut receiver) = mpsc::channel::<Job>(64);
        let (ready, opened) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("etd-sqlite-ledger".into())
            .spawn(move || {
                let mut worker = match storage::open(&path, &options) {
                    Ok((conn, state)) => Worker {
                        pending_checkpoint: state.has_pending_purge(),
                        conn,
                        state,
                        boot,
                        options,
                        reload: false,
                    },
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let _ = worker.finish_checkpoint();
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Some(job) = receiver.blocking_recv() {
                    job(&mut worker);
                }
            })
            .map_err(|_| worker_gone())?;
        opened.await.map_err(|_| worker_gone())??;
        Ok(Self { sender, thread })
    }

    async fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Worker) -> Result<T, LedgerError> + Send + 'static,
    ) -> Result<T, LedgerError> {
        let (reply, result) = oneshot::channel();
        self.sender
            .send(Box::new(move |worker| {
                let _ = reply.send(f(worker));
            }))
            .await
            .map_err(|_| worker_gone())?;
        result.await.map_err(|_| worker_gone())?
    }

    async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&LedgerState) -> Result<T, LedgerError> + Send + 'static,
    ) -> Result<T, LedgerError> {
        self.call(move |worker| {
            worker.refresh()?;
            f(&worker.state)
        })
        .await
    }
    async fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut LedgerState, &BootId) -> Result<T, LedgerError> + Send + 'static,
    ) -> Result<T, LedgerError> {
        self.call(move |worker| worker.write(f)).await
    }

    /// Query the actual writer connection, not a second connection whose
    /// synchronous and fullfsync settings may differ.
    pub async fn pragmas(&self) -> Result<LedgerPragmas, LedgerError> {
        self.call(|worker| storage::pragmas(&worker.conn)).await
    }

    /// Optional graceful close; dropping also closes the queue. Awaiting
    /// this guarantees that SQLite has closed its files (useful on Windows).
    pub async fn close(self) -> Result<(), LedgerError> {
        let Self { sender, thread } = self;
        drop(sender);
        tokio::task::spawn_blocking(move || thread.join().map_err(|_| worker_gone()))
            .await
            .map_err(|_| worker_gone())?
    }
}

#[async_trait]
impl Ledger for SqliteLedger {
    async fn commit(&self, expected: Revision, change: ChangeSet) -> Result<Receipt, LedgerError> {
        self.call(move |worker| {
            worker.refresh()?;
            let request_id = change.request.request_id.clone();
            let receipt = match worker.state.request_status(&change.request) {
                RequestStatus::Done(receipt) => Ok(receipt),
                RequestStatus::Reused => Err(LedgerError::RequestReused(change.request.request_id)),
                RequestStatus::New => worker
                    .write(move |s, boot| s.commit(expected, change, boot, jiff::Timestamp::now())),
            }?;
            if worker.state.is_purge_request(&request_id) {
                worker.finish_checkpoint()?;
            }
            Ok(receipt)
        })
        .await
    }
    async fn request_status(&self, request: &RequestRecord) -> Result<RequestStatus, LedgerError> {
        let request = request.clone();
        self.call(move |worker| {
            worker.refresh()?;
            let status = worker.state.request_status(&request);
            if matches!(status, RequestStatus::Done(_))
                && worker.state.is_purge_request(&request.request_id)
            {
                worker.finish_checkpoint()?;
            }
            Ok(status)
        })
        .await
    }
    async fn receipt(&self, request: &RequestId) -> Result<Option<Receipt>, LedgerError> {
        let request = request.clone();
        self.call(move |worker| {
            worker.refresh()?;
            if worker.state.is_purge_request(&request) {
                worker.finish_checkpoint()?;
            }
            Ok(worker.state.receipt(&request))
        })
        .await
    }
    async fn pending_tickets(&self) -> Result<Vec<Ticket>, LedgerError> {
        self.read(move |s| Ok(s.pending_tickets())).await
    }
    async fn complete_ticket(&self, ticket: &str) -> Result<(), LedgerError> {
        let ticket = ticket.to_owned();
        self.call(move |worker| {
            worker.refresh()?;
            if worker.state.is_purge_ticket(&ticket) {
                worker.finish_checkpoint()?;
            }
            worker.write(move |s, _| s.complete_ticket(&ticket))
        })
        .await
    }
    async fn desired(&self) -> Result<(Revision, Vec<DesiredInstance>), LedgerError> {
        self.read(move |s| Ok(s.desired())).await
    }
    async fn spec_revision(&self, instance: &InstanceId) -> Result<Revision, LedgerError> {
        let instance = instance.clone();
        self.read(move |s| s.spec_revision(&instance)).await
    }
    async fn settings(&self) -> Result<HostSettings, LedgerError> {
        self.read(move |s| Ok(s.settings())).await
    }
    async fn claims(&self) -> Result<Vec<ClaimHold>, LedgerError> {
        self.read(move |s| Ok(s.claims())).await
    }
    async fn next_epoch(&self, instance: &InstanceId) -> Result<Epoch, LedgerError> {
        let instance = instance.clone();
        self.read(move |s| s.next_epoch(&instance)).await
    }
    async fn begin_epoch(&self, plan: GenerationPlan) -> Result<Vec<Effect>, LedgerError> {
        self.write(move |s, boot| s.begin_epoch(plan, boot, jiff::Timestamp::now()))
            .await
    }
    async fn generation(
        &self,
        instance: &InstanceId,
        epoch: Epoch,
    ) -> Result<Option<StoredGeneration>, LedgerError> {
        let instance = instance.clone();
        self.read(move |s| Ok(s.generation(&instance, epoch))).await
    }
    async fn record(&self, intent: EffectIntent) -> Result<Effect, LedgerError> {
        self.write(move |s, boot| s.record(intent, boot, jiff::Timestamp::now()))
            .await
    }
    async fn transition(
        &self,
        id: &EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError> {
        let id = id.clone();
        self.write(move |s, _| s.transition(&id, to, obs)).await
    }
    async fn record_failure(&self, id: &EffectId, error: &str) -> Result<u32, LedgerError> {
        let id = id.clone();
        let error = error.to_owned();
        self.write(move |s, _| s.record_failure(&id, &error)).await
    }
    async fn open_effects(&self, filter: &ScopeFilter) -> Result<Vec<Effect>, LedgerError> {
        let filter = filter.clone();
        self.read(move |s| Ok(s.open_effects(&filter))).await
    }
    async fn compact(&self) -> Result<usize, LedgerError> {
        self.write(move |s, _| Ok(s.compact())).await
    }
}
