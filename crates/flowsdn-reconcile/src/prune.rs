use flowsdn_table::Revision;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// A coalescing request that can be shared with callers while a round runs.
/// It records work only; the caller remains responsible for scheduling a round.
#[derive(Clone, Default)]
pub struct PruneHandle {
    requested: Arc<AtomicBool>,
}
impl PruneHandle {
    /// Multiple requests before the next prune become one operation. Requests
    /// arriving during that operation schedule one further pass.
    pub fn prune_now(&self) {
        self.requested.store(true, Ordering::Release);
    }
    pub(crate) fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
    pub(crate) fn take(&self) {
        let _ = self.requested.swap(false, Ordering::AcqRel);
    }
}

/// The most recently completed prune attempt. Failure is diagnostic and does
/// not enter the per-key retry queue; the interval or a new request retries it.
#[derive(Clone, Debug)]
pub struct PruneStatus {
    pub revision: Revision,
    pub updated_at: Instant,
    pub error: Option<String>,
}

#[derive(Default)]
pub(crate) struct PruneState {
    pub(crate) handle: PruneHandle,
    pub(crate) in_flight: bool,
    pub(crate) next_due: Option<Instant>,
    pub(crate) status: Option<PruneStatus>,
}
