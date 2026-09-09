//! Reconciler rounds and a caller-owned async loop from spec 00 §3.2.
//!
//! Desired rows and reconciliation status are separate. Revision checks reject
//! stale results, and status reads synthesize Pending for newer desired rows.
//! The caller owns the `run` future and its shutdown signal; no task is spawned.
//! Atomic table write hooks, annotations, batch targets, health
//! reporting and asynchronous completion waiters remain integration work.
//! Prune runs only after table initialization and clears a resync request only
//! on success. Incremental updates alone cannot remove unknown target entries
//! after deletion history has been discarded.
use flowsdn_table::{Change, ChangeStream, Key, Keyed, Revision, Snapshot, Table};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

mod refresh;
use refresh::RefreshState;
mod prune;
mod run;
use prune::PruneState;
pub use prune::{PruneHandle, PruneStatus};

/// Whether an update follows a desired change or requests a forced rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateHint { Changed, Refresh }

/// Operations must be idempotent: cancelling a round may replay its in-flight
/// operation, including one whose target side effect already occurred.
pub trait Target<T: Keyed>: Send {
    type Error: fmt::Display;
    fn update(&mut self, row: Arc<T>) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Refresh asks the target to force a rewrite even if it believes the row
    /// unchanged. Existing targets default to repeating their idempotent update;
    /// targets that skip unchanged values should override and honor the hint.
    fn update_with_hint(&mut self, row: Arc<T>, _hint: UpdateHint) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.update(row)
    }
    fn delete(&mut self, key: Key) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Remove target objects absent from this immutable desired snapshot.
    /// It is called only after the table has completed initialization.
    fn prune(
        &mut self,
        desired: Snapshot<T>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub round_size: usize,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub prune_interval: Duration,
    /// Minimum gap between loop rounds; `run_round` itself remains unthrottled.
    pub round_interval: Duration,
    /// Zero disables refresh.
    pub refresh_interval: Duration,
    /// Maximum newly scheduled refresh rows per second; no burst credit.
    pub refresh_rate: u32,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            round_size: 1000,
            min_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(60),
            prune_interval: Duration::from_secs(3600),
            round_interval: Duration::from_millis(1),
            refresh_interval: Duration::from_secs(1800),
            refresh_rate: 100,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileError {
    EmptyRound,
    InvalidBackoff,
    RetryDeadlineOverflow,
    InvalidPruneInterval,
    PruneDeadlineOverflow,
    InvalidRoundInterval,
    RoundDeadlineOverflow,
    InvalidRefreshRate,
    RefreshDeadlineOverflow,
}
impl fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyRound => "round size must be positive",
            Self::InvalidBackoff => "backoff must be positive and minimum must not exceed maximum",
            Self::RetryDeadlineOverflow => "retry deadline exceeds the monotonic clock range",
            Self::InvalidPruneInterval => "prune interval must be positive",
            Self::PruneDeadlineOverflow => "prune deadline exceeds the monotonic clock range",
            Self::InvalidRoundInterval => "round interval must be positive",
            Self::RoundDeadlineOverflow => "round deadline exceeds the monotonic clock range",
            Self::InvalidRefreshRate => "refresh rate must be positive when refresh is enabled",
            Self::RefreshDeadlineOverflow => "refresh deadline exceeds the monotonic clock range",
        })
    }
}
impl Error for ReconcileError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Pending,
    Refreshing,
    Done,
    Error,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Update,
    Delete,
}

#[derive(Clone, Debug)]
pub struct Status {
    pub kind: Kind,
    /// Desired revision acts as the pending generation token in this slice.
    pub id: Revision,
    pub operation: Operation,
    /// None for a desired write not observed by a round yet.
    pub updated_at: Option<Instant>,
    pub error: Option<String>,
    pub retries: u32,
    pub next_retry: Option<Instant>,
}
impl Status {
    fn pending(revision: Revision, operation: Operation) -> Self {
        Self {
            kind: Kind::Pending,
            id: revision,
            operation,
            updated_at: None,
            error: None,
            retries: 0,
            next_retry: None,
        }
    }
}

#[derive(Clone)]
struct Retry {
    key: Key,
    revision: Revision,
    operation: Operation,
    failures: u32,
    deadline: Instant,
    refresh: bool,
}
#[derive(Default)]
struct RetryQueue {
    entries: BTreeMap<Key, Retry>,
    deadlines: BTreeSet<(Instant, Key)>,
    revisions: BTreeSet<(Revision, Key)>,
}
impl RetryQueue {
    fn remove(&mut self, key: &[u8]) -> Option<Retry> {
        let old = self.entries.remove(key)?;
        self.deadlines.remove(&(old.deadline, old.key.clone()));
        self.revisions.remove(&(old.revision, old.key.clone()));
        Some(old)
    }
    fn insert(&mut self, retry: Retry) {
        self.remove(&retry.key);
        self.deadlines.insert((retry.deadline, retry.key.clone()));
        self.revisions.insert((retry.revision, retry.key.clone()));
        self.entries.insert(retry.key.clone(), retry);
    }
    fn due(&mut self, now: Instant) -> Option<Retry> {
        let (deadline, key) = self.deadlines.first()?;
        if *deadline > now {
            return None;
        }
        let key = key.clone();
        self.remove(&key)
    }
}

#[derive(Clone)]
struct Work<T> {
    key: Key,
    revision: Revision,
    row: Option<Arc<T>>,
    failures: u32,
    refresh: bool,
}
impl<T> Work<T> {
    fn operation(&self) -> Operation {
        if self.row.is_some() {
            Operation::Update
        } else {
            Operation::Delete
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Round {
    pub processed: usize,
    pub updated: usize,
    pub refreshed: usize,
    pub deleted: usize,
    pub stale: usize,
    pub attempted_revision: Revision,
    pub remaining_retries: usize,
    pub resync_required: bool,
    pub prune: Option<PruneStatus>,
}

/// Owns a separate status store and retry indexes for one target. Multiple
/// instances can consume one desired table without writing status into its rows.
pub struct Reconciler<'a, T: Keyed, U: Target<T>> {
    table: &'a Table<T>,
    stream: ChangeStream<'a, T>,
    target: U,
    options: Options,
    statuses: BTreeMap<Key, Status>,
    retries: RetryQueue,
    pending: VecDeque<Work<T>>,
    attempted_revision: Revision,
    resync_required: bool,
    prune: PruneState,
    refresh: RefreshState<T>,
}
impl<'a, T: Keyed, U: Target<T>> Reconciler<'a, T, U> {
    pub fn new(table: &'a Table<T>, target: U, options: Options) -> Result<Self, ReconcileError> {
        if options.round_size == 0 {
            return Err(ReconcileError::EmptyRound);
        }
        if options.min_backoff.is_zero() || options.min_backoff > options.max_backoff {
            return Err(ReconcileError::InvalidBackoff);
        }
        if options.prune_interval.is_zero() {
            return Err(ReconcileError::InvalidPruneInterval);
        }
        if options.round_interval.is_zero() {
            return Err(ReconcileError::InvalidRoundInterval);
        }
        if !options.refresh_interval.is_zero() && options.refresh_rate == 0 {
            return Err(ReconcileError::InvalidRefreshRate);
        }
        Ok(Self {
            table,
            stream: table.watch(0),
            target,
            options,
            statuses: BTreeMap::new(),
            retries: RetryQueue::default(),
            pending: VecDeque::new(),
            attempted_revision: 0,
            resync_required: false,
            prune: PruneState::default(),
            refresh: RefreshState::default(),
        })
    }

    pub fn target(&self) -> &U {
        &self.target
    }
    /// Immediate queued work, including an initialized table awaiting its
    /// first prune. Time-based deadlines are exposed separately.
    pub fn has_pending_work(&self) -> bool {
        !self.pending.is_empty()
            || self.prune.in_flight
            || (self.table.initialized()
                && (self.prune.handle.requested() || self.prune.next_due.is_none()))
    }

    /// For a present row, status matches the desired snapshot revision. This
    /// avoids exposing old Done/Error before its next stream drain.
    ///
    /// For an absent row, a retained delete error is diagnostic only: snapshots
    /// do not expose deletion generations. It can describe an earlier delete
    /// until the next round observes a newer delete or reinsert-delete sequence.
    /// Successful deletion removes this diagnostic; it is not a readiness proof.
    pub fn status(&self, key: &[u8]) -> Option<Status> {
        if let Some((_, revision)) = self
            .table
            .snapshot()
            .get("primary", key)
            .expect("primary index exists")
        {
            Some(
                self.statuses
                    .get(key)
                    .filter(|status| status.id == revision && status.operation == Operation::Update)
                    .cloned()
                    .unwrap_or_else(|| Status::pending(revision, Operation::Update)),
            )
        } else {
            self.statuses
                .get(key)
                .filter(|status| status.operation == Operation::Delete)
                .cloned()
        }
    }

    pub fn attempted_revision(&self) -> Revision {
        self.attempted_revision
    }
    pub fn resync_required(&self) -> bool {
        self.resync_required
    }
    /// Request an additional prune. Calls before initialization remain pending.
    pub fn prune_now(&self) {
        self.prune.handle.prune_now();
    }
    pub fn prune_handle(&self) -> PruneHandle {
        self.prune.handle.clone()
    }
    pub fn prune_status(&self) -> Option<&PruneStatus> {
        self.prune.status.as_ref()
    }
    /// Periodic deadline after the last completed attempt. Before the first
    /// attempt, initialization itself makes prune due. Explicit requests and
    /// cancelled attempts can make work due before this deadline.
    pub fn next_prune(&self) -> Option<Instant> {
        self.prune.next_due
    }
    pub fn next_retry(&self) -> Option<Instant> {
        self.retries
            .deadlines
            .first()
            .map(|(deadline, _)| *deadline)
    }
    pub fn retry_low_water_mark(&self) -> Option<Revision> {
        self.retries
            .revisions
            .first()
            .map(|(revision, _)| *revision)
            .into_iter()
            .chain(
                self.pending
                    .iter()
                    .filter(|work| work.failures > 0)
                    .map(|work| work.revision),
            )
            .min()
    }

    fn current(&self, work: &Work<T>) -> bool {
        match self
            .table
            .snapshot()
            .get("primary", &work.key)
            .expect("primary index exists")
        {
            Some((_, revision)) => work.row.is_some() && revision == work.revision,
            None => work.row.is_none(),
        }
    }

    fn backoff(&self, failures: u32) -> Duration {
        let mut delay = self.options.min_backoff;
        for _ in 0..failures {
            delay = delay.saturating_mul(2).min(self.options.max_backoff);
            if delay == self.options.max_backoff {
                break;
            }
        }
        delay
    }

    fn load_changes(&mut self) {
        let changes = self.stream.drain(self.options.round_size);
        self.enqueue_changes(changes);
    }

    fn enqueue_changes(&mut self, changes: impl IntoIterator<Item = Change<T>>) {
        let mut pending = Vec::new();
        for change in changes {
            match change {
                Change::Resync { .. } => {
                    self.resync_required = true;
                    self.prune.handle.prune_now();
                    self.retries = RetryQueue::default();
                    self.statuses.clear();
                    self.refresh.reset_pass();
                }
                Change::Insert { row, revision } => {
                    let key = row.primary_key();
                    self.retries.remove(&key);
                    pending.push(Work {
                        key,
                        revision,
                        row: Some(row),
                        failures: 0,
                        refresh: false,
                    });
                }
                Change::Delete { key, revision } => {
                    self.retries.remove(&key);
                    pending.push(Work {
                        key,
                        revision,
                        row: None,
                        failures: 0,
                        refresh: false,
                    });
                }
            }
        }
        // Preserve revision order within each operation group, deletes first.
        pending.sort_by_key(|work| work.row.is_some());
        self.pending.extend(pending);
    }

    async fn run_prune(
        &mut self,
        clock: &impl Fn() -> Instant,
    ) -> Result<Option<PruneStatus>, ReconcileError> {
        let now = clock();
        if !self.table.initialized() {
            return Ok(None);
        }
        if !self.prune.in_flight
            && !self.prune.handle.requested()
            && self.prune.next_due.is_some_and(|deadline| deadline > now)
        {
            return Ok(None);
        }
        // Retain in_flight across cancellation, so an interrupted target side
        // effect is replayed. Consume requests before awaiting: a request made
        // during this call must survive for the following round.
        self.prune.in_flight = true;
        self.prune.handle.take();
        let desired = self.table.snapshot();
        let revision = desired.revision();
        let result = self.target.prune(desired).await;
        let now = clock();
        let next_due = now
            .checked_add(self.options.prune_interval)
            .ok_or(ReconcileError::PruneDeadlineOverflow)?;
        let status = PruneStatus {
            revision,
            updated_at: now,
            error: result.err().map(|error| error.to_string()),
        };
        self.prune.in_flight = false;
        self.prune.next_due = Some(next_due);
        if status.error.is_none() {
            self.resync_required = false;
        }
        self.prune.status = Some(status.clone());
        Ok(Some(status))
    }

    /// Execute one bounded round using a caller-supplied monotonic scheduling
    /// instant. Prune is initialization-gated; the caller owns any additional
    /// startup gating for incremental writes, timers and repeat scheduling.
    /// Work stays queued across cancellation until its result is recorded.
    pub async fn run_round(&mut self, now: Instant) -> Result<Round, ReconcileError> {
        self.run_round_with_clock(|| now).await
    }

    async fn run_round_with_clock(
        &mut self,
        clock: impl Fn() -> Instant,
    ) -> Result<Round, ReconcileError> {
        self.arm_refresh(clock())?;
        let mut round = Round::default();
        if self.pending.is_empty() {
            self.load_changes();
        }
        while round.processed < self.options.round_size {
            if self.pending.is_empty() {
                if let Some(retry) = self.retries.due(clock()) {
                let row = self
                    .table
                    .snapshot()
                    .get("primary", &retry.key)
                    .expect("primary index exists")
                    .map(|(row, _)| row);
                // Preserve the failed operation; a recreated row must never be
                // deleted by an old delete retry.
                let row = if retry.operation == Operation::Update {
                    row
                } else {
                    None
                };
                let work = Work {
                    key: retry.key,
                    revision: retry.revision,
                    row,
                    failures: retry.failures,
                    refresh: retry.refresh,
                };
                if retry.operation == Operation::Update && work.row.is_none() {
                    self.statuses.remove(&work.key);
                    round.stale = round.stale.saturating_add(1);
                    round.processed = round.processed.saturating_add(1);
                    continue;
                }
                self.pending.push_back(work);
                } else if let Some(work) = self.next_refresh_work(clock())? {
                    self.pending.push_back(work);
                } else { break; }
            }
            let work = self
                .pending
                .front()
                .expect("pending work was filled")
                .clone();
            round.processed = round.processed.saturating_add(1);
            if !self.current(&work) {
                self.statuses.remove(&work.key);
                self.pending.pop_front();
                round.stale = round.stale.saturating_add(1);
                continue;
            }
            let mut pending = Status::pending(work.revision, work.operation());
            pending.retries = work.failures;
            if work.refresh { pending.kind = Kind::Refreshing; }
            self.statuses.insert(work.key.clone(), pending);
            let result = match &work.row {
                Some(row) => self.target.update_with_hint(row.clone(), if work.refresh { UpdateHint::Refresh } else { UpdateHint::Changed }).await,
                None => self.target.delete(work.key.clone()).await,
            };
            if !self.current(&work) {
                self.statuses.remove(&work.key);
                self.pending.pop_front();
                round.stale = round.stale.saturating_add(1);
                continue;
            }
            let now = clock();
            let mut status = Status::pending(work.revision, work.operation());
            status.updated_at = Some(now);
            match result {
                Ok(()) => {
                    status.kind = Kind::Done;
                    self.retries.remove(&work.key);
                    if work.row.is_some() {
                        round.updated = round.updated.saturating_add(1);
                        if work.refresh { round.refreshed = round.refreshed.saturating_add(1); }
                    } else {
                        round.deleted = round.deleted.saturating_add(1);
                    }
                }
                Err(error) => {
                    let failures = work.failures.saturating_add(1);
                    let deadline = now
                        .checked_add(self.backoff(failures))
                        .ok_or(ReconcileError::RetryDeadlineOverflow)?;
                    status.kind = Kind::Error;
                    status.error = Some(error.to_string());
                    status.retries = failures;
                    status.next_retry = Some(deadline);
                    self.retries.insert(Retry {
                        key: work.key.clone(),
                        revision: work.revision,
                        operation: work.operation(),
                        failures,
                        deadline,
                        refresh: work.refresh,
                    });
                }
            }
            if work.row.is_none() && status.kind == Kind::Done {
                self.statuses.remove(&work.key);
            } else {
                self.statuses.insert(work.key, status);
            }
            self.pending.pop_front();
        }
        if self.pending.is_empty() {
            self.attempted_revision = self.stream.revision();
            self.stream.ack(self.attempted_revision);
        }
        round.prune = self.run_prune(&clock).await?;
        round.attempted_revision = self.attempted_revision;
        round.remaining_retries = self.retries.entries.len();
        round.resync_required = self.resync_required;
        Ok(round)
    }
}
