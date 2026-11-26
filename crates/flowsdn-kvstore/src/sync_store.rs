//! `SyncStore` (spec 20 §3.4.2): one-way export of local state into the
//! kvstore. A work queue with per-item exponential retry (5 ms → 1000 s) and
//! a global token bucket (10 qps, burst 100), one worker ([`SyncStore::run`]).
//!
//! - [`SyncStore::upsert`] is a no-op when the bytes equal what was last
//!   written, so a resync does not rewrite the world.
//! - Writes are leased unless the store was built without a lease.
//! - [`SyncStore::synced`] (the source's initial list is complete) queues the
//!   synced canary, written once nothing is pending, so it means "everything
//!   from the initial list is in the store".
//! - A lost lease (§3.3.1) re-queues the data keys it held and, for the
//!   canary, the canary, without re-running the completion callbacks.
use crate::{Kvstore, Lease, Result, join, rfc3339};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
use tokio::sync::Notify;
use tokio::time::Instant;

/// A SyncStore's settings.
#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// The data prefix; a name `n` is written at `<prefix>/n`.
    pub prefix: String,
    /// The synced canary's key; None: no canary.
    pub canary: Option<String>,
    /// Bind data writes to the key lease (the canary always is).
    pub leased: bool,
    pub qps: f64,
    pub burst: u32,
    pub retry_min: Duration,
    pub retry_max: Duration,
}
impl SyncConfig {
    /// The reference's settings for `prefix` and `canary`, leased.
    pub fn new(prefix: &str, canary: Option<String>) -> Self {
        Self {
            prefix: prefix.to_owned(),
            canary,
            leased: true,
            qps: 10.0,
            burst: 100,
            retry_min: Duration::from_millis(5),
            retry_max: Duration::from_secs(1000),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Op {
    Put(Vec<u8>),
    Delete,
}

#[derive(Clone, Debug)]
struct Pending {
    op: Op,
    failures: u32,
    ready_at: Instant,
}

/// One-shot completion callbacks.
type Callback = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct Inner {
    /// What is in the store, by name, as this store last wrote it.
    written: BTreeMap<String, Vec<u8>>,
    queue: BTreeMap<String, Pending>,
    /// The canary is due (initial list done, or its lease was lost).
    canary_due: bool,
    canary_failures: u32,
    canary_ready_at: Option<Instant>,
    canary_written: bool,
    callbacks: Vec<Callback>,
    tokens: f64,
    refilled: Option<Instant>,
    closed: bool,
    /// Writes and deletes made, for tests and logs.
    writes: u64,
    errors: u64,
}

/// What [`SyncStore::stats`] reports.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyncStats {
    pub written: usize,
    pub pending: usize,
    pub writes: u64,
    pub errors: u64,
    pub synced: bool,
}

/// The exporter. Clone handles share one queue.
pub struct SyncStore<K: Kvstore> {
    kv: Arc<K>,
    config: SyncConfig,
    inner: Arc<Mutex<Inner>>,
    wake: Arc<Notify>,
}
impl<K: Kvstore> Clone for SyncStore<K> {
    fn clone(&self) -> Self {
        Self {
            kv: Arc::clone(&self.kv),
            config: self.config.clone(),
            inner: Arc::clone(&self.inner),
            wake: Arc::clone(&self.wake),
        }
    }
}

fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<K: Kvstore> SyncStore<K> {
    /// A store over `kv`; registers its lease observers.
    pub fn new(kv: Arc<K>, config: SyncConfig) -> Self {
        let store = Self {
            kv,
            inner: Arc::new(Mutex::new(Inner {
                tokens: f64::from(config.burst),
                ..Inner::default()
            })),
            config,
            wake: Arc::new(Notify::new()),
        };
        if store.config.leased {
            let data = format!("{}/", store.config.prefix);
            let (inner, wake, prefix) = (
                Arc::clone(&store.inner),
                Arc::clone(&store.wake),
                data.clone(),
            );
            store.kv.lease_expired(
                &data,
                Some(Arc::new(move |key: &str| {
                    let name = key.strip_prefix(prefix.as_str()).unwrap_or(key);
                    let mut state = lock(&inner);
                    if let Some(bytes) = state.written.remove(name) {
                        state.queue.entry(name.to_owned()).or_insert(Pending {
                            op: Op::Put(bytes),
                            failures: 0,
                            ready_at: Instant::now(),
                        });
                    }
                    drop(state);
                    wake.notify_one();
                })),
            );
        }
        if let Some(canary) = &store.config.canary {
            let (inner, wake, canary) = (
                Arc::clone(&store.inner),
                Arc::clone(&store.wake),
                canary.clone(),
            );
            store.kv.lease_expired(
                &canary.clone(),
                Some(Arc::new(move |key: &str| {
                    if key == canary {
                        let mut state = lock(&inner);
                        if state.canary_written {
                            state.canary_written = false;
                            state.canary_due = true;
                            state.canary_ready_at = None;
                        }
                        drop(state);
                        wake.notify_one();
                    }
                })),
            );
        }
        store
    }

    fn key(&self, name: &str) -> String {
        join(&[&self.config.prefix, name])
    }

    /// Write `data` at `name`, unless it is what was last written.
    pub fn upsert(&self, name: &str, data: Vec<u8>) {
        let mut state = lock(&self.inner);
        if state.written.get(name) == Some(&data) {
            // Already in the store: whatever is pending for it is moot.
            state.queue.remove(name);
            return;
        }
        state.queue.insert(
            name.to_owned(),
            Pending {
                op: Op::Put(data),
                failures: 0,
                ready_at: Instant::now(),
            },
        );
        drop(state);
        self.wake.notify_one();
    }

    /// Delete `name`, unless this store never wrote it and nothing is pending.
    pub fn delete(&self, name: &str) {
        let mut state = lock(&self.inner);
        if !state.written.contains_key(name) {
            state.queue.remove(name);
            return;
        }
        state.queue.insert(
            name.to_owned(),
            Pending {
                op: Op::Delete,
                failures: 0,
                ready_at: Instant::now(),
            },
        );
        drop(state);
        self.wake.notify_one();
    }

    /// The names this store holds (written, or pending a write).
    pub fn names(&self) -> Vec<String> {
        let state = lock(&self.inner);
        let mut names: Vec<String> = state
            .written
            .keys()
            .filter(|n| state.queue.get(*n).is_none_or(|p| p.op != Op::Delete))
            .cloned()
            .collect();
        for (name, pending) in &state.queue {
            if matches!(pending.op, Op::Put(_)) && !state.written.contains_key(name) {
                names.push(name.clone());
            }
        }
        names.sort();
        names
    }

    /// The source's initial list is complete: write the canary once the
    /// queue is empty, then run `done` (once).
    pub fn synced(&self, done: Option<Callback>) {
        let mut state = lock(&self.inner);
        if let Some(done) = done {
            if state.canary_written || self.config.canary.is_none() && state.queue.is_empty() {
                drop(state);
                done();
                return;
            }
            state.callbacks.push(done);
        }
        if !state.canary_written {
            state.canary_due = true;
        }
        drop(state);
        self.wake.notify_one();
    }

    pub fn stats(&self) -> SyncStats {
        let state = lock(&self.inner);
        SyncStats {
            written: state.written.len(),
            pending: state.queue.len(),
            writes: state.writes,
            errors: state.errors,
            synced: state.canary_written,
        }
    }

    /// Stop [`SyncStore::run`].
    pub fn close(&self) {
        lock(&self.inner).closed = true;
        self.wake.notify_one();
    }

    fn backoff(&self, failures: u32) -> Duration {
        let factor = 2u32.checked_pow(failures.min(20)).unwrap_or(u32::MAX);
        self.config
            .retry_min
            .saturating_mul(factor)
            .min(self.config.retry_max)
    }

    /// Take a token, or say how long until one is there.
    fn token(&self, state: &mut Inner, now: Instant) -> Option<Duration> {
        let last = state.refilled.unwrap_or(now);
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.config.qps).min(f64::from(self.config.burst));
        state.refilled = Some(now);
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            None
        } else if self.config.qps > 0.0 {
            Some(Duration::from_secs_f64(
                (1.0 - state.tokens) / self.config.qps,
            ))
        } else {
            Some(Duration::from_secs(1))
        }
    }

    /// The next job, or how long to wait for one.
    fn next(&self) -> Next {
        let now = Instant::now();
        let mut state = lock(&self.inner);
        if state.closed {
            return Next::Closed;
        }
        let ready = state
            .queue
            .iter()
            .filter(|(_, p)| p.ready_at <= now)
            .min_by_key(|(n, p)| (p.ready_at, (*n).clone()))
            .map(|(n, p)| (n.clone(), p.op.clone()));
        let earliest = state.queue.values().map(|p| p.ready_at).min();
        let job = match ready {
            Some((name, op)) => Some(Job::Item(name, op)),
            None if state.queue.is_empty()
                && state.canary_due
                && state.canary_ready_at.is_none_or(|at| at <= now) =>
            {
                Some(Job::Canary)
            }
            None => None,
        };
        match job {
            Some(job) => match self.token(&mut state, now) {
                None => Next::Job(job),
                Some(wait) => Next::Wait(Some(wait)),
            },
            None => {
                let canary_at = state.canary_due.then_some(state.canary_ready_at).flatten();
                let at = [earliest, canary_at].into_iter().flatten().min();
                Next::Wait(at.map(|at| at.saturating_duration_since(now)))
            }
        }
    }

    async fn apply(&self, job: Job) {
        let lease = if self.config.leased {
            Lease::Attached
        } else {
            Lease::None
        };
        match job {
            Job::Item(name, op) => {
                let key = self.key(&name);
                let result: Result<()> = match &op {
                    Op::Put(data) => self.kv.put(&key, data.clone(), lease, None).await,
                    Op::Delete => self.kv.delete(&key, None).await,
                };
                let mut state = lock(&self.inner);
                match result {
                    Ok(()) => {
                        state.writes = state.writes.saturating_add(1);
                        // Done, unless a newer op replaced this one meanwhile.
                        if state.queue.get(&name).is_some_and(|p| p.op == op) {
                            state.queue.remove(&name);
                        }
                        match op {
                            Op::Put(data) => {
                                state.written.insert(name, data);
                            }
                            Op::Delete => {
                                state.written.remove(&name);
                            }
                        }
                    }
                    Err(error) => {
                        state.errors = state.errors.saturating_add(1);
                        if let Some(pending) = state.queue.get_mut(&name)
                            && pending.op == op
                        {
                            pending.failures = pending.failures.saturating_add(1);
                            let wait = self.backoff(pending.failures);
                            pending.ready_at = Instant::now()
                                .checked_add(wait)
                                .unwrap_or_else(Instant::now);
                        }
                        eprintln!("kvstore sync {}: {key}: {error}", self.config.prefix);
                    }
                }
            }
            Job::Canary => {
                let Some(canary) = self.config.canary.clone() else {
                    let callbacks = {
                        let mut state = lock(&self.inner);
                        state.canary_due = false;
                        state.canary_written = true;
                        std::mem::take(&mut state.callbacks)
                    };
                    callbacks.into_iter().for_each(|done| done());
                    return;
                };
                let value = rfc3339(SystemTime::now()).into_bytes();
                let result = self.kv.put(&canary, value, Lease::Attached, None).await;
                let callbacks = {
                    let mut state = lock(&self.inner);
                    match result {
                        Ok(()) => {
                            state.writes = state.writes.saturating_add(1);
                            state.canary_due = false;
                            state.canary_written = true;
                            state.canary_failures = 0;
                            state.canary_ready_at = None;
                            std::mem::take(&mut state.callbacks)
                        }
                        Err(error) => {
                            state.errors = state.errors.saturating_add(1);
                            state.canary_failures = state.canary_failures.saturating_add(1);
                            let wait = self.backoff(state.canary_failures);
                            state.canary_ready_at = Instant::now().checked_add(wait);
                            eprintln!(
                                "kvstore sync {}: canary {canary}: {error}",
                                self.config.prefix
                            );
                            Vec::new()
                        }
                    }
                };
                callbacks.into_iter().for_each(|done| done());
            }
        }
    }

    /// The worker: runs until [`SyncStore::close`].
    pub async fn run(&self) {
        loop {
            match self.next() {
                Next::Closed => return,
                Next::Job(job) => self.apply(job).await,
                Next::Wait(None) => self.wake.notified().await,
                Next::Wait(Some(wait)) => {
                    let _ = tokio::time::timeout(wait, self.wake.notified()).await;
                }
            }
        }
    }
}

enum Job {
    Item(String, Op),
    Canary,
}
enum Next {
    Closed,
    Job(Job),
    /// Until woken, or at most this long.
    Wait(Option<Duration>),
}

#[cfg(test)]
#[path = "sync_store_tests.rs"]
mod tests;
