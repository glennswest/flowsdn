//! Probe scheduling with staleness detection (spec 00 §3.4.2, #456): each
//! probe runs on its own thread every [`Thresholds::interval`]; one that has
//! not finished for [`Thresholds::warning`] is a warning, for
//! [`Thresholds::failure`] a failure (a deadlocked subsystem stops its probe,
//! so the agent's health check fails instead of hanging). Readiness waits
//! until every probe ran once. The evaluation takes the time as an argument,
//! so it is tested without waiting.
use crate::State;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// The reference's `status-collector-*` defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Thresholds {
    /// How often a probe runs (`status-collector-interval`, 5 s).
    pub interval: Duration,
    /// A probe outstanding this long is a warning
    /// (`status-collector-warning-threshold`, 15 s).
    pub warning: Duration,
    /// ... and this long a failure (`status-collector-failure-threshold`, 1 m).
    pub failure: Duration,
}
impl Default for Thresholds {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            warning: Duration::from_secs(15),
            failure: Duration::from_secs(60),
        }
    }
}

/// One probe's last run.
#[derive(Clone, Debug)]
struct Probe<T> {
    /// When the current run started (None between runs).
    running: Option<Instant>,
    /// When the last run finished, and its result.
    finished: Option<(Instant, T)>,
    /// When the probe was registered: a probe that never finished is
    /// outstanding since then.
    registered: Instant,
}

/// The probes and their last results, shared by the probe threads and the
/// health handler. Cloning shares the same probes.
#[derive(Clone, Debug)]
pub struct Collector<T> {
    probes: Arc<Mutex<BTreeMap<String, Probe<T>>>>,
}
impl<T> Default for Collector<T> {
    fn default() -> Self {
        Self {
            probes: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
impl<T: Clone + Send + 'static> Collector<T> {
    pub fn new() -> Self {
        Self::default()
    }
    // A panicking probe thread leaves the map consistent: every write is a
    // single assignment.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Probe<T>>> {
        self.probes.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Register `name` (not yet run) at `now`.
    pub fn register(&self, name: &str, now: Instant) {
        self.lock().insert(
            name.to_owned(),
            Probe {
                running: None,
                finished: None,
                registered: now,
            },
        );
    }
    /// `name` starts a run at `now`.
    pub fn begin(&self, name: &str, now: Instant) {
        if let Some(probe) = self.lock().get_mut(name) {
            probe.running = Some(now);
        }
    }
    /// `name`'s run finished at `now` with `result`.
    pub fn finish(&self, name: &str, now: Instant, result: T) {
        if let Some(probe) = self.lock().get_mut(name) {
            probe.running = None;
            probe.finished = Some((now, result));
        }
    }
    /// `name`'s last result.
    pub fn last(&self, name: &str) -> Option<T> {
        self.lock()
            .get(name)
            .and_then(|p| p.finished.as_ref().map(|(_, r)| r.clone()))
    }
    /// Every registered probe finished at least once.
    pub fn ran_once(&self) -> bool {
        self.lock().values().all(|p| p.finished.is_some())
    }
    /// The worst staleness at `now`: a probe whose result is older than the
    /// threshold, because its run is outstanding (a stuck subsystem) or its
    /// thread stopped running it. None when every probe is fresh.
    pub fn stale(&self, now: Instant, thresholds: &Thresholds) -> Option<(State, String)> {
        let mut worst: Option<(State, String)> = None;
        for (name, probe) in self.lock().iter() {
            let since = match (&probe.running, &probe.finished) {
                (Some(started), _) => *started,
                (None, Some((finished, _))) => *finished,
                (None, None) => probe.registered,
            };
            let age = now.saturating_duration_since(since);
            let state = if age >= thresholds.failure {
                State::Failure
            } else if age >= thresholds.warning {
                State::Warning
            } else {
                continue;
            };
            let what = if probe.running.is_some() {
                "has not completed"
            } else {
                "has no result"
            };
            let message = format!("probe {name} {what} for {}s", age.as_secs());
            if worst.as_ref().is_none_or(|(w, _)| state == State::Failure && *w != State::Failure) {
                worst = Some((state, message));
            }
        }
        worst
    }
    /// Run `probe` as `name` every `interval` on its own thread, for the life
    /// of the process.
    pub fn spawn(
        &self,
        name: &str,
        interval: Duration,
        mut probe: impl FnMut() -> T + Send + 'static,
    ) -> std::io::Result<JoinHandle<()>> {
        self.register(name, Instant::now());
        let collector = self.clone();
        let owned = name.to_owned();
        std::thread::Builder::new()
            .name(format!("health-{name}"))
            .spawn(move || {
                loop {
                    collector.begin(&owned, Instant::now());
                    let result = probe();
                    collector.finish(&owned, Instant::now(), result);
                    std::thread::sleep(interval);
                }
            })
    }
}
