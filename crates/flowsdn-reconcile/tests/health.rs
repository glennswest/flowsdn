#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
use flowsdn_health::{HealthStatus, Level, Registry};
use flowsdn_reconcile::{
    BatchResult, BatchUpdate, DriverState, Options, ReconcileError, Reconciler, Target,
};
use flowsdn_table::{Key, Keyed, Snapshot, Table};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};
use tokio::time::{Instant as Clock, advance};
#[derive(Clone)]
struct Item(u8);
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        vec![self.0]
    }
}
#[derive(Default)]
struct State {
    fail: Option<u8>,
    block: Option<u8>,
    fail_prune: bool,
    batch: bool,
    malformed: bool,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);
impl Fake {
    async fn apply(&mut self, id: u8) -> Result<(), &'static str> {
        let (fail, block) = {
            let mut state = self.0.lock().unwrap();
            let fail = state.fail == Some(id);
            if fail {
                state.fail = None;
            }
            let block = state.block == Some(id);
            if block {
                state.block = None;
            }
            (fail, block)
        };
        if block {
            std::future::pending::<()>().await;
        }
        if fail {
            Err("target rejected row")
        } else {
            Ok(())
        }
    }
}
impl Target<Item> for Fake {
    type Error = &'static str;
    fn supports_batches(&self) -> bool {
        self.0.lock().unwrap().batch
    }
    async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
        self.apply(row.0).await
    }
    async fn delete(&mut self, key: Key) -> Result<(), Self::Error> {
        self.apply(key[0]).await
    }
    async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> {
        if std::mem::take(&mut self.0.lock().unwrap().fail_prune) {
            Err("prune failed")
        } else {
            Ok(())
        }
    }
    async fn update_batch(&mut self, updates: Vec<BatchUpdate<Item>>) -> Vec<BatchResult> {
        if std::mem::take(&mut self.0.lock().unwrap().malformed) {
            return Vec::new();
        }
        let mut results = Vec::new();
        for update in updates {
            let result = self
                .update_with_hint(update.row, update.hint)
                .await
                .map_err(str::to_owned);
            results.push(BatchResult {
                key: update.key,
                revision: update.revision,
                result,
            });
        }
        results
    }
}
fn options() -> Options {
    Options {
        refresh_interval: Duration::ZERO,
        ..Options::default()
    }
}
fn now() -> Instant {
    Clock::now().into_std()
}
fn status(registry: &Registry) -> HealthStatus {
    registry
        .snapshot()
        .get("primary", b"reconcile")
        .unwrap()
        .unwrap()
        .0
        .as_ref()
        .clone()
}
struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(NoopWake));
    future.poll(&mut Context::from_waker(&waker))
}

#[tokio::test(start_paused = true)]
async fn optional_reporter_leaves_registry_untouched_and_success_counts_desired_objects() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.insert(Item(2)).await.unwrap();
    let registry = Registry::new();
    let mut reconciler = Reconciler::new(&table, Fake::default(), options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    assert!(registry.snapshot().is_empty());
    let mut reconciler = reconciler.with_reporter(registry.reporter("reconcile").unwrap());
    reconciler.run_round(now()).await.unwrap();
    let health = status(&registry);
    assert_eq!(
        (health.level, health.message.as_str()),
        (Level::Ok, "2 objects")
    );
    assert!(health.error.is_empty());
    assert_eq!(table.snapshot().revision(), 2);
}

#[tokio::test(start_paused = true)]
async fn retry_recovery_and_cancelled_replay_preserve_failure_diagnostics() {
    for batch in [false, true] {
        let table = Table::new(vec![]).unwrap();
        table.insert(Item(1)).await.unwrap();
        let registry = Registry::new();
        let target = Fake::default();
        {
            let mut state = target.0.lock().unwrap();
            state.fail = Some(1);
            state.batch = batch;
        }
        let control = target.clone();
        let mut reconciler = Reconciler::new(&table, target, options())
            .unwrap()
            .with_reporter(registry.reporter("reconcile").unwrap());
        reconciler.run_round(now()).await.unwrap();
        let health = status(&registry);
        assert_eq!(
            (health.level, health.message.as_str()),
            (Level::Degraded, "1 errors")
        );
        assert!(health.error.contains("target rejected row"));
        advance(Duration::from_millis(200)).await;
        control.0.lock().unwrap().block = Some(1);
        let mut cancelled = Box::pin(reconciler.run_round(now()));
        assert!(poll(cancelled.as_mut()).is_pending());
        assert_eq!(status(&registry).level, Level::Degraded);
        drop(cancelled);
        control.0.lock().unwrap().block = Some(1);
        let mut cancelled_again = Box::pin(reconciler.run_round(now()));
        assert!(poll(cancelled_again.as_mut()).is_pending());
        assert!(status(&registry).error.contains("target rejected row"));
        drop(cancelled_again);
        reconciler.run_round(now()).await.unwrap();
        let health = status(&registry);
        assert_eq!(health.level, Level::Ok);
        assert!(health.error.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn prune_and_row_failures_are_joined_and_clear_independently() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.seal_initializers();
    let registry = Registry::new();
    let target = Fake::default();
    {
        let mut state = target.0.lock().unwrap();
        state.fail = Some(1);
        state.fail_prune = true;
    }
    let mut reconciler = Reconciler::new(&table, target, options())
        .unwrap()
        .with_reporter(registry.reporter("reconcile").unwrap());
    reconciler.run_round(now()).await.unwrap();
    let health = status(&registry);
    assert_eq!(health.message, "2 errors");
    assert!(health.error.contains("target rejected row"));
    assert!(health.error.contains("prune failed"));
    advance(Duration::from_millis(200)).await;
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(status(&registry).message, "1 errors");
    reconciler.prune_now();
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(status(&registry).level, Level::Ok);
}

#[tokio::test(start_paused = true)]
async fn malformed_batch_is_degraded_until_valid_replay_finishes() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let registry = Registry::new();
    let target = Fake::default();
    {
        let mut state = target.0.lock().unwrap();
        state.batch = true;
        state.malformed = true;
    }
    let control = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options())
        .unwrap()
        .with_reporter(registry.reporter("reconcile").unwrap());
    assert_eq!(
        reconciler.run_round(now()).await.unwrap_err(),
        ReconcileError::InvalidBatchResults
    );
    assert!(status(&registry).error.contains("batch results"));
    assert!(reconciler.has_pending_work());
    control.0.lock().unwrap().block = Some(1);
    let mut replay = Box::pin(reconciler.run_round(now()));
    assert!(poll(replay.as_mut()).is_pending());
    assert_eq!(status(&registry).level, Level::Degraded);
    drop(replay);
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(status(&registry).level, Level::Ok);
}

#[tokio::test(start_paused = true)]
async fn resync_degrades_until_initialization_allows_prune() {
    let table = Table::with_stream_options(
        vec![],
        flowsdn_table::StreamOptions {
            tombstone_max_count: 1,
            ..flowsdn_table::StreamOptions::default()
        },
    )
    .unwrap();
    let registry = Registry::new();
    let mut reconciler = Reconciler::new(&table, Fake::default(), options())
        .unwrap()
        .with_reporter(registry.reporter("reconcile").unwrap());
    table.delete(&[1]).await.unwrap();
    table.delete(&[2]).await.unwrap();
    reconciler.run_round(now()).await.unwrap();
    assert!(status(&registry).error.contains("prune recovery"));
    table.seal_initializers();
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(status(&registry).level, Level::Ok);
}

#[tokio::test(start_paused = true)]
async fn clean_pending_work_stays_ok_and_explicit_shutdown_records_stop() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let registry = Registry::new();
    let target = Fake::default();
    target.0.lock().unwrap().block = Some(1);
    let mut reconciler = Reconciler::new(&table, target, options())
        .unwrap()
        .with_reporter(registry.reporter("reconcile").unwrap());
    let observer = reconciler.observer();
    let (stop, receiver) = tokio::sync::oneshot::channel::<()>();
    let mut running = Box::pin(reconciler.run(async move {
        let _ = receiver.await;
    }));
    assert!(poll(running.as_mut()).is_pending());
    assert_eq!(status(&registry).level, Level::Ok);
    stop.send(()).unwrap();
    assert!(matches!(poll(running.as_mut()), Poll::Ready(Ok(()))));
    drop(running);
    assert!(status(&registry).stopped.is_some());
    assert_eq!(observer.progress().driver, DriverState::Stopped);
    assert!(reconciler.has_pending_work());
    reconciler.run_round(now()).await.unwrap();
    assert!(status(&registry).stopped.is_none());
}

#[tokio::test(start_paused = true)]
async fn dropped_run_future_has_observer_stop_without_async_health_stop() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let registry = Registry::new();
    let target = Fake::default();
    target.0.lock().unwrap().block = Some(1);
    let mut reconciler = Reconciler::new(&table, target, options())
        .unwrap()
        .with_reporter(registry.reporter("reconcile").unwrap());
    let observer = reconciler.observer();
    let mut running = Box::pin(reconciler.run(std::future::pending::<()>()));
    assert!(poll(running.as_mut()).is_pending());
    drop(running);
    assert_eq!(observer.progress().driver, DriverState::Stopped);
    assert!(status(&registry).stopped.is_none());
    assert_eq!(status(&registry).level, Level::Ok);
}

#[tokio::test(start_paused = true)]
async fn joined_diagnostics_are_bounded_without_losing_error_count() {
    struct LargeError;
    impl Target<Item> for LargeError {
        type Error = String;
        async fn update(&mut self, _: Arc<Item>) -> Result<(), Self::Error> {
            Err("é".repeat(40_000))
        }
        async fn delete(&mut self, _: Key) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    let table = Table::new(vec![]).unwrap();
    for id in 1..=3 {
        table.insert(Item(id)).await.unwrap();
    }
    let registry = Registry::new();
    let mut reconciler = Reconciler::new(&table, LargeError, options())
        .unwrap()
        .with_reporter(registry.reporter("reconcile").unwrap());
    reconciler.run_round(now()).await.unwrap();
    let health = status(&registry);
    assert_eq!(health.message, "3 errors");
    assert!(health.error.len() <= 64 * 1024);
    assert!(health.error.ends_with("[diagnostics truncated]"));
}

#[tokio::test(start_paused = true)]
async fn healthy_round_does_not_publish_health_per_row() {
    let table = Table::new(vec![]).unwrap();
    for id in 1..=100 {
        table.insert(Item(id)).await.unwrap();
    }
    let registry = Registry::new();
    let mut reconciler = Reconciler::new(&table, Fake::default(), options())
        .unwrap()
        .with_reporter(registry.reporter("reconcile").unwrap());
    reconciler.run_round(now()).await.unwrap();
    let health = status(&registry);
    assert_eq!(health.level, Level::Ok);
    assert_eq!(health.message, "100 objects");
    assert_eq!(health.count, 2);
}
