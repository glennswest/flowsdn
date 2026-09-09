#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
use flowsdn_reconcile::{
    BatchResult, BatchUpdate, DriverState, Options, ReconcileError, Reconciler, Target, WaitError,
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
    block_prune: bool,
    mutate: Option<Arc<Table<Item>>>,
    batch: bool,
    malformed: bool,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);
impl Fake {
    async fn apply(&mut self, id: u8) -> Result<(), &'static str> {
        let (fail, block, mutate) = {
            let mut state = self.0.lock().unwrap();
            let fail = state.fail == Some(id);
            if fail {
                state.fail = None;
            }
            let block = state.block == Some(id);
            if block {
                state.block = None;
            }
            (fail, block, state.mutate.take())
        };
        if block {
            std::future::pending::<()>().await;
        }
        if let Some(table) = mutate {
            table.insert(Item(id)).await.unwrap();
        }
        if fail {
            Err("injected failure")
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
        let block = std::mem::take(&mut self.0.lock().unwrap().block_prune);
        if block {
            std::future::pending::<()>().await;
        }
        Ok(())
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
fn now() -> Instant {
    Clock::now().into_std()
}
fn options() -> Options {
    Options {
        refresh_interval: Duration::ZERO,
        ..Options::default()
    }
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
async fn multiple_observers_wait_across_bounded_population_and_waiter_cancellation() {
    let table = Table::new(vec![]).unwrap();
    for id in 1..=5 {
        table.insert(Item(id)).await.unwrap();
    }
    let mut reconciler = Reconciler::new(
        &table,
        Fake::default(),
        Options {
            round_size: 2,
            ..options()
        },
    )
    .unwrap();
    let observer = reconciler.observer();
    let other = observer.clone();
    let mut abandoned = Box::pin(observer.wait_until_reconciled(5));
    let mut waiting = Box::pin(other.wait_until_reconciled(5));
    assert!(poll(abandoned.as_mut()).is_pending());
    assert!(poll(waiting.as_mut()).is_pending());
    drop(abandoned);
    for _ in 0..2 {
        reconciler.run_round(now()).await.unwrap();
        assert!(poll(waiting.as_mut()).is_pending());
    }
    reconciler.run_round(now()).await.unwrap();
    assert!(
        matches!(poll(waiting.as_mut()), Poll::Ready(Ok(progress)) if progress.attempted_revision == 5 && progress.retry_low_water_mark.is_none())
    );
    assert_eq!(
        observer
            .wait_until_reconciled(0)
            .await
            .unwrap()
            .attempted_revision,
        5
    );
}

#[tokio::test(start_paused = true)]
async fn failures_satisfy_attempted_barrier_and_retry_low_water_survives_cancelled_replay() {
    for batched in [false, true] {
        let table = Table::new(vec![]).unwrap();
        table.insert(Item(1)).await.unwrap();
        let target = Fake::default();
        {
            let mut state = target.0.lock().unwrap();
            state.fail = Some(1);
            state.batch = batched;
        }
        let control = target.clone();
        let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
        let mut observer = reconciler.observer();
        reconciler.run_round(now()).await.unwrap();
        let progress = observer.wait_until_reconciled(1).await.unwrap();
        assert_eq!(progress.retry_low_water_mark, Some(1));
        observer.changed().await.unwrap();
        advance(Duration::from_millis(200)).await;
        control.0.lock().unwrap().block = Some(1);
        let mut retry = Box::pin(reconciler.run_round(now()));
        assert!(poll(retry.as_mut()).is_pending());
        assert_eq!(observer.progress().retry_low_water_mark, Some(1));
        drop(retry);
        assert_eq!(
            observer
                .wait_until_reconciled(1)
                .await
                .unwrap()
                .retry_low_water_mark,
            Some(1)
        );
        reconciler.run_round(now()).await.unwrap();
        assert!(
            observer
                .changed()
                .await
                .unwrap()
                .retry_low_water_mark
                .is_none()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn delete_first_dispatch_cannot_jump_over_an_unattempted_older_update() {
    let table = Table::new(vec![]).unwrap();
    let target = Fake::default();
    target.0.lock().unwrap().block = Some(1);
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let observer = reconciler.observer();
    table.insert(Item(1)).await.unwrap();
    table.delete(&[2]).await.unwrap();
    let mut round = Box::pin(reconciler.run_round(now()));
    assert!(poll(round.as_mut()).is_pending());
    assert_eq!(observer.progress().attempted_revision, 0);
    let mut waiting = Box::pin(observer.wait_until_reconciled(2));
    assert!(poll(waiting.as_mut()).is_pending());
    drop(round);
    reconciler.run_round(now()).await.unwrap();
    assert!(
        matches!(poll(waiting.as_mut()), Poll::Ready(Ok(progress)) if progress.attempted_revision == 2)
    );
}

#[tokio::test(start_paused = true)]
async fn completed_live_prefix_is_observable_while_later_update_is_in_flight() {
    let table = Table::new(vec![]).unwrap();
    let target = Fake::default();
    target.0.lock().unwrap().block = Some(2);
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let observer = reconciler.observer();
    table.insert(Item(1)).await.unwrap();
    table.insert(Item(2)).await.unwrap();
    let mut round = Box::pin(reconciler.run_round(now()));
    assert!(poll(round.as_mut()).is_pending());
    assert_eq!(
        observer
            .wait_until_reconciled(1)
            .await
            .unwrap()
            .attempted_revision,
        1
    );
    let mut waiting = Box::pin(observer.wait_until_reconciled(2));
    assert!(poll(waiting.as_mut()).is_pending());
    drop(round);
    reconciler.run_round(now()).await.unwrap();
    assert!(matches!(poll(waiting.as_mut()), Poll::Ready(Ok(_))));
}

#[tokio::test(start_paused = true)]
async fn obsolete_generation_does_not_leave_a_retry_or_satisfy_its_replacement() {
    let table = Arc::new(Table::new(vec![]).unwrap());
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    {
        let mut state = target.0.lock().unwrap();
        state.fail = Some(1);
        state.mutate = Some(table.clone());
    }
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let observer = reconciler.observer();
    reconciler.run_round(now()).await.unwrap();
    assert!(
        observer
            .wait_until_reconciled(1)
            .await
            .unwrap()
            .retry_low_water_mark
            .is_none()
    );
    let mut replacement = Box::pin(observer.wait_until_reconciled(2));
    assert!(poll(replacement.as_mut()).is_pending());
    reconciler.run_round(now()).await.unwrap();
    assert!(
        matches!(poll(replacement.as_mut()), Poll::Ready(Ok(progress)) if progress.attempted_revision == 2)
    );
}

#[tokio::test(start_paused = true)]
async fn malformed_batch_cannot_publish_attempted_progress() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    {
        let mut state = target.0.lock().unwrap();
        state.batch = true;
        state.malformed = true;
    }
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let observer = reconciler.observer();
    assert_eq!(
        reconciler.run_round(now()).await.unwrap_err(),
        ReconcileError::InvalidBatchResults
    );
    let mut waiting = Box::pin(observer.wait_until_reconciled(1));
    assert!(poll(waiting.as_mut()).is_pending());
    reconciler.run_round(now()).await.unwrap();
    assert!(matches!(poll(waiting.as_mut()), Poll::Ready(Ok(_))));
}

#[tokio::test(start_paused = true)]
async fn attempted_barrier_does_not_wait_for_blocked_prune() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.seal_initializers();
    let target = Fake::default();
    target.0.lock().unwrap().block_prune = true;
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let observer = reconciler.observer();
    let mut round = Box::pin(reconciler.run_round(now()));
    assert!(poll(round.as_mut()).is_pending());
    assert_eq!(
        observer
            .wait_until_reconciled(1)
            .await
            .unwrap()
            .attempted_revision,
        1
    );
}

#[tokio::test(start_paused = true)]
async fn stopped_loop_notifies_waiters_and_manual_round_can_resume() {
    let table = Table::new(vec![]).unwrap();
    let mut reconciler = Reconciler::new(&table, Fake::default(), options()).unwrap();
    let observer = reconciler.observer();
    let mut waiting = Box::pin(observer.wait_until_reconciled(1));
    assert!(poll(waiting.as_mut()).is_pending());
    reconciler.run(async {}).await.unwrap();
    assert!(matches!(
        poll(waiting.as_mut()),
        Poll::Ready(Err(WaitError::Stopped))
    ));
    assert_eq!(observer.progress().driver, DriverState::Stopped);
    table.insert(Item(1)).await.unwrap();
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(
        observer.wait_until_reconciled(1).await.unwrap().driver,
        DriverState::Manual
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_run_future_reports_stopped_and_dropping_owner_reports_closed() {
    let table = Table::new(vec![]).unwrap();
    let mut reconciler = Reconciler::new(&table, Fake::default(), options()).unwrap();
    let observer = reconciler.observer();
    let mut running = Box::pin(reconciler.run(std::future::pending::<()>()));
    assert!(poll(running.as_mut()).is_pending());
    assert_eq!(observer.progress().driver, DriverState::Running);
    drop(running);
    assert_eq!(
        observer.wait_until_reconciled(1).await.unwrap_err(),
        WaitError::Stopped
    );
    drop(reconciler);
    assert_eq!(
        observer.wait_until_reconciled(1).await.unwrap_err(),
        WaitError::Closed
    );
    assert_eq!(
        observer
            .wait_until_reconciled(0)
            .await
            .unwrap()
            .attempted_revision,
        0
    );
}

#[tokio::test(start_paused = true)]
async fn final_checkpoint_remains_available_after_owner_drop() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let mut reconciler = Reconciler::new(&table, Fake::default(), options()).unwrap();
    let observer = reconciler.observer();
    let mut waiting = Box::pin(observer.wait_until_reconciled(1));
    assert!(poll(waiting.as_mut()).is_pending());
    reconciler.run_round(now()).await.unwrap();
    drop(reconciler);
    assert!(
        matches!(poll(waiting.as_mut()), Poll::Ready(Ok(progress)) if progress.attempted_revision == 1)
    );
    assert_eq!(
        observer.wait_until_reconciled(2).await.unwrap_err(),
        WaitError::Closed
    );
}

#[tokio::test(start_paused = true)]
async fn future_revision_waits_across_later_writes_and_failed_delete_reports_low_water() {
    let table = Table::new(vec![]).unwrap();
    let target = Fake::default();
    let control = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let observer = reconciler.observer();
    let mut waiting = Box::pin(observer.wait_until_reconciled(3));
    assert!(poll(waiting.as_mut()).is_pending());
    for _ in 0..2 {
        table.insert(Item(1)).await.unwrap();
        reconciler.run_round(now()).await.unwrap();
        assert!(poll(waiting.as_mut()).is_pending());
    }
    table.delete(&[1]).await.unwrap();
    control.0.lock().unwrap().fail = Some(1);
    reconciler.run_round(now()).await.unwrap();
    assert!(
        matches!(poll(waiting.as_mut()), Poll::Ready(Ok(progress)) if progress.attempted_revision == 3 && progress.retry_low_water_mark == Some(3))
    );
    advance(Duration::from_millis(200)).await;
    reconciler.run_round(now()).await.unwrap();
    assert!(observer.progress().retry_low_water_mark.is_none());
}

#[tokio::test(start_paused = true)]
async fn forced_resync_waits_for_partial_population_and_exposes_prune_requirement() {
    let table = Table::with_stream_options(
        vec![],
        flowsdn_table::StreamOptions {
            tombstone_max_count: 1,
            ..flowsdn_table::StreamOptions::default()
        },
    )
    .unwrap();
    table.insert(Item(1)).await.unwrap();
    let mut reconciler = Reconciler::new(
        &table,
        Fake::default(),
        Options {
            round_size: 1,
            ..options()
        },
    )
    .unwrap();
    reconciler.run_round(now()).await.unwrap();
    table.delete(&[1]).await.unwrap();
    table.delete(&[2]).await.unwrap();
    for id in 3..=5 {
        table.insert(Item(id)).await.unwrap();
    }
    let observer = reconciler.observer();
    let mut waiting = Box::pin(observer.wait_until_reconciled(6));
    for _ in 0..3 {
        reconciler.run_round(now()).await.unwrap();
        assert!(poll(waiting.as_mut()).is_pending());
        assert!(observer.progress().resync_required);
    }
    reconciler.run_round(now()).await.unwrap();
    assert!(
        matches!(poll(waiting.as_mut()), Poll::Ready(Ok(progress)) if progress.attempted_revision == 6 && progress.resync_required)
    );
    table.seal_initializers();
    reconciler.run_round(now()).await.unwrap();
    assert!(!observer.progress().resync_required);
}
