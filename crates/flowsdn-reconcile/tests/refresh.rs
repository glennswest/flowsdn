#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use flowsdn_reconcile::{Kind, Options, Reconciler, Target, UpdateHint};
use flowsdn_table::{Key, Keyed, Snapshot, Table};
use std::{future::Future, sync::{Arc, Mutex}, task::{Context, Poll, Wake, Waker}, time::{Duration, Instant}};
use tokio::time::{advance, Instant as Clock};

#[derive(Clone)]
struct Item(u8, u64);
impl Keyed for Item { fn primary_key(&self) -> Key { vec![self.0] } }
#[derive(Default)]
struct Observed {
    calls: Vec<(u8, UpdateHint, Instant)>,
    fail_refresh: usize,
    fail_changed: usize,
    block_refresh_once: bool,
    mutate_refresh: Option<Arc<Table<Item>>>,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Observed>>);
impl Fake {
    async fn apply(&mut self, row: Arc<Item>, hint: UpdateHint) -> Result<(), &'static str> {
        let (fail, block, mutate) = {
            let mut state = self.0.lock().unwrap();
            state.calls.push((row.0, hint, now()));
            let failures = if hint == UpdateHint::Refresh { &mut state.fail_refresh } else { &mut state.fail_changed };
            let fail = *failures > 0;
            if fail { *failures -= 1; }
            let block = hint == UpdateHint::Refresh && std::mem::take(&mut state.block_refresh_once);
            let mutate = if hint == UpdateHint::Refresh { state.mutate_refresh.take() } else { None };
            (fail, block, mutate)
        };
        if block { std::future::pending::<()>().await; }
        if let Some(table) = mutate {
            table.insert(Item(row.0, row.1 + 1)).await.unwrap();
            return Err("obsolete refresh failure");
        }
        if fail { Err("injected failure") } else { Ok(()) }
    }
    fn refreshed(&self) -> Vec<u8> {
        self.0.lock().unwrap().calls.iter().filter(|(_, hint, _)| *hint == UpdateHint::Refresh).map(|(id, _, _)| *id).collect()
    }
}
impl Target<Item> for Fake {
    type Error = &'static str;
    async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> { self.apply(row, UpdateHint::Changed).await }
    async fn update_with_hint(&mut self, row: Arc<Item>, hint: UpdateHint) -> Result<(), Self::Error> { self.apply(row, hint).await }
    async fn delete(&mut self, _: Key) -> Result<(), Self::Error> { Ok(()) }
    async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> { Ok(()) }
}
fn now() -> Instant { Clock::now().into_std() }
fn options() -> Options { Options { refresh_interval: Duration::from_secs(1), ..Options::default() } }
struct NoopWake;
impl Wake for NoopWake { fn wake(self: Arc<Self>) {} }

#[tokio::test(start_paused = true)]
async fn default_refresh_occurs_after_thirty_minutes_without_desired_revision_write() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 10)).await.unwrap();
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1799)).await;
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 0);
    advance(Duration::from_secs(1)).await;
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 1);
    assert_eq!(observed.refreshed(), [1]);
    assert_eq!(table.snapshot().revision(), 1);
    let status = reconciler.status(&[1]).unwrap();
    assert_eq!((status.kind, status.id), (Kind::Done, 1));
    assert_eq!(status.updated_at, Some(now()));
}

#[tokio::test(start_paused = true)]
async fn zero_interval_disables_refresh_and_accepts_unused_zero_rate() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 10)).await.unwrap();
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, Options { refresh_interval: Duration::ZERO, refresh_rate: 0, ..Options::default() }).unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(36_000)).await;
    reconciler.run_round(now()).await.unwrap();
    assert!(observed.refreshed().is_empty());
    assert!(reconciler.next_refresh().is_none());
}

#[tokio::test(start_paused = true)]
async fn revision_order_rate_spacing_and_no_accumulated_burst_credit() {
    let table = Table::new(vec![]).unwrap();
    for id in [9, 2, 5] { table.insert(Item(id, 0)).await.unwrap(); }
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, Options { refresh_rate: 2, ..options() }).unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1)).await;
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 1);
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 0);
    advance(Duration::from_millis(499)).await;
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 0);
    advance(Duration::from_millis(1)).await;
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_millis(500)).await;
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(observed.refreshed(), [9, 2, 5]);
    advance(Duration::from_secs(10)).await;
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 1);
    assert_eq!(observed.refreshed(), [9, 2, 5, 9]);
    assert_eq!(table.snapshot().revision(), 3);
}

#[tokio::test(start_paused = true)]
async fn recent_statuses_deleted_rows_and_changed_cached_candidates_are_skipped() {
    let table = Table::new(vec![]).unwrap();
    for id in 1..6 { table.insert(Item(id, 0)).await.unwrap(); }
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, Options { round_size: 2, ..options() }).unwrap();
    for _ in 0..3 { reconciler.run_round(now()).await.unwrap(); }
    advance(Duration::from_millis(500)).await;
    table.insert(Item(2, 1)).await.unwrap();
    table.delete(&[4]).await.unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_millis(500)).await;
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(observed.refreshed(), [1]);
    table.insert(Item(3, 1)).await.unwrap();
    for _ in 0..5 {
        advance(Duration::from_millis(10)).await;
        reconciler.run_round(now()).await.unwrap();
    }
    assert_eq!(observed.refreshed(), [1, 5]);
    assert_eq!(reconciler.status(&[3]).unwrap().kind, Kind::Done);
}

#[tokio::test(start_paused = true)]
async fn refresh_failure_retries_keep_force_hint_and_reset_on_success() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 0)).await.unwrap();
    let target = Fake::default();
    target.0.lock().unwrap().fail_refresh = 1;
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1)).await;
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Error);
    let deadline = reconciler.next_retry().unwrap();
    assert_eq!(deadline, now() + Duration::from_millis(200));
    advance(Duration::from_millis(199)).await;
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(observed.refreshed(), [1]);
    advance(Duration::from_millis(1)).await;
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 1);
    assert_eq!(observed.refreshed(), [1, 1]);
    assert_eq!(reconciler.status(&[1]).unwrap().retries, 0);
    assert!(reconciler.next_retry().is_none());
    assert_eq!(table.snapshot().revision(), 1);
}

#[tokio::test(start_paused = true)]
async fn cancelling_refresh_preserves_refreshing_status_and_hint_for_replay() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 0)).await.unwrap();
    let target = Fake::default();
    target.0.lock().unwrap().block_refresh_once = true;
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1)).await;
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut cancelled = Box::pin(reconciler.run_round(now()));
    assert!(cancelled.as_mut().poll(&mut context).is_pending());
    drop(cancelled);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Refreshing);
    assert!(reconciler.has_pending_work());
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 1);
    assert_eq!(observed.refreshed(), [1, 1]);
    assert_eq!(table.snapshot().revision(), 1);
}

#[tokio::test(start_paused = true)]
async fn in_flight_refresh_result_is_discarded_after_a_new_desired_generation() {
    let table = Arc::new(Table::new(vec![]).unwrap());
    table.insert(Item(1, 10)).await.unwrap();
    let target = Fake::default();
    target.0.lock().unwrap().mutate_refresh = Some(table.clone());
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1)).await;
    assert_eq!(reconciler.run_round(now()).await.unwrap().stale, 1);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Pending);
    assert!(reconciler.next_retry().is_none());
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Done);
    assert_eq!(observed.0.lock().unwrap().calls.last().unwrap().1, UpdateHint::Changed);
}

#[tokio::test(start_paused = true)]
async fn refresh_does_not_reset_backoff_for_an_already_failed_row() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 0)).await.unwrap();
    let target = Fake::default();
    target.0.lock().unwrap().fail_changed = 1;
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, Options { min_backoff: Duration::from_secs(10), max_backoff: Duration::from_secs(10), ..options() }).unwrap();
    reconciler.run_round(now()).await.unwrap();
    let retry = reconciler.next_retry();
    advance(Duration::from_secs(2)).await;
    reconciler.run_round(now()).await.unwrap();
    assert!(observed.refreshed().is_empty());
    assert_eq!(reconciler.next_retry(), retry);
    assert_eq!(reconciler.status(&[1]).unwrap().retries, 1);
}

#[tokio::test(start_paused = true)]
async fn run_scheduler_wakes_for_refresh_and_shutdown_keeps_interrupted_force_work() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 0)).await.unwrap();
    table.seal_initializers();
    let target = Fake::default();
    target.0.lock().unwrap().block_refresh_once = true;
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let (stop, receiver) = tokio::sync::oneshot::channel::<()>();
    let mut running = Box::pin(reconciler.run(async move { let _ = receiver.await; }));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    assert!(running.as_mut().poll(&mut context).is_pending());
    advance(Duration::from_millis(999)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    assert!(observed.refreshed().is_empty());
    advance(Duration::from_millis(1)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    assert_eq!(observed.refreshed(), [1]);
    stop.send(()).unwrap();
    assert!(matches!(running.as_mut().poll(&mut context), Poll::Ready(Ok(()))));
    drop(running);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Refreshing);
    let mut resumed = Box::pin(reconciler.run(std::future::pending::<()>()));
    assert!(resumed.as_mut().poll(&mut context).is_pending());
    assert_eq!(observed.refreshed(), [1, 1]);
}

#[tokio::test(start_paused = true)]
async fn default_target_hint_method_repeats_existing_update_implementations() {
    struct Legacy(usize);
    impl Target<Item> for Legacy {
        type Error = &'static str;
        async fn update(&mut self, _: Arc<Item>) -> Result<(), Self::Error> { self.0 += 1; Ok(()) }
        async fn delete(&mut self, _: Key) -> Result<(), Self::Error> { Ok(()) }
        async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> { Ok(()) }
    }
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 0)).await.unwrap();
    let mut reconciler = Reconciler::new(&table, Legacy(0), options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1)).await;
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(reconciler.target().0, 2);
}

#[tokio::test(start_paused = true)]
async fn all_ineligible_multi_chunk_pass_finishes_and_rearms_at_eligibility() {
    let table = Table::new(vec![]).unwrap();
    for id in 1..=5 { table.insert(Item(id, 0)).await.unwrap(); }
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, Options { round_size: 2, ..options() }).unwrap();
    for _ in 0..3 { reconciler.run_round(now()).await.unwrap(); }
    advance(Duration::from_millis(500)).await;
    for id in 1..=5 { table.insert(Item(id, 1)).await.unwrap(); }
    for _ in 0..3 { reconciler.run_round(now()).await.unwrap(); }
    advance(Duration::from_millis(500)).await;
    for _ in 0..2 {
        assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 0);
        assert_eq!(reconciler.next_refresh(), Some(now()));
    }
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 0);
    assert_eq!(reconciler.next_refresh(), Some(now() + Duration::from_millis(500)));
    assert!(observed.refreshed().is_empty());
}

#[tokio::test(start_paused = true)]
async fn slow_successes_refresh_at_completion_age_without_skipping_an_interval() {
    struct Slow(Arc<Mutex<Vec<(UpdateHint, Instant)>>>);
    impl Target<Item> for Slow {
        type Error = &'static str;
        async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
            self.update_with_hint(row, UpdateHint::Changed).await
        }
        async fn update_with_hint(&mut self, _: Arc<Item>, hint: UpdateHint) -> Result<(), Self::Error> {
            self.0.lock().unwrap().push((hint, now()));
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(())
        }
        async fn delete(&mut self, _: Key) -> Result<(), Self::Error> { Ok(()) }
        async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> { Ok(()) }
    }
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 0)).await.unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut reconciler = Reconciler::new(&table, Slow(calls.clone()), options()).unwrap();
    let start = now();
    let mut running = Box::pin(reconciler.run(std::future::pending::<()>()));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    assert!(running.as_mut().poll(&mut context).is_pending());
    advance(Duration::from_millis(200)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    advance(Duration::from_millis(800)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    assert_eq!(calls.lock().unwrap().len(), 1);
    advance(Duration::from_millis(200)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    assert_eq!(calls.lock().unwrap()[1], (UpdateHint::Refresh, start + Duration::from_millis(1200)));
    advance(Duration::from_millis(200)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    advance(Duration::from_millis(999)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    assert_eq!(calls.lock().unwrap().len(), 2);
    advance(Duration::from_millis(1)).await;
    assert!(running.as_mut().poll(&mut context).is_pending());
    assert_eq!(calls.lock().unwrap()[2], (UpdateHint::Refresh, start + Duration::from_millis(2400)));
    assert_eq!(table.snapshot().revision(), 1);
}
