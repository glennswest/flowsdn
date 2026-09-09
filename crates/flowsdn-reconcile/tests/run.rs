#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use flowsdn_reconcile::{Options, ReconcileError, Reconciler, Target};
use flowsdn_table::{Key, Keyed, Snapshot, Table};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}, task::{Context, Poll, Wake, Waker}, time::Duration};
use tokio::{sync::oneshot, time::advance};

#[derive(Clone)]
struct Item(u8);
impl Keyed for Item { fn primary_key(&self) -> Key { vec![self.0] } }
#[derive(Default)]
struct Observed {
    rows: BTreeMap<u8, ()>,
    updates: usize,
    deletes: usize,
    prunes: usize,
    failures: usize,
    block_once: bool,
    delay_failure_once: Option<Duration>,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Observed>>);
impl Target<Item> for Fake {
    type Error = &'static str;
    async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
        let (block, failed, delay) = {
            let mut state = self.0.lock().unwrap();
            state.updates += 1;
            let failed = state.failures > 0;
            if failed { state.failures -= 1; }
            else { state.rows.insert(row.0, ()); }
            (std::mem::take(&mut state.block_once), failed, state.delay_failure_once.take())
        };
        if let Some(delay) = delay { tokio::time::sleep(delay).await; }
        if failed { return Err("injected failure"); }
        if block { std::future::pending::<()>().await; }
        Ok(())
    }
    async fn delete(&mut self, key: Key) -> Result<(), Self::Error> {
        let mut state = self.0.lock().unwrap();
        state.deletes += 1;
        state.rows.remove(key.first().unwrap());
        Ok(())
    }
    async fn prune(&mut self, desired: Snapshot<Item>) -> Result<(), Self::Error> {
        let mut state = self.0.lock().unwrap();
        state.prunes += 1;
        state.rows.retain(|key, _| desired.get("primary", &[*key]).unwrap().is_some());
        Ok(())
    }
}
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn poll<F: Future>(future: &mut Pin<Box<F>>, wakes: &Arc<WakeCount>) -> Poll<F::Output> {
    let waker = Waker::from(wakes.clone());
    future.as_mut().poll(&mut Context::from_waker(&waker))
}
fn assert_send(_: &impl Send) {}
fn wakes() -> Arc<WakeCount> { Arc::new(WakeCount(AtomicUsize::new(0))) }
async fn shutdown(receiver: oneshot::Receiver<()>) { let _ = receiver.await; }
fn completed(result: Poll<Result<(), ReconcileError>>) { assert!(matches!(result, Poll::Ready(Ok(())))); }

#[tokio::test(start_paused = true)]
async fn idle_loop_sleeps_until_periodic_prune_without_repeating_work() {
    let table = Table::<Item>::new(vec![]).unwrap();
    table.seal_initializers();
    let target = Fake::default();
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let (stop, receiver) = oneshot::channel();
    let mut running = Box::pin(reconciler.run(shutdown(receiver)));
    assert_send(&running);
    let wakes = wakes();
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().prunes, 1);
    for _ in 0..10 { assert!(poll(&mut running, &wakes).is_pending()); }
    assert_eq!(observed.lock().unwrap().prunes, 1);
    advance(Duration::from_secs(3599)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().prunes, 1);
    advance(Duration::from_secs(1)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().prunes, 2);
    stop.send(()).unwrap();
    completed(poll(&mut running, &wakes));
}

#[tokio::test(start_paused = true)]
async fn rows_wake_during_initialization_but_prune_waits_for_readiness() {
    let table = Table::new(vec![]).unwrap();
    let source = table.register_initializer("source").unwrap();
    table.seal_initializers();
    let target = Fake::default();
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let (stop, receiver) = oneshot::channel();
    let mut running = Box::pin(reconciler.run(shutdown(receiver)));
    let wakes = wakes();
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().prunes, 0);
    table.insert(Item(1)).await.unwrap();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 1);
    assert_eq!(observed.lock().unwrap().prunes, 0);
    let before = wakes.0.load(Ordering::SeqCst);
    source.complete();
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    advance(Duration::from_millis(1)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().prunes, 1);
    stop.send(()).unwrap();
    completed(poll(&mut running, &wakes));
}

#[tokio::test(start_paused = true)]
async fn retry_timer_runs_at_deadline_using_tokios_paused_clock() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.seal_initializers();
    let target = Fake::default();
    target.0.lock().unwrap().failures = 1;
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let (stop, receiver) = oneshot::channel();
    let mut running = Box::pin(reconciler.run(shutdown(receiver)));
    let wakes = wakes();
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 1);
    advance(Duration::from_millis(199)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 1);
    advance(Duration::from_millis(1)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 2);
    assert!(observed.lock().unwrap().rows.contains_key(&1));
    stop.send(()).unwrap();
    completed(poll(&mut running, &wakes));
    drop(running);
    assert!(reconciler.next_retry().is_none());
}

#[tokio::test(start_paused = true)]
async fn prune_handle_wakes_an_idle_loop_and_coalesces_requests() {
    let table = Table::<Item>::new(vec![]).unwrap();
    table.seal_initializers();
    let target = Fake::default();
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let handle = reconciler.prune_handle();
    let (stop, receiver) = oneshot::channel();
    let mut running = Box::pin(reconciler.run(shutdown(receiver)));
    let wakes = wakes();
    assert!(poll(&mut running, &wakes).is_pending());
    let before = wakes.0.load(Ordering::SeqCst);
    handle.prune_now(); handle.prune_now();
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    advance(Duration::from_millis(1)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().prunes, 2);
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().prunes, 2);
    stop.send(()).unwrap();
    completed(poll(&mut running, &wakes));
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_target_work_without_losing_the_queued_operation() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.seal_initializers();
    let target = Fake::default();
    target.0.lock().unwrap().block_once = true;
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let (stop, receiver) = oneshot::channel();
    let mut running = Box::pin(reconciler.run(shutdown(receiver)));
    let wakes = wakes();
    assert!(poll(&mut running, &wakes).is_pending());
    assert!(observed.lock().unwrap().rows.contains_key(&1));
    stop.send(()).unwrap();
    completed(poll(&mut running, &wakes));
    drop(running);
    assert!(reconciler.has_pending_work());
    assert_eq!(reconciler.attempted_revision(), 0);
    let (stop, receiver) = oneshot::channel();
    let mut resumed = Box::pin(reconciler.run(shutdown(receiver)));
    assert!(poll(&mut resumed, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 2);
    assert_eq!(observed.lock().unwrap().prunes, 1);
    stop.send(()).unwrap();
    completed(poll(&mut resumed, &wakes));
}

#[tokio::test(start_paused = true)]
async fn rate_limit_bounds_bursts_and_dropping_sleep_retains_prefetched_rows() {
    let table = Table::new(vec![]).unwrap();
    for id in 0..15 { table.insert(Item(id)).await.unwrap(); }
    table.seal_initializers();
    let target = Fake::default();
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options { round_size: 5, round_interval: Duration::from_millis(10), ..Options::default() }).unwrap();
    let wakes = wakes();
    let mut running = Box::pin(reconciler.run(std::future::pending::<()>()));
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 5);
    advance(Duration::from_millis(9)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 5);
    drop(running);
    assert!(reconciler.has_pending_work(), "prefetched work survives cancellation during throttling");
    let mut resumed = Box::pin(reconciler.run(std::future::pending::<()>()));
    assert!(poll(&mut resumed, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 10);
    advance(Duration::from_millis(10)).await;
    assert!(poll(&mut resumed, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 15);
    assert_eq!(observed.lock().unwrap().rows.len(), 15);
}

#[tokio::test(start_paused = true)]
async fn already_requested_shutdown_wins_over_ready_rows_and_initialization() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let mut running = Box::pin(reconciler.run(std::future::ready(())));
    completed(poll(&mut running, &wakes()));
    assert_eq!(observed.lock().unwrap().updates, 0);
    assert_eq!(observed.lock().unwrap().prunes, 0);
}

#[tokio::test(start_paused = true)]
async fn backoff_starts_when_slow_failure_completes_not_when_round_started() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.seal_initializers();
    let target = Fake::default();
    {
        let mut observed = target.0.lock().unwrap();
        observed.failures = 1;
        observed.delay_failure_once = Some(Duration::from_secs(1));
    }
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let (stop, receiver) = oneshot::channel();
    let mut running = Box::pin(reconciler.run(shutdown(receiver)));
    let wakes = wakes();
    assert!(poll(&mut running, &wakes).is_pending());
    advance(Duration::from_secs(1)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 1);
    advance(Duration::from_millis(199)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 1);
    advance(Duration::from_millis(1)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert_eq!(observed.lock().unwrap().updates, 2);
    stop.send(()).unwrap();
    completed(poll(&mut running, &wakes));
}

#[tokio::test(start_paused = true)]
async fn deletion_after_idle_wakes_loop_and_removes_realized_row() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.seal_initializers();
    let target = Fake::default();
    let observed = target.0.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let (stop, receiver) = oneshot::channel();
    let mut running = Box::pin(reconciler.run(shutdown(receiver)));
    let wakes = wakes();
    assert!(poll(&mut running, &wakes).is_pending());
    assert!(observed.lock().unwrap().rows.contains_key(&1));
    table.delete(&[1]).await.unwrap();
    advance(Duration::from_millis(1)).await;
    assert!(poll(&mut running, &wakes).is_pending());
    assert!(observed.lock().unwrap().rows.is_empty());
    assert_eq!(observed.lock().unwrap().deletes, 1);
    stop.send(()).unwrap();
    completed(poll(&mut running, &wakes));
    drop(running);
    assert_eq!(reconciler.attempted_revision(), 2);
}
