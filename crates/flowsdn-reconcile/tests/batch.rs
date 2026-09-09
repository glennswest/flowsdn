#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
use flowsdn_reconcile::{
    BatchDelete, BatchResult, BatchUpdate, Kind, Options, ReconcileError, Reconciler, Target,
    UpdateHint,
};
use flowsdn_table::{Key, Keyed, Snapshot, Table};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};
use tokio::time::{Instant as Clock, advance};

#[derive(Clone, Debug)]
struct Item(u8);
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        vec![self.0]
    }
}
#[derive(Clone, Debug, PartialEq)]
enum Call {
    Delete(Vec<u8>),
    Update(Vec<(u8, UpdateHint)>),
}
#[derive(Clone, Copy, Default)]
enum Malformed {
    #[default]
    None,
    Missing,
    Extra,
    Duplicate,
    Key,
    Revision,
}
#[derive(Default)]
struct State {
    calls: Vec<Call>,
    fail: Option<u8>,
    malformed: Malformed,
    block_updates: bool,
    update_delay: Duration,
    block_deletes: bool,
    mutate_update: Option<Arc<Table<Item>>>,
    mutate_delete: Option<Arc<Table<Item>>>,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);
impl Target<Item> for Fake {
    type Error = &'static str;
    fn supports_batches(&self) -> bool {
        true
    }
    async fn update(&mut self, _: Arc<Item>) -> Result<(), Self::Error> {
        panic!("unexpected scalar update")
    }
    async fn delete(&mut self, _: Key) -> Result<(), Self::Error> {
        panic!("unexpected scalar delete")
    }
    async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn update_batch(&mut self, updates: Vec<BatchUpdate<Item>>) -> Vec<BatchResult> {
        let (fail, malformed, block, mutate, delay) = {
            let mut state = self.0.lock().unwrap();
            state.calls.push(Call::Update(
                updates
                    .iter()
                    .map(|entry| (entry.row.0, entry.hint))
                    .collect(),
            ));
            (
                state.fail.take(),
                std::mem::take(&mut state.malformed),
                std::mem::take(&mut state.block_updates),
                state.mutate_update.take(),
                state.update_delay,
            )
        };
        if block {
            std::future::pending::<()>().await;
        }
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if let Some(table) = mutate {
            table.insert(Item(1)).await.unwrap();
        }
        let mut results: Vec<_> = updates
            .into_iter()
            .map(|entry| BatchResult {
                result: if fail == Some(entry.row.0) {
                    Err("injected update failure".into())
                } else {
                    Ok(())
                },
                key: entry.key,
                revision: entry.revision,
            })
            .collect();
        // Results may arrive in a different order than requests.
        results.reverse();
        match malformed {
            Malformed::None => {}
            Malformed::Missing => {
                results.pop();
            }
            Malformed::Extra => results.push(BatchResult {
                key: vec![99],
                revision: 999,
                result: Ok(()),
            }),
            Malformed::Duplicate => {
                results[1] = results[0].clone();
            }
            Malformed::Key => {
                results[0].key = vec![99];
            }
            Malformed::Revision => {
                results[0].revision += 1;
            }
        }
        results
    }
    async fn delete_batch(&mut self, deletes: Vec<BatchDelete>) -> Vec<BatchResult> {
        let (fail, block, mutate) = {
            let mut state = self.0.lock().unwrap();
            state.calls.push(Call::Delete(
                deletes.iter().map(|entry| entry.key[0]).collect(),
            ));
            (
                state.fail.take(),
                std::mem::take(&mut state.block_deletes),
                state.mutate_delete.take(),
            )
        };
        if block {
            std::future::pending::<()>().await;
        }
        if let Some(table) = mutate {
            table.insert(Item(1)).await.unwrap();
        }
        deletes
            .into_iter()
            .map(|entry| BatchResult {
                result: if fail == Some(entry.key[0]) {
                    Err("injected delete failure".into())
                } else {
                    Ok(())
                },
                key: entry.key,
                revision: entry.revision,
            })
            .collect()
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
fn poll_pending(future: std::pin::Pin<&mut impl Future>) {
    let waker = Waker::from(Arc::new(NoopWake));
    assert!(future.poll(&mut Context::from_waker(&waker)).is_pending());
}

#[tokio::test(start_paused = true)]
async fn bounded_round_groups_deletes_before_updates_with_unordered_results() {
    let table = Table::new(vec![]).unwrap();
    for id in 1..=4 {
        table.insert(Item(id)).await.unwrap();
    }
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(
        &table,
        target,
        Options {
            round_size: 3,
            ..options()
        },
    )
    .unwrap();
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 3);
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 1);
    observed.0.lock().unwrap().calls.clear();
    table.insert(Item(5)).await.unwrap();
    table.delete(&[1]).await.unwrap();
    table.insert(Item(6)).await.unwrap();
    table.delete(&[2]).await.unwrap();
    let round = reconciler.run_round(now()).await.unwrap();
    assert_eq!((round.processed, round.deleted, round.updated), (3, 1, 2));
    assert_eq!(
        observed.0.lock().unwrap().calls,
        [
            Call::Delete(vec![1]),
            Call::Update(vec![(5, UpdateHint::Changed), (6, UpdateHint::Changed)])
        ]
    );
    assert_eq!(reconciler.run_round(now()).await.unwrap().deleted, 1);
    assert_eq!(reconciler.status(&[6]).unwrap().kind, Kind::Done);
}

#[tokio::test(start_paused = true)]
async fn partial_results_retry_only_failed_entries_and_merge_due_delete_first() {
    let table = Table::new(vec![]).unwrap();
    for id in 1..=3 {
        table.insert(Item(id)).await.unwrap();
    }
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    table.delete(&[1]).await.unwrap();
    observed.0.lock().unwrap().fail = Some(1);
    reconciler.run_round(now()).await.unwrap();
    table.insert(Item(4)).await.unwrap();
    table.insert(Item(5)).await.unwrap();
    advance(Duration::from_millis(200)).await;
    observed.0.lock().unwrap().calls.clear();
    let round = reconciler.run_round(now()).await.unwrap();
    assert_eq!((round.deleted, round.updated), (1, 2));
    assert_eq!(
        observed.0.lock().unwrap().calls,
        [
            Call::Delete(vec![1]),
            Call::Update(vec![(4, UpdateHint::Changed), (5, UpdateHint::Changed)])
        ]
    );
    table.insert(Item(4)).await.unwrap();
    table.insert(Item(5)).await.unwrap();
    observed.0.lock().unwrap().fail = Some(4);
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 1);
    assert_eq!(reconciler.status(&[4]).unwrap().kind, Kind::Error);
    assert_eq!(reconciler.status(&[5]).unwrap().kind, Kind::Done);
    advance(Duration::from_millis(200)).await;
    observed.0.lock().unwrap().calls.clear();
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 1);
    assert_eq!(
        observed.0.lock().unwrap().calls,
        [Call::Update(vec![(4, UpdateHint::Changed)])]
    );
}

#[tokio::test(start_paused = true)]
async fn malformed_responses_acknowledge_nothing_and_replay_every_input() {
    for malformed in [
        Malformed::Missing,
        Malformed::Extra,
        Malformed::Duplicate,
        Malformed::Key,
        Malformed::Revision,
    ] {
        let table = Table::new(vec![]).unwrap();
        for id in 1..=2 {
            table.insert(Item(id)).await.unwrap();
        }
        let target = Fake::default();
        target.0.lock().unwrap().malformed = malformed;
        let observed = target.clone();
        let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
        assert_eq!(
            reconciler.run_round(now()).await.unwrap_err(),
            ReconcileError::InvalidBatchResults
        );
        assert!(reconciler.has_pending_work());
        assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Pending);
        assert_eq!(reconciler.status(&[2]).unwrap().kind, Kind::Pending);
        assert!(reconciler.next_retry().is_none());
        assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 2);
        let calls = &observed.0.lock().unwrap().calls;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_replays_updates_but_not_completed_deletes() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    table.delete(&[1]).await.unwrap();
    table.insert(Item(2)).await.unwrap();
    table.insert(Item(3)).await.unwrap();
    {
        let mut state = observed.0.lock().unwrap();
        state.calls.clear();
        state.block_updates = true;
    }
    let mut round = Box::pin(reconciler.run_round(now()));
    poll_pending(round.as_mut());
    drop(round);
    assert!(reconciler.status(&[1]).is_none());
    assert_eq!(reconciler.status(&[2]).unwrap().kind, Kind::Pending);
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 2);
    assert_eq!(
        observed.0.lock().unwrap().calls,
        [
            Call::Delete(vec![1]),
            Call::Update(vec![(2, UpdateHint::Changed), (3, UpdateHint::Changed)]),
            Call::Update(vec![(2, UpdateHint::Changed), (3, UpdateHint::Changed)])
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn stale_update_and_recreated_delete_results_do_not_publish_or_retry() {
    let table = Arc::new(Table::new(vec![]).unwrap());
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    {
        let mut state = target.0.lock().unwrap();
        state.mutate_update = Some(table.clone());
        state.fail = Some(1);
    }
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    assert_eq!(reconciler.run_round(now()).await.unwrap().stale, 1);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Pending);
    assert!(reconciler.next_retry().is_none());
    reconciler.run_round(now()).await.unwrap();
    table.delete(&[1]).await.unwrap();
    {
        let mut state = observed.0.lock().unwrap();
        state.mutate_delete = Some(table.clone());
        state.fail = Some(1);
    }
    assert_eq!(reconciler.run_round(now()).await.unwrap().stale, 1);
    assert!(reconciler.next_retry().is_none());
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Pending);
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 1);
}

#[tokio::test(start_paused = true)]
async fn refresh_batch_preserves_hint_through_failure_and_cancelled_retry() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(
        &table,
        target,
        Options {
            refresh_interval: Duration::from_secs(1),
            ..options()
        },
    )
    .unwrap();
    reconciler.run_round(now()).await.unwrap();
    {
        let mut state = observed.0.lock().unwrap();
        state.calls.clear();
        state.fail = Some(1);
    }
    advance(Duration::from_secs(1)).await;
    let round = reconciler.run_round(now()).await.unwrap();
    assert_eq!(round.refreshed, 0);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Error);
    advance(Duration::from_millis(200)).await;
    observed.0.lock().unwrap().block_updates = true;
    let mut cancelled = Box::pin(reconciler.run_round(now()));
    poll_pending(cancelled.as_mut());
    drop(cancelled);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Refreshing);
    assert_eq!(reconciler.run_round(now()).await.unwrap().refreshed, 1);
    assert_eq!(
        observed.0.lock().unwrap().calls,
        vec![Call::Update(vec![(1, UpdateHint::Refresh)]); 3]
    );
    assert_eq!(table.snapshot().revision(), 1);
    assert_eq!(reconciler.status(&[1]).unwrap().retries, 0);
}

#[tokio::test(start_paused = true)]
async fn default_batch_methods_use_scalar_fallback_with_explicit_opt_in() {
    struct Fallback(Vec<Call>);
    impl Target<Item> for Fallback {
        // The batch fallback must not add a Send bound to target errors.
        type Error = std::rc::Rc<str>;
        fn supports_batches(&self) -> bool {
            true
        }
        async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
            self.0
                .push(Call::Update(vec![(row.0, UpdateHint::Changed)]));
            Ok(())
        }
        async fn update_with_hint(
            &mut self,
            row: Arc<Item>,
            hint: UpdateHint,
        ) -> Result<(), Self::Error> {
            self.0.push(Call::Update(vec![(row.0, hint)]));
            Ok(())
        }
        async fn delete(&mut self, key: Key) -> Result<(), Self::Error> {
            self.0.push(Call::Delete(vec![key[0]]));
            Ok(())
        }
        async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let mut reconciler = Reconciler::new(
        &table,
        Fallback(Vec::new()),
        Options {
            refresh_interval: Duration::from_secs(1),
            ..options()
        },
    )
    .unwrap();
    reconciler.run_round(now()).await.unwrap();
    table.delete(&[1]).await.unwrap();
    table.insert(Item(2)).await.unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1)).await;
    reconciler.run_round(now()).await.unwrap();
    assert_eq!(
        reconciler.target().0,
        [
            Call::Update(vec![(1, UpdateHint::Changed)]),
            Call::Delete(vec![1]),
            Call::Update(vec![(2, UpdateHint::Changed)]),
            Call::Update(vec![(2, UpdateHint::Refresh)])
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_delete_batch_replays_delete_before_updates() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    reconciler.run_round(now()).await.unwrap();
    table.delete(&[1]).await.unwrap();
    table.insert(Item(2)).await.unwrap();
    {
        let mut state = observed.0.lock().unwrap();
        state.calls.clear();
        state.block_deletes = true;
    }
    let (stop, receiver) = tokio::sync::oneshot::channel::<()>();
    let mut running = Box::pin(reconciler.run(async move {
        let _ = receiver.await;
    }));
    poll_pending(running.as_mut());
    stop.send(()).unwrap();
    let waker = Waker::from(Arc::new(NoopWake));
    assert!(matches!(
        running.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Ok(()))
    ));
    drop(running);
    let round = reconciler.run_round(now()).await.unwrap();
    assert_eq!((round.deleted, round.updated), (1, 1));
    assert_eq!(
        observed.0.lock().unwrap().calls,
        [
            Call::Delete(vec![1]),
            Call::Delete(vec![1]),
            Call::Update(vec![(2, UpdateHint::Changed)])
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn overriding_batch_without_opt_in_retains_scalar_dispatch() {
    struct Scalar(usize);
    impl Target<Item> for Scalar {
        type Error = &'static str;
        async fn update(&mut self, _: Arc<Item>) -> Result<(), Self::Error> {
            self.0 += 1;
            Ok(())
        }
        async fn update_batch(&mut self, _: Vec<BatchUpdate<Item>>) -> Vec<BatchResult> {
            panic!("batch requires opt-in")
        }
        async fn delete(&mut self, _: Key) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.insert(Item(2)).await.unwrap();
    let mut reconciler = Reconciler::new(&table, Scalar(0), options()).unwrap();
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 2);
    assert_eq!(reconciler.target().0, 2);
}

#[tokio::test(start_paused = true)]
async fn cancelled_batch_filters_stale_inputs_before_replay() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    table.insert(Item(2)).await.unwrap();
    let target = Fake::default();
    target.0.lock().unwrap().block_updates = true;
    let observed = target.clone();
    let mut reconciler = Reconciler::new(&table, target, options()).unwrap();
    let mut cancelled = Box::pin(reconciler.run_round(now()));
    poll_pending(cancelled.as_mut());
    drop(cancelled);
    table.insert(Item(1)).await.unwrap();
    observed.0.lock().unwrap().calls.clear();
    let round = reconciler.run_round(now()).await.unwrap();
    assert_eq!((round.updated, round.stale), (1, 1));
    assert_eq!(
        observed.0.lock().unwrap().calls,
        [Call::Update(vec![(2, UpdateHint::Changed)])]
    );
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Pending);
    assert_eq!(reconciler.run_round(now()).await.unwrap().updated, 1);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Done);
}

#[tokio::test(start_paused = true)]
async fn cancelled_final_refresh_arms_next_pass_after_slow_replay_completes() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1)).await.unwrap();
    let target = Fake::default();
    let observed = target.clone();
    let mut reconciler = Reconciler::new(
        &table,
        target,
        Options {
            refresh_interval: Duration::from_secs(1),
            ..options()
        },
    )
    .unwrap();
    reconciler.run_round(now()).await.unwrap();
    advance(Duration::from_secs(1)).await;
    observed.0.lock().unwrap().block_updates = true;
    let mut cancelled = Box::pin(reconciler.run_round(now()));
    poll_pending(cancelled.as_mut());
    drop(cancelled);
    advance(Duration::from_millis(20)).await;
    observed.0.lock().unwrap().update_delay = Duration::from_millis(200);
    let mut resumed = Box::pin(reconciler.run(std::future::pending::<()>()));
    poll_pending(resumed.as_mut());
    advance(Duration::from_millis(200)).await;
    poll_pending(resumed.as_mut());
    drop(resumed);
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Done);
    assert_eq!(
        reconciler.next_refresh(),
        Some(now() + Duration::from_secs(1))
    );
    assert_eq!(table.snapshot().revision(), 1);
}
