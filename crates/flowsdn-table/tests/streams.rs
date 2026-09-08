#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use flowsdn_table::{Change, Index, Key, Keyed, StreamOptions, Table};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    task::{Context, Poll, Wake, Waker},
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Item(u8, u64);
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        vec![self.0]
    }
}

fn inserts(changes: Vec<Change<Item>>) -> Vec<(u8, u64, u64)> {
    changes.into_iter().map(|change| match change {
        Change::Insert { row, revision } => (row.0, row.1, revision),
        other => panic!("expected insert, got {other:?}"),
    }).collect()
}

#[tokio::test]
async fn initial_population_precedes_live_changes_and_coalesces() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(9, 1)).await.unwrap();
    table.insert(Item(2, 2)).await.unwrap();
    let mut stream = table.watch(0);
    table.insert(Item(9, 3)).await.unwrap();
    assert!(stream.drain(0).is_empty());
    assert_eq!(inserts(stream.drain(1)), [(9, 1, 1)]);
    assert_eq!(stream.ack(u64::MAX), 0, "partial population is not a checkpoint");
    assert_eq!(inserts(stream.drain(10)), [(2, 2, 2)]);
    for value in 4..104 {
        table.insert(Item(9, value)).await.unwrap();
    }
    assert_eq!(inserts(stream.drain(10)), [(9, 103, 103)]);
    assert_eq!(stream.ack(stream.revision()), 103);
    assert!(stream.drain(10).is_empty());
}

#[tokio::test]
async fn deletion_order_absent_keys_reinsert_and_partial_batches() {
    let table = Table::new(vec![]).unwrap();
    let mut stream = table.watch(0);
    table.batch(|w| {
        w.insert(Item(1, 0)).unwrap();
        w.insert(Item(2, 0)).unwrap();
        w.delete(&[1]).unwrap();
        w.delete(&[99]).unwrap();
        w.insert(Item(1, 9)).unwrap();
    }).await;
    assert_eq!(table.tombstone_count(), 1);
    assert_eq!(inserts(stream.drain(1)), [(2, 0, 2)]);
    assert!(matches!(stream.drain(1).as_slice(), [Change::Delete { key, revision: 4 }] if key == &[99]));
    assert_eq!(inserts(stream.drain(1)), [(1, 9, 5)]);
    assert!(stream.drain(1).is_empty());
    assert_eq!(stream.revision(), 5);
}

#[tokio::test]
async fn failed_writes_do_not_notify_but_successful_batch_prefix_does() {
    let table = Table::new(vec![Index::new("value", true, |item: &Item| vec![item.1.to_be_bytes().to_vec()])]).unwrap();
    table.insert(Item(1, 1)).await.unwrap();
    let mut stream = table.watch(1);
    assert!(table.insert(Item(2, 1)).await.is_err());
    assert!(stream.drain(1).is_empty());
    let result = table.batch(|w| {
        w.insert(Item(2, 2))?;
        w.insert(Item(3, 1))
    }).await;
    assert!(result.is_err());
    assert_eq!(inserts(stream.drain(10)), [(2, 2, 2)]);
}

#[tokio::test]
async fn lagging_subscriber_resyncs_without_disrupting_fast_subscriber() {
    let table = Table::with_stream_options(vec![], StreamOptions {
        tombstone_max_count: 2,
        ..StreamOptions::default()
    }).unwrap();
    table.insert(Item(1, 1)).await.unwrap();
    let mut slow = table.watch(1);
    let mut fast = table.watch(1);
    for id in 10..13 {
        table.delete(&[id]).await.unwrap();
        assert!(matches!(fast.drain(1).as_slice(), [Change::Delete { .. }]));
        fast.ack(fast.revision());
    }
    let changes = slow.drain(10);
    assert!(matches!(changes.first(), Some(Change::Resync { revision: 4 })));
    assert!(matches!(changes.get(1), Some(Change::Insert { row, revision: 1 }) if row.0 == 1));
    assert!(table.tombstone_count() <= 2);
    let mut old = table.watch(1);
    assert!(matches!(old.drain(1).as_slice(), [Change::Resync { .. }]));
    let mut initial = table.watch(0);
    assert_eq!(inserts(initial.drain(10)), [(1, 1, 1)]);
}

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn sleeping_reader_wakes_and_cancelled_wait_loses_nothing() {
    let table = Table::new(vec![]).unwrap();
    let unrelated = Table::new(vec![]).unwrap();
    let mut stream = table.watch(0);
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut context = Context::from_waker(&waker);
    let mut next = Box::pin(stream.next());
    assert!(next.as_mut().poll(&mut context).is_pending());
    unrelated.insert(Item(9, 9)).await.unwrap();
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    table.insert(Item(1, 1)).await.unwrap();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(next.as_mut().poll(&mut context), Poll::Ready(Some(Change::Insert { revision: 1, .. }))));
    drop(next);
    let mut cancelled = Box::pin(stream.next());
    assert!(cancelled.as_mut().poll(&mut context).is_pending());
    drop(cancelled);
    table.insert(Item(2, 2)).await.unwrap();
    assert!(matches!(stream.next().await, Some(Change::Insert { revision: 2, .. })));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn racing_subscription_cannot_miss_publication() {
    for _ in 0..100 {
        let table = Arc::new(Table::new(vec![]).unwrap());
        let writer = table.clone();
        let task = tokio::spawn(async move { writer.insert(Item(1, 7)).await.unwrap() });
        let mut stream = table.watch(0);
        task.await.unwrap();
        let mut rows = inserts(stream.drain(10));
        rows.extend(inserts(stream.drain(10)));
        assert_eq!(rows, [(1, 7, 1)]);
    }
}

#[tokio::test]
async fn random_stream_mirror_converges_through_forced_resyncs() {
    let table = Table::with_stream_options(vec![], StreamOptions {
        tombstone_max_count: 3,
        ..StreamOptions::default()
    }).unwrap();
    let mut stream = table.watch(0);
    let mut mirror = BTreeMap::new();
    let mut seed = 17_u64;
    for round in 0..500_u64 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let id = (seed >> 32) as u8 % 20;
        if seed.is_multiple_of(3) {
            table.delete(&[id]).await.unwrap();
        } else {
            table.insert(Item(id, round)).await.unwrap();
        }
        if round.is_multiple_of(19) || round == 499 {
            loop {
                let changes = stream.drain(2);
                if changes.is_empty() { break; }
                for change in changes {
                    match change {
                        Change::Insert { row, .. } => { mirror.insert(row.0, row.1); }
                        Change::Delete { key, .. } => { mirror.remove(key.first().unwrap()); }
                        Change::Resync { .. } => mirror.clear(),
                    }
                }
            }
            stream.ack(stream.revision());
            let desired: BTreeMap<_, _> = table.snapshot().all().map(|(row, _)| (row.0, row.1)).collect();
            assert_eq!(mirror, desired, "round {round}");
        }
    }
}
