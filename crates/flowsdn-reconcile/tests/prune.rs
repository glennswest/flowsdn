#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use flowsdn_reconcile::{Options, PruneHandle, Reconciler, Target};
use flowsdn_table::{Key, Keyed, Snapshot, StreamOptions, Table};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Wake, Waker},
    time::{Duration, Instant},
};

#[derive(Clone)]
struct Item(u8, u64);
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        vec![self.0]
    }
}

#[derive(Default)]
struct Fake {
    rows: BTreeMap<u8, u64>,
    snapshots: Vec<Vec<(u8, u64)>>,
    events: Vec<&'static str>,
    failures: u8,
    block_once: bool,
    request_during: Arc<Mutex<Option<PruneHandle>>>,
    mutate_during: Option<Arc<Table<Item>>>,
}
impl Target<Item> for Fake {
    type Error = &'static str;
    async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
        self.events.push("update");
        self.rows.insert(row.0, row.1);
        Ok(())
    }
    async fn delete(&mut self, key: Key) -> Result<(), Self::Error> {
        self.events.push("delete");
        self.rows.remove(key.first().unwrap());
        Ok(())
    }
    async fn prune(&mut self, desired: Snapshot<Item>) -> Result<(), Self::Error> {
        self.events.push("prune");
        self.snapshots
            .push(desired.all().map(|(row, _)| (row.0, row.1)).collect());
        if let Some(request) = self.request_during.lock().unwrap().take() {
            request.prune_now();
            request.prune_now();
        }
        if let Some(table) = self.mutate_during.take() {
            table.delete(&[1]).await.unwrap();
            table.insert(Item(2, 20)).await.unwrap();
            assert_eq!(
                desired
                    .all()
                    .map(|(row, _)| (row.0, row.1))
                    .collect::<Vec<_>>(),
                [(1, 10)]
            );
        }
        if self.failures > 0 {
            self.failures -= 1;
            return Err("prune fault");
        }
        self.rows
            .retain(|key, _| desired.get("primary", &[*key]).unwrap().is_some());
        if self.block_once {
            self.block_once = false;
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}

#[tokio::test]
async fn first_prune_waits_for_seal_and_every_initializer() {
    let table = Table::new(vec![]).unwrap();
    let first = table.register_initializer("first").unwrap();
    let second = table.register_initializer("second").unwrap();
    table.insert(Item(1, 10)).await.unwrap();
    let target = Fake {
        rows: BTreeMap::from([(99, 99)]),
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let now = Instant::now();
    reconciler.prune_now();
    first.complete();
    assert!(reconciler.run_round(now).await.unwrap().prune.is_none());
    table.seal_initializers();
    assert!(reconciler.run_round(now).await.unwrap().prune.is_none());
    assert!(reconciler.target().rows.contains_key(&99));
    second.complete();
    let status = reconciler.run_round(now).await.unwrap().prune.unwrap();
    assert_eq!(status.revision, 1);
    assert!(status.error.is_none());
    assert_eq!(reconciler.target().events, ["update", "prune"]);
    assert_eq!(reconciler.target().rows, BTreeMap::from([(1, 10)]));
    assert_eq!(
        reconciler.next_prune(),
        Some(now + Duration::from_secs(3600))
    );
    assert!(reconciler.run_round(now).await.unwrap().prune.is_none());
}

#[tokio::test]
async fn failures_wait_for_interval_but_coalesced_requests_can_retry_earlier() {
    let table = Table::<Item>::new(vec![]).unwrap();
    table.seal_initializers();
    let target = Fake {
        failures: 2,
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(
        &table,
        target,
        Options {
            prune_interval: Duration::from_secs(10),
            ..Options::default()
        },
    )
    .unwrap();
    let now = Instant::now();
    assert_eq!(
        reconciler
            .run_round(now)
            .await
            .unwrap()
            .prune
            .unwrap()
            .error
            .as_deref(),
        Some("prune fault")
    );
    assert!(reconciler.next_retry().is_none());
    assert!(
        reconciler
            .run_round(now + Duration::from_secs(1))
            .await
            .unwrap()
            .prune
            .is_none()
    );
    let handle = reconciler.prune_handle();
    let mut requests = Vec::new();
    for _ in 0..16 {
        let handle = handle.clone();
        requests.push(tokio::spawn(async move {
            handle.prune_now();
        }));
    }
    for request in requests {
        request.await.unwrap();
    }
    assert!(
        reconciler
            .run_round(now + Duration::from_secs(2))
            .await
            .unwrap()
            .prune
            .unwrap()
            .error
            .is_some()
    );
    assert_eq!(reconciler.target().snapshots.len(), 2);
    assert!(
        reconciler
            .run_round(now + Duration::from_secs(11))
            .await
            .unwrap()
            .prune
            .is_none()
    );
    assert!(
        reconciler
            .run_round(now + Duration::from_secs(12))
            .await
            .unwrap()
            .prune
            .unwrap()
            .error
            .is_none()
    );
    assert!(reconciler.prune_status().unwrap().error.is_none());
    assert_eq!(reconciler.target().snapshots.len(), 3);
}

#[tokio::test]
async fn resync_remains_required_after_failed_prune_until_success() {
    let table = Table::<Item>::with_stream_options(
        vec![],
        StreamOptions {
            tombstone_max_count: 1,
            ..StreamOptions::default()
        },
    )
    .unwrap();
    let target = Fake {
        rows: BTreeMap::from([(99, 1)]),
        failures: 1,
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(
        &table,
        target,
        Options {
            prune_interval: Duration::from_secs(10),
            ..Options::default()
        },
    )
    .unwrap();
    table.delete(&[1]).await.unwrap();
    table.delete(&[2]).await.unwrap();
    table.seal_initializers();
    let now = Instant::now();
    let failed = reconciler.run_round(now).await.unwrap();
    assert!(failed.resync_required);
    assert!(failed.prune.unwrap().error.is_some());
    let waiting = reconciler.run_round(now).await.unwrap();
    assert!(
        waiting.prune.is_none(),
        "a retained resync must not busy-retry failures"
    );
    assert!(waiting.resync_required);
    let success = reconciler
        .run_round(now + Duration::from_secs(10))
        .await
        .unwrap();
    assert!(success.prune.unwrap().error.is_none());
    assert!(!success.resync_required);
    assert!(reconciler.target().rows.is_empty());
}

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

#[tokio::test]
async fn cancelled_prune_replays_side_effect_and_retains_resync_obligation() {
    let table = Table::<Item>::with_stream_options(
        vec![],
        StreamOptions {
            tombstone_max_count: 0,
            ..StreamOptions::default()
        },
    )
    .unwrap();
    let target = Fake {
        rows: BTreeMap::from([(99, 1)]),
        block_once: true,
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    table.delete(&[1]).await.unwrap();
    table.seal_initializers();
    let now = Instant::now();
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut cancelled = Box::pin(reconciler.run_round(now));
    assert!(cancelled.as_mut().poll(&mut context).is_pending());
    drop(cancelled);
    assert!(reconciler.resync_required());
    assert!(reconciler.has_pending_work());
    assert!(reconciler.prune_status().is_none());
    assert!(
        reconciler.target().rows.is_empty(),
        "side effect occurred before cancellation"
    );
    assert!(reconciler.run_round(now).await.unwrap().prune.is_some());
    assert!(!reconciler.resync_required());
    assert!(!reconciler.has_pending_work());
    assert_eq!(reconciler.target().snapshots.len(), 2);
}

#[tokio::test]
async fn request_during_inflight_prune_is_preserved_for_one_more_pass() {
    let table = Table::<Item>::new(vec![]).unwrap();
    table.seal_initializers();
    let target = Fake::default();
    let request_during = target.request_during.clone();
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    *request_during.lock().unwrap() = Some(reconciler.prune_handle());
    let now = Instant::now();
    reconciler.run_round(now).await.unwrap();
    assert!(reconciler.has_pending_work());
    reconciler.run_round(now).await.unwrap();
    assert!(!reconciler.has_pending_work());
    assert!(reconciler.run_round(now).await.unwrap().prune.is_none());
    assert_eq!(reconciler.target().snapshots.len(), 2);
}

#[tokio::test]
async fn desired_changes_during_prune_use_stable_snapshot_then_converge() {
    let table = Arc::new(Table::new(vec![]).unwrap());
    table.insert(Item(1, 10)).await.unwrap();
    table.seal_initializers();
    let target = Fake {
        rows: BTreeMap::from([(99, 99)]),
        mutate_during: Some(table.clone()),
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let now = Instant::now();
    let first = reconciler.run_round(now).await.unwrap();
    assert_eq!(first.prune.unwrap().revision, 1);
    assert_eq!(table.snapshot().revision(), 3);
    assert_eq!(reconciler.target().rows, BTreeMap::from([(1, 10)]));
    reconciler.run_round(now).await.unwrap();
    assert_eq!(reconciler.target().rows, BTreeMap::from([(2, 20)]));
    assert_eq!(reconciler.attempted_revision(), 3);
}

#[tokio::test]
async fn readiness_transition_advertises_first_prune_without_an_armed_timer() {
    let table = Table::<Item>::new(vec![]).unwrap();
    let initializer = table.register_initializer("source").unwrap();
    let mut reconciler = Reconciler::new(&table, Fake::default(), Options::default()).unwrap();
    assert!(!reconciler.has_pending_work());
    assert!(reconciler.next_prune().is_none());
    table.seal_initializers();
    assert!(!reconciler.has_pending_work());
    initializer.complete();
    assert!(
        reconciler.has_pending_work(),
        "readiness must schedule the first prune"
    );
    assert!(reconciler.next_prune().is_none());
    let round = reconciler.run_round(Instant::now()).await.unwrap();
    assert!(round.prune.is_some());
    assert!(!reconciler.has_pending_work());
    assert!(reconciler.next_prune().is_some());
}
