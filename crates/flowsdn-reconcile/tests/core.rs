#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use flowsdn_reconcile::{Kind, Options, Reconciler, Target};
use flowsdn_table::{Key, Keyed, Snapshot, StreamOptions, Table};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
struct Item(u8, u64);
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        vec![self.0]
    }
}
#[derive(Default)]
struct Fake {
    rows: BTreeMap<u8, u64>,
    calls: Vec<(bool, u8)>,
    failures: BTreeMap<u8, u32>,
}
impl Fake {
    fn fail(&mut self, key: u8) -> Result<(), &'static str> {
        let failures = self.failures.entry(key).or_default();
        if *failures > 0 {
            *failures -= 1;
            Err("injected fault")
        } else {
            Ok(())
        }
    }
}
impl Target<Item> for Fake {
    type Error = &'static str;
    async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
        self.calls.push((false, row.0));
        self.fail(row.0)?;
        self.rows.insert(row.0, row.1);
        Ok(())
    }
    async fn delete(&mut self, key: Key) -> Result<(), Self::Error> {
        let key = *key.first().unwrap();
        self.calls.push((true, key));
        self.fail(key)?;
        self.rows.remove(&key);
        Ok(())
    }
    async fn prune(&mut self, desired: Snapshot<Item>) -> Result<(), Self::Error> {
        self.rows
            .retain(|key, _| desired.get("primary", &[*key]).unwrap().is_some());
        Ok(())
    }
}

#[tokio::test]
async fn bounded_rounds_keep_status_out_of_desired_rows() {
    let table = Table::new(vec![]).unwrap();
    for id in 0..5 {
        table.insert(Item(id, u64::from(id))).await.unwrap();
    }
    let mut reconciler = Reconciler::new(
        &table,
        Fake::default(),
        Options {
            round_size: 2,
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(reconciler.status(&[0]).unwrap().kind, Kind::Pending);
    let now = Instant::now();
    assert_eq!(reconciler.run_round(now).await.unwrap().updated, 2);
    assert_eq!(reconciler.run_round(now).await.unwrap().updated, 2);
    assert_eq!(reconciler.run_round(now).await.unwrap().updated, 1);
    assert_eq!(reconciler.target().rows.len(), 5);
    assert_eq!(reconciler.status(&[0]).unwrap().kind, Kind::Done);
    assert_eq!(
        table.snapshot().revision(),
        5,
        "status writes never publish desired revisions"
    );
    assert_eq!(reconciler.attempted_revision(), 5);
    table.insert(Item(0, 99)).await.unwrap();
    assert_eq!(reconciler.status(&[0]).unwrap().kind, Kind::Pending);
    reconciler.run_round(now).await.unwrap();
    assert_eq!(reconciler.target().rows.get(&0), Some(&99));
    assert_eq!(reconciler.status(&[0]).unwrap().id, 6);
}

#[tokio::test]
async fn deletes_precede_updates_in_one_live_round() {
    let table = Table::new(vec![]).unwrap();
    let mut reconciler = Reconciler::new(&table, Fake::default(), Options::default()).unwrap();
    table.insert(Item(1, 1)).await.unwrap();
    table.delete(&[8]).await.unwrap();
    table.insert(Item(2, 2)).await.unwrap();
    table.delete(&[9]).await.unwrap();
    let round = reconciler.run_round(Instant::now()).await.unwrap();
    assert_eq!((round.updated, round.deleted), (2, 2));
    assert_eq!(
        reconciler.target().calls,
        [(true, 8), (true, 9), (false, 1), (false, 2)]
    );
    assert!(
        reconciler.status(&[8]).is_none(),
        "successful deletes release status storage"
    );
}

#[tokio::test]
async fn exponential_retries_use_deadlines_cap_and_reset_on_success() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 10)).await.unwrap();
    let target = Fake {
        failures: BTreeMap::from([(1, 3)]),
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(
        &table,
        target,
        Options {
            max_backoff: Duration::from_millis(500),
            ..Options::default()
        },
    )
    .unwrap();
    let start = Instant::now();
    reconciler.run_round(start).await.unwrap();
    let status = reconciler.status(&[1]).unwrap();
    assert_eq!(status.kind, Kind::Error);
    assert_eq!(status.error.as_deref(), Some("injected fault"));
    assert_eq!(status.retries, 1);
    assert_eq!(
        reconciler.next_retry(),
        Some(start + Duration::from_millis(200))
    );
    assert_eq!(reconciler.retry_low_water_mark(), Some(1));
    assert_eq!(reconciler.attempted_revision(), 1);
    assert_eq!(
        reconciler
            .run_round(start + Duration::from_millis(199))
            .await
            .unwrap()
            .processed,
        0
    );
    reconciler
        .run_round(start + Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(
        reconciler.next_retry(),
        Some(start + Duration::from_millis(600))
    );
    reconciler
        .run_round(start + Duration::from_millis(600))
        .await
        .unwrap();
    assert_eq!(
        reconciler.next_retry(),
        Some(start + Duration::from_millis(1100))
    );
    reconciler
        .run_round(start + Duration::from_millis(1100))
        .await
        .unwrap();
    let status = reconciler.status(&[1]).unwrap();
    assert_eq!(status.kind, Kind::Done);
    assert_eq!(status.retries, 0);
    assert!(reconciler.next_retry().is_none());
    assert!(reconciler.retry_low_water_mark().is_none());
}

#[tokio::test]
async fn newer_desired_generation_clears_failure_count_and_delete_retry() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 10)).await.unwrap();
    let target = Fake {
        failures: BTreeMap::from([(1, 2)]),
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let now = Instant::now();
    reconciler.run_round(now).await.unwrap();
    table.delete(&[1]).await.unwrap();
    reconciler.run_round(now).await.unwrap();
    assert_eq!(reconciler.status(&[1]).unwrap().retries, 1);
    table.insert(Item(1, 30)).await.unwrap();
    reconciler
        .run_round(now + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(reconciler.target().rows.get(&1), Some(&30));
    assert_eq!(
        reconciler.target().calls,
        [(false, 1), (true, 1), (false, 1)]
    );
    assert!(reconciler.retry_low_water_mark().is_none());
}

struct RacingTarget {
    table: Arc<Table<Item>>,
    changed: bool,
}
impl Target<Item> for RacingTarget {
    type Error = &'static str;
    async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
        if !self.changed {
            self.changed = true;
            self.table.insert(Item(row.0, row.1 + 1)).await.unwrap();
            return Err("obsolete error");
        }
        Ok(())
    }
    async fn delete(&mut self, _: Key) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[tokio::test]
async fn result_is_discarded_when_desired_changes_during_target_await() {
    let table = Arc::new(Table::new(vec![]).unwrap());
    table.insert(Item(1, 10)).await.unwrap();
    let mut reconciler = Reconciler::new(
        &table,
        RacingTarget {
            table: table.clone(),
            changed: false,
        },
        Options::default(),
    )
    .unwrap();
    let now = Instant::now();
    assert_eq!(reconciler.run_round(now).await.unwrap().stale, 1);
    let status = reconciler.status(&[1]).unwrap();
    assert_eq!((status.kind, status.id), (Kind::Pending, 2));
    assert!(status.error.is_none());
    assert!(reconciler.retry_low_water_mark().is_none());
    reconciler.run_round(now).await.unwrap();
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Done);
}

struct NoopWaker;
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}
struct CancellableTarget {
    calls: Arc<Mutex<Vec<u8>>>,
    block_once: bool,
}
impl Target<Item> for CancellableTarget {
    type Error = &'static str;
    async fn update(&mut self, row: Arc<Item>) -> Result<(), Self::Error> {
        self.calls.lock().unwrap().push(row.0);
        if self.block_once {
            self.block_once = false;
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn delete(&mut self, _: Key) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_retains_inflight_and_remaining_drained_work() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 1)).await.unwrap();
    table.insert(Item(2, 2)).await.unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut reconciler = Reconciler::new(
        &table,
        CancellableTarget {
            calls: calls.clone(),
            block_once: true,
        },
        Options::default(),
    )
    .unwrap();
    let now = Instant::now();
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut context = Context::from_waker(&waker);
    let mut cancelled = Box::pin(reconciler.run_round(now));
    assert!(matches!(
        cancelled.as_mut().poll(&mut context),
        Poll::Pending
    ));
    drop(cancelled);
    assert!(reconciler.has_pending_work());
    assert_eq!(reconciler.attempted_revision(), 0);
    let round = reconciler.run_round(now).await.unwrap();
    assert_eq!(round.updated, 2);
    assert_eq!(*calls.lock().unwrap(), [1, 1, 2]);
    assert_eq!(reconciler.attempted_revision(), 2);
}

#[tokio::test]
async fn forced_resync_requests_prune_and_rebuilds_current_rows() {
    let table = Table::with_stream_options(
        vec![],
        StreamOptions {
            tombstone_max_count: 1,
            ..StreamOptions::default()
        },
    )
    .unwrap();
    table.insert(Item(1, 1)).await.unwrap();
    let mut reconciler = Reconciler::new(&table, Fake::default(), Options::default()).unwrap();
    let now = Instant::now();
    reconciler.run_round(now).await.unwrap();
    table.delete(&[1]).await.unwrap();
    table.delete(&[2]).await.unwrap();
    table.insert(Item(3, 3)).await.unwrap();
    let round = reconciler.run_round(now).await.unwrap();
    assert!(round.resync_required);
    assert_eq!(reconciler.target().rows.get(&3), Some(&3));
    assert!(
        reconciler.target().rows.contains_key(&1),
        "prune must wait for initialization"
    );
    table.seal_initializers();
    assert!(reconciler.run_round(now).await.unwrap().prune.is_some());
    assert!(!reconciler.target().rows.contains_key(&1));
    assert!(!reconciler.resync_required());
}

#[tokio::test]
async fn independent_reconcilers_keep_independent_status_and_retry_state() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 10)).await.unwrap();
    let mut first = Reconciler::new(&table, Fake::default(), Options::default()).unwrap();
    let mut second = Reconciler::new(
        &table,
        Fake {
            failures: BTreeMap::from([(1, 1)]),
            ..Fake::default()
        },
        Options::default(),
    )
    .unwrap();
    let now = Instant::now();
    first.run_round(now).await.unwrap();
    second.run_round(now).await.unwrap();
    assert_eq!(first.status(&[1]).unwrap().kind, Kind::Done);
    assert_eq!(second.status(&[1]).unwrap().kind, Kind::Error);
    assert!(first.retry_low_water_mark().is_none());
    assert_eq!(second.retry_low_water_mark(), Some(1));
    assert_eq!(table.snapshot().revision(), 1);
}

#[tokio::test]
async fn retry_low_water_mark_advances_independently_of_next_deadline() {
    let table = Table::new(vec![]).unwrap();
    table.insert(Item(1, 1)).await.unwrap();
    table.insert(Item(2, 2)).await.unwrap();
    let target = Fake {
        failures: BTreeMap::from([(1, 1), (2, 2)]),
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let now = Instant::now();
    reconciler.run_round(now).await.unwrap();
    assert_eq!(reconciler.retry_low_water_mark(), Some(1));
    reconciler
        .run_round(now + Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(reconciler.retry_low_water_mark(), Some(2));
    assert_eq!(
        reconciler.next_retry(),
        Some(now + Duration::from_millis(600))
    );
    reconciler
        .run_round(now + Duration::from_millis(600))
        .await
        .unwrap();
    assert!(reconciler.retry_low_water_mark().is_none());
}

#[test]
fn options_reject_rounds_and_backoffs_that_cannot_progress() {
    let table = Table::<Item>::new(vec![]).unwrap();
    for options in [
        Options {
            round_size: 0,
            ..Options::default()
        },
        Options {
            refresh_rate: 0,
            ..Options::default()
        },
        Options {
            round_interval: Duration::ZERO,
            ..Options::default()
        },
        Options {
            prune_interval: Duration::ZERO,
            ..Options::default()
        },
        Options {
            min_backoff: Duration::ZERO,
            ..Options::default()
        },
        Options {
            min_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(1),
            ..Options::default()
        },
    ] {
        assert!(Reconciler::new(&table, Fake::default(), options).is_err());
    }
}

#[tokio::test]
async fn absent_row_delete_diagnostic_is_replaced_on_next_observed_generation() {
    let table = Table::<Item>::new(vec![]).unwrap();
    let target = Fake {
        rows: BTreeMap::from([(1, 99)]),
        failures: BTreeMap::from([(1, 1)]),
        ..Fake::default()
    };
    let mut reconciler = Reconciler::new(&table, target, Options::default()).unwrap();
    let now = Instant::now();
    table.delete(&[1]).await.unwrap();
    reconciler.run_round(now).await.unwrap();
    assert_eq!(reconciler.status(&[1]).unwrap().id, 1);
    table.insert(Item(1, 2)).await.unwrap();
    assert_eq!(reconciler.status(&[1]).unwrap().kind, Kind::Pending);
    table.delete(&[1]).await.unwrap();
    // A snapshot contains no deletion generation. Until draining, this error
    // remains a diagnostic about revision 1, never proof of revision 3 state.
    let diagnostic = reconciler.status(&[1]).unwrap();
    assert_eq!((diagnostic.kind, diagnostic.id), (Kind::Error, 1));
    reconciler.run_round(now).await.unwrap();
    assert!(reconciler.status(&[1]).is_none());
    assert!(!reconciler.target().rows.contains_key(&1));
    assert!(reconciler.retry_low_water_mark().is_none());
    assert_eq!(reconciler.attempted_revision(), 3);
}
