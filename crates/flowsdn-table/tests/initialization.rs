#![allow(clippy::unwrap_used)]
use flowsdn_table::{InitializationError, Key, Keyed, Table};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

#[derive(Clone)]
struct Item(u8);
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        vec![self.0]
    }
}

#[tokio::test]
async fn empty_table_requires_sealing_and_readiness_is_sticky() {
    let table = Table::<Item>::new(vec![]).unwrap();
    assert!(!table.initialized());
    assert!(table.pending_initializers().is_empty());
    table.seal_initializers();
    assert!(table.initialized());
    table.wait_initialized().await;
    table.seal_initializers();
    assert!(table.initialized());
    assert_eq!(
        table.register_initializer("late").unwrap_err(),
        InitializationError::Sealed
    );
    assert_eq!(table.snapshot().revision(), 0);
}

#[tokio::test]
async fn completion_before_seal_does_not_close_registration() {
    let table = Table::<Item>::new(vec![]).unwrap();
    let first = table.register_initializer("first").unwrap();
    assert_eq!(first.name(), "first");
    assert!(first.complete());
    assert!(!first.complete());
    assert!(!table.initialized());
    assert_eq!(
        table.register_initializer("first").unwrap_err(),
        InitializationError::DuplicateName("first".to_owned())
    );
    assert_eq!(
        table.register_initializer(" \t").unwrap_err(),
        InitializationError::EmptyName
    );
    let second = table.register_initializer("second").unwrap();
    table.seal_initializers();
    assert_eq!(table.pending_initializers(), ["second"]);
    assert!(!table.initialized());
    assert!(second.complete());
    table.wait_initialized().await;
    assert!(table.initialized());
}

#[test]
fn dropped_producer_is_not_success() {
    let table = Table::<Item>::new(vec![]).unwrap();
    let abandoned = table.register_initializer("z-abandoned").unwrap();
    let other = table.register_initializer("a-other").unwrap();
    table.seal_initializers();
    drop(abandoned);
    assert_eq!(table.pending_initializers(), ["a-other", "z-abandoned"]);
    other.complete();
    assert!(!table.initialized());
    assert_eq!(table.pending_initializers(), ["z-abandoned"]);
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

#[test]
fn cancelling_one_waiter_preserves_other_waiters_and_source_progress() {
    let table = Table::<Item>::new(vec![]).unwrap();
    let first = table.register_initializer("first").unwrap();
    let second = table.register_initializer("second").unwrap();
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut context = Context::from_waker(&waker);
    let mut cancelled = Box::pin(table.wait_initialized());
    let mut surviving = Box::pin(table.wait_initialized());
    assert!(cancelled.as_mut().poll(&mut context).is_pending());
    assert!(surviving.as_mut().poll(&mut context).is_pending());
    table.seal_initializers();
    first.complete();
    drop(cancelled);
    assert!(!table.initialized());
    assert!(surviving.as_mut().poll(&mut context).is_pending());
    second.complete();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert_eq!(surviving.as_mut().poll(&mut context), Poll::Ready(()));
    assert!(table.pending_initializers().is_empty());
    let mut late_waiter = Box::pin(table.wait_initialized());
    assert_eq!(late_waiter.as_mut().poll(&mut context), Poll::Ready(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_waiters_observe_rows_published_before_source_completion() {
    let table = Arc::new(Table::<Item>::new(vec![]).unwrap());
    let first = table.register_initializer("first").unwrap();
    let second = table.register_initializer("second").unwrap();
    table.seal_initializers();
    let mut waiters = Vec::new();
    for _ in 0..8 {
        let table = table.clone();
        waiters.push(tokio::spawn(async move {
            table.wait_initialized().await;
            table
                .snapshot()
                .all()
                .map(|(row, _)| row.0)
                .collect::<Vec<_>>()
        }));
    }
    let first_table = table.clone();
    let first_source = tokio::spawn(async move {
        first_table.insert(Item(1)).await.unwrap();
        first.complete();
    });
    let second_table = table.clone();
    let second_source = tokio::spawn(async move {
        second_table.insert(Item(2)).await.unwrap();
        second.complete();
    });
    first_source.await.unwrap();
    second_source.await.unwrap();
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap(), [1, 2]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_racing_seal_never_reopens_readiness() {
    for _ in 0..100 {
        let table = Arc::new(Table::<Item>::new(vec![]).unwrap());
        let gate = Arc::new(tokio::sync::Barrier::new(3));
        let registering_table = table.clone();
        let registering_gate = gate.clone();
        let registration = tokio::spawn(async move {
            registering_gate.wait().await;
            registering_table.register_initializer("racing")
        });
        let sealing_table = table.clone();
        let sealing_gate = gate.clone();
        let sealing = tokio::spawn(async move {
            sealing_gate.wait().await;
            sealing_table.seal_initializers();
        });
        gate.wait().await;
        let registration = registration.await.unwrap();
        sealing.await.unwrap();
        match registration {
            Ok(handle) => {
                assert!(!table.initialized());
                handle.complete();
            }
            Err(InitializationError::Sealed) => assert!(table.initialized()),
            Err(other) => panic!("unexpected registration error: {other}"),
        }
        table.wait_initialized().await;
        assert!(table.initialized());
    }
}
