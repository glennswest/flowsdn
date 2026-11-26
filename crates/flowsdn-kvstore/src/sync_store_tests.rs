#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;
use crate::memory::{MemoryBackend, MemoryStore};
use std::sync::atomic::{AtomicUsize, Ordering};

fn store(kv: &Arc<MemoryBackend>) -> SyncStore<MemoryBackend> {
    SyncStore::new(
        Arc::clone(kv),
        SyncConfig::new(
            "flowsdn/state/nodes/v1",
            Some("flowsdn/synced/c1/flowsdn/state/nodes/v1".into()),
        ),
    )
}

/// Let the worker run until it has nothing ready.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn upserts_deletes_and_identical_bytes_are_not_rewritten() {
    let kv = Arc::new(MemoryBackend::new());
    let sync = store(&kv);
    let worker = tokio::spawn({
        let sync = sync.clone();
        async move { sync.run().await }
    });
    sync.upsert("c1/n1", b"one".to_vec());
    sync.upsert("c1/n2", b"two".to_vec());
    settle().await;
    let dump = kv.store().dump();
    assert_eq!(dump["flowsdn/state/nodes/v1/c1/n1"].data, b"one");
    assert_ne!(dump["flowsdn/state/nodes/v1/c1/n1"].lease_id, 0, "leased");
    let writes = kv.store().writes();
    sync.upsert("c1/n1", b"one".to_vec());
    settle().await;
    assert_eq!(kv.store().writes(), writes, "identical bytes: no write");
    sync.upsert("c1/n1", b"uno".to_vec());
    sync.delete("c1/n2");
    sync.delete("c1/never");
    settle().await;
    let dump = kv.store().dump();
    assert_eq!(dump["flowsdn/state/nodes/v1/c1/n1"].data, b"uno");
    assert!(!dump.contains_key("flowsdn/state/nodes/v1/c1/n2"));
    assert_eq!(sync.names(), ["c1/n1"]);
    sync.close();
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_canary_waits_for_the_initial_list_and_runs_callbacks_once() {
    let kv = Arc::new(MemoryBackend::new());
    let sync = store(&kv);
    let done = Arc::new(AtomicUsize::new(0));
    for i in 0..300 {
        sync.upsert(&format!("c1/n{i}"), vec![1]);
    }
    let counter = Arc::clone(&done);
    sync.synced(Some(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    })));
    let worker = tokio::spawn({
        let sync = sync.clone();
        async move { sync.run().await }
    });
    // 300 writes at burst 100 and 10 qps: the canary only after all of them.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !kv.store()
            .dump()
            .contains_key("flowsdn/synced/c1/flowsdn/state/nodes/v1")
    );
    assert_eq!(done.load(Ordering::SeqCst), 0);
    tokio::time::sleep(Duration::from_secs(30)).await;
    let dump = kv.store().dump();
    assert_eq!(dump.len(), 301);
    let canary = &dump["flowsdn/synced/c1/flowsdn/state/nodes/v1"];
    assert!(
        String::from_utf8(canary.data.clone())
            .unwrap()
            .ends_with('Z')
    );
    assert_eq!(done.load(Ordering::SeqCst), 1);
    assert!(sync.stats().synced);
    // A synced() after the canary runs its callback at once.
    let counter = Arc::clone(&done);
    sync.synced(Some(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    })));
    assert_eq!(done.load(Ordering::SeqCst), 2);
    sync.close();
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_lost_lease_rewrites_the_keys_and_the_canary_without_callbacks() {
    let backend = Arc::new(MemoryStore::new().client());
    let sync = store(&backend);
    let done = Arc::new(AtomicUsize::new(0));
    let worker = tokio::spawn({
        let sync = sync.clone();
        async move { sync.run().await }
    });
    sync.upsert("c1/n1", b"one".to_vec());
    let counter = Arc::clone(&done);
    sync.synced(Some(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    })));
    settle().await;
    assert_eq!(backend.store().dump().len(), 2);
    let lease = backend.key_leases()[0];
    backend.lose_lease(lease);
    assert!(backend.store().dump().is_empty(), "the server dropped them");
    settle().await;
    let dump = backend.store().dump();
    assert_eq!(dump.len(), 2, "both rewritten: {dump:?}");
    assert_ne!(dump["flowsdn/state/nodes/v1/c1/n1"].lease_id, lease);
    assert_eq!(
        done.load(Ordering::SeqCst),
        1,
        "callbacks are not run again"
    );
    sync.close();
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_failed_write_is_retried_with_backoff() {
    let kv = Arc::new(MemoryBackend::new());
    let sync = store(&kv);
    sync.upsert("c1/n1", b"one".to_vec());
    // A closed client refuses every write.
    kv.close().await;
    let worker = tokio::spawn({
        let sync = sync.clone();
        async move { sync.run().await }
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let stats = sync.stats();
    assert!(stats.errors >= 5, "{stats:?}");
    assert_eq!(stats.pending, 1);
    assert_eq!(stats.written, 0);
    sync.close();
    worker.await.unwrap();
}
