#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[tokio::test]
async fn reads_writes_and_revisions() {
    let kv = MemoryBackend::new();
    assert_eq!(kv.get("a", None).await, Ok(None));
    kv.put("a", b"1".to_vec(), Lease::None, None).await.unwrap();
    let first = kv.get("a", None).await.unwrap().unwrap();
    assert_eq!((first.data.as_slice(), first.lease_id), (&b"1"[..], 0));
    kv.put("a", b"2".to_vec(), Lease::None, None).await.unwrap();
    let second = kv.get("a", None).await.unwrap().unwrap();
    assert_eq!(second.create_revision, first.create_revision);
    assert!(second.mod_revision > first.mod_revision);
    assert!(!kv.put_if_absent("a", b"x".to_vec(), Lease::None, None).await.unwrap());
    assert!(kv.put_if_absent("b", b"x".to_vec(), Lease::None, None).await.unwrap());
    // Same bytes, same (no) lease: not rewritten; a lease change is.
    let writes = kv.store().writes();
    assert!(!kv.put_if_different("a", b"2".to_vec(), Lease::None, None).await.unwrap());
    assert_eq!(kv.store().writes(), writes);
    assert!(kv.put_if_different("a", b"2".to_vec(), Lease::Attached, None).await.unwrap());
    assert!(!kv.put_if_different("a", b"2".to_vec(), Lease::Attached, None).await.unwrap());
    kv.put("p/1", vec![], Lease::None, None).await.unwrap();
    kv.put("p/2", vec![], Lease::None, None).await.unwrap();
    kv.put("q", vec![], Lease::None, None).await.unwrap();
    let listed: Vec<String> = kv.list_prefix("p/", None).await.unwrap().into_keys().collect();
    assert_eq!(listed, ["p/1", "p/2"]);
    kv.delete_prefix("p/").await.unwrap();
    assert!(kv.list_prefix("p/", None).await.unwrap().is_empty());
    kv.delete("missing", None).await.unwrap();
    assert!(matches!(
        kv.put("big", vec![0; crate::MAX_VALUE + 1], Lease::None, None).await,
        Err(Error::TooLarge { .. })
    ));
}

#[tokio::test]
async fn watches_list_then_follow() {
    let kv = MemoryBackend::new();
    kv.put("w/a", b"1".to_vec(), Lease::None, None).await.unwrap();
    kv.put("wx", b"no".to_vec(), Lease::None, None).await.unwrap();
    let mut events = kv.watch("w/").await.unwrap();
    let first = events.recv().await.unwrap();
    assert_eq!((first.kind, first.key.as_str()), (EventKind::Create, "w/a"));
    assert_eq!(events.recv().await.unwrap().kind, EventKind::ListDone);
    kv.put("w/a", b"2".to_vec(), Lease::None, None).await.unwrap();
    kv.put("w/b", b"3".to_vec(), Lease::None, None).await.unwrap();
    kv.put("wx", b"still no".to_vec(), Lease::None, None).await.unwrap();
    kv.delete("w/a", None).await.unwrap();
    let kinds: Vec<(EventKind, String)> = (0..3)
        .map(|_| events.try_recv().unwrap())
        .map(|e| (e.kind, e.key))
        .collect();
    assert_eq!(
        kinds,
        [
            (EventKind::Modify, "w/a".to_owned()),
            (EventKind::Create, "w/b".to_owned()),
            (EventKind::Delete, "w/a".to_owned())
        ]
    );
    assert!(events.try_recv().is_err());
    kv.close().await;
    assert!(events.recv().await.is_none(), "closing ends the watch");
}

#[tokio::test]
async fn leases_bind_keys_and_loss_calls_observers() {
    let store = MemoryStore::new();
    let kv = store.client();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    kv.lease_expired(
        "data/",
        Some(Arc::new(move |key: &str| sink.lock().unwrap().push(key.to_owned()))),
    );
    kv.put("data/a", b"1".to_vec(), Lease::Attached, None).await.unwrap();
    kv.put("data/b", b"1".to_vec(), Lease::Attached, None).await.unwrap();
    kv.put("other", b"1".to_vec(), Lease::Attached, None).await.unwrap();
    kv.put("plain", b"1".to_vec(), Lease::None, None).await.unwrap();
    let lease = kv.lease_for("data/a").await.unwrap();
    assert_eq!(kv.key_leases(), [lease], "one lease until it holds 1000 keys");
    assert_eq!(kv.get("data/a", None).await.unwrap().unwrap().lease_id, lease);
    kv.lose_lease(lease);
    assert_eq!(*seen.lock().unwrap(), ["data/a", "data/b"]);
    assert_eq!(store.dump().keys().collect::<Vec<_>>(), ["plain"]);
    // The next leased write gets a new lease.
    kv.put("data/a", b"1".to_vec(), Lease::Attached, None).await.unwrap();
    assert_ne!(kv.lease_for("data/a").await.unwrap(), lease);
    // A thousand keys fill a lease; the next one takes another.
    for i in 0..crate::KEYS_PER_LEASE {
        kv.put(&format!("many/{i}"), vec![], Lease::Attached, None).await.unwrap();
    }
    assert_eq!(kv.key_leases().len(), 2);
    // Closing revokes this client's leases: its leased keys go.
    kv.close().await;
    assert_eq!(store.dump().keys().collect::<Vec<_>>(), ["plain"]);
    assert_eq!(kv.get("plain", None).await, Err(Error::Closed));
}

#[tokio::test]
async fn transactions_compare_then_write() {
    let kv = MemoryBackend::new();
    let put = |key: &str| TxnPut {
        key: key.into(),
        data: b"v".to_vec(),
        lease: Lease::None,
    };
    assert!(kv.txn(vec![Compare::Absent("o".into())], vec![put("o"), put("c")]).await.unwrap());
    assert!(!kv.txn(vec![Compare::Absent("o".into())], vec![put("x")]).await.unwrap());
    assert_eq!(kv.get("x", None).await, Ok(None), "a failed compare writes nothing");
    let stored = kv.get("o", None).await.unwrap().unwrap();
    let exact = |rev| Compare::Exact {
        key: "o".into(),
        data: b"v".to_vec(),
        mod_revision: rev,
        lease_id: 0,
    };
    assert!(!kv.txn(vec![exact(stored.mod_revision + 1)], vec![put("x")]).await.unwrap());
    assert!(kv.txn(vec![exact(stored.mod_revision)], vec![put("x")]).await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn locks_exclude_and_guard() {
    let store = MemoryStore::new();
    let (a, b) = (Arc::new(store.client()), Arc::new(store.client()));
    let guard = a.lock("locks/x").await.unwrap();
    assert!(guard.key.starts_with("locks/x/"));
    a.put("g", b"1".to_vec(), Lease::None, Some(&guard)).await.unwrap();
    let held = Arc::new(AtomicUsize::new(0));
    let waiter = {
        let (b, held) = (Arc::clone(&b), Arc::clone(&held));
        tokio::spawn(async move {
            let g = b.lock("locks/x").await.unwrap();
            held.store(1, Ordering::SeqCst);
            g
        })
    };
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(held.load(Ordering::SeqCst), 0, "b waits while a holds it");
    a.unlock(&guard).await.unwrap();
    let second = waiter.await.unwrap();
    assert_eq!(held.load(Ordering::SeqCst), 1);
    // a's guard no longer holds: guarded operations fail distinguishably.
    assert_eq!(
        a.put("g", b"2".to_vec(), Lease::None, Some(&guard)).await,
        Err(Error::LockLeaseExpired)
    );
    assert_eq!(a.get("g", Some(&guard)).await, Err(Error::LockLeaseExpired));
    // A lock not released in time is a timeout, and leaves no key behind.
    let error = a.lock("locks/x").await;
    assert_eq!(error, Err(Error::LockTimeout("locks/x".into())));
    assert_eq!(a.list_prefix("locks/x/", None).await.unwrap().len(), 1);
    b.unlock(&second).await.unwrap();
}
