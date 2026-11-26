//! List-then-watch with relist (spec 20 §5.4): the paginated list, Create /
//! Modify for listed keys, synthetic Delete for cached keys gone meanwhile,
//! `ListDone` once, then a Watch stream from the list revision + 1. Any watch
//! error or cancellation (compaction included) relists; a stream that ends
//! cleanly is recreated after 50 ms; every `resync_interval` relists too
//! (§5.4.4).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::proto::{EVENT_DELETE, WatchCreateRequest, WatchRequest, WatchResponse};
use super::{HASLEADER, Inner, WATCH, grpc, key_string, to_value};
use crate::{Error, Event, EventKind, prefix_end};

const MIN_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const RECREATE_DELAY: Duration = Duration::from_millis(50);

enum Outcome {
    /// The receiver or the client is gone.
    Stop,
    /// The stream ended without an error: recreate it.
    Ended,
    /// The resync interval elapsed: relist.
    Resync,
    /// A watch error or cancellation: relist after the backoff.
    Failed(Error),
}

fn next_backoff(backoff: Duration) -> Duration {
    backoff.saturating_mul(2).min(MAX_BACKOFF)
}

/// Sleep `wait`; false when the receiver or the client went away.
async fn pause(inner: &Inner, tx: &mpsc::Sender<Event>, wait: Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(wait) => !inner.is_closed(),
        () = tx.closed() => false,
        () = inner.wait_closed() => false,
    }
}

/// The watcher task of one prefix.
pub(crate) async fn run(inner: Arc<Inner>, prefix: String, tx: mpsc::Sender<Event>) {
    let mut cache: BTreeSet<String> = BTreeSet::new();
    let mut list_done = false;
    let mut backoff = MIN_BACKOFF;
    loop {
        if inner.is_closed() || tx.is_closed() {
            return;
        }
        let listing = {
            let _permit = inner.limiter.acquire().await;
            inner.paginated(&prefix, None).await
        };
        let (kvs, mut revision) = match listing {
            Ok(listing) => listing,
            Err(Error::Closed) => return,
            Err(e) => {
                eprintln!("warning: kvstore: list {prefix}: {e}; retrying in {backoff:?}");
                if !pause(&inner, &tx, backoff).await {
                    return;
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };
        let mut stale = cache.clone();
        for (key, value) in kvs {
            stale.remove(&key);
            let kind = if cache.insert(key.clone()) {
                EventKind::Create
            } else {
                EventKind::Modify
            };
            let event = Event {
                kind,
                key,
                value: Some(value),
            };
            if tx.send(event).await.is_err() {
                return;
            }
        }
        for key in stale {
            cache.remove(&key);
            let event = Event {
                kind: EventKind::Delete,
                key,
                value: None,
            };
            if tx.send(event).await.is_err() {
                return;
            }
        }
        if !list_done {
            list_done = true;
            let event = Event {
                kind: EventKind::ListDone,
                key: String::new(),
                value: None,
            };
            if tx.send(event).await.is_err() {
                return;
            }
        }
        let interval = inner.config.resync_interval;
        let resync_at = if interval.is_zero() {
            None
        } else {
            Instant::now().checked_add(interval)
        };
        loop {
            let outcome = watch_once(
                &inner,
                &prefix,
                &mut revision,
                &mut cache,
                &tx,
                resync_at,
                &mut backoff,
            )
            .await;
            match outcome {
                Outcome::Stop => return,
                Outcome::Ended => {
                    if !pause(&inner, &tx, RECREATE_DELAY).await {
                        return;
                    }
                }
                Outcome::Resync => break,
                Outcome::Failed(Error::Closed) => return,
                Outcome::Failed(e) => {
                    eprintln!("warning: kvstore: watch {prefix}: {e}; relisting in {backoff:?}");
                    if !pause(&inner, &tx, backoff).await {
                        return;
                    }
                    backoff = next_backoff(backoff);
                    break;
                }
            }
        }
    }
}

/// Wait until `at` (forever when `None`).
async fn until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// One Watch stream from `revision + 1` (one limiter token per attempt).
async fn watch_once(
    inner: &Inner,
    prefix: &str,
    revision: &mut i64,
    cache: &mut BTreeSet<String>,
    tx: &mpsc::Sender<Event>,
    resync_at: Option<Instant>,
    backoff: &mut Duration,
) -> Outcome {
    inner.limiter.token().await;
    let request = WatchRequest::create(WatchCreateRequest {
        key: prefix.as_bytes().to_vec(),
        range_end: prefix_end(prefix.as_bytes()),
        start_revision: revision.saturating_add(1),
        ..Default::default()
    });
    let channel = match inner.channel().await {
        Ok(channel) => channel,
        Err(e) => return Outcome::Failed(e),
    };
    let (_send, mut receive) = match channel
        .open(WATCH, &[HASLEADER], grpc::frame(&request), false)
        .await
    {
        Ok(stream) => stream,
        Err(e) => return Outcome::Failed(e),
    };
    loop {
        let message = tokio::select! {
            message = receive.recv::<WatchResponse>() => message,
            () = until(resync_at) => return Outcome::Resync,
            () = tx.closed() => return Outcome::Stop,
            () = inner.wait_closed() => return Outcome::Stop,
        };
        let response = match message {
            Ok(Some(response)) => response,
            Ok(None) => return Outcome::Ended,
            Err(e) => return Outcome::Failed(e),
        };
        if response.canceled || response.compact_revision != 0 {
            return Outcome::Failed(Error::Backend(format!(
                "watch canceled (compact revision {}): {}",
                response.compact_revision, response.cancel_reason
            )));
        }
        if response.created {
            *backoff = MIN_BACKOFF;
        }
        for event in response.events {
            let Some(kv) = event.kv else {
                continue;
            };
            if kv.mod_revision > *revision {
                *revision = kv.mod_revision;
            }
            let key = key_string(&kv.key);
            let event = if event.kind == EVENT_DELETE {
                cache.remove(&key);
                Event {
                    kind: EventKind::Delete,
                    key,
                    value: None,
                }
            } else {
                let kind = if kv.version == 1 {
                    EventKind::Create
                } else {
                    EventKind::Modify
                };
                cache.insert(key.clone());
                Event {
                    kind,
                    key,
                    value: Some(to_value(kv)),
                }
            };
            if tx.send(event).await.is_err() {
                return Outcome::Stop;
            }
        }
    }
}
