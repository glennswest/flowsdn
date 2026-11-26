//! Lease bookkeeping (spec 20 §3.3.1, §5.5): leases with their key counts,
//! the in-process `key -> lease id` bindings, and the keepalive task of each
//! lease.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::task::AbortHandle;
use tokio::time::MissedTickBehavior;

use super::proto::{LeaseKeepAliveRequest, LeaseKeepAliveResponse};
use super::{Inner, LEASE_KEEPALIVE, LeaseKind, grpc};

struct Entry {
    keys: usize,
    task: Option<AbortHandle>,
}

#[derive(Default)]
struct State {
    leases: HashMap<i64, Entry>,
    current: Option<i64>,
    bindings: HashMap<String, i64>,
}

/// One lease manager: the key leases (up to `per_lease` keys each) or the
/// lock lease (one, unbounded).
pub(crate) struct Leases {
    /// The TTL leases are granted with.
    pub(crate) ttl: Duration,
    per_lease: usize,
    state: Mutex<State>,
    /// Single-flight grants (§5.5).
    pub(crate) grant: tokio::sync::Mutex<()>,
}

impl Leases {
    pub(crate) fn new(ttl: Duration, per_lease: usize) -> Self {
        Self {
            ttl,
            per_lease,
            state: Mutex::new(State::default()),
            grant: tokio::sync::Mutex::new(()),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The lease `key` is (or now gets) bound to, without granting: its
    /// binding, else the current lease with room, else any lease with room.
    /// `None` key: a lease without binding anything.
    pub(crate) fn try_bind(&self, key: Option<&str>) -> Option<i64> {
        let mut guard = self.state();
        let state = &mut *guard;
        if let Some(id) = key.and_then(|key| state.bindings.get(key)) {
            return Some(*id);
        }
        let per_lease = self.per_lease;
        let room = |id: i64, entry: &Entry| entry.keys < per_lease && id != 0;
        let id = match state.current {
            Some(current) if state.leases.get(&current).is_some_and(|e| room(current, e)) => {
                current
            }
            _ => state
                .leases
                .iter()
                .find(|&(id, entry)| room(*id, entry))
                .map(|(id, _)| *id)?,
        };
        state.current = Some(id);
        if let Some(key) = key {
            state.bindings.insert(key.to_owned(), id);
            if let Some(entry) = state.leases.get_mut(&id) {
                entry.keys = entry.keys.saturating_add(1);
            }
        }
        Some(id)
    }

    /// A freshly granted lease becomes the current one.
    pub(crate) fn insert(&self, id: i64) {
        let mut state = self.state();
        state.leases.insert(id, Entry { keys: 0, task: None });
        state.current = Some(id);
    }

    /// Attach the keepalive task; aborts it when the lease is already gone.
    pub(crate) fn set_task(&self, id: i64, task: AbortHandle) {
        let mut state = self.state();
        match state.leases.get_mut(&id) {
            Some(entry) => entry.task = Some(task),
            None => task.abort(),
        }
    }

    /// Forget `key`'s binding (delete, or an unleased write).
    pub(crate) fn release(&self, key: &str) {
        let mut guard = self.state();
        let state = &mut *guard;
        if let Some(id) = state.bindings.remove(key)
            && let Some(entry) = state.leases.get_mut(&id)
        {
            entry.keys = entry.keys.saturating_sub(1);
        }
    }

    /// Forget every binding under `prefix` (`delete_prefix`).
    pub(crate) fn release_prefix(&self, prefix: &str) {
        let mut guard = self.state();
        let state = &mut *guard;
        let keys: Vec<String> = state
            .bindings
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        for key in keys {
            if let Some(id) = state.bindings.remove(&key)
                && let Some(entry) = state.leases.get_mut(&id)
            {
                entry.keys = entry.keys.saturating_sub(1);
            }
        }
    }

    /// Drop lease `id` and its bindings, stopping its keepalive; the keys
    /// that were bound to it, sorted.
    pub(crate) fn remove(&self, id: i64) -> Vec<String> {
        let mut guard = self.state();
        let state = &mut *guard;
        if let Some(entry) = state.leases.remove(&id)
            && let Some(task) = entry.task
        {
            task.abort();
        }
        if state.current == Some(id) {
            state.current = None;
        }
        let mut keys: Vec<String> = state
            .bindings
            .iter()
            .filter(|(_, bound)| **bound == id)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &keys {
            state.bindings.remove(key);
        }
        keys.sort();
        keys
    }

    /// Stop every keepalive and forget everything; the lease ids.
    pub(crate) fn drain(&self) -> Vec<i64> {
        let mut state = self.state();
        state.current = None;
        state.bindings.clear();
        let mut ids = Vec::new();
        for (id, entry) in state.leases.drain() {
            if let Some(task) = entry.task {
                task.abort();
            }
            ids.push(id);
        }
        ids
    }

    /// The number of leases held.
    pub(crate) fn count(&self) -> usize {
        self.state().leases.len()
    }
}

/// The keepalive task of one lease: a `LeaseKeepAlive` stream with a request
/// every TTL/3. When the stream ends, fails or reports TTL <= 0 while the
/// client is open, the lease is lost (§3.3.1).
pub(crate) async fn keepalive(inner: Arc<Inner>, kind: LeaseKind, id: i64, ttl: Duration) {
    let reason = run(&inner, id, ttl).await;
    if inner.is_closed() {
        return;
    }
    eprintln!("warning: kvstore: {} lease {id:x} lost: {reason}", kind.name());
    inner.lose_lease(kind, id);
}

async fn run(inner: &Inner, id: i64, ttl: Duration) -> String {
    let period = ttl
        .checked_div(3)
        .unwrap_or(ttl)
        .max(Duration::from_millis(100));
    let request = LeaseKeepAliveRequest { id };
    let channel = match inner.channel().await {
        Ok(channel) => channel,
        Err(e) => return e.to_string(),
    };
    let (mut send, mut receive) = match channel
        .open(LEASE_KEEPALIVE, &[], grpc::frame(&request), false)
        .await
    {
        Ok(stream) => stream,
        Err(e) => return e.to_string(),
    };
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first tick is immediate; the first request is already sent.
    tick.tick().await;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Err(e) = send.send(grpc::frame(&request), false).await {
                    return e.to_string();
                }
            },
            message = receive.recv::<LeaseKeepAliveResponse>() => match message {
                Ok(Some(response)) if response.ttl <= 0 => {
                    return "the server reports TTL 0: lease not found".into();
                }
                Ok(Some(_)) => {}
                Ok(None) => return "keepalive stream ended".into(),
                Err(e) => return e.to_string(),
            },
            () = inner.wait_closed() => return "client closed".into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn binds_up_to_per_lease_then_needs_a_grant() {
        let leases = Leases::new(Duration::from_secs(60), 2);
        assert_eq!(leases.try_bind(Some("a")), None);
        leases.insert(10);
        assert_eq!(leases.try_bind(Some("a")), Some(10));
        assert_eq!(leases.try_bind(Some("a")), Some(10));
        assert_eq!(leases.try_bind(Some("b")), Some(10));
        assert_eq!(leases.try_bind(Some("c")), None);
        leases.insert(11);
        assert_eq!(leases.try_bind(Some("c")), Some(11));
        // A released slot on 10 is reused once 11 fills.
        leases.release("a");
        assert_eq!(leases.try_bind(Some("d")), Some(11));
        assert_eq!(leases.try_bind(Some("e")), Some(10));
        assert_eq!(leases.count(), 2);
        assert_eq!(leases.remove(11), vec!["c".to_owned(), "d".to_owned()]);
        assert_eq!(leases.try_bind(Some("c")), None);
        leases.release_prefix("");
        assert_eq!(leases.try_bind(Some("c")), Some(10));
        assert_eq!(leases.try_bind(None), Some(10));
        assert_eq!(leases.drain(), vec![10]);
        assert_eq!(leases.count(), 0);
    }
}
