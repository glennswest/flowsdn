//! An in-process kvstore (spec 20 §11.1, §3.1 rule 5): a [`MemoryStore`]
//! with etcd's revision model (global revision, per-key create/mod revision
//! and version, leases), and [`MemoryBackend`] clients of it implementing
//! [`Kvstore`]. Several clients of one store behave like several processes
//! on one etcd: their own key leases, lock lease and lease observers.
//!
//! It is the store unit tests and the scripttest harness use. Watches never
//! break, so there is no relist; [`MemoryBackend::lose_lease`] stands in for
//! a keepalive failure (§3.3.1).
use crate::{
    Compare, Error, Event, EventKind, Guard, KEYS_PER_LEASE, Kvstore, LOCK_TIMEOUT, Lease,
    Observer, Result, State, Status, TxnPut, Value, check_size,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::{Notify, mpsc};

/// Watch channel depth; a watcher that falls this far behind is dropped.
const WATCH_DEPTH: usize = 65_536;

#[derive(Clone, Debug)]
struct Entry {
    data: Vec<u8>,
    create_revision: i64,
    mod_revision: i64,
    version: i64,
    lease: i64,
}
impl Entry {
    fn value(&self) -> Value {
        Value {
            data: self.data.clone(),
            mod_revision: self.mod_revision,
            create_revision: self.create_revision,
            lease_id: self.lease,
        }
    }
}

struct Watcher {
    /// The client's lock lease, which identifies it.
    owner: i64,
    prefix: String,
    tx: mpsc::Sender<Event>,
}

#[derive(Default)]
struct Server {
    revision: i64,
    kv: BTreeMap<String, Entry>,
    next_lease: i64,
    live: BTreeSet<i64>,
    watchers: Vec<Watcher>,
    writes: u64,
}
impl Server {
    fn grant(&mut self) -> i64 {
        self.next_lease = self.next_lease.saturating_add(1);
        let id = 0x6a00_0000_0000_0000_i64.saturating_add(self.next_lease);
        self.live.insert(id);
        id
    }
    fn emit(&mut self, event: &Event) {
        self.watchers.retain(|w| {
            if !event.key.starts_with(&w.prefix) {
                return !w.tx.is_closed();
            }
            w.tx.try_send(event.clone()).is_ok()
        });
    }
    fn put(&mut self, key: &str, data: Vec<u8>, lease: i64) -> Result<()> {
        if lease != 0 && !self.live.contains(&lease) {
            return Err(Error::LeaseNotFound(lease));
        }
        self.revision = self.revision.saturating_add(1);
        self.writes = self.writes.saturating_add(1);
        let revision = self.revision;
        let entry = match self.kv.get(key) {
            Some(old) => Entry {
                data,
                create_revision: old.create_revision,
                mod_revision: revision,
                version: old.version.saturating_add(1),
                lease,
            },
            None => Entry {
                data,
                create_revision: revision,
                mod_revision: revision,
                version: 1,
                lease,
            },
        };
        let kind = if entry.version == 1 {
            EventKind::Create
        } else {
            EventKind::Modify
        };
        let value = entry.value();
        self.kv.insert(key.to_owned(), entry);
        self.emit(&Event {
            kind,
            key: key.to_owned(),
            value: Some(value),
        });
        Ok(())
    }
    fn delete(&mut self, key: &str) {
        if self.kv.remove(key).is_some() {
            self.revision = self.revision.saturating_add(1);
            self.writes = self.writes.saturating_add(1);
            self.emit(&Event {
                kind: EventKind::Delete,
                key: key.to_owned(),
                value: None,
            });
        }
    }
    /// Revoke a lease: it and every key on it go.
    fn revoke(&mut self, lease: i64) {
        self.live.remove(&lease);
        let keys: Vec<String> = self
            .kv
            .iter()
            .filter(|(_, e)| e.lease == lease)
            .map(|(k, _)| k.clone())
            .collect();
        for key in keys {
            self.delete(&key);
        }
    }
    fn holds(&self, compare: &Compare) -> bool {
        match compare {
            Compare::Absent(key) => !self.kv.contains_key(key),
            Compare::Exact {
                key,
                data,
                mod_revision,
                lease_id,
            } => self.kv.get(key).is_some_and(|e| {
                e.data == *data && e.mod_revision == *mod_revision && e.lease == *lease_id
            }),
        }
    }
    fn guarded(&self, guard: Option<&Guard>) -> Result<()> {
        match guard {
            Some(g)
                if self
                    .kv
                    .get(&g.key)
                    .is_none_or(|e| e.create_revision != g.create_revision) =>
            {
                Err(Error::LockLeaseExpired)
            }
            _ => Ok(()),
        }
    }
}

/// The shared store.
#[derive(Default)]
pub struct MemoryStore {
    server: Mutex<Server>,
    changed: Notify,
}
impl MemoryStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn lock(&self) -> MutexGuard<'_, Server> {
        self.server
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// A new client of this store.
    pub fn client(self: &Arc<Self>) -> MemoryBackend {
        let lock_lease = self.lock().grant();
        MemoryBackend {
            store: Arc::clone(self),
            client: Mutex::new(Client {
                lock_lease,
                ..Client::default()
            }),
            local_locks: Mutex::new(BTreeMap::new()),
        }
    }
    /// Every key and its value.
    pub fn dump(&self) -> BTreeMap<String, Value> {
        self.lock()
            .kv
            .iter()
            .map(|(k, e)| (k.clone(), e.value()))
            .collect()
    }
    /// Writes (puts and effective deletes) so far.
    pub fn writes(&self) -> u64 {
        self.lock().writes
    }
    /// The current revision.
    pub fn revision(&self) -> i64 {
        self.lock().revision
    }
    /// Write as another writer would (no lease), e.g. a foreign modification.
    pub fn put_raw(&self, key: &str, data: &[u8]) {
        let _ = self.lock().put(key, data.to_vec(), 0);
        self.changed.notify_waiters();
    }
    /// Delete as another writer would.
    pub fn delete_raw(&self, key: &str) {
        self.lock().delete(key);
        self.changed.notify_waiters();
    }
}

#[derive(Default)]
struct Client {
    /// Key lease -> keys bound.
    leases: BTreeMap<i64, usize>,
    bindings: BTreeMap<String, i64>,
    current: Option<i64>,
    lock_lease: i64,
    observers: Vec<(String, Observer)>,
    closed: bool,
}

/// One client of a [`MemoryStore`].
pub struct MemoryBackend {
    store: Arc<MemoryStore>,
    client: Mutex<Client>,
    local_locks: Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>,
}
impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl MemoryBackend {
    /// A client of a new store.
    pub fn new() -> Self {
        MemoryStore::new().client()
    }
    pub fn store(&self) -> Arc<MemoryStore> {
        Arc::clone(&self.store)
    }
    fn client(&self) -> MutexGuard<'_, Client> {
        self.client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn open(&self) -> Result<()> {
        if self.client().closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    /// The lease a write of `key` gets (§5.5): its binding, else the current
    /// lease while it has room, else another with room, else a new one.
    fn bind(&self, key: &str) -> i64 {
        let mut client = self.client();
        if let Some(id) = client.bindings.get(key) {
            return *id;
        }
        let room = |c: &Client, id: i64| c.leases.get(&id).is_some_and(|n| *n < KEYS_PER_LEASE);
        let id = match client.current.filter(|id| room(&client, *id)) {
            Some(id) => id,
            None => match client.leases.keys().copied().find(|id| room(&client, *id)) {
                Some(id) => id,
                None => {
                    let id = self.store.lock().grant();
                    client.leases.insert(id, 0);
                    id
                }
            },
        };
        client.current = Some(id);
        if let Some(count) = client.leases.get_mut(&id) {
            *count = count.saturating_add(1);
        }
        client.bindings.insert(key.to_owned(), id);
        id
    }
    fn unbind(&self, key: &str) {
        let mut client = self.client();
        if let Some(id) = client.bindings.remove(key)
            && let Some(count) = client.leases.get_mut(&id)
        {
            *count = count.saturating_sub(1);
        }
    }
    fn lease_of(&self, key: &str, lease: Lease) -> i64 {
        match lease {
            Lease::None => {
                self.unbind(key);
                0
            }
            Lease::Attached => self.bind(key),
        }
    }
    /// The key leases this client holds.
    pub fn key_leases(&self) -> Vec<i64> {
        self.client().leases.keys().copied().collect()
    }
    /// Lose a key lease as a failed keepalive would (§3.3.1): the server
    /// drops it and its keys, the client its bindings, and the observers of
    /// each bound key's prefix are called.
    pub fn lose_lease(&self, id: i64) {
        self.store.lock().revoke(id);
        self.store.changed.notify_waiters();
        let (keys, observers) = {
            let mut client = self.client();
            client.leases.remove(&id);
            if client.current == Some(id) {
                client.current = None;
            }
            let keys: Vec<String> = client
                .bindings
                .iter()
                .filter(|(_, l)| **l == id)
                .map(|(k, _)| k.clone())
                .collect();
            for key in &keys {
                client.bindings.remove(key);
            }
            (keys, client.observers.clone())
        };
        eprintln!("kvstore: lease {id:x} lost, {} keys", keys.len());
        for key in &keys {
            for (prefix, observer) in &observers {
                if key.starts_with(prefix.as_str()) {
                    observer(key);
                }
            }
        }
    }
    fn changed(&self) {
        self.store.changed.notify_waiters();
    }
}

impl Kvstore for MemoryBackend {
    async fn get(&self, key: &str, guard: Option<&Guard>) -> Result<Option<Value>> {
        self.open()?;
        let server = self.store.lock();
        server.guarded(guard)?;
        Ok(server.kv.get(key).map(Entry::value))
    }

    async fn put(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> Result<()> {
        self.open()?;
        check_size(key, &data)?;
        let lease = self.lease_of(key, lease);
        {
            let mut server = self.store.lock();
            server.guarded(guard)?;
            server.put(key, data, lease)?;
        }
        self.changed();
        Ok(())
    }

    async fn put_if_absent(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> Result<bool> {
        self.open()?;
        check_size(key, &data)?;
        if self.store.lock().kv.contains_key(key) {
            return Ok(false);
        }
        let lease = self.lease_of(key, lease);
        {
            let mut server = self.store.lock();
            server.guarded(guard)?;
            if server.kv.contains_key(key) {
                return Ok(false);
            }
            server.put(key, data, lease)?;
        }
        self.changed();
        Ok(true)
    }

    async fn put_if_different(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> Result<bool> {
        self.open()?;
        check_size(key, &data)?;
        let wanted = self.lease_of(key, lease);
        {
            let mut server = self.store.lock();
            server.guarded(guard)?;
            if server
                .kv
                .get(key)
                .is_some_and(|e| e.data == data && e.lease == wanted)
            {
                return Ok(false);
            }
            server.put(key, data, wanted)?;
        }
        self.changed();
        Ok(true)
    }

    async fn delete(&self, key: &str, guard: Option<&Guard>) -> Result<()> {
        self.open()?;
        {
            let mut server = self.store.lock();
            server.guarded(guard)?;
            server.delete(key);
        }
        self.unbind(key);
        self.changed();
        Ok(())
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<()> {
        self.open()?;
        let keys: Vec<String> = {
            let mut server = self.store.lock();
            let keys: Vec<String> = server
                .kv
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect();
            for key in &keys {
                server.delete(key);
            }
            keys
        };
        for key in &keys {
            self.unbind(key);
        }
        self.changed();
        Ok(())
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        guard: Option<&Guard>,
    ) -> Result<BTreeMap<String, Value>> {
        self.open()?;
        let server = self.store.lock();
        server.guarded(guard)?;
        Ok(server
            .kv
            .range(prefix.to_owned()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, e)| (k.clone(), e.value()))
            .collect())
    }

    async fn watch(&self, prefix: &str) -> Result<mpsc::Receiver<Event>> {
        self.open()?;
        let (tx, rx) = mpsc::channel(WATCH_DEPTH);
        // Client before store, everywhere.
        let owner = self.client().lock_lease;
        let mut server = self.store.lock();
        for (key, entry) in server
            .kv
            .range(prefix.to_owned()..)
            .take_while(|(k, _)| k.starts_with(prefix))
        {
            let _ = tx.try_send(Event {
                kind: EventKind::Create,
                key: key.clone(),
                value: Some(entry.value()),
            });
        }
        let _ = tx.try_send(Event {
            kind: EventKind::ListDone,
            key: String::new(),
            value: None,
        });
        server.watchers.push(Watcher {
            owner,
            prefix: prefix.to_owned(),
            tx,
        });
        Ok(rx)
    }

    async fn lock(&self, path: &str) -> Result<Guard> {
        self.open()?;
        let local = {
            let mut locks = self
                .local_locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(locks.entry(path.to_owned()).or_default())
        };
        let _local = local.lock().await;
        let lease = self.client().lock_lease;
        let key = format!("{path}/{lease:x}");
        let prefix = format!("{path}/");
        let deadline = tokio::time::Instant::now()
            .checked_add(LOCK_TIMEOUT)
            .unwrap_or_else(tokio::time::Instant::now);
        {
            let mut server = self.store.lock();
            if !server.kv.contains_key(&key) {
                server.put(&key, Vec::new(), lease)?;
            }
        }
        self.changed();
        loop {
            let notified = self.store.changed.notified();
            let owner = {
                let server = self.store.lock();
                let mine = server.kv.get(&key).map(|e| e.create_revision);
                let lowest = server
                    .kv
                    .range(prefix.clone()..)
                    .take_while(|(k, _)| k.starts_with(&prefix))
                    .min_by_key(|(_, e)| e.create_revision)
                    .map(|(k, e)| (k.clone(), e.create_revision));
                match (mine, lowest) {
                    (None, _) => return Err(Error::LockLeaseExpired),
                    (Some(rev), Some((k, _))) if k == key => Some(rev),
                    _ => None,
                }
            };
            if let Some(create_revision) = owner {
                return Ok(Guard {
                    key,
                    create_revision,
                });
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                self.store.lock().delete(&key);
                self.changed();
                return Err(Error::LockTimeout(path.to_owned()));
            }
        }
    }

    async fn unlock(&self, guard: &Guard) -> Result<()> {
        self.store.lock().delete(&guard.key);
        self.changed();
        Ok(())
    }

    fn lease_expired(&self, prefix: &str, observer: Option<Observer>) {
        let mut client = self.client();
        client.observers.retain(|(p, _)| p != prefix);
        if let Some(observer) = observer {
            client.observers.push((prefix.to_owned(), observer));
        }
    }

    fn status(&self) -> Status {
        let client = self.client();
        if client.closed {
            return Status {
                state: State::Failure,
                message: "Err: closed".into(),
            };
        }
        Status {
            state: State::Ok,
            message: format!(
                "memory: 1/1 connected, leases={}, lock leases=1, has-quorum=true",
                client.leases.len()
            ),
        }
    }

    fn status_errors(&self) -> Option<mpsc::Receiver<Error>> {
        None
    }

    async fn txn(&self, compares: Vec<Compare>, puts: Vec<TxnPut>) -> Result<bool> {
        self.open()?;
        for put in &puts {
            check_size(&put.key, &put.data)?;
        }
        let leases: Vec<i64> = puts
            .iter()
            .map(|p| match p.lease {
                Lease::None => 0,
                Lease::Attached => self.bind(&p.key),
            })
            .collect();
        {
            let mut server = self.store.lock();
            if !compares.iter().all(|c| server.holds(c)) {
                return Ok(false);
            }
            for (put, lease) in puts.into_iter().zip(leases) {
                server.put(&put.key, put.data, lease)?;
            }
        }
        self.changed();
        Ok(true)
    }

    async fn lease_for(&self, key: &str) -> Result<i64> {
        self.open()?;
        Ok(self.bind(key))
    }

    async fn close(&self) {
        let owner = self.client().lock_lease;
        let leases: Vec<i64> = {
            let mut client = self.client();
            client.closed = true;
            client.bindings.clear();
            client.current = None;
            let mut leases: Vec<i64> = std::mem::take(&mut client.leases).into_keys().collect();
            leases.push(client.lock_lease);
            leases
        };
        let mut server = self.store.lock();
        for lease in leases {
            server.revoke(lease);
        }
        server.watchers.retain(|w| w.owner != owner);
        drop(server);
        self.changed();
    }
}

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;
