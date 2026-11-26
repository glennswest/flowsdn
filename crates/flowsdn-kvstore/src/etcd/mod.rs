//! The etcd v3 backend (spec 20 §3.2, §3.3, §5.3-5.5): the RPCs of §2.6 as
//! gRPC over `h2`, hand-written `prost` messages ([`proto`]), TLS through
//! Fedora OpenSSL (ADR-0016), the rate limiter of §3.2.4, key and lock
//! leases, client-side locks, list-then-watch and the status checker of
//! §3.2.5.

mod grpc;
mod lease;
mod limiter;
pub mod proto;
mod watch;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{OwnedMutexGuard, mpsc};
use tokio::task::AbortHandle;

use crate::{
    Compare, Error, Event, Guard, KEY_LEASE_TTL, KEYS_PER_LEASE, Kvstore, LOCK_LEASE_TTL,
    LOCK_TIMEOUT, Lease, Observer, Result, State, Status, TxnPut, Value, check_size, prefix_end,
};
use grpc::{Channel, Endpoint, TlsFiles};
use lease::Leases;
use limiter::Limiter;
use proto::{
    DeleteRangeRequest, DeleteRangeResponse, EVENT_DELETE, KeyValue, LeaseGrantRequest,
    LeaseGrantResponse, LeaseRevokeRequest, LeaseRevokeResponse, PutRequest, PutResponse,
    RangeRequest, RangeResponse, RequestOp, StatusRequest, StatusResponse, TxnRequest, TxnResponse,
    WatchCreateRequest, WatchRequest, WatchResponse,
};

const RANGE: &str = "/etcdserverpb.KV/Range";
const PUT: &str = "/etcdserverpb.KV/Put";
const DELETE_RANGE: &str = "/etcdserverpb.KV/DeleteRange";
const TXN: &str = "/etcdserverpb.KV/Txn";
const WATCH: &str = "/etcdserverpb.Watch/Watch";
const LEASE_GRANT: &str = "/etcdserverpb.Lease/LeaseGrant";
const LEASE_KEEPALIVE: &str = "/etcdserverpb.Lease/LeaseKeepAlive";
const LEASE_REVOKE: &str = "/etcdserverpb.Lease/LeaseRevoke";
const STATUS: &str = "/etcdserverpb.Maintenance/Status";

/// `WithRequireLeader` metadata on watches (§2.7 F11: set, not relied on).
const HASLEADER: (&str, &str) = ("hasleader", "true");

/// The quorum probe's lock prefix (§3.2.5, ADR-0023 names).
const INIT_LOCK: &str = "flowsdn/.initlock";
/// The status checker's intervals (§3.2.5; not scaled by cluster size).
const STATUS_INTERVAL: Duration = Duration::from_secs(30);
const STATUS_RETRY: Duration = Duration::from_secs(5);
/// The quorum probe and per-endpoint status deadlines (§3.2.5).
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// `kvstore-max-consecutive-quorum-errors` (§3.2.5).
const MAX_QUORUM_ERRORS: u32 = 2;
/// Status errors buffered for the owner (§3.2.5).
const STATUS_ERRORS: usize = 128;
/// Events buffered per watcher.
const WATCH_BUFFER: usize = 1024;
/// One dial attempt per endpoint.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Best-effort revokes on close.
const REVOKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The etcd backend's configuration (§3.2.1-3.2.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EtcdConfig {
    /// `http://` or `https://` URLs; shuffled before use (§3.2.1).
    pub endpoints: Vec<String>,
    /// Server CA; the system roots when unset (§3.2.2).
    pub trusted_ca_file: Option<PathBuf>,
    /// Client certificate, used with `key_file`, re-read on every dial.
    pub cert_file: Option<PathBuf>,
    /// Client key, used with `cert_file`.
    pub key_file: Option<PathBuf>,
    /// `etcd.qps`: steady rate and burst (§3.2.4); 0: unlimited.
    pub qps: u32,
    /// `etcd.bootstrapQps`: the rate until [`EtcdBackend::bootstrap_done`];
    /// 0: off.
    pub bootstrap_qps: u32,
    /// `etcd.maxInflight`; 0: `qps`.
    pub max_inflight: u32,
    /// `kvstore-lease-ttl` (§3.3.1).
    pub key_lease_ttl: Duration,
    /// `etcd.limit`: the page size of the paginated list (§5.3).
    pub list_limit: i64,
    /// `kvstore-resync-interval` (§5.4.4); zero: off.
    pub resync_interval: Duration,
}

impl Default for EtcdConfig {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            trusted_ca_file: None,
            cert_file: None,
            key_file: None,
            qps: 20,
            bootstrap_qps: 0,
            max_inflight: 20,
            key_lease_ttl: KEY_LEASE_TTL,
            list_limit: 256,
            resync_interval: Duration::from_secs(5 * 60),
        }
    }
}

fn strip_comment(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }
    match line.find(" #") {
        Some(at) => line.get(..at).unwrap_or(line),
        None => line,
    }
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    let unquoted = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);
    unquoted.trim().to_owned()
}

fn path_value(value: &str) -> Option<PathBuf> {
    let value = unquote(value);
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// Parse the etcd client YAML of §2.3: `endpoints` (a block or flow list, or
/// one URL), `trusted-ca-file`, `cert-file`, `key-file`. Other keys
/// (`cilium-host-aliases` included) are ignored. The other fields keep their
/// defaults.
pub fn parse_client_yaml(text: &str) -> Result<EtcdConfig> {
    let mut config = EtcdConfig::default();
    let mut section = String::new();
    for raw in text.lines() {
        let line = strip_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(item) = trimmed.strip_prefix('-') {
            if section == "endpoints" {
                let endpoint = unquote(item);
                if !endpoint.is_empty() {
                    config.endpoints.push(endpoint);
                }
            }
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // A nested mapping of another key.
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        section = key.to_owned();
        match key {
            "endpoints" if !value.is_empty() => {
                let list = value
                    .strip_prefix('[')
                    .and_then(|v| v.strip_suffix(']'))
                    .unwrap_or(value);
                config.endpoints.extend(
                    list.split(',')
                        .map(unquote)
                        .filter(|endpoint| !endpoint.is_empty()),
                );
            }
            "trusted-ca-file" => config.trusted_ca_file = path_value(value),
            "cert-file" => config.cert_file = path_value(value),
            "key-file" => config.key_file = path_value(value),
            _ => {}
        }
    }
    if config.endpoints.is_empty() {
        return Err(Error::Backend("etcd config: no endpoints".into()));
    }
    Ok(config)
}

/// A xorshift64 step seeded from the clock (no `rand` crate).
fn random_u64() -> u64 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut x = STATE.load(Ordering::Relaxed) ^ nanos ^ 0x9E37_79B9_7F4A_7C15;
    if x == 0 {
        x = 0x9E37_79B9_7F4A_7C15;
    }
    x ^= x.wrapping_shl(13);
    x ^= x.wrapping_shr(7);
    x ^= x.wrapping_shl(17);
    STATE.store(x, Ordering::Relaxed);
    x
}

/// Fisher-Yates over [`random_u64`] (§3.2.1).
fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let bound = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
        let j = random_u64()
            .checked_rem(bound)
            .and_then(|j| usize::try_from(j).ok())
            .unwrap_or(0);
        items.swap(i, j);
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn key_string(key: &[u8]) -> String {
    String::from_utf8_lossy(key).into_owned()
}

pub(crate) fn to_value(kv: KeyValue) -> Value {
    Value {
        data: kv.value,
        mod_revision: kv.mod_revision,
        create_revision: kv.create_revision,
        lease_id: kv.lease,
    }
}

/// Which lease manager (§3.3.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseKind {
    Key,
    Lock,
}

impl LeaseKind {
    fn name(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Lock => "lock",
        }
    }
}

/// The status line and verdict of §3.2.5 (frozen format).
pub(crate) fn render_status(
    ok: usize,
    endpoints: &[String],
    leases: usize,
    lock_leases: usize,
    quorum: &std::result::Result<(), String>,
    consecutive_quorum_errors: u32,
) -> Status {
    if consecutive_quorum_errors > MAX_QUORUM_ERRORS {
        let error = quorum.as_ref().err().map_or("", String::as_str);
        return Status {
            state: State::Failure,
            message: format!(
                "Err: quorum check failed {consecutive_quorum_errors} times in a row: {error}"
            ),
        };
    }
    if !endpoints.is_empty() && ok == 0 {
        return Status {
            state: State::Failure,
            message: "Err: not able to connect to any etcd endpoints".into(),
        };
    }
    let has_quorum = match quorum {
        Ok(()) => "true".to_owned(),
        Err(error) => error.clone(),
    };
    Status {
        state: State::Ok,
        message: format!(
            "etcd: {ok}/{} connected, leases={leases}, lock leases={lock_leases}, \
             has-quorum={has_quorum}: {}",
            endpoints.len(),
            endpoints.join("; ")
        ),
    }
}

/// The shared client state; tasks hold an `Arc` of it.
pub(crate) struct Inner {
    config: EtcdConfig,
    endpoints: Vec<Endpoint>,
    tls: TlsFiles,
    next_endpoint: AtomicUsize,
    conn: tokio::sync::Mutex<Option<Channel>>,
    /// Operations refuse and tasks stop.
    closed: AtomicBool,
    /// No more dials (after close's revokes).
    shut: AtomicBool,
    closing: tokio::sync::watch::Sender<bool>,
    limiter: Limiter,
    keys: Leases,
    locks: Leases,
    observers: Mutex<Vec<(String, Observer)>>,
    status: Mutex<Status>,
    status_tx: mpsc::Sender<Error>,
    status_rx: Mutex<Option<mpsc::Receiver<Error>>>,
    /// Process-local locks per path (§3.3.2).
    local_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// The local lock of each held distributed lock, by lock key.
    held: Mutex<HashMap<String, OwnedMutexGuard<()>>>,
    tasks: Mutex<Vec<AbortHandle>>,
}

impl Inner {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn ensure_open(&self) -> Result<()> {
        if self.is_closed() {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    /// Resolves once the client is closing.
    async fn wait_closed(&self) {
        let mut rx = self.closing.subscribe();
        let _ = rx.wait_for(|closed| *closed).await;
    }

    fn leases(&self, kind: LeaseKind) -> &Leases {
        match kind {
            LeaseKind::Key => &self.keys,
            LeaseKind::Lock => &self.locks,
        }
    }

    fn spawn_task(&self, task: AbortHandle) {
        let mut tasks = locked(&self.tasks);
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    /// The live connection, redialing (and so re-reading the TLS files)
    /// when it broke.
    async fn channel(&self) -> Result<Channel> {
        if self.shut.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let mut slot = self.conn.lock().await;
        if let Some(channel) = slot.as_ref().filter(|channel| channel.is_alive()) {
            return Ok(channel.clone());
        }
        *slot = None;
        let channel = self.dial_any().await?;
        *slot = Some(channel.clone());
        Ok(channel)
    }

    /// The first endpoint that answers, starting from the last good one.
    async fn dial_any(&self) -> Result<Channel> {
        let count = self.endpoints.len();
        let start = self.next_endpoint.load(Ordering::Relaxed);
        let mut errors = Vec::new();
        for offset in 0..count {
            let index = start.wrapping_add(offset).checked_rem(count).unwrap_or(0);
            let Some(endpoint) = self.endpoints.get(index) else {
                continue;
            };
            match tokio::time::timeout(DIAL_TIMEOUT, grpc::dial(endpoint, &self.tls)).await {
                Ok(Ok(channel)) => {
                    self.next_endpoint.store(index, Ordering::Relaxed);
                    return Ok(channel);
                }
                Ok(Err(e)) => errors.push(e.to_string()),
                Err(_) => errors.push(format!("{}: dial timeout", endpoint.url)),
            }
        }
        Err(Error::Backend(format!(
            "etcd: no endpoint answered: {}",
            errors.join("; ")
        )))
    }

    async fn call<Q, R>(&self, path: &'static str, request: &Q) -> Result<R>
    where
        Q: prost::Message,
        R: prost::Message + Default,
    {
        let channel = self.channel().await?;
        channel.unary(path, request).await
    }

    // ---- leases (§3.3.1, §5.5) ----

    /// The lease `key` gets (binding it), granting one when every lease is
    /// full (single-flight). `None`: the manager's lease without a binding.
    async fn lease(self: &Arc<Self>, kind: LeaseKind, key: Option<&str>) -> Result<i64> {
        let leases = self.leases(kind);
        if let Some(id) = leases.try_bind(key) {
            return Ok(id);
        }
        let _grant = leases.grant.lock().await;
        if let Some(id) = leases.try_bind(key) {
            return Ok(id);
        }
        self.ensure_open()?;
        let ttl = i64::try_from(leases.ttl.as_secs())
            .unwrap_or(i64::MAX)
            .max(1);
        let response: LeaseGrantResponse = self
            .call(LEASE_GRANT, &LeaseGrantRequest { ttl, id: 0 })
            .await?;
        if !response.error.is_empty() {
            return Err(Error::Backend(format!(
                "etcd: lease grant: {}",
                response.error
            )));
        }
        if response.id == 0 {
            return Err(Error::Backend("etcd: lease grant returned id 0".into()));
        }
        let granted = u64::try_from(response.ttl)
            .ok()
            .filter(|ttl| *ttl > 0)
            .map_or(leases.ttl, Duration::from_secs);
        leases.insert(response.id);
        let task = tokio::spawn(lease::keepalive(
            Arc::clone(self),
            kind,
            response.id,
            granted,
        ));
        leases.set_task(response.id, task.abort_handle());
        leases
            .try_bind(key)
            .ok_or_else(|| Error::Backend(format!("etcd: lease {:x} lost", response.id)))
    }

    /// The loss path (§3.3.1): drop the lease and its bindings, then tell
    /// every observer whose prefix matches a bound key.
    fn lose_lease(&self, kind: LeaseKind, id: i64) {
        let keys = self.leases(kind).remove(id);
        if keys.is_empty() {
            return;
        }
        let observers = locked(&self.observers).clone();
        for key in &keys {
            for (prefix, observer) in &observers {
                if key.starts_with(prefix.as_str()) {
                    observer(key.as_str());
                }
            }
        }
    }

    /// Orphan the leases of a write that failed with `lease not found` and
    /// name the lease in the error (§3.3.1).
    fn lease_error(&self, kind: LeaseKind, error: Error, ids: &[i64]) -> Error {
        match error {
            Error::LeaseNotFound(_) => {
                let mut first = 0;
                for &id in ids.iter().filter(|id| **id != 0) {
                    if first == 0 {
                        first = id;
                    }
                    eprintln!("warning: kvstore: {} lease {id:x} not found", kind.name());
                    self.lose_lease(kind, id);
                }
                Error::LeaseNotFound(first)
            }
            other => other,
        }
    }

    async fn lease_for_write(self: &Arc<Self>, key: &str, lease: Lease) -> Result<i64> {
        match lease {
            Lease::None => Ok(0),
            Lease::Attached => self.lease(LeaseKind::Key, Some(key)).await,
        }
    }

    // ---- KV (§3.1) ----

    /// One Txn guarded by the lock's ownership compare (§3.1 rule 2).
    async fn guarded(&self, guard: &Guard, success: Vec<RequestOp>) -> Result<TxnResponse> {
        let request = TxnRequest {
            compare: vec![proto::Compare::create_equal(
                &guard.key,
                guard.create_revision,
            )],
            success,
            failure: Vec::new(),
        };
        let response: TxnResponse = self.call(TXN, &request).await?;
        if response.succeeded {
            Ok(response)
        } else {
            Err(Error::LockLeaseExpired)
        }
    }

    async fn get_raw(&self, key: &str, guard: Option<&Guard>) -> Result<Option<Value>> {
        let range = RangeRequest {
            key: key.as_bytes().to_vec(),
            ..Default::default()
        };
        let response: RangeResponse = match guard {
            None => self.call(RANGE, &range).await?,
            Some(guard) => self
                .guarded(guard, vec![RequestOp::range(range)])
                .await?
                .first_range(),
        };
        Ok(response
            .kvs
            .into_iter()
            .find(|kv| kv.key == key.as_bytes())
            .map(to_value))
    }

    async fn put_raw(
        &self,
        key: &str,
        data: Vec<u8>,
        lease_id: i64,
        guard: Option<&Guard>,
    ) -> Result<()> {
        let put = PutRequest {
            key: key.as_bytes().to_vec(),
            value: data,
            lease: lease_id,
            ..Default::default()
        };
        let result = match guard {
            None => self.call::<_, PutResponse>(PUT, &put).await.map(|_| ()),
            Some(guard) => self
                .guarded(guard, vec![RequestOp::put(put)])
                .await
                .map(|_| ()),
        };
        match result {
            Ok(()) => {
                if lease_id == 0 {
                    self.keys.release(key);
                }
                Ok(())
            }
            Err(e) => Err(self.lease_error(LeaseKind::Key, e, &[lease_id])),
        }
    }

    async fn put_if_absent(
        self: &Arc<Self>,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> Result<bool> {
        check_size(key, &data)?;
        self.ensure_open()?;
        let _permit = self.limiter.acquire().await;
        let lease_id = self.lease_for_write(key, lease).await?;
        let mut compare = vec![proto::Compare::version_equal(key, 0)];
        let mut failure = Vec::new();
        if let Some(guard) = guard {
            compare.push(proto::Compare::create_equal(
                &guard.key,
                guard.create_revision,
            ));
            failure.push(RequestOp::range(RangeRequest {
                key: guard.key.as_bytes().to_vec(),
                ..Default::default()
            }));
        }
        let request = TxnRequest {
            compare,
            success: vec![RequestOp::put(PutRequest {
                key: key.as_bytes().to_vec(),
                value: data,
                lease: lease_id,
                ..Default::default()
            })],
            failure,
        };
        let response: TxnResponse = match self.call(TXN, &request).await {
            Ok(response) => response,
            Err(e) => return Err(self.lease_error(LeaseKind::Key, e, &[lease_id])),
        };
        if response.succeeded {
            return Ok(true);
        }
        if let Some(guard) = guard {
            let held = response
                .first_range()
                .kvs
                .iter()
                .any(|kv| kv.create_revision == guard.create_revision);
            if !held {
                return Err(Error::LockLeaseExpired);
            }
        }
        Ok(false)
    }

    async fn delete_raw(&self, key: &str, guard: Option<&Guard>) -> Result<()> {
        let request = DeleteRangeRequest {
            key: key.as_bytes().to_vec(),
            ..Default::default()
        };
        match guard {
            None => {
                self.call::<_, DeleteRangeResponse>(DELETE_RANGE, &request)
                    .await?;
            }
            Some(guard) => {
                self.guarded(guard, vec![RequestOp::delete(request)])
                    .await?;
            }
        }
        self.keys.release(key);
        Ok(())
    }

    /// The paginated list of §5.3: the revision pinned from the first page,
    /// each next page from the last key + `\0`. Takes no limiter token.
    async fn paginated(
        &self,
        prefix: &str,
        guard: Option<&Guard>,
    ) -> Result<(BTreeMap<String, Value>, i64)> {
        let end = prefix_end(prefix.as_bytes());
        let mut start = prefix.as_bytes().to_vec();
        let mut revision = 0;
        let mut out = BTreeMap::new();
        loop {
            let range = RangeRequest {
                key: start.clone(),
                range_end: end.clone(),
                limit: self.config.list_limit.max(0),
                revision,
                ..Default::default()
            };
            let response: RangeResponse = match guard {
                None => self.call(RANGE, &range).await?,
                Some(guard) => self
                    .guarded(guard, vec![RequestOp::range(range)])
                    .await?
                    .first_range(),
            };
            if revision == 0 {
                revision = response.header.as_ref().map_or(0, |header| header.revision);
            }
            let more = response.more;
            let mut last = None;
            for kv in response.kvs {
                last = Some(kv.key.clone());
                out.insert(key_string(&kv.key), to_value(kv));
            }
            match last {
                Some(mut key) if more => {
                    key.push(0);
                    start = key;
                }
                _ => return Ok((out, revision)),
            }
        }
    }

    async fn txn(self: &Arc<Self>, compares: Vec<Compare>, puts: Vec<TxnPut>) -> Result<bool> {
        for put in &puts {
            check_size(&put.key, &put.data)?;
        }
        self.ensure_open()?;
        let _permit = self.limiter.acquire().await;
        let mut compare = Vec::new();
        for item in compares {
            match item {
                Compare::Absent(key) => compare.push(proto::Compare::version_equal(&key, 0)),
                Compare::Exact {
                    key,
                    data,
                    mod_revision,
                    lease_id,
                } => {
                    compare.push(proto::Compare::value_equal(&key, data));
                    compare.push(proto::Compare::mod_equal(&key, mod_revision));
                    compare.push(proto::Compare::lease_equal(&key, lease_id));
                }
            }
        }
        let mut success = Vec::new();
        let mut lease_ids = Vec::new();
        for put in puts {
            let lease_id = self.lease_for_write(&put.key, put.lease).await?;
            lease_ids.push(lease_id);
            success.push(RequestOp::put(PutRequest {
                key: put.key.into_bytes(),
                value: put.data,
                lease: lease_id,
                ..Default::default()
            }));
        }
        let request = TxnRequest {
            compare,
            success,
            failure: Vec::new(),
        };
        match self.call::<_, TxnResponse>(TXN, &request).await {
            Ok(response) => Ok(response.succeeded),
            Err(e) => Err(self.lease_error(LeaseKind::Key, e, &lease_ids)),
        }
    }

    // ---- locks (§3.3.2) ----

    fn local_mutex(&self, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            locked(&self.local_locks)
                .entry(path.to_owned())
                .or_default(),
        )
    }

    /// Drop a local lock entry nobody holds or waits for.
    fn prune_local(&self, path: &str) {
        let mut locks = locked(&self.local_locks);
        if locks
            .get(path)
            .is_some_and(|mutex| Arc::strong_count(mutex) == 1)
        {
            locks.remove(path);
        }
    }

    async fn lock(self: &Arc<Self>, path: &str) -> Result<Guard> {
        self.ensure_open()?;
        let path = path.trim_end_matches('/').to_owned();
        let local = self.local_mutex(&path);
        let mut pending = PendingLock {
            inner: Arc::clone(self),
            key: None,
        };
        let attempt =
            tokio::time::timeout(LOCK_TIMEOUT, self.acquire(&path, local, &mut pending.key)).await;
        let error = match attempt {
            Ok(Ok((guard, local_guard))) => {
                pending.key = None;
                locked(&self.held).insert(guard.key.clone(), local_guard);
                return Ok(guard);
            }
            Ok(Err(e)) => e,
            Err(_) => Error::LockTimeout(path.clone()),
        };
        if let Some(key) = pending.key.take() {
            self.delete_lock_key(key).await;
        }
        self.prune_local(&path);
        Err(error)
    }

    /// Best-effort delete of an abandoned lock key.
    async fn delete_lock_key(&self, key: String) {
        let request = DeleteRangeRequest {
            key: key.into_bytes(),
            ..Default::default()
        };
        let delete = self.call::<_, DeleteRangeResponse>(DELETE_RANGE, &request);
        let _ = tokio::time::timeout(REVOKE_TIMEOUT, delete).await;
    }

    /// Take the local lock, create `<path>/<lock lease hex>`, and wait until
    /// it has the lowest create revision under `<path>/`, watching the
    /// immediately preceding key.
    async fn acquire(
        self: &Arc<Self>,
        path: &str,
        local: Arc<tokio::sync::Mutex<()>>,
        created: &mut Option<String>,
    ) -> Result<(Guard, OwnedMutexGuard<()>)> {
        let local_guard = local.lock_owned().await;
        let lease = self.lease(LeaseKind::Lock, None).await?;
        let key = format!("{path}/{lease:x}");
        *created = Some(key.clone());
        let prefix = format!("{path}/");
        loop {
            let request = TxnRequest {
                compare: vec![proto::Compare::version_equal(&key, 0)],
                success: vec![RequestOp::put(PutRequest {
                    key: key.as_bytes().to_vec(),
                    lease,
                    ..Default::default()
                })],
                failure: Vec::new(),
            };
            if let Err(e) = self.call::<_, TxnResponse>(TXN, &request).await {
                return Err(self.lease_error(LeaseKind::Lock, e, &[lease]));
            }
            let (keys, revision) = self.paginated(&prefix, None).await?;
            let Some(mine) = keys.get(&key).map(|value| value.create_revision) else {
                // Gone between the create and the list (lease loss): again.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let predecessor = keys
                .iter()
                .filter(|(_, value)| value.create_revision < mine)
                .max_by_key(|(_, value)| value.create_revision)
                .map(|(key, _)| key.clone());
            match predecessor {
                None => {
                    let guard = Guard {
                        key,
                        create_revision: mine,
                    };
                    return Ok((guard, local_guard));
                }
                Some(predecessor) => self.wait_deleted(&predecessor, revision).await?,
            }
        }
    }

    /// Watch `key` from `revision + 1` until it is deleted (or the watch
    /// ends: the caller re-evaluates).
    async fn wait_deleted(&self, key: &str, revision: i64) -> Result<()> {
        let request = WatchRequest::create(WatchCreateRequest {
            key: key.as_bytes().to_vec(),
            start_revision: revision.saturating_add(1),
            ..Default::default()
        });
        let channel = self.channel().await?;
        let (_send, mut receive) = channel
            .open(WATCH, &[HASLEADER], grpc::frame(&request), false)
            .await?;
        loop {
            let Some(response) = receive.recv::<WatchResponse>().await? else {
                return Ok(());
            };
            if response.canceled
                || response
                    .events
                    .iter()
                    .any(|event| event.kind == EVENT_DELETE)
            {
                return Ok(());
            }
        }
    }

    async fn unlock(&self, guard: &Guard, limited: bool) -> Result<()> {
        self.ensure_open()?;
        let _permit = if limited {
            self.limiter.acquire().await
        } else {
            None
        };
        let request = DeleteRangeRequest {
            key: guard.key.as_bytes().to_vec(),
            ..Default::default()
        };
        let result = self
            .call::<_, DeleteRangeResponse>(DELETE_RANGE, &request)
            .await
            .map(|_| ());
        let local = locked(&self.held).remove(&guard.key);
        drop(local);
        if let Some((path, _)) = guard.key.rsplit_once('/') {
            self.prune_local(path);
        }
        result
    }

    // ---- status (§3.2.5) ----

    async fn status_loop(self: Arc<Self>) {
        let mut consecutive = 0u32;
        loop {
            let all_answered = self.check_status(&mut consecutive).await;
            let wait = if all_answered {
                STATUS_INTERVAL
            } else {
                STATUS_RETRY
            };
            tokio::select! {
                () = tokio::time::sleep(wait) => {},
                () = self.wait_closed() => return,
            }
        }
    }

    async fn probe(self: &Arc<Self>, path: &str) -> Result<()> {
        let guard = self.lock(path).await?;
        self.unlock(&guard, false).await
    }

    async fn endpoint_status(&self, endpoint: &Endpoint) -> Result<StatusResponse> {
        let channel = grpc::dial(endpoint, &self.tls).await?;
        channel.unary(STATUS, &StatusRequest {}).await
    }

    /// One iteration; true when every endpoint answered.
    async fn check_status(self: &Arc<Self>, consecutive: &mut u32) -> bool {
        let path = format!("{INIT_LOCK}/{:x}", random_u64());
        let quorum = match tokio::time::timeout(PROBE_TIMEOUT, self.probe(&path)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err(Error::LockTimeout(path.clone()).to_string()),
        };
        if self.is_closed() {
            return true;
        }
        if quorum.is_ok() {
            *consecutive = 0;
        } else {
            *consecutive = consecutive.saturating_add(1);
            // A probe cut off by the deadline may have left its local lock.
            let stale: Vec<String> = locked(&self.held)
                .keys()
                .filter(|key| key.starts_with(path.as_str()))
                .cloned()
                .collect();
            for key in stale {
                let local = locked(&self.held).remove(&key);
                drop(local);
                self.delete_lock_key(key).await;
            }
            self.prune_local(&path);
        }
        let mut answered = 0usize;
        let mut lines = Vec::new();
        for endpoint in &self.endpoints {
            match tokio::time::timeout(PROBE_TIMEOUT, self.endpoint_status(endpoint)).await {
                Ok(Ok(response)) => {
                    answered = answered.saturating_add(1);
                    let leader = response.leader != 0
                        && response
                            .header
                            .as_ref()
                            .is_some_and(|header| header.member_id == response.leader);
                    let suffix = if leader { " (Leader)" } else { "" };
                    lines.push(format!("{} - {}{suffix}", endpoint.url, response.version));
                }
                Ok(Err(e)) => lines.push(format!("{} - {e}", endpoint.url)),
                Err(_) => lines.push(format!("{} - context deadline exceeded", endpoint.url)),
            }
        }
        let status = render_status(
            answered,
            &lines,
            self.keys.count(),
            self.locks.count(),
            &quorum,
            *consecutive,
        );
        if status.state == State::Failure {
            let message = status
                .message
                .strip_prefix("Err: ")
                .unwrap_or(&status.message)
                .to_owned();
            if let Err(mpsc::error::TrySendError::Full(_)) =
                self.status_tx.try_send(Error::Backend(message))
            {
                eprintln!("warning: kvstore: status error channel full, dropping the error");
            }
        }
        *locked(&self.status) = status;
        answered == self.endpoints.len()
    }

    // ---- close ----

    /// Mark closed and stop every task; the lease ids to revoke. `None` when
    /// already closed.
    fn stop(&self) -> Option<Vec<i64>> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return None;
        }
        self.closing.send_replace(true);
        let tasks = std::mem::take(&mut *locked(&self.tasks));
        for task in tasks {
            task.abort();
        }
        let mut ids = self.keys.drain();
        ids.extend(self.locks.drain());
        Some(ids)
    }

    async fn close(&self) {
        let Some(ids) = self.stop() else {
            return;
        };
        for id in ids {
            let request = LeaseRevokeRequest { id };
            let revoke = self.call::<_, LeaseRevokeResponse>(LEASE_REVOKE, &request);
            if let Ok(Err(e)) = tokio::time::timeout(REVOKE_TIMEOUT, revoke).await {
                eprintln!("warning: kvstore: revoke lease {id:x}: {e}");
            }
        }
        locked(&self.held).clear();
        self.shut.store(true, Ordering::SeqCst);
        *self.conn.lock().await = None;
    }
}

/// Deletes the key of a lock acquisition that did not finish, also when the
/// `lock` future is dropped by a caller's own deadline (§3.3.2).
struct PendingLock {
    inner: Arc<Inner>,
    key: Option<String>,
}

impl Drop for PendingLock {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let inner = Arc::clone(&self.inner);
        runtime.spawn(async move { inner.delete_lock_key(key).await });
    }
}

/// The etcd v3 [`Kvstore`] (spec 20 §3.2).
pub struct EtcdBackend {
    inner: Arc<Inner>,
}

impl EtcdBackend {
    /// Dial the first endpoint that answers (the list shuffled, §3.2.1),
    /// grant the lock lease (§3.2.6) and start the status checker (§3.2.5).
    /// Later calls redial lazily when the connection breaks.
    pub async fn connect(config: EtcdConfig) -> Result<Self> {
        if config.endpoints.is_empty() {
            return Err(Error::Backend("etcd: no endpoints".into()));
        }
        let mut endpoints = config
            .endpoints
            .iter()
            .map(|url| Endpoint::parse(url.as_str()))
            .collect::<Result<Vec<_>>>()?;
        shuffle(&mut endpoints);
        let (status_tx, status_rx) = mpsc::channel(STATUS_ERRORS);
        let (closing, _) = tokio::sync::watch::channel(false);
        let inner = Arc::new(Inner {
            tls: TlsFiles {
                ca: config.trusted_ca_file.clone(),
                cert: config.cert_file.clone(),
                key: config.key_file.clone(),
            },
            limiter: Limiter::new(config.qps, config.bootstrap_qps, config.max_inflight),
            keys: Leases::new(config.key_lease_ttl, KEYS_PER_LEASE),
            locks: Leases::new(LOCK_LEASE_TTL, usize::MAX),
            config,
            endpoints,
            next_endpoint: AtomicUsize::new(0),
            conn: tokio::sync::Mutex::new(None),
            closed: AtomicBool::new(false),
            shut: AtomicBool::new(false),
            closing,
            observers: Mutex::new(Vec::new()),
            status: Mutex::new(Status {
                state: State::Warning,
                message: "etcd: waiting for the first status check".into(),
            }),
            status_tx,
            status_rx: Mutex::new(Some(status_rx)),
            local_locks: Mutex::new(HashMap::new()),
            held: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
        });
        let backend = Self { inner };
        backend.inner.channel().await?;
        backend.inner.lease(LeaseKind::Lock, None).await?;
        let checker = tokio::spawn(Arc::clone(&backend.inner).status_loop());
        backend.inner.spawn_task(checker.abort_handle());
        Ok(backend)
    }

    /// The owner's initial synchronization finished: leave `bootstrap_qps`
    /// for `qps` (§3.2.4).
    pub fn bootstrap_done(&self) {
        self.inner.limiter.bootstrap_done();
    }
}

impl Drop for EtcdBackend {
    fn drop(&mut self) {
        // Without close(): stop the tasks; the leases expire server-side.
        let _ = self.inner.stop();
    }
}

impl Kvstore for EtcdBackend {
    async fn get(&self, key: &str, guard: Option<&Guard>) -> Result<Option<Value>> {
        self.inner.ensure_open()?;
        let _permit = self.inner.limiter.acquire().await;
        self.inner.get_raw(key, guard).await
    }

    async fn put(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> Result<()> {
        check_size(key, &data)?;
        self.inner.ensure_open()?;
        let _permit = self.inner.limiter.acquire().await;
        let lease_id = self.inner.lease_for_write(key, lease).await?;
        self.inner.put_raw(key, data, lease_id, guard).await
    }

    async fn put_if_absent(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> Result<bool> {
        self.inner.put_if_absent(key, data, lease, guard).await
    }

    async fn put_if_different(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> Result<bool> {
        check_size(key, &data)?;
        self.inner.ensure_open()?;
        let _permit = self.inner.limiter.acquire().await;
        let current = self.inner.get_raw(key, guard).await?;
        let lease_id = self.inner.lease_for_write(key, lease).await?;
        if let Some(current) = current {
            let same_lease = lease == Lease::None || current.lease_id == lease_id;
            if current.data == data && same_lease {
                return Ok(false);
            }
        }
        self.inner.put_raw(key, data, lease_id, guard).await?;
        Ok(true)
    }

    async fn delete(&self, key: &str, guard: Option<&Guard>) -> Result<()> {
        self.inner.ensure_open()?;
        let _permit = self.inner.limiter.acquire().await;
        self.inner.delete_raw(key, guard).await
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<()> {
        self.inner.ensure_open()?;
        let _permit = self.inner.limiter.acquire().await;
        let request = DeleteRangeRequest {
            key: prefix.as_bytes().to_vec(),
            range_end: prefix_end(prefix.as_bytes()),
            ..Default::default()
        };
        self.inner
            .call::<_, DeleteRangeResponse>(DELETE_RANGE, &request)
            .await?;
        self.inner.keys.release_prefix(prefix);
        Ok(())
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        guard: Option<&Guard>,
    ) -> Result<BTreeMap<String, Value>> {
        self.inner.ensure_open()?;
        // One token for the whole paginated list (§3.2.4).
        let _permit = self.inner.limiter.acquire().await;
        Ok(self.inner.paginated(prefix, guard).await?.0)
    }

    async fn watch(&self, prefix: &str) -> Result<mpsc::Receiver<Event>> {
        self.inner.ensure_open()?;
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);
        let task = tokio::spawn(watch::run(Arc::clone(&self.inner), prefix.to_owned(), tx));
        self.inner.spawn_task(task.abort_handle());
        Ok(rx)
    }

    async fn lock(&self, path: &str) -> Result<Guard> {
        self.inner.lock(path).await
    }

    async fn unlock(&self, guard: &Guard) -> Result<()> {
        self.inner.unlock(guard, true).await
    }

    fn lease_expired(&self, prefix: &str, observer: Option<Observer>) {
        let mut observers = locked(&self.inner.observers);
        observers.retain(|(registered, _)| registered != prefix);
        if let Some(observer) = observer {
            observers.push((prefix.to_owned(), observer));
        }
    }

    fn status(&self) -> Status {
        locked(&self.inner.status).clone()
    }

    fn status_errors(&self) -> Option<mpsc::Receiver<Error>> {
        locked(&self.inner.status_rx).take()
    }

    async fn txn(&self, compares: Vec<Compare>, puts: Vec<TxnPut>) -> Result<bool> {
        self.inner.txn(compares, puts).await
    }

    async fn lease_for(&self, key: &str) -> Result<i64> {
        self.inner.ensure_open()?;
        self.inner.lease(LeaseKind::Key, Some(key)).await
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used
)]
mod tests {
    use super::*;

    #[test]
    fn client_yaml_parses() {
        let text = "\
endpoints:
- https://cluster2.mesh.cilium.io:2379
- \"https://10.0.0.2:2379\"   # second
trusted-ca-file: /var/lib/cilium/clustermesh/common-etcd-client-ca.crt
key-file:        /var/lib/cilium/clustermesh/common-etcd-client.key
cert-file:       '/var/lib/cilium/clustermesh/common-etcd-client.crt'
# a comment
cilium-host-aliases:            # optional extension, ignored by etcd itself
- hostname: cluster2.mesh.cilium.io
  ips: [192.0.2.10, 192.0.2.11]
";
        let config = parse_client_yaml(text).unwrap();
        assert_eq!(
            config.endpoints,
            vec![
                "https://cluster2.mesh.cilium.io:2379".to_owned(),
                "https://10.0.0.2:2379".to_owned()
            ]
        );
        assert_eq!(
            config.trusted_ca_file,
            Some(PathBuf::from(
                "/var/lib/cilium/clustermesh/common-etcd-client-ca.crt"
            ))
        );
        assert_eq!(
            config.key_file,
            Some(PathBuf::from(
                "/var/lib/cilium/clustermesh/common-etcd-client.key"
            ))
        );
        assert_eq!(
            config.cert_file,
            Some(PathBuf::from(
                "/var/lib/cilium/clustermesh/common-etcd-client.crt"
            ))
        );
        assert_eq!(config.qps, 20);
        assert_eq!(config.list_limit, 256);

        let flow = parse_client_yaml("endpoints: [http://a:1, 'http://b:2']\n").unwrap();
        assert_eq!(
            flow.endpoints,
            vec!["http://a:1".to_owned(), "http://b:2".to_owned()]
        );
        assert_eq!(flow.trusted_ca_file, None);
        let single = parse_client_yaml("endpoints: http://a:1\n").unwrap();
        assert_eq!(single.endpoints, vec!["http://a:1".to_owned()]);
        let indented = parse_client_yaml("endpoints:\n  - http://a:1\n  - http://b:2\n").unwrap();
        assert_eq!(indented.endpoints.len(), 2);
        assert!(parse_client_yaml("trusted-ca-file: /x\n").is_err());
    }

    #[test]
    fn status_messages_render() {
        let endpoints = [
            "https://a:2379 - 3.5.0 (Leader)".to_owned(),
            "https://b:2379 - 3.5.0".to_owned(),
        ];
        let ok = render_status(2, &endpoints, 1, 1, &Ok(()), 0);
        assert_eq!(ok.state, State::Ok);
        assert_eq!(
            ok.message,
            "etcd: 2/2 connected, leases=1, lock leases=1, has-quorum=true: \
             https://a:2379 - 3.5.0 (Leader); https://b:2379 - 3.5.0"
        );
        let degraded = render_status(1, &endpoints, 0, 1, &Err("lock timeout".into()), 2);
        assert_eq!(degraded.state, State::Ok);
        assert!(degraded.message.contains("has-quorum=lock timeout: "));
        let failed = render_status(1, &endpoints, 0, 1, &Err("lock timeout".into()), 3);
        assert_eq!(failed.state, State::Failure);
        assert_eq!(
            failed.message,
            "Err: quorum check failed 3 times in a row: lock timeout"
        );
        let none = render_status(0, &endpoints, 0, 0, &Ok(()), 0);
        assert_eq!(none.state, State::Failure);
        assert_eq!(
            none.message,
            "Err: not able to connect to any etcd endpoints"
        );
    }

    #[test]
    fn shuffles_and_randoms() {
        let mut items: Vec<u32> = (0..32).collect();
        shuffle(&mut items);
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..32).collect::<Vec<_>>());
        assert_ne!(random_u64(), random_u64());
        let mut one = [1];
        shuffle(&mut one);
        assert_eq!(one, [1]);
    }

    #[test]
    fn defaults() {
        let config = EtcdConfig::default();
        assert_eq!(config.qps, 20);
        assert_eq!(config.bootstrap_qps, 0);
        assert_eq!(config.max_inflight, 20);
        assert_eq!(config.key_lease_ttl, KEY_LEASE_TTL);
        assert_eq!(config.resync_interval, Duration::from_secs(300));
    }
}
