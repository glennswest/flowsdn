//! flowsdn's kvstore client (spec 20 §3.1-3.5, §5).
//!
//! - [`Kvstore`]: the client trait of §3.1, plus [`Kvstore::txn`] and
//!   [`Kvstore::lease_for`] for the cluster-config ownership claim of §12
//!   decision 9 (spec 20's #567 amendment).
//! - [`memory::MemoryBackend`]: an in-process store with revisions, leases and
//!   watches, for unit tests and the scripttest harness (§11.1).
//! - [`etcd::EtcdBackend`]: etcd v3 over HTTP/2 (`h2`), hand-written `prost`
//!   messages for the RPCs of §2.6, TLS through Fedora OpenSSL (ADR-0016).
//! - [`sync_store::SyncStore`]: one-way export with synced canaries (§3.4.2).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc;

pub mod etcd;
pub mod memory;
pub mod sync_store;

/// The largest value written (§2.7 F24).
pub const MAX_VALUE: usize = 4 * 1024 * 1024;
/// Keys bound to one lease before another is granted (§3.3.1).
pub const KEYS_PER_LEASE: usize = 1000;
/// The default key lease TTL (`kvstore-lease-ttl`, §3.3.1).
pub const KEY_LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
/// The lock lease TTL (§3.3.1).
pub const LOCK_LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(25);
/// The longest lock acquisition (§3.3.2).
pub const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// A stored value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Value {
    pub data: Vec<u8>,
    pub mod_revision: i64,
    pub create_revision: i64,
    /// 0: not leased.
    pub lease_id: i64,
}

/// Whether a write is bound to the client's key lease (§3.3.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lease {
    None,
    Attached,
}

/// A held distributed lock (§3.3.2): its key, and the ownership compare
/// `CreateRevision(key) == create_revision` the `guard` arguments use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Guard {
    pub key: String,
    pub create_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Create,
    Modify,
    Delete,
    /// The initial list is complete (once per watcher, never on a relist).
    ListDone,
}

/// A watch event. `value` is None for deletes and `ListDone`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub kind: EventKind,
    pub key: String,
    pub value: Option<Value>,
}

/// A transaction compare (§12 decision 9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Compare {
    /// `Version(key) == 0`.
    Absent(String),
    /// The key holds exactly these bytes, at this mod revision, on this lease
    /// (0: none).
    Exact {
        key: String,
        data: Vec<u8>,
        mod_revision: i64,
        lease_id: i64,
    },
}

/// A transaction write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxnPut {
    pub key: String,
    pub data: Vec<u8>,
    pub lease: Lease,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum State {
    #[default]
    Ok,
    Warning,
    Failure,
}

/// The client's state and its human-readable message (§3.2.5).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Status {
    pub state: State,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A guarded operation's lock compare failed (§3.1 rule 2).
    LockLeaseExpired,
    /// A value over [`MAX_VALUE`].
    TooLarge { key: String, size: usize },
    /// The client was closed.
    Closed,
    /// A lock was not acquired within [`LOCK_TIMEOUT`].
    LockTimeout(String),
    /// The server's lease is gone (`lease not found`).
    LeaseNotFound(i64),
    /// Anything else from the store or the transport.
    Backend(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockLeaseExpired => f.write_str("lock lease expired"),
            Self::TooLarge { key, size } => {
                write!(f, "value of {key} is {size} bytes, over {MAX_VALUE}")
            }
            Self::Closed => f.write_str("kvstore client closed"),
            Self::LockTimeout(path) => write!(f, "lock timeout on {path}"),
            Self::LeaseNotFound(id) => write!(f, "lease {id:x} not found"),
            Self::Backend(text) => f.write_str(text),
        }
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Called with each key whose lease was lost (§3.3.1).
pub type Observer = Arc<dyn Fn(&str) + Send + Sync>;

/// Refuse a value over [`MAX_VALUE`].
pub fn check_size(key: &str, data: &[u8]) -> Result<()> {
    if data.len() > MAX_VALUE {
        return Err(Error::TooLarge {
            key: key.into(),
            size: data.len(),
        });
    }
    Ok(())
}

/// The kvstore client (spec 20 §3.1). Every operation but `lock`, `status`
/// and the lease keepalives passes the backend's rate limiter.
pub trait Kvstore: Send + Sync + 'static {
    /// `None` for a missing key.
    fn get(
        &self,
        key: &str,
        guard: Option<&Guard>,
    ) -> impl Future<Output = Result<Option<Value>>> + Send;
    fn put(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// One `Txn` with `Version(key) == 0`; false: the key existed.
    fn put_if_absent(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Read-compare-write: writes when the bytes differ or, for a leased
    /// write, when the stored lease is not the one the key would get now.
    /// True: written.
    fn put_if_different(
        &self,
        key: &str,
        data: Vec<u8>,
        lease: Lease,
        guard: Option<&Guard>,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Idempotent.
    fn delete(&self, key: &str, guard: Option<&Guard>) -> impl Future<Output = Result<()>> + Send;
    fn delete_prefix(&self, prefix: &str) -> impl Future<Output = Result<()>> + Send;
    /// The whole prefix, read at one revision (§5.3).
    fn list_prefix(
        &self,
        prefix: &str,
        guard: Option<&Guard>,
    ) -> impl Future<Output = Result<BTreeMap<String, Value>>> + Send;
    /// List-then-watch (§5.4): `Create`/`Modify` for the listed keys,
    /// `ListDone`, then changes; a broken watch relists and reports keys
    /// deleted meanwhile. The receiver closes when the client does.
    fn watch(&self, prefix: &str) -> impl Future<Output = Result<mpsc::Receiver<Event>>> + Send;
    /// Take the distributed lock on `path` (§3.3.2); release with
    /// [`Kvstore::unlock`].
    fn lock(&self, path: &str) -> impl Future<Output = Result<Guard>> + Send;
    fn unlock(&self, guard: &Guard) -> impl Future<Output = Result<()>> + Send;
    /// Register (`Some`) or remove (`None`) the observer of lost leases for
    /// keys under `prefix`.
    fn lease_expired(&self, prefix: &str, observer: Option<Observer>);
    fn status(&self) -> Status;
    /// The status checker's errors (bounded, 128); taken once.
    fn status_errors(&self) -> Option<mpsc::Receiver<Error>>;
    /// **DEVIATION (#567, §12 decision 9):** compares and leased writes in
    /// one transaction; true when the compares held and the writes were made.
    fn txn(
        &self,
        compares: Vec<Compare>,
        puts: Vec<TxnPut>,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// **DEVIATION (#567):** the key lease `key` gets on a leased write now
    /// (granting one if needed, §5.5), so a caller can tell whether a stored
    /// key is on it.
    fn lease_for(&self, key: &str) -> impl Future<Output = Result<i64>> + Send;
    /// Close the connection and stop the lease keepalives.
    fn close(&self) -> impl Future<Output = ()> + Send;
}

/// Join key elements (§5.1): `/` between them, `//` collapsed, no trailing
/// `/`. `.` and `..` are ordinary bytes.
pub fn join(elements: &[&str]) -> String {
    let mut key = elements.join("/");
    while key.contains("//") {
        key = key.replace("//", "/");
    }
    while key.ends_with('/') {
        key.pop();
    }
    key
}

/// The end of the range of keys starting with `prefix`: the prefix with its
/// last byte incremented (bytes 0xff dropped first); empty for "to the end".
pub fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if let Some(next) = last.checked_add(1) {
            end.push(next);
            return end;
        }
    }
    vec![0]
}

/// A watch prefix ends with `/`, so `.../c1` never sees `.../c11` (§3.4.3).
pub fn watch_prefix(prefix: &str) -> String {
    if prefix.ends_with('/') {
        prefix.to_owned()
    } else {
        format!("{prefix}/")
    }
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ`, the canary and heartbeat value.
// Day counts from a u64 of seconds divided by 86 400 cannot overflow i64.
#[allow(clippy::arithmetic_side_effects)]
pub fn rfc3339(time: std::time::SystemTime) -> String {
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Civil from days (Howard Hinnant's algorithm).
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn keys_join_and_ranges() {
        assert_eq!(
            join(&["flowsdn/state", "nodes/v1", "c1", ""]),
            "flowsdn/state/nodes/v1/c1"
        );
        assert_eq!(join(&["a//b/", "/c/"]), "a/b/c");
        assert_eq!(join(&["a", "..", "."]), "a/../.");
        assert_eq!(prefix_end(b"flowsdn/state/"), b"flowsdn/state0".to_vec());
        assert_eq!(prefix_end(b"a\xff"), b"b".to_vec());
        assert_eq!(watch_prefix("x/c1"), "x/c1/");
        assert_eq!(watch_prefix("x/c1/"), "x/c1/");
        assert_eq!(check_size("k", &[0; 16]), Ok(()));
        assert!(check_size("k", &vec![0; MAX_VALUE + 1]).is_err());
    }

    #[test]
    fn rfc3339_times() {
        let at = |s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s);
        assert_eq!(rfc3339(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(at(951_782_400)), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(at(1_791_302_693)), "2026-10-06T16:04:53Z");
    }
}
