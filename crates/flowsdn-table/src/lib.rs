//! Indexed tables and change streams from spec 00 §§3.1.1–3.1.6.
//!
//! Snapshots are immutable and cheap; writers publish one version atomically.
//! Whole-table streams coalesce writes and retain deletions until acknowledged.
//! Named initializers gate readiness after registration is sealed.
//! Metrics and reconciliation are not implemented yet.
use arc_swap::ArcSwap;
use imbl::OrdMap;
use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};
use tokio::sync::{Mutex, watch};

mod initialization;
use initialization::Initialization;
pub use initialization::{InitializationError, Initializer};

mod streams;
use streams::StreamState;
pub use streams::{Change, ChangeStream, StreamOptions};

pub type Key = Vec<u8>;
pub type Revision = u64;
pub type Row<T> = (Arc<T>, Revision);
type IndexKeys<T> = dyn Fn(&T) -> Vec<Key> + Send + Sync;
type IndexMap = OrdMap<(Key, Key), ()>;

/// Rows must remain logically immutable after insertion (including any
/// interior-mutable state). Construct and insert a replacement to change a row.
pub trait Keyed: Clone + Send + Sync + 'static {
    fn primary_key(&self) -> Key;
}

/// Explicit display order for the harvested table expectations (#205).
/// `cells()` must return exactly one cell per header, in the same order.
/// Whitespace alignment and escaping belong to the renderer, not the row.
pub trait TableRender {
    fn headers() -> &'static [&'static str];
    fn cells(&self) -> Vec<String>;
}

/// A multi-key secondary index. Keys returned more than once are deduplicated.
/// The callback must return stable keys for an immutable row: deletion and
/// replacement recompute its old keys to remove the corresponding entries.
pub struct Index<T> {
    name: &'static str,
    unique: bool,
    keys: Arc<IndexKeys<T>>,
}

impl<T> Index<T> {
    pub fn new(
        name: &'static str,
        unique: bool,
        keys: impl Fn(&T) -> Vec<Key> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            unique,
            keys: Arc::new(keys),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TableError {
    InvalidIndexName(&'static str),
    UnknownIndex(String),
    NonUniqueIndex(String),
    UniqueViolation { index: &'static str, key: Key },
    RevisionMismatch { current: Option<Revision> },
    RevisionExhausted,
    PrimaryKeyChanged,
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIndexName(name) => write!(f, "duplicate or reserved index name: {name}"),
            Self::UnknownIndex(name) => write!(f, "unknown index: {name}"),
            Self::NonUniqueIndex(name) => write!(f, "get requires a unique index: {name}"),
            Self::UniqueViolation { index, key } => {
                write!(f, "unique index {index} collision on {key:?}")
            }
            Self::RevisionMismatch { current } => {
                write!(f, "revision mismatch (current: {current:?})")
            }
            Self::RevisionExhausted => write!(f, "table revision exhausted"),
            Self::PrimaryKeyChanged => write!(f, "modify cannot change a row's primary key"),
        }
    }
}
impl Error for TableError {}

#[derive(Clone)]
struct Version<T: Keyed> {
    revision: Revision,
    rows: OrdMap<Key, Row<T>>,
    revisions: OrdMap<Revision, Key>,
    indexes: Vec<IndexMap>,
}

/// One table, with lock-free snapshot publication and serialized writers.
pub struct Table<T: Keyed> {
    indexes: Arc<Vec<Index<T>>>,
    published: ArcSwap<Version<T>>,
    writer: Mutex<()>,
    streams: std::sync::Mutex<StreamState>,
    notify: watch::Sender<Revision>,
    initialization: Arc<Initialization>,
}

impl<T: Keyed> Table<T> {
    /// `primary` is reserved for the unique primary index.
    pub fn new(indexes: Vec<Index<T>>) -> Result<Self, TableError> {
        Self::with_stream_options(indexes, StreamOptions::default())
    }

    /// Configure deletion retention and the maximum lag of each subscriber.
    pub fn with_stream_options(
        indexes: Vec<Index<T>>,
        options: StreamOptions,
    ) -> Result<Self, TableError> {
        let mut names = BTreeSet::from(["primary"]);
        for index in &indexes {
            if index.name.is_empty() || !names.insert(index.name) {
                return Err(TableError::InvalidIndexName(index.name));
            }
        }
        let version = Version {
            revision: 0,
            rows: OrdMap::new(),
            revisions: OrdMap::new(),
            indexes: indexes.iter().map(|_| OrdMap::new()).collect(),
        };
        Ok(Self {
            indexes: Arc::new(indexes),
            published: ArcSwap::from_pointee(version),
            writer: Mutex::new(()),
            streams: std::sync::Mutex::new(StreamState::new(options)),
            notify: watch::channel(0).0,
            initialization: Arc::new(Initialization::new()),
        })
    }

    /// O(1); no writer lock is taken. A retained snapshot never changes.
    pub fn snapshot(&self) -> Snapshot<T> {
        Snapshot {
            version: self.published.load_full(),
            indexes: self.indexes.clone(),
        }
    }

    /// Publishes all successful operations together. A closure returning Err
    /// still commits its successful prefix; this is not a rollback transaction.
    /// Callbacks must not block on another writer to this table.
    pub async fn batch<R>(&self, apply: impl FnOnce(&mut Write<'_, T>) -> R) -> R {
        let _writer = self.writer.lock().await;
        let mut version = self.published.load_full().as_ref().clone();
        let previous_revision = version.revision;
        let mut mutations = Vec::new();
        let result = apply(&mut Write {
            version: &mut version,
            indexes: &self.indexes,
            mutations: &mut mutations,
        });
        if previous_revision != version.revision {
            let mut streams = self.streams.lock().expect("stream registry poisoned");
            let revision = version.revision;
            streams.publish(mutations, revision);
            self.published.store(Arc::new(version));
            self.notify.send_replace(revision);
        }
        result
    }

    pub async fn insert(&self, row: T) -> Result<WriteResult<T>, TableError> {
        self.batch(|write| write.insert(row)).await
    }
    pub async fn insert_if_revision(
        &self,
        row: T,
        expected: Revision,
    ) -> Result<WriteResult<T>, TableError> {
        self.batch(|write| write.insert_if_revision(row, expected))
            .await
    }
    pub async fn delete(&self, key: &[u8]) -> Result<WriteResult<T>, TableError> {
        self.batch(|write| write.delete(key)).await
    }
    pub async fn delete_if_revision(
        &self,
        key: &[u8],
        expected: Revision,
    ) -> Result<WriteResult<T>, TableError> {
        self.batch(|write| write.delete_if_revision(key, expected))
            .await
    }
    pub async fn modify(
        &self,
        key: &[u8],
        modify: impl FnOnce(Option<&T>) -> Option<T>,
    ) -> Result<WriteResult<T>, TableError> {
        self.batch(|write| write.modify(key, modify)).await
    }
    pub async fn delete_all(&self) -> Result<usize, TableError> {
        self.batch(|write| write.delete_all()).await
    }
}

/// The previous row and the resulting table revision (unchanged for a no-op).
#[derive(Debug)]
pub struct WriteResult<T> {
    pub previous: Option<Arc<T>>,
    pub revision: Revision,
}

/// Scoped batch writer. Each failed operation leaves every index unchanged.
pub struct Write<'a, T: Keyed> {
    version: &'a mut Version<T>,
    indexes: &'a [Index<T>],
    mutations: &'a mut Vec<(Key, Revision, bool)>,
}

impl<T: Keyed> Write<'_, T> {
    fn require_revision(&self, key: &[u8], expected: Revision) -> Result<(), TableError> {
        let current = self.version.rows.get(key).map(|(_, revision)| *revision);
        if current != Some(expected) {
            return Err(TableError::RevisionMismatch { current });
        }
        Ok(())
    }

    fn next_revision(&self) -> Result<Revision, TableError> {
        self.version
            .revision
            .checked_add(1)
            .ok_or(TableError::RevisionExhausted)
    }

    fn remove_indexes(&mut self, key: &Key, row: &T, revision: Revision) {
        self.version.revisions.remove(&revision);
        for (index, map) in self.indexes.iter().zip(&mut self.version.indexes) {
            for secondary in (index.keys)(row) {
                map.remove(&(secondary, key.clone()));
            }
        }
    }

    pub fn insert(&mut self, row: T) -> Result<WriteResult<T>, TableError> {
        let key = row.primary_key();
        let revision = self.next_revision()?;
        let keys: Vec<BTreeSet<Key>> = self
            .indexes
            .iter()
            .map(|index| (index.keys)(&row).into_iter().collect())
            .collect();
        // Validate every unique key before removing anything from the old row.
        for ((index, map), keys) in self.indexes.iter().zip(&self.version.indexes).zip(&keys) {
            if index.unique {
                for secondary in keys {
                    if let Some(((found, primary), _)) =
                        map.range((secondary.clone(), Key::new())..).next()
                        && found == secondary
                        && primary != &key
                    {
                        return Err(TableError::UniqueViolation {
                            index: index.name,
                            key: secondary.clone(),
                        });
                    }
                }
            }
        }
        let previous = self.version.rows.get(&key).cloned();
        if let Some((old, old_revision)) = &previous {
            self.remove_indexes(&key, old, *old_revision);
        }
        for (map, keys) in self.version.indexes.iter_mut().zip(keys) {
            for secondary in keys {
                map.insert((secondary, key.clone()), ());
            }
        }
        self.version
            .rows
            .insert(key.clone(), (Arc::new(row), revision));
        self.version.revisions.insert(revision, key.clone());
        self.mutations.push((key, revision, false));
        self.version.revision = revision;
        Ok(WriteResult {
            previous: previous.map(|(row, _)| row),
            revision,
        })
    }

    pub fn insert_if_revision(
        &mut self,
        row: T,
        expected: Revision,
    ) -> Result<WriteResult<T>, TableError> {
        self.require_revision(&row.primary_key(), expected)?;
        self.insert(row)
    }

    /// Even an absent-key delete consumes a revision, matching spec 00.
    /// An absent-key delete also produces a tombstone for change streams.
    pub fn delete(&mut self, key: &[u8]) -> Result<WriteResult<T>, TableError> {
        let revision = self.next_revision()?;
        let previous = self.version.rows.remove(key);
        self.mutations.push((key.to_vec(), revision, true));
        if let Some((old, old_revision)) = &previous {
            self.remove_indexes(&key.to_vec(), old, *old_revision);
        }
        self.version.revision = revision;
        Ok(WriteResult {
            previous: previous.map(|(row, _)| row),
            revision,
        })
    }

    pub fn delete_if_revision(
        &mut self,
        key: &[u8],
        expected: Revision,
    ) -> Result<WriteResult<T>, TableError> {
        self.require_revision(key, expected)?;
        self.delete(key)
    }

    pub fn modify(
        &mut self,
        key: &[u8],
        modify: impl FnOnce(Option<&T>) -> Option<T>,
    ) -> Result<WriteResult<T>, TableError> {
        let current = self.version.rows.get(key);
        match modify(current.map(|(row, _)| row.as_ref())) {
            Some(row) => {
                if row.primary_key() != key {
                    return Err(TableError::PrimaryKeyChanged);
                }
                self.insert(row)
            }
            None if current.is_some() => self.delete(key),
            None => Ok(WriteResult {
                previous: None,
                revision: self.version.revision,
            }),
        }
    }

    pub fn delete_all(&mut self) -> Result<usize, TableError> {
        let keys: Vec<_> = self.version.rows.keys().cloned().collect();
        let count = u64::try_from(keys.len()).map_err(|_| TableError::RevisionExhausted)?;
        self.version
            .revision
            .checked_add(count)
            .ok_or(TableError::RevisionExhausted)?;
        for key in &keys {
            self.delete(key)?;
        }
        Ok(keys.len())
    }
}

#[derive(Clone)]
pub struct Snapshot<T: Keyed> {
    version: Arc<Version<T>>,
    indexes: Arc<Vec<Index<T>>>,
}

impl<T: Keyed> Snapshot<T> {
    pub fn len(&self) -> usize {
        self.version.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.version.rows.is_empty()
    }
    pub fn revision(&self) -> Revision {
        self.version.revision
    }
    pub fn all(&self) -> impl Iterator<Item = Row<T>> + '_ {
        self.version.rows.values().cloned()
    }
    pub fn by_revision(&self, from: Revision) -> impl Iterator<Item = Row<T>> + '_ {
        self.version
            .revisions
            .range(from..)
            .filter_map(|(_, key)| self.version.rows.get(key).cloned())
    }
    fn index(&self, name: &str) -> Result<(&Index<T>, &IndexMap), TableError> {
        self.indexes
            .iter()
            .zip(&self.version.indexes)
            .find(|(index, _)| index.name == name)
            .ok_or_else(|| TableError::UnknownIndex(name.to_owned()))
    }
    pub fn get(&self, index: &str, key: &[u8]) -> Result<Option<Row<T>>, TableError> {
        if index == "primary" {
            return Ok(self.version.rows.get(key).cloned());
        }
        let (definition, _) = self.index(index)?;
        if !definition.unique {
            return Err(TableError::NonUniqueIndex(index.to_owned()));
        }
        Ok(self.list(index, key)?.into_iter().next())
    }
    pub fn list(&self, index: &str, key: &[u8]) -> Result<Vec<Row<T>>, TableError> {
        if index == "primary" {
            return Ok(self.version.rows.get(key).cloned().into_iter().collect());
        }
        let (_, map) = self.index(index)?;
        Ok(map
            .range((key.to_vec(), Key::new())..)
            .take_while(|((secondary, _), _)| secondary.as_slice() == key)
            .filter_map(|((_, primary), _)| self.version.rows.get(primary).cloned())
            .collect())
    }
    pub fn prefix(&self, index: &str, prefix: &[u8]) -> Result<Vec<Row<T>>, TableError> {
        if index == "primary" {
            return Ok(self
                .version
                .rows
                .range(prefix.to_vec()..)
                .take_while(|(key, _)| key.starts_with(prefix))
                .map(|(_, row)| row.clone())
                .collect());
        }
        let (_, map) = self.index(index)?;
        Ok(map
            .range((prefix.to_vec(), Key::new())..)
            .take_while(|((key, _), _)| key.starts_with(prefix))
            .filter_map(|((_, primary), _)| self.version.rows.get(primary).cloned())
            .collect())
    }
    pub fn lower_bound(&self, index: &str, key: &[u8]) -> Result<Vec<Row<T>>, TableError> {
        if index == "primary" {
            return Ok(self
                .version
                .rows
                .range(key.to_vec()..)
                .map(|(_, row)| row.clone())
                .collect());
        }
        let (_, map) = self.index(index)?;
        Ok(map
            .range((key.to_vec(), Key::new())..)
            .filter_map(|((_, primary), _)| self.version.rows.get(primary).cloned())
            .collect())
    }
}

/// Order-preserving encodings used by the primary and secondary indexes.
pub mod key {
    pub fn u32be(value: u32) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }
    pub fn u64be(value: u64) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }
    pub fn addr(value: std::net::IpAddr) -> Vec<u8> {
        match value {
            std::net::IpAddr::V4(address) => address.to_ipv6_mapped().octets().to_vec(),
            std::net::IpAddr::V6(address) => address.octets().to_vec(),
        }
    }
}
