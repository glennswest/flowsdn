use crate::{Key, Keyed, Revision, Table};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// Limits for a subscriber that does not acknowledge delivered revisions.
#[derive(Clone, Copy, Debug)]
pub struct StreamOptions {
    pub tombstone_max_age: Duration,
    pub tombstone_max_count: usize,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            tombstone_max_age: Duration::from_secs(600),
            tombstone_max_count: 65_536,
        }
    }
}

/// Changes describe current desired state, not an event log.
#[derive(Clone, Debug)]
pub enum Change<T> {
    Insert {
        row: Arc<T>,
        revision: Revision,
    },
    Delete {
        key: Key,
        revision: Revision,
    },
    /// Discard the old mirror and reconcile the following full population.
    /// Its rows retain their original revisions, possibly below this revision.
    Resync {
        revision: Revision,
    },
}

impl<T> Change<T> {
    pub fn revision(&self) -> Revision {
        match self {
            Self::Insert { revision, .. }
            | Self::Delete { revision, .. }
            | Self::Resync { revision } => *revision,
        }
    }
}

struct Progress {
    acked: Revision,
    last_ack: Instant,
    resync: bool,
}

pub(crate) struct StreamState {
    tombstones: BTreeMap<Revision, Key>,
    by_key: BTreeMap<Key, Revision>,
    subscribers: Vec<Weak<Mutex<Progress>>>,
    // Track real lost deletes, never infer loss from gaps between live revisions.
    discarded_through: Revision,
    last_gc: Instant,
    options: StreamOptions,
}

impl StreamState {
    pub(crate) fn new(options: StreamOptions) -> Self {
        Self {
            tombstones: BTreeMap::new(),
            by_key: BTreeMap::new(),
            subscribers: Vec::new(),
            discarded_through: 0,
            last_gc: Instant::now(),
            options,
        }
    }

    pub(crate) fn publish(&mut self, mutations: Vec<(Key, Revision, bool)>, revision: Revision) {
        for (key, at, deleted) in mutations {
            if let Some(previous) = self.by_key.remove(&key) {
                self.tombstones.remove(&previous);
            }
            if deleted {
                self.by_key.insert(key.clone(), at);
                self.tombstones.insert(at, key);
            }
        }
        self.maintain(revision, Instant::now());
    }

    fn maintain(&mut self, revision: Revision, now: Instant) {
        let mut low = revision;
        self.subscribers.retain(|weak| {
            let Some(progress) = weak.upgrade() else {
                return false;
            };
            let mut progress = progress.lock().expect("stream progress poisoned");
            let over_count = self.tombstones.len() > self.options.tombstone_max_count
                && self
                    .tombstones
                    .range((
                        std::ops::Bound::Excluded(progress.acked),
                        std::ops::Bound::Unbounded,
                    ))
                    .nth(self.options.tombstone_max_count)
                    .is_some();
            if progress.acked < revision
                && (over_count
                    || now.duration_since(progress.last_ack) > self.options.tombstone_max_age)
            {
                progress.acked = revision;
                progress.last_ack = now;
                progress.resync = true;
            }
            low = low.min(progress.acked);
            true
        });
        // Ordinary GC is throttled. Exceeding the hard count limit forces a
        // collection immediately after lagging subscribers have been resynced.
        if now.duration_since(self.last_gc) < Duration::from_secs(1)
            && self.tombstones.len() <= self.options.tombstone_max_count
        {
            return;
        }
        self.last_gc = now;
        while let Some((&revision, _)) = self.tombstones.first_key_value() {
            if revision > low {
                break;
            }
            if let Some(key) = self.tombstones.remove(&revision) {
                self.by_key.remove(&key);
                self.discarded_through = self.discarded_through.max(revision);
            }
        }
    }
}

/// A whole-table subscriber. `drain` delivers available state without blocking;
/// `next` waits when drained. Acknowledgements are explicit and never advance
/// beyond the delivered checkpoint returned by `revision()`.
///
/// Dropping releases retention. Lag limits may force a resync; callers must
/// handle it even after their initial population. No task or timer is spawned:
/// retention maintenance runs during writes and subscriber operations.
pub struct ChangeStream<'a, T: Keyed> {
    table: &'a Table<T>,
    notify: watch::Receiver<Revision>,
    progress: Arc<Mutex<Progress>>,
    pending: VecDeque<Change<T>>,
    cursor: Revision,
    delivered: Revision,
}

impl<T: Keyed> Table<T> {
    /// Subscribe atomically with the initial snapshot. `watch(0)` starts with
    /// all current rows. A historical checkpoint whose deletions were collected
    /// (or a checkpoint ahead of the table) begins with `Resync`.
    ///
    /// A gap between retained revisions alone does not prove a lost deletion;
    /// the table records the actual discarded-delete watermark instead.
    pub fn watch(&self, from_revision: Revision) -> ChangeStream<'_, T> {
        let notify = self.notify.subscribe();
        let mut registry = self.streams.lock().expect("stream registry poisoned");
        let version = self.published.load_full();
        let progress = Arc::new(Mutex::new(Progress {
            acked: from_revision.min(version.revision),
            last_ack: Instant::now(),
            resync: from_revision != 0
                && (from_revision < registry.discarded_through || from_revision > version.revision),
        }));
        registry.subscribers.push(Arc::downgrade(&progress));
        let mut stream = ChangeStream {
            table: self,
            notify,
            progress,
            pending: VecDeque::new(),
            cursor: from_revision.min(version.revision),
            delivered: from_revision.min(version.revision),
        };
        if from_revision == 0 {
            stream.populate(&version);
        }
        stream
    }

    /// Current retained deletion count, useful for diagnostics.
    pub fn tombstone_count(&self) -> usize {
        self.streams
            .lock()
            .expect("stream registry poisoned")
            .tombstones
            .len()
    }
}

impl<T: Keyed> ChangeStream<'_, T> {
    fn populate(&mut self, version: &crate::Version<T>) {
        self.cursor = version.revision;
        self.pending
            .extend(version.revisions.values().filter_map(|key| {
                version.rows.get(key).map(|(row, revision)| Change::Insert {
                    row: row.clone(),
                    revision: *revision,
                })
            }));
    }

    /// Largest checkpoint fully delivered, including gaps with no changes.
    /// After consuming a batch, `ack(revision())` releases its tombstones.
    pub fn revision(&self) -> Revision {
        self.delivered
    }

    /// Acknowledge at most the delivered checkpoint. Returns the effective
    /// acknowledgement; older acknowledgements cannot move it backwards.
    pub fn ack(&mut self, revision: Revision) -> Revision {
        let mut registry = self.table.streams.lock().expect("stream registry poisoned");
        let acked = {
            let mut progress = self.progress.lock().expect("stream progress poisoned");
            let next = revision.min(self.delivered);
            if next > progress.acked {
                progress.acked = next;
                progress.last_ack = Instant::now();
            }
            progress.acked
        };
        registry.maintain(self.table.published.load().revision, Instant::now());
        acked
    }

    /// Return at most `max` changes, globally ordered by revision within a
    /// population or live batch. A resync starts a new population and may reset
    /// ordering. Zero leaves both delivery and acknowledgement unchanged.
    pub fn drain(&mut self, max: usize) -> Vec<Change<T>> {
        if max == 0 {
            return Vec::new();
        }
        self.notify.borrow_and_update();
        let table = self.table;
        let mut registry = table.streams.lock().expect("stream registry poisoned");
        let version = table.published.load_full();
        registry.maintain(version.revision, Instant::now());
        let resync = {
            let mut progress = self.progress.lock().expect("stream progress poisoned");
            std::mem::take(&mut progress.resync)
        };
        if resync {
            self.pending.clear();
            self.pending.push_back(Change::Resync {
                revision: version.revision,
            });
            self.populate(&version);
        }
        if self.pending.is_empty() {
            let lower = std::ops::Bound::Excluded(self.cursor);
            let upper = std::ops::Bound::Unbounded;
            let mut deletes = registry
                .tombstones
                .range((lower, upper))
                .map(|(revision, key)| Change::Delete {
                    key: key.clone(),
                    revision: *revision,
                })
                .peekable();
            let mut inserts = version
                .revisions
                .range((lower, upper))
                .filter_map(|(revision, key)| {
                    version.rows.get(key).map(|(row, _)| Change::Insert {
                        row: row.clone(),
                        revision: *revision,
                    })
                })
                .peekable();
            // Merge the two ordered indexes lazily. Small drains must not
            // scan or clone the entire remaining backlog on every call.
            let mut changes = Vec::new();
            while changes.len() < max {
                let next = match (deletes.peek(), inserts.peek()) {
                    (Some(delete), Some(insert)) if delete.revision() < insert.revision() => deletes.next(),
                    (_, Some(_)) => inserts.next(),
                    (Some(_), None) => deletes.next(),
                    (None, None) => break,
                };
                if let Some(change) = next {
                    changes.push(change);
                }
            }
            // Only snapshot populations need buffering. Live updates can be
            // coalesced again between drains, bounding retained row versions.
            if let Some(change) = changes.last() {
                self.cursor = change.revision();
            } else {
                self.cursor = version.revision;
            }
            self.delivered = self.cursor;
            return changes;
        }
        let changes: Vec<_> = self.pending.drain(..max.min(self.pending.len())).collect();
        if self.pending.is_empty() {
            self.delivered = self.cursor;
        }
        changes
    }

    /// Wait for one change. Cancellation before delivery cannot consume a
    /// change, and publication between draining and awaiting cannot be lost.
    pub async fn next(&mut self) -> Option<Change<T>> {
        loop {
            if let Some(change) = self.drain(1).pop() {
                return Some(change);
            }
            self.notify.changed().await.ok()?;
        }
    }
}

impl<T: Keyed> Drop for ChangeStream<'_, T> {
    fn drop(&mut self) {
        let mut registry = self.table.streams.lock().expect("stream registry poisoned");
        registry
            .subscribers
            .retain(|weak| !Weak::ptr_eq(weak, &Arc::downgrade(&self.progress)));
        registry.maintain(self.table.published.load().revision, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    #[derive(Clone)]
    struct Item(u8);
    impl Keyed for Item {
        fn primary_key(&self) -> Key {
            vec![self.0]
        }
    }

    #[tokio::test]
    async fn slowest_ack_and_drop_control_collection() {
        let table = Table::<Item>::new(vec![]).unwrap();
        let mut fast = table.watch(0);
        let mut slow = table.watch(0);
        table.delete(&[1]).await.unwrap();
        fast.drain(10);
        fast.ack(1);
        let now = Instant::now();
        {
            let mut state = table.streams.lock().unwrap();
            state.maintain(1, now + Duration::from_secs(2));
            assert_eq!(state.tombstones.len(), 1);
        }
        slow.drain(10);
        // Delivery alone must not release a tombstone.
        {
            let mut state = table.streams.lock().unwrap();
            state.maintain(1, now + Duration::from_secs(4));
            assert_eq!(state.tombstones.len(), 1);
        }
        drop(slow);
        {
            let mut state = table.streams.lock().unwrap();
            state.maintain(1, now + Duration::from_secs(6));
            assert!(state.tombstones.is_empty());
            assert_eq!(state.discarded_through, 1);
        }
    }

    #[tokio::test]
    async fn elapsed_ack_limit_forces_resync_without_count_overflow() {
        let table = Table::with_stream_options(
            vec![],
            StreamOptions {
                tombstone_max_age: Duration::from_secs(10),
                ..StreamOptions::default()
            },
        )
        .unwrap();
        table.insert(Item(1)).await.unwrap();
        let mut stream = table.watch(1);
        table.delete(&[1]).await.unwrap();
        table
            .streams
            .lock()
            .unwrap()
            .maintain(2, Instant::now() + Duration::from_secs(11));
        assert!(matches!(
            stream.drain(10).as_slice(),
            [Change::Resync { revision: 2 }]
        ));
        assert_eq!(table.tombstone_count(), 0);
    }

    #[tokio::test]
    async fn ordinary_revision_gaps_do_not_imply_lost_deletes() {
        let table = Table::new(vec![]).unwrap();
        let _retainer = table.watch(0);
        for _ in 0..20 {
            table.insert(Item(1)).await.unwrap();
        }
        table.delete(&[1]).await.unwrap();
        let mut stream = table.watch(1);
        assert!(matches!(
            stream.drain(10).as_slice(),
            [Change::Delete { revision: 21, .. }]
        ));
    }
}
