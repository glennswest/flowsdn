//! Expired-key deletion protocol (spec 04 §5.3). The kernel adapter supplies
//! syscall results; errors include observed progress so metrics never guess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchStatus {
    Complete,
    Unsupported,
    Missing,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchResult {
    pub deleted: usize,
    pub status: BatchStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingleResult {
    Deleted,
    Missing,
    Failed,
}
pub trait DeleteMap<K> {
    fn delete_batch(&mut self, keys: &[K]) -> BatchResult;
    fn delete_one(&mut self, key: &K) -> SingleResult;
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    pub deleted: usize,
    pub skipped: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidProgress,
    BatchFailed(Counts),
    SingleFailed(Counts),
}
/// Capability is cached by the owning map adapter. EINVAL/EOPNOTSUPP should be
/// classified Unsupported only after validating the map and syscall arguments.
/// ENOENT provides no missing-key count: retry the unprocessed suffix one key
/// at a time and count only individually observed ENOENTs.
pub fn expired<K>(
    map: &mut impl DeleteMap<K>,
    keys: &[K],
    batch_enabled: &mut bool,
) -> Result<Counts, Error> {
    let mut counts = Counts::default();
    let mut pending = keys;
    if keys.is_empty() {
        return Ok(counts);
    }
    if *batch_enabled {
        let result = map.delete_batch(keys);
        pending = keys.get(result.deleted..).ok_or(Error::InvalidProgress)?;
        counts.deleted = result.deleted;
        match result.status {
            BatchStatus::Complete if pending.is_empty() => return Ok(counts),
            BatchStatus::Complete => return Err(Error::InvalidProgress),
            BatchStatus::Unsupported => *batch_enabled = false,
            BatchStatus::Missing => {}
            BatchStatus::Failed => return Err(Error::BatchFailed(counts)),
        }
    }
    for key in pending {
        match map.delete_one(key) {
            SingleResult::Deleted => counts.deleted = counts.deleted.saturating_add(1),
            SingleResult::Missing => counts.skipped = counts.skipped.saturating_add(1),
            SingleResult::Failed => return Err(Error::SingleFailed(counts)),
        }
    }
    Ok(counts)
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        batch: BatchResult,
        seen: u32,
        calls: u32,
    }
    impl DeleteMap<u32> for Fake {
        fn delete_batch(&mut self, _: &[u32]) -> BatchResult {
            self.calls = self.calls.saturating_add(1);
            self.batch
        }
        fn delete_one(&mut self, key: &u32) -> SingleResult {
            self.seen |= 1 << key;
            if *key == 2 {
                SingleResult::Missing
            } else {
                SingleResult::Deleted
            }
        }
    }
    #[test]
    fn partial_missing_retries_only_suffix_without_inventing_skips() {
        let mut f = Fake {
            batch: BatchResult {
                deleted: 1,
                status: BatchStatus::Missing,
            },
            seen: 0,
            calls: 0,
        };
        let mut enabled = true;
        assert_eq!(
            expired(&mut f, &[1, 2, 3], &mut enabled),
            Ok(Counts {
                deleted: 2,
                skipped: 1
            })
        );
        assert_eq!(f.seen, 12);
        assert!(enabled);
    }
    #[test]
    fn unsupported_is_cached_and_fatal_keeps_progress() {
        let mut f = Fake {
            batch: BatchResult {
                deleted: 0,
                status: BatchStatus::Unsupported,
            },
            seen: 0,
            calls: 0,
        };
        let mut enabled = true;
        assert_eq!(
            expired(&mut f, &[1, 2], &mut enabled),
            Ok(Counts {
                deleted: 1,
                skipped: 1
            })
        );
        assert!(!enabled);
        assert!(expired(&mut f, &[3], &mut enabled).is_ok());
        assert_eq!(f.calls, 1);
        f.batch = BatchResult {
            deleted: 1,
            status: BatchStatus::Failed,
        };
        assert_eq!(
            expired(&mut f, &[1, 2], &mut true),
            Err(Error::BatchFailed(Counts {
                deleted: 1,
                skipped: 0
            }))
        );
    }
    #[test]
    fn impossible_count_rejected() {
        let mut f = Fake {
            batch: BatchResult {
                deleted: 4,
                status: BatchStatus::Complete,
            },
            seen: 0,
            calls: 0,
        };
        assert_eq!(
            expired(&mut f, &[1], &mut true),
            Err(Error::InvalidProgress)
        );
    }
}
