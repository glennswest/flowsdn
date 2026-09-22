//! Bounded single-owner model of the observer ring. The newest slot stays
//! unreadable until the next write. Async fan-out and wakeups are not provided.
use std::{fmt, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCapacity;
impl fmt::Display for InvalidCapacity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ring capacity must be 2^n - 1 in 1..=65535")
    }
}
impl std::error::Error for InvalidCapacity {}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Read<T> {
    Event(Arc<T>),
    Lost { count: u64 },
    End,
}

/// A new instance is always empty. Cursors belong to this instance and must
/// not be reused after restart. Mutation requires exclusive ownership; this
/// type is not the concurrent production observer implementation.
pub struct MemoryRing<T> {
    slots: Box<[Option<Arc<T>>]>,
    mask: u64,
    next: u64,
    filled: usize,
}
impl<T> MemoryRing<T> {
    pub fn new(capacity: u32) -> Result<Self, InvalidCapacity> {
        if capacity == 0 || capacity > 65535 || capacity & capacity.saturating_add(1) != 0 {
            return Err(InvalidCapacity);
        }
        let size = usize::try_from(capacity.saturating_add(1)).map_err(|_| InvalidCapacity)?;
        let slots = std::iter::repeat_with(|| None)
            .take(size)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            slots,
            mask: u64::from(capacity),
            next: 0,
            filled: 0,
        })
    }
    pub fn capacity(&self) -> usize {
        self.slots.len().saturating_sub(1)
    }
    /// At most capacity events are reported, including the reserved newest slot.
    pub fn len(&self) -> usize {
        self.filled.min(self.capacity())
    }
    pub fn is_empty(&self) -> bool {
        self.filled == 0
    }
    pub fn push(&mut self, event: T) -> u64 {
        let sequence = self.next;
        let slot = usize::try_from(sequence & self.mask).expect("validated slot fits usize");
        *self.slots.get_mut(slot).expect("mask bounds slot") = Some(Arc::new(event));
        self.next = self.next.wrapping_add(1);
        self.filled = self.filled.saturating_add(1).min(self.slots.len());
        sequence
    }
    pub fn oldest(&self) -> u64 {
        self.next
            .wrapping_sub(u64::try_from(self.filled).expect("bounded fill"))
    }
    pub fn next_sequence(&self) -> u64 {
        self.next
    }
    /// Modular sequence ordering assumes cursors are less than 2^63 writes
    /// apart. A lapped cursor emits exactly one loss per position, not the gap.
    pub fn read(&self, sequence: u64) -> Read<T> {
        if self.is_empty() {
            return Read::End;
        }
        let latest = self.next.wrapping_sub(1);
        let distance = latest.wrapping_sub(sequence);
        if distance == 0 || distance >= (1u64 << 63) {
            return Read::End;
        }
        if distance > self.mask {
            return Read::Lost { count: 1 };
        }
        let slot = usize::try_from(sequence & self.mask).expect("validated slot fits usize");
        match self.slots.get(slot).and_then(Option::as_ref) {
            Some(value) => Read::Event(Arc::clone(value)),
            None => Read::Lost { count: 1 },
        }
    }
    /// Retry the same cursor at EOF; advance on either an event or in-band loss.
    pub fn read_next(&self, cursor: &mut u64) -> Read<T> {
        let value = self.read(*cursor);
        if !matches!(value, Read::End) {
            *cursor = cursor.wrapping_add(1);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sequence_wrap_retains_order_and_detects_overwrite() {
        let mut ring = MemoryRing::new(3).expect("capacity");
        ring.next = u64::MAX.wrapping_sub(1);
        let first = ring.push(10);
        let second = ring.push(20);
        let third = ring.push(30);
        assert_eq!(third, 0);
        assert_eq!(ring.read(first), Read::Event(Arc::new(10)));
        assert_eq!(ring.read(second), Read::Event(Arc::new(20)));
        assert_eq!(ring.read(third), Read::End);
        assert_eq!(ring.read(1), Read::End);
        ring.push(40);
        ring.push(50);
        assert_eq!(ring.read(first), Read::Lost { count: 1 });
        assert_eq!(ring.read(second), Read::Event(Arc::new(20)));
    }
}
