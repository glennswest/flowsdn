//! Bounded admission primitive for a future Kubernetes PacketDrop recorder.
//! Call only for eligible pod drops after reason/direction and pod-UID lookup.
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
    sync::Arc,
};
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key {
    pub pod_uid: String,
    pub reason: String,
    pub message: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Duplicate,
    RateLimited,
    Capacity,
    ClockReversed,
    InvalidKey,
    SequenceExhausted,
}
#[derive(Debug)]
pub struct Ticket {
    issuer: Arc<()>,
    key: Key,
    sequence: u64,
}
#[derive(Clone, Copy, Debug)]
struct Entry {
    at: Duration,
    sequence: u64,
}
pub struct Gate {
    issuer: Arc<()>,
    interval: Duration,
    maximum: usize,
    per_second: usize,
    entries: BTreeMap<Key, Entry>,
    attempts: VecDeque<Duration>,
    last_time: Duration,
    sequence: u64,
}
impl Gate {
    /// per_second=0 disables only the global limiter, never the dedupe bound.
    pub fn new(
        interval: Duration,
        maximum: usize,
        per_second: usize,
    ) -> Result<Self, &'static str> {
        if interval.is_zero() || maximum == 0 {
            return Err("drop interval and dedupe capacity must be positive");
        }
        Ok(Self {
            issuer: Arc::new(()),
            interval,
            maximum,
            per_second,
            entries: BTreeMap::new(),
            attempts: VecDeque::new(),
            last_time: Duration::ZERO,
            sequence: 0,
        })
    }
    pub fn retained_keys(&self) -> usize {
        self.entries.len()
    }
    /// Uses caller-supplied monotonic elapsed time. The rate window is one
    /// second, half-open at its lower bound. Full dedupe tables refuse new
    /// keys rather than evicting live entries and permitting duplicate floods.
    pub fn admit(&mut self, now: Duration, key: Key) -> Result<Ticket, Rejected> {
        if now < self.last_time {
            return Err(Rejected::ClockReversed);
        }
        if key.pod_uid.is_empty() || key.reason.is_empty() || key.message.is_empty() {
            return Err(Rejected::InvalidKey);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Rejected::SequenceExhausted)?;
        self.last_time = now;
        self.entries
            .retain(|_, entry| now.saturating_sub(entry.at) < self.interval);
        while self
            .attempts
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= Duration::from_secs(1))
        {
            self.attempts.pop_front();
        }
        if self.entries.contains_key(&key) {
            return Err(Rejected::Duplicate);
        }
        if self.entries.len() >= self.maximum {
            return Err(Rejected::Capacity);
        }
        if self.per_second != 0 && self.attempts.len() >= self.per_second {
            return Err(Rejected::RateLimited);
        }
        self.sequence = sequence;
        self.entries
            .insert(key.clone(), Entry { at: now, sequence });
        if self.per_second != 0 {
            self.attempts.push_back(now);
        }
        Ok(Ticket { issuer: Arc::clone(&self.issuer), key, sequence })
    }
    /// Failed writes may retry without waiting for dedupe expiry, but do not
    /// refund the global attempt budget. Stale completion cannot erase a later
    /// reservation for the same key or a replacement Gate. Success retains the
    /// dedupe record; tickets hold their issuer identity alive to avoid reuse.
    pub fn finish(&mut self, ticket: Ticket, success: bool) {
        if Arc::ptr_eq(&self.issuer, &ticket.issuer)
            && !success
            && self
                .entries
                .get(&ticket.key)
                .is_some_and(|entry| entry.sequence == ticket.sequence)
        {
            self.entries.remove(&ticket.key);
        }
    }
}
