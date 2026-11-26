//! The client's rate limiter and inflight cap (spec 20 §3.2.4): a token
//! bucket of `qps` (burst `qps`), a bootstrap rate until the owner signals
//! its initial sync finished, and a semaphore of `max_inflight`. A request
//! that cannot get a token or a slot waits; it never fails.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// The semaphore's ceiling (well under tokio's `MAX_PERMITS`).
const MAX_INFLIGHT: usize = 1_048_576;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// One limiter per client instance (§3.2.4).
pub(crate) struct Limiter {
    bucket: Mutex<Bucket>,
    inflight: Arc<Semaphore>,
    qps: f64,
    bootstrap_qps: f64,
    bootstrapping: AtomicBool,
}

impl Limiter {
    /// `qps` 0: no rate limit. `max_inflight` 0: `qps` (0 too: unbounded).
    pub(crate) fn new(qps: u32, bootstrap_qps: u32, max_inflight: u32) -> Self {
        let inflight = if max_inflight == 0 { qps } else { max_inflight };
        let permits = if inflight == 0 {
            MAX_INFLIGHT
        } else {
            usize::try_from(inflight)
                .unwrap_or(MAX_INFLIGHT)
                .min(MAX_INFLIGHT)
        };
        Self {
            bucket: Mutex::new(Bucket {
                tokens: f64::from(qps.max(1)),
                last: Instant::now(),
            }),
            inflight: Arc::new(Semaphore::new(permits)),
            qps: f64::from(qps),
            bootstrap_qps: f64::from(bootstrap_qps),
            bootstrapping: AtomicBool::new(bootstrap_qps > 0),
        }
    }

    /// Leave the bootstrap rate for the steady one (once).
    pub(crate) fn bootstrap_done(&self) {
        self.bootstrapping.store(false, Ordering::SeqCst);
    }

    fn rate(&self) -> f64 {
        if self.bootstrapping.load(Ordering::SeqCst) && self.bootstrap_qps > 0.0 {
            self.bootstrap_qps
        } else {
            self.qps
        }
    }

    /// A token, then an inflight slot held by the returned permit.
    pub(crate) async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.token().await;
        Arc::clone(&self.inflight).acquire_owned().await.ok()
    }

    /// Wait for one token.
    pub(crate) async fn token(&self) {
        while let Some(wait) = self.take() {
            tokio::time::sleep(wait).await;
        }
    }

    /// Take a token (`None`) or say how long until one is due.
    // Floating-point bucket arithmetic: finite, positive operands.
    #[allow(clippy::arithmetic_side_effects)]
    fn take(&self) -> Option<Duration> {
        let rate = self.rate();
        if rate <= 0.0 {
            return None;
        }
        let burst = self.qps.max(1.0);
        let mut bucket = self.bucket.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return None;
        }
        let wait = ((1.0 - bucket.tokens) / rate).max(0.000_001);
        Some(Duration::try_from_secs_f64(wait).unwrap_or(Duration::from_millis(1)))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn bucket_bursts_then_waits() {
        let limiter = Limiter::new(2, 0, 0);
        let start = Instant::now();
        limiter.token().await;
        limiter.token().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        limiter.token().await;
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(499), "{waited:?}");
        assert!(waited <= Duration::from_millis(510), "{waited:?}");
        limiter.token().await;
        assert!(start.elapsed() >= Duration::from_millis(999));
    }

    #[tokio::test(start_paused = true)]
    async fn bootstrap_rate_until_done() {
        let limiter = Limiter::new(1, 100, 0);
        let start = Instant::now();
        for _ in 0..11 {
            limiter.token().await;
        }
        // One burst token, then ten at 100/s.
        assert!(start.elapsed() <= Duration::from_millis(110), "{:?}", start.elapsed());
        limiter.bootstrap_done();
        let start = Instant::now();
        limiter.token().await;
        assert!(start.elapsed() >= Duration::from_millis(900), "{:?}", start.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn inflight_cap_waits() {
        let limiter = Limiter::new(100, 0, 1);
        let held = limiter.acquire().await;
        assert!(held.is_some());
        let blocked =
            tokio::time::timeout(Duration::from_millis(50), limiter.acquire()).await;
        assert!(blocked.is_err());
        drop(held);
        let next = tokio::time::timeout(Duration::from_millis(50), limiter.acquire()).await;
        assert!(next.unwrap().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn zero_qps_is_unlimited() {
        let limiter = Limiter::new(0, 0, 0);
        let start = Instant::now();
        for _ in 0..1000 {
            limiter.token().await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
