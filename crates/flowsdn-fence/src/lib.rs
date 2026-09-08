//! Named, one-shot startup barriers (spec 00 §3.4.1).
//!
//! Construct with [`Fence::add`], then [`Fence::seal`] before sharing with
//! dependents. Dropping `wait()` cancels that caller, preserving the in-flight
//! waiter for the next caller. Waiters must not wait recursively on this fence.
use std::{error::Error, fmt, future::Future, pin::Pin, time::Instant};
use tokio::sync::{Mutex, watch};

type WaiterFuture = Pin<Box<dyn Future<Output = Result<(), FenceError>> + Send>>;

/// A startup failure, including waiter context when returned by `wait`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceError(String);

impl FenceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for FenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for FenceError {}

struct Waiter {
    name: &'static str,
    future: Option<WaiterFuture>,
    result: Option<Result<(), FenceError>>,
    started: Option<Instant>,
}

/// An ordered barrier whose successful and failed results are retained.
pub struct Fence {
    name: &'static str,
    sealed: bool,
    waiters: Mutex<Vec<Waiter>>,
}

impl Fence {
    pub fn new(name: &'static str) -> Self {
        Self { name, sealed: false, waiters: Mutex::new(Vec::new()) }
    }

    /// Registers a waiter. Invalid registration panics in debug builds and
    /// returns an error in release builds, as required by spec 00.
    pub fn add(
        &mut self,
        name: &'static str,
        future: impl Future<Output = Result<(), FenceError>> + Send + 'static,
    ) -> Result<(), FenceError> {
        let error = if self.sealed {
            Some(format!("{}: fence is sealed", self.name))
        } else if self.waiters.get_mut().iter().any(|waiter| waiter.name == name) {
            Some(format!("{}: duplicate waiter {name}", self.name))
        } else {
            None
        };
        if let Some(error) = error {
            debug_assert!(false, "{error}");
            return Err(FenceError::new(error));
        }
        self.waiters.get_mut().push(Waiter {
            name, future: Some(Box::pin(future)), result: None, started: None,
        });
        Ok(())
    }

    /// Ends construction. Repeated sealing is harmless.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// Waits in registration order. Concurrent callers share the same work.
    ///
    /// Cancellation is expressed by dropping this future (for example via
    /// `tokio::select!` or `timeout`). It never marks incomplete work successful.
    pub async fn wait(&self) -> Result<(), FenceError> {
        if !self.sealed {
            return Err(FenceError::new(format!("{}: fence is not sealed", self.name)));
        }
        let mut waiters = self.waiters.lock().await;
        let total = waiters.len();
        for (position, waiter) in waiters.iter_mut().enumerate() {
            if waiter.result.is_none() {
                let started = *waiter.started.get_or_insert_with(Instant::now);
                tracing::debug!(fence = self.name, name = waiter.name,
                    remaining = total.saturating_sub(position), "Fence waiting");
                if let Some(future) = waiter.future.as_mut() {
                    let result = future.await.map_err(|error| {
                        FenceError::new(format!("{}: {error}", waiter.name))
                    });
                    waiter.result = Some(result);
                    waiter.future = None;
                    tracing::debug!(fence = self.name, name = waiter.name,
                        duration = ?started.elapsed(), "Fence done");
                }
            }
            if let Some(result) = &waiter.result {
                result.clone()?;
            }
        }
        Ok(())
    }

    /// Waits for a watch channel to become true. A closed, false channel is an
    /// error; a final true value still succeeds after the sender is dropped.
    pub async fn watch_waiter(mut receiver: watch::Receiver<bool>) -> Result<(), FenceError> {
        loop {
            if *receiver.borrow_and_update() {
                return Ok(());
            }
            receiver.changed().await.map_err(|_| FenceError::new("watch channel closed before ready"))?;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn empty_and_unsealed() {
        let mut fence = Fence::new("empty");
        assert_eq!(fence.wait().await.unwrap_err().to_string(), "empty: fence is not sealed");
        fence.seal();
        fence.wait().await.unwrap();
        fence.wait().await.unwrap();
    }

    #[tokio::test]
    async fn ordered_and_shared_by_concurrent_callers() {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let mut fence = Fence::new("startup");
        for name in ["first", "second", "third"] {
            let log = log.clone();
            fence.add(name, async move {
                tokio::task::yield_now().await;
                log.lock().unwrap().push(name);
                Ok(())
            }).unwrap();
        }
        fence.seal();
        let (a, b) = tokio::join!(fence.wait(), fence.wait());
        a.unwrap(); b.unwrap();
        fence.wait().await.unwrap();
        assert_eq!(*log.lock().unwrap(), ["first", "second", "third"]);
    }

    #[tokio::test]
    async fn failure_is_cached_and_stops_later_waiters() {
        let mut fence = Fence::new("startup");
        fence.add("identity", async { Err(FenceError::new("unavailable")) }).unwrap();
        fence.add("must-not-run", async { panic!("ran after failure") }).unwrap();
        fence.seal();
        for _ in 0..2 {
            assert_eq!(fence.wait().await.unwrap_err().to_string(), "identity: unavailable");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_preserves_in_flight_work() {
        let (tx, rx) = watch::channel(false);
        let (started_tx, mut started_rx) = watch::channel(false);
        let mut fence = Fence::new("startup");
        fence.add("source", async move {
            // Restarting this future would attempt to send to a closed channel.
            started_tx.send(true).unwrap();
            Fence::watch_waiter(rx).await
        }).unwrap();
        fence.seal();
        assert!(timeout(Duration::from_secs(1), fence.wait()).await.is_err());
        assert!(*started_rx.borrow_and_update());
        drop(started_rx);
        tx.send(true).unwrap();
        fence.wait().await.unwrap();
    }

    #[tokio::test]
    async fn watch_close_and_final_value() {
        let (tx, rx) = watch::channel(false);
        drop(tx);
        assert!(Fence::watch_waiter(rx).await.is_err());
        let (tx, rx) = watch::channel(false);
        tx.send(true).unwrap();
        drop(tx);
        Fence::watch_waiter(rx).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn composite_waits_for_every_child() {
        let (tx, rx) = watch::channel(false);
        let mut child = Fence::new("identity");
        child.add("k8s", Fence::watch_waiter(rx)).unwrap();
        child.seal();
        let mut parent = Fence::new("regeneration");
        parent.add("identity", async move { child.wait().await }).unwrap();
        parent.seal();
        assert!(timeout(Duration::from_secs(1), parent.wait()).await.is_err());
        tx.send(true).unwrap();
        parent.wait().await.unwrap();
    }

    #[test]
    fn invalid_registration() {
        for sealed in [false, true] {
            let result = std::panic::catch_unwind(move || {
                let mut fence = Fence::new("startup");
                fence.add("source", async { Ok(()) }).unwrap();
                if sealed { fence.seal(); }
                fence.add("source", async { Ok(()) })
            });
            if cfg!(debug_assertions) {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
        }
    }
}
