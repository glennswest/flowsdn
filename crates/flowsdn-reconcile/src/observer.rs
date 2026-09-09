use crate::{Keyed, Reconciler, Target};
use flowsdn_table::Revision;
use std::{error::Error, fmt};
use tokio::sync::watch;

/// Whether the caller-owned loop is currently being driven.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DriverState {
    /// New reconcilers and callers driving individual rounds may wait here.
    #[default]
    Manual,
    Running,
    /// The loop returned or its future was dropped. The owner may restart it.
    Stopped,
}

/// A coherent checkpoint of attempted work and remaining failures.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileProgress {
    pub attempted_revision: Revision,
    /// Includes failed entries currently being replayed outside the retry index.
    pub retry_low_water_mark: Option<Revision>,
    /// Lost deletion history still requires successful prune recovery.
    pub resync_required: bool,
    pub driver: DriverState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitError {
    Stopped,
    Closed,
}
impl fmt::Display for WaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stopped => "reconciler loop stopped before reaching the requested revision",
            Self::Closed => "reconciler owner was dropped before reaching the requested revision",
        })
    }
}
impl Error for WaitError {}

/// Cloneable observer that does not borrow the mutable reconciler or keep it alive.
#[derive(Clone)]
pub struct ReconcileObserver {
    receiver: watch::Receiver<ReconcileProgress>,
}
impl ReconcileObserver {
    pub fn progress(&self) -> ReconcileProgress {
        *self.receiver.borrow()
    }

    /// Observe a later checkpoint, including retry resolution and loop shutdown.
    /// Watch notifications coalesce; this is a state observer, not an event log.
    pub async fn changed(&mut self) -> Result<ReconcileProgress, WaitError> {
        self.receiver
            .changed()
            .await
            .map_err(|_| WaitError::Closed)?;
        Ok(*self.receiver.borrow_and_update())
    }

    /// Wait for stream catch-up and a first attempt of all non-superseded work
    /// through `revision`. Failures do not block this barrier: inspect the retry
    /// low-water mark separately. This does not wait for prune or future refreshes.
    /// Cancelling this future has no effect on reconciliation or other observers.
    pub async fn wait_until_reconciled(
        &self,
        revision: Revision,
    ) -> Result<ReconcileProgress, WaitError> {
        let mut receiver = self.receiver.clone();
        loop {
            let closed = receiver.has_changed().is_err();
            let progress = *receiver.borrow_and_update();
            if progress.attempted_revision >= revision {
                return Ok(progress);
            }
            if closed {
                return Err(WaitError::Closed);
            }
            if progress.driver == DriverState::Stopped {
                return Err(WaitError::Stopped);
            }
            if receiver.changed().await.is_err() {
                // Closing may race with the final publication. Read the retained
                // checkpoint once more before reporting an unreachable barrier.
                let progress = *receiver.borrow_and_update();
                return if progress.attempted_revision >= revision {
                    Ok(progress)
                } else {
                    Err(WaitError::Closed)
                };
            }
        }
    }
}

pub(crate) struct DriverGuard(watch::Sender<ReconcileProgress>);
impl DriverGuard {
    pub(crate) fn new(sender: &watch::Sender<ReconcileProgress>) -> Self {
        sender.send_modify(|progress| progress.driver = DriverState::Running);
        Self(sender.clone())
    }
}
impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0
            .send_modify(|progress| progress.driver = DriverState::Stopped);
    }
}

impl<T: Keyed, U: Target<T>> Reconciler<'_, T, U> {
    pub fn observer(&self) -> ReconcileObserver {
        ReconcileObserver {
            receiver: self.progress.subscribe(),
        }
    }

    pub(crate) fn publish_progress(&mut self) {
        // Deletes can run ahead of older updates. A checkpoint must stop before
        // any queued first attempt, regardless of dispatch order. Failed retries
        // already satisfy the attempted barrier even while their future is pending.
        let checkpoint = self
            .pending_first_attempts
            .first_key_value()
            .map(|(revision, _)| revision.saturating_sub(1))
            .map_or(self.stream.revision(), |limit| {
                limit.min(self.stream.revision())
            });
        self.attempted_revision = self.attempted_revision.max(checkpoint);
        let low = self.retry_low_water_mark();
        self.progress.send_if_modified(|progress| {
            let next = ReconcileProgress {
                attempted_revision: self.attempted_revision,
                retry_low_water_mark: low,
                resync_required: self.resync_required,
                driver: progress.driver,
            };
            if *progress == next {
                false
            } else {
                *progress = next;
                true
            }
        });
    }
}
