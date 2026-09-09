use crate::{Keyed, ReconcileError, Reconciler, Target};
use std::{future::Future, time::Instant};
use tokio::time::{Instant as Clock, sleep_until};

impl<T: Keyed, U: Target<T>> Reconciler<'_, T, U> {
    fn loop_deadline(&self) -> Option<Instant> {
        self.next_retry()
            .into_iter()
            .chain(self.next_prune().filter(|_| self.table.initialized()))
            .chain(self.next_refresh())
            .min()
    }

    /// Drive bounded rounds until shutdown completes or a scheduling error
    /// occurs. The caller polls or spawns this future; no worker is detached.
    ///
    /// Rows may be applied during source initialization, but prune remains
    /// gated. Targets needing stricter startup ordering (such as restored BPF
    /// maps) should await `table.wait_initialized()` before invoking this loop.
    ///
    /// Shutdown takes priority over ready work and cancels an in-flight target
    /// future. Dropping this future does the same. Queued work and interrupted
    /// prune state remain in this reconciler, so a later invocation can resume;
    /// idempotent operations may be replayed after their side effects occurred.
    ///
    /// Retry/prune/refresh deadlines use Tokio's monotonic clock, allowing virtual-time
    /// testing. Completed rounds are separated by `Options::round_interval`.
    pub async fn run(&mut self, shutdown: impl Future<Output = ()>) -> Result<(), ReconcileError> {
        tokio::pin!(shutdown);
        let mut next_round = Clock::now();
        loop {
            // Capture before checking work. If initialization completes between
            // that check and select, keep the readiness future enabled.
            let initialized = self.table.initialized();
            let deadline = self.loop_deadline();
            let ready = self.has_pending_work()
                || deadline.is_some_and(|deadline| deadline <= Clock::now().into_std());
            if !ready {
                let request = self.prune.handle.clone();
                let table = self.table;
                let timer = async {
                    if let Some(deadline) = deadline {
                        sleep_until(Clock::from_std(deadline)).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::select! {
                    biased;
                    _ = &mut shutdown => return Ok(()),
                    change = self.stream.next() => {
                        let Some(change) = change else { return Ok(()); };
                        // Preserve the awaited item before yielding. Fill the
                        // rest of this bounded batch now, rather than reducing
                        // a busy stream to a single row per throttled round.
                        let remaining = self.stream.drain(self.options.round_size.saturating_sub(1));
                        self.enqueue_changes(std::iter::once(change).chain(remaining));
                    }
                    _ = request.notified() => {},
                    _ = table.wait_initialized(), if !initialized => {},
                    _ = timer => {},
                }
                continue;
            }
            tokio::select! {
                biased;
                _ = &mut shutdown => return Ok(()),
                _ = sleep_until(next_round) => {},
            }
            tokio::select! {
                biased;
                _ = &mut shutdown => return Ok(()),
                result = self.run_round_with_clock(|| Clock::now().into_std()) => { result?; },
            }
            next_round = Clock::now()
                .checked_add(self.options.round_interval)
                .ok_or(ReconcileError::RoundDeadlineOverflow)?;
        }
    }
}
