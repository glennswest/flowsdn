use crate::{Kind, ReconcileError, Reconciler, Round, Status, Target, UpdateHint, Work};
use flowsdn_table::{Key, Keyed, Revision};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

/// One desired update in a bounded target batch.
#[derive(Clone, Debug)]
pub struct BatchUpdate<T> {
    pub key: Key,
    pub revision: Revision,
    pub row: Arc<T>,
    pub hint: UpdateHint,
}

/// One desired deletion in a bounded target batch.
#[derive(Clone, Debug)]
pub struct BatchDelete {
    pub key: Key,
    pub revision: Revision,
}

/// Result identity must exactly match a requested key and revision.
/// Error text becomes the row's diagnostic and schedules its normal retry.
#[derive(Clone, Debug)]
pub struct BatchResult {
    pub key: Key,
    pub revision: Revision,
    pub result: Result<(), String>,
}

impl<T: Keyed, U: Target<T>> Reconciler<'_, T, U> {
    pub(crate) async fn run_batch_round(
        &mut self,
        clock: &impl Fn() -> Instant,
        round: &mut Round,
    ) -> Result<(), ReconcileError> {
        // Transfer retries into the durable pending queue before any await.
        // Cancellation then replays every input whose result was not recorded.
        while self.pending.len().saturating_add(round.processed) < self.options.round_size {
            if let Some(retry) = self.retries.due(clock()) {
                let row = if retry.operation == crate::Operation::Update {
                    self.table
                        .snapshot()
                        .get("primary", &retry.key)
                        .expect("primary index exists")
                        .map(|(row, _)| row)
                } else {
                    None
                };
                if retry.operation == crate::Operation::Update && row.is_none() {
                    self.statuses.remove(&retry.key);
                    round.stale = round.stale.saturating_add(1);
                    round.processed = round.processed.saturating_add(1);
                    continue;
                }
                self.pending.push_back(Work {
                    key: retry.key,
                    revision: retry.revision,
                    row,
                    failures: retry.failures,
                    refresh: retry.refresh,
                });
            } else if self.pending.iter().any(|work| work.refresh) {
                // A dispatched refresh keeps its pass alive until its result is
                // recorded, including cancellation replay after the rate gap.
                break;
            } else if let Some(work) = self.next_refresh_work(clock())? {
                self.pending.push_back(work);
            } else {
                break;
            }
        }
        self.pending
            .make_contiguous()
            .sort_by_key(|work| (work.row.is_some(), work.revision));
        // Exactly one nonempty delete group and one nonempty update group.
        for deleting in [true, false] {
            let capacity = self.options.round_size.saturating_sub(round.processed);
            let group: Vec<_> = self
                .pending
                .iter()
                .take(capacity)
                .take_while(|work| work.row.is_none() == deleting)
                .cloned()
                .collect();
            let active: Vec<_> = group
                .iter()
                .filter(|work| self.current(work))
                .cloned()
                .collect();
            for work in &active {
                let mut status = Status::pending(work.revision, work.operation());
                status.retries = work.failures;
                if work.refresh {
                    status.kind = Kind::Refreshing;
                }
                self.statuses.insert(work.key.clone(), status);
            }
            let results = if active.is_empty() {
                Vec::new()
            } else if deleting {
                self.target
                    .delete_batch(
                        active
                            .iter()
                            .map(|work| BatchDelete {
                                key: work.key.clone(),
                                revision: work.revision,
                            })
                            .collect(),
                    )
                    .await
            } else {
                self.target
                    .update_batch(
                        active
                            .iter()
                            .map(|work| BatchUpdate {
                                key: work.key.clone(),
                                revision: work.revision,
                                row: work.row.clone().expect("update group has rows"),
                                hint: if work.refresh {
                                    UpdateHint::Refresh
                                } else {
                                    UpdateHint::Changed
                                },
                            })
                            .collect(),
                    )
                    .await
            };
            // Validate the complete response before committing any result. Missing,
            // extra, duplicated or foreign identities retain the whole group.
            if results.len() != active.len() {
                return Err(ReconcileError::InvalidBatchResults);
            }
            let mut indexed = BTreeMap::new();
            for result in results {
                if indexed
                    .insert((result.key, result.revision), result.result)
                    .is_some()
                {
                    return Err(ReconcileError::InvalidBatchResults);
                }
            }
            if active
                .iter()
                .any(|work| !indexed.contains_key(&(work.key.clone(), work.revision)))
            {
                return Err(ReconcileError::InvalidBatchResults);
            }
            for work in group {
                let result = indexed.remove(&(work.key.clone(), work.revision));
                match result {
                    Some(result) if self.current(&work) => {
                        self.record_result(&work, result, clock(), round)?
                    }
                    _ => {
                        self.statuses.remove(&work.key);
                        round.stale = round.stale.saturating_add(1);
                    }
                }
                self.pending.pop_front();
                round.processed = round.processed.saturating_add(1);
                if work.refresh {
                    self.complete_refresh_work(clock())?;
                }
            }
        }
        Ok(())
    }
}
