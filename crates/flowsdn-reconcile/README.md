# flowsdn-reconcile

A caller-driven reconciliation core for immutable desired tables. Each round
processes a bounded set of changes, applies deletes before updates in that set,
and retries failed operations with capped exponential backoff. Targets must be
idempotent because cancellation can replay an operation after its side effect.

Each reconciler owns separate in-memory status and retry indexes. Desired rows
are never rewritten merely to record status. Present-row status is matched to
the desired snapshot revision; a newer desired row reports Pending until its
operation is attempted. Results from obsolete in-flight updates are discarded.

Absent-row delete errors are diagnostics about the last observed deletion.
Table snapshots do not expose deletion generations, so a newer absent delete or
reinsert-delete sequence can temporarily leave an older error visible. The next
round observes the new stream generation and replaces or clears it. An absent
row's status is therefore not evidence that its latest deletion has succeeded.
Successful deletion releases its status entry.

The caller supplies the scheduling instant for a round and owns initialization
gating and subsequent scheduling. `next_retry()` and `retry_low_water_mark()`
expose the next timer deadline and oldest failed revision. A cancelled round
retains queued work; `has_pending_work()` indicates it can resume immediately.

This slice does not run an autonomous task or timer and does not install atomic
status hooks into table publication. Prune, refresh, annotations, batch targets,
health reporting and asynchronous completion waiters remain unimplemented.
`resync_required()` requests a full external reconciliation after deletion
history loss; incremental application alone cannot remove unknown target rows.
