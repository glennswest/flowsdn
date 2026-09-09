# flowsdn-reconcile

Reconciliation rounds and a caller-owned async loop for immutable desired tables. Each round
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

`run(shutdown_future)` drives work until shutdown completes or a scheduling or batch-protocol error
occurs. It waits for table changes, initialization readiness, retry/prune/refresh timers,
and explicit prune requests. The caller owns this future and may poll or spawn
it; no worker is detached. Shutdown takes priority and cancels an in-flight
operation. Dropping the future also cancels it, retaining queued work so the
same reconciler can resume later.

The loop waits at least `round_interval` between completed rounds (1 ms by
default, at most 1000 rounds/s). Idle loops wait on notifications or timers;
retries are timed from operation completion, including slow target calls. Tokio's
monotonic clock supports paused-time tests.

Callers can instead use `run_round(now)` to supply a fixed scheduling instant and
drive rounds themselves. `next_retry()` and `retry_low_water_mark()` expose the
next retry deadline and oldest failed revision. `has_pending_work()` indicates
immediate queued work, including cancellation recovery and the initial prune.

After incremental work, a round prunes only if the table is initialized. The
first prune follows initialization, then repeats at `prune_interval` (one hour
by default; it must be positive). `prune_now()` requests an extra pass, and a
cloneable `prune_handle()` allows other callers to request it while a round runs.
Requests coalesce; a request arriving during prune schedules one further pass.
Requests made before initialization remain pending. The handle wakes an active
`run` future. Callers using manual rounds still schedule their own wakeups.

`Target::prune` receives an immutable snapshot of all desired rows and removes
target objects absent from it. Its scan is separate from the incremental round
size limit. Concurrent desired changes arrive through subsequent stream rounds.
`prune_status()` reports the last completed attempt's snapshot revision and
error; `next_prune()` gives the periodic deadline. Failure does not enter the
per-key retry queue and waits for that deadline or another explicit request.
Cancellation replays the interrupted prune immediately, so targets must remain
idempotent even when an operation already changed the target before cancellation.

A resync caused by discarded deletion history requests prune automatically.
`resync_required()` remains true until prune succeeds; there is no manual bypass.
Clearing it confirms deletion-history recovery, not successful application of
all rows: individual update failures may still be queued for retry.

This slice does not install atomic status hooks into table publication.
Annotations,
health reporting and asynchronous completion waiters remain unimplemented.
Prune owns its initialization gate; callers still own any extra startup gate
needed before incremental target writes, such as restoration of allocated IDs.

Periodic refresh defaults to 30 minutes and 100 newly scheduled rows per second.
Set `refresh_interval` to zero to disable it. Each pass visits an immutable
snapshot in revision order, scanning bounded chunks and selecting Done statuses
at least one interval old. Recent successes contribute their next eligibility
deadline; failed rows retain their existing backoff. Rate limits do not accumulate
burst credit while idle. `next_refresh()` exposes the next scan or dispatch timer
for callers driving manual rounds.

Refresh sets the side-table status to Refreshing and calls
`Target::update_with_hint` with `UpdateHint::Refresh`, requesting a forced rewrite.
The default method repeats `update`, preserving existing target implementations;
targets that skip unchanged values should override it to honor the hint. Retries
and cancellation replay retain the hint. Generation checks discard stale results,
and refresh never changes desired-table revisions.

Targets can opt into coalescing with `supports_batches()`. Each round gathers at
most `round_size` changes, due retries and eligible refresh work, then calls
`delete_batch` before `update_batch`, at most once each for nonempty groups.
`BatchUpdate` includes the desired row, key, revision and refresh hint;
`BatchDelete` includes the key and revision. Both methods have scalar defaults,
so a target can specialize either operation. Existing targets keep scalar
behavior unless they explicitly opt in.

Each `BatchResult` identifies its input by key and revision and contains a
per-entry success or diagnostic string. Results may arrive in any order, but
must contain every requested identity exactly once. Missing, extra, duplicate
or mismatched identities return `InvalidBatchResults` without acknowledging any
entry in that group. The caller can fix the target and resume the retained work.
A valid response records independent retries and discards stale generations.
Cancellation replays the unfinished group, including any already applied target
side effects; successfully recorded earlier groups remain complete.
