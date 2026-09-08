# ADR-0008: Table watches and row rendering

Date: 2026-09-08. Status: accepted for implementation.

## Decision

Issue #42: use whole-table watch notifications, following spec 00 §3.1.5.
Per-key subscriptions are deferred until profiling establishes a need.

Issue #205: add `TableRender` to the table crate with ordered `headers()` and
`cells()` methods. Row types define their display contract explicitly; serde
field order is not a display contract. A derive macro may follow once concrete
row types reveal useful common formatting patterns.

Secondary indexes use ordered `(secondary_key, primary_key)` tuples internally.
This has the logical ordering required by spec 00 without ambiguity when a
caller supplies zero bytes inside a key. This representation is not a wire ABI.
An exact-key query returns only that key's rows, ordered by primary key.
A multi-key prefix query can return one row once for each matching index key.

`modify` rejects a replacement with a different primary key. Missing-key
conditional writes fail even when expected revision is zero. An absent-key
delete consumes a revision, while `modify(absent, |_| None)` is a no-op.
A batch returning an error publishes its successful prefix together, as required
by spec 00's no-rollback contract. Failed individual operations change nothing.

## Implementation staging

The first table release implements indexed immutable snapshots and writes.
It does not expose watch streams, retained tombstones, initialization, metrics
or reconciliation. These remain required before using it for a live reconciler.
No event-delivery or garbage-collection guarantee is implied by this core slice.

Version 0.4 adds whole-table streams and retained tombstones. A discarded-delete
watermark identifies checkpoints requiring resync; gaps between live revisions
alone do not imply loss. Acknowledgements are explicit. Maintenance runs during
writes and stream operations, with ordinary garbage collection throttled to one
second and count overflow forcing collection. Initialization, metrics and
reconciliation remain separate work.

Version 0.5 adds named initialization gates. Explicit sealing prevents an empty
registration set from reporting readiness before sources register. Owners seal
even tables with no initializers. Source completion follows initial publication;
dropping a source does not imply successful synchronization.
