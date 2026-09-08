# ADR-0009: Reconciliation status remains separate from desired rows

Date: 2026-09-08. Status: accepted.

Resolve #43 by retaining spec 00's companion status storage keyed by primary
key and desired revision. Status updates do not rewrite desired rows or notify
other desired-state watchers. Multiple reconcilers maintain independent status.
API handlers join desired and realized state when presenting objects.

The first caller-driven reconciler slice compares desired revisions before
accepting operation results, and exposes Pending when a stored result belongs
to an older revision. Atomic publication hooks for status creation remain
upcoming; this slice must not claim that a stored Pending row appears in the
same transaction as a desired write. Autonomous scheduling, target annotations,
refresh, prune and health integration remain separate work.
