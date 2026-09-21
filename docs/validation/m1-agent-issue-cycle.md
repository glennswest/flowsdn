# Milestone 1: standalone agent and issue-driven cycle

Validated 2026-09-21 on x86-64 Linux 6.17.1 and Rust 1.95.0; BPF objects
use nightly-2026-04-03 and bpf-linker 0.11.1. Runtime/config source baseline:
`835273f`; final dependency/test revision and workspace totals are recorded below.
This is an unreleased milestone 1 checkpoint, not Kubernetes acceptance.

## Demonstrated behavior

- The real agent process serves the real CNI executable over a Unix socket.
  ADD produces dual-stack endpoints and bidirectional UDP traffic; CHECK passes.
- Killing and restarting the agent restores persisted endpoints, IP ownership,
  CHECK and bidirectional traffic. Traffic stops during downtime because the
  initial program/map ownership is not pinned independently of the process.
- Offline CNI DEL removes the peer, persists a deletion request, and replays
  after restart without resurrecting stale state. Repeated DEL is idempotent;
  the fixture verifies queue and endpoint-state cleanup.
- An unexpected fixture-owned state file forces deletion to fail after datapath
  teardown. Endpoint health reports Failure, the file is preserved, and deletion
  succeeds after removing the obstruction.
- Five new API tests cover ambiguous/truncated/oversized HTTP requests, a stalled
  request deadline, live/non-socket/stale socket handling, failed deletion replay
  retention and retry, and gateway/family/MTU configuration checks.
- Eleven agent tests, twenty-two CNI tests, nine IPAM tests and fifty-one config
  tests passed in focused runs. The default regression verifies a one-minute
  load-balancer retry maximum; exact specification metadata/provenance matches.
- Focused Clippy, formatting, BPF compilation and agent/CNI x86-64 and arm64 musl
  compile checks passed. The architecture checks do not establish arm64 runtime.

## Failures found and corrected

The recovered agent source needed module wiring, a closure type and a mutable
queue guard. Review found skipped deletion replay after lock failure and lost
requests after teardown failure; startup now fails with valid failed entries
retained for a supervisor retry. Health no longer treats partial teardown or a
missing/mismatched host link as healthy. Full GC and externally replaced BPF
program detection remain unimplemented.

Spec edits exposed stale configuration provenance and malformed registry-table
metadata. The table and citations were corrected, including an older socket-path
citation that already pointed at the wrong line.

Dependency policy found RUSTSEC-2026-0292 in imbl-sized-chunks 0.1.3. The exact
workspace dependency moves from imbl 7.0.1 to 7.0.2, selecting imbl-sized-chunks
0.2.0. No advisory exception was added. Dependency policy passes, with nonfatal
duplicate-version and unused-license-allowance warnings.

The first full-workspace run hit the durable queue duplicate-writer test's
three-second lock budget under shared storage load. Durable tests now use a
separate sixty-second I/O budget, join all writers before asserting, and require
capacity failures to be the precise queue-full error. The production timeout and
explicit short lock-timeout regression are unchanged. The final workspace run
serializes test functions to reduce competing fsync traffic; concurrency inside
the queue tests remains exercised.

## Final workspace validation

Final source revision: `dd65674` (includes runtime baseline `835273f` and
queue-test correction `7505b8e`).

- `cargo test --workspace --all-features --locked -- --test-threads=1`:
  **428 passed, zero failed, zero ignored**, including documentation tests.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  passed. Workspace formatting check passed.
- `cargo check --workspace --all-features --target <target> --locked`:
  passed for x86-64 and arm64 Linux musl after the dependency update.
- `cargo xtask deny`: advisories, bans, licenses and sources passed.
- The privileged standalone `agent-runtime` fixture passed all assertions at
  `835273f`; the later dependency change affects the table family, not that
  fixture's agent/CNI dependency graph.
- Cleanup removed **18,889 files / 6.7 GiB** of project build output and the
  six task-specific validation logs. Both worktrees were inspected; no
  distributable build artifacts or new release were published.

This was a debug workspace run, not a repeated release-mode or full-kernel
acceptance matrix. The BPF and live checks are reported separately from ordinary
Cargo tests, which do not execute privileged fixtures.

## Issue acceptance and remaining scope

ADRs 0011–0013 record the reviewed resolution of 101 existing design/spec/default
issues, with remaining implementation explicitly preserved. Each closed issue
links to committed evidence. #129 stays open for missing rollback verification;
#261 stays open for the missing control-plane golden-test specification.
Implementation acceptance is tracked by #291–#294; dependency remediation is #295.
The cycle JSON records exact issue states and timestamps.

The full recognized API route matrix, identity/policy controllers, Kubernetes
watches, uninterrupted forwarding, stale-pod GC, native routing controller and
two-node cluster gate remain outstanding. The initial serialized API has narrower
permissions/deadlines than the full contract, and endpoint GET still lacks full
lifecycle status reporting. No new release or runtime architecture claim is made.
