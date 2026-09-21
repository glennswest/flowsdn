# Control-plane golden tests — specification

Status: accepted contract, harness implementation pending. Resolves #261.
Governed by ADR-0005 and docs/licensing.md. Inputs are the attributed data in
`tests/golden/controlplane/`; this specification does not copy reference test
code. This is a controller-state harness, separate from script execution
(spec 17), kernel packet tests (spec 18), and connectivity (spec 19).

## 1. Scope and compatibility

`flowsdn-cptest` drives Rust controller adapters with Kubernetes object events
and compares their resulting desired and realized state with reviewed goldens.
The initial corpus is the 18 harvested YAML object sets and its version list.
The harness MUST inventory the corpus before claiming coverage; unavailable
adapters are reported as unsupported, never as passing fixtures.

Kubernetes apiVersion/kind, names, namespace, UID, generation and resourceVersion
are preserved. Map and API snapshots use the owning specification's field names
and widths. Numeric identity, revision and timestamp normalization is permitted
only through explicit per-snapshot normalization rules below.

## 2. Case manifest and state machine

A static JSON manifest has `schemaVersion: 1`, `name`, `adapter`, `kubernetesVersion`,
`seed` (u64), `timeoutMillis` (positive u64), `steps` (nonempty array), and optional
`expectedDivergence` with issue and ADR references. Unknown manifest fields fail
validation. All referenced paths MUST be relative to the case directory; absolute
paths, traversal and symlink escape are rejected.

Each step is exactly one of:

| Operation | Fields | Effect |
| --- | --- | --- |
| apply | objectFile | Parse one YAML document or List; publish ordered add/update events. |
| delete | apiVersion, kind, namespace, name, uid | Delete only the matching generation identity; NotFound is idempotent. |
| fence | name | Wait for the adapter's acknowledged event watermark and reconciliation fence. |
| expect | snapshot, goldenFile, normalize | Compare only after the preceding fence is complete. |
| restart | mode | Recreate controllers; mode is `preserve` or `fresh`, explicitly controlling persistent state. |
| failNext | operation, count | Inject a bounded adapter failure; unsupported fault points fail the case. |

Cases progress validated → initialized → executing → cleanup → passed/failed.
Any error enters cleanup. The adapter MUST finish or cancel all spawned work
before the next case starts. A shared deadline bounds initialization, execution,
fences and cleanup; a timeout is a failure with the last acknowledged watermark.
An external watchdog may enforce a hard process deadline for broken cleanup.

## 3. Event and reconciliation behavior

The fake API store keys objects by group/resource/namespace/name and tracks UID
separately. Create of an existing object, stale resourceVersion update, and
UID-precondition delete mismatch MUST behave as explicit conflicts. The adapter
MUST observe the same event sequence a real watch would deliver. No controller
may read fixture files or goldens directly. The harness MUST distinguish desired
state from realized state so a failed map/API write cannot pass a desired-state
comparison while runtime state is stale.

A fence means all submitted events through its watermark have completed their
required reconciliation or produced a terminal reported failure. It does not
mean an arbitrary sleep elapsed. Timers use an injected clock; retry assertions
advance that clock and require bounded attempts. Random ordering is seeded and
recorded, including the seed on failure.

## 4. Snapshots and comparison

Adapters expose named snapshots: Kubernetes output objects, endpoint/identity
state, ipcache, services/backends, policy-map desired state, and realized state
where available. Each snapshot includes a schema version and revision. Tables
sort by their owning composite key; JSON object key order is ignored, array
order is preserved unless the snapshot schema explicitly defines a set.

Normalization is a whitelist of JSON pointers. The manifest names a supported
rule (`timestamp`, `allocated-identity`, `revision`) for each pointer. A missing
pointer or unknown rule fails. Allocated identities are replaced consistently
across all snapshots of a case using one bijection; reserved identities, addresses,
ports, verdicts and object references MUST NOT be normalized. This prevents
normalization from hiding policy or ownership errors.

Comparison reports the first differing pointer plus bounded expected/actual
context. Golden files are read-only during ordinary test runs. An explicit
`--update` invocation writes proposed snapshots only after successful execution;
review and commit are required before those proposals become accepted goldens.
Expected divergences report XFAIL only when the named assertion fails; unexpected
success is XPASS and fails until the divergence is reviewed and removed.

## 5. Rust design and configuration

One Rust crate owns manifest validation, deterministic clock/store, comparison,
and reporting. Controllers provide adapters through a trait with initialize,
apply/delete, fence, snapshot, restart, fault-injection and shutdown operations.
The first adapter targets node-object reconciliation in the harvested corpus;
service and policy adapters follow their owning milestones. No Go runner or
reference controller is executed. Unit tests use an independent small test
adapter rather than mocking a successful snapshot into every expectation.

CLI configuration: `--case`, `--adapter`, `--seed`, `--timeout`, `--update`,
`--output-dir`; explicit CLI timeout/seed overrides are recorded in results.
Default timeout is 30 seconds per case and default seed is 0. No network or
privileged kernel access is required for the fake-adapter lane. Real-controller
integration declares its dependencies separately and never silently falls back
to a fake when a dependency is missing.

## 6. Failure reporting and acceptance

Each result records case, adapter, source provenance, seed, duration, outcome,
last event watermark, snapshot schema versions and a bounded diff. Secrets in
objects and diagnostics are redacted at known secret fields; raw API credentials
are never accepted as fixture configuration. Cleanup failures are failures even
when comparison passed. Parallel cases require isolated stores, clocks, output
directories and adapter instances.

Required unit cases: malformed/unknown manifest fields; path escapes; UID and
version conflicts; list expansion; deterministic event order; timer cancellation;
fence does not acknowledge incomplete realization; restart preserve/fresh;
normalization bijection and forbidden fields; mismatching array order; timeout;
XFAIL/XPASS; failed cleanup; update mode never writes on failed execution.

Controller acceptance: enumerate all 18 YAML inputs with provenance, run each
supported node case against the real Rust node controller, compare reviewed
state snapshots, and publish unsupported coverage explicitly. Add/delete/update,
retry, restart and concurrent-event permutations must be represented. This spec
closes the missing-contract issue; harness implementation and controller adapters
remain acceptance work in #294 and the relevant feature milestones.

## 7. Open decisions

None for the harness contract. Adapter-specific snapshot schemas belong to the
owning controller specification and require review before its first golden is
accepted. Recovery of older upstream cases remains separate issue #36.
