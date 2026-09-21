# Milestone 1: configuration and CNI ownership batch

This unreleased checkpoint groups issues #48, #115, #120, #121, #127, #130
and #131. ADR-0014 records the contracts and remaining implementation scope.
The all-feature workspace run passed **447 tests**, zero failed or ignored,
including documentation tests. Workspace Clippy passes with warnings denied.
New test assertions were corrected to satisfy the indexing lint, then their
configuration and CNI suites were rerun successfully. Final source revision: `34fc3a1` (implementation `335ede3`, formatting and test
lint corrections only afterward). Validation ran on x86-64 Linux 6.17.1 with
Rust 1.95.0; BPF used nightly-2026-04-03 and bpf-linker 0.11.1.

- `cargo test --workspace --all-features --locked -- --test-threads=1`: 447 passed.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  passed; formatting and whitespace checks passed.
- The corrected configuration strict/catalogue and CNI library tests passed again.
- Workspace all-feature checks passed for x86-64 and arm64 Linux musl.
- The BPF build and both privileged `agent-runtime` and `cni-runtime` fixtures
  passed, including their existing teardown, retry and dual-stack traffic gates.

No dependency versions changed in this batch. The preceding cycle's dependency
policy result is unchanged; dependency policy was not rerun here.

## Changes exercised

- Strict configuration defaults to warnings and optionally rejects unknown keys
  after resolving source precedence. Lower-layer typos remain errors in strict
  mode; diagnostic values are not exposed. The original reference catalogue is
  preserved separately from two flowsdn extensions.
- Endpoint allocation defaults to 1–4095 and supports an inclusive ceiling up to
  65535. Restored historical IDs above a lowered ceiling remain reserved. The
  live agent fixture uses a ceiling of two, rejects a third attachment, and
  verifies released-ID reuse without harming the surviving endpoint.
- Duplicate CNI ADD checks health, host identity, namespace cookie, peer MAC and
  assigned addresses, then returns the existing attachment result. A populated
  foreign namespace is rejected while both original endpoints retain traffic.
- Creation-time gateways and route MTU survive restart. The live fixture changes
  configured MTU between process runs and requires identical duplicate results.
  Endpoint PUT also supplies the installed MTU; a stale setting is rejected
  before endpoint creation, with ordinary CNI rollback.
- CNI no longer sends a synthetic namespace mount path. Full-width namespace
  cookies remain decimal strings in the API, avoiding precision loss.

## Scope limits

Strict configuration is implemented in the library; CLI/chart lint integration
is pending. Endpoint ceilings above 4095 are unit-tested, not demonstrated at
high endpoint density. Loader object identity publication and nftables policy
integration are specification resolutions, with runtime acceptance still open.
Incomplete-probe Warning semantics retain HTTP 500 readiness behavior.

The existing CHECK implementation does not verify every route/MTU detail (#126).
Cross-endpoint rollback verification (#129), connectivity specification (#261),
Kubernetes controllers, persistent forwarding through agent downtime and the
two-node networking gate remain outstanding in milestone tracker #291. No new
release or arm64 runtime claim is made.

All seven listed issues were closed with links to this record. Cleanup removed
17,737 build files / 6.5 GiB and eleven task logs.
