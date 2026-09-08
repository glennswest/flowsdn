# Implementation assessment — 2026-09-08

## Current state

The initial tree contains specifications, inventories and harvested fixture data,
with no implementation or executable harness. The first implementation adds the
Cargo workspace, a Linux xtask driver and flowsdn-fence from spec 00 §3.4.1.
The dependency license policy is configured for issue #265; enforcement must be
validated with cargo-deny before that issue can be considered complete.

The GitHub backlog was read live on 2026-09-08: **287 open issues**:
204 open decisions, 36 verification items, 24 specification gaps, 13 deferred
items, 7 upstream bugs, and 3 blocked-on-code items. The generated index is a
historical harvest, not a current open-issue count. No issues were closed by
this assessment.

## Execution order

1. Validate and release the workspace/fence foundation. Fences have no table,
   Kubernetes, BPF or kernel dependency.
2. Table core: resolve #42 using the spec recommendation (whole-table watches),
   and #205 using explicit ordered TableRender headers/cells. Record decisions
   before freezing row APIs. Implement snapshots, revisions and watches with
   race/lag tests before adding reconciliation.
3. Config normalization, typed parsing and precedence; then the complete key
   registry. Build the txtar parser independently; command adapters follow the
   table/config APIs. Fixture presence alone does not count as passing coverage.
4. Workspace CI and change detection (#264), then map ABI and loader.
5. First datapath milestone, agent and CNI; identity/policy/service programming
   follows the inventory dependency order.

## Decisions that need reconciliation

- #54: kernel-requirements.md says general minimum 6.6 and stormcos 6.12;
  the datapath issue recommends general minimum 6.1. Reconcile the normative
  texts before implementing loader fallbacks.
- #53: start with the proposed single object per hook only after defining the
  verifier measurement gate; proposed fallback split dimensions differ by spec.
- #55: identical Cilium wire encoding is recommended for mixed-cluster migration.
  Boundary compatibility does not itself prove compatibility of restored state.
- #30, #20, #156 and #114 gate Kubernetes capabilities, identity backend,
  CEP/CES rollout and endpoint migration respectively. They do not block the
  first foundation crates.
- The referenced ../CLAUDE.md does not exist in this checkout. Build-host rules
  are restated in this repository and spec 22; AGENTS.md records the user rule
  that all transfers and results go through GitHub.

## First-slice scope

Fence registration is mutable construction, followed by explicit seal and shared
immutable use. Concurrent waits serialize access to retained futures; cancelling
one caller leaves the pending future available for another caller. Completed
successes and failures are cached. A watch sender closing before readiness is
an error. Timeout policy and health degradation belong to owners, not the fence.
The empty fence resolves after sealing; waiting before sealing returns an error.

No BPF nightly pin or empty component crates are invented. The initial xtask has
no automatic SSH dispatch, packaging or deployment. Cross-target cargo check
validates compilation, not arm64 runtime behavior or static executable linking.

## Validation

Executed on dev.g8.lo with Rust 1.95.0:
- cargo xtask check: formatting, warning-free Clippy, 7 native tests, and
  all-target compile checks for x86_64/aarch64 Linux musl passed.
- cargo test --workspace --release --locked: 7 tests passed, including release
  registration errors (the debug run checks the corresponding panics).
- cargo-deny 0.20.2: advisories, bans, licenses and sources passed. Warnings
  only report allowed licenses absent from this small dependency graph.
- cargo clean --target-dir /build/cargo/flowsdn completed after checks.
  Compiler artifacts, including cargo-deny installation intermediates, removed.
  The reusable cargo-deny executable remains in /build/cache/flowsdn-tools/bin.

The build target directory is on /dev/sdc (ROTA=1), mounted at /build.
Only project source lives on the root SSD. No other project's output was cleaned.
CI automation, negative policy fixtures, privileged tests, arm64 execution,
static linking, health/timeout owners and harvested-corpus execution remain
future work; this release does not claim those gates.
