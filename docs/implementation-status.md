# Implementation assessment — 2026-09-08

## Current state

The initial tree contained specifications, inventories and harvested fixture data,
with no implementation or executable harness. The first implementation adds the
Cargo workspace, a Linux xtask driver and flowsdn-fence from spec 00 §3.4.1.
The dependency license policy for issue #265 passes cargo-deny on the resolved
graph; negative policy fixtures and CI automation remain. Version 0.2.0 adds
the dependency-free txtar/script parsing front end from spec 17.

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

## Version 0.1.0 validation

Executed on Linux with Rust 1.95.0:
- cargo xtask check: formatting, warning-free Clippy, 7 native tests, and
  all-target compile checks for x86_64/aarch64 Linux musl passed.
- cargo test --workspace --release --locked: 7 tests passed, including release
  registration errors (the debug run checks the corresponding panics).
- cargo-deny 0.20.2: advisories, bans, licenses and sources passed. Warnings
  only report allowed licenses absent from this small dependency graph.
- cargo clean --target-dir <cargo-target-dir> completed after checks.
  Compiler artifacts, including cargo-deny installation intermediates, removed.

CI automation, negative policy fixtures, privileged tests, arm64 execution,
static linking, health/timeout owners and harvested-corpus execution remain
future work; this release does not claim those gates.

## Version 0.2.0 validation

On Linux with Rust 1.95.0 and normal compiler caching:
- Formatting and warning-free Clippy passed.
- 15 tests passed in debug and 15 in release.
- The corpus test parsed 168 archives, 1,444 embedded files and 3,537 commands,
  and reconstructed every archive byte for byte.
- Compile checks passed for both x86_64 and aarch64 Linux musl.
- cargo-deny 0.20.2 passed advisories, bans, licenses and sources; only unused
  allow-list entries produced warnings.
- Compiler output was cleaned after these checks.

Parsing does not execute assertions, validate command registrations or
condition capabilities, expand variables, or materialize archive files.
The runtime engine and adapters remain unimplemented. No harvested file changed.

## Version 0.3.0 validation

The indexed table core adds immutable snapshots, revisions, serialized writes,
unique/multikey indexes and atomic batch publication. Watches, retained
change streams, initialization tracking and reconciliation are not implemented.

Validated on Linux with Rust 1.95.0:
- `cargo xtask check`: formatting, Clippy with warnings denied, 29 native
  tests and all-target compile checks for x86_64/aarch64 Linux musl passed.
- `cargo test --workspace --release --locked`: the same 29 tests passed.
- `cargo xtask deny`: advisories, bans, licenses and sources passed.
- Rust BPF harvester: all 142 translation units and 625 effective cases match
  the pinned reference inventory, including feature/configuration, entrypoint
  and milestone fields. Generated TOML passed a second comparison.

The 29 tests comprise 7 fence, 8 parser, 10 table and 4 harvester tests.
No Python executable source remains tracked. These checks do not exercise
BPF programs or the networking assertions in the harvested corpus.

## Version 0.4.0 validation

Whole-table streams and the typed configuration core are implemented. All 51
unique tests passed in debug and release: 24 table, 8 configuration, 8 parser,
7 fence and 4 harvester. Formatting, Clippy with warnings denied, all-target
x86_64/aarch64 Linux musl compile checks, and cargo-deny passed.

Stream tests cover concurrent subscription/publication, cancelled waits,
independent acknowledgements, lag resync, partially consumed snapshots, and
reference-model convergence. Live draining merges ordered indexes up to the
requested limit. Configuration tests cover aliases, precedence, list replacement
and flag append, typed ranges, durations, malformed inputs and diagnostics.

Initialization gates, source loaders, the full configuration catalogue,
reconciliation and script execution remain forthcoming. Compile checks on both
architectures do not claim arm64 runtime or networking coverage.

## Version 0.5.0 validation

All 71 unique tests passed in debug and release: 30 table, 17 configuration,
13 parser/expansion, 7 fence and 4 harvester. Formatting, Clippy with warnings
denied, all-target x86_64/aarch64 Linux musl compile checks and cargo-deny passed.

The new regressions cover initializer registration/seal races and cancellation,
YAML scalar lexemes and duplicate detection, projected directory symlinks,
source precedence and alias collisions, plus literal/regex variable expansion.
A missing type annotation in one initializer test was corrected during validation.

The full configuration catalogue, cross-key validators, runtime persistence,
reconciliation and script command execution remain forthcoming. No networking
coverage is claimed by these foundation tests.

## Version 0.6.0 validation

All 110 unique tests passed in debug and release: 30 table, 29 configuration,
22 script/parser, 11 reconciler, 7 fence, 7 build-selector and 4 harvester tests.
Formatting, Clippy with warnings denied, both Linux musl all-target compile
checks, and cargo-deny passed. Dependency policy initially rejected the new
internal path dependency without a version; pinning it to the workspace release
passed the locked resolution and policy checks.

Synthetic txtar scripts now execute generic commands and assertions. Harvested
networking scenarios still lack their subsystem adapters. Reconciler tests cover
retry deadlines, stale asynchronous results, cancellation replay and resync
requests. Its caller-driven interface defers background timers and actual prune.
Configuration tests cover foundation dependencies, ignored-feature behavior and
restart comparisons of immutable values. Change-selection tests cover transitive
and patched dependencies, cycles, shared inputs and documentation-only changes.
The empty committed-diff CLI path was exercised and skipped workspace checks.

Issue #43 is resolved by ADR-0009. Issue #264 remains open: check selection is
implemented, but CI provisioning and remote cache integration are not complete.

## Version 0.7.0 validation

All 149 unique tests passed in debug and release: 41 configuration, 35 script,
30 table, 18 reconciler, 7 health, 7 fence, 7 build-selector and 4 harvester tests.
Formatting, Clippy with warnings denied, both Linux musl all-target compile
checks and cargo-deny passed. Issue #265 is complete: the workspace license
policy is configured and its checks pass against the locked dependencies.

The milestone adds initialization-gated target pruning, bounded runtime
configuration snapshots with atomic publication and history rotation, module
health reporters and readiness evaluation, and confined script file commands.
Regression coverage includes cancellation replay, concurrent snapshot readers,
special-file rejection, symlink confinement, expansion and log limits, and
normalization of the script working directory after returning to its root.

Reconciler scheduling remains caller-owned. The full configuration catalogue,
health HTTP serving, script subprocesses and networking adapters remain pending.
These foundation tests do not establish runtime networking compatibility.

## Version 0.8.0 implementation

All 180 unique tests passed in debug and release: 48 configuration, 45 script,
30 table, 27 reconciler, 7 health, 7 fence, 7 build-selector, 5 build-metadata
and 4 harvester tests. Formatting, Clippy with warnings denied, both Linux musl
all-target compile checks and dependency policy checks passed.

The registry catalogue contains all 539 normative declarations, with 488
literal defaults and 51 unresolved defaults requiring explicit values and
provenance. Class metadata includes immutable, runtime and dynamic keys;
registration does not itself make an option mutable. Missing help metadata
and area validators remain documented gaps.

The reconciler has a caller-owned run loop for row changes, retries, periodic
pruning and shutdown. It preserves queued work across cancellation, measures
retry delays after failures complete and throttles bounded rounds. Initialization
gates prune; stricter startup fences remain the caller's responsibility.

Script file commands now include exists, chmod, mv, symlink and rm. New
regressions cover mode-000 paths, special files, recursive limits, workspace-root
aliases and cleanup beyond the command depth budget. Validation corrected an
invalid combination of Linux path-only and nonblocking open flags.

The new build-metadata crate provides deterministic timestamp conversion, JSON
and metric labels. Invalid injected values fail explicitly, including non-UTF-8
environment values. No current-clock build timestamps are sampled. This does
not establish whole-binary reproducibility or provide a networking executable.

Issue #122 is resolved by ADR-0010. Refresh and batched reconciliation, remaining
catalogue defaults, script subprocesses and networking adapters remain pending.

## Version 0.9.0 implementation

All 211 unique tests passed in debug and release with all features enabled:
55 script, 51 configuration, 39 reconciler, 30 table, 7 health, 7 fence,
7 build-selector, 6 map ABI, 5 build-metadata and 4 harvester tests.
Formatting, Clippy with warnings denied, both Linux musl all-target compile
checks and dependency policy passed against 89 external dependency versions.

The first map ABI subset provides dependency-free `no_std` connection tuples,
LPM address keys and frozen ipcache layouts. Compile-time layout assertions and
independent byte fixtures cover offsets, endian rules, prefix bounds and padding.
This does not establish Aya integration, live-map or verifier compatibility.

Owning specifications resolve 33 more configuration defaults with recorded
provenance. Of 539 declarations, 521 defaults now resolve and 18 remain explicit
gaps. Conflicting declarations remain unresolved; no reference implementation
code was used to invent missing values.

Periodic refresh traverses a revision snapshot in bounded chunks, rechecks
candidate generations, limits new refresh dispatches and carries force-write
hints across cancellation and retries. Slow successes schedule from completion;
recent rows skipped by a pass contribute their earliest eligibility deadline.

Foreground subprocess execution uses the existing engine's expansion, conditions
and exit assertions. It bounds output, clears the inherited environment, tracks
cancellation/deadlines and owns process-group signals before reaping the leader.
Rust fixture processes cover graceful interruption, forced cleanup, descendants,
caller-future drop, output overflow and invalid UTF-8 error precedence.
Feature-gated fixtures are included in the standard workspace checks. Executable
code retains OS permissions; stronger process isolation remains caller-owned.

Batch reconciliation, remaining map layouts, background script jobs and
networking subsystem adapters remain forthcoming.

## Version 0.10.0 implementation

The map ABI now includes conntrack and NAT values plus 15 load-balancer layouts.
Explicit codecs retain raw unions, unknown flags and padding; compile-time
assertions freeze sizes and offsets, including the proxy identity at byte 44.
Independent Rust byte fixtures exercise network-order addresses and ports,
host-order counters, prefix bounds and service union views. The specifications
conflict on L7 proxy-port byte order, so that conversion remains deferred.

Targets can opt into bounded reconciliation batches with scalar defaults.
Deletes precede updates, each result names its desired key and revision, and
malformed responses retain the complete unacknowledged group for replay.
Per-row failures use normal retry scheduling; stale generations, refresh hints
and completion-based refresh deadlines remain checked across cancellation.

Background script execution snapshots each job's environment and working
directory. `wait` drains in launch order, combines output and applies individual
exit expectations. Job count, shared queued output and diagnostics are bounded;
script exit and dropped futures clean up retained processes and workspaces.
Section retries and networking subsystem adapters remain forthcoming.

These additions remain foundation libraries. Map creation, Aya integration,
live datapath compatibility and an operational networking agent are not included.

Validation completed against source commit `cc9ec2c`: **247 unique tests passed
in debug and release with all features** (66 script, 51 configuration,
50 reconciler, 30 table, 20 map ABI, 7 health, 7 fence, 7 build-selector,
5 build-metadata and 4 harvester). Formatting, warning-free Clippy,
x86_64/aarch64 Linux musl compile checks and dependency policy all passed.
The locked dependency graph remains unchanged at 89 external versions.
Build output was cleaned after validation: 9,880 files / 2.7 GiB removed, along
with this milestone's temporary logs. The release is source-only.
