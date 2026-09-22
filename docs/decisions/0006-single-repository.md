# ADR-0006: One repository. A single Cargo workspace.

Date: 2026-09-07. Status: accepted.

## Decision

flowsdn is **one private repository** containing one Cargo workspace with all
~30 crates, the BPF programs, the Helm chart, the harvested test corpora and
the documentation. It is not split into per-component repositories.

## Why

**The BPF ABI is shared between kernel and userspace code.** `flowsdn-bpf-abi`
is compiled into both the aya-ebpf programs and the agent. A layout change is
only correct if both sides change together. Splitting that across repositories
puts version skew in the single most dangerous place in the system: a mismatched
`#[repr(C)]` does not fail to build, it silently misreads packets.

**Ordinary changes are inherently cross-crate.** Adding one field to a
conntrack entry touches the ABI crate, the datapath programs, the loader, the
GC task, the debug CLI's dump format, and the harvested `.table` expectations.
In one workspace that is one commit that either builds or does not. Across six
repositories it is six pull requests with a broken intermediate state at every
step, and a bisect that cannot be performed.

**The test corpus is cross-cutting by construction.** A single txtar scenario
drives the config registry, the k8s fakes, the tables, the reconcilers and the
BPF maps at once. 168 of them span load balancing, policy, BGP, ClusterMesh and
the datapath. There is no repository boundary that does not cut through them.

**One version, one golden.** Per the stormboot model the deliverable is a
sealed image, not a set of independently versioned libraries. Semver across
six repos would be bookkeeping with no consumer.

**Prior experience in this codebase.** `rustkube-node` consumes `rustkube`'s
apimachinery through a sibling-directory path dependency, which requires both
trees checked out side by side and pins nothing. The `mkfs-ext4`/`fio-ext4`
lockstep pin is another instance of the same tax. That pattern is a known cost
here and this project does not need to pay it again.

## What this does not preclude

Two crates have a plausible audience outside flowsdn and may be **extracted and
published later, once their APIs have stopped moving**:

- `flowsdn-bgp-proto` — a BGP message codec and FSM with no flowsdn types in
  its interface. Genuinely reusable; nothing comparable exists in Rust today.
- `flowsdn-scripttest` — a txtar-driven script test engine, useful to any
  project that wants the reference's testing style.

Extraction is a deliberate, later decision, made when the crate has external
users, not in anticipation of them. Until then they live in the workspace like
everything else.

## Consequences

- Clone size grows with the harvested corpora (currently ~8 MB of test data).
  Acceptable; the reference clone is 900 MB.
- CI must use per-crate caching and change detection so a documentation edit
  does not rebuild the BPF programs.
- `cargo deny`, the license policy and the MSRV are configured once at the
  workspace root.

## Extraction review (#263, 2026-09-22)

Keep `flowsdn-bgp-proto` and `flowsdn-scripttest` in this workspace and keep
`publish = false`. Their APIs are still changing in the active milestone work;
no external consumer requirement is recorded in this repository. Do not create
placeholder repositories or publish prereleases to reserve names.

Reopen extraction when a concrete external consumer requests it, the public
API has survived a flowsdn release without incompatible changes, each crate
builds/tests independently with no private workspace types, and ownership,
licensing, release automation and compatibility policy have been reviewed.
Extraction is gated by those events, with no speculative calendar date. This
resolves the timing decision; it is not a claim that either crate is published.
