# flowsdn

A Rust reimplementation of the Cilium networking stack: eBPF datapath, CNI,
kube-proxy replacement, identity-based network policy, encryption, egress,
BGP, cloud IPAM, and a Hubble-compatible observability API.

Goals:

- **Boundary-compatible with Cilium.** Same CRDs and semantics, same Hubble
  gRPC observer API, same agent REST API, documented Helm value mapping.
  Existing Cilium manifests, `cilium` and `hubble` CLIs keep working.
- **Free inside.** Precompiled eBPF (no clang on the node), one static binary
  per component, `scratch` container images, no iptables dependency.
- **Two architectures.** x86-64 and arm64, one BPF object for both.
- **Everything.** Full feature scope unless a documented decision records a
  better solution.

## Status

**Foundation implementation started (2026-09-08), version 0.14.0.**

The workspace includes indexed tables, initialization gates, a reconciler with
pruning, optional batching and a caller-owned scheduling loop, configuration snapshots, module
health and a script engine with generic file commands, foreground execution,
background jobs and whole-section retries. Reconciliation observers expose
attempted revisions and remaining retry progress, with optional module health
reporting. Typed script table bindings support `db/show` and `db/empty`.
The map ABI crate defines connection tuples, conntrack/NAT values, service
and policy layouts, plus endpoint, node, subnet and ipcache byte layouts.
The loader crate provides pinned-map compatibility planning, auxiliary scratch
layout planning and typed tail-program inventory checks.
The policy crate now supplies validated L3/L4 building blocks and an initial
independent oracle; Kubernetes policy import and enforcement remain outstanding.
The loader also plans capacity-preserving LRU reuse and feature-gated nested maps.
The identity crate adds numeric scopes, cluster ranges and tunnel encoding,
plus canonical CIDR labels and optional identity/node label filtering.
Fixed VXLAN/Geneve headers and Geneve DSR options have explicit wire codecs.
The released foundation has no working networking agent. Synthetic scripts and file assertions
execute, while the harvested networking scenarios still lack their adapters.

The unreleased milestone 1 work adds [privileged networking tests](crates/flowsdn-bpftest/README.md),
dual-stack BPF endpoint delivery, native cross-node routing, host-scope IPAM,
initial CNI and standalone endpoint agent executables, with persisted state.
Isolated endpoint tests exercise live IPv4/IPv6 traffic, allocation, attachment,
rollback, retry, process restart and offline deletion replay. The standalone
agent verifies ownership before reusing duplicate CNI attachments and preserves
their original route settings across restart. Endpoint allocation has a configurable
ceiling (4095 by default); the configuration library supports opt-in strict
unknown-key validation. The agent uses explicit local configuration; Kubernetes discovery, identity/policy
controllers, uninterrupted forwarding across agent downtime and two-node
Kubernetes pod connectivity remain outstanding.

The agent also exposes read-only module health through the reference query wire
format and a native JSON route, reporting missing controllers as degraded.
New Kubernetes and operator libraries provide guarded Node patch plans, CRD
registration/version checks, leadership/readiness gates and CES rate selection.
Hubble primitives cover IP/CIDR filters, drop decoding, ring behavior and realized
policy correlation. These libraries do not yet provide live controllers or an
Observer server. See the [metrics migration guide](docs/compatibility/metrics.md)
for the documented dashboard changes.

BGP protocol helpers now validate frames, OPEN capabilities and UPDATE structure,
with explicit lenient/strict content-error policy. Gateway helpers validate
configuration and project conditions; ClusterMesh helpers check address overlap,
read authorization and guarded ownership/lease plans. Deployment policy and
bounded script diagnostics are also available. Live speakers, controllers,
transactions and deployment adapters remain unfinished.

| | |
|---|---|
| Specifications | 24 files, ~40k lines — every area, normative, with compatibility contracts and test plans |
| Inventories | 17 files, ~12.5k lines — the reference measured at v1.20.1 (`7d68cfb394`) |
| Decision records | 13 (`docs/decisions/`) |
| Harvested test corpora | 1,444 files — 168 txtar scenarios, 625 BPF cases, 1,196 golden fixtures, 30 fuzz seeds |
| Open backlog | 173 issues as checked 2026-09-21; implementation acceptance tracked in #291–#294 |

Read in this order: `docs/decisions/` for what was decided and why,
`docs/inventory/README.md` for the scope table and build order,
then the spec for the area you are working on.

The configuration catalogue records all 539 keys. Of their defaults, 521 resolve
from the specifications and 18 require explicit values; see the
[catalogue gaps](crates/flowsdn-config/REGISTRY-GAPS.md). Build identity metadata
is available for future binaries.

The remaining implementation follows [four milestones](docs/milestones.md),
starting with working pod networking. See the
[implementation assessment](docs/implementation-status.md) for delivered components. The kernel target and measured object-variant policy are reconciled in the
specifications. The wire-format policy preserves the reference encodings; live
mixed-cluster compatibility remains unvalidated.

## Layout

```
docs/inventory/   per-area inventory of the reference implementation
docs/spec/        flowsdn specifications, one document per area
docs/decisions/   architecture decision records
docs/licensing.md clean-room protocol and license analysis
```

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.

## Building and testing

Development requires Linux and the Rust toolchain pinned in `rust-toolchain.toml`.

```sh
cargo xtask check
cargo test --workspace --all-features --release --locked
cargo xtask deny
```

`check` runs formatting, Clippy, tests, and compile checks for x86-64 and arm64
Linux musl, including all feature-gated test fixtures. `deny` requires
`cargo-deny`. Build output follows Cargo's standard
configuration, including `CARGO_TARGET_DIR` when set.

The test harnesses and inventory tools are Rust. Static compatibility fixtures
use txtar, YAML, TOML, and JSON. A txtar archive packages test commands and named
fixture files in one readable text file.

The next unreleased batch adds encryption and egress-selection plans, proxy ACK
barriers, ClusterMesh principal binding, bounded flow/event admission, and LB
input parsing and ordering. These libraries have explicit runtime integration
gaps; see [batch 6 evidence](docs/workcycles/2026-09-22-batch6.md). CI workflow
configuration is committed, with runner activation still outstanding.
