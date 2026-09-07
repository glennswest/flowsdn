# <Area> — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `<list>`.

## Purpose
One paragraph: what this area does in the reference.

## Components
| Path | Lines | Purpose |
|---|---|---|

## Features
One bullet per user-visible or system-visible feature: name, behavior,
config keys / Helm values that enable it, CRDs or APIs involved.

## Data model
Structs, BPF maps (key/value layout, type, size, pinning), CRDs, persisted
files. At the boundary only; internal structs only when they leak.

## External interfaces
APIs (REST/gRPC/unix sockets), wire formats (VNI encoding, headers, marks),
files on disk, netlink objects created, sysctls touched.

## Dependencies
Other inventory areas, kernel features (with the exact helper/feature names
for BPF), external services (kvstore, cloud APIs, Envoy).

## Kernel / platform requirements
For datapath areas: helpers used, map types, program types, minimum kernel,
arch-specific notes (x86-64 vs arm64), driver requirements (XDP).

## Tests
What the reference tests: unit, privileged (needs root/kernel), e2e under
`test/` and `.github/workflows`, and what behaviors they pin down.

## Rust mapping
Candidate crates, obvious structure, risks and hard parts.

## Recommendation
keep / defer / replace, with the reason. Effort: S (< 2k lines), M (2-8k),
L (8-20k), XL (> 20k) in Rust.

## Open questions
