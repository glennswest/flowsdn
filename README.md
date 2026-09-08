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

**Foundation implementation started (2026-09-08), version 0.7.0.**

The workspace includes indexed tables, initialization gates, a caller-driven
reconciler, configuration loaders and validation, and a script-engine core.
There is no working networking agent or datapath. Synthetic script commands
execute, while the harvested networking scenarios still lack their adapters.

| | |
|---|---|
| Specifications | 24 files, ~40k lines — every area, normative, with compatibility contracts and test plans |
| Inventories | 17 files, ~12.5k lines — the reference measured at v1.20.1 (`7d68cfb394`) |
| Decision records | 9 (`docs/decisions/`) |
| Harvested test corpora | 1,444 files — 168 txtar scenarios, 625 BPF cases, 1,196 golden fixtures, 30 fuzz seeds |
| Open backlog | 282 issues as checked 2026-09-08, indexed in `docs/open-decisions-index.md` |

Read in this order: `docs/decisions/` for what was decided and why,
`docs/inventory/README.md` for the scope table and build order,
then the spec for the area you are working on.

Next steps are the full configuration key catalogue, reconciler scheduling and script filesystem/subsystem commands; see
[implementation assessment](docs/implementation-status.md). Before the datapath crates are written, the three decisions at the top
of `docs/open-decisions-index.md` need settling: the kernel floor, the
single-object-versus-matrix question, and wire compatibility with Cilium nodes.

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
cargo test --workspace --release --locked
cargo xtask deny
```

`check` runs formatting, Clippy, tests, and compile checks for x86-64 and arm64
Linux musl. `deny` requires `cargo-deny`. Build output follows Cargo's standard
configuration, including `CARGO_TARGET_DIR` when set.

The test harnesses and inventory tools are Rust. Static compatibility fixtures
use txtar, YAML, TOML, and JSON. A txtar archive packages test commands and named
fixture files in one readable text file.
