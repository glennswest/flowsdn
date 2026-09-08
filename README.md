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

**Foundation implementation started (2026-09-08), version 0.1.0.**

The Cargo workspace and startup fence are implemented. There is no working
agent or datapath yet; the harvested corpora are not executable tests yet.

| | |
|---|---|
| Specifications | 24 files, ~40k lines — every area, normative, with compatibility contracts and test plans |
| Inventories | 17 files, ~12.5k lines — the reference measured at v1.20.1 (`7d68cfb394`) |
| Decision records | 7 (`docs/decisions/`) |
| Harvested test corpora | 1,444 files — 168 txtar scenarios, 625 BPF cases, 1,196 golden fixtures, 30 fuzz seeds |
| Open backlog | 287 issues as checked 2026-09-08, indexed in `docs/open-decisions-index.md` |

Read in this order: `docs/decisions/` for what was decided and why,
`docs/inventory/README.md` for the scope table and build order,
then the spec for the area you are working on.

Next steps are the table crate, configuration registry and txtar parser; see
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

## Development

Rule #1: commit and push to GitHub, then pull on dev; never copy working trees
between hosts. Source changes and validation records return through commits;
distributable artifacts go to GitHub Releases. See [AGENTS.md](AGENTS.md).

Build on `dev.g8.lo`, with Rust 1.95.0 pinned by `rust-toolchain.toml`:

```sh
ssh root@dev.g8.lo
# First use: git clone git@github.com:glennswest/flowsdn.git /root/flowsdn
cd /root/flowsdn
git pull --ff-only
export CARGO_TARGET_DIR=/build/cargo/flowsdn TMPDIR=/build/tmp
cargo xtask check
cargo test --workspace --release --locked
cargo xtask deny  # requires cargo-deny on the build host
```

`check` runs formatting, Clippy, native tests and compile checks for both Linux
musl architectures. arm64 execution and static binary linking are separate
future gates. The initial xtask supports `build`, `test`, `check`, and `deny`;
remote dispatch, BPF builds, images and deployment commands are not implemented.
