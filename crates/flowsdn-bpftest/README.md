# Kernel smoke harness

This implements the first self-test from specification 18 §9.1. It loads the
Rust `smoke` classifier, verifies six packet round trips and shared map updates,
then tests live UDP pass/drop/recovery, explicit detach and owner-drop cleanup.
It is test infrastructure, not the networking agent or a production firewall.

Requirements: Linux 6.6+, BPF and network namespace privileges, `ip`, the
userspace Rust toolchain and the BPF crate's pinned nightly. Install
`bpf-linker` 0.11.1 from its [official release](https://github.com/aya-rs/bpf-linker/releases/tag/v0.11.1)
and place it on `PATH`. Its x86-64 Linux archive has SHA-256
`e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8`.

From the repository root:

```sh
CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS='-C debuginfo=2 -C link-arg=--btf' \
  cargo +nightly-2026-04-03 build --manifest-path crates/flowsdn-bpf/Cargo.toml \
  --target bpfel-unknown-none -Z build-std=core --release --locked
cargo build -p flowsdn-bpftest --locked
```

Run the resulting `flowsdn-bpftest` executable with the path to the resulting
`bpfel-unknown-none/release/smoke` object. Both outputs use `CARGO_TARGET_DIR`
when configured; otherwise they use their workspace's normal Cargo target
directory. Run with the required privileges. The harness creates an anonymous
network namespace before changing loopback and fails if isolation is unavailable.
No host interfaces or persistent BPF pins are used. The namespace disappears
when the process exits. Only the smoke map's last packet length is observed;
it is not a concurrency-safe packet counter.

Ordinary `cargo test` does not execute these privileged checks. Failure exits
nonzero; an unavailable kernel feature is a failure, not a silent pass.
The smoke harness tests TC/IPv4 loopback. Neither harness covers XDP or the
full harvested BPF case corpus.

Run `flowsdn-endpoint-test` with the `local-delivery` BPF object to exercise
two endpoint namespaces. Sixteen kernel packet cases check MAC rewriting,
hop limits, IPv4 checksums and malformed-packet rejection. Live IPv4/IPv6 UDP
checks map deletion/reinsertion, detach and fresh-object reload. The fixture
uses the CNI ADD transaction, real host-scope allocation and an injected
post-creation failure to verify endpoint, link and address rollback and retry.
Endpoint setup now uses the native Rust connector. The fixture retains `ip`
for isolated setup/inspection; it is not the CNI executable.

Run `native-routing` with the same BPF object for two router namespaces and
two endpoints. It tests dual-stack traffic, route removal/restoration and
object detach/reload. Mandatory namespace-local nftables FORWARD drops prevent
ordinary Linux forwarding from masking BPF failures. This fixture additionally
requires `nft`; routes and neighbors are provisioned explicitly, with no
Kubernetes discovery controller.

Run `cni-runtime` with the `flowsdn-cni` executable path followed by the BPF
object path to exercise the executable's ADD/CHECK/DEL workflow. Its Unix
test server drives real IPAM and BPF operations; checks include live dual-stack
UDP, missing-address detection, duplicate deletion and HTTP503 offline queueing.
The test server is not a deployable agent.

Run `agent-runtime` with the CNI executable, agent executable and BPF object
paths to exercise the real standalone process. It checks dual-stack ADD/CHECK,
restart recovery, offline deletion replay, partial teardown health, retries and
persisted-state cleanup. It also checks module-health query wire rows, native
health JSON and rejection of other table queries across process restarts. Traffic loss during agent downtime is an explicit
current limitation, not a continuity claim.

The BPF crate is a separate workspace with its own lockfile and toolchain.
Format it separately with `cargo +nightly-2026-04-03 fmt --manifest-path
crates/flowsdn-bpf/Cargo.toml`. Its dependency policy must also be checked
against the repository's `deny.toml`.
