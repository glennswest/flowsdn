# Milestone 1 checkpoint: Rust BPF kernel smoke

Validated 2026-09-09, completed by 17:32:08 UTC. Source revision `bbc6541`.
No release was created; milestone 1 remains in progress.

## Executed behavior

- Rust `aya-ebpf` classifier compiled to BPF ELF with BTF and loaded through Aya.
- Six `BPF_PROG_TEST_RUN` executions: 64/128/1500-byte packets, each with pass
  and drop rules. Verdict, unchanged output bytes, output length and observed
  skb length in the shared map matched; repeat was explicitly one.
- Live UDP in a fresh anonymous network namespace: pass, drop and resumed
  delivery after rule updates, with map evidence of classifier execution.
- Explicit TCX detach restored delivery while a drop rule remained in the map.
  The map stopped changing. Reattachment followed by owner drop left no TCX
  attachment. Namespace lifetime is bound to the single harness process.

## Validation

Linux kernel 6.17.1, x86-64 runtime; stable Rust 1.95.0 userspace;
nightly-2026-04-03 (LLVM 22.1.2) BPF compilation; bpf-linker 0.11.1;
Aya 0.14.0 and aya-ebpf 0.2.1. Both workspaces have committed lockfiles.
The linker was obtained from its GitHub release and the archive digest checked
against the release asset. No C compiler or libbpf was used.

- Workspace and separate BPF workspace formatting passed.
- Userspace all-targets Clippy and BPF-target release Clippy passed with
  warnings denied.
- Harness all-target compile checks passed for x86_64 and aarch64 Linux musl.
- Dependency advisories, bans, licenses and sources passed for both workspaces.
  Existing duplicate-version and unused-allowance warnings remain nonfatal.
- The privileged executable printed all three PASS groups and exited zero.

BPF object SHA-256:
`03d0c1aeb7a6105123bb7fa840ab9d1a45942131565345158770c54126e4d6d8`.
Build/run instructions are in `crates/flowsdn-bpftest/README.md`.

The initial nix 0.31.1 selection conflicted with the existing libc pin;
nix 0.30.1 resolved the graph without changing libc. A dependency-check command
initially misplaced the config option; the corrected invocation passed.

These checks do not claim arm64 execution, the 6.6/6.12 kernel matrix,
production forwarding, CNI, cross-node traffic or harvested networking-case
coverage. The existing 377 foundation tests were not rerun for this independent
harness checkpoint. No milestone acceptance gate is marked complete.
