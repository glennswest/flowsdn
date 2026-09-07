# ADR-0002: Everything in Rust, including the BPF programs. No C.

Date: 2026-09-07. Status: accepted (user decision).

## Decision

flowsdn contains no C. The BPF datapath programs are written in Rust with
`aya-ebpf` and compiled at build time to BPF bytecode (`bpfel-unknown-none`),
one object for x86-64 and arm64. Userspace is Rust. There is no clang, llc or
libbpf anywhere in the build or on the node.

This overrides the inventory recommendation in `01-bpf-programs.md` to keep
the reference's C program bodies and compile them at build time.

## What this commits us to

- **Verifier budget management is our problem.** The reference relies on
  `#ifdef`-driven dead-code elimination to keep each program under the
  verifier's complexity limits on older kernels. In Rust the equivalent is
  Cargo features for compile-time variants plus `.rodata` globals patched at
  load with a reachability pass that prunes dead branches before load.
  Which combination we use, and how many object variants we ship, is decided
  in the datapath spec, not here.
- **Tail calls, unrolled copies and helper access** are written with
  aya-ebpf's primitives and, where the crate lacks one, with `core::arch::asm!`
  in BPF assembly or a local extension crate. Gaps are recorded in the
  datapath spec and fixed upstream where possible.
- **The 35k lines of C BPF tests** in the reference are not ported. flowsdn
  writes its own BPF test harness in Rust (userspace-driven `BPF_PROG_RUN`
  with packet fixtures) and reuses the reference test *cases* as a checklist.
- **Minimum kernel** is set by the datapath spec. Rust BPF output tends to
  need a newer verifier than hand-tuned C; a 5.10 floor is not promised.
- **Two Rust toolchains**: stable for userspace, the nightly (or pinned)
  toolchain aya-ebpf requires for the BPF target, driven from one workspace.

## Consequences

- Effort for area 01 moves from XL-with-C-reuse to XL-from-scratch. The
  first datapath milestone is the same set (no DSR, IPsec, SRv6, multicast,
  egress gateway, host firewall) but is a new implementation.
- The BPF programs follow the same clean-room protocol as everything else:
  spec first, code from the spec. The C reference is read for behavior,
  not transliterated.
