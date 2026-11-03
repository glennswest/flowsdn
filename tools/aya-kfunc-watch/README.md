# aya-kfunc-watch

Tells flowsdn when it can call the `bpf_sock_destroy` kfunc from eBPF (#315).

Until then, policy-driven socket termination (milestone 3) uses netlink
`SOCK_DIAG` `SOCK_DESTROY`. That was the owner's decision on #3. The switch
needs two things upstream:

- **aya** must relocate kfunc calls. Done upstream:
  [aya-rs/aya#1372](https://github.com/aya-rs/aya/pull/1372) resolves externs
  listed in the object's `.ksyms` BTF datasec, released in aya 0.16.0.
- **The object** must list the kfunc in `.ksyms`. C's `__ksym` does this. A
  Rust `extern "C"` declaration does not, even with bpf-linker 0.13.0: that
  release keeps an extern declaration's linkage and BTF
  ([aya-rs/bpf-linker#317](https://github.com/aya-rs/bpf-linker/pull/317)), but
  only for a declaration carrying `section ".ksyms"` and declaration debug
  info, which rustc does not emit. bpf-linker's own test supplies both from a
  hand-written LLVM IR file (`tests/assembly/auxiliary/extern.ll`). So every
  aya fails with `ExternNotFound` on a Rust object. This is the gap now.

## Running it

```sh
sc-build 'tools/aya-kfunc-watch.sh'                    # release + main
sc-build 'tools/aya-kfunc-watch.sh pinned release main'
tools/aya-kfunc-watch.sh --load --file-issue           # privileged runner with gh
```

The script builds the `loader-kfunc` probe (`crates/flowsdn-bpf`, `iter/tcp`
calling `bpf_sock_destroy`) with `tools/build-bpf.sh`. It uses the pinned
bpf-linker, plus the latest bpf-linker release when that differs. For each
aya under test, it builds this crate against that aya:

- `release`: the latest on crates.io, built with stable;
- `main`: aya's main branch, built with stable;
- `pinned`: the workspace's aya, built with the repository toolchain.

It then loads each object. Relocation runs without privileges. `--load` also
loads the program into the kernel; it is never attached or run.

It prints one line per combination:

```
aya-kfunc-watch: <source> aya <version> <crate source>, bpf-linker <tag>: <word>: <detail>
```

| Exit | Word | Meaning |
|---|---|---|
| 0 | `missing` | No combination relocates the kfunc yet. Nothing to do. |
| 3 | `relocates` | One combination does. Open or update the P1 issue "aya relocates kfuncs: switch socket termination to bpf_sock_destroy" (`--file-issue` does this with gh). |
| 1 | `broken` | The check needs attention: the probe doesn't build against an aya, the load failed in an unexpected way, or a download failed. |

On 2026-10-05 the result (sc-build, unprivileged) was `missing` for every
combination: 0.14.0 failed with `UnknownFunction`, and main at `1668342`
failed with `ExternNotFound`.

On 2026-11-03 (sc-build at a6c6c1a, `pinned release main`) it was `missing`
everywhere: pinned aya 0.14.0 failed with `UnknownFunction`; aya 0.16.0 and
main at `f7f0f05` failed with `ExternNotFound` with both bpf-linker 0.11.1
and 0.13.0.

## The switch (#315)

When the watch exits 3:

1. Bump aya.
2. Declare `bpf_sock_destroy` so that it lands in `.ksyms` (from Rust, once
   rustc or aya-ebpf can emit it there).
3. Use it from eBPF for policy-driven socket termination.
4. Keep `SOCK_DESTROY` as the fallback for kernels without the kfunc.
5. Add a test for each path.
