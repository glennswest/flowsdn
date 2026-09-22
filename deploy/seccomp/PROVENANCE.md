# Seccomp profile provenance

`agent-amd64.json` is derived from the Apache-2.0 containers/common seccomp
baseline packaged as `containers-common-0.64.2-1.fc43.noarch`.
Copyright containers/common contributors. The repository’s Apache-2.0 LICENSE
also supplies the license text for this derived JSON data.

Upstream source: [containers/common v0.64.2](https://github.com/containers/common/tree/v0.64.2/pkg/seccomp).
Packaged baseline SHA-256:
`886ae167646b7e5db381ecf7c31e6de720a8e8da15cf3202fe1f67f424af2b75`.

The Rust generator resolves amd64 architecture/capability conditions for
`NET_ADMIN`, `NET_RAW`, `BPF`, `PERFMON`, `IPC_LOCK`, `SYS_ADMIN`, preserves
argument filters, and adds explicit `bpf`, `perf_event_open`, `setns`, `mount`
allow rules. It never turns trace observations into new permissions.

On 2026-09-22, 25 selected agent/CNI execs yielded 60 observed syscall names:
59 unconditionally allowed and one conditionally covered. The sanitized report
records 85 unattributed files and 5,702 unattributed calls rather than guessing
thread/helper ownership. No raw trace is committed.

The generated filter was installed through system libseccomp and inherited by
the complete agent restart/rollback/offline-delete fixture, which passed.
A separate process check reported `NoNewPrivs: 1`, `Seccomp: 2`,
`Seccomp_filters: 1`. This validates that x86-64 fixture, not every runtime,
arm64, Helm deployment or production subsystem.

The validation-only `enforce` executable dynamically opens the installed Linux
`libseccomp.so.2` (LGPL-2.1). It neither vendors nor distributes that library;
its Rust dependency graph adds only the existing MIT/Apache-2.0 libc crate.
This system-library requirement does not apply to shipped agent/CNI binaries.
