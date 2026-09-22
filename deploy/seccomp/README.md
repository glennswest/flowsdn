# Optional local seccomp profile

The `flowsdn-trace-seccomp` Rust tool generates an OCI seccomp profile from a
reviewed container-runtime default baseline, a target architecture and the
container's exact bounding capability set. It preserves the baseline's rules
and argument restrictions, then unconditionally allows `bpf`, `perf_event_open`,
`setns` and `mount`. This grants syscall entry, not kernel capabilities.
It is an opt-in scaffold; no universal production profile is shipped or enabled.

Run on the target Linux architecture using a baseline approved for that runtime:

```console
cargo run -p flowsdn-trace-seccomp --bin flowsdn-trace-seccomp -- \
  --baseline runtime-default.json --arch amd64 \
  --caps CAP_BPF,CAP_PERFMON,CAP_NET_ADMIN,CAP_SYS_ADMIN \
  --exe /usr/local/bin/flowsdn-agent --exe /opt/cni/bin/flowsdn-cni \
  --trace trace.1234 --trace trace.1235 \
  --output flowsdn-amd64.json --report syscall-counts.json
```

Replace paths, capabilities and trace files with the actual deployment values;
repeat `--trace` for each `strace -ff` file. Output files must not already exist.
Use `--arch arm64` for arm64. Capability includes require all listed capabilities;
excludes match any listed capability. Architecture conditions use the native
architecture. Argument filters remain intact. Unsupported condition types fail
instead of silently broadening access. Numeric errno and the common EPERM/ENOSYS
symbols are supported. The baseline is an input, not a bundled third-party copy.

Trace collection must include successful `execve` calls. Selection uses exact
executable paths, not basenames. Each PID file starts unattributed; collection
starts after a successful selected exec and stops at a successful helper exec.
Failed execs preserve attribution. Split exec calls and successful `execveat`
clear attribution. Threads or fork children without their own selected exec are
not attributed; their calls are counted as unattributed. This conservative sample
does not establish complete syscall coverage. Raw traces can contain credentials
and packet contents: keep them private and commit only the sanitized name/count
report. The report contains no executable paths, arguments or trace filenames.

Reports distinguish unconditional allow, conditional coverage, denial and missing
rules. Syscall-name counts cannot establish whether argument constraints matched.
Observations never grant new permissions. Review any missing or denied operations,
then run the privileged test suite **under the generated profile**, on both
architectures and the intended capability set, before adopting it. A passing
unconfined trace is not enforcement validation.

Install the reviewed generated JSON below each node's kubelet seccomp profile
root, for example `flowsdn/agent.json`. Apply the following fragment only after
node installation and enforcement testing (it is not a complete workload):

```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: flowsdn/agent.json
```

Seccomp settings on the agent Pod do not constrain a host-invoked CNI executable.
Applying a profile to that process needs its actual launcher/runtime integration.
Privileged containers commonly run unconfined despite a seccomp declaration;
verify the effective filter, rather than relying on the manifest alone.

The eventual Helm opt-in remains integration work. Retain the deployment's
existing security context until its reviewed generated profile is installed.

## Linux enforcement test runner

`cargo run -p flowsdn-trace-seccomp --bin enforce -- PROFILE.json -- COMMAND ARGS`
loads a resolved profile through the installed `libseccomp.so.2`, enables its
default no-new-privileges behavior, and replaces itself with the command. The
filter survives exec and is inherited by children, including test helpers.
Failures therefore include helper dependencies as well as agent/CNI syscalls.
Use the compiled test harness executable directly for meaningful validation;
running Cargo under the profile additionally exercises the compiler/toolchain.

The runner accepts only explicit native-family architectures, ALLOW/ERRNO/KILL
actions and standard comparison operators. It rejects unknown fields, unresolved
conditions, unsupported flags and syscall names. It does not silently discard
rules that cannot be represented. It is a single-process validation utility,
not a container-runtime integration. The system libseccomp shared library is
LGPL-2.1; it is dynamically loaded, not bundled into this tool.

## Validated opt-in artifact

[agent-amd64.json](agent-amd64.json) passed the complete isolated agent lifecycle
fixture under an installed seccomp filter on Linux x86-64. See
[provenance and limits](PROVENANCE.md). This artifact is opt-in; arm64 enforcement
and Helm integration remain outstanding. It does not change the default
security context or establish complete syscall coverage for future controllers.
