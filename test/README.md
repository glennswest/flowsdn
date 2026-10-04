# flowsdn test container

flowsdn's suites under stormcentral's
[test standard](https://github.com/glennswest/stormcentral/blob/main/docs/test-standard.md)
(#303). There is one image, built from `test/Containerfile` with the repository
root as context, and it runs as `/test short|medium|long`. stormcentral runs it
as a Job on each test machine:
`stormcentral test run flowsdn <suite> --url http://stormcentral.g8.lo`.

## What it tests

Every suite tests the **commit under test**, not whatever the node has
installed. The image carries that commit's `flowsdn-agent`, `flowsdn-cni`, BPF
objects and kernel fixtures. The test moves itself into anonymous network and
mount namespaces of the pod, refuses ordinary forwarding there with nftables,
mounts a private bpffs and starts the real agent. Each sandbox is a worker
process in its own network namespace, wired up by the real CNI executable.
Nothing is attached to the node's links, pinned in the node's bpffs or created
in the cluster.

| suite | budget | checks |
|---|---|---|
| `short` | < 2 min | `agent-start`; `endpoint-add` (two dual-stack sandboxes); `pod-traffic-ipv4`/`-ipv6` (UDP both ways through BPF); `endpoint-del` (endpoints, IPAM, pins, links and state back to baseline) |
| `medium` | < 30 min | `short`, then the fixtures from [flowsdn-bpftest](../crates/flowsdn-bpftest/README.md), each a `fixture-<name>` line with its log in `/results`: smoke, packet-ingress, loader-features, uplink-ingress, endpoint, native-routing, cni-runtime, agent-runtime, skb-ctx-matrix (the spec 18 §9.1 `__sk_buff` `ctx_in` table; its last line is the per-kernel matrix, #256) and socket-live |
| `long` | night window | waves of sandboxes against one agent: size from the pod's CPUs and memory limit (16 per CPU, half the memory at 16 MiB each, at most 500 for the endpoint map, capped by `STORM_WAVE_MAX`); sizes cycle full, half, three quarters; traffic on up to 32 pairs per family; agent restart under load every third wave; drain. One `wave-<n>` line per wave, the trend in `/results/waves.jsonl`, then `wave-slowdown` (mean ADD over 2x wave 1 + 5 ms) and `wave-residue` (any object above wave 1's drained count, agent fds +4, RSS +50% + 16 MiB) |

Every suite starts with a read-only **node probe**. `node-cni` checks for
`/opt/cni/bin/flowsdn`, and `node-agent` sends GETs to `/v1/healthz`,
`/v1/config` and `/v1/endpoint` on the node agent's socket. A node without the
flowsdn CNI is not the flowsdn flavor, and both checks report skip.

Left out of `medium`: `socket-context`, because the kernel's test-run of
connect hooks is unsupported (errno 524 on 6.17), and `socket-live` covers those
programs instead. The load-only kfunc probe is also left out, because running it
would destroy sockets (#3).

## Machine requirements

[`requires.toml`](requires.toml) declares a privileged pod for each suite, plus
read-only `/opt/cni/bin` and `/run` for the node probe. The test checks the
machine itself:

- If the kernel is older than 6.6 (no TCX) or has no BTF, the test prints one
  `datapath` skip and exits 0.
- If the pod lacks `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` or `CAP_BPF`, or the image
  is missing something, that is infrastructure: exit 2.

## Results

Each test is one JSON line on stdout, followed by a `summary` line. The exit
code is 0 for a pass, 1 if a test failed and 2 if the test could not run. Agent
and fixture logs go under `/results`.

## Build

`test/build.sh` runs on the build box (stormcentral calls it before `podman
build`). It builds the BPF objects with the nightly pinned in
`crates/flowsdn-bpf/rust-toolchain.toml`, installing that nightly through rustup
if it is absent, and with bpf-linker 0.11.1, downloaded and SHA-256 checked if
it is not on `PATH`. It builds the static musl binaries and stages them all in
`test/.stage` (git-ignored). The image is `fedora-minimal`, because the fixtures
and the namespace setup call `ip` and `nft`.
