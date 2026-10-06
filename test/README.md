# flowsdn test container

flowsdn's suites (and the `perf` comparison suite, below) under stormcentral's
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
| `medium` | < 30 min | `short`, then the fixtures from [flowsdn-bpftest](../crates/flowsdn-bpftest/README.md), each a `fixture-<name>` line with its log in `/results`: smoke, packet-ingress, loader-features, uplink-ingress, endpoint, native-routing, cni-runtime, agent-runtime, skb-ctx-matrix (the spec 18 §9.1 `__sk_buff` `ctx_in` table; its last line is the per-kernel matrix, #256), socket-live and socket-lb-live (ClusterIP socket LB, #292) |
| `long` | night window | waves of sandboxes against one agent: size from the pod's CPUs and memory limit (16 per CPU, half the memory at 16 MiB each, at most 500 for the endpoint map, capped by `STORM_WAVE_MAX`); sizes cycle full, half, three quarters; traffic on up to 32 pairs per family; agent restart under load every third wave; drain. One `wave-<n>` line per wave, the trend in `/results/waves.jsonl`, then `wave-slowdown` (mean ADD over 2x wave 1 + 5 ms) and `wave-residue` (any object above wave 1's drained count, agent fds +4, RSS +50% + 16 MiB) |

Every suite starts with a read-only **node probe**. `node-cni` checks for
`/opt/cni/bin/flowsdn`, and `node-agent` sends GETs to `/v1/healthz`,
`/v1/config` and `/v1/endpoint` on the node agent's socket. A node without the
flowsdn CNI is not the flowsdn flavor, and both checks report skip.

On a flowsdn node with a healthy agent, the probe then checks ClusterIP
Services from the test pod's own network (#292), before the suite isolates
itself: `node-service-dns` queries kube-dns at the pod's nameserver (its
ClusterIP) for `kubernetes.default.svc.<domain>` and expects
`KUBERNETES_SERVICE_HOST`, with the reply from the ClusterIP:53;
`node-service-kubernetes` connects TCP to that Service and expects the
ClusterIP as the peer; `node-service-programmed` expects both frontends in the
agent's `GET /v1/service` with `status.realized`.

Left out of `medium`: `socket-context`, because the kernel's test-run of
connect hooks is unsupported (errno 524 on 6.17), and `socket-live` covers those
programs instead. The load-only kfunc probe is also left out, because running it
would destroy sockets (#3).

## `perf`: flowsdn vs Cilium (#321)

`/test perf` is the network performance suite, declared in
[`requires.toml`](requires.toml) with a 1800 s budget, so it runs by day:
`stormcentral test run flowsdn perf --tag <machine>`. Unlike the other
suites, it doesn't test the commit's own datapath. It measures **the cluster's
pod network as any pod sees it**, and nothing in it is flowsdn-specific, so
it runs unchanged on a Cilium-flavor and a flowsdn-flavor machine. The two
runs compare metric by metric. **Primary** (owner, #321) means every probe
passes on the flowsdn flavor, and each metric equals Cilium's or is better,
or the owner accepts the gap.

The suite is `flowsdn-perf`, a GNU binary that reaches the Kubernetes API
over Fedora OpenSSL. `/test perf` execs it. The test pod is the client, on
its pod network. It creates server pods from the same image
(`flowsdn-perf server`: TCP/UDP echo on 5201, a stream sink on 5202 that
returns the bytes it read, accept-and-close on 5203). It pins them with
`nodeName` to its own node and to another ready node, plus a ClusterIP
Service and NetworkPolicies, all in its run namespace and labelled with the
run id. It deletes them at the end. `host_pid` lets it find the CNI agent by
process name (`flowsdn-agent` or `cilium-agent`), which gives the flavor
(`STORM_FLAVOR` overrides when there is none) and the agent's CPU and memory.
`cluster_read` of nodes picks the peer. Each measurement runs 10 s
(`STORM_PERF_SECONDS`).

| test | measures |
|---|---|
| `perf-setup` | flavor, ready nodes, the cross-node peer |
| `agent-cost-idle`, `agent-cost-load` | agent CPU (% of one core) and RSS, idle and during the same-node 8-stream run |
| `pod-network-ready` | 10 pods created together on the node: create to Running with a pod IP, p50/p99/max ms |
| `cni-ready-after-boot` | skip: the network phase of stormcentral's boot breakdown (stormcentral#365) |
| `perf-server-same`, `perf-server-cross` | server pod placement and reachability |
| `pod-tcp-rr-*`, `pod-udp-rr-*` | 1-byte request/response latency p50/p90/p99/max and transactions/s (netperf TCP_RR/UDP_RR equivalents), `same-node` and `cross-node` |
| `pod-tcp-stream-1-*`, `pod-tcp-stream-8-*` | throughput in Gbit/s of what the server received, 1 and 8 streams (iperf3 equivalent) |
| `pod-connect-rate-*` | TCP connections/s and connect latency |
| `svc-ready`, `svc-*-clusterip` | the same through a ClusterIP Service (backend on the peer node when there is one), plus Service create to first connect |
| `dns-lookup` | 200 A/AAAA lookups each of the run's Service and `kubernetes.default` via the pod's nameserver (kube-dns), p50/p99 |
| `policy-deny-enforced`, `policy-remove-restored` | NetworkPolicy deny-all ingress create to enforcement, delete to traffic back (3 probes in a row, 60 s limit) |
| `policy-rules-100-*`, `policy-rules-1000-*` | single-stream throughput to a pod selected by a policy with 100 / 1,000 ingress rules (one allows the client) |
| `scale-pods-ready` | up to 100 pods (at most half the node's allocatable) on the node: how many got a pod IP, and how fast |
| `scale-endpoints`, `scale-svc-connect` | one Service over them: ready endpoints in its EndpointSlices, then connects/s spread over them with no failures |
| `conntrack-entries` | the host namespace's netfilter conntrack count before and after the connect run (skip without nf_conntrack) |

Each line is the standard test line plus `flavor`, `node` and a `metrics`
object, e.g. `{"test":"pod-tcp-rr-cross-node","status":"pass",…,
"flavor":"flowsdn","node":"pvetest1","metrics":{"p50_us":41.2,"p99_us":88.0,
"transactions_per_second":23011,…}}`. A probe fails when the network doesn't
do the thing at all, for example a policy that is never enforced. The numbers
themselves don't fail a run: comparing them is stormcentral's side-by-side view.
Run it on the same machines with each flavor installed: pvetest1+pvetest2
as a pair, then the Dell and a blade.

## `perf-scale`: how far each flavor goes (#321)

The owner asked for "a set of tests with both, in 100 unit (containers), and see
how far we go". `/test perf-scale` adds server pods in steps of 100,
round-robin over the ready nodes, all behind one ClusterIP Service. A step
passes when:

- every new pod gets a pod IP within 10 minutes;
- the Service's EndpointSlices hold every pod;
- 3 s of connects through the ClusterIP all succeed;
- the newest pod answers TCP_RR.

Each `scale-step-<n>` line carries the total pods, the step's p50/p99 to a pod
IP and the agent's CPU and RSS. The ramp stops at the first failing step, or at
the cluster's allocatable pods (`STORM_SCALE_MAX` caps it). Then `scale-max`
reports the most pods that had working networking and why it stopped, and
`scale-drain` deletes everything and times the Service emptying. The budget is
4 h, so it is a night run on a pve VM.

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
