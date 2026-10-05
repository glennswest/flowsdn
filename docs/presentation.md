---
marp: true
title: flowsdn — purpose and functionality
paginate: true
---

<!-- Render: npx @marp-team/marp-cli docs/presentation.md (HTML), add --pdf for PDF.
     Facts as of 2026-10-05, flowsdn main (golden-flowsdn-a7ee3f63195b from c6c96c7,
     perf suite at e397e16). Every claim points at code or a doc you can check. -->

# flowsdn

**Pod networking for stormcos, written in Rust.**

- The CNI plugin and node agent of stormcos's **flowsdn edition**.
- Cilium's boundary formats (CNI result, agent API, BPF map layouts) are the
  compatibility target; Cilium itself is not shipped.
- Rust userspace and **aya** eBPF datapath: no C datapath, no iptables dependency.

Repo: `glennswest/flowsdn` · version 0.14.0 · 31 crates

---

## The problem it solves

stormcos nodes need a pod network: an address per pod, delivery between pods
on a node and across nodes, Services, and later policy and observability.

- The Cilium edition runs a large Go/C stack that stormcos doesn't own.
- flowsdn is the stormcos-owned replacement, built from Cilium v1.20.1's
  documented behaviour (`docs/spec/`, 24 specifications), so existing
  tooling and formats keep working.
- **Goal (owner, #321):** make flowsdn the *primary* network, when it matches
  or beats Cilium on the same machines.

---

## Where it sits in stormcos

From stormcentral's relationships (`stormcentral check`):

```
            stormcos (product: composes the flowsdn edition)
                │  depends on
                ▼
            flowsdn  ── network ──►  rustkube-node
           (agent + CNI)            (kubelet: runs the DaemonSet,
                │                    calls the CNI, kube API creds)
                ▼
   stormpump runtime (roots `image: flowsdn` on the golden) · Linux kernel ≥ 6.6 (TCX, BTF)
```

- **Depends on:** rustkube-node (kubelet, CNI calls), the stormcos kernel,
  stormpump (container runtime), the Kubernetes API (Kubernetes mode).
- **Depended on by:** stormcos's flowsdn edition, which ships flowsdn's
  manifests (`deploy/stormcos/manifests-kubernetes/`). Planned consumers:
  a stormconsole plugin (#297, stormconsole#83) and `sc net` (#298).

---

## How it works

```
 kubelet ──CNI ADD/DEL──► flowsdn-cni ──Unix socket API──► flowsdn-agent
                            │  veth pair, IPs,               │  IPAM, endpoint state,
                            │  routes in the pod netns       │  BPF maps, TCX links
                            ▼                                ▼
   pod netns ◄── veth ──► host veth ── TCX ingress: local-delivery (BPF)
                                         ├─ to a local pod: redirect to its veth
                                         └─ otherwise: FIB redirect, or the host stack (egress: stack)

   every process (host + pods) ── cgroup v2 ── socket-lb (BPF): ClusterIP:port → backend
   kube-apiserver ──watch──► agent (Kubernetes mode): Nodes, Pods, Services, EndpointSlices
                              → pod CIDR, routes to other nodes, socket-LB maps
```

Code: `crates/flowsdn-cni`, `crates/flowsdn-agent`, `crates/flowsdn-bpf`
(`local-delivery`, `socket-lb`), `crates/flowsdn-bpf-loader`, `crates/flowsdn-k8s`.

---

## What works today (1/2): pod networking

From the code, verified by tests in sc-build and namespace fixtures:

- **CNI plugin** (`flowsdn-cni`): ADD/DEL/CHECK for a primary veth plus
  loopback, Cilium-compatible CNI result. `flowsdn-cni install` copies the
  plugin into `/opt/cni/bin` and writes `/etc/cni/net.d/00-flowsdn.conflist`.
- **Agent** (`flowsdn-agent`): IPv4/IPv6 host-scope IPAM (`auto` pools from
  the Node), endpoint create/delete with persisted state, offline delete
  replay, endpoint IDs and health.
- **Datapath:** `local-delivery` on TCX ingress of each host veth; with a pin
  root, maps and links survive agent restarts.
- **Egress modes:** `fib` (BPF FIB redirect) or `stack` (every pod frame to
  the host stack, with a host route per pod).

---

## What works today (2/2): Kubernetes mode

`--features kubernetes` (GNU build, Fedora OpenSSL), the agent in the golden
since stormcos#171:

- Watches Nodes and all Pods (relist with backoff); pod CIDR from
  `spec.podCIDRs` or `10.<last byte of node IP>.0.0/16`.
- **Direct node routes** `<podCIDR> via <nodeIP> proto kernel` to every other
  node, with reachability and conflict checks, and pruning across restarts.
- **ClusterIP Services without kube-proxy** (#292): Service + EndpointSlice
  watches feed the `socket-lb` cgroup programs. TCP/UDP, IPv4/IPv6, UDP
  replies shown as from the ClusterIP. kube-dns and `kubernetes` covered.
- Forwarding sysctls; IP cache view with node identities and pod labels.

---

## Planned (not built yet)

Tracked by milestone issues; none of this is claimed to work:

- **Milestone 1 (#291):** cluster identity allocation; two-node acceptance on
  pvetest1 + pvetest2.
- **Milestone 2 (#292):** NodePort, LoadBalancer/externalIPs, session
  affinity, Maglev, DSR, NAT46/64, tc-level LB, socket termination;
  **NetworkPolicy enforcement** and host firewall.
- **Milestone 3 (#293):** remaining IPAM modes and operator controllers,
  WireGuard/IPsec, egress gateway, BGP, Hubble, DNS/L7/Envoy, Gateway/Ingress,
  ClusterMesh.
- **Milestone 4 (#294):** compatibility and release hardening: upgrades,
  both architectures at runtime, the full test matrix.
- **Operator and relay services** (#296); console plugin (#297); `sc net` (#298).

---

## Interfaces

- **Agent API:** HTTP over a Unix socket (`socket-path`, the manifests use
  `/var/run/cilium/cilium.sock`). `GET /v1/config`, `/v1/healthz`,
  `/v1/endpoint[/{id}[/healthz]]`, `PUT/DELETE /v1/endpoint/{attachment}`,
  `GET/POST /v1/ipam`, `DELETE /v1/ipam/{address}`, `/v1/health/modules`,
  `/v1/statedb/query`. Kubernetes mode adds `GET /v1/ip`, `/v1/node/routes`
  and `/v1/service`. Full contract: `docs/agent-api.md`.
- **CLI:** `flowsdn-agent --config PATH`, `flowsdn-agent cni install`,
  `flowsdn-cni install`.
- **Config** (JSON, `docs/runtime.md`): `socket-path`, `state-dir`,
  `ipv4-pool`/`ipv6-pool` (CIDR or `auto`), MTUs, `egress`, `bpf-pin-root`,
  `bpf-object`, `kubernetes{node-name, kubeconfig, auto-direct-node-routes,
  service-lb, cgroup-root}`.
- **Health:** `GET /v1/healthz` (with a `kubernetes` member). No TCP listener
  and no Prometheus metrics yet.

---

## How it ships and is operated

- **Golden:** `flowsdn` is a *special* component, built by stormcos's stage
  mode (`stormcentral component stage flowsdn`). It carries the GNU
  Kubernetes-mode agent with its Fedora OpenSSL runtime, the static musl
  CNI, and the agent's embedded BPF objects. Latest:
  **golden-flowsdn-a7ee3f63195b** (c6c96c7), release request stormcos#255.
- **Start:** a DaemonSet with `image: flowsdn` (stormpump roots it on the
  golden, nothing is pulled). An init container installs the CNI, then the
  agent runs privileged on the host network.
- **Update:** a new golden composed into a stormcos release; a source push
  alone changes no node. Restarts keep endpoints (state dir) and, with a
  pin root, forwarding.
- **Build/test:** `sc-build` on dev.g8.lo; `test/` image (`/test
  short|medium|long|perf`) run by `stormcentral test run flowsdn <suite>`.

---

## How we know: tests

- **sc-build:** rustfmt, Clippy `-D warnings`, 705 workspace tests (0 failed,
  1 ignored) at e397e16; agent `--features kubernetes` tests; the GNU agent
  build; `test/build.sh` refuses stale embedded BPF objects.
- **Kernel fixtures** (`crates/flowsdn-bpftest`, the medium suite): endpoint
  delivery, native routing, CNI/agent runtime, socket hooks, `socket-lb-live`.
- **perf suite** (#321): the same measurements on Cilium and flowsdn
  machines. Pod readiness, RR latency, throughput, ClusterIP, DNS, policy,
  scale, agent cost, compared in stormcentral (#412).

Not yet: a test-machine run of medium or perf (registries full,
stormcentral#376), or a two-node cluster run.

---

## Status and open issues that matter

| Issue | What | State |
|---|---|---|
| #291 | Milestone 1: working pod networking | agent built; two-node acceptance open |
| #292 | Milestone 2: services and policy | ClusterIP socket LB shipped in a golden; rest open |
| #321 | perf suite: flowsdn vs Cilium | suite built; runs blocked on test machines |
| #303 | test containers | built; machine runs blocked (stormcentral#376) |
| #296 | stormcos manifests, operator, relay | manifests shipped; operator/relay open |
| #256 | `__sk_buff` ctx matrix on the shipped kernel | waits on a test run |
| #315 | switch socket termination to `bpf_sock_destroy` | waits on aya |

**Next:** a medium/perf run on both flavors, two-node acceptance, then
NetworkPolicy and NodePort.
