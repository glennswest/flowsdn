# End-to-end connectivity suite and CI — specification

Status: draft. Derived from: `docs/inventory/15-helm-images-ci-tests.md` §F9–F11,
`docs/kernel-requirements.md` §5.3, `docs/decisions/0005-test-strategy.md`;
reference cilium v1.20.1 (7d68cfb394) paths `.github/workflows/**`,
`.github/actions/{e2e,cli-test-config,conn-disrupt-test-setup,conn-disrupt-test-check,
feature-status,kind-external-targets,generic-external-targets,nodes-without-cilium,
bpftrace,ipsec-key-rotate}/**`, `bugtool/cmd/configuration.go`,
`contrib/scripts/kind.sh`, `test/k8s/**`, `Documentation/operations/**`.
The connectivity suite itself is **not in that tree** — `cilium-cli` lives in its
own repository — so this spec is written from what the reference's CI *invokes*
and asserts, not from suite source. Governed by ADR-0001 (full feature scope,
boundary compatibility), ADR-0002 (Rust only), ADR-0003 (nftables residual, no
iptables), ADR-0005 (harvest data, all harnesses in Rust).

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* the suite does, the exact objects it creates, the exact assertions it
makes and the exact CI that runs it. Deviations from the reference's approach
are marked **DEVIATION** with the reason and the ADR.

**Amendments.** 2026-09-07 — §11 gap 9 (cloud-provider scenarios) narrowed for
**ADR-0007**: recorded-response cloud fakes close the gap for the cloud IPAM
control plane; end-to-end *datapath* testing on a cloud provider remains out of
scope and the gap is restated to say only that.

---

## 1. Scope

In scope:

- The **cluster-side topology** the suite builds: namespaces, workloads,
  services, external and DNS targets, and the reason each object exists (§3.1).
- The **connectivity matrix**: every source→destination pair, its expected
  result, and the flowsdn subsystem it proves (§3.2).
- **Feature-gated scenarios**: policy (L3/L4, L7 HTTP, L7 DNS, deny),
  encryption (WireGuard, IPsec) including on-the-wire proof, egress gateway,
  NodePort `externalTrafficPolicy`, session affinity, host firewall, BGP
  advertisement reachability, ClusterMesh (§3.3).
- **How each assertion is made**: in-pod traffic generation, in-cluster probe
  agents, packet capture, and — the part black-box suites cannot do — matching
  flowsdn's own Hubble flows by verdict, observation point and identity (§3.4).
- **Interoperability**: a mixed cluster of flowsdn nodes and upstream Cilium
  nodes, and exactly what that proves about the wire contract (§3.5).
- **Upgrade and downgrade** with live traffic, against the map-versioning and
  pin-replace protocol of `01-bpf-map-abi-loader.md` (§3.6).
- **Scale and performance smoke tests** and their regression gates (§3.7).
- **Failure diagnosis**: the sysdump equivalent, specified as a Rust subcommand
  (§3.8).
- **The binary**: subcommands, flags, output formats including JUnit XML, and
  feature-driven scenario selection (§3.9, §6).
- **The CI matrix**: kernels, architectures, cluster provisioning, PR gates
  versus nightly, expected runtimes (§10).
- The suite's own tests (§9) and its Rust design (§11).

Out of scope (owned by sibling specs; referenced, never duplicated):

- The txtar scripttest, `BPF_PROG_RUN` BPF unit tests, and control-plane golden
  tests — `17-scripttest-harness.md` (ADR-0005 §3). This spec covers only the fourth
  harness, `flowsdn-connectivity`.
- Map layouts, pin paths, the ABI version and the pin-replace protocol —
  `01-bpf-map-abi-loader.md`. §3.6 here consumes them, it does not define them.
- The wire formats (VXLAN/Geneve VNI, DSR options, `skb->mark`, IPsec SPI
  encoding) — `02-datapath-programs.md`. §3.5 here tests them.
- Flow schema, filter semantics, the Observer gRPC surface —
  `11-hubble-monitor.md`. §3.4 here consumes them.
- Helm values, images, DaemonSet shape — the packaging spec (wave 4).
- Kubernetes conformance and Gateway API conformance suites: those are upstream
  binaries flowsdn runs unchanged; they are CI jobs (§10.4), not scenarios here.

Non-goal: reproducing the reference's `cilium connectivity test` test *names*
one-for-one. flowsdn's scenario ids are its own (§4.4), and the mapping to
reference names is recorded in §4.5 and accepted as explicit --test aliases
(§5.2), so comparisons use canonical flowsdn scenario IDs in reports.

---

## 2. Compatibility contract

The suite is flowsdn's own code, so almost nothing here is a wire contract.
Four things are:

| Interface | What MUST match | Consumer |
|---|---|---|
| Hubble Observer gRPC (`hubble.Observer/GetFlows`, `ServerStatus`, `GetNodes`) on `/var/run/cilium/hubble.sock` and TCP `:4244`, relay `:4245` | The full `flow.proto` / `observer.proto` contract in `11-hubble-monitor.md` §4.15, including `GetFlowsRequest.follow = 3` | The suite is a **client** of the same API Hubble UI and the `hubble` CLI use; using it here is the load-bearing regression test for that API |
| Agent REST API `GET /healthz`, `GET /v1/healthz`, `GET /v1/status`, `GET /v1/endpoint`, `GET /v1/config` over `/var/run/cilium/health.sock` and `cilium.sock` | `08-endpoint-agent-api.md` | The suite's feature detection and readiness gate |
| `flowsdn-config` ConfigMap keys | Reference-compatible key names (`08`, `00` §6) | Feature detection (§5.1) reads the ConfigMap as its primary source |
| JUnit XML output | Ant/`surefire` JUnit schema as consumed by GitHub Actions test reporters and `mikepenz/action-junit-report` | CI dashboards; the reference emits the same shape from `--junit-file` |

Two interfaces are deliberately **not** compatible:

- **DEVIATION (ADR-0005).** The suite is not `cilium-cli`. Flags are flowsdn's
  own (§6), the test names are flowsdn's own, and the sysdump archive layout is
  flowsdn's own (§4.6). Anyone wanting to cross-check against upstream runs
  `cilium connectivity test` manually against a flowsdn cluster; that is
  supported (the agent API and Hubble API are compatible enough for it) but not
  a CI gate, because it would make a Go binary a build dependency.
- **DEVIATION (ADR-0003).** No assertion anywhere in the suite reads
  `iptables-save`. Where the reference's diagnostics dump six iptables variants,
  flowsdn dumps one nftables ruleset (`inet flowsdn`). Harvested scenarios that
  assert on iptables rules are marked expected-divergence per ADR-0005.

---

## 3. Behavior

### 3.1 Test topology

The suite creates everything it needs and deletes it on exit (unless
`--no-cleanup`). Nothing in the topology assumes a particular CNI configuration;
what varies with the detected feature set is which *scenarios* run (§5.2), not
which objects exist — with the four exceptions marked "conditional" below.

#### 3.1.1 Namespaces

| Namespace | Labels | Why it exists |
|---|---|---|
| `flowsdn-test` | `flowsdn.io/test=true`, `pod-security.kubernetes.io/enforce=privileged`, `pod-security.kubernetes.io/warn=privileged` | Primary namespace. Privileged PSA because host-network pods and pods needing `NET_RAW` (ICMP probes) live here. |
| `flowsdn-test-other` | `flowsdn.io/test=true`, `flowsdn.io/tier=other` | A **second** namespace with an identical `echo` deployment. Exists so that namespace-scoped policy (`CiliumNetworkPolicy` in one namespace) can be shown *not* to affect the other, and so `toEndpoints` with `k8s:io.kubernetes.pod.namespace` is exercised. Also proves identities are namespace-qualified (`03-identity-ipcache.md`). |
| `flowsdn-test-perf` | `flowsdn.io/test=true` | Conditional (`--perf`). Isolated so a perf run's pods do not perturb the functional matrix's flow counts. |

Every namespace name is prefixed by `--namespace-prefix` (default `flowsdn-test`)
so that concurrent runs against one cluster do not collide, and so a ClusterMesh
run can use a distinct prefix per cluster.

#### 3.1.2 Workloads

All workloads use one image, `flowsdn-testpod`, described in §4.1: a single
static Rust binary that is both a server (HTTP/1.1, TCP echo, UDP echo, a tiny
authoritative DNS responder) and a probe agent (§3.4.2). One image, two modes,
so that any pod can be a source or a sink and the matrix has no gaps.

| Workload | Kind / replicas | Placement | Labels | Why it exists |
|---|---|---|---|---|
| `client` | Deployment ×1 | pinned to node **A** by `nodeName` resolved at plan time | `kind=client`, `name=client`, `other=client` | The primary traffic source. `other=client` gives a second selector key so `matchExpressions` policies have something to match on. |
| `client2` | Deployment ×1 | node **A** (same as `client`, `podAffinity`) | `kind=client`, `name=client2`, `other=client` | A **different pod, same identity-relevant labels except `name`**. Needed to prove that a policy selecting `name=client` allows `client` and denies `client2` — i.e. that identity allocation is label-exact, not "any client". Also the same-node peer for pod↔pod-same-node. |
| `client3` | Deployment ×1 | node **B** (`podAntiAffinity` to `client`) | `kind=client`, `name=client3` | The cross-node source. Every same-node row in §3.2 has a `client3` twin so that same-node and cross-node paths are exercised by identical probes. |
| `echo-same-node` | Deployment ×2 | node **A** (`podAffinity` to `client`) | `kind=echo`, `name=echo-same-node` | Same-node destination. Two replicas so a ClusterIP over it can show load spreading and so session affinity has something to be affine *to*. |
| `echo-other-node` | Deployment ×2 | node **B** | `kind=echo`, `name=echo-other-node` | Cross-node destination. |
| `echo-other-ns` | Deployment ×1 in `flowsdn-test-other` | node **B** | `kind=echo`, `name=echo-other-ns` | Cross-namespace destination. |
| `host-netns` | DaemonSet, `hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet` | every flowsdn-managed node | `kind=host-netns` | Represents the **host identity (1)**. Source for host→pod, sink for pod→host. A DaemonSet rather than a Deployment so that "the host on *this* node" and "the host on the *other* node" (remote-node identity, 6) are both addressable. |
| `host-netns-non-flowsdn` | DaemonSet, `hostNetwork: true` | conditional: nodes carrying the `flowsdn.io/no-agent` label or the `node.flowsdn.io/agent-not-ready` taint that CI leaves in place | `kind=host-netns-non-flowsdn` | Represents **`reserved:world` (2)** from inside the cluster network. This is how "world→NodePort" and "pod→world" are tested deterministically without depending on internet reachability. |
| `perf-client` / `perf-server` | Deployment ×1 each, `flowsdn-test-perf` | nodes A and B | `kind=perf` | Conditional (`--perf`). §3.7. |
| `interop-echo` | Deployment ×1 | pinned to an **upstream-Cilium** node | `kind=echo`, `name=interop-echo` | Conditional (`--interop`). §3.5. |

Placement is by resolved `nodeName`, not by affinity alone. The suite lists
nodes at plan time, picks A and B deterministically (sorted by name, first two
schedulable flowsdn-managed nodes), and writes `spec.nodeName` into the pod
template. Reason: `podAffinity` is a scheduler *hint* under pressure and a
failure to co-locate turns a same-node test into a silently-passing cross-node
test — the worst kind of false green. Affinity terms are still emitted as
documentation and as a second line of defence.

Every pod carries `terminationGracePeriodSeconds: 1`, no readiness gate other
than its own HTTP `/healthz`, and `automountServiceAccountToken: false` except
for the pods used in the `kube-apiserver` reachability rows.

#### 3.1.3 Services

| Service | Type | Backend | Why it exists |
|---|---|---|---|
| `echo-same-node` | ClusterIP | `name=echo-same-node` | The east-west base case. Ports: `http` 8080/TCP, `http-2` 8081/TCP (a **named second port** so named-port policy has a target), `udp` 8080/UDP, `tftp` 69/UDP. |
| `echo-other-node` | ClusterIP | `name=echo-other-node` | Cross-node ClusterIP: forces the LB translation *and* the overlay/native routing path in one probe. |
| `echo-headless` | ClusterIP `None` | `name=echo-other-node` | Headless: DNS returns backend pod IPs, no LB translation. Proves the DNS path and pod-IP reachability are independent of the LB path — when `echo-other-node` fails but `echo-headless` succeeds, the fault is in the service maps, not the datapath. |
| `echo-nodeport-cluster` | NodePort, `externalTrafficPolicy: Cluster` | `name=echo-other-node` | NodePort with cluster-wide backend selection; forces SNAT-or-DSR on the second hop. |
| `echo-nodeport-local` | NodePort, `externalTrafficPolicy: Local` | `name=echo-other-node` | ETP=Local: MUST preserve the client source IP and MUST NOT forward to a node without a local backend. Both halves are asserted (§3.3.6). Carries `healthCheckNodePort` (allocated by the API server), asserted against the agent's `/healthz` server (`05-service-loadbalancing.md` §3.7). |
| `echo-affinity` | ClusterIP, `sessionAffinity: ClientIP`, `timeoutSeconds: 30` | `name=echo-same-node` (2 replicas) | Session affinity: N sequential requests from one client must all land on one backend (§3.3.7). |
| `echo-lb` | LoadBalancer | `name=echo-other-node` | Conditional on LB-IPAM being enabled (`CiliumLoadBalancerIPPool` present, `12-operator.md`). Asserts an ingress IP is assigned, that it is advertised (§3.3.8 when BGP or L2 announcements are on), and that it is reachable from `host-netns-non-flowsdn`. |
| `echo-dual` | ClusterIP, `ipFamilyPolicy: RequireDualStack` | `name=echo-other-node` | Conditional on dual-stack. Gives a single frontend with both an IPv4 and an IPv6 ClusterIP so the two families' maps are exercised against one backend set. |
| `echo-other-ns` | ClusterIP in `flowsdn-test-other` | `name=echo-other-ns` | Cross-namespace service resolution (`svc.ns.svc.cluster.local`). |
| `echo-interop` | ClusterIP | `name=interop-echo` | Conditional (`--interop`). §3.5. |

`echo-lb`, `echo-dual`, `echo-nodeport-local`'s `healthCheckNodePort` assertion,
and `echo-interop` are the four conditional objects; everything else is created
unconditionally so that a failure to *create* an object is itself a test result
rather than a silent skip.

#### 3.1.4 External and DNS targets

The reference points at `bing.com.` and `8.8.4.4`. That makes CI depend on the
public internet, and it makes a DNS-policy test depend on somebody else's TTLs.

**DEVIATION.** flowsdn's default external target is **in-cluster but outside the
flowsdn datapath**: the `host-netns-non-flowsdn` DaemonSet on a node with no
agent. Its pod IPs are the node IPs, which sit outside `cluster-pool-ipv4-cidr`
and therefore carry `reserved:world` identity, which is exactly the property a
"pod to world" test needs. Concretely:

| Target | Default | Override |
|---|---|---|
| External IPv4 | first `host-netns-non-flowsdn` pod IP | `--external-ip` |
| External IPv6 | that pod's IPv6 | `--external-ipv6` |
| Second external IPv4/IPv6 | second such pod | `--external-other-ip`, `--external-other-ipv6` |
| External CIDR | the node subnet containing them, widened to a /8 in kind (`8.0.0.0/8` equivalent) | `--external-cidr`, `--external-cidrv6` |
| External DNS name | `external.flowsdn.test`, served by a `CoreDNS` `hosts` stanza the suite patches in, or by a `flowsdn-testpod` in DNS mode registered as the cluster's stub domain for `flowsdn.test` | `--external-target` |
| Second external DNS name | `external-other.flowsdn.test` | `--external-other-target` |
| Cluster DNS | the `kube-dns` Service ClusterIP, discovered from the cluster | `--dns-service` |

When a cluster has **no** agent-free node (a plain 2-node kind cluster with
flowsdn everywhere), the suite falls back to a real internet target and marks
every world row `degraded: external target is off-cluster`, which is reported in
the JUnit output as a property, not as a skip. CI always provisions the
agent-free node (§10.3) so the fallback is never taken in a gating job.

The DNS-name target exists separately from the IP target because `toFQDNs`
policy and the DNS proxy are only exercised when the client resolves a *name*
(`16-l7-envoy-dns.md` §3.9): a probe to a literal IP proves nothing about DNS.

#### 3.1.5 Policy objects

Policies are applied and removed **per scenario**, never left behind, and each
application is followed by a barrier (§5.4) that waits for every agent to report
the new policy revision — not a sleep. The policy objects, all created in
`flowsdn-test` unless noted:

| Object | Kind | Used by |
|---|---|---|
| `allow-all-ingress` / `allow-all-egress` | `CiliumNetworkPolicy` | baseline that a permissive policy does not change any verdict |
| `client-egress-to-echo` | `CiliumNetworkPolicy` | L3/L4 allow, and the `client2` deny half |
| `client-egress-to-echo-knp` | `NetworkPolicy` (upstream KNP) | the same shape through the Kubernetes API, proving KNP→flowsdn translation |
| `client-egress-to-echo-expression` | `CiliumNetworkPolicy` with `matchExpressions` | selector expression handling |
| `echo-ingress-l7-http` | `CiliumNetworkPolicy` with `toPorts[].rules.http` | L7 HTTP allow/deny (§3.3.3) |
| `client-egress-l7-dns` | `CiliumNetworkPolicy` with `toPorts[].rules.dns.matchPattern` + `toFQDNs` | DNS proxy and FQDN policy (§3.3.4) |
| `client-egress-to-cidr-deny` | `CiliumNetworkPolicy` with `egressDeny.toCIDRSet` | deny precedence over allow |
| `all-ingress-deny` / `all-egress-deny` | `CiliumNetworkPolicy` with an empty allow list | default-deny |
| `host-fw-ingress` / `host-fw-egress` | `CiliumClusterwideNetworkPolicy` with `nodeSelector` | host firewall (§3.3.9) |
| `to-entities-world`, `host-entity-egress`, `cluster-entity` | `CiliumNetworkPolicy` with `toEntities` | reserved-identity semantics (`world`, `host`, `remote-node`, `cluster`, `kube-apiserver`) |
| `client-egress-to-egressgw` | `CiliumEgressGatewayPolicy` (cluster-scoped) | egress gateway (§3.3.5) |

Every policy carries the label `flowsdn.io/test-scenario=<id>` so that the
sysdump collector can attribute a leaked policy to the scenario that leaked it,
and so a `--no-cleanup` debug run can be untangled by hand.

#### 3.1.6 Topology diagram (logical)

```
                node A (flowsdn)                node B (flowsdn)         node C (no agent)
 ns flowsdn-test  ┌──────────────┐              ┌──────────────┐         ┌──────────────┐
   client ────────┤ client       │              │ client3      │         │ host-netns-  │
   client2 ───────┤ client2      │              │ echo-other-  │         │ non-flowsdn  │
                  │ echo-same-   │              │   node ×2    │         │ (world, and  │
                  │   node ×2    │              │              │         │  external    │
                  │ host-netns   │              │ host-netns   │         │  target)     │
                  └──────────────┘              └──────────────┘         └──────────────┘
 ns flowsdn-test-other                          echo-other-ns
 services: echo-same-node(CIP)  echo-other-node(CIP)  echo-headless(None)
           echo-nodeport-cluster(NP/Cluster)  echo-nodeport-local(NP/Local)
           echo-affinity(CIP+affinity)  echo-lb(LB)  echo-dual(CIP dual)
```

### 3.2 The connectivity matrix

Each row is a **scenario**: a source, a destination, a protocol, an expected
result, and — where flowsdn can do better than a black-box probe — one or more
Hubble flow assertions (§3.4.3). `ok` means every probe attempt succeeds within
the per-probe timeout; `deny` means every attempt fails *in the specific way*
named (a policy drop is not the same as a connection refused, and the suite
MUST distinguish them — see §5.5).

Column `proves` names the flowsdn subsystem whose failure the row would catch
first. Column `v6` is `y` when the row is duplicated for IPv6 with the same
expectation (run only when `--ipv6` or dual-stack is detected).

#### 3.2.1 Pod to pod

| ID | Source | Destination | L4 | Expect | Proves | v6 |
|---|---|---|---|---|---|---|
| `pod-to-pod-same-node` | `client` | `echo-same-node` pod IP | TCP 8080 | ok | veth/netkit attach, `from-container`→`to-container`, `redirect_peer` (or netkit direct delivery), local CT | y |
| `pod-to-pod-same-node-udp` | `client` | same | UDP 8080 | ok | UDP CT `cilium_ct_any4_global`, no TCP-only shortcuts | y |
| `pod-to-pod-same-node-icmp` | `client` | same | ICMP echo | ok | ICMP CT tuple handling, `NET_RAW` path | y |
| `pod-to-pod-cross-node` | `client` | `echo-other-node` pod IP | TCP 8080 | ok | ipcache remote-endpoint lookup, tunnel encap (`to-overlay`/`from-overlay`) **or** native routing + `fib_lookup`, identity carried in the VNI/mark | y |
| `pod-to-pod-cross-node-udp` | `client` | same | UDP 8080 | ok | as above for UDP; MTU handling under encap | y |
| `pod-to-pod-cross-ns` | `client` | `echo-other-ns` pod IP | TCP 8080 | ok | namespace-qualified identity allocation | y |
| `pod-to-self` | `client` | its own pod IP | TCP 8080 | ok | loopback shortcut; must not enter the datapath twice | y |
| `pod-to-pod-large` | `client` | `echo-other-node` pod IP | TCP 8080, 4 MiB body | ok | MTU/GSO/fragmentation under encap; catches the classic "small requests work, large ones hang" encap MTU bug | y |

#### 3.2.2 Pod to service

| ID | Source | Destination | L4 | Expect | Proves | v6 |
|---|---|---|---|---|---|---|
| `pod-to-clusterip-local-backend` | `client` | `echo-same-node` ClusterIP | TCP 8080 | ok | socket LB `connect4` rewrite (when `socketLB` on) or per-packet LB in `from-container`; `cilium_lb4_services_v2` + `_backends_v3` | y |
| `pod-to-clusterip-remote-backend` | `client` | `echo-other-node` ClusterIP | TCP 8080 | ok | LB translation *then* cross-node delivery; reverse-NAT on the return (`cilium_lb4_reverse_nat`) | y |
| `pod-to-clusterip-udp` | `client` | `echo-other-node` ClusterIP | UDP 8080 | ok | UDP service translation, `sendmsg4`/`recvmsg4` when socket LB is on | y |
| `pod-to-own-service` | `echo-same-node` pod | `echo-same-node` ClusterIP | TCP 8080 | ok | **hairpin**: a backend reaching its own service and being LB'd to itself. Exercises loopback SNAT and the `cilium_skip_lb4` / hostport-loopback logic. Historically the single most common regression in this area. | y |
| `pod-to-headless` | `client` | `echo-headless` A/AAAA records → pod IPs | TCP 8080 | ok | DNS returns pod IPs; no LB entry exists; isolates DNS from LB | y |
| `pod-to-nodeport-own-node` | `client` | node A IP : `echo-nodeport-cluster` nodePort | TCP | ok | NodePort frontend on the local node with a **remote** backend; SNAT or DSR on the second hop | y |
| `pod-to-nodeport-remote-node` | `client` | node B IP : nodePort | TCP | ok | NodePort frontend on a remote node reached from a pod; double translation | y |
| `pod-to-loadbalancer` | `client` | `echo-lb` ingress IP | TCP | ok (cond.) | LB-IPAM assignment, LB frontend maps, and — with BGP or L2 announcement on — that the VIP is locally answered | y |
| `pod-to-affinity-service` | `client` | `echo-affinity` ClusterIP ×10 | TCP | ok, one backend | `cilium_lb4_affinity` + `cilium_lb_affinity_match` | y |
| `pod-to-multiport-named` | `client` | `echo-other-node` ClusterIP port `http-2` | TCP 8081 | ok | named-port resolution end to end | y |
| `pod-to-dual-service` | `client` | `echo-dual` v4 and v6 ClusterIPs | TCP | ok (cond.) | one Service, two families, one backend set | — |

#### 3.2.3 Pod, host and node

| ID | Source | Destination | L4 | Expect | Proves | v6 |
|---|---|---|---|---|---|---|
| `pod-to-host-local` | `client` | node A IP (its own node) | TCP 8080 on `host-netns` | ok | `to-host`, host identity (1), `cilium_host`/`cilium_net` path | y |
| `pod-to-host-remote` | `client` | node B IP | TCP 8080 | ok | remote-node identity (6), and that remote-node is not confused with world | y |
| `host-to-pod-local` | `host-netns` on A | `echo-same-node` pod IP | TCP 8080 | ok | `from-host` → local endpoint; host→pod policy path | y |
| `host-to-pod-remote` | `host-netns` on A | `echo-other-node` pod IP | TCP 8080 | ok | host-sourced traffic across the tunnel or native route; source identity is host, not the pod CIDR | y |
| `host-to-clusterip` | `host-netns` on A | `echo-other-node` ClusterIP | TCP 8080 | ok | socket LB in the **host** cgroup (or the host NodePort path when `socketLB.hostNamespaceOnly` is set — the row's expectation is the same either way, the Hubble assertion differs) | y |
| `pod-to-controlplane-host` | `client` | control-plane node IP : 6443 | ok | the control plane is a node like any other; catches "everything works except the API server node" | y |
| `pod-to-kube-apiserver` | `client` | `kubernetes.default.svc` ClusterIP : 443 | ok | the `kube-apiserver` reserved identity and its ipcache entry | y |
| `pod-to-health` | suite (via agent API) | every node's health endpoint 4240 | ok | `flowsdn-health` connectivity mesh; a cheap all-pairs check that also seeds the ipcache | y |

#### 3.2.4 World, DNS and north-south

| ID | Source | Destination | L4 | Expect | Proves | v6 |
|---|---|---|---|---|---|---|
| `pod-to-world-ip` | `client` | external IP (§3.1.4) | TCP 8080 | ok | egress masquerade (`enable-bpf-masquerade`, `cilium_snat_v4_external`), `reserved:world` identity, and that the return path finds the CT entry | y |
| `pod-to-world-cidr` | `client` | second external IP | TCP 8080 | ok | a second world destination so a `toCIDR` policy can allow one and deny the other | y |
| `pod-to-world-icmp` | `client` | external IP | ICMP | ok | ICMP masquerade, which uses a different NAT key than TCP/UDP | y |
| `pod-to-world-dns-name` | `client` | `external.flowsdn.test` → external IP | TCP 8080 | ok | full path: DNS query → cluster DNS → answer → connect. The prerequisite for every FQDN-policy row. | y |
| `pod-to-dns-service` | `client` | `kube-dns` ClusterIP : 53 | UDP + TCP | ok | UDP service translation on port 53 specifically (the port the DNS proxy may be intercepting) | y |
| `pod-to-dns-external` | `client` | external resolver : 53 | UDP | ok | egress DNS not via the cluster service | y |
| `world-to-nodeport-cluster` | `host-netns-non-flowsdn` | node A IP : `echo-nodeport-cluster` nodePort | TCP | ok | north-south ingress into the cluster; `from-netdev` NodePort, SNAT/DSR, and the reply path back out | y |
| `world-to-nodeport-cluster-remote` | `host-netns-non-flowsdn` | node A IP, backend on node B | TCP | ok | the **second hop**: this is the row that DSR and Hybrid modes exist for; §3.3.6 adds the source-IP assertions | y |
| `world-to-loadbalancer` | `host-netns-non-flowsdn` | `echo-lb` ingress IP | TCP | ok (cond.) | the LB VIP is reachable from outside | y |
| `world-to-pod` | `host-netns-non-flowsdn` | `echo-other-node` pod IP | TCP 8080 | **deny** by default (no route) / ok when pod CIDRs are routed | reachability policy is not accidentally open; the expectation is derived from the detected routing mode, not hard-coded | y |

#### 3.2.5 Negative baseline rows

Three rows exist only to catch a suite that is passing for the wrong reason:

| ID | What | Expect |
|---|---|---|
| `probe-sanity-closed-port` | `client` → `echo-same-node` pod IP : 9999 (nothing listening) | TCP RST / connection refused. If this "succeeds", the probe agent is lying and every other row is meaningless. |
| `probe-sanity-blackhole` | `client` → `192.0.2.1:8080` (TEST-NET-1, unrouted) | timeout, **not** refused. Distinguishes "dropped" from "rejected", which §5.5 depends on. |
| `no-unexpected-drops` | Hubble query across the whole run | zero `DROPPED` flows whose `drop_reason` is not on the per-scenario expected list (§3.4.4) |

#### 3.2.6 IPv6

Every row marked `v6` is instantiated twice with the same id plus a `-v6`
suffix. There is no separate IPv6 matrix. Rows are selected as follows: IPv4
rows run when `enable-ipv4` is true, IPv6 rows when `enable-ipv6` is true, and
in an IPv6-only cluster the IPv4 rows are **skipped with a reason**, never
silently omitted (§4.4).

Two IPv6-specific rows have no IPv4 twin:

| ID | What | Proves |
|---|---|---|
| `pod-to-pod-v6-ndp` | `client` → `echo-same-node` v6 pod IP, forcing a fresh neighbour resolution | the in-BPF NDP responder (`ipv6_ndp`) |
| `pod-to-world-v6-ext-header` | `client` → external v6 IP with a hop-by-hop extension header | extension-header walking in the parser, which is where the IPv6 path most often breaks |

### 3.3 Feature-gated scenarios

A scenario in this section runs only when feature detection (§5.1) says the
cluster has the feature enabled. A scenario whose feature is off is reported
`skipped` with the feature name and the ConfigMap key that turned it off; it is
never reported `passed`. **A CI job that expected a feature and got a skip fails
the job** (`--require-feature`, §6).

#### 3.3.1 Policy: L3/L4 allow and deny

| ID | Policy applied | Probe | Expect | Hubble assertion |
|---|---|---|---|---|
| `policy-l3l4-allow` | `client-egress-to-echo` (allow `client`→`echo` TCP 8080) | `client`→`echo-same-node` :8080 | ok | a `FORWARDED` policy-verdict flow at `FROM_ENDPOINT` on the client's node with `egress_allowed_by` naming the CNP |
| `policy-l3l4-allow-other-denied` | same policy | `client2`→`echo-same-node` :8080 | deny | a `DROPPED` flow, `drop_reason = 133 (POLICY_DENIED)`, `event_type {5,·}`, source identity = `client2`'s |
| `policy-l3l4-wrong-port` | same policy | `client`→`echo-same-node` :8081 | deny | `DROPPED`, policy denied, `destination_port = 8081` |
| `policy-l3l4-knp` | `client-egress-to-echo-knp` (`NetworkPolicy`) | same pair | ok / deny as above | identical assertions, proving KNP and CNP compile to the same map state |
| `policy-l3l4-expression` | `client-egress-to-echo-expression` | `client`→`echo` | ok | selector expressions produce the same identity set |
| `policy-ingress-default-deny` | `all-ingress-deny` on `echo` | every source→`echo` | deny | every drop is `POLICY_DENIED` at `TO_ENDPOINT`, i.e. **ingress** enforcement, not egress |
| `policy-egress-default-deny` | `all-egress-deny` on `client` | `client`→everything, **including DNS** | deny | drops at `FROM_ENDPOINT`; the DNS failure is asserted explicitly, because a default-deny that still permits DNS is a real and easy bug |
| `policy-deny-beats-allow` | `client-egress-to-echo` **and** `client-egress-to-cidr-deny` covering the echo IP | `client`→`echo` | deny | deny rules take precedence regardless of order of application |
| `policy-entity-world` | `to-entities-world` | `client`→external IP ok, `client`→`echo` deny | reserved-identity semantics |
| `policy-entity-host` | `host-entity-egress` | `client`→node IP ok, `client`→`echo` deny | host (1) vs remote-node (6) distinction |
| `policy-entity-cluster` | `cluster-entity` | `client`→any in-cluster ok, →world deny | the `cluster` entity's identity set |
| `policy-audit` | any deny policy with `policy-audit-mode` on the endpoint | `client2`→`echo` | **ok** (traffic passes) | an `AUDIT` verdict flow exists — the whole point of audit mode is that the flow says "would have dropped" while the packet goes through |

Each policy scenario is run twice: once same-node and once cross-node, because
ingress policy on a remote endpoint is enforced on the *destination* node and
egress on the *source* node, and a bug that only affects the remote direction is
invisible in a same-node-only run.

#### 3.3.2 Policy churn under load

`policy-churn-no-drop`: with a long-lived connection open from `client` to
`echo-other-node`, apply and remove `allow-all-egress` 50 times at 200 ms
intervals. Expect: zero interruption in the long-lived connection and zero
`DROPPED` flows for that 5-tuple. This is the scenario that catches a policy map
update that briefly empties the map — a bug class that no steady-state test
sees. Gated on `--include-unsafe-tests` because it is deliberately abusive.

#### 3.3.3 L7 HTTP policy

Requires the L7 proxy (`16-l7-envoy-dns.md`): `enable-l7-proxy` true and an
Envoy DaemonSet present.

| ID | Policy | Probe | Expect |
|---|---|---|---|
| `l7-http-allow-path` | `echo-ingress-l7-http` allowing `GET /public` | `GET /public` | 200 |
| `l7-http-deny-path` | same | `GET /private` | **403 from the proxy**, not a connection failure. Asserted on the *status code*, because a TCP-level drop here means the redirect never happened and the test would otherwise pass for the wrong reason. |
| `l7-http-deny-method` | policy allowing `GET` only | `POST /public` | 403 |
| `l7-http-header` | policy requiring header `X-Test: yes` | with and without the header | 200 / 403 |
| `l7-http-named-port` | policy on port name `http-2` | `:8081/public` | 200 |
| `l7-http-flow` | any of the above | — | Hubble carries an **L7 flow** (`event_type {129,0}`, `l7.http` populated with method, url and `http_status_code`) for both the allowed and the denied request, and the denied one has verdict `DROPPED` at the proxy |
| `l7-http-redirect-point` | allowed request | — | a `REDIRECTED` policy-verdict flow with a non-zero proxy port, then `TO_PROXY` / `FROM_PROXY` trace points. This is the assertion that proves the datapath actually punted to the proxy rather than the proxy being bypassed. |

#### 3.3.4 L7 DNS policy and FQDN

| ID | Policy | Probe | Expect |
|---|---|---|---|
| `l7-dns-allow-pattern` | `client-egress-l7-dns` with `matchPattern: "*.flowsdn.test"` | resolve `external.flowsdn.test` | answer returned |
| `l7-dns-deny-pattern` | same | resolve `blocked.example.com` | **REFUSED or empty answer from the proxy**, and a `DROPPED` L7 DNS flow — not a timeout. A timeout here means the proxy crashed. |
| `fqdn-allow` | `toFQDNs: [{matchName: external.flowsdn.test}]` under egress default-deny | resolve then connect | ok |
| `fqdn-allow-then-expire` | same, with a short TTL | connect, wait past TTL + `tofqdns-min-ttl`, connect again | ok both times (the selector must be refreshed, not dropped) |
| `fqdn-deny-unresolved` | same policy | connect to the external IP **directly**, without resolving | deny — proves the FQDN allow is bound to the DNS answer, not to the address being generally reachable |
| `l7-dns-ordering` | any FQDN policy | resolve, then connect **immediately** (no delay) | ok. This is the response-hold ordering contract (`16-l7-envoy-dns.md` §3.9): the proxy MUST NOT release the DNS answer to the client before the ipcache and policy maps have the resulting identity. A race here shows up as a flaky first-connection failure, and this scenario runs the resolve/connect pair 20 times to expose it. |

#### 3.3.5 Egress gateway

Requires `enable-ipv4-egress-gateway` (and/or v6) and a node designated as the
gateway. The suite applies a `CiliumEgressGatewayPolicy` selecting `client`,
destination = the external CIDR, gateway = node B, `egressIP` = node B's IP (or
an `interface`).

| ID | Probe | Expect |
|---|---|---|
| `egressgw-source-ip` | `client` (on node A) → external target's `/whoami`, which echoes the observed source IP | the observed source IP is **node B's egress IP**, not node A's. This is the whole test; anything weaker (just "it connects") passes with the policy doing nothing. |
| `egressgw-non-selected-pod` | `client3` (not selected) → same target | observed source IP is `client3`'s own node's IP |
| `egressgw-excluded-cidr` | `client` → an IP inside `excludedCIDRs` | observed source IP is node A's — the exclusion took effect |
| `egressgw-conn-persist` | long-lived connection open **before** the policy is applied | the existing connection survives the policy application (CT entries are not rewritten mid-flow) |
| `egressgw-gateway-failover` | with HA configured, drain the active gateway | new connections use the surviving gateway within the configured interval; existing ones may break and that is recorded, not asserted as success |
| `egressgw-with-l7` | egress gateway **and** an L7 policy on the same pod | source IP is still the gateway's; proves the proxy return path does not bypass the egress redirect |

The `/whoami` endpoint on `flowsdn-testpod` returns the peer address it observed
as JSON. That single endpoint is what makes every SNAT-shaped assertion in this
spec (egress gateway, masquerade, ETP=Local, DSR) a *positive* assertion about
an address rather than a guess.

#### 3.3.6 NodePort: `externalTrafficPolicy` Local and Cluster

| ID | Probe | Expect |
|---|---|---|
| `nodeport-etp-cluster-source-ip` | `host-netns-non-flowsdn` → node A : `echo-nodeport-cluster`, backend on node B | connection ok; observed source IP is **node A's** (SNAT) in SNAT mode, or the **original client IP** in DSR/Hybrid mode. The expectation is computed from the detected `bpf-lb-mode`, and the mismatch message names both the detected mode and the observed address. |
| `nodeport-etp-local-source-ip` | `host-netns-non-flowsdn` → node **B** : `echo-nodeport-local` (has a local backend) | ok, and observed source IP is the **original client IP**, in every LB mode. ETP=Local's contract is source-IP preservation. |
| `nodeport-etp-local-no-backend` | same client → node **A** : `echo-nodeport-local` (no local backend) | **deny**: connection refused/timeout. A node with no local backend must not forward. Asserting only the positive half of ETP=Local is the classic gap. |
| `nodeport-etp-local-healthcheck` | HTTP to node A and node B `:healthCheckNodePort` | node B returns 200 with `localEndpoints > 0`; node A returns 503 with `localEndpoints == 0` |
| `nodeport-hostport` | a pod with `hostPort: 18080` | reachable at node IP :18080 from `host-netns-non-flowsdn`; gated on `enable-host-port` |
| `nodeport-dsr-fragmented` | a UDP payload larger than the MTU through the NodePort | ok; DSR + fragmentation is a known-hard combination and the row exists to keep it honest. Gated on `--include-unsafe-tests`. |

#### 3.3.7 Session affinity

`affinity-sticky`: 20 sequential HTTP requests from `client` to `echo-affinity`
(2 backends). Expect: all 20 report the same backend pod name (the testpod's
`/whoami` includes its own pod name). Then wait past the affinity timeout plus
5 s and issue 20 more; expect the set of observed backends across the two bursts
to be allowed to differ (no assertion), but each burst internally consistent.

`affinity-per-client`: `client` and `client3` each issue 20 requests. Expect each
is internally consistent; no assertion that they differ (with two backends they
may legitimately hash to the same one), but the run records which, so a change
from "different" to "same" across releases is visible in the report.

`affinity-socket-lb`: when socket LB is enabled, the same probe from
`host-netns` — because affinity in the socket-LB path uses a different key
(netns cookie) than the per-packet path (source IP).

#### 3.3.8 Encryption: WireGuard and IPsec

Requires `enable-wireguard` or `enable-ipsec`. The functional half is trivial
(pod-to-pod still works); the load-bearing half is proving the bytes on the wire
are actually ciphertext. Three independent assertions, run together, because
each alone has a known blind spot:

**A. Negative capture on the physical device.** For the duration of a
pod-to-pod cross-node probe carrying a unique 32-byte magic cookie in its
payload, capture on node A's egress device (`--devices`) inside the host netns
and assert the cookie **never appears in the clear**. Implementation: an
AF_PACKET socket with an attached classic-BPF filter, opened from a privileged
pod on each node (§3.4.4), not `tcpdump`. Absence-of-plaintext is the assertion
that actually means "encrypted"; "an ESP packet was seen" does not, because a
leak alongside the tunnel still leaks.

**B. Positive protocol assertion.** On the same capture, assert that packets
between the two node IPs during the probe window are UDP/51871 (WireGuard) or
IP protocol 50 / ESP (IPsec), and that their count is greater than zero. Rules
out "nothing was sent at all" passing test A.

**C. Hubble/agent state assertion.** `flowsdn-dbg encrypt status` on both nodes
reports the expected mode; for WireGuard, the peer list contains the other node
and its `rx_bytes`/`tx_bytes` increased across the probe; for IPsec, the XFRM
state count is non-zero and `/proc/net/xfrm_stat` counters for errors
(`XfrmInNoStates`, `XfrmOutNoStates`, `XfrmInStateProtoError`) did **not**
increase beyond an allowlist (`--expected-xfrm-errors`, default
`+inbound_no_state` only during the first seconds after a key rotation, matching
the reference's tolerance).

| ID | What | Gate |
|---|---|---|
| `encryption-pod-to-pod` | A + B + C on a cross-node pod-to-pod probe | wireguard \| ipsec |
| `encryption-pod-to-pod-l7` | same, with an L7 policy in the path | + l7 proxy. Catches the proxy return path leaking in the clear — the exact case the reference's bpftrace script was written for. |
| `encryption-node-to-node` | A + B on a `host-netns`→`host-netns` probe | + `encryption.nodeEncryption` |
| `encryption-strict-drop` | with strict mode on, remove the peer's ipcache entry (or target an address outside the strict CIDR) | traffic is **dropped** with `drop_reason = 195 (DROP_UNENCRYPTED_TRAFFIC)` — asserted in Hubble. Gated on `--include-unsafe-tests`. |
| `encryption-key-rotate` | rotate the IPsec key mid-run with a long-lived connection open | the connection survives; XFRM error counters stay inside the allowlist | ipsec |
| `encryption-overlay` | encryption **and** tunnel mode together | A + B, plus the assertion that the VXLAN/Geneve header is itself inside the ESP/WireGuard payload (the cookie test covers this: the VNI is part of the cleartext we must not see) |

**DEVIATION.** The reference asserts leaks with a `bpftrace` script attached to
`__dev_queue_xmit` and `br_forward` kprobes. flowsdn does not ship bpftrace.
The equivalent kprobe-based check is available as an *optional* deeper mode
(`--leak-check=kprobe`) implemented as a small aya `kprobe` program on
`__dev_queue_xmit` that reports matching skbs on a perf ring — same technique,
Rust, no external tool. The default (`--leak-check=capture`) is the AF_PACKET
form above, which needs no BPF privileges beyond `CAP_NET_RAW` and works on any
kernel in the matrix.

#### 3.3.9 Host firewall

Requires `enable-host-firewall`.

| ID | Policy | Probe | Expect |
|---|---|---|---|
| `hostfw-ingress-allow` | `CCNP` with `nodeSelector`, ingress allow from the `client` identity on 8080 | `client`→node A `host-netns` :8080 | ok |
| `hostfw-ingress-deny` | same policy | `client2`→node A :8080 | deny, `POLICY_DENIED`, and the Hubble flow's **destination identity is `host` (1)** — proving it was the host endpoint's policy that dropped it |
| `hostfw-egress-allow` | egress allow from host to the echo identity | `host-netns`→`echo-same-node` | ok |
| `hostfw-egress-deny` | same | `host-netns`→external IP | deny |
| `hostfw-does-not-break-kubelet` | any host policy applied | node stays `Ready`, agent stays healthy, control-plane reachability rows still pass | this is the row that catches a host firewall that locks the operator out of the cluster; it runs before any deny-shaped host policy and again after |

#### 3.3.10 BGP advertisement reachability

Requires `enable-bgp-control-plane` and a peer. In CI the peer is a
containerised BGP speaker on the kind network (the suite does not require a
router); on the Rose cluster it is the real RouterOS device (`15-bgp.md` §3.9
`Advertiser` trait, RouterOS backend).

| ID | What | Expect |
|---|---|---|
| `bgp-session-established` | `flowsdn-dbg shell -- bgp/peers` on every node with a `CiliumBGPNodeConfig` | session state `ESTABLISHED` within the configured hold time |
| `bgp-advertise-podcidr` | `CiliumBGPAdvertisement` of type `PodCIDR` | the peer's RIB contains each node's pod CIDR with that node as next hop |
| `bgp-advertise-service-vip` | advertisement of `Service` `LoadBalancerIP` | the peer's RIB contains `echo-lb`'s ingress IP as a /32 (or /128) |
| `bgp-vip-reachable` | from a client on the **other side of the peer** (a container on the kind network with a route via the peer) | the LB VIP is reachable end to end. This is the row that turns "we sent a BGP UPDATE" into "traffic actually arrives", and it is the only one that catches a correct advertisement with a broken datapath (or vice versa). |
| `bgp-etp-local-withdraw` | scale `echo-other-node` to 0 on one node with ETP=Local | that node withdraws the VIP; the other keeps it; the VIP stays reachable throughout |
| `bgp-graceful-restart` | restart the agent on a peering node with GR configured | the peer keeps the routes for the restart window; `bgp-vip-reachable` never fails |

#### 3.3.11 ClusterMesh

Runs only when `--multi-cluster <context>` names a second kubeconfig context and
both clusters report ClusterMesh enabled. The suite deploys the standard
topology into both clusters with distinct namespace prefixes and a shared
service name, and marks the service for global export.

| ID | What | Expect |
|---|---|---|
| `clustermesh-pod-to-pod` | `client` in cluster 1 → `echo` pod IP in cluster 2 | ok; the Hubble flow's destination has `cluster_name` = cluster 2 and an identity from cluster 2's identity space |
| `clustermesh-global-service` | `client` in cluster 1 → the global service ClusterIP | ok; backends from **both** clusters are observed across N requests |
| `clustermesh-service-affinity-local` | same with `service.cilium.io/affinity: local` | only local backends observed |
| `clustermesh-service-affinity-remote` | `affinity: remote` | only remote backends observed |
| `clustermesh-policy-cross-cluster` | a CNP selecting the remote cluster's labels | allow and deny both behave; proves remote identities reached the policy engine |
| `clustermesh-endpointslice-sync` | MCS-API `ServiceExport` | an `EndpointSlice` mirroring remote endpoints appears in cluster 1 |
| `clustermesh-encryption` | with WireGuard or IPsec on both clusters | the §3.3.8 capture assertions applied to the inter-cluster path |
| `clustermesh-partition` | sever the mesh (scale `clustermesh-apiserver` to 0 in cluster 2) | cluster-1-local traffic is unaffected; cross-cluster traffic degrades to a clean failure; on restore, cross-cluster traffic recovers within the reconnect interval |

If only one cluster is available, every row above is `skipped` with reason
`multi-cluster not configured`.

### 3.4 How assertions are made

Four mechanisms, in increasing order of cost and decreasing order of how often
they are used.

#### 3.4.1 The probe agent, not `kubectl exec` per probe

**DEVIATION and the main structural difference from the reference's approach.**
The reference execs `curl`/`ping` in a pod per action. At 250–300 actions that
is 250–300 exec sessions, each with SPDY/WebSocket setup, a shell, and output
scraping — slow, and the failure mode ("exit code 28") carries almost no
information.

flowsdn's `flowsdn-testpod` runs a **probe agent**: an HTTP control API on
`127.0.0.1`-and-pod-IP port 8079 with one endpoint, `POST /probe`, taking a
`ProbeSpec` (§4.2) and returning a `ProbeResult` (§4.2) as JSON. The suite:

1. Reaches the probe agent through the API server's pod `proxy` subresource
   (`/api/v1/namespaces/<ns>/pods/<pod>:8079/proxy/probe`) via kube-rs, so no
   port-forward, no in-cluster network path from the runner, and no dependence
   on the runner being able to reach pod IPs.
2. Gets back a **structured** result: connect time, TLS time, first-byte time,
   total time, bytes, HTTP status, response headers, the peer address the server
   observed, the DNS answer used, the errno class, and — for a failure — which
   phase failed (`dns`, `connect`, `tls`, `request`, `response`).
3. Can ask for N repeats, a concurrency level, and a payload size in one call,
   so a 20-request affinity check is one round trip.

`ProbeSpec` covers: TCP connect, HTTP/1.1 and HTTP/2 request with method,
path and headers, UDP echo, ICMP echo (v4 and v6), DNS query (A, AAAA, with a
chosen resolver or the pod's `/etc/resolv.conf`), and a "hold open" mode that
starts a long-lived connection and returns a handle for later interrogation
(used by §3.3.2, §3.3.5 and §3.6).

`kubectl`-style exec is still implemented, via kube-rs `Api::<Pod>::exec` with
`AttachedProcess` (no `kubectl` binary anywhere), and is used for exactly three
things: the initial "is the probe agent alive" bootstrap, running `ip`/`ss`-shaped
diagnostics inside a pod netns during failure collection, and probing from pods
the suite did not create (`--from-pod`, a debugging convenience).

#### 3.4.2 Where a probe runs

| Source in the matrix | Mechanism |
|---|---|
| a suite-created pod | probe agent via the pod proxy subresource |
| `host-netns` / `host-netns-non-flowsdn` | the same probe agent — it is the same image, running with `hostNetwork: true`; its bind address is the node IP |
| "the suite itself" (only `pod-to-health` and the BGP peer RIB checks) | direct gRPC/HTTP from the runner |
| a container on the kind network outside the cluster (BGP `bgp-vip-reachable`) | a `flowsdn-testpod` container started on that network by the provisioner, driven over its own port | 

There is no probe anywhere in the suite that runs on the CI runner and targets a
pod IP directly. That path does not exist on a real cluster and testing it
would encode a kind-only assumption.

#### 3.4.3 Hubble flow assertions — the mechanism

This is the capability a black-box connectivity suite does not have, and the
reason spec 11 was written before this one. A probe tells you a connection
worked. A Hubble assertion tells you **which path it took**, and that is what
turns "the tests pass" into "the datapath is correct". A pod-to-pod cross-node
probe that succeeds because the packet went out to the router and back looks
identical, at the socket, to one that went through the tunnel.

**Mechanism.**

1. Before a scenario's probes run, the suite opens one `Observer.GetFlows`
   stream per node — direct to each agent's `:4244` through the pod proxy
   subresource of that node's agent pod, or a single stream to `hubble-relay`
   `:4245` when relay is deployed (`--hubble-mode=relay|per-node`). `follow =
   true` (**field 3** on `GetFlowsRequest`, not field 2 — spec 11 §4.15),
   `number = 0`, `since` = the moment the stream opened. `first` is never set:
   spec 11 rejects `first` together with `follow` with `InvalidArgument`.
   Node enumeration comes from `Observer.GetNodes`, which is served by
   **relay only** — the agent returns `Unimplemented` — so in `per-node` mode
   the node list comes from the Kubernetes API instead.
2. The stream carries a `whitelist` of `FlowFilter`s narrowed to the scenario's
   pods (`source_pod`/`destination_pod` as `ns/name`, namespace exact and name
   prefix — the semantics in `11-hubble-monitor.md` §3.16). Narrowing at the
   server, not the client, is what keeps a 4-node run from shipping millions of
   flows to the runner.
3. Probes run. Each probe carries a **correlation key**: a unique source port
   range allocated per scenario, plus, for HTTP, a `X-Flowsdn-Probe: <uuid>`
   header that appears in L7 flows. Flows are matched to probes by 5-tuple
   first, by header second.
4. After the probes, the suite drains the stream for `--flow-settle` (default
   2 s; flows are asynchronous and arriving late is normal), closes it, and
   evaluates the scenario's `FlowAssertion`s against the collected set.

**A `FlowAssertion`** (§4.3) is a predicate over the collected flows plus a
cardinality:

```
assert exists  >= 1 flow where
    verdict                 == FORWARDED         // Verdict 1
  & event_type.type         == 4                 // CILIUM_NOTIFY_TRACE
  & trace_observation_point == TO_OVERLAY        // 4
  & source.identity         == identity_of(client)
  & destination.identity    == identity_of(echo-other-node)
  & node_name               == "<cluster>/<node A>"
```

The fields available and their exact semantics are `11-hubble-monitor.md` §3.16
(the 25 filter fields, with their frozen field numbers) and §4 (the flow
schema). The assertion evaluator uses the **same filter code** as the agent's
server-side filter — one crate, `flowsdn-hubble-filter`, shared between the
agent and the suite — so an assertion cannot be satisfied by a filter bug that
the agent does not have.

The enum values assertions are written against, all frozen by spec 11:

| Enum | Values used here |
|---|---|
| `Verdict` | `1 FORWARDED`, `2 DROPPED`, `3 ERROR`, `4 AUDIT`, `5 REDIRECTED`, `6 TRACED`, `7 TRANSLATED` |
| `event_type.type` | `1` drop, `2` debug, `3` debug capture, `4` trace, `5` policy verdict, `7` trace-sock, `129` L7, `130` agent |
| `TraceObservationPoint` | `1 TO_PROXY`, `2 TO_HOST`, `3 TO_STACK`, `4 TO_OVERLAY`, `5 FROM_ENDPOINT`, `6 FROM_PROXY`, `7 FROM_HOST`, `8 FROM_STACK`, `9 FROM_OVERLAY`, `10 FROM_NETWORK`, `11 TO_NETWORK`, `12 FROM_CRYPTO`, `13 TO_CRYPTO`, **`101 TO_ENDPOINT`**. There is deliberately no `FROM_NETDEV`/`TO_NETDEV`; `0` is `UNKNOWN_POINT` and never carries meaning. |
| `TraceReason` | `1 NEW`, `2 ESTABLISHED`, `3 REPLY`, `4 RELATED`, `6 SRV6_ENCAP`, `7 SRV6_DECAP`; the `0x80` mask on the datapath value is what sets `IP.encrypted` |
| `DropReason` | the codes an assertion names explicitly: `133 POLICY_DENIED`, `140 MISSED_TAIL_CALL`, `147 NO_TUNNEL_KEY`, `160 NO_TUNNEL_ENDPOINT`, `171 INVALID_IDENTITY`, `181 POLICY_DENY`, `189 AUTH_REQUIRED`, `195 UNENCRYPTED_TRAFFIC`, `203 EP_NOT_READY` |
| reserved identities | `1 host`, `2 world`, `3 unmanaged`, `4 health`, `5 init`, `6 remote-node`, `7 kube-apiserver`, `8 ingress`, `9 world-ipv4`, `10 world-ipv6` |
| `Tunnel.Protocol` | `1 VXLAN`, `2 GENEVE`; `Tunnel.vni` carries the outer VNI while `IP`/`l4` describe the **inner** packet |

Three flow fields deserve naming because they are what make a path assertion
possible at all and are easy to overlook: `IP.encrypted` (derived from the trace
reason's `0x80` bit, not from configuration), `IP.source_xlated` (the pre-SNAT
source, which is how a masquerade assertion is made from a flow rather than from
a capture), and `flow.file{name,line}` (set on drops only, naming the datapath
source site — the single most useful field in a drop nobody expected).

`is_reply` is a `BoolValue` whose **absence means unknown**, not false. An
assertion on `is_reply == false` must therefore be written as "present and
false"; writing it as "not true" silently matches every drop, since drops carry
no `is_reply`.

**The assertions that carry the most weight**, and what each catches:

| Assertion shape | Catches |
|---|---|
| `TO_OVERLAY` + `FROM_OVERLAY` pair exists for a cross-node flow, in tunnel mode | traffic silently taking the underlay route instead of the tunnel |
| **no** `TO_OVERLAY` flow exists, in native routing mode | a stale tunnel route surviving a mode change |
| `FROM_ENDPOINT` on node A and `TO_ENDPOINT` on node B for the same 5-tuple | the packet was actually delivered to the endpoint program, not just accepted by the host stack |
| `source.identity` is the client's **numeric** identity, not `world (2)` or `unknown` | an ipcache miss — which usually still forwards, and still passes a black-box probe, but breaks policy |
| `destination.identity == remote-node (6)` for `pod-to-host-remote` | remote node addresses misclassified as `world`, which quietly opens or closes `toEntities` policies |
| `REDIRECTED` with a non-zero proxy port, then `TO_PROXY`/`FROM_PROXY` | an L7 policy that is installed but never actually redirects |
| `verdict == DROPPED` **and** `drop_reason == <the specific code>` | a test that "passes" because the traffic failed for an unrelated reason (no route, port closed) rather than the policy under test |
| `is_reply == true` flows exist for every forward direction | one-way connectivity: SYN arrives, SYN-ACK does not |
| `IP.encrypted == true` on the pod-to-pod flow with encryption on | encryption enabled in config but not on the path |
| `Tunnel.protocol == VXLAN\|GENEVE` matching the configured mode | a Geneve config running a VXLAN datapath |
| `interface.name` equals the expected device | traffic leaving the wrong NIC in a multi-device setup |
| zero flows with an unexpected `drop_reason` across the whole run (`no-unexpected-drops`) | drops nobody looked for |

**Fallback.** When Hubble is disabled (`--hubble=false`, or an agent built
without it), every `FlowAssertion` is reported `skipped: hubble disabled` and
the scenario's pass/fail reduces to the probe result. A CI job MUST set
`--require-hubble` so that this degradation is a failure rather than a quiet
loss of coverage.

**Cost.** One `GetFlows` stream per node per scenario is too much. The suite
opens streams **per scenario group** (a group is a set of scenarios sharing a
source/destination pair) and keeps them open across the group, tagging flows by
correlation key. Measured budget: one stream per node held for the whole run,
with a per-scenario windowing index, is the intended design once the run is
long; the per-group form is the starting point (open decision D6).

#### 3.4.4 Packet capture

Used only where the on-the-wire bytes are the assertion: encryption (§3.3.8),
tunnel-protocol confirmation when Hubble is unavailable, and DSR option
presence. Implemented as a `flowsdn-testpod --mode=capture` pod on the target
node, `hostNetwork: true`, `CAP_NET_RAW`, with an `AF_PACKET` `SOCK_RAW` socket
bound to the device, a classic-BPF filter attached with `SO_ATTACH_FILTER`, and
a bounded ring (default 64 MiB, `--capture-limit`). The suite drives it over the
same probe-agent control API: `POST /capture/start` with a filter spec, `POST
/capture/stop` returning counters plus, when `--capture-save` is set, a pcap
written into the sysdump.

Filters are expressed as a small typed `CaptureFilter` (§4.2) and compiled to
cBPF in Rust (`flowsdn-cbpf`) rather than by shelling out to `tcpdump -d`. The
filter forms needed: `host A and host B`, `udp port 51871`, `proto esp`,
`udp port 8472|6081`, and `contains <32-byte cookie>` (a payload substring
match, which cBPF can express as a sequence of `ld`/`jeq` at fixed offsets for
the fixed-position cookie the testpod emits).

### 3.5 Interoperability with upstream Cilium

Spec 02 §2.5 decides that **wire compatibility with Cilium nodes is a goal**:
"a mixed cluster during migration MUST forward pod traffic in both directions
with correct identities", and its §9.5 already carries the acceptance item this
section implements — one Cilium v1.20.1 node and one flowsdn node in the same
VXLAN cluster, pod-to-pod and NodePort across the two, with correct identities
in Hubble. That decision is only worth anything if it is tested; an untested
compatibility claim is a wish.

The concrete contract the scenarios below exercise, all from spec 02 §2.5:

| Element | Value that must match |
|---|---|
| VXLAN / Geneve UDP port | 8472 / 6081 (`tunnel_port`), protocol selector `1 = VXLAN`, `2 = Geneve` |
| VNI | `VNI = security identity << 8` as a 24-bit field; recovery `identity = ntohl(vni) >> 8`. This is why spec 03 keeps identity numbering inside 24 bits. |
| Identity rewrites on the wire | `WORLD_IPV4 (9)` and `WORLD_IPV6 (10)` collapse to `WORLD (2)` and are re-split by ethertype on decap; `HOST (1)` is rewritten to `REMOTE_NODE (6)` before encap, and a received VNI decoding to `HOST` is dropped (`DROP_INVALID_IDENTITY`, 171) |
| Geneve DSR option | class `0x014B`, type `0x81` (critical), length 2 for IPv4 (`{addr be32, port be16, pad}`), length 5 for IPv6 |
| IPv4 DSR IP option | type `IPOPT_COPY \| 0x1a`, total 8 bytes `{type, len, port be16, addr be32}` |
| IPv6 DSR | 24-byte Destination Options header, option type `0x1B`, option length 20 |
| IPsec mark | `MARK_MAGIC_ENCRYPT 0x0E00`, node id in bits 16..31, key index (= SPI) in bits 12..15; `MARK_MAGIC_DECRYPT 0x0D00` |
| Node ids | `cilium_node_map_v2`, 20-byte key / 4-byte value `{id u16, spi u8, pad}` |
| Program symbol prefix | `cil_`, so each implementation cleans up the other's tc filters and links on takeover (spec 01 §2.1) |
| `Flow.emitter.name` | flowsdn emits `"flowsdn"` where the reference emits `"cilium"` — a deliberate **DEVIATION**, and the field the interop run uses to tell whose datapath produced a flow |

**Setup (`flowsdn-connectivity interop`).** A 4-node cluster: nodes A and B run
the flowsdn agent, nodes C and D run upstream `cilium/cilium` at a pinned
version (`--peer-version`, default the latest release at the reference tag's
minor, i.e. `v1.20.x`). Both agents are configured from the same value set:
same `cluster-pool-ipv4-cidr`, same `cluster-id`/`cluster-name`, same tunnel
protocol and port, same encryption mode and key, same `bpf-lb-mode`. The two
agents run as **two DaemonSets with disjoint node selectors**; neither manages
the other's nodes.

Because both write the same CRDs (`CiliumNode`, `CiliumEndpoint`,
`CiliumIdentity`, `CiliumEndpointSlice`) into the same API server, the control
plane is shared by construction; there is no gateway or translation layer.

**What the test asserts.**

| ID | Probe | Asserts about the contract |
|---|---|---|
| `interop-pod-to-pod-f2c` | pod on A → pod on C | flowsdn's encapsulation is parsed by Cilium's datapath: tunnel protocol, port, VNI framing |
| `interop-pod-to-pod-c2f` | pod on C → pod on A | the reverse, which is a genuinely different code path |
| `interop-identity-preserved` | either direction, with a policy on the receiving side selecting the sender's labels | the **security identity survived the wire**. This is the sharpest assertion in the whole spec: it can only pass if flowsdn's identity numbering, the identity's placement in the VNI/mark, and the identity allocation (same `CiliumIdentity` objects, same numbering) all agree with upstream. A policy that allows and one that denies are both run — an allow that passes because policy is not enforced at all is not evidence. |
| `interop-identity-rewrites` | host-network pod on a flowsdn node → pod on a Cilium node, and a pod→world flow crossing the tunnel in each direction | the two `HOST → REMOTE_NODE (6)` and `WORLD_IPV4/6 → WORLD (2)` rewrites are applied identically by both. Asserted in Hubble on the *receiving* side: the source identity seen after decap is `remote-node (6)` (never `host (1)`), and a dual-stack world flow is re-split back to `9`/`10` by ethertype. These two rewrites are the least obvious part of the VNI contract and the most likely to be got wrong on a reimplementation. |
| `interop-ipcache-agreement` | dump `cilium_ipcache_v2` on a flowsdn node and on a Cilium node | the two maps agree on every remote endpoint: same identity, same tunnel endpoint, same encryption key id. Compared as sets, tolerating ordering and propagation lag (retry window `--interop-settle`, default 30 s). |
| `interop-service-both-ways` | pod on A → ClusterIP with backends on C; pod on C → ClusterIP with backends on A | both agents produced compatible service/backend map contents from the same `EndpointSlice`s, and reverse-NAT works across the boundary |
| `interop-nodeport-cross` | world → node A NodePort with the backend on node C | NodePort's second hop crosses implementations; SNAT/DSR framing must match. In DSR mode this asserts the **DSR option encoding** (Geneve TLV class/type, or the IPv4 IP option) is byte-compatible, which is the finest-grained wire assertion available. |
| `interop-encryption-wireguard` | encryption on, pod A → pod C | flowsdn's WireGuard peer/key exchange (via `CiliumNode` annotations) is understood by Cilium's, and vice versa; the §3.3.8 capture assertions apply |
| `interop-encryption-ipsec` | same for IPsec | SPI and node-ID encoding in `skb->mark`, XFRM state/policy shape, and key id agreement |
| `interop-health` | health endpoints | each agent's health prober reaches the other's endpoints |
| `interop-hubble-identity` | Hubble flow on the flowsdn node for a packet from a Cilium node | flowsdn's decoder reads the identity Cilium put on the wire and renders the right pod name and labels |

**What it does not assert.** It does not assert that the two agents' internal
state, CLI output, or map *layouts* match — only the wire and the shared CRDs.
A map layout difference that both sides handle is fine; spec 01's ABI applies to
flowsdn's own upgrades, not to the neighbour's.

**When it runs.** Nightly, not per-PR: it requires pulling an upstream image and
a 4-node cluster, and it fails for reasons outside flowsdn's control (an
upstream point release changing a default). A failure files an issue rather than
blocking the merge queue, per §10.5.

### 3.6 Upgrade and downgrade with live traffic

The property under test: **an agent version change does not break established
connections**, which is what the map-versioning and pin-replace protocol of
`01-bpf-map-abi-loader.md` exists to guarantee.

**Mechanism (`flowsdn-connectivity conn-disrupt`).** Three subcommands used in
sequence by CI, mirroring the reference's setup/check split so that the traffic
outlives the process that started it:

1. `conn-disrupt setup` — deploys long-lived-flow workloads and returns
   immediately. Flows established (each a `flowsdn-testpod` pair holding an open
   connection and sending a keepalive every `--conn-disrupt-interval`, default
   0 ms meaning "as fast as the peer accepts", with a sequence number in each
   message so a gap is detectable, not just a disconnect):

   | Flow | Path exercised |
   |---|---|
   | pod → pod, same node | local endpoint delivery |
   | pod → pod, cross node | tunnel/native + CT + ipcache |
   | pod → ClusterIP, remote backend | service maps + reverse NAT |
   | pod → NodePort on a remote node | NodePort maps + SNAT/DSR state |
   | world → NodePort | north-south CT and NAT state |
   | pod → external, through the egress gateway | egress policy map + SNAT state (only with egress gateway on) |
   | pod → pod through an L7 HTTP policy | proxy connections, which are **expected** to break on an Envoy restart; recorded separately and asserted only when `--conn-disrupt-l7` says the deployment should have preserved them |
   | host-netns → pod | host endpoint state |

   Each flow's endpoints record: bytes sent, bytes received, highest contiguous
   sequence number, count of gaps, count of reconnects, and a monotonic
   `restarts` counter read from the pod status. The counters and the observed
   agent restart counts are written to `--conn-disrupt-state <path>` on the
   runner.

2. The upgrade happens (CI's business, not the suite's): `helm upgrade` to the
   new agent image, DaemonSet rolls node by node.

3. `conn-disrupt check` — reads the state file, re-interrogates every flow, and
   asserts:

   | Assertion | Meaning |
   |---|---|
   | zero sequence gaps on every flow marked `must-survive` | no packet loss window during the swap |
   | zero reconnects on those flows | the TCP connection itself was never reset |
   | the pods' restart counters are unchanged | the flows did not survive because the workload restarted and silently re-established |
   | agent restart counts increased by exactly the expected number | the upgrade actually happened; a "no disruption" result on an upgrade that did not occur is the classic false pass |
   | zero `DROPPED` Hubble flows for those 5-tuples, or only drops on the allowlist | the datapath did not drop and recover |
   | for IPsec: XFRM error counters within the allowlist | no window where the SA was missing |
   | hold the original CT map FD, compare kernel map IDs, and check each surviving tuple plus its quiesced raw value after the swap | evidence that the same kernel map object and sampled state survived; identical entry delete/reinsert is not detectable (§12.8) |
   | the `cilium_calls_*` pin's map id **changed exactly once**, at commit | the tail-call map was replaced wholesale rather than rewritten in place — the direct assertion on the pin-replace protocol |
   | zero `DROP_MISSED_TAIL_CALL` (140) and zero `DROP_EP_NOT_READY` (203) flows during the roll | no packet ever saw a half-populated tail-call graph or an empty `cilium_call_policy` slot |

**What the protocol is being tested against.** Spec 01 defines three distinct
behaviours and the suite must not conflate them:

1. **Compatible pinned map** (same type, key size, value size, max entries,
   flags): the new agent reuses it and **contents are preserved** (§3.2 step 2).
   This is the normal path for the CT and NAT maps, which are agent-owned, and
   it is why an upgrade does not break connections.
2. **Incompatible agent-owned map** (a layout or `max_entries` change on
   `cilium_ct4_global`, `cilium_snat_v4_external`, …): the map is unpinned and
   **recreated empty. There is no content migration — the connections in it are
   lost, by design**, and the agent logs old versus new attributes (§3.2 step 5,
   §7). Anyone expecting migration here is expecting something the spec does not
   promise.
3. **Loader-owned maps** (`cilium_calls_*`, per-object policy maps): never
   reused. Every load creates a fresh map; the pin is swapped only after every
   entrypoint of the object is attached (`PIN_REPLACE` + commit), with programs
   swapped by `BPF_LINK_UPDATE` so no packet sees "no program".

The suite therefore tests three cases, with three *different* expectations:

| ID | What | Expect |
|---|---|---|
| `upgrade-same-abi` | roll to a build with an identical map ABI | all `must-survive` flows survive; CT map IDs and quiesced tuple values preserved; the `cilium_calls_*` map id changes exactly once per object |
| `upgrade-calls-replace` | any roll | during the whole roll, no flow observes `DROP_MISSED_TAIL_CALL`; the policy program is present in `cilium_call_policy[epid]` **before** the ingress link exists (checked by sampling the map during the roll) |
| `upgrade-ct-abi-bump` | roll to a CI-only build with a deliberately bumped CT map layout (`--force-map-abi-bump=ct`) | the flows **break and re-establish** within one keepalive interval, the agent logged the old and new map attributes, and the CT map's id changed. This asserts the *documented* consequence. A run where the flows survive a CT layout change means something silently kept the old map, which is a bug in the other direction. |
| `upgrade-agent-restart` | restart the agent without changing the image | flows survive; this is the cheap variant that runs per-PR |
| `upgrade-agent-crash` | `SIGKILL` the agent | flows survive (the datapath is in the kernel and keeps running); the agent recovers endpoint state from `/var/run/cilium/state`. Gated on `--include-unsafe-tests`. |
| `downgrade` | roll **back** to the previous version | the previous version starts successfully against the maps the newer one wrote, and connectivity is fully restored. Flow survival is asserted only when the two versions share the map ABI; where they do not, the assertion is that the older agent **recreated the map cleanly and logged it**, per spec 01 §3.2 steps 4–5, rather than crashing or silently mis-reading a newer layout. Attach-mechanism downgrade is asserted too: after a roll back from a tcx-capable to a clsact build, no orphan tcx link pin remains (spec 01 §3.9 step 3). |
| `upgrade-policy-during` | apply and remove policy during the roll | no drops beyond the allowlist |
| `upgrade-cni-conflist` | during the roll | no pod fails to start; the CNI configuration file is never absent (spec 09's install/uninstall ordering) |

Downgrade is asserted **one minor version back only**, matching the reference's
support statement, and the version to downgrade to is computed the way the
reference's `print-downgrade-version.sh` does: from the project `VERSION`.

### 3.7 Scale and performance smoke tests

Not a benchmark suite. The purpose is a **regression gate**: catch the change
that makes something 10× worse, with a signal stable enough that it does not
fire on noise. Everything here runs on a fixed node shape (§10.6) and compares
against a stored baseline for that shape.

| ID | Measurement | Method | Gate |
|---|---|---|---|
| `scale-endpoint-churn` | time to create and delete 200 pods on one node; p50/p99 CNI ADD latency; agent RSS delta | a Deployment scaled 0→200→0; latencies read from the agent's own CNI metrics (spec 09) | p99 ADD < 2× baseline; RSS delta < 1.5× baseline; **zero** failed ADDs |
| `scale-identity-churn` | identities allocated and released for 200 distinct label sets | as above with distinct labels per pod | allocation p99 < 2× baseline; identities released within the GC interval; no identity leak (count returns to baseline ±5) |
| `scale-policy-churn` | time from `CiliumNetworkPolicy` apply to every agent reporting the new revision, with 500 policies already loaded | apply/remove 50 policies; poll each agent's `/v1/status` policy revision | p99 propagation < 2× baseline; **zero** dropped packets on a concurrent long-lived flow |
| `scale-service-churn` | time from Service create to the LB map entry being present on every node, with 1000 services already present | create/delete 100 services; read `flowsdn-dbg bpf lb list` (or the agent's service API) | p99 < 2× baseline; map entry count returns to baseline |
| `scale-flow-throughput` | Hubble flows per second sustained without loss | drive 50k pps between two pods; read `ServerStatus.flows_rate` and the per-node `LostEvent` count | lost events < 1% of observed; flows_rate within 20% of the packet rate |
| `perf-tcp-stream` | single-stream throughput pod→pod cross node | `flowsdn-testpod` bulk mode (its own generator, not netperf), 30 s | ≥ 0.8 × baseline |
| `perf-tcp-rr` | request/response latency pod→pod cross node | same, 1-byte req/resp, 30 s | p99 ≤ 1.25 × baseline |
| `perf-udp-stream` | UDP throughput and loss | same | ≥ 0.8 × baseline throughput |
| `perf-host-to-pod` | the host path, same two measurements | | ≥ 0.8 × baseline |

Baselines are stored per `(kernel, arch, node shape, datapath config)` in
`tests/perf-baselines/<key>.json`, committed, and updated by a deliberate PR
that says why. A missing baseline is a **skip with a warning**, not a failure —
so a new matrix row does not block on data that does not exist yet.

Gates are ratios, not absolutes, and every gate is evaluated over the **median
of 5 runs** with the run-to-run spread also reported. A gate that fires is
reported as a distinct JUnit failure kind (`performance-regression`) so it can be
routed differently from a correctness failure. **DEVIATION**: the reference has
no dedicated perf workflow at v1.20.1 (its `network-perf` test uses netperf
inside the connectivity suite); flowsdn keeps performance in the same binary but
runs it as a separate nightly job with its own baselines, because mixing a
timing-sensitive measurement into a PR gate produces flakes and teaches people
to re-run.

### 3.8 Failure diagnosis: the sysdump

When a scenario fails, the suite MUST collect enough to diagnose it without
re-running. This is `flowsdn-connectivity sysdump`, also usable standalone.

**Trigger.** `--collect-sysdump-on-failure` (default true in CI, false
interactively). One sysdump per run, not per failure, collected after the last
scenario, plus an immediate lightweight snapshot (the "quick set" below) at the
moment of each failure so that transient state is not lost by the time the run
ends.

**Quick set (at each failure, seconds).** Per node involved in the failed
scenario: agent `/v1/status --verbose` JSON; the last 200 Hubble flows matching
the scenario's filter (including `DROPPED` ones the assertion did not expect);
`/v1/endpoint` for the source and destination endpoints; the last 100 agent log
lines. Attached to the JUnit case as `system-err` and written to
`<out>/failures/<scenario-id>/`.

**Full set (once, at run end).** Fanned out to every node in parallel by
scheduling a short-lived privileged `flowsdn-testpod --mode=collect` pod, or —
preferred, and the default when the agent is present and healthy — by calling
the agent's own collector subcommand `flowsdn-agent bugtool` through the agent
pod's exec, since the agent already has the mounts and capabilities.

| Group | Contents |
|---|---|
| Cluster objects | all `cilium.io` CRs (identities, endpoints, endpoint slices, nodes, policies, egress policies, BGP objects, LB IP pools, CEC/CCEC), plus `Pod`, `Service`, `EndpointSlice`, `Node`, `NetworkPolicy`, `Event` in the test namespaces and `kube-system`; the flowsdn ConfigMap, DaemonSet, Deployment and their describe output; the k8s version |
| Agent state per node | `/v1/status --verbose`, `/v1/config`, `/v1/endpoint -o json`, `/v1/healthz`, `flowsdn-dbg identity list`, `policy get`, `policy selectors -o json`, `service list -o json`, `node list -o json`, `bpf nodeid list`, `lrp list`, `encrypt status`, `fqdn cache list`, `bpf metrics list`, `map list --verbose`, health history |
| **BPF map dumps** | every pinned map under `<bpf-root>/tc/globals` by name, dumped through flowsdn's own map reader (`flowsdn-dbg bpf … list`, JSON). Spec 01 §2.1 keeps the reference's map names verbatim (`cilium_*`), because they are the interface `cilium-dbg`, `bpftool map dump pinned`, the Hubble decoders and Envoy's `cilium.bpf_metadata` all consume — so the sysdump uses those names, not `flowsdn_*`: `cilium_lxc`, `cilium_ipcache_v2`, `cilium_ct4_global`/`ct6_global`/`ct_any4_global`/`ct_any6_global`, `cilium_snat_v4_external`/`v6_external` and `_alloc_retries`, `cilium_lb4_services_v2`/`lb6_services_v2`, `cilium_lb4_backends_v3`/`lb6_backends_v3`, `cilium_lb4_reverse_nat`/`lb6_reverse_nat`, `cilium_lb4_affinity`/`lb6_affinity`/`lb_affinity_match`, `cilium_lb4_maglev`/`lb6_maglev`, `cilium_lb4_source_range`/`lb6_source_range`, `cilium_node_map_v2`, `cilium_metrics`, `cilium_policy_v3_<epid:05d>` for every endpoint, `cilium_call_policy` and `cilium_egresscall_policy`, `cilium_egress_gw_policy_v4_v2`/`v6`, `cilium_ipmasq_v4`/`v6`, `cilium_encrypt_state`, `cilium_auth_map`, `cilium_skip_lb4`/`lb6`, `cilium_throttle`, `cilium_ipv4_frag_datagrams`/`ipv6_`, `cilium_runtime_config`, `cilium_events` and `cilium_signals` (metadata only), and the contents of every `cilium_calls_*` tail-call `PROG_ARRAY` (`cilium_calls_%05d`, `_hostns_%05d`, `_netdev_%05d`, `_overlay_2`, `_wireguard_<ifindex>`, `_xdp_<ifindex>`). A pin the collector does not recognise is dumped as raw key/value bytes and flagged, since an unrecognised pin is itself a finding. |
| **Hubble flows** | up to `--sysdump-hubble-flows-count` (default 1 000 000) flows from every node, JSONL, collected with a `--sysdump-hubble-flows-timeout` (default 5 min) budget, no filter — the whole ring. This is usually the largest artifact and the most useful one. |
| **Kernel logs** | `dmesg --time-format=iso` per node; `/var/log/messages` where present; the agent container's full log and its previous-instance log |
| **nftables ruleset** | `nft -j list ruleset` equivalent read over netlink by flowsdn's own nftables code (spec 10) — the whole ruleset, not just the `inet flowsdn` table, because a conflicting table from another component is exactly what one is looking for. **DEVIATION (ADR-0003)**: no `iptables-save`. If `iptables` rules exist on the node they are captured *as a foreign-component observation* under `foreign/` with a note, since they can still break the datapath. |
| **Routes and rules** | `ip -4 route show table all`, `ip -6 route show table all`, per-table dumps for every table id present (as the reference enumerates them), `ip -d rule`, `ip -4/-6 neigh`, `ip -d -s -s link`, `ip -s xfrm policy`, `ip -s xfrm state` |
| Devices and attachments | tc/tcx filter and chain listing per device, XDP attachments, qdiscs, cgroup program tree, `bpftool`-equivalent prog/map/link listings produced by flowsdn's own loader introspection (no `bpftool` dependency), `find /sys/fs/bpf -ls` |
| Host facts | `uname -a`, `sysctl -a`, `/proc/net/{snmp,snmp6,netstat,softnet_stat,xfrm_stat,dev}`, `lsmod`, `/boot/config-$(uname -r)` or `/proc/config.gz`, cgroup and bpffs mount info, `ss -tanpi`, `ss -uanpi`, `ps` |
| Suite state | the full run plan, every scenario's result with timings, every probe's `ProbeResult`, every flow assertion and the flows it evaluated against, the detected feature set, the manifests as applied, and pcaps from any capture that ran |
| Envoy | when the L7 proxy is deployed: the Envoy admin `/config_dump`, `/stats`, `/clusters`, `/listeners` from each Envoy pod |

**Archive.** A single `.tar.zst` named
`flowsdn-sysdump-<cluster>-<timestamp>.tar.zst`, laid out as
`nodes/<node>/…`, `cluster/…`, `suite/…`, `failures/<scenario-id>/…`, with a
top-level `MANIFEST.json` listing every file, its size, the command or API call
that produced it, and any collection error. A collection failure never aborts
the sysdump: it is recorded in the manifest and the rest proceeds. Redaction:
Secrets are collected as names and metadata only, never `data`; the IPsec key
file and WireGuard private keys are collected as SHA-256 hashes only;
`--redact` extends the list.

**Size.** A 4-node run with a full flow ring is expected around 200–600 MB
compressed; `--sysdump-max-size` (default 2 GiB) truncates flows first, then
map dumps, and records what was truncated in the manifest.

### 3.9 Invoking the suite

One statically linked binary, `flowsdn-connectivity`, cross-compiled for
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, published as a
release asset and as a scratch image. Subcommands:

| Subcommand | Purpose |
|---|---|
| `test` | the default: install topology, detect features, run scenarios, report, clean up |
| `features` | print the detected feature set (table, JSON, markdown) and exit — the equivalent of the reference's `features status`, used by CI to publish a feature summary |
| `install` / `uninstall` | create or delete the topology without running anything (for interactive debugging) |
| `conn-disrupt setup` / `conn-disrupt check` | §3.6 |
| `interop` | §3.5 |
| `perf` | §3.7 |
| `sysdump` | §3.8, standalone |
| `flows` | a thin `GetFlows` client with the suite's filter builder — handy for the same query the assertions use |
| `list` | print the scenario catalogue with ids, groups, and required features; `--json` for tooling |
| `version` | version, git sha, build target |

Flags are §6. Output formats: human (default, a live-updating summary plus a
final table), `--output=json` (the full `RunReport`, §4.4), `--output=junit
<file>` (§4.5), `--output=markdown` (a GitHub step-summary table). More than one
`--output` may be given.

---

## 4. Data model

### 4.1 The `flowsdn-testpod` image

One static Rust binary, `flowsdn-testpod`, in a `scratch` image, multi-arch
(`linux/amd64`, `linux/arm64`). Modes selected by `--mode` (default `server`),
all of which also run the probe-agent control API unless `--no-agent`:

| Mode | Behaviour |
|---|---|
| `server` | HTTP/1.1 + HTTP/2 (h2c) on 8080 and 8081; TCP echo on 8090; UDP echo on 8080/udp; a minimal TFTP responder on 69/udp; endpoints `/`, `/healthz`, `/public`, `/private`, `/whoami` (peer address, local pod name, node name, local address as JSON), `/echo` (echoes body), `/bulk?bytes=N`, `/slow?ms=N`, `/status/<code>` |
| `dns` | a tiny authoritative responder for a configured zone, used as the external DNS target and as a stub domain |
| `capture` | §3.4.4 |
| `collect` | §3.8 node collector when the agent is unavailable |
| `load` | the perf generator: TCP_STREAM/TCP_RR/UDP_STREAM equivalents with histogram output |

No shell, no busybox, no `curl`, no `tcpdump`, no `ping` binary — ICMP is a raw
socket in the same binary. This is what makes the image small (a few MB), the
same on both arches, and free of the "the test failed because the image's curl
is a different version" class of problem. **DEVIATION** from the reference,
which uses `quay.io/cilium/alpine-curl` and `json-mock`.

### 4.2 Probe and capture types

```rust
struct ProbeSpec {
    kind: ProbeKind,              // Tcp | Http | Udp | Icmp | Dns | HoldOpen
    target: Target,               // Ip(IpAddr) | HostPort(String,u16) | Name(String) | Url(String)
    port: Option<u16>,
    family: Family,               // V4 | V6 | Either
    repeats: u32,                 // default 1
    concurrency: u32,             // default 1
    timeout: Duration,            // default 5s per attempt
    payload_bytes: Option<usize>,
    http: Option<HttpSpec>,       // method, path, headers, expect_status, http2
    dns: Option<DnsSpec>,         // qtype, resolver override, expect_rcode
    source_port_range: Option<(u16,u16)>,  // the correlation key (§3.4.3)
    correlation_header: Option<String>,    // X-Flowsdn-Probe: <uuid>
    cookie: Option<[u8;32]>,      // the plaintext magic for encryption tests
}

struct ProbeResult {
    attempts: u32, successes: u32, failures: u32,
    per_attempt: Vec<Attempt>,
}

struct Attempt {
    ok: bool,
    phase_failed: Option<Phase>,  // Dns | Connect | Tls | Request | Response
    error_class: Option<ErrorClass>, // Refused | TimedOut | Unreachable | Reset
                                     // | DnsNxDomain | DnsRefused | DnsTimeout
                                     // | HttpStatus(u16) | TlsError | Other
    dns_ms: Option<f64>, connect_ms: Option<f64>,
    ttfb_ms: Option<f64>, total_ms: f64,
    bytes_tx: u64, bytes_rx: u64,
    http_status: Option<u16>,
    observed_peer: Option<IpAddr>,     // from /whoami — the SNAT assertion
    observed_server_pod: Option<String>, // the affinity / LB-spread assertion
    resolved_addrs: Vec<IpAddr>,
    local_addr: Option<SocketAddr>,    // gives the exact 5-tuple for flow matching
}

struct CaptureFilter {
    hosts: Vec<IpAddr>, ports: Vec<u16>,
    ip_proto: Option<u8>,          // 50 = ESP
    contains: Option<(usize,[u8;32])>,   // offset, cookie
}
struct CaptureResult { packets: u64, bytes: u64, matched: u64, pcap: Option<PathBuf> }
```

`error_class` is what §5.5 uses to tell "denied by policy" from "nothing
listening" from "no route", and it is derived from the errno, not from a
message.

### 4.3 Scenario and assertion types

```rust
struct Scenario {
    id: &'static str,                 // stable, kebab-case; the CI selector
    group: &'static str,              // pod-to-pod | pod-to-service | ... 
    requires: FeatureSet,             // ANDed; a missing feature => Skipped
    conflicts: FeatureSet,            // any present => Skipped
    families: &'static [Family],
    setup: Vec<Manifest>,             // policies etc., applied then removed
    probes: Vec<PlannedProbe>,        // (source pod selector, ProbeSpec, Expect)
    flow_assertions: Vec<FlowAssertion>,
    expected_drop_reasons: Vec<DropReason>,  // feeds `no-unexpected-drops`
    unsafe_: bool,                    // requires --include-unsafe-tests
}

enum Expect { Ok, Deny(DenyKind), Status(u16) }
enum DenyKind { PolicyDrop, Refused, Timeout, DnsRefused, Any }

struct FlowAssertion {
    name: &'static str,
    filter: FlowFilter,              // the real hubble FlowFilter (spec 11 §3.16)
    cardinality: Cardinality,        // AtLeast(n) | Exactly(n) | None
    window: AssertWindow,            // the probe window + --flow-settle
    on_node: Option<NodeSelector>,   // per-node streams only
    severity: Severity,              // Fail | Warn  (Warn for informational shapes)
}
```

`FlowFilter` is the protobuf type from `11-hubble-monitor.md` §4, constructed
with a builder; the assertion is evaluated with `flowsdn-hubble-filter`, the
same crate the agent uses server-side.

### 4.4 The run report

```
RunReport {
  version, git_sha, started, finished, duration,
  cluster: { name, k8s_version, node_count, nodes: [{name, arch, kernel, agent_version, roles}] },
  features: FeatureSet,             // §5.1, with the source of each value
  flags: { ... },                   // the exact invocation
  scenarios: [ ScenarioResult ],
  summary: { passed, failed, skipped, warned, duration_by_group },
  sysdump: Option<path>,
}
ScenarioResult {
  id, group, status: Passed|Failed|Skipped{reason}|Warned,
  duration, probes: [ProbeOutcome], flow_assertions: [AssertionOutcome],
  messages: [String], artifacts: [path],
}
```

`Skipped{reason}` always carries the *why*: the feature name and the config key
that produced it, or `not applicable to this ip family`, or `multi-cluster not
configured`. A skip with an empty reason is a bug in the suite and §9 tests for
it.

### 4.5 JUnit XML

One `<testsuite>` per scenario group, one `<testcase>` per scenario, `classname`
= group, `name` = scenario id. A failure emits `<failure type="...">` with the
type drawn from a closed set — `probe-failed`, `unexpected-success`,
`flow-assertion-failed`, `wrong-error-class`, `unexpected-drop`,
`source-ip-mismatch`, `performance-regression`, `setup-failed`, `timeout` — so
CI can classify without parsing prose. A skip emits `<skipped message="...">`.
Every case carries `<properties>` with `feature-set-hash`, `kernel`, `arch`,
`datapath-mode`, `lb-mode`, and, on failure, `sysdump-path`. Extra properties
come from `--junit-property k=v` (repeatable), which CI uses for the job name,
matching the reference's use of `--junit-property github_job_step=…`.

### 4.6 Manifests

Manifests are **not** YAML files embedded as strings. They are built as typed
`k8s-openapi` objects in Rust and applied server-side (`Patch::Apply` with a
field manager `flowsdn-connectivity`), so a schema change is a compile error
rather than a runtime rejection, and so re-running over an existing topology is
idempotent. `--dump-manifests <dir>` writes the YAML the suite *would* apply,
for review and for pasting into a bug report; the sysdump always includes it.

---

## 5. Algorithms

### 5.1 Feature detection

The scenario set is a function of the cluster, computed once, before anything is
applied, and recorded in the report. Sources, in precedence order:

1. `--feature k=v` on the command line (an override; recorded as such).
2. The agent's `GET /v1/config` on one healthy agent per distinct
   configuration — flowsdn supports per-node config (`CiliumNodeConfig`), so
   the suite queries **every** node and takes the intersection for
   cluster-wide features and the per-node value for node-scoped ones.
3. The `flowsdn-config` ConfigMap (used when the agent API is unreachable, and
   as a cross-check: a disagreement between the ConfigMap and a running agent is
   itself reported as a warning, because it means a node has not picked up a
   config change).
4. Cluster inspection: presence of the Envoy DaemonSet, hubble-relay Deployment,
   `CiliumLoadBalancerIPPool` objects, `CiliumBGPClusterConfig` objects,
   `clustermesh-apiserver`, the count of nodes without an agent, the node
   kernel versions from `Node.status.nodeInfo.kernelVersion`, node
   architectures, and the k8s version.

The resulting `FeatureSet` is a map from a stable feature name to
`{enabled: bool, source: ConfigMap|AgentApi|Inspection|Override, detail: String}`.
Feature names track the config keys — `enable-ipv4`, `enable-ipv6`,
`tunnel-protocol`, `routing-mode`, `enable-bpf-masquerade`, `bpf-lb-mode`,
`bpf-lb-algorithm`, `bpf-lb-acceleration`, `enable-host-port`,
`enable-socket-lb`, `socket-lb-host-namespace-only`, `enable-host-firewall`,
`enable-l7-proxy`, `enable-wireguard`, `enable-ipsec`,
`enable-encryption-strict-mode-{egress,ingress}`, `enable-ipv4-egress-gateway`,
`enable-bgp-control-plane`, `enable-local-redirect-policy`,
`enable-cilium-endpoint-slice`, `bpf-datapath-mode` (`veth`|`netkit`|`netkit-l2`),
`kube-proxy-replacement`, `enable-clustermesh`, `enable-hubble`,
`enable-node-port`, `enable-external-ips`, `enable-session-affinity`,
`enable-endpoint-routes`, `enable-bandwidth-manager` — plus the derived
inspection features `has-node-without-agent`, `has-relay`, `has-envoy`,
`has-lb-ipam-pool`, `has-second-cluster`, `dual-stack`.

The hash of the `FeatureSet` goes into every JUnit property so that two runs
with different results can be compared on configuration first.

### 5.2 Scenario selection

```
selected = catalogue
  |> filter: every f in scenario.requires is enabled
  |> filter: no f in scenario.conflicts is enabled
  |> filter: scenario.families ∩ enabled families ≠ ∅
  |> filter: !scenario.unsafe_ || --include-unsafe-tests
  |> filter: name filters (--test) match
  |> expand: one instance per family in scenario.families ∩ enabled
```

Pinned upstream aliases are expanded to canonical scenario IDs before name
filters are evaluated; expansion is deduplicated and applies equally to negated
selectors. The mapping revision is included in the report (#233).

`--test` accepts the reference's shape: comma-separated, prefix match on
`group/` or on the id, and `!` negation (`--test='!pod-to-world'`,
`--test='policy/,l7/'`). A `--test` expression matching **nothing** is an error,
not an empty pass — the single most common way a CI job silently stops testing
anything.

`--require-feature f` (repeatable) turns a scenario skipped for want of `f` into
a failure. CI jobs that exist to test WireGuard pass `--require-feature
enable-wireguard`, so a Helm value typo that quietly disables it fails the job
that was supposed to prove it.

### 5.3 Execution order and concurrency

Scenarios are grouped; groups run in a fixed order (connectivity baseline →
services → world → policy → L7 → encryption → egress → north-south → scale),
and within a group up to `--test-concurrency` (default 1) scenarios run in
parallel. Concurrency is not the default because (a) flow assertions are easier
to attribute when one scenario is running, and (b) policy scenarios mutate
cluster-wide state. Scenarios are annotated `exclusive: true` when they apply
cluster-scoped policy or change node state, and an exclusive scenario never runs
concurrently with anything.

Ordering rule: the negative baseline rows (§3.2.5) run **first**. If
`probe-sanity-closed-port` reports success, the run aborts immediately with
`setup-failed`, because nothing after it can be believed.

### 5.4 Barriers, not sleeps

Every state change is followed by a barrier that polls a real signal, with an
exponential backoff (10 ms → 500 ms) and a deadline:

| After | Barrier |
|---|---|
| applying/removing a policy | every agent's `/v1/status` reports a policy revision ≥ the one the operator/agent assigned to that object, **and** the object's `status` (where flowsdn writes one) shows it enforced on every node |
| creating a Service | every node's LB map contains the frontend (via the agent's service API), and the `EndpointSlice` has the expected backend count |
| creating pods | every pod `Ready` **and** its `CiliumEndpoint` shows an allocated identity and `state: ready` |
| deleting pods | the `CiliumEndpoint` is gone on every node (otherwise a later scenario's identity assertions see a ghost) |
| a `CiliumEgressGatewayPolicy` | the egress policy map on the client's node contains the entry |
| an agent restart | the agent's `/healthz` is 200 **and** its endpoint count matches the pre-restart count |
| a DNS-policy change | the policy revision barrier plus one successful resolve, because the DNS proxy's readiness is separate |

There is exactly one unconditional sleep in the suite: `--flow-settle` (§3.4.3),
because flow delivery is genuinely asynchronous with no completion signal.
Any other sleep introduced later must be justified in review; §9 has a test that
greps for `sleep` outside the settle path.

### 5.5 Deciding what a failure means

A `Deny` expectation is satisfied only by the right *kind* of failure:

| `DenyKind` | Satisfied by |
|---|---|
| `PolicyDrop` | the probe times out (no RST) **and** a Hubble `DROPPED` flow with an expected policy drop reason exists for the 5-tuple. Without Hubble, by timeout alone plus a warning that the assertion was weakened. |
| `Refused` | `ECONNREFUSED` / TCP RST |
| `Timeout` | `ETIMEDOUT` with no RST and no ICMP unreachable |
| `DnsRefused` | DNS `REFUSED` or `NXDOMAIN` from the proxy, not a query timeout |
| `Any` | any failure; used only where the mode is genuinely mode-dependent |

A probe that fails with the *wrong* class is a `wrong-error-class` failure with
both classes named. This is the difference between "the policy works" and "the
pod could not have reached the target anyway".

### 5.6 Flake control

| Technique | Detail |
|---|---|
| Retry with a budget | Each probe retries up to `--probe-retries` (default 3) with 250 ms backoff *before* the scenario fails. Retries are counted and reported: a scenario that passes only on retry 3 is `Passed` with `flaky: true` in the report and a JUnit property, so flakiness is visible without failing the build. |
| No retry on unexpected success | A `Deny` expectation that succeeds is never retried — retrying a security failure until it passes is exactly wrong. |
| Deterministic placement | §3.1.2: `nodeName`, not affinity. |
| Deterministic targets | §3.1.4: in-cluster external targets, not the internet. |
| Barriers, not sleeps | §5.4. |
| Per-scenario correlation keys | §3.4.3: flows cannot be attributed to the wrong scenario. |
| Warm-up | Before the first scenario in a group, one throwaway probe per source/destination pair warms the ipcache, ARP/NDP and CT state; its result is discarded. Without it, the first probe of a run measures neighbour resolution and occasionally exceeds the timeout. |
| Clock | All durations from `Instant`; all report timestamps from `SystemTime`; no wall-clock arithmetic in assertions. |
| Quarantine | `tests/quarantine.toml` lists scenario ids that are known-flaky, with an issue link and an expiry date. A quarantined scenario runs, and its failure is reported as `Warned`. An entry past its expiry date **fails the run**, so quarantine cannot become permanent. |

### 5.7 Cleanup

`Drop`-based, plus a `--cleanup-only` mode and a startup sweep that deletes any
namespace matching the prefix older than `--stale-after` (default 2 h). Cleanup
runs even after a panic (a `catch_unwind` at the top level) and even on
`SIGINT`/`SIGTERM` (a signal handler that triggers the same path and then
re-raises). Failure to clean up is reported but does not change the run's exit
status, because a red run whose only failure is cleanup teaches people to ignore
red runs.

---

## 6. Configuration

Flags for `flowsdn-connectivity test` (others as noted). Every flag also has an
environment variable `FLOWSDN_CONN_<UPPER_SNAKE>` and may be set in a config
file passed with `--config`; precedence is flag > env > file > default.

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--kubeconfig`, `--context` | path, string | env / current | cluster selection |
| `--multi-cluster` | string | — | second context; enables §3.3.11 |
| `--namespace-prefix` | string | `flowsdn-test` | §3.1.1 |
| `--test` | string list | all | §5.2 selector with `!` negation |
| `--test-concurrency` | u32 | 1 | §5.3 |
| `--include-unsafe-tests` | bool | false | enables scenarios that disrupt the cluster |
| `--require-feature` | string, repeatable | — | §5.2; a skip for this feature becomes a failure |
| `--require-hubble` | bool | false | a skipped flow assertion becomes a failure |
| `--hubble` | bool | auto | use Hubble assertions at all |
| `--hubble-mode` | `relay`\|`per-node` | `relay` | §3.4.3; CI explicitly selects `per-node` (#227) |
| `--flow-settle` | duration | 2s | §3.4.3 |
| `--flow-timeout` | duration | 30s | max wait for a flow assertion's cardinality |
| `--external-ip`, `--external-other-ip`, `--external-ipv6`, `--external-other-ipv6` | IP | discovered | §3.1.4 |
| `--external-cidr`, `--external-cidrv6` | CIDR | discovered | §3.1.4 |
| `--external-target`, `--external-other-target` | name | `external.flowsdn.test` | §3.1.4 |
| `--dns-service` | ns/name | discovered `kube-system/kube-dns` | §3.1.4 |
| `--ip-family` | `v4`\|`v6`\|`dual`\|`auto` | auto | overrides detection |
| `--probe-timeout` | duration | 5s | per attempt |
| `--probe-retries` | u32 | 3 | §5.6 |
| `--scenario-timeout` | duration | 3m | hard cap per scenario |
| `--run-timeout` | duration | 60m | hard cap per run; on expiry, sysdump then fail |
| `--image` | ref | the release testpod image | `flowsdn-testpod` override |
| `--image-pull-policy` | enum | `IfNotPresent` | |
| `--nodes` | string list | auto | pin nodes A and B explicitly |
| `--expected-drop-reasons` | list | `[]` | additional drop reasons `no-unexpected-drops` tolerates; `+name` adds to the default set |
| `--expected-xfrm-errors` | list | `+inbound_no_state` | §3.3.8 |
| `--leak-check` | `capture`\|`kprobe`\|`off` | `capture` | §3.3.8 |
| `--capture-limit` | size | 64MiB | §3.4.4 |
| `--capture-save` | bool | false | keep pcaps in the sysdump |
| `--collect-sysdump-on-failure` | bool | false (true in CI) | §3.8 |
| `--sysdump-output` | path | `./flowsdn-sysdump-<ts>.tar.zst` | |
| `--sysdump-hubble-flows-count` | u64 | 1000000 | §3.8 |
| `--sysdump-hubble-flows-timeout` | duration | 5m | §3.8 |
| `--sysdump-max-size` | size | 2GiB | §3.8 |
| `--redact` | string list | — | extra redaction patterns |
| `--output` | repeatable | `human` | `human`\|`json[=path]`\|`junit=path`\|`markdown[=path]` |
| `--junit-property` | `k=v`, repeatable | — | §4.5 |
| `--no-cleanup` | bool | false | leave the topology for debugging |
| `--cleanup-only` | bool | false | delete and exit |
| `--stale-after` | duration | 2h | startup sweep |
| `--dump-manifests` | path | — | §4.6 |
| `--feature` | `k=v`, repeatable | — | override detection |
| `--perf` | bool | false | include §3.7 (also `perf` subcommand) |
| `--perf-baseline` | path | `tests/perf-baselines` | §3.7 |
| `--interop`, `--peer-version` | bool, string | false, latest 1.20.x | §3.5 (also `interop` subcommand) |
| `--conn-disrupt-state` | path | `./flowsdn-conn-disrupt.json` | §3.6 |
| `--conn-disrupt-interval` | duration | 0ms | §3.6 |
| `--conn-disrupt-l7` | bool | false | include the L7 flow in `must-survive` |
| `--log-level` | enum | info | |
| `--quarantine` | path | `tests/quarantine.toml` | §5.6 |

Exit codes: `0` all passed (skips and warns allowed); `1` one or more scenarios
failed; `2` setup or cleanup error (the cluster was never in a testable state);
`3` invalid invocation (including a `--test` expression matching nothing); `4`
run timeout.

---

## 7. Failure modes

| Failure | Behaviour |
|---|---|
| API server unreachable at start | exit 2, no partial topology |
| API server becomes unreachable mid-run | retry with backoff for `--api-retry-budget` (60 s); then abort with exit 2, collect what sysdump it can |
| An agent is not ready | the run waits (barrier) up to 5 min, then fails setup with a per-node readiness table. A run against a half-ready cluster produces meaningless results and must not proceed. |
| A node has no agent and none was expected | detected as `has-node-without-agent`; world rows use it. Not an error. |
| Hubble unavailable | flow assertions `skipped` (or the run fails with `--require-hubble`); probes still run |
| Hubble ring overflow during a scenario | `LostEvent` records are counted; if any lost event falls inside an assertion window, the assertion is `Warned`, not `Failed` — a lost flow is not evidence of absence. The lost count is reported and, above `--max-lost-flows` (default 1000), fails the run as an observability regression. |
| A pod fails to schedule | setup failure naming the node, its taints and its allocatable; not a scenario failure |
| The image cannot be pulled | setup failure with the image ref and the node's events |
| A policy fails validation | setup failure for that scenario only; other scenarios continue |
| A scenario exceeds `--scenario-timeout` | `Failed{timeout}`, quick-set collected, run continues |
| Cluster left dirty by a previous run | startup sweep (§5.7) deletes stale namespaces; a namespace stuck `Terminating` past 60 s is reported and the run uses a new suffix rather than blocking |
| The suite crashes | `catch_unwind` → cleanup → exit 2 with the panic message and a backtrace in the report |
| Concurrent runs against one cluster | namespace prefixes differ; cluster-scoped objects (CCNP, CEGP, LB pools) are prefixed too, and a scenario needing an exclusive cluster-scoped object takes a lease (a `coordination.k8s.io/Lease` named `flowsdn-connectivity-exclusive`) so two runs serialise instead of corrupting each other |
| An assertion's flows never arrive | after `--flow-timeout`, the assertion fails with the flows that *did* arrive attached, so the diff is visible |

---

## 8. Observability

The suite is a test tool, so its observability is its report — but three things
are exposed for CI:

- **Live progress**: a line per scenario as it completes, with duration and
  status, written to stderr; `--output=human` adds a final table grouped by
  scenario group with counts and the slowest ten scenarios.
- **A step summary**: `--output=markdown` produces the table CI writes to
  `$GITHUB_STEP_SUMMARY`, plus the feature-set table (the equivalent of the
  reference's `features status -o markdown`).
- **Structured logs**: `--log-format=json` emits one JSON object per event
  (scenario start/end, probe, assertion, barrier wait with its duration) so a
  slow run can be profiled without instrumenting the suite. Barrier durations in
  particular are the fastest way to find out that the run is slow because policy
  propagation is slow — which is a product signal, not a test signal, and §3.7
  turns it into a gate.

The suite emits no metrics endpoint and no telemetry.

---

## 9. Test plan (for the suite itself)

A test suite that is not itself tested fails open. Marked `u` unit, `i`
integration (against a fake or a throwaway kind cluster), `e` e2e.

Selection and reporting:

- [ ] `u` `--test` selector: prefix, exact, group, negation, combinations
- [ ] `u` a `--test` expression matching nothing exits 3
- [ ] `u` `--require-feature` converts a skip to a failure; a skip always carries a non-empty reason
- [ ] `u` scenario catalogue: every id unique, kebab-case, present in `list`
- [ ] `u` every scenario has at least one probe **or** at least one flow assertion
- [ ] `u` every `Deny` expectation names a `DenyKind` other than `Any`, or carries a comment justifying `Any`
- [ ] `u` JUnit XML validates against the schema; every failure `type` is in the closed set; properties present
- [ ] `u` `RunReport` JSON round-trips; the report is stable across two runs with the same inputs modulo timings
- [ ] `u` exit codes for each of the five cases

Feature detection:

- [ ] `u` precedence override > agent API > ConfigMap > inspection
- [ ] `u` an agent/ConfigMap disagreement produces a warning, not a wrong answer
- [ ] `u` per-node config differences produce the intersection for cluster-wide features
- [ ] `i` detection against recorded `/v1/config` and ConfigMap fixtures for each of the §10.2 datapath configurations, with a golden `FeatureSet` per fixture

Probing:

- [ ] `u` `error_class` mapping from errno for refused / timeout / unreachable / reset
- [ ] `i` probe agent: each `ProbeKind` against a local server; `/whoami` reports the right peer
- [ ] `i` `Deny(PolicyDrop)` is not satisfied by a `Refused` result
- [ ] `i` retries are counted and a retry-only pass is marked `flaky`
- [ ] `i` `HoldOpen` detects a single dropped packet as a sequence gap

Flow assertions:

- [ ] `u` `FlowAssertion` evaluation against recorded flow fixtures (a JSONL corpus checked in), one fixture per assertion shape in §3.4.3
- [ ] `u` the assertion evaluator and the agent's server-side filter agree on the same corpus (the shared-crate invariant)
- [ ] `u` a `LostEvent` inside a window downgrades a failed assertion to `Warned`
- [ ] `i` per-node vs relay mode produce the same verdicts on the same cluster

Barriers and cleanup:

- [ ] `i` every barrier returns as soon as its signal is true (asserted by injecting the signal and measuring)
- [ ] `u` the source tree contains no `sleep` outside `--flow-settle` and the backoff helper
- [ ] `i` cleanup runs after a panic and after SIGTERM
- [ ] `i` the stale-namespace sweep deletes only namespaces matching the prefix and older than the threshold
- [ ] `i` two concurrent runs against one cluster both pass

Sysdump:

- [ ] `i` a sysdump from a healthy cluster contains every group in §3.8 and a `MANIFEST.json` with no collection errors
- [ ] `i` a sysdump with one node unreachable still completes, and records the error
- [ ] `u` redaction: no Secret `data`, no key material, in any collected file (asserted by scanning the archive for the known test key)
- [ ] `i` `--sysdump-max-size` truncation order is flows, then map dumps, and is recorded

End to end:

- [ ] `e` full run against a 3-node kind cluster in the default configuration: all scenarios pass, runtime within budget (§10.6)
- [ ] `e` a deliberately broken cluster (an endpoint's policy map entry deleted out from under the agent) produces a failure that names the right scenario and whose sysdump contains the offending map dump
- [ ] `e` `conn-disrupt setup`/`check` across an agent restart: zero gaps
- [ ] `e` `conn-disrupt check` **fails** when a deliberate 2 s datapath outage is injected — proving the disruption detector detects disruption
- [ ] `e` quarantine: a quarantined failing scenario yields `Warned`; the same entry past its expiry fails the run

---

## 10. Kernel, platform and the CI matrix

### 10.1 What the suite itself needs

The suite binary needs only a Kubernetes API endpoint; it runs on the CI runner
or a laptop, on either arch. The **testpod** needs `CAP_NET_RAW` for ICMP and
capture modes and `hostNetwork` for the host rows; the **capture** mode
additionally needs to run on the node under test. The `--leak-check=kprobe`
mode needs `CAP_BPF` + `CAP_PERFMON` and a kernel with kprobe BPF (every kernel
in the matrix). Nothing in the suite requires a kernel feature beyond what
`docs/kernel-requirements.md` §2.5 already demands of flowsdn itself.

### 10.2 Datapath configurations under test

Taken from `docs/kernel-requirements.md` §5.3's recommendation (the reduced set
of the reference's 41 upgrade-matrix configs):

| Config id | Settings |
|---|---|
| `vxlan-kpr` | tunnel vxlan, kube-proxy-replacement true, SNAT, veth, IPv4 |
| `native-kpr-dsr` | routing native, KPR true, DSR, endpoint routes, IPv4 |
| `geneve-dsr` | tunnel geneve, KPR true, DSR-Geneve, IPv4 |
| `wireguard` | vxlan + WireGuard, node encryption on |
| `ipsec` | vxlan + IPsec, both cipher suites, strict egress off |
| `egressgw` | native + KPR + egress gateway + masquerade |
| `hostfw` | vxlan + KPR + host firewall |
| `ipv6only` | IPv6-only, vxlan, KPR |
| `dualstack` | dual-stack, vxlan, KPR |
| `netkit` | netkit device mode (6.12+ rows only) |
| `l7` | vxlan + KPR + L7 proxy + Ingress |
| `kubeproxy` | KPR false, kube-proxy present (the "we do not own the services" path) |

### 10.3 Cluster provisioning

**x86-64.** `kind` inside an LVH VM, exactly as the reference does: an LVH kernel
image (`quay.io/lvh-images/kind:<kernel>-<date>`) boots a VM, `kind` runs inside
it, so the kernel under test is the VM's. Cluster shape for the gating job: 1
control-plane + 2 workers + **1 worker with no agent** (labelled
`flowsdn.io/no-agent`, tainted so nothing else schedules there), a secondary
docker network attached (`--secondary-network`) so multi-device rows are real,
and one external-target container on the kind network. Provisioning is
`tools/ci/cluster.sh` in flowsdn (a thin wrapper over `kind` and the LVH runner
action), not `contrib/scripts/kind.sh` copied from the reference.

Additionally, the **stormcos row**: a Rocky 10 VM running the exact
`kernel-6.12.0-2xx.el10` stormcos pins, with `kind` inside it. This is the only
row that tests the kernel flowsdn actually ships on, and it is a PR gate.

**arm64 — the honest position.** There is no LVH arm64 image; the reference has
no arm64 kernel VMs at all (its arm64 coverage is image builds and Go
integration tests on arm64 runners). So flowsdn has to build this itself. The
options, with what each actually gives:

| Option | Gives | Costs / limits |
|---|---|---|
| (a) GitHub-hosted arm64 runners (`ubuntu-24.04-arm`) | real arm64 CPU, `kind` works, fast | the runner's kernel is Ubuntu's, **not** 6.12-el10 or an LVH image — so this row tests the arch, not the kernel. Private-repo arm64 minutes are billed. |
| (b) Self-hosted arm64 runner on the **Rose / stormcos nodes** | real arm64 **and** the real kernel **and** the real NIC drivers (`al_eth` — the one that has no `ndo_bpf`, per kernel-requirements §5.1) | needs the nodes registered as Actions runners and reachable; capacity is finite; a broken test can take a real node down |
| (c) QEMU `aarch64` (TCG) on `<build-host>` | any kernel, including a Rocky 10 aarch64 or an upstream 6.6/6.18 build; no extra hardware | ~10–20× slower under TCG. Fine for the verifier and `BPF_PROG_RUN` unit-test rows (CPU-light, per kernel-requirements §5.3); **too slow for a full e2e connectivity run** — a 15-minute run becomes hours. |
| (d) An Ampere/Graviton cloud VM, nested `kind` | real arm64 with a chosen kernel | recurring cost; another environment to maintain |

**Recommendation.** Use all three of (a), (b), (c), for different jobs, and do
not pretend any one of them covers arm64 on its own:

1. **PR gate, arm64**: nothing. Verifier complexity is arch-independent
   (kernel-requirements §5.2), so the x86 verifier gate covers the load path;
   the arm64 JIT gates are covered by the nightly BPF unit tests. Making a PR
   wait on arm64 e2e would be paying a large latency cost for a small marginal
   signal.
2. **Nightly, arm64 e2e**: option (b) — a 3-node cluster on the Rose/stormcos
   arm64 nodes, provisioned by stormboot golden clone swap rather than `kind`
   (these are real nodes; there is no docker-in-docker to nest), running the
   `vxlan-kpr`, `native-kpr-dsr` and `wireguard` configs. This is the row that
   catches an arm64 JIT bug, a 64K-page perf-ring bug, and the `al_eth`/XDP
   reality. It is the highest-value arm64 signal available and it uses hardware
   that already exists.
3. **Nightly, arm64 arch smoke**: option (a) — one `kind` run of the
   `vxlan-kpr` config on a GitHub arm64 runner, purely to catch "the arm64
   binary does not start" and "the arm64 image is wrong" quickly and
   independently of the Rose cluster's availability.
4. **Nightly, arm64 kernel matrix (non-e2e)**: option (c) on `<build-host>` — QEMU
   aarch64 VMs at 6.6, 6.12 and 6.18 running the verifier and `BPF_PROG_RUN`
   rows only, per kernel-requirements §5.3. Their VM images and the build
   outputs live under `/build/images` and `/build/cache`, never on the SSD root
   and never in `/tmp` (per the cross-project rules).

`<build-host>` is also the natural host for the **nightly x86-64 matrix**: it has
the 2 TB `/build` volume for LVH images and sysdumps, and running the long
matrix there keeps GitHub-hosted minutes for the PR gate. Register it as a
self-hosted runner with a label (`flowsdn-dev-x86`).

### 10.4 The CI matrix

Legend: **PR** = required check on every pull request; **merge** = runs on the
merge queue / after merge to `main`; **nightly** = scheduled; **weekly** = once.

| Job | Config × kernel × arch | When | Budget |
|---|---|---|---|
| `e2e-smoke` | `vxlan-kpr`, 6.12 (LVH), x86-64, 3-node kind | **PR** | 12 min |
| `e2e-stormcos` | `vxlan-kpr`, Rocky 10 `6.12.0-el10`, x86-64 | **PR** | 15 min |
| `e2e-core` | `native-kpr-dsr`, `geneve-dsr`, `hostfw` on 6.12 x86-64 | **PR** (3 parallel) | 20 min each |
| `e2e-encryption` | `wireguard`, `ipsec` on 6.12 x86-64 | **PR** (2 parallel) | 25 min each |
| `e2e-ipv6` | `ipv6only`, `dualstack` on 6.12 x86-64 | **PR** (2 parallel) | 20 min each |
| `e2e-l7` | `l7` on 6.12 x86-64 | **PR** | 25 min |
| `conn-disrupt-restart` | `vxlan-kpr` 6.12 x86-64, agent restart only | **PR** | 10 min |
| `e2e-full-matrix` | all 12 configs × {6.6, 6.12, 6.18} x86-64 | nightly | ~6 h wall, parallel |
| `e2e-egressgw`, `e2e-netkit`, `e2e-kubeproxy` | on 6.12 and 6.18 x86-64 | nightly | 25 min each |
| `e2e-upgrade` | previous minor → PR build → downgrade, `vxlan-kpr` + `ipsec` + `wireguard`, 6.12 x86-64, with `conn-disrupt` around each step | nightly, and **PR** for the `vxlan-kpr` row only | 45 min (PR row: 25 min) |
| `e2e-arm64-rose` | `vxlan-kpr`, `native-kpr-dsr`, `wireguard` on the Rose 3-node arm64 cluster, kernel 6.12 el10 aarch64 | nightly | 40 min |
| `e2e-arm64-smoke` | `vxlan-kpr` on a GitHub arm64 runner, kind | nightly | 15 min |
| `arm64-verifier-bpftest` | verifier + `BPF_PROG_RUN` on QEMU aarch64 6.6/6.12/6.18 (`<build-host>`) | nightly | 90 min |
| `e2e-clustermesh` | two kind clusters, `vxlan-kpr` and `wireguard`, 6.12 x86-64 | nightly | 45 min |
| `e2e-interop` | §3.5, 4-node kind, 6.12 x86-64 | nightly | 30 min |
| `e2e-bgp` | `misc`-style config + a containerised peer, 6.12 x86-64; and the RouterOS peer on the Rose cluster | nightly (kind), weekly (RouterOS) | 25 min |
| `perf-smoke` | §3.7 on a fixed-shape 2-node cluster, 6.12 x86-64 and arm64 Rose | nightly | 40 min |
| `scale-smoke` | §3.7 scale rows, 6.12 x86-64, 5 nodes | nightly | 40 min |
| `e2e-canary` | `vxlan-kpr` on the newest LVH kernel available | weekly, non-blocking | 20 min |
| `k8s-conformance` | upstream `[sig-network]` e2e and NetworkPolicy e2e, `vxlan-kpr` 6.12 | nightly | 90 min |

The PR set totals roughly **10 jobs, ~25 min wall clock** with parallelism,
which is the design target: a PR gate longer than half an hour stops being used.
The choice of what is on the PR gate follows one rule — a PR job must catch a
regression that a *typical* change can cause. Encryption and IPv6 are on the
gate because the datapath crates are shared and a change to conntrack breaks
them silently; ClusterMesh and interop are not, because they break for
environmental reasons and would train people to ignore red.

### 10.5 Failure routing

| Job class | On failure |
|---|---|
| PR gate | blocks the PR |
| nightly x86-64 | opens/updates a single tracking issue per job with the sysdump attached; three consecutive failures escalate to blocking the next release |
| nightly arm64 Rose | same, plus a note that a hardware/environment cause must be ruled out before treating it as a code regression |
| interop | files an issue tagged `interop`, never blocks a PR; a change in upstream behaviour is a finding, not a flowsdn bug |
| canary | never blocks; a failure is a heads-up about the next kernel |
| perf/scale | a `performance-regression` failure opens an issue with the baseline, the measurement and the spread; it blocks a release, not a PR |

Every job uploads: the JUnit XML, the `RunReport` JSON, the feature-set
markdown into the step summary, and — on failure — the sysdump archive, retained
30 days (7 for nightly, to keep storage bounded).

### 10.6 Expected runtimes and the shape they assume

Measured budget for the reference implementation of this design, on a 3-node
kind cluster inside an LVH VM with 4 vCPU / 8 GiB:

| Phase | Budget |
|---|---|
| cluster provisioning (LVH boot + kind + flowsdn install + ready) | 4–6 min |
| topology install + readiness barriers | 45–75 s |
| feature detection | < 5 s |
| the §3.2 matrix (about 60 scenario instances with IPv4 only) | 3–5 min |
| policy scenarios (§3.3.1, applied and removed with barriers) | 3–4 min |
| L7 scenarios | 2–3 min |
| encryption scenarios incl. capture | 2–3 min |
| sysdump on failure | 1–4 min |
| cleanup | 30–60 s |

Dual-stack roughly doubles the matrix phase. The scale rows are deliberately
excluded from any job with a time budget under 30 minutes.

---

## 11. Rust design notes

**Crate**: `flowsdn-connectivity` (binary `flowsdn-connectivity`), plus the
companion binary crate `flowsdn-testpod`. Both are workspace members. Shared
pieces live in existing crates rather than being duplicated:

| Need | Crate |
|---|---|
| Kubernetes client, typed objects, apply, exec, pod proxy | `flowsdn-k8s` (spec 13) wrapping `kube` + `k8s-openapi` |
| Hubble protobuf types and the flow filter evaluator | `flowsdn-hubble-proto`, `flowsdn-hubble-filter` (spec 11) — the **same** filter crate the agent uses server-side |
| Agent REST client | `flowsdn-api-client` (spec 08) |
| Map dump formatting in the sysdump | `flowsdn-bpf-maps` / `flowsdn-dbg` (specs 01, 04, 05) |
| nftables ruleset read | `flowsdn-nft` (spec 10) |
| cBPF assembly for capture filters | `flowsdn-cbpf` (new, ~300 lines) |

**Dependencies** (all in the permitted licence set of `docs/licensing.md`):
`kube` + `k8s-openapi` (Apache-2.0) for orchestration; `tokio` for the runtime;
`tonic` + `prost` for the Observer gRPC client; `hyper`/`reqwest` for HTTP
probes (`rustls` only — no OpenSSL, so the binary stays static); `clap` for the
CLI; `serde`/`serde_json`; `quick-xml` for JUnit; `zstd` + `tar` for the
sysdump; `pnet_packet` or a hand-rolled parser for pcap writing; `socket2` for
raw and AF_PACKET sockets; `hdrhistogram` for the perf rows; `insta` for the
report snapshot tests. No `libc`-gated code outside the testpod's socket paths,
so the suite binary itself builds and runs on macOS for development (it only
talks to an API server), which matters because the repository's build rule keeps
compilation on `<build-host>` — the suite is one of the few crates a developer can
usefully `cargo check` locally.

**Exec without `kubectl`.** `kube::api::Api::<Pod>::exec` returns an
`AttachedProcess` giving `stdin`/`stdout`/`stderr` as async streams over the
API server's SPDY-or-WebSocket exec channel. That is the whole mechanism; there
is no `kubectl` and no subprocess. The pod **proxy** subresource
(`Api::<Pod>::request` against `…/pods/<name>:<port>/proxy/<path>`) is what
carries the probe-agent calls, and it is preferred over exec everywhere it
works, because it is one HTTP round trip rather than a session. Port-forward
(`Api::<Pod>::portforward`) is implemented as a fallback for clusters where the
proxy subresource is blocked by an admission policy.

**Concurrency model.** One `tokio` runtime. A scenario is an `async fn`; a
scenario group is a `JoinSet` bounded by `--test-concurrency`; the Hubble
streams last for one scenario group and write into bounded per-node windows.
Wait for every participating stream to become ready before sending traffic;
settle, cancel and join all streams before finishing that group. No stream or
flow collection carries into the next group.
Cancellation is by `tokio_util::sync::CancellationToken` so that
`--scenario-timeout` actually stops the work rather than leaving a task running
into the next scenario's window and polluting its flows.

**Timeouts.** Every await that touches the network has an explicit timeout;
there is a lint-level rule (a small `clippy.toml` disallowed-method entry plus a
review checklist item) that a bare `reqwest`/`kube` call without a timeout is
rejected. The hierarchy is probe (5 s) < barrier (per-barrier deadline) <
scenario (3 min) < run (60 min), each strictly smaller than its parent so a
timeout is attributed to the right level.

**Determinism.** No `HashMap` iteration in any output path (`BTreeMap`
everywhere the order reaches a report); a fixed RNG seed (`--seed`, default
derived from the run id and printed) for anything that samples; scenario order
is the catalogue order, not a set's order.

**Honest note: what upstream's Go suite does that this will not cover
initially.** Naming these so nobody discovers them by being surprised:

1. **Test count.** `cilium connectivity test` at v0.19 is roughly 32–70 tests
   and 250–300 actions depending on features. The first version of this suite
   targets the §3.2 matrix plus §3.3.1–3.3.4 — call it 90–120 scenario
   instances. Egress gateway, BGP reachability, ClusterMesh and interop land
   after, in that order.
2. **Ingress and Gateway API scenarios.** The reference has
   `pod-to-ingress-service`, `outside-to-ingress-service` and their deny
   variants. flowsdn's Ingress/Gateway support is a wave-4 spec; those scenarios
   are deferred until it exists.
3. **Local redirect policy** (`local-redirect-policy`,
   `local-redirect-policy-with-node-dns`). Deferred with LRP itself.
4. **Mutual authentication / SPIFFE** (`echo-ingress-mutual-auth-spiffe`,
   `echo-ingress-auth-always-fail`). Deferred: spec 16 defers mutual auth.
5. **TLS interception scenarios** (`client-egress-tls-sni`,
   `client-egress-l7-tls-headers`, `client-egress-l7-set-header`). These need
   the CA/secret plumbing; deferred to the second pass on L7.
6. **`network-perf` via netperf.** flowsdn uses its own generator (§4.1). The
   numbers will not be directly comparable to upstream's netperf numbers; where
   a comparison is wanted, run netperf manually. This is a deliberate trade for
   one image and no external binary.
7. **Code-owner attribution on failure** (`--log-code-owners`). Useful at
   upstream's contributor scale; not worth the machinery here.
8. **The `check-log-errors` scan** for `level=error` in agent logs is *not*
   deferred — it is cheap and valuable, and is implemented as a final scenario
   that reads every agent's log and fails on error lines outside an allowlist.
   Noting it here because it is easy to forget that it is part of what "the
   connectivity test passed" means upstream.
9. **Cloud-provider scenarios** (EKS/ENI, GKE, AKS): no flowsdn CI runs against
   a cloud provider. **Narrowed 2026-09-07 by ADR-0007**, which closes the half
   of this gap that mattered most: the cloud IPAM *control plane* — every mode
   of spec 07 §3.9–3.12, including the error and exhaustion paths — MUST become a
   pull-request gate using recorded provider responses replayed at the
   HTTP layer (spec 07 §9.1), with a weekly live-cloud drift check as the only
   credentialed job. What remains out of scope is genuinely end-to-end
   *datapath* testing on a cloud provider: no job runs this suite's §3.2 matrix
   on EKS, AKS or GKE, so ENI/Azure-attached pod interfaces, cloud-provider
   LoadBalancer Services, cloud-native routing MTUs and the per-endpoint policy
   routing of spec 07 §3.20 are exercised only in the `E` lane, which is
   manual. The gap therefore narrows rather than disappears, and the residual
   is stated precisely: **recorded replay must prove that flowsdn asks for the
   right addresses; it cannot prove that packets flow once allocated. Neither
   CI implementation nor live-cloud datapath validation is claimed here.**

---

## 12. Decisions and remaining questions

Resolved entries are normative decisions from [ADR-0013](../decisions/0013-integration-issue-resolutions.md); their implementation and acceptance tests remain required.

1. **Resolved #225: per-scenario-group Hubble streams.** Bound each node's
   flow window; wait for stream readiness before traffic, settle afterwards,
   cancel/join at group completion and discard the group index before starting
   another. Generation tokens reject late data from an earlier group. Overflow,
   lost-event markers and unexpected stream termination mark evidence incomplete;
   negative assertions must not pass from a partial sample. `FlowWindow` implements
   bounded group storage, token checks and explicit complete/abort results.
   Transport readiness, cancellation and actual Hubble RPCs remain work. Consider
   long-lived streams only after measured full runs exceed about twenty minutes
   and memory/latency measurements justify the change; no such result is claimed.
   Bounded historical ring queries are not a durable replacement for live capture.

2. **`--flow-settle` value.** 2 s is a guess carried from how long perf-ring
   drainage typically takes. *Recommendation*: measure the distribution of
   (packet time → flow arrival at the client) on the 6.12 x86 row during
   bring-up and set the default at p99.9 + 50%. Until measured, treat every
   flow-assertion flake as a settle-time question first.

3. **Resolved — #227.** Default interactive use to relay; CI explicitly sets per-node
   mode and obtains node membership from Kubernetes. Relay behavior has its own tests,
   so a broken relay cannot silently invalidate datapath assertions. Explicit user flags
   override the interactive default.

4. **Resolved — #228.** Perform encryption negative captures in a privileged test pod on
   each participating node using the Rust test probe. Do not add a test-only capture API
   to the production agent. Bound capture duration and size and clean up the pod after
   failures.

5. **Resolved #229/#241: dedicated physical arm64 nightly placement.**
   Use a reserved CI-only arm64 node set with real kernel/NIC coverage. Do not
   schedule destructive tests on shared workload nodes. A cloud arm64 lane is a
   later availability-driven option; QEMU remains suitable for separate verifier
   testing, not evidence about physical drivers. This fixes target placement, not
   a claim that nodes are allocated or a nightly job exists. Missing hardware
   leaves that acceptance outstanding, never a passing skip.

6. **Resolved — #230.** Keep e2e-encryption as a required PR gate once the encryption
   lane is implemented: both WireGuard and IPsec must verify confidentiality, not just
   successful traffic. Missing required encryption capability is a failed gate, not a
   passing skip.

7. **Resolved #231: weekly advisory upstream connectivity cross-check.**
   Run the real upstream `cilium connectivity test` against a disposable flowsdn
   cluster as an independent oracle. Pin and verify the CLI artifact; record its
   version with findings. It is never a Rust build dependency and failures do not
   block PRs automatically: triage them as compatibility findings. Scheduling,
   artifact provenance and successful executions remain unimplemented here.

8. **Resolved #232: no fabricated CT creation timestamp.** The frozen 56-byte
   `ct_entry` contains `lifetime` at 32 (absolute expiry), `last_tx_report` at 48
   and `last_rx_report` at 52 (mutable monitor times), **no creation timestamp**.
   Evidence: spec 04 §2.3 and `flowsdn-bpf-abi/src/ct.rs` layout assertions;
   inspected 2026-09-22. Do not expose any of these fields as created_at or alter
   the shared map ABI for this test. Hold the original map FD throughout the
   observation, compare kernel map IDs (not pin-path names/inodes), tuple keys
   and raw values during a quiesced sampling window, plus continued traffic
   survival. `quiesced_ct_reuse` classifies those observations. Map/tuple sampling,
   diagnostic JSON and live pin-replacement tests remain work. Same value/map
   evidence cannot prove entry-generation identity: delete/reinsert of identical
   data is unobservable without an independently designed generation marker.

9. **Resolved — #233.** Accept pinned upstream connectivity-test names as aliases in
   --test through an explicit mapping to canonical flowsdn scenario IDs. Expand aliases
   before applying inclusion/exclusion filters, deduplicate IDs, and retain the no-match
   error. Report canonical IDs and the alias mapping revision.

10. **Resolved #234: separate datapath churn from control-plane scale.**
    Retain five real nodes for the nightly datapath scale row. Add a separate
    weekly simulated-node job targeting at least 100 nodes after CES controllers
    can be exercised; measure control-plane object churn and reconciliation there.
    Synthetic nodes do not validate routing, drivers or packet throughput. The
    placement primitive distinguishes these lanes; no cluster, simulator job or
    100-node measurement has been provisioned or run by this change.

11. **Resolved #235: bounded evidence retention.** Keep a 10 MB decimal quick
    set for every run (seven days on success, fourteen on failure), plus full
    failure-only sysdumps capped at 2 GiB (fourteen days). Nightly flow capacity
    is 100,000; PR capacity 1,000,000. Existing truncation manifests remain
    required. Planning helpers are implemented; collection/upload wiring is not.

### Implementation boundary for the evidence primitives

`flowsdn-connectivity` is currently a library, not the e2e executable. It supplies
bounded per-group flow storage, CT observation comparisons and declarative lane
placements. It has no Hubble client, cluster provisioner, simulator, packet
traffic generator or workflow runner. The matrix above describes target gates;
its presence does not mean any row has been installed or passed. Payload sizes
and discovered node count must also be bounded by the eventual ingestion owner.
