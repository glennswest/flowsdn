# Inventory roll-up — flowsdn scope table

Reference: cilium v1.20.1 (7d68cfb394). One file per area; this table is the
summary and the scope decision. Effort is Rust lines to write: S < 2k,
M 2–8k, L 8–20k, XL > 20k. Decisions that override an area recommendation
are in `../decisions/` and noted in the last column.

**Amendments.** 2026-09-07 — build order clarified for **ADR-0006** (one
repository, one Cargo workspace): the ordering below is a crate dependency
order, not a repository or release split.

| # | Area | Reference size (non-test Go / BPF C) | Decision | Effort | Notes |
|---|---|---|---|---|---|
| 01 | [BPF datapath programs](01-bpf-programs.md) | 8k program + 23k lib C | keep | XL | ADR-0002 overrides: Rust (aya-ebpf), no C. First milestone (lxc/host/overlay, v4/v6, CT, policy, ClusterIP/NodePort SNAT, VXLAN, monitor) is L. |
| 02 | [BPF maps + loader](02-bpf-maps-loader.md) | 13k maps + 6k bpf + loader | keep ABI byte-for-byte; replace impl with aya | L | Map names/layouts kept so cilium-dbg/bpftool/Hubble decoders interoperate. Gaps in aya: map-in-map, batch ops, link update, netkit → raw-syscall shims. |
| 03 | [Datapath userspace + node](03-datapath-userspace-node.md) | 26k + 11k | keep; simplify bandwidth/BIG TCP/GARP; **replace iptables** | L | ADR-0003: nftables residual, no iptables/ipset. Defer netkit (≥ 6.7) behind veth. |
| 04 | [Load balancer](04-loadbalancer.md) | 15k + lbipam 2.5k + l2 1.7k | keep | L | LB IPAM M, L2 announcements S/M. Defer NAT46/64, socket termination. ADR-0004 replaces StateDB. |
| 05 | [Policy + identity](05-policy-identity.md) | 33k | keep | XL | Tier-based engine (Admin/Normal/Baseline), aggregate identities 11–14, KCNP instead of ANP. Defer kvstore identity backend, toGroups. |
| 06 | [Agent core, endpoints, API](06-agent-endpoint-api.md) | ~45k incl. cilium-dbg | keep, byte-compatible API/state dir/config keys | L | 539 flags, 47 REST ops, 8-state endpoint machine. ADR-0004 replaces Hive. XL if flowsdn-dbg + bugtool in same phase. |
| 07 | [IPAM incl. cloud](07-ipam-cloud.md) | ipam 8.4k + aws 5k + azure 2.7k + alibaba 2.9k + operator ipam 6.8k | keep, all cloud modes | XL (~23k) | ENI in 1.20 uses the multi-pool manager + CIDR release; drop the 1.19 ENI compat path. GKE has no GCP API code (ipam=kubernetes + native routing). AWS/Azure have Rust SDKs; Alibaba needs an own signed REST client. |
| 08 | [Operator](08-operator.md) | 48k (38k excl. IPAM/LB IPAM) | keep core; defer Gateway API/Ingress until Envoy path exists | M core, L→XL with Gateway API | Drop SPIRE (deprecated 1.20), ztunnel, four cloud binary variants → one binary. |
| 09 | [Hubble + monitor](09-hubble-monitor.md) | 18k + monitor 4.5k + relay | keep server/parser/metrics/exporter; relay separate binary | L (+M relay) | Recorder gone upstream: not ported. Parser lives in-agent (needs six internal tables). gob monitor socket: implement subset. |
| 10 | [BGP](10-bgp.md) | 13.6k + operator 1.4k | keep; **replace GoBGP with own minimal speaker** + RouterOS advertiser backend | L | Export-only, small RFC surface. No usable embeddable Rust speaker exists. Defer BFD, ADD-PATH, v2alpha1. |
| 11 | [L7 proxy, DNS, auth, mesh](11-l7-proxy-dns-auth-mesh.md) | envoy 12k + proxy 2.7k + fqdn 7.6k + auth 2.2k + ztunnel 6.2k | keep xDS driver + DNS proxy; defer mutual auth (deprecated); ztunnel defer-then-keep | L + L + M | Only HTTP and DNS L7 rules remain (Kafka/proxylib gone). Envoy reads the pinned ipcache map directly, so the ipcache ABI is part of the Envoy contract. Envoy stays an external image (ADR-0001). |
| 12 | [ClusterMesh + kvstore](12-clustermesh-kvstore.md) | kvstore 6.9k + clustermesh 11.9k + apiserver 3k | keep client/store/schema/agent import + kvstoremesh; replace etcd sidecar with fastetcd | M+M+M (~14k) | Defer MCS-API, EndpointSlice v2. fastetcd compatibility checklist in file. |
| 13 | [CRDs + k8s integration](13-crds-k8s.md) | k8s 66k (slim 27k, apis 16k, client 12k) + 20k lines CRD YAML | keep; vendor CRD YAML verbatim, kube-derive types with CI diff test | L (15–18k) | 22 CRDs tabulated field by field. Agent uses JSON/strategic/merge patch, never server-side apply; CiliumEndpoint has no status subresource. API-server capability list for rustkube is in the file. |
| 14 | [Encryption + egress](14-encryption-egress.md) | 7.4k + 2.3k BPF | keep WireGuard, IPsec (staged), egress gateway, ip-masq-agent; defer VTEP, SRv6 | M | IPsec XFRM + rotation is the risk. Egress gateway HA/status is a candidate improvement. |
| 15 | [Helm, images, CI, tests](15-helm-images-ci-tests.md) | chart + Dockerfiles + workflows | keep as contract, replace as implementation | M ×5 | Single static binary with init subcommands; reuse upstream Envoy/Hubble UI/relay images; adopt cilium-cli connectivity test + verifier matrix as gates. |

## Totals (15 of 15 areas)

Rough Rust estimate from the per-area numbers: **200–260k lines** including
tests for full scope. Datapath (01+02), policy (05), agent core (06), IPAM
incl. cloud (07) and CRDs (13) are about two thirds of it. Gateway API translation (08) and MCS-API (12) are
the largest deferrable blocks.

## Cross-area decisions raised by the inventories

- ADR-0002 Rust only, incl. BPF programs — raised by 01, 02.
- ADR-0003 nftables residual, no iptables — raised by 03, 15.
- ADR-0004 no Hive, no StateDB; explicit composition + table crate — raised by 04, 06, 08, 09.
- Open: verifier budget of a single all-features BPF object per hook on the
  minimum kernel (01); whether to keep 5.10 as floor at all under ADR-0002.
- Open: egress gateway health failover + CRD status as a flowsdn improvement (14).
- Open: identity management mode default, CES slim-mode-first (08).

## Build order (dependency-driven)

The order in which crates are *written*, inside the single workspace of
ADR-0006. It is not a repository split and not a release sequence: every crate
below lives in the same tree and is versioned once, so a step here can be
revisited without a cross-repository migration. `flowsdn-bgp-proto` (step 10)
and `flowsdn-scripttest` (built ahead of step 5, per ADR-0005) are the only two
crates ADR-0006 names as candidates for later extraction and publication, and
only once their APIs have stopped moving.

1. `flowsdn-table` (ADR-0004), config/flag registry, netlink layer.
2. BPF map ABI crate + loader (02), then datapath programs first milestone (01).
3. Agent skeleton, IPAM (07), endpoint manager, CNI plugin (06).
4. Identity + ipcache + policy → maps (05).
5. Service LB → maps (04).
6. Node model, routes, neighbors, sysctl, MTU, nftables residual (03).
7. Monitor + Hubble server (09).
8. Operator core (08), CRDs (13).
9. WireGuard, then IPsec; egress gateway (14).
10. BGP speaker + RouterOS backend (10).
11. Envoy integration, DNS proxy (11). Then Gateway API/Ingress (08).
12. ClusterMesh (12).
