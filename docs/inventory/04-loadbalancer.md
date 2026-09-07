# Service load balancing (kube-proxy replacement) — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/loadbalancer/**`
(root types, `cell`, `writer`, `reflectors`, `reconciler`, `maps`,
`healthserver`, `redirectpolicy`, `benchmark`, `repl`, `tests`), `pkg/maglev`,
`pkg/l2announcer`, `pkg/datapath/l2responder`, `operator/pkg/lbipam`,
`pkg/lbipamconfig`, `pkg/kpr`, `daemon/healthz/kube_proxy_healthz.go`,
`pkg/k8s/endpoints.go` (EndpointSlice parsing), `pkg/annotation/k8s.go`
(service annotations), `pkg/k8s/apis/cilium.io/v2/{clrp,lbipam}_types.go`,
`pkg/k8s/apis/cilium.io/v2alpha1/l2announcement_types.go`. Datapath side
(`bpf/lib/lb.h`, `bpf/bpf_sock.c`) is read only for semantics; another
inventory documents map layouts and programs.

Note on paths named in the task that do not exist at this tag:
`pkg/redirectpolicy` moved to `pkg/loadbalancer/redirectpolicy`,
`pkg/maps/lbmap` moved to `pkg/loadbalancer/maps`, `pkg/service` is gone
(replaced by the StateDB tables + `writer`), and `pkg/k8s/watchers` no longer
watches Services/EndpointSlices (only CiliumNode, CEP/CES, Pod); the LB
reflector owns its own ListerWatchers.

## Purpose

Replaces kube-proxy. Turns Kubernetes `Service` + `EndpointSlice` (+ Pod
hostPorts, CiliumLocalRedirectPolicy, ClusterMesh remote services,
CiliumEnvoyConfig L7 redirects, a YAML/JSON state file) into three StateDB
tables — services, frontends, backends — and reconciles frontends into the BPF
LB maps (`cilium_lb{4,6}_services_v2`, `_backends_v3`, `_reverse_nat`,
`_affinity`, `_source_range`, `_maglev`, `_reverse_sk`, `cilium_skip_lb{4,6}`).
Also allocates service IDs and backend IDs, builds Maglev lookup tables,
runs the `healthCheckNodePort` HTTP servers, the kube-proxy-compatible
`/healthz`, socket termination for deleted backends, and (operator side) LB
IP allocation (LB IPAM) and (agent side) L2 announcement leases feeding the
ARP/ND responder.

## Components

| Path | Lines (non-test / test) | Purpose |
|---|---|---|
| `pkg/loadbalancer/*.go` | 3264 / 1416 | Core types: `Service`, `Frontend`, `Backend`, `L3n4Addr`, `ServiceName`, flags, config (`UserConfig`/`Config`/`ExternalConfig`), table definitions and indexes |
| `pkg/loadbalancer/config.go` | 581 (in above) | All `bpf-lb-*`, `node-port-range`, `enable-health-check-*`, `enable-service-topology` flags and validation |
| `pkg/loadbalancer/writer` | 1249 / 1562 | `Writer`: the only mutation API; keeps frontend↔service↔backend references, backend selection (traffic policy, topology), NodePort-address and zone watchers |
| `pkg/loadbalancer/reflectors` | 1898 / 145 | k8s Service/EndpointSlice/Pod(hostPort) → tables; batching; annotation handling; file reflector (`--lb-state-file`) |
| `pkg/loadbalancer/reconciler` | 2221 / 2118 | `BPFOps`: frontend → BPF maps, ID allocators, restore-from-maps, pruning, Maglev updates, source ranges, wildcard entries; socket termination job |
| `pkg/loadbalancer/maps` | 3357 / 0 | `LBMaps` interface + `BPFLBMaps` (real) + fake; key/value Go structs; `cilium-dbg lb/maps-dump`; pressure metrics; SkipLB map |
| `pkg/loadbalancer/healthserver` | 372 / 245 | `healthCheckNodePort` HTTP servers (kube-proxy compatible JSON) |
| `pkg/loadbalancer/redirectpolicy` | 1846 / 229 | CiliumLocalRedirectPolicy: CRD parse → table → controller → frontends `RedirectTo` + `cilium_skip_lb` netns-cookie map |
| `pkg/loadbalancer/cell` | 165 / 58 | Hive wiring, `GET /service` REST handler, init-wait promise |
| `pkg/loadbalancer/benchmark`, `repl`, `tests` | 643+119 / 18+16+429 | Throughput benchmark (~50k svc/s), standalone REPL, 51 txtar end-to-end script tests |
| `pkg/maglev` | 360 / 249 | Maglev permutation + lookup table with weights, murmur3 seeding |
| `pkg/l2announcer` | 1229 / 1193 | CiliumL2AnnouncementPolicy → per-service `coordination.k8s.io/Lease` leader election → `Table[L2AnnounceEntry]` |
| `pkg/datapath/l2responder` | ~430 / — | `Table[L2AnnounceEntry]` → `cilium_l2_responder_v4/v6` maps + gratuitous ARP/NA on new entry |
| `operator/pkg/lbipam` + `pkg/lbipamconfig` | 2516+40 / 3621 | CiliumLoadBalancerIPPool → `.status.loadBalancer.ingress`, sharing keys, conditions |
| `pkg/kpr` | ~50 / — | `--kube-proxy-replacement`, `--bpf-lb-sock` |
| `daemon/healthz/kube_proxy_healthz.go` | ~130 / — | `/healthz` on `--kube-proxy-replacement-healthz-bind-address` |
| `pkg/k8s/endpoints.go` (part) | ~250 relevant | `ParseEndpointSliceV1`: conditions, zone, hints, `service.cilium.io/weight` |

Totals: ~19.7k non-test Go lines (core LB ~15.1k, Maglev 0.4k, L2 ~1.7k, LB IPAM 2.5k), ~11.3k test lines. Datapath C for LB (`bpf/lib/lb.h`, `bpf_sock.c`, nodeport) is counted in the BPF inventory.

## Features

### Configuration options (agent, `pkg/loadbalancer/config.go`, `pkg/kpr`, `pkg/maglev`, `pkg/option`)

| Flag | Default | Effect |
|---|---|---|
| `--kube-proxy-replacement` | false | Master switch; NodePort/LB/HostPort frontends only programmed when true; forces `--bpf-lb-sock` |
| `--bpf-lb-sock` | false | Socket-level (cgroup) E/W load balancing |
| `--bpf-lb-sock-hostns-only` | false | Socket LB only for host-netns sockets |
| `--bpf-lb-sock-terminate-pod-connections` | false | Also destroy sockets inside pod netns on backend removal |
| `--lb-sock-terminate-all-protos` (hidden) | false | Terminate TCP as well as UDP sockets |
| `--bpf-sock-rev-map-max` | dynamic (`SockRevNATMapEntriesDefault`, LRU-aligned) | `cilium_lb{4,6}_reverse_sk` size |
| `--bpf-lb-map-max` | 65536 | Default size for all LB maps |
| `--bpf-lb-service-map-max`, `--bpf-lb-service-backend-map-max`, `--bpf-lb-rev-nat-map-max`, `--bpf-lb-affinity-map-max`, `--bpf-lb-source-range-map-max`, `--bpf-lb-maglev-map-max` (hidden) | 0 = inherit | Per-map overrides |
| `--node-port-range` | `30000,32767` | NodePort range; HostPorts inside it are refused |
| `--nodeport-addresses` | empty | CIDR whitelist for NodePort addresses (node area) |
| `--bpf-lb-mode` | `snat` | `snat` / `dsr` / `hybrid` |
| `--bpf-lb-mode-annotation` | false | Honour `service.cilium.io/forwarding-mode`; hybrid default not allowed |
| `--bpf-lb-dsr-dispatch` | `opt` | `opt` / `ipip` / `geneve` |
| `--bpf-lb-algorithm` | `random` | `random` / `maglev` |
| `--bpf-lb-algorithm-annotation` | false | Honour `service.cilium.io/lb-algorithm` |
| `--bpf-lb-maglev-table-size` | 16381 | M, one of the 10 supported primes |
| `--bpf-lb-maglev-hash-seed` | `JLfvgnHc2kaSUFaI` | 12-byte base64 seed, cluster-wide |
| `--bpf-lb-external-clusterip` | false | ClusterIP reachable from outside |
| `--bpf-lb-source-range-all-types` | false | Apply `loadBalancerSourceRanges` to ClusterIP/NodePort too |
| `--bpf-lb-enable-wildcard-entries` (hidden) | true | Program `(vip, 0, ANY)` drop entries |
| `--bpf-lb-nat46x64` | false | Compile `ENABLE_NAT_46X64` |
| `--bpf-lb-acceleration` / `--node-port-acceleration` | `disabled` | XDP NodePort (`native`, `best-effort`) |
| `--enable-health-check-nodeport` | true | `healthCheckNodePort` servers |
| `--enable-health-check-loadbalancer-ip` | false | Expose health server on LB VIP |
| `--kube-proxy-replacement-healthz-bind-address` | "" | `/healthz` listener |
| `--enable-service-topology` | false | Topology hints / trafficDistribution |
| `--enable-dynamic-source-lookup-nodeport` | false | SNAT source via FIB lookup |
| `--enable-local-redirect-policy` | false | LRP controller |
| `--lrp-address-matcher-cidrs` | empty | Restrict LRP addressMatcher IPs |
| `--enable-l2-announcements` | false | L2 announcer + responder |
| `--l2-announcements-lease-duration/-renew-deadline/-retry-period` | 15s / 5s / 2s | Lease timings |
| `--enable-lb-ipam` (operator) | true in Helm | LB IPAM controller |
| `--default-lb-service-ipam` | `lbipam` | Which IPAM owns class-less LB services (`lbipam` / `nodeipam`) |
| `--lb-retry-backoff-min/max` (hidden) | 1s / 1m | Reconciler retry |
| `--lb-init-wait-timeout` (hidden) | 1m | Wait for initializers before first reconcile after restore |
| `--lb-reflector-wait-time` (hidden) | 500ms | k8s event batching window |
| `--lb-pressure-metrics-interval` (hidden) | 5m | Map pressure metrics; 0 disables |
| `--lb-state-file`, `--lb-state-file-interval` (hidden) | "" / 1s | File data source |
| `--enable-sctp` | false | SCTP service support in the datapath |
| `--k8s-service-proxy-name` | "" | Only handle Services/EndpointSlices with matching `service.kubernetes.io/service-proxy-name` |

Helm keys (`install/kubernetes/cilium/values.yaml`): `kubeProxyReplacement`, `kubeProxyReplacementHealthzBindAddr`, `socketLB.{enabled,hostNamespaceOnly,terminatePodConnections}`, `loadBalancer.{algorithm,mode,dsrDispatch,acceleration,serviceTopology,reflectorWaitTime,l7.*}`, `maglev.{tableSize,hashSeed}`, `nodePort.range`, `localRedirectPolicies.enabled` (legacy `localRedirectPolicy`), `l2announcements.{enabled,leaseDuration,leaseRenewDeadline,leaseRetryPeriod}`, `lbipam` via operator flags.

### Service model (`pkg/loadbalancer/{service,frontend,backend,loadbalancer}.go`)

- **Service** (`Table[*Service]`, keyed by `ServiceName` = `(<cluster>/)<namespace>/<name>`): `Source`, `Labels`, `Annotations`, `Selector`, `NatPolicy` (`NONE|Nat46|Nat64`), `ExtTrafficPolicy`/`IntTrafficPolicy` (`Cluster|Local`), `ForwardingMode` (`""|dsr|snat`), `SessionAffinity` + `SessionAffinityTimeout`, `LoadBalancerClass *string`, `ProxyRedirects []ProxyRedirect{ProxyPort, Ports}` (L7 Envoy), `HealthCheckNodePort`, `LoopbackHostPort`, `SourceRanges []netip.Prefix`, `PortNames map[string]uint16`, `TrafficDistribution` (`""|PreferSameZone|PreferClose|PreferSameNode`).
- **Frontend** (`Table[*Frontend]`, unique index by `L3n4Addr` = 20-byte AddrCluster + port + proto byte `T/U/S` + scope, secondary index by service name): `FrontendParams{Address, Type, ServiceName, PortName, ServicePort}` + managed fields `Status` (reconciler), `Backends` (lazy iterator, result of selection), `HealthCheckBackends`, `ID ServiceID` (u16 rev-NAT id), `RedirectTo *ServiceName` (LRP), `Service *Service` pointer.
- **Frontend types** (`SVCType`): `ClusterIP`, `NodePort`, `LoadBalancer`, `ExternalIPs`, `HostPort`, `LocalRedirect` (and `NONE`). Scope `ScopeExternal`=0 / `ScopeInternal`=1: a NodePort/LoadBalancer frontend gets a second, internal-scope frontend only when exactly one of ext/int traffic policy is `Local` ("two scopes").
- **Backend** (`Table[*Backend]`, primary key `(ServiceName, Address, sourcePriority)`, secondary index by address): `PortNames`, `Weight` (default 100), `NodeName`, `Zone *BackendZone{Zone, ForZones}`, `ClusterID` (0 local), `Source`, `State`, `Unhealthy` + `UnhealthyUpdatedAt` (active health checker overlay). Size asserted ≤ 140 bytes. One row per (service, backend, source); `PreferredBackendsByAddress` picks the lowest source priority per address.
- **Backend states** (`BackendState` u8, ordering matters for slot sorting): `Active`=0, `Terminating`=1, `TerminatingNotServing`=2, `Quarantined`=3, `Maintenance`=4. Datapath flags (`BackendStateFlags`): active=0, terminating=1, quarantined=2, maintenance=3 (TerminatingNotServing maps to terminating flag). `IsAlive()` = not Unhealthy and (Active or Terminating).
- **Service flags** (u16 into `lb4_service.flags`/`flags2`): ExternalIPs 1<<0, NodePort 1<<1, ExtLocalScope 1<<2, HostPort 1<<3, SessionAffinity 1<<4, LoadBalancer 1<<5, Routable 1<<6, SourceRange 1<<7, LocalRedirect 1<<8, Nat46x64 1<<9, L7LoadBalancer 1<<10, Loopback/L7Delegate 1<<11, IntLocalScope 1<<12, TwoScopes 1<<13, Quarantined (backend slots) / SourceRangeDeny (master slot) 1<<14, FwdModeDSR 1<<15. `Routable` = not a 0.0.0.0/:: surrogate and (type != ClusterIP or `--bpf-lb-external-clusterip`).
- **LB algorithm** (`SVCLoadBalancingAlgorithm` u8 in top 8 bits of master `backend_id` union): Undef 0, Random 1, Maglev 2, Custom 0x80 (pluggable registry `RegisterSVCLoadBalancingAlgorithm`). Datapath also has `LB_SELECTION_FIRST`.

Frontend type × behaviour matrix (as programmed by the reconciler):

| Type | Address | Scope(s) | Routable | Source ranges | Maglev LUT | Health server | Expanded to node addrs |
|---|---|---|---|---|---|---|---|
| ClusterIP | clusterIPs | ext | only with `bpf-lb-external-clusterip` | only with `source-range-all-types` | only with external-clusterip | no | no |
| NodePort | 0.0.0.0 / :: surrogate | ext (+int if two scopes) | surrogate no; expansions yes | only with all-types | yes (expansions) | yes (if hc port + Local) | yes |
| LoadBalancer | `status.loadBalancer.ingress[].ip` (VIP mode) | ext (+int) | yes | yes | yes | yes (if hc port + Local) | no |
| ExternalIPs | `spec.externalIPs` | ext | yes | yes | yes | no | no |
| HostPort | hostIP or surrogate | ext | yes | no | yes | no | surrogate only |
| LocalRedirect | addressMatcher IP or target ClusterIP | ext | as target | no | no | no | no |

### k8s Service → model (`reflectors/conversions.go: convertService`)

- Name/labels/annotations/selector copied; `HealthCheckNodePort` from `spec.healthCheckNodePort`; `LoadBalancerClass` from spec.
- **Headless**: label `service.kubernetes.io/headless` or `spec.clusterIP == "None"` → Service row kept, zero frontends.
- **ExternalName**: no explicit handling; such services have no ClusterIP and produce no frontends (same path as headless). Not proxied.
- **Node exposure**: `service.cilium.io/node-selector` (label selector matched against local node labels; takes precedence) or `service.cilium.io/node` (value must equal local node label of same key); non-matching nodes delete the service.
- **Type exposure**: `service.cilium.io/type` ∈ `ClusterIP|NodePort|LoadBalancer` provisions only that frontend type (e.g. skip ClusterIP+NodePort of a LoadBalancer).
- **ClusterIP**: one frontend per `spec.clusterIPs` (sorted; fallback `spec.clusterIP`) × port, scope external, family-filtered by `enable-ipv4/6`.
- **NodePort**: only when `kube-proxy-replacement=true`; for Service type NodePort or LoadBalancer, per scope × IP family (`spec.ipFamilies`, else deduced from clusterIPs) × port with `nodePort != 0`; address is the 0.0.0.0 / :: surrogate; expansion to concrete node addresses happens in the reconciler. `allocateLoadBalancerNodePorts=false` simply yields `nodePort == 0` → skipped.
- **LoadBalancer**: per `status.loadBalancer.ingress[].ip` with `ipMode` nil or `VIP` (KEP-1860 `Proxy` mode skipped) × scope × port.
- **ExternalIPs**: per `spec.externalIPs` × port, external scope. LB/ExternalIP frontends whose port falls in the NodePort range *and* whose IP is a NodePort node address are dropped with a warning (`writer.isNodePortConflict`).
- **Ports**: named ports go into `Service.PortNames` and `Frontend.PortName`; backends carry `PortNames` from EndpointSlice ports; a frontend with a `PortName` only selects backends whose `PortNames` contains it (unnamed backend ports → nil list → match everything). Protocol `TCP|UDP|SCTP` taken verbatim from `port.protocol` (SCTP requires `--enable-sctp` for datapath support; the control plane treats it like any L4Type, byte `'S'`, proto 132). Legacy `ANY`-protocol map entries are migrated on restart by reusing their IDs for TCP/UDP/SCTP.
- **externalTrafficPolicy**: `Local` → `ExtTrafficPolicy=Local` → for NodePort/LB/ExternalIPs external-scope frontends only node-local backends (`be.NodeName == local`) are selected; flag ExtLocalScope.
- **internalTrafficPolicy**: `Local` → `IntTrafficPolicy=Local` → ClusterIP frontends and internal-scope frontends select node-local backends only; also disables trafficDistribution.
- **sessionAffinity**: `ClientIP` → `SessionAffinity=true`, timeout = `sessionAffinityConfig.clientIP.timeoutSeconds` (default 10800 s); reconciler sets 24-bit timeout in the master slot and one `cilium_lb_affinity_match` entry per *active* backend. Incompatible with ProxyRedirects (reconcile error).
- **loadBalancerSourceRanges**: parsed as prefixes (invalid ones ignored). Enforced only on LoadBalancer and ExternalIPs frontends unless `--bpf-lb-source-range-all-types`; per-family LPM entries `(revnat id, cidr)` in `cilium_lb{4,6}_source_range`. Annotation `service.cilium.io/src-ranges-policy: deny` inverts to a deny-list (flag SourceRangeDeny on master slot).
- **publishNotReadyAddresses**: not read directly; effect arrives via EndpointSlice conditions (ready+terminating endpoints are considered `Active`, matching kube-proxy).
- **trafficDistribution / topology hints** (needs `--enable-service-topology`): `spec.trafficDistribution` `PreferSameZone`/`PreferClose`/`PreferSameNode`; else annotations `service.kubernetes.io/topology-aware-hints` (deprecated, precedence) or `service.kubernetes.io/topology-mode` with any value other than `""|disabled|Disabled` → PreferSameZone. Selection: PreferSameNode → if any eligible backend on this node, use only those. PreferSameZone → use only backends whose `hints.forZones` contains the node's `topology.kubernetes.io/zone`; fall back to all if any candidate lacks hints or none match; terminating and (when health-checked) not-yet-verified backends are excluded from candidacy. `writer/zones.go` refreshes frontends on local zone label change.
- **EndpointSlice → Backend** (`pkg/k8s/endpoints.go`, `convertEndpoints`): conditions `ready` (nil=true), `serving` (nil=true), `terminating`; `nodeName`; `zone` (or deprecatedTopology zone label); `hints.forZones`; annotation `service.cilium.io/weight` on the slice sets all its backends' weight (0 ⇒ `Maintenance`). State mapping: Maintenance if weight-0; `Active` if ready (even if terminating); `TerminatingNotServing` if terminating && !serving; `Terminating` if terminating && serving; otherwise (not ready, not terminating) `Maintenance` — kept in the backends map but excluded from service slots so existing connections are not disrupted on readiness flaps. A dummy endpoint `192.192.192.192:9999` (legacy ingress/gateway trick) is ignored. Only slices with `service.kubernetes.io/service-proxy-name` matching `--k8s-service-proxy-name` (default empty) are watched; `--enable-k8s-endpoint-slice`-era Endpoints v1 is gone.

### Reflector mechanics (`reflectors/k8s.go`)

- Two ListerWatchers (Services, EndpointSlices; both filtered by `service.kubernetes.io/service-proxy-name` and headless-watch config) are merged into one observable and buffered: a `Replace` (initial list / relist) event becomes one `Sync` entry; individual events are keyed by `(isService, ns/name)` in an insertion-ordered map so a Service and its slices land in the same batch. Multiple slices for one service in a batch are merged (`allEndpoints`) so orphan detection compares per-slice previous state against the new union.
- `Sync` handling: services not present in the list are deleted (except synthetic `:host-port:` ones); all previously known slice backends are deleted by address then the replacement set is upserted; frontends of services that lost all backends are refreshed; then the initializer is marked complete (unblocks the reconciler's init-wait).
- Per-service processing errors are aggregated into module health (`Degraded: Failure processing services`) and cleared on recovery.
- Metrics hook (`SVCMetrics`) counts services by type.
- The pod reflector runs only under KPR and waits for `Table[LocalPod]` to initialise; pods with `deletionTimestamp` are skipped so a terminating pod keeps its HostPort until the object disappears or hits Failed/Succeeded.

### NodePort range, device binding, wildcard entries

- `--node-port-range` default `30000,32767` (`NodePortMin/Max`, accepts `"a,b"` or two values). HostPorts inside the range are ignored with a warning. `--enable-auto-protect-node-port-range` adds the range to `net.ipv4.ip_local_reserved_ports` (datapath/node area).
- Node addresses come from `Table[NodeAddress]` (`pkg/datapath/tables/node_address.go`) with `NodePort=true` for: all addresses inside `--nodeport-addresses` CIDRs, or when unset the first private (else public) IPv4/IPv6 of each native device (never `cilium_host`). `writer/node_addr_reconciler.go` marks all NodePort/HostPort(0.0.0.0) frontends Pending when the set changes; `BPFOps.Update` expands the surrogate frontend into one service entry per node address (`nodePortAddrByPort`), skipping addresses owned by a "primary" (non-expansion) frontend (#44730). The surrogate itself is also programmed (non-routable) for socket-LB/host lookups.
- **Wildcard entries** (`--bpf-lb-enable-wildcard-entries`, hidden, default true): for LoadBalancer/ClusterIP external-scope frontends whose VIP is LB-IPAM-managed (`loadBalancerClass` nil and `--default-lb-service-ipam=lbipam`, or class `io.cilium/bgp-control-plane` / `io.cilium/l2-announcer`) and whose address is not a local node address, a `(addr, port 0, proto ANY)` service entry is programmed so the datapath drops traffic to unknown port/proto on the VIP instead of forwarding it to the host. Reference-counted per address (`wildcardReferences`).

### LB mode, DSR dispatch, algorithm

- `--bpf-lb-mode` `snat` (default) | `dsr` | `hybrid` (DSR for TCP, SNAT for UDP). `--bpf-lb-mode-annotation` (default false) lets `service.cilium.io/forwarding-mode: dsr|snat` override per service (hybrid not allowed as default in annotation mode). Result → flag FwdModeDSR per frontend (protocol-aware for hybrid).
- `--bpf-lb-dsr-dispatch` `opt` (default; IPv4 option / IPv6 ext header carrying service addr:port) | `ipip` | `geneve` (auto-enables the Geneve tunnel device via `tunnel.NewEnabler`, without MTU adaptation since the datapath handles the overhead). Datapath defines `DSR_ENCAP_MODE`, `ENABLE_DSR`, `ENABLE_DSR_ICMP_ERRORS`, `ENABLE_DSR_BYUSER` (annotation mode).
- `--bpf-lb-algorithm` `random` (default) | `maglev`. `--bpf-lb-algorithm-annotation` (default false) enables `service.cilium.io/lb-algorithm: random|maglev` per service; annotation wins over the global default and is written into the master slot (`SetLbAlg`, top 8 bits). Maglev LUT is provisioned only for frontends with a concrete address (never for 0.0.0.0/:: surrogates) of type ClusterIP (only if `--bpf-lb-external-clusterip`), NodePort, LoadBalancer, HostPort, ExternalIPs.
- `--bpf-lb-acceleration` / `--node-port-acceleration` (`disabled|native|best-effort`, XDP) and `--bpf-lb-proto-diff` live in `pkg/option` and the datapath loader (other inventory).

### Maglev (`pkg/maglev/maglev.go`)

- `--bpf-lb-maglev-table-size` M ∈ {251, 509, 1021, 2039, 4093, 8191, 16381 (default), 32749, 65521, 131071} (primes; datapath `LB_MAGLEV_LUT_SIZE` compiled to match). `--bpf-lb-maglev-hash-seed` base64 of 12 bytes (default `JLfvgnHc2kaSUFaI`); bytes 0-3 → murmur3 seed, 4-7 and 8-11 → two jhash seeds used by the datapath `__hash_from_tuple_v4/v6`. **The seed must be identical cluster-wide** or nodes disagree on backend for the same flow.
- Backend hash string is frozen: `"[" + addr:port/PROTO(+"/i") + ",State:active]"` (IPv6 bracketed). Backends are sorted by this string (not by node-local ID) so every node computes the same table for the same backend set. `offset = murmur3_128(hashString, seedMurmur).h1 % M`, `skip = h2 % (M-1) + 1`, permutation row `perm[i][j] = (offset + j*skip) % M` computed in parallel batches (worker pool sized to NumCPU; the permutation buffer, up to `(M/100)*M` u64 ≈ 20 MB at M=16381, is reused).
- Table fill: classic Maglev round-robin over backends taking the next free slot from each backend's permutation; **weights** (Envoy-style): each backend's turn is skipped while `(n+1)*weight < weightCntr[i]`, counters start at `weight/len` and advance by `weightSum`; weights are only applied when `weightSum/len > 1`.
- Inputs are only the *active* backends (terminating ones are used when there are zero active); Unhealthy/Quarantined/Maintenance never enter the LUT. Table stored per rev-NAT id in `cilium_lb{4,6}_maglev` (hash-of-maps; inner `cilium_maglev_inner` array of one value holding M×u32 backend IDs) via `LBMaps.UpdateMaglev`; deleted when a service has no active backends or is removed. Datapath: `index = hash(tuple, sport(0 if affinity), dport) % M`, `backend_id = lut[index]`.

### Reconciliation into BPF maps (`reconciler/bpf_reconciler.go`)

- One `statedb/reconciler` over `Table[*Frontend]` with `Update`/`Delete`/`Prune`, retry backoff `--lb-retry-backoff-min/max` (1 s / 1 min, hidden), full prune every 30 min. Status written back to `Frontend.Status`.
- **Restore on start**: dumps `_backends_v3` and `_services_v2`; reuses backend IDs (by address) and service IDs (by frontend address; master slot's `rev_nat_index`), records quarantined slots so health state survives restart, and advances `nextID` past the max. If anything was restored it waits up to `--lb-init-wait-timeout` (1 min, hidden) for all registered initializers (k8s services/endpoints/pods, LRP, clustermesh, …) before reconciling, to avoid scaling down services while data sources are still warming up.
- **ID allocators**: service IDs u16 1..0xFFFF (`firstFreeServiceID=1`), backend IDs u32 1..0xFFFFFFFF; linear scan with rollover; IDs are node-local (kvstore-global IDs are gone).
- **Update(frontend)** (must be idempotent; state only mutated after the map op succeeds): sort selected backends (healthy before unhealthy, then by state, then address, then port); release orphaned backends (refcount 1) → delete backend + affinity-match; upsert changed backends (revision compare) into `_backends_v3` (addr, port, proto, state flags, cluster id, zone id from `--zones` mapping); write slots 1..N (`backend_slot` in key, `backend_id` in value) skipping Maintenance backends; affinity-match upsert for active backends when SessionAffinity else delete; count `active`, `terminating`, `inactive` (quarantined/terminating-not-serving/unhealthy); **if active==0 then active=terminating** (KEP-1669 graceful termination) else terminating counts as inactive; update Maglev LUT with `sorted[:active]`; sync source ranges (add new, delete orphans, tracked in `prevSourceRanges`); upsert rev-NAT `(id → frontend addr:port)`; write master slot 0 with `count=active`, `qcount=inactive`, flags, algorithm, affinity timeout or L7 proxy port (all share the `backend_id` union); wildcard entry; delete stale slots beyond the new count; finally update references. Slot layout consumed by the datapath: slot 0 master, slots 1..count are load-balanced, slots count+1..count+qcount are looked up only for existing connections (quarantined/terminating) — this is what gives graceful termination and quarantine without breaking established flows.
- **Delete(frontend)**: Maglev, affinity matches, orphan backends, all slots, rev-NAT, source ranges, wildcard refs, NodePort expansions; release IDs.
- **Prune**: removes service slots beyond expected count, unknown backends, rev-NAT/source-range/Maglev entries for unknown IDs, wildcard entries without parents; drops the restored-ID maps.
- KPR off (`kube-proxy-replacement=false`): only ClusterIP, LocalRedirect and ExternalIPs frontends are datapath candidates (for pod-to-service via socket LB / tc); NodePort/LB/HostPort entries are withdrawn.
- Invalid combos rejected at reconcile: SessionAffinity+ProxyRedirects; HostPort loopback + proxy delegation.

### Datapath lookup contract (what the filled maps mean, `bpf/lib/lb.h`)

1. Service lookup: key `(dst addr, dst port, proto, scope, slot=0)`; a miss retries with `proto=ANY`/`port=0` wildcard entry (drop) when wildcards are enabled; `scope` starts at external and the datapath retries with internal scope when `SVC_FLAG_TWO_SCOPES` and the source is in-cluster.
2. Master slot 0 gives `count` (LB-able backends), `qcount` (quarantined/terminating-not-serving backends only valid for existing CT entries), `rev_nat_index`, flags, `lb_alg` (top byte of union), `affinity_timeout` (low 24 bits) or `l7_lb_proxy_port`.
3. Existing connection: CT entry carries `backend_id`; the datapath looks the backend up directly in `_backends_v3`; if it is gone or its state flag is not active/terminating, it re-selects. Quarantined slots exist so that a CT-bound backend that is in `qcount` range is still resolvable.
4. New connection, `count>0`: if `SVC_FLAG_AFFINITY`, look up `cilium_lb{4,6}_affinity` by `(client id, rev_nat)`; a hit is honoured only if `cilium_lb_affinity_match(backend_id, rev_nat)` still exists (that is why the reconciler maintains match entries only for active backends). Else `LB_SELECTION_MAGLEV`: `lut[hash(tuple) % M]`; `LB_SELECTION_RANDOM`: `slot = prandom % count + 1`, read slot → `backend_id`; `LB_SELECTION_FIRST`: slot 1.
5. Backend value gives `addr, port, proto, state, cluster_id, zone`; DNAT (and SNAT unless DSR flag) performed; `rev_nat_index` recorded in CT for reverse translation via `cilium_lb{4,6}_reverse_nat`.
6. Source ranges: if `SVC_FLAG_SOURCE_RANGE`, LPM lookup `(rev_nat_id, src)`; allow on hit unless `SVC_FLAG_SOURCE_RANGE_DENY` inverts.
7. NodePort: after lookup on a node address, if no local backend and ext policy Local, drop; else forward to remote backend using SNAT (node IP) or DSR (encode original service addr/port via option/IPIP/Geneve so the backend replies directly).
8. Socket LB: `connect()`-time translation writes `cilium_lb{4,6}_reverse_sk` `(cookie, backend addr, port) → rev_nat` so `getpeername`/UDP `recvmsg` can present the service address; `cilium_skip_lb` short-circuits translation for listed `(cookie, addr, port)`.

The control plane never touches CT or affinity data maps; it only guarantees the invariants above (contiguous slots, count/qcount consistency, match entries, LUT reflecting exactly `sorted[:active]`).

### Writer and StateDB architecture (`writer/writer.go`, `README.md`)

- Single `Writer` owning the three tables; `WriteTxn` locks all three (plus optional extra tables) so cross-table references are always consistent. APIs: `UpsertService`, `UpsertFrontend`, `UpsertServiceAndFrontends` (deletes frontends no longer listed), `UpsertBackends`, `UpsertAndReleaseBackends`, `SetBackends(OfCluster)`, `DeleteBackends{BySource,OfService,ByAddress}`, `DeleteService(s)…`, `SetRedirectTo`, `UpdateBackendHealth`, `RefreshFrontends`, `RegisterInitializer`. Any backend change re-runs `refreshFrontend` on all frontends of the service (recomputing the lazy `Backends` sequence and setting `Status=Pending`).
- Source priorities (`source.Sources` order; smaller = preferred) allow the same backend address to be contributed by several sources (k8s, clustermesh, local API, health checker) and the preferred one wins per address.
- Data sources today: k8s reflector (services+endpointslices batched together in one buffer, `--lb-reflector-wait-time` 500 ms, buffer 500), pod reflector (HostPort, KPR only), file reflector (`--lb-state-file`, `source.LocalAPI`), ClusterMesh `service_merger.go` (`SetBackendsOfCluster` with ClusterID), CiliumEnvoyConfig reconciler (sets `Service.ProxyRedirects`), LRP controller, healthserver (`:healthserver` pseudo-service), BGP test commands, active health checker (`UpdateBackendHealth`).
- What it buys: (1) data sources never see BPF errors; (2) readers (Hubble, REST, L2 announcer, envoy) get consistent snapshots + watch channels for free; (3) restart/resync is a table diff, not event replay; (4) the whole control plane is testable from YAML → expected map dump without BPF (`tests/testdata/*.txtar`, run with a fake `LBMaps`; `PRIVILEGED_TESTS=1` runs the same against real maps).

### HostPort (`reflectors/k8s.go: upsertHostPort`)

- Watches local pods (`Table[LocalPod]`); for Running pods without `deletionTimestamp`, every container/initContainer port with `hostPort>0` outside the NodePort range becomes a synthetic service `<ns>/<pod>:host-port:<hostPort>:<uid>` (infix deliberately not RFC-1123 so it cannot collide) of type HostPort with backends = pod IPs × containerPort. `hostIP` unset or unspecified → surrogate 0.0.0.0/:: (expanded to node addresses); explicit `hostIP` → that single address; loopback `hostIP` → surrogate + `LoopbackHostPort=true` (flag Loopback: only reachable from the node; requires netns-cookie kernel support else skipped). Failed/Succeeded pods and host-network pods release their HostPorts immediately. Test `hostport-lb-collision.txtar` covers collision with LB IPs.

### Health check server for externalTrafficPolicy=Local (`healthserver/`)

- Enabled by `--enable-health-check-nodeport` (default true) when KPR on. For every LoadBalancer/NodePort external-scope frontend whose service has `healthCheckNodePort>0` and `ExtTrafficPolicy=Local`, an HTTP listener on `:<healthCheckNodePort>` returns kube-proxy-compatible JSON `{"service":{"namespace","name"},"localEndpoints":N}` with header `X-Load-Balancing-Endpoint-Weight: N`, 200 if N>0 else 503. N counts node-local `Active` backends (preferred instance per address); with ProxyRedirects returns 1.
- `--enable-health-check-loadbalancer-ip` (default false) additionally creates a pseudo LoadBalancer service `<svc>:healthserver` with frontend `<LB VIP>:<hcPort>/TCP` and backend `<nodeport addr>:<hcPort>` so external LBs can probe the VIP.

### Kube-proxy `/healthz` (`daemon/healthz/kube_proxy_healthz.go`)

- `--kube-proxy-replacement-healthz-bind-address` (empty = disabled; e.g. `0.0.0.0:10256`). Returns `{"lastUpdated": ..., "currentTime": ...}`; 503 when the node is unhealthy, using `BPFOps.GetLastUpdatedAt()` (last successful map write) as `lastUpdated`.

### Socket LB (`bpf_sock.c`, `--bpf-lb-sock`, `--bpf-lb-sock-hostns-only`)

- `pkg/kpr`: `--kube-proxy-replacement` (bool) and `--bpf-lb-sock` (E/W socket-level LB via cgroup hooks `connect4/6`, `sendmsg4/6`, `recvmsg4/6`, `getpeername4/6`, `bind4/6`, `post_bind4/6`, `sock_release`); KPR=true forces socket LB on. `--bpf-lb-sock-hostns-only` (`BPFSocketLBHostnsOnly`) compiles `ENABLE_SOCKET_LB_HOST_ONLY`: only sockets whose netns cookie equals the host's are translated (pods fall back to tc-level LB; used with Istio/service-mesh sidecars). `--trace-sock` enables socket trace events.
- Reverse map `cilium_lb{4,6}_reverse_sk` (LRU, `--bpf-sock-rev-map-max`, default dynamically sized) keyed by `(socket cookie, backend addr, port)` → rev-NAT index, so `getpeername`/`recvmsg` can undo the translation.
- **Socket termination** (`reconciler/termination.go`): when socket LB is on, a job watches backend table changes; for deleted or non-alive UDP backends (TCP too with hidden `--lb-sock-terminate-all-protos`) it uses `SOCK_DESTROY` (inet_diag) in the host netns — and in every pod netns when `--bpf-lb-sock-terminate-pod-connections` and not hostns-only — filtered to sockets whose cookie appears in the reverse-sk map. Kernel without `CONFIG_INET_DIAG_DESTROY` → health degraded, feature off. Batched every 50 ms.
- **`cilium_skip_lb{4,6}`** (`maps/skiplb.go`, 100 entries, hash keyed `(netns_cookie, addr, port)`): sockets in a pod's netns are exempted from socket LB for the listed frontends — used by LRP `skipRedirectFromBackend` so a node-local-DNS pod can still reach the real kube-dns ClusterIP.

### `--bpf-lb-external-clusterip`

Default false. When true ClusterIP frontends get flag Routable so N/S traffic hitting a ClusterIP from outside is load-balanced (kube-proxy parity), and Maglev LUTs are built for ClusterIP too. Test `external-clusterip.txtar`.

### NAT46/64 service path

`Service.NatPolicy` (`Nat46|Nat64`) sets flag `SVC_FLAG_NAT_46X64` and the datapath translates v4↔v6 between frontend and backends (`bpf-lb-nat46x64` → `ENABLE_NAT_46X64`; `--enable-nat46x64-gateway` → L3 gateway mode). At this tag **no reflector sets NatPolicy** (the k8s reflector filters backends by frontend family instead), so the path is reachable only through the file reflector / API model. Treat as legacy/optional.

### Local Redirect Policy (`redirectpolicy/`, CRD `cilium.io/v2 CiliumLocalRedirectPolicy`)

- Enabled by `--enable-local-redirect-policy`; `--lrp-address-matcher-cidrs` restricts which IPs an `addressMatcher` may name. Spec: `redirectFrontend.addressMatcher{ip, toPorts[{port, protocol, name}]}` **xor** `serviceMatcher{serviceName, namespace, toPorts}`; `redirectBackend{localEndpointSelector, toPorts}`; `skipRedirectFromBackend`; `description`. Status: `ok`.
- Frontend types: `svcFrontendAll` (no toPorts), `svcFrontendSinglePort`, `svcFrontendNamedPorts` (>1 port ⇒ names required and backend ports matched by name), `addrFrontendSinglePort`, `addrFrontendNamedPorts`. Single-port case requires frontend and backend protocol to match. serviceMatcher namespace must equal the policy namespace.
- Controller: a pseudo-service `<ns>/<lrp>:local-redirect` holds backends = Ready pods in the policy namespace matching the selector × container ports matching `redirectBackend.toPorts` (by number+protocol, and by name in the named case). **serviceMatcher**: every ClusterIP frontend of the target service that matches the port rules gets `RedirectTo = pseudo-service` (type reported as `LocalRedirect`, flag LocalRedirect) — only when ≥1 matching pod exists, otherwise redirect is removed and normal backends are used. **addressMatcher**: creates new frontends of type LocalRedirect at `ip:port/proto`; refuses to override an address owned by an existing service; frontends are deleted when no pods match. `skipRedirectFromBackend`: for each backend pod, program `cilium_skip_lb` entries (pod netns cookie learned from the endpoint manager) for the redirected frontends; requires kernel ≥ 5.12 (netns cookie) else warns once. REST `GET /lrp`. Tests: 12 txtar incl. `node-local-dns.txtar`, `skiplb*.txtar`, `pod-readiness.txtar`.

### LB IPAM (operator, `operator/pkg/lbipam`, CRD `cilium.io/v2 CiliumLoadBalancerIPPool`, also served as v2alpha1)

- Enabled by `--enable-lb-ipam` (operator); `--default-lb-service-ipam` `lbipam` (default) | `nodeipam`. Responsible for `type: LoadBalancer` services with `loadBalancerClass` nil (only if default is `lbipam`) or ∈ {`io.cilium/bgp-control-plane` (if BGP enabled), `io.cilium/l2-announcer` (if L2 announcements enabled)}.
- Pool spec: `serviceSelector` (label selector; may match on `io.kubernetes.service.namespace`/`name` meta labels), `blocks[]{cidr | start[,stop]}`, `allowFirstLastIPs: Yes|No` (No reserves network/broadcast of CIDR blocks ≥ /30 or /126), `disabled` (no new allocations; existing kept). Status conditions: `cilium.io/PoolConflict` (True with reason `cidr_overlap` when ranges overlap another pool's — the *newer* pool by creationTimestamp is marked and all its ranges internally disabled; internal overlap within one pool also conflicts), `cilium.io/IPsTotal`, `cilium.io/IPsAvailable`, `cilium.io/IPsUsed` (big-int counts in `message`).
- Service side: requested IPs from `spec.loadBalancerIP` (legacy) plus annotation `lbipam.cilium.io/ips` (alias `io.cilium/lb-ipam-ips`, comma-separated); families from `spec.ipFamilyPolicy`/`ipFamilies`/clusterIPs (dual-stack aware; falls back to enabled families). Allocations written to `status.loadBalancer.ingress[].ip` (with `ipMode` VIP semantics) and condition `cilium.io/IPAMRequestSatisfied` True/False with reasons (`satisfied`, no pool / out of IPs / requested IP in use, incompatible sharing…). Existing ingress IPs are re-imported on restart (so a restart never reallocates) and stripped when no longer valid (pool gone/disabled, family or requested-IP mismatch, sharing incompatibility).
- **Sharing**: `lbipam.cilium.io/sharing-key` (alias `io.cilium/lb-ipam-sharing-key`) lets services share one IP if: same key; same namespace unless both list the other's namespace (or `*`) in `lbipam.cilium.io/sharing-cross-namespace` (alias `io.cilium/lb-ipam-sharing-cross-namespace`); no overlapping (port, protocol); same `externalTrafficPolicy`; and if Local, identical non-empty pod selectors. A `sharingCluster` per IP tracks its services; IP freed when the last leaves.
- Service deleted / no longer LoadBalancer / class changed away → ingress IPs and condition removed. Metrics: conflicting pools, matching/unsatisfied services, per-pool counts.

Allocation algorithm (`lbipam.go: satisfyService`, per reconciliation pass):

1. Build a `ServiceView` (requested families, requested IPs, sharing key, cross-namespace list, ports, selector, externalTrafficPolicy).
2. `stripInvalidAllocations`: drop allocated IPs whose range vanished/disabled, family no longer requested, IP not in the requested list, or sharing cluster no longer compatible.
3. `stripOrImportIngresses`: existing `status.loadBalancer.ingress` IPs are imported as allocations if they fall in a known range and are free (or sharable), else removed from status.
4. Specific requests: for each requested IP find its range (skipping disabled pools; pool selector must match); allocate or join the sharing cluster; set `IPAMRequestSatisfied=False` with a reason if impossible.
5. Generic requests: for each requested family lacking an IP, first try an existing compatible sharing cluster with the same key, else `AllocAny` from the first enabled, family-matching range whose pool selector matches the service (pools iterated in map order — no priority field).
6. Patch service status (ingress + condition) only when changed; then recompute pool counts and patch pool conditions.

### L2 announcements (`pkg/l2announcer`, `pkg/datapath/l2responder`, CRD `cilium.io/v2alpha1 CiliumL2AnnouncementPolicy`)

- Enabled by `--enable-l2-announcements`; lease tuning `--l2-announcements-lease-duration` (15 s), `--l2-announcements-renew-deadline` (5 s), `--l2-announcements-retry-period` (2 s) with sanity clamping (duration ≥ 1 s, renew < duration, retry < renew). Requires `--devices` (interfaces listed by regex).
- Policy spec: `nodeSelector`, `serviceSelector`, `loadBalancerIPs bool`, `externalIPs bool`, `interfaces []regex`. Status annotations on the policy for `io.cilium/bad-node-selector`, `io.cilium/bad-interface-regex`, `io.cilium/bad-service-selector`.
- Agent selects policies matching the local `CiliumNode` labels, then services (from the LB tables, matched on labels + `io.kubernetes.service.namespace/name`) that have LB or ExternalIP frontends of the requested kind and `loadBalancerClass` nil or `io.cilium/l2-announcer`. For each selected service it runs leader election on a `coordination.k8s.io/Lease` named `cilium-l2announce-<ns>-<name>` in the agent namespace; the leader writes `L2AnnounceEntry{IP, NetworkInterface, Origins[]}` rows for every IP × selected device; a periodic GC deletes leases nobody holds. `l2responder` reconciles the table into `cilium_l2_responder_v4` / `_v6` (4096 entries, keyed `(ip, ifindex)`) — the BPF host program answers ARP/NS for those IPs — and sends a **gratuitous ARP / unsolicited NA** when an entry is newly created, plus joins the solicited-node multicast MAC for IPv6.

Runtime flow:

1. Policy events → validate selectors/regex → status annotations; devices from `Table[Device]` filtered by `interfaces` regexes (all devices if empty).
2. Local `CiliumNode` label changes re-evaluate `nodeSelector` for all policies.
3. Service/frontend table changes → `upsertSvc`: collect LB and ExternalIP frontend addresses, match policies; first match starts a `leaderelection.LeaderElector` on the Lease (identity = node name); loss of all policies stops it and drops table rows.
4. Leader events → `recalculateL2EntriesTableEntries`: desired = (policy IP kinds ∩ service addrs) × selected devices; rows carry `Origins` (service keys) so the same IP/iface from two services is reference counted; non-leader removes only its origin.
5. `l2responder` (separate cell) diffs the table against `cilium_l2_responder_v4/v6` (and IPv6 solicited-node multicast MAC membership), creating entries and sending GARP/unsolicited NA for new ones; a full reconciliation runs on start and periodically.
6. Lease GC every so often deletes `cilium-l2announce-*` leases with empty holder; if the feature is disabled a one-shot GC removes leftovers.

### Health checking of backends

`Backend.Unhealthy`/`UnhealthyUpdatedAt` is the hook for an active health checker (enterprise/optional cell) through `Writer.UpdateBackendHealth` and `SetIsServiceHealthCheckedFunc`; unhealthy backends are placed in quarantined slots and excluded from Maglev/topology candidacy; quarantine survives restart via slot restore. Test `quarantined.txtar`.

### Annotations Cilium honors on Services (complete list at this tag)

| Annotation | Effect | Gate |
|---|---|---|
| `service.cilium.io/lb-algorithm` = `random|maglev` | Per-service algorithm (master slot `lb_alg`) | `--bpf-lb-algorithm-annotation` |
| `service.cilium.io/forwarding-mode` = `dsr|snat` | Per-service DSR/SNAT | `--bpf-lb-mode-annotation` |
| `service.cilium.io/node` = `<value>` | Install only on nodes with label `service.cilium.io/node=<value>` | always |
| `service.cilium.io/node-selector` = `<label selector>` | Install only on matching nodes (precedence over `/node`) | always |
| `service.cilium.io/type` = `ClusterIP|NodePort|LoadBalancer` | Provision only that frontend type | always |
| `service.cilium.io/src-ranges-policy` = `allow|deny` | Source-range list semantics | when source ranges enforced |
| `service.cilium.io/proxy-delegation` = `none|delegate-if-local` | Push packets to a local user-space proxy when the chosen backend IP is a local node IP (flag L7Delegate; backend selection restricted to node IPs) | always |
| `service.cilium.io/weight` (on **EndpointSlice**) | Backend weight; 0 = maintenance | always |
| `service.cilium.io/lb-l7` = `enabled` | L7 load balancing through Envoy (creates ProxyRedirects; owned by `pkg/ciliumenvoyconfig`) | `loadBalancer.l7.backend=envoy` |
| `service.cilium.io/global`, `/shared`, `/affinity` (`local|remote|none`), `/global-sync-endpoint-slices`, `/local-endpointslice` (aliases `io.cilium/global-service`, `io.cilium/shared-service`, `io.cilium/service-affinity`) | ClusterMesh global services (documented in the clustermesh inventory) | ClusterMesh |
| `lbipam.cilium.io/ips`, `/sharing-key`, `/sharing-cross-namespace` (aliases `io.cilium/lb-ipam-*`) | LB IPAM requests and sharing | LB IPAM |
| `service.kubernetes.io/topology-aware-hints`, `service.kubernetes.io/topology-mode` | Upstream topology hints → PreferSameZone | `--enable-service-topology` |
| `service.kubernetes.io/service-proxy-name` (label) | Only services/slices matching `--k8s-service-proxy-name` are watched | always |
| `service.kubernetes.io/headless` (label) | No frontends | always |

## Data model

- StateDB tables (in-memory, not persisted): `services` (index `name`), `frontends` (indexes `address` unique, `service`), `backends` (indexes `key` unique `(service,addr,prio)`, `address`), `desired-skiplbmap` (LRP), `LocalRedirectPolicy` table, `L2AnnounceEntry` table (`pkg/datapath/tables`), `NodeAddress` table. Inspectable via `cilium-dbg shell`: `db/show frontends|backends|services`, `lb/maps-dump`, `lb/skiplbmap`.
- BPF maps touched (layouts in the maps inventory): `cilium_lb4_services_v2`/`lb6` (hash; key addr+dport+backend_slot+proto+scope; value backend_id-union+count+rev_nat_index+flags+flags2+qcount; size `--bpf-lb-service-map-max` else `--bpf-lb-map-max`=65536), `cilium_lb4_backends_v3`/`lb6` (hash; key u32 id; value addr+port+proto+flags(state)+cluster_id+zone), `cilium_lb4_reverse_nat`/`lb6` (hash; u16 id → addr+port), `cilium_lb_affinity_match` (hash; (backend_id, rev_nat_id)), `cilium_lb4_affinity`/`lb6` (LRU; client id (ip or netns cookie)+rev_nat → backend_id+last used), `cilium_lb4_source_range`/`lb6` (LPM; prefixlen = 32 + cidr bits; key rev_nat_id + cidr), `cilium_lb4_maglev`/`lb6` (hash-of-maps keyed u16 rev_nat_id (network order) → inner array `cilium_maglev_inner` of M u32), `cilium_lb4_reverse_sk`/`lb6` (LRU), `cilium_skip_lb4`/`6` (hash, 100), `cilium_lb4_health`/`lb6` (health probe), `cilium_l2_responder_v4`/`_v6`. All sized via `--bpf-lb-*-map-max` (default inherit `--bpf-lb-map-max`); pressure metrics every `--lb-pressure-metrics-interval` (5 min).
- CRDs: `CiliumLocalRedirectPolicy` (v2, namespaced), `CiliumLoadBalancerIPPool` (v2 + v2alpha1, cluster-scoped, status conditions), `CiliumL2AnnouncementPolicy` (v2alpha1, cluster-scoped, status conditions/annotations). Kubernetes objects written: Service `.status.loadBalancer.ingress` and `.status.conditions` (operator), `coordination.k8s.io/Lease` (agent).
- Files: `--lb-state-file` (optional YAML/JSON of services/frontends/backends, source `LocalAPI`, re-read on change after `--lb-state-file-interval`).
- REST model: `GET /service` → `[]models.Service{spec{id, frontend-address{ip,port,protocol,scope}, flags{type, trafficPolicy, extTrafficPolicy, intTrafficPolicy, natPolicy, healthCheckNodePort, name, namespace, cluster}, backend-addresses[{ip,port,protocol,nodeName,zone,state,preferred,weight}]}, status.realized}`; `GET /lrp` → `[]models.LRPSpec`.

## External interfaces

- Agent REST (unix socket `/var/run/cilium/cilium.sock`): `GET /service`, `GET /lrp` (both read-only at this tag; the old `PUT/DELETE /service/{id}` are gone — the file reflector replaces the imperative API).
- HTTP: `healthCheckNodePort` servers (`:<port>`, all addresses); `/healthz` on `--kube-proxy-replacement-healthz-bind-address`.
- Kubernetes API: watches Services, EndpointSlices (filtered by proxy-name label), Pods (local), CiliumLocalRedirectPolicy, CiliumL2AnnouncementPolicy, CiliumNode (local); writes Leases, policy status, Service status/conditions (operator), pool status (operator).
- Netlink: `SOCK_DESTROY` via inet_diag (termination); gratuitous ARP/NA raw sockets and multicast MAC membership (l2responder); Geneve device via tunnel enabler when DSR dispatch is geneve.
- Wire formats (datapath inventory): DSR IPv4 option / IPv6 DST ext header (`opt`), IPIP, Geneve class option; socket cookies as affinity client id.
- Sysctls: `net.ipv4.ip_local_reserved_ports` (node-port range protection, in datapath/node area).

## Dependencies

- Inventory 01/02 (BPF programs, map layouts): `bpf/lib/lb.h` (`lb4_lookup_service`, `lb4_select_backend_id_{random,maglev,first}`, affinity, source-range LPM, quarantine slots), `bpf/lib/nodeport.h` (DSR/SNAT, NodePort expansion semantics), `bpf/bpf_sock.c` (cgroup hooks, `HOST_NETNS_COOKIE`), `bpf/lib/arp.h`/host program for L2 responder.
- Inventory 03 (datapath userspace/node): `Table[NodeAddress]`, `Table[Device]`, `--devices`, `--nodeport-addresses`, tunnel enabler, zone mapper (`--zones`?) `ExternalConfig.GetZoneID`.
- Inventory 05 (policy/identity): label selector types for LRP (`policy/types.LabelSelector`).
- Inventory 06 (agent API): REST models. Inventory 08 (operator): LB IPAM runs there. Inventory 10 (BGP): advertises LB IPs, LB class `io.cilium/bgp-control-plane`. Inventory 11 (Envoy): `ProxyRedirects`, `service.cilium.io/lb-l7`. Inventory 12 (ClusterMesh): `service_merger`, global service annotations. Inventory 13 (CRDs): the three CRDs.
- External Go libs: `cilium/statedb` (+ `reconciler`, `index`, `part`), `cilium/hive`, `cilium/stream`, `k8s client-go` (leaderelection/resourcelock, discovery/v1), `vishvananda/netlink`, `spaolacci/murmur3`-style `pkg/murmur3`, `cespare/xxhash`.
- Kernel (control plane side): `SO_NETNS_COOKIE` / `bpf_get_netns_cookie` (≥5.12) for loopback HostPort and LRP skip-LB; `CONFIG_INET_DIAG_DESTROY` for socket termination; cgroup v2 socket hooks for socket LB; LPM trie, hash-of-maps for Maglev.

## Kernel / platform requirements

Control plane is pure userspace. Feature gates that depend on the kernel: socket LB (cgroup/connect etc., ≥4.17; `getpeername` hook ≥5.8), netns cookie (≥5.12), `SOCK_DESTROY` (inet_diag destroy, ≥4.9 with config), XDP acceleration for NodePort (driver support), Geneve/IPIP DSR (tunnel devices). Arch: none specific; Maglev computation is CPU-bound and parallelised (NumCPU workers); at M=131071 the permutation buffer is ~1.3 GB — memory sizing matters on small arm64 nodes (default M=16381 ≈ 20 MB).

## Tests

- **Unit**: `pkg/loadbalancer/*_test.go` (flags/strings, L3n4Addr parsing, fuzz `fuzz_test.go`, hybrid DSR, proxy redirects), `writer/*_test.go` (1562 lines: reference maintenance, backend selection incl. zones, benchmark), `reconciler/bpf_reconciler_test.go` (1634 lines: slot layout, ID reuse/restore, prune, fault injection via `--lb-test-fault-probability`), `maglev/maglev_test.go` (determinism across order, weights, table sizes), `healthserver/script_test.go`, `redirectpolicy/script_test.go`, `l2announcer_test.go` (1193 lines: policy/service selection, lease events, table output), `operator/pkg/lbipam/*_test.go` (3621 lines: allocation, sharing, conflicts, conditions, restart import, first/last IP).
- **Script (txtar) tests** (`pkg/loadbalancer/tests/testdata`, 51 files; each starts a hive with flags in the `#!` line, feeds YAML via `k8s/add|update|delete`, and compares `db/cmp` table output and `lb/maps-dump` against expected files). What they pin down:

| File(s) | Behaviour pinned |
|---|---|
| `clusterip`, `clusterip-allowed`, `multiport`, `dualstack`, `dualstack-maglev` | ClusterIP frontends per IP × port, family filtering, named ports, Maglev on dual-stack |
| `nodeport`, `nodeport-addr`, `nodeport-lb-nodeport-range`, `nodeport-explicit-random`, `nodeport-explicit-maglev`, `nodeport-maglev` | Surrogate + node-address expansion, range conflict with LB IPs, per-service algorithm annotation |
| `loadbalancer`, `loadbalancer-multiport`, `loadbalancer-multiprotocol`, `loadbalancer-class-wildcards`, `loadbalancer-disabled-wildcards`, `loadbalancer-localaddr-wildcards` | LB VIP frontends, TCP+UDP same port, wildcard drop entries and their class/local-address gating |
| `external-ips`, `external-clusterip` | ExternalIPs frontends; Routable flag on ClusterIP |
| `hostport`, `hostport-lb-collision` | HostPort synthetic services, loopback hostIP, collision with LB VIP |
| `headless`, `svc-type-annotation`, `svc-node-exposure`, `svc-forwarding-mode-annotation` | No frontends for headless; `service.cilium.io/type`, `/node`, `/node-selector`, `/forwarding-mode` |
| `trafficpolicy` | ext/int Local, two scopes, local backend selection |
| `topology-aware`, `topology-aware-terminating`, `prefer-same-node`, `prefer-same-zone-fallback` | Hints, PreferSameNode/Zone, fallback when hints missing, terminating exclusion |
| `graceful-termination`, `quarantined`, `endpointslice-weight`, `multiple-endpointslices` | active/terminating/qcount slot layout incl. Maglev; unhealthy quarantine and restore; weight 0 = maintenance; slice merge/orphans |
| `source-ranges-dfl`, `source-ranges-all` | LPM entries per family, deny policy, all-types flag |
| `proxy-delegation`, `hybrid-dsr`, `ingress` | L7 delegate flag and node-IP backend filter; DSR flag per protocol; ingress dummy endpoint ignored |
| `kpr-transition-to-disabled`, `kpr-transition-to-enabled` | Which frontend types are datapath candidates without KPR |
| `migrate-any-proto`, `migrate-backend`, `reuse`, `resync`, `prune-deleted-on-restart`, `pruning` | ID restore/reuse, ANY→TCP/UDP/SCTP migration, backend map version migration, prune of stale entries |
| `name-collisions`, `marshalling`, `queries`, `file` | Frontend ownership conflicts, JSON/YAML of tables, StateDB query strings, `--lb-state-file` |

  LRP: 12 txtar (`address*`, `service`, `lrp-single-multiple-ports`, `node-local-dns`, `pod-readiness`, `no-target-pods`, `skiplb`, `skiplb-addr`, `avoid-recompute`). Health server: 3 txtar (IPv4, IPv6, proxy-redirect → 1 endpoint). `PRIVILEGED_TESTS=1` runs `tests/script_test.go` and `termination_test.go` against real BPF maps. `stress.sh` runs 500 iterations to catch flakes.
- **e2e**: kube-proxy replacement / KPR modes exercised via cilium-cli connectivity suites in `.github/workflows/conformance-*.yaml` (kind, EKS/AKS/GKE, ipsec, clustermesh, ingress/gateway), `tests-e2e-upgrade.yaml`; `test/k8s` and `test/controlplane` hold legacy suites. LRP and L2 announcements have dedicated connectivity tests in cilium-cli (separate module).

## Rust mapping

Proposed crate split (all `no_std`-free userspace):

- `flowsdn-lb-model`: `ServiceName` (interned, `cluster/ns/name`), `L3n4Addr` (interned 24-byte key; consider `Arc<str>`-free `#[repr(C)]` struct + `FxHashMap` interner), `Service`, `FrontendParams`/`Frontend`, `Backend`, `BackendState`, `SvcFlags` (bitflags), `LbAlgorithm`, `TrafficDistribution`, `SvcType`, `L4Type`. Derive `PartialEq` cheaply (the Go side hand-rolls DeepEqual to skip iterators).
- `flowsdn-lb-tables`: the three tables. Decision point: mirror StateDB (MVCC, per-table revision, watch channels, indexes) or use a simpler "single writer, `Arc<im::OrdMap>` snapshot" store. Recommendation: implement a small generic `Table<T>` over persistent maps (`im` / `rpds` crate) with revision counters, prefix queries on byte keys and `tokio::sync::watch` per table — that is what the reference actually uses (StateDB's radix tree + watch closures); a full StateDB port is not needed for LB alone, but the same crate will be wanted by endpoints/policy so design it shared.
- `flowsdn-lb-writer`: transactional facade (`WriteTxn` = exclusive `RwLock` over the three tables), reference upkeep, `select_backends` (traffic policy, port-name matching, topology, proxy delegation, health), source priorities.
- `flowsdn-lb-k8s`: Service/EndpointSlice/Pod → model with the exact rules above; batching by `(kind, ns/name)` in an insertion-ordered map with a 500 ms/500-item flush (use `kube-runtime` watcher streams + `tokio::time::timeout` batching).
- `flowsdn-lb-reconciler`: `BpfOps` against an `LbMaps` trait (real `aya` maps vs in-memory fake), ID allocators, restore, prune, slot writer, source ranges, wildcards, NodePort expansion. Reconciler loop generic over "object with status" — reuse for other areas.
- `flowsdn-maglev`: murmur3-128 with the same seed split and hash string; sort by hash string; permutation rows computed with `rayon`; weighted fill. **Bit-exact compatibility with the reference table is a hard requirement if mixed-vendor nodes are ever considered; otherwise only cluster-internal consistency matters.** Add a property test that two permutations of the same backend list give identical tables.
- `flowsdn-lb-health`: `axum`/`hyper` listeners per `healthCheckNodePort`; kube-proxy `/healthz`.
- `flowsdn-lrp`, `flowsdn-l2announce` (+ `kube` `Lease` leader election — `kube-leader-election` crate or hand-rolled), `flowsdn-lbipam` (operator; `ipnet`/`iprange` bitmaps, big-int counts, condition patching).

Hard parts:

1. **Maglev consistency across nodes**: table is a pure function of (seed, M, sorted backend hash strings, weights); node-local backend IDs are substituted after sorting. Must never let node-local ordering or IDs leak into the hash. Weight semantics (float counters) must be reproduced exactly or documented as a deliberate divergence.
2. **Atomic backend-set updates**: the datapath reads slot 0 (`count`, `qcount`) then slot N; the reference orders writes as backends → slots 1..N → Maglev → revnat → master (count) → delete stale slots, and keeps `backendReferences` only after success so retries are safe. A Rust port must keep this ordering and idempotency; per-frontend `RwLock`-free single reconciler thread is fine (reference is single-threaded plus a mutex for tests).
3. **Terminating / quarantine semantics**: three-way count (active / terminating / inactive), "terminating become active when active==0", Maintenance excluded from slots but present in backends map, Unhealthy → quarantined slot while backend map keeps the source state (a backend may be healthy for one service and not another). Restore of quarantine from `qcount` slots on restart.
4. **ID restore and migration**: reuse IDs from live maps (avoid connection resets), `ANY`-proto → TCP/UDP/SCTP migration, prune only after init-wait.
5. **Source priority merging** (k8s vs clustermesh vs health vs file) and the `PreferredBackendsByAddress` invariant relying on key ordering.
6. **NodePort expansion** against a moving node-address set with primary-frontend exclusion, plus `nodeport-addresses` selection rules from the node area.
7. **Hive-style lifecycle** (initializers, init-wait, health reporting) needs an equivalent (e.g. `tokio` tasks + a readiness registry).

## Recommendation

**Keep** (core LB control plane, reflectors, reconciler, Maglev, health servers, HostPort, LRP): this is the kube-proxy replacement and non-negotiable for a Cilium-equivalent. Effort **L** (~10-14k Rust lines incl. tests; reference core is 15k Go + 6k tests; Rust with `bitflags`/`serde` will be somewhat smaller but the txtar-style golden tests must be re-created).
**Keep** LB IPAM (operator) — small, self-contained, widely used with BGP/L2: **M** (~3k).
**Keep** L2 announcements + responder — **S/M** (~2k), depends on a Lease leader-election implementation.
**Defer**: NAT46/64 service path (dormant at this tag), custom LB algorithm registry, socket termination for TCP (hidden flag), `--lb-state-file` reflector (nice for testing; cheap, do later), pressure metrics.
**Replace**: StateDB — do not port wholesale; implement a minimal persistent-map table with revisions/watches shared across areas (decide in a cross-area ADR). Hive DI — replace with explicit construction.

## Open questions

- Does flowsdn need bit-exact Maglev tables with Cilium (mixed clusters during migration)? If yes, `murmur3` 128-bit x64 variant and the frozen hash string are fixed; if no, we can hash the binary key.
- Table store: shared persistent-map crate vs. per-area ad-hoc `HashMap` + broadcast. Needs an ADR before the writer is designed (affects Hubble/service lookups, Envoy, L2).
- NodePort surrogate: keep programming the 0.0.0.0/:: entry (needed by socket LB host lookups) — confirm in the socket-LB program inventory.
- `bpf-lb-sock-hostns-only` interaction with LRP skip-LB and termination (reference disables pod-netns termination when hostns-only) — carry the same rule.
- Active backend health checker is an extension point only (`SetIsServiceHealthCheckedFunc`); do we implement a checker (HTTP/TCP probes per backend) in-tree?
- Which LB classes flowsdn will own (`io.cilium/*` strings) — keep Cilium's class names for drop-in compatibility or mint `flowsdn.io/*`?
- `--enable-service-topology` default false in reference; consider default true (upstream kube-proxy honours hints by default).
