# Service load balancing (kube-proxy replacement) — specification

Status: draft. Derived from: `docs/inventory/04-loadbalancer.md` (primary),
`docs/inventory/02-bpf-maps-loader.md`, `docs/inventory/13-crds-k8s.md`;
reference cilium v1.20.1 (7d68cfb394) paths `pkg/loadbalancer/**` (root types,
`config.go`, `writer/`, `reflectors/`, `reconciler/`, `maps/`, `healthserver/`,
`redirectpolicy/`, `tests/testdata/*.txtar`), `pkg/maglev/maglev.go`,
`pkg/murmur3/murmur3.go`, `pkg/kpr/kpr.go`, `pkg/k8s/endpoints.go`,
`pkg/annotation/k8s.go`, `pkg/lbipamconfig/cell.go`, `operator/pkg/lbipam/**`,
`pkg/l2announcer/l2announcer.go`, `pkg/datapath/l2responder/l2responder.go`,
`daemon/healthz/kube_proxy_healthz.go`,
`pkg/k8s/apis/cilium.io/v2/{clrp,lbipam}_types.go`,
`pkg/k8s/apis/cilium.io/v2alpha1/l2announcement_types.go`. Governed by
ADR-0001..0004. Builds on spec `00-foundation-table-config.md` (table store,
reconciler helper, config registry, fences) and `01-bpf-map-abi-loader.md`
(LB map layouts — referenced, never redefined here); interlocks with
`04-conntrack-nat.md` §3.8–3.10 (service CT entries, backend-gone) and
`02-datapath-programs.md` §3.6/§3.12 (datapath-side selection).

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* flowsdn does and the exact data it exchanges; it does not transcribe
reference code. Where the reference behavior is kept for compatibility the
dependent consumer is named (datapath programs, cilium-dbg, kubelet/kube-proxy
probes, cloud LB health checkers, other flowsdn nodes, LB IPAM consumers,
BGP/L2). Where flowsdn deviates, the paragraph is marked **DEVIATION** with the
reason.

## 1. Scope

In scope — the userspace control plane of the kube-proxy replacement:

- The service model: services, frontends, backends, backend states, weights,
  the 16 service flag bits, the master-slot union.
- Translation of Kubernetes `Service` + `EndpointSlice` + local `Pod`
  hostPorts into that model, including every annotation honored.
- Backend selection per frontend (traffic policies, port names, topology,
  proxy delegation, health).
- The BPF reconciler: write ordering into the LB maps, ID allocation, restore
  from pinned maps, pruning, NodePort address expansion, wildcard entries.
- Maglev table computation, frozen bit-exact.
- The `healthCheckNodePort` HTTP servers and the kube-proxy-compatible
  `/healthz`.
- Socket LB as seen from userspace (config, `cilium_skip_lb`, socket
  termination — the last one deferred).
- Local Redirect Policy (`CiliumLocalRedirectPolicy`).
- LB IPAM in the operator (`CiliumLoadBalancerIPPool`).
- L2 announcements (`CiliumL2AnnouncementPolicy`) and the L2 responder maps.

Out of scope, owned elsewhere: BPF program behavior (`02`), LB map layouts and
sizing mechanics (`01`), CT service entries (`04`), the `NodeAddress` /
`Device` tables and `nodeport-addresses` selection (datapath userspace spec),
ClusterMesh global services (`service_merger`; ClusterMesh spec — this spec
only reserves the `ClusterID` field and source-priority merging), L7 /
`CiliumEnvoyConfig` (`ProxyRedirects` is a field written by the Envoy spec),
BGP advertisement of LB IPs (BGP spec), the agent REST route plumbing (agent
API spec; the `GET /service` / `GET /lrp` payloads are fixed here), NAT46/64
service path (dormant at this tag; §12).

## 2. Compatibility contract

| Interface | MUST match | Consumer |
|---|---|---|
| LB map names, key/value layouts, pin paths | spec 01 §2.2 rows `cilium_lb{4,6}_services_v2`, `_backends_v3`, `_reverse_nat`, `_affinity`, `cilium_lb_affinity_match`, `_source_range`, `_maglev` (+ inner), `_reverse_sk`, `cilium_skip_lb{4,6}`, `cilium_l2_responder_v{4,6}`; §4.3 layouts | datapath programs, `cilium-dbg bpf lb list`, `cilium-dbg bpf lb maglev list` |
| Service flag bits (§4.3) | bit values 0..15, split low byte → `flags`, high byte → `flags2` | datapath `lb.h`, `cilium-dbg` flag decoding |
| Backend state flags | `active 0`, `terminating 1`, `quarantined 2`, `maintenance 3` in `lb{4,6}_backend.flags` | datapath, `cilium-dbg` |
| Master slot union | `alg<<24 \| affinity_timeout_s & 0xFFFFFF`, or `htons(proxy_port)` when an L7 redirect exists for the port | datapath |
| Slot layout | slot 0 master; slots `1..count` load-balanced; `count+1..count+qcount` lookup-only | datapath (spec 04 §3.8) |
| Maglev table | pure function of `(seed, M, sorted backend hash strings, weights)` (§5.1) | every other node in the cluster (flow-consistent backend choice), `cilium-dbg bpf lb maglev` |
| `bpf-lb-maglev-hash-seed` split | bytes 0–3 murmur seed, 4–7 `jhash` seed 0, 8–11 `jhash` seed 1, each big-endian u32 | datapath `__hash_from_tuple_v{4,6}` |
| Service annotations (§2.1) | exact keys, values, gates | users, Helm docs |
| `CiliumLocalRedirectPolicy` v2, `CiliumLoadBalancerIPPool` v2 (+v2alpha1 served), `CiliumL2AnnouncementPolicy` v2alpha1 | field names and semantics in §4.6–4.8 | CRD spec, users, cilium-cli |
| Service status written by the operator | `.status.loadBalancer.ingress[].ip` (no `ipMode`, VIP semantics), condition type `cilium.io/IPAMRequestSatisfied` with reasons in §3.10 | kubectl, BGP, L2 announcer, external controllers |
| Pool status conditions | `cilium.io/PoolConflict`, `cilium.io/IPsTotal`, `cilium.io/IPsAvailable`, `cilium.io/IPsUsed`; printcolumns read them | kubectl printcolumns, dashboards |
| L2 leases | `coordination.k8s.io/Lease` named `cilium-l2announce-<ns>-<name>` in the agent namespace, holder identity = node name | other nodes, operators debugging |
| L2 policy status conditions | types `io.cilium/bad-node-selector`, `io.cilium/bad-interface-regex`, `io.cilium/bad-service-selector` | users |
| LB classes | `io.cilium/bgp-control-plane`, `io.cilium/l2-announcer` | users' Service specs |
| `healthCheckNodePort` HTTP | `:<port>` all addresses; JSON `{"service":{"namespace","name"},"localEndpoints":N}`; header `X-Load-Balancing-Endpoint-Weight: N`; 200 if N>0 else 503 | cloud LB health checkers, kube-proxy-compatible tooling |
| `/healthz` | on `kube-proxy-replacement-healthz-bind-address`; body `{"lastUpdated": "<ts>","currentTime": "<ts>"}`; 503 when agent status not OK/Disabled or node being deleted | kubelet-style probes, monitoring that replaced kube-proxy's `:10256` |
| `GET /service`, `GET /lrp` | `models.Service`/`models.LRPSpec` JSON as in inventory 04 "REST model"; `status.realized` from the reconciler status table (spec 00 §4.2) | `cilium-dbg service list`, `cilium-dbg lrp list` |
| Config keys | every key in §6 byte-identical | Helm ConfigMap |
| HostPort synthetic service name | `<ns>/<pod>:host-port:<hostPort>:<uid>` | `cilium-dbg service list` readers, tests |
| Health-server pseudo service | `<svc name>:healthserver` | same |
| LRP pseudo service | `<ns>/<lrp>:local-redirect` | same, `GET /lrp` |

Nothing else in this spec is a compatibility surface. In particular the
in-memory table schemas, the reflector batching, and the ID allocator are
internal.

### 2.1 Service annotations honored (frozen)

`annotation.Get(obj, key, aliases…)` semantics: the primary key is checked
first, then each alias in order; the first present wins. Values are compared
case-insensitively where noted.

| Key (aliases) | Object | Values | Effect | Gate |
|---|---|---|---|---|
| `service.cilium.io/lb-algorithm` | Service | `random`, `maglev` | per-service algorithm in master union top byte; overrides `bpf-lb-algorithm`; also decides Maglev LUT provisioning | `bpf-lb-algorithm-annotation=true` |
| `service.cilium.io/forwarding-mode` | Service | `dsr`, `snat` (lower-cased) | per-service `FwdModeDSR` flag; invalid value → warning, global mode used | `bpf-lb-mode-annotation=true` |
| `service.cilium.io/node` | Service | `<label value>` | install only on nodes whose label `service.cilium.io/node` equals the value | always |
| `service.cilium.io/node-selector` | Service | k8s label selector string | install only where the selector matches the local node labels; takes precedence over `/node`; unparsable → warning, service installed | always |
| `service.cilium.io/type` | Service | `ClusterIP`, `NodePort`, `LoadBalancer` | provision only that frontend type; other values → warning, all types | always |
| `service.cilium.io/src-ranges-policy` | Service | `allow` (default), `deny` (lower-cased) | `deny` inverts `loadBalancerSourceRanges` into a deny list (master flag bit 14) | source ranges enforced for the frontend |
| `service.cilium.io/proxy-delegation` | Service | `none` (default), `delegate-if-local` (lower-cased) | flag bit 11 set; backend selection restricted to addresses that are local node IPs | always |
| `service.cilium.io/weight` | **EndpointSlice** | u16 decimal | weight for every endpoint in the slice; `0` ⇒ every endpoint `Maintenance`; unparsable → warning, default 100 | always |
| `service.cilium.io/lb-l7` | Service | `enabled` | L7 redirect via Envoy (`ProxyRedirects` written by the Envoy spec) | `loadBalancer.l7.backend=envoy` |
| `service.cilium.io/global`, `/shared`, `/affinity`, `/global-sync-endpoint-slices`, `/local-endpointslice` (aliases `io.cilium/global-service`, `io.cilium/shared-service`, `io.cilium/service-affinity`) | Service | see ClusterMesh spec | global services | ClusterMesh |
| `lbipam.cilium.io/ips` (`io.cilium/lb-ipam-ips`) | Service | comma-separated IPs | requested LB IPs (in addition to `spec.loadBalancerIP`) | LB IPAM |
| `lbipam.cilium.io/sharing-key` (`io.cilium/lb-ipam-sharing-key`) | Service | string | services with equal key may share an IP (§3.10) | LB IPAM |
| `lbipam.cilium.io/sharing-cross-namespace` (`io.cilium/lb-ipam-sharing-cross-namespace`) | Service | comma-separated namespaces or `*` | permit sharing across namespaces (both sides must permit) | LB IPAM |
| `service.kubernetes.io/topology-aware-hints` (deprecated, precedence) then `service.kubernetes.io/topology-mode` | Service | anything but `""`, `disabled`, `Disabled` | `TrafficDistribution = PreferSameZone` when `spec.trafficDistribution` is unset | `enable-service-topology=true` |
| `service.kubernetes.io/service-proxy-name` (**label**) | Service, EndpointSlice | string | watched only if equal to `k8s-service-proxy-name` (default `""` = objects without the label) | always |
| `service.kubernetes.io/headless` (**label**) | Service | presence | zero frontends | always |

## 3. Behavior

### 3.1 Service model

Three tables (spec 00 §3.1), one `Writer` (§3.1.6):

- **Service** — keyed by `ServiceName` = `[<cluster>/]<ns>/<name>`. Carries
  everything that is per-service, not per-address: source, labels,
  annotations, selector, `NatPolicy` (`NONE|Nat46|Nat64`), external and
  internal traffic policy (`Cluster|Local`), `ForwardingMode` (`""|dsr|snat`),
  `SessionAffinity` + timeout, `LoadBalancerClass`, `ProxyRedirects`
  (`[{ProxyPort, Ports}]`), `HealthCheckNodePort`, `LoopbackHostPort`,
  `SourceRanges`, `PortNames` (name → port), `TrafficDistribution`
  (`""|PreferSameZone|PreferClose|PreferSameNode`).
- **Frontend** — keyed by `L3n4Addr` (addr+cluster, port, proto, scope);
  secondary index by service name. Desired part: `Address`, `Type`,
  `ServiceName`, `PortName`, `ServicePort`. Derived part (written by the
  Writer, not by data sources): `Backends` (selection result, §3.3),
  `RedirectTo` (LRP), `Service` snapshot. Reconciler-owned: `ID` (rev-NAT id)
  and status (spec 00 §3.2.2 side table).
- **Backend** — keyed by `(ServiceName, L3n4Addr, source priority)`;
  secondary index by address. `PortNames`, `Weight` (default **100**),
  `NodeName`, `Zone{Zone, ForZones}`, `ClusterID` (0 = local), `Source`,
  `State`, `Unhealthy`, `UnhealthyUpdatedAt`.

Frontend types: `ClusterIP`, `NodePort`, `LoadBalancer`, `ExternalIPs`,
`HostPort`, `LocalRedirect` (and `NONE`). Scopes: `External = 0`,
`Internal = 1`.

Backend states (ordering matters for slot sorting):

| State | value | datapath flag | k8s origin | in slots | LB-able |
|---|---|---|---|---|---|
| `Active` | 0 | 0 | ready (even if terminating) | yes | yes |
| `Terminating` | 1 | 1 | terminating ∧ serving ∧ ¬ready | yes | only when `active == 0` |
| `TerminatingNotServing` | 2 | 1 | terminating ∧ ¬serving | yes (q-range) | no |
| `Quarantined` | 3 | 2 | never from k8s; health checker / API | yes (q-range) | no |
| `Maintenance` | 4 | 3 | ¬ready ∧ ¬terminating, or weight 0 | **no** (map only) | no |

`alive(be) := ¬Unhealthy ∧ State ∈ {Active, Terminating}`. `Unhealthy` is an
overlay supplied through the health integration hook (no in-tree active
TCP/HTTP prober, #84); it MUST NOT change `State` (a backend
may be healthy for one service and not for another) but it places the backend
in the quarantined range (§3.4 step 6).

Allowed transitions (informative, from the reference's documented table):
`Active → Terminating | Quarantined | Maintenance`; `Quarantined → Active |
Terminating`; `Maintenance → Active`; terminating states are terminal.

### 3.2 Kubernetes Service + EndpointSlice → model

The reflector (§3.2.6) turns each Service into one `Service` row plus a list of
`FrontendParams`, and each EndpointSlice into a set of `Backend` rows for its
owning service. Rules, in order:

**3.2.1 Service row.** Name/labels/annotations/selector copied.
`HealthCheckNodePort = spec.healthCheckNodePort`. `LoadBalancerClass =
spec.loadBalancerClass` (pointer, nil when unset). `ForwardingMode` from the
annotation when `bpf-lb-mode-annotation`, else `""`. `PortNames[port.name] =
port.port` for every port (the unnamed port maps `"" → port`). Every entry of
`spec.loadBalancerSourceRanges` is parsed as a prefix; unparsable entries are
skipped with a debug log.

`ExtTrafficPolicy = Local` iff `spec.externalTrafficPolicy == Local`, else
`Cluster`. `IntTrafficPolicy = Local` iff `spec.internalTrafficPolicy ==
Local`, else `Cluster`. **Two scopes** := exactly one of the two is `Local`;
then NodePort and LoadBalancer frontends are emitted twice, once per scope.

`SessionAffinity = true` iff `spec.sessionAffinity == ClientIP`; timeout =
`spec.sessionAffinityConfig.clientIP.timeoutSeconds` if set and non-zero, else
**10800 s**. `TrafficDistribution` is computed (§3.2.4) only when
`IntTrafficPolicy != Local`.

**Node exposure.** If `service.cilium.io/node-selector` is present: parse;
parse error → warn and treat as matching; else install only if the selector
matches the local node's labels. Otherwise if `service.cilium.io/node` is
present: install only if the local node has label `service.cilium.io/node`
with exactly that value. A non-matching service MUST be treated as deleted on
this node (service row and frontends removed).

**Type exposure.** `service.cilium.io/type` restricts which frontend blocks
below run (`CanExpose(t)`); an unsupported value warns and exposes all.

**Headless / ExternalName.** If label `service.kubernetes.io/headless` is
present or `spec.clusterIP` equals `None` (case-insensitive): keep the Service
row, emit **no** frontends. `type: ExternalName` services have no ClusterIP
and no `status.loadBalancer.ingress`; they fall through every block and
produce no frontends. flowsdn MUST NOT proxy ExternalName (kube-proxy parity).

**3.2.2 Frontends.** Family filtering applies everywhere: an address (or
family) whose IP family is disabled (`enable-ipv4`/`enable-ipv6`) is skipped
with a debug log.

1. **ClusterIP** (if exposable): addresses = `spec.clusterIPs` sorted
   lexicographically, else `[spec.clusterIP]`; unparsable → skip. For each
   address × each `spec.ports[]`: type `ClusterIP`, scope External, port =
   `port.port`, proto = `port.protocol` verbatim (`TCP`/`UDP`/`SCTP`),
   `PortName = port.name`, `ServicePort = port.port`.
2. **NodePort** (only when `kube-proxy-replacement=true`, service type
   `NodePort` or `LoadBalancer`, exposable as NodePort): for each scope
   (External, plus Internal when two scopes) × each IP family × each port with
   `port.nodePort != 0`: type `NodePort`, address = surrogate `0.0.0.0` (v4) /
   `::` (v6), port = `port.nodePort`, `ServicePort = port.port`. IP families
   := `spec.ipFamilies` if non-empty; else if `spec.clusterIP` is empty or
   `None` → none; else the families of `spec.clusterIPs` (or `spec.clusterIP`).
   `allocateLoadBalancerNodePorts=false` yields `nodePort == 0` and thus no
   frontend; there is no other handling.
3. **LoadBalancer** (service type `LoadBalancer`, exposable): for each
   `status.loadBalancer.ingress[]` with non-empty `ip` and `ipMode` nil or
   `VIP` (KEP-1860 `Proxy` entries and hostname-only entries are skipped),
   for each scope × port: type `LoadBalancer`, address = the ingress IP, port
   = `port.port`.
4. **ExternalIPs**: for each `spec.externalIPs[]` (parsable) × port: type
   `ExternalIPs`, scope External, port = `port.port`.

**NodePort-range conflict.** On upsert the Writer drops any `LoadBalancer` or
`ExternalIPs` frontend whose port lies within `[NodePortMin, NodePortMax]` and
whose address equals a node address flagged NodePort (table `node-addresses`,
index `node-port=true`), logging a warning. The rest of the service is
installed.

**Frontend ownership.** A frontend address already owned by a *different*
service is a conflict: the upsert of the whole service fails with
`ErrFrontendConflict` (reported in module health, retried on the next event).
Test `name-collisions`.

**3.2.3 EndpointSlice → backends.** Only slices whose
`service.kubernetes.io/service-proxy-name` label equals
`k8s-service-proxy-name` are watched. Owning service = label
`kubernetes.io/service-name` in the slice's namespace. Per endpoint:

- Conditions: `ready` nil ⇒ true; `serving` nil ⇒ true; `terminating` nil ⇒
  false.
- `NodeName = endpoint.nodeName` (fallback: the deprecated topology
  `kubernetes.io/hostname` entry). `Zone = endpoint.zone`, fallback
  `deprecatedTopology["topology.kubernetes.io/zone"]`. `ForZones =
  hints.forZones[].name`.
- Weight: slice annotation `service.cilium.io/weight` parsed as u16; `0` sets
  `Maintenance = true`; absent/invalid → 0 → replaced by **100** unless
  `Maintenance`.
- For each slice `ports[]` × endpoint address: `L3n4Addr(proto, addr, port,
  External)`. The port name list of the backend is the slice port names for
  that (port, proto); an empty name is removed from the list; a list that
  becomes empty is `nil` (matches every frontend port name).
- The legacy ingress dummy `192.192.192.192:9999` MUST be ignored.
- State: `Maintenance` if weight-0; else `Active` if ready; else
  `TerminatingNotServing` if terminating ∧ ¬serving; else `Terminating` if
  terminating; else `Maintenance` (not ready, not terminating — kept in the
  backend map so existing connections survive readiness flaps, excluded from
  slots).
- Family filtering as above. `publishNotReadyAddresses` is not read: its
  effect arrives through the conditions kube-controller-manager publishes.

Multiple slices of one service are merged per batch; a backend address that
disappears from *all* slices of the service is deleted (`SetBackends` of the
union). Test `multiple-endpointslices`.

**3.2.4 Traffic distribution.** `spec.trafficDistribution` ∈
`PreferSameZone | PreferClose | PreferSameNode` maps 1:1; otherwise the
topology annotations (§2.1) give `PreferSameZone`; otherwise `""`. Effective
only with `enable-service-topology=true` and `IntTrafficPolicy != Local`.

**3.2.5 SCTP.** The control plane treats `SCTP` like any L4 type (byte `S`,
protocol 132) with no gate. The datapath handles SCTP only when `enable-sctp`
is on; without it SCTP frontends are programmed but not matched (reference
parity; documented in §7).

**3.2.6 Reflector mechanics.** Services and EndpointSlices are two watches
merged into one buffered stream: events are keyed by `(kind, ns/name)` in an
insertion-ordered map and flushed when the buffer holds 500 entries or
`lb-reflector-wait-time` (500 ms) has elapsed since the first entry, so a
Service and its slices land in one Writer transaction. An initial list /
relist is one `Sync` entry: services absent from the list are deleted (except
synthetic `:host-port:` ones), all previously known slice backends are
replaced by the listed set, frontends of services that lost every backend are
refreshed, then the reflector's initializer (spec 00 §3.1.6) is marked
complete. Per-service processing errors aggregate into module health
`Degraded: Failure processing services` and clear on success.

### 3.3 Backend selection (Writer)

For every frontend the Writer computes the ordered candidate set that the
reconciler will program. Recomputed (and the frontend marked Pending) whenever
the service, any backend of the service, the local node labels/zone, or the
NodePort address set changes.

1. **Frontend match**: `be.proto == fe.proto`; same IP family; if
   `fe.PortName != ""` and `be.PortNames` non-empty then `fe.PortName ∈
   be.PortNames`.
2. **Local-only** (`shouldUseLocalBackends`): External-scope ClusterIP →
   `IntTrafficPolicy == Local`; External-scope NodePort/LoadBalancer/
   ExternalIPs → `ExtTrafficPolicy == Local`; Internal-scope (any of
   ClusterIP/NodePort/LoadBalancer/ExternalIPs) → `IntTrafficPolicy == Local`;
   HostPort/LocalRedirect → never. When local-only, keep only backends with
   `NodeName == ""` or `NodeName == local node`.
3. **Proxy delegation** (`delegate-if-local`): additionally keep only backends
   whose address is one of the local node's IPs (for the health-server /
   service-less path this is evaluated without a frontend).
4. **PreferSameNode** (topology on, `TrafficDistribution == PreferSameNode`):
   if at least one backend on this node passes 1 and is a *topology
   candidate*, the result is exactly those; else fall through.
5. **PreferSameZone / PreferClose** (topology on, node has label
   `topology.kubernetes.io/zone`, `fe.RedirectTo == nil`): scan candidates
   passing 1–3 that are topology candidates; if *every* one carries
   `ForZones` hints and at least one lists this node's zone, keep only
   backends whose hints contain the zone; otherwise (any candidate without
   hints, or none for this zone) use all — no hints, no filtering.
6. **Topology candidate** := not `Terminating`/`TerminatingNotServing`, and —
   when the service is health-checked (§3.3 hook) — `Active ∧ ¬Unhealthy ∧
   UnhealthyUpdatedAt != nil` (verified at least once).

Source priorities: the same address may be contributed by several sources
(k8s, ClusterMesh, local file/API, health server); the lowest priority number
wins per address (`PreferredBackendsByAddress`, which relies on the primary
key ordering `service, address, priority`).

### 3.4 Reconciler: frontend → LB maps

One `Reconciler<Frontend>` (spec 00 §3.2) with a `Target` that owns all LB
maps; single-threaded per node (one mutex). `update` MUST be idempotent and
MUST mutate its bookkeeping only after the corresponding map operation
succeeded, so a failed step is retried from the same desired row without
double-counting.

**Candidacy.** Frontends of a disabled IP family are ignored (no-op). With
`kube-proxy-replacement=false` only `ClusterIP`, `LocalRedirect` and
`ExternalIPs` are datapath candidates; a non-candidate frontend is *deleted*
from the maps (and `fe.ID = 0`) but kept in the table. Tests
`kpr-transition-to-*`.

**Rejected combinations** (error, row `Error`, retried with backoff):
`SessionAffinity` with `ProxyRedirects`; `LoopbackHostPort` with proxy
delegation.

**Update(fe), for a concrete address** — ordered steps; each step's map write
MUST complete before the next begins:

| # | Step | Map(s) | Atomicity need |
|---|---|---|---|
| 1 | Service ID: reuse restored ID for this address if present, else allocate (§5.3). Write `fe.ID`. | — | — |
| 2 | Compute flags (§4.3), `rev_nat_index = ID`. Sort backends (§5.2). | — | — |
| 3 | **Orphans**: backends referenced by this frontend last time but not now, with refcount 1 → delete affinity-match `(ID, beID)`, delete backend, release backend ID. | `_backends_v3`, `_affinity_match` | delete match before backend so affinity can never point at a dead id |
| 4 | **Backends**: for each sorted backend, get/restore/allocate its ID; upsert the backend value if its table revision changed since the last write (`needsUpdate`). | `_backends_v3` | backends exist before any slot references them |
| 5 | **Slots**: skipping `Maintenance` backends, write slot `1..N` `(key{slot}, value{backend_id, rev_nat})`. Upsert affinity-match for `Active` backends of an affinity service, else delete it. | `_services_v2`, `_affinity_match` | slots written before the master's `count` grows; a slot beyond the old `count` is invisible until step 9 |
| 6 | **Counting**: `active` = Active ∧ ¬Unhealthy; `terminating` = Terminating ∧ ¬Unhealthy; `inactive` = everything else in slots (Unhealthy → counted as quarantined, TerminatingNotServing, Quarantined). **If `active == 0` then `active = terminating`, else `inactive += terminating`** (KEP-1669 graceful termination). | — | — |
| 7 | **Maglev** (if §3.13 says so): LUT from `sorted[:active]`; if `active == 0` delete the LUT. | `_maglev` | LUT references only backends written in step 4 |
| 8 | **Source ranges**: upsert `(ID, cidr)` for each family-matching prefix, delete previously programmed prefixes no longer listed. | `_source_range` | — |
| 9 | **Rev-NAT**: upsert `ID → (fe.addr, fe.port)`. | `_reverse_nat` | before master so `rev_nat_index` in CT resolves |
| 10 | **Master slot 0**: `count = active`, `qcount = inactive`, flags, `backend_id = 0` then union (alg, affinity timeout, or proxy port — §4.3). | `_services_v2` | the single publish point: readers see the new backend set atomically |
| 11 | **Wildcard** (§3.5): upsert or delete the `(addr, port 0, proto ANY)` entry. | `_services_v2` | — |
| 12 | **Stale slots**: if the number of slotted backends changed, delete slots `newTotal+1 .. oldTotal`. | `_services_v2` | after master shrank `count+qcount`, so no live lookup reads a deleted slot |
| 13 | Commit references: backend refcounts for this frontend, `prevSourceRanges`. | — | only now, so a failure above retries cleanly |

`lastUpdatedAt` is stamped after every `update` (used by `/healthz`).

**Delete(fe)**: if the frontend has an ID: drop restored-quarantine state;
delete Maglev LUT (if applicable); delete affinity-match for every referenced
backend; delete orphan backends (refcount 1) and release their IDs; delete
slots `0..N`; delete rev-NAT; delete this frontend's source-range entries;
drop wildcard reference (delete the entry when the last reference goes);
release the service ID. For a surrogate NodePort/HostPort frontend, `Delete`
also deletes every expansion (§3.5).

**Restore on start** (§5.4) then **init wait**: if anything was restored, wait
up to `lb-init-wait-timeout` (1 min) for all registered initializers (k8s
services, endpoints, pods, LRP, ClusterMesh, file) before the first round —
timeout is a warning, not fatal. Prune runs first after initialization and
then every 30 min (`prune_interval` override of spec 00 §3.2.4).

**Prune** removes, in this order and joining errors: the restored-ID maps;
service entries beyond a frontend's expected slot count or for unknown
frontends (wildcard entries only if unreferenced); backends with unknown IDs;
rev-NAT, source-range and Maglev entries whose rev-NAT id is not allocated.

### 3.5 NodePort expansion, surrogates, wildcards

A `NodePort` frontend, and a `HostPort` frontend with the unspecified address,
is a **surrogate**: it is programmed itself (non-routable; needed for socket-LB
and host lookups) and **expanded** into one service entry per node address
with the same family from `node-addresses` where `node-port=true`. Per
expansion the reconciler runs the full Update above with the concrete address
and `isLocalAddr = nil`. Expansions skip any address that is a **primary**
frontend of another service (a `LoadBalancer`/`ExternalIPs` frontend already
owns `addr:port/proto`); orphan expansions (address left the set) are deleted,
except when that address became a primary. The `node-addresses` reconciler
marks all surrogate frontends Pending whenever the NodePort address set
changes.

**Wildcard entries** (`bpf-lb-enable-wildcard-entries`, default true): for a
`LoadBalancer` or `ClusterIP` frontend of External scope whose service is of a
*wildcard class* — `loadBalancerClass == nil ∧ default-lb-service-ipam ==
lbipam`, or class ∈ {`io.cilium/bgp-control-plane`, `io.cilium/l2-announcer`}
— and whose address is **not** a local node address, an entry
`(addr, port 0, proto 0 ANY, same scope, slot 0)` with flags = type bit only
is programmed so the datapath drops traffic to unknown ports on the VIP
instead of handing it to the host stack. Reference-counted per address by
service ID; deleted with the last reference or when the address becomes local
or the flag is off. Tests `loadbalancer-{class,disabled,localaddr}-wildcards`.

### 3.6 HostPort synthesis from pods

Only with `kube-proxy-replacement=true`; waits for the local-pod table to
initialize. For a local pod that is `Running` and has no `deletionTimestamp`
(a terminating pod keeps its HostPort until it disappears or reaches
`Failed`/`Succeeded`), for every init/regular container port with
`hostPort > 0`:

- `hostPort` inside `[NodePortMin, NodePortMax]` → warning, ignored.
- Service name `<ns>/<pod>:host-port:<hostPort>:<uid>` (the infix is
  intentionally not RFC-1123 so it cannot collide with a real Service), type
  `HostPort`, both traffic policies `Cluster`, source Kubernetes.
- Backends: every valid pod IP (family-filtered) × `containerPort`, weight 100.
- Frontend address: `hostIP` unset → surrogate `0.0.0.0` if the pod has an
  IPv4, `::` if it has an IPv6 (expanded per §3.5); explicit non-loopback
  `hostIP` → that one address; loopback `hostIP` → surrogate of that family
  and `LoopbackHostPort = true` (flag bit 11; datapath restricts reachability
  to the node). Loopback requires netns-cookie support; without it the port is
  ignored with a warning. Mixing a loopback and a non-loopback `hostIP` in one
  synthetic service → the later one is skipped with a warning.
- Pods that are `Failed`/`Succeeded`, deleted, or `hostNetwork: true` release
  every HostPort service they own immediately.

### 3.7 externalTrafficPolicy=Local health check server and `/healthz`

**healthCheckNodePort** (`enable-health-check-nodeport`, default true, KPR
on): for every `LoadBalancer` or `NodePort` frontend of External scope whose
service has `HealthCheckNodePort > 0` and `ExtTrafficPolicy == Local`, run one
HTTP listener on `:<healthCheckNodePort>` (all addresses; listen failure
retried with backoff from 200 ms). Response on any path: headers
`Content-Type: application/json`, `X-Content-Type-Options: nosniff`,
`X-Load-Balancing-Endpoint-Weight: <N>`; status 200 if `N > 0` else 503; body
`{"service":{"namespace":"…","name":"…"},"localEndpoints":N}`. `N` = number
of preferred-source backends of the service with `NodeName ∈ {"", local}` and
`State == Active` — or exactly **1** when the service has `ProxyRedirects`.
The listener is removed when the frontend or the conditions go away.

**enable-health-check-loadbalancer-ip** (default false): additionally, for
each such `LoadBalancer` frontend, upsert a pseudo service
`<name>:healthserver` (source Local, both policies Local) with frontend
`(VIP, hcPort, TCP, External)` type `LoadBalancer` and one backend
`(<first NodePort node address of the VIP's family>, hcPort, TCP)` marked
`Active` on this node, so an external load balancer can probe the VIP itself.

**`/healthz`** (`kube-proxy-replacement-healthz-bind-address`, default `""` =
off; typically `0.0.0.0:10256`): body `{"lastUpdated": "<time>","currentTime":
"<time>"}` (Go time formatting, `%q`-quoted). 503 when the agent status is not
`Ok`/`Disabled` or the local node is being deleted, in which case
`lastUpdated` is the reconciler's last successful map write; otherwise 200
and both timestamps are now. Bind failure logs the kube-proxy hint and fails
the module.

### 3.8 Socket LB from userspace

`kube-proxy-replacement=true` **forces** `bpf-lb-sock=true`. Socket LB itself
is datapath (spec 02: cgroup `connect/sendmsg/recvmsg/getpeername/bind/
post_bind/sock_release` hooks). Userspace obligations (**socket LB retained for milestone 2**, #2, ADR-0011):

- Program the surrogate `0.0.0.0`/`::` NodePort entries (§3.5; resolved #11) — the socket
  programs look them up for host-namespace connects to `<nodeIP>:<nodePort>`.
- `bpf-lb-sock-hostns-only` (default false) selects the program variant that
  only translates sockets whose netns cookie is the host's; pods then rely on
  tc-level LB. It also disables pod-netns socket termination (#12), including
  when the termination flag is true; retain the LRP skip-LB checks before
  service translation. Host-netns termination is unaffected by this restriction.
- `cilium_skip_lb{4,6}` (hash, **100** entries, key `(netns_cookie, addr,
  port)`): a socket in that netns connecting to that frontend is not
  translated. Written only by the LRP controller (§3.9). Entries whose cookie
  belongs to no known endpoint are pruned on full reconcile.
- `cilium_lb{4,6}_reverse_sk` is sized by `bpf-sock-rev-map-max` (0 = dynamic:
  the CT-any default through the dynamic-size calculator, at least 64Ki,
  LRU-aligned, within `[1Ki, 16Mi]`).
- **Socket termination** — **scheduled for the LB implementation milestone** (#82;
  §12.3). When implemented it MUST: watch backend changes; for deleted or
  non-alive UDP backends (TCP too only with hidden
  `lb-sock-terminate-all-protos`) destroy matching sockets via
  `SOCK_DESTROY`/`inet_diag` in the host netns, and in every pod netns when
  `bpf-lb-sock-terminate-pod-connections` (default **true**) and not
  hostns-only, filtered to sockets whose cookie appears in `_reverse_sk`;
  batched at one pass per 50 ms; kernel without `CONFIG_INET_DIAG_DESTROY` →
  module Degraded, feature off.

### 3.9 Local Redirect Policy

Enabled by `enable-local-redirect-policy` (default false). CRD
`cilium.io/v2 CiliumLocalRedirectPolicy` (namespaced), fields in §4.6.

**Validation** (invalid → policy status `ok: false`, error logged): name and
namespace non-empty; exactly one of `redirectFrontend.addressMatcher` /
`serviceMatcher`; addressMatcher IP parsable and — when
`lrp-address-matcher-cidrs` is non-empty — inside one of the CIDRs;
serviceMatcher `namespace` equal to the policy namespace; ports parsable;
frontend type derived as: serviceMatcher with no `toPorts` → `svcFrontendAll`;
with exactly one → `svcFrontendSinglePort`; with several → `svcFrontendNamedPorts`
(every port MUST carry a `name`); addressMatcher with one port →
`addrFrontendSinglePort`; several → `addrFrontendNamedPorts` (names required).
In the single-port cases the backend port's protocol MUST equal the frontend
port's protocol. Named cases match backend ports to frontend ports by name.

**Controller.** A pseudo service `<ns>/<lrp>:local-redirect` holds backends =
pods in the policy namespace matching `localEndpointSelector` that are Ready,
× their container ports matching `redirectBackend.toPorts` (by number and
protocol; by name in the named cases). Then:

- **serviceMatcher**: every `ClusterIP` frontend of the target service whose
  port matches the rules gets `RedirectTo = pseudo service` — only while the
  pseudo service has ≥ 1 backend; with zero matching pods the redirect is
  removed and the service's own backends are used (test `no-target-pods`).
  The reconciler programs such a frontend as type `LocalRedirect` (flag bit 8).
- **addressMatcher**: new frontends of type `LocalRedirect` at
  `ip:port/proto` for each frontend port (or the named ports); an address
  already owned by another service is refused (test `address-matcher-conflict`);
  frontends are deleted when no pod matches.
- **skipRedirectFromBackend**: for each backend pod, program
  `cilium_skip_lb` `(pod netns cookie, frontend addr, port)` for every
  redirected frontend so the redirect target (e.g. node-local DNS) can still
  reach the original ClusterIP. Cookies come from the endpoint manager; a
  policy seen before its pod's endpoint is completed when the cookie appears.
  Requires kernel ≥ 5.12 (netns cookie); otherwise warn once and skip.

`GET /lrp` lists policies. Tests: the 12 txtar in §9.

### 3.10 LB IPAM (operator)

Enabled by `enable-lb-ipam` (default **true**); `default-lb-service-ipam`
`lbipam` (default) | `nodeipam` | `none`. Responsible for `type:
LoadBalancer` services with `loadBalancerClass` nil (only when the default is
`lbipam`) or ∈ {`io.cilium/bgp-control-plane` (when BGP is enabled),
`io.cilium/l2-announcer` (when L2 announcements are enabled)}. Services of any
other class, or that stop being `LoadBalancer`, or whose class changes away,
get their ingress IPs and the `IPAMRequestSatisfied` condition removed.

**Pools** (`CiliumLoadBalancerIPPool`, cluster-scoped, §4.7). Each block is a
`cidr` or a `start`[,`stop`] range. With `allowFirstLastIPs: No` (the
default when unset is `Yes` at this tag; the field is optional) the network and
broadcast addresses of CIDR blocks of size ≥ /30 (v4) or /126 (v6) are
reserved. `disabled: true` stops new allocations but keeps existing ones.
Ranges overlapping another pool's ranges (or each other within one pool) put
the **newer** pool (by `creationTimestamp`) in conflict: condition
`cilium.io/PoolConflict = True`, reason `cidr_overlap`, and all its ranges are
internally disabled; resolution sets `False`, reason `resolved`. Every pool
carries `cilium.io/IPsTotal`, `cilium.io/IPsAvailable`, `cilium.io/IPsUsed`
with the (big-integer) count in `message`.

**Service view**: requested families from `spec.ipFamilyPolicy`/`ipFamilies`/
`clusterIPs` (dual-stack aware; falls back to the enabled families);
requested IPs = `spec.loadBalancerIP` ∪ annotation `lbipam.cilium.io/ips`;
sharing key, cross-namespace list, ports, selector, `externalTrafficPolicy`.

**Sharing compatibility** (all required): equal sharing key; same namespace,
or each side's `sharing-cross-namespace` lists the other's namespace or `*`;
no `(port, protocol)` in common; equal `externalTrafficPolicy`; and when that
policy is `Local`, identical non-empty selectors. Reasons on failure:
`different sharing key`, `different and not permitted namespace`, `same port
and protocol`, `different ExternalTrafficPolicy`, selector mismatch.

**Allocation pass** (§5.6) writes `status.loadBalancer.ingress[].ip` and the
condition `cilium.io/IPAMRequestSatisfied`: `True`/`satisfied`, or `False`
with reason ∈ {`no_pool`, `pool_selector_mismatch`, `out_of_ips`,
`already_allocated`, `already_allocated_incompatible_service`} and a human
message. Status is patched (field manager `cilium-operator-lb-ipam`) only when
changed. Existing ingress IPs are re-imported on operator start so a restart
never reallocates; they are stripped when no longer valid (range gone or
disabled, family no longer requested, not in the requested list, sharing
incompatible).

### 3.11 L2 announcements

Enabled by `enable-l2-announcements` (default false); requires `devices`.
CRD `cilium.io/v2alpha1 CiliumL2AnnouncementPolicy` (cluster-scoped, §4.8).

1. **Policy validation** → status conditions `io.cilium/bad-node-selector`,
   `io.cilium/bad-interface-regex`, `io.cilium/bad-service-selector`
   (`True` with the error as message when invalid, `False` when valid).
2. **Node selection**: a policy applies when `nodeSelector` (nil = all)
   matches the local `CiliumNode` labels; re-evaluated on label change.
3. **Device selection**: devices from the `devices` table whose name matches
   any `interfaces` regex (empty list = all selected devices).
4. **Service selection**: services from the LB tables matched by
   `serviceSelector` on labels plus the synthetic labels
   `io.kubernetes.service.namespace`/`io.kubernetes.service.name`, that have
   `LoadBalancer` frontends (if `loadBalancerIPs`) and/or `ExternalIPs`
   frontends (if `externalIPs`), and `loadBalancerClass` nil or
   `io.cilium/l2-announcer`.
5. **Leader election** per selected service on Lease
   `cilium-l2announce-<ns>-<name>` in the agent namespace, identity = node
   name, with `leaseDuration`/`renewDeadline`/`retryPeriod` from §5.7. The
   leader writes rows `L2AnnounceEntry{IP, NetworkInterface, Origins[]}` for
   every selected IP × selected device; `Origins` (service keys) reference-
   count the same IP/interface across services; losing leadership or
   selection removes only this service's origin. A service selected by no
   policy stops its elector and drops its rows.
6. **Lease GC** every minute deletes `cilium-l2announce-*` leases with an
   empty holder; when the feature is disabled a one-shot GC removes leftovers.
7. **L2 responder** (datapath userspace) reconciles the table into
   `cilium_l2_responder_v4`/`_v6` (key `(ip, ifindex)`, 4096 entries): on a
   newly created entry it sends a gratuitous ARP (v4) or unsolicited NA (v6)
   and, for v6, joins the solicited-node multicast group on the interface;
   removed entries leave the group. A full reconciliation runs at start and
   every 5 minutes.

### 3.12 Forwarding mode (DSR/SNAT)

`bpf-lb-mode` `snat` (default) | `dsr` | `hybrid` (DSR for TCP, SNAT
otherwise). Per frontend: mode = annotation override (only with
`bpf-lb-mode-annotation`, and then `hybrid` is refused as the global default),
else global mode resolved per protocol; `dsr` → flag bit 15.
`bpf-lb-dsr-dispatch` `opt` | `ipip` | `geneve`; `geneve` enables the Geneve
tunnel device without MTU adaptation. Test `hybrid-dsr`,
`svc-forwarding-mode-annotation`.

### 3.13 Algorithm selection and Maglev provisioning

Per-service algorithm = annotation (`bpf-lb-algorithm-annotation` on) else
`Undef` (0), written to the master union top byte. A Maglev LUT is built for a
frontend iff: its address is not a surrogate; and (annotation says `maglev`)
or (no annotation ∧ `bpf-lb-algorithm=maglev` ∧ type ∈ {NodePort,
LoadBalancer, HostPort, ExternalIPs, or ClusterIP only with
`bpf-lb-external-clusterip`}). The datapath uses the annotation byte when
non-zero, else the compile-time default (spec 02 §3.12).

## 4. Data model

### 4.1 Tables (flowsdn-table, spec 00)

| Table | Primary key encoding | Secondary indexes |
|---|---|---|
| `services` | `ServiceName` UTF-8 `[cluster/]ns/name` | — |
| `frontends` | `L3n4Addr` 24 B: `addr` 16 (v4-mapped) ++ `cluster_id` u32 BE ++ `port` u16 BE ++ `proto` u8 (`T`=TCP `U`=UDP `S`=SCTP `?`=ANY `N`=NONE) ++ `scope` u8 | `service` (name, non-unique) |
| `backends` | `ServiceName` ++ `0x00` ++ `L3n4Addr` ++ `0x00` ++ `priority` u8 | `address` (`L3n4Addr`, non-unique) |
| `frontends-status-bpf` | as frontends | (spec 00 §4.2) |
| `lrps` | policy `ns/name` | `service` (target service), `address` |
| `desired-skiplb` | `(pod ns/name)` | `lrp-id` |
| `l2-announce` | `(ip, interface)` | `origin` (multi-key) |

Iterating `backends` with prefix `ServiceName ++ 0x00` yields a service's
backends grouped by address with ascending priority — the invariant
`PreferredBackendsByAddress` needs.

### 4.2 Rows

```
Service   { name, source, labels, annotations, selector, nat_policy: None|Nat46|Nat64,
            ext_traffic_policy, int_traffic_policy: Cluster|Local, forwarding_mode: ""|dsr|snat,
            session_affinity: bool, session_affinity_timeout: Duration, load_balancer_class: Option<String>,
            proxy_redirects: Vec<{proxy_port: u16, ports: Vec<u16>}>, health_check_node_port: u16,
            loopback_host_port: bool, source_ranges: Vec<Prefix>, port_names: Map<String,u16>,
            traffic_distribution: ""|PreferSameZone|PreferClose|PreferSameNode }
Frontend  { address: L3n4Addr, type: SvcType, service_name, port_name, service_port: u16,
            -- derived: backends: Vec<(Arc<Backend>, Revision)>, redirect_to: Option<ServiceName>,
            service: Arc<Service>; -- reconciler-owned: id: u16 }
Backend   { service_name, address: L3n4Addr, port_names: Vec<String>, weight: u16 (100),
            node_name, zone: Option<{zone, for_zones}>, cluster_id: u32, source, state: BackendState,
            unhealthy: bool, unhealthy_updated_at: Option<Time>, source_priority: u8 }
```

`Backend` SHOULD stay ≤ 140 bytes (reference asserts this; it bounds table
memory for large clusters).

### 4.3 Service flags (u16), backend flags, master union

| Bit | Name | Set when | Which entries |
|---|---|---|---|
| 0 | `ExternalIPs` | type ExternalIPs | all slots of the frontend |
| 1 | `NodePort` | type NodePort | all |
| 2 | `ExtLocalScope` | `ExtTrafficPolicy == Local` | all |
| 3 | `HostPort` | type HostPort | all |
| 4 | `SessionAffinity` | `SessionAffinity` | all |
| 5 | `LoadBalancer` | type LoadBalancer | all |
| 6 | `Routable` | address not a surrogate ∧ (type ≠ ClusterIP ∨ `bpf-lb-external-clusterip`) | all |
| 7 | `SourceRange` | source ranges non-empty ∧ (type ∈ {LoadBalancer, ExternalIPs} ∨ `bpf-lb-source-range-all-types`) | all |
| 8 | `LocalRedirect` | type LocalRedirect, or `RedirectTo` set | all |
| 9 | `Nat46x64` | `NatPolicy ∈ {Nat46, Nat64}` | all |
| 10 | `L7LoadBalancer` | a `ProxyRedirect` covers `ServicePort` | all |
| 11 | `Loopback` (a.k.a. L7Delegate) | `LoopbackHostPort` ∨ proxy delegation ≠ none | all |
| 12 | `IntLocalScope` | `IntTrafficPolicy == Local` | all |
| 13 | `TwoScopes` | ext-local ≠ int-local ∧ type ≠ ClusterIP | all |
| 14 | `SourceRangeDeny` | bit 7 ∧ `src-ranges-policy: deny` | master; **the reference never sets the aliased `Quarantined` meaning on backend slots at this tag — flowsdn MUST NOT either** (quarantine is conveyed by slot position and backend state flag) |
| 15 | `FwdModeDSR` | resolved forwarding mode is DSR | all |

Type is one-hot among bits 0/1/3/5/8; ClusterIP is "none of them". Encoded
`flags = low byte`, `flags2 = high byte`. Wildcard entries carry only the type
bit.

Backend value `flags` (u8): state flag from §3.1; `zone` u8 =
`fixed-zone-mapping[be.zone]` (0 when unmapped); `cluster_id` from
`ClusterID`.

Master slot value (`lb{4,6}_service`, spec 01 §4.3): `count` = active,
`qcount` = inactive, `rev_nat_index` = ID, flags as above, and the u32 union
written in this precedence: if a `ProxyRedirect` exists for `ServicePort` the
union is `htons(proxy_port)` in the low 16 bits (algorithm and timeout bits
are **not** preserved — reference behavior the datapath relies on); else
`(alg as u8) << 24 | (affinity_timeout_seconds & 0x00FF_FFFF)` (timeout only
when `SessionAffinity`; > 2^24−1 s is a reconcile error). Backend slots carry
`backend_id` in the union and `count = qcount = 0`.

### 4.4 Restore bookkeeping (in-memory, per node)

`restored_service_ids: L3n4Addr → u16`, `restored_backend_ids: L3n4Addr →
u32`, `restored_quarantined: frontend → {backend addrs}`, `backend_states:
addr → {id, refcount, revision}`, `backend_references: frontend → {backend
addrs}`, `wildcard_references: addr → [service ids]`, `nodeport_addr_by_port:
(family, port, proto) → [addrs]`, `prev_source_ranges: frontend → {prefix}`.
All rebuilt from the maps at start (§5.4) and discarded on `prune`.

### 4.5 `GET /service` model

`[]Service{ spec{ id, frontend-address{ip, port, protocol, scope},
flags{type, trafficPolicy, extTrafficPolicy, intTrafficPolicy, natPolicy,
healthCheckNodePort, name, namespace, cluster}, backend-addresses[{ip, port,
protocol, nodeName, zone, state, preferred, weight}] }, status{ realized } }`
— `realized` from the status side table serialized as spec 00 §4.2.
`state` strings: `active`, `terminating`, `terminating-not-serving`,
`quarantined`, `maintenance`.

### 4.6 `CiliumLocalRedirectPolicy` (v2, namespaced)

```
spec:
  redirectFrontend:
    addressMatcher: { ip: string, toPorts: [ {port: string, protocol: TCP|UDP, name?: string} ] }   # xor
    serviceMatcher: { serviceName: string, namespace: string, toPorts?: [PortInfo] }
  redirectBackend:
    localEndpointSelector: LabelSelector
    toPorts: [PortInfo]
  skipRedirectFromBackend?: bool
  description?: string
status: { ok: bool }
```

### 4.7 `CiliumLoadBalancerIPPool` (v2, also served as v2alpha1; cluster-scoped)

```
spec:
  serviceSelector?: LabelSelector     # may match io.kubernetes.service.namespace / .name
  allowFirstLastIPs?: Yes|No
  blocks: [ { cidr?: string, start?: string, stop?: string } ]
  disabled?: bool
status:
  conditions: [ metav1.Condition ]    # types in §2; merge patch key `type`
```

### 4.8 `CiliumL2AnnouncementPolicy` (v2alpha1, cluster-scoped)

```
spec:
  nodeSelector?: LabelSelector
  serviceSelector?: LabelSelector
  loadBalancerIPs?: bool
  externalIPs?: bool
  interfaces?: [ regex ]
status:
  conditions: [ metav1.Condition ]    # io.cilium/bad-node-selector, bad-interface-regex, bad-service-selector
```

### 4.9 Files

`lb-state-file` (hidden, default `""`): optional YAML/JSON object with
`services: [Kubernetes Service]` and `endpoints: [Kubernetes EndpointSlice]`.
**Resolved (#83): implement after the shared LB conversion core.** Audit of
`pkg/loadbalancer/reflectors/file.go:32–35,192–248` at the pinned reference
corrects the prior `/service` schema claim: these are Kubernetes objects.
The file replaces only source `LocalAPI` in one transaction, preserving other
sources. Empty files clear that source; malformed reads retain the last good
snapshot. Writers should atomically rename complete files. Unknown top-level
fields are ignored, matching the reference's fixture that renames `endpoints`.
`flowsdn-lb::LocalSnapshot` implements JSON/YAML parsing, identity checks,
lossless object round-trip and atomic input replacement. File watching,
Kubernetes-to-LB conversion and transactional BPF reconciliation remain required
under #292; this library does not expose a working agent reflector yet.

## 5. Algorithms

### 5.1 Maglev (frozen bit-exact)

Inputs: `M` (table size), `seed_murmur` (u32, §2), the *active* backends of a
frontend (`sorted[:active]`, §3.4 step 6 — which means terminating backends
are inputs exactly when no active ones exist; Unhealthy, Quarantined,
Maintenance and TerminatingNotServing never are), each with `(id, address,
weight)`.

1. **Hash string** per backend, ASCII:
   `"[" + A + ":" + port_decimal + "/" + PROTO + S + ",State:active]"` where
   `A` is the address text — IPv6 wrapped as `"[" + addr + "]"` — with
   `"@" + cluster_id_decimal` appended when `cluster_id != 0`; `PROTO` is
   `TCP`/`UDP`/`SCTP`; `S` is `"/i"` when scope is Internal, else empty.
   Examples: `[10.0.0.1:8080/TCP,State:active]`,
   `[[fd00::1]:53/UDP/i,State:active]`, `[10.0.0.1@3:80/TCP,State:active]`.
   Address text MUST be the canonical shortest form (`netip::Addr` Display
   for v6: lowercase hex, `::` compression per RFC 5952).
2. **Sort** backends by hash string, bytewise ascending. Node-local IDs MUST
   NOT influence the order.
3. **Permutation** per backend `i`: `(h1, h2) = MurmurHash3_x64_128(hash_string,
   seed_murmur)` — the x64 variant with constants `c1 = 0x87c37b91114253d5`,
   `c2 = 0x4cf5ad432745937f`, both lanes seeded with the same u32 seed
   zero-extended, standard tail handling and `fmix64`; `offset = h1 mod M`,
   `skip = (h2 mod (M−1)) + 1`; `perm[i][j] = (offset + j·skip) mod M` for
   `j ∈ [0, M)`.
4. **Fill** (`n` from 0 to M−1, `L` = number of backends): `i = n mod L`; loop:
   if weights are in use and `(n+1)·weight[i] < trunc(weight_ctr[i])` then
   `i = (i+1) mod L` and repeat; else if weights in use `weight_ctr[i] +=
   weight_sum`; take `c = perm[i][next[i]]`, advancing `next[i]` while
   `entry[c]` is taken; `entry[c] = id[i]`; `next[i] += 1`; break.
   Initialization: `weight_sum = Σ weight`, `weight_ctr[i] = weight[i] / L`
   as IEEE-754 double, `weights_in_use := (weight_sum / L) > 1` using
   **integer** division. The comparison converts `weight_ctr[i]` to an
   integer by truncation. All arithmetic on `n`, `weight`, `weight_sum` is
   unsigned 64-bit.
5. Output: `entry[0..M)` of u32 backend IDs; written as the single value of
   the inner array map `cilium_lb{4,6}_maglev_inner`, then the outer
   `cilium_lb{4,6}_maglev[rev_nat_id]` is updated to the inner fd (spec 01).

Supported `M`: {251, 509, 1021, 2039, 4093, 8191, **16381**, 32749, 65521,
131071}. Two implementations following steps 1–5 MUST produce identical
tables; §9 pins vectors from the reference. Property: any permutation of the
input list yields the same table.

Calibration #250 freezes the pinned `pkg/maglev/maglev_test.go::TestReproducible`
RLE data in `flowsdn-lb/tests/maglev-weighted.rle`: M251, seed 0x24b7ef82,
TCP addresses/ports 1,3,4,5 (0.0.0.1:1 etc.), weights 2,13,111,10,
IDs 0,1,2,3. Zero weights must be removed before the bounded builder;
duplicate IDs/hash strings and unsupported sizes are rejected.

### 5.2 Backend sort order for slots

Healthy (`¬Unhealthy`) before unhealthy; then ascending `State` value
(Active 0, Terminating 1, TerminatingNotServing 2, Quarantined 3, Maintenance
4); then address ascending (`AddrCluster` compare: v4 before v6, then bytes,
then cluster id); then port ascending. Backends restored as quarantined
(§5.4) are treated as Unhealthy until a health checker verifies them
(`UnhealthyUpdatedAt` set).

### 5.3 ID allocation

Two node-local allocators: service IDs `1..0xFFFF` (u16, rev-NAT id) and
backend IDs `1..0xFFFF_FFFF` (u32). Each maps address ↔ id; `acquire(addr)`
returns the existing id for a known address, else scans from `next` upward,
rolling over to the first id once at the max and failing with "no ID
available" after a full cycle; `next` advances past every id handed out or
restored. IDs are released when the frontend is deleted (service id) or the
backend's refcount reaches zero (backend id). **DEVIATION from pre-1.17
Cilium** (not from v1.20.1): no kvstore-global IDs.

### 5.4 Restore from pinned maps (start)

1. Dump `_backends_v3`: record `id → addr`, `restored_backend_ids[addr] = id`
   (an `ANY`-protocol legacy entry seeds TCP, UDP and SCTP variants of the
   address with the same id — migration), `next_backend_id = max+1`.
2. Dump `_services_v2` grouped by frontend address into slot arrays. For each
   with a master slot: `restored_service_ids[addr] = master.rev_nat_index`
   (again fanned out for `ANY`), `next_service_id = max+1`; if
   `qcount > 0 ∧ slots == 1 + count + qcount`, remember the backend addresses
   in slots `count+1..` as *restored quarantined* for that frontend.
3. Then init-wait (§3.4). The first `update` of a frontend consumes its
   restored id (so connections survive the restart); ids never claimed are
   dropped by the first `prune`, which also removes their map entries.

Tests `reuse`, `resync`, `migrate-any-proto`, `migrate-backend`,
`prune-deleted-on-restart`, `quarantined`.

### 5.5 Reflector batching

Spec 00 change streams are not used between k8s and the Writer; the k8s
watches feed an insertion-ordered buffer keyed `(kind, ns/name)` where a newer
event for the same key replaces the older in place (keeping position), flushed
at 500 entries or `lb-reflector-wait-time` after the first insert. One Writer
transaction per flush.

### 5.6 LB IPAM allocation pass (per reconciliation of a service)

1. Build the service view (§3.10).
2. Strip invalid allocations: range vanished/disabled, family not requested,
   IP not in a non-empty requested list, sharing cluster incompatible.
3. Import or strip `status.loadBalancer.ingress` IPs: import when inside a
   known range and free (or sharable and compatible), else remove from status.
4. Specific requests: for each requested IP find its range (skipping disabled
   pools; pool `serviceSelector` must match) → allocate or join the sharing
   cluster; failures set `IPAMRequestSatisfied=False` with the reason table of
   §3.10.
5. Generic requests: for each requested family still without an IP, first try
   an existing compatible sharing cluster with the same key; else allocate the
   lowest free IP from the first enabled, family-matching range whose pool
   selector matches (pools in map iteration order — **DEVIATION (#89)**:
   flowsdn MUST iterate pools in a deterministic order, by `creationTimestamp`
   then name, so two operator instances agree; there is no priority field).
6. Patch service status (ingress + condition) only if changed; recompute pool
   counts and patch pool conditions.

Pool ranges: a CIDR block is `[first, last]` with first/last reserved when
`allowFirstLastIPs: No` and the block is ≥ /30 or /126; `start`/`stop` ranges
are inclusive; a `start` without `stop` is a single IP.

### 5.7 L2 lease timing sanitization

From `l2-announcements-lease-duration` (15 s), `-renew-deadline` (5 s),
`-retry-period` (2 s): clamp `leaseDuration ≥ 1 s`, `renewDeadline ≥ 1 s`,
`retryPeriod ≥ 1 s` (warn); if `leaseDuration ≤ renewDeadline` set
`renewDeadline = leaseDuration/2` (warn); if `renewDeadline ≤ retryPeriod` set
`retryPeriod = renewDeadline/2` (warn).

### 5.8 Retry and prune cadence

Reconciler backoff `lb-retry-backoff-min` (1 s) doubling to
`lb-retry-backoff-max` (1 min, §6 note); prune 30 min after init and
periodically; refresh disabled (the LB reconciler does not need it: every
state change is an explicit table write).

## 6. Configuration

All keys are agent keys unless marked (op) = operator. Kinds per spec 00
§3.3.3. Defaults are the reference's effective defaults at v1.20.1.

| Key | Kind | Default | Validation / effect |
|---|---|---|---|
| `kube-proxy-replacement` | Bool | `false` | master switch; forces `bpf-lb-sock=true`; NodePort/LB/HostPort programmed only when true |
| `bpf-lb-sock` | Bool (immutable) | `false` | socket LB program attach |
| `bpf-lb-sock-hostns-only` | Bool | `false` | host-netns-only variant; disables pod-netns termination |
| `bpf-lb-sock-terminate-pod-connections` | Bool | **`true`** | pod-netns socket termination (deferred feature) |
| `lb-sock-terminate-all-protos` | Bool (hidden) | `false` | also terminate TCP |
| `bpf-sock-rev-map-max` | Int | `0` = dynamic (§3.8) | `[1024, 16777216]`, LRU-aligned |
| `bpf-lb-map-max` | Int (immutable) | `65536` | > 0; default for every `bpf-lb-*-map-max` that is 0 |
| `bpf-lb-service-map-max`, `bpf-lb-service-backend-map-max`, `bpf-lb-rev-nat-map-max`, `bpf-lb-affinity-map-max`, `bpf-lb-source-range-map-max`, `bpf-lb-maglev-map-max` | Int (hidden) | `0` | ≥ 0; 0 inherits |
| `node-port-range` | StringSlice | `["30000","32767"]` | one `"a,b"` or two values; `a < b`; u16 |
| `nodeport-addresses` | StringSlice | `[]` | CIDRs selecting NodePort node addresses (datapath spec owns) |
| `enable-auto-protect-node-port-range` | Bool | `true` | reserve range in `ip_local_reserved_ports` (datapath spec) |
| `node-port-bind-protection` | Bool | `true` | datapath `bind` hook rejects binds in range |
| `bpf-lb-mode` | String | `snat` | `snat`\|`dsr`\|`hybrid` |
| `bpf-lb-mode-annotation` | Bool | `false` | with `bpf-lb-mode=hybrid` → error |
| `bpf-lb-dsr-dispatch` | String | `opt` | `opt`\|`ipip`\|`geneve` |
| `bpf-lb-algorithm` | String | `random` | `random`\|`maglev` |
| `bpf-lb-algorithm-annotation` | Bool | `false` | |
| `bpf-lb-maglev-table-size` | Uint (immutable) | `16381` | one of the ten primes |
| `bpf-lb-maglev-hash-seed` | String (immutable) | `JLfvgnHc2kaSUFaI` | base64 of exactly 12 bytes; MUST be identical cluster-wide |
| `bpf-lb-external-clusterip` | Bool | `false` | Routable on ClusterIP; Maglev for ClusterIP |
| `bpf-lb-source-range-all-types` | Bool | `false` | |
| `bpf-lb-enable-wildcard-entries` | Bool (hidden) | `true` | |
| `bpf-lb-nat46x64` | Bool | `false` | datapath define only (§12) |
| `bpf-lb-acceleration` / `node-port-acceleration` | String | `disabled` | `disabled`\|`native`\|`best-effort` (datapath spec) |
| `bpf-lb-ipip-sock-mark`, `bpf-lb-rss-ipv4-src-cidr`, `bpf-lb-rss-ipv6-src-cidr` | Bool/String | `false`/`""` | datapath spec |
| `enable-health-check-nodeport` | Bool | `true` | §3.7 |
| `enable-health-check-loadbalancer-ip` | Bool | `false` | needs the above |
| `kube-proxy-replacement-healthz-bind-address` | String | `""` | `host:port`; empty disables |
| `enable-service-topology` | Bool | `false` | §3.3 |
| `enable-dynamic-source-lookup-nodeport` | Bool | `false` | datapath SNAT source via FIB |
| `enable-sctp` | Bool | `false` | datapath SCTP support |
| `k8s-service-proxy-name` | String | `""` | label filter |
| `fixed-zone-mapping` | Map string→u8 | `{}` | zone name → `lb_backend.zone` |
| `enable-local-redirect-policy` | Bool | `false` | §3.9 |
| `lrp-address-matcher-cidrs` | StringSlice | `[]` | prefixes; empty = unrestricted |
| `enable-l2-announcements` | Bool | `false` | §3.11 |
| `l2-announcements-lease-duration` | Duration | `15s` | §5.7 |
| `l2-announcements-renew-deadline` | Duration | `5s` | |
| `l2-announcements-retry-period` | Duration | `2s` | |
| `enable-lb-ipam` (op) | Bool | `true` | §3.10 |
| `default-lb-service-ipam` (op, also read by agent for wildcards) | String | `lbipam` | `lbipam`\|`nodeipam`\|`none` |
| `lb-retry-backoff-min` | Duration (hidden) | `1s` | > 0 |
| `lb-retry-backoff-max` | Duration (hidden) | **`1m`** — see note | ≥ min |
| `lb-init-wait-timeout` | Duration (hidden) | `1m` | |
| `lb-reflector-wait-time` | Duration (hidden) | `500ms` | > 0 |
| `lb-pressure-metrics-interval` | Duration (hidden) | `5m` | 0 disables |
| `lb-state-file`, `lb-state-file-interval` | String, Duration (hidden) | `""`, `1s` | deferred |
| `lb-test-fault-probability` | Float (test only) | `0` | not registered in the agent |

**Resolution of spec 00 open decision 12.6 (`lb-retry-backoff-max`).** The
reference's `DefaultUserConfig.RetryBackoffMax` is 1 min, but
`UserConfig.Flags` registers the `lb-retry-backoff-max` flag with
`def.RetryBackoffMin` as its default value (a copy-paste bug in
`pkg/loadbalancer/config.go`), so the *effective* default is 1 s and the
backoff is constant. flowsdn adopts the **intended** value `1m` —
**DEVIATION** (bug fix): an exponential 1 s → 1 min backoff is what the
surrounding code and inventory 04 describe, and a constant 1 s retry against
a full map is a log storm. The registry table in spec 00 §6.4 MUST be updated
to `1m`. Validation adds `max ≥ min`.

**Keys accepted and ignored**: `enable-session-affinity` — does not exist at
v1.20.1 (session affinity is always compiled; kept in the registry as
accepted-and-ignored for older ConfigMaps with a warning); `enable-svc-source-range-check`
(removed upstream; same treatment). `--enable-k8s-endpoint-slice` — gone
(EndpointSlice is the only source).

## 7. Failure modes

| Situation | Behavior |
|---|---|
| LB map full (`E2BIG`) | `update` fails with a message naming `bpf-lb-map-max`; row `Error`, retried with backoff; health Degraded with the count of failing frontends. Partial writes are safe: master slot not yet updated → old backend set stays live. |
| Map write fails mid-Update | steps after the failure are not applied; bookkeeping unchanged; retry re-executes from step 1 (idempotent — same IDs, same slots). |
| Service ID space exhausted (65535 frontends incl. expansions) | error per frontend; health Degraded; nothing else affected. |
| k8s API unavailable | tables keep last state; maps untouched; reflector health Degraded. On reconnect the relist is a `Sync` (§3.2.6): diff, not replay. |
| Restart | restore IDs (§5.4), init-wait, then reconcile; connections to unchanged backends keep their IDs (no CT reset). Agent killed during a write leaves at worst a slot beyond `count+qcount` or an orphan backend — cleaned by the first prune. |
| Initializer never completes | init-wait times out after `lb-init-wait-timeout` with a warning; reconcile proceeds (services may briefly scale down). |
| Layout change (`_v2`/`_v3` suffix bump) | spec 01 §3.4: old maps are read for restore when a migration is defined (the `ANY` → per-protocol case here), then removed. |
| Maglev `M` or seed changed | immutable keys (spec 00 §3.3.9): refuse to start with endpoints present unless forced; on start with a new `M` the inner map value size differs — maps recreated empty (spec 01). |
| Missing kernel feature: netns cookie (< 5.12) | loopback HostPort and LRP `skipRedirectFromBackend` skipped with one warning each. |
| Missing `CONFIG_INET_DIAG_DESTROY` | socket termination off; health Degraded (when the feature exists). |
| `healthCheckNodePort` bind fails | retried with backoff from 200 ms; health Degraded for that port. |
| `/healthz` bind fails | module fails; log hints kube-proxy may still be running. |
| Frontend address conflict between services | whole service upsert rejected; health Degraded; resolved when either service changes. |
| LB/ExternalIP port in NodePort range on a node address | that frontend dropped with a warning; rest installed. |
| LB IPAM pool overlap | newer pool `PoolConflict=True`, its ranges disabled; services keep existing IPs from it until stripped. |
| LB IPAM out of IPs | `IPAMRequestSatisfied=False/out_of_ips`; retried on every pool/service event. |
| L2 lease API errors | elector retries per `retryPeriod`; entries stay until leadership is lost. |
| SCTP service without `enable-sctp` | programmed, not matched by the datapath; documented. |

## 8. Observability

Metrics (reference names kept; consumers: Grafana dashboards, cilium-cli):

| Metric | Labels | Meaning |
|---|---|---|
| `cilium_services_events_total` | `action` (`add`,`update`,`delete`) | k8s service events processed |
| `cilium_service_implementation_delay` | `action` | seconds from k8s event to map write (histogram) |
| `cilium_k8s_terminating_endpoints_events_total` | — | terminating endpoints seen |
| `cilium_bpf_map_pressure` | `map_name` | fill ratio of every LB map, sampled every `lb-pressure-metrics-interval` |
| `flowsdn_lb_reconciler_*` (spec 00 §8: `_errors_total`, `_duration_seconds`, `_retries`) | `table=frontends` | reconciler health |
| `cilium_lbipam_conflicting_pools` (op) | — | |
| `cilium_lbipam_ips_available`, `cilium_lbipam_ips_used` (op) | `pool` | |
| `cilium_lbipam_services_matching`, `cilium_lbipam_services_unsatisfied` (op) | — | |
| `cilium_lbipam_event_processing_time_seconds` (op) | `action`, `resource` | |
| `cilium_lrp_controller_duration_seconds` | — | LRP controller pass |
| `flowsdn_table_*` for the LB tables | `table` | spec 00 |

Health (spec 00 §3.4.3): modules `loadbalancer.reflector-k8s` (Degraded:
"Failure processing services"), `loadbalancer.reconciler-bpf` ("N error(s)"),
`loadbalancer.healthserver`, `loadbalancer.socket-termination`,
`local-redirect-policy`, `l2-announcer`, `lbipam` (operator).

Logs: structured fields `service`, `k8s-namespace`, `address`, `id`,
`backend-id`, `slot`, `count`, `active-count`, `terminating-count`,
`inactive-count`, `frontend-id`, `error`.

Status/API: `GET /service`, `GET /lrp`; `cilium-dbg bpf lb list|maglev list`
read the maps directly; `flowsdn-dbg lb tables` (flowsdn-specific) dumps the
three tables as JSON (no `db/show` — ADR-0004).

## 9. Test plan

Golden tests reproduce the reference txtar shape: feed k8s objects (YAML), run
the reflector + Writer + reconciler against an **in-memory `LbMaps`**, compare
table dumps and a map dump against expected text; with `PRIVILEGED_TESTS=1` the
same scenarios run against real maps. Checklist of reference scenarios to
re-create (unit unless noted):

- [ ] `clusterip`, `clusterip-allowed`, `multiport`, `dualstack`, `dualstack-maglev`
- [ ] `nodeport`, `nodeport-addr`, `nodeport-lb-nodeport-range`, `nodeport-explicit-random`, `nodeport-explicit-maglev`, `nodeport-maglev`
- [ ] `loadbalancer`, `loadbalancer-multiport`, `loadbalancer-multiprotocol`, `loadbalancer-class-wildcards`, `loadbalancer-disabled-wildcards`, `loadbalancer-localaddr-wildcards`
- [ ] `external-ips`, `external-clusterip`
- [ ] `hostport`, `hostport-lb-collision`
- [ ] `headless`, `svc-type-annotation`, `svc-node-exposure`, `svc-forwarding-mode-annotation`
- [ ] `trafficpolicy`
- [ ] `topology-aware`, `topology-aware-terminating`, `prefer-same-node`, `prefer-same-zone-fallback`
- [ ] `graceful-termination`, `quarantined`, `endpointslice-weight`, `multiple-endpointslices`
- [ ] `source-ranges-dfl`, `source-ranges-all`
- [ ] `proxy-delegation`, `hybrid-dsr`, `ingress`
- [ ] `kpr-transition-to-disabled`, `kpr-transition-to-enabled`
- [ ] `migrate-any-proto`, `migrate-backend`, `reuse`, `resync`, `prune-deleted-on-restart`, `pruning`
- [ ] `name-collisions`, `marshalling`, `queries` (as typed assertions), `file` (when the file reflector lands)
- [ ] LRP: `address`, `address-malformed`, `address-matcher-conflict`, `address-matcher-named-ports`, `avoid-recompute`, `lrp-single-multiple-ports`, `no-target-pods`, `node-local-dns`, `pod-readiness`, `service`, `skiplb`, `skiplb-addr`
- [ ] Health server: `healthserver`, `healthserver-ipv6`, `healthserver-proxy-redirect`

New, flowsdn-specific:

- [ ] **Maglev vectors** (unit): tables produced by the reference for fixed
  inputs — (a) 3 backends equal weight, M=251; (b) same with weights 100/200/300;
  (c) IPv6 + internal scope + cluster id; (d) `M=16381` single backend — stored
  as test data with source path/commit/license header (`docs/licensing.md`);
  flowsdn output MUST be byte-identical.
- [ ] Maglev permutation invariance (property): shuffle inputs → same table.
- [ ] Maglev weights-in-use boundary: `weight_sum/L == 1` → no weighting.
- [ ] Murmur3 x64_128 vectors against the reference `murmur3_test.go`.
- [ ] Flag encoding: every bit → `flags`/`flags2` bytes; union precedence
  (proxy port beats alg/timeout); timeout > 2^24−1 rejected.
- [ ] Sort order table for §5.2 including restored-quarantined inputs.
- [ ] `active == 0 → active = terminating` and `qcount` arithmetic for every
  state mix, incl. Unhealthy overlay.
- [ ] Write-order fault injection (spec 00 §9): fail each of steps 3–12 once;
  assert the map is consistent (master never references a missing backend or
  slot) and the retry converges.
- [ ] Restore: crafted map dumps (ANY-proto, qcount slots) → expected
  restored ids and quarantine.
- [ ] NodePort expansion with primary-frontend exclusion and address churn.
- [ ] HostPort naming, loopback, NodePort-range refusal, terminating pod keeps
  port.
- [ ] Health server HTTP contract (headers, 200/503, proxy-redirect → 1).
- [ ] `/healthz` body and 503 conditions.
- [ ] LB IPAM (operator, unit): allocation, specific requests, sharing
  compatibility matrix, cross-namespace, first/last IP, conflicts, restart
  import, condition reasons — ported from the reference's 3.6k-line suite.
- [ ] L2: policy selection, lease naming, timing sanitization, origin
  refcounting, GC.
- [ ] Privileged: real map round-trip for every LB map; Maglev inner map
  update; `cilium_skip_lb` insert; L2 responder GARP emission observed on a
  veth pair.
- [ ] e2e: cilium-cli connectivity suites in KPR mode (ClusterIP, NodePort,
  LB, externalTrafficPolicy=Local, hostPort, LRP node-local-dns, L2
  announcements) — as in the reference workflows.

## 10. Kernel and platform requirements

Control plane is userspace; requirements arrive through features:

- Hash-of-maps + inner array (Maglev), LPM trie (source ranges): kernel ≥ 4.15
  (well below the 6.6 floor of `docs/kernel-requirements.md`).
- cgroup v2 socket hooks incl. `getpeername` (socket LB): ≥ 5.8.
- `bpf_get_netns_cookie` / `SO_NETNS_COOKIE` (loopback HostPort, LRP skip-LB,
  affinity by cookie): ≥ 5.12.
- `SOCK_DESTROY` (socket termination, deferred): `CONFIG_INET_DIAG_DESTROY`.
- Raw `AF_PACKET` send + multicast group membership (L2 responder GARP/NA).
- Netlink: `coordination.k8s.io` is API-side; no netlink beyond the datapath
  spec's.
- Memory: Maglev permutation buffer is `L × M` u64 (reference reuses a buffer
  sized `(M/100)·M`; ≈ 20 MB at M=16381, ≈ 1.3 GB at 131071). arm64 nodes
  with small RAM SHOULD not use the two largest sizes; document in Helm.
- No architecture-specific behavior; murmur3 operates on little-endian 64-bit
  lanes on both x86-64 and arm64 (reference reads blocks as native u64 —
  flowsdn MUST read them as **little-endian** explicitly so a hypothetical
  big-endian build agrees).

## 11. Rust design notes

Crates (workspace members):

- **`flowsdn-lb`** — the model and control plane:
  `model` (`ServiceName` interned `Arc<str>` with cached `xxhash`, `L3n4Addr`
  as `#[repr(C)] [u8; 24]` newtype with accessors, `SvcType`, `SvcFlags`
  (`bitflags!` u16 with the bit table of §4.3 as the single source of truth
  for tests), `BackendState`, `LbAlgorithm`, `TrafficDistribution`,
  `Service`, `Frontend`, `FrontendParams`, `Backend`), `tables` (three
  `flowsdn_table::Table<T>` with the indexes of §4.1; `Keyed` impls), `writer`
  (`Writer` behind one `tokio::sync::Mutex`; `WriteTxn` with the fixed write
  order services → frontends → backends per spec 00 §3.1.8; `select_backends`
  as §3.3; `RegisterInitializer`), `k8s` (reflector: `kube-runtime` watchers
  for `Service`, `EndpointSlice`, local `Pod`; `IndexMap`-based batch buffer;
  conversions as §3.2), `reconciler` (`BpfOps: Target<Frontend>` over an
  `LbMaps` trait; `IdAllocator<T: IdKind>`; restore; prune; expansions;
  wildcards), `maglev` (pure functions: `hash_string`, `permutation`,
  `lookup_table`; `rayon` for permutation rows; own `murmur3_x64_128`
  implementation — ~60 lines, no crate dependency, tested against vectors),
  `healthserver` (`hyper` 1.x listeners; one per port), `healthz`.
- **`flowsdn-lb-maps`** — `LbMaps` trait (`update_service`, `delete_service`,
  `dump_service`, `update_backend`, …, `update_maglev(rev_nat, &[u32], v6)`,
  `exists_sock_rev_nat`), `AyaLbMaps` (real; spec 01 typed maps, `to_network`
  byte swaps at the boundary) and `FakeLbMaps` (`BTreeMap`s, fault injection
  probability) — the fake is what the golden tests run on.
- **`flowsdn-lrp`** — CRD types (`kube-derive`), validation of §3.9, the
  controller as an async task consuming table watches, `desired-skiplb` table
  and its reconciler into `cilium_skip_lb`.
- **`flowsdn-lbipam`** (operator) — pools (`ipnet` + a bit-set per range or a
  `roaring`-style allocator; `num-bigint` only for the condition messages),
  sharing clusters, status patching with `kube` server-side apply, field
  manager `cilium-operator-lb-ipam`.
- **`flowsdn-l2announce`** — policy handling, `Lease` leader election
  (hand-rolled over `kube` `coordination/v1` — the semantics are
  `client-go`'s `leaderelection`: acquire when holder empty/expired, renew
  every `retryPeriod` until `renewDeadline`, release on shutdown), `l2-announce`
  table; the responder reconciler lives in the datapath userspace crate and
  needs `AF_PACKET` (`socket2`) for GARP/NA and `netlink` for multicast
  membership.

Key traits: `LbMaps`, `flowsdn_table::Target<Frontend>`, `BackendSelector`
(pluggable; `Default` implements §3.3), `IsServiceHealthChecked` (hook for a
future active health checker). No Hive, no DI: `flowsdn-agent` constructs
`Writer`, reflectors, reconciler, health servers and hands out `Arc`s;
ordering via `lb-init` fence (spec 00 §5.7).

Sizing: `flowsdn-lb` ~7k lines + ~5k tests/golden data; `flowsdn-lb-maps`
~1.5k; `flowsdn-lrp` ~1.5k; `flowsdn-lbipam` ~2.5k + tests; `flowsdn-l2announce`
~1.5k.

## 12. Open decisions

1. **Resolved (#80, ADR-0011): freeze §5.1 bit-exact Maglev.**
   Retain canonical backend strings, ordering and MurmurHash3 x64-128.
   Binary-key hashing is not an alternative within the compatible mode.
2. **Resolved (#81, ADR-0011): reproduce IEEE-754 f64 counters.**
   Use §5.1 initialization, arithmetic and truncation; do not substitute
   fixed point. Golden weighted vectors remain required before implementation
   can claim mixed-node equivalence.
3. **Socket termination.** Deferred in inventory 04. (a) implement in phase 2
   with UDP only; (b) never. Recommendation: (a) — without it UDP clients
   pinned to a removed backend hang until their own timeout; keep TCP behind
   the hidden flag.
4. **`lb-state-file` reflector.** (a) implement (cheap, invaluable for
   standalone tests); (b) rely on the golden harness only. Recommendation:
   (a) after the core lands; the serde types already exist for `GET /service`.
5. **Resolved (#84, ADR-0011): expose the active-health hook only.**
   No built-in periodic TCP/HTTP backend prober is part of this contract.
   External health integrations/API updates may supply `Unhealthy`; Kubernetes
   readiness continues to select the ordinary backend lifecycle state.
6. **Resolved (#85, ADR-0011): retain only the specified `io.cilium/*` classes.**
   Do not add implicit `flowsdn.io/*` aliases. Existing Service manifests
   retain the ownership behavior in §3.
7. **Resolved (#86, ADR-0011): `enable-service-topology` defaults false.**
   Explicit enablement applies the specified hints; chart mappings preserve
   the default unless the user selects a value.
8. **Resolved (#87): socket termination defaults true.** The pinned daemon
   registers `true` (`daemon/cmd/daemon_main.go:272`). Helm
   `values.yaml:1388` is a commented example; the ConfigMap template at
   `templates/cilium-configmap.yaml:878` emits a value only when
   `socketLB.terminatePodConnections` is explicitly present. An absent chart
   key preserves the daemon default; explicit `false` overrides it. This
   resolves default selection, not implementation of socket destruction.
9. **Resolved (#88, ADR-0011): backend-slot bit 14 is never written.**
   Quarantine is conveyed by slot range and backend state, as §4 requires.
   Spec 02 §3.12 no longer makes this bit a condition for correct selection.
10. **LB IPAM pool ordering.** Reference iterates a Go map (nondeterministic).
    This spec mandates `creationTimestamp, name` order (§5.6 step 5).
    Confirm no consumer depends on the previous behavior (none known).
11. **Resolved (#90/#47, ADR-0011): retry maximum is `1m`.**
   Spec 00 §6.4 and §3.2.3 now agree with §6; the minimum remains `1s`.
12. **Resolved (#91, ADR-0011): bind healthCheckNodePort on all addresses.**
   Preserve `:<port>` from §3.7; restricting the listener to classified
   NodePort addresses could exclude cloud health-check destinations.
   This does not change the separately configured KPR healthz bind address.

### Batch 6 decisions (#82, #89)

Socket termination is retained: UDP first, TCP only with the hidden all-protocols
flag; preserve cookie ownership and namespace gates. The reference supports
inet_diag `SOCK_DESTROY` and a newer BPF iterator destroyer
(`pkg/datapath/sockets/sockets.go`, `pkg/loadbalancer/reconciler/termination.go`).
Issue #82's claim that only `bpf_sock_destroy` works is corrected: the initial
adapter uses inet_diag and requires `CONFIG_INET_DIAG_DESTROY`.
`flowsdn-lb::Termination` tests eligibility; the 50ms coalescer, namespace walker
and real socket destruction remain #292 implementation work.

Pool traversal is creation timestamp then name, with timestamps normalized to
UTC seconds/nanoseconds, unique names and existing allocations preserved.
Reference consumers `operator/pkg/lbipam/pool.go` and `lbipam.go` select free
ranges via map iteration; no ordering guarantee exists to retain. This audit
cannot promise undocumented third-party behavior. The stable order is an
explicit deviation for new allocations, covered by `ordered_pools` tests.
