# BGP control plane and speaker — specification

Status: draft. Derived from: `docs/inventory/10-bgp.md` (primary),
`docs/inventory/13-crds-k8s.md`, `docs/inventory/04-loadbalancer.md`,
`docs/inventory/08-operator.md`; reference cilium v1.20.1 (7d68cfb394) paths
`pkg/bgp/**` (`agent/`, `types/`, `gobgp/`, `manager/`, `manager/reconciler/`,
`manager/tables/`, `manager/store/`, `metrics/`, `api/`, `commands/`,
`test/testdata/*.txtar`), `operator/pkg/bgp/**` (`manager.go`, `cluster.go`,
`peer.go`), `pkg/k8s/apis/cilium.io/v2/bgp_{cluster,peer,advert,node,node_override}_types.go`,
`pkg/ipalloc/`, `api/v1/openapi.yaml` (`/bgp/*`),
`Documentation/network/bgp-control-plane/*.rst`,
`install/kubernetes/cilium/values.yaml` (`bgpControlPlane.*`).
Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* flowsdn does and the exact data it exchanges; it does not transcribe
reference code. Where reference behavior is kept for compatibility the
dependent consumer is named (upstream routers, `cilium-dbg`, cilium-cli, the
operator, users' CRDs). Where flowsdn deviates the paragraph is marked
**DEVIATION** with the reason and the ADR.

Builds on `00-foundation-table-config.md` (table store, watch streams,
reconciler helper, config registry, fences), `05-service-loadbalancing.md`
(the `Frontend`/`Service`/`Backend` tables, `LoadBalancerClass`,
`ProxyRedirects`, traffic policies), `07-ipam.md` (`CiliumNode.spec.ipam`,
`CiliumPodIPPool`), `10-node-routing-nftables.md` (`Device` and `Route`
tables), `12-operator.md` (leader election, resource stores, per-node config
fan-out, condition writing).

---

## 1. Scope

In scope:

- The five `cilium.io/v2` BGP CRDs — `CiliumBGPClusterConfig`,
  `CiliumBGPPeerConfig`, `CiliumBGPAdvertisement`, `CiliumBGPNodeConfig`,
  `CiliumBGPNodeConfigOverride` — every field, validation rule and effect.
- The operator's compilation of cluster config × node selector × override into
  one `CiliumBGPNodeConfig` per node, owner references, conflict resolution,
  conditions, and the router-ID IP pool allocator.
- The agent's seven config reconcilers in fixed priority order, the one state
  reconciler (CRD status), the event sources that trigger them, and the
  level-triggered signaller they share.
- The export policy model: one policy per peer, default reject, first match
  wins; how advertisements become statements; merging, ordering, soft reset.
- Advertisement semantics for `PodCIDR`, `CiliumPodIPPool`, `Service`,
  `Interface`, including traffic policies, aggregation, VIP reference
  counting, `loadBalancerClass` gating and the no-endpoints-routable option.
- Route attributes: ORIGIN, AS_PATH, NEXT_HOP / MP_REACH_NLRI, COMMUNITIES,
  LARGE_COMMUNITIES, LOCAL_PREF.
- Session management: FSM, timers, hard vs. soft reset, instance recreation,
  graceful restart, MD5 authentication, eBGP multihop, router-ID allocation.
- **flowsdn's own BGP speaker** — RFC subset, wire codec, FSM, capability
  negotiation, error handling, the hard "never import" invariant, and the
  internal API the reconcilers drive.
- The pluggable `Advertiser`/`Speaker` trait pair and the RouterOS REST
  backend for MikroTik fleets.
- Read APIs for peers, routes and route policies.

Out of scope, owned elsewhere: the `Frontend`/`Service`/`Backend` model and
`loadBalancerClass` assignment (`05`); LB-IPAM which *allocates* the VIPs this
spec advertises (`05`); `CiliumNode.spec.ipam` population (`07`); the `Device`
and `Route` tables (`10`); the operator binary skeleton, leader election and
resource stores (`12`); the datapath that must accept traffic for an
advertised prefix (`02`, `05`) — BGP installs nothing in the kernel or in BPF.

Explicitly not implemented (matching the reference): BFD, TCP-AO, ADD-PATH,
route reflection, confederations, VRFs, non-unicast SAFIs, importing learned
routes into any table, per-neighbor import policies.

---

## 2. Compatibility contract

| Interface | MUST match | Consumer |
|---|---|---|
| CRD group/version/kind for all five resources | `cilium.io/v2`, cluster-scoped, short names `cbgpcluster`, `cbgppeer`, `cbgpadvert`, `cbgpnode`, `cbgpnodeoverride`, categories `{cilium,ciliumbgp}` | users, cilium-cli, `kubectl` |
| Every CRD field name, type, default, enum, pattern and CEL rule | §4.1–4.5 | API server validation, users' manifests |
| `CiliumBGPNodeConfig` name | equals the node name | operator/agent rendezvous |
| `CiliumBGPNodeConfig` owner reference | `apiVersion: cilium.io/v2`, `kind: CiliumBGPClusterConfig`, `controller: true`, cluster config's UID | Kubernetes GC |
| `CiliumBGPNodeConfig.status` schema | §4.4; written with a JSON patch `replace /status`, field manager `CiliumBGPNodeConfigStatusReconciler` | cilium-cli `cilium bgp peers`, users |
| Condition types | `cilium.io/NoMatchingNode`, `cilium.io/MissingPeerConfigs`, `cilium.io/ConflictingClusterConfig` (cluster config); `cilium.io/MissingAuthSecret` (peer config); `cilium.io/BGPReconcileError` (node config) | users, dashboards |
| `loadBalancerClass` gate | `io.cilium/bgp-control-plane`, or nil | users' `Service` specs; `05` §3.6 |
| Implicit selector labels | `io.kubernetes.service.name`, `io.kubernetes.service.namespace`, `io.cilium.podippool.name`, `io.cilium.podippool.namespace` | users' `CiliumBGPAdvertisement` selectors |
| Well-known community names → values | the fourteen names in §3.9 mapped to the exact 32-bit values | users, upstream router policy |
| Auth secret shape | `Secret` in `--bgp-secrets-namespace`, key `password` | users |
| BGP wire protocol | RFCs in §3.11; interoperable with GoBGP, FRR, bird, Arista, RouterOS 7 | upstream routers |
| Session state strings | `unknown`, `idle`, `connect`, `active`, `open_sent`, `open_confirm`, `established` | CRD status, CLI, metrics |
| Metric names and labels | §8.1 | Grafana dashboards shipped for the reference |
| Config keys | §6, byte-identical to the reference flag names | Helm ConfigMap, `cilium-config` |
| Route policy naming | policy `peer-<peerName>-export`; statement `<Type>[-<resourceID>]-ipv{4,6}[-agg-<len>]` | `cilium-dbg bgp route-policies`, txtar expectations |

**Version compatibility (resolved #184, spec 13 §12.2).** All five BGP CRDs
MUST serve `cilium.io/v2` and deprecated `cilium.io/v2alpha1`, with `v2` as the
sole storage version and strategy `None`. Preserve the vendored versions array.
This supersedes the earlier v2-only proposal; manifests using the older served
version must remain accepted. Serving both versions does not itself rewrite
existing storage: storage-version migration and its verification remain runtime
implementation work, and no served version may be removed before that completes.

**DEVIATION (ADR-0001).** The deprecated agent REST endpoints `GET /bgp/peers`,
`GET /bgp/routes`, `GET /bgp/route-policies` are kept (they are what `cilium-dbg
bgp *` and cilium-cli call) but the `hive shell` command surface
(`cilium-dbg shell -- bgp/peers`) is not, because there is no hive (ADR-0004).
The same three views are reachable through the REST endpoints and through
`flowsdn-dbg bgp {peers,routes,route-policies}`.

**DEVIATION (ADR-0004).** `CiliumBGPNodeConfigOverride.spec.bgpInstances[].peers[].localPort`
is a dead field in the reference (present in the CRD, never copied by the
operator). flowsdn keeps the field in the schema for manifest compatibility and
**MUST** ignore it, logging once per object at `debug`. See open decision O-7.

---

## 3. Behavior

### 3.1 Enablement and top-level structure

The BGP control plane is enabled by `enable-bgp-control-plane` (default
`false`). When disabled, the agent MUST NOT start any BGP task, MUST NOT watch
any BGP resource, and the read APIs MUST return HTTP 501. The operator MUST NOT
create or delete `CiliumBGPNodeConfig` objects when disabled.

When enabled the agent runs, per node:

1. a **signaller** — a one-deep coalescing channel; every event source sends
   into it and a full channel is a no-op (level-triggered, not edge-triggered);
2. a **controller loop** that, on each signal, fetches the local `CiliumNode`
   and the `CiliumBGPNodeConfig` named after the node, and calls
   `reconcile_instances`;
3. a **router manager** holding zero or more **BGP instances**, one per
   `spec.bgpInstances[]` entry, each with its own speaker, ASN, router ID and
   optional listen port;
4. per instance, the seven **config reconcilers** in fixed priority order;
5. a **state reconciler** job that writes `CiliumBGPNodeConfig.status`.

`reconcile_instances` MUST be retried with exponential backoff on failure:
initial 500 ms, factor 2, jitter 0.5, 5 steps (≈15 s total). A retry that still
fails leaves the error in the reconcile-error table (§3.8) and the next event
re-triggers.

If `CiliumBGPNodeConfig` for this node does not exist, the manager MUST
withdraw all instances (full destroy, §3.13).

### 3.2 The operator: compiling cluster config into node config

The operator watches `CiliumBGPClusterConfig`, `CiliumBGPPeerConfig`,
`CiliumBGPNodeConfigOverride`, `CiliumBGPNodeConfig`, `CiliumNode` and
`Secret` (in `--bgp-secrets-namespace`). Any change triggers one coalesced
reconcile of *all* cluster configs, retried with backoff.

For each `CiliumBGPClusterConfig` `C`, in order:

1. **Select nodes.** `nodeSelector == nil` selects every `CiliumNode`;
   otherwise it is a label selector matched against `CiliumNode.metadata.labels`.
2. **Allocate router IDs** (only in `ip-pool` mode, §3.14) for every
   (node, instance) pair not already allocated.
3. **Conflict resolution.** If a `CiliumBGPNodeConfig` already exists for the
   node and its owner references do *not* contain `C`'s UID, the node is
   **skipped** — first owner wins — and the name of the owning cluster config
   is recorded for the `cilium.io/ConflictingClusterConfig` condition on `C`.
   The operator MUST NOT overwrite another cluster config's node config and
   MUST NOT delete it.
4. **Merge the override.** Look up `CiliumBGPNodeConfigOverride` named after
   the node. For each instance, by matching `name`:
   `routerID`, `localPort`, `localASN` from the override replace the cluster
   values when non-nil; for each peer, by matching `name`, `localAddress` from
   the override is copied into the node peer. Override entries whose `name`
   matches no cluster instance/peer are ignored.
5. **Render** `CiliumBGPNodeConfig/<nodeName>` with
   `spec.bgpInstances[]` = the merged instances and exactly one owner
   reference to `C` (`controller: true`).
6. **Create** if absent; **update** only when the rendered `spec` differs
   structurally from the stored one (a deep comparison, not a serialization
   comparison — the operator MUST NOT write on every reconcile).
7. **Delete** every `CiliumBGPNodeConfig` owned by `C` whose node is no longer
   selected, freeing its router-ID allocations.

When *no* cluster configs exist at all and `ip-pool` mode is on, the operator
MUST clear the whole router-ID allocator (the node configs are removed by
Kubernetes garbage collection, so there is no delete event to free them from).

An error on one cluster config MUST NOT abort the others; errors are joined and
the reconcile is retried.

#### 3.2.1 Cluster config conditions

Written only when `enable-bgp-control-plane-status-report` is true; when false
the operator MUST *remove* all three conditions so stale state is not shown.
Conditions are sorted by `type` before the status update, and the status update
API call is made only when at least one condition changed.

| Type | True when | Reason (True / False) |
|---|---|---|
| `cilium.io/NoMatchingNode` | zero nodes matched `nodeSelector` | `MatchingNodeUnavailable` / `MatchingNodeSelected` |
| `cilium.io/MissingPeerConfigs` | some `peers[].peerConfigRef.name` resolves to no `CiliumBGPPeerConfig` | `PeerConfigsMissing` / `PeerConfigsResolved` |
| `cilium.io/ConflictingClusterConfig` | another cluster config already owns a node this one selects | `ClusterConfigConflict` / `ClusterConfigValidated` |

`MissingPeerConfigs` message lists the missing names sorted and deduplicated.
`ConflictingClusterConfig` message lists the conflicting cluster config names
sorted.

#### 3.2.2 Peer config condition

For each `CiliumBGPPeerConfig` with a non-nil `spec.authSecretRef`, the
operator sets `cilium.io/MissingAuthSecret` True when no `Secret` of that name
exists in `--bgp-secrets-namespace`, False otherwise. When
`--bgp-secrets-namespace` is unset the reconciler does not run and the
condition is not written. A `Secret` add/delete triggers re-evaluation of every
peer config referencing it.

### 3.3 Agent reconcilers: fixed priority order

Reconcilers run lowest priority number first, on every reconcile of every
instance. The order is normative — it is not an optimization.

| Prio | Name | Computes | Why here |
|---|---|---|---|
| 10 | `DefaultGateway` | fills in `peers[].peerAddress` from the default route for peers using `autoDiscovery` | must run before anything that keys policies on the peer address |
| 20 | `Interface` | /32 and /128 paths + policy statements for IPs on a named device | |
| 30 | `PodCIDR` | paths + statements for `CiliumNode.spec.ipam.podCIDRs` | |
| 40 | `Service` | paths + statements for service VIPs | |
| 50 | `PodIPPool` | paths + statements for multi-pool allocations | |
| 100 | `RoutePolicy` | materializes all desired statements into one export policy per peer | after every producer has written its statements |
| 110 | `Neighbor` | adds / updates / removes peers | **last**, so the Loc-RIB and the export policies are complete before a session comes up and the End-of-RIB marker is sent |

The priority of the `Neighbor` reconciler is the load-bearing part of graceful
restart correctness: a peer added before the RIB is populated would send an EOR
marker with an incomplete route set, and a restarting-speaker peer would then
flush the routes it was holding.

Reconcilers are keyed by name; if two implementations register the same name
the higher-priority (lower number) one wins and the other is dropped with a
log line.

Each reconciler holds per-instance metadata (its current paths, its current
advertisement set, its change-stream cursor). `init(instance)` allocates it,
`cleanup(instance)` frees it and deletes the instance's rows from the desired
policy table.

Error handling within one instance's reconcile pass:

- A reconciler returning `ErrAbortReconcile` (used when a resource store is not
  yet initialized, or when a hard ordering dependency failed) MUST stop the
  pass immediately; remaining reconcilers are not run.
- Any other error is recorded and the pass **continues** with the next
  reconciler, so as much configuration as possible is applied.
- Errors are joined and returned so the outer retry fires.
- A reconciler that failed mid-way MUST persist the *actual* router state it
  achieved (the paths it really advertised) and MUST invalidate its change
  cursor so the next attempt does a full reconciliation rather than a diff.
  Persisting the desired-but-unapplied state is a bug class that leaves the
  speaker and the reconciler permanently out of sync.

### 3.4 Event sources

| Event | Triggers |
|---|---|
| local `CiliumNode` upsert | full reconcile (also supplies pod CIDRs, pools, node IP) |
| `CiliumBGPNodeConfig` change | full reconcile |
| `CiliumBGPPeerConfig` change | full reconcile |
| `CiliumBGPAdvertisement` change | full reconcile |
| `Secret` change in the secrets namespace | full reconcile |
| `CiliumPodIPPool` change (multi-pool IPAM only) | full reconcile |
| `Frontend` table change (includes backend changes) | full reconcile, rate-limited to one signal per 100 ms |
| `Route` table change where `dst` is `0.0.0.0/0` or `::/0` | full reconcile (default-gateway failover) |
| `Device` table change | full reconcile (`sourceInterface`, `Interface` adverts, gateway link state) |
| speaker session-state or path change | state reconcile only (§3.8), not a config reconcile |

All sources funnel into the one-deep signaller; bursts collapse into a single
reconcile.

### 3.5 Peer → advertisement resolution

For a given advertisement type set, for each peer in the node instance:

1. Skip the peer if `peerConfigRef` is nil or names a `CiliumBGPPeerConfig`
   that does not exist. A peer with no resolvable config advertises nothing;
   the `Neighbor` reconciler still peers with it using defaults (§3.12).
2. Load the peer config and apply defaults (§4.2) to a copy.
3. For each entry of `spec.families[]`, evaluate `advertisements` as a label
   selector over all `CiliumBGPAdvertisement` objects' labels. A nil selector
   selects **nothing** (not everything).
4. From each selected `CiliumBGPAdvertisement`, take the entries of
   `spec.advertisements[]` whose `advertisementType` is in the requested set.

The result is `peer → family → [advertisement]`. Note the same
`CiliumBGPAdvertisement` may be selected by several families and several peers;
the reconcilers collapse per-family for *paths* (the Loc-RIB is per instance,
not per peer) and keep per-peer for *policies* (which is where per-peer
filtering happens).

A change in this resolved structure — compared field by field, order-insensitively
by advertisement type — forces a full (non-diff) reconciliation in the Service
reconciler.

### 3.6 Advertisement semantics

Common rules:

- A path is created for a prefix only if the prefix's family matches the
  address family under which it is being advertised (an IPv4 prefix never
  becomes an IPv6 path).
- Paths are per instance, deduplicated by NLRI string; policies are per peer.
- Every generated policy statement matches the exact prefix
  (`prefixLenMin == prefixLenMax == prefix length`) except where noted.

#### 3.6.1 `PodCIDR`

Advertises every prefix in `CiliumNode.spec.ipam.podCIDRs`. `selector` is
forbidden by CEL. The reconciler is active only when `ipam` is `kubernetes` or
`cluster-pool`; under any other IPAM mode the reconciler MUST be inactive and
advertise nothing (pod CIDRs are not node-scoped in those modes). Statement
name: `PodCIDR-ipv4` / `PodCIDR-ipv6`.

#### 3.6.2 `CiliumPodIPPool`

Requires `ipam: multi-pool`. For each `CiliumPodIPPool` matching `selector`
(matched against the pool's labels plus the implicit
`io.cilium.podippool.name` and `io.cilium.podippool.namespace`), advertise the
prefixes in `CiliumNode.spec.ipam.pools.allocated[]` whose `pool` equals the
pool name. The policy prefix match uses
`prefixLenMin = prefixLenMax = pool.spec.ipv4.maskSize` (resp. `ipv6.maskSize`)
— **not** the advertised prefix's own length. Statement name:
`CiliumPodIPPool-<poolName>-ipv{4,6}`.

#### 3.6.3 `Service`

`spec.advertisements[].service.addresses[]` selects among `LoadBalancerIP`,
`ClusterIP`, `ExternalIP`. `selector` matches the `Service`'s labels plus the
implicit `io.kubernetes.service.name` and `io.kubernetes.service.namespace`.
A nil `selector` or nil `service` block selects nothing.

For each frontend of the selected service, let `hasBackends` be true when at
least one backend is in state `active`, and `hasLocalBackends` be true when at
least one `active` backend has `nodeName` equal to this node.

| Address type | Frontend type | Advertise when |
|---|---|---|
| `LoadBalancerIP` | `LoadBalancer` | `loadBalancerClass` gate passes **and** (`externalTrafficPolicy != Local` ∨ `hasLocalBackends` ∨ `hasLocalProxy`) **and** (`hasBackends` ∨ `enable-no-service-endpoints-routable` ∨ `hasLocalProxy`) |
| `ClusterIP` | `ClusterIP` | (`internalTrafficPolicy != Local` ∨ `hasLocalBackends`) **and** (`hasBackends` ∨ `enable-no-service-endpoints-routable`) |
| `ExternalIP` | `ExternalIPs` | (`externalTrafficPolicy != Local` ∨ `hasLocalBackends`) **and** (`hasBackends` ∨ `enable-no-service-endpoints-routable`) |

`hasLocalProxy` is true when the service's `ProxyRedirects` set is non-empty —
that is, a local Envoy is configured to handle this service (Gateway API or
Ingress). It counts as a local backend for `LoadBalancer` frontends only, and
it also overrides the no-endpoints rule, because traffic terminates at the
proxy rather than at a backend. It has no effect on `ClusterIP` or
`ExternalIP`.

**The `loadBalancerClass` gate:** advertise `LoadBalancerIP` only when
`Service.spec.loadBalancerClass` is nil **or** equals
`io.cilium/bgp-control-plane`. Any other class means another controller owns
the VIP and flowsdn MUST NOT advertise it. The gate is evaluated once per
service, before any frontend is examined.

**`externalTrafficPolicy: Local` / `internalTrafficPolicy: Local`** turn the
advertisement into a per-node signal: only nodes with a local active backend
advertise, and the upstream router therefore forwards only to nodes that can
serve without a second hop. Under a `Local` policy the prefix length is forced
to the host length (`/32`, `/128`) and **aggregation is ignored**, because an
aggregate cannot express "this node, for these addresses".

**`Cluster` policy** advertises from every selected node regardless of backend
placement; the upstream router ECMPs across them. With zero active backends the
VIP stays advertised only if `enable-no-service-endpoints-routable` is true
(the default), which preserves the reference behavior of not black-holing a
service that is momentarily empty.

**Aggregation.** When `service.aggregationLengthIPv4` (0..31) or
`aggregationLengthIPv6` (0..127) is set and the traffic policy is not `Local`,
the frontend address is masked to that length and the aggregate is advertised
instead of the host route. Consequences that MUST be documented for users:

- addresses inside the aggregate but not assigned to any service are
  black-holed at the advertising node;
- two advertisements aggregating the same prefix with different attributes
  produce an implementation-defined merge (see §3.7 — flowsdn merges them by
  the same union/max rule as any overlap, which is defined, unlike the
  reference's "undefined" note);
- an aggregate statement is given priority `base + 1` and its name gains a
  `-agg-<len>` suffix, so exact-match statements are evaluated **before**
  summary statements within the same policy.

Statement name: `Service-<svcName>-<svcNamespace>-<addressType>-ipv{4,6}`,
plus `-agg-<len>` when the statement's prefix is shorter than the host length.

**VIP reference counting.** Several `Service` objects may share a VIP (the
`Service` merging rules in `05` §3.9 permit it). Paths are tracked per
resource (namespace/name) *and* globally by NLRI with a reference count:

- advertising a prefix already present increments the count and reuses the
  existing path handle rather than issuing a second advertise;
- withdrawing decrements; the speaker is asked to withdraw only when the count
  reaches zero.

Reference counts are recomputed from the full per-resource path map at the
start of every reconcile pass, so a crashed or partially failed pass cannot
leak a count.

**Legacy ORIGIN.** When `enable-bgp-legacy-origin-attribute` is true, paths
generated for `LoadBalancerIP` addresses (only those) carry ORIGIN =
INCOMPLETE (2) instead of IGP (0), for compatibility with MetalLB-era upstream
policy. All other advertisement types and address types keep IGP.

#### 3.6.4 `Interface`

For the device named by `interface.name`, advertise every address as a host
prefix (`/32`, `/128`), subject to: the device is administratively up and
operationally `up` or `unknown` (dummy and loopback devices report `unknown`);
the address family matches the family being advertised; and the address is not
IPv4-mapped-IPv6, and is global unicast — with IPv4 link-local additionally
allowed and IPv6 link-local excluded. Duplicates (the same IP present with
different masks) are collapsed. Statement name: `Interface-ipv{4,6}`.

### 3.7 Export policy model

flowsdn MUST implement exactly one **export** policy per peer, named
`peer-<peerName>-export`, whose semantics are:

- statements are evaluated **in order**;
- a statement matches when **all** of its conditions match;
- the **first** matching statement's route action and set-actions apply and
  evaluation stops;
- if no statement matches, the **default action is REJECT**.

This is the whole filtering mechanism. There is no other place where a prefix
is allowed out.

Statement conditions:

- `matchNeighbors`: match type `any` over a list of peer addresses (in
  practice a single address — the peer this policy belongs to);
- `matchPrefixes`: match type `any` over a list of
  `{cidr, prefixLenMin, prefixLenMax}` entries;
- `matchFamilies`: optional; unused by the generated statements because v4 and
  v6 prefixes are never mixed in one statement.

Statement actions: `accept`, plus `addCommunities`, `addLargeCommunities`,
`setLocalPreference`, and a next-hop action (`self` / `unchanged`) that the
generated statements do not use.

**How advertisements become statements.** Every path-producing reconciler
writes rows into a shared **desired route policy table** keyed by
`(instance, peer, policyType, statementName)`, carrying the statement, a
`priority`, the owning reconciler name and the originating resource key. Rows
are reconciled per (instance, owner, resource): stale rows for that triple are
deleted, new and changed rows inserted. The `RoutePolicy` reconciler (priority
100) then, per (instance, peer, policyType):

1. collects all rows,
2. sorts them by `priority` ascending, then by statement name ascending,
3. renders them as the statement list of `peer-<peer>-export`,
4. diffs against the previously installed policy and applies add / remove /
   **recreate-on-change** (an in-place update of a complex policy is not
   attempted; the policy is removed and re-added),
5. issues a **soft reset** of the affected peers (§3.13).

Because priority ordering is `DefaultGateway 10 < Interface 20 < PodCIDR 30 <
Service 40 < Service-aggregate 41 < PodIPPool 50`, a host route always wins
over an aggregate covering it, and the ordering is stable across restarts.

**Overlapping advertisement merging.** When two advertisements select the same
resource and produce statements with the *same* name, the *same* conditions and
the *same* route action, they MUST be merged into one statement:

- `addCommunities` and `addLargeCommunities` become the **union** of both
  sets, sorted;
- `setLocalPreference` becomes the **maximum** of the two (RFC 4271: "the
  higher degree of preference MUST be preferred"); if only one side sets it,
  that value is used;
- next-hop action is taken from the first statement.

Merging two statements whose names, conditions or route action differ is an
error and MUST fail the reconcile pass with a message naming the statement and
the resource. This merge is what makes "two advertisements matching one
Service" well defined; without it, first-match-wins would silently drop the
second advertisement's attributes.

Community deduplication happens before merging, within one advertisement:
standard numeric communities and well-known names are resolved to their 32-bit
values and deduplicated by value (so `65535:65281` and `no-export` collapse to
one), preserving the order in which they were written and preferring the form
in which they were written. Large communities are deduplicated by string.

### 3.8 Status reporting and cadence

Two independent writers:

**Instance/peer status** (agent → `CiliumBGPNodeConfig.status.bgpInstances[]`).
The speaker signals the manager on any peer-state or path change; the manager
marks the instance pending and wakes a state-reconcile loop, which asks the
speaker for peer state and rebuilds the desired status. The desired status is
*flushed to the API server* on a ticker of **5 s with ±500 ms normal jitter**,
and only when it differs from the last successfully written status. A failed
patch is retried with backoff (initial 5 s, factor 1.2, jitter 0.5, 10 steps)
and then falls back to the plain ticker, producing a see-saw retry pattern
rather than a tight loop; the failure is logged once per exhausted backoff.
`NotFound` on the patch resets the last-written status to empty and is not an
error (the node config was deleted).

Per peer the status reports: name, peer address, peer ASN (filled in from the
session when configured as 0), peering state string, negotiated hold and
keepalive, established time as RFC 3339 derived from session uptime, and per
family received/advertised route counts. Peers with no `peerAddress` or no
`peerASN` are omitted. Advertised prefixes and installed policies are **not**
in the status; they are reachable only through the read APIs.

**Reconcile errors** (agent → `CiliumBGPNodeConfig.status.conditions[]`). Each
instance keeps at most **5** reconcile errors in an in-memory error table,
replaced atomically when the error set changes. A watcher on that table
recomputes the `cilium.io/BGPReconcileError` condition: True with
reason `ReconcileFailed` and a message of `"<instance>: <error>\n"` lines
sorted by instance then error index, truncated at **32 KiB**; False with reason
`ReconcileSucceeded` and an empty message otherwise.

When `enable-bgp-control-plane-status-report` is false, the agent MUST NOT
write status and MUST, once at startup, patch `/status` with an empty object so
stale status from a previous run is not left behind. This cleanup is retried
(3 s interval, 20 attempts) and a `NotFound` counts as success.

### 3.9 Route attributes

Paths generated by flowsdn carry:

| Attribute | Type | Value |
|---|---|---|
| ORIGIN | 1, well-known mandatory | IGP (0); INCOMPLETE (2) for LoadBalancerIP under legacy-origin |
| AS_PATH | 2, well-known mandatory | empty in the Loc-RIB; the local ASN is prepended on export to an eBGP peer |
| NEXT_HOP | 3, well-known mandatory | `0.0.0.0` in the Loc-RIB for IPv4; rewritten per session on export (§3.10) |
| MP_REACH_NLRI | 14, optional non-transitive | used for IPv6 NLRI, and for IPv4 NLRI over an IPv6 session; next hop `::` in the Loc-RIB, rewritten on export |
| MP_UNREACH_NLRI | 15, optional non-transitive | used to withdraw non-IPv4-unicast NLRI |
| COMMUNITIES | 8, optional transitive | from `attributes.communities.standard[]` and `.wellKnown[]` |
| LARGE_COMMUNITIES | 32, optional transitive | from `attributes.communities.large[]` |
| LOCAL_PREF | 5, well-known discretionary | from `attributes.localPreference`; sent to iBGP peers only |

MED, ATOMIC_AGGREGATE and AGGREGATOR are never generated. Note that despite the
name, `aggregationLength*` produces a shorter prefix, not an RFC 4271
aggregate; ATOMIC_AGGREGATE is deliberately not set.

Standard communities accept either a 32-bit decimal (`4259840099`) or
`<0-65535>:<0-65535>` (`65000:99`). Well-known names map as:

| Name | Value | Name | Value |
|---|---|---|---|
| `internet` | `0x00000000` | `llgr-stale` | `0xffff0006` |
| `planned-shut` | `0xffff0000` | `no-llgr` | `0xffff0007` |
| `accept-own` | `0xffff0001` | `blackhole` | `0xffff029a` |
| `route-filter-translated-v4` | `0xffff0002` | `no-export` | `0xffffff01` |
| `route-filter-v4` | `0xffff0003` | `no-advertise` | `0xffffff02` |
| `route-filter-translated-v6` | `0xffff0004` | `no-export-subconfed` | `0xffffff03` |
| `route-filter-v6` | `0xffff0005` | `no-peer` | `0xffffff04` |

Large communities are `<u32>:<u32>:<u32>`.

`no-advertise` and `no-export` are honored by the *receiver*; flowsdn sets them
but, being export-only with an empty adj-RIB-in, never has to act on them.

### 3.10 Next hop selection

The Loc-RIB stores a path with an unspecified next hop (`0.0.0.0` / `::`). The
next hop is resolved **per session, at export time**:

1. If the session's local address is configured (`localAddress` override, or
   derived from `sourceInterface`), that address is the next hop.
2. Otherwise the next hop is the local address of the established TCP
   connection to that peer — i.e. what the kernel chose as the source for the
   route to the peer. A node with two upstream subnets therefore advertises a
   different next hop to each peer without any per-peer configuration.
3. Next hop is never `0.0.0.0` or `::` on the wire; a path that cannot resolve
   a next hop for a session MUST NOT be exported to that session, and the
   condition MUST be logged and counted.

**IPv4 NLRI over an IPv6 session (RFC 8950).** When the session's local
address is IPv6 and an IPv4 unicast path is exported:

- flowsdn MUST have negotiated the Extended Next Hop Encoding capability
  (code 5) for the tuple (AFI 1 IPv4, SAFI 1 unicast, next-hop AFI 2 IPv6);
- the path MUST be encoded as MP_REACH_NLRI with AFI 1 / SAFI 1, a 16-byte (or
  32-byte, link-local included) IPv6 next hop, and the IPv4 prefixes as NLRI;
  the legacy NEXT_HOP attribute MUST NOT be used;
- if the capability was not negotiated, the IPv4 path MUST NOT be exported to
  that session, and a warning is logged once per peer per family.

The reverse (IPv6 NLRI over an IPv4 session) is normal MP-BGP and requires only
that the node has an IPv6 address to use as next hop.

### 3.11 Session management

Session parameters are assembled per peer from the node config peer entry and
its `CiliumBGPPeerConfig` (after defaults), plus the MD5 password from the
`Secret`:

- **peer address** — from `peers[].peerAddress`, or discovered (§3.12). A peer
  with neither is skipped entirely with a debug log.
- **peer ASN** — `peerASN`; `0` disables the OPEN ASN check and the ASN is
  learned from the peer's OPEN (and reported back in the status).
- **local address** — override `localAddress`, else derived from
  `transport.sourceInterface`, else unset (bind wildcard).
- **remote port** — `transport.peerPort`, default 179.
- **timers** — connect-retry 120 s, hold 90 s, keepalive 30 s by default.
- **eBGP multihop** — `ebgpMultihop` TTL; `1` means disabled. Ignored for iBGP.
- **graceful restart** — `gracefulRestart.enabled` and `restartTimeSeconds`.
- **MD5** — `authSecretRef` → `Secret` key `password`.

**`sourceInterface` resolution.** The named device must exist and must have
exactly one usable address in the peer's family, applying the same address
filter as `Interface` advertisements (§3.6.4). Zero usable addresses, or more
than one, is not an error: the peer is **skipped** for this pass with a
warning, and the next `Device` table change retries. An explicit
`localAddress` override always wins and skips this resolution.

**Which change causes what.**

| Change | Effect |
|---|---|
| `localASN`, `localPort`, or router ID of an instance | **instance recreate**: withdraw (full destroy, CEASE sent, GR ended) then register; all sessions of that instance drop |
| instance removed from the node config | withdraw, full destroy |
| `holdTimeSeconds` or `keepAliveTimeSeconds` of a peer | **hard reset** of that session (the values are negotiated in OPEN; a declarative API must make them take effect now) |
| any other peer parameter (multihop, GR, transport, password, families) | update in place; **soft reset in** if the speaker reports the change needs re-evaluation of received routes |
| peer added / removed | add / remove neighbor |
| any route policy add, remove or change | **soft reset out** (or in+out if an import policy were ever added) of the peers named in the old and new policy; a policy with an empty neighbor match resets all peers |
| peer address changes | treated as a different peer: remove the old, add the new (peers are identified by `name + address + ASN`) |

Soft reset out re-runs the export policy over the Loc-RIB and re-advertises;
it does not drop the TCP session. Hard reset drops the session; after a reset
the session MUST stay in Idle for an **idle-hold time of 5 s** before
re-attempting, to avoid a reset storm.

**Graceful restart.** flowsdn acts as a **restarting speaker** only; it never
acts as a receiving speaker because it has no adj-RIB-in to preserve
(§3.15). When `gracefulRestart.enabled`:

- the GR capability is advertised with the configured Restart Time and the
  Notification bit (RFC 8538) set, and per-AFI GR is enabled for every
  configured family;
- on **agent shutdown**, the speaker MUST stop without sending a NOTIFICATION,
  so the peer holds the routes for the restart time;
- on **instance withdrawal** (the instance was removed or must be recreated),
  the speaker MUST be fully destroyed, which sends CEASE and ends graceful
  restart — otherwise a stale instance's routes would survive a reconfiguration
  that was meant to remove them;
- on restart, the reconciler ordering (§3.3) guarantees the Loc-RIB and the
  export policies are complete before the first peer is added, so the initial
  UPDATE burst is complete before the End-of-RIB marker.

### 3.12 Default-gateway auto-discovery

A peer with `autoDiscovery.mode: DefaultGateway` and no `peerAddress` gets its
peer address from the routing table at priority 10, before any other
reconciler:

1. Select routes whose destination is exactly `0.0.0.0/0` (for
   `addressFamily: ipv4`) or `::/0` (for `ipv6`) and which have a valid
   gateway.
2. Drop routes whose output device is absent or not operationally `up`.
3. Drop routes whose gateway is link-local (unsupported; logged as a warning).
4. Pick the route with the lowest `priority` (metric); its gateway is the peer
   address, written into the in-memory copy of the node config for the rest of
   this pass.

If no route qualifies, the peer is left without an address and is skipped by
every later reconciler; the next `Route` or `Device` change retries. This is
the multi-homing failover path: when the primary uplink goes down its route is
removed or its device goes down, the next-lowest-metric default route is
chosen, and the session moves.

Exactly one session per address family per peer entry is possible; a peer entry
cannot discover both a v4 and a v6 gateway.

### 3.13 Instance lifecycle

`reconcile_instances(nodeConfig, ciliumNode)` computes a diff:

- **register** — instance name not currently running;
- **recreate** — running, but `localASN`, `localPort` or the derived router ID
  differs → scheduled as withdraw + register;
- **reconcile** — running and none of those three differ;
- **withdraw** — running but absent from the node config.

Withdrawals are applied **before** registrations so a recreate works. Duplicate
instance names in one node config are a hard error for the whole pass.

Register: derive ASN (required — a missing `localASN` is an error), listen port
(absent → do not listen), router ID (§3.14); create the speaker; run every
reconciler's `init`; run a full reconcile pass. Withdraw: run every
reconciler's `cleanup`, cancel the instance context, stop the speaker with full
destroy, close its notification channel, drop its reconcile errors.

**Listening.** With no `localPort` the speaker MUST NOT bind a listening socket
and MUST only initiate outbound connections. This is deliberate: it lets
flowsdn coexist with another BGP speaker (bird, FRR) on the same host. A
`localPort` below 1024 requires `CAP_NET_BIND_SERVICE` on the agent.

### 3.14 Router-ID allocation

Two modes, selected by `bgp-router-id-allocation-mode`:

**`default`** (agent-side). If `spec.bgpInstances[].routerID` is set (from an
override), use it. Otherwise use the node's IPv4 address from `CiliumNode`. On
an IPv6-only node there is none, so derive the router ID from the **lower four
bytes of the `cilium_host` device's MAC address**, formatted as a dotted quad.
This is deterministic per node but MUST be documented as not guaranteed unique
across a large fleet; conflicting router IDs surface as OPEN errors (§3.19).

**`ip-pool`** (operator-side). The operator holds a hash allocator over the
IPv4 range given by `bgp-router-id-allocation-ip-pool` and allocates one
address per `(nodeName, instanceName)`, writing it into
`CiliumBGPNodeConfig.spec.bgpInstances[].routerID`. On operator restart,
allocations are **restored** by reading existing node configs, skipping any
router ID outside the pool range. An override's `routerID`:

- **outside** the pool range is accepted verbatim and the pool allocation for
  that key (if any) is freed;
- **inside** the pool range must be free or already held by that same key;
  otherwise the reconcile for that node errors with a message naming the
  current holder.

In `ip-pool` mode the agent MUST NOT derive a router ID; a node config instance
with no `routerID` is an error, and the router ID MUST parse as IPv4.

### 3.15 Import: the hard invariant

**flowsdn MUST NEVER install a route learned from a BGP peer anywhere.** Not
into the kernel routing table, not into the ipcache, not into any BPF map, not
into the Loc-RIB.

Concretely:

- the Loc-RIB contains **only** locally originated paths;
- an incoming UPDATE is parsed, counted, and stored in a **per-peer
  adj-RIB-in that exists solely for observability** (route counts in the CRD
  status and metrics, and the `adj-rib-in` view of the read API);
- there is no best-path selection, because there is never more than one path
  per prefix in the Loc-RIB;
- there is no import policy engine and no per-peer import policy; the import
  side is a constant `REJECT` with a single exception for locally originated
  routes (which some policy engines evaluate against the import assignment).

This invariant is what makes the whole feature safe to run on every node: a
misconfigured or hostile upstream router cannot change how the node forwards.
It is also what shrinks the RFC surface enough to justify writing our own
speaker (§3.16). Any future proposal to import routes is a new ADR, not a
config flag.

The adj-RIB-in MUST be bounded: at most `bgp-adj-rib-in-max-prefixes` prefixes
per peer per family (default 100 000). On overflow the speaker MUST stop
storing (but keep counting) and log once per peer; it MUST NOT tear down the
session, because the routes are not load-bearing.

### 3.16 The speaker

No Rust crate today provides an embeddable, policy-capable, graceful-restart
capable BGP speaker as a library (survey in §11.5). flowsdn therefore
implements its own, export-only, in-process speaker. Because the control plane
never imports, the required RFC surface is small and fully enumerated here.

#### 3.16.1 RFC subset

| RFC | Scope | flowsdn support |
|---|---|---|
| 4271 | BGP-4 base: header, OPEN/UPDATE/NOTIFICATION/KEEPALIVE, FSM, timers, attributes | full, minus best-path selection and route aggregation |
| 4760 | Multiprotocol extensions, MP_REACH/MP_UNREACH_NLRI | full for ipv4-unicast and ipv6-unicast; other AFI/SAFI are accepted in the CRD enum and rejected at instance start |
| 6793 | Four-octet AS numbers, capability 65, AS4_PATH | full; AS_TRANS (23456) handling on the receive side |
| 2918 | Route refresh, capability 2 | full: send on soft-reset-in, honor on receive by re-running export |
| 4724 | Graceful restart, capability 64 | restarting speaker only; forwarding-state bit not set |
| 8538 | GR for NOTIFICATION-triggered session close ("N" bit) | full, on the restarting side |
| 8950 | Extended next hop encoding, capability 5 | IPv4 NLRI with an IPv6 next hop (§3.10) |
| 1997 | Communities attribute (8) | full on generate; parsed on receive |
| 8092 | Large communities attribute (32) | full on generate; parsed on receive |
| 2385 | TCP MD5 signature | via `setsockopt(TCP_MD5SIG)` |
| 5492 | Capability advertisement, unsupported-capability handling | full |
| 6608 | FSM error subcodes | full |
| 4486 | Cease subcodes | full |

Deliberately **not** implemented: ADD-PATH (7911), enhanced route refresh
(7313 — the plain 2918 form is used), extended messages (8654 — 4096 byte cap
retained), BGP-LS, flowspec, VPN SAFIs, route reflection (4456),
confederations (5065), BFD (5880), TCP-AO (5925 — deferred by decision O-3).

#### 3.16.2 Message encoding and decoding

Header, common to all messages: 16-byte marker (all ones on send; on receive
any value is accepted and the marker is not validated for content, only for
length), 2-byte big-endian total length, 1-byte type. Total length MUST be
19..4096. A length outside that range, or a type outside 1..5, is a Message
Header Error.

| Type | Name | Body |
|---|---|---|
| 1 | OPEN | version (1, must be 4), my AS (2, `23456` when the real ASN needs 4 octets), hold time (2), BGP identifier (4), optional parameters length (1), optional parameters |
| 2 | UPDATE | withdrawn routes length (2) + withdrawn IPv4 prefixes, total path attribute length (2) + attributes, NLRI (IPv4 prefixes, to end of message) |
| 3 | NOTIFICATION | error code (1), error subcode (1), data |
| 4 | KEEPALIVE | empty (length exactly 19) |
| 5 | ROUTE-REFRESH | AFI (2), reserved (1, sent as 0, ignored on receive), SAFI (1) |

Prefixes in NLRI and withdrawn-routes fields are encoded as a 1-byte length in
bits followed by `ceil(bits/8)` bytes; trailing bits beyond the prefix length
MUST be sent as zero and MUST be ignored on receive.

Path attributes: flags (1) — bits `O` optional 0x80, `T` transitive 0x40,
`P` partial 0x20, `E` extended-length 0x10, low nibble reserved zero — type
(1), length (1 or 2 when `E`), value. Encoder rules: well-known attributes are
sent transitive with `O=0`; optional non-transitive attributes (MP_REACH,
MP_UNREACH) with `O=1,T=0`; optional transitive (COMMUNITIES,
LARGE_COMMUNITIES) with `O=1,T=1`; extended length is used only when the value
exceeds 255 bytes. Decoder rules: an unknown optional transitive attribute is
retained verbatim in the adj-RIB-in with the partial bit set; an unknown
optional non-transitive attribute is dropped; an unknown well-known attribute
is an Unrecognized Well-known Attribute error.

MP_REACH_NLRI value: AFI (2), SAFI (1), next-hop length (1), next hop, reserved
(1, sent as 0), NLRI. MP_UNREACH_NLRI value: AFI (2), SAFI (1), withdrawn NLRI.
Accepted next-hop lengths: 4 (IPv4), 16 (IPv6 global), 32 (IPv6 global +
link-local; the global half is used).

Capabilities inside OPEN optional parameter type 2: capability code (1),
length (1), value. Encoded by flowsdn:

| Code | Capability | Value |
|---|---|---|
| 1 | Multiprotocol | AFI (2), reserved (1), SAFI (1) — one per configured family |
| 2 | Route refresh | empty |
| 5 | Extended next hop encoding | triples of NLRI AFI (2), NLRI SAFI (2), next-hop AFI (2) — sent only when an IPv6 session carries IPv4 families |
| 64 | Graceful restart | restart flags + restart time packed as a 16-bit field (`R` bit 0x8000 set only while restarting, `N` bit 0x4000 per RFC 8538 always set when GR is enabled, time in the low 12 bits, capped at 4095), then per family: AFI (2), SAFI (1), flags (1) with the forwarding-state bit **clear** |
| 65 | Four-octet AS | the local ASN as a 4-byte value |

#### 3.16.3 Finite state machine

States and the events that move between them. `ConnectRetry`, `Hold`,
`Keepalive`, `IdleHold` are the timers; `DelayOpen` is not implemented.

| State | Event | Next | Action |
|---|---|---|---|
| Idle | start (manual or IdleHold expiry) | Connect | reset ConnectRetry, initiate TCP |
| Idle | inbound connection | Idle | drop (unless listening is enabled, then → OpenSent after accept) |
| Connect | TCP established | OpenSent | send OPEN, set Hold to 4 min |
| Connect | TCP failed | Active | restart ConnectRetry |
| Connect | ConnectRetry expiry | Connect | retry TCP |
| Active | TCP established | OpenSent | send OPEN |
| Active | ConnectRetry expiry | Connect | initiate TCP |
| OpenSent | valid OPEN received | OpenConfirm | negotiate (§3.16.4), send KEEPALIVE, start Hold and Keepalive timers |
| OpenSent | invalid OPEN | Idle | send NOTIFICATION 2/x, close, start IdleHold |
| OpenSent | Hold expiry (4 min) | Idle | NOTIFICATION 4, close |
| OpenSent | TCP closed | Active | restart ConnectRetry |
| OpenConfirm | KEEPALIVE received | Established | reset Hold; run the export pass; send EOR per family |
| OpenConfirm | NOTIFICATION received | Idle | close; GR applies if the N bit was negotiated |
| OpenConfirm | Hold expiry | Idle | NOTIFICATION 4, close |
| Established | KEEPALIVE / UPDATE received | Established | reset Hold |
| Established | Keepalive timer expiry | Established | send KEEPALIVE |
| Established | Hold expiry | Idle | NOTIFICATION 4/0, close |
| Established | ROUTE-REFRESH received | Established | re-run export for that family |
| Established | NOTIFICATION received | Idle | close |
| Established | TCP closed | Idle | close |
| any | administrative reset (hard) | Idle | NOTIFICATION 6/4, close, IdleHold 5 s |
| any | administrative soft reset out | unchanged | re-run export for the affected families |
| any | shutdown with GR enabled | Idle | close TCP **without** NOTIFICATION |
| any | shutdown without GR / instance destroy | Idle | NOTIFICATION 6/2 (administrative shutdown), close |

**Passive mode (#186).** When `spec.transport.passiveMode=true`, startup and
ConnectRetry expiry MUST NOT initiate TCP: remain in Active while listening.
A missing or zero instance localPort is a configuration error, not an implicit
port 179. Inbound OPEN handling, Hold/Keepalive timers and administrative
reset behavior are unchanged. After transport loss and IdleHold, return to
passive Active. Default false retains both listening and initiating when a
localPort exists. Socket listeners and this FSM integration remain unimplemented;
the transport planner enforces configuration and initiation decisions.

Connection collision (both sides connect simultaneously, only possible when
listening): resolved per RFC 4271 §6.8 — the connection whose BGP identifier is
numerically larger on the local side is kept; the other is closed with
NOTIFICATION 6/7.

Timers:

- **ConnectRetry** — configured value, applied with jitter in `[t, 2t)` so a
  fleet reconnecting after an upstream reboot does not synchronize.
- **Hold** — negotiated (§3.16.4). Reset on accepted KEEPALIVE or UPDATE;
  malformed discarded UPDATEs do not extend peer liveness.
- **Keepalive** — `min(configured keepalive, negotiated hold / 3)`. Disabled
  when the negotiated hold is 0.
- **IdleHold** — fixed **5 s** after any reset before leaving Idle.

#### 3.16.4 Capability negotiation and OPEN validation

On receiving an OPEN:

1. version ≠ 4 → NOTIFICATION 2/1 with the supported version in the data;
2. if the configured peer ASN is non-zero and the OPEN's AS (or the four-octet
   AS capability, which wins when present) differs → 2/2;
3. if the peer's BGP identifier is 0, or equals our own router ID → 2/3;
4. hold time 1 or 2 → 2/6; 0 is legal and means "no keepalives";
5. an optional parameter type other than 2 (capabilities) → 2/4.

Negotiated hold time = `min(local hold, peer hold)`.

Capability handling, per RFC 5492:

| Peer capability | flowsdn |
|---|---|
| Multiprotocol for a family we configured | family is usable |
| Multiprotocol missing for a configured family | that family is **not** usable; log once per peer; do **not** fail the session — the other families keep working. If no family is common, send NOTIFICATION 2/7 with the capabilities we required |
| Multiprotocol for a family we did not configure | ignored; nothing is sent for it |
| Route refresh absent | soft-reset-out is performed locally (re-run export and re-advertise); no ROUTE-REFRESH is sent |
| Four-octet AS absent | fall back to two-octet AS; if the local ASN needs four octets, send `23456` in OPEN and set AS4_PATH on export |
| Graceful restart absent while we requested it | GR is not active for this session; a restart will drop the peer's routes. Log at `info`, do not fail |
| Extended next hop absent while an IPv4-over-IPv6 export is needed | that family is not exported to this peer (§3.10) |
| Any capability we do not implement | **ignored silently** — flowsdn MUST NOT send NOTIFICATION 2/7 for an unknown capability, per RFC 5492 §4 |

flowsdn never *requires* a capability except when it would leave the session
with nothing to do at all.

#### 3.16.5 Error handling and notification codes

| Code | Meaning | Subcodes used by flowsdn |
|---|---|---|
| 1 | Message header error | 1 not synchronized, 2 bad length, 3 bad type |
| 2 | OPEN message error | 1 unsupported version, 2 bad peer AS, 3 bad BGP identifier, 4 unsupported optional parameter, 6 unacceptable hold time, 7 unsupported capability (RFC 5492) |
| 3 | UPDATE message error | 1 malformed attribute list, 2 unrecognized well-known attribute, 3 missing well-known attribute, 4 attribute flags error, 5 attribute length error, 6 invalid ORIGIN, 8 invalid NEXT_HOP, 9 optional attribute error, 10 invalid network field, 11 malformed AS_PATH |
| 4 | Hold timer expired | 0 |
| 5 | FSM error | 0 unspecified, 1 unexpected message in OpenSent, 2 in OpenConfirm, 3 in Established (RFC 6608) |
| 6 | Cease | 1 max prefixes reached, 2 administrative shutdown, 3 peer de-configured, 4 administrative reset, 6 other configuration change, 7 connection collision resolution, 8 out of resources (RFC 4486) |
| 7 | ROUTE-REFRESH message error | 1 invalid message length |

**Resolved error policy (#191).** `bgp-strict-update-errors` defaults to
`false`. When true, every detected malformed UPDATE causes its notification
and session close. When false, only bounded UPDATE-content errors take the
count/log/discard path below; malformed framing or attribute TLV boundaries
still close the session. A malformed optional attribute with a valid outer
length is a content error: its enclosing UPDATE boundary is known. Never apply
this lenient mode to a receive path that imports routes into forwarding.

**Treat-as-withdraw is not applicable.** Because the adj-RIB-in is
observability-only, a malformed UPDATE cannot corrupt forwarding. flowsdn
therefore prefers **session survival** over strict error handling for the
receive path: an UPDATE that fails to parse increments a counter, is logged at
`debug` with the first 64 bytes hex-dumped, and the session continues. A
In default lenient mode, a NOTIFICATION is sent only when the error is in the message *framing* (code 1)
or in the attribute *length* structure such that the remainder of the message
cannot be located. This is a deliberate divergence from RFC 4271's
session-reset default and MUST be documented; the risk that motivates
session reset (installing a bad route) does not exist here.

Sending an UPDATE that would exceed 4096 bytes MUST split the NLRI across
several UPDATEs with identical attributes. An attribute set that alone exceeds
the message limit is a configuration error and is reported per path.

#### 3.16.6 Internal API

The reconcilers see the speaker through this surface (Rust signatures in
§11.2). Every operation is idempotent and cancel-safe.

| Operation | Semantics |
|---|---|
| `advertise(path) -> handle` | insert a locally originated path into the Loc-RIB; return an opaque handle. Re-advertising an identical NLRI returns the existing handle |
| `withdraw(handle)` | remove the path; export policies re-evaluate and MP_UNREACH / withdrawn-routes are sent to every session that had it |
| `set_export_policy(peer, policy)` | replace the peer's export policy atomically; implies a soft reset out |
| `add_neighbor` / `update_neighbor` / `remove_neighbor` | as §3.11 |
| `reset_neighbor(peer, hard \| soft{in,out,both})` | as §3.11 |
| `reset_all_neighbors(...)` | same, over every configured peer |
| `peer_states() -> Vec<PeerState>` | state, uptime, negotiated timers, per-family counts, capabilities, MD5-enabled flag |
| `routes(table, family, peer?) -> Vec<Route>` | `table` ∈ {`loc-rib`, `adj-rib-in`, `adj-rib-out`} |
| `policies() -> Vec<RoutePolicy>` | installed export policies, in evaluation order |
| `stop(graceful: bool)` | `true` → close sockets without NOTIFICATION (GR); `false` → CEASE and destroy |

`advertise` and `withdraw` MUST NOT block on network I/O; they mutate the
Loc-RIB and wake per-session export tasks.

**Primitive implementation boundary.** `flowsdn-bgp-proto` implements bounded
framing, OPEN capability negotiation, IPv4/IPv6 UPDATE encoders and splitting,
AS_TRANS/AS4_PATH conversion, strict/lenient validation, and a deterministic
six-state session core with injected clock/entropy and generation checks.
Its collision owner uses opaque instance-bound tokens; adapters must validate
OPEN before collision selection and reject displaced-token callbacks before
forwarding them to the session. Numeric session generations alone are not
cross-instance socket identities. Collision rejection sends Cease/7 in the
transport adapter; the owner returns the displaced connection explicitly.

GR negotiation uses the last advertised GR capability and RFC 8538's N mask
`0x4000`, separate from the low twelve restart-time bits. Hard administrative
resets wrap their cause in Cease/9 only after bilateral N negotiation. The
close disposition reports when peers may retain **our exported** routes; it
does not retain or install learned forwarding state. Unsupported-version
notifications include the supported version. Complete per-error notification
payload extraction remains required.

The independent local-origin and bounded per-family observation stores have
no operation that promotes received routes. Observation overflow counts
announcement/withdrawal events and omitted storage, not an exact unique live
prefix count (which would require unbounded memory after overflow). One
instance reports overflow once; withdrawals free stored capacity. A transcript
feeds 100001 announcements through an established session and asserts the
local-origin snapshot is unchanged, storage is bounded and the session stays
established. No kernel/BPF adapter exists in this crate; runtime assertions
that those stores remain unchanged still belong to the speaker acceptance
suite. Likewise actual sockets, TCP authentication, timer tasks, adj-RIB-out,
export-policy/next-hop resolution, reconciler integration and interoperability
remain required. These unit primitives do not alone close issue #249.

### 3.17 The pluggable advertiser

The reconcilers do not need a BGP session; they need prefixes to become
reachable with the right attributes. flowsdn splits the speaker interface in
two so a second backend can satisfy the same reconcilers:

- **`Advertiser`** — `ensure(prefix, attrs) -> handle`, `withdraw(handle)`,
  `observed() -> Vec<AdvertisedPrefix>`. Used by the `Interface`, `PodCIDR`,
  `Service` and `PodIPPool` reconcilers.
- **`Speaker: Advertiser`** — adds neighbors, policies, resets and peer state.
  Used by the `DefaultGateway`, `RoutePolicy` and `Neighbor` reconcilers and by
  the status writer.

Two backends:

**`bgp`** (default) — the speaker of §3.16. Per-peer export policies are
realized as adj-RIB-out filters exactly as described in §3.7.

**`routeros`** — for MikroTik fleets where the RouterOS 7 router in front of
the cluster is already the BGP speaker. The node does not speak BGP at all; it
programs the router's routing table so the router redistributes the prefixes.

RouterOS backend behavior:

- **Route programming.** For each desired prefix, `PUT`/`PATCH` a static route
  via the REST API — `/rest/ip/route` for IPv4, `/rest/ipv6/route` for IPv6 —
  with `dst-address` = the prefix, `gateway` = this node's address (the same
  address the `bgp` backend would use as next hop), `routing-table` = the VRF
  when one is configured, and
  `comment` = `flowsdn:<instance>:<owner>:<namespace>/<name>` so ownership is
  recoverable after an agent restart. Reconciliation is a full diff of the
  routes whose comment carries this node's `flowsdn:` prefix: routes present on
  the router and not desired are deleted; desired and absent are created;
  differing are patched. Routes without the prefix are never touched.
- **Attributes.** Communities and local preference cannot ride on a static
  route, so they are expressed as routing filter rules —
  `/rest/routing/filter/rule` — in a chain the router applies when
  redistributing static routes into BGP, using `set bgp-communities`,
  `set bgp-large-communities` and `set bgp-local-pref`, matched on
  `dst in <prefix>` and on the route comment. The chain name is
  `flowsdn-<instance>` and its contents are replaced as one ordered list
  whenever the desired statement set changes, preserving the same priority
  ordering as §3.7 so exact routes precede aggregates.
- **Peer state.** `peer_states()` reads `/rest/routing/bgp/session` and maps
  the router's sessions onto the configured peers by remote address, so
  `CiliumBGPNodeConfig.status` stays meaningful even though the node holds no
  session. Fields the router does not expose are reported as absent, not zero.
- **The `Neighbor` reconciler becomes a validator.** It checks that a session
  matching each configured peer exists on the router and records a reconcile
  error if not. Timers, MD5, graceful restart, eBGP multihop, router ID and
  `localASN` are the router's business and are ignored (logged once per
  instance as ignored-in-this-backend).
- **Authentication.** The RouterOS API credential is a `Secret` in
  `--bgp-secrets-namespace` named by `bgp-routeros-secret-name`, keys
  `username`, `password`, and optionally `ca.crt`. TLS is required unless
  `bgp-routeros-insecure` is set; the flag exists for lab use and MUST log a
  warning at startup.
- **Rate limiting.** RouterOS REST is not a high-throughput API. The backend
  MUST batch a reconcile pass into as few requests as possible, MUST rate-limit
  to `bgp-routeros-max-requests-per-second` (default 10) and MUST back off on
  HTTP 5xx and on connection failure with the same schedule as the k8s client.

**Backend selection.** `bgp-backend` = `bgp` (default) or `routeros`, a
node-level setting delivered through the per-node config fan-out of `12`. The
CRD surface is identical for both; a cluster may run different backends on
different nodes (an edge site behind a MikroTik, a datacenter rack peering
directly). ECMP behavior is unchanged: every node programs the same VIP with
itself as gateway, so the router load-shares across nodes, and
`externalTrafficPolicy: Local` still withdraws a node's route when it has no
local backend. See open decision O-1.

### 3.18 ECMP and upstream expectations

flowsdn advertises the same host prefix from every eligible node; the upstream
router's ECMP is the load balancer. Two operational consequences MUST be
documented:

- Routers cap the number of ECMP next hops (commonly 8, 16, 32, 64). A service
  advertised from more nodes than the cap is reachable through an
  implementation-defined subset.
- Plain ECMP rehashes every flow when the next-hop set changes, so losing one
  node resets connections to all of them. Where the upstream supports resilient
  hashing it SHOULD be enabled; where it does not, the datapath's Maglev
  backend selection (`05` §5.1) absorbs the rehash for connections that land on
  a surviving node.

---

## 4. Data model

### 4.1 `CiliumBGPClusterConfig` (cluster-scoped, `cbgpcluster`, status subresource)

| Field | Type | Default / validation | Effect |
|---|---|---|---|
| `spec.nodeSelector` | LabelSelector | optional; nil = all nodes | which nodes get a node config |
| `spec.bgpInstances[]` | list, `listType=map`, key `name` | required, 1..16 items | one speaker instance each |
| `.name` | string | required, 1..255 | instance id; keys node config, override, policies |
| `.localASN` | int64 | optional in CRD, 1..4294967295; **agent errors if absent** | local AS |
| `.localPort` | int32 | optional, 1..65535; nil = do not listen | inbound listen port |
| `.peers[]` | list, `listType=map`, key `name` | optional | |
| `.peers[].name` | string | required, 1..255 | peer id; policy name `peer-<name>-export` |
| `.peers[].peerAddress` | string | optional, IPv4/IPv6 pattern | neighbor IP |
| `.peers[].peerASN` | int64 | optional, 0..4294967295, default `0` | 0 = accept the ASN from OPEN |
| `.peers[].autoDiscovery.mode` | enum | `DefaultGateway` | |
| `.peers[].autoDiscovery.defaultGateway.addressFamily` | enum | `ipv4` \| `ipv6`, required when the block is present | which default route |
| `.peers[].peerConfigRef.name` | string | required inside the block | names a `CiliumBGPPeerConfig`; nil ref = no advertisements, default session parameters |
| `status.conditions[]` | `[]metav1.Condition`, `listType=map` key `type` | | §3.2.1 |

### 4.2 `CiliumBGPPeerConfig` (cluster-scoped, `cbgppeer`, status subresource)

| Field | Type | Default / validation | Effect |
|---|---|---|---|
| `spec.transport.peerPort` | int32 | default `179`, 1..65535 | remote TCP port |
| `spec.transport.passiveMode` | bool | flowsdn extension, default false; true requires nonzero instance `localPort` | suppress every outbound connect/retry; wait in Active for inbound sessions (#186) |
| `spec.transport.sourceInterface` | string | optional | source IP from this device; must yield exactly one usable address per family |
| `spec.timers.connectRetryTimeSeconds` | int32 | default `120`, 1..2147483647 | ConnectRetry |
| `spec.timers.holdTimeSeconds` | int32 | default `90`, 3..65535 | Hold; change ⇒ hard reset |
| `spec.timers.keepAliveTimeSeconds` | int32 | default `30`, 1..65535 | Keepalive; change ⇒ hard reset |
| `spec.timers` | object | **CEL:** `self.keepAliveTimeSeconds <= self.holdTimeSeconds` | |
| `spec.authSecretRef` | string | optional | `Secret` name in the secrets namespace, key `password` |
| `spec.gracefulRestart.enabled` | bool | required inside the block | advertise GR capability |
| `spec.gracefulRestart.restartTimeSeconds` | int32 | default `120`, 1..4095 | GR restart time |
| `spec.ebgpMultihop` | int32 | default `1`, 1..255 | TTL; 1 = disabled; ignored for iBGP |
| `spec.families[]` | list | default `[{ipv6,unicast},{ipv4,unicast}]` with no advertisements | |
| `.afi` | enum | `ipv4;ipv6;l2vpn;ls;opaque`, required | only `ipv4`/`ipv6` produce paths |
| `.safi` | enum | `unicast;multicast;mpls_label;encapsulation;vpls;evpn;ls;sr_policy;mup;mpls_vpn;mpls_vpn_multicast;route_target_constraints;flowspec_unicast;flowspec_vpn;key_value`, required | only `unicast` produces paths |
| `.advertisements` | LabelSelector | optional; **nil selects nothing** | selects `CiliumBGPAdvertisement` by labels |
| `status.conditions[]` | `[]metav1.Condition` | | `cilium.io/MissingAuthSecret` |

Defaults are applied to a **copy** at read time, so every consumer sees a fully
populated spec. A nil `transport`, `timers` or `gracefulRestart` block is
materialized with the defaults above; `gracefulRestart.enabled` defaults to
`false`.

A configured family whose `afi`/`safi` is outside {ipv4,ipv6}×{unicast} MUST be
rejected at instance registration with a reconcile error naming the family,
rather than silently producing an empty session.

### 4.3 `CiliumBGPAdvertisement` (cluster-scoped, `cbgpadvert`, no status)

| Field | Type | Default / validation | Effect |
|---|---|---|---|
| `metadata.labels` | map | | matched by `families[].advertisements` |
| `spec.advertisements[]` | list | required | |
| `.advertisementType` | enum | `PodCIDR;CiliumPodIPPool;Service;Interface`, required | |
| `.service` | object | **CEL:** required iff type is `Service`; forbidden otherwise | |
| `.service.addresses[]` | enum list | `LoadBalancerIP;ClusterIP;ExternalIP`, minItems 1 | which VIPs |
| `.service.aggregationLengthIPv4` | int16 | optional, 0..31 | summary length; ignored under a `Local` traffic policy |
| `.service.aggregationLengthIPv6` | int16 | optional, 0..127 | idem |
| `.interface` | object | **CEL:** required iff type is `Interface`; forbidden otherwise | |
| `.interface.name` | string | required | local device |
| `.selector` | LabelSelector | **CEL:** forbidden for `PodCIDR`; optional otherwise, **nil selects nothing** | selects Services / pools |
| `.attributes.communities.standard[]` | string | pattern: 32-bit decimal or `<0-65535>:<0-65535>` | RFC 1997 |
| `.attributes.communities.wellKnown[]` | enum | the fourteen names of §3.9 | RFC 1997 |
| `.attributes.communities.large[]` | string | pattern `<u32>:<u32>:<u32>` | RFC 8092 |
| `.attributes.localPreference` | int64 | optional | LOCAL_PREF; meaningful to iBGP peers only |

The five CEL rules on `BGPAdvertisement` are normative and MUST be present in
the shipped CRD YAML:

```
self.advertisementType != 'Service'   || has(self.service)
self.advertisementType == 'Service'   || !has(self.service)
self.advertisementType != 'Interface' || has(self.interface)
self.advertisementType == 'Interface' || !has(self.interface)
self.advertisementType != 'PodCIDR'   || !has(self.selector)
```

Because flowsdn also runs the equivalent checks in the controller (a
self-managed CRD may be replaced by a user), a violation that reaches the
controller is a reconcile error naming the object and the rule, not a panic.

### 4.4 `CiliumBGPNodeConfig` (cluster-scoped, `cbgpnode`, operator-owned, status subresource)

Name equals the node name. `spec.bgpInstances[]` mirrors the cluster config
plus:

| Field | Source | Effect |
|---|---|---|
| `.routerID` | override, or operator `ip-pool` allocation; format `ipv4` | when nil the agent derives it (§3.14) |
| `.localPort`, `.localASN` | cluster config, override wins | |
| `.peers[].localAddress` | override; IPv4/IPv6 pattern | session source address |
| `.peers[].{name,peerAddress,peerASN,autoDiscovery,peerConfigRef}` | cluster config | |

`status.bgpInstances[]` (`listType=map` key `name`), agent-written:

| Field | Type | Meaning |
|---|---|---|
| `.name` | string | instance name |
| `.localASN` | int64 | |
| `.peers[]` | `listType=map` key `name` | |
| `.peers[].name`, `.peerAddress` | string | required |
| `.peers[].peerASN` | int64 | learned from the session when configured as 0 |
| `.peers[].peeringState` | string | `unknown\|idle\|connect\|active\|open_sent\|open_confirm\|established` |
| `.peers[].timers.appliedHoldTimeSeconds` | int32 | negotiated |
| `.peers[].timers.appliedKeepaliveSeconds` | int32 | negotiated |
| `.peers[].establishedTime` | string | RFC 3339 UTC, derived from session uptime |
| `.peers[].routeCount[]` | `{afi, safi, received, advertised}` | per family |
| `status.conditions[]` | `[]metav1.Condition` | `cilium.io/BGPReconcileError` |

**DEVIATION (compatibility-preserving).** `peeringState` reports `open_sent`
and `open_confirm` with underscores, matching the reference's string form; the
CRD documentation in the reference lists `opensent`/`openconfirm`. flowsdn
emits the underscore form because that is what the reference code produces and
what cilium-cli parses.

**Opt-in advertised status (#187).** Add optional instance-level
`advertised[]` entries `{peer: string, prefix: CIDR, policy: string}` only when
`bgp-status-report-prefixes=true`. Prefixes are canonical; entries sort by
peer, address family/address/prefix length, then policy and are deduplicated.
Use acknowledged backend state; pending desired advertisements must never be
reported as installed. Default false omits the field entirely; enabled with no
advertisements emits an empty list. The writer supplies a bounded row limit
and checks serialized object size before publication; exceeding either fails
that publication with a reconcile error, retaining the previous status. Never
truncate silently or publish only one backend's subset as a complete snapshot.
The planner implements omission/sorting/deduplication/row limits; CRD schema,
backend acknowledgements, JSON size limits and status writer remain required.
The existing reference fields and defaults remain unchanged.

### 4.5 `CiliumBGPNodeConfigOverride` (cluster-scoped, `cbgpnodeoverride`, no status)

Name MUST equal the node name; instance and peer names MUST match the cluster
config or the entry is ignored.

| Field | Type | Validation | Effect |
|---|---|---|---|
| `spec.bgpInstances[]` | list, key `name`, minItems 1 | | |
| `.name` | string | required, 1..255 | |
| `.routerID` | string | format `ipv4` | router ID; validated against the pool in `ip-pool` mode |
| `.localPort` | int32 | optional | listen port |
| `.localASN` | int64 | 1..4294967295 | per-node ASN |
| `.peers[]` | list, key `name` | | |
| `.peers[].name` | string | required, 1..255 | |
| `.peers[].localAddress` | string | IPv4/IPv6 pattern | session source address |
| `.peers[].localPort` | int32 | optional | **ignored** (§2 DEVIATION) |

### 4.6 Internal types

```
Path            { nlri: Nlri, attrs: PathAttributes, family: Family,
                  created_at: Instant, handle: PathHandle }
PathHandle      opaque, u64
Family          { afi: Afi, safi: Safi }              // ipv4|ipv6 × unicast
Neighbor        { name, address, asn, auth_password, ebgp_multihop_ttl,
                  timers { connect_retry, hold, keepalive },
                  transport { local_address, local_port, remote_port },
                  graceful_restart { enabled, restart_time },
                  families: Vec<Family> }
RoutePolicy     { name, kind: Export|Import, statements: Vec<Statement> }
Statement       { name,
                  conditions { match_neighbors: Option<NeighborMatch>,
                               match_prefixes: Option<PrefixMatch>,
                               match_families: Vec<Family> },
                  actions    { route_action: None|Accept|Reject,
                               add_communities: Vec<Community>,
                               add_large_communities: Vec<LargeCommunity>,
                               set_local_pref: Option<u32>,
                               next_hop: Option<Self_|Unchanged> } }
PrefixMatch     { kind: Any|All|Invert, prefixes: Vec<{cidr, len_min, len_max}> }
PeerState       { name, address, port, peer_asn, local_asn, session_state,
                  uptime, families: Vec<{family, received, accepted, advertised}>,
                  timers { applied_hold, applied_keepalive, configured_*,
                           connect_retry },
                  ebgp_multihop_ttl, graceful_restart { enabled, restart_time },
                  local_caps, remote_caps, tcp_password_enabled }
```

Two tables (`00` §4) back the reconcilers:

- `bgp-desired-route-policies`, primary key
  `(instance, peer, policyType, statementName)`, secondary indexes on
  `(instance, owner)` and `(instance, owner, resource)`, carrying
  `{statement, priority, owner, resource}`;
- `bgp-reconcile-errors`, primary key `(instance, errorId)` with `errorId`
  0..4, secondary index on `instance`.

Neither table is persisted. There is no on-disk RIB, no lock file and no
speaker config file; all durable state lives in the CRDs.

---

## 5. Algorithms

### 5.1 Path reconciliation with reference counting

Per reconciler, state is `resource → family → nlri → Path`. One pass:

1. Recompute the global reference map from the *current* (not desired) state:
   for every resource, family and NLRI, count how many resources hold it.
2. For each resource in the desired set:
   a. For each family present in current but absent from desired, withdraw all
      its paths and drop the family.
   b. For each family in desired, compute `to_advertise` = desired − current
      and `to_withdraw` = current − desired, by NLRI string.
   c. Withdraw first, then advertise. Withdrawing before advertising keeps the
      peak path count bounded and makes a prefix-length change (aggregation
      toggled) a clean replace.
3. Advertise: if the reference map already holds the NLRI with count > 0,
   increment and reuse the existing handle without calling the speaker.
   Otherwise call `advertise`, and on success record `{count: 1, handle}`.
4. Withdraw: if the reference count is > 1, decrement and return without
   calling the speaker. Otherwise call `withdraw`, and on success drop the
   entry.
5. On any speaker error, return the *achieved* state (what is actually in the
   speaker) together with the error. The caller stores the achieved state and
   invalidates its change cursor.

A desired set that is empty for a resource means "withdraw everything for this
resource and forget it".

### 5.2 Full versus diff reconciliation

The `Service` and `RoutePolicy` reconcilers consume change streams and do
incremental work. A full pass is forced when:

- the reconciler has no valid change cursor (first pass, or the previous pass
  failed after the cursor advanced), or
- the resolved peer→family→advertisement structure changed.

A full pass re-subscribes the change stream (whose first batch enumerates every
existing row), rebuilds the desired set from scratch, and additionally computes
the set of resources present in the reconciler's own state but absent from the
stream — those are withdrawals.

A diff pass consumes the pending batch only. A deleted frontend does not
immediately mean a deleted service (other frontends may remain), so a frontend
deletion is turned into a *re-reconcile* of its service, not a withdrawal.

The cursor MUST be invalidated on error. Advancing a cursor and then failing
would silently lose the events in that batch.

### 5.3 Policy rendering and reset computation

Given the desired statement rows for one `(instance, peer, export)`:

1. Sort by `(priority, statementName)`, stable.
2. Build `peer-<peer>-export` with those statements in order.
3. Diff against the installed policy of the same name:
   - present in desired only → **add**;
   - present in both but structurally different → **remove then add**;
   - present in installed only → **remove**.
4. Collect the peers to reset: for every added, removed or changed policy, take
   the union of the neighbor addresses named in the **old** and the **new**
   statements. A statement with no neighbor match (or an empty list) means "all
   peers"; if any such statement appears, reset all peers instead and skip the
   per-peer resets.
5. Issue soft resets. A soft reset that fails (typically because the session is
   not established) is **not** an error: log at `debug` and continue.

Direction is derived from the policy kind: export → out, import → in, both
kinds present → both.

### 5.4 Community parsing and deduplication

```
parse_standard(s):
  if s contains ':' -> (hi, lo) = split; require hi,lo in 0..=65535
                       -> (hi << 16) | lo
  else               -> decimal, require 0..=u32::MAX
```

Within one advertisement, standard and well-known communities are resolved to
`u32` and deduplicated by value, first occurrence winning and the original
string form retained (so a user who wrote `no-export` sees `no-export` in the
policy dump). Large communities are deduplicated by their string form. Across
merged statements (§3.7) the union is taken and sorted lexicographically for
determinism.

### 5.5 Router-ID derivation

```
if node_config.router_id.is_some()      -> use it (already validated as IPv4)
else match allocation_mode:
  Default => match cilium_node.ipv4_address():
               Some(ip) => ip
               None     => mac = link("cilium_host").mac
                           require mac.len() >= 4
                           format "{}.{}.{}.{}" over the last four octets
  IpPool  => error: router ID must have been assigned by the operator
```

The MAC-derived ID is not guaranteed unique. Duplicate router IDs between two
nodes peering with the same upstream produce OPEN error 2/3 on that router; the
condition is visible as a peer stuck below `established` and MUST be called out
in the troubleshooting docs.

### 5.6 Export pipeline for one session

For each locally originated path and each established session:

1. Skip if the path's family is not usable on this session (§3.16.4).
2. Evaluate the session's export policy (§3.7). Reject → skip.
3. Clone the path's attributes; apply the statement's `addCommunities`,
   `addLargeCommunities`, `setLocalPreference`.
4. Drop LOCAL_PREF if the peer is eBGP (different ASN).
5. Prepend the local ASN to AS_PATH if the peer is eBGP; leave AS_PATH empty
   for iBGP.
6. Resolve the next hop (§3.10) and encode as NEXT_HOP or MP_REACH_NLRI.
7. Diff against this session's adj-RIB-out; emit UPDATEs only for the delta.
8. On the first pass after the session reaches Established, emit an
   End-of-RIB marker per family after the delta — an UPDATE with empty
   withdrawn routes and empty NLRI for IPv4 unicast, or an UPDATE carrying only
   an MP_UNREACH_NLRI with no NLRI for other families.

Steps 1–7 also run on a soft reset out and on a received ROUTE-REFRESH; step 8
runs only once per session establishment.

---

## 6. Configuration

Additional resolved keys: `bgp-strict-update-errors` is boolean, default false
(§3.16.5), and `bgp-status-report-prefixes` is boolean, default false (§4.4).
The former is fixed for a session; changing it requires session reconfiguration.
The latter can requeue status projection without resetting sessions.


Agent and operator share the key names of the reference so an existing
`cilium-config` ConfigMap works unchanged.

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-bgp-control-plane` | bool | `false` | master switch; everything here is inert when false |
| `bgp-secrets-namespace` | string | `""` | namespace watched for MD5 and RouterOS secrets; empty disables secret lookup and the peer-config condition |
| `enable-bgp-control-plane-status-report` | bool | `true` | write `CiliumBGPNodeConfig.status` and the operator conditions; false clears existing status |
| `bgp-router-id-allocation-mode` | enum | `default` | `default` \| `ip-pool` (§3.14) |
| `bgp-router-id-allocation-ip-pool` | string | `""` | IPv4 CIDR or range; required in `ip-pool` mode |
| `enable-bgp-legacy-origin-attribute` | bool | `false` | LoadBalancerIP paths get ORIGIN INCOMPLETE |
| `enable-no-service-endpoints-routable` | bool | `true` | keep advertising a VIP with zero active backends (shared with `05`) |

flowsdn-only keys (**DEVIATION**, ADR-0001 — new capability, no reference
equivalent):

| Key | Type | Default | Effect |
|---|---|---|---|
| `bgp-backend` | enum | `bgp` | `bgp` \| `routeros` (§3.17); per node |
| `bgp-routeros-address` | string | `""` | router REST base URL; required for the `routeros` backend |
| `bgp-routeros-secret-name` | string | `""` | `Secret` in the secrets namespace with `username`, `password`, optional `ca.crt` |
| `bgp-routeros-insecure` | bool | `false` | skip TLS verification; logs a warning at startup |
| `bgp-routeros-routing-table` | string | `""` | RouterOS `routing-table` (VRF) for programmed routes |
| `bgp-routeros-max-requests-per-second` | int | `10` | client-side rate limit |
| `bgp-adj-rib-in-max-prefixes` | int | `100000` | per peer per family cap on the observability-only adj-RIB-in |

Helm values, unchanged from the reference:
`bgpControlPlane.enabled`, `.secretsNamespace.{create,name}`,
`.statusReport.enabled`, `.routerIDAllocation.{mode,ipPool}`,
`.legacyOriginAttribute.enabled`; plus flowsdn's
`bgpControlPlane.backend`, `.routeros.{address,secretName,insecure,routingTable}`.
`securityContext.capabilities.ciliumAgent` must include `NET_BIND_SERVICE`
when any instance sets `localPort` below 1024.

Accepted and ignored: `CiliumBGPNodeConfigOverride.spec.bgpInstances[].peers[].localPort`
(§2). Not accepted at all: any `CiliumBGPPeeringPolicy` (the v1 model, removed
before the reference tag) — an object of that kind is not watched and produces
no behavior.

---

## 7. Failure modes

| Failure | Behavior |
|---|---|
| BGP disabled | no tasks, no watches; read APIs return 501; operator creates no node configs |
| `CiliumBGPNodeConfig` for this node missing | all instances withdrawn with full destroy; not an error |
| `CiliumBGPNodeConfig` deleted while running | as above; status writer treats `NotFound` on patch as success |
| `localASN` missing on an instance | instance registration fails; reconcile error recorded; retried |
| Duplicate instance names in one node config | whole pass fails with an error naming the duplicate; nothing is applied |
| `peerConfigRef` names a missing peer config | that peer advertises nothing; the `Neighbor` reconciler skips it; operator sets `MissingPeerConfigs` on the cluster config |
| `authSecretRef` names a missing `Secret` | session is established **without** MD5; operator sets `MissingAuthSecret`. Documented as a security-relevant fallback: the peer will normally refuse the unauthenticated session, which is the intended visible failure |
| `Secret` present but no `password` key | reconcile error; the peer is not (re)configured |
| `sourceInterface` missing, down, or with 0 or >1 usable addresses | peer skipped this pass with a warning; retried on the next `Device` change |
| No default route for an auto-discovery peer | peer has no address; skipped; retried on the next `Route` change |
| Resource store not yet initialized | reconciler returns abort; the pass stops; the store's initialization triggers a new pass |
| Speaker error mid-pass | achieved state persisted, change cursor invalidated, error recorded, outer retry |
| More than 5 reconcile errors on an instance | only the first 5 are kept in the table and in the condition message |
| Condition message over 32 KiB | truncated at a line boundary |
| API server unavailable | status patches retried with backoff; reconcile continues against cached stores; no session is torn down because the API server is down |
| Agent restart with GR enabled | sockets closed without NOTIFICATION; the peer holds routes for the restart time; on restart the RIB and policies are rebuilt before the first peer is added |
| Agent restart with GR disabled | sessions drop, routes are withdrawn by the peer, traffic reconverges via the remaining nodes |
| Agent crash (no clean shutdown) | the peer sees TCP reset; GR applies only if the peer honors RFC 8538 / hold expiry semantics; routes are withdrawn after the hold time at the latest |
| Instance recreate (ASN/port/router-ID change) | full destroy: CEASE sent, GR ended, all sessions of that instance drop and re-establish |
| Router ID collision between two nodes | OPEN error 2/3 from the upstream; the peer stays below `established`; visible in status and metrics |
| Peer does not support a configured family | that family is not exported; other families work; logged once |
| Peer does not support four-octet AS while our ASN needs it | AS_TRANS (23456) is sent and AS4_PATH is used |
| Peer sends a malformed UPDATE | counted and logged; session survives (§3.16.5) |
| Peer floods the adj-RIB-in past the cap | storing stops, counting continues, session survives |
| RouterOS unreachable | reconcile error recorded; existing router state is left alone (routes stay programmed); retried with backoff |
| RouterOS routes with our comment prefix but not desired | deleted — the comment prefix is the ownership marker and is authoritative |
| `enable-no-service-endpoints-routable` false and a service loses all backends | the VIP is withdrawn from every node; the upstream has no route; documented as intended black-holing |
| Aggregation configured on an `externalTrafficPolicy: Local` service | aggregation is ignored, host route advertised; no error |
| `ip-pool` exhausted | allocation fails for that (node, instance); reconcile error on the cluster config; the node keeps its previous router ID if it had one |

---

## 8. Observability

### 8.1 Metrics

Agent, namespace `cilium_bgp_control_plane_`:

| Metric | Type | Labels |
|---|---|---|
| `session_state` | gauge, 1 when established else 0 | `instance_name`, `local_asn`, `neighbor` (`ip:port`), `neighbor_asn` |
| `advertised_routes` | gauge | the four above plus `afi`, `safi` |
| `received_routes` | gauge | the four above plus `afi`, `safi` |
| `reconcile_errors_total` | counter | `instance_name` |
| `reconcile_run_duration_seconds` | histogram | `instance_name` |

Route counts are emitted only for established sessions. The collector queries
peer state under a 5 s timeout; a timeout skips the scrape with an error log
rather than blocking Prometheus.

Operator: `cilium_operator_bgp_control_plane_reconcile_errors_total`
(`resource_kind`, `resource_name`) and
`cilium_bgp_control_plane_reconcile_run_duration_seconds`.

flowsdn additions (**DEVIATION**, new): `messages_total{direction,type}`,
`notifications_total{direction,code,subcode}`, `session_flaps_total`,
`update_parse_errors_total`, `graceful_restarts_total{role}`,
`routeros_requests_total{method,status}`.

### 8.2 Read APIs

| Endpoint | Returns |
|---|---|
| `GET /bgp/peers` | per instance, per peer: name, address, port, local/peer ASN, session state, uptime, per-family counts, timers, multihop TTL, GR state, capabilities, MD5-enabled |
| `GET /bgp/routes?table_type=loc-rib\|adj-rib-in\|adj-rib-out&afi=&safi=[&router_asn=][&neighbor=]` | prefixes with their attributes and age |
| `GET /bgp/route-policies[?router_asn=]` | installed policies with statements in evaluation order |

All three return 501 when BGP is disabled. `flowsdn-dbg bgp peers`,
`flowsdn-dbg bgp routes <available|advertised> <afi> <safi> [vrouter <asn>] [peer <addr>]`
and `flowsdn-dbg bgp route-policies [vrouter <asn>]` render them; the output
columns match the reference so existing runbooks and the cilium-cli aggregation
keep working.

### 8.3 Logging and health

Log fields, structured: `subsys=bgp-control-plane` (agent) or
`subsys=bgp-cp-operator` (operator), plus `instance`, `peer`, `family`,
`prefix`, `policy`, `statement`, `reconciler`, `priority`, `resource`,
`router_id`, `local_asn`, `direction`. Session transitions log at `info`;
per-path advertise/withdraw at `debug`; capability mismatches and skipped peers
at `warn`.

Health: the module registers into the agent's health registry (`00` §3) with
one entry per instance, degraded while any reconcile error is outstanding, and
one entry for the status writer, degraded while status patches are failing.

---

## 9. Test plan

### 9.1 Unit (no kernel, no network)

- [ ] CRD deserialization and defaulting: every nil block filled, every default
      value, the CEL rules rejected in the controller as well.
- [ ] Community parsing: both standard forms, all fourteen well-known names,
      large communities, dedup by value, invalid values rejected.
- [ ] Statement merge: union of communities, max local preference, mismatched
      name/conditions/action rejected.
- [ ] Statement ordering: priority then name; aggregate at `base+1`.
- [ ] Policy rendering, add/remove/recreate diff, and the reset-peer set
      computed from old ∪ new neighbors, including the all-peers case.
- [ ] Path reconciliation with reference counting: shared VIP across two
      services, one deleted, path survives; both deleted, path withdrawn.
- [ ] Partial-failure semantics: achieved state kept, cursor invalidated.
- [ ] Service prefix selection: the full truth table of §3.6.3 across ETP/ITP,
      backends present/absent/local, proxy redirect, no-endpoints flag,
      `loadBalancerClass` nil / cilium / other.
- [ ] Aggregation: length applied, ignored under `Local`, name suffix and
      priority.
- [ ] Legacy origin: INCOMPLETE only for LoadBalancerIP.
- [ ] PodCIDR reconciler inactive outside `kubernetes`/`cluster-pool` IPAM.
- [ ] PodIPPool prefix-length match uses the pool's `maskSize`.
- [ ] Interface address filter: link-local v4 allowed, link-local v6 excluded,
      4-in-6 excluded, device down excluded, oper `unknown` allowed.
- [ ] Default gateway: lowest metric wins, down device excluded, link-local
      gateway excluded, no route → peer skipped.
- [ ] Neighbor diff keyed on name+address+ASN; timer change ⇒ hard reset.
- [ ] Instance recreate triggers on ASN, listen port and router ID.
- [ ] Router ID: from override, from node IPv4, from MAC, `ip-pool` errors.
- [ ] Operator compilation: node selection, override merge, owner reference,
      first-owner-wins conflict, stale node config deletion.
- [ ] Router-ID pool: allocate, restore from existing node configs, override
      inside pool free / inside pool taken / outside pool, free on delete,
      clear-all when no cluster configs remain.
- [ ] All conditions on all three objects, including removal when status
      reporting is disabled.
- [ ] Status: 5 s jittered cadence, no write when unchanged, `NotFound`
      handling, 32 KiB truncation, 5-error cap.

### 9.2 Speaker unit (wire codec and FSM)

- [ ] Round-trip encode/decode of every message type, including boundary
      lengths 19 and 4096.
- [ ] Header errors: short length, long length, bad type, each producing the
      right NOTIFICATION.
- [ ] Attribute flags/length errors, extended length, unknown optional
      transitive retained with the partial bit, unknown well-known rejected.
- [ ] MP_REACH with next-hop lengths 4, 16 and 32; MP_UNREACH.
- [ ] Capability encode/decode for codes 1, 2, 5, 64, 65, including the GR
      flags/time packing and the RFC 8538 N bit.
- [ ] Four-octet AS: AS_TRANS in OPEN, AS4_PATH on export.
- [ ] FSM table of §3.16.3 driven event by event, with a mock clock; every
      transition and every timer.
- [ ] Hold-time negotiation including hold 0; keepalive = min(configured,
      hold/3).
- [ ] Connect-retry jitter lands in `[t, 2t)`.
- [ ] Idle-hold of 5 s enforced after every reset.
- [ ] Connection collision resolution by BGP identifier.
- [ ] Export pipeline: LOCAL_PREF dropped to eBGP, AS_PATH prepended to eBGP
      only, next hop resolution per session, EOR emitted once per family.
- [ ] Import invariant: a session that receives a full table changes no
      Loc-RIB entry, no kernel route and no map — asserted directly.
- [ ] adj-RIB-in cap: storing stops at the cap, counting continues, session
      survives.
- [ ] Malformed UPDATE does not reset the session.

### 9.3 Acceptance suite — the twenty scenarios

The reference's twenty txtar scenarios are the best behavioral specification
that exists for this area, and they are ported as flowsdn's acceptance suite.
Each is a scripted scenario that starts the agent against a fake Kubernetes
API, brings up one or more **real** peer speakers, applies manifests, and pins
the exact set of routes the peer sees. The peer side runs **GoBGP** (a
container in CI, driven over its gRPC API) so the expectations remain a true
interoperability assertion rather than a self-consistency check.

| Scenario | Asserts |
|---|---|
| `commands` | the three read APIs and their CLI rendering |
| `interface` | `Interface` advertisement, device up/down, address filter |
| `multi-peer-advertisements` | different advertisement sets per peer |
| `peering-auth` | MD5; skipped when `TCP_MD5SIG` is unavailable |
| `peering-changes` | timer change ⇒ hard reset; other changes ⇒ update in place |
| `peering-default-gateway` | auto-discovery and metric-based failover |
| `peering-ipv6` | IPv6 sessions, IPv6 NLRI, IPv4-over-IPv6 (RFC 8950) |
| `peering-multi-instance` | two instances, two ASNs, independent lifecycles |
| `pod-cidr` | pod CIDR advertisement and IPAM-mode gating |
| `pod-ip-pool` | multi-pool prefixes and the `maskSize` prefix match |
| `svc-adverts` | the three address types |
| `svc-aggregation` | aggregate lengths v4 and v6 |
| `svc-aggregation-priority` | exact statements evaluated before aggregates |
| `svc-gateway-proxy-redirect` | proxy redirect counts as a local backend |
| `svc-kpr-disabled` | behavior without kube-proxy replacement |
| `svc-modifications` | add/update/delete of services and advertisements |
| `svc-no-endpoints` | the no-endpoints-routable flag both ways |
| `svc-path-attributes` | communities (all three kinds) and local preference |
| `svc-sharing` | VIP shared between services, reference counting |
| `svc-traffic-policy` | ETP/ITP `Local` withdraw and re-advertise |

Each scenario MUST use unique peering addresses so the suite runs in parallel,
and MUST assert the peer's adjacency-RIB-in contents, not only the agent's own
view.

### 9.4 Interoperability

- [ ] **GoBGP** — the acceptance suite above; additionally a long-running
      session exercising route refresh, graceful restart (agent restart with
      the peer holding routes), and four-octet ASNs.
- [ ] **RouterOS** — a CHR instance in CI. Two modes: (a) the `bgp` backend
      peering *with* RouterOS, asserting the router's `/routing/bgp/session`
      and its RIB match expectations; (b) the `routeros` backend, asserting
      programmed static routes, filter rules, comment-based ownership recovery
      after an agent restart, and the peer-state read-back into the CRD status.
- [ ] **FRR** and **bird** — a reduced matrix (session establishment, both
      families, communities, GR) run nightly rather than per-PR, to catch
      encoding assumptions that GoBGP happens to tolerate.
- [ ] A negative interop case per peer: a peer that does not advertise route
      refresh, and a peer that does not advertise graceful restart, both
      asserting the documented fallbacks.

### 9.5 End-to-end

- [ ] Three-node cluster, one upstream router, a `LoadBalancer` service with
      `externalTrafficPolicy: Cluster`: ECMP across three next hops; drain one
      node and confirm the route is withdrawn from that node only.
- [ ] Same with `externalTrafficPolicy: Local`: only nodes with a backend
      advertise; scale the deployment and watch the next-hop set follow.
- [ ] Agent upgrade with GR enabled: no packet loss beyond the datapath's own
      window.
- [ ] Operator restart in `ip-pool` mode: router IDs are restored, no session
      is recreated.

---

## 10. Kernel and platform requirements

This is not a datapath area. Requirements are socket-level and small:

| Requirement | When | Note |
|---|---|---|
| `setsockopt(TCP_MD5SIG)` | `authSecretRef` set | present on every kernel in `docs/kernel-requirements.md`; probed at session setup, and a failure is a reconcile error for that peer |
| `CAP_NET_BIND_SERVICE` | `localPort` < 1024 | otherwise the listen socket fails; instance registration errors |
| IPv6 sockets | IPv6 peers | |
| `IP_TTL` / `IPV6_UNICAST_HOPS` | eBGP multihop, and the TTL=1 default for single-hop eBGP | |
| netlink read of `cilium_host` | router-ID fallback on IPv6-only nodes | read-only; no `NET_ADMIN` needed beyond what the agent already holds |
| Outbound TCP to the peer port | always | |

No BPF helpers, no map or program types, no netlink writes, no sysctls, no
architecture dependence. x86-64 and arm64 are identical. The RouterOS backend
needs only outbound HTTPS to the router.

**BGP creates nothing in the kernel.** No routes, no rules, no addresses, no
neighbor entries. The datapath must independently be able to forward traffic
arriving for an advertised prefix — native routing (or a locally routable
prefix) for pod CIDRs, the kube-proxy-replacement service path for VIPs, and
`bpf.lbExternalClusterIP` for externally reachable ClusterIPs. Advertising a
prefix the datapath cannot serve black-holes it. Keep ClusterIP in the CRD
address enum. If a configured ClusterIP advertisement has
`bpf.lbExternalClusterIP` disabled, reconciliation MUST warn and name that
setting, but MUST NOT reject the advertisement solely for that reason:
external reachability may be supplied separately (ADR-0012 #190). Actual
external ClusterIP forwarding still requires its datapath acceptance tests.

---

## 11. Rust design notes

### 11.1 Crates

| Crate | Contents | Depends on |
|---|---|---|
| `flowsdn-bgp-proto` | wire codec only: messages, path attributes, NLRI, capabilities, communities; `no_std`-friendly, zero-copy decode into borrowed views, owned types for encode. No sockets, no timers, no policy. Fuzzed. | `bytes` |
| `flowsdn-bgp` | speaker: session tasks, FSM, timers, Loc-RIB, adj-RIB-out, adj-RIB-in, export policy engine, the `Advertiser`/`Speaker` traits, MD5 socket option | `flowsdn-bgp-proto`, `tokio`, `socket2`, `flowsdn-table` |
| `flowsdn-bgp-routeros` | the RouterOS REST `Advertiser` implementation | `reqwest` (rustls), `serde` |
| `flowsdn-bgp-cp` | control plane: CRD types, the seven reconcilers, the desired-policy and error tables, the status writer, the read APIs | `flowsdn-bgp`, `flowsdn-bgp-routeros`, `kube`, `flowsdn-table` |
| (operator) | the cluster→node compiler and the router-ID allocator live in the operator crate, using `flowsdn-bgp-cp`'s CRD types | |

Splitting the codec out is deliberate: it is the part with the highest bug
density per line, the part that must be fuzzed, and the part that could
plausibly be published for others.

### 11.2 Key traits

```rust
pub trait Advertiser: Send + Sync {
    async fn ensure(&self, prefix: IpNet, attrs: &PathAttrs) -> Result<PathHandle>;
    async fn withdraw(&self, handle: PathHandle) -> Result<()>;
    async fn observed(&self) -> Result<Vec<AdvertisedPrefix>>;
}

pub trait Speaker: Advertiser {
    async fn add_neighbor(&self, n: &Neighbor) -> Result<()>;
    async fn update_neighbor(&self, n: &Neighbor) -> Result<()>;
    async fn remove_neighbor(&self, n: &Neighbor) -> Result<()>;
    async fn reset_neighbor(&self, addr: IpAddr, kind: ResetKind) -> Result<()>;
    async fn reset_all(&self, kind: ResetKind) -> Result<()>;
    async fn set_export_policy(&self, peer: &str, p: Option<RoutePolicy>) -> Result<()>;
    async fn peer_states(&self) -> Result<Vec<PeerState>>;
    async fn routes(&self, t: TableKind, f: Family, peer: Option<IpAddr>)
        -> Result<Vec<Route>>;
    async fn policies(&self) -> Result<Vec<RoutePolicy>>;
    async fn stop(&self, graceful: bool);
}
```

`PathHandle` is a `u64` newtype minted by the Loc-RIB, not a UUID: the handle
never leaves the process and a monotonic counter is cheaper and easier to debug
than the reference's UUID-per-path scheme.

`PathAttrs` is flowsdn's own type — an `enum PathAttribute` plus an ordered
`SmallVec` — **not** a codec type. The reference's "vendor-agnostic" layer
leaks GoBGP's `packet/bgp` types into every consumer, which is exactly what
makes replacing the speaker hard there; flowsdn's boundary is a plain data type
that both backends can produce.

### 11.3 Async session handling

One `tokio` task per session, owning its TCP stream, its timers
(`tokio::time::sleep_until`, not intervals, so a reset is exact) and its
adj-RIB-out. It receives commands over an `mpsc` channel and Loc-RIB deltas
over a `watch`/broadcast pair from the table crate (`00` §3). A `select!` over
{socket readable, command, RIB delta, hold timer, keepalive timer,
connect-retry timer} is the whole loop; there is no shared mutable state
between sessions except the read-only Loc-RIB snapshot, which is a persistent
map so a snapshot is a cheap clone.

The instance owns the Loc-RIB and a `JoinSet` of session tasks. `stop(graceful)`
either drops the sockets (graceful) or sends CEASE and awaits the flush
(destroy) with a bounded timeout.

Cancel-safety matters: every `await` in the session loop is either a
`select!` branch that can be dropped without losing state, or is guarded by
writing intent to the adj-RIB-out before the write. A partially written message
closes the session rather than resuming mid-frame.

MD5 is applied with `socket2` before `connect`, via `setsockopt(IPPROTO_TCP,
TCP_MD5SIG)` on the raw fd, which forces manual socket construction rather than
`TcpStream::connect`; this is contained in one function.

### 11.4 Reconcilers

Reconcilers are plain `async fn`s over a `&InstanceCtx`, held in a
`Vec<Box<dyn ConfigReconciler>>` sorted once at startup — no dependency
injection (ADR-0004). Per-instance metadata lives in a `HashMap<String, M>`
inside each reconciler, cleared by `cleanup`. The desired-policy and
reconcile-error tables are `flowsdn-table` tables with the indexes of §4.6;
change streams come from `watch()` and the "invalidate the cursor on error"
rule is enforced by making the cursor an `Option` that the error path takes.

### 11.5 Why not an existing Rust BGP crate

Surveyed for: embeddable as a library, export policy with per-neighbor
conditions and attribute setting, graceful restart, IPv6 and RFC 8950, TCP MD5,
maintenance.

| Project | Verdict |
|---|---|
| **holo-bgp** (holo-routing, MIT) | The only feature-complete Rust speaker. Rejected on architecture: it is a component of the `holod` daemon, configured through a YANG northbound built on `libyang3` C bindings, with no programmatic library API for injecting paths. Using it means running a second process configured over gRPC and shipping a C library — which breaks the single static binary on a `scratch` image (ADR-0001) and adds libyang to the dependency and CVE surface. A fork exposing a library API would be a larger and more permanent commitment than writing the export-only subset. |
| **RustyBGP** (osrg, Apache-2.0) | Complete-ish speaker with GoBGP-compatible gRPC, by GoBGP's author. Rejected on maintenance (activity largely stopped around 2022) and on shape: the API surface is GoBGP's protobufs, so adopting it re-imports exactly the type leakage we are trying to remove, and it too is a daemon rather than a library. Graceful restart is not claimed. |
| **sartd / sart** (Apache-2.0) | Purpose-built for the same job — a Kubernetes controller advertising LB and pod routes with its own speaker. Excellent design reference; rejected as a dependency on maturity (no GR, no MD5, minimal policy) and on scope (it brings its own CNI and controller). |
| **zettabgp** (MIT) | A solid, broad message codec — no FSM, no session, no policy. A candidate to supply `flowsdn-bgp-proto`'s decode side rather than writing it. Rejected as the basis because its types are parse-oriented (it decodes far more AFI/SAFIs than we need) and its encode side is not the focus; a purpose-built codec for eleven attribute types and two families is smaller than the adapter would be. Kept as a cross-check oracle in the fuzz harness. |
| **bgpkit-parser** (MIT) | MRT/BMP analytics parser. Parse-only, no UPDATE serialization. Not applicable. |
| **bgp-rs** (MIT) | Older codec, low activity, superseded by zettabgp. Not applicable. |
| bird / FRR / GoBGP / OpenBGPD | Mature, and all sidecars. Rejected for the same reason as holo-bgp, plus the operational seam the reference deliberately avoided: an in-process speaker means an agent restart is one graceful-restart window, not two. |

Honest summary: **no Rust crate offers an embeddable, policy-capable,
GR-capable speaker as a library.** Given that flowsdn needs only the
export-only subset — no best-path selection, no import policy, no route
reflection, no ADD-PATH, two families — the implementable surface is roughly
6–10k lines including tests, against ~2–3k lines of glue for a sidecar plus a
second process in every image. Writing it is the smaller long-term cost and the
one that keeps the single-binary model.

The estimate for the whole area: **L**, 8–20k lines — ~6–10k speaker and codec
with interop tests, ~8–12k control plane (CRDs, operator compiler, seven
reconcilers, status, read APIs), ~1–2k RouterOS backend.

### 11.6 Risks

- Graceful restart is what makes agent restarts invisible and is the easiest
  thing here to get subtly wrong: EOR emitted after policies are installed
  (hence the reconciler ordering), the RFC 8538 N bit, CEASE-vs-silence on
  stop. Test it against a real peer, not a mock.
- Timer negotiation and the hard-reset rule must match the reference exactly or
  peers see flapping on ordinary config edits.
- Statement naming and ordering leak into the CLI output and the acceptance
  expectations. They are frozen in §3.7 and §4; changing them is a
  compatibility break.
- The `Service` reconciler is the largest single piece in the reference (767
  lines of logic against 3081 lines of tests). Port its tests first and write
  the logic against them.

---

## 12. Decision register (resolved and open)

**O-1. Resolved #183: protocol/control plane, RouterOS path, then speaker.**
Build protocol primitives and the shared control plane first. The first
working end-to-end backend is RouterOS under the §3.17 advertiser contract;
then complete the in-tree `bgp` speaker for other deployments. Both remain in
scope. The protocol crate now exists; no working RouterOS backend, control
plane or session speaker is implied by this sequencing decision.

**O-2. Resolved #184: serve both versions.** Keep deprecated `v2alpha1` served
alongside storage `v2` for all five BGP CRDs, consistent with spec 13 §12.2.
Registration projection rejects removal of the older served version. Live
registration and storage-version migration remain unimplemented; the decision
is not a claim that a running reference installation can already be migrated.

**O-3. Resolved #185: MD5 first, TCP-AO deferred.** Keep TCP MD5 as the
initial authenticated transport contract. Do not expose an operative TCP-AO
mode or silently downgrade an AO request to MD5/plaintext. The transport
planner explicitly rejects AO. Introduce an `authMode` CRD extension only with
implementation, feature probing and an independently tested peer/key-rollover
interop case. This decision does not rely on claims about current RouterOS or
GoBGP capabilities; no live MD5 socket implementation is claimed either.

**O-4. Resolved #186: explicit passive-only extension.** Add
`spec.transport.passiveMode`, default false; true requires a configured nonzero
instance localPort and forbids outbound connections/retries. The initial state
is passive Active. Transport planning tests cover missing listener, active
mode and passive suppression; CRD schema and live FSM integration remain work.

**O-5. Resolved #187: opt-in advertised prefix/policy status.** Use the
optional `advertised[]` projection in §4.4, default omitted. Include the
acknowledged peer/prefix/policy association, with deterministic ordering and
bounded all-or-error publication. The pure planner is implemented; CRD schema,
serialized-size validation, backend state and status writes are not.

**O-6. BGP policy names — resolved #188.** Preserve the exact policy names generated by
§3.7, including `peer-<name>-export` and address-family/resource naming. Names are CLI
and scenario compatibility data.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

**O-7. Ignored BGP override port — resolved #189.** Retain
`CiliumBGPNodeConfigOverride.peers[].localPort` in the schema and decoded type, but
ignore it exactly as specified. Do not reinterpret it as a local TCP source-port
binding.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

**O-8. ClusterIP advertisements — resolved #190.** Keep ClusterIP in the advertisement
enum. When configured while `bpf.lbExternalClusterIP` is disabled, warn at
reconciliation naming that setting; do not reject the advertisement solely for that
reason. Operators may supply external reachability separately.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

**O-9. Resolved #191: explicit strict-update-errors escape hatch.** Adopt
§3.16.5 default-false session-survival policy for bounded content errors, with
strict=true closing on all detected UPDATE errors. Framing/TLV truncation is
always fatal. The classifier and independent malformed-message vectors cover
both modes; runtime counters, bounded diagnostics and session actions remain
unimplemented. This does not claim interop coverage or full RFC conformance.

**O-10. BGP backend scope — resolved #192.** Keep `bgp-backend` a node-level setting.
Both in-tree BGP and RouterOS backends remain in scope under the shared advertiser
contract; do not mix next-hop/status models per peer in one instance.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

**Test peer (#208).** The script peer will reuse the Rust protocol library,
while an independent `[exec:gobgpd]`-gated job cross-checks sessions and wire
behavior. A shared codec oracle alone cannot detect shared bugs. Spec 17 owns
command wiring and capability detection; both runtime peers and the twenty
scenario executions remain implementation acceptance. The initial vector tests
use independently specified bytes, not only encoder/decoder round trips.
