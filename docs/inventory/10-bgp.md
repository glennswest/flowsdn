# BGP control plane — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/bgp/**`,
`operator/pkg/bgp/**`, `pkg/k8s/apis/cilium.io/v2/bgp_*_types.go`,
`pkg/k8s/apis/cilium.io/v2alpha1/bgp_*_types.go`,
`pkg/k8s/apis/cilium.io/client/crds/v2/ciliumbgp*.yaml`, `api/v1/openapi.yaml`
(`/bgp/*`), `api/v1/models/bgp_*.go`, `cilium-dbg/cmd/bgp*.go`,
`pkg/bgp/commands/**` (cilium-dbg shell), `Documentation/network/bgp-control-plane/**`,
`install/kubernetes/cilium/values.yaml` (`bgpControlPlane.*`).

## Purpose

The BGP control plane makes a node's pod CIDRs, CiliumPodIPPool allocations,
Service VIPs (LoadBalancer / ClusterIP / ExternalIP) and selected interface IPs
reachable from outside the cluster by advertising them to upstream routers over
BGP. It is **export-only**: Cilium embeds a GoBGP speaker in the agent, installs
a global import policy that rejects every path learned from peers, never touches
the kernel routing table, and does not program the eBPF datapath. The operator
compiles cluster-scoped CRDs into one per-node `CiliumBGPNodeConfig`; the agent
reconciles that into GoBGP sessions, paths and export policies, and writes
session state back into the CRD status.

Only the "v2" model exists in v1.20. The v1 model (`CiliumBGPPeeringPolicy`,
`pkg/bgpv1`) was removed on the way to v1.19/v1.20: `b74e51b715 k8s: remove
CiliumBGPPeeringPolicy CRD` (2025-09-04), `ed874f88fa bgpv1: Remove BGPv1
functionality` (2025-10-20), `97dd2252de bgp: Rename bgpv1 package to bgp`
(2025-10-24). The `v2alpha1` CRD versions still exist (served, not storage,
`deprecated: true`) and the operator runs a one-shot storage-version migrator
that rewrites objects from `v2alpha1` to `v2`.

## Components

Line counts are non-test / test (`wc -l`).

| Path | Lines | Purpose |
|---|---|---|
| `pkg/bgp/cell.go` | 195 / 0 | Hive module `bgp-control-plane`: wires resources (NodeConfig, PeerConfig, Advertisement, Secret, CiliumPodIPPool), stores, reconcilers, API handlers, metrics, statedb tables |
| `pkg/bgp/option/config.go` | 26 / 0 | `enable-bgp-legacy-origin-attribute` flag |
| `pkg/bgp/agent/controller.go` | 206 / 0 | Agent controller: waits for local `CiliumNode`, level-triggered signal, fetches own `CiliumBGPNodeConfig`, calls `BGPRouterManager.ReconcileInstances` with 5-step exponential retry (~15 s) |
| `pkg/bgp/agent/routermgr.go` | 104 / 0 | `BGPRouterManager` interface (ReconcileInstances, GetPeers, GetRoutes, GetRoutePolicies + `*Legacy` REST variants, Stop) |
| `pkg/bgp/agent/signaler/` | 39 / 29 | `BGPCPSignaler`: 1-deep channel that coalesces events from all sources |
| `pkg/bgp/types/bgp.go` | 723 / 144 | Vendor-agnostic `Router` / `RouterProvider` interfaces; `Neighbor`, `Path`, `PeerState`, `RoutePolicy` model; table types |
| `pkg/bgp/types/conversions.go` | 397 / 273 | `ToNeighborV2` (CRD peer + peer-config + password -> `Neighbor`), family conversions |
| `pkg/bgp/types/utils.go` | 132 / 0 | `NewPathForPrefix` (IPv4: ORIGIN+NEXT_HOP 0.0.0.0; IPv6: ORIGIN+MP_REACH_NLRI ::), `SetPathOriginAttrIncomplete`, `CanAdvertisePodCIDR` |
| `pkg/bgp/types/{log,test_fixtures,zz_generated}.go` | 635 / 0 | Log fields, fixtures, deepequal |
| `pkg/bgp/gobgp/server.go` | 392 / 162 | `GoBGPServer`: starts in-process `server.BgpServer`, installs `allow-local` import policy + global import/export REJECT defaults, WatchEvent -> state notification channel, AdvertisePath/WithdrawPath (UUID-keyed), Add/RemoveRoutePolicy (defined-sets + policy + global assignment), Stop (`StopBgp{AllowGracefulRestart:true}` vs full destroy) |
| `pkg/bgp/gobgp/peer.go` | 163 / 0 | Add/Update/Remove/Reset neighbor; hard reset when hold/keepalive change, soft-reset-in when GoBGP says so |
| `pkg/bgp/gobgp/conversions.go` | 714 / 269 | Path/policy/peer conversions to GoBGP API (MD5 -> `PeerConf.AuthPassword`, GR -> `GracefulRestart{Enabled,RestartTime,NotificationEnabled,LocalRestarting}` + per-AFI `MpGracefulRestart`, transport wildcard `0.0.0.0`/`::`, `IdleHoldTimeAfterReset`=5 s) |
| `pkg/bgp/gobgp/state.go` | 363 / 476 | GetPeerState (session state, timers, per-family received/accepted/advertised, capabilities), GetRoutes (loc-rib / adj-rib-in / adj-rib-out), GetRoutePolicies |
| `pkg/bgp/gobgp/provider.go` | 22 / 0 | `RouterProvider` for GoBGP (the only implementation) |
| `pkg/bgp/manager/manager.go` | 966 / 513 | `BGPRouterManager`: per-instance lifecycle (register / reconcile / withdraw via `workdiff.go`), router-ID derivation, runs config reconcilers in priority order, state-reconciler job, statedb reconcile-error table |
| `pkg/bgp/manager/workdiff.go` | 126 / 0 | Diff desired instances vs running; `requiresRecreate` when ASN, listen port or router-ID changes |
| `pkg/bgp/manager/state_tracker.go` | 120 / 0 | Fan-in of GoBGP state notifications -> state reconcilers |
| `pkg/bgp/manager/instance/` | 80 / 0 | `BGPInstance{Name, Global, Router, Config, CancelCtx}` |
| `pkg/bgp/manager/store/` | 181 / 0 | `BGPCPResourceStore[T]` wrapper over `resource.Store` with `ErrStoreUninitialized` |
| `pkg/bgp/manager/tables/` | 381 / 0 | statedb tables `bgp-desired-route-policies` (per instance/peer/type/statement, with owner + resource indexes) and `BGPReconcileError` |
| `pkg/bgp/manager/reconciler/reconcilers.go` | 138 / 0 | `ConfigReconciler` interface, priorities, dedupe by name |
| `pkg/bgp/manager/reconciler/default_gateway.go` | 218 / 583 | prio 10: fills `peerAddress` from the lowest-metric default route (statedb `Route` + `Device` tables) |
| `pkg/bgp/manager/reconciler/interface.go` | 278 / 492 | prio 20: advertises /32 or /128 for IPs on a named, up interface |
| `pkg/bgp/manager/reconciler/pod_cidr.go` | 263 / 523 | prio 30: advertises `CiliumNode.spec.ipam.podCIDRs` (kubernetes / cluster-pool IPAM only) |
| `pkg/bgp/manager/reconciler/service.go` | 767 / 3081 | prio 40: Service VIP advertisement from statedb `Frontend` table; ETP/ITP, `loadBalancerClass`, aggregation, no-endpoint handling, legacy ORIGIN |
| `pkg/bgp/manager/reconciler/pod_ip_pool.go` | 443 / 681 | prio 50: advertises `CiliumNode.spec.ipam.pools.allocated[*].cidrs` for label-selected `CiliumPodIPPool`s |
| `pkg/bgp/manager/reconciler/route_policy.go` | 243 / 101 | prio 100: materialises `bgp-desired-route-policies` rows into one `peer-<name>-export` policy per peer, diff-driven via statedb change iterator |
| `pkg/bgp/manager/reconciler/neighbor.go` | 415 / 593 | prio 110 (last so RIB+policies exist before EOR): add/update/remove peers, secret lookup, `sourceInterface` address resolution |
| `pkg/bgp/manager/reconciler/policies.go` | 500 / 717 | Policy statement builders, community parsing/dedup, statement merging for overlapping adverts, soft-reset after policy change |
| `pkg/bgp/manager/reconciler/paths.go` | 313 / 0 | Generic per-family / per-resource path diff with reference counting (shared prefixes across Services) |
| `pkg/bgp/manager/reconciler/peer_advertisements.go` | 213 / 598 | Resolves peer -> peer-config -> families -> label-selected `CiliumBGPAdvertisement`s |
| `pkg/bgp/manager/reconciler/crd_status.go` | 489 / 430 | State reconciler: builds `CiliumBGPNodeConfig.status`, patches `/status` every 5 s (jittered), `cilium.io/BGPReconcileError` condition; clears status when reporting disabled |
| `pkg/bgp/manager/reconciler/state_reconcilers.go` | 87 / 0 | `StateReconciler` interface |
| `pkg/bgp/api/` | 953 / 262 | REST handlers for `GET /bgp/peers`, `/bgp/routes`, `/bgp/route-policies` (all deprecated) and printers |
| `pkg/bgp/commands/` | 1040 / 0 | `cilium-dbg shell` commands `bgp/peers`, `bgp/routes`, `bgp/route-policies` |
| `pkg/bgp/metrics/metrics.go` | 145 / 0 | Prometheus collector: `session_state`, `advertised_routes`, `received_routes` |
| `pkg/bgp/manager/metrics.go` | 37 / 0 | `reconcile_errors_total`, `reconcile_run_duration_seconds` |
| `pkg/bgp/fake/`, `pkg/bgp/mock/` | 232 / 0 | Fake router / provider for tests |
| `pkg/bgp/test/` | 781 / 235 | Privileged hive-script test harness with in-process GoBGP peers (`gobgp/*` script commands) |
| **`pkg/bgp` total** | **13,604 / 10,247** | |
| `operator/pkg/bgp/cell.go` | 39 / 0 | Module `bgp-cp-operator` |
| `operator/pkg/bgp/manager.go` | 457 / 96 | Operator resource manager: watches ClusterConfig / NodeConfig / Override / PeerConfig / CiliumNode, router-ID IP pool (`ipalloc.HashAllocator`), storage-version migrator |
| `operator/pkg/bgp/cluster.go` | 590 / 1728 | Compiles `CiliumBGPClusterConfig` x nodeSelector x `CiliumBGPNodeConfigOverride` into `CiliumBGPNodeConfig` (ownerRef to cluster config); conditions |
| `operator/pkg/bgp/peer.go` | 267 / 334 | `CiliumBGPPeerConfig` status: `cilium.io/MissingAuthSecret` |
| `operator/pkg/bgp/metrics.go` | 38 / 0 | Operator metrics |
| **`operator/pkg/bgp` total** | **1,391 / 2,321** | |
| `pkg/k8s/apis/cilium.io/v2/bgp_*_types.go` | 1,132 | Five CRD type files (storage version) |
| `pkg/k8s/apis/cilium.io/v2alpha1/bgp_*_types.go` | 1,091 | Deprecated served copies |
| `api/v1/models/bgp_*.go` | 2,184 (generated) | REST models |
| `cilium-dbg/cmd/bgp*.go` | 339 | Deprecated `cilium-dbg bgp {peers,routes,route-policies}` |
| `Documentation/network/bgp-control-plane/*.rst` | 1,770 | Configuration, operation, troubleshooting |

GoBGP dependency: `github.com/osrg/gobgp/v4 v4.6.1-0.20260630022313-d6dee8360046`
(a pinned pre-release). GoBGP's `pkg/packet/bgp` types (`bgp.NLRI`,
`bgp.PathAttributeInterface`, `bgp.ParameterCapabilityInterface`,
`WellKnownCommunityValueMap`) leak into `pkg/bgp/types`, so the "vendor-agnostic"
layer is not actually GoBGP-free.

## Features

- **Enable**: `--enable-bgp-control-plane` (default false; Helm
  `bgpControlPlane.enabled`). Everything below is a no-op when off; the hive
  graph is static and constructors return nil.
- **Multiple BGP instances per node** (`bgpInstances[]`, 1..16, unique `name`).
  Each instance is its own GoBGP server with its own ASN, router-ID and
  optional listen port. Instance is recreated (all sessions dropped) when
  `localASN`, `localPort` or router-ID changes.
- **Active-only by default**: with no `localPort`, GoBGP starts with
  `ListenPort: -1` and never accepts inbound TCP. `localPort: 179` requires
  `CAP_NET_BIND_SERVICE` on the agent (Helm
  `securityContext.capabilities.ciliumAgent`). Rationale in docs: co-exist with
  another speaker (e.g. bird) on the same host.
- **Peers** (`peers[]` per instance, unique `name`): IPv4 or IPv6 `peerAddress`,
  `peerASN` (0 = accept whatever the peer's OPEN says), `peerConfigRef` ->
  `CiliumBGPPeerConfig`, optional `autoDiscovery`. iBGP and eBGP both work.
- **Default-gateway auto-discovery** (`autoDiscovery.mode: DefaultGateway`,
  `defaultGateway.addressFamily: ipv4|ipv6`): peer address = gateway of the
  lowest-`Priority` active default route whose device is oper-up; link-local
  gateways rejected. One session per AF at a time; route/device table changes
  re-trigger reconciliation (multi-homing fail-over).
- **Transport**: `transport.peerPort` (default 179), `transport.sourceInterface`
  (source IP taken from the named interface, which must have exactly one
  usable address per AF; falls back to auto-detect otherwise). Per-node
  `localAddress` override via `CiliumBGPNodeConfigOverride`. Without a local
  address GoBGP binds `0.0.0.0`/`::`.
- **Timers**: `connectRetryTimeSeconds` (120), `holdTimeSeconds` (90, min 3),
  `keepAliveTimeSeconds` (30, must be <= hold, CEL-validated). Hold/keepalive
  changes cause a hard session reset; GoBGP applies jitter to connect-retry
  (`[t, 2t)`); `IdleHoldTimeAfterReset` is hard-coded to 5 s.
- **TCP MD5 (RFC 2385)**: `authSecretRef` names a `Secret` in
  `--bgp-secrets-namespace` (Helm `bgpControlPlane.secretsNamespace.name`,
  default `kube-system`; `.create` optionally creates it). Key must be
  `password`. Missing secret -> session proceeds with empty password and the
  operator sets `cilium.io/MissingAuthSecret`. No TCP-AO (RFC 5925) support.
- **Graceful restart (RFC 4724 + RFC 8538 notification)**:
  `gracefulRestart.enabled`, `restartTimeSeconds` (120, 1..4095). Cilium acts
  as restarting speaker only; on agent stop it calls
  `StopBgp{AllowGracefulRestart:true}` (no CEASE) unless the instance is being
  withdrawn, in which case it destroys the server (sends CEASE, ends GR).
  Per-AFI `MpGracefulRestart` is enabled for every configured family.
- **eBGP multihop**: `ebgpMultihop` TTL (default 1 = disabled, 1..255); ignored
  for iBGP.
- **Address families**: `families[]` of `{afi, safi}` with an `advertisements`
  label selector each. Default when empty: `ipv6/unicast` and `ipv4/unicast`
  with **no** advertisements (nothing is advertised unless a family selects
  adverts). CRD enum allows many AFI/SAFIs (l2vpn/evpn, flowspec, mpls_vpn,
  ...) but only ipv4/ipv6 unicast paths are ever generated.
- **IPv6**: v6 sessions, v6 prefixes via MP_REACH_NLRI, and IPv4 NLRI over an
  IPv6 session (GoBGP emits MP_REACH ipv4-unicast with an IPv6 next hop, RFC
  8950 — visible in the docs' `cilium bgp routes advertised` sample). Cilium
  only advertises the AFs it is itself enabled for.
- **Advertisement types** (`CiliumBGPAdvertisement.spec.advertisements[]`):
  - `PodCIDR`: node's `CiliumNode.spec.ipam.podCIDRs` (only for `--ipam
    kubernetes` / `cluster-pool`; reconciler disabled otherwise). No selector.
  - `CiliumPodIPPool`: prefixes from `CiliumNode.spec.ipam.pools.allocated`
    for pools matching `selector` (labels plus implicit
    `io.cilium.podippool.name` / `.namespace`); requires `--ipam multi-pool`.
    Export policy matches with `PrefixLenMin=PrefixLenMax=pool maskSize`.
  - `Service`: `service.addresses` ⊆ {LoadBalancerIP, ClusterIP, ExternalIP};
    `selector` matches Service labels plus implicit
    `io.kubernetes.service.name` / `.namespace`; optional
    `aggregationLengthIPv4` (0..31) / `aggregationLengthIPv6` (0..127).
  - `Interface`: `interface.name`; every global-unicast (or v4 link-local) IP
    on an admin-up, oper `up|unknown` device as /32 or /128.
  - `attributes`: `communities.standard[]` (`"65000:99"` or 32-bit decimal),
    `communities.wellKnown[]` (14-name enum mapped via GoBGP
    `WellKnownCommunityValueMap`), `communities.large[]` (`a:b:c`),
    `localPreference`. The v1 name for this was
    `advertisedPathAttributes`; in v2 it is `attributes` on the advertisement.
- **Service semantics**:
  - LoadBalancerIP: only if `spec.loadBalancerClass` is nil or
    `io.cilium/bgp-control-plane` (`v2.BGPLoadBalancerClass`).
  - `externalTrafficPolicy: Local` (LB IP, ExternalIP) / `internalTrafficPolicy:
    Local` (ClusterIP): advertise only when an **active** backend is on this
    node; aggregation is ignored and the exact /32 or /128 is sent. An L7
    proxy redirect (Gateway API / Ingress via Envoy) counts as a local backend
    for LoadBalancer frontends.
  - `Cluster` policy: advertised from every selected node regardless of
    backend placement -> upstream ECMP across nodes. With zero active backends
    the VIP stays advertised only if `--enable-no-service-endpoints-routable`
    (default true).
  - Aggregation: prefix length replaced by `aggregationLength*`; the
    aggregated statement is given priority `base+1` and name suffix
    `-agg-<len>`; docs warn of black-holes for unassigned addresses and of
    undefined behaviour when two adverts aggregate the same prefix with
    different attributes.
  - Overlapping advertisements matching one Service: statements with equal
    conditions are merged — communities are unioned, local-pref takes the max.
  - Shared VIPs across Services are reference-counted so a path is withdrawn
    only when the last owner goes away.
  - `--enable-bgp-legacy-origin-attribute`: LoadBalancerIP paths get ORIGIN
    INCOMPLETE (MetalLB compatibility) instead of IGP.
- **Route-policy model** (internal, exposed read-only via API): one **export**
  policy per peer named `peer-<peerName>-export`, default action REJECT;
  statements named `<Type>[-<resource>]-ipv4|ipv6[-agg-N]`, each matching
  `MatchNeighbors{any,[peer]}` + `MatchPrefixes{any,[cidr min..max]}`, action
  ACCEPT + AddCommunities / AddLargeCommunities / SetLocalPreference. Ordered
  by reconciler priority then name. Policies are installed as GoBGP *global*
  policies with neighbor conditions because per-neighbor policies only work in
  GoBGP route-server mode. Any policy change triggers a soft reset (out, or
  in/out) of the affected peers or all peers.
- **Import side**: global import assignment `DefaultAction: REJECT` with a
  single `allow-local` policy accepting `ROUTE_TYPE_LOCAL`; nothing a peer
  sends enters Loc-RIB. `received_routes` metrics and `adj-rib-in` listing
  still show what peers sent.
- **Path selection / ECMP**: not a Cilium concern — Loc-RIB only contains
  locally originated paths, one per prefix, next hop rewritten to the session's
  local address by GoBGP (`AdvertiseInactiveRoutes: true` is set so paths are
  exported even when the kernel has no matching route). ECMP happens on the
  upstream router because N nodes advertise identical /32s; docs warn about
  router ECMP path limits and recommend resilient hashing / Maglev to survive
  node loss.
- **Node-config generation (operator)**: for each `CiliumBGPClusterConfig`, for
  each `CiliumNode` matching `nodeSelector` (nil = all), create/update
  `CiliumBGPNodeConfig/<nodeName>` with an owner reference; merge
  `CiliumBGPNodeConfigOverride/<nodeName>` (routerID, localPort, localASN,
  peers[].localAddress); delete NodeConfigs whose node no longer matches;
  first-owner-wins on conflicts. Conditions on the cluster config:
  `cilium.io/NoMatchingNode`, `cilium.io/MissingPeerConfigs`,
  `cilium.io/ConflictingClusterConfig`.
- **Router-ID allocation** (`--bgp-router-id-allocation-mode`, Helm
  `bgpControlPlane.routerIDAllocation.mode`): `default` = node IPv4 from
  `CiliumNode` else lower 32 bits of `cilium_host` MAC (IPv6-only clusters);
  `ip-pool` = operator allocates a unique IPv4 per (node, instance) from
  `--bgp-router-id-allocation-ip-pool` (`ipPool`), writes it into
  `NodeConfig.spec.bgpInstances[].routerID`, restores allocations from existing
  NodeConfigs on restart, honours overrides (inside pool: must be free;
  outside pool: free-form).
- **Status reporting** (`--enable-bgp-control-plane-status-report`, default
  true, Helm `bgpControlPlane.statusReport.enabled`): agent patches
  `CiliumBGPNodeConfig.status` every 5 s ± jitter with per-instance / per-peer
  state (see Data model); operator maintains conditions on ClusterConfig and
  PeerConfig. Disabling clears all existing status.
- **Observability**: `cilium-dbg bgp peers|routes|route-policies` (deprecated
  REST-backed), `cilium-dbg shell -- bgp/peers|bgp/routes|bgp/route-policies`
  (statedb-era commands), `cilium bgp peers|routes` (cilium-cli, aggregates
  across nodes), Prometheus metrics, logs tagged `subsys=bgp-control-plane` /
  `subsys=bgp-cp-operator`.
- **Not supported**: BFD (docs say so explicitly), TCP-AO, ADD-PATH, route
  import into kernel or datapath, per-peer import policies, passive-only
  sessions without `localPort`, VRFs, non-unicast SAFIs in practice.

## Data model

### CiliumBGPClusterConfig (cluster-scoped, `cbgpcluster`, status subresource)

| Field | Type | Default / validation | Effect |
|---|---|---|---|
| `spec.nodeSelector` | `LabelSelector` | nil = all nodes | Which nodes get a `CiliumBGPNodeConfig` |
| `spec.bgpInstances[]` | list, map key `name` | required, 1..16 | One GoBGP server each |
| `.name` | string | 1..255 | Instance id; NodeConfig, override and policy names key on it |
| `.localASN` | int64 | 1..4294967295, optional in CRD but agent errors if missing | Local AS (4-byte OK) |
| `.localPort` | int32 | 1..65535, nil = do not listen | Listen port (`-1` to GoBGP when nil) |
| `.peers[]` | list, map key `name` | optional | |
| `.peers[].name` | string | 1..255 | Peer id (policy name `peer-<name>-export`) |
| `.peers[].peerAddress` | string | IPv4/IPv6 regex; optional | Neighbor IP; nil + no autoDiscovery = skipped |
| `.peers[].peerASN` | int64 | 0..4294967295, default 0 | 0 disables OPEN ASN check |
| `.peers[].autoDiscovery.mode` | enum `DefaultGateway` | | |
| `.peers[].autoDiscovery.defaultGateway.addressFamily` | enum `ipv4|ipv6` | required with mode | Which default route to use |
| `.peers[].peerConfigRef.name` | string | optional (v2alpha1 also had `group`/`kind`; dropped in v2) | Reference to `CiliumBGPPeerConfig`; nil = defaults; missing object = peer skipped |
| `status.conditions[]` | `metav1.Condition` | | `cilium.io/NoMatchingNode`, `cilium.io/MissingPeerConfigs`, `cilium.io/ConflictingClusterConfig` |

### CiliumBGPPeerConfig (cluster-scoped, `cbgppeer`, status subresource)

| Field | Type | Default / validation | Effect |
|---|---|---|---|
| `spec.transport.peerPort` | int32 | 179 (1..65535) | Remote TCP port |
| `spec.transport.sourceInterface` | string | optional | Source IP from this device (exactly one usable addr per AF) |
| `spec.timers.connectRetryTimeSeconds` | int32 | 120 (1..2^31-1) | ConnectRetryTimer |
| `spec.timers.holdTimeSeconds` | int32 | 90 (3..65535) | HoldTimer; change = hard reset |
| `spec.timers.keepAliveTimeSeconds` | int32 | 30 (1..65535, <= hold via CEL) | KeepaliveTimer; change = hard reset |
| `spec.authSecretRef` | string | optional | Secret name in `--bgp-secrets-namespace`, key `password`, TCP MD5 |
| `spec.gracefulRestart.enabled` | bool | required inside block; block optional (disabled) | Advertise GR capability, restarting-speaker |
| `spec.gracefulRestart.restartTimeSeconds` | int32 | 120 (1..4095) | GR Restart Time |
| `spec.ebgpMultihop` | int32 | 1 (1..255) | TTL; <=1 means disabled |
| `spec.families[]` | list | default `[ipv6/unicast, ipv4/unicast]` with no adverts | |
| `.afi` | enum `ipv4;ipv6;l2vpn;ls;opaque` | required | |
| `.safi` | enum `unicast;multicast;mpls_label;encapsulation;vpls;evpn;ls;sr_policy;mup;mpls_vpn;mpls_vpn_multicast;route_target_constraints;flowspec_unicast;flowspec_vpn;key_value` | required | Only unicast is meaningful |
| `.advertisements` | `LabelSelector` | nil = advertise nothing for this family | Selects `CiliumBGPAdvertisement`s by labels |
| `status.conditions[]` | | | `cilium.io/MissingAuthSecret` |

Go constants: `DefaultBGPPeerPort=179`, `DefaultBGPEBGPMultihopTTL=1`,
`DefaultBGPConnectRetryTimeSeconds=120`, `DefaultBGPHoldTimeSeconds=90`,
`DefaultBGPKeepAliveTimeSeconds=30`, `DefaultBGPGRRestartTimeSeconds=120`.
`SetDefaults()` on the spec fills every nil block, so the agent always sees a
fully populated config.

### CiliumBGPAdvertisement (cluster-scoped, `cbgpadvert`, no status)

| Field | Type | Default / validation | Effect |
|---|---|---|---|
| `metadata.labels` | | | Matched by `families[].advertisements` |
| `spec.advertisements[]` | list | required | |
| `.advertisementType` | enum `PodCIDR;CiliumPodIPPool;Service;Interface` | required | |
| `.service` | object | required iff type=Service (CEL) | |
| `.service.addresses[]` | enum `LoadBalancerIP;ClusterIP;ExternalIP` | min 1 | Which VIPs |
| `.service.aggregationLengthIPv4` | int16 | 0..31 | Summary length (ignored under Local traffic policy) |
| `.service.aggregationLengthIPv6` | int16 | 0..127 | idem |
| `.interface` | object | required iff type=Interface (CEL) | |
| `.interface.name` | string | required | Local device |
| `.selector` | `LabelSelector` | forbidden for PodCIDR (CEL); nil for other types = select nothing | Selects Services / PodIPPools |
| `.attributes.communities.standard[]` | `BGPStandardCommunity` | regex `<0-4294967295>` or `<0-65535>:<0-65535>` | RFC 1997 |
| `.attributes.communities.wellKnown[]` | enum `internet;planned-shut;accept-own;route-filter-translated-v4;route-filter-v4;route-filter-translated-v6;route-filter-v6;llgr-stale;no-llgr;blackhole;no-export;no-advertise;no-export-subconfed;no-peer` | | Mapped to 0x0, 0xffff0000..0xffff0007, 0xffff029a, 0xffffff01..04 |
| `.attributes.communities.large[]` | `BGPLargeCommunity` | regex `u32:u32:u32` | RFC 8092 |
| `.attributes.localPreference` | int64 | optional | LOCAL_PREF (only meaningful to iBGP peers) |

### CiliumBGPNodeConfig (cluster-scoped, `cbgpnode`, operator-owned, status subresource)

Name = node name. `spec.bgpInstances[]` mirrors the cluster config with
additions:

| Field | Source | Effect |
|---|---|---|
| `.routerID` | override or operator ip-pool allocation | If nil the agent derives it (see Features) |
| `.localPort` | cluster config or override | |
| `.localASN` | cluster config or override | |
| `.peers[].localAddress` | override | Source IP for the session |
| `.peers[].{name,peerAddress,peerASN,autoDiscovery,peerConfigRef}` | cluster config | |

`status.bgpInstances[]` (agent-written):

| Field | Type | Meaning |
|---|---|---|
| `.name`, `.localASN` | | |
| `.peers[].name`, `.peerAddress`, `.peerASN` | | `peerASN` filled from the session when configured as 0 |
| `.peers[].peeringState` | string | `idle|connect|active|opensent|openconfirm|established|unknown` |
| `.peers[].timers.appliedHoldTimeSeconds`, `.appliedKeepaliveSeconds` | int32 | Negotiated values |
| `.peers[].establishedTime` | RFC 3339 | Derived from uptime |
| `.peers[].routeCount[]` | `{afi, safi, received, advertised}` | Per family |
| `status.conditions[]` | | `cilium.io/BGPReconcileError` (True with up to 32 KiB of joined reconciler errors from the statedb error table) |

Advertised prefixes and installed route policies are **not** in the status;
they are only reachable through the agent API / shell commands.

### CiliumBGPNodeConfigOverride (cluster-scoped, `cbgpnodeoverride`, no status)

Name must equal the node name; instance and peer names must match the cluster
config.

| Field | Type | Effect |
|---|---|---|
| `spec.bgpInstances[].name` | string 1..255 | |
| `.routerID` | IPv4 | Router-ID (validated against pool in `ip-pool` mode) |
| `.localPort` | int32 | Listen port |
| `.localASN` | int64 1..2^32-1 | Per-node ASN |
| `.peers[].name` | string | |
| `.peers[].localAddress` | IP | Session source address |
| `.peers[].localPort` | int32 | Present in CRD, **not copied** by the operator (dead field) |

### Internal / boundary structs (`pkg/bgp/types`)

- `Neighbor{Name, Address, ASN, AuthPassword, EbgpMultihop{TTL}, Timers{ConnectRetry, HoldTime, KeepaliveInterval}, Transport{LocalAddress, LocalPort, RemotePort}, GracefulRestart{Enabled, RestartTime}, AfiSafis[]}`
- `Path{NLRI, PathAttributes[], Family, CreatedAt, Best, UUID, SourceASN}` — `UUID` is GoBGP's handle used for withdrawal.
- `RoutePolicy{Name, Type export|import, Statements[]{Name, Conditions{MatchNeighbors{any|all|invert,[]addr}, MatchPrefixes{type,[]{CIDR,PrefixLenMin,PrefixLenMax}}, MatchFamilies[]}, Actions{RouteAction none|accept|reject, AddCommunities[], AddLargeCommunities[], SetLocalPreference, NextHop{Self,Unchanged}}}}`
- `PeerState{Name, Address, Port, PeerAsn, LocalAsn, SessionState, Uptime, Families[]{Afi,Safi,Received,Accepted,Advertised}, Timers{Applied*/Configured* hold+keepalive, ConnectRetry}, EbgpMultihopTTL, GracefulRestart{Enabled,RestartTime}, Local/RemoteCapabilities[], TCPPasswordEnabled}`
- statedb `DesiredRoutePolicy{Instance, Peer, PolicyType, Statement, Priority, Owner, Resource}` and `BGPReconcileError{Instance, ErrorID, Error}`.

### Persisted files

None. All state is in CRDs (status) and in-memory GoBGP RIBs. There is no
on-disk RIB, no lock files, no config file for GoBGP.

## External interfaces

- **BGP wire protocol** (via GoBGP): TCP/179 outbound (or `peerPort`),
  optional inbound listener on `localPort`; OPEN capabilities: 4-byte ASN,
  MP-BGP per configured AFI/SAFI, route-refresh, graceful restart (+ RFC 8538
  notification), extended-next-hop when needed. Path attributes emitted:
  ORIGIN (IGP or INCOMPLETE), AS_PATH (GoBGP prepends local ASN for eBGP),
  NEXT_HOP / MP_REACH_NLRI (self), COMMUNITIES, LARGE_COMMUNITIES, LOCAL_PREF.
  TCP MD5 via `TCP_MD5SIG` socket option inside GoBGP.
- **Kubernetes API**: watches (agent) `CiliumBGPNodeConfig`,
  `CiliumBGPPeerConfig`, `CiliumBGPAdvertisement`, `Secret` (one namespace),
  `CiliumPodIPPool` (multi-pool only), local `CiliumNode`; statedb tables
  `Frontend` (loadbalancer), `Device`, `Route`. Writes `CiliumBGPNodeConfig/status`
  (JSON patch `replace /status`, field manager
  `CiliumBGPNodeConfigStatusReconciler`). Operator watches
  `CiliumBGPClusterConfig`, `CiliumBGPNodeConfigOverride`, `CiliumNode`,
  `CiliumBGPPeerConfig`, `Secret`; creates/updates/deletes `CiliumBGPNodeConfig`;
  updates `CiliumBGPClusterConfig/status` and `CiliumBGPPeerConfig/status`;
  patches CRD `status.storedVersions` during the v2alpha1 -> v2 migration.
- **Agent REST API** (`api/v1/openapi.yaml`, all marked `deprecated: true`,
  501 when BGP disabled):
  - `GET /bgp/peers` -> `[]BgpPeer`
  - `GET /bgp/routes?table_type=loc-rib|adj-rib-in|adj-rib-out&afi=&safi=[&router_asn=][&neighbor=]` -> `[]BgpRoute`
  - `GET /bgp/route-policies[?router_asn=]` -> `[]BgpRoutePolicy`
- **cilium-dbg**: `cilium-dbg bgp peers [-c]`, `cilium-dbg bgp routes
  <available|advertised> <afi> <safi> [vrouter <asn>] [peer|neighbor <addr>]`,
  `cilium-dbg bgp route-policies [vrouter <asn>]` (deprecated). Shell:
  `cilium-dbg shell -- bgp/peers [--format table|table-json|json|detailed]
  [--no-uptime] [-o file]`, `bgp/routes [--no-age] [-a] <loc|adj-in|adj-out>
  <afi> <safi>`, `bgp/route-policies [-i instance]`.
- **Metrics** (agent, namespace `cilium_bgp_control_plane_*`): `session_state`
  (1/0; labels `instance_name, local_asn, neighbor (ip:port), neighbor_asn`),
  `advertised_routes`, `received_routes` (+ `afi, safi`),
  `reconcile_errors_total`, `reconcile_run_duration_seconds` (`instance_name`).
  Operator: `cilium_operator_bgp_control_plane_reconcile_errors_total`
  (`resource_kind, resource_name`), `cilium_bgp_control_plane_reconcile_run_duration_seconds`.
- **Flags** (agent + operator share `option.DaemonConfig`):
  `--enable-bgp-control-plane` (false), `--bgp-secrets-namespace` (""),
  `--enable-bgp-control-plane-status-report` (true),
  `--bgp-router-id-allocation-mode default|ip-pool` (`default`),
  `--bgp-router-id-allocation-ip-pool` (""),
  `--enable-bgp-legacy-origin-attribute` (false),
  `--enable-no-service-endpoints-routable` (true, from `svcrouteconfig`).
  Helm: `bgpControlPlane.{enabled, secretsNamespace.{create,name},
  statusReport.enabled, routerIDAllocation.{mode,ipPool},
  legacyOriginAttribute.enabled}` rendered into the ConfigMap.
- **Netlink**: read-only. `safenetlink.LinkByName("cilium_host")` for the
  MAC-based router-ID fallback; statedb `Device`/`Route` tables (populated
  elsewhere) for `sourceInterface`, `Interface` advertisements and default
  gateway discovery. **No routes, rules, or addresses are created.** No
  sysctls.

## Dependencies

- Inventory areas: **loadbalancer / service** (statedb `Frontend` table,
  `Service.LoadBalancerClass`, `ProxyRedirects`, backend `NodeName` and
  `State`); **IPAM** (`CiliumNode.spec.ipam.podCIDRs`, `pools.allocated`,
  `CiliumPodIPPool`); **node / datapath tables** (`Device`, `Route`,
  `NodeAddress` statedb tables, `cilium_host` device); **k8s resource layer**
  (`resource.Resource`, `BGPCPResourceStore`); **hive / statedb / job**
  framework; **metrics**; **operator** framework (LB-IPAM's
  `RangeFromPrefix`, `ipalloc.HashAllocator` for router-IDs).
- External: GoBGP v4 (in-process library, not a daemon); Kubernetes API
  server. No kvstore, no cloud APIs, no Envoy.
- Datapath contract: BGP assumes the node's datapath will accept and forward
  traffic arriving for the advertised prefixes — native routing for pod CIDRs
  (or the advertised prefix must be locally routable), KPR/NodePort-style
  service handling for VIPs, and for externally reachable ClusterIPs the
  `bpf.lbExternalClusterIP` datapath setting. The BGP code itself has no
  datapath hooks and installs nothing.

## Kernel / platform requirements

Not a datapath area. Requirements are socket-level:

- `TCP_MD5SIG` setsockopt (Linux, any modern kernel) for `authSecretRef`; the
  privileged tests probe for it and skip otherwise.
- `CAP_NET_BIND_SERVICE` only when `localPort` < 1024.
- IPv6 sockets for v6 peers; TTL/`IP_TTL`/`IPV6_UNICAST_HOPS` for multihop
  and the GTSM-style TTL=1 default (handled by GoBGP).
- Reads `cilium_host` MAC (netlink) for router-ID fallback; needs `NET_ADMIN`
  only through the surrounding agent, not for BGP itself.
- No BPF helpers, no map types, no arch dependence.

## Tests

- **Unit** (`pkg/bgp/**/*_test.go`, 10,247 lines; `operator/pkg/bgp`, 2,321):
  reconciler behaviour with a fake router — `Test_ServiceLBReconciler`,
  `Test_ServiceClusterIPReconciler`, `Test_ServiceExternalIPReconciler`,
  `Test_ServiceVIPSharing`, `Test_ServiceAndAdvertisementModifications`,
  `Test_ServiceAdvertisementWithPeerIPChange`,
  `Test_ServiceLBReconcilerWithLegacyOriginAttr`,
  `TestServiceReconcilerMetadataPartialFailure`, `Test_PodCIDRAdvertisement`,
  `Test_PodIPPoolAdvertisements`, `Test_InterfaceAdvertisement`,
  `TestNeighborReconciler_StaticPeer`,
  `TestNeighborReconciler_SourceInterfaceAddress`,
  `TestDefaultGatewayReconciler_*`, `TestRoutePolicyReconciler` (txtar
  `route-policy-reconciler.txtar`), `TestRoutePolicySoftReset`,
  `TestMergeRoutePolicyStatements`, `TestCRDConditions`,
  `TestDisableStatusReport`, `TestStatedbReconcileErrors`; GoBGP layer
  `TestGlobalImportPolicy`, `TestAddRemoveRoutePolicy`, `TestGetPeerState`,
  `TestGetRoutes`, `TestToGoBGPPeer`, `TestPathConversions`; operator
  `Test_ClusterConfigSteps`, `Test_NodeLabels`, `TestRouterIDAllocation`,
  `TestClusterConfigConditions`, `TestConflictingClusterConfigCondition`,
  `TestMissingAuthSecretCondition`, `TestVersionMigration`.
- **Privileged script tests** (`pkg/bgp/test/script_test.go`,
  `TestPrivilegedScript`): brings up the real `bgp.Cell` in a hive with a fake
  k8s client, a dummy link `cilium-bgp-test`, and in-process GoBGP *peer*
  instances driven by `gobgp/add-server|add-peer|peers|routes|wait-state`
  script commands. 20 txtar scenarios: `commands`, `interface`,
  `multi-peer-advertisements`, `peering-auth` (MD5, skips without
  `TCP_MD5SIG`), `peering-changes`, `peering-default-gateway`, `peering-ipv6`,
  `peering-multi-instance`, `pod-cidr`, `pod-ip-pool`, `svc-adverts`,
  `svc-aggregation`, `svc-aggregation-priority`, `svc-gateway-proxy-redirect`,
  `svc-kpr-disabled`, `svc-modifications`, `svc-no-endpoints`,
  `svc-path-attributes`, `svc-sharing`, `svc-traffic-policy`. Each pins the
  exact adj-rib-in seen by the peer (`cmp gobgp-routes-*.expected`) — these
  are the best behavioural spec for a reimplementation.
- **E2E**: `.github/workflows/tests-e2e-upgrade.yaml` has a
  `bgp-control-plane` matrix dimension (upgrade/downgrade with BGP on);
  cilium-cli's connectivity suite provides the `bgp` tests used by the
  `conformance-*` workflows (external repo). No BGP-specific privileged
  datapath tests, since there is no datapath.

## Rust mapping

### What must exist regardless of speaker choice (control plane, ~8-12k lines)

1. CRD types for the five resources (serde + schemars/CEL-equivalent
   validation performed in the controller since we cannot rely on the API
   server for the regex/CEL rules if we ship our own CRD YAML — or generate the
   same YAML and let the API server validate).
2. Operator: cluster-config -> node-config compiler, override merge, owner
   references, conflict detection, conditions, router-ID pool allocator,
   storage-version migration and verification before future served-version
   removal (retain deprecated `v2alpha1` and storage `v2`; resolved #184).
3. Agent: level-triggered reconciler with the same seven reconcilers and the
   same ordering (default-gateway 10, interface 20, pod-cidr 30, service 40,
   pod-ip-pool 50, route-policy 100, neighbor 110), the reference-counted path
   diff, the desired-route-policy table and policy materialisation, soft-reset
   on policy change, hard-reset on timer change, instance recreate on
   ASN/port/router-ID change, status writer with 5 s jittered patch.
4. Read APIs (peers / routes / route-policies) for the CLI.

The natural Rust boundary is exactly Cilium's `types.Router` trait, minus the
GoBGP leakage:

```
trait Speaker {                // one per BGP instance
  fn add_neighbor / update_neighbor / remove_neighbor / reset_neighbor
  fn advertise(Path) -> PathHandle / withdraw(PathHandle)
  fn set_export_policy(peer, Policy)      // replaces add/remove policy + global assignment
  fn peer_states() / routes(table, family, peer) / policies()
  fn stop(graceful: bool)
}
```

Two independent hard parts hide here: (a) the `Path` type must be our own
(prefix + attribute set), not a wire-codec type; (b) policy semantics must be
"first accept/reject wins, default reject", identical to GoBGP, or the txtar
expectations will not match.

### Rust BGP implementations (assessed as of mid-2026; verify before committing)

| Project | Kind | Speaker? | Policy | MD5 | GR | IPv6 / RFC 8950 | Communities | Notes |
|---|---|---|---|---|---|---|---|---|
| **holo-bgp** (holo-routing, MIT) | Full routing daemon (BGP, OSPF, IS-IS, RIP, LDP, BFD, VRRP, MPLS) | Yes: RFC 4271 FSM, active+passive, 4-byte ASN, route refresh | Yes, via YANG `ietf-routing-policy` (prefix/neighbor/community match, set local-pref/communities/next-hop) | Yes (TCP_MD5SIG via socket option; verify) | Partial/verify — GR was on the roadmap; check current status | IPv4+IPv6 unicast; RFC 8950 verify | Standard + large + extended | Most complete Rust speaker. **Embedding cost is high**: architecture is a daemon (`holod`) driven by a YANG northbound (libyang3 C bindings, `yang3` crate), gRPC/CLI; the BGP crate expects holo's `holo-utils`/`holo-northbound` runtime and does not expose a library API for programmatic paths. Realistic use is as a **sidecar daemon** configured over gRPC, not as an in-process crate. |
| **RustyBGP** (osrg/rustybgp, Apache-2.0; by the GoBGP author) | Speaker with GoBGP-compatible gRPC API | Yes: FSM, IPv4/IPv6 unicast, 4-byte ASN, route-server oriented | Partial (prefix/neighbor/community match, subset of GoBGP policy) | Verify (not in README) | No | Yes / verify ENH | Standard, large | Activity slowed since ~2022; reuses GoBGP protobufs, so the API surface is the gobgp one. Would give a drop-in for Cilium's gobgp layer but inherits its staleness. |
| **sartd / sart** (terassyi, Apache-2.0) | Kubernetes LB + CNI in Rust with its own BGP speaker | Yes: RFC 4271, MP-BGP IPv4/IPv6, gRPC API, k8s controller advertising LB IPs | Minimal (export what the controller says) | No | No | Yes | Basic | Purpose-built for the same use case (advertise pod/LB routes from k8s nodes). Small, readable; good design reference for a minimal speaker, not mature enough to depend on. |
| **zettabgp** (MIT) | Message codec | No (no FSM/session) | n/a | n/a | n/a | Parses many AFI/SAFI incl. EVPN, flowspec, VPN | Parses all community types | Solid wire codec; could supply the encoder/decoder for an own speaker. |
| **bgpkit-parser** (MIT) | MRT/BMP/BGP message parser | No | n/a | n/a | n/a | Parses | Parses | Analytics-oriented; parse-only, no serialisation of UPDATEs for sending. |
| **bgp-rs** (MIT) | Message codec | No | n/a | n/a | n/a | Basic | Basic | Older, low activity; superseded by zettabgp. |
| bird / FRR / GoBGP / OpenBGPD | External daemons (C / C / Go / C) | Yes, mature | Yes | Yes | Yes | Yes | Yes | Sidecar option; needs a config-rendering or API-driving backend. GoBGP has gRPC; FRR has vtysh/`mgmtd` and northbound gRPC (experimental); bird has a socket CLI and reloads config files; OpenBGPD is config-file + `bgpctl`. |

Honest summary: **no Rust crate today offers an embeddable, policy-capable,
GR-capable speaker as a library.** holo-bgp is the only feature-complete
speaker and is a daemon; RustyBGP is complete-ish but dormant; everything
else is a parser or a toy.

### The three options

1. **Embed a Rust speaker** — only holo-bgp qualifies, and only as a
   sidecar-style process (or a heavy fork to expose a library API). Pulls in
   libyang3, the holo runtime and its release cadence. Effort M to integrate,
   but it converts "our BGP bugs" into "someone else's daemon" and defeats the
   single-binary scratch-image model (see MikroTik build notes: scratch base,
   golden clones).
2. **Write our own minimal speaker** — RFC 4271 FSM (active + optional
   passive), RFC 4760 MP-BGP for ipv4/ipv6 unicast, RFC 6793 4-byte ASN, RFC
   2918 route refresh, RFC 4724 + 8538 graceful restart (restarting-speaker
   role only, as Cilium), RFC 8950 IPv4-over-IPv6 next hop, RFC 1997 / 8092
   communities, LOCAL_PREF, ORIGIN, AS_PATH prepend for eBGP, TCP MD5 via
   `setsockopt(TCP_MD5SIG)` (and optionally TCP-AO on >= 6.7 kernels, which
   would exceed Cilium). Export-only Loc-RIB (locally originated paths), per-peer
   adj-rib-out, an adj-rib-in kept purely for observability (received counts,
   `adj-rib-in` listing) with no best-path selection needed. No import policy
   engine, no route reflection, no confederations, no ADD-PATH. Wire codec can
   come from zettabgp or be hand-written (the attribute set is small). Estimate
   6-10k lines of Rust including tests; the GoBGP-facing tests in
   `pkg/bgp/test/testdata/*.txtar` translate directly into interop tests
   against a real GoBGP/bird/RouterOS peer.
3. **External daemon sidecar** (bird / FRR / GoBGP) — fastest path to full RFC
   coverage, but: second process and image, config-templating or gRPC glue
   (~2-3k lines), and an operational seam that Cilium deliberately avoided
   (they run GoBGP in-process so a sidecar restart does not double the GR
   windows). On a scratch-image fleet this also means shipping a C/Go daemon we
   do not build.

### flowsdn-specific: pluggable advertiser backend and RouterOS

On MikroTik fleets the RouterOS 7 router is already a BGP speaker. A node
therefore does not need to *speak* BGP at all to get its prefixes advertised;
it needs the **router's** routing table to contain `prefix -> node` entries
with the right attributes. That suggests splitting Cilium's single `Router`
trait into two:

```
trait Advertiser {            // what the reconcilers actually need
  fn ensure(prefix, attrs: {communities, large, local_pref, origin}) -> Handle
  fn withdraw(Handle)
  fn observed() -> Vec<AdvertisedPrefix>      // for status / CLI
}
trait Speaker: Advertiser {    // adds sessions; the in-process BGP backend
  fn add/update/remove/reset neighbor; fn peer_states()
}
```

Reconcilers (pod-cidr, service, pod-ip-pool, interface) target `Advertiser`;
only the neighbor / route-policy reconcilers and the status writer need
`Speaker`. Backends:

- **`bgp` backend**: our speaker; per-peer export policies are realised as
  adj-rib-out filters exactly as Cilium does (neighbor + prefix match ->
  accept + set attributes; default reject).
- **`routeros` backend**: talks to the router's REST API (`/rest/ip/route`,
  `/rest/ipv6/route`) and programs static routes `dst-address=<prefix>
  gateway=<node address> comment=flowsdn:<owner>:<resource>` (plus
  `routing-table` when VRFs are used). Attributes map onto RouterOS
  `/routing/filter/rule` chains that the router applies when redistributing
  connected/static into its BGP (`set bgp-communities`, `set
  bgp-local-pref`), or onto route `comment`/`bgp-*` fields where ROS7 exposes
  them. `peer_states()` is served by reading `/rest/routing/bgp/session` from
  the router so the CRD status stays meaningful. The "neighbor" reconciler
  becomes a validator that the router's BGP connection exists; timers, MD5 and
  GR are the router's business. Node-to-router auth uses the RouterOS API
  credential from a `Secret` in `--bgp-secrets-namespace`, reusing the same
  namespace-scoping rule.
- Selection: a `--bgp-backend bgp|routeros` flag (or per-`CiliumBGPPeerConfig`
  field `backend`) chosen by the node-config compiler; the RouterOS backend
  does not need `localASN`/`routerID` at all.

This keeps the CRD surface identical to Cilium's for the `bgp` backend and
makes the ROS backend an implementation detail of the same reconcilers. The
ECMP behaviour is unchanged: every node programs the same VIP with itself as
gateway, so the router ECMPs across nodes; `externalTrafficPolicy: Local`
still withdraws the node's route when it has no local backend.

### Risks / hard parts

- GR correctness (RFC 4724 + 8538) is the feature that makes agent restarts
  invisible; it is also the easiest to get subtly wrong (EOR marking after
  policies are installed — hence Cilium's reconciler ordering; stale-path
  timers; CEASE vs no-CEASE on stop).
- Timer negotiation (min of hold times, keepalive = hold/3) and the hard-reset
  semantics on config change must match or peers will see flapping.
- Policy statement naming and ordering leaks into `route-policies` CLI output
  and the txtar expectations; decide early whether to preserve them.
- Service reconciler is the largest piece (767 + 3,081 test lines): ETP/ITP,
  proxy redirects, aggregation priority, VIP sharing, no-endpoint flag, legacy
  origin. Port its tests first.
- Router-ID from `cilium_host` MAC and from an IP pool are both node-identity
  concerns; on IPv6-only fleets this is mandatory.

## Recommendation

**Keep the feature; replace GoBGP with an own minimal Rust speaker behind an
`Advertiser`/`Speaker` trait pair, and add a RouterOS `Advertiser` backend.**
BGP is the only north-south reachability mechanism Cilium offers that fits a
MikroTik-fronted fleet, and the Cilium implementation is export-only with a
small attribute set, so the RFC surface we must implement is genuinely small
(4271, 4760, 6793, 2918, 4724/8538, 8950, 1997/8092, 2385). Do not embed
holo-bgp (daemon architecture, libyang) or a sidecar (breaks the scratch
single-binary model). Defer BFD, ADD-PATH, non-unicast SAFIs and import policies.
Retain both BGP CRD versions and the REST compatibility surface required by
spec 15. Live registration and migration remain implementation work.

Effort: **L** (8-20k lines): ~6-10k speaker + codec + interop tests, ~8-12k
control plane (CRDs, operator compiler, seven reconcilers, status, CLI),
~1-2k RouterOS backend. Port the 20 txtar scenarios as the acceptance suite,
peering against GoBGP and against a RouterOS CHR in CI.

## Open questions

- Which peers will real deployments have — RouterOS only, or also
  FRR/bird/Arista? This decides whether the `bgp` backend is v1 or v2 work
  (RouterOS backend alone could ship first).
- Resolved #184: retain served deprecated `v2alpha1` alongside sole storage
  `v2` for all five BGP CRDs (spec 15 O-2; spec 13 §12.2). Live migration
  remains unimplemented.
- TCP-AO (RFC 5925, Linux 6.7+): worth adding beyond Cilium's MD5-only
  support, given the fleet kernel version?
- Passive sessions: Cilium requires `localPort` for inbound; do we want a
  passive-only mode for routers that insist on initiating?
- Should advertised prefixes and installed policies be added to
  `CiliumBGPNodeConfig.status` (Cilium exposes them only via the agent API)?
  Useful for a RouterOS backend where the node has no local RIB to query.
- Policy naming (`peer-<name>-export`, `<Type>-<resource>-ipv4`): preserve
  for CLI parity or simplify?
- `CiliumBGPNodeConfigOverride.peers[].localPort` is a dead field in Cilium —
  drop it or implement it?
- ClusterIP advertisement depends on `bpf.lbExternalClusterIP` in the
  datapath inventory; confirm the flowsdn datapath will support external
  traffic to ClusterIPs before exposing that address type.
