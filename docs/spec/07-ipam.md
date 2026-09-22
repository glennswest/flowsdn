# IPAM — specification (all modes, cloud modes complete)

Status: draft. Derived from: `docs/inventory/07-ipam-cloud.md`,
`docs/inventory/13-crds-k8s.md` (CiliumNode / CiliumPodIPPool schemas),
`docs/inventory/08-operator.md` (binary layout, leader lifecycle, node GC);
reference cilium v1.20.1 (7d68cfb394) paths `pkg/ipam/**` (`ipam.go`,
`allocator.go`, `types.go`, `hostscope.go`, `pool.go`, `multipool.go`,
`multipool_manager.go`, `eni.go`, `crd.go`, `noop_allocator.go`, `option/`,
`types/`, `metadata/`, `podippool/`, `service/ipallocator`, `service/allocator`,
`cidrset/`, `cell/`, `api/`), `pkg/aws/{api,ipam,ipam/limits,metadata,types}`,
`pkg/azure/{api,ipam,metadata,types,types/azureid}`,
`pkg/alibabacloud/{api,ipam,ipam/limits,metadata,types}`,
`pkg/nodediscovery/{eni,nodediscovery_eni.go,nodediscovery_azure.go,nodediscovery_alibabacloud.go,cell.go}`,
`pkg/datapath/linux/routing/{routing.go,info.go}`, `pkg/datapath/linux/linux_defaults`,
`operator/pkg/ipam/**` (`cell.go`, `aws.go`, `azure.go`, `alibabacloud.go`,
`clusterpool.go`, `multipool.go`, `cloud_allocator.go`, `nodewatcher.go`,
`nodemanager/{node.go,node_manager.go}`, `allocator/{aws,azure,alibabacloud,clusterpool,podcidr,multipool}`,
`metrics/metrics.go`), `operator/watchers/cilium_node_gc*.go`,
`pkg/api/helpers/rate_limit.go`, `pkg/api/metrics/metrics.go`,
`daemon/infraendpoints/infra_ip_allocation.go`, `plugins/cilium-cni/cmd/{interface.go,cmd.go}`,
`api/v1/openapi.yaml` (`/ipam*`), `install/kubernetes/cilium/{values.yaml,templates/cilium-configmap.yaml}`,
`Documentation/network/concepts/ipam/*.rst`. Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* flowsdn does and the exact data it exchanges; it does not transcribe
reference code. Where reference behavior is kept for compatibility the consumer
is named (cilium-dbg, CNI plugin, Helm, a Cilium operator or agent of the other
implementation during migration, Hubble). Where flowsdn deviates the paragraph
is marked **DEVIATION** with the reason and the ADR.

**Amendments.** 2026-09-07 — §9 rewritten for **ADR-0007** (recorded-response
cloud fakes): the `F` lane is redefined from hand-written in-memory API servers
to replayed real provider responses, and §9.1 states the fixture layout,
scrubbing rule, replay layer and mandatory scenario list.

## 1. Scope

In scope:

- The agent-side IP allocator: the `Allocator` interface, owner bookkeeping,
  excluded IPs, expiration timers, restore, dump, pool selection for a pod, and
  the agent REST `/ipam` endpoints the CNI plugin and `cilium-dbg` call.
- Every IPAM mode, normatively: `kubernetes`, `cluster-pool`, `multi-pool`,
  `crd`, `delegated-plugin`, `eni` (AWS), `azure`, `alibabacloud`, and the GKE
  arrangement (which is `kubernetes` plus datapath settings).
- The `CiliumNode` IPAM schema (`spec.ipam`, `status.ipam`, `spec.eni`/`status.eni`,
  `spec.azure`/`status.azure`, `spec.alibaba-cloud`/`status.alibaba-cloud`) field by
  field with the writer of each field, and the `CiliumPodIPPool` CRD.
- The operator node manager shared by the cloud modes: watermarks, resync,
  workers, rate limiting, release scheduling, the excess-IP release handshake
  (Azure, Alibaba) and the CIDR-based release (ENI), ENI garbage collection,
  CiliumNode garbage collection, cluster-pool and multi-pool operator allocators,
  cluster-pool → multi-pool migration.
- The per-endpoint policy-routing state (ip rules, per-interface route tables,
  ENI device configuration, `rp_filter`) that cloud IPAM requires.
- Cloud API clients: EC2, Azure ARM (network + compute), Alibaba ECS/VPC, and the
  three instance-metadata services.

Out of scope (sibling specs): the CNI plugin binary itself and the veth/endpoint
creation flow (`09-cni-plugin`; it consumes section 3.2 and 3.20 here); the
endpoint state machine and the endpoint REST API (`08-endpoint-agent-api`); node
routes, `cilium_host`, device management, the nftables residual including the
ENI `ct mark 0x80` rule (`10-node-routing-nftables`); BPF masquerade and the
`ParentInterfaceIndex` consumer in the datapath (`02-datapath-programs`,
`04-conntrack-nat`); LB-IPAM and Node-IPAM (`05-service-loadbalancing`); BGP
advertisement of `CiliumPodIPPool` (BGP spec); Helm value → key mapping
(Helm spec) beyond the keys named in section 6.

## 2. Compatibility contract

| Interface | MUST match | Consumer |
|---|---|---|
| `--ipam` values `kubernetes`, `crd`, `eni`, `azure`, `cluster-pool`, `multi-pool`, `alibabacloud`, `delegated-plugin` | byte-identical | Helm `ipam.mode`, operator reading the agent ConfigMap |
| `CiliumNode` (`cilium.io/v2`) `spec.ipam.*`, `status.ipam.*`, `spec.eni`/`status.eni`, `spec.azure`/`status.azure`, `spec.alibaba-cloud`/`status.alibaba-cloud` | JSON field names, types, `omitempty`/`omitzero` presence rules and write ownership of section 4.1 | Cilium agents/operators of the other implementation in a mixed cluster during migration, `kubectl`, `cilium-dbg` |
| `CiliumPodIPPool` (`cilium.io/v2alpha1`) | schema of section 4.2, including immutability of `maskSize`, `allowFirstIP`, `allowLastIP` | users, BGP advertisement, operator |
| `status.ipam.release-ips` values `marked-for-release`, `ready-for-release`, `do-not-release`, `released` | strings and transitions of 3.13 | Azure/Alibaba agent↔operator protocol |
| Pod/Namespace annotations `ipam.cilium.io/ip-pool`, `ipam.cilium.io/ipv4-pool`, `ipam.cilium.io/ipv6-pool`, `ipam.cilium.io/require-pool-match`; CiliumNode annotation `ipam.cilium.io/ignore`; CiliumPodIPPool annotation `ipam.cilium.io/skip-masquerade` | names and precedence of 3.3 | users |
| Agent REST `POST /ipam`, `POST /ipam/{ip}`, `DELETE /ipam/{ip}` with parameters `family`, `owner`, `pool`, header `expiration`; models `IPAMResponse`, `IPAMAddressResponse`, `AddressPair`, `NodeAddressing`; status codes of 3.2 | OpenAPI-identical | CNI plugin, `cilium-dbg ipam` |
| ip rule priorities 20 (ingress), 110 (compat egress, Azure), 111 (egress v2, ENI/Alibaba), 109 (nodeport, owned by routing spec); route table id `10 + interface number` (ENI/Alibaba) or `ifindex` (Azure); routes installed with `RTPROT_KERNEL` | exact values | coexistence with Cilium-installed rules on a node during upgrade; egress gateway spec relies on ordering |
| ENI tags `io.cilium/cilium-managed=true`, `io.cilium/cluster-name=<name>`; ENI description `Cilium-CNI (<instance-id>)`; Alibaba ENI tag `cilium-eni-index` | exact strings | ENI GC across implementations, operators, humans |
| Config keys of section 6 | names and defaults | Helm ConfigMap, `CiliumNodeConfig` |
| Metric names of section 8 | names and labels | dashboards |
| Cloud API call sets of 3.9–3.11 (the IAM/RBAC/RAM permissions they imply) | same calls, so existing IAM policies work | cluster operators |

Everything else — internal traits, table layout, timers not listed above — is
internal to flowsdn.

## 3. Behavior

### 3.1 Agent allocator core

The agent holds at most one allocator per address family, selected once at
startup by `--ipam` (table below). Allocators are created only for enabled
families (`enable-ipv4`, `enable-ipv6`).

| `--ipam` | IPv4/IPv6 allocator | Source of addresses |
|---|---|---|
| `kubernetes`, `cluster-pool` | host-scope bitmap over one prefix | `LocalNode.IPv{4,6}AllocCIDR` (3.4, 3.5) |
| `multi-pool` | multi-pool manager (3.6) reading `spec.ipam.pools.allocated` | operator |
| `eni` | multi-pool manager with the ENI pool accessor (3.9) | operator via `status.eni.enis` |
| `crd`, `azure`, `alibabacloud` | CRD per-IP allocator (3.7, 3.13) over `spec.ipam.pool` / `spec.ipam.ipv6-pool` | operator or external writer |
| `delegated-plugin` | no-op allocator; every operation fails with "not supported" | delegated CNI plugin |

The allocator interface (one per family) is:

| Operation | Semantics |
|---|---|
| `allocate(addr, owner, pool)` | reserve a specific address; error if not in range / already allocated / not available. Triggers upstream sync (CiliumNode write) in modes that have one. |
| `allocate_without_sync(addr, owner, pool)` | as above without triggering upstream sync (restore path, infra IPs). |
| `allocate_next(owner, pool)` / `allocate_next_without_sync` | reserve any free address from `pool`. |
| `release(addr, pool)` | free the address; releasing an unallocated address is not an error for bitmap modes, is an error for the CRD allocator. |
| `dump()` | `map[pool] → map[ip] → owner` plus a one-line status string. |
| `capacity()` | total allocatable addresses (not free). |
| `restore_finished()` | endpoint restore is complete; modes that defer upstream writes until then start them. |

Around the per-family allocators the core MUST:

1. Track the owner of every allocated IP per `(pool, ip)` and expose it through
   `dump()`; the owner string is the value the CNI passed (`<namespace>/<pod>` or
   an infra name such as `router`, `health`, `ingress`).
2. Resolve an empty `pool` argument by 3.3 (`allocate_next`) or reject it
   (`allocate`, `release`: "pool name must be provided"). An allocator that does
   not know pools returns an empty pool name; the core then reports the pool as
   `default`.
3. Keep an **excluded IP** set keyed `pool:ip` (`exclude_ip(ip, owner, pool)`,
   used for the router IP and other infra addresses that must never be handed
   to a pod). `allocate` of an excluded IP fails with "IP is excluded, owned by
   <owner>". `allocate_next` that yields an excluded IP MUST keep the excluded
   IP allocated (owner `<owner> (excluded)`) and try again until a non-excluded
   IP is found or the allocator is exhausted.
4. `allocate_next(family="")` allocates IPv6 first, then IPv4, and MUST release
   the IPv6 result if IPv4 allocation fails.
5. Maintain **expiration timers** (3.17).
6. On endpoint deletion (subscription from the endpoint manager) release the
   endpoint's IPv4 and IPv6 with the pool names recorded on the endpoint unless
   the delete request carries `NoIPRelease` (set for `delegated-plugin` and CNI
   chaining, where an external IPAM owns the IP).
7. Update the capacity gauge on every allocate/release (section 8).

Mutual exclusion: one lock covers owner map, excluded set and timers; the
allocators are internally synchronized.

### 3.2 Agent REST endpoints (consumed by the CNI plugin and `cilium-dbg`)

Unix socket, same API as the rest of the agent (spec 08). Parameters are
`family` (query, enum `ipv4|ipv6`, empty = both), `owner` (query string),
`pool` (query string, empty = resolve by 3.3), `expiration` (header boolean),
`ip` (path).

| Method / path | Behavior | Responses |
|---|---|---|
| `POST /ipam` | `allocate_next` for the requested family(ies); if `expiration: true` start a 10 min (`IPAMExpiration`) timer per allocated IP and return its UUID. Fill `host-addressing` from the local node: per enabled family `{enabled, ip=<CiliumInternalIP>, alloc-range=<IPvXAllocCIDR>}`. | `201` `IPAMResponse`; `502` `Error` on allocation failure; `403` forbidden |
| `POST /ipam/{ip}` | `allocate(ip, owner, pool)` (restore / static request). | `200`; `400` invalid IP; `409` already allocated; `500` other failure (`Error`); `501` family disabled. The reference returns `500` for all failures after parsing; flowsdn SHOULD map already-allocated → `409` and disabled family → `501` |
| `DELETE /ipam/{ip}` | refuse if any local endpoint still uses `ip` ("IP is in use by endpoint <id>"); else `release(ip, pool)`. | `200`; `400` invalid IP; `404` not found; `500` failure |

Response models (field names are the wire contract):

```
IPAMResponse        { address: AddressPair, ipv4?: IPAMAddressResponse,
                      ipv6?: IPAMAddressResponse, host-addressing: NodeAddressing }
AddressPair         { ipv4, ipv4-pool-name, ipv4-expiration-uuid,
                      ipv6, ipv6-pool-name, ipv6-expiration-uuid }   (all strings)
IPAMAddressResponse { ip, gateway, cidrs: [string], master-mac, expiration-uuid,
                      interface-number, skip-masquerade: bool }
NodeAddressing      { ipv4?: NodeAddressingElement, ipv6?: NodeAddressingElement }
NodeAddressingElement { enabled: bool, ip, alloc-range, address-type }
```

`IPAMAddressResponse` is the wire form of the internal `AllocationResult`
(4.3). `gateway`, `master-mac`, `cidrs`, `interface-number` are empty except in
ENI/Azure/Alibaba modes; the CNI plugin treats an empty `gateway` as "no
per-endpoint routing needed".

### 3.3 Pool selection for a pod (`multi-pool` only; other modes always `default`)

Given an owner string and a family, the pool is determined in this order; the
first hit wins:

1. Owner not of the form `<namespace>/<name>` (both DNS-1123 subdomains) → `default`.
2. Pod annotation `ipam.cilium.io/ipv4-pool` (for IPv4) / `ipam.cilium.io/ipv6-pool`
   (for IPv6), else pod annotation `ipam.cilium.io/ip-pool`.
3. The same two annotations on the pod's Namespace.
4. `CiliumPodIPPool` selectors: a pool matches when it has the requested family
   (`spec.ipv4` / `spec.ipv6` present), it has at least one selector, its
   `podSelector` (if present) matches the pod labels plus synthetic labels
   `io.kubernetes.pod.namespace=<ns>` and `io.kubernetes.pod.name=<name>`, and
   its `namespaceSelector` (if present) matches the Namespace labels. Exactly
   one match → that pool. More than one → allocation fails with an error naming
   the matches (and a warning log). Zero → step 5.
5. If the pod or its Namespace carries `ipam.cilium.io/require-pool-match: "true"`
   → fail ("no matching CiliumPodIPPool ... require-pool-match"); else
   `--ipam-default-ip-pool` (default `default`).

The Pod and Namespace MUST be present in the agent's local pod/namespace tables
(spec 00 tables `k8s-pods`, `k8s-namespaces`); a missing Pod or Namespace is an
error ("resource Pod/Namespace not found"), which the CNI retries. Selection
MUST fail with "pools not synced" until the initial `CiliumPodIPPool` list has
been received. Pools whose selector fails to compile are ignored (logged).

### 3.4 `kubernetes` (host scope)

- Kubelet / kube-controller-manager assign `Node.spec.podCIDRs`. The agent reads
  them (node discovery, spec 03/10) into `LocalNode.IPv4AllocCIDR` /
  `IPv6AllocCIDR`; the operator does nothing for IPAM.
- `--ipv4-range` / `--ipv6-range` (default `auto`) override the alloc CIDR. With
  `auto` and no k8s CIDR, the agent derives a default: IPv4 `10.<x>.0.0/16`
  where `<x>` is the last byte of the node IPv4 (or byte 11 of the IPv6 alloc
  CIDR if only that is known); IPv6 `<ipv6-cluster-alloc-cidr-base><4 bytes of
  the IPv4 alloc CIDR or of the node IPv6>::/96`. Missing CIDR for an enabled
  family is fatal ("Please specify --ipv4-range").
- `--k8s-require-ipv4-pod-cidr` / `--k8s-require-ipv6-pod-cidr` (false): fail
  startup if the Node has no CIDR of that family.
- The allocator is a bitmap over the alloc CIDR excluding network and broadcast
  addresses for prefixes larger than 2 addresses (5.5). Capacity gauge carries
  the CIDR as label.
- Dual-stack: one bitmap per family over the corresponding CIDR; only the first
  CIDR of each family is used.

### 3.5 `cluster-pool` (default)

Operator:

- Config `--cluster-pool-ipv4-cidr` (list), `--cluster-pool-ipv4-mask-size`
  (24), `--cluster-pool-ipv6-cidr` (list), `--cluster-pool-ipv6-mask-size`
  (112). Validation at start: a family that is enabled MUST have at least one
  CIDR ("cluster-pool-ipv4-cidr must be provided when using ClusterPool"); a
  family that is disabled MUST NOT have CIDRs; a mask size larger than the
  family's address length or smaller than the cluster prefix length is fatal;
  the node mask MUST NOT be more than 16 bits longer than its cluster prefix
  (bitmap limit, 5.4).
- One CIDR-set per cluster CIDR (5.4). Per node the operator allocates the first
  free node CIDR from the first non-full set of each enabled family, writes them
  into `spec.ipam.podCIDRs` (IPv4 entries first, then IPv6) and clears
  `status.ipam.operator-status.error`.
- Startup: nodes are upserted into a pending map until the CiliumNode list has
  synced (`Resync`); only then are nodes without CIDRs allocated, so a CIDR
  already used by a node not yet seen cannot be handed out twice. Existing
  `spec.ipam.podCIDRs` are **occupied** in the sets first; a CIDR that is
  already occupied by another node is stripped from this node's spec (warning),
  the other family is kept, and the error is written to `operator-status.error`.
- Writes are batched: a per-node op (`create`, `update`, `update-status`,
  `delete`) is queued and flushed by a trigger plus a 15 s interval controller
  (`update-cilium-nodes-pod-cidr`). On conflict the operator re-fetches the
  node, re-applies `spec.ipam.podCIDRs`, owner references and
  `operator-status.error`, and retries on the next run. `NotFound` ends the
  retry (the delete event will arrive).
- CiliumNode deletion releases the node's CIDRs back to the sets.
- Exhaustion: `allocateNext` fails with "allocator full" (all sets full) or "no
  allocators" (no set for any enabled family); the error text is written to
  `status.ipam.operator-status.error` and retried on every resync; the node
  keeps no CIDR and its agent stays in "Waiting for IPs" (3.1 fence
  `ipam-configured` never completes; agent readiness fails).

Agent:

- Same host-scope bitmap as 3.4 over the first IPv4 and first IPv6 entry of
  `spec.ipam.podCIDRs`, mirrored into `LocalNode.IPv{4,6}AllocCIDR` and
  `IPv{4,6}SecondaryAllocCIDRs` (remaining entries) by the CiliumNode observer.
  The agent MUST block IPAM configuration until its CiliumNode carries a CIDR
  for every enabled family (logging "Waiting for ..." every 5 s).
- `status.ipam.pod-cidrs{}.status` (`released|depleted|in-use`) exists in the
  schema; **no component writes it at v1.20.1**. flowsdn MUST accept it and
  MUST NOT write it.
- Helm `nativeRoutingCIDRFromClusterPool` (a Helm-only derivation of
  `ipv4-native-routing-cidr` from a single cluster CIDR) is handled by the Helm
  spec.

### 3.6 `multi-pool`

Cluster-wide pools are `CiliumPodIPPool` objects (4.2). The operator carves
per-node CIDRs of `maskSize` out of each pool; the agent requests addresses per
pool and allocates single IPs locally from the CIDRs it was given.

Operator (`PoolAllocator` + `NodeHandler`):

- Watches `CiliumPodIPPool`: upsert → `UpsertPool(name, v4 cidrs, v4 mask, v6
  cidrs, v6 mask, allowFirstIP, allowLastIP)`; delete → `DeletePool`. Changing
  `maskSize`, `allowFirstIP` or `allowLastIP` of an existing pool is rejected
  (the CRD also forbids it with CEL). Removing a cluster CIDR from a pool while
  nodes still hold node-CIDRs in it marks those node-CIDRs **orphans**: they stay
  allocated to the node, are still reported in `allocated`, but no new CIDRs come
  from that range. Deleting a pool orphans all its node CIDRs the same way.
  Orphans are re-adopted when a pool covering them reappears.
- `--auto-create-cilium-pod-ip-pools` (map `pool=spec`) creates pools at start
  with spec syntax
  `ipv4-cidrs:<cidr>[,<cidr>];ipv4-mask-size:<n>[;ipv6-cidrs:...;ipv6-mask-size:<n>][;allow-first-ip:<bool>][;allow-last-ip:<bool>]`
  (spaces stripped). Existing pools are never updated ("Found existing
  CiliumPodIPPool resource. Skipping creation").
- Start order: (1) auto-create pools, (2) optionally migrate cluster-pool nodes
  (below), (3) sync all pools, (4) watch CiliumNodes. Before the CiliumNode list
  has synced every node's `allocated` CIDRs are occupied only; allocation
  starts after `Resync` (`ErrAllocatorNotReady` until then).
- Per node, on every CiliumNode event, a per-node retrying controller runs
  `AllocateToNode(node, pools)`:
  1. Occupy every CIDR in `spec.ipam.pools.allocated`; a CIDR whose pool is
     unknown becomes an orphan and produces an error.
  2. Release any CIDR this node held that is no longer in `allocated` (agent
     released it).
  3. For each `requested[]` entry and enabled family: `toAllocate =
     needed.ipv{4,6}-addrs − usable addresses already allocated to the node from
     that pool` (usable = per node-CIDR `2^(bits) − (allowFirstIP?0:1) −
     (allowLastIP?0:1)` for prefixes with > 2 addresses); while `toAllocate >
     0` allocate the next node-CIDR from the first non-full cluster CIDR of the
     pool and subtract its usable count. Pool empty → error "pool empty".
  4. Write `spec.ipam.pools.allocated = AllocatedPools(node)` (nodes' CIDRs
     plus orphans, sorted by pool name, CIDRs sorted, IPv4 before IPv6, with
     the pool's `allowFirstIP`/`allowLastIP`) via `Update` when changed; write
     `status.ipam.operator-status.error` (`"ipam-multi-pool-sync allocation
     failed: <err>"` or empty) via `UpdateStatus` when changed. On `Conflict`
     re-fetch the node before the next run.
- CiliumNode deletion releases all node CIDRs and stops the controller.
- Cluster-pool → multi-pool migration (`--enable-cluster-pool-to-multi-pool-migration`,
  `--multi-pool-migration-workers` 16): for every CiliumNode with
  `spec.ipam.podCIDRs`, move them into `spec.ipam.pools.allocated[{pool:
  <--ipam-default-ip-pool>, cidrs}]` and clear `podCIDRs`, with exponential
  retry on conflict (10 ms, ×2.5, 10 steps); failures are written to
  `operator-status.error` as `"migration to multi-pool IPAM failed: <err>"`.
  Node allocation starts only after migration finished.

Agent (`multiPoolManager`):

- `--ipam-multi-pool-pre-allocation` (map `pool=count`, default `default=8`
  when empty). Startup waits, per pool with non-zero pre-allocation, until the
  pool exists in the local `CiliumPodIPPool` table (up to 1 m, then proceeds)
  and until the pool has at least one free IP for every enabled family (retry
  every 3 m, forever, logging every 5 s "Waiting for cidr pool to become
  available ... Check if cilium-operator pod is running"). Then it waits for
  the first successful CiliumNode write and for the local-node alloc-CIDR
  observer to have processed one CiliumNode event (fatal after 5 m).
- Pools are mirrored from `spec.ipam.pools.allocated`: per pool one CIDR-list
  allocator per family (5.6) with the pool's `allowFirstIP`/`allowLastIP`;
  changing those flags on a pool with in-use IPs is ignored with a warning.
- Demand (5.2): per pool `needed = neededIPCeil(inUse + pending, preAlloc)`.
  **Pending** allocations are `allocate_next`/`allocate` calls that failed
  because the pool was absent or exhausted, keyed by owner and family, expiring
  after 5 m; each pending owner adds one to demand until fulfilled.
- Every `--ipam-cilium-node-update-rate` (15 s, debounced trigger) and at least
  every 1 m the agent recomputes demand, releases excess CIDRs (5.7) once
  restore has finished for the family, and writes `spec.ipam.pools.requested`
  (pools with non-zero demand, sorted) and `spec.ipam.pools.allocated` (in-use
  CIDRs, sorted; pools with no CIDR left are dropped) with `Update`. Before the
  CiliumNode informer has synced, `allocated` is carried over unchanged so a
  restarting agent never clears CIDRs it may still be using. `Conflict` is
  retried on the next run.
- If `status.ipam.used` is non-empty (left by a previous CRD-allocator agent)
  the agent clears it with `UpdateStatus` (operator detection of multi-pool
  agents, 3.9).
- `AllocationResult.SkipMasquerade` is set when `--only-masquerade-default-pool`
  (requires `enable-bpf-masquerade`) and the pool is not `default`, or when the
  `CiliumPodIPPool` carries annotation `ipam.cilium.io/skip-masquerade: "true"`.
  A pool missing from the local pool table is an allocation error (and counts as
  pending). Consumer: BPF masquerade (spec 04) and the endpoint's datapath config.
- Removed-in-use CIDRs: a CIDR that disappears from `allocated` while IPs are
  still allocated from it is kept (no new allocations, error log "in-use CIDR
  was removed from spec") and keeps being reported so the operator can
  re-adopt it.
- Local node store: `IPv4AllocCIDR` = first IPv4 CIDR of the `default` pool
  (or the first pool), the rest `IPv4SecondaryAllocCIDRs`; same for IPv6.

### 3.7 `crd`

- An external writer (user or controller) maintains `spec.ipam.pool` (IPv4) and
  `spec.ipam.ipv6-pool` (IPv6): `map[ip] → {owner?, resource?}`. The agent MUST
  NOT write those fields. The agent writes `status.ipam.used` /
  `status.ipam.ipv6-used` (allocated IPs with `owner` set) via `UpdateStatus`,
  rate limited by `--ipam-cilium-node-update-rate` (15 s), first write after
  restore finished.
- Startup gate: the agent waits (5 s polls, forever) until
  `len(spec.ipam.pool) ≥ required` where `required = spec.ipam.min-allocate` if
  non-zero, else `spec.ipam.pre-allocate` if non-zero, else 2 if endpoint
  health checking is enabled, else 1; and, if `spec.ipam.static-ip-tags` is
  set, until `status.ipam.assigned-static-ip` is non-empty.
- `allocate_next`: in `crd` mode only, an entry whose `owner` equals the
  requesting owner is a **pinned IP** and is returned first (family must
  match). Otherwise the first entry (map order, unspecified) of the right family
  that is not allocated, has empty `owner`, and is not in the release handshake
  (3.13) is chosen. Exhaustion error text: "no IPs currently available on the
  node, allocation will be retried once IPs are added to CiliumNode
  spec.ipam.pool".
- `allocate(ip)`: the IP MUST be in the pool and not in the handshake.
- `dump()` reports `<used>/<pool size> allocated`; `capacity()` is the pool size
  of the family.

### 3.8 `delegated-plugin`

- The CNI plugin invokes the delegated IPAM plugin (CNI spec §4); the agent's
  allocator is a no-op that fails every operation with "not supported". The
  endpoint is created with `ExternalIpam=true` so deletion does not release.
- Startup validation (fatal): `--local-router-ipv4` (and `-ipv6` if enabled)
  MUST be set; `enable-endpoint-health-checking` MUST be false;
  `enable-envoy-config` MUST be false; native routing is required (spec 00 §6
  validation table also requires `enable-endpoint-routes`).
- `--install-uplink-routes-for-delegated-ipam` (false): the CNI installs the
  per-endpoint rules/routes of 3.20 with interface number `0` and the gateway
  from the delegated result.
- Masquerade MUST be BPF masquerade with `ip-masq-agent` CIDRs (there is no pod
  CIDR); ADR-0003 already removes the iptables alternative.

### 3.9 `eni` (AWS) — the v1.20 design

**DEVIATION (scope, inventory 07 recommendation, ADR-0001 "compatible at the
boundaries"):** flowsdn implements only the v1.20 ENI protocol: the agent uses
the multi-pool manager with the ENI pool accessor and signals demand through
`spec.ipam.pools.requested`; the operator provisions IPs/prefixes/ENIs and
releases by CIDR. The v1.19 per-IP path (agent CRD allocator over
`spec.ipam.pool`, `status.ipam.used`, four-state `release-ips` handshake on
ENI) is **not implemented on either side**. A flowsdn operator that observes a
node with non-empty `status.ipam.used` and no `requested` entry for `default`
MUST NOT allocate for it and MUST write
`status.ipam.operator-status.error = "agent uses the pre-1.20 ENI protocol; upgrade the agent"`.
A flowsdn agent MUST clear a stale `status.ipam.used` (3.6) so a Cilium 1.20
operator detects it as multi-pool. Mixed clusters with Cilium ≥ 1.20 on the
other side are supported; Cilium 1.19 is not.

#### 3.9.1 Agent

- Node discovery seeds `spec.instance-id` and `spec.eni` from IMDS + flags before
  the CiliumNode is created (4.1). IMDS fields: `instance-id`, `instance-type`,
  `placement/availability-zone`, `mac`, `network/interfaces/macs/<mac>/vpc-id`,
  `.../subnet-id`. The CNI custom netconf (`cni.customConf`, `ipam.{min-allocate,
  pre-allocate}` and `eni.*`) overrides the flags field by field
  (`delete-on-termination` is taken from the netconf unconditionally when a
  netconf exists).
- Pools: exactly one pool, `default`, with `allowFirstIP=allowLastIP=true`,
  pre-allocation `8` (`IPAMPreAllocation`), overridden by `spec.ipam.pre-allocate`
  when > 0 (the operator sets it, 3.15). The pool's CIDRs are **derived from
  `status.eni.enis`**, not read from `spec.ipam.pools.allocated`: for every ENI
  not excluded by `spec.eni.exclude-interface-tags` and with `number ≥
  first-interface-index`: every `prefixes[]` entry (/28), every
  `ipv6-prefixes[]` entry (/80), and every `addresses[]` entry not covered by
  one of the ENI's prefixes as a /32 (or /128). The agent writes the derived
  list into `spec.ipam.pools.allocated` (it is the sole writer of that field in
  ENI mode) and its demand into `spec.ipam.pools.requested`.
- Demand is **linear**: `needed = inUse + pending + preAlloc` (no rounding), so
  the operator can recover usage as `requested − preAlloc`.
- Startup waits: first successful CiliumNode write; alloc-CIDR observer; and the
  VPC primary CIDR in `status.eni.enis[*].vpc.primary-cidr` (fatal after 5 m,
  logging every 5 s). Native routing CIDR: if `--ipv4-native-routing-cidr` is
  unset, `LocalNode.IPv4NativeRoutingCIDR = VPC primary CIDR`; if set, it MUST
  overlap the VPC primary CIDR (subnet or supernet), otherwise fatal
  "Configured native routing CIDR does not overlap VPC CIDR".
- Static IP: if `spec.ipam.static-ip-tags` is set, block until
  `status.ipam.assigned-static-ip` is set (log every 5 s).
- `AllocationResult` enrichment for an allocated IP: find the ENI whose primary
  IP, `addresses[]` or a prefix contains it (error, and release the reservation,
  if none): `PrimaryMAC = eni.mac`; `CIDRs = [vpc.primary-cidr] + vpc.cidrs +
  [ipv4-native-routing-cidr if IPv4 enabled] + [ipv6-native-routing-cidr if IPv6
  enabled] + ip-masq-agent non-masquerade CIDRs of the same family (if
  `enable-ip-masq-agent`)`; `GatewayIP = subnet.cidr first address + 1` for
  IPv4, `fe80:ec2::1` for IPv6; `InterfaceNumber = eni.number`.
- ENI device configuration (agent-side, per new ENI seen in status, skipped for
  excluded ENIs, only when all ENIs in status have primary IP, subnet CIDR and
  VPC primary CIDR set): wait for a link with the ENI's MAC (15 tries, 100 ms →
  30 s exponential), sleep 1 s and re-fetch (udev renames `eth1`→`ensX`), then:
  set MTU to the device MTU, link up; unless `spec.eni.use-primary-address` is
  true: add `<eni.ip>/<subnet bits>` to the link (EEXIST ok), delete the
  `scope link` subnet route `dst=<subnet> src=<eni.ip> table main` if one
  exists (systemd-networkd artifact), and set `net.ipv4.conf.<dev>.rp_filter=0`.
  Failures are logged, not fatal.
- Masquerade datapath: the CNI passes `ParentInterfaceIndex` (ifindex of
  `master-mac`) to the endpoint so replies leave via the pod's ENI (spec 04).

#### 3.9.2 Operator — provider bootstrap

- Credentials and region: AWS default credential chain (env, shared config,
  IRSA web identity via `AWS_WEB_IDENTITY_TOKEN_FILE`/`AWS_ROLE_ARN`, IMDS
  instance role); region from the IMDS instance identity document. The SDK's
  own client-side rate limiter MUST be disabled (flowsdn's limiter of 3.15 is
  the only one). `--ec2-api-endpoint <host>` sets the base endpoint
  `https://<host>`.
- Instance filters: `--instance-tags-filter` (map) → `tag:<k>=<v>` filters on
  `DescribeInstances`; `--subnet-ids-filter`, `--subnet-tags-filter` → filters
  on `DescribeSubnets` (and the `subnet-id` filter is reused for ENI GC).
  `--aws-max-results-per-call` (0): page size for `DescribeNetworkInterfaces`;
  on `OperationNotPermitted` with page size 0 the client MUST switch to 1000 for
  the rest of its life and retry (one warning when switching). An explicit
  nonzero page size MUST NOT be overwritten by this heuristic (ADR-0012 #108).
- ENI creation tags = `--eni-tags` merged with the GC tags (GC tags win). GC
  tags = `--eni-gc-tags` if set, else `{io.cilium/cilium-managed: "true",
  io.cilium/cluster-name: <name>}` where `<name>` is `--cluster-name` if not
  `default`, else the instance tag `aws:eks:cluster-name` of the operator's own
  instance (`DescribeTags`), else the literal `default` (with the warning that
  the operator may GC other clusters' ENIs).
- Limits: `DescribeInstanceTypes` (paginated) at start (fatal if it fails after
  2 retries of 5 s each) into `{Adapters=MaximumNetworkInterfaces,
  IPv4=Ipv4AddressesPerInterface, IPv6=Ipv6AddressesPerInterface,
  HypervisorType, IsBareMetal}` per instance type. A lookup miss triggers a
  refresh (min interval 1 m) and waits up to 5.5 s for it; misses within the
  minimum interval return "not found" immediately. There is no embedded limits
  table.
- Instances manager cache (full resync every 1 m and at start, blocking):
  VPCs (`DescribeVpcs`, own VPC id from IMDS when available), subnets
  (`DescribeSubnets` incl. `AvailableIpAddressCount`, tags, AZ), security groups
  (`DescribeSecurityGroups`), route tables (`DescribeRouteTables` → subnet
  associations), then all instances' ENIs (`DescribeInstances` with instance
  filters when set, else `DescribeNetworkInterfaces` with subnet filters;
  paginated). Per-instance incremental sync (`DescribeNetworkInterfaces`
  filtered by `attachment.instance-id`) runs in parallel across nodes and MUST
  be excluded against the full resync (RW lock). Parsing an ENI: `id, ip
  (primary), mac, availability-zone, description, number (attachment
  DeviceIndex), subnet{id,cidr}, vpc{id,primary-cidr,cidrs}, addresses (all
  secondary private IPs; the primary only when `--aws-use-primary-address`),
  prefixes (/28 list; **each prefix is also expanded to its 16 addresses and
  appended to `addresses`** — compatibility with the agent derivation above and
  with Cilium consumers of `status.eni.enis`), ipv6-prefixes, security-groups,
  tags, public-ip`.
- ENI garbage collector (`--eni-gc-interval` 5 m; 0 disables): each run deletes
  the ENIs marked on the previous run, then lists `status=available` ENIs
  matching the GC tags (and the subnet-id filter) up to 25
  (`ENIGarbageCollectionMaxPerInterval`) and marks them for the next run. The
  one-interval delay protects freshly created, not yet attached ENIs.

#### 3.9.3 Operator — per-node operations (`NodeOperations` for AWS)

Limits used below: `L = limits(spec.eni.instance-type)`; missing limits →
"unable to determine limits" (allocation skipped, warning, node needed=0).

- `GetMaximumAllocatableIPv4 = (L.Adapters − first-interface-index) × (L.IPv4 − 1) [× 16 if prefix delegation]`;
  0 (with warning "maximum allocatable ipv4 addresses will be 0 (unlimited)")
  when limits or `first-interface-index` are unknown or `L.Adapters <
  first-interface-index`.
- `GetMinimumAllocatableIPv4 = min(8, (L.Adapters − first-interface-index) × (L.IPv4 − 1))`,
  0 if `first-interface-index ≥ L.Adapters`, 8 when limits are unknown.
- **Prefix delegation is enabled for a node** iff `--aws-enable-prefix-delegation`
  and `L.HypervisorType == "nitro"` or `L.IsBareMetal` and
  `spec.eni.disable-prefix-delegation` is not true and no ENI carries plain
  secondary IPs (an ENI whose only address is its primary does not count).
  Mixed prefixes and secondary IPs on one node are never created.
- Effective per-ENI address limit: `L.IPv4 − 1` (+1 when `use-primary-address`),
  ×16 under prefix delegation; for a node no longer prefix-delegated but with
  prefixes attached, `+ len(prefixes) × 15` leftover capacity.
- `ResyncInterfacesAndIPs`: rebuild the ENI map from the cache; `available =
  {addr → {resource: eni.id}}` over all non-excluded ENIs' `addresses` (so
  prefixes count through their expansion); `NodeCapacity = effective limit ×
  L.Adapters` adjusted for excluded ENIs and leftover prefix capacity;
  `RemainingAvailableInterfaceCount = #ENIs with room + (L.Adapters − #ENIs)`;
  `NodeIPv6Prefixes = Σ len(ipv6-prefixes)`; `AssignedStaticIP = public IP of
  ENI number 0` if any. Zero ENIs → error "unable to retrieve ENIs" (instance
  gone).
- `PrepareIPAllocation`: over non-excluded ENIs with room (`effective limit −
  len(addresses) > 0`, counted as `InterfaceCandidates`), pick the first whose
  subnet has `AvailableAddresses > 0`: `InterfaceID = eni.id`, `PoolID =
  subnet.id`, `AvailableForAllocation = min(subnet.AvailableAddresses, room)`.
  `EmptyInterfaceSlots = L.Adapters − #ENIs`.
- `AllocateIPs(action)`: if `IPv6.MaxPrefixesToAllocate > 0`:
  `AssignIpv6Addresses(Ipv6PrefixCount=1)`. If `IPv4.AvailableForAllocation >
  0`: under prefix delegation `AssignPrivateIpAddresses(Ipv4PrefixCount =
  ceil(n/16))`; if that fails with `InsufficientCidrBlocks` or
  `InvalidParameterValue` containing "There aren't sufficient free Ipv4
  addresses or prefixes" fall back (warning "Subnet might be out of prefixes")
  to `AssignPrivateIpAddresses(SecondaryPrivateIpAddressCount = n)`; without
  prefix delegation the latter directly. Assigned IPs are added to the cache.
- `CreateInterface(action)`: subnet by 5.8; `PoolID = subnet.id`; security
  groups: `spec.eni.security-groups` → groups matching
  `spec.eni.security-group-tags` in the VPC (sorted; warning and fallthrough if
  none match) → the security groups of ENI number 0 (error "failed to get
  security group ids" if unknown). `toAllocate = min(MaxIPsToAllocate, (L.IPv4
  − 1) × 16)` under PD else `min(MaxIPsToAllocate, L.IPv4 − 1)`; return
  without action when 0 and no IPv6 prefix is needed. Index = first free
  attachment index ≥ `first-interface-index`. `CreateNetworkInterface`
  (description `Cilium-CNI (<instance-id>)`, groups, tag specification =
  creation tags, `Ipv4PrefixCount=ceil(toAllocate/16)` under PD else
  `SecondaryPrivateIpAddressCount=toAllocate`, `Ipv6PrefixCount=1` when IPv6
  needed); on the prefix-capacity error above retry once without prefixes.
  `AttachNetworkInterface(index)`; on `InvalidParameterValue` "interface
  attached at device" pick the next free index and retry (5 attempts). Any
  attach failure deletes the ENI; "is not 'running'" marks the node not running
  (no error). Unless `spec.eni.delete-on-termination == false`:
  `ModifyNetworkInterfaceAttribute(DeleteOnTermination=true)` (failure → delete
  the ENI, error). Record the ENI (with `number = index`, subnet CIDR) in the
  cache. Metrics label the error class: `unableToDetermineLimits`,
  `unableToFindSubnet`, `unableToGetSecurityGroups`, `unableToCreateENI`,
  `unableToAttachENI`, `unableToMarkENIForDeletion`.
- `AllocateStaticIP(tags)`: if ENI 0 already has a public IP return it; else
  `DescribeAddresses(tag filters)` and `AssociateAddress(AllowReassociation=false,
  NetworkInterfaceId = ENI 0)` with the first unassociated EIP; error if none.
- `GetAttachedCIDRs`: all prefixes, ipv6-prefixes and addresses (as /32 or
  /128) of all ENIs.
- `PrepareCIDRRelease(cidrs)`: group by owning non-excluded ENI (a /32 equal to
  an ENI primary IP is never released); `ReleaseAction{InterfaceID, PoolID =
  subnet.id, CIDRsToRelease}`.
- `ReleaseCIDRs(action)`: prefixes first via
  `UnassignPrivateIpAddresses(Ipv4Prefixes)`, then single IPs via
  `UnassignPrivateIpAddresses(PrivateIpAddresses)` (removed from the cache);
  returns the subset released before the first error.
- `PopulateStatusFields`: overwrite `status.eni.enis` with a copy of every ENI
  of the instance from the cache.

Release scheduling for ENI nodes is 3.14. The four-state handshake (3.13) is
never used for ENI nodes: the operator MUST write `status.ipam.release-ips =
null` for them.

Required EC2 permissions (the calls above): `DescribeInstances`,
`DescribeNetworkInterfaces`, `DescribeVpcs`, `DescribeSubnets`,
`DescribeRouteTables`, `DescribeSecurityGroups`, `DescribeInstanceTypes`,
`DescribeAddresses`, `DescribeTags`, `CreateNetworkInterface`,
`AttachNetworkInterface`, `ModifyNetworkInterfaceAttribute`,
`DeleteNetworkInterface`, `AssignPrivateIpAddresses`, `AssignIpv6Addresses`,
`UnassignPrivateIpAddresses`, `AssociateAddress`, `CreateTags` (tag
specification on create).

### 3.10 `azure`

Azure NICs are fixed at VM creation; the operator adds **IP configurations**
to an existing NIC. The agent uses the CRD allocator (3.7) over `spec.ipam.pool`
where `resource` is the NIC resource id, and participates in the release
handshake (3.13) — although the reference operator never initiates it on
Azure (`ReleaseIPs` unimplemented, excess release disabled), the agent side
MUST be implemented because it is shared with Alibaba.

Agent:

- Node discovery: `spec.instance-id = lowercase(Node.spec.providerID minus
  "azure://")` (fatal if missing or wrong prefix); `spec.azure.interface-name =
  --azure-interface-name`; `spec.ipam.{min,pre,max}-allocate` from flags; CNI
  custom netconf overrides `ipam.{min,pre}-allocate` and
  `azure.interface-name`.
- Native routing CIDR autodetection (part of the startup gate of 3.7): the
  first interface's subnet CIDR (fallback: deprecated `status.azure.interfaces[].cidr`)
  becomes `LocalNode.IPv4NativeRoutingCIDR` when `--ipv4-native-routing-cidr`
  is unset; when set it MUST contain (coalesce to one range with) the subnet
  CIDR, else fatal. The gate stays closed until a CIDR is derivable.
- `AllocationResult` for IP with `resource = iface.id`: `PrimaryMAC = iface.mac`,
  `GatewayIP = iface.gateway` (subnet first address + 1), `CIDRs = [subnet.cidr
  (or deprecated cidr)] + [ipv4-native-routing-cidr] + ip-masq-agent CIDRs of
  the family`, `InterfaceNumber = "0"` (unused: Azure uses the compat egress
  rule, 3.20). Interface not found → allocation error.

Operator:

- Auth: `--azure-user-assigned-identity-id` → managed identity credential with
  that client id; empty → default credential chain (environment service
  principal `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`, workload
  identity, managed identity). Cloud from IMDS `azEnvironment`:
  `AzurePublicCloud`, `AzureUSGovernmentCloud`, `AzureChinaCloud`; anything
  else is fatal ("Unknown Azure cloud"). `--azure-subscription-id` and
  `--azure-resource-group` default from IMDS `instance/compute/subscriptionId`
  and `resourceGroupName`. IMDS: `GET http://169.254.169.254/metadata/<path>?
  api-version=2019-06-01&format=text` with header `Metadata: true`, 10 s
  timeout.
- Full resync (1 m): list NICs of standalone VMs (`Interfaces.List` in the
  resource group) and of every VMSS (`VirtualMachineScaleSets.List` then
  `ListVirtualMachineScaleSetNetworkInterfaces`); parse each NIC (below) to
  discover the subnet ids in use; `Subnets.Get` for exactly those (paged by
  vnet); re-parse with subnet details. Instance sync: `Interfaces` of one VM
  (`ListVirtualMachineScaleSetVMNetworkInterfaces` for VMSS instances). A
  subnet lookup failure degrades to empty subnet info (warning), it does not
  fail the resync.
- NIC parse → `AzureInterface{id, name, mac (AA-BB-.. → aa:bb:..), state,
  security-group, subnet{id, cidr}, gateway = subnet first address + 1,
  addresses[] = {ip, state (lowercased provisioning state), subnet(deprecated)}}`;
  the primary IP configuration sets `ip` and is included in `addresses` only
  with `--azure-use-primary-address`. Instance id = lowercase of the NIC's
  `virtualMachine.id`. VMSS name and VM index are parsed from the NIC resource
  id (`.../virtualMachineScaleSets/<vmss>/virtualMachines/<idx>/networkInterfaces/<nic>`).
  `status.azure.interfaces` MUST be written sorted by `id`, addresses sorted by
  IP, so unchanged nodes compare equal and skip the status write.
- Limits: fixed 256 addresses per NIC and per VM (`InterfaceAddressLimit`),
  minus one per NIC whose primary is not exposed. `GetMaximumAllocatableIPv4 =
  256`, `GetMinimumAllocatableIPv4 = 8`, no prefix delegation, `CreateInterface`
  → error "not implemented".
- `ResyncInterfacesAndIPs`: `available = {ip → {resource: nic.id}}` for
  addresses in state `succeeded` only (others logged and skipped);
  `NodeCapacity = 256 − #NICs whose primary is hidden`;
  `RemainingAvailableInterfaceCount = #NICs eligible` (name matches
  `spec.azure.interface-name` when set, and room left).
- `PrepareIPAllocation`: first eligible NIC; `PoolID` = its subnet if that
  subnet has free addresses else any subnet with free addresses;
  `AvailableForAllocation = min(subnet free, NIC room)`.
- `AllocateIPs`: VMSS instance → `VirtualMachineScaleSetVMs.Get(expand
  instanceView)`, find the NIC configuration by name, append `n` IP
  configurations `{name: ipconfig-<random>, privateIPAddressVersion: IPv4,
  subnet: <PoolID>, applicationSecurityGroups: <copied from the first existing
  ipconfig>}`, clear `storageProfile.imageReference` (gallery references cause
  permission errors), `BeginUpdate` and poll to completion. Standalone VM →
  `Interfaces.Get`, append ipconfigs, `BeginCreateOrUpdate`, poll. Updates to
  one VM MUST be serialized per node (the node manager guarantees one
  maintenance at a time per node); flowsdn MUST additionally serialize
  mutating operations by full VMSS resource ID across nodes, retaining the
  async permit through confirmed terminal LRO completion/failure/cancellation.
  Cancelling a caller only stops its wait: the owning reconciler retains the
  permit while the remote operation runs. After restart, reconcile in-flight
  remote operations before issuing another mutation (ADR-0012 #107). Different
  scale sets remain independent.
- `AllocateStaticIP(tags)`: find a `PublicIPPrefix` whose tags match,
  attach a public IP from it to the primary ipconfig of the primary NIC (VMSS
  model update or NIC update), return the resulting public address (reads it
  back via `PublicIPAddresses`). Legacy values in `assigned-static-ip` that do
  not parse as an IP MUST be re-resolved (3.15).
- `PrepareIPRelease` returns an empty action; `ReleaseIPs` is "not implemented";
  the node manager is started with release disabled. The deprecated mirror
  fields `interfaces[].cidr` and `addresses[].subnet` MUST be read (fallback)
  and MUST be written as mirrors of the current fields (ADR-0012 #106).
  Removing these fields requires a separate migration decision.

Required RBAC actions: `Microsoft.Network/networkInterfaces/read`,
`Microsoft.Network/virtualNetworks/read`, `.../subnets/read`,
`.../subnets/join/action`, `Microsoft.Compute/virtualMachineScaleSets/read`;
VMSS: `.../virtualMachineScaleSets/virtualMachines/{read,write}`; standalone:
`Microsoft.Network/networkInterfaces/write`; static IP:
`Microsoft.Network/publicIPPrefixes/{read,join/action}`,
`Microsoft.Compute/virtualMachines/read`.

Not Azure IPAM: AKS BYOCNI (`aksbyocni.enabled`) is `cluster-pool` in tunnel
mode; `azure.enabled` and BYOCNI are mutually exclusive (Helm spec).

### 3.11 `alibabacloud`

ENI-equivalent on Alibaba Cloud ECS. The agent uses the CRD allocator (3.7) over
`spec.ipam.pool` with `resource` = ENI id and the release handshake (3.13); the
operator creates/attaches ENIs and assigns private IPs.

Agent:

- Node discovery from metadata `http://100.100.100.200/latest/meta-data/{instance-id,
  instance/instance-type, region-id, zone-id, vpc-id, vpc-cidr-block}` (fatal
  on failure): `spec.instance-id`, `spec.alibaba-cloud.{instance-type, vpc-id,
  cidr-block, availability-zone}`; from flags `vswitches`, `vswitch-tags`,
  `security-groups`, `security-group-tags`, `spec.ipam.{min,pre,max}-allocate`;
  CNI custom netconf overrides all of these plus `cidr-block`.
- Native routing CIDR autodetection: primary = `spec.alibaba-cloud.cidr-block`,
  secondaries = `status.alibaba-cloud.enis[*].vpc.secondary-cidrs`; same rule as
  Azure (configured CIDR must contain one of them).
- `AllocationResult` for `resource = eni.network-interface-id`: `PrimaryMAC =
  eni.mac-address`, `CIDRs = [vswitch.cidr]`, `GatewayIP = last address of the
  vSwitch CIDR − 2` (Alibaba reserves the third-to-last address),
  `InterfaceNumber = tag cilium-eni-index` (0 when absent/unparseable).

Operator:

- Auth: SDK default credential chain (env `ALIBABA_CLOUD_ACCESS_KEY_ID`/`..._SECRET`,
  RAM role via metadata `ram/security-credentials/<role>`, OIDC RRSA). Region
  from metadata `region-id`. Endpoints MUST be the VPC endpoints
  `ecs-vpc.<region>.aliyuncs.com` / `vpc-vpc.<region>.aliyuncs.com` over
  HTTPS (no public egress needed). `--alibaba-cloud-vpc-id` (default: the
  operator's own VPC). `--instance-tags-filter` at most 20 tags (fatal
  otherwise).
- Limits: `DescribeInstanceTypes` paged with `MaxResults=100`/`NextToken` at
  start (fatal on failure): `{Adapters=EniQuantity,
  IPv4=EniPrivateIpAddressQuantity, IPv6=EniIpv6AddressQuantity}`; no refresh.
- Resync (1 m): `DescribeVpcs`/`DescribeVSwitches` (with
  `AvailableIpAddressCount`, zone, tags), `DescribeSecurityGroups`, ENIs via
  `DescribeNetworkInterfaces` paged `MaxResults=500`; with instance tag filters:
  `ListTagResources` → instance ids in batches of 100 → `DescribeInstances` →
  `DescribeNetworkInterfaces` per ENI id batch, in parallel. Per-instance sync
  by `InstanceId`. ENI parse → `{network-interface-id, mac-address, type
  (Primary|Secondary), instance-id, security-groupids, vpc{vpc-id, cidr,
  ipv6-cidr, secondary-cidrs}, zone-id, vswitch{vswitch-id, cidr, ipv6-cidr},
  primary-ip-address, private-ipsets[{private-ip-address, primary}], tags}`.
- `GetMaximumAllocatableIPv4 = (L.Adapters − 1) × L.IPv4` (primary ENI is never
  used for pods); `GetMinimumAllocatableIPv4 = 8`; no prefix delegation; no
  static IP ("not implemented").
- `ResyncInterfacesAndIPs`: `available = {ip → {resource: eni id}}` over
  **secondary** ENIs' `private-ipsets` (including their primary address);
  `NodeCapacity = L.IPv4 × (L.Adapters − 1) − #primary addresses of secondary
  ENIs`. Zero ENIs → error.
- `PrepareIPAllocation`: first secondary ENI with room whose vSwitch has free
  addresses; `PoolID = vswitch id`; `EmptyInterfaceSlots = L.Adapters − #ENIs`.
- `AllocateIPs`: `AssignPrivateIpAddresses(SecondaryPrivateIpAddressCount=n)`.
- `CreateInterface`: `toAllocate = min(MaxIPsToAllocate, L.IPv4, 10)`
  (`maxENIIPCreate`); vSwitch = `spec.alibaba-cloud.vswitches` ids filtered by
  VPC+zone with most free addresses, else any vSwitch in VPC+zone with
  `AvailableAddresses ≥ toAllocate` matching `vswitch-tags`, most free first;
  security groups `security-groups` → `security-group-tags` match → primary
  ENI's groups; ENI index = lowest unused integer in `1..49` over the tags
  `cilium-eni-index` of existing ENIs (0 reserved for eth0, 50 max ENIs,
  out-of-range tag is an error); `CreateNetworkInterface(SecondaryPrivateIpAddressCount
  = toAllocate − 1, VSwitchId, SecurityGroupIds, Tag[cilium-eni-index=<idx>])`,
  `AttachNetworkInterface(InstanceId)`, then poll `DescribeNetworkInterfaces`
  until `Status == "InUse"` (6 × 2.5 s); on attach/wait failure delete the ENI.
- `PrepareIPRelease(excess)`: iterate secondary ENIs; free = non-primary
  `private-ipsets` addresses not in `status.ipam.used`; the **last** ENI with
  free addresses wins in the reference (map order). flowsdn MUST instead pick
  the ENI with the most free addresses, breaking ties by ascending ENI ID, and
  sort candidate IPs numerically (ADR-0012 #111; an internal choice); `IPsToRelease = free[:min(free,
  excess)]`, `PoolID = vpc id`. `ReleaseIPs` → `UnassignPrivateIpAddresses`.
  Release is enabled by `--alibaba-cloud-release-excess-ips` with the release
  delay fixed at 0 s.

Required RAM actions: `ecs:{CreateNetworkInterface, DescribeNetworkInterfaces,
AttachNetworkInterface, DetachNetworkInterface, DeleteNetworkInterface,
DescribeInstanceAttribute, DescribeInstanceTypes, AssignPrivateIpAddresses,
UnassignPrivateIpAddresses, DescribeInstances, DescribeSecurityGroups,
ListTagResources}`, `vpc:{DescribeVSwitches, DescribeVpcs}`.

### 3.12 GKE

There is no GCP API client in the reference and none in flowsdn. Helm
`gke.enabled=true` implies: `ipam: kubernetes` (3.4), `routing-mode: native`
(fatal in Helm if set otherwise), `enable-endpoint-routes: "true"`,
`enable-health-check-loadbalancer-ip: "true"`,
`install-no-conntrack-iptables-rules: "false"` (moot under ADR-0003), and the
user-supplied `ipv4-native-routing-cidr` (the cluster's pod range). The agent
waits for `Node.spec.podCIDR(s)` as in 3.4. GKE alias-IP programming is done
by GKE itself. Decision #109 retains this integration; no separate GCP Compute client is planned.

### 3.13 Excess-IP release handshake (CRD allocator modes: Azure, Alibaba, crd)

State lives in `status.ipam.release-ips` (IPv4) / `status.ipam.release-ipv6s`
(map `ip → state`). Operator-side timestamps `ipsMarkedForRelease` and states
`ipReleaseStatus` are in memory.

| State (writer) | Meaning |
|---|---|
| `marked-for-release` (operator) | candidate; agent must answer |
| `ready-for-release` (agent) | not allocated locally; operator may release |
| `do-not-release` (agent) | allocated locally, or IP not in `spec.ipam.pool` |
| `released` (operator) | unassigned at the cloud and removed from `spec.ipam.pool` |

Operator per maintenance run (only when release is enabled and the node has
`ExcessIPs > 0` or entries in `release-ips`):

1. `PrepareIPRelease(excess)` yields candidate IPs on one interface. Each
   candidate not yet timestamped gets `now`. Candidates no longer returned are
   dropped from both maps (interface changed or IP no longer excess). If there
   are no candidates the timestamp map is reset.
2. A candidate whose timestamp is older than `--excess-ip-release-delay`
   (180 s AWS default, 0 Alibaba) and has no agent answer is set to
   `marked-for-release`. An answer `ready-for-release` queues the IP for
   release; `do-not-release` drops it from both maps.
3. Abort: any IP in `release-ips` that is not among the current candidates is
   removed from the in-memory maps unless it is `released`; a `released` IP that
   is back in `spec.ipam.pool` is removed from `release-ips` too.
4. Release the queued IPs (`ReleaseIPPrefixes` if any prefixes, then
   `ReleaseIPs`); on success set them to `released`. Prefixes count as 16 IPs
   toward `excess`.
5. On status sync (`PopulateIPReleaseStatus`) the operator writes its map; for
   IPs it holds as `marked-for-release` it retains an existing agent answer.
   Entries in `released` state are purged from memory once the agent removed
   them from the CR.

Agent, on every CiliumNode update: for each `release-ips` entry not already
answered by it: IP absent from `spec.ipam.pool` and state `released` → delete
the entry (and remove the `unreachable` route of 3.18); absent and
`marked-for-release` → `do-not-release`; present and `marked-for-release` →
`do-not-release` if allocated locally else `ready-for-release`; other states are
left alone. Any change triggers the rate-limited status write. IPs in
`marked-for-release`, `ready-for-release` or `released` are never allocated and
do not count toward the startup minimum (3.7).

Ordering guarantee the operator MUST keep: status (`used`, `release-ips`,
cloud status) is written **before** `spec.ipam.pool` in each sync so an IP never
appears in the pool without its interface information being present.

### 3.14 CIDR-based release (ENI, multi-pool nodes)

The operator tracks `previousAllocatedCIDRs` per node from
`spec.ipam.pools.allocated`:

- On the first observation (seed; covers operator restart), every attached
  IPv4 CIDR (`GetAttachedCIDRs`) that is not in `allocated` is marked for
  release with timestamp `now`. On later observations, every previously
  allocated IPv4 CIDR that disappeared is marked (existing timestamps are
  kept). A marked CIDR that reappears in `allocated`, or is no longer attached
  at the cloud, is unmarked. IPv6 CIDRs are never released.
- A maintenance run (when release is enabled) selects marked CIDRs older than
  `--excess-ip-release-delay`, groups them by ENI (`PrepareCIDRRelease`),
  re-checks membership immediately before each call (the agent may have
  re-added a CIDR), calls `ReleaseCIDRs`, and unmarks what was released even on
  partial failure. A mutating run triggers an instance sync.
- The agent side is 5.7: it drops a CIDR from `allocated` only when no IP is
  allocated from it and dropping keeps `free ≥ needed − inUse`. A dropped but
  still attached CIDR is reclaimed by the agent when demand grows back before
  the operator released it.

### 3.15 Operator node manager (shared by ENI, Azure, Alibaba)

- Start: blocking full cloud resync (fatal on failure), then a 1 m interval
  background resync (`ipam-node-interval-refresh`) which re-reads the cloud
  and runs `Resync` over all nodes. Cloud API errors flip "instances API
  unstable"; while unstable every maintenance is refused and retried through a
  1 m-min-interval retry trigger.
- Watching: all `CiliumNode`s (a CiliumNode annotated `ipam.cilium.io/ignore:
  "true"` is skipped) and all Pods (for surge). Upsert of an unknown node:
  if its instance is not in the cache, do an instance sync; create the
  provider's `NodeOperations`; create triggers `ipam-pool-maintainer-<node>`
  (min interval 10 ms, exponential backoff on error: jittered, max 5 m, reset
  after 10 m quiet), `ipam-pool-maintainer-<node>-retry` (1 m),
  `ipam-node-k8s-sync-<node>` (10 ms), `ipam-node-instance-sync-<node>` (10 ms).
  Delete: stop triggers, drop metrics for the node, delete the instance from
  the cache.
- Every CiliumNode update: store the resource (also marks the instance
  running), 3.14 tracking, provider `UpdatedNode`, `recalculate`, and trigger
  maintenance if allocation or release is needed.
- `recalculate`: `ResyncInterfacesAndIPs` → `AvailableIPs = len(available)`,
  `RemainingInterfaces`, `Capacity`, IPv6 prefixes; `UsedIPs`: for a multi-pool
  node `max(0, requested.ipv4-addrs − preAllocate)` and `NeededPrefixes = 1`
  when `requested.ipv6-addrs > 0` and no IPv6 prefix is attached (never
  released), for a CRD node `len(status.ipam.used)`; then `NeededIPs` and
  `ExcessIPs` by 5.1. An error from the provider zeroes needed/excess and logs
  "Instance not found! Please delete corresponding ciliumnode" (or "Instance
  limits not found").
- `Resync(all nodes)`: nodes sorted by `GetNeededAddresses` descending
  (deficits first; excess as negative numbers, larger excess first), processed
  by up to `--parallel-alloc-workers` (50) concurrent workers (semaphore);
  each worker updates the node's last-resync time, recalculates, triggers
  maintenance and k8s sync, and contributes to the aggregate metrics of §8.
- `MaintainIPPool` (one at a time per node): refuse while the instances API is
  unstable; skip if the instance stopped running less than 1 m ago; then (a)
  purge stale handshake entries, (b) 3.14 release, (c) static IP resolution
  when `spec.ipam.static-ip-tags` is set and `assigned-static-ip` is empty or
  not an IP, (d) determine the action: release (3.13) if excess and not
  multi-pool, else allocation: `PrepareIPAllocation`, `MaxIPsToAllocate =
  NeededIPs + max-above-watermark + surge` where `surge = max(0, pending
  non-hostNetwork pods on the node − NeededIPs)`, `MaxPrefixesToAllocate =
  NeededPrefixes`; (e) `handleIPRelease` then `handleIPAllocation`:
  `AvailableForAllocation = min(AvailableForAllocation, MaxIPsToAllocate)`;
  `AllocateIPs` on the chosen interface; if that fails or nothing is
  available, `CreateInterface` unless `EmptyInterfaceSlots == 0` ("Instance is
  out of interfaces", warned once per hour, not a failure). After a successful
  run mark a resync needed (blocks further allocation until the next resync
  confirms the state), recalculate, and trigger an instance sync if the cloud
  was mutated.
- `syncToAPIServer` (per node, triggered and after every resync): take a
  snapshot of `available` as the pool, then **status first**: `status.ipam.used`
  kept from the CR (empty map if nil), provider status fields
  (`status.eni.enis` / `status.azure.interfaces` / `status.alibaba-cloud.enis`),
  `status.ipam.release-ips` (3.13, or `null` for multi-pool nodes),
  `status.ipam.assigned-static-ip`; `UpdateStatus` only if the status changed.
  Then **spec**: `spec.ipam.pool = snapshot` and, if `spec.ipam.pre-allocate ==
  0`, `spec.ipam.pre-allocate = GetMinimumAllocatableIPv4()`; `Update` only if
  the spec changed. Two attempts each; on failure re-`Get` the node and retry
  once; `NotFound` ends the sync. In ENI mode the operator MUST keep writing
  `spec.ipam.pool` (the agent ignores it but validates it against status; other
  implementations' tooling reads it).
- Cloud API rate limiting: one token bucket per provider client,
  `--limit-ipam-api-qps` (4.0) / `--limit-ipam-api-burst` (20); every call
  reserves a token first and records the wait in the rate-limit histogram; on
  context cancellation the reservation is returned.

### 3.16 Infra IPs (router, health, ingress)

Allocated from the same per-family allocator with `allocate_without_sync` /
`allocate_next_without_sync`, owner `router`, `health`, `ingress`, pool
`default`:

- Router IP: `--local-router-ipv4/6` wins (warning if inside the pod CIDR);
  else restore the previous IP preferring the filesystem copy over the
  CiliumNode's (warning on mismatch), else `allocate_next`. In modes where the
  router IP is not part of the pool (cloud modes, delegated) the IP is
  `exclude_ip`'d so a pod never gets it.
- Health endpoint IP: `allocate_next`; in ENI/Azure/Alibaba the resulting
  `AllocationResult` is kept as the health endpoint's routing info (3.20, host
  = false).
- Infra IPs are released and re-allocated on restart; they never expire.

### 3.17 Expiration timers

`start_expiration_timer(ip, pool, timeout)` registers a UUID and a timer;
`stop_expiration_timer(ip, pool, uuid)` cancels it only if the UUID matches;
`release` cancels any timer. On expiry, if the registered UUID still matches,
the IP is released with a warning "Released IP after expiration". A second
timer on the same `(ip, pool)` is an error. The CNI plugin's `POST /ipam` with
`expiration: true` starts a 10 min timer; the endpoint creation request carries
the UUIDs (`AddressPair.ipv{4,6}-expiration-uuid`) and the endpoint manager
stops them once the endpoint exists (spec 08).

### 3.18 Unreachable routes (`--enable-unreachable-routes`, false)

On endpoint deletion the routing layer replaces the pod's /32 (or /128) route in
`main` with `unreachable <ip> proto kernel`. The CRD allocator removes that
route when the IP leaves `spec.ipam.pool` in state `released`; the multi-pool
manager removes all `unreachable` routes covered by a CIDR that leaves the
node's pool set. Purpose: ICMP errors for clients of a stale IP and no
`rp_filter` martian warnings.

### 3.19 CiliumNode garbage collection (operator)

`--nodes-gc-interval` (5 m, 0 disables). Every interval, for each CiliumNode: if
a k8s Node of that name exists it is valid; otherwise it becomes a candidate
with a timestamp and is deleted on a later run once it has been a candidate for
at least one interval. When `enable-ciliumnode-crd=false` a one-off pass deletes
every CiliumNode. Deletion feeds `NodeManager.Delete` (3.15) and pool release
(3.5/3.6).

### 3.20 Per-endpoint policy routing (ENI, Azure, Alibaba, delegated with uplink routes)

Installed by the CNI plugin at ADD from `IPAMAddressResponse` (and by the agent
for the health endpoint), reconciled by the agent's route reconciler (spec 10)
for the gateway routes. `RoutingInfo = {gateway, cidrs (coalesced, same family
as the IP), master-mac, masquerade (BPF masquerade enabled for the family),
interface-number, ipam-mode}`. `NewRoutingInfo` MUST reject an empty gateway,
an unparsable CIDR/MAC/interface number, and empty `cidrs` when masquerade is
on.

`Configure(ip, mtu, host)`:

1. Resolve the master ifindex by MAC, skipping `IFF_SLAVE` devices; several
   matches or none is an error. Set MTU and bring the link up.
2. Ingress rule unless `host`: `priority 20 to <ip>/32 lookup main proto kernel`.
3. Egress: `compat = (ipam-mode == azure)`. `priority = compat ? 110 : 111`;
   `table = compat ? ifindex : 10 + interface-number`. If masquerade and mode
   ∈ {eni, azure}: one rule `from <ip>/32 to <cidr> lookup <table>` per
   coalesced CIDR (a `0.0.0.0/0`/`::/0` CIDR is written without `to`);
   otherwise one rule `from <ip>/32 lookup <table>`.
4. Routes in `<table>`: IPv4 `<gw>/32 dev <ifindex> scope link` and `default via
   <gw>`; IPv6 `<gw>/128 dev <ifindex> scope link` and `default via <gw>` with
   `dev <ifindex>` only when the gateway is link-local. All `proto kernel`,
   installed with replace semantics.

`Delete(ip)`: delete all ingress rules matching `priority 20 to <ip>/32 table
main`; delete egress rules matching `priority <110|111> from <ip>/32` (and,
when masquerade and mode ∈ {eni, azure}, `to <cidr>` for each coalesced native
routing CIDR of the node) whose table is ≥ the first per-interface table (10,
or 0 in compat mode); "no rule found" is an error; then 3.18 if enabled. The
per-interface tables and their routes are never deleted (shared by other
endpoints on the same interface).

Rule priorities 109 (`RulePriorityNodeport`), 9/10 (proxy) and 112 (VTEP) belong
to other specs but share the number space; this spec MUST NOT use them.

**DEVIATION (ADR-0003):** the reference also installs iptables rules in ENI mode
(CONNMARK 0x80 restore, `--egress-masquerade-interfaces eth+`). flowsdn's
nftables residual (spec 10) covers the `ct mark` rule; interface-scoped
iptables masquerade does not exist, BPF masquerade with `ParentInterfaceIndex`
is the only path.

## 4. Data model

### 4.1 `CiliumNode` (`cilium.io/v2`, cluster-scoped, status subresource) — IPAM fields

Writer column: **A** agent (its own CiliumNode), **O** operator, **U** user or
external controller. "Mode" lists where the field is meaningful. Presence:
`omitempty` (omitted when zero/empty) unless noted `omitzero` (structs/prefixes
omitted when unset) or `always`.

| Field | JSON | Type | Writer / when | Mode |
|---|---|---|---|---|
| `spec.instance-id` | `instance-id` | string | A at node discovery (EC2 `i-…`, Azure providerID sans prefix lowercased, ECS id) | eni, azure, alibabacloud |
| `spec.ipam.pool` | `pool` | `map[ip]{owner?,resource?}` | O on every sync (snapshot of available IPv4); U in `crd` | crd, azure, alibabacloud, eni (written, ignored by agent) |
| `spec.ipam.ipv6-pool` | `ipv6-pool` | same | U in `crd` (operators do not populate it at 1.20) | crd |
| `spec.ipam.pools.requested[]` | `requested` | `[{pool, needed{ipv4-addrs?,ipv6-addrs?}}]` | A every update cycle (sorted by pool; only non-zero demand) | multi-pool, eni |
| `spec.ipam.pools.allocated[]` | `allocated` | `[{pool, allowFirstIP?, allowLastIP?, cidrs[]}]` | multi-pool: O adds, A removes (A rewrites the field with its in-use set once synced); eni: A only (derived from status.eni) | multi-pool, eni |
| `spec.ipam.podCIDRs` | `podCIDRs` | `[]cidr` | O (cluster-pool), migration clears | cluster-pool |
| `spec.ipam.min-allocate` | `min-allocate` | int ≥ 0 | A from flag/netconf at discovery | cloud modes, crd |
| `spec.ipam.max-allocate` | `max-allocate` | int ≥ 0 | A from flag/netconf | cloud modes |
| `spec.ipam.pre-allocate` | `pre-allocate` | int ≥ 0 | A from flag/netconf; O sets `GetMinimumAllocatableIPv4()` when 0 | cloud modes, crd |
| `spec.ipam.max-above-watermark` | `max-above-watermark` | int ≥ 0 | U (never set by A/O) | cloud modes |
| `spec.ipam.static-ip-tags` | `static-ip-tags` | map | A from `--ipam-static-ip-tags` | eni, azure |
| `spec.eni.instance-type`, `availability-zone`, `vpc-id`, `node-subnet-id` | same | string | A from IMDS | eni |
| `spec.eni.first-interface-index` | | *int ≥ 0 | A (flag, default 0; pointer, always written) | eni |
| `spec.eni.use-primary-address`, `disable-prefix-delegation`, `delete-on-termination` | | *bool | A (flags; defaults false/false/true; pointers, always written) | eni |
| `spec.eni.subnet-ids[]`, `subnet-tags`, `security-groups[]`, `security-group-tags`, `exclude-interface-tags` | | list / map | A from flags/netconf | eni |
| `spec.azure.interface-name` | `interface-name` | string | A | azure |
| `spec.alibaba-cloud.instance-type`, `availability-zone`, `vpc-id`, `cidr-block` (omitzero, cidr) | | string | A from metadata | alibabacloud |
| `spec.alibaba-cloud.vswitches[]`, `vswitch-tags`, `security-groups[]`, `security-group-tags` | | list / map | A from flags/netconf | alibabacloud |
| `status.ipam.used` | `used` | `map[ip]{owner,resource}` | A (CRD allocator) on allocation change, rate limited; A clears it in multi-pool/eni | crd, azure, alibabacloud |
| `status.ipam.ipv6-used` | `ipv6-used` | same | A | crd |
| `status.ipam.pod-cidrs` | `pod-cidrs` | `map[cidr]{status: released\|depleted\|in-use}` | nobody at 1.20; accepted, never written | — |
| `status.ipam.operator-status.error` | `error` | string | O (cluster-pool, multi-pool, migration; flowsdn also for the 3.9 protocol error) | cluster-pool, multi-pool |
| `status.ipam.release-ips` | `release-ips` | `map[ip]state` | O writes its view; A rewrites answers; O writes `null` for multi-pool nodes | azure, alibabacloud, crd |
| `status.ipam.release-ipv6s` | `release-ipv6s` | same | schema only at 1.20 | — |
| `status.ipam.assigned-static-ip` | `assigned-static-ip` | string (IP) | O after static IP resolution | eni, azure |
| `status.eni.enis` | `enis` | `map[eni-id]ENI` | O on every sync, full overwrite | eni |
| `ENI` | | `{id, ip (omitzero), mac, availability-zone, description, number, subnet{id,cidr}, vpc{id,primary-cidr,cidrs[]}, addresses[], prefixes[], ipv6-prefixes[], security-groups[], tags, public-ip (omitzero)}` | O | eni |
| `status.azure.interfaces` | `interfaces` | `[]AzureInterface` sorted by id | O | azure |
| `AzureInterface` | | `{id, ip (omitzero), name, mac, state, addresses[{ip, subnet (deprecated), state}], security-group, subnet{id,cidr}, gateway (always), cidr (deprecated, omitzero)}` | O | azure |
| `status.alibaba-cloud.enis` | `enis` | `map[eni-id]ENI` | O | alibabacloud |
| Alibaba `ENI` | | `{network-interface-id, mac-address, type, instance-id, security-groupids[], vpc{vpc-id, cidr, ipv6-cidr, secondary-cidrs[]}, zone-id, vswitch{vswitch-id, cidr, ipv6-cidr}, primary-ip-address, private-ipsets[{private-ip-address, primary}], tags}` | O | alibabacloud |

Update protocol: the agent uses `Update` for spec (`pools`) and `UpdateStatus`
for status; the operator uses `UpdateStatus` then `Update` (3.15), or batched
`Create`/`Update`/`UpdateStatus` (3.5), or per-node controllers (3.6). All
writers MUST compare deep-equal before writing (skip no-op writes) and MUST
treat `409 Conflict` as "re-read and retry", never as failure. The agent's
CiliumNode informer MUST keep the latest `resourceVersion` even for events that
are deep-equal, because the next `UpdateStatus` needs it.

### 4.2 `CiliumPodIPPool` (`cilium.io/v2alpha1`, cluster-scoped, short name `cpip`, no status)

```
spec:
  ipv4:  { cidrs: [cidr, …] (min 1), maskSize: 1..32 (immutable) }   optional
  ipv6:  { cidrs: [cidr, …] (min 1), maskSize: 1..128 (immutable) }  optional
  allowFirstIP: bool (immutable; ignored for /31,/32,/127,/128)
  allowLastIP:  bool (immutable; same)
  podSelector:       metav1.LabelSelector (optional)
  namespaceSelector: metav1.LabelSelector (optional)
```

Annotations read: `ipam.cilium.io/skip-masquerade: "true"`. The agent mirrors
pools into a `flowsdn-table` table `LocalPodIPPool` keyed by name (name,
annotations, `hasV4`, `hasV6`, compiled selectors), replacing the reference's
StateDB table (ADR-0004).

### 4.3 Agent-internal structures that reach the wire

```
AllocationResult { ip: IpAddr, pool: Pool, cidrs: Vec<IpNet>, primary_mac: String,
                   gateway: Option<IpAddr>, expiration_uuid: String,
                   interface_number: String, skip_masquerade: bool }
   → IPAMAddressResponse (3.2) → RoutingInfo (3.20)
Pool = newtype String; "" is normalized to "default" (IPAMDefaultIPPool)
Family = "ipv4" | "ipv6"
```

### 4.4 Operator-internal structures (shared `flowsdn-ipam-types`)

```
Limits         { adapters, ipv4, ipv6: u32, hypervisor_type: String, is_bare_metal: bool }
Subnet         { id, name, cidr, ipv6_cidr, availability_zone, virtual_network_id,
                 available_addresses, available_ipv6_addresses, tags }
VirtualNetwork { id, primary_cidr, cidrs[], ipv6_cidrs[] }
RouteTable     { id, virtual_network_id, subnets: Set<id> }
PoolQuota      { availability_zone, available_ips, available_ipv6s }   keyed by PoolID (subnet/vSwitch id)
InstanceMap    instance-id → interface-id → Interface (ENI | AzureInterface | AlibabaENI), copy-on-write
AllocationAction { interface_id, interface, pool_id, empty_interface_slots,
                   ipv4: { available_for_allocation, max_ips_to_allocate, max_prefixes_to_allocate, interface_candidates },
                   ipv6: { same } }
ReleaseAction  { interface_id, pool_id, ips_to_release[], ip_prefixes_to_release[], cidrs_to_release[] }
Statistics     { ipv4: { used, available, available_prefixes, capacity, needed, needed_prefixes, excess,
                         remaining_interfaces, interface_candidates, assigned_static_ip },
                 ipv6: { same }, empty_interface_slots }
```

Tags matching: `have.matches(required)` iff every required key is present with
an equal value.

### 4.5 Files

None. Router IP restoration reads the endpoint restore state and
`cilium_host` addresses owned by spec 08/10. The CNI custom netconf
(`cni.customConf`) is read by the CNI config manager (spec 09) and consumed here
through node discovery.

## 5. Algorithms

### 5.1 Operator watermarks (pure functions; identical results required)

```
needed(available, used, pre, min, max):
    n = max(pre + used − available, min − available)
    if max > 0 and available + n > max: n = max − available
    return max(n, 0)

excess(available, used, pre, min, maxAbove):
    if used ≤ min + maxAbove:
        if available ≤ min + maxAbove: return 0
        if used + pre ≤ min + maxAbove: return available − min − maxAbove
    return max(available − used − pre − maxAbove, 0)
```

`pre = spec.ipam.pre-allocate` if non-zero else 8; `min =
spec.ipam.min-allocate`; `max = spec.ipam.max-allocate` if > 0 (warn when above
the instance maximum) else `GetMaximumAllocatableIPv4()`; `maxAbove =
spec.ipam.max-above-watermark`. `MaxIPsToAllocate = needed + maxAbove + surge`.

### 5.2 Agent demand (multi-pool and ENI)

```
neededIPCeil(n, pre): pre == 0 → n; n % pre > 0 → (n/pre + 2)·pre; else (n/pre + 1)·pre
   (pre=16: 0→16, 1→32, 15→32, 16→32, 17→48)
multi-pool: needed[pool][fam] = neededIPCeil(inUse + pending, pre[pool])
eni (linear):   needed[default][fam] = inUse + pending + pre
```

Pools with zero pre-allocation and zero use are not requested. Pending entries
expire 5 m after their last failed attempt.

### 5.3 ENI usage recovery (operator)

`used = max(0, requested.ipv4-addrs − pre)`; `pre` is the operator's view
(`spec.ipam.pre-allocate` or 8), which the agent also uses once the operator
has written it — until then the agent uses 8, so the two agree after the first
sync.

### 5.4 Node-CIDR sets (cluster-pool and multi-pool operator)

A CIDR set carves fixed-size node prefixes of `nodeMask` bits from one cluster
prefix: `maxCIDRs = 2^(nodeMask − clusterMask)` (IPv6 ≤2^16; flowsdn
IPv4 bounded at 2^24), a bitmap of that
size, a `nextCandidate` cursor. `AllocateNext` scans from the cursor for the
first free bit (wrapping) → prefix at that index; `Occupy(prefix)` idempotently sets every intersecting node-block bit,
including all blocks for a covering supernet (error if disjoint or wrong family);
`Release(prefix)` idempotently clears the same interval; `IsFull`, `InRange` (any overlap), `IsAllocated` (all overlapping blocks set),
`IsClusterCIDR(p)` (p equals the cluster prefix). IPv6 index→prefix uses the
upper 64 bits when the node mask ≤ 64 (k8s-derived layout). Errors:
"there are no remaining CIDRs left to allocate", "subnet mask size too big",
"CIDR allocation failed; not in range".

Calibration #250 ports all 52 static rows of pinned `cidr_set_test.go` plus
both full-256 allocation/release/reallocation workflows and half-occupied
workflows. The reference limits only IPv6 to a 16-bit prefix difference;
IPv4 /8→/32 is covered, requiring 16,777,216 bitmap slots. flowsdn caps IPv4
at a 24-bit difference (16 MiB boolean bitmap), rejecting larger requests
before allocation. This explicit resource bound differs from the reference's
unbounded IPv4 constructor and does not affect any harvested test case.
`index(address)` rejects wrong-family/outside addresses and returns the
node-block index; occupied counts remain exact under repeated operations.

### 5.5 Single-IP bitmap (`kubernetes`, `cluster-pool`, per-CIDR in multi-pool)

Range over a prefix: `base = first address (+1 unless allowFirstIP)`, `max =
2^(bits) − (allowFirstIP?0:1) − (allowLastIP?0:1)` for prefixes with > 2
addresses (no reservation for /31, /32, /127, /128). `AllocateNext` uses a
**random-scan** strategy (random start offset, then linear scan) — not
sequential; tests MUST not assume ordering. `Allocate(ip)` errors:
`ErrNotInRange`, `ErrAllocated`; `AllocateNext` → `ErrFull`. `Release` of a
free or foreign IP is a no-op.

### 5.6 Agent CIDR-list pool (`cidrPool`)

Ordered list of 5.5 ranges (CRD order), plus sets `released` (CIDRs the agent
dropped but the operator still advertises) and `removed` (CIDRs the operator
dropped while in use). `allocate_next` takes the first non-removed range with
free space (avoids fragmentation); `allocate(ip)` finds the containing range.
`updatePool(prefixes)`: de-duplicate (error log); forget `released` entries no
longer advertised (and clean their unreachable routes); keep existing ranges
still advertised or still in use (the latter → `removed`); create ranges for
new prefixes unless `released`; a prefix with zero usable addresses goes
straight to `released` ("skipping too-small CIDR"). `hasAvailableIPs`,
`capacity` and `dump` ignore `removed` ranges.

### 5.7 Agent excess-CIDR release (`releaseExcessCIDRsMultiPool(freeNeeded)`)

`freeNeeded = max(needed − inUse, 0)`. First, if `totalFree < freeNeeded` and
`released` is non-empty, reclaim released CIDRs in sorted order (address, then
length) until `totalFree ≥ freeNeeded`. Then walk ranges from the **last** to
the first: a range with `used == 0` whose removal keeps `totalFree − free ≥
freeNeeded` is moved to `released`; others are retained in original order.

### 5.8 ENI subnet selection (`findSuitableSubnet`)

1. `spec.eni.subnet-ids` non-empty → the listed subnet in the node's VPC and AZ
   with the most free addresses (warn if not in the node subnet's route table).
2. `spec.eni.subnet-tags` non-empty → the tag-matching subnet in VPC+AZ with the
   most free addresses (same warning).
3. The node's own subnet (`node-subnet-id`) if `AvailableAddresses ≥ L.IPv4`.
4. A subnet in the same VPC and AZ that shares a route table with the node
   subnet, most free addresses first.
5. Any subnet in VPC+AZ, most free addresses first (warning if route table
   differs).
6. None → error "No matching subnet available for interface creation
   (VPC=… AZ=… SubnetIDs=… SubnetTags=…)".

### 5.9 Operator write ordering and retry

Status before spec (3.13 rationale). Two attempts per object; on any error
other than `NotFound` re-`Get`, copy into both the working and baseline copies,
and retry once; then fall back to the next interval. Per-node pool maintenance
backoff: exponential with jitter, first delay 10 ms-scale trigger interval,
maximum 5 m, reset to the minimum after 10 m without failures; the node
manager's cluster-size-dependent interval scaling of the reference MAY be
applied to the background resync.

### 5.10 Instance limits cache (AWS)

Full refresh via paginated `DescribeInstanceTypes`, trigger min interval 1 m,
per-call timeout 5 s, 2 retries. `Get(type)`: hit → return; miss and last
update < 1 m ago → not found; else trigger and wait for the refresh to finish
or 5.5 s (timeout + 10 %).

## 6. Configuration

All keys are registered in the flowsdn config registry (spec 00 §6.4) with the
reference names. "Agent"/"Operator" says which binary reads it.

### 6.1 Agent

| Key | Type | Default | Effect |
|---|---|---|---|
| `ipam` | string (immutable) | `cluster-pool` | mode (3.1) |
| `ipam-cilium-node-update-rate` | duration | `15s` | debounce of CiliumNode writes (3.6, 3.7) |
| `ipam-default-ip-pool` | string | `default` | fallback pool (3.3); MUST equal the operator's |
| `ipam-multi-pool-pre-allocation` | map `pool=int` | `default=8` | per-pool buffer (5.2) |
| `ipam-min-allocate` / `ipam-pre-allocate` / `ipam-max-allocate` | int | 0 / 0 / 0 | seeded into `spec.ipam.*` (cloud modes) |
| `ipam-static-ip-tags` | map | `{}` | `spec.ipam.static-ip-tags` (eni, azure) |
| `only-masquerade-default-pool` | bool | false | requires `enable-bpf-masquerade`; 3.6 |
| `enable-unreachable-routes` | bool | false | 3.18 |
| `local-router-ipv4` / `local-router-ipv6` | IP | "" | 3.16; mandatory in `delegated-plugin` |
| `install-uplink-routes-for-delegated-ipam` | bool | false | 3.8 |
| `ipv4-range` / `ipv6-range` | cidr or `auto` (immutable) | `auto` | 3.4 |
| `k8s-require-ipv4-pod-cidr` / `k8s-require-ipv6-pod-cidr` | bool | false | 3.4 |
| `ipv4-native-routing-cidr` / `ipv6-native-routing-cidr` | cidr | "" | validated against the VPC in cloud modes (3.9–3.11) |
| `eni-first-interface-index` | int ≥ 0 | 0 | `spec.eni.first-interface-index` |
| `eni-use-primary-address` | bool | false | `spec.eni.use-primary-address` |
| `eni-disable-prefix-delegation` | bool | false | `spec.eni.disable-prefix-delegation` |
| `eni-delete-on-termination` | bool | true | `spec.eni.delete-on-termination` |
| `eni-subnet-ids` / `eni-subnet-tags` / `eni-security-groups` / `eni-security-group-tags` / `eni-exclude-interface-tags` | list / map | empty | `spec.eni.*` |
| `azure-interface-name` | string | "" | `spec.azure.interface-name` |
| `alibabacloud-vswitches` / `alibabacloud-vswitch-tags` / `alibabacloud-security-groups` / `alibabacloud-security-group-tags` | list / map | empty | `spec.alibaba-cloud.*` |
| `enable-ip-masq-agent` | bool | false | adds non-masquerade CIDRs to `AllocationResult.CIDRs` (cloud modes) |
| `enable-endpoint-routes` | bool | false | required by ENI (Helm forces true), delegated, GKE |
| `auto-create-cilium-node-resource` | bool | true | Helm sets it in ENI mode; node discovery creates the CiliumNode before IPAM starts |

Validation (fatal): `delegated-plugin` rules of 3.8; `only-masquerade-default-pool`
without BPF masquerade; `ipam=eni`/`azure`/`alibabacloud` require
`routing-mode=native` and `enable-endpoint-routes=true` (Helm enforces; the
agent SHOULD enforce too).

### 6.2 Operator

| Key | Type | Default | Effect |
|---|---|---|---|
| `ipam` | string | `cluster-pool` (see 11.4 for binary selection) | which allocator starts |
| `parallel-alloc-workers` | int | 50 | 3.15 |
| `limit-ipam-api-qps` / `limit-ipam-api-burst` | float / int | 4.0 / 20 | cloud API limiter |
| `nodes-gc-interval` | duration | `5m` | 3.19 (0 disables) |
| `cluster-pool-ipv4-cidr` / `cluster-pool-ipv6-cidr` | list | `[]` (Helm: `10.0.0.0/8`, `fd00::/104`) | 3.5 |
| `cluster-pool-ipv4-mask-size` / `cluster-pool-ipv6-mask-size` | int | 24 / 112 (Helm IPv6: 120) | 3.5 |
| `auto-create-cilium-pod-ip-pools` | map | `{}` | 3.6 |
| `ipam-default-ip-pool` | string | `default` | 3.6 migration target and demand pool |
| `enable-cluster-pool-to-multi-pool-migration` | bool | false | 3.6 |
| `multi-pool-migration-workers` | int | 16 | 3.6 |
| `aws-release-excess-ips` | bool | false | enables 3.14 (and, for CRD nodes, 3.13) |
| `excess-ip-release-delay` | int (seconds) | 180 | 3.13/3.14 (AWS; Alibaba uses 0, Azure n/a) |
| `aws-enable-prefix-delegation` | bool | false | 3.9.3 |
| `aws-use-primary-address` | bool | false | primary ENI IP allocatable |
| `eni-tags` | map | `{}` | tags on created ENIs |
| `eni-gc-tags` | map | `{}` → derived | GC filter (3.9.2) |
| `eni-gc-interval` | duration | `5m` | 0 disables GC |
| `ec2-api-endpoint` | host | "" | base endpoint override |
| `aws-max-results-per-call` | int32 | 0 | page size; auto-switch to 1000 |
| `subnet-ids-filter` / `subnet-tags-filter` | list / map | empty | subnet discovery filters |
| `instance-tags-filter` | map | `{}` | instance discovery filter (AWS, Alibaba; ≤ 20 tags on Alibaba) |
| `azure-subscription-id` / `azure-resource-group` | string | "" → IMDS | 3.10 |
| `azure-user-assigned-identity-id` | string | "" → default chain | 3.10 |
| `azure-use-primary-address` | bool | false (Helm: true unless `azure.enabled`) | 3.10 |
| `alibaba-cloud-vpc-id` | string | "" → own VPC | 3.11 |
| `alibaba-cloud-release-excess-ips` | bool | false | 3.11 |
| `cluster-name` | string | `default` | ENI GC tag value |
| `enable-ciliumnode-crd` | bool (hidden) | true | false → one-off CiliumNode deletion (3.19) |

### 6.3 Keys accepted and ignored

`egress-masquerade-interfaces`, `install-no-conntrack-iptables-rules`,
`iptables-*` (ADR-0003: no iptables masquerade; logged once at startup).
`update-ec2-adapter-limit-via-api`, `aws-instance-limit-mapping`: removed in the
reference at 1.20; flowsdn rejects them as unknown keys like any other.

## 7. Failure modes

| Situation | Behavior |
|---|---|
| Cloud API throttling / errors during resync | resync fails → instances API marked unstable; all node maintenance refused ("instances API is unstable. Blocking mutating operations") and retried every 1 m; background sync metric `status=failed`. Successful resync clears it. AWS `OperationNotPermitted` on list calls → permanent switch to 1000-entry pages. |
| Rate limiter saturation | calls wait for a token (recorded in `api_rate_limit_duration_seconds`); a cancelled context returns the token. |
| ENI limit reached (`EmptyInterfaceSlots == 0`) | no interface creation; warning once per hour; node counted `at-capacity` when also no free IPs; `NeededIPs` stays > 0. |
| Subnet exhausted | `PrepareIPAllocation` skips interfaces in that subnet; `CreateInterface` picks another subnet (5.8) or fails "No matching subnet"; prefix exhaustion falls back to /32s. AWS eventual consistency can make `AllocateIPs` fail — logged at info, next run retries. |
| Attachment index conflict | retried up to 5 indexes; then the ENI is deleted. |
| Instance not running | "is not 'running'" errors mark the node stopped; maintenance paused for 1 m; a CiliumNode update marks it running again. |
| Instance deleted but CiliumNode present | resync finds no ENIs → "Instance not found! Please delete corresponding ciliumnode"; needed/excess zeroed; CiliumNode GC (3.19) removes it once the k8s Node is gone. |
| IMDS unavailable (operator) | AWS: cannot determine region → allocator init fails (operator exits after leader election, fatal). Own VPC id unknown → empty filter (all VPCs), info log. Azure: subscription/RG/cloud unresolvable and not configured → fatal. Alibaba: region unresolvable → fatal. |
| IMDS unavailable (agent) | node discovery cannot seed `spec.*` → fatal (ENI/Alibaba) or fatal on missing providerID (Azure). |
| Instance limits unknown | ENI/Alibaba: allocation skipped, `GetMaximumAllocatableIPv4 = 0` (warning: unlimited unless `max-allocate`), `GetMinimumAllocatableIPv4 = 8`. |
| Operator restart mid-allocation | cache rebuilt by the blocking resync; cloud state is ground truth. ENI: a CIDR attached but not yet acked by the agent is marked at seed and unmarked as soon as the agent lists it (well within 180 s). Multi-pool: `allocated` is occupied before any allocation; orphans preserved. Cluster-pool: existing `podCIDRs` occupied; conflicts stripped. |
| Agent restart | multi-pool/ENI: `allocated` is carried over until the informer syncs; restore re-allocates endpoint IPs with `allocate_without_sync`; `restore_finished` starts upstream writes and excess release. CRD: `status.ipam.used` rebuilt from restored endpoints before the first write. |
| Node deleted | CiliumNode delete → node manager stops triggers and drops the instance from cache; pool allocators release CIDRs; ENIs with `delete-on-termination` disappear with the instance; others are GC'd (3.9.2). |
| CiliumNode `409 Conflict` | re-read and retry (agent: next trigger run; operator: immediate second attempt then interval). |
| CiliumNode deleted while agent runs | agent keeps its last view ("IPAM will continue on last seen version"); node discovery recreates the resource. |
| Multiple `CiliumPodIPPool` match a pod | allocation fails; CNI retries; warning event. |
| Pool missing for a non-zero pre-allocation | agent waits at startup (3.6) — the agent is not ready until the operator creates the pool. |
| `spec.ipam.pools.allocated` lists a CIDR still in use but the operator removed it | agent keeps allocating nothing new from it, keeps reporting it; operator re-adopts it as orphan. |
| ENI primary IP would be released | never released (3.9.3); a stuck marked /32 equal to a primary is dropped from tracking. |
| Configured native routing CIDR outside the VPC | fatal at agent startup (3.9.1, 3.10, 3.11). |
| Static IP requested, none free | operator maintenance errors every run (backoff); agent blocks startup logging every 5 s. |
| Kernel lacks policy routing | 3.20 `Configure` fails → CNI ADD fails; startup check (§10) refuses ENI/Azure/Alibaba modes. |

## 8. Observability

### 8.1 Agent metrics

| Metric | Labels | Meaning |
|---|---|---|
| `cilium_ipam_capacity` | `family`, `cidr` (the alloc CIDR in `kubernetes`/`cluster-pool`, else `""`) | allocator capacity, set on every allocate/release |
| `cilium_ipam_events_total` | `action=allocate\|release`, `family` | counter |

### 8.2 Operator metrics (`cilium_operator_ipam_*`)

Per node (`target_node`): `available_ips` (= capacity), `used_ips`,
`needed_ips`. Per subnet (`subnet_id`): `ip_allocation_ops`, `ip_release_ops`,
`interface_creation_ops`; `available_ips_per_subnet{subnet_id,
availability_zone}`. Aggregates: `interface_candidates`,
`empty_interface_slots`, `nodes{category=total|in-deficit|at-capacity}`,
`resync_total`. Histograms: `allocation_duration_seconds{type=allocateIP|
createInterfaceAndAllocateIP, status=success|failed|<error class>, subnet_id}`,
`release_duration_seconds{type=releaseIP|releaseIPPrefixes, status, subnet_id}`,
`background_sync_duration_seconds{status}`. Trigger metrics for
`ipam-pool-maintainer`, `ipam-node-k8s-sync`, `ipam-node-instance-sync`:
`<name>_queued_total`, `<name>_folds`, `<name>_duration_seconds`,
`<name>_latency_seconds`. Node metrics MUST be deleted when the node is
deleted.

### 8.3 Cloud API metrics

`cilium_operator_<ec2|azure|alibabacloud>_api_duration_seconds{operation,
response_code}` (AWS: HTTP status text or `OK`/`Failed`; Azure/Alibaba:
`OK`/`Failed`) and `cilium_operator_<…>_api_rate_limit_duration_seconds{operation}`.
Operation names are the API action names (e.g. `DescribeNetworkInterfaces`,
`VirtualMachineScaleSetVMs.Update`, `CreateNetworkInterface`).

### 8.4 Status, logs, health

- `cilium-dbg status` shows `IPAM: IPv4: <used>/<capacity> allocated from
  <cidr>, IPv6: …` from `dump()`; `cilium-dbg ipam list` shows the owner map
  with pool prefix `<pool>/` for non-default pools; the debug status object
  dumps owners, timers and excluded IPs.
- Health (spec 00 §3.4): module `ipam` reports Degraded while waiting for
  pools/CIDRs/static IP/VPC CIDR at startup, OK afterwards; the operator's
  `ipam` module reports Degraded while the instances API is unstable.
- Log fields (names kept): `ipAddr`, `owner`, `poolName`, `family`, `cidr`,
  `instanceID`, `eniID`/`interface`, `subnetID`/`vswitchID`, `available`,
  `used`, `neededIPs`, `toRelease`, `remainingInterfaces`,
  `maxIPsToAllocate`, `selectedInterface`, `selectedPoolID`.
- Help message on every startup wait: "Check if cilium-operator pod is running
  and does not have any warnings or error messages." (users grep for it).

## 9. Test plan

Unit (U), privileged/kernel (P), cloud modes against **recorded-response fakes**
(F: real EC2 / ARM / ECS / OpenAPI responses captured once, scrubbed, committed
and replayed at the HTTP layer — ADR-0007, detailed in §9.1; this supersedes the
earlier plan of hand-written in-memory API servers), real-cloud e2e (E).

Agent core and pool selection (U): allocate/release/owner bookkeeping;
`allocate_next(family="")` releases IPv6 on IPv4 failure; excluded IP retry;
expiration timer start/stop/UUID mismatch/expiry release;
`TestManager_GetIPPoolForPod`, `PodAnnotationOverridesSelector`,
`NamespaceAnnotationOverridesSelector`, `SelectorBasedMatching`,
`SelectorMultipleMatches_Error`, `NoSelectorNoMatch`,
`RequirePoolMatchAnnotation` (pod / namespace / `false`), `NamespaceSelector`,
`handlePoolEvent_UpsertAndDelete`, `BadSelectorIgnored`, `DefaultPool`.

Host scope / bitmap (U): random-scan allocation, first/last IP options, /31 and
/32 ranges, `ErrFull`, `ErrNotInRange`, dual-stack CIDR derivation of 3.4.

Multi-pool agent (U): `Test_MultiPoolManager` (allocation, requested/allocated
writes, pending demand), `ReleaseAllCIDRs`, `ReleaseUnusedCIDR`,
`ReleaseUnusedCIDR_PreAlloc`, `Test_LocalNodeCIDRsSyncer`,
`UpdateNodeRetries` (update / updateStatus conflicts), `Test_neededIPCeil`
(table of 5.2), `Test_pendingAllocationsPerPool` (TTL expiry),
`TestAllocateNext_SkipMasquerade`, `UpdatesFirstLastIPSettingsBeforeAllocation`,
`WaitForAllPools`, `staticIPStatus`; reclaim of released CIDRs when demand
grows back (5.7).

ENI agent (U): `Test_validateENIConfig`, `TestBuildENIAllocationResult`
(secondary IP on eni-1/eni-2, unknown IP, native routing CIDR appended / not
when family disabled), `…PrefixDelegation` (IP in first/second prefix, outside,
IPv6 prefix, IPv6 native CIDR), `…IPMasq`, `…IPMasqIPv6`, `TestEniContainsIP`,
`TestAddressCoveredByPrefix`, `TestENIPoolsAccessorFromResource` (no ENIs,
/32 derivation, prefixes exclude covered addresses, IPv6 prefixes, excluded
ENIs), `TestENIMultiPoolAllocator`, `TestDeriveENIVpcCIDR`,
`TestAutoDetectENINativeRoutingCIDR` (auto, configured, subnet of VPC, fatal on
non-overlap), linear demand and `status.ipam.used` clearing; device
configurator against a fake netlink (P: `rp_filter`, address add, subnet route
delete, rename re-fetch).

CRD agent and handshake (U): `TestMarkForReleaseNoAllocate`,
`TestNodeStoreStaticIPStatus`, `TestAzureInterfaceCIDR` (deprecated fallback),
`TestAzureIPMasq`, `TestIPNotAvailableInPoolError`; pinned owner in `crd`;
startup minimum computation; all agent transitions of 3.13.

Operator node manager (U): `TestCalculateNeededIPs`, `TestCalculateExcessIPs`
(tables of 5.1), `TestStaticIPNeedsResolution`,
`TestSyncToAPIServerForNonExistingNode`, `TestPoolRequestedIPv4` (all six
sub-cases), `TestTrackMultiPoolAllocatedLocked` (seed, removed, reappearing,
detached cleanup, timestamp kept, prefix CIDR), `TestHandleMultiPoolCIDRRelease`
(non-multi-pool no-op, empty map, delay not elapsed, no actions, single IPs,
prefixes, only past-delay, re-check filter, error preserves, partial release,
multiple ENIs); handshake transitions and abort; status-before-spec ordering;
`pre-allocate` seeding; surge from pending pods.

AWS provider (F): `TestNodeManagerDefaultAllocation`, `PrefixDelegation`,
`ENIWithSGTags`, `MinAllocate20`, `MinAllocateAndPreallocate`,
`ReleaseAddress` (delay, ack, release), `ENIExcludeInterfaceTags`,
`ExceedENICapacity`, `InterfaceCreatedInInitialSubnet`, `ManyNodes` (parallel
workers), `InstanceNotRunning`, `InstanceBeenDeleted`, `StaticIP`,
`StaticIPAlreadyAssociated`, `StaticIPPrimaryENI`, `TestAllocateIPs_IPv6Prefix`,
`NoIPv6WhenNotRequested`, `CreateInterface_IPv6Only`, `TestGetNodeNames`,
`NodeManagerGet`; limits `TestGet`, `TestInitEC2APIUpdateTrigger`; subnet
selection order of 5.8; attachment index conflict retry; prefix-capacity
fallback; `OperationNotPermitted` pagination switch; ENI GC two-run delay and
25 cap; GC tag derivation (cluster-name, EKS tag, default).

Azure provider (F): VMSS vs VM assignment (ipconfig naming, ASG copy,
imageReference cleared), `Interfaces.List` + VMSS listing, targeted subnet
lookup, `succeeded`-state filter, primary hidden/exposed capacity, interface
name filter, public IP prefix by tags, resource-id parsing (VMSS name / VM
index / resource group), IMDS cloud names incl. unknown → error, sorted status
output equality.

Alibaba provider (F): vSwitch selection (ids vs tags vs most-free ≥
toAllocate), ENI index tag allocation and out-of-range, `maxENIIPCreate`,
attach wait polling, tag-filtered instance discovery batches, release with
delay 0, primary ENI excluded from capacity, gateway = last − 2.

Cluster-pool operator (U): `TestNodesPodCIDRManager_{Upsert,Delete,Resync,
allocateIPNets,allocateNext,releaseIPNets}`, `Test_splitPodCIDRs`,
`Test_syncToK8s` (create/update/status/delete, conflict path),
`TestNewNodesPodCIDRManager` (validation), `DuplicateIPv6CausesIPv4Duplication`
(strip conflicting CIDR, keep other family); cidrset `TestCIDRSetFullyAllocated`,
`TestIndexToCIDRBlock`, `RandomishAllocation`, `AllocationOccupied`,
`TestGetBitforCIDR`, `TestOccupy`, `TestCIDRSetv6`, `TestInvalidSubNetMaskSize`.

Multi-pool operator (U): `TestPoolAllocator`, `PoolErrors`, `AddUpsertDelete`,
`Test_addrsInPrefix`, `AllowFirstAndLastIPs`, `UpdateCIDRSets_ShrinkPool`,
`PoolUpdateWithCIDRInUse`, `TestOrphanCIDRs`, `OrphanCIDRsNotStolenFromAnotherPool`,
`UpdatePoolKeepOldCIDRs`, `TestNodeHandler`, `OrphanCIDRsAfterRestart`,
`OrphanCIDRsReleased`, `NodeHandlerRetries` (get+update, updatestatus),
`TestMigrateNode` (updated, transient retry, conflict refetch, deleted),
`TestUpdateStatusForFailure`; pool spec string parser incl. `allow-first-ip`.

Routing (P): `TestPrivilegedConfigure`, `ConfigureAzureMasquerade` (priority
110, table = ifindex), `ConfigureZeros` (catch-all CIDR without `to`),
`ConfigureRouteWithIncompatibleIP`, `DeleteRouteWithIncompatibleIP`,
`TestPrivilegedDelete` (all matching rules removed, tables retained),
`TestPrivilegedParse`; unreachable route add/remove; IPv6 link-local gateway
`dev` handling.

REST (U): `/ipam` family variants, expiration header, host-addressing;
`/ipam/{ip}` 400/409/501; `DELETE` refused while an endpoint uses the IP.

E2E (E; CI matrix as reference): EKS ENI with and without prefix delegation and
`awsReleaseExcessIPs`; AKS Azure IPAM dual-stack with `azure.resourceGroup`;
GKE with `ipv4NativeRoutingCIDR`; multi-pool with auto-created pools,
`ipMasqAgent`, endpoint routes; delegated IPAM on kind with `host-local`;
cluster-pool manager on EKS. Alibaba has no CI in the reference; flowsdn adds
an F suite only.

### 9.1 The `F` lane: recorded-response cloud fakes (ADR-0007)

**Added 2026-09-07 by amendment.** Every cloud mode specified normatively above
— `eni` (3.9), `azure` (3.10), `alibabacloud` (3.11) and GKE (3.12, which makes
no cloud API call and is therefore covered by an IMDS-only scenario set) — MUST
be tested in CI against recorded provider responses. No `F` test may reach a
live provider, and no `F` job may hold cloud credentials.

**Fixtures.** One directory per scenario:
`tests/cloud/<provider>/<scenario>/`, containing the ordered interactions as
`NNN-<operation>.json` plus a `scenario.toml` naming the scenario, provider,
region, the flowsdn operations performed and the capture date. Capture is a
manual, human-run `flowsdn-cloud-record` xtask against a throwaway account; it
is never part of CI. Because the fixtures *are* the contract, a change to how
flowsdn calls a provider API MUST land with a re-capture in the same commit.

**Scrubbing.** Capture writes through a scrubber that MUST replace,
deterministically and reversibly within a scenario, every account ID, ARN and
resource ID (ENI, subnet, VPC, security group, instance, image), subscription
and tenant ID, resource-group and VMSS name, Alibaba UID and vSwitch/VPC ID,
public IP, DNS name, `Authorization` / `x-amz-security-token` / MSI-token
header, bearer token and request signature. Private IPs and CIDRs inside the
test VPC are **kept** — they are the substance of the allocation assertions. A
committed fixture MUST NOT contain a credential, a real account identifier or a
signature; a pattern scan over `tests/cloud/**` runs *before* any fixture is
read and fails the build on a hit.

**Replay is at the HTTP layer, not at the SDK trait.** AWS uses
`aws-smithy-runtime`'s replay client where it fits and otherwise the shared
local replay server with `--ec2-api-endpoint` pointed at it; Azure and Alibaba
use the shared replay server with the SDK endpoint and credential source
overridden to a static test credential; IMDS and the Azure instance-metadata
endpoint are served by the same server. This is deliberate: it keeps the SDKs'
own **request signing, retry/backoff, pagination and error mapping** inside the
tested path, which stubbing the Rust traits would skip — and those are exactly
the layers 3.9–3.11 depend on (the `OperationNotPermitted` pagination switch of
the AWS paragraph above, the throttling backoff of `pkg/api/helpers/rate_limit`,
and Alibaba's own signed REST client, which has no vendor SDK to trust).
Matching is by method, path and canonicalized body, in scenario order. An
unmatched request fails the test and prints it beside the closest recorded
interaction; strict mode (the CI default) additionally fails on recorded
interactions never used, so a fixture set cannot silently rot.

**Scenarios every provider MUST carry** (ADR-0007 §4): happy-path node
bring-up; pre-allocation watermark growth (5.1); excess-IP release (3.13);
ENI creation, attach and tag; subnet selection with several candidates (5.8);
prefix delegation and the `InsufficientCidrBlocks` fallback (AWS); instance-type
limits lookup (5.10); API throttling with backoff; ENI-or-IP limit reached;
subnet exhausted; IMDS unavailable at startup; credential expiry mid-run;
operator restart mid-allocation; node deleted during allocation. The
provider-specific `F` lists earlier in this section are additional to, not a
substitute for, those fourteen.

**Drift detection.** Recorded fixtures go stale silently when a provider changes
its API, so a **weekly scheduled** job re-runs the capture xtask against the
live account and diffs the normalized result against the committed fixtures,
opening an issue on a difference. It gates nothing, runs on a schedule rather
than on a pull request, and is the **only** job in the repository that holds
cloud credentials — read-only where the provider supports it. The `E` lane
above is likewise never a pull-request gate.

## 10. Kernel and platform requirements

- Policy routing: `CONFIG_IP_MULTIPLE_TABLES`, `CONFIG_IPV6_MULTIPLE_TABLES`;
  FIB rules with `from`/`to` selectors, `FRA_TABLE` for table ids > 255,
  `RTM_NEWRULE`/`RTM_DELRULE`/`RTM_GETRULE` with dump filters; routes of type
  `unreachable`; `RTPROT_KERNEL` protocol tagging.
- Sysctl `net.ipv4.conf.<dev>.rp_filter` writable per interface.
- Netlink link events for hot-plugged cloud NICs (ENA on AWS, Mellanox/netvsc on
  Azure, virtio on Alibaba); interface renaming by udev is tolerated by the
  MAC-based re-fetch.
- No BPF in this area. Startup check (ADR-0001): in `eni`/`azure`/`alibabacloud`
  modes the agent MUST verify it can create a rule in a table > 255 and remove
  it, refusing to run otherwise.
- x86-64 and arm64 identical; Graviton instances are nitro, so prefix
  delegation applies. Minimum kernel per `docs/kernel-requirements.md` (6.6
  general, 6.12 stormcos); nothing here needs more.

## 11. Rust design notes

### 11.1 Crates

| Crate | Contents |
|---|---|
| `flowsdn-ipam-types` | serde types for 4.1/4.2 with exact JSON tags (`skip_serializing_if` for `omitempty`/`omitzero`), `IpNet`/`IpAddr` newtypes that serialize as strings, kube-rs `CustomResource` derives for `CiliumNode` and `CiliumPodIPPool`, `Limits`, `Subnet`, `VirtualNetwork`, `RouteTable`, `PoolQuota`, `InstanceMap` (`im::HashMap` copy-on-write), `Tags::matches`. No cloud SDK dependency (so the agent and the generic operator stay small). |
| `flowsdn-ipam` (agent) | `trait Allocator` (3.1), `Ipam` core (owners, excluded, timers, metrics), `HostScope`, `CidrPool` (5.6/5.7), `MultiPoolManager` generic over `trait PoolSpecAccessor { fn from_resource(&CiliumNode) -> IpamPoolSpec; fn to_resource(&mut CiliumNode, IpamPoolSpec) -> bool }` with `MultiPoolAccessor` and `EniAccessor`, `CrdAllocator` + `NodeStore` (3.7, 3.13 agent side), `NoOpAllocator`, `PoolMetadata` (3.3) over the `flowsdn-table` pod/namespace/pool tables, `ipam_api` (axum handlers for 3.2), `eni_device` (netlink device configuration), `infra_ips` (3.16). Bitmaps: `roaring` or `bitvec` with a `rand` random-scan. |
| `flowsdn-routing-cloud` (agent + CNI) | `RoutingInfo`, `configure`, `delete`, `reconcile_gateway_routes` over `rtnetlink`; sysctl via `/proc/sys`. Shared with the CNI binary (spec 09). |
| `flowsdn-operator-ipam` | `NodeManager`, `Node` (watermarks as free functions, handshake, CIDR release tracking), `trait NodeOperations` and `trait CloudInstances` (11.2), `ClusterPoolAllocator` + `NodesPodCidrManager` (3.5) + `CidrSet` (5.4), `PoolAllocator` + `NodeHandler` + migration (3.6), CiliumNode GC (3.19), metrics (8.2), `ApiLimiter` (`governor` token bucket recording waits). |
| `flowsdn-ipam-aws` | `aws-config` (default chain incl. IRSA and IMDS, `retry_config` with rate limiter disabled), `aws-sdk-ec2` with paginators, `aws-sdk-ec2::config::Builder::endpoint_url` for `--ec2-api-endpoint`, IMDS via `aws_config::imds::Client`; `Ec2Api` trait + in-memory fake; `InstancesManager`, `LimitsGetter`, `EniNode: NodeOperations`, ENI GC. Error classification by `ProvideErrorMetadata::code()`/`message()` for `InsufficientCidrBlocks`, `InvalidParameterValue`, `OperationNotPermitted`. |
| `flowsdn-ipam-azure` | Application-owned ARM REST over future pinned `azure_core`/`azure_identity` transport; `flowsdn-cloud-azure` provides request/polling contracts (12.2), not a live cloud allocator. IMDS still requires Metadata:true; AzureNode implements NodeOperations in the runtime integration. |
| `flowsdn-ipam-alibaba` | own RPC-style client over `reqwest`: query-parameter signing (RPC signature version 1.0, HMAC-SHA1, `SignatureNonce`, `Timestamp`) for the `ecs` 2014-05-26 and `vpc` 2016-04-28 APIs, credential chain (env AK/SK/STS token, ECS RAM role via metadata, OIDC RRSA), endpoints `<product>-vpc.<region>.aliyuncs.com`, paging by `NextToken`/`PageNumber`; `AlibabaNode: NodeOperations`; metadata client. Budget ~1k lines including the signer and a fake. |

`flowsdn-table` (spec 00) provides `LocalPodIPPool`, pods and namespaces tables
the agent reads; `flowsdn-config` supplies the keys of §6; fences (`spec 00
§3.4`) express "ipam-configured" and "ipam-restored".

### 11.2 Operator provider traits

```rust
#[async_trait]
pub trait CloudInstances: Send + Sync {
    fn create_node(&self, cn: &CiliumNode, node: Arc<NodeHandle>) -> Box<dyn NodeOperations>;
    fn pool_quota(&self) -> PoolQuotaMap;
    async fn resync(&self, ctx: &Ctx) -> Result<Instant>;               // full
    async fn instance_sync(&self, ctx: &Ctx, id: &str) -> Result<Instant>;
    fn has_instance(&self, id: &str) -> bool;
    fn delete_instance(&self, id: &str);
}

#[async_trait]
pub trait NodeOperations: Send + Sync {
    fn updated_node(&self, cn: &CiliumNode);
    fn populate_status_fields(&self, cn: &mut CiliumNode);
    async fn create_interface(&self, a: &mut AllocationAction) -> Result<(u32, ErrClass)>;
    async fn resync_interfaces_and_ips(&self) -> Result<(AllocationMap, InterfaceStats)>;
    fn prepare_ip_allocation(&self) -> Result<AllocationAction>;
    async fn allocate_ips(&self, a: &AllocationAction) -> Result<()>;
    async fn allocate_static_ip(&self, tags: &Tags) -> Result<IpAddr>;
    fn prepare_ip_release(&self, excess: u32) -> ReleaseAction;
    async fn release_ip_prefixes(&self, r: &ReleaseAction) -> Result<()>;
    async fn release_ips(&self, r: &ReleaseAction) -> Result<()>;
    fn max_allocatable_ipv4(&self) -> u32;
    fn min_allocatable_ipv4(&self) -> u32;
    fn is_prefix_delegated(&self) -> bool;
    fn attached_cidrs(&self) -> Vec<IpNet>;
    fn prepare_cidr_release(&self, cidrs: &[IpNet]) -> Vec<ReleaseAction>;
    async fn release_cidrs(&self, r: &ReleaseAction) -> (Vec<IpNet>, Result<()>);
}
```

`NodeManager` is generic over `Arc<dyn CloudInstances>`; the three cloud crates
implement both traits and expose `fn build(cfg: &OperatorConfig, metrics) ->
Result<Arc<dyn CloudInstances>>`. The k8s side is `trait CiliumNodeStore {
create, get, update(orig, new), update_status(orig, new) }` with the deep-equal
skip.

### 11.3 Concurrency

Per node one `tokio` task owns the maintenance loop, driven by an mpsc
"trigger" (debounced, min interval 10 ms) with exponential backoff state;
`Resync` fans out with a `Semaphore(parallel_alloc_workers)`; the instances
cache is an `RwLock` around persistent maps so readers never block API calls;
the full-vs-instance resync exclusion is a second `RwLock`. The agent's
`MultiPoolManager` is a single task with a `watch` of the CiliumNode, a
debounced writer (`tokio::time::interval` 1 m + trigger 15 s) and a
`Notify`-based wait for pool readiness; expiration timers are `tokio::spawn`ed
sleeps guarded by UUID.

### 11.4 One operator binary, provider selected at runtime

**DEVIATION (inventory 08, ADR-0001 "one static binary per component"):** the
reference ships five operator binaries with build tags and derives the default
`--ipam` from the binary name. flowsdn ships **one** `flowsdn-operator`
containing all providers (the cloud SDKs add size but no runtime cost when
idle). Provider selection: read `ipam` from the shared agent ConfigMap /
flags; start `ClusterPoolAllocator` for `cluster-pool`, `PoolAllocator` for
`multi-pool`, `flowsdn-ipam-aws` for `eni`, `-azure` for `azure`, `-alibaba`
for `alibabacloud`, nothing for `kubernetes`/`crd`/`delegated-plugin`. The
default is `cluster-pool`. Helm `operator.image.suffix`/`*Digest` variants map
to the same image (Helm spec). The IPAM subsystem runs inside the
leader-elected lifecycle (spec 08-operator); a lost lease exits the process.

### 11.5 Aya / kernel gaps

None: this area uses netlink and sysctl only. `rtnetlink` lacks rule `to`
selector helpers for some versions; a small `netlink-packet-route` encoder for
`FRA_SRC`/`FRA_DST`/`FRA_TABLE`/`FRA_PRIORITY`/`FRA_PROTOCOL` is expected.

## 12. Decision register (resolved and open)

1. **ENI pool compatibility — resolved #104.** Keep writing `spec.ipam.pool` in ENI mode
   alongside status and multi-pool fields. Preserve status-before-spec ordering; remove
   no compatibility field merely because the flowsdn agent does not consume it.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

2. **Azure client library — resolved #105.** Use application-owned ARM REST
   requests and recoverable LRO state, with a future exactly pinned `azure_core`
   pipeline plus `azure_identity` transport. Source-audited generated management
   crates 0.21.0 expose the routes and raw send APIs, but the generated NIC await
   poller ignores initial Retry-After and cannot checkpoint progress for restart.
   The Compute VMSS update await loop also repeats PUT instead of monitoring GET.
   These are concrete integration concerns, not a claim that the SDK is unmaintained.
   `flowsdn-cloud-azure` tests the REST contract without adding Azure dependencies.
   Network API is pinned to `2024-03-01`, Compute to `2024-07-01`; NIC/public-IP
   operations nested beneath Microsoft.Compute retain the Network API version.
   The inventory contains thirteen methods, superseding the earlier “eight” shorthand.
   Initial retry delay, async-header precedence, Location fallback, provisioning
   states, confirmed failure/cancellation, final resource GET, restart checkpoints,
   pagination authority and three cloud origins are explicit tested contracts.
   Never release VMSS ownership on timeout, caller cancellation, malformed replies
   or transport failure; persist uncertain outcomes and recover before new writes.
   The local checkpoint object does not implement durable ownership itself.
   Synthetic fixtures are not ADR-0007 recorded-response acceptance. HTTP transport,
   credential compatibility/pins, API payload allocation, durable reconciliation,
   real response replay and live validation remain implementation gates. See the
   [prototype and pinned-source audit](../../crates/flowsdn-cloud-azure/README.md).
3. **Azure mirror fields — resolved #106.** Read and write `interfaces[].cidr` and
   `addresses[].subnet` as mirrors of the current fields, without a feature flag. A
   future incompatible removal requires a separate migration decision.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

4. **VMSS update serialization — resolved #107.** Serialize mutating Azure operations
   per full VMSS resource ID, across all nodes of that scale set, retaining per-node
   serialization. Hold the asynchronous permit through long-running-operation completion
   or terminal failure. Caller cancellation stops waiting but does not release
   the owning reconciler's permit until remote completion or confirmed remote
   cancellation. Recover in-flight operations before new mutations on restart.
   Different scale sets remain independent.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

5. **AWS pagination fallback — resolved #108.** Keep the `OperationNotPermitted`
   fallback from page size 0 to 1000 for the provider client lifetime. Log once when
   switching and retry; do not override an explicitly configured nonzero size.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

6. **GKE real integration** (alias IP ranges via the Compute API). No
   precedent; recommendation: none until a concrete need (`ipam=kubernetes`
   covers GKE).
7. **ENI IPv6 compatibility — resolved #110.** Keep the reference model: one /80 prefix
   per node, no IPv6 secondary-address allocation, and no IPv6-prefix release. This
   preserves the specified API behavior and does not assert that IPv6-only EKS is
   validated.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

8. **Deterministic Alibaba release — resolved #111.** Choose the eligible secondary ENI
   with the most free releasable addresses; break ties by ascending ENI ID. Sort
   candidate IPs numerically before taking the requested count. Primary and used
   addresses remain excluded.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

9. **Alibaba credentials — resolved #112.** Support environment access keys, ECS
   RAM-role metadata credentials, and OIDC RRSA from the initial Alibaba implementation.
   RRSA exchanges the projected token with `AssumeRoleWithOIDC`; refresh expiring
   credentials and never log tokens or signing material.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

10. **Unused pod CIDR status field — resolved #113.** Retain the `status.ipam.pod-cidrs`
   type for wire decoding and schema compatibility. No flowsdn controller writes or uses
   it as allocation authority.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

### Batch 6: GKE allocation contract (#109)

GKE uses Kubernetes-provided PodCIDRs and native endpoint routes. Alias-IP
programming remains GKE-owned; no GCP allocator is added without a concrete new
requirement. Packaging validation rejects another IPAM/routing mode, missing
endpoint routes and a missing/noncanonical IPv4 native-routing CIDR. Actual GKE
cluster validation is still required before claiming provider support (#293).
