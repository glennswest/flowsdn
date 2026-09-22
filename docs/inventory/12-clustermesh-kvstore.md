# ClusterMesh and kvstore layer — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/kvstore/**`,
`pkg/kvstore/store`, `pkg/kvstore/allocator`, `pkg/kvstore/etcdinit`,
`pkg/kvstore/heartbeat`, `pkg/clustermesh/**` (incl. `common`, `types`,
`clustercfg`, `kvstoremesh`, `store`, `mcsapi`, `endpointslicesync`,
`operator`, `wait`), `clustermesh-apiserver/**`, `pkg/allocator` (remote-cache
glue), `pkg/identity/cache/allocator.go` (remote identities),
`pkg/ipcache/kvstore.go`, `pkg/node/store`,
`install/kubernetes/cilium/templates/clustermesh-*`,
`Documentation/network/clustermesh/**`, `Documentation/cmdref/clustermesh-apiserver*`.

## Purpose

The kvstore layer is Cilium's etcd client abstraction: a `BackendOperations`
interface (get/put/delete/list, create-only, "if-locked" transactional
variants, prefix list+watch, distributed locks, leases, user management) with a
single remaining backend, etcd (consul was removed; there is no `consul.go` and
no reference to consul under `pkg/kvstore`). On top of it sit the
`store` synchronizers (SharedStore for owned-key round-tripping, workqueue
SyncStore for one-way k8s->kvstore export, restartable WatchStore for
kvstore->local import, and a WatchStoreManager that gates watches on
"synced canary" keys) and the kvstore identity-allocator backend (master/slave
keys, cluster-id-prefixed ID ranges). ClusterMesh reuses exactly that layer to
export a cluster's nodes, identities, ip->identity mappings, shared services
and (optionally) EndpointSlices / MCS-API ServiceExports into an etcd exposed
by `clustermesh-apiserver`, and to import the same from every remote cluster
found in a config directory. `kvstoremesh` is an optional cacher that mirrors
all remote clusters' `cilium/state/*` into the local etcd under
`cilium/cache/*` so agents dial only one etcd.

## Components

| Path | Lines | Purpose |
|---|---|---|
| `pkg/kvstore/etcd.go` | 1701 | etcd backend: options, client creation, TLS reloader, rate limiter, list+watch with pagination/relist, txn-based `*IfLocked`, status checker, quorum lock, user mgmt |
| `pkg/kvstore/etcd_lease.go` | 314 | lease manager: `concurrency.Session` per lease, <=1000 keys/lease, expiry observers |
| `pkg/kvstore/etcd_debug.go` | 503 | `EtcdDbg`: parse config, resolve/dial/TLS each endpoint, print certs, `Get(cilium/.heartbeat)`, print etcd cluster ID |
| `pkg/kvstore/lock.go` | 176 | `LockPath`: local path mutex + etcd mutex, stale local lock GC (30 s) |
| `pkg/kvstore/backend.go` | 212 | `BackendOperations`, `ExtraOptions`, backend registry, `StatusCheckInterval` |
| `pkg/kvstore/client.go` | 145 | `Client` cell impl, `Start` with 5 s circuit breaker (`OptAsyncWaitForEstablished`), script commands |
| `pkg/kvstore/cell.go`, `config.go`, `kvstore.go`, `events.go`, `watcher_cache.go`, `metrics.go`, `trace.go`, `logfields.go` | 109/55/76/80/46/53/27/41 | Hive cell + flags, key prefix constants, event types, watcher local cache |
| `pkg/kvstore/commands.go`, `commands_transcode.go` | 148/76 | hive script cmds `kvstore/update|delete|list` (transcodes zstd+proto EndpointSlice values for display) |
| `pkg/kvstore/memory.go`, `dummy.go` | 293/113 | statedb-backed in-memory `Client` for tests/scripts; `SetupDummy` (etcd at `http://127.0.0.1:4002`) |
| `pkg/kvstore/etcdinit/init.go` | 293 | one-shot etcd auth bootstrap: users `root`, `admin-<cluster>`, `local-<cluster>`, `remote`; roles `root`, `local`, `remote`; key-range read perms; `AuthEnable` |
| `pkg/kvstore/heartbeat/cell.go` | 55 | writes RFC3339 time to `cilium/.heartbeat` every 60 s with lease (operator, apiserver, optionally kvstoremesh) |
| `pkg/kvstore/store/store.go` | 470 | `SharedStore`: JoinSharedStore, local keys re-created on delete, periodic resync, `SharedKeyDeleteDelay` |
| `pkg/kvstore/store/syncstore.go` | 371 | workqueue `SyncStore`: upsert/delete with retry, synced canary key write, lease-expiry re-enqueue |
| `pkg/kvstore/store/watchstore.go` | 265 | `restartableWatchStore`: list+watch to Observer, stale-drain on restart, entries/sync metrics |
| `pkg/kvstore/store/watchstoremgr.go` | 143 | `WatchStoreManager`: start per-prefix watch when `cilium/synced/<cluster>/<prefix>` appears (or immediately) |
| `pkg/kvstore/store/cell.go`, `metrics.go`, `doc.go` | 51/38/17 | `Factory`, metrics `kvstore_sync_queue_size`, `kvstore_sync_errors_total`, `kvstore_initial_sync_completed` |
| `pkg/kvstore/allocator/allocator.go` | 667 | identity allocator kvstore backend (`id/`, `value/`, `locks/` sub-prefixes, GC, lock GC) |
| `pkg/kvstore/allocator/doublewrite/backend.go` | 323 | CRD+kvstore double-write backend (`doublewrite-readkvstore` / `doublewrite-readcrd`) |
| `pkg/kvstore/*_test.go` (all) | 4397 | see Tests |
| `pkg/kvstore` total | 11269 | 6872 non-test |
| `pkg/clustermesh/common/config.go` | 327 | flags `clustermesh-config`, `clustermesh-cache-ttl`; fsnotify directory watcher; `cilium-host-aliases` parsing |
| `pkg/clustermesh/common/clustermesh.go` | 276 | remote-cluster set: add/remove with tombstones, `NumReadyClusters` |
| `pkg/clustermesh/common/remote_cluster.go` | 500 | per-remote connection controller, watchdog, cluster-config retrieval, status, cache TTL checker |
| `pkg/clustermesh/common/interceptor.go` | 114 | gRPC interceptors pinning the etcd cluster ID (`ErrClusterIDChanged`) |
| `pkg/clustermesh/common/factory.go` | 39 | `DefaultRemoteClientFactory`: builds kvstore client from `etcd.config=<file>` plus whitelisted `kvstore-opt`s |
| `pkg/clustermesh/common/services.go` | 218 | `GlobalServiceCache`, shared-services observer |
| `pkg/clustermesh/common/metrics.go` | 63 | `clustermesh_remote_clusters`, `_remote_cluster_failures`, `_last_failure_ts`, `_readiness_status`, `_cache_revocations` |
| `pkg/clustermesh/clustermesh.go` | 358 | agent `ClusterMesh`: per-remote watch stores, sync waiters, `Status()`, LB initializer |
| `pkg/clustermesh/remote_cluster.go` | 407 | agent `remoteCluster.Run`: validate config, reserve cluster ID, register nodes/services/ipcache/identities watches |
| `pkg/clustermesh/service_merger.go` | 121 | `ClusterService` -> LB backends (`writer.SetBackendsOfCluster`) |
| `pkg/clustermesh/selectbackends.go` | 110 | `service.cilium.io/affinity` local/remote/none backend selection |
| `pkg/clustermesh/cell.go`, `idsmgr.go`, `notifier.go` | 71/81/58 | Hive wiring, cluster-ID reservation, ipset/nodemanager sync notifiers |
| `pkg/clustermesh/clustercfg/*.go` | 121+124+48 | `cilium/cluster-config/<name>` Get/Set/Enforce (5 min refresh, watch-triggered) |
| `pkg/clustermesh/types/option.go`, `types.go`, `addressing.go` | 223/129/424 | `cluster-id`, `cluster-name`, `max-connected-clusters`, `CiliumClusterConfig`, `AddrCluster`/`PrefixCluster` (`ip@clusterID`) |
| `pkg/clustermesh/types/endpointslice/*` | 232 + 867 generated | `ClusterEndpointSlice` protobuf + zstd encoding |
| `pkg/clustermesh/store/store.go` | 278 | `ClusterService` JSON struct, validators |
| `pkg/clustermesh/kvstoremesh/*.go` + `reflector/*.go` | 223+310 / 236+68 | remote->local etcd reflectors, drain on disconnect, readiness |
| `pkg/clustermesh/wait/synced.go` | 87 | `clustermesh-sync-timeout` (1 min), `ForAll` |
| `pkg/clustermesh/mcsapi/*` | ~2600 incl tests | ServiceExport/ServiceImport controllers, CRD install, EndpointSlice mirror |
| `pkg/clustermesh/endpointslicesync/*` | ~1150 | operator: remote-cluster EndpointSlice generation for global services |
| `pkg/clustermesh/operator/*` | ~1000 | operator-side ClusterMesh (services + service exports only) |
| `pkg/clustermesh/namespace/*` | ~120 | `clustermesh.cilium.io/global` namespace annotation, `clustermesh-default-global-namespace` |
| `pkg/clustermesh` total | 20679 | incl. tests and generated pb |
| `clustermesh-apiserver/clustermesh/{cells,synchronizer,converters,users_mgmt,health}.go` | 176/259/334/222/53 | k8s->kvstore synchronizers, etcd user reconciliation, `/readyz` |
| `clustermesh-apiserver/kvstoremesh/{root,cells,api,health,lifecycle}.go` | 152/61/59/51/38 | leader-elected kvstoremesh, REST `GET /cluster` on `localhost:9889` |
| `clustermesh-apiserver/etcdinit/root.go` | 283 | init container: wipe data dir, run localhost etcd, call `ClusterMeshEtcdInit`, SIGTERM |
| `clustermesh-apiserver/common/cells.go`, `option/config.go`, `syncstate/`, `health/`, `metrics/` | 57/41/76/76/129 | shared cells, `--health-port` 9880, bootstrap sync state |
| `clustermesh-apiserver/*-dbg/*.go`, `mcsapi-coredns-cfg/*` | ~150 / ~350 | `troubleshoot`, `status`; CoreDNS auto-config for `clusterset.local` |
| `clustermesh-apiserver` total | 3624 | |
| `install/kubernetes/cilium/templates/clustermesh-*` | 1831 | Deployment (etcd-init, etcd, apiserver, kvstoremesh containers), TLS secrets (helm/certmanager/cronjob), `cilium-clustermesh` + `cilium-kvstoremesh` secrets, `clustermesh-remote-users` ConfigMap |
| `Documentation/network/clustermesh/*.rst` | ~2350 (+2975 excalidraw) | setup, global-services, affinity, mcsapi, policy, cloud prep |

## Features

- **etcd kvstore client** (`--kvstore=etcd`, default `""` = disabled on agent and
  operator, forced `etcd` in clustermesh-apiserver). `--kvstore-opt` keys:
  `etcd.address`, `etcd.config` (path to etcd client YAML; one of the two is
  required), `etcd.qps` (default 20), `etcd.bootstrapQps` (applies until
  `BootstrapComplete` channel closes; apiserver uses 10000), `etcd.maxInflight`
  (default = qps), `etcd.limit` (list page size, default 256, 0 = unlimited),
  `etcd.keepaliveHeartbeat` (15 s), `etcd.keepaliveTimeout` (25 s). Other
  flags: `--kvstore-lease-ttl` (15 m, must be in [25 s, 24 h]),
  `--kvstore-max-consecutive-quorum-errors` (2). `kvstore-connectivity-timeout`
  and `kvstore-periodic-sync` no longer exist in v1.20 (initial connection
  timeout is hard-coded 15 min; SharedStore resync interval is per-store, e.g.
  30 min for nodes).
- **Quorum / liveness detection**: lock-based quorum probe on
  `cilium/.initlock/<random-hex>` every status interval; per-endpoint
  `Status()` RPC; heartbeat key watch. Status interval 30 s OK / 5 s failing,
  scaled by cluster size (`ClusterSizeDependantInterval`, table in
  `backend.go`). After `MaxConsecutiveQuorumErrors` the status turns
  `Failure` and an error is pushed to `StatusCheckErrors()`.
- **Leases**: generic lease manager (TTL = `kvstore-lease-ttl`) and a lock
  lease manager (TTL = `LockLeaseTTL` = 25 s). Keys attach to the current
  lease until it has 1000 keys, then a new lease is granted. On session loss,
  `RegisterLeaseExpiredObserver(prefix, fn)` callbacks fire per key so
  SyncStores re-upsert.
- **Distributed locks**: `LockPath(path)` = etcd `concurrency.Mutex` on
  `<path>` under the lock lease; callers add `.lock` suffix via `getLockPath`
  in allocator. Local `pathLocks` prevents in-process contention; stale local
  entries force-unlocked after `KVStoreStaleLockTimeout` = 30 s
  (`RunLockGC` in daemon). Lock acquisition timeout 1 min.
- **Heartbeat**: `cilium/.heartbeat` written every `HeartbeatWriteInterval` =
  1 min by cilium-operator, clustermesh-apiserver, and kvstoremesh when
  `--enable-heartbeat` (Helm sets it true unless identity mode is CRD).
  Remote-cluster clients (`NoEndpointStatusChecks && NoLockQuorumCheck`)
  declare quorum failure if no heartbeat event for 2 min.
- **Identity allocation modes** (`--identity-allocation-mode`, agent default
  `kvstore`, Helm default `crd`): `kvstore`, `crd`, `doublewrite-readkvstore`,
  `doublewrite-readcrd`.
- **ClusterMesh agent side**: enabled when `cluster-id != 0` and
  `--clustermesh-config` is set (Helm mounts `/var/lib/cilium/clustermesh`
  from secret `cilium-clustermesh` + `clustermesh-apiserver-remote-cert` +
  `clustermesh-apiserver-local-cert`; env `CILIUM_CLUSTERMESH_CONFIG`). Every
  file in that directory whose content contains `endpoints:` is a remote
  cluster; filename = cluster name. fsnotify on directory and each file (hash
  compared) adds/updates/removes connections at runtime.
- **Cluster identity**: `--cluster-name` (regex
  `^([a-z0-9][-a-z0-9]*)?[a-z0-9]$`, max 32), `--cluster-id` (1..255 or 1..511),
  `--max-connected-clusters` (255 or 511; all clusters must match; changes
  identity bit split). Buggy-ID guard: ID with bit 0x80 set is refused on
  ENI/AlibabaCloud IPAM or `aws-cni` chaining unless hidden
  `--allow-unsafe-policy-skb-usage`.
- **Global services**: annotations `service.cilium.io/global=true` (also
  `io.cilium/global-service`), `service.cilium.io/shared` (default true when
  global; `io.cilium/shared-service`), `service.cilium.io/affinity=local|remote|none`
  (`io.cilium/service-affinity`), `service.cilium.io/global-sync-endpoint-slices`
  (operator EndpointSlice mirroring, needs `--clustermesh-enable-endpoint-sync`).
  Remote backends are merged into the local LB tables with
  `source.ClusterMesh` and `ClusterID`; `SelectBackends` implements affinity.
- **Service v2 rollout** (hidden `--clustermesh-service-v2`:
  `prefer-legacy` default, `prefer-endpointslice`, `only-endpointslice`):
  chooses between watching `services/v1` (legacy `ClusterService`) or
  `endpointslices/v1`; advertised to peers via
  `capabilities.endpointSlicesExportMode`.
- **MCS-API** (`--clustermesh-enable-mcs-api`, `--clustermesh-mcs-api-install-crds`
  default true): ServiceExport -> `cilium/state/serviceexports/v1/...`,
  operator builds ServiceImport + derived Services; apiserver
  `mcsapi-coredns-cfg` job patches CoreDNS for `clusterset.local`.
- **Global namespaces**: `--clustermesh-default-global-namespace` (true);
  annotation `clustermesh.cilium.io/global=true|false` on Namespace; non-global
  namespaces' identities/endpoints/services are not exported (converted to
  deletes by the apiserver synchronizer).
- **KVStoreMesh** (Helm `clustermesh.apiserver.kvstoremesh.enabled`, default
  true; `kvstoreMode: internal|external`): mirrors each remote cluster's state
  into the local etcd under `cilium/cache/...`, rewrites the remote
  `cilium/cluster-config/<name>` with `cached: true, syncedCanaries: true`.
  Flags: `--per-cluster-ready-timeout` 15 s, `--global-ready-timeout` 10 m,
  `--enable-heartbeat`, hidden `--disable-drain-on-disconnection`. Leader
  election via lock `cilium/kvstoremesh-lock`.
- **Cache TTL** (`--clustermesh-cache-ttl`, default 0 = never): if a remote
  cluster stays disconnected longer than the TTL, cached services/endpoint
  slices/service exports are revoked (agent: services drained; kvstoremesh:
  reflectors with `WithRevocation()` drained).
- **Remote cluster status** exposed in `GET /healthz` (`cluster-mesh` field),
  operator `GET /cluster`, kvstoremesh `GET /cluster` (`localhost:9889`).
- **etcd user management** (`--cluster-users-enabled`,
  `--cluster-users-config-path=/var/lib/cilium/etcd-config/users.yaml`):
  reconciles etcd users from `users: [{name, role}]` (Helm generates
  `remote-<cluster>` / role `remote` per configured cluster; only when
  `tls.authMode != legacy`).
- **Cluster-aware addressing / inter-cluster SNAT**: only `#ifdef
  ENABLE_CLUSTER_AWARE_ADDRESSING` / `ENABLE_INTER_CLUSTER_SNAT` blocks in
  `bpf/lib/{conntrack_map,nat,nodeport,nodeport_egress}.h` and
  `bpf/node_config.h`; **no Go flag emits these defines in v1.20.1**
  (`enable-cluster-aware-addressing` / `enable-inter-cluster-snat` do not
  exist in `pkg/option`). The Go-side per-cluster maps
  (`pkg/maps/ctmap/per_cluster_ctmap.go`: outer `cilium_per_cluster_ct_*`,
  `pkg/maps/nat/per_cluster_nat.go`: `cilium_per_cluster_snat_*`) and the
  `ClusterID uint16` in the ipcache map key remain.

## Data model

### Key schema (all under `cilium/`)

| Key | Value | Lease | Writer |
|---|---|---|---|
| `cilium/.initlock/<rand-hex>` | etcd mutex key | lock lease (25 s) | every client with quorum check |
| `cilium/.heartbeat` | RFC3339 timestamp | yes | operator, apiserver, kvstoremesh |
| `cilium/kvstoremesh-lock` | etcd mutex | lock lease | kvstoremesh leader |
| `cilium/cluster-config/<cluster-name>` | JSON `CiliumClusterConfig` (below) | yes | agent/operator/apiserver enforcer (`UpdateIfDifferent`, refresh 5 min, re-written on foreign change or delete); kvstoremesh rewrites for cached clusters |
| `cilium/synced/<cluster-name>/cilium/state/nodes/v1` | RFC3339 | yes | SyncStore canary after initial k8s list flushed |
| `cilium/synced/<cluster>/cilium/state/services/v1` | RFC3339 | yes | idem |
| `cilium/synced/<cluster>/cilium/state/identities/v1` | RFC3339 | yes | idem (override: canary at `identities/v1`, keys under `identities/v1/id`) |
| `cilium/synced/<cluster>/cilium/state/ip/v1` | RFC3339 | yes | idem (keys under `ip/v1/default`) |
| `cilium/synced/<cluster>/cilium/state/endpointslices/v1`, `.../serviceexports/v1` | RFC3339 | yes | idem |
| `cilium/synced/<cluster>/cilium/cache/<prefix>` | RFC3339 | yes | kvstoremesh reflectors (canary for cached copies) |
| `cilium/state/nodes/v1/<cluster>/<node-name>` | JSON `node.Node` | yes | agent `NodeRegistrar` (SharedStore, resync 30 min) or apiserver from `CiliumNode` |
| `cilium/state/identities/v1/id/<numeric-id>` | label string (see below) | **no lease** (master key) | agent allocator `CreateOnly`; apiserver from `CiliumIdentity` |
| `cilium/state/identities/v1/value/<label-string>/<node-ip>` | decimal numeric id | yes (slave key) | agent allocator per node using the identity |
| `cilium/state/identities/v1/locks/<label-string>.lock` | etcd mutex | lock lease | allocator around allocate/release/GC |
| `cilium/state/ip/v1/default/<ip>` | JSON `IPIdentityPair` | yes | agent `IPIdentitySynchronizer` (`UpdateIfDifferent`) per local endpoint; apiserver from `CiliumEndpoint`/`CiliumEndpointSlice` |
| `cilium/state/services/v1/<cluster>/<namespace>/<name>` | JSON `ClusterService` | yes | apiserver/operator `service_sync` (only if `service.cilium.io/shared`) |
| `cilium/state/endpointslices/v1/<cluster>/<namespace>/<slice-name>` | zstd(protobuf `ClusterEndpointSlice`) | yes | apiserver `endpointslice_export_sync` |
| `cilium/state/serviceexports/v1/<cluster>/<namespace>/<name>` | JSON `MCSAPIServiceSpec` | yes | apiserver `mcsapi.ServiceExportSyncCell` |
| `cilium/cache/nodes/v1/<cluster>/<node>` etc. | verbatim copy of remote value | yes | kvstoremesh reflector; identities land at `cilium/cache/identities/v1/<cluster>/id/<id>`, ipcache at `cilium/cache/ip/v1/<cluster>/<ip>` |

Address space constant `DefaultAddressSpace = "default"`. `JoinKey` collapses
`//` and strips trailing `/`; `StateToCachePrefix` replaces the leading
`cilium/state` with `cilium/cache`.

### Value encodings

`CiliumClusterConfig` (`pkg/clustermesh/types/types.go`), `encoding/json`, all
`omitempty`:

```
{ "id": <uint32>,
  "capabilities": {
     "syncedCanaries": bool,          // reader must wait for cilium/synced/<name>/<prefix>
     "cached": bool,                  // data lives under cilium/cache/<prefix>/<name>
     "maxConnectedClusters": 255|511,
     "serviceExportsEnabled": *bool,  // nil = peer predates MCS-API
     "endpointSlicesExportMode": "" | "services-and-endpointslices" | "endpointslices-only" } }
```

`node.Node` (`pkg/node/types/node.go`) has **no json tags**, so Go field names
are the wire names: `Name`, `Cluster`, `IPAddresses` (`[{Type:
"InternalIP"|"ExternalIP"|"CiliumInternalIP", IP}]`), `IPv4AllocCIDR`,
`IPv4SecondaryAllocCIDRs`, `IPv6AllocCIDR`, `IPv6SecondaryAllocCIDRs`,
`IPv4HealthIP`, `IPv6HealthIP`, `IPv4IngressIP`, `IPv6IngressIP`, `ClusterID`,
`Source`, `EncryptionKey` (uint8 IPsec key index), `Labels`, `Annotations`,
`WireguardPubKey`, `BootID`. Key name = `<Cluster>/<Name>`. Unmarshal
validates `Cluster` and `Name` non-empty and `ClusterID` valid unless equal to
the local ID; readers add `ClusterNameValidator(name)`, `NameValidator()`
(key == name) and `ClusterIDValidator(&rc.clusterID)`.

`IPIdentityPair` (`pkg/identity/identity.go`):

```
{ "IP": "10.0.1.5", "Mask": null|"...", "HostIP": "192.168.1.10", "ID": 65538,
  "Key": 0, "Metadata": "", "K8sNamespace": "...", "K8sPodName": "...",
  "K8sServiceAccount": "...", "NamedPorts": [{"Name","Port","Protocol"}] }
```

Key name = `PrefixString()` (IP, or `ip/len` when Mask set). `Key` is the
IPsec key index used by the encryption datapath; `HostIP` is the node the
endpoint lives on (used for tunnel/ipcache `tunnel_endpoint`).

Identity master key value = `GlobalIdentity.GetKey()` = concatenation of
`Label.FormatForKVStore()` for the sorted label array, i.e.
`<source>:<key>=<value>;` per label with a trailing `;` (e.g.
`k8s:app=foo;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.kubernetes.pod.namespace=default;`).
The apiserver writes the same string from `CiliumIdentity.SecurityLabels` via
`Map2Labels(...).SortedList()`. The slave key is
`value/<that string>/<node-suffix>` where node-suffix is the local node IP
(`GetNodeSuffix`, IPv4 preferred); `prefixMatchesKey` relies on the trailing
`;` so a label string is never a prefix of another.

`ClusterService` (`pkg/clustermesh/store/store.go`):

```
{ "cluster": "c1", "namespace": "ns", "name": "svc",
  "frontends": { "10.96.0.10": { "http": {"Protocol":"TCP","Port":80} } },
  "backends":  { "10.0.1.5":   { "http": {"Protocol":"TCP","Port":8080} } },
  "hostnames": { "10.0.1.5": "pod-hostname" },          // omitempty
  "zones": { "10.0.1.5": {"zone":"a","forZones":[{"name":"a"}]} }, // omitempty
  "labels": {...}, "selector": {...},
  "includeExternal": true, "shared": true, "clusterID": 1 }
```

`PortConfiguration = map[portName]*loadbalancer.L4Addr`. Key name =
`<cluster>/<namespace>/<name>`; validators check cluster name == filename,
`<namespace>/<name>` == key suffix, `clusterID` == the ID from the cluster
config. The apiserver always sets `Shared=true, IncludeExternal=true`
(unshared services are deleted from the store), copies k8s `Labels` and
`Spec.Selector`, frontends = ClusterIPs x ports (headless services skipped),
backends from EndpointSlices.

`MCSAPIServiceSpec`: `cluster`, `name`, `namespace`, `annotations`, `labels`
(plus legacy capitalised duplicates `Labels`/`Annotations` written on marshal
for old readers), `exportCreationTimestamp`, `ports` (MCS `ServicePort`),
`type` (`ClusterSetIP`|`Headless`), `sessionAffinity`,
`sessionAffinityConfig`, `ipFamilies`, `internalTrafficPolicy`,
`trafficDistribution`.

`ClusterEndpointSlice`: protobuf message (`cluster`, `clusterID`, `namespace`,
`name`, `labels`, `annotations`, `addressType`, repeated slim discovery/v1
`endpoints`, `ports`) then **zstd-compressed** (decoder cap 16 MiB). JSON
only for debug output.

### Identity numbering across clusters

`NumericIdentityBitlength = 24` usable bits (top 8 bits are the scope:
`0` global, `1<<24` local, `2<<24` remote-node). `clusterIDBits =
log2(ClusterIDMax+1)` = 8 (255) or 9 (511); `clusterIDShift = 24 -
clusterIDBits` = 16 or 15. For cluster ID `c > 0`, allocation range is
`[c << shift, ((c+1) << shift) - 1]`: 65536 per cluster with 255, 32768 with
511. Cluster 0 (no mesh) allocates `[256, 65535]`. Reserved identities
(< 256) are global and not scoped. The allocator applies `WithPrefixMask(ID <<
shift)` and `WithMin/WithMax`; remote caches validate every observed identity
(`clusterIDValidator`) and every ipcache pair (`WithIdentityValidator`) against
the remote cluster's range; identities also carry the label
`k8s:io.cilium.k8s.policy.cluster=<name>` and `clusterNameValidator` checks
it. `NumericIdentity.ClusterID()` = `(id >> shift) & ClusterIDMax`.

### BPF maps touched (cluster-aware)

`cilium_ipcache` key: `{prefixlen u32, cluster_id u16, pad u8, family u8,
ip[16]}` — remote entries are inserted with `cluster_id = 0` unless the
watcher has `WithClusterID` (only used by tests/extensions;
`AnnotateIPCacheKeyWithClusterID` produces `ip@id`). Per-cluster CT/SNAT
outer maps (`cilium_per_cluster_ct_{tcp4,any4,tcp6,any6}`,
`cilium_per_cluster_snat_v{4,6}_external`) are array-of-maps indexed by
cluster ID; created only under the dead `ENABLE_CLUSTER_AWARE_ADDRESSING`
path.

### Files on disk

- Agent: `/var/lib/cilium/clustermesh/<cluster-name>` (etcd client YAML),
  `<cluster-name>.etcd-client-ca.crt|.etcd-client.crt|.etcd-client.key`
  (per-cluster certs when provided), `common-etcd-client-ca.crt`,
  `common-etcd-client.crt|.key` (from `clustermesh-apiserver-remote-cert`, CN
  `remote`), `local-etcd-client-ca.crt|.crt|.key` (from
  `clustermesh-apiserver-local-cert`, CN `local-<cluster>`, used when
  kvstoremesh is on and agents dial the local apiserver). Secret mode 0400.
- etcd client YAML (etcd `clientv3/yaml` format plus Cilium extension):
  ```
  endpoints:
  - https://c2.mesh.cilium.io:2379      # or https://<address>:<port>, or https://clustermesh-apiserver.<ns>.svc:2379 (kvstoremesh)
  trusted-ca-file: /var/lib/cilium/clustermesh/common-etcd-client-ca.crt
  key-file: /var/lib/cilium/clustermesh/common-etcd-client.key
  cert-file: /var/lib/cilium/clustermesh/common-etcd-client.crt
  cilium-host-aliases:                  # optional; static resolution, fallback to k8s service resolver
  - hostname: c2.mesh.cilium.io
    ips: [1.2.3.4]
  ```
  Cert/key files are re-read on every TLS handshake
  (`getClientCertificateReloader`).
- Apiserver pod: `/var/lib/cilium/etcd-config.yaml` (from `cilium-config`
  ConfigMap key `etcd-config`), `/var/lib/cilium/etcd-secrets/{ca.crt,tls.crt,tls.key}`
  (admin cert, CN `admin-<cluster>`), `/var/lib/cilium/etcd-config/users.yaml`,
  etcd sidecar `/var/lib/etcd-secrets/{ca.crt,tls.crt,tls.key}` (server cert,
  CN `clustermesh-apiserver.<ns>.svc`, SANs incl. `*.mesh.cilium.io`,
  `127.0.0.1`, `::1`), data dir `/var/run/etcd` (emptyDir, `storageMedium`
  Disk|Memory). kvstoremesh: `/var/lib/cilium/clustermesh` from secret
  `cilium-kvstoremesh` (+ `clustermesh-apiserver-remote-cert` as `common-*`).
- Agent standalone etcd (`etcd.enabled`): `/var/lib/etcd-config/etcd.config`
  and `/var/lib/etcd-secrets/etcd-client{-ca.crt,.crt,.key}`.

## External interfaces

- **etcd gRPC (client side)**: KV `Range` (with prefix, sort, limit, rev for
  pagination; key `+"\x00"` continuation), `Put` (with lease), `DeleteRange`,
  `Txn` (compare `Version(key)==0` for create-only; mutex `IsOwner()` compare
  for `*IfLocked`), `Watch` (`WithRequireLeader`, `WithPrefix`, `WithRev`;
  `ErrCompacted` triggers full relist, stale keys deleted via
  `watcherCache.MarkAllForDeletion`), Lease `Grant` + `KeepAlive` (via
  `concurrency.Session`), Lock via `concurrency.Mutex` (Txn on
  `<path>/<lease-id-hex>`), Maintenance `Status(endpoint)` (version, leader
  id), Auth `UserAddWithOptions{NoPassword}`, `UserGrantRole`, `UserDelete`,
  `RoleAdd`, `RoleGrantPermission(read, range)`, `AuthEnable`. TLS client
  certs are the auth credential (etcd `--client-cert-auth`; CN = etcd user).
  gRPC dial: `DialTimeout=0`, keepalive 15 s / 25 s, custom context dialer
  (k8s Service resolver + host aliases), unary+stream interceptors that read
  `ResponseHeader.cluster_id` and abort with `ErrClusterIDChanged` if the
  etcd cluster behind an endpoint changes (forces reconnect + drain).
- **etcd server (apiserver pod)**: `etcd --client-cert-auth
  --listen-client-urls=https://0.0.0.0:2379 --auto-compaction-retention=1
  --enable-grpc-gateway=false --listen-metrics-urls=http://0.0.0.0:<port>`;
  exposed by Service `clustermesh-apiserver` (`LoadBalancer`/`NodePort`
  32379/`ClusterIP`) on port 2379. Auth modes (`clustermesh.apiserver.tls.authMode`):
  `legacy` (single `remote` user, role `root`), `migration` (default; `remote`
  user with read-only `remote` role plus per-cluster `remote-<name>` users),
  `cluster` (per-cluster users only).
- **etcd ACLs** (`pkg/kvstore/etcdinit`): role `remote` = read on
  `cilium/.heartbeat`, `cilium/state/`, `cilium/cluster-config/<local-name>`,
  `cilium/synced/<local-name>/`; role `local` = read on `cilium/.heartbeat`,
  `cilium/cache/`, `cilium/cluster-config/`, `cilium/synced/`; `admin-<name>`
  and `root` = role `root`.
- **REST**: agent `GET /healthz` -> `StatusResponse.cluster-mesh:
  {clusters: [RemoteCluster]}`; operator `GET /cluster` -> `[RemoteCluster]`;
  kvstoremesh `GET /cluster` (default `localhost:9889`, flag
  `--api-serve-addr`). `RemoteCluster` JSON: `name`, `ready`, `connected`,
  `status` (etcd status string + `, ID: <etcd-cluster-id-hex>`),
  `num-nodes`, `num-shared-services`, `num-endpoints`, `num-identities`,
  `num-endpoint-slices`, `num-service-exports`, `num-failures`,
  `last-failure`, `synced: {nodes, services, identities, endpoints,
  endpoint-slices*, service-exports*}`, `config: {required, retrieved,
  cluster-id, kvstoremesh, sync-canaries, service-exports-enabled,
  endpoint-slices-export-mode}`. `ready` requires connected + config
  retrieved + all enabled stores synced + `registered`.
- **Health**: apiserver/kvstoremesh `GET /readyz` on `--health-port` (9880 /
  Helm 9881 for kvstoremesh) -> 200 `Ready` once all `SyncState` resources
  finished initial sync; kvstoremesh forces ready after
  `--global-ready-timeout`.
- **CLI**: `cilium-dbg status` prints `ClusterMesh: N/M remote clusters
  ready` and per-cluster lines; `cilium-dbg troubleshoot clustermesh
  [--clustermesh-config /var/lib/cilium/clustermesh/ --timeout 5s
  --without-service-resolution]` runs `EtcdDbg` per config file (DNS,
  TCP, TLS, cert dump, `Get cilium/.heartbeat`, etcd cluster ID);
  `cilium-dbg troubleshoot kvstore`; `cilium-dbg kvstore get|set|delete`;
  `cilium-operator status clustermesh`, `troubleshoot clustermesh|kvstore`;
  `clustermesh-apiserver clustermesh-dbg troubleshoot
  [--etcd-config /var/lib/cilium/etcd-config.yaml]`, `kvstoremesh-dbg status
  [--verbose]`, `kvstoremesh-dbg troubleshoot`. Hive script commands
  `kvstore/list [--keys-only|--values-only|-o json]`, `kvstore/update`,
  `kvstore/delete`. The `cilium clustermesh enable|connect|status` CLI is
  not in this repo (cilium-cli); it creates/reads secrets
  `cilium-clustermesh`, `cilium-kvstoremesh`, `clustermesh-remote-users`,
  the `clustermesh-apiserver-*-cert` secrets and reads `/healthz`.
- **Metrics**: `cilium_kvstore_operations_duration_seconds`,
  `cilium_kvstore_events_queue_seconds`, `cilium_kvstore_quorum_errors_total`,
  `cilium_kvstore_sync_queue_size{scope,source_cluster}`,
  `cilium_kvstore_sync_errors_total`, `cilium_kvstore_initial_sync_completed{scope,source_cluster,action=read|write}`,
  `cilium_clustermesh_remote_clusters`, `..._remote_cluster_failures`,
  `..._remote_cluster_last_failure_ts`, `..._remote_cluster_readiness_status`,
  `..._remote_cluster_cache_revocations`, `..._global_services`,
  `..._remote_cluster_nodes|services|endpoints`; apiserver
  `cilium_clustermesh_apiserver_bootstrap_seconds`; kvstoremesh
  `cilium_kvstoremesh_leader_election_status`.
- **Kubernetes objects** (Helm): Deployment `clustermesh-apiserver`
  (containers `etcd-init`, `etcd`, `apiserver`, `kvstoremesh`), Service
  `clustermesh-apiserver` + metrics Service, ServiceMonitor, PDB, ClusterRole
  (read CiliumNode/CiliumIdentity/CiliumEndpoint/CiliumEndpointSlice,
  Services, EndpointSlices, Namespaces, ServiceExports), TLS CronJob
  (`schedule: "0 0 1 */4 *"`), cert-manager Certificates, CoreDNS MCS-API
  Job. Agent ConfigMap keys: `cluster-name`, `cluster-id`,
  `max-connected-clusters`, `clustermesh-cache-ttl`,
  `clustermesh-enable-endpoint-sync`, `clustermesh-enable-mcs-api`,
  `clustermesh-mcs-api-install-crds`, `clustermesh-default-global-namespace`,
  `policy-default-local-cluster`, `identity-allocation-mode`, `kvstore`,
  `kvstore-opt`, `etcd-config`.

## Dependencies

- Inventory areas: identity/policy (numeric identity scoping, well-known
  identities carry `io.cilium.k8s.policy.cluster=<name>`), ipcache (remote
  `IPIdentityPair` upsert with `source.ClusterMesh`, `HostIP`, `Key`),
  node manager (`NodeUpdated/NodeDeleted` with `source.ClusterMesh`,
  `MeshNodeSync`, ipset initializer), load balancer writer
  (`SetBackendsOfCluster`, `DeleteBackendsOfServiceFromCluster`,
  `RegisterInitializer("clustermesh")`, `SetSelectBackendsFunc`), encryption
  (IPsec `EncryptionKey`/`Key`, WireGuard `WireguardPubKey` travel inside
  node and ipcache records), datapath ipcache/tunnel maps.
- External: etcd v3 (`go.etcd.io/etcd/client/v3` incl. `concurrency`,
  `clientv3/yaml`), gRPC, fsnotify, k8s client (apiserver/operator side),
  zstd (`klauspost/compress`), workqueue (`k8s.io/client-go/util/workqueue`).
- Cluster requirements (docs): unique `cluster.name` + `cluster.id`,
  non-overlapping PodCIDRs across all clusters, node-to-node reachability on
  the datapath ports, same `maxConnectedClusters`, apiserver reachable on
  2379 from every remote node.

## Kernel / platform requirements

Control-plane only. No kernel helpers. The only datapath touch points are the
`cluster_id` field in the ipcache key (present in all supported kernels) and
the per-cluster CT/SNAT array-of-maps which require `BPF_MAP_TYPE_ARRAY_OF_MAPS`
(kernel >= 4.12) and are unused by default.

## Tests

- **Unit (no etcd)**: `pkg/kvstore/store/*_test.go` (SharedStore
  collaboration/local-key protection/periodic sync; SyncStore workers,
  rate limiter, without-lease, synced canary, lease expiry; WatchStore
  restart/drain/sync callback; WatchStoreManager canary gating), `lock_test`
  (local lock, cancel), `kvstore_test` (`JoinKey`, `StateToCachePrefix`,
  scope from key), `etcd_lease_test` (lease manager parallel/limit/expiry
  with a fake), `allocator_test` (`prefixMatchesKey`, `keyToID`, GC range
  skip), `doublewrite` backend tests, `pkg/clustermesh/common` (config
  directory watcher, `isEtcdConfigFile`, interceptors with cluster-ID
  change, remote cluster run/status/watchdog/cache-revoke/TTL, services
  observer), `pkg/clustermesh` (remote cluster run, cluster-ID change drains,
  extra observers, used-IDs manager, ipcache watcher opts, `TestClusterMesh`
  add/remove), `pkg/clustermesh/types` (name/ID validation, buggy ID,
  `ValidateRemoteConfig` mismatch, `AddrCluster`/`PrefixCluster` parse), 
  `clustercfg` (enforce/get/set), `kvstoremesh` (reflectors, drain,
  readiness timeouts), `mcsapi` controllers (~2900 lines),
  `endpointslicesync`, `clustermesh-apiserver/clustermesh/users_mgmt_test`.
- **Script tests (txtar, in-memory kvstore)**: `pkg/clustermesh/testdata/`
  (`clusterservice`, `clusterservice-multiport`, `clusterservice-without-local-eps`,
  `service-affinity`) pin the ClusterService -> LB backend merge and
  affinity selection; `clustermesh-apiserver/clustermesh/testdata/`
  (`ciliumnodes`, `ciliumidentitites`, `ciliumendpoints`,
  `ciliumendpointslices`, `globalnamespace`, `clusterconfig*`,
  `serviceexports-crd-upgrade`) pin the exact kvstore keys/values the
  apiserver writes; `pkg/kvstore/testdata/endpointslice-transcode.txtar`;
  `mcsapi-coredns-cfg/testdata/configure.txtar`.
- **Integration (real etcd)**: `pkg/kvstore/{etcd,base}_test.go` need etcd at
  `http://127.0.0.1:4002` (`make start-kvstores` runs a container mapping
  4002->4001; ldflag `kvstore.etcdDummyAddress`): get/set, create-only,
  `*IfLocked` txns, list+watch with pagination and compaction relist,
  rate limiter, lease expiry, `Hint`, endpoint shuffling. No privileged tests.
- **E2E workflows**: `conformance-clustermesh.yaml` (10-entry matrix over
  tunnel disabled/vxlan/geneve, encryption none/ipsec/wireguard, IPv6-only,
  `mode: clustermesh|kvstoremesh|external`, `cm-auth-mode legacy|migration|cluster`,
  `maxConnectedClusters 255|511`), `conformance-mcs-api.yaml`,
  `tests-clustermesh-upgrade.yaml` (upgrade/downgrade with mixed auth modes
  and encryption).

## Behavioral notes that must be preserved

### Connection lifecycle (remote cluster)

1. Config file appears -> `remoteCluster.connect()` -> controller
   `remote-etcd-<name>` (`CancelDoFuncOnUpdate`, exponential backoff).
2. `releaseOldConnection()`; parse `cilium-host-aliases`; build client with
   `NoLockQuorumCheck=true`, `NoEndpointStatusChecks=true`, cluster-ID
   interceptors, `ClusterName=<name>` (rate-limiter name `etcd-<name>`).
   Only whitelisted `kvstore-opt`s propagate: `etcd.qps`, `etcd.maxInflight`,
   `etcd.limit`, `etcd.keepaliveHeartbeat`, `etcd.keepaliveTimeout`; lease TTL
   and max quorum errors are inherited.
3. Wait for `errChan` (initial connection = heartbeat watcher `ListDone`,
   15 min cap) or interceptor error. Start watchdog goroutine on
   `StatusCheckErrors()` + interceptor errors -> on error: failures++,
   metrics, restart controller.
4. `getClusterConfig`: controller polling `cilium/cluster-config/<name>` up to
   3 min (retry <= 30 s). Missing key -> `ErrNotFound` hint "check
   KVStoreMesh / cluster name". Status `config.required=true`,
   `retrieved=false` until found.
5. `Run(ctx, backend, config, ready)`: `ValidateRemoteConfig` (ID in range,
   `maxConnectedClusters` equal when extended, export mode known);
   `onUpdateConfig` reserves the cluster ID (error if 0, local, or already
   used by another remote) and if the ID changed drains everything first;
   `WatchRemoteIdentities`; choose `WatchStoreManager` (canary-gated if
   `syncedCanaries`, else immediate) and prefix adapter (`cilium/cache` if
   `cached`); register nodes, services (unless `endpointslices-only` or v2
   mode says not to), ipcache, identities, extra observers (endpointslices);
   `close(ready)`; `mgr.Run`.
6. Failure at any step -> controller error -> backoff and full restart; TTL
   checker starts on first failure and revokes cache after
   `clustermesh-cache-ttl`.
7. File removed -> `remove()`: tombstone, stop controller, `Remove()` drains
   nodes/services/ipcache/identities/observers and releases the cluster ID; a
   re-add during removal is replayed afterwards.

### Ordering constraints

- Agent LB initializer `clustermesh` waits for `ServicesSynced` (legacy) or
  `EndpointSlicesSynced` (v2) of all remotes with `clustermesh-sync-timeout`
  (1 min, warn once and continue on timeout).
- `IPIdentitiesSynced` waits for ipcache **and** identities **and** nodes of
  each remote; the daemon's endpoint restore / policy regeneration and
  `MeshNodeSync` / ipset init wait on `NodesSynced`.
- With canaries, a prefix watch does not start until the writer published
  `cilium/synced/<cluster>/<prefix>`; without canaries the import proceeds
  immediately and the local caches may transiently miss entries.
- Cluster config is enforced by the local agent/operator/apiserver before
  peers can consider it ready; the enforcer waits for its own watcher to be
  established (5 s) before the first write.
- kvstoremesh writes the rewritten cluster config **before** registering
  reflectors, deletes it **first** on drain, waits 3 min grace so agents
  disconnect, then deletes `cilium/synced/<name>/` and each
  `cilium/cache/<prefix>/<name>/` (5 retries, 2 s doubling backoff).

### Data flow direction

Each cluster **writes** only under its own name (`.../<own-name>/...`), its
own `cilium/cluster-config/<own-name>`, and its own synced canaries; every
other cluster **reads** `cilium/state/*` of the peer (or `cilium/cache/*`
through kvstoremesh). Nothing flows back. Identities in kvstore mode are the
exception: the allocator writes master keys `id/<n>` and per-node slave keys
into the **local** kvstore only; remote clusters see them read-only, cached
into a remote `Allocator` with `WithoutGC`, `WithoutAutostart`.

### Version skew

Peers only exchange `cilium/cluster-config/<name>`; missing key -> the agent
waits/retries forever (pre-1.13 peers). Unknown
`capabilities.endpointSlicesExportMode` -> `Run` fails. `serviceExportsEnabled
== nil` -> ServiceExports reflector/observer disabled. `cached` is only ever
set by kvstoremesh. Mismatched `maxConnectedClusters` refuses connection when
extended mode is on. Wire values are additive JSON; new fields must be
`omitempty`.

## Rust mapping

- **etcd client**: the `etcd-client` crate (tonic-based) covers KV
  (range/put/delete with prefix, sort, limit, revision), Txn with compare on
  version/value/lease, Watch (prefix, start revision, `require_leader`
  option via metadata `hasleader`), Lease (grant/keepalive/revoke/TTL), Lock
  service (`lock`/`unlock` gRPC — Cilium instead uses client-side
  `concurrency.Mutex` implemented as Txn on `<path>/<lease-hex>` + watch of
  predecessors; re-implementing that is ~200 lines and keeps key layout
  compatible), Maintenance `status`, and Auth (`user_add` with
  `no_password`, `user_grant_role`, `role_add`, `role_grant_permission`,
  `auth_enable`). TLS with client certs via `tonic`/`rustls`; certificate
  hot-reload must be built (rustls `ResolvesClientCert`). gRPC interceptors
  for the cluster-ID pin map to a tonic `Interceptor`/tower layer inspecting
  `ResponseHeader.cluster_id` on every response and watch message. The
  custom dialer (k8s Service resolver, `cilium-host-aliases`) maps to a
  tonic `connect_with_connector` with a custom resolver.
- **fastetcd compatibility**: beyond plain KV/watch/lease the reference uses
  (1) **Txn** with `Version(key) == 0` compare and mutex-owner compare
  (`CreateOnly*`, all `*IfLocked`, `GetIfLocked`); (2) **watch with
  `WithRev`** and correct `ErrCompacted` signalling plus **`WithRequireLeader`**;
  (3) **paginated Range** with `sort`, `limit`, `more`, `count`, and
  `WithRev(revision)` to read a consistent snapshot; (4) **lease KeepAlive
  streams** and `ErrLeaseNotFound` semantics, lease IDs reported in
  `KeyValue.lease`; (5) **`mod_revision`** and `lease` per key (used by
  allocator GC to detect stale locks/master keys); (6) **Maintenance
  Status** (version, `member_id`, `leader`) used only for status strings;
  (7) **Auth users/roles with key-range read permissions and
  `auth_enable`** — required only for the apiserver deployment model;
  (8) **`ResponseHeader.cluster_id`** stable per etcd instance (interceptor
  pin); (9) server-side `--auto-compaction-retention` (the client must
  survive compaction by relisting). Nothing uses gRPC gateway, snapshots,
  member management, or min-revision beyond `WithRev`. Confirm fastetcd
  returns `Count`/`More` on limited ranges, `Version` in `KeyValue`,
  `cluster_id` in headers, and implements Auth if the users model is kept;
  otherwise the flowsdn apiserver can skip per-cluster users and rely on
  mTLS + a read-only proxy.
- **Structure**: `flowsdn-kvstore` (client trait mirroring
  `BackendOperations`, lease manager, path locks, watch relist state
  machine, rate limiter with bootstrap QPS, status checker), `flowsdn-store`
  (SharedStore/SyncStore/WatchStore/manager over an in-memory or etcd
  backend), `flowsdn-clustermesh` (config dir watcher, remote cluster state
  machine, cluster config, ID reservation, watch registration, LB merge,
  affinity), `flowsdn-kvstoremesh` (reflectors + drain), `flowsdn-cm-apiserver`
  (k8s->kvstore converters, canaries, users). Serde structs must reproduce
  the exact JSON field names above (note Go-default capitalised names for
  `Node` and `IPIdentityPair`, lower-camel for `ClusterService`,
  `CiliumClusterConfig`, `MCSAPIServiceSpec`) and the label-string identity
  key format; `ClusterEndpointSlice` needs prost + zstd.
- **Hard parts**: the watch relist/compaction/delete-reconciliation logic
  (`watch()` + `watcherCache`), lease-key bookkeeping and expiry observers,
  allocator master/slave/lock protocol and GC (two-round stale detection on
  `mod_revision`), canary-gated ordering, tombstoned add/remove races,
  identity bit split affecting policy maps, and reproducing readiness
  semantics the cilium-cli expects from `/healthz`.

## Recommendation

**Keep** the kvstore client, store synchronizers, key schema and the
agent-side ClusterMesh import path (nodes, identities, ipcache, shared
services, cluster config, canaries) — they are the interoperability contract
and the only way a flowsdn cluster can mesh with (or replace) a Cilium one.
**Keep** kvstoremesh (small, pure kvstore->kvstore). **Defer** MCS-API,
the EndpointSlice v2 consumer, operator-side EndpointSlice mirroring and the
CoreDNS auto-config job until the legacy interoperability gate passes (#279).
Required export retains both legacy and slice shapes (#27). Replace etcd user
management with mTLS plus in-process prefix authorization, not mTLS alone (#277). **Replace** the etcd sidecar + `etcdinit` with fastetcd embedded/adjacent
to the flowsdn apiserver, keeping the client-facing key/ACL layout.

Effort: kvstore client + store layer **M** (~5k), identity kvstore backend +
remote caches **S–M** (~2k), agent ClusterMesh core **M** (~4k), kvstoremesh +
apiserver synchronizers **M** (~3k), MCS-API/EndpointSlice v2 **L** if taken.

## Open questions

- Does fastetcd implement Txn compares on `version`, `Count`/`More` for
  limited ranges, `ErrCompacted` on stale watch revisions, per-key `lease`
  and `mod_revision`, and `ResponseHeader.cluster_id`? Each is load-bearing
  above.
- Do we keep etcd Auth (users/roles) for per-cluster read scoping, or rely on
  mTLS with a proxy that restricts prefixes? The `remote` role read set is
  small and could be enforced in a flowsdn front-end instead.
- **Resolved #20:** CRD identities default; explicit kvstore remains required
  with `kvstore=etcd`. Runtime backends/GC still need implementation (spec 20 §12.1).
- **Resolved #27:** require legacy service import and dual export; only
  `prefer-legacy` until slice-consumer interoperability tests pass (spec 20 §12.4).
- **Resolved #28:** cross-cluster PodCIDRs must not overlap; topology replacement
  checks preserve prior state on conflict. Live admission remains pending (spec 20 §12.7).
- The cilium-cli (`cilium clustermesh connect`) is out of tree; flowsdn needs
  its own tool to exchange endpoints/certs and write the
  `/var/lib/cilium/clustermesh/<name>` files or an equivalent config source.

Spec 20 §12 also resolves #273 (5m resync pending an evidence-gated default
change), #274 (reject double-write, offline migration), #276 (stable UUID plus
durable CAS ownership guard), #277 (in-process prefix front) and #279 (explicit
MCS/mirroring staging). `flowsdn-clustermesh` provides local planning/checking
primitives only; no live store/client/controller behavior is established.
