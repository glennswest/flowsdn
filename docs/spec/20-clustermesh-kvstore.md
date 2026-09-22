# ClusterMesh and the key-value store layer — specification

Status: draft. Derived from: `docs/inventory/12-clustermesh-kvstore.md` (primary),
`docs/inventory/05-policy-identity.md`, `docs/inventory/08-operator.md`;
reference cilium v1.20.1 (7d68cfb394) paths `pkg/kvstore/**` (`etcd.go`,
`etcd_lease.go`, `backend.go`, `client.go`, `kvstore.go`, `events.go`,
`lock.go`, `metrics.go`, `config.go`, `heartbeat/`, `etcdinit/`, `store/`,
`allocator/`), `pkg/clustermesh/**` (`common/`, `types/`, `clustercfg/`,
`store/`, `endpointslice/`, `kvstoremesh/`, `observer/`, `wait/`, `mcsapi/`,
`endpointslicesync/`, `operator/`, `namespace/`, `clustermesh.go`,
`remote_cluster.go`, `service_merger.go`, `selectbackends.go`, `idsmgr.go`),
`clustermesh-apiserver/**`, `pkg/node/store/store.go`, `pkg/ipcache/kvstore.go`,
`pkg/identity/cache/allocator.go`, `pkg/annotation/clustermesh.go`,
`api/v1/models/{remote_cluster,remote_cluster_synced,remote_cluster_config,cluster_mesh_status}.go`,
`pkg/client/client.go`, `install/kubernetes/cilium/templates/clustermesh-*`,
`Documentation/network/clustermesh/**`. Governed by ADR-0001..0005.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes *what*
flowsdn does and the exact data it exchanges. It does not transcribe reference
code. Where the reference behavior is kept for compatibility, the consumer that
depends on it is named (another cluster's agent, `cilium-dbg`, the operator,
kvstoremesh, `cilium clustermesh` CLI). Where flowsdn deviates, the paragraph is
marked **DEVIATION** with the reason and the ADR.

## 1. Scope

Two layers, specified together because the upper one is the only substantial
consumer of the lower one.

**The kvstore layer** is flowsdn's abstraction over a strongly-consistent,
watchable, leased key-value store. It is used for exactly two purposes:
publishing this cluster's state for peer clusters to read, and (optionally)
allocating security identities cluster-wide.

**ClusterMesh** is the multi-cluster control plane: a mesh of Kubernetes
clusters that share node information, security identities, IP→identity
mappings and global services, so that pods in one cluster can reach and be
policy-matched against pods in another.

**In scope here:**

- The kvstore client trait, its complete operation set, and the etcd backend:
  configuration, TLS, dialing, reconnection, quorum detection, rate limiting
  and inflight caps (§3.1–§3.3, §5.2–§5.4).
- Leases, lease bookkeeping, expiry observers, distributed locks (§3.3, §5.5).
- The store synchronizers built on the client: one-way export (`SyncStore`),
  one-way import (`WatchStore`), owned-key round-trip (`SharedStore`), and the
  canary-gated watch manager (§3.4).
- The complete key schema under the `cilium/` prefix, every value encoding,
  and the `cilium/cache/` mirror layout used by kvstoremesh (§4).
- Identity allocation in kvstore mode: master/slave/lock keys, per-cluster ID
  ranges, allocate/release/GC protocol, and coexistence with CRD mode behind
  the `IdentityBackend` trait of spec `03` §11 (§3.6, §5.6).
- The agent side of ClusterMesh: config directory, connection lifecycle,
  cluster-ID interceptor pin, watchdog, ordering constraints as spec `00`
  fences, remote node/ipcache/identity/service import, global-service merge,
  affinity, endpoint-slice sync mode, status (§3.7).
- The `flowsdn-clustermesh-apiserver`: what it exposes, its synchronizers,
  per-remote-cluster users and ACL ranges, TLS layout, health, metrics, and
  the kvstoremesh caching mode with its drain sequence (§3.8, §3.9).
- Version skew: cluster-config capabilities, what each gates, and behavior
  against older and newer peers (§3.10).
- **fastetcd** as the shipped backend: a normative etcd compatibility
  checklist and the operational consequences of replacing the reference's
  etcd sidecar (§2.7, §6.6).
- Configuration keys (§6), failure modes (§7), observability (§8), test plan
  (§9), Rust design (§11), open decisions (§12).

**Out of scope — specified elsewhere, referenced not restated:**

| Subject | Spec |
|---|---|
| Identity numbering, scope byte, cluster-ID bit split, `cluster_id(id)`, remote-identity validation rules, canonical label string | `03-identity-ipcache.md` §4.1, §4.5, §4.7 |
| ipcache metadata model, `PrefixCluster`, source precedence, `cilium_ipcache_v2` writes | `03-identity-ipcache.md` §3.10, §4.6, §4.8 |
| How backends reach the LB tables and the BPF maps, backend/frontend data model, `SelectBackends` default, LB initializers | `05-service-loadbalancing.md` §3.1, §3.3, §3.4, §4.2 |
| IPAM, `CiliumNode` PodCIDR fields that travel inside the node record | `07-ipam.md` |
| Operator duties that *use* this layer (service sync, node GC, lock sweeper, heartbeat, cluster config, EndpointSlice sync) — the duty, not the schema | `12-operator.md` §3.13 |
| CRD schemas, k8s client, informer sets, RBAC, annotation catalogue | `13-crds-k8s-client.md` |
| `Fence` semantics, the table store, the config registry, module health | `00-foundation-table-config.md` §3.2, §3.3, §3.4 |
| Node manager, `NodeUpdated`/`NodeDeleted`, ipset, tunnel/route programming for remote nodes | `10-node-routing-nftables.md` |
| WireGuard public keys and IPsec key indices carried inside node and ipcache records | `14-encryption-egress.md` |
| The scripttest harness that runs the harvested `.txtar` corpora | `17-scripttest-harness.md` (ADR-0005) |

**Deferred from the first cut** (§12 records the decisions):

- MCS-API (`ServiceExport` / `ServiceImport`, the `clusterset.local` CoreDNS
  job, the `serviceexports/v1` prefix) — read-side tolerated, write-side not
  implemented.
- Operator-side EndpointSlice mirroring of remote services into local
  `discovery.k8s.io/v1` objects (`clustermesh-enable-endpoint-sync`).
- The `endpointslices/v1` export path and `clustermesh-service-v2` modes other
  than `prefer-legacy` (§3.7.9 explains why the reference's non-legacy modes
  are not usable at v1.20.1).
- The double-write identity allocation modes.

## 2. Compatibility contract

Everything in this section is an interoperability surface: a flowsdn cluster
must be able to mesh with a Cilium v1.20.x cluster in either direction, and a
Cilium agent must be able to consume a flowsdn cluster's exported state
without modification.

### 2.1 Key schema and value encodings

| Surface | Consumer | Frozen part |
|---|---|---|
| Every key path in §4.1 | peer agents, peer operators, kvstoremesh, `cilium-dbg kvstore get/list` | the literal path, the separator (`/`), the trailing-slash and empty-element collapsing rule of §5.1 |
| `CiliumClusterConfig` JSON (§4.2) | peer agents on connect | field names `id`, `capabilities`, and every capability field; additive-only evolution |
| Node record JSON (§4.3) | peer agents' node managers | Go-style **capitalised, tag-less** field names |
| `IPIdentityPair` JSON (§4.4) | peer agents' ipcache | capitalised field names; key = `IP` or `IP/len` |
| Identity master-key value (§4.5) | peer agents, the local allocator, `cilium-dbg identity list` | the canonical label string of spec `03` §4.1 with its trailing `;` |
| `ClusterService` JSON (§4.6) | peer agents' LB, operator EndpointSlice mirroring | lower-camel field names; key `<cluster>/<ns>/<name>` |
| `ClusterEndpointSlice` (§4.7) | peer agents/operators in v2 modes | zstd(protobuf), field numbers 1..9 |
| `MCSAPIServiceSpec` JSON (§4.8) | peer operators with MCS-API | lower-camel plus the two legacy capitalised duplicates |
| Synced-canary key and value (§4.1) | peer readers gating their watches | path and RFC3339 value |

### 2.2 Cluster identity

| Item | Rule |
|---|---|
| `cluster-name` | matches `^([a-z0-9][-a-z0-9]*)?[a-z0-9]$`, at most 32 characters; default `default`; MUST differ from `default` when `cluster-id != 0` |
| `cluster-id` | `0` = unset (no mesh); `1..max` when meshing, where `max` is `max-connected-clusters` |
| `max-connected-clusters` | `255` (default) or `511`; anything else is fatal at startup; MUST be identical on every cluster of a mesh |
| Identity range of cluster `c` | `[c << shift, ((c+1) << shift) - 1]` with `shift = 24 - log2(max+1)`; spec `03` §4.5 owns the arithmetic |
| Buggy-ID guard | a `cluster-id` with bit `0x80` set is refused with ENI or Alibaba IPAM, or `aws-cni` chaining, unless the hidden `allow-unsafe-policy-skb-usage` is set |

### 2.3 Config directory and file format

The agent (and the operator, and kvstoremesh) discovers remote clusters by
reading a directory. The file name is the cluster name; the content is an etcd
client YAML with one flowsdn/Cilium extension key. Both are frozen: the
`cilium clustermesh connect` CLI, Helm, and any operator tooling write these
files.

```yaml
endpoints:
- https://cluster2.mesh.cilium.io:2379
trusted-ca-file: /var/lib/cilium/clustermesh/common-etcd-client-ca.crt
key-file:        /var/lib/cilium/clustermesh/common-etcd-client.key
cert-file:       /var/lib/cilium/clustermesh/common-etcd-client.crt
cilium-host-aliases:            # optional extension, ignored by etcd itself
- hostname: cluster2.mesh.cilium.io
  ips: [192.0.2.10, 192.0.2.11]
```

### 2.4 Status surfaces

| Surface | Shape |
|---|---|
| Agent `GET /healthz` → `StatusResponse.cluster-mesh` | `{ "clusters": [ RemoteCluster ] }`, clusters sorted by name |
| Operator `GET /v1/cluster` | `[ RemoteCluster ]` |
| kvstoremesh `GET /cluster` on `127.0.0.1:9889` | `[ RemoteCluster ]` |
| `RemoteCluster` JSON keys | `name`, `ready`, `connected`, `status`, `num-nodes`, `num-shared-services`, `num-endpoints`, `num-identities`, `num-endpoint-slices`, `num-service-exports`, `num-failures`, `last-failure`, `synced`, `config` |
| `synced` keys | `nodes`, `services`, `identities`, `endpoints`, `endpoint-slices` (nullable), `service-exports` (nullable) |
| `config` keys | `required`, `retrieved`, `cluster-id`, `kvstoremesh`, `sync-canaries`, `service-exports-enabled` (nullable), `endpoint-slices-export-mode` |

### 2.5 Annotations

| Annotation | Alias | Object | Meaning |
|---|---|---|---|
| `service.cilium.io/global` | `io.cilium/global-service` | Service | export/import this service across the mesh; `"true"` (case-insensitive) enables |
| `service.cilium.io/shared` | `io.cilium/shared-service` | Service | share *this cluster's* backends; ignored unless global; default `true` when global |
| `service.cilium.io/affinity` | `io.cilium/service-affinity` | Service | `none` \| `local` \| `remote`; ignored unless global; unknown value logs a warning and falls back to `none` |
| `service.cilium.io/global-sync-endpoint-slices` | — | Service | operator mirrors remote backends into local EndpointSlices (deferred) |
| `clustermesh.cilium.io/global` | — | Namespace | `"true"`/`"false"` overrides `clustermesh-default-global-namespace` |

### 2.6 etcd wire surface actually used

The reference uses a strict subset of etcd v3. flowsdn MUST use no more than
this subset, so that the backend stays replaceable (§2.7).

| gRPC service | RPC | Used for |
|---|---|---|
| KV | `Range` | `Get`, `ListPrefix`, the paginated initial list before a watch |
| KV | `Put` | `Update`, with or without a lease |
| KV | `DeleteRange` | `Delete` (single key) and `DeletePrefix` |
| KV | `Txn` | create-only (`Compare(Version(key), "=", 0)`), every `*IfLocked` variant (compare on the lock key's `CreateRevision`), and the client-side mutex |
| Watch | `Watch` | prefix watch from a revision, with `require_leader` |
| Lease | `LeaseGrant`, `LeaseKeepAlive`, `LeaseRevoke` | key leases and lock leases |
| Maintenance | `Status` | per-endpoint status string, leader id, version |
| Auth | `UserAdd`(no-password), `UserGrantRole`, `UserDelete`, `RoleAdd`, `RoleGrantPermission`, `AuthEnable` | apiserver per-cluster users — **not used by flowsdn**, see §2.7 and §3.8.5 |

Not used, and flowsdn MUST NOT introduce a dependency on: the `v3lock` and
`v3election` gRPC services, `Compact` from the client, member management,
snapshots, gRPC gateway, watch fragmentation, nested `Txn`, descending or
non-key sort orders, `min/max_{mod,create}_revision` filters.

### 2.7 FASTETCD compatibility checklist (normative)

flowsdn ships **fastetcd** as its key-value store rather than etcd (§6.6). The
checklist below is the complete contract this spec places on the store. Each
row is a requirement on the backend, with the flowsdn feature that breaks if it
is unmet. It is written so fastetcd can be verified — or extended — against it
mechanically, and so any other etcd-compatible store can be swapped in.

Status column: **OK** = fastetcd 1.2.0 satisfies it; **GAP** = it does not, and
either fastetcd must be extended or flowsdn must avoid the dependency (the
"flowsdn action" column says which).

| # | Requirement | Why | fastetcd 1.2.0 | flowsdn action |
|---|---|---|---|---|
| F1 | `Range` with `range_end` = key-prefix successor, `limit`, and a returned `more` flag and `count` | paginated initial list (`etcd.limit`, default 256) before every watch | OK | use as is |
| F2 | `Range` with an explicit `revision` returning a consistent historical snapshot, and `OutOfRange`/compacted error when that revision is gone | the list→watch handoff reads at revision `R` then watches from `R+1`; without it the handoff races | OK | use as is |
| F3 | Ascending-by-key ordering of `Range` results | continuation uses "last key seen + `\x00`" as the next `key`; a non-ascending order silently loses keys | OK (always ascending) — but `sort_order`/`sort_target` are **ignored, not rejected** | flowsdn MUST NOT set `sort_order`/`sort_target` and MUST NOT rely on any order other than ascending. A conformance test asserts ascending order. |
| F4 | `KeyValue` carries `create_revision`, `mod_revision`, `version` and `lease` | `version == 0` compare for create-only; `mod_revision` for allocator stale detection (§5.6); `lease` for lease bookkeeping | OK | use as is |
| F5 | `Txn` compare targets `VERSION` and `CREATE`, results `EQUAL`, with `RequestPut` / `RequestRange` / `RequestDeleteRange` in `success` and `failure` | create-only writes and every `*IfLocked` operation | OK | use as is |
| F6 | `Txn` response ops are tagged with the operation that produced them | a client that matches on `ResponseOp` variants mis-reads a single-key `DeleteRange` as a `Put` in fastetcd | **GAP** (`crates/server/src/kv.rs` infers the variant) | flowsdn's `Txn` wrapper MUST decide success/failure from `TxnResponse.succeeded` and MUST NOT inspect the response-op variants. Fastetcd issue to file. |
| F7 | `Txn` is subject to the same authorization as `Put`/`Range` | otherwise RBAC is bypassable | **GAP** (no `authorize()` on `Txn`) | flowsdn does not use etcd Auth (F19); no impact, but the gap is recorded and filed. |
| F8 | `Watch` with `key`+`range_end` (prefix), `start_revision`, and `prev_kv` not required | all imports | OK | use as is |
| F9 | `Watch` cancels with `canceled = true` and `compact_revision` set when `start_revision` precedes the compaction floor | the relist-on-compaction state machine (§5.4) is the only thing standing between a compaction and permanently stale caches | OK, with an off-by-one at the boundary (`start_revision < compact_rev` vs etcd's `<=`) | flowsdn treats *any* watch cancellation with a non-zero `compact_revision`, and any watch error, as "relist from scratch"; the boundary difference is therefore unobservable. Conformance test C9 pins it. |
| F10 | A watch never silently skips a revision in its range | every import cache would drift with no error and no self-heal | **GAP** — fastetcd logs `RecvError::Lagged(n)` and continues, dropping events | **Blocking for production.** fastetcd MUST cancel the watch (any cancel reason) instead of dropping. Until then flowsdn MUST run the periodic full resync of §5.4.4 with a bounded interval (`kvstore-resync-interval`, default 5 m) rather than the reference's watch-only model. Filed as the highest-priority fastetcd change. |
| F11 | `WithRequireLeader` (`hasleader` gRPC metadata): a watch on a member that has lost quorum is cancelled rather than going silent | a partitioned reader would serve stale remote state indefinitely | **GAP** — not implemented | flowsdn sets the metadata anyway (harmless), and does not rely on it: liveness is detected by the heartbeat watcher (§3.5.1) and the status checker (§3.2.5), which are mandatory in flowsdn (they are optional in the reference for remote clients). |
| F12 | `LeaseGrant` with a client-visible TTL; `LeaseKeepAlive` as a bidirectional stream; `LeaseRevoke` | every non-master key in the schema is leased so a dead writer's state expires | OK | use as is |
| F13 | Keys attached to a lease are deleted, with normal `DELETE` watch events, when the lease expires or is revoked | remote readers learn that a peer died | OK | use as is |
| F14 | `Put` against a non-existent lease id fails | detects a lease that expired between grant and use | **GAP** — fastetcd accepts it and records a dangling lease id | flowsdn MUST NOT rely on the error. The lease manager (§3.3.1) instead re-grants on any keep-alive stream failure and re-writes every key of the lost lease (this is required against etcd too, because the same race exists there). |
| F15 | `LeaseTimeToLive` returning the remaining TTL | diagnostics only | OK | optional |
| F16 | `Maintenance.Status` returning `version`, `member_id`/`leader` | the human-readable status string, and leader-known-ness in the quorum probe | OK | use as is |
| F17 | `ResponseHeader.cluster_id` stable per store instance and **distinct per deployed cluster** | the cluster-ID interceptor pin (§3.7.4) detects "the endpoint now points at a different store" and forces a full drain+reconnect | **GAP** — fastetcd defaults `cluster_id` to `1` for every deployment and does not derive it from `--initial-cluster-token` | Deploying flowsdn's apiserver MUST pass a distinct `--cluster-id` per meshed cluster. §6.6 makes this a hard requirement of the deployment manifest, derived from the cluster name (FNV-1a-64 of `cluster-name`, masked to 63 bits, never 0). Without it the pin is inert and a mis-pointed endpoint is not detected. |
| F18 | Server-side automatic compaction, so history does not grow without bound | a mesh writes continuously | OK, but **revision mode only**; etcd's `--auto-compaction-mode=periodic` (`"1h"`) is unsupported and a duration string fails to parse | §6.6 configures `--auto-compaction-retention` as a **revision count**, not a duration. This is a documented operational difference from the reference's `--auto-compaction-retention=1` (which means one hour). |
| F19 | Users, roles, key-range read permissions, `AuthEnable`, and mapping a client certificate CN to a user (`--client-cert-auth`) | the reference's per-remote-cluster etcd users and their ACL ranges (§3.8.5) | **GAP** — RBAC primitives exist, but CN→user mapping does not exist at all, and the Auth service is reachable without the auth interceptor | **DEVIATION (§3.8.5).** flowsdn does not use etcd Auth. Read scoping is enforced by the flowsdn apiserver front (mTLS identity → allowed prefix set) instead. The `users.yaml` file and the `clustermesh-remote-users` ConfigMap are accepted and ignored, with a startup warning. |
| F20 | Server TLS with mandatory client-certificate verification against a CA | the only authentication in the flowsdn model | OK (`--cert-file`, `--key-file`, `--trusted-ca-file`, `--client-cert-auth`) | use as is; §3.8.6 |
| F21 | Separate server and peer TLS identities | defence in depth for the raft port | **GAP** — one identity is shared; `--peer-*-file` flags are parsed and discarded | accepted with the shipped peer-port NetworkPolicy; tracked in fastetcd#23. Port 2380 remains cluster-internally reachable in HA; see §12 decision 8. |
| F22 | A `Range` of a prefix that returns nothing must be distinguishable from an error | "cluster config missing" is a normal, expected state on a peer that has not started yet | OK | use as is |
| F23 | Revisions are globally monotonic across the whole keyspace | watch-from-revision and the list→watch handoff | OK (`Revision { main, sub }`) | use as is |
| F24 | Bounded request/response size, or at least a documented limit | `ClusterEndpointSlice` values can approach the 16 MiB decode cap | fastetcd does not enforce `--max-request-bytes`; gRPC transport limits apply | flowsdn caps a single value at 4 MiB on write and rejects larger ones with a named error rather than relying on the store. |
| F25 | `Snapshot` restorable by the store's own tooling | operational backup | fastetcd's `Snapshot` streams a bincode blob (not restorable by `etcdctl`), but `fastetcd backup`/`restore` exist | flowsdn documents `fastetcd backup` as the backup path; it never calls the gRPC `Snapshot` RPC. |
| F26 | `v3lock` / `v3election` services | not needed | missing in fastetcd | flowsdn implements the distributed lock **client-side** as a `Txn` + watch-predecessor protocol (§3.3.2), exactly as the reference does, so the key layout stays compatible and no server-side lock service is required. |

**Conformance suite.** §9.6 defines `flowsdn-kvstore-conformance`, a binary
that runs every row above against a live store and prints a pass/fail table.
It is the acceptance gate for a fastetcd release and for any alternative
backend. Rows F6, F7, F10, F11, F14, F17, F19, F21 are the currently failing
ones; F10 and F17 are blocking, the rest are accepted with the stated
mitigation.

## 3. Behavior

### 3.1 The kvstore client trait

flowsdn's kvstore surface is deliberately narrower than the reference's
`BackendOperations`. The reference exposes 20 methods; several exist only to
serve one caller, and three (`GetIfLocked`, `ListPrefixIfLocked`,
`CreateOnlyIfLocked`, `UpdateIfLocked`, `UpdateIfDifferentIfLocked`,
`DeleteIfLocked`) are the same operation with a lock-ownership compare bolted
on. flowsdn expresses the lock compare as an optional argument instead.

The trait MUST be exactly this, and MUST NOT grow without an entry in §12:

| Operation | Signature (semantics, not Rust) | Notes |
|---|---|---|
| `get` | `(key, guard?) -> Option<Value>` | `Value = { data, mod_revision, lease_id }`; missing key is `None`, not an error |
| `put` | `(key, value, lease: Lease, guard?) -> ()` | `Lease ∈ { None, Attached }`; `Attached` binds the key to the client's current lease (§3.3.1) |
| `put_if_absent` | `(key, value, lease, guard?) -> bool` | one `Txn` with `Compare(Version(key) == 0)`; `false` = key existed |
| `put_if_different` | `(key, value, lease, guard?) -> bool` | read-compare-write; MUST also rewrite when the stored key's lease id differs from the client's current lease, otherwise the key silently outlives its writer's lease generation |
| `delete` | `(key, guard?) -> ()` | idempotent; deleting a missing key is success |
| `delete_prefix` | `(prefix) -> ()` | one `DeleteRange`; also releases every lease binding under the prefix |
| `list_prefix` | `(prefix, guard?) -> Map<key, Value>` | paginated internally (§5.3); returns the whole prefix |
| `watch` | `(prefix) -> Stream<Event>` | list-then-watch; `Event ∈ { Create, Modify, Delete, ListDone }` (§5.4) |
| `lock` | `(path) -> Guard` | distributed lock; `Guard` yields the compare used by the `guard?` arguments (§3.3.2) |
| `lease_expired` | `(prefix, callback)` / `(prefix, None)` | register/unregister the observer fired per key when a lease is lost (§3.3.1) |
| `status` | `() -> Status` | the human-readable state + message of §3.2.5 |
| `status_errors` | `() -> Stream<Error>` | bounded (128) channel of status-check errors; the connection watchdog consumes it |
| `close` | `()` | closes the connection and waits for lease keepalive tasks |

Rules:

1. A backend MUST implement all of it or fail construction; there is no
   capability negotiation between flowsdn and its store.
2. `guard?` is `Option<&Guard>`. When present, the operation MUST be executed
   as one transaction whose compare is the guard's ownership compare, and MUST
   fail with a distinguishable `LockLeaseExpired` error when the compare fails.
   This preserves the reference's `*IfLocked` semantics and its error.
3. Every operation except `lock`, `status` and the lease keepalive path MUST
   pass through the rate limiter (§3.2.4). `lock` is deliberately unlimited so
   that a saturated limiter cannot deadlock the quorum probe.
4. **DEVIATION (ADR-0001).** The reference's user-management methods
   (`UserEnforcePresence`, `UserEnforceAbsence`) are not part of the trait.
   flowsdn does not use etcd Auth (§2.7 F19, §3.8.5).
5. **DEVIATION (ADR-0004).** There is no `Client` cell, no hive script
   commands and no statedb-backed in-memory backend. Tests use an in-process
   backend implementing the same trait (§11.1); the scripttest harness drives
   it through the same commands the reference's `kvstore/list|update|delete`
   scripts use, so the harvested `.txtar` files run unmodified.

### 3.2 The etcd backend

#### 3.2.1 Configuration and endpoints

The backend is selected by `kvstore` (`""` = disabled, `etcd` = enabled) and
configured by repeated `kvstore-opt` key/value pairs. Exactly one of
`etcd.address` and `etcd.config` MUST be given; both missing is fatal. An
`etcd.config` path that does not yet exist is retried every 5 s with the log
`Waiting for all kvstore configuration files to be available` rather than
being fatal, because Helm mounts the secret asynchronously.

`etcd.config` names a YAML file in the etcd client format (§2.3). Its
`endpoints` list is **shuffled** before use; the reference does this to work
around an etcd client failover defect, and flowsdn keeps it because it also
spreads read load across apiserver replicas.

#### 3.2.2 TLS

TLS is configured entirely from the client YAML: `trusted-ca-file`,
`cert-file`, `key-file`. When both `cert-file` and `key-file` are set, the
client MUST install a **certificate resolver that re-reads both files on every
TLS handshake**. This is the reference's rotation mechanism and it is
load-bearing: the Helm CronJob and cert-manager rotate the secret in place, and
nothing signals the process. A resolver that caches the parsed certificate
breaks a mesh silently, hours after rotation.

Server certificate verification MUST use `trusted-ca-file` when present and
the system roots otherwise. Hostname verification is against the endpoint
host — including when `cilium-host-aliases` redirected the connection to a
different IP (§3.2.3), which is the entire point of the alias mechanism.

#### 3.2.3 Dialing

Three resolution layers, applied in order, before a TCP connect:

1. **Static host aliases.** If the endpoint host appears in
   `cilium-host-aliases`, its IP list is used directly. The last IP that
   connected successfully is tried first; the rest are shuffled. Dial deadline
   is split across candidates with a 2 s per-candidate minimum.
2. **Kubernetes Service resolution.** A host of the form `<name>.<namespace>`
   or `<name>.<namespace>.svc` is resolved to the Service's ClusterIP (agent:
   from the LB frontend table; operator: from the Service informer). This lets
   an agent reach the local apiserver without DNS.
3. **DNS**, the normal path.

Connection parameters: dial timeout is **not** set (connection establishment is
asynchronous and bounded by §3.2.6 instead), gRPC keepalive time
`etcd.keepaliveHeartbeat` (15 s), keepalive timeout `etcd.keepaliveTimeout`
(25 s). A single value MUST NOT exceed 4 MiB on write (§2.7 F24).

#### 3.2.4 Rate limit and inflight cap

One limiter per client instance, named `etcd` for the local store and
`etcd-<cluster>` for each remote.

| Parameter | Source | Default | Meaning |
|---|---|---|---|
| steady-state rate | `etcd.qps` | 20 | requests per second, token bucket |
| burst | `etcd.qps` | 20 | bucket depth; equals the steady rate even during bootstrap |
| bootstrap rate | `etcd.bootstrapQps` | 0 (disabled) | rate applied until the bootstrap signal fires; the apiserver uses 10000 |
| inflight cap | `etcd.maxInflight` | `etcd.qps` | maximum concurrent in-flight operations |

The bootstrap rate exists so that a cold apiserver can flush its initial
Kubernetes list into the store in seconds instead of minutes. It is raised to
the steady rate exactly once, when the owning component signals that its
initial synchronization finished.

A request that cannot get a token or an inflight slot **waits**; it MUST NOT
fail. There is no maximum wait: the caller's cancellation is the bound.

The paginated list of §5.3 consumes **one** token for the whole list, not one
per page. Watch creation consumes one token per attempt.

#### 3.2.5 Status, quorum and reconnection

A background status checker runs continuously and is the only writer of the
client's status. One iteration:

1. **Quorum probe** (skipped for remote-cluster clients, see below): acquire and
   immediately release a distributed lock on
   `cilium/.initlock/<random-u64-hex>` under a 10 s deadline, retrying with
   exponential backoff. Success means the store can serve a linearizable write,
   i.e. it has quorum. Failure records a `lock timeout` quorum error.
2. **Heartbeat probe** (remote-cluster clients only): if no heartbeat watch
   event has arrived for more than **2 minutes** (twice the write interval),
   record a `no event received` quorum error. A remote client deliberately does
   *not* take the init lock — it has no write permission on a peer's store —
   so the heartbeat is its only liveness signal.
3. **Endpoint status** (skipped for remote-cluster clients): for each endpoint,
   a `Maintenance.Status` RPC under a 10 s deadline yields
   `<endpoint> - <version>`, with ` (Leader)` appended when that member is the
   leader, or `<endpoint> - <error>` on failure.
4. **Verdict:**

| Condition | State | Message |
|---|---|---|
| consecutive quorum errors > `kvstore-max-consecutive-quorum-errors` (2) | `Failure` | `Err: quorum check failed <n> times in a row: <err>` |
| endpoints exist and none responded | `Failure` | `Err: not able to connect to any etcd endpoints` |
| otherwise | `Ok` | `etcd: <ok>/<total> connected, leases=<n>, lock leases=<n>, has-quorum=<true\|err>: <per-endpoint strings joined by "; ">` |

The message format is rendered verbatim by `cilium-dbg status` and by the
per-remote-cluster status line, so it is frozen.

5. **Interval**: 30 s when every endpoint responded, 5 s otherwise, scaled by
   cluster size on the reference's curve (1 node → 20 s/3 s; 128 → 2 m 25 s/24 s;
   8192 → 4 m 30 s/45 s). Errors are pushed into a bounded channel of 128; when
   it is full the error is dropped with a warning rather than blocking.

**Reconnection.** The client itself does not reconnect: gRPC does, per
endpoint. What reconnects is the *consumer*. A status error, or the cluster-ID
interceptor firing (§3.7.4), causes the owner of the connection to tear the
client down and build a new one. For remote clusters that owner is the
per-cluster connection controller (§3.7.3). For the local store it is the
agent's kvstore module, which reports `Degraded` and retries with backoff.

#### 3.2.6 Initial connection

Establishing the first connection is bounded at **15 minutes**. Two things must
happen: the lock lease session must be created (skipped for remote clients),
and the heartbeat watcher must complete its initial list. Timeout produces
`timed out while waiting for kvstore connection` or `timed out while starting
the heartbeat watcher`, naming the endpoints.

Because 15 minutes is far longer than a pod start budget, the agent and the
operator wait only **5 seconds** synchronously (a circuit breaker) and then
continue starting while the connection completes in the background. If it
ultimately fails, the process exits. **DEVIATION (ADR-0004):** the reference
implements this with a hive job with shutdown semantics; flowsdn implements it
as a fence waiter (`kvstore-connected`) with a non-fatal 5 s bound and a task
that terminates the process on definitive failure (spec `00` §3.4.1).

### 3.3 Leases and locks

#### 3.3.1 Leases

Two lease managers per client:

| Manager | TTL | Used by |
|---|---|---|
| key lease | `kvstore-lease-ttl` (15 m; valid range 25 s..24 h) | every leased data key and every synced canary |
| lock lease | 25 s (fixed) | distributed locks, including the quorum probe |

A manager grants a lease, starts its keepalive stream, and binds keys to it
until it holds **1000 keys**, then grants another. Bindings are tracked
in-process (`key → lease id`) so that:

- `delete` / `delete_prefix` release the binding and decrement the lease's key
  count;
- `put_if_different` can detect that a key's *server-side* lease no longer
  matches the client's current lease and force a rewrite (§3.1 row 4);
- a lost lease can be reported per key.

**Lease loss.** When a keepalive stream ends for any reason other than client
shutdown, the manager MUST log at warning level, drop the lease and its
bindings, and invoke every registered expiry observer whose prefix matches each
bound key. Observers are registered by prefix; a `SyncStore` registers one for
its data prefix and one for its canary key, and re-enqueues the affected keys
for rewrite (§3.4.2). Without this, a lease loss silently deletes a cluster's
entire exported state from every peer's view and it never comes back.

The manager MUST NOT check lease validity client-side before handing a lease
out. A stale lease is handed out, the operation fails at the server, and the
caller retries — this is simpler and has no race window. On a
`lease not found` error the manager orphans the session, which triggers the
loss path above.

#### 3.3.2 Distributed locks

Locks are implemented **client-side** over `Txn` and `Watch`, not with the
`v3lock` gRPC service (§2.7 F26). The key layout MUST be the reference's, since
the reference's lock sweeper and any Cilium peer share it:

```
<path>/<lease-id-in-lowercase-hex>
```

Acquire: create `<path>/<hex>` with the lock lease, `put_if_absent`; read the
prefix `<path>/` ordered by creation revision; if this client's key has the
lowest creation revision it owns the lock, otherwise watch the immediately
preceding key until it disappears and re-evaluate. Release: delete the key.
The ownership compare handed to `guard?` arguments is
`Compare(CreateRevision(<path>/<hex>) == <the revision we created it at>)`.

Two bounds: acquisition is capped at **1 minute**; the lock lease is 25 s, so a
crashed holder's key disappears within 25 s regardless.

**Process-local locks.** Before taking the distributed lock, a caller takes an
in-process lock on the same path, so that concurrent tasks in one agent do not
contend over the network. A local lock held longer than **30 s** is
force-released by a GC timer running every 30 s, with an error log naming the
path: it means a task leaked, and blocking identity allocation forever is worse
than the leak.

### 3.4 Store synchronizers

Three patterns over the client, plus the manager that gates them.

#### 3.4.1 `SharedStore` — owned keys, round-tripped

Used only for node records. The store owns a set of local keys, writes them
leased, and simultaneously watches the whole prefix to learn about other
writers' keys.

- Initial list must complete within **3 minutes** or the join fails.
- A `Delete` event for a key this store owns is an anomaly (someone else, or a
  lease loss) and MUST cause an immediate re-create, logged at warning level.
- A `Delete` event for a foreign key is **deferred** by
  `SharedKeyDeleteDelay` (30 s for nodes) before being reported: if the key
  reappears inside the window the delete is suppressed, with a warning. This
  absorbs a peer agent restarting and re-writing its own node key.
- Optional periodic resync (30 minutes for nodes) rewrites every owned key,
  repairing any drift.

#### 3.4.2 `SyncStore` — one-way export

Used by the apiserver and the operator to push Kubernetes state into the store.
A work queue with per-item exponential retry (5 ms → 1000 s) plus a global
10 qps / burst 100 bucket, one worker by default.

- `upsert(key, value)` is a no-op when the marshalled value is byte-identical
  to what was last written. This is what keeps a resync from rewriting the
  world.
- Every write is leased unless the store was built without a lease.
- When the source signals that its initial listing is complete, the store
  enqueues a **synced canary**: it is written only once the pending set is
  empty, so the canary means "everything from the initial list is durably in
  the store". If the pending set is not empty the canary is re-queued through
  the rate limiter.
- On lease expiry (§3.3.1): the canary key expiring re-enqueues the canary
  *without* re-running the completion callbacks; a data key expiring re-enqueues
  that key.

#### 3.4.3 `WatchStore` — one-way import

Used for every remote resource. `watch(prefix)` appends a trailing `/` to the
prefix if absent, so a watch on `.../nodes/v1/c1` never sees `.../nodes/v1/c11`.

- **Restartable.** On every (re)start, all currently held entries are marked
  stale. When the initial list completes, entries still marked stale are
  emitted as synthetic deletes and dropped. This is what makes a reconnection
  converge without a full drain, and it is why the reference can survive a
  compaction (§5.4).
- Starting a watch on a store that is already watching, or draining one that
  is, is a programming error.
- `drain()` emits deletes for every entry and clears the store: used on
  permanent disconnect, cluster-ID change, and cache revocation.
- On-sync callbacks run once and are then cleared, so a reconnection does not
  re-signal readiness.

#### 3.4.4 `WatchStoreManager` — canary gating

Callers `register(prefix, start_fn)` before the manager runs; registration
after start is a programming error. Two implementations:

- **Canary-gated** (peer advertises `syncedCanaries`): the manager watches
  `cilium/synced/<cluster>/` and starts `start_fn` for a registered prefix only
  when the canary for that prefix appears. Each prefix starts at most once.
- **Immediate** (peer does not advertise it): everything starts at once, and
  the local caches may transiently miss entries the peer has not written yet.

### 3.5 Heartbeat and cluster config

#### 3.5.1 Heartbeat

A single writer per cluster (the operator, or the apiserver, or kvstoremesh)
writes `cilium/.heartbeat` = RFC3339 timestamp, leased, **every 60 s**, each
write bounded at 25 s. Readers never parse the value: the *arrival of the watch
event* is the signal, so no clock synchronisation between clusters is required.
Two missed writes (§3.2.5 step 2) declare the peer's control plane dead.

#### 3.5.2 Cluster config enforcement

Each cluster writes exactly one `cilium/cluster-config/<own-name>` key holding
its `CiliumClusterConfig` (§4.2), leased. The writer:

1. establishes its own watch on the key first, and waits **5 s** for it to be
   established before the first write, so it cannot race itself;
2. computes the ownership-guarded transaction in §12 decision 9; unchanged
   same-owner values on the desired lease require no write; unchanged bytes
   on a different lease MUST be rebound by a guarded PUT;
3. on modification/deletion rereads owner and config together, then repairs
   only when the same UUID still owns the name; foreign/legacy values fail closed;
4. refreshes every **5 minutes** regardless.

The key is the only thing peers exchange about each other's configuration.

### 3.6 Identity allocation in kvstore mode

Spec `03` owns the identity model, the numbering and the CRD backend. This
section specifies the kvstore backend that sits behind the same
`IdentityBackend` trait (spec `03` §11), so that the allocation protocol above
the trait — reference counting, local caches, the identity manager, GC
scheduling — is shared and unchanged.

#### 3.6.1 Keys

| Key | Value | Lease | Meaning |
|---|---|---|---|
| `cilium/state/identities/v1/id/<decimal id>` | the canonical label string (spec `03` §4.1) | **none** | *master key*: this id is taken, and this is what it means |
| `cilium/state/identities/v1/value/<label string>/<node suffix>` | the decimal id | key lease | *slave key*: this node is using this id |
| `cilium/state/identities/v1/locks/<label string>/<lease hex>` | (lock) | lock lease | serialises allocate/release/GC for one label set |

`<node suffix>` is the node's identifier — its IPv4 address when it has one,
otherwise its IPv6 address. It appears in the key, not the value, so that a
node's slave keys vanish with its lease.

The master key is deliberately **unleased**: an identity must outlive the agent
that first allocated it, or every agent restart would renumber the cluster.
Reclaiming it is GC's job (§5.6).

The trailing `;` of the canonical label string is what makes the `value/`
prefix listing sound: without it, `value/k8s:app=foo;` would also match
`value/k8s:app=foobar;/...`. A listing therefore additionally checks that the
**last** `/` in the returned key sits exactly at the end of the requested
prefix.

#### 3.6.2 ID range per cluster

`shift = 24 - log2(max-connected-clusters + 1)` (16 or 15). The allocator is
constructed with:

- `min = cluster-id == 0 ? 256 : cluster-id << shift`
- `max = ((cluster-id + 1) << shift) - 1`
- prefix mask `cluster-id << shift`

so cluster 1 with `max-connected-clusters = 255` allocates `65536..131071`,
cluster 2 `131072..196607`, and a cluster with id 0 (not meshed) allocates
`256..65535`. Reserved identities (`< 256`) are global and never allocated.
Spec `03` §4.5 is normative for the arithmetic; this section is normative for
the fact that the allocator applies it.

#### 3.6.3 Allocation

1. Take the lock on `locks/<label string>`.
2. `list_prefix("value/<label string>/")` under the lock. If any entry's key
   matches the prefix exactly at its last `/`, that entry's value is the id —
   go to step 5.
3. Pick a free id from the local id pool within `[min, max]`.
4. `put_if_absent("id/<id>", label string, lease = None)` under the lock. If it
   returns `false`, another cluster member took that id between steps 3 and 4;
   return the id to the pool and retry from step 3.
5. `put_if_different("value/<label string>/<node suffix>", <id>, lease = key
   lease)` under the lock.
6. Release the lock.

Release is the mirror and does **not** take the lock (it is serialised by the
in-process slave-key mutex): delete `value/<label string>/<node suffix>`. The
master key is left for GC.

**Refresh.** Every entry the local cache still holds is periodically
re-asserted: the master key is re-created with `put_if_absent` (never
overwritten — a warning is logged if it had gone missing), and the slave key is
re-created or updated. This repairs a lease loss and a master key deleted by an
over-eager GC.

#### 3.6.4 Coexistence with CRD mode

`identity-allocation-mode` selects the backend:

| Value | Backend | Status in flowsdn |
|---|---|---|
| `crd` | `CiliumIdentity` objects (spec `03` §3.3) | supported; the default |
| `kvstore` | this section | supported when `kvstore` is set; otherwise fatal |
| `doublewrite-readkvstore`, `doublewrite-readcrd` | both, one authoritative | **not implemented**; rejected at startup with a message naming the two supported values |

Everything above the trait is identical in both modes, including the numbering,
the cluster-ID range, the label-string key, the local (`0x01`) and remote-node
(`0x02`) scopes, and the identity change stream the policy engine consumes.
A cluster MUST NOT change modes while running; the migration path the
double-write modes exist to serve is rejected in favor of the documented offline
procedure (§12 decision 3).

In CRD mode, a mesh still needs identities visible to peers: the
clustermesh-apiserver mirrors `CiliumIdentity` objects into
`cilium/state/identities/v1/id/<id>` (§3.8.2). Peers cannot tell the two modes
apart, which is exactly the intent.

### 3.7 ClusterMesh: the agent side

ClusterMesh is enabled when `cluster-id != 0` **and** `clustermesh-config` names
a directory. Either alone disables it silently.

#### 3.7.1 The config directory

Every regular file in the directory whose **content contains the substring
`endpoints:`** is a remote-cluster config; its **file name is the cluster
name**. Directories are skipped. This test is intentionally crude — it is what
lets a Kubernetes Secret projection, whose directory also contains `..data`
symlinks and per-cluster certificate files, be watched directly.

Two file-system watchers are required: one on the directory, one added
explicitly per config file. A Secret projection replaces a symlink rather than
writing the file, so a watcher on the directory alone misses content changes,
and a watcher on the file alone is broken by the symlink swap. On adding a
per-file watch the implementation MUST immediately re-read the file, closing
the window between the read and the watch registration.

Each tracked file's SHA-256 is remembered. A notification whose content hash is
unchanged MUST be ignored — Secret projections generate many spurious events.

Lifecycle events: a new or changed file is an `add` (add and update are the
same event; the connection layer distinguishes them); a file that stops being a
config, or disappears, is a `remove`. A file whose name equals the local cluster
name is ignored. A file whose name is not a valid cluster name is refused with
an error log and no connection.

The config file MAY carry a `cilium-host-aliases` list (§2.3). It is parsed
from the same YAML and validated: empty hostname, empty IP list, or a duplicate
hostname is a parse error that fails the connection attempt.

#### 3.7.2 Cluster-ID reservation

The agent keeps a set of cluster IDs in use by remote clusters. Reserving fails
when the ID is `0` (`clusterID 0 is reserved`), equals the local cluster's ID
(`clusterID <n> is assigned to the local cluster`), or is already held by a
different remote (`clusterID <n> is already used`). Two peers advertising the
same ID is a misconfiguration that MUST be refused rather than merged: their
identity ranges and ipcache cluster-ids would collide.

#### 3.7.3 Connection lifecycle

One controller per remote cluster, named `remote-etcd-<cluster>`, restarted on
every failure with linear backoff (1 s, 2 s, 3 s, …, reset on success). One
attempt:

| Step | Action | Failure |
|---|---|---|
| 1 | Arm the cache-TTL timer if it is not already armed (§3.7.7) | — |
| 2 | Release the previous connection: wait for all child tasks, drop the client, clear the pinned store id, close the old client | — |
| 3 | Create a fresh cluster-ID pin (§3.7.4) and parse `cilium-host-aliases` | parse error → retry |
| 4 | Build a kvstore client for this peer with the forced options below | — |
| 5 | Wait for *either* the client's initial-connection signal or a pin error | error → close client, retry |
| 6 | Record the peer store's id (lower-case hex) and start the watchdog (§3.7.6) | — |
| 7 | Fetch `cilium/cluster-config/<cluster>` (§3.7.5) | error → cancel, retry |
| 8 | Disarm the cache-TTL timer | — |
| 9 | Run the import registration (§3.7.8) in a child task and wait for its readiness signal | error → retry |
| 10 | Mark the remote cluster ready | — |

**Forced client options** for a remote peer, which MUST NOT be overridable:
quorum lock check **off** (the client has no write permission on a peer's
store), endpoint status checks **off**, cluster name set for the rate-limiter
name, plus the cluster-ID interceptors and the dialer. Consequently the only
liveness signal for a remote peer is the heartbeat (§3.2.5 step 2).

**Propagated options.** Exactly five keys from the local `kvstore-opt` reach a
remote client: `etcd.qps`, `etcd.maxInflight`, `etcd.limit`,
`etcd.keepaliveHeartbeat`, `etcd.keepaliveTimeout`. `kvstore-lease-ttl` and
`kvstore-max-consecutive-quorum-errors` are inherited. Everything else — in
particular `etcd.address` and `etcd.bootstrapQps` — MUST be dropped: the
endpoint comes from the per-cluster config file, and a shared bootstrap rate
would let one peer's cold start starve the others.

#### 3.7.4 The cluster-ID interceptor pin

Every response and every watch message from a remote store carries the store's
own cluster id in its header. The first non-zero id observed on a connection is
**latched**; every later response MUST match it. A mismatch, or a response with
no header at all, pushes an error onto a one-slot channel that both the initial
connect and the watchdog select on, and the in-flight operation fails with a
distinguishable "aborted by interceptor" error so the watch loop treats it as a
relist trigger rather than a data error.

This exists because an endpoint address can start pointing at a different store
— a DNS change, a Service reused for a rebuilt cluster, a load balancer
fronting two apiservers. Without the pin the agent would silently merge two
clusters' state under one name. A fresh pin is created on every reconnect, so a
deliberate rebuild recovers after one connection cycle.

**fastetcd note (§2.7 F17).** The pin is only as good as the store's cluster
id. fastetcd defaults it to `1` for every deployment, so §6.6 makes a distinct
`--cluster-id` mandatory in the flowsdn apiserver manifest.

#### 3.7.5 Cluster config retrieval

A sub-controller polls `cilium/cluster-config/<cluster>` for up to **3 minutes**
with retries capped at 30 s. Retrying here rather than in the outer controller
is deliberate: a missing config is a normal state on a peer that has not
finished starting, and tearing down the connection each time would be much
slower to converge.

A missing key is reported with the hint *"If KVStoreMesh is enabled, check
whether it is connected to the target cluster. Additionally, ensure that the
cluster name is correct"* — the two overwhelmingly common causes.

The status fields `config.required` (always true once retrieval starts) and
`config.retrieved` come from this step, as do the reported `cluster-id`,
`kvstoremesh`, `sync-canaries`, `service-exports-enabled` and
`endpoint-slices-export-mode`.

#### 3.7.6 The watchdog

One task per connection selects on the client's status-error stream and the
pin's error channel. On either, it increments the failure counter, stamps the
last-failure time, updates the readiness metric, and restarts the connection
controller. It is the only thing that turns a *detected* fault into a
*reconnect*; the client itself never reconnects on its own.

#### 3.7.7 Cache TTL and revocation

`clustermesh-cache-ttl` (default `0` = never) bounds how long a disconnected
peer's imported data stays usable. The timer is armed on the first failed
connection attempt and disarmed on the first successful config retrieval. On
expiry the agent performs a **partial** revocation: it drains remote
**services** (and any observer that supports revocation), and leaves remote
nodes, ipcache entries and identities in place.

The asymmetry is deliberate and MUST be preserved. Stale service backends cause
active mis-routing to a cluster that may be gone. Stale nodes and ipcache
entries cause, at worst, tunnel and policy state for endpoints that no longer
answer — and dropping them tears down working IPsec associations and forces a
full policy recomputation on a peer that is very likely to come back.

#### 3.7.8 Import registration and ordering

Once the config is validated (§3.10) and the cluster ID reserved, the agent
registers imports on a watch-store manager — canary-gated when the peer
advertises `syncedCanaries`, immediate otherwise — and, when the peer
advertises `cached`, rewrites every prefix from `cilium/state` to
`cilium/cache`.

| Import | Prefix watched | Validators | Consumer |
|---|---|---|---|
| nodes | `<p>/nodes/v1/<cluster>` | cluster name matches the file name; node name matches the key; `ClusterID` matches the reserved ID | node manager, source `clustermesh` |
| services | `<p>/services/v1/<cluster>` | cluster name; `<ns>/<name>` matches the key; `clusterID` matches | global service cache → LB merge (§3.7.9) |
| ipcache | `<p>/ip/v1/default` (or `<cache>/ip/v1/<cluster>`) | identity in the peer's range **or** reserved (`< 256`) | ipcache, source `clustermesh` |
| identities | `<p>/identities/v1` (or `<cache>/identities/v1/<cluster>`) | identity in the peer's range; labels contain `k8s:io.cilium.k8s.policy.cluster=<cluster>` — checked on upsert only, never on delete | remote identity cache |
| endpoint slices | `<p>/endpointslices/v1/<cluster>` | cluster name; namespaced name; `clusterID` | counted only at this reference tag (§3.7.9) |

The cluster-name label check is skipped for deletions on purpose: labels may not
have propagated, and refusing a delete leaves a stale identity forever.

**Ordering constraints as fences (spec `00` §3.4.1).** Registration order does
not impose ordering — the manager may start all prefixes at once. Ordering is
expressed by what the rest of the agent *waits for*:

| Waiter | Waits for, per remote cluster | Released to |
|---|---|---|
| `clustermesh-nodes` | nodes synced | node manager's mesh-sync signal, ipset initializer |
| `clustermesh-ip-identities` | ipcache **and** identities **and** nodes synced | the `clustermesh-sync` fence, hence the first endpoint regeneration |
| `clustermesh-services` | services synced (or endpoint slices, per §3.7.9) | the `lb-init` fence's `clustermesh` initializer |

Nodes are included in the ip-identities waiter because node records themselves
insert ipcache entries (node addresses, health IPs, ingress IPs); waiting only
on the ipcache prefix would release the fence before those exist.

All three are bounded by `clustermesh-sync-timeout` (1 minute). On expiry the
waiter logs *once* at warning level and **returns success**: this is a circuit
breaker, not a failure. Blocking endpoint regeneration forever because one peer
is unreachable is strictly worse than starting with incomplete remote state.
A cluster that disconnects while a waiter is pending releases that waiter
immediately with a distinguishable "disconnected" outcome, which the aggregate
waiter ignores.

#### 3.7.9 Global services

A remote `ClusterService` becomes LB backends:

1. For each backend IP in the record (which may carry an `@<cluster-id>`
   suffix), for each named port, construct a backend at
   `(protocol, addr, port)` with weight 100, **no node name**, state `Active`,
   the record's `clusterID`, external scope, and the zone from the record's
   `zones` map if present.
2. **De-duplicate by L4 address within one IP**: several port names sharing one
   `(protocol, port)` collapse into a single backend carrying all of those port
   names. The exporting side writes one entry per port name; the LB model wants
   one backend with several names.
3. Sort each backend's port names, so the result is deterministic.
4. Replace the whole backend set for `(service name, source = clustermesh,
   cluster id)` in one write transaction. A delete removes the whole set for
   that `(service, cluster id)`.

**Affinity.** `service.cilium.io/affinity` overrides backend selection for
global services only. Let `L` = local backends, `R` = remote backends
(source `clustermesh`); "healthy" = state `Active` or `Terminating` and not
marked unhealthy; `L_active` = healthy locals in state `Active`.

| Value | Locals used | Remotes used |
|---|---|---|
| service is not global | yes | **no** |
| `none`, absent, or unparseable | yes | yes |
| `local` | **always**, even when unhealthy | only when `L_active == 0` and there is at least one healthy remote |
| `remote` | only when there are no healthy remotes and at least one healthy local | **always** |

An unparseable value logs a warning and behaves as `none`. Terminating local
backends do not keep remotes out (`L_active` counts only `Active`), while
terminating remote backends do count as present for the `local` fallback test —
this asymmetry is the reference's and is preserved, because it biases towards
keeping traffic local during a rolling update.

**Endpoint-slice sync mode.** `clustermesh-service-v2` selects between the
legacy `services/v1` import and the `endpointslices/v1` import. At the reference
tag the endpoint-slice import store **has no consumer**: entries are counted for
status and metrics and then discarded. Selecting `prefer-endpointslice` or
`only-endpointslice` therefore stops importing service backends *without
replacing them*, and every global service loses its remote backends.

**DEVIATION.** flowsdn accepts only `prefer-legacy` and rejects the other two
values at startup, rather than shipping a mode that silently breaks global
services. The key schema, the export path and the `endpointSlicesExportMode`
capability remain part of the required producer contract. A peer exporting only
slices is incompatible with this importer and must be rejected; dual exporters
remain compatible through their legacy records. §12 decision 4 revisits
this when the consumer exists.

#### 3.7.10 Status

`ready` for a remote cluster is the conjunction of: a live connection; the
cluster config retrieved; nodes, services, identities and ipcache all synced;
the import registration completed; and every *enabled* observer synced.
`services` is forced true when legacy services are not being watched, and the
`endpoint-slices` / `service-exports` fields are null when the corresponding
import is not enabled — nullability is how "not applicable" is distinguished
from "not yet synced".

`status` is the client's status message (§3.2.5), with `, ID: <store id hex>`
appended once the pin has latched, or the literal `Waiting for initial
connection to be established` before the first connection.

`cilium-dbg status` renders (clusters sorted by name; by default only
not-ready clusters get the detail block, `--all-clusters` shows all):

```
ClusterMesh:    <ready>/<total> remote clusters ready
   <name>: <ready|not-ready>, N nodes, N endpoints, N identities, N services, N endpoint slices, N MCS-API service exports, N reconnections (last: <since>)
   └  <status string>
   └  remote configuration: expected=<bool>, retrieved=<bool>[, cluster-id=N, kvstoremesh=<bool>, sync-canaries=<bool>, service-exports=<enabled|disabled|unsupported>, endpoint-slice-export-mode=<mode|services-only>]
   └  synchronization status: nodes=<bool>, endpoints=<bool>, identities=<bool>, services=<bool>[, endpoint-slices=<bool>][, service-exports=<bool>]
```

The bracketed part of the configuration line appears only when `retrieved` is
true; when the config is absent entirely the line reads
`expected=unknown, retrieved=unknown`. An empty export mode renders as the
literal `services-only`.

### 3.8 `flowsdn-clustermesh-apiserver`

One Deployment per cluster. It is the cluster's *publisher*: it watches
Kubernetes and writes this cluster's state into a store that peers read.

#### 3.8.1 Process shape

**DEVIATION (§6.6).** The reference pod is four containers: an `etcd-init` job
that wipes a data dir, starts a localhost etcd, creates users/roles and enables
auth; an `etcd` sidecar; the `apiserver`; and optionally `kvstoremesh`. flowsdn
ships **two**: `fastetcd` and `flowsdn-clustermesh-apiserver` (with kvstoremesh
as a mode of the same binary). There is no init container, because there is no
etcd Auth bootstrap to perform (§3.8.5).

#### 3.8.2 Synchronizers

Each synchronizer watches one Kubernetes resource, writes one kvstore prefix
through a `SyncStore` (§3.4.2), and publishes one synced canary. Readiness
(§3.8.7) is the conjunction of all enabled synchronizers having published
theirs.

| Synchronizer | Watches | Prefix written | Key | Value | Canary |
|---|---|---|---|---|---|
| nodes | `CiliumNode` | `cilium/state/nodes/v1` | `<cluster>/<node name>` | node JSON (§4.3), with `Cluster` and `ClusterID` overwritten with this cluster's | `cilium/synced/<cluster>/cilium/state/nodes/v1` |
| identities | `CiliumIdentity` | `cilium/state/identities/v1/id` | `<numeric id>` | the canonical label string built from `security-labels` (§4.5) | `cilium/synced/<cluster>/cilium/state/identities/v1` (**note: the canary drops the `/id` segment**) |
| ipcache | `CiliumEndpoint`, or `CiliumEndpointSlice` when CES is enabled | `cilium/state/ip/v1/default` | the IP (or `ip/len`) | `IPIdentityPair` JSON (§4.4) | `cilium/synced/<cluster>/cilium/state/ip/v1` (**drops `/default`**) |
| services | `Service` + `EndpointSlice` + `Namespace` | `cilium/state/services/v1` | `<cluster>/<ns>/<name>` | `ClusterService` JSON (§4.6) | `cilium/synced/<cluster>/cilium/state/services/v1` |
| endpoint slices | `EndpointSlice` + `Service` + `Namespace` | `cilium/state/endpointslices/v1` | `<cluster>/<ns>/<slice>` | zstd(protobuf) (§4.7) | `cilium/synced/<cluster>/cilium/state/endpointslices/v1` |
| service exports (deferred) | `ServiceExport` | `cilium/state/serviceexports/v1` | `<cluster>/<ns>/<name>` | `MCSAPIServiceSpec` JSON (§4.8) | `cilium/synced/<cluster>/cilium/state/serviceexports/v1` |

The two canary overrides are load-bearing: readers register their watch on
`cilium/state/identities/v1` and `cilium/state/ip/v1`, not on the `/id` and
`/default` sub-prefixes, so the canary must name what the reader registered.

**Identity values are not JSON.** The identity key's value is the bare
canonical label string. An identity with no security labels is skipped
entirely — neither written nor deleted — with a warning.

**IP ownership arbitration.** Two Kubernetes objects can claim the same IP
(a pod recreated with the same address, or a CEP and a CES entry overlapping).
Each IP key has one primary owner and a FIFO of pending owners: only the
primary's value is written; when the primary releases, the next pending owner's
value is written; the key is deleted only when the last owner releases. Without
this, a pod deletion racing a pod creation on a reused IP deletes the new pod's
ipcache entry.

**Global namespaces.** `clustermesh-default-global-namespace` (default `true`)
and the `clustermesh.cilium.io/global` namespace annotation decide whether a
namespace's identities, endpoints, services and endpoint slices are exported.
A resource in a non-global namespace is **converted to a delete**, not dropped:
that is what makes flipping a namespace from global to local remove the already
published state. A namespace event re-evaluates every object of every namespaced
synchronizer in that namespace. Delete events bypass the namespace check
entirely, so a delete is never suppressed.

#### 3.8.3 Cluster config publication

The apiserver publishes `cilium/cluster-config/<own name>` with
`syncedCanaries: true`, its cluster ID, `maxConnectedClusters`,
`serviceExportsEnabled` (a pointer: absent means "does not support the concept")
and `endpointSlicesExportMode`. Enforcement follows §3.5.2: watch first, write
after a 5 s establishment wait, re-write on foreign modification or deletion,
refresh every 5 minutes. The initial write is retried three times with 2 s→30 s
backoff and, on final failure, terminates the process — a cluster whose config
is unpublished is invisible to the mesh and should fail loudly.

#### 3.8.4 The local etcd

The apiserver's own connection to the store uses `etcd.qps=50` and
`etcd.bootstrapQps=10000`; kvstoremesh uses `etcd.qps=100` and
`etcd.maxInflight=10`. The bootstrap rate applies until the last synchronizer
publishes its canary.

#### 3.8.5 Users, roles and ACL ranges

The reference creates etcd users and roles at init time and relies on
`--client-cert-auth` mapping a client certificate's CN to an etcd user:

| User | Role | Read ranges granted |
|---|---|---|
| `root` | `root` (built-in) | everything |
| `admin-<cluster>` | `root` | everything; used by the apiserver itself |
| `local-<cluster>` | `local` | `cilium/.heartbeat`; prefixes `cilium/cache/`, `cilium/cluster-config/`, `cilium/synced/` |
| `remote` (and per-cluster `remote-<peer>`) | `remote` | `cilium/.heartbeat`; prefix `cilium/state/`; the single key `cilium/cluster-config/<own cluster>`; prefix `cilium/synced/<own cluster>/` |

All grants are **read-only**; no role is ever granted write. Range ends are the
prefix successor (`cilium/state/` → `cilium/state0`), and the heartbeat is
granted as a prefix *without* a trailing slash, so `cilium/.heartbeat` →
`cilium/.heartbeau`. The three auth modes are `legacy` (one `remote` user with
the `root` role), `migration` (default: shared `remote` user plus per-cluster
users) and `cluster` (per-cluster users only).

**DEVIATION (§2.7 F19).** fastetcd has no CN→user mapping, so etcd Auth cannot
authenticate anyone in this deployment model; enabling it would either lock the
apiserver out or leave every client unauthenticated. flowsdn therefore does not
use etcd Auth at all. Instead:

1. Authentication is mTLS: the store requires a client certificate signed by
   the cluster's CA. This is unchanged from the reference.
2. Authorization is **prefix scoping enforced by the flowsdn apiserver front**,
   not by the store. A peer connects to the apiserver's gRPC listener, which
   maps the verified leaf certificate's single CN through an explicit binding
   to Local or Remote read-only roles (never a caller-supplied role) and rejects
   any `Range`/`Watch` outside its allowed ranges and every mutating RPC.
3. The table above is therefore still normative: it is the front's policy
   table, expressed in exactly the reference's ranges, so a Cilium peer using a
   `remote` certificate sees exactly what it expects.
4. `cluster-users-enabled`, `cluster-users-config-path`, the `users.yaml` file
   and the `clustermesh-remote-users` ConfigMap are accepted and ignored, with
   one startup warning naming this section.

`flowsdn-clustermesh::principal` binds an already TLS-verified certificate CN
to an opaque, authority-bound principal. Missing/multiple CNs and unknown names
reject; comparison is exact and case-sensitive. A principal cannot be reused
with another front authority. Binding updates validate atomically, and request
authorization consults the current bindings, so removing a CN revokes existing
session principals. The transport must also cancel existing watches when their
binding is revoked or narrowed; checking only watch creation is insufficient.
The table's root/admin entries describe the reference private administration
path, not public frontend roles. Administrative writes use a separate private
trusted client and are never granted by the public reader front.

The trusted TLS adapter must verify certificate chain, validity and client-auth
purpose before invoking this helper. The helper performs no cryptographic
verification, gRPC parsing, active-watch cancellation or network isolation.
Its name/role API is not permission to trust an RPC field or unverified CN.

§12 decision 5 records the alternative (implement CN→user mapping and RBAC in
fastetcd and keep the reference model) and why it is not the first cut.

#### 3.8.6 TLS layout

Four certificates, one CA (`Cilium CA`), all with the reference's common names
because a Cilium peer's certificate must be accepted and vice versa.

| Certificate | CN | SANs | Where used |
|---|---|---|---|
| server | `clustermesh-apiserver.<namespace>.svc` | that name, `*.mesh.cilium.io`, `127.0.0.1`, `::1`, plus configured extras | the store's listener |
| admin | `admin-<cluster>` | — | apiserver and kvstoremesh → local store |
| remote | `remote`, or `remote-<cluster>` in `cluster` auth mode | — | this cluster's agents and kvstoremesh → **peer** stores |
| local | `local-<cluster>` | — | this cluster's agents → **local** store, when kvstoremesh is on |

Agent-side file names are frozen because the config files reference them:
`common-etcd-client{-ca.crt,.crt,.key}` (remote cert),
`local-etcd-client{-ca.crt,.crt,.key}` (local cert), and the per-cluster
`<cluster>.etcd-client{-ca.crt,.crt,.key}` form. All mounted mode `0400`.

Which one an agent uses is decided by whether kvstoremesh is enabled: with
kvstoremesh the agent dials its **own** apiserver at
`https://clustermesh-apiserver.<ns>.svc:2379` with the `local-` files; without
it, each peer directly with the `common-` files.

#### 3.8.7 Health and metrics

`GET /readyz` on `agent-health-port`-style flag `health-port` (9880 for the
apiserver, 9881 for kvstoremesh), all interfaces, plain HTTP: `200 Ready` once
every registered synchronizer has completed its initial sync, `500 NotReady`
otherwise. `GET /metrics` on `prometheus-serve-addr` (disabled by default;
9962 / 9964 in the manifests). Metric namespaces are
`cilium_clustermesh_apiserver` and `cilium_kvstoremesh` (§8).

### 3.9 kvstoremesh

kvstoremesh mirrors every remote cluster's exported state into the **local**
store under `cilium/cache/`, so that every agent in the cluster dials one
endpoint instead of N, and one component absorbs the N connections.

It reuses the entire agent-side connection lifecycle of §3.7.1–§3.7.7
unchanged. What differs is what it does once connected.

#### 3.9.1 Reflectors

Six reflectors, each a `WatchStore` on the remote feeding a `SyncStore` on the
local store, passing values through **byte-for-byte** with no re-encoding.

| Reflector | Remote prefix | Local prefix written | Local canary |
|---|---|---|---|
| `nodes` | `cilium/state/nodes/v1/<cluster>` | `cilium/cache/nodes/v1/<cluster>` | `cilium/synced/<cluster>/cilium/cache/nodes/v1` |
| `identities` | `cilium/state/identities/v1/id` | `cilium/cache/identities/v1/<cluster>/id` | `cilium/synced/<cluster>/cilium/cache/identities/v1` |
| `endpoints` | `cilium/state/ip/v1/default` | `cilium/cache/ip/v1/<cluster>` | `cilium/synced/<cluster>/cilium/cache/ip/v1` |
| `services` | `cilium/state/services/v1/<cluster>` | `cilium/cache/services/v1/<cluster>` | `cilium/synced/<cluster>/cilium/cache/services/v1` |
| `endpoint slices` | `cilium/state/endpointslices/v1/<cluster>` | `cilium/cache/endpointslices/v1/<cluster>` | `cilium/synced/<cluster>/cilium/cache/endpointslices/v1` |
| `service exports` | `cilium/state/serviceexports/v1/<cluster>` | `cilium/cache/serviceexports/v1/<cluster>` | `cilium/synced/<cluster>/cilium/cache/serviceexports/v1` |

Identities and ipcache are the two irregular ones: their source prefixes are
not cluster-scoped (a cluster publishes identities under a flat `id/`), so the
mirror **inserts** the cluster name — which is exactly why the `cached`
capability changes the reader's prefix shape as well as its root.

When a remote peer is itself `cached`, the reflector reads the peer's
`cilium/cache/...` instead. A disabled reflector still drains its store and
publishes its canary, so it never blocks readiness.

Only `services`, `endpoint slices` and `service exports` participate in
cache-TTL revocation, matching the agent's partial-revocation rule (§3.7.7).

#### 3.9.2 Cluster config rewrite

kvstoremesh republishes each peer's config into the **local** store at
`cilium/cluster-config/<peer>`, copying every field and overriding exactly two:
`syncedCanaries = true` and `cached = true`. Local agents then read the peer's
real ID and capabilities but look for its data under `cilium/cache/`.

This write happens **before** any reflector is registered, so an agent that
sees the config can rely on the canaries appearing.

#### 3.9.3 Drain on disconnection

When a peer's config file is removed, its mirrored data MUST be removed, or
agents would keep serving it forever with no writer to expire it. The sequence,
in this exact order:

1. Delete `cilium/cluster-config/<peer>`. **First**, so an agent starting
   during the drain does not connect to a half-deleted cache.
2. Wait a **3 minute grace period** — first attempt only — so running agents
   observe the config deletion and disconnect on their own before their data
   disappears underneath them.
3. Delete the prefix `cilium/synced/<peer>/`.
4. Delete each reflector's `cilium/cache/<resource>/<peer>/`, reflectors taken
   in a deterministic (name-sorted) order.

The whole sequence is retried up to 5 times (6 attempts) with 2 s doubling
backoff (2, 4, 8, 16, 32 s); the grace period is skipped on retries. Failure
after the last attempt is logged as an error naming the inconsistency risk.

A hidden `disable-drain-on-disconnection` skips the drain entirely; it MUST log
that reconnecting to the same cluster without restarting kvstoremesh can leave
inconsistent state.

#### 3.9.4 Leader election and readiness

Exactly one kvstoremesh instance may write the cache. Leadership is a
distributed lock on `cilium/kvstoremesh-lock` held under the lock lease; losing
the lock's lease MUST terminate the process rather than continue writing. The
first acquisition attempt is bounded at 10 s; on timeout the component signals
readiness anyway and then retries without a bound, so a stuck lock does not
gate the pod's readiness forever.

Readiness: a peer that does not connect within `per-cluster-ready-timeout`
(15 s) is dropped from the readiness computation with a log line; the whole
sync is bounded by `global-ready-timeout` (10 m), after which kvstoremesh
declares itself ready and serves possibly-incomplete data, logging that it did.

### 3.10 Version skew

The only thing peers exchange about each other is
`cilium/cluster-config/<name>`. Everything below is derived from it.

| Capability | Absent / false | True | Gates |
|---|---|---|---|
| `id` | invalid — connection refused | 1..max | cluster-ID reservation, identity-range and ipcache validators |
| `syncedCanaries` | watches start immediately; caches may transiently miss entries | watches wait for `cilium/synced/<cluster>/<prefix>` | watch start ordering |
| `cached` | data under `cilium/state/...` | data under `cilium/cache/<...>/<cluster>`, cluster-scoped | prefix rewriting for every import |
| `maxConnectedClusters` | treated as 255 | 255 or 511 | refuse connection when the **local** cluster is in extended mode and the values differ |
| `serviceExportsEnabled` (nullable) | `null` = peer predates MCS-API → service-export import disabled | bool | the service-exports reflector/observer |
| `endpointSlicesExportMode` | `""` = services only | `services-and-endpointslices`, `endpointslices-only` | which of services / endpoint slices are imported; an **unknown** value refuses the connection |

Rules:

1. **Missing config key** is not an error; it is "the peer has not started yet".
   The agent retries for 3 minutes per connection attempt and then reconnects,
   forever. A pre-1.13 Cilium peer that never writes the key therefore never
   becomes ready, and says so in status, which is the correct outcome.
2. **Unknown fields** in the JSON MUST be ignored. Every field is
   `omitempty`-equivalent, so a newer peer's additions are invisible to an older
   reader and an older peer's omissions read as zero.
3. **New capabilities MUST be additive and default-off.** A capability whose
   absence changes behavior cannot be added without breaking every existing
   peer.
4. `maxConnectedClusters` asymmetry is the reference's: a cluster at the default
   255 accepts a peer advertising anything, while a cluster at 511 refuses a
   mismatch. flowsdn preserves it — tightening it would refuse connections that
   Cilium accepts — but logs a warning at 255 when a peer advertises 511,
   because the identity ranges then genuinely disagree.
5. flowsdn advertises `syncedCanaries: true` always, `cached` only from
   kvstoremesh, `serviceExportsEnabled: false` (present, not null) while MCS-API
   is deferred, and `endpointSlicesExportMode: services-and-endpointslices`
   because it exports both.
6. Cilium documents a **one-minor-version** skew limit across a mesh. flowsdn
   inherits it as a support statement, not an enforced check: nothing in the
   protocol carries a version, and refusing to connect on version grounds would
   be a new failure mode the reference does not have.

## 4. Data model

### 4.1 Complete key schema

All keys live under `cilium/`. `<C>` is the writing cluster's name. Keys are
built by joining elements with `/`, collapsing any `//`, and trimming a trailing
`/` (§5.1). Every path below is **frozen**: it is read by peer clusters.

| Key | Value encoding | Leased | Writer | Reader |
|---|---|---|---|---|
| `cilium/.initlock/<rand-u64-hex>/<lease-hex>` | lock marker | lock lease (25 s) | any client with the quorum probe enabled | itself only |
| `cilium/.heartbeat` | RFC3339 timestamp | key lease | operator, apiserver, kvstoremesh (`enable-heartbeat`) | every client, as a liveness watch |
| `cilium/kvstoremesh-lock/<lease-hex>` | lock marker | lock lease | kvstoremesh candidates | themselves |
| `cilium/cluster-config/<C>` | `CiliumClusterConfig` JSON (§4.2) | key lease | the cluster's own enforcer; kvstoremesh for a mirrored peer | every peer agent on connect |
| `cilium/synced/<C>/cilium/state/nodes/v1` | RFC3339 timestamp | key lease | nodes `SyncStore` | peers' watch manager |
| `cilium/synced/<C>/cilium/state/identities/v1` | RFC3339 | key lease | identities `SyncStore` (override: keys live under `.../id`) | idem |
| `cilium/synced/<C>/cilium/state/ip/v1` | RFC3339 | key lease | ipcache `SyncStore` (override: keys live under `.../default`) | idem |
| `cilium/synced/<C>/cilium/state/services/v1` | RFC3339 | key lease | services `SyncStore` | idem |
| `cilium/synced/<C>/cilium/state/endpointslices/v1` | RFC3339 | key lease | endpoint-slice `SyncStore` | idem |
| `cilium/synced/<C>/cilium/state/serviceexports/v1` | RFC3339 | key lease | service-export `SyncStore` (deferred) | idem |
| `cilium/synced/<C>/cilium/cache/<resource>/v1` | RFC3339 | key lease | kvstoremesh reflectors | local agents |
| `cilium/state/nodes/v1/<C>/<node>` | node JSON (§4.3) | key lease | agent node registrar (kvstore mode) or apiserver | peers' node manager |
| `cilium/state/identities/v1/id/<decimal id>` | canonical label string (§4.5) | **none** | agent allocator (kvstore mode) or apiserver | peers, local allocator |
| `cilium/state/identities/v1/value/<label string>/<node suffix>` | decimal id | key lease | agent allocator only | local allocator, GC |
| `cilium/state/identities/v1/locks/<label string>/<lease-hex>` | lock marker | lock lease | agent allocator, GC | themselves |
| `cilium/state/ip/v1/default/<ip or ip/len>` | `IPIdentityPair` JSON (§4.4) | key lease | agent (kvstore mode) or apiserver | peers' ipcache |
| `cilium/state/services/v1/<C>/<ns>/<name>` | `ClusterService` JSON (§4.6) | key lease | apiserver / operator | peers' LB |
| `cilium/state/endpointslices/v1/<C>/<ns>/<slice>` | zstd(protobuf) (§4.7) | key lease | apiserver | peers (counted at this tag) |
| `cilium/state/serviceexports/v1/<C>/<ns>/<name>` | `MCSAPIServiceSpec` JSON (§4.8) | key lease | apiserver (deferred) | peers' operator |
| `cilium/cache/nodes/v1/<C>/<node>` | verbatim copy | key lease | kvstoremesh | local agents |
| `cilium/cache/identities/v1/<C>/id/<id>` | verbatim copy | key lease | kvstoremesh | local agents |
| `cilium/cache/ip/v1/<C>/<ip>` | verbatim copy | key lease | kvstoremesh | local agents |
| `cilium/cache/services/v1/<C>/<ns>/<name>` | verbatim copy | key lease | kvstoremesh | local agents |
| `cilium/cache/endpointslices/v1/<C>/<ns>/<slice>` | verbatim copy | key lease | kvstoremesh | local agents |
| `cilium/cache/serviceexports/v1/<C>/<ns>/<name>` | verbatim copy | key lease | kvstoremesh | local operator |

Note the two irregular cache shapes: `identities` gains a `<C>` segment *before*
`id/` (the source has no cluster segment), and `ip` replaces `default` with
`<C>`.

### 4.2 `CiliumClusterConfig`

JSON, every field omitted when empty:

```json
{ "id": 3,
  "capabilities": {
    "syncedCanaries": true,
    "cached": false,
    "maxConnectedClusters": 255,
    "serviceExportsEnabled": false,
    "endpointSlicesExportMode": "services-and-endpointslices" } }
```

`capabilities.flowsdnInstanceUUID` is a flowsdn additive optional string,
required on local writes, governed by §12 decision 9. Old peers may omit it on
read; that does not authorize local ownership adoption.

`id` is `u32`. `serviceExportsEnabled` is **nullable**: absent means the peer
does not know the concept, `false` means it knows it and has it off.
`endpointSlicesExportMode` is one of `""` (services only),
`"services-and-endpointslices"`, `"endpointslices-only"`; any other value
refuses the connection.

### 4.3 Node record

The reference type carries **no JSON tags**, so the Go field names are the wire
names. Preserving them exactly is mandatory.

`Name`, `Cluster`, `IPAddresses` (array of `{Type, IP}` where `Type` ∈
`InternalIP`, `ExternalIP`, `CiliumInternalIP`), `IPv4AllocCIDR`,
`IPv4SecondaryAllocCIDRs`, `IPv6AllocCIDR`, `IPv6SecondaryAllocCIDRs`,
`IPv4HealthIP`, `IPv6HealthIP`, `IPv4IngressIP`, `IPv6IngressIP`, `ClusterID`,
`Source`, `EncryptionKey` (u8 IPsec key index), `Labels`, `Annotations`,
`WireguardPubKey`, `BootID`.

Key name is `<Cluster>/<Name>`. On unmarshal: `Cluster` and `Name` MUST be
non-empty. Readers additionally check the cluster name against the config file
name, the node name against the key, and `ClusterID` against the reserved ID.

**PodCIDR stripping.** In IPAM modes that do not use pod CIDRs (ENI, Azure,
GCP, Alibaba) the alloc-CIDR fields are auto-generated and meaningless to a
peer; a writer MUST clear all four before publishing.

### 4.4 `IPIdentityPair`

Capitalised field names (Go defaults):

```json
{ "IP": "10.0.1.5", "Mask": null, "HostIP": "192.168.1.10", "ID": 65538,
  "Key": 0, "Metadata": "", "K8sNamespace": "ns", "K8sPodName": "pod",
  "K8sServiceAccount": "sa",
  "NamedPorts": [{"Name": "http", "Port": 8080, "Protocol": "TCP"}] }
```

Key name is the IP, or `ip/len` when `Mask` is set. `HostIP` is the node the
endpoint lives on and becomes the ipcache tunnel endpoint. `Key` is the IPsec
key index. `K8sNamespace`, `K8sPodName`, `K8sServiceAccount` and `NamedPorts`
are omitted when empty.

### 4.5 Identity master-key value

The canonical label string of spec `03` §4.1: labels sorted by key, each
rendered `<source>:<key>=<value>;`, concatenated with no separator beyond each
element's trailing `;`. Example:

```
k8s:app=foo;k8s:io.cilium.k8s.policy.cluster=cluster3;k8s:io.kubernetes.pod.namespace=default;
```

The trailing `;` is what makes `value/`-prefix listings unambiguous (§3.6.1).
When the apiserver derives this string from a `CiliumIdentity`, the source of
each label comes from the `security-labels` map key (`source:key`), and an
identity with an empty `security-labels` map is skipped entirely.

### 4.6 `ClusterService`

Lower-camel JSON:

```json
{ "cluster": "c1", "namespace": "ns", "name": "svc",
  "frontends": { "10.96.0.10": { "http": {"Protocol":"TCP","Port":80} } },
  "backends":  { "10.0.1.5":   { "http": {"Protocol":"TCP","Port":8080} } },
  "hostnames": { "10.0.1.5": "pod-1" },
  "zones": { "10.0.1.5": {"zone":"a","forZones":[{"name":"a"}]} },
  "labels": {}, "selector": {},
  "includeExternal": true, "shared": true, "clusterID": 1 }
```

Port maps are keyed by port name; the inner object uses **capitalised**
`Protocol`/`Port` (it is a nested tag-less Go type). `hostnames` and `zones` are
omitted when empty. Key name is `<cluster>/<namespace>/<name>`.

Writer rules: `shared` and `includeExternal` are always `true` on a published
record — an unshared service is *deleted*, not published with `shared: false`.
Headless services publish no frontends. Backends come from EndpointSlices,
skipping addresses that are neither ready nor serving.

Reader validators: cluster name equals the config file name, `<ns>/<name>`
equals the key suffix, `clusterID` equals the reserved ID.

### 4.7 `ClusterEndpointSlice`

Protocol buffers, then **zstd**. Decoder memory capped at 16 MiB. Fields, with
their frozen numbers: `cluster` 1, `clusterID` 2, `namespace` 3, `name` 4,
`labels` 5 (map), `annotations` 6 (map), `addressType` 7, `endpoints` 8
(repeated, the slim `discovery/v1` Endpoint), `ports` 9 (repeated, slim
EndpointPort). Key name `<cluster>/<namespace>/<slice>`. A JSON rendering exists
for debug output only and is not a wire format.

### 4.8 `MCSAPIServiceSpec` (deferred)

Lower-camel: `cluster`, `name`, `namespace`, `annotations`, `labels`,
`exportCreationTimestamp`, `ports`, `type` (`ClusterSetIP` | `Headless`),
`sessionAffinity`, `sessionAffinityConfig`, `ipFamilies`,
`internalTrafficPolicy`, `trafficDistribution`, plus the two **capitalised
duplicates** `Labels` and `Annotations` written for older readers. A flowsdn
writer, when this ships, MUST write both spellings.

### 4.9 Status models

`RemoteCluster`: `name`, `ready`, `connected`, `status`, `config`, `synced`,
`num-nodes`, `num-shared-services`, `num-endpoints`, `num-identities`,
`num-endpoint-slices`, `num-service-exports`, `num-failures`, `last-failure`.
`RemoteClusterSynced`: `nodes`, `services`, `identities`, `endpoints`,
`endpoint-slices` (nullable), `service-exports` (nullable).
`RemoteClusterConfig`: `required`, `retrieved`, `cluster-id`, `kvstoremesh`,
`sync-canaries`, `service-exports-enabled` (nullable),
`endpoint-slices-export-mode`. All fields omitted when empty.

## 5. Algorithms

### 5.1 Key joining

Join elements with `/`; repeatedly replace `//` with `/`; trim trailing `/`.
Empty elements therefore vanish. `.` and `..` have **no** special meaning and
MUST NOT be normalized away — they are legal key bytes.
`state → cache` rewriting replaces only the **first** occurrence of the literal
`cilium/state` at the start of a prefix; a prefix not starting with it is
returned unchanged.

### 5.2 Metric scope derivation

Operation metrics are labelled by a `scope` derived from the key: split on `/`
into at most 5 parts; if there are fewer than 4, use the first 12 bytes of the
key; otherwise use `<part 3>/<part 4>`. So
`cilium/state/identities/v1/id/1` → `identities/v1`. This keeps cardinality
bounded regardless of how many identities or IPs exist, and is the reason the
schema's version segment sits where it does.

### 5.3 Paginated list

```
start := prefix
end   := prefix with its last byte incremented        (prefix range end)
rev   := 0
loop:
  page := range(start, end, limit = etcd.limit, revision = rev)
  if rev == 0 { rev = page.header.revision }          // pin on the FIRST page only
  append page.kvs
  if !page.more || page.kvs is empty { return kvs, rev }
  start = last key of page ++ "\x00"
```

Pinning the revision on the first page is mandatory: without it, later pages
are read at a higher revision and any key modified in between is either seen
twice or missed entirely, and the watch that follows starts from the wrong
place. The returned revision is what the watch resumes from.

### 5.4 Watch, relist and compaction

#### 5.4.1 The loop

```
relist:
  kvs, rev := paginated_list(prefix)          // on error: exponential backoff
                                              // 50 ms → 1 m, retry
  for each kv:
      emit Create if not in local cache else Modify;  mark in-use
  emit synthetic Delete for every cache entry still marked for deletion
  emit ListDone (once per watcher lifetime, never on a relist)
recreate:
  w := watch(prefix, from = rev + 1, require_leader)
  for each batch in w:
      if batch.error:
          mark ALL cache entries for deletion
          goto relist
      for each event: emit Create / Modify / Delete; update the cache
      rev = batch.header.revision
  // channel closed without an error
  sleep 50 ms; goto recreate
```

#### 5.4.2 Why the local cache exists

The watcher keeps a set of keys it has told its consumer about. On a relist it
marks them all, clears the mark for every key the list returned, and then emits
a delete for the remainder. This is the **only** mechanism that tells a consumer
about keys deleted while the watch was broken. Without it, a compaction or a
network partition leaves permanently stale remote state.

#### 5.4.3 Compaction

A watch cancelled because its start revision was compacted is not a special
case: it takes the same path as any watch error — mark all, relist. flowsdn
MUST NOT attempt to be clever here (e.g. resuming from the compaction
revision); the relist is correct and the cost is bounded by the prefix size.

#### 5.4.4 Periodic resync (**DEVIATION**, fastetcd F10)

Because fastetcd can currently drop watch events silently under load without
cancelling the watch (§2.7 F10), flowsdn adds a periodic relist every
`kvstore-resync-interval` (default 5 m, `0` disables). It runs the same relist
path, so it converges the same way, and its cost is one paginated list per
prefix per interval. A future change to `0` requires the explicit evidence gate in §12 decision 2;
it is never selected automatically. The reference has no equivalent.

### 5.5 Lease bookkeeping

```
get_lease(key):
  if key already bound      -> return its lease
  if current lease has < 1000 keys -> bind, count++, return
  scan other leases for one with < 1000 keys -> make current, bind, return
  otherwise: grant a new lease (single-flight: concurrent callers wait on the
             in-progress grant and then re-enter), make it current, start its
             keepalive, then re-enter to bind the key
```

Never validate a lease client-side before returning it: a stale lease produces
a server error the caller retries, which is simpler and race-free. On a
`lease not found` error, orphan the session so the loss path (§3.3.1) runs.

### 5.6 Identity GC (kvstore mode)

Runs in the operator, on the operator's identity-GC schedule (spec `12`), with
a rate limiter shared with CRD-mode GC. It is a **two-round** algorithm keyed on
each master key's modification revision.

```
for each master key `id/<n>` in the local cluster's range:
    if <n> outside [min(local cluster), max(local cluster)]: skip
    take the lock on locks/<the key's label string>
    users := list_prefix("value/<label string>/") under the lock
    in_use := any user whose key matches the prefix exactly at its last '/'
              AND whose value equals <n>
    if in_use:                 forget the key
    else if key in previous round's stale set:
        if its mod_revision is UNCHANGED since that round:
            delete the master key under the lock          -> counted deleted
        else:
            the identity was reused between rounds: drop it from the stale set
            entirely (it will be re-evaluated from scratch next round)
    else:
        record (key -> mod_revision) in this round's stale set
    release the lock
    if anything was deleted this iteration, wait for a rate-limiter token
```

Two properties matter and MUST be preserved: (a) an identity is only deleted if
it had **no users in two consecutive rounds and was not modified in between**,
which is what makes the unleased master key safe; (b) the rate-limiter wait
happens **after** releasing the lock, so a slow GC never blocks allocation.
Keys outside the local cluster's range are skipped, so GC never touches another
cluster's identities even if they are visible.

**Lock GC** is the same shape over `locks/`: a lock key is force-deleted only
when both its modification revision **and** its lease id are unchanged since the
previous round, proving the same client still holds it and has been stuck.
Deleting a live lock would corrupt allocation, so the double check is required.

### 5.7 Reconnection and drain matrix

| Trigger | Nodes | Services | ipcache | Identities | Observers | Cluster ID |
|---|---|---|---|---|---|---|
| watch error / status error | relist (§5.4) | relist | relist | relist | relist | kept |
| peer cluster ID changed | drain | drain | drain | drain | drain | released, then re-reserved |
| cache TTL expired | keep | **drain** | keep | keep | revoke | kept |
| config file removed | drain | drain | drain | drain | drain | released |
| agent shutting down | **keep** | keep | keep | keep | keep | kept |

The last row is the important one: on shutdown nothing is drained, because a
drain would delete every remote endpoint from the datapath and break every
established cross-cluster connection for the duration of the restart.

## 6. Configuration

### 6.1 kvstore

| Key | Type | Default | Effect |
|---|---|---|---|
| `kvstore` | string | `""` | `""` disables the layer; `etcd` enables it. Any other value is fatal |
| `kvstore-opt` | map | `{}` | backend options below; an unknown key is fatal and logs the supported set |
| `kvstore-lease-ttl` | duration | `15m` | key-lease TTL; MUST be within `[25s, 24h]`, else fatal |
| `kvstore-max-consecutive-quorum-errors` | uint | `2` | consecutive quorum errors tolerated before the status turns `Failure` |
| `kvstore-resync-interval` | duration | `5m` | **DEVIATION** (§5.4.4): periodic relist; `0` disables |

`kvstore-opt` keys:

| Key | Default | Effect |
|---|---|---|
| `etcd.address` | `""` | single endpoint; mutually exclusive with `etcd.config`, one is required |
| `etcd.config` | `""` | path to the client YAML (§2.3); retried every 5 s if missing |
| `etcd.qps` | `20` | steady-state rate and burst |
| `etcd.bootstrapQps` | `0` | rate until the bootstrap signal; `0` disables |
| `etcd.maxInflight` | `= etcd.qps` | concurrent in-flight operation cap |
| `etcd.limit` | `256` | list page size; `0` = unlimited |
| `etcd.keepaliveHeartbeat` | `15s` | gRPC keepalive time |
| `etcd.keepaliveTimeout` | `25s` | gRPC keepalive timeout |

Fixed, not configurable: 1000 keys per lease, 25 s lock lease, 30 s stale local
lock timeout, 1 minute lock acquisition, 15 minute initial connection, 10 s
status probe, 60 s heartbeat write, 3 minute shared-store initial list.

### 6.2 Cluster identity

| Key | Type | Default | Effect |
|---|---|---|---|
| `cluster-name` | string | `default` | §2.2; MUST NOT be `default` when `cluster-id != 0` |
| `cluster-id` | u32 | `0` | `0` = no mesh; `1..max` otherwise |
| `max-connected-clusters` | u32 | `255` | `255` or `511` only; identical across the mesh |
| `allow-unsafe-policy-skb-usage` | bool (hidden) | `false` | downgrade the buggy-ID guard from fatal to an error log |

### 6.3 Agent ClusterMesh

| Key | Type | Default | Effect |
|---|---|---|---|
| `clustermesh-config` | string | `""` | config directory; empty disables ClusterMesh |
| `clustermesh-cache-ttl` | duration | `0s` | revoke a disconnected peer's cached services after this; `0` never |
| `clustermesh-sync-timeout` | duration | `1m` | circuit breaker on every remote sync waiter |
| `clustermesh-default-global-namespace` | bool | `true` | namespaces are global unless annotated otherwise |
| `policy-default-local-cluster` | bool | `true` | policy rules default to the local cluster when no cluster is selected |
| `clustermesh-service-v2` | string (hidden) | `prefer-legacy` | **DEVIATION** (§3.7.9): only `prefer-legacy` is accepted; the other two are fatal |
| `identity-allocation-mode` | string | `crd` | `crd` or `kvstore`; `kvstore` requires `kvstore` to be set; the double-write modes are fatal |

### 6.4 clustermesh-apiserver

| Key | Type | Default | Effect |
|---|---|---|---|
| `cluster-name`, `cluster-id`, `max-connected-clusters` | — | — | as §6.2; forced non-zero |
| `health-port` | int | `9880` | `/readyz` listener (kvstoremesh: `9881`) |
| `prometheus-serve-addr` | string | `""` | `/metrics`; empty disables |
| `enable-cilium-endpoint-slice` | bool | `false` | source ipcache entries from `CiliumEndpointSlice` instead of `CiliumEndpoint` |
| `clustermesh-enable-mcs-api`, `clustermesh-mcs-api-install-crds` | bool | `false`, `true` | deferred; accepted and ignored with a warning |
| `cluster-users-enabled`, `cluster-users-config-path` | bool, string | `false`, `/var/lib/cilium/etcd-config/users.yaml` | **accepted and ignored** (§3.8.5) |

### 6.5 kvstoremesh

| Key | Type | Default | Effect |
|---|---|---|---|
| `per-cluster-ready-timeout` | duration | `15s` | a peer not connected within this is dropped from readiness |
| `global-ready-timeout` | duration | `10m` | declare ready regardless after this |
| `enable-heartbeat` | bool | `false` | write `cilium/.heartbeat` in the local store |
| `disable-drain-on-disconnection` | bool (hidden) | `false` | skip §3.9.3 |
| `api-serve-addr` | string | `localhost:9889` | `GET /v1/cluster` |

### 6.6 fastetcd as the shipped backend

**DEVIATION (ADR-0001, ADR-0002).** The reference deploys a Go etcd binary as a
sidecar, bootstrapped by an init container that wipes a data directory, runs a
throwaway localhost etcd, creates users and roles, and enables auth. flowsdn
deploys **fastetcd** and drops the init container entirely.

What changes operationally:

| Aspect | Reference | flowsdn |
|---|---|---|
| Containers in the pod | 4 (`etcd-init`, `etcd`, `apiserver`, `kvstoremesh`) | 2 (`fastetcd`, `flowsdn-clustermesh-apiserver`) |
| Base image | distro-based etcd | `scratch`, static musl binaries |
| Auth bootstrap | init container + `AuthEnable` | none; mTLS + apiserver-side prefix scoping (§3.8.5) |
| `users.yaml` / `clustermesh-remote-users` | reconciled into etcd users | accepted and ignored |
| Data directory | `emptyDir`, optionally `Memory` | unchanged; still ephemeral by design |
| Compaction | `--auto-compaction-retention=1` (one **hour**) | `--auto-compaction-retention=<revisions>`; fastetcd supports revision mode only (§2.7 F18). Set it to `max(100 × expected agent count, 10000)` |
| Store cluster id | derived by etcd | **MUST** be set explicitly: `--cluster-id=<FNV-1a-64(cluster-name) masked to 63 bits, never 0>` (§2.7 F17) |
| Backup | `etcdctl snapshot` | `fastetcd backup` / `restore`; the gRPC `Snapshot` RPC is never used |
| Metrics | etcd's `/metrics` on 9963 | fastetcd's `--listen-metrics-url`, same port |
| Peer TLS | separate peer identity | shared identity (§2.7 F21); TCP 2380 restricted to same-namespace store members by shipped NetworkPolicy |

Required fastetcd flags in the manifest: `--cert-file`, `--key-file`,
`--trusted-ca-file`, `--client-cert-auth`, `--listen-client-urls`,
`--cluster-id`, `--auto-compaction-retention`, `--data-dir`.

The store remains a **cache, not a database**: everything in it is derived from
Kubernetes and is rewritten on restart. Losing it costs a resync, not data.
That is why an ephemeral data directory is correct and why no backup is
required for correctness.

## 7. Failure modes

| Failure | Detection | Behavior |
|---|---|---|
| Remote cluster unreachable (network, DNS, TLS) | initial connection times out (15 m) or the dial fails | connection controller retries with linear backoff forever; status `not-ready`, `connected=false`; failure counter and last-failure timestamp advance; already-imported state is retained until the cache TTL (if any) |
| Remote control plane dead but store reachable | no heartbeat event for 2 minutes | after `kvstore-max-consecutive-quorum-errors` consecutive checks the status turns `Failure`, the watchdog reconnects; the cycle repeats until the peer recovers |
| Peer's cluster config missing | 3-minute retrieval timeout per attempt | reconnect and retry forever; status shows `expected=true, retrieved=false` with the kvstoremesh/cluster-name hint |
| Peer advertises an unknown `endpointSlicesExportMode` | config validation | connection refused with a named error; retried on every reconnect, so a peer downgrade recovers automatically |
| **Identity range collision** — two peers advertise the same cluster ID | ID reservation | the second connection is refused (`clusterID <n> is already used`) and stays not-ready; the first keeps working. No merging, ever |
| Peer changes its cluster ID | config differs from the reserved ID | drain nodes → services → ipcache → identities → observers, release the old ID, reserve the new, then re-import. Logged as an expected connectivity disruption |
| Identity observed outside the peer's range, or missing the cluster-name label | per-event validator | the event is skipped with a warning; delete events skip the label check so stale identities are always removable |
| **Compaction during a watch** | watch cancelled with a compaction revision, or any watch error | mark the whole local cache, relist, emit synthetic deletes for what vanished (§5.4) |
| Watch drops events without an error (fastetcd F10) | not detectable | the periodic relist of §5.4.4 converges within `kvstore-resync-interval` |
| **Key lease expiry** | the keepalive stream ends | every key bound to the lease is reported to its observer; a `SyncStore` re-enqueues them, including its synced canary (without re-running readiness callbacks); a `SharedStore` re-creates its owned keys. Peers see deletes followed by re-creates |
| **Lock lease expiry** while a lock is held | the guard's compare fails | the guarded operation fails with `LockLeaseExpired` and is retried from the top, re-acquiring the lock. GC's lock is 25 s, so a crashed holder blocks nothing longer than that |
| Local lock leaked in-process | held > 30 s | force-released by the local GC timer with an error log naming the path |
| Store loses quorum | quorum probe fails, or endpoint status fails | status `Failure`; the agent's `/healthz` returns 500 when a kvstore is configured; writers retry, readers keep serving their last known state |
| **Split brain** — an endpoint starts pointing at a different store | the cluster-ID pin (§3.7.4) | the connection is torn down and rebuilt against whatever is now there; state from the old store is drained only if the peer's cluster ID also changed. Requires distinct store cluster ids (§6.6) |
| Two clusters accidentally share a cluster **name** | not detectable by protocol | each overwrites the other's `<name>`-scoped keys. Documented as a hard operator requirement; the local cluster refuses a config file named after itself, which catches the common self-mesh case |
| kvstoremesh loses leadership | lock lease expiry observer | the process exits; the replacement acquires the lock and re-mirrors. Cached data survives the gap |
| kvstoremesh drain fails | 6 attempts exhausted | logged as an error; stale `cilium/cache/<peer>/` remains and agents keep serving it. Restarting kvstoremesh after re-adding the peer is the documented recovery |
| Apiserver cannot publish its cluster config | initial write fails 3× | the process exits: an unpublished config makes the cluster invisible, and failing loudly beats a silently unmeshed cluster |
| Value exceeds 4 MiB | write-side check | rejected with a named error rather than being sent (§2.7 F24) |
| Agent restart | — | nothing is drained (§5.7); imports re-list and converge |

## 8. Observability

### 8.1 Metrics

Namespace is `cilium` in the agent, `cilium_operator`,
`cilium_clustermesh_apiserver` and `cilium_kvstoremesh` in the other
components. Names and labels are reference-compatible.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `<ns>_kvstore_operations_duration_seconds` | histogram | `scope`, `kind` (`read`/`set`/`delete`), `action`, `outcome` | per-operation latency; `action` ∈ `Get`, `GetLocked`, `Update`, `UpdateIfLocked`, `CreateOnly`, `CreateOnlyLocked`, `Delete`, `DeleteLocked`, `DeletePrefix`, `ListPrefix`, `ListPrefixLocked`, `Lock`, `Unlock`, `AcquireLease` |
| `<ns>_kvstore_events_queue_seconds` | histogram | `scope`, `action` (`create`/`modify`/`delete`/`listDone`) | time an event waited before the consumer took it |
| `<ns>_kvstore_quorum_errors_total` | counter | `error` ∈ `lock timeout`, `no event received` | quorum probe failures |
| `<ns>_kvstore_sync_queue_size` | gauge | `scope`, `source_cluster` | pending export writes |
| `<ns>_kvstore_sync_errors_total` | counter | `scope`, `source_cluster` | failed export writes |
| `<ns>_kvstore_initial_sync_completed` | gauge | `scope`, `source_cluster`, `action` (`read`/`write`) | canary published, or initial list consumed |
| `<ns>_clustermesh_remote_clusters` | gauge | — | configured remote clusters |
| `<ns>_clustermesh_remote_cluster_failures` | gauge | `target_cluster` | cumulative reconnections |
| `<ns>_clustermesh_remote_cluster_last_failure_ts` | gauge | `target_cluster` | last failure timestamp |
| `<ns>_clustermesh_remote_cluster_readiness_status` | gauge | `target_cluster` | 1 = ready |
| `<ns>_clustermesh_remote_cluster_cache_revocations` | gauge | `target_cluster` | cache TTL expiries |
| `<ns>_clustermesh_remote_cluster_nodes\|services\|endpoints\|endpoint_slices` | gauge | `target_cluster` | imported entry counts |
| `<ns>_bootstrap_seconds` | gauge | — | apiserver time to full initial sync |
| `cilium_kvstoremesh_leader_election_master_status` | gauge | `name="kvstoremesh"` | 1 = this instance holds the lock |

`scope` is derived by §5.2 and MUST NOT be the raw key: identity and IP keys
would otherwise produce unbounded cardinality.

### 8.2 Logging

Subsystems `kvstore`, `kvstore-store`, `clustermesh`, `clustermesh-apiserver`,
`kvstoremesh`. Structured fields: `clusterName`, `clusterID`, `etcdClusterID`,
`config`, `configDir`, `key`, `prefix`, `rev`, `leaseID`, `ttl`, `hint`.

Events that MUST be logged at info or above because they are the ones people
look for during an incident: connection established / lost per peer with the
store id; cluster config found / missing with the hint; cluster ID changed and
draining; lease expired; forcefully removed a stale lock; cache TTL expired and
revoking; kvstoremesh drain start/finish per peer; sync timeout circuit breaker
(once per process).

### 8.3 Status surfaces

Agent `GET /healthz` → `cluster-mesh` (§2.4); operator `GET /v1/cluster`;
kvstoremesh `GET /v1/cluster`; apiserver and kvstoremesh `GET /readyz`.
`flowsdn-dbg status [--all-clusters]` renders §3.7.10.
`flowsdn-dbg troubleshoot clustermesh [--clustermesh-config DIR] [--timeout 5s]
[--without-service-resolution]` MUST, per config file: resolve the endpoint
host, TCP-connect, complete the TLS handshake, print the presented certificate
chain and the client certificate's CN, `get cilium/.heartbeat`, and print the
store's cluster id. `flowsdn-dbg troubleshoot kvstore` does the same for the
local store. These are the first commands run when a mesh does not come up and
they MUST work without the agent being healthy.

## 9. Test plan

Unless marked otherwise, tests are **unit** tests with an in-process backend.
"integration" means against a live fastetcd.

### 9.1 kvstore client

- [ ] get / put / delete / delete-prefix round trip; missing key returns none
- [ ] `put_if_absent` returns false on an existing key and does not overwrite
- [ ] `put_if_different` skips an identical value; rewrites when the stored lease differs
- [ ] every guarded variant fails with `LockLeaseExpired` when the lock was lost (integration)
- [ ] paginated list across ≥ 3 pages with `etcd.limit = 2`; revision pinned on page 1; a key inserted mid-list is not observed (integration)
- [ ] list of a prefix that is a string prefix of another does not leak siblings (trailing `/`)
- [ ] rate limiter: N concurrent operations respect qps and the inflight cap; bootstrap rate is raised exactly once
- [ ] status message format matches §3.2.5 verbatim for ok, quorum-failure and no-endpoints
- [ ] quorum failure after exactly `max-consecutive-quorum-errors + 1` checks
- [ ] remote-client mode: no heartbeat for > 2 minutes produces the `no event received` quorum error
- [ ] certificate resolver re-reads the files on each handshake (rotate the file mid-test) (integration)

### 9.2 Watch, lease, lock

- [ ] list→watch handoff sees no gap and no duplicate for a key written between the two
- [ ] watch error → mark-all → relist → synthetic deletes for keys removed while disconnected
- [ ] compaction cancels the watch and the relist recovers (integration; compact under the watch)
- [ ] `ListDone` is emitted exactly once per watcher lifetime, not on relists
- [ ] lease manager: 1001 keys occupy two leases; release decrements; single-flight grant under concurrency
- [ ] lease loss fires observers for every bound key, prefix-matched
- [ ] lock: two clients contend, the second acquires after the first releases; a lock key is `<path>/<lease hex>` (integration)
- [ ] stale local lock is force-released after 30 s

### 9.3 Stores and identity

- [ ] `SyncStore` publishes the canary only after the pending set drains; canary value parses as RFC3339
- [ ] canary lease expiry re-enqueues the canary without re-running readiness callbacks
- [ ] `WatchStore` restart marks stale, then deletes what did not reappear; `drain()` deletes everything
- [ ] `WatchStoreManager` canary gating starts each prefix exactly once, on its own canary
- [ ] `SharedStore` re-creates an owned key deleted by a third party; suppresses a foreign delete that reappears within the delay
- [ ] identity allocation: master + slave + lock keys have the exact paths of §3.6.1
- [ ] `value/` prefix listing does not match a longer label string (trailing `;` and last-`/` rule)
- [ ] per-cluster range: cluster 3 with max 255 allocates only `[196608, 262143]`; with max 511, `[98304, 131071]`
- [ ] GC deletes only after two rounds with an unchanged mod revision; a reuse between rounds spares the key
- [ ] GC skips ids outside the local cluster's range
- [ ] lock GC deletes only when mod revision **and** lease id are unchanged

### 9.4 ClusterMesh

- [ ] config directory: a file containing `endpoints:` is a cluster; a directory and a non-matching file are not; an unchanged hash is ignored; a symlink swap is observed
- [ ] `cilium-host-aliases` parse errors (empty hostname, no IPs, duplicate) fail the connection
- [ ] only the five allow-listed `kvstore-opt` keys reach a remote client
- [ ] cluster-ID pin: a changed store id aborts the operation and triggers a reconnect; a fresh pin latches after
- [ ] ID reservation refuses 0, the local ID, and a duplicate
- [ ] a peer changing its ID drains in the order of §5.7 and re-reserves
- [ ] validators reject a node whose cluster/name/ID disagrees, an identity outside the range, an identity missing the cluster label on **upsert** but not on **delete**
- [ ] `cached` capability rewrites every prefix, including the irregular identity and ip shapes
- [ ] sync waiters: ip-identities waits for nodes too; the 1-minute circuit breaker releases with one warning; a disconnect releases immediately
- [ ] cache TTL revokes services only, leaving nodes/ipcache/identities
- [ ] affinity matrix: all five rows of §3.7.9, plus an unparseable value behaving as `none`
- [ ] port de-duplication: three names on one `(TCP, 80)` collapse to one backend with three sorted names
- [ ] status rendering matches §3.7.10 byte for byte for ready and not-ready clusters
- [ ] `prefer-endpointslice` and `only-endpointslice` are rejected at startup

### 9.5 apiserver and kvstoremesh

- [ ] each synchronizer writes the exact key and value of §3.8.2 and its canary, including the two canary overrides
- [ ] an identity with no security labels is neither written nor deleted
- [ ] IP ownership arbitration: two objects claiming one IP; the key survives until the last releases
- [ ] a namespace flipped to non-global converts every affected object to a delete; a delete is never suppressed by the namespace check
- [ ] cluster config is rewritten after an external modification and after a deletion
- [ ] a service losing `shared` is deleted from the store, not written with `shared: false`
- [ ] kvstoremesh mirrors verbatim, sets exactly `cached` and `syncedCanaries`, and publishes the config before registering reflectors
- [ ] drain order: config key, 3-minute grace, `synced/` prefix, then each cache prefix in name order; retries 2/4/8/16/32 s; grace skipped on retries
- [ ] `disable-drain-on-disconnection` skips the drain and warns
- [ ] leadership loss terminates the process

### 9.6 Harvested scenarios (ADR-0005)

The reference ships **nine** clustermesh `.txtar` scenarios, harvested verbatim
at `tests/scripttest/corpus/clustermesh/` (from
`clustermesh-apiserver/clustermesh/testdata`), plus four agent-side scenarios at
`tests/scripttest/corpus/clustermesh-agent/` (from `pkg/clustermesh/testdata`)
and one at `tests/scripttest/corpus/kvstore/`. They run unmodified under
`flowsdn-scripttest` (spec `17`) and are the acceptance gate for this spec.

| Scenario | Pins |
|---|---|
| `ciliumnodes` | node key path, value, update and delete; the nodes canary |
| `ciliumidentitites` (upstream spelling) | identity key path, the label-string value, the `/id`-dropping canary |
| `ciliumendpoints` | ipcache keys from `CiliumEndpoint`, IPv4/IPv6 add-change-remove, the `/default`-dropping canary |
| `ciliumendpointslices` | the same from `CiliumEndpointSlice` |
| `clusterconfig` | the exact config JSON; reconciliation after external modification and after deletion |
| `clusterconfig-serviceexport` | `serviceExportsEnabled: true` |
| `clusterconfig-endpointslices-only` | `endpointSlicesExportMode: endpointslices-only` |
| `globalnamespace` | non-global namespaces are not exported; annotating adds, un-annotating removes |
| `serviceexports-crd-upgrade` | degraded-then-recovering export job without a restart (deferred with MCS-API; kept as an expected-divergence marker) |
| `clusterservice`, `clusterservice-multiport`, `clusterservice-without-local-eps`, `service-affinity` | the LB merge, port de-duplication, selector-less services, and the full affinity matrix |
| `endpointslice-transcode` | value transcoding for `-o json` listings |

### 9.7 `flowsdn-kvstore-conformance` (integration)

One row per §2.7 requirement, run against a live store, printing pass/fail.
It is the acceptance gate for a fastetcd release and for any alternative
backend. It MUST additionally assert: ascending range order (F3), the
compaction cancel carries a compaction revision (F9), a watch never skips a
revision under a 10 000-write burst (F10), and that two stores deployed with
different `--cluster-id` values report different header cluster ids (F17).

### 9.8 End-to-end (privileged, multi-cluster)

Two clusters, then three. Matrix: tunnel off / VXLAN / Geneve × encryption none
/ WireGuard / IPsec × mode `clustermesh` / `kvstoremesh` × `max-connected-clusters`
255 / 511, plus one IPv6-only run. Assertions: pod-to-pod across clusters,
global service load balancing, affinity `local` and `remote` with failover,
cross-cluster policy by identity label, and convergence after killing the peer's
apiserver, after a network partition longer than the cache TTL, and after a peer
cluster-ID change.

## 10. Kernel and platform requirements

Control plane only; no BPF helpers, no netlink, no kernel version floor beyond
the agent's own. The two datapath touch points are owned elsewhere: the
`cluster_id` field in the `cilium_ipcache_v2` key (spec `01` §2.2, spec `03`
§4.8) and the identity bit split (spec `03` §4.5). The per-cluster
conntrack/NAT array-of-maps that the reference carries behind
`ENABLE_CLUSTER_AWARE_ADDRESSING` have no user-facing switch at the reference
tag and are **not implemented** (§12 decision 7); flowsdn keeps the reference's
documented requirement that PodCIDRs be unique across the mesh.

Both x86-64 and arm64 are first class. fastetcd builds static musl binaries for
both; the apiserver image is `scratch`.

## 11. Rust design notes

### 11.1 Crates

- **`flowsdn-kvstore`** — the trait of §3.1 as
  `#[async_trait] pub trait Kvstore`, plus `Value { data: Bytes, mod_revision: u64, lease_id: i64 }`,
  `Event`, `Lease`, `Guard`. Two implementations: `EtcdBackend` over the
  **`etcd-client`** crate (tonic/prost), and `MemoryBackend`, an in-process
  store with revisions and watch channels used by every unit test and by the
  scripttest harness. Contains the lease manager, the client-side mutex, the
  paginated list, the watch/relist state machine with its key cache, the rate
  limiter (`governor` token bucket plus a `tokio::sync::Semaphore` for the
  inflight cap), and the status checker.
  - TLS: `tonic` + `rustls`. The per-handshake certificate reload is a
    `rustls::client::ResolvesClientCert` implementation that re-reads and
    re-parses both files on each call — this must be written; no crate provides
    it.
  - The cluster-ID pin is a `tower` layer wrapping the channel, inspecting
    `ResponseHeader.cluster_id` on unary responses and on every watch message.
  - The dialer is `connect_with_connector` over a custom `tower::Service` that
    consults the host-alias map, then the Service resolver, then DNS.
- **`flowsdn-kvstore-store`** — `SyncStore`, `WatchStore`, `SharedStore`,
  `WatchStoreManager`. The work queue is a `tokio` task with a
  `DelayQueue`-backed per-item exponential retry plus a shared `governor`
  bucket; `Key`/`NamedKey` are traits with `key_name()` and
  `marshal()`/`unmarshal(key, bytes)` so validators compose as closures.
- **`flowsdn-clustermesh`** — the config-directory watcher (`notify`, two
  watchers, SHA-256 via `sha2`), the per-remote connection task, the cluster-ID
  pin plumbing, `ClusterIdRegistry`, the import registrations, the global
  service cache, the service merger and `select_backends`. Depends on
  `flowsdn-lb` (spec `05`) only through a `BackendWriter` trait, so the LB crate
  does not depend back.
- **`flowsdn-clustermesh-apiserver`** — the synchronizers over `kube-rs`
  reflectors (spec `13`), the converters, the namespace manager, the ownership
  arbiter, the readiness aggregator, the prefix-scoping front of §3.8.5, and
  kvstoremesh as a subcommand with its reflectors, drain and leader election.
- **`flowsdn-identity`** (spec `03`) gains `KvstoreBackend` implementing the
  existing `IdentityBackend` trait; the allocation protocol above the trait is
  untouched.

**DEVIATION (ADR-0004).** No hive cells, no statedb. Each component is built
explicitly in `main`; ordering is `flowsdn-fence` waiters
(`kvstore-connected`, `clustermesh-nodes`, `clustermesh-ip-identities`,
`clustermesh-services`); per-module health is reported into the registry the
status endpoint reads. Remote-cluster state lives in a `flowsdn-table` table
keyed by cluster name so the status endpoint and the metrics exporter read a
consistent snapshot without locking the connection tasks.

### 11.2 Types worth naming

```
ClusterName(String)            // validated at construction
ClusterId(u32)                 // 1..=max, with the layout from spec 03
KvKey(String)                  // built only through join(); never concatenated
CanonicalLabels(String)        // the identity label string, trailing ';' enforced
Prefix { state: &'static str, cached: Option<ClusterName> }   // renders both shapes
```

`Prefix` is the answer to the `cached` capability: one type that knows how to
render `cilium/state/ip/v1/default` and `cilium/cache/ip/v1/<cluster>` from the
same declaration, so no call site does string surgery.

### 11.3 Serde shapes

Three different naming conventions coexist on the wire and MUST be expressed
per type, never globally: **capitalised, tag-less** for the node record and
`IPIdentityPair` (`#[serde(rename_all = "PascalCase")]` plus explicit renames
for `IP`, `ID`, `K8sNamespace`, `NamedPorts`); **lower-camel** for
`CiliumClusterConfig`, `ClusterService` and `MCSAPIServiceSpec`; and
**capitalised nested** for `L4Addr` inside `ClusterService`'s port maps. A
round-trip test per type against a fixture captured from the reference is the
only way to keep this honest, and §9.6's harvested scenarios supply the
fixtures.

`ClusterEndpointSlice` uses `prost` with the field numbers of §4.7 and `zstd`
with a 16 MiB decode cap.

### 11.4 Effort

kvstore client + store layer ≈ 5k lines; identity kvstore backend + remote
caches ≈ 2k; agent ClusterMesh ≈ 4k; apiserver synchronizers + kvstoremesh ≈ 3k;
the prefix-scoping front ≈ 0.5k. MCS-API and the EndpointSlice v2 consumer add
≈ 4k if taken.

## 12. Open decisions

1. **Resolved #20: CRD allocation is the default.** Use `crd` with the
   apiserver mirroring identities into kvstore for remote readers. Explicit
   `kvstore` remains a required supported backend, selected only with
   `kvstore=etcd`; it is not delivered by the configuration planner. Agent vs
   operator identity management is independent (spec 12). Both allocators and
   their GC/concurrency acceptance remain required before runtime claims.
2. **Resolved #273: keep the five-minute resync default.** Keep `5m` until
   pinned-server tests prove watch lag always cancels rather than silently
   dropping events, with compaction/relist recovery tests. Do not automatically
   switch to zero based on a version string or a reported upstream fix. A later
   explicit default change needs those tests and list-cost evidence. Explicit
   `0` remains available with a warning that periodic convergence is disabled;
   it cannot make an F10-failing server production conformant. No adaptive
   resync is selected; scheduling/watch integration remains to implement.
3. **Resolved #274: reject double-write modes.** Both double-write values
   remain fatal. Offline migration requires draining affected workloads,
   stopping old allocators/writers, switching the configured backend, allocating
   identities afresh, reconciling maps/policy, and validating connectivity before
   uncordon. Do not promise stable numeric IDs or a live transition. Revisit
   live migration only with a concrete deployment and an acceptance suite proving
   ownership, GC and rollback across both backends. Ordinary kvstore support is
   still required, not removed by this migration restriction.
4. **Resolved #27: preserve legacy imports and dual exports.** Only
   `prefer-legacy` is accepted. The required producer publishes both
   `services/v1` and `endpointslices/v1`, while backend selection consumes the
   legacy service store. Non-legacy selection remains fatal until an actual
   EndpointSlice consumer and mixed-peer migration tests exist. A peer exporting
   only slices cannot supply usable remote service backends to this importer;
   detect/reject that unsupported peer mode instead of claiming interoperability.
   The library supplies the plan, not producers or consumers.
5. **Resolved #26: mTLS plus an in-process prefix front.** Use the explicit
   verified-CN binding and complete-range authorization contract in §3.8.5.
   Reject every mutation, including apparently read-only Txn, on the public
   frontend. No etcd Auth bootstrap is required. Store-side CN/RBAC hardening
   remains a fastetcd roadmap item, not an implementation dependency or a filed
   upstream issue claim. The binding/range primitives have local tests; TLS,
   protocol enforcement and isolation remain release requirements.
6. **Resolved #29: offline peer-bundle CLI first.** `flowsdn-cli clustermesh
   connect --bundle FILE --config-dir DIRECTORY [--replace] [--dry-run]`
   installs an explicitly provisioned peer's endpoints and credentials. This
   is an offline exchange interface, not the upstream Kubernetes-context UX:
   operators provision/export client credentials through their existing CA
   workflow, transfer bundles securely, and invoke the command at each receiving
   cluster. Each direction requires its own authorized client bundle. No
   Kubernetes credentials, Secret writes, certificate issuance or connectivity
   handshake are implied. A peer CRD/controller remains a later interface.

   The JSON bundle contains exactly `cluster`, `endpoints` (nonempty unique HTTPS
   authorities with explicit nonzero ports), `ca_pem`, `cert_pem`, and `key_pem`.
   Cluster names are validated DNS labels. The bundle must be an owner-only
   regular file of at most 4 MiB. PEM envelope/base64 character checks are
   structural only: transport must still verify trust chain, validity, client
   purpose, server identity and key correspondence. Never print credential data
   or parser excerpts. Input/output path symlinks and parent traversal reject.

   The preexisting config directory must not be group/other writable. CLI
   writers serialize using an exclusive owner-only lock file. The tool prepares
   immutable credentials under `.flowsdn-peer-material/<generation>/` (0700),
   using `<cluster>.etcd-client-ca.crt`, `.crt`, `.key` basenames (0400). It fsyncs
   these files and directories before publishing the `<cluster>` YAML config by
   one atomic rename. This nested staging prevents the directory watcher from
   seeing a partial peer config. Existing regular configs require `--replace`;
   symlink targets are never followed. Failed preparation retains the old config;
   after successful rename, even a durability error must retain new credentials.
   Old credential generations remain for readers holding old configs; operators
   may prune them only after proving no active config/reader uses them. A stale
   lock requires explicit verification/removal, never automatic stealing.

   `--dry-run` validates without writes. Bundle/config directories are trusted
   against same-user adversarial mutation; the tool does not claim a sandbox
   against a hostile process with the same filesystem authority. Paths encoded
   in YAML must be visible unchanged to the receiving agent. CLI integration
   tests cover real writes, permissions, replacement, retained generations,
   malformed inputs, locks, symlinks and secret-free output. Live mesh importers
   and TLS/provider interoperability retain their own acceptance gates.
7. **Resolved #28: require non-overlapping PodCIDRs between clusters.**
   Validate every known local and remote allocation prefix before accepting a
   topology replacement. CIDR containment in either direction is overlap;
   IPv4 and IPv6 remain distinct. A failed update must preserve the prior
   accepted topology and report both cluster names. Nested prefixes within the
   same cluster are permitted. Missing allocation information is not proof of
   non-overlap: cloud modes still require an operator-verified disjoint address
   plan. Live watcher/IPAM admission integration remains required. Cluster-aware
   overlapping addressing needs a separate concrete deployment requirement and
   tests for per-cluster CT/NAT and inter-cluster SNAT before support is claimed.
8. **Resolved #275 — peer restriction shipped; TLS hardening tracked.**
   `deploy/clustermesh/network-policy.yaml` restricts TCP 2380 ingress to store
   member pods selected by name+instance labels in the policy namespace.
   TCP 2379 client ingress is a separate rule with a client authorization label.
   Workload labels, policy namespace and effective additive policy set MUST be
   verified by the deployment adapter; ports must never be combined into a
   broad client allow rule. The README records direct-pod/service and
   same/cross-namespace positive/negative probes; enforcement is not yet tested.
   fastetcd `cf53856` still discards peer certificate flags and clones client
   TLS into the Raft listener. The existing
   [fastetcd#23](https://github.com/glennswest/fastetcd/issues/23) tracks this
   hardening; no duplicate is needed. HA headless service reachability means
   “not exposed externally” must not be confused with pod-level isolation.
9. **Resolved #276: stable instance UUID with guarded ownership.** Add
   `capabilities.flowsdnInstanceUUID` (canonical lowercase, nonzero UUID string;
   omitted by reference peers). Provision it once in durable cluster bootstrap
   state shared by HA writers; restart/leader change must reuse it. Never derive
   it from a process ID or generate one on each start. Claim an unleased
   `flowsdn/cluster-owners/<name>` key containing that UUID atomically with the
   leased config write. The guard survives config lease expiry. Compare absence
   with `Version==0`, and existing records with exact value, `mod_revision` and lease ID. Desired
   config lease IDs must be nonzero; equal bytes never suppress a required
   lease rebind after a new session.
   Never blindly rewrite a foreign modification. A different UUID, leased owner
   key, unstamped existing config or stamped config with missing owner guard is
   an error requiring explicit offline operator recovery, not automatic adoption.
   Preserve unknown config fields when adding the stamp. On CAS failure reread
   both keys and replan. No remote frontend role may access the private owner
   prefix. Administrative deletion/backup restore must preserve guard+bootstrap
   consistency; reference writers do not honor this guard, so it cannot promise
   collision protection against mixed unmodified writers. Such a collision must
   fail the flowsdn writer closed. Live atomic-store, bootstrap persistence and
   migration tests remain required; the library produces the guarded plan only.
10. **Resolved #277: prefix authorization lives in the apiserver process.**
    One public mTLS termination and explicit CN-to-role mapping feed the
    read-range checker before forwarding to the private backend. No additional
    sidecar is selected. The backend must be unreachable directly by peers.
    Check the entire requested byte range against one granted interval, not
    just the first key; reject unbounded reads, unknown principals and every
    non-Range/Watch RPC (including Txn). Decode an empty etcd `range_end` as a
    single-key request, and reject the zero-byte unbounded sentinel. Local
    administrative writes use a separate private trusted client. The pure range
    checker is implemented; TLS, CN mapping, gRPC enforcement, network isolation
    and adversarial transport conformance are outstanding.
11. **Resolved #279: explicit MCS and EndpointSlice-mirroring staging.** MCS
    `ServiceExport`/`ServiceImport`, `clusterset.local` DNS, `serviceexports/v1`
    writes and operator EndpointSlice mirroring remain required feature scope,
    owned by this spec's apiserver/mesh controllers and the spec 12 operator.
    Stage them after legacy mesh import/export, reconnect/resync and mixed-peer
    conformance pass. Enabling their currently accepted-but-ignored keys emits
    named warnings; it must not publish capabilities suggesting active support.
    Keep schemas, read-side tolerance and the harvested divergence marker. Revisit
    the stage when the legacy interoperability gate passes, then require MCS
    CRD/DNS lifecycle and EndpointSlice ownership/update/delete tests before
    enabling the keys. A warning planner is delivered, no feature runtime.

### Current implementation boundary

`flowsdn-clustermesh` provides configuration/compatibility plans, five-minute
resync selection, cross-cluster CIDR checks, byte-range authorization and UUID
ownership transaction planning. Local tests cover prefix escapes, forbidden RPCs,
atomic failed topology replacement, competing claims, stale revisions, restarts
and config lease loss. No network clients, leases, TLS, scheduler, API controllers,
actual store transactions, identity allocator or bootstrap persistence are
implemented here. Existing full acceptance gates in §9 remain open.


### Packaging decision (#238)

[ADR-0015](../decisions/0015-proxy-and-ztunnel-contracts.md) confirms the existing
§6.6 Rust apiserver plus separately owned fastetcd backend. There is no interim
upstream Go apiserver image. This resolves the image-owner choice, not server
implementation, image publication or backend acceptance. #275 now has the
shipped policy artifact and existing fastetcd#23 hardening tracker; workload
packaging and deployed policy enforcement remain validation obligations.
