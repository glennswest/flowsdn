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
| The scripttest harness that runs the harvested `.txtar` corpora | `17-test-harness.md` (in flight; ADR-0005) |

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
| F21 | Separate server and peer TLS identities | defence in depth for the raft port | **GAP** — one identity is shared; `--peer-*-file` flags are parsed and discarded | accepted for now; the peer port is not exposed outside the pod/StatefulSet. Recorded in §12 decision 8. |
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
