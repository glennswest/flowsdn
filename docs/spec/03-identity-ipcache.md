# Security identities, labels and the ipcache — specification

Status: draft. Derived from: `docs/inventory/05-policy-identity.md`,
`docs/inventory/12-clustermesh-kvstore.md`, `docs/inventory/13-crds-k8s.md`,
`docs/inventory/08-operator.md`, `docs/inventory/02-bpf-maps-loader.md`,
`docs/inventory/11-l7-proxy-dns-auth-mesh.md`; reference cilium v1.20.1
(7d68cfb394) paths `pkg/labels`, `pkg/labelsfilter`, `pkg/identity`,
`pkg/identity/cache`, `pkg/identity/key`, `pkg/identity/identitymanager`,
`pkg/allocator`, `pkg/k8s/identitybackend`, `pkg/k8s/labels.go`,
`pkg/k8s/utils/utils.go`, `pkg/source`, `pkg/ipcache`, `pkg/ipcache/types`,
`pkg/ipcache/restore`, `pkg/ipcache/cell`, `pkg/maps/ipcache`,
`pkg/datapath/ipcache`, `pkg/node/manager/manager.go`,
`daemon/cmd/hostips-sync.go`, `pkg/policy/cell/policy_importer.go`,
`pkg/policy/k8s/cilium_cidr_group.go`, `pkg/policy/aggregate.go`,
`operator/identitygc`, `bpf/lib/identity.h`, `bpf/lib/clustermesh.h`.
Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes
*what* flowsdn does and the exact data it exchanges. It does not transcribe
reference code. Where the reference behavior is kept for compatibility, say
so and name the consumer that depends on it (cilium-dbg, Hubble, Envoy,
operator, other cluster). Where flowsdn deviates, mark **DEVIATION** with the
reason and the ADR.

## 1. Scope

In scope: the label model (sources, synthesis from Kubernetes objects, the
identity-relevance filter, canonical string form); numeric identity encoding
(reserved, well-known, user-reserved, cluster-local, ClusterMesh and local
scopes); identity allocation in CRD mode (`CiliumIdentity`), release,
restart restore, and node-local allocation for CIDR/FQDN/CIDR-group and
per-node identities; the operator's identity garbage collector; the ipcache
(prefix to identity/tunnel/encryption/flags mapping), its metadata sources
and precedence, its update pipeline and its writes to `cilium_ipcache_v2`.

Out of scope, with owning spec: the ipcache BPF map layout and pinning
(`01-bpf-map-abi-loader`, this spec only writes it); how the datapath reads
identities from marks, VNIs and the ipcache (`02-datapath-programs`); the
policy engine that consumes identity add/delete events and selects CIDR
identities (policy spec); the FQDN proxy that produces `fqdn:` metadata (L7
spec); the kvstore client and ClusterMesh remote watchers (ClusterMesh spec,
which uses the import hooks defined in section 3.10); the endpoint state
machine that requests identities (agent/endpoint spec, section 7.1 here only
fixes the contract it relies on); operator-managed identity creation
(`--identity-management-mode=operator|both`, deferred per inventory 05).

## 2. Compatibility contract

| Interface | Consumer | MUST match |
|---|---|---|
| Canonical label string `source:key=value;`... (section 4.1) | other agents (CID index), kvstore peers, ClusterMesh, `cilium-dbg identity` | exact format, sort order, trailing `;` |
| `CiliumIdentity` object (section 4.3) | every agent in the cluster, operator GC, `cilium-dbg`, clustermesh-apiserver | `metadata.name` = decimal id, `security-labels` map keyed `source:key`, `metadata.labels[io.kubernetes.pod.namespace]`, annotation `io.cilium.heartbeat` |
| Reserved / well-known / user-reserved numbers (section 4.4) | BPF datapath, Hubble flows, policy maps, peer clusters, Envoy | numbers and meanings frozen |
| Identity bit layout and cluster-id shift (section 4.5) | peer clusters (VNI, ipcache), Envoy, Hubble | `24 - log2(max-connected-clusters + 1)` |
| `cilium_ipcache_v2` map (section 4.8) | Envoy `cilium.bpf_metadata` reads it directly (inventory 11); `cilium-dbg bpf ipcache` | layout owned by `01-bpf-map-abi-loader`; values written as specified here |
| Default label filter list (section 4.2) | users: changes identity numbering and policy semantics | regex list byte-identical |
| Synthesized pod labels (section 3.1) | policy authors, well-known identities, Hubble | key names and values |
| Source names and precedence (section 4.6) | `cilium-dbg ip list` (`metadata.source`), kvstore peers | names and order |
| kvstore key layout `cilium/state/identities/v1/{id,value,locks}` and `cilium/state/ip/v1/default/<ip>` | ClusterMesh peers, clustermesh-apiserver | preserved by the deferred kvstore backend; documented in section 4.7 |
| Local checkpoint `<state-dir>/local_allocator_state.json` | flowsdn restart only (upgrade from Cilium reads it) | JSON array of `{"id": n, "labels": {...}}` |
| REST `GET /identity`, `/identity/{id}`, `/identity/endpoints`, `GET /ip` | `cilium-dbg identity`, `cilium-dbg ip list`, health checks | models in section 4.9 |
| Monitor agent notifications `IPCache entry upserted/deleted` | Hubble, `cilium-dbg monitor` | JSON in section 8 |
| Metrics names (section 8) | Grafana dashboards | names and label sets |
| Config keys (section 6) | `cilium-config` ConfigMap, Helm | names and defaults |

## 3. Behavior

### 3.1 Label model

A label is `(source, key, value)`. Sources and their meaning:

| Source | Origin | Identity-relevant |
|---|---|---|
| `k8s` | pod/namespace/service-account synthesis (below), CNP selectors | yes, after filter |
| `container` / `cni` | legacy runtime labels | yes, after filter (flowsdn never produces them) |
| `reserved` | fixed entities `host`, `world`, ... (section 4.4) | always |
| `cidr` | one label per prefix, `cidr:<encoded prefix>` (section 4.1) | yes, local scope |
| `cidrgroup` | `CiliumCIDRGroup` labels | yes, local scope |
| `fqdn` | FQDN proxy resolutions `fqdn:<name>` | yes, local scope |
| `node` | node labels, only with `--enable-node-selector-labels` | yes, after node filter |
| `gen` | agent-generated, e.g. `io.cilium.k8s.named-ports.<i>` | yes |
| `directory` | static CNP files | selector-only |
| `unspec` | default when a parsed string has no source prefix | yes |
| `any` | selector wildcard; matches every source | selector-only |

Parsing rules (`ParseLabel`): the text up to the first `:` is the source if
present, else `unspec`; a leading `$` means source `reserved`; the text up to
the first `=` is the key, the rest the value; for `reserved` a string
`reserved:=x` yields key `x`. A `cidr` label MUST NOT carry a value. In a
selector (`ParseSelectLabel`) an absent source becomes `any`.

**Parsing clarification (2026-09-09).** Verified against the pinned reference
`pkg/labels/labels.go:807–887`: source splitting precedes value splitting,
so even a colon after an equals sign is the source delimiter. An empty source
normalizes to `unspec`; selector parsing changes both implicit and explicit
`unspec` to `any`. The reserved empty-key shorthand moves the entire remainder
into the key and leaves the value empty. Parsing does not trim whitespace.
The flowsdn validated label constructor rejects an empty final key and a
nonempty CIDR value; CIDR prefix validation, selector matching and label-source
validation remain separate responsibilities. Canonical serialization uses the
specified unescaped delimiters; callers must validate external label grammars
before treating that representation as a unique allocation key.

A label set (`Labels`) is a map keyed by **key only**. Two labels with the
same key and different sources cannot coexist in one set; the last write
wins. flowsdn MUST keep this (it is visible in `security-labels`, the
canonical string and selector matching).

**Pod identity labels.** For a pod in namespace `ns` with service account
`sa` in cluster `c`, the candidate set is built from the pod's
`metadata.labels` as follows, in order:

1. drop every pod label whose key starts with `io.cilium.k8s`;
2. add `io.cilium.k8s.namespace.labels.<nskey>=<nsvalue>` for every label of
   the Namespace object (hence `io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=<ns>`
   always exists on clusters that set the metadata label);
3. set `io.kubernetes.pod.namespace=<ns>`;
4. set `io.cilium.k8s.policy.serviceaccount=<sa>` if `sa` is non-empty, else
   ensure the key is absent;
5. set `io.cilium.k8s.policy.cluster=<c>`.

All of these carry source `k8s`. If the pod declares named container ports,
one or more `gen:io.cilium.k8s.named-ports.<i>` labels are appended whose
value is `name.PROTO.port` items joined by `_`, ports sorted by name, split
into a new label (`<i>` increments) whenever a value would exceed 63 bytes.
The result passes the identity filter (section 4.2); labels that fail become
*information labels* kept on the endpoint but not part of its identity.
Endpoint label state is four sets: `custom` (API-added), `orchestration
identity`, `disabled` (identity labels the user removed through the API),
`orchestration info`; `IdentityLabels() = custom ∪ orchestration identity`.

**Node identity labels** (for `reserved:host` and `reserved:remote-node`
prefixes when `--enable-node-selector-labels` is set): node labels with
source `node` filtered by `--node-labels`, plus
`k8s:io.cilium.k8s.policy.cluster=<node cluster>`.

### 3.2 Identity scope selection

Given a label set `L` the scope is determined first, then the allocator:

| Condition (checked in order) | Result |
|---|---|
| `L` equals a well-known identity's label set (section 4.4, feature enabled) | that well-known identity |
| `L` contains key `io.cilium.fixed-identity` whose value names a user-reserved label (`--fixed-identity-mapping`) | that user-reserved identity (128..255) |
| `L` has `reserved:host` | `reserved:host` (1); labels of the host identity are the dynamic merge in section 3.9 |
| `L` has `reserved:remote-node` and neither `policy-cidr-match-mode` contains `nodes` nor node-selector labels are enabled | `reserved:kube-apiserver` (7) if `L` also has `reserved:kube-apiserver`, else `reserved:remote-node` (6) |
| `L` is exactly one `reserved:` label naming a reserved identity other than user-reserved | that reserved identity |
| `L` has `reserved:remote-node` (per-node mode) | scope `0x02` (node-local allocation) |
| `L` is all `reserved` and has `reserved:ingress` | scope `0x01` (local) |
| every label has source `cidr`, `fqdn`, `reserved` or `cidrgroup` | scope `0x01` (local) |
| otherwise | global (CRD allocation) |

Local and reserved resolutions never touch the API server.

### 3.3 Global allocation (CRD mode)

The allocator MUST implement the following, observable by peers through the
`CiliumIdentity` objects it creates:

1. **Readiness.** Allocation and release block until the initial list of
   `CiliumIdentity` objects has been received; if that takes longer than
   `allocator-list-timeout` (3 m) the agent exits.
2. **Fast path.** If the node already holds a *verified* reference to key
   `K` (canonical string of `L`), increment its reference count and return
   the id.
3. **Lookup.** Look `K` up in the local informer index (`security-labels`
   canonicalized). If several objects match, choose the oldest
   `creationTimestamp`; ties broken by the lowest numeric name (the reference
   leaves the tie unspecified; flowsdn fixes it so two flowsdn agents
   converge). If found: take a local reference, then *acquire*: if the object
   carries `io.cilium.heartbeat`, remove the annotation with an Update (this
   is the signal to the operator that the identity is alive again); mark the
   local key verified; return.
4. **Create.** Otherwise lease a free id from the pool
   `[min(cluster), max(cluster)]` (section 4.5) minus every id currently seen
   in the cache, take a local reference, re-check the index (abort the
   attempt if `K` appeared meanwhile), then `Create` a `CiliumIdentity` named
   with the decimal id (section 4.3). `AlreadyExists` (another agent leased
   the same number) or any other error fails the attempt: release the id and
   the local reference.
5. **Retry.** Up to 16 attempts with exponential backoff from 20 ms, factor
   2, bounded by `identity-allocation-timeout` (2 m). Each attempt restarts
   at step 2, so an object created by a peer between attempts is reused.
6. **Concurrent identical label sets.** Two agents MAY both succeed at step 4
   with different numbers for the same `K`. This is legal: identity→labels
   is many-to-one. Both ids carry identical labels, so every selector that
   matches one matches the other and policy is unaffected. Each agent keeps
   the id it allocated for the lifetime of its local references; new lookups
   on every node converge to the oldest object (step 3); the newer object is
   deleted by the operator GC once no `CiliumEndpoint` references it.
   flowsdn MUST NOT "repair" duplicates by renumbering live endpoints.
7. **Release.** Decrement the local reference count; at zero drop the local
   key. No API call is made: deletion is the operator's job (section 3.6).
8. **Master-key protection.** If a `CiliumIdentity` that this node still
   references is deleted (event observed), re-create it (Create with the same
   number and labels) with retry until it exists or the local reference is
   gone. Without this, GC of a partitioned node's identity would orphan its
   endpoints.
9. **Periodic sync.** Every `identity-allocation-sync-interval` (5 m) every
   verified local key is re-acquired (step 3 acquire; recreated if missing).
   A key that lost its last reference while a sync was in flight is released
   again after the sync.
10. **Cache and events.** The informer feeds an id→labels cache (with a
    labels→id index). Each upsert/delete emits an identity change event.
    Events are drained in batches and delivered to the policy engine as one
    `UpdateIdentities(added, deleted)` call with disjoint sets; the initial
    list is followed by a `sync` event whose completion the policy engine
    acknowledges before allocations proceed. Ids seen in the cache are
    removed from the free pool; deleted ids return to it.

Kvstore, double-write and operator-managed modes are behind the backend
trait (section 11) and are **deferred**. `--identity-allocation-mode` other
than `crd` is rejected at startup (section 6).

### 3.4 Local allocation (scopes 0x01 and 0x02)

Two independent node-local caches, one per scope, each over numbers
`1..0xFFFFFF`. `lookupOrCreate(L, requested)`:

1. key = canonical string of `L`; if present, increment its reference count
   and return.
2. If `requested` is non-zero, has this scope, and is not taken, use it.
3. Otherwise scan from the "next" cursor for a number that is neither taken
   nor *withheld*, wrapping at the range end; the cursor advances past the
   chosen number. If the scan returns to its start, claim the first withheld
   number that is not taken (log a warning: this can cause momentary policy
   drops); if none, fail with "out of local identity space".
4. Store, emit an upsert change, return `(identity, allocated=true)`.

`release(id)`: decrement; at zero remove both indexes and emit a delete
change. Withhold/unwithhold manage the set used by restore (section 3.5).
Every allocation and release triggers a checkpoint (min interval 10 s) and,
when requested by the caller, an `UpdateIdentities` call.

### 3.5 Restart and restore

On start, before endpoints are restored:

1. Read `<state-dir>/local_allocator_state.json`. Withhold every id in it.
   For each entry whose labels still resolve to the same scope and still do
   not need a global identity, allocate with `requested = old id` (warn if a
   different number results). Deliver all as one `UpdateIdentities(added)`.
   Unwithhold. These are *restored references* (one per identity).
2. Dump the previous `cilium_ipcache_v2`. Keep entries with cluster id 0 and
   no tunnel endpoint whose identity is local scope or `reserved:ingress`.
   Ingress prefixes are re-inserted with `reserved:ingress` (source
   `restored`, resource `daemon//ingress`) and become the local node's
   ingress IPs. For the others: if the id was restored in step 1, insert its
   labels; else insert `RequestedIdentity(id)` plus, when that id maps to
   exactly one prefix in the dump, the CIDR labels of the prefix; withhold
   the id. Source `restored`, resource `daemon//restored`.
3. After endpoint restoration completes plus `identity-restore-grace-period`
   (30 s; 10 m when a kvstore is configured): remove the `daemon//restored`
   and `daemon//ingress` metadata and release the restored references.
   Identities still referenced by restored endpoints or policy survive; the
   rest are freed and their prefixes deleted from the map.

Restored endpoints re-acquire their global identity with a blocking
`AllocateIdentity` over their filtered labels (step 3.3); no numeric id is
requested, so a restarted node normally reuses the existing
`CiliumIdentity` and removes its heartbeat annotation.

### 3.6 Operator identity GC (CRD mode)

Runs in the operator every `identity-gc-interval` (15 m), only when
`CiliumEndpoint` GC is enabled (`cilium-endpoint-gc-interval != 0`) and the
`CiliumEndpoint` CRD exists (or CES is enabled).

- **Alive:** a `CiliumIdentity` is alive at time `t` if any `CiliumEndpoint`
  has `status.identity.id` equal to its name (informer index), or, with CES
  enabled, any `CiliumEndpointSlice` lists that id. Alive identities get
  `lifesign := t`. Any `CiliumIdentity` upsert event also sets its lifesign
  (so the agent's annotation removal, and the GC's own annotation write,
  count as life).
- **Timeout:** an identity is *expired* when `now - lifesign >
  identity-heartbeat-timeout` (30 m); an identity never seen counts from
  operator start, so a new leader waits one full timeout before acting.
- **Pass 1:** an expired, not-alive identity without `io.cilium.heartbeat`
  is annotated `io.cilium.heartbeat=<now, RFC3339Nano>` via Update.
- **Pass 2:** on a later run, an expired, not-alive identity that carries the
  annotation is deleted with preconditions `{UID, ResourceVersion}` after
  the rate limiter admits it (`identity-gc-rate-limit` 2500 per
  `identity-gc-rate-interval` 1 m). A conflict (agent re-acquired it) is
  logged and skipped. Because pass 1's write refreshes the lifesign, pass 2
  happens no sooner than one heartbeat timeout after pass 1.
- Lifesign entries older than 10× the timeout are dropped from memory.
- Reference deletes the SPIRE auth entry first; mutual auth is deprecated in
  1.20 and flowsdn does not implement it (**DEVIATION**, ADR-0001 scope
  table).

### 3.7 ipcache model

The ipcache maps `PrefixCluster = (prefix, cluster id)` to
`(identity, tunnel peer, encryption key index, endpoint flags, k8s metadata,
source)`. Cluster id is 0 for everything except ClusterMesh entries whose
watcher is configured with `WithClusterID` (tests/extensions only; production
remote entries use cluster id 0, inventory 12). Prefixes are canonical
(IPv4-mapped IPv6 unmapped; masked). The datapath sees only the BPF map;
userspace additionally holds the metadata layers below.

**Metadata layering.** For each prefix, metadata is stored per
`(resource id)` where a resource is `<kind>/<namespace>/<name>`
(kinds `ccnp`, `cidrgroup`, `cnp`, `daemon`, `ep`, `file`, `netpol`,
`kcnp`, `node`; FQDN uses `fqdn-name-manager:<name>`). Each resource layer
carries a source and any of: labels, identity-override flag, tunnel peer,
encryption key, requested identity, endpoint flags. Setting a field replaces
that field for that resource; removing a field clears it; a resource with no
fields is dropped; a prefix with no resources is dropped.

**Flattening** (the effective view) walks resources ordered by source
precedence (section 4.6), ties by resource id string ascending, and for each
field takes the first resource that sets it; for labels, keys are merged in
that order and a conflicting value for an existing key is ignored with a
warning. The effective source is the first resource's source. An identity
override, when present, replaces the merged labels with the override
resource's labels exactly.

**Identity resolution for a prefix** (in the pipeline, section 3.8):

1. override present → allocate a local identity from the override labels
   (this is how `0.0.0.0/0` and `::/0` become `reserved:world`).
2. Otherwise start from the flattened labels and **inherit** from every
   covering prefix (shorter prefix lengths, same cluster id) each label whose
   key is absent; at most one `cidr:` label is inherited and only if the
   prefix has none of its own.
3. Normalize (`resolveLabels`):
   - `in-cluster` = has `reserved:remote-node`, `reserved:host`,
     `reserved:health` or `reserved:ingress`; `node` = the first two;
   - in-cluster removes `reserved:world*`;
   - in-cluster removes `cidr:`, `fqdn:`, `cidrgroup:` labels unless the
     prefix is a node and `policy-cidr-match-mode` contains `nodes`;
   - `node:` labels are removed unless the prefix is a node and node
     selector labels are enabled;
   - if the set is now empty, it becomes the CIDR labels of the prefix
     (`cidr:<enc>` unless prefix length 0, plus the world label);
   - not in-cluster adds the world label for the address family
     (`reserved:world` single-stack; `reserved:world-ipv4`/`-ipv6`
     dual-stack).
4. Cluster id 0 and `reserved:host` present → the reserved host identity;
   its labels are recorded for this prefix (section 3.9).
5. Otherwise allocate a local identity with `requested` = the flattened
   requested identity (0 if none), per section 3.2/3.4. A set that would
   need a global identity here is a bug and MUST fail the prefix.

**Writers.** The table fixes who writes what; the identity column is the
result after resolution.

| Writer | Resource | Source | Prefixes | Metadata → identity |
|---|---|---|---|---|
| host-IP sync | `daemon//reserved` | `local` | every local device address (not excluded, family enabled) as /32,/128 | `reserved:host` → 1 |
| host-IP sync | `daemon//reserved` | `local` | `0.0.0.0/0`, `::/0` | override `reserved:world[-ipv4/-ipv6]` → 2 / 9 / 10 |
| node manager | `node//<name>` | node source (`k8s`, `custom-resource`, `kvstore`, `clustermesh`, `local`) | each node address /32,/128 (CiliumInternalIP may carry a cluster id) | node labels (3.1) → 6, 1, 7 or scope 0x02; TunnelPeer = node IP when the address is CiliumInternalIP, or node encryption, or host firewall is on; EncryptKey = node's key when node encryption is on and the local node has not opted out; flags `remote-cluster` when the node's cluster differs; with `nodes` CIDR match mode the CIDR labels of each address are added |
| node manager | `node//<name>` | as above | remote node pod CIDRs | world label + TunnelPeer(node IP) + EncryptKey(node key) → 2 / 9 / 10 with tunnel endpoint |
| node manager | `node//<name>` | as above | health IPs | `reserved:health` + TunnelPeer + EncryptKey (static WireGuard key when WireGuard) → 4 |
| node manager | `node//<name>` | as above | ingress IPs | `reserved:ingress` + TunnelPeer + EncryptKey → 8 (local scope resolution yields 8 because the set is exactly one reserved label) |
| kube-apiserver watcher | `ep/default/kubernetes` | `kube-apiserver` | backend addresses of Service `default/kubernetes` | `reserved:kube-apiserver` → 7 when on a node prefix, else world+kube-apiserver → local identity |
| policy importer | `cnp/..`, `ccnp//..`, `netpol/..`, `kcnp//..`, `file//..`, consolidated under `daemon//consolidated-prefix` with a per-prefix reference count across resources | policy's source (`custom-resource` for CNP/CCNP, `k8s` for NetworkPolicy/KCNP, `directory` for files) | every CIDR referenced by `toCIDR`, `toCIDRSet`, `fromCIDR`, `fromCIDRSet`, `ipBlock`, `networks`, generated `toServices` | `cidr:<enc>` + world → local identity |
| CIDR group watcher | `cidrgroup//<name>` | `generated` | `spec.externalCIDRs[]` | `cidrgroup:<k>=<v>`, `cidrgroup:<k>+<v>`, `cidrgroup:io.cilium.policy.cidrgroupname/<name>`, world → local |
| FQDN name manager | `fqdn-name-manager:<name>` | `generated` | resolved addresses /32,/128 | `fqdn:<name>` (+ world via normalization) → local |
| pod watcher | (assigned identity, see 3.10) | `k8s` | pod IPs | identity 3 `reserved:unmanaged`, host IP, encrypt key, `{namespace, pod, named ports}` |
| CiliumEndpoint watcher | (assigned identity) | `custom-resource` | CEP addressing IPs | `status.identity.id`, node IP, encryption key, `{namespace, pod, named ports}` |
| kvstore / ClusterMesh watcher | (assigned identity) | `kvstore` / `clustermesh` | `IPIdentityPair` keys | pair id (host→remote-node), `HostIP`, `Key`, k8s metadata |
| restorer | `daemon//restored`, `daemon//ingress` | `restored` | from the old map | see 3.5 |

Local endpoints are **not** written into the ipcache by the endpoint itself
in CRD mode: they arrive through the CEP watcher (own node's CEP) and the pod
watcher, exactly as for remote pods. The endpoint publishes to the kvstore
only in kvstore mode (deferred).

### 3.8 Update pipeline and revision fence

All metadata writes are batched (`UpsertMetadataBatch` / `RemoveMetadataBatch`)
and return a **revision**:

1. Under the metadata lock, apply each update; for `IsCIDR` updates the
   consolidated resource's per-prefix reference count is incremented (first
   reference inserts) or decremented (last reference removes). Collect the
   *affected prefixes*: the prefix itself and, for non-host prefixes, every
   descendant prefix of the same cluster id (their inherited labels may
   change).
2. Enqueue the affected prefixes; return the current *queued revision*
   (starts at 1). Wake the injector.
3. The injector (one task, `ipcache-inject-labels`; retries with backoff up
   to 1 m on error) waits for the Kubernetes caches to be synced, dequeues
   the whole set and bumps the queued revision, then processes chunks of 512
   prefixes (the first revision is one chunk). For each prefix:
   - resolve the identity (3.7); note `isNew`;
   - compute the new entry `(id, source, tunnel peer, key, flags)`; if it
     equals the current one, skip;
   - schedule the map upsert; `force` if the source changed and the id
     changed; if the prefix has no metadata left, schedule a delete;
   - remember the previous identity for release.
4. After the chunk: deliver `UpdateIdentities(added = new ids incl. a changed
   host identity)` to the policy engine and **wait for its completion** (all
   affected policy maps programmed) — identity additions MUST reach policy
   maps before the ipcache map learns the prefix, otherwise traffic from the
   new identity is dropped by default-deny.
5. Apply upserts then deletes to the ipcache table, which notifies listeners
   (BPF map writer, monitor, Envoy NPHDS when enabled). Then release the
   previous identities; the resulting `UpdateIdentities(deleted)` runs after
   the map no longer references them — deletions MUST reach policy maps
   after the ipcache map, the reverse order of additions.
6. When every chunk succeeded, set *injected revision* = the dequeued
   revision and wake waiters. Failed prefixes are re-enqueued and the
   revision is not advanced.

`WaitForRevision(rev)` blocks until injected revision ≥ rev or the context
ends. The policy importer uses it with a 10 s bound after upserting CIDR
prefixes (skipped while the queued revision is 1, i.e. during startup); the
FQDN proxy uses it before releasing a DNS response. A timeout is logged as a
warning ("may cause policy drops") and is not an error.

### 3.9 Special identities in the ipcache

- **`reserved:host` labels are dynamic.** Every prefix resolving to the host
  identity contributes its labels; the host identity's label set is
  `reserved:host` ∪ all contributions. On change, the new label array is
  pushed to the policy engine as an *added* identity 1. A prefix leaving the
  host removes its contribution. This is how `node:` labels and CIDR labels
  reach host policy.
- **remote-node vs host.** A node prefix gets `reserved:host` when the node
  is the local node, else `reserved:remote-node`. Numerically: local node →
  1; remote → 6, or 7 if the same prefix also carries
  `reserved:kube-apiserver`, or a scope-0x02 identity when per-node labels
  are enabled (kube-apiserver then stays a label on that identity).
- **kube-apiserver outside the cluster.** A backend address that is not a
  node prefix resolves to labels `{reserved:kube-apiserver, reserved:world*}`
  and a **local** identity (scope 0x01); policy entity `kube-apiserver`
  selects both 7 and such local identities. When the backend disappears, the
  removal set is widened to include the world label so the prefix is deleted
  rather than left as a bare world entry.
- **Shadowing.** A /32 or /128 entry for an address hides any CIDR entry
  with the same address and full length coming from the legacy assigned
  path (3.10). The hidden entry is kept but not notified to listeners; when
  the endpoint entry is deleted the hidden entry is revived (an upsert
  notification carrying the CIDR's own attributes). In the BPF map this is
  natural LPM; the rule fixes the userspace listener/monitor stream.
- **Unmanaged pods.** Pod IPs learned from Pods (identity 3) are overridden
  by CEP (source `custom-resource` beats `k8s`), so a managed pod is
  `unmanaged` only until its CEP is observed.

### 3.10 Assigned-identity entries (legacy `Upsert` path)

The reference keeps a second write API for entries whose identity is decided
elsewhere (CEP, Pod, kvstore, ClusterMesh) and tracks per entry whether it is
owned by that API, the metadata API, or both. flowsdn represents such writes
as a metadata field `AssignedIdentity(id)` on resource
`<source>//<ip>` (**DEVIATION**: internal representation only; observable
precedence, shadowing and notifications are unchanged). Rules:

- An `AssignedIdentity` resource short-circuits resolution: no labels are
  merged, no local identity is allocated, `k8s metadata` (namespace, pod
  name, named ports) and host IP / key come from the same resource.
- Precedence between an assigned entry and metadata entries for the same
  prefix follows section 4.6 exactly as for any two resources; a lower
  precedence write is refused and counted in
  `cilium_ipcache_errors_total{error="cannot_overwrite_by_source"}`; equal
  precedence overwrites.
- A delete from source `S` is honored only if the effective source is `S`
  (`no_such_prefix` / `cannot_overwrite_by_source` otherwise).
- Remote (`kvstore`/`clustermesh`) pairs with identity 1 are stored as 6.
  Every remote pair MUST pass the identity validator for its cluster
  (section 4.5) before insertion; the `remote-cluster` flag is set when the
  node's cluster name differs from the local one.
- Named ports from k8s metadata feed the policy engine's named-port map,
  keyed by identity; a changed identity moves the ports.

## 4. Data model

### 4.1 Canonical label string (the identity key)

`Labels` sorted by **key** (byte order), each rendered as
`<source>:<key>=<value>;` — the `=` is always present, even for an empty
value — and concatenated with **no** separator other than the trailing `;`
of each element:

```
k8s:app=foo;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.kubernetes.pod.namespace=default;
reserved:host=;
cidr:10.0.0.0/8=;reserved:world=;
```

This string is the informer index key, the local identity cache key, the
kvstore master-key value and the slave-key path component; the trailing `;`
guarantees no key is a prefix of another. `LabelArray` (the sorted slice) is
sorted by key only; ordering between arrays compares key, then value, then
source. There is no hashing of labels in the allocation path; `labelsSHA256`
in the REST model is informational.

**CIDR label key encoding.** `cidr:<addr>/<len>` for IPv4. For IPv6 every
`:` becomes `-`; a leading `:` becomes `0-`, a trailing `:` becomes `-0`:
`::1/128` → `cidr:0--1/128`, `fd00::/64` → `cidr:fd00--0/64`,
`2001:db8::1/128` → `cidr:2001-db8--1/128`. Decoding replaces `-` with `:`.
A prefix of length 0 yields no `cidr:` label, only the world label. Printing
(`Labels.String()`, REST) renders `cidr:` labels with the decoded prefix.
A `cidr` selector label `A` matches a `cidr` label `B` when `A`'s prefix
contains `B`'s address and is not longer.

The CIDR numeric boundary canonicalizes a prefix by masking all host bits before
encoding or comparison. IPv4 lengths are 0–32 and IPv6 lengths 0–128; an address
and a decimal length are both required. IPv6 uses compressed lowercase address
formatting before colon escaping. IPv4-mapped IPv6 remains an IPv6 prefix and
never matches an IPv4 prefix. Family equality is required for containment,
including `/0` selectors. These rules make selector containment deterministic
without introducing general label matching or identity allocation.

Decoding accepts the encoded key or the decoded textual prefix used for display,
then validates and masks it. It does not accept zone identifiers, whitespace or
signed lengths; encoded input is bounded to 64 bytes (longer than every valid
key). Generating identity labels for either family's `/0` omits the CIDR label;
the caller still selects the appropriate reserved world label from its stack
mode. A manually supplied `/0` CIDR selector can be decoded for same-family
containment without being emitted as an identity label. Non-CIDR source labels
are outside this helper's matching contract. This clarifies the §4.1 boundary
for the Rust CIDR primitive; no reference implementation read was needed.

`cidrgroup` encoded form: key `<key>+<value>`, no value.

### 4.2 Identity label filter

Grammar of one entry (`--labels`, one per element): `[<source>:]<regex>`,
optional leading `!` on the regex part meaning *exclude*. `<source>` limits
the entry to labels of that source (empty = any). The regex MUST match at
offset 0 of the key (Go RE2 syntax; flowsdn uses the `regex` crate in the
RE2-compatible subset). Entries from `--labels` are appended to the defaults
(or to the file's list). A user or file include enables whitelist mode;
built-in includes do not. The built-in includes instead override shorter
exclusions, keeping ordinary application labels by default.

For each label, `included` and `ignored` begin at zero. Each matching include
updates `included` to the larger match end offset. Each matching exclusion
updates `ignored` when it is zero or the new match end is smaller. Retain the
label when `(!whitelist && ignored == 0) || included > ignored`. Offsets are
UTF-8 byte offsets. Equal positive lengths exclude. Zero-length matches use
the same zero sentinel: an empty include does not itself admit a label, an
empty exclusion alone does not reject it, and an empty exclusion can reset
a prior positive exclusion before later rules are examined. This preserves
the reference's ordered behavior rather than treating zero as a positive match.

Default list, in order (`reserved:.*` is first in the defaults; file diagnostics
are described below):

```
reserved:.*
io\.kubernetes\.pod\.namespace
io\.cilium\.k8s\.namespace\.labels
app\.kubernetes\.io
io\.cilium\.k8s\.policy\.cluster
io\.cilium\.k8s\.policy\.serviceaccount
!io\.kubernetes
!kubernetes\.io
!statefulset\.kubernetes\.io/pod-name
!apps\.kubernetes\.io/pod-index
!batch\.kubernetes\.io/job-completion-index
!batch\.kubernetes\.io/controller-uid
!.*beta\.kubernetes\.io
!k8s\.io
!pod-template-generation
!pod-template-hash
!controller-revision-hash
!controller-uid
!annotation.*
!etcd_node
!topology\.kubernetes\.io
```

`--label-prefix-file` JSON: `{"version":1,"valid-prefixes":[{"prefix":"..",
"source":"..","invert":false}]}`; version MUST be 1, prefix and source
non-empty. File entries are **literal key prefixes**, not compiled regexes;
their match length is the prefix's byte length. `invert` defaults to false.
The file replaces the defaults; CLI additions remain regexes. Missing or null
`valid-prefixes` means an empty list. Unknown JSON fields are ignored. A final
file-plus-CLI list lacking source `reserved` and pattern `.*` emits an
error-level diagnostic but is accepted. This presence check does not require
first position or inspect `invert`, and does not prove reserved labels will
be retained (a file's literal `.*` differs from a CLI regex). The pure API
returns the diagnostic for its caller to log.

`--node-labels` uses the CLI grammar with an empty default list, and applies
only to `node:` labels. With no include, unmatched node labels are kept but
positive-length exclusions still reject them. Non-node labels pass through
unchanged when applying this node-only filter.

CLI parsing splits at the first colon, then strips at most one leading `!`
from the pattern. Thus `node:!zone` excludes while `!node:zone` is an include
for the literal source `!node`. Use an explicit empty source for a regex
containing a colon, such as `:(?:a|b)`. Empty CLI elements are skipped by list
construction; a standalone empty pattern is invalid, while `!` compiles the
empty exclusion regex. No whitespace is trimmed. Rust regex syntax outside
the RE2-compatible subset is not a portability guarantee.

Within the shared syntax, Perl classes `\d`, `\w` and `\s` use ASCII sets:
digits, ASCII letters/digits/underscore, and tab/newline/form-feed/carriage-return/
space, respectively (vertical tab is excluded from `\s`). Their uppercase
negations include Unicode characters outside those sets. `\b` and `\B` test
ASCII word boundaries. Unicode literals, dot and explicit `\p`/`\P` classes
retain Unicode behavior. Normalization uses regex syntax-tree spans so escaped
backslashes and bracket expressions retain their meaning. Case-insensitive
classes apply Unicode simple folding before negation, including Kelvin sign
and long s in folded `\w`; word boundaries remain ASCII even in that mode.
This is the common syntax subset, not a full Go RE2 syntax implementation.
Sources: [RE2 syntax](https://github.com/google/re2/wiki/syntax),
[Rust regex Unicode semantics](https://docs.rs/regex/latest/regex/#unicode),
and Go's [regexp syntax parser](https://github.com/golang/go/blob/master/src/regexp/syntax/parse.go)
(`parsePerlClassEscape` and `appendGroup`, inspected 2026-09-09 for the
case-folding ambiguity). No implementation was copied.

**Reference ambiguity resolution, 2026-09-09.** These details correct the
earlier summary that every include (including defaults) enabled a whitelist,
and clarify file literal matching and zero-length behavior. Read-only evidence:
Cilium v1.20.1, commit `7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc`,
`pkg/labelsfilter/filter.go` lines 58–105 (matching and source split),
135–189 (user includes and nonfatal reserved diagnostic), 220–259
(default mode), 264–341 (file decoding and precedence). This records behavior;
no reference implementation or test fixture was copied. The Rust `filter`
feature enables the existing regex and JSON dependencies; numeric and label
primitives remain available without default features.

### 4.3 `CiliumIdentity` (cilium.io/v2, cluster-scoped)

```yaml
apiVersion: cilium.io/v2
kind: CiliumIdentity
metadata:
  name: "1000"                              # decimal numeric identity
  labels:
    io.kubernetes.pod.namespace: default    # only if k8s:io.kubernetes.pod.namespace is a security label
  annotations:
    io.cilium.heartbeat: 2026-09-07T10:00:00.123456789Z   # set by operator GC pass 1; removed by agents
security-labels:                            # required; source-of-truth
  k8s:app: foo
  k8s:io.cilium.k8s.policy.cluster: default
  k8s:io.cilium.k8s.policy.serviceaccount: default
  k8s:io.kubernetes.pod.namespace: default
  k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: default
```

`security-labels` keys are `<source>:<key>`; values are the label values
(empty string allowed). The CRD schema (inventory 13) MUST be installed
byte-identically; `status` exists but is unused. A `CiliumIdentity` whose
`security-labels` do not pass the identity filter is still honored as-is
(the filter runs on the writer, not the reader).

### 4.4 Numeric identity table (frozen)

`NumericIdentity` is `u32`; bits 31..24 scope, 23..0 usable on the wire
(VXLAN/Geneve VNI, skb mark). Wire identities MUST be < 2^24.

**Numeric decoding boundary.** The supported numeric core accepts scope zero
including reserved holes (decoding does not authorize allocation), and the two
nonzero-index scoped ranges in the table below. Their highest supported value
is `0x02FF_FFFF`; the empty bases `0x0100_0000` and `0x0200_0000` are not
allocated identities and are rejected by validated constructors. Other scope
bytes are unsupported. All supported scoped identities are rejected by the
24-bit wire encoder rather than truncated. This defines the numeric core's
supported boundary without importing an unspecified backend sentinel value.

| Number | `reserved:` name | Meaning |
|---|---|---|
| 0 | unknown | invalid / not yet determined; also the wildcard key in policy maps |
| 1 | host | the local node's own addresses |
| 2 | world | outside the cluster (single-stack), or any world in policy entities |
| 3 | unmanaged | pod IP known from Kubernetes but not (yet) managed |
| 4 | health | health-check endpoints |
| 5 | init | endpoint whose labels are not yet resolved |
| 6 | remote-node | another node of this or a meshed cluster |
| 7 | kube-apiserver | a node that hosts a kube-apiserver backend (labels `kube-apiserver` + `remote-node`) |
| 8 | ingress | Cilium Ingress / Gateway proxy source address |
| 9 | world-ipv4 | world, IPv4 (dual-stack only; single-stack uses 2) |
| 10 | world-ipv6 | world, IPv6 (dual-stack only) |
| 11 | aggregate-cluster | policy-map aggregate of all global identities of the local cluster |
| 12 | aggregate-cluster-mesh | aggregate of global identities of other clusters |
| 13 | aggregate-world | aggregate of scope-0x01 identities (CIDR/FQDN/CIDR-group) |
| 14 | aggregate-remote-node | aggregate of scope-0x02 per-node identities |
| 15..99 | — | unallocated reserved space; MUST NOT be allocated |
| 100 | (deprecated etcd-operator) | never allocated |
| 101 | (deprecated cilium-kvstore) | never allocated |
| 102 | kube-dns (well-known) | see below |
| 103 | eks-kube-dns | |
| 104 | coredns | |
| 105 | cilium-operator | |
| 106 | eks-coredns | |
| 107..109 | (deprecated) | never allocated |
| 110 | kube-dns + namespace metadata label | |
| 111 | eks-kube-dns + ns label | |
| 112 | coredns + ns label | |
| 113 | cilium-operator + ns label | |
| 114 | eks-coredns + ns label | |
| 115 | (deprecated) | never allocated |
| 116..127 | — | unallocated |
| 128..255 | user reserved | `--fixed-identity-mapping=<id>=<label>`; pod selects it with label `io.cilium.fixed-identity=<label>` |
| 256..max(0) | cluster-local global | CRD-allocated, cluster id 0 |
| `c<<shift .. ((c+1)<<shift)-1` | ClusterMesh cluster `c` | allocated by cluster `c` |
| `0x0100_0001..0x01FF_FFFF` | local (scope 0x01) | CIDR, FQDN, CIDR group, ingress-from-restore; never on the wire |
| `0x0200_0001..0x02FF_FFFF` | per-node (scope 0x02) | node identities with node selector labels |

**Well-known identities** (enabled by `enable-well-known-identities`, default
true; `C` = cluster name, `N` = the agent's namespace, all source `k8s`):

| Id | Labels |
|---|---|
| 102 | `k8s-app=kube-dns`, `io.kubernetes.pod.namespace=kube-system`, `io.cilium.k8s.policy.serviceaccount=kube-dns`, `io.cilium.k8s.policy.cluster=C` |
| 103 | 102's labels + `eks.amazonaws.com/component=kube-dns` |
| 104 | `k8s-app=kube-dns`, namespace `kube-system`, serviceaccount `coredns`, cluster `C` |
| 105 | `name=cilium-operator`, `io.cilium/app=operator`, `app.kubernetes.io/part-of=cilium`, `app.kubernetes.io/name=cilium-operator`, namespace `N`, serviceaccount `cilium-operator`, cluster `C` |
| 106 | 104's labels + `eks.amazonaws.com/component=coredns` |
| 110–114 | the same as 102–106 respectively, plus `io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=<that namespace>` |

A label set equal to one of these resolves without the API server. The
reference keeps the table but inventory 05 recommends shipping it flag-off;
flowsdn keeps the reference default (on) because existing clusters have
policy-map entries and Hubble history with these numbers.

**Aggregation** (`aggregate_for(id)`, must agree between userspace and BPF):

| Input | Aggregate |
|---|---|
| 0, 11, 12, 13, 14 | itself |
| 1..99 (all other reserved) | 0 (not aggregated) |
| scope 0x02 | 14 |
| scope 0x01 | 13 |
| global, ≥ 100, `cluster_id(id) == local cluster id` | 11 (includes 100..255) |
| global, ≥ 100, other cluster | 12 |

`AllAggregates = {0, 14, 13, 11, 12}`. Identities 9/10 fold to 2 in the
tunnel id (`get_tunnel_id`) and unfold by L3 protocol on receive.

### 4.5 Bit layout and ClusterMesh ranges

```
bit 31..24  scope        0x00 global, 0x01 local, 0x02 remote-node
bit 23..16  cluster id   (8 bits when max-connected-clusters = 255)
bit 15..0   identity     (16 bits)
--- or, with max-connected-clusters = 511 ---
bit 23..15  cluster id   (9 bits)
bit 14..0   identity     (15 bits)
```

`bits = log2(max + 1)` (8 or 9), `shift = 24 - bits` (16 or 15).
`cluster_id(id) = (id >> shift) & max`. Allocation range of cluster `c`:
`min(c) = c == 0 ? 256 : c << shift`, `max(c) = ((c + 1) << shift) - 1`
(so cluster 0 has 256..65535 with 255 clusters and 256..32767 with 511).
The CRD allocator leases numbers in `[min(c), max(c)]` with prefix mask
`c << shift`. `max-connected-clusters` MUST be 255 or 511 and MUST be equal
on every cluster of a mesh (`CiliumClusterConfig.capabilities.maxConnectedClusters`
is checked on connect). `cluster-id` MUST be in `1..max` when meshing (0 =
unset); an id with bit `0x80` set is refused with ENI or Alibaba IPAM or
`aws-cni` chaining (mark collision). `cluster-name` matches
`^([a-z0-9][-a-z0-9]*)?[a-z0-9]$`, max 32 chars.

For the numeric interface, the configured maximum is inclusive: valid meshed
cluster IDs are `1..=255` or `1..=511`. Cluster zero is allowed for standalone
allocation only. Index zero in a nonzero cluster is included in its range;
only cluster zero excludes indices 0 through 255. Cluster extraction applies
to global identities; the scoped identity index is not a cluster encoding.

**Remote identity validation.** An identity observed from cluster `c` MUST
be in `[min(c), max(c)]`, and its labels MUST include
`k8s:io.cilium.k8s.policy.cluster=<c's name>` (source `k8s`, exact value);
otherwise the event is skipped with a warning. A remote ipcache pair's
identity MUST be in that range or `< 256` (reserved). Identities `> u32`
or `> MaxNumericIdentity` from any backend are rejected.

**Local identity upper bound (DEVIATION, resolves inventory 05's open
question).** The reference userspace allocates local identities up to
`0x01FF_FFFF`, while the reference BPF classifies "CIDR identity" as
`0x0100_0001..0x0100_FFFF` (`CIDR_IDENTITY_RANGE_END`), so a node with more
than 65 535 live CIDR identities would have the datapath treat the excess as
in-cluster (`identity_is_cluster`) — a latent reference defect affecting
egress gateway, encryption and host policy decisions. flowsdn keeps the
userspace range (`1..0xFFFFFF` per scope) and its datapath MUST classify by
scope byte: `is_cidr(id) = (id & 0xFF00_0000) == 0x0100_0000`, and
`is_world(id) = id ∈ {2, 9, 10} || is_cidr(id)`. Both sides then agree for
the entire range. The datapath spec MUST reference this paragraph. Local
identities MUST never be written into a VNI or into the identity field of a
mark; the proxy redirect mark carries the proxy port, and Envoy resolves
identities from the ipcache map, so no consumer needs a local identity on
the wire.

### 4.6 Sources and precedence

Highest first: `kube-apiserver`, `local`, `kvstore`, `custom-resource`,
`k8s`, `clustermesh`, `directory`, `api`, `generated`, `restored`,
`unspec`. `allow_overwrite(existing, next)` is true when `next`'s rank is
less than or equal to `existing`'s; unknown sources rank last. The
per-prefix effective source is the highest-ranked resource; when a prefix
has more than one resource and any is `kube-apiserver`, that is the
effective source.

### 4.7 kvstore layout (deferred backend; documented for peers)

Master key `cilium/state/identities/v1/id/<id>` → canonical label string,
no lease; slave key `cilium/state/identities/v1/value/<label string>/<node
suffix>` → decimal id, leased; lock `cilium/state/identities/v1/locks/<label
string>.lock`. ipcache `cilium/state/ip/v1/default/<ip or ip/len>` →
`IPIdentityPair` JSON: `{"IP","Mask","HostIP","ID","Key","Metadata",
"K8sNamespace","K8sPodName","K8sServiceAccount","NamedPorts":[{"Name","Port",
"Protocol"}]}`; key name equals `IP` or `IP/len`. Remote clusters are
mirrored under `cilium/cache/{identities,ip}/v1/<cluster>/...`.

### 4.8 `cilium_ipcache_v2` writes

Layout owned by `01-bpf-map-abi-loader` (LPM trie, 24-byte packed key
`{prefixlen u32, cluster_id u16, pad u8, family u8, ip[16]}`, 24-byte value
`{sec_identity u32, tunnel_endpoint[16], pad u16, key u8, flags u8}`,
512 000 entries, `NO_PREALLOC | RDONLY_PROG`, pinned under
`/sys/fs/bpf/tc/globals/`). This spec fixes the values written:

- `prefixlen = 32 + prefix bits` (the 32 static bits cover cluster id, pad
  and family); `family` 1 = IPv4, 2 = IPv6; `cluster_id` from the
  `PrefixCluster`.
- `sec_identity` = the resolved identity.
- `tunnel_endpoint` = the entry's host IP, **omitted (zero, `has_tunnel`
  clear)** when it equals the local node's IP of the underlay family
  (IPv4 underlay: compare the IPv4 form; IPv6 underlay: compare as is), or
  when no host IP is known. Flags: bit 0 `skip_tunnel`, bit 1
  `has_tunnel_endpoint`, bit 2 `ipv6_tunnel_endpoint`, bit 3
  `remote_cluster`. Bits 0 and 3 come from the entry's endpoint flags; bits
  1 and 2 are derived from the tunnel endpoint.
- `key` = encryption key index (0 = none).
- Deletes remove the key; no tombstones. The map is recreated (not reused)
  at start after the restore dump (section 3.5), so stale entries cannot
  survive a restart.

Envoy's `cilium.bpf_metadata` opens the map by pinned name; the Envoy
bootstrap written by flowsdn MUST pass the pinned name of this map
(`cilium_ipcache_v2`) in `ipcache_name` (inventory 11 lists the proto
default `cilium_ipcache`).

### 4.9 REST models

- `Identity`: `{ "id": int, "labels": ["source:key=value", ...],
  "labelsSHA256": string }` — labels in canonical (key) order, `cidr:`
  rendered decoded, `=value` omitted when empty.
- `IdentityEndpoints`: `{ "identity": Identity, "refCount": int }`
  (`GET /identity/endpoints`, from the local identity manager, section 5.4).
- `GET /identity?labels=...` lists reserved, well-known, global (cache) and
  local identities; `GET /identity/{id}` (404 when unknown).
- `GET /ip?cidr=&labels=`: `IPListEntry` `{ "cidr": "a.b.c.d/32",
  "identity": int, "hostIP": string, "encryptKey": int, "metadata": {
  "source": string, "namespace": string, "name": string } }`, filtered by
  containment in `cidr` and by identity labels; 404 when empty; shadowed
  entries omitted; sorted by prefix length then address.

### 4.10 Local checkpoint file

`<state-dir>/local_allocator_state.json`: JSON array of
`{"id": <u32>, "labels": {"<key>": {"key": "...", "value": "...",
"source": "..."}}}` covering both local scopes; written atomically
(temp file + rename, mode 0600), at most every 10 s, and once at shutdown.

## 5. Algorithms

### 5.1 Free-id selection (global)

Pool = `[min(c), max(c)]` as a set of intervals. `lease()` takes the lowest
free number and marks it leased (not yet used); `use()` confirms;
`release()` returns it. Every id observed in the cache is `remove()`d from
the pool, every deleted id `insert()`ed back. Two agents racing for the same
number are resolved by the API server's name uniqueness (section 3.3 step 4).

### 5.2 Local next-free cursor

Section 3.4 step 3. Complexity is O(1) amortized; the wrap check compares
the cursor to its value at scan start. The cursor is per scope and is not
persisted (restore re-requests old numbers explicitly).

### 5.3 Flatten and inherit

`flatten(prefix)` is memoized per prefix and invalidated on any write to
that prefix. `inherit(prefix, labels)` iterates prefix lengths from the
prefix's own length down to 0, looking up the canonical parent at each
length (a `bits+1`-step loop, not a trie walk), merging absent keys and at
most one `cidr:` label. Descendant enumeration for invalidation uses a
per-cluster-id prefix trie.

### 5.4 Local identity manager

A reference-counted set of identities held by local endpoints (`Add`,
`Remove`, `RemoveOldAddNew`), with observers notified on first add and last
remove. It drives per-identity policy computation and `GET /identity/endpoints`.
`RemoveOldAddNew(old, new)` with `old.id == new.id` is a no-op except for
identity 1 (whose labels may have changed).

### 5.5 Kubernetes label sanitization corner cases

- A pod label `io.cilium.k8s.policy.cluster=evil` is dropped (prefix rule)
  and replaced by the real cluster name — pods cannot forge cluster,
  namespace, service-account or namespace-label labels.
- The namespace label copy uses `.` as the path delimiter:
  `io.cilium.k8s.namespace.labels.<nskey>`; `<nskey>` may itself contain
  `.` and `/` and is copied verbatim.
- Service account empty → key absent (an older pod object with the key is
  cleaned).

## 6. Configuration

| Key | Type | Default | Effect |
|---|---|---|---|
| `identity-allocation-mode` | string | `crd` | flowsdn accepts `crd`; `kvstore`, `doublewrite-readkvstore`, `doublewrite-readcrd` are rejected at startup until the kvstore backend ships (**DEVIATION**, inventory 05 defer). Reference flag default is `kvstore` but it is forced to `crd` when `kvstore` is empty and Helm sets `crd`; the observable default is identical. |
| `identity-management-mode` | `agent\|operator\|both` | `agent` | only `agent` accepted (deferred) |
| `identity-allocation-timeout` | duration | 2m | bound on one allocate/release/lookup |
| `identity-allocation-sync-interval` | duration | 5m | periodic re-acquire of held identities |
| `allocator-list-timeout` | duration | 3m | fatal if the initial CID list is not received |
| `identity-change-grace-period` | duration | 5s | wait before an endpoint switches to a new non-init identity (policy maps first) |
| `identity-restore-grace-period` | duration | 30s (10m when `kvstore` is set) | delay before restored local identities/prefixes are released |
| `identity-max-jitter` | duration | 30s | operator-managed CID processing jitter (accepted, ignored: deferred) |
| `enable-well-known-identities` | bool | true | section 4.4 table |
| `fixed-identity-mapping` | map `<id>=<label>` | empty | user-reserved identities; `<id>` MUST be 128..255, else fatal |
| `labels` | string list | empty | extra filter entries (section 4.2) |
| `label-prefix-file` | path | empty | replaces the default filter list |
| `node-labels` | string list | empty | node label filter |
| `enable-node-selector-labels` | bool | false | per-node identities (scope 0x02), `node:` labels on host |
| `policy-cidr-match-mode` | list of `nodes`, `pods` | empty | `nodes`: node prefixes keep CIDR labels and remote nodes get local identities; `pods`: endpoints inherit ipcache CIDR labels; other values fatal |
| `cluster-id` | u32 | 0 | section 4.5 |
| `cluster-name` | string | `default` | section 4.5 |
| `max-connected-clusters` | u32 | 255 | 255 or 511, else fatal |
| `enable-ipv4`, `enable-ipv6` | bool | true / false | decides world 2 vs 9/10 and which host addresses are inserted |
| `identity-gc-interval` (operator) | duration | 15m | GC period; 0 disables |
| `identity-heartbeat-timeout` (operator) | duration | 30m | section 3.6 |
| `identity-gc-rate-interval` / `identity-gc-rate-limit` (operator) | duration / int | 1m / 2500 | deletes per window |
| `cilium-endpoint-gc-interval` (operator) | duration | 30m | 0 disables identity GC too |
| `enable-cilium-endpoint-slice` | bool | false | CES ids count as alive |
| `bpf-map-event-buffers` | map | empty | event buffer for `cilium_ipcache_v2` (debug) |

The ipcache map size (512 000) is a constant in the reference; flowsdn keeps
it constant (no key).

## 7. Failure modes

### 7.1 API server unavailable

- Global allocation fails after the retry budget (≤ 2 m). The endpoint
  contract: an endpoint keeps identity 5 (`reserved:init`, always
  default-deny) until resolution succeeds; identity resolution for global
  labels is non-blocking (a controller retries with backoff, re-running
  every 5 m), and blocking only for labels that resolve locally
  (reserved/local scope). Endpoint state is `waiting-for-identity`; traffic
  is dropped unless policy allows `reserved:init`. Restore of existing
  endpoints proceeds because their identities are re-acquired from the
  informer cache once the list arrives; if the list never arrives the agent
  exits after `allocator-list-timeout`.
- Release never needs the API server. The metadata pipeline continues for
  local identities but the injector waits for Kubernetes cache sync at
  startup.

### 7.2 Identity leak on agent crash

A crashed agent leaves `CiliumIdentity` objects and `CiliumEndpoint`s. The
CEP GC removes CEPs of dead pods; identities then lose their aliveness and
are collected ≥ 30 m + 15 m later (pass 1 + pass 2). Local identities and the
BPF map survive the crash and are restored (3.5); unreferenced ones are
freed after the grace period. No numeric id is reused for different labels
while an old policy-map entry could still reference it: global ids are
pooled from the observed cache; local ids are withheld through restore.

### 7.3 GC deletes an identity still in use on a partitioned node

The node cannot update its CEP, so the operator sees no reference and
deletes the identity. When the partition heals, the node's informer observes
the delete; master-key protection (3.3 step 8) recreates the object with the
same number and labels, and its CEP update marks it alive. Peers that
observed the delete removed the identity from their selector caches and
policy maps and re-add it on the recreate; traffic from that node's pods is
dropped by peers during the window. If meanwhile another agent allocated the
same number for different labels (possible only after the deletion event
reached it), the recreate fails with `AlreadyExists` and the partitioned
node MUST re-resolve its endpoints' identities (they receive a new number);
this is the reference behavior and is accepted.

### 7.4 Map full

`cilium_ipcache_v2` updates failing with `E2BIG`/`ENOSPC` are logged per
prefix and counted (`cilium_bpf_map_ops_total{outcome="fail"}`, map pressure
gauge). The userspace entry is kept; the injector does not retry a map write
by itself, the next change to the prefix rewrites it. Policy for an
unmapped prefix falls back to the covering entry (typically world), so the
failure is fail-closed for allow-by-identity policies and fail-open for
world-allow policies. flowsdn SHOULD alarm at 90 % pressure.

### 7.5 Local identity space exhausted

3.4 step 3: withheld ids are claimed with a warning; otherwise the prefix
fails, is re-enqueued and retried with backoff; policy referencing it drops
traffic until space frees.

### 7.6 Restart mid-operation

Metadata is in memory only; every writer (node manager, watchers, policy,
FQDN) re-populates on start from its own source of truth, so an in-flight
batch lost at crash is replayed. The revision counter restarts at 1 (the
first cycle is unchunked and waiters are skipped by the importer).

### 7.7 Upgrade from the reference

Same CRD, same map name and layout, same checkpoint file, same kvstore
layout: a mixed reference/flowsdn cluster interoperates. Identities
allocated by either side are honored by the other. The only behavioral
difference is the local-identity classification bound in the datapath
(4.5), which only matters above 65 535 live CIDR identities on one node.

## 8. Observability

Metrics (Prometheus names, reference-compatible):

| Metric | Labels | Meaning |
|---|---|---|
| `cilium_identity` (gauge) | `type` ∈ `cluster_local`, `node_local`, `remote_node`, `reserved`, `well_known` | identities in use on the node by type |
| `cilium_identity_label_sources` (gauge) | `source` | identities in use containing a label of that source (an identity counts in several buckets) |
| `cilium_ipcache_errors_total` (counter) | `type` ∈ `upsert`, `delete`; `error` ∈ `invalid_prefix`, `no_such_prefix`, `cannot_overwrite_by_source` | refused ipcache writes |
| `cilium_ipcache_events_total` (counter, disabled by default) | `type` | ipcache writes |
| `cilium_bpf_map_pressure` (gauge) | `map_name="cilium_ipcache_v2"` | fill ratio |
| `cilium_operator_identity_gc_entries` (gauge) | `status` ∈ `alive`, `deleted`; `identity_type` ∈ `crd`, `kvstore` | last GC run counts (note the label is `status`, not `outcome`, in 1.20.1) |
| `cilium_operator_identity_gc_runs` (gauge) | `outcome` ∈ `success`, `fail`; `identity_type` | runs |
| `cilium_operator_identity_gc_latency` (gauge) | `outcome`, `identity_type` | seconds of the last run |

Monitor: agent notification messages (type `MessageTypeAgent`) with
notification types `IPCache entry upserted` and `IPCache entry deleted`,
payload `{"cidr": "10.0.0.5/32", "id": 1000, "old-id": 3, "host-ip":
"192.168.1.10", "old-host-ip": ..., "encrypt-key": 0, "namespace": "default",
"pod-name": "foo"}` (`old-id`, host IPs, namespace and pod omitted when
empty). Emitted from the map-writing listener for every non-shadowed change.

Logs (structured fields): `identity`, `identityLabels`, `labels`, `cidr`,
`clusterID`, `source`, `resource`, `revision`. Every "conflicting
<field> for prefix" warning names both resources. Health: the injector
reports degraded while a chunk keeps failing; the allocator reports
degraded until the initial list arrives.

`cilium-dbg` commands served: `identity get|list`, `ip list`, `bpf ipcache
get|list`, `identity/allocate|release|list` shell commands are not provided
(ADR-0004: no hive shell).

## 9. Test plan

Checklist of reference tests to reproduce (unit unless marked).

**Labels** (`pkg/labels`, `pkg/labelsfilter`, `pkg/k8s`): TestParseLabel,
TestParseSelectLabel, TestLabel_String, TestLabelArraySorted, TestLess,
TestLabelCompare, TestLabelsCompare, TestSortMap, TestMap2Labels,
TestNewFrom, TestMergeLabels, TestRemove, TestRemoveFromSource,
TestLabels_GetFromSource, TestLabels_HasSource, TestLabels_Has, TestHas,
TestLabelArray_Has, TestLabelArray_Intersects, TestK8sLabelArrayLookup,
TestLabelSelectorMatchExpression, TestMatches, TestGetPrintableModel,
TestOutputConversions, TestLabelsK8sStringMap, TestNewLabelCIDR,
TestIPStringToLabel, TestGetCIDRLabels, TestLabelToPrefix,
TestValidateLabels, TestLabelArrayListEquals, TestLabelArrayListMergeSorted,
TestLabelArrayListSort, TestModelsFromLabelArrayListString, FuzzNewLabels;
TestDefaultFilterLabels, TestFilterLabels, TestFilterLabelsDocExample,
TestFilterLabelsByRegex, FuzzLabelsfilterPkg; TestSanitizePodLabels,
TestStripPodLabels, TestGetPodMetadata, TestNamedPortsIdentityLabels,
Test_filterPodLabels. Add: canonical-string golden vectors incl. IPv6 CIDR
encoding and empty values.

**Identity numbering** (`pkg/identity`): TestClusterID,
TestGetClusterIDShift (255 and 511), TestGetAllReservedIdentities,
TestIsReservedIdentity, TestReservedID, TestLocalIdentity,
TestScopeForLabels, TestLookupReservedIdentityByLabels,
TestNewIdentityFromLabelArray, TestAsUint32Slice,
TestIPIdentityPair_PrefixString; `pkg/policy` TestAggregate* for the
aggregate table; `pkg/identity/key` TestGetCIDKeyFromLabels. Add: a table
test of min/max per cluster for both shifts; `is_cidr` by scope byte
mirrored in the BPF harness (privileged).

**Allocator** (`pkg/allocator`, `pkg/identity/cache`,
`pkg/k8s/identitybackend`): TestSelectID, TestPrefixMask, TestLocalKeys,
TestAllocateCached, TestHandleK8sDelete (master-key protection),
TestSyncLocalKeys, TestSyncLocalKeysWithIdentityAllocations,
TestCacheValidators, TestObserveAllocatorChanges, TestWatchRemoteKVStore
(deferred with kvstore); TestAllocator, TestAllocatorReset,
TestAllocateIdentityReserved, TestAllocateLocally, TestLocalAllocation,
TestLocalIdentityCache, TestBumpNextNumericIdentity, TestOldNID,
TestCheckpointRestore, TestEventWatcherBatching, TestObserve,
TestLookupReservedIdentity, TestLookupReservedIdentityByLabels,
TestClusterIDValidator, TestClusterNameValidator, TestNoopAllocateIdentity;
TestGetIdentity (oldest-by-creation lookup), TestSelectK8sLabels;
`pkg/identity/identitymanager` TestIdentityManagerLifecycle,
TestLocalEndpointIdentityAdded/Removed, TestHostIdentityLifecycle. Add: two
fake agents allocating the same labels concurrently converge on lookup and
neither renumbers; AlreadyExists retry; heartbeat annotation removal on
acquire.

**Operator GC** (`operator/identitygc`): TestIdentitiesGC,
TestIdentitiesGC_Disabled, TestIdentityHeartbeatStore,
TestUsedIdentitiesInCESs. Add: preconditions on delete; conflict skipped;
fresh leader waits a full timeout.

**ipcache** (`pkg/ipcache`): TestIPCache, TestIPCacheNamedPorts,
TestIPCacheNamedPortsMoveOnIdentityChange, TestIPCacheShadowing,
TestIPCachePodCIDRShadowing, TestIPCacheShadowedCIDRRevivalUsesCurrentAttributes,
TestIPCachePodCIDREntries, TestIPCacheSubnetCIDRInject,
TestIPCacheCIDRResourceConsolidation(NonCanonical), TestInjectLabels,
TestInjectExisting, TestInjectFailedAllocate, TestHandleLabelInjection,
TestFlatten, TestHighestPrecedenceSource, Test_sortedByResourceIDsAndSource,
Test_metadata_mergeParentLabels, Test_canonicalPrefix, TestFilterMetadataByLabels,
TestRemoveLabelsFromIPs, TestRemoveAPIServerIdentityExternal,
TestResolveIdentity, TestResolveFQDNLabels, TestRequestIdentity,
TestOverrideIdentity, TestUpsertMetadataCIDRGroup,
TestUpsertMetadataInheritedCIDRPrefix, TestUpsertMetadataTunnelPeerAndEncryptKey,
TestUpsertMetadataUpdatedFQDNLabels, TestMetadataRevision,
TestMetadataWaitForRevision, TestUpdateLocalNode, TestIdentityValidator,
TestIPIdentityWatcher(NamedPorts) (deferred with kvstore),
TestIPListEntrySlice*; `pkg/source` TestAllowOverwrite; benchmarks
BenchmarkInjectLabels, BenchmarkManyCIDREntries, BenchmarkManyResources,
BenchmarkIPCacheUpsert*. Add: ordering test that `UpdateIdentities(added)`
completes before the map write and deletes come after; restore from a
dumped map with shared ids.

**Privileged**: map write/read round trip of the value encoding (tunnel
omitted for local node IP; flags), restore dump, map recreate at start.

**E2E**: cilium-cli connectivity suites for CIDR, FQDN, host firewall and
ClusterMesh identity ranges (inventory 15); `cilium-dbg identity list` and
`ip list` output parity against a reference cluster.

## 10. Kernel and platform requirements

Userspace-only area except the map writes: `BPF_MAP_TYPE_LPM_TRIE` with
24-byte keys, `BPF_F_NO_PREALLOC`, `BPF_F_RDONLY_PROG`, batch lookup for the
restore dump (falls back to iteration). No arch-specific behavior; identity
values are host-endian `u32` in the map. Requires `/sys/fs/bpf` mounted and
the tc/globals pin directory shared with Envoy's pod (inventory 11).

## 11. Rust design notes

Crates (dependency order):

- **`flowsdn-labels`**: `Label { source: Source, key: Key, value: Value }`
  with interned strings (`lasso` or `string_cache`), `Labels` (a small map
  keyed by `Key`, `SmallVec`-backed below ~8 entries), `LabelArray` (sorted
  by key), `canonical_string()` / `parse_canonical()`, CIDR key
  encode/decode (`ipnet::IpNet`), `LabelFilter` (compiled `regex::RegexSet`
  plus per-entry anchors; default list as a `const`), `PodLabelSynthesizer`
  (namespace, service account, cluster, named ports). Serde for the REST and
  checkpoint shapes. `Source` is an enum with `Display` giving the exact
  names and `Ord` giving section 4.6.
- **`flowsdn-identity`**: `NumericIdentity(u32)` newtype with
  `scope()`, `cluster_id(shift)`, `aggregate_for(local_cluster)`,
  `is_reserved()`, reserved and well-known tables as `const`/`LazyLock`,
  `ClusterLayout { bits, shift, min(c), max(c) }` computed once from config,
  `Identity { id, labels, array }`, `IdentityChange { Sync | Upsert | Delete }`
  stream, `LocalIdentityCache` (section 3.4), `IdentityManager` (5.4),
  checkpoint read/write, and the `IdentityBackend` trait:
  `list_and_watch()`, `get(key)`, `get_by_id()`, `create(id, key)`,
  `acquire(id, key)`, `delete(id)`; `CrdBackend` on `kube-rs`
  (`kube::runtime::watcher` + `reflector` with a secondary index on the
  canonical string; typed `CiliumIdentity` via `kube-derive` with
  `#[serde(rename = "security-labels")]`). `KvstoreBackend` is a stub that
  fails construction. The allocation protocol (3.3) lives above the trait in
  `GlobalAllocator`, so the kvstore backend later only supplies keys and
  locks.
- **`flowsdn-ipcache`**: `PrefixCluster { prefix: IpNet, cluster: u32 }`;
  metadata store `HashMap<PrefixCluster, PrefixInfo>` plus
  `prefix_trie::PrefixMap<IpNet, ()>` per cluster id for descendant
  enumeration (`ipnet` for canonicalization); `IPMetadata` enum
  `{ Labels, Override, TunnelPeer, EncryptKey, RequestedIdentity,
  EndpointFlags, AssignedIdentity }`; the flattened view cached with
  invalidation; the ipcache table itself is a `flowsdn-table` table keyed by
  `PrefixCluster` (ADR-0004) whose `watch()` feeds the BPF reconciler, the
  monitor notifier and the optional NPHDS feed; the injector is one tokio
  task woken by a `Notify`, with `revision` as a `tokio::sync::watch<u64>`
  (`WaitForRevision` = `wait_for(|r| *r >= rev)` under a timeout).
  `IdentityUpdater` is a trait implemented by the policy crate; the
  `completion` is a `oneshot`. BPF writes go through the maps crate's
  `LpmTrie<IpcacheKey, RemoteEndpointInfo>` (`#[repr(C, packed)]` key).
- Operator GC lives in `flowsdn-operator` using the same `kube-rs`
  reflectors and a token-bucket limiter (`governor`).

No Hive (ADR-0004): construction order is explicit — labels filter config →
identity layout → local caches → CRD backend + global allocator → ipcache →
policy engine registers as `IdentityUpdater` → node manager / watchers start
writing. Startup fences: `initial_cid_list`, `k8s_caches_synced`,
`endpoints_restored` (used by the grace-period release).

## 12. Open decisions

1. **Resolved (#64, ADR-0011): retain duplicate identities until GC.**
   Do not actively renumber live endpoints to prefer the oldest duplicate.
   Normal reference-counted release and allocator GC reclaim unused entries.
2. **kvstore backend timing.** Ship the `IdentityBackend` stub now and the
   `etcd-client` backend with the ClusterMesh spec (recommended), or never
   and require CRD mode plus clustermesh-apiserver's CRD mirroring for
   meshes? Depends on whether ClusterMesh spec needs kvstore identities.
3. **Resolved (#66, ADR-0011): scope-byte classification.**
   Preserve the full supported 24-bit local index range and §4.5 deviation;
   the datapath spec explicitly references this contract.
4. **Assigned-identity resource ids.** Section 3.10 uses `<source>//<ip>`;
   alternative is one resource per writer (`ep/<ns>/<pod>` for CEP, which
   also enables `DeleteOnMetadataMatch` by ns/name without a k8s-metadata
   lookup). Recommendation: per-writer resource ids
   (`ep/<ns>/<name>`, `pod/<ns>/<name>`, `kvstore//<ip>`); unobservable.
5. **ipcache map size.** Constant 512 000 as in the reference, or a config
   key (`bpf-ipcache-map-max`) with the same default? Recommendation: add
   the key; no compatibility cost.
6. **Resolved (#69, ADR-0011): well-known identities default on.**
   `enable-well-known-identities=true` follows §4.4 and the config catalogue.
   Explicit false disables the shortcut; no inventory suggestion overrides it.
7. **Envoy `ipcache_name`.** Confirm against the cilium/proxy image that
   the bootstrap field must name `cilium_ipcache_v2` (section 4.8); if the
   proxy hard-codes the legacy name, a symlink pin or NPHDS mode is needed.
8. **GC and CES.** With CES enabled the reference still requires the CEP
   GC interval to be non-zero; keep that coupling or allow identity GC with
   CES only? Recommendation: keep, until CES is specified.
9. **Fixed identity validator.** The reference validates `128..255` at flag
   parse; should flowsdn also reject a `--fixed-identity-mapping` label
   that collides with a reserved name (`host`, `world`, ...)? Recommended
   yes (fatal); the reference silently overrides.
