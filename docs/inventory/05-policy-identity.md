# Policy and security identities — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/policy/**`,
`pkg/labels/**`, `pkg/labelsfilter/`, `pkg/identity/**`, `pkg/allocator/**`,
`pkg/ipcache/**`, `pkg/source/`, `pkg/maps/policymap/`, `pkg/k8s/network_policy.go`,
`pkg/k8s/cluster_network_policy.go`, `pkg/k8s/apis/cilium.io/utils/`,
`pkg/k8s/apis/cilium.io/v2/{cnp,ccnp,cidrgroups}_types.go`, `pkg/k8s/identitybackend/`,
`operator/identitygc/`, `operator/pkg/ciliumidentity/`, `bpf/lib/policy.h`,
`bpf/lib/policy_log.h`, `bpf/lib/identity.h` (read for the datapath contract only).

Line counts are `wc -l` of non-test Go unless noted; `_test.go` given separately.

## Purpose

This area turns labels into 32-bit security identities, distributes those
identities cluster-wide (CRD or kvstore), maps every IP prefix the datapath can
see to an identity (ipcache), and compiles the policy language (Kubernetes
NetworkPolicy, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy,
ClusterNetworkPolicy from network-policy-api v1alpha2, CiliumCIDRGroup, static
files) into per-endpoint BPF policy-map entries keyed by
`(identity, direction, protocol, port-prefix)`. It also owns incremental
recomputation when identities appear or disappear, the precedence model for
allow/deny/pass across tiers, the L4→L7 redirect decision, policy verdict
notifications, and the operator-side identity garbage collection.

## Components

| Path | Lines (non-test / test) | Purpose |
|---|---|---|
| `pkg/policy/*.go` | 8164 / 21034 | Repository, rule resolution, `L4Filter`/`PerSelectorPolicy`, `SelectorCache`, `mapState` (LPM-trie indexed policy map computation), precedence/pass logic, aggregate identities, port-range masking, proxy IDs, flow lookup |
| `pkg/policy/api` | 5659 / 2779 | Policy language types (`Rule`, `IngressRule`, `EgressRule`, deny variants, `PortRule`, `L7Rules`, `CIDRRule`, `FQDNSelector`, `ICMPRule`, `Groups`, `Service`, `EndpointSelector`, entities) and `Sanitize()` validation; 2494 lines are generated deepcopy/deepequal |
| `pkg/policy/types` | 2281 / 525 | Intermediate representation: `PolicyEntry`, `Tier`, `Verdict`, `Priority`/`Precedence`, `Key`/`LPMKey`, `MapStateEntry`, `AuthRequirement`, compiled `Selector`s (`LabelSelector`, `CIDRSelector`, `FQDNSelector`), `Requirements` |
| `pkg/policy/k8s` | 1572 / 1242 | Watcher for CNP/CCNP/KNP/KCNP/CiliumCIDRGroup resources, `toServices` resolution from statedb services, CIDRGroup → ipcache metadata |
| `pkg/policy/cell` | 899 / 245 | Hive wiring: repository, `Importer` (serialised policy updates), `IdentityUpdater` (batched identity → selector-cache → policy-map pipeline) |
| `pkg/policy/compute` | 541 / 268 | Per-identity `SelectorPolicy` computation queue and statedb `Table[Result]` (replaces the old policy cache / "distillery") |
| `pkg/policy/commands` | 1083 / 0 | `cilium-dbg shell` commands `policy/mapstate/{entries,topk,stage}` and mapstate diffing |
| `pkg/policy/correlation` | 150 / 914 | Hubble flow → matched rule labels (`IngressAllowedBy` etc.) |
| `pkg/policy/directory` | 370 / 136 | Static CNP YAML files from `--static-cnp-path` (fsnotify) |
| `pkg/policy/cookie` | 231 / 196 | Generic cookie bakery: allocates the 32-bit `cookie` written into policy entries for `log.value` correlation |
| `pkg/policy/utils` | 195 / 685 | JSON/YAML rule parsing used by API and CLI |
| `pkg/policy/groups/aws` | 154 / 0 | `toGroups.aws` expansion via EC2 `DescribeNetworkInterfaces`/`DescribeInstances` |
| `pkg/policy/trafficdirection` | 39 / 0 | `Ingress=0`, `Egress=1`, `Invalid` |
| `pkg/labels` | 2358 / 1841 | `Label{Key,Value,Source}`, `Labels` map, `LabelArray` sorted slice, `OpLabels` (identity vs information labels), CIDR label encoding, validation |
| `pkg/labelsfilter` | ~370 / fuzz+unit | `--labels` / `--label-prefix-file` include/exclude regex filtering |
| `pkg/identity` | 1004 / 581 | `NumericIdentity`, scopes, reserved and well-known identities, `Identity`, `ScopeForLabels` |
| `pkg/identity/cache` | 1888 / 1224 | `CachingIdentityAllocator`: global (CRD/kvstore/double-write) plus two local allocators (CIDR scope, remote-node scope), checkpoint/restore, remote-cluster caches |
| `pkg/identity/identitymanager` | 304 / 205 | Ref-counted set of identities in use by local endpoints; observers drive per-identity policy computation |
| `pkg/identity/{key,basicallocator,api,model,cell}` | 384 / 340 | kvstore key encoding of a label set, simple ID pool, REST handlers for `/identity*` |
| `pkg/allocator` | 1835 / 905 | Backend-agnostic distributed ID allocator (master/slave keys, local refcounts, remote caches, GC hooks) |
| `pkg/ipcache` | 3102 / 3488 | prefix → identity mapping, metadata layering by source/resource, label injection controller, legacy `Upsert`, kvstore sync |
| `pkg/ipcache/{types,api,restore,cell}` | 910 / 115 | `ResourceID`/`ResourceKind`, `TunnelPeer`, `EncryptKey`, `RequestedIdentity`, `EndpointFlags`, REST `/ip`, restore of CIDR identities from the BPF map |
| `pkg/source` | ~110 | Source enum and precedence |
| `pkg/maps/policymap` | ~800 | BPF map `cilium_policy_v3_<epid>` (LPM trie) and `cilium_policystats` (per-CPU hash), call maps |
| `pkg/k8s/network_policy.go`, `cluster_network_policy.go` | ~330 + ~400 | k8s `NetworkPolicy` and network-policy-api `ClusterNetworkPolicy` → `types.PolicyEntries` |
| `pkg/k8s/apis/cilium.io/utils` | ~350 | `ParseToCiliumRule`: namespace/cluster label injection for CNP/CCNP, `GetPolicyLabels` |
| `pkg/k8s/apis/cilium.io/v2/{cnp,ccnp,cidrgroups}_types.go`, `types.go:CiliumIdentity` | ~500 | CRD Go types (`v2alpha1.CiliumCIDRGroup` is `+kubebuilder:deprecatedversion`) |
| `pkg/k8s/identitybackend` | ~450 | CRD allocator backend (`CiliumIdentity` objects, `io.cilium.heartbeat` annotation) |
| `operator/identitygc` | ~600 | CRD and kvstore identity GC with heartbeat store and rate limiting |
| `operator/pkg/ciliumidentity` | ~1200 | Operator-managed identity controller (`--identity-management-mode=operator|both`) |

Approximate total for the area: 33k non-test Go, 36k test Go.

## Features

- **Label model.** A label is `source:key=value`. Sources: `k8s`, `container`
  (legacy, via `cni`), `reserved`, `cidr`, `cidrgroup`, `fqdn`, `node`, `gen`
  (agent-generated, e.g. named ports), `directory`, `unspec` (default when the
  source is omitted), and the selector-only wildcard source `any`. A key starting
  with `$` is rewritten to source `reserved`. Identity-relevant labels are
  filtered from the pod's labels by `--labels` (regex prefixes; a leading `!`
  excludes) or `--label-prefix-file`; the default list includes all `reserved:*`,
  `io.kubernetes.pod.namespace`, `io.cilium.k8s.namespace.labels`,
  `app.kubernetes.io`, `io.cilium.k8s.policy.cluster`,
  `io.cilium.k8s.policy.serviceaccount`, and excludes `io.kubernetes`,
  `kubernetes.io`, `statefulset.kubernetes.io/pod-name`,
  `apps.kubernetes.io/pod-index`, `batch.kubernetes.io/job-completion-index`,
  `batch.kubernetes.io/controller-uid`, `*beta.kubernetes.io`, `k8s.io`,
  `pod-template-generation`, `pod-template-hash`, `controller-revision-hash`,
  `controller-uid`, `annotation.*`, `etcd_node`, `topology.kubernetes.io`.
  `--node-labels` is the equivalent filter for node labels (`node:` source).
  Labels that fail the filter become "information labels" kept on the endpoint
  but not part of the identity (`labels.OpLabels`).
- **Identity from pod.** `k8s.GetPodMetadata` → `SanitizePodLabels`: strips any
  pod-supplied `io.cilium.k8s.*` keys, adds every namespace label as
  `io.cilium.k8s.namespace.labels.<key>=<value>`, adds
  `io.kubernetes.pod.namespace=<ns>`, `io.cilium.k8s.policy.serviceaccount=<sa>`
  (removed if the SA is empty), `io.cilium.k8s.policy.cluster=<cluster-name>`.
  Named container ports become `gen:io.cilium.k8s.named-ports.<i>` labels.
  Result passes `labelsfilter.Filter`, then `AllocateIdentity`.
- **Reserved identities** (`pkg/datapath/types/types_generated.go`, mirrored in
  `bpf/lib/identity.h`): see table in Data model. Identities 100–115 are
  **well-known** identities (kube-dns, EKS kube-dns, CoreDNS, cilium-operator,
  EKS CoreDNS, each in a variant with and without the
  `io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name` label) enabled by
  `--enable-well-known-identities` (cell default `true`). 128–255 are
  **user-reserved** via `--fixed-identity-mapping=<id>=<label>` selected by pod
  label `io.cilium.fixed-identity=<label>`.
- **Identity scopes** (top 8 bits): `0x00` global/reserved, `0x01000000` local
  (CIDR/FQDN/CIDRGroup/ingress), `0x02000000` remote-node (per-node identities,
  only with `--enable-node-selector-labels` or `--policy-cidr-match-mode=nodes`).
  Global allocation range for cluster 0 is 256..65535; ClusterMesh cluster N
  gets `N<<shift .. (N+1)<<shift - 1` where `shift = 24 - log2(ClusterIDMax+1)`
  (16 for the default `--max-connected-clusters=255`, 15 for 511). Only 24 bits
  travel on the wire (`NumericIdentityBitlength = 24`, VNI); local identities
  never leave the node.
- **Identity allocation modes.** `--identity-allocation-mode=crd` (default,
  `CiliumIdentity` CRD named by numeric id, labels in `security-labels`),
  `kvstore` (`cilium/state/identities/v1/id/<id>` master keys and
  `.../value/<sorted-labels>/<node-suffix>` slave keys, lease-TTL protected),
  `doublewrite-readkvstore`, `doublewrite-readcrd` (migration modes). 16 alloc
  attempts, 5 min local-key resync. `--identity-management-mode=agent|operator|both`
  lets cilium-operator create CIDs from Pod+Namespace events. Local identities
  are refcounted per node and checkpointed to `local_allocator_state.json`;
  restored on start with a `--identity-restore-grace-period` (30 s k8s, 10 m
  kvstore) during which withheld IDs are not reused. `--identity-change-grace-period`
  (5 s) delays endpoint identity swaps so policy maps are programmed first.
- **CiliumIdentity GC (operator).** `--identity-gc-interval` (default
  `KVstoreLeaseTTL`, 15 m), `--identity-heartbeat-timeout` (2× that),
  `--identity-gc-rate-interval=1m`, `--identity-gc-rate-limit=2500`. A CID not
  referenced by any CiliumEndpoint (or CiliumEndpointSlice) is first annotated
  `io.cilium.heartbeat=<RFC3339>`; on a later round past the timeout it is
  deleted. kvstore mode GCs orphan master keys and stale locks.
- **ipcache.** Every prefix known to the node maps to `(identity, tunnel
  endpoint, encrypt key, flags, k8s metadata)`. New-style metadata API:
  `UpsertMetadata(prefix, source, resourceID, labels|TunnelPeer|EncryptKey|RequestedIdentity|EndpointFlags|override)`
  layered per resource, flattened by source precedence, then a controller
  (`ipcache-inject-labels`) allocates local identities, pushes identity adds to
  the policy engine, waits for policy maps, then updates the BPF map and
  releases old identities. Legacy `Upsert(ip, hostIP, key, k8sMeta, Identity)`
  remains for kvstore/clustermesh and endpoints. Sources (highest first):
  `kube-apiserver`, `local`, `kvstore`, `custom-resource`, `k8s`, `clustermesh`,
  `directory`, `api`, `generated`, `restored`, `unspec`.
- **CIDR identities.** A prefix with no in-cluster labels gets
  `cidr:<prefix>` (IPv6 `:` rendered as `-`, leading `0-`/trailing `-0`) plus
  `reserved:world` (or `world-ipv4`/`world-ipv6` in dual-stack) and a local
  identity. `resolveLabels` drops `cidr:`/`fqdn:`/`cidrgroup:` labels from
  in-cluster prefixes unless `--policy-cidr-match-mode=nodes` for nodes, and
  drops `node:` labels unless per-node labels are enabled. Selectors match CIDR
  identities by prefix containment (`CIDRSelector`, `Requirement.GetKeyPrefix`).
- **Policy language** (`api.Rule`): `endpointSelector` xor `nodeSelector`;
  `ingress[]`, `ingressDeny[]`, `egress[]`, `egressDeny[]`; `labels`,
  `description`, `enableDefaultDeny{ingress,egress}`, `log{value}`.
  Ingress peers: `fromEndpoints`, `fromRequires`, `fromCIDR`, `fromCIDRSet`
  (`cidr` | `cidrGroupRef` | `cidrGroupSelector`, `except[]`), `fromEntities`,
  `fromGroups`, `fromNodes`. Egress peers add `toServices`
  (`k8sService{serviceName,namespace}` | `k8sServiceSelector{selector,namespace}`),
  `toFQDNs` (`matchName` | `matchPattern`, `*`/`**` wildcards), `toGroups`,
  `toNodes`. L4: `toPorts[]{ports[]{port,endPort,protocol}, rules{http[],dns[]},
  terminatingTLS, originatingTLS, serverNames[], listener{envoyConfig{kind,name},
  name, priority}}`; deny variants carry `ports` only (no L7). `icmps[]{fields[]{family,type}}`
  needs `--enable-icmp-rules` and cannot be combined with `toPorts`.
  `authentication{mode: disabled|required|test-always-fail}`. Entities: `all`,
  `world`, `world-ipv4`, `world-ipv6`, `cluster`, `cluster-mesh`, `host`,
  `init`, `ingress`, `unmanaged`, `remote-node`, `health`, `none`,
  `kube-apiserver`. Limits: 40 ports per `toPorts`, 40 ICMP fields; DNS rules
  need port 53 and no ranges; L7 only on TCP except DNS; DNS/`listener` not on
  ingress; port ranges use `endPort`; CIDR masks must be contiguous; allow CIDR
  must contain its `except`s. `fromNodes`/`toNodes` require
  `--enable-node-selector-labels`. `toServices` in the same rule as `toPorts`
  is rejected for L3 members that cannot combine.
- **Default deny.** A rule with `enableDefaultDeny.ingress=false` (needs
  `--enable-non-default-deny-policies`) contributes allows without switching the
  subject to default-deny. If a subject has rules but none is default-deny, a
  wildcard allow is synthesised (`reserved:io.cilium.policy.derived-from=allow-any-ingress`).
  `--allow-localhost=auto|always|policy` synthesises `allow-localhost-ingress`
  from `reserved:host`. `reserved:init` endpoints are always default-deny.
- **Enforcement modes.** `--enable-policy=default|always|never`; `always` forces
  default-deny for every endpoint, `never` disables everything. Host identity is
  skipped unless `--enable-host-firewall`. `--policy-audit-mode` (global) or the
  per-endpoint option `PolicyAuditMode=Enabled` (`cilium-dbg endpoint config`)
  forwards packets that would be dropped and sets `audited=1` in the verdict
  notification.
- **Deny semantics.** Deny rules have no L7, no auth, no proxy port. At equal
  precedence deny beats allow regardless of L4 specificity; a broader deny
  (e.g. L3-only) still beats a narrower allow at the same tier/priority. In the
  tiered model (KCNP) a higher tier's Accept beats a lower tier's Deny; `Pass`
  delegates to the next tier.
- **Tiers and priorities** (`types.Tier`): `Admin=100`, `Normal=200`
  (CNP/CCNP/KNP), `Baseline=250`, `DefaultPolicy=255`. Priority within a tier is
  a float (`spec.priority + ruleIndex/100` for KCNP, 0 for others).
  `computeTierPriorities` packs tiers into the 24-bit `Priority` space (10-level
  round-up per tier, extra room per `Pass` rule); `Precedence = (LowestPriority
  - priority) << 8 | verdictByte` with `deny=255`, `allow=1`, proxy redirect
  `2..254` (listener priority), `pass=0`. Higher `Precedence` wins.
- **Kubernetes NetworkPolicy translation** (`ParseNetworkPolicy`): all rules
  `Tier=Normal`, `Verdict=Allow`, `DefaultDeny=true`; subject =
  `podSelector` + `k8s:io.kubernetes.pod.namespace=<ns>`; `ipBlock` →
  `CIDRRule{cidr, except}`; `podSelector` alone → same namespace;
  `namespaceSelector` keys become `io.cilium.k8s.namespace.labels.<key>` (an
  empty selector becomes `io.kubernetes.pod.namespace Exists`); both → AND.
  `k8s:io.cilium.k8s.policy.cluster=<cluster>` is added unless present or the
  cluster name is the any-cluster value. Ports default to TCP, `port="0"` if
  unset, `endPort` honoured, named ports passed as strings. `policyTypes`: an
  empty ingress list with `Ingress` present (or `Egress` absent) yields an
  ingress default-deny entry; likewise egress. Policy labels:
  `k8s:io.cilium.k8s.policy.derived-from=NetworkPolicy`, `.name`, `.namespace`,
  `.uid` (name overridable via the policy-name annotation).
- **CNP/CCNP translation** (`ParseToCiliumRule`): selector keys get the `k8s:`
  prefix unless already sourced (`reserved:`, `any:`); the policy's namespace is
  added to `endpointSelector` and `fromEndpoints`/`toEndpoints` unless the
  selector already names a namespace, a namespace-meta label, or `reserved:init`;
  CCNP (no namespace) adds `k8s:io.kubernetes.pod.namespace Exists` to endpoint
  selectors so `{}` does not select host/world; the cluster label is added by
  default; `nodeSelector` keys are prefixed `node:` and target `reserved:host`.
  `spec` and `specs[]` both allowed; each resource is one `ResourceID`
  (`cnp/<ns>/<name>`, `ccnp//<name>`). `toServices` is resolved by the watcher
  from statedb `Service`/`Backend` tables into generated `toCIDRSet` entries and
  re-resolved on service change. `toGroups` are expanded to derivative CNPs by
  the operator (AWS security-group ids/names/tags, `extgrp.cilium.io/` labels).
- **CiliumCIDRGroup** (`v2`, `spec.externalCIDRs[]`): the watcher turns each
  CIDR into ipcache metadata (source `generated`, `ResourceKindCIDRGroup`) with
  labels `cidrgroup:<key>=<value>`, an encoded `<key>+<value>` form, and
  `cidrgroup:io.cilium.policy.cidrgroupname/<name>` so `cidrGroupRef` and
  `cidrGroupSelector` select the resulting local identities.
- **AdminNetworkPolicy / BaselineAdminNetworkPolicy: not supported.** The only
  references are under `vendor/`. Instead v1.20 implements the successor API
  `policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy` ("KCNP"):
  `spec.tier=Admin|Baseline`, `spec.priority`, `subject{namespaces|pods}`,
  rules with `action=Accept|Deny|Pass`, peers `pods`, `namespaces`, `nodes`
  (egress, needs node selector labels), `networks` (CIDRs), `domainNames`
  (egress Accept only, needs L7 proxy; auto-adds a DNS-visibility rule to
  `k8s-app=kube-dns` ports `dns`/`dns-tcp`), protocols `TCP|UDP|SCTP{destinationPort{number|range}}`
  or `destinationNamedPort`. Rules are `DefaultDeny=false`; a Deny with no
  peer becomes a wildcard deny. ipcache `ResourceKindKCNP`.
- **Host firewall.** `--enable-host-firewall`; host policies use `nodeSelector`
  (CCNP). L7 on host ingress is rejected. `--enable-node-selector-labels` +
  `--node-labels` make node labels part of host/remote-node identities
  (remote nodes then get per-node identities in scope `0x02`).
- **L7 handoff.** `createL4Filter` picks the parser: TLS (`terminatingTLS`,
  `originatingTLS` or `serverNames`), DNS (`rules.dns`), HTTP (`rules.http`, TCP
  only), CRD (`listener`). Any parser, an explicit `authentication`, a non-allow
  verdict, or a non-zero priority makes a `PerSelectorPolicy`. Redirect types:
  DNS (agent's own proxy) and Envoy. Listener priorities: HTTP 101, TLS 116,
  DNS 121, CRD 126 (max 126). Default-allow rules with L7 get a wildcard L7 rule
  appended so unmatched traffic still passes. Parsing of L7 rules belongs to the
  proxy area.
- **Selector cache / incremental updates.** Two caches per repository: peer
  selectors and subject selectors. `UpdateIdentities(added, deleted)` recomputes
  only the affected selectors (namespace-indexed shortcut), notifies users
  (`L4Filter`s), which accumulate `MapChanges`; endpoints consume them and apply
  deltas to the BPF map without a regeneration. Identity additions are applied
  to policy maps before the ipcache map is updated; deletions after.
- **Policy revision and regeneration.** Repository `revision` (atomic u64) bumps
  on every `ReplaceByResource`. Each endpoint tracks `desiredPolicyRevision`
  and realized `policyRevision`; unaffected endpoints have their revision
  advanced without regeneration. `cilium-dbg policy wait <rev>`, CNP status
  `localPolicyRevision`. Regeneration reasons include `PolicyUpdate`,
  `LabelsUpdate`, `EndpointInit/Restore`, `DaemonConfigUpdate`,
  `PeriodicRegeneration`; levels `RegenerateWithoutDatapath` vs datapath
  rewrite. `--policy-trigger-interval` (1 s) batches full recomputes;
  `--policy-queue-size` (100).
- **Policy map sizing.** `--bpf-policy-map-max` default 16384 (min 256, max
  65536) per endpoint; `--bpf-policy-stats-map-max` 65536 (rounded down to a
  multiple of possible CPUs); `--bpf-policy-map-full-reconciliation-interval`
  re-syncs desired vs realised; `--enable-endpoint-lockdown-on-policy-overflow`
  drops all traffic of an endpoint whose desired map exceeds capacity (otherwise
  adds fail, are retried after deletes, the `sync-policymap` controller keeps
  retrying, and `ErrPolicyEntryMaxExceeded` is surfaced; missing deny keys mean
  fail-open for that endpoint). Map pressure is exported as a metric.
- **Verdict notifications.** `--bpf-events-policy-verdict-enabled`; per-endpoint
  `PolicyVerdictNotification` option filter (ingress/egress bits). Message type
  `policy-verdict` (5), 40-byte header carrying remote identity, verdict,
  dport, proto, `dir:2 ipv6:1 match_type:3 audited:1 l3:1`, `auth_type`,
  `cookie`. Match types: none 0, L3-only 1, L3/L4 2, L4-only 3, all 4,
  L3+proto 5, proto-only 6. `--policy-accounting` (default true) counts
  packets/bytes per `(endpoint, direction, identity, proto, port-prefix)` in
  `cilium_policystats`.
- **Tooling.** `cilium-dbg policy get|selectors|wait`, `cilium-dbg bpf policy
  get|list|add|delete`, `cilium-dbg identity get|list`, `cilium-dbg preflight
  migrate-identity` (kvstore → CRD), shell commands `policy/mapstate/entries`,
  `topk`, `stage`. The old `cilium policy trace` CLI is gone at this tag;
  `policy.LookupFlow` remains for tests/scripts. Hubble policy correlation adds
  the matching rules (labels + `log` strings) to flows.
- **Static policy files.** `--static-cnp-path=<dir>`: `*.yaml` CNPs, source
  `directory`, `ResourceKindFile`.

## Data model

**Label / Labels / LabelArray** (`pkg/labels`): `Label{Key, Value, Source,
cidr *netip.Prefix}`; `Labels = map[string]Label` keyed by `Key`; `LabelArray`
is a sorted slice used for matching and hashing; kvstore form
`source:key=value;` concatenated (`FormatForKVStore`, `SortedList`).
`LabelSelectorRequirement` operators `In`, `NotIn`, `Exists`, `DoesNotExist`
over keys with source prefix; `any:` matches every source.

**NumericIdentity** (`uint32`): bits 0–15 identity, 16–23 cluster id, 24–31 scope.

| Numeric | Name (`reserved:`) | Meaning |
|---|---|---|
| 0 | unknown | invalid / not yet determined |
| 1 | host | local host (all node IPs) |
| 2 | world | outside the cluster (single-stack) |
| 3 | unmanaged | pods not managed by Cilium |
| 4 | health | cilium-health endpoint |
| 5 | init | endpoint whose labels are not yet known |
| 6 | remote-node | any other node in this or a meshed cluster |
| 7 | kube-apiserver | remote node(s) hosting kube-apiserver backends (labels `kube-apiserver` + `remote-node`) |
| 8 | ingress | source IP of Cilium Ingress/Gateway proxies |
| 9 | world-ipv4 | world, IPv4 only (dual-stack) |
| 10 | world-ipv6 | world, IPv6 only (dual-stack) |
| 11 | aggregate-cluster | wildcard for all global identities of the local cluster (policy-map aggregation only) |
| 12 | aggregate-cluster-mesh | wildcard for identities of other clusters |
| 13 | aggregate-world | wildcard for local-scope (CIDR/FQDN) identities |
| 14 | aggregate-remote-node | wildcard for scope-0x02 node identities |
| 100–115 | well-known | 102 kube-dns, 103 eks-kube-dns, 104 coredns, 105 cilium-operator, 106 eks-coredns; 110–114 the same with the namespace `metadata.name` label; 100, 101, 107, 108, 109, 115 deprecated (etcd-operator, kvstore) |
| 128–255 | user reserved | `--fixed-identity-mapping` |
| 256–65535 | cluster-local global | allocated (cluster 0) |
| `N<<shift ..` | ClusterMesh | per remote cluster N |
| `0x01000001..0x01FFFFFF` | local (CIDR/FQDN/CIDRGroup/ingress) | never on wire; BPF `CIDR_IDENTITY_RANGE_END` is `(1<<24)+(1<<16)-1` |
| `0x02000001..0x02FFFFFF` | per-node remote-node identities | with node selector labels |

There is no reserved identity for encrypted overlay at this tag; that is a
datapath mark, not an identity. `aggregateFor(nid)`: identities < 100 aggregate
to 0; scope 0x02 → 14; scope 0x01 → 13; else by cluster id → 11 or 12.
Aggregates aggregate to themselves. `AllAggregates = {0, 14, 13, 11, 12}`.

**Identity**: `{ID, Labels, LabelArray, ReferenceCount}`; `IdentityMap =
map[NumericIdentity]LabelArray`. `ScopeForLabels`: remote-node label → 0x02;
reserved+ingress → 0x01; all labels from `cidr`/`fqdn`/`reserved`/`cidrgroup`
→ 0x01; anything else → global.

**CiliumIdentity CRD** (`cilium.io/v2`, cluster-scoped): `metadata.name =
"<numeric id>"`, `security-labels: map[string]string` (`source:key: value`),
annotation `io.cilium.heartbeat`. kvstore: `cilium/state/identities/v1/id/<id>`
→ label string; `.../value/<label string>/<node>` slave keys; remote clusters
under `cilium/cache/identities/v1/<cluster>/...`.

**Policy IR** (`types.PolicyEntry`): `{Tier, Priority float64, Authentication,
Log, Subject *LabelSelector, L3 Selectors, L4 api.PortRules, Labels,
DefaultDeny, Verdict (Allow|Deny|Pass), Ingress, Node}`. `PolicyUpdate{Rules,
Resource ResourceID, Source, ProcessingStartTime, DoneChan chan<- revision}`.
`ResourceID = "<kind>/<namespace>/<name>"`, kinds `ccnp`, `cidrgroup`, `cnp`,
`daemon`, `ep`, `file`, `netpol`, `kcnp`, `node`.

**Compiled policy**: `selectorPolicy{Revision, L4Policy{Ingress, Egress
L4DirectionPolicy}, IngressPolicyEnabled, EgressPolicyEnabled}`;
`L4DirectionPolicy{PortRules L4PolicyMaps (one map per tier), tier base
priorities}`; `L4Filter{Port, EndPort, PortName, Protocol, U8Proto, Ingress,
wildcard CachedSelector, PerSelectorPolicies map[CachedSelector]*PerSelectorPolicy,
RuleOrigin}`; `PerSelectorPolicy{L7Parser, L7Rules, TerminatingTLS,
OriginatingTLS, ServerNames, Listener, ListenerPriority, Priority, Verdict,
Authentication, isRedirect}`. `EndpointPolicy = selectorPolicy.DistillPolicy(owner,
redirects)` = `{policyMapState, Redirects map[proxyID]port, selectors snapshot}`.

**Policy map state** (`types.Key`, 8 bytes): `LPMKey{bits u8 (bit7 direction,
bits0-4 port prefix len), Nexthdr u8proto, DestPort u16}` + `Identity u32`.
`MapStateEntry{Precedence u32, ProxyPort u16, AuthRequirement u8 (bit7 =
explicit), Cookie u32, invalid}`. `mapState` indexes entries in a `bitlpm.Trie`
over `LPMKey` (direction 1 bit, proto 8 bits, port up to 16 bits) with an
`IDSet` per node, plus `byId` index. Port ranges are expanded with
`PortRangeToMaskedPorts` into CIDR-like `(port, prefixLen)` keys.

**BPF policy map** `cilium_policy_v3_<endpoint id>` (`BPF_MAP_TYPE_LPM_TRIE`,
`max_entries` = `--bpf-policy-map-max`, pinned per endpoint under
`/sys/fs/bpf/tc/globals/`), must match `struct policy_key`/`policy_entry` in
`bpf/lib/policy.h`:

```
key   (12 B): prefixlen u32 | sec_label u32 | egress u8 | protocol u8 | dport be16
              prefixlen = 40 (identity 32 + direction 8) + 0 | 8 (proto) | 8+portbits
value (12 B): proxy_port be16 | flags u8 (bit0 deny, top 5 bits lpm_prefix_length 0..24)
              | auth_type:7 has_explicit_auth_type:1 | precedence u32 | cookie u32
```

Lookup (`__policy_can_access`): full-prefix lookup with the remote identity,
then with `aggregate_for_identity(remote)`, then with 0 if both miss. The
aggregate entry wins if its `precedence` is higher, or equal with a longer
`lpm_prefix_length`; otherwise the specific entry. Then `deny` → `DROP_POLICY_DENY`;
auth type is inherited from the equal-precedence broader entry when the chosen
one has no explicit auth; `auth_type != 0` → `DROP_POLICY_AUTH_REQUIRED` unless
the auth map says authenticated. No entry → `DROP_POLICY`. With
`--enable-icmp-rules` the ICMP type is placed in `dport`.

**Policy stats map** `cilium_policystats` (`BPF_MAP_TYPE_PERCPU_HASH`):
key `{endpoint id u16, prefix_len u8, egress u8, sec_label u32, protocol u8,
dport be16}`, value `{packets u64, bytes u64}`.

**Call maps** `cilium_call_policy`, `cilium_egresscall_policy`
(`PROG_ARRAY`, 65535 entries) index tail calls per endpoint (datapath area).

**ipcache BPF map** `cilium_ipcache_v2` (LPM trie, 512000 entries): key
`{prefixlen, cluster_id u16, pad, family, ip}`; value `RemoteEndpointInfo{
sec_identity u32, tunnel endpoint, key u8, flags (skiptunnel, hastunnel,
ipv6tunnel, remotecluster)}` — layout owned by the BPF-maps area; this area
owns the writes.

**Persisted files**: `<state-dir>/local_allocator_state.json` (checkpoint of
local identities), `--static-cnp-path` YAMLs, `--label-prefix-file` JSON
(`{"version":1,"valid-prefixes":[{"prefix":"...","source":"k8s","ignore":false}]}`).

## External interfaces

- REST (`api/v1/openapi.yaml`): `GET /policy` (full rule list + revision),
  `GET /policy/selectors`, `GET /policy/subject-selectors`, `GET /identity`,
  `GET /identity/{id}`, `GET /identity/endpoints`, `GET /ip` (ipcache dump,
  `pkg/ipcache/api`). Policy mutation via REST was removed; policies come from
  Kubernetes or files.
- Monitor / Hubble: `policy-verdict` message (type 5) as above; `PolicyUpdate` /
  `PolicyDelete` agent notifications carrying rule count, labels, revision.
- CRDs consumed: `NetworkPolicy` (networking.k8s.io/v1), `ClusterNetworkPolicy`
  (policy.networking.k8s.io/v1alpha2), `CiliumNetworkPolicy`,
  `CiliumClusterwideNetworkPolicy`, `CiliumCIDRGroup` (v2; v2alpha1 deprecated),
  `CiliumIdentity`. CNP/CCNP status (`derivativePolicies`, `conditions`) is
  written by the operator path.
- kvstore key spaces above; lease TTL and lock GC.
- Metrics: `cilium_policy`, `cilium_policy_change_total`, `cilium_identity`,
  `cilium_identity_label_sources`, selector cache stats, policy map pressure,
  identity updater latency.
- `cilium-dbg shell` script commands: `policy/import`, `policy/remove`,
  `identity/allocate`, `endpoint/wait-for-policy-revision`, `policy/mapstate/*`.

## Dependencies

- Inventory areas: 01 bpf-programs and 02 bpf-maps-loader (policy.h contract,
  LPM trie map, ipcache map layout, auth map), 06 agent-endpoint-api (endpoint
  regeneration, proxy redirects, `OpLabels`), 11 l7-proxy-dns-auth-mesh (Envoy
  translation of `L7Rules`, DNS proxy for `toFQDNs`, SPIRE auth), 12
  clustermesh-kvstore (remote identity caches, cluster id bits), 13 crds-k8s,
  08 operator (identity GC, operator-managed CIDs, `toGroups` derivative CNPs).
- External services: Kubernetes API (CRDs, Pods, Namespaces, Services), etcd
  (kvstore mode), AWS EC2 API (`toGroups`), Envoy (redirects).
- Go libraries whose semantics leak into behaviour: `k8s.io/apimachinery` label
  selector semantics, `sigs.k8s.io/network-policy-api` v1alpha2 types,
  `cilium/statedb` tables for services and policy computation results.

## Kernel / platform requirements

Not a datapath area, but it dictates: `BPF_MAP_TYPE_LPM_TRIE` with 12-byte
keys and `BPF_F_NO_PREALLOC`; `BPF_MAP_TYPE_PERCPU_HASH` for stats;
`BPF_MAP_TYPE_PROG_ARRAY` call maps; map sizes up to 65536 entries per
endpoint. The identity is carried in the skb mark (`MARK_MAGIC_IDENTITY`) and
the VXLAN/Geneve VNI (24 bits), which caps wire identities at 2^24. No
arch-specific concerns.

## Tests

- Unit: 180 `Test*/Fuzz*/Benchmark*` functions in `pkg/policy` (21k lines),
  notably `mapstate_test.go`, `mapstate_iterator_test.go`,
  `distillery_test.go`, `distillery_precedence_test.go`, `l4_filter_deny_test.go`,
  `repository_deny_test.go`, `resolve_deny_test.go`, `selectorcache_test.go`,
  `portrange_test.go`, `aggregate_test.go`; `pkg/policy/testutils/simulate.go`
  is a brute-force reference model used to check the LPM/precedence engine.
  Fuzzers: `FuzzResolvePolicy`, `FuzzDenyPreferredInsert`,
  `FuzzAccumulateMapChange`, `FuzzDistillPolicy`,
  `FuzzDistillPolicyWithAggregates` (27 seed corpus files under
  `pkg/policy/testdata/fuzz/`), `FuzzNewLabels`, `FuzzLabelsfilterPkg`.
- Hive script tests (`pkg/policy/test/testdata/*.txtar`): policy import/remove,
  revision propagation, kube-apiserver allow/deny identity handling, shared
  identity teardown, regenerate-retry.
- k8s translation: `pkg/k8s/network_policy_test.go`,
  `cluster_network_policy_test.go`, `pkg/policy/k8s/*_test.go` (CNP, CIDR group,
  toServices).
- Identity/ipcache: `pkg/identity/cache` (allocation, restore, withhold),
  `pkg/allocator` (kvstore semantics with fake backend), `pkg/ipcache` (3.5k
  lines: metadata layering, source precedence, label injection ordering,
  CIDR identity lifecycle), `operator/identitygc` (heartbeat and GC).
- Privileged: `pkg/maps/policymap/policymap_privileged_test.go`,
  `statsmap_privileged_test.go`.
- E2E (`.github/workflows`): `conformance-k8s-network-policies.yaml` (cyclonus
  suite from `test/k8s/manifests/netpol-cyclonus`), `conformance-l3-l4.yaml`,
  `conformance-l7.yaml`, `conformance-ginkgo.yaml` (`test/k8s/net_policies.go`,
  `fqdn.go`), cilium-cli connectivity tests (policy, deny, host firewall,
  FQDN, CIDR groups) in most workflows.

## Rust mapping

Crates (dependency order): `flowsdn-labels` (Label, Labels, LabelArray,
selector requirements, label filter), `flowsdn-identity` (NumericIdentity,
scopes, reserved/well-known tables, `Identity`), `flowsdn-policy-api` (serde
types for the rule language + `Sanitize`, generated CRD schemas via
`kube-derive`/`schemars`), `flowsdn-policy` (repository, tiers/precedence,
selector cache, mapstate, L4 filters, proxy-id, cookies), `flowsdn-ipcache`
(metadata layering, label injection, BPF map writes through the maps crate),
`flowsdn-idalloc` (allocator trait with CRD backend first; kvstore backend
later), plus `flowsdn-policy-k8s` (watchers and translation of KNP/KCNP/CNP/
CCNP/CIDRGroup).

Model: `NumericIdentity(u32)` newtype with scope helpers; interned label
strings (`lasso`/`string_cache`) since selector matching is hot; `LabelArray`
as sorted `SmallVec`; selectors compiled to `Requirements` with operators and
optional CIDR prefix; `Key`/`Entry` as `#[repr(C)]` types shared with the BPF
crate via `aya`; `MapState { entries: HashMap<Key, Entry>, trie: LpmTrie<LpmKey,
IdSet> }` (write our own 25-bit trie; `ip_network_table` does not fit the
direction+proto+port shape). `Precedence` as a newtype with the exact bit
layout. Policy computation runs per identity on a worker with snapshotted
selector versions (`Arc` + generation counters), matching the reference's
`SelectorSnapshot`.

Hardest correctness areas:

1. **Deny / pass / tier precedence and LPM tie-breaking.** The userspace
   `mapState.insertWithChanges` and the BPF two-lookup algorithm must agree
   exactly: higher precedence wins; equal precedence → longer prefix; equal
   both → deny; auth propagates only from equal-precedence broader entries and
   never upward. Pass entries inherit precedence into the next tier
   (`InheritPassPrecedence`, `passMetas`). Reproduce the reference's fuzzers and
   the brute-force simulator before trusting any optimisation.
2. **Aggregate identities.** Wildcard selectors emit five keys (0, 11, 12, 13,
   14), entities map to aggregate selectors, and `pruneAggregated` removes
   per-identity entries equivalent to their aggregate. Getting this wrong
   silently changes map size and verdicts.
3. **Incremental selector updates and ordering.** Identity add must reach every
   endpoint's policy map before the ipcache map learns the prefix; delete the
   other way round; batched with waitgroups and a bounded ipcache wait (10 s).
   Selector recomputation must be namespace-indexed to stay O(affected).
4. **Identity churn.** Refcounted local identities, restore with withheld IDs,
   grace periods, CID heartbeat GC, and the CRD/kvstore race semantics
   (create-if-not-exists master key, slave key per node). Reuse of a numeric ID
   for different labels while old policy-map entries exist is the classic
   failure.
5. **Port ranges** exploding into masked keys (a 1–65535 range is 16 keys per
   identity) and 16k-entry maps; lockdown-on-overflow behaviour.
6. **Kubernetes selector semantics** (`any:` source, namespace-meta labels,
   cluster label injection, `reserved:init` handling in CCNP) — every
   translation rule above is observable by users.

## Recommendation

**Keep** (core of the product): labels, identity model, CRD identity
allocation, ipcache, policy repository/selector cache/mapstate, KNP + CNP +
CCNP + CiliumCIDRGroup + KCNP translation, host firewall, audit mode, verdict
notifications, operator identity GC. **Defer**: kvstore and double-write
identity backends (implement the allocator behind a trait, ship CRD only),
`toGroups` (AWS), well-known identities (keep the table, flag off),
operator-managed CIDs (`identity-management-mode=operator`), `--static-cnp-path`.
**Replace**: nothing with a third-party crate — no Rust crate implements this
policy model; the kvstore allocator is the only piece worth reconsidering
(etcd-only via `etcd-client` if ClusterMesh needs it).

Effort: **XL**. ~33k lines of Go excluding tests and generated code; expect
20–30k lines of Rust plus a comparable test corpus (the reference's fuzz seeds
and txtar scripts should be ported).

## Open questions

- Which flag gates the `ClusterNetworkPolicy` (KCNP) watcher, and is the
  v1alpha2 API stable enough to target, or should flowsdn wait for v1beta1?
- BPF `CIDR_IDENTITY_RANGE_END` is `(1<<24)+(1<<16)-1` while the Go local
  allocator may allocate up to `0x01FFFFFF`; which bound does the datapath
  actually rely on (e.g. `identity_is_local`)?
- The exact bit positions of the two reserved flag bits between `deny` and
  `lpm_prefix_length` in `policy_entry` (lines hidden in this read) — confirm
  from `bpf/lib/policy.h` before freezing the Rust `#[repr(C)]` type.
- How much of `pkg/policy/commands` (statedb mapstate diffing) is needed for
  parity versus debugging convenience.
- Whether flowsdn should keep the legacy ipcache `Upsert` path for
  kvstore/clustermesh or move all writers to the metadata API from day one.
- `toServices`: the reference resolves to backend IPs at policy time and
  re-resolves on service change; confirm behaviour for headless services and
  ClusterMesh global services before specifying.
