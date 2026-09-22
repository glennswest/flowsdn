# CRD catalogue and the Kubernetes client layer — specification

Status: draft. Derived from: `docs/inventory/13-crds-k8s.md` (primary),
`docs/inventory/05-policy-identity.md`, `docs/inventory/07-ipam-cloud.md`,
`docs/inventory/08-operator.md`; reference cilium v1.20.1 (7d68cfb394) paths
`pkg/k8s/apis/cilium.io/{register.go,const.go}`,
`pkg/k8s/apis/cilium.io/client/{register.go,crds/v2/*.yaml,crds/v2alpha1/*.yaml}`,
`pkg/k8s/apis/crdhelpers/register.go`, `pkg/k8s/apis/cell.go`,
`pkg/k8s/client/{cell.go,config.go,rest_config_provider.go}`,
`pkg/k8s/{resource_ctors.go,statedb.go,labels.go,utils/utils.go}`,
`pkg/k8s/tables/{pods.go,namespaces.go}`, `pkg/k8s/resource/resource.go`,
`pkg/k8s/synced/{crd.go,resources.go,cell.go}`, `pkg/k8s/slim/**`,
`pkg/k8s/version/version.go`, `pkg/k8s/hostfirewallbypass/`,
`pkg/k8s/identitybackend/`, `pkg/annotation/`, `pkg/labelsfilter/filter.go`,
`pkg/nodediscovery/k8s_node_annotate.go`,
`pkg/endpointmanager/endpointsynchronizer.go`, `operator/k8s/resources.go`,
`operator/watchers/node_taint.go`, `operator/pkg/lbipam/lbipam.go`,
`pkg/l2announcer/l2announcer.go`,
`install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml`,
`Documentation/network/kubernetes/compatibility.rst`. Governed by
ADR-0001..0004. Builds on spec `00-foundation-table-config.md` (table store,
change streams, config registry, fences, health).

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes *what*
flowsdn does and the exact data it exchanges. It does not transcribe reference
code. Where the reference behavior is kept for compatibility, the consumer that
depends on it is named (`kubectl`, users' stored CRs, cilium-dbg, the operator,
another implementation's agent during migration). Where flowsdn deviates, the
paragraph is marked **DEVIATION** with the reason and the ADR.

## 1. Scope

In scope:

- The **CRD catalogue**: the 22 `cilium.io` CustomResourceDefinitions, their
  identity (group, kind, plural, singular, short names, categories, scope),
  served and storage versions, subresources, printer columns, and the
  schema-version label; the rule that flowsdn **vendors the reference YAML
  verbatim**, the registration payload built from it, and the CI tests that
  prove the Rust types round-trip it.
- The **slim type contract**: the exact field subset of `Pod`, `Service`,
  `Node`, `Namespace`, `Secret`, `EndpointSlice`, `NetworkPolicy` and the
  shared meta types that flowsdn deserializes, and the unknown-field rule.
- The **watch sets**: every resource the agent watches and every resource the
  operator watches, with field and label selectors, resync behavior, indexers,
  and what each watcher drives.
- The **API server capability contract** (§2.4) — content negotiation, patch
  types, subresources, selectors, bookmarks, `PartialObjectMetadata`,
  pagination, CEL and defaulting, Leases, ownerReferences/GC, discovery,
  `GET /version`. This doubles as the **rustkube compatibility checklist**.
- **Annotations and labels** flowsdn reads or writes, node annotations and
  taints, synthesized identity labels, the default label filter.
- **Client configuration**: kubeconfig vs in-cluster, the API server URL list
  and rotation, QPS/burst, timeouts, heartbeat, and startup vs runtime
  unavailability.
- **RBAC for the agent**, the supported Kubernetes version range and the
  refusal path.

Out of scope, with the owning spec named:

| Subject | Owning spec |
|---|---|
| `CiliumIdentity` semantics, allocation, GC, label model and the identity-relevance filter's *effect* | `03-identity-ipcache` |
| `CiliumLoadBalancerIPPool`, `CiliumL2AnnouncementPolicy`, `CiliumLocalRedirectPolicy` semantics; Service/EndpointSlice → LB model | `05-service-loadbalancing` |
| `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, `CiliumCIDRGroup`, `NetworkPolicy`, `ClusterNetworkPolicy` semantics | `06-policy-engine` |
| `CiliumNode`, `CiliumPodIPPool` semantics and status writers | `07-ipam` |
| `CiliumEndpoint` content, the CEP synchronizer's state machine | `08-endpoint-agent-api` |
| CRD **registration** as an operator responsibility, leader election, `CiliumEndpointSlice` batching, node taint controller | `12-operator` |
| `CiliumEnvoyConfig`, `CiliumClusterwideEnvoyConfig` | `16-l7-envoy-dns` |
| The five `CiliumBGP*` CRDs | `15-bgp` |
| `CiliumEgressGatewayPolicy` | `14-encryption-egress` |
| `CiliumNodeConfig` as a configuration source | `00-foundation-table-config` §3.3 |
| Helm value → config key mapping | packaging spec (wave 4) |
| Gateway API, Ingress, MCS-API, ClusterMesh EndpointSlice mirroring | wave 4 specs; **deferred from the first cut** (§12.5) |

This spec owns the *schema* and the *client layer*. It does not restate any
CRD's field semantics; the inventory (`docs/inventory/13-crds-k8s.md`) carries
the full flattened field tables and remains the reference for them.

## 2. Compatibility contract

### 2.1 CRD documents

| Interface | MUST match | Consumer |
|---|---|---|
| The 22 CRD YAML documents | byte-identical to the reference files under `pkg/k8s/apis/cilium.io/client/crds/{v2,v2alpha1}/` at 7d68cfb394 | every CR a user has ever `kubectl apply`ed; `kubectl explain`; admission validation |
| CRD object names | `<plural>.cilium.io` | `kubectl get crd`, RBAC `resourceNames` |
| `spec.names` | kind, plural, singular, shortNames, categories exactly as §4.1 | `kubectl get cnp`, `kubectl get cilium` (category) |
| `spec.scope` | as §4.1 | client URL construction |
| `spec.versions[].{name,served,storage,deprecated}` | as §4.1 | stored CRs, `kubectl` version negotiation |
| `spec.versions[].subresources` | as §4.1; **CiliumEndpoint has none** | status writers on both sides |
| `spec.versions[].additionalPrinterColumns` | as §4.1 | `kubectl get` output users script against |
| `spec.conversion` | absent → server default strategy `None` | multi-version CRDs (schemas are identical) |
| CRD label `io.cilium.k8s.crd.schema.version` | `1.33.11` | the update comparison (§3.2), `cilium-dbg`/support bundles, mixed-version clusters |
| Group | `cilium.io` | everything |

**DEVIATION (none, deliberate):** flowsdn keeps the `cilium.io` group and the
`io.cilium.*` label/annotation keys. `docs/licensing.md` records this as
nominative use: the group name is the compatibility interface, not branding.

### 2.2 Rust type ↔ YAML round-trip

flowsdn MUST be able to accept, without loss, any document that validates
against a vendored schema, and MUST NOT emit a document that fails to validate
against it. §3.1 defines the vendoring and verification mechanism; §9.1 the
tests.

### 2.3 Slim types

flowsdn MUST deserialize exactly the field subsets in §4.3 and MUST ignore
every other field. Field subsets are a memory contract, not a schema contract:
the API server sends the whole object, flowsdn keeps a fraction of it.

### 2.4 API server capability contract (rustkube checklist)

Everything in this table is exercised by flowsdn against the API server. A
Kubernetes-compatible server (including rustkube) that does not implement a
row breaks the named feature. "Required" = flowsdn cannot start or cannot
provide the feature; "Degraded" = flowsdn works with the stated fallback.

| # | Capability | Where used | Level |
|---|---|---|---|
| C1 | `apiextensions.k8s.io/v1` CRD create/get/update, with `status.conditions[type=Established]` reaching `True` and `NamesAccepted=False` reported on conflict | operator registration (§3.2) | Required |
| C2 | Structural-schema validation of CRs, including `format: cidr\|ipv4\|idn-hostname\|date-time`, `pattern`, `enum`, `minItems/maxItems`, `minLength/maxLength`, `minimum/maximum` | every `cilium.io` write by a user or by flowsdn | Required |
| C3 | `x-kubernetes-validations` (CEL), including `has(self.spec) \|\| has(self.specs)` (CNP/CCNP top level), `self == oldSelf` immutability rules, `isIP()`/`isCIDR()` calls | CNP/CCNP, LB IP pool, BGP CRDs | Required |
| C4 | Schema **defaulting** (`default:` in the schema) — e.g. ICMP `family: IPv4` | CNP/CCNP; flowsdn does not re-default client-side | Required |
| C5 | `x-kubernetes-int-or-string` | CNP ICMP `type`, Service `targetPort` | Required |
| C6 | `x-kubernetes-list-type: map` + `x-kubernetes-list-map-keys` merge semantics | `status.conditions` on CNP/CCNP, LB pool, BGP | Required |
| C7 | `x-kubernetes-list-type: atomic` / `set`, `x-kubernetes-map-type: atomic` | label selectors, `serverNames` | Required |
| C8 | `x-kubernetes-preserve-unknown-fields` | `CiliumEnvoyConfig.spec.resources[]` (opaque Envoy config) | Required for L7 |
| C9 | `oneOf` / `anyOf` at object level | CNP `spec` (`{endpointSelector}\|{nodeSelector}`), `toPorts[].rules` (`{http}\|{dns}`) | Required |
| C10 | Multiple **served** versions with a single **storage** version, `conversion.strategy: None` | CIDRGroup, LB IP pool, five BGP CRDs (v2 + deprecated v2alpha1) | Required (or §12.2) |
| C11 | `additionalPrinterColumns`, including JSONPath filters `?(@.type=="X")` and escaped keys `.metadata.labels.io\.kubernetes\.pod\.namespace` | `kubectl get` UX only | Degraded (columns missing) |
| C12 | **Status subresource** on the CRDs listed in §4.1, with `UpdateStatus`/`PatchStatus` semantics (spec writes ignored on the status endpoint and vice versa) | CiliumNode, CNP/CCNP, LB pool, L2 policy, BGP, GatewayClassConfig | Required |
| C13 | **No** status subresource on `CiliumEndpoint`: `status` is a plain field, written by a whole-object JSON patch | agent CEP writer (§3.9) | Required |
| C14 | **JSON Patch** (`application/json-patch+json`, RFC 6902) including the `test` op with a structured value, and atomic failure of the whole patch when `test` fails | CEP status, node taints, LB pool status, L2 policy status, BGP node status | Required |
| C15 | **Strategic merge patch** (`application/strategic-merge-patch+json`) on `nodes/status` for `metadata.annotations` (map merge) and `status.conditions` (merge on key `type`) | `annotateK8sNode`, `NetworkUnavailable=False` | Default; guarded JSON fallback permitted (§12.3) |
| C16 | **Merge patch** (`application/merge-patch+json`) | operator BGP manager | Required for BGP |
| C17 | **Server-side apply is NOT used.** flowsdn MUST NOT issue `PATCH` with `application/apply-patch+yaml`. `fieldManager` is set on some writes for attribution only | — | Must-not |
| C18 | Field selectors: `spec.nodeName=<name>` on pods; `status.phase=Running` on pods (operator); `metadata.name=` | agent pod watch (the single biggest memory lever), operator kube-dns restarter | Required |
| C19 | Label selectors with `=`, `==`, `!=`, `Exists`, `DoesNotExist`, `in`, `notin` | Service/EndpointSlice proxy-name and headless filters, operator pod selectors | Required |
| C20 | `PartialObjectMetadata`/`PartialObjectMetadataList` content negotiation via `Accept: application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io`, with plain `application/json` fallback in the same Accept header | agent CRD readiness watch (avoids pulling ~400 KB CNP schemas onto every node) | Degraded (falls back to full CRD objects; §7 F5) |
| C21 | Protobuf content type `application/vnd.kubernetes.protobuf` for built-in groups | memory/bandwidth optimization | Optional — see §3.6 and §12.1 |
| C22 | List pagination (`limit`, `continue`, `metadata.continue`, `metadata.remainingItemCount`) and `410 Gone` on an expired `continue` token | initial list of large collections | Degraded (unpaginated list; memory spike) |
| C23 | Watch semantics: list-then-watch with `resourceVersion` continuation, `resourceVersion=0` accepted on the initial list, `410 Gone` on expired watch RV triggering relist | every watcher | Required |
| C24 | Watch **bookmarks** (`allowWatchBookmarks=true`, `Bookmark` event type) | requested by flowsdn's watchers; flowsdn MUST NOT depend on receiving them | Optional |
| C25 | `SendInitialEvents` / streaming list (WatchList) | **not used** | Must-not-require |
| C26 | `coordination.k8s.io/v1` Leases: create, get, update with optimistic concurrency on `resourceVersion` | operator leader election, agent L2 announcements | Required for those features |
| C27 | `ownerReferences` with `controller: true` and namespace-scoped **garbage collection** (deleting a Pod deletes its CEP) | CEP lifecycle; operator GC is the fallback, not the primary | Degraded (operator GC covers it, with lag) |
| C28 | `metadata.name` uniqueness enforced on Create with `409 AlreadyExists` | CRD-mode identity allocation race resolution (spec 03 §3) | Required |
| C29 | `GET /version` returning `gitVersion` (or `major`+`minor`) | version detection and refusal (§3.10) | Required |
| C30 | `GET /readyz` returning 200 | client heartbeat (§3.5) | Required |
| C31 | Discovery (`GET /apis`, `/apis/<group>/<version>`) | **not consulted**; `--enable-k8s-api-discovery` is accepted and ignored (§6) | Must-not-require |
| C32 | `GET /api/v1/namespaces/kube-system` for the startup readiness probe | `waitForConn` (§3.5) | Required |
| C33 | HTTP/2 with idle-connection close, or HTTP/1.1 when `DISABLE_HTTP2` is set | connection rotation on heartbeat failure | Degraded |
| C34 | `429 Too Many Requests` distinguishable as a status error (heartbeat does **not** rotate on 429) | heartbeat (§3.5) | Degraded |
| C35 | `deletecollection` on `ciliumendpointslices`, `endpointslices` | operator CES/ClusterMesh cleanup | Required for those features |
| C36 | Server-side `listKind` defaulting to `<Kind>List` when a CRD is created without it | registration payload omits `listKind` (§3.2) | Required |

A conformance suite that mechanically exercises C1–C36 is specified in §9.5.

### 2.5 Config keys

Every key in §6 MUST keep its reference-compatible name so an existing
`cilium-config` ConfigMap continues to work (spec 00 §2).

## 3. Behavior

### 3.1 CRD vendoring and verification

**Vendoring.** flowsdn MUST carry the 22 reference CRD YAML documents in the
repository at `crates/flowsdn-k8s/crds/{v2,v2alpha1}/<plural>.yaml`, copied
byte-for-byte from the reference tree at the pinned commit. Each file is a
direct copy permitted by `docs/licensing.md` ("CRD OpenAPI schemas"); the
directory MUST carry a `LICENSE-CILIUM` note naming the source path, the
commit `7d68cfb394`, and Apache-2.0, and `NOTICE` MUST have a corresponding
entry.

The refresh procedure is a script, `tools/vendor-crds.sh`, that copies from a
reference checkout, regenerates `crds/SHA256SUMS`, and refuses to run if the
reference checkout is not at the pinned commit. Hand-editing a vendored file is
forbidden; changing one is a deliberate schema change and MUST bump
`io.cilium.k8s.crd.schema.version` (§3.2) and be recorded in `CHANGELOG.md`.

**Rust types.** For each CRD, flowsdn MUST provide a Rust type that
deserializes and serializes the custom resource. Types are hand-written with
`kube::CustomResource` derive (§11.2) rather than machine-generated, because
the reference schemas use constructs (`oneOf` alternatives, `int-or-string`,
`additionalProperties` maps keyed by full label strings) that no generator
expresses cleanly. Rules the types MUST follow:

1. Every field is `#[serde(default)]` and, where the reference marks it
   `omitempty`, `#[serde(skip_serializing_if = "…is_empty/is_none")]`.
2. No `#[serde(deny_unknown_fields)]` anywhere (see §3.6).
3. Enumerated string fields deserialize into a Rust enum with a
   `#[serde(other)] Unknown(String)` arm, never a hard failure — a newer
   API server may have defaulted a value flowsdn does not know.
4. `x-kubernetes-int-or-string` fields deserialize into an `IntOrString`
   newtype that accepts both JSON forms and re-serializes in the form it was
   received.
5. `x-kubernetes-preserve-unknown-fields` subtrees are typed as
   `serde_json::Value` and preserved verbatim.
6. `status` is a separate type; for CRDs with the status subresource the
   spec type MUST NOT serialize `status` on spec writes.

**Verification — the CI diff tests.** The following MUST run in CI on every
commit. They are the whole reason the "vendor the YAML, hand-write the types"
split is safe.

| Test | What it does | Fails when |
|---|---|---|
| **T-CRD-1** vendor integrity | Recompute SHA-256 of every file under `crds/` and compare to `crds/SHA256SUMS` | anyone edits a vendored YAML without the script |
| **T-CRD-2** document round-trip | For each YAML: parse to `serde_yaml::Value` → convert to `serde_json::Value` → deserialize into flowsdn's `CustomResourceDefinition` model → re-serialize → compare against the input with keys sorted and YAML/JSON scalar normalization | flowsdn's CRD model loses a field of the CRD document itself |
| **T-CRD-3** schema ↔ type diff | For each CRD version, generate an OpenAPI v3 schema from the Rust type (`schemars` via `kube-derive`), normalize both sides (drop `description`, sort `required`, canonicalize numbers), and diff against `versions[].schema.openAPIV3Schema` from the vendored YAML | the Rust type and the schema drift in a field name, type, or requiredness |
| **T-CRD-3a** known-diff allowlist | Entries in `crds/known-diffs.toml` are `(crd, version, json-pointer, reason)`; each suppresses one T-CRD-3 difference. The test fails if an allowlist entry no longer matches anything | a stale suppression hides a real drift |
| **T-CRD-4** instance round-trip | Golden CRs under `crates/flowsdn-k8s/testdata/crs/<plural>/*.yaml` (one per CRD minimum, plus every example in the reference documentation and every fixture the sibling specs' tests need) are deserialized into the Rust type, re-serialized, and compared field-for-field to the input after applying schema defaults | a type drops or mangles a field a user can write |
| **T-CRD-5** unknown-field tolerance | Each golden CR is re-run with an extra unknown object key at every level and an unknown enum value at each enum; deserialization MUST still succeed and the known fields MUST be unchanged | a type is accidentally strict |
| **T-CRD-6** registration payload | The object flowsdn would POST for each CRD is compared to a golden file, asserting: `metadata.name`, `metadata.labels` = exactly the schema-version label, `metadata.annotations` **absent**, `spec.group`, `spec.names.{kind,plural,singular,shortNames,categories}` (no `listKind`), `spec.scope`, `spec.versions` copied verbatim, `spec.conversion` copied verbatim (absent), `spec.preserveUnknownFields = false` | the registration payload drifts from §3.2 |
| **T-CRD-7** property test | `proptest` generates arbitrary values of each Rust CRD type, serializes, and validates the result against the vendored schema with a CEL-less structural validator | flowsdn can emit a document its own CRD rejects |

T-CRD-3's allowlist is expected to be non-empty and small. Known permitted
entries at the time of writing: printer columns and CEL rules are attached
through `#[kube(printcolumn = …)]` / literal schema patches rather than derived
from the type, and `description` strings are dropped on both sides.

**The YAML is the artifact; the Rust type is a consumer.** When the two
disagree, the YAML wins and the type is fixed.

### 3.2 Registration and readiness

**Who registers.** The **operator** creates and updates CRDs
(spec `12-operator`). The agent MUST NOT create or update a CRD. This spec
defines the payload and the algorithm; the operator spec owns when it runs and
under which leader election.

Registration for each CRD:

1. Build the payload from the vendored YAML: keep `spec.group` = `cilium.io`,
   `spec.names.{kind,plural,singular,shortNames,categories}` (drop `listKind`;
   the server defaults it — C36), `spec.scope`, `spec.versions` verbatim,
   `spec.conversion` verbatim. Set `metadata.name` = `<plural>.cilium.io` and
   `metadata.labels` = `{ io.cilium.k8s.crd.schema.version: "1.33.11" }`.
   Do **not** copy `metadata.annotations` from the YAML (the
   `controller-gen.kubebuilder.io/version` annotation is informational and the
   reference drops it too).
2. `GET` the CRD. On `404`, `POST` it; a `409 AlreadyExists` is success (two
   operators raced).
3. Decide whether an update is needed:
   - if the existing CRD's `spec.versions[0].schema` is absent → update;
   - if the existing CRD has no `io.cilium.k8s.crd.schema.version` label →
     update;
   - if the label does not parse as semver, or parses **strictly less than**
     `1.33.11` → update;
   - otherwise → no update. A **newer** label in the cluster is left alone, so
     a downgraded operator does not clobber a newer schema.
4. If an update is needed, poll every 500 ms for up to 60 s: re-`GET`, re-check
   the condition, then set `metadata.labels`, `spec` and
   `spec.preserveUnknownFields = false` explicitly (the server carries the old
   value forward otherwise) and `PUT`. A `409 Conflict` retries the poll.
5. Poll every 500 ms for up to 60 s until `status.conditions` contains
   `Established=True`. `NamesAccepted=False` is a fatal error naming the
   conflicting CRD.

`--skip-crd-creation` (default false) skips steps 1–5 entirely, for clusters
where an administrator applies the CRDs out of band.

**Readiness gating (agent).** Before starting any watcher for a `cilium.io`
resource, the agent MUST wait until every CRD in its required set exists:

- It lists and watches `customresourcedefinitions.apiextensions.k8s.io` with
  `Accept: application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io,application/json;as=PartialObjectMetadataList;v=v1beta1;g=meta.k8s.io,application/json`
  for the list and the `PartialObjectMetadata` (non-list) equivalent for the
  watch, so it never downloads the ~400 KB CNP/CCNP schemas.
- It tracks presence per name and completes when all required names are
  present. Names may also disappear (a CRD deleted mid-run flips its entry
  back to absent).
- Timeout `--crd-wait-timeout` (default 5 m) is **fatal**: the agent exits with
  a message naming the CRDs still missing and pointing at the operator.
- Progress is logged every ~1 s of ticks (the reference logs every 20 ticks of
  50 ms).

The required set is computed from configuration:

| Condition | CRDs added |
|---|---|
| always | `ciliumidentities`, `ciliumpodippools`, `ciliumloadbalancerippools`, `ciliuml2announcementpolicies` |
| `disable-endpoint-crd=false` | `ciliumendpoints` |
| `enable-cilium-endpoint-slice` | `ciliumendpointslices` |
| `enable-ciliumnode-crd` (hidden, default true) | `ciliumnodes` |
| `enable-cilium-network-policy` (default true) | `ciliumnetworkpolicies` |
| `enable-cilium-clusterwide-network-policy` (default true) | `ciliumclusterwidenetworkpolicies` |
| either policy CRD enabled | `ciliumcidrgroups` |
| `enable-egress-gateway` | `ciliumegressgatewaypolicies` |
| `enable-local-redirect-policy` | `ciliumlocalredirectpolicies` |
| `enable-envoy-config` | `ciliumenvoyconfigs`, `ciliumclusterwideenvoyconfigs` |
| `enable-bgp-control-plane` | the five `ciliumbgp*` |
| `enable-datapath-plugins` | `ciliumdatapathplugins` |

`ciliumnodeconfigs` and `ciliumgatewayclassconfigs` are registered by the
operator but are **not** in the agent's required set.

Every `cilium.io` watcher MUST be constructed with a handle to the readiness
fence (spec 00 §3.4) so its first list cannot be issued before the fence
opens.

**Cache-sync gating.** After the watchers start, the agent MUST wait for the
initial list of every watched group to complete. The timeout is
`--k8s-sync-timeout` (default 3 m, hidden) measured **from the last event
received on that group**, not from start, so a slowly-streaming large cluster
does not trip it. Expiry is fatal.

### 3.3 Agent watch set

Resync: **flowsdn MUST NOT use a periodic full resync.** Every watcher runs
with resync period 0 and relies on the watch stream plus `410 Gone` relist —
the same as the reference (`FullResyncPeriod: 0`). Periodic resync exists in
client-go to re-deliver adds to handlers with lossy processing; flowsdn's
reconcilers are revision-driven (spec 00 §3.2) and do not need it.

| Resource (GVR) | Codec | Field selector | Label selector | Indexes | Drives |
|---|---|---|---|---|---|
| `v1 pods` | slim | `spec.nodeName=<node-name>` | — | name (`ns/name`) | table `k8s-pods`; endpoint labels, host ports, named ports, pod annotations (§4.4) |
| `v1 namespaces` | slim | — | — | name | table `k8s-namespaces`; namespace labels in identities (spec 03) |
| `v1 nodes` | slim | — | — | — | node manager, PodCIDR, node labels/annotations (spec 10) |
| `v1 services` | slim | — | §3.3.1 | namespace | LB tables (spec 05) |
| `discovery.k8s.io/v1 endpointslices` | slim | — | §3.3.1 + `endpointslice.kubernetes.io/managed-by!=endpointslice-mesh-controller.cilium.io` | namespace | LB backends (spec 05) |
| `networking.k8s.io/v1 networkpolicies` | slim | — | — | — | policy repository (spec 06) |
| `policy.networking.k8s.io/v1alpha2 clusternetworkpolicies` | full | — | — | — | policy repository (spec 06); only when `enable-k8s-cluster-network-policy` |
| `v1 secrets` | full | direct `GET` by ns/name | — | — | TLS contexts and header matches for L7 policy (spec 16) |
| `v1 configmaps` | full | direct `GET` by ns/name | — | — | `config-sources` (spec 00 §3.3) |
| `apiextensions.k8s.io/v1 customresourcedefinitions` | PartialObjectMetadata | — | — | name | CRD readiness gate (§3.2) |
| `coordination.k8s.io/v1 leases` | full | — | — | — | L2 announcement leadership (spec 05) |
| `cilium.io/v2 ciliumnodes` | JSON | — | — | name | node/IPAM (spec 07) |
| `cilium.io/v2 ciliumendpoints` | JSON, lazily transformed to the slim CEP of §4.3 | — | — | namespace, `localNode` (by `status.networking.node`) | ipcache remote endpoints (spec 03); own CEP |
| `cilium.io/v2alpha1 ciliumendpointslices` | JSON | — | — | namespace (from `spec`-level field, CES is cluster-scoped), `localNode` | ipcache when CES mode is on |
| `cilium.io/v2 ciliumidentities` | JSON | — | — | **by-key**: the canonical label-set string of `security-labels` | identity allocator, CRD mode (spec 03) |
| `cilium.io/v2 ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies`, `ciliumcidrgroups` | JSON | — | — | — | policy (spec 06) |
| `cilium.io/v2 ciliumegressgatewaypolicies` | JSON | — | — | — | egress gateway (spec 14) |
| `cilium.io/v2 ciliumlocalredirectpolicies` | JSON | — | — | — | LRP (spec 05) |
| `cilium.io/v2 ciliumenvoyconfigs`, `ciliumclusterwideenvoyconfigs` | JSON | — | — | — | L7 (spec 16) |
| `cilium.io/v2 ciliumloadbalancerippools` | JSON | — | — | — | LB IPAM read side (spec 05) |
| `cilium.io/v2 ciliumbgpnodeconfigs`, `ciliumbgpadvertisements`, `ciliumbgppeerconfigs` | JSON | — | — | — | BGP (spec 15) |
| `cilium.io/v2 ciliumnodeconfigs` | JSON | — | — | — | dynamic config (spec 00) |
| `cilium.io/v2alpha1 ciliumpodippools` | JSON | — | — | — | multi-pool IPAM (spec 07) |
| `cilium.io/v2alpha1 ciliuml2announcementpolicies` | JSON | — | — | — | L2 announcements (spec 05) |
| `cilium.io/v2alpha1 ciliumdatapathplugins` | JSON | — | — | — | datapath plugins |
| `/readyz`, `/version` | — | — | — | — | heartbeat, version detection (§3.5, §3.10) |
| `v1 events` (write only) | full | — | — | — | Hubble drop-event emitter (spec 11), optional |

The pod field selector is the single most important line in this table: on a
5,000-pod cluster it is the difference between every agent holding every pod
and every agent holding its own ~30. flowsdn MUST NOT fall back to an
unfiltered pod watch with client-side filtering, and MUST refuse to start (§7
F6) if the server rejects the field selector.

#### 3.3.1 Service / EndpointSlice selector

Let `P` = `--k8s-service-proxy-name` and `H` = `enable-headless-service-watch`.

```
requirement 1:  P == ""  →  service.kubernetes.io/service-proxy-name DoesNotExist
                P != ""  →  service.kubernetes.io/service-proxy-name == P
requirement 2:  H == false →  service.kubernetes.io/headless DoesNotExist
```

EndpointSlices additionally carry
`endpointslice.kubernetes.io/managed-by != endpointslice-mesh-controller.cilium.io`,
excluding slices mirrored from remote clusters by ClusterMesh. The
proxy-name/headless requirements reach EndpointSlices through label mirroring
from the parent Service (Kubernetes ≥ 1.20 behavior), not through a join.

The selector string flowsdn sends MUST be built in the canonical order above so
that server-side selector caching and audit logs match the reference.

### 3.4 Operator watch set

| Resource | Codec | Selector / options | Indexes | Drives |
|---|---|---|---|---|
| `v1 pods` (all nodes) | slim | none for the general watch; `status.phase=Running` + `--pod-restart-selector` (default `k8s-app=kube-dns`) for the unmanaged-pod restarter | namespace, `pod-node` (`spec.nodeName`) | CEP GC correlation, unmanaged kube-dns restart, agent-pod liveness for the taint controller (namespace + Helm label selector) |
| `v1 namespaces` | slim | — | name | namespace labels for identity GC correlation |
| `v1 nodes` | slim | — | — | taint removal, `NetworkUnavailable` condition, CiliumNode creation in cloud/cluster-pool IPAM |
| `v1 services` | slim | §3.3.1 | namespace | LB IPAM, ClusterMesh sync, Ingress/Gateway |
| `discovery.k8s.io/v1 endpointslices` | slim | §3.3.1 | namespace | ClusterMesh mirroring, Gateway backends |
| `v1 secrets` | full | — | — | BGP session auth, policy secret sync |
| `cilium.io/v2 ciliumendpoints` | JSON | — | namespace, **identity** (`status.identity.id`) | identity GC liveness, CEP GC, CES batching |
| `cilium.io/v2alpha1 ciliumendpointslices` | JSON | — | — | CES controller |
| `cilium.io/v2 ciliumnodes` | JSON | — | **node-ip** (`spec.addresses[]` of type Internal/External) | cloud IPAM, node GC |
| `cilium.io/v2 ciliumidentities` | JSON | — | by-key | identity GC |
| `cilium.io/v2 ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies` | JSON | — | — | validation → `status.conditions[Valid]`, `toGroups` derivation |
| `cilium.io/v2 ciliumcidrgroups` | JSON | — | — | `toGroups` external CIDR groups |
| `cilium.io/v2 ciliumloadbalancerippools` | JSON | — | — | LB IPAM |
| `cilium.io/v2alpha1 ciliumpodippools` | JSON | — | — | multi-pool IPAM; operator auto-creates the default pool |
| `cilium.io/v2 ciliumbgpclusterconfigs`, `ciliumbgppeerconfigs`, `ciliumbgpadvertisements`, `ciliumbgpnodeconfigoverrides` | JSON | — | — | BGP node config generation |
| `apiextensions.k8s.io/v1 customresourcedefinitions` | full (needs schemas) | — | — | registration (§3.2) |
| `coordination.k8s.io/v1 leases` | full | — | — | leader election |

**DEVIATION:** the reference operator additionally runs controller-runtime
managers for Gateway API, Ingress, MCS-API and ClusterMesh EndpointSlice sync,
and a `secretsync` controller over Secrets and ConfigMaps. Those are **deferred
out of the first cut** (§12.5) with their own wave-4 spec; the CRDs they need
(`ciliumgatewayclassconfigs`) are still registered so a later enable is a
restart, not a migration. Reason: they are ~40% of the operator's API surface
and none of them are on the datapath path. ADR-0001 keeps them in overall
scope.

### 3.5 Client construction, connection and heartbeat

**Enablement.** The Kubernetes client is enabled when `--enable-k8s` is true
(default) **and** at least one of: `--k8s-api-server-urls` is non-empty,
`--k8s-kubeconfig-path` is set, both `KUBERNETES_SERVICE_HOST` and
`KUBERNETES_SERVICE_PORT` are set, or `K8S_NODE_NAME` is set. Otherwise flowsdn
runs without Kubernetes (CNI-compatible standalone mode) and every watcher in
§3.3 is absent.

**Configuration precedence** for building the REST configuration:

1. `--k8s-kubeconfig-path` — load the kubeconfig (current context).
2. Otherwise, the first entry of `--k8s-api-server-urls`:
   - a URL with scheme `https://` → load the in-cluster configuration
     (service-account token and CA from
     `/var/run/secrets/kubernetes.io/serviceaccount/`) and override the host;
   - any other URL → a bare configuration with that host and no credentials
     (development only).
   A URL without a scheme is rewritten to `https://<url>`. An unparseable URL
   is logged and skipped.
3. Otherwise, in-cluster configuration.

QPS and burst are applied last and always: `--k8s-client-qps` (default 10.0)
and `--k8s-client-burst` (default 20); a value of 0 leaves the client library
default. The operator uses `--operator-k8s-client-qps` / `-burst`. The
user agent is `<binary-basename>/<version>` plus, for a named sub-client, a
space and the name.

**Multiple API servers and rotation.** With more than one URL:

- An initial URL is picked **at random** (not the first) so a fleet restart
  does not stampede one server.
- All requests go through a layer that rewrites the request host to the
  currently selected URL, so a rotation takes effect on the next request
  without rebuilding the client.
- Rotation picks a **different** random URL from the list.
- Rotation happens on: startup connectivity failure (§3.5 startup), and
  heartbeat failure or timeout.
- Once flowsdn has switched to the in-cluster `default/kubernetes` **service**
  address (below), manual rotation stops: the datapath load-balances to the
  API-server backends.

**Service-address takeover.** After the load-balancer control plane is up
(spec 05), flowsdn watches the `default/kubernetes` frontend. When its address
or backend set changes, flowsdn verifies connectivity to the service address
(§3.5 probe, up to 60 s), and on success: persists
`{"service": "<addr:port>", "endpoints": ["<addr:port>", …]}` to
`<state-dir>/k8sapi_server_state.json`, sets the REST host to the service
address, replaces the URL list with the endpoint list, and marks itself
"connected to service". On the next start, that file is restored (after the
same connectivity check) before falling back to the configured URLs — the
configured URLs may all have been rotated out while the agent was down.

**Startup.** Before anything else in the Kubernetes layer, flowsdn probes the
API server by `GET`ting the `kube-system` namespace, retrying every 5 s for up
to 60 s and rotating the URL between attempts when rotation is possible. On
success it starts the heartbeat and runs version detection (§3.10). **If the
API server is unreachable at startup, the agent MUST exit non-zero** with a
message naming the last host tried and the underlying error. It MUST NOT
proceed to program the datapath from an empty cache: doing so would install a
default-deny world or an empty service table on a node with running workloads.

**Runtime.** After startup the agent MUST NOT exit because the API server
became unreachable. The datapath keeps running with the last known state; the
BPF maps are not pruned on a watch failure (spec 00 §3.2 forbids a reconciler
pruning from an unsynchronized table). Behavior is:

- Watches reconnect with exponential backoff.
- A `410 Gone` triggers a relist; on relist completion the tables are replaced
  and reconcilers prune as normal.
- The health registry (spec 00) records the `k8s-client` module as `Degraded`
  with the error; `GET /healthz` reflects it; the `cilium_k8s_*` metrics of §8
  move.
- The CNI plugin's behavior while the API server is down is spec 09's
  business; nothing here blocks pod creation that IPAM can satisfy locally.

**Heartbeat.** A controller runs every `--k8s-heartbeat-timeout` (default 30 s;
0 disables it):

1. If a successful API interaction happened within the last timeout window,
   skip — the heartbeat is a liveness check of an *idle* connection.
2. Otherwise `GET /readyz` with that timeout as the deadline.
3. On any error **other than** `429 Too Many Requests`, or on the deadline
   expiring: close all idle connections and rotate the API server URL.
   A 429 is explicitly not a failure: the server is up and overloaded, and
   dropping connections would make it worse.

**Connection settings.** Dial timeout `--k8s-client-connection-timeout`
(default 30 s) and keep-alive `--k8s-client-connection-keep-alive` (default
30 s). If either is 0, the connection-rotating dialer is disabled and idle
connections are never force-closed. `DISABLE_HTTP2` in the environment forces
HTTP/1.1 and switches the "close all connections" action to the dialer's own
close-all.

**Host-firewall bypass.** When the host firewall is enabled and
`--enable-k8s-host-firewall-bypass` (hidden, default true) is set, every socket
the Kubernetes client opens — including the Go-resolver DNS sockets — MUST
carry `SO_MARK` = the egress magic mark combined with the reserved `host`
identity, so API-server traffic bypasses the host policy and the DNS proxy.
This requires `CAP_NET_ADMIN`, which the agent already holds. Mark values are
owned by spec 02; this spec only requires that the marking hook exists on the
client's dialer and resolver.

### 3.6 Content negotiation and unknown fields

**Codecs.** Built-in groups (`""`, `discovery.k8s.io`, `networking.k8s.io`,
`apiextensions.k8s.io`, `coordination.k8s.io`, `policy.networking.k8s.io`) are
requested with `application/vnd.kubernetes.protobuf` in the reference; the
`cilium.io` group is JSON because CRDs have no protobuf representation.

**DEVIATION:** flowsdn's first implementation requests **JSON for all groups**.
Reason: `kube-rs` has no protobuf codec, and the reference's protobuf advantage
is bandwidth and decode cost, not correctness. The cost is roughly 2–3× the
bytes on the initial list of large collections. Mitigations that stay in scope:
the pod field selector (§3.3) removes the largest collection, and §12.1 keeps
protobuf as an optimization with a defined path — the reference's slim `.proto`
files are already the minimal field set and carry the *same* field numbers as
the upstream types (e.g. `ObjectMeta.uid`=5, `resourceVersion`=6,
`generation`=7, `deletionTimestamp`=9, `labels`=11, `annotations`=12,
`ownerReferences`=13), so a `prost` decoder over the slim protos decodes a full
upstream message and skips the rest. A rustkube that does not speak protobuf at
all (C21) makes this moot.

**Unknown fields — the rule.** flowsdn MUST ignore unknown fields at every
level of every object it deserializes, and MUST NOT error on them. Concretely:

- No Rust type in `flowsdn-k8s` carries `deny_unknown_fields`; a lint in CI
  greps for it.
- Unknown *enum variants* deserialize into an `Unknown(String)` arm and are
  treated as "not a value flowsdn acts on" by the consumer, never as a parse
  failure. Where the consumer must choose, it MUST choose the safe branch and
  log once per distinct value.
- Fields flowsdn drops on read are **lost**: flowsdn never round-trips a
  built-in object it read through a slim type back to the API server. Every
  write to a built-in resource is a patch of named paths (§3.9), never a
  whole-object update. This is a hard rule — a slim `Update` would silently
  delete every field not in §4.3.
- For `cilium.io` objects flowsdn *does* write whole objects
  (`CiliumEndpoint`, `CiliumNode`, `CiliumIdentity`). Those types are the full
  types, and unknown fields inside a
  `x-kubernetes-preserve-unknown-fields` subtree are preserved verbatim
  (§3.1 rule 6). For all other unknown fields on a `cilium.io` object, flowsdn
  MUST use a read-modify-write with the *decoded* object and accept the loss
  of fields the API server would have rejected anyway (the schema is
  structural and prunes them server-side).

### 3.7 Identity label synthesis

The label model, the numeric identity space and the filter's *effect* belong to
spec 03. This spec fixes the mechanical transformation from Kubernetes objects
to the label set, because it is a client-layer concern and because getting it
wrong renumbers every identity in a cluster.

Given a Pod, its Namespace object, its `spec.serviceAccountName` and the
configured cluster name:

1. Start from `pod.metadata.labels`.
2. Remove every label whose key starts with `io.cilium.k8s` (the
   Cilium-owned prefix) — a user MUST NOT be able to forge them.
3. For every label `k=v` on the Namespace, add
   `io.cilium.k8s.namespace.labels.<k> = v`. (This is why
   `io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name` is the reliable
   namespace selector: `kubernetes.io/metadata.name` is set by Kubernetes on
   every namespace.)
4. Add `io.kubernetes.pod.namespace = <namespace name>`.
5. If the service account is non-empty, add
   `io.cilium.k8s.policy.serviceaccount = <sa>`; otherwise remove that key.
6. Add `io.cilium.k8s.policy.cluster = <cluster-name>`.
7. If the pod declares named ports, add `io.cilium.k8s.named-ports`.

The result is then passed through the identity-relevance filter. The default
allow/deny list, in order, MUST be:

```
  reserved:.*                                  (allow, source-qualified)
  io.kubernetes.pod.namespace                  (allow)
  io.cilium.k8s.namespace.labels               (allow, prefix)
  app.kubernetes.io                            (allow, prefix)
  io.cilium.k8s.policy.cluster                 (allow)
  io.cilium.k8s.policy.serviceaccount          (allow)
 !io\.kubernetes                               (deny, regex)
 !kubernetes\.io                               (deny, regex)
 !statefulset.kubernetes.io/pod-name           (deny)
 !apps.kubernetes.io/pod-index                 (deny)
 !batch.kubernetes.io/job-completion-index     (deny)
 !batch.kubernetes.io/controller-uid           (deny)
 !.*beta\.kubernetes\.io                       (deny, regex)
 !k8s\.io                                      (deny, regex)
 !pod-template-generation                      (deny)
 !pod-template-hash                            (deny)
 !controller-revision-hash                     (deny)
 !controller-uid                               (deny)
 !annotation.*                                 (deny, regex)
 !etcd_node                                    (deny)
 !topology\.kubernetes\.io                     (deny, regex)
```

Entries are regular expressions anchored at the start of the key; the longest
match wins, and an allow entry beats a deny entry of equal length. `--labels`
appends entries, `--label-prefix-file` (JSON `{version:1, valid-prefixes:
[{prefix, source, invert}]}`) replaces the list, `--node-labels` (with
`--enable-node-selector-labels`) sets the separate list used for node
identities. The list MUST be byte-identical to the above by default: changing
it changes which pods share an identity, which changes identity numbering,
which invalidates every policy map on the node.

**Policy provenance labels.** Every rule imported from Kubernetes carries
`k8s:io.cilium.k8s.policy.derived-from` = one of `CiliumNetworkPolicy`,
`CiliumClusterwideNetworkPolicy`, `NetworkPolicy`, `ClusterNetworkPolicy`;
`k8s:io.cilium.k8s.policy.name`; `k8s:io.cilium.k8s.policy.uid`; and for
namespaced sources `k8s:io.cilium.k8s.policy.namespace`. Spec 06 owns what they
mean; this spec fixes the keys.

**Workload attribution.** From a Pod's `ownerReferences` (the entry with
`controller: true`), flowsdn derives a workload name and kind for Hubble and
CEP metadata: `ReplicaSet` + a `pod-template-hash` label → the parent
`Deployment` (name with the hash suffix stripped); `ReplicationController` +
a `deploymentconfig` label → `DeploymentConfig`; a `Job` whose name matches the
CronJob naming pattern → `CronJob`; otherwise the owner itself.

### 3.8 Annotations read and written

§4.4 is the catalogue. The behavioral rules:

- **Node annotations read by the agent**: every annotation whose key matches
  `^([A-Za-z0-9]+\.)*cilium\.io/` is copied into the internal node object.
  Additionally the specific pairs in §4.4 are parsed, each with a **new key**
  and a **legacy alias**; the new key wins when both are present.
- **Node annotations written by the agent**: only when
  `--annotate-k8s-node` is true. The write is a **strategic merge patch to
  `nodes/<name>/status`** with body `{"metadata":{"annotations":{…}}}`,
  retried by a controller until it succeeds. Only annotations whose source
  value is non-nil are included; an annotation is never explicitly deleted.
- **Node labels**: read, then filtered by `--exclude-node-label-patterns`
  before use.
- **Pod annotations** are read for: no-track ports, source-IP-verification
  opt-out (gated by the namespace's delegation annotation), IPAM pool
  selection, FIB table id, and the CNI-written MAC address.
- **Namespace annotations** are read for: IPAM pool selection defaults, FIB
  table id, and the source-IP-verification delegation gate.
- **Service and EndpointSlice annotations** are read by the LB layer (spec 05);
  this spec only fixes the keys.

### 3.9 Writers and patch types

Every write flowsdn makes, with its exact method. This table is the source for
capability rows C12–C17.

| Object | Operation | Method | Notes |
|---|---|---|---|
| `CiliumEndpoint` | create | `POST` | `ownerReferences` → the Pod (or the endpoint's owner), `controller: true` |
| `CiliumEndpoint` | status update | `PATCH` type `application/json-patch+json` on the **object** (no subresource) with `[{"op":"test","path":"/metadata/uid","value":<uid>},{"op":"replace","path":"/status","value":<status>}]` | The `test` op makes the patch a no-op-or-fail if the CEP was recreated under a new UID. A `409 Conflict` is not an error: the next controller run retries |
| `CiliumEndpoint` | delete | `DELETE` | on endpoint removal; kube GC via ownerReference is the backstop |
| `CiliumNode` | create/update | `POST` / `PUT` | own node object |
| `CiliumNode` | status | `PUT` on `ciliumnodes/<name>/status` | IPAM status (spec 07) |
| `CiliumIdentity` | create | `POST` with `metadata.name` = the decimal identity | uniqueness on `metadata.name` is the allocation race resolver (C28) |
| `CiliumIdentity` | update | `PUT` | to clear the `io.cilium.heartbeat` annotation when re-acquiring |
| `CiliumL2AnnouncementPolicy` | status | `PATCH` JSON patch on `…/status` | `fieldManager: cilium-agent-l2-announcer` |
| `CiliumBGPNodeConfig` | status | `PATCH` JSON patch on `…/status` | agent side |
| `nodes/<name>/status` | annotations | `PATCH` strategic merge | `annotateK8sNode` (§3.8) |
| `nodes/<name>/status` | `NetworkUnavailable=False`, reason `CiliumIsUp` | `PATCH` strategic merge with `{"status":{"conditions":[…]}}` | operator; conditions merge on key `type` |
| `nodes/<name>` | taint removal / addition | `PATCH` JSON patch `[{"op":"test","path":"/spec/taints","value":<old>},{"op":"replace","path":"/spec/taints","value":<new>}]` | operator; the `test` op is the optimistic-concurrency mechanism |
| `CiliumLoadBalancerIPPool` | status | `PATCH` JSON patch on `…/status` | operator, `fieldManager: cilium-operator-lb-ipam` |
| `CiliumNetworkPolicy` / `CiliumClusterwideNetworkPolicy` | `status.conditions[Valid]` | `PUT` on `…/status` | operator validator |
| `CiliumCIDRGroup` | create/update | `POST`/`PUT`, `fieldManager: cilium.io/external-group-controller` | operator, `toGroups` derivation |
| `CiliumEndpointSlice` | full CRUD | `POST`/`PUT`/`DELETE`/`deletecollection` | operator CES controller |
| `CiliumPodIPPool` | create | `POST` | operator auto-creates the default pool |
| `Lease` | create/get/update | `POST`/`GET`/`PUT` | leader election, L2 announcements |
| `v1 events` | create/patch | `POST`/`PATCH` | Hubble drop emitter, optional |
| `customresourcedefinitions` | create/update | `POST`/`PUT` | operator registration (§3.2) |

**Server-side apply MUST NOT be used.** flowsdn issues no
`application/apply-patch+yaml` request. `fieldManager` is set on some writes
purely so `kubectl get -o yaml --show-managed-fields` attributes them; it does
not imply apply semantics.

### 3.10 Version detection and refusal

At startup, after the connectivity probe and before any watcher:

1. `GET /version`.
2. Parse `gitVersion` as semver; strip a leading `v`; tolerate pre-release and
   build metadata (`v1.33.4+rustkube.2` is valid and compares as 1.33.4).
3. If `gitVersion` is empty or unparseable, fall back to
   `<major>.<minor>` and treat the patch level as 0. `major`/`minor` may carry
   a `+` suffix (GKE style); strip trailing non-digits.
4. If both fail, this is a fatal startup error.
5. Compare against the floor (§10.2). Below the floor → fatal, with a message
   naming the detected version and the floor. Between the floor and the tested
   range → a single warning at startup and a `flowsdn_k8s_version_unsupported`
   gauge set to 1.
6. Record the version in the status API and in every support bundle.

Discovery (`GET /apis`) is **not** consulted. `--enable-k8s-api-discovery` is
accepted and ignored (§6); the reference plumbs it but never reads `/apis`
either.

`--k8s-force-version` (hidden) overrides detection for tests and for a server
whose `/version` is not representative; it MUST NOT be set in production and
its use MUST be logged at warn level.

## 4. Data model

### 4.1 CRD catalogue

Common to all 22: `apiVersion: apiextensions.k8s.io/v1`, group `cilium.io`,
CRD name `<plural>.cilium.io`, no `conversion` stanza (server default `None`),
label `io.cilium.k8s.crd.schema.version: 1.33.11` applied at registration, and
`metadata.annotations` dropped from the registration payload. **Storage version
in bold.** "Owner" is the sibling spec that owns the resource's semantics.

| Kind | Plural | Short names | Categories | Scope | Versions (served) | Subres. | Printer columns | Owner spec |
|---|---|---|---|---|---|---|---|---|
| CiliumNetworkPolicy | ciliumnetworkpolicies | cnp, ciliumnp | cilium, ciliumpolicy | Namespaced | **v2** | status | Age (date, `.metadata.creationTimestamp`); Valid (string, `.status.conditions[?(@.type=='Valid')].status`) | 06 |
| CiliumClusterwideNetworkPolicy | ciliumclusterwidenetworkpolicies | ccnp | cilium, ciliumpolicy | Cluster | **v2** | status | Valid (string, same path) | 06 |
| CiliumCIDRGroup | ciliumcidrgroups | ccg | cilium | Cluster | **v2**, v2alpha1 (deprecated) | – | none | 06 |
| CiliumEndpoint | ciliumendpoints | cep, ciliumep | cilium | Namespaced | **v2** | **none** | Security Identity (integer, `.status.identity.id`); Ingress Enforcement (string, `.status.policy.ingress.state`, prio 1); Egress Enforcement (string, `.status.policy.egress.state`, prio 1); Endpoint State (string, `.status.state`); IPv4 (string, `.status.networking.addressing[0].ipv4`); IPv6 (string, `…ipv6`) | 08 |
| CiliumEndpointSlice | ciliumendpointslices | ces | cilium | Cluster | **v2alpha1** | – | none | 12 |
| CiliumIdentity | ciliumidentities | ciliumid | cilium | Cluster | **v2** | status (unused) | Namespace (string, `.metadata.labels.io\.kubernetes\.pod\.namespace`); Age (date) | 03 |
| CiliumNode | ciliumnodes | cn, ciliumn | cilium | Cluster | **v2** | status | CiliumInternalIP (string, `.spec.addresses[?(@.type=="CiliumInternalIP")].ip`); InternalIP (string, `…"InternalIP"…`); Age (date) | 07 |
| CiliumNodeConfig | ciliumnodeconfigs | – | cilium | Namespaced | **v2** | – | none | 00 |
| CiliumLocalRedirectPolicy | ciliumlocalredirectpolicies | clrp | cilium, ciliumpolicy | Namespaced | **v2** | – | Age (date) | 05 |
| CiliumEgressGatewayPolicy | ciliumegressgatewaypolicies | cegp | cilium, ciliumpolicy | Cluster | **v2** | – | Age (date) | 14 |
| CiliumEnvoyConfig | ciliumenvoyconfigs | cec | cilium | Namespaced | **v2** | – | Age (date) | 16 |
| CiliumClusterwideEnvoyConfig | ciliumclusterwideenvoyconfigs | ccec | cilium | Cluster | **v2** | – | Age (date) | 16 |
| CiliumLoadBalancerIPPool | ciliumloadbalancerippools | ippools, ippool, lbippool, lbippools | cilium | Cluster | **v2**, v2alpha1 (deprecated) | status | Disabled (boolean, `.spec.disabled`); Conflicting (string, `.status.conditions[?(@.type=="cilium.io/PoolConflict")].status`); IPs Available (string, `.status.conditions[?(@.type=="cilium.io/IPsAvailable")].message`); Age (date) | 05 |
| CiliumL2AnnouncementPolicy | ciliuml2announcementpolicies | l2announcement | cilium | Cluster | **v2alpha1** | status | Age (date) | 05 |
| CiliumPodIPPool | ciliumpodippools | cpip | cilium | Cluster | **v2alpha1** | – | none | 07 |
| CiliumBGPClusterConfig | ciliumbgpclusterconfigs | cbgpcluster | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | status | Age (date) | 15 |
| CiliumBGPPeerConfig | ciliumbgppeerconfigs | cbgppeer | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | status | Age (date) | 15 |
| CiliumBGPAdvertisement | ciliumbgpadvertisements | cbgpadvert | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | – | Age (date) | 15 |
| CiliumBGPNodeConfig | ciliumbgpnodeconfigs | cbgpnode | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | status | Age (date) | 15 |
| CiliumBGPNodeConfigOverride | ciliumbgpnodeconfigoverrides | cbgpnodeoverride | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | – | Age (date) | 15 |
| CiliumGatewayClassConfig | ciliumgatewayclassconfigs | cgcc | cilium | Namespaced | **v2alpha1** | status | Accepted (string, `.status.conditions[?(@.type=="Accepted")].status`); Age (date); Description (string, `.spec.description`, prio 1) | wave 4 |
| CiliumDatapathPlugin | ciliumdatapathplugins | cddp | cilium | Cluster | **v2alpha1** (marked `deprecated: true`) | – | none | 02 |

For each of the 22, the following is normative:

> flowsdn MUST vendor the reference YAML for this CRD byte-for-byte (§3.1), MUST
> register it with the payload of §3.2, and MUST provide a Rust type that
> round-trips every document valid against its schema. Test **T-CRD-3** (schema
> ↔ type diff) and **T-CRD-4** (instance round-trip) MUST pass for it in CI, and
> **T-CRD-6** MUST match the golden registration payload. The field semantics
> are owned by the spec named in the "Owner spec" column; this spec does not
> restate them.

Version and deprecation policy inherited from the reference: a new CRD starts
at `v2alpha1`; graduation adds a `v2` served + storage version with a
**byte-identical schema** and marks `v2alpha1` `served: true, storage: false,
deprecated: true` with no `deprecationWarning` and no conversion webhook.
Removal of a served version has not happened for any CRD and MUST NOT happen in
flowsdn without a decision record. Seven CRDs have graduated: CiliumCIDRGroup,
CiliumLoadBalancerIPPool, and all five BGP CRDs listed above.

`CiliumDatapathPlugin` is served as `v2alpha1` **and** flagged `deprecated:
true` in the same (only) version; this is intentional in the reference and
flowsdn reproduces it verbatim rather than "fixing" it.

### 4.2 Vendored file layout

```
crates/flowsdn-k8s/crds/
  SHA256SUMS                 # one line per file, produced by tools/vendor-crds.sh
  LICENSE-CILIUM             # source path, commit 7d68cfb394, Apache-2.0
  known-diffs.toml           # T-CRD-3a suppressions, each with a reason
  v2/       ciliumbgpadvertisements.yaml … ciliumnodes.yaml           (17 files)
  v2alpha1/ ciliumdatapathplugins.yaml … ciliumpodippools.yaml         (5 files)
```

The `v2` directory holds 17 documents and the `v2alpha1` directory 5, totalling
22 CRDs and 20,112 YAML lines, of which `ciliumnetworkpolicies.yaml` (6,552)
and `ciliumclusterwidenetworkpolicies.yaml` (6,554) are two thirds. The two
policy schemas are identical modulo kind/plural names, scope and the missing
`Age` printer column on CCNP; flowsdn's Rust types for CNP and CCNP MUST share
one `spec` type.

### 4.3 Slim types — the exact field subset

Every type below embeds `TypeMeta { kind, apiVersion }` and the slim
`ObjectMeta`. Deserialization is lossy by construction: everything not listed
is skipped by the decoder. The reason is memory — an agent on a 250-pod node
holds these objects for the life of the process, and a full `Pod` type is
roughly an order of magnitude larger than the subset below.

| Type | Fields kept |
|---|---|
| `meta/v1.ObjectMeta` | `name`, `generateName`, `namespace`, `uid`, `resourceVersion`, `generation`, `deletionTimestamp`, `labels`, `annotations`, `ownerReferences[]{apiVersion,kind,name,uid,controller}`. **Not kept**: `creationTimestamp`, `finalizers`, `managedFields`, `deletionGracePeriodSeconds`, `selfLink`. `managedFields` alone can be kilobytes per object on a cluster with several controllers |
| `meta/v1.ListMeta` | `resourceVersion`, `continue`, `remainingItemCount` |
| `meta/v1.LabelSelector` | `matchLabels`, `matchExpressions[]{key,operator,values}` |
| `meta/v1.Condition` | `type`, `status`, `observedGeneration`, `lastTransitionTime`, `reason`, `message` |
| `meta/v1.PartialObjectMetadata(List)` | TypeMeta + ObjectMeta (+ ListMeta) only |
| `core/v1.Pod` | `spec{ initContainers[], containers[]{name,image,ports[]{name,hostPort,containerPort,protocol,hostIP},volumeMounts[]{mountPath}}, serviceAccountName, nodeName, hostNetwork }`; `status{ phase, conditions[]{type,status,lastProbeTime,lastTransitionTime,reason,message}, hostIP, podIP, podIPs[]{ip}, startTime, containerStatuses[]{state{running{startedAt}},containerID}, qosClass }`. **Not kept**: volumes, resources, env, tolerations, affinity, securityContext, probes — none of which affect the datapath |
| `core/v1.Service` | `spec{ ports[]{name,protocol,appProtocol,port,targetPort,nodePort}, selector, clusterIP, clusterIPs, type, externalIPs, sessionAffinity, loadBalancerIP, loadBalancerSourceRanges, externalTrafficPolicy, healthCheckNodePort, sessionAffinityConfig{clientIP{timeoutSeconds}}, ipFamilies, ipFamilyPolicy, loadBalancerClass, internalTrafficPolicy, trafficDistribution }`; `status{ loadBalancer{ingress[]{ip,hostname,ipMode,ports[]{port,protocol,error}}}, conditions[] }` |
| `core/v1.Node` | `spec{ podCIDR, podCIDRs, providerID, taints[]{key,value,effect,timeAdded} }`; `status{ conditions[]{type,status,reason}, addresses[]{type,address} }`. Labels and annotations come from ObjectMeta |
| `core/v1.Namespace` | metadata only — no `spec`, no `status` |
| `core/v1.Secret` | `immutable`, `data` (map of base64 bytes), `stringData`, `type` |
| `core/v1.TypedLocalObjectReference` | `apiGroup`, `kind`, `name` |
| `discovery/v1.EndpointSlice` | `addressType`; `endpoints[]{ addresses, conditions{ready,serving,terminating}, hostname, deprecatedTopology, nodeName, zone, hints{forZones[]{name}} }`; `ports[]{name,protocol,port,appProtocol}`. The owning Service is read from the metadata label `kubernetes.io/service-name` |
| `networking/v1.NetworkPolicy` | `spec{ podSelector, ingress[]{ports[]{protocol,port,endPort},from[]}, egress[]{ports[],to[]}, policyTypes }`, where a peer is `{podSelector, namespaceSelector, ipBlock{cidr,except}}` |
| internal `CiliumEndpoint` (transformed) | ObjectMeta + `Identity{id,labels}`, `Networking{addressing[],node}`, `Encryption{key}`, `NamedPorts`, `ServiceAccount`. Produced from a full CEP by a transform applied **before** the object enters the store, so the full CEP is never retained |

Full (non-slim) types are used for: every `cilium.io` CRD,
`apiextensions.k8s.io/v1 CustomResourceDefinition` (operator only — the agent
uses `PartialObjectMetadata`), `coordination.k8s.io/v1 Lease`,
`core/v1 ConfigMap`, `core/v1 Event`, and
`policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy`.

### 4.4 Annotations

flowsdn MUST recognize every key below. Where a legacy alias exists, both are
accepted and the new key wins.

| Key (legacy alias) | On | Read/Write | Meaning |
|---|---|---|---|
| `policy.cilium.io/name` (`io.cilium.name`) | NetworkPolicy | R | legacy policy-node name |
| `policy.cilium.io/no-track-port` (`io.cilium.no-track-port`) | Pod | R | ports bypassing conntrack (NodeLocal DNS) |
| `network.cilium.io/no-track-host-ports` | Pod, Node | R | host ports bypassing conntrack |
| `network.cilium.io/ipv4-pod-cidr`, `ipv6-pod-cidr` (`io.cilium.network.*`) | Node | R/W | pod CIDR |
| `network.cilium.io/ipv4-cilium-host`, `ipv6-cilium-host` (`io.cilium.network.*`) | Node | R/W | router IP on `cilium_host` |
| `network.cilium.io/ipv4-health-ip`, `ipv6-health-ip` | Node | R/W | health endpoint IP |
| `network.cilium.io/ipv4-Ingress-ip`, `ipv6-Ingress-ip` | Node | R/W | Ingress listener IP (capital `I` is intentional) |
| `network.cilium.io/encryption-key` | Node | R/W | IPsec key index |
| `network.cilium.io/wg-pub-key` | CiliumNode | R/W | WireGuard public key |
| `network.cilium.io/fib-table-id` | Pod, Namespace | R | FIB table for egress routing |
| `config.cilium.io/delegate-source-ip-verification` | Namespace | R | admin gate letting pods opt out |
| `config.cilium.io/disable-source-ip-verification` | Pod | R | opt out, only if the namespace delegates |
| `config.cilium.io/<key>` | Node (label or annotation) | R | per-node config override (spec 00 §3.3) |
| `cni.cilium.io/mac-address` | Pod | W (by the CNI plugin), R | MAC assigned to the pod |
| `service.cilium.io/global` (`io.cilium/global-service`) | Service | R | ClusterMesh global service |
| `service.cilium.io/shared` (`io.cilium/shared-service`) | Service | R | share local backends |
| `service.cilium.io/affinity` (`io.cilium/service-affinity`) | Service | R | `local`/`remote`/`none` |
| `service.cilium.io/global-sync-endpoint-slices` | Service | R | mirror remote slices locally |
| `service.cilium.io/lb-algorithm` | Service | R | `random`/`maglev` |
| `service.cilium.io/weight` | EndpointSlice | R | LB weight for all backends in the slice; 0 = maintenance |
| `service.cilium.io/node`, `service.cilium.io/node-selector` | Service | R | expose only on matching nodes |
| `service.cilium.io/type` | Service | R | provision only `ClusterIP`/`NodePort`/`LoadBalancer` |
| `service.cilium.io/src-ranges-policy` | Service | R | `allow`/`deny` for `loadBalancerSourceRanges` |
| `service.cilium.io/proxy-delegation` | Service | R | `none`/`delegate-if-local` |
| `service.cilium.io/forwarding-mode` | Service | R | `dsr`/`snat` |
| `service.cilium.io/lb-l7` | Service | R | L7 LB via Envoy |
| `ipam.cilium.io/ip-pool`, `ipv4-pool`, `ipv6-pool` | Pod, Namespace | R | multi-pool selection |
| `ipam.cilium.io/ignore` | CiliumNode | R | operator IPAM skips this node |
| `ipam.cilium.io/require-pool-match` | Pod, Namespace | R | no fallback to the default pool |
| `ipam.cilium.io/skip-masquerade` | CiliumPodIPPool | R | no masquerade for this pool in tunnel mode |
| `lbipam.cilium.io/ips` (`io.cilium/lb-ipam-ips`) | Service | R | requested LB IPs |
| `lbipam.cilium.io/sharing-key` (`io.cilium/lb-ipam-sharing-key`) | Service | R | share one LB IP |
| `lbipam.cilium.io/sharing-cross-namespace` (`io.cilium/lb-ipam-sharing-cross-namespace`) | Service | R | allow cross-namespace sharing |
| `cec.cilium.io/inject-cilium-filters`, `cec.cilium.io/is-l7lb`, `cec.cilium.io/use-original-source-address` | CiliumEnvoyConfig | R | Envoy listener behavior |
| `clustermesh.cilium.io/global` | Namespace | R | export namespace (MCS-API) |
| `clustermesh.cilium.io/supported-ip-families`, `clustermesh.cilium.io/autoPatchedAt` | Service, CoreDNS Deployment | R/W | MCS-API internals |
| `ingress.cilium.io/loadbalancer-mode`, `tls-passthrough`, `host-listener-port`, `force-https`, `service-external-traffic-policy`, `loadbalancer-class`, `service-type`, `secure-node-port`, `insecure-node-port` | Ingress | R | Ingress controller knobs |
| `io.cilium.heartbeat` | CiliumIdentity | R/W | GC heartbeat timestamp, RFC3339Nano |
| `secretsync.cilium.io/*`, `mesh.cilium.io/*`, `gateway.cilium.io/*`, `io.cilium.gateway/owning-gateway` | operator-managed objects | R/W | ownership bookkeeping |

**DEVIATION (dropped):** `cilium.io/bgp-virtual-router.<asn>` (legacy BGP
annotation, superseded by the BGP CRDs) is **not** honored. Reason: the
reference already treats it as legacy and the CRD path is the documented one;
honoring it would require a second BGP configuration source. A node carrying it
logs a warning naming the CRD replacement.

### 4.5 Labels

| Label | Set by | Meaning |
|---|---|---|
| `io.kubernetes.pod.namespace` | flowsdn (identity synthesis) | pod's namespace |
| `io.cilium.k8s.namespace.labels.<k>` | flowsdn | mirror of the Namespace's label `<k>` |
| `io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name` | flowsdn (via the above) | the reliable namespace selector |
| `io.cilium.k8s.policy.serviceaccount` | flowsdn | pod's service account |
| `io.cilium.k8s.policy.cluster` | flowsdn | cluster name |
| `io.cilium.k8s.named-ports` | flowsdn | marker that the pod declares named ports |
| `io.cilium.k8s.policy.{name,uid,namespace,derived-from}` | flowsdn | policy provenance (§3.7) |
| `io.cilium.fixed-identity` | user, on a Pod | pin a well-known identity |
| `io.cilium.k8s.crd.schema.version` | flowsdn operator, on CRD objects | schema version for the update comparison |
| `service.kubernetes.io/service-proxy-name` | user/other proxy, on a Service | watch selector (§3.3.1) |
| `service.kubernetes.io/headless` | Kubernetes, on a Service | watch selector |
| `endpointslice.kubernetes.io/managed-by` | Kubernetes/ClusterMesh | watch selector |
| `kubernetes.io/service-name` | Kubernetes, on an EndpointSlice | owning Service |

**Node taints.** `node.cilium.io/agent-not-ready` (key configurable with
`--agent-not-ready-taint-key`), effect `NoSchedule`. The operator removes it
once the agent pod on that node is running (`--remove-cilium-node-taints`,
default true) and can add it (`--set-cilium-node-taints`); both use the
JSON-patch `test`+`replace` on `/spec/taints` of §3.9. `--set-cilium-is-up-condition`
(default true) sets `NetworkUnavailable=False`, reason `CiliumIsUp`, message
"Cilium is running on this node".

### 4.6 Files

| Path | Written by | Read by |
|---|---|---|
| `<state-dir>/k8sapi_server_state.json` | client, on API-server service takeover (§3.5) | client, on the next start |
| kubeconfig at `--k8s-kubeconfig-path` | administrator | client |
| `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}` | kubelet | client (in-cluster path) |
| `--label-prefix-file` | administrator | label filter (§3.7) |

### 4.7 RBAC — agent ClusterRole

The agent's ClusterRole MUST grant exactly the following, with the conditional
rules omitted when the feature is off. It MUST NOT grant `create` or `update`
on `customresourcedefinitions` (registration is the operator's job) and MUST
NOT grant any write on `pods`, `services`, `namespaces` or `endpointslices`.

| apiGroup | Resources | Verbs | Condition |
|---|---|---|---|
| `networking.k8s.io` | `networkpolicies` | get, list, watch | always |
| `discovery.k8s.io` | `endpointslices` | get, list, watch | always |
| `""` | `namespaces`, `services`, `pods`, `nodes` | get, list, watch | always |
| `""` | `secrets` | get, list, watch | unless secrets are read only from the policy-secrets namespace |
| `""` | `events` | create, patch | Hubble drop-event emitter enabled |
| `""` | `nodes/status` | patch | `annotateK8sNode` enabled |
| `coordination.k8s.io` | `leases` | create, get, update, list, delete | L2 announcements enabled |
| `apiextensions.k8s.io` | `customresourcedefinitions` | list, watch, get | always |
| `cilium.io` | `ciliumloadbalancerippools`, `ciliumbgpnodeconfigs`, `ciliumbgpadvertisements`, `ciliumbgppeerconfigs`, `ciliumclusterwideenvoyconfigs`, `ciliumclusterwidenetworkpolicies`, `ciliumegressgatewaypolicies`, `ciliumendpoints`, `ciliumendpointslices`, `ciliumenvoyconfigs`, `ciliumidentities`, `ciliumlocalredirectpolicies`, `ciliumnetworkpolicies`, `ciliumnodes`, `ciliumnodeconfigs`, `ciliumcidrgroups`, `ciliuml2announcementpolicies`, `ciliumpodippools`, `ciliumdatapathplugins` | list, watch | always |
| `cilium.io` | `ciliumidentities`, `ciliumendpoints`, `ciliumnodes` | create | always |
| `cilium.io` | `ciliumidentities` | update | always (heartbeat-annotation removal) |
| `cilium.io` | `ciliumendpoints` | delete, get | always |
| `cilium.io` | `ciliumnodes`, `ciliumnodes/status` | get, update | always |
| `cilium.io` | `ciliumendpoints/status`, `ciliumendpoints`, `ciliuml2announcementpolicies/status`, `ciliumbgpnodeconfigs/status` | patch | always |
| `policy.networking.k8s.io` | `clusternetworkpolicies` | get, list, watch | `enable-k8s-cluster-network-policy` |

Note `ciliumendpoints` appears in the `patch` rule **without** a subresource:
that is what makes the whole-object JSON patch of §3.9 legal, and it is the
RBAC consequence of CEP having no status subresource (C13).

The operator ClusterRole is specified in `12-operator`; it is a superset of the
verbs implied by §3.4 and §3.9, plus `update` on
`customresourcedefinitions` restricted by `resourceNames` to the 22 CRD names.

## 5. Algorithms

### 5.1 CRD needs-update comparison

```
needs_update(target, current) -> bool:
    if current.spec.versions[0].schema is absent:            return true
    v = current.metadata.labels["io.cilium.k8s.crd.schema.version"]
    if v is absent:                                          return true
    if v does not parse as semver:                           return true
    if semver(v) < semver("1.33.11"):                        return true
    return false
```

The comparison is deliberately one-directional: a cluster whose CRDs carry a
*newer* schema version is left untouched, so rolling back one node's operator
does not roll back the cluster's schemas.

### 5.2 Reflector and change delivery

Each watcher is a list-then-watch loop feeding a table (spec 00 §3.1):

1. Await the CRD fence (for `cilium.io` resources only).
2. LIST with `resourceVersion=0` (any cached version is acceptable for the
   initial fill). If the server rejects it, retry with a consistent read and
   page with `limit=500`, following `metadata.continue`.
3. Insert every listed object into the table in **one** write transaction, then
   delete every row in the table that was not in the list (a full replace).
   Mark the table initialized; this is what the cache-sync fence waits on.
4. WATCH from the list's `resourceVersion` with `allowWatchBookmarks=true`.
5. Batch incoming events: commit when either 10,000 objects have accumulated or
   50 ms have elapsed since the first buffered event, whichever comes first
   (≈200k objects/s ceiling, and the batching is what keeps table revisions
   from churning once per event on a large cluster).
6. On `410 Gone`, or any watch error, go to step 2 with exponential backoff.
   The table is **not** cleared before the new list completes; step 3's replace
   is the only pruning point.
7. Bookmark events advance the stored `resourceVersion` and are otherwise
   ignored. flowsdn MUST work correctly if no bookmark ever arrives.

Per-key consumer retries (a reconciler that failed to program a row) use an
exponential per-item rate limiter with a 5 ms base doubling to a 1,000 s cap,
overlaid with a global 10 items/s, burst 100 bucket — the client-go default
controller rate limiter, kept so failure storms behave the way operators
expect.

### 5.3 Lazy transform

The `CiliumEndpoint` watcher decodes the full CEP and immediately projects it
to the internal slim CEP (§4.3) **before** insertion, so the store never holds
the full object. Indexers run on the projected object. A projection that
returns "skip" (e.g. a CEP with no networking status) removes the key rather
than storing a partial row.

### 5.4 Selector string construction

Label selectors are serialized in the fixed order of §3.3.1 and joined with
`,`. Requirements use the forms `key`, `!key`, `key==value`, `key!=value`,
`key in (a,b)`, `key notin (a,b)`. Values are not quoted; a value containing a
character outside `[A-Za-z0-9._-]` is a configuration error caught at startup,
because the API server's selector parser would reject it at list time and the
resulting failure is far from its cause.

### 5.5 Unknown enum handling

For a string field with an `enum` in the schema, deserialization maps a known
value to the corresponding variant and anything else to `Unknown(s)`. The
consumer decides:

- A **selector-like** unknown value (e.g. an unknown `protocol`) MUST NOT match
  anything — fail closed.
- An **action-like** unknown value (e.g. an unknown `mismatch` action on a
  header match) MUST cause the enclosing rule to be rejected with a validation
  error surfaced on the object's status where one exists, and logged once per
  distinct value otherwise.
- A **cosmetic** unknown value (e.g. an unknown `state` string on a CEP written
  by another implementation) is passed through unchanged.

## 6. Configuration

Keys owned by this spec. All are registered in the config registry of spec 00
§6.4 and keep their reference names.

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-k8s` | bool | true | master switch; false runs flowsdn without any Kubernetes integration |
| `k8s-api-server-urls` | list | `[]` | API server URLs; >1 enables random selection and rotation (§3.5) |
| `k8s-kubeconfig-path` | string | `""` | absolute path to a kubeconfig; highest precedence |
| `k8s-client-qps` | float | 10.0 | client-side rate limit |
| `k8s-client-burst` | int | 20 | client-side burst |
| `k8s-client-connection-timeout` | duration | 30s | dial timeout; 0 disables the rotating dialer |
| `k8s-client-connection-keep-alive` | duration | 30s | TCP keep-alive; 0 disables the rotating dialer |
| `k8s-heartbeat-timeout` | duration | 30s | `/readyz` probe period and deadline; 0 disables the heartbeat |
| `k8s-service-proxy-name` | string | `""` | value of `service.kubernetes.io/service-proxy-name` this instance handles |
| `enable-headless-service-watch` | bool | true | when false, headless Services and their slices are excluded (§3.3.1) |
| `k8s-sync-timeout` | duration | 3m (hidden) | time since the last event on a group before a stalled initial sync is fatal |
| `crd-wait-timeout` | duration | 5m | time to wait for all required CRDs before exiting |
| `skip-crd-creation` | bool | false | operator only: do not create or update CRDs |
| `enable-k8s-host-firewall-bypass` | bool | true (hidden) | `SO_MARK` on API-server sockets |
| `enable-k8s-networkpolicy` | bool | true (hidden) | watch `networking.k8s.io/v1 NetworkPolicy` |
| `enable-k8s-cluster-network-policy` | bool | false (hidden) | watch `policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy` |
| `enable-cilium-network-policy` | bool | true | watch CNP; adds it to the CRD required set |
| `enable-cilium-clusterwide-network-policy` | bool | true | watch CCNP; adds it to the required set |
| `enable-ciliumnode-crd` | bool | true (hidden) | watch/write CiliumNode |
| `disable-endpoint-crd` | bool | false | stop creating CiliumEndpoints |
| `enable-cilium-endpoint-slice` | bool | false | consume CiliumEndpointSlices instead of CEPs |
| `annotate-k8s-node` | bool | false | write node annotations (§3.8) |
| `k8s-require-ipv4-pod-cidr` | bool | false | a missing IPv4 PodCIDR on the Node is fatal |
| `k8s-require-ipv6-pod-cidr` | bool | false | as above for IPv6 |
| `exclude-node-label-patterns` | list of regex | `[]` | node labels matching are dropped before use |
| `labels` | list | `[]` | appended to the identity-relevance filter (§3.7) |
| `label-prefix-file` | path | `""` | replaces the default filter list |
| `node-labels` | list | `[]` | filter list for node identities |
| `enable-node-selector-labels` | bool | false | enable node-label-based selectors |
| `agent-not-ready-taint-key` | string | `node.cilium.io/agent-not-ready` | taint key the operator manages |
| `k8s-force-version` | string | `""` (hidden) | override version detection; test only |
| `user-agent` | string | `""` | suffix appended to the user agent |

Accepted and ignored, with the reason:

| Key | Reason |
|---|---|
| `enable-k8s-api-discovery` | Nothing reads `/apis`. The reference plumbs the flag and never consults discovery either (§3.10). Setting it logs an informational message |
| `k8s-api-server` (singular) | Removed upstream in favor of `k8s-api-server-urls`. Accepted as a one-element list with a deprecation warning for one release |
| `enable-k8s-endpoint-slice` | EndpointSlices are the only backend source; `core/v1 Endpoints` is not watched at all |
| `k8s-watcher-endpoint-selector`, `k8s-event-handover`, `disable-cnp-status-updates`, `cnp-node-status-gc-interval` | Removed upstream; no behavior attached |

Environment variables follow spec 00 §2: `CILIUM_` + key upper-cased with `-` →
`_`. `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT`, `K8S_NODE_NAME` and
`DISABLE_HTTP2` are read directly and are not config keys.

## 7. Failure modes

| # | Failure | Behavior |
|---|---|---|
| F1 | API server unreachable **at startup** | Probe `kube-system` every 5 s for 60 s, rotating URLs. On expiry: exit non-zero, log the last host and error. The datapath is never programmed from an empty cache |
| F2 | API server unreachable **at runtime** | Never fatal. Watches back off and retry; tables keep their last state; reconcilers do not prune; `k8s-client` module reports `Degraded`; heartbeat rotates the URL and closes idle connections |
| F3 | Heartbeat returns 429 | Not treated as a failure; no rotation, no connection close |
| F4 | CRDs missing at startup | Block on the readiness watch; log the missing names every ~1 s; at `crd-wait-timeout` (5 m) exit non-zero naming the missing CRDs and the operator |
| F5 | `PartialObjectMetadata` negotiation unsupported | The `Accept` header lists `application/json` last, so the server returns full CRD objects. flowsdn parses them, keeps only the metadata, and logs a warning that CRD-watch memory is elevated. Not fatal |
| F6 | Field selector `spec.nodeName` rejected or silently ignored | Fatal at startup. flowsdn issues a probe LIST with `limit=1` and the selector against a pod name it knows is on another node; if the selector is ignored the agent exits rather than silently watching every pod in the cluster |
| F7 | Label selector rejected | Fatal at startup for the Service/EndpointSlice watchers — the alternative is handling services owned by another proxy |
| F8 | CRD schema in the cluster is **newer** than flowsdn's | Registration leaves it alone (§5.1). The agent may fail to deserialize a field a newer CRD allows; because no type denies unknown fields, this degrades to ignoring the field. Logged once per resource kind |
| F9 | CRD schema in the cluster is **older** | The operator updates it. Until then, writes of new fields are pruned server-side; flowsdn logs the mismatch and continues |
| F10 | CRD deleted while flowsdn runs | The readiness watcher flips the entry to absent; the affected watchers stop with an error and the module reports `Degraded`. flowsdn does **not** exit and does not delete the datapath state derived from the CRD |
| F11 | `410 Gone` on a watch | Relist from scratch; replace the table; reconcilers prune on the replace. Counted in `flowsdn_k8s_watch_relist_total` |
| F12 | `409 Conflict` on a status write | Not an error. Retry on the next controller tick with fresh state; log at debug |
| F13 | JSON-patch `test` op fails (CEP UID changed, taint list changed) | The patch is rejected atomically. Re-read and retry; for CEP, mark the local record as needing re-initialization |
| F14 | Two operators race to create a CRD | `409 AlreadyExists` on create is success; `409 Conflict` on update retries the poll |
| F15 | Server does not implement CEL (C3) | CRs that should be rejected are accepted. flowsdn MUST NOT compensate by re-validating client-side in the first cut; instead the conformance suite (§9.5) fails and the gap is documented for that server. Open decision §12.4 |
| F16 | Server does not implement schema defaulting (C4) | Fields flowsdn expects to be defaulted arrive absent. flowsdn's Rust types carry `#[serde(default)]` with the **same** default value as the schema, so this degrades correctly. The defaults are asserted equal to the schema's by test T-CRD-8 (§9.1) |
| F17 | Server does not implement the status subresource (C12) | A status write would clobber spec. flowsdn probes at startup by writing an empty status patch to its own CiliumNode and verifying `metadata.generation` did not change; on failure it refuses to start |
| F18 | Restart mid-operation | Every write in §3.9 is idempotent: creates tolerate `AlreadyExists`, status writes are last-writer-wins with a `test` guard, and the identity allocator's `Create` race is resolved by name uniqueness (spec 03) |
| F19 | Kubeconfig or service-account token expires/rotates | The client re-reads the token file on each request (in-cluster path). An expired kubeconfig produces 401s: the module reports `Degraded` and the heartbeat rotates; not fatal at runtime, fatal at startup (F1) |
| F20 | Clock skew making `io.cilium.heartbeat` timestamps look stale | Identity GC is the operator's concern (spec 03/12); this layer only stores the RFC3339Nano string verbatim |

## 8. Observability

**Metrics.** Reference-compatible names are kept where dashboards depend on
them.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `cilium_k8s_client_api_calls_total` | counter | `host`, `method`, `return_code` | every API request |
| `cilium_k8s_client_api_latency_time_seconds` | histogram | `path`, `method` | request latency |
| `cilium_k8s_event_received_total` | counter | `scope`, `action`, `valid`, `equal` | objects delivered by a watcher; `scope` is the metric name registered per resource (`Service`, `CiliumNode`, `CiliumEndpoint`, …) |
| `cilium_k8s_event_lag_seconds` | gauge | `source` | lag of the last processed event |
| `cilium_k8s_terminating_endpoints_events_total` | counter | — | terminating-backend events |
| `flowsdn_k8s_watch_relist_total` | counter | `resource` | `410 Gone` relists (flowsdn-specific) |
| `flowsdn_k8s_apiserver_rotations_total` | counter | `reason` | URL rotations, `reason` ∈ {startup, heartbeat} |
| `flowsdn_k8s_crd_wait_seconds` | gauge | — | time spent in the CRD readiness gate |
| `flowsdn_k8s_version_unsupported` | gauge | `version` | 1 when the detected version is below the tested range |

**Health.** Modules registered in the health registry (spec 00 §3.4):
`k8s-client` (connection, heartbeat, current host), `k8s-crd-sync` (missing
CRDs), and one `k8s-watcher/<resource>` per watcher (initialized, last event,
last error). `cilium-dbg status` surfaces them; the reference's
`k8sAPIGroups`/`k8sResources` fields in the status payload are preserved with
the same resource names so `cilium-dbg status --all-controllers` output stays
parseable.

**Logs.** Every log line from this layer carries `module=k8s`, plus `resource`
(GVR), `host` (API server), `name`/`namespace` where applicable. Rotation,
relist, CRD-wait progress, version detection and every fatal in §7 are logged
at info or higher. Deserialization of an unknown enum value logs once per
distinct value at debug with `resource`, `field`, `value`.

## 9. Test plan

### 9.1 CRD contract (unit, no cluster)

- [ ] **T-CRD-1** vendored file SHA-256 manifest matches.
- [ ] **T-CRD-2** CRD document round-trip for all 22.
- [ ] **T-CRD-3** generated schema vs vendored schema diff, per CRD per version.
- [ ] **T-CRD-3a** every `known-diffs.toml` entry still matches something.
- [ ] **T-CRD-4** golden CR instance round-trip; at minimum one per CRD, plus
      every example in the reference documentation and every fixture the
      sibling specs need.
- [ ] **T-CRD-5** unknown-field and unknown-enum tolerance on every golden CR.
- [ ] **T-CRD-6** registration payload golden comparison (name, label,
      annotations absent, names subset, no `listKind`, versions verbatim,
      `preserveUnknownFields=false`).
- [ ] **T-CRD-7** property test: arbitrary Rust values serialize to documents
      that pass structural validation against the vendored schema.
- [ ] **T-CRD-8** every `#[serde(default)]` value equals the schema's
      `default:` for that path, or the path has no schema default.
- [ ] CNP and CCNP share one `spec` type and their schemas differ only in
      scope, kind/plural names, the `Age` printer column and descriptions.
- [ ] Lint: no `deny_unknown_fields` anywhere in `flowsdn-k8s`.

### 9.2 Client (unit + fake server)

- [ ] Enablement matrix: each of the four enabling conditions in §3.5
      independently enables the client; none of them → disabled.
- [ ] Precedence: kubeconfig beats URL list beats in-cluster; `https://` URL
      takes in-cluster credentials with an overridden host; a scheme-less URL
      gets `https://`; an unparseable URL is skipped with a log.
- [ ] QPS/burst applied; 0 leaves the library default.
- [ ] Rotation: with N>1 URLs, the initial pick is random over many runs;
      rotation never picks the current URL; rotation stops after service
      takeover.
- [ ] Service takeover: mapping written to `k8sapi_server_state.json`,
      restored on the next start, connectivity-checked before use, and the URL
      list replaced by the endpoint list.
- [ ] Heartbeat: skipped when a recent successful interaction exists; rotates
      and closes connections on error and on deadline; does **not** rotate on
      429.
- [ ] Startup with an unreachable server exits non-zero after the retry budget
      (F1); runtime unreachability does not exit (F2).
- [ ] `DISABLE_HTTP2` switches the close-all behavior.
- [ ] Host-firewall bypass sets `SO_MARK` on both the dialer and the resolver's
      dialer.

### 9.3 Watchers and selectors

- [ ] Pod watch carries `spec.nodeName=<node>`; F6 probe fails the agent when
      the selector is ignored.
- [ ] Service/EndpointSlice selector strings for the four combinations of
      (`k8s-service-proxy-name` empty/set) × (`enable-headless-service-watch`
      true/false), plus the EndpointSlice `managed-by!=` requirement.
- [ ] No watcher sets a non-zero resync period.
- [ ] Batching: 10,000 events or 50 ms, whichever first; a burst of 25,000
      commits in three transactions.
- [ ] `410 Gone` relist replaces the table and prunes exactly the objects that
      disappeared.
- [ ] Bookmarks: correctness with bookmarks enabled, and identical correctness
      with a server that never sends one.
- [ ] Pagination: a 3,000-object list with `limit=500` produces 6 pages and one
      table replace; an expired `continue` token restarts the list.
- [ ] CEP lazy transform: the store holds only the projected type (asserted by
      a size probe), and indexers see the projected object.
- [ ] Indexers: namespace, `localNode`, identity-by-key, `pod-node`,
      `node-ip` return the expected key sets.

### 9.4 Registration, readiness and writers

- [ ] `needs_update` truth table: no schema, no label, unparseable label, older
      label, equal label, newer label.
- [ ] Create → `AlreadyExists` → success; update → `Conflict` → retry; wait for
      `Established`; `NamesAccepted=False` is fatal.
- [ ] The required-CRD set for each of the 13 configuration conditions in §3.2.
- [ ] `crd-wait-timeout` expiry exits non-zero naming the missing CRDs.
- [ ] CEP JSON patch: `test` on UID succeeds on match, and the whole patch is
      rejected on mismatch; `Conflict` is retried, not surfaced.
- [ ] Node annotate: strategic merge patch on `nodes/status`, only non-nil
      values, never deleting an annotation.
- [ ] Taint patch: `test`+`replace` on `/spec/taints`; a concurrent taint
      change makes the patch fail rather than clobber.
- [ ] No request in any test carries `Content-Type:
      application/apply-patch+yaml` (asserted by a request-recording client).

### 9.5 rustkube conformance suite

A standalone binary, `flowsdn-k8s-conformance`, that takes a kubeconfig and
exercises C1–C36 as independent named checks, each reporting
pass/fail/not-applicable with the request and response that decided it. It MUST
be runnable against upstream Kubernetes (where it must pass 100%) and against
rustkube, and it MUST NOT require flowsdn to be installed. Checks, one per
capability row:

- **C1** create the 22 CRDs, observe `Established=True`; delete and recreate
  one; create a CRD with a conflicting plural and observe `NamesAccepted=False`.
- **C2** apply a CR violating each of `pattern`, `enum`, `maxItems`,
  `minLength`, `format: cidr`, `maximum`; each must be rejected.
- **C3** apply a CNP with neither `spec` nor `specs` (must be rejected by the
  top-level CEL rule); mutate a field guarded by `self == oldSelf` (must be
  rejected).
- **C4** create a CNP with an ICMP field lacking `family`; read it back and
  assert `family: IPv4`.
- **C5** create a CNP with ICMP `type` as an integer and as a string; both must
  round-trip in the form written.
- **C6** append a condition to `status.conditions` twice with the same `type`;
  assert one entry, merged.
- **C7/C8** an atomic list replaces wholesale; a
  `x-kubernetes-preserve-unknown-fields` subtree survives a round-trip with
  unknown keys.
- **C9** a CNP with both `endpointSelector` and `nodeSelector` is rejected; a
  `toPorts[].rules` with both `http` and `dns` is rejected.
- **C10** GET a CIDRGroup created as `v2alpha1` through the `v2` endpoint and
  vice versa; both must succeed with identical content.
- **C11** `kubectl get` (or a Table request) returns the declared columns.
- **C12** write `spec` through the status endpoint (must be ignored) and
  `status` through the main endpoint on a CRD with the subresource (must be
  ignored); assert `metadata.generation` only advances on spec changes.
- **C13** patch a CiliumEndpoint's `status` through the main endpoint; must
  succeed.
- **C14** a JSON patch whose `test` op fails must leave the object unchanged
  and return 409/422.
- **C15** a strategic merge patch on `nodes/status` merges annotations and
  merges conditions on `type` rather than replacing the array.
- **C16** a merge patch nulls a field.
- **C17** (negative) not exercised; the suite asserts flowsdn's own request
  recorder saw no apply patch.
- **C18** list pods with `spec.nodeName=<node>` and assert the returned set is
  exactly that node's pods; repeat with `status.phase=Running`.
- **C19** each of the seven selector operators returns the expected set.
- **C20** the `PartialObjectMetadataList` Accept header returns metadata-only
  objects; the fallback path is exercised by removing that media type.
- **C21** request `application/vnd.kubernetes.protobuf` on `pods`; pass, or
  report not-applicable if the server returns JSON.
- **C22** list 3,000 objects with `limit=500`; assert `continue` and
  `remainingItemCount`; assert 410 on a stale token.
- **C23** watch from a `resourceVersion`, then from `0`, then from a compacted
  one (expect 410).
- **C24** watch with `allowWatchBookmarks=true` and report whether bookmarks
  arrive (informational).
- **C26** two clients contend for one Lease; exactly one wins; the loser's
  update fails on `resourceVersion`.
- **C27** delete a Pod that owns a CEP; assert the CEP disappears within the GC
  window, or report not-applicable.
- **C28** two concurrent creates of the same `metadata.name`; exactly one
  succeeds, the other gets 409.
- **C29/C30/C32** `GET /version`, `GET /readyz`, `GET /api/v1/namespaces/kube-system`.
- **C35** `deletecollection` on `ciliumendpointslices`.
- **C36** create a CRD without `listKind`; assert the server defaults it.

The suite emits a Markdown matrix suitable for pasting into a rustkube issue.
A capability marked "Required" that fails means flowsdn cannot run on that
server; the suite exits non-zero.

### 9.6 End-to-end

- [ ] Kind cluster on each supported Kubernetes minor: agent starts, CRDs
      registered by the operator, all watchers sync, `cilium-dbg status`
      reports every k8s API group healthy.
- [ ] Upstream NetworkPolicy conformance suite passes (spec 06 owns the policy
      semantics; this line asserts the client layer delivers the objects).
- [ ] Restart the API server mid-run: the agent stays up, relists, and the
      datapath state is unchanged across the outage.
- [ ] Delete a CRD while running: F10 behavior.
- [ ] Apply every golden CR to a live cluster and read it back byte-identical
      after defaulting — this is the test that proves the vendored schemas and
      the Rust types agree with a real API server.
- [ ] Migration: install reference Cilium 1.20.1, apply a representative set of
      CRs, replace it with flowsdn, and assert every CR is still readable and
      that flowsdn's registration does not modify the CRDs (same schema
      version).

## 10. Kernel and platform requirements

### 10.1 Kernel

None. This layer is pure userspace control plane. The one platform dependency
is `SO_MARK` on the client's sockets for the host-firewall bypass (§3.5), which
needs `CAP_NET_ADMIN` — already held by the agent — and is Linux-only. On a
build without the datapath (unit tests, macOS development), the bypass hook is
compiled out.

### 10.2 Kubernetes version range

| Band | Versions | Behavior |
|---|---|---|
| Refused | < 1.26 | Fatal at startup (§3.10 step 5), message names the detected version and the floor |
| Accepted, untested | 1.26 – 1.32 | One warning at startup; `flowsdn_k8s_version_unsupported = 1` |
| Reference e2e range (flowsdn verification pending) | 1.33, 1.34, 1.35, 1.36 | No warning |
| Accepted, untested | > 1.36 | One informational log; Kubernetes' own forward compatibility applies |

**DEVIATION:** the reference's floor is 1.21.0. flowsdn raises it to **1.26**.
Reason: the vendored CRD schemas require CEL validation rules
(`x-kubernetes-validations`, C3), which are only on by default from 1.25, and
1.26 is the first release where the surrounding structural-schema behavior is
settled. Accepting a 1.21 server would mean the CRDs install but silently stop
validating, which is worse than refusing. The tested range matches the
reference's documented range for v1.20.1.

rustkube is out-of-band: it reports its own version string through
`GET /version`, and the conformance suite of §9.5 — not the version number — is
what decides whether flowsdn will run on it. A rustkube that reports a version
below the floor but passes the suite may be admitted with
`--k8s-force-version`; that is a deliberate, logged escape hatch.

## 11. Rust design notes

### 11.1 Crate `flowsdn-k8s`

One crate, no sub-crates, because everything in it shares the client handle.

```
flowsdn-k8s/
  crds/                    vendored YAML + SHA256SUMS + known-diffs.toml (§4.2)
  src/
    client.rs              Client construction, precedence, QPS/burst, user agent
    rotate.rs              URL list, random pick, rotating tower layer, service takeover
    heartbeat.rs           /readyz controller (§3.5)
    version.rs             /version parsing, floor check (§3.10)
    slim/                  the types of §4.3, hand-written serde
    crd/                   Rust CRD types, one module per kind
    crd/registry.rs        vendored-YAML loader, registration payload, needs_update
    watch.rs               reflector → flowsdn-table wiring (§5.2)
    index.rs               the indexers of §3.3/§3.4
    labels.rs              synthesis (§3.7) and the default filter list
    annotations.rs         the key catalogue of §4.4 as constants + parsers
    conformance/           the §9.5 binary
```

Dependencies: `kube` (client + runtime + derive) with `rustls`, `k8s-openapi`
**only** for the handful of full built-in types flowsdn writes (Lease, Event,
CRD), `serde`/`serde_json`/`serde_yaml`, `schemars` (for T-CRD-3), `tower`
(rate limit and the rotating layer), `tokio`, `semver`. `k8s-openapi`'s full
`Pod`/`Service` types MUST NOT be used on any watched path — they are the thing
§4.3 exists to avoid.

### 11.2 Generated vs hand-written types

- **Vendored YAML is generated output, treated as data.** It is never parsed
  into Rust structs for registration beyond the CRD envelope; the
  `versions[].schema` subtree is carried as an opaque `serde_json::Value` and
  posted verbatim. That is what makes byte-identity achievable.
- **CRD resource types are hand-written** with `#[derive(CustomResource)]`,
  which supplies `Resource` impls, the `<Kind>` / `<Kind>Spec` split and the
  `#[kube(printcolumn = …)]` attributes T-CRD-3 needs. CEL rules, `oneOf`
  alternatives and `x-kubernetes-list-map-keys` are **not** expressible in the
  derive; they live in the vendored schema only and appear in
  `known-diffs.toml`.
- **Slim types are hand-written** plain serde structs. They are ~1,500 lines
  and are the most-read code in the crate; generation would obscure exactly the
  thing (which fields are kept) that this spec is pinning.
- A build script emits, from the vendored YAML, a `const` table of
  `(plural, kind, scope, versions, subresources)` used by the registration
  payload builder and by the required-set computation, so those cannot drift
  from the YAML.

### 11.3 Watcher and reflector wiring

Each watcher is one `tokio` task:

```
kube::runtime::watcher(Api<T>, watcher::Config { field_selector, label_selector,
                                                 bookmarks: true, page_size: 500 })
  → project (optional lazy transform, §5.3)
  → batch (10,000 items or 50 ms)
  → flowsdn_table::Table<T>::write_txn { insert/delete; replace on relist }
```

`kube::runtime::reflector` is **not** used: its `Store` duplicates what
`flowsdn-table` already provides, and flowsdn needs the table's revisions and
change streams (spec 00 §3.1) for the reconcilers. The `watcher` stream's
`Event::Init`/`InitApply`/`InitDone` sequence maps onto the table's replace
transaction; `Event::Apply`/`Delete` map onto insert/delete. The CRD fence is
awaited before the stream is created, so a `cilium.io` watcher issues no
request before its CRD exists.

Consumers subscribe to `Table::watch(revision)` rather than to the watcher, so
a relist is invisible to them except as a burst of changes.

### 11.4 Writers

`kube::Api::patch` with `Patch::Json` (RFC 6902, including the `test` op —
`json-patch` crate types), `Patch::Strategic`, `Patch::Merge`;
`replace_status`/`patch_status` for the subresource writers. **`Patch::Apply`
is forbidden** and a CI grep enforces it (C17). Leader election uses a
Lease-based implementation with the reference's 15 s lease / 10 s renew / 2 s
retry timings (spec 12 owns the operator side).

### 11.5 Effort

Client + rotation + heartbeat ≈ 1.5k lines; slim types ≈ 1.5k; watch/index
layer ≈ 2k; CRD Rust types ≈ 4k (CNP/CCNP is most of it); registration and
readiness ≈ 0.6k; annotations, labels and the filter ≈ 0.8k; conformance suite
≈ 1.2k; tests ≈ 4k. Total ≈ 15–17k lines: **L**, matching the inventory's
estimate.

## 12. Open decisions

**12.1 Protobuf for built-in types.** §3.6 chooses JSON for everything in the
first cut.
(a) JSON only, forever — simplest, costs 2–3× bytes on initial lists.
(b) JSON first, add a `prost` decoder over the vendored slim `.proto` field
numbers as an optimization behind a config key.
(c) Protobuf from the start.
*Recommendation:* (b). The measurement that decides it is the initial-list byte
count on a 5,000-pod cluster; if it is under ~50 MB per agent, (a) is fine.
Blocked on whether rustkube speaks protobuf at all (C21).

**12.2 Resolved #166: preserve every served version.** All seven graduated
CRDs (CIDRGroup, LB IP pool and all five BGP kinds) MUST retain served `v2`
and deprecated served `v2alpha1`, with `v2` the sole storage version and no
conversion webhook (strategy `None`). Registration MUST preserve the complete
vendored versions array. C10 is required; absence is an explicit incompatibility,
never permission to strip a version. Existing stored versions must be migrated
before any future served-version removal. This also resolves BGP #184.

**12.3 Resolved #167: guarded JSON patch fallback.** Strategic merge remains
the default for node annotations and conditions on `nodes/status`. Only an
explicit unsupported result from the startup strategic-merge probe plus a
successful JSON-patch/test probe permits fallback; authentication, transport
and unknown results are errors, not evidence of unsupported merge semantics.
Fallback MUST test both `/metadata/uid` and `/metadata/resourceVersion` before
mutating the snapshot, escape annotation keys as JSON pointers, ignore nil
annotation updates, create absent parent objects, and preserve other annotations
and condition types. Conditions are merged by matching `type` (omitted fields retained, explicit null
fields removed) or appended;
malformed or duplicate condition types are rejected. Any precondition failure
requires rereading and rebuilding the patch, never replaying stale operations.

**12.4 Resolved #168: no client CEL evaluator.** Server CEL remains required
(C3); absence fails conformance and cannot be disguised by local CEL evaluation.
The importer must still perform its own semantic validation and emit the spec 06
`Valid` condition for invalid policies. That validation does not substitute for
admission validation or authorize a nonconformant server. No `cel-rust` dependency.

**12.5 Resolved #169: registration independent of enabled controllers.** Register
all 22 CRDs, including `ciliumgatewayclassconfigs`, regardless of Gateway API,
Ingress, MCS or ClusterMesh controller enablement. Feature ordering in §3.4 does
not remove schemas from the registration set or reduce the final project scope.

**12.6 Resolved #170: CEP by default.** Per-pod CEP remains the default. Enabling
CES in its default mode still requires CEP, which supplies the slice controller.
Opt-in slim CES requires CES enabled, CEP disabled, operator-managed identities,
and no mixed reference agents (spec 12). Reject inconsistent combinations.
Runtime controllers and 100-node write-QPS comparison remain required future
work; the library option tests establish no API-load improvement measurement.

**12.7 Resolved #171: list both configuration kinds across all namespaces.**
`CiliumNodeConfig` selection needs every matching namespace (spec 00).
`CiliumGatewayClassConfig` references use the explicit namespace/name in
GatewayClass `parametersRef` (spec 21 §3.3), which may differ from the installation
namespace. Therefore both informers MUST list/watch all namespaces with matching
RBAC, retaining namespace as part of object identity; lookups MUST use the exact
reference namespace/name. Restricting GatewayClassConfig to `--cilium-namespace`
would silently lose valid references and is rejected.

**12.8 Resolved #172: Kubernetes 1.26.0 floor.** Refuse older servers using
§3.10 parsing and numeric version comparison. Version acceptance does not prove
CEL or any other required capability: those probes/conformance tests remain
mandatory. Versions 1.26–1.32 warn as outside the reference test range; newer
versions than 1.36 are untested too. The reference range is not a flowsdn e2e
claim. Do not accept 1.21 or require 1.29 solely because of CEL's GA milestone.

### 12.9 Implementation boundary

`flowsdn-k8s` provides version/capability checks, registration projection and
catalogue, namespace/endpoint plans, and guarded node patch construction with
local regression tests. It does not yet provide an HTTP client, actual probes,
CRD YAML corpus/hash CI, Rust resource types, admission or importer condition
writes, informers, migration, or controllers. §9 remains the complete acceptance
suite. The operator's CRD availability fence gates readiness (`/readyz`) separately
from liveness (`/healthz`), including when CRD creation is skipped (spec 12).
Issue #165 remains open pending list-byte measurement and protobuf capability
evidence; JSON is the current baseline, not a measured permanent decision.
