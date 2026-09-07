# Operator — specification

Status: draft. Derived from: `docs/inventory/08-operator.md` (primary),
`docs/inventory/13-crds-k8s.md` (CRD catalogue), `docs/inventory/12-clustermesh-kvstore.md`
(kvstore key schema); reference cilium v1.20.1 (7d68cfb394) paths
`operator/cmd/{root,flags,leader_election,lifecycle,status,metrics_list}.go`,
`operator/option/config.go`, `operator/api/{cell,server,health,metrics}.go`,
`api/v1/operator/{openapi.yaml,server/server.go}`, `operator/metrics/`,
`operator/k8s/`, `operator/endpointgc/`, `operator/endpointslicegc/`,
`operator/unmanagedpods/`, `operator/watchers/{node_taint,node_taint_cell,cilium_node_gc,service_sync,endpointslice_export_sync,pod}.go`,
`operator/pkg/ciliumendpointslice/`, `operator/pkg/networkpolicy/`,
`operator/pkg/secretsync/`, `pkg/secretsync/names/names.go`,
`operator/pkg/kvstore/{nodesgc,locksweeper}`, `operator/pkg/gateway-api/{cell.go,helpers/schemes.go}`,
`pkg/k8s/apis/{cell.go,cilium.io/client/register.go,crdhelpers/register.go}`,
`pkg/k8s/synced/crd.go`, `pkg/k8s/utils/utils.go`,
`install/kubernetes/cilium/templates/cilium-operator/{deployment,clusterrole,role}.yaml`.
Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes *what*
flowsdn does and the exact data it exchanges. It does not transcribe reference
code. Where the reference behavior is kept for compatibility, the consumer that
depends on it is named (agent, kubelet, scheduler, `cilium-dbg`, another
cluster). Where flowsdn deviates, the paragraph is marked **DEVIATION** with
the reason and the ADR.

## 1. Scope

`flowsdn-operator` is the single-leader, cluster-scoped control plane companion
to the per-node agent. It does the work that must happen exactly once per
cluster.

**In scope here:**

- Process model, provider selection, leader election, startup/shutdown order.
- CRD registration and upgrade (§3.4), and the contract the agent's CRD wait
  depends on (§3.5).
- `CiliumEndpoint` garbage collection (§3.6).
- `CiliumEndpointSlice` controller, both controller modes, and the one-shot GC
  when the feature is off (§3.7, §3.8).
- `CiliumNode` lifecycle and GC, node taint removal, `NetworkUnavailable`
  condition (§3.9, §3.10).
- Unmanaged-pod detection and restart (§3.11).
- `CiliumNetworkPolicy` / `CiliumClusterwideNetworkPolicy` status validator (§3.12).
- kvstore-mode duties: service sync, EndpointSlice export sync, node GC, lock
  sweeping, heartbeat, cluster-config (§3.13) — the *duty*, not the key schema.
- Secret and ConfigMap synchronization into the agent-readable namespaces (§3.14).
- Operator REST API, metrics, health model (§3.16, §8).
- RBAC (§4.8), the complete operator flag table (§6), failure modes (§7),
  tests (§9), Rust design (§11).

**Out of scope — specified elsewhere, referenced not restated:**

| Subject | Spec |
|---|---|
| Identity GC (CRD and kvstore modes), heartbeat annotation protocol, rate limiter, identity data model | `03-identity-ipcache.md` §3.6, §4.3, §6 |
| Operator IPAM: cluster-pool / multi-pool podCIDR handout, cloud providers, node manager, `CiliumNode` IPAM fields, the CiliumNode-GC ↔ pool-release coupling | `07-ipam.md` §3.5, §3.6, §3.9–§3.15, §3.19, §4.1, §6.2, §11.4 |
| LB IPAM (`CiliumLoadBalancerIPPool`), node IPAM, L2 announcement policy handling | `05-service-loadbalancing.md` §3.10, §3.11, §4.7, §4.8 |
| Policy CRD semantics that the validator checks (`Sanitize`) | `06-policy-engine.md` |
| kvstore key schema, `ClusterService` JSON, cluster-config, heartbeat cadence, remote-cluster connection manager | ClusterMesh + kvstore spec (wave 4; inventory `12-clustermesh-kvstore.md`) |
| BGP CRD fan-out (`CiliumBGPClusterConfig` → `CiliumBGPNodeConfig`), router-ID allocation, BGP status conditions | `15-bgp.md` (in flight; inventory `10-bgp.md`) |
| Gateway API and Ingress: ingestion, model, Envoy translation, status conditions, GAMMA | Gateway API spec (wave 4). **Only** the trigger conditions and required CRDs are specified here (§3.15) |
| CRD OpenAPI schemas field by field, the shared k8s client, informer plumbing | `13-crds-k8s-client.md` (in flight; inventory `13-crds-k8s.md`) |
| `CiliumEnvoyConfig` semantics and the agent's Envoy integration | `16-l7-envoy-dns.md` (in flight; inventory `11-l7-proxy-dns-auth-mesh.md`) |
| Config registry mechanism (sources, precedence, `--config-dir`, typed kinds, validation) | `00-foundation-table-config.md` §3.3, §5.5. This spec lists the operator's *keys*, not the loader |
| Module health registry, fences | `00-foundation-table-config.md` §3.4 |
| Table store and generic reconciler | `00-foundation-table-config.md` §3.1, §3.2 |

**Dropped from the reference (ADR-0001 scope table, inventory 08
recommendation):** SPIRE / mutual auth (deprecated upstream at 1.20),
double-write identity mode and its metric reporter, ztunnel DaemonSet
management, gops, hive shell (`shell.sock`), `--cmdref`, the five-binary split
(§3.1).

## 2. Compatibility contract

| Interface | MUST match | Consumer |
|---|---|---|
| Lease name `cilium-operator-resource-lock`, `coordination.k8s.io/v1`, in the operator namespace | name, namespace resolution, holder-identity shape | a mixed-version rollout where a Cilium operator and a flowsdn operator briefly coexist; both must contend for the *same* lock |
| CRD schema-version label `io.cilium.k8s.crd.schema.version`, value on the `1.33.x` line | label key, semver value, "update only if strictly older" rule | in-place upgrade of an existing Cilium cluster; a Cilium operator that races with flowsdn must not downgrade the schema |
| CRD names, group `cilium.io`, versions, scope, short names, categories, printer columns, OpenAPI schemas | byte-identical to the vendored YAML (§4.2) | agents (Cilium and flowsdn), `kubectl`, users' manifests |
| CRD `Established` gate | operator MUST NOT report ready before every CRD it creates is `Established` | agent CRD wait (`crd-wait-timeout`, spec `00` fence `k8s-crds`) |
| `CiliumEndpointSlice` object shape: cluster-scoped, `namespace` string, `endpoints[]` of `CoreCiliumEndpoint` with JSON keys `name`, `id`, `pod-uid`, `networking`, `encryption`, `named-ports`, `service-account` | byte-identical JSON | agent CES watcher (spec `08-endpoint-agent-api`), `cilium-dbg` |
| CES object name shape `ces-<9>-<5>` from the alphabet `bcdfghjklmnpqrstvwxyz2456789` | shape only; names are opaque | humans, `kubectl get ces` |
| CES namespace-priority annotation `cilium.io/ces-namespace=priority` | key and value | users |
| Node taint key `node.cilium.io/agent-not-ready` (overridable by `agent-not-ready-taint-key`) | key string, `NoSchedule` effect when *set*, removal of any effect | kubeadm/cloud-init pre-taint, kubelet, scheduler, `cilium connectivity test` |
| Node condition `NetworkUnavailable=False`, `Reason: CiliumIsUp`, `Message: Cilium is running on this node` | `Type`+`Status`+`Reason` triple — it is the idempotency marker | the operator itself, GKE's route controller, humans |
| `CiliumEndpoint` delete preconditions `{UID}` and `PropagationPolicy=Background` | preconditions present | agents (a CEP re-created by the owning agent must not be deleted) |
| `CiliumNode` skip annotation `cilium.io/do-not-gc=true` | key, case-insensitive `true` | users |
| CNP/CCNP `.status.conditions[]` entry `Type: Valid`, `Status: True|False`, `Message` | condition type string | users, `kubectl describe cnp` |
| Synced Secret naming `cilium-sync-secret-<sha256hex>` / `cilium-sync-cfgmap-<sha256hex>` with digest over `<kind>\0<ns>\0<name>` and the legacy `<ns>-<name>` cleanup | name derivation exactly | agent Envoy SDS (spec L7), agent RBAC scoped to the secrets namespace |
| Synced object annotations `secretsync.cilium.io/source-{kind,namespace,name}` and ownership labels `secretsync.cilium.io/owning-secret-{namespace,name}` | keys and values | operator's own reconcile, humans |
| Operator REST API: `GET /healthz` (plain text, 200/500/501) and its alias at `/v1/healthz`; `GET /v1/metrics/`; `GET /v1/cluster` | paths, status codes, payload shapes | kubelet liveness/readiness probes on port 9234, `flowsdn-operator status`, `cilium-dbg` |
| Prometheus metric names under the `cilium_operator_` namespace (§8.1) | names and label names | dashboards |
| Config key names (§6) | byte-identical, dash-separated lower case | Helm `cilium-config` ConfigMap |
| Deployment shape: `hostNetwork: true`, container port 9234 (`health`, also `hostPort`), 9963 metrics, `SO_REUSEADDR|SO_REUSEPORT` on the API listener | kept | Helm chart, two replicas landing on one node in a small cluster |

Everything else is internal.

## 3. Behavior

### 3.1 Process model

**One binary.** `flowsdn-operator` is a single static binary containing every
IPAM provider. **DEVIATION** (ADR-0001 "one static binary per component";
already recorded in `07-ipam.md` §11.4): the reference ships five binaries
(`cilium-operator`, `-generic`, `-aws`, `-azure`, `-alibabacloud`) selected by
Go build tags, derives the default `--ipam` from `filepath.Base(os.Args[0])`,
and rejects `--ipam` values the binary was not built with. flowsdn selects the
provider **at runtime** from the `ipam` key; the default is `cluster-pool`. No
key is rejected for being "in the wrong binary".

- The process MUST refuse to start if `ipam` names a provider that is
  compiled out of this build (there are none in the default build) or is not a
  recognised value.
- Provider start-up, credentials and the per-provider key set are specified in
  `07-ipam.md` §3.9–§3.11 and §11.4.

**Kubernetes is mandatory in practice.** The reference tolerates `enable-k8s=false`
(most cells then do not register). flowsdn keeps the key but the operator with
`enable-k8s=false` has nothing to do except serve `/healthz` with 501 and
`/metrics`; this is retained only so the binary can be started for
`--version`/`metrics list` style introspection.

**Minimum apiserver version.** Before contending for the lease, the operator
MUST query the apiserver version and refuse to run (exit non-zero, one log
line naming both versions) when it is below the enforced minimum. Two
different numbers are in play and both are kept:

- **Enforced constraint: `>= 1.21.0`.** This is the reference's
  `MinimalVersionConstraint` and it is what the fatal check compares against.
  It is deliberately far below the tested line — it exists to reject something
  ancient, not to police support.
- **Documented supported line: 1.33–1.36** (inventory 13). Outside it, flowsdn
  relies on Kubernetes API compatibility and offers no guarantee.

The check is fatal, not a warning.

**Client tuning.** One shared Kubernetes client for the whole process with
`operator-k8s-client-qps` (100) and `operator-k8s-client-burst` (200) —
deliberately higher than the agent's, because a single operator drives every
CES write in the cluster. API discovery is always enabled (the reference forces
`enable-k8s-api-discovery=true` in the operator; flowsdn does the same and the
key is accepted-and-ignored).

**DEVIATION (ADR-0004).** The reference is a Hive of ~45 cells split into
`InfrastructureCells` / `ControlPlaneCells` / `ControlPlaneLeaderCells`, the
last wrapped in a nested `LeaderLifecycle`. flowsdn has no DI container: `main`
constructs an `Infrastructure` value, then a `ControlPlane` value, then — on
winning the lease — a `LeaderScope` that owns every leader duty. The three
tiers survive as three explicit construction functions, because the tier
boundary is behavioral (what runs on a follower) and not an artifact of Hive.

### 3.2 Leader election

The operator MUST hold a `coordination.k8s.io/v1` `Lease` before starting any
leader duty.

| Property | Value |
|---|---|
| Lease name | `cilium-operator-resource-lock` |
| Lease namespace | `k8s-namespace`; when empty, `default` |
| Holder identity | `<hostname>-<10 random chars>` from a lowercase-alnum alphabet, computed once per process |
| `lease-duration` | `leader-election-lease-duration`, 15 s |
| `renew-deadline` | `leader-election-renew-deadline`, 10 s |
| `retry-period` | `leader-election-retry-period`, 2 s |
| HTTP timeout for lock operations | `leader-election-resource-lock-timeout`; `0` (default) → `max(1 s, renew-deadline / 2)` = 5 s |
| Release on shutdown | yes — the Lease MUST be released (holder identity cleared) when the process shuts down cleanly, so a standby takes over in ≪ `lease-duration` |

Algorithm (client-go `leaderelection` semantics, restated because flowsdn
implements it rather than importing it):

1. Every `retry-period`, `GET` the Lease.
2. If it does not exist, `CREATE` it with `holderIdentity = self`,
   `leaseDurationSeconds = lease-duration`, `acquireTime = renewTime = now`,
   `leaderTransitions = 0`. On `AlreadyExists`, go to 1.
3. If it exists and `holderIdentity == self`, `UPDATE` with `renewTime = now`
   (keep `acquireTime`, `leaderTransitions`). A successful update refreshes the
   local `last_renew` clock.
4. If it exists and `holderIdentity != self`: the lease is acquirable only when
   `observed_renewTime + leaseDurationSeconds < now`, measured against the
   *locally observed* time at which the record last changed (not the
   apiserver's clock). On acquire, set `holderIdentity = self`,
   `acquireTime = renewTime = now`, `leaderTransitions += 1`.
5. While leading, if `now - last_renew > renew-deadline`, leadership is lost.

**On becoming leader** the operator starts the leader scope (§3.3). Failure to
start any leader duty is fatal: the operator MUST release the Lease and exit
non-zero rather than lead with a partially-started control plane.

**On losing leadership** — the decision:

> **flowsdn keeps the reference's fatal behavior.** The process cancels the
> leader scope's cancellation token (which aborts in-flight apiserver
> requests) and then exits with status 1 **without waiting for tasks to
> drain**. It does not attempt to demote itself to a follower.

Rationale, recorded here so it is not relitigated: the gap between
`renew-deadline` (10 s) and `lease-duration` (15 s) is 5 s. A standby may
legally acquire the lease 5 s after this process notices the loss. Every leader
duty writes shared cluster state (CES objects, node taints, CRDs, kvstore
keys, `CiliumNode.spec.ipam.podCIDRs`) under the assumption that it is the only
writer. A graceful demotion would have to prove that every in-flight write has
either landed or been aborted inside that 5 s window, for every duty, forever —
an obligation that grows with each new controller. Exiting hands that proof to
the kernel. The deployment already has `replicas: 2` and a `RollingUpdate`
strategy, so the cost is one pod restart. Kept as a **non-deviation**; the
graceful-demote alternative is Open Decision 1.

Two refinements over the reference, neither observable:

- The exit is preceded by cancelling the leader scope, so open request bodies
  are closed rather than left to the process teardown. No wait, no timeout.
- The exit path logs one structured line
  `{event: "leadership-lost", holder_identity, leader_transitions, uptime_as_leader}`
  before exiting, so a leader flap is diagnosable from logs alone.

**Followers** run the infrastructure and control-plane tiers only: the API
server (§3.16), the metrics endpoint, the kvstore client, and nothing else.
A follower's `/healthz` reports on the kvstore and apiserver connections only;
it does **not** report "not leader" as unhealthy, because kubelet must keep the
standby pod alive.

An `is_leader` flag (atomic) is set when the leader scope has finished starting
and cleared on shutdown. It is surfaced in `/v1/metrics/`, in the health module
tree, and in the feature gauges (which are only populated while leading). It is
deliberately **not** an input to the `/healthz` verdict (§3.16) — the reference
passes it into the health handler and then never reads it, and flowsdn makes
that non-use explicit rather than inheriting a dangling wire.

### 3.3 Startup order and shutdown

Startup is expressed with the fence mechanism of spec `00` §3.4.1. The operator
has its own, much smaller, fence graph:

| Fence | Waiters | Dependents |
|---|---|---|
| `config` | config registry frozen and validated (spec `00` §3.3.5) | everything |
| `k8s-client` | client built, apiserver version fetched and accepted | leader election, API server |
| `api-listening` | operator API bound on `operator-api-serve-addr` | readiness probe answers |
| `leader` | Lease acquired | the entire leader scope |
| `crds-established` | every CRD in the conditional set (§3.4) created/updated and `Established` | every leader duty that lists a Cilium CRD |
| `informers-synced` | initial list complete for every shared informer the leader scope needs | CES controller startup replay, GC controllers |

Ordering constraints that MUST hold:

1. **CRD registration is the first leader operation.** Nothing that lists a
   Cilium CRD may start before `crds-established` releases. The reference
   enforces this by ordering `RegisterCRDsCell` first inside the leader
   lifecycle; flowsdn enforces it with the fence.
2. **kvstore client initialisation precedes identity GC in kvstore mode.**
   (The reference calls this out as a "hacky workaround"; with explicit
   composition it is simply a fence.)
3. **Validation runs before any duty starts, not lazily.** Specifically:
   - `identity-allocation-mode ∈ {crd, doublewrite-*}` requires k8s enabled
     **and** `cilium-endpoint-gc-interval != 0`. Violation is a fatal startup
     error naming both keys. (Spec `03` §3.6 relies on this.)
   - `ces-controller-mode ∈ {default, slim}`, else fatal.
   - `ces-rate-limits` must parse as a JSON array of `{nodes,limit,burst}`
     with no unknown fields, else fatal.
   - `gateway-api-service-externaltrafficpolicy ∈ {Cluster, Local}`, else fatal.
   - `max-connected-clusters ∈ {255, 511}`, else fatal (spec `03` §4.5).
4. **The API server starts on every replica, before leader election.** A pod
   that never wins the lease must still answer probes.

**Shutdown.** On `SIGTERM`: stop accepting new work in the leader scope, cancel
its token, wait at most `hive-stop-timeout` (1 m, key retained) for tasks to
finish, release the Lease, close the API listener, exit 0. On leadership loss
the path of §3.2 applies instead.

### 3.4 CRD registration

Skipped entirely when `skip-crd-creation` is set or k8s is disabled; the
operator logs one line and releases `crds-established` immediately.
`skip-crd-creation` exists for clusters where a separate process (GitOps,
cluster addon manager) owns the CRDs; the operator then MUST still verify each
required CRD exists and is `Established` before releasing the fence, and MUST
fail readiness (not exit) if one is missing.

**Payload.** The CRD objects are the vendored OpenAPI YAML (§4.2), embedded in
the binary. The object written is assembled as:

- `metadata.name` = `<plural>.cilium.io`
- `metadata.labels` = exactly `{io.cilium.k8s.crd.schema.version: <schema version>}`
  — the label map is **replaced**, not merged, on update
- `spec.group` = `cilium.io`
- `spec.names` = `{kind, plural, singular, shortNames, categories}` from the
  vendored template
- `spec.scope`, `spec.versions`, `spec.conversion` from the template
- `spec.preserveUnknownFields` explicitly `false` on every update (the
  apiserver carries the old `true` forward otherwise)

**Schema version.** The label value is a semver string. flowsdn continues the
reference's `1.33.x` line so that an existing Cilium v1.20.1 cluster can be
upgraded in place (Open Decision 3). The value MUST be a compile-time constant
of the binary, bumped whenever any vendored CRD YAML changes.

**Create/update algorithm** (per CRD, run once at leader start):

1. `GET` the CRD.
   - `NotFound` → `CREATE`. On `AlreadyExists` (another operator raced), return
     success without further work — the racing writer will also update it.
   - Any other error → fail.
2. Decide `needs_update` against the *installed* object:
   - installed `spec.versions[0].schema` is absent → **yes**
   - label `io.cilium.k8s.crd.schema.version` absent → **yes**
   - label value does not parse as semver → **yes**
   - parsed value `< binary schema version` → **yes**
   - otherwise → **no**

   This is a strict "**update only if older**" rule: equal or newer installed
   schemas are left alone. There is no downgrade path and no forced overwrite.
3. If `needs_update` and the target has a schema, poll every **500 ms** for up
   to **60 s**: re-`GET`, re-evaluate `needs_update` (it may have become false
   because another operator updated it), and if still true `UPDATE` the object
   with the target labels and spec. A `Conflict` on `UPDATE` is **not** an
   error: log at debug and retry the poll. Any other error aborts.
4. Poll every **500 ms** for up to **60 s** until the CRD's status has
   `Established=True`. If it instead has `NamesAccepted=False`, abort
   immediately with the condition's `Reason` as the error — a name conflict is
   never transient.

**Schema conflict.** Three cases, all handled by step 2/3:

| Situation | Result |
|---|---|
| Installed label is newer (a newer Cilium/flowsdn operator raced, or an admin applied a newer CRD) | no write; the older operator runs against a newer schema. Additive CRD evolution makes this safe; the operator MUST log one `WARN` naming both versions so the mismatch is visible |
| Installed label is equal | no write |
| Installed label is older / missing / unparsable | full `UPDATE` of labels + spec, retried on conflict for up to 60 s |
| `NamesAccepted=False` | fatal for that CRD: another CRD already owns the plural/short name. The operator fails startup rather than proceeding without the resource |

**Conditional CRD set.** The operator creates the union of the agent's required
set and its own:

*Always:*

| Kind | Plural | Version |
|---|---|---|
| CiliumIdentity | `ciliumidentities` | v2 |
| CiliumPodIPPool | `ciliumpodippools` | v2alpha1 |
| CiliumLoadBalancerIPPool | `ciliumloadbalancerippools` | v2 (+ v2alpha1 deprecated) |
| CiliumL2AnnouncementPolicy | `ciliuml2announcementpolicies` | v2alpha1 |
| CiliumNodeConfig | `ciliumnodeconfigs` | v2 |

*Conditional:*

| Kind | Gate (key) | Default state |
|---|---|---|
| CiliumEndpoint | `!disable-endpoint-crd` | created |
| CiliumEndpointSlice | `enable-cilium-endpoint-slice` | not created |
| CiliumNode | `enable-ciliumnode-crd` (hidden) | created |
| CiliumNetworkPolicy | `enable-cilium-network-policy` | created |
| CiliumClusterwideNetworkPolicy | `enable-cilium-clusterwide-network-policy` | created |
| CiliumCIDRGroup | either policy CRD enabled | created |
| CiliumEgressGatewayPolicy | `enable-egress-gateway` | not created |
| CiliumLocalRedirectPolicy | `enable-local-redirect-policy` | not created |
| CiliumEnvoyConfig + CiliumClusterwideEnvoyConfig | `enable-envoy-config` | not created |
| CiliumBGPClusterConfig, CiliumBGPPeerConfig, CiliumBGPAdvertisement, CiliumBGPNodeConfig, CiliumBGPNodeConfigOverride | `enable-bgp-control-plane` | not created |
| CiliumDatapathPlugin | `enable-datapath-plugins` | not created |
| CiliumGatewayClassConfig | `enable-gateway-api` | not created |
| `ServiceExport`, `ServiceImport` (`multicluster.x-k8s.io/v1beta1`) | `clustermesh-enable-mcs-api` **and** `clustermesh-mcs-api-install-crds` | not created |

Note that the always-set is *smaller* than inventory 08 states: `CiliumNode`
and `CiliumEndpoint` are conditional (on hidden keys that default to
create-it), and `CiliumNodeConfig` is operator-only. Several of these gates are
**agent** keys read from the shared `cilium-config` ConfigMap — the operator
therefore MUST accept the agent's key names verbatim (§6, Open Decision 6 of
inventory 08 risk list).

The operator MUST NOT *delete* a CRD it no longer needs. Disabling a feature
leaves its CRD installed; the corresponding data is cleaned up by the
feature's own one-shot GC where one exists (CES: §3.8; CEP: §3.6;
`CiliumNode`: §3.9).

### 3.5 How the agent waits for CRDs

Specified here because the operator side is the producer of the contract; the
consumer side lives in the agent (spec `00` §3.4.1 fence `k8s-crds`).

The agent MUST NOT create CRDs. It lists and watches
`apiextensions.k8s.io/v1 CustomResourceDefinition` as **metadata-only** objects
(`PartialObjectMetadata`, requested with the metadata-only `Accept` header) and
blocks until every name in its own required set exists. Metadata-only matters:
the full CRD objects carry ~20 000 lines of OpenAPI schema and pulling them on
every agent at startup is a measurable load on the apiserver.

The required set is the conditional table above minus the operator-only entries
(`CiliumNodeConfig`, `CiliumGatewayClassConfig`) and gated by the *agent's* copy
of the same keys.

Readiness is polled every **50 ms**; every 20th poll (≈1 s) the agent logs one
line naming the CRDs still missing, so a stuck bootstrap is diagnosable from
the agent's log without looking at the operator. The wait is bounded by
`crd-wait-timeout` (5 m) and expiry is **fatal** for the agent — an agent that
proceeded without CRDs would silently drop policy.

Consequence for the operator: it MUST finish CRD registration promptly after
winning the lease. A slow or wedged CRD step does not merely delay the operator,
it kills every agent in the cluster 5 minutes later. The operator therefore
reports `crds-established` as a distinct health module (§8.3) so the condition
is visible before agents start failing.

### 3.6 CiliumEndpoint garbage collection

Purpose: delete `CiliumEndpoint` objects whose pod is gone or finished, so
their IPs leave the ipcache and their identities become GC-able (spec `03`
§3.6 depends on this).

**Mode selection.** If `cilium-endpoint-gc-interval == 0` **or**
`disable-endpoint-crd` is set, the GC runs **once** at leader start and deletes
**every** CEP in the cluster — this is feature-disable cleanup, not orphan
detection. Otherwise it runs periodically at `cilium-endpoint-gc-interval`
(default 5 m).

**Precondition.** In one-shot mode, the GC first checks that the
`ciliumendpoints.cilium.io` CRD exists. If it does not, the GC does not run at
all (nothing to clean, and the `List` would fail). A transient error checking
for it is logged and the GC does not start; it is retried on the next leader
election.

**Orphan rules** (periodic mode, evaluated per CEP against the Pod informer
store):

| Step | Condition | Result |
|---|---|---|
| 1 | `now - cep.metadata.creationTimestamp < interval` | **keep** (the pod event may not have arrived yet) |
| 2 | CEP has an `ownerReference` whose `Kind` is **not** `Pod` | **keep**, unconditionally and without looking at pods — something else owns this object's lifecycle |
| 3 | CEP has one or more `Pod` owner references: look up `Pod{namespace: cep.namespace, name: owner.name}` | pod found and running → **keep**; pod found and `Failed`/`Succeeded` → **delete**; pod not found → fall through |
| 4 | No `Pod` owner reference was resolvable: look up `Pod{namespace: cep.namespace, name: cep.name}` | same three outcomes as step 3 |
| 5 | Nothing resolved | **delete** |

"Running" means the pod's `status.phase` is **not** `Failed` and **not**
`Succeeded`. `Pending` and `Unknown` count as running — a pod whose Job has
finished but whose object lingers is the case this rule exists for.

**Deletion.** `DELETE` with `PropagationPolicy: Background` and
`Preconditions: {uid: <cep.uid>}`. The UID precondition is mandatory: without
it a CEP recreated by the owning agent between the list and the delete would be
destroyed. `NotFound` and `Conflict` are counted as failures in the metric but
are not errors — both mean somebody else already resolved the race. Any other
error aborts the run (the next tick retries).

Ordering note: the GC iterates the informer store snapshot; it does not page
the apiserver. A single run therefore sees a consistent-enough view and costs
one `DELETE` per orphan.

### 3.7 CiliumEndpointSlice controller

Enabled by `enable-cilium-endpoint-slice` (default false). Purpose: replace
`N` per-endpoint `CiliumEndpoint` watches on every agent with `N/100` `CES`
watches, which is the difference between a cluster scaling to 5 000 nodes and
not.

#### 3.7.1 Object model and slicing

- `CiliumEndpointSlice` is **cluster-scoped** and carries a `namespace` field.
- **Namespace is the only grouping key.** A CEP goes into a CES whose
  `namespace` matches. There is no identity-based or FCFS slicing at this tag
  (`ces-slice-mode` was removed) and flowsdn does not reintroduce it.
- Capacity: `ces-max-ciliumendpoints-per-ces`, default **100**.
- Only endpoints with both `status.networking` and `status.identity` populated
  are placed (default mode); in slim mode the equivalent is "the pod has at
  least one IP and a resolvable identity".

**Bin packing** (§5.1): place into the *fullest* CES of the namespace that
still has room; create a new one if none. This is deliberately not
best-fit-decreasing — it keeps slices dense so the count stays near
`ceil(n/100)` and, crucially, keeps churn local: adding one endpoint touches
one CES, so one watch event reaches every agent instead of a reshuffle.

#### 3.7.2 Controller modes

Hidden key `ces-controller-mode`, values `default` and `slim`.

| | `default` | `slim` |
|---|---|---|
| Input objects | `CiliumEndpoint` (written by agents) + `CiliumEndpointSlice` + `Namespace` + `CiliumNode` | `Pod` + `CiliumIdentity` + `CiliumNode` + `CiliumEndpointSlice` + `Namespace` |
| Who computes the endpoint's identity | the agent, published in `cep.status.identity.id` | the **operator**, from pod labels ∪ namespace labels (§5.6) |
| Who computes networking | the agent | the operator, from `pod.status.podIPs` and `pod.spec.nodeName` |
| Who computes the encryption key | the agent | the operator, from `enable-wireguard` / `enable-ipsec` and the node's `CiliumNode.spec.encryption.key` (§5.6) |
| Named ports | from the CEP | from the pod's container ports that have a `name` |
| Service account | from the CEP | `pod.spec.serviceAccountName` |
| Requires agents to write CEPs | yes | no |

Slim mode is the path to `disable-endpoint-crd` plus
`identity-management-mode=operator`: with both, agents neither create nor watch
`CiliumEndpoint` objects and the apiserver load of a large cluster drops by
roughly the pod count. The cost is that the operator must reproduce the
agent's label→identity derivation *exactly* (§5.6); a divergence silently
mislabels traffic.

flowsdn implements **default mode first** and slim mode second (Open
Decision 2), because default mode is the one a mixed Cilium/flowsdn cluster can
run.

#### 3.7.3 Queues, batching and rate limiting

Two work queues over CES names, sharing one exponential failure limiter:

| Parameter | Value |
|---|---|
| Queues | `fast`, `standard` |
| `fast` selection | the CES's namespace carries annotation `cilium.io/ces-namespace: priority` |
| Drain order | `fast` fully drained before `standard` is polled |
| Sync batching delay | 500 ms — a CES is enqueued with this delay so a burst of CEP changes collapses into one write |
| Failure backoff | exponential, base **1 s**, cap **100 s** |
| Max retries | **15**, then the key is dropped with an error log |
| Apiserver write gate | a token-bucket limiter, parameters from `ces-rate-limits` |

`ces-rate-limits` is a JSON array of `{"nodes": <int>, "limit": <float>,
"burst": <int>}`, default `[{"nodes":0,"limit":10,"burst":20}]`. Unknown JSON
fields are rejected. The array is sorted ascending by `nodes`; the entry with
the greatest `nodes ≤ current CiliumNode count` is in force. The selection is
re-evaluated on every `CiliumNode` add/delete, and a change reconfigures the
existing limiter's rate and burst in place (no queue reset). `limit` is
writes per second; `burst` is the bucket depth. The delay a write waits is
observed as `cilium_operator_ces_queueing_delay_seconds`.

#### 3.7.4 Startup replay

Before reconciling anything, the controller MUST rebuild its CEP→CES mapping
from existing objects:

1. List `CiliumEndpointSlice`; for each, register the CES name, its namespace,
   and every `endpoints[].name` as living in that CES.
2. List the source objects (CEPs in default mode; Pods + CIDs + CiliumNodes in
   slim mode) and reconcile the difference.

Skipping this produces duplicate slices after every operator restart: the
placement function would find no existing CES with room and create fresh ones,
leaving each endpoint listed twice and agents seeing every endpoint's identity
twice.

#### 3.7.5 What the agent consumes in CES mode

Specified here because it is the reason the object shape is frozen:

- With `enable-cilium-endpoint-slice`, an agent **does not watch
  `CiliumEndpoint` objects of other nodes**. It watches `CiliumEndpointSlice`
  and fans each `CoreCiliumEndpoint` into the same ipcache + policy path that a
  CEP event would take.
- On a CES **update** the agent diffs old vs new `endpoints[]`: entries added
  are upserts, entries removed are candidate deletes.
- A removed entry is only deleted from the ipcache once the endpoint appears in
  **no remaining CES**. A pod moving between slices (which happens when a slice
  is repacked) must not flap its ipcache entry.
- In `default` controller mode the agent still **writes** its own CEPs — CES is
  a read-side optimisation only. In `slim` mode it writes nothing.

#### 3.7.6 Migration between modes

| Transition | Operator behavior | Cluster effect |
|---|---|---|
| CES off → on | CES CRD is created (§3.4); controller starts; startup replay finds no CES and creates them from the CEP set | agents must be restarted/reconfigured to watch CES; until they are, they keep watching CEPs, which still exist. Order: enable on the operator first, then roll agents |
| CES on → off | the CES controller does not start; the one-shot CES GC (§3.8) deletes every CES | roll agents back to CEP watching **before** the CES objects vanish, or endpoints disappear from the ipcache for the duration of the gap |
| `default` → `slim` | the controller switches input sources; startup replay reads the existing CES set, so slices are preserved and only their contents are recomputed | agents may keep writing CEPs (harmless, ignored) until `disable-endpoint-crd` is also set. Identities must already be operator-managed, or the operator has no CID to point at |
| `slim` → `default` | symmetric; agents must be writing CEPs again *before* the switch, else the replay finds no sources and empties every slice | |

Both mode switches are operator-restart-scoped: `ces-controller-mode` is read
once at startup.

### 3.8 CiliumEndpointSlice GC (feature disabled)

When `enable-cilium-endpoint-slice` is false, a one-shot job runs at leader
start:

1. Check the `ciliumendpointslices.cilium.io` CRD exists. `NotFound` → nothing
   to do, exit successfully. Other error → retry.
2. `DELETE` the whole collection with `PropagationPolicy: Orphan`.
3. Retried up to **3** times with exponential backoff between **1 m** and
   **5 m**.

`Orphan` is deliberate: CES objects own nothing, and a background cascade would
be pointless work for the apiserver.

### 3.9 CiliumNode lifecycle and GC

**Creation.** `CiliumNode` objects are created by **agents**, not by the
operator. Each agent creates the object for its own node with an
`ownerReference` to the corresponding `Node`, so that deleting the `Node`
cascades. The operator's `create`/`update` RBAC on `ciliumnodes` exists for the
IPAM path (writing `spec.ipam.podCIDRs`, spec `07-ipam.md` §3.5/§3.6) and for
the cloud providers' node bootstrap, not for creating nodes from scratch.

**Deletion (GC).** Specified in `07-ipam.md` §3.19; restated here only as the
interface, because the GC is an operator duty and its interaction with the
taint controller matters:

- Interval `nodes-gc-interval` (5 m); `0` disables the GC entirely.
- Two-pass hysteresis: a `CiliumNode` with no matching k8s `Node` becomes a
  *candidate* with a timestamp on the first pass, and is deleted on a later
  pass only once it has been a candidate for at least one interval. A
  `CiliumNode` whose k8s `Node` reappears loses its candidacy.
- Never GC'd: an object with any `ownerReferences` (k8s cascading deletion owns
  it), or one annotated `cilium.io/do-not-gc: true` (case-insensitive).
- If a candidate has vanished from the store between the iteration and the
  read, drop the candidacy and move on.
- Deletion is a plain `DELETE`; `NotFound` is success.
- When `enable-ciliumnode-crd=false`, the predicate degenerates to "delete
  everything" — feature-disable cleanup, same shape as §3.6 and §3.8.
- Deletion feeds the IPAM node manager's `Delete` and pool release
  (`07-ipam.md` §3.15).

### 3.10 Node taint removal and NetworkUnavailable condition

This is the mechanism that gates workload scheduling on CNI readiness. It is
the operator's most externally-visible behavior: get it wrong and either pods
start without networking, or no pod ever schedules.

**Input.** An informer on `Pod` objects in `cilium-pod-namespace` (defaulting
to `k8s-namespace`) matching `cilium-pod-labels` (default `k8s-app=cilium`).
Pods are transformed on ingest to keep only `spec.nodeName`,
`metadata.deletionTimestamp` and `status.conditions` — a large cluster's agent
pod objects are otherwise a meaningful fraction of the operator's heap. The
store is indexed by node name.

**Trigger.** Every pod add/update enqueues `pod.spec.nodeName` (skipped when
empty — unscheduled) onto a work queue named `node-queue`, drained by
`taint-sync-workers` (10) workers. The queue's failure limiter is exponential
with base **1 s** and cap **120 s**. Each work item is processed under a **10 s**
deadline.

**Per-node decision.** Compute `(scheduled, running)` over the agent pods
indexed for that node:

- `scheduled` = at least one agent pod is indexed for the node.
- `running` = at least one such pod has **no** `deletionTimestamp` **and** its
  most recent `Ready` condition is `True`. A terminating pod never counts as
  running, even while its `Ready` condition still says `True`.

| State | Key | Precondition | Action |
|---|---|---|---|
| running | `remove-cilium-node-taints` (default **true**) | node carries the taint | remove the taint (below) |
| running | `set-cilium-is-up-condition` (default **true**) | node lacks the marker condition | set `NetworkUnavailable=False` (below) |
| scheduled ∧ ¬running | `set-cilium-node-taints` (default **false**) | node lacks the taint | add the taint |

If **both** `remove-cilium-node-taints` and `set-cilium-is-up-condition` are
false, the controller does not start at all — `set-cilium-node-taints` alone is
not enough to bring it up. This is a reference quirk that flowsdn keeps,
because starting the taint-adder without the taint-remover would wedge a
cluster.

**Taint removal — the JSON patch.** The operator MUST use a JSON Patch
(`application/json-patch+json`) of exactly two operations against `Node`:

```
[ { "op": "test",    "path": "/spec/taints", "value": <the observed taints array> },
  { "op": "replace", "path": "/spec/taints", "value": <observed minus the agent-not-ready taint> } ]
```

The `test` operation is the optimistic-concurrency mechanism: if any other
controller has changed `spec.taints` since the informer's snapshot, the whole
patch fails atomically with `422` and the item is requeued. A blind `replace`
would silently drop a taint another controller added in the interim (a real
hazard: the cloud controller manager, the node-lifecycle controller and
descheduler all write `spec.taints`). Strategic-merge patch is not usable here
because `taints` has no merge key.

The taint key is `node.cilium.io/agent-not-ready`, overridable by the agent key
`agent-not-ready-taint-key` (the operator reads the agent's key from the shared
ConfigMap). Removal matches on **key only** — any value and any effect.

flowsdn keeps this key rather than a `node.flowsdn.io/...` key: the taint is
placed by kubeadm/cloud-init/Karpenter templates and cluster-API bootstrap
configs that exist before flowsdn is installed, and renaming it strands them
(Open Decision 4).

**Taint addition** (`set-cilium-node-taints`) uses the identical two-op patch
with the appended taint `{key: node.cilium.io/agent-not-ready, value: "",
effect: NoSchedule}`. Note the effect: the operator adds `NoSchedule`, while
the documented bootstrap taint is often `NoExecute`. Removal is
effect-agnostic, so this asymmetry is harmless.

**The condition.** Set with a **strategic merge patch** on the `status`
subresource:

```
{"status":{"conditions":[{
   "type":"NetworkUnavailable","status":"False",
   "reason":"CiliumIsUp","message":"Cilium is running on this node",
   "lastTransitionTime":<now>,"lastHeartbeatTime":<now>}]}}
```

`conditions` has `type` as its patch merge key, so this upserts the one entry
without touching `Ready`, `MemoryPressure`, etc.

**Idempotency.** The operator MUST NOT patch when the node already carries a
condition with `type == NetworkUnavailable && status == False && reason ==
CiliumIsUp`. That triple — not the message, not the timestamps — is the marker.
Patching unconditionally would rewrite `lastHeartbeatTime` on every agent-pod
update and generate node writes proportional to pod churn.

flowsdn **never sets `NetworkUnavailable=True`**. The condition is set to
`True` by cloud controller managers (notably GCP) that expect the network
provider to clear it; clearing it is the entire job. A node with no such
condition still gets the `False`/`CiliumIsUp` entry, because that entry is also
how the operator (and humans) tell "Cilium is up here" from "nothing has
looked at this node".

**Retries.** Errors requeue with the work queue's rate limiter. `NotFound`
(node deleted) forgets the key immediately. The first **6** consecutive
failures for a key log at debug; from the 7th the log level rises to warn. On
eventual success, if the key had been requeued 6 or more times, one info line
records the recovery. Success otherwise forgets the key silently.

### 3.11 Unmanaged pod detection and restart

Purpose: a pod that started before the CNI was ready has no Cilium networking
and will never get any — it must be recreated. In practice this is CoreDNS on
a fresh cluster, which is why the default selector is `k8s-app=kube-dns`.

- Interval `unmanaged-pod-watcher-interval` (15 s); `0` disables. Also disabled
  when `disable-endpoint-crd` is set (there are no CEPs to compare against).
- Input: pods matching `pod-restart-selector` (default `k8s-app=kube-dns`;
  empty selector means **all** pods) with the server-side field selector
  `status.phase=Running`, plus the `CiliumEndpoint` store.
- A pod is **unmanaged** when: it matches the selector, is `Running`, is
  **not** `hostNetwork`, and there is **no** `CiliumEndpoint` with the same
  namespace and name.
- The count of unmanaged pods is published as the gauge
  `cilium_operator_unmanaged_pods` **before** any restart, so the gauge is
  accurate even on cycles that restart something.
- A pod is a **restart candidate** if it is unmanaged, has a `status.startTime`,
  is older than **30 s**, and has not been restarted by this operator within
  the last **5 minutes**.
- **At most one pod is deleted per cycle.** This is the load-bearing detail:
  restarting every replica of CoreDNS at once takes DNS down for the cluster.
  If the delete fails, the next candidate in the list is tried, so one bad pod
  does not stall the cycle.
- The restart is a plain `DELETE`; the ReplicaSet/DaemonSet recreates the pod.
- Restart history is kept in memory keyed `<namespace>/<name>` and entries older
  than **10 minutes** (2× the cooldown) are dropped.

RBAC note: `delete` on `pods` is only granted when the feature is enabled in
Helm (§4.8). An operator without it logs the restart attempt and fails; the
gauge still works.

### 3.12 CiliumNetworkPolicy status validator

`validate-network-policy` (default true). Purely **informational**: the agent
enforces a policy regardless of what this writes. It exists so that
`kubectl describe cnp` explains why a policy is not doing what the author
expected.

- Registered for `CiliumNetworkPolicy` when `enable-cilium-network-policy`, and
  for `CiliumClusterwideNetworkPolicy` when
  `enable-cilium-clusterwide-network-policy`.
- On every upsert event: run the policy's own validation (`Sanitize`, spec
  `06-policy-engine.md`) over `spec` and every entry of `specs`, joining all
  errors. In addition, any rule carrying an `authentication` block is an error
  when mutual authentication is disabled. **DEVIATION**: flowsdn does not
  implement mutual auth at all (§1), so this check is unconditional — every
  policy with an `authentication` block is reported `Valid=False` with a
  message naming the unsupported field. The agent likewise ignores the block,
  so the status is the only place a user learns it is inert.
- Compute the desired condition:
  - no errors → `{type: Valid, status: True, message: "Policy validation succeeded"}`
  - errors → `{type: Valid, status: False, message: <joined error text>}`
- Upsert it into `status.conditions` by `type`:
  - if an entry with `type == Valid` exists with the same `status` **and** the
    same `message`, do nothing at all (no write);
  - if it exists with the same `status` but a different `message`, replace the
    entry but **keep** the old `lastTransitionTime` — the condition did not
    transition, only its explanation changed;
  - otherwise replace/append with `lastTransitionTime = now`.
- Write via the `status` subresource, so `metadata.generation` is not bumped and
  the write does not re-trigger the agents' policy watchers.
- No write at all if the resulting status deep-equals the observed status.

This is the only remaining CNP status writer at this tag; the old per-node
`status.nodes` map and `cnp-status-*` keys are gone and flowsdn does not
reintroduce them.

### 3.13 kvstore-mode duties

These duties only exist when `kvstore` is set (i.e. `etcd`). They are the
operator's half of ClusterMesh. The **key schema, value encoding, lease and
canary semantics are specified in the ClusterMesh + kvstore spec** and are not
restated here; what follows is the operator's obligation.

| Duty | Key | Behavior |
|---|---|---|
| **Service sync** | `synchronize-k8s-services` (true) | Mirror every non-headless `Service` that is shared (annotated `service.cilium.io/global=true`, or in a global namespace per `clustermesh-default-global-namespace`) into the kvstore as a `ClusterService`. Backed by a work queue with retry; a failed write is retried, never dropped. Only runs when the service-mode configuration says legacy service export is wanted |
| **EndpointSlice export sync** | `synchronize-k8s-services` (true) | Export the `EndpointSlice`s of shared services as cluster endpoint-slice entries (service mode v2) |
| **kvstore node GC** | `synchronize-k8s-nodes` (true) | After the k8s `Node` informer has completed its initial list — **not before**, or every node is deleted — delete kvstore node entries for the local cluster whose `Node` no longer exists |
| **Lock sweeper** | always (kvstore mode) | Remove stale lock keys left behind by crashed agents |
| **Heartbeat** | always (kvstore mode) | Write the heartbeat key on a lease so agents can detect a stale kvstore |
| **Cluster config** | always (kvstore mode) | Publish this cluster's ID and capabilities; re-write it if a foreign writer changes or deletes it |
| **Remote cluster connections** | `clustermesh-config` | Maintain connections to remote clusters listed in the config directory and expose their status on `GET /v1/cluster` (§3.16) |
| **Endpoint sync (inbound)** | `clustermesh-enable-endpoint-sync` | Materialise remote `ClusterService`s as local `discovery.k8s.io/EndpointSlice`s labelled for the local `Service`, so kube-proxy-less DNS and non-Cilium consumers see remote endpoints. Sizing `clustermesh-endpoints-per-slice` (100), batching `clustermesh-endpoint-updates-batch-period` (500 ms), parallelism `clustermesh-concurrent-service-endpoint-syncs` (5) |
| **MCS-API** | `clustermesh-enable-mcs-api` | `ServiceExport` → kvstore; `ServiceImport` + derived local `Service` |

The **node GC ordering constraint** deserves emphasis: it is the one duty where
running before informers are synced destroys the cluster. It MUST wait on the
`informers-synced` fence for the `Node` informer specifically, and MUST NOT run
if that informer's initial list failed.

Identity GC in kvstore mode is a *different* duty and is specified in
`03-identity-ipcache.md` §3.6; it also sits inside the leader scope and it
blocks on the kvstore client being initialised (§3.3 constraint 2).

### 3.14 Secret and ConfigMap synchronization

Agents' Envoy needs TLS material, but agent RBAC is deliberately scoped to a
single namespace so that a compromised agent cannot read every Secret in the
cluster. The operator is the bridge: it copies referenced Secrets into that
namespace.

**Registrations.** Three producers register with one generic syncer, each
supplying: the referencing object kind, a mapper from that object to the
Secrets it references, a predicate answering "is this Secret still referenced
by anything", and a target namespace.

| Registration | Enabled by | Target namespace key (default) | Sources |
|---|---|---|---|
| Ingress | `enable-ingress-secrets-sync` (true) ∧ `enable-ingress-controller` | `ingress-secrets-namespace` (`cilium-secrets`) | `Ingress.spec.tls[].secretName`, plus the fallback `ingress-default-secret-namespace`/`-name` |
| Gateway API | `enable-gateway-api-secrets-sync` (true) ∧ gateway API enabled | `gateway-api-secrets-namespace` (`cilium-secrets`) | `Gateway`/`ListenerSet` listener `tls.certificateRefs`, and `BackendTLSPolicy.validation.caCertificateRefs` (ConfigMaps) |
| Network policy | `enable-policy-secrets-sync` | `policy-secrets-namespace` (`cilium-secrets`) | Secrets referenced by policy TLS interception rules |

**Copy semantics.**

- Copy name: `cilium-sync-secret-<hex>` where `<hex>` is the lowercase
  SHA-256 of `"secret" || 0x00 || <source namespace> || 0x00 || <source name>`.
  ConfigMap copies (which are materialised as Secrets so Envoy's SDS can serve
  them uniformly) use prefix `cilium-sync-cfgmap-` and the digest input
  `"configmap" || 0x00 || <ns> || 0x00 || <name>`.
  The hash exists because the previous scheme, `<ns>-<name>`, is ambiguous:
  namespace `a-b`/name `c` and namespace `a`/name `b-c` collide.
- **Legacy cleanup**: the reconciler also deletes any object at the old
  `<ns>-<name>` (Secrets) / `<ns>-cfgmap-<name>` (ConfigMaps) name for the same
  source, so an upgrade from a Cilium install does not leave orphans.
- Ownership labels on the copy, set to the source's namespace and name. The
  label **pair depends on the source kind**:
  - Secret source: `secretsync.cilium.io/owning-secret-namespace` and
    `secretsync.cilium.io/owning-secret-name`
  - ConfigMap source: `secretsync.cilium.io/owning-configmap-namespace` and
    `secretsync.cilium.io/owning-configmap-name`

  (Both kinds materialise as `Secret` objects in the target namespace, so the
  label pair is the only thing distinguishing their provenance for the
  ownership check.) The reconciler MUST refuse to overwrite an existing copy that
  carries no ownership labels, or whose labels name a different source, and log
  the refusal — that is a name collision or a hand-made object, and clobbering
  it is worse than failing.
- Provenance annotations on the copy:
  `secretsync.cilium.io/source-kind` (`Secret` | `ConfigMap`),
  `secretsync.cilium.io/source-namespace`, `secretsync.cilium.io/source-name`.
- A copy whose source Secret is no longer referenced by **any** registration is
  deleted.
- Every synced object is re-reconciled after a jittered interval: base
  **1 hour**, jittered by ±**20 %**, so a large fleet of copies does not
  stampede the apiserver on the hour.

**BGP** also consumes Secrets (peer passwords), read directly by the operator
from its `get/list/watch` on `secrets`; those are not copied.

### 3.15 Gateway API and Ingress — trigger conditions only

The translation pipeline (ingestion → model → Envoy `CiliumEnvoyConfig`) is a
separate spec. What is normative **here** is when the controllers may start,
because that determines the operator's startup behavior and health.

**Gateway API preconditions**, evaluated in order at leader start:

1. `enable-gateway-api` is true. This key is set by Helm directly into the
   `cilium-config` ConfigMap and is not exposed as a registered flag in the
   reference; flowsdn registers it as an ordinary key (**DEVIATION**, cosmetic:
   the ConfigMap contract is unchanged).
2. `kube-proxy-replacement` is true. If not: log one warning naming the key and
   **disable Gateway API**. Not fatal — a cluster with kube-proxy is a valid
   cluster, it just cannot host Cilium's Gateway.
3. `gateway-api-service-externaltrafficpolicy` parses as `Cluster` or `Local`.
   Invalid → **fatal**, this is a typo in configuration.
4. CRD discovery succeeds (below).

**Required CRDs** — all must be present, all group `gateway.networking.k8s.io`,
version `v1`:

| Kind |
|---|
| `GatewayClass` |
| `Gateway` |
| `HTTPRoute` |
| `GRPCRoute` |
| `TLSRoute` |
| `ReferenceGrant` |
| `BackendTLSPolicy` |

**Optional CRDs** — presence enables extra features, absence is silent:

| Kind | Group/version |
|---|---|
| `ListenerSet` | `gateway.networking.k8s.io/v1` |
| `TCPRoute` | `gateway.networking.k8s.io/v1` |
| `UDPRoute` | `gateway.networking.k8s.io/v1` |
| `ServiceImport` | `multicluster.x-k8s.io/v1beta1` |

Discovery matches on the **plural resource name** (`gatewayclasses`,
`httproutes`, `backendtlspolicies`, …), not the singular Kind. The reference's
"kind" constants in fact hold the plurals; flowsdn names the field honestly but
MUST match on the same strings, because that is what the discovery API returns.

**Discovery with retry.** Discovery is attempted in a loop with exponential
backoff, minimum **200 ms**, maximum **5 s**, factor 2, jittered, under an
overall deadline of **30 s**. Outcomes:

| Outcome | Result |
|---|---|
| All required kinds found | Gateway API enabled; the installed optional kinds are recorded and their controllers/scheme entries registered |
| A required kind is missing (a definitive answer from the apiserver) | Gateway API **disabled**, health module `degraded` with "CRDs not installed", operator continues. Not fatal — the user has not installed the Gateway API CRDs |
| Transient error (apiserver unreachable) | retry with backoff; health `degraded` |
| Deadline expires while still retrying transient errors | **fatal**: the operator exits so it restarts. A 30 s inability to talk to the apiserver at startup is not something to run through |

Note the asymmetry, and keep it: *missing* is a user state, *unreachable* is an
operator state.

**Controller name** is `io.cilium/gateway-controller`. A `GatewayClass` is
accepted only when its `spec.controllerName` matches this string exactly. It is
part of the compatibility surface — users' `GatewayClass` manifests name it
(Open Decision 5).

**CRDs the operator creates for Gateway API**: only
`CiliumGatewayClassConfig` (v2alpha1), and only when `enable-gateway-api` is
set (§3.4). The operator never creates upstream Gateway API CRDs.

**Ingress** is enabled by `enable-ingress-controller`, handles the `cilium`
`IngressClass`, and additionally handles class-less Ingresses when that
`IngressClass` is annotated
`ingressclass.kubernetes.io/is-default-class: "true"`. It has no CRD
precondition. Everything else about it belongs to the Gateway API spec.

### 3.16 Operator API and health

**Listener.** `operator-api-serve-addr`, default `localhost:9234`. When the
address is empty, the operator binds two listeners, `127.0.0.1:0` and
`[::1]:0`, so a v4-only or v6-only host still gets one; at least one must bind
or startup fails. The listening socket MUST set `SO_REUSEADDR` **and**
`SO_REUSEPORT` — with Helm's `hostNetwork: true` and two replicas, both pods
can land on one node in a small cluster and would otherwise collide on 9234.

**Routes.**

| Path | Method | Response |
|---|---|---|
| `/healthz` | GET | alias of `/v1/healthz`; `text/plain`. This is the path kubelet probes |
| `/v1/healthz` | GET | `text/plain` |
| `/v1/metrics/` | GET | JSON array of `{name, labels{}, value}` |
| `/v1/cluster` | GET | JSON array of remote-cluster status objects |

**Health semantics** (`/healthz`):

| Condition | Status | Body |
|---|---|---|
| k8s is disabled | **501** | explanatory text |
| kvstore configured and its status is not `ok` | **500** | the kvstore's message |
| apiserver version query fails | **500** | the error |
| otherwise | **200** | `ok` |

Deliberately, **leadership is not part of the verdict**. A follower that can
reach the apiserver is healthy; failing its probe would restart the standby in
a loop. The `is_leader` flag is exposed in `/v1/metrics/` and the health
module tree instead.

Consecutive failures are counted and logged with the count; a success after
failures logs one recovery line.

**Access control.** `enable-cilium-operator-server-access` is a list of API
operations that are administratively enabled; entries are operation names with
glob support (`Get*`), and `*` (the default) means all. Every operation not
matched is denied: it returns **403** with the body

```
This API is administratively disabled. Contact your administrator for more details.
```

and logs one line naming the endpoint. This is a blunt allowlist, not
authentication — the listener is on localhost/hostNetwork and the threat model
is "do not expose `/v1/cluster` on a shared node", not authorization. The
manually-registered `/healthz` alias is outside the generated router and is
therefore **not** subject to the allowlist; kubelet probes keep working
whatever the setting.

**Probes** (Helm, part of the compatibility surface):

| Probe | Path | Port | Timing |
|---|---|---|---|
| liveness | `/healthz` | 9234 | `initialDelaySeconds: 60`, `periodSeconds: 10`, `timeoutSeconds: 3` |
| readiness | `/healthz` | 9234 | `initialDelaySeconds: 0`, `periodSeconds: 5`, `timeoutSeconds: 3`, `failureThreshold: 5` |

With `hostNetwork: true` the probes target `127.0.0.1` (or `::1` when IPv4 is
disabled).

**Prometheus** listens separately on `operator-prometheus-serve-addr` (`:9963`)
when `enable-metrics` is set, optionally with TLS/mTLS
(`operator-prometheus-enable-tls`, `-tls-cert-file`, `-tls-key-file`,
`-tls-client-ca-files`).

## 4. Data model

### 4.1 Lease

`coordination.k8s.io/v1 Lease`, name `cilium-operator-resource-lock`, in the
operator namespace.

| Field | Written by the operator |
|---|---|
| `spec.holderIdentity` | `<hostname>-<10 random chars>` |
| `spec.leaseDurationSeconds` | `leader-election-lease-duration` in seconds (15) |
| `spec.acquireTime` | set on acquisition (transition), preserved on renewal |
| `spec.renewTime` | set on every renewal |
| `spec.leaseTransitions` | incremented on every acquisition from a different holder |

### 4.2 CRDs created or updated

Group `cilium.io`, `apiextensions.k8s.io/v1`. Storage version in bold. The
full OpenAPI schemas are the vendored YAML and are catalogued per-field in
`docs/inventory/13-crds-k8s.md`; they are not duplicated here.

| Kind | Plural | Scope | Versions (storage bold) | Subresources | Gate |
|---|---|---|---|---|---|
| CiliumIdentity | `ciliumidentities` | Cluster | **v2** | status (unused) | always |
| CiliumPodIPPool | `ciliumpodippools` | Cluster | **v2alpha1** | – | always |
| CiliumLoadBalancerIPPool | `ciliumloadbalancerippools` | Cluster | **v2**, v2alpha1 (deprecated) | status | always |
| CiliumL2AnnouncementPolicy | `ciliuml2announcementpolicies` | Cluster | **v2alpha1** | status | always |
| CiliumNodeConfig | `ciliumnodeconfigs` | Namespaced | **v2** | – | always (operator-only) |
| CiliumEndpoint | `ciliumendpoints` | Namespaced | **v2** | – | `!disable-endpoint-crd` |
| CiliumEndpointSlice | `ciliumendpointslices` | Cluster | **v2alpha1** | – | `enable-cilium-endpoint-slice` |
| CiliumNode | `ciliumnodes` | Cluster | **v2** | status | `enable-ciliumnode-crd` |
| CiliumNetworkPolicy | `ciliumnetworkpolicies` | Namespaced | **v2** | status | `enable-cilium-network-policy` |
| CiliumClusterwideNetworkPolicy | `ciliumclusterwidenetworkpolicies` | Cluster | **v2** | status | `enable-cilium-clusterwide-network-policy` |
| CiliumCIDRGroup | `ciliumcidrgroups` | Cluster | **v2**, v2alpha1 (deprecated) | – | either policy CRD |
| CiliumEgressGatewayPolicy | `ciliumegressgatewaypolicies` | Cluster | **v2** | – | `enable-egress-gateway` |
| CiliumLocalRedirectPolicy | `ciliumlocalredirectpolicies` | Namespaced | **v2** | – | `enable-local-redirect-policy` |
| CiliumEnvoyConfig | `ciliumenvoyconfigs` | Namespaced | **v2** | – | `enable-envoy-config` |
| CiliumClusterwideEnvoyConfig | `ciliumclusterwideenvoyconfigs` | Cluster | **v2** | – | `enable-envoy-config` |
| CiliumBGPClusterConfig | `ciliumbgpclusterconfigs` | Cluster | **v2**, v2alpha1 | status | `enable-bgp-control-plane` |
| CiliumBGPPeerConfig | `ciliumbgppeerconfigs` | Cluster | **v2**, v2alpha1 | status | `enable-bgp-control-plane` |
| CiliumBGPAdvertisement | `ciliumbgpadvertisements` | Cluster | **v2**, v2alpha1 | – | `enable-bgp-control-plane` |
| CiliumBGPNodeConfig | `ciliumbgpnodeconfigs` | Cluster | **v2**, v2alpha1 | status | `enable-bgp-control-plane` |
| CiliumBGPNodeConfigOverride | `ciliumbgpnodeconfigoverrides` | Cluster | **v2**, v2alpha1 | – | `enable-bgp-control-plane` |
| CiliumDatapathPlugin | `ciliumdatapathplugins` | Cluster | **v2alpha1** | – | `enable-datapath-plugins` |
| CiliumGatewayClassConfig | `ciliumgatewayclassconfigs` | Namespaced | **v2alpha1** | status | `enable-gateway-api` |
| ServiceExport / ServiceImport | `serviceexports` / `serviceimports` | Namespaced | `multicluster.x-k8s.io/v1beta1` | status | `clustermesh-enable-mcs-api` ∧ `clustermesh-mcs-api-install-crds` |

Every one carries `metadata.labels["io.cilium.k8s.crd.schema.version"]`. No
CRD has a conversion webhook; multi-version CRDs use strategy `None` with
byte-identical schemas across versions.

### 4.3 CiliumEndpointSlice

```
CiliumEndpointSlice (cilium.io/v2alpha1, cluster-scoped)
  metadata.name : "ces-" + 9 chars + "-" + 5 chars   # alphabet bcdfghjklmnpqrstvwxyz2456789
  namespace     : string          # the namespace whose CEPs this slice holds
  endpoints     : [CoreCiliumEndpoint]   # required, ≤ ces-max-ciliumendpoints-per-ces

CoreCiliumEndpoint          # JSON keys are frozen — agents parse them
  name            : string          json:"name"
  id              : int64           json:"id"              # numeric security identity
  pod-uid         : string          json:"pod-uid"
  networking      : EndpointNetworking  json:"networking"  # addressing{ipv4,ipv6} + node
  encryption      : {key: int}      json:"encryption"
  named-ports     : [{name, port, protocol}]  json:"named-ports"
  service-account : string          json:"service-account"
```

The name alphabet excludes vowels and visually ambiguous digits (`0`, `1`) for
the same reason k8s generated names do: the names appear in logs and are read
aloud.

### 4.4 Node objects written

| Object | Field | Patch type | Content |
|---|---|---|---|
| `Node` | `spec.taints` | JSON Patch, `test` + `replace` | agent-not-ready taint added or removed |
| `Node` | `status.conditions` | strategic merge on `status` | `NetworkUnavailable=False`, `Reason=CiliumIsUp`, `Message="Cilium is running on this node"` |

### 4.5 Synced Secret / ConfigMap copies

```
Secret in <target namespace>
  metadata.name        : "cilium-sync-secret-" + hex(sha256("secret\0<ns>\0<name>"))
                       | "cilium-sync-cfgmap-" + hex(sha256("configmap\0<ns>\0<name>"))
  metadata.labels      : secretsync.cilium.io/owning-secret-namespace    = <src ns>     # Secret source
                         secretsync.cilium.io/owning-secret-name         = <src name>
                       | secretsync.cilium.io/owning-configmap-namespace = <src ns>     # ConfigMap source
                         secretsync.cilium.io/owning-configmap-name      = <src name>
  metadata.annotations : secretsync.cilium.io/source-kind      = "Secret" | "ConfigMap"
                         secretsync.cilium.io/source-namespace = <src ns>
                         secretsync.cilium.io/source-name      = <src name>
  data                 : copied verbatim
```

### 4.6 Operator API models

```
Metric      { name: string, labels: map<string,string>, value: number }
Healthz     text/plain: "ok" | "<error message>"
Cluster     [ RemoteCluster ]   # shape owned by the ClusterMesh spec
```

Histograms and summaries are **expanded** into several `Metric` entries in the
JSON rendering, one per quantile, distinguished by the synthetic label
`quantile`. Histograms emit `0.5`, `0.9`, `0.99`; summaries emit their own
configured quantiles formatted with the shortest representation that round-trips
(`0.5`, not `0.500000`). The Prometheus endpoint on 9963 is unaffected — this
expansion exists only because the JSON model has a single scalar `value`.

### 4.7 In-memory state (per leader term)

| Structure | Lifetime | Content |
|---|---|---|
| CES ↔ CEP mapping | leader term | which CES holds which endpoints, per-CES CEP count and namespace |
| Priority namespace set | leader term | namespaces annotated `cilium.io/ces-namespace=priority` |
| CiliumNode GC candidates | leader term | node name → first-seen-orphaned timestamp |
| Unmanaged pod restart history | leader term | `<ns>/<name>` → last restart time, pruned at 10 min |
| Identity lifesign map | leader term | spec `03` §3.6 |
| Agent pod index | leader term | node name → agent pods (trimmed objects) |

All of it is rebuilt from the apiserver on a new leader term. Nothing is
persisted; the only on-disk state is the health history log (spec `00` §3.4.3).

### 4.8 RBAC

The operator's ServiceAccount needs the following. "cond:" marks a block that
Helm only emits when the named feature is on; flowsdn keeps the same
conditionality so a minimal install has a minimal role.

**ClusterRole — core:**

| apiGroup | Resources | Verbs |
|---|---|---|
| `""` | `pods` | get, list, watch (+ **delete**, cond: unmanaged-pod restart enabled ∧ interval ≠ 0 ∧ CEP CRD enabled) |
| `""` | `configmaps` (`resourceNames: cilium-config`) | patch |
| `""` | `nodes` | list, watch (cond: taint removal ∨ condition setting ∨ CEP GC) |
| `""` | `nodes` | patch (cond: `remove-cilium-node-taints`) |
| `""` | `nodes/status` | patch (cond: `set-cilium-is-up-condition`) |
| `""` | `namespaces`, `serviceaccounts` | get, list, watch |
| `""` | `secrets` | get, list, watch (cond: ingress ∨ gateway ∨ BGP ∨ secret sync) |
| `""` | `services` | get, list, watch (+ create, update, delete, patch — cond: ingress ∨ gateway) |
| `""` | `services/status` | update, patch |
| `""` | `services/finalizers` | update (cond: clustermesh endpoint-slice sync) |
| `""` | `events` | create, patch (cond: clustermesh endpoint-slice sync) |
| `discovery.k8s.io` | `endpointslices` | get, list, watch (+ create, update, delete, deletecollection — cond: clustermesh EPS sync ∨ MCS-API; + create, update, delete, patch — cond: ingress ∨ gateway) |
| `coordination.k8s.io` | `leases` | create, get, update |
| `apiextensions.k8s.io` | `customresourcedefinitions` | create, get, list, watch |
| `apiextensions.k8s.io` | `customresourcedefinitions` **restricted by `resourceNames`** to the CRD list of §4.2 | update |
| `apiextensions.k8s.io` | `customresourcedefinitions/status`, `resourceNames` = the five BGP CRDs | update |

The `resourceNames` restriction on CRD `update` is the important one: it means
a compromised operator cannot rewrite an unrelated CRD in the cluster. flowsdn
MUST keep it and MUST keep the name list in sync with §4.2 — adding a CRD
without adding its name silently breaks upgrades.

**ClusterRole — `cilium.io`:**

| Resources | Verbs |
|---|---|
| `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies` | create, update, deletecollection, patch, get, list, watch |
| `ciliumnetworkpolicies/status`, `ciliumclusterwidenetworkpolicies/status` | patch, update |
| `ciliumendpoints`, `ciliumidentities` | delete, list, watch |
| `ciliumidentities` | update (+ **create**, cond: `identity-management-mode ∈ {operator, both}`) |
| `ciliumnodes` | create, update, get, list, watch (+ **delete**, cond: `nodes-gc-interval ≠ 0`) |
| `ciliumnodes/status` | update |
| `ciliumendpointslices`, `ciliumenvoyconfigs`, `ciliumcidrgroups`, and all five BGP kinds | create, update, get, list, watch, delete, patch |
| `ciliumendpointslices` | deletecollection |
| `ciliumbgpclusterconfigs/status`, `ciliumbgppeerconfigs/status` | update |
| `ciliumloadbalancerippools`, `ciliumpodippools`, `ciliumbgppeerconfigs`, `ciliumdatapathplugins` | get, list, watch |
| `ciliumpodippools` | create |
| `ciliumloadbalancerippools/status` | patch |

**ClusterRole — Ingress (cond):** `networking.k8s.io` `ingresses`,
`ingressclasses` get/list/watch; `ingresses/status`, `ingresses/finalizers`
update.

**ClusterRole — Gateway API (cond):** `gateway.networking.k8s.io`
`gatewayclasses`, `gateways`, `httproutes`, `grpcroutes`, `tlsroutes`,
`tcproutes`, `udproutes`, `referencegrants`, `referencepolicies`,
`backendtlspolicies`, `listenersets` get/list/watch; `gatewayclasses` patch;
all of `*/status` update/patch; `cilium.io` `ciliumgatewayclassconfigs`
get/list/watch and `/status` update/patch; `""` `configmaps` get/list/watch.

**ClusterRole — MCS-API (cond):** `multicluster.x-k8s.io` `serviceimports`
get/list/watch (+ create/update/patch/delete), `serviceimports/status`
update/patch, `serviceimports/finalizers` update, `serviceexports`
get/list/watch, `serviceexports/status` update/patch; `""` `services`
create/update/patch/delete.

**Roles (namespaced), one per secrets namespace in use:** `""` `secrets`
create, delete, update, patch — in `ingress-secrets-namespace`,
`gateway-api-secrets-namespace` and `policy-secrets-namespace` respectively.
The operator has **no cluster-wide secret write** permission; that asymmetry is
the point of the design in §3.14.

**Not granted** (dropped features, §1): `apps` `daemonsets` (ztunnel).

## 5. Algorithms

### 5.1 CES bin packing

```
place(cep):
    ces = largest_available(cep.namespace)
    if ces is None:
        ces = new_ces(namespace = cep.namespace)   # name from 5.3
    insert cep into ces

largest_available(ns):
    best = None; best_count = 0
    for ces in all_slices:
        if ces.namespace != ns: continue
        n = count(ces)
        if n < max_ceps and n > best_count:
            best = ces; best_count = n
            if best_count == max_ceps - 1: break      # cannot do better
    return best
```

Two consequences to preserve exactly:

- The comparison is `n > best_count` with `best_count` initialised to **0**, so
  an **empty** CES is never selected. An emptied slice is therefore left alone
  rather than refilled — it is eventually deleted when it stays empty.
- The early exit at `max_ceps - 1` bounds the scan for the common case.

The scan is O(number of slices). At 100 per slice and 100 000 endpoints that is
1 000 slices scanned per placement; an index from namespace → slices, and
within it a bucket by fill level, reduces it to O(1) and is behaviour-preserving.

### 5.2 Dynamic rate limit selection

```
parse ces-rate-limits as [ {nodes:int, limit:float, burst:int} ], reject unknown fields
sort ascending by nodes
select(node_count):
    chosen = entries[0]
    for e in entries: if e.nodes <= node_count: chosen = e else break
    return chosen
```

Applied at startup with `node_count = 0`, and re-evaluated on every
`CiliumNode` add/delete. A change adjusts the live limiter's rate and burst;
tokens already in the bucket are kept.

### 5.3 CES name generation

`"ces-" + rand9 + "-" + rand5` over the alphabet
`bcdfghjklmnpqrstvwxyz2456789` (28 symbols). Regenerate on collision with a
name already known to the controller. Collision probability per draw is
negligible (28^14 ≈ 2^67); the retry loop exists to make the function total.

### 5.4 Two-pass hysteresis (shared shape)

Three GCs use the same shape and it is worth naming once:

| GC | Pass 1 | Pass 2 | Why two passes |
|---|---|---|---|
| Identity (spec `03` §3.6) | annotate `io.cilium.heartbeat` | delete if still unused | the annotation write is itself a lifesign, so the delete is at least one heartbeat timeout later |
| `CiliumNode` (§3.9) | record candidacy with a timestamp | delete once orphaned for ≥ one interval | an informer that has not yet seen a new `Node` must not delete its `CiliumNode` |
| `CiliumEndpoint` (§3.6) | the age check (`< interval` → keep) is the first pass | delete | the pod informer may lag the CEP informer |

The invariant in all three: **never act on the first observation of an
absence.** An absence in an informer store is indistinguishable from a
not-yet-delivered event.

### 5.5 CRD schema-version comparison

Parse the installed label as semver. Update iff: the label is missing, or the
value fails to parse, or `installed < binary`. Never on `installed == binary`
or `installed > binary`. Pre-release and build metadata follow semver ordering.
A non-semver value (e.g. someone set the label to `latest`) is treated as
"older" and overwritten — that is the reference behavior and it is the right
one: an unparsable version conveys no information.

### 5.6 Slim-mode identity and encryption key derivation

Used only in `ces-controller-mode=slim`. Both must match the agent bit for bit.

**Identity key.** Take the pod's labels ∪ its namespace's labels, apply the
identity label filter (spec `03` §4.2), canonicalise to the label-string form
of spec `03` §4.1 with source `k8s`. Look up the `CiliumIdentity` whose
`security-labels` equal that key; its numeric name is the endpoint's `id`. If
no CID exists yet, the endpoint is **not placed** (the operator waits — placing
it with identity 0 would blackhole it). When duplicate CIDs exist for one key,
the controller caches its selection so the same CID is used consistently and
churn is avoided.

**Encryption key**, from the endpoint's node's `CiliumNode`:

```
if enable-wireguard:  key = <the WireGuard static key constant>
elif enable-ipsec:    key = ciliumnode.spec.encryption.key
else:                 key = 0
```

A pod event that arrives before its node's `CiliumNode` event yields "key not
yet known"; the endpoint is placed once the node is seen, and a node's key
change re-enqueues every CES holding endpoints on that node.

### 5.7 Startup replay (CES)

```
1. list CiliumEndpointSlice → for each: register (name, namespace);
                              for each endpoint: map endpoint → this CES
2. list sources (CEPs | Pods+CIDs+CiliumNodes)
3. for each source not in the map: place() it (5.1)
   for each mapped endpoint with no source: remove it from its CES
4. enqueue every touched CES
```

Step 1 must complete before step 3 or slices are duplicated (§3.7.4).

### 5.8 Retry and backoff summary

| Operation | Policy |
|---|---|
| CRD update / establish poll | fixed 500 ms, 60 s cap |
| CES work queue | exponential 1 s → 100 s, 15 retries, then drop with error |
| CES apiserver writes | token bucket from `ces-rate-limits` |
| Node taint queue | exponential 1 s → 120 s; unlimited retries; log level rises after 6 |
| CES one-shot GC | exponential 1 m → 5 m, 3 attempts |
| Gateway API CRD discovery | exponential 200 ms → 5 s, jittered, 30 s deadline |
| Secret resync | 1 h ± 20 % jitter |
| Periodic GCs (CEP, CiliumNode, identity) | fixed interval; a failed run logs and the next tick retries |

## 6. Configuration

Complete operator key table. Names are byte-identical to the reference so an
existing `cilium-config` ConfigMap works unchanged. Keys marked *(agent key)*
are owned by the agent's table (spec `00` §6.4) and read by the operator from
the shared ConfigMap; they are listed here because operator behavior depends on
them. Keys marked *(hidden)* are not shown in help output. Loading, precedence
and validation are spec `00` §3.3.

### 6.1 Process, leader election, client

| Key | Type | Default | Effect |
|---|---|---|---|
| `k8s-namespace` | string | "" | operator namespace: Lease, secrets, agent-pod watch. Empty → `default` for the Lease |
| `k8s-kubeconfig-path` | path | "" | out-of-cluster kubeconfig |
| `k8s-api-server-urls` | list | [] | apiserver endpoints |
| `k8s-client-connection-timeout` | duration | 30s | dial timeout |
| `k8s-client-connection-keep-alive` | duration | 30s | keepalive |
| `k8s-heartbeat-timeout` | duration | 30s | apiserver heartbeat |
| `operator-k8s-client-qps` | float | 100 | shared client QPS |
| `operator-k8s-client-burst` | int | 200 | shared client burst |
| `enable-k8s` | bool | true | k8s client at all |
| `enable-k8s-api-discovery` | bool | true (forced) | accepted and ignored: always on in the operator |
| `k8s-service-proxy-name` | string | "" | `service-proxy-name` label filter |
| `leader-election-lease-duration` | duration | 15s | §3.2 |
| `leader-election-renew-deadline` | duration | 10s | §3.2 |
| `leader-election-retry-period` | duration | 2s | §3.2 |
| `leader-election-resource-lock-timeout` | duration | 0 | HTTP timeout for lock ops; 0 → `max(1s, renew/2)` |
| `cluster-name` | string | `default` | ClusterMesh cluster name |
| `cluster-id` | u32 | 0 | ClusterMesh cluster ID |
| `max-connected-clusters` | u32 | 255 | 255 or 511, else fatal |
| `config` | path | "" | config file |
| `config-dir` | path | "" | one file per key (the ConfigMap mount) |
| `log-driver` | list | [] | logging |
| `log-opt` | map | {} | logging |
| `version` | bool | false | print version and exit |

### 6.2 CRDs

| Key | Type | Default | Effect |
|---|---|---|---|
| `skip-crd-creation` | bool | false | do not create/update CRDs (§3.4) |
| `disable-endpoint-crd` *(agent key, hidden)* | bool | false | no CEP CRD; forces one-shot CEP GC; disables unmanaged-pod restart |
| `enable-ciliumnode-crd` *(agent key, hidden)* | bool | true | false → CiliumNode CRD not created and all CiliumNodes deleted |
| `enable-cilium-network-policy` *(agent key, hidden)* | bool | true | CNP CRD + validator |
| `enable-cilium-clusterwide-network-policy` *(agent key, hidden)* | bool | true | CCNP CRD + validator |
| `enable-egress-gateway` *(agent key, hidden)* | bool | false | CEGP CRD |
| `enable-local-redirect-policy` *(agent key, hidden)* | bool | false | CLRP CRD |
| `enable-envoy-config` *(agent key)* | bool | false | CEC + CCEC CRDs |
| `enable-bgp-control-plane` *(agent key, hidden)* | bool | false | five BGP CRDs + BGP fan-out |
| `enable-datapath-plugins` *(agent key)* | bool | false | CiliumDatapathPlugin CRD |
| `enable-srv6` *(agent key, hidden)* | bool | false | accepted; no operator effect at this tag |
| `enable-k8s-network-policy` *(agent key, hidden)* | bool | true | accepted |

### 6.3 Garbage collection

| Key | Type | Default | Effect |
|---|---|---|---|
| `cilium-endpoint-gc-interval` | duration | 5m | §3.6; 0 → one-shot delete-all |
| `nodes-gc-interval` | duration | 5m | §3.9; 0 disables |
| `identity-gc-interval` | duration | 15m | spec `03` §3.6 |
| `identity-gc-rate-interval` | duration | 1m | spec `03` §3.6 |
| `identity-gc-rate-limit` | int | 2500 | spec `03` §3.6 |
| `identity-heartbeat-timeout` | duration | 30m | spec `03` §3.6 |
| `identity-allocation-mode` | string | `crd` | spec `03` §6; reference flag default is `kvstore`, Helm sets `crd` |
| `identity-management-mode` | `agent\|operator\|both` | `agent` | operator-managed CID creation (deferred, Open Decision 7) |
| `unmanaged-pod-watcher-interval` | duration | 15s | §3.11; 0 disables |
| `pod-restart-selector` | string | `k8s-app=kube-dns` | §3.11; empty = all pods |

### 6.4 CiliumEndpointSlice

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-cilium-endpoint-slice` *(agent key)* | bool | false | §3.7; false → one-shot CES GC (§3.8) |
| `ces-max-ciliumendpoints-per-ces` | int | 100 | slice capacity |
| `ces-rate-limits` | JSON string | `[{"nodes":0,"limit":10,"burst":20}]` | §5.2 |
| `ces-controller-mode` *(hidden)* | `default\|slim` | `default` | §3.7.2 |
| `enable-ipsec` *(agent key)* | bool | false | slim-mode encryption key (§5.6) |
| `enable-wireguard` *(agent key)* | bool | false | slim-mode encryption key (§5.6) |

### 6.5 Node taint and condition

| Key | Type | Default | Effect |
|---|---|---|---|
| `remove-cilium-node-taints` | bool | true | §3.10 |
| `set-cilium-node-taints` | bool | false | §3.10 |
| `set-cilium-is-up-condition` | bool | true | §3.10 |
| `taint-sync-workers` | int | 10 | queue workers |
| `cilium-pod-namespace` | string | = `k8s-namespace` | agent pod watch |
| `cilium-pod-labels` | string | `k8s-app=cilium` | agent pod selector |
| `agent-not-ready-taint-key` *(agent key)* | string | `node.cilium.io/agent-not-ready` | taint key |

### 6.6 kvstore and ClusterMesh

| Key | Type | Default | Effect |
|---|---|---|---|
| `kvstore` | string | "" | `etcd` or empty (disabled) |
| `kvstore-opt` | map | {} | backend options, e.g. `etcd.config=/var/lib/etcd-config/etcd.config` |
| `kvstore-lease-ttl` | duration | 15m | lease TTL |
| `kvstore-max-consecutive-quorum-errors` | uint | 2 | quorum failure threshold |
| `synchronize-k8s-services` | bool | true | §3.13 service + EPS export sync |
| `synchronize-k8s-nodes` | bool | true | §3.13 kvstore node GC |
| `clustermesh-config` | path | "" | remote cluster config directory |
| `clustermesh-cache-ttl` | duration | 0 | revoke remote cache after disconnect |
| `clustermesh-sync-timeout` | duration | 1m | initial remote sync bound |
| `clustermesh-default-global-namespace` | bool | true | namespaces global unless annotated |
| `clustermesh-enable-endpoint-sync` | bool | false | remote endpoints → local EndpointSlices |
| `clustermesh-endpoints-per-slice` | int | 100 | imported slice size |
| `clustermesh-endpoint-updates-batch-period` | duration | 500ms | batching |
| `clustermesh-concurrent-service-endpoint-syncs` | int | 5 | workers |
| `clustermesh-enable-mcs-api` | bool | false | MCS-API controllers |
| `clustermesh-mcs-api-install-crds` | bool | true | install MCS CRDs |
| `policy-default-local-cluster` | bool | true | policy assumes local cluster |

### 6.7 Policy, LB, secrets

| Key | Type | Default | Effect |
|---|---|---|---|
| `validate-network-policy` | bool | true | §3.12 |
| `policy-external-group-sync-interval` | duration | 10m | `toGroups` → `CiliumCIDRGroup` refresh |
| `enable-policy` *(agent key)* | string | `default` | validator input |
| `enable-l7-proxy` *(agent key)* | bool | true | validator input |
| `enable-node-selector-labels` *(agent key)* | bool | false | validator input |
| `enable-policy-secrets-sync` | bool | false | §3.14 |
| `policy-secrets-namespace` | string | `cilium-secrets` | §3.14 |
| `enable-lb-ipam` | bool | true | spec `05` §3.10 |
| `default-lb-service-ipam` | string | `lbipam` | `lbipam` \| `nodeipam` \| `none`; spec `05` §3.10 |
| `enable-node-ipam` | bool | false | node IPAM for `loadBalancerClass: io.cilium/node` |
| `kube-proxy-replacement` *(agent key, hidden)* | bool/string | false | Gateway API precondition (§3.15) |
| `loadbalancer-l7` | string | "" | `envoy` enables L7 LB for annotated Services |
| `loadbalancer-l7-algorithm` | string | `round_robin` | |
| `loadbalancer-l7-ports` | list | [] | auto-redirected ports |
| `proxy-idle-timeout-seconds` | int | 60 | Envoy upstream idle |
| `proxy-stream-idle-timeout-seconds` | int | 300 | Envoy stream idle |

### 6.8 Gateway API and Ingress (trigger surface only; see §3.15)

| Key | Type | Default |
|---|---|---|
| `enable-gateway-api` | bool | false |
| `enable-gateway-api-secrets-sync` | bool | true |
| `enable-gateway-api-proxy-protocol` | bool | false |
| `enable-gateway-api-app-protocol` | bool | false |
| `enable-gateway-api-alpn` | bool | false |
| `gateway-api-secrets-namespace` | string | `cilium-secrets` |
| `gateway-api-service-externaltrafficpolicy` | string | `Cluster` |
| `gateway-api-use-remote-address` | bool | true |
| `gateway-api-xff-num-trusted-hops` | u32 | 0 |
| `gateway-api-hostnetwork-enabled` | bool | false |
| `gateway-api-hostnetwork-nodelabelselector` | string | "" |
| `enable-ingress-controller` | bool | false |
| `enable-ingress-secrets-sync` | bool | true |
| `enable-ingress-proxy-protocol` | bool | false |
| `enforce-ingress-https` | bool | true |
| `ingress-default-lb-mode` | string | `dedicated` |
| `ingress-secrets-namespace` | string | `cilium-secrets` |
| `ingress-shared-lb-service-name` | string | `cilium-ingress` |
| `ingress-default-secret-name` / `-namespace` | string | "" |
| `ingress-default-request-timeout` | duration | 0 |
| `ingress-default-xff-num-trusted-hops` | u32 | 0 |
| `ingress-use-remote-address` | bool | true |
| `ingress-lb-annotation-prefixes` | list | `lbipam.cilium.io, service.beta.kubernetes.io, service.kubernetes.io, cloud.google.com` |
| `ingress-hostnetwork-enabled` | bool | false |
| `ingress-hostnetwork-nodelabelselector` | string | "" |
| `ingress-hostnetwork-shared-listener-port` | u32 | 0 |
| `ingress-hostnetwork-http-listener-port` | u32 | 0 |
| `ingress-hostnetwork-https-listener-port` | u32 | 0 |
| `ingress-hostnetwork-tls-passthrough-listener-port` | u32 | 0 |

### 6.9 API, metrics, debug

| Key | Type | Default | Effect |
|---|---|---|---|
| `operator-api-serve-addr` | string | `localhost:9234` | §3.16 |
| `enable-cilium-operator-server-access` | list | `*` | allowed API paths |
| `enable-metrics` | bool | false | Prometheus endpoint (Helm sets true) |
| `operator-prometheus-serve-addr` | string | `:9963` | metrics listener |
| `operator-prometheus-enable-tls` | bool | false | TLS on metrics |
| `operator-prometheus-tls-cert-file` / `-key-file` | path | "" | TLS material |
| `operator-prometheus-tls-client-ca-files` | list | [] | mTLS client CAs |
| `controller-group-metrics` | list | [] | controller groups to expose (`all`/`none`) |
| `metrics-sampling-interval` | duration | 5m | internal sampling |

### 6.10 IPAM (owned by spec `07-ipam.md` §6.2)

`ipam`, `parallel-alloc-workers`, `limit-ipam-api-qps`, `limit-ipam-api-burst`,
`cluster-pool-ipv4-cidr`, `cluster-pool-ipv6-cidr`,
`cluster-pool-ipv4-mask-size`, `cluster-pool-ipv6-mask-size`,
`auto-create-cilium-pod-ip-pools`, `ipam-default-ip-pool`,
`enable-cluster-pool-to-multi-pool-migration`, `multi-pool-migration-workers`,
`aws-*`, `eni-*`, `ec2-api-endpoint`, `subnet-ids-filter`,
`subnet-tags-filter`, `instance-tags-filter`, `excess-ip-release-delay`,
`azure-*`, `alibaba-cloud-*`, `enable-ipv4`, `enable-ipv6`.

### 6.11 Keys accepted and ignored

| Key | Reason |
|---|---|
| `enable-gops`, `gops-port` | gops dropped (§1); use `tokio-console`/`tracing`. Accepted so a Cilium ConfigMap loads |
| `shell-sock-path` | hive shell dropped (ADR-0004) |
| `operator-pprof`, `operator-pprof-address`, `operator-pprof-port`, `operator-pprof-block-profile-rate`, `operator-pprof-mutex-profile-fraction` | Go pprof; the Rust equivalent is not wire-compatible. Accepted, ignored, logged once |
| `mesh-auth-spiffe-trust-domain`, `mesh-auth-spire-agent-socket`, `mesh-auth-spire-server-address`, `mesh-auth-spire-server-connection-timeout` | mutual auth deprecated upstream and dropped (§1) |
| `double-write-metric-reporter-interval` | double-write mode dropped (§1) |
| `enable-ztunnel`, `ztunnel-ca-type` | ztunnel dropped (§1) |
| `register-dummy-external-group` *(hidden)* | test-only hook in the reference |

Unknown keys are an error, as in spec `00` §3.3.

## 7. Failure modes

| Failure | Behavior |
|---|---|
| **Apiserver unavailable at startup** | Leader election cannot proceed; the operator retries every `retry-period` indefinitely and logs "waiting for leader election". `/healthz` returns 500 (apiserver check fails), so kubelet's readiness probe fails; liveness has a 60 s initial delay and a 10 s period, so a long outage eventually restarts the pod, which is harmless. **Exception:** Gateway API CRD discovery has a 30 s deadline and exits the process (§3.15) |
| **Apiserver unavailable while leading** | Lease renewal fails; after `renew-deadline` (10 s) leadership is lost and the process exits (§3.2). No standby can take over either, so the cluster runs without an operator until the apiserver returns. Agents are unaffected — they do not depend on the operator at steady state |
| **Leader flap** (network partition, apiserver latency, node pressure) | Each flap is one pod restart plus a full leader-scope rebuild: re-register CRDs (all no-ops after the first time), re-list every informer, replay the CES mapping. Cost is O(cluster size) apiserver reads per flap, no writes if nothing changed. The flap is visible as `leaderTransitions` on the Lease and as the `leadership-lost` log line. Mitigation for latent control planes is `leader-election-resource-lock-timeout` and longer durations, not a graceful demote |
| **Two leaders** | Prevented by construction: a standby cannot acquire before `lease-duration` (15 s) after the incumbent's last successful renewal, and the incumbent exits at `renew-deadline` (10 s). The 5 s margin is the safety budget and §3.2 spends none of it |
| **CRD conflict — installed schema newer** | No write, one WARN naming both versions. The operator runs against a newer schema; because CRD evolution here is additive, this works. Fields the older binary does not know are preserved by the apiserver on updates it does not touch |
| **CRD conflict — `NamesAccepted=False`** | Fatal for that CRD; the operator fails startup. Another CRD owns the plural or a short name and no amount of retrying fixes it |
| **CRD update conflict (`409`)** | Not an error: re-`GET` and re-evaluate inside the 60 s poll. Two operators racing to update converge; whichever writes last writes the same content |
| **CRD never reaches `Established` in 60 s** | Startup fails; the process exits and restarts. Agents will fail their own 5-minute CRD wait if this persists (§3.5), so this is loud by design |
| **CES rate limit saturated** | Writes queue; `ces_queueing_delay_seconds` rises. Agents see stale endpoint sets for the duration — connectivity to new pods is delayed, existing connectivity is unaffected. Sustained saturation means the limit is set too low for the cluster's churn; the metric is the signal |
| **CES work item exhausts 15 retries** | The key is dropped with an ERROR and the slice stays stale until something else touches it. A subsequent event for any endpoint in that slice re-enqueues it; a leader restart repairs it via replay (§5.7). Accepted risk, inherited |
| **CES controller restarts mid-write** | The write either landed or did not; replay (§5.7) rebuilds the mapping from what is in the apiserver, so a partially written batch converges. Duplicate slices are only possible if replay is skipped |
| **Node taint patch rejected (`test` op failed)** | Another writer changed `spec.taints`; the item is requeued with backoff. Repeated failure means a fight with another controller — visible as rising requeues and, after 6, WARN logs |
| **Node deleted mid-patch** | `NotFound` forgets the key immediately; no retry |
| **Operator has no `nodes/status` permission** | The condition patch fails forever, logged at WARN from the 7th attempt. The taint is still removed (different RBAC rule), so pods still schedule. Deliberate: the two are separate rules so a half-configured RBAC degrades rather than deadlocks |
| **CEP GC deletes a CEP whose pod event was merely late** | Guarded by the age check (§3.6 step 1) and the UID precondition. The owning agent recreates the CEP on its next sync; the window costs one identity-lifesign miss |
| **Unmanaged-pod restart loop** | A pod that is genuinely un-networkable (e.g. no CNI at all) would be restarted every 5 min. The 5-minute per-pod cooldown and the one-per-cycle rule bound the damage to one delete per pod per 5 min |
| **kvstore unavailable** | `/healthz` returns 500 on every replica, so both pods eventually restart — which is correct, since kvstore-mode duties (service sync, node GC, identity GC) cannot make progress. The node GC MUST NOT interpret an empty kvstore listing as "everything is orphaned" |
| **kvstore node GC runs before the Node informer synced** | Would delete every node key. Prevented by the `informers-synced` fence (§3.13); a failed initial list means the GC does not run at all this term |
| **Secret sync target namespace missing** | Copy creation fails with `NotFound`; retried on the resync interval. The operator does not create the namespace (Helm owns it) |
| **Secret copy name collision with a hand-made object** | Refused with an error log (§3.14), never overwritten |
| **Upgrade from a Cilium operator** | The Lease is contended by both; whichever wins runs. CRD schema version comparison prevents a downgrade. Synced secrets are migrated by the legacy-name cleanup. CES objects are compatible because §4.3 is frozen. Rolling both at once is safe; running both indefinitely is not (they will fight over `identity-management-mode` if it differs) |
| **Downgrade to a Cilium operator** | Works if flowsdn has not written a newer CRD schema version. This is the reason for Open Decision 3 |

## 8. Observability

### 8.1 Metrics

Namespace `cilium_operator_`. Names and label names are frozen where dashboards
depend on them.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `cilium_operator_identity_gc_entries` | gauge | `status` (`alive`\|`deleted`), `identity_type` (`crd`\|`kvstore`) | identities counted at the end of a GC run. Note the label is `status`, not `outcome` — the other two identity-GC metrics use `outcome` |
| `cilium_operator_identity_gc_runs` | gauge | `outcome` (`success`\|`fail`), `identity_type` | GC runs |
| `cilium_operator_identity_gc_latency` | gauge | `outcome`, `identity_type` | duration of the last successful run |
| `cilium_operator_endpoint_gc_objects` | counter | `outcome` (`success`\|`fail`) | CEPs processed by the GC |
| `cilium_operator_unmanaged_pods` | gauge | – | unmanaged pods observed on the last cycle |
| `cilium_operator_number_of_ceps_per_ces` | histogram | – | buckets 1, 10, 25, 50, 100, 200, 500, 1000 |
| `cilium_operator_number_of_cep_changes_per_ces` | histogram | `opcode` (`cepinserted`\|`cepremoved`) | buckets 1, 5, 10, 25, 50, 100, 250, 500, 1000 |
| `cilium_operator_ces_sync_total` | counter | `outcome` (`success`\|`fail`), `failure_type` (`transient`\|`fatal`) | CES syncs |
| `cilium_operator_ces_queueing_delay_seconds` | histogram | `queue` (`fast`\|`standard`) | default buckets plus 60, 300, 900, 1800, 3600 |
| `cilium_operator_cid_controller_work_queue_event_count` | counter | `resource`, `outcome` | operator-managed identity controller (deferred) |
| `cilium_operator_cid_controller_work_queue_latency` | histogram | `resource`, `phase` (`enqueued`\|`processing`) | default buckets plus 60, 300, 900, 1800, 3600 |
| `cilium_operator_errors_warnings_total` | counter | `level`, `subsystem` | log-level counter fed by the logging layer |
| `cilium_operator_feature_adv_connect_and_lb_gateway_api_enabled` | gauge | – | feature gauges, populated only while leading |
| `cilium_operator_feature_adv_connect_and_lb_ingress_controller_enabled` | gauge | – | |
| `cilium_operator_feature_adv_connect_and_lb_lb_ipam_enabled` | gauge | – | |
| `cilium_operator_feature_adv_connect_and_lb_l7_aware_traffic_management_enabled` | gauge | – | |
| `cilium_operator_feature_adv_connect_and_lb_node_ipam_enabled` | gauge | – | |
| `cilium_operator_feature_controlplane_kubernetes_version` | gauge | `version` | emitted unless suppressed by `CILIUM_FEATURE_METRICS_WITHOUT_ENV_VERSION` |
| `cilium_operator_process_*`, `cilium_operator_go_*` | — | — | **DEVIATION**: Go runtime collectors have no Rust equivalent. flowsdn exports `process_*` (RSS, CPU, FDs, start time) and omits `go_*`. Dashboards keying on `go_goroutines` will show no data |
| `cilium_operator_workqueue_depth` | gauge | `name` | per queue |
| `cilium_operator_workqueue_adds_total` | counter | `name` | |
| `cilium_operator_workqueue_queue_duration_seconds` | histogram | `name` | |
| `cilium_operator_workqueue_work_duration_seconds` | histogram | `name` | |
| `cilium_operator_workqueue_unfinished_work_seconds` | gauge | `name` | |
| `cilium_operator_workqueue_longest_running_processor_seconds` | gauge | `name` | |
| `cilium_operator_workqueue_retries_total` | counter | `name` | |
| LB IPAM `cilium_operator_lbipam_*` | — | — | spec `05` §8 |
| IPAM `cilium_operator_ipam_*` | — | — | spec `07` §8.2 |
| BGP `cilium_operator_bgp_*` | — | — | BGP spec |

Dropped with their features: `cilium_operator_doublewrite_*`,
`cilium_operator_ztunnel_*`, hive/job metrics.

### 8.2 Logs

Structured. Fields that MUST be present where applicable so that operational
questions are answerable from logs alone:

| Event | Fields |
|---|---|
| leader acquired / lost | `holder_identity`, `leader_transitions`, `uptime_as_leader` (on loss) |
| CRD created / updated / established | `crd_name`, `installed_schema_version`, `target_schema_version` |
| CRD schema newer than binary | `crd_name`, both versions, level WARN |
| CEP GC delete | `namespace`, `name`, `endpoint_id`, `reason` (`no-pod` \| `pod-not-running` \| `feature-disabled`) |
| CES sync | `ces_name`, `namespace`, `queue`, `cep_count`, `delay` |
| CES key dropped after retries | `ces_name`, `retries`, level ERROR |
| node marked | `node_name`, `action` (`taint-removed` \| `taint-added` \| `condition-set`) |
| node patch failure | `node_name`, `error`, `requeues`; level debug < 6 requeues, warn ≥ 6 |
| unmanaged pod restarted | `namespace`, `name`, `time_since_pod_started` |
| secret synced / deleted | `source_namespace`, `source_name`, `target_namespace`, `target_name` |
| secret copy refused | `target_name`, `existing_owner`, `desired_owner`, level ERROR |
| kvstore node GC | `node_name`, `cluster` |

### 8.3 Health modules

Per spec `00` §3.4.3, identifiers `operator.<component>[.<sub>]`:

| Module | Degraded when |
|---|---|
| `operator.leader` | not leading (informational; does not fail `/healthz`) |
| `operator.crds` | a CRD failed to create/update/establish; message names it |
| `operator.gateway-api` | required CRDs absent, or discovery retrying |
| `operator.ces` | last sync failed, or the queue has items older than 5× the sync delay |
| `operator.endpoint-gc` | last run errored |
| `operator.identity-gc` | last run errored or exceeded its interval |
| `operator.node-taint` | any node key has exceeded 6 requeues |
| `operator.ciliumnode-gc` | last run errored |
| `operator.unmanaged-pods` | last delete failed |
| `operator.secretsync` | a copy is refused or repeatedly failing |
| `operator.kvstore` | kvstore status not `ok` |
| `operator.ipam` | spec `07` |
| `operator.lbipam` | spec `05` |

`flowsdn-operator status` renders this tree; it is also the body of a failing
`/healthz` where the failure is not the kvstore or apiserver check.

## 9. Test plan

Unit unless marked. There is no privileged/kernel test in this area — the
operator touches no BPF, no netlink, no kernel interface, so every case below
runs on a fake apiserver and a fake kvstore.

**Harvested corpus (ADR-0005).** The reference's operator tests include four
txtar script files that are pure data and MUST be harvested verbatim and run
under `flowsdn-scripttest`:

| File | Reference path | Covers |
|---|---|---|
| `servicesync.txtar` | `operator/watchers/testdata/` | §3.13 service → kvstore sync |
| `endpointslice-export-sync.txtar` | `operator/watchers/testdata/` | §3.13 EndpointSlice export |
| `globalnamespace-services.txtar` | `operator/watchers/testdata/` | global-namespace selection |
| `enabled.txtar`, `disabled.txtar` | `operator/pkg/kvstore/nodesgc/testdata/` | §3.13 kvstore node GC, both flag states |

These need the scripttest command registry to grow `k8s/add`, `k8s/delete`,
`kvstore/cmp` and `kvstore/list` verbs; no per-file work beyond that. The
remaining checklist is hand-written because the reference's coverage for it is
Go code, not data.

**Leader election**

- [ ] Acquire from no Lease; the created object has the expected duration, holder, `leaseTransitions=0`.
- [ ] Renew keeps `acquireTime` and increments nothing.
- [ ] Acquire from an expired foreign Lease increments `leaseTransitions`.
- [ ] Do not acquire from an unexpired foreign Lease.
- [ ] Loss (renew fails past `renew-deadline`) exits the process with status 1 and emits the `leadership-lost` line. (Harness: run the binary; assert exit code.)
- [ ] `leader-election-resource-lock-timeout=0` computes `max(1s, renew/2)`.
- [ ] Clean shutdown releases the Lease; a second instance acquires in ≪ `lease-duration`. **e2e**
- [ ] Two replicas, one node, `hostNetwork`: both bind 9234 (`SO_REUSEPORT`); only one leads. **e2e**

**CRD registration**

- [ ] Create path on an empty cluster produces every CRD of the conditional set for a default config, and no others.
- [ ] `AlreadyExists` on create returns success without update.
- [ ] Installed label older → update; equal → no write; newer → no write + WARN; missing → update; unparsable → update.
- [ ] Installed CRD with no schema → update.
- [ ] `preserveUnknownFields` is forced false on update.
- [ ] Conflict on update is retried inside the 60 s poll and converges.
- [ ] `NamesAccepted=False` aborts with the condition's reason.
- [ ] `Established` poll times out at 60 s and fails startup.
- [ ] Agent CRD wait: polls at 50 ms, logs missing names about once a second, and is fatal at `crd-wait-timeout`.
- [ ] `skip-crd-creation` writes nothing but still verifies presence and fails readiness when a CRD is absent.
- [ ] Feature gates: each of the 12 conditional gates flips exactly the expected CRD set.
- [ ] Generated CRD YAML diffs clean against the vendored reference YAML for all 22 CRDs (schema fidelity gate, §11).

**CiliumEndpoint GC**

- [ ] Owner-reference matrix: no owners; `Pod` owner present+running; `Pod` owner present+`Succeeded`; `Pod` owner present+`Failed`; `Pod` owner absent; non-`Pod` owner (never deleted); mixed `Pod`+non-`Pod` owners.
- [ ] Age guard: a CEP younger than the interval is kept even with no pod.
- [ ] Fallback name lookup when no `Pod` owner resolves.
- [ ] Delete carries `PropagationPolicy=Background` and the UID precondition.
- [ ] `NotFound`/`Conflict` on delete counts `fail` but does not abort the run.
- [ ] `interval=0` → one-shot, deletes every CEP regardless of pod state.
- [ ] `disable-endpoint-crd` → one-shot.
- [ ] One-shot with the CEP CRD absent → does not run.

**CiliumEndpointSlice**

- [ ] Bin packing: fills the fullest non-full slice; never selects an empty slice; creates a new slice when none has room; early-exits at `max-1`.
- [ ] Capacity respected at `ces-max-ciliumendpoints-per-ces` = 1, 2, 100.
- [ ] Namespace isolation: endpoints of different namespaces never share a slice.
- [ ] `CoreCiliumEndpoint` JSON keys match §4.3 byte for byte (golden fixture).
- [ ] CES name matches `^ces-[bcdfghjklmnpqrstvwxyz2456789]{9}-[...]{5}$`.
- [ ] Startup replay: with existing slices, no duplicates are created and no endpoint is listed twice.
- [ ] Startup replay: an endpoint present in a slice but with no source is removed.
- [ ] Priority namespace annotation routes to the `fast` queue; `fast` drains before `standard`.
- [ ] Removing the annotation moves subsequent work to `standard`.
- [ ] Rate limit selection over a multi-step table at node counts below the first step, exactly on a step, and between steps.
- [ ] Node add/delete re-evaluates the limiter; rate and burst change in place.
- [ ] `ces-rate-limits` with an unknown field is rejected at startup.
- [ ] Backoff: a failing sync retries at 1 s…100 s and is dropped after 15.
- [ ] Slim mode: pod+namespace labels → identity key matches the agent's derivation for a table of label sets (shared fixture with spec `03` §4.1).
- [ ] Slim mode: encryption key is the WireGuard constant / the node's IPsec key / 0 for the three configurations.
- [ ] Slim mode: a pod with no IPs, or no resolvable CID, is not placed.
- [ ] Slim mode: a node key change re-enqueues every slice holding endpoints on that node.
- [ ] Disable → one-shot `DeleteCollection` with `Orphan`, 3 attempts, 1–5 m backoff; CRD absent → no-op.
- [ ] **e2e**: enable CES on a live cluster, verify agents see the same endpoint set as with CEPs; disable it, verify CES objects are collected and connectivity survives (the reference's `tests-ces-migrate` scenario).

**CiliumNode**

- [ ] Orphan requires two passes separated by ≥ one interval.
- [ ] Candidacy is cleared when the k8s `Node` reappears.
- [ ] Object with any `ownerReferences` is never GC'd.
- [ ] `cilium.io/do-not-gc` = `true`, `TRUE`, `True` all skip; `false` does not.
- [ ] A candidate that vanishes between iteration and read drops its candidacy.
- [ ] `enable-ciliumnode-crd=false` deletes every object.
- [ ] `nodes-gc-interval=0` runs nothing.

**Node taint / condition**

- [ ] Taint removed when an agent pod is Ready; patch is `test`+`replace` and preserves other taints.
- [ ] Patch fails (`test` mismatch) when the observed taints are stale; the item is requeued.
- [ ] Condition set with the exact `Type`/`Status`/`Reason`/`Message`.
- [ ] Idempotency: with the marker condition present, no patch is issued (assert zero writes).
- [ ] Message differing but the triple matching → still no patch.
- [ ] Terminating agent pod (`deletionTimestamp` set) does not count as running even with `Ready=True`.
- [ ] Multiple agent pods on one node: any one Ready is enough.
- [ ] `set-cilium-node-taints=true` adds `{key, "", NoSchedule}` when scheduled-but-not-ready; does not add when already present.
- [ ] Both `remove-cilium-node-taints=false` and `set-cilium-is-up-condition=false` → controller does not start even with `set-cilium-node-taints=true`.
- [ ] Custom `agent-not-ready-taint-key` is honoured for both add and remove.
- [ ] Removal matches on key only, ignoring value and effect (`NoExecute` bootstrap taint is removed).
- [ ] `NotFound` forgets the key; other errors requeue; log level rises at 6.
- [ ] **e2e**: a node pre-tainted `node.cilium.io/agent-not-ready=true:NoExecute` schedules no workload until the agent is Ready, then does.

**Unmanaged pods**

- [ ] Running, non-hostNetwork, no CEP, selector match → counted and restarted.
- [ ] hostNetwork pod is never counted.
- [ ] Pod with a CEP is never counted.
- [ ] Pod younger than 30 s is counted but not restarted.
- [ ] Per-pod 5-minute cooldown honoured.
- [ ] At most one delete per cycle; a failed delete falls through to the next candidate.
- [ ] Gauge is published before any restart.
- [ ] History entries older than 10 min are pruned.
- [ ] `interval=0` and `disable-endpoint-crd` both disable it.
- [ ] Empty `pod-restart-selector` matches all pods.

**CNP validator**

- [ ] Valid policy → `Valid=True` with the success message.
- [ ] Invalid policy → `Valid=False` with the joined error text.
- [ ] Errors from `specs[]` entries are joined with those from `spec`.
- [ ] Unchanged status → zero writes.
- [ ] Same status, different message → entry replaced, `lastTransitionTime` preserved.
- [ ] Status change → `lastTransitionTime` updated.
- [ ] Written via the `status` subresource; `metadata.generation` unchanged.
- [ ] A rule with an `authentication` block is reported invalid with a message naming the field.
- [ ] `NotFound` on the status update (policy deleted concurrently) is swallowed.
- [ ] CCNP path exercised identically.

**Secret sync**

- [ ] Copy name equals the specified SHA-256 construction (golden vectors, including the `a-b`/`c` vs `a`/`b-c` collision pair).
- [ ] Legacy `<ns>-<name>` copy is deleted for the same source.
- [ ] ConfigMap copies use the `cfgmap` prefix and digest input.
- [ ] Ownership labels and source annotations present.
- [ ] Copy without ownership labels is not overwritten (error logged).
- [ ] Copy owned by a different source is not overwritten.
- [ ] Unreferenced copy is deleted.
- [ ] Resync interval is within ±20 % of 1 h across many draws.

**API and health**

- [ ] `/healthz` and `/v1/healthz` return identical bodies.
- [ ] 501 when k8s disabled; 500 with the kvstore message when kvstore is not `ok`; 500 with the error when the version query fails; 200 `ok` otherwise.
- [ ] A follower with a healthy apiserver returns 200.
- [ ] `enable-cilium-operator-server-access` restricted to `/healthz` returns 403 for `/v1/metrics/` with the exact disabled-API body.
- [ ] The `/healthz` alias still answers when the allowlist denies everything (kubelet probes must not be lockable-out).
- [ ] Histogram metrics expand into `quantile` 0.5/0.9/0.99 entries in `/v1/metrics/`.
- [ ] Empty serve address binds both `127.0.0.1:0` and `[::1]:0`; one failing is tolerated, both failing fails startup.
- [ ] `SO_REUSEPORT` set (assert via socket options).
- [ ] `/v1/metrics/` payload shape `{name, labels, value}`.

**kvstore duties**

- [ ] Node GC does not run when the `Node` informer's initial list failed.
- [ ] Node GC deletes only keys for the local cluster whose `Node` is absent.
- [ ] Service sync exports only shared services; unsharing removes the key.
- [ ] The five harvested txtar scenarios above pass unmodified except for mechanical renames.

**Configuration**

- [ ] Every key in §6 parses from a flag, an env var, and a `config-dir` file.
- [ ] Validation failures listed in §3.3 are each fatal with a message naming the key.
- [ ] A real Cilium v1.20.1 `cilium-config` ConfigMap loads with no unknown-key errors (fixture).
- [ ] Ignored keys (§6.11) load and emit exactly one notice each.

**Upgrade / interop (e2e)**

- [ ] Cilium v1.20.1 operator → flowsdn operator on a live cluster: CRDs unchanged, CES objects still parsed by Cilium agents, taints still removed, no agent restarts.
- [ ] flowsdn operator → Cilium operator (downgrade), given an unchanged schema version.
- [ ] Rolling restart of a 2-replica operator Deployment with no observable interruption to CES updates.

## 10. Kernel and platform requirements

None. The operator is a pure userspace Kubernetes controller. It runs anywhere
the apiserver is reachable, on x86-64 and arm64 alike, with no kernel version
floor, no BPF, no netlink, no privileged capabilities.

Two platform properties MUST be preserved:

- **`SO_REUSEADDR | SO_REUSEPORT`** on the API listener (Linux/BSD). Required
  because Helm runs the operator with `hostNetwork: true`.
- **`hostNetwork: true`** in the deployment. The operator must reach the
  apiserver on a node where CNI is not yet up — including the node it is
  scheduled on during a fresh install. Removing `hostNetwork` produces a
  chicken-and-egg deadlock on cluster bootstrap. Kept from the reference.

The container image is `scratch` with a single static binary (ADR-0001).
`hostUsers: true` is required alongside `hostNetwork` in the pod spec.

## 11. Rust design notes

**Crate: `flowsdn-operator`** (binary + library). Depends on `flowsdn-config`,
`flowsdn-health`, `flowsdn-fence` (spec `00`), `flowsdn-crds` (shared CRD
types with the agent), `flowsdn-ipam-*` (spec `07`), `flowsdn-lbipam`
(spec `05`), `flowsdn-kvstore` (ClusterMesh spec).

**Kubernetes access.** `kube` / `kube-runtime` / `k8s-openapi`, one
`kube::Client` for the whole process configured with the QPS/burst of §6.1
through a `tower` rate-limit layer (kube-rs has no built-in QPS/burst; a
`ServiceBuilder` with `RateLimitLayer` + `ConcurrencyLimitLayer` reproduces
client-go's behavior closely enough, and the difference is not observable
outside the process).

**One duty, one `Controller`.** Each duty is a `kube_runtime::Controller`
(watch + reflector store + reconcile closure returning `Action::requeue`) or,
for the periodic GCs, a plain `tokio` interval task over a reflector store.
This collapses the reference's *two* informer stacks (`pkg/k8s/resource` for
most cells, a `controller-runtime` Manager for Ingress/Gateway/secretsync/CEC)
into one, which is a real simplification: at this tag the reference maintains
two independent caches of `Service` and `EndpointSlice` in one process.

**Composition without Hive (ADR-0004).** Three functions:

```
fn infrastructure(cfg) -> Infrastructure      // client, metrics registry, health registry, kvstore client
fn control_plane(infra) -> ControlPlane       // API server, health handler, metrics handler
fn leader_scope(infra, cp, token) -> LeaderScope   // every leader duty, all owned by `token`
```

`LeaderScope` owns a `tokio_util::sync::CancellationToken` and a `JoinSet`.
Starting it is `leader_scope(...).await?` — errors abort leadership. Cancelling
it is `token.cancel()`. There is no lifecycle registry, no `cell.In`, no
`cell.Invoke`: dependencies are function arguments. Startup ordering is the
fence graph of §3.3, expressed with `flowsdn_fence::Fence`.

**Key types:**

| Type | Role |
|---|---|
| `LeaderElector` | ~250 lines over `kube` `coordination/v1`; the same primitive `flowsdn-l2announce` needs (spec `05` §11), so it lives in a small shared crate `flowsdn-lease` |
| `CrdRegistrar` | vendored YAML (`include_str!`) → `CustomResourceDefinition`, semver compare (`semver` crate), create/update/establish |
| `CesIndex` | namespace → slices, and slices bucketed by fill level (§5.1) |
| `RateGate` | `governor` limiter reconfigurable at runtime (§5.2) |
| `TwoPassGc<K>` | the §5.4 shape, shared by CiliumNode GC and identity GC |
| `SecretSyncer` | registration list + reconcile, generic over `Secret`/`ConfigMap` |
| `NodeMarker` | the §3.10 decision table and the two patch shapes |

**CRD strategy** (inventory 13 recommendation, adopted): vendor the 22 CRD YAML
files verbatim as the registration payload — that guarantees byte-identical
schemas, printer columns, CEL rules and `x-kubernetes-list-map-keys`, none of
which `kube-derive` fully expresses. Hand-write `#[derive(CustomResource)]`
Rust types for *deserialisation*, and add a CI test that generates a CRD from
each Rust type and diffs it against the vendored YAML over the subset
`kube-derive` can express, with a checked-in allowlist of known differences.

**JSON Patch.** `json-patch` for the `test`+`replace` node patch; the value of
the `test` op must serialise the observed taints exactly as the apiserver
returned them, so the patch is built from the raw JSON of the informer's object
rather than from a re-serialised typed struct (a typed round-trip drops
unknown fields and the `test` then fails permanently).

**Metrics.** `metrics` + `metrics-exporter-prometheus`, with an explicit
`cilium_operator_` prefix on every name. The `/v1/metrics/` JSON endpoint
reads the same registry and renders `{name, labels, value}`.

**HTTP.** `axum` on 9234 with the three routes of §3.16, on a listener built
with `socket2` so `SO_REUSEADDR|SO_REUSEPORT` can be set before `bind`.

**Field indexers.** kube-rs has no equivalent of controller-runtime's field
indexers (used heavily by Gateway API and by the agent-pod-by-node index).
Replace with reflector-derived `HashMap`s maintained in the store's event
stream; each index is a small struct with `insert`/`remove`/`get` and is unit
tested independently.

**No `HasCEWithIdentity` informer index needed at the apiserver:** the identity
GC's "alive" test (spec `03` §3.6) becomes a `HashMap<IdentityId, usize>`
maintained from the CEP (or CES) reflector.

**Sizing estimate** (excluding Gateway API/Ingress/translation, which is its
own spec and its own 12–18k lines):

| Component | Lines |
|---|---|
| main, config wiring, fences | 600 |
| leader election (`flowsdn-lease`) | 300 |
| CRD registrar + vendored YAML plumbing | 400 |
| CEP GC | 300 |
| CES controller (default + slim) | 2 200 |
| CES GC | 100 |
| CiliumNode GC + node taint/condition | 700 |
| unmanaged pods | 250 |
| CNP validator | 250 |
| secret sync | 700 |
| kvstore duties (operator half) | 900 |
| API + metrics + health | 600 |
| **total** | **≈ 7 300** + ~5 000 test |

Matching inventory 08's "M (≈ 6–8k Rust lines)" for the core.

**Risks carried from inventory 08, restated as design constraints:**

1. Wire compatibility during a mixed rollout — pinned by §2 and the golden
   fixtures in §9.
2. The operator reads ~15 agent keys from the shared ConfigMap; the config
   registry must accept the agent's key names in the operator binary (§6).
3. `hostNetwork` + `SO_REUSEPORT` must survive packaging (§10).

## 12. Open decisions

1. **Graceful demotion on lost leadership.** §3.2 keeps the reference's
   fatal exit. The alternative is to cancel the leader scope, await all tasks
   with a deadline strictly less than `lease-duration − renew-deadline` (5 s),
   and continue as a follower — saving a pod restart per flap and keeping the
   API server's connection warm. **Recommendation: keep the exit.** Revisit
   only if leader flaps become a measured operational problem, and only with a
   per-duty audit proving every write path is cancel-safe within the budget.

2. **Slim mode first, or default mode first?** Inventory 08 open question 1
   asks whether flowsdn agents write CEPs at all. Going slim-first
   (`ces-controller-mode=slim` + `disable-endpoint-crd` +
   `identity-management-mode=operator`) removes CEP GC entirely, halves
   identity-GC complexity, and removes one apiserver object per pod — a large
   simplification and the direction upstream is heading. It also makes a mixed
   Cilium/flowsdn cluster impossible, because Cilium agents watch CEPs.
   **Recommendation: default mode first, slim mode as a supported second
   mode behind the same hidden key.** Ship slim-first only if the migration
   story is abandoned. Note that slim mode's correctness depends on §5.6
   matching the agent exactly, which is a shared-fixture obligation on spec
   `03`.

3. **CRD schema-version line.** Continue `io.cilium.k8s.crd.schema.version` on
   `1.33.x` (upgrade-in-place from Cilium works; but flowsdn is then obliged to
   keep its CRDs a superset of whatever Cilium ships at that version, forever),
   or fork the label (clean semantics, no in-place upgrade path).
   **Recommendation: continue the line**, and pin the exact value in a
   compile-time constant with a CI check that the vendored YAML hash and the
   constant move together. Revisit at 1.0.

4. **Taint key.** Keep `node.cilium.io/agent-not-ready` (recommended:
   bootstrap tooling already writes it) or move to `node.flowsdn.io/...` with
   the old key accepted as an alias for removal. A dual-key removal (remove
   both keys, add only the new one) is a cheap middle path and costs one extra
   entry in the removal filter. **Recommendation: keep the reference key; add
   dual-key *removal* when the flowsdn key is introduced.**

5. **Gateway API controller name.** `io.cilium/gateway-controller` is what
   users' `GatewayClass` manifests name. Changing it to `io.flowsdn/...`
   breaks every existing manifest. **Recommendation: keep it**, and make it
   configurable so a cluster running both implementations can disambiguate.
   Defer the key until that need is real.

6. **Operator REST API surface.** `/healthz` is load-bearing (kubelet probes).
   `/v1/metrics/` and `/v1/cluster` exist only for `cilium-operator status`.
   Options: (a) keep all three; (b) keep `/healthz` and serve the other two
   only when a key enables them; (c) keep `/healthz` only and give
   `flowsdn-operator status` a Prometheus scrape instead.
   **Recommendation: (a)** — the cost is ~150 lines and `/v1/cluster` is the
   only way to see remote-cluster state without a shell in the pod.

7. **`identity-management-mode` default.** The reference defaults to `agent`
   (agents allocate their own `CiliumIdentity`); Helm does not change it.
   `operator` moves allocation into the operator, which is a precondition for
   slim CES mode and removes the agents' `create` on `ciliumidentities`
   (a meaningful RBAC reduction: an agent can then no longer mint identities).
   It also makes identity allocation a single-leader bottleneck and adds a
   failure mode where a new pod waits on the operator.
   **Recommendation: default `agent`**, matching the reference, with
   `operator` implemented alongside slim CES mode and promoted to the default
   only after it has run at scale. Spec `03` §6 currently accepts only
   `agent`; that restriction lifts when this lands.

8. **CES dynamic rate limit for small clusters.** Inventory 08 open question 7
   notes that the target clusters here are small and a single
   `{nodes:0,limit:10,burst:20}` step may suffice, making the whole stepped
   table dead configuration. Dropping it saves ~150 lines but breaks a
   `cilium-config` that sets a multi-step table.
   **Recommendation: keep the table** (it is cheap and it is config
   compatibility), but do not build a UI or Helm surface for it.

9. **Prometheus `go_*` metrics.** Dashboards ported from Cilium will have
   empty panels for `go_goroutines`, `go_memstats_*`. Options: omit (current
   §8.1), or emit deliberately-fake equivalents mapping to Rust concepts
   (`go_goroutines` ← live tokio tasks). **Recommendation: omit**, and ship a
   dashboard delta document with the Helm spec. Faking a runtime's metrics
   under another runtime's names is a trap for whoever debugs it next.

10. **`--skip-crd-creation` verification strictness.** §3.4 says the operator
    must verify presence and fail *readiness* when a CRD is missing. The
    alternative is to fail *startup*. Failing readiness keeps the pod alive so
    `/healthz` can explain the problem; failing startup makes it a
    `CrashLoopBackOff` whose reason is only in logs.
    **Recommendation: fail readiness**, as specified.
