# CRDs and Kubernetes integration — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/k8s/**` (client, resource, watchers, slim, synced, tables, apis), `pkg/k8s/apis/cilium.io/client/crds/{v2,v2alpha1}/*.yaml`, `pkg/annotation`, `pkg/labelsfilter`, `pkg/k8s/identitybackend`, `operator/k8s`, `operator/watchers`, `install/kubernetes/cilium/templates/{cilium-agent,cilium-operator}/clusterrole.yaml`, `Documentation/network/kubernetes/compatibility*.rst`, `Documentation/contributing/development/introducing_new_crds.rst`.

## Purpose

This area is the entire boundary between Cilium and the Kubernetes API server: the REST client (endpoint rotation, QPS/burst, heartbeat, protobuf-vs-JSON), the informer/reflector layer (`resource.Resource[T]` and the StateDB reflector), the "slim" copies of core k8s types that strip everything Cilium does not read, the registration and readiness gating of the 22 `cilium.io` CRDs, the synthesis of identity labels from Pod/Namespace/ServiceAccount metadata, and the annotations/labels/taints Cilium reads from or writes to Pods, Services, Nodes and Namespaces. The CRD YAML under `client/crds/` is the compatibility contract: every `kubectl apply` a user has ever done against a Cilium cluster validated against these schemas, and flowsdn must accept the same documents byte-for-byte.

## Components

| Path | Lines | Purpose |
|---|---|---|
| `pkg/k8s/*.go` (non-test) | 3,234 | Top-level helpers: `resource_ctors.go` (402, agent Resource[T] constructors + list-option modifiers), `statedb.go` (698, k8s→StateDB reflector), `endpoints.go` (389, EndpointSlice→Endpoints/backends), `node.go` (372, k8s Node→`nodeTypes.Node`), `network_policy.go`/`cluster_network_policy.go` (342/404, `networking.k8s.io/v1` NetworkPolicy and `policy.networking.k8s.io/v1alpha2` ClusterNetworkPolicy → Cilium `api.Rule`), `labels.go` (111, pod identity labels), `factory_functions.go` (266, object conversion/equality), `error_helpers.go` (102) |
| `pkg/k8s/apis/` | 16,314 | Go types for `cilium.io/v2` and `v2alpha1` (deepcopy/deepequal generated), CRD registration (`client/register.go`, `crdhelpers/`), embedded CRD YAML (22 files, 20,112 YAML lines), `apis/cell.go` (`RegisterCRDsCell`, `--skip-crd-creation`) |
| `pkg/k8s/client/` | 11,634 | Composite clientset (k8s, slim, apiext, cilium, mcs-api, network-policy-api), generated typed clients/informers/listers for cilium.io, `rest_config_provider.go` (URL rotation), `cell.go` (heartbeat, content types), `testutils/object_tracker.go` (fake API server used by script tests) |
| `pkg/k8s/slim/` | 27,384 | Slim `core/v1`, `discovery/v1`, `networking/v1`, `meta/v1` types with protobuf codegen (`generated.pb.go`) and a slim clientset. The exact field subset flowsdn must deserialise (see Data model) |
| `pkg/k8s/resource/` | 1,575 | `Resource[T]`: informer + store + event stream with rate-limited retries, indexers, lazy transforms, CRD-sync gating, `FilteredResource` |
| `pkg/k8s/watchers/` | 2,369 | Legacy agent watchers still wired by group name: Pods (`core/v1::Pods`), CiliumNode, CiliumEndpoint/CiliumEndpointSlice; `watcher.go` maps every CRD to skip/start/waitOnly; `K8sEventReporter` metrics |
| `pkg/k8s/synced/` | 829 | Cache-sync bookkeeping (`Resources`), `--k8s-sync-timeout`, `--crd-wait-timeout`, CRD presence watcher via `PartialObjectMetadata`, `AgentCRDResourceNames()` |
| `pkg/k8s/tables/` | 308 | StateDB tables `k8s-pods` (local node only, `spec.nodeName=<node>`) and `k8s-namespaces` |
| `pkg/k8s/identitybackend/` | 428 | CRD-mode identity allocator backend over `CiliumIdentity` (name = numeric ID, `io.cilium.heartbeat` annotation) |
| `pkg/k8s/utils/` | 460 | List-option modifiers (`service-proxy-name`, headless filter, EndpointSlice mirroring filter), `SanitizePodLabels`, `GetWorkloadMetaFromPod` |
| `pkg/k8s/informer/` | 174 | Thin wrapper around `cache.NewInformer` with a transform hook (used by operator + CRD sync) |
| `pkg/k8s/types/` | 292 | Internal slim `CiliumEndpoint` (`Identity`, `Networking`, `Encryption`, `NamedPorts`, `ServiceAccount`) produced by `TransformToCiliumEndpoint` |
| `pkg/k8s/version/` | 126 | `ServerVersion()` discovery, `MinimalVersionConstraint = "1.21.0"` |
| `pkg/k8s/hostfirewallbypass/` | 90 | Dialer `SO_MARK` = MagicMarkEgress+host identity so API-server traffic bypasses host firewall/DNS proxy (hidden flag) |
| `pkg/k8s/portforward/`, `metrics/`, `constants/`, `testutils/` | 201 / 38 / 10 / 333 | Port-forward helper (cilium-dbg), metric names, test list-watchers |
| `pkg/annotation/` | 373 (non-test) | Every annotation key Cilium honours (`k8s.go`, `clustermesh.go`) |
| `pkg/labelsfilter/filter.go` | ~300 | Default label-prefix allow/deny list for identity relevance |
| `operator/k8s/` | ~300 | Operator `Resource[T]` constructors (Pods all nodes with `PodNodeNameIndex`, CEP, CES, CiliumNode, LBIPPool, EndpointSlice, BGP ClusterConfig/NodeConfigOverride) |
| `operator/watchers/` | ~1,500 | Node taint/`NetworkUnavailable` manager, unmanaged kube-dns pod restarter, CiliumNode GC, ClusterMesh service/EndpointSlice sync |
| `install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml` | 167 | Agent RBAC |
| `install/kubernetes/cilium/templates/cilium-operator/clusterrole.yaml` | 484 | Operator RBAC |
| `Documentation/network/kubernetes/compatibility.rst` + `compatibility-table.rst` | 60 + table | Supported k8s versions and CRD schema-version table |
| `Documentation/contributing/development/introducing_new_crds.rst` | 383 | How CRDs are generated (controller-gen marks, `make manifests`, `CRDS_CILIUM_V2*`) |

Total non-test Go under `pkg/k8s/`: **65,799** lines (of which ~40k are generated: protobuf, deepcopy, typed clients). CRD manifests: **20,112** YAML lines (CNP and CCNP are 6,552 and 6,554 of those).

## Features

- **API-server client** — `--k8s-api-server-urls` (list; round-robin rotation via `rotatingHttpRoundTripper` on heartbeat failure; the old singular `k8s-api-server` flag is gone), `--k8s-kubeconfig-path`, `--enable-k8s` (default true; auto-detected from kubeconfig or `KUBERNETES_SERVICE_HOST/PORT` or `K8S_NODE_NAME`), `--k8s-client-qps` (10.0) / `--k8s-client-burst` (20) (operator: `--operator-k8s-client-qps/burst`), `--k8s-client-connection-timeout` / `--k8s-client-connection-keep-alive` (30s each; 0 disables connection rotation), `--k8s-heartbeat-timeout` (30s; `GET /readyz` on the core REST client via the `k8s-heartbeat` controller; on timeout closes all idle conns and rotates URL), `--enable-k8s-api-discovery` (default false; unused beyond plumbing in 1.20 — `version.Update` only calls `ServerVersion()`), `user-agent` option. Helm: `k8sServiceHost/Port`, `k8sServiceHostRef`, `k8sServiceLookupConfigMapName/Namespace`, `k8sClientRateLimit.{qps,burst,operator.*}`, `k8sClientExponentialBackoff.{enabled,backoffBaseSeconds=1,backoffMaxDurationSeconds=120}`.
- **Content negotiation** — the k8s core/slim/apiext/mcs-api/policy clientsets use `application/vnd.kubernetes.protobuf`; the cilium.io clientset uses `application/json` (CRDs have no protobuf). CRD-presence watch requests `as=PartialObjectMetadata(List);v=v1;g=meta.k8s.io` with JSON fallback.
- **Agent watch set** (`pkg/k8s/resource_ctors.go`, `pkg/k8s/tables`, `pkg/loadbalancer/reflectors/k8s.go`) — see External interfaces table. Pods are watched **only for the local node** (`fieldSelector spec.nodeName=<nodeName>`). Services and EndpointSlices use a label selector honouring `--k8s-service-proxy-name` (`service.kubernetes.io/service-proxy-name` DoesNotExist when empty, `==value` otherwise), optionally excluding headless (`service.kubernetes.io/headless` DoesNotExist) when `EnableHeadlessServiceWatch=false`, and EndpointSlices additionally `endpointslice.kubernetes.io/managed-by != endpointslice-mesh-controller.cilium.io`.
- **Operator watch set** (`operator/k8s/resources.go`) — Pods on all nodes (indexed by namespace and `spec.nodeName`), Namespaces, Nodes (slim, for taints), EndpointSlices, Services (ClusterMesh sync), CiliumEndpoint/CiliumEndpointSlice, CiliumNode, CiliumIdentity, CNP/CCNP, CiliumCIDRGroup, CiliumPodIPPool, CiliumLoadBalancerIPPool, all five BGP CRDs, Secrets (BGP auth), `multicluster.x-k8s.io` ServiceExport/ServiceImport; plus controller-runtime managers for Gateway API/Ingress (Gateway, GatewayClass, HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, UDPRoute, ReferenceGrant, BackendTLSPolicy, ListenerSet, Ingress, IngressClass, CiliumGatewayClassConfig, CiliumEnvoyConfig, Service, EndpointSlice, Secret, ConfigMap, Node, Namespace, ServiceImport) and secretsync (Secret, ConfigMap).
- **CRD registration** — done by the **operator** only (`operator/cmd/root.go` includes `apis.RegisterCRDsCell`; `--skip-crd-creation=false` default). `crdhelpers.CreateUpdateCRD` creates or updates each CRD, updating only when the existing CRD's label `io.cilium.k8s.crd.schema.version` is older than `CustomResourceDefinitionSchemaVersion = "1.33.11"` (semver, `pkg/k8s/apis/cilium.io/register.go`), then polls until `Established`. The agent never creates CRDs; it waits for them.
- **CRD readiness gating** — the agent lists/watches `customresourcedefinitions.apiextensions.k8s.io` as `PartialObjectMetadata` and blocks (`--crd-wait-timeout`, 5m, fatal on expiry) until every name in `AgentCRDResourceNames()` exists. Required set: always `ciliumidentities`, `ciliumpodippools`, `ciliumloadbalancerippools`, `ciliuml2announcementpolicies`; conditionally `ciliumendpoints` (unless `--disable-endpoint-crd`), `ciliumendpointslices` (`--enable-cilium-endpoint-slice`), `ciliumnodes` (`--enable-ciliumnode-crd`, hidden, default true), `ciliumnetworkpolicies` (`--enable-cilium-network-policy`, true), `ciliumclusterwidenetworkpolicies` (`--enable-cilium-clusterwide-network-policy`, true), `ciliumcidrgroups` (if either policy CRD), `ciliumegressgatewaypolicies` (`--enable-egress-gateway`), `ciliumlocalredirectpolicies` (`--enable-local-redirect-policy`), `ciliumenvoyconfigs`+`ciliumclusterwideenvoyconfigs` (`--enable-envoy-config`), the five BGP CRDs (`--enable-bgp-control-plane`), `ciliumdatapathplugins` (`--enable-datapath-plugins`). `ciliumnodeconfigs` and `ciliumgatewayclassconfigs` are operator-only. Every `Resource[T]` for a CRD is created `WithCRDSync(promise)` so no list starts before the CRD exists.
- **Cache sync gating** — `--k8s-sync-timeout` (3m, hidden): after the last event on any watched group, all pre-existing objects must be received or the agent exits (`InitK8sSubsystem`).
- **Config sources** — `--config-sources` list of `{kind: config-map|cilium-node-config|node, namespace, name}` merged in order by `pkg/option/resolver`; `CiliumNodeConfig` objects are selected by `spec.nodeSelector` against the Node's labels (or by name), `node` kind reads `config.cilium.io/<key>` labels/annotations from the Node; `--allow-config-keys`/`--deny-config-keys` gate overrides.
- **Identity labels** — `SanitizePodLabels`: drop pod labels prefixed `io.cilium.k8s` (and `CiliumOwnedLabelPrefixes`), add `io.cilium.k8s.namespace.labels.<nslabel>=<v>` for every Namespace label, `io.kubernetes.pod.namespace=<ns>`, `io.cilium.k8s.policy.serviceaccount=<sa>` (if set), `io.cilium.k8s.policy.cluster=<cluster-name>`. Then `labelsfilter` keeps only: `reserved:.*`, `io.kubernetes.pod.namespace`, `io.cilium.k8s.namespace.labels`, `app.kubernetes.io`, `io.cilium.k8s.policy.cluster`, `io.cilium.k8s.policy.serviceaccount`; drops `io.kubernetes*`, `kubernetes.io*`, `statefulset.kubernetes.io/pod-name`, `apps.kubernetes.io/pod-index`, `batch.kubernetes.io/job-completion-index`, `batch.kubernetes.io/controller-uid`, `*beta.kubernetes.io`, `k8s.io`, `pod-template-generation`, `pod-template-hash`, `controller-revision-hash`, `controller-uid`, `annotation.*`, `etcd_node`, `topology.kubernetes.io`; overridable with `--labels` / `--label-prefix-file` (JSON `{version, valid-prefixes:[{prefix,source,invert}]}`) and `--node-labels` (+`--enable-node-selector-labels`) for node identities. `io.cilium.k8s.named-ports` is added to identity labels when the pod has named ports.
- **Policy labels** — every imported rule carries `k8s:io.cilium.k8s.policy.derived-from=<CiliumNetworkPolicy|CiliumClusterwideNetworkPolicy|NetworkPolicy|ClusterNetworkPolicy>`, `k8s:io.cilium.k8s.policy.name`, `k8s:io.cilium.k8s.policy.uid`, and (namespaced) `k8s:io.cilium.k8s.policy.namespace` (`pkg/k8s/apis/cilium.io/utils/utils.go GetPolicyLabels`).
- **Workload attribution** — `GetWorkloadMetaFromPod` walks `ownerReferences` (controller=true) and maps ReplicaSet+`pod-template-hash` → Deployment, ReplicationController+`deploymentconfig` label → DeploymentConfig, Job named by CronJob → CronJob; used for Hubble/CEP metadata.
- **Node metadata** — agent reads from the k8s Node: `status.addresses` (InternalIP/ExternalIP), `spec.podCIDR(s)` (≤2), labels (filtered by `--exclude-node-label-patterns`), all `*.cilium.io/*` annotations, and the annotation pairs (new key / legacy alias): `network.cilium.io/ipv4-pod-cidr` / `io.cilium.network.ipv4-pod-cidr`, `…/ipv6-pod-cidr`, `…/ipv4-cilium-host` / `io.cilium.network.ipv4-cilium-host`, `…/ipv6-cilium-host`, `…/ipv4-health-ip`, `…/ipv6-health-ip`, `…/ipv4-Ingress-ip`, `…/ipv6-Ingress-ip`, `…/encryption-key`, `…/wg-pub-key`. With Helm `annotateK8sNode` the agent writes them back with a **strategic-merge PATCH to `nodes/<name>/status`** (`pkg/nodediscovery/k8s_node_annotate.go`). `--k8s-require-ipv4-pod-cidr` / `--k8s-require-ipv6-pod-cidr` make a missing PodCIDR fatal.
- **Node taint / readiness** (operator) — `--remove-cilium-node-taints` (true), `--set-cilium-node-taints`, `--set-cilium-is-up-condition` (true), `--agent-not-ready-taint-key` (`node.cilium.io/agent-not-ready`): operator watches cilium pods (namespace + label selector) and Nodes, removes the taint with a **JSON PATCH** on `nodes/<name>` and sets condition `NetworkUnavailable=False reason=CiliumIsUp` with a **strategic-merge PATCH to `nodes/<name>/status`**.
- **CiliumEndpoint lifecycle** — agent creates the CEP (`ownerReferences` → the Pod, kind/UID from the endpoint owner), then keeps `status` current with **JSON PATCH `replace /status`** (no status subresource on CEP), deletes on endpoint removal (`pkg/endpointmanager/endpointsynchronizer.go`). `--disable-endpoint-crd` turns it off. Operator GCs orphaned CEPs (`--cilium-endpoint-gc-interval`) and, with `--enable-cilium-endpoint-slice`, batches CEPs into CiliumEndpointSlices (`--ces-max-ciliumendpoints-per-ces`, `--ces-rate-limits`, `--ces-controller-mode default|slim`).
- **CiliumNode lifecycle** — agent Create/Update of its own CiliumNode (`pkg/nodediscovery`), `UpdateStatus` from IPAM (`pkg/ipam/crd.go`); operator creates CiliumNodes from k8s Nodes in ENI/Azure/AlibabaCloud/cluster-pool modes (`operator/pkg/ipam/nodewatcher.go`), updates `status` subresource, GCs stale ones (`--nodes-gc-interval`).
- **CiliumIdentity (CRD identity mode)** — `--identity-allocation-mode=crd` (agent), `--identity-management-mode=agent|operator|both` (operator). `AllocateID` = Create `CiliumIdentity{name: <decimal id>, labels: {io.kubernetes.pod.namespace: ns}, security-labels: <full label map>}`; lookup is by the informer index on the label-set key; operator GC (`--identity-gc-interval`, `--identity-heartbeat-timeout`) stamps `io.cilium.heartbeat=<RFC3339Nano>` on unused identities and deletes them after the timeout; the agent removes the annotation via Update when it re-acquires the identity.
- **CNP/CCNP status** — the operator (`--validate-network-policy`) validates every CNP/CCNP and writes `status.conditions[type=Valid]` through `UpdateStatus` (status subresource). The agent no longer writes per-node CNP status (`status.derivativePolicies` remains in the schema for derived policies from `toGroups`).
- **Leader election (operator)** — `coordination.k8s.io` Lease `cilium-operator-resource-lock` in the operator namespace, `--leader-election-lease-duration` 15s, `--leader-election-renew-deadline` 10s, `--leader-election-retry-period` 2s, `--leader-election-resource-lock-timeout` (default max(1s, renew/2)); on lost leadership the process exits. Agent L2 announcements also use Leases named `cilium-l2announce-<ns>-<svc>` in the Cilium namespace (`--l2-announcements-lease-duration/renew-deadline/retry-period`).
- **Policy Secrets** — with `--enable-policy-secrets-sync` the operator copies Secrets referenced by CNP/CCNP `terminatingTLS/originatingTLS/headerMatches[].secret` into `--policy-secrets-namespace` (labels `secretsync.cilium.io/*`) and the agent reads them from there via direct `GET` (`--policy-secrets-only-from-secrets-namespace`); otherwise the agent needs `get/list/watch secrets` cluster-wide.
- **k8s ClusterNetworkPolicy** — `--enable-k8s-cluster-network-policy` (hidden, false) watches `policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy` (sigs.k8s.io/network-policy-api v0.2.0). `--enable-k8s-networkpolicy` (hidden, true) for `networking.k8s.io/v1`.
- **Removed vs earlier releases (relevant to compatibility claims)** — no `k8s-api-server` singular flag, no `enable-k8s-endpoint-slice` (EndpointSlices are the only backend source; `core/v1 Endpoints` is not watched), no `k8s-watcher-endpoint-selector`, no `k8s-event-handover`, no `disable-cnp-status-updates`/`cnp-node-status-gc-interval`, no `io.cilium.proxy-visibility` / `policy.cilium.io/proxy-visibility` annotation, no `CiliumExternalWorkload`, no `CiliumBGPPeeringPolicy`, no `CiliumClusterwideEnvoyConfig`-only listener refs. Kafka and generic L7 (`l7proto`) rules are **absent from the CNP schema** — `toPorts[].rules` is `oneOf {http} | {dns}` only.

## Data model

### CRD catalogue (contract)

All CRDs: group `cilium.io`, `apiextensions.k8s.io/v1`, generated with controller-gen v0.20.1, label `io.cilium.k8s.crd.schema.version: 1.33.11` set at registration, no `conversion` stanza (all multi-version CRDs use strategy `None`, identical schemas). Storage version is bold.

| Kind | Plural | Short names | Categories | Scope | Versions served (storage bold) | Subresources | Written by |
|---|---|---|---|---|---|---|---|
| CiliumNetworkPolicy | ciliumnetworkpolicies | cnp, ciliumnp | cilium, ciliumpolicy | Namespaced | **v2** | status | user; operator status |
| CiliumClusterwideNetworkPolicy | ciliumclusterwidenetworkpolicies | ccnp | cilium, ciliumpolicy | Cluster | **v2** | status | user; operator status |
| CiliumCIDRGroup | ciliumcidrgroups | ccg | cilium | Cluster | **v2**, v2alpha1 (deprecated) | – | user; operator (`toGroups` external groups, FieldManager `cilium.io/external-group-controller`) |
| CiliumEndpoint | ciliumendpoints | cep, ciliumep | cilium | Namespaced | **v2** | – | agent (create/JSON-patch/delete) |
| CiliumEndpointSlice | ciliumendpointslices | ces | cilium | Cluster | **v2alpha1** | – | operator |
| CiliumIdentity | ciliumidentities | ciliumid | cilium | Cluster | **v2** | status (unused) | agent or operator |
| CiliumNode | ciliumnodes | cn, ciliumn | cilium | Cluster | **v2** | status | agent + operator |
| CiliumNodeConfig | ciliumnodeconfigs | – | cilium | Namespaced | **v2** | – | user |
| CiliumLocalRedirectPolicy | ciliumlocalredirectpolicies | clrp | cilium, ciliumpolicy | Namespaced | **v2** | – | user |
| CiliumEgressGatewayPolicy | ciliumegressgatewaypolicies | cegp | cilium, ciliumpolicy | Cluster | **v2** | – | user |
| CiliumEnvoyConfig | ciliumenvoyconfigs | cec | cilium | Namespaced | **v2** | – | user; operator (Gateway/Ingress) |
| CiliumClusterwideEnvoyConfig | ciliumclusterwideenvoyconfigs | ccec | cilium | Cluster | **v2** | – | user; operator |
| CiliumLoadBalancerIPPool | ciliumloadbalancerippools | ippools, ippool, lbippool, lbippools | cilium | Cluster | **v2**, v2alpha1 (deprecated) | status | user; operator status (JSON patch, FieldManager `cilium-operator-lb-ipam`) |
| CiliumL2AnnouncementPolicy | ciliuml2announcementpolicies | l2announcement | cilium | Cluster | **v2alpha1** | status | user; agent status (JSON patch, FieldManager `cilium-agent-l2-announcer`) |
| CiliumPodIPPool | ciliumpodippools | cpip | cilium | Cluster | **v2alpha1** | – | user; operator (auto-create default) |
| CiliumBGPClusterConfig | ciliumbgpclusterconfigs | cbgpcluster | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | status | user; operator status |
| CiliumBGPPeerConfig | ciliumbgppeerconfigs | cbgppeer | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | status | user; operator status |
| CiliumBGPAdvertisement | ciliumbgpadvertisements | cbgpadvert | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | – | user |
| CiliumBGPNodeConfig | ciliumbgpnodeconfigs | cbgpnode | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | status | operator spec; agent status (JSON patch) |
| CiliumBGPNodeConfigOverride | ciliumbgpnodeconfigoverrides | cbgpnodeoverride | cilium, ciliumbgp | Cluster | **v2**, v2alpha1 (deprecated) | – | user |
| CiliumGatewayClassConfig | ciliumgatewayclassconfigs | cgcc | cilium | Namespaced | **v2alpha1** | status | user; operator status |
| CiliumDatapathPlugin | ciliumdatapathplugins | cddp | cilium | Cluster | **v2alpha1** (flagged deprecated in YAML) | – | user |

Version/deprecation policy (from `introducing_new_crds.rst`, `register.go`, and the YAML): new CRDs start in `v2alpha1`; graduation adds a `v2` served+storage version with a byte-identical schema and marks `v2alpha1` `deprecated: true, storage: false` (no `deprecationWarning` text, no conversion webhook); the Go `v2alpha1` package keeps type aliases so old clients still compile. Removal of a served version has not yet happened for any of the seven graduated CRDs. The agent's `ciliumResourceToGroupMapping` still keys BGP CRDs by their `v2alpha1` names (the names are version-independent). The schema-version label is bumped on every CRD change (`1.33.11` for v1.20.1; `latest/main` is `1.34.3`).

CRD annotations/labels used by Cilium on the CRD objects themselves: label `io.cilium.k8s.crd.schema.version` (only key the updater compares); annotation `controller-gen.kubebuilder.io/version=v0.20.1` (informational).

### Per-CRD schema tables

Legend: Type `[]T` array, `map[string]T` additionalProperties, `int|string` = `x-kubernetes-int-or-string`; Req = in parent `required`; Constraints = default/enum/format/pattern/min-max/list-type/CEL (`x-kubernetes-validations`) / `oneOf`+`anyOf` alternatives; rows ending `.*` reuse an earlier identical subtree. `apiVersion`/`kind`/`metadata` are omitted from every table (all are standard; `metadata` is `type: object`).

### CiliumNetworkPolicy

- **name**: `ciliumnetworkpolicies.cilium.io`  group `cilium.io`  scope **Namespaced**
- **names**: kind `CiliumNetworkPolicy`, plural `ciliumnetworkpolicies`, singular `ciliumnetworkpolicy`, shortNames `cnp,ciliumnp`, categories `cilium,ciliumpolicy`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`); `Valid` (string, jsonPath `.status.conditions[?(@.type=='Valid')].status`)
  - top-level CEL: `has(self.spec) || has(self.specs)`
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object |  | oneOf={endpointSelector} \| {nodeSelector}; anyOf={ingress} \| {ingressDeny} \| {egress} \| {egressDeny} | Spec is the desired Cilium specific rule specification. |
| `spec.description` | string |  |  | Description is a free form string, it can be used by the creator of the rule to store human readable explanat… |
| `spec.egress` | []object |  |  | Egress is a list of EgressRule which are enforced at egress. |
| `spec.egress[].authentication` | object |  |  | Authentication is the required authentication type for the allowed traffic, if any. |
| `spec.egress[].authentication.mode` | string | yes | enum=disabled/required/test-always-fail | Mode is the required authentication mode for the allowed traffic, if any. |
| `spec.egress[].icmps` | []object |  |  | ICMPs is a list of ICMP rule identified by type number which the endpoint subject to the rule is allowed to c… |
| `spec.egress[].icmps[].fields` | []object |  | maxItems=40 | Fields is a list of ICMP fields. |
| `spec.egress[].icmps[].fields[].family` | string |  | default="IPv4"; enum=IPv4/IPv6 | Family is a IP address version. |
| `spec.egress[].icmps[].fields[].type` | int\|string | yes | pattern=`^([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5]\|EchoRepl…`; int-or-string; anyOf=integer \| string | Type is a ICMP-type. |
| `spec.egress[].toCIDR` | []string |  |  | ToCIDR is a list of IP blocks which the endpoint subject to the rule is allowed to initiate connections. |
| `spec.egress[].toCIDRSet` | []object |  |  | ToCIDRSet is a list of IP blocks which the endpoint subject to the rule is allowed to initiate connections to… |
| `spec.egress[].toCIDRSet[].cidr` | string |  | fmt=cidr | CIDR is a CIDR prefix / IP Block. |
| `spec.egress[].toCIDRSet[].cidrGroupRef` | string |  | pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0…`; maxLength=253 | CIDRGroupRef is a reference to a CiliumCIDRGroup object. |
| `spec.egress[].toCIDRSet[].cidrGroupSelector` | object |  | mapType=atomic | CIDRGroupSelector selects CiliumCIDRGroups by their labels, rather than by name. |
| `spec.egress[].toCIDRSet[].cidrGroupSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.egress[].toCIDRSet[].cidrGroupSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.egress[].toCIDRSet[].cidrGroupSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.egress[].toCIDRSet[].cidrGroupSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.egress[].toCIDRSet[].cidrGroupSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.egress[].toCIDRSet[].except` | []string |  |  | ExceptCIDRs is a list of IP blocks which the endpoint subject to the rule is not allowed to initiate connecti… |
| `spec.egress[].toEndpoints` | []object |  |  | ToEndpoints is a list of endpoints identified by an EndpointSelector to which the endpoints subject to the ru… |
| `spec.egress[].toEndpoints[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.egress[].toEntities` | []string |  |  | ToEntities is a list of special entities to which the endpoint subject to the rule is allowed to initiate con… |
| `spec.egress[].toFQDNs` | []object |  |  | ToFQDN allows whitelisting DNS names in place of IPs. |
| `spec.egress[].toFQDNs[].matchName` | string |  | pattern=`^([-a-zA-Z0-9_]+[.]?)+$`; maxLength=255 | MatchName matches literal DNS names. |
| `spec.egress[].toFQDNs[].matchPattern` | string |  | pattern=`^([-a-zA-Z0-9_*]+[.]?)+$`; maxLength=255 | MatchPattern allows using wildcards to match DNS names. |
| `spec.egress[].toGroups` | []object |  |  | ToGroups allows policies to reference CIDRs provided by external integrations. |
| `spec.egress[].toGroups[].aws` | object |  |  | AWSGroup is an structure that can be used to whitelisting information from AWS integration |
| `spec.egress[].toGroups[].aws.labels` | map[string]string |  |  | Labels selects AWS ENIs by labels. |
| `spec.egress[].toGroups[].aws.region` | string |  |  | Deprecated: Region is unused. |
| `spec.egress[].toGroups[].aws.securityGroupsIds` | []string |  |  | SecurityGroupsIds selects VPC SecurityGroups by IDs. |
| `spec.egress[].toGroups[].aws.securityGroupsNames` | []string |  |  | SecurityGroupsNames selects VPC SecurityGroups by name. |
| `spec.egress[].toNodes` | []object |  |  | ToNodes is a list of nodes identified by an EndpointSelector to which endpoints subject to the rule is allowe… |
| `spec.egress[].toNodes[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.egress[].toPorts` | []object |  |  | ToPorts is a list of destination ports identified by port number and protocol which the endpoint subject to t… |
| `spec.egress[].toPorts[].listener` | object |  |  | listener specifies the name of a custom Envoy listener to which this traffic should be redirected to. |
| `spec.egress[].toPorts[].listener.envoyConfig` | object | yes |  | EnvoyConfig is a reference to the CEC or CCEC resource in which the listener is defined. |
| `spec.egress[].toPorts[].listener.envoyConfig.kind` | string |  | enum=CiliumEnvoyConfig/CiliumClusterwideEnvoyConfig | Kind is the resource type being referred to. |
| `spec.egress[].toPorts[].listener.envoyConfig.name` | string | yes | minLength=1 | Name is the resource name of the CiliumEnvoyConfig or CiliumClusterwideEnvoyConfig where the listener is defi… |
| `spec.egress[].toPorts[].listener.name` | string | yes | minLength=1 | Name is the name of the listener. |
| `spec.egress[].toPorts[].listener.priority` | integer |  | minimum=1; maximum=100 | Priority for this Listener that is used when multiple rules would apply different listeners to a policy map e… |
| `spec.egress[].toPorts[].originatingTLS` | object |  |  | OriginatingTLS is the TLS context for the connections originated by the L7 proxy. |
| `spec.egress[].toPorts[].originatingTLS.certificate` | string |  |  | Certificate is the file name or k8s secret item name for the certificate chain. |
| `spec.egress[].toPorts[].originatingTLS.privateKey` | string |  |  | PrivateKey is the file name or k8s secret item name for the private key matching the certificate chain. |
| `spec.egress[].toPorts[].originatingTLS.secret` | object | yes |  | Secret is the secret that contains the certificates and private key for the TLS context. |
| `spec.egress[].toPorts[].originatingTLS.secret.name` | string | yes |  | Name is the name of the secret. |
| `spec.egress[].toPorts[].originatingTLS.secret.namespace` | string |  |  | Namespace is the namespace in which the secret exists. |
| `spec.egress[].toPorts[].originatingTLS.trustedCA` | string |  |  | TrustedCA is the file name or k8s secret item name for the trusted CA. |
| `spec.egress[].toPorts[].ports` | []object |  | maxItems=40 | Ports is a list of L4 port/protocol |
| `spec.egress[].toPorts[].ports[].endPort` | integer |  | fmt=int32; minimum=0; maximum=65535 | EndPort can only be an L4 port number. |
| `spec.egress[].toPorts[].ports[].port` | string |  | pattern=`^(6553[0-5]\|655[0-2][0-9]\|65[0-4][0-9]{2}\|6[0-4][0-9]{3}\|…` | Port can be an L4 port number, or a name in the form of "http" or "http-8080". |
| `spec.egress[].toPorts[].ports[].protocol` | string |  | enum=TCP/UDP/SCTP/VRRP/IGMP/GRE/IPIP/IPV6/ESP/AH/ANY | Protocol is the L4 protocol. |
| `spec.egress[].toPorts[].rules` | object |  | oneOf={http} \| {dns} | Rules is a list of additional port level rules which must be met in order for the PortRule to allow the traff… |
| `spec.egress[].toPorts[].rules.dns` | []object |  |  | DNS-specific rules. |
| `spec.egress[].toPorts[].rules.dns[].*` |  |  |  | → same schema as `spec.egress[].toFQDNs[]` |
| `spec.egress[].toPorts[].rules.http` | []object |  |  | HTTP specific rules. |
| `spec.egress[].toPorts[].rules.http[].headerMatches` | []object |  |  | HeaderMatches is a list of HTTP headers which must be present and match against the given values. |
| `spec.egress[].toPorts[].rules.http[].headerMatches[].mismatch` | string |  | enum=LOG/ADD/DELETE/REPLACE | Mismatch identifies what to do in case there is no match. |
| `spec.egress[].toPorts[].rules.http[].headerMatches[].name` | string | yes | minLength=1 | Name identifies the header. |
| `spec.egress[].toPorts[].rules.http[].headerMatches[].secret` | object |  |  | Secret refers to a secret that contains the value to be matched against. |
| `spec.egress[].toPorts[].rules.http[].headerMatches[].secret.*` |  |  |  | → same schema as `spec.egress[].toPorts[].originatingTLS.secret` |
| `spec.egress[].toPorts[].rules.http[].headerMatches[].value` | string |  |  | Value matches the exact value of the header. |
| `spec.egress[].toPorts[].rules.http[].headers` | []string |  |  | Headers is a list of HTTP headers which must be present in the request. |
| `spec.egress[].toPorts[].rules.http[].host` | string |  | fmt=idn-hostname | Host is an extended POSIX regex matched against the host header of a request. |
| `spec.egress[].toPorts[].rules.http[].method` | string |  |  | Method is an extended POSIX regex matched against the method of a request, e.g. |
| `spec.egress[].toPorts[].rules.http[].path` | string |  |  | Path is an extended POSIX regex matched against the path of a request. |
| `spec.egress[].toPorts[].serverNames` | []string |  | minItems=1; listType=set | ServerNames is a list of allowed TLS SNI values. |
| `spec.egress[].toPorts[].terminatingTLS` | object |  |  | TerminatingTLS is the TLS context for the connection terminated by the L7 proxy. |
| `spec.egress[].toPorts[].terminatingTLS.*` |  |  |  | → same schema as `spec.egress[].toPorts[].originatingTLS` |
| `spec.egress[].toRequires` | []string |  | maxItems=0 | Deprecated. |
| `spec.egress[].toServices` | []object |  |  | ToServices is a list of services to which the endpoint subject to the rule is allowed to initiate connections. |
| `spec.egress[].toServices[].k8sService` | object |  |  | K8sService selects service by name and namespace pair |
| `spec.egress[].toServices[].k8sService.namespace` | string |  |  |  |
| `spec.egress[].toServices[].k8sService.serviceName` | string |  |  |  |
| `spec.egress[].toServices[].k8sServiceSelector` | object |  |  | K8sServiceSelector selects services by k8s labels and namespace |
| `spec.egress[].toServices[].k8sServiceSelector.namespace` | string |  |  |  |
| `spec.egress[].toServices[].k8sServiceSelector.selector` | object | yes | mapType=atomic | ServiceSelector is a label selector for k8s services |
| `spec.egress[].toServices[].k8sServiceSelector.selector.*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.egressDeny` | []object |  |  | EgressDeny is a list of EgressDenyRule which are enforced at egress. |
| `spec.egressDeny[].icmps` | []object |  |  | ICMPs is a list of ICMP rule identified by type number which the endpoint subject to the rule is not allowed … |
| `spec.egressDeny[].icmps[].fields` | []object |  | maxItems=40 | Fields is a list of ICMP fields. |
| `spec.egressDeny[].icmps[].fields[].*` |  |  |  | → same schema as `spec.egress[].icmps[].fields[]` |
| `spec.egressDeny[].toCIDR` | []string |  |  | ToCIDR is a list of IP blocks which the endpoint subject to the rule is allowed to initiate connections. |
| `spec.egressDeny[].toCIDRSet` | []object |  |  | ToCIDRSet is a list of IP blocks which the endpoint subject to the rule is allowed to initiate connections to… |
| `spec.egressDeny[].toCIDRSet[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[]` |
| `spec.egressDeny[].toEndpoints` | []object |  |  | ToEndpoints is a list of endpoints identified by an EndpointSelector to which the endpoints subject to the ru… |
| `spec.egressDeny[].toEndpoints[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.egressDeny[].toEntities` | []string |  |  | ToEntities is a list of special entities to which the endpoint subject to the rule is allowed to initiate con… |
| `spec.egressDeny[].toGroups` | []object |  |  | ToGroups allows policies to reference CIDRs provided by external integrations. |
| `spec.egressDeny[].toGroups[].aws` | object |  |  | AWSGroup is an structure that can be used to whitelisting information from AWS integration |
| `spec.egressDeny[].toGroups[].aws.*` |  |  |  | → same schema as `spec.egress[].toGroups[].aws` |
| `spec.egressDeny[].toNodes` | []object |  |  | ToNodes is a list of nodes identified by an EndpointSelector to which endpoints subject to the rule is allowe… |
| `spec.egressDeny[].toNodes[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.egressDeny[].toPorts` | []object |  |  | ToPorts is a list of destination ports identified by port number and protocol which the endpoint subject to t… |
| `spec.egressDeny[].toPorts[].ports` | []object |  |  | Ports is a list of L4 port/protocol |
| `spec.egressDeny[].toPorts[].ports[].*` |  |  |  | → same schema as `spec.egress[].toPorts[].ports[]` |
| `spec.egressDeny[].toRequires` | []string |  | maxItems=0 | Deprecated. |
| `spec.egressDeny[].toServices` | []object |  |  | ToServices is a list of services to which the endpoint subject to the rule is allowed to initiate connections. |
| `spec.egressDeny[].toServices[].*` |  |  |  | → same schema as `spec.egress[].toServices[]` |
| `spec.enableDefaultDeny` | object |  |  | EnableDefaultDeny determines whether this policy configures the subject endpoint(s) to have a default deny mo… |
| `spec.enableDefaultDeny.egress` | boolean |  |  | Whether or not the endpoint should have a default-deny rule applied to egress traffic. |
| `spec.enableDefaultDeny.ingress` | boolean |  |  | Whether or not the endpoint should have a default-deny rule applied to ingress traffic. |
| `spec.endpointSelector` | object |  | mapType=atomic | EndpointSelector selects all endpoints which should be subject to this rule. |
| `spec.endpointSelector.*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.ingress` | []object |  |  | Ingress is a list of IngressRule which are enforced at ingress. |
| `spec.ingress[].authentication` | object |  |  | Authentication is the required authentication type for the allowed traffic, if any. |
| `spec.ingress[].authentication.mode` | string | yes | enum=disabled/required/test-always-fail | Mode is the required authentication mode for the allowed traffic, if any. |
| `spec.ingress[].fromCIDR` | []string |  |  | FromCIDR is a list of IP blocks which the endpoint subject to the rule is allowed to receive connections from. |
| `spec.ingress[].fromCIDRSet` | []object |  |  | FromCIDRSet is a list of IP blocks which the endpoint subject to the rule is allowed to receive connections f… |
| `spec.ingress[].fromCIDRSet[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[]` |
| `spec.ingress[].fromEndpoints` | []object |  |  | FromEndpoints is a list of endpoints identified by an EndpointSelector which are allowed to communicate with … |
| `spec.ingress[].fromEndpoints[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.ingress[].fromEntities` | []string |  |  | FromEntities is a list of special entities which the endpoint subject to the rule is allowed to receive conne… |
| `spec.ingress[].fromGroups` | []object |  |  | FromGroups allows policies to reference CIDRs provided by external integrations. |
| `spec.ingress[].fromGroups[].aws` | object |  |  | AWSGroup is an structure that can be used to whitelisting information from AWS integration |
| `spec.ingress[].fromGroups[].aws.*` |  |  |  | → same schema as `spec.egress[].toGroups[].aws` |
| `spec.ingress[].fromNodes` | []object |  |  | FromNodes is a list of nodes identified by an EndpointSelector which are allowed to communicate with the endp… |
| `spec.ingress[].fromNodes[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.ingress[].fromRequires` | []string |  | maxItems=0 | Deprecated. |
| `spec.ingress[].icmps` | []object |  |  | ICMPs is a list of ICMP rule identified by type number which the endpoint subject to the rule is allowed to r… |
| `spec.ingress[].icmps[].fields` | []object |  | maxItems=40 | Fields is a list of ICMP fields. |
| `spec.ingress[].icmps[].fields[].*` |  |  |  | → same schema as `spec.egress[].icmps[].fields[]` |
| `spec.ingress[].toPorts` | []object |  |  | ToPorts is a list of destination ports identified by port number and protocol which the endpoint subject to t… |
| `spec.ingress[].toPorts[].*` |  |  |  | → same schema as `spec.egress[].toPorts[]` |
| `spec.ingressDeny` | []object |  |  | IngressDeny is a list of IngressDenyRule which are enforced at ingress. |
| `spec.ingressDeny[].fromCIDR` | []string |  |  | FromCIDR is a list of IP blocks which the endpoint subject to the rule is allowed to receive connections from. |
| `spec.ingressDeny[].fromCIDRSet` | []object |  |  | FromCIDRSet is a list of IP blocks which the endpoint subject to the rule is allowed to receive connections f… |
| `spec.ingressDeny[].fromCIDRSet[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[]` |
| `spec.ingressDeny[].fromEndpoints` | []object |  |  | FromEndpoints is a list of endpoints identified by an EndpointSelector which are allowed to communicate with … |
| `spec.ingressDeny[].fromEndpoints[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.ingressDeny[].fromEntities` | []string |  |  | FromEntities is a list of special entities which the endpoint subject to the rule is allowed to receive conne… |
| `spec.ingressDeny[].fromGroups` | []object |  |  | FromGroups allows policies to reference CIDRs provided by external integrations. |
| `spec.ingressDeny[].fromGroups[].aws` | object |  |  | AWSGroup is an structure that can be used to whitelisting information from AWS integration |
| `spec.ingressDeny[].fromGroups[].aws.*` |  |  |  | → same schema as `spec.egress[].toGroups[].aws` |
| `spec.ingressDeny[].fromNodes` | []object |  |  | FromNodes is a list of nodes identified by an EndpointSelector which are allowed to communicate with the endp… |
| `spec.ingressDeny[].fromNodes[].*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `spec.ingressDeny[].fromRequires` | []string |  | maxItems=0 | Deprecated. |
| `spec.ingressDeny[].icmps` | []object |  |  | ICMPs is a list of ICMP rule identified by type number which the endpoint subject to the rule is not allowed … |
| `spec.ingressDeny[].icmps[].fields` | []object |  | maxItems=40 | Fields is a list of ICMP fields. |
| `spec.ingressDeny[].icmps[].fields[].*` |  |  |  | → same schema as `spec.egress[].icmps[].fields[]` |
| `spec.ingressDeny[].toPorts` | []object |  |  | ToPorts is a list of destination ports identified by port number and protocol which the endpoint subject to t… |
| `spec.ingressDeny[].toPorts[].ports` | []object |  |  | Ports is a list of L4 port/protocol |
| `spec.ingressDeny[].toPorts[].ports[].*` |  |  |  | → same schema as `spec.egress[].toPorts[].ports[]` |
| `spec.labels` | []object |  |  | Labels is a list of optional strings which can be used to re-identify the rule or to store metadata. |
| `spec.labels[].key` | string | yes |  |  |
| `spec.labels[].source` | string |  |  | Source can be one of the above values (e.g.: LabelSourceK8s). |
| `spec.labels[].value` | string |  |  |  |
| `spec.log` | object |  |  | Log specifies custom policy-specific Hubble logging configuration. |
| `spec.log.value` | string |  | pattern=`^\PC*$`; maxLength=32 | Value is a free-form string that is included in Hubble flows that match this policy. |
| `spec.nodeSelector` | object |  | mapType=atomic | NodeSelector selects all nodes which should be subject to this rule. |
| `spec.nodeSelector.*` |  |  |  | → same schema as `spec.egress[].toCIDRSet[].cidrGroupSelector` |
| `specs` | []object |  |  | Specs is a list of desired Cilium specific rule specification. |
| `specs[].*` |  |  |  | → same schema as `spec` |
| `status` | object |  |  | Status is the status of the Cilium policy rule |
| `status.conditions` | []object |  | listType=map; listMapKeys=type |  |
| `status.conditions[].lastTransitionTime` | string |  | fmt=date-time | The last time the condition transitioned from one status to another. |
| `status.conditions[].message` | string |  |  | A human readable message indicating details about the transition. |
| `status.conditions[].reason` | string |  |  | The reason for the condition's last transition. |
| `status.conditions[].status` | string | yes |  | The status of the condition, one of True, False, or Unknown |
| `status.conditions[].type` | string | yes |  | The type of the policy condition |
| `status.derivativePolicies` | map[string]object |  |  | DerivativePolicies is the status of all policies derived from the Cilium policy |
| `status.derivativePolicies{}.annotations` | map[string]string |  |  | Annotations corresponds to the Annotations in the ObjectMeta of the CNP that have been realized on the node f… |
| `status.derivativePolicies{}.enforcing` | boolean |  |  | Enforcing is set to true once all endpoints present at the time the policy has been imported are enforcing th… |
| `status.derivativePolicies{}.error` | string |  |  | Error describes any error that occurred when parsing or importing the policy, or realizing the policy for the… |
| `status.derivativePolicies{}.lastUpdated` | string |  | fmt=date-time | LastUpdated contains the last time this status was updated |
| `status.derivativePolicies{}.localPolicyRevision` | integer |  | fmt=int64 | Revision is the policy revision of the repository which first implemented this policy. |
| `status.derivativePolicies{}.ok` | boolean |  |  | OK is true when the policy has been parsed and imported successfully into the in-memory policy repository on … |

### CiliumClusterwideNetworkPolicy

- **name**: `ciliumclusterwidenetworkpolicies.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumClusterwideNetworkPolicy`, plural `ciliumclusterwidenetworkpolicies`, singular `ciliumclusterwidenetworkpolicy`, shortNames `ccnp`, categories `cilium,ciliumpolicy`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Valid` (string, jsonPath `.status.conditions[?(@.type=='Valid')].status`)
  - top-level CEL: `has(self.spec) || has(self.specs)`
  - top-level required: metadata

Schema is byte-identical to CiliumNetworkPolicy above (verified with `diff` after normalising the kind/plural names): the only differences are `scope: Cluster`, the missing `Age` printer column, and description text. `spec.nodeSelector` (host policy) is only meaningful in CCNP; `spec.endpointSelector` in a CCNP selects across all namespaces. Same `oneOf={endpointSelector}|{nodeSelector}`, `anyOf` rule-presence check, and `status.conditions`/`status.derivativePolicies`.

### CiliumCIDRGroup

- **name**: `ciliumcidrgroups.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumCIDRGroup`, plural `ciliumcidrgroups`, singular `ciliumcidrgroup`, shortNames `ccg`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - top-level required: spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  |  |
| `spec.externalCIDRs` | []string | yes | minItems=0 | ExternalCIDRs is a list of CIDRs selecting peers outside the clusters. |

- **version `v2alpha1`**: served=True storage=False deprecated=True subresources=none
  - top-level required: spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  |  |
| `spec.externalCIDRs` | []string | yes | minItems=0 | ExternalCIDRs is a list of CIDRs selecting peers outside the clusters. |

### CiliumEndpoint

- **name**: `ciliumendpoints.cilium.io`  group `cilium.io`  scope **Namespaced**
- **names**: kind `CiliumEndpoint`, plural `ciliumendpoints`, singular `ciliumendpoint`, shortNames `cep,ciliumep`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - printer columns: `Security Identity` (integer, jsonPath `.status.identity.id`); `Ingress Enforcement` (string, jsonPath `.status.policy.ingress.state`, priority=1); `Egress Enforcement` (string, jsonPath `.status.policy.egress.state`, priority=1); `Endpoint State` (string, jsonPath `.status.state`); `IPv4` (string, jsonPath `.status.networking.addressing[0].ipv4`); `IPv6` (string, jsonPath `.status.networking.addressing[0].ipv6`)
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `status` | object |  |  | EndpointStatus is the status of a Cilium endpoint. |
| `status.controllers` | []object |  |  | Controllers is the list of failing controllers for this endpoint. |
| `status.controllers[].configuration` | object |  |  | Configuration is the controller configuration |
| `status.controllers[].configuration.error-retry` | boolean |  |  | Retry on error |
| `status.controllers[].configuration.error-retry-base` | integer |  | fmt=int64 | Base error retry back-off time Format: duration |
| `status.controllers[].configuration.interval` | integer |  | fmt=int64 | Regular synchronization interval Format: duration |
| `status.controllers[].name` | string |  |  | Name is the name of the controller |
| `status.controllers[].status` | object |  |  | Status is the status of the controller |
| `status.controllers[].status.consecutive-failure-count` | integer |  | fmt=int64 |  |
| `status.controllers[].status.failure-count` | integer |  | fmt=int64 |  |
| `status.controllers[].status.last-failure-msg` | string |  |  |  |
| `status.controllers[].status.last-failure-timestamp` | string |  |  |  |
| `status.controllers[].status.last-success-timestamp` | string |  |  |  |
| `status.controllers[].status.success-count` | integer |  | fmt=int64 |  |
| `status.controllers[].uuid` | string |  |  | UUID is the UUID of the controller |
| `status.encryption` | object |  |  | Encryption is the encryption configuration of the node |
| `status.encryption.key` | integer |  |  | Key is the index to the key to use for encryption or 0 if encryption is disabled. |
| `status.external-identifiers` | object |  |  | ExternalIdentifiers is a set of identifiers to identify the endpoint apart from the pod name. |
| `status.external-identifiers.cni-attachment-id` | string |  |  | ID assigned to this attachment by container runtime |
| `status.external-identifiers.container-id` | string |  |  | ID assigned by container runtime (deprecated, may not be unique) |
| `status.external-identifiers.container-name` | string |  |  | Name assigned to container (deprecated, may not be unique) |
| `status.external-identifiers.docker-endpoint-id` | string |  |  | Docker endpoint ID |
| `status.external-identifiers.docker-network-id` | string |  |  | Docker network ID |
| `status.external-identifiers.k8s-namespace` | string |  |  | K8s namespace for this endpoint (deprecated, may not be unique) |
| `status.external-identifiers.k8s-pod-name` | string |  |  | K8s pod name for this endpoint (deprecated, may not be unique) |
| `status.external-identifiers.pod-name` | string |  |  | K8s pod for this endpoint (deprecated, may not be unique) |
| `status.health` | object |  |  | Health is the overall endpoint & subcomponent health. |
| `status.health.bpf` | string |  |  | bpf |
| `status.health.connected` | boolean |  |  | Is this endpoint reachable |
| `status.health.overallHealth` | string |  |  | overall health |
| `status.health.policy` | string |  |  | policy |
| `status.id` | integer |  | fmt=int64 | ID is the cilium-agent-local ID of the endpoint. |
| `status.identity` | object |  |  | Identity is the security identity associated with the endpoint |
| `status.identity.id` | integer |  | fmt=int64 | ID is the numeric identity of the endpoint |
| `status.identity.labels` | []string |  |  | Labels is the list of labels associated with the identity |
| `status.log` | []object |  |  | Log is the list of the last few warning and error log entries |
| `status.log[].code` | string |  |  | Code indicate type of status change Enum: ["ok","failed"] |
| `status.log[].message` | string |  |  | Status message |
| `status.log[].state` | string |  |  | state |
| `status.log[].timestamp` | string |  |  | Timestamp when status change occurred |
| `status.named-ports` | []object |  |  | NamedPorts List of named Layer 4 port and protocol pairs which will be used in Network Policy specs. |
| `status.named-ports[].name` | string |  |  | Optional layer 4 port name |
| `status.named-ports[].port` | integer |  |  | Layer 4 port number |
| `status.named-ports[].protocol` | string |  |  | Layer 4 protocol Enum: ["TCP","UDP","SCTP","ICMP","ICMPV6","ANY"] |
| `status.networking` | object |  |  | Networking is the networking properties of the endpoint. |
| `status.networking.addressing` | []object | yes |  | IP4/6 addresses assigned to this Endpoint |
| `status.networking.addressing[].ipv4` | string |  |  |  |
| `status.networking.addressing[].ipv6` | string |  |  |  |
| `status.networking.node` | string |  |  | NodeIP is the IP of the node the endpoint is running on. |
| `status.policy` | object |  |  | EndpointPolicy represents the endpoint's policy by listing all allowed ingress and egress identities in combi… |
| `status.policy.egress` | object |  |  | EndpointPolicyDirection is the list of allowed identities per direction. |
| `status.policy.egress.adding` | []object |  |  | Deprecated |
| `status.policy.egress.adding[].dest-port` | integer |  |  |  |
| `status.policy.egress.adding[].identity` | integer |  | fmt=int64 |  |
| `status.policy.egress.adding[].identity-labels` | map[string]string |  |  |  |
| `status.policy.egress.adding[].protocol` | integer |  |  |  |
| `status.policy.egress.allowed` | []object |  |  | AllowedIdentityList is a list of IdentityTuples that species peers that are allowed. |
| `status.policy.egress.allowed[].*` |  |  |  | → same schema as `status.policy.egress.adding[]` |
| `status.policy.egress.denied` | []object |  |  | DenyIdentityList is a list of IdentityTuples that species peers that are denied. |
| `status.policy.egress.denied[].*` |  |  |  | → same schema as `status.policy.egress.adding[]` |
| `status.policy.egress.enforcing` | boolean | yes |  |  |
| `status.policy.egress.removing` | []object |  |  | Deprecated |
| `status.policy.egress.removing[].*` |  |  |  | → same schema as `status.policy.egress.adding[]` |
| `status.policy.egress.state` | string |  |  | EndpointPolicyState defines the state of the Policy mode: "enforcing", "non-enforcing", "disabled" |
| `status.policy.ingress` | object |  |  | EndpointPolicyDirection is the list of allowed identities per direction. |
| `status.policy.ingress.*` |  |  |  | → same schema as `status.policy.egress` |
| `status.service-account` | string |  |  | ServiceAccount is the service account associated with the endpoint |
| `status.state` | string |  | enum=creating/waiting-for-identity/not-ready/waiting-to-regenerate/regenerating/restoring/ready/disconnecting/disconnected/invalid | State is the state of the endpoint. |

### CiliumEndpointSlice

- **name**: `ciliumendpointslices.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumEndpointSlice`, plural `ciliumendpointslices`, singular `ciliumendpointslice`, shortNames `ces`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2alpha1`**: served=True storage=True deprecated=False subresources=none
  - top-level required: endpoints,metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `endpoints` | []object | yes |  | Endpoints is a list of coreCEPs packed in a CiliumEndpointSlice |
| `endpoints[].encryption` | object |  |  | EncryptionSpec defines the encryption relevant configuration of a node. |
| `endpoints[].encryption.key` | integer |  |  | Key is the index to the key to use for encryption or 0 if encryption is disabled. |
| `endpoints[].id` | integer |  | fmt=int64 | IdentityID is the numeric identity of the endpoint |
| `endpoints[].name` | string |  |  | Name indicate as CiliumEndpoint name. |
| `endpoints[].named-ports` | []object |  |  | NamedPorts List of named Layer 4 port and protocol pairs which will be used in Network Policy specs. |
| `endpoints[].named-ports[].name` | string |  |  | Optional layer 4 port name |
| `endpoints[].named-ports[].port` | integer |  |  | Layer 4 port number |
| `endpoints[].named-ports[].protocol` | string |  |  | Layer 4 protocol Enum: ["TCP","UDP","SCTP","ICMP","ICMPV6","ANY"] |
| `endpoints[].networking` | object |  |  | EndpointNetworking is the addressing information of an endpoint. |
| `endpoints[].networking.addressing` | []object | yes |  | IP4/6 addresses assigned to this Endpoint |
| `endpoints[].networking.addressing[].ipv4` | string |  |  |  |
| `endpoints[].networking.addressing[].ipv6` | string |  |  |  |
| `endpoints[].networking.node` | string |  |  | NodeIP is the IP of the node the endpoint is running on. |
| `endpoints[].pod-uid` | string |  |  | PodUID is the UID of the Pod that owns this endpoint. |
| `endpoints[].service-account` | string |  |  | ServiceAccount is the service account of the endpoint. |
| `namespace` | string |  |  | Namespace indicate as CiliumEndpointSlice namespace. |

### CiliumIdentity

- **name**: `ciliumidentities.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumIdentity`, plural `ciliumidentities`, singular `ciliumidentity`, shortNames `ciliumid`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Namespace` (string, jsonPath `.metadata.labels.io\.kubernetes\.pod\.namespace`); `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,security-labels

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `security-labels` | map[string]string | yes |  | SecurityLabels is the source-of-truth set of labels for this identity. |

### CiliumNode

- **name**: `ciliumnodes.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumNode`, plural `ciliumnodes`, singular `ciliumnode`, shortNames `cn,ciliumn`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `CiliumInternalIP` (string, jsonPath `.spec.addresses[?(@.type=="CiliumInternalIP")].ip`); `InternalIP` (string, jsonPath `.spec.addresses[?(@.type=="InternalIP")].ip`); `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec defines the desired specification/configuration of the node. |
| `spec.addresses` | []object |  |  | Addresses is the list of all node addresses. |
| `spec.addresses[].ip` | string |  |  | IP is an IP of a node |
| `spec.addresses[].type` | string |  |  | Type is the type of the node address |
| `spec.alibaba-cloud` | object |  |  | AlibabaCloud is the AlibabaCloud IPAM specific configuration. |
| `spec.alibaba-cloud.availability-zone` | string |  |  | AvailabilityZone is the availability zone to use when allocating ENIs. |
| `spec.alibaba-cloud.cidr-block` | string |  | fmt=cidr | CIDRBlock is vpc ipv4 CIDR |
| `spec.alibaba-cloud.instance-type` | string |  |  | InstanceType is the ECS instance type, e.g. |
| `spec.alibaba-cloud.security-group-tags` | map[string]string |  |  | SecurityGroupTags is the list of tags to use when evaluating which security groups to use for the ENI. |
| `spec.alibaba-cloud.security-groups` | []string |  |  | SecurityGroups is the list of security groups to attach to any ENI that is created and attached to the instan… |
| `spec.alibaba-cloud.vpc-id` | string |  |  | VPCID is the VPC ID to use when allocating ENIs. |
| `spec.alibaba-cloud.vswitch-tags` | map[string]string |  |  | VSwitchTags is the list of tags to use when evaluating which vSwitch to use for the ENI. |
| `spec.alibaba-cloud.vswitches` | []string |  |  | VSwitches is the ID of vSwitch available for ENI |
| `spec.azure` | object |  |  | Azure is the Azure IPAM specific configuration. |
| `spec.azure.interface-name` | string |  |  | InterfaceName is the name of the interface the cilium-operator will use to allocate all the IPs on |
| `spec.bootid` | string |  |  | BootID is a unique node identifier generated on boot |
| `spec.encryption` | object |  |  | Encryption is the encryption configuration of the node. |
| `spec.encryption.key` | integer |  |  | Key is the index to the key to use for encryption or 0 if encryption is disabled. |
| `spec.eni` | object |  |  | ENI is the AWS ENI specific configuration. |
| `spec.eni.availability-zone` | string |  |  | AvailabilityZone is the availability zone to use when allocating ENIs. |
| `spec.eni.delete-on-termination` | boolean |  |  | DeleteOnTermination defines that the ENI should be deleted when the associated instance is terminated. |
| `spec.eni.disable-prefix-delegation` | boolean |  |  | DisablePrefixDelegation determines whether ENI prefix delegation should be disabled on this node. |
| `spec.eni.exclude-interface-tags` | map[string]string |  |  | ExcludeInterfaceTags is the list of tags to use when excluding ENIs for Cilium IP allocation. |
| `spec.eni.first-interface-index` | integer |  | minimum=0 | FirstInterfaceIndex is the index of the first ENI to use for IP allocation, e.g. |
| `spec.eni.instance-type` | string |  |  | InstanceType is the AWS EC2 instance type, e.g. |
| `spec.eni.node-subnet-id` | string |  |  | NodeSubnetID is the subnet of the primary ENI the instance was brought up with. |
| `spec.eni.security-group-tags` | map[string]string |  |  | SecurityGroupTags is the list of tags to use when evaliating what AWS security groups to use for the ENI. |
| `spec.eni.security-groups` | []string |  |  | SecurityGroups is the list of security groups to attach to any ENI that is created and attached to the instan… |
| `spec.eni.subnet-ids` | []string |  |  | SubnetIDs is the list of subnet ids to use when evaluating what AWS subnets to use for ENI and IP allocation. |
| `spec.eni.subnet-tags` | map[string]string |  |  | SubnetTags is the list of tags to use when evaluating what AWS subnets to use for ENI and IP allocation. |
| `spec.eni.use-primary-address` | boolean |  |  | UsePrimaryAddress determines whether an ENI's primary address should be available for allocations on the node |
| `spec.eni.vpc-id` | string |  |  | VpcID is the VPC ID to use when allocating ENIs. |
| `spec.health` | object |  |  | HealthAddressing is the addressing information for health connectivity checking. |
| `spec.health.ipv4` | string |  |  | IPv4 is the IPv4 address of the IPv4 health endpoint. |
| `spec.health.ipv6` | string |  |  | IPv6 is the IPv6 address of the IPv4 health endpoint. |
| `spec.ingress` | object |  |  | IngressAddressing is the addressing information for Ingress listener. |
| `spec.ingress.*` |  |  |  | → same schema as `spec.health` |
| `spec.instance-id` | string |  |  | InstanceID is the identifier of the node. |
| `spec.ipam` | object |  |  | IPAM is the address management specification. |
| `spec.ipam.ipv6-pool` | map[string]object |  |  | IPv6Pool is the list of IPv6 addresses available to the node for allocation. |
| `spec.ipam.ipv6-pool{}.owner` | string |  |  | Owner is the owner of the IP. |
| `spec.ipam.ipv6-pool{}.resource` | string |  |  | Resource is set for both available and allocated IPs, it represents what resource the IP is associated with, … |
| `spec.ipam.max-above-watermark` | integer |  | minimum=0 | MaxAboveWatermark is the maximum number of addresses to allocate beyond the addresses needed to reach the Pre… |
| `spec.ipam.max-allocate` | integer |  | minimum=0 | MaxAllocate is the maximum number of IPs that can be allocated to the node. |
| `spec.ipam.min-allocate` | integer |  | minimum=0 | MinAllocate is the minimum number of IPs that must be allocated when the node is first bootstrapped. |
| `spec.ipam.podCIDRs` | []string |  |  | PodCIDRs is the list of CIDRs available to the node for allocation. |
| `spec.ipam.pool` | map[string]object |  |  | Pool is the list of IPv4 addresses available to the node for allocation. |
| `spec.ipam.pool{}.*` |  |  |  | → same schema as `spec.ipam.ipv6-pool{}` |
| `spec.ipam.pools` | object |  |  | Pools contains the list of assigned IPAM pools for this node. |
| `spec.ipam.pools.allocated` | []object |  |  | Allocated contains the list of pooled CIDR assigned to this node. |
| `spec.ipam.pools.allocated[].allowFirstIP` | boolean |  |  | AllowFirstIP allows the first IP of each allocated CIDR to be used. |
| `spec.ipam.pools.allocated[].allowLastIP` | boolean |  |  | AllowLastIP allows the last IP of each allocated CIDR to be used. |
| `spec.ipam.pools.allocated[].cidrs` | []string |  |  | CIDRs contains a list of pod CIDRs currently allocated from this pool |
| `spec.ipam.pools.allocated[].pool` | string | yes | minLength=1 | Pool is the name of the IPAM pool backing this allocation |
| `spec.ipam.pools.requested` | []object |  |  | Requested contains a list of IPAM pool requests, i.e. |
| `spec.ipam.pools.requested[].needed` | object |  |  | Needed indicates how many IPs out of the above Pool this node requests from the operator. |
| `spec.ipam.pools.requested[].needed.ipv4-addrs` | integer |  |  | IPv4Addrs contains the number of requested IPv4 addresses out of a given pool |
| `spec.ipam.pools.requested[].needed.ipv6-addrs` | integer |  |  | IPv6Addrs contains the number of requested IPv6 addresses out of a given pool |
| `spec.ipam.pools.requested[].pool` | string | yes | minLength=1 | Pool is the name of the IPAM pool backing this request |
| `spec.ipam.pre-allocate` | integer |  | minimum=0 | PreAllocate defines the number of IP addresses that must be available for allocation in the IPAMSpec. |
| `spec.ipam.static-ip-tags` | map[string]string |  |  | StaticIPTags are used to determine the pool of IPs from which to attribute a static IP to the node. |
| `status` | object |  |  | Status defines the realized specification/configuration and status of the node. |
| `status.alibaba-cloud` | object |  |  | AlibabaCloud is the AlibabaCloud specific status of the node. |
| `status.alibaba-cloud.enis` | map[string]object |  |  | ENIs is the list of ENIs on the node |
| `status.alibaba-cloud.enis{}.instance-id` | string |  |  | InstanceID is the InstanceID using this ENI |
| `status.alibaba-cloud.enis{}.mac-address` | string |  |  | MACAddress is the mac address of the ENI |
| `status.alibaba-cloud.enis{}.network-interface-id` | string |  |  | NetworkInterfaceID is the ENI id |
| `status.alibaba-cloud.enis{}.primary-ip-address` | string |  |  | PrimaryIPAddress is the primary IP on ENI |
| `status.alibaba-cloud.enis{}.private-ipsets` | []object |  |  | PrivateIPSets is the list of all IPs on the ENI, including PrimaryIPAddress |
| `status.alibaba-cloud.enis{}.private-ipsets[].primary` | boolean |  |  |  |
| `status.alibaba-cloud.enis{}.private-ipsets[].private-ip-address` | string |  |  |  |
| `status.alibaba-cloud.enis{}.security-groupids` | []string |  |  | SecurityGroupIDs is the security group ids used by this ENI |
| `status.alibaba-cloud.enis{}.tags` | map[string]string |  |  | Tags is the tags on this ENI |
| `status.alibaba-cloud.enis{}.type` | string |  |  | Type is the ENI type Primary or Secondary |
| `status.alibaba-cloud.enis{}.vpc` | object |  |  | VPC is the vpc to which the ENI belongs |
| `status.alibaba-cloud.enis{}.vpc.cidr` | string |  | fmt=cidr | CIDRBlock is the VPC IPv4 CIDR |
| `status.alibaba-cloud.enis{}.vpc.ipv6-cidr` | string |  | fmt=cidr | IPv6CIDRBlock is the VPC IPv6 CIDR |
| `status.alibaba-cloud.enis{}.vpc.secondary-cidrs` | []string |  |  | SecondaryCIDRs is the list of Secondary CIDRs associated with the VPC |
| `status.alibaba-cloud.enis{}.vpc.vpc-id` | string |  |  | VPCID is the vpc to which the ENI belongs |
| `status.alibaba-cloud.enis{}.vswitch` | object |  |  | VSwitch is the vSwitch the ENI is using |
| `status.alibaba-cloud.enis{}.vswitch.cidr` | string |  | fmt=cidr | CIDRBlock is the vSwitch IPv4 CIDR |
| `status.alibaba-cloud.enis{}.vswitch.ipv6-cidr` | string |  | fmt=cidr | IPv6CIDRBlock is the vSwitch IPv6 CIDR |
| `status.alibaba-cloud.enis{}.vswitch.vswitch-id` | string |  |  | VSwitchID is the vSwitch to which the ENI belongs |
| `status.alibaba-cloud.enis{}.zone-id` | string |  |  | ZoneID is the zone to which the ENI belongs |
| `status.azure` | object |  |  | Azure is the Azure specific status of the node. |
| `status.azure.interfaces` | []object |  |  | Interfaces is the list of interfaces on the node |
| `status.azure.interfaces[].addresses` | []object |  |  | Addresses is the list of secondary IPs associated with the interface. |
| `status.azure.interfaces[].addresses[].ip` | string |  |  | IP is the ip address of the address |
| `status.azure.interfaces[].addresses[].state` | string |  |  | State is the provisioning state of the address |
| `status.azure.interfaces[].addresses[].subnet` | string |  |  | Subnet is the subnet the address belongs to. |
| `status.azure.interfaces[].cidr` | string |  | fmt=cidr | CIDR is the range that the interface belongs to. |
| `status.azure.interfaces[].gateway` | string |  |  | Gateway is the interface's subnet's default route |
| `status.azure.interfaces[].id` | string |  |  | ID is the identifier |
| `status.azure.interfaces[].ip` | string |  |  | IP is the primary IP of the interface |
| `status.azure.interfaces[].mac` | string |  |  | MAC is the mac address |
| `status.azure.interfaces[].name` | string |  |  | Name is the name of the interface |
| `status.azure.interfaces[].security-group` | string |  |  | SecurityGroup is the security group associated with the interface |
| `status.azure.interfaces[].state` | string |  |  | State is the provisioning state |
| `status.azure.interfaces[].subnet` | object |  |  | Subnet is the subnet the interface is attached to. |
| `status.azure.interfaces[].subnet.cidr` | string |  | fmt=cidr | CIDR is the CIDR range associated with the subnet |
| `status.azure.interfaces[].subnet.id` | string |  |  | ID is the resource ID of the subnet |
| `status.eni` | object |  |  | ENI is the AWS ENI specific status of the node. |
| `status.eni.enis` | map[string]object |  |  | ENIs is the list of ENIs on the node |
| `status.eni.enis{}.addresses` | []string |  |  | Addresses is the list of all secondary IPs associated with the ENI |
| `status.eni.enis{}.availability-zone` | string |  |  | AvailabilityZone is the availability zone of the ENI |
| `status.eni.enis{}.description` | string |  |  | Description is the description field of the ENI |
| `status.eni.enis{}.id` | string |  |  | ID is the ENI ID |
| `status.eni.enis{}.ip` | string |  |  | IP is the primary IP of the ENI |
| `status.eni.enis{}.ipv6-prefixes` | []string |  |  | IPv6Prefixes is the list of all IPv6 /80 delegated prefixes associated with the ENI |
| `status.eni.enis{}.mac` | string |  |  | MAC is the mac address of the ENI |
| `status.eni.enis{}.number` | integer |  |  | Number is the interface index, it used in combination with FirstInterfaceIndex |
| `status.eni.enis{}.prefixes` | []string |  |  | Prefixes is the list of all IPv4 /28 delegated prefixes associated with the ENI |
| `status.eni.enis{}.public-ip` | string |  |  | PublicIP is the public IP associated with the ENI |
| `status.eni.enis{}.security-groups` | []string |  |  | SecurityGroups are the security groups associated with the ENI |
| `status.eni.enis{}.subnet` | object |  |  | Subnet is the subnet the ENI is associated with |
| `status.eni.enis{}.subnet.*` |  |  |  | → same schema as `status.azure.interfaces[].subnet` |
| `status.eni.enis{}.tags` | map[string]string |  |  | Tags is the set of tags of the ENI. |
| `status.eni.enis{}.vpc` | object |  |  | VPC is the VPC information to which the ENI is attached to |
| `status.eni.enis{}.vpc.cidrs` | []string |  |  | CIDRs is the list of CIDR ranges associated with the VPC |
| `status.eni.enis{}.vpc.id` | string |  |  | / ID is the ID of a VPC |
| `status.eni.enis{}.vpc.primary-cidr` | string |  | fmt=cidr | PrimaryCIDR is the primary CIDR of the VPC |
| `status.ipam` | object |  |  | IPAM is the IPAM status of the node. |
| `status.ipam.assigned-static-ip` | string |  |  | AssignedStaticIP is the static IP assigned to the node (ex: public Elastic IP address in AWS) |
| `status.ipam.ipv6-used` | map[string]object |  |  | IPv6Used lists all IPv6 addresses out of Spec.IPAM.IPv6Pool which have been allocated and are in use. |
| `status.ipam.ipv6-used{}.*` |  |  |  | → same schema as `spec.ipam.ipv6-pool{}` |
| `status.ipam.operator-status` | object |  |  | Operator is the Operator status of the node |
| `status.ipam.operator-status.error` | string |  |  | Error is the error message set by cilium-operator. |
| `status.ipam.pod-cidrs` | map[string]object |  |  | PodCIDRs lists the status of each pod CIDR allocated to this node. |
| `status.ipam.pod-cidrs{}.status` | string |  | enum=released/depleted/in-use | Status describes the status of a pod CIDR |
| `status.ipam.release-ips` | map[string]string |  |  | ReleaseIPs tracks the state for every IPv4 address considered for release. |
| `status.ipam.release-ipv6s` | map[string]string |  |  | ReleaseIPv6s tracks the state for every IPv6 address considered for release. |
| `status.ipam.used` | map[string]object |  |  | Used lists all IPv4 addresses out of Spec.IPAM.Pool which have been allocated and are in use. |
| `status.ipam.used{}.*` |  |  |  | → same schema as `spec.ipam.ipv6-pool{}` |

### CiliumNodeConfig

- **name**: `ciliumnodeconfigs.cilium.io`  group `cilium.io`  scope **Namespaced**
- **names**: kind `CiliumNodeConfig`, plural `ciliumnodeconfigs`, singular `ciliumnodeconfig`, shortNames `-`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - top-level required: spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is the desired Cilium configuration overrides for a given node |
| `spec.defaults` | map[string]string | yes |  | Defaults is treated the same as the cilium-config ConfigMap - a set of key-value pairs parsed by the agent an… |
| `spec.nodeSelector` | object | yes | mapType=atomic | NodeSelector is a label selector that determines to which nodes this configuration applies. |
| `spec.nodeSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.nodeSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.nodeSelector.matchExpressions[].operator` | string | yes |  | operator represents a key's relationship to a set of values. |
| `spec.nodeSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.nodeSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |

### CiliumLocalRedirectPolicy

- **name**: `ciliumlocalredirectpolicies.cilium.io`  group `cilium.io`  scope **Namespaced**
- **names**: kind `CiliumLocalRedirectPolicy`, plural `ciliumlocalredirectpolicies`, singular `ciliumlocalredirectpolicy`, shortNames `clrp`, categories `cilium,ciliumpolicy`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object |  |  | Spec is the desired behavior of the local redirect policy. |
| `spec.description` | string |  |  | Description can be used by the creator of the policy to describe the purpose of this policy. |
| `spec.redirectBackend` | object | yes | CEL:`self == oldSelf` | RedirectBackend specifies backend configuration to redirect traffic to. |
| `spec.redirectBackend.localEndpointSelector` | object | yes | mapType=atomic | LocalEndpointSelector selects node local pod(s) where traffic is redirected to. |
| `spec.redirectBackend.localEndpointSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.redirectBackend.localEndpointSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.redirectBackend.localEndpointSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.redirectBackend.localEndpointSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.redirectBackend.localEndpointSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.redirectBackend.toPorts` | []object | yes |  | ToPorts is a list of L4 ports with protocol of node local pod(s) where traffic is redirected to. |
| `spec.redirectBackend.toPorts[].name` | string |  | pattern=`^([0-9]{1,4})\|([a-zA-Z0-9]-?)*[a-zA-Z](-?[a-zA-Z0-9])*$` | Name is a port name, which must contain at least one [a-z], and may also contain [0-9] and '-' anywhere excep… |
| `spec.redirectBackend.toPorts[].port` | string | yes | pattern=`^()([1-9]\|[1-5]?[0-9]{2,4}\|6[1-4][0-9]{3}\|65[1-4][0-9]{2}…` | Port is an L4 port number. |
| `spec.redirectBackend.toPorts[].protocol` | string | yes | enum=TCP/UDP | Protocol is the L4 protocol. |
| `spec.redirectFrontend` | object | yes | CEL:`self == oldSelf`; oneOf={addressMatcher} \| {serviceMatcher} | RedirectFrontend specifies frontend configuration to redirect traffic from. |
| `spec.redirectFrontend.addressMatcher` | object |  |  | AddressMatcher is a tuple {IP, port, protocol} that matches traffic to be redirected. |
| `spec.redirectFrontend.addressMatcher.ip` | string | yes | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | IP is a destination ip address for traffic to be redirected. |
| `spec.redirectFrontend.addressMatcher.toPorts` | []object | yes |  | ToPorts is a list of destination L4 ports with protocol for traffic to be redirected. |
| `spec.redirectFrontend.addressMatcher.toPorts[].*` |  |  |  | → same schema as `spec.redirectBackend.toPorts[]` |
| `spec.redirectFrontend.serviceMatcher` | object |  |  | ServiceMatcher specifies Kubernetes service and port that matches traffic to be redirected. |
| `spec.redirectFrontend.serviceMatcher.namespace` | string | yes |  | Namespace is the Kubernetes service namespace. |
| `spec.redirectFrontend.serviceMatcher.serviceName` | string | yes |  | Name is the name of a destination Kubernetes service that identifies traffic to be redirected. |
| `spec.redirectFrontend.serviceMatcher.toPorts` | []object |  |  | ToPorts is a list of destination service L4 ports with protocol for traffic to be redirected. |
| `spec.redirectFrontend.serviceMatcher.toPorts[].*` |  |  |  | → same schema as `spec.redirectBackend.toPorts[]` |
| `spec.skipRedirectFromBackend` | boolean |  | default=false; CEL:`self == oldSelf` | SkipRedirectFromBackend indicates whether traffic matching RedirectFrontend from RedirectBackend should skip … |
| `status` | object |  |  | Status is the most recent status of the local redirect policy. |
| `status.ok` | boolean |  |  |  |

### CiliumEgressGatewayPolicy

- **name**: `ciliumegressgatewaypolicies.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumEgressGatewayPolicy`, plural `ciliumegressgatewaypolicies`, singular `ciliumegressgatewaypolicy`, shortNames `cegp`, categories `cilium,ciliumpolicy`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object |  |  |  |
| `spec.destinationCIDRs` | []string | yes |  | DestinationCIDRs is a list of destination CIDRs for destination IP addresses. |
| `spec.egressGateway` | object | yes |  | EgressGateway is the gateway node responsible for SNATing traffic. |
| `spec.egressGateway.egressIP` | string |  | maxLength=39; CEL:`self == '' \|\| isIP(self)` | EgressIP is the source IP address that the egress traffic is SNATed with. |
| `spec.egressGateway.interface` | string |  |  | Interface is the network interface to which the egress IP address that the traffic is SNATed with is assigned. |
| `spec.egressGateway.nodeSelector` | object | yes | mapType=atomic | This is a label selector which selects the node that should act as egress gateway for the given policy. |
| `spec.egressGateway.nodeSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.egressGateway.nodeSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.egressGateway.nodeSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.egressGateway.nodeSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.egressGateway.nodeSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.egressGateways` | []object |  | default=[]; maxItems=64 | Optional list of gateway nodes responsible for SNATing traffic. |
| `spec.egressGateways[].*` |  |  |  | → same schema as `spec.egressGateway` |
| `spec.excludedCIDRs` | []string |  |  | ExcludedCIDRs is a list of destination CIDRs that will be excluded from the egress gateway redirection and SN… |
| `spec.selectors` | []object | yes |  | Egress represents a list of rules by which egress traffic is filtered from the source pods. |
| `spec.selectors[].namespaceSelector` | object |  | mapType=atomic | Selects Namespaces using cluster-scoped labels. |
| `spec.selectors[].namespaceSelector.*` |  |  |  | → same schema as `spec.egressGateway.nodeSelector` |
| `spec.selectors[].nodeSelector` | object |  | mapType=atomic | This is a label selector which selects Pods by Node. |
| `spec.selectors[].nodeSelector.*` |  |  |  | → same schema as `spec.egressGateway.nodeSelector` |
| `spec.selectors[].podSelector` | object |  | mapType=atomic | This is a label selector which selects Pods. |
| `spec.selectors[].podSelector.*` |  |  |  | → same schema as `spec.egressGateway.nodeSelector` |

### CiliumEnvoyConfig

- **name**: `ciliumenvoyconfigs.cilium.io`  group `cilium.io`  scope **Namespaced**
- **names**: kind `CiliumEnvoyConfig`, plural `ciliumenvoyconfigs`, singular `ciliumenvoyconfig`, shortNames `cec`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object |  |  |  |
| `spec.backendServices` | []object |  |  | BackendServices specifies Kubernetes services whose backends are automatically synced to Envoy using EDS. |
| `spec.backendServices[].name` | string | yes |  | Name is the name of a destination Kubernetes service that identifies traffic to be redirected. |
| `spec.backendServices[].namespace` | string |  |  | Namespace is the Kubernetes service namespace. |
| `spec.backendServices[].number` | []string |  |  | Ports is a set of port numbers, which can be used for filtering in case of underlying is exposing multiple po… |
| `spec.nodeSelector` | object |  | mapType=atomic | NodeSelector is a label selector that determines to which nodes this configuration applies. |
| `spec.nodeSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.nodeSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.nodeSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.nodeSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.nodeSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.resources` | []object | yes |  | Envoy xDS resources, a list of the following Envoy resource types: type.googleapis.com/envoy.config.listener.… |
| `spec.services` | []object |  |  | Services specifies Kubernetes services for which traffic is forwarded to an Envoy listener for L7 load balanc… |
| `spec.services[].listener` | string |  |  | Listener specifies the name of the Envoy listener the service traffic is redirected to. |
| `spec.services[].name` | string | yes |  | Name is the name of a destination Kubernetes service that identifies traffic to be redirected. |
| `spec.services[].namespace` | string |  |  | Namespace is the Kubernetes service namespace. |
| `spec.services[].ports` | []integer |  |  | Ports is a set of service's frontend ports that should be redirected to the Envoy listener. |

### CiliumClusterwideEnvoyConfig

- **name**: `ciliumclusterwideenvoyconfigs.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumClusterwideEnvoyConfig`, plural `ciliumclusterwideenvoyconfigs`, singular `ciliumclusterwideenvoyconfig`, shortNames `ccec`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object |  |  |  |
| `spec.backendServices` | []object |  |  | BackendServices specifies Kubernetes services whose backends are automatically synced to Envoy using EDS. |
| `spec.backendServices[].name` | string | yes |  | Name is the name of a destination Kubernetes service that identifies traffic to be redirected. |
| `spec.backendServices[].namespace` | string |  |  | Namespace is the Kubernetes service namespace. |
| `spec.backendServices[].number` | []string |  |  | Ports is a set of port numbers, which can be used for filtering in case of underlying is exposing multiple po… |
| `spec.nodeSelector` | object |  | mapType=atomic | NodeSelector is a label selector that determines to which nodes this configuration applies. |
| `spec.nodeSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.nodeSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.nodeSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.nodeSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.nodeSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.resources` | []object | yes |  | Envoy xDS resources, a list of the following Envoy resource types: type.googleapis.com/envoy.config.listener.… |
| `spec.services` | []object |  |  | Services specifies Kubernetes services for which traffic is forwarded to an Envoy listener for L7 load balanc… |
| `spec.services[].listener` | string |  |  | Listener specifies the name of the Envoy listener the service traffic is redirected to. |
| `spec.services[].name` | string | yes |  | Name is the name of a destination Kubernetes service that identifies traffic to be redirected. |
| `spec.services[].namespace` | string |  |  | Namespace is the Kubernetes service namespace. |
| `spec.services[].ports` | []integer |  |  | Ports is a set of service's frontend ports that should be redirected to the Envoy listener. |

### CiliumLoadBalancerIPPool

- **name**: `ciliumloadbalancerippools.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumLoadBalancerIPPool`, plural `ciliumloadbalancerippools`, singular `ciliumloadbalancerippool`, shortNames `ippools,ippool,lbippool,lbippools`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Disabled` (boolean, jsonPath `.spec.disabled`); `Conflicting` (string, jsonPath `.status.conditions[?(@.type=="cilium.io/PoolConflict")].status`); `IPs Available` (string, jsonPath `.status.conditions[?(@.type=="cilium.io/IPsAvailable")].message`); `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is a human readable description for a BGP load balancer ip pool. |
| `spec.allowFirstLastIPs` | string |  | enum=Yes/No | AllowFirstLastIPs, if set to `Yes` or undefined means that the first and last IPs of each CIDR will be alloca… |
| `spec.blocks` | []object |  |  | Blocks is a list of CIDRs comprising this IP Pool |
| `spec.blocks[].cidr` | string |  | fmt=cidr |  |
| `spec.blocks[].start` | string |  |  |  |
| `spec.blocks[].stop` | string |  |  |  |
| `spec.disabled` | boolean |  | default=false | Disabled, if set to true means that no new IPs will be allocated from this pool. |
| `spec.serviceSelector` | object |  | mapType=atomic | ServiceSelector selects a set of services which are eligible to receive IPs from this |
| `spec.serviceSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.serviceSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.serviceSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.serviceSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.serviceSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `status` | object |  |  | Status is the status of the IP Pool. |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | Current service state |
| `status.conditions[].lastTransitionTime` | string | yes | fmt=date-time | lastTransitionTime is the last time the condition transitioned from one status to another. |
| `status.conditions[].message` | string | yes | maxLength=32768 | message is a human readable message indicating details about the transition. |
| `status.conditions[].observedGeneration` | integer |  | fmt=int64; minimum=0 | observedGeneration represents the .metadata.generation that the condition was set based upon. |
| `status.conditions[].reason` | string | yes | pattern=`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`; minLength=1; maxLength=1024 | reason contains a programmatic identifier indicating the reason for the condition's last transition. |
| `status.conditions[].status` | string | yes | enum=True/False/Unknown | status of the condition, one of True, False, Unknown. |
| `status.conditions[].type` | string | yes | pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z…`; maxLength=316 | type of condition in CamelCase or in foo.example.com/CamelCase. |

- **version `v2alpha1`**: served=True storage=False deprecated=True subresources=status
  - printer columns: `Disabled` (boolean, jsonPath `.spec.disabled`); `Conflicting` (string, jsonPath `.status.conditions[?(@.type=="cilium.io/PoolConflict")].status`); `IPs Available` (string, jsonPath `.status.conditions[?(@.type=="cilium.io/IPsAvailable")].message`); `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is a human readable description for a BGP load balancer ip pool. |
| `spec.*` |  |  |  | → same schema as `spec` |
| `status` | object |  |  | Status is the status of the IP Pool. |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | Current service state |
| `status.conditions[].*` |  |  |  | → same schema as `status.conditions[]` |

### CiliumL2AnnouncementPolicy

- **name**: `ciliuml2announcementpolicies.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumL2AnnouncementPolicy`, plural `ciliuml2announcementpolicies`, singular `ciliuml2announcementpolicy`, shortNames `l2announcement`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2alpha1`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object |  |  | Spec is a human readable description of a L2 announcement policy |
| `spec.externalIPs` | boolean |  |  | If true, the external IPs of the services are announced |
| `spec.interfaces` | []string |  |  | A list of regular expressions that express which network interface(s) should be used to announce the services… |
| `spec.loadBalancerIPs` | boolean |  |  | If true, the loadbalancer IPs of the services are announced If nil this policy applies to all services. |
| `spec.nodeSelector` | object |  | mapType=atomic | NodeSelector selects a group of nodes which will announce the IPs for the services selected by the service se… |
| `spec.nodeSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.nodeSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.nodeSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.nodeSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.nodeSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.serviceSelector` | object |  | mapType=atomic | ServiceSelector selects a set of services which will be announced over L2 networks. |
| `spec.serviceSelector.*` |  |  |  | → same schema as `spec.nodeSelector` |
| `status` | object |  |  | Status is the status of the policy. |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | Current service state |
| `status.conditions[].lastTransitionTime` | string | yes | fmt=date-time | lastTransitionTime is the last time the condition transitioned from one status to another. |
| `status.conditions[].message` | string | yes | maxLength=32768 | message is a human readable message indicating details about the transition. |
| `status.conditions[].observedGeneration` | integer |  | fmt=int64; minimum=0 | observedGeneration represents the .metadata.generation that the condition was set based upon. |
| `status.conditions[].reason` | string | yes | pattern=`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`; minLength=1; maxLength=1024 | reason contains a programmatic identifier indicating the reason for the condition's last transition. |
| `status.conditions[].status` | string | yes | enum=True/False/Unknown | status of the condition, one of True, False, Unknown. |
| `status.conditions[].type` | string | yes | pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z…`; maxLength=316 | type of condition in CamelCase or in foo.example.com/CamelCase. |

### CiliumPodIPPool

- **name**: `ciliumpodippools.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumPodIPPool`, plural `ciliumpodippools`, singular `ciliumpodippool`, shortNames `cpip`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2alpha1`**: served=True storage=True deprecated=False subresources=none
  - top-level required: spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  |  |
| `spec.allowFirstIP` | boolean |  | default=false; CEL:`self == oldSelf` | AllowFirstIP allows the first IP of each allocated CIDR to be used. |
| `spec.allowLastIP` | boolean |  | default=false; CEL:`self == oldSelf` | AllowLastIP allows the last IP of each allocated CIDR to be used. |
| `spec.ipv4` | object |  |  | IPv4 specifies the IPv4 CIDRs and mask sizes of the pool |
| `spec.ipv4.cidrs` | []string | yes | minItems=1 | CIDRs is a list of IPv4 CIDRs that are part of the pool. |
| `spec.ipv4.maskSize` | integer | yes | minimum=1; maximum=32; CEL:`self == oldSelf` | MaskSize is the mask size of the pool. |
| `spec.ipv6` | object |  |  | IPv6 specifies the IPv6 CIDRs and mask sizes of the pool |
| `spec.ipv6.cidrs` | []string | yes | minItems=1 | CIDRs is a list of IPv6 CIDRs that are part of the pool. |
| `spec.ipv6.maskSize` | integer | yes | minimum=1; maximum=128; CEL:`self == oldSelf` | MaskSize is the mask size of the pool. |
| `spec.namespaceSelector` | object |  | mapType=atomic | NamespaceSelector selects the set of Namespaces that are eligible to use this pool. |
| `spec.namespaceSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.namespaceSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.namespaceSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.namespaceSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.namespaceSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.podSelector` | object |  | mapType=atomic | PodSelector selects the set of Pods that are eligible to receive IPs from this pool when neither the Pod nor … |
| `spec.podSelector.*` |  |  |  | → same schema as `spec.namespaceSelector` |

### CiliumBGPClusterConfig

- **name**: `ciliumbgpclusterconfigs.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumBGPClusterConfig`, plural `ciliumbgpclusterconfigs`, singular `ciliumbgpclusterconfig`, shortNames `cbgpcluster`, categories `cilium,ciliumbgp`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec defines the desired cluster configuration of the BGP control plane. |
| `spec.bgpInstances` | []object | yes | minItems=1; maxItems=16; listType=map; listMapKeys=name | A list of CiliumBGPInstance(s) which instructs the BGP control plane how to instantiate virtual BGP routers. |
| `spec.bgpInstances[].localASN` | integer |  | fmt=int64; minimum=1; maximum=4294967295 | LocalASN is the ASN of this BGP instance. |
| `spec.bgpInstances[].localPort` | integer |  | fmt=int32; minimum=1; maximum=65535 | LocalPort is the port on which the BGP daemon listens for incoming connections. |
| `spec.bgpInstances[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the BGP instance. |
| `spec.bgpInstances[].peers` | []object |  | listType=map; listMapKeys=name | Peers is a list of neighboring BGP peers for this virtual router |
| `spec.bgpInstances[].peers[].autoDiscovery` | object |  |  | AutoDiscovery is the configuration for auto-discovery of the peer address. |
| `spec.bgpInstances[].peers[].autoDiscovery.defaultGateway` | object |  |  | defaultGateway is the configuration for auto-discovery of the default gateway. |
| `spec.bgpInstances[].peers[].autoDiscovery.defaultGateway.addressFamily` | string | yes | enum=ipv4/ipv6 | addressFamily is the address family of the default gateway. |
| `spec.bgpInstances[].peers[].autoDiscovery.mode` | string | yes | enum=DefaultGateway | mode is the mode of the auto-discovery. |
| `spec.bgpInstances[].peers[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the BGP peer. |
| `spec.bgpInstances[].peers[].peerASN` | integer |  | default=0; fmt=int64; minimum=0; maximum=4294967295 | PeerASN is the ASN of the peer BGP router. |
| `spec.bgpInstances[].peers[].peerAddress` | string |  | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | PeerAddress is the IP address of the neighbor. |
| `spec.bgpInstances[].peers[].peerConfigRef` | object |  |  | PeerConfigRef is a reference to a peer configuration resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.name` | string | yes |  | Name is the name of the peer config resource. |
| `spec.nodeSelector` | object |  | mapType=atomic | NodeSelector selects a group of nodes where this BGP Cluster config applies. |
| `spec.nodeSelector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.nodeSelector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.nodeSelector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.nodeSelector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.nodeSelector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `status` | object |  |  | Status is a running status of the cluster configuration |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | The current conditions of the CiliumBGPClusterConfig |
| `status.conditions[].lastTransitionTime` | string | yes | fmt=date-time | lastTransitionTime is the last time the condition transitioned from one status to another. |
| `status.conditions[].message` | string | yes | maxLength=32768 | message is a human readable message indicating details about the transition. |
| `status.conditions[].observedGeneration` | integer |  | fmt=int64; minimum=0 | observedGeneration represents the .metadata.generation that the condition was set based upon. |
| `status.conditions[].reason` | string | yes | pattern=`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`; minLength=1; maxLength=1024 | reason contains a programmatic identifier indicating the reason for the condition's last transition. |
| `status.conditions[].status` | string | yes | enum=True/False/Unknown | status of the condition, one of True, False, Unknown. |
| `status.conditions[].type` | string | yes | pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z…`; maxLength=316 | type of condition in CamelCase or in foo.example.com/CamelCase. |

- **version `v2alpha1`**: served=True storage=False deprecated=True subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec defines the desired cluster configuration of the BGP control plane. |
| `spec.bgpInstances` | []object | yes | minItems=1; maxItems=16; listType=map; listMapKeys=name | A list of CiliumBGPInstance(s) which instructs the BGP control plane how to instantiate virtual BGP routers. |
| `spec.bgpInstances[].localASN` | integer |  | fmt=int64; minimum=1; maximum=4294967295 | LocalASN is the ASN of this BGP instance. |
| `spec.bgpInstances[].localPort` | integer |  | fmt=int32; minimum=1; maximum=65535 | LocalPort is the port on which the BGP daemon listens for incoming connections. |
| `spec.bgpInstances[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the BGP instance. |
| `spec.bgpInstances[].peers` | []object |  | listType=map; listMapKeys=name | Peers is a list of neighboring BGP peers for this virtual router |
| `spec.bgpInstances[].peers[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the BGP peer. |
| `spec.bgpInstances[].peers[].peerASN` | integer |  | default=0; fmt=int64; minimum=0; maximum=4294967295 | PeerASN is the ASN of the peer BGP router. |
| `spec.bgpInstances[].peers[].peerAddress` | string |  | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | PeerAddress is the IP address of the neighbor. |
| `spec.bgpInstances[].peers[].peerConfigRef` | object |  |  | PeerConfigRef is a reference to a peer configuration resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.group` | string |  | default="cilium.io" | Group is the group of the peer config resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.kind` | string |  | default="CiliumBGPPeerConfig" | Kind is the kind of the peer config resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.name` | string | yes |  | Name is the name of the peer config resource. |
| `spec.nodeSelector` | object |  | mapType=atomic | NodeSelector selects a group of nodes where this BGP Cluster config applies. |
| `spec.nodeSelector.*` |  |  |  | → same schema as `spec.nodeSelector` |
| `status` | object |  |  | Status is a running status of the cluster configuration |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | The current conditions of the CiliumBGPClusterConfig |
| `status.conditions[].*` |  |  |  | → same schema as `status.conditions[]` |

### CiliumBGPPeerConfig

- **name**: `ciliumbgppeerconfigs.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumBGPPeerConfig`, plural `ciliumbgppeerconfigs`, singular `ciliumbgppeerconfig`, shortNames `cbgppeer`, categories `cilium,ciliumbgp`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is the specification of the desired behavior of the CiliumBGPPeerConfig. |
| `spec.authSecretRef` | string |  |  | AuthSecretRef is the name of the secret to use to fetch a TCP authentication password for this peer. |
| `spec.ebgpMultihop` | integer |  | default=1; fmt=int32; minimum=1; maximum=255 | EBGPMultihopTTL controls the multi-hop feature for eBGP peers. |
| `spec.families` | []object |  |  | Families, if provided, defines a set of AFI/SAFIs the speaker will negotiate with it's peer. |
| `spec.families[].advertisements` | object |  | mapType=atomic | Advertisements selects group of BGP Advertisement(s) to advertise for this family. |
| `spec.families[].advertisements.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.families[].advertisements.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.families[].advertisements.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.families[].advertisements.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.families[].advertisements.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.families[].afi` | string | yes | enum=ipv4/ipv6/l2vpn/ls/opaque | Afi is the Address Family Identifier (AFI) of the family. |
| `spec.families[].safi` | string | yes | enum=unicast/multicast/mpls_label/encapsulation/vpls/evpn/ls/sr_policy/mup/mpls_vpn/mpls_vpn_multicast/route_target_constraints/flowspec_unicast/flowspec_vpn/key_value | Safi is the Subsequent Address Family Identifier (SAFI) of the family. |
| `spec.gracefulRestart` | object |  |  | GracefulRestart defines graceful restart parameters which are negotiated with this peer. |
| `spec.gracefulRestart.enabled` | boolean | yes |  | Enabled flag, when set enables graceful restart capability. |
| `spec.gracefulRestart.restartTimeSeconds` | integer |  | default=120; fmt=int32; minimum=1; maximum=4095 | RestartTimeSeconds is the estimated time it will take for the BGP session to be re-established with peer afte… |
| `spec.timers` | object |  | CEL:`self.keepAliveTimeSeconds <= self.holdTimeSeconds` | Timers defines the BGP timers for the peer. |
| `spec.timers.connectRetryTimeSeconds` | integer |  | default=120; fmt=int32; minimum=1; maximum=2147483647 | ConnectRetryTimeSeconds defines the initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8). |
| `spec.timers.holdTimeSeconds` | integer |  | default=90; fmt=int32; minimum=3; maximum=65535 | HoldTimeSeconds defines the initial value for the BGP HoldTimer (RFC 4271, Section 4.2). |
| `spec.timers.keepAliveTimeSeconds` | integer |  | default=30; fmt=int32; minimum=1; maximum=65535 | KeepaliveTimeSeconds defines the initial value for the BGP KeepaliveTimer (RFC 4271, Section 8). |
| `spec.transport` | object |  |  | Transport defines the BGP transport parameters for the peer. |
| `spec.transport.peerPort` | integer |  | default=179; fmt=int32; minimum=1; maximum=65535 | PeerPort is the peer port to be used for the BGP session. |
| `spec.transport.sourceInterface` | string |  |  | SourceInterface is the name of a local interface, which IP address will be used as the source IP address for … |
| `status` | object |  |  | Status is the running status of the CiliumBGPPeerConfig |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | The current conditions of the CiliumBGPPeerConfig |
| `status.conditions[].lastTransitionTime` | string | yes | fmt=date-time | lastTransitionTime is the last time the condition transitioned from one status to another. |
| `status.conditions[].message` | string | yes | maxLength=32768 | message is a human readable message indicating details about the transition. |
| `status.conditions[].observedGeneration` | integer |  | fmt=int64; minimum=0 | observedGeneration represents the .metadata.generation that the condition was set based upon. |
| `status.conditions[].reason` | string | yes | pattern=`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`; minLength=1; maxLength=1024 | reason contains a programmatic identifier indicating the reason for the condition's last transition. |
| `status.conditions[].status` | string | yes | enum=True/False/Unknown | status of the condition, one of True, False, Unknown. |
| `status.conditions[].type` | string | yes | pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z…`; maxLength=316 | type of condition in CamelCase or in foo.example.com/CamelCase. |

- **version `v2alpha1`**: served=True storage=False deprecated=True subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is the specification of the desired behavior of the CiliumBGPPeerConfig. |
| `spec.authSecretRef` | string |  |  | AuthSecretRef is the name of the secret to use to fetch a TCP authentication password for this peer. |
| `spec.ebgpMultihop` | integer |  | default=1; fmt=int32; minimum=1; maximum=255 | EBGPMultihopTTL controls the multi-hop feature for eBGP peers. |
| `spec.families` | []object |  |  | Families, if provided, defines a set of AFI/SAFIs the speaker will negotiate with it's peer. |
| `spec.families[].*` |  |  |  | → same schema as `spec.families[]` |
| `spec.gracefulRestart` | object |  |  | GracefulRestart defines graceful restart parameters which are negotiated with this peer. |
| `spec.gracefulRestart.*` |  |  |  | → same schema as `spec.gracefulRestart` |
| `spec.timers` | object |  | CEL:`self.keepAliveTimeSeconds <= self.holdTimeSeconds` | Timers defines the BGP timers for the peer. |
| `spec.timers.*` |  |  |  | → same schema as `spec.timers` |
| `spec.transport` | object |  |  | Transport defines the BGP transport parameters for the peer. |
| `spec.transport.localPort` | integer |  | fmt=int32; minimum=1; maximum=65535 | Deprecated LocalPort is the local port to be used for the BGP session. |
| `spec.transport.peerPort` | integer |  | default=179; fmt=int32; minimum=1; maximum=65535 | PeerPort is the peer port to be used for the BGP session. |
| `status` | object |  |  | Status is the running status of the CiliumBGPPeerConfig |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | The current conditions of the CiliumBGPPeerConfig |
| `status.conditions[].*` |  |  |  | → same schema as `status.conditions[]` |

### CiliumBGPAdvertisement

- **name**: `ciliumbgpadvertisements.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumBGPAdvertisement`, plural `ciliumbgpadvertisements`, singular `ciliumbgpadvertisement`, shortNames `cbgpadvert`, categories `cilium,ciliumbgp`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  |  |
| `spec.advertisements` | []object | yes |  | Advertisements is a list of BGP advertisements. |
| `spec.advertisements[].advertisementType` | string | yes | enum=PodCIDR/CiliumPodIPPool/Service/Interface | AdvertisementType defines type of advertisement which has to be advertised. |
| `spec.advertisements[].attributes` | object |  |  | Attributes defines additional attributes to set to the advertised routes. |
| `spec.advertisements[].attributes.communities` | object |  |  | Communities sets the community attributes in the route. |
| `spec.advertisements[].attributes.communities.large` | []string |  |  | Large holds a list of the BGP Large Communities Attribute (RFC 8092) values. |
| `spec.advertisements[].attributes.communities.standard` | []string |  |  | Standard holds a list of "standard" 32-bit BGP Communities Attribute (RFC 1997) values defined as numeric val… |
| `spec.advertisements[].attributes.communities.wellKnown` | []string |  |  | WellKnown holds a list "standard" 32-bit BGP Communities Attribute (RFC 1997) values defined as well-known st… |
| `spec.advertisements[].attributes.localPreference` | integer |  | fmt=int64 | LocalPreference sets the local preference attribute in the route. |
| `spec.advertisements[].interface` | object |  |  | Interface defines configuration options for the "Interface" advertisementType. |
| `spec.advertisements[].interface.name` | string | yes |  | Name of local interface of whose IP addresses will be advertised via BGP. |
| `spec.advertisements[].selector` | object |  | mapType=atomic | Selector is a label selector to select objects of the type specified by AdvertisementType. |
| `spec.advertisements[].selector.matchExpressions` | []object |  | listType=atomic | matchExpressions is a list of label selector requirements. |
| `spec.advertisements[].selector.matchExpressions[].key` | string | yes |  | key is the label key that the selector applies to. |
| `spec.advertisements[].selector.matchExpressions[].operator` | string | yes | enum=In/NotIn/Exists/DoesNotExist | operator represents a key's relationship to a set of values. |
| `spec.advertisements[].selector.matchExpressions[].values` | []string |  | listType=atomic | values is an array of string values. |
| `spec.advertisements[].selector.matchLabels` | map[string]string |  |  | matchLabels is a map of {key,value} pairs. |
| `spec.advertisements[].service` | object |  |  | Service defines configuration options for the "Service" advertisementType. |
| `spec.advertisements[].service.addresses` | []string | yes | minItems=1 | Addresses is a list of service address types which needs to be advertised via BGP. |
| `spec.advertisements[].service.aggregationLengthIPv4` | integer |  | minimum=0; maximum=31 | IPv4 mask to aggregate BGP route advertisements of service |
| `spec.advertisements[].service.aggregationLengthIPv6` | integer |  | minimum=0; maximum=127 | IPv6 mask to aggregate BGP route advertisements of service |

- **version `v2alpha1`**: served=True storage=False deprecated=True subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  |  |
| `spec.advertisements` | []object | yes |  | Advertisements is a list of BGP advertisements. |
| `spec.advertisements[].advertisementType` | string | yes | enum=PodCIDR/CiliumPodIPPool/Service | AdvertisementType defines type of advertisement which has to be advertised. |
| `spec.advertisements[].attributes` | object |  |  | Attributes defines additional attributes to set to the advertised routes. |
| `spec.advertisements[].attributes.*` |  |  |  | → same schema as `spec.advertisements[].attributes` |
| `spec.advertisements[].selector` | object |  | mapType=atomic | Selector is a label selector to select objects of the type specified by AdvertisementType. |
| `spec.advertisements[].selector.*` |  |  |  | → same schema as `spec.advertisements[].selector` |
| `spec.advertisements[].service` | object |  |  | Service defines configuration options for advertisementType service. |
| `spec.advertisements[].service.*` |  |  |  | → same schema as `spec.advertisements[].service` |

### CiliumBGPNodeConfig

- **name**: `ciliumbgpnodeconfigs.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumBGPNodeConfig`, plural `ciliumbgpnodeconfigs`, singular `ciliumbgpnodeconfig`, shortNames `cbgpnode`, categories `cilium,ciliumbgp`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is the specification of the desired behavior of the CiliumBGPNodeConfig. |
| `spec.bgpInstances` | []object | yes | minItems=1; maxItems=16; listType=map; listMapKeys=name | BGPInstances is a list of BGP router instances on the node. |
| `spec.bgpInstances[].localASN` | integer |  | fmt=int64; minimum=1; maximum=4294967295 | LocalASN is the ASN of this virtual router. |
| `spec.bgpInstances[].localPort` | integer |  | fmt=int32; minimum=1; maximum=65535 | LocalPort is the port on which the BGP daemon listens for incoming connections. |
| `spec.bgpInstances[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the BGP instance. |
| `spec.bgpInstances[].peers` | []object |  | listType=map; listMapKeys=name | Peers is a list of neighboring BGP peers for this virtual router |
| `spec.bgpInstances[].peers[].autoDiscovery` | object |  |  | AutoDiscovery is the configuration for auto-discovery of the peer address. |
| `spec.bgpInstances[].peers[].autoDiscovery.defaultGateway` | object |  |  | defaultGateway is the configuration for auto-discovery of the default gateway. |
| `spec.bgpInstances[].peers[].autoDiscovery.defaultGateway.addressFamily` | string | yes | enum=ipv4/ipv6 | addressFamily is the address family of the default gateway. |
| `spec.bgpInstances[].peers[].autoDiscovery.mode` | string | yes | enum=DefaultGateway | mode is the mode of the auto-discovery. |
| `spec.bgpInstances[].peers[].localAddress` | string |  | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | LocalAddress is the IP address of the local interface to use for the peering session. |
| `spec.bgpInstances[].peers[].name` | string | yes |  | Name is the name of the BGP peer. |
| `spec.bgpInstances[].peers[].peerASN` | integer |  | fmt=int64; minimum=0; maximum=4294967295 | PeerASN is the ASN of the peer BGP router. |
| `spec.bgpInstances[].peers[].peerAddress` | string |  | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | PeerAddress is the IP address of the neighbor. |
| `spec.bgpInstances[].peers[].peerConfigRef` | object |  |  | PeerConfigRef is a reference to a peer configuration resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.name` | string | yes |  | Name is the name of the peer config resource. |
| `spec.bgpInstances[].routerID` | string |  | fmt=ipv4 | RouterID is the BGP router ID of this virtual router. |
| `status` | object |  |  | Status is the most recently observed status of the CiliumBGPNodeConfig. |
| `status.bgpInstances` | []object |  | listType=map; listMapKeys=name | BGPInstances is the status of the BGP instances on the node. |
| `status.bgpInstances[].localASN` | integer |  | fmt=int64 | LocalASN is the ASN of this BGP instance. |
| `status.bgpInstances[].name` | string | yes |  | Name is the name of the BGP instance. |
| `status.bgpInstances[].peers` | []object |  | listType=map; listMapKeys=name | PeerStatuses is the state of the BGP peers for this BGP instance. |
| `status.bgpInstances[].peers[].establishedTime` | string |  |  | EstablishedTime is the time when the peering session was established. |
| `status.bgpInstances[].peers[].name` | string | yes |  | Name is the name of the BGP peer. |
| `status.bgpInstances[].peers[].peerASN` | integer |  | fmt=int64 | PeerASN is the ASN of the neighbor. |
| `status.bgpInstances[].peers[].peerAddress` | string | yes |  | PeerAddress is the IP address of the neighbor. |
| `status.bgpInstances[].peers[].peeringState` | string |  |  | PeeringState is last known state of the peering session. |
| `status.bgpInstances[].peers[].routeCount` | []object |  |  | RouteCount is the number of routes exchanged with this peer per AFI/SAFI. |
| `status.bgpInstances[].peers[].routeCount[].advertised` | integer |  | fmt=int32 | Advertised is the number of routes advertised to this peer. |
| `status.bgpInstances[].peers[].routeCount[].afi` | string | yes | enum=ipv4/ipv6/l2vpn/ls/opaque | Afi is the Address Family Identifier (AFI) of the family. |
| `status.bgpInstances[].peers[].routeCount[].received` | integer |  | fmt=int32 | Received is the number of routes received from this peer. |
| `status.bgpInstances[].peers[].routeCount[].safi` | string | yes | enum=unicast/multicast/mpls_label/encapsulation/vpls/evpn/ls/sr_policy/mup/mpls_vpn/mpls_vpn_multicast/route_target_constraints/flowspec_unicast/flowspec_vpn/key_value | Safi is the Subsequent Address Family Identifier (SAFI) of the family. |
| `status.bgpInstances[].peers[].timers` | object |  |  | Timers is the state of the negotiated BGP timers for this peer. |
| `status.bgpInstances[].peers[].timers.appliedHoldTimeSeconds` | integer |  | fmt=int32 | AppliedHoldTimeSeconds is the negotiated hold time for this peer. |
| `status.bgpInstances[].peers[].timers.appliedKeepaliveSeconds` | integer |  | fmt=int32 | AppliedKeepaliveSeconds is the negotiated keepalive time for this peer. |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | The current conditions of the CiliumBGPNodeConfig |
| `status.conditions[].lastTransitionTime` | string | yes | fmt=date-time | lastTransitionTime is the last time the condition transitioned from one status to another. |
| `status.conditions[].message` | string | yes | maxLength=32768 | message is a human readable message indicating details about the transition. |
| `status.conditions[].observedGeneration` | integer |  | fmt=int64; minimum=0 | observedGeneration represents the .metadata.generation that the condition was set based upon. |
| `status.conditions[].reason` | string | yes | pattern=`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`; minLength=1; maxLength=1024 | reason contains a programmatic identifier indicating the reason for the condition's last transition. |
| `status.conditions[].status` | string | yes | enum=True/False/Unknown | status of the condition, one of True, False, Unknown. |
| `status.conditions[].type` | string | yes | pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z…`; maxLength=316 | type of condition in CamelCase or in foo.example.com/CamelCase. |

- **version `v2alpha1`**: served=True storage=False deprecated=True subresources=status
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is the specification of the desired behavior of the CiliumBGPNodeConfig. |
| `spec.bgpInstances` | []object | yes | minItems=1; maxItems=16; listType=map; listMapKeys=name | BGPInstances is a list of BGP router instances on the node. |
| `spec.bgpInstances[].localASN` | integer |  | fmt=int64; minimum=1; maximum=4294967295 | LocalASN is the ASN of this virtual router. |
| `spec.bgpInstances[].localPort` | integer |  | fmt=int32; minimum=1; maximum=65535 | LocalPort is the port on which the BGP daemon listens for incoming connections. |
| `spec.bgpInstances[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the BGP instance. |
| `spec.bgpInstances[].peers` | []object |  | listType=map; listMapKeys=name | Peers is a list of neighboring BGP peers for this virtual router |
| `spec.bgpInstances[].peers[].localAddress` | string |  | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | LocalAddress is the IP address of the local interface to use for the peering session. |
| `spec.bgpInstances[].peers[].name` | string | yes |  | Name is the name of the BGP peer. |
| `spec.bgpInstances[].peers[].peerASN` | integer |  | fmt=int64; minimum=0; maximum=4294967295 | PeerASN is the ASN of the peer BGP router. |
| `spec.bgpInstances[].peers[].peerAddress` | string |  | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | PeerAddress is the IP address of the neighbor. |
| `spec.bgpInstances[].peers[].peerConfigRef` | object |  |  | PeerConfigRef is a reference to a peer configuration resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.group` | string |  | default="cilium.io" | Group is the group of the peer config resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.kind` | string |  | default="CiliumBGPPeerConfig" | Kind is the kind of the peer config resource. |
| `spec.bgpInstances[].peers[].peerConfigRef.name` | string | yes |  | Name is the name of the peer config resource. |
| `spec.bgpInstances[].routerID` | string |  | fmt=ipv4 | RouterID is the BGP router ID of this virtual router. |
| `status` | object |  |  | Status is the most recently observed status of the CiliumBGPNodeConfig. |
| `status.*` |  |  |  | → same schema as `status` |

### CiliumBGPNodeConfigOverride

- **name**: `ciliumbgpnodeconfigoverrides.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumBGPNodeConfigOverride`, plural `ciliumbgpnodeconfigoverrides`, singular `ciliumbgpnodeconfigoverride`, shortNames `cbgpnodeoverride`, categories `cilium,ciliumbgp`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2`**: served=True storage=True deprecated=False subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is the specification of the desired behavior of the CiliumBGPNodeConfigOverride. |
| `spec.bgpInstances` | []object | yes | minItems=1; listType=map; listMapKeys=name | BGPInstances is a list of BGP instances to override. |
| `spec.bgpInstances[].localASN` | integer |  | fmt=int64; minimum=1; maximum=4294967295 | LocalASN is the ASN to use for this BGP instance. |
| `spec.bgpInstances[].localPort` | integer |  | fmt=int32 | LocalPort is port to use for this BGP instance. |
| `spec.bgpInstances[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the BGP instance for which the configuration is overridden. |
| `spec.bgpInstances[].peers` | []object |  | listType=map; listMapKeys=name | Peers is a list of peer configurations to override. |
| `spec.bgpInstances[].peers[].localAddress` | string |  | pattern=`((^\s*((([0-9]\|[1-9][0-9]\|1[0-9]{2}\|2[0-4][0-9]\|25[0-5])\…` | LocalAddress is the IP address to use for connecting to this peer. |
| `spec.bgpInstances[].peers[].localPort` | integer |  | fmt=int32 | LocalPort is source port to use for connecting to this peer. |
| `spec.bgpInstances[].peers[].name` | string | yes | minLength=1; maxLength=255 | Name is the name of the peer for which the configuration is overridden. |
| `spec.bgpInstances[].routerID` | string |  | fmt=ipv4 | RouterID is BGP router id to use for this instance. |

- **version `v2alpha1`**: served=True storage=False deprecated=True subresources=none
  - printer columns: `Age` (date, jsonPath `.metadata.creationTimestamp`)
  - top-level required: metadata,spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  | Spec is the specification of the desired behavior of the CiliumBGPNodeConfigOverride. |
| `spec.bgpInstances` | []object | yes | minItems=1; listType=map; listMapKeys=name | BGPInstances is a list of BGP instances to override. |
| `spec.bgpInstances[].*` |  |  |  | → same schema as `spec.bgpInstances[]` |

### CiliumGatewayClassConfig

- **name**: `ciliumgatewayclassconfigs.cilium.io`  group `cilium.io`  scope **Namespaced**
- **names**: kind `CiliumGatewayClassConfig`, plural `ciliumgatewayclassconfigs`, singular `ciliumgatewayclassconfig`, shortNames `cgcc`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2alpha1`**: served=True storage=True deprecated=False subresources=status
  - printer columns: `Accepted` (string, jsonPath `.status.conditions[?(@.type=="Accepted")].status`); `Age` (date, jsonPath `.metadata.creationTimestamp`); `Description` (string, jsonPath `.spec.description`, priority=1)
  - top-level required: metadata

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object |  |  | Spec is a human-readable of a GatewayClass configuration. |
| `spec.description` | string |  | maxLength=64 | Description helps describe a GatewayClass configuration with more details. |
| `spec.envoy` | object |  |  | Envoy specifies proxy configuration options. |
| `spec.envoy.serverHeaderTransformation` | string |  | default="OVERWRITE"; enum=OVERWRITE/APPEND_IF_ABSENT/PASS_THROUGH | ServerHeaderTransformation controls the HTTP "Server" response header. |
| `spec.httpOptions` | object |  |  | HTTPOptions specifies HTTP connection manager options. |
| `spec.httpOptions.grpcWebTranslation` | object |  |  | GRPCWebTranslation controls Envoy's gRPC-web to gRPC request translation. |
| `spec.httpOptions.grpcWebTranslation.enabled` | boolean |  | default=true | Enabled controls Envoy's gRPC-web to gRPC request translation. |
| `spec.service` | object |  |  | Service specifies the configuration for the generated Service. |
| `spec.service.allocateLoadBalancerNodePorts` | boolean |  |  | Sets the Service.Spec.AllocateLoadBalancerNodePorts in generated Service objects to the given value. |
| `spec.service.externalTrafficPolicy` | string |  | default="Cluster" | Sets the Service.Spec.ExternalTrafficPolicy in generated Service objects to the given value. |
| `spec.service.ipFamilies` | []string |  | listType=atomic | Sets the Service.Spec.IPFamilies in generated Service objects to the given value. |
| `spec.service.ipFamilyPolicy` | string |  |  | Sets the Service.Spec.IPFamilyPolicy in generated Service objects to the given value. |
| `spec.service.loadBalancerClass` | string |  |  | Sets the Service.Spec.LoadBalancerClass in generated Service objects to the given value. |
| `spec.service.loadBalancerSourceRanges` | []string |  | listType=atomic | Sets the Service.Spec.LoadBalancerSourceRanges in generated Service objects to the given value. |
| `spec.service.loadBalancerSourceRangesPolicy` | string |  | default="Allow"; enum=Allow/Deny | LoadBalancerSourceRangesPolicy defines the policy for the LoadBalancerSourceRanges if the incoming traffic is… |
| `spec.service.trafficDistribution` | string |  |  | Sets the Service.Spec.TrafficDistribution in generated Service objects to the given value. |
| `spec.service.type` | string |  | default="LoadBalancer"; enum=LoadBalancer/NodePort | Sets the Service.Spec.Type in generated Service objects to the given value. |
| `spec.telemetry` | object |  |  | Telemetry specifies observability options for Gateways using this GatewayClass configuration. |
| `spec.telemetry.accessLogs` | []object |  | minItems=1; maxItems=8 | AccessLogs configures Envoy access logging for generated Gateway listeners. |
| `spec.telemetry.accessLogs[].format` | string | yes | enum=JSON/Text | Format specifies the access log output format. |
| `spec.telemetry.accessLogs[].json` | map[string]string |  | default={"authority": "%REQUEST_HEADER(:AUTHORITY)%", "bytes_received": "%BYTES_RECEIVED%", "bytes_sent": "%BYTES_SENT%", "duration": "%DURATION%", "method": "%REQUEST_HEADER(:METHOD)%", "path": "%REQUEST_HEADER(X-ENVOY-ORIGINAL-PATH?:PATH)%", "protocol": "%PROTOCOL%", "request_id": "%REQUEST_HEADER(X-REQUEST-ID)%", "response_code": "%RESPONSE_CODE%", "response_flags": "%RESPONSE_FLAGS%", "start_time": "%START_TIME%", "upstream_host": "%UPSTREAM_HOST%", "upstream_service_time": "%RESPONSE_HEADER(X-ENVOY-UPSTREAM-SERVICE-TIME)%", "user_agent": "%REQUEST_HEADER(USER-AGENT)%", "x_forwarded_for": "%REQUEST_HEADER(X-FORWARDED-FOR)%"}; minProperties=1; maxProperties=64 | JSON maps access log field names to Envoy command operators. |
| `spec.telemetry.accessLogs[].targets` | []string |  | default=["HTTP"]; minItems=1; listType=set | Targets specifies the generated Envoy proxy components where access logs are emitted. |
| `spec.telemetry.accessLogs[].text` | string |  | default="[%START_TIME%] \"%REQUEST_HEADER(:METHOD)% %REQUEST_HEADER(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESPONSE_HEADER(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQUEST_HEADER(X-FORWARDED-FOR)%\" \"%REQUEST_HEADER(USER-AGENT)%\" \"%REQUEST_HEADER(X-REQUEST-ID)%\" \"%REQUEST_HEADER(:AUTHORITY)%\" \"%UPSTREAM_HOST%\""; minLength=1; maxLength=4096 | Text specifies the Envoy access log format string. |
| `status` | object |  |  | Status is the status of the policy. |
| `status.conditions` | []object |  | listType=map; listMapKeys=type | Current service state |
| `status.conditions[].lastTransitionTime` | string | yes | fmt=date-time | lastTransitionTime is the last time the condition transitioned from one status to another. |
| `status.conditions[].message` | string | yes | maxLength=32768 | message is a human readable message indicating details about the transition. |
| `status.conditions[].observedGeneration` | integer |  | fmt=int64; minimum=0 | observedGeneration represents the .metadata.generation that the condition was set based upon. |
| `status.conditions[].reason` | string | yes | pattern=`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`; minLength=1; maxLength=1024 | reason contains a programmatic identifier indicating the reason for the condition's last transition. |
| `status.conditions[].status` | string | yes | enum=True/False/Unknown | status of the condition, one of True, False, Unknown. |
| `status.conditions[].type` | string | yes | pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z…`; maxLength=316 | type of condition in CamelCase or in foo.example.com/CamelCase. |

### CiliumDatapathPlugin

- **name**: `ciliumdatapathplugins.cilium.io`  group `cilium.io`  scope **Cluster**
- **names**: kind `CiliumDatapathPlugin`, plural `ciliumdatapathplugins`, singular `ciliumdatapathplugin`, shortNames `cddp`, categories `cilium`
- **annotations**: `controller-gen.kubebuilder.io/version=v0.20.1`
- **version `v2alpha1`**: served=True storage=True deprecated=True subresources=none
  - top-level required: spec

| Field | Type | Req | Constraints | Meaning |
|---|---|---|---|---|
| `spec` | object | yes |  |  |
| `spec.attachmentPolicy` | string | yes | enum=Always/BestEffort | AttachmentPolicy dictates how Cilium behaves when it cannot talk to a plugin. |
| `spec.version` | string | yes |  | Version is an opaque string used to indicate the datapath plugin version. |


### Slim k8s types — the exact subset flowsdn must deserialise

`pkg/k8s/slim/k8s/api/*/types.go` (protobuf-encoded on the wire, so unknown fields are dropped by the decoder, not rejected). Every struct below embeds slim `TypeMeta` (`kind`, `apiVersion`) and slim `ObjectMeta`.

| Slim type | Fields kept (JSON names) |
|---|---|
| `meta/v1.ObjectMeta` | `name`, `generateName`, `namespace`, `uid`, `resourceVersion`, `generation`, `deletionTimestamp`, `labels`, `annotations`, `ownerReferences[]{apiVersion,kind,name,uid,controller}` — **no** `creationTimestamp`, `finalizers`, `managedFields`, `deletionGracePeriodSeconds` |
| `meta/v1.ListMeta` | `resourceVersion`, `continue`, `remainingItemCount` |
| `meta/v1.LabelSelector` | `matchLabels` (map), `matchExpressions[]{key,operator,values}` |
| `meta/v1.Condition` | `type`, `status`, `observedGeneration`, `lastTransitionTime`, `reason`, `message` |
| `meta/v1.PartialObjectMetadata(List)` | TypeMeta + ObjectMeta (used for CRD presence watch) |
| `core/v1.Pod` | `spec{initContainers[],containers[]{name,image,ports[]{name,hostPort,containerPort,protocol,hostIP},volumeMounts[]{mountPath}},serviceAccountName,nodeName,hostNetwork}`, `status{phase,conditions[]{type,status,lastProbeTime,lastTransitionTime,reason,message},hostIP,podIP,podIPs[]{ip},startTime,containerStatuses[]{state{running{startedAt}},containerID},qosClass}` |
| `core/v1.Service` | `spec{ports[]{name,protocol,appProtocol,port,targetPort(int-or-string),nodePort},selector,clusterIP,clusterIPs,type,externalIPs,sessionAffinity,loadBalancerIP,loadBalancerSourceRanges,externalTrafficPolicy,healthCheckNodePort,sessionAffinityConfig{clientIP{timeoutSeconds}},ipFamilies,ipFamilyPolicy,loadBalancerClass,internalTrafficPolicy,trafficDistribution}`, `status{loadBalancer{ingress[]{ip,hostname,ipMode,ports[]{port,protocol,error}}},conditions[]}` |
| `core/v1.Node` | `spec{podCIDR,podCIDRs,providerID,taints[]{key,value,effect,timeAdded}}`, `status{conditions[]{type,status,reason},addresses[]{type,address}}` |
| `core/v1.Namespace` | metadata only (no spec/status) |
| `core/v1.Secret` | `immutable`, `data` (map of bytes), `stringData`, `type` |
| `core/v1.TypedLocalObjectReference` | `apiGroup`, `kind`, `name` |
| `discovery/v1.EndpointSlice` | `addressType`, `endpoints[]{addresses,conditions{ready,serving,terminating},hostname,deprecatedTopology,nodeName,zone,hints{forZones[]{name}}}`, `ports[]{name,protocol,port,appProtocol}`; label `kubernetes.io/service-name` is read from metadata |
| `networking/v1.NetworkPolicy` | `spec{podSelector,ingress[]{ports[]{protocol,port,endPort},from[]},egress[]{ports[],to[]},policyTypes}`; peer = `{podSelector,namespaceSelector,ipBlock{cidr,except}}` |
| `types.CiliumEndpoint` (internal) | ObjectMeta + `Identity{id,labels}`, `Networking{addressing[],node}`, `Encryption{key}`, `NamedPorts`, `ServiceAccount` — produced from the full CEP by `TransformToCiliumEndpoint` |

Full (non-slim) Go types are used for every `cilium.io` CRD, for `apiextensions.k8s.io/v1 CRD` (operator), `coordination.k8s.io/v1 Lease`, `core/v1 ConfigMap` (config sources, secretsync), `core/v1 Event` (Hubble drop emitter), Gateway API, MCS-API and network-policy-api types.

### Annotations Cilium honours (`pkg/annotation/k8s.go`, `clustermesh.go`)

| Key (alias) | On | Meaning |
|---|---|---|
| `policy.cilium.io/name` (`io.cilium.name`) | NetworkPolicy | name of policy node all rules apply to (legacy) |
| `policy.cilium.io/no-track-port` (`io.cilium.no-track-port`) | Pod | port(s) to bypass conntrack (NodeLocalDNS) |
| `network.cilium.io/no-track-host-ports` | Pod/Node | host ports to bypass conntrack |
| `network.cilium.io/ipv4-pod-cidr` / `ipv6-pod-cidr` (`io.cilium.network.*`) | Node | pod CIDR written/read by agent |
| `network.cilium.io/ipv4-cilium-host` / `ipv6-cilium-host` | Node | `cilium_host` router IP |
| `network.cilium.io/ipv4-health-ip` / `ipv6-health-ip` | Node | cilium-health endpoint IP |
| `network.cilium.io/ipv4-Ingress-ip` / `ipv6-Ingress-ip` | Node | Ingress listener IP |
| `network.cilium.io/encryption-key` | Node | IPsec key index |
| `network.cilium.io/wg-pub-key` | CiliumNode | WireGuard public key |
| `network.cilium.io/fib-table-id` | Pod/Namespace | FIB table for egress routing |
| `config.cilium.io/delegate-source-ip-verification` | Namespace | admin gate allowing pods to opt out of source-IP verification |
| `config.cilium.io/disable-source-ip-verification` | Pod | disable source-IP verification (only if namespace delegates) |
| `config.cilium.io/<option>` | Node (label or annotation) | per-node agent option override via `--config-sources kind=node` |
| `cni.cilium.io/mac-address` | Pod | MAC assigned to pod (written by CNI) |
| `service.cilium.io/global` (`io.cilium/global-service`) | Service | ClusterMesh global service |
| `service.cilium.io/shared` (`io.cilium/shared-service`) | Service | share local backends (default true if global) |
| `service.cilium.io/affinity` (`io.cilium/service-affinity`) | Service | `local`/`remote`/`none` |
| `service.cilium.io/global-sync-endpoint-slices` | Service | mirror remote EndpointSlices into local API |
| `service.cilium.io/lb-algorithm` | Service | `random`/`maglev` override |
| `service.cilium.io/weight` | EndpointSlice | LB weight for all backends in the slice (0 = maintenance) |
| `service.cilium.io/node` | Service | expose only on nodes whose label `service.cilium.io/node` matches |
| `service.cilium.io/node-selector` | Service | expose only on nodes matching selector |
| `service.cilium.io/type` | Service | provision only `ClusterIP`/`NodePort`/`LoadBalancer` |
| `service.cilium.io/src-ranges-policy` | Service | `allow`/`deny` semantics for `loadBalancerSourceRanges` |
| `service.cilium.io/proxy-delegation` | Service | `none`/`delegate-if-local` |
| `service.cilium.io/forwarding-mode` | Service | `dsr`/`snat` |
| `service.cilium.io/lb-l7` | Service | L7 LB via Envoy (Ingress/Gateway) |
| `ipam.cilium.io/ip-pool`, `ipv4-pool`, `ipv6-pool` | Pod/Namespace | multi-pool IPAM pool selection |
| `ipam.cilium.io/ignore` | CiliumNode | operator IPAM ignores this node |
| `ipam.cilium.io/require-pool-match` | Pod/Namespace | no fallback to default pool |
| `ipam.cilium.io/skip-masquerade` | CiliumPodIPPool | do not masquerade this pool in tunnel mode |
| `lbipam.cilium.io/ips` (`io.cilium/lb-ipam-ips`) | Service | requested LB IPs |
| `lbipam.cilium.io/sharing-key` (`io.cilium/lb-ipam-sharing-key`) | Service | share one LB IP |
| `lbipam.cilium.io/sharing-cross-namespace` (`io.cilium/lb-ipam-sharing-cross-namespace`) | Service | allow sharing across namespaces |
| `cec.cilium.io/inject-cilium-filters`, `cec.cilium.io/is-l7lb`, `cec.cilium.io/use-original-source-address` | CiliumEnvoyConfig | Envoy listener behaviour |
| `cilium.io/bgp-virtual-router.<asn>` | Node | legacy BGP virtual router annotation |
| `clustermesh.cilium.io/global` | Namespace | export namespace (MCS-API) |
| `clustermesh.cilium.io/supported-ip-families`, `clustermesh.cilium.io/autoPatchedAt` | Service / CoreDNS Deployment | MCS-API internals |
| `ingress.cilium.io/loadbalancer-mode`, `tls-passthrough`, `host-listener-port`, `force-https`, `service-external-traffic-policy`, `loadbalancer-class`, `service-type`, `secure-node-port`, `insecure-node-port` | Ingress | Ingress controller knobs |
| `io.cilium.heartbeat` | CiliumIdentity | GC heartbeat timestamp |
| `io.cilium.fixed-identity` | Pod (label) | pin a well-known identity |
| `secretsync.cilium.io/*`, `mesh.cilium.io/*`, `gateway.cilium.io/*`, `io.cilium.gateway/owning-gateway` | operator internals | ownership bookkeeping |

`annotation.CiliumPrefixRegex = ^([A-Za-z0-9]+\.)*cilium.io/` — every Node annotation matching it is copied into the internal node object.

### Labels Cilium reads or synthesises

- Identity labels (source `k8s:`): pod labels after `SanitizePodLabels` + `labelsfilter` (see Features); `io.kubernetes.pod.namespace`, `io.cilium.k8s.namespace.labels.<key>` (note `io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name` is the reliable namespace selector), `io.cilium.k8s.policy.serviceaccount`, `io.cilium.k8s.policy.cluster`, `io.cilium.k8s.named-ports`. Node identity labels via `--node-labels`.
- Selector translation in policy: `k8s:io.kubernetes.pod.namespace`, `k8s:io.cilium.k8s.namespace.labels.*`, `k8s:io.cilium.k8s.policy.cluster` are injected into `EndpointSelector`s by the policy importer.
- Policy metadata labels: `io.cilium.k8s.policy.{name,uid,namespace,derived-from}`.
- CiliumIdentity object labels: `io.kubernetes.pod.namespace` (printer column). Note the CRD requires `security-labels` — a map keyed by the *full* label string e.g. `k8s:app=foo`.
- Service/EndpointSlice watch selectors: `service.kubernetes.io/service-proxy-name`, `service.kubernetes.io/headless`, `endpointslice.kubernetes.io/managed-by`, `kubernetes.io/service-name`.
- Node taints: `node.cilium.io/agent-not-ready` (key configurable).
- Operator pod watch: cilium pods by namespace + Helm label selector; unmanaged pod restarter `--pod-restart-selector` (default `k8s-app=kube-dns`) with `fieldSelector status.phase=Running`.

## External interfaces

### API server requests by resource (agent)

| Resource (GVR) | Client | List/Watch options | Verbs used | Drives |
|---|---|---|---|---|
| `core/v1 pods` | slim (protobuf) | `fieldSelector=spec.nodeName=<node>` | list, watch (+ get/patch of CEP owner in `pod.go`) | StateDB `k8s-pods`; endpoint creation/labels, host-port, named ports |
| `core/v1 namespaces` | slim | none | list, watch | StateDB `k8s-namespaces`; namespace labels in identities |
| `core/v1 nodes` | slim | none | list, watch; `patch nodes/status` (annotateK8sNode) | node manager, PodCIDR, node labels/annotations |
| `core/v1 services` | slim | label selector (proxy-name/headless) | list, watch | load balancer tables |
| `discovery.k8s.io/v1 endpointslices` | slim | same label selector + `managed-by!=endpointslice-mesh-controller.cilium.io` | list, watch | backends |
| `networking.k8s.io/v1 networkpolicies` | slim | none | list, watch | policy repo |
| `policy.networking.k8s.io/v1alpha2 clusternetworkpolicies` | typed | none | list, watch (opt-in) | policy repo |
| `core/v1 secrets` | typed | direct GET by ns/name | get (and list/watch unless restricted) | TLS/header-match secrets for L7 policy |
| `core/v1 configmaps` | typed | GET | get | `--config-sources` |
| `apiextensions.k8s.io/v1 customresourcedefinitions` | apiext | `Accept: …as=PartialObjectMetadataList` | list, watch, get | CRD readiness gate |
| `coordination.k8s.io/v1 leases` | typed | – | create, get, update, list, delete | L2 announcements |
| `cilium.io/v2 ciliumnodes` | cilium (JSON) | none | list, watch, create, update, get, `update ciliumnodes/status` | node/IPAM |
| `cilium.io/v2 ciliumendpoints` | cilium | none, lazy-transformed to slim, indexed by namespace + `localNode` | list, watch, create, get, patch (JSON), delete | ipcache remote endpoints; own CEP |
| `cilium.io/v2alpha1 ciliumendpointslices` | cilium | none | list, watch | ipcache (when CES enabled) |
| `cilium.io/v2 ciliumidentities` | cilium | none, indexed by label key | list, watch, create, update | identity allocator (CRD mode) |
| `cilium.io/v2 ciliumnetworkpolicies` / `ciliumclusterwidenetworkpolicies` / `ciliumcidrgroups` | cilium | none | list, watch | policy repo |
| `cilium.io/v2 ciliumegressgatewaypolicies`, `ciliumlocalredirectpolicies`, `ciliumenvoyconfigs`, `ciliumclusterwideenvoyconfigs`, `ciliumloadbalancerippools`, `ciliumbgp{nodeconfigs,advertisements,peerconfigs}`, `ciliumnodeconfigs` | cilium | none | list, watch; `patch ciliumbgpnodeconfigs/status`, `patch ciliuml2announcementpolicies/status` | respective feature |
| `cilium.io/v2alpha1 ciliumpodippools`, `ciliuml2announcementpolicies`, `ciliumdatapathplugins` | cilium | none | list, watch | IPAM, L2, plugins |
| `/readyz`, `/version` | core REST | – | get | heartbeat, version detection |
| `core/v1 events` | typed | – | create, patch (Hubble drop emitter, optional) | – |

### Operator additional requests

`pods` (all nodes; delete for unmanaged kube-dns restart), `nodes` (list/watch; `patch nodes`, `patch nodes/status`), `configmaps/cilium-config` (patch), `services` (get/list/watch; create/update/patch/delete for Ingress/Gateway/MCS), `services/status` (update/patch for LB IPAM), `services/finalizers`, `endpointslices` (full CRUD + deletecollection for ClusterMesh mirroring/Gateway), `namespaces`, `secrets`, `serviceaccounts`, `customresourcedefinitions` (create/get/list/watch; update restricted by `resourceNames` to the 22 Cilium CRDs + MCS-API; `update customresourcedefinitions/status` for the BGP CRDs), `leases` (create/get/update), CNP/CCNP (full CRUD + `*/status` patch/update), `ciliumendpoints`+`ciliumidentities` (delete/list/watch; identities update/create), `ciliumnodes` (create/update/get/list/watch/delete + `status` update), `ciliumendpointslices` (CRUD + deletecollection), `ciliumenvoyconfigs`, BGP CRDs (CRUD + status update), `ciliumcidrgroups` (CRUD), `ciliumloadbalancerippools`/`ciliumpodippools`/`ciliumbgppeerconfigs`/`ciliumdatapathplugins` (get/list/watch; `create ciliumpodippools`; `patch ciliumloadbalancerippools/status`), `ciliumgatewayclassconfigs` (+status), Gateway API kinds (+status), `ingresses`/`ingressclasses` (+`ingresses/status`, `ingresses/finalizers`), MCS-API `serviceimports`/`serviceexports` (+status/finalizers), `events` (ClusterMesh EndpointSlice sync).

### RBAC (verbatim from Helm templates, defaults)

Agent ClusterRole: `networking.k8s.io/networkpolicies` get,list,watch; `discovery.k8s.io/endpointslices` get,list,watch; `""/namespaces,services,pods,nodes[,secrets]` get,list,watch; `""/nodes/status` patch (if `annotateK8sNode`); `""/events` create,patch (Hubble drop emitter); `coordination.k8s.io/leases` create,get,update,list,delete (L2); `apiextensions.k8s.io/customresourcedefinitions` list,watch,get; `cilium.io/{ciliumloadbalancerippools, ciliumbgpnodeconfigs, ciliumbgpadvertisements, ciliumbgppeerconfigs, ciliumclusterwideenvoyconfigs, ciliumclusterwidenetworkpolicies, ciliumegressgatewaypolicies, ciliumendpoints, ciliumendpointslices, ciliumenvoyconfigs, ciliumidentities, ciliumlocalredirectpolicies, ciliumnetworkpolicies, ciliumnodes, ciliumnodeconfigs, ciliumcidrgroups, ciliuml2announcementpolicies, ciliumpodippools, ciliumdatapathplugins}` list,watch; `ciliumidentities,ciliumendpoints,ciliumnodes` create; `ciliumidentities` update; `ciliumendpoints` delete,get; `ciliumnodes,ciliumnodes/status` get,update; `ciliumendpoints/status,ciliumendpoints,ciliuml2announcementpolicies/status,ciliumbgpnodeconfigs/status` patch; `policy.networking.k8s.io/clusternetworkpolicies` get,list,watch (if enabled).

Operator ClusterRole: see "Operator additional requests" above — every verb there is granted in `cilium-operator/clusterrole.yaml` (484 lines, heavily templated on Helm feature flags).

### Wire/protocol details relied upon

- HTTP/2 to the API server (client-go default; `DISABLE_HTTP2` env honoured), connection rotation dialer (`connrotation`), `SO_MARK` on API-server sockets when host-firewall bypass is enabled.
- **Protobuf** (`application/vnd.kubernetes.protobuf`) for all built-in types including `PartialObjectMetadata` fallback list; **JSON** for `cilium.io`, Gateway API, MCS-API.
- **Field selectors**: `spec.nodeName=` (pods), `status.phase=Running` (operator), `metadata.name=` (CRD sync helper). **Label selectors** with `DoesNotExist`, `==`, `!=` operators.
- **Patch types**: JSON Patch (`application/json-patch+json`) for CEP status, node taints, LB-IPAM pool status, L2 policy status, BGP node status; Strategic Merge Patch (`application/strategic-merge-patch+json`) on `nodes/status` (annotations, conditions); Merge Patch (`application/merge-patch+json`) in operator BGP manager. **No server-side apply** (`FieldManager` is set on some Create/Update/Patch calls for attribution only; no `Apply` calls).
- **Status subresource** `UpdateStatus` on CiliumNode, CNP/CCNP, BGP cluster/peer configs; CEP has no status subresource (whole-object JSON patch).
- **Watch semantics**: standard list-then-watch with `resourceVersion` continuation and 410 Gone relist (client-go reflector); watch **bookmarks are requested by client-go** (`AllowWatchBookmarks=true` default) but Cilium code never depends on them; `SendInitialEvents`/WatchList is **not** used; list paging (`limit/continue`) is client-go default (500) — the slim `ListMeta` carries `continue`/`remainingItemCount` for this.
- **Discovery**: only `GET /version` (`ServerVersion()`); `--enable-k8s-api-discovery` exists but no code path consults `/apis` in 1.20. Minimum accepted server version 1.21.0 (only recorded as a capability flag).
- **CRD API**: `apiextensions.k8s.io/v1` with `Established` condition polling; printer columns, `x-kubernetes-validations` (CEL), `x-kubernetes-list-type/map-keys`, `x-kubernetes-int-or-string`, `x-kubernetes-preserve-unknown-fields` (CEC `spec.resources[]`), `default:` values, `format: cidr|ipv4|idn-hostname|date-time`, `oneOf/anyOf` in schemas — the API server must implement structural-schema validation, defaulting and CEL for the contract to hold.
- **Leases** (`coordination.k8s.io/v1`) for operator leader election and L2 announcements.
- **OwnerReferences / garbage collection**: CEP owned by Pod (kube GC deletes CEP when pod goes; operator GC is the fallback), CES managed by operator, secretsync ownership via labels.
- **Files on disk**: `/tmp/cilium/config-map/*` (or `--config-dir`) written by `option/resolver` from config sources; kubeconfig path; CNI conf written when ready.

## Dependencies

- Inventory areas: policy (consumes CNP/CCNP/CCG/NetworkPolicy resources and identity labels), ipam (CiliumNode/CiliumPodIPPool), loadbalancer (Service/EndpointSlice/LRP/LB-IPAM/L2), bgp, envoy/CEC, clustermesh (kvstore-backed peers share the same slim types and CiliumNode/CiliumIdentity/CiliumEndpoint wire formats), identity allocator (kvstore vs CRD backend), node discovery, endpoint manager (CEP writer), hubble (workload metadata).
- Go libraries: `k8s.io/{api,apimachinery,client-go} v0.36.3`, `sigs.k8s.io/controller-runtime v0.24.1` (operator only), `sigs.k8s.io/gateway-api v1.6.1`, `sigs.k8s.io/mcs-api v0.5.2`, `sigs.k8s.io/network-policy-api v0.2.0`, `cilium/hive` + `cilium/statedb` (reflectors), `cilium/stream`.
- External services: the Kubernetes API server only (etcd is indirect). No cloud APIs here (ENI/Azure fields in CiliumNode are filled by the ipam area).

## Kernel / platform requirements

None (pure control-plane). `hostfirewallbypass` sets `SO_MARK` on outgoing sockets (needs `CAP_NET_ADMIN`, already held).

## Tests

- Unit: 33 `_test.go` files, 15,351 lines under `pkg/k8s/` — CNP/CCNP parsing (`network_policy_test.go`, `cluster_network_policy_test.go`), EndpointSlice→backends (`endpoints_test.go` incl. terminating/serving/zone hints/weight), Node parsing (`node_test.go`), label synthesis (`labels_test.go`), `resource_test.go`/`statedb_test.go` (event ordering, retries, rate limits, transforms), `synced/resources_test.go`, `factory_functions_test.go` (equality/conversion), `apis/register_test.go`, `v2/types_test.go`, `v2/fuzz_test.go`, `cec_types_test.go`, `client_test.go`, `identitybackend` tests, `annotation/*_test.go`, slim `labels` selector tests (1,459 lines of vendored selector code).
- Script tests (`hive/script` txtar with the fake API server `pkg/k8s/client/testutils/object_tracker.go`, which implements field/label selectors, watch bookmarks and `SendInitialEvents`): `pkg/k8s/tables/testdata/{pod,namespace}.txtar`, `operator/watchers/testdata`, plus dozens more across loadbalancer/policy/bgp areas that exercise these watchers.
- Control-plane integration tests `test/controlplane/` ("k8s objects in, datapath state out"; fixtures captured from k8s v1.24–v1.26 clusters).
- CI: kind on `quay.io/cilium/kindest-node:v1.36.0`; `conformance-k8s-network-policies.yaml` (upstream NetworkPolicy conformance), `conformance-gateway-api.yaml`, `conformance-ingress.yaml`, `conformance-mcs-api.yaml`, `conformance-clustermesh.yaml`, managed clusters GKE 1.31–1.35, AKS 1.31–1.35, EKS 1.33–1.35. Documented supported k8s versions: **1.33, 1.34, 1.35, 1.36** (`compatibility.rst`); older/newer rely on k8s API compatibility. CRD schema version pinned per Cilium release in `compatibility-table.rst` (v1.20.x → 1.33.11).
- CRD generation check: `contrib/scripts/check-k8s-code-gen.sh` / `make manifests` diff the YAML against the Go markers — the YAML is the artifact, the Go is the source.

## Rust mapping

- **Client**: `kube` (kube-client) with `rustls`; enable feature `kube/protobuf`-style support does not exist upstream, so either (a) accept JSON for built-in types (2–3× the bytes of protobuf on large clusters; acceptable for rustkube-scale clusters) or (b) hand-roll a protobuf decoder for the slim subset using `prost` with the `generated.proto` files vendored from `pkg/k8s/slim/**/generated.proto` — the slim protos are already the minimal field set, and the k8s protobuf envelope (`k8s\0` magic + `runtime.Unknown`) is simple. Recommend (a) first, (b) as an optimisation. Multi-URL rotation, `/readyz` heartbeat and QPS/burst need a thin wrapper over `kube::Client` (tower layers: `tower::limit::RateLimit`, custom rotating `Service`).
- **Slim types**: hand-write Rust structs mirroring the slim table above with `serde(default)` everywhere and no `deny_unknown_fields`; this is the contract for what flowsdn reads. Do not use `k8s-openapi` full types for the hot path (Pod is ~1,000 fields).
- **Watchers/reflectors**: `kube-runtime` `watcher()` + `reflector()` with `watcher::Config` for field/label selectors (`spec.nodeName=`, the service-proxy-name selector), feeding a StateDB-like table layer. Replicate `Resource[T]` semantics: per-key rate-limited retry with `Done(err)` acks, indexers (namespace, localNode, identity-label key), lazy transform to slim types, and "wait for CRD to exist before first list" gating (watch `CustomResourceDefinition` as `PartialObjectMetadata` via `kube::core::PartialObjectMeta`).
- **CRDs**: two viable strategies. (1) **Vendor the 22 YAML files verbatim** and apply them as the registration payload (same `io.cilium.k8s.crd.schema.version` label/compare logic) — this guarantees byte-identical schemas and printer columns; then hand-write `kube-derive` `#[derive(CustomResource)]` Rust types for deserialisation only, with a CI test that generates the CRD from the Rust type and diffs it against the vendored YAML (restricted to the fields kube-derive can express; CEL rules, `oneOf/anyOf`, `x-kubernetes-list-map-keys` and printer columns must be attached via `#[kube(...)]`/`#[schemars(...)]` attributes or accepted as a known diff). (2) Generate Rust types from the YAML OpenAPI with a small in-repo generator (the flattener used for this inventory shows the structure is regular). Recommend (1): vendored YAML is the contract, Rust types are consumers; the diff test prevents drift. The operator-side `CreateUpdateCRD` is ~150 lines.
- **Writers**: `kube::Api::patch` with `Patch::Json` (CEP status, taints, LB pool status), `Patch::Strategic` (node status annotations/conditions), `patch_status`/`replace_status` for CiliumNode/CNP/BGP. Leader election: `kube-leader-election` or `kube-coordinate` (Lease-based, same 15s/10s/2s timings).
- **Label synthesis** and `labelsfilter`: straightforward; keep the default regex list identical (it changes identity numbering semantics).
- **Sizing**: client+config ~1.5k, slim types ~1.5k, resource/reflector layer ~2k, CRD Rust types ~4k (mostly CNP), registration/sync ~0.6k, annotation/label constants ~0.5k, identity CRD backend ~0.5k, operator watchers (taint, GC, unmanaged pods, CES batching) ~3k, tests ~4k. Total ≈ 15–18k lines: **L**.
- **Risks / hard parts**: (i) CNP `oneOf/anyOf` plus `x-kubernetes-int-or-string` ICMP types and `format: cidr` need custom serde; (ii) rustkube must implement structural-schema defaulting, CEL (`self == oldSelf`, `isIP()`, `has(self.spec) || has(self.specs)`), `x-kubernetes-list-type=map` merge semantics, status subresources, printer columns, strategic-merge patch on `nodes/status`, field selectors `spec.nodeName`/`status.phase`, `PartialObjectMetadata` content negotiation (or Cilium-style JSON fallback), Leases, `Established` CRD condition, and `ownerReferences` GC — any gap must be papered over on the flowsdn side; (iii) protobuf if chosen; (iv) the 410-Gone relist path and `resourceVersion` semantics of watches on a non-etcd store.

## Recommendation

**Keep** (with scope trimming). The client/watch/slim/CRD layer is mandatory for a Kubernetes CNI and is the compatibility surface users touch directly. Trim: drop Gateway API/Ingress/MCS-API/ClusterMesh EndpointSlice sync from the first cut (operator-only, controller-runtime heavy); drop `enable-k8s-api-discovery` (dead), `cilium.io/bgp-virtual-router.*` legacy annotation, alias annotation keys can be kept cheaply. Vendor the CRD YAML unchanged. Effort **L** (15–18k Rust lines incl. tests); the CRD type tree alone is ~1/4 of it.

## Open questions

- **Resolved #30:** the [audited capability matrix](../validation/dependency-capabilities-2026-09-22.md)
  records each requested capability and its missing probes. 184 existing unit
  tests passed; CEL/schema defaulting/list-map, CRD status isolation and stale
  watch recovery still have gaps. This is an audit result, not server conformance.
- Should flowsdn serve `v2alpha1` for the five graduated BGP/LB/CIDRGroup CRDs at all, or only `v2`? Serving both with strategy `None` costs nothing on a store that does not convert, but rustkube must accept two served versions with one storage version.
- Resolved #20: CRD identities are primary; kvstore remains optional scope.
  API-server uniqueness of metadata.name is still a required CRD allocation gate.
- Whether to keep `CiliumEndpoint` as a per-pod object (N objects, JSON-patched on every regeneration) or go straight to `CiliumEndpointSlice`-only (`--disable-endpoint-crd` + CES); the latter halves API write load but changes what `kubectl get cep` shows.
- Protobuf vs JSON for built-in types on rustkube (does rustkube speak protobuf at all?).
- Namespaced `CiliumNodeConfig`/`CiliumGatewayClassConfig` are the only namespaced non-policy CRDs; confirm the namespace(s) flowsdn's operator should list (`--cilium-namespace`).

### flowsdn decision outcomes (2026-09-22)

Spec 13 §12.2–12.8 resolves #166–172: preserve both served versions for seven
graduated CRDs, strategic merge with explicitly probed guarded JSON fallback,
no client CEL substitute, all 22 registrations regardless of feature enablement,
CEP default with validated opt-in slim CES, all-namespace NodeConfig and
GatewayClassConfig watches, and Kubernetes 1.26.0 floor with separate capability
requirements. The original questions above are historical, superseded by those
contracts. #165 remains open for measurement. `flowsdn-k8s` implements bounded
planning/patch primitives; live API, schema corpus and controller conformance
remain pending.
