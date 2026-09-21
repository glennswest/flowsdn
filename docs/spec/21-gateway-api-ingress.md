# Gateway API and Ingress — specification

Status: draft. Derived from: `docs/inventory/08-operator.md` (Gateway API and
Ingress sections), reference cilium v1.20.1 (7d68cfb394) paths
`operator/pkg/gateway-api/**`, `operator/pkg/ingress/**`,
`operator/pkg/model/**` (`model.go`, `helpers.go`, `types.go`, `ingestion/`,
`translation/`, `translation/gateway-api/`, `translation/ingress/`),
`operator/pkg/secretsync/`, `install/kubernetes/cilium/values.yaml`,
`.github/workflows/conformance-gateway-api.yaml`,
`.github/workflows/conformance-ingress.yaml`.
Governed by ADR-0001 (full feature scope, boundary compatibility), ADR-0004
(no Hive, no StateDB), ADR-0005 (harvest the reference's test data).

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes
*what* flowsdn does and the exact data it exchanges. It does not transcribe
reference code. Where the reference behavior is kept for compatibility, say
so and name the consumer that depends on it. Where flowsdn deviates, that is
marked **DEVIATION** with the reason and the ADR.

Sibling specs this one depends on and does **not** restate:

| Spec | What it owns that this spec consumes |
|---|---|
| `16-l7-envoy-dns.md` | The `CiliumEnvoyConfig` / `CiliumClusterwideEnvoyConfig` schema, the agent-side parse/qualify/inject/validate pipeline, the xDS contract with Envoy, proxy-port allocation, `services[]` → LB redirect and `backendServices[]` → EDS wiring, `nodeSelector` handling, and secret mirroring into the agent's Envoy. **This spec produces CEC objects; it does not redefine what a CEC means.** |
| `05-service-loadbalancing.md` | The `Service`/`EndpointSlice` model, LB IPAM (`CiliumLoadBalancerIPPool`, the `lbipam.cilium.io/ips` annotation, the `IPAMRequestSatisfied` condition), `service.cilium.io/*` annotations, `loadBalancerClass`, `externalTrafficPolicy`. The Services this spec generates are ordinary Services to that spec. |
| `12-operator.md` | Where these controllers run (leader-elected operator), the Gateway API startup preconditions and CRD discovery loop, `CiliumGatewayClassConfig` CRD creation, and the generic Secret/ConfigMap sync controller (copy naming, ownership labels, resync jitter). |
| `13-crds-k8s-client.md` | CRD registration and vendoring, the Kubernetes client, watch sets, slim types, RBAC. |
| `00-foundation-table-config.md` | The config-key registry and `flowsdn-table`. |

---

## 1. Scope

### 1.1 In scope

- The **Gateway API controller**: `GatewayClass`, `Gateway`, `HTTPRoute`,
  `GRPCRoute`, `TLSRoute`, `TCPRoute`, `UDPRoute`, `ReferenceGrant`,
  `BackendTLSPolicy`, `XListenerSet`, `ServiceImport`, and the
  `CiliumGatewayClassConfig` parameters CRD.
- The **Ingress controller**: `networking.k8s.io/v1` `Ingress` and
  `IngressClass`, in shared and dedicated load-balancer modes.
- The **GAMMA** mesh profile: `HTTPRoute`/`GRPCRoute` whose `parentRef` is a
  `Service` rather than a `Gateway`.
- The **intermediate model** (§4) that both front ends produce and the single
  translator consumes. This is the heart of the spec: it is the contract
  between ingestion and translation, and it is what makes one Envoy code path
  serve two (three, with GAMMA) Kubernetes APIs.
- The **translation** of that model into Envoy v3 protobufs packed into a
  `CiliumEnvoyConfig`, plus the exposing `Service` and its `EndpointSlice`.
- **Status reporting** on every object in the two APIs.
- **TLS**: certificate refs, cross-namespace grants, where secrets land for
  Envoy, and TLS passthrough.
- **Host network mode** for both front ends.

### 1.2 Out of scope

- The CEC schema and its agent-side handling — spec 16.
- Envoy itself. flowsdn consumes the `cilium/proxy` image unchanged
  (ADR-0001); this spec only decides what protobufs are put in front of it.
- LB IPAM, L2 announcement, BGP advertisement of the generated Service's
  ingress IP — spec 05 and spec 15.
- `Service`-annotation-driven L7 load balancing
  (`service.cilium.io/lb-l7=enabled`) — spec 16 §3.4, a different producer of
  CECs with no relation to these APIs.
- Istio/ztunnel, `Backend` (the Gateway API v1.4 non-Service backend kind),
  and `HTTPRoute` `BackendLBPolicy`. Not supported at the reference tag.

### 1.3 Prerequisites and staging

This whole area is **deferred** in `docs/inventory/README.md` (area 08:
*"defer Gateway API/Ingress until Envoy path exists"*) and it is the largest
single deferrable block in the project — roughly 18k lines of reference Go
plus 604 golden fixture files. It is deferred because it produces nothing but
`CiliumEnvoyConfig` objects, and a CEC with no agent to consume it is inert.

**Prerequisites, all hard.** flowsdn MUST NOT start either controller until:

| # | Prerequisite | Owner |
|---|---|---|
| P1 | The agent applies `CiliumEnvoyConfig`: parse, qualify, filter injection, proxy-port allocation, xDS push, ACK/NACK handling | spec 16 §3.4 |
| P2 | The agent runs the external Envoy DaemonSet and serves it xDS over `xds.sock` | spec 16 §3.1 |
| P3 | Service load balancing can attach an L7 proxy redirect to a frontend (`svc.l7_lb_proxy_port`) | spec 05 §3.4 |
| P4 | Secret sync copies Secrets and ConfigMaps into the Envoy secrets namespace | spec 12 §3.14 |
| P5 | The operator's leader-elected controller runtime and CRD-discovery loop exist | spec 12 §3.15 |
| P6 | `kube-proxy-replacement` is true in the cluster. Gateway API without KPR is refused with a warning, not a fatal error | spec 12 §3.15 |

**Two stages.** The staging is deliberate: Ingress is a strict subset of the
work, exercises the whole model→CEC→Envoy path end to end, and has a small,
stable API with a ready-made external conformance suite. Getting it green
proves the translator before the far larger status-and-attachment machinery
of Gateway API is written.

**Stage 1 — Ingress, dedicated load balancer mode only.**

- Ingest `Ingress` → model: hosts, paths, TLS, default backend, default
  secret, force-HTTPS.
- Translate model → CEC + `Service` + dummy `EndpointSlice`.
- Class handling, the annotation set (§6.2), `status.loadBalancer` mirroring.
- Host-network mode for Ingress.
- **Shared mode is explicitly deferred inside stage 1** and lands at the end
  of it: shared mode requires building one model from *all* shared Ingresses
  in the cluster and reconciling a single cluster-wide CEC, which is a
  different (and less forgiving) reconciliation shape than one-object-in,
  one-CEC-out. Dedicated mode alone is a complete, shippable Ingress
  controller.
- Exit criterion: `ingress-controller-conformance` passes (§9.4), and every
  harvested `08-operator-model-translation-ingress` golden matches byte for
  byte after normalization.

**Stage 2 — Gateway API.**

- `GatewayClass` + `CiliumGatewayClassConfig`, `Gateway`, `HTTPRoute`,
  `GRPCRoute`, `TLSRoute` first; `TCPRoute`/`UDPRoute`, `XListenerSet`,
  `ServiceImport` and GAMMA second.
- The full status surface (§3.11) — this is the bulk of the work, and it is
  where the 604 harvested fixtures are spent.
- Exit criterion: the upstream Gateway API conformance suite passes for the
  profiles in §2.4.

**Stage 2 MUST NOT begin before stage 1's translator is golden-clean.** Both
front ends share one translator; a translator bug found during Gateway API
bring-up is a bug that Ingress goldens would have caught for a tenth of the
cost.

---

## 2. Compatibility contract

### 2.1 Gateway API version and resources

flowsdn targets **`sigs.k8s.io/gateway-api` v1.6.1** — the version the
reference vendors at v1.20.1 — and **`sigs.k8s.io/mcs-api` v0.5.2** for
`ServiceImport`. flowsdn does **not** ship the Gateway API CRDs; the cluster
administrator installs them, exactly as with the reference. The only CRD
flowsdn creates for this area is `CiliumGatewayClassConfig` (spec 12 §3.4).

**Required.** All must be present or the Gateway API controllers do not start
(spec 12 §3.15 owns the discovery loop and its outcomes). Group
`gateway.networking.k8s.io`, version `v1`:

| Kind | Plural (what discovery matches on) |
|---|---|
| `GatewayClass` | `gatewayclasses` |
| `Gateway` | `gateways` |
| `HTTPRoute` | `httproutes` |
| `GRPCRoute` | `grpcroutes` |
| `TLSRoute` | `tlsroutes` |
| `ReferenceGrant` | `referencegrants` |
| `BackendTLSPolicy` | `backendtlspolicies` |

**Optional.** Presence enables the feature; absence is silent and MUST NOT be
an error or a warning:

| Kind | Group/version | Enables |
|---|---|---|
| `TCPRoute` | `gateway.networking.k8s.io/v1` | `TCP` protocol listeners |
| `UDPRoute` | `gateway.networking.k8s.io/v1` | `UDP` protocol listeners |
| `XListenerSet` | `gateway.networking.k8s.io/v1` | listeners contributed by a separate object (§3.6) |
| `ServiceImport` | `multicluster.x-k8s.io/v1beta1` | `backendRefs` to a ClusterSet service (§3.4.4) |

Discovery matches the **plural resource name**, because that is what the
discovery API returns. flowsdn names its constants after the plurals.

### 2.2 Names that users' manifests depend on — frozen

| Thing | Value | Depended on by |
|---|---|---|
| Gateway controller name | `io.cilium/gateway-controller` | every user `GatewayClass` manifest |
| GatewayClass name (as shipped by Helm) | `cilium` | conformance runs, docs, examples |
| IngressClass name | `cilium` | every user `Ingress` with an explicit class |
| GatewayClass `parametersRef` target | `cilium.io/v2alpha1` `CiliumGatewayClassConfig` | Helm, user manifests |
| Generated Gateway objects prefix | `cilium-gateway-` | scripts, dashboards, NetworkPolicies that name the Service |
| Generated dedicated Ingress objects prefix | `cilium-ingress-` | same |
| Shared Ingress Service name | `cilium-ingress` (key `ingress-shared-lb-service-name`) | Helm creates this Service, not the operator |
| Secrets namespace | `cilium-secrets` | agent RBAC is scoped to it |

Open decision 8 revisits whether the `io.cilium/` controller name and the
`cilium-*` object prefixes should become configurable.

### 2.3 Generated objects

For a `Gateway` named `G` in namespace `N`, and an `Ingress` named `I` in
namespace `N`:

| Object | Gateway API | Ingress, dedicated | Ingress, shared |
|---|---|---|---|
| `CiliumEnvoyConfig` | `N/cilium-gateway-G` | `N/cilium-ingress-N-I` | `<operator ns>/cilium-ingress` (one, for all shared Ingresses) |
| `Service` | `N/cilium-gateway-G`, type from params (default `LoadBalancer`) | `N/cilium-ingress-I`, type from annotation (default `LoadBalancer`) | `<operator ns>/cilium-ingress` — **created by Helm, not by the operator** |
| `EndpointSlice` | `N/cilium-gateway-G` (dummy for L7; real skeletons for L4) | `N/cilium-ingress-I` (dummy) | created by Helm alongside the Service |
| CEC `spec.services[].name` | `cilium-gateway-G` | `cilium-ingress-I` | `cilium-ingress` |

Every generated name is passed through the **name shortener** (§5.9) before
use. Every operator-created object carries an `ownerReference` with
`controller: true` pointing at its source object, so Kubernetes garbage
collection removes it when the source is deleted; the controller
additionally performs an explicit sweep (§3.13) because owner references do
not cover a *mode change* (dedicated → shared) or a *class change*.

**Labels on generated objects:**

| Label | Value | On |
|---|---|---|
| `gateway.networking.k8s.io/gateway-name` | shortened Gateway name | Gateway Service, EndpointSlice, CEC |
| `io.cilium.gateway/owning-gateway` | shortened Gateway name | Gateway Service, EndpointSlice (**deprecated**, kept for compatibility) |
| `kubernetes.io/service-name` | generated Service name | EndpointSlice |
| `endpointslice.kubernetes.io/managed-by` | `cilium-operator` | operator-managed L4 EndpointSlices |
| `cilium.io/ingress` | `"true"` | dedicated Ingress Service |

**Annotations on generated objects:**

| Annotation | Value | On |
|---|---|---|
| `cec.cilium.io/use-original-source-address` | `"true"` only for GAMMA models, else `"false"` | CEC |
| `service.cilium.io/node-selector` | the host-network node selector rendered as `k=v,k=v` (sorted) | generated Service, host-network mode only, and only if not already set |
| `service.cilium.io/src-ranges-policy` | model `Service.LoadBalancerSourceRangesPolicy` | generated Service |
| `service.cilium.io/lb-algorithm` | `maglev`, injected when any L4 route carries backend weights | generated Service |
| `lbipam.cilium.io/ips` | from `Gateway.spec.addresses` of type `IPAddress` | generated Service |
| `gateway.cilium.io/backend-service`, `gateway.cilium.io/backend-port`, `service.cilium.io/weight` | L4 EndpointSlice reconciliation bookkeeping | operator-managed L4 EndpointSlices |

### 2.4 Conformance profile

flowsdn targets, and CI MUST run (§9.5), the upstream Gateway API
conformance profiles:

```
GATEWAY-HTTP  GATEWAY-TLS  GATEWAY-GRPC  GATEWAY-TCP  GATEWAY-UDP
MESH-HTTP     MESH-GRPC
```

run with `--gateway-class cilium --all-features --allow-crds-mismatch
--cleanup-base-resources=false`, no exempt features on the command line, and
the same two test skips the reference carries: `MeshConsumerRoute` and
`HTTPRouteListenerPortMatching`. Each skip MUST be listed in §12 with an owner
and a target release; a skip that is not tracked is a silent regression.

**`GatewayClass.status.supportedFeatures`** is the list conformance keys off,
and it MUST be written on every accepted GatewayClass, sorted ascending by
name. flowsdn reports the upstream `AllFeatures` set minus an **exempt list**.
The reference's exempt list, which flowsdn adopts as its starting point, is:

| Exempt feature | Why |
|---|---|
| `HTTPRouteParentRefPort` | `parentRef.port` disambiguation not implemented |
| `MeshConsumerRoute` | GAMMA consumer routes (§3.8) |
| `BackendTLSPolicySANValidation` | SAN validation not passed to Envoy |
| `TLSRouteModeTerminate` | `TLSRoute` only supports passthrough |
| `GatewayBackendClientCertificate` | no client cert for upstream |
| `GatewayFrontendClientCertificateValidation` | no downstream mTLS |
| `GatewayHTTPSListenerDetectMisdirectedRequests` | 421 on SNI/authority mismatch not emitted |

Everything else in the upstream feature set is reported: `Gateway`,
`HTTPRoute`, `GRPCRoute`, `TLSRoute`, `TCPRoute`, `UDPRoute`,
`ReferenceGrant`, `BackendTLSPolicy`, `ListenerSet`, `Mesh`, the
`HTTPRoute*` matching/filter/redirect/rewrite/mirror/retry/timeout/CORS
features, `GatewayHTTPListenerIsolation`,
`GatewayInfrastructurePropagation`, `GatewayStaticAddresses`,
`GatewayAddressEmpty`, `GatewayPort8080`, `TLSRouteModeMixed`, and the
`Mesh*` variants — 51 names at the reference tag.

flowsdn keeps the exempt list as **one sorted constant in one file**, with a
CI test asserting that `AllFeatures − exempt` equals the golden list, so that
bumping the Gateway API dependency surfaces new features as a test failure
rather than as a silently-unreported capability.

### 2.5 Ingress conformance

The Ingress front end targets the `ingress-controller-conformance` suite
(`cilium/ingress-controller-conformance` fork) run with
`-ingress-class cilium`. flowsdn keeps that as a CI gate for stage 1 (§9.4).

---

## 3. Behavior

### 3.1 The pipeline

Both front ends run the same three-stage pipeline. Nothing else in flowsdn
may shortcut it.

```
  Kubernetes objects
        │
        │  (a) ingestion — front-end specific, pure
        ▼
     model::Model                          ← §4, the contract
        │
        │  (b) translation — shared, pure
        ▼
  CiliumEnvoyConfig + Service + EndpointSlice
        │
        │  (c) reconciliation — apply, then write status
        ▼
   apiserver  →  spec 16 (agent)  →  Envoy
```

Normative properties of the pipeline:

- **(a) and (b) MUST be pure functions.** No API reads, no clock, no
  randomness, no map-iteration order leaking into output. Every collection
  that reaches the output is explicitly sorted (§5.10). This is what makes the
  604 harvested golden fixtures usable as tests, and it is what makes a
  reconcile idempotent.
- **All API reads happen before (a).** The reconciler gathers the input set —
  Gateway, listeners, attached routes, referenced Services, ServiceImports,
  Secrets, ConfigMaps, ReferenceGrants, BackendTLSPolicies — into one input
  struct, and ingestion consumes only that struct.
- **Status is computed in (a)** as a by-product, not in (c). Ingestion decides
  which routes attach and which references resolve; those decisions *are* the
  status. Computing status separately from ingestion is how implementations
  end up reporting `Accepted: True` for a route that was silently dropped.
- **(c) is the only stage that writes**, and it writes in a fixed order:
  Service, then EndpointSlice, then CEC, then status. Status last, so a
  Gateway never reports `Programmed: True` before the CEC exists.

### 3.2 Controllers

| Controller | Owns | Watches (→ enqueue) |
|---|---|---|
| `gatewayclass` | `GatewayClass` status | GatewayClass (filtered to our controller name), `CiliumGatewayClassConfig` |
| `gatewayclassconfig` | `CiliumGatewayClassConfig` status | `CiliumGatewayClassConfig` |
| `gateway` | Gateway status; generated Service / EndpointSlice / CEC | Gateway, XListenerSet, all route kinds, Service, ServiceImport, Secret, ConfigMap, Namespace, ReferenceGrant, BackendTLSPolicy, Node (host-network mode only), GatewayClass |
| `gamma` | route status for Service-parented routes; generated CEC | HTTPRoute, GRPCRoute, Service |
| `endpointslice` | operator-owned L4 EndpointSlices | EndpointSlice (filtered to `endpointslice.kubernetes.io/managed-by=cilium-operator`), Service, EndpointSlice of backend Services |
| `ingress` | Ingress status; generated Service / EndpointSlice / CEC | Ingress, IngressClass, Secret, Service, EndpointSlice, CEC |

Every watch that is not on the primary object needs a **mapper** that turns
the changed object into the set of Gateways (or Ingresses) to re-reconcile.
Doing this by relisting every Gateway on every Secret change is correct but
quadratic; flowsdn MUST maintain indexes:

| Index | Key | Value |
|---|---|---|
| routes-by-gateway | `<ns>/<gateway name>` | route object keys |
| routes-by-backend | `<ns>/<service name>` | route object keys |
| routes-by-backend-serviceimport | `<ns>/<serviceimport name>` | route object keys |
| gateways-by-secret | `<ns>/<secret name>` | Gateway keys |
| gateways-by-listenerset | `<ns>/<listenerset name>` | Gateway keys |
| backendtlspolicy-by-configmap | `<ns>/<configmap name>` | BackendTLSPolicy keys |
| backendtlspolicy-by-service | `<ns>/<service name>` | BackendTLSPolicy keys |

A `Namespace` label change enqueues every Gateway that has a listener with
`allowedRoutes.namespaces.from: Selector`; a `ReferenceGrant` change enqueues
every Gateway and route in the grant's namespace and in every namespace named
by the grant's `from`.

### 3.3 GatewayClass reconciliation

1. If `spec.controllerName != io.cilium/gateway-controller`, do nothing. Not
   ours; MUST NOT write status, MUST NOT emit events.
2. If `spec.parametersRef` is set, it MUST be
   `group: cilium.io`, `kind: CiliumGatewayClassConfig`, with `namespace` set
   (the CRD is namespaced). Resolve it.
3. On successful resolution, stamp the annotation
   `gateway.cilium.io/config-checksum` = `sha256:<hex>` where the digest is
   over the canonical serialization of the config's `spec`. This is what makes
   a Gateway re-reconcile when the parameters object changes *content* without
   changing its name, and it MUST be written with a merge patch on the
   GatewayClass object (not its status).
4. Set `Accepted`:

| Condition | Status | Reason | Message | When |
|---|---|---|---|---|
| `Accepted` | `True` | `Accepted` | `Valid GatewayClass` | controller name matches and `parametersRef` (if any) resolves |
| `Accepted` | `False` | `InvalidParameters` | `Invalid GatewayClass` | `parametersRef` names a group/kind other than `cilium.io`/`CiliumGatewayClassConfig`, omits `namespace` or `name`, or points at a missing object |

5. `status.supportedFeatures` MUST be set to the feature set of §2.4, sorted
   ascending, deduplicated.
6. `observedGeneration` on every condition MUST be the GatewayClass's
   `metadata.generation`.

A GatewayClass that stops matching (its `controllerName` is edited away) is
reconciled **once more** — the ownership predicate matches on *old or new* —
so that dependent state is cleaned up, and thereafter its conditions are left
alone: another controller owns it now.

### 3.4 Gateway reconciliation

Ordered steps. A failure at any step writes status and returns; it MUST NOT
leave a half-applied set of generated objects.

1. **Class check.** Resolve `spec.gatewayClassName`. If the class does not
   exist, or is not ours, or is not `Accepted`, the Gateway is not ours: do
   nothing, write no status.
2. **Params.** Resolve the class's `CiliumGatewayClassConfig` (§4.11) and
   merge it with `spec.infrastructure` and `spec.addresses`. Per-Gateway
   `infrastructure` wins over class params.
3. **Gather input.** Listeners from `spec.listeners` plus every `XListenerSet`
   that targets this Gateway and is permitted (§3.6). All routes whose
   `parentRefs` name this Gateway. Every `Service`, `ServiceImport`, `Secret`,
   `ConfigMap`, `ReferenceGrant` and `BackendTLSPolicy` they reference.
4. **Listener validation and conflict detection** (§3.5). Each listener gets
   `Accepted`, `Conflicted`, `ResolvedRefs`, `Programmed`.
5. **Route attachment** (§3.7). Each `(route, parentRef)` pair gets `Accepted`
   and `ResolvedRefs`.
6. **Ingest** → `Model` (§4). Only accepted listeners and attached routes
   contribute.
7. **Translate** → CEC, Service, EndpointSlices (§5).
8. **Apply** Service, then EndpointSlices, then CEC — create-or-update with
   server-side apply, field manager `flowsdn-operator-gateway`.
9. **Read back addresses.** The generated Service's
   `status.loadBalancer.ingress[]` becomes `gateway.status.addresses[]`
   (`type: IPAddress` for `.ip`, `type: Hostname` for `.hostname`). In
   host-network mode there is no LoadBalancer address; see §3.10.
10. **Write status** (§3.11).
11. **Sweep** any previously generated object that is no longer desired
    (§3.13).

If the model is **empty** — no listener produced any Envoy config — the CEC
MUST be deleted rather than applied empty, and the Gateway gets
`Programmed: False, Reason: NoResources`. The Service is still created, so
that a Gateway with no routes still gets an address, which is what conformance
expects.

### 3.5 Listener validation and conflicts

Per listener, in order. The first failing check sets the condition and the
listener contributes nothing to the model.

| # | Check | Failure condition |
|---|---|---|
| 1 | Protocol is one of `HTTP`, `HTTPS`, `TLS`, `TCP`, `UDP`; `TCP`/`UDP` only when their route CRD is installed | `Accepted: False`, `UnsupportedProtocol` |
| 2 | `allowedRoutes.kinds` names only kinds valid for the protocol | `ResolvedRefs: False`, `InvalidRouteKinds` |
| 3 | `hostname` is absent for `TCP`/`UDP`; is a valid (possibly wildcard-prefixed) DNS name otherwise | `Accepted: False`, `Invalid` |
| 4 | For `HTTPS`/`TLS` terminate: at least one `certificateRefs` entry; each is a `core/v1` `Secret` of type `kubernetes.io/tls`; cross-namespace refs are permitted by a `ReferenceGrant` | `ResolvedRefs: False`, `InvalidCertificateRef` or `RefNotPermitted` |
| 5 | For `TLS` with `mode: Passthrough`: `certificateRefs` MUST be empty | `Accepted: False`, `Invalid` |
| 6 | No conflict with another listener on this Gateway (below) | `Conflicted: True`, `HostnameConflict` or `ProtocolConflict` |

**Pairwise conflict predicate**, evaluated for every unordered pair of
listeners in scope. Return the first match:

| # | Condition | Result |
|---|---|---|
| 1 | ports differ | no conflict |
| 2 | both are L4 (`TCP`/`UDP`) and their protocols differ | **no conflict** — TCP and UDP may share a port number |
| 3 | either is L4 (and rule 2 did not fire) | `ProtocolConflict` |
| 4 | one is `HTTPS` and the other is `TLS`/passthrough | `ProtocolConflict` **iff** their SNI hostname sets intersect (§5.1); otherwise no conflict |
| 5 | same protocol and the normalized hostnames are equal (absent hostname normalizes to `*`) | `HostnameConflict` |
| 6 | otherwise | no conflict |

Messages (frozen; conformance and the harvested fixtures assert on them, `%q`
being the *other* listener's name and `%d` this listener's port):

- `HostnameConflict` → `Listener conflicts with listener %q: same port %d has overlapping hostnames.`
- `ProtocolConflict`, HTTPS/passthrough pair → `Listener conflicts with listener %q: same port %d has overlapping HTTPS and TLS passthrough hostnames.`
- `ProtocolConflict`, otherwise → `Listener conflicts with listener %q: same port %d has incompatible protocols.`

**Ordering and precedence.** Listeners are considered in source precedence
order: the Gateway's own `spec.listeners` first, then each attached
`XListenerSet` in (creationTimestamp, then `namespace/name`) order. Within one
source, a conflicting pair marks **both** members — the conflict is symmetric
and flowsdn MUST NOT arbitrarily pick a winner. Across sources, an earlier
source's listener wins: the later one is marked `Conflicted` (with an empty
message, since the loser is unambiguous) and dropped. A conflicted listener
contributes nothing to the model.

**Cross-protocol SNI overlap on different ports** is *not* a conflict; it is
handled by splitting the output into per-port Envoy listeners (§5.7), because
a combined Envoy listener would erase the Gateway listener's port boundary and
route one listener's traffic to another's backends.

### 3.6 XListenerSet

When the `XListenerSet` CRD is installed, a `Gateway` MAY delegate listeners
to one or more `XListenerSet` objects.

- A `XListenerSet` attaches to a Gateway through its `spec.parentRef`.
- The Gateway MUST permit it. **The default is deny**: a ListenerSet attaches
  only when `gateway.spec.allowedListeners.namespaces.from` is explicitly set,
  to `All`, `Same`, or `Selector` (`None` denies). An unset
  `allowedListeners`, an unset `namespaces`, or an unset `from` all mean *no
  ListenerSet may attach* — this is deliberate and MUST NOT be relaxed to a
  friendlier default, because the friendly default silently lets any namespace
  add listeners to someone else's Gateway. A selector that fails to parse, or
  a namespace list that fails, denies. Rejected ListenerSets get
  `Accepted: False`/`Programmed: False`, reason `NotAllowed`, message
  `ListenerSet is not allowed by the Gateway's allowedListeners policy`.
- Listeners contributed by a ListenerSet participate in conflict detection
  (§3.5) on equal terms with the Gateway's own listeners, and are ordered
  **after** them for the purposes of "first listener wins" tie-breaks.
- Certificate refs in a ListenerSet listener are resolved relative to the
  **ListenerSet's** namespace and need a `ReferenceGrant` to reach a Secret in
  another namespace, including the Gateway's.
- Listener status for a ListenerSet listener is written on the
  `XListenerSet`, not the Gateway. The Gateway carries
  `status.attachedListenerSets` = the count of ListenerSets with at least one
  valid listener (left unset when zero), recomputed from scratch each
  reconcile.
- A route attaches to a ListenerSet listener by naming the **ListenerSet** in
  its `parentRef` (group `gateway.networking.k8s.io`, kind `ListenerSet`), not
  the Gateway.
- ListenerSet status is computed **independently of** the Gateway's `Accepted`
  and `Programmed` conditions: a Gateway that is waiting for an address does
  not drag its ListenerSets to `Programmed: False`.
- In the model, a ListenerSet-sourced listener carries **two** entries in
  `sources`: the ListenerSet first, the Gateway second. Translation uses the
  first non-`ListenerSet` source as the object naming root, so generated
  objects are still named after the Gateway.

### 3.7 Route attachment

For each route object and each of its `parentRefs`, in order:

| # | Check | Failure |
|---|---|---|
| 1 | The parent exists and is a `Gateway` (or, for GAMMA, a `Service`) of our class | `Accepted: False`, `NoMatchingParent` |
| 2 | `sectionName`, if set, names an existing listener | `Accepted: False`, `NoMatchingParent` |
| 3 | `port`, if set, matches the listener port | `Accepted: False`, `NoMatchingParent` |
| 4 | The listener's `allowedRoutes.namespaces` admits the route's namespace | `Accepted: False`, `NotAllowedByListeners` |
| 5 | The listener's `allowedRoutes.kinds` admits the route's kind | `Accepted: False`, `NotAllowedByListeners` |
| 6 | Hostname intersection with the listener is non-empty (HTTP/GRPC/TLS only) | `Accepted: False`, `NoMatchingListenerHostname` |
| 7 | Every `backendRef` resolves: kind ∈ {`Service`, `ServiceImport`}, object exists, named port exists | `ResolvedRefs: False`, `InvalidKind` or `BackendNotFound` |
| 8 | Every cross-namespace `backendRef` (and mirror backend, and ext-auth backend) is permitted by a `ReferenceGrant` | `ResolvedRefs: False`, `RefNotPermitted` |
| 9 | Filters are supported and internally consistent (no `RequestRedirect` together with `URLRewrite`; `ExtensionRef` names a supported kind) | `Accepted: False`, `UnsupportedValue` or `ResolvedRefs: False`, `InvalidKind` |
| 10 | A `BackendTLSPolicy` targeting a backend resolves its `caCertificateRefs` | `ResolvedRefs: False`, `InvalidKind` / `BackendNotFound` |

Route rules that fail check 7 or 8 do **not** remove the whole route. The
Gateway API rule is: a rule whose backends all fail MUST still produce a route
that returns **500**, so that traffic is not silently routed to a different,
broader rule. flowsdn MUST emit that 500 as an Envoy `direct_response`. A rule
where *some* backends fail keeps the surviving backends with their original
weights, and the failed backends' weight is dropped (not redistributed).

**Hostname intersection** is §5.1. **Precedence between rules** is §5.3.

#### 3.7.1 GRPCRoute

A `GRPCRoute` is ingested into the same `HTTPRoute` model type with
`is_grpc = true`. Method matches map to path matches:

| GRPCRoute match | Model path match |
|---|---|
| `method: {service: S, method: M}`, type `Exact` | `exact: /S/M` |
| `method: {service: S}` only | `prefix: /S/` |
| `method: {method: M}` only | `regex: /.+/M` |
| `method` type `RegularExpression` | `regex: /S/M` with the parts as given |
| no `method` | empty (matches all) |

Header matches carry over unchanged. `is_grpc` forces the backend cluster to
HTTP/2 (§5.6) and adds the gRPC stats filter.

#### 3.7.2 TLSRoute (passthrough)

A `TLSRoute` attaches to a `TLS`/`Passthrough` listener and produces a
`TLSPassthroughRoute`: hostnames (post-intersection) and backends only. There
is no HTTP processing; Envoy matches SNI in the filter chain and hands the
connection to a `tcp_proxy`. Weighted backends are supported.

#### 3.7.3 TCPRoute and UDPRoute

`TCPRoute`/`UDPRoute` attach to `TCP`/`UDP` listeners and produce an
`L4Listener` with one `L4Route`. There is no hostname, so `sectionName` or
`port` is the only disambiguator, and two routes attaching to one listener is
a conflict resolved by the oldest-then-lexicographic rule (§5.3.1).

L4 routes are **not** proxied through Envoy in the same way as L7: the
generated Service's `EndpointSlice`s point directly at the backend Service's
endpoints, and the datapath load-balances. Weighted L4 backends require the
Maglev algorithm to be honoured, so the generated Service is annotated
`service.cilium.io/lb-algorithm: maglev` whenever any L4 backend carries a
weight.

#### 3.7.4 ServiceImport backends

A `backendRef` of kind `ServiceImport` (group `multicluster.x-k8s.io`)
resolves to the **derived Service** that the MCS-API controller creates for
that import: the `ServiceImport` carries an annotation
`multicluster.kubernetes.io/derived-service` naming it, and the model's
`Backend` records that derived Service's name and namespace. Everything
downstream — cluster naming, EDS, `backendServices[]` — sees an ordinary
Service. If the derived Service does not exist yet, the ref is
`BackendNotFound`.

### 3.8 GAMMA

A `HTTPRoute` or `GRPCRoute` whose `parentRef` is a **`Service`** (group
`""`, kind `Service`) is a GAMMA (mesh) route.

- The parent Service is the source; the route is the owner of the generated
  CEC. The CEC is named after the **Service**, not prefixed with
  `cilium-gateway-`.
- No `Service`, no `EndpointSlice` is generated — the parent Service already
  exists and already has endpoints.
- The CEC redirects the parent Service's own frontends to Envoy, so that pods
  calling `svc.ns.svc.cluster.local` are intercepted. This is why the model's
  listener carries `gamma: true` and the CEC is annotated
  `cec.cilium.io/use-original-source-address: "true"` — the mesh path must
  preserve the client identity for policy.
- Route conditions are written per parentRef on the route, with the same
  reasons as §3.11.4. A GAMMA route whose parent Service does not exist gets
  `Accepted: False, NoMatchingParent`.
- Consumer routes (a route in a different namespace from its parent Service)
  are **not** supported at this tag; the conformance test `MeshConsumerRoute`
  is skipped (§2.4).

### 3.9 Ingress reconciliation

See §6.2 for the annotation table and §3.14 for path types.

1. **Class check.** The Ingress is ours when `spec.ingressClassName == cilium`,
   or the legacy annotation `kubernetes.io/ingress.class: cilium` is present,
   or `spec.ingressClassName` is unset **and** the `cilium` `IngressClass`
   carries `ingressclass.kubernetes.io/is-default-class: "true"`. The
   controller therefore watches `IngressClass` and re-enqueues every
   class-less Ingress when that annotation flips.
2. **Mode.** `ingress.cilium.io/loadbalancer-mode`, else
   `ingress-default-lb-mode` (default `dedicated`).
3. **Dedicated**: ingest this one Ingress, translate, apply
   `Service`+`EndpointSlice`+`CEC` named per §2.3, mirror the Service's
   `status.loadBalancer` to `ingress.status.loadBalancer`.
4. **Shared**: ingest **every** shared-mode Ingress that is ours, in a stable
   order, into one model; translate to one CEC named
   `ingress-shared-lb-service-name` in the operator namespace; mirror the
   shared Service's `status.loadBalancer` to every contributing Ingress. The
   operator does **not** create the shared Service — Helm does — and MUST NOT
   delete it.
5. **Mode change**: when an Ingress moves between modes, the objects of the
   *other* mode MUST be deleted in the same reconcile, and the shared CEC
   rebuilt. This is the single most common source of stale-config bugs in this
   area; §9.2 has a dedicated test.
6. **Class removal**: an Ingress that stops being ours has all its generated
   objects deleted and its `status.loadBalancer` left alone (another
   controller may now own it).

### 3.10 Host network mode

Host-network mode moves the Envoy listeners onto the node's network namespace
and removes the LoadBalancer Service from the path. Enabled by
`gateway-api-hostnetwork-enabled` / `ingress-hostnetwork-enabled`.

| Aspect | Normal | Host network |
|---|---|---|
| Generated Service type | `LoadBalancer` (or as configured) | `NodePort` |
| `externalTrafficPolicy` on it | from params / config key | **unset** |
| Node selection | none | `service.cilium.io/node-selector` annotation from `*-hostnetwork-nodelabelselector` |
| CEC `spec.nodeSelector` | `nil` (all nodes) | the parsed node label selector |
| Listener port (Gateway) | the Gateway listener's `port` | the same port, bound on the host |
| Listener port (Ingress) | 80 / 443 | `ingress-hostnetwork-http-listener-port` / `-https-listener-port` / `-tls-passthrough-listener-port`, each falling back to `ingress-hostnetwork-shared-listener-port` when 0, or the per-Ingress `ingress.cilium.io/host-listener-port` in dedicated mode |
| Gateway `status.addresses` | Service `status.loadBalancer.ingress` | the addresses of the nodes matching the selector |
| Data path | client → LB VIP → node → BPF L7 redirect → Envoy | client → node IP:port → Envoy directly (Envoy is listening on the host) |

The node-label-selector string is a comma-separated `key=value` list; pairs
that do not split into exactly two non-empty parts are **skipped silently**
(reference behavior, kept: a typo disables one label, not the feature). An
empty selector means all nodes.

**L4 is unsupported in host-network mode.** A `TCP` or `UDP` listener on a
host-network Gateway is rejected immediately, before any other listener check,
with `Accepted: False`, reason `UnsupportedProtocol`, message
`<protocol> listeners are not supported when Gateway API Host Network mode is
enabled`. The corresponding `TCPRoute`/`UDPRoute` gets
`Accepted: False, UnsupportedValue` with message
`<Kind> is not supported when Gateway API Host Network mode is enabled`, and
`ResolvedRefs: Unknown, Pending` with the message
`Backend references were not evaluated because this route type is not
supported in Gateway API Host Network mode` — the backends genuinely were not
looked at, and reporting `False` there would be a lie.

**Listener bind addresses.** With host network on, the Envoy listener binds
`0.0.0.0` (when IPv4 is enabled) and `::` (when IPv6 is enabled) at the
configured port. The first (port, address) pair becomes the listener's
`address`; the rest become `additional_addresses`. The cross product is
generated port-major so the ordering is stable.

**Host port collisions.** In host-network mode the listener addresses are real
host ports, so a collision between two Gateways scheduled to the same node is
possible and is *not* detected by the Gateway API's per-Gateway conflict
rules. flowsdn MUST detect cross-Gateway host-port collision among Gateways
whose node selectors intersect, and mark the younger Gateway's listener
`Accepted: False, Reason: PortUnavailable`.
**DEVIATION** (ADR-0001, "Kubernetes-facing behavior"): the reference does not
do this and produces two Envoy listeners that fight over one port, with the
loser failing to bind and NACKing. `PortUnavailable` exists in the Gateway API
for exactly this situation, and a condition is a better failure than a
silently dead listener.

### 3.11 Status

Every condition MUST carry `observedGeneration` equal to the object's
`metadata.generation`, and `lastTransitionTime` MUST change **only** when
`status`, `reason` or `message` changes. A reconcile that computes the same
conditions MUST NOT write, so that `resourceVersion` does not churn and
watchers do not loop.

Conditions are merged, not replaced: a condition type flowsdn does not manage
is left untouched.

#### 3.11.1 GatewayClass

| Type | Status | Reason | Message |
|---|---|---|---|
| `Accepted` | `True` | `Accepted` | `Valid GatewayClass` |
| `Accepted` | `False` | `InvalidParameters` | `Invalid GatewayClass` |

Plus `status.supportedFeatures` (§2.4).

#### 3.11.2 Gateway

Only `Accepted` and `Programmed` are written. The two are set **as a pair** on
every failure path, so a Gateway is never left with a stale `Programmed: True`
next to a fresh `Accepted: False`.

| Trigger | `Accepted` | `Programmed` |
|---|---|---|
| `spec.infrastructure.parametersRef` is set (unsupported) | `False`/`InvalidParameters`/`Invalid Gateway parameters: spec.infrastructure.parametersRef is not supported` | `Unknown`/`Pending`/`Waiting for Accepted condition to be True` |
| GatewayClass `parametersRef` names the wrong kind | `False`/`InvalidParameters`/`Invalid GatewayClass parameters: spec.parametersRef.kind must be CiliumGatewayClassConfig` | `Unknown`/`Pending`/`Waiting for Accepted condition to be True` |
| GatewayClass `parametersRef` missing name or namespace | `False`/`InvalidParameters`/`Invalid GatewayClass parametersRef: both name and namespace are required` | `Unknown`/`Pending`/`Waiting for Accepted condition to be True` |
| listener status could not be computed | `False`/`NoResources`/`Unable to set listener status` | `False`/`ListenersNotValid`/`Unable to set listener status` |
| no listener was accepted | `False`/`ListenersNotValid`/`No Accepted Listeners` | `False`/`ListenersNotValid`/`No Accepted Listeners` |
| some listeners valid, ≥1 with an unsupported protocol | **`True`**/`ListenersNotValid`/`Gateway has unsupported listeners` | (unchanged; set later) |
| some or all listeners valid | `True`/`Accepted`/`Gateway successfully scheduled` | (set later) |
| ingestion/translation failed | `False`/`NoResources`/`Unable to translate resources` | `False`/`ListenersNotValid`/`Unable to translate resources` |
| a static address in `spec.addresses` is unusable | `False`/`UnsupportedAddress`/`Unsupported Gateway address, <detail>` | `False`/`ListenersNotReady`/`Address is not ready` |
| Service apply failed | `False`/`NoResources`/`Unable to create Service resource` | `False`/`NoResources`/`Unable to create Service resource` |
| EndpointSlice apply failed | `False`/`NoResources`/`Unable to reconcile EndpointSlices` | `False`/`NoResources`/`Unable to reconcile EndpointSlices` |
| CEC apply failed | `False`/`NoResources`/`Unable to ensure CEC resource` | `False`/`NoResources`/`Unable to create CEC resource` |
| applied, no address yet | — | `False`/`AddressNotAssigned`/`Gateway waiting for address` |
| address resolution failed | — | `False`/`AddressNotAssigned`/`Address is not ready, <detail>` |
| ≥1 address resolved | — | `True`/`Programmed`/`Gateway Programmed` |
| static address could not be applied | — | `False`/`AddressNotUsable`/`StaticAddress can't be used` |

Note the deliberate asymmetry on row 6: a Gateway with a mix of good and
unsupported-protocol listeners is **`Accepted: True` with reason
`ListenersNotValid`**. That combination looks wrong and is not; conformance
depends on it, because the Gateway is genuinely usable for the listeners that
did work. flowsdn keeps it and this paragraph exists so nobody "fixes" it.

The `Unsupported Gateway address, <detail>` details are, verbatim:
`address type is not supported`, `address value is not set`,
`invalid ip address`.

**Address computation.** Find the generated Service by the label
`io.cilium.gateway/owning-gateway = <shortened Gateway name>` in the Gateway's
namespace, then:

| Service type | `gateway.status.addresses` |
|---|---|
| `LoadBalancer` | one entry per `status.loadBalancer.ingress[]`: `IPAddress` for a non-empty `.ip`, `Hostname` for a non-empty `.hostname`. An empty ingress list is **not an error** — return without writing and let the Service watch retrigger |
| `NodePort` (host network) | the first address of every Node, parsed as an IP, IPv4-mapped forms unmapped, sorted, **capped at 16**, each emitted as `IPAddress` |
| anything else | an error; `Programmed: False, AddressNotAssigned` |

`status.listeners[]` carries one entry per listener with `name`,
`supportedKinds`, `attachedRoutes` and the four listener conditions.
Entries whose listener name no longer exists in `spec.listeners` MUST be
pruned.

**`attachedRoutes`** counts, across all five route kinds, the routes that pass
*parent attachability* ∧ *listener allows this route* ∧ *non-empty computed
hostnames* ∧ *parentRef matched this listener*. It is a count of routes that
**could** attach, not of routes that produced Envoy config.

#### 3.11.3 Listener

`supportedKinds` per protocol, all group `gateway.networking.k8s.io`:

| Protocol | `supportedKinds` |
|---|---|
| `HTTP`, `HTTPS` | `HTTPRoute`, `GRPCRoute` |
| `TLS` | `TLSRoute` |
| `TCP` | `TCPRoute` |
| `UDP` | `UDPRoute` |
| anything else | empty → the listener is invalid |

With `allowedRoutes.kinds` set, `supportedKinds` is the intersection. A
non-empty intersection that is smaller than the request additionally emits
`ResolvedRefs: False, InvalidRouteKinds`; an empty intersection makes the
listener invalid.

| Type | Status | Reason | Message |
|---|---|---|---|
| `Conflicted` | `True` | `HostnameConflict` / `ProtocolConflict` | the §3.5 conflict messages |
| `Accepted` | `True` | `Accepted` | `Listener Accepted` |
| `Accepted` | `False` | `Invalid` \| `UnsupportedProtocol` \| `UnsupportedValue` | `Listener not valid. ` + the joined validation fragments below |
| `ResolvedRefs` | `True` | `ResolvedRefs` | `Resolved Refs` |
| `ResolvedRefs` | `False` | `InvalidRouteKinds` | `Unsupported Route Kinds in allowedRoutes.kinds` |
| `ResolvedRefs` | `False` | `InvalidCertificateRef` | `Invalid CertificateRef` |
| `ResolvedRefs` | `False` | `RefNotPermitted` | `CertificateRef is not permitted` |
| `Programmed` | `False` | `Pending` | `Address not ready yet` — the initial value for every listener |
| `Programmed` | `False` | (mirrors the `Accepted` reason) | `Address not ready yet` |
| `Programmed` | `True` | `Programmed` | `Listener Programmed` — set only once the Gateway itself reaches `Programmed: True` |

Validation fragments, concatenated with a single space into the `Accepted`
message (the first one short-circuits the rest):

| Fragment | Reason |
|---|---|
| `<protocol> listeners are not supported when Gateway API Host Network mode is enabled` | `UnsupportedProtocol` (short-circuits) |
| `Unsupported Listener Protocol.` | `UnsupportedProtocol` |
| `None of the Allowed Route Kinds are supported.` | `Invalid` |
| `Invalid CertificateRef, must be a Secret.` | `Invalid` |
| `Invalid CertificateRef, not permitted.` | `Invalid` |
| `Invalid CertificateRef, <error>` where `<error>` ∈ {the API error, `PEM format error in TLS Certificate`, `PEM format error in TLS Key`} | `Invalid` |
| `Using TLSRoute with TLS.mode Terminate is unsupported.` | `UnsupportedValue`, and `supportedKinds` is forced **empty** |

The last row is a compatibility quirk worth naming: conformance asserts an
empty `supportedKinds` for a terminate-mode TLS listener even though the
listener's protocol would otherwise support `TLSRoute`. flowsdn reproduces it
and this note records why, so it is not "cleaned up" into a test failure.

#### 3.11.4 ListenerSet

Object-level:

| Situation | `Accepted` | `Programmed` |
|---|---|---|
| not permitted by `allowedListeners` | `False`/`NotAllowed`/`ListenerSet is not allowed by the Gateway's allowedListeners policy` | same |
| ≥1 valid listener | `True`/`Accepted`/`ListenerSet is accepted` | `True`/`Programmed`/`ListenerSet is programmed` |
| 0 valid listeners | `False`/`ListenersNotValid`/`No valid listeners` | same |

Per-listener entries in `status.listeners[]`:

| Situation | Conditions |
|---|---|
| conflicted | `Accepted: False`, `Programmed: False`, `Conflicted: True` — all with the conflict reason and message `Listener has a conflict` — plus `ResolvedRefs: True`/`Resolved Refs`. `supportedKinds` is left empty (validation is skipped for a conflicted entry) |
| invalid | `Accepted: False`/`<reason>`/`Listener not valid. <fragments>`, `Programmed: False`/`<reason>`/`Listener not valid` |
| valid | `ResolvedRefs: True` (if not already present), `Accepted: True`/`Listener Accepted`, `Programmed: True`/`Listener Programmed` |

Unlike a Gateway listener, a valid ListenerSet listener is `Programmed: True`
immediately rather than waiting on address assignment.

#### 3.11.5 Route (per parentRef, in `status.parents[]`)

Each entry carries `parentRef`, `controllerName: io.cilium/gateway-controller`
and the conditions below. Every matching parent starts from the optimistic
pair

```
Accepted:     True / Accepted     / "Accepted <Kind>"
ResolvedRefs: True / ResolvedRefs / "Service reference is valid"
```

which the checks below then overwrite. Checks run in two ordered groups;
within a group the first failing check stops that group.

**Group 1 — parent attachment.**

| # | Check | Type / Status / Reason / Message |
|---|---|---|
| 0 | the parent Gateway or ListenerSet cannot be resolved | `Accepted`/`False`/**`Invalid<Kind>`**/`<error>` |
| 1 | no listener whose protocol can carry this route kind | `Accepted`/`False`/`NotAllowedByListeners`/`No matching listener protocol; route requires one of: <protocols>` |
| 2 | `allowedRoutes.kinds` excludes this kind | `Accepted`/`False`/`NotAllowedByListeners`/`<Kind> is not allowed to attach to this Gateway due to route kind restrictions` |
| 3 | `parentRef.port` matches no listener | `Accepted`/`False`/`NoMatchingParent`/`No matching listener with port <n>` |
| 4 | hostname intersection empty | `Accepted`/`False`/`NoMatchingListenerHostname`/`No matching listener hostname` |
| 5 | `parentRef.sectionName` matches no listener | `Accepted`/`False`/`NoMatchingParent`/`No matching listener with sectionName <name>` |
| 6 | `allowedRoutes.namespaces` excludes the route's namespace | `Accepted`/`False`/`NotAllowedByListeners`/`<Kind> is not allowed to attach to this Gateway due to namespace restrictions` |

`Invalid<Kind>` (`InvalidHTTPRoute`, `InvalidGRPCRoute`, `InvalidTLSRoute`,
`InvalidTCPRoute`, `InvalidUDPRoute`) is **not** an upstream Gateway API reason
constant. flowsdn keeps it for compatibility with the harvested fixtures and
records it here as a known non-standard reason (Open decision 6).

Check 6 is silent when no candidate listener had a namespace restriction at
all — an unrestricted Gateway that simply has no matching listener produces
the hostname or section failure, not a namespace one.

**Group 2 — backends.** These run even when group 1 failed, so a route that
cannot attach still reports whether its backends are sane.

| # | Check | Type / Status / Reason / Message |
|---|---|---|
| 1 | cross-namespace backendRef without a `ReferenceGrant` | `ResolvedRefs`/`False`/`RefNotPermitted`/`Cross namespace references are not allowed` |
| 2 | backendRef kind is not `Service`/`ServiceImport` | `ResolvedRefs`/`False`/`InvalidKind`/`Unsupported backend kind <kind>` |
| 2b | backendRef has no `port` | `ResolvedRefs`/`False`/`InvalidKind`/`Must have port for backend object reference` |
| 3 | a `ServiceImport` backend while the CRD is not installed | `ResolvedRefs`/`False`/`BackendNotFound`/`Attempt to reference a ServiceImport backend while the corresponding CRD is not installed, please restart the operator if the CRD is already installed` |
| 4 | the Service does not exist, or does not expose the port | `ResolvedRefs`/`False`/`BackendNotFound`/`<error>` or `Service port <n> could not be resolved for backend <ns>/<name>` |

Checks 1 and 2 visit **every** rule and every backendRef before returning, so
that the reported condition names the last offending backend rather than
stopping at the first; that is deliberate and makes the message stable across
reconciles for a route with several bad backends.

**Group 3 — HTTPRoute/GRPCRoute value validation**, applied to every parent
already present in `status.parents[]`:

| Check | Type / Status / Reason / Message |
|---|---|
| a header modifier names `Host` | `Accepted`/`False`/`UnsupportedValue`/`Invalid header modifier: "Host" header is not supported` |
| a match regular expression does not compile | `Accepted`/`False`/`UnsupportedValue`/`Invalid regular expression in <field> match: <error>` |

`<field>` ∈ {`path`, `header`, `queryParam`} for `HTTPRoute` and
{`method.service`, `method.method`, `header`} for `GRPCRoute`.

**Pruning.** A `RouteParentStatus` entry is kept if its `controllerName` is not
ours, or if its `parentRef` still equals one of the route's current
`parentRefs`. Everything else is removed. Parents belonging to other
controllers MUST never be touched.

#### 3.11.6 GAMMA parent Service

GAMMA writes two **Cilium-specific** conditions onto the parent
`Service.status.conditions`, because `Service` has no Gateway API status:

| Type | Status | Reason | Message |
|---|---|---|---|
| `gamma.cilium.io/GammaRoutesAttached` | `True`/`False` | `Accepted` | `Gamma Service has routes attached` |
| `gamma.cilium.io/GammaRoutesProgrammed` | `True`/`False` | `Programmed` | `Gamma Service has been programmed` |

Note that the reason string does not vary with the status. That is the
reference's behavior; flowsdn keeps it because tooling greps the type, and
records it here as a wart rather than silently improving it (Open decision 6).

A Service with no GAMMA routes referencing it MUST have **no** conditions
written — flowsdn must not stamp status on every Service in the cluster.

#### 3.11.7 BackendTLSPolicy

Ancestor ref is the Gateway (`group gateway.networking.k8s.io`, kind
`Gateway`, the Gateway's namespace and name) with
`controllerName: io.cilium/gateway-controller`. Starts optimistic:
`Accepted: True/Accepted/Accepted BackendTLSPolicy` and
`ResolvedRefs: True/ResolvedRefs/All references are valid`.

| Situation | `Accepted` | `ResolvedRefs` |
|---|---|---|
| target Service missing | `False`/`Invalid`/`TargetRef does not exist: <ns>/<name>` | `False`/`BackendNotFound`/same message |
| loses conflict resolution against another policy | `False`/`Conflicted`/`BackendTLSPolicy conflicts with another` | — |
| both `caCertificateRefs` and `wellKnownCACertificates` set | `False`/`Invalid`/`Cannot have both CACertificateRefs and wellKnownCACertificates set` | `False`/`Invalid`/same |
| more than one `caCertificateRefs` entry | `False`/`Invalid`/`Having more than one CA Certificate Ref is not supported` | `False`/`Invalid`/same |
| CA ref is not a core `ConfigMap` | `False`/`NoValidCACertificate`/`Only ConfigMaps are supported for CA Certificate Refs` | `False`/`InvalidKind`/same |
| ConfigMap missing | `False`/`NoValidCACertificate`/`CA Certificate does not exist: <ns>/<name>` | `False`/`InvalidCACertificateRef`/same |
| no `ca.crt` key | `False`/`NoValidCACertificate`/``CA Certificate ConfigMap does not contain a `ca.crt` key`` | `False`/`InvalidCACertificateRef`/same |
| `ca.crt` holds no valid PEM certificate | `False`/`NoValidCACertificate`/`CA Certificate ConfigMap does not contain at least one valid PEM-encoded certificate` | `False`/`InvalidCACertificateRef`/same |

A policy that fails validation is recorded as **invalid**, not merely absent:
ingestion distinguishes "no policy for this backend" (plaintext upstream) from
"a policy exists but is broken" (**drop the backend entirely**). Silently
falling back to plaintext because the CA bundle is malformed would be a
downgrade attack surface, and this distinction is why the model carries it.

#### 3.11.8 CiliumGatewayClassConfig

| Type | Status | Reason | Message |
|---|---|---|---|
| `Accepted` | `True` | `Accepted` | `Valid GatewayClassConfig` |
| `Accepted` | `False` | `Accepted` | `Invalid GatewayClassConfig` |

The reference performs no validation here and the `False` branch is
unreachable. flowsdn MUST implement the validation the reference left as a
TODO — at minimum: `loadBalancerClass`, `loadBalancerSourceRanges` and
`allocateLoadBalancerNodePorts` are only meaningful with
`service.type: LoadBalancer`; `ipFamilyPolicy` must agree with `ipFamilies`;
`accessLogs[].format: Text` requires `text`, `JSON` requires `json`.
**DEVIATION**, additive: the `False` branch becomes reachable, and its reason
becomes `InvalidParameters` rather than `Accepted`, because a reason string
that does not change with the status carries no information.

#### 3.11.9 Ingress

`Ingress` has no conditions in the Kubernetes API. flowsdn writes only
`status.loadBalancer.ingress[]`, mirrored from the dedicated or shared Service
(`ip`, `hostname`, and each port's `port`/`protocol`/`error`), and emits
Kubernetes `Event`s for failures (§8). This is a real limitation of the
Ingress API: an Ingress with an unresolvable backend looks identical in
`kubectl get` to a healthy one. It is also why §1.3 stages Ingress first but
does not treat it as the finished product.

### 3.12 TLS

#### 3.12.1 Where certificates come from

| Source | Front end | Resolved to |
|---|---|---|
| `Gateway`/`XListenerSet` listener `tls.certificateRefs[]` | Gateway API | `core/v1` `Secret`, type `kubernetes.io/tls`, keys `tls.crt` + `tls.key` |
| `Ingress.spec.tls[].secretName` | Ingress | same |
| `ingress-default-secret-namespace` / `-name` | Ingress | used when an `Ingress.spec.tls[]` entry names no secret |
| `BackendTLSPolicy.validation.caCertificateRefs[]` | Gateway API | `ConfigMap` with key `ca.crt` (or a `Secret`) — **upstream** TLS, not downstream |

#### 3.12.2 Cross-namespace references

A `certificateRefs` entry, `backendRef`, mirror backend or ext-auth backend
whose `namespace` differs from the referring object's namespace requires a
`ReferenceGrant` in the **target** namespace whose `spec.from[]` names the
referring object's group/kind/namespace and whose `spec.to[]` names the target
group/kind (and optionally `name`). No grant → `RefNotPermitted`, and the
reference is dropped: flowsdn MUST NOT read the object anyway. Deleting a
grant MUST re-reconcile every affected Gateway and route and revoke the
config; a certificate that has already been synced MUST be removed from the
secrets namespace when it is no longer referenced by any permitted reference.

#### 3.12.3 Secret synchronization

Agents' Envoy reads TLS material only from the configured secrets namespace,
because agent RBAC is scoped to it. The operator copies. **Spec 12 §3.14 owns
the copy mechanism** — the `cilium-sync-secret-<sha256 hex>` naming, the
ownership labels, the refusal to overwrite an unowned object, the legacy
`<ns>-<name>` cleanup and the 1 h ± 20 % resync. What this spec adds:

- **Registrations**: Gateway API registers `Gateway` and `XListenerSet`
  `certificateRefs` (Secrets) and `BackendTLSPolicy.caCertificateRefs`
  (ConfigMaps, materialised as Secrets); Ingress registers
  `Ingress.spec.tls[].secretName` plus the configured default secret. Each
  registration is gated on its own key (`enable-gateway-api-secrets-sync`,
  `enable-ingress-secrets-sync`, both default true).
- **A Secret is only synced if the reference is permitted.** The
  `ReferenceGrant` check runs *before* the sync registration reports the
  Secret as referenced. Otherwise the sync controller becomes a
  cross-namespace secret exfiltration primitive, which is precisely the thing
  the scoped agent RBAC exists to prevent.
- **Translation emits the synced name.** The Envoy `DownstreamTlsContext`
  refers to an SDS secret named
  `<secrets namespace>/<synced secret name>`, which the agent resolves from
  its watch on that namespace (spec 16 §3.5.4). Translation MUST compute the
  synced name with the same hash function the sync controller uses; a
  mismatch is a silent TLS failure with no error anywhere.
- With sync **disabled**, translation still emits
  `<secrets namespace>/<synced name>` and the administrator is responsible for
  putting the material there. flowsdn MUST log this once per Gateway at
  `warn` when sync is off and a certificateRef is present.

#### 3.12.4 Passthrough

`TLS` listeners with `mode: Passthrough` terminate nothing. The Envoy listener
gets a TLS-inspector listener filter and one filter chain per SNI value,
each holding a `tcp_proxy` to the route's cluster. There is no
`transport_socket`, no certificate, no HTTP filter, and no route
configuration. `certificateRefs` on a passthrough listener is an error
(§3.5 check 5).

### 3.13 Deletion and cleanup

Owner references handle the common case (source object deleted → generated
objects garbage collected). They do not handle:

- **Mode change** (Ingress dedicated ↔ shared): the other mode's objects have
  the wrong owner or no owner.
- **Class change**: the Gateway/Ingress is still there but is no longer ours.
- **Feature disable**: `enable-gateway-api` turned off leaves objects behind.
- **Shortener collision resolution**: a rename that changes the shortened
  name leaves the old object.

Each reconcile therefore MUST list operator-owned objects for the source
(by owner reference and by the `gateway.networking.k8s.io/gateway-name` /
`cilium.io/ingress` labels) and delete any that are not in the desired set.
On operator startup, before the first reconcile of a given kind completes,
this sweep MUST NOT run — a sweep against an unsynced cache deletes live
config. flowsdn gates the sweep on the informer cache having synced, the same
"prune after full sync" rule spec 05 uses for LB maps.

### 3.14 Ingress path types

| Ingress `pathType` | Model path match | Envoy |
|---|---|---|
| `Exact` | `exact: <path>` | `path:` |
| `Prefix`, path `/` | `prefix: /` | `prefix: /` |
| `Prefix`, other | `prefix: <path>` | `path_separated_prefix: <path without trailing "/">` |
| `ImplementationSpecific` | `regex: <path>` | `safe_regex:` (RE2, **unanchored** — the value is passed through verbatim) |
| absent (server-side defaulted by Kubernetes) | `prefix: /` | `prefix: /` |

`path_separated_prefix` is what makes `Prefix` mean *path-segment* prefix:
`/foo` matches `/foo` and `/foo/bar` but not `/foobar`, which is what the
Ingress spec requires and what a bare Envoy `prefix` match would get wrong.

The **default backend** (`spec.defaultBackend`) becomes a route with an empty
path match (which translation renders as `prefix: /`) on every host listener,
sorted last by §5.3 because its path match has length zero.

---

## 4. Data model

This section is normative and complete. Both front ends produce exactly these
types; the translator consumes exactly these types and nothing else. A field
that is not here does not reach Envoy.

Conventions in the tables below: **opt** means the field is optional
(`Option<T>` in Rust, a pointer in the reference); a *value* field with a
documented default is always present. The `serde` column gives the wire name,
which is fixed: the harvested ingestion goldens (`output-listeners.yaml`,
324 files) are YAML documents of these types and are compared textually, so
renaming a field breaks the fixtures.

### 4.1 `Model`

| Field | Type | serde | Meaning |
|---|---|---|---|
| `http` | `Vec<HttpListener>` | `http` | HTTP and HTTPS terminating listeners |
| `tls_passthrough` | `Vec<TlsPassthroughListener>` | `tls_passthrough` | SNI-routed passthrough listeners |
| `l4` | `Vec<L4Listener>` | `l4` | TCP and UDP listeners |
| `http_options` | opt `HttpOptions` | `http_options` | model-wide HTTP switches |
| `telemetry` | opt `Telemetry` | `telemetry` | access-log configuration |

Derived queries the translator relies on (all pure, all specified here so two
implementations agree):

| Query | Definition |
|---|---|
| `is_empty()` | all three listener vectors are empty |
| `http_ports()` | sorted unique ports of `http` |
| `https_ports()` | sorted unique ports of `http` entries with non-empty `tls` |
| `tls_passthrough_ports()` | sorted unique ports of `tls_passthrough` entries **that have at least one route** |
| `all_ports()` | sorted unique union of the two above and `http_ports()` |
| `needs_per_port_listeners()` | `https_ports().len() > 1` ∨ `tls_passthrough_ports().len() > 1` ∨ `needs_cross_protocol_split()` |
| `needs_cross_protocol_split()` | ∃ an HTTPS filter-chain match and a passthrough filter-chain match on **different** ports whose SNI hostnames intersect (§5.1) |
| `grpc_web_enabled()` | `true` unless `http_options.grpc_web_translation.enabled` is explicitly `false` |
| `server_header_transformation()` | the first non-empty value across `http`, else `Overwrite` |
| `tls_secrets_to_listeners()` | `TlsSecret → Vec<(hostname, port)>` over `http` |

The HTTPS filter-chain match set is `{(normalize(listener.hostname), port)}`
over HTTPS listeners; the passthrough match set is
`{(normalize(route hostname), port)}` over passthrough **routes**, with the
empty hostname normalizing to `*`. The asymmetry is not an oversight: an HTTPS
listener SNI-matches on the *listener's* hostname, while each passthrough
route gets its own filter chain keyed on the *route's* hostnames.

### 4.2 `HttpListener`

| Field | Type | serde | Meaning |
|---|---|---|---|
| `name` | `String` | `name` | Gateway: the listener section name. Ingress: `ing-<ingress name>-<namespace>-<host>`. GAMMA: `<service ns>-<service name>-<port>` |
| `sources` | `Vec<FullyQualifiedResource>` | `sources` | what produced this listener. GAMMA puts the parent Service at `[0]` and the route at `[1]`; a ListenerSet listener puts the ListenerSet at `[0]` |
| `address` | `String` | `address` | reserved; never populated by either front end |
| `port` | `u32` | `port` | |
| `hostname` | `String` | `hostname` | `*` when the source specified none |
| `tls` | `Vec<TlsSecret>` | `tls` | empty ⇒ this is a cleartext HTTP listener |
| `routes` | `Vec<HttpRoute>` | `routes` | |
| `service` | opt `ServiceParams` | `service` | overrides for the generated Service |
| `infrastructure` | opt `Infrastructure` | `infrastructure` | labels/annotations to propagate |
| `force_http_to_https_redirect` | `bool` | `force_http_to_https_redirect` | Ingress only; makes the translator emit a redirecting plaintext virtual host that **overrides** any other plaintext config for that hostname |
| `server_header_transformation` | `ServerHeaderTransformation` | `server_header_transformation` | `""` ⇒ `OVERWRITE` |
| `gamma` | `bool` | `gamma` | drives `cec.cilium.io/use-original-source-address` |

### 4.3 `TlsPassthroughListener`

`name`, `sources`, `address`, `port`, `hostname`, `routes:
Vec<TlsPassthroughRoute>` (`routes`), `service`, `infrastructure`. Same
semantics as §4.2 for the shared fields. No TLS, no redirect, no GAMMA.

### 4.4 `L4Listener`

`name`, `sources`, `address`, `port`, `protocol: L4Protocol` (`protocol`,
`TCP` | `UDP`), `routes: Vec<L4Route>`, `service`, `infrastructure`.

`L4Route { name: String, backends: Vec<Backend> }`.

### 4.5 `HttpRoute`

| Field | Type | serde | Meaning |
|---|---|---|---|
| `name` | `String` | `name` | |
| `source_rule` | opt `HttpRouteRule` | *(not serialized)* | rule identity, §5.4 |
| `hostnames` | `Vec<String>` | `hostnames` | post-intersection hostnames; **empty means "inherit the listener's"**, not "match nothing" |
| `path_match` | `StringMatch` | `path_match` | value, not optional; all-empty means "match every path" |
| `headers_match` | `Vec<KeyValueMatch>` | `headers_match` | |
| `query_params_match` | `Vec<KeyValueMatch>` | `query_params_match` | |
| `method` | opt `String` | `method` | uppercased only at Envoy emission |
| `backends` | `Vec<Backend>` | `backends` | empty ⇒ `direct_response` |
| `backend_http_filters` | `Vec<BackendHttpFilter>` | `backend_http_filters` | per-backend header mutation |
| `direct_response` | opt `DirectResponse` | `direct_response` | |
| `request_header_filter` | opt `HttpHeaderFilter` | `request_header_filter` | |
| `response_header_modifier` | opt `HttpHeaderFilter` | `response_header_modifier` | |
| `request_redirect` | opt `HttpRequestRedirectFilter` | `request_redirect` | |
| `rewrite` | opt `HttpUrlRewriteFilter` | `rewrite` | |
| `request_mirrors` | `Vec<HttpRequestMirror>` | `request_mirrors` | **multiple allowed**, unlike every other filter |
| `external_auth` | opt `HttpExternalAuthFilter` | `external_auth` | |
| `is_grpc` | `bool` | `is_grpc` | forces the backend cluster to HTTP/2 |
| `timeout` | `Timeout` | `timeout` | value, not optional |
| `retry` | opt `HttpRetry` | `retry` | |
| `cors` | opt `HttpCorsFilter` | `cors` | |

`HttpRouteRule { source: FullyQualifiedResource, rule_index: usize,
match_index: usize }` — the identity of the Gateway API rule and match that
produced this model route. It is **not serialized**, so it does not appear in
the goldens; it exists only to keep two identical matches from different rules
from being merged (§5.4).

`TlsPassthroughRoute { name, hostnames: Vec<String>, backends: Vec<Backend> }`.

### 4.6 Matchers

```
StringMatch  { prefix: String, exact: String, regex: String }   // at most one non-empty
KeyValueMatch{ key: String, match: StringMatch }
```

`StringMatch` renders to a canonical string used for sorting and keying:
`prefix:<v>` if `prefix` is non-empty, else `exact:<v>`, else `regex:<v>`,
else the empty string. `KeyValueMatch` renders as `kv:<key>:<match>`. The
precedence in that rendering is `prefix` → `exact` → `regex`, which is *not*
the same order the Envoy path-matcher selection uses (§5.5) — both orders are
frozen and must not be "unified".

An all-empty `StringMatch` is legal and means *no constraint*.

### 4.7 `Backend`

| Field | Type | serde | Meaning |
|---|---|---|---|
| `name` | `String` | `name` | Service name. A `ServiceImport` backend is resolved to its derived Service **during ingestion**, so translation never sees an import |
| `namespace` | `String` | `namespace` | |
| `port` | opt `BackendPort` | `port` | absent ⇒ use the listener's port |
| `app_protocol` | opt `String` | `app_protocol` | copied from the Service port's `appProtocol` (KEP-3726) |
| `tls` | opt `BackendTlsOrigination` | *(not serialized)* | upstream TLS from a `BackendTLSPolicy` |
| `weight` | opt `i32` | `weight` | absent ⇒ **1** at emission time |

```
BackendPort          { port: u32, name: String }      // exactly one is set
BackendTlsOrigination{ ca_cert_ref: opt FullyQualifiedResource, sni: String }
```

`BackendPort::as_str()` yields the decimal port when `port != 0`, else `name`.
That string is what appears in cluster names, EDS service names and
`backendServices[].number`, so a named port stays a name all the way through
to the agent, which resolves it against the Service. This is deliberate: the
operator must not resolve named ports itself, because the Service's port
numbering can change without the routes changing.

### 4.8 Filters

| Type | Fields |
|---|---|
| `Header` | `name`, `value` |
| `HttpHeaderFilter` | `headers_to_add: Vec<Header>` (append), `headers_to_set: Vec<Header>` (overwrite), `headers_to_remove: Vec<String>` |
| `HttpRequestRedirectFilter` | opt `scheme`, opt `hostname`, opt `path: StringMatch`, opt `port: i32`, opt `status_code: i32` |
| `HttpUrlRewriteFilter` | opt `host_name`, opt `path: StringMatch` |
| `HttpRequestMirror` | opt `backend: Backend`, `numerator: i32`, `denominator: i32` (defaults 100/100) |
| `DirectResponse` | `status_code: i32`, `body: String` |
| `BackendHttpFilter` | `name` (format `<ns>:<name>:<port>`, matching the cluster name), opt `request_header_filter`, opt `response_header_modifier` |
| `HttpExternalAuthFilter` | `backend: Backend` (required), `protocol: GRPC \| HTTP`, `path_prefix`, `allowed_request_headers: Vec<String>`, `allowed_response_headers: Vec<String>`, opt `forward_body: { max_size: u32 }` |
| `HttpCorsFilter` | `allow_origins`, `allow_credentials: bool`, `allow_methods`, `allow_headers`, `expose_headers`, `max_age: i32` — serde names are **camelCase** here (`allowOrigins`, …), unlike the rest of the model; that inconsistency is in the harvested fixtures and is therefore frozen |
| `Timeout` | opt `request: Duration`, opt `backend: Duration` |
| `HttpRetry` | `codes: Vec<u32>`, opt `attempts: i32`, opt `backoff: Duration` |
| `TlsSecret` | `name`, `namespace` — used as a **map key**, so it must be hashable and totally ordered |

### 4.9 Supporting types

```
FullyQualifiedResource { name, namespace, group, version, kind, uid }
    // namespace == "" means cluster-scoped

Infrastructure { labels: BTreeMap<String,String>, annotations: BTreeMap<String,String> }
    // note: serialized with CAPITALIZED keys "Labels"/"Annotations" in the
    // reference's goldens; flowsdn keeps those names for fixture compatibility

ServerHeaderTransformation = OVERWRITE | APPEND_IF_ABSENT | PASS_THROUGH   // default OVERWRITE
L4Protocol                 = TCP | UDP
ExternalAuthProtocol       = GRPC | HTTP
AccessLogsFormat           = Text | JSON
AccessLogsTarget           = HTTP | TCP
```

`ServiceParams` (the model's own subset of a Kubernetes `ServiceSpec`; named
`Service` in the reference, renamed here so it cannot be confused with the
Kubernetes object — **DEVIATION**, cosmetic, serde names unchanged):

| Field | Type | serde |
|---|---|---|
| `type` | `String` | `type` (default `LoadBalancer`) |
| `insecure_node_port` | opt `u32` | `insecure_node_port` (Ingress NodePort, the `:80` port) |
| `secure_node_port` | opt `u32` | `secure_node_port` (Ingress NodePort, the `:443` port) |
| `external_traffic_policy` | `String` | `external_traffic_policy` |
| `load_balancer_class` | opt `String` | `load_balancer_class` |
| `load_balancer_source_ranges` | `Vec<String>` | `load_balancer_source_ranges` |
| `load_balancer_source_ranges_policy` | `String` | `load_balancer_source_ranges_policy` (`Allow` \| `Deny`, default `Allow`) |
| `ip_families` | `Vec<String>` | `ip_families` |
| `ip_family_policy` | opt `String` | `ip_family_policy` |
| `allocate_load_balancer_node_ports` | opt `bool` | `allocate_load_balancer_node_ports` |
| `traffic_distribution` | opt `String` | `traffic_distribution` |

`Telemetry { access_logs: Map<AccessLogsTarget, Vec<AccessLogs>>,
namespaced_name: (namespace, name) }` and
`AccessLogs { format, text: String, json: Map<String,String> }`. The format
strings may contain two flowsdn-specific operators, `%CILIUM_GATEWAY_NAME%`
and `%CILIUM_GATEWAY_NAMESPACE%`, substituted from `namespaced_name` at
translation time — including inside JSON *values*.

### 4.10 `CiliumGatewayClassConfig` (`cilium.io/v2alpha1`, namespaced)

Short name `cgcc`, status subresource, storage version. Printer columns:
`Accepted` (`.status.conditions[?(@.type=="Accepted")].status`), `Age`,
`Description` (priority 1). Spec 13 §4.1 owns its registration.

```
spec:
  description:  string, maxLength 64
  service:      ServiceConfig
  httpOptions:  { grpcWebTranslation: { enabled: bool, default true } }
  telemetry:    { accessLogs: [AccessLogs], minItems 1, maxItems 8 }
  envoy:        { serverHeaderTransformation: OVERWRITE|APPEND_IF_ABSENT|PASS_THROUGH }
```

`ServiceConfig`:

| Field | Type | Default / constraint |
|---|---|---|
| `type` | enum `LoadBalancer` \| `NodePort` | `LoadBalancer` |
| `externalTrafficPolicy` | `Cluster` \| `Local` | `Cluster` |
| `loadBalancerClass` | opt string | applied only when `type: LoadBalancer` |
| `ipFamilies` | list, atomic | |
| `ipFamilyPolicy` | opt | |
| `allocateLoadBalancerNodePorts` | opt bool | `LoadBalancer` only |
| `loadBalancerSourceRanges` | list, atomic | `LoadBalancer` only |
| `loadBalancerSourceRangesPolicy` | `Allow` \| `Deny` | `Allow` |
| `trafficDistribution` | opt string | |

`AccessLogs`: `format` (required, `JSON` \| `Text`), `json` (map, 1–64
entries), `text` (1–4096 chars), `targets` (set of `HTTP`/`TCP`, minItems 1,
default `[HTTP]`). Both `json` and `text` carry substantial defaults matching
Envoy's standard access-log fields; flowsdn MUST ship the same defaults in its
CRD YAML, because they are part of the CRD's schema and therefore part of the
compatibility surface (spec 13's vendor-verbatim rule applies).

**There is deliberately no host-network, node-selector, listener-port,
resources, labels or annotations field on this CRD.** Host network and node
selection are operator-level configuration (§6.1); labels and annotations on
generated objects come from `Gateway.spec.infrastructure`. Adding them here
would give a namespace-scoped object control over cluster-scoped behavior.

### 4.11 What translation produces

| Object | Content |
|---|---|
| `CiliumEnvoyConfig` | `spec.services[]`, `spec.backendServices[]`, `spec.resources[]` (Listener, RouteConfiguration, Cluster — in that order), `spec.nodeSelector`; annotation `cec.cilium.io/use-original-source-address`. Schema and agent handling: spec 16 §3.4 |
| `Service` | §2.3 naming, ports from the listeners, spec fields from `ServiceParams` merged with config defaults (§5.8) |
| `EndpointSlice` | one dummy slice for the L7 path; one skeleton per (backend Service, port, IP family) for the L4 path (§5.10) |

The dummy L7 `EndpointSlice` carries exactly one endpoint, address
`192.192.192.192`, `conditions.ready: true`, and one port `9999`. It exists
because the agent refuses to install a service entry in the LB maps for a
Service with no backends, and the generated Service's "backend" is Envoy
itself, reached by a proxy redirect rather than by an endpoint. `ready` MUST be
set explicitly: Kubernetes treats a nil `ready` as ready, but some consumers
(cloud NEG controllers) require the field present.

---

## 5. Algorithms

### 5.1 Hostname intersection

`compute_hosts(route_hostnames, listener_hostname, other_listener_hostnames)`
returns the hostnames a route contributes on a given listener. Empty result ⇒
the route does not attach (`NoMatchingListenerHostname`).

Definitions. `*` is the global wildcard. A *wildcard hostname* starts `*.` and
must have at least one further label. `matches_wildcard(h, w)`: `h` ends with
`w` minus its leading `*`, **and** at least one character is consumed by the
wildcard (so `foo.com` does not match `*.foo.com`).

`wildcards_intersect(a, b)`: true if either is `*`; otherwise both must be
well-formed `*.x`; compare labels right to left, stopping at the first `*`;
require all compared labels equal and at least one compared.

`isolated(route_h, listener_h, others)`: true when some *other* listener
hostname either equals `route_h`, or is a wildcard matching `route_h` **and is
strictly longer than** `listener_h`. This is the Gateway API's HTTP listener
isolation rule: a more specific listener claims the hostname, and the less
specific one must not also serve it.

The algorithm, per route hostname, first match wins:

| # | Condition | Contributes |
|---|---|---|
| 0 | `route_hostnames` is empty | `[listener_hostname]` if non-empty, else `["*"]` — and stop |
| 1 | `listener_hostname` is empty | `route_h`, unless `isolated` |
| 2 | `listener_hostname == route_h` | `route_h` |
| 3 | both are wildcards, `wildcards_intersect`, not `isolated` | **whichever has more DNS labels** |
| 4 | `listener_hostname` is a wildcard and `matches_wildcard(route_h, listener_hostname)`, not `isolated` | `route_h` |
| 5 | `route_h` is a wildcard and `matches_wildcard(listener_hostname, route_h)` | `listener_hostname` |
| 6 | otherwise | nothing |

The result is sorted stably by specificity (§5.2). Rule 3's "more labels wins"
is the non-obvious one: `*.foo.example.com` on a listener and `*.example.com`
on a route intersect, and the *more specific* of the two is what Envoy must
match on, otherwise the route would swallow siblings.

For SNI purposes only (the cross-protocol split check, §3.5 rule 4) the
simpler `sni_hostnames_intersect(a, b)` is used: `*` on either side intersects
everything; two wildcards intersect per `wildcards_intersect`; a wildcard and
a concrete name intersect per `matches_wildcard`; two concrete names intersect
iff equal.

### 5.2 Hostname specificity ordering

`sort_hostnames(a, b)`, stable, most specific first:

1. `a == b` → equal.
2. The bare `*` always sorts **last**.
3. More DNS labels first — **except** that if the longer one begins with a
   wildcard label and the shorter one does not, the shorter (concrete) one
   wins, because a leading wildcard makes a name less specific despite being
   longer.
4. Trim a leading wildcard label from both and compare label counts again;
   more labels first.
5. Tie-break: byte-wise lexical ascending.

### 5.3 Route precedence (the Envoy route order)

Envoy matches routes sequentially inside a virtual host, so the model's set
semantics must be flattened into a total order. flowsdn sorts with a **stable**
sort using this comparator, "greater" meaning "earlier in the list":

| # | Key | Direction |
|---|---|---|
| 1 | length of the exact path match (`0` when not an exact match) | descending |
| 2 | length of the regex path match (`0` when not a regex match) | descending |
| 3 | `max(len(path_separated_prefix), len(prefix))` | descending |
| 4 | presence of a `:method` matcher — a route that constrains the method sorts before one that does not; if both do, the method strings compare **ascending** | see left |
| 5 | number of header matchers, excluding flowsdn's own redirect guard | descending |
| 6 | number of query-parameter matchers | descending |

The stable sort is load-bearing: routes that tie on all six keys keep the
order ingestion produced, which is Gateway-API rule order, which is what
conformance expects.

**The redirect guard.** When a route carries a scheme redirect, flowsdn adds an
inverted, case-insensitive `X-Forwarded-Proto` header matcher so the redirect
does not loop. That matcher is flowsdn's, not the user's, and MUST be excluded
from key 5 — otherwise adding a redirect silently promotes a route above its
siblings. It is identified by the triple (name `X-Forwarded-Proto`, inverted,
`ignore_case` set); user-written `X-Forwarded-Proto` matchers do not set
`ignore_case` and are counted normally.

### 5.4 Route aggregation

Model routes are grouped before emission; each group becomes **one** Envoy
route whose action lists all the group's backends.

The grouping key is:

- the route's **rule identity** (`source`, `rule_index`, `match_index`) when
  `source_rule` is set, or
- the route's **match key** otherwise.

The match key is the ordered concatenation
`method:<M>| path:<path_match>| header:<kv>|… query:<kv>|… [redirect:true|] [auth:<proto>:<ns>:<name>[:<port>]|]`,
with the header and query lists each sorted by their rendered string.

Ingestion sets `source_rule` and then **clears it again** for every group whose
match key was produced by only one rule index. The effect: two identical
matches coming from two *different* Gateway API rules stay separate (so rule
precedence is preserved and the first rule wins), while everything else
aggregates by match as before. This is subtle and it is the reason
`source_rule` exists; implementing aggregation on the match key alone silently
merges two rules that the Gateway API says must be ordered.

### 5.5 Path, header and query matching

**Path**, first match wins — note this order differs from `StringMatch`'s own
rendering order (§4.6):

| Model | Envoy |
|---|---|
| `exact` non-empty | `path: <exact>` |
| `prefix == "/"` | `prefix: "/"` |
| `prefix` non-empty otherwise | `path_separated_prefix: <prefix with trailing "/" trimmed>` |
| `regex` non-empty | `safe_regex: <regex>` (RE2, unanchored) |
| all empty | `prefix: "/"` |

`path_separated_prefix` is what gives path-segment semantics; a plain `prefix`
would make `/foo` match `/foobar`.

**Headers.** Emitted in this order: the authority regex (below, Ingress only),
then the user's header matchers sorted by rendered string, then the `:method`
matcher with the method **upper-cased**.

**The authority regex.** When `host_name_suffix_match` is false — which is the
Ingress configuration — a hostname containing `*` but not equal to `*` gets an
extra `:authority` regex matcher so that the wildcard consumes exactly one DNS
label:

```
*.foo.com   →   ^[^.]+[.]foo[.]com$
foo.com     →   ^foo[.]com$          (dots escaped as [.])
```

Gateway API sets `host_name_suffix_match` **true** and relies on the virtual
host's `domains` for wildcard matching instead, where `*.example.com` is an
Envoy suffix match and does match `a.b.example.com`. The two front ends
therefore differ in wildcard semantics, deliberately, because the Ingress spec
and the Gateway API spec differ. flowsdn MUST NOT unify them.

**Query parameters** become `QueryParameterMatcher { name, string_match }`,
sorted by rendered string.

**String matcher** selection for headers and query values: `exact` → `prefix`
→ `regex`, first non-empty.

### 5.6 Clusters, weights and backend protocol

| Thing | Value |
|---|---|
| Cluster name | `<namespace>:<name>:<port>` — colons, never a slash, because a slash would make the agent's name-qualification pass rewrite it (spec 16 §3.4.2 step 2) |
| EDS `service_name` | `<namespace>/<name>:<port>` |
| gRPC ext-authz cluster | `grpc:` + the cluster name |
| HTTP ext-authz cluster | `http:` + the cluster name |
| Discovery type | `EDS`, with the config source coming from the agent |
| LB policy | `ROUND_ROBIN` |
| Outlier detection | `split_external_local_origin_errors: true`, nothing else |
| Idle timeout | `cluster-idle-timeout` (§6.1), applied unconditionally including when 0 |
| Default protocol | `use_downstream_protocol_config` with HTTP/2 allowed — i.e. mirror the client |

Protocol override, first match wins:

1. the route is gRPC (`is_grpc`) → explicit HTTP/2;
2. `use-app-protocol` is on and the backend's `appProtocol` is
   `kubernetes.io/h2c` → explicit HTTP/2;
3. `use-app-protocol` is on, any other `appProtocol` → explicit HTTP/1.1;
4. otherwise leave `use_downstream_protocol_config`.

**Weights.** A backend with no weight counts as **1**. A negative weight is
clamped to 0. A single backend emits `route.cluster`; two or more emit
`weighted_clusters` with per-cluster weights and **no** `total_weight` — Envoy
sums them. A rule where every backend failed to resolve emits a 500
`direct_response` instead (§3.7); one where some resolved keeps the survivors
with their original weights, and the failures' weight is simply absent from
the sum, which shifts traffic to the survivors proportionally. That is the
Gateway API's specified behavior and it is why weights must not be
renormalized.

**Upstream TLS** (`BackendTLSPolicy`) is applied only when the origination
record is complete — SNI set, CA ref set with both name and namespace.
Anything less emits **no** transport socket, i.e. plaintext. Combined with
§3.11.7's rule that a *broken* policy drops the backend entirely, the three
states are distinct: no policy → plaintext; valid policy → TLS; invalid policy
→ no backend. When TLS is originated, the context sets the SNI, caps the
maximum version at TLS 1.3, and validates against an SDS secret named
`<secrets namespace>/<synced ConfigMap name>` (§3.12.3).

### 5.7 Listener and route-configuration layout

**Combined layout** (the default, when `needs_per_port_listeners()` is false):
one Envoy `Listener` named `listener`, carrying

1. one plaintext filter chain (`transport_protocol: raw_buffer`) whose HCM
   stat prefix and RDS route config name are both `listener-insecure`;
2. one TLS filter chain **per TLS secret**, secrets ordered by
   `<namespace>/<name>`, matching on `transport_protocol: tls` plus the sorted
   unique SNI names of the hostnames using that secret, with HCM name and RDS
   name `listener-secure`;
3. one passthrough filter chain per (listener, route) with backends, matching
   on that route's hostnames, holding a `tcp_proxy`.

**Per-port layout** (when there is more than one HTTPS port, more than one
passthrough port, or a cross-protocol SNI overlap across ports): a base
`listener` for the plaintext ports, plus one `listener-<port>` per HTTPS port
and, when passthrough also needs splitting, one `listener-<port>` per
passthrough port. The HCM name and RDS route config name for a per-port
listener are both `listener-<port>`.

A filter chain match whose SNI set contains `*` MUST omit `server_names`
entirely — Envoy rejects `*` as a server name, and an omitted `server_names`
is the correct "any SNI" match.

**Route configuration names** are `listener-<key>` where `<key>` is
`insecure`, `secure`, or the decimal port. The HCM's RDS name must equal it
exactly or Envoy drops every request on that chain. Configured-but-routeless
ports still get an **empty** RouteConfiguration, so the RDS reference resolves
and Envoy returns 404 instead of stalling. Port keys are sorted with
`insecure` forced first and the rest compared lexically — so `1443` sorts
before `443`. That is textual, not numeric, and it is frozen because the
goldens encode it.

**Virtual hosts.** Each hostname contributes two `domains` entries, `host` and
`host:*`, so a request carrying an explicit port in `:authority` still
matches. If any hostname is `*`, `domains` is exactly `["*"]` and nothing
else. The virtual host's `name` is its first domain. Virtual hosts are sorted
by name.

**Force-HTTPS.** For an Ingress hostname with `force_http_to_https_redirect`,
the *insecure* route configuration gets a virtual host for that hostname whose
routes all redirect, built from that hostname's *secure* routes, and the
hostname is then excluded from the normal insecure virtual host. The redirect
action is `https_redirect: true` with **no explicit response code**, which
means Envoy's default **301 Moved Permanently**.

> The reference's flag help and Helm chart both say this redirect is a **308**.
> It is a 301. flowsdn keeps 301 for byte-compatibility with the harvested
> goldens and **fixes the documentation** rather than the behavior; changing
> the code would change caching semantics for every existing user. Open
> decision 5 revisits making the code configurable.

### 5.8 The generated Service

Ports come from the listeners: one entry per (port, L4 protocol), sorted by
port then TCP-before-UDP, named `port-<n>` for TCP and `port-<n>-udp` for UDP
(Gateway API), or `http`/`https` on 80/443 (Ingress).

| Spec field | Rule |
|---|---|
| `type` | host network → `NodePort` (Gateway API) or `ClusterIP` (Ingress); else `ServiceParams.type`; else `LoadBalancer` |
| `externalTrafficPolicy` | host network → **unset**; else `ServiceParams`; else the config key |
| `loadBalancerClass`, `loadBalancerSourceRanges`, `allocateLoadBalancerNodePorts` | only when the **effective** type is `LoadBalancer`; otherwise unset |
| `ipFamilies` | `ServiceParams`; else derived from the enabled IP families |
| `ipFamilyPolicy` | `ServiceParams`; else `PreferDualStack` when both families are enabled; else unset |
| `trafficDistribution` | `ServiceParams` or unset |
| `clusterIP` | always the empty string (let the API server assign) |

**Apply semantics** matter as much as the content. On update, flowsdn replaces
`spec` and `ownerReferences` but **merges** labels and annotations (never
removes), and it **preserves an externally-set `spec.loadBalancerClass`** by
reading the live value before the patch and writing it back — cloud providers'
mutating webhooks set that field, and clobbering it every reconcile makes the
Service flap between two controllers.

### 5.9 Name shortening

Kubernetes object names are limited to 63 characters. Every generated name is
passed through:

```
shorten(s) = s                                    if len(s) <= 63
           = s[..52] + "-" + encode(sha256_hex(s)[..10])
```

where `encode` substitutes `0→g, 1→h, 3→k, a→m, e→t` over those 10 characters
(the `kubectl` name-hash alphabet, which avoids names that look like numbers).
The function is deterministic and stable across restarts.

Note the consequence, which is a real operational sharp edge: the dedicated
Ingress `Service` (`cilium-ingress-<name>`) and its `CiliumEnvoyConfig`
(`cilium-ingress-<ns>-<name>`) are shortened **independently**, so a long
Ingress name yields two objects with different hash suffixes. That is
compatible with the reference and must not be changed, but it means an
operator grepping for one name will not find the other.

### 5.10 L4 EndpointSlice reconciliation

The L4 path does not go through Envoy, so the generated Service needs real
endpoints. Two controllers share the object, with a strict ownership split
that exists to stop them overwriting each other:

| Owner | Fields |
|---|---|
| Gateway reconciler | identity: `ports[].name`, `ports[].protocol`, labels, annotations, owner references, and deletion of stale slices. Creates slices with **empty** `endpoints` |
| EndpointSlice reconciler | data: `endpoints`, and the resolved numeric value written to every `ports[].port` |

Slices are grouped by (backend namespace, backend name, backendRef port,
protocol, IP family) and named
`shorten(<lb service name>-<sha256(ns/name|port|proto)[..8]>-<ipv4|ipv6>)`.
They carry `kubernetes.io/service-name`,
`endpointslice.kubernetes.io/managed-by: cilium-operator`, the gateway-name
label, and the annotations `gateway.cilium.io/backend-service`,
`gateway.cilium.io/backend-port` and — when the backend is weighted —
`service.cilium.io/weight` (clamped to 65535).

Backend port resolution, in order: match the `EndpointPort` by **name** against
the `ServicePort` name; else match numerically against the ServicePort's
integer `targetPort`; else, if the backend slice has exactly one port, use it.
A backend Service that disappears, or that stops exposing the port, clears the
endpoints rather than leaving stale ones — traffic to a removed backend must
fail closed.

A slice whose `AddressType` is not among the backend Service's `ipFamilies` is
dropped (unless the Service is missing or declares no families).

### 5.11 Determinism

Every collection that reaches the output is ordered by an explicit rule.
Collected here because a single missed one produces a CEC that rewrites itself
on every reconcile, which is invisible in a unit test and obvious only as
apiserver write amplification in a real cluster:

| Collection | Order |
|---|---|
| `backendServices[]` | namespace, then name, then first port |
| a backend's `number[]` | sorted, unique, as strings |
| `services[].ports` | ascending numeric |
| Envoy clusters | by cluster name |
| TLS filter chains | by `<secret namespace>/<secret name>` |
| filter-chain `server_names` | sorted, unique |
| passthrough listeners | (port, address, hostname, name) |
| passthrough routes | (hostnames key, backends key, name) |
| passthrough backends | (namespace, name, port string, weight) |
| route-config port keys | `insecure` first, then lexical |
| virtual hosts | by name |
| routes within a virtual host | §5.3, stable |
| header and query matchers | by rendered `KeyValueMatch` string |
| hostnames | §5.2 |
| Ingress listeners | insecure by hostname, then secure by hostname |
| shared-mode Ingress merge | `<namespace>/<name>` |
| ListenerSets | creationTimestamp, then `<namespace>/<name>` |
| L4 route conflict resolution | creationTimestamp, then namespace, then name; **only the first survives** |
| Node addresses (host network) | parsed, unmapped, sorted, capped at 16 |

Rust's `HashMap` iteration order is randomized per process, which makes a
missed sort here fail *intermittently* rather than consistently. flowsdn
therefore uses `BTreeMap`/`BTreeSet` throughout ingestion and translation, and
a lint forbids `HashMap` in the `flowsdn-gateway` model and translation
modules.

---

## 6. Configuration

All keys are reference-compatible names in the `cilium-config` ConfigMap.
Spec 12 §6.8 lists the same keys as the operator's trigger surface; this
section is the authority on what each one *does*.

### 6.1 Gateway API

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-gateway-api` | bool | `false` | master switch. Requires `kube-proxy-replacement`; without it, log one warning and disable (spec 12 §3.15) |
| `enable-gateway-api-secrets-sync` | bool | `true` | register Gateway/ListenerSet certificateRefs and BackendTLSPolicy CA ConfigMaps with the sync controller |
| `enable-gateway-api-proxy-protocol` | bool | `false` | prepend a PROXY-protocol listener filter to **every** Gateway listener. Once on, only PROXY-protocol traffic is accepted |
| `enable-gateway-api-app-protocol` | bool | `false` | honour the backend Service port's `appProtocol` (GEP-1911) when choosing the upstream protocol (§5.6) |
| `enable-gateway-api-alpn` | bool | `false` | advertise ALPN on every TLS filter chain. **Also implies app-protocol handling**: a backend that wants HTTP/2 must say so via `appProtocol` |
| `gateway-api-secrets-namespace` | string | `cilium-secrets` | where synced TLS material lands; agent RBAC is scoped to it |
| `gateway-api-service-externaltrafficpolicy` | string | `Cluster` | `Cluster` \| `Local` for generated Services. **Invalid value is fatal** — it is a configuration typo, not a cluster state. Ignored (with a warning) when host network is on |
| `gateway-api-use-remote-address` | bool | `true` | Envoy `use_remote_address` on every HCM |
| `gateway-api-xff-num-trusted-hops` | u32 | `0` | Envoy `xff_num_trusted_hops`; only emitted when > 0 |
| `gateway-api-hostnetwork-enabled` | bool | `false` | §3.10 |
| `gateway-api-hostnetwork-nodelabelselector` | string | `""` | comma-separated `k=v` list → `matchLabels`. Malformed pairs are skipped silently; empty means all nodes |

### 6.2 Ingress

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-ingress-controller` | bool | `false` | master switch; also requires `kube-proxy-replacement` |
| `enable-ingress-secrets-sync` | bool | `true` | |
| `enable-ingress-proxy-protocol` | bool | `false` | as above, for Ingress listeners |
| `enforce-ingress-https` | bool | `true` | emit an HTTP→HTTPS redirect for hosts that appear in `spec.tls[].hosts`. **Emits 301, not 308** (§5.7) |
| `ingress-default-lb-mode` | string | `dedicated` | `dedicated` \| `shared` |
| `ingress-shared-lb-service-name` | string | `cilium-ingress` | name of the shared CEC, and of the Helm-created shared Service |
| `ingress-secrets-namespace` | string | `cilium-secrets` | |
| `ingress-default-secret-namespace` / `-name` | string | `""` | fallback TLS secret for `spec.tls[]` entries with no `secretName`. Used **only when both are non-empty** |
| `ingress-default-request-timeout` | duration | `0` | route request timeout; per-Ingress annotation overrides |
| `ingress-default-xff-num-trusted-hops` | u32 | `0` | |
| `ingress-use-remote-address` | bool | `true` | |
| `ingress-lb-annotation-prefixes` | list | `lbipam.cilium.io`, `nodeipam.cilium.io`, `service.beta.kubernetes.io`, `service.kubernetes.io`, `cloud.google.com` | prefixes of Ingress annotations **and labels** copied onto the dedicated Service |
| `ingress-hostnetwork-enabled` | bool | `false` | |
| `ingress-hostnetwork-shared-listener-port` | u32 | `8080` | fallback for all three per-protocol ports |
| `ingress-hostnetwork-http-listener-port` | u32 | `0` | 0 ⇒ use the shared port |
| `ingress-hostnetwork-https-listener-port` | u32 | `0` | 0 ⇒ use the shared port |
| `ingress-hostnetwork-tls-passthrough-listener-port` | u32 | `0` | 0 ⇒ use the shared port |
| `ingress-hostnetwork-nodelabelselector` | string | `""` | |

> The reference's compiled-in default for `ingress-lb-annotation-prefixes`
> omits `nodeipam.cilium.io` while its Helm chart includes it, so an operator
> started without the ConfigMap key behaves differently from one started by
> Helm. flowsdn adopts the **Helm** list as the compiled-in default, so the two
> agree. **DEVIATION**, additive: the only effect is that one more annotation
> prefix propagates by default.

### 6.3 Shared with the L7 proxy (spec 16 §6.1)

| Key | Default | Use here |
|---|---|---|
| `proxy-idle-timeout-seconds` | `60` | Envoy cluster `idle_timeout` |
| `proxy-stream-idle-timeout-seconds` | `300` | HCM `stream_idle_timeout` |
| `enable-ipv4` / `enable-ipv6` | | generated Service `ipFamilies`, host-network bind addresses, HCM internal-address CIDRs |
| `enable-envoy-config` | | implied true whenever either front end is on |

### 6.4 Fixed, not configurable

Values the reference hard-codes per front end. flowsdn keeps them fixed and
records them so nobody looks for a key:

| Behavior | Gateway API | Ingress |
|---|---|---|
| `host_name_suffix_match` (§5.5) | `true` | `false` |
| `use_app_protocol` | from `enable-gateway-api-app-protocol` | always `false` |
| TCP keep-alive on listeners | enabled, idle 10 s, interval 5 s, 10 probes | same |
| HCM `common_http_protocol_options.max_stream_duration` | `0s` (disables Envoy's default 15 s route timeout) | same |
| websocket upgrade | enabled | enabled |
| HCM internal-address CIDRs | `10/8`, `172.16/12`, `192.168/16`, `127.0.0.1/32`, `::1/128` | same |
| HTTP filter chain order | grpc_web (if enabled), grpc_stats, ext_authz…, cors (if used), router | same |

### 6.5 Ingress annotations

Canonical prefix `ingress.cilium.io/`; the legacy prefix `io.cilium.ingress/`
is accepted as an alias where noted, and the canonical key wins when both are
present.

| Annotation | Legacy alias | Values | Default | Effect |
|---|---|---|---|---|
| `loadbalancer-mode` | yes | `dedicated`, `shared` | `ingress-default-lb-mode` | §3.9. Any other value falls back to the default |
| `service-type` | yes | `LoadBalancer`, `NodePort` | `LoadBalancer` | dedicated Service type; anything else warns and defaults |
| `loadbalancer-class` | no | any string | unset | `spec.loadBalancerClass`, only when the type is `LoadBalancer` |
| `service-external-traffic-policy` | no | `Cluster`, `Local` | unset | dedicated Service `externalTrafficPolicy` |
| `insecure-node-port` | yes | int32 | unset | NodePort for the `:80` port |
| `secure-node-port` | yes | int32 | unset | NodePort for the `:443` port |
| `host-listener-port` | no | int | `8080` | host-network dedicated mode: sets all three listener ports |
| `tls-passthrough` | yes | `enabled`, or a bool | `false` | route via SNI passthrough instead of HTTP |
| `force-https` | no | `enabled`, `disabled`, or a bool | `enforce-ingress-https` | per-Ingress override, authoritative in **both** directions |
| `request-timeout` | no | Go duration (`30s`, `1m30s`) | `ingress-default-request-timeout` | route request timeout; an unparseable value warns and falls back |
| `kubernetes.io/ingress.class` | — | `cilium` | — | legacy class selector, §3.9 |

**Passthrough constraints.** A passthrough Ingress rule MUST set `host`; its
paths MUST be exactly `/`; `spec.defaultBackend` is ignored. Each violation is
logged and skipped, and a host left with no valid rules drops its listener.
These are not arbitrary: SNI routing has no path visibility, so a path rule
would be silently ineffective.

**Class resolution order** is: the legacy annotation first, then
`spec.ingressClassName`. That inverts the usual Kubernetes precedence, where
the field wins over the deprecated annotation. flowsdn keeps the reference's
order for compatibility and flags it in Open decision 4.

---

## 7. Failure modes

| Failure | Behavior |
|---|---|
| **Gateway API CRDs missing** | controllers do not start; health module `degraded`; the operator keeps running (spec 12 §3.15). A user who has not installed the CRDs is not a broken operator |
| **API server unreachable at startup** | retry with backoff, `degraded`; fatal after 30 s so the pod restarts |
| **`kube-proxy-replacement` false** | one warning, feature disabled, operator healthy |
| **Two listeners conflict** | both marked `Conflicted`, both drop out; the rest of the Gateway still programs. A conflict never takes down a whole Gateway |
| **Cross-source listener conflict** | the later source loses; the Gateway's own listeners always win over a ListenerSet's |
| **All listeners invalid** | `Accepted: False, ListenersNotValid`; the CEC is **deleted**, the Service is kept so the address is stable |
| **Backend Service missing** | `ResolvedRefs: False, BackendNotFound`; the rule emits a 500 `direct_response` if *all* its backends failed, otherwise the survivors carry the traffic. Never a silent fall-through to a broader route |
| **Backend port not exposed** | as above, `Service port <n> could not be resolved` |
| **Cross-namespace ref with no grant** | `RefNotPermitted`; the reference is dropped **and the object is not read**. Deleting a grant revokes the config and removes the synced Secret |
| **Certificate Secret missing, wrong type, or malformed PEM** | `ResolvedRefs: False, InvalidCertificateRef`; the listener does not program. flowsdn MUST NOT fall back to a plaintext listener on the same port — that would downgrade TLS silently |
| **BackendTLSPolicy invalid** | the backend is **dropped**, not downgraded to plaintext (§3.11.7) |
| **Secret sync disabled but certificateRefs present** | translation still emits the synced SDS name; one `warn` per Gateway; the administrator owns the secrets namespace |
| **Synced-secret name collision with a hand-made object** | the sync controller refuses to overwrite an object with no ownership labels or with labels naming a different source, and logs the refusal (spec 12 §3.14) |
| **CEC apply rejected by the apiserver** | `Accepted`/`Programmed` both `False`, `NoResources`; retried with the controller's backoff. The previous CEC is left in place — a rejected update must not leave the data path empty |
| **Envoy NACKs the pushed config** | invisible to this spec; spec 16 §7 owns NACK handling. flowsdn's obligation here is that a NACK is *possible* to diagnose, which is why every generated resource name is deterministic |
| **Generated Service gets no address** | `Programmed: False, AddressNotAssigned`. Not an error, not a retry loop: the Service watch retriggers when LB IPAM or the cloud controller assigns one |
| **Ingress mode flip** | the other mode's objects are deleted in the same reconcile and the shared CEC is rebuilt; §9.2 tests it explicitly |
| **Ingress class removed** | all generated objects deleted; `status.loadBalancer` left alone, because another controller may now own the object |
| **Operator restart mid-apply** | every apply is idempotent and every generated name is a pure function of the source, so the next reconcile converges. No finalizers are used anywhere in this area |
| **Sweep before cache sync** | forbidden (§3.13). A sweep against an unsynced informer deletes live configuration |
| **Host-network port collision** | `Accepted: False, PortUnavailable` on the younger Gateway (§3.10, DEVIATION) |
| **Route attached to a Gateway that never programs** | `Accepted: False, GatewayNotProgrammed` so the route's owner sees why traffic never arrives |
| **Namespace terminating** | a `Forbidden` with cause `NamespaceTerminating` on create is treated as **success**, not an error: the namespace is going away and retrying is noise |

---

## 8. Observability

### 8.1 Metrics

Namespace `flowsdn_operator_`, reference-compatible where the reference has an
equivalent. New metrics carry the `gateway_` / `ingress_` prefix.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `gateway_api_reconcile_total` | counter | `controller`, `result` (`success`\|`error`) | reconciles per controller |
| `gateway_api_reconcile_duration_seconds` | histogram | `controller` | |
| `gateway_api_gateways` | gauge | `accepted`, `programmed` | Gateways by condition state |
| `gateway_api_listeners` | gauge | `state` (`accepted`\|`conflicted`\|`invalid`) | |
| `gateway_api_routes` | gauge | `kind`, `state` (`accepted`\|`rejected`) | |
| `gateway_api_translation_duration_seconds` | histogram | `frontend` (`gateway`\|`ingress`\|`gamma`) | ingestion + translation, excluding I/O |
| `gateway_api_generated_resources` | gauge | `kind` (`cec`\|`service`\|`endpointslice`) | operator-owned objects |
| `ingress_reconcile_total` | counter | `mode` (`dedicated`\|`shared`), `result` | |
| `ingress_shared_model_size` | gauge | — | Ingresses merged into the shared model |
| `gateway_api_status_writes_total` | counter | `kind` | status updates actually written |
| `gateway_api_status_writes_skipped_total` | counter | `kind` | status computations that matched and were not written |

The last pair is the one that matters operationally. A healthy cluster shows
`skipped` growing and `writes` flat; `writes` growing at steady state means
something in ingestion or translation is non-deterministic (§5.11), and this
is the cheapest place to see it.

### 8.2 Logging

Structured fields on every log line from this area: `controller`, `resource`
(`<namespace>/<name>`), `kind`, and where relevant `gateway`, `listener`,
`route`, `backend`, `secret`.

Levels: `info` for reconcile start/finish per object; `warn` for
user-correctable problems that also produce a condition (invalid annotation,
missing backend, ungranted reference) — the log is a convenience, the
condition is the contract; `error` only for genuine operator faults (apply
failed, apiserver error). A user typo MUST NOT log at `error`.

Kubernetes `Event`s are emitted on the source object for every condition
transition to a `False` state, and for Ingress — which has no conditions —
this is the *only* user-visible signal.

### 8.3 Health and debug

- One health module per controller, reporting `ok` / `degraded` with the
  reason, surfaced through the operator's `/healthz` (spec 12 §3.16).
- A debug endpoint dumps, for one Gateway or Ingress: the gathered input set,
  the serialized model, and the generated CEC/Service/EndpointSlice. Because
  the model is a serializable type with a stable wire form (§4), this dump is
  the same YAML the golden fixtures use — so a production problem can be
  turned into a regression test by copying the dump into `tests/golden/`.
  That property is worth the endpoint on its own.

---

## 9. Test plan

### 9.1 Harvested fixtures (ADR-0005)

Already in the tree at `tests/golden/`, harvested verbatim from the reference
at 7d68cfb394 with `PROVENANCE` files:

| Directory | Files | What it drives |
|---|---|---|
| `08-operator-gateway-api/` | 604 | end-to-end reconcile: input Kubernetes objects → expected Gateway/route/ListenerSet/BackendTLSPolicy status **and** expected CEC |
| `08-operator-model-ingestion/` | 324 | Kubernetes objects → serialized model |
| `08-operator-model-translation-gateway-api/` | 207 | model + config → CEC + Service |
| `08-operator-model-translation-ingress/` | 14 | model → CEC (Ingress shapes) |

**Layout and consumption.**

*Reconcile fixtures* (`08-operator-gateway-api/{gateway,gamma}/`): a `base/`
directory loaded into every scenario, then one directory per scenario holding
`input/` (Kubernetes YAML, possibly multi-document) and `output/` (one golden
file per expected object). The golden file name encodes the object:
`<gatewayName>.yaml`, `cec-<gw>.yaml`, `endpointslice-<name>.yaml`,
`httproute-<name>.yaml`, `tlsroute-`, `grpcroute-`, `tcproute-`, `udproute-`,
`backendtlspolicy-`, `listenerset-`.

*Ingestion fixtures*: `input-<kind>.yaml` files (gateway, gatewayclass,
gatewayclassconfig, httproute, service, serviceimport, backendtlspolicy,
namespace, …) plus `output-listeners.yaml`.

*Translation fixtures*: `input.yaml` (a model), optional `config-input.yaml`
(a translation config), and `cec-output.yaml` + `service-output.yaml`, or
`output-cec.yaml` in the Ingress tree.

**Harness rules**, in the Rust `flowsdn-gateway-golden` harness:

1. A missing `input-*.yaml` or `config-input.yaml` means "zero value", not an
   error. Most scenarios omit most inputs.
2. Comparison is **round-tripped**: the golden is deserialized into the typed
   object and re-serialized before comparing, so key order and formatting
   differences do not fail a test. Only semantic differences fail.
3. An empty or whitespace-only golden means "expect no such object".
4. Scenarios are discovered from the directory tree; adding a fixture
   directory adds a test with no code change. A scenario directory with no
   corresponding test MUST fail the suite, so a fixture cannot be silently
   orphaned.
5. Deliberate divergences (§12) are annotated in a single
   `EXPECTED-DIVERGENCE` file per fixture directory naming the scenario and
   the reason, never by editing the fixture. A re-harvest at a newer reference
   tag then stays a mechanical copy.

Anticipated divergences from flowsdn's own decisions: the `PortUnavailable`
host-network collision condition (§3.10), the reachable
`CiliumGatewayClassConfig` validation branch (§3.11.8), the corrected
HTTPS-redirect matcher (Open decision 2), and the `nodeipam.cilium.io`
default prefix (§6.2). Each MUST be annotated before the suite is declared
green.

### 9.2 Unit tests

Ingestion: path type mapping including the `Prefix: /` special case and the
trailing-slash trim; GRPC method → path match for all seven shapes; hostname
intersection (§5.1) against a table covering listener isolation, both-wildcard
"more labels wins", and the empty-route-hostnames case; redirect port
defaulting; mirror fraction arithmetic; rule-identity retention (§5.4) with
one rule and with two rules producing the same match; default-backend and
default-secret handling; the TLS-host listener copy.

Translation: route precedence (§5.3) as a table, including the redirect-guard
exclusion; path/header/query matcher selection; the authority regex for both
`host_name_suffix_match` settings; cluster naming and protocol selection for
all four cases; weights including absent, zero, negative and a single backend;
the combined-vs-per-port listener decision for every combination in
`needs_per_port_listeners()`; `server_names` omission when `*` is present;
route-configuration port key ordering (`insecure`, `1443`, `443`).

Controllers: conflict detection over the six-row predicate; cross-source
precedence; ListenerSet allow/deny including all the unset cases;
condition merge (no write when unchanged, `lastTransitionTime` stability);
route parent status pruning with a foreign controller's entry present;
name shortening at 62/63/64 characters.

Ingress: class resolution for all six combinations of field, annotation and
default-class; **mode flip** dedicated→shared→dedicated leaving no orphans;
shared-model merge order; passthrough rule rejection cases.

### 9.3 Property tests

- Translation is idempotent: `translate(m) == translate(m)` across processes
  (this is the §5.11 determinism check, and it MUST run with a randomized hash
  seed).
- Round-trip: `model → yaml → model` is the identity for arbitrary models.
- Route order is a total order: the §5.3 comparator is antisymmetric and
  transitive over generated route sets.
- Hostname intersection is symmetric where it should be:
  `sni_intersect(a,b) == sni_intersect(b,a)`.

### 9.4 Ingress conformance (stage 1 gate)

Run `ingress-controller-conformance` with `-ingress-class cilium` against a
live cluster in CI. This is an external Go binary. **DEVIATION** from
ADR-0005's "all harnesses in Rust": the suite is a *conformance* definition
owned by upstream, not a test flowsdn writes, and reimplementing it would
prove compatibility with our reading of the spec rather than with the spec.
The same reasoning applies to §9.5. flowsdn writes no Go; it runs a published
binary.

### 9.5 Gateway API conformance (stage 2 gate, recommended)

**flowsdn SHOULD run the upstream Gateway API conformance suite in CI**, at the
pinned version, for the profiles in §2.4, and SHOULD publish the conformance
report. The recommendation is strong for three reasons:

1. The 604 harvested fixtures pin *the reference's* behavior at one commit.
   Conformance pins *the specification's* behavior, and where the two disagree
   the specification is right. Only one of these two suites can tell flowsdn
   that the reference had a bug.
2. Conformance is the only credible external claim that flowsdn implements the
   Gateway API. Without a report, "Gateway API support" is an assertion.
3. It is a fixed cost: a kind cluster, the pinned suite, and the profile list.
   Everything expensive — the behavior — is already being built.

The suite is run with the flags in §2.4. The two skips and the exempt-feature
list are the only permitted deviations, and both are tracked in §12.

### 9.6 End-to-end

Against a live cluster with Envoy: HTTP and HTTPS through a Gateway;
host-based and path-based Ingress; TLS passthrough; a weighted split verified
statistically; a mirror verified by counting requests at the mirror backend;
a redirect and a rewrite; a request timeout and a retry; CORS preflight;
cross-namespace backend with and without a grant; a certificate rotation
observed to take effect without a connection reset for existing streams; an
operator restart with no traffic interruption; Gateway deletion removing every
generated object.

---

## 10. Kernel and platform requirements

None of its own. This area runs in the operator, in userspace, and produces
Kubernetes objects. Its requirements are inherited:

- **Kubernetes** ≥ 1.26 (spec 13 §10.2), with the Gateway API CRDs at v1.6.1
  installed by the administrator, and `EndpointSlice` (`discovery.k8s.io/v1`).
- **Datapath**: `kube-proxy-replacement` enabled, which is what makes an L7
  proxy redirect on a service frontend possible (spec 05).
- **Envoy**: the external `cilium/proxy` DaemonSet (ADR-0001), reachable by
  the agent's xDS server (spec 16). The Envoy version determines which
  extension types the generated protobufs may use; flowsdn pins the Envoy
  image digest and the vendored `data-plane-api` protos together, and a
  mismatch is a build failure, not a runtime NACK.
- **x86-64 and arm64** are both first class; nothing here is architecture
  dependent.

---

## 11. Rust design notes

### 11.1 Crate `flowsdn-gateway`

One crate, four modules, with a strict dependency direction —
`model ← ingest`, `model ← translate`, and `controller` depending on all
three. `model` depends on nothing but `serde` and the k8s API types.

| Module | Contents |
|---|---|
| `model` | §4 types, the derived queries, hostname intersection and ordering (§5.1, §5.2). **No I/O, no k8s client, no Envoy types.** |
| `ingest` | `gateway.rs`, `ingress.rs`, `gamma.rs`, each a pure `fn(Input) -> (Model, Vec<StatusUpdate>)` |
| `translate` | `cec.rs`, `listener.rs`, `hcm.rs`, `route_config.rs`, `virtual_host.rs`, `cluster.rs`, plus `frontend/gateway.rs` and `frontend/ingress.rs` for the Service/EndpointSlice wrappers. Pure `fn(&Model, &Config) -> Output` |
| `controller` | kube-rs controllers, indexes, watch mappers, apply and status writing. The only module that touches the network |

`flowsdn-gateway` depends on `flowsdn-k8s` (spec 13) for the client and
CRD types, and on `flowsdn-envoy-proto` (spec 16 §11.1) for the generated
Envoy v3 message types — it does **not** define its own.

### 11.2 Types

- Model types are plain `#[derive(Clone, Debug, PartialEq, Serialize,
  Deserialize)]` structs with `#[serde(default, skip_serializing_if)]` matching
  §4's serde column exactly. `Duration` fields serialize as the Go duration
  string form the fixtures use.
- `StringMatch` is a struct with three `String`s rather than an enum, matching
  the wire form. A constructor enforces "at most one non-empty" and a
  `Display` impl produces the canonical rendering (§4.6). Modelling it as an
  enum would be nicer Rust and would break every fixture.
- `L4Protocol`, `ServerHeaderTransformation`, `ExternalAuthProtocol`,
  `AccessLogsFormat`, `AccessLogsTarget` are `#[serde(rename_all)]` enums with
  an explicit `Unknown(String)` variant, so an unrecognized value from a newer
  CRD round-trips instead of failing the whole object (spec 13 §5.5).
- `BTreeMap`/`BTreeSet` everywhere in `model`, `ingest` and `translate`; a
  clippy lint denies `std::collections::HashMap` in those modules (§5.11).

### 11.3 Controllers

- `kube-rs` `Controller` per §3.2, one per primary kind, all inside the
  operator's leader-elected scope (spec 12 §3.2). No `controller-runtime`
  equivalent is needed beyond what `kube-rs` provides; ADR-0004's "explicit
  composition" applies — controllers are constructed in the operator's
  `build()` and handed their clients and shared caches.
- Indexes (§3.2) are built over the reflector stores as
  `BTreeMap<String, BTreeSet<ObjectRef>>` maintained by a store subscriber,
  not by re-listing. Every index function is `fn(&Object) -> Vec<String>` with
  **no client access**, which is what makes them unit-testable against a
  synthetic store.
- Apply uses server-side apply with a per-controller field manager
  (`flowsdn-operator-gateway`, `flowsdn-operator-ingress`), except for the
  label/annotation merge and `loadBalancerClass` preservation in §5.8, which
  need a read-modify-write.
- Status writes go through one helper that computes the merged condition set,
  compares it to the live one ignoring `lastTransitionTime`, and skips the
  write when equal — incrementing the skipped counter of §8.1.

### 11.4 Envoy protobuf emission

- `prost` types generated from the vendored `data-plane-api` protos, pinned
  alongside the Envoy image digest (spec 16 §11.2). No dependency on
  `envoy-types` or `envoy-control-plane`.
- Each resource is built, encoded with `prost::Message::encode`, and wrapped
  in an `Any` with the correct `type_url`. The CEC's `resources[]` is a list of
  those. **The encoded bytes must be canonical**: `prost` orders fields by tag
  and does not emit defaults, which is deterministic, but map fields are not —
  flowsdn therefore avoids protobuf `map` fields in generated config, using
  the repeated-entry forms Envoy also accepts, and where a map is unavoidable
  (`typed_per_filter_config`) it is populated from a `BTreeMap`.
- The goldens are YAML of the *JSON* projection of these protos. The harness
  therefore encodes to protobuf, decodes to `serde_json::Value` through the
  well-known JSON mapping, and compares that — which is also what catches a
  wrong `type_url`, since the JSON form carries `@type`.

### 11.5 Effort

Roughly 12–16k lines of Rust: model ~1k, ingestion ~3.5k, translation ~4.5k,
controllers ~4k, plus the golden harness ~800. The reference's 18k Go lines
compress somewhat — no DI framework, no generated deepcopy — but the status
surface does not compress at all, and it is the majority of the controller
half. Budget the status work as the schedule risk, not the Envoy work.

---

## 12. Decisions and remaining questions

Resolved entries are normative decisions from [ADR-0013](../decisions/0013-integration-issue-resolutions.md); their implementation and acceptance tests remain required.

1. **Resolved — #280.** Ship and retain both Ingress and Gateway API, with Ingress first
   to exercise the shared translator. This follows ADR-0001 boundary compatibility; a
   green Gateway API report does not itself authorize dropping Ingress.

2. **The HTTPS-redirect matcher bug.** In the reference, the code path that
   builds routes for a force-HTTPS virtual host passes the header and query
   matcher lists in the wrong argument order, so query parameters are emitted
   as header matchers and vice versa. Options: reproduce it for fixture
   compatibility, or fix it and annotate the affected goldens.
   **Recommendation: fix it**, annotate the goldens as expected divergences,
   and file the bug upstream (cross-project rule 11). Reproducing a matcher
   bug means a user's query-parameter match silently does not work on exactly
   the routes that redirect.
3. **Resolved — #282.** Keep one combined CEC for shared Ingress mode and the common
   listener set. Do not split per Ingress without an agent-side listener-merge contract.
   Preserve validation and last accepted configuration when a replacement is rejected.

4. **Resolved — #283.** Preserve annotation-over-field Ingress class precedence from
   §3.9. Document the precedence and test the case where both values conflict so
   migration does not silently move ownership to a different controller.

5. **Resolved — #284.** Force-HTTPS redirects use 301. Sections 5.7 and 6.2 already
   document this value; help text and chart descriptions must say 301 as well. Do not
   silently change to 308 or introduce a new setting in this decision.

6. **Non-standard reason strings.** `Invalid<Kind>` on route `Accepted`, and
   the GAMMA conditions whose reason does not vary with status (§3.11.5,
   §3.11.6). Options: keep for fixture compatibility; or emit the upstream
   constants (`NoMatchingParent`, `Accepted`/`NotAccepted`) and annotate the
   goldens. **Recommendation: keep them**, because they are what users' tooling
   and the harvested fixtures both expect, and revisit if the Gateway API adds
   a conformance assertion on the reason.
7. **`XListenerSet` at all.** It is an experimental Gateway API resource,
   ~13 fixture scenarios, and it complicates conflict detection, status
   ownership and secret grants materially. Options: implement in stage 2 as
   specified; or defer to a stage 3. **Recommendation: defer to stage 3.**
   Nothing else depends on it, the `ListenerSet` feature is simply not
   advertised while it is absent, and the conflict machinery is easier to get
   right for one source before it is generalized to many.
8. **Controller and object names.** `io.cilium/gateway-controller`,
   `cilium-gateway-*`, `cilium-ingress-*`, `cilium-secrets`. Keeping them means
   existing manifests work unchanged; changing them to `flowsdn` equivalents is
   honest but breaks every `GatewayClass` in the world.
   **Recommendation: keep, and make the controller name a config key** so a
   cluster running both implementations can disambiguate. Defer the key until
   that need is real (this matches spec 12 Open decision 5).
9. **Resolved — #287.** Vendor the reference access-log default format strings verbatim
   with the CRD schema, source revision and licensing provenance, as required by spec
   13. Keep log parsers compatible across migration.

10. **Resolved — #288.** Spec 21 owns GAMMA route ingestion, the shared model/CEC
   translator, status behavior and MESH-HTTP/MESH-GRPC profile requirements. Spec 16
   owns proxy execution and mesh transport; a new transport does not silently transfer
   the route contract.
