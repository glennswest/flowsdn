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
  profiles in §2.5.

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

run with `--gateway-class cilium --all-features --allow-crds-mismatch`, no
exempt features, and the same two skips the reference carries:
`MeshConsumerRoute` and `HTTPRouteListenerPortMatching`. Each skip MUST be
recorded in `docs/spec/21-gateway-api-ingress.md` §12 with an owner and a
target release; a skip that is not tracked is a silent regression.

The `SupportedFeatures` list reported on `GatewayClass.status` MUST be derived
at run time from what is actually installed and enabled (which optional CRDs
were discovered, whether ALPN / appProtocol / proxy-protocol are on), not
hard-coded, so that a cluster without `TCPRoute` does not advertise TCP
support.

### 2.5 Ingress conformance

The Ingress front end targets the `ingress-controller-conformance` suite
(`cilium/ingress-controller-conformance` fork) run with
`-ingress-class cilium`. flowsdn keeps that as a CI gate for stage 1 (§9.4).
