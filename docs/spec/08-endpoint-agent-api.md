# Endpoint lifecycle, endpoint manager, state directory and agent REST API — specification

Status: draft. Derived from: `docs/inventory/06-agent-endpoint-api.md` (primary),
`docs/inventory/13-crds-k8s.md` (CiliumEndpoint), reference cilium v1.20.1
(7d68cfb394) paths `pkg/endpoint/**`, `pkg/endpointmanager/**`,
`pkg/endpointstate`, `pkg/status/**`, `pkg/health/**`, `cilium-health/**`,
`pkg/api/**`, `pkg/rate/**`, `daemon/cmd/endpoint_restore*.go`,
`daemon/healthz/**`, `daemon/restapi/**`, `api/v1/openapi.yaml`,
`api/v1/health/openapi.yaml`. Governed by ADR-0001..0004. Builds on spec 00
(fences, health registry, config registry, runtime options), spec 01
(per-endpoint maps, loader pipeline, `.rodata.config`), spec 03 (identity
allocation, ipcache). Sibling specs referenced by number: 02 datapath
programs, 04 conntrack, 05 service LB, 06 policy engine, 07 IPAM, 09 CNI
plugin, 10 node routing, 11 L7 proxy, 13 CRDs.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes
*what* flowsdn does and the exact data it exchanges. It does not transcribe
reference code. Where the reference behavior is kept for compatibility, say
so and name the consumer that depends on it (cilium-dbg, Hubble, Envoy,
operator, other cluster). Where flowsdn deviates, mark **DEVIATION** with the
reason and the ADR.

## 1. Scope

In scope:

- The **endpoint** as the agent's unit of per-workload state: identifiers,
  labels, identity, options, properties, DNS rules, proxy state; the 8-state
  machine; creation, update, deletion.
- **Regeneration**: what triggers it, the ordered pipeline that turns policy
  and configuration into loaded programs and populated maps, coalescing,
  concurrency, atomicity and what a failed build leaves behind.
- The **state directory** `/var/run/cilium/state` and the per-endpoint
  directory contract (`ep_config.json`, `_next`, `_next_fail`, atomic swap),
  and **restore on restart**.
- The **endpoint manager**: id allocation, lookup indexes, periodic
  regeneration and GC, CiliumEndpoint (CEP) synchronization, policy-map
  pressure, the host, ingress and health endpoints.
- The **agent REST API** on `/var/run/cilium/cilium.sock`: all 44 swagger
  operations, socket permissions, operation-id access control, rate limiting,
  readiness gating; the **cilium-health API** on `health.sock` (3
  operations); auxiliary HTTP listeners (`127.0.0.1:9879`, `:10256`,
  `:4240`); the `/statedb/query` compatibility route proposed by spec 00.
- The **health checker** (prober, responder, health endpoint) and the
  **status collector** behind `GET /healthz`.

Out of scope, with owner:

- CNI plugin behavior, deletion-queue writer, conflist generation — spec 09.
  (The agent-side reader of the deletion queue is here.)
- IPAM allocation semantics behind `POST /ipam` — spec 07. The route is
  tabulated here; its body is specified there.
- Policy computation (`SelectorPolicy`, `EndpointPolicy`, policy-map entry
  layout) — spec 06. This spec says *when* it is invoked and what it must
  return.
- Program loading, attach, pin-replace commit — spec 01 §3.5–3.9; datapath
  program bodies — spec 02.
- Identity allocation and ipcache writes — spec 03. This spec says when the
  endpoint asks for an identity and what it does with the answer.
- Proxy redirect creation and Envoy xDS — spec 11.
- Hubble, monitor, `cilium-dbg` rewrite, bugtool.
- The hive shell (`shell.sock`), StateDB dump, `dynamiclifecycle`,
  `prefilter` semantics (route kept, returns 501 until an XDP prefilter spec
  exists), `cgroup-dump-metadata` and `map/{name}/events` (deferred, see 2.2).

## 2. Compatibility contract

### 2.1 Paths, sockets, permissions

| Item | Value | Consumer |
|---|---|---|
| run dir | `/var/run/cilium` (`--state-dir`; the reference name is misleading, this is `RunDir`), mode 0775 | everything below |
| API socket | `/var/run/cilium/cilium.sock` (`--socket-path`, env `CILIUM_SOCK`), owner root, group `cilium`, mode 0660 | cilium-dbg, cilium-cni, cilium-health, operator, Hubble CLI helpers |
| health socket | `/var/run/cilium/health.sock` (env `CILIUM_HEALTH_SOCK`), same group/mode | cilium-health CLI, cilium-dbg status |
| pidfile | `/var/run/cilium/cilium.pid` | bugtool, gops-style tooling |
| deletion queue | `/var/run/cilium/deleteQueue/*.delete`, lock `/var/run/cilium/deleteQueue/lockfile` | cilium-cni (writer), agent (reader) |
| state dir | `/var/run/cilium/state`, mode 0770; the agent `chdir`s here | bugtool (`cp -r`), restore, spec 01 config dumps |
| endpoint dir | `/var/run/cilium/state/<id>/` with `ep_config.json`; `<id>_next/`, `<id>_next_fail/` | restore, bugtool |
| globals | `/var/run/cilium/state/globals/` (spec 01 writes the node config dump here) | bugtool |
| templates | `/var/run/cilium/state/templates/` (kept as an empty directory, see 3.6) | bugtool |
| health pid | `/var/run/cilium/state/health-endpoint.pid` | agent restart |
| runtime config | `/var/run/cilium/state/agent-runtime-config.json` (spec 00 §4.5) | spec 00 |
| health history | `/var/run/cilium/state/<bin>-health-history.log` (spec 00 §3.4.3) | flowsdn-dbg |
| agent healthz | `127.0.0.1:<agent-health-port=9879>` and `[::1]:9879`, `GET /healthz` | kubelet probes (Helm) |
| KPR healthz | `--kube-proxy-replacement-healthz-bind-address` (Helm `0.0.0.0:10256`), `GET /healthz` | cloud LB health checks |
| cluster health | `:<cluster-health-port=4240>` `GET /hello` on every node IP and inside the health endpoint | remote agents' probers |

### 2.2 REST API

- Base path `/v1`, JSON, unix socket only. Every path, method, parameter
  name, JSON field name, enum value and HTTP status code in §4.4–4.6 MUST
  match `api/v1/openapi.yaml`. Field names are byte-identical; unknown fields
  in requests are ignored; responses never emit fields the swagger does not
  declare (an extra field breaks the strict go-swagger client used by
  `cilium-dbg`? — no, the client tolerates extras; the rule exists so that
  `models.Error` and enum strings stay exact).
- Operation identifiers (`--enable-cilium-api-server-access` tokens) are
  `Method + PascalPath` per §5.9; the 47 tokens are listed in §4.4/4.7.
- Rate-limited operations return `429` with `Retry-After` from the limiter.
- Access-denied operations return `403` with body `"Forbidden"`.
- Deferred operations MUST still exist in the router and return `501` with
  `models.Error` text `"not implemented"`: `GET /cgroup-dump-metadata`,
  `GET /map/{name}/events`, `PATCH /prefilter`, `DELETE /prefilter`
  (`GET /prefilter` returns an empty `Prefilter{spec{deny:[],revision:0}}`).
  Reason: a missing route yields a go-swagger `404 path not found`, which
  `cilium-dbg` prints as a confusing "unknown API" error; `501` is what the
  reference itself returns for BGP when the control plane is disabled.

### 2.3 File formats

- `ep_config.json` — §4.2, including legacy keys `dockerID`, `OpLabels`,
  `SecLabel`, `DNSRules` (v1, read and ignored), `DNSRulesV2`.
- deletion queue entries — container JSON or bare attachment strings, as
  specified in spec 09 §4.7 and §5.1.
- `health-endpoint.pid` — decimal PID and newline.

### 2.4 Kubernetes

`CiliumEndpoint` (`cilium.io/v2`, namespaced): fields written in §4.8;
created with `ownerReferences` to the Pod; `status` updated by **JSON Patch
on the whole object** (`test /metadata/uid`, `replace /status`) — the CRD has
no status subresource (inventory 13). Deleted with `preconditions.uid`.

### 2.5 Configuration keys

§6 lists 48 keys owned here. Names, types and defaults are the
`cilium-config` surface and MUST parse as in the reference (spec 00 §6.4).

### 2.6 Metric names

§8.1: `cilium_endpoint_*`, `cilium_policy_endpoint_enforcement_status`,
`cilium_endpoint_restoration_*`, `cilium_node_health_connectivity_*`,
`cilium_api_process_time_seconds`, `cilium_api_limiter_*`,
`cilium_controllers_*` keep their names and labels.

## 3. Behavior

### 3.1 Endpoint model

An **endpoint** is a local workload attachment that the datapath enforces
policy for. One pod may have several (secondary interfaces), the node itself
is one (host endpoint), the ingress proxy is one, and the health checker is
one.

**Identifiers** (all fixed at creation unless noted):

| Identifier | Type | Source | Notes |
|---|---|---|---|
| `id` | u16, 1..65535, never 0 | allocator §5.1 | `cilium_policy_v3_%05d`, `cilium_calls_%05d` suffix (spec 01 §2.1/3.3), `lxc_id` in `endpoint_info`, `cilium_call_policy` slot, `EndpointID` in trace events, `int64` on the wire |
| container id | string | `EndpointChangeRequest.container-id` | mutable via PATCH; persisted as `dockerID` |
| container interface name | string | `container-interface-name` | `eth0` normally; non-empty for secondary interfaces |
| CNI attachment id | string | derived `<container-id>:<container-ifname>` or `<container-id>` when ifname empty | primary lookup key used by the CNI on DEL/CHECK |
| pod name / namespace / UID | strings | `k8s-pod-name`, `k8s-namespace`, `k8s-uid` | UID detects a re-created pod with the same name (informer staleness, 3.3 step 6) |
| CEP name | string | `property-cep-name` if set, else `<pod>-<container-ifname>` for secondary interfaces, else `<pod>` | `cep-name:` lookup prefix and CEP object name |
| netns path / netns cookie | string / u64 | `container-netns-path`, `netns-cookie` (decimal string on the wire) | cookie patched into `.rodata.config` `endpoint_netns_cookie` (spec 01 §3.7) |
| host interface name / index | string / i32 | `interface-name`, `interface-index` | `lxc<hash>` veth or netkit primary; GC checks the link by name (3.9) |
| parent ifindex | i32 | `parent-interface-index` | ENI/Azure secondary-interface routing; `endpoint_info.parent_ifindex` |
| MAC / host MAC | 6 bytes | `mac`, `host-mac` | `endpoint_info.mac/node_mac`; host MAC differs per endpoint (peer of the pair) |
| IPv4 / IPv6 (+ pool names) | addr | `addressing.{ipv4,ipv6,ipv4-pool-name,ipv6-pool-name}` | `endpoint_key` in `cilium_lxc`; `ipv4:`/`ipv6:` lookup prefixes; expiration UUIDs stop the IPAM timer (spec 07) |
| identity | `Identity{id,labels}` | allocator (spec 03) | `SecLabel` in JSON; `endpoint_info.sec_id`; changes trigger regeneration |
| RT info | u32 | pod annotation `fib-table-id` (when `enable-fib-table-id-annotation`) or IPAM | `endpoint_info.rt_info`, `.rodata.config` `rt_info` |

**Labels** are an `OpLabels` quadruple, all `Labels` maps (source:key=value,
spec 03 §3.1):

| Set | Content | Identity-relevant | Persisted |
|---|---|---|---|
| `Custom` | labels given through the API (`PUT`/`PATCH /endpoint/{id}/labels`); reserved and generated (`k8s:`, `cidr:`) sources rejected | yes | yes |
| `OrchestrationIdentity` | pod labels that pass the identity label filter (spec 03 §4.2), plus synthesized `io.cilium.k8s.namespace.labels.*`, `io.cilium.k8s.policy.{cluster,serviceaccount}`, `io.kubernetes.pod.namespace` | yes | yes |
| `Disabled` | labels the user moved out of identity via `PATCH .../labels` delete of an orchestration label | no | yes |
| `OrchestrationInfo` | pod labels that fail the filter | no | yes |

`IdentityLabels()` = `Custom ∪ OrchestrationIdentity`. An endpoint with no
identity labels gets `reserved:init` until its pod metadata resolves.

**Runtime options** (`Options`, an `IntOptions` map): the endpoint subset of
spec 00 §3.3.8 — `Debug`, `DebugLB`, `DebugPolicy`, `DropNotification`,
`TraceNotification`, `PolicyVerdictNotification`, `PolicyAuditMode`,
`MonitorAggregationLevel`, `SourceIPVerification`. Initial values are the
daemon's; `PATCH /endpoint/{id}/config` overrides per endpoint; persisted.
Each maps to a `.rodata.config` variable of the lxc object (spec 01 §3.7).

**Datapath configuration** (`EndpointDatapathConfiguration`, from the CNI):
`require-arp-passthrough`, `require-egress-prog`, `external-ipam`,
`require-routing` (nullable bool; nil = true), `install-endpoint-route`,
`disable-sip-verification`. When `enable-endpoint-routes` is set the agent
forces `install-endpoint-route=true` (false if `cni-external-routing`),
`require-egress-prog=true`, `require-routing=false` on every create.

**Properties** (`map[string]any`, persisted): `property-fake-endpoint`
(never touches BPF or proxy; tests and unit fixtures), `property-at-host-network-namespace`
(`endpoint_info.flags` ATHOSTNS), `property-without-bpf-endpoint` (no lxc
program; watchdog skips), `property-skip-bpf-policy`,
`property-skip-bpf-regeneration`, `property-cep-owner` (the k8s object the
CEP is owned by when not the Pod), `property-cep-name`,
`property-skip-masquerade-v4`/`-v6` (`endpoint_info.flags` NO_SNAT_V4/V6),
`property-rt-info` (`"fib"` encoding of `RTInfo`).

**Not persisted, rebuilt**: state, policy revision (starts at 0 on every
agent start), desired/realized policy, proxy redirects and statistics,
controllers, status log, `bpf_headerfile_hash`, `ct_cleaned`,
`has_bpf_program`.

### 3.2 State machine

States are the `EndpointState` enum strings. `not-ready` is never stored: it
is rendered by the API when state is `ready` and the status log's current
status is not OK (3.13). `creating` exists only in the CEP CRD enum and is
never written by flowsdn.

Transitions permitted by `set_state` (the reference `setState`); anything
else is **rejected**: the state is unchanged, `false` is returned, an
`Other/Warning` status-log entry `Skipped invalid state transition to <to>
due to: <reason>` is appended, and an info log `Invalid state transition
skipped` with `from`, `to` is emitted — except the two silent cases marked
(silent), which return `false` without logging.

| From | Event / caller | To | Action on success |
|---|---|---|---|
| `""` (new) | `PUT /endpoint` parsed, or health/host/ingress creation | `waiting-for-identity` | log `Other/OK` reason; `cilium_endpoint_state` gauge +1 |
| `""` | `ep_config.json` parsed at restore | `restoring` | same |
| `waiting-for-identity` | identity resolved (labels unchanged, no regen needed) | `ready` | consume deferred regeneration (5.2) and enqueue it if any |
| `waiting-for-identity` | identity resolved (build needed) | `waiting-to-regenerate` | **rejected by `set_state`**; the resolver instead records the level in `skipped_regeneration_level` and lets the regeneration that follows the identity assignment pick it up |
| `waiting-for-identity` | delete requested | `disconnecting` | 3.8 |
| `waiting-for-identity` | create failed validation (labels, addressing) | `invalid` | terminal; endpoint removed by the create path |
| `ready` | labels changed and identity re-resolution needed | `waiting-for-identity` | resolver controller runs |
| `ready` | regeneration trigger (3.5) | `waiting-to-regenerate` | build enqueued on the endpoint's event queue |
| `ready` | delete requested | `disconnecting` | |
| `ready` | restore path re-entered (test/rare) | `restoring` | |
| `waiting-to-regenerate` | further trigger | `waiting-to-regenerate` | (silent) `false`: a build is already queued; caller MUST NOT enqueue another; level bumped per 5.2 |
| `waiting-to-regenerate` | identity change | `waiting-for-identity` | (silent) `false`: would break the queued build; level bumped per 5.2 |
| `waiting-to-regenerate` | delete requested | `disconnecting` | queued build observes `disconnecting` and exits with `EndpointStateInvalid` |
| `waiting-to-regenerate` | restore | `restoring` | |
| `waiting-to-regenerate` | build starts (`builder_set_state`, holds build mutex) | `regenerating` | not via `set_state` |
| `regenerating` | trigger while building | `waiting-to-regenerate` | the running build finishes; on completion the endpoint stays `waiting-to-regenerate` and the next queued build runs |
| `regenerating` | identity change while building | `waiting-for-identity` | current build result is discarded by `set_desired_policy` (identity revision mismatch → error → retry) |
| `regenerating` | delete requested | `disconnecting` | |
| `regenerating` | restore | `restoring` | |
| `regenerating` | build finished, no pending request (`builder_set_state`) | `ready` | `policy_revision` set, waiters woken |
| `restoring` | delete requested (validation failed) | `disconnecting` | |
| `restoring` | restore continues | `restoring` | |
| `restoring` | restored endpoint's first regeneration begins | `waiting-to-regenerate` → `regenerating` | via `set_regenerate_state` then `builder_set_state` |
| `disconnecting` | teardown complete | `disconnected` | terminal; gauge −1; status log cleared |
| `disconnected`, `invalid` | anything | — | terminal, rejected |

`cilium_endpoint_state{endpoint_state}` MUST be decremented for the old state
and incremented for the new one on every successful transition (from `""`
counts only the increment).

### 3.3 Creation (`PUT /endpoint/{id}`)

The create path is the reference's `CreateEndpoint`; the ordering matters
for the 409/400 semantics the CNI relies on.

1. Wait for `api-ready` (spec 00 fence): until the deletion queue has been
   replayed and the API is serving, return `503`.
2. Acquire the `endpoint-create` limiter (3.11.3); on timeout `429`.
3. If `enable-endpoint-routes`, force the datapath-configuration bits (3.1).
4. Parse `EndpointChangeRequest` into an endpoint (state MUST be
   `waiting-for-identity`; `id` is allocated by the manager in step 9, an
   `id` in the body is ignored). Parse errors → `400`, endpoint set `invalid`.
5. The reference reports conflicts as `400`; flowsdn MUST return **`409`**
   when the CNI attachment id or an IP already
   belongs to a live endpoint and `400` for everything else — **DEVIATION**:
   the reference returns 400 for both; `cilium-cni` treats any non-2xx as
   failure so the distinction is free and the swagger already documents 409.
   Checks in order: `id` taken (only when the body carries one), CNI
   attachment id taken, IPv4 taken, IPv6 taken.
6. Labels from the API (`labels[]`): reserved labels → `400`; generated
   (`k8s:`, `cidr:`) → `400`; after the identity filter nothing left → `400`.
7. Register a *create request* (cancellable): `DELETE` of the same endpoint
   while creation is in flight cancels the create context.
8. If `k8s-pod-name` and `k8s-namespace` are set and Kubernetes is enabled:
   fetch the Pod from the informer; if the cached Pod's UID differs from
   `k8s-uid`, poll the informer every 100 ms for up to the create timeout,
   then fall back to a direct API `GET`; on total failure log and proceed
   with `reserved:init`. From the Pod: identity and info labels (spec 03
   §3.1), named ports, `io.cilium.network.mac` annotation (primary interface
   only; unparsable → `400`), `fib-table-id` annotation, bandwidth
   annotations (warn if bandwidth manager off).
9. `EndpointManager::add` — allocate id (§5.1), expose in all indexes, start
   the endpoint task and its event queue, start the CEP sync controller
   (3.9.4). Failure → `500`.
10. Resolve identity: with a pod, run the metadata resolver
    (`resolve-labels-<id>` controller, blocking first pass); without, apply
    the API labels directly. Either path allocates the identity (3.4) and,
    if the state machine allows, enqueues the first regeneration
    (`EndpointInit`, `rewrite+load`). If the create context was cancelled
    → `500` "request cancelled while resolving identity".
11. If `sync-build-endpoint` is true, wait for the first successful
    regeneration (`policy_revision ≥ 1`) with a 330 s bound (5.3); a deleted
    endpoint or timeout → `500`. The CNI always sets this flag; the limiter's
    `max-wait 60 s` and the kubelet's 4 min sandbox timeout frame it.
12. Stop the IPAM expiration timers named by
    `addressing.ipv4-expiration-uuid` / `ipv6-expiration-uuid` (spec 07);
    failure → `500`.
13. Return `201` with the `Endpoint` model.

Any error after step 9 removes the endpoint (`release identity`, `release
IP` unless `external-ipam`), so a failed PUT leaves no state.

### 3.4 Identity resolution and label updates

- `update_labels(identity_labels, info_labels, blocking)` replaces
  `OrchestrationIdentity`/`OrchestrationInfo` (source-filtered) and, if the
  identity-relevant set changed, bumps `identity_revision` and runs the
  resolver.
- The resolver (`resolve-identity-<id>` controller, `RunInterval` 5 m, jitter
  = `identity-change-grace-period`… bounded by `cilium-identity-max-jitter`
  30 s for pod-driven updates) computes the new label set (identity labels
  plus, when `policy-cidr-match-mode` includes pods, the ipcache CIDR labels
  of the endpoint's IPs), then:
  1. if the endpoint already holds an identity with equal labels: if state is
     `waiting-for-identity` → `ready` and consume any deferred regeneration;
     done;
  2. otherwise `AllocateIdentity(labels)` (spec 03 §3.3/3.4; blocking, may
     wait on the API server or kvstore);
  3. if `identity_revision` moved meanwhile → release the new identity, abort
     (a newer resolution owns the endpoint);
  4. if the endpoint had a different non-`init` identity: sleep
     `identity-change-grace-period` (5 s) **without the lock**, re-check
     obsolescence — this lets the new identity propagate to peers' policy
     maps before this endpoint starts emitting it;
  5. `set_identity`: swap, release the old identity, upsert the endpoint's
     IPs into the ipcache with the new identity (spec 03 §3.10 legacy
     `Upsert` path, resource `cilium-global:<cluster>/<node>/<id>`), force
     policy recomputation, mark the CEP sync controller for a run;
  6. `set_regenerate_state(LabelsUpdate, rewrite+load)` and enqueue.
- `PATCH /endpoint/{id}/labels` adds to `Custom` / deletes from
  `Custom`+`OrchestrationIdentity` (moving orchestration labels to
  `Disabled`); reserved labels rejected (`500` code path per swagger).
- The host endpoint's labels follow the Node object's labels (filtered);
  `EndpointManager` observes the local node store and calls
  `update_labels_from(old, new)`.

### 3.5 Regeneration

#### 3.5.1 Triggers, reasons, levels

| Reason string (metrics label, status log) | Source | Level |
|---|---|---|
| `EndpointInit` | first build after create | `rewrite+load` |
| `EndpointRestore` | first build after restore | `rewrite+load` |
| `LabelsUpdate` | identity changed (3.4) | `rewrite+load` |
| `EndpointUpdate` | `PATCH /endpoint/{id}` changed addressing/labels/MAC/ifindex | `rewrite+load` |
| `AnnotationsUpdate` | pod annotation change affecting no-track ports, bandwidth, visibility | `no-rebuild` |
| `PolicyUpdate` | policy repository revision advanced and the endpoint's identity is in the affected set (spec 06) | `no-rebuild` |
| `SelectorPolicyStale` | selector policy detached/recomputed | `no-rebuild` |
| `DaemonConfigUpdate` | `PATCH /config` or `PATCH /endpoint/{id}/config` option change | `rewrite+load` |
| `DeviceConfigurationChanged` | devices/MTU/node addressing changed (spec 10) | `rewrite+load` |
| `PeriodicRegeneration` | `endpoint-regen-interval` (2 m) tick | `no-rebuild` |
| `RegenerationFailure` | `endpoint-<id>-regeneration-recovery` controller retry | the failed level |
| `DeferredRegeneration` | consumed after identity resolution (5.2) | max(buffered, `no-rebuild`) |
| `DeamonTrigger` (sic) | `RegenerateAllEndpoints` from a policy trigger, spelled as the reference does because it appears in `cilium_endpoint_regenerations_total{reason}` | as given |

Levels: `no-rebuild` (policy map + proxy + ipcache/lxc refresh; programs
untouched) and `rewrite+load` (also re-patch `.rodata.config` and reload
programs through spec 01 §3.5–3.6). A `no-rebuild` request is promoted to
`rewrite+load` when the *endpoint hash* changes (5.4).

#### 3.5.2 Coalescing and concurrency

- Each endpoint owns one **event queue** (`endpoint-queue-size` 25) drained
  by one task; regenerations are events on it, so builds of one endpoint are
  serialized. A second regeneration event enqueued while one is pending is
  dropped by the state machine (3.2: `waiting-to-regenerate` → same is
  rejected) and its level/revision folded into the pending one (§5.2).
- Across endpoints, builds take a permit from the **build queue**, a
  semaphore of `max(2, num_cpus)`; the permit is released early when the
  build only waits for proxy ACKs so another endpoint can proceed.
- Before its first build an endpoint MUST wait on the `regeneration` fence
  (spec 00 §3.4.1: datapath base, identity init, policy rev 1, ipcache rev 1,
  LB init, ClusterMesh IP sync with `clustermesh-ip-identities-sync-timeout`
  released-on-timeout).
- `PolicyRevisionToWaitFor` (from `RegenerateAllEndpoints` after a policy
  import): the build MUST not compute policy against a repository revision
  lower than requested.

#### 3.5.3 Pipeline

One regeneration, in order. Steps marked (revertible) are undone on failure
of a later step; everything before the *commit point* is invisible to
traffic.

| # | Step | Detail | On failure |
|---|---|---|---|
| 1 | acquire build permit | semaphore; stats `buildPermitAcquisition` | `RegenerationFailure` retry |
| 2 | lock, `builder_set_state(regenerating)` | if state is not `waiting-to-regenerate`/`restoring` → `EndpointStateInvalid` and exit quietly (endpoint is disconnecting) | none |
| 3 | fold skipped level/revision | §5.2 | |
| 4 | prepare `_next` dir | `rm -rf <id>_next`; `mkdir <id>_next` (stats `prepareBuild`) | `PrepareBuildError` |
| 5 | compute policy | if `identity_revision` or repository revision moved since the cached result: `SelectorPolicy` for the identity (shared, spec 06) then `EndpointPolicy` (per endpoint) — computed **without** the endpoint lock; wait for the repository ≥ `PolicyRevisionToWaitFor`. If the identity changed while computing → error, retry | `PolicyRegenerationError` |
| 6 | proxy redirects (revertible) | for each L7 rule create/update a redirect (spec 11), collecting the proxy ports into the desired policy; `addNewRedirects`; missing listener → counted `missingProxyRedirects`, not an error | `ProxyPolicyError` |
| 7 | DNS rules | fetch current L7 DNS rules for the endpoint (must not hold the endpoint lock; ipcache lock ordering) | |
| 8 | first-build CT clean | if `ct_cleaned` is false, schedule `ctmap.GC` for the endpoint's IPs (spec 04) once; later builds skip | |
| 9 | open policy map | `cilium_policy_v3_%05d` create-or-open (spec 01 §3.2); on first open **dump** it to `policy_map_dump` so restore diffs instead of wipes (§5.5); if the dump is empty, sync now | `PolicyBPFError` |
| 10 | write endpoint config | `ep_config.json` (§4.2) via temp+rename into `_next`; the per-object config dump `bpf_lxc.json` is written by the loader in step 13 (spec 01) | `DatapathOrchestrationError` |
| 11 | endpoint hash | hash of every `.rodata.config` value and map name the lxc object depends on (§5.4); if changed → promote level to `rewrite+load` | |
| 12 | `cilium_lxc` upsert (early) | when the level is `no-rebuild` and the endpoint already has a program: write `endpoint_info` now so identity/MAC changes reach peers without waiting | `BPFError` |
| 13 | reload datapath (`rewrite+load` only) | spec 01 §3.5 load → insert `cil_lxc_policy{,_egress}` into `cilium_call_policy`/`cilium_egresscall_policy[id]` → attach ingress → attach/detach egress (`require-egress-prog`) → **commit** pin-replace → per-endpoint routes (`install-endpoint-route`). Write `template.txt` (object identity hash) into `_next`. This is the **commit point** for program changes | `DatapathOrchestrationError`; spec 01 guarantees the old program keeps running |
| 14 | `cilium_lxc` upsert | write `endpoint_info` (ifindex, lxc_id, flags, rt_info, mac, node_mac, sec_id, parent_ifindex) keyed by each IP | `BPFError` |
| 15 | release build permit; wait proxy ACKs | Envoy NACK/timeout (330 s completion context) → error | `ProxyPolicyError` |
| 16 | wait CT clean | `<-ct_cleaned`; set `ct_cleaned = true` | |
| 17 | policy map sync | diff `desired` against `policy_map_dump` (first build) or `realized` (later): add/update then delete (spec 06 defines entry order; proxy-port-bearing entries after their listener exists) (stats `mapSync`) | `PolicyBPFError` |
| 18 | swap directories | §5.3 `renameat2(RENAME_EXCHANGE)`; remove `_next_fail` | swap error → `_next` renamed to `_next_fail` |
| 19 | realize | `realized_policy = desired`, `policy_revision = repository revision used in step 5`, remove old redirects (`removeOldRedirects`), wake `WaitForPolicyRevision` waiters, drop restored DNS rules for this endpoint | |
| 20 | `builder_set_state(ready)` unless a new request arrived (then stay `waiting-to-regenerate`) | status log `BPF/OK` "Successfully regenerated endpoint program (Reason: …)", `Policy/OK`; metrics §8.1 | |

**Atomicity requirements.**

- Traffic MUST never observe a half-programmed endpoint: the new program is
  attached only after its policy programs are in the call maps (spec 01
  §3.6), and the policy map is written after the program that reads it is
  live (for `no-rebuild` there is no program change, so the map diff is the
  only visible change).
- Identity additions reach policy maps before the ipcache learns the prefix;
  deletions the reverse (spec 03 §3.8). Step 12/14 (own IP → own identity)
  is exempt because the endpoint's own program is the only reader of its own
  entry that matters and a missing entry drops, never mis-allows.
- Directory swap is the single atomic point for on-disk state; a crash before
  step 18 leaves `<id>/` describing the previous good build, which is what
  restore reads.

**What a failed regeneration leaves behind.**

- `<id>_next/` renamed to `<id>_next_fail/` (kept for `bugtool`; removed by
  the next success); `<id>/` untouched.
- Programs: previous programs still attached (spec 01 rollback); the calls
  map pin still points at the previous map.
- Policy map: partially applied entries are possible only if step 17 failed
  mid-way; `realized_policy` is **not** advanced, so the next build re-diffs
  from the map dump (`policy_map_dump` is refreshed by a `DumpToMapStateMap`
  on the revert path).
- Proxy redirects created in step 6 are reverted (`revertFunc`); their
  statistics rows get `allocated-proxy-port = 0`.
- Status log: `BPF/Failure` "Error regenerating endpoint: …" and `Policy/Failure`
  or `Policy/Warning` (policy vs non-policy cause); `EndpointHealth` becomes
  `not-ready`-derived (3.13).
- A controller `endpoint-<id>-regeneration-recovery` (group
  `endpoint-regeneration-recovery`, `RunInterval` 1 s, exponential error
  backoff) re-enqueues `RegenerationFailure` at the failed level until a
  build succeeds; it is removed on success.
- `cilium_endpoint_regenerations_total{outcome="fail",error=<failure reason>}`
  incremented; time stats are **not** observed for failures.

Failure reasons (label `error`): `none`, `unknown`, `EndpointStateInvalid`,
`PrepareBuildError`, `PolicyRegenerationError`, `EndpointPolicyUpdateError`,
`ProxyPolicyError`, `DatapathOrchestrationError`, `BPFError`,
`PolicyBPFError`; the policy ones (`PolicyRegenerationError`,
`EndpointPolicyUpdateError`, `PolicyBPFError`) mark the `Policy` status
component `Failure`, the rest `Warning`.

### 3.6 State directory contract

```
/var/run/cilium/state/                      0770, agent cwd
  agent-runtime-config{,-1,-2}.json         spec 00 §4.5
  <bin>-health-history.log{,.1,.2}          spec 00 §3.4.3
  health-endpoint.pid                       3.10.3
  local_allocator_state.json                spec 03 §4.10
  globals/                                  node config dump (spec 01 §3.7 layer-2 values as JSON)
  templates/                                empty; kept so `bugtool` and old tooling do not warn
  bpf/<dev>/bpf_{host,xdp,overlay,wireguard}.json, bpf/bpf_sock.json   spec 01 §2.1
  <id>/                                     one per live endpoint, bare decimal name
    ep_config.json                          §4.2, the persisted endpoint
    bpf_lxc.json                            spec 01 per-object config dump (informational)
    template.txt                            object identity hash + "\n"
  <id>_next/                                build in progress
  <id>_next_fail/                           last failed build, debugging only
```

Rules:

- Files inside `_next` MUST be written with temp-file + `rename` so a reader
  never sees a partial file.
- **Swap** (§5.3): if `<id>/` exists, hard-link every file present in the old
  dir and absent in `_next` into `_next`, then `renameat2(AT_FDCWD, "<id>_next",
  AT_FDCWD, "<id>", RENAME_EXCHANGE)`; the old contents end up in `_next`,
  which the next build removes. If `<id>/` does not exist, plain `rename`.
  Then `rm -rf <id>_next_fail`.
- **Restore** reads only directories whose name is a bare decimal; a
  `<n>_next` or `<n>_next_fail` whose base `<n>` also exists is *incomplete*
  and removed; a `_next`/`_next_fail` **without** a base directory is read as
  a complete directory (the reference's `partitionEPDirNamesByRestoreStatus`
  behaves this way — it covers a crash between `rename` and nothing else).
  Two directories yielding the same `id` → the one whose name is exactly
  `<id>` wins.
- Unparseable `ep_config.json` → directory removed, counted `failed`.
- On endpoint deletion all three directories are removed.

**DEVIATION — `ep_config.h` is not produced (ADR-0002).** The reference
writes a C header per endpoint (`#define`s for the endpoint's constants plus
the JSON embedded as a comment) that clang consumes on the node, and
`SyncEndpointHeaderFile` rewrites it when DNS rules change. flowsdn has no
compiler on the node; the same information exists as:

| Reference `ep_config.h` content | flowsdn |
|---|---|
| `LXC_ID`, `LXC_IP`, `LXC_IPV4`, `LXC_MAC`, `THIS_INTERFACE_MAC`, `THIS_INTERFACE_IFINDEX`, `SECLABEL`, `POLICY_VERDICT_LOG_FILTER`, `ENDPOINT_NETNS_COOKIE`, `RT_INFO`, option `#define`s | `.rodata.config` variables of the lxc object (spec 01 §3.7 table) patched at load; dumped to `<id>/bpf_lxc.json` for humans |
| `POLICY_MAP`, `CALLS_MAP` names | spec 01 §3.3 rename table; visible as pins |
| embedded JSON comment | `ep_config.json` is the only copy; nothing embeds it |
| rewrite on DNS-rule change | `DNSRulesV2` in `ep_config.json` is rewritten in place (temp+rename inside `<id>/`, no swap) by a debounced trigger (`MinInterval` 1 s) when the DNS proxy updates restored rules |
| `EndpointHash` over the header text | hash over the config struct (§5.4) |

`restore` therefore parses only `ep_config.json`; a state directory written
by a Cilium agent (which has both files) restores because the JSON is read
and the `.h` ignored — see open decision 12.1.

### 3.7 Restore on restart

Preconditions and ordering come from spec 00 §3.4.1 (`ipam-restored`,
`endpoint-restore` fences). Steps:

1. **Clear stale veths** (`clearStaleCiliumEndpointVeths`): list veth links
   in the host namespace; delete any veth whose peer is *also* in the host
   namespace and whose name starts with `lxc` (an orphan pair left by a pod
   whose netns was destroyed but whose host side survived). Never delete a
   veth whose peer index is absent (peer in a live netns).
2. **Read from disk** (`readOldEndpointsFromDisk`): list the state dir,
   partition per 3.6, parse each `ep_config.json` into an endpoint in state
   `restoring` with `SkipStateClean` (its directories are not removed on
   parse). Endpoints with `reserved:host` record the host endpoint id for
   the node. Announce the *possible* set to IPAM (spec 07 withholds their
   IPs) and to the ipcache (spec 03 §3.5 restored identities). Metrics
   `cilium_endpoint_restoration_endpoints{phase="read_from_disk",outcome}`.
3. **Validate** each (`RestoreOldEndpoints`, after IPAM is configured and
   the k8s pod cache is synced):
   - `reserved:health` endpoint: drop silently and `rm -rf` its directory —
     the health endpoint is always recreated.
   - **Datapath mode compatibility**: for pod endpoints, if the restored
     link type (veth vs netkit) differs from `datapath-mode`, the agent MUST
     exit with a fatal error naming the endpoints; mixing is not supported.
   - Pod endpoints (`k8s-pod-name` set, k8s enabled): the Pod MUST exist in
     the informer cache and be scheduled on this node; otherwise delete the
     endpoint's CEP (`DeleteK8sCiliumEndpointSync`) and mark `toClean`.
   - `ValidateConnectorPlumbing`: the host interface `IfName` MUST exist;
     otherwise `toClean`.
   - Re-allocate IPv4/IPv6 via IPAM "allocate without upstream sync"
     (`<ns>/<pod> [restored]`); `bypass-ip-availability-upon-restore` turns
     an IPv4 "not available in pool" error into a warning; other errors →
     `toClean`. `external-ipam` endpoints skip this.
   - Survivors: status log `Other/OK` "Restoring endpoint from previous
     cilium instance", `SetDefaultConfiguration` (options missing from the
     JSON get daemon defaults).
   - Dump `cilium_lxc`; after the loop delete every non-host entry whose IP
     is not owned by a restored endpoint (stale pods).
4. **Restore into the manager** (`regenerateRestoredEndpoints`, after k8s
   caches, `policy-dir-loaded`, ipcache rev ≥ 1): `EndpointManager::restore`
   (reuse id §5.1, expose, start task) for each survivor; remove `toClean`
   endpoints with `NoIdentityRelease`, `NoIPRelease` (their directories go,
   their IPs were never re-claimed). Release `endpoint-restore.restored-into-manager`.
5. **Regenerate in background** (`RegenerateAfterRestore`, per endpoint,
   concurrently, after the `api-ready` fence): re-read the host ifindex for
   the host endpoint; **re-allocate the identity** from the filtered labels
   with a `restoring-ep-identity (<id>)` controller (retries until the
   allocator answers; spec 03 §3.5 normally returns the same numeric id);
   apply `identity-change-grace-period` if the number changed from the one
   in `SecLabel`; run the metadata resolver (pod labels may have changed
   while down); `Regenerate(EndpointRestore, rewrite+load)` and wait for the
   result. Release `endpoint-restore.regenerated` when all finished;
   `endpoint-restore.initial-policy` when every restored endpoint has
   computed its first policy.
6. Datapath continuity: programs and pins from the previous agent stay
   attached throughout (spec 01 §3.4); the first regeneration replaces them
   via pin-replace. Because `policy_revision` restarts at 0, `PUT
   /endpoint` waiters and `cilium-dbg policy wait` only see revisions of the
   current agent lifetime.

`--restore=false` skips steps 2–5; existing directories are left alone and
existing endpoints are treated as unknown (their `cilium_lxc` entries are
**not** removed either).

### 3.8 Deletion

**Rollback ownership (ADR-0012 #129):** teardown MUST affect only the target
endpoint generation and allocations it still owns. Shared identity release
is reference-counted (spec 03); another live endpoint's identity or policy
must not be removed. A rollback attempt must not delete a replacement endpoint
that reused the same attachment ID; the API/controller must validate the
creation identity or serialize creation and rollback under that identity.

Triggered by `DELETE /endpoint/{id}` (CNI DEL, `cilium-dbg endpoint
disconnect`), `DELETE /endpoint` (by container id), the deletion queue
replay, GC (3.9.3), restore cleanup, or health endpoint relaunch.

1. Cancel any in-flight create request for the endpoint.
2. `set_state(disconnecting)`; `unexpose` from every index (lookups fail
   from here); the event queue is stopped and drained (a queued build exits
   with `EndpointStateInvalid`).
3. `leave`: detach the desired and realized policies from the selector
   cache, remove all proxy redirects and the endpoint's network policy from
   the proxy, drop restored DNS rules, close the policy map, release the
   identity (unless `NoIdentityRelease` or the identity is `reserved:init`),
   remove the endpoint's IPs from the ipcache, remove `<id>`, `<id>_next`,
   `<id>_next_fail`, remove all controllers, wake and drop policy-revision
   waiters, scrub the endpoint's IPs from the CT maps (spec 04) unless
   `property-fake-endpoint`, `set_state(disconnected)`, clear the status
   log, remove the policy-enforcement metric row.
4. Datapath teardown (spec 01 §3.4 `Unload`): detach programs, remove the
   link directory; policy/calls pins are left for the sweep. Delete the
   `cilium_lxc` entries. Delete per-endpoint routes/rules; in ENI/Azure mode
   only if `EndpointOwnsIP(ip)` still says this endpoint owns the IP (a
   stale delete must not strip a new owner's rules).
5. Release IPs to IPAM unless `NoIPRelease` (set for `external-ipam` and
   restore cleanup). Release the id last (§5.1).
6. Delete the CEP with `preconditions.uid = CiliumEndpointUID`; skipped when
   the UID is unknown (never owned) — the operator GC handles orphans.

`DELETE` returns `200` when every step succeeded and `206` with the number
of errors when some did (errors are logged and ignored so the CNI can
proceed). `404` when unknown; `400` when the endpoint cannot be modified via
the API (host/ingress/health endpoints reject `APICanModify`).

**Deletion queue (agent side).** Before the API socket is created, after
`endpoint-restore.restored-into-manager`: take the exclusive `flock` on
`deleteQueue/lockfile` (creating the directory 0755 if missing), read every
`*.delete` file, first trying JSON `EndpointBatchDeleteRequest`; otherwise
decode the bare `<container-id>:<ifname>` attachment string. Delete endpoints
by container id or attachment id respectively (missing endpoints are not
errors), remove the file, then
release the lock **after** the API is listening (`api-ready` fence orders
`delete-queue-lock-held` before `api-listening`; the unlock is a job that
runs once the server is up). The CNI holds a shared lock while writing, so
no request is lost in either direction.

### 3.9 Endpoint manager

#### 3.9.1 Indexes

One `RwLock`-protected index set (or a `flowsdn-table` with secondary
indexes, §11): by id (u16), by CNI attachment id, by IPv4, by IPv6, by CEP
name `<ns>/<cep>`; derived scans by pod name, namespace, container id (may
match several — secondary interfaces), service account. `Lookup(str)` parses
the prefixes below; the empty prefix means `cilium-local`.

| Prefix | Meaning |
|---|---|
| `cilium-local:<n>` or bare `<n>` | numeric id, parsed base 0 (so `0x10` works); negative → 400 |
| `cilium-global:<cluster>/<node>/<id>` | ipcache metadata form; the local component is resolved by id |
| `cni-attachment-id:<cid>[:<ifname>]` | CNI |
| `container-id:<cid>` | first endpoint of the container (legacy) |
| `container-name:<name>` | legacy docker; always 404 in k8s deployments |
| `pod-name:<ns>/<pod>` | first matching endpoint |
| `cep-name:<ns>/<cep>` | exact |
| `ipv4:<a.b.c.d>`, `ipv6:<addr>` | exact |
| anything else | 400 |

`GET /endpoint?labels=` filters by `IdentityLabels()` containing every given
label; no match → 404 (the reference returns 404 for an empty list).

#### 3.9.2 Periodic regeneration

Every `endpoint-regen-interval` (2 m; 0 disables) enqueue
`PeriodicRegeneration` at `no-rebuild` for every endpoint in `ready`. The
per-endpoint `bpf-policy-map-full-reconciliation-interval` (15 m) is a
policy-map-only resync owned by spec 06 and does not go through the
regeneration pipeline.

#### 3.9.3 GC of vanished endpoints

Every `endpoint-gc-interval` (5 m; 0 disables) run **mark and sweep**:
sweep the set marked in the *previous* round, then mark anew. An endpoint is
marked when its health check fails; the only check is "host interface by
name (`IfName`) no longer exists" (`LinkNotFound`); any other netlink error
does not mark. Endpoints without a host interface (host, ingress,
`property-at-host-network-namespace`) log once and are never GC'd. Sweep =
3.8 with `NoIPRelease = external-ipam`, logging `Stray endpoint found. You
may be affected by upstream Kubernetes issue #86944`. The two-round scheme
gives a link that is being replaced one interval to reappear.

#### 3.9.4 CiliumEndpoint sync

Unless `disable-endpoint-crd`, each endpoint with a pod (and not
`reserved:health`) runs controller `sync-to-k8s-ciliumendpoint (<id>)`
(group `sync-to-k8s-ciliumendpoint`, `RunInterval` 10 s, error backoff):

1. Skip while the endpoint has no identity yet, or state is
   `disconnecting`/`disconnected` (the delete path removes the CEP).
2. Build `CiliumEndpoint.status` (§4.8) from the endpoint.
3. If the endpoint holds no `CiliumEndpointUID`: look for an existing CEP
   `<ns>/<cep-name>`. If found and `status.networking.node` equals the local
   node IP and the CEP has no owner conflict → take ownership (store its
   UID, mark `ep_config.json` for rewrite); if found but owned by another
   node/pod UID (StatefulSet pod re-created elsewhere) → delete it with
   `preconditions.uid` and create anew; if not found → `Create` with
   `ownerReferences` [{apiVersion v1, kind Pod, name, uid, controller?}] (or
   the `property-cep-owner` object), labels copied from the owner, `status`
   filled; store the new UID.
4. Otherwise `Patch(JSONPatchType)` with
   `[{"op":"test","path":"/metadata/uid","value":"<uid>"},
   {"op":"replace","path":"/status","value":<status>}]`. A failed `test`
   (409/422) clears the stored UID so step 3 re-evaluates ownership. Skip
   the patch when `status` equals the last successfully written one.
5. Record `cilium_endpoint_propagation_delay_seconds` when the informer
   echoes the update (time since the write).

With `enable-cilium-endpoint-slice` the agent still **writes** CEPs; the
operator batches them into `CiliumEndpointSlice`s and the agent **reads**
CES (not CEP) for remote endpoints' ipcache entries (spec 03/13). Nothing in
this spec changes under CES mode except that the local CEP watcher is off.

`enable-stale-cilium-endpoint-cleanup` (default true): once after
`endpoint-restore.restored-into-manager`, list CEPs whose
`status.networking.node` is this node and whose `<ns>/<name>` is not a
managed endpoint; delete them (with UID precondition).

#### 3.9.5 Policy-map pressure

Each endpoint reports `(id, used/max)` after every policy-map sync; the
manager exports the **maximum** across endpoints as
`cilium_bpf_map_pressure{map_name="cilium_policy_v3_*"}` (a debounced
trigger, 10 s) and logs when above `bpf-policy-map-pressure-metrics-threshold`
(0.1). `enable-endpoint-lockdown-on-policy-overflow`: when a sync fails with
`E2BIG`/`ENOSPC`, the endpoint sets `lockdown = true`, writes a deny-all
policy map (spec 06) and logs at error; cleared by the next successful full
sync.

### 3.10 Special endpoints

#### 3.10.1 Host endpoint

Created at start (`init-host-endpoint`) unless one was restored: id from
the allocator (the reference historically used a fixed id; flowsdn MUST
accept any id from the JSON), labels `reserved:host` plus the Node's labels
after the identity filter, identity `reserved:host` (1), interface
`cilium_host`, `is_host = true`, no IPs in `cilium_lxc` (the host's
`endpoint_info` is written by the node routing spec 10 with flag HOST),
programs attached by spec 01 to `cilium_host`/`cilium_net`/devices as
`bpf_host`. It regenerates like any endpoint (host firewall policy, spec 06);
its `host_ep_id` is a node-level `.rodata.config` value (spec 01). API: read
only; `DELETE`/`PATCH` → 400.

#### 3.10.2 Ingress endpoint

When `enable-envoy-config` or the ingress controller is on: labels
`reserved:ingress`, IPs = the node's ingress IPs (allocated from the pod CIDR
by infra IP allocation, published in `CiliumNode.spec.addresses` type
`CiliumInternalIP`? — no: `status.ipam`? — the reference publishes them as
node annotations `…/ipv4-Ingress-ip` and in `CiliumNode`; spec 10 owns the
publication), `property-fake-endpoint` is **not** set; it has no interface
and `property-without-bpf-endpoint`; policy for it is computed so Envoy
receives the ingress network policy (spec 11); it is restored from ipcache
(spec 03 §3.5) not from disk.

#### 3.10.3 Health endpoint (`cilium-health-ep`)

When `enable-endpoint-health-checking` (default true, requires
`enable-health-checking`): a real endpoint in its own network namespace so
that node-to-pod connectivity is probed through the datapath.

Launch (after `endpoint-restore.restored-into-manager`), controller
`cilium-health-ep` (group `cilium-health`, `RunInterval` 60 s):

1. Remove `<state>/health-endpoint.pid` if present (kill the process it
   names if alive), delete links `lxc_health` and legacy `cilium_health` if
   present, delete any endpoint owning the node's health IPs.
2. Create a netns (anonymous, held by fd) and a link pair per
   `datapath-mode` (veth or netkit) with host side `lxc_health`, MTU from
   the MTU module, BIG-TCP GRO/GSO sizes if enabled.
3. Move the peer into the netns; assign `IPv4HealthIP/32` and
   `IPv6HealthIP/128` (from the local node store; spec 07 allocates them,
   spec 10 publishes them in `CiliumNode.spec.health`); enable IPv6 on the
   interface; install routes inside the netns toward `cilium_host`'s
   addresses with `route-mtu` (same shape the CNI installs, spec 09), plus
   per-endpoint routes/rules on the host when `enable-endpoint-routes` or an
   ENI-style routing config is active.
4. Start the responder listening on `:<cluster-health-port>` inside the
   netns (3.12) and write `health-endpoint.pid`.
5. `PUT`-equivalent in-process create with `EndpointChangeRequest{state:
   waiting-for-identity, addressing, mac, host-mac, interface-name,
   interface-index, container-name: "cilium-health", labels:
   [reserved:health]}`, `datapath-configuration.install-endpoint-route` when
   `enable-endpoint-routes`; the endpoint gets identity `reserved:health` (4)
   and regenerates. It is exempt from CEP sync and from restore (3.7 step 3).
6. Every 60 s ping the health IP (`GET /hello`); if there has been no
   successful ping for 5 min, tear down (step 1) and relaunch.

**DEVIATION (implementation, not interface).** The reference `exec`s a
separate `cilium-health-responder` binary inside the netns and tracks it by
pidfile. flowsdn runs the responder as a thread of the agent: the thread
`setns(CLONE_NEWNET)` into the health netns, binds the listening socket
there, and hands the socket to the async runtime (a socket stays in the
namespace it was created in). No child process, no orphan on crash, one
image binary. `health-endpoint.pid` is still written and contains the
**agent's** PID so tooling that reads it finds a live process; on start the
agent MUST NOT signal a process solely because a stale pidfile names it.
Before stopping a former responder, verify its executable identity and expected
health namespace and guard against PID reuse (for example with a verified
pidfd). An unrelated or unverifiable process is left alone and reported.
Namespace switching occurs only on the dedicated thread, never on a runtime
worker (ADR-0012 #117).

### 3.11 REST API server

#### 3.11.1 Listener and permissions

- One `UnixListener` at `--socket-path`; remove a stale socket file first
  (refuse to start if the path exists and a live agent answers `GET
  /healthz` on it — two agents on one node is a configuration error).
- After bind: `chown root:cilium` (group looked up by name; if the group
  does not exist log at debug and leave root:root), `chmod 0660`.
- HTTP/1.1, read and write timeouts 60 s, no TLS, no auth beyond the
  filesystem.
- Requests are served only after the `api-ready` fence; earlier requests
  block (not error) up to the client timeout. The `PUT/PATCH/DELETE
  /endpoint*` handlers additionally return `503` ("API not ready") if the
  fence is not released within the request context — matching the
  reference `waitReadyFn`.

#### 3.11.2 Operation-id access control

`--enable-cilium-api-server-access` (StringSlice, default `["*"]`): a list of
operation tokens (§5.9) and/or suffix wildcards `Prefix*`. The **denied** set
is every known token minus the allowed ones; `*` alone allows everything; an
unknown token or a wildcard not at the end is a fatal configuration error at
start. A request whose token is denied gets `403` with body `"Forbidden"`
before any handler runs. The six tokens the CNI and kubelet path need are
`GetConfig`, `GetHealthz`, `PutEndpointID`, `DeleteEndpointID`, `PostIPAM`,
`DeleteIPAMIP`; the agent MUST log at warning level when the configured
allow list excludes any of them (Helm never does; this catches hand-edited
ConfigMaps). The health API and the auxiliary listeners are not subject to
this list.

#### 3.11.3 Rate limiting

`--api-rate-limit` is a comma list `name=key:value,key:value;name=...` (the
reference `ToStringMapString` form: `endpoint-create=rate-limit:10/m,rate-burst:2`)
overriding the defaults below per limiter. Keys: `rate-limit` (`<n>/<unit>`,
unit `s|m|h`), `rate-burst`, `min-wait-duration`, `max-wait-duration`,
`estimated-processing-duration`, `auto-adjust`, `parallel-requests`,
`min-parallel-requests`, `max-parallel-requests`, `mean-over`, `log`,
`delayed-adjustment-factor`, `max-adjustment-factor`, `skip-initial`.

| Limiter | Ops | rate/s | burst | parallel (min) | est. proc | max wait | auto | skip-initial |
|---|---|---|---|---|---|---|---|---|
| `endpoint-create` | `PutEndpointID` | 0.5 | 4 | 4 (2) | 2 s | 60 s | yes | 4 |
| `endpoint-delete` | `DeleteEndpointID`, `DeleteEndpoint` | — | — | 4 (4) | 200 ms | — | yes | 0 |
| `endpoint-get` | `GetEndpointID` | 4 | 4 | 4 (2) | 200 ms | 10 s | yes | 4 |
| `endpoint-patch` | `PatchEndpointID`, `PatchEndpointIDConfig`, `PatchEndpointIDLabels` | 0.5 | 4 | 4 | 1 s | 15 s | yes | 4 |
| `endpoint-list` | `GetEndpoint` | 1 | 4 | 2 (2) | 300 ms | — | yes | 0 |

Semantics (§5.6): a request first waits for a parallelism slot, then for a
token; exceeding `max-wait` → `429` with `Retry-After: <seconds>` and
`models.Error` text. Auto-adjust scales rate and parallelism by
`estimated / mean(actual processing)` bounded by `max-adjustment-factor`
(100) and applied at `delayed-adjustment-factor` (0.5) per step, after the
first `skip-initial` requests, using the last `mean-over` (10) samples.
Metrics §8.1 `cilium_api_limiter_*`.

#### 3.11.4 Request processing metrics and logging

Every request records `cilium_api_process_time_seconds{path,method,return_code}`
(the swagger path template, e.g. `/endpoint/{id}`) and logs at debug with
`subsys=api`; `PUT/PATCH/DELETE /endpoint*` log at info with `endpointID`,
`containerID`, `k8sPodName`, `labels`, `ipv4`, `ipv6`, `syncBuild`.

### 3.12 Auxiliary listeners

| Listener | Behavior |
|---|---|
| `127.0.0.1:9879` and `[::1]:9879` (only the enabled families; failure to bind both is fatal, one is enough) `GET /healthz` | `StatusResponse` with `brief=true`; header `require-k8s-connectivity` (bool) overrides `agent-health-require-k8s-connectivity`; **200** when `cilium.state` is `Ok` or `Disabled`, **500** otherwise, body always the JSON. Kubelet startup/liveness/readiness (Helm sets `brief: true`) |
| `kube-proxy-replacement-healthz-bind-address` `GET /healthz` | JSON `{"lastUpdated": "<RFC3339>", "currentTime": "<RFC3339>"}`; **200** when `cilium.state` is Ok/Disabled and the local node is not being deleted, else **503** with `lastUpdated` = time of the last healthy status. `X-Content-Type-Options: nosniff` |
| `:4240` `GET /hello` | bound on every local node address (IPv4/IPv6 internal and external IPs from the local node store, re-bound when they change) and inside the health netns; responds `200` empty body to any path? — no: only `/hello`; other paths 404. Plain HTTP/1.1 |
| `/statedb/query` on the API socket | conditional on spec 00 decision 12.5 (recommended (a)): `POST`? — the reference client uses `GET` with a JSON body; flowsdn MUST accept both `GET` and `POST` with body `{"table":"health","index":"id","key":"<base64>","lowerbound":bool}` and stream `{"rev":n,"obj":<HealthStatus>}` objects then EOF, or `{"err":"…"}`. Only `table == "health"`; other tables `404`. This is what upstream `cilium-dbg status` calls to print "Modules Health" |
| `GET /health/modules` on the API socket | flowsdn-native JSON array of `HealthStatus` (spec 00 §8.4) |

### 3.13 Health checker

Owner: `flowsdn-healthcheck` (ADR-0010). Enabled by `enable-health-checking` (default true).
Runs inside the agent after `endpoint-restore.restored-into-manager` and
after `GET /healthz` first answered (the health server waits for the agent
status to be available).

- **Node list**: `GET /cluster/nodes` on the agent's own API (in-process
  call is acceptable) with `client-id` for incremental `nodes-added` /
  `nodes-removed`; a `client-id` the server does not know (restart) returns
  the full list with a new id. For every node: host primary address
  (IPv4 preferred unless the node has only IPv6 or `prefer IPv6` when the
  local node is IPv6-only), host secondary addresses, health-endpoint
  primary address (`health-endpoint-address`), secondary health addresses.
- **Probes** per address, concurrently, spread by a token bucket of
  `ipCount / interval` so one round completes within one interval:
  - ICMP echo: `health-check-icmp-failure-threshold` (3) requests 100 ms
    apart, deadline `probe-deadline` (10 s? the reference `ProbeDeadline`
    default is 10 s? — it is 1 s per request? No: `ProbeDeadline` = 10 s
    total); reachable if ≥ 1 reply; latency = mean RTT of replies. Needs
    `CAP_NET_RAW`.
  - HTTP: `GET http://<ip>:4240/hello`, timeout 10 s; reachable on 200;
    latency = wall time.
- **Interval** (§5.7): `base = 10 s + connectivity-probe-frequency-ratio ×
  100 s` (60 s at the default 0.5), `interval = base × ln(1 + ipCount)`
  (base when ipCount is 0). Recomputed when the node set changes; the ticker
  is reset.
- **Results**: `HealthStatusResponse` (§4.7) replaced atomically after each
  round; `ConnectivityStatus.status` is empty on success, otherwise the
  error text; `latency` in ns; `lastProbed` RFC3339.
- **Metrics** after each round (§8.1): counts per `type` (`node`/`endpoint`)
  and status (`reachable`/`unreachable`/`unknown`, summarized over all
  addresses of the node: unknown if none probed, unreachable if any failed);
  latency histogram per `type`, `protocol` (`icmp`/`http`), `address_type`
  (`primary`/`secondary`); an unreachable HTTP path observes the 10 s
  timeout value.
- `PUT /status/probe` runs one synchronous round and returns it without
  disturbing the ticker.
- **`cilium-dbg status`** renders `cluster.ciliumHealth` (the health
  server's own status: `Ok` once the prober ran, `Warning` "not yet
  probed"), and with `--verbose` fetches `GET /v1beta/status` and prints per
  node `host` and `health-endpoint` reachability and latency; `cilium-health
  status` prints the same tree (`--succinct` one line per node, `--probe`
  uses `PUT /status/probe`).

### 3.14 Status collector

A set of named **probes**, each a task: run, wait `interval` (default
`status-collector-interval` 5 s, or the probe's own function of consecutive
failures), run again. A probe that has not returned after
`status-collector-warning-threshold` (15 s) is **stale** (its name and start
time appear in `StatusResponse.stale`); after
`status-collector-failure-threshold` (1 m) its result is recorded as an
error and, if `status-collector-stackdump-path` is set, a goroutine/thread
dump is written once (in Rust: `tokio-console`-style task dump if available,
else a note). Probes never overlap with themselves.

| Probe | Interval | Fills |
|---|---|---|
| `kvstore` | 5 s | `kvstore` (`Disabled` when no kvstore) |
| `kubernetes` | 10 s × cluster-size factor on success (2 m when CiliumNode CRD is off); exponential 5 s→2 m on failure | `kubernetes{state,msg=<server version>,k8s-api-versions}` |
| `ipam` | 5 s | `ipam{allocations,ipv4[],ipv6[],status}` |
| `node-monitor` | 5 s | `nodeMonitor` |
| `cluster` | 5 s | `cluster.self` (node name), `cluster.nodes` |
| `cilium-health` | 5 s | `cluster.ciliumHealth` |
| `l7-proxy` | 5 s | `proxy` |
| `controllers` | 5 s | `controllers[]` (global controller manager) |
| `clustermesh` | 5 s | `cluster-mesh` |
| `hubble`, `hubble-metrics` | 5 s | `hubble`, `hubble-metrics` |
| `encryption` | 5 s | `encryption` |
| `kube-proxy-replacement` | 5 s | `kube-proxy-replacement` |
| `auth-cert-provider` | 5 s | `auth-certificate-provider` |
| `cni-config` | 5 s | `cni-file` |
| `masquerading`, `bigtcp-v6`, `bigtcp-v4`, `bandwidth-manager`, `host-firewall`, `routing`, `clock-source`, `bpf-maps`, `cni-chaining`, `identity-range`, `SRv6`, `attach-mode`, `datapath-mode`, `configured-datapath-mode` | 5 s | the field of the same name |

**Verdict** (`cilium` field, computed on every `GET`, §5.8), first match:

| Condition | `cilium.state` | `cilium.msg` |
|---|---|---|
| not every probe has completed once (bounded by `status-collector-probe-check-timeout` 5 m, after which the missing probes are reported as errors) | `Warning` | `Not all probes executed at least once` |
| `stale` non-empty | `Warning` | `<version>    Stale status data` |
| `kvstore.state` not Ok and not Disabled | that state | `<version>    Kvstore service is not ready: <msg>` |
| k8s enabled, `kubernetes.state` not Ok, and `require-k8s-connectivity` | that state | `<version>    Kubernetes service is not ready: <msg>` |
| `cni-file.state` is Failure | `Failure` | `<version>    Could not write CNI config file: <msg>` |
| otherwise | `Ok` | `<version>` |

`<version>` = `"<ver> (v<ver>-<revision>)"`. **DEVIATION** (spec 00 §3.4.2
approximated this table; this spec is authoritative): the reference reports
"not all probes" as `Warning`, not `Failure`, and does not consult module
health for the verdict. `brief=true` returns only `cluster.ciliumHealth`,
the first controller with a `last-failure-msg`, `stale` and `cilium`.

## 4. Data model

### 4.1 Endpoint (in memory)

Beyond the identifiers of 3.1: `state`, `status_log` (ring of 256
`{timestamp, code: OK|Warning|Failure, type: BPF|Policy|Other, message,
state}`; `current_status()` = worst code among the latest entry of each
type, BPF > Policy > Other priority for the message), `identity_revision`
(i32, bumped on label change), `policy_revision` (u64), `desired_policy`,
`realized_policy`, `proxy_policy_revision`, `proxy_statistics`
(map keyed `ingress|egress:<proto>:<port>:<proxy-port>`), `dns_rules`
(`DNSRulesV2`), `dns_history`, `dns_zombies`, `controllers` (per-endpoint
controller manager), `skipped_regeneration_level`, `skipped_policy_revision`,
`ct_cleaned`, `bpf_headerfile_hash` (endpoint hash), `has_bpf_program`
(one-shot), `alive` (cancellation token), `regen_failed` (one-shot),
`cilium_endpoint_uid`, `lockdown`, `no_track_port` (u16), `bps`,
`ingress_bps`, `is_host`, `is_ingress`, `pod` (cached slim Pod), `k8s_ports`
(named ports), `reporter` (health scope `cilium-endpoint-<id> (<ns>/<pod>)`).

### 4.2 `ep_config.json`

Top-level JSON object; Go's default encoding of the struct below (field name
= JSON key unless tagged). Order is not significant. `omitempty` fields are
absent when zero.

| JSON key | Type | Meaning / notes |
|---|---|---|
| `ID` | u16 | endpoint id |
| `dockerID` | string, omitempty | container id (legacy key, MUST be kept) |
| `ContainerNetnsPath` | string | |
| `IfName` | string | host interface |
| `IfIndex` | i32 | host ifindex (0 for restored host endpoint; re-read) |
| `ParentIfIndex` | i32 | |
| `ContainerIfName` | string | |
| `IsSecondaryInterface` | bool | |
| `OpLabels` | object `{"Custom":Labels,"OrchestrationIdentity":Labels,"Disabled":Labels,"OrchestrationInfo":Labels}` where `Labels` = `{"<key>": {"key":"…","value":"…","source":"…"}}` | 3.1 |
| `LXCMAC` | string `aa:bb:cc:dd:ee:ff` | endpoint MAC |
| `IPv6` | string (empty `""` when unset) | |
| `IPv6IPAMPool` | string | |
| `IPv4` | string | |
| `IPv4IPAMPool` | string | |
| `NodeMAC` | string | host-side MAC |
| `SecLabel` | object `{"id":u32,"labels":Labels,"labelsSHA256"?:string}` or `null` | identity; the numeric id is a hint for restore, labels are authoritative |
| `Options` | object `{"map":{"<OptionName>":int}}`? — the reference `IntOptions` marshals as `{"<OptionName>": <int>, …}` under key `Options` via its own `MarshalJSON` (map of name → value) | runtime options 3.1 |
| `DNSRules` | omitempty | **legacy v1**, keyed `<port>` (u16 string). Read: ignored. Write: never |
| `DNSRulesV2` | object `{"<port>/<proto>": {"<selector-string>": {"<IP>": …}}}`, omitempty | restored L7 DNS rules keyed by port/protocol (spec 11 owns the value shape) |
| `DNSHistory` | object (`fqdn.DNSCache` JSON: array of `{"Name","LookupTime","IPs","TTL"}` groups) or `null` | |
| `DNSZombies` | object or `null` | |
| `K8sPodName` | string | |
| `K8sNamespace` | string | |
| `K8sUID` | string | |
| `DatapathConfiguration` | object with the six kebab-case fields of `EndpointDatapathConfiguration` (`require-routing` nullable) | |
| `CiliumEndpointUID` | string | `""` when never owned |
| `Properties` | object `{"property-…": any}` or `null` | 3.1 |
| `NetnsCookie` | u64 | |
| `RTInfo` | u32 | |

Reader rules: unknown keys ignored; missing keys take zero values then
`SetDefaultConfiguration` fills options; `SecLabel: null` restores as
`reserved:init` until re-resolved; both `DNSRules` and `DNSRulesV2` present
→ v2 wins. Writer rules: always emit every non-omitempty key, `IPv4`/`IPv6`
as `""` when unset (Go `netip.Addr` zero marshals to `""`).

### 4.3 State-directory files

See 3.6. `template.txt` = spec 01 object identity hash (hex) + `\n`.
`bpf_lxc.json` = spec 01 config dump.

### 4.4 REST operations (agent API, `/v1`)

Legend: consumers **cni** (`cilium-cni`, spec 09), **dbg** (`cilium-dbg`),
**health** (cilium-health server/CLI), **op** (operator status),
**kubelet** (via 9879 only). RL = limiter of 3.11.3. Mandatory-for-CNI
operations are marked ★. Error bodies are `models.Error` (a JSON string)
unless the code is listed bare (empty body).

| # | Method path | Token | Parameters | Request → Response | Errors | Consumer | RL |
|---|---|---|---|---|---|---|---|
| 1 | `GET /cluster/nodes` | `GetClusterNodes` | header `client-id` int | — → 200 `ClusterNodeStatus` | — | health prober, dbg node list | — |
| 2 | `GET /healthz` ★ | `GetHealthz` | headers `brief` bool, `require-k8s-connectivity` bool | — → 200 `StatusResponse` | — (verdict inside body) | dbg status, health, op, monitor | — |
| 3 | `GET /config` ★ | `GetConfig` | — | — → 200 `DaemonConfiguration` | — | **cni** (every ADD), dbg config | — |
| 4 | `PATCH /config` | `PatchConfig` | body `DaemonConfigurationSpec` (required) | → 200 | 400 `Error` (bad option), 403, 500 `Error` | dbg config `X=enable`; triggers `RegenerateAllEndpoints(DaemonConfigUpdate)` | — |
| 5 | `GET /endpoint/{id}` | `GetEndpointID` | path `id` (prefixed, 3.9.1) | → 200 `Endpoint` | 400 `Error` (bad id), 404, 429 | dbg endpoint get, cni CHECK | `endpoint-get` |
| 6 | `PUT /endpoint/{id}` ★ | `PutEndpointID` | path `id`; body `EndpointChangeRequest` (required) | → 201 `Endpoint` | 400 `Error`, 403, 409 (exists, 3.3 step 5), 429, 500 `Error`, 503 | **cni ADD**, in-process health | `endpoint-create` |
| 7 | `PATCH /endpoint/{id}` | `PatchEndpointID` | path `id`; body `EndpointChangeRequest` | → 200 | 400 `Error`, 403, 404, 429, 500 `Error` (regen failed), 503 | dbg (rare), tests; `state` only `ready`/`waiting-for-identity`/empty is applied; addressing/labels/MAC/ifindex changes → `EndpointUpdate rewrite+load` and wait | `endpoint-patch` |
| 8 | `DELETE /endpoint/{id}` ★ | `DeleteEndpointID` | path `id` | → 200; 206 `integer` (error count) | 400 `Error`, 403, 404, 429, 503 | **cni DEL**, dbg endpoint disconnect | `endpoint-delete` |
| 9 | `GET /endpoint` | `GetEndpoint` | query `labels` []string | → 200 `[]Endpoint` | 404 (no match), 429 | dbg endpoint list, monitor, policy wait | `endpoint-list` |
| 10 | `DELETE /endpoint` | `DeleteEndpoint` | body `EndpointBatchDeleteRequest` (required) | → 200; 206 `integer` | 400 (empty container-id), 404, 429, 503 | cni DEL fallback / deletion queue replay | `endpoint-delete` |
| 11 | `GET /endpoint/{id}/config` | `GetEndpointIDConfig` | path `id` | → 200 `EndpointConfigurationStatus` | 404, 429 | dbg endpoint config | — |
| 12 | `PATCH /endpoint/{id}/config` | `PatchEndpointIDConfig` | path `id`; body `EndpointConfigurationSpec` (required) | → 200 | 400 (validation), 403, 404, 429, 500 `Error`, 503 | dbg endpoint config `Debug=enable` | `endpoint-patch` |
| 13 | `GET /endpoint/{id}/labels` | `GetEndpointIDLabels` | path `id` | → 200 `LabelConfiguration` | 404, 429 | dbg endpoint labels | — |
| 14 | `PATCH /endpoint/{id}/labels` | `PatchEndpointIDLabels` | path `id`; body `LabelConfigurationSpec` (required) | → 200 | 403, 404, 429, 500 `Error` (reserved label), 503 | dbg endpoint labels `-a/-d` | `endpoint-patch` |
| 15 | `GET /endpoint/{id}/log` | `GetEndpointIDLog` | path `id` | → 200 `EndpointStatusLog` (`[]EndpointStatusChange`, newest first, ≤ 256) | 400, 404, 429 | dbg endpoint log | — |
| 16 | `GET /endpoint/{id}/healthz` | `GetEndpointIDHealthz` | path `id` | → 200 `EndpointHealth` | 400, 404, 429 | dbg endpoint health | — |
| 17 | `GET /identity` | `GetIdentity` | query `labels` []string | → 200 `[]Identity` | 404, 520 `Error` (allocator unavailable), 521 `Error` (invalid storage format) | dbg identity list | — |
| 18 | `GET /identity/{id}` | `GetIdentityID` | path `id` string | → 200 `Identity` | 400, 404, 520 `Error`, 521 `Error` | dbg identity get | — |
| 19 | `GET /identity/endpoints` | `GetIdentityEndpoints` | — | → 200 `[]IdentityEndpoints` | 404 | dbg identity list --endpoints | — |
| 20 | `POST /ipam` ★ | `PostIPAM` | query `family` (`ipv4`\|`ipv6`), `owner`, `pool`; header `expiration` bool | → 201 `IPAMResponse` | 403, 502 `Error` | **cni ADD** (`owner=<ns>/<pod>`, `expiration=true`) — spec 07 | — |
| 21 | `POST /ipam/{ip}` | `PostIPAMIP` | path `ip`; query `owner`, `pool` | → 200 | 400, 403, 409 (in use), 500 `Error`, 501 | tests, dbg (not wired) — spec 07 | — |
| 22 | `DELETE /ipam/{ip}` ★ | `DeleteIPAMIP` | path `ip`; query `pool` | → 200 | 400, 403, 404, 500 `Error`, 501 | **cni** rollback — spec 07 | — |
| 23 | `GET /policy` | `GetPolicy` | — | → 200 `Policy{revision, policy: JSON string of rules}` | 404 | dbg policy get — spec 06 | — |
| 24 | `GET /policy/selectors` | `GetPolicySelectors` | — | → 200 `SelectorCache` | — | dbg policy selectors — spec 06 | — |
| 25 | `GET /policy/subject-selectors` | `GetPolicySubjectSelectors` | — | → 200 `SelectorCache` | — | dbg policy selectors --subject | — |
| 26 | `GET /lrp` | `GetLRP` | — | → 200 `[]LRPSpec` | — | dbg lrp list — spec 05 | — |
| 27 | `GET /service` | `GetService` | — | → 200 `[]Service` | — | dbg service list — spec 05 | — |
| 28 | `GET /prefilter` | `GetPrefilter` | — | → 200 `Prefilter` | 500 `Error` | dbg prefilter list (deferred: empty spec) | — |
| 29 | `PATCH /prefilter` | `PatchPrefilter` | body `PrefilterSpec` | → 200 `Prefilter` | 403, 461 `Error` (invalid CIDR), 500 `Error`; flowsdn 501 | dbg prefilter update (deferred) | — |
| 30 | `DELETE /prefilter` | `DeletePrefilter` | body `PrefilterSpec` | → 200 `Prefilter` | 403, 461 `Error`, 500 `Error`; flowsdn 501 | dbg prefilter delete (deferred) | — |
| 31 | `GET /debuginfo` | `GetDebuginfo` | — | → 200 `DebugInfo` | 500 `Error` | dbg debuginfo, dbg version, bugtool | — |
| 32 | `GET /cgroup-dump-metadata` | `GetCgroupDumpMetadata` | — | → 200 `CgroupDumpMetadata` | 500 `Error`; flowsdn 501 | dbg cgroups list (deferred) | — |
| 33 | `GET /map` | `GetMap` | — | → 200 `BPFMapList` | — | dbg map list (userspace cache view, spec 01 §3.11) | — |
| 34 | `GET /map/{name}` | `GetMapName` | path `name` | → 200 `BPFMap` | 404 | dbg map get | — |
| 35 | `GET /map/{name}/events` | `GetMapNameEvents` | path `name`; query `follow` bool | → 200 JSON-lines stream | 404; flowsdn 501 | dbg map events (deferred) | — |
| 36 | `GET /fqdn/cache` | `GetFqdnCache` | query `matchpattern`, `cidr`, `source` | → 200 `[]DNSLookup` | 400 `Error`, 404 | dbg fqdn cache list — spec 11 | — |
| 37 | `DELETE /fqdn/cache` | `DeleteFqdnCache` | query `matchpattern` | → 200 | 400 `Error`, 403 | dbg fqdn cache clean — spec 11 | — |
| 38 | `GET /fqdn/cache/{id}` | `GetFqdnCacheID` | path `id` (endpoint); query as 36 | → 200 `[]DNSLookup` | 400 `Error`, 404 | dbg fqdn cache list -e — spec 11 | — |
| 39 | `GET /fqdn/names` | `GetFqdnNames` | — | → 200 `NameManager` | 400 `Error` | dbg fqdn names — spec 11 | — |
| 40 | `GET /ip` | `GetIP` | query `cidr`, `labels` []string | → 200 `[]IPListEntry` | 400 `Error`, 404 (empty) | dbg ip list/get — spec 03 §4.9 | — |
| 41 | `GET /node/ids` | `GetNodeIds` | — | → 200 `[]NodeID` | — | dbg nodeid list — spec 10 | — |
| 42 | `GET /bgp/peers` | `GetBGPPeers` | — | → 200 `[]BgpPeer` | 500 `Error`, 501 `Error` (BGP disabled) | dbg bgp peers | — |
| 43 | `GET /bgp/routes` | `GetBGPRoutes` | query `table_type` (`loc-rib`\|`adj-rib-in`\|`adj-rib-out`), `afi`, `safi`, `router_asn`, `neighbor` | → 200 `[]BgpRoute` | 500 `Error`, 501 `Error` | dbg bgp routes | — |
| 44 | `GET /bgp/route-policies` | `GetBGPRoutePolicies` | query `router_asn` | → 200 `[]BgpRoutePolicy` | 500 `Error`, 501 `Error` | dbg bgp route-policies | — |

Plus the non-swagger routes `GET|POST /statedb/query` (conditional, 3.12)
and `GET /health/modules` (flowsdn-native). Removed in 1.20 and therefore
**not** served: `PUT/DELETE /policy`, `GET /metrics/`, `/recorder*`,
`/service/{id}` writes, `/statedb/dump`.

### 4.5 REST models (agent API)

Field names exactly as below (kebab-case unless shown). `*` = required.

| Model | Fields |
|---|---|
| `Error` | JSON string |
| `EndpointState` | enum `waiting-for-identity` `not-ready` `waiting-to-regenerate` `regenerating` `restoring` `ready` `disconnecting` `disconnected` `invalid` |
| `EndpointChangeRequest` | `id` int64, `container-id`, `container-netns-path`, `labels` []string (`source:key=value`), `interface-name`, `interface-index` int64, `parent-interface-index` int64, `container-interface-name`, `state`* `EndpointState`, `mac`, `host-mac`, `addressing` `AddressPair`, `k8s-pod-name`, `k8s-namespace`, `k8s-uid`, `datapath-map-id` int64, `policy-enabled` bool, `pid` int64, `sync-build-endpoint` bool, `is-secondary-interface` bool, `netns-cookie` string, `datapath-configuration` `EndpointDatapathConfiguration`, `properties` object |
| `EndpointDatapathConfiguration` | `require-arp-passthrough` bool, `require-egress-prog` bool, `external-ipam` bool, `require-routing` bool (nullable), `install-endpoint-route` bool, `disable-sip-verification` bool |
| `AddressPair` | `ipv4`, `ipv4-expiration-uuid`, `ipv4-pool-name`, `ipv6`, `ipv6-expiration-uuid`, `ipv6-pool-name` |
| `Endpoint` | `id` int64, `spec` `EndpointConfigurationSpec`, `status` `EndpointStatus` |
| `EndpointConfigurationSpec` | `options` `ConfigurationMap` (string→string of option name → `Enabled`/`Disabled`/numeric), `label-configuration` `LabelConfigurationSpec` |
| `EndpointConfigurationStatus` | `realized` `EndpointConfigurationSpec`, `immutable` `ConfigurationMap`, `error` `Error` |
| `EndpointStatus` | `external-identifiers` `EndpointIdentifiers`, `identity` `Identity`, `labels` `LabelConfigurationStatus`, `realized` `EndpointConfigurationSpec`, `networking` `EndpointNetworking`, `policy` `EndpointPolicyStatus`, `log` `EndpointStatusLog` (only the **latest** entry in `GET /endpoint*`; full ring in `/log`), `controllers` `ControllerStatuses`, `state`* `EndpointState` (`not-ready` substituted per 3.2), `health` `EndpointHealth`, `namedPorts` `NamedPorts` |
| `EndpointIdentifiers` | `cni-attachment-id`, `container-id`, `container-name`, `docker-endpoint-id`, `docker-network-id`, `pod-name` (`<ns>/<pod>`), `k8s-pod-name`, `k8s-namespace` |
| `EndpointNetworking` | `addressing` []`AddressPair`, `host-addressing` `NodeAddressing`, `host-mac`, `mac`, `interface-name`, `interface-index` int64, `container-interface-name` |
| `NodeAddressing` | `ipv4`, `ipv6` `NodeAddressingElement{enabled bool, ip, alloc-range, address-type}` |
| `EndpointHealth` | `overallHealth`, `bpf`, `policy` (enum `OK` `Bootstrap` `Pending` `Warning` `Failure` `Disabled`), `connected` bool. Mapping from state: `regenerating`/`waiting-to-regenerate`/`disconnecting` → all `Pending`, connected; `waiting-for-identity` → bpf `Disabled`, policy `Bootstrap`, overall `Disabled`, connected; `not-ready` → all `Warning`, connected; `disconnected` → all `Disabled`, not connected; `ready` → all `OK`, connected; otherwise (`restoring`, `invalid`) all `Disabled`, not connected |
| `EndpointStatusChange` | `timestamp` string, `code` enum `ok`\|`failed` (Warning and Failure both render `failed`), `message`, `state` `EndpointState` |
| `EndpointStatusLog` | `[]EndpointStatusChange` |
| `EndpointPolicyStatus` | `spec` `EndpointPolicy` (desired), `realized` `EndpointPolicy`, `proxy-policy-revision` int64, `proxy-statistics` []`ProxyStatistics` |
| `EndpointPolicy` | `policy-revision` int64, `id` int64 (identity), `policy-enabled` enum `none` `ingress` `egress` `both` `audit-ingress` `audit-egress` `audit-both`, `build` int64, `allowed-ingress-identities` []int64, `denied-ingress-identities`, `allowed-egress-identities`, `denied-egress-identities` (identities of L3-only entries), `l4` `L4Policy{ingress[],egress[] PolicyRule{rule string, derived-from-rules [][]string, rules-by-selector}}`, `cidr-policy` `CIDRPolicy{ingress[],egress[] PolicyRule}` — spec 06 owns the content |
| `ProxyStatistics` | `protocol`, `port` int64, `allocated-proxy-port` int64, `location` enum `ingress`\|`egress`, `statistics` `RequestResponseStatistics{requests,responses: MessageForwardingStatistics{received,forwarded,denied,error}}` |
| `LabelConfiguration` | `spec` `LabelConfigurationSpec{user []string}`, `status` `LabelConfigurationStatus{realized LabelConfigurationSpec, security-relevant []string, derived []string, disabled []string}` |
| `ControllerStatus` | `name`, `uuid`, `configuration{interval, error-retry bool, error-retry-base}` (durations as Go strings e.g. `10s`), `status{success-count, failure-count, consecutive-failure-count, last-success-timestamp, last-failure-timestamp, last-failure-msg}` |
| `ControllerStatuses` | `[]ControllerStatus` |
| `Identity` | `id` int64, `labels` []string, `labelsSHA256` (spec 03 §4.9) |
| `IdentityEndpoints` | `identity` `Identity`, `refCount` int64 |
| `EndpointBatchDeleteRequest` | `container-id` |
| `DaemonConfiguration` | `spec` `DaemonConfigurationSpec{options ConfigurationMap, policy-enforcement enum default|always|never}`, `status` `DaemonConfigurationStatus` |
| `DaemonConfigurationStatus` | `realized` `DaemonConfigurationSpec`, `immutable` `ConfigurationMap`, `addressing` `NodeAddressing`, `k8s-endpoint`, `k8s-configuration`, `nodeMonitor` `MonitorStatus`, `kvstoreConfiguration{type, options map}`, `deviceMTU` int64, `routeMTU` int64, `enableRouteMTUForCNIChaining` bool, `packetizationLayerPMTUDMode`, `datapathMode` enum `veth`\|`netkit`\|`netkit-l2`, `configuredDatapathMode` enum `auto`\|…, `ipam-mode`, `masquerade` bool, `masqueradeProtocols{ipv4 bool, ipv6 bool}`, `installUplinkRoutesForDelegatedIPAM` bool, `daemonConfigurationMap` object (every config key → effective value; spec 00 §8.4), `GSOMaxSize`, `GROMaxSize`, `GSOIPv4MaxSize`, `GROIPv4MaxSize` int64, `deviceHeadroom`, `deviceTailroom` int64, `ipLocalReservedPorts` string, `enableBBRHostNamespaceOnly` bool. **cni reads**: `ipam-mode`, `addressing`, `routeMTU`, `deviceMTU`, `datapathMode`, `masquerade*`, `ipLocalReservedPorts`, headroom/tailroom, GRO/GSO, `enableRouteMTUForCNIChaining`, `installUplinkRoutesForDelegatedIPAM`, `packetizationLayerPMTUDMode`, `enableBBRHostNamespaceOnly` |
| `ClusterNodeStatus` | `self` (node name), `nodes-added` []`NodeElement`, `nodes-removed` []`NodeElement`, `client-id` int64 |
| `NodeElement` | `name`, `primary-address` `NodeAddressing`, `secondary-addresses` []`NodeAddressingElement`, `health-endpoint-address` `NodeAddressing`, `ingress-address` `NodeAddressing`, `source` |
| `IPAMResponse` | `address`* `AddressPair`, `ipv4`, `ipv6` `IPAMAddressResponse{ip, gateway, cidrs[], master-mac, expiration-uuid, interface-number, skip-masquerade bool}`, `host-addressing`* `NodeAddressing` (spec 07) |
| `DebugInfo` | `cilium-version`, `kernel-version`, `cilium-status` `StatusResponse`, `endpoint-list` []`Endpoint`, `service-list` []`Service`, `policy` `Policy`, `cilium-memory-map`, `cilium-nodemonitor-memory-map`, `environment-variables` []string, `subsystem` map[string]string, `encryption` object |
| `BPFMapList` / `BPFMap` | `maps[]{path, cache[] BPFMapEntry{key, value, desired-action enum ok|insert|delete, last-error}}`; `BPFMapStatus{dynamic-size-ratio number, maps[] {name, size}}` |
| `Policy` | `revision` int64, `policy` string |
| `SelectorCache` | `[]SelectorIdentityMapping{selector, labels, identities []int64, users int64}` |
| `IPListEntry` | `cidr`*, `identity`* int64, `hostIP`, `encryptKey` int64, `metadata{source, namespace, name}` |
| `NodeID` | `id`* int64, `ips`* []string |
| `Prefilter` | `spec{revision int64, deny []string}`, `status{realized}` |
| `NamedPorts` / `Port` | `[]{name, port uint16, protocol enum TCP UDP SCTP ICMP ICMPV6 ANY}` |
| `Service`, `LRPSpec`, `BgpPeer`, `BgpRoute`, `BgpRoutePolicy`, `DNSLookup`, `NameManager`, `CgroupDumpMetadata` | owned by specs 05, 10 (BGP), 11; shapes as in `openapi.yaml` |

### 4.6 `StatusResponse` (what `cilium status` parses)

`Status` = `{state: Ok|Warning|Failure|Disabled, msg}`.

| Field | Type | Filled by | `cilium-dbg status` line |
|---|---|---|---|
| `cilium` | `Status` | verdict 3.14 | `Cilium: <state> <msg>` |
| `kvstore` | `Status` | kvstore probe | `KVStore:` |
| `kubernetes` | `K8sStatus{state,msg,k8s-api-versions[]}` | kubernetes probe | `Kubernetes:`, `Kubernetes APIs:` |
| `cni-file` | `Status` | cni-config probe (`Ok` "successfully wrote CNI configuration file to …") | `CNI Config file:` |
| `cni-chaining` | `{mode enum none aws-cni flannel generic-veth portmap}` | | `CNI Chaining:` |
| `host-firewall` | `{mode Disabled|Enabled, devices[]}` | | `Host firewall:` |
| `hubble` | `{state, msg, observer{…}}` | | `Hubble:` |
| `hubble-metrics` | `{state, msg}` | | part of `Hubble:` |
| `datapath-mode` | enum `veth` `netkit` `netkit-l2` | | `Device Mode:` |
| `configured-datapath-mode` | enum `auto` … | | |
| `attach-mode` | enum `tc` `tcx` | | `Attach Mode:` |
| `kube-proxy-replacement` | `{mode True|False, devices[], deviceList[{name, ip[]}], directRoutingDevice, features{…}}` | | `KubeProxyReplacement:` (+ `--verbose` details) |
| `ipam` | `{allocations map ip→owner, ipv4[], ipv6[], status}` | | `IPAM:` (+ verbose allocated addresses) |
| `nodeMonitor` | `{cpus, npages, pagesize, lost, unknown}` | | verbose |
| `cluster` | `{ciliumHealth Status, self, nodes[]}` | cluster + cilium-health probes | `Cluster health:`, `Cilium health daemon:` |
| `controllers` | `[]ControllerStatus` | controllers probe | `Controller Status: n/m healthy` (+ `--all-controllers`) |
| `proxy` | `{port-range, ip, total-redirects, total-ports, redirects[{name, proxy, proxy-port}], envoy-deployment-mode embedded|external}` | | `Proxy Status:` |
| `identity-range` | `{min-identity, max-identity}` | | `Global Identity Range:` |
| `ipv6-big-tcp`, `ipv4-big-tcp` | `{enabled, maxGRO, maxGSO}` | | `IPv6 BIG TCP:`, `IPv4 BIG TCP:` |
| `bandwidth-manager` | `{enabled, devices[], congestionControl cubic|bbr}` | | `BandwidthManager:` |
| `masquerading` | `{enabled, enabledProtocols{ipv4,ipv6}, mode BPF|iptables (always `BPF`, ADR-0003), ip-masq-agent bool, snat-exclusion-cidr, -v4, -v6}` | | `Masquerading:` |
| `routing` | `{inter-host-routing-mode Native|Tunnel, intra-host-routing-mode BPF|Legacy, tunnel-protocol}` | | `Routing:` |
| `clock-source` | `{mode ktime|jiffies, hertz}` | | `Clock Source for BPF:` |
| `srv6` | `{enabled, srv6EncapMode SRH|Reduced}` | | verbose |
| `stale` | map probe name → RFC3339 start time | collector | `Stale status data` warning |
| `client-id` | int64 | `GET /cluster/nodes` bookkeeping (0 here) | — |
| `cluster-mesh` | `{clusters[] RemoteCluster{name, ready, connected, synced{…}, config{…}, num-nodes, num-shared-services, num-endpoint-slices, num-service-exports, num-identities, num-endpoints, status, num-failures, last-failure}}` | | `ClusterMesh: n/m remote clusters ready` |
| `bpf-maps` | `BPFMapStatus` | bpf-maps probe (the 22 named maps: Auth, Non-TCP CT, TCP CT, Endpoints, IP cache, IPv4/IPv6 masquerading agent, IPv4 fragmentation, IPv4/IPv6 service, backend, reverse NAT, Metrics, Ratelimit metrics, NAT, Neighbor table, Endpoint policy, Policy stats, Session affinity, Sock reverse NAT) | verbose |
| `encryption` | `{mode Disabled|IPsec|Wireguard|Ztunnel, msg, ipsec{…}, wireguard{…}}` | | `Encryption:` |
| `auth-certificate-provider` | `Status` | | verbose |

### 4.7 Health API (`/v1beta` on `health.sock`)

| # | Method path | Token | Response | Consumer |
|---|---|---|---|---|
| 45 | `GET /healthz` | `GetHealthz` | 200 `HealthResponse{cilium StatusResponse, uptime string, system-load{last1min,last5min,last15min} strings}`; 500 `Error` when the agent `GET /healthz` fails | `cilium-health get`, `ping` |
| 46 | `GET /status` | `GetStatus` | 200 `HealthStatusResponse` | `cilium-health status`, `cilium-dbg status --verbose` |
| 47 | `PUT /status/probe` | `PutStatusProbe` | 200 `HealthStatusResponse`; 403; 500 `Error` | `cilium-health status --probe` |

`HealthStatusResponse{timestamp, probeInterval (Go duration string),
local{name}, nodes[] NodeStatus{name, host{primary-address PathStatus,
secondary-addresses[]}, health-endpoint{primary-address, secondary-addresses[]},
endpoint PathStatus (deprecated copy of health-endpoint.primary-address)}}`;
`PathStatus{ip, icmp ConnectivityStatus, http ConnectivityStatus}`;
`ConnectivityStatus{latency int64 ns, status string ("" = ok), lastProbed}`.

### 4.8 `CiliumEndpoint.status` fields written

`id`, `external-identifiers` (as 4.5), `identity{id, labels[]}`,
`networking{addressing[{ipv4,ipv6}], node: <node IP>}`, `state`
(**compressed**: `restoring`, `waiting-to-regenerate`, `regenerating`,
`ready`, `disconnecting`, `disconnected` all render `ready`; others as-is),
`encryption{key}` (IPsec SPI or 0), `named-ports[]`, `service-account`.
**Not** written: `controllers`, `health`, `log`, `policy` (schema fields kept
for old readers; the reference stopped writing them). Consumers: operator
(CES batching, GC), remote agents (ipcache via CEP/CES), Hubble (pod
metadata), `kubectl get cep`.

### 4.9 Deletion-queue entry

`<deleteQueue>/<sha256hex(contents)>.delete`, containing either
`{"container-id":"<cid>"}` or the bare `<cid>:<ifname>` string. The CNI
enforces a 256-entry cap. This aligns the agent replay contract with the
normative writer format in spec 09 §4.7/§5.1; the earlier random-name and
JSON-only description was incomplete.

## 5. Algorithms

### 5.1 Endpoint id allocation

- Pool `1..4095` (reference `maxID`), free-list semantics: allocate the
  **lowest** free id? — the reference `idpool` returns an arbitrary free id
  (map iteration); flowsdn MUST return the lowest free id so that ids are
  stable across implementations in tests (**DEVIATION**, harmless: nothing
  depends on which id is chosen). The pool MUST hold at most one lease per
  id; `release(id)` after the endpoint is fully gone (3.8 step 5).
- `reuse(id)` (restore): mark `id` leased even if `id > 4095` (a state dir
  from an implementation with a wider pool restores); refuse if already
  leased (duplicate directory) → the endpoint goes to `toClean`.
- Exhaustion → `PUT` fails `500` "no more endpoint IDs available".
- The type is u16 and every consumer (`%05d` names, `cilium_call_policy`
  65536 slots, `endpoint_info.lxc_id`) admits `1..65535`; widening the pool
  is open decision 12.2.

### 5.2 Regeneration coalescing

Per endpoint: `skipped_regeneration_level: Level` (initially `Invalid`) and
`skipped_policy_revision: u64` (0).

```
set_regenerate_state(meta):
  if state == waiting-to-regenerate or state == regenerating-with-pending:
      skipped_level = max(skipped_level, meta.level)
      skipped_rev   = max(skipped_rev, meta.policy_revision_to_wait_for)
      log Other/OK "Skipped duplicate endpoint regeneration trigger due to <reason>"
      return false                     # a build is already queued
  if state == waiting-for-identity:
      skipped_level = max(skipped_level, meta.level); skipped_rev likewise
      log Other/OK "Deferred endpoint regeneration until identity resolution completes due to <reason>"
      return false                     # resolver will consume it
  return set_state(waiting-to-regenerate, "Triggering endpoint regeneration due to <reason>")

consume_deferred():                    # called when identity resolves without a build
  if skipped_level == Invalid and skipped_rev == 0: return None
  return meta{reason: DeferredRegeneration, level: max(skipped_level, no-rebuild), rev: skipped_rev}

regenerate(ctx) at step 3:
  ctx.level = max(ctx.level, skipped_level); skipped_level = Invalid
  ctx.rev   = max(ctx.rev, skipped_rev);     skipped_rev = 0
```

### 5.3 Directory swap and first-regeneration wait

Swap: see 3.6. `WaitForFirstRegeneration`: bound 330 s; every 1 s check the
endpoint is alive (deleted → error "endpoint was deleted while waiting for
initial endpoint generation to complete"); return when
`WaitForPolicyRevision(1)` fires. `WaitForPolicyRevision(rev)` completes
immediately if `policy_revision ≥ rev` or state is `disconnected`; otherwise
registers a waiter woken at step 19 or on deletion.

### 5.4 Endpoint hash

SHA-256 over the canonical encoding (name-sorted `name=value\n`) of every
lxc-object `.rodata.config` value for this endpoint (spec 01 §3.7 table,
including the option-derived ones) plus the map rename table. Stored in
memory as `bpf_headerfile_hash`; differs → level promoted to `rewrite+load`.
Because it hashes values, not header text, two agents produce equal hashes
for equal configuration; nothing on disk depends on it (the reference's
`template.txt` stores the *object identity* hash, spec 01, not this one).

### 5.5 Policy-map diff on first build

`policy_map_dump` (map state read from the pinned `cilium_policy_v3_<id>`
at first open) is the "realized" baseline for the first sync after restore:
entries in `desired` but not in the dump are inserted, entries in the dump
but not desired are deleted, differing values updated; the datapath keeps
the previous agent's policy in force until the very entry changes. If the
dump is empty (fresh endpoint) the sync happens immediately in step 9 so the
program attached in step 13 finds its map populated.

### 5.6 API limiter auto-adjust

Per limiter: ring of the last `mean-over` processing durations and wait
durations. After each completed request (once `skip-initial` have passed):

```
factor = clamp(estimated_processing / mean_processing, 1/max_adj, max_adj)
factor = 1 + (factor - 1) * delayed_adjustment_factor
rate   = clamp(base_rate * factor, base_rate / max_adj, base_rate * max_adj)     # if rate-limit set
par    = clamp(round(base_parallel * factor), min_parallel, max_parallel or ∞)   # if parallel set
```

Wait: acquire a parallel slot (semaphore sized `par`), then a token
(`rate`, `burst`), each bounded by `max-wait` (minus `min-wait` already
slept); on timeout release and return 429 with `Retry-After` = ceil(seconds
until the next token). `Done()` records the processing duration; `Error(err,
code)` records an error outcome for metrics.

### 5.7 Health probe interval

`base_ns = (10 + ratio·100)·1e9`; `interval = base` if `ip_count == 0`,
else `base · ln(1 + ip_count)` (truncated to ns). Per-probe spacing: a token
bucket refilled at `ip_count / interval` tokens per second, burst 1.

### 5.8 Status verdict

As the table in 3.14, evaluated on every request against the latest probe
results under a read lock; `brief` selects the reduced projection before the
verdict is attached.

### 5.9 Operation-id derivation

```
token = Method (Get|Put|Post|Patch|Delete) + concat(for hunk in path.split('/'):
          for word in hunk.trim('{}').split('-'): pascalize(word))
pascalize(w) = special.get(w) or (w[0].upper() + w[1:].lower())
special = { "bgp":"BGP", "id":"ID", "ip":"IP", "ipam":"IPAM", "lrp":"LRP" }
```

Yields the 44 tokens in §4.4 (e.g. `/policy/subject-selectors` →
`GetPolicySubjectSelectors`, `/node/ids` → `GetNodeIds`,
`/cgroup-dump-metadata` → `GetCgroupDumpMetadata`). The health API tokens
(`GetHealthz`, `GetStatus`, `PutStatusProbe`) follow the same rule but are
not subject to the allow list.

### 5.10 GC mark and sweep

See 3.9.3. Complexity O(endpoints) netlink `LinkByName` per round; with 0
interval the job is not started.

## 6. Configuration

Keys owned or primarily consumed by this spec (types per spec 00 §3.3.3).

| Key | Type | Default | Effect | Class |
|---|---|---|---|---|
| `state-dir` | string | `/var/run/cilium` | run dir; state dir is `<state-dir>/state` | immutable |
| `socket-path` | string | `/var/run/cilium/cilium.sock` | API socket | immutable |
| `lib-dir` | string | `/var/lib/cilium` | accepted; nothing is read from it (no BPF sources, ADR-0002) | ignored (warn if non-default) |
| `restore` | bool | true | 3.7 | startup |
| `bypass-ip-availability-upon-restore` | bool | false | 3.7 step 3 | startup |
| `endpoint-queue-size` | int | 25 | per-endpoint event queue depth | startup |
| `endpoint-gc-interval` | duration | 5m (hidden) | 3.9.3; 0 disables | startup |
| `endpoint-regen-interval` | duration | 2m | 3.9.2; 0 disables | startup |
| `endpoint-policy-update-timeout` | duration | 10s | bound for `UpdatePolicyMaps` across all endpoints after a policy change (spec 06) | startup |
| `endpoint-bpf-prog-watchdog-interval` | duration | 30s | 8.3 watchdog; 0 disables | startup |
| `bpf-policy-map-max` | int | 16384 | per-endpoint policy map size (spec 01) | immutable |
| `bpf-policy-map-pressure-metrics-threshold` | float | 0.1 | 3.9.5; negative → default with warning | startup |
| `bpf-policy-map-full-reconciliation-interval` | duration | 15m | spec 06 | startup |
| `enable-endpoint-lockdown-on-policy-overflow` | bool | false | 3.9.5 | startup |
| `enable-endpoint-routes` | bool | false | forces datapath configuration (3.1), health endpoint routes | immutable |
| `disable-endpoint-crd` | bool | false | 3.9.4 off | startup |
| `enable-cilium-endpoint-slice` | bool | false | CES consumption (3.9.4) | startup |
| `enable-stale-cilium-endpoint-cleanup` | bool | true | 3.9.4 | startup |
| `identity-change-grace-period` | duration | 5s | 3.4 step 4 | startup |
| `identity-restore-grace-period` | duration | 30s | spec 03 §3.5 (consumed after `endpoint-restore.regenerated`) | startup |
| `cilium-identity-max-jitter` | duration | 30s | resolver controller jitter cap | startup |
| `labels`, `label-prefix-file` | []string / string | — | identity filter (spec 03 §4.2) applied to API labels | immutable |
| `datapath-mode` | string | `veth` | link type; restore compatibility check (3.7) | immutable |
| `enable-cilium-api-server-access` | []string | `*` | 3.11.2 | startup |
| `api-rate-limit` | string | `` | 3.11.3 overrides | startup |
| `agent-health-port` | int | 9879 | 3.12 | startup |
| `agent-health-require-k8s-connectivity` | bool | true | 3.12 | startup |
| `kube-proxy-replacement-healthz-bind-address` | string | `` | 3.12; empty disables | startup |
| `cluster-health-port` | int | 4240 | responder and probes | startup |
| `enable-health-checking` | bool | true | 3.13 | startup |
| `enable-endpoint-health-checking` | bool | true | 3.10.3 (needs the former) | startup |
| `health-check-icmp-failure-threshold` | int | 3 | ICMP requests per probe | startup |
| `connectivity-probe-frequency-ratio` | float [0,1] | 0.5 | 5.7 | startup |
| `status-collector-interval` | duration | 5s | 3.14 | startup |
| `status-collector-warning-threshold` | duration | 15s | stale | startup |
| `status-collector-failure-threshold` | duration | 1m | failed | startup |
| `status-collector-probe-check-timeout` | duration | 5m | first-run bound | startup |
| `status-collector-stackdump-path` | string | `/run/cilium/state/agent.stack.gz` | dump on hung probe | startup |
| `max-controller-interval` | uint (s) | 0 | caps every controller `RunInterval` | startup |
| `k8s-sync-timeout` | duration | 3m | restore waits for caches (spec 00 fence) | startup |
| `enable-fib-table-id-annotation` | bool | false | `RTInfo` from pod annotation | startup |
| `tofqdns-min-ttl`, `tofqdns-endpoint-max-ip-per-hostname`, `tofqdns-max-deferred-connection-deletes`, `dns-max-ips-per-restored-rule` | int | 0 / 1000 / 10000 / 1000 | sizes for `DNSHistory`/`DNSZombies`/`DNSRulesV2` reconstruction on restore (spec 11 semantics) | startup |
| `dns-policy-unload-on-shutdown` | bool | false | shutdown removes wildcard L7 DNS rules before stopping (3.8 shutdown note) | startup |
| `hive-start-timeout`, `hive-stop-timeout` | duration | 5m / 1m | start/stop deadlines (spec 00) | startup |
| `debug`, `monitor-aggregation`, `policy-audit-mode`, `enable-tracing`, `trace-sock`, `bpf-events-*-enabled` | — | — | seed the runtime options (spec 00 §3.3.8) | runtime |

Accepted and ignored with a one-line info log: `lib-dir` (no BPF sources),
`hive-log-threshold`, `endpoint-status` (removed upstream; `cilium-config`
maps may still carry it), `enable-endpoint-health-checking` when
`enable-health-checking` is false (effectively off).

Shutdown (for completeness): cancel the token; if
`dns-policy-unload-on-shutdown`, remove wildcard DNS rules; stop modules in
reverse order under `hive-stop-timeout`; **do not** detach programs, unpin
maps, or remove endpoint directories; remove the API socket and the pidfile;
the health endpoint netns/links are left in place (the next start recreates
them, 3.10.3 step 1).

## 7. Failure modes

| Failure | Behavior |
|---|---|
| Agent restart mid-regeneration | `<id>_next` (or `_next_fail`) exists next to `<id>`: removed at restore; `<id>/ep_config.json` describes the last good build. Programs attached by the crashed build keep running (spec 01 commit protocol); pins may reference either generation — the first regeneration after restore repairs via pin-replace. Policy map may hold a partial diff; first sync re-diffs from the dump. Proxy redirects created but not committed are unknown to the new agent and get garbage-collected by the proxy port allocator's restore (spec 11, `restored-proxy-ports-age-limit`). |
| Restart between `rename` and nothing (fresh endpoint whose `<id>` never existed) | `<id>_next` with no base directory is read as complete (3.6); if `ep_config.json` is present it restores, else it is removed as unparseable. |
| Pod netns gone while the agent was down | `ValidateConnectorPlumbing` fails (host veth deleted with the netns) → `toClean`: directories removed, `cilium_lxc` entry removed, no IP release (IPAM never re-claimed it), CEP deleted. If only the peer vanished (host veth orphaned) step 1 of 3.7 removed the veth first, leading to the same outcome. |
| Pod netns gone while running | GC (3.9.3) removes the endpoint within two `endpoint-gc-interval`s; the CNI DEL normally arrives first. |
| Identity allocation blocked (API server/kvstore down) | The resolver controller retries with backoff; the endpoint stays `waiting-for-identity` holding `reserved:init`; traffic to it is subject to the `init` identity's policy (spec 06); `PUT` with `sync-build-endpoint` fails after 330 s (kubelet retries the sandbox). Restore: `restoring-ep-identity` retries indefinitely; the endpoint keeps forwarding with its **old** programs and maps meanwhile (spec 03 §3.5 restored identities keep the numeric ids valid). |
| Identity allocation returns a different numeric id on restore | `identity-change-grace-period` sleep, then swap; peers update via ipcache; cross-node drops possible during the grace window (accepted, matches reference). |
| Policy map full (`E2BIG`/`ENOSPC`) | sync fails `PolicyBPFError`, endpoint `not-ready`, recovery controller retries every 1 s (spec 06 may shrink entries); with lockdown enabled the map is replaced by deny-all. Pressure metric at 1.0. |
| `cilium_lxc` full | `BPFError`, retry; the map is fixed at 65536 (spec 01) so this indicates a leak — log at error with the dump count. |
| Build permit starvation | Many endpoints regenerate at once (policy change): builds proceed `num_cpus` at a time; `PUT` may time out (429 from the limiter is preferred to a 500 — the limiter caps parallel creates at 4). |
| API socket permission error | Cannot `chown` to `cilium` (group missing): continue with root:root 0660 and log; `cilium-dbg` run as root works. Cannot `chmod`: fatal. Cannot bind (path in use by a live agent): fatal. |
| Deletion-queue lock held by a CNI writer | The agent waits (blocking `flock`) — bounded by the start deadline; a wedged CNI process is an operator problem and is logged every 10 s while waiting. |
| Stale `health-endpoint.pid` | PID dead → remove; PID alive and not ours → `SIGTERM`, wait 1 s, `SIGKILL` (a reference `cilium-health-responder` from before an in-place swap). |
| Status probe hangs | stale → `cilium.state=Warning "Stale status data"` (kubelet liveness fails after 15 s), failed after 1 m; the hung task is abandoned and a new one started at the next interval. |
| `GET /healthz` before probes ran | `Warning` "Not all probes executed at least once" → 500 on 9879 → pod not Ready; CNI conf not written until `agent-ready`. |
| CEP patch `test` fails | UID cleared, ownership re-evaluated next run; never overwrites a CEP owned by another node. |
| CEP create conflicts (409 AlreadyExists) | re-fetch and take over if `networking.node` matches, else delete with UID precondition and create. |
| Datapath-mode mismatch on restore | fatal at start with the list of offending endpoints; the operator drains or reverts `datapath-mode` (spec 00 §3.3.9 immutable-key check catches the config change first). |
| Immutable key changed with endpoints present | refuse to start (spec 00 §3.3.9, open decision there). |

## 8. Observability

### 8.1 Metrics (names kept; labels as listed)

| Metric | Labels | Meaning |
|---|---|---|
| `cilium_endpoint_state` gauge | `endpoint_state` | endpoints per state (3.2) |
| `cilium_endpoint_regenerations_total` counter | `reason`, `outcome` (`success`\|`fail`), `error` (failure reason, `none`) | completed regenerations |
| `cilium_endpoint_regeneration_time_stats_seconds` histogram (buckets 10µs×10^k, 8) | `scope`, `status` (`success`\|`failure`) | scopes `total`, `buildPermitAcquisition`, `waitingForLock`, `waitingForCTClean`, `policyCalculation`, `waitForPolicyCompute`, `endpointPolicyCalculation`, `proxyConfiguration`, `proxyPolicyCalculation`, `proxyWaitForAck`, `mapSync`, `prepareBuild`, plus the loader's `bpfCompilation`? — no compilation exists; the loader contributes `bpfLoadProg`, `bpfWriteELF` is absent (**DEVIATION**: scopes tied to clang do not exist; `bpfLoadProg` is the load+attach span, spec 01 §8) |
| `cilium_endpoint_detached_selector_policy_time_stats_seconds` histogram | `scope=regeneration` | time a detached selector policy lingered |
| `cilium_endpoint_component_status` gauge | `type` (`BPF`\|`Policy`\|`Other`), `status` (`OK`\|`Warning`\|`Failure`) | endpoints per component status |
| `cilium_policy_endpoint_enforcement_status` gauge | `enforcement` (`none` `ingress` `egress` `both` `audit-ingress` `audit-egress` `audit-both`) | endpoints per policy mode |
| `cilium_endpoint_propagation_delay_seconds` histogram (.05…600) | — | CEP write → informer echo |
| `cilium_endpoint_restoration_endpoints` gauge | `phase` (`read_from_disk` `restoration` `prepare_regeneration` `initial_policy_computation` `regeneration`), `outcome` (`total` `successful` `skipped` `failed`) | restore counts |
| `cilium_endpoint_restoration_duration_seconds` gauge | `phase` | restore phase durations |
| `cilium_bpf_map_pressure` gauge | `map_name=cilium_policy_v3_*` | max policy-map fill ratio |
| `cilium_node_health_connectivity_status` gauge | `type` (`node`\|`endpoint`), `status` (`reachable`\|`unreachable`\|`unknown`) | peers per status |
| `cilium_node_health_connectivity_latency_seconds` histogram (1 ms…8 s) | `type`, `protocol` (`icmp`\|`http`), `address_type` (`primary`\|`secondary`) | last observed latency |
| `cilium_api_process_time_seconds` histogram (5 ms…120 s) | `path`, `method`, `return_code` | REST latency |
| `cilium_api_limiter_adjustment_factor` gauge, `_processed_requests_total{outcome}` counter, `_processing_duration_seconds{value=estimated|mean}` gauge, `_rate_limit{value=limit|burst}` gauge, `_requests_in_flight{value=in-flight|limit}` gauge, `_wait_duration_seconds{value=min|max|mean}` gauge, `_wait_history_duration_seconds` histogram | `api_call` (limiter name) | limiter state |
| `cilium_controllers_runs_total`, `_runs_duration_seconds`, `_failing`, `_group_runs_total` | `status`, `group_name` | controllers (spec 00) |
| `cilium_agent_api_process_time_seconds`? — not a reference name; do not add | | |

### 8.2 Logs

`subsys=endpoint` with fields `endpointID`, `containerID` (10-char short
form), `k8sPodName` (`<ns>/<pod>`), `ciliumEndpointName`, `identity`,
`identityLabels`, `ipv4`, `ipv6`, `policyRevision`, `reason`, `regenLevel`,
`state`, `from`/`to` (transitions); `subsys=endpoint-manager`,
`subsys=api`, `subsys=health`, `subsys=status`. Messages that tooling greps
(`Invalid state transition skipped`, `Successful endpoint creation`,
`Restored endpoint`, `Endpoints restored`, `Regenerating restored endpoints`,
`Finished regenerating restored endpoints`, `Stray endpoint found`,
`Waiting for endpoint to be generated`) MUST be kept verbatim.

### 8.3 Watchdog

`ep-bpf-prog-watchdog` (interval `endpoint-bpf-prog-watchdog-interval`
30 s) after `endpoint-restore.regenerated`: for every `ready` endpoint
without `property-without-bpf-endpoint`, check that a program is attached
to its host interface ingress (spec 01 §3.9); if any is missing, log at
error listing the endpoints and trigger
`RegenerateAllEndpoints(DeamonTrigger, rewrite+load)` once — it heals a
node where something detached the filters (e.g. an interface flap).

### 8.4 Health registry

Scopes: `agent.endpoint-manager` (OK after restore; Degraded while GC or
CEP sync fail), `agent.endpoint-manager.cilium-endpoint-<id> (<ns>/<pod>)`
per endpoint (Degraded on regeneration failure, closed on delete),
`agent.endpoint-restore` (messages `Waiting for K8s initialization`,
`Waiting for directory watcher to ingest policies from files`, `Waiting for
initial IPCache revision`, `Regenerating restored endpoints`),
`agent.api-server`, `agent.deletion-queue`, `agent.health` (`Wait for
endpoint restoration`, `Start initialization`), `agent.status-collector`.

### 8.5 Status/API exposure

`GET /endpoint/{id}` `status.log[0]`, `status.health`, `status.controllers`;
`GET /endpoint/{id}/log` full ring; `GET /healthz` `controllers[]` includes
the per-endpoint controllers (`resolve-identity-<id>`, `resolve-labels-<id>`,
`sync-to-k8s-ciliumendpoint (<id>)`, `endpoint-<id>-regeneration-recovery`,
`restoring-ep-identity (<id>)`) and the global ones (`cilium-health-ep`,
`ep-bpf-prog-watchdog`, `write-cni-file`, `validate-unchanged-daemon-config`).

## 9. Test plan

Unit (U), privileged/kernel (P), e2e (E).

State machine
- [ ] U every allowed transition of 3.2 succeeds and updates the gauge; every other pair is rejected, leaves state unchanged, appends a Warning entry; the two silent cases append nothing.
- [ ] U `not-ready` rendered when ready and status not OK; never persisted.
- [ ] U `EndpointHealth` mapping per state (4.5).

Creation / API
- [ ] U PUT with reserved label → 400; generated label → 400; filtered-away labels → 400.
- [ ] U PUT duplicate attachment id → 409; duplicate IP → 409; second PUT with same body after success → 409.
- [ ] U PUT before `api-ready` → 503; limiter timeout → 429 with `Retry-After`.
- [ ] U PUT `sync-build-endpoint` returns after `policy_revision ≥ 1`; deletion mid-wait → 500 "endpoint was deleted…".
- [ ] U PUT stops the IPAM expiration timers; failure → 500 and endpoint removed.
- [ ] U pod UID mismatch: informer polled, API fallback, `reserved:init` on total failure.
- [ ] U PATCH state other than ready/waiting-for-identity/empty is ignored; address change triggers `EndpointUpdate rewrite+load`.
- [ ] U DELETE returns 206 with error count; 404 unknown; 400 for host endpoint.
- [ ] U `Lookup` prefixes (3.9.1) incl. base-0 numeric, negative → 400, unknown prefix → 400.
- [ ] U `GET /endpoint?labels=` filtering; empty → 404.
- [ ] U every swagger response of §4.4 serializes with byte-identical field names against golden JSON captured from the reference client (`cilium-dbg -o json` fixtures).
- [ ] U operation-id derivation produces exactly the 44 tokens; allow list `*`, suffix wildcard, unknown token fatal, denied → 403.
- [ ] U rate limiter: parse `api-rate-limit` string; auto-adjust math (5.6) against the reference's `pkg/rate` test vectors (limits clamp, delayed factor, skip-initial).
- [ ] P socket created with group `cilium` mode 0660; missing group → root, non-fatal.

Regeneration
- [ ] U coalescing (5.2): trigger while queued bumps level, returns false; deferred consumed on identity resolution; `PolicyRevisionToWaitFor` honored.
- [ ] U build queue permits = max(2, cpus); permit released before proxy wait.
- [ ] U pipeline ordering with a fake loader/proxy/policy: policy programs inserted before attach; lxc upsert after attach for rewrite+load, early for no-rebuild; map sync after proxy ACK; swap last; `policy_revision` set only on success.
- [ ] U failure at each step leaves `_next_fail`, `realized` unchanged, redirects reverted, recovery controller registered; success removes `_next_fail`.
- [ ] U endpoint hash stable across processes; option change promotes level.
- [ ] P full regeneration of a veth endpoint on the CI kernel (spec 01 loader real, policy fake): programs attached, `cilium_lxc` entry correct (`endpoint_info` bytes), policy map populated.

State directory / restore
- [ ] U `ep_config.json` round-trip for every field of 4.2; reference fixtures with `dockerID`, `DNSRules` v1 only, `DNSRulesV2`, `SecLabel: null`, unknown keys, missing `Options` (defaults filled).
- [ ] U partition: `_next` with base → removed; `_next` without base → read; duplicate ids → exact-name wins; unparseable → removed and counted.
- [ ] U swap: existing dir → hard-link missing files then `RENAME_EXCHANGE`; missing dir → rename; `_next_fail` removed after.
- [ ] P `renameat2(RENAME_EXCHANGE)` on tmpfs and overlayfs (the state dir is a hostPath in Helm; document EINVAL on filesystems without exchange support).
- [ ] U restore validation: health endpoint dropped and dir removed; pod missing → CEP delete + toClean; pod on another node → toClean; link missing → toClean; IP unavailable → toClean unless bypass flag; datapath-mode mismatch → fatal.
- [ ] U stale `cilium_lxc` entries deleted after restore; host entries kept.
- [ ] U restored endpoint re-allocates identity, applies grace period only when the number changed, regenerates `EndpointRestore rewrite+load`; three fences released in order.
- [ ] P orphan veth cleanup deletes host-host pairs named `lxc*` only.
- [ ] E agent restart with running pods: same id/IP/identity, no drops during restart (reference `tests-e2e-upgrade` behavior), `_next` dirs discarded.

Manager
- [ ] U id pool: lowest free, release/reuse, `reuse(4096+)` accepted, exhaustion error.
- [ ] U GC mark-and-sweep: link missing two rounds → removed with `NoIPRelease = external-ipam`; other netlink errors do not mark; no-interface endpoints never marked.
- [ ] U CEP sync: create with owner refs; JSON patch body exact (`test uid`, `replace /status`); patch skipped when unchanged; UID takeover rules; delete with precondition; health endpoint excluded; `disable-endpoint-crd` off.
- [ ] U CEP status compression of states.
- [ ] U policy-map pressure exports the maximum; threshold log; lockdown path.
- [ ] U host endpoint labels follow node labels; ingress endpoint exists iff envoy config enabled.

Health
- [ ] U node map from `ClusterNodeStatus` incremental updates; IPv6 preference; secondary addresses.
- [ ] U interval formula (5.7) for ip_count 0, 1, 10, 1000 against reference values.
- [ ] U `HealthStatusResponse` shape and `ConnectivityStatus` on success/failure/rate-limit error; metrics label values.
- [ ] P responder thread bound inside a netns answers `/hello`; agent restart kills a foreign pidfile PID.
- [ ] E `cilium-health status` and `cilium-dbg status --verbose` from upstream binaries render against flowsdn.

Status
- [ ] U verdict table (3.14) for each condition in order; `brief` projection; `stale` population after 15 s; failure after 1 m.
- [ ] U 9879 returns 500 for non-Ok; `require-k8s-connectivity` header parsing; KPR healthz JSON and 503.
- [ ] E kubelet readiness gating: pod not Ready until probes ran and CNI conf written.

Compatibility
- [ ] E upstream `cilium-dbg status`, `endpoint list/get/log/health/config/labels`, `config`, `identity list`, `ip list`, `node list`, `debuginfo`, `policy get` succeed against flowsdn's socket; `cilium-dbg status` prints Modules Health via `/statedb/query` when decision 12.5(a) holds.
- [ ] E `cilium-cni` (upstream binary) ADD/DEL/CHECK against flowsdn (spec 09 owns the CNI, this checks routes 3, 6, 8, 20, 22).

## 10. Kernel and platform requirements

No BPF program of its own. Needs: `renameat2(RENAME_EXCHANGE)` (≥ 3.15;
filesystem support — tmpfs, ext4, xfs, btrfs yes; overlayfs since 4.x);
network namespaces (`setns`, `/proc/<pid>/ns/net`, `unshare(CLONE_NEWNET)`
for the health netns); `SO_NETNS_COOKIE` (≥ 5.7) only to validate the
CNI-provided cookie (optional); veth or netkit (≥ 6.7) for the health link
pair per `datapath-mode`; `flock` on the run dir filesystem; raw ICMP
sockets (`CAP_NET_RAW`) or `IPPROTO_ICMP` datagram sockets where
`net.ipv4.ping_group_range` permits (preferred: no capability needed);
`CAP_NET_ADMIN` for links/routes; unix sockets with `SO_PEERCRED` not
required. Arch-neutral; within the 6.6 LTS minimum / 6.12 stormcos line of
`docs/kernel-requirements.md`.

## 11. Rust design notes

Crates (all `#![forbid(unsafe_code)]` except the netns thread, which needs
`nix::sched::setns` — safe wrapper, no `unsafe` in our code):

- **`flowsdn-endpoint`** — `Endpoint` as an actor: `struct Endpoint {
  inner: Arc<RwLock<EndpointState>>, events: mpsc::Sender<EndpointEvent>,
  alive: CancellationToken, build_mutex: tokio::sync::Mutex<()> }` with one
  task per endpoint draining `EndpointEvent::{Regenerate(meta, oneshot<bool>),
  NoTrack(port), Bandwidth(..), Stop}` (queue depth = `endpoint-queue-size`).
  `State` enum with `Display` giving the exact strings and
  `fn transition(&self, to) -> Result<(), Rejected{silent: bool}>` as a match
  table mirroring 3.2. `StatusLog` = `VecDeque<StatusEntry>` cap 256 with
  `current()` by component priority. Regeneration = `async fn regenerate(&self,
  ctx: RegenContext) -> Result<u64, RegenError>` where `RegenError` carries
  the failure-reason enum for metrics and the *revert stack*
  (`Vec<Box<dyn FnOnce() + Send>>`) built as steps succeed. Coalescing state
  (`skipped_level`, `skipped_rev`) lives inside the lock. Build permits:
  `Arc<tokio::sync::Semaphore>` shared by the manager, `OwnedSemaphorePermit`
  dropped early before the proxy wait. The regeneration fence is spec 00's
  `Fence` handle. Directory ops in `dir.rs`: `tempfile::NamedTempFile::persist`
  for files, `nix::fcntl::renameat2(.., RenameFlags::RENAME_EXCHANGE)` for the
  swap, `std::fs::hard_link` for the copy step. Persistence in `restore.rs`:
  `#[derive(Serialize, Deserialize)] struct SerializableEndpoint` with
  `#[serde(rename = "dockerID", skip_serializing_if = "String::is_empty")]`,
  `#[serde(rename = "OpLabels")]`, `#[serde(rename = "SecLabel")]`,
  `#[serde(rename = "DNSRules", skip_serializing, default)] dns_rules_v1:
  IgnoredAny`, `#[serde(rename = "DNSRulesV2", default,
  skip_serializing_if = "..")]`; `netip.Addr`-compatible codec for `IPv4`/`IPv6`
  (`""` ↔ `None`). Identity resolver, label update, proxy redirect glue
  (`trait EndpointProxy`), DNS rule trigger (a debounced `Trigger` type,
  `MinInterval` 1 s) also here. Depends on: `flowsdn-labels`,
  `flowsdn-identity`, `flowsdn-ipcache` (spec 03), `flowsdn-policy` (spec
  06, via traits `PolicyRepository`, `PolicyComputer`), `flowsdn-bpf-maps` +
  loader (spec 01, via `trait Orchestrator { async fn reload_endpoint(..);
  fn endpoint_hash(..); async fn unload(..) }`), `flowsdn-ctmap` (spec 04
  GC), `flowsdn-controller` (named controllers with backoff, exposed in
  status), `flowsdn-health` (registry).
- **`flowsdn-endpoint-manager`** (may live as a module of the above) —
  `EndpointManager { table: flowsdn_table::Table<EndpointRow>, ids: IdPool
  (a `FixedBitSet` of 65536 bits + `next_free` cursor), build_permits,
  subscribers }`. Rows are `Arc<Endpoint>` handles keyed by id with secondary
  indexes `cni_attachment_id`, `ipv4`, `ipv6`, `cep_name`, `pod_name`,
  `namespace`, `container_id`; the table's `watch()` feeds the CEP
  synchronizer and Hubble's endpoint cache (spec 09-hubble) for free
  (ADR-0004). Periodic GC and regeneration are `tokio::time::interval`
  tasks. CEP sync via `kube` (`Api<CiliumEndpoint>` with a hand-written
  `#[derive(CustomResource)]`-free type: `kube::api::DynamicObject` avoids
  drifting from the CRD; `Patch::Json(json_patch::Patch)`); typed status
  struct with `serde` renames per 4.8.
- **`flowsdn-api`** — `axum` `Router` served on `tokio::net::UnixListener`
  (`axum::serve` with a `UnixStream` connect-info type); `nix::unistd::chown`
  + `std::fs::set_permissions` after bind. Models are **hand-written**
  `serde` structs from `openapi.yaml` (§4.5; ~120 structs; generated code
  would be larger than the hand version and the swagger uses go-swagger
  extensions no Rust generator understands) in a `models` module shared with
  the health server and `flowsdn-dbg`; a unit test compares each struct's
  field-name set against a JSON dump of the swagger definitions checked in
  under `docs/spec/fixtures/` (copied with attribution per
  `docs/licensing.md`). Middleware layers: access control (`tower::Layer`
  mapping `(method, matched path template) → token` via 5.9, denying with
  403), rate limiting (`ApiLimiterSet` hand-written, ~300 lines: rate via
  `governor` or a token bucket, parallelism via `Semaphore`, auto-adjust
  state in a `Mutex`), request metrics (`cilium_api_process_time_seconds`
  with the axum `MatchedPath`), readiness gating (`Fence::wait` with the
  request deadline). Routes for other specs are registered by their crates
  through a `trait ApiExtension { fn routes(&self) -> Router }` so
  `flowsdn-api` does not depend on them. The `/statedb/query` route reads
  the health table and streams `serde_json` objects through
  `axum::body::Body::from_stream`.
- **`flowsdn-healthcheck`** (the checker; the registry of spec 00 remains
  `flowsdn-health`, as settled by ADR-0010) — prober task (`surge-ping` for ICMP over `IPPROTO_ICMP`
  datagram sockets with raw fallback; `hyper` client with a 10 s timeout for
  `/hello`), responder (`hyper` server bound on each node address and on a
  socket created by a `std::thread` that `setns` into the health netns),
  health-endpoint manager (netns via `nix::sched::unshare` in a scoped
  thread, link pair via `rtnetlink`, routes, the in-process create), health
  REST (`axum` on `health.sock`, three routes, `/proc/loadavg` for
  `system-load`), metrics.
- **`flowsdn-status`** — `Collector { probes: Vec<Probe>, results:
  RwLock<StatusResponse>, stale: RwLock<HashMap<..>> }`, one task per probe
  with `tokio::time::timeout` at the warning and failure thresholds
  (abandon-and-respawn on failure); `get_status(brief, require_k8s)`
  computes the verdict. Probes are closures registered by other crates
  (`ProbeSource` trait) so this crate depends on none of them.

Concurrency notes: the reference's lock discipline (endpoint lock must not
be held while calling into the ipcache or the policy repository; the build
mutex is separate from the state lock) maps to: state `RwLock` held only for
field reads/writes, never across `.await`; long operations (policy compute,
proxy wait, loader) run with a snapshot. Deadlock detection of `pkg/lock`'s
`lockdebug` is replaced by `tokio-console` and `parking_lot::deadlock`
detection in debug builds.

Sizing: endpoint + regeneration + restore ~5k lines, manager + CEP ~1.5k,
API server + models + limiter ~5k, healthcheck ~2k, status ~0.8k, tests ~5k.

## 12. Decision register (resolved and open)

1. **Reference endpoint restore — resolved #114.** Read reference-written
   `ep_config.json` using §4.2, including `dockerID`, `OpLabels`, legacy `DNSRules`
   (accepted and ignored), and `DNSRulesV2`; tolerate unrelated `ep_config.h`. Restore
   does not import the reference runtime configuration. Responder cleanup follows the
   process-ownership safeguards in decision #117.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

2. **Widen the id pool to 1..65535.** (a) keep 4095 (reference; some
   dashboards assume it, `%05d` unaffected); (b) 65535 (u16 max; every map
   and name format admits it; `cilium_call_policy` already has 65536 slots).
   Recommendation: (b) behind a flowsdn-only key `endpoint-id-max` defaulting
   to 4095 until an e2e run with > 4095 endpoints per node is meaningful;
   `reuse()` accepts either regardless.
3. **Endpoint conflict status — resolved #116.** Return 409 with the API Error body for
   live attachment-ID or IP ownership conflicts on endpoint PUT. Preserve 400 for
   malformed or otherwise invalid requests. This is the existing documented deviation
   from the reference implementation.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

4. **Health responder process model — resolved #117.** Create the health namespace
   socket on a dedicated OS thread using `setns`, then hand the socket to the runtime.
   Do not change a shared runtime worker namespace. Keep the agent PID in the
   compatibility pidfile. A stale PID alone never authorizes signalling: verify the
   process is the former health responder in the expected namespace, protect against PID
   reuse, and otherwise report/leave the unrelated process alone.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

5. **`/statedb/query` for the `health` table.** Conditional on spec 00
   decision 12.5; if (a) there, the route in 3.12 is normative here. If it is
   dropped, `cilium-dbg status` from upstream exits non-zero after printing
   the status; `flowsdn-dbg` becomes P0.
6. **Unimplemented API routes — resolved #118.** Register recognized but
   not-yet-implemented method/path pairs and return 501 with the standard Error body.
   Unknown paths remain 404; invalid methods are handled separately. A 501 explicitly
   reports an unfinished feature and does not remove it from scope.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

7. **Adaptive API limiting — resolved #119.** Implement the adaptive auto-adjust
   algorithm specified in §3.11 with its configuration and metrics; fixed limits are not
   a replacement for that contract.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

8. **Endpoint-hash scope.** (a) hash `.rodata.config` values + rename table
   (this spec); (b) additionally hash the object identity so a flowsdn
   upgrade forces `rewrite+load` on every endpoint. Recommendation: (b) is
   already implied by spec 01's object identity hash stored in
   `template.txt`; confirm in spec 01 that a changed embedded object
   triggers reload on restore and drop the duplication here.
9. **Status verdict severity of "not all probes executed".** Reference:
   `Warning`; spec 00 §3.4.2: `Failure`. Both yield 500 on 9879. This spec
   follows the reference; spec 00 should be amended.
10. **Resolved by ADR-0010 (#122):** the module health registry keeps
    `flowsdn-health`; this spec's checker is `flowsdn-healthcheck`.
