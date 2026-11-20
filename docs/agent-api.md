# Standalone agent API

`flowsdn-agent --config PATH` exposes HTTP/1.1 on the configured `socket-path`
Unix socket, with mode 0600. With `http-listen` (a loopback `IP:port`; others are
refused) it also serves a **read-only** TCP listener: `GET` routes and the
statedb query (`GET`/`POST`) answer as on the socket, every other method returns
403 `the TCP listener is read-only; use the Unix socket`. It is for the stormcos
console plugin (#297). Socket access depends on filesystem permissions; there is
no HTTP authentication layer, which is why TCP is loopback and read-only. Config is the standalone
agent JSON format, not the full configuration catalogue. `--help` and `--version`
exit successfully without loading config or starting the daemon.

This is the persisted endpoint and host-scope IPAM API. Built with the
`kubernetes` feature and configured with a `kubernetes` section, the agent also
watches Nodes, Pods and (with `service-lb`) Services and EndpointSlices, and
serves `/v1/ip`, `/v1/service` and `/v1/node/routes` from them. It has no
identity/policy controllers, operator service, Hubble gRPC observer on 4244, or
relay. A successful response does not establish a working multi-node pod
network. The config response's `ipam-mode: kubernetes` is a compatibility value:
the agent allocates from its configured local prefixes; with pools `auto` in
Kubernetes mode that prefix is derived from the Node at startup (see
[runtime.md](runtime.md)).

## Stability (#298)

This API is a supported boundary: `sc net` (stormcos), the stormconsole flowsdn
plugin (stormconsole#83) and the CNI depend on it. Within `/v1`:

- Routes, methods and the fields documented here keep their names, types and
  meaning. New routes and new response fields may appear; clients must ignore
  fields they do not know.
- A removal or an incompatible change gets a new path (`/v2/...`), with `/v1`
  kept for at least one release and the change in the changelog as **BREAKING**.
- Status codes keep their meaning: 2xx success, 400 bad request, 403 a mutation on
  the read-only TCP listener, 404 unknown object or route, 405 method, 409
  conflict, 413 too large, 501 a transfer coding the server does not take
  (chunked), 502 an internal allocation failure.
- Error bodies are a JSON string with the message.

`api::ROUTES` in the agent lists the routes below, and a test fails when this
page's table differs from it, so a route change changes this page in the same
commit.

## Transport and supervision

Send a bounded request to the configured Unix socket, for example:

```sh
curl --unix-socket /var/run/flowsdn/flowsdn.sock http://localhost/v1/healthz   # the edition manifests' socket-path
curl http://127.0.0.1:9878/v1/endpoint     # with "http-listen": "127.0.0.1:9878"
```

`localhost` is an HTTP request authority in this example, not a TCP destination.
`GET /v1/healthz` returns HTTP 200 and the initial endpoint API status after
state restoration and queued deletion replay complete. It is an API liveness
and startup signal, not policy/controller readiness. Bare `/healthz` and
`/readyz` do not exist (404). A supervisor that only probes TCP HTTP needs a
Unix-socket-capable probe or an explicit adapter; do not configure a nonexistent
path and restart an otherwise running daemon.

The body is `{"agent":{"state":"Ok","msg":…}}`, plus a `kubernetes` member in
Kubernetes mode: `{state, msg, node-name, auto-direct-node-routes, service-lb,
identity-allocation, network-policy, flowsdn-policy, policy}`, `state` `Warning` until the
initial Node and Pod lists (and, with `service-lb`, Service and EndpointSlice
lists; with `identity-allocation` or `network-policy`, Namespaces and
FlowsdnIdentity or NetworkPolicy lists; with `flowsdn-policy`, Namespaces and both
flowsdn policy lists) are complete or while a part has an
error (`msg` then lists `<part>: <error>`, for example `annotations`,
`services`, `node-port`, `policy`), otherwise `Ok` with node, pod and frontend
counts. `policy` is what the policy thread last programmed (#292):
`{endpoints: [{id, pod, ingress-enforced, egress-enforced, entries}], ipcache,
host-firewall, flowsdn-policies, problems}`, `null` before its first pass. `host-firewall` (#379)
is `null` with `kubernetes.host-firewall: off`, else `{mode, policies,
ingress-enforced, audit, interfaces, learning, enforcing-on, pods, addresses,
entries}`: the selecting FlowsdnClusterwideNetworkPolicy names, the
interfaces it is on (every one holding a global address of the node, and the
uplink ports), those still in their first 60 s (flows learned, nothing
enforced), those enforcing (or auditing), the local Pods' path to the host
(`tracking` with no selecting policy, `learning`, `enforcing`; #384) and the
node's global addresses, all with the host identity. Its unsupported rules are among `problems`; an uplink
that cannot be found or attached is the `host-firewall` /
`host-firewall-attach` part error. (Before #298 the member was named after the reference project;
it is `agent` now.)

`GET /v1/health/modules` (and the `health` table of `/v1/statedb/query`)
reports module rows built from the agent's live state on each request (#418):
`agent.api` (OK, with the endpoint count) and `agent.restore` (OK: restore and
deletion replay completed) always; with Kubernetes, `agent.kubernetes` (OK with
the `/v1/healthz` `kubernetes` message, or Degraded with that message as
`Error` while lists are not synced or a part has failed) and, while the policy
maps could not be shared, `agent.policy` (Degraded: NetworkPolicy is not
enforced). A row is rewritten (`Count`, `Updated`) only when its level,
message or error changes; a row whose cause is gone is removed. The agent also
refreshes the rows once a second and logs each new row, level change and
removal (`health agent.kubernetes OK: …`). Nothing is reported that was not
observed. Module rows and endpoint health are separate
from `/v1/healthz`.

The server processes one request per connection, then closes it. Request headers
are limited to 16 KiB, request bodies to 4 MiB, with a 2-second request budget.
Chunked transfer encoding is unsupported. Endpoint listing is all-or-error:
if its encoded JSON exceeds 4 MiB, return HTTP 413 rather than a truncated list.
There is no pagination, watch stream, concurrent query snapshot protocol or
Kubernetes API-server proxy. Unknown routes return HTTP 404; unsupported methods
on recognized endpoint detail/IPAM address routes return HTTP 405.

## Supported methods

| Method and path | Behavior |
|---|---|
| `GET /v1/config` | Initial datapath/IPAM mode, MTUs and configured host addressing. |
| `GET /v1/healthz` | Initial API availability, as described above. |
| `GET /v1/health/modules` | Module health rows; `/health/modules` is also accepted. |
| `GET` or `POST /v1/statedb/query` | Read-only health-table query; `/statedb/query` is also accepted. Other tables are unavailable. |
| `GET /v1/endpoint` | Endpoint response array sorted by ascending numeric ID. Empty state returns `[]`. |
| `GET /v1/endpoint/{id}` | Read a numeric endpoint ID or URL-encoded CNI attachment identifier. Unknown IDs return 404. |
| `GET /v1/endpoint/{id}/healthz` | Same read identifiers; initial live host-link/teardown health, not policy convergence. |
| `PUT /v1/endpoint/{attachment}` | Initial CNI publication using pending IP allocations and validated attachment metadata. |
| `DELETE /v1/endpoint/{attachment}` | Delete by CNI attachment identifier; numeric read aliases do not change this mutation contract. |
| `DELETE /v1/endpoint` | Delete attachments matching JSON `container-id`; may return 206 for partial failure. |
| `GET /v1/ipam` | Read the configured default-pool family summaries below. |
| `POST /v1/ipam` | Allocate pending addresses; requires owner and supports family/default-pool selection. |
| `DELETE /v1/ipam/{address}?pool=default` | Release an unused allocation; endpoint-owned addresses return 409. |
| `GET /v1/ip` | Kubernetes mode: the IP cache view (reference `IPListEntry`), rows `{cidr, …}` sorted by address. Each node InternalIP as `/32`/`/128` with identity 1 (this node) or 6 (remote node) and `metadata{source,name}`; each IP of a non-host-network Pod with `hostIP` (its node's InternalIP of the family), `metadata{source,namespace,name}` (plus flowsdn's `uid`, `containers` and, with a controller owner, `workloads`, #328) and the flowsdn `labels` extension (`k8s:<key>=<value>` plus `k8s:io.kubernetes.pod.namespace`). A Pod entry carries `identity` once its Pod has one (see `GET /v1/identity`). No `cidr` query filter. 404 when Kubernetes mode is off. |
| `GET /v1/identity` | Kubernetes mode (reference `Identity` list): `[{id, labels}]` sorted by id, every FlowsdnIdentity object (labels as `<source>:<key>=<value>`) plus the well-known identities Pods resolve to. Empty with `identity-allocation: false`, before the Namespace and FlowsdnIdentity lists are complete, or when the FlowsdnIdentity CRD is not installed. 404 when Kubernetes mode is off. |
| `GET /v1/service` | Kubernetes mode with `service-lb` (reference `Service` model): one row per frontend, `spec{id, frontend-address{ip,port,protocol,scope}, backend-addresses[{ip,port,protocol,state}], flags{type, name, namespace, port-name, service-type}}`; `type` is `ClusterIP`, `ExternalIPs`, `LoadBalancer` or `NodePort`, `session-affinity-timeout` (seconds) is present for `sessionAffinity: ClientIP`, and `lb-algorithm: maglev` on a node-local frontend that picks backends by Maglev (#292). `nat-policy: Nat46|Nat64` marks a node-local frontend translated to the other family's backends. `forwarding-mode: dsr` on a node-local frontend with direct server return (#292). `frontend-address.scope` is `external` for the cluster view and `node-local` for the copy that serves traffic from outside the cluster on this node's uplink (every backend, other nodes' through SNAT; this node's only with `externalTrafficPolicy: Local`). `id` is the service ID (`rev_nat_index`) the socket-LB maps hold, 0 until programmed; `status.realized` repeats `spec` once it is. Empty until both the Service and EndpointSlice lists are complete. 404 when Kubernetes mode is off. |
| `GET /v1/node/routes` | Kubernetes mode (flowsdn): the direct node routes, `{destination, gateway, gateways, node, state}` with state `installed`, `installed: N paths` (ECMP over several uplinks, #408), `skipped: …` or `error: …`. `gateways` lists every InternalIP of the node in that family. Empty before the first Node list or with `auto-direct-node-routes: false`. 404 when Kubernetes mode is off. |
| `GET /v1/uplinks` | Kubernetes mode (flowsdn, #408): the node's uplink ports as the monitor last read them (every 500 ms). Fields: `mode`, `monitoring`, `balancing` (two or more uplinks, mode not `single`), `carrying` (the ports with carrier that carry the balanced routes). `uplinks[]` has `{name, ifindex, mac, carrier, primary, weight, addresses, ports[]}`; each port is `{name, carrier, speed-mbps, fec {configured, active}, rx-bytes, tx-bytes}`, and a bridge lists its physical members. `failover[]` is `{address, from, on}` for a down port's address held as a host address by a live one. `history[]` holds the last 64 joins and leaves, `{at, port, event, message}`. 404 when Kubernetes mode is off. |
| `GET /v1/lb-ipam` | Kubernetes mode with `lb-ipam` (flowsdn, #475): `{enabled, leader, synced, pools[], services[]}`. `enabled` is the setting; `leader` is whether this agent holds the Lease `kube-system/flowsdn-lb-ipam` and so writes Service and pool status; every agent plans the same. `pools[]` is `{name, used, available, conflict}` (counts as decimal strings; `conflict` names the older pool it overlaps, or null); `services[]` is `{namespace, name, ips, problem}` for every Service LB-IPAM decides (`problem` says why it has fewer addresses than it asks for). Empty until the Service and FlowsdnLoadBalancerIPPool lists are complete. 404 when Kubernetes mode is off. |
| `GET /v1/l2-announcements` | Kubernetes mode with `l2-announcements` (flowsdn, #475): `{enabled, policies[{name, invalid}], announcing[{ip, service, interfaces}], errors[]}` (`enabled` is the setting): the FlowsdnL2AnnouncementPolicies, and the addresses this node answers ARP/NDP for and on which interfaces. Empty until the policy, Service, EndpointSlice and Node lists are complete. 404 when Kubernetes mode is off. |
| `GET /v1/policy/verdicts` | flowsdn (#379): the policy decisions the endpoint programs counted, one row per `{endpoint, direction, verdict, protocol, port}` with `packets` and `bytes` summed over CPUs. `endpoint` is the Pod endpoint ID or `host` (the host firewall); `verdict` is `allowed` (a rule allowed a new flow), `denied` (dropped) or `audit` (audit mode: would have been dropped, passed); `port` is the destination port (0 without one). Packets of a remembered flow are not counted. LRU, 16384 rows; counters reset when the agent's object is reloaded. Read-only, also on the TCP listener. |
| `GET /v1/cni/timing` | Each CNI ADD step's `{samples, p50-us, p99-us, max-us}` over its last 256 samples: the plugin's `config`, `lookup`, `allocate`, `link`, `configure`, `endpoint`, `finalize`, `total`, and the agent's `agent-check`, `agent-state`, `agent-install`, `agent-create` (#396). |
| `POST /v1/cni/timing` | The plugin's report after an ADD: `{"steps":{"<step>":<microseconds>}}`. Unknown steps are ignored. |
| `GET /metrics` | Prometheus text format 0.0.4 (#420), every name `flowsdn_*`, built from live state on each scrape; also the only route of `metrics-listen` (other paths 404). See [Metrics](#metrics). |

List, detail and pool summary reads perform no allocation or endpoint mutation.
As with existing API requests, expired pending IP leases are processed first.
Read identifiers consisting entirely of decimal digits must fit a nonzero u16;
invalid or unknown numeric IDs return 404. Other identifiers match the stored
CNI attachment string. PUT/DELETE continue to use attachment identifiers.

## Metrics

`GET /metrics` (on the socket, `http-listen`, or its own loopback
`metrics-listen`; the edition manifests use `127.0.0.1:9962`, the port the node
scrape config already knows for the network level, stormcos#64). Every series
is read when scraped; nothing is cached or estimated.

| Series | Type | Meaning |
|---|---|---|
| `flowsdn_build_info{version}` | gauge | 1; the agent's version. |
| `flowsdn_endpoint_state{endpoint_state}` | gauge | Endpoints held, `ready` or `disconnecting` (deletion started, not finished). |
| `flowsdn_controllers_failing` | gauge | Controller parts whose last reconcile failed (the `errors` of `/v1/healthz`, plus `policy-maps` when NetworkPolicy maps could not be shared). |
| `flowsdn_controller_failing{controller}` | gauge | 1 per failing part (`routes`, `pod-cidrs`, `services`, `identities`, `policy`, `host-firewall`, `host-firewall-attach`, `uplinks`, `node-port`, `socket-termination`, `policy-maps`). The error text is in `/v1/healthz`. |
| `flowsdn_policy_verdict_total{direction,action}` | counter | Packets judged by policy, `ingress`/`egress` × `allowed`/`denied`/`audit`, summed over endpoints and ports from `flowsdn_policy_verdicts` (new flows only). |
| `flowsdn_drop_count_total{reason,direction}`, `flowsdn_drop_bytes_total{…}` | counter | Dropped packets/bytes by reason. Only `policy_denied` is counted: the datapath keeps no counter for its other drops yet (#421). |
| `flowsdn_bpf_map_pressure{map_name}` | gauge | Entries / `max_entries` of `flowsdn_policy_ep`, `flowsdn_policy`, `flowsdn_ipcache`, `flowsdn_policy_ct`, `flowsdn_policy_verdicts` (keys are walked per scrape). |
| `flowsdn_kubernetes_synced` | gauge | Kubernetes mode: 1 once every list the enabled features need was received. |
| `flowsdn_nodes`, `flowsdn_pods` | gauge | Kubernetes mode: Nodes and Pods watched. |
| `flowsdn_unreachable_nodes` | gauge | Kubernetes mode: nodes with a direct pod-CIDR route not installed (`skipped` or `error`). |
| `flowsdn_identity{type="cluster"}`, `flowsdn_identity_waiting` | gauge | With identity allocation: identities known; local label sets still waiting for one. |
| `flowsdn_services{state}` | gauge | Kubernetes mode with the service LB: frontends `desired` and `programmed`. |
| `flowsdn_uplink_up{uplink}` | gauge | Kubernetes mode: 1 while an uplink has carrier (#408). |
| `flowsdn_metrics_source_failing{source}` | gauge | 1 for `policy-verdicts` or `bpf-map-pressure` when that map could not be read this scrape; its series are then absent, not zero. |

The operator has no metrics: there is no operator executable yet (#337).

## Endpoint inventory shape

Each list entry has the same shape as endpoint detail, including:

```json
{
  "id": 42,
  "status": {
    "state": "ready",
    "external-identifiers": {
      "k8s-pod-name": "example-pod",
      "k8s-namespace": "default",
      "k8s-uid": "pod-uid",
      "container-id": "sandbox-id",
      "pod-name": "default/example-pod",
      "cni-attachment-id": "sandbox-id:eth0"
    },
    "pod": {
      "ID": 42,
      "namespace": "default",
      "pod_name": "example-pod",
      "pod_uid": "pod-uid",
      "container_id": "sandbox-id",
      "node_name": "node-a",
      "labels": ["k8s:app=web", "k8s:io.kubernetes.pod.namespace=default"],
      "workloads": [{"name": "web", "kind": "Deployment"}],
      "containers": [{"name": "app", "container-id": "containerd://…", "init": false}]
    },
    "pod-networks": {"default": {"…": "the flowsdn.io/pod-networks value, below"}},
    "networking": {
      "interface-name": "lxc-example",
      "interface-index": 12,
      "container-interface-name": "eth0",
      "netns-cookie": "123456",
      "addressing": [{"ipv4": "10.0.0.2", "ipv4-pool-name": "default"}]
    }
  }
}
```

`external-identifiers` and the endpoint's own facts in `pod` (`ID`,
`namespace`, `pod_name`, `pod_uid`, `container_id`) are retained
CNI-supplied information. `container_id` is the sandbox (`CNI_CONTAINERID`): the
CNI sees one network namespace per Pod, not its containers. In Kubernetes mode
`pod` is joined with the Pod view when the Pod is on this node with the same
UID: `node_name`, `labels`, `workloads` (the controller owner; a ReplicaSet
named `<deployment>-<pod-template-hash>` reports its Deployment) and
`containers` (status container names and runtime IDs, init containers
flagged). `pod` is the Hubble flow `Endpoint` JSON shape plus flowsdn's
`pod_uid`, `container_id`, `node_name` and `containers`; empty fields are left
out and there is no `identity` until cluster identities are allocated (#328).

## Pod network annotation (#328)

`pod-networks` is the value the agent keeps in the Pod's
`flowsdn.io/pod-networks` annotation in Kubernetes mode (OVN-Kubernetes's
`k8s.ovn.org/pod-networks` shape, keyed by network; flowsdn attaches one,
`default`). It describes what the CNI configured inside the Pod:

```json
{"default": {
  "role": "primary", "interface": "eth0", "mac_address": "02:…",
  "ip_addresses": ["10.5.0.7/32", "f00d::a05:0:0:7/128"],
  "gateway_ips": ["10.5.0.1", "f00d::a05:0:0:1"],
  "routes": [{"dest": "10.5.0.1/32"}, {"dest": "0.0.0.0/0", "nextHop": "10.5.0.1"},
             {"dest": "f00d::a05:0:0:1/128"}, {"dest": "::/0", "nextHop": "f00d::a05:0:0:1"}],
  "host_interface": "lxc…", "endpoint_id": 7, "sandbox": "…", "node": "node-a"}}
```

`node` is absent outside Kubernetes mode. `identity` will be added when
identities are allocated. The agent merge-patches the annotation (with the Pod
UID as precondition) within about two seconds of the endpoint's creation and
rewrites it when it is removed or edited; a failing write is retried after 30 s
and reported in `GET /v1/healthz` under `kubernetes` (`annotations: …`).

### Multus network-status (#371)

Beside it the agent keeps flowsdn's entry in the Pod's
`k8s.v1.cni.cncf.io/network-status` annotation (Kubernetes Network Plumbing WG
format, as Multus writes it; stormcos#249), derived from the same value so the
two always agree:

```json
[{"name": "flowsdn", "interface": "eth0", "ips": ["10.5.0.7", "f00d::a05:0:0:7"],
  "mac": "02:…", "default": true}]
```

`name` is the conflist's network name. The entry is merged into the Pod's list:
other plugins' entries (Multus's secondary attachments) are kept, an earlier
flowsdn entry (same name, or same interface) is replaced, and the default
network's entry is first. These writes carry the Pod's `resourceVersion` as a
precondition too, so a concurrent write by Multus fails ours (409) instead of
being lost; it is retried on the next pass. A network-status value too large
for the Pod view (over 16 KiB) is left alone. No change is needed in RBAC.

Pod metadata is retained CNI-supplied information, not a fresh Kubernetes
lookup. Missing legacy metadata is JSON null. Existing networking fields also
include MACs, host addressing and route MTU. `state: ready` describes the initial
published endpoint response, not Kubernetes Pod Ready or policy readiness;
use the separate endpoint health route for current link/teardown checks.

## Pool summary shape

```json
{
  "pools": [
    {
      "pool": "default",
      "family": "ipv4",
      "cidr": "10.0.0.0/24",
      "capacity": "254",
      "allocated": "2",
      "excluded": "1",
      "allocated-excluded": "0",
      "available": "251"
    }
  ]
}
```

Families are ordered IPv4 then IPv6; disabled families are omitted. An empty
configuration returns `{"pools":[]}`. All counts are decimal **strings**, even
for IPv4, so IPv6 prefixes remain exact beyond JSON/JavaScript integer limits.

- `capacity`: addresses within the allocatable range after prefix endpoint
  reservations; exclusions do not reduce this fixed count.
- `allocated`: actual user/pending reservations, including infrastructure
  allocations and endpoint-owned addresses. It is **not an endpoint count**.
  Lazily inserted allocator bookkeeping entries for exclusions are not counted.
- `excluded`: configured exclusions inside the allocatable range; foreign
  addresses and already-reserved prefix endpoints do not consume capacity again.
- `allocated-excluded`: actual allocations subsequently covered by an exclusion.
  They remain allocated until release and must not be counted twice.
- `available`: `capacity - allocated - excluded + allocated-excluded`.

Releasing an excluded address removes its allocation but does not remove the
exclusion. Summaries inspect sparse allocation/exclusion metadata; they never
scan the IPv6 address space or materialize exclusions merely to count them.

## Persisted endpoint fields

The persisted endpoint document's `EndpointUID` field (the UID of the
endpoint's FlowsdnEndpoint, empty while none is owned) was spelled with the
reference project's name before #330; documents written earlier keep the old
key as a retained unknown field. It is not permission to adopt upstream objects. Owned
Kubernetes resources follow [ADR-0017](decisions/0017-flowsdn-resource-identity.md).
