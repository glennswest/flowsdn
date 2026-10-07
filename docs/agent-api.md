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

This is the initial persisted endpoint and host-scope IPAM API. The daemon has
no Kubernetes watches, identity/policy controllers, operator service, Hubble
gRPC observer on 4244, or relay. A successful response does not establish a
working multi-node pod network. The config response's `ipam-mode: kubernetes`
is a compatibility value; this daemon allocates from configured local prefixes
and does not discover Kubernetes PodCIDRs.

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
  conflict, 413 too large, 501 not implemented, 502 an internal allocation failure.
- Error bodies are a JSON string with the message.

`api::ROUTES` in the agent lists the routes below, and a test fails when this
page's table differs from it, so a route change changes this page in the same
commit.

## Transport and supervision

Send a bounded request to the configured Unix socket, for example:

```sh
curl --unix-socket /run/flowsdn/agent.sock http://localhost/v1/healthz
curl http://127.0.0.1:9878/v1/endpoint     # with "http-listen": "127.0.0.1:9878"
```

`localhost` is an HTTP request authority in this example, not a TCP destination.
`GET /v1/healthz` returns HTTP 200 and the initial endpoint API status after
state restoration and queued deletion replay complete. It is an API liveness
and startup signal, not policy/controller readiness. Bare `/healthz` and
`/readyz` are not implemented. A supervisor that only probes TCP HTTP needs a
Unix-socket-capable probe or an explicit adapter; do not configure a nonexistent
path and restart an otherwise running daemon.

The body is `{"agent":{"state":"Ok","msg":…}}`, plus a `kubernetes` member in
Kubernetes mode. (Before #298 the member was named after the reference project;
it is `agent` now.)

`GET /v1/health/modules` reports component details, including the degraded
unimplemented-controller state. Module rows and endpoint health are separate
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
| `GET /v1/ip` | Kubernetes mode: the IP cache view (reference `IPListEntry`). Each node InternalIP as `/32`/`/128` with identity 1 (this node) or 6 (remote node); each IP of a non-host-network Pod with `hostIP` (its node's InternalIP of the family), `metadata{source,namespace,name}` (plus flowsdn's `uid`, `containers` and, with a controller owner, `workloads`, #328) and the flowsdn `labels` extension (`k8s:<key>=<value>` plus `k8s:io.kubernetes.pod.namespace`). Pod entries have no `identity` until cluster identity allocation exists. No `cidr` query filter. 404 when Kubernetes mode is off. |
| `GET /v1/service` | Kubernetes mode with `service-lb` (reference `Service` model): one row per frontend, `spec{id, frontend-address{ip,port,protocol,scope}, backend-addresses[{ip,port,protocol,state}], flags{type, name, namespace, port-name, service-type}}`; `type` is `ClusterIP`, `ExternalIPs`, `LoadBalancer` or `NodePort` (#292). `id` is the service ID (`rev_nat_index`) the socket-LB maps hold, 0 until programmed; `status.realized` repeats `spec` once it is. Empty until both the Service and EndpointSlice lists are complete. 404 when Kubernetes mode is off. |
| `GET /v1/node/routes` | Kubernetes mode (flowsdn): the direct node routes, `{destination, gateway, node, state}` with state `installed`, `skipped: …` or `error: …`. Empty before the first Node list or with `auto-direct-node-routes: false`. 404 when Kubernetes mode is off. |

List, detail and pool summary reads perform no allocation or endpoint mutation.
As with existing API requests, expired pending IP leases are processed first.
Read identifiers consisting entirely of decimal digits must fit a nonzero u16;
invalid or unknown numeric IDs return 404. Other identifiers match the stored
CNI attachment string. PUT/DELETE continue to use attachment identifiers.

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
