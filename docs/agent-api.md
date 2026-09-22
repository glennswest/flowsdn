# Standalone agent API

`flowsdn-agent --config PATH` exposes HTTP/1.1 on the configured `socket-path`
Unix socket, with mode 0600. It opens no TCP listener. Access depends on filesystem
permissions; there is no HTTP authentication layer. Config is the standalone
agent JSON format, not the full configuration catalogue. `--help` and `--version`
exit successfully without loading config or starting the daemon.

This is the initial persisted endpoint and host-scope IPAM API. The daemon has
no Kubernetes watches, identity/policy controllers, operator service, Hubble
gRPC observer on 4244, or relay. A successful response does not establish a
working multi-node pod network. The config response's `ipam-mode: kubernetes`
is a compatibility value; this daemon allocates from configured local prefixes
and does not discover Kubernetes PodCIDRs.

## Transport and supervision

Send a bounded request to the configured Unix socket, for example:

```sh
curl --unix-socket /run/flowsdn/agent.sock http://localhost/v1/healthz
```

`localhost` is an HTTP request authority in this example, not a TCP destination.
`GET /v1/healthz` returns HTTP 200 and the initial endpoint API status after
state restoration and queued deletion replay complete. It is an API liveness
and startup signal, not policy/controller readiness. Bare `/healthz` and
`/readyz` are not implemented. A supervisor that only probes TCP HTTP needs a
Unix-socket-capable probe or an explicit adapter; do not configure a nonexistent
path and restart an otherwise running daemon.

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
      "container-id": "sandbox-id"
    },
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
