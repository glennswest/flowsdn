# Current runtime configuration and deployment

This describes the executable code as of 2026-10-09 (`53bffc7`), including
changes since 2026-09-25. The agent owns local endpoints and host-scope IPAM.
Built with the `kubernetes` feature and configured with a `kubernetes` section,
it also watches Nodes and Pods, takes its pod CIDR from its Node, routes to the
other nodes' pod CIDRs (#291) and load balances Services at the socket and, for
traffic from outside the cluster, on the node's uplink (#292), and holds a
cluster identity for each local Pod's labels (#291); it has no policy
enforcement yet. The broader configuration catalogue
and specifications describe library contracts and planned integrations, not
additional options accepted by this executable.

## Agent configuration

Run `flowsdn-agent --config PATH` with a JSON file. `--help`/`-h` and
`--version`/`-V` succeed without reading configuration. There is no config-reload
API or generic compatibility flag parser. Configuration is read once at startup,
limited to 1 MiB. The authoritative reader is
[`Config::read`](../crates/flowsdn-agent/src/api.rs).

| Key | Required/default | Meaning |
|---|---|---|
| `socket-path` | Required nonempty string | Unix HTTP socket; created with mode 0600. |
| `http-listen` | Omitted, null or empty: disabled | `IP:port` of a **read-only** HTTP listener; the address must be loopback (`127.0.0.1`, `::1`) and the port nonzero, or the config is refused. It serves the same routes as the socket for `GET` and the statedb query (`POST`); any other method returns 403, since TCP has no authentication. For the stormcos console plugin (#297); the edition manifests use `127.0.0.1:9878`. |
| `state-dir` | Required nonempty string | Durable endpoint state; exclusive ownership lock. |
| `bpf-object` | Omitted, null or empty: the object embedded in the agent | A `local-delivery` BPF ELF to load instead of the embedded one (built from this commit by `tools/build-bpf.sh`; `test/build.sh` refuses an embedded copy whose code differs). |
| `egress` | `fib` | `fib`: a destination that is not a local endpoint is FIB-redirected in BPF (native routing between router namespaces). `stack`: every frame from an endpoint goes to the host stack (routing, netfilter), same-node pod-to-pod included, so the endpoint's ARP replies reach the host and host routes (including direct node routes) apply; every endpoint also gets host `/32`/`/128` routes over its host link. The stormcos edition uses `stack`. |
| `bpf-pin-root` | Omitted, null or empty: disabled | Dedicated bpffs directory for persistent map and TCX ownership. |
| `delete-queue` | Omitted, null or empty: `deleteQueue` in the socket's parent directory | Durable CNI offline deletion queue. |
| `ipv4-pool` | Omitted, null or empty: disabled | IPv4 host allocation CIDR. |
| `ipv6-pool` | Omitted, null or empty: disabled | IPv6 host allocation CIDR. At least one family must be enabled. |
| `ipv4-pool`/`ipv6-pool` `auto` | Needs `kubernetes` | The pool comes from this node's Node (spec 07 §3.4): the first `spec.podCIDRs` entry of the family, else IPv4 `10.<last byte of the node's IPv4 InternalIP>.0.0/16`, IPv6 `f00d::<4 bytes of the IPv4 pool, else of the node IPv6>:0:0/96`. The agent waits for the Node before restore, logging every 5 s. |
| `ipv4-gateway` | Required when IPv4 is enabled | IPv4 router address, excluded from allocation. Must be absent/empty when IPv4 is disabled. With an `auto` pool: absent, empty or `auto`, and the router is the pool's first host address. |
| `ipv6-gateway` | Required when IPv6 is enabled | IPv6 router address, excluded from allocation. Must be absent/empty when IPv6 is disabled. Same `auto` rule. |
| `device-mtu` | Required integer, at least 1280 | Device MTU. |
| `route-mtu` | Required integer, at least 1280 | Route MTU; must not exceed device MTU. |
| `endpoint-id-max` | `4095` | Integer in `1..=65535`; bounds ID allocation, not BPF map capacity. |
| `kubernetes` | Omitted or null: disabled | Object; enables Node/Pod discovery. Needs an agent built with `--features kubernetes`; the default (static musl) build fails startup with it. |
| `kubernetes.node-name` | `K8S_NODE_NAME`, then `NODE_NAME` | This node's Node name: required (from one of the three), at most 253 characters of ASCII letters, digits, `-` and `.`. |
| `kubernetes.kubeconfig` | In-cluster service account | Explicit kubeconfig path. A developer's default kubeconfig is never consulted. HTTPS must verify. |
| `kubernetes.auto-direct-node-routes` | `true` | Install `<podCIDR> via <InternalIP> proto kernel` for every other node (spec 10 §3.2.3). |
| `kubernetes.direct-routing-skip-unreachable` | `false` | Skip, instead of reporting an error for, a node whose InternalIP is reached through a gateway. |
| `kubernetes.service-lb` | `true` | Watch Services and EndpointSlices and load the embedded `socket-lb` object ([socket LB](#clusterip-socket-lb-292)). |
| `kubernetes.cgroup-root` | `/sys/fs/cgroup` | Absolute path of the cgroup v2 directory the socket-LB programs attach to (the manifests mount the host's root at `/run/flowsdn/cgroupv2`). |
| `kubernetes.node-port` | `true` | Attach the NodePort programs to the uplinks (traffic from outside the cluster). Takes effect only with `service-lb`. |
| `kubernetes.identity-allocation` | `true` | Watch Namespaces and FlowsdnIdentity objects and allocate cluster identities ([identities](#cluster-identities-291)). |
| `kubernetes.cluster-name` | `default` | The cluster label on every Pod identity (`io.flowsdn.k8s.policy.cluster`); a DNS label of at most 32 bytes. |

The `kubernetes` booleans must be JSON booleans and its strings strings, or
startup fails.

Unknown JSON keys are currently ignored; they do not enable features. Gateway
addresses must match their family and cannot be unspecified, multicast,
loopback, or IPv4 broadcast addresses. An invalid `egress` value fails startup.
Examples: the stormcos edition's
[ConfigMap](../deploy/stormcos/manifests/61-flowsdn-config.yaml) and the
dual-stack [validation ConfigMap](../deploy/stormcos/50-config.yaml) (pinned).

The CNI executable is invoked through CNI environment variables and JSON on
stdin, not the agent's command-line interface. Its agent socket defaults to
`/var/run/flowsdn/flowsdn.sock`, overridden by `FLOWSDN_SOCK`; its offline queue
defaults to `/var/run/flowsdn/deleteQueue`, overridden by `FLOWSDN_DELETE_QUEUE`.
These are environment overrides, not CNI JSON keys. When using custom agent
paths, configure both sides consistently.

## Installing the CNI on a node

The CNI executable treats a first argument `install` as the node installer (a runtime never
passes arguments). It copies its own executable into `$CNI_DIR/bin` and writes
the network configuration, then prints a JSON report (`installed`, `conflist`,
`plugin_replaced`, `loopback_replaced`, `warnings`); failure exits 1.

| Environment | Default | Meaning |
|---|---|---|
| `HOST_PREFIX` | `/host` | Prefix for the two defaults below. |
| `CNI_DIR` | `$HOST_PREFIX/opt/cni` | Its `bin/` gets `flowsdn-cni` (copied atomically), the hardlink `flowsdn`, and `loopback`. |
| `CNI_CONF_DIR` | `$HOST_PREFIX/etc/cni/net.d` | Gets `00-flowsdn.conflist`, written atomically with mode 0644. |
| `OVERWRITE_PLUGIN` | `true` | `false` keeps an existing regular `flowsdn-cni` and relinks `flowsdn` to it. |
| `OVERWRITE_LOOPBACK` | `false` | `true` replaces an existing `loopback`; otherwise it is copied only when absent. Loopback failures are warnings. |

The conflist is `{"cniVersion":"1.1.0","name":"flowsdn","plugins":[{"type":"flowsdn-cni"}]}`:
no chained plugins, no delegated IPAM. The `00-` prefix sorts ahead of a
leftover `05-cilium.conflist`. `flowsdn-agent cni install --source PATH` does the
binary half only (same variables, no conflist). Neither removes an installation.

## CNI input

The CNI entry point reads at most 1 MiB from stdin. `CNI_COMMAND` selects ADD,
CHECK, DEL, STATUS or VERSION; GC is unsupported. VERSION returns supported
versions without contacting the agent. The other supported commands require
`cniVersion` equal to `1.0.0` or `1.1.0`.

| Input | Behavior/default |
|---|---|
| JSON `name` | Required nonempty network name for ADD/CHECK. |
| JSON `type` | The runtime uses it to select the installed binary: the installed conflist names `flowsdn-cni`; `flowsdn` is a hardlink to it. This executable does not validate it (except `loopback`/`flowsdn-loopback`, which select the loopback adapter). |
| JSON `chaining-mode` | Absent/empty; a nonempty string is rejected. |
| JSON `ipam.type` | Absent/empty; delegated IPAM is rejected. Allocation comes from the agent. |
| JSON `prevResult` | Absent/null for primary ADD; CHECK uses prior interfaces, IPs and routes for validation. |
| `CNI_CONTAINERID`, `CNI_IFNAME`, `CNI_NETNS`, `CNI_PATH` | Required nonempty environment values for ADD/CHECK. Interface names must be shorter than 16 bytes and contain neither slash nor NUL. |
| `CNI_ARGS` | Optional semicolon-separated `key=value` pairs. `K8S_POD_NAME`, `K8S_POD_NAMESPACE`, `K8S_POD_UID` default to empty metadata. |
| `FLOWSDN_SOCK` | Default `/var/run/flowsdn/flowsdn.sock`. |
| `FLOWSDN_DELETE_QUEUE` | Default `/var/run/flowsdn/deleteQueue` for offline DEL. |

MTUs, gateways and pools come from the agent response, not extra CNI JSON
options. DEL tolerates missing container/interface values and namespace for
idempotent cleanup; unknown commands fail. See the authoritative
[request parser](../crates/flowsdn-cni/src/lib.rs) and
[command implementation](../crates/flowsdn-cni/src/runtime.rs).

## Loopback CNI

The CNI executable also dispatches by `loopback`/`flowsdn-loopback` basename or
configuration type. This adapter operates on namespace `lo` independently of
the agent: ADD raises it and returns its addresses, CHECK requires UP, and DEL
lowers it (a missing namespace succeeds). VERSION and STATUS require no namespace.
Only CNI 1.0.0/1.1.0 are currently supported. The installers above publish the
`loopback` name.

## Ports and APIs

HTTP/1.1 is served on `socket-path` and, with `http-listen`, read-only on a
loopback TCP port (the edition manifests: `127.0.0.1:9878`; the agent runs on the
host network, so that is the node's loopback). Nothing listens on a non-loopback
address. It does not serve Hubble gRPC on port 4244, a relay, a metrics listener, or a
Kubernetes Service endpoint. Port numbers in subsystem specifications or
library configuration must not be used as evidence that the daemon listens.

The [API contract](agent-api.md) lists every supported method and response
shape: config, endpoint inventory/detail/publication/deletion, host IPAM,
module health and the read-only health StateDB query. Requests are processed
serially, one per connection, with 16 KiB headers, 4 MiB bodies and a two-second
request budget. There is no pagination, watch endpoint or HTTP authentication;
access is controlled by socket permissions, and the loopback listener refuses every
method that can change state (403). Pending leases requesting
expiration time out after 600 seconds.

`GET /v1/healthz` reports initial API availability after restoration and queued
deletion replay; in Kubernetes mode it adds a `kubernetes` member (`Ok` once
the Node and Pod lists, with `service-lb` the Service and EndpointSlice
lists, and with `identity-allocation` the Namespace and FlowsdnIdentity lists,
are synced and nothing failed). `/healthz` and `/readyz`
are not implemented. Module health marks the policy controllers as unavailable. The config response's `ipam-mode: kubernetes` is a compatibility
value: allocation uses the configured pools, or with `auto` the pool resolved
from the Node at startup.

## Runtime behavior and shipping

The agent and CNI implement native veth attachment, local IPv4/IPv6 allocation,
endpoint persistence, teardown and offline deletion replay. Configured bpffs
pins retain endpoint maps and TCX ownership across process absence and allow
validated reuse at restore. Without a pin root, links belong to the process and
are reinstalled from state at restart, briefly pausing endpoint traffic. This
does not establish rolling upgrade support. In `egress: stack` mode the agent
replaces a host route to each endpoint address over its host link; deleting the
link removes the routes.

## Kubernetes mode

With the `kubernetes` feature and section the agent:

- writes Kubernetes Events (core/v1, `source.component: flowsdn-agent`, #298) so
  `kubectl describe` / `sc describe` shows what it did. On the Pod:
  `EndpointCreated` (Normal: endpoint ID and addresses), `EndpointCreateFailed`
  and `IPAllocationFailed` (Warning: the reason). On its Node: `PodCIDRSelected`
  (Normal), `DirectRouteFailed`, `ServiceLBUnavailable` and `SysctlFailed`
  (Warning). Repeats of one object, reason and message are one Event with a
  growing `count`, rewritten at most once a minute and forgotten after an hour.
  Recording never blocks or fails a request: a full queue (256) drops events. Needs
  `events` create/update (the manifests and chart grant it);

- tags each local Pod with its network (#328): the `flowsdn.io/pod-networks`
  annotation (OVN-style: addresses, MAC, gateways, routes, interface, host
  interface, endpoint ID, sandbox, node; [API](agent-api.md#pod-network-annotation-328)),
  merge-patched within about 2 s of the endpoint's creation and rewritten if it
  is removed or edited. Needs `pods` patch (the manifests and chart grant it).
  The Pod view also gives each endpoint and `GET /v1/ip` row its UID, workload
  (Deployment for its ReplicaSets) and containers;

- loads credentials (explicit kubeconfig, else in-cluster) and, when a pool is
  `auto`, blocks until its Node yields a pool for every such family;
- after restore, sets `net.ipv4.conf.all.rp_filter=0`, `net.ipv4.ip_forward=1`,
  `net.ipv4.conf.all.forwarding=1` and, with an IPv6 pool,
  `net.ipv6.conf.all.forwarding=1` (spec 10 §3.6). A failed write is reported
  in health, not fatal;
- lists and watches Nodes and all Pods on its own thread (pages of 500; a watch
  the server ends resumes from its resourceVersion; any other failure relists
  after 1 s doubling to 30 s, keeping the last good snapshot);
- with `auto-direct-node-routes`, owns `<podCIDR> via <InternalIP> proto
  kernel` routes in the main table for every other node that has
  `spec.podCIDRs` (a node's own derived pool is not known to the others, so
  without `spec.podCIDRs` there is no route to it; #296), using the node's first
  InternalIP of the family. Before installing it checks that the kernel reaches
  the InternalIP without another gateway, and refuses to replace a route of
  another protocol to the same prefix. Installed routes are recorded in
  `<state-dir>/direct-routes.json` before they are added, so routes for nodes
  that left while the agent was down are deleted on the next reconcile. It
  reconciles on every change of the desired set and every 30 s;
- with `service-lb` (default on), lists and watches Services and
  EndpointSlices and load balances ClusterIPs at the socket (below);
- with `identity-allocation` (default on), lists and watches Namespaces and
  FlowsdnIdentity objects and holds a cluster identity for each local Pod
  ([below](#cluster-identities-291));
- serves `GET /v1/ip`, `GET /v1/identity`, `GET /v1/node/routes` and
  `GET /v1/service` ([API](agent-api.md)).

### Cluster identities (#291)

Spec 03 §3.3 in CRD mode, over cluster-scoped `flowsdn.io/v1alpha1`
FlowsdnIdentity objects named by the decimal identity. A Pod's identity labels
(spec 03 §3.1, flowsdn keys per ADR-0020) are its own labels without
`io.flowsdn.k8s*` keys, `io.flowsdn.k8s.namespace.labels.<key>` for each
label of its Namespace, `io.kubernetes.pod.namespace`,
`io.flowsdn.k8s.policy.serviceaccount` (when set) and
`io.flowsdn.k8s.policy.cluster`, all source `k8s`, then the default identity
label filter (spec 03 §4.2 with flowsdn keys: `pod-template-hash`,
`kubernetes.io/…` and similar are dropped). Host-network Pods have none.

Nothing is allocated before the Pod, Namespace and FlowsdnIdentity lists are
complete. Every second the identities thread, for each label set among this
node's Pods:

- uses a well-known identity when the set is a cluster-DNS one (102, 103, 104,
  106, 110–112, 114; spec 03 §4.4, no API call);
- else reuses the oldest object with exactly those labels (ties to the lower
  number), removing the operator's `io.flowsdn.heartbeat` annotation with an
  Update if present;
- else creates one on a free number in 256–65535, searched from a random
  start; a 409 (another node took the number) or other failure drops it and
  the next pass looks up or tries again;
- re-creates a held identity whose object was deleted while a local Pod still
  uses it (master-key protection). A node that created a duplicate for the
  same labels keeps it; new lookups everywhere converge on the oldest.

Sets no longer used are released without an API call: deleting unused objects
is the operator's identity GC (#332), which does not run yet, so objects
accumulate until it does. Remote Pods resolve to the oldest object with their
labels. The identities appear in `GET /v1/identity`, on Pod rows of
`GET /v1/ip`, and as `status.identity` and `pod.identity` of local endpoints.
They are not in BPF maps: nothing in the datapath consumes them until policy
(#292). Needs `flowsdnidentities` list/watch/create/update and `namespaces`
list/watch (the manifests and chart grant them) and the FlowsdnIdentity CRD
(stormcos#303 applies `crds/`); without the CRD the identity watch reports
an error in health and nothing is allocated.

Not yet: a flow/drop observer (the
`flowsdn-hubble` `endpoint` module names flow peers `ns/pod (container)` once
one exists, #293), BPF ipcache maps, tunnel routing, masquerade, and policy enforcement. Unit tests and a loopback-HTTPS controller test cover the
watch and route logic; two-node pod traffic has not been demonstrated
(pvetest1 + pvetest2, stormcentral#360).

### ClusterIP socket LB (#292)

Spec 05 §3.8. The agent embeds the `socket-lb` BPF object: eight
`cgroup_sock_addr` programs (`connect4/6`, `sendmsg4/6`, `recvmsg4/6`,
`getpeername4/6`) over `flowsdn_lb{4,6}_services`, `flowsdn_lb{4,6}_backends`
and `flowsdn_lb{4,6}_reverse_sk` (spec 01 layouts; flowsdn's names, #330). At startup it loads them
and attaches them as bpf_links (which coexist with other cgroup programs) to `kubernetes.cgroup-root`
(default `/sys/fs/cgroup`; the manifests mount the host's root at
`/run/flowsdn/cgroupv2`). A cgroup program sees every socket of every process
below it, whatever its network namespace, so pods and the host are covered.

- `connect` (TCP, connected UDP) and `sendmsg` (unconnected UDP) to a
  frontend `ClusterIP:port/proto` pick a backend slot uniformly at random and
  rewrite the destination before routing; the packets carry the backend
  address, so there is no packet DNAT and no conntrack entry. IPv4-mapped
  IPv6 destinations use the IPv4 maps.
- For UDP the program records `(socket cookie, backend) -> frontend` in the
  LRU reverse map; `recvmsg` and `getpeername` show the backend as the
  frontend, so resolvers that check the reply source accept it.
- A frontend whose backend count is 0 fails `connect`/`sendmsg` with EPERM.
  Other destinations are untouched.
- `sessionAffinity: ClientIP` (#292): each client, identified by its network
  namespace (a pod; all host processes are one client), keeps getting the
  backend it last got while that is within
  `sessionAffinityConfig.clientIP.timeoutSeconds` (default 10800) of its last
  use. The program remembers it in the LRU `flowsdn_lb{4,6}_affinity` maps;
  the agent keeps `flowsdn_lb_affinity_match` pairing each current backend
  with its service, and removes a pair before the backend, so a client never
  sticks to a backend that has left.

The frontends, for every TCP/UDP port of every Service: each cluster IP
(`spec.clusterIPs`, headless skipped) and each `spec.externalIPs` address on
the port; for type LoadBalancer each `status.loadBalancer.ingress[].ip` on
the port; for types NodePort and LoadBalancer every node's InternalIP on the
`nodePort` (recomputed when node addresses change). These cover clients
inside the cluster, pods and node processes, whichever node's address they
use. Traffic arriving from outside the cluster (#292, IPv4 and IPv6): the agent
also writes a node-local copy (key scope 1) of every NodePort, external and
LoadBalancer frontend (not cluster IPs), with every backend (only this node's
with `externalTrafficPolicy: Local`), and, with `kubernetes.node-port` (default
on), attaches the `nodeport_ingress`/`nodeport_egress` tc programs (TCX) to
every interface holding this node's InternalIP, rechecked every pass of the
services thread (an interface that no longer holds it is detached; none found
is a `node-port` health error). For a packet to such a frontend the program
picks a backend and asks the FIB where it is. On this node (a pod's device,
or a node address): the destination is rewritten (IPv4 header and TCP/UDP
checksums fixed; IPv6 has no header checksum, the TCP/UDP one covers the
addresses), the host stack routes it to the pod, and the reply's source is
rewritten back on the way out. Back out of the uplink it came in on (a pod
on another node): the source is also rewritten to this node's address toward
that backend (the FIB's source, `BPF_FIB_LOOKUP_SRC`, Linux 6.7 or later) on
a port in 61000-65535 (outside the kernel's default ephemeral range), TTL
(IPv6: hop limit) is decremented, and the packet is redirected out of the uplink to the FIB's next
hop (`bpf_redirect_neigh` when the neighbour is not resolved yet). The other
node's reply to that port is reverse-NATed on the uplink's ingress and
redirected to the client. The other node must not masquerade that reply; it
is the reply of a connection its conntrack saw arrive, which masquerade rules
leave alone. Every direction is kept per flow in the LRU
`flowsdn_nodeport4_nat` / `flowsdn_nodeport6_nat` maps (64Ki entries each), so
a connection keeps its backend and NAT port. A packet the FIB cannot route,
with TTL 1, or for which no NAT port is free within eight tries passes
untranslated, and so does an IPv6 packet with extension headers before its
TCP/UDP header (fragments among them).
Other packets pass untouched; the programs never drop. `GET /v1/service` gives
each frontend's `flags.type` (`ClusterIP`, `ExternalIPs`, `LoadBalancer`,
`NodePort`) and `frontend-address.scope` (`external` for the socket LB's copy,
`node-local` for the uplink copy).
`internalTrafficPolicy: Local` limits a cluster IP to endpoints on this node;
`externalTrafficPolicy: Local` limits a NodePort on a node's address to that
node's endpoints (an empty set fails `connect`, as Kubernetes drops such
traffic). Backends are the addresses of the Service's
EndpointSlices of the same family on the slice port with the same name and
protocol, `ready` endpoints first, serving-terminating ones only when none is
ready. A services thread owns the maps. Once both lists are complete, on each
change and every 30 s, it reads the maps, plans the difference
(`flowsdn_lb::socket`: service IDs and backend IDs are kept from what the
maps hold, and new IDs never reuse a live one) and writes in spec 05 §3.4
order: backends, slots, then the master entry that publishes the new count,
then stale masters, slots and backends. A failed write is retried from the
kernel state on the next pass and reported in the `kubernetes` health member
(`services`; a socket LB that cannot load or attach is also a
`ServiceLBUnavailable` Node event, and ClusterIPs are then not handled).

With `bpf-pin-root` the maps and links are pinned under `<pin root>/socket-lb`.
A restarted agent reuses the maps (a pinned map with another layout refuses
startup), attaches its programs, then releases the old links. Without a pin
root the links detach when the agent exits. The NodePort uplink links are never
pinned: they detach when the agent exits, and the per-CPU
`flowsdn_nodeport6_fib` scratch map is not pinned either. Not implemented:
Maglev, DSR, topology hints, skip-LB for local redirect policy, socket
termination when a backend goes away (an existing connection stays on its
backend), SCTP, NAT46/64, IPv4 fragments other than the first (they pass
untouched), and BPF masquerade. `socket-lb-live` (medium test suite) checks the
programs on a kernel, including the NodePort local and SNAT paths through
`BPF_PROG_TEST_RUN`; no two-node cluster run yet.

Without Kubernetes mode the agent does no Node/Pod discovery, installs no
remote routes and has no Service handling. The `local-delivery` object's uplink
ingress program is not attached in either mode (the NodePort programs above
are the `socket-lb` object's).

stormcos ships flowsdn as a **golden** containing the agent (`/flowsdn-agent`;
since golden-flowsdn-4e9e3f0bc876 the GNU Kubernetes-mode build with its Fedora
OpenSSL runtime, stormcos#171) and the static musl CNI (`/opt/cni/bin/flowsdn`). Nodes
clone goldens copy-on-write and mount it at `/pallets/flowsdn`; nothing is
pulled. The latest golden is `golden-flowsdn-cc0835c8a1db`, staged from
`347581a` (IPv4 NodePort SNAT); the IPv6 NodePort programs (`53bffc7`) are in no
golden yet. The golden/release authority is
[stormcos's golden documentation](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
The flowsdn edition and composition are owned by stormcos; source changes reach
nodes through a newly staged golden and composed release, not through a Git
push alone. The workspace version is still `0.14.0`; the subsequent agent work
is unreleased in this repository's version history.

The [deployment contract](../deploy/stormcos/README.md) describes the edition
manifests (`deploy/stormcos/manifests/`): a DaemonSet with `image: flowsdn`
(the golden itself under the stormpump runtime), an init container running
`flowsdn-cni install`, and the agent with `egress: stack` and a static
single-node IPv4 pool. Whether stormcos applies them is
[stormcos#261](https://github.com/glennswest/stormcos/issues/261); the node
provides masquerade. The edition runs no kube-proxy: ClusterIPs are handled by
the Kubernetes-mode agent's socket LB (#292, above), so they need
`deploy/stormcos/manifests-kubernetes/`, the multi-node set for the
Kubernetes-connected agent.

`flowsdn-operator` and `flowsdn-hubble` are libraries, without operator or relay
service binaries. Their duties have not moved into the agent. CRD registration
plans use flowsdn's own `flowsdn.io/v1alpha1` group with `Flowsdn*` kinds
([ADR-0017](decisions/0017-flowsdn-resource-identity.md), #299); `cilium.io`
schemas are read only by the explicit migration projection. The agent does not
register or reconcile CRDs. Compatibility with Cilium formats is an integration
goal, not a claim that all Cilium APIs, CRDs, CLIs or networking features work today.

## Fedora TLS build boundary

The Kubernetes client selects Fedora system OpenSSL under
[ADR-0016](decisions/0016-fedora-openssl.md). Building TLS consumers requires `openssl-devel` and
`pkgconf-pkg-config`; runtime requires matching `openssl-libs`, GNU/glibc,
OpenSSL configuration/provider files and certificate trust. Vendoring is disabled.
The default agent and the CNI do not link this client and stay static musl.
`cargo build --release -p flowsdn-agent --features kubernetes` (GNU target)
links it: the binary needs `libssl.so.3`, `libcrypto.so.3`, `libz.so.1`,
`libgcc_s.so.1` and glibc at run time. Its golden runtime is
[stormcos#171](https://github.com/glennswest/stormcos/issues/171).
