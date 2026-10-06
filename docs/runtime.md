# Current runtime configuration and deployment

This describes the executable code as of 2026-10-05, including changes since
2026-09-25. The agent owns local endpoints and host-scope IPAM. Built with the
`kubernetes` feature and configured with a `kubernetes` section, it also
watches Nodes and Pods, takes its pod CIDR from its Node and routes to the
other nodes' pod CIDRs (#291); it has no identity allocator, policy or
Services yet. The broader configuration catalogue
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
| `kubernetes.node-name` | `K8S_NODE_NAME`, then `NODE_NAME` | This node's Node name. |
| `kubernetes.kubeconfig` | In-cluster service account | Explicit kubeconfig path. A developer's default kubeconfig is never consulted. HTTPS must verify. |
| `kubernetes.auto-direct-node-routes` | `true` | Install `<podCIDR> via <InternalIP> proto kernel` for every other node (spec 10 §3.2.3). |
| `kubernetes.direct-routing-skip-unreachable` | `false` | Skip, instead of reporting an error for, a node whose InternalIP is reached through a gateway. |

Unknown JSON keys are currently ignored; they do not enable features. Gateway
addresses must match their family and cannot be unspecified, multicast,
loopback, or IPv4 broadcast addresses. An invalid `egress` value fails startup.
Examples: the stormcos edition's
[ConfigMap](../deploy/stormcos/manifests/61-flowsdn-config.yaml) and the
dual-stack [validation ConfigMap](../deploy/stormcos/50-config.yaml) (pinned).

The CNI executable is invoked through CNI environment variables and JSON on
stdin, not the agent's command-line interface. Its agent socket defaults to
`/var/run/cilium/cilium.sock`, overridden by `CILIUM_SOCK`; its offline queue
defaults to `/var/run/cilium/deleteQueue`, overridden by `FLOWSDN_DELETE_QUEUE`.
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
| `CNI_DIR` | `$HOST_PREFIX/opt/cni` | Its `bin/` gets `cilium-cni` (copied atomically), hardlinks `flowsdn-cni` and `flowsdn`, and `loopback`. |
| `CNI_CONF_DIR` | `$HOST_PREFIX/etc/cni/net.d` | Gets `00-flowsdn.conflist`, written atomically with mode 0644. |
| `OVERWRITE_CILIUM` | `true` | `false` keeps an existing regular `cilium-cni` and relinks the aliases to it. |
| `OVERWRITE_LOOPBACK` | `false` | `true` replaces an existing `loopback`; otherwise it is copied only when absent. Loopback failures are warnings. |

The conflist is `{"cniVersion":"1.1.0","name":"flowsdn","plugins":[{"type":"cilium-cni"}]}`:
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
| JSON `type` | The runtime uses it to select the installed binary: the installed conflist names `cilium-cni`; `flowsdn` and `flowsdn-cni` are hardlinks to it. This executable does not validate it (except `loopback`/`flowsdn-loopback`, which select the loopback adapter). |
| JSON `chaining-mode` | Absent/empty; a nonempty string is rejected. |
| JSON `ipam.type` | Absent/empty; delegated IPAM is rejected. Allocation comes from the agent. |
| JSON `prevResult` | Absent/null for primary ADD; CHECK uses prior interfaces, IPs and routes for validation. |
| `CNI_CONTAINERID`, `CNI_IFNAME`, `CNI_NETNS`, `CNI_PATH` | Required nonempty environment values for ADD/CHECK. Interface names must be shorter than 16 bytes and contain neither slash nor NUL. |
| `CNI_ARGS` | Optional semicolon-separated `key=value` pairs. `K8S_POD_NAME`, `K8S_POD_NAMESPACE`, `K8S_POD_UID` default to empty metadata. |
| `CILIUM_SOCK` | Default `/var/run/cilium/cilium.sock`. |
| `FLOWSDN_DELETE_QUEUE` | Default `/var/run/cilium/deleteQueue` for offline DEL. |

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
the Node and Pod lists, and with `service-lb` the Service and EndpointSlice
lists, are synced and nothing failed). `/healthz` and `/readyz`
are not implemented. Module health marks identity and policy controllers as
unavailable. The config response's `ipam-mode: kubernetes` is a compatibility
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
  kernel` routes in the main table for every other node, using the node's first
  InternalIP of the family. Before installing it checks that the kernel reaches
  the InternalIP without another gateway, and refuses to replace a route of
  another protocol to the same prefix. Installed routes are recorded in
  `<state-dir>/direct-routes.json` before they are added, so routes for nodes
  that left while the agent was down are deleted on the next reconcile. It
  reconciles on every change of the desired set and every 30 s;
- with `service-lb` (default on), lists and watches Services and
  EndpointSlices and load balances ClusterIPs at the socket (below);
- serves `GET /v1/ip`, `GET /v1/node/routes` and `GET /v1/service`
  ([API](agent-api.md)).

Not yet: a cluster identity allocator (pod IP cache entries carry labels but no
numeric identity), BPF ipcache maps, tunnel routing, masquerade, NodePort and
LoadBalancer Services, and policy. Unit tests and a loopback-HTTPS controller test cover the
watch and route logic; two-node pod traffic has not been demonstrated
(pvetest1 + pvetest2, stormcentral#360).

### ClusterIP socket LB (#292)

Spec 05 §3.8. The agent embeds the `socket-lb` BPF object: eight
`cgroup_sock_addr` programs (`connect4/6`, `sendmsg4/6`, `recvmsg4/6`,
`getpeername4/6`) over `cilium_lb{4,6}_services_v2`, `cilium_lb{4,6}_backends_v3`
and `cilium_lb{4,6}_reverse_sk` (spec 01 layouts). At startup it loads them
and attaches them with `BPF_F_ALLOW_MULTI` to `kubernetes.cgroup-root`
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

The frontends: every cluster IP (`spec.clusterIPs`, headless skipped) x every
TCP/UDP port of every Service; backends are the addresses of the Service's
EndpointSlices of the same family on the slice port with the same name and
protocol, `ready` endpoints first, serving-terminating ones only when none is
ready. A services thread owns the maps. Once both lists are complete, on each
change and every 30 s, it reads the maps, plans the difference
(`flowsdn_lb::socket`: service IDs and backend IDs are kept from what the
maps hold, and new IDs never reuse a live one) and writes in spec 05 §3.4
order: backends, slots, then the master entry that publishes the new count,
then stale masters, slots and backends. A failed write is retried from the
kernel state on the next pass and reported in health (`services`).

With `bpf-pin-root` the maps and links are pinned under `<pin root>/socket-lb`.
A restarted agent reuses the maps (a pinned map with another layout refuses
startup), attaches its programs, then releases the old links. Without a pin
root the links detach when the agent exits. Not implemented: NodePort and
LoadBalancer/externalIPs frontends, session affinity, Maglev, topology
hints, `internalTrafficPolicy: Local`, skip-LB for local redirect policy,
socket termination when a backend goes away (an existing connection stays
on its backend), SCTP, and tc-level LB for traffic that arrives from outside
the node. `socket-lb-live` (medium test suite) checks the programs on a
kernel; no cluster run yet.

Without Kubernetes mode the agent does no Node/Pod discovery, installs no
remote routes and has no Service handling; uplink ingress attachment is not
wired in either mode.

stormcos ships flowsdn as a **golden** containing the static musl agent
(`/flowsdn-agent`, BPF object embedded) and CNI (`/opt/cni/bin/flowsdn`). Nodes
clone goldens copy-on-write and mount it at `/pallets/flowsdn`; nothing is
pulled. The latest golden is `golden-flowsdn-a7ee3f63195b`, staged from
`c6c96c7`. The golden/release authority is
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
the Kubernetes-mode agent's socket LB (#292, below), so they need
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
