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
| `metrics-listen` | Omitted, null or empty: disabled | `IP:port` of a loopback listener for `GET /metrics` only (#420; Prometheus text, `flowsdn_*` series, see [agent-api](agent-api.md#metrics)); other paths 404, other methods 403. Loopback and nonzero port, and not the `http-listen` address, or the config is refused. The edition manifests use `127.0.0.1:9962` for the node scraper (stormcos#64). |
| `state-dir` | Required nonempty string | Durable endpoint state; exclusive ownership lock (`agent.lock`, naming its holder). At start the agent waits while another agent holds it, logging `waiting for the state lock: … held by another flowsdn agent (pod …, pid …, since …, cgroup …)` at once and every 30 s, instead of exiting (#404). The lock it takes is kept through endpoint restoration and the whole run, never released in between, so a second waiting agent keeps waiting (#500). |
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
| `kubernetes.l2-neigh-discovery` | `false` | Managed neighbor entries for the next hops to other nodes on the uplinks ([neighbor management](#neighbor-management-469); the reference's `enable-l2-neigh-discovery`). On, the agent refuses to start on a kernel without managed neighbors. |
| `kubernetes.xdp-prefilter` | `false` | The XDP prefilter on the uplinks and its `/v1/prefilter` deny list ([XDP prefilter](#xdp-prefilter-467); the reference's `enable-xdp-prefilter`). |
| `kubernetes.node-port` | `true` | Attach the NodePort programs to the uplinks (traffic from outside the cluster). Takes effect only with `service-lb`. |
| `kubernetes.uplinks` | `{}` (`mode: active-active`, `table: 2080`, `rule-priority: 9100`, no weights) | Several uplinks (#408): an object, every key optional. `mode` is `active-active`, `active-backup` or `single` (as before #408); `weights` is `{"<interface>": 1-255}`; `table` and `rule-priority` place flowsdn's per-address source rules. Uplinks are discovered, never listed ([several uplinks](#several-uplinks-408)). |
| `kubernetes.lb-algorithm` | `random` | `random` or `maglev`: how the uplink programs pick a backend for a new flow from outside the cluster ([Maglev](#clusterip-socket-lb-292)). A Service's `service.flowsdn.io/lb-algorithm` annotation (`random` or `maglev`) overrides it. |
| `kubernetes.lb-mode` | `snat` | `snat`, `dsr` or `hybrid` (DSR for TCP, SNAT otherwise): how traffic from outside the cluster reaches a backend on another node ([DSR](#direct-server-return)). A Service's `service.flowsdn.io/forwarding-mode: dsr\|snat` annotation overrides it. |
| `kubernetes.lb-dsr-dispatch` | `opt` | How a DSR packet carries its frontend to the backend's node (#447; the reference's `bpf-lb-dsr-dispatch`): `opt` (an IPv4 option or IPv6 Destination Options header), `ipip` (IPIP / IP6IP6) or `geneve` (UDP 6081 with the DSR option) ([DSR](#direct-server-return)). A node accepts all three whatever its own setting. |
| `kubernetes.lb-external-clusterip` | `false` | External access to ClusterIP Services (#465; the reference's `bpf-lb-external-clusterip`): each cluster IP also gets a node-local copy, so traffic from outside the cluster that is routed to a ClusterIP on this node (a static route or BGP advertisement) reaches its backends through the uplink programs, with `internalTrafficPolicy` and with Maglev as for NodePort. |
| `kubernetes.nat46x64` | `false` | Service NAT46/64: a node-local frontend with no backend of its own family reaches the other family's backends, on other nodes and on this one (#450) ([NAT46/64](#service-nat4664)). |
| `kubernetes.lb-ipam` | `true` | LB-IPAM: give `type: LoadBalancer` Services addresses from FlowsdnLoadBalancerIPPools ([LoadBalancer Services](#loadbalancer-services-475)). Takes effect only with `service-lb`; nothing happens without a pool. |
| `kubernetes.l2-announcements` | `true` | Answer ARP and NDP for the load-balancer and external addresses FlowsdnL2AnnouncementPolicies give this node ([LoadBalancer Services](#loadbalancer-services-475)). Takes effect only with `service-lb` and `node-port`; nothing is announced without a policy. |
| `kubernetes.local-redirect-policy` | `false` | Local redirect policy (#565; the reference's `enable-local-redirect-policy`): FlowsdnLocalRedirectPolicy frontends, an address or a Service's ClusterIP, go to this node's Pods in the socket LB, with skip-LB for the backends' own traffic ([local redirect policy](#local-redirect-policy-565)). Needs `service-lb`. |
| `kubernetes.egress-gateway` | `false` | Egress gateway (#564; the reference's `enable-egress-gateway`): selected Pods' IPv4 traffic to a FlowsdnEgressGatewayPolicy's destinations leaves the cluster through a gateway node, from its egress address ([egress gateway](#egress-gateway-564)). Needs `bpf-masquerade` and `service-lb`; the agent refuses to start otherwise. |
| `kubernetes.endpoint-crd` | `true` | Keep a FlowsdnEndpoint for each local Pod endpoint ([endpoint and node objects](#flowsdnendpoint-and-flowsdnnode-332)). Nothing is written while the kind is not served. |
| `kubernetes.node-crd` | `true` | Keep this node's FlowsdnNode ([endpoint and node objects](#flowsdnendpoint-and-flowsdnnode-332)). |
| `kubernetes.bpf-masquerade` | `false` | BPF masquerade (#460, IPv6 #513; the reference's `enable-bpf-masquerade`), IPv4 and IPv6: the uplink programs source-NAT local Pods' traffic leaving the cluster ([BPF masquerade](#bpf-masquerade-460)). Needs `service-lb`; attaches the uplink programs even with `node-port` off. |
| `kubernetes.nat46x64-gateway` | `false` | The RFC 6052 NAT46/64 gateway (#454; the reference's `enable-nat46x64-gateway`): local Pods' IPv6 TCP/UDP to `nat46x64-gateway-prefix` leaves the uplink as IPv4 from this node's address ([RFC 6052 gateway](#rfc-6052-gateway-454)). Needs `service-lb`. |
| `kubernetes.nat46x64-gateway-prefix` | `64:ff9b::/96` | The gateway's prefix: an IPv6 /96 whose last 32 bits are the IPv4 destination. Anything else is refused at startup. |
| `kubernetes.non-masquerade-cidrs` | `[]` | CIDRs, IPv4 or IPv6, the BPF masquerade never masquerades to, beside the cluster's pod CIDRs and node addresses. |
| `kubernetes.lb-sock-terminate-all-protos` | `false` | Socket termination also ends TCP connections to a backend that leaves a Service ([socket LB](#clusterip-socket-lb-292); by backend address and port). |
| `kubernetes.crd-wait-timeout` | `300` | Seconds the flowsdn.io watchers wait for the CRDs this configuration uses before the agent exits ([CRDs and the operator](#crds-and-the-operator-337)). 1 to 86400. |
| `kubernetes.hubble-drop-events` | `false` | `PacketDrop` Events on local Pods for policy drops (#470, the reference's `hubble-drop-events`; [PacketDrop Events](#packetdrop-events-470)). |
| `kubernetes.hubble-drop-events-interval` | `120` | The same Pod, reason and message are written at most once per interval: seconds, or `90s`/`2m`/`1h`; 1 s to 24 h. |
| `kubernetes.hubble-drop-events-reasons` | `["auth_required","policy_denied"]` | The drop reasons that get an Event: `policy_denied` (no rule allows it), `policy_deny` (a deny rule) and `auth_required` (the allowing entry needs authentication). Any other name is refused at startup: the policy programs drop for no other reason. |
| `kubernetes.hubble-drop-events-extended` | `false` | The message also lists the policies applied to the Pod in that direction. |
| `kubernetes.hubble-drop-events-rate-limit` | `1` | At most this many Events a second, 0 for no limit. |
| `kubernetes.identity-allocation` | `true` | Watch Namespaces and FlowsdnIdentity objects and allocate cluster identities ([identities](#cluster-identities-291)). |
| `kubernetes.network-policy` | `true` | Watch NetworkPolicies (and Namespaces) and enforce them in the endpoint programs ([NetworkPolicy](#networkpolicy-enforcement-292)). |
| `kubernetes.policy-audit-mode` | `false` | Pod policy audit mode (#461; the reference's `policy-audit-mode`): Pod endpoints judge and count what their policy refuses (`audit` in `/v1/policy/verdicts`) but never drop it, and new endpoints are not quarantined. The host firewall's own audit mode is `host-firewall: audit`. |
| `kubernetes.flowsdn-policy` | `false` | Enforce the Pod rules of FlowsdnNetworkPolicy and FlowsdnClusterwideNetworkPolicy ([Pod rules](#pod-rules-of-the-flowsdn-policy-kinds-292)). The CRDs must exist: the policy thread waits for both lists, NetworkPolicy enforcement included. |
| `kubernetes.host-firewall` | `off` | `off`, `audit` or `enforce`: filter traffic to the node itself from FlowsdnClusterwideNetworkPolicy host rules ([host firewall](#host-firewall-379)); `audit` counts would-be drops and passes them. The stormcos Kubernetes-mode config sets `audit` (#402). |
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
are synced and nothing failed), as the controller's status probe last read it
every 5 s. Its status follows probe staleness (#456): 500 until every probe ran
once, `Warning` after 15 s without a probe result and 500 `Failure` after 60 s,
so a stuck controller fails the check instead of hanging it. `/healthz` and
`/readyz` do not exist (404). Module health (`/v1/health/modules`) is built
from the live state on each request: API and restore rows, and with Kubernetes
the controller and policy-map rows; every row change is kept in
`<state-dir>/flowsdn-agent-health-history.log` (10 MB, three files), read back
by `GET /v1/health/history` (see `docs/agent-api.md`). The config response's `ipam-mode: kubernetes` is a compatibility
value: allocation uses the configured pools, or with `auto` the pool resolved
from the Node at startup.

## Runtime behavior and shipping

Every line of the agent's log starts with its UTC time in milliseconds. `ready: serving
CNI requests <n> ms after start` marks when the endpoint API answers, after the BPF object
is loaded, endpoints are restored and, in Kubernetes mode, the pod pools are known.

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
  (Normal), `DirectRouteFailed`, `PodCIDRCollision`, `ServiceLBUnavailable` and
  `SysctlFailed` (Warning). Repeats of one object, reason and message are one Event with a
  growing `count`, rewritten at most once a minute and forgotten after an hour.
  Recording never blocks or fails a request: a full queue (256) drops events. Needs
  `events` create/update (the manifests and chart grant it);

- tags each local Pod with its network (#328): the `flowsdn.io/pod-networks`
  annotation (OVN-style: addresses, MAC, gateways, routes, interface, host
  interface, endpoint ID, sandbox, node; [API](agent-api.md#pod-network-annotation-328)),
  merge-patched within about 2 s of the endpoint's creation and rewritten if it
  is removed or edited. Beside it, flowsdn's entry in the Multus/NPWG
  `k8s.v1.cni.cncf.io/network-status` list (name `flowsdn`, interface, ips, mac,
  `default`; other plugins' entries kept; [API](agent-api.md#multus-network-status-371), #371). Needs `pods` patch (the manifests and chart grant it).
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
  after 1 s doubling to 30 s, keeping the last good snapshot; a 404, as for a CRD
  not served yet at boot, stays at 1 s for the watch's first minute and logs once,
  and a recovery logs `kubernetes <part>: listed`);
- with `auto-direct-node-routes`, owns `<podCIDR> via <InternalIP> proto
  kernel` routes in the main table for every other node's pod CIDRs, using the
  node's first InternalIP of the family. A node's pod CIDRs are its
  `spec.podCIDRs`; for a family whose pool is `auto` on this agent and which the
  Node has none of, the agent derives it by the same rule as that node's own
  agent (`10.<last IPv4 byte>.0.0/16`, `f00d::…/96`; #296, owner decision C:
  no operator or node IPAM needed). Two nodes whose pod CIDRs overlap (the same
  last IPv4 byte on different subnets, or a podCIDR inside a derived pool) get
  no route for the overlapping CIDRs, and the agent reports it: a
  `PodCIDRCollision` Event on its Node and the `pod-cidrs` healthz error,
  cleared when the collision goes. Refusing is chosen over routing pods to the
  wrong node. Before installing it checks that the kernel reaches
  the InternalIP without another gateway, and refuses to replace a route of
  another protocol to the same prefix. With several uplinks each path's
  InternalIP is checked, and only the directly reachable paths are installed;
  the first InternalIP is checked only for the plain route, used when no path
  is (#498). Installed routes are recorded in
  `<state-dir>/direct-routes.json` before they are added, so routes for nodes
  that left while the agent was down are deleted on the next reconcile. A
  stale route is deleted by destination (flowsdn's protocol-kernel route with
  a gateway or paths, whatever gateway it uses), never a route of another
  protocol (#498). It
  reconciles on every change of the desired set and every 30 s;
- with `service-lb` (default on), lists and watches Services and
  EndpointSlices and load balances ClusterIPs at the socket (below);
- with `identity-allocation` (default on), lists and watches Namespaces and
  FlowsdnIdentity objects and holds a cluster identity for each local Pod
  ([below](#cluster-identities-291));
- with `network-policy` (default on), lists and watches NetworkPolicies (and
  Namespaces) and enforces them in the endpoint programs
  ([below](#networkpolicy-enforcement-292));
- watches the node's uplink ports for its whole life and uses every one with
  carrier ([below](#several-uplinks-408));
- serves `GET /v1/ip`, `GET /v1/identity`, `GET /v1/node/routes`,
  `GET /v1/service` and `GET /v1/uplinks` ([API](agent-api.md)).

### Several uplinks (#408)

Owner's choice B (2026-11-13): routed, one address per port, no switch
configuration (no LACP, no bond). A thread, `flowsdn-uplinks`, runs every
500 ms for the agent's whole life.

**Which ports.** An uplink is any interface that holds one of the Node's
InternalIPs, or a global address on the subnet of one. Nothing names a port.
On forge1 that is `stormbr0` (.203, the bridged boot port) and the second 25G
port (.204, its own stormpump lease). A storage VLAN on another subnet, pod
veths and `lo` are not uplinks. They are ordered by `weight`, then the one
holding the first InternalIP, then ifindex. A down port that lost its address
keeps the last one the monitor saw. With one uplink, or `mode: single`,
nothing below happens and the routes are as before.

**Only carrier decides.** `/sys/class/net/<port>/carrier` is read every tick.
A port that gains carrier joins, one that loses it leaves; traffic,
thresholds or tests never decide. Each join or leave is a log line with its
UTC time (`uplink enp65s0f1np1 left: no carrier (192.168.16.204/20); 1 of 2
carrying`), a Node Event (`UplinkJoined` Normal, `UplinkLeft` Warning) and an
entry in the last 64 of `GET /v1/uplinks` `history`. A port may come and go
any number of times.

**Both carry (active-active, the default).**
- Each other node's pod CIDR is one per-flow ECMP route, protocol kernel in
  the main table, with one path per live uplink. Path k pairs the node's k-th
  InternalIP with the k-th live port (cycling the shorter list); a pair whose
  port is not on that address's subnet is dropped, and a live port left
  without a path takes the first InternalIP on its subnet (#499). Once peers
  publish both addresses (rustkube-node#366), traffic is spread over both
  ports at both ends. `GET /v1/node/routes` says `installed: 2 paths`.
- The kernel hashes per flow on the L4 tuple (`fib_multipath_hash_policy=1`,
  IPv4 and IPv6), so a flow is never reordered. `fib_multipath_use_neigh=1`
  skips an IPv4 path whose gateway does not answer ARP through that port: a
  port on another segment that reuses the subnet is not a blackhole.
- Source rules pin each node address to the port that holds it. Rule
  `priority+10+i` sends `from <addr> to <its subnet>` to table `table+1+i`
  (`<subnet> dev <port> src <addr>`). Rule `priority+50` is `lookup main
  suppress_prefixlength 0`, so every main-table route but the default still
  applies. Rule `priority+100+i` sends `from <addr>` to the same table, whose
  default route goes via the main default gateway over that port. Rule
  `priority+200` sends everything else to table `table`, an ECMP copy of the
  default route over the live ports; the main default stays as a fallback.
  Defaults: `table` 2080 and `priority` 9100. flowsdn owns tables
  2080–2112 and priorities 9100–9399, and nothing else: stormpump's lease,
  address, subnet route and default route are never touched.
- NodePort, LoadBalancer and externalIP programs, and the host firewall, are
  attached to every uplink.
- On each uplink: `arp_ignore=1` and `arp_announce=2` (each address is
  answered only on its own port, the same as stormpump's path NIC), and
  `rp_filter=0` (a reply may come back on the other port). Also
  `ignore_routes_with_linkdown=1` (also `all`) and IPv6 `ndisc_notify=1`.
  An uplink counts as tuned only once every write succeeded; a failed write
  is tried again each tick and stays in the `uplinks` error until it
  succeeds (#497).
  An address held on `lo` and answered over an uplink through ARP flux is no
  longer answered.

**A port leaves.** The kernel stops using its paths at once
(`ignore_routes_with_linkdown`). Within one tick, its addresses are added
as host addresses (`/32`, `/128`) on the most preferred live uplink on that
subnet, followed by three gratuitous ARPs (IPv6: three unsolicited Neighbor
Advertisements with the override flag to all nodes, #497; `ndisc_notify` only
announces on link or MAC changes).
Its source rules' tables point at that port, and the ECMP routes are
rewritten over the ports left. Peers keep reaching every node address.

**It returns.** The host addresses are removed, its own addresses are
announced from it with three gratuitous ARPs or unsolicited NAs, and the
routes spread over both ports again. The moved addresses are recorded in
`<state-dir>/uplink-moves.json`, so a restarted agent removes them when they
are no longer wanted. Only an address change that succeeded is recorded: a
failed add or removal stays in the `uplinks` error and is tried again each
tick until the host matches the plan (#497).

`mode: active-backup` carries the balanced routes on the most preferred live
uplink only. Failover is the same. `weights` (1–255, default 1) become path
weights and the preference order.

**Report.** `GET /v1/uplinks` gives each uplink's carrier, addresses and
physical ports (a bridge lists its members), and for each port its carrier,
speed, configured and active FEC (`ETHTOOL_GFECPARAM`, read every 5 s) and
rx/tx bytes. It also gives the failover host addresses and the history.
`/v1/healthz` `kubernetes.uplinks` is a one-line summary
(`2 of 2 uplinks carrying (stormbr0, enp65s0f1np1), active-active`). Failures
are in the `uplinks` healthz error.

Not done here: forge1 must run the flowsdn flavour (it is a cilium node), the
peers' second InternalIP is rustkube-node#366, NVMe/TCP multipath is
stormblock#596, and stormpump keeping the failover `/32` is stormpump#234.

### XDP prefilter (#467)

With `kubernetes.xdp-prefilter` (default off) the API thread attaches the
local-delivery object's `xdp_prefilter` program to every uplink with a
hardware address (native XDP where the driver has it, else generic; checked
every second as uplinks come and go) and serves its deny list at
`GET`/`PATCH`/`DELETE /v1/prefilter` ([agent API](agent-api.md)). A frame
whose IPv4 or IPv6 source is in the list is dropped before the stack sees it:
host prefixes in the `flowsdn_cidr_v{4,6}_fix` hash maps, other prefixes in
the `flowsdn_cidr_v{4,6}_dyn` LPM tries (1024 entries each). ARP, VLAN-tagged
and non-IP frames pass. Each change takes the current revision and
increments it, as the reference's prefilter does. The list is not
persisted: at start the maps are emptied and the revision is 1. Attach
failures are the `prefilter-attach` part error; `/v1/healthz`
`kubernetes.prefilter` lists the uplinks and their mode. `prefilter-live`
checks it on a kernel.

### Neighbor management (#469)

With `kubernetes.l2-neigh-discovery` (default off; spec 10 §3.4) the
`flowsdn-neighbors` thread keeps a kernel-managed neighbor entry
(`extern_learn managed`, `NUD_NONE`) for every next hop to another node, so
`bpf_redirect_neigh` and `bpf_fib_lookup` find it resolved instead of dropping
the first packets while the kernel resolves it.

- **Forwardable addresses**: every InternalIP of the other Nodes. (The
  reference also adds Service backends, for XDP acceleration only; flowsdn has
  no XDP acceleration.)
- **Devices**: the uplinks ([several uplinks](#several-uplinks-408)) with a
  hardware address.
- **Next hops**: `ip route get <address> oif <uplink> fibmatch` for every pair:
  the route's gateway, every gateway of a multipath route on that uplink, or
  the address itself on-link. No route on that uplink: no entry there
  (`unreachable` counts them).
- **Reconcile**: every next hop gets `ip neigh replace … extern_learn
  managed`; the kernel resolves it and keeps it fresh. Entries with
  `extern_learn` on those uplinks that are not next hops are deleted;
  entries without it (an administrator's) are never touched. It runs at
  start, on any change of the nodes' addresses or the uplinks (at most once
  per 15 s), and as a full resync every 5 minutes.
- **Start**: with the setting on, the agent first probes for managed
  neighbors (a veth pair in a throwaway network namespace gets a managed
  entry that must read back as managed). A kernel without them stops the
  agent, naming the setting; there is no fallback (#132).
- **Status**: `/v1/healthz` `kubernetes.neighbors`: `{enabled, devices,
  forwardable, desired, unreachable, pruned, last, errors}` (`null` when
  off); failures are the `neighbors` part error. `neighbors-live` checks it on
  a kernel (kernel-check).

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
is the operator's identity GC ([below](#crds-and-the-operator-337), #479). Remote Pods resolve to the oldest object with their
labels. The identities appear in `GET /v1/identity`, on Pod rows of
`GET /v1/ip`, and as `status.identity` and `pod.identity` of local endpoints.
They are not in BPF maps: nothing in the datapath consumes them until policy
(#292). Needs `flowsdnidentities` list/watch/create/update and `namespaces`
list/watch (the manifests and chart grant them) and the FlowsdnIdentity CRD
(stormcos#303 applies `crds/`); without the CRD the identity watch reports
an error in health and nothing is allocated.

Not yet: a flow/drop observer (the
`flowsdn-hubble` `endpoint` module names flow peers `ns/pod (container)` once
one exists, #293), BPF ipcache maps, tunnel routing, masquerade, and the L7/FQDN policy kinds. Unit tests and a loopback-HTTPS controller test cover the
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
LoadBalancer frontend, with every backend (only this node's with
`externalTrafficPolicy: Local`). Cluster IPs get one only with
`kubernetes.lb-external-clusterip` (#465), limited by `internalTrafficPolicy`
(`Local`: this node's backends), the policy Kubernetes applies to a cluster
IP. With `kubernetes.node-port` (default
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
a connection keeps its backend and NAT port. A NAT port's reservation is
renewed by every packet of its flow, in either direction, and expires after
6 h without traffic for TCP, 10 s after a FIN or RST, and 60 s for other
protocols (#488). A new flow that finds an expired reservation on the port
it tries takes it over, and the old flow's forward entry is dropped; a
known flow whose reservation another flow took starts again as a new flow.

#### BPF masquerade (#460)

With `kubernetes.bpf-masquerade: true` the services thread keeps two LPM maps
from the Node list: `flowsdn_masq4_sources` (this node's IPv4 pod CIDRs) and
`flowsdn_masq4_exclude` (every node's pod CIDRs and InternalIPs, and
`non-masquerade-cidrs`). At an uplink's TCX egress (`nodeport_egress`), a
packet from a source in the first to a destination in neither, TCP, UDP or an
ICMP echo request, leaves from the FIB's source address for that destination
on this uplink, and a NAT port (an echo: a NAT identifier) from the same
61000-65535 range, map (`flowsdn_nodeport4_nat`) and expiry as NodePort's SNAT
ports. A packet the FIB would send out of another uplink is left to that
uplink. At the ingress, the reply, an echo reply, and an ICMP destination
unreachable, time exceeded or parameter problem about such a TCP/UDP flow
(outer destination, embedded source address, port and header checksum, ICMP
checksum) are translated back to the Pod and passed to the host stack, so the
Pod's own programs judge them, and netfilter's conntrack sees the Pod's
address both ways. Fragments follow the IPv4 fragment table above. If the
node also masquerades (a netfilter rule), it does so before these programs
run and they see the node's address: turn the node's rule off to use this one.

IPv6 (#513) works the same way with `flowsdn_masq6_sources` (this node's IPv6 pod
CIDRs) and `flowsdn_masq6_exclude` (every node's IPv6 pod CIDRs and InternalIPs, and
the IPv6 `non-masquerade-cidrs`). TCP, UDP or an ICMPv6 echo request leaves from the
FIB's IPv6 source on this uplink and a NAT port (an echo: identifier) claimed in
`flowsdn_nodeport6_nat`. The reply, an echo reply, and an ICMPv6 destination
unreachable, packet too big, time exceeded or parameter problem about such a TCP/UDP
flow come back to the Pod through the host stack: outer destination, quoted source
address and port, and the ICMPv6 checksum with its pseudo-header. Only TCP/UDP/ICMPv6
right after the fixed header: a packet with extension headers, a fragment among them,
passes untouched. A destination in the RFC 6052 gateway's prefix (#454) goes to the
gateway, not the masquerade.

#### RFC 6052 gateway (#454)

With `kubernetes.nat46x64-gateway: true` the services thread writes the
prefix and this node's IPv6 pod CIDRs to `flowsdn_gw64_config` and
`flowsdn_gw64_sources`. At an uplink's TCX egress, an IPv6 TCP or UDP packet
from those CIDRs to the prefix is translated to IPv4: destination the address
in the prefix's last 32 bits, same port; source this node's address on that
uplink and a NAT port from the 61000-65535 range, claimed and kept as Service
NAT64 flows are. It is redirected out of the uplink. The IPv4 reply is
translated back to IPv6 from `prefix + server`, to the Pod. The node must route
the prefix out of an uplink (an IPv6 default route); a Pod reaches the
gateway like any IPv6 destination. ICMP and fragments are not translated;
reservations last until the LRU evicts them.
IPv4 fragments (#458): each first fragment (offset 0, more fragments) the
uplink programs see, in either direction, records its datagram's ports in the
LRU `flowsdn_nodeport4_frags` (8192 entries, by source, destination, IP ID
and protocol). A later fragment takes them from there and follows its
datagram's flow; only its IP header is rewritten (address and header
checksum), since the first fragment carries the L4 header and checksum. A
later fragment whose first was not seen, or whose datagram has no flow, passes
untouched. IPv6 fragments pass untouched.
So closed connections never hold the 4536 ports of a backend. NAT46/64 and RFC
6052 gateway reservations expire the same way (#494): the translation paths
renew them in both directions (and mark them closing on a FIN or RST), a
reclaimed NAT64 or gateway reservation takes its reply entry with it, and a
flow whose reservation was reclaimed is translated anew on its next packet. A packet the FIB cannot route,
with TTL 1, or for which no NAT port is free within eight tries passes
untranslated, and so does an IPv6 packet with extension headers before its
TCP/UDP header (fragments among them).
A new flow's backend is a random slot, or, for a Maglev frontend
(`kubernetes.lb-algorithm: maglev` or the Service's
`service.flowsdn.io/lb-algorithm: maglev` annotation; spec 05 §3.13), entry
`hash % 16381` of the frontend's lookup table: the hash is Linux jhash over
the client address, both ports and the protocol (the client port left out
with ClientIP affinity), so every node sends a flow to the same backend and
a backend change moves few flows. The agent builds each table (spec 05 §5.1,
16381 entries, fixed seeds so every node agrees) from the frontend's backends
and swaps it in whole as an inner map of `flowsdn_lb4_maglev` /
`flowsdn_lb6_maglev` (BTF hash of maps, keyed by service ID) after the
backends and before the master entry, which carries the algorithm. A Maglev
master without a table picks at random. The socket LB (clients inside the
cluster) always picks at random.
Other packets pass untouched; the only drop is a refused DSR option (below). `GET /v1/service` gives
each frontend's `flags.type` (`ClusterIP`, `ExternalIPs`, `LoadBalancer`,
`NodePort`) and `frontend-address.scope` (`external` for the socket LB's copy,
`node-local` for the uplink copy).
`internalTrafficPolicy: Local` limits a cluster IP to endpoints on this node;
`externalTrafficPolicy: Local` limits a NodePort on a node's address to that
node's endpoints (an empty set fails `connect`, as Kubernetes drops such
traffic). Backends are the addresses of the Service's
EndpointSlices of the same family on the slice port with the same name and
protocol, `ready` endpoints first, serving-terminating ones only when none is
ready. With traffic policy Cluster, ready endpoints are chosen by their
EndpointSlice hints as kube-proxy does (#459): when every one has
`hints.forNodes` and one names this node, those naming it
(`trafficDistribution: PreferSameNode`); else when every one has
`hints.forZones` and one names this node's `topology.kubernetes.io/zone`,
those naming it; else all of them. `Local` policies and the serving-terminating
fallback ignore hints. A services thread owns the maps. Once both lists are complete, on each
change and every 30 s, it reads the maps, plans the difference
(`flowsdn_lb::socket`: service IDs and backend IDs are kept from what the
maps hold, and new IDs never reuse a live one) and writes in spec 05 §3.4
order: backends, Maglev tables, slots, then the master entry that publishes
the new count, then stale masters, slots, tables and backends. A failed write is retried from the
kernel state on the next pass and reported in the `kubernetes` health member
(`services`; a socket LB that cannot load or attach is also a
`ServiceLBUnavailable` Node event, and ClusterIPs are then not handled).

With `bpf-pin-root` the maps and links are pinned under `<pin root>/socket-lb`.
A restarted agent reuses the maps (a pinned map with another layout refuses
startup), attaches its programs, then releases the old links. Without a pin
root the links detach when the agent exits. The NodePort uplink links are never
pinned: they detach when the agent exits, and the per-CPU
`flowsdn_nodeport6_fib`, `flowsdn_nodeport6_scratch` and
`flowsdn_nodeport4_xlate_scratch` scratch maps are not
pinned either. The socket LB picks backends at random: Maglev is for traffic
entering on the uplink only, as in the reference (#453); an existing TCP connection stays on its backend when it leaves unless
`kubernetes.lb-sock-terminate-all-protos` is on (#392, below); SCTP ports get no translation (#457); IPv6
fragments pass untouched. Local redirect policy and its skip-LB are
[below](#local-redirect-policy-565). `socket-lb-live` (medium test suite) checks the
programs on a kernel, including the NodePort local and SNAT paths through
`BPF_PROG_TEST_RUN` and Maglev picks against the planner's tables; no
two-node cluster run yet.

Socket termination (spec 05 §3.8, #292, #392): when a UDP backend leaves the
programmed services, the services thread finds the sockets the socket LB sent
to it (their cookies in `flowsdn_lb{4,6}_reverse_sk` with that backend) and
destroys them with netlink `SOCK_DESTROY` (`CONFIG_INET_DIAG_DESTROY`), so the
application's next call fails with `ECONNABORTED` and it reconnects to a live
backend (a CoreDNS restart, for example). It looks in the host network
namespace and in each local Pod's: the CNI passes the observed `CNI_NETNS`
(`/run/netns/<sandbox>` on stormcos, mounted into the agent with
HostToContainer propagation), and the agent enters it only when the
namespace's cookie equals the endpoint's. A failure (a namespace it cannot
enter, a kernel without `SOCK_DESTROY`) is a `socket-termination` error in
`GET /v1/healthz`. Removals come together in passes at most every 50 ms (a
rollout's backends leaving at once are one pass). At its first programming
after a start the agent also ends sockets to UDP backends that
`_reverse_sk` (pinned, so kept across restarts) remembers and no Service has
now: those backends left while it was down. With
`kubernetes.lb-sock-terminate-all-protos` (default false, the reference's
hidden option) a leaving TCP backend's connections are ended too (the
application sees `ECONNABORTED` or a reset): the socket LB records no TCP
translation, so every TCP connection to that backend address and port is
ended, a direct one included. TCP backends that left while the agent was down
are not known at start.

Without Kubernetes mode the agent does no Node/Pod discovery, installs no
remote routes and has no Service handling. The `local-delivery` object's uplink
ingress program is not attached in either mode (the NodePort programs above
are the `socket-lb` object's).

stormcos ships flowsdn as a **golden** containing the agent (`/flowsdn-agent`;
since golden-flowsdn-4e9e3f0bc876 the GNU Kubernetes-mode build with its Fedora
OpenSSL runtime, stormcos#171) and the static musl CNI (`/opt/cni/bin/flowsdn`). Nodes
clone goldens copy-on-write and mount it at `/pallets/flowsdn`; nothing is
pulled. The latest golden is `golden-flowsdn-760c3a2e89d6`, staged from
`9732b71` (NetworkPolicy enforcement, #292). The golden/release authority is
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

### Service NAT46/64

With `kubernetes.nat46x64: true` (default off; spec 04 §3.15), a frontend on the
uplink that has no backend of its own family and has backends of the other family
is translated: an IPv4 client reaches IPv6 backends (NAT46) and an
IPv6 client reaches IPv4 backends (NAT64). The usual case is a NodePort, externalIP
or LoadBalancer address of one family on a Service whose endpoints are the other's.
`nodeport_ingress` rewrites the header (`bpf_skb_change_proto`), always source-NATs
to this node's address of the backend's family on a port in 61000-65535, and
redirects by the FIB. A remote backend's reply is translated back at uplink ingress
and redirected to the client from the frontend. A backend on this node (#450) gets
the translated packet on its veth; its reply to this node's address would be local
input, so `nodeport_endpoint`, attached first on every local endpoint's veth ingress
while the setting is on (ahead of local-delivery, which it passes everything else),
translates it back the same way and sends it out of the uplink. Problems attaching
it are the `nat46x64-endpoints` controller error. `GET /v1/service` shows `nat-policy: Nat46` or
`Nat64`. IPv4-keyed flows are in `flowsdn_nodeport4_xlate` (64Ki entries), IPv6-keyed
ones in `flowsdn_nodeport6_nat`.

Limits:

- **Not with `externalTrafficPolicy: Local`.** Such a frontend is not translated:
  the backend would see this node's address, not the client's.
- **Client's address hidden, no DSR.** The backend sees this node's address. A local
  backend's NetworkPolicy judges the packet as from this node.
- **A local backend's reply skips local-delivery.** `nodeport_endpoint` redirects it
  before local-delivery's egress policy; it is the reply of a connection the pod's
  ingress policy admitted.
- **The socket LB translates IPv6 sockets only** (#542, as the reference does): a
  pod's or the host's IPv6 socket to `::ffff:<IPv4 frontend>` connects to its IPv6
  backend, and one to an IPv6 frontend with IPv4 backends connects to
  `::ffff:<backend>`; getpeername and UDP replies show the frontend. TCP and
  connected UDP only: the kernel sends an unconnected `sendto` to `::ffff:` down its
  IPv4 path, and refuses a sendmsg rewrite to `::ffff:`. An IPv4 socket to such a
  frontend fails with EPERM, since it cannot be pointed at an IPv6 backend. Sockets
  to a NAT64 frontend's IPv4 backend are not ended when that backend leaves
  (termination matches IPv6 entries by IPv6 address). Pod traffic to IPv4 by an
  RFC 6052 address is the gateway below (#454).
- **Passes untouched, with no ICMP error:** IPv4 options, a fragment, UDP without a
  checksum (IPv6 requires one), TTL 1, a packet too big for the device once translated
  (an IPv4 packet grows by 20 bytes). TCP is not affected by that last one in practice:
  an IPv6 peer's MSS already allows for the larger header.
- A frontend removed while a NAT46 flow lives stops that flow, unlike untranslated
  flows, which keep going from their map entries.

Verified by kernel test runs only (`socket-lb-live`); it has not carried traffic
between two nodes.

### Direct server return

With `kubernetes.lb-mode: dsr` or `hybrid`, or a Service's
`service.flowsdn.io/forwarding-mode: dsr` annotation (spec 05 §3.12), a backend
on another node sees the client's own address and answers it directly. The
uplink's `nodeport_ingress` DNATs the packet, keeps its source, and on a TCP SYN
or a UDP packet adds the frontend as an option (spec 02 §2.5: IPv4 option `0x9a`,
IPv6 24-byte Destination Options type `0x1B`), then redirects it by the FIB. On
the backend's node `nodeport_ingress` records the frontend from the option, and
`nodeport_egress` rewrites the reply's source to it. It accepts an option
only when the frontend it names is a DSR frontend on this node too and the
packet's destination is one of that frontend's backends (at most the first
256 checked); any other option drops the packet, so a forged one cannot set a
reply's source (#488). The client's source cannot vouch for the node that
added the option. `GET /v1/service` shows `forwarding-mode: dsr`.

Every node on the path must run these programs and the network must carry a
reply whose source is the frontend. `kubernetes.lb-dsr-dispatch` (#447) picks how
the frontend travels, on the same packets (a TCP SYN, a UDP packet that fits):

- `opt` (default): the option above.
- `ipip`: the client's packet as it came, to the frontend, inside an outer IPv4
  (protocol 4) or IPv6 (next header 41) header from this node's address to the
  backend. The backend's node accepts it when the inner destination is a DSR
  frontend and the outer destination one of its backends, strips the outer
  header, DNATs the packet to that backend (with the backend's port) and
  records the frontend.
- `geneve`: the DNATed packet, in Ethernet, in Geneve (VNI 2, the DSR option:
  class `0x014b`, type `0x81`, the frontend) over UDP 6081 to the FIB's next hop,
  the backend's node. Its UDP checksum is zero, IPv6 included: the receiving
  program takes the packet before the stack. The backend's node checks the
  frontend and destination as for the option, then strips everything before the
  inner IP header.

Nothing on either node is a kernel tunnel device, and routing is unchanged. A
node accepts all three modes whatever its own setting, so changing it node by
node does not break flows; an encapsulated packet that fails the check drops,
one that is not DSR (an inner destination that is no DSR frontend, Geneve
without the DSR option) goes on untouched. The room each mode adds (option 8 /
24 bytes, IPIP 20 / 40, Geneve 62 / 94 for IPv4 / IPv6) decides which UDP packets
still fit the MTU.

A new flow whose first packet cannot carry the frontend (UDP that the added
bytes would push over the device's MTU, an IPv4 header with options already, a
TCP segment that is not a SYN) is source-NATed like an SNAT flow instead (#488),
so its reply still comes back through this node. A later UDP packet of a DSR
flow that would go over the MTU is sent DNATed without it; the backend's node
already has the frontend. Verified by kernel test runs only (`socket-lb-live`); it has not
carried traffic between two nodes.

ICMP and ICMPv6 errors about DSR flows, and about flows to a node-local backend, are
translated (#449), since a client matches an error to its connection by the
packet the error quotes. Errors handled: destination unreachable (with
fragmentation needed and packet too big), time exceeded and parameter problem,
quoting TCP or UDP.
- **Backend's node, `nodeport_egress`:** an error about the client's packet (quoted as the backend got
it, with the DSR option or Destination Options header) leaves quoting the
frontend. Its source becomes the frontend too when the backend sent it. A router's error keeps the
router's source.
- **Frontend's node, `nodeport_ingress`:** an error a client sends about a reply
from the frontend goes to the backend, with its destination and the quote's
source rewritten. A DSR flow's error is redirected toward the backend's node like the flow's
packets; a local one goes to the stack.
- **Source-NATed flows (#534), frontend's node, `nodeport_ingress`:** an error the backend's side sends
about a forwarded packet (to this node's NAT address, quoting `nat:natport -> backend`) goes to the
client quoting `client -> frontend`, from the frontend when the backend sent it. A client's error about
a reply goes to the backend as an error about the packet it sent (`backend -> nat:natport`), from this
node's NAT address, while the flow's NAT reservation still names that client. Both are redirected by the
FIB, TTL or hop limit lowered.

The quote's IP header checksum and the ICMP
checksum are kept right. The quoted TCP/UDP checksum is left alone: a quote may be cut short, and receivers do
not check it.

### CRDs and the operator (#337)

- **The operator** is `flowsdn-agent operator` (Kubernetes builds; the
  stormcos edition runs it as the host-network Deployment
  `kube-system/flowsdn-operator`, `64-flowsdn-operator.yaml`). It holds the
  Lease `kube-system/flowsdn-operator` (30 s) and, while leading, registers
  the 22 flowsdn.io CRDs at once and every five minutes (spec 13 §3.2):
  `GET`; absent: `POST` (409 is success); present without a schema or with
  an older `io.flowsdn.k8s.crd.schema.version` label: `PUT` this build's
  labels and spec (409: re-read and retry, 500 ms for up to 60 s); a newer
  label is left alone. Then it waits up to 60 s for `Established=True`.
  `NamesAccepted=False` exits the operator naming the CRD; other failures
  are retried after 30 s. The payloads are the generated `crds/` files,
  embedded in the binary. `--skip-crd-creation` leaves the CRDs to an
  administrator (the Helm chart installs its `crds/`).
- **Identity GC** (#479, spec 03 §3.6), every `--identity-gc-interval`
  seconds (900; 0 turns it off) while leading. It lists FlowsdnIdentities,
  FlowsdnEndpoints and, when served, FlowsdnEndpointSlices. An identity is
  in use when an endpoint's `status.identity.id` (or a slice entry's `id`)
  names it; its lifesign is renewed then, and whenever its resourceVersion
  changed since the last list (an agent acquired it). One in the term's
  first list counts from the operator's start, so a new leader waits a whole
  timeout. Unused for more than `--identity-heartbeat-timeout` (1800 s):
  the first run sets `io.flowsdn.heartbeat` (a `PUT`, which itself renews
  the lifesign); a later run, unused a further timeout and still marked,
  deletes it with preconditions `{uid, resourceVersion}`. An agent that
  takes the identity again removes the annotation, which stops it; a 409 or
  404 is skipped. At most `--identity-gc-rate-limit` deletes (2500) per
  `--identity-gc-rate-interval` (60 s); the rest wait for the next run, so
  the loop keeps renewing the Lease. A list that fails writes nothing; the
  run is retried after 30 s. There is no FlowsdnEndpoint GC: endpoints are
  owned by their Pods and go with them.
- **FlowsdnNode GC** (#479, spec 12 §3.9), every `--nodes-gc-interval`
  seconds (300; 0 off). A FlowsdnNode with no ownerReferences, without
  `flowsdn.io/do-not-gc: true` (any case) and with no Node of its name is a
  candidate; still one a whole interval later, it is deleted (404 is
  success). A Node that comes back ends the candidacy. The agents' own
  FlowsdnNodes are owned by their Node and go with it, so this catches
  objects written without an owner.
- Both collectors log only when they change something, and keep their
  memory for one leader term.
- **The agent's gate.** Before any flowsdn.io watcher starts (identities,
  LB pools, L2 policies, the policy kinds), the agent lists the CRDs as
  metadata only (`PartialObjectMetadataList`) every second until every CRD
  its configuration uses exists: FlowsdnIdentity with
  `identity-allocation`, FlowsdnLoadBalancerIPPool with LB-IPAM,
  FlowsdnL2AnnouncementPolicy with L2 announcements,
  FlowsdnNetworkPolicy with `flowsdn-policy`,
  FlowsdnClusterwideNetworkPolicy with it or the host firewall,
  FlowsdnEndpoint with `endpoint-crd`, FlowsdnNode with `node-crd`. Node,
  Pod and Service watches do not wait. While it waits, `crds` is a part
  error naming the missing ones; after `kubernetes.crd-wait-timeout`
  (300 s) the agent exits with that list (the kubelet restarts it).

### FlowsdnEndpoint and FlowsdnNode (#332)

The Kubernetes-mode agent publishes its endpoints and its node as
`flowsdn.io/v1alpha1` objects, from a `flowsdn-crds` thread every 2 s
(`flowsdn_agent::endpoint_crd`, `node_crd`; types in `flowsdn_k8s::kinds`).

- **FlowsdnEndpoint**, one per local Pod endpoint (not host-network Pods),
  in the Pod's namespace and named after it, owned by the Pod
  (`controller: true`), so Kubernetes deletes it with the Pod. `status`:
  `id`, `state` (`ready`, or `waiting-for-identity` while allocation has
  none), `service-account`, `identity` (`id`, `labels`), `networking`
  (`node`: this node's first InternalIP; `addressing`: the endpoint's IPv4
  and IPv6), `named-ports`, `external-identifiers` (`container-id`: the
  sandbox, `cni-attachment-id`: `<sandbox>:<interface>`, `k8s-namespace`,
  `k8s-pod-name`, `pod-name`) and `policy` (`ingress`/`egress` `enforcing`
  and `state`, from the policy thread). The Pod's workload and containers
  (#328) have no field in the schema; they stay on `/v1/endpoint` and the
  Pod's `flowsdn.io/pod-networks`. Created with `POST`; a status change is a
  JSON patch whose first op tests the object's UID (spec 13 §3.9), so a
  replaced object is never overwritten; deleted (UID precondition) when the
  endpoint goes, retried every pass until the server deletes it or finds it
  gone or replaced (#551); a new Pod of the same name gets its object after
  that. An existing object of the same name is adopted when the
  same Pod owns it (an agent restart) and replaced otherwise. A write the
  server refuses is a `flowsdn-endpoints` part error and a
  `FlowsdnEndpointFailed` Warning Event on the Pod.
- **FlowsdnNode**, cluster-scoped, named after the Node and owned by it,
  with its labels; `spec.addresses` (InternalIPs), `spec.ipam.podCIDRs` (the
  Node's pod CIDRs, or the ones this agent derives, #296) and `spec.bootid`;
  `status.ipam.used` maps each local endpoint address to its
  `<namespace>/<pod>`. Read, then created (`POST`), replaced (`PUT` with the
  read resourceVersion) when labels, owner or spec differ, and its status
  written through `/status`; left alone for 5 minutes while unchanged. A
  refused write is the `flowsdn-node` part error.
- **Not served.** Until the CRDs are applied (stormcos#303) a create gets
  404: the writer logs it once, retries every minute, and it is not an
  error. `/v1/healthz` shows `flowsdn-endpoints` (`served`, `objects`) and
  `flowsdn-node` (`served`).
- **Elsewhere.** A removed Node's FlowsdnNode goes with it (owner), and
  unowned ones and unused FlowsdnIdentities are the operator's GC
  ([above](#crds-and-the-operator-337)). Nothing writes FlowsdnEndpointSlices:
  agents read remote Pods from their Pod watch, so slices would have no reader
  (decided on #479). FlowsdnNodeConfig: [below](#per-node-settings-flowsdnnodeconfig-480).

### Per-node settings: FlowsdnNodeConfig (#480)

A FlowsdnNodeConfig in the agent's namespace (`POD_NAMESPACE`, else
`kube-system`) whose `spec.nodeSelector` matches this Node's labels
overrides this agent's own settings with its `spec.defaults`: each key is a
setting of this page, dotted for the `kubernetes` section
(`kubernetes.host-firewall: enforce`). The value is taken as JSON when it
parses (`"true"`, `"1400"`, `'{"mode":"single"}'`) and as text otherwise.

- **Which keys.** `egress`, `device-mtu`, `route-mtu`, `ipv4-pool`,
  `ipv6-pool`, `ipv4-gateway`, `ipv6-gateway`, and the `kubernetes` settings
  `auto-direct-node-routes`, `direct-routing-skip-unreachable`,
  `service-lb`, `node-port`, `lb-algorithm`, `lb-mode`, `lb-dsr-dispatch`, `nat46x64`,
  `lb-external-clusterip`, `policy-audit-mode`,
  `lb-ipam`, `l2-announcements`, `identity-allocation`, `network-policy`,
  `flowsdn-policy`, `host-firewall`, `uplinks`, `endpoint-crd`, `node-crd`,
  `crd-wait-timeout`, `lb-sock-terminate-all-protos`. Not the paths the
  manifest mounts (`socket-path`, `state-dir`, …), `node-name`,
  `kubeconfig`, `cgroup-root` or the cluster-wide `cluster-name`; the
  reference's own option names (`enable-…`) are not flowsdn settings.
- **When.** Read once at agent start, after the configuration file and
  before anything else; a change takes effect at the agent's next start, as
  the reference's do. Several selecting configs apply in name order, a later
  one overriding an earlier one's key. While the kind is not served there
  is none. The agent retries reading the Node and the configs for 60 s,
  then exits.
- **Refusals.** A config's keys apply together when the configuration
  parses with all of them (a pool and its gateway are valid only as a
  pair); otherwise each one that keeps it valid applies. A key not in the
  list, a value that makes the configuration invalid, a non-string value or
  a bad `nodeSelector` is refused: logged and a `NodeConfigRefused` Warning
  Event on the Node. Nothing refused stops the agent.
- **Status.** `kubernetes.node-config` in `/v1/healthz`: `selected`
  configs, `applied` (key → config) and `refused` (config, key, reason).
  The live ConfigMap is not changed.

### LoadBalancer Services (#475)

A `type: LoadBalancer` Service gets its address from flowsdn and is reached
from the node's LAN without a router or BGP. Three parts, all in the
Kubernetes-mode agent (the operator registers CRDs and collects garbage, #337, #479):

- **LB-IPAM** (`kubernetes.lb-ipam`). One agent at a time holds the Lease
  `kube-system/flowsdn-lb-ipam` (taken over when its holder stops renewing for
  15 s, measured by the taker's own clock) and writes; every agent plans the
  same and shows it in `GET /v1/lb-ipam`. Addresses come from
  FlowsdnLoadBalancerIPPools: `blocks` of `cidr` or `start`/`stop` (no `stop`:
  one address), `allowFirstLastIPs: "No"` keeps a CIDR's first and last
  address back (not /31, /32, /127, /128), `disabled: true` gives no new
  addresses but keeps those given, and `serviceSelector` matches the
  Service's labels plus `io.kubernetes.service.namespace` and
  `io.kubernetes.service.name`. A pool overlapping an older one is not used
  (`flowsdn.io/PoolConflict` True); one with a block or selector that does not
  parse is not used (`flowsdn.io/IPsAvailable` False, `InvalidPool`). Otherwise
  `flowsdn.io/IPsAvailable` carries the free count. A Service with no
  `loadBalancerClass` or `io.flowsdn/l2-announcer` gets one address per
  `spec.ipFamilies` family (default IPv4), the lowest free one of the first
  matching pool by name, or exactly the addresses it asks for in the
  `lbipam.flowsdn.io/ips` annotation (comma separated) or
  `spec.loadBalancerIP`. It is written to `status.loadBalancer.ingress[].ip`
  by a merge patch guarded by the Service's resourceVersion. A Service keeps
  its address while a matching pool holds it; of two Services with one
  address the older keeps it. A deleted Service's address is free once it is
  gone; a Service that stops being a LoadBalancer loses its pool addresses.
  Why a Service has fewer addresses than it asks for is in
  `GET /v1/lb-ipam` (`problem`) and the agent log (`lb-ipam: ns/name -> [...]`).
- **L2 announcement** (`kubernetes.l2-announcements`). A
  FlowsdnL2AnnouncementPolicy selects Services (`serviceSelector`, the same
  two naming labels) and nodes (`nodeSelector`), and announces their ingress
  addresses with `loadBalancerIPs: true` and their `spec.externalIPs` with
  `externalIPs: true` (both default false). One node answers for a Service:
  the holder of its Lease `kube-system/flowsdn-l2announce-<namespace>-<name>`
  (15 s, renewed every 2 s), for which only eligible nodes contend (#549):
  Ready, selected by a selecting policy, with an interface to answer on (see
  below), and with `externalTrafficPolicy: Local` a ready endpoint of the
  Service. A node that stops being eligible (not Ready, its last endpoint
  gone, no matching interface) gives the Lease up and another eligible node
  takes it within about 2 s; a node whose agent stops renewing loses it after
  15 s. The new holder takes over with three gratuitous ARPs or unsolicited
  Neighbor Advertisements, one a second. Once a minute the agents delete
  announcement Leases with no holder or not renewed for that minute.
  Lease problems are the `l2-leases` entry of the controller errors. The address is never
  added to the host: an AF_PACKET socket per interface answers ARP requests,
  and one with a classic BPF filter answers Neighbor Solicitations (it joins
  each address's solicited-node group; duplicate address detection is not
  answered). Interfaces are those a policy's `interfaces` regular expressions
  match, else the uplinks with carrier on the address's subnet, else every
  uplink with carrier. `GET /v1/l2-announcements` lists what this node
  answers for.
- **Datapath**: the uplink programs serve a Service's ingress addresses
  like its NodePorts ([socket LB](#clusterip-socket-lb-292)): every backend
  (other nodes' through SNAT, or DSR), or with `externalTrafficPolicy: Local`
  this node's only, keeping the client's address.

In L2 mode one node receives a Service's traffic. With
`externalTrafficPolicy: Local` that node's endpoints serve it, so endpoints
on other nodes get none of it; spread over every endpoint needs
`externalTrafficPolicy: Cluster` (with `lb-mode: dsr` to keep the client's
address). A pool and a policy for a LAN are in
[deploy/stormcos/README.md](../deploy/stormcos/README.md#loadbalancer-services).

Verified by unit tests, the loopback API-server test (Lease taken, Service
status patched) and the `l2-announce-live` kernel run (another namespace's
kernel resolves the addresses to the answering interface, and an unsolicited
NA moves its entry to another MAC); it has not served a
Service on a node yet.

### Local redirect policy (#565)

With `kubernetes.local-redirect-policy` (default off; needs `service-lb`) the
agent watches FlowsdnLocalRedirectPolicies (spec 05 §3.9) and redirects
their frontends to this node's Pods in the socket LB:

- **Backends.** This node's Ready, non-host-network Pods in the policy's
  namespace that `redirectBackend.localEndpointSelector` selects, on the
  container ports `redirectBackend.toPorts` names (the Pod must declare the
  port). A frontend port pairs with a backend port when each side has one
  (same protocol); otherwise by name, and every port must then be named.
- **`serviceMatcher`.** Each ClusterIP frontend of the Service (all its ports,
  or the `toPorts` given) whose port pairs goes to the local backends, marked
  `LOCAL_REDIRECT`. With no local backend the Service keeps its own.
- **`addressMatcher`.** A new frontend at `ip:port` for each port, only while
  it has a local backend. An address a Service already serves is refused.
- **`skipRedirectFromBackend`.** Each backend Pod's network namespace cookie
  goes in `flowsdn_skip_lb{4,6}` (1024 entries each) with the frontend's
  address and port. A socket from that namespace is not redirected. flowsdn
  translates Pods' Service traffic only in the socket LB, so for a
  `serviceMatcher` it gets the Service's own backends (a copy of the frontend
  at scope 2), and for an `addressMatcher` it is not translated. A Pod's
  cookie comes from its endpoint, so a backend gets its skip entry once its
  endpoint exists.
- **Validation and status.** An invalid policy (both or neither matcher, a
  `serviceMatcher` in another namespace, a bad address, port or protocol,
  unnamed ports where several are given) does nothing. `status.ok` says
  whether it is valid: every agent agrees, and one writes it where it
  differs. `GET /v1/lrp` lists the policies, why one is refused, and the
  frontends this node redirects.

The agent re-plans every 2 s (a Pod becoming Ready, an endpoint created).
The reference's `lrp-address-matcher-cidrs` restriction is not read.
`socket-lb-live` checks redirected connects, a Service's own backends after
skip-LB, and no translation after skip-LB, on a kernel. There is no cluster
run yet.

### L7 proxy core (#577)

ADR-0024 step 1, the base the L7 features build on (DNS #536, HTTP #537,
Ingress #578). Nothing in the agent opens a proxy port yet, so this is not
active on a node.

- **Datapath.** An endpoint's egress TCP flow that its policy allows through
  an entry with a proxy port goes to the proxy. `local_delivery` marks the
  packet `0x200 | port << 16` and assigns its first packet to the proxy's
  transparent listener (`bpf_sk_assign`, the listener looked up on loopback).
  The flow's entry in `flowsdn_policy_ct` remembers the port, so every later
  packet is marked too. The packet goes to the stack, and the ip rule
  `pref 9 fwmark 0x200/0xf00 lookup 2004` with `local default dev lo` in table
  2004 delivers it locally. With no listener on the port the packet is
  dropped (fail closed). BPF only: there are no nftables `tproxy` rules.
- **`flowsdn-l7`.** It provides:
  - transparent listeners, where an accepted connection's local address is the
    original destination and its source identity comes from the ipcache;
  - proxy ports (10000–20000), with the requested port when free, reference
    counts, a 5-minute reuse delay and `proxy-ports.json` persistence (a file
    older than 15 minutes is ignored);
  - the rule and route above;
  - the L7 record that becomes an L7 flow.
- **Not yet:** the ingress-direction redirect (traffic into an endpoint),
  Service `l7_lb_proxy_port` redirects and the upstream leg's marks (#582). `proxy-live` (medium suite) checks the
  egress path on a kernel.

### Egress gateway (#564)

With `kubernetes.egress-gateway` (default off; needs `bpf-masquerade` and
`service-lb`) the agent watches FlowsdnEgressGatewayPolicies (spec 14 §3.4)
and keeps `flowsdn_egress_gw_policy_v4` planned, re-planning every second:

- **Sources.** Pods with an IPv4 address that a `selectors[]` entry's
  namespace selector (on the Namespace's labels) and Pod selector both
  select. Every entry's `nodeSelector` forms one list the Pod's node must
  match, as in the reference.
- **Gateway.** The first node in name order that the gateway's `nodeSelector`
  selects, by its IPv4 InternalIP. With `egressGateways`, each Pod gets one of
  the resolved gateways by FNV-1a of its UID (a node joining or leaving
  reshuffles them, as upstream). With none resolved, the Pod's matching
  traffic is dropped, never sent from its own node.
- **Egress address,** on the gateway node: the `interface`'s first IPv4,
  else `egressIP` (it must be on one of the node's interfaces; the FIB picks
  the device), else the first IPv4 of the uplink holding the node's address.
  Its interface gets loose `rp_filter`. If none can be found, the gateway
  drops the traffic. Addresses are read again on every pass.
- **Datapath (native routing).** On the Pod's node the uplink's egress
  program sends the packet unchanged to the gateway node, its next hop
  (`bpf_redirect_neigh`). There is no tunnel, so the nodes must share a
  segment, as direct node routes already require. On the gateway the packet is
  forwarded to its uplink, whose egress program source-NATs it to the egress
  address with a NAT port from BPF masquerade's range. The reply is reverse
  translated there and routed back to the Pod's node. `excludedCIDRs` are
  passed on as if no policy matched.

IPv4 only. IPv6 sources and destinations are counted in
`GET /v1/egress-gateway` (`ipv6-skipped`) but not programmed. There is no
policy status and no gateway health check (spec 14 §3.4.10). Kernel checks
cover both nodes' halves (`socket-lb-live` `egress_gateway`). There is no
two-node cluster run yet.

### NetworkPolicy enforcement (#292)

Until the FlowsdnIdentity list first succeeds, `podSelector` peers allow nothing while isolation already applies, so traffic a policy allows from a selected peer is dropped (#401). `ipBlock` peers and policies with no peers are not affected.

Kubernetes `networking.k8s.io/v1` NetworkPolicy, enforced in the datapath
([ADR-0021](decisions/0021-endpoint-policy-datapath.md)). The `local-delivery`
object has two programs on each endpoint's host-side veth: `local_delivery` on
its ingress (traffic leaving the Pod: the Pod's egress policy, then delivery or
the host stack) and `to_container` on its egress (traffic into the Pod: its
ingress policy). Both read:

- `flowsdn_policy_ep` (host interface index -> endpoint ID and the enforced
  directions): an endpoint without an entry is neither enforced nor tracked;
- `flowsdn_ipcache` (LPM, address -> identity): every Pod IP with an identity,
  this node's InternalIPs and router addresses (host, 1), each of other
  nodes' InternalIPs with an identity of its own (`2<<24 | n`, numbered in
  address order; the datapath aggregates them to remote-node, 14, so
  `remote-node` and `cluster` rules cover them, #490), and one local identity
  (`1<<24 | n`) per `ipBlock`/host-rule prefix and exception. An `ipBlock`
  selects exactly the node addresses inside it, never every node for one.
  Anything else is world;
- `flowsdn_policy` (LPM): spec 06 §4.4 policy keys and entries behind a 32-bit
  endpoint ID, looked up as spec 02 §3.10 says (the identity, its aggregate,
  then the wildcard identity 0);
- `flowsdn_policy_ct` (LRU, 65536): flows an enforcing program allowed, with
  the direction. A packet of a known flow, or the reply of a flow allowed in
  the other direction, passes without a policy lookup. TCP lives 6 h without
  traffic (10 s after a FIN or RST), anything else 60 s.

Always passed: non-IP frames (ARP), IPv6 neighbour/router discovery, ICMP
fragmentation-needed and IPv6 packet-too-big, and traffic into a Pod from the
node itself (kubelet probes). Where enforced, fragments other than the first
(and IPv6 fragments) and malformed IP headers are dropped.

**New endpoints start isolated** (#489). With `network-policy` or
`flowsdn-policy` on (and the policy maps shared, so the policy thread runs),
the endpoint manager writes a quarantine row for a new endpoint before its
programs attach: both directions enforced with no entries and the flag bit
`8`, which the datapath ignores. So from its first packet the Pod sends and
receives only what is always passed (the node's own traffic to it, ARP,
neighbour discovery). The policy thread replaces the row with the Pod's own
once it knows the Pod and its labels, a tracking row when no policy selects
the Pod (#462); until then (the lists not complete, the Pod not yet in the watch, a
first list that never succeeds) the quarantine stays. Its sweep never removes
a quarantine row of an endpoint it has not seen yet. Endpoints restored at
agent start keep their pinned row (or get theirs from the policy thread).
`policy.quarantined` in `/v1/healthz` lists the endpoint IDs still isolated.
`cni-runtime` checks it on a kernel with real CNI ADDs.

The policy thread compiles, every second once the NetworkPolicy, Pod, Node and
Namespace lists are complete and the endpoints are published:

- a local Pod is enforced in a direction when a NetworkPolicy selects it for
  that direction (its identity labels, computed from the Pod and Namespace, so
  enforcement does not wait for the identity allocator);
- each rule's peers resolve to identities: `podSelector`/`namespaceSelector`
  peers against every identity's labels (so they need `identity-allocation`),
  no `from`/`to` to the wildcard identity, `ipBlock` to the CIDR identities it
  covers minus its exceptions, plus the host when one of its addresses is
  inside it and each remote node address inside it; ports to masked LPM
  blocks (spec 06 §5.2), named ports to the Pod's container ports (ingress)
  or, on egress, per destination identity whose Pods all map the name to the
  same ports (never as a port open to every destination: a peer-less rule
  names the identities of the Pods that declare it; Pods of one identity
  that disagree get nothing and a `policy` problem, #490);
- the maps are brought to the result when it changes and every minute,
  compared with what the kernel holds: entries and ipcache before enforcement,
  removals last.

With a pin root the four maps are pinned beside `flowsdn_lxc`, so enforcement
and tracked flows survive an agent restart. `GET /v1/healthz` reports
`network-policy` and `policy` (enforced endpoints, ipcache size, problems)
under `kubernetes`; a policy that cannot be enforced as written (a rule the
importer refuses, an invalid `ipBlock`) is a `policy` problem and allows
nothing. Isolation applies as soon as the Pod and Namespace lists are in, but
selector peers (`podSelector`/`namespaceSelector`, `from/toEndpoints`) resolve
against the FlowsdnIdentity list: until it succeeds they match nothing, so a
selected Pod stays default deny for that traffic (fail closed; a selector deny
denies nothing meanwhile). This is reported as the `policy` problem
`identities not listed yet (flowsdnidentities.flowsdn.io): … in <policies>`,
which also turns the `kubernetes` health to Warning (#401). If it persists,
check `kubectl get crd flowsdnidentities.flowsdn.io` (stormcos#303). `ipBlock`
peers and policies without peers do not wait. Each decision of an enforcing program (a rule allowed a new flow, a
drop, an audit pass) is counted in `flowsdn_policy_verdicts` (LRU per-CPU,
16384 rows): `GET /v1/policy/verdicts`. Deny and entity rules for Pods come
from the flowsdn policy kinds (below). With `kubernetes.policy-audit-mode:
true` (#461) every enforced Pod row also carries the AUDIT flag: what its
policy refuses (default deny, a deny rule) passes and is counted as `audit` in
`/v1/policy/verdicts`, and new endpoints are not quarantined (an unknown Pod's
row is audit too). `policy.audit` in `/v1/healthz` says which mode is on. A Pod no policy selects keeps a tracking row
(flags 0, #462): nothing is judged but its flows are remembered, so a
connection open when a policy first selects the Pod keeps working (its
replies and later packets pass as remembered flows; only new flows are
judged). Flows idle past their lifetime, or opened before the agent first
wrote the row, are not remembered. `policy.tracking` in `/v1/healthz` lists
these endpoints. An ICMP or ICMPv6 error
(destination unreachable, time exceeded, parameter problem) whose embedded
packet was sent by its destination and belongs to a remembered flow, in either
direction, is related traffic: it passes without a policy lookup and does not
refresh the flow (#463). One about no remembered flow is judged as new ICMP
traffic. Fragmentation-needed and packet-too-big always pass. Each counted
decision is also an event in the `flowsdn_policy_events` ring buffer (256 KiB,
#452): time, endpoint, direction, verdict, remote identity, interface and the
packet's tuple. The agent reads it every 100 ms, keeps the newest 4096 and
serves them at `GET /v1/policy/events` (a full buffer only loses events, the
counts stay), and as flow records with both sides named (Pod, node or reserved
peer) at `GET /v1/flows` (#485, for the console's Flows tab).

ICMP type rules (#448, spec 06 §3.2.6) work in Pod and host rules, allow and deny. An
`icmps[].fields[]` entry (`family` IPv4, the default, or IPv6; `type` a number or the
reference's frozen name such as `EchoRequest`) is a port rule of protocol ICMP or
ICMPv6 whose port is the type. The datapath judges an ICMP/ICMPv6 packet with its
type as the port, always: the reference's `enable-icmp-rules` defaults to true, and
there is no setting. A protocol-only ICMP rule still allows every type. Policy verdict
counts of ICMP are per type. A rule that combines `icmps` with `toPorts`, has more than
40 fields, or names an unknown type or family is skipped and reported. L7 HTTP/Kafka
rules (#537) and `toFQDNs`/DNS rules (#536) are gaps, each an issue.
`policy-live` (medium test suite) checks the programs
on a kernel through `BPF_PROG_TEST_RUN`; no cluster run yet.

### PacketDrop Events (#470)

Each drop event says why the policy refused the packet: `policy_denied` (no rule allows
it), `policy_deny` (a deny rule) or `auth_required` (the allowing entry needs
authentication, which the datapath does not do). A malformed packet or a later fragment
has no reason. With `kubernetes.hubble-drop-events`, the agent turns the drops of local
Pods' traffic whose reason is listed into a Warning Event `PacketDrop` on the Pod. An
ingress drop goes on the destination Pod, an egress drop on the source Pod. The message is
the reference's: `Incoming packet dropped (policy_denied) from shop/client (10.1.0.9)
TCP/80.` or `Outgoing packet dropped (policy_denied) to world (198.51.100.9) UDP/53.`. A
peer is `namespace/pod (ip)`, a reserved identity's name and address, or the address.
With `-extended` it adds `Applied policies: NetworkPolicy/a,FlowsdnNetworkPolicy/b.` and
`Applied clusterwide policies: …`, the policies that select the Pod in that direction (the
reference lists the denying policy instead when it can correlate one; flowsdn cannot).
One Event per Pod, reason and message per interval, and at most `-rate-limit` a second; the
agent's Event writer then aggregates repeats as the kubelet does. The host firewall's
drops and audit-mode passes get no Event.

### Pod rules of the flowsdn policy kinds (#292)

With `kubernetes.flowsdn-policy: true`, the `endpointSelector` specs (`spec` or
`specs[]`) of FlowsdnNetworkPolicy and FlowsdnClusterwideNetworkPolicy go into
the same endpoint maps as NetworkPolicy. No program changes. Off by default:
stormcos does not apply the CRDs yet (stormcos#303).

- **Subjects and peers (spec 06 §3.2.9).** A FlowsdnNetworkPolicy selects Pods
  of its own namespace. `from/toEndpoints` without a namespace label mean that
  namespace (the clusterwide kind: every namespace, so `{}` is every Pod, not
  host or world), limited to this cluster.
- **Rules.** `ingress`, `ingressDeny`, `egress`, `egressDeny` with
  `from/toEntities`, `from/toCIDR`, `from/toCIDRSet` (`cidr`, `except`),
  `from/toEndpoints` and `toPorts` (`port`, `endPort`, `protocol`, named ports:
  the destination's container ports).
- **Default deny (§3.2.8, §3.6).** A direction with rules is default deny,
  deny-only specs included, unless `enableDefaultDeny` turns it off. If every
  spec selecting a Pod turns it off and no NetworkPolicy selects it in that
  direction, its rules add to a wildcard allow.
- **Denies** win over the allows they cover, NetworkPolicy's too.
- **`ingress: [{}]`** turns on default deny and allows nothing, as for the host
  firewall. An L4-only rule allows every peer on those ports.
- **Refused.** A spec the reference's validation refuses fails its whole object,
  which then enforces nothing, its host-firewall (`nodeSelector`) specs too
  (#496): L3 members that may not be combined (only Endpoints + Entities and
  CIDR + CIDRSet may), no selector, both, or a selector that does not parse.
- **Skipped and reported** in `policy` problems: L7 rules, ICMP rules, FQDN,
  `toServices`, `from/toRequires`, `toGroups` (not built, #530),
  `cidrGroupRef`, authentication, and `reserved:` labels in a selector.
  `from/toNodes` (#451) select Nodes by their labels: this node is the host
  identity, another node each of its InternalIPs' own identity (#490). A skipped
  allow still leaves the direction enforced, so it fails closed. **A skipped deny
  denies nothing**, so read the problems.
- **Status.** `kubernetes.policy.flowsdn-policies` in `GET /v1/healthz` names the
  objects with Pod rules.

Compiler unit-tested; not on a cluster.

### Host firewall (#379)

Traffic to the node itself, filtered in eBPF from the same rule model as the
reference's host firewall ([ADR-0022](decisions/0022-host-firewall.md)), so one
policy works on both stormcos flavours: stormfw (stormcos#558) translates its
`HostFirewallPolicy` into a `FlowsdnClusterwideNetworkPolicy` here as it does
into a `CiliumClusterwideNetworkPolicy` there. Off by default
(`kubernetes.host-firewall`); the stormcos Kubernetes-mode config
(`manifests-kubernetes/61-flowsdn-config.yaml`) sets `audit` for stormfw's
audit phase (#402, stormcos#877). Until the FlowsdnClusterwideNetworkPolicy list
succeeds (its CRD is applied by stormcos#303) the host endpoint has no rules: the
uplinks carry the programs as while learning and nothing is judged. The policy
thread does not wait for that list for the host firewall, so NetworkPolicy is
not held back (before #402 it was); `kubernetes.flowsdn-policy` still waits for it.

- **Policies.** Every FlowsdnClusterwideNetworkPolicy spec (`spec` or
  `specs[]`) with a `nodeSelector` that matches this Node's labels.
  Supported: `ingress` and `ingressDeny` rules with `fromEntities` (`all`,
  `world`, `cluster`, `host`, `remote-node`, `health`, `init`,
  `kube-apiserver`, `ingress`, `unmanaged`), `fromCIDR`, `fromCIDRSet`
  (`cidr`, `except`), `fromEndpoints` (Pod label selectors, any namespace
  unless the selector names one), `toPorts` (`port`, `endPort`, `protocol`
  TCP/UDP/SCTP/ANY), and `enableDefaultDeny.ingress`. An L4-only rule allows
  every source; `ingress: [{}]` turns on default deny and allows nothing.
  `egress` and `egressDeny` (#477) take the same peers as `toEntities`,
  `toCIDR`, `toCIDRSet` and `toEndpoints` (destinations), with
  `enableDefaultDeny.egress`; a spec with egress rules default-denies the
  node's own outgoing traffic. Denies win over the allows they cover.
  `fromNodes`/`toNodes` (#451) select Nodes by their labels, as for Pod
  rules. Reported in `policy` problems and not enforced: L7 rules, ICMP rules,
  `*Requires`, `*Groups` (not built, #530), `toServices`, `toFQDNs`, `cidrGroupRef`,
  authentication and named ports.
  `endpointSelector` specs are [Pod rules](#pod-rules-of-the-flowsdn-policy-kinds-292);
  they are reported here too unless `kubernetes.flowsdn-policy` is on.
  A spec the reference's validation refuses (see Pod rules, **Refused**; a
  `nodeSelector` that does not parse) fails its whole object, Pod and host
  rules alike (#496): it reports `<policy>: not enforced, <reason>` and
  installs nothing.
- **Where.** The `from_netdev` program on the TCX ingress of every interface
  holding a global address of this node (InternalIP or not: an admin
  network's NIC, a SLAAC IPv6 on the uplink; not `lo`, not a bridge or bond
  port; #384) and every uplink port (#408), after the NodePort program, so
  NodePort traffic is judged as the Pod's after translation, and `to_netdev`
  on its egress. The NodePort programs end a packet's TCX chain only when
  they redirect (SNAT or DSR to another node, NAT46/64) or drop it; every
  other packet, and every packet on egress, goes on to the host firewall
  (`TCX_NEXT`; before #484 they returned a final pass and the firewall never
  ran on an uplink with NodePort on). `host-chain-live` checks the chain with
  real connections. Every such address has the host identity while the
  firewall is on. Only packets to (ingress) or from (egress) the node's own
  addresses are looked at; forwarded traffic passes. The host is endpoint
  65536 in the policy maps, under each uplink's interface index.
- **Egress** (#477). With egress rules, `to_netdev` judges packets leaving
  from the node's own addresses by them, and `to_container` judges the
  node's packets to a local Pod (kubelet probes included, as the reference's
  host firewall does: allow them, e.g. `toEntities: [cluster]`). Replies of
  connections the firewall let in, and of flows learned in the first 60 s,
  leave without a rule.
- **Local Pods** (#384). A local Pod's traffic to the node arrives on its
  veth, not an uplink: `local_delivery` judges it by the host's ingress
  rules after the Pod's own egress policy, and `to_container` remembers the
  flows the node starts to a Pod (kubelet probes) so the Pod's replies pass
  (and, with egress rules, judges them).
  The host endpoint for this path is `flowsdn_policy_ep` key 0
  (`HOST_PODS`, no interface has that index), with its own 60 s learning.
  `fromEndpoints` and `fromEntities: cluster` select local Pods as they do
  remote ones; a policy that allows the node only from the node network now
  refuses Pods too, as the reference's host firewall does.
- **State.** `to_netdev` remembers the flows the node starts, so their
  replies pass; `from_netdev` remembers allowed flows. On a new uplink the
  firewall only learns flows for its first 60 s, so connections the node
  already has (kubelet, the API server, SSH sessions) keep working when
  enforcement starts.
- **Audit.** `kubernetes.host-firewall: audit`, or a selecting policy with
  the annotation `policy.flowsdn.io/audit: "true"`: what the policy refuses is
  counted (`audit` in `GET /v1/policy/verdicts`) and passed.
- **Always passed:** ARP, IPv6 neighbour/router discovery, ICMP
  fragmentation-needed and packet-too-big.
- **Status.** `kubernetes.policy.host-firewall` in `GET /v1/healthz`: mode,
  selecting policies, `ingress-enforced` and `egress-enforced`, uplinks, those still learning and those enforcing,
  the local Pods' path (`pods`: `tracking`, `learning` or `enforcing`) and
  the node's addresses. Each change of those is a `HostFirewall` node Event
  and agent log line (`host firewall audit: interfaces eth0; enforcing on
  none; local Pods tracking; 3 node addresses`). An uplink that cannot be
  found or attached is a `host-firewall` / `host-firewall-attach` part error.
- **Hand-over from the boot window.** The node is filtered before the agent
  runs only by stormfw's boot-time program (stormfw#1, stormcos#558). That
  program can stand down for an interface once `enforcing-on` lists it and
  `pods` is `enforcing` (after the 60 s learning); while flowsdn only
  learns, it judges nothing.

The links are not pinned: the firewall is off while the agent restarts,
until stormfw's program covers it again. `policy-live` test-runs the uplink
and the local-Pod paths in both directions; the first cluster run is #478.

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
