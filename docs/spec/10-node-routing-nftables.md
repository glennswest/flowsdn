# Node-level networking: devices, routes, rules, neighbors, MTU, sysctls, the node model and the nftables residual — specification

Status: draft. Derived from: `docs/inventory/03-datapath-userspace-node.md`
(primary), `docs/inventory/13-crds-k8s.md` (CiliumNode non-IPAM fields, node
annotations), `docs/kernel-requirements.md` (§4.3 sysctls, §4.4 netlink
families, §4.7 startup check); reference cilium v1.20.1 (7d68cfb394) paths
`pkg/datapath/linux/{node.go,node_ids.go,devices_controller.go,linux_defaults/,
route/,routing/,sysctl/,bigtcp/,bandwidth/,probes/managed_neighbors.go}`,
`pkg/datapath/tables/{device,node_address,direct_routing_device}.go`,
`pkg/datapath/{neighbor,tunnel,vtep,xdp}/`, `pkg/datapath/loader/{netlink,base}.go`
(device creation and global sysctls, read for the device layout only),
`pkg/datapath/iptables/iptables.go` (read to enumerate every rule the residual
must account for), `pkg/mtu/mtu.go`, `pkg/node/{address_linux.go,manager/}`,
`pkg/nodediscovery/`, `pkg/proxy/routes.go` (rule/table numbers only),
`pkg/kpr/initializer/`, `pkg/socketlb/`, `pkg/cgroups/`, `pkg/defaults/node.go`,
`daemon/infraendpoints/infra_ip_allocation.go` (router IP). Governed by
ADR-0001..0004; **ADR-0003 (nftables residual) is implemented by this spec.**

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes *what*
flowsdn does and the exact data it exchanges with the kernel and the cluster. It
does not transcribe reference code. Where reference behavior is kept for
compatibility the consumer is named (kernel, operator, cilium-dbg, Envoy,
clustermesh peers, other nodes running the reference). Where flowsdn deviates the
paragraph is marked **DEVIATION** with the reason and the ADR.

**Amendments.** 2026-09-07 — §9 gained **§9.1**, the enumerated nftables test
cases that replace the coverage ADR-0003 drops with the reference's
`pkg/datapath/iptables` and `pkg/datapath/iptables/ipset` packages (25 tests,
2,592 Go test lines). Written before the nftables code, as
`docs/test-port-plan.md` §6 item 2 requires.

Sibling specs: `00-foundation-table-config.md` (tables, reconciler helper,
config registry, fences), `01-bpf-map-abi-loader.md` (map layouts incl.
`cilium_node_map_v2`, attach mechanics incl. cgroup socket programs),
`02-datapath-programs.md` (what the programs need from the host: marks,
`ENCAP_IFINDEX`, direct-routing device, masquerade addresses),
`03-identity-ipcache.md` (ipcache entries the node manager writes),
`04-conntrack-nat.md` (§3.12 masquerade decision — BPF only), `05-service-loadbalancing.md`
(NodePort addresses consumer, backend IPs feeding neighbors), `07-ipam.md`
(pod CIDRs, router IP allocation, `spec.ipam.*` of CiliumNode), `08-endpoint-agent-api.md`
(per-endpoint routes, veth connector, REST models), `09-cni-plugin.md`
(container-side routes and MTU).

## 1. Scope

Everything that must be true about the host network namespace, outside the BPF
programs and outside per-endpoint plumbing, before and while the datapath runs:

- **(A) Device model**: which devices exist, which are *selected* for programs,
  the `devices`, `routes`, `neighbors`, `node-addresses` tables and their
  netlink sources; the direct-routing device; NodePort and masquerade address
  selection.
- **(B) Host networking layout** per routing mode: `cilium_host`/`cilium_net`,
  tunnel and IPIP devices, per-node routes, the ip-rule set and the routing
  tables flowsdn owns.
- **(C) Node model**: the local node (addresses, CIDRs, health/ingress IPs, boot
  ID, encryption key), its publication as `CiliumNode` and Node annotations, the
  remote node cache and its fan-out (routes, node IDs, ipcache, neighbors).
- **(D) Neighbor management** for `bpf_redirect_neigh` / XDP.
- **(E) MTU** derivation and BIG TCP.
- **(F) Sysctls**, **(G) bandwidth manager qdiscs**, **(H) socket-LB cgroup
  root**, **(I) kube-proxy-replacement mode and host-routing selection**.
- **(J) The nftables residual** (ADR-0003): one table, its chains and rules, the
  disposition of every reference iptables rule.

Out of scope (owned elsewhere): BPF program attach itself (01), per-endpoint
veth/netkit creation and `lxc*` routes (08/09), IPAM and `CiliumNode.spec.ipam`
(07), IPsec XFRM state and WireGuard peers (encryption spec; only their routes,
rules, marks and MTU deltas appear here), ip-masq-agent map contents (04/07),
L2 announcements / GARP responder (LB/L2 spec), VTEP and datapath plugins
(deferred per inventory 03; the VTEP rule/table numbers are reserved here),
ENI/Azure/Alibaba per-interface routing (cloud IPAM decision; rule numbers
reserved here), socket termination via `SOCK_DESTROY` (LB spec).

## 2. Compatibility contract

These MUST match the reference because something outside flowsdn depends on
them.

| Interface | Value | Consumer |
|---|---|---|
| Device names | `cilium_host`, `cilium_net`, `cilium_vxlan`, `cilium_geneve`, `cilium_ipip4`, `cilium_ipip6`, `cilium_wg0`, `lxc*`, `lxc_health` | cilium-dbg, Hubble device names, operators' runbooks, `--devices` exclusion list of other CNIs |
| Tunnel UDP ports | VXLAN 8472, Geneve 6081 (`tunnel-port` 0 = these defaults) | other nodes (mixed reference/flowsdn clusters during migration), firewalls |
| Route protocol | `RTPROT_KERNEL` (2) on every route and rule flowsdn installs | systemd-networkd / NetworkManager leave `proto kernel` objects alone |
| Route tables | 200 IPsec, 202 VTEP, 2004 to-proxy, 2005 from-proxy, `10 + n` per-ENI, 254 main, 255 local | cilium-dbg, operators' runbooks, Envoy (2004/2005 via marks) |
| Rule priorities | 1 IPsec decrypt, 9 to-proxy, 10 from-proxy, 20 ENI ingress, 100 relocated local lookup, 109 ENI NodePort, 110/111 ENI egress, 112 VTEP | same |
| skb mark magic | `0x200` to-proxy, `0x800` proxy-EPID / skip-tproxy, `0xA00` from-ingress-proxy, `0xB00` from-egress-proxy, `0xC00` host, `0xD00` decrypt, `0xE00` encrypt, `0x80` ENI connmark; masks `0xF00`, `0xE00`, `0xFFFFFEFF` | BPF programs (spec 02 §2.1), Envoy (`SO_MARK` 0xA00/0xB00) |
| `cilium_node_map_v2` | `node_key`(20) → `node_value`(4), 16384 entries, `BPF_F_NO_PREALLOC`, read-only-from-program, pinned; ID 0 = local node, IDs 1..65535 remote | spec 01 §2.2/§4.4; IPsec marks; `cilium-dbg bpf nodeid list` |
| `CiliumNode` spec fields written | `spec.addresses[]{type,ip}` with types `InternalIP`, `ExternalIP`, `CiliumInternalIP`; `spec.health.{ipv4,ipv6}`; `spec.ingress.{ipv4,ipv6}`; `spec.encryption.key`; `spec.bootid`; labels/annotations copied from the Node; `ownerReferences` → Node | operator, clustermesh, other nodes |
| Node status annotations (`annotate-k8s-node`) | `network.cilium.io/ipv4-pod-cidr`, `ipv6-pod-cidr`, `ipv4-cilium-host`, `ipv6-cilium-host`, `ipv4-health-ip`, `ipv6-health-ip`, `ipv4-Ingress-ip`, `ipv6-Ingress-ip`, `encryption-key`; legacy aliases `io.cilium.network.*` are read, never written | external tooling, older agents |
| kvstore node key | `cilium/state/nodes/v1/<cluster>/<node>` JSON of `Node` (§4.3) | clustermesh (deferred backend; format frozen) |
| REST | `GET /cluster/nodes` (`ClusterNodeStatus`), `GET /node/ids` (`[]NodeID{id, ips[]}`) | cilium-dbg |
| Config keys | every key in §6 with the reference name and default | Helm ConfigMap `cilium-config` |
| Pod annotations | `policy.cilium.io/no-track-port` (alias `io.cilium.no-track-port`), `network.cilium.io/no-track-host-ports` | users (NodeLocalDNS) |
| ip-masq-agent file | `nonMasqueradeCIDRs`, `masqLinkLocal`, `masqLinkLocalIPv6` (spec 07 owns the map) | users |

Not part of the contract (flowsdn-internal): the nftables table name and chain
names (§3.10), the tables crate schemas, the node checkpoint file format, metric
names not listed in §8.

## 3. Behavior

### 3.1 Device model

#### 3.1.1 The `devices` table and its source

`flowsdn-node` MUST subscribe to `NETLINK_ROUTE` groups `RTNLGRP_LINK`,
`RTNLGRP_IPV4_IFADDR`, `RTNLGRP_IPV6_IFADDR`, `RTNLGRP_IPV4_ROUTE`,
`RTNLGRP_IPV6_ROUTE`, `RTNLGRP_NEIGH`, perform one full dump of each object kind
after subscribing (subscribe-then-dump, so no event is lost), and maintain four
`flowsdn-table` tables (spec 00 §4.3):

| Table | Row | Primary key | Indexes |
|---|---|---|---|
| `devices` | `Device{index, name, alt_names[], mtu, hw_addr, flags, raw_flags, kind ("veth","vxlan","bridge",…), master_index, oper_status, addrs[]{addr, scope, flags(secondary,tentative,dadfailed,deprecated)}, selected: bool, not_selected_reason: String}` | `index` | `name` (unique, multi-key over name + alt_names), `selected` |
| `routes` | `Route{table, link_index, dst: Prefix, src: Option<Addr>, gw: Option<Addr>, scope, priority, proto, type, mtu: Option<u32>, multipath[]}` | `(table, link_index, dst)` | `link_index` |
| `neighbors` | `Neighbor{link_index, addr, hw_addr, state (NUD_*), flags, flags_ext}` | `(link_index, addr)` | `link_index`, `addr` |
| `node-addresses` | `NodeAddress{addr, device_name, node_port: bool, primary: bool}` | `(addr, device_name)` | `device_name`, `node_port` |

Rules:

- Dumps interrupted by concurrent changes (`NLM_F_DUMP_INTR` set on a message)
  MUST be retried, up to 10 attempts with 100 ms spacing, then the table is
  marked degraded and the next event triggers a new dump. `ENOBUFS` on the
  subscription socket MUST trigger a full re-dump of all kinds (the socket
  overflowed; events were lost).
- Events are applied in a batch: the controller drains all pending events, waits
  for a quiescence window of 100 ms (max 1 s), then commits the batch to the
  tables. Device selection (§3.1.3) is re-evaluated for every device in the batch
  and for every device whose routes changed (a veth may become selected when it
  gains a default route).
- Deleted links produce tombstones; addresses and routes of a deleted link are
  removed in the same batch.
- A device with `name == ""` (address seen before its link) is never selected
  (`not_selected_reason = "link not seen yet"`).
- The `devices` table registers an initializer (spec 00 §3.1.6) that completes
  after the first successful dump of all six groups; consumers (loader, MTU,
  neighbors, node addresses) MUST NOT prune before that.

**Loopback and `cilium_*` devices are in the table** (un-selected); the loader
and proxy read `lo`, `cilium_host`, `cilium_net` from it.

#### 3.1.2 `devices` configuration grammar

`devices` is a list of entries. Each entry is one of:

| Form | Meaning |
|---|---|
| `eth0` | exact name (also matched against alt names) |
| `eth+` | prefix wildcard: names starting with `eth` |
| `!eth+`, `!eth0` | exclusion; same matching, first match wins |

Matching is first-match over the list in order; a `!` entry that matches makes
the device *not selected* with reason `"excluded by user filter"`. Entries MUST
NOT contain other glob characters (`*`, `?`) — validation error at startup. The
`+` is the iptables-style wildcard kept for Helm compatibility (`devices:
"eth+ !eth1"`).

When the list is non-empty and `force-device-detection=false`, a device that
matches no entry is not selected (`"not matching user filter"`) and no further
checks run. When the list is non-empty and `force-device-detection=true`, or
when the list is empty, auto-detection (§3.1.3) applies to unmatched devices.
A positively matched device is selected **without** the auto-detection checks
(the user knows better: a bridge or an addressless VLAN can be forced in).

#### 3.1.3 Auto-detection

A device is selected iff every predicate below holds; the first failing
predicate is recorded as `not_selected_reason` (exact strings are informational
and appear in `cilium-dbg status --verbose`-style output and logs).

| # | Predicate | Reason string when false |
|---|---|---|
| 1 | has at least one address | `device has no addresses` |
| 2 | `IFF_UP` set | `missing required flag` |
| 3 | neither `IFF_SLAVE` nor `IFF_LOOPBACK` set | `excluded flag set` |
| 4 | `master_index == 0`, or the master is of kind `vrf` | `bridged or bonded to ifindex N` (or `device has parent but parent device could not be found`) |
| 5 | name does not start with `cilium_`, `lo`, `lxc`, `cni`, `docker` | `excluded prefix "…"` |
| 6 | kind is not `bridge` or `openvswitch` | `bridge-like device, use --devices to override` |
| 7 | kind is not `ipoib` | `IPoIB device, use --devices to override` |
| 8 | if kind is `veth`: a default route (`0.0.0.0/0` or `::/0`, any table ≠ local) exits via this device | `veth without default route` |
| 9 | at least one route with `RT_SCOPE_UNIVERSE` in the main table (any family) exits via this device | `no global unicast routes` |

Predicate 8 exists for kind-in-docker (the node's uplink is a veth) and to skip
veths left behind by other CNIs; predicate 9 rejects link-local-only devices
(e.g. a bare `docker0` clone with only a scope-link route).

Devices are **required** (the agent MUST fail at startup with
`"no devices selected; set --devices"` when the set is empty) iff any of:
`kube-proxy-replacement`, `enable-bpf-masquerade`, `enable-host-firewall`,
WireGuard enabled, IPsec enabled, `enable-l2-announcements`,
`force-device-required`. Otherwise an empty set is allowed (pure tunnel mode
with kube-proxy) and only `cilium_host`/`cilium_net`/tunnel devices get programs.

Selection is **dynamic**: hot-plugged devices (AWS ENA, VLAN sub-interfaces,
bonds coming up) enter the table and, if selected, the loader attaches programs
and the node-address, neighbor and MTU consumers react through their watches. A
device that disappears produces a tombstone; the loader detaches (link pins are
unpinned; §7).

#### 3.1.4 Which devices get which programs (contract for spec 01/02)

| Device set | Programs |
|---|---|
| every selected device | `from_netdev` (tcx ingress), `to_netdev` (tcx egress); XDP `cil_xdp_entry` when acceleration is on |
| `cilium_host` | `from_host` (egress of cilium_host = traffic from the host stack), `to_host` (ingress) |
| `cilium_net` | `to_host`-side program (ingress) |
| `cilium_vxlan` / `cilium_geneve` | `from_overlay` (ingress), `to_overlay` (egress) |
| `cilium_ipip4` / `cilium_ipip6` | IPIP termination programs (DSR `ipip`) |
| `cilium_wg0` | `from_wireguard` (ingress; egress only when needed) — encryption spec |
| `lxc*` | endpoint programs (spec 08) |

#### 3.1.5 Direct-routing device

The direct-routing device is the native device whose address the datapath uses
as the source of encapsulated/DSR traffic and for `bpf_redirect_neigh` when
there is one obvious uplink. Selection:

1. If `direct-routing-device` is set it is a **single** filter entry (§3.1.2
   grammar, exact or `+` wildcard) evaluated over the *selected* devices; the
   first match wins.
2. Else if exactly one device is selected, that device.
3. Else none.

It is **required** iff `kube-proxy-replacement=true`, or BPF host routing is
enabled (§3.9), or WireGuard is enabled, or NodePort acceleration ≠ `disabled`.
When required and none is found the agent MUST fail with
`"unable to determine direct routing device; use --direct-routing-device"`.
A change of the direct-routing device (hot-plug, rename) triggers a datapath
config reload (spec 01 §3.7: `.rodata` `DIRECT_ROUTING_DEV_IFINDEX`,
`IPV4_DIRECT_ROUTING`, `IPV6_DIRECT_ROUTING`).

#### 3.1.6 Node addresses (`node-addresses` table)

For every device in the `devices` table (selected or `cilium_host`), plus the
`lo`-hosted "local table" addresses (below), the controller derives
`NodeAddress` rows. This table feeds NodePort frontends (spec 05), the
masquerade address per device (spec 04 §3.12), the host-identity ipcache
entries (spec 03), and the local node's `InternalIP` fallback.

Per device, candidate addresses are the device's addresses filtered by:

- scope `<= address-scope-max`, default **254 (`RT_SCOPE_HOST`)**, matching
  pinned reference `pkg/defaults/defaults_linux.go` and
  `pkg/defaults/defaults_unspecified.go` at `7d68cfb394` (ADR-0012 #136).
  `cilium_host`'s `RT_SCOPE_LINK` addresses are **always** included regardless
  of the maximum;
- not loopback;
- IPv6 link-local addresses are included only for `cilium_host` (IPv6 router LL)
  and are never `primary`/`node_port`.

Candidates are ordered: non-secondary before secondary (`IFA_F_SECONDARY`);
lower scope first (universe before link); public (non-RFC1918/ULA) before
private; then by address. The first IPv4 and the first IPv6 in that order are
`primary`. `node_port`:

- if `nodeport-addresses` is set: `node_port = device != cilium_host &&
  address ∈ one of the CIDRs` (all matching addresses, not just one);
- else: the first **private** IPv4 (fallback: first public IPv4) and likewise
  for IPv6 on each selected, `IFF_UP` device other than `cilium_host`.

Additionally, routes in the **local table (255)** with scope `RT_SCOPE_HOST`,
no `src`, a valid non-loopback, non-unspecified `dst`, whose device passes the
same device filter, contribute `NodeAddress{addr: dst, primary: !device
already has a primary of that family, node_port: per nodeport-addresses only}`
(GCE-style alias IPs installed as local routes on the uplink).

A synthetic device name `*` (wildcard) carries one fallback IPv4 and IPv6 —
the primary address of the "best" non-`lxc`, non-`cilium_host` device, best =
device with a default route, then lowest ifindex — used when a consumer needs
"some node IP" and no k8s address is known.

The table is recomputed from a snapshot on every `devices`/`routes` batch
commit; rows are upserted/deleted by diff so unchanged rows keep their revision.

#### 3.1.7 Node IP selection (`ipv4-node` / `ipv6-node` = `auto`)

The local node's `InternalIP` per family is, in order: the value of
`ipv4-node`/`ipv6-node` when not `auto`; the k8s `Node.status.addresses`
`InternalIP` (spec 00 config layering happens before this); else the **first
global address**: over all addresses of all devices (or only the
direct-routing device when `--direct-routing-device` is set — reference passes
the device name), excluding loopback, secondary (unless it is the k8s-preferred
IP), `IFA_F_TENTATIVE|IFA_F_DADFAILED`, and scope > `RT_SCOPE_UNIVERSE`; prefer
the k8s-preferred IP if it is public; else the lowest-ifindex **public**
address; else the k8s-preferred IP; else the lowest-ifindex private address. If
nothing matches at scope universe, retry once with scope `RT_SCOPE_SITE`.
`ExternalIP` comes only from the k8s Node.

### 3.2 Host networking layout

#### 3.2.1 `cilium_host` / `cilium_net`

Created (or adopted if present) as a veth pair at datapath (re)initialization:

| Attribute | Value |
|---|---|
| names | `cilium_host` (host side), `cilium_net` (peer) |
| MAC | random locally-administered, stable for the process (regenerated only on recreation) |
| `txqueuelen` | 1000 |
| ARP | **off** (`IFF_NOARP`) on both — the kernel then skips DAD on the auto-generated IPv6 link-local |
| MTU | `DeviceMTU` (§3.5) on both, updated in place on MTU change |
| state | up, both |
| per-device sysctls | §3.6 table, group "host devices" |
| addresses on `cilium_host` | `CiliumInternalIPv4/32` and `CiliumInternalIPv6/128` via `RTM_NEWADDR` with `NLM_F_REPLACE`; stale addresses of the same family that are not the current router IP MUST be removed at startup (the reference logs "Restore of the cilium_host ips failed. Manual intervention is required" when it cannot); the kernel's IPv6 link-local stays |

The pair is never deleted by flowsdn except when recreating a broken one
(missing peer). On upgrade from the reference the existing pair is adopted
(same names, same semantics).

**Router IP (`CiliumInternalIP`)**: allocated by IPAM (spec 07) from the
node's primary pod CIDR with owner `"router"`, restoring in order: the IP
present on `cilium_host` on disk/kernel (`fromFS`), then the `CiliumInternalIP`
in the existing `CiliumNode` (`fromK8s`); if both exist and differ, warn and
prefer `fromFS`. If neither can be re-allocated, allocate the next free IP and
warn `"Router IP could not be re-allocated. Need to re-allocate. This will
cause brief network disruption"`. `local-router-ipv4`/`-ipv6` pin the router
IP instead (allowed only in native routing mode and never with IPsec — startup
error otherwise; warn when the pinned IP lies inside the pod CIDR). The router
IP is published as the `CiliumInternalIP` address and is the `via` of every
tunnel-mode route (§3.2.3).

#### 3.2.2 Tunnel and IPIP devices

Present iff `routing-mode=tunnel` (or a feature enables encapsulation: DSR
`geneve` dispatch, egress gateway, clustermesh with tunnel, per spec 05/07).

| Device | Kind | Attributes |
|---|---|---|
| `cilium_vxlan` | `vxlan` | `IFLA_VXLAN_COLLECT_METADATA=1` (flow-based, one device for all peers), `IFLA_VXLAN_PORT=<tunnel-port or 8472>`, `IFLA_VXLAN_PORT_RANGE=<tunnel-source-port-range>` (`0-0` → kernel default), `IFLA_VXLAN_LEARNING=0`, no `IFLA_VXLAN_ID`, no remote/group/local, MTU `DeviceMTU`, random MAC, up |
| `cilium_geneve` | `geneve` | `IFLA_GENEVE_COLLECT_METADATA=1`, `IFLA_GENEVE_PORT=<tunnel-port or 6081>`, `IFLA_GENEVE_PORT_RANGE` low/high (`0-0` → `1-65535`), MTU, random MAC, up |
| `cilium_ipip4` | `ipip` | `IFLA_IPTUN_COLLECT_METADATA=1` (flow-based), MTU, up — only for DSR `ipip` dispatch / IPIP termination |
| `cilium_ipip6` | `ip6tnl` | `IFLA_IPTUN_COLLECT_METADATA=1`, MTU, up — same |

Rules:

- Exactly one of `cilium_vxlan`/`cilium_geneve` exists; the other, if present
  from a previous configuration, MUST be deleted.
- Changing the **destination port** requires recreating the device (kernel
  refuses to modify it). If a device of that name exists with a different port
  it MUST be deleted first (the kernel allows several vxlan devices with the
  same dstport but only one `up`; an unmanaged one would otherwise block us).
- Changing the **source port range** on an existing device is not possible;
  log `"Source port range hint ignored given <dev> already exists"` and keep the
  existing device.
- MTU changes are applied in place.
- The tunnel device's ifindex is exported to the datapath as `ENCAP_IFINDEX`;
  `TUNNEL_PROTOCOL` 0/1/2 = none/vxlan/geneve; `TUNNEL_PORT` (spec 02 §6.1).
- With IPIP devices, sysctl `net.core.fb_tunnels_only_for_init_net=2`
  (best-effort) so the kernel's fallback `tunl0`/`ip6tnl0` are not created in
  every new netns.
- BIG TCP GSO/GRO sizes are applied to the tunnel device as to native devices
  (§3.5.3) when the "BIG TCP over UDP tunnels" capability is present.
- `underlay-protocol`: `auto` → IPv4 if enabled else IPv6; explicit `ipv4`/
  `ipv6` MUST be enabled families (error otherwise). The underlay decides
  whether `tunnel_endpoint` in ipcache entries is the node's IPv4 or IPv6 and
  sets `TunnelOverheadIPv4/IPv6` in §3.5.

#### 3.2.3 Routes per routing mode

All routes and rules carry `proto kernel` (`RTPROT_KERNEL`, 2) — **kept for
compatibility with systemd-networkd/NetworkManager**, which by default only
manage routes of their own protocol and leave `kernel` ones alone (reference
rationale in `linux_defaults`). Metric = `route-metric` (default 0) on node
routes.

**Tunnel mode** — for every remote node and each of its IPv4 alloc CIDRs
(primary + secondary):

```
<podCIDR> via <CiliumInternalIPv4> dev cilium_host src <CiliumInternalIPv4> mtu <RouteMTU> proto kernel metric <route-metric>
```

and for IPv6 alloc CIDRs (the kernel rejects a local address as IPv6 gateway
with "Gateway can not be a local address"):

```
<podCIDR6> dev cilium_host src <CiliumInternalIPv6> mtu <RouteMTU> proto kernel metric <route-metric>
```

**Nexthop trick** (IPv4 only, whenever a route has a gateway): before
`RTM_NEWROUTE` of the prefix, ensure `<gateway>/32 dev <device> scope link proto
kernel` exists (`NLM_F_REPLACE`), so the gateway is resolvable even though it is
an address on the device itself; delete that nexthop route when the last route
using it is deleted and no other route on that device uses it. Route replace is
retried up to 10 times at 100 ms on `ENETUNREACH`/`EEXIST`-class transient
errors (the kernel may not yet have processed the nexthop route).

**Local node route** (`enable-local-node-route=true`, forced `false` for ENI/
Azure/AlibabaCloud IPAM): the local alloc CIDRs (primary + secondary) get the
same `cilium_host` route **without** `mtu`. `ipv4-service-range` /
`ipv6-service-range` when not `auto` are "auxiliary prefixes" routed the same
way (as local node routes).

**Native routing** (`routing-mode=native`): no per-node route by default (the
underlay routes pod CIDRs). With `auto-direct-node-routes=true`, for each
remote node and each alloc CIDR:

1. `RTM_GETROUTE` for the node IP; if the result has a gateway that is neither
   unspecified nor the node IP itself, the node is not directly reachable: fail
   the update with `"route to destination <ip> contains gateway <gw>, must be
   directly reachable. Add direct-routing-skip-unreachable to skip unreachable
   routes"` unless `direct-routing-skip-unreachable=true`, in which case skip
   silently (debug log).
2. If the result's ifindex is `lo` (1), look up the node IP in table 255 and use
   that route's ifindex (the node IP is local: this is us).
3. Install `<podCIDR> via <nodeIP> dev <ifindex> proto kernel` (IPv6 likewise).
4. Delete routes for CIDRs that left the node's set; on node deletion delete all.

On first addition of a node in native mode without auto-direct routes, any
leftover `cilium_host` route for that CIDR from a previous tunnel configuration
MUST be deleted.

**Encapsulation per node**: a node uses encapsulation iff the global mode is
tunnel, except that a `Node` marked (by clustermesh or a future per-node
policy) as "skip tunnel" is treated as native for routing purposes; the
predicate is an injectable function so spec 12 can override it.

**Endpoint routes mode** (`enable-endpoint-routes=true`): the loader/endpoint
manager installs `<podIP>/32 dev lxcXXXX` host routes (spec 08). Node-level
consequences specified here: the IPv4 IPsec decrypt rule (§3.2.4) is not
installed; `ipcache`'s local delivery uses the host stack, so the nftables
proxy-return `notrack` rules take `oifname "lxc*"` as delivery interface
(§3.10.4).

**IPsec table 200** (contract only; encryption spec fills XFRM): per remote
node `<podCIDR> dev cilium_host mtu <RoutePostEncryptMTU> proto kernel table
200` (out) and `local <podCIDR> dev <encrypt-interface> table 200` (in);
routes for `ipv4-pod-subnets`/`ipv6-pod-subnets` likewise. Table 200 is flushed
when IPsec is disabled at startup.

**VTEP table 202** (deferred feature; reserved): `<vtepCIDR> via
<CiliumInternalIPv4> dev cilium_host mtu 1450 table 202`.

**Proxy tables 2004/2005** (installed by the proxy module through
`flowsdn-netlink`, numbers reserved here): table 2004 `local default dev lo`
(type local, IPv4 `0.0.0.0/0` and IPv6 `::/0`); table 2005
`<CiliumInternalIPv4>/32 dev cilium_host scope link` and `default via
<CiliumInternalIPv4> dev cilium_host mtu <RouteMTU or RoutePostEncryptMTU>`;
IPv6 uses the **link-local address of `cilium_net`** as the gateway (again
because a local address cannot be an IPv6 gateway). Present only when the L7
proxy is enabled; table 2005 only when IPsec or WireGuard makes proxy return
traffic need the special path.

#### 3.2.4 ip rules

Installed with `RTM_NEWRULE` + `NLM_F_REPLACE` semantics (delete-then-add of
an identical rule is not atomic; flowsdn MUST look up an equal rule first and
add only if absent, and MUST remove duplicates of its own rules found on
startup). `FRA_PROTOCOL = RTPROT_KERNEL` on every rule.

| Pref | Selector | Action | Families | When |
|---|---|---|---|---|
| 1 | `fwmark 0xd00/0xf00` | `lookup 200` | IPv4 only when `enable-endpoint-routes=false`; IPv6 always | IPsec enabled |
| 9 | `fwmark 0x200/0xf00` | `lookup 2004` | both | L7 proxy enabled (proxy module) |
| 10 | `fwmark 0xa00/0xf00` and a second rule `fwmark 0xb00/0xf00` | `lookup 2005` | both | L7 proxy with IPsec/WireGuard (proxy module) |
| 20 | `to <podIP>` | `lookup main` | per pod | ENI/Azure IPAM (deferred) |
| **100** | `from all` | `lookup local` | both | **always** |
| 109 | `fwmark 0x80/0x80` | `lookup main` | both | ENI/Azure with multi-node NodePort (deferred) |
| 110 / 111 | `from <podIP> [to <vpcCIDR>]` | `lookup 10+iface` | per pod | ENI/Azure (110 = compat priority with table `10+ifindex`; 111 = v2 with table `10+eni number`) (deferred) |
| 112 | `to <vtepCIDR>` | `lookup 202` | IPv4 | VTEP (deferred) |

**Relocating the kernel's local rule** (`NodeEnsureLocalRoutingRule`): at
startup, per enabled family, (1) add `pref 100 from all lookup local proto
kernel` if absent, then (2) delete the kernel default `pref 0 from all lookup
local` (ignore `ENOENT`). Order (1) before (2) is mandatory — a moment without
a local rule breaks local delivery. This creates room for prefs 1..99 (IPsec
decrypt, proxy). flowsdn MUST NOT re-add pref 0 on shutdown (the reference does
not; `ip rule` users expect 100 on a Cilium node). Rules 1, 9, 10 exist so
that marked packets bypass the *local* table lookup (e.g. a decrypted packet's
destination is a local pod IP that would otherwise match a local route).

Startup pruning: rules with `proto kernel` and the prefs above whose selector
does not match the desired set are deleted (e.g. table 200 rule when IPsec is
now off); rules of other protocols are never touched.

### 3.3 Node model

#### 3.3.1 Local node

`LocalNode` (§4.3) is a single-row watchable value. It is populated in this
order, each step overriding the previous where it has data:

1. Config: `cluster-name`, `cluster-id`, `ipv4-node`/`ipv6-node` (if not
   `auto`), `ipv4-native-routing-cidr`/`ipv6-native-routing-cidr`,
   `ipv4-service-loopback-address`, `node-labels`, underlay protocol.
2. The k8s `Node` (name from `K8S_NODE_NAME`/`--k8s-node-name` — hostname
   fallback is not supported when running under Kubernetes): `InternalIP`s and
   `ExternalIP`s (both families), labels (filtered by
   `exclude-node-label-patterns`), annotations matching
   `^([A-Za-z0-9]+\.)*cilium.io/`, UID, providerID, `spec.podCIDRs` (spec 07
   decides use), `taints`.
3. The existing `CiliumNode` (if any): restore `CiliumInternalIP`s, health IPs,
   ingress IPs so they are stable across restarts.
4. Discovery: node IPs per §3.1.7 when step 2 gave none; boot ID from
   `/proc/sys/kernel/random/boot_id` (MUST be readable when IPsec is enabled;
   otherwise best-effort); encryption key index from the IPsec key file
   (encryption spec); WireGuard public key (annotation `network.cilium.io/wg-pub-key`
   on the CiliumNode, written by the encryption module).
5. IPAM assigns alloc CIDRs, router IP, health IP, ingress IP (spec 07).

Steps 2–3 MUST complete or time out (`node-init-timeout`, 15 min, fatal) before
the datapath is initialized (fence `local-node-ready`, spec 00 §5.7).
Labels/annotations continue to sync from the k8s Node for the life of the
process.

#### 3.3.2 Publishing: `CiliumNode`

When `auto-create-cilium-node-resource=true` (and `enable-cilium-node-crd`,
hidden, default true), the agent creates or updates the `CiliumNode` named
after the node whenever `LocalNode` changes (debounced to the same 15 s rate
as `ipam-cilium-node-update-rate` when only IPAM fields changed; immediately
for address changes). Write set (non-IPAM; §7 owns `spec.ipam.*`):

| Field | Value |
|---|---|
| `metadata.ownerReferences` | one ref to `v1/Node` `<name>` with the Node's UID (no controller flag) |
| `metadata.labels`, `metadata.annotations` | copied from `LocalNode` (the Node's labels/annotations as filtered in §3.3.1) — **existing keys the agent did not set are preserved**: labels/annotations are merged, not replaced |
| `spec.addresses[]` | one entry per `LocalNode` address: `{type: InternalIP\|ExternalIP\|CiliumInternalIP, ip}`; entries of other types (cloud IPAM writes none here) are kept; entries of these three types not in the current set are removed |
| `spec.health.ipv4/ipv6` | health endpoint IPs, `""` when the family is off |
| `spec.ingress.ipv4/ipv6` | ingress IPs, `""` when unset |
| `spec.encryption.key` | IPsec key index, 0 when off |
| `spec.bootid` | boot ID |
| `spec.ipam.podCIDRs` | only in `ipam=kubernetes` mode: the Node's podCIDRs (spec 07) |
| `spec.ipam.{min-allocate,pre-allocate,max-allocate,max-above-watermark,static-ip-tags}`, `spec.instance-id`, `spec.eni.*`, `spec.azure.*`, `spec.alibaba-cloud.*` | cloud IPAM modes (spec 07; deferred) |

Create/Update is retried 10 times with 500 ms backoff; persistent failure is
**fatal** (the operator cannot allocate to a node it cannot see). A 409 conflict
re-reads and re-applies. `status` is never written by this module.

The kvstore registration (`cilium/state/nodes/v1/<cluster>/<name>` = JSON
`Node`, lease-bound) is performed when a kvstore is configured (deferred with
clustermesh; format in §4.3).

#### 3.3.3 Publishing: Node annotations

When `annotate-k8s-node=true`, patch `nodes/<name>/status` (strategic-merge
patch, `application/strategic-merge-patch+json`) with the annotations in §2:
pod CIDRs (primary only), `cilium_host` IPs, health IPs, ingress IPs,
`encryption-key`. Retried with backoff; failure is logged, not fatal
(inventory: "fatal on transient errors" refers to CiliumNode, not the
annotation). Keys whose value is empty are omitted, not set to `""`.

#### 3.3.4 Remote nodes: the node manager

Sources: `CiliumNode` watch (all nodes; the local node's own object is ignored
for datapath purposes), kvstore/clustermesh (deferred), and the on-disk
**checkpoint** `<state-dir>/nodes.json` (all known nodes, written at most once
per minute on change and on shutdown; restored at startup with `source =
Restored`). Source precedence follows spec 03 §4.6 (`Restored` is lowest; a
live source overwrites it; nodes still `Restored` after the first full sync
are deleted — "startup pruning").

For each `NodeUpdated(new)` (with the previous `old` if known) the manager
applies, in this order:

1. **Node IDs** (§3.3.5) — allocate/verify before anything that encodes the ID.
2. **IPsec** XFRM for the node (encryption spec) — when enabled.
3. **Routes** (§3.2.3): local node → local route/aux prefixes; remote →
   tunnel routes or direct routes; delete routes for removed CIDRs.
4. **ipcache** (spec 03 §3.9 owns semantics; contents here):
   - each node address: prefix `/32` or `/128`, labels `reserved:remote-node`
     (or `reserved:host` for the local node and, with
     `enable-node-selector-labels`, the node's selected labels merged), `TunnelPeer
     = node IP of the underlay family`, `EncryptKey = spec.encryption.key`,
     `remote-cluster` flag for other clusters; `CiliumInternalIP` prefixes are
     cluster-scoped, other address types are local-scoped (`cluster_id 0`).
     An existing entry with a higher-precedence source is not overwritten
     except by `KubeAPIServer` or when it is our own local router IP.
   - health IPs → `reserved:health`, ingress IPs → `reserved:ingress`, both
     with `TunnelPeer = node IP`.
   - remote nodes only: each alloc CIDR → a **pod CIDR fallback entry**
     (identity `reserved:world` ... spec 03 §3.9 "CIDR entry with tunnel peer
     and encrypt key") so pods whose CEP has not arrived still route.
5. **Neighbors**: node IPs enter the forwardable-IP table (§3.4).
6. **Handlers**: WireGuard peer, IPsec, REST status cache, metrics
   (`flowsdn_node_events_received_total{type,source}`).
7. Checkpoint trigger.

`NodeDeleted` reverses 6→1: remove ipcache entries (only those this node
resource contributed), delete routes (tunnel or direct), unmap node IDs, remove
IPsec state, remove forwardable IPs, checkpoint.

**Background re-validation**: every `interval(n)` where
`interval = base × (1 + log2(n)) … ` — concretely the reference's
`ClusterSizeDependantInterval(1 min, n)`: ≈ 42 s at 1 node, 1 m06 at 2, 1 m37
at 4, 2 m12 at 8, 2 m50 at 16, 3 m30 at 32, 4 m10 at 64, 4 m52 at 128, 5 m33 at
256, 6 m14 at 512, 6 m56 at 1024, 7 m38 at 2048, 8 m19 at 4096, 9 m01 at 8192,
9 m42 at 16384 — the manager re-runs `NodeUpdated(n, n)` for every known node
(rate-limited so one loop takes about the interval), which re-asserts routes
and ipcache entries that an external actor removed. flowsdn MUST implement the
same growth curve (formula: `base × (1 + 0.6931 × ln(n)) … ` — see §5.5 for
the exact function) so a large mixed cluster behaves the same.

`--enable-node-selector-labels` + `node-labels`: node identities carry the
listed labels (spec 03).

#### 3.3.5 Node IDs and `cilium_node_map_v2`

- IDs are `u16` in 1..65535 allocated from a pool; **0 means the local node**
  and is never allocated. Every IP address of a remote node maps to the same
  ID: `node_key{family, ip} → node_value{id, spi}` where `spi = node's
  spec.encryption.key` (0 without IPsec).
- Allocation on `NodeUpdated`: if any IP of the node already has an ID, reuse
  it; else allocate. New IPs of the node are mapped; IPs that left the node are
  unmapped; if the SPI changed every IP is rewritten. Pool exhausted →
  error `"no available node ID"` for that node (logged, node handled without
  ID; retried on the next update).
- On `NodeDeleted` all its IPs are unmapped and the ID returns to the pool.
- **Restore**: at startup, before any node event, iterate the pinned map and
  register every `(ip → id, spi)`; IDs seen are removed from the pool; entries
  with `id == 0` are invalid and deleted (`"Removing incorrect node IP to node
  ID mappings from the BPF map"`). Restore is mandatory because IPsec XFRM
  marks (`nodeID << 16`) and in-flight encrypted traffic depend on stable IDs
  across agent restarts. After the first full node sync, mappings for IPs that
  belong to no known node are pruned.
- `GET /node/ids` returns `[{id, ips[]}]` grouped by ID; `GetNodeIP(0)` is the
  local node's IP.

### 3.4 Neighbor management

Enabled iff `enable-l2-neigh-discovery=true` or XDP acceleration ≠ `disabled`.
Purpose: `bpf_redirect_neigh` and `bpf_fib_lookup` in native routing, and XDP
NodePort forwarding, need resolved L2 next hops for **remote node IPs** and
(when the LB spec enables it) **service backend IPs**; the kernel would resolve
lazily and drop the first packets.

Pipeline:

1. **Forwardable IPs** table: `ForwardableIP{ip, owners[]{kind: node|service,
   id}}` — union of all remote node addresses (from the node manager) and
   backend addresses (LB spec, `enable-l2-neigh-discovery` + backend neighbors
   option). An IP is removed when its last owner is gone.
2. **Desired neighbors**: for each forwardable IP × each *selected* device that
   has a hardware address (L2 devices; `cilium_*`, tunnels and L3 devices are
   skipped): `RTM_GETROUTE` with `RTA_OIF = device`, `RTM_F_FIB_MATCH`, `RTM_F_LOOKUP_TABLE`
   for the IP. If the route has a gateway the next hop is the gateway; with
   `RTA_MULTIPATH` every path's gateway on that device is a next hop; without a
   gateway the IP itself is the next hop (on-link). Unreachable (`ENETUNREACH`,
   `EHOSTUNREACH`) → no desired neighbor for that device
   (`flowsdn_neighbor_nexthop_lookup_total{result=failed}`).
   Recalculation is rate-limited to 1 per 15 s per trigger burst and runs a
   **full resync every 5 min** and on every change of `devices`,
   `forwardable-ips`, or `routes`.
3. **Reconcile** into the kernel (`neighbors` table is the realized view):
   `RTM_NEWNEIGH` `NLM_F_CREATE|NLM_F_REPLACE`, `ndm_state = NUD_NONE`,
   `NDA_FLAGS = NTF_EXT_LEARNED`, `NDA_FLAGS_EXT = NTF_EXT_MANAGED`. The kernel
   then resolves and periodically refreshes the entry itself. Entries in the
   kernel with `NTF_EXT_LEARNED` on a selected device that are not desired are
   deleted (prune, at initialization and every resync); entries without
   `NTF_EXT_LEARNED` are never touched (static entries of the administrator).

**DEVIATION**: the reference probes for managed neighbors (create a veth in a
throwaway netns, add a neighbor with `NTF_EXT_MANAGED`, read it back) and
falls back to `NTF_EXT_LEARNED|NTF_USE` with an initial `NUD_STALE` insert
plus a userspace refresher that re-arms entries reported `NUD_STALE` by the
neighbor subscription. flowsdn's floor is 6.6 (managed neighbors are 5.16+),
so the fallback is **not implemented**; the probe remains as part of the
startup check (kernel-requirements §4.7) and its failure is fatal when neighbor
management is enabled (ADR-0001: refuse, don't adapt). The `NTF_USE` mode is
documented here only so a future decision can restore it.

### 3.5 MTU

#### 3.5.1 Base MTU

`base MTU` = minimum `mtu` over the selected devices, excluding `cilium_vxlan`,
`cilium_geneve`, `cilium_ipip4`, `cilium_ipip6` and kind `dummy`; in ENI mode
only the primary ENI counts. When no device is selected, base = 1500
(`EthernetMTU`). `mtu` (config) > 0 overrides the base outright. Maximum is
`MaxMTU = 65520`. The derived values are recomputed on every change of the
selected devices' MTUs and published as a `route-mtu` table row per prefix
(`0.0.0.0/0`, `::/0`) so endpoints (spec 08 updates `lxc*` and container
default routes) and the routes above (§3.2.3) can follow.

#### 3.5.2 Derivation

Constants (bytes): `TunnelOverheadIPv4 50`, `TunnelOverheadIPv6 70`,
`DsrTunnelOverhead 12`, `EncryptionIPsecOverhead 77`,
`EncryptionDefaultAuthKeyLength 16`, `WireguardOverhead 95`, `IPv6MinMTU 1280`,
`IPIPv4Overhead 20`, `IPIPv6Overhead 48`.

```
DeviceMTU            = base (1500 if 0)
tunnel               = TunnelOverheadIPv4 | TunnelOverheadIPv6 by underlay family
ipsec                = EncryptionIPsecOverhead + (authKeySize − 16)          (0 when IPsec off)

RouteMTU:
  WireGuard on, tunnel on      → DeviceMTU − (WireguardOverhead + tunnel)
  WireGuard on, tunnel off     → DeviceMTU − WireguardOverhead
  tunnel off, IPsec off        → DeviceMTU
  tunnel off, IPsec on         → base − ipsec        (if that is 0: 1500 − 77)
  tunnel on                    → base − (tunnel + ipsec)
                                 if ≤ 0: 1500 − tunnel [− 77 when IPsec]
RoutePostEncryptMTU  = DeviceMTU
```

Additional rules: DSR with `geneve` dispatch subtracts `DsrTunnelOverhead`
(12) from `RouteMTU` when the tunnel device is used for DSR; DSR `ipip` uses
`IPIPv4Overhead`/`IPIPv6Overhead` on the IPIP devices' MTU; the WireGuard
device MTU is `DeviceMTU − 95`, clamped to at least 1280 when IPv6 is enabled;
`RouteMTU` MUST never be below 1280 when IPv6 is enabled (startup error
`"MTU too small for IPv6"` otherwise). CNI chaining honors `RouteMTU` only
with `enable-route-mtu-for-cni-chaining=true` (spec 09).

`DeviceMTU` is applied to `cilium_host`, `cilium_net`, tunnel devices and every
endpoint device; `RouteMTU` to remote node routes, container default routes and
table 2005's default route (`RoutePostEncryptMTU` for table 200 routes).

#### 3.5.3 BIG TCP

`enable-ipv6-big-tcp` (kernel ≥ 5.19) and `enable-ipv4-big-tcp` (≥ 6.3; both
present on the 6.6 floor). In tunnel mode also requires the "BIG TCP over UDP
tunnels" capability, probed at startup (absent → startup error `"BIG TCP in
tunneling mode requires pending kernel support"`). Rejected (startup error)
with IPsec, with legacy host routing, and with DSR `ipip` dispatch.

Procedure over the selected devices (plus the tunnel device when supported):

1. Read `IFLA_GSO_MAX_SIZE`, `IFLA_GSO_IPV4_MAX_SIZE`, `IFLA_GRO_MAX_SIZE`,
   `IFLA_GRO_IPV4_MAX_SIZE`, `IFLA_TSO_MAX_SIZE`; record originals.
2. `gsoLimit = min(196608, min over devices of tso_max_size)`; `groLimit =
   min(196608, 8 × 65535)` (= 196608 unless a device reports less).
3. For each device set `gso_max_size = gsoLimit`, `gro_max_size = groLimit`
   (IPv6) and/or the `_ipv4_` pair (IPv4), via `RTM_SETLINK`. Failure on one
   device → restore originals on all devices already modified, disable the
   feature, warn.
4. When a family's BIG TCP is disabled but a device still carries a size >
   65536 from a previous run, reset it to 65536 (`GROGSOLegacyMaxSize`).
5. The resulting sizes are published to the connector (spec 08) so endpoint
   devices get the same GSO/GRO sizes, and into `.rodata` where the datapath
   needs them (spec 02).

### 3.6 Sysctls

Written through `/proc/sys` (host `/proc` mounted at `/host/proc` in the
container is used when present; the reference's `nsenter`-based init container
is not used). Each write is `Sysctl{name, value, ignore_err, warn}` in the
`sysctl` table with a reconciler (spec 00 §3.2) whose target writes the file
and reads it back; a caller that needs the value in place before continuing
waits for `Done` with a 1 s timeout (`"sysctl <k> not reconciled within 1s"`
is an error unless `ignore_err`).

| Key | Value | When | ignore_err |
|---|---|---|---|
| `net.core.bpf_jit_enable` | 1 | datapath init | yes (warn: "Unable to ensure that BPF JIT compilation is enabled…") |
| `net.ipv4.conf.all.rp_filter` | 0 | datapath init | no |
| `net.ipv4.fib_multipath_use_neigh` | 1 | datapath init | yes |
| `kernel.unprivileged_bpf_disabled` | 1 | datapath init | yes |
| `kernel.timer_migration` | 0 | datapath init | yes |
| `net.ipv6.conf.all.disable_ipv6` | 0 | IPv6 enabled | no |
| `net.core.fb_tunnels_only_for_init_net` | 2 | IPIP devices | yes |
| `net.ipv4.ip_forward` | 1 | datapath init | no |
| `net.ipv4.conf.all.forwarding`, `net.ipv6.conf.all.forwarding` | 1 | datapath init (v6 when enabled) | no |
| `net.ipv4.conf.<dev>.forwarding` | 1 | `cilium_host`, `cilium_net` creation | no |
| `net.ipv4.conf.<dev>.rp_filter` | 0 | `cilium_host`, `cilium_net`, every `lxc*`, `cilium_wg0`, tunnel devices; ENI secondary interfaces | no |
| `net.ipv4.conf.<dev>.accept_local` | 1 | `cilium_host`, `cilium_net` | no |
| `net.ipv4.conf.<dev>.send_redirects` | 0 | `cilium_host`, `cilium_net` | no |
| `net.ipv6.conf.<dev>.forwarding` | 1 | `cilium_host`, `cilium_net` when IPv6 | no |
| `net.ipv4.conf.<primary ENI>.rp_filter` | 2 | ENI mode (deferred) | no |
| `net.ipv4.ip_local_reserved_ports` | += NodePort range when it overlaps `ip_local_port_range` | KPR + `enable-auto-protect-node-port-range` | no |
| `net.core.default_qdisc` | `fq` | bandwidth manager | no |
| `net.ipv4.tcp_congestion_control` | `bbr` (with `enable-bbr`) else left alone; on BBR disable restore `cubic` | bandwidth manager | no |
| `net.ipv4.tcp_slow_start_after_idle` | 0 | BBR | no |
| `net.core.netdev_max_backlog` ≥ 1000, `net.core.somaxconn` ≥ 4096, `net.ipv4.tcp_max_syn_backlog` ≥ 4096 | raised to the baseline only if lower | bandwidth manager | no |
| `net.ipv4.tcp_mtu_probing`, `tcp_base_mss`, `tcp_mtu_probe_floor` | per `packetization-layer-pmtud-mode` (deferred) | | |

**Removed**: `net.ipv4.ip_early_demux=0` (`enable-xt-socket-fallback`) — the
`nft_socket` expression does not have `xt_socket`'s COS-kernel absence problem
(**DEVIATION**, ADR-0003).

**Persistence against `systemd-sysctl`**: distributions re-apply
`rp_filter=1` on hot-plug. flowsdn writes
`/etc/sysctl.d/99-zzz-override_flowsdn.conf` through the `/host/etc` hostPath
when writable, containing `net.ipv4.conf.all.rp_filter = 0` and the per-device
`lxc*`/`cilium_*` keys as glob lines (`net.ipv4.conf.lxc*.rp_filter = 0`);
per-device values are also re-asserted at every device creation (the file is
belt-and-braces, not the mechanism). The reference file name
`99-zzz-override_cilium.conf`, if present, is left in place.

### 3.7 Bandwidth manager

`enable-bandwidth-manager=true` (keep-but-simplify per inventory 03):

- **Sysctls** as in §3.6 (baselines raised, `default_qdisc=fq`, BBR keys when
  `enable-bbr`). `enable-bbr` requires `bpf_skb_set_tstamp` (5.18; present) and
  BPF host routing unless `enable-bbr-hostns-only`; incompatible with IPsec
  (startup error).
- **Qdiscs** on every selected device (table `bandwidth-qdiscs`, one reconciler):
  if the device has more than one TX queue: root `mq` (handle `8000:`) with one
  `fq` leaf per TX queue (parent `8000:<n>`), each `fq` with `TCA_FQ_HORIZON =
  2 000 000 µs` (2 s, = the EDT map's `DefaultDropHorizon`), `TCA_FQ_BUCKETS_LOG`
  such that buckets = 15 … the reference sets `Buckets: 15` and `Pacing: 1`;
  single-queue devices get a root `fq` with the same parameters. Existing
  `mq`/`fq` with matching parameters are left alone; anything else at root is
  replaced (`RTM_NEWQDISC` + `NLM_F_REPLACE`). Bond masters get `noqueue` at
  root (the slaves carry the `fq`). On disable, qdiscs are **not** reverted
  (reference behavior; the default `fq` is harmless).
- **EDT map** `cilium_throttle`: `edt_id{id u32, direction u8, pad[3]}` →
  `edt_info{bps u64, t_last u64, t_horizon_drop u64, prio u32, pad}` written
  by the endpoint manager from pod annotations `kubernetes.io/egress-bandwidth`,
  `kubernetes.io/ingress-bandwidth`, `bandwidth.cilium.io/priority` (QoS default
  priorities: Guaranteed 7, Burstable 9, BestEffort 6; the host endpoint is
  pinned to Guaranteed with bps 0 = unlimited). Layout and pin per spec 01.
- `.rodata` gate `ENABLE_BANDWIDTH_MANAGER` (spec 02 §6.2).

### 3.8 Socket LB cgroup root

- Root path `cgroup-root` (default `/run/cilium/cgroupv2`). If the path is not
  a `cgroup2` mount (`statfs` magic `CGROUP2_SUPER_MAGIC`), create it and
  `mount("none", path, "cgroup2", 0, "")`. A path mounted with a different
  filesystem is a fatal error. A second cgroup2 root mount is harmless; what
  matters is that programs attach to the **root** cgroup so every pod's netns
  inherits them. cgroup v1-only hosts cannot run socket LB (fatal when enabled).
- Attach per spec 01 §3.9 (pinned links under
  `/sys/fs/bpf/cilium/socketlb/links/cgroup/<prog>`). **Which of the 13
  programs**: `cil_sock4_{connect,sendmsg,recvmsg}` when IPv4;
  `cil_sock4_getpeername` when the getpeername hook is supported (5.8; always
  on the floor) and socket-LB peer lookups are enabled; `cil_sock4_post_bind`
  when KPR and `node-port-bind-protection`; `cil_sock4_pre_bind` when the
  health datapath is enabled; the `cil_sock6_*` mirror set when IPv6 is
  enabled **or** when IPv4-only but the kernel has IPv6 (v4-mapped sockets;
  detected by successfully opening an `AF_INET6` socket); `cil_sock_release`
  when either family. Programs not in the set are detached.
- `pkg/cgroups/manager`-equivalent (pod cgroup ID tracking for socket-LB
  tracing) is deferred with Hubble socket tracing.

### 3.9 kube-proxy replacement mode and host routing

`kube-proxy-replacement` (bool; immutable). `true` implies `bpf-lb-sock=true`.
Validation and derived settings at startup, in order:

1. **BPF host routing** is on unless `enable-host-legacy-routing=true`. It is
   **downgraded to legacy** (`EnableHostLegacyRouting := true`, log `"BPF host
   routing requires kube-proxy-replacement. Falling back to legacy host routing
   (enable-host-legacy-routing=true)."`) when `kube-proxy-replacement=false`,
   because kube-proxy must see the packets in the host stack. **DEVIATION**:
   the reference also downgrades when iptables masquerading is enabled; that
   condition cannot occur in flowsdn (spec 04 §3.12: `enable-ipv4-masquerade`
   without `enable-bpf-masquerade` is a startup error; ADR-0003).
2. `bpf-lb-rss-ipv4-src-cidr`/`-ipv6-` validated as CIDRs of the right family;
   only allowed with DSR `ipip` dispatch.
3. DSR `ipip` dispatch → IPIP devices + IPIP termination enabled.
4. XDP acceleration with IPv6 underlay → error `"XDP acceleration cannot be
   used with an IPv6 underlay"`; XDP with IPsec/WireGuard N/S encryption →
   warning that N/S traffic bypasses encryption.
5. Tunnel `vxlan` + DSR (any dispatch except via annotation-mode `ipip`) →
   error `"Node Port dsr mode cannot be used with vxlan tunneling"`; tunnel +
   DSR requires `geneve` dispatch with `geneve` tunnel protocol.
6. `install-no-conntrack-iptables-rules` requires KPR with socket LB **and**
   `enable-bpf-masquerade` (error otherwise) — the key is kept (it maps to the
   pod-CIDR `notrack` rules in §3.10.5).
7. Socket LB requires cgroup attach (§3.8); `getpeername` hook presence is
   part of the startup check (always present on 6.6).
8. Health datapath (`bpf_getsockopt/setsockopt` in `cgroup/sock_addr`, 5.12)
   is present on the floor.
9. NodePort range (`node-port-range`, default `30000-32767`) MUST NOT lie
   after the ephemeral range; with `enable-auto-protect-node-port-range` the
   overlapping part is added to `ip_local_reserved_ports`.
10. With DSR and more than one selected device, warn if
    `net.ipv4.conf.<direct-routing-device>.rp_filter == 1`: `"DSR might not
    work for requests sent to other than <dev> device. Run 'sysctl -w
    net.ipv4.conf.<dev>.rp_filter=2' (or set to '0') on each node to fix"`.
11. `bpf-lb-sock-hostns-only` without socket LB → warning only.
12. MKE cgroup v1 `net_cls` marking — **not implemented** (deferred, inventory).

**BPF host routing prerequisites** (for spec 02 `fib_redirect`):
`bpf_redirect_neigh` and `bpf_redirect_peer` (5.10; startup check), KPR on,
BPF masquerade on when masquerading. In legacy mode packets to/from pods
traverse the host stack, which is why the `0xC00` host-mark rule and the
proxy/`notrack` rules matter more there (§3.10).

**XDP acceleration** (`bpf-lb-acceleration`): `native` → driver mode
(`XDP_FLAGS_DRV_MODE`), `best-effort` → driver, fall back to generic per
device, `testing-only` → generic (`XDP_FLAGS_SKB_MODE`), `disabled` → detach.
Several enablers (NodePort, egress gateway HA, prefilter) each request a mode;
`native` beats `best-effort`; two different non-disabled explicit modes →
error `"XDP mode conflict: trying to set conflicting modes <a> and <b>"`.

### 3.10 The nftables residual (ADR-0003)

#### 3.10.1 Principles

- flowsdn owns exactly one table, **`inet flowsdn`**, and MUST NOT create,
  modify, flush or delete any other table, chain, set or rule — not
  `ip filter`, not `inet firewalld`, not the iptables-nft compatibility tables.
- The desired content of the table is a **pure function** of configuration,
  the tunnel port, the set of active proxy ports (L7 spec), the set of pod
  no-track ports (endpoint manager), and the set of pod CIDRs (§3.10.5).
- Every change is applied as **one atomic netlink batch** that replaces the
  whole table: `NFNL_MSG_BATCH_BEGIN`, `NFT_MSG_NEWTABLE inet flowsdn`
  (idempotent create), `NFT_MSG_DELTABLE inet flowsdn` (deletes the table and
  everything in it — now guaranteed to exist), `NFT_MSG_NEWTABLE`,
  `NFT_MSG_NEWCHAIN` ×N, `NFT_MSG_NEWRULE` ×M, `NFNL_MSG_BATCH_END`. The
  kernel commits or rejects the whole batch; no packet observes a partial rule
  set, and no rename/backup-chain dance is needed. When the desired set is
  **empty** the batch is `NEWTABLE, DELTABLE` (table absent afterwards) so an
  idle node carries no nftables state at all.
- Changes are debounced (200 ms) and coalesced; a full recompute-and-replace
  runs every 30 min and whenever an `NFNLGRP_NFTABLES` event names our table
  (someone else touched it). Generation ID (`NFT_MSG_GETGEN`) is recorded for
  the metrics.
- The agent MUST NOT shell out; no `nft`, `iptables`, `ip6tables`, `ipset`
  binaries exist in the image.
- **Kernel modules autoload**: sending the first `NFNL_SUBSYS_NFTABLES` message
  makes `nfnetlink` request `nf_tables`; creating a base chain of family
  `inet` requests `nf_tables_inet`; each expression (`ct`, `tproxy`, `socket`)
  is requested by name (`nft-expr-<name>`) when first referenced. The agent
  needs no `CAP_SYS_MODULE`; on a stormcos node the modules must be in the
  image (kernel-requirements §2.6 config fragment).

#### 3.10.2 Table layout

Chains are created only when at least one rule needs them. Priorities are the
standard nftables ones (raw −300 runs before conntrack at −200; mangle −150;
filter 0). All base chains have `policy accept`.

| Chain | `type hook priority` | Holds |
|---|---|---|
| `raw_prerouting` | `filter prerouting -300` | all `notrack` rules for inbound/forwarded traffic |
| `raw_output` | `filter output -300` | all `notrack` rules for locally originated traffic |
| `mangle_prerouting` | `filter prerouting -150` | socket-transparent mark, TPROXY, ENI ct-mark |
| `filter_output` | `filter output 0` | host mark `0xC00` |

No `forward`, `input` accept chains: see §3.10.6 (DEVIATION with rationale).

#### 3.10.3 Rule catalogue

Notation is nft syntax for readability; the implementation encodes the
equivalent expressions (§4.5). `<tp>` = tunnel port, `<pp>` = proxy port,
`<lxc>` = delivery interface pattern (`"lxc*"`), all masks hexadecimal.
Presence column = condition under which the rule is in the desired set. IPv4
and IPv6 variants are emitted where the rule mentions an address family; mark
and port rules in the `inet` family cover both at once.

**Tunnel** (presence: encapsulation enabled — `routing-mode=tunnel` or a
feature that creates the tunnel device):

```
raw_prerouting:  udp dport <tp> notrack       comment "flowsdn: notrack tunnel"
raw_output:      udp dport <tp> notrack
```

**WireGuard** (presence: `encryption.type=wireguard`): same two rules with
`udp dport 51871`.

**Encryption marks** (presence: IPsec **or** WireGuard):

```
raw_prerouting:  meta mark & 0xf00 == 0xd00 notrack      comment "flowsdn: notrack decrypt"
raw_prerouting:  meta mark & 0xf00 == 0xe00 notrack      comment "flowsdn: notrack encrypt"
raw_output:      meta mark & 0xf00 == 0xd00 notrack
raw_output:      meta mark & 0xf00 == 0xe00 notrack
```

**Proxy, static** (presence: L7 proxy enabled and `enable-bpf-tproxy=false`;
with `enable-bpf-tproxy=true` only the `notrack` rules remain because the
datapath performs the redirect with `bpf_sk_assign`):

```
raw_prerouting:  meta mark & 0xf00 == 0x200 notrack                          # to proxy
raw_output:      oifname <lxc> meta mark & 0xfffffeff == 0xa00 notrack       # proxy return → pod (endpoint-routes mode only, when <lxc> ≠ cilium_host)
raw_output:      oifname <lxc> meta mark & 0xe00 == 0x800 notrack            # L7 upstream → pod (same)
raw_output:      oifname "cilium_host" meta mark & 0xfffffeff == 0xa00 notrack
raw_output:      oifname "cilium_host" meta mark & 0xe00 == 0x800 notrack
raw_output:      oifname "cilium_host" meta mark & 0xf00 == 0xb00 notrack    # proxy forward, IPsec only
mangle_prerouting:
    socket transparent 1 iifname != "lo" meta mark & 0xf00 != 0xe00 meta mark & 0xf00 != 0x800 meta mark set 0x200
```

The `socket transparent` rule (replaces `-m socket --transparent`) marks
packets that belong to an existing transparent proxy socket so they are routed
to the local stack via rule pref 9 / table 2004 *without* going through
TPROXY again; it MUST precede the TPROXY rules in the chain. It excludes
IPsec-encrypted packets and `MarkSkipTProxy` (`0x800`) packets.

**Proxy, per port** (presence: for each active proxy redirect `(name, port,
ip)`; `ip` = `127.0.0.1` for IPv4, `::1` for IPv6):

```
mangle_prerouting:  meta l4proto tcp meta mark == (0x200 | htons(<pp>) << 16) tproxy ip  to 127.0.0.1:<pp> meta mark set 0x200 accept
mangle_prerouting:  meta l4proto udp meta mark == (0x200 | htons(<pp>) << 16) tproxy ip  to 127.0.0.1:<pp> meta mark set 0x200 accept
mangle_prerouting:  meta l4proto tcp meta mark == (0x200 | htons(<pp>) << 16) tproxy ip6 to [::1]:<pp>     meta mark set 0x200 accept
mangle_prerouting:  meta l4proto udp meta mark == (0x200 | htons(<pp>) << 16) tproxy ip6 to [::1]:<pp>     meta mark set 0x200 accept
```

The match is a **full 32-bit** mark equality: the datapath writes
`0x200 | (proxy_port_be << 16)` (spec 02 §2.1); the `tproxy` statement is
non-terminal in nftables, hence the explicit `meta mark set 0x200` (the
"tproxy-mark", making pref-9 rule deliver locally) and `accept`. The L7 spec
owns the set of `(name, port)`; the reference's "restore proxy ports from the
iptables comment" (`GetProxyPorts`) is replaced by the L7 spec's own port
persistence (`<state-dir>/proxy-ports.json`) — **DEVIATION**, the rule set is
regenerated, never parsed.

**Host mark** (presence: `enable-host-firewall=true`, or legacy host routing,
or `kube-proxy-replacement=false`; see 12.3):

```
filter_output:  meta mark & 0xf00 != 0xd00  meta mark & 0xf00 != 0xe00  meta mark & 0xf00 != 0x400
                meta mark & 0xe00 != 0xa00  meta mark & 0xe00 != 0x800
                meta mark set (meta mark & 0xfffff0ff) | 0xc00          comment "flowsdn: host->any mark as from host"
```

(`--set-xmark 0xc00/0xf00` semantics: clear the magic nibble, set `0xC`.) It
tags locally originated packets that are not decrypt/encrypt/overlay/proxy so
that when they re-enter the datapath (e.g. via kube-proxy's DNAT to a pod) the
programs classify them as `reserved:host`.

**ENI multi-node NodePort connmark** (presence: `ipam=eni|alibabacloud`,
deferred with cloud IPAM; specified for completeness):

```
mangle_prerouting:  iifname <default-route-dev> fib daddr . iif type local  ct mark set ct mark | 0x80        comment "flowsdn: primary ENI"
mangle_prerouting:  iifname "lxc*" meta mark set (meta mark & 0xffffff7f) | (ct mark & 0x80)
```

(`--limit-iface-in --dst-type LOCAL` = `fib daddr . iif type local`; CONNMARK
restore with nfmask/ctmask 0x80 = the bitwise expression shown.) Together with
rule pref 109 (`fwmark 0x80/0x80 lookup main`) replies leave via the interface
the request arrived on.

**Per-pod no-track ports** (presence: for each pod on this node with
`policy.cilium.io/no-track-port=<port>[/<proto>]`, for each of its IPs `<ip>`
and protocol `<proto>` (default tcp; `ip` or `ip6` selected by family):

```
raw_prerouting:  ip daddr <ip> <proto> dport <port> notrack
raw_prerouting:  ip saddr <ip> <proto> sport <port> notrack
raw_output:      ip daddr <ip> <proto> dport <port> notrack
raw_output:      ip saddr <ip> <proto> sport <port> notrack
```

**Host no-track ports** (presence: union over pods with
`network.cilium.io/no-track-host-ports`, grouped by protocol, ports as an
anonymous set):

```
raw_prerouting:  <proto> dport { p1, p2, … } notrack     comment "flowsdn: no-track-host-ports"
raw_output:      <proto> sport { p1, p2, … } notrack
```

**Pod-CIDR no-track** (presence: `install-no-conntrack-iptables-rules=true`,
IPv4 only as in the reference, for each local IPv4 alloc CIDR):

```
raw_prerouting:  ip saddr <podCIDR> notrack
raw_prerouting:  ip daddr <podCIDR> notrack
raw_output:      ip saddr <podCIDR> notrack
raw_output:      ip daddr <podCIDR> notrack
```

Ordering inside a chain: pod-CIDR no-track first, then proxy, encryption,
tunnel, WireGuard, per-pod, host-ports (all are `notrack`, so order is
immaterial for correctness; the fixed order makes the rendered table stable
for tests and diffs).

#### 3.10.4 Delivery interface

`<lxc>` is `"lxc*"` when `enable-endpoint-routes=true` (packets to pods leave
the host via the pod's veth), else `cilium_host`; the `oifname <lxc>` proxy
rules are emitted only when it differs from `cilium_host`. For AWS-CNI
chaining the delivery interface is `"eni*"` (deferred).

#### 3.10.5 Disposition of every reference iptables rule

| Reference rule (table:chain) | flowsdn | Why |
|---|---|---|
| raw `CILIUM_PRE_raw`/`CILIUM_OUTPUT_raw` `-p udp --dport <tp> -j CT --notrack` | **residual** §3.10.3 tunnel | avoids conntrack cost on overlay |
| filter `CILIUM_OUTPUT` `-p udp --dport <tp> -j ACCEPT` | **dropped** (cross-table accept is a no-op, §3.10.6) | |
| mangle `CILIUM_PRE_mangle -p tcp/udp -m mark --mark 0x200\|port -j TPROXY …` | **residual** `tproxy` | kernel redirect to Envoy without BPF tproxy |
| mangle `-m socket --transparent ! -o lo -m mark ! 0xe00/0xf00 ! 0x800/0xf00 -j MARK --set-mark 0x200` | **residual** `socket transparent` | `nft_socket` replaces `xt_socket` |
| raw `--mark 0x200/0xf00 -j CT --notrack` (to proxy) | **residual** | |
| raw `-o <lxc\|cilium_host> --mark 0xa00/0xfffffeff -j CT --notrack` (proxy return) | **residual** | |
| raw `-o … --mark 0x800/0xe00 -j CT --notrack` (L7 upstream) | **residual** | |
| raw `-o cilium_host --mark 0xb00/0xf00 -j CT --notrack` (proxy forward, IPsec) | **residual** | |
| filter `CILIUM_INPUT --mark 0x200/0xf00 -j ACCEPT`, `CILIUM_OUTPUT --mark 0xa00/0xe00 -j ACCEPT`, `--mark 0x800/0xe00 -j ACCEPT` | **dropped** (§3.10.6) | |
| filter `CILIUM_FORWARD -o cilium_host`, `-i cilium_host`, `-i lxc+`, `-i cilium_net`, `-o/-i <delivery>` ACCEPT | **dropped** (§3.10.6; documented allow-list) | |
| filter `CILIUM_OUTPUT … -j MARK --set-xmark 0xc00/0xf00` (host mark) | **residual** (feature-gated) | |
| nat `CILIUM_POST_nat … -j MASQUERADE [--random-fully]` (all variants: per-interface, `! -d <native-cidr>`, `-o cilium_+` exclusion) | **dropped-because-BPF** | BPF masquerade is the only path (ADR-0001/0003; spec 04 §3.12) |
| nat `-s <alloc> -m set --match-set cilium_node_set_v4/v6 dst -j ACCEPT` + ipsets | **dropped-because-BPF** | the datapath's remote-node identity check replaces the ipset |
| nat `-m mark --mark 0xa00/0xe00 -j ACCEPT` (proxy return from masquerade) | **dropped-because-BPF** | no nat table |
| nat `! -s <alloc> ! -d <alloc> -o cilium_host -j SNAT --to-source <router IP>` (tunnel host→cluster) | **dropped-because-BPF** | spec 04 §3.10/3.12: host-origin SNAT is done in `to_overlay`/`to_netdev` |
| nat `-s 127.0.0.1 -o lxc+ -j SNAT --to-source <router IP>` | **dropped-because-BPF** | loopback-source hairpin handled by the datapath (spec 02 §3.19) |
| nat `--mark 0xf00/0xf00 -o lxc+ --ctstate DNAT -j SNAT` (hairpin) | **dropped-because-BPF** | kube-proxy DNAT hairpin does not exist with KPR; in legacy mode the LB spec's hairpin path applies |
| nat `-j SNAT` "via source route" (`enable-masquerade-to-route-source`) | **dropped-because-BPF** | key kept; spec 04 implements with `BPF_FIB_LOOKUP_SRC` |
| raw NOTRACK `0xd00/0xf00`, `0xe00/0xf00` (encryption) | **residual** | |
| filter/nat ACCEPT for `0xd00`, `0xe00` marks; WireGuard `udp dport 51871 ACCEPT` | **dropped** (§3.10.6) | |
| raw NOTRACK `udp dport 51871` (WireGuard) | **residual** | |
| mangle CONNMARK `0x80` set/restore (ENI) | **residual** `ct mark` (deferred with cloud IPAM) | |
| raw `-s/-d <podCIDR> -j CT --notrack` (`install-no-conntrack-iptables-rules`) | **residual** | |
| per-pod `no-track-port` raw NOTRACK ×4 | **residual** | |
| per-pod `no-track-port` filter ACCEPT ×5 | **dropped** (§3.10.6) | |
| `no-track-host-ports` raw multiport NOTRACK ×2 | **residual** (anonymous set) | |
| feeder rules `-j CILIUM_*` in INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING, chain rename/copy update model, `-S` parsing, `xtables.lock` | **dropped-with-feature** | no iptables |
| `enableIPForwarding` sysctl side effect | kept as sysctl (§3.6) | |
| transient rules during endpoint restore (`transientRulesStart`: `-m comment "cilium-transient" -j ACCEPT`) | **dropped-with-feature** | |

#### 3.10.6 Coexistence with a host firewall

nftables evaluates **every** base chain registered at a hook, across all
tables, in priority order; a verdict in one table does not stop chains of
other tables. Therefore an `accept` in `inet flowsdn` cannot override a `drop`
policy or rule in `inet firewalld`, `ip filter` (iptables-nft) or a
distribution firewall — unlike the reference, whose `ACCEPT` in
`CILIUM_FORWARD` terminated the very `FORWARD` chain whose policy was `DROP`.
**Resolved #131:** ADR-0003 now agrees that flowsdn installs **no accept rules**
to override another table. They would not bypass its drop policy. Instead:

- **Detection**: at startup and on every `NFNLGRP_NFTABLES` event, dump all
  base chains (read-only `NFT_MSG_GETCHAIN`); if any chain of another table
  hooks `forward` or `input` with `policy drop`, or the legacy `ip filter
  FORWARD`/`INPUT` chain has policy drop, set health `Degraded("host firewall
  with default-drop detected on <table> <chain>; see flowsdn firewall
  coexistence")` and log the allow-list below once.
- **Documented allow-list** (what such a firewall must permit; the datapath
  needs these because packets to/from pods traverse the `forward` hook only in
  legacy host routing or endpoint-routes mode, and the `input`/`output` hooks
  for tunnel, WireGuard, proxy and health traffic): `udp dport <tp>` in and
  out; `udp dport 51871` (WireGuard); `meta mark & 0xf00 == 0x200` on input;
  `meta mark & 0xe00 == 0xa00` and `& 0xe00 == 0x800` on output; forward
  `iifname/oifname { cilium_host, cilium_net, "lxc*" }`; per-pod no-track
  ports. `cilium-dbg`-compatible surface: `GET /debuginfo` includes the
  rendered `inet flowsdn` table and the allow-list.
- **What still works regardless**: `notrack`, `tproxy`, `socket`, `meta mark
  set`, `ct mark` act on the packet, not on a verdict, so every residual rule
  in §3.10.3 is effective in the presence of any other table.
- The `ct state invalid drop` rule kube-proxy ≥ 1.15 installs is harmless in
  flowsdn's default mode (BPF host routing bypasses the stack for pod↔pod and
  pod↔external) and is exactly why the `notrack` rules exist for the paths
  that do traverse the stack.
- iptables-legacy on the host (no nft backend) coexists trivially: it is a
  separate netfilter hook chain; flowsdn never touches it.

### 3.11 Startup and shutdown order (this area)

```
config frozen → startup check (kernel-requirements §4.7 incl. nf_tables load probe
  when any residual is configured, managed-neighbor probe when neighbors enabled)
→ netlink subscriptions + dumps → [devices initialized]
→ local node steps 1–3 → sysctls (global) → cilium_host/cilium_net, tunnel/IPIP devices,
  router IP, addresses → MTU table → local rule relocation, IPsec/proxy rules
→ node IDs restore → node manager starts (checkpoint restore, CiliumNode watch)
→ loader attaches programs (spec 01) → nftables residual first transaction
→ CiliumNode publish → neighbors, bandwidth qdiscs, BIG TCP
→ [agent-ready]
shutdown: stop reconcilers; write node checkpoint; leave every kernel object in place
  (routes, rules, devices, nftables table, neighbors, qdiscs, sysctls) so a restart is
  non-disruptive; `flowsdn-agent --cleanup` (or the CNI uninstall path) removes them.
```

## 4. Data model

### 4.1 Tables (all in `flowsdn-table`; keys per spec 00 §3.1.2 encodings)

See §3.1.1 for `devices`, `routes`, `neighbors`, `node-addresses`. Additional:

| Table | Row | Primary key |
|---|---|---|
| `desired-routes` | `DesiredRoute{owner: &'static str, table u32, prefix, priority u32, nexthop: Option<Addr>, src: Option<Addr>, device_index, scope u8, type u8 (unicast/local), mtu: Option<u32>, admin_distance u8}` — reconciled into the kernel; several owners may desire the same `(table, prefix, priority)`; lowest admin distance wins | `(table, prefix, priority)` + owner as secondary |
| `desired-rules` | `Rule{family, priority u32, fwmark: Option<(u32 mark, u32 mask)>, from: Option<Prefix>, to: Option<Prefix>, table u32}` | `(family, priority, selector bytes)` |
| `forwardable-ips` | `ForwardableIP{addr, owners: Vec<Owner{kind: Node\|Service, id: String}>}` | `addr` |
| `desired-neighbors` | `DesiredNeighbor{addr, link_index}` | `(link_index, addr)` |
| `route-mtu` | `RouteMTU{prefix, device_mtu u32, route_mtu u32, route_post_encrypt_mtu u32}` | `prefix` |
| `sysctl` | `Sysctl{name: String ("net.ipv4.conf.eth0.rp_filter"), value: String, ignore_err: bool, warn: Option<String>}` | `name` |
| `bandwidth-qdiscs` | `BandwidthQdisc{link_index, link_name, fq_horizon: Duration, fq_buckets: u32}` | `link_index` |
| `nodes` | `Node` (§4.3) | `Identity{cluster, name}` |
| `nft-desired` | single row: `NftTable{rules: Vec<NftRule>, generation: u64}` | constant |

### 4.2 Constants

```
RouteTableIPSec 200, RouteTableVtep 202, RouteTableToProxy 2004, RouteTableFromProxy 2005,
RouteTableInterfacesOffset 10, MainTable 254, LocalTable 255
RulePriorityIPsecDecrypt 1, ToProxyIngress 9, FromProxy 10, Ingress 20, LocalLookup 100,
Nodeport 109, Egress 110, Egressv2 111, Vtep 112
RTProto RTPROT_KERNEL (2)
MarkSkipTProxy 0x800, RouteMarkDecrypt 0xD00, RouteMarkEncrypt 0xE00, RouteMarkMask 0xF00,
OutputMarkMask 0xFFFFFF00, MarkMultinodeNodeport 0x80
MTU constants: §3.5.2.  BIG TCP: bigTCPMaxSize 196608, legacy 65536, GRO ceiling 8*65535
Neighbor: resync 5 min, calculator rate 1 per 15 s
Node: checkpoint min interval 1 min, background sync base 1 min, node ID range 1..65535
CiliumNode: 10 retries × 500 ms; node-init-timeout 15 min
nft: debounce 200 ms, full resync 30 min
```

### 4.3 `Node` (kvstore JSON and checkpoint; frozen for clustermesh peers)

```
Node {
  Name: String, Cluster: String, ClusterID: u32,
  IPAddresses: [ {Type: "InternalIP"|"ExternalIP"|"CiliumInternalIP", IP: String} ],
  IPv4AllocCIDR: Option<CIDR>, IPv4SecondaryAllocCIDRs: [CIDR],
  IPv6AllocCIDR: Option<CIDR>, IPv6SecondaryAllocCIDRs: [CIDR],
  IPv4HealthIP, IPv6HealthIP, IPv4IngressIP, IPv6IngressIP: Option<IP>,
  Source: "local"|"kubernetes"|"custom-resource"|"kvstore"|"restored"|…,
  EncryptionKey: u8, Labels: map, Annotations: map, WireguardPubKey: String, BootID: String
}
LocalNode { node: Node, uid, provider_id, opt_out_node_encryption: bool,
            ipv4_native_routing_cidr, ipv6_native_routing_cidr, service_loopback_ipv4/6,
            is_being_deleted: bool, underlay: Ipv4|Ipv6 }
```

Field names in JSON MUST match the reference's `json:` tags (`Name`,
`Cluster`, `IPAddresses`, `IPv4AllocCIDR`, `IPv4SecondaryAllocCIDRs`,
`IPv6AllocCIDR`, `IPv6SecondaryAllocCIDRs`, `IPv4HealthIP`, `IPv6HealthIP`,
`IPv4IngressIP`, `IPv6IngressIP`, `ClusterID`, `Source`, `EncryptionKey`,
`Labels`, `Annotations`, `WireguardPubKey`, `BootID`); addresses as
`{"Type":..,"IP":..}`.

### 4.4 BPF map written here

`cilium_node_map_v2` — layout frozen in spec 01 §4.4: `node_key{pad1 u16, pad2
u8, family u8 (1 IPv4, 2 IPv6), ip[16] (IPv4 in first 4 bytes)}` →
`node_value{id u16, spi u8, pad u8}`. Writers: node ID allocator only.

### 4.5 nftables wire model (`flowsdn-nft`)

```
NftTable   { family: NFPROTO_INET (1), name: "flowsdn", chains: Vec<NftChain> }
NftChain   { name, hook: Prerouting|Output, priority: i32 (-300|-150|0), type: "filter", policy: Accept,
             rules: Vec<NftRule> }
NftRule    { exprs: Vec<Expr>, comment: Option<String> (NFTA_RULE_USERDATA, ≤ 128 bytes) }
Expr       = Meta{key: L4PROTO|MARK|IIFNAME|OIFNAME|NFPROTO, dreg}
           | Payload{base: NETWORK|TRANSPORT, offset, len, dreg}       # ip saddr/daddr, ip6 …, udp/tcp ports
           | Cmp{sreg, op: EQ|NEQ, data}
           | Bitwise{sreg, dreg, len, mask, xor}                       # mark & mask, mark set (m & ~x) | y
           | Immediate{dreg|verdict, data}                             # mark set, accept
           | Lookup{sreg, set}  + anonymous Set{ elements }            # port sets
           | Notrack
           | Ct{key: MARK, dreg | sreg (set)}
           | Tproxy{family, addr_reg, port_reg}
           | Socket{key: TRANSPARENT, dreg}
           | Fib{flags: DADDR|IIF, result: TYPE, dreg}
Batch      = [NFNL_MSG_BATCH_BEGIN, NFT_MSG_NEWTABLE, NFT_MSG_DELTABLE, NFT_MSG_NEWTABLE,
              NFT_MSG_NEWCHAIN*, NFT_MSG_NEWRULE* (NLM_F_APPEND), NFNL_MSG_BATCH_END]
```

Mark expressions: `meta mark & M == V` = `Meta(MARK)→r1; Bitwise(r1, mask M,
xor 0)→r1; Cmp(r1, EQ, V)`. `meta mark set (mark & A) | B` = `Meta(MARK)→r1;
Bitwise(r1, mask A, xor B)→r1; Meta(MARK) set from r1`. The `inet` family
rules that use `ip`/`ip6` payload MUST be prefixed with `Meta(NFPROTO) == 
IPv4|IPv6` (the kernel requires a family dependency for L3 payloads in `inet`).

### 4.6 Files

| Path | Content |
|---|---|
| `<state-dir>/nodes.json` | node checkpoint (JSON array of `Node`) |
| `/sys/fs/bpf/cilium/tc/globals/cilium_node_map_v2` | pinned node map (spec 01 path scheme) |
| `/run/cilium/cgroupv2` | cgroup2 mount |
| `/host/etc/sysctl.d/99-zzz-override_flowsdn.conf` | rp_filter persistence |
| `<state-dir>/proxy-ports.json` | proxy ports (L7 spec; input to §3.10.3) |

No `device-reconciler.wal` (owned VLAN sub-devices are deferred with cloud
IPAM; when added, the owner list persists in a table checkpoint file).

## 5. Algorithms

### 5.1 Device selection evaluation order

For each device in a batch: filter match (§3.1.2) → if matched, done;
`force-device-detection` or empty filter → predicates 1–9 in order (§3.1.3).
Re-evaluate all devices when the `routes` batch adds/removes a default or
universe-scope route (predicates 8, 9 depend on routes) and when a master
device appears (predicate 4).

### 5.2 Route reconciliation (the `desired-routes` reconciler)

Target = kernel via `RTM_NEWROUTE` with `NLM_F_CREATE|NLM_F_REPLACE`
(`ip route replace` semantics; the kernel matches on `(table, dst, priority,
tos)` so a route with a different nexthop/device is replaced in place, never
duplicated). Delete = `RTM_DELROUTE` matching the exact spec; `ESRCH` is
success. Nexthop trick per §3.2.3 before create, after delete. Retry: 10 × 100
ms on `ENETUNREACH`/`EEXIST`/`EBUSY`, then reconciler backoff (spec 00 §3.2.3).
Prune: on every full sync, list all routes with `proto kernel` in the tables
flowsdn owns (200, 202, 2004, 2005; and in main only routes whose `dev` is
`cilium_host` or whose `(dst, via)` pair is in the desired direct-route set)
and delete those not desired. Routes in main via other devices are **never**
pruned (they may be the administrator's).

Conflicts: if the kernel already has a route for the same `(table, dst,
priority)` with `proto` ≠ kernel (static/boot/dhcp/ra), flowsdn's replace
would clobber it. flowsdn MUST first `RTM_GETROUTE`-dump the exact prefix; if
a non-kernel-proto route exists, it is **not** replaced; the row is marked
`Error("route conflict with proto <p> on <dev>")`, health degraded (§7).

### 5.3 Rule reconciliation

Rules have no replace semantics in the kernel (`RTM_NEWRULE` with
`NLM_F_EXCL` fails on duplicates; without it duplicates are created). Upsert =
dump rules of the family, compare on `(priority, fwmark, fwmask, src, dst,
table, iif, oif)`, add if absent. Prune duplicates of desired rules (keep one).
Delete = `RTM_DELRULE` with the exact spec; `ENOENT` is success.

### 5.4 Node-address derivation

Per §3.1.6, implemented as a pure function `(devices snapshot, local-table
routes, config) → Vec<NodeAddress>`; the controller diffs against the table
(insert/delete only rows that changed) so watchers do not wake needlessly.
Sort comparator: `(secondary, scope, !is_public, addr)` ascending.

### 5.5 Cluster-size-dependent interval

`interval(n) = base × (1 + log2(max(n,1)) × 0.5…)` — the reference's
`backoff.ClusterSizeDependantInterval` is
`base × (1 + ln(n) )` scaled so that the table in §3.3.4 holds; flowsdn MUST
reproduce the table's values within 5 %: `interval(n) = base × (1 +
ln(1 + n) )^… `. Implementers take the reference table as the acceptance
vector (unit test in §9): 1 → 41.6 s, 8 → 131.8 s, 64 → 250.5 s, 1024 → 416 s,
16384 → 582 s with base 60 s. (Formula extracted at implementation time from
`pkg/backoff`; this spec pins the *values*, which is what matters for cluster
API load parity.)

### 5.6 nft table rendering

`render(config, tunnel_port, proxy_ports, notrack_pods, host_ports, pod_cidrs)
→ NftTable` is deterministic: chains in the order of §3.10.2, rules in the
order of §3.10.3, ports sorted ascending, pods sorted by IP. The rendered table
is hashed; a transaction is sent only if the hash changed or a resync is due.
The transaction builder encodes into one netlink batch (≤ 64 KiB per message
page; large per-pod sets are split across messages within the same batch —
the batch is still atomic). On `EOPNOTSUPP`/`ENOENT` for an expression (module
missing): fail the transaction, health degraded with the expression name; the
previous table stays (the batch was rejected as a whole).

### 5.7 Neighbor calculation

`for fip in forwardable-ips: for dev in selected devices with hw_addr:
route_get(fip, oif=dev, fib_match)` → collect next hops; the desired set is
the union; diff against the previous desired set → table upserts/tombstones →
reconciler (§3.4 step 3). Rate limiter: token bucket 1 token / 15 s, burst 1;
a full resync timer at 5 min bypasses the limiter.

## 6. Configuration

Keys owned or consumed here (name, type, default, effect). Immutable = change
requires agent restart with map/state migration per spec 00 §6.7.

| Key | Type | Default | Effect |
|---|---|---|---|
| `devices` | list | `[]` | immutable filter; §3.1.2 grammar; hotplug discovery remains dynamic |
| `force-device-detection` | bool | false | run auto-detection for devices unmatched by the filter |
| `force-device-required` | bool | false | make an empty device set fatal (hidden) |
| `direct-routing-device` | string | `""` | §3.1.5 |
| `direct-routing-skip-unreachable` | bool | false | skip instead of error for gateway'd nodes |
| `routing-mode` | `tunnel`\|`native` | `tunnel` | immutable |
| `tunnel-protocol` | `vxlan`\|`geneve` | `vxlan` | immutable |
| `tunnel-port` | u16 | 0 (→ 8472/6081) | immutable |
| `tunnel-source-port-range` | `lo-hi` | `0-0` | applied only at device creation |
| `underlay-protocol` | `auto`\|`ipv4`\|`ipv6` | `auto` | |
| `auto-direct-node-routes` | bool | false | native mode per-node routes |
| `ipv4-native-routing-cidr`, `ipv6-native-routing-cidr` | CIDR | `""` | SNAT exclusion (spec 04) and native routing sanity |
| `enable-local-node-route` | bool | true | forced false for ENI/Azure/Alibaba |
| `ipv4-service-range`, `ipv6-service-range` | CIDR\|`auto` | `auto` | auxiliary prefixes |
| `enable-endpoint-routes` | bool | false | immutable; §3.2.3 |
| `route-metric` | int | 0 | metric on node routes |
| `local-router-ipv4`, `local-router-ipv6` | IP | `""` | pin router IP; native only; not with IPsec |
| `ipv4-node`, `ipv6-node` | IP\|`auto` | `auto` | node IP override |
| `address-scope-max` (`local-max-addr-scope`) | int | 254 (`RT_SCOPE_HOST`; ADR-0012 #136) | node-address scope filter |
| `nodeport-addresses` | list of CIDR | `[]` | §3.1.6 |
| `enable-ipv4`, `enable-ipv6` | bool | true | immutable |
| `enable-ipv6-ndp`, `ipv6-mcast-device` | bool, string | false, `""` | solicited-node multicast join (L2 spec) |
| `mtu` | int | 0 | override base MTU |
| `enable-ipv4-big-tcp`, `enable-ipv6-big-tcp` | bool | false | §3.5.3 |
| `enable-route-mtu-for-cni-chaining` | bool | false | spec 09 |
| `enable-l2-neigh-discovery` | bool | false | §3.4 |
| `bpf-neigh-global-max` | int | derived | reserved (no userspace neigh map in 1.20; accepted) |
| `kube-proxy-replacement` | bool | false | immutable; §3.9 |
| `bpf-lb-sock`, `bpf-lb-sock-hostns-only` | bool | false | socket LB |
| `bpf-lb-sock-terminate-pod-connections` | bool | true | LB spec |
| `enable-host-legacy-routing` | bool | false | explicit legacy host routing |
| `node-port-range` | `lo,hi` | `30000,32767` | |
| `node-port-bind-protection` | bool | true | `post_bind` programs |
| `enable-auto-protect-node-port-range` | bool | true | reserved ports sysctl |
| `node-port-acceleration` / `bpf-lb-acceleration` | `disabled`\|`native`\|`best-effort`\|`testing-only` | `disabled` | XDP |
| `bpf-lb-mode`, `bpf-lb-dsr-dispatch`, `bpf-lb-algorithm` | LB spec | | validated here for tunnel/DSR/IPIP interplay |
| `bpf-lb-rss-ipv4-src-cidr`, `-ipv6-` | CIDR | `""` | DSR ipip only |
| `enable-bandwidth-manager` | bool | false | §3.7 |
| `enable-bbr`, `enable-bbr-hostns-only` | bool | false | |
| `cgroup-root` | path | `/run/cilium/cgroupv2` | §3.8 |
| `auto-create-cilium-node-resource` | bool | true | |
| `enable-cilium-node-crd` | bool (hidden) | true | |
| `annotate-k8s-node` | bool | false | §3.3.3 |
| `ipam-cilium-node-update-rate` | duration | 15 s | debounce for IPAM-only updates |
| `node-init-timeout` (hidden) | duration | 15 m | fatal bound for local node init |
| `enable-node-selector-labels`, `node-labels` | bool, list | false, `[]` | node identity labels |
| `exclude-node-label-patterns` | list | `[]` | |
| `enable-bpf-masquerade`, `enable-ipv4-masquerade`, `enable-ipv6-masquerade`, `enable-masquerade-to-route-source`, `enable-remote-node-masquerade`, `only-masquerade-default-pool` | bool | false/true/true/false/false/false | spec 04; `enable-ipv{4,6}-masquerade` without `enable-bpf-masquerade` is a **startup error** (spec 04 §3.12) |
| `enable-ip-masq-agent`, `ip-masq-agent-config-path` | bool, path | false, `/etc/config/ip-masq-agent` | spec 04/07 |
| `enable-bpf-tproxy` | bool | false | when true the TPROXY/socket rules are omitted |
| `install-no-conntrack-iptables-rules` | bool | false | **kept**: pod-CIDR `notrack` rules (name retained for Helm `installNoConntrackIptablesRules`) |
| `enable-host-firewall` | bool | false | host mark rule; policy spec |
| `datapath-mode` | `veth`\|`netkit`\|`netkit-l2`\|`auto` | `veth` | immutable; spec 08 |
| `enable-vtep`, `vtep-endpoint`, `vtep-cidr`, `vtep-mac`, `vtep-mask`, `vtep-sync-interval` | | | accepted; feature deferred → startup error `"vtep is not supported in this release"` when `enable-vtep=true` |
| `encrypt-node`, `ipv4-pod-subnets`, `ipv6-pod-subnets` | | | encryption spec; routes in §3.2.3 |
| `enable-pmtu-discovery`, `packetization-layer-pmtud-mode` | | | deferred |
| `enable-l2-announcements`, `enable-l2-pod-announcements`, `l2-pod-announcements-interface-pattern`, `l2-announcements-*` | | | L2 spec; device requirement here |

**Accepted and ignored** (registry class `Ignored{adr: 0003}`; spec 00 §6.5).
Each produces exactly one startup log line at level `warn`:

```
option "<key>" has no effect: flowsdn does not use iptables (ADR-0003); the nftables residual is derived from the feature configuration
```

Keys: `install-iptables-rules`, `iptables-lock-timeout`, `iptables-random-fully`,
`prepend-iptables-chains`, `disable-iptables-feeder-rules`,
`enable-xt-socket-fallback`, `egress-masquerade-interfaces` (BPF masquerade
selects devices via `devices`; a non-empty value logs the warning with the
suffix `"; use --devices to restrict masquerading devices"`). The iptables
*variant* of masquerading (`enable-ipv4-masquerade=true` with
`enable-bpf-masquerade=false`) is **not** ignored but rejected (spec 04), with
the message
`"enable-ipv4-masquerade requires enable-bpf-masquerade: flowsdn has no iptables masquerade (ADR-0003)"`.

## 7. Failure modes

| Situation | Behavior |
|---|---|
| Selected device disappears (unplug, `ip link del`, rename) | tombstone in `devices`; loader unpins its links (spec 01); node addresses, neighbors, qdisc rows for it are deleted; if it was the direct-routing device and one is required: health `Degraded("direct routing device <name> gone")`, datapath keeps the last `.rodata` until a new device is selected (or fatal after `node-init-timeout`? no — never fatal at runtime; degraded only). Renames arrive as a link change with the same ifindex: rows update in place. |
| Address change on a selected device | `node-addresses` recomputed; NodePort frontends and masquerade addresses follow (spec 05/04); ipcache host entries updated (spec 03); `CiliumNode.spec.addresses` republished if the node IP changed |
| Node IP changes | remote nodes: routes/ipcache/node-map entries re-keyed by `NodeUpdated(old,new)`; local: CiliumNode republished; IPsec re-keyed |
| Route conflict with systemd-networkd/NetworkManager | our routes are `proto kernel`, which both tools ignore by default (`ManageForeignRoutes=`/`KeepConfiguration=` aside); a foreign route on the same `(table,dst,priority)` is not replaced (§5.2) and reported. Documented remedy: exclude `cilium_host`, `lxc*`, `cilium_*` in `NetworkManager.conf` `[keyfile] unmanaged-devices` / networkd `.network` match — the Helm chart ships the snippet (inventory 15). |
| systemd-sysctl re-applies `rp_filter=1` | per-device re-assert on creation + persistence file (§3.6); the periodic sysctl reconciler refresh (30 min) rewrites drifted keys |
| `nf_tables` unavailable (compiled out, `nfnetlink` returns `EOPNOTSUPP`/`ENOENT`) | if no residual rule is configured: nothing happens. If one is: startup error naming the feature (`"L7 proxy requires nf_tables with nft_tproxy and nft_socket"`); at runtime (module removed): health degraded, previous table (if any) is gone with the module; retry with backoff |
| nftables transaction rejected (`EINVAL` on an expression, quota) | table unchanged (atomic); health `Degraded` with the netlink error and the offending message index; retry with backoff; full resync in 30 min |
| Someone deletes/flushes `inet flowsdn` | `NFNLGRP_NFTABLES` event → immediate re-render and replace; counter `flowsdn_nft_external_changes_total` |
| Kernel local rule (pref 0) reappears (e.g. `ip rule flush`… `systemd-networkd` restart) | the 30 min rule resync deletes pref 0 again after re-asserting 100; between the two the node still works (both rules resolve local) — `ip rule flush` itself removes our rules 1/9/10/100 and breaks local delivery for everyone until resync; a `RTNLGRP_IPV4_RULE`/`IPV6_RULE` subscription (**MUST**, ADR-0012 #139) enqueues prompt reconcile; coalesce event bursts and retain periodic full resync for missed events |
| Router IP cannot be restored | new IP allocated; old address removed from `cilium_host`; routes rewritten; existing pod connections through the router IP break (warned) |
| CiliumNode create/update fails persistently | fatal after 10 × 500 ms (operator cannot function without it) |
| Node map full (16384 IPs) | `mapNodeID` error → node handled without ID; IPsec to that node fails; health degraded; `flowsdn_node_id_map_errors_total` |
| Neighbor `RTM_NEWNEIGH` fails (`EINVAL` on a device without L2) | that device is excluded from neighbor calculation (`hw_addr` empty) — should not happen; else error on the row, retry |
| MTU too small / device MTU lowered below 1280 with IPv6 | route MTU is clamped to 1280 and health degraded `"device MTU <n> too small for IPv6"` |
| Restart mid-operation | all kernel state is idempotently re-asserted from desired tables; node IDs restored from the pinned map before any node event; the nftables table is replaced wholesale on the first transaction; neighbors with `NTF_EXT_LEARNED` not desired are pruned after `forwardable-ips` initializes |
| Upgrade from the reference | adopts `cilium_host`/`cilium_net`/tunnel devices, routes (same spec), rules (same prefs), pinned node map (same layout). The reference's iptables chains `CILIUM_*` and feeder rules are **not** removed by flowsdn (never touch other tables) — the Helm pre-upgrade job or the documented `iptables -D` list removes them; leftover `CILIUM_POST_nat` MASQUERADE rules would double-SNAT, so the upgrade doc MUST require their removal (open decision 12.4 considers a one-shot cleanup mode that *does* delete chains whose names start with `CILIUM_` in the `ip`/`ip6` `filter`/`nat`/`raw`/`mangle` tables, opt-in). |
| cgroup2 not mountable | fatal when socket LB enabled; warn otherwise |

## 8. Observability

Metrics (Prometheus, reference-compatible names where dashboards exist):

| Metric | Labels | Meaning |
|---|---|---|
| `cilium_neighbor_entry_refresh_count`, `cilium_neighbor_nexthop_lookup_count`, `cilium_neighbor_entry_insert_count`, `cilium_neighbor_entry_delete_count` | — | reference names kept (dashboards) |
| `cilium_node_manager_events_received_total` / `flowsdn_node_events_received_total` | `type=update\|delete`, `source` | |
| `cilium_nodes_all_num` | — | known nodes |
| `cilium_nodes_all_datapath_validations_total` | — | background re-validations |
| `flowsdn_devices_selected` | `device` (1/0 per device) | |
| `flowsdn_routes_desired`, `flowsdn_routes_errors_total` | `owner` | |
| `flowsdn_rules_desired` | `family` | |
| `flowsdn_node_ids_allocated`, `flowsdn_node_id_map_errors_total` | — | |
| `flowsdn_mtu_device`, `flowsdn_mtu_route` | — | current values |
| `flowsdn_sysctl_errors_total` | `key` | |
| `flowsdn_nft_rules`, `flowsdn_nft_transactions_total{result}`, `flowsdn_nft_external_changes_total`, `flowsdn_nft_generation` | | |
| `flowsdn_bigtcp_enabled` | `family` | |
| `flowsdn_ciliumnode_updates_total{result}` | | |

Logs (structured fields): `device`, `ifindex`, `prefix`, `nexthop`, `table`,
`priority`, `mark`, `node`, `nodeID`, `spi`, `reason`. Every kernel object
written is logged at `debug` with its full spec; failures at `warn` with the
netlink errno.

Health (spec 00 §3.4 registry) modules: `devices-controller`,
`node-addresses`, `route-reconciler`, `rule-reconciler`, `neighbor-reconciler`,
`mtu`, `sysctl`, `bandwidth-qdisc`, `nft-residual`, `node-manager`,
`node-discovery` (CiliumNode), `node-ids`, `bigtcp`.

Status API (`GET /healthz` model, cilium-dbg `status --verbose` sections):
`KubeProxyReplacement{mode, devices[], directRoutingDevice, features}`,
`Masquerading{enabled, mode: BPF, snat-exclusion CIDRs}`, `Routing{mode,
tunnel protocol, underlay, ...}`, `HostRouting{mode: BPF|Legacy}`,
`BandwidthManager{enabled, congestionControl, devices[]}`, `ClusterNodes`;
`GET /debuginfo` adds the rendered nftables table and the firewall allow-list.

Monitor events: none originate here.

## 9. Test plan

Unit (no root):

- [ ] `devices` filter grammar: exact, `+`, `!`, alt names, first-match, invalid glob rejected.
- [ ] Auto-detection predicates 1–9 with table fixtures (reference `testdata/device-detection*.txtar` scenarios as vectors: kind veth uplink, docker0, bond + slaves, vrf child, ipoib, bridge, addressless VLAN, `force-device-detection`).
- [ ] Direct-routing device: filter, single-device default, required-but-missing error text.
- [ ] Node-address derivation: sort comparator, primary/node_port with and without `nodeport-addresses`, local-table alias routes, `cilium_host` link-local inclusion, wildcard fallback.
- [ ] `firstGlobalAddr`: public before private, secondary/tentative skip, preferred IP rules, scope retry.
- [ ] MTU derivation table (reference `TestNewConfiguration` vectors) for every combination of tunnel v4/v6 × IPsec (key sizes 16/20/32) × WireGuard × DSR × IPv6 minimum.
- [ ] Route spec rendering: tunnel v4 (`via`), v6 (no `via`), local (no mtu), aux prefixes, direct routes (gateway/unreachable/`lo` cases).
- [ ] Rule set rendering per feature matrix; local rule 0→100 ordering.
- [ ] Node manager: update/delete fan-out order, ipcache entry set per node (labels, tunnel peer, encrypt key, remote-cluster flag), health/ingress IPs, source precedence, startup pruning of `Restored`, checkpoint round-trip, cluster-size interval table (§5.5 vectors).
- [ ] Node IDs: allocate/reuse/SPI change/exhaustion/deallocate; restore from a fake map incl. `id 0` cleanup; `GET /node/ids` shape.
- [ ] CiliumNode mutate: write set, address type filtering, preserved foreign labels, owner ref; annotation patch body; retry/fatal.
- [ ] `Node` JSON compatibility vectors (bytes from the reference test fixtures).
- [ ] KPR initializer decisions (§3.9 items 1–11) with expected error/warning texts.
- [ ] BIG TCP size computation (limits, min over devices, legacy reset).
- [ ] The nftables residual — rendering per feature gate, golden rulesets, the netlink encoder round-trip, determinism and the ignored-key warnings: **enumerated case by case in §9.1** (N1–N22, N38–N45), which replaces the coverage ADR-0003 drops.

Privileged (fresh netns, run on dev per cross-project rules; the reference's
`TestPrivileged*` list is the checklist):

- [ ] devices controller against a live netns: create veth/bridge/bond/vlan/dummy, addresses, default route; assert table contents and selection changes on route add/remove; dump-interrupted retry (inject churn).
- [ ] `cilium_host`/`cilium_net` creation, idempotent adoption, address replace and stale-address cleanup, sysctls applied, MTU update.
- [ ] VXLAN/Geneve device: create, port change recreates, port-range hint ignored, switch protocol removes the other.
- [ ] Routes: tunnel route install with nexthop trick, delete removes nexthop route only when unused, v6 without via, replace conflicts with `proto static` are refused, prune leaves foreign routes.
- [ ] Rules: local rule relocation (never a moment without a local rule — verify with a concurrent `ip rule` poller), IPsec/proxy rules, duplicate cleanup, `ip rule flush` recovery.
- [ ] Direct routes: reachable, unreachable (error vs skip), node IP on `lo`.
- [ ] Node IDs against the real pinned map: write, restore after re-open, prune.
- [ ] Neighbors: desired set from `RTM_GETROUTE` incl. multipath; `NTF_EXT_MANAGED` insert, prune of stale `NTF_EXT_LEARNED`, non-learned entries untouched; managed-neighbor probe.
- [ ] MTU updater end-to-end: lower a device MTU, observe `route-mtu` row and routes' `mtu` metric.
- [ ] Bandwidth qdiscs: mq+fq on a multi-queue dummy (`numtxqueues 4`), fq on single queue, bond noqueue, idempotence.
- [ ] BIG TCP: set/restore sizes on a dummy device; failure rollback.
- [ ] Sysctl reconciler: write/read/timeout, `ignore_err` semantics.
- [ ] Socket LB cgroup: mount detection, mount, wrong-fs fatal.
- [ ] nftables against a live kernel — transaction install/replace/empty-delete, atomicity under a concurrent GETRULE poller, external flush detection and re-install, module autoload, coexistence with a foreign default-drop table, and teardown: **enumerated as §9.1 cases N23–N37**.
- [ ] TPROXY end-to-end: transparent listener in the netns, marked packet redirected; `socket transparent` re-mark on the reply path.
- [ ] Per-pod notrack: verify no conntrack entry is created (`nf_conntrack` count via `NETLINK_NETFILTER` `IPCTNL_MSG_CT_GET_STATS`).

e2e (kind matrix, spec 15): `routingMode` × `tunnelProtocol` × `bpf.masquerade`
× `kubeProxyReplacement` × `bandwidthManager` × BIG TCP × IPv6 underlay;
firewalld-enabled node image (default-drop) to exercise §3.10.6 diagnostics;
upgrade-from-reference with leftover iptables chains.

### 9.1 The nftables residual: the enumerated replacement for the dropped iptables coverage

**Added 2026-09-07 by amendment.** `docs/test-port-plan.md` §6 item 2 records
that ADR-0003 drops the reference's `pkg/datapath/iptables` and
`pkg/datapath/iptables/ipset` packages — measured at v1.20.1 as
`iptables_test.go` 1,303 lines / 18 tests, `reconciler_test.go` 605 lines /
1 test and `ipset/ipset_test.go` 684 lines / 6 tests, **25 tests and 2,592 test
lines** — with no automatic replacement, and warns that unless the equivalent
assertions are enumerated *before* the nftables code is written the residual
becomes an untested surface by default. This subsection is that enumeration. It
is normative for `flowsdn-nft` and `nft-residual`: an implementation is not
complete until every case below exists.

Three facts about the reference tests shape what follows.

- **They are all unprivileged.** No test file in either package carries a
  `//go:build linux` tag; every one drives a mock that records the argv it was
  handed, or a closure over a `map[string]AddrSet` standing in for the kernel.
  Nothing runs `iptables`, and nothing needs root. flowsdn keeps that property
  for everything that is a question about *what we decided to install* — which
  is most of it — and pays for a network namespace only where the question is
  about the kernel's behavior.
- **There are no golden files upstream.** Every expected ruleset is an inline
  Go literal, which is why the reference has 478 lines of expectation inside
  one 199-line test function and why a rule can be changed without anyone
  seeing the diff. flowsdn inverts this: expectations live in
  `crates/flowsdn-nft/tests/golden/<case>.nft` and are reviewed as a diff.
  `--update-golden` regenerates them; regenerating is a reviewed commit.
- **The reference's central mechanism is a strict, ordered, exhaustive command
  transcript** (`mockIptables.expectations`): an unexpected command fails, and
  an unconsumed expectation fails. flowsdn's equivalent is `NftRecorder`, a
  `Client` implementation that captures each batch as a decoded `NftTable` plus
  the ordered message list, with the same two failure modes — an unexpected
  transaction fails, and a transaction that never arrives fails. Case IDs below
  are `N<n>`; **U** = unit, no privileges, **P** = privileged, fresh netns.

#### 9.1.1 Rule presence and absence per feature gate (U)

Over `render(ResidualInputs) → NftTable` (§5.6) — a pure function, so these are
ordinary `#[test]`s. Each case asserts both halves: the rules that MUST appear,
and that **nothing else does**. Absence is the half the reference tests get
right (`TestTunnelRulesTunnelingDisabled` asserts an empty command list) and
the half that rots first.

- [ ] **N1 `residual-empty`** — default config, no feature on. The rendered
      table has **zero chains and zero rules**, and §3.10.1's empty-set rule
      applies: the transaction is `NEWTABLE, DELTABLE`, so an idle node carries
      no nftables state at all. This is flowsdn's counterpart to
      `TestTunnelRulesTunnelingDisabled` and is stronger, because the reference
      still installs its chain skeleton when every feature is off.
- [ ] **N2 tunnel** — `routing-mode=tunnel`, `tunnel-protocol` ∈ {`vxlan`
      (8472), `geneve` (6081)}, and an explicit `tunnel-port` override. Exactly
      two rules, `udp dport <tp> notrack` in `raw_prerouting` and `raw_output`.
      Replaces `TestTunnelVxlankRulesTunnelingEnabled` /
      `TestTunnelGeneveRulesTunnelingEnabled`, minus their third command
      (`filter CILIUM_OUTPUT … -j ACCEPT`), which §3.10.5 drops as a
      cross-table no-op — the case MUST assert that no `accept` rule is
      emitted, so the deviation is pinned rather than assumed.
- [ ] **N3 tunnel off** — `routing-mode=native` with no feature that creates a
      tunnel device: no tunnel rules, and `tunnel-port` set to a non-zero value
      does not resurrect them.
- [ ] **N4 WireGuard** — `encryption.type=wireguard`: `udp dport 51871 notrack`
      in both raw chains, and no `accept`.
- [ ] **N5 encryption marks** — IPsec, WireGuard, and both: four `notrack`
      rules on `meta mark & 0xf00 == 0xd00` and `== 0xe00` across the two raw
      chains, emitted **once** when both are on. Replaces the NOTRACK half of
      `TestEncryptionRules`. The reference's twelve-and-eight `ACCEPT` rules in
      `filter`/`nat` are dropped by §3.10.5; assert their absence.
- [ ] **N6 IPsec-vs-WireGuard precedence** — the reference lets WireGuard
      *replace* the IPsec ruleset (`addCiliumAcceptEncryptionRules` early-returns
      into the WireGuard variant). flowsdn's rules are mark-based and additive,
      so with both enabled the mark rules appear once and the WireGuard port
      rule appears too. Assert the union, and record it here as a **DEVIATION**
      the case exists to pin.
- [ ] **N7 proxy, static** — L7 proxy on, `enable-bpf-tproxy=false`: the
      `socket transparent` rule with its two mark exclusions, and the four/five
      `notrack` rules of §3.10.3 including the IPsec-only `0xb00` one. The
      reference has **no test for `installStaticProxyRules` at all** — its
      largest rule-emitting function — so this case is new coverage, not a port.
- [ ] **N8 proxy per port** — two redirects (`(dns-egress, 37379)`,
      `(http-ingress, 37380)`) × {tcp, udp} × {ip, ip6} = 8 `tproxy` rules.
      Assert the **full 32-bit** mark equality `0x200 | (port_be << 16)` — the
      reference's own vectors are usable as arithmetic fixtures: port 37379 ⇒
      `0x3920200`, 37380 ⇒ `0x4920200`, 43477 ⇒ `0xd5a90200`, 43479 ⇒
      `0xd7a90200`. Assert the non-terminal `tproxy` is followed by
      `meta mark set 0x200` and `accept`, and that the `socket transparent`
      rule precedes every `tproxy` rule in the chain.
- [ ] **N9 proxy with `enable-bpf-tproxy=true`** — the `tproxy` and `socket`
      rules disappear, the `notrack` rules remain. The reference cannot test
      this: all five of its proxy tests hardcode `haveBPFSocketAssign: false`,
      so its ~478 lines of proxy-rule tests describe a path that does not run
      when `bpf_sk_assign` is available. flowsdn's default is the BPF path, so
      **this case, not N7/N8, is the one that guards the shipped default.**
- [ ] **N10 delivery interface** — `enable-endpoint-routes` on ⇒ the
      `oifname "lxc*"` proxy-return rules are emitted *in addition to* the
      `cilium_host` ones; off ⇒ only `cilium_host` (§3.10.4).
- [ ] **N11 host mark `0xC00`** — `enable-host-firewall=true`, legacy host
      routing, and `kube-proxy-replacement=false` each independently produce
      the `filter_output` rule with all five negative mark matches
      (`0xd00`, `0xe00`, `0x400` on mask `0xf00`; `0xa00`, `0x800` on mask
      `0xe00`) and the `mark set (mark & 0xfffff0ff) | 0xc00` result; with none
      of the three, the rule is absent (§12.3 is the open decision this case
      pins either way). **The reference has no test for this rule** — a
      five-negative-match rule with no coverage is exactly the kind that rots,
      so this case is new coverage.
- [ ] **N12 ENI ct-mark `0x80`** — `ipam=eni` and `ipam=alibabacloud` each
      produce the two `mangle_prerouting` rules of §3.10.3; every other IPAM
      mode produces neither. **Also new coverage**: the reference's
      `addCiliumENIRules` is untestable as written because it calls
      `route.NodeDeviceWithDefaultRoute()` directly. flowsdn MUST take the
      default-route device as an input to `render()` rather than looking it up
      inside, which is what makes this a unit test at all — recorded here as a
      design requirement, not just a test.
- [ ] **N13 per-pod no-track ports** — one pod, two pods sharing a port, a pod
      with both an IPv4 and an IPv6 address, `tcp` default and explicit
      `/udp`, and pod deletion. Assert the four rules per (ip, port, proto) and
      the family dependency (`meta nfproto`) that `ip`/`ip6` payloads require
      in the `inet` family (§4.5). Replaces the per-pod half of the reference's
      `TestNoTrackHostPorts` bookkeeping.
- [ ] **N14 host no-track ports** — union across pods, grouped by protocol,
      rendered as an **anonymous set** with ports sorted ascending. The
      reference's `TestNoTrackHostPorts` sub-cases are the vectors: adding the
      same port for a second pod changes nothing (the set is refcounted by port,
      not by pod); `{443} → {443, 999}` renders one rule with `{ 443, 999 }`;
      an empty annotation value behaves as a removal; removing the last pod
      empties the set and the rule disappears. flowsdn's version is
      *simpler than the reference's and must be asserted as such*: because the
      whole table is replaced atomically there is no add-before-delete ordering
      to test, which is what four of the reference's five sub-cases are about.
- [ ] **N15 pod-CIDR no-track** — `install-no-conntrack-iptables-rules=true`
      with one and with two local IPv4 alloc CIDRs ⇒ four rules per CIDR;
      IPv6 CIDRs produce nothing (IPv4-only, as in the reference); the key
      false ⇒ nothing. Replaces `TestAddNoTrackPodTrafficRules`.
- [ ] **N16 rule ordering** — with every feature above enabled at once, the
      chain contents are in the fixed order of §3.10.3 (pod-CIDR, proxy,
      encryption, tunnel, WireGuard, per-pod, host-ports), ports sorted
      ascending and pods sorted by IP. Correctness does not depend on this —
      they are all `notrack` — but the golden files do, and a renderer that is
      order-stable only by accident produces diff noise that trains reviewers
      to skim.

#### 9.1.2 Golden expected rulesets per feature combination (U)

Each case renders, encodes to a netlink batch, decodes it back, and compares
**both** representations against a committed golden: the decoded `NftTable`
(structural) and an `nft list table`-style text rendering (reviewable). Encoding
through the wire and back is what makes this a test of the encoder rather than
of a `Debug` impl, and it is why §11 says the decoder makes golden tests
possible without root.

- [ ] **N17** goldens for: `none`, `tunnel-vxlan`, `tunnel-geneve`,
      `tunnel+proxy-2-ports`, `proxy-bpf-tproxy`, `ipsec`, `wireguard`,
      `ipsec+wireguard`, `host-firewall`, `eni`, `per-pod-notrack-v4v6`,
      `host-ports-set`, `pod-cidr-notrack`, `endpoint-routes`, and
      **`all-features`** — the combination no single reference test covers.
- [ ] **N18** the text rendering is byte-stable across runs and across
      `BTreeMap`/`HashMap` changes (render twice in one process, compare).
- [ ] **N19** every `Expr` variant of §4.5 round-trips encode→decode
      unchanged, including `Bitwise` mask/xor pairs, anonymous `Set` elements,
      `Tproxy` with both families, `Socket`, `Ct{MARK}` get and set, and `Fib`.
- [ ] **N20** batch splitting: a per-pod set large enough to exceed one 64 KiB
      netlink message splits across messages **within one batch**, and the
      decoded result is identical to the unsplit render.

#### 9.1.3 Determinism and idempotent re-apply (U, then P)

- [ ] **N21 (U)** `render()` called twice on equal inputs produces an equal
      table and an equal hash; called on inputs differing only in the iteration
      order of the pod and port collections, likewise. This is the property
      §5.6 relies on to skip a transaction.
- [ ] **N22 (U)** an unchanged desired set produces **no transaction at all**
      (the recorder sees zero batches), which is the flowsdn analogue of the
      reference's idempotency assertions in `TestAddProxyRulesv4` scenario 2
      and `TestNoTrackHostPorts` — and stronger, because those assert "no
      mutating command", while flowsdn asserts "no netlink write whatsoever".
- [ ] **N23 (P)** apply the same table twice against a real kernel: the second
      apply leaves the generation ID unchanged if skipped by the hash, and if
      forced (resync) leaves an identical ruleset, with no rule duplication.
- [ ] **N24 (P)** the 30-minute full resync re-derives and re-applies the whole
      table even with no event, and converges after the table is corrupted
      out-of-band. This is the counterpart of `TestReconciliationLoop`'s final
      block, the reference's only self-heal assertion, and it is worth keeping:
      it is the difference between "we react to events" and "we are eventually
      correct". Drive it with a mock clock, never a sleep.

#### 9.1.4 Transaction atomicity (P)

The reference has **no atomicity test, because it has no atomicity**: its
update model is rename → reinstall → delete, with a window in which both the
old and the new chains are live, and `TestRenameCustomChain` covers only the
`-E` rename in isolation. flowsdn replaces the whole model with one netlink
batch (§3.10.1), so this is not a port but a stronger claim that needs its own
proof.

- [ ] **N25** during a replace that changes the whole rule set, a concurrent
      poller issuing `NFT_MSG_GETRULE` in a tight loop **never observes a
      partial set**: every dump it collects equals either the old table or the
      new one, never a mixture. Run for a fixed number of replaces, not a fixed
      duration, so the case cannot pass by not racing.
- [ ] **N26** a batch containing one invalid expression is rejected **whole**:
      the previous table is still present and byte-identical afterwards, the
      health entry is `Degraded` with the netlink error and the offending
      message index (§7), and the retry backoff is armed.
- [ ] **N27** `EOPNOTSUPP`/`ENOENT` for a missing expression module (`tproxy`,
      `socket`, `ct`) fails the transaction with the **expression name** in the
      health message, not a bare errno — §5.6 requires the name and it is the
      difference between a one-minute and a one-day diagnosis.
- [ ] **N28** module autoload: in a fresh netns with the modules not loaded,
      the first transaction that references `ct`, `tproxy` and `socket` loads
      them without `CAP_SYS_MODULE`.
- [ ] **N29** the empty case: with every feature off, the transaction is
      `NEWTABLE, DELTABLE` and `inet flowsdn` does not exist afterwards.

#### 9.1.5 Coexistence with a foreign table (P)

The reference's coexistence coverage is incidental — `KUBE-KUBELET-CANARY` and
`KUBE-PROXY-CANARY` sit in the `iptables -S` dumps of seven tests and are
asserted untouched, and `TestManagerNodeIpsetNotNeeded` asserts a set named
`unmanaged-ipset` survives. flowsdn makes it explicit, because §3.10.1's
ownership rule ("exactly one table, never touch another") is a promise to the
host's own firewall.

- [ ] **N30** with `inet firewalld`, `ip filter` (iptables-nft) and a bare
      `inet foo` table present, a full install/replace/delete cycle leaves all
      three **byte-identical** (compare full `NFT_MSG_GETTABLE`/`GETCHAIN`/
      `GETRULE` dumps before and after), and no message in any batch names a
      table other than `flowsdn`.
- [ ] **N31** with a second table whose `forward` chain has `policy drop`, the
      §3.10.6 claims hold on live traffic: `notrack` still takes effect (no
      conntrack entry is created), `tproxy` still redirects, `meta mark set`
      still marks — and an `accept` in `inet flowsdn` does **not** override the
      drop. The last half is the one that justifies installing no accept rules
      at all; assert it by temporarily adding one and showing it changes
      nothing.
- [ ] **N32** the §3.10.6 detection path: a foreign default-drop `forward` or
      `input` chain, and the legacy `ip filter FORWARD` with policy drop, each
      set health `Degraded` with the table and chain named, and log the
      allow-list exactly once (not once per resync).
- [ ] **N33** external interference: another process flushes or deletes
      `inet flowsdn`; the `NFNLGRP_NFTABLES` subscription fires, the table is
      re-installed, and `flowsdn_nft_external_changes_total` increments once.
- [ ] **N34** leftover reference state: with `CILIUM_*` chains and feeder rules
      present in `ip filter`/`nat`/`raw`/`mangle`, flowsdn installs its table
      and **does not remove or modify any of them** (§7 upgrade row). The
      documented removal is the Helm job's, not the agent's.

#### 9.1.6 Teardown (P)

- [ ] **N35** `flowsdn-agent --cleanup` deletes `inet flowsdn` entirely — table,
      chains, rules and anonymous sets — and leaves every other table
      untouched. Replaces `TestRemoveCiliumRulesv4`/`v6`, whose real content is
      "delete exactly our feeder rules and nothing else"; with one owned table
      the flowsdn version is a single `DELTABLE`, and the assertion that
      matters moves entirely to "nothing else changed".
- [ ] **N36** cleanup is idempotent and succeeds when the table is already
      absent (the reference's `remove` silently no-ops on a missing ipset; the
      same tolerance is required here).
- [ ] **N37** normal shutdown leaves the table **in place** (§3.11: restart is
      non-disruptive), and a restarted agent replaces it wholesale on its first
      transaction without a window in which the node has no rules — N25's
      poller, applied across a process restart.

#### 9.1.7 Accepted-and-ignored iptables configuration keys (U)

The reference has **no coverage of these at all** — a repo-wide grep for
`DisableIptablesFeederRules` or `PrependIptablesChains` in any `*_test.go`
returns nothing — so this is entirely new. It is also the surface a user meets
first when migrating a values file, which makes an untested warning string a
poor trade.

- [ ] **N38** each of `install-iptables-rules`, `iptables-lock-timeout`,
      `iptables-random-fully`, `prepend-iptables-chains`,
      `disable-iptables-feeder-rules` and `enable-xt-socket-fallback`, when set
      to a non-default value, produces **exactly one** `warn` line matching §6's
      text verbatim, naming the key and citing ADR-0003 — and the rendered table
      is bit-identical to the run without the key, which is what "no effect"
      actually means.
- [ ] **N39** `egress-masquerade-interfaces` with a non-empty value produces the
      same warning with the `"; use --devices to restrict masquerading devices"`
      suffix; empty produces no warning at all.
- [ ] **N40** the warning is emitted **once at startup**, not per reconcile —
      assert over a run with several resyncs.
- [ ] **N41** `enable-ipv4-masquerade=true` with `enable-bpf-masquerade=false`
      is **rejected**, not warned: startup fails with spec 04's exact message.
      This is the one iptables-shaped key that is an error rather than a
      no-op, and conflating the two would be a silent loss of masquerading.
- [ ] **N42** the registry classifies all of the above as `Ignored{adr: 0003}`
      (spec 00 §6.5), so a future key added to the list inherits the behavior
      without a new code path — assert the class, not just the message.

#### 9.1.8 Reconciler convergence (U)

`TestReconciliationLoop` is the single largest test in either reference package
(605 lines) and asserts *desired-state convergence*, never rule text — the one
reference test whose shape survives ADR-0003 unchanged.

- [ ] **N43** a nine-step sequence mirroring its rows — initial state, device
      added, local node IP and alloc-CIDR change, first proxy port, second proxy
      port, two no-track pods, one removed, host no-track port added, changed
      protocol, deleted — drives the `nft-desired` row (§4.1) to the expected
      table at each step, with a mock clock stepping the 200 ms debounce. No
      kernel, no privileges.
- [ ] **N44** coalescing: N changes inside one debounce window produce **one**
      transaction whose content equals the render of the final state.
- [ ] **N45** the reconciler task exits cleanly on shutdown with no leaked
      task and no pending timer (the reference asserts this with `goleak`; the
      Rust equivalent is a `tokio` runtime that shuts down within a bounded time).

#### 9.1.9 What has no nftables equivalent, because BPF does the job

These reference assertions are deliberately **not** replaced. Each names what
proves the flowsdn path instead, so "dropped" never has to be re-litigated
from scratch.

| Reference test(s) | Lines | Why there is no nftables case | What proves flowsdn's path |
|---|---|---|---|
| the entire `ipset` package — `TestManager`, `TestManagerNodeIpsetNotNeeded`, `TestOpsPruneEnabled`, `TestOpsRetry`, `TestIPSetList`, `TestIPSetListInexistentIPSet` | 684 (6 tests) | `cilium_node_set_v{4,6}` exists **only** to let the iptables masquerade path exclude node-destined traffic; its gate is `!tunneling && !bpf-masquerade`. flowsdn has no iptables masquerade (ADR-0001/0003), so the set is never created and nothing references it. The `ipset restore` batching protocol it spends most of its lines on is an artifact of shelling out to a CLI, which §3.10.1 forbids outright | the datapath's remote-node identity check: spec 04 §3.12 decision step 7 and its BPF cases `remote_node_masquerade{,_skip}_test` (spec 04 §9), over the ipcache entries spec 03 writes |
| `TestNodeIpsetNATCmds` | 69 | same gate; the rule it renders (`-m set --match-set … dst -j ACCEPT` in `CILIUM_POST_nat`) is `dropped-because-BPF` in §3.10.5 | as above |
| `TestAllEgressMasqueradeCmds`, `TestAllEgressMasqueradeCmdsRandomFully` | 137 | BPF masquerade is the only masquerade path. `--random-fully` is a netfilter NAT-engine concern with no BPF analogue — the BPF SNAT engine chooses ports itself | spec 04 §3.12 decision order and its cases `host_bpf_masq_{native,overlay}`, `hostfw_bpf_masq`, `skip_tunnel_nodeport_{masq,nat,revnat}` (spec 04 §9); port selection by spec 04's SNAT port-allocation cases |
| `TestInstallMasqueradeRouteSourceRules` | 25 | `enable-masquerade-to-route-source` is iptables-only upstream; the key is kept and reimplemented in BPF (§6, spec 04) | spec 04's `BPF_FIB_LOOKUP_SRC` source-selection cases |
| the hairpin and loopback SNAT rules (untested upstream, but part of the dropped surface) | — | kube-proxy DNAT hairpin does not exist under KPR; loopback-source hairpin is a datapath concern | spec 02 §3.19 pipeline 8 (hairpin/loopback), spec 04's `hairpin_sctp_flow` |
| `TestGetProxyPorts` | 51 | it recovers proxy ports by **parsing the live ruleset** on restart — the ruleset used as a persistence store. §3.10.3 makes this a **DEVIATION**: flowsdn regenerates the rule set from `<state-dir>/proxy-ports.json` and never parses it back | spec 16's proxy-port persistence and restore cases |
| `TestCopyProxyRulesv4`/`v6`, and the `haveBPFSocketAssign:false` half of `TestAddProxyRulesv4`/`v6` | ~430 of ~478 | the copy-on-first-init dance exists to carry rules across the rename→reinstall→delete update model, which one atomic transaction removes; and all five reference proxy tests describe the path that does **not** run when `bpf_sk_assign` is available | N7/N8 cover the static-rule path that remains; **N9** covers the shipped default; N25 covers the property the copy dance was working around |
| `TestRenameCustomChain` | 28 | there are no custom chains to rename and no `OLD_` generation | N25 (atomicity), N29 (empty delete) |

One reference behavior in this class is worth recording even though it produces
no test: upstream `installMasqueradeRules` hard-errors when the iptables backend
is `nft` and the exclusion CIDR is `0.0.0.0/0` or `::/0`, because nftables
cannot express that negation in its NAT path. flowsdn never hits it — there is
no nftables masquerade — and spec 04's BPF exclusion-CIDR check has no such
limit. It is noted so the absence is a known consequence rather than an
oversight.

Finally, the four rules the reference emits and **never tests** — the `0xC00`
host mark, the ENI `0x80` ct-mark, the `cilium_host`/`cilium_net` forward
accepts and the whole of `installStaticProxyRules` — are covered here by N11,
N12, N7 and, for the forward accepts, by N1's "nothing else is emitted" plus
§3.10.6's detection cases N31/N32, since flowsdn deliberately installs no accept
rules. Net of the ADR-0003 drops, flowsdn's nftables coverage is **broader**
than the reference's, not merely different: 45 enumerated cases against 25,
with the four highest-risk rules covered for the first time.

## 10. Kernel and platform requirements

- Netlink families: `NETLINK_ROUTE` (links incl. vxlan/geneve/ipip/ip6tnl/veth
  attributes, `IFLA_GSO/GRO_*_MAX_SIZE`, `IFLA_TSO_MAX_SIZE`, addresses,
  routes with `RTA_TABLE` > 255, `RTAX_MTU`, `RTA_MULTIPATH`, rules with
  `FRA_FWMARK/FRA_FWMASK/FRA_PROTOCOL/FRA_TABLE`, neighbors with
  `NDA_FLAGS_EXT`, qdiscs `mq`/`fq` with `TCA_FQ_*`; multicast groups §3.1.1
  plus `RTNLGRP_IPV4_RULE`/`IPV6_RULE`), `NETLINK_NETFILTER`
  (`NFNL_SUBSYS_NFTABLES` batches, `NFNLGRP_NFTABLES` events,
  `NFNL_SUBSYS_CTNETLINK` stats in tests), generic netlink only via the
  WireGuard spec.
- Kernel config: `IP_MULTIPLE_TABLES`, `IPV6_MULTIPLE_TABLES`, `FIB_RULES`,
  `IP_ADVANCED_ROUTER`, `VXLAN=m`, `GENEVE=m`, `NET_IPIP=m`, `IPV6_TUNNEL=m`,
  `NET_SCH_FQ=m`, `TCP_CONG_BBR=m`, `CGROUPS` with cgroup2, `NETFILTER`,
  `NF_TABLES=m`, `NF_TABLES_INET=y`, `NF_CONNTRACK=m`, `NFT_CT=m`, `NFT_TPROXY=m`,
  `NF_TPROXY_IPV4/6=m`, `NFT_SOCKET=m`, `NF_SOCKET_IPV4/6=m`, `NFT_FIB_INET=m`
  (ENI rule; deferred). All modules autoload through `request_module`; the
  agent never loads modules itself (no `CAP_SYS_MODULE`).
- Minimum kernel 6.6 (kernel-requirements §2.5): managed neighbors (5.16),
  IPv4 BIG TCP (6.3), `NDA_FLAGS_EXT`, `nft_socket` `transparent` (5.3+),
  `nft_tproxy` (4.19+), `TCA_FQ_HORIZON` (5.8+) are all present.
- Capabilities: `CAP_NET_ADMIN` (all netlink writes, `IP_TRANSPARENT`),
  `CAP_SYS_ADMIN` (cgroup2 mount), `CAP_BPF`/`CAP_PERFMON` for the map.
- x86-64 vs arm64: nothing arch-specific in this area except native-endian
  netlink payloads (u32 marks are host-endian in nft data; ports in payload
  matches are big-endian) — the encoder MUST be tested on both.
- Startup check additions (kernel-requirements §4.7): `RTM_GETRULE` dump
  succeeds (multiple tables), `RTM_NEWNEIGH` with `NTF_EXT_MANAGED` in a
  scratch netns when neighbors are enabled, vxlan/geneve/ipip link creation
  in a scratch netns for the configured mode, `NFT_MSG_GETGEN` succeeds when
  any residual rule is configured, `fq` qdisc creation on a scratch device when
  the bandwidth manager is enabled.

## 11. Rust design notes

Crates:

- **`flowsdn-netlink`** — typed, async (`tokio`) rtnetlink layer built on
  `rtnetlink` + `netlink-packet-route` + `netlink-sys`. Provides:
  `Links` (create veth/vxlan/geneve/ipip/ip6tnl/dummy with the attributes in
  §3.2, set MTU/up/ARP-off/GSO-GRO sizes, altnames), `Addrs` (replace/delete),
  `Routes` (`upsert` with replace semantics + nexthop trick + 10×100 ms retry,
  `delete`, `get` with oif/fib-match, `list(table, family)`), `Rules`
  (`ensure`/`delete`/`list`, duplicate-aware), `Neighs` (`set_managed`,
  `delete`, `list`), `Qdiscs` (`replace_root(mq|fq|noqueue)`, `fq` TLVs
  hand-rolled if `netlink-packet-route` lacks `TCA_FQ_*`), `Sysctl`
  (`/proc/sys` writer with `procfs` root override), and `Events`: one
  subscription socket → `Stream<Change<Link|Addr|Route|Neigh|Rule>>` with
  `NLM_F_DUMP_INTR` and `ENOBUFS` handling and subscribe-then-dump. Gaps to
  verify against the pinned versions: `NDA_FLAGS_EXT` (managed neighbors),
  `IFLA_GSO_IPV4_MAX_SIZE`/`IFLA_GRO_IPV4_MAX_SIZE`/`IFLA_TSO_MAX_SIZE`,
  `IFLA_VXLAN_PORT_RANGE`, `IFLA_GENEVE_*`, `IFLA_IPTUN_COLLECT_METADATA`,
  `RTA_VIA`; each gap is a local `Nla::Other` encoding in this crate, upstreamed
  later. Errors are `NetlinkError{errno, request_summary}`.
- **`flowsdn-node`** — everything in §3 except the residual: `DevicesController`
  (tables), `NodeAddresses`, `DirectRoutingDevice`, `HostDevices` (§3.2.1–2),
  `RouteOwner`s + `RouteReconciler`/`RuleReconciler` (spec 00 reconciler
  helper with a netlink `Target`), `NeighborCalculator` + reconciler, `Mtu`,
  `SysctlReconciler`, `Bandwidth`, `BigTcp`, `CgroupRoot`, `KprInit`,
  `LocalNodeStore` (a `watch::Sender<Arc<LocalNode>>`), `NodeManager`
  (`nodes` table + fan-out to `NodeHandler` trait objects: linux routes,
  neighbors, IPsec, WireGuard, ipcache, REST cache), `NodeIds` (pool + map
  writes via `aya` `HashMap<node_key,node_value>` on the pinned fd),
  `CiliumNodePublisher` (kube client, `serde` CRD types from spec 13's crate),
  `NodeAnnotator`. Key types: `Device`, `Route`, `Rule`, `Neighbor`,
  `NodeAddress`, `Node`, `LocalNode`, `RouteMtu`, `Sysctl` as in §4.
- **`flowsdn-nft`** — nftables over `NETLINK_NETFILTER`: `Expr` enum and
  `Rule/Chain/Table` model (§4.5), `render()` from a `ResidualInputs` struct
  (§5.6), `Batch` encoder, `Client` (send batch, `GETGEN`, `GETCHAIN` dump for
  §3.10.6 detection, `NFNLGRP_NFTABLES` subscription), a decoder used by tests
  and by `debuginfo` to print `nft list table`-style text. Dependency options
  evaluated:
  - `nftnl` (Mullvad): FFI over `libnftnl`/`libmnl` — **rejected**: C
    dependency (ADR-0002 spirit, scratch image) and `libnftnl` is GPL-2.0
    (licensing.md forbids without an ADR).
  - `nftables` crate: shells out to `nft` with JSON — **rejected** (no binary
    in the image, ADR-0003).
  - `rustables` (pure-Rust nftables netlink since 0.8, MIT-or-Apache to be
    verified at Phase 2 start; supports table/chain/rule/set and a subset of
    expressions): **candidate**; adopt if its expression set covers `tproxy`,
    `socket`, `ct mark set`, `fib` and batch transactions, and its license
    passes `cargo deny`. Otherwise:
  - **own encoder (recommended default)**: the residual needs ~11 expression
    kinds and four message types; the TLV encoding on top of
    `netlink-packet-core` is ~1.5–2k lines including tests and removes a
    dependency whose maintenance cadence is uncertain. `netlink-packet-nftables`
    does not exist in the rust-netlink organization at the time of writing
    (to verify); if it appears, it is the natural home for the encoder.
- **`flowsdn-ip`** (shared): CIDR math, public/private classification
  (`ip.IsPublicAddr` semantics: not RFC1918/ULA/link-local/loopback), used by
  §3.1.6/§3.1.7.

Concurrency model: each reconciler is one tokio task consuming a table watch;
netlink writes go through one `flowsdn-netlink` handle per family with an
internal mutex (rtnetlink is not reentrant per socket; use separate sockets for
the event subscription and for requests). No global lock across areas
(ADR-0004).

Testing: netns-based privileged tests use `nix::sched::unshare(CLONE_NEWNET)`
in a dedicated thread per test; the nft decoder makes golden tests possible
without root by encoding then decoding.

## 12. Decision register (resolved and open)

1. **Resolved #131:** ADR-0003 is amended to no accept rules, read-only
   detection and documented allow-list. Other firewall tables remain unowned.
   Runtime detection/coexistence tests N31/N32 remain required.

2. **Managed neighbors — resolved #132.** Use kernel-managed neighbors with
   `NTF_EXT_MANAGED` on the supported kernel floor. Do not add the `NTF_USE` refresher
   fallback. Fail the startup capability check when enabled neighbor management cannot
   be supported.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

3. **Host mark rule gating** (§3.10.3). Options: always install (one rule,
   matches the reference; contradicts "installs nothing when no feature is
   on"); gate on host firewall / legacy routing / no KPR (this spec). Depends on
   spec 02 confirming that `from_host` in BPF-host-routing mode does not rely
   on the mark for host identity. **Recommend: gated, revisit after spec 02
   pipeline 6 is final.**
4. **Reference iptables cleanup on upgrade.** flowsdn never touches other
   tables, but a reference → flowsdn upgrade leaves `CILIUM_*` chains with
   MASQUERADE rules that double-SNAT. Options: documented manual cleanup (Helm
   hook running `iptables` in a job image); an opt-in `--cleanup-reference-iptables`
   that deletes exactly the chains named `CILIUM_*`/`OLD_CILIUM_*` and their
   feeder rules through `NFNL_SUBSYS_NFTABLES` when the host uses iptables-nft
   (the chains live in `ip filter` etc. as nft objects) — cannot help
   iptables-legacy hosts. **Recommend: Helm pre-upgrade job + document; no
   agent code.**
5. **Node ID persistence.** Keep restore-from-pinned-map as the only source of
   truth (this spec), or additionally checkpoint `(ip → id)` in
   `<state-dir>` so IDs survive a map recreation (layout change upgrade).
   **Recommend: map only for parity; add the checkpoint when spec 01's
   upgrade protocol needs to recreate the node map.**
6. **Address scope default — resolved #136.** Set `address-scope-max` to 254
   (`RT_SCOPE_HOST`). Retain the unconditional `cilium_host` link-scope exception and
   the independent loopback/IPv6-link-local filtering rules.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

7. **Device filter lifetime — resolved #137.** Keep `devices` immutable after startup
   while continuing dynamic device discovery and hotplug reconciliation. Preserve
   ordered first-match exact names, trailing `+` prefix matching, and `!` exclusions
   from §3.1.2; reject other glob syntax.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

8. **Endpoint routes — resolved #138.** Support `enable-endpoint-routes` as specified,
   including per-endpoint delivery routes, encryption delivery variants, hairpin
   handling and netkit scrub attributes. It remains a full feature obligation for cloud
   IPAM and chaining.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

9. **Rule event reconciliation — resolved #139.** Subscribe to IPv4 and IPv6 rule
   notifications to enqueue prompt reconciliation after rule changes. Keep periodic full
   resync to recover missed events, coalesce bursts, and avoid self-triggered busy
   loops.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

10. **`rustables` vs own nft encoder** (§11). Decide at Phase 2 start after a
    one-day evaluation against the golden files in §9. **Recommend: own
    encoder unless `rustables` passes licensing and covers every expression.**
