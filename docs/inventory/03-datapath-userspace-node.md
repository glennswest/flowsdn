# Userspace datapath management and node-level networking — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/datapath/**` except
`loader/`, `config/`, `tables/` (covered elsewhere), i.e. `pkg/datapath/linux/**`
(minus `linux/config`), `pkg/datapath/{iptables,tunnel,orchestrator,types,ipcache,
prefilter,xdp,neighbor,link,sockets,connector,fake,gneigh,l2responder,node,vtep,
mapsweeper,plugins,option,alignchecker,agentliveness}`, plus `pkg/mtu`, `pkg/node/**`,
`pkg/nodediscovery`, `pkg/cgroups`, `pkg/socketlb`, `pkg/kpr`, `pkg/ip`, `pkg/mac`,
`pkg/ipmasq`, `pkg/maglev`. Not present in v1.20.1 as separate packages:
`pkg/datapath/garp` (now `gneigh` + `l2responder`), `pkg/sysctl` (now
`pkg/datapath/linux/sysctl`), `pkg/bandwidth` (now `pkg/datapath/linux/bandwidth`),
`pkg/redirectpolicy` (now `pkg/loadbalancer/redirectpolicy`, load-balancer area).

Total non-test Go in scope: ~26.5k lines under `pkg/datapath` (excluding loader,
config, tables, maps, bpf) + ~10.7k in the other listed packages = ~37k lines;
~25k lines of tests.

## Purpose

This area is the "Linux plumbing" half of the agent: everything that has to be
true about the host network namespace before and while the BPF programs run.
It creates and addresses `cilium_host`/`cilium_net`, the tunnel devices and the
IPIP devices; decides which physical devices get programs; installs the routes,
ip rules and (residual) iptables/ipset rules for each routing mode; keeps the
kernel neighbor table populated for `bpf_redirect_neigh`; computes MTU per mode;
enables BIG TCP; sets sysctls; attaches the socket-LB cgroup programs; sets up
fq/mq qdiscs for the bandwidth manager; creates veth/netkit pairs for endpoints;
publishes the local node (addresses, CIDRs, health IP, encryption key, boot ID,
ENI info) to the `CiliumNode` CRD / kvstore and Node annotations; and turns
remote node events into routes, node IDs (`cilium_node_map_v2`), ipcache entries
and IPsec XFRM state.

## Components

| Path | Lines (go / test) | Purpose |
|---|---|---|
| `pkg/datapath/cells.go` | 96 | Hive composition of the whole datapath module (order of cells) |
| `pkg/datapath/linux/node.go` | 877 / 1480 | `linuxNodeHandler`: per-node routes for tunnel/direct/local modes, IPsec rules, local-lookup rule move |
| `pkg/datapath/linux/node_ids.go` | 400 | 16-bit node ID allocation, `cilium_node_map_v2` writes, restore from map |
| `pkg/datapath/linux/ipsec.go` | 893 | Node handler IPsec glue: XFRM in/out per node, table 200 routes, subnet encryption |
| `pkg/datapath/linux/devices_controller.go` | 836 / 266 | Netlink subscription → `Table[Device]`, `Table[Route]`, `Table[Neighbor]`; device auto-detection |
| `pkg/datapath/linux/backend_neighbors.go` | 123 / 80 | Service backend IPs → forwardable-IP table (neighbor refresh) |
| `pkg/datapath/linux/requirements.go` | 153 | `CheckRequirements`: kernel/BPF feature gate at start |
| `pkg/datapath/linux/linux_defaults/` | 272 | Route table IDs, rule priorities, skb mark layout |
| `pkg/datapath/linux/route/` | 702 / 576 | `Route`/`Rule` structs, Upsert/Delete/Lookup, nexthop trick, rule list/replace |
| `pkg/datapath/linux/route/reconciler/` | 1565 / 284 | StateDB `DesiredRoute` table + reconciler + WAL (`device-reconciler.wal`-style) + refresher |
| `pkg/datapath/linux/routing/` | 578 / 501 | ENI/Azure per-interface routing tables and ip rules (`RoutingInfo.Configure`) |
| `pkg/datapath/linux/device/` | 768 / 233 | `DesiredDevice` table + reconciler (VLAN sub-devices), owner model, WAL persistence |
| `pkg/datapath/linux/sysctl/` | 503 / 260 | Reconciling `Sysctl` interface over `/proc/sys`, `Table[Sysctl]` |
| `pkg/datapath/linux/bigtcp/` | 653 | Probe + set GRO/GSO max sizes (IPv4/IPv6 BIG TCP) on selected devices |
| `pkg/datapath/linux/bandwidth/` | 729 / 484 | Bandwidth manager: EDT table → `cilium_throttle`, fq/mq qdisc setup, BBR sysctls |
| `pkg/datapath/linux/ipsec/` | 2171 / 1281 | IPsec agent: key file, XFRM state/policy, SPI rotation, metrics (encryption area overlaps) |
| `pkg/datapath/linux/probes/` | 1262 / 416 | Kernel feature probes (`Have*`), managed-neighbor probe, cgroup attach probe, HZ |
| `pkg/datapath/linux/safenetlink/` | 627 / 50 | Retry wrappers around vishvananda/netlink dumps (`ErrDumpInterrupted`) |
| `pkg/datapath/linux/utime/` | 184 / 64 | Boot-time offset → `cilium_config` map (`UTimeOffset`) |
| `pkg/datapath/linux/ethtool/`, `netdevice/` | 24, 128 | ethtool driver name query; netdevice helpers |
| `pkg/datapath/iptables/` | 3904 / 2592 | iptables/ip6tables manager: chains, feeders, masquerade, proxy TPROXY, NOTRACK |
| `pkg/datapath/iptables/ipset/` | 563 / 684 | `cilium_node_set_v4/v6` ipsets via `ipset restore`, StateDB reconciler |
| `pkg/datapath/tunnel/` | 350 / 204 | Encap protocol/port/underlay config; `ENCAP_IFINDEX` define |
| `pkg/datapath/orchestrator/` | 661 / 105 | Builds `config.Config` (LocalNodeConfiguration) from tables and triggers loader reinit |
| `pkg/datapath/connector/` | 1175 / 1407 | veth / netkit / netkit-l2 endpoint pair creation and configuration |
| `pkg/datapath/neighbor/` | 1192 / 298 | Forwardable IP table → desired neighbors → `NeighSet` with `NTF_EXT_LEARNED`/`NTF_EXT_MANAGED` |
| `pkg/datapath/gneigh/` | 530 / 257 | Gratuitous ARP / unsolicited NA sender (mdlayher/arp, ndp, packet) |
| `pkg/datapath/l2responder/` | 474 / 673 | `Table[L2AnnounceEntry]` → `cilium_l2_responder_v4`/`v6` maps, GARP on new entry, solicited-node mcast join |
| `pkg/datapath/sockets/` | 778 / 741 | `SOCK_DIAG` + `SOCK_DESTROY` netlink: terminate sockets to removed backends |
| `pkg/datapath/xdp/` | 268 / 131 | XDP acceleration mode arbitration (`native`, `best-effort`, `testing-only`) |
| `pkg/datapath/prefilter/` | 403 | XDP CIDR prefilter maps + REST API (`GET/PATCH/DELETE /prefilter`) |
| `pkg/datapath/ipcache/` | 214 | ipcache → `cilium_ipcache` BPF listener (tunnel endpoint selection by underlay) |
| `pkg/datapath/link/` | 162 / 88 | Link helpers, ifindex→name cache (15 s resync) |
| `pkg/datapath/node/` | 111 | `node.Addressing` implementation, `GET /node/ids` handler |
| `pkg/datapath/vtep/` | 287 | VTEP integration: `cilium_vtep_map`, table 202 routes, rule pref 112 |
| `pkg/datapath/mapsweeper/` | 400 / 189 | GC of stale per-endpoint BPF map pins and disabled-feature maps |
| `pkg/datapath/plugins/` | 475 / 131 | `CiliumDatapathPlugin` CRD registry, gRPC to plugin sockets |
| `pkg/datapath/types/` | 1048 | Generated Go mirrors of C structs (`types_generated.go`, via `gen.go`) |
| `pkg/datapath/alignchecker/`, `agentliveness/`, `option/`, `fake/` | 142, 65, 25, 156 | struct alignment check vs BTF; 1 s liveness timestamp into `cilium_config`; datapath-mode names; fake cells |
| `pkg/mtu/` | 1136 / 161 | Overhead constants, `Table[RouteMTU]`, device-derived base MTU, endpoint MTU updater |
| `pkg/node/` (top) | 1085 / 320 | `LocalNodeStore`, `LocalNode`, node IP selection (`firstGlobalAddr`), boot ID |
| `pkg/node/types/` | 945 / 286 | `Node`, `Address`, `Identity`, kvstore (un)marshal |
| `pkg/node/manager/` | 1669 / 2039 | Remote node cache, handler fan-out, ipcache/ipset writes, checkpoint, REST `GET /cluster/nodes` |
| `pkg/node/sync/` | 467 / 367 | `LocalNodeSynchronizer`: init from config + k8s `Node`/`CiliumNode`, label/annotation sync |
| `pkg/node/store/`, `neighbordiscovery/`, `addressing/` | 206, 205, 65 | kvstore `cilium/state/nodes/v1`; node IPs → forwardable IPs; address type enum |
| `pkg/nodediscovery/` (+`eni/`) | 963+111 / 302 | Registers local node in kvstore, creates/updates `CiliumNode`, node annotations, ENI/Azure/Alibaba spec |
| `pkg/cgroups/` (+`manager/`) | 953 / 510 | cgroup2 mount at `/run/cilium/cgroupv2`, cgroup ID lookup, pod↔cgroup metadata for socket-LB tracing |
| `pkg/socketlb/` | 465 / 239 | Attach/detach the 13 `cil_sock*` cgroup programs via bpf_link (pinned) or `PROG_ATTACH` |
| `pkg/kpr/` (+`initializer/`) | 565 / 506 | `--kube-proxy-replacement`, `--bpf-lb-sock`; KPR option validation and kernel probes |
| `pkg/ip/`, `pkg/mac/` | 921, 159 / 944, 115 | CIDR math (coalesce, partition, count), public/private test; MAC parse, random MAC |
| `pkg/ipmasq/` | 374 / 679 | ip-masq-agent: config file → `cilium_ipmasq_v4/v6` maps, fsnotify |
| `pkg/maglev/` | 360 / 249 | Maglev permutation/lookup table (M ∈ {251..131071}, murmur3 + jhash seeds) |

Adjacent but owned by other inventories: `pkg/datapath/loader` (creates
`cilium_host`/`cilium_net`, `cilium_vxlan`/`cilium_geneve`, `cilium_ipip4/6`;
attaches programs), `pkg/datapath/config` (`config.Config` struct), `pkg/datapath/tables`
(StateDB tables `Device`, `Route`, `Neighbor`, `NodeAddress`, `Sysctl`, `L2AnnounceEntry`,
`BandwidthQDisc`, `DirectRoutingDevice`), `pkg/wireguard` (1319 lines; encryption),
`pkg/loadbalancer/redirectpolicy` (1846 lines; LB).

## Features

- **Routing mode selection** — `--routing-mode` (`tunnel` default | `native`);
  `TunnelingEnabled() == RoutingMode != native`. `--tunnel-protocol` (`vxlan`
  default | `geneve`), `--tunnel-port` (0 → 8472 for VXLAN, 6081 for Geneve),
  `--tunnel-source-port-range` (default `0-0`), `--underlay-protocol`
  (`auto` | `ipv4` | `ipv6`; auto picks IPv4 if enabled else IPv6). BPF sees
  `TUNNEL_PROTOCOL_{NONE,VXLAN,GENEVE}` = 0/1/2 and `ENCAP_IFINDEX`. Tunnel
  devices are flow-based (collect-metadata) so one device serves all peers. Helm:
  `routingMode`, `tunnelProtocol`, `tunnelPort`, `underlayProtocol`.
- **Per-node routes in tunnel mode** — for every remote node's primary and
  secondary alloc CIDRs (`GetIPv4AllocCIDRs()`), `updateNodeRoute` installs
  `<podCIDR> via <CiliumInternalIPv4> dev cilium_host src <CiliumInternalIPv4> mtu <RouteMTU> proto kernel`
  (IPv6: no `via`, kernel rejects a local gateway; `<podCIDR> dev cilium_host src <CiliumInternalIPv6>`),
  metric from `--route-metric` (default 0). Traffic hits `cilium_host`'s program
  and is encapsulated there. Nexthop route trick: `route.Upsert` first ensures a
  `/32` (or `/128`) scope-link route to the gateway on the device.
- **Native routing** — no per-node route unless `--auto-direct-node-routes`
  (`autoDirectNodeRoutes`), in which case `installDirectRoute` adds
  `<podCIDR> via <nodeIP> proto kernel` on the ifindex returned by
  `RouteGet(nodeIP)`; refuses if the path to the node has a gateway unless
  `--direct-routing-skip-unreachable` (then skips). `--ipv4-native-routing-cidr`
  / `--ipv6-native-routing-cidr` define `NativeRoutingCIDR` used for SNAT
  exclusion. `--direct-routing-device` (in `tables`) is required when KPR, BPF
  host routing or WireGuard is on (`DirectRoutingDeviceRequired`).
- **Local node route** — `--enable-local-node-route` (default true, forced off
  for ENI/Azure/AlibabaCloud IPAM) installs the local alloc CIDR route via
  `cilium_host` with no MTU override. `--ipv4-service-range`/`--ipv6-service-range`
  (non-`auto`) become `AuxiliaryPrefixes` routed the same way.
- **Per-endpoint routes** — `--enable-endpoint-routes` (`endpointRoutes.enabled`):
  host-side `/32` routes to each `lxc*` device are installed by the loader
  (other inventory); this area skips the IPv4 decrypt rule and the hairpin SNAT
  rule in that mode and passes `ZeroOutputMark` to XFRM.
- **Device model** — `--devices` (StringSlice; `eth+` wildcard, `!eth+`
  exclusion, first match wins), `--force-device-detection`. Auto-detection
  (`isSelectedDevice`) requires `IFF_UP`, rejects `IFF_SLAVE|IFF_LOOPBACK`,
  bridge/bond children (VRF children allowed), prefixes `cilium_`, `lo`, `lxc`,
  `cni`, `docker`, type `veth` without a global-scope route (unless listed),
  `bridge`/`openvswitch`, IPoIB. Devices are only required at all when KPR,
  BPF masquerade, host firewall, WireGuard, L2 announcements or IPsec are on
  (`AreDevicesRequired`). Result lives in `Table[Device]` with `Selected` +
  `NotSelectedReason`. A separate `DesiredDevice` reconciler (with WAL at
  `<StateDir>/device-reconciler.wal`) creates owned VLAN sub-interfaces.
- **Host device layout** (created by loader, consumed here) — veth pair
  `cilium_host` ↔ `cilium_net`, ARP off, MTU = DeviceMTU, sysctls
  `net.ipv4.conf.<dev>.{forwarding=1,rp_filter=0,accept_local=1,send_redirects=0}`,
  `net.ipv6.conf.<dev>.forwarding=1`. Addresses: `CiliumInternalIPv4/32` and
  `CiliumInternalIPv6/128` (`AddrReplace`) on `cilium_host`. `--local-router-ipv4`
  / `--local-router-ipv6` pin the router IP. Global sysctls at reinit:
  `net.core.bpf_jit_enable=1` (ignore err), `net.ipv4.conf.all.rp_filter=0`,
  `net.ipv4.fib_multipath_use_neigh=1` (ignore err), `net.ipv6.conf.all.disable_ipv6=0`
  when IPv6, `net.core.fb_tunnels_only_for_init_net=2` when IPIP devices.
- **ip rules and tables** (see Data model for numbers) — `NodeEnsureLocalRoutingRule`
  adds `from all lookup local pref 100 proto kernel` then deletes the kernel's
  pref-0 local rule (IPv4 and IPv6) so Cilium can install rules with pref < 100.
  IPsec: `pref 1 fwmark 0xd00/0xf00 lookup 200` (IPv4 only without endpoint
  routes; IPv6 always). ENI/Azure multi-node NodePort: `pref 109 fwmark 0x80/0x80 lookup main`.
  ENI/Azure per-pod: ingress `pref 20 to <podIP> lookup main`, egress
  `pref 111 from <podIP> [to <vpcCIDR>] lookup <10+ifaceNumber>` (Azure compat:
  pref 110, table `10+ifindex`), plus in that table `<gw>/32 dev <eni> scope link`
  and `default via <gw>`. VTEP: `pref 112 to <vtepCIDR> lookup 202`. Proxy
  (other area) uses tables 2004/2005 with prefs 9/10.
- **Masquerade** — `--enable-ipv4-masquerade`/`--enable-ipv6-masquerade`
  (default true), `--enable-bpf-masquerade` (default false; Helm
  `bpf.masquerade`). `IptablesMasqueradingIPv4Enabled = !EnableBPFMasquerade && EnableIPv4Masquerade`.
  BPF masquerade needs devices and KPR; iptables masquerade installs the rules in
  `CILIUM_POST_nat` described under External interfaces. `--enable-masquerade-to-route-source`
  builds SNAT rules from the routing table's `src` per device instead of
  MASQUERADE. `--egress-masquerade-interfaces` restricts to `-o <iface>` rules
  (mandatory for ENI/Azure/Alibaba IPAM when iptables masquerading is on —
  the manager panics otherwise). `--iptables-random-fully`. Node ipset
  `cilium_node_set_v4/v6` (`--match-set … dst -j ACCEPT`) is only maintained when
  `NodeIpsetNeeded = !TunnelingEnabled && IptablesMasqueradingEnabled`.
- **ip-masq-agent** — `--enable-ip-masq-agent`, `--ip-masq-agent-config-path`
  (default `/etc/config/ip-masq-agent`). YAML/JSON file with
  `nonMasqueradeCIDRs: [..]`, `masqLinkLocal: bool`, `masqLinkLocalIPv6: bool`.
  Empty/missing file → RFC1918 + 100.64/10, 192.0.0.0/24, 192.0.2.0/24,
  192.88.99.0/24, 198.18/15, 198.51.100/24, 203.0.113/24, 240/4; link-local
  169.254/16 and fe80::/10 added unless masqLinkLocal*. Entries are diffed into
  `cilium_ipmasq_v4/v6` LPM maps; directory watched with fsnotify; `restore()`
  reloads map contents on start.
- **Node discovery / `CiliumNode`** — `--auto-create-cilium-node-resource`
  (default true), `--enable-cilium-node-crd` (hidden). Writes
  `spec.addresses[]` (types `InternalIP`, `ExternalIP`, `CiliumInternalIP`),
  `spec.ipam.podCIDRs` (only IPAM=kubernetes), `spec.encryption.key`,
  `spec.health.ipv4/ipv6`, `spec.ingress.ipv4/ipv6`, `spec.bootid`,
  `spec.ipam.{min,pre,max}Allocate`, `spec.ipam.static-ip-tags`, owner ref to
  the `Node`, labels and annotations copied from the local node; ENI:
  `spec.instance-id`, `spec.eni.{vpc-id,availability-zone,instance-type,node-subnet-id,first-interface-index,security-groups,subnet-ids,subnet-tags,exclude-interface-tags,use-primary-address,disable-prefix-delegation,delete-on-termination}`;
  Azure `spec.azure.interface-name`; AlibabaCloud `spec.alibaba-cloud.*`. Retries
  10× with 500 ms backoff then fatal. `--annotate-k8s-node` (default false)
  patches `Node.status` annotations `network.cilium.io/ipv4-pod-cidr`,
  `ipv6-pod-cidr`, `ipv4-health-ip`, `ipv6-health-ip`, `ipv4-ingress-ip`,
  `ipv6-ingress-ip`, `ipv4-cilium-host`, `ipv6-cilium-host`, `encryption-key`.
  kvstore registration under `cilium/state/nodes/v1/<cluster>/<node>` when the
  kvstore is enabled; `NodeInitTimeout` 15 min.
- **Local node model** — `LocalNodeStore` (observable) initialised from flags
  (`--ipv4-node`/`--ipv6-node` non-`auto`, cluster name/ID, native routing
  CIDRs) then the k8s `Node` (name, `InternalIP`/`ExternalIP`, labels,
  annotations, UID, providerID) then the existing `CiliumNode` (restore
  `CiliumInternalIP`, health IPs). `firstGlobalAddr` picks the node IP: prefer
  public over private, skip secondary/tentative/DAD-failed, scope universe then
  site, stable by ifindex; `--address-scope-max` bounds ipcache host addresses.
  Boot ID from `/proc/sys/kernel/random/boot_id` (required by IPsec).
- **Remote node handling** — `node/manager` receives `NodeUpdated/NodeDeleted`
  from k8s `CiliumNode`, kvstore or clustermesh; fans out to `node.Handler`s
  (linux node handler, neighbor discovery, IPsec, WireGuard, REST client,
  cluster-nodes status); writes ipcache metadata per node IP (labels
  `reserved:remote-node` or `reserved:host`, `TunnelPeer`, `EncryptKey`,
  `EndpointFlags.remote-cluster`), health/ingress IPs (`reserved:health`,
  `reserved:ingress`) and pod CIDR fallback entries; adds `InternalIP`s to the
  node ipsets; checkpoints nodes to disk for restart; background re-validation
  interval scales with cluster size. `--enable-node-selector-labels` +
  `--node-labels` allow per-node identities.
- **Node IDs** — `linuxNodeHandler` allocates IDs 1..65535 (`idpool`) per remote
  node, maps every node IP to `(nodeID, SPI)` in `cilium_node_map_v2`
  (`BPF_F_NO_PREALLOC|BPF_F_RDONLY_PROG`, 16384 entries default), restores the
  mapping from the pinned map on start, ID 0 = local node. `GET /node/ids` dumps them.
- **Neighbor management** — enabled by `--enable-l2-neigh-discovery` or any XDP
  acceleration. Purpose: `bpf_redirect_neigh`/`bpf_fib_lookup` in native routing
  and XDP NodePort need resolved L2 next hops for remote node IPs and service
  backend IPs. Forwardable IPs (remote node IPs from `node/neighbordiscovery`,
  backend IPs from `backend_neighbors.go`) × selected L2 devices (with a
  hardware address) → next hop via `RouteGetWithOptions{OifIndex, FIBMatch}`
  (multipath aware) → `DesiredNeighbor{IP, IfIndex}`. Reconciler does
  `NeighSet` with `NTF_EXT_LEARNED|NTF_EXT_MANAGED` on kernels that support
  managed neighbors (probe: create veth in a netns, add neighbor with the
  flags, read back), else `NTF_EXT_LEARNED|NTF_USE` plus an initial `NUD_STALE`
  insert and a refresher that re-arms entries when `Table[Neighbor]` reports
  `NUD_STALE`. Prune deletes `NTF_EXT_LEARNED` entries not desired. Full resync
  every 5 min; rate-limited 1/15 s. Metrics `cilium_neighbor_{entry_refresh,nexthop_lookup,entry_insert,entry_delete}_count`.
- **MTU** — base MTU = min MTU over selected devices (excluding `cilium_vxlan`,
  `cilium_geneve`, `cilium_ipip4`, `cilium_ipip6` and type `dummy`; in ENI mode
  only the primary ENI); `MaxMTU 65520`, default `EthernetMTU 1500`. Overheads:
  `TunnelOverheadIPv4 50`, `TunnelOverheadIPv6 70`, `DsrTunnelOverhead 12`,
  `EncryptionIPsecOverhead 77` (+ authKeySize − 16), `WireguardOverhead 95`,
  `IPIPv4Overhead 20`, `IPIPv6Overhead 48`, `IPv6MinMTU 1280`. `RouteMTU` =
  DeviceMTU − (tunnel + ipsec) or − WireGuard (+ tunnel); `RoutePostEncryptMTU`
  = DeviceMTU. Stored in `Table[RouteMTU]` for `0.0.0.0/0` and `::/0`; endpoint
  MTU updater pushes changes to endpoint devices and container default routes;
  CNI chaining honors `enable-route-mtu`/`--enable-route-mtu-for-cni-chaining`.
  WireGuard device MTU = DeviceMTU − 95, clamped to 1280 with IPv6.
- **BIG TCP** — `--enable-ipv4-big-tcp` (kernel ≥ 6.3), `--enable-ipv6-big-tcp`
  (≥ 5.19); tunnel mode needs the "BIG TCP for UDP tunnels" probe. Sets
  `gro_max_size`/`gso_max_size` (IPv6) and `gro_ipv4_max_size`/`gso_ipv4_max_size`
  to min(196608, device `tso_max_size`/`gro limit 8*65535`) on selected devices
  via `IFLA_GRO_MAX_SIZE` etc.; original values restored on disable. Rejected
  with IPsec, legacy host routing, DSR `ipip` dispatch.
- **Sysctl subsystem** — `Sysctl` interface (`Enable/Disable/Write/WriteInt/ApplySettings/Read/ReadInt`)
  backed by `Table[Sysctl]{Name []string, Val, IgnoreErr, Warn}` and a
  reconciler writing `/proc/sys/<a>/<b>/…`; 1 s wait for reconciliation.
  Keys touched in this area: `net.ipv4.ip_forward`, `net.ipv4.conf.all.forwarding`,
  `net.ipv6.conf.all.forwarding`, `net.ipv4.ip_early_demux` (=0 when IPsec+L7
  proxy and `xt_socket` is missing, `--enable-xt-socket-fallback`),
  `net.ipv4.conf.<lxc|cilium_wg0|eni>.rp_filter` (0, or 2 on the primary ENI),
  `net.ipv4.ip_local_port_range` / `net.ipv4.ip_local_reserved_ports` (KPR
  NodePort range protection, `--enable-auto-protect-nodeport-range` default
  true), `net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=cubic|bbr`,
  `net.ipv4.tcp_slow_start_after_idle=0` (BBR), baselines
  `net.core.netdev_max_backlog≥1000`, `net.core.somaxconn≥4096`,
  `net.ipv4.tcp_max_syn_backlog≥4096` (bandwidth manager).
- **kube-proxy replacement** — `--kube-proxy-replacement` (bool; true implies
  `--bpf-lb-sock`), `--bpf-lb-sock`, `--bpf-lb-sock-hostns-only`,
  `--enable-socket-lb-tracing`, `--enable-socket-lb-pod-connection-termination`,
  `--nodeport-range` (30000-32767), `--node-port-bind-protection` (true),
  `--bpf-lb-mode` (`snat`|`dsr`|`hybrid`), `--bpf-lb-dsr-dispatch`
  (`opt`|`ipip`|`geneve`), `--bpf-lb-algorithm` (`random`|`maglev`),
  `--bpf-lb-acceleration` (`disabled`|`native`|`best-effort`|`testing-only`),
  `--bpf-lb-rss-ipv4-src-cidr`, `--enable-host-legacy-routing`. Initializer
  logic: BPF host routing is silently downgraded to legacy (`EnableHostLegacyRouting=true`)
  when iptables masquerading or no KPR; VXLAN tunnel + DSR rejected unless
  `geneve` dispatch with geneve tunnel; XDP + IPv6 underlay rejected; IPIP DSR
  turns on `cilium_ipip4/6` devices + IPIP termination; `--install-no-conntrack-iptables-rules`
  requires KPR+socket LB and BPF masquerade; health datapath needs
  `bpf_getsockopt/setsockopt` in `cgroup/sock_addr` (5.12) else disabled;
  socket LB needs cgroup attach + `cgroup/connect4` (4.17) + `cgroup/recvmsg4`
  (4.19.57/5.1.16/5.2); `getpeername` hook probed (else `EnableSocketLBPeer=false`).
  With multiple devices and DSR it warns if `rp_filter=1` on the direct-routing
  device. MKE: cgroup v1 `net_cls` classid marking of non-kubepods paths.
- **Socket LB attachment** — programs `cil_sock4_{connect,sendmsg,recvmsg,getpeername,post_bind,pre_bind}`,
  `cil_sock6_*`, `cil_sock_release` from `<StateDir>/bpf_sock.o`, attached at
  `cgroups.GetCgroupRoot()` (default `/run/cilium/cgroupv2`, mounted by the
  agent as `cgroup2`) with bpf_links pinned under
  `/sys/fs/bpf/cilium/socketlb/links/cgroup/<prog>` (kernel ≥ 5.7), falling
  back to `PROG_ATTACH`; `post_bind` only when KPR + bind protection; `pre_bind`
  only with health datapath; IPv6 programs also loaded on IPv4-only hosts when
  the kernel has IPv6 (v4-in-v6 sockets). Config dump `<StateDir>/bpf/bpf_sock.json`.
  `pkg/cgroups/manager` tracks pod cgroup IDs (systemd/cgroupfs/nested
  providers) for socket-LB tracing metadata; `GetCgroupID` via `name_to_handle_at`.
- **Socket termination** — `SocketDestroyer` iterates `SOCK_DIAG_BY_FAMILY`
  (TCP state mask incl. `TCP_LISTEN`, UDP `0xffff`) and issues `SOCK_DESTROY`
  (21) for sockets connected to a deleted backend `(ip, port)`; probes the
  feature by creating a loopback TCP/UDP socket and destroying it
  (`CONFIG_INET_DIAG_DESTROY`).
- **Bandwidth manager** — `--enable-bandwidth-manager`, `--enable-bbr`
  (needs `bpf_skb_set_tstamp`, 5.18, and BPF host routing unless
  `--enable-bbr-hostns-only`), incompatible with IPsec. Pod annotations
  `kubernetes.io/egress-bandwidth`, `kubernetes.io/ingress-bandwidth`,
  `bandwidth.cilium.io/priority`; QoS default prios Guaranteed 7, Burstable 9,
  BestEffort 6; host endpoint pinned to Guaranteed. `Table[BandwidthQDisc]`
  reconciler replaces the root qdisc on each selected device with `mq` + `fq`
  leaves (fallback single `fq` with `pacing`), `fq horizon 2 s`, `buckets 15`;
  bond slaves get `noqueue` on the bond. EDT entries go into `cilium_throttle`
  (`EdtId{id u32, direction u8}` → `EdtInfo{bps, t_last, t_horizon_drop, prio}`),
  `ENABLE_BANDWIDTH_MANAGER` define.
- **Endpoint connector** — `--datapath-mode` (`veth` default | `netkit` |
  `netkit-l2` | `auto`). Host name `lxc<sha256(epID)[:10]>`, temporary peer
  `tmp<epID[:5]>`, renamed inside the pod netns; peer gets altname
  `cilium_cni:<ifname>` to mark ownership. Both sides: MTU=DeviceMTU, TxQLen
  1000, random MACs (veth/netkit-l2; netkit L3 has none), GRO/GSO max sizes
  from BIG TCP, host side up, `net.ipv4.conf.<host>.rp_filter=0`. netkit:
  `Policy FORWARD`, `PeerPolicy BLACKHOLE`, `Scrub NONE` (host) /
  `PeerScrub DEFAULT`, `DesiredHeadroom/Tailroom` = WireGuard + tunnel device
  headroom/tailroom (tunable buffer margins probe). netkit requires ≥ 6.7
  (`CONFIG_NETKIT`), BPF host routing, BPF masquerade, KPR, no `--enable-bpf-tproxy`,
  and the scrub attribute when endpoint routes are on; `auto` falls back to veth.
  Container routes: `<routerIP>/32 dev eth0 scope link` and `default via <routerIP> mtu <RouteMTU>`.
- **XDP / prefilter** — `--bpf-lb-acceleration` maps to `xdpdrv` (native,
  best-effort) or `xdpgeneric`; enablers can conflict (error) and native beats
  best-effort. `--enable-xdp-prefilter` exposes CIDR deny lists through the REST
  API into 4 LPM/hash maps (`CIDR4_HMAP_ELEMS 20M`, `CIDR4_LMAP_ELEMS 64K`).
- **IPv6 specifics** — no `via` in `cilium_host` routes; `net.ipv6.conf.all.disable_ipv6=0`;
  `/proc/net/if_inet6` required; IPv6 decrypt rule always installed; nf_tables
  cannot express `::/0` exclusion (masquerade error); `--enable-ipv6-ndp` +
  `--ipv6-mcast-device` for solicited-node multicast; L2 responder joins
  solicited-node groups (`ff02::1:ffXX:XXXX`) and uses `cilium_l2_responder_v6`;
  `gneigh` sends unsolicited NA (`Override`, target LL option) to `ff02::1`.
- **GARP / L2 announcements** — `--enable-l2-pod-announcements` +
  `--l2-pod-announcements-interface-pattern` (regex over selected devices):
  gratuitous ARP request (`AF_PACKET` raw socket, BPF filter drops all RX) or NA
  for every endpoint IPv4/IPv6 on create/restore. `--enable-l2-announcements`
  (service VIPs, `l2announcer` elsewhere) feeds `Table[L2AnnounceEntry]`; the
  responder reconciler writes `{IP, ifindex}` into the responder maps (BPF
  answers ARP/NS), sends one GARP when an entry first appears, full
  reconciliation every 5 min.
- **IPsec node glue** (encryption inventory covers XFRM detail) — per remote
  node: XFRM out policy/state keyed by node ID and SPI in the mark
  (`spi<<12 | nodeID<<16 | 0xe00`), decrypt mark `0xd00 | nodeID<<16`; route
  table 200: `<podCIDR> dev cilium_host mtu <RoutePostEncryptMTU>` (out) and
  `local <podCIDR> dev <encryptInterface>` (in); `--ipv4-pod-subnets` /
  `--ipv6-pod-subnets` pre-configure subnet encryption. `--encrypt-node` (WireGuard).
- **VTEP** — `--vtep-endpoint`, `--vtep-cidr`, `--vtep-mac`: `cilium_vtep_map`
  entries, table 202 routes via `cilium_host` with MTU 1450, rule pref 112.
- **Datapath plugins** — `CiliumDatapathPlugin` CRD (`v2alpha1`) reflected to
  StateDB; gRPC to `<StateDir>/plugins/<name>/…sock`; `PrepareCollection` /
  `InstrumentCollection` hooks; attachment policy per plugin.
- **Requirements gate** — `CheckRequirements` at start: `CONFIG_IP_MULTIPLE_TABLES`
  (rule list), IPv6 compiled in, `bpf()`, JIT, clsact/`tcx` (6.6 when
  `--enable-tcx`), helpers `bpf_skb_change_tail` (4.9), `bpf_get_socket_cookie`
  (4.12), `bpf_get_current_cgroup_id`/`bpf_fib_lookup` (4.18), dead code elim,
  writable `queue_mapping` (5.1), 1M insns and `BPF_ADJ_ROOM_MAC` (5.2),
  `bpf_jiffies64`, `BPF_MAP_LOOKUP_BATCH` (5.6), `bpf_get_netns_cookie`,
  `bpf_sk_assign`, `bpf_get_cgroup_classid`, `bpf_perf_event_output` (5.7),
  `bpf_csum_level`, `bpf_skb_change_head` (5.8), `bpf_redirect_neigh`,
  `bpf_redirect_peer` (5.10). Optional: `BPF_FIB_LOOKUP_SKIP_NEIGH`, `_SRC`, `_TBID`.

## Data model

Route tables and rule priorities (`linux_defaults`):

| Constant | Value | Use |
|---|---|---|
| `RouteTableIPSec` | 200 | IPsec in/out routes |
| `RouteTableVtep` | 202 | VTEP CIDR routes |
| `RouteTableToProxy` / `FromProxy` | 2004 / 2005 | proxy redirection (proxy area) |
| `RouteTableInterfacesOffset` | 10 | ENI table = 10 + interface number (Azure: 10 + ifindex) |
| `MainTable` / `RT_TABLE_LOCAL` | 254 / 255 | |
| `RulePriorityToProxyIngress` / `FromProxy` | 9 / 10 | |
| `RulePriorityIngress` | 20 | ENI pod ingress `to <ip>` |
| `RulePriorityLocalLookup` | 100 | relocated kernel local rule |
| `RulePriorityNodeport` | 109 | ENI multi-node NodePort fwmark 0x80/0x80 |
| `RulePriorityEgress` / `Egressv2` | 110 / 111 | ENI pod egress `from <ip>` |
| `RulePriorityVtep` | 112 | |
| IPsec decrypt rule | pref 1, fwmark 0xd00/0xf00 | lookup 200 |
| `IPsecFwdPriority` | 0x0B9F | XFRM fwd policy priority |
| `RTProto` | `RTPROT_KERNEL` (2) | all routes/rules, so systemd-networkd leaves them alone |

skb mark layout (32 bits): `identity[15:0]<<16 | k8s[15:12] | magic[11:8] | identity[23:16]`.
Magic values: `0x200` to-proxy, `0x300` SNAT done, `0x400` overlay, `0x800`
proxy-EPID (also `MarkSkipTProxy`), `0x900` proxy egress EPID, `0xA00` from
proxy / ingress, `0xB00` egress, `0xC00` host, `0xD00` decrypt, `0xE00` encrypt
(also WireGuard encrypted), `0xF00` carries identity, `0x1D00` decrypted overlay,
`0x4000` k8s masq, `0x8000` k8s drop, `0x80` ENI multi-node NodePort (connmark).
Masks: `MagicMarkHostMask 0x0F00`, `MagicMarkProxyMask 0x0E00`,
`MagicMarkProxyNoIDMask 0xFFFFFEFF`, `RouteMarkMask 0xF00`, `OutputMarkMask
0xFFFFFF00`, `IPsecMarkMaskNodeID 0xFFFF0000`, `IPsecXFRMMarkSPIShift 12`.

Core structs at the boundary:

- `nodeTypes.Node{Name, Cluster, IPAddresses []Address{Type, IP}, IPv4AllocCIDR, IPv4SecondaryAllocCIDRs, IPv6AllocCIDR, IPv6SecondaryAllocCIDRs, IPv4HealthIP, IPv6HealthIP, IPv4IngressIP, IPv6IngressIP, ClusterID, Source, EncryptionKey u8, Labels, Annotations, WireguardPubKey, BootID}`
  — JSON-marshalled into the kvstore; `Identity{Name, Cluster}` is the key.
  Address types: `InternalIP`, `ExternalIP`, `CiliumInternalIP` (addressing pkg).
- `node.LocalNode{Node, Local *LocalNodeInfo{OptOutNodeEncryption, UID, ProviderID, IPv4/IPv6NativeRoutingCIDR, ServiceLoopbackIPv4/6, IsBeingDeleted, UnderlayProtocol}}`.
- `route.Route{Prefix, Nexthop *IP, Local IP, Device, MTU, Priority, Proto, Scope, Table, Type}`,
  `route.Rule{Priority, Mark, Mask, From, To, Table, Protocol}`.
- `reconciler.DesiredRoute` keyed by `(Table, Prefix, Priority)` with owner
  name; `device.DesiredDevice` keyed by `(Owner, Name)` with `DesiredVLANDeviceSpec{ParentIndex, VLANID}`.
- `tables.Device{Index, MTU, Name, AltNames, HardwareAddr, Flags, Addrs, RawFlags, Type, MasterIndex, OperStatus, Selected, NotSelectedReason}` (tables inventory).
- `neighbor.ForwardableIP{IP, Owners []{Type node|service, ID}}`, `DesiredNeighbor{IP, IfIndex, Status}`.
- `mtu.RouteMTU{Prefix, DeviceMTU, RouteMTU, RoutePostEncryptMTU}`.
- `tunnel.Config{underlay, protocol, port, srcPortLow/High, deviceName, shouldAdaptMTU}`.
- `connector.LinkConfig{EndpointID, HostIfName, PeerIfName, PeerNamespace, GRO/GSO IPv4/IPv6 MaxSize, DeviceMTU, DeviceHeadroom, DeviceTailroom}`.
- `kpr.KPRConfig{KubeProxyReplacement, EnableSocketLB}`; `xdp.Config{mode}`;
  `maglev.Config{TableSize, HashSeed, SeedMurmur, SeedJhash0, SeedJhash1}` (seed is 12 base64 bytes, default `JLfvgnHc2kaSUFaI`).
- ip-masq-agent config file: `{"nonMasqueradeCIDRs": ["10.0.0.0/8"], "masqLinkLocal": false, "masqLinkLocalIPv6": false}` (YAML accepted).

BPF maps written from this area (layouts owned by `pkg/maps`, listed for the boundary):

| Map | Key → Value | Type / size | Writer |
|---|---|---|---|
| `cilium_node_map_v2` | `NodeKey{pad u16, pad u8, family u8, ip [16]}` → `NodeValueV2{node_id u16, spi u8, pad u8}` | hash, 16384, NO_PREALLOC, RDONLY_PROG, pinned | `node_ids.go` |
| `cilium_throttle` | `EdtId{id u32, direction u8, pad[3]}` → `EdtInfo{bps u64, t_last u64, t_horizon_drop u64, prio u32, pad}` | hash, `lxcmap.MaxEntries` | bandwidth |
| `cilium_ipmasq_v4` / `_v6` | LPM prefix → `{}` | LPM trie | ipmasq |
| `cilium_l2_responder_v4` / `_v6` | `{ip, ifindex}` → stats | hash | l2responder |
| `cilium_vtep_map` | vtep CIDR → `{endpoint IP, MAC}` | hash | vtep |
| `cilium_ipcache` | `{prefix, cluster_id}` → `RemoteEndpointInfo{identity, tunnel_endpoint, key, flags}` | LPM | datapath/ipcache listener |
| `cilium_config` | index → u64 (`AgentLiveness`, `UTimeOffset`) | array | agentliveness, utime |
| prefilter `cilium_cidr_v4_dyn/fix`, `v6_*` | CIDR → `{}` | LPM / hash | prefilter |

Files on disk: `<StateDir>/device-reconciler.wal`, `<StateDir>/bpf_sock.o`,
`<StateDir>/bpf/bpf_sock.json`, `/etc/config/ip-masq-agent`, node checkpoint
(node manager, under StateDir), `/sys/fs/bpf/cilium/socketlb/{links,plugin_links}/cgroup/*`,
`/run/cilium/cgroupv2` mount, IPsec key file (`--ipsec-key-file`).

## External interfaces

Netlink objects created/managed:

- Links: `cilium_host`/`cilium_net` veth (loader), `cilium_vxlan` (VXLAN,
  `FlowBased`, dst port, src port range), `cilium_geneve`, `cilium_ipip4`
  (`iptun` collect-metadata), `cilium_ipip6` (`ip6tnl`), `cilium_wg0`
  (WireGuard, port 51871, fwmark 0xE00), VLAN sub-devices (device reconciler),
  per-endpoint `lxc*` veth/netkit pairs with altname `cilium_cni:<name>`.
- Addresses: `CiliumInternalIPv4/32`, `CiliumInternalIPv6/128` on `cilium_host`;
  pod IP `/32` or `/128` inside the container.
- Routes: listed under Features; all `proto kernel`; IPv6 routes on
  `cilium_host` without gateway; ENI tables `10+n`; IPsec table 200; VTEP 202.
- Rules: pref 1 (IPsec decrypt), 20/109/110/111/112 as above, 100 local.
- Neighbors: `NeighSet`/`NeighDel` with `NTF_EXT_LEARNED`, `NTF_USE`, `NTF_EXT_MANAGED`.
- Qdiscs: root `mq` + `fq` (horizon 2 s, buckets 15, pacing) or `noqueue`.
- Link attributes: `IFLA_GRO_MAX_SIZE`, `IFLA_GSO_MAX_SIZE`, `IFLA_GRO_IPV4_MAX_SIZE`,
  `IFLA_GSO_IPV4_MAX_SIZE`, MTU, ARP off, altnames, netns move.
- XFRM: states/policies (in/out/fwd) with marks and `output-mark`, default
  drop policy (encryption inventory).
- `SOCK_DIAG_BY_FAMILY` dumps and `SOCK_DESTROY`.
- Netlink subscriptions: `RTNLGRP_LINK`, `RTNLGRP_IPV4_IFADDR`/`IPV6_IFADDR`,
  `RTNLGRP_IPV4_ROUTE`/`IPV6_ROUTE`, `RTNLGRP_NEIGH` (devices controller).

iptables (external binaries `iptables`, `ip6tables`, `ipset`; `--install-iptables-rules`
default true, `--iptables-lock-timeout 5s`, `--prepend-iptables-chains true`,
`--disable-iptables-feeder-rules`, env `CILIUM_PREPEND_IPTABLES_CHAINS`).
Chains (`table:hook`, `*` = also ip6tables): `CILIUM_INPUT` filter:INPUT*,
`CILIUM_OUTPUT` filter:OUTPUT*, `CILIUM_OUTPUT_raw` raw:OUTPUT*,
`CILIUM_POST_nat` nat:POSTROUTING*, `CILIUM_OUTPUT_nat` nat:OUTPUT,
`CILIUM_PRE_nat` nat:PREROUTING, `CILIUM_POST_mangle` mangle:POSTROUTING,
`CILIUM_PRE_mangle` mangle:PREROUTING*, `CILIUM_PRE_raw` raw:PREROUTING*,
`CILIUM_FORWARD` filter:FORWARD*. Feeder: `-t <table> -I|-A <hook> -m comment --comment "cilium-feeder: <chain>" -j <chain>`.
Update strategy: rename existing chains to `OLD_CILIUM_*`, install fresh, copy
TPROXY rules (`cilium-dns-egress`), delete old; partial reconcile ≥ 200 ms,
full every 30 min; `-S` dumps parsed to find/remove rules mentioning `CILIUM_`.

Rules installed (why they still exist):

- Tunnel: `raw CILIUM_PRE_raw / CILIUM_OUTPUT_raw -p udp --dport <tunnelPort> -j CT --notrack`
  and `filter CILIUM_OUTPUT … -j ACCEPT` — avoid conntrack on overlay packets.
- Proxy (L7, when no `--enable-bpf-tproxy`): `mangle CILIUM_PRE_mangle -p tcp|udp -m mark --mark <0x200|port<<16> -j TPROXY --tproxy-mark 0x200/0xffffffff --on-ip 127.0.0.1|::1 --on-port <port>`;
  `mangle CILIUM_PRE_mangle -m socket --transparent -m mark ! --mark 0xe00/0xf00 -m mark ! --mark 0x800/0xf00 -j MARK --set-xmark 0x200/0xffffffff` (`xt_socket`);
  NOTRACK + ACCEPT for `0x200/0xf00` (to proxy), `0xa00/0xfffffeff` (proxy reply),
  `0xb00/0xf00` (proxy forward), `0x800/0xe00` (L7 upstream), ACCEPT `0xa00/0xe00`.
- Forward: `CILIUM_FORWARD -o cilium_host ACCEPT`, `-i cilium_host ACCEPT`,
  `-i lxc+ ACCEPT`, `-i cilium_net ACCEPT`, and for the delivery interface
  (`lxc+`, `eni+` for aws-cni chaining) both directions.
- Host mark: `filter CILIUM_OUTPUT -m mark ! 0xd00/0xf00 ! 0xe00/0xf00 ! 0x400/0xf00 ! 0xa00/0xe00 ! 0x800/0xe00 -j MARK --set-xmark 0xc00/0xf00` ("host->any mark as from host").
- Masquerade (`CILIUM_POST_nat`): optional `-s <alloc> -m set --match-set cilium_node_set_v4 dst -j ACCEPT`;
  `! -d <nativeRoutingCIDR|alloc> -s <alloc> ! -o cilium_+ -j MASQUERADE [--random-fully]`
  (or per `-o <iface>`); `-m mark --mark 0xa00/0xe00 -j ACCEPT` (proxy return);
  tunnel mode: `! -s <alloc> ! -d <alloc> -o cilium_host -j SNAT --to-source <CiliumInternalIP>`;
  `-s 127.0.0.1 -o lxc+ -j SNAT --to-source <CiliumInternalIP>`; without endpoint
  routes: `-m mark --mark 0xf00/0xf00 -o lxc+ -m conntrack --ctstate DNAT -j SNAT --to-source <CiliumInternalIP>` (hairpin).
- Encryption: NOTRACK for `0xd00/0xf00` and `0xe00/0xf00` in raw PRE/OUTPUT,
  ACCEPT for those marks in filter (IPsec) or WireGuard variants.
- ENI/Alibaba: `mangle CILIUM_PRE_mangle -i <defaultRouteDev> -m addrtype --dst-type LOCAL --limit-iface-in -j CONNMARK --set-xmark 0x80/0x80`
  and `-i lxc+ -j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80`.
- `--install-no-conntrack-iptables-rules`: `raw -I CILIUM_PRE_raw/CILIUM_OUTPUT_raw -s|-d <podCIDR> -j CT --notrack`.
  Per-pod `policy.cilium.io/no-track-port` and `no-track-host-ports` add
  `-p <proto> -d <ip> --dport <p> -j CT --notrack` + ACCEPT pairs.
- Sysctl side effects: `enableIPForwarding` on start.

APIs: REST `GET /cluster/nodes` (node manager, `models.ClusterNodeStatus`),
`GET /node/ids`, `GET/PATCH/DELETE /prefilter`; Kubernetes `CiliumNode` CRUD,
`Node.status` annotation patch; kvstore `cilium/state/nodes/v1/…`; gRPC to
datapath plugins; `ipset restore` batches on stdin. Metrics: neighbor counters,
IPsec XFRM collector, node manager event/emit metrics.

## Dependencies

- Other inventories: loader (device creation, program attach, endpoint routes,
  `ReinitializeHostDev`), `pkg/datapath/config` (`config.Config` fields consumed
  by `orchestrator.newLocalNodeConfig`), tables (StateDB `Device`, `Route`,
  `Neighbor`, `NodeAddress`, `DirectRoutingDevice`, `Sysctl`, `L2AnnounceEntry`,
  `BandwidthQDisc`, `IPSet`), maps (`nodemap`, `bwmap`, `ipmasq`, `l2respondermap`,
  `vtep`, `ipcache`, `configmap`, `cidrmap`), ipcache/identity (labels
  `reserved:remote-node|host|health|ingress`, `source` precedence), load balancer
  (`loadbalancer.Config`, `Table[Backend]`), encryption (IPsec agent, WireGuard
  agent), endpoint manager (gneigh, mapsweeper, MTU updater), proxy (TPROXY
  ports), k8s watchers (`LocalNodeResource`, `LocalCiliumNodeResource`, pods for
  cgroup manager), CNI plugin (`connector.IPv4Routes`, rules), clustermesh
  (`PrefixCluster`, cluster ID), hive/statedb/reconciler/job framework.
- External services: Kubernetes API (`CiliumNode`, `Node`), kvstore (etcd),
  EC2 IMDS (ENI discovery), Azure/Alibaba metadata, `iptables`/`ip6tables`/`ipset`
  binaries (legacy or nft backend), WireGuard via `wgctrl`.
- Kernel: netlink (`rtnetlink`, `sock_diag`, `xfrm`, generic netlink for
  WireGuard), cgroup2, bpffs, `/proc/sys`, `/proc/stat`, `/proc/net/if_inet6`,
  `/proc/sys/kernel/random/boot_id`.

## Kernel / platform requirements

- Hard floor from `CheckRequirements`: effectively Linux ≥ 5.10 (`bpf_redirect_neigh`,
  `bpf_redirect_peer`) plus `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`,
  `CONFIG_NET_CLS_ACT`/`NET_SCH_INGRESS`/`NET_CLS_BPF` (or tcx on ≥ 6.6),
  `CONFIG_IP_MULTIPLE_TABLES`, IPv6 when enabled.
- Feature-gated: managed neighbors (`NTF_EXT_MANAGED`, 5.16+ probed
  functionally), BIG TCP IPv6 5.19 / IPv4 6.3 / UDP tunnels (pending), netkit
  6.7 (`CONFIG_NETKIT`) with scrub attrs 6.13 (backported) and tunable buffer
  margins, tcx 6.6, bpf_link for cgroup 5.7, `bpf_skb_set_tstamp` 5.18 (BBR),
  `getsockopt/setsockopt` in `cgroup/sock_addr` 5.12 (health datapath),
  `cgroup/connect4` 4.17, `cgroup/recvmsg4` 4.19.57+, `getpeername` hooks
  5.8, `BPF_FIB_LOOKUP_SKIP_NEIGH`/`_SRC`/`_TBID` (5.x–6.x), `INET_DIAG_DESTROY`
  (socket termination), `xt_socket`/`xt_TPROXY`/`xt_set`/`xt_connmark`/`xt_addrtype`
  netfilter modules for the iptables paths, `sch_fq`/`sch_mq`, `tcp_bbr`, `vxlan`,
  `geneve`, `ipip`/`ip6_tunnel`, `wireguard`, cgroup2.
- Program/attach types touched here: `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`
  (`connect4/6`, `sendmsg4/6`, `recvmsg4/6`, `getpeername4/6`, `bind4/6`),
  `CGROUP_SOCK` (`post_bind4/6`, `sock_release`), probes use `SCHED_CLS`, `XDP`.
- XDP native mode needs a driver with XDP support on the selected devices;
  `best-effort` falls back to generic. arm64 vs x86-64: nothing arch-specific in
  userspace besides `binary.NativeEndian` in sock_diag structs and BTF alignment
  checks (`alignchecker` compares Go struct layout to the compiled object).

## Tests

- Unit (no root): MTU calculation (`TestNewConfiguration`), tunnel config
  parsing, orchestrator local-node-config, iptables command generation and
  chain rename/copy (`TestAllEgressMasqueradeCmds`, `TestNodeIpsetNATCmds`,
  `TestTunnel*Rules*`, `TestEncryptionRules`, `TestAddProxyRulesv4/v6`,
  `TestInstallMasqueradeRouteSourceRules`, `TestReconciliationLoop` with fake
  iptables), ipmasq config/update/restore, maglev tables and permutation
  determinism, node manager (lifecycle, labels, multiple sources, ipcache
  entries, health IPs, encryption key, ipset, startup pruning, background sync),
  node types, `LocalNodeStore`, nodediscovery annotation patch and fatal on
  transient errors, KPR option validation, gneigh processor, l2responder
  reconciler with fake maps, xdp mode arbitration, sockets serialization,
  connector config/buffer margins, bandwidth host-QoS, cgroup manager providers.
- Privileged (`make tests-privileged`, `TestPrivileged*`, run in a fresh
  netns): node handler routes for encapsulation / direct routing / node IDs /
  aux prefixes / IPsec XFRM leak checks (`node_linux_test.go`, 1356 lines),
  devices controller script tests (`testdata/device-detection*.txtar`,
  `device-controller-tables.txtar`), route package (rule/route replace, list),
  route reconciler scripttests (`manager`, `priority`, `multipath`, `refresher`,
  `persistance` txtar), device reconciler scripttests (`vlan`, `vlan-recreate`,
  `owners`, `persistance`), ENI routing (`TestPrivilegedConfigure*`), neighbor
  scripttests (`desired-neighbors`, `neighbor-reconciler`,
  `neighbor-reconciler-kernel-arp`, `neighbor-initialization`), connector
  veth/netkit pair creation and configuration, socketlb cgroup attach/detach
  with links and legacy attach, sockets destroy, bandwidth qdisc ops incl.
  bonds, `firstGlobalV4Addr`, NodePort/ephemeral range check, MTU endpoint
  updater, nodemap.
- e2e (`.github/workflows`): `conformance-*` matrices vary `routingMode`,
  `tunnelProtocol`, `bpf.masquerade`, `kubeProxyReplacement`, `bandwidthManager`,
  `datapathMode: netkit`, BIG TCP, IPv6 underlay (`tests-smoke-ipv6`),
  EKS/AKS/GKE/AWS-CNI chaining, delegated IPAM, clustermesh, `tests-datapath-verifier`,
  `conformance-runtime` (privileged unit tests). `test/` holds the older
  Ginkgo runtime suite.

## Rust mapping

- **Netlink**: `rtnetlink` + `netlink-packet-route` (async, tokio) cover links
  (veth, vxlan, geneve, ipip/ip6tnl, vlan, netkit attrs are missing upstream and
  need a local `IFLA_NETKIT_*` extension), addresses, routes (incl. `RTA_VIA`
  for IPv6 gateway on IPv4 routes, MTU metric `RTAX_MTU`, table > 255 via
  `RTA_TABLE`), rules (`FRA_FWMARK`/`FRA_FWMASK`, `FRA_PROTOCOL`), neighbors
  (`NTF_EXT_LEARNED`, `NDA_FLAGS_EXT` for `NTF_EXT_MANAGED` — verify in
  `netlink-packet-route`), qdiscs (`fq`/`mq` attributes need `netlink-packet-route`
  tc support or hand-rolled TLVs), GRO/GSO max size attributes (`IFLA_GRO_MAX_SIZE`
  etc. — check coverage, otherwise raw attrs). `neli` is an alternative with
  simpler sync API and generic netlink for WireGuard; `netlink-packet-sock-diag`
  covers `SOCK_DIAG`/`SOCK_DESTROY`. XFRM has no mature crate (`netlink-packet-xfrm`
  is partial) — encryption inventory's problem, but the node handler depends on it.
- **Subscriptions**: `rtnetlink` multicast groups for link/addr/route/neigh
  events; the Go controller's batching (wait for quiescence before committing)
  maps onto a tokio task feeding a state store. Retry on `ENOBUFS`/interrupted
  dumps (Go's `safenetlink`) must be reproduced: `netlink-sys` surfaces
  `NLM_F_DUMP_INTR` only if you check the flag.
- **Sysctl / procfs**: `procfs` crate or direct `std::fs` under `/proc/sys`;
  `nix` for `mount(2)` (cgroup2), `name_to_handle_at`, `setns`/`unshare`
  (probes in throwaway netns), `AF_PACKET` raw sockets (GARP), `IPV6_JOIN_GROUP`.
- **BPF side**: `aya` (or `libbpf-rs`) for cgroup program attach with pinned
  links, map updates (`cilium_node_map_v2`, `cilium_throttle`, ipmasq LPM),
  feature probes (`aya` lacks the `HaveProgramHelper` style probe — replicate by
  loading tiny programs, as Cilium does), TCX/netkit link attach (aya has tcx;
  netkit link support must be checked).
- **iptables**: shell out to `iptables`/`ip6tables`/`ipset` exactly as Cilium
  does (`std::process::Command`), parsing `-S` output; or drop the legacy path
  entirely and use `nftables` via `nftnl`/`rustables` — see Recommendation.
- **GARP/NA**: `pnet`/`etherparse` + raw sockets replace mdlayher/arp, ndp.
- **Structure**: one crate `flowsdn-netlink` (typed Route/Rule/Neigh ops with
  retry and "replace" semantics, netlink event stream), `flowsdn-node`
  (LocalNode store, Node types, node manager, node IDs, CiliumNode publisher),
  `flowsdn-hostnet` (device selection, MTU, sysctl reconciler, tunnel config,
  BIG TCP, bandwidth qdiscs, neighbor reconciler, connector), `flowsdn-nf`
  (iptables/ipset or nftables residuals), `flowsdn-socketlb` (cgroup attach,
  sock_diag destroy), `flowsdn-ip` (CIDR math, maglev). The StateDB-centric
  desired/actual reconcilers translate naturally to `watch`/`broadcast`
  channels over an in-memory store; the WAL-based owner persistence is small.
- **Hard parts**: exact replication of the ip-rule/route sets and their
  ordering relative to the kernel local rule (breaking local delivery on
  upgrade); iptables coexistence with kube-proxy/other CNIs and the
  rename-and-swap update; IPsec node handler coupling (XFRM in Rust);
  ENI per-interface routing (cloud-specific, table ID collisions); netkit
  attribute coverage; kernel feature probing breadth; sock_diag struct layout
  by endianness; keeping `cilium_node_map_v2` restore semantics so node IDs
  survive restarts (IPsec marks depend on them).

## Recommendation

- **Keep (re-implement faithfully)**: routing modes and per-node route/rule
  sets, `cilium_host` addressing, node model + `CiliumNode`/kvstore publishing
  (interoperability with the operator and clustermesh depends on the exact CRD
  fields), node IDs + `cilium_node_map_v2`, device selection semantics
  (`--devices` grammar), MTU constants, sysctl set, neighbor reconciler
  (needed for `bpf_redirect_neigh`), socket-LB cgroup attach, veth connector,
  ip-masq-agent file format, maglev (bit-exact with the BPF side), ipcache
  listener. Effort: **L** (~12–16k lines Rust including a netlink layer with
  replace semantics and retries).
- **Keep but simplify**: bandwidth manager (fq/mq setup + EDT map; BBR sysctls),
  BIG TCP, GARP/L2 responder, VTEP, prefilter, mapsweeper, agentliveness/utime
  (tiny). Effort: **M** together.
- **Defer**: netkit/netkit-l2 connector (needs ≥ 6.7 and netlink attribute
  work; veth first), ENI/Azure/Alibaba routing and node discovery (cloud IPAM
  is a separate decision), datapath plugins gRPC, MKE cgroup v1 hack,
  IPsec node glue until the encryption crate exists, socket termination
  (`SOCK_DESTROY`) until socket LB lands.
- **Replace**: the iptables manager. Ship only the residual rules that still
  matter with BPF masquerade + KPR (proxy TPROXY/NOTRACK, tunnel NOTRACK,
  encryption NOTRACK/ACCEPT, host mark) and express them via nftables
  (`nftnl`) in a dedicated table instead of parsing `iptables -S`; drop
  iptables-based masquerade and `ipset` entirely (require `bpf.masquerade`).
  Effort for the residual: **S–M**.
- Overall area effort: **L** initially (veth, VXLAN/Geneve + native routing,
  node model, neighbors, socket LB attach, sysctl, MTU), growing to **XL** if
  cloud IPAM routing, netkit and the full iptables surface are included.

## Open questions

- Does flowsdn support `--enable-endpoint-routes`? It changes the decrypt rule,
  hairpin SNAT and requires netkit scrub attrs; dropping it removes several
  branches here and in the BPF side.
- Is legacy host routing (upper-stack forwarding, iptables masquerade, no KPR)
  a supported configuration at all? If not, the whole `CILIUM_POST_nat`
  masquerade family, node ipsets, `xt_socket` fallback and the KPR downgrade
  path disappear.
- Node ID persistence: keep the "restore from pinned `cilium_node_map_v2`"
  approach, or persist the ID allocation in flowsdn's own state store and
  rewrite the map on start?
- Which kernel floor is flowsdn targeting? If ≥ 6.6/6.7 is assumed, tcx and
  managed neighbors are unconditional, and the `NTF_USE` refresher, PROG_ATTACH
  fallback and many probes can be dropped.
- Cloud IPAM (ENI/Azure/Alibaba per-interface tables and `CiliumNode.spec.eni`)
  — in scope for a first release, or cluster-pool/kubernetes IPAM only?
- IPv6 underlay: the ipcache listener and node manager select tunnel endpoints
  by `UnderlayProtocol`; confirm flowsdn wants dual underlay support or IPv4-only
  underlay initially.
- `--devices` grammar (`+` wildcard, `!` exclusion, ordered first-match) and
  runtime device detection (hot-plug) — keep compatible for Helm parity?
- Should the residual netfilter rules be nftables-native (breaks environments
  running iptables-legacy alongside) or continue to shell out to `iptables`?
- WireGuard vs IPsec: the node handler's IPsec path is ~1.8k lines of this
  area; if flowsdn ships WireGuard-only first, the IPsec table 200 rules, node
  ID SPI encoding and XFRM coupling can be deferred wholesale.
