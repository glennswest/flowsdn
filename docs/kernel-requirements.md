# Kernel and platform requirements — roll-up

Reference: cilium v1.20.1 (commit 7d68cfb394). Derived from the "Kernel /
platform requirements" and "Dependencies" sections of all fifteen inventories
in `docs/inventory/01..15`, cross-checked against the reference's
`Documentation/operations/system_requirements.rst`,
`bpf/include/bpf/helpers{,_skb,_xdp,_sock}.h`,
`pkg/datapath/linux/requirements.go` (`CheckRequirements`),
`pkg/datapath/linux/probes/probes.go`, `bpf/complexity-tests/{510,61,netnext}`,
`tools/complexity-diff/main.go`, `.github/actions/e2e/kernel-versions.yml` and
`bpf/Makefile` (`MAX_BASE_OPTIONS`). Decisions in force: ADR-0001 (one supported
kernel line per arch plus a documented minimum; no runtime probing beyond a
startup check that refuses to run), ADR-0002 (Rust/aya-ebpf datapath, no C),
ADR-0003 (nftables residual, no iptables).

Kernel version numbers below are upstream mainline versions in which a feature
first shipped. Where two inventories disagree the upstream commit wins and the
disagreement is noted. Distribution kernels (RHEL, and therefore the stormcos
Rocky kernel) backport features, so the startup check must test **features**,
never compare **version strings** (section 4.7).

## 0. Decisions at a glance

| Question | Decision | Section |
|---|---|---|
| Supported kernel line, x86-64 | **6.12** — the Rocky Linux 10 `kernel-6.12.0-2xx.el10` line stormcos already pins (RHEL kABI, consumed as-is, no custom config) | 2.4 |
| Supported kernel line, arm64 | **6.12** — Rocky 10 `aarch64` build of the same line where the hardware boots a stock RHEL 10 kernel; otherwise upstream `6.12.y` LTS with the config fragment in 2.6 | 2.4 |
| Documented minimum for general use | **6.6 LTS** (tcx present, `bpf_loop`, XDP frags, IPv4 BIG TCP, `bpf_sock_destroy`, arm64 tail-call/subprog parity). Anything older is refused at startup | 2.5 |
| Features that need more than 6.6 | netkit pod devices (6.7 device, 6.8 required as in the reference), `BPF_FIB_LOOKUP_SRC` (6.7), `BPF_FIB_LOOKUP_MARK` (6.10), netkit scrub attributes (6.13, backported to 6.12.y) — disabled or degraded below those | 1, 2.5 |
| 5.10 / 5.15 / RHEL 8 (4.18) | **Not supported.** Requires the legacy clsact attach path, an older verifier with weaker state pruning, `CAP_SYS_ADMIN` on RHEL 8, and no `bpf_loop`; incompatible with an aya-ebpf budget (ADR-0002) | 2.2, 3 |
| Agent capabilities | `NET_ADMIN, NET_RAW, BPF, PERFMON, IPC_LOCK, SYS_ADMIN` (SYS_ADMIN only for `setns`/mounts); no `SYS_MODULE`, no `SYS_RESOURCE` (memcg accounting since 5.11) | 4.5 |
| Test matrix | verifier + BPF unit tests on {6.6, 6.12, 6.18} × {x86-64, arm64}; e2e on 6.12 both arches, 6.6 and 6.18 nightly on x86-64 | 5.3 |

**Decision reconciliation (2026-09-09, #54 and #53).** The 6.6 general minimum
and 6.12 supported line above are the target contract, superseding the older
6.1 recommendations in specs 01/02. Required features are checked at startup;
legacy clsact is cleanup-only. The object policy is single-object-first with
measured promotion (§3.3), not an unconditional feature matrix. These choices
resolve conflicting prescriptions; they do not claim completed privileged
loader or verifier validation.

## 1. Feature → requirement matrix

Column legend. **Helpers**: `bpf_*` helpers the program(s) call (names as in
`helpers*.h`, `bpf_` prefix dropped). **Maps**: `BPF_MAP_TYPE_*` and flags.
**Prog / attach / link**: program type, attach point and the link kind used to
attach. **Config / modules**: `CONFIG_*` symbols and kernel modules. **Ref min**:
the reference's documented or probed minimum. **flowsdn**: what flowsdn requires
on the 6.6 minimum / 6.12 line. **arm64 / NIC**: architecture and driver notes.

Cross-cutting requirements that every row inherits and that are not repeated:
`CONFIG_BPF=y BPF_SYSCALL=y BPF_JIT=y HAVE_EBPF_JIT DEBUG_INFO_BTF=y PERF_EVENTS=y
NET_CLS_ACT=y` (selects `NET_XGRESS`, which tcx needs) `CGROUPS=y CGROUP_BPF=y
NAMESPACES=y NET_NS=y`, bpffs mounted (4.1), cgroup2 mounted (4.2), JIT enabled
(`net.core.bpf_jit_enable=1` or `BPF_JIT_ALWAYS_ON`). Every row uses
`map_lookup_elem/update_elem/delete_elem`, `tail_call`, `ktime_get_ns`,
`jiffies64` (5.5, checked by the reference at 5.6), `get_prandom_u32`,
`get_smp_processor_id`, `perf_event_output`, `trace_printk` (debug builds only).

| Feature | Helpers (beyond common) | Maps | Prog / attach / link | Config / modules | Ref min | flowsdn | arm64 / NIC |
|---|---|---|---|---|---|---|---|
| **Base datapath** | | | | | | | |
| Pod attach (`from-container`, `to-container` on veth) | `redirect`, `redirect_peer` (5.10), `skb_load_bytes`, `skb_store_bytes`, `skb_pull_data`, `skb_change_type`, `get_hash_recalc`, `csum_diff`, `l3_csum_replace`, `l4_csum_replace`, `skb_change_tail` (4.9) | `HASH` (lxc, ipcache metadata), `LPM_TRIE` (ipcache, `BPF_F_NO_PREALLOC`), `LRU_HASH` (CT, `BPF_F_NO_COMMON_LRU`), `PERCPU_ARRAY` (scratch), `PROG_ARRAY` (`cilium_calls_<epid>`), `PERF_EVENT_ARRAY` (`cilium_events`), `PERCPU_HASH` (metrics), `ARRAY` (config) | `SCHED_CLS` tc ingress+egress on the lxc device; **tcx link** (6.6) — legacy `clsact` filter path not implemented | `VETH=y`; `NET_CLS_ACT=y`; `NET_SCH_INGRESS`/`NET_CLS_BPF` only for the legacy path (not needed) | 5.10 (`redirect_peer`) | 6.6 (tcx only) | One bpfel object for both arches. Unaligned 8/4/2/1-byte loads assumed JIT-handled (true on both). |
| Host datapath (`from-netdev`, `to-netdev`, `from-host`, `to-host` on physical devices, `cilium_host`/`cilium_net`) | `fib_lookup` (4.18), `redirect_neigh` (5.10), `skb_change_head` (tc since 5.8), `csum_level` (5.8), `skb_adjust_room` with `BPF_ADJ_ROOM_MAC` (5.2), `skb_change_proto` | as above plus `HASH` node map (`cilium_node_map_v2`), `LPM_TRIE` (ip-masq, egress), `HASH` `cilium_ipv4_frag_datagrams` (LRU) | `SCHED_CLS` tcx ingress+egress on every `--devices` entry and on `cilium_host`/`cilium_net` | `IP_MULTIPLE_TABLES=y IPV6_MULTIPLE_TABLES=y FIB_RULES=y IP_ADVANCED_ROUTER=y` | 5.10 | 6.6 | — |
| Conntrack + NAT tables, GC, `cilium-dbg bpf ct list` | — | `LRU_HASH` (`cilium_ct4_global`, `cilium_ct_any4_global`, `cilium_snat_v4_external`, v6 variants; `BPF_F_NO_COMMON_LRU` per-CPU LRU flavour), per-cluster `ARRAY_OF_MAPS` (ClusterMesh) | userspace `BPF_MAP_LOOKUP_BATCH` / `BPF_MAP_LOOKUP_AND_DELETE_BATCH` (5.6) | — | 5.6 batch API (hard check) | 6.6 | LRU memory scales with CPU count × `BPF_F_NO_COMMON_LRU`; small arm64 boards: size `bpf-ct-global-*-max` down. |
| Monitor events (drop, trace, policy verdict, debug) | `perf_event_output`, `get_socket_cookie`, `get_current_cgroup_id` (4.18, `TraceSock`) | `PERF_EVENT_ARRAY` `cilium_events` (max_entries = possible CPUs); optional `RINGBUF` (5.8) declared, unused | userspace `perf_event_open(2)` per CPU + mmap 64 pages × page size | `PERF_EVENTS=y` | 4.18 | 6.6 | Ring size is `64 × PAGE_SIZE`: 256 KiB/CPU on 4 K pages, 4 MiB/CPU on a 64 K-page arm64 kernel (`kernel-64k`). Never hard-code 4096. |
| Per-endpoint policy maps | `map_lookup_elem` on LPM | `LPM_TRIE` `cilium_policy_v2_<epid>` (12-byte key, `BPF_F_NO_PREALLOC`, up to 65536 entries), `PERCPU_HASH` stats | — | — | 4.11 (LPM) | 6.6 | Identity is 24 bits on the wire (VNI) and in `skb->mark`. |
| **Tunnel modes** | | | | | | | |
| VXLAN overlay (`cilium_vxlan`, 8472/udp) | `skb_get_tunnel_key`, `skb_set_tunnel_key` (flags `BPF_F_ZERO_CSUM_TX`, `BPF_F_TUNINFO_IPV6`) | tunnel endpoint from ipcache | `SCHED_CLS` tcx ingress+egress on `cilium_vxlan` (`bpf_overlay`) | `VXLAN=m` (`NET_UDP_TUNNEL` auto); autoloaded by rtnetlink link creation | 4.9 | 6.6 | — |
| Geneve overlay (`cilium_geneve`, 6081/udp) | as VXLAN plus `skb_get_tunnel_opt`, `skb_set_tunnel_opt` (DSR option) | — | as VXLAN | `GENEVE=m` | 4.9 | 6.6 | — |
| Tunnel NOTRACK / proxy return NOTRACK (ADR-0003) | — | — | nftables `inet flowsdn` table, `notrack` on the tunnel port | `NF_TABLES=m NF_TABLES_INET=y NFT_CT=m NF_CONNTRACK=m`; installed only when conntrack is present | — | 6.6 | — |
| **Native routing / BPF host routing** | | | | | | | |
| Direct routing (`ENABLE_ROUTING`, `enable-bpf-host-routing`) | `fib_lookup` (4.18) + `redirect_neigh` (5.10); `BPF_FIB_LOOKUP_SKIP_NEIGH` (6.3), `BPF_FIB_LOOKUP_SRC` (6.7), `BPF_FIB_LOOKUP_MARK` (6.10) probed | node map, ipcache | tcx on native devices | `IP_MULTIPLE_TABLES FIB_RULES`; sysctl `rp_filter=0` on lxc/host devices | 5.10; flags optional | 6.6; `_SRC`/`_MARK` used only when present (feature-tested at start) | — |
| Endpoint routes mode, per-ENI tables (`10+ifindex`), IPsec table 200, VTEP 202, proxy 2004/2005 | — | — | rtnetlink `RTM_NEWRULE`/`RTM_NEWROUTE`, `FRA_TABLE` > 255 | `IP_MULTIPLE_TABLES IPV6_MULTIPLE_TABLES` | — | 6.6 | AWS ENA hotplug surfaces via netlink; udev renames must be tolerated (07). |
| Managed neighbors (`NTF_EXT_MANAGED`) | — | — | rtnetlink `RTM_NEWNEIGH` | — | 5.16 (probed functionally) | 6.6 | — |
| **KPR / NodePort / socket LB** | | | | | | | |
| Per-packet ClusterIP/NodePort/LB/ExternalIP/HostPort (`lb.h`, `nodeport.h`) | `csum_diff`, `l4_csum_replace`, `skb_store_bytes`, `get_prandom_u32`, `fib_lookup`, `redirect_neigh` | `HASH` services/backends/revnat (`cilium_lb4_services_v2`, `_backends_v3`, `_reverse_nat`), `LRU_HASH` affinity (`cilium_lb4_affinity`, `cilium_lb_affinity_match`), `LPM_TRIE` source ranges, `HASH` `cilium_skip_lb4`, `PROG_ARRAY` `cilium_calls_*` | tcx on lxc + native devices | — | 5.10 | 6.6 | NodePort SNAT with multiple devices: `rp_filter` on the direct-routing device must not be 1. |
| Socket LB (`bpf_sock`) | `get_socket_cookie` (4.12), `get_netns_cookie` (5.7), `sk_lookup_tcp`/`sk_lookup_udp`, `getsockopt`/`setsockopt` in `sock_addr` (5.12, health), `set_retval` (5.17, probed `HAVE_SET_RETVAL`), `get_cgroup_classid` (5.7) | `LRU_HASH` `cilium_lb4_reverse_sk`, services/backends as above | `CGROUP_SOCK_ADDR`: `connect4/6` (4.17), `sendmsg4/6`, `recvmsg4/6` (5.2; 4.19.57 backport), `getpeername4/6` (5.8), `bind4/6`; `CGROUP_SOCK`: `post_bind4/6`, `sock_release` (5.9). **cgroup bpf_link** (5.7) on the cgroup2 root | `CGROUP_BPF=y`; optional `CGROUP_NET_CLASSID` | 5.7 (links) / 5.12 (health) | 6.6 | Attached to the unified cgroup2 root; hybrid v1/v2 hosts are refused. |
| Socket termination on backend removal | kfunc `bpf_sock_destroy` (6.5; inventory 01 says 6.4, 02 says 6.5 — upstream is v6.5-rc1), `seq_write` | — | `TRACING` `iter/tcp`, `iter/udp` (5.9) with `.ksyms` BTF relocation; fallback `NETLINK_SOCK_DIAG` `SOCK_DESTROY` | `DEBUG_INFO_BTF=y` (kfunc resolution); fallback `INET_DIAG=m INET_TCP_DIAG INET_UDP_DIAG INET_DIAG_DESTROY=y` | 6.5 / fallback 4.9 | 6.6 (kfunc path); keep sock_diag fallback for the 6.6 line without the kfunc (feature-tested) | arm64 JIT kfunc-call support postdates x86's (5.13); present on 6.12 both arches. |
| HostPort loopback, LRP skip-LB, `socketLB.hostNamespaceOnly` | `get_netns_cookie` in BPF; userspace `SO_NETNS_COOKIE` | `cilium_skip_lb4` | — | — | `SO_NETNS_COOKIE` is 5.14 upstream (inventory 04 says 5.12, 06 says 5.7 — the latter is the BPF helper) | 6.6 | — |
| **DSR variants** | | | | | | | |
| DSR, IP option (IPv4) / destination option (IPv6), Hybrid | `skb_adjust_room` (`BPF_ADJ_ROOM_MAC`, 5.2), `skb_store_bytes`, `csum_diff`, `l3_csum_replace` | NodePort maps + `LRU_HASH` `cilium_snat_v4_external` (Hybrid) | tcx on native devices; optional XDP | — | 5.2 | 6.6 | — |
| DSR Geneve (`DSR_ENCAP_GENEVE`) | `skb_set_tunnel_key` + `skb_set_tunnel_opt` | — | `bpf_host` + `bpf_overlay` | `GENEVE=m` | 5.2 | 6.6 | — |
| DSR IPIP (`DSR_ENCAP_IPIP`, `cilium_ipip4`/`cilium_ipip6`) | `skb_adjust_room` (encap flags), `skb_change_proto` | — | tcx on `cilium_ipip*` | `NET_IPIP=m IPV6_TUNNEL=m`; sysctl `net.core.fb_tunnels_only_for_init_net=2` | 5.10 | 6.6 | — |
| DSR ICMP error translation (`ENABLE_DSR_ICMP_ERRORS`) | as DSR + `skb_load_bytes` deep into the inner header | — | — | — | 5.10 | 6.6 | Adds a full inner-header parse to the heaviest NodePort programs (section 3). |
| **Maglev** | `map_lookup_elem` on inner arrays | `HASH_OF_MAPS` outer (`cilium_lb4_maglev`, `cilium_lb6_maglev`), inner `ARRAY` per service with `BPF_F_RDONLY_PROG` (5.2), inner spec via BTF | userspace `BPF_MAP_CREATE` of inner + `BPF_MAP_UPDATE_ELEM` of fd (map-in-map, 4.12) | — | 5.2 | 6.6 | Table size M: default 16381 ≈ 20 MB permutation buffer; M = 131071 ≈ 1.3 GB in userspace during computation — cap on small arm64 nodes. |
| **XDP acceleration** (`loadBalancer.acceleration=native` or `best-effort`) | `xdp_adjust_head`, `xdp_adjust_meta`, `xdp_adjust_tail`, `redirect`, `xdp_load_bytes`/`xdp_store_bytes` (5.18, probed; software loops otherwise), `xdp_get_buff_len` (5.18); csum/adjust-room/tunnel are software (`ctx/xdp.h`, `CSUM_MANGLED_0`) | same LB/NAT/CT maps; `PERF_EVENT_ARRAY` | `XDP` on `--devices`; **XDP bpf_link** (5.7); `BPF_F_XDP_HAS_FRAGS` (5.18) attempted first, retried without; `XDP_TX` for DSR/ICMP hairpin, `XDP_REDIRECT` (`ndo_xdp_xmit`) to peers | none beyond core BPF; `XDP_SOCKETS` not needed | 5.7 / 5.18 | 6.6 | Native mode needs `ndo_bpf` in the NIC driver: i40e, ice, ixgbe, igb, igc, mlx4, mlx5, bnxt, ena, nfp, virtio_net, veth, tun; arm64 SoC drivers with native XDP: mvneta, mvpp2, dpaa2, stmmac (recent), hns3. Marvell/Annapurna `al_eth` on MikroTik RDS-class boards is out-of-tree without `ndo_bpf` → generic XDP only (slower than tcx; disable). `xdp_adjust_meta` must be driver-supported for `XFER_PKT_*` metadata to reach tc. |
| **BPF masquerade** (`enable-bpf-masquerade`, ip-masq-agent, egress IP) | `csum_diff`, `l3_csum_replace`, `l4_csum_replace`, `skb_store_bytes`, `fib_lookup` | `LRU_HASH` `cilium_snat_v4_external`/`v6`, `LPM_TRIE` `cilium_ipmasq_v4`/`v6`, node map | tcx egress on native devices; optional XDP reply path | none — no iptables MASQUERADE, no ipset (ADR-0003) | 5.10 | 6.6 | — |
| **Policy** | | | | | | | |
| L3/L4 identity policy, CIDR, deny, audit, policy verdict notify | `map_lookup_elem` LPM, `perf_event_output` | `LPM_TRIE` policy maps, `LPM_TRIE` ipcache, `PERCPU_HASH` `cilium_metrics`, `HASH` `cilium_auth_map` | lxc + host tcx | — | 4.11 | 6.6 | — |
| Host firewall (`ENABLE_HOST_FIREWALL`) | as policy + CT helpers on `from-netdev`/`to-netdev`; `skb->mark` 0xC00 "from host" | host endpoint policy map, host CT | tcx on native devices; nftables `meta mark set 0xC00` and forward-chain accept for `cilium_host`/`cilium_net` only in default-drop mode (ADR-0003) | `NF_TABLES=m` only when host policy is default-drop | 5.10 | 6.6 | Biggest single contributor to `bpf_host` verifier cost (section 3). |
| **L7 redirect / TPROXY** | | | | | | | |
| BPF TPROXY (`enable-bpf-tproxy`) | `sk_lookup_tcp`/`sk_lookup_udp` (4.20/5.2 for tc), `skc_lookup_tcp` (5.2), `sk_release`, `sk_assign` (5.7) | policy map `proxy_port`, CT `proxy_redirect` | tcx ingress on lxc / host | — | 5.7 | 6.6 (default on) | — |
| nftables TPROXY fallback + proxy marks + return-path NOTRACK (ADR-0003) | — | — | nftables prerouting `tproxy to :port` + `socket transparent`, `meta mark set`, `notrack`; `ip rule` tables 2004/2005 | `NF_TABLES NF_TABLES_INET NFT_TPROXY NF_TPROXY_IPV4 NF_TPROXY_IPV6 NFT_SOCKET NF_SOCKET_IPV4 NF_SOCKET_IPV6 NFT_CT NF_CONNTRACK` (all `=m`, autoloaded by nfnetlink) | — | 6.6 | `nft_socket` replaces `xt_socket`; the reference's `ip_early_demux=0` fallback for COS kernels without `xt_socket` is unnecessary. |
| Envoy (external DaemonSet) and DNS proxy sockets | — | Envoy reads pinned `cilium_ipcache` directly (`bpf_root`) | userspace: `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR`, `SO_MARK` (NET_ADMIN), `SO_REUSEPORT`, `SCM_RIGHTS` | — | — | 6.6 | Envoy image is multi-arch (`cilium/proxy`). |
| **WireGuard** (`encryption.type=wireguard`, 51871/udp, node encryption, strict mode) | `redirect`, `redirect_peer`, `skb_change_type`, ipcache LPM lookups; `set_decrypt_mark` | `HASH` node map (`cilium_node_map_v2`), `PROG_ARRAY` `cilium_calls_wireguard*`, `cilium_encrypt_state` | tcx ingress (+egress when needed) on `cilium_wg0` (`bpf_wireguard`); **no XDP on wg** | `WIREGUARD=m` (5.6) + its crypto selects; generic netlink `wireguard` family | 5.10 | 6.6 | ChaCha20-Poly1305 has NEON paths on arm64; throughput only. |
| **IPsec** (`encryption.type=ipsec`, ESP) | `skb->mark` SPI/node-ID encoding (`0x*E00`, SPI bits 12..15, node ID 16..31), `redirect`, `cb[]` meta carry across redirects | node map, `cilium_encrypt_state`, ipcache `encrypt_key` | tcx on native + `cilium_host`; XFRM in/out/fwd policies and states with mark + `output-mark`; routes in table 200 | `XFRM=y XFRM_USER=m XFRM_ALGO=m XFRM_STATISTICS=y` (`/proc/net/xfrm_stat`) `XFRM_OFFLOAD=y` (optional) `INET_ESP=m INET6_ESP=m INET_IPCOMP INET6_IPCOMP INET_XFRM_TUNNEL INET6_XFRM_TUNNEL INET_TUNNEL INET6_TUNNEL CRYPTO_AEAD CRYPTO_AEAD2 CRYPTO_GCM CRYPTO_SEQIV CRYPTO_CBC CRYPTO_HMAC CRYPTO_SHA256 CRYPTO_AES`; `NETLINK_XFRM` | 4.19 (`output-mark`) probed at start; RHEL 8.6 quirk | 6.6 | Decryption is single-core per SA on both arches. AES-GCM uses AES-NI on x86-64 and ARMv8-CE on arm64 (`CRYPTO_AES_ARM64_CE_BLK`, `CRYPTO_GHASH_ARM64_CE`) — throughput only. Boot ID from `/proc/sys/kernel/random/boot_id`. |
| **Egress gateway** (CEGP, egress IP, HA) | `fib_lookup` (+`BPF_FIB_LOOKUP_TBID` 6.5, optional), `redirect_neigh`, SNAT helpers | `LPM_TRIE` `cilium_egress_gw_policy_v4`/`v6`, `HASH` `cilium_egress_gw_ha_*`, SNAT maps | tcx on lxc egress, host, overlay; optional XDP reply path | `IP_MULTIPLE_TABLES`; tunnel device | 5.10; TBID optional | 6.6 | — |
| **Bandwidth manager / BBR** | writable `skb->tstamp` (EDT, 5.1, probed via `skb_ecn_set_ce`), `skb_set_tstamp` (5.18, BBR), `ktime_get_ns` | `HASH` `cilium_throttle` (EDT per endpoint) | tcx egress on native devices; `fq` root qdisc per device (`mq` + `fq` per TX queue) via rtnetlink | `NET_SCH_FQ=m` (`mq` is built into `NET_SCHED`), `TCP_CONG_BBR=m`; sysctls `net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`, `tcp_slow_start_after_idle=0`, `netdev_max_backlog`, `somaxconn`, `tcp_max_syn_backlog` | 5.1 / 5.18 (BBR) | 6.6 | — |
| **BIG TCP** (IPv6 5.19, IPv4 6.3) | none in BPF beyond larger `skb->len` handling | — | rtnetlink `IFLA_GSO_MAX_SIZE`, `IFLA_GRO_MAX_SIZE`, `IFLA_GSO_IPV4_MAX_SIZE`, `IFLA_GRO_IPV4_MAX_SIZE`, `IFLA_TSO_MAX_SIZE` | none | 5.19 / 6.3 | 6.6 (both families) | NIC driver must accept GSO > 64 KiB (mlx5 first; verify per NIC — most arm64 SoC NICs do not). |
| **netkit** pod devices (`bpf-datapath-mode=netkit` or `netkit-l2`) | as pod attach, without `redirect_peer` (`AttachNetkitPrimary` delivers directly) | as pod attach | `SCHED_CLS` via **netkit bpf_link** (`BPF_NETKIT_PRIMARY` on the host side, `BPF_NETKIT_PEER`) | `NETKIT=y` (6.7); scrub attributes 6.13 (backported to 6.12.y); tuned buffer margins | 6.8 | 6.12 line only; veth default below 6.8 | aya has no netkit link wrapper — raw `bpf(BPF_LINK_CREATE)` shim (inventory 02). |
| **Multicast** (`ENABLE_MULTICAST`, `cilium_mcast_group_outer_v4_map`) | `for_each_map_elem` (5.13) with a callback subprogram, `clone_redirect`, `redirect` | `HASH_OF_MAPS` outer, inner `HASH` per group (subscribers) | tcx on lxc, overlay, host | — | amd64 ≥ 5.10 (docs; only true with the RHEL backport of `for_each_map_elem`), arm64 ≥ 6.0 | 6.6 both | arm64 < 6.0 cannot mix callback subprogs with tail calls; irrelevant at 6.6. |
| **SRv6** (deferred) | `skb_adjust_room`, `skb_change_proto`, `skb_store_bytes` (SRH push/pop in BPF, no kernel `seg6` lightweight tunnels) | `LPM_TRIE` `cilium_srv6_policy_v4`/`v6`, `HASH` `cilium_srv6_vrf_*`, `cilium_srv6_sid` | tcx on lxc, host, overlay | `IPV6=y` | 5.10 | 6.6 | — |
| **IPv6** (dual-stack, IPv6-only, IPv6 underlay) | NDP responder in BPF (`ipv6_ndp`), `skb_load_bytes` for extension headers | v6 twins of every map | same hooks | `IPV6=y IPV6_MULTIPLE_TABLES=y`; `/proc/net/if_inet6` must exist; sysctl `net.ipv6.conf.all.disable_ipv6=0`, `forwarding=1` | hard check | 6.6 | — |
| **Monitor / Hubble** (observer, relay, metrics, exporter) | see monitor row | `PERF_EVENT_ARRAY` reader via `bpf_obj_get` on the pinned `cilium_events` | userspace only | — | — | 6.6 | Struct decoding is native-endian; both arches are little-endian. Bitfield byte layout is LSB-first on both. |
| **nftables residual** (ADR-0003; the only non-BPF datapath) | — | — | `NETLINK_NETFILTER` / `NFNL_SUBSYS_NFTABLES` batch transactions; one table `inet flowsdn` | `NF_TABLES=m NF_TABLES_INET=y NFT_CT=m NF_CONNTRACK=m` always available; `NFT_TPROXY NF_TPROXY_IPV4/6 NFT_SOCKET NF_SOCKET_IPV4/6` for L7; `nft_ct` `ct mark` for ENI `0x80` | — | 6.6 | Installs nothing when no residual feature is enabled. |
| **cgroup v2** (socket LB attach, pod metadata by cgroup id) | `get_current_cgroup_id` (4.18) | — | cgroup2 root fd for `BPF_LINK_CREATE`; `/sys/fs/cgroup` walked for container cgroup ids | `CGROUPS=y CGROUP_BPF=y MEMCG=y` (BPF memory accounting, 5.11) | — | 6.6 | Unified hierarchy only. |
| **Health** (`cilium-health`, 4240/tcp, ICMP) | — | — | ICMP raw socket (`CAP_NET_RAW`); `setns` into `lxc_health` netns (`CAP_SYS_ADMIN`) | — | — | 6.6 | — |
| **BGP** (own speaker, RouterOS backend) | — | — | `TCP_MD5SIG`, `IP_TTL`/`IPV6_UNICAST_HOPS`; `CAP_NET_BIND_SERVICE` only for `localPort` < 1024 | — | — | 6.6 | No BPF, no arch dependence. |
| **Operator, ClusterMesh, IPAM cloud, CRDs** | — | ClusterMesh per-cluster CT/SNAT `ARRAY_OF_MAPS` (unused by default) | userspace only; `SO_REUSEPORT`, `hostNetwork` | — | — | any | — |

Helpers declared by the reference but unused by flowsdn on the 6.6+ line:
`ringbuf_reserve/submit/discard` (declared, events stay on perf for Hubble
decoder compatibility — open question in inventory 01), `ktime_get_boot_ns`
(5.8), `map_lookup_percpu_elem` (5.19, used only by the ratelimit path),
`loop` (5.17, declared, unused by the reference; flowsdn may use it, see 2.3).

## 2. Minimum kernel decision

### 2.1 What the reference supports

Documented floor: **Linux ≥ 5.10**, or RHEL 8.10's 4.18 with backports.
`CheckRequirements` (`pkg/datapath/linux/requirements.go`) refuses to start
without every item in this list; everything else is probed and feature-gated.

| Hard check (fatal at start) | Kernel |
|---|---|
| `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT` + `HAVE_EBPF_JIT` | — |
| clsact + `NET_SCH_INGRESS` + `NET_CLS_BPF`, **or** tcx | — / 6.6 |
| `bpf_skb_change_tail` | 4.9 |
| `bpf_get_socket_cookie` in `cgroup/sock_addr` | 4.12 |
| `bpf_get_current_cgroup_id` in `cgroup/sock_addr` | 4.18 |
| `bpf_fib_lookup` in tc | 4.18 |
| Dead-code elimination on `.rodata` constants | 5.1 |
| Writable `skb->queue_mapping` / EDT (`bpf_skb_ecn_set_ce` as proxy) | 5.1 |
| 1 M instruction limit | 5.2 |
| `bpf_skb_adjust_room` `BPF_ADJ_ROOM_MAC` | 5.2 |
| `bpf_jiffies64` in `cgroup/sock`, `sock_addr`, tc, XDP | 5.5 (checked as 5.6) |
| `BPF_MAP_LOOKUP_BATCH` | 5.6 |
| `bpf_get_netns_cookie` in cgroup programs | 5.7 |
| `bpf_sk_assign` in tc | 5.7 |
| `bpf_get_cgroup_classid`, `bpf_perf_event_output` in `cgroup/sock_addr` | 5.7 |
| `bpf_csum_level`, `bpf_skb_change_head` in tc | 5.8 |
| `bpf_redirect_neigh`, `bpf_redirect_peer` | **5.10** |
| `CONFIG_IP_MULTIPLE_TABLES` (warn), `/proc/net/if_inet6` when IPv6 | — |

Probed and gated (from `probes.go`, `bpf_probes` objects, and the inventories):
`HaveV2ISA`/`HaveV3ISA` (`-mcpu`), `HaveBoundedLoops` (5.3),
`HAVE_SET_RETVAL` (5.17), `HAVE_XDP_GET_BUFF_LEN`/`HAVE_XDP_LOAD_BYTES`/
`HAVE_XDP_STORE_BYTES` (5.18), `BPF_F_XDP_HAS_FRAGS` (5.18, by retry),
`BPF_FIB_LOOKUP_SKIP_NEIGH` (6.3), `_TBID` (6.5), `_SRC` (6.7), managed
neighbors (5.16), tcx (6.6), netkit (6.7/6.8), `bpf_sock_destroy` (6.5),
`bpf_skb_set_tstamp` (5.18), BIG TCP (5.19 / 6.3), multicast (5.13 helper;
arm64 6.0), `kernel_hz` estimation, IPv6 support, XFRM output-mark (4.19).

The reference's own CI (`kernel-versions.yml`) no longer runs 5.10: the LVH set
is **rhel8.10 (4.18), 5.15, 6.1, 6.6, 6.12, 6.18**; the verifier matrix runs
5.15 with the `510` permutation set and 6.1/6.6/6.12/6.18 with `61`. 6.12 is the
most-used kernel across the reference's matrices (17 occurrences), then 6.18
(9), 6.6 and 5.15 (7 each), 6.1 (5), rhel8.10 (3).

### 2.2 What an aya-ebpf datapath actually needs

ADR-0002 says a 5.10 floor is not promised. The concrete reasons:

| Requirement | Why it matters for Rust/aya-ebpf | Kernel |
|---|---|---|
| Global data (`.rodata`/`.data`/`.bss` as array maps), `BPF_MAP_FREEZE`, `BPF_F_RDONLY_PROG` | aya-ebpf `static` globals patched by `EbpfLoader::set_global` replace the reference's `#define` configuration; the verifier treats frozen read-only values as constants and prunes dead branches (the `HaveDeadCodeElim` check) | 5.2 |
| 1 M instructions processed, 512-byte stack per frame, 8 frames, 33 tail calls | Rust output is larger than the hand-tuned C for the same logic (bounds checks, `Option`/`Result` lowering, slice copies) — the older the verifier, the more instructions it "processes" for the same program because state pruning is weaker | 5.2 limit; pruning quality improves through 5.x–6.x |
| Bounded loops | Rust `for i in 0..N` with const `N` verifies; iterator chains over runtime-length slices usually do not. Hand-unrolled copies as in the reference's `builtins.h` remain necessary | 5.3 |
| `bpf_loop` | The only way to express a data-dependent loop the verifier will not unroll (e.g. IPv6 extension-header walks, Maglev-free backend scans). Callback is a subprogram | 5.17 |
| `bpf_for_each_map_elem` | Multicast fan-out callback | 5.13 |
| BPF-to-BPF calls mixed with tail calls | LLVM does not honour `#[inline(always)]` unconditionally; any non-inlined function becomes a subprogram. The reference relies on `__always_inline` everywhere. A program that both calls a subprogram and tail-calls is rejected on x86 < 5.10 and **arm64 < 6.0** | x86 5.10, arm64 6.0 |
| Global functions verified once (`static` vs global subprogs with BTF `func_info`) | The main lever for cutting "insns processed" in Rust: a `#[inline(never)]` global function is verified once against its argument types rather than per call path. Needs BTF in the object (bpf-linker `--btf`) | 5.6 (global subprogs), 5.13+ for pointer-to-context args |
| ISA v3 (`-C target-cpu=v3`: `jmp32`, ALU32, `<` comparisons) | Fewer instructions, matches the reference's `-mcpu=v3` default; 32-bit subregister ops are what LLVM emits for `u32` arithmetic. v4 (`gotol`, sign-extending loads, `bswap`, 6.6 on both JITs) is not needed | 5.1 |
| Atomic fetch ops (`fetch_add` with used result) | Rust `AtomicU64::fetch_add` whose result is used emits `BPF_ATOMIC | BPF_FETCH`; result unused emits plain `xadd` (works everywhere). arm64 JIT gained the fetch forms later than x86 | x86 5.12, arm64 5.17 |
| BTF in the loaded object (`bpf-linker --btf`), kernel BTF at `/sys/kernel/btf/vmlinux` | Map definitions, `.rodata` datasec for `set_global`, `func_info` for global subprogs, kfunc (`.ksyms`) resolution for `bpf_sock_destroy`, aya feature detection | `CONFIG_DEBUG_INFO_BTF=y` |
| tcx links | The only tc attach path flowsdn implements (no clsact/`RTM_NEWTFILTER` legacy code, no `cls_bpf` filter ownership heuristics). aya: `SchedClassifier::attach_with_options(TcAttachOptions::TcxOrder)` | 6.6 |
| XDP, cgroup bpf_link, `BPF_LINK_UPDATE` | Atomic program replacement on upgrade without a traffic gap; pinned links survive agent restart | 5.7 |
| `BPF_F_XDP_HAS_FRAGS`, `bpf_xdp_load_bytes`/`store_bytes` | Multi-buffer XDP on drivers with jumbo/GRO; without `xdp_load_bytes` the software byte-loops cost verifier budget in `bpf_xdp` | 5.18 |
| memcg accounting of BPF memory | Removes `RLIMIT_MEMLOCK`, `CAP_SYS_RESOURCE` and the `rlimit.RemoveMemlock()` dance | 5.11 |
| `CAP_BPF` + `CAP_PERFMON` | Load and attach without `CAP_SYS_ADMIN` | 5.8 |
| `bpf_sock_destroy` kfunc (+ `iter/tcp`, `iter/udp`) | Socket termination without `INET_DIAG_DESTROY` | 6.5 (iters 5.9) |
| netkit + netkit bpf_link | Pod device without `redirect_peer`; not required, but the 6.12 line has it | 6.7 (6.8 as required by the reference) |

Toolchain facts that follow: BPF programs build with a pinned nightly
`rustc` for `bpfel-unknown-none` (`-Z build-std=core`) and `bpf-linker`
(LLVM matching rustc's, LLVM ≥ 19 in 2026, above the reference's 18.1 floor);
release profile `opt-level = 3`, `lto = true`, `codegen-units = 1`,
`panic = "abort"`, `overflow-checks = false`, `debug = true` (line info and BTF);
`RUSTFLAGS="-C target-cpu=v3"`. Any reachable `core::panicking::*` symbol
(unchecked indexing, `unwrap`, overflow) leaves an unresolved call in the
object and the load fails — the CI verifier job (section 3) is the gate for that
as much as for complexity.

### 2.3 Feature-by-kernel ladder

| Kernel | What becomes possible | Verdict for flowsdn |
|---|---|---|
| 5.10 | `redirect_neigh`/`redirect_peer`; reference floor | No tcx, no `bpf_loop`, no XDP frags, weak verifier pruning, arm64 cannot mix subprogs and tail calls, `SYS_RESOURCE`/memlock required. **Rejected.** |
| 5.15 | LVH `510` permutation row in the reference; `bpf_loop` absent (5.17) | Rejected for the same reasons minus memlock. |
| 6.1 LTS | `bpf_loop`, XDP frags, `xdp_load_bytes`, BBR `skb_set_tstamp`, IPv6 BIG TCP, arm64 subprog/tail-call parity, `SKIP_NEIGH` absent (6.3) | Still requires the legacy clsact attach path. Rejected as minimum. |
| **6.6 LTS** | tcx, IPv4 BIG TCP, `BPF_FIB_LOOKUP_SKIP_NEIGH`, `_TBID`, `bpf_sock_destroy` (6.5), ISA v4 | **General minimum.** Everything in section 1 works except netkit, `FIB_LOOKUP_SRC`/`_MARK`. |
| 6.7 / 6.8 | netkit device and link (6.7), netkit fixes the reference requires (6.8), `BPF_FIB_LOOKUP_SRC` | Enables the netkit datapath mode. |
| 6.10 | `BPF_FIB_LOOKUP_MARK` | Egress-gateway/ip-rule interplay in FIB lookups. |
| **6.12 LTS** | Everything above; netkit scrub attrs via backport; what Rocky 10 / RHEL 10 ship for the life of RHEL 10 | **Supported line (stormcos).** |
| 6.18 LTS | Reference's "latest" CI row; nothing flowsdn needs | Next line candidate when stormcos moves; canary in CI. |

### 2.4 Recommendation (a): the stormcos kernel

**x86-64: Rocky Linux 10 `kernel-6.12.0-2xx.el10` — already pinned by stormcos
(`stormcos/kernel/README.md`, validated pin `6.12.0-211.34.1.el10_2` on
2026-07-18).** stormcos consumes the RHEL-kABI rebuild kernel as-is, with no
custom config, because vendor kmods (Mellanox OFED, NVIDIA, HBAs) depend on the
kABI. flowsdn therefore does not get to choose a config; it gets to **verify**
one. The checklist stormcos already runs (`DEBUG_INFO_BTF`, `BPF_SYSCALL`,
`XDP_SOCKETS`, cgroup v2) must grow by the fragment in 2.6, and the items most
likely to be absent or modular in an enterprise config are: `NETKIT`,
`NET_SCH_FQ`, `TCP_CONG_BBR`, `NFT_TPROXY`/`NFT_SOCKET`, `INET_DIAG_DESTROY`,
`WIREGUARD`, `XFRM_STATISTICS`, `CGROUP_NET_CLASSID`. A missing knob is "an
upstream conversation or a documented feature cut, not a fork" (stormcos policy)
— so flowsdn's Helm/values mapping must be able to turn each affected feature
off cleanly.

Two runtime traits of the RHEL 10 line matter:

- It reports `6.12.0` but contains backports (e.g. netkit scrub attributes from
  6.13). The startup check must probe features (load a tiny program that uses
  the helper/flag, `bpf(BPF_LINK_CREATE)` with the tcx attach type on a dummy
  device, `/sys/kernel/btf/vmlinux` presence), not parse `uname -r`.
- RHEL ships hardening sysctls (`kernel.io_uring_disabled=2` bit stormcos
  already; expect `kernel.unprivileged_bpf_disabled=2` — irrelevant to a
  `CAP_BPF` agent — and `net.core.bpf_jit_harden` possibly set, which costs JIT
  performance; the agent should warn if `bpf_jit_harden != 0`).

**arm64: the same 6.12 line.** Rocky 10 publishes `aarch64` builds of the
identical source (`kernel-6.12.0-2xx.el10.aarch64`, 4 K pages; `kernel-64k` is
the 64 K-page variant). Where the arm64 node boots a stock RHEL 10 kernel
(Ampere/Graviton-class servers) use it unchanged. Where the board needs a vendor
or out-of-tree kernel (MikroTik RDS-class Annapurna/Marvell SoCs with `al_eth`),
build upstream `6.12.y` LTS with the fragment in 2.6 and the vendor drivers on
top — still 6.12, so one feature set and one verifier behaviour per release.
Do not adopt a 6.6-based vendor BSP kernel for arm64: it splits the line and
loses netkit and `FIB_LOOKUP_SRC` on one arch only.

Why 6.12 rather than 6.6: it is what stormcos runs (deciding anything else
means a second kernel to maintain); it is the most-exercised kernel in the
reference's CI; it carries netkit, `FIB_LOOKUP_SRC`/`_MARK` and the netkit
scrub backport; and, being the RHEL 10 base, its maintenance horizon is RHEL
10's (2035), far past the upstream `6.6.y`/`6.12.y` LTS end dates (both listed
as December 2026 on kernel.org at the time of writing — verify). When stormcos
moves to a newer base, flowsdn re-runs the matrix; 6.18 LTS is already in the
reference's CI set and needs nothing new.

### 2.5 Recommendation (b): documented minimum for general use

**Linux ≥ 6.6 LTS with the config fragment in 2.6**, refused at startup
otherwise. Netkit mode additionally requires ≥ 6.8; `BPF_FIB_LOOKUP_SRC` and
`_MARK` are used when present and silently not used otherwise (feature test at
start; the object is built with the flags and the loader patches a `.rodata`
boolean). Distributions that satisfy this today: Debian 13 (6.12), Ubuntu 24.04
(6.8) and later, Fedora/CoreOS current, RHEL 10 family (6.12), Talos ≥ 1.8
(6.6+), Flatcar current (6.6+), Bottlerocket current (6.12), GKE COS current
(6.6), Amazon Linux 2023 (6.12). Not satisfied: RHEL 8 (4.18), RHEL 9 (5.14),
Ubuntu 22.04 GA kernel (5.15; HWE 6.8 is fine), Debian 12 (6.1), Amazon Linux
2 (5.10).

### 2.6 Kernel config fragment

Suitable for `scripts/config --enable`/`--module` followed by `make
olddefconfig`, or as the checklist against a distribution config. `=m` items
autoload on first use through the kernel's own `request_module` (rtnetlink link
creation for `vxlan`/`geneve`/`ipip`/`ip6_tunnel`/`wireguard`, nfnetlink for
`nf_tables`, `tc qdisc add` for `sch_fq`, `NETLINK_XFRM` for `xfrm_user`,
sysctl for `tcp_bbr`) — the agent never needs `CAP_SYS_MODULE`. On a
`scratch`/stormcos node the modules must be in the image; there is no package
manager to fetch them later.

```
# --- BPF core (required) ------------------------------------------------
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y          # recommended; fixes net.core.bpf_jit_enable=1
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_DEBUG_INFO_BTF=y             # kernel BTF: kfuncs, aya feature detection
CONFIG_DEBUG_INFO_BTF_MODULES=y     # recommended
CONFIG_BPF_EVENTS=y                 # reference lists it; only trace_printk/debug needs it
CONFIG_PERF_EVENTS=y                # cilium_events perf ring
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y                 # socket LB
CONFIG_CGROUP_NET_CLASSID=y         # optional: bpf_get_cgroup_classid
CONFIG_MEMCG=y                      # BPF memory accounting (no RLIMIT_MEMLOCK)
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
# CONFIG_BPF_LSM is NOT required: the reference attaches no LSM programs.
# CONFIG_BPF_UNPRIV_DEFAULT_OFF may be y: the agent holds CAP_BPF.

# --- tc / tcx attach (required) -----------------------------------------
CONFIG_NET_SCHED=y
CONFIG_NET_CLS_ACT=y                # selects NET_XGRESS, NET_INGRESS, NET_EGRESS -> tcx
CONFIG_NET_SCH_INGRESS=m            # legacy clsact only; not used by flowsdn, harmless
CONFIG_NET_CLS_BPF=m                # legacy cls_bpf only; not used by flowsdn, harmless

# --- devices -------------------------------------------------------------
CONFIG_VETH=y                       # pod devices (default), cilium_host/cilium_net
CONFIG_NETKIT=y                     # netkit pod devices (>= 6.7; used on the 6.12 line)
CONFIG_VXLAN=m                      # tunnel mode vxlan (8472/udp)
CONFIG_GENEVE=m                     # tunnel mode geneve, DSR geneve (6081/udp)
CONFIG_NET_UDP_TUNNEL=m
CONFIG_NET_IPIP=m                   # DSR IPIP (v4)
CONFIG_IPV6_TUNNEL=m                # DSR IPIP (v6)

# --- routing -------------------------------------------------------------
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_MULTIPLE_TABLES=y         # ip rules: ENI tables, IPsec 200, proxy 2004/2005
CONFIG_IPV6_MULTIPLE_TABLES=y
CONFIG_FIB_RULES=y
CONFIG_INET_DIAG=m                  # socket termination fallback (sock_diag)
CONFIG_INET_TCP_DIAG=m
CONFIG_INET_UDP_DIAG=m
CONFIG_INET_DIAG_DESTROY=y

# --- nftables residual (ADR-0003) ---------------------------------------
CONFIG_NETFILTER=y
CONFIG_NF_TABLES=m
CONFIG_NF_TABLES_INET=y
CONFIG_NF_CONNTRACK=m               # notrack / ct mark statements
CONFIG_NFT_CT=m
CONFIG_NFT_TPROXY=m                 # L7 TPROXY fallback when BPF TPROXY is off
CONFIG_NF_TPROXY_IPV4=m
CONFIG_NF_TPROXY_IPV6=m
CONFIG_NFT_SOCKET=m                 # "socket transparent" (replaces xt_socket)
CONFIG_NF_SOCKET_IPV4=m
CONFIG_NF_SOCKET_IPV6=m
# No CONFIG_NETFILTER_XT_*, CONFIG_IP_SET*, CONFIG_IP_NF_* are required.

# --- bandwidth manager / BBR --------------------------------------------
CONFIG_NET_SCH_FQ=m
CONFIG_TCP_CONG_BBR=m
CONFIG_TCP_CONG_ADVANCED=y

# --- WireGuard -----------------------------------------------------------
CONFIG_WIREGUARD=m                  # selects its crypto (curve25519, chacha20poly1305, blake2s)

# --- IPsec (GCM-128-AES per the reference; CBC/HMAC for the legacy cipher) -
CONFIG_XFRM=y
CONFIG_XFRM_USER=m
CONFIG_XFRM_ALGO=m
CONFIG_XFRM_STATISTICS=y            # /proc/net/xfrm_stat metrics
CONFIG_XFRM_OFFLOAD=y               # optional, NIC crypto offload
CONFIG_INET_ESP=m
CONFIG_INET6_ESP=m
CONFIG_INET_IPCOMP=m
CONFIG_INET6_IPCOMP=m
CONFIG_INET_XFRM_TUNNEL=m
CONFIG_INET6_XFRM_TUNNEL=m
CONFIG_INET_TUNNEL=m
CONFIG_INET6_TUNNEL=m
CONFIG_CRYPTO_AEAD=m
CONFIG_CRYPTO_AEAD2=m
CONFIG_CRYPTO_GCM=m
CONFIG_CRYPTO_SEQIV=m
CONFIG_CRYPTO_CBC=m
CONFIG_CRYPTO_HMAC=m
CONFIG_CRYPTO_SHA256=m
CONFIG_CRYPTO_AES=m
# x86-64 throughput: CONFIG_CRYPTO_AES_NI_INTEL=m CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL=m
# arm64 throughput:  CONFIG_CRYPTO_AES_ARM64_CE_BLK=m CONFIG_CRYPTO_GHASH_ARM64_CE=m
#                    CONFIG_CRYPTO_CHACHA20_NEON=m CONFIG_CRYPTO_POLY1305_NEON=m

# --- not required (present in the reference's list) ---------------------
# CONFIG_CRYPTO_SHA1 / CONFIG_CRYPTO_USER_API_HASH: the reference hashes
#   endpoint headers via AF_ALG for its runtime clang compile; flowsdn has
#   no runtime compile.
# CONFIG_SCHEDSTATS: listed by the reference without a consumer in flowsdn.
# CONFIG_XDP_SOCKETS: AF_XDP is not used (stormcos enables it for other users).
```

## 3. Verifier-complexity risk

### 3.1 Limits and how the reference measures them

Kernel limits: **1 000 000 instructions processed** per program load (5.2+),
**512 bytes of stack per frame**, 8 call frames, 33 chained tail calls, 64 maps
referenced per program. The reference's `tools/complexity-diff` flags a program
at **50 % of the instruction limit (warning) and 70 % (error)**, and at 75 % /
90 % of the stack-depth and map-count limits; `TestPrivilegedVerifier`
(`pkg/datapath/loader/verifier_test.go`) loads every object under every
permutation in `bpf/complexity-tests/<kernel>/<object>/*.txt`, parses
`processed N insns (limit 1000000) … stack depth A+B+C … verification time`,
writes `verifier-complexity.json` and the workflow diffs base vs PR. The JSON
is a CI artifact, not in tree, so exact per-program counts are not quotable
here; the structure of the permutation files is the evidence.

### 3.2 Which programs sit closest to the limits

Permutation counts per object (`510` → `netnext`): `bpf_host` 8 → 8,
`bpf_lxc` 7 → 7, `bpf_wireguard` 7 → 7, `bpf_xdp` 6 → 7, `bpf_overlay` 4 → 3,
`bpf_sock` 2 → 2. The everything-on set (`bpf/Makefile` `MAX_BASE_OPTIONS`) is:

```
SKIP_DEBUG ENABLE_IPV4 ENABLE_IPV6 ENABLE_ROUTING POLICY_VERDICT_NOTIFY
MONITOR_AGGREGATION=3 CT_REPORT_FLAGS ENABLE_HOST_FIREWALL ENABLE_SRV6
ENABLE_L7_LB ENABLE_MASQUERADE_IPV4 ENABLE_IP_MASQ_AGENT_IPV4
ENABLE_MASQUERADE_IPV6 ENABLE_IP_MASQ_AGENT_IPV6 ENABLE_NODEPORT
ENABLE_NODEPORT_ACCELERATION ENABLE_DSR_ICMP_ERRORS ENABLE_DSR ENABLE_DSR_BYUSER
ENABLE_BANDWIDTH_MANAGER ENABLE_EGRESS_GATEWAY ENABLE_VTEP
ENABLE_CLUSTER_AWARE_ADDRESSING ENABLE_INTER_CLUSTER_SNAT ENABLE_NAT_46X64
ENABLE_NAT_46X64_GATEWAY ENCAP_IFINDEX TUNNEL_MODE ENABLE_MULTICAST
ENABLE_WIREGUARD ENCRYPTION_STRICT_MODE_EGRESS ENABLE_SCTP
ENABLE_ACTIVE_CONNECTION_TRACKING
```

What the permutation sets reveal:

| Observation | Meaning |
|---|---|
| Every `510` file carries `SKIP_DEBUG`; `netnext/bpf_host/7.txt` and `netnext/bpf_wireguard/7.txt` are the only debug (tracing-on) builds and exist only for the new verifier | The all-features **debug** `bpf_host` does not fit on 5.10; it fits on 6.x only because of better state pruning. The same program text costs more "insns processed" on an older verifier. |
| `bpf_host` has the most permutations and the longest option lists (up to 27 defines), and one 13-option "LB" set (`ENABLE_SOCKET_LB_FULL`, `ENABLE_L7_LB`, `ENABLE_EGRESS_GATEWAY`, `SERVICE_NO_BACKEND_RESPONSE`) | The heaviest programs are in `bpf_host`: `cil_from_netdev` → `tail_handle_ipv4_from_netdev`/`ipv6` (host firewall ingress + NodePort ingress + DSR + reverse NAT + encryption marks), `tail_nodeport_nat_ingress_ipv4/6`, `tail_nodeport_nat_egress_ipv4/6`, `tail_rev_nodeport_lb4/6`, `tail_nodeport_ipv4_dsr`, and `cil_to_netdev` (host firewall egress + BPF masquerade + egress gateway + WireGuard/IPsec redirect). `nodeport.h`, `lb.h` and `nat.h` are the three largest library headers and all three are inlined into these entry points. |
| `bpf_lxc` permutations toggle v4/v6 and DSR encap modes | `cil_from_container` → `tail_handle_ipv4_cont`/`ipv6_cont` (CT + policy + per-packet LB + egress gateway + encryption + tunnel/native branching) is the second cluster; the reference splits CT lookup into `TAIL_CT_LOOKUP4` explicitly to reset the verifier's state budget. |
| `bpf_xdp` 510 lacks `HAVE_XDP_LOAD_BYTES`/`HAVE_XDP_STORE_BYTES`/`HAVE_XDP_GET_BUFF_LEN` | Without those helpers `cil_xdp_entry` → `tail_lb_ipv4/6` does header access and checksums with software byte loops; all NodePort/DSR/ICMP-error logic runs without `skb` helpers. On 6.6+ the helpers exist and this shrinks. |
| `bpf_overlay` loses a permutation from 510 to netnext | Overlay is comfortable; its budget concern is only when host firewall + SRv6 + DSR are all on. |
| `bpf_sock` has two permutations | Small programs; the risk there is not complexity but the per-hook attach semantics. |

Explicit `#pragma unroll` sites (`ipv6.h` extension-header walk ×2, `nat.h`
×2, `nodeport.h` ×1) mark loops the reference must unroll to verify — each is a
place where Rust must either unroll identically or move to `bpf_loop` (5.17,
available on the 6.6 minimum).

### 3.3 What this implies for ADR-0002

1. **Rust output is larger for the same logic.** Bounds checks on every slice
   access, `Option`/`Result` lowering, `memcpy` for struct moves > 8 bytes,
   and LLVM inlining decisions that ignore `#[inline(always)]` under size
   pressure all add instructions and, worse, add *verifier paths*. Expect
   1.5–3× the "insns processed" of the C for a first port of the NodePort
   path. The 6.6 minimum buys the better verifier; it does not buy a bigger
   limit.
2. **One object per hook family first (#53).** Follow datapath spec §6.2:
   runtime configuration and pruning are the default. Each object is shared
   by x86-64 and arm64. Add compile-time feature variants only after measured
   all-features results on the 6.6 floor exceed 800,000 instructions or 480 B
   stack. Address-family, tunnel and DSR dimensions remain candidates, not a
   preselected matrix. This replaces the earlier unmeasured matrix prescription;
   ADR-0002 explicitly leaves variant count to the datapath spec.
3. **A loader-side reachability pass** is mandatory, using Tier A of loader
   spec §5.2: evaluate known `.rodata` conditions conservatively and remove
   unreachable tail programs and unused maps from the collection. The kernel
   performs instruction dead-code elimination. Physically removing blocks and
   rewriting branches/BTF metadata is optional Tier B, justified by measurements
   under loader spec §12.1; it is not a prerequisite for the first object.
   Live-map and tail-call limits remain part of verifier validation.
4. **Use global subprograms deliberately.** A `#[inline(never)]` global
   function with BTF `func_info` is verified once; use it for CT lookup, NAT
   rewrite, policy lookup and the LB backend selection so those bodies are not
   re-verified along every branch of every caller. Stack: each frame is
   limited to 512 bytes and frames nest, so large scratch stays in
   `PERCPU_ARRAY` maps as in the reference.
5. **Tail calls remain the state-reset tool** at the boundaries the reference
   uses (`TAIL_CT_LOOKUP4`, `tail_nodeport_*`, `tail_handle_ipv4_cont`), and
   `ProgramArray` population from a `tail:`-style attribute list keeps the
   `cilium_calls_*` layout compatible for `cilium-dbg`.
6. **CI gate from day one.** The verifier job (section 5.3) loads every
   object variant under the everything-on `.rodata` configuration on every
   matrix kernel, records `insns processed`, stack depth and map count, and
   fails above 800,000 instructions or 480 B stack and warns on a greater
   than 10% instruction-count regression against the previous commit, matching
   datapath spec §9.4. Hard kernel map/tail-call limits remain mandatory. Trend the JSON per program; the number to watch is the
   `bpf_host` NodePort family on the 6.6 x86-64 row, which is the oldest
   verifier in the matrix.
7. **The panic-path problem is a verifier problem too.** A stray
   `core::panicking` reference fails the load with an unresolved call, not a
   complexity error; the same CI job catches it, but the datapath crate lints
   (`clippy::indexing_slicing`, `arithmetic_side_effects` as deny) should
   catch it earlier.

## 4. Userspace platform requirements

### 4.1 bpffs

- Detect: `statfs("/sys/fs/bpf")` with `f_type == BPF_FS_MAGIC (0xcafe4a11)`.
  If absent and `CAP_SYS_ADMIN` is held, `mount("bpffs", "/sys/fs/bpf",
  "bpf", 0, NULL)`; otherwise fail with the `sys-fs-bpf.mount` unit as the
  documented host-side fix. In Kubernetes the mount must be `Bidirectional`
  so pins outlive the pod (privileged init container, or host mounts it —
  open question 4 in inventory 15).
- Pin layout kept byte-compatible with the reference for `cilium-dbg`,
  `bpftool` and the Hubble/Envoy consumers (inventory 02): maps under
  `/sys/fs/bpf/tc/globals/cilium_*`, links and programs under
  `/sys/fs/bpf/cilium/...` (the datapath spec fixes the exact tree). Envoy's
  `cilium.bpf_metadata` opens `cilium_ipcache` under `bpf_root`, so the path
  is part of the Envoy contract.

### 4.2 cgroup v2

- Detect the unified hierarchy: `statfs("/sys/fs/cgroup")` with
  `f_type == CGROUP2_SUPER_MAGIC (0x63677270)`. If the host is hybrid or v1,
  the reference mounts a private cgroup2 root at `/run/cilium/cgroupv2`
  (`cgroup-root` option) via an `nsenter` init container. flowsdn: use the
  host's unified root when present; otherwise mount cgroup2 at
  `/run/cilium/cgroupv2` from the agent when `CAP_SYS_ADMIN` is held, else
  refuse socket LB. Socket LB links attach to that root fd.
- Pod metadata by cgroup id (Hubble `TraceSock`, `bpf_get_current_cgroup_id`)
  walks the container runtime's cgroup paths under the same root.

### 4.3 `/proc/sys` keys written (from `pkg/datapath/linux/sysctl` users)

| Key | Value | When |
|---|---|---|
| `net.core.bpf_jit_enable` | 1 (ignore error; fixed with `BPF_JIT_ALWAYS_ON`) | start |
| `net.ipv4.ip_forward`, `net.ipv4.conf.all.forwarding`, `net.ipv6.conf.all.forwarding` | 1 | start |
| `net.ipv4.conf.all.rp_filter` | 0 | start |
| `net.ipv4.conf.<dev>.rp_filter` for `lxc*`, `cilium_host`, `cilium_net`, `cilium_wg0`, ENI devices | 0 (2 on the primary ENI in ENI mode) | device creation |
| `net.ipv4.conf.<dev>.{forwarding=1, accept_local=1, send_redirects=0}` | | `cilium_host`/`cilium_net`, lxc |
| `net.ipv6.conf.<dev>.forwarding`, `net.ipv6.conf.all.disable_ipv6=0`, `net.ipv6.conf.<dev>.disable_ipv6` | | IPv6 |
| `net.core.fb_tunnels_only_for_init_net` | 2 | IPIP devices (DSR IPIP) |
| `net.ipv4.fib_multipath_use_neigh` | 1 | multipath routing |
| `net.ipv4.ip_early_demux` | 0 | reference only, `xt_socket` fallback — **not needed with `nft_socket`** |
| `kernel.unprivileged_bpf_disabled` | 1 | start (reference hardening; keep) |
| `kernel.timer_migration` | 0 | bandwidth manager |
| `net.core.default_qdisc` | `fq` | bandwidth manager |
| `net.ipv4.tcp_congestion_control` | `bbr` (or restore `cubic`) | bandwidth manager BBR |
| `net.ipv4.tcp_slow_start_after_idle` | 0 | bandwidth manager |
| `net.core.netdev_max_backlog`, `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog` | tuned | bandwidth manager |
| `net.ipv4.tcp_mtu_probing`, `tcp_base_mss`, `tcp_mtu_probe_floor` | | MTU probing option |
| `net.ipv4.ip_local_port_range`, `ip_local_reserved_ports` | | port reservation for proxy ports |

Persistence: `systemd-sysctl` re-applies distro `rp_filter=1` on device
hotplug; the reference writes `/etc/sysctl.d/99-zzz-override_cilium.conf` from
an `nsenter` init container. flowsdn writes the same file through a `/host/etc`
hostPath (no `nsenter`, no shell) and sets per-device values at link creation
through the mounted `/host/proc/sys/net` (inventory 15).

### 4.4 Netlink families and other kernel interfaces

| Family / interface | Used for | Crate direction (inventory 03) |
|---|---|---|
| `NETLINK_ROUTE` | links (veth/netkit/vxlan/geneve/ipip/wg create, MTU, GSO/GRO sizes, altnames), addresses, routes, rules (`FRA_TABLE` > 255), neighbors (`NTF_EXT_MANAGED`), qdiscs (`fq`, `mq`); subscriptions `RTNLGRP_LINK`, `IPV4_IFADDR`, `IPV6_IFADDR`, `IPV4_ROUTE`, `IPV6_ROUTE`, `NEIGH` with dump-interrupted retry | `rtnetlink` / `netlink-packet-route` |
| `NETLINK_XFRM` | IPsec states/policies (in/out/fwd) with mark + `output-mark`, SPI rotation, `/proc/net/xfrm_stat` | `netlink-packet-xfrm` (immature) or own encoding |
| `NETLINK_GENERIC` | `wireguard` family (device, peers, allowed IPs, keys), `nlctrl` family lookup | `wireguard-uapi` / `genetlink` |
| `NETLINK_NETFILTER` | nftables (`NFNL_SUBSYS_NFTABLES`) batch transactions for the residual | `nftnl`/`rustables`-class or own |
| `NETLINK_SOCK_DIAG` | `SOCK_DIAG_BY_FAMILY` dumps, `SOCK_DESTROY` (socket termination fallback) | `netlink-packet-sock-diag` |
| `bpf(2)` | maps, programs, links (`BPF_LINK_CREATE` tcx/netkit/XDP/cgroup, `BPF_LINK_UPDATE`), batch map ops, BTF load, `BPF_PROG_TEST_RUN` (tests, probes), `BPF_OBJ_PIN/GET` | `aya` + raw shims for gaps |
| `perf_event_open(2)` + `mmap` | `cilium_events` reader, one ring per CPU | `aya::maps::perf` |
| `mount(2)`, `setns(2)`, `unshare` | bpffs/cgroup2 mounts; entering pod and `lxc_health` netns via `/proc/<pid>/ns/net` or `/var/run/netns/<name>` fds | `nix` |
| `renameat2(RENAME_EXCHANGE)`, `flock` | atomic endpoint state-dir swap under `/var/run/cilium/state` | `std`/`nix` |
| procfs | `/proc/sys/kernel/random/boot_id` (IPsec), `/proc/net/if_inet6`, `/proc/stat` (CPU count), `/proc/net/xfrm_stat`, `/proc/<pid>/cgroup` | `std::fs` |
| Socket options | `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`, `SO_MARK`, `SO_REUSEPORT`, `SO_NETNS_COOKIE` (5.14), `TCP_MD5SIG`, `IP_TTL`, `SCM_RIGHTS` | `socket2`/`nix` |

### 4.5 Capabilities

The reference documents `CAP_SYS_ADMIN` as the minimum and ships the agent with
`CHOWN, KILL, NET_ADMIN, NET_RAW, IPC_LOCK, SYS_MODULE, SYS_ADMIN,
SYS_RESOURCE, DAC_OVERRIDE, FOWNER, SETGID, SETUID, SYSLOG` (inventory 15 §F3),
plus `SYS_ADMIN, SYS_CHROOT, SYS_PTRACE` for the two `nsenter` init containers,
a fully privileged `mount-bpf-fs` init and a privileged `wait-for-kube-proxy`
init. With a 6.6 minimum, a scratch image and no iptables, the mapping becomes:

| Operation | Capability on ≥ 6.6 | Reference needed | Note |
|---|---|---|---|
| `bpf(2)`: create maps, load `SCHED_CLS`/`XDP`/cgroup programs, pin, batch ops, BTF load | `CAP_BPF` | `SYS_ADMIN` (< 5.8) | `kernel.unprivileged_bpf_disabled` irrelevant to a capable process |
| Load `BPF_PROG_TYPE_TRACING` (`iter/tcp`, `iter/udp`), `bpf_trace_printk`, read kernel BTF for kfuncs | `CAP_BPF` + `CAP_PERFMON` | `SYS_ADMIN` | debug tracing prints also need `PERFMON` |
| `perf_event_open` for `cilium_events` | `CAP_PERFMON` (or `perf_event_paranoid` ≤ 1) | `SYS_ADMIN` | |
| mmap the perf rings beyond `RLIMIT_MEMLOCK` | `CAP_IPC_LOCK` | same | perf mmap is still memlock-accounted; 64 pages × CPUs exceeds 8 MiB quickly |
| Attach tcx/XDP/netkit links, cgroup socket programs; netlink writes (links, addrs, routes, rules, neigh, qdisc, xfrm, wireguard, nftables); `SO_MARK`, `IP_TRANSPARENT` | `CAP_NET_ADMIN` | same | loading `CGROUP_SOCK*` program types also requires `NET_ADMIN` |
| ICMP raw socket (health prober), `AF_PACKET` if ever used | `CAP_NET_RAW` | same | |
| Mount bpffs / cgroup2; `setns` into pod and `lxc_health` netns | `CAP_SYS_ADMIN` | same | The only remaining reason for `SYS_ADMIN`. Removable if the host mounts bpffs/cgroup2 and netns entry is confined to the CNI plugin invocation (which runs as root from kubelet anyway). |
| `setrlimit(RLIMIT_MEMLOCK, ∞)` | **not needed** | `SYS_RESOURCE` | BPF memory is memcg-accounted since 5.11 |
| Load kernel modules (`xt_*`, `ip_set`) | **not needed** | `SYS_MODULE` | no iptables (ADR-0003); remaining modules autoload via kernel `request_module` |
| Kill the embedded Envoy | **not needed** | `KILL` | Envoy is its own DaemonSet (ADR-0001) |
| `chown` unix sockets to `proxy-gid` | `CAP_CHOWN` | same | only when Envoy/Hubble sockets must be group-owned; otherwise drop |
| Package-install leftovers | **not needed** | `DAC_OVERRIDE, FOWNER, SETGID, SETUID` | scratch image, no runtime compile |
| `dmesg`/kptr | **not needed** | `SYSLOG` | |
| `nsenter` into PID 1 mount ns (init containers) | `CAP_SYS_ADMIN, SYS_CHROOT, SYS_PTRACE` | same | only if the `mount-cgroup`/`apply-sysctl` inits are kept; hostPath writes remove the need |
| BGP `localPort` < 1024 | `CAP_NET_BIND_SERVICE` | same | off by default |

Resulting per-container sets (`drop ALL`, then add):

| Container | `capabilities.add` |
|---|---|
| `flowsdn-agent` | `NET_ADMIN, NET_RAW, BPF, PERFMON, IPC_LOCK, SYS_ADMIN` (+ `CHOWN` if proxy-gid sockets, + `NET_BIND_SERVICE` if BGP < 1024) |
| init `config` (build-config) | none |
| init `mount-bpf-fs` | `privileged: true` (only if the host does not mount bpffs; `Bidirectional` propagation requires privileged) |
| init `mount-cgroup`, `apply-sysctl-overwrites` | `SYS_ADMIN` only, via hostPath (no `SYS_CHROOT`/`SYS_PTRACE` once `nsenter` is gone) |
| init `install-cni-binaries`, `clean-state` | none / `NET_ADMIN, BPF, SYS_ADMIN` |
| `flowsdn-cni` (invoked by kubelet) | runs as root in the host namespaces; `setns` into the pod netns |
| `cilium-envoy` (upstream image) | `NET_ADMIN, SYS_ADMIN` as upstream (`IP_TRANSPARENT`, netns) |
| `flowsdn-operator`, `hubble-relay`, `hubble-ui`, `clustermesh-apiserver` | none; non-root uid |

`securityContext.privileged=true` remains a values switch for hosts where
`CAP_BPF` is filtered by a runtime profile; RHEL 8 (`SYS_ADMIN`-only BPF) is not
a supported target, so the switch is convenience, not a requirement.

### 4.6 What a scratch image needs on disk

- **The binary only**: `/flowsdn` (static, `musl` or static-PIE glibc-free
  Rust), multi-call: `agent`, `cni`, `install-cni`, `build-config`,
  `mount-cgroup`, `cleanup`, `dbg`. No shell, no `iptables`, no `clang`, no
  `bpftool`, no CA bundle (`rustls` + `webpki-roots` or the Kubernetes SA CA
  from `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`), no timezone
  data, no `/etc/passwd` (runs as uid 0).
- **BPF objects embedded** in the binary (`include_bytes_aligned!`), one per
  hook-family variant (section 3.3), built at image build time on dev.
- **Host paths mounted**: `/var/run/cilium` (kept for `cilium-dbg`/Hubble
  compatibility: `cilium.sock`, `hubble.sock`, `state/<epid>/ep_config.json`,
  `health-endpoint.pid`), `/sys/fs/bpf` (Bidirectional), `/sys/fs/cgroup` or
  `/run/cilium/cgroupv2`, `/var/run/netns`, `/proc/sys/net`, `/proc/sys/kernel`,
  `/host/etc/sysctl.d`, `/opt/cni/bin`, `/etc/cni/net.d`, `/tmp/cilium/config-map`
  (ConfigMap projection read with `--config-dir`). Dropped versus the
  reference: `/lib/modules`, `/run/xtables.lock`, `/var/lib/cilium/bpf` (no
  template compile), `/hostbin`, `/hostproc` (once `nsenter` inits are gone).
- **Kernel modules** are the host's responsibility (they autoload); on
  stormcos they are in the golden image because there is no package manager on
  the node.

### 4.7 Startup check (ADR-0001: refuse to run, no adaptive probing)

Fail with a single actionable message if any of these is false; log a
one-line summary of the optional features found.

Required: `bpf(BPF_PROG_LOAD)` works (`CAP_BPF`); JIT enabled
(`/proc/sys/net/core/bpf_jit_enable == 1` or `BPF_JIT_ALWAYS_ON`);
`/sys/kernel/btf/vmlinux` readable; tcx link creation succeeds on a scratch
device (`BPF_LINK_CREATE`, `BPF_TCX_INGRESS`); helpers `redirect_neigh`,
`redirect_peer`, `sk_assign`, `fib_lookup`, `csum_level`, `skb_change_head`
accepted in `SCHED_CLS` (load a probe program per helper, as
`features.HaveProgramHelper` does); `bpf_loop` accepted; `BPF_MAP_LOOKUP_BATCH`
works on an LRU map; cgroup2 root found or mountable; bpffs found or mountable;
`CONFIG_IP_MULTIPLE_TABLES` (a `RTM_GETRULE` dump does not return
`EAFNOSUPPORT`); `/proc/net/if_inet6` when IPv6 is enabled; `nf_tables` loads
when any residual rule is configured; `wireguard`/`xfrm_user`/`vxlan`/`geneve`
link creation succeeds when the corresponding mode is configured; `sch_fq` when
the bandwidth manager is enabled.

Optional, recorded and written into `.rodata` gates: `BPF_FIB_LOOKUP_SRC`,
`BPF_FIB_LOOKUP_MARK`, `bpf_sock_destroy` kfunc (else `SOCK_DESTROY`
fallback), `BPF_F_XDP_HAS_FRAGS` per device, native XDP per device
(`IFLA_XDP` with `XDP_FLAGS_DRV_MODE`), netkit (device create + link),
`NTF_EXT_MANAGED`, BIG TCP sizes per device, `bpf_jit_harden` (warn if ≠ 0).

## 5. x86-64 vs arm64, and the test matrix

### 5.1 Differences that affect flowsdn

| Topic | x86-64 | arm64 | Consequence |
|---|---|---|---|
| BPF object | one `bpfel-unknown-none` object | same object | Only userspace is per-arch. |
| BPF-to-BPF calls mixed with tail calls | 5.10 | **6.0** | Moot at the 6.6 minimum; the reason multicast is "arm64 ≥ 6.0" in the reference. |
| Atomic fetch instructions (`BPF_FETCH`, `cmpxchg`) | 5.12 | 5.17 | Moot at 6.6; Rust atomics with unused results emit plain `xadd`, fine everywhere. |
| ISA v3 (`jmp32`, ALU32) | 5.1 | 5.1 | Build with `-C target-cpu=v3`. |
| ISA v4 | 6.6 | 6.6 | Not required; do not enable until the minimum is ≥ 6.6 on every target and there is a measured win. |
| kfunc calls from JIT | 5.13 | later 6.x | `bpf_sock_destroy` needs 6.5 anyway; present on 6.12 both arches. |
| Retpoline for indirect tail calls | yes — reference writes `tail_call_static` inline asm with constant index so the JIT emits a direct `jmp` | no retpoline; direct-jump form still cheaper | Emit tail calls with compile-time-constant indices (`ProgramArray::tail_call` with a `const`), never a runtime index. |
| Unaligned 8/4/2/1-byte loads in packet parsing | handled by JIT | handled by JIT | The reference's `builtins.h` assumption holds; `#[repr(C, packed)]` reads are fine. |
| Page size | 4 KiB | 4 KiB (Rocky 10 default) or **64 KiB** (`kernel-64k`) | Perf ring = 64 pages × page size (256 KiB vs 4 MiB per CPU); memlock accounting for perf mmap; always `sysconf(_SC_PAGESIZE)`. |
| Cache line pad (`.data.aux` stride, reference uses Go's `cpu.CacheLinePad`) | 64 B | 128 B (Go's definition; hardware is often 64) | Rust must compute the same per-target constant so `_aux_stride` matches the map layout expected by tools (inventory 02). |
| Endianness | LE | LE | Monitor payloads decode native-endian on both; network fields stay big-endian in maps. |
| Crypto throughput | AES-NI, CLMUL | ARMv8 CE (AES, GHASH), NEON ChaCha/Poly | IPsec/WireGuard throughput only; single-core-per-SA decryption on both. |
| Native XDP drivers | broad (i40e, ice, ixgbe, igb, igc, mlx4/5, bnxt, ena, nfp, virtio) | server NICs (mlx5, bnxt, ena on Graviton) yes; SoC NICs mixed (mvneta, mvpp2, dpaa2, stmmac, hns3 yes; `al_eth` and most vendor BSP drivers no) | Default `loadBalancer.acceleration=disabled` on arm64 SoC boards; `best-effort` on servers. |
| BIG TCP | mlx5, bnxt-class NICs | same NICs on arm64 servers; not on SoC NICs | Enable per NIC, not per arch. |
| Maglev/LRU memory | ample | small boards: default Maglev M (20 MB), CT sizes scaled by CPU count | Size defaults by `MemTotal`, not by arch. |
| Reference CI coverage | full LVH matrix | images multi-arch; integration tests on arm64 runners; **no arm64 LVH kernels** | flowsdn must build its own arm64 kernel VMs (5.3). |
| Envoy image | `cilium/proxy` amd64 | `cilium/proxy` arm64 | No action. |

### 5.2 Verifier behaviour is arch-independent; JIT is not

The verifier runs before the JIT and does not depend on the architecture, so
"does it load" is the same answer on both arches for a given kernel version
— with the one exception of features the JIT must support (`bpf_jit_supports_*`:
subprog + tail-call mixing, kfuncs, atomics, v4 instructions), which the
verifier consults. On ≥ 6.6 those are all present on both arches. What differs
is performance (JIT code quality, retpoline cost) and driver behaviour (XDP).
Hence: complexity gating can run on x86-64 alone as a fast PR gate, but the
BPF unit tests (`BPF_PROG_RUN`) and e2e must run on arm64 too because they
exercise the JIT output and the drivers.

### 5.3 Test matrix recommendation

Start from the reference's LVH set (`quay.io/lvh-images/kind:{5.15,6.1,6.6,
6.12,6.18}-<date>`, amd64 only) and drop the rows below the flowsdn minimum.

| Row | Kernel | x86-64 image | arm64 image | Verifier (load every object variant, everything-on rodata, record complexity) | BPF unit tests (`BPF_PROG_RUN` packet fixtures) | Privileged userspace tests (netlink, maps, tcx/netkit/XDP attach) | e2e (kind + cilium-cli connectivity test) |
|---|---|---|---|---|---|---|---|
| Minimum | **6.6 LTS** | LVH `6.6` | Debian/Ubuntu arm64 cloud image with a 6.6.y kernel, or QEMU `virt` with an upstream 6.6.y build | PR gate | PR gate (x86), nightly (arm64) | nightly | nightly (x86) |
| Supported line | **6.12** (Rocky 10 `el10` kernel **and** upstream 6.12.y) | Rocky 10 VM (the stormcos kernel exactly) + LVH `6.12` | Rocky 10 `aarch64` VM (4 K and `kernel-64k`) or the Rose node | PR gate (both) | PR gate (both) | PR gate (both) | PR gate (x86, Rocky kernel); nightly arm64 on the Rose cluster |
| Next | **6.18 LTS** | LVH `6.18` | upstream 6.18.y arm64 VM | PR gate (x86), nightly (arm64) | nightly | nightly | nightly (x86) |
| Canary | latest stable / bpf-next | LVH latest when published, else own build | — | nightly, non-blocking | — | — | — |
| Not run | rhel8.10 (4.18), 5.15, 6.1 | — | — | — | — | — | — |

Notes.

- The verifier job is cheap (load only, no traffic) and is the right place to
  enforce the flowsdn 800,000-instruction / 480 B-stack gate and greater
  than 10% instruction-count regression warning from datapath spec §9.4; run it on every kernel × arch pair
  in the table on every PR for x86-64, nightly for arm64 (same verifier, so
  the arm64 run guards only JIT-support gates).
- BPF unit tests are the reference's 141 `bpf/tests/*.c` cases re-expressed in
  Rust (ADR-0002); they need `BPF_PROG_TEST_RUN` and a netns — no NIC — so they
  run inside the same VMs.
- arm64 needs its own VM images because LVH has none: build them with the
  stormcos composer (the Rocky `aarch64` kernel) and, for 6.6/6.18, from
  upstream tarballs with the 2.6 fragment. QEMU TCG on the x86-64 dev box is
  acceptable for verifier and unit-test rows (CPU-light); e2e on arm64 runs on
  real hardware (Rose cluster) nightly.
- Feature permutations: keep the reference's model (`bpf/complexity-tests`
  option files → flowsdn `.rodata`/feature-variant permutation files, one set
  per kernel row). The everything-on set is the one that must pass on 6.6; the
  netkit permutations exist only on the 6.12 and 6.18 rows.
- e2e configs: take the reference's 41 upgrade-matrix configs (inventory 15)
  as the long list, and run the reduced set {vxlan+KPR, native+KPR+DSR,
  geneve+DSR-geneve, WireGuard, IPsec, egress gateway, host firewall,
  IPv6-only, netkit (6.12+)} on the 6.12 x86-64 row per PR.

## 6. Open items carried into the datapath spec

- Exact object-variant set per hook family (section 3.3 item 2) and the
  loader's reachability pass design.
- Resolved (#57, ADR-0011): `cilium_events` remains `PERF_EVENT_ARRAY`,
  preserving decoder framing and per-CPU ordering/loss accounting. No ring
  buffer replacement is selected by the kernel floor.
- bpffs and cgroup2: host-mounted contract (stormcos can guarantee it) versus
  the privileged init container for general Kubernetes.
- Verify the Rocky 10 `el10` config against section 2.6 on dev
  (`ssh <build-user>@<build-host> 'grep -E "..." /boot/config-$(uname -r)'` on a Rocky
  10 VM) and record the result in stormcos's kernel README; in particular
  `NETKIT`, `NET_SCH_FQ`, `TCP_CONG_BBR`, `NFT_TPROXY`, `NFT_SOCKET`,
  `INET_DIAG_DESTROY`, `XFRM_STATISTICS`.
- arm64 NIC driver of the MikroTik RDS-class boards (`al_eth` or successor):
  confirm no `ndo_bpf` → XDP disabled by default on that hardware.
- Measure, not estimate: first Rust `bpf_host` NodePort build's `insns
  processed` on 6.6 versus the reference's C on the same kernel, to replace
  the 1.5–3× expectation in 3.3 with a number.
