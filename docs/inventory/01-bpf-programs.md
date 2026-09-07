# BPF datapath programs — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `bpf/*.c`, `bpf/lib/*.h`
(map definitions excluded — covered by the maps inventory), `bpf/include/`,
`bpf/complexity-tests/`, `bpf/tests/`, `bpf/test-progs/`, `bpf/tools/`. Go-side
references (loader, config generation) are cited only where they define the C
contract: `pkg/datapath/loader/`, `pkg/datapath/config/`, `pkg/bpf/`,
`pkg/datapath/linux/config/config.go`.

## Purpose

The `bpf/` tree is the whole per-packet datapath of Cilium: a set of C programs
compiled by clang to BPF and attached to tc/tcx (or netkit) hooks on veths,
`cilium_host`/`cilium_net`, the tunnel device, the WireGuard device and the
physical NICs; an XDP program for the NIC ingress fast path; a set of
`cgroup/*` socket programs for socket-level load balancing; and `iter/tcp`,
`iter/udp` programs for socket termination. Together they implement identity
lookup (ipcache), L3/L4 network policy with L7 proxy redirection, connection
tracking, service load balancing (ClusterIP/NodePort/LB/ExternalIP/HostPort,
Maglev/random, DSR, session affinity), SNAT/masquerading, NAT46/64, VXLAN/Geneve
encapsulation carrying the security identity, IPsec/WireGuard hooks, egress
gateway, SRv6, multicast, host firewall, bandwidth manager (EDT), and the
monitor event stream. Every `bpf_*.c` is compiled per-node at agent runtime
with a generated `node_config.h`, and per-object/per-endpoint values are then
patched into `.rodata.config` at load time by the Go loader.

## Components

### Program objects (`bpf/*.c`)

| Path | Lines | Purpose |
|---|---|---|
| `bpf/bpf_lxc.c` | 2771 | Workload endpoint programs on the veth/netkit: `cil_from_container` (egress from pod), `cil_to_container` (ingress to pod), `cil_lxc_policy` (ingress policy tail-call target), `cil_lxc_policy_egress` (L7 LB return path). Per-endpoint object. |
| `bpf/bpf_host.c` | 2040 | Host endpoint: `cil_from_netdev`/`cil_to_netdev` on physical devices, `cil_from_host`/`cil_to_host` on `cilium_host`/`cilium_net`, `cil_host_policy` (host firewall tail-call target). Includes ETH_HLEN=0 support for L3 devices. |
| `bpf/bpf_overlay.c` | 668 | Tunnel device (`cilium_vxlan`/`cilium_geneve`): `cil_from_overlay` (decap, identity from VNI), `cil_to_overlay` (SNAT/nodeport NAT-fwd, EDT). |
| `bpf/bpf_xdp.c` | 333 | `cil_xdp_entry`: CIDR prefilter + NodePort acceleration (`nodeport_lb4/6` at XDP), transfers `XFER_PKT_*` flags to skb via `xdp_adjust_meta`. |
| `bpf/bpf_wireguard.c` | 386 | `cilium_wg0`: `cil_from_wireguard` (decrypted ingress: local delivery, decrypt mark), `cil_to_wireguard` (nodeport rev-DNAT on egress). |
| `bpf/bpf_sock.c` | 1342 | Socket LB: `cgroup/connect4|6`, `sendmsg4|6`, `recvmsg4|6`, `getpeername4|6`, `bind4|6`, `post_bind4|6`, `sock_release`. |
| `bpf/bpf_sock_term.c` | 172 | `iter/tcp`, `iter/udp` socket iterators that call kfunc `bpf_sock_destroy` on sockets matching a rev-NAT entry (backend removal for UDP/TCP). |
| `bpf/bpf_probes.c` | 43 | Load-only probe programs for `BPF_FIB_LOOKUP_SKIP_NEIGH`, `BPF_FIB_LOOKUP_TBID`, `BPF_FIB_LOOKUP_SRC` flag support. |
| `bpf/bpf_alignchecker.c` | 117 | Emits DWARF/BTF for ~50 map key/value structs so `pkg/alignchecker` can verify Go struct layouts match C. |
| `bpf/node_config.h` | 146 | **Dummy** node config used by `make -C bpf`/tests. At runtime the agent overwrites it via `HeaderfileWriter.WriteNodeConfig` (`pkg/datapath/linux/config/config.go`). Marked deprecated. |
| `bpf/ep_config.h`, `netdev_config.h`, `filter_config.h` | 18 / 11 / 13 | Dummy per-endpoint / netdev / XDP prefilter configs for test compilation; real ones written by `WriteEndpointConfig`/`WriteTemplateConfig`. |
| `bpf/Makefile`, `bpf/Makefile.bpf` | — | Build permutations (`LXC_OPTIONS`, `HOST_OPTIONS`, `XDP_OPTIONS`, `LB_OPTIONS`, `MAX_BASE_OPTIONS`), clang flags, checkpatch/coccicheck/sparse targets, `go generate` of `pkg/datapath/{types,config,maps,bpf}`. |

### Library headers (`bpf/lib/*.h`, 23,283 lines total; map-definition headers omitted)

| Path | Lines | Purpose |
|---|---|---|
| `lib/nodeport.h` | 3030 | NodePort/LB ingress on netdev/overlay/XDP: `nodeport_lb4/6`, `nodeport_svc_lb4/6`, DSR encap (option/IPIP/Geneve), rev-DNAT, NAT-ingress/egress tail calls, NAT46x64 gateway, RSS source generation, DSR ICMP errors. |
| `lib/lb.h` | 2471 | Service/backend lookup, backend selection (random / Maglev / first / custom), affinity, source ranges, `lb4/6_local` (CT_SERVICE handling), `lb4/6_xlate`, `lb4/6_rev_nat`, L7 LB hooks, loopback/hairpin SNAT. |
| `lib/nat.h` | 2305 | SNAT engine: `snat_v4/6_nat`, `snat_v4/6_rev_nat`, mapping creation with `SNAT_COLLISION_RETRIES`, port range from `nodeport_port_max+1..65535`, ICMP error translation, `snat_v4/6_needs_masquerade` decision. |
| `lib/conntrack.h` | 1391 | CT lookup/create, TCP flag state machine, timeouts, scopes, `ct_buffer4/6`, rev-NAT bookkeeping. |
| `lib/nodeport_egress.h` | 740 | `handle_nat_fwd` (egress path on netdev/overlay/wireguard): SNAT-fwd, masquerade, egress gateway SNAT redirect, rev-DNAT for replies. |
| `lib/icmp6.h` | 703 | ICMPv6 NS/NA responder, time-exceeded generation, ICMPv6 rate limiting, checksum. |
| `lib/egress_gateway.h` | 662 | EGW policy LPM lookup (v4/v6, v2 entries with ifindex), `egress_gw_fib_lookup_and_redirect`, SNAT/reply hooks. |
| `lib/host_firewall.h` | 636 | Host policy ingress/egress lookups on CT + `cilium_policy`, proxy redirect for host. |
| `lib/policy.h` | 506 | `__policy_can_access` LPM policy lookup with precedence, match-type classification, deny/auth, audit mode, `policy_can_ingress/egress4/6`. |
| `lib/ipv6.h` | 476 | Extension-header walking (`IPV6_MAX_HEADERS 4`), fragment header, `NEXTHDR_*`, v6 frag map. |
| `lib/srv6.h` | 475 | SRv6 VRF/policy/SID LPM lookups, H.Encaps (reduced / SRH), decap. |
| `lib/mcast.h` | 430 | IGMPv2/v3 membership tracking, `for_each_map_elem` + `clone_redirect` delivery to subscribers. |
| `lib/common.h` | 429 | Shared constants: `MARK_MAGIC_*`, `CB_*` slots, `TC_INDEX_F_*`, `XFER_PKT_*`, `REASON_*`, tuples, `ct_dir`, `ct_status`. |
| `lib/nat_46x64.h` | 417 | RFC6052 NAT46/NAT64 header/ICMP translation, `NAT46x64_MODE_XLATE/ROUTE`. |
| `lib/trace.h` | 412 | `send_trace_notify*` (perf event `TRACE_*`), aggregation levels, `trace_ctx`. |
| `lib/proxy.h` | 408 | `ctx_redirect_to_proxy4/6` via `sk_assign`/`skc_lookup_tcp`/`sk_lookup_udp`, TPROXY mark, `tc_index_from_*_proxy`. |
| `lib/identity.h` | 406 | Reserved identities, `identity_is_*`, `inherit_identity_from_host`, VNI<->identity, aggregate identities. |
| `lib/fib.h` | 357 | `fib_lookup` wrappers, `fib_redirect`, `redirect_neigh` fallbacks, neigh-map fallback (`BPF_FIB_MAP_NO_NEIGH 100`). |
| `lib/ipsec.h` | 311 | `do_decrypt` (ESP → `MARK_MAGIC_DECRYPT|node_id<<16`), `set_ipsec_encrypt` (`MARK_MAGIC_ENCRYPT|key<<12|node_id<<16`), redirect to `cilium_net` ingress for XFRM. |
| `lib/dbg.h` | 298 | `cilium_dbg*` debug perf events (`DBG_*` codes). |
| `lib/local_delivery.h` | 295 | `ipv4/6_local_delivery` (redirect_peer / policy tail call), `cilium_call_policy`/`cilium_egresscall_policy` prog arrays, `ipv4/6_host_delivery`. |
| `lib/classifiers.h` | 278 | `CLS_FLAG_IPV6/L3_DEV/VXLAN/GENEVE` classification of packets for trace/drop notifications. |
| `lib/overloadable_xdp.h` / `overloadable_skb.h` | 274 / 257 | Context-specific implementations of `bpf_clear_meta`, `ctx_snat_done*`, `ctx_is_overlay/encrypt/decrypt`, identity mark, `XFER_MARKER` meta transfer. |
| `lib/trace_sock.h` | 230 | Socket LB trace events (`XLATE_PRE/POST_DIRECTION_FWD/REV`). |
| `lib/drop.h` / `drop_reasons.h` | 222 / 90 | `send_drop_notify*` (tail-calls `CILIUM_CALL_DROP_NOTIFY`), `DROP_*` codes −130..−189. |
| `lib/conntrack_map.h` | 205 | CT map selection incl. per-cluster `ARRAY_OF_MAPS` (`get_cluster_ct_map4/6`). |
| `lib/ip_options.h` | 190 | IPv4 option parsing for tracing IP option (`trace_id_from_ip4`). |
| `lib/eps.h` | 179 | `lookup_ip4/6_endpoint` (`cilium_lxc`), `lookup_ip4/6_remote_endpoint` (`cilium_ipcache_v2` LPM, keyed with cluster_id). |
| `lib/wireguard.h` | 169 | `wg_maybe_redirect_to_encrypt`, `CONFIG(wg_ifindex)`, `CONFIG(wg_port)`, strict-mode CIDR check. |
| `lib/ipv4.h` | 157 | IPv4 helpers, frag map, `ipv4_dec_ttl`, `ipv4_hdrlen`. |
| `lib/tailcall.h` | 138 | `CILIUM_CALL_*` constants, `cilium_calls` prog array, `__declare_tail`, `tail_call_internal`. |
| `lib/encap.h` / `tunnel.h` | 136 / 117 | `__encap_with_nodeid`, `encap_and_redirect_*`, `get_tunnel_key`, VXLAN/Geneve headers, Geneve DSR option (`class 0x014B`, type `0x81`), VNI<->identity shift. |
| `lib/ratelimit.h` / `token_bucket.h` | 135 / 60 | Token-bucket rate limiting (ICMPv6, events map, socket events). |
| `lib/policy_log.h` | 135 | `send_policy_verdict_notify`, `policy_verdict_log_filter`. |
| `lib/hexdump.h` / `icmp.h` / `icmp_wsum.h` | 124 / 123 / 47 | Debug hexdump; ICMPv4 error generation; checksum accumulate. |
| `lib/edt.h` | 122 | Bandwidth manager: `edt_sched_departure` sets `skb->tstamp`, `DROP_EDT_HORIZON`, `cilium_throttle` map, priority. |
| `lib/l2_responder.h` | 114 | L2 announcements: ARP/NDP responder lookup maps, liveness. |
| `lib/ipfrag.h` | 110 | `fraginfo_t` (`__s64`) encoding: `IPFRAG_BIT_FRAGMENTED (1<<40)`, `IPFRAG_BIT_NO_L4_HEADER (1<<41)`, proto in bits 32..39, frag id low 32/16 bits. |
| `lib/eth.h` / `l4.h` / `l3.h` / `arp.h` / `csum.h` | 108 / 104 / 97 / 85 / 79 | L2/L3/L4 header load/store helpers, `pull_l3_hdr`, ARP responder. |
| `lib/jhash.h` / `hash.h` / `ghash.h` | 107 / 45 / 56 | jhash for Maglev/tuple hashing with `hash_init4/6_seed`; golden-ratio hash. |
| `lib/subnet.h` | 102 | Hybrid routing: subnet-ID LPM lookup (`hybrid_routing_enabled`). |
| `lib/neigh.h` / `node.h` | 100 / 95 | Nodeport neigh map (`NODEPORT_NEIGH4/6_SIZE`), node-id/SPI lookup (`cilium_node_map_v2`). |
| `lib/encrypt.h` | 94 | `set_decrypt_mark`, strict-mode helpers. |
| `lib/lrp.h` | 88 | Local Redirect Policy skip-LB maps (`skip_lb4/6_key` keyed by netns cookie). |
| `lib/metrics.h` / `signal.h` / `notify.h` / `events.h` | 86 / 68 / 66 / 13 | Metrics map update, `cilium_signals` (`SIGNAL_NAT_FILL_UP`, `SIGNAL_CT_FILL_UP`, `SIGNAL_AUTH_REQUIRED`), notify header/`TRACE_*` points, `cilium_events` perf array. |
| `lib/clustermesh.h` | 85 | Cluster-aware addressing: identity bit split (`IDENTITY_BITS 24`, `cluster_id_bits`), cluster-id in mark. |
| `lib/static_data.h` | 83 | `DECLARE_CONFIG` / `NODE_CONFIG` / `ASSIGN_CONFIG` / `CONFIG()` — the `.rodata.config` mechanism. |
| `lib/proxy_hairpin.h` | 76 | L7 LB hairpin to proxy via `cilium_host`. |
| `lib/source_info.h` | 66 | `__MAGIC_FILE__`/`__MAGIC_LINE__` embedded in drop notifications. |
| `lib/sock.h` / `sock_term.h` / `act.h` | 64 / 17 / 61 | Socket rev-NAT maps (`cilium_lb4/6_reverse_sk`), termination filter, active-connection-tracking counters. |
| `lib/config_map.h` | 60 | `cilium_runtime_config` array (`RUNTIME_CONFIG_UTIME_OFFSET`, `RUNTIME_CONFIG_AGENT_LIVENESS`). |
| `lib/network_device.h` / `auth.h` / `lxc.h` / `vtep.h` | 56 / 54 / 51 / 29 | Device state map, mutual-auth lookup (`auth_key`), lxc source-IP validation, VTEP map. |
| `lib/time.h` / `utime.h` / `utils.h` / `endian.h` / `ipv6_core.h` / `map_defs.h` / `config.h` / `stubs.h` / `export_type.h` / `overloadable.h` / `auxvars.h` / `socket.h` / `trace_helpers.h` | ≤ 63 each | Time (`bpf_mono_now` with jiffies option, `BPF_MONO_SCALER 8`), utime, byte order, v6 addr copy, map flag conditionals, `is_defined()`, aux data for plugins. |

### Include tree (`bpf/include/`, 2,191 + 9,325 lines)

| Path | Lines | Purpose |
|---|---|---|
| `include/bpf/builtins.h` | 554 | Hand-rolled `memcpy`/`memset`/`memcmp`/`memmove` unrolled by size (avoid clang libcalls; `__bpf_memcpy_builtin` opt-in). |
| `include/bpf/ctx/xdp.h` / `skb.h` / `common.h` / `sock.h` / `unspec.h` | 458 / 155 / 28 / 10 / 10 | Context abstraction: `PROG_TYPE "tc"|"xdp"`, `CTX_ACT_*`, `ctx_load/store_bytes`, meta slots (`cb[]` vs `cilium_xdp_scratch` percpu array), XDP software csum/adjust-room emulation, `META_PIVOT`. |
| `include/bpf/compiler.h` | 123 | `__section`, `__always_inline`, `READ_ONCE/WRITE_ONCE`, `build_bug_on`, `__throw_build_bug`. |
| `include/bpf/helpers.h` / `helpers_skb.h` / `helpers_xdp.h` / `helpers_sock.h` | 121 / 70 / 68 / 15 | `BPF_FUNC(name,...)` declarations of every kernel helper used (list below). |
| `include/bpf/tailcall.h` | 55 | `tail_call_static` (inline asm `call 12` with fixed r2/r3 so the x86-64 JIT can patch to a direct jump; loader relies on exact instruction sequence), `tail_call_dynamic`. |
| `include/bpf/config/{global,node,endpoint,lxc,host,overlay,sock,xdp}.h` | 15/102/25/20/25/10/13/12 | `DECLARE_CONFIG`/`NODE_CONFIG` variables per object kind. |
| `include/bpf/section.h`, `loader.h`, `api.h`, `csum.h`, `errno.h`, `access.h`, `types_mapper.h`, `stddef.h`, `features*.h`, `lb_selection.h` | ≤ 51 each | ELF section names (`PROG_TYPE "/entry"`, `PROG_TYPE "/tail"`, `.maps`, `license`), `LIBBPF_PIN_BY_NAME 1`, `CILIUM_PIN_REPLACE 1<<4`, `__uint/__type/__array` BTF map macros, `LB_SELECTION_RANDOM 1 / MAGLEV 2 / FIRST 3 / CUSTOM 0x80`. |
| `include/linux/*.h` | 9325 | Vendored UAPI: `bpf.h` (kernel copy, 32 helper docs matched), `if_ether.h`, `ip.h`, `ipv6.h`, `tcp.h`, `udp.h`, `icmp*.h`, `igmp.h`, `in*.h`, `if_arp.h`, `byteorder`, `swab.h`. No libc; `-nostdinc`. |

### Tests

| Path | Lines | Purpose |
|---|---|---|
| `bpf/tests/*.c` (141 files) | 35,501 | BPF unit tests run via `BPF_PROG_RUN` (`bpf/tests/bpftest/bpf_test.go`, 1,152 lines with coverbee coverage). |
| `bpf/tests/*.h`, `bpf/tests/lib/*.h` | 12,270 | `common.h` (TEST/PKTGEN/SETUP/CHECK macros, protobuf-encoded results), `pktgen.h` (1,391 lines packet builder), `lib/{bpf_host,bpf_lxc,bpf_overlay,bpf_xdp,ipcache,lb,policy,endpoint,egressgw,ipsec,node,subnet,metrics,...}.h` fixtures. |
| `bpf/tests/scapy/` | — | Python scapy generates `output/scapy_bytes.h`; `tools/log2scapy.py`. |
| `bpf/complexity-tests/{61,510,netnext}/bpf_{lxc,host,overlay,xdp,sock,wireguard}/N.txt` | 100 files, 2,352 lines | Option-set permutations per kernel (6.1, 5.10, net-next) used by `tests-datapath-verifier.yaml` to load every program and record verifier complexity. |
| `bpf/test-progs/` | 143 | Plugin base/hook test programs (`tcx_early_hook`, `xdp_early_hook` plugin mechanism). |

## Features

Each bullet: what the BPF side implements, and the compile-time / runtime knobs
that turn it on. Helm/agent flag names are indicative (owned by the agent
inventory); the C macro is authoritative here.

- **Endpoint egress pipeline (pod → world)** — `cil_from_container` → per-packet
  service LB (`ENABLE_PER_PACKET_LB`, defined when `ENABLE_SOCKET_LB_FULL` is
  off) → CT lookup → egress policy → forward (local delivery / tunnel / FIB
  redirect / stack). Always on.
- **Endpoint ingress pipeline (world → pod)** — `cil_to_container` or
  `cilium_call_policy[ep_id]` tail call from `bpf_host`/`bpf_overlay` →
  CT → ingress policy → optional proxy redirect. Always on.
- **Identity-based policy** — LPM map `cilium_policy` keyed by
  `{sec_label, egress, protocol, dport}`, `precedence`, `deny`, `auth_type`,
  `proxy_port`, `cookie`. `POLICY_AUDIT_MODE` (policy-audit-mode),
  `POLICY_VERDICT_NOTIFY`, `POLICY_ACCOUNTING` (`enable_policy_accounting`),
  `policy_deny_response_enabled` (ICMP unreachable on deny via
  `CILIUM_CALL_IPV4/6_POLICY_DENIED`).
- **Mutual authentication** — `DROP_POLICY_AUTH_REQUIRED` → `auth_lookup` in
  `cilium_auth_map` keyed `{local_sec_label, remote_sec_label, remote_node_id,
  auth_type}` with expiration in ns/512; on miss emits `SIGNAL_AUTH_REQUIRED`.
- **L7 proxy redirection** — `ENABLE_L7_LB`, `CONFIG(enable_tproxy)`,
  `CONFIG(proxy_redirect_via_cilium_net)`; redirect via `sk_assign` on an
  `skc_lookup_tcp`/`sk_lookup_udp` result or via `MARK_MAGIC_TO_PROXY|port<<16`
  for iptables TPROXY. `TC_INDEX_F_FROM_INGRESS_PROXY 1` /
  `TC_INDEX_F_FROM_EGRESS_PROXY 2` on `skb->tc_index` identify proxy-originated
  packets; `MARK_MAGIC_PROXY_EGRESS_EPID` carries the endpoint ID in upper 16
  bits so `cil_from_host`/`cil_to_container` can tail-call
  `cilium_egresscall_policy[ep_id]`.
- **Connection tracking** — global `cilium_ct4/6_global` (TCP) and
  `cilium_ct_any4/6_global` (non-TCP) LRU maps, per-cluster `ARRAY_OF_MAPS`
  variants under `ENABLE_CLUSTER_AWARE_ADDRESSING`. Accounting via
  `enable_conntrack_accounting`. Details under Data model.
- **Service load balancing (per-packet)** — `ENABLE_NODEPORT` (kube-proxy
  replacement), `ENABLE_NODEPORT_ACCELERATION` (XDP), service flags
  `SVC_FLAG_*` (NodePort, ExternalIP, HostPort, LoadBalancer, affinity,
  source-range check + `SVC_FLAG_SOURCE_RANGE_DENY`, `SVC_FLAG_TWO_SCOPES`
  internal/externalTrafficPolicy, `SVC_FLAG_L7_LOADBALANCER`, `SVC_FLAG_L7_DELEGATE`,
  `SVC_FLAG_LOCALREDIRECT`, `SVC_FLAG_NAT_46X64`, `SVC_FLAG_FWD_MODE_DSR`,
  `SVC_FLAG_QUARANTINED`). Backend selection algorithm per service
  (`lb_selection_per_service`, algorithm in `affinity_timeout >> 24`) or node
  default `lb_default_alg`. `SERVICE_NO_BACKEND_RESPONSE` → ICMP unreachable.
  `ENABLE_SCTP`. `ENABLE_ACTIVE_CONNECTION_TRACKING` (`lib/act.h` per-svc/zone
  open/closed counters).
- **Maglev** — `cilium_lb4/6_maglev` `HASH_OF_MAPS` keyed by `rev_nat_index`,
  inner array of `LB_MAGLEV_LUT_SIZE` (default 32749, `#define`) backend IDs;
  index = `jhash(tuple, hash_init4/6_seed) % LUT_SIZE`; sport zeroed when
  affinity is on.
- **Session affinity** — `cilium_lb4/6_affinity` keyed by client IP or netns
  cookie (socket LB) + `rev_nat_id`; `cilium_lb_affinity_match` validates the
  backend still belongs; timeout `affinity_timeout & 0xFFFFFF` seconds.
- **Socket-level LB** — `bpf_sock.c` cgroup hooks; `ENABLE_SOCKET_LB_FULL`,
  `ENABLE_SOCKET_LB_HOST_ONLY`, `ENABLE_SOCKET_LB_PEER` (getpeername rev-NAT),
  `ENABLE_SOCKET_LB_TCP/UDP`, `ENABLE_HEALTH_CHECK` (health-check socket
  auto-bind, `MARK_MAGIC_HEALTH 0x0D00`), `ENABLE_MKE` (Mirantis host netns
  detection), `HOST_NETNS_COOKIE`, `enable_no_service_endpoints_routable`.
  `post_bind4/6` rejects binds to NodePort/HostPort ports (`-EADDRINUSE`).
- **Socket termination** — `bpf_sock_term.c` `iter/tcp|udp` + kfunc
  `bpf_sock_destroy`; filter struct `cilium_sock_term_filter` set via
  `coll.Variables` before each iteration.
- **NodePort / DSR** — `ENABLE_DSR`, `ENABLE_DSR_BYUSER` (per-service hybrid
  via `SVC_FLAG_FWD_MODE_DSR`), `DSR_ENCAP_MODE` ∈ {`DSR_ENCAP_NONE` (IP
  option/IPv6 DstOpt), `DSR_ENCAP_IPIP`, `DSR_ENCAP_GENEVE`},
  `ENABLE_DSR_ICMP_ERRORS` (PMTU replies). IPv4 option type
  `DSR_IPV4_OPT_TYPE = IPOPT_COPY|0x1a`, IPv6 DstOpt type `0x1B`. Geneve TLV
  class `0x014B` type `0x81` (critical).
- **SNAT / masquerading** — `ENABLE_MASQUERADE_IPV4/6` (bpf-masquerade),
  `ENABLE_IP_MASQ_AGENT_IPV4/6` (ip-masq-agent CIDR exclusion LPM),
  `IPV4/6_SNAT_EXCLUSION_DST_CIDR` (native-routing CIDR), `nat_ipv4/6_masquerade`
  address, `enable_remote_node_masquerade`, `enable_nodeport_source_lookup`
  (`BPF_FIB_LOOKUP_SRC`), `ENABLE_SNAT_ICMPV4`, `ENDPOINT_F_NO_SNAT_V4/6`
  per-endpoint opt-out (multi-pool IPAM). Port range
  `[nodeport_port_max+1, 65535]` unless `ephemeral_min`; `SNAT_COLLISION_RETRIES
  32`, `SNAT_SIGNAL_THRES 16` → `SIGNAL_NAT_FILL_UP`.
- **NAT46/NAT64** — `ENABLE_NAT_46X64` (service-side 4-in-6 translation, `SVC_FLAG_NAT_46X64`),
  `ENABLE_NAT_46X64_GATEWAY` (RFC6052 stateless gateway via
  `CILIUM_CALL_IPV46_RFC6052`/`IPV64_RFC6052`), prefix `CONFIG(nat_46x64_prefix)`,
  `NODEPORT_USE_NAT_46x64` in host/xdp objects.
- **Tunneling** — `TUNNEL_MODE`, `HAVE_ENCAP` (also set when DSR Geneve /
  cluster mesh need encap without tunnel routing), `ENCAP_IFINDEX`,
  `ENCAP4_IFINDEX`/`ENCAP6_IFINDEX`, `CONFIG(tunnel_protocol)` ∈ {1 VXLAN,
  2 Geneve}, `CONFIG(tunnel_port)`; `flag_skip_tunnel` per ipcache entry;
  hybrid routing by subnet ID (`hybrid_routing_enabled`). `ENABLE_VTEP`
  (external VXLAN VTEP integration, `vtep_mask`).
- **Cluster mesh** — `ENABLE_CLUSTER_AWARE_ADDRESSING`,
  `ENABLE_INTER_CLUSTER_SNAT`, `cluster_id`, `cluster_id_bits` (default 8):
  identity = `cluster_id << (24 - bits) | local`; cluster ID carried in
  `MARK_MAGIC_CLUSTER_ID` (= `0x0200` magic, low byte) and in `CB_CLUSTER_ID_*`.
  `CILIUM_CALL_IPV4_INTER_CLUSTER_REVSNAT` in overlay.
- **IPsec** — `ENABLE_IPSEC`, `ENABLE_NODE_ENCRYPTION`,
  `ENCRYPTION_STRICT_MODE_EGRESS` (+`STRICT_IPV4_NET`, `STRICT_IPV4_NET_SIZE`,
  `STRICT_IPV4_OVERLAPPING_CIDR`), `encryption_strict_ingress`, `IPV4_ENCRYPT_IFACE`,
  key index 4 bits (`MAX_KEY_INDEX 15`) in mark bits 12..15, node id in bits
  16..31; `cilium_encrypt_state` current key; `cilium_node_map_v2` node → id/spi.
- **WireGuard** — `ENABLE_WIREGUARD`, `CONFIG(wg_ifindex)`, `CONFIG(wg_port)`;
  `bpf_host` redirects pod→remote-node traffic to `cilium_wg0` after setting
  `MARK_MAGIC_IDENTITY`; `cil_from_wireguard` sets `MARK_MAGIC_DECRYPT`.
  Strict mode drops unencrypted cluster traffic (`DROP_UNENCRYPTED_TRAFFIC`).
- **Egress gateway** — `ENABLE_EGRESS_GATEWAY` (CiliumEgressGatewayPolicy) and
  `ENABLE_EGRESS_GATEWAY_COMMON` (also for `ENABLE_EGRESS_GATEWAY_HA`-style
  consumers); LPM `cilium_egress_gw_policy_v4` (+`_v2` with egress ifindex, v6);
  sentinel `gateway_ip` values `EGRESS_GATEWAY_NO_GATEWAY 0` and
  `EGRESS_GATEWAY_EXCLUDED_CIDR htonl(1)`; `MARK_MAGIC_EGW_DONE 0x0500`;
  `EGRESS_GATEWAY_RT_TBID` and per-endpoint `rt_info` for `BPF_FIB_LOOKUP_TBID`.
- **Local Redirect Policy** — `CONFIG(enable_lrp)`, `cilium_skip_lb4/6` maps
  keyed `{netns_cookie, addr, port}` so a backend pod can reach the original
  service; `SVC_FLAG_LOCALREDIRECT`.
- **Host firewall** — `ENABLE_HOST_FIREWALL`, `HOST_ENDPOINT`,
  `CONFIG(host_ep_id)`; policy for identity `HOST_ID` in the same `cilium_policy`
  map; `cil_host_policy` tail-called via `cilium_call_policy[host_ep_id]`;
  `TC_INDEX_F_SKIP_HOST_FIREWALL 16`, `FROM_HOST_FLAG_NEED_HOSTFW`.
- **Bandwidth manager (EDT)** — `ENABLE_BANDWIDTH_MANAGER`; `edt_set_aggregate`
  stores endpoint ID in `skb->queue_mapping`; `edt_sched_departure` on
  `to-netdev`/`to-overlay` computes `t_next = t_last + wire_len*1e9/bps`, sets
  `skb->tstamp` (needs `sch_fq`), drops if beyond `t_horizon_drop`; sets
  `skb->priority = prio-1`.
- **SRv6** — `ENABLE_SRV6`, `ENABLE_SRV6_SRH_ENCAP` (SRH vs reduced encap);
  VRF LPM `{src, dst}` → vrf_id, policy LPM `{vrf_id, dst}` → SID, SID map →
  vrf_id; tail calls `CILIUM_CALL_SRV6_ENCAP/DECAP`.
- **Multicast** — `ENABLE_MULTICAST` (IPv4 only, AMD64 ≥ 5.10, arm64 ≥ 6.0):
  `cilium_mcast_group_outer_v4_map` `HASH_OF_MAPS`; IGMP handling in `bpf_lxc`,
  `for_each_map_elem`+`clone_redirect` fan-out in `CILIUM_CALL_MULTICAST_EP_DELIVERY`.
- **L2 announcements** — `enable_l2_announcements`, `l2_announcements_max_liveness`
  with `RUNTIME_CONFIG_AGENT_LIVENESS`; ARP/NDP replies from `bpf_host`.
- **ARP responder for pods** — `CONFIG(enable_arp_responder)`:
  `CILIUM_CALL_ARP` answers gateway ARP from the container.
- **IP fragmentation tracking** — `enable_ipv4_fragments`,
  `enable_ipv6_fragments`: `cilium_ipv4/6_frag_datagrams` LRU maps keyed by
  `{id, saddr, daddr, proto}` store L4 ports of first fragment;
  `DROP_FRAG_NOT_FOUND`, `DROP_FRAG_NOSUPPORT`.
- **Tracing IP option** — `tracing_ip_option_type`: `check_and_store_ip_trace_id`
  extracts an IPv4 option carrying a trace id into meta for trace events.
- **XDP prefilter** — `CONFIG(enable_xdp_prefilter)`, `CIDR4/6_FILTER`,
  `CIDR4/6_LPM_PREFILTER`: source-CIDR drop lists `cilium_cidr_v4/6_fix`
  (HASH) and `_dyn` (LPM).
- **Observability** — `DROP_NOTIFY`, `TRACE_NOTIFY`, `DEBUG`/`SKIP_DEBUG`,
  `MONITOR_AGGREGATION` (0 none, 1 rx, 3 active CT; `CT_REPORT_INTERVAL 5`,
  `CT_REPORT_FLAGS`), `TRACE_SOCK_NOTIFY`, `LOCAL_DELIVERY_METRICS`,
  `trace_payload_len`, `trace_payload_len_overlay`, events-map rate limit
  (`events_map_rate_limit`, `events_map_burst_limit`).
- **VLAN filter** — `VLAN_FILTER(ifindex, vlan_id)` macro generated into
  `node_config.h` as a `switch` (`--vlan-bpf-bypass`); `DROP_VLAN_FILTERED`.
- **IPIP termination** — `enable_ipip_termination`: `bpf_host` decapsulates
  inbound IPIP/IP6IP6 when outer dst is a local endpoint (L4LB health-check
  use case, tests `l4lb_ipip_health_check_host.c`).
- **Plugins** — `tcx_early_hook(ctx, proto)` / `xdp_early_hook` weak hook points
  (`bpf/test-progs/bpf_plugins*.c`, `pkg/datapath/loader/plugins.go`) that
  external BPF objects can fill via freplace-style linking; `lib/auxvars.h`
  `_aux_stride`/`_aux_max_off`.

## Data model

Only what leaks across the C/Go boundary or between programs; map layouts
themselves belong to the maps inventory.

### Program-to-program metadata

- **`skb->cb[0..4]`** (`ctx_store_meta`/`ctx_load_meta`; XDP uses the
  `cilium_xdp_scratch` percpu array, `META_PIVOT = sizeof(cb) + 2*4`): five
  slots `CB_SRC_LABEL`, `CB_1`, `CB_2`, `CB_3`, `CB_CT_STATE` with aliases
  `CB_PORT/HINT/PROXY_MAGIC/ENCRYPT_MAGIC/DST_ENDPOINT_ID/SRV6_SID_1/VERDICT`
  (slot 0); `CB_DELIVERY_FLAGS/NAT_46X64/ADDR_V4/ADDR_V6_1/IPCACHE_SRC_LABEL/
  SRV6_SID_2/CLUSTER_ID_EGRESS/TRACED/FORCED_BACKEND_V4/FORCED_BACKEND_V6_1`
  (slot 1); `CB_ADDR_V6_2/SRV6_SID_3/CLUSTER_ID_INGRESS/NAT_FLAGS` (slot 2);
  `CB_ADDR_V6_3/FROM_HOST/SRV6_SID_4` (slot 3); `CB_ADDR_V6_4/ENCRYPT_IDENTITY/
  SRV6_VRF_ID` (slot 4). `CB_DELIVERY_FLAGS_*` bits: REDIRECT 1, FROM_HOST 2,
  FROM_TUNNEL 4, USE_REDIRECT_PEER 8, FROM_INGRESS_PROXY 16, FROM_EGRESS_PROXY 32.
  `CB_NAT_FLAGS_REVDNAT_ONLY 1`. `FROM_HOST_L7_LB 0xFACADE42` sentinel.
- **`skb->tc_index`**: `TC_INDEX_F_FROM_INGRESS_PROXY 1`, `_FROM_EGRESS_PROXY 2`,
  `_SKIP_NODEPORT 4`, `_SKIP_HEALTH_CHECK 8`, `_SKIP_HOST_FIREWALL 16`.
- **`skb->queue_mapping`**: EDT aggregate id (endpoint ID) set by
  `edt_set_aggregate`; reset to 0 in `cil_from_container` (veth GH-18311).
- **XDP → skb transfer**: `XFER_MARKER` slot 6 of scratch pad, moved into
  `data_meta[XFER_FLAGS]` via `xdp_adjust_meta(-4)`; flags `XFER_PKT_NO_SVC 1`,
  `XFER_PKT_SNAT_DONE 4`. `RECIRC_MARKER` slot 5 for tail-call recirculation.
- **Per-CPU tail-call buffers**: `cilium_tail_call_buffer4/6` (`struct
  ct_buffer4/6`: tuple, `ct_state`, monitor, ret, l4_off, [fraginfo]) carry CT
  lookup results from `CILIUM_CALL_IPV4_CT_*` into the policy tail call;
  `cilium_nodeport_nat_buffer` (`struct nodeport_nat_info`) carries SNAT addr/port
  from LB into CT create; `snat_v4/6_args` via `AUX()` percpu.

### skb->mark layout (`lib/common.h` 223–270)

Bits 8..11 = magic (`MARK_MAGIC_HOST_MASK 0x0F00`), bits 8..15 = key mask
(`MARK_MAGIC_KEY_MASK 0xFF00`), bits 16..31 = payload (identity, endpoint id,
proxy port, node id, or cluster id) depending on magic; bits 0..7 low byte may
carry cluster id (`CLUSTER_ID_LOWER_MASK 0xFF`) with `MARK_MAGIC_CLUSTER_ID
(= MARK_MAGIC_TO_PROXY)`. For `MARK_MAGIC_IDENTITY`, `get_identity()` composes
`(mark >> 16) | ((mark & 0xFF) << 16)` (upper 8 bits of identity in low byte).

| Constant | Value | Payload in bits 16..31 |
|---|---|---|
| `MARK_MAGIC_TO_PROXY` | `0x0200` | proxy port (TPROXY) |
| `MARK_MAGIC_SNAT_DONE` | `0x0300` | — |
| `MARK_MAGIC_OVERLAY` | `0x0400` | source identity |
| `MARK_MAGIC_EGW_DONE` | `0x0500` | source identity |
| `MARK_MAGIC_SKIP_TPROXY` | `0x0800` | — |
| `MARK_MAGIC_PROXY_EGRESS_EPID` | `0x0900` | source endpoint ID |
| `MARK_MAGIC_PROXY_INGRESS` | `0x0A00` | source identity |
| `MARK_MAGIC_PROXY_EGRESS` | `0x0B00` | source identity |
| `MARK_MAGIC_HOST` | `0x0C00` | — |
| `MARK_MAGIC_DECRYPT` | `0x0D00` | node id (IPsec ingress) |
| `MARK_MAGIC_HEALTH` | `0x0D00` | (sock LB only, reset before tc) |
| `MARK_MAGIC_ENCRYPT` | `0x0E00` | node id; key idx in bits 12..15 |
| `MARK_MAGIC_IDENTITY` | `0x0F00` | source identity |

### Conntrack

- **Tuple** (`struct ipv4_ct_tuple` / `ipv6_ct_tuple`, `__packed`): `daddr,
  saddr, dport, sport, nexthdr, flags`. Address fields are named for the reply
  direction; ports for the original direction. `flags`: `TUPLE_F_OUT 0`,
  `TUPLE_F_IN 1`, `TUPLE_F_RELATED 2`, `TUPLE_F_SERVICE 4`.
- **Entry** (`struct ct_entry`, 56 bytes): `union {nat_addr(v6) | {reserved0,
  backend_id}}`, `packets`, `bytes`, `lifetime` (mono seconds/8 scaled), bit flags
  `rx_closing, tx_closing, lb_loopback, seen_non_syn, node_port, proxy_redirect,
  dsr_internal, from_l7lb, from_tunnel`, `rev_nat_index`, `nat_port`,
  `tx_flags_seen`, `rx_flags_seen`, `src_sec_id` (offset fixed — read by
  userspace proxies), `last_tx_report`, `last_rx_report`.
- **Directions** `enum ct_dir { CT_EGRESS, CT_INGRESS, CT_SERVICE }`; **status**
  `enum ct_status { CT_NEW, CT_ESTABLISHED, CT_REPLY, CT_RELATED }`; **scope**
  `SCOPE_FORWARD / SCOPE_REVERSE / SCOPE_BIDIR`; **entry type mask**
  `CT_ENTRY_ANY 0, CT_ENTRY_NODEPORT 1, CT_ENTRY_DSR 2, CT_ENTRY_SVC 4`.
- **Lifecycle**: `ct_lookup4/6` looks up forward tuple then flipped tuple
  (`ct_flip_tuple_dir`), returning `CT_ESTABLISHED`, `CT_REPLY` (`TUPLE_F_IN`
  hit) or `CT_RELATED` (ICMP error, related map). `ct_create4/6` writes the
  entry into the main map and, for TCP/UDP/SCTP, a `TUPLE_F_RELATED` entry into
  the `_any` map for ICMP errors. Service entries (`CT_SERVICE`) store
  `backend_id` and `rev_nat_index`; `ct_update_svc_entry` rewrites them on
  backend change; `ct_lazy_lookup` variants avoid creating entries for
  non-SYN.
- **TCP flags**: `ct_tcp_select_action`: RST|FIN → `ACTION_CLOSE`, SYN →
  `ACTION_CREATE`, else `ACTION_UNSPEC`. On SYN for a closing entry the entry
  is recreated (`ct_reset_seen_flags`, `ct_reset_closing`); on RST both
  directions closing → `CT_CLOSE_TIMEOUT`; on FIN only that direction.
  `seen_non_syn` promotes lifetime from `CT_SYN_TIMEOUT` (60 s) to the
  established lifetime.
- **Timeouts** (node_config.h, seconds, overridable by agent flags):
  `CT_CONNECTION_LIFETIME_TCP 21600`, `CT_CONNECTION_LIFETIME_NONTCP 60`,
  `CT_SERVICE_LIFETIME_TCP 21600`, `CT_SERVICE_LIFETIME_NONTCP 60`,
  `CT_SERVICE_CLOSE_REBALANCE 30`, `CT_SYN_TIMEOUT 60`, `CT_CLOSE_TIMEOUT 10`,
  `CT_REPORT_INTERVAL 5`, `CT_REPORT_FLAGS 0xff`. Time base is
  `bpf_mono_now()` = `ktime_get_ns() >> 32` scaled (`BPF_MONO_SCALER 8`) or
  `jiffies64 / kernel_hz` when `enable_jiffies`. Garbage collection is done by
  the agent (not in BPF); BPF only refreshes `lifetime`.
- **Monitor aggregation**: `__ct_update_timeout` returns `TRACE_PAYLOAD_LEN`
  (emit trace) when new flags appear or `CT_REPORT_INTERVAL` elapsed since
  `last_{rx,tx}_report`.
- **`struct ct_state`** (in-program only): `nat_addr, nat_port, rev_nat_index,
  loopback, node_port, dsr_internal, syn, proxy_redirect, from_l7lb,
  from_tunnel, closing, src_sec_id, backend_id`.

### NAT

- `struct ipv4_nat_entry { common (created, needs_ct, ...) ; to_saddr; to_sport }`
  in `cilium_snat_v4_external` (and per-cluster `cilium_per_cluster_snat_v4_external`);
  both directions stored (`NAT_DIR_EGRESS = TUPLE_F_OUT`, `NAT_DIR_INGRESS = TUPLE_F_IN`).
  `struct ipv4_nat_target { addr; min_port; max_port; from_local_endpoint;
  egress_gateway; cluster_id; needs_ct; ifindex; tbid }`.
- NAT return codes: `NAT_PUNT_TO_STACK = DROP_NAT_NOT_NEEDED (-173)`,
  `NAT_NEEDED = CTX_ACT_OK`; `DROP_NAT_NO_MAPPING -167`.
- `snat_v4_needs_masquerade` order: local endpoint lookup → egress gateway
  hook → `IPV4_SNAT_EXCLUSION_DST_CIDR` → `ENDPOINT_MASK_SKIP_MASQ_V4` →
  ip-masq-agent LPM → remote-node destination (`enable_remote_node_masquerade`)
  → masquerade if from local endpoint.

### Identity / ipcache

- Reserved identities (`lib/identity.h`): `UNKNOWN 0, HOST 1, WORLD 2,
  UNMANAGED 3, HEALTH 4, INIT 5, LOCAL_NODE/REMOTE_NODE 6, KUBE_APISERVER_NODE 7,
  INGRESS 8, WORLD_IPV4 9, WORLD_IPV6 10, AGGREGATE_CLUSTER 11,
  AGGREGATE_CLUSTER_MESH 12, AGGREGATE_WORLD 13, AGGREGATE_REMOTE_NODE 14`.
  CIDR identities `[(1<<24)+1, (1<<24)+(1<<16)-1]`; local scope masks
  `IDENTITY_LOCAL_SCOPE_MASK 0xFF000000`, `_CIDR 0x01000000`,
  `_REMOTE_NODE 0x02000000`.
- `struct remote_endpoint_info { sec_identity; tunnel_endpoint (v4|v6); key
  (IPsec); flag_skip_tunnel, flag_has_tunnel_ep, flag_ipv6_tunnel_ep,
  flag_remote_cluster }` from `cilium_ipcache_v2` LPM keyed
  `{prefixlen, cluster_id, family, addr}`; lookups always use full prefix
  (`V4_CACHE_KEY_LEN 32`, `V6_CACHE_KEY_LEN 128`).
- `struct endpoint_info { ifindex; lxc_id; flags (ENDPOINT_F_HOST 1, _ATHOSTNS 2,
  _NO_SNAT_V4 4, _NO_SNAT_V6 8); rt_info; mac; node_mac; sec_id; parent_ifindex }`
  from `cilium_lxc` keyed `{addr, family, key, cluster_id}`.

### Configuration variables (`.rodata.config`)

Generated Go structs in `pkg/datapath/config/*_config.go`. Node-level
(`NODE_CONFIG`, embedded in all objects): `cilium_net_ifindex`, `cilium_net_mac`,
`cilium_host_ifindex`, `cilium_host_mac`, `service_loopback_ipv4/6`,
`router_ipv6`, `trace_payload_len[_overlay]`, `direct_routing_dev_ifindex`,
`supports_fib_lookup_skip_neigh`, `supports_fib_lookup_src`,
`enable_nodeport_source_lookup`, `enable_ipip_termination`,
`tracing_ip_option_type`, `policy_deny_response_enabled`, `cluster_id`,
`cluster_id_bits`, `enable_conntrack_accounting`, `debug_lb`, `lb_default_alg`,
`lb_selection_per_service`, `nodeport_port_min/max`, `hash_init4/6_seed`,
`nat_46x64_prefix`, `enable_tproxy`, `events_map_rate_limit/burst_limit`,
`enable_endpoint_routes`, `enable_identity_mark`, `enable_bpf_host_routing`,
`encryption_strict_ingress`, `enable_jiffies`, `kernel_hz`.
Object-level (`DECLARE_CONFIG`): global `interface_mac`, `interface_ifindex`;
endpoint `security_label`, `host_ep_id`, `enable_arp_responder`; lxc
`endpoint_id`, `endpoint_ipv4/6`, `endpoint_netns_cookie`, `rt_info`; host
`eth_header_length`; xdp `enable_xdp_prefilter`; sock
`enable_no_service_endpoints_routable`; shared lib-level `device_mtu`,
`tunnel_protocol`, `tunnel_port`, `vtep_mask`, `wg_ifindex`, `wg_port`,
`enable_lrp`, `enable_ipv4/6_fragments`, `enable_extended_ip_protocols`,
`enable_netkit`, `enable_remote_node_masquerade`, `nat_ipv4/6_masquerade`,
`ephemeral_min`, `proxy_redirect_via_cilium_net`, `allow_icmp_frag_needed`,
`enable_icmp_rule`, `enable_policy_accounting`, `policy_verdict_log_filter`,
`hybrid_routing_enabled`, `enable_l2_announcements`, `l2_announcements_max_liveness`.

## External interfaces

### Program entry points and hooks

| Program (`__section_entry` / section) | Object | Attach point (Go loader) |
|---|---|---|
| `cil_from_container` | bpf_lxc | tc/tcx **ingress** of pod veth (host side) or netkit primary; `pkg/datapath/loader/endpoint.go` |
| `cil_to_container` | bpf_lxc | tc/tcx **egress** of pod veth, only if `ep.RequireEgressProg()` (endpoint routes / host FW / L7 LB) |
| `cil_lxc_policy` | bpf_lxc | not attached: inserted into `cilium_call_policy[ep_id]` |
| `cil_lxc_policy_egress` | bpf_lxc | not attached: inserted into `cilium_egresscall_policy[ep_id]` |
| `cil_from_netdev` | bpf_host | tc/tcx **ingress** of each native device |
| `cil_to_netdev` | bpf_host | tc/tcx **egress** of each native device (when nodeport/egw/hostfw/etc. need it) |
| `cil_from_host` | bpf_host | tc/tcx **egress** of `cilium_host` (packets leaving host stack toward pods) |
| `cil_to_host` | bpf_host | tc/tcx **ingress** of `cilium_host` and of `cilium_net` |
| `cil_host_policy` | bpf_host | `cilium_call_policy[host_ep_id]` |
| `cil_from_overlay` | bpf_overlay | tc/tcx **ingress** of `cilium_vxlan`/`cilium_geneve` |
| `cil_to_overlay` | bpf_overlay | tc/tcx **egress** of tunnel device |
| `cil_xdp_entry` | bpf_xdp | XDP on native devices, driver (`XDPDriverMode`) or generic mode; flag `BPF_F_XDP_HAS_FRAGS` permutation tried |
| `cil_from_wireguard` | bpf_wireguard | tc/tcx **ingress** of `cilium_wg0` |
| `cil_to_wireguard` | bpf_wireguard | tc/tcx **egress** of `cilium_wg0` (when `NeedEgressOnWireGuardDevice`) |
| `cil_sock4_connect`, `cil_sock6_connect` | bpf_sock | `cgroup/connect4|6` on root cgroup v2 |
| `cil_sock4_sendmsg`, `cil_sock6_sendmsg` | bpf_sock | `cgroup/sendmsg4|6` (UDP) |
| `cil_sock4_recvmsg`, `cil_sock6_recvmsg` | bpf_sock | `cgroup/recvmsg4|6` (UDP rev-NAT) |
| `cil_sock4_getpeername`, `cil_sock6_getpeername` | bpf_sock | `cgroup/getpeername4|6` (`ENABLE_SOCKET_LB_PEER`) |
| `cil_sock4_pre_bind`, `cil_sock6_pre_bind` | bpf_sock | `cgroup/bind4|6` (`ENABLE_HEALTH_CHECK`) |
| `cil_sock4_post_bind`, `cil_sock6_post_bind` | bpf_sock | `cgroup/post_bind4|6` (`ENABLE_NODEPORT`) |
| `cil_sock_release` | bpf_sock | `cgroup/sock_release` (delete rev-NAT entries) |
| `cil_sock_{udp,tcp}_destroy_v{4,6}` | bpf_sock_term | `iter/udp`, `iter/tcp` BPF iterators |
| `probe_fib_lookup_{skip_neigh,tbid,src}` | bpf_probes | load-only feature probes |

tc attachment uses tcx links (`link.AttachTCX`, anchor `Tail()`) when the kernel
supports it, else `clsact` + `netlink.BpfFilter` with `DirectAction: true` and
`option.Config.TCFilterPriority`; netkit devices use `AttachNetkitPrimary`
(host side) / `AttachNetkitPeer`. Programs are pinned under
`/sys/fs/bpf/cilium/...` by name.

### Tail-call graph

All internal tail calls go through the per-object `cilium_calls` PROG_ARRAY
(`CILIUM_CALL_SIZE 50`, pinned `CILIUM_PIN_REPLACE`), populated by the loader
from BTF decl tags `tail:cilium_calls/<idx>` (`pkg/bpf/collection.go:
resolveTailCalls`). Per-endpoint delivery uses two global PROG_ARRAYs indexed by
endpoint ID: `cilium_call_policy` (ingress policy) and `cilium_egresscall_policy`
(`POLICY_PROG_MAP_SIZE = ENDPOINTS_MAP_SIZE 65536`).

Slots (`lib/tailcall.h`): 1 `DROP_NOTIFY`, 2 `ERROR_NOTIFY`, 4 `HANDLE_ICMP6_NS`,
5 `SEND_ICMP6_TIME_EXCEEDED`, 6 `ARP`, 7 `IPV4_FROM_LXC` (= `IPV4_FROM_NETDEV` =
`IPV4_FROM_OVERLAY` = `IPV4_FROM_WIREGUARD`), 8 `IPV46_RFC6052`, 9 `IPV64_RFC6052`,
10 `IPV6_FROM_LXC` (= v6 NETDEV/OVERLAY/WIREGUARD), 11 `IPV4_TO_LXC_POLICY_ONLY`
(= `IPV4_TO_HOST_POLICY_ONLY`), 12 `IPV6_TO_LXC_POLICY_ONLY`, 13
`IPV4_TO_ENDPOINT`, 14 `IPV6_TO_ENDPOINT`, 15 `IPV4_NODEPORT_NAT_EGRESS`, 16
`IPV6_NODEPORT_NAT_EGRESS`, 17 `IPV4_NODEPORT_REVNAT`, 18
`IPV6_NODEPORT_REVNAT_INGRESS`, 19 `IPV6_NODEPORT_REVNAT_EGRESS`, 20
`IPV4_NODEPORT_NAT_FWD`, 21 `IPV4_NODEPORT_DSR`, 22 `IPV6_NODEPORT_DSR`, 23
`IPV4_FROM_HOST`, 24 `IPV6_FROM_HOST`, 25 `IPV6_NODEPORT_NAT_FWD`, 26
`IPV4_FROM_LXC_CONT`, 27 `IPV6_FROM_LXC_CONT`, 28 `IPV4_CT_INGRESS`, 29
`IPV4_CT_INGRESS_POLICY_ONLY`, 30 `IPV4_CT_EGRESS`, 31 `IPV6_CT_INGRESS`, 32
`IPV6_CT_INGRESS_POLICY_ONLY`, 33 `IPV6_CT_EGRESS`, 34 `SRV6_ENCAP`, 35
`SRV6_DECAP`, 36 `IPV4_NODEPORT_NAT_INGRESS`, 37 `IPV6_NODEPORT_NAT_INGRESS`,
38 `IPV4_NODEPORT_SNAT_FWD`, 39 `IPV6_NODEPORT_SNAT_FWD`, 40
`IPV4_INTER_CLUSTER_REVSNAT`, 41 `IPV4_CONT_FROM_HOST`, 42
`IPV4_CONT_FROM_NETDEV`, 43 `IPV6_CONT_FROM_HOST`, 44 `IPV6_CONT_FROM_NETDEV`,
45 `IPV4_NO_SERVICE`, 46 `IPV6_NO_SERVICE`, 47 `MULTICAST_EP_DELIVERY`, 48
`IPV4_POLICY_DENIED`, 49 `IPV6_POLICY_DENIED`. Slot 3 is a deliberate gap.

Edges (IPv4 shown; IPv6 mirrors with the v6 slots):

```
bpf_lxc
  cil_from_container ─► 7 IPV4_FROM_LXC (tail_handle_ipv4: per-packet LB)
                     ─► 6 ARP
  cil_lxc_policy_egress ─► 7 IPV4_FROM_LXC
  7  ─► 45 IPV4_NO_SERVICE (no backend, SERVICE_NO_BACKEND_RESPONSE)
     ─► 30 IPV4_CT_EGRESS (TAIL_CT_LOOKUP4)
  30 ─► 26 IPV4_FROM_LXC_CONT (or inline if only one AF)
  26 ─► 48 IPV4_POLICY_DENIED | 17 IPV4_NODEPORT_REVNAT | 34 SRV6_ENCAP
     ─► cilium_call_policy[dst_ep] (local delivery, ENABLE_ROUTING off)
     ─► redirect_peer / encap / fib_redirect / stack
  cil_to_container ─► 28 IPV4_CT_INGRESS ─► 13 IPV4_TO_ENDPOINT (ipv4_policy)
                   ─► cilium_egresscall_policy[epid]   (MARK_MAGIC_PROXY_EGRESS_EPID)
                   ─► cilium_call_policy[host_ep_id]   (host FW, identity HOST_ID)
  cil_lxc_policy   ─► 29 IPV4_CT_INGRESS_POLICY_ONLY ─► 11 IPV4_TO_LXC_POLICY_ONLY
  any drop         ─► 1 DROP_NOTIFY;  ICMPv6 ─► 4 / 5

bpf_host
  cil_from_netdev / cil_from_host ─► 7 IPV4_FROM_NETDEV / 23 IPV4_FROM_HOST
  7/23 (handle_ipv4: nodeport_lb4, host FW lookup)
       ─► 42 IPV4_CONT_FROM_NETDEV / 41 IPV4_CONT_FROM_HOST
       ─► 35 SRV6_DECAP
  nodeport_lb4 ─► 21 IPV4_NODEPORT_DSR | 15 IPV4_NODEPORT_NAT_EGRESS
               ─► 36 IPV4_NODEPORT_NAT_INGRESS ─► 17 IPV4_NODEPORT_REVNAT
               ─► 8 IPV46_RFC6052 / 9 IPV64_RFC6052 | 37 IPV6_NODEPORT_NAT_INGRESS
               ─► 45 IPV4_NO_SERVICE
  41/42 ─► cilium_call_policy[ep] (local delivery) | encap | redirect | stack
  cil_to_netdev ─► handle_nat_fwd ─► 20 IPV4_NODEPORT_NAT_FWD ─► 38 IPV4_NODEPORT_SNAT_FWD
                ─► 34 SRV6_ENCAP
  cil_to_host ─► 11 IPV4_TO_HOST_POLICY_ONLY (host FW)  ─► 20 (IPsec rev-DNAT)
  cil_host_policy ─► cilium_call_policy[lxc_id] (host → pod hairpin)

bpf_overlay
  cil_from_overlay ─► 7 IPV4_FROM_OVERLAY ─► 40 IPV4_INTER_CLUSTER_REVSNAT
                                          ─► 47 MULTICAST_EP_DELIVERY
                                          ─► nodeport_lb4 (same as host)
                   ─► 6 ARP (VTEP)
  cil_to_overlay ─► handle_nat_fwd ─► 20 ─► 38

bpf_xdp
  cil_xdp_entry ─► 7 IPV4_FROM_NETDEV (tail_lb_ipv4) ─► 21 DSR | 15 NAT_EGRESS | 36 NAT_INGRESS ─► 17

bpf_wireguard
  cil_from_wireguard ─► 7 IPV4_FROM_WIREGUARD ─► cilium_call_policy[ep] | stack
  cil_to_wireguard   ─► handle_nat_fwd ─► 20 ─► 38
```

`tail_call_internal` returns `DROP_MISSED_TAIL_CALL (-140)` and stores the
slot in `ext_err` if the slot is empty (the loader prunes unreachable tail
programs, so a miss is a config/DCE bug).

### Per-packet pipelines

1. **Container → anywhere** (`cil_from_container`, veth ingress): clear cb;
   store trace-id; `queue_mapping=0`; `edt_set_aggregate(LXC_ID)`;
   `TRACE_FROM_LXC`; ethertype/`pull_l3_hdr`; tail 7. `tail_handle_ipv4`:
   `lxc.h` source-IP check (`DROP_INVALID_SIP`), `ENABLE_PER_PACKET_LB`:
   `lb4_lookup_service` (east-west) → `lb4_local` (CT_SERVICE, backend select,
   hairpin if backend == self → `loopback`, DNAT via `lb4_xlate`) → store
   `rev_nat_index/proxy_port/cluster_id` in cb (`lb4_ctx_store_state`) → tail
   30 `IPV4_CT_EGRESS` (TAIL_CT_LOOKUP4 fills `ct_buffer4`, scope FORWARD after
   LB) → tail 26 `handle_ipv4_from_lxc`: restore LB state, `lookup_ip4_remote_endpoint(daddr,
   cluster_id)` → `dst_sec_identity` (WORLD_IPV4 if none); CT status switch:
   NEW/ESTABLISHED → L7 LB redirect first if `proxy_port`, skip policy for
   hairpin, `policy_can_egress4` (+auth), verdict notify, deny → tail 48 or
   drop; REPLY/RELATED → skip policy, redirect to proxy if `proxy_redirect`.
   Then CT create (NEW) / recreate on `rev_nat_index` or `proxy_redirect`
   mismatch; REPLY with `node_port` → tail 17 rev-DNAT. `ipv4_forward_to_destination`:
   `proxy_port` → `ctx_redirect_to_proxy4`; `ENABLE_ROUTING` off & local ep →
   `ipv4_local_delivery` (policy tail call or `redirect_peer`); multicast;
   `ENABLE_SRV6` → tail 34; egress-gateway hook; `ENABLE_VTEP`; `TUNNEL_MODE`
   → `encap_and_redirect_lxc` (VNI = identity<<8); IPsec/WireGuard: set
   `MARK_MAGIC_ENCRYPT`/`MARK_MAGIC_IDENTITY` and pass to stack (redirect
   happens in `cil_to_netdev`); `enable_bpf_host_routing` → `fib_redirect_v4`
   (`BPF_FIB_LOOKUP_TBID` with `rt_info`); else `TRACE_TO_STACK`, `CTX_ACT_OK`.
2. **Host/network → container** (`cil_to_container`, veth egress; or
   `cilium_call_policy[ep]` from bpf_host/bpf_overlay/bpf_wireguard via
   `tail_call_policy` in `local_delivery.h`): `inherit_identity_from_host`
   decodes `MARK_MAGIC_IDENTITY/PROXY_INGRESS/PROXY_EGRESS/HOST/ENCRYPT/
   DECRYPT/OVERLAY` into `src_identity` (HOST_ID, WORLD, or identity); host FW
   hairpin for `HOST_ID`; store `CB_SRC_LABEL`; tail 28 → TAIL_CT_LOOKUP4
   (CT_INGRESS, BIDIR) → `tail_ipv4_to_endpoint` → `ipv4_policy`: REPLY/RELATED
   → `lb4_rev_nat` if `rev_nat_index`/`nat_port` (undo hairpin/loopback SNAT),
   redirect to egress proxy if `proxy_redirect`; NEW → loopback detection via
   `service_loopback_ipv4`, `policy_can_ingress4`, auth, CT create with
   `from_tunnel`, `proxy_redirect`; `proxy_port` → `POLICY_ACT_PROXY_REDIRECT`
   → `ctx_redirect_to_proxy4` (sk_assign) or `TRACE_TO_LXC` + OK. From bpf_host
   the final step is `redirect_ep` (`redirect_peer` for veth, plain redirect for
   netkit) after `local_delivery_fill_meta`.
3. **Node → node overlay egress**: from (1) `encap_and_redirect_with_nodeid`:
   `ctx_set_encap_info4` fills `bpf_tunnel_key{tunnel_id=identity, remote_ipv4=
   tunnel_endpoint}` via `skb_set_tunnel_key` (optionally Geneve TLV via
   `skb_set_tunnel_opt`), redirects to `ENCAP_IFINDEX`. `cil_to_overlay`:
   EDT, read tunnel key back to recover identity, set `MARK_MAGIC_OVERLAY|id`,
   `handle_nat_fwd` (SNAT for inter-cluster / nodeport if not `ctx_snat_done`).
4. **Overlay ingress** (`cil_from_overlay`): WireGuard strict ingress check,
   `get_tunnel_key` → `tunnel_vni_to_sec_identity(vni) = ntohl(vni)>>8`
   (`WORLD_ID` split into WORLD_IPV4/6 by ethertype), `HOST_ID` from remote →
   `DROP_INVALID_IDENTITY`; tail 7: fragments, multicast, `nodeport_lb4`
   (NodePort from overlay, DSR Geneve extraction), VTEP validation, inter-cluster
   revSNAT, remote-node/DSR identity refresh from ipcache, egress gateway
   redirect to egress interface (`MARK_MAGIC_EGW_DONE`), local endpoint →
   `ipv4_local_delivery`, else `MARK_MAGIC_IDENTITY` + `ipv4_host_delivery`
   (redirect to `cilium_host` ingress).
5. **Native routing egress/ingress on NIC** (`cil_to_netdev`/`cil_from_netdev`):
   ingress: VLAN filter, `XFER_PKT_*` from XDP, IPsec `do_decrypt` (ESP →
   `MARK_MAGIC_DECRYPT|node_id<<16`, redirect to `cilium_host`), `do_netdev`
   → tail 7 (`handle_ipv4`: WireGuard strict, `nodeport_lb4`, host FW lookup)
   → tail 42 (`handle_ipv4_cont`: host FW verdict, local endpoint →
   `ipv4_local_delivery` with `enable_bpf_host_routing` (otherwise stack),
   VTEP, tunnel forwarding for hybrid, `DROP_UNROUTABLE` for unknown dst in
   `ENABLE_ROUTING` mode, else stack). Egress: derive `src_sec_identity` from
   mark (HOST for `MARK_MAGIC_HOST/OVERLAY/ENCRYPT`, identity for
   `PROXY_EGRESS/IDENTITY/EGW_DONE`), L7 LB EPID hairpin, host FW egress policy
   (skipped if `ctx_snat_done`), `host_egress_policy_hook`, egress gateway
   request redirect, EDT, IPsec `ipsec_maybe_redirect_to_encrypt` (redirect to
   `cilium_net` ingress for XFRM), WireGuard `host_wg_encrypt_hook` (redirect to
   `cilium_wg0`), strict-mode drop, health-check, `handle_nat_fwd` (SNAT-fwd /
   rev-DNAT), `TRACE_TO_NETWORK`.
6. **Host → pod** (`cil_from_host` on `cilium_host` egress): `edt_set_aggregate(0)`,
   L7 LB EPID hairpin, `inherit_identity_from_host`, `do_netdev(from_host=true)`
   → tail 23 → host FW egress (`ipv4_host_policy_egress_lookup`) → tail 41 →
   `handle_ipv4_cont`: local endpoint → `ipv4_local_delivery`; else tunnel or
   stack; `from_proxy` sets `MARK_MAGIC_SKIP_TPROXY`.
7. **NodePort from outside** (native device or XDP): `nodeport_lb4` →
   `lb4_lookup_service(key, east_west=false)` (scope EXT/INT), source-range
   check (`DROP_NOT_IN_SRC_RANGE`), ClusterIP from outside → `DROP_IS_CLUSTER_IP`
   unless `DISABLE_EXTERNAL_IP_MITIGATION`, L7 LB → hairpin to proxy (not in
   XDP), `lb4_local` (backend select, CT_SERVICE) → `backend_local` ? CT
   create (CT_EGRESS, `node_port=1`) and continue to local delivery :
   `nodeport_uses_dsr4` ? tail 21 (encode client in IP option / IPIP / Geneve,
   `fib_redirect`) : tail 15 NAT egress (`__snat_v4_nat` to `IPV4_DIRECT_ROUTING`
   or via tunnel with `WORLD_ID` VNI, `ctx_snat_done_set`, `fib_redirect`).
   Replies from remote backend hit `nodeport_lb4` → `nodeport_rev_dnat_get_info`
   / tail 36 `snat_v4_rev_nat` → tail 17 `nodeport_rev_dnat_ipv4` → `lb4_rev_nat`
   → `fib_redirect` back to client; DSR replies leave the backend node directly
   (backend's CT has `dsr_internal`, `nodeport_dsr_lookup_v4_nat_entry`
   restores service IP/port from a NAT entry created at DSR ingress).
   `XFER_PKT_NO_SVC` tells tc to skip nodeport after XDP handled it.
8. **Hairpin / loopback**: pod → its own service → itself: `lb4_local` marks
   `loopback`, SNATs source to `service_loopback_ipv4` (`USE_LOOPBACK_LB` in
   bpf_lxc), skips policy; reply path in `ipv4_policy` detects
   `saddr == service_loopback_ipv4` + `ct_has_loopback_egress_entry4` and
   `lb4_rev_nat(..., loopback=true)` restores addresses. Same-veth L7 LB
   hairpin: `from_l7lb && ifindex != cilium_host_ifindex` → `ctx_redirect(ctx,
   ifindex, 0)`.
9. **Fragments**: `ipfrag_encode_ipv4/6` → `fraginfo_t`; for non-first
   fragments `ipv4_handle_fragmentation` looks up L4 ports in
   `cilium_ipv4_frag_datagrams` (`DROP_FRAG_NOT_FOUND`, reported as WORLD),
   first fragments insert; `enable_ipv4/6_fragments` off → `DROP_FRAG_NOSUPPORT`
   for non-first fragments in policy/CT paths.
10. **MTU**: `CONFIG(device_mtu)` used only by DSR (`dsr_is_too_big` → ICMP
    frag-needed with `mtu - ohead`), `dsr_reply_icmp4/6`, and `icmp6.h` sample
    truncation (1280 − headers). Tunnel/pod MTU is handled by the agent
    (route MTU), not the datapath; `REASON_MTU_ERROR_MSG 15` marks CT trace of
    ICMP errors.

### Wire formats and marks

- VXLAN VNI / Geneve VNI = `sec_identity << 8` (`sec_identity_to_tunnel_vni`),
  so the 24-bit VNI holds a 24-bit identity; `WORLD_IPV4/6_ID` collapse to
  `WORLD_ID` on the wire (`get_tunnel_id`). Tunnel key read with
  `TUNNEL_KEY_WITHOUT_SRC_IP = offsetof(struct bpf_tunnel_key, local_ipv4)`.
- Geneve DSR option: `{opt_class 0x014B, type 0x81, length 2 (v4) / 5 (v6)}`
  + `addr, port, pad`. IPv4 DSR option: type `IPOPT_COPY|0x1a`, 8 bytes
  `{type, len, port, addr}`. IPv6 DSR: 24-byte Destination Options header
  `{nexthdr, hdrlen, opt_type 0x1B, opt_len 20, port, pad, addr}`.
- IPIP DSR: outer IPv4/IPv6 with RSS-friendly source
  (`rss_gen_src4(client, l4_hint)` within `IPV4_RSS_PREFIX/BITS`).
- IPsec: relies on XFRM policies keyed by mark (`0x*E00 | key<<12 | node_id<<16`);
  BPF only sets the mark and redirects to `cilium_net` ingress / `cilium_host`.
- Monitor events over `cilium_events` `PERF_EVENT_ARRAY`: `CILIUM_NOTIFY_DROP 1`
  (`NOTIFY_DROP_VER 3`), `DBG_MSG 2`, `DBG_CAPTURE 3`, `TRACE 4`
  (`NOTIFY_TRACE_VER 2`), `POLICY_VERDICT 5`, `CAPTURE 6`, `TRACE_SOCK 7`.
  Signals over `cilium_signals`. Both consumed by the agent monitor/Hubble.
- bpffs pins: `/sys/fs/bpf/tc/globals/cilium_*` (maps, `LIBBPF_PIN_BY_NAME`),
  `/sys/fs/bpf/cilium/<device>/{ingress,egress}/cil_*` (program links).
- netlink objects: `clsact` qdisc per device (legacy tc), tcx/netkit links,
  XDP link; no sysctls set from BPF (the agent sets `ip_early_demux`,
  `rp_filter`, `accept_local`, etc.).

### Files consumed at compile time (generated by the agent)

`<statedir>/globals/node_config.h` (WriteNodeConfig: all `#define`s listed
under "ENABLE_*" below plus map sizes, timeouts, `IPV4_GATEWAY`,
`IPV4_DIRECT_ROUTING`, `IPV4_RSS_PREFIX`, `VLAN_FILTER`, `ENCAP4/6_IFINDEX`,
`HOST_NETNS_COOKIE`, `NO_COMMON_MEM_MAPS`, `PREALLOCATE_MAPS`, `MKE_HOST`,
`STRICT_IPV4_*`), `<statedir>/<template-hash>/ep_config.h`
(WriteTemplateConfig with dummy template values), per-endpoint
`<statedir>/<ep-id>/ep_config.h` (WriteEndpointConfig, used only for hashing
and debugging — real values are patched as variables).

## Dependencies

- **Maps inventory** (all `cilium_*` maps referenced above), **loader/agent
  inventory** (`pkg/datapath/loader`, `pkg/bpf`, `pkg/datapath/config`,
  `pkg/datapath/linux/config`), **monitor/Hubble** (event formats), **proxy**
  (Envoy/DNS proxy consume `MARK_MAGIC_TO_PROXY`, `src_sec_id` offset in CT
  entry, `TC_INDEX_F_*`), **IPsec/WireGuard control plane** (XFRM state and
  `cilium_node_map_v2`, `cilium_encrypt_state`), **iptables/route manager**
  (TPROXY rules, `ip rule` for marks, `sch_fq` for EDT).
- Kernel: see next section. `bpf_sock_destroy` kfunc (6.4+) for socket
  termination; `BPF_F_XDP_HAS_FRAGS`; tcx (6.6+) / netkit (6.8+) optional.
- Toolchain: clang ≥ LLVM minimum in `Documentation/operations/system_requirements.rst`
  (agent image ships clang); `-mcpu=v3` in tests, `v3`/`v2`/`v1` probed at
  runtime (`getBPFCPU`: `HaveV3ISA` → v3, else `HaveV2ISA` → v2).

## Kernel / platform requirements

Minimum kernel: **5.10** (or RHEL 8.10's 4.18 backport). Feature-gated:
multicast amd64 ≥ 5.10 / arm64 ≥ 6.0, IPv6 BIG TCP ≥ 5.19, IPv4 BIG TCP ≥ 6.3,
netkit ≥ 6.8, tcx ≥ 6.6, `bpf_sock_destroy` ≥ 6.4, `BPF_FIB_LOOKUP_TBID` ≥ 6.5,
`BPF_FIB_LOOKUP_SRC` ≥ 6.7, `BPF_FIB_LOOKUP_SKIP_NEIGH` ≥ 6.4 (probed by
`bpf_probes.c`).

### Helpers declared (`include/bpf/helpers*.h`), by program type

- Generic (`helpers.h`): `map_lookup_elem`, `map_update_elem`, `map_delete_elem`,
  `map_lookup_percpu_elem`, `for_each_map_elem`, `ktime_get_ns`,
  `ktime_get_boot_ns`, `jiffies64`, `get_socket_cookie`, `get_netns_cookie`,
  `get_cgroup_classid`, `trace_printk`, `get_prandom_u32`, `csum_diff`,
  `tail_call`, `get_smp_processor_id`, `fib_lookup`, `sk_lookup_tcp`,
  `sk_lookup_udp`, `getsockopt`/`setsockopt`, `get_current_cgroup_id`,
  `set_retval` (probed `HAVE_SET_RETVAL`), `loop`, `ringbuf_reserve/submit/discard`
  (declared; events still use perf).
- tc/skb (`helpers_skb.h`): `get_hash_recalc`, `redirect`, `redirect_neigh`,
  `redirect_peer`, `clone_redirect`, `skb_load_bytes`, `skb_store_bytes`,
  `l3_csum_replace`, `l4_csum_replace`, `skb_adjust_room`, `skb_change_type`,
  `skb_change_proto`, `skb_change_tail`, `skb_change_head`, `skb_pull_data`,
  `skb_get_tunnel_key`, `skb_set_tunnel_key`, `skb_get_tunnel_opt`,
  `skb_set_tunnel_opt`, `perf_event_output`, `skc_lookup_tcp`, `sk_release`,
  `sk_assign`.
- XDP (`helpers_xdp.h`): `xdp_adjust_meta`, `xdp_adjust_head`,
  `xdp_adjust_tail`, `redirect`, `xdp_load_bytes`/`xdp_store_bytes`
  (probed `HAVE_XDP_LOAD_BYTES`/`HAVE_XDP_STORE_BYTES`, else software loops in
  `ctx/xdp.h`), `xdp_get_buff_len` (`HAVE_XDP_GET_BUFF_LEN`),
  `perf_event_output`; csum/adjust-room/tunnel helpers are `BPF_STUB`s in XDP
  (software checksum in `ctx/xdp.h`, `CSUM_MANGLED_0`).
- cgroup sock (`helpers_sock.h`): `perf_event_output` on `bpf_sock_addr`;
  plus `get_socket_cookie`, `get_netns_cookie`, `sk_lookup_*`, `set_retval`.
- iter (`bpf_sock_term.c`): `seq_write`, kfunc `bpf_sock_destroy`.
- Kernel probes at agent start (`pkg/datapath/linux/probes/probes.go`):
  `HaveProgramHelper` for the above, `HaveLargeInstructionLimit` (1M insns),
  `HaveBoundedLoops`, `HaveWriteableQueueMapping` (`skb_ecn_set_ce` as proxy),
  `HaveV2ISA`/`HaveV3ISA`, `HaveSKBAdjustRoomL2RoomMACSupport`,
  `HaveDeadCodeElim`, `HaveIPv6Support`, `HaveBatchAPI`, managed neighbors,
  `kernel_hz`.

### Map types used

`BPF_MAP_TYPE_LRU_HASH` (23 uses), `HASH` (22), `LPM_TRIE` (16), `PERCPU_ARRAY`
(9), `ARRAY_OF_MAPS` (6), `ARRAY` (4), `PROG_ARRAY` (3), `HASH_OF_MAPS` (3),
`PERF_EVENT_ARRAY` (2), `PERCPU_HASH` (1), `LRU_PERCPU_HASH` (1). Flags:
`BPF_F_NO_PREALLOC` (conditional `CONDITIONAL_PREALLOC`), `BPF_F_NO_COMMON_LRU`
(`LRU_MEM_FLAVOR`), `BPF_F_RDONLY_PROG` (`BPF_F_RDONLY_PROG_COND`, unpinned
for downgrade compatibility by `adjustMapFlagsForUpgrade`).

### Program types

`BPF_PROG_TYPE_SCHED_CLS` (tc/tcx/netkit), `BPF_PROG_TYPE_XDP`,
`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (connect/sendmsg/recvmsg/getpeername/bind),
`BPF_PROG_TYPE_CGROUP_SOCK` (post_bind, sock_release), `BPF_PROG_TYPE_TRACING`
iter (`iter/tcp`, `iter/udp`).

### Architecture notes

- The C is architecture-neutral BPF bytecode; the same object runs on x86-64
  and arm64. Differences that matter: (1) `tail_call_static` is written as
  inline asm with constant r2/r3 so the **x86-64 JIT** can emit a direct
  `jmp` instead of a retpoline; arm64 has no retpoline concern but benefits
  from the same constant-index form. (2) `builtins.h` `memcpy`/`memcmp` do
  8/4/2/1-byte unaligned loads assuming the JIT handles unaligned access
  (both arches do; `__align_stack_8` used for >8-byte stack objects).
  (3) `include/linux/socket.h` has an `__x86_64__ && __ILP32__` conditional
  only. (4) Multicast requires arm64 ≥ 6.0 (`for_each_map_elem` on
  `HASH_OF_MAPS` inner maps). (5) BIG TCP arm64 support follows the kernel.
  (6) The agent builds the objects with the host clang at runtime, so arm64
  nodes need an arm64 clang in the image (`CROSS_ARCH` in `Makefile.bpf`).
- **XDP driver dependence**: `XDPDriverMode` needs a NIC driver with native XDP
  (`ndo_bpf`) and, for redirects, `ndo_xdp_xmit`; `BPF_F_XDP_HAS_FRAGS`
  (multi-buffer) is attempted first and falls back (`xdpPermutations`); no
  native support → `XDPGenericMode` (skb-based, slower). `XDP_TX` is used for
  hairpin replies (DSR/ICMP), `XDP_REDIRECT` for forwarding to another device.
  Checksum offload is unavailable in XDP, hence software csum in `ctx/xdp.h`.
  `xdp_adjust_meta` must be supported by the driver for `XFER_PKT_*` to reach
  tc (`ctx_move_xfer`).

## Tests

- **Unit tests (`bpf/tests/*.c`, `make run_bpf_tests`, CI
  `lint-bpf-checks.yaml`)**: each `.c` includes a real object (`bpf_lxc.c`,
  `bpf_host.c`, …) with option `#define`s, uses `PKTGEN`/`SETUP`/`CHECK`
  sections; `bpf/tests/bpftest/bpf_test.go` loads the ELF with cilium/ebpf,
  runs programs with `prog.Run` (BPF_PROG_RUN) in a netns, decodes
  protobuf-encoded results from `suite_result_map`, and produces coverbee
  coverage. Fixtures in `tests/lib/*.h` populate ipcache, lxc, lb, policy,
  egressgw, node, subnet maps; `mock_skb_metadata.c` mocks skb fields;
  scapy-generated packets in `output/scapy_bytes.h` and `_scapy_selftest.c`.
  Behaviours pinned (by file family): CT (`bpf_ct_tests.c`,
  `conntrack_test.c`), NAT incl. ICMP and collisions (`bpf_nat_tests.c`,
  `tc_nodeport_snat_conflict.c`, `tc_nodeport_icmp{4,6}_snat*.c`), NodePort
  NAT/DSR/IPIP/Geneve/hybrid/fragments/no-backend/terminating/wildcard
  (`tc_nodeport_*.c`, `nodeport_*.c`, `host_kpr_dsr_*.c`), ClusterIP/external
  IPs/hostport (`tc_lb_*.c`, `tc_lxc_lb_*.c`), Maglev + affinity
  (`session_affinity*_test.c`), LRP skip (`skip_lb_xlate_*.c`), egress gateway
  (`tc_egressgw_*.c`), IPsec/WireGuard encrypt/decrypt incl. strict
  (`encrypt_host_*.c`, `decrypt_host_*.c`, `decrypt_overlay_wireguard.c`),
  host firewall (`host_hostfw_*.c`, `hostfw_*.c`), policy drop/reject
  (`tc_lxc_policy_drop.c`, `tc_policy_reject_response_test.c`,
  `network_policy.c`), redirect veth vs netkit (`tc_redirect_*_{veth,netkit}.c`),
  L2 announcements, SRv6 encap/decap, IPv6 NDP, IP options trace id, multicast,
  ratelimit, jhash, builtins (`builtins.c`, memcpy/memmove/memzero/memcmp
  generators), fib, classifiers, skip-tunnel, inter-cluster SNAT, L7 LB
  hairpin/local backend, socket LB host-only and destroy, ENI symmetric routing,
  drop notify, IPIP health-check termination, `bpf_skb_255/511_tests.c`
  (skb length edge cases).
- **Compile permutations (`make -C bpf build_all`, `BUILD_PERMUTATIONS=1`)**:
  every option list in `bpf/Makefile` (`LXC_OPTIONS`, `HOST_OPTIONS`,
  `XDP_OPTIONS`, `LB_OPTIONS`, `WIREGUARD_OPTIONS`) plus `MAX_BASE_OPTIONS`
  (everything on) must compile with `-Werror`.
- **Verifier / complexity (`tests-datapath-verifier.yaml`)**: loads each
  program with every option set in `bpf/complexity-tests/{510,61,netnext}`
  on LVH VMs for kernels 5.10, 6.1 and net-next; records verifier instruction
  counts (`verifier-complexity*.json`, `tools/complexity-diff`). Privileged Go
  tests in `pkg/datapath/loader/*_test.go` (37 `Test*`, e.g.
  `TestPrivilegedCompile`, `verifier_load_test.go`, tcx/tc/xdp attach,
  plugins, template hashing).
- **Static checks**: `make -C bpf checkpatch` (kernel checkpatch.pl in
  container), `coccicheck` (`contrib/coccinelle/*.cocci`), `sparse`, `clang
  --analyze`. `bpf_alignchecker.o` + `pkg/alignchecker` in Go unit tests.
- **E2E**: `test/` and `.github/workflows/conformance-*`, `tests-e2e-*` run
  the real datapath in kind/LVH — owned by the e2e inventory.

## Rust mapping

### What the reference's runtime clang compile buys

Cilium compiles `bpf_lxc.c`/`bpf_host.c`/`bpf_overlay.c`/`bpf_xdp.c`/
`bpf_wireguard.c`/`bpf_sock.c` **on the node at agent start** (and whenever
`hashDatapath(node_config)` changes): `compileDatapath` in
`pkg/datapath/loader/compile.go` runs `clang -O2 --target=bpf -std=gnu99
-nostdinc -Wall -Wextra -Werror -Wshadow -mcpu=<probed v1|v2|v3> -D... -c`. The
per-node specialization comes from three layers:

1. **Preprocessor `#define`s in `node_config.h`** — every `ENABLE_*`, map
   size, CT timeout, `TUNNEL_MODE`, `DSR_ENCAP_MODE`, `IPV4_DIRECT_ROUTING`,
   `VLAN_FILTER`, `ENCAP_IFINDEX`, `HOST_NETNS_COOKIE`. These prune whole
   code paths at compile time, which is how a 3,000-line `nodeport.h` fits
   the verifier: the `MAX_BASE_OPTIONS` object exists only to prove it can
   still load. Map sizes must be compile-time constants because BTF map
   definitions carry `max_entries`.
2. **Template objects + `.rodata.config` patching** — `bpf_lxc` and
   `bpf_host` are compiled once per *template hash* (node config + dummy
   endpoint values: `templateLxcID 65535`, `templateIPv4 192.0.2.3`,
   `templateMAC 02:00:60:0D:F0:0D`, identity WORLD). At endpoint load, the
   Go loader sets `ebpf.CollectionSpec.Variables["__config_<name>"]` from the
   generated `config.BPFLXC`/`BPFHost` structs (`applyConstants` in
   `pkg/bpf/constants.go`), then runs its own **reachability analysis**
   (`pkg/bpf/analyze`, `computeReachability`) to delete branches that became
   dead after constant substitution, so `if (CONFIG(enable_x))` is free at
   runtime and unused maps are not created (`logFreedMaps`). The `CONFIG()`
   macro reloads the `.rodata` pointer per access (inline asm `ll`) precisely
   so this branch-pruning works.
3. **Runtime map-based config** — `cilium_runtime_config` array
   (`RUNTIME_CONFIG_UTIME_OFFSET`, `RUNTIME_CONFIG_AGENT_LIVENESS`) and per-
   feature maps (`cilium_encrypt_state`, `cilium_throttle`, ipcache flags)
   for values that change without reload.

Build-time compilation loses only layer 1. Layers 2 and 3 are available to
any loader (cilium/ebpf in Go, aya in Rust) with no compiler on the node.

### Replacing layer 1 without a node-side compiler

- **Global variables + verifier DCE (CO-RE style)**: turn every `#ifdef
  ENABLE_X` that gates *code* (not map definitions) into `if (CONFIG(enable_x))`
  on a `volatile const` in `.rodata`. The kernel verifier already removes
  branches on constant `.rodata` when the map is frozen (`BPF_MAP_FREEZE`,
  5.2+), and aya/libbpf/cilium-ebpf freeze `.rodata` on load. Cilium's own
  `pkg/bpf/analyze` shows the extra pre-load pruning needed to keep
  instruction counts within the 1M limit and to avoid creating unused maps;
  flowsdn needs the same pass in Rust (walk `asm::Instructions`, evaluate
  `ld_imm64` of `.rodata` + `ldx` + `jmp` sequences). This is the right
  architectural answer and matches where Cilium itself is migrating
  (`datapath_config.rst` calls `#define` config deprecated).
- **Map sizes**: BTF map `max_entries` can be overridden at load
  (`MapSpec.MaxEntries` in cilium/ebpf; `aya::EbpfLoader::set_max_entries`),
  so `CT_MAP_SIZE_*`, `IPCACHE_MAP_SIZE`, `SNAT_MAPPING_*`, `LB_MAGLEV_LUT_SIZE`
  (inner map value size = `4 * LUT_SIZE`, needs `MapSpec.InnerMap` override)
  become loader parameters. `LB_MAGLEV_LUT_SIZE` is also a modulus in code →
  make it a `.rodata` variable read once.
- **Structural variants that cannot be a runtime branch**: `ETH_HLEN` (L2 vs
  L3 device — already `CONFIG(eth_header_length)` in bpf_host), `PROG_TYPE`
  (tc vs xdp — separate objects anyway), `DSR_ENCAP_MODE` (three code
  variants — build all three into one object behind a `.rodata` switch, DCE
  removes two), `IS_BPF_LXC/HOST/OVERLAY/XDP/WIREGUARD` (per object, fine),
  `ENABLE_IPV4`/`ENABLE_IPV6` (keep as runtime flags; verifier budget is the
  risk — measure against `complexity-tests/netnext/*`). Ship a small matrix of
  prebuilt objects only if a single object exceeds the verifier budget on 5.10.
- **Per-node constants** (`IPV4_GATEWAY`, `IPV4_DIRECT_ROUTING`,
  `IPV4_SNAT_EXCLUSION_DST_CIDR`, `HOST_NETNS_COOKIE`, `ENCAP_IFINDEX`,
  `VLAN_FILTER` switch table): all become `.rodata` variables or a small
  `ARRAY` map (`VLAN_FILTER` → `HASH` map keyed `{ifindex, vlan}`).
- **`-mcpu` selection**: build with `-mcpu=v3` (5.10 supports v3 on x86-64
  and arm64 JITs); keep a `v2` build only if a target kernel lacks
  32-bit-subreg JIT support.

### aya-ebpf in Rust vs keeping C compiled at build time

- **Rewrite in Rust (aya-ebpf)**. Pros: one language, `no_std` shared types
  between kernel and userspace crates (the whole `bpf_alignchecker` problem
  disappears), `#[map]`/`#[classifier]`/`#[xdp]`/`#[cgroup_sock_addr]`
  attributes, `aya-log`. Cons and hard parts: (a) the reference relies on
  `__always_inline` everywhere plus tail calls and `PERCPU_ARRAY` scratch to
  fit the verifier; Rust's codegen for BPF is less mature (bounds-check
  patterns, `core::mem::size_of` reads through `Option`, panics must be
  compiled out) and produces larger programs for the same logic — the 1M
  instruction limit and 512-byte stack are the binding constraints in
  `nodeport.h`/`lb.h`/`nat.h`; (b) `tail_call_static` inline asm and the
  `CONFIG()` `ll` asm are not expressible in stable Rust BPF codegen without
  `asm!` support for BPF (nightly, limited); (c) the unrolled
  `memcpy`/`memcmp` in `builtins.h` exist because compiler-generated loops or
  libcalls break the verifier — Rust `copy_from_slice` on BPF hits the same
  issue and needs the same hand-unrolled helpers; (d) helpers not wrapped by
  aya (`skb_set_tunnel_opt`, `sk_assign`, `skc_lookup_tcp`,
  `redirect_neigh` with params, `fib_lookup` flags, `for_each_map_elem`
  callbacks, `xdp_load_bytes`) need `aya_ebpf::helpers::gen` raw bindings;
  (e) BTF-defined maps with `__array(values, int())` PROG_ARRAY and
  `ARRAY_OF_MAPS`/`HASH_OF_MAPS` inner specs need aya's BTF map support, which
  is newer and less exercised; (f) `iter/tcp` + kfunc `bpf_sock_destroy` needs
  kfunc calls (`.ksyms`), supported in aya only recently; (g) no equivalent to
  Cilium's 35k lines of C unit tests — porting `bpf/tests` is as large as
  porting the datapath.
- **Keep C, compile at build time, load with aya (userspace)**. Pros: the
  reference algorithms and their verifier-proven shapes can be re-derived
  without also fighting Rust codegen; `aya::EbpfLoader` handles BTF maps,
  `.rodata` globals (`set_global`), pinning, tcx/netkit/XDP/cgroup links, prog
  arrays; clang is a build dependency only (matches the "OCI is a build-time
  input, nothing on the start path compiles" rule). Cons: two languages;
  need to regenerate Rust structs from BTF (`aya-tool`/`bindgen`-style) to
  keep map layouts in sync; still need the Rust reachability/DCE pass and
  map-size override plumbing described above; clean-room means the C must
  be rewritten from this inventory, not copied.
- **Recommended structure**: `flowsdn-bpf` (C, `#![no_std]`-adjacent build
  via `cc`/`build.rs` calling clang with `-mcpu=v3 -O2 -g -target bpf`,
  emitting one object per hook family: `lxc`, `host`, `overlay`, `xdp`,
  `wireguard`, `sock`, `sock_term`); `flowsdn-datapath` (Rust: object
  embedding via `include_bytes_aligned!`, `.rodata` config structs generated
  from BTF datasec `.rodata.config` decl tags exactly as `dpgen` does, DCE
  pass, tail-call population from `tail:` decl tags, tcx/netkit/XDP/cgroup
  attach with pinning under `/sys/fs/bpf/flowsdn`, feature probes); keep the
  `CB_*`/`MARK_MAGIC_*`/`TC_INDEX_F_*` contract identical where interop with
  Envoy/iptables TPROXY or Hubble-compatible event formats is desired, or
  redefine deliberately.
- **Testing**: reuse the `BPF_PROG_RUN` harness idea — a Rust test runner
  (`aya::programs::ProgramFd` + `bpf_prog_test_run`) with a packet builder
  (`etherparse`/`smoltcp` wire crates) replacing `pktgen.h`; coverage via
  instruction-level instrumentation is optional. Verifier complexity CI is
  mandatory: load every object on 5.10, 6.1, latest with the all-features
  config to catch budget regressions early.

## Recommendation

**Keep C for the kernel programs, compiled at build time (`-mcpu=v3`, one
object per hook family), loaded and configured from Rust with aya.** Replace
Cilium's node-side clang + `#define` specialization with `.rodata` config
variables, loader-side map-size overrides and a Rust reachability/DCE pass;
keep template-style constant patching for per-endpoint values (identity,
endpoint id, IPs, MAC, ifindex, netns cookie). Defer a Rust (aya-ebpf) rewrite
of program bodies until the C datapath is stable and the verifier budget of a
single-object-per-hook design is measured; if any object cannot fit 5.10's
verifier with all features enabled, ship a small prebuilt matrix (e.g.
`{tunnel,native} × {v4,v6,dual}`) rather than reintroducing a compiler.
Effort: **XL** — the reference is ~8k lines of program bodies + ~23k lines of
library + ~2k include, and the Rust userspace side (config generation from
BTF, DCE, attach, probes, test harness) is another 8–15k lines; a
feature-parity clean-room reimplementation is > 20k lines of Rust plus a
comparable amount of new C. A first milestone (lxc + host + overlay, v4/v6,
CT, policy, ClusterIP/NodePort SNAT, VXLAN, monitor events; no DSR/IPsec/
SRv6/multicast/egress-gw/host-fw) is L.

## Open questions

- Which parts of the `skb->mark` contract must stay bit-compatible? Envoy
  TPROXY (`MARK_MAGIC_TO_PROXY`, proxy port in upper 16 bits) and IPsec XFRM
  policies (`0x*E00`, key in bits 12..15, node id in 16..31) are the external
  consumers; everything else is internal and can be redesigned (e.g. a full
  32-bit identity instead of the 24-bit split).
- Verifier budget: does a single `host` object with v4+v6+nodeport+DSR
  (all three encap modes)+masquerade+hostfw+egw fit on 5.10 when `#ifdef`s
  become `.rodata` branches pruned only by the loader? Needs measurement
  against `bpf/complexity-tests/510/bpf_host/*.txt` instruction counts.
- Tail-call indirection vs verifier: Cilium uses tail calls partly to reset
  the verifier's state budget (`TAIL_CT_LOOKUP4` splitting CT from policy).
  With kernels ≥ 5.10 supporting BPF-to-BPF calls plus tail calls mixed
  (x86 5.10, arm64 6.0), can flowsdn use `__noinline` subprograms instead of
  `cilium_calls` for some edges? arm64 < 6.0 cannot mix them.
- Do we keep `PERF_EVENT_ARRAY` for monitor events (Hubble compatibility) or
  move to `BPF_MAP_TYPE_RINGBUF` (5.8+, already declared in `helpers.h` but
  unused)?
- Socket LB: keep `cgroup/*` hooks (requires cgroup v2 root attach and
  interacts with kube-proxy-less host networking) or start with per-packet
  LB only (`ENABLE_PER_PACKET_LB` path) and add socket LB later?
- Per-endpoint program objects (one `bpf_lxc` load per pod, ~50 tail programs
  each) vs a single shared lxc object with endpoint id read from a map keyed
  by ifindex (`skb->ifindex` / `CONFIG(interface_ifindex)`): the latter cuts
  load time and memory but changes how per-endpoint policy maps are selected
  (Cilium uses a per-endpoint `cilium_policy_<epid>` map renamed at load;
  a shared object needs `HASH_OF_MAPS` keyed by endpoint id).
- `bpf_sock_destroy` requires 6.4+; on older kernels Cilium falls back to
  no socket termination. Do we target ≥ 6.1 (LVH `61` matrix) and accept the
  same fallback, or require 6.6+ (tcx) and drop legacy `clsact` attachment
  entirely?
- Netkit vs veth as the default pod device: netkit (6.8+) allows the
  `AttachNetkitPrimary` path without `redirect_peer`; deciding this early
  simplifies `local_delivery.h` logic (`CB_DELIVERY_FLAGS_USE_REDIRECT_PEER`).
