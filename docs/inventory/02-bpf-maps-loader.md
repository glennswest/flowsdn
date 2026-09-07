# BPF map catalogue and userspace loader — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `bpf/lib/*.h` (map
definitions), `bpf/include/bpf/{loader.h,section.h,ctx/skb.h,ctx/xdp.h}`,
`bpf/node_config.h`, `bpf/ep_config.h`, `bpf/netdev_config.h`, `pkg/bpf/**`,
`pkg/maps/**`, `pkg/datapath/maps/**` (generated MapSpec catalogue),
`pkg/datapath/loader/**`, `pkg/datapath/config/**`, `pkg/datapath/tables/**`,
`pkg/datapath/linux/config/config.go` (header writer), `pkg/socketlb/**`
(cgroup attach), `pkg/monitor/{datapath_*.go,payload,agent}` (event decode),
`pkg/loadbalancer/maps/**` (LB map Go side).

Note: there is no `bpf/lib/maps.h` in v1.20.1. Map definitions are spread over
the per-feature headers listed below. There is also no `cilium_tunnel_map` any
more; the tunnel endpoint is carried in `remote_endpoint_info` (ipcache) and
`cilium_node_map_v2`.

## Purpose

This area is the contract between the C datapath and the Go agent: the set of
BPF maps (names, key/value layouts, sizes, flags, pin paths), the loader that
takes a compiled ELF, rewrites it for a specific node/endpoint/device (map
renames, `.rodata.config` constant patching, tail-call plumbing, dead-code
pruning), creates or reuses pinned maps under bpffs, attaches the programs
(tc/tcx/netkit/XDP/cgroup/iter) and swaps them atomically on upgrade, and the
perf-event channel that carries trace/drop/debug/policy-verdict notifications
from the datapath to the monitor (and on to Hubble). It also covers the
compile step (clang invoked at runtime against generated headers) and the
object cache that amortises it.

## Components

| Path | Lines | Purpose |
|---|---|---|
| `bpf/lib/conntrack_map.h` | 165 | CT maps (global + per-cluster array-of-maps) |
| `bpf/lib/nat.h` | ~1400 | SNAT maps, retries histogram, ipmasq LPM, per-cluster SNAT |
| `bpf/lib/lb.h` | ~2000 | LB service/backend/revnat/affinity/source-range/maglev/health maps |
| `bpf/lib/policy.h`, `local_delivery.h`, `tailcall.h` | ~130 / 40 / ~250 | policy LPM + stats, policy call PROG_ARRAYs, `cilium_calls` |
| `bpf/lib/eps.h`, `node.h`, `config_map.h`, `metrics.h`, `events.h`, `signal.h` | small | lxc, ipcache, node map, runtime config, metrics, perf arrays |
| `bpf/lib/{act,auth,edt,egress_gateway,ipsec,l2_responder,lrp,mcast,neigh,network_device,ratelimit,sock,srv6,subnet,trace_helpers,vtep,ipv4,ipv6}.h` | — | remaining map definitions |
| `bpf/lib/static_data.h`, `auxvars.h`, `map_defs.h` | 75 / 25 / 30 | `DECLARE_CONFIG`/`CONFIG()`, per-CPU `.data.aux`, prealloc/LRU flag macros |
| `bpf/lib/{notify,trace,drop,dbg,policy_log,trace_sock}.h` | — | monitor notification layouts |
| `bpf/include/bpf/loader.h`, `section.h` | 18 / 27 | `__uint/__type/__array`, `LIBBPF_PIN_BY_NAME`, `CILIUM_PIN_REPLACE`, section names |
| `bpf/node_config.h`, `ep_config.h`, `netdev_config.h` | ~140 / 12 / 5 | build-time stand-ins for the headers the agent writes at runtime |
| `bpf/Makefile.bpf` | ~90 | reference clang flags (`-O2 -g --target=bpf -std=gnu99 -nostdinc -mcpu=v3`) |
| `pkg/bpf` | 4286 (6212 with tests) | `bpf.Map` abstraction, `LoadCollection`, constants, pinning, reachability pruning, bpffs mount, perf/link helpers |
| `pkg/bpf/analyze` | ~1200 | basic-block + reachability analysis over `asm.Instructions` |
| `pkg/maps` (all subpackages) | ~11500 non-test (~16500 total) | per-map Go packages: key/value structs, cells, GC, REST handlers |
| `pkg/maps/ctmap` / `nat` / `policymap` / `srv6map` / `egressmap` / `multicast` | 1952 / 1133 / 960 / 538 / 607 / 530 | largest map packages |
| `pkg/maps/registry` | 287 | `MapRegistry`: MapSpec patches (max_entries/flags) applied at load |
| `pkg/datapath/maps` | ~1300 (generated) | `maps_generated.go`: `ebpf.MapSpec` per map, from `.maps` BTF; `mapkv.btf` |
| `pkg/datapath/loader` | 5666 (9597 with tests) | compile, template cache, endpoint/host/overlay/wireguard/xdp/sock load, tc/tcx/netkit/xdp attach, netlink device setup, datapath plugins (freplace) |
| `pkg/datapath/config` | 1724 | `config.Config` (node config) + dpgen-generated `Node`, `BPFLXC`, `BPFHost`, `BPFXDP`, `BPFOverlay`, `BPFWireguard`, `BPFSock` constant structs |
| `pkg/datapath/linux/config/config.go` | ~660 | `HeaderfileWriter`: writes `node_config.h`, endpoint/template/netdev headers |
| `pkg/datapath/tables` | 2114 (3628 with tests) | statedb tables: `Device`, `DeviceAddress`, `Route`, `Neighbor`, `Sysctl`, `NodeAddress`, `BandwidthQDisc`, `IPSetEntry`, `DirectRoutingDevice`, `L2Announce` |
| `pkg/socketlb` | ~450 | cgroup attach for `bpf_sock.c` (bpf_link with PROG_ATTACH fallback) |
| `pkg/datapath/bpf` | generated | bpf2go objects for `bpf_sock_term.c` and `bpf_probes.c` |
| `pkg/monitor/datapath_*.go`, `payload`, `agent` | ~2500 | decode of perf records, monitor socket protocol |

## Features

- **Pinned global maps under `/sys/fs/bpf/tc/globals/<name>`** survive agent
  restart; endpoints keep forwarding while the agent is down. `--bpf-root`
  overrides the bpffs mount (`defaults.BPFFSRoot=/sys/fs/bpf`, fallback
  `/run/cilium/bpffs` when running in a container without a host mount).
- **Per-endpoint policy maps** `cilium_policy_v3_<ID:05d>` (LPM trie) and
  per-endpoint tail-call maps `cilium_calls_<ID:05d>`; policy programs are
  reached through the global `cilium_call_policy` / `cilium_egresscall_policy`
  PROG_ARRAYs indexed by endpoint ID (65536 slots).
- **Map sizing options**: `--bpf-ct-global-tcp-max` (default 512Ki),
  `--bpf-ct-global-any-max` (256Ki), `--bpf-nat-global-max` (default
  `(tcp+any)*2/3`), `--bpf-neigh-global-max` (= NAT size),
  `--bpf-policy-map-max` (16384), `--bpf-lb-map-max` (65536) plus per-LB-map
  hidden overrides (`--bpf-lb-service-map-max`, `--bpf-lb-service-backend-map-max`,
  `--bpf-lb-rev-nat-map-max`, `--bpf-lb-affinity-map-max`,
  `--bpf-lb-source-range-map-max`, `--bpf-lb-maglev-map-max`),
  `--bpf-sock-rev-map-max` (256Ki), `--bpf-auth-map-max` (2^19),
  `--bpf-fragments-map-max` (8192), `--egress-gateway-policy-map-max`,
  `--bpf-map-dynamic-size-ratio` (sizes CT/NAT/neigh/sock-revnat from total
  RAM, then `AlignMapSizeForLRU` rounds to a multiple of possible CPUs).
- **`--preallocate-bpf-maps`**: toggles `PREALLOCATE_MAPS` → `CONDITIONAL_PREALLOC`
  (0 vs `BPF_F_NO_PREALLOC`) for hash maps; `NO_COMMON_MEM_MAPS` →
  `BPF_F_NO_COMMON_LRU` for LRU maps.
- **`BPF_F_RDONLY_PROG` on agent-owned maps** (lxc, ipcache, policy, services,
  node map, egress gw, srv6, subnet, vtep, auth, ipmasq, runtime config, ...)
  with upgrade/downgrade handling (`adjustMapFlagsForUpgrade`).
- **Map cache + error resolver** (`Map.WithCache()`): desired-state cache per
  key, failed updates retried by a controller (`bpf-map-sync`, 5 s min
  interval, `maxSyncErrors=512`).
- **Map event buffers** (`--bpf-map-event-buffers`, `Map.WithEvents`): ring of
  last N update/delete events per map with TTL, exposed via REST
  `GET /map/{name}/events`.
- **Map pressure metrics** (`WithPressureMetric`): gauge of fill ratio per map.
- **Runtime constants without recompilation** via `DECLARE_CONFIG` /
  `NODE_CONFIG` globals in `.rodata.config`, patched through
  `CollectionSpec.Variables` before load; JSON dump of applied values to
  `<state>/bpf_lxc.json`, `<state>/bpf/<dev>/bpf_host.json`, etc.
- **Dead-code elimination in the loader**: branches on `CONFIG()` values are
  evaluated statically; unreachable tail calls and maps are removed before the
  verifier sees them (fewer map FDs, smaller programs, per-endpoint pruning).
- **Template object cache**: one compile per distinct (node config, endpoint
  template config) hash under `/var/run/cilium/state/templates/<sha256>/`;
  endpoints with the same feature set share the ELF and differ only by
  constants and map renames.
- **Attach modes**: legacy tc (clsact, `--bpf-filter-priority`), tcx
  (`--enable-tcx`, kernel ≥ 6.6), netkit (`--datapath-mode=netkit`, ≥ 6.7),
  XDP (`--bpf-lb-acceleration` / `NodePortAcceleration` = disabled|native|
  generic|best-effort), cgroup socket hooks for socket LB, `iter/tcp|udp` for
  socket termination.
- **Atomic upgrade**: pinned `bpf_link` objects are `BPF_LINK_UPDATE`d in place;
  legacy tc uses `RTM_NEWTFILTER` replace; tail-call maps use
  `CILIUM_PIN_REPLACE` so a new program never runs against a half-populated
  calls map.
- **Datapath plugins** (`--enable-datapath-plugins`): `freplace` hooks inserted
  before/after subprograms, pinned under `/sys/fs/bpf/cilium/.../plugins/`.
- **Monitor events** over `cilium_events` (perf array), rate-limited per node
  (`--bpf-events-default-rate-limit`, `--bpf-events-default-burst-limit`),
  with payload capture length `--trace-payloadlen` (default 128) and
  `--trace-payloadlen-overlay`; `--monitor-aggregation` controls trace verbosity.
- **Datapath signals** over `cilium_signals` (CT/NAT fill-up, auth required)
  read by `pkg/signal`.
- **Struct alignment check at startup**: `bpf_alignchecker.c` compiled and its
  BTF compared against Go struct layouts (`alignchecker.CheckStructAlignments`).
- **REST**: `GET /map`, `GET /map/{name}`, `GET /map/{name}/events`
  (`pkg/maps/api.go`, `pkg/bpf/map_register_linux.go`).

## Data model

### Definition mechanics

Maps are BTF-defined (`__section(".maps")`, `__section_maps_btf`) using
`__uint/__type/__array` from `bpf/include/bpf/loader.h`. Pinning values:
`LIBBPF_PIN_BY_NAME = 1` (reuse `/sys/fs/bpf/tc/globals/<name>` if compatible)
and `CILIUM_PIN_REPLACE = 1<<4` (never reuse; create, populate, attach, then
overwrite the pin). Flag macros from `bpf/lib/map_defs.h`:
`CONDITIONAL_PREALLOC`, `LRU_MEM_FLAVOR`, `BPF_F_RDONLY_PROG_COND` (cleared
under `BPF_TEST`). `pkg/datapath/maps/maps_generated.go` is generated by dpgen
from the `.maps` BTF of the compiled objects and is the authoritative Go-side
catalogue (85 specs incl. inner maps); the sizes below come from it.

Common building blocks (`bpf/lib/common.h`, `ipv6_core.h`, `eth.h`):

- `union v6addr` 16 B (`addr[16]` | `p1..p4` u32 | `d1,d2` u64), `union v4addr` 4 B.
- `union macaddr` 8 B (`addr[6]` + pad), `mac_t` = u64.
- `struct bpf_lpm_trie_key { u32 prefixlen; }` 4 B header of every LPM key.
- `struct ipv4_ct_tuple` 14 B packed: `daddr be32, saddr be32, dport be16,
  sport be16, nexthdr u8, flags u8` (addresses are stored reversed).
- `struct ipv6_ct_tuple` 38 B packed: `daddr v6, saddr v6, dport, sport, nexthdr, flags`.
- `struct lpm_v4_key` 8 B (`lpm` + `addr[4]`), `lpm_v6_key` 20 B, `lpm_val` 1 B (`flags`).

### Catalogue

Abbreviations: DP = datapath programs, UA = userspace agent. "pin" is the
name under `/sys/fs/bpf/tc/globals/` unless stated. Sizes are ELF defaults
from `bpf/node_config.h` at build time; the runtime value is written into the
agent-generated `node_config.h` and/or applied through `MapRegistry` patches.

**Connection tracking (`bpf/lib/conntrack_map.h`, Go `pkg/maps/ctmap`)**

| Map | Type | Key | Value | Max | Flags | Writers | Notes |
|---|---|---|---|---|---|---|---|
| `cilium_ct4_global` | LRU_HASH | `ipv4_ct_tuple` 14 B | `ct_entry` 56 B | `CT_MAP_SIZE_TCP` (512Ki, `--bpf-ct-global-tcp-max`) | `LRU_MEM_FLAVOR` | DP creates/updates; UA GC (`ctmap/gc`) deletes | LRU: no explicit eviction needed |
| `cilium_ct_any4_global` | LRU_HASH | 14 B | 56 B | `CT_MAP_SIZE_ANY` (256Ki, `--bpf-ct-global-any-max`) | same | same | UDP/ICMP/SCTP |
| `cilium_ct6_global` | LRU_HASH | `ipv6_ct_tuple` 38 B | 56 B | TCP size | same | same | |
| `cilium_ct_any6_global` | LRU_HASH | 38 B | 56 B | ANY size | same | same | |
| `cilium_per_cluster_ct_{tcp4,any4,tcp6,any6}` | ARRAY_OF_MAPS | u32 cluster ID | u32 fd | 256 (`ClusterIDMax`) | — | UA creates inner LRU maps per remote cluster (`per_cluster_ctmap.go`) | inner: same key/value as global, `cilium_per_cluster_ct_*_inner` |

`struct ct_entry` (56 B, `bpf/lib/conntrack.h`): `union { v6addr nat_addr; struct
{u64 reserved0; u64 backend_id;} }` 16 B, `u64 packets`, `u64 bytes`, `u32
lifetime`, `u16` bitfield (`rx_closing, tx_closing, reserved1, lb_loopback,
seen_non_syn, node_port, proxy_redirect, dsr_internal, from_l7lb, reserved2,
from_tunnel, reserved3:5`), `u16 rev_nat_index`, `be16 nat_port`, `u8
tx_flags_seen`, `u8 rx_flags_seen`, `u32 src_sec_id` (offset fixed, read by
proxies), `u32 last_tx_report`, `u32 last_rx_report`. Lifetimes are compiled in
via `CT_CONNECTION_LIFETIME_TCP=21600`, `_NONTCP=60`, `CT_SERVICE_LIFETIME_*`,
`CT_SYN_TIMEOUT=60`, `CT_CLOSE_TIMEOUT=10`, `CT_REPORT_INTERVAL=5`.

**NAT (`bpf/lib/nat.h`, Go `pkg/maps/nat`, `pkg/maps/ipmasq`)**

| Map | Type | Key | Value | Max | Flags | Writers |
|---|---|---|---|---|---|---|
| `cilium_snat_v4_external` | LRU_HASH | `ipv4_ct_tuple` 14 B | `ipv4_nat_entry` 40 B | `SNAT_MAPPING_IPV4_SIZE` (`--bpf-nat-global-max`) | `LRU_MEM_FLAVOR` | DP; UA GC via ctmap |
| `cilium_snat_v6_external` | LRU_HASH | 38 B | `ipv6_nat_entry` 56 B | `SNAT_MAPPING_IPV6_SIZE` | same | DP |
| `cilium_snat_v4_alloc_retries` | PERCPU_ARRAY | u32 | u32 | `SNAT_COLLISION_RETRIES+1` = 33 | — | DP histogram of port-alloc retries; UA `nat/stats` reads |
| `cilium_snat_v6_alloc_retries` | PERCPU_ARRAY | u32 | u32 | 33 | — | not pinned in ELF (no `pinning`) |
| `cilium_per_cluster_snat_v{4,6}_external` | ARRAY_OF_MAPS | u32 | u32 | 256 | — | UA creates inner per cluster |
| `cilium_ipmasq_v4` | LPM_TRIE | `lpm_v4_key` 8 B | `lpm_val` 1 B | 16384 | `NO_PREALLOC \| RDONLY_PROG` | UA (ip-masq-agent) |
| `cilium_ipmasq_v6` | LPM_TRIE | `lpm_v6_key` 20 B | 1 B | 16384 | same | UA |

`struct nat_entry` (32 B): `u64 created, u64 needs_ct, u64 pad1, u64 pad2`.
`ipv4_nat_entry` = `nat_entry` + `union { lb4_reverse_nat nat_info; {be32 to_saddr; be16 to_sport}; {be32 to_daddr; be16 to_dport} }` → 40 B.
`ipv6_nat_entry` = `nat_entry` + `union { lb6_reverse_nat; {v6addr to_saddr; be16 to_sport}; ... }` → 56 B.

**Load balancer (`bpf/lib/lb.h`, `sock.h`, `lrp.h`, `act.h`; Go `pkg/loadbalancer/maps`, `pkg/maps/act`)**

| Map | Type | Key | Value | Max | Flags | Writers |
|---|---|---|---|---|---|---|
| `cilium_lb4_services_v2` | HASH | `lb4_key` 12 B | `lb4_service` 12 B | `CILIUM_LB_SERVICE_MAP_MAX_ENTRIES` 65536 | `CONDITIONAL_PREALLOC \| RDONLY_PROG` | UA LB reconciler |
| `cilium_lb6_services_v2` | HASH | `lb6_key` 24 B | `lb6_service` 12 B | 65536 | same | UA |
| `cilium_lb4_backends_v3` | HASH | u32 backend ID | `lb4_backend` 12 B | 65536 | `CONDITIONAL_PREALLOC` | UA |
| `cilium_lb6_backends_v3` | HASH | u32 | `lb6_backend` 24 B | 65536 | same | UA |
| `cilium_lb4_reverse_nat` | HASH | u16 rev_nat_index | `lb4_reverse_nat` 6 B packed (`be32 address, be16 port`) | 65536 | same | UA |
| `cilium_lb6_reverse_nat` | HASH | u16 | `lb6_reverse_nat` 18 B | 65536 | same | UA |
| `cilium_lb4_affinity` | LRU_HASH | `lb4_affinity_key` 16 B | `lb_affinity_val` 16 B (`u64 last_used, u32 backend_id, u32 pad`) | 65536 | `LRU_MEM_FLAVOR` | DP |
| `cilium_lb6_affinity` | LRU_HASH | `lb6_affinity_key` 24 B | 16 B | 65536 | same | DP |
| `cilium_lb_affinity_match` | HASH | `lb_affinity_match` 8 B (`u32 backend_id, u16 rev_nat_id, u16 pad`) | u8 | 65536 | `CONDITIONAL_PREALLOC \| RDONLY_PROG` | UA |
| `cilium_lb4_source_range` | LPM_TRIE | `lb4_src_range_key` 12 B (`lpm, u16 rev_nat_id, u16 pad, u32 addr`) | u8 | `LB4_SRC_RANGE_MAP_SIZE` 1000 | `NO_PREALLOC \| RDONLY_PROG` | UA |
| `cilium_lb6_source_range` | LPM_TRIE | 24 B | u8 | 1000 | same | UA |
| `cilium_lb4_health` / `lb6_health` | LRU_HASH | `__sock_cookie` u64 | `lb4_health` 12 B / `lb6_health` 24 B (= backend) | 65536 | `LRU_MEM_FLAVOR` | DP (health-check socket lookups) |
| `cilium_lb4_maglev` / `lb6_maglev` | HASH_OF_MAPS | u16 rev_nat_id | u32 inner fd | 65536 | `CONDITIONAL_PREALLOC \| RDONLY_PROG` | UA; inner `cilium_lb{4,6}_maglev_inner` ARRAY, key u32, value `u32[LB_MAGLEV_LUT_SIZE=32749]` = 130996 B, max 1 |
| `cilium_lb4_reverse_sk` | LRU_HASH | `ipv4_revnat_tuple` 16 B (`u64 cookie, be32 address, be16 port, u16 pad`) | `ipv4_revnat_entry` 8 B (`be32 address, be16 port, u16 rev_nat_index`) | `LB4_REVERSE_NAT_SK_MAP_SIZE` (`--bpf-sock-rev-map-max`) | `LRU_MEM_FLAVOR` | DP (`bpf_sock.c`); read by `bpf_sock_term.c` |
| `cilium_lb6_reverse_sk` | LRU_HASH | `ipv6_revnat_tuple` 32 B | `ipv6_revnat_entry` 20 B | same | same | DP |
| `cilium_skip_lb4` | HASH | `skip_lb4_key` 16 B (`u64 netns_cookie, u32 address, u16 port, u16 pad`) | u8 | `CILIUM_LB_SKIP_MAP_MAX_ENTRIES` 100 | `NO_PREALLOC \| RDONLY_PROG` | UA (local redirect policy) |
| `cilium_skip_lb6` | HASH | 32 B | u8 | 100 | same | UA |
| `cilium_lb_act` | LRU_HASH | `lb_act_key` 4 B (`u16 svc_id, u8 zone, u8 pad`) | `lb_act_value` 8 B (`u32 opened, u32 closed`) | 65536 (registry patch) | `LRU_MEM_FLAVOR` | DP; UA reads for active-connection metrics. Go also defines `cilium_lb_fct` which has no ELF counterpart |

Key layouts: `lb4_key` = `be32 address, be16 dport, u16 backend_slot, u8 proto,
u8 scope, u8 pad[2]`; `lb6_key` same with `v6addr`. `lb4_service` = `union {u32
backend_id; u32 affinity_timeout; u32 l7_lb_proxy_port}`, `u16 count, u16
rev_nat_index, u8 flags, u8 flags2, u16 qcount`. `lb4_backend` = `be32 address,
be16 port, u8 proto, u8 flags, u16 cluster_id, u8 zone, u8 pad`.
`lb4_affinity_key` = `union lb4_affinity_client_id {u32 client_ip; u64
client_cookie}` + `u16 rev_nat_id`, `u8 netns_cookie:1`, `u8 pad1`, `u32 pad2`.

**Policy (`bpf/lib/policy.h`, `local_delivery.h`; Go `pkg/maps/policymap`)**

| Map | Type | Key | Value | Max | Flags | Writers |
|---|---|---|---|---|---|---|
| `cilium_policy` → renamed `cilium_policy_v3_<EPID:05d>` | LPM_TRIE | `policy_key` 12 B | `policy_entry` 12 B | `POLICY_MAP_SIZE` 16384 (`--bpf-policy-map-max`) | `NO_PREALLOC \| RDONLY_PROG` | UA `pkg/endpoint` (per endpoint) |
| `cilium_policystats` | LRU_PERCPU_HASH | `policy_stats_key` 12 B | `policy_stats_value` 16 B (`u64 packets, u64 bytes`) | `POLICY_STATS_MAP_SIZE` 200 (runtime: sized by policy-map-max) | `BPF_F_NO_COMMON_LRU` | DP |
| `cilium_call_policy` | PROG_ARRAY | u32 endpoint ID | u32 prog fd | `POLICY_PROG_MAP_SIZE` = 65536 | — | loader inserts `cil_lxc_policy` / `cil_host_policy` at slot = EPID |
| `cilium_egresscall_policy` | PROG_ARRAY | u32 | u32 | 65536 | — | loader inserts `cil_lxc_policy_egress` |

`policy_key` = `lpm prefixlen u32, u32 sec_label, u8 egress:1/pad:7, u8 protocol,
be16 dport` (LPM over protocol+dport, `SinglePortPrefixLen=16`, `AllPorts=0`).
`policy_entry` = `be16 proxy_port, u8 deny:1/reserved:2/lpm_prefix_length:5, u8
auth_type:7/has_explicit_auth_type:1, u32 precedence, u32 cookie`.
`policy_stats_key` = `u16 endpoint_id, u8 pad1, u8 prefix_len, u32 sec_label, u8
egress:1, u8 protocol, be16 dport`. The `_v3_` name suffix encodes a layout/
semantic version; the ELF map is always `cilium_policy` and renamed at load.

**Endpoints, identities, nodes (`bpf/lib/eps.h`, `node.h`, `subnet.h`)**

| Map | Type | Key | Value | Max | Flags | Writers |
|---|---|---|---|---|---|---|
| `cilium_lxc` | HASH | `endpoint_key` 20 B packed (`union {v4addr; v6addr}`, `u8 family`, `u8 key`, `u16 cluster_id`) | `endpoint_info` 48 B | `ENDPOINTS_MAP_SIZE` 65536 (Go 65535) | `CONDITIONAL_PREALLOC \| RDONLY_PROG` | UA `lxcmap` |
| `cilium_ipcache_v2` | LPM_TRIE | `ipcache_key` 24 B packed (`lpm`, `u16 cluster_id`, `u8 pad1`, `u8 family`, `union {v4;v6}`) | `remote_endpoint_info` 24 B | `IPCACHE_MAP_SIZE` 512000 | `NO_PREALLOC \| RDONLY_PROG` | UA `pkg/datapath/ipcache` |
| `cilium_node_map_v2` | HASH | `node_key` 20 B (`u16 pad1, u8 pad2, u8 family, union {v4;v6}`) | `node_value` 4 B (`u16 id, u8 spi, u8 pad`) | `NODE_MAP_SIZE` 16384 | same | UA `nodemap` |
| `cilium_subnet_map` | LPM_TRIE | `subnet_key` 24 B packed | `subnet_value` 4 B (`u32 identity`) | `SUBNET_MAP_SIZE` 1024 | same | UA `subnet` (statedb reconciler via `bpf.NewMapOps`) |

`endpoint_info` = `u32 ifindex, u16 unused, u16 lxc_id, u32 flags, u32 rt_info,
mac_t mac, mac_t node_mac, u32 sec_id, u32 parent_ifindex, u32 pad[2]`.
`remote_endpoint_info` = `u32 sec_identity, union {v4;v6} tunnel_endpoint (16 B),
u16 pad, u8 key, u8 flag_skip_tunnel:1/flag_has_tunnel_ep:1/flag_ipv6_tunnel_ep:1/flag_remote_cluster:1`.

**Tail calls, config, telemetry**

| Map | Type | Key | Value | Max | Flags/Pinning | Writers |
|---|---|---|---|---|---|---|
| `cilium_calls` → renamed per object (see lifecycle) | PROG_ARRAY | u32 slot | prog | `CILIUM_CALL_SIZE` 50 | `CILIUM_PIN_REPLACE` | loader from `__declare_tail(N)` decl tags |
| `cilium_runtime_config` | ARRAY | u32 index | u64 | 256 | `RDONLY_PROG` | UA `configmap` (e.g. utime offset, agent liveness) |
| `cilium_metrics` | PERCPU_HASH | `metrics_key` 8 B (`u8 reason, u8 dir:2, u16 line, u8 file, u8 reserved[3]`) | `metrics_value` 16 B (`u64 count, u64 bytes`) | `METRICS_MAP_SIZE` 65536 (Go 1024) | `CONDITIONAL_PREALLOC` | DP; UA Prometheus collector |
| `cilium_events` | PERF_EVENT_ARRAY | u32 cpu | u32 fd | ELF 0 → Go sets `PossibleCPU()` | pin by name | DP `perf_event_output`; UA monitor agent |
| `cilium_signals` | PERF_EVENT_ARRAY | u32 | u32 | possible CPUs | pin by name | DP; UA `pkg/signal` |
| `cilium_percpu_trace_id` | PERCPU_ARRAY | u32 | u64 trace id | 1 | pin | DP (IP-option tracing) |
| `cilium_ratelimit` | LRU_HASH | `ratelimit_key` 8 B (`u32 usage, union {u32 netdev_idx}`) | `ratelimit_value` 16 B (`u64 last_topup, u64 tokens`) | 1024 | `LRU_MEM_FLAVOR` | DP (events + ICMPv6 rate limits) |
| `cilium_ratelimit_metrics` | HASH | `ratelimit_metrics_key` 4 B | `ratelimit_metrics_value` 8 B (`u64 dropped`) | 64 | `CONDITIONAL_PREALLOC` | DP; UA reads |
| `cilium_devices` | HASH | u32 ifindex | `device_state` 16 B (`macaddr mac, u8 l3:1, pads`) | 512 | `NO_PREALLOC` | UA `netdev` |
| `cilium_xdp_scratch` | PERCPU_ARRAY | int | `META_PIVOT` 28 B | 1 | pin | DP (XDP metadata staging) |
| `cilium_tail_call_buffer4` / `6`, `cilium_nodeport_nat_buffer` | PERCPU_ARRAY | u32 | `ct_buffer4/6`, `nodeport_nat_info` | 1 | **unpinned**, per object | DP scratch between tail calls (bpf_lxc.c, bpf_host.c) |

**Feature maps**

| Map | Type | Key | Value | Max | Flags | Writers |
|---|---|---|---|---|---|---|
| `cilium_auth_map` | HASH | `auth_key` 12 B (`u32 local_sec_label, u32 remote_sec_label, u16 remote_node_id, u8 auth_type, u8 pad`) | `auth_info` 8 B (`u64 expiration`) | 524288 (`--bpf-auth-map-max`, registry patch) | `NO_PREALLOC \| RDONLY_PROG` | UA auth manager |
| `cilium_throttle` | HASH | `edt_id` 8 B (`u32 id, u8 direction, u8 pad[3]`) | `edt_info` 56 B (`u64 bps, u64 t_last, union{t_horizon_drop;tokens}, u32 prio, u32 pad_32, u64 pad[3]`) | 65535 (registry patch `bwmap.MapSize`) | `NO_PREALLOC` | UA statedb `Edt` table via `NewMapOps`; DP updates `t_last`/`tokens` |
| `cilium_egress_gw_policy_v4` | LPM_TRIE | `egress_gw_policy_key` 12 B (`lpm, be32 saddr, be32 daddr`) | `egress_gw_policy_entry` 8 B (`egress_ip, gateway_ip`) | `EGRESS_POLICY_MAP_SIZE` 16384 | `NO_PREALLOC \| RDONLY_PROG` | UA (legacy v1 layout) |
| `cilium_egress_gw_policy_v4_v2` | LPM_TRIE | 12 B | `egress_gw_policy_entry_v2` 28 B (`egress_ip, gateway_ip, u32 reserved[3], u32 egress_ifindex, u32 reserved2`) | 16384 | same | UA |
| `cilium_egress_gw_policy_v6` | LPM_TRIE | `egress_gw_policy_key6` 36 B | `egress_gw_policy_entry6` 40 B | 16384 | same | UA |
| `cilium_encrypt_state` | ARRAY | u32 | `encrypt_config` 1 B (`u8 encrypt_key`) | 1 | `RDONLY_PROG` | UA IPsec key rotation |
| `cilium_l2_responder_v4` | HASH | `l2_responder_v4_key` 8 B (`v4addr ip4, u32 ifindex`) | `l2_responder_stats` 8 B (`u64 responses_sent`) | 4096 | `NO_PREALLOC` | UA inserts keys; DP bumps stats |
| `cilium_l2_responder_v6` | HASH | `l2_responder_v6_key` 24 B | 8 B | 4096 | same | same |
| `cilium_nodeport_neigh4` | LRU_HASH | be32 | `macaddr` 8 B | `NODEPORT_NEIGH4_SIZE` (`--bpf-neigh-global-max`) | `LRU_MEM_FLAVOR` | DP (learned next hops) |
| `cilium_nodeport_neigh6` | LRU_HASH | `v6addr` 16 B | 8 B | same | same | DP |
| `cilium_srv6_vrf_v4` / `v6` | LPM_TRIE | `srv6_vrf_key4` 12 B (`lpm, u32 src_ip, u32 dst_cidr`) / `key6` 36 B | u32 vrf id | 16384 | `NO_PREALLOC \| RDONLY_PROG` | UA srv6 manager |
| `cilium_srv6_policy_v4` / `v6` | LPM_TRIE | `srv6_policy_key4` 12 B (`lpm, u32 vrf_id, u32 dst_cidr`) / `key6` 24 B | `v6addr` SID 16 B | 16384 | same | UA |
| `cilium_srv6_sid` | HASH | `v6addr` SID | u32 vrf id | 16384 | same | UA |
| `cilium_vtep_map` | HASH | `vtep_key` 4 B (`u32 vtep_ip`) | `vtep_value` 16 B (`u64 vtep_mac, u32 tunnel_endpoint`) | `VTEP_MAP_SIZE` 8 | `CONDITIONAL_PREALLOC \| RDONLY_PROG` | UA |
| `cilium_ipv4_frag_datagrams` | LRU_HASH | `ipv4_frag_id` 12 B packed (`be32 daddr, be32 saddr, be16 id, u8 proto, u8 pad`) | `ipv4_frag_l4ports` 4 B | 8192 (`--bpf-fragments-map-max`) | `LRU_MEM_FLAVOR` | DP |
| `cilium_ipv6_frag_datagrams` | LRU_HASH | `ipv6_frag_id` 40 B packed | 4 B | 8192 | same | DP |
| `cilium_mcast_group_outer_v4_map` | HASH_OF_MAPS | `mcast_group_v4` be32 | u32 inner fd | `MCAST_MAX_GROUP` 1024 | `CONDITIONAL_PREALLOC` | UA; inner HASH `be32 saddr` → `mcast_subscriber_v4` 12 B (`saddr, ifindex, pad, flags`), 1024 entries |
| `cilium_cidr_v4_fix` / `v6_fix` | HASH | `lpm_v4_key` 8 B / `lpm_v6_key` 20 B | `lpm_val` | `CIDR4_HMAP_ELEMS` 1024 | `NO_PREALLOC \| RDONLY_PROG` | UA XDP prefilter (`cidrmap`), pinned as `cilium_cidr_*` |
| `cilium_cidr_v4_dyn` / `v6_dyn` | LPM_TRIE | same | same | `CIDR4_LMAP_ELEMS` 1024 | same | UA |

### Lifecycle, pinning and migration

1. **bpffs mount** (`pkg/bpf/bpffs_linux.go`): `CheckOrMountFS` mounts `bpf` at
   `/sys/fs/bpf` (or `/run/cilium/bpffs` fallback, or `--bpf-root`), refuses
   multiple mounts of the same root. Global pin dir `TCGlobalsPath()` =
   `<root>/tc/globals`; program/link pins under `CiliumPath()` = `<root>/cilium`.
2. **Agent-created maps** (`bpf.Map.OpenOrCreate` → `OpenOrCreateMap`,
   `pkg/bpf/bpf_linux.go`): `ebpf.NewMapWithOptions(spec{Pinning: PinByName},
   PinPath)`; on `ErrMapIncompatible` (type, key/value size, max_entries or
   flags differ) the old pin is **removed and the map recreated empty** — there
   is no content migration. Exception handled specially: `BPF_F_RDONLY_PROG`
   present in spec but absent on the pinned map → strip from spec and reuse;
   absent in spec but present on pinned map → unpin and recreate.
   `Map.Recreate()` forces the same. `GetMapMemoryFlags` adds memory flags per
   type.
3. **Loader-created maps** (`LoadCollection`, `pkg/bpf/collection.go`): maps
   with `LIBBPF_PIN_BY_NAME` are opened from `Maps.PinPath` by cilium/ebpf; on
   `ErrMapIncompatible` `incompatibleMaps()` clears their pin flag, the
   collection is loaded again with fresh unpinned maps, and after **all
   entrypoints are attached** `commit()` (`commitMapPins`) removes the stale pin
   and pins the new map. Maps flagged `CILIUM_PIN_REPLACE` (`cilium_calls`)
   always take this path: never reused, populated by `resolveTailCalls`, pin
   swapped post-attach. `MapReplacements` lets the agent hand in already-open
   `*bpf.Map`s (e.g. `sock.go` passes `cilium_lb{4,6}_reverse_sk`).
4. **Layout versioning by name**: a breaking key/value change renames the map
   (`cilium_ipcache_v2`, `cilium_node_map_v2`, `cilium_lb{4,6}_services_v2`,
   `cilium_lb{4,6}_backends_v3`, `cilium_egress_gw_policy_v4_v2`,
   `cilium_policy_v3_`). New and old coexist during upgrade; the previous name
   is left for removal by the agent's stale-map cleanup. `bpf/map.go`
   `commonNameRegexps` strips `_v[0-9]+`, `_reserved_N`, `_netdev_ns_N`,
   `_overlay_N`, `_N` suffixes for metrics grouping.
5. **Per-object renames at load** (`CollectionOptions.MapRenames`, applied by
   `renameMaps` before `ebpf.NewCollectionWithOptions`):
   - endpoint (`bpf_lxc.o`): `cilium_calls` → `cilium_calls_%05d` (EPID),
     `cilium_policy` → `cilium_policy_v3_%05d`;
   - `cilium_host` (`bpf_host.o`): `cilium_calls_hostns_%05d` (host EPID);
   - `cilium_net` and physical devices: `cilium_calls_netdev_%05d` (ifindex),
     policy map → host endpoint's `cilium_policy_v3_%05d`;
   - overlay: `cilium_calls_overlay_2` (`ReservedIdentityWorld`);
   - WireGuard: `cilium_calls_wireguard_<ifindex>`; XDP: `cilium_calls_xdp_<ifindex>`.
   `bpf.LocalMapName(prefix, id)` = `fmt.Sprintf("%s%05d")`.
6. **Per-endpoint teardown** (`loader.Unload`): remove legacy tc filters, then
   `/sys/fs/bpf/cilium/endpoints/<id>/links`, then the endpoint dir. Global
   maps are never unpinned by design. Disabling a feature removes its device
   dir and `cilium_calls_overlay*` / `cilium_calls_wireguard*` pins
   (`cleanCallsMaps`).
7. **`MapRegistry`** (`pkg/maps/registry`): built from `LoadMapSpecs()` at
   hive construction; cells call `Modify(name, func(*MapSpecPatch))` to set
   `MaxEntries`/`Flags` (incl. `InnerMap`) before start; after start it is
   immutable and `LoadCollection.patchMaps` applies the patches to the ELF
   spec so ELF and agent-created maps agree. Users: `authmap`, `bwmap`, `act`,
   `ctmap` (`NewMapFromRegistry`), `configmap`.

### Config mechanism end to end

There are three layers, all present at once:

1. **Compile-time headers** (features that change code shape):
   - `HeaderfileWriter.WriteNodeConfig` writes `<StateDir>/globals/node_config.h`
     (~115 `#define`s from `cDefinesMap`: `ENABLE_IPV4/6`, `ENABLE_NODEPORT`,
     `ENABLE_DSR`, `DSR_ENCAP_MODE`, `ENABLE_MASQUERADE_IPV4/6`,
     `ENABLE_SOCKET_LB_*`, `ENABLE_SRV6`, `ENABLE_VTEP`, `TUNNEL_MODE`,
     `ENCAP4_IFINDEX`, `IPV4_GATEWAY`, `HOST_NETNS_COOKIE`, `PREALLOCATE_MAPS`,
     `NO_COMMON_MEM_MAPS`, every `*_MAP_SIZE` / `*_MAX_ENTRIES`, `CT_*`
     lifetimes, `TRACE_SOCK_NOTIFY`, plus the generated `VLAN_FILTER(ifindex,
     vlan_id)` macro). Written atomically via `renameio`.
   - `WriteEndpointConfig` → per-template `ep_config.h`: `ENABLE_ROUTING`,
     `HOST_ENDPOINT`, `LOCAL_DELIVERY_METRICS`, then the endpoint option list
     (`DEBUG`, `DROP_NOTIFY`, `TRACE_NOTIFY`, `POLICY_VERDICT_NOTIFY`,
     `MONITOR_AGGREGATION`, ...) via `option.IntOptions.GetFmtList()`.
   - `netdev_config.h` (`DROP_NOTIFY`, `DEBUG`...) for `bpf_host`/`bpf_overlay`,
     `filter_config.h` for XDP prefilter CIDRs.
   - `bpf/node_config.h`, `bpf/ep_config.h` in the tree are the CI stand-ins.
   - Compile (`pkg/datapath/loader/compile.go`): `clang -O2 --target=bpf
     -std=gnu99 -nostdinc -g -ftrap-function=__undefined_trap -Wall -Wextra
     -Werror ... -mcpu=<v1|v2|v3 probed> -I<StateDir>/globals -I<ep state>
     -I<BpfDir> -I<BpfDir>/include -c bpf_lxc.c -o -` → `<templates>/<hash>/bpf_lxc.o`.
     Objects: `bpf_lxc`, `bpf_host`, `bpf_overlay`, `bpf_wireguard`, `bpf_xdp`,
     `bpf_sock`, `bpf_alignchecker`; `bpf_sock_term.c` and `bpf_probes.c` are
     precompiled with bpf2go into `pkg/datapath/bpf`.
   - **Template cache** (`cache.go`, `hash.go`): `baseHash =
     sha256(node_config.h)`; template hash = `sha256(baseHash ‖ template
     config)` where per-endpoint static values are replaced by dummies
     (`templateLxcID=65535`, `192.0.2.3`, `2001:db8:bad:cafe:600d:bee2:bad:cafe`,
     MAC `02:00:60:0d:f0:0d`, ifindex `MaxUint32`, netns cookie `MaxUint64`,
     verdict filter `0xffff`, identity `world`). Endpoint hash additionally
     includes the runtime constants (`hashEndpoint`) so a change in constants
     triggers a reload without recompilation. `UpdateDatapathHash` wipes the
     templates dir when node config changes.
2. **Load-time constants** (`bpf/lib/static_data.h`, `pkg/bpf/constants.go`,
   `pkg/datapath/config`): `DECLARE_CONFIG(type, name, "desc")` /
   `NODE_CONFIG(...)` emit `volatile const type __config_<name>` into
   `.rodata.config` with `btf_decl_tag("kind:object|node")` and a description
   tag; `ASSIGN_CONFIG` hard-codes a value. Access is only through `CONFIG(name)`,
   which forces an `r = <sym> ll` + deref on every use so the loader's
   reachability analysis can see the pattern. dpgen (`go:generate` in
   `pkg/datapath/config/gen.go`) reads the `.o` BTF and emits Go structs with
   `config:"<name>"` tags and `NewX()` constructors carrying ELF defaults:
   `Node` (embedded everywhere; e.g. `cluster_id`, `cluster_id_bits=8`,
   `enable_bpf_host_routing`, `hash_init4_seed`, `lb_default_alg`,
   `nodeport_port_min/max`, `router_ipv6`, `service_loopback_ipv4/6`,
   `supports_fib_lookup_skip_neigh/src`, `trace_payload_len`, `kernel_hz`,
   `events_map_rate_limit/burst_limit`...), `BPFLXC` (`endpoint_id`,
   `endpoint_ipv4/6`, `endpoint_netns_cookie`, `interface_ifindex`,
   `interface_mac`, `security_label`, `policy_verdict_log_filter`, `rt_info`,
   `host_ep_id`, `device_mtu`, `tunnel_port/protocol`, `nat_ipv4/6_masquerade`,
   `enable_*` toggles), `BPFHost`, `BPFXDP`, `BPFOverlay`, `BPFWireguard`,
   `BPFSock`. `applyConstants` → `config.Map(obj)` → `spec.Variables["__config_"+tag].Set(v)`,
   rejecting variables outside `.rodata.config`. Values are also dumped as
   JSON (`configDumpLayout{objects, variables}`) for sysdumps. Datapath plugins
   register extra config/rename providers via `funcRegistry`.
3. **Runtime map** `cilium_runtime_config` (u64 array) for values that change
   while programs run, plus `.data.aux` per-CPU variables (`DEFINE_AUX` /
   `AUX()`, `_aux_stride`, `_aux_max_off`; `modifyAuxData` pads the stride to
   the cache line and multiplies the map value by possible CPUs).

**Loader pipeline** (`LoadCollection`): copy spec → `patchMaps` (registry) →
`adjustMapFlagsForUpgrade` → `renameMaps` → `applyConstants` →
`computeReachability` (`analyze.MakeBlocks` + `Reachability` over
`spec.Variables`) → `removeUnusedTailcalls` (walks `tail_call_static` slots from
entrypoints) → `resolveTailCalls` (fills `cilium_calls.Contents` from
`tail:cilium_calls/N` decl tags; entrypoints are `__section("tc/entry")` /
`"xdp/entry"`, tails `"tc/tail"`) → `fixedResources` + `removeUnusedMaps`
(unreferenced map loads replaced by `poisonedMapLoad=0xdeadc0de`) →
`dumpConstants` → `modifyAuxData` → `consumePinReplace` → `patchPrograms`
(plugin instrumentation) → `ebpf.NewCollectionWithOptions` (retry on
incompatible pins) → return `commit()`. `LoadAndAssign` additionally does
`coll.Assign(&xxxObjects)` using `ebpf:"cil_from_container"`-style tags.
**No CO-RE relocations are used** by the tc/XDP datapath: it compiles against
uapi headers and `struct __sk_buff`/`xdp_md`; BTF is needed only for `.maps`,
decl tags, `Variables` and the alignchecker. `bpf_sock_term.c` is the exception
(kfunc `bpf_sock_destroy` via `.ksyms`, `iter/tcp`, `iter/udp`).

### Attach mechanics

- **tc SKB programs** (`tc.go`, `tcx.go`, `netkit.go`; `attachSKBProgram`):
  entrypoints `cil_from_container`/`cil_to_container` (endpoint veth/netkit
  ingress/egress), `cil_from_host`/`cil_to_host` (`cilium_host`; `cil_to_host`
  also on `cilium_net` ingress), `cil_from_netdev`/`cil_to_netdev` (physical
  devices), `cil_from_overlay`/`cil_to_overlay` (`cilium_vxlan`/`cilium_geneve`),
  `cil_from_wireguard`/`cil_to_wireguard` (`cilium_wg0`).
  - If `--enable-tcx` and the device is `netkit`: `link.AttachNetkit`
    (`AttachNetkitPeer` for ingress, `AttachNetkitPrimary` for egress),
    `Anchor: Tail`, link pinned at `<CiliumPath>/{endpoints/<id>|devices/<dev>}/links/<prog>`.
    Else tcx: `link.AttachTCX(AttachTCXIngress|Egress, Tail)`, same pin
    layout; on success legacy tc filters on that parent are removed.
  - Upgrade path: `bpf.UpdateLink(pin, prog)` (`BPF_LINK_UPDATE`) replaces the
    program atomically; `ENOLINK` means the link is defunct (device gone) →
    unpin and re-attach.
  - Legacy fallback: `replaceQdisc` (clsact, handle `ffff:`), `netlink.FilterReplace`
    of a `BpfFilter{Parent: HANDLE_MIN_INGRESS|EGRESS, Handle 1, ETH_P_ALL,
    Priority --bpf-filter-priority (default 1), Name "<prog>-<dev>", DirectAction}`;
    stale Cilium filters (`cil_` prefix) at other priorities are deleted;
    `detachGeneric` removes any tcx pin.
- **XDP** (`xdp.go`): `cil_xdp_entry` from `bpf_xdp.o`; mode from
  `xdp.Config` (`ModeLinkDriver` → `XDPDriverMode`, `ModeLinkGeneric` →
  `XDPGenericMode`, best-effort tolerates failure). `attachXDPProgram`: try
  `UpdateLink` on `<CiliumPath>/devices/<dev>/links/cil_xdp_entry`, else
  `link.AttachXDP` + pin, else (`EBUSY`/unsupported) `LinkSetXdpFdWithFlags`.
  `xdpPermutations` retries on `EINVAL` flipping `AttachType` (XDP vs none) and
  `BPF_F_XDP_HAS_FRAGS`. `maybeUnloadObsoleteXDPPrograms` detaches from devices
  no longer selected; `cilium_wg0` is skipped. `DetachXDP` handles both link
  and netlink attachments.
- **cgroup socket hooks** (`pkg/socketlb`, `bpf_sock.c`): programs
  `cil_sock4_connect` (`cgroup/connect4`), `_post_bind` (`cgroup/post_bind4`),
  `_pre_bind` (`cgroup/bind4`), `_sendmsg`, `_recvmsg`, `_getpeername`, the v6
  set, and `cil_sock_release` (`AttachCgroupInetSockRelease`). Attach:
  `link.AttachRawLink{Target: cgroup root fd}` pinned at
  `/sys/fs/bpf/cilium/socketlb/links/cgroup/<prog>`; upgrades via `UpdateLink`;
  fallback `PROG_ATTACH` without flags (and `PROG_DETACH`) for kernels without
  cgroup links or when an older agent attached that way.
- **Socket termination** (`bpf_sock_term.c`, `pkg/datapath/sockets`):
  `iter/tcp` + `iter/udp` programs `cil_sock_{udp,tcp}_destroy_v{4,6}` attached
  with `link.AttachIter`; filter set through variable `cilium_sock_term_filter`;
  reverse-sk maps injected via `MapReplacements`.
- **Ordering guarantees** (`reloadEndpoint`): (1) load collection; (2) insert
  `cil_lxc_policy` / `cil_lxc_policy_egress` into `cilium_call_policy` /
  `cilium_egresscall_policy` at slot EPID (this is "attachment" from
  bpf_host's point of view); (3) attach ingress, then egress if
  `RequireEgressProg`; (4) `commit()` pin swaps; (5) endpoint routes. For
  `bpf_host`: `cilium_host` (to/from), `cilium_net` (to_host), then every
  selected device (from/to_netdev). `LoadCollection` doc: when one ELF is
  attached at several hooks, commit only after all are attached, otherwise
  missing tail calls occur.
- **Program identification**: names/filters prefixed `cil_` are treated as
  Cilium's (`isCiliumFilter`, `hasCiliumTCXLinks`, `hasCiliumNetkitLinks`).

### Monitor / Hubble event channel

- Transport: `cilium_events` PERF_EVENT_ARRAY, one ring per possible CPU;
  `perf.NewReader(map, pagesize*npages)` in `pkg/monitor/agent` (`AttachToEventsMap(nPages)`).
  Records go to listeners as `payload.Payload{Data, CPU, Lost, Type}` with
  `Type` = `EventSample (9)` or `RecordLost (2)`; gob-encoded behind a
  `Meta{Size}` header on `/var/run/cilium/monitor1_2.sock`. `LostSamples`
  increments `MonitorStatus.Lost` and emits a lost record.
- Message types (`pkg/monitor/api/types.go`, `bpf/lib/notify.h`): 0 unspec,
  1 drop, 2 debug, 3 debug-capture, 4 trace, 5 policy-verdict, 6 capture
  (recorder; enum present, no emitter left in the tree), 7 trace-sock,
  129 access-log (L7, agent-generated), 130 agent.
- Headers: `NOTIFY_COMMON_HDR` 8 B = `u8 type, u8 subtype, u16 source, u32 hash`
  (`EVENT_SOURCE` = `LXC_ID` in bpf_lxc, `CONFIG(host_ep_id)` in bpf_host, 0
  elsewhere; `hash = get_hash(ctx)`). `NOTIFY_CAPTURE_HDR` 16 B adds
  `u32 len_orig, u16 len_cap, u8 version, u8 ext_version`; captured packet bytes
  (`len_cap`, up to `CONFIG(trace_payload_len)`, default 128) follow the struct.
- `struct trace_notify` (v2, 56 B; v0 32 B, v1 48 B): capture hdr, `u32
  src_label, u32 dst_label, u16 dst_id, u8 reason, u8 flags, u32 ifindex,
  union {v4addr orig_ip4; v6addr orig_ip6} (16 B), u64 ip_trace_id`. `subtype` =
  observation point (`TRACE_TO_LXC, TO_PROXY, TO_HOST, TO_STACK, TO_OVERLAY,
  FROM_LXC, FROM_PROXY, FROM_HOST, FROM_STACK, FROM_OVERLAY, FROM_NETWORK,
  TO_NETWORK, FROM_CRYPTO, TO_CRYPTO`). `reason` = `TRACE_REASON_POLICY(=CT_NEW),
  CT_ESTABLISHED, CT_REPLY, CT_RELATED, RESERVED, UNKNOWN, SRV6_ENCAP,
  SRV6_DECAP, RESERVED_2` with `TRACE_REASON_ENCRYPTED = 0x80` as a mask.
  `flags` bit0 = IPv6.
- `struct drop_notify` (v3, 48 B; v1 36, v2 40): capture hdr, `u32 src_label,
  u32 dst_label, u32 dst_id, u16 line, u8 file, s8 ext_error, u32 ifindex, u8
  flags, u8 pad2[3], u64 ip_trace_id`; `subtype` = drop reason (`drop_reasons.h`).
- `struct debug_msg` 20 B: common hdr + `u32 arg1, arg2, arg3`; `subtype` = `DBG_*`.
- `struct debug_capture_msg` 24 B: capture hdr + `u32 arg1, arg2`.
- `struct policy_verdict_notify` 40 B: capture hdr, `u32 remote_label, s32
  verdict, u16 dst_port, u8 proto, u8 dir:2/ipv6:1/match_type:3/audited:1/l3:1,
  u8 auth_type, u8 pad1[3], u32 cookie, u32 pad2`.
- `struct trace_sock_notify` 40 B: `u8 type, u8 xlate_point, u8 l4_proto, u8
  ipv6:1/pad:7, u16 dst_port, u16 pad2, u64 sock_cookie, u64 cgroup_id, struct
  ip dst_ip (16 B)`.
- Go mirrors in `pkg/monitor/datapath_*.go` carry `align:"<cfield>"` tags
  checked by the alignchecker; decoders accept per-version lengths
  (`traceNotifyLength`, `dropNotifyLengthFromVersion`) plus `ext_version`
  extension lengths (all extensions are empty in 1.20).
- `cilium_signals`: same perf mechanism (`perf.NewReader(map, pagesize)`), read
  by `pkg/signal` for `SIGNAL_NAT_FILL_UP`, `SIGNAL_CT_FILL_UP`, `SIGNAL_AUTH_REQUIRED`.
- Rate limiting: `NODE_CONFIG(events_map_rate_limit/burst_limit)` with a token
  bucket in `cilium_ratelimit` (`bpf/lib/ratelimit.h`).

### Persisted files

- `/sys/fs/bpf/tc/globals/*` maps; `/sys/fs/bpf/cilium/{devices/<dev-with-dots-replaced>/links,
  devices/<dev>/plugins/{tc,xdp}, endpoints/<id>/{links,plugin_pins},
  socketlb/{links,plugin_links}/cgroup, plugins/<plugin>/<op-id>}`.
- `/var/run/cilium/state/globals/node_config.h`, `<state>/templates/<sha256>/{ep_config.h,bpf_lxc.o|bpf_host.o}`,
  `<state>/<epid>/{ep_config.h,bpf_lxc.json}`, `<state>/bpf/<dev>/{bpf_host.json,bpf_xdp.json,bpf_overlay.json,bpf_wireguard.json}`,
  `<state>/netdev_config.h`, `<state>/filter_config.h`, `<state>/bpf_sock.o`, `<state>/bpf_alignchecker.o`.

## External interfaces

- REST (`api/v1` daemon): `GET /map` (all registered maps → `models.BPFMap`),
  `GET /map/{name}` (dump via `MapKey/MapValue.String()`), `GET /map/{name}/events?follow=`
  (streams `bpf.Event{Timestamp, action, cacheEntry{Key, Value, DesiredAction, LastError}}`).
- Monitor unix socket `/var/run/cilium/monitor1_2.sock` (gob `Meta`+`Payload`).
- bpffs layout above (also consumed by `cilium-dbg bpf ...` and by `bpftool`).
- Config dump JSON (`{"objects":[{"name":"config.BPFLXC","values":{...}}],"variables":{"__config_x":"base64"}}`).
- Netlink objects created (`netlink.go`): veth pair `cilium_host`/`cilium_net`
  (random MACs, `txqlen 1000`, ARP off, MTU set, `/32`+`/128` internal IPs on
  `cilium_host`), `cilium_vxlan` or `cilium_geneve` (port, src-port range,
  GSO/GRO), `cilium_ipip4/6` when enabled, clsact qdiscs, legacy tc filters,
  `ip rule` for ENI (`RulePriorityNodeport`, mark `MarkMultinodeNodeport`),
  per-endpoint `/32` routes when `RequireEndpointRoute`.
- sysctls (`Reinitialize`, `enableForwarding`): `net.core.bpf_jit_enable=1`,
  `net.ipv4.conf.all.rp_filter=0`, `net.ipv4.fib_multipath_use_neigh=1`,
  `kernel.unprivileged_bpf_disabled=1`, `kernel.timer_migration=0`,
  `net.ipv6.conf.all.disable_ipv6=0`, per-device `forwarding=1`, `rp_filter=0`,
  `accept_local=1`, `send_redirects=0`, `net.core.fb_tunnels_only_for_init_net=2`
  (IPIP), ENI `rp_filter=2` on the default-route device.
- skb mark encoding (`bpf/lib/common.h`): `MARK_MAGIC_*` in bits 8-15
  (`HOST 0x0C00`, `PROXY_INGRESS 0x0A00`, `PROXY_EGRESS 0x0B00`, `IDENTITY
  0x0F00`, `TO_PROXY 0x0200`, `SNAT_DONE 0x0300`, `OVERLAY 0x0400`, `EGW_DONE
  0x0500`, `DECRYPT 0x0D00`, `ENCRYPT 0x0E00`, `CLUSTER_ID = TO_PROXY`), mask
  `MARK_MAGIC_KEY_MASK 0xFF00`.

## Dependencies

- Inventory areas: datapath programs (bpf_lxc/host/overlay/xdp/sock — the
  readers of every map), policy (writes policy maps), ipcache/identity, LB
  (`pkg/loadbalancer`), CT GC, node manager, clustermesh (per-cluster maps),
  encryption (IPsec/WireGuard), egress gateway, SRv6, multicast, L2
  announcements, bandwidth manager (statedb `Edt`), Hubble (consumer of
  monitor payloads), datapath plugins.
- Libraries: `github.com/cilium/ebpf` (ELF parsing, BTF, `CollectionSpec`,
  `Variables`, `link` for tcx/netkit/xdp/cgroup/iter, `perf`, batch ops,
  bpf2go), `github.com/vishvananda/netlink`, `cilium/hive` + `statedb`
  (`reconciler.Operations` via `bpf.NewMapOps`).
- Kernel helpers used by the C side (declared through `BPF_FUNC(...)` in
  `bpf/include/bpf/helpers*.h`, 45 total): `map_lookup_elem`,
  `map_update_elem`, `map_delete_elem`, `map_lookup_percpu_elem`,
  `for_each_map_elem`, `loop`, `tail_call`, `redirect`, `redirect_neigh`,
  `redirect_peer`, `clone_redirect`, `fib_lookup`, `csum_diff`,
  `l3_csum_replace`, `l4_csum_replace`, `skb_load_bytes`, `skb_store_bytes`,
  `skb_pull_data`, `skb_change_type`, `skb_change_proto`, `skb_change_head`,
  `skb_change_tail`, `skb_adjust_room`, `skb_get/set_tunnel_key`,
  `skb_get/set_tunnel_opt`, `get_hash_recalc`, `get_socket_cookie`,
  `get_netns_cookie`, `sk_lookup_tcp`, `sk_lookup_udp`, `skc_lookup_tcp`,
  `sk_release`, `sk_assign`, `set_retval`, `getsockopt`, `setsockopt`,
  `perf_event_output`, `ringbuf_reserve/submit/discard`, `trace_printk`,
  `xdp_adjust_head`, `xdp_adjust_meta`, `xdp_adjust_tail`, `xdp_get_buff_len`,
  `xdp_load_bytes`, `xdp_store_bytes`; kfunc `bpf_sock_destroy`.

## Kernel / platform requirements

- Documented minimum: Linux ≥ 5.10 (or RHEL 8.10's 4.18 backport).
- Map types: `HASH`, `LRU_HASH`, `LRU_PERCPU_HASH`, `PERCPU_HASH`, `ARRAY`,
  `PERCPU_ARRAY`, `PROG_ARRAY`, `PERF_EVENT_ARRAY`, `LPM_TRIE`,
  `ARRAY_OF_MAPS`, `HASH_OF_MAPS`. Flags `BPF_F_NO_PREALLOC`,
  `BPF_F_NO_COMMON_LRU`, `BPF_F_RDONLY_PROG` (≥ 5.2), `BPF_F_XDP_HAS_FRAGS`
  (≥ 5.18, probed by retry). Batch lookup/delete (≥ 5.6) used by
  `Map.BatchLookup`/`BatchIterator` for CT/NAT dumps.
- Program types: `SCHED_CLS` (tc/tcx/netkit), `XDP`, `CGROUP_SOCK_ADDR`,
  `CGROUP_SOCK`, `TRACING`/`iter`, `EXT` (freplace, plugins only).
- Links: XDP `bpf_link` (≥ 5.7), cgroup links (≥ 5.7), tcx (≥ 6.6), netkit
  (≥ 6.7), `BPF_LINK_UPDATE`, `bpf_iter` for tcp/udp (≥ 5.9) plus
  `bpf_sock_destroy` kfunc (≥ 6.5).
- Probed at start (`pkg/datapath/linux/probes`): ISA v2/v3 (`-mcpu`),
  `BPF_FIB_LOOKUP_SKIP_NEIGH` (≥ 6.3), `BPF_FIB_LOOKUP_SRC` (≥ 6.7), large
  instruction limit, `bpf_probes.c` feature probes.
- Arch: `.data.aux` stride uses Go `cpu.CacheLinePad` (64 B on amd64, 128 B
  on arm64 in Go's definition) — the C side reads `_aux_stride` so it is
  consistent, but Rust must compute the same value per target. All map
  key/value structs are little-endian-agnostic C layouts; network fields are
  `__be16/__be32`. XDP native mode needs driver support; generic mode works on
  veth/virtio; MikroTik/ARM64 targets fall under generic unless the NIC driver
  supports XDP.

## Tests

- `pkg/bpf`: 15 test files, 4 privileged (`map_linux_test.go` open/create/
  recreate/dump/batch, `ops_linux_test.go` reconciler ops, `collection_test.go`
  load + constants, `unused_maps_test.go`/`unused_tailcalls_test.go` pruning
  against `testdata` ELFs, `constants_test.go` variable patching).
- `pkg/maps`: 28 test files, 16 privileged (ctmap GC and per-cluster maps, NAT
  batch dump/flush, policymap key encoding, egressmap, lxcmap, srv6, multicast
  inner maps, ratelimit, l2responder, nodemap, bwmap, act).
- `pkg/datapath/loader`: 14 test files, 8 privileged (`tc_test.go`,
  `tcx_test.go`, `netdev_test.go`, `netlink_test.go`, `xdp_test.go`,
  `loader_test.go` end-to-end template compile + attach in a netns,
  `verifier_load_test.go`), plus `compile_test.go`, `template_test.go`,
  `hash_test.go`, `cache_test.go`, `plugins_test.go`.
- `pkg/datapath/config/unmarshal_test.go` (struct → variable map),
  `pkg/datapath/maps/maps_generated_test.go` (catalogue loads),
  `pkg/datapath/tables` (node address, direct routing device).
- BPF unit tests: `bpf/tests/*.c` (141 files) run by `bpf/tests/bpftest`
  (Go: loads each `.o`, runs `pktgen`/`setup`/`check` programs through
  `BPF_PROG_RUN` (`ebpf.RunOptions`), collects a result map, optional coverage
  via `gocovmerge`/`trf.proto`, scapy-based assertions). Covers CT, NAT, LB,
  DSR, masquerade, encryption, fragmentation, drop notify, jhash, IPv6 NDP.
- Verifier/complexity: `TestPrivilegedVerifier` compiles every object under
  `bpf/complexity-tests/{510,61,netnext}` option permutations and loads them,
  recording verifier complexity (`.github/workflows/tests-datapath-verifier.yaml`).
  `lint-bpf-checks.yaml` runs clang-format/checkpatch/coccinelle-style checks.
- Startup self-check: `bpf_alignchecker.o` vs Go `align:` tags.

## Rust mapping

Candidate crates: **aya** + **aya-obj** (pure Rust, no libbpf/libelf, static
musl-friendly, fits the scratch-image and `cross` ARM64 build rules), with
`rtnetlink`/`netlink-packet-route` for devices/qdiscs/filters, `zerocopy` or
`bytemuck` for `#[repr(C)]` key/value structs, and a `build.rs` step that
reads the compiled objects' BTF (via `aya-obj::btf`) to generate the map
catalogue and constant structs (the dpgen equivalent). `libbpf-rs` is the
fallback where aya has gaps, but it drags in libbpf/libelf/zlib C code.

Assessment against each requirement:

| Requirement | aya status | Gap / how to fill |
|---|---|---|
| HASH, LRU_HASH, PERCPU_HASH, LRU_PERCPU_HASH, ARRAY, PERCPU_ARRAY | supported (`HashMap`, `LruHashMap`, `PerCpuHashMap`, `LruPerCpuHashMap`, `Array`, `PerCpuArray`) | per-CPU values via `PerCpuValues`; fine |
| LPM_TRIE | supported (`LpmTrie<K,V>` with `Key{prefix_len, data}`) | key struct must be `#[repr(C)]` with the u32 prefixlen first; Cilium's packed keys (`ipcache_key`, `subnet_key`) need `repr(C, packed)` |
| PROG_ARRAY | supported (`ProgramArray::set(idx, &prog)`) | populate from decl tags ourselves |
| PERF_EVENT_ARRAY | supported (`PerfEventArray`/`AsyncPerfEventArray`, per-CPU `open(cpu, page_count)`, lost-sample counts) | matches `cilium_events` usage; ringbuf also available if we ever switch |
| ARRAY_OF_MAPS / HASH_OF_MAPS (maglev, per-cluster CT/NAT, multicast) | **gap**: aya has no outer-map API and aya-obj does not create inner maps from `__array(values, ...)` BTF | implement with raw `bpf(BPF_MAP_CREATE)` passing `inner_map_fd`, and outer updates with fd values; ~300 lines |
| `BPF_F_RDONLY_PROG`, `NO_PREALLOC`, `NO_COMMON_LRU` | flags pass through `MapData::create` | need the upgrade/downgrade flag reconciliation logic ourselves |
| Batch lookup/delete (CT/NAT dumps and GC) | **gap**: no `BPF_MAP_LOOKUP_BATCH` wrappers in aya | raw syscall wrappers with cursor; ~200 lines; libbpf-rs has them if needed |
| Pin by name, reuse-if-compatible, pin swap after attach | partial: aya-obj honours `pinning` in BTF map defs and `EbpfLoader::map_pin_path`; `MapData::pin`, `PinnedLink` exist | compatibility check (type/key/value/max/flags vs `bpf_obj_get_info_by_fd`) and the `PIN_REPLACE` commit protocol must be written; `CILIUM_PIN_REPLACE=16` is not a libbpf value, strip it before aya sees it |
| Map renames before load | not an API, but `aya_obj::Object.maps` is mutable | rename in the parsed object before `EbpfLoader`; small |
| `.rodata.config` global patching | supported (`EbpfLoader::set_global(name, &value, must_exist)`) | verify it accepts symbols in `.rodata.config` (aya matches sections by `rodata` prefix); values must be `Pod` |
| Reading BTF decl tags (`kind:`, description, `tail:cilium_calls/N`) | aya-obj parses `BTF_KIND_DECL_TAG` but exposes no query API | walk `Btf` types ourselves in build.rs and at load; ~200 lines |
| Reachability-based dead-code elimination (unused tail calls/maps) | **gap**: nothing equivalent | either port `pkg/bpf/analyze` (~1.2k Go lines → ~1.5k Rust over aya-obj's instruction slices) or drop it and pay in verifier complexity / extra map FDs; ELF-per-feature-set compile makes it less critical |
| Tail-call resolution from decl tags | gap (aya only handles BTF-defined `.maps`) | populate `ProgramArray` after load; trivial once tags are read |
| CO-RE | supported in aya-obj (field/type/enum relocations) | not needed for the tc/XDP datapath; needed only if we keep `bpf_sock_term.c` (kfunc + iter) |
| kfuncs (`bpf_sock_destroy`), `iter/tcp|udp` | partial: aya has `Iter` programs; kfunc/ksym relocation support is recent and lightly used | validate on the target kernel; otherwise delegate socket termination to libbpf-rs or drop the feature initially |
| Legacy tc clsact attach/replace | supported (`SchedClassifier::attach(iface, TcAttachType)`, `qdisc_add_clsact`, priority/handle options) | stale-filter cleanup by name needs `rtnetlink` filter listing |
| tcx (`BPF_LINK_TYPE_TCX`) | supported since aya 0.13 (`TcAttachOptions::TcxOrder`, `LinkOrder::last()`) | verify pin + `BPF_LINK_UPDATE` availability |
| netkit | **gap** | raw `bpf_link_create` with `BPF_NETKIT_PRIMARY/PEER` + netkit link creation via `rtnetlink` (`IFLA_NETKIT_*`); ~400 lines |
| XDP driver/generic/frags, link vs netlink attach | supported (`Xdp::attach` with `XdpFlags`, `XdpLink` pin) | `BPF_F_XDP_HAS_FRAGS` needs `ProgramSpec` flag setting — check aya-obj exposes `prog_flags`; netlink fallback via `rtnetlink` |
| `BPF_LINK_UPDATE` on pinned links (atomic upgrade) | **gap** in aya's public API | one syscall wrapper; libbpf-rs has `Link::update_prog` |
| cgroup sock_addr / sock hooks | supported (`CgroupSockAddr`, `CgroupSock`, `CgroupAttachMode`, link pinning) | `PROG_ATTACH` fallback for old kernels probably unnecessary on our targets |
| Perf reader, lost samples | supported | decoding structs must mirror C layouts exactly (versioned lengths) |
| clang at runtime + include dirs | `std::process::Command` | design choice, see open questions |

Obvious structure:

- `flowsdn-bpf-abi` crate: `#[repr(C)]` key/value/notification structs, one
  module per C header, with a test that loads the reference `.o` BTF and
  asserts `size_of`/offsets (replaces `bpf_alignchecker`). Generated from BTF
  in `build.rs` where possible, hand-written where unions/bitfields need
  ergonomics (`ct_entry` bitfield u16, `policy_entry`, `remote_endpoint_info`).
- `flowsdn-bpf-maps` crate: typed wrappers per map (open-or-create, pin
  policy, registry patches, cache/error-resolver, pressure metric, event ring,
  batch iteration), a `MapCatalogue` mirroring `maps_generated.go`.
- `flowsdn-bpf-loader` crate: object cache, constants application, renames,
  tail-call resolution, optional reachability pruning, pin commit protocol,
  attach backends (`tc`, `tcx`, `netkit`, `xdp`, `cgroup`, `iter`), device
  setup (`rtnetlink`), sysctl table.
- `flowsdn-monitor` crate: perf reader + versioned decoders for the seven
  message types + payload framing.

Risks and hard parts: exact byte compatibility of 60+ structs (packed unions,
bitfields, `__align_stack_8`); the pin-swap/commit ordering that makes
upgrades hitless; reachability pruning is intricate and its absence changes
verifier behaviour; map-in-map and netkit are outside aya's surface; runtime
clang dependency conflicts with a scratch image (clang+LLVM is hundreds of MB
and Cilium's own image ships it) — the alternative is compile-time
permutations plus `.rodata.config` patching, which is what the constants
mechanism was built to enable, but the header-driven `#ifdef` layer (~115
defines) is still compile-time today.

## Recommendation

**keep** the map catalogue and ABI (byte-for-byte; interoperability with
`cilium-dbg`/`bpftool` dumps and with Hubble decoders is worth more than a
cleaner layout), **keep** the loader design (constants in `.rodata.config`,
per-object renames, pin-replace commit protocol, link-update upgrades,
tcx/netkit/XDP/cgroup attach), **replace** the implementation with aya plus
raw-syscall shims for map-in-map, batch ops, `BPF_LINK_UPDATE` and netkit.
**defer** datapath plugins (freplace instrumentation, 1.1k lines), the
`cilium_lb_fct` dead Go map, legacy `cilium_egress_gw_policy_v4` (v1) and the
XDP prefilter `cidr_*` maps until the corresponding features are inventoried.
Decide early whether to ship clang; if not, treat the `#define` layer as a
fixed set of build-time profiles and move remaining toggles to `DECLARE_CONFIG`.

Effort: **L** (8-20k lines Rust): ABI structs + BTF alignment tests ~3k, map
wrappers + registry + GC-facing batch iteration ~3.5k, loader core (constants,
renames, tail calls, pinning, pruning) ~3.5k, attach + netlink devices +
sysctls ~2.5k, monitor decode ~1.5k, tests ~3k.

## Open questions

- Ship clang in the node image (Cilium does) or precompile a fixed set of
  header profiles and rely solely on `.rodata.config` patching? The latter
  needs an audit of which `cDefinesMap` entries actually change code shape
  versus values that could become `DECLARE_CONFIG`.
- Is reachability-based pruning required to pass the verifier on 5.10-class
  kernels for the full bpf_host/bpf_lxc objects, or only an optimisation?
  Answer by loading unpruned objects under `TestPrivilegedVerifier` permutations.
- Keep the `/sys/fs/bpf/tc/globals` + `/sys/fs/bpf/cilium` layout and
  `cilium_*` names verbatim (enables `cilium-dbg bpf` tooling and in-place
  takeover of a running Cilium node) or use a `flowsdn_*` namespace?
- aya specifics to verify on the target kernel/toolchain: `set_global` on
  `.rodata.config`, `prog_flags` for `BPF_F_XDP_HAS_FRAGS`, kfunc relocation
  for `bpf_sock_destroy`, tcx link pinning and update.
- `.data.aux` stride: Go uses `cpu.CacheLinePad` (128 B on arm64); confirm the
  C side has no hidden assumption so Rust can pick the real cache line size.
- Which maps need the value cache + error resolver in Rust (Cilium enables it
  on lxc, ipcache, ipmasq, encrypt, vtep, NAT, egress) versus statedb-style
  reconciliation (`bpf.NewMapOps`: bwmap, subnet)? Prefer one model.
- Per-cluster CT/NAT array-of-maps and multicast hash-of-maps: in scope for
  the first release, or deferred with clustermesh/multicast?
- Stale-map cleanup after a versioned rename (`_v2`/`_v3`) lives outside this
  area (`pkg/datapath/linux` startup); confirm during the datapath-init inventory.
