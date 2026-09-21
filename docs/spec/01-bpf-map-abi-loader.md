# BPF map ABI and loader — specification

Status: draft. Derived from: `docs/inventory/02-bpf-maps-loader.md`,
`docs/inventory/01-bpf-programs.md` (config variables, tail-call slots, mark
layout), `docs/inventory/09-hubble-monitor.md` (perf framing),
`docs/inventory/11-l7-proxy-dns-auth-mesh.md` (Envoy reads the ipcache map),
`docs/inventory/03-datapath-userspace-node.md` (cgroup root, mapsweeper,
netkit deferral). Reference cilium v1.20.1 (7d68cfb394) paths: `bpf/lib/*.h`
(map and notification layouts), `bpf/include/bpf/{loader.h,section.h,ctx/xdp.h}`,
`bpf/node_config.h`, `bpf/lib/{tailcall,static_data,auxvars,map_defs}.h`,
`pkg/datapath/maps/maps_generated.go`, `pkg/bpf/{collection,pinning,bpf_linux,
map_linux,constants,reachability,unused_maps,unused_tailcalls,bpffs_linux}.go`,
`pkg/bpf/analyze`, `pkg/datapath/loader/{tc,tcx,netkit,xdp,endpoint,host,
overlay,wireguard,paths,template}.go`, `pkg/socketlb/{socketlb,cgroup}.go`,
`pkg/datapath/mapsweeper/map.go`, `pkg/datapath/alignchecker/alignchecker.go`,
`pkg/datapath/config/*_config.go`, `pkg/monitor/{datapath_*.go,payload}`,
`pkg/maps/{policymap,callsmap,ipcache,registry}`, `pkg/option/config.go`,
`pkg/defaults/defaults.go`, `pkg/envoy/model.go`. Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. Where the reference
behavior is kept for compatibility, the consumer that depends on it is named.
Where flowsdn deviates, the item is marked **DEVIATION** with the reason.

Every "confirm" left open by inventory 02 is resolved in this document and
marked **CONFIRMED** at the point where it is settled.

## 1. Scope

In scope:

- The set of pinned BPF maps: names, pin paths, types, flags, key/value layouts
  as exact `#[repr(C)]` structures with offsets, default sizes and the
  configuration keys that size them (§2, §4).
- Map lifecycle: bpffs mount, create-or-open, pin, compatibility check,
  versioned rename, stale-map cleanup, what survives an agent restart (§3.1–3.4).
- The loader: object preparation (map renames, `.rodata.config` patching,
  registry size/flag patches, tail-call population, reachability pruning,
  `.data.aux` sizing), the pin-replace commit protocol, rollback (§3.5–3.8, §5).
- Attach mechanics per hook: tcx, legacy-filter cleanup, netkit, XDP, cgroup socket
  programs, socket iterators, and the `BPF_LINK_UPDATE` upgrade path (§3.9).
- The monitor and signal perf-event channels: map names, per-CPU sizing,
  payload framing and the fixed notification layouts (§3.10, §4.6).
- Userspace map access semantics: batch ops, iteration under concurrent
  modification, LRU eviction as seen by GC, per-CPU aggregation (§3.11, §5).
- Kernel requirements for everything above (§10), test plan (§9), Rust crate
  design and aya gaps (§11).

Out of scope (sibling specs):

- What the datapath programs *do* with the maps: `02-datapath-programs.md`.
- Identity numbering, ipcache population policy: `03-identity-ipcache.md`.
- CT/NAT entry semantics, timeouts and GC policy: `04-conntrack-nat.md`
  (this spec covers only the map layout and the GC-facing access primitives).
- Service LB map population, Maglev table computation: the load-balancer spec.
- Policy map population and the policy engine: the policy spec.
- Config-key registry and typed config struct: `00-foundation-table-config.md`.
- Kernel feature roll-up across all areas: `docs/kernel-requirements.md`.
- Datapath plugins (`freplace`), the legacy `cilium_egress_gw_policy_v4` (v1)
  layout, the XDP prefilter `cilium_cidr_*` maps and the dead Go-only
  `cilium_lb_fct` map: **deferred** per inventory 02. Their layouts are listed
  in §4 for completeness so a future spec does not have to re-derive them, but
  flowsdn MUST NOT create them until the owning feature is specified.

## 2. Compatibility contract

### 2.1 Names and paths

flowsdn keeps the reference names and bpffs layout verbatim. This is the
deliberate answer to inventory 02's open question ("`cilium_*` or
`flowsdn_*`?"): the map names and paths are the interface consumed by
`cilium-dbg bpf ...` (60 subcommands, listed in §2.3), `bpftool map dump
pinned ...`, Hubble and the monitor decoders, and by Envoy's `cilium.bpf_metadata`
listener filter, which opens the ipcache map by pinned name. Renaming would
break all four and gain nothing.

| Item | Value | Consumer |
|---|---|---|
| bpffs root | `/sys/fs/bpf` (`--bpf-root`), fallback `/run/cilium/bpffs` when `/sys/fs/bpf` cannot be mounted | everything below |
| global map pin dir | `<root>/tc/globals/<map name>` | cilium-dbg, bpftool, Envoy, Hubble |
| program/link pin base | `<root>/cilium/` | loader, cilium-dbg |
| endpoint links | `<root>/cilium/endpoints/<endpoint id decimal>/links/<program symbol>` | loader |
| device links | `<root>/cilium/devices/<ifname with "." → "-">/links/<program symbol>` | loader |
| socket-LB links | `<root>/cilium/socketlb/links/cgroup/<program symbol>` | loader |
| reserved (deferred) | `<root>/cilium/{devices/<dev>/plugins/{tc,xdp},endpoints/<id>/plugin_pins,socketlb/plugin_links,plugins/...}` | datapath plugins, not created |
| cgroup v2 root | `/run/cilium/cgroupv2` (mounted by the agent if absent) | socket LB attach |
| monitor socket | `/var/run/cilium/monitor1_2.sock` | cilium-dbg monitor, Hubble |
| per-object config dump | `<state>/<epid>/bpf_lxc.json`, `<state>/bpf/<dev>/bpf_{host,xdp,overlay,wireguard}.json`, `<state>/bpf/bpf_sock.json` | sysdump, cilium-dbg bpf sha (informational) |

Program symbols are the reference entrypoint names (`cil_from_container`,
`cil_to_container`, `cil_from_netdev`, `cil_to_netdev`, `cil_from_host`,
`cil_to_host`, `cil_from_overlay`, `cil_to_overlay`, `cil_from_wireguard`,
`cil_to_wireguard`, `cil_xdp_entry`, `cil_sock4_*`, `cil_sock6_*`,
`cil_sock_release`, `cil_lxc_policy`, `cil_lxc_policy_egress`,
`cil_host_policy`). The `cil_` prefix is the contract by which a loader
recognises its own tc filters, tcx links and netkit links; flowsdn MUST use it
so an in-place takeover of a node previously run by the reference cleans up
the right objects and vice versa.

### 2.2 Map catalogue (frozen)

All 85 specs of `pkg/datapath/maps/maps_generated.go` were re-derived from the
C headers and cross-checked; every size in the tables below matches both. The
"Max" column is the build-time default (`bpf/node_config.h`); the "Sized by"
column is the runtime key. Flags: `NP` = `BPF_F_NO_PREALLOC`, `RO` =
`BPF_F_RDONLY_PROG`, `NCL` = `BPF_F_NO_COMMON_LRU`, `CP` = conditional
prealloc (0 when `--preallocate-bpf-maps`, else `NP`), `LRUF` = LRU flavor (0
by default, `NCL` when `--bpf-distributed-lru`). All maps are `PIN_BY_NAME`
under `tc/globals` unless marked. Layouts are in §4.

**Connection tracking and NAT**

| Pinned name | Type | Key | Value | Max | Flags | Sized by | Writers / consumers |
|---|---|---|---|---|---|---|---|
| `cilium_ct4_global` | LRU_HASH | `ipv4_ct_tuple` 14 | `ct_entry` 56 | 512Ki | LRUF | `bpf-ct-global-tcp-max`, dynamic ratio | DP; agent GC; cilium-dbg bpf ct |
| `cilium_ct_any4_global` | LRU_HASH | 14 | 56 | 256Ki | LRUF | `bpf-ct-global-any-max` | same |
| `cilium_ct6_global` | LRU_HASH | `ipv6_ct_tuple` 38 | 56 | TCP size | LRUF | TCP key | same |
| `cilium_ct_any6_global` | LRU_HASH | 38 | 56 | ANY size | LRUF | ANY key | same |
| `cilium_per_cluster_ct_{tcp4,any4,tcp6,any6}` | ARRAY_OF_MAPS | u32 cluster id | u32 (inner fd) | 256 | 0 | `max-connected-clusters` | agent (clustermesh); inner = same key/value/flags as global, unpinned |
| `cilium_snat_v4_external` | LRU_HASH | `ipv4_ct_tuple` 14 | `ipv4_nat_entry` 40 | 512Ki | LRUF | `bpf-nat-global-max` | DP; agent GC; cilium-dbg bpf nat |
| `cilium_snat_v6_external` | LRU_HASH | 38 | `ipv6_nat_entry` 56 | 512Ki | LRUF | same | same |
| `cilium_snat_v4_alloc_retries` | PERCPU_ARRAY | u32 | u32 | 33 | 0 | fixed (`SNAT_COLLISION_RETRIES`+1) | DP histogram; cilium-dbg bpf nat retries |
| `cilium_snat_v6_alloc_retries` | PERCPU_ARRAY | u32 | u32 | 33 | 0 | fixed | **unpinned in the reference ELF** (no `pinning`); flowsdn MUST pin it (§3.4 note) |
| `cilium_per_cluster_snat_v{4,6}_external` | ARRAY_OF_MAPS | u32 | u32 | 256 | 0 | `max-connected-clusters` | agent; inner = SNAT layout, unpinned |
| `cilium_ipmasq_v4` | LPM_TRIE | `lpm_v4_key` 8 | `lpm_val` 1 | 16384 | NP,RO | fixed | agent (ip-masq-agent); cilium-dbg bpf ipmasq |
| `cilium_ipmasq_v6` | LPM_TRIE | `lpm_v6_key` 20 | 1 | 16384 | NP,RO | fixed | same |

**Load balancer**

| Pinned name | Type | Key | Value | Max | Flags | Sized by | Writers / consumers |
|---|---|---|---|---|---|---|---|
| `cilium_lb4_services_v2` | HASH | `lb4_key` 12 | `lb4_service` 12 | 65536 | CP,RO | `bpf-lb-map-max` / `bpf-lb-service-map-max` | agent LB; cilium-dbg bpf lb |
| `cilium_lb6_services_v2` | HASH | `lb6_key` 24 | `lb6_service` 12 | 65536 | CP,RO | same | same |
| `cilium_lb4_backends_v3` | HASH | u32 backend id | `lb4_backend` 12 | 65536 | CP | `bpf-lb-service-backend-map-max` | agent; cilium-dbg bpf lb |
| `cilium_lb6_backends_v3` | HASH | u32 | `lb6_backend` 24 | 65536 | CP | same | same |
| `cilium_lb4_reverse_nat` | HASH | u16 | `lb4_reverse_nat` 6 | 65536 | CP | `bpf-lb-rev-nat-map-max` | agent |
| `cilium_lb6_reverse_nat` | HASH | u16 | `lb6_reverse_nat` 18 | 65536 | CP | same | agent |
| `cilium_lb4_affinity` | LRU_HASH | `lb4_affinity_key` 16 | `lb_affinity_val` 16 | 65536 | LRUF | `bpf-lb-affinity-map-max` | DP |
| `cilium_lb6_affinity` | LRU_HASH | `lb6_affinity_key` 24 | 16 | 65536 | LRUF | same | DP |
| `cilium_lb_affinity_match` | HASH | `lb_affinity_match` 8 | u8 | 65536 | CP,RO | affinity key | agent |
| `cilium_lb4_source_range` | LPM_TRIE | `lb4_src_range_key` 12 | u8 | 1000 | NP,RO | `bpf-lb-source-range-map-max` | agent |
| `cilium_lb6_source_range` | LPM_TRIE | `lb6_src_range_key` 24 | u8 | 1000 | NP,RO | same | agent |
| `cilium_lb4_health` | LRU_HASH | u64 sock cookie | `lb4_backend` 12 | 65536 | LRUF | backend key | DP (health datapath) |
| `cilium_lb6_health` | LRU_HASH | u64 | `lb6_backend` 24 | 65536 | LRUF | same | DP |
| `cilium_lb4_maglev` | HASH_OF_MAPS | u16 rev-nat id | u32 (inner fd) | 65536 | CP,RO | `bpf-lb-maglev-map-max` | agent; cilium-dbg bpf lb maglev; inner `cilium_lb4_maglev_inner` ARRAY key u32, value `u32[table_size]`, max 1 |
| `cilium_lb6_maglev` | HASH_OF_MAPS | u16 | u32 | 65536 | CP,RO | same | same |
| `cilium_lb4_reverse_sk` | LRU_HASH | `ipv4_revnat_tuple` 16 | `ipv4_revnat_entry` 8 | 256Ki | LRUF | `bpf-sock-rev-map-max`, dynamic | DP sock programs; cilium-dbg bpf socknat |
| `cilium_lb6_reverse_sk` | LRU_HASH | `ipv6_revnat_tuple` 32 | `ipv6_revnat_entry` 20 | 256Ki | LRUF | same | same |
| `cilium_skip_lb4` | HASH | `skip_lb4_key` 16 | u8 | 100 | NP,RO | fixed | agent (LRP) |
| `cilium_skip_lb6` | HASH | `skip_lb6_key` 32 | u8 | 100 | NP,RO | fixed | agent |
| `cilium_lb_act` | LRU_HASH | `lb_act_key` 4 | `lb_act_value` 8 | 65536 | LRUF | registry patch | DP; agent metrics |

**Policy, endpoints, identities, nodes**

| Pinned name | Type | Key | Value | Max | Flags | Sized by | Writers / consumers |
|---|---|---|---|---|---|---|---|
| `cilium_policy_v3_<EPID:05d>` (ELF `cilium_policy`) | LPM_TRIE | `policy_key` 12 | `policy_entry` 12 | 16384 | NP,RO | `bpf-policy-map-max` (256..65536) | agent per endpoint; cilium-dbg bpf policy; bpf_host reads the host endpoint's map |
| `cilium_policystats` | LRU_PERCPU_HASH | `policy_stats_key` 12 | `policy_stats_value` 16 | 200 (ELF) | NCL | policy-map-max × endpoints (registry patch) | DP; agent policy accounting |
| `cilium_call_policy` | PROG_ARRAY | u32 endpoint id | prog | 65536 | 0 | fixed | loader inserts `cil_lxc_policy`/`cil_host_policy` at slot = EPID |
| `cilium_egresscall_policy` | PROG_ARRAY | u32 | prog | 65536 | 0 | fixed | loader inserts `cil_lxc_policy_egress` |
| `cilium_lxc` | HASH | `endpoint_key` 20 | `endpoint_info` 48 | 65536 | CP,RO | fixed | agent; cilium-dbg bpf endpoint |
| `cilium_ipcache_v2` | LPM_TRIE | `ipcache_key` 24 | `remote_endpoint_info` 24 | 512000 | NP,RO | fixed | agent; cilium-dbg bpf ipcache; **Envoy `cilium.bpf_metadata`** (`ipcache_name` = `cilium_ipcache_v2`, **CONFIRMED** `pkg/envoy/model.go:167` passes `ipcache.Name`) |
| `cilium_node_map_v2` | HASH | `node_key` 20 | `node_value` 4 | 16384 | NP,RO | fixed | agent node IDs; cilium-dbg bpf nodeid; IPsec |
| `cilium_subnet_map` | LPM_TRIE | `subnet_key` 24 | `subnet_value` 4 | 1024 | NP,RO | fixed | agent |

**Tail calls, config, telemetry**

| Pinned name | Type | Key | Value | Max | Flags | Sized by | Writers / consumers |
|---|---|---|---|---|---|---|---|
| `cilium_calls_*` (ELF `cilium_calls`, renamed per object, §3.3) | PROG_ARRAY | u32 slot | prog | 50 | 0, **PIN_REPLACE** | fixed | loader only |
| `cilium_runtime_config` | ARRAY | u32 index | u64 | 256 | RO | fixed | agent (index 0 utime offset in 512 ns units, 1 agent liveness); cilium-dbg bpf config |
| `cilium_metrics` | PERCPU_HASH | `metrics_key` 8 | `metrics_value` 16 | 65536 | CP | fixed | DP; agent Prometheus; cilium-dbg bpf metrics |
| `cilium_events` | PERF_EVENT_ARRAY | u32 cpu | u32 fd | possible CPUs (ELF 0) | 0 | kernel | DP; monitor agent (§3.10) |
| `cilium_signals` | PERF_EVENT_ARRAY | u32 | u32 | possible CPUs | 0 | kernel | DP; agent signal handler |
| `cilium_percpu_trace_id` | PERCPU_ARRAY | u32 | u64 | 1 | 0 | fixed | DP (IP-option trace id) |
| `cilium_ratelimit` | LRU_HASH | `ratelimit_key` 8 | `ratelimit_value` 16 | 1024 | LRUF | fixed | DP token buckets |
| `cilium_ratelimit_metrics` | HASH | `ratelimit_metrics_key` 4 | `ratelimit_metrics_value` 8 | 64 | CP | fixed | DP; agent metrics |
| `cilium_devices` | HASH | u32 ifindex | `device_state` 16 | 512 | NP | fixed | agent device table |
| `cilium_xdp_scratch` | PERCPU_ARRAY | int | 28 B scratch | 1 | 0 | fixed | bpf_xdp |
| `cilium_tail_call_buffer4/6`, `cilium_nodeport_nat_buffer` | PERCPU_ARRAY | u32 | `ct_buffer4/6`, `nodeport_nat_info` | 1 | 0 | fixed | **unpinned**, private to each loaded object |

**Feature maps**

| Pinned name | Type | Key | Value | Max | Flags | Sized by | Writers / consumers |
|---|---|---|---|---|---|---|---|
| `cilium_auth_map` | HASH | `auth_key` 12 | `auth_info` 8 | 524288 | NP,RO | `bpf-auth-map-max` | agent; cilium-dbg bpf auth |
| `cilium_throttle` | HASH | `edt_id` 8 | `edt_info` 56 | 65535 | NP | registry patch | agent bandwidth manager; DP updates `t_last`/`tokens`; cilium-dbg bpf bandwidth |
| `cilium_egress_gw_policy_v4_v2` | LPM_TRIE | `egress_gw_policy_key` 12 | `egress_gw_policy_entry_v2` 28 | 16384 | NP,RO | `egress-gateway-policy-map-max` | agent; cilium-dbg bpf egress |
| `cilium_egress_gw_policy_v6` | LPM_TRIE | `egress_gw_policy_key6` 36 | `egress_gw_policy_entry6` 40 | 16384 | NP,RO | same | same |
| `cilium_egress_gw_policy_v4` (v1) | LPM_TRIE | 12 | `egress_gw_policy_entry` 8 | 16384 | NP,RO | — | **deferred**, removed by cleanup when IPv4 disabled |
| `cilium_encrypt_state` | ARRAY | u32 | `encrypt_config` 1 | 1 | RO | fixed | agent IPsec |
| `cilium_l2_responder_v4` | HASH | `l2_responder_v4_key` 8 | `l2_responder_stats` 8 | 4096 | NP | fixed | agent inserts; DP counts |
| `cilium_l2_responder_v6` | HASH | `l2_responder_v6_key` 24 | 8 | 4096 | NP | fixed | same |
| `cilium_nodeport_neigh4` | LRU_HASH | be32 | `macaddr` 8 | 512Ki | LRUF | `bpf-neigh-global-max` (= NAT size) | DP |
| `cilium_nodeport_neigh6` | LRU_HASH | `v6addr` 16 | 8 | 512Ki | LRUF | same | DP |
| `cilium_srv6_vrf_v4` / `_v6` | LPM_TRIE | `srv6_vrf_key4` 12 / `key6` 36 | u32 | 16384 | NP,RO | fixed | agent; cilium-dbg bpf srv6 (deferred feature) |
| `cilium_srv6_policy_v4` / `_v6` | LPM_TRIE | `srv6_policy_key4` 12 / `key6` 24 | `v6addr` 16 | 16384 | NP,RO | fixed | same |
| `cilium_srv6_sid` | HASH | `v6addr` 16 | u32 | 16384 | NP,RO | fixed | same |
| `cilium_vtep_map` | HASH | `vtep_key` 4 | `vtep_value` 16 | 8 | CP,RO | fixed | agent; cilium-dbg bpf vtep (deferred) |
| `cilium_ipv4_frag_datagrams` | LRU_HASH | `ipv4_frag_id` 12 | `ipv4_frag_l4ports` 4 | 8192 | LRUF | `bpf-fragments-map-max` | DP; cilium-dbg bpf frag |
| `cilium_ipv6_frag_datagrams` | LRU_HASH | `ipv6_frag_id` 40 | 4 | 8192 | LRUF | same | DP |
| `cilium_mcast_group_outer_v4_map` | HASH_OF_MAPS | be32 group | u32 (inner fd) | 1024 | CP | fixed | agent; inner HASH be32 → `mcast_subscriber_v4` 12, 1024, CP (deferred) |
| `cilium_cidr_v{4,6}_{fix,dyn}` | HASH / LPM_TRIE | `lpm_v4_key` 8 / `lpm_v6_key` 20 | `lpm_val` 1 | 1024 | NP,RO | — | **deferred** (XDP prefilter) |

### 2.3 Consumers that freeze the layouts

- `cilium-dbg bpf {auth,bandwidth,config,ct,egress,endpoint,frag,ipcache,
  ipmasq,lb,lb maglev,metrics,mountfs,multicast,nat,nat retries,nodeid,policy,
  sha,socknat,srv6,vtep}` open the maps by pin path and decode with the Go
  structs mirrored in §4. flowsdn's own `flowsdn-dbg` (area 06) reuses the same
  Rust ABI crate, so the two tools agree by construction.
- `bpftool map dump pinned` relies on BTF for pretty-printing; flowsdn objects
  MUST carry BTF for every map key/value type with the reference type names
  (`ipv4_ct_tuple`, `ct_entry`, ... exactly as in §4) so dumps stay readable
  and so the layout test in §9.1 can compare against the reference BTF.
- Envoy (`cilium/proxy` image, ADR-0001) opens `<bpf_root>/tc/globals/cilium_ipcache_v2`
  and performs LPM lookups with `ipcache_key` and reads `remote_endpoint_info.sec_identity`.
  Key, value and pin path are therefore frozen for as long as Envoy is the L7 proxy.
- Userspace proxies read `ct_entry.src_sec_id` at offset 44 (comment in the
  reference header: "do not change offset").
- Hubble/monitor decoders (`cilium-dbg monitor`, Hubble parser) decode the
  perf payloads of §4.6 by version byte; flowsdn emits the same versions.
- The skb mark values (§4.7) are consumed by Envoy TPROXY (`MARK_MAGIC_TO_PROXY`,
  `MARK_MAGIC_PROXY_{INGRESS,EGRESS}`, `MARK_MAGIC_PROXY_EGRESS_EPID`), by the
  nftables residual (ADR-0003: `0x0C00` host mark, TPROXY), by IPsec XFRM
  policies (`0x0E00`/`0x0D00`, key in bits 12..15, node id in 16..31) and by
  socket LB health checks (`MARK_MAGIC_HEALTH` is user-facing per the header).

### 2.4 Configuration keys that are part of the contract

Names and defaults MUST be accepted as in the reference so existing
`cilium-config` ConfigMaps and Helm values apply (area 00 owns the registry):
`bpf-root`, `preallocate-bpf-maps` (false), `bpf-distributed-lru` (false),
`bpf-map-dynamic-size-ratio` (0.0025), `bpf-ct-global-tcp-max` (524288),
`bpf-ct-global-any-max` (262144), `bpf-nat-global-max` ((tcp+any)·2/3),
`bpf-neigh-global-max` (= NAT), `bpf-policy-map-max` (16384),
`bpf-lb-map-max` (65536), `bpf-lb-service-map-max`,
`bpf-lb-service-backend-map-max`, `bpf-lb-rev-nat-map-max`,
`bpf-lb-affinity-map-max`, `bpf-lb-source-range-map-max`,
`bpf-lb-maglev-map-max`, `bpf-lb-maglev-table-size` (16381),
`bpf-sock-rev-map-max` (262144), `bpf-auth-map-max` (524288),
`bpf-fragments-map-max` (8192), `egress-gateway-policy-map-max` (16384),
`bpf-filter-priority` (1), `enable-tcx` (true), `datapath-mode`
(`veth`|`netkit`|`netkit-l2`), `bpf-lb-acceleration`
(`disabled`|`native`|`generic`|`best-effort`), `trace-payloadlen` (128),
`trace-payloadlen-overlay` (192), `bpf-events-default-rate-limit`,
`bpf-events-default-burst-limit`, `monitor-aggregation`, `bpf-map-event-buffers`.

## 3. Behavior

### 3.1 bpffs mount

1. At startup the loader MUST ensure a bpffs is mounted at `--bpf-root`
   (default `/sys/fs/bpf`). If the path is not a mount point and mounting
   fails (typical when running in a container without the host bpffs), it
   MUST fall back to mounting at `/run/cilium/bpffs` and log the fallback.
2. Two bpffs mounts of the same root MUST be refused (fatal): pins would
   silently land in different namespaces.
3. `<root>/tc/globals` and `<root>/cilium` MUST be created (mode 0755) before
   any map or link is pinned.

### 3.2 Map lifecycle: create-or-open

Every map in §2.2 is opened with the same procedure, whether created by the
agent (`OpenOrCreate`) or by the loader as part of a collection:

| Step | Condition | Action |
|---|---|---|
| 1 | pin `<globals>/<name>` does not exist | create map from spec, pin it |
| 2 | pin exists and is compatible (same type, key size, value size, max entries, flags) | reuse the existing map, contents preserved |
| 3 | pin exists, spec has `RO` but pinned map lacks it | strip `RO` from the spec and reuse (upgrade path: a read-write map is a superset) |
| 4 | pin exists, spec lacks `RO` but pinned map has it | unpin the old map, create new (downgrade path: programs need write access) |
| 5 | pin exists and is incompatible for any other reason | agent-created maps: unpin and create empty (**no content migration**, log old vs new type/key/value/max/flags). Loader-created maps: defer the replacement to the commit step (§3.6) so the old map keeps serving until the new programs are attached |

**Flag encoding verified (2026-09-09).** `RO` is bit 7 (`0x80`), as
declared in the pinned reference’s `bpf/include/linux/bpf.h:1294` at
`7d68cfb394`. This kernel ABI value is used by the explicit compatibility
planner; no reference implementation logic is copied. Loader-owned replacements,
including a read-only downgrade, retain the staged-commit rule from step 5.

Steps 3–4 exist because the reference toggled `RO` between releases; flowsdn
keeps them so a node can be taken over from a running reference agent without
recreating agent-owned maps. Memory flags (`BPF_F_MMAPABLE` and similar) are
never added; the kernel rejects `RO` on per-CPU and LRU types, so the flag is
only ever set on the maps marked RO in §2.2.

### 3.3 Per-object map renames

The ELF names `cilium_calls` and `cilium_policy` are placeholders. Before load
the loader MUST rename them, producing the pinned names of §2.2:

| Object | `cilium_calls` → | `cilium_policy` → |
|---|---|---|
| endpoint (lxc) | `cilium_calls_%05d` (endpoint id) | `cilium_policy_v3_%05d` (endpoint id) |
| host, attached to `cilium_host` | `cilium_calls_hostns_%05d` (host endpoint id) | `cilium_policy_v3_%05d` (host endpoint id) |
| host, attached to `cilium_net` or a native device | `cilium_calls_netdev_%05d` (ifindex, truncated to u16) | host endpoint's policy map |
| overlay | `cilium_calls_overlay_2` (reserved identity `world`) | — |
| wireguard | `cilium_calls_wireguard_<ifindex>` (decimal, not zero-padded) | — |
| xdp | `cilium_calls_xdp_<ifindex>` (decimal) | — |
| sock | no `cilium_calls` | — |

Zero-padding is `%05d` for the first three rows and none for the last three;
the mapsweeper (§3.4) depends on the exact form to recognise stale pins.

### 3.4 What survives a restart; stale-map cleanup

- All maps pinned under `tc/globals` survive agent restart and MUST NOT be
  unpinned on shutdown. Endpoints keep forwarding while the agent is down.
- Endpoint teardown (`Unload`) removes, in order: legacy tc filters on the
  endpoint device, `<cilium>/endpoints/<id>/links/*`, the endpoint directory.
  It MUST NOT remove the endpoint's policy or calls map pins directly; those
  are reclaimed by the sweep below so a crash between steps leaves nothing
  unreachable.
- Startup sweep (reference `mapsweeper`), run once after the endpoint
  restore has produced the set of live endpoint ids:
  1. Walk `tc/globals`. For every file whose name starts with `cilium_policy_v3_`
     or `cilium_calls_` followed by a decimal endpoint id: if the id is not a
     live endpoint, delete slot `id` from `cilium_call_policy` and
     `cilium_egresscall_policy`, then remove the pin. If the id is live but the
     filename is not exactly `<prefix>%05d`, remove the pin (malformed).
  2. Remove pins of maps that no longer exist in any supported layout:
     `cilium_proxy4`, `cilium_proxy6`, `cilium_capture_cache`,
     `cilium_capture4_rules`, `cilium_capture6_rules`, `cilium_ktime_cache`,
     and every `cilium_policy_*` pin whose name is not `cilium_policy_v3_*`.
  3. Remove pins for disabled features, using the same name lists as the
     reference: IPv6 disabled → all `*6*` CT/LB/SNAT/L2/egress/maglev/affinity/
     source-range/health/ipmasq/cidr v6 maps (including obsolete
     `cilium_lb6_services`, `cilium_lb6_rr_seq`, `cilium_lb6_rr_seq_v2`,
     `cilium_lb6_backends_v2`); IPv4 disabled → the v4 equivalents plus
     `cilium_egress_gw_policy_v4` and `_v4_v2`; neither KPR nor BPF
     masquerade → SNAT and retries maps; fragments tracking disabled → frag
     maps; health datapath disabled → health maps; Maglev not selected and no
     per-service algorithm annotation → maglev outer maps; ip-masq-agent off →
     ipmasq maps; SRv6 off → the five srv6 maps; XDP prefilter off → the four
     cidr maps.
  4. Feature disable at runtime additionally removes `cilium_calls_overlay*`
     and `cilium_calls_wireguard*` pins and the device link directory.
- **CONFIRMED**: stale-map cleanup after a versioned rename lives in this
  sweep (it is the `_v2`/`_v3`-less old names in step 2/3), not in the loader.
  The sweep is the only place that removes a global pin.
- `cilium_snat_v6_alloc_retries` is not pinned by the reference ELF (missing
  `pinning`), so `cilium-dbg bpf nat retries list` for IPv6 reads an
  agent-created map. flowsdn MUST pin it like its v4 twin (**DEVIATION**:
  reference omission; the agent-created path already assumes the pin exists).

### 3.5 Loader pipeline (per object load)

Input: the embedded object for the hook family (lxc, host, overlay, xdp,
wireguard, sock, sock_term), the node config struct, the per-object config
struct, the map registry patches, the rename table, the map replacement set
(already-open maps to inject, e.g. `cilium_lb{4,6}_reverse_sk` into sock_term).

Steps, in order; each step is pure spec manipulation until step 11:

1. Verify every program has a known type and attach type; fail otherwise.
2. Copy the parsed object so the embedded original can be reused.
3. Apply registry patches (`max_entries`, `flags`, inner-map patch) by name.
4. Adjust `RO` per §3.2 steps 3–4 against the currently pinned maps.
5. Apply renames (§3.3).
6. Patch `.rodata.config` globals from the config structs (§3.7). A struct
   field naming a variable that does not exist in the object is an error; a
   variable outside `.rodata.config` is an error.
7. Compute reachability (§5.2) and remove tail programs not reachable from
   any entrypoint.
8. Populate the `cilium_calls` initial contents from the slot table (§3.8).
9. Remove maps not referenced by any surviving program, except the fixed
   set (`cilium_calls`, `cilium_call_policy`, `cilium_egresscall_policy`,
   `.rodata*`, `.data*`, `.bss`, and any name in the caller's keep set);
   replace each removed map's load instructions with the poison immediate
   `0xdeadc0de` so a bug surfaces as a verifier error, not a wrong map.
10. Size `.data.aux` (§5.4), write the config dump JSON, strip the
    `PIN_REPLACE` (16) pinning value (the kernel-facing loader only knows 0/1)
    and remember which maps had it.
11. Load the collection with pin dir `<globals>`. On `EMAPINCOMPATIBLE` for a
    `PIN_BY_NAME` map: record the map, clear its pinning, and load again with
    that map created fresh and unpinned. The set {PIN_REPLACE maps} ∪
    {incompatible maps} is the *pending pin set*.
12. Return the loaded collection plus a `commit` closure; the caller attaches
    programs and then calls `commit` (§3.6).

### 3.6 Pin-replace commit protocol (program upgrade)

Motivation, kept from the reference: repopulating an existing tail-call map
in place moves code between slots while packets are flowing, so a running
program can execute a mixed old/new graph. flowsdn MUST never reuse a pinned
`cilium_calls_*`; every load creates a fresh one and swaps the pin only after
every entrypoint of the object is attached.

Ordering for one object attached at several hooks (e.g. bpf_host on
`cilium_host` ingress+egress, `cilium_net` ingress, N native devices):

```
load collection (§3.5)                      -- new maps and programs exist, unpinned
for each hook: attach or link-update        -- new programs start running, calling the NEW calls map
                                            -- old programs, still linked from nowhere, drain
commit:
  for each map in pending pin set:
     unlink <globals>/<name> if present     -- old map now only held by old programs' fds
     pin new map at <globals>/<name>
close old programs / collection             -- old maps freed when last program goes away
```

Rules:

- `PIN_BY_NAME` and `PIN_REPLACE` are mutually exclusive on one map.
- `commit` MUST be called only after *all* hooks of the object are attached.
  Committing early makes a hook that is still attached to the old program
  observe a calls map whose pin points at the new map: no correctness
  problem for the running program (it holds its own fd) but a subsequent
  crash leaves the pin inconsistent with what runs.
- Endpoint objects have one extra "attachment": inserting `cil_lxc_policy`
  and `cil_lxc_policy_egress` into `cilium_call_policy[epid]` /
  `cilium_egresscall_policy[epid]` MUST happen *before* the tc/tcx attach and
  after all internal tail-call plumbing (steps 7–11) — from bpf_host's point of
  view the policy program is reachable as soon as it is in the array.
  Ordering for an endpoint reload: load → insert policy programs → attach
  ingress → attach egress if required (else detach egress) → commit → routes.
- Rollback: if any attach fails, the loader MUST NOT commit; it closes the
  new collection. Pins still point at the old maps and the old links/filters
  keep the old programs running: an attach failure leaves the datapath in its
  previous state. Links that were already updated to the new program before
  the failure are re-updated to the old program if the old program fd is
  still held (it is, until the collection is closed); the loader MUST keep
  the previous collection's program fds until commit succeeds for exactly
  this reason. If the process dies between the first inserted policy program
  and commit, the endpoint's next regeneration repairs it (the reference
  documents this window as accepted).
- Agent-created maps never use PIN_REPLACE; their incompatible-pin path is
  §3.2 step 5.

### 3.7 Configuration mechanism (ADR-0002)

Three layers, all present:

**Layer 1 — build-time variants.** The reference's ~87 `#define`s in
`node_config.h` (list in §6.3) select code shape at clang time on the node.
flowsdn has no compiler on the node. Every define is reclassified:

- *Value-like* (`*_MAP_SIZE`, `*_MAX_ENTRIES`, `CT_*` lifetimes, addresses,
  `HOST_NETNS_COOKIE`, `ENCAP*_IFINDEX`, `IPV4_GATEWAY`, `TUNNEL_MODE`,
  `DSR_ENCAP_MODE`, `LB_MAGLEV_LUT_SIZE`, `SNAT_COLLISION_RETRIES`,
  `TRACE_SOCK_NOTIFY`, `MONITOR_AGGREGATION`, `POLICY_VERDICT_LOG_FILTER`):
  become `.rodata.config` variables (layer 2) or map-size patches. Map sizes
  MUST come from the registry patch, never from the object.
- *Shape-like* (`ENABLE_IPV4/6`, `ENABLE_NODEPORT`, `ENABLE_DSR`,
  `ENABLE_MASQUERADE_*`, `ENABLE_SOCKET_LB_*`, `ENABLE_HOST_FIREWALL`,
  `ENABLE_SRV6`, `ENABLE_VTEP`, `ENABLE_L7_LB`, `ENABLE_HEALTH_CHECK`,
  `ENABLE_NAT_46X64*`, `ENABLE_SCTP`, `ENABLE_MKE`, ...): become `bool`
  `.rodata.config` variables, and the datapath spec MUST write every use as a
  runtime branch on that variable so the pass in §5.2 and the kernel verifier
  prune it. Cargo features are reserved for variants that cannot be a branch
  (`PROG_TYPE` tc vs xdp, which are separate objects anyway; `ETH_HLEN` is
  already `eth_header_length`).
- If a single object still exceeds the verifier budget on the minimum kernel
  with every feature enabled, flowsdn ships a small prebuilt matrix; the
  dimensions are open decision §12.2.

**Layer 2 — load-time constants.** Each config variable is a global in the
ELF section `.rodata.config`, symbol `__config_<name>`, read in program code
through a volatile load so the compiler materialises a fresh
`ld_imm64 <map value>` + `ldx` per use (the reachability pass and the kernel
verifier both key on this pattern). The loader sets values before load via the
aya equivalent of `CollectionSpec.Variables` (`EbpfLoader::set_global(name,
&value, must_exist=true)`), rejecting names outside `.rodata.config`.
**CONFIRMED** (aya 0.13 `aya_obj::Object::patch_map_data` matches sections by
the `.rodata` prefix, so `.rodata.config` is accepted; the loader MUST
nevertheless check the symbol's section name itself, as aya does not.)

The variable set is frozen from inventory 01 and the generated Go structs;
types are the exact widths the BPF side declares:

| Kind | Variable (`__config_` prefix) | Type |
|---|---|---|
| node | `cilium_host_ifindex`, `cilium_net_ifindex`, `direct_routing_dev_ifindex`, `cluster_id`, `cluster_id_bits`, `hash_init4_seed`, `hash_init6_seed`, `kernel_hz`, `events_map_rate_limit`, `events_map_burst_limit`, `trace_payload_len`, `trace_payload_len_overlay` | u32 |
| node | `cilium_host_mac`, `cilium_net_mac` | `macaddr` 8 (6 bytes + 2 pad) |
| node | `service_loopback_ipv4` | `v4addr` 4 |
| node | `service_loopback_ipv6`, `router_ipv6` | `v6addr` 16 |
| node | `nat_46x64_prefix` | `v4addr` 4 |
| node | `nodeport_port_min`, `nodeport_port_max` | u16 |
| node | `lb_default_alg`, `tracing_ip_option_type` | u8 |
| node | `debug_lb`, `enable_bpf_host_routing`, `enable_conntrack_accounting`, `enable_endpoint_routes`, `enable_ipip_termination`, `enable_identity_mark`, `enable_jiffies`, `enable_nodeport_source_lookup`, `enable_tproxy`, `encryption_strict_ingress`, `lb_selection_per_service`, `policy_deny_response_enabled`, `supports_fib_lookup_skip_neigh`, `supports_fib_lookup_src` | bool (u8, 0/1) |
| object (all tc/xdp) | `interface_ifindex` | u32 |
| object | `interface_mac` | `macaddr` |
| object | `device_mtu`, `tunnel_port`, `ephemeral_min` | u16 |
| object | `tunnel_protocol` | u8 (1 vxlan, 2 geneve as in the datapath spec) |
| object | `vtep_mask`, `security_label`, `rt_info`, `policy_verdict_log_filter`, `wg_ifindex` | u32 |
| object | `host_ep_id`, `endpoint_id`, `wg_port` | u16 |
| object | `endpoint_ipv4`, `nat_ipv4_masquerade` | `v4addr` |
| object | `endpoint_ipv6`, `nat_ipv6_masquerade` | `v6addr` |
| object | `endpoint_netns_cookie`, `l2_announcements_max_liveness` | u64 |
| object | `eth_header_length` | u8 |
| object | `allow_icmp_frag_needed`, `enable_arp_responder`, `enable_extended_ip_protocols`, `enable_icmp_rule`, `enable_ipv4_fragments`, `enable_ipv6_fragments`, `enable_lrp`, `enable_netkit`, `enable_no_service_endpoints_routable`, `enable_policy_accounting`, `enable_remote_node_masquerade`, `enable_l2_announcements`, `enable_xdp_prefilter`, `hybrid_routing_enabled`, `proxy_redirect_via_cilium_net` | bool |

Per-object struct membership follows the reference (`BPFLXC`, `BPFHost`,
`BPFXDP`, `BPFOverlay`, `BPFWireguard`, `BPFSock`, each embedding `Node`);
the reclassified layer-1 defines are appended to these structs by the
datapath spec. **DEVIATION**: the reference discovers variables and their
`kind:`/description through BTF decl tags emitted by clang; rustc does not
emit `BTF_KIND_DECL_TAG`. flowsdn's single source of truth is a table in the
shared ABI crate (`flowsdn-bpf-abi::config::VARIABLES`, generated from one
Rust declaration macro used by the BPF crate), and the loader checks that
every table entry exists in the object's `.rodata.config` BTF with the
expected size (§9.1). The description strings are kept in the table for the
config dump.

**Per-endpoint template objects vs map-based endpoint config.** flowsdn keeps
the reference model: one object load per endpoint, endpoint constants patched
into `.rodata.config`, `cilium_policy`/`cilium_calls` renamed per endpoint.
Reasons: it is what the policy-map naming, `cilium_call_policy` slot
insertion, mapsweeper and cilium-dbg all assume, and per-endpoint constants
let the reachability pass drop code per endpoint (an endpoint without IPv6
loses the IPv6 paths). Template values used to compute the *object identity*
hash so endpoints with the same feature set share the prepared spec:
security id `2` (world), endpoint id `65535`, IPv4 `192.0.2.3`, IPv6
`2001:db8:bad:cafe:600d:bee2:bad:cafe`, MAC `02:00:60:0d:f0:0d`, ifindex
`0xFFFFFFFF`, netns cookie `0xFFFFFFFFFFFFFFFF`, verdict filter `0xffff`.
The alternative (one shared lxc object, endpoint selected by a
`HASH_OF_MAPS` keyed on endpoint id) is open decision §12.3.

**Object identity and restart invalidation (resolved #120).** The loader owns
this identity independently of the endpoint-configuration hash in spec 08 §5.4.
Compute SHA-256 over a versioned, length-delimited encoding of the embedded ELF
bytes, selected object variant and loader transformation/ABI version. A changed
input invalidates prepared-template reuse even if endpoint rodata and map names
are unchanged. The generation's `template.txt` records this digest as lowercase
hex plus newline; publish it atomically only after successful load/attachment.
On restore a missing, malformed or different digest requires `rewrite+load`;
never infer compatibility from timestamps or an equal endpoint-value hash.
Retain the prior working generation on load failure under §3.4's commit protocol.
This is a normative loader obligation; the initial anonymous local-delivery
owner still reloads unconditionally and does not implement pinned-generation reuse.

**Layer 3 — runtime map.** `cilium_runtime_config[0]` = Unix-time offset in
512 ns units (`utime`), `[1]` = agent liveness timestamp (written every 1 s).
Values that change while programs run go here, never into `.rodata`.

### 3.8 Tail-call table

The per-object `cilium_calls` PROG_ARRAY has 50 slots. Slot numbers are
frozen from `bpf/lib/tailcall.h` (**CONFIRMED** identical to inventory 01):

| Slot | Name | Slot | Name |
|---|---|---|---|
| 1 | `DROP_NOTIFY` | 26 | `IPV4_FROM_LXC_CONT` |
| 2 | `ERROR_NOTIFY` | 27 | `IPV6_FROM_LXC_CONT` |
| 3 | *(reserved gap)* | 28 | `IPV4_CT_INGRESS` |
| 4 | `HANDLE_ICMP6_NS` | 29 | `IPV4_CT_INGRESS_POLICY_ONLY` |
| 5 | `SEND_ICMP6_TIME_EXCEEDED` | 30 | `IPV4_CT_EGRESS` |
| 6 | `ARP` | 31 | `IPV6_CT_INGRESS` |
| 7 | `IPV4_FROM_LXC` (= `_FROM_NETDEV` = `_FROM_OVERLAY` = `_FROM_WIREGUARD`) | 32 | `IPV6_CT_INGRESS_POLICY_ONLY` |
| 8 | `IPV46_RFC6052` | 33 | `IPV6_CT_EGRESS` |
| 9 | `IPV64_RFC6052` | 34 | `SRV6_ENCAP` |
| 10 | `IPV6_FROM_LXC` (= v6 NETDEV/OVERLAY/WIREGUARD) | 35 | `SRV6_DECAP` |
| 11 | `IPV4_TO_LXC_POLICY_ONLY` (= `IPV4_TO_HOST_POLICY_ONLY`) | 36 | `IPV4_NODEPORT_NAT_INGRESS` |
| 12 | `IPV6_TO_LXC_POLICY_ONLY` (= `IPV6_TO_HOST_POLICY_ONLY`) | 37 | `IPV6_NODEPORT_NAT_INGRESS` |
| 13 | `IPV4_TO_ENDPOINT` | 38 | `IPV4_NODEPORT_SNAT_FWD` |
| 14 | `IPV6_TO_ENDPOINT` | 39 | `IPV6_NODEPORT_SNAT_FWD` |
| 15 | `IPV4_NODEPORT_NAT_EGRESS` | 40 | `IPV4_INTER_CLUSTER_REVSNAT` |
| 16 | `IPV6_NODEPORT_NAT_EGRESS` | 41 | `IPV4_CONT_FROM_HOST` |
| 17 | `IPV4_NODEPORT_REVNAT` | 42 | `IPV4_CONT_FROM_NETDEV` |
| 18 | `IPV6_NODEPORT_REVNAT_INGRESS` | 43 | `IPV6_CONT_FROM_HOST` |
| 19 | `IPV6_NODEPORT_REVNAT_EGRESS` | 44 | `IPV6_CONT_FROM_NETDEV` |
| 20 | `IPV4_NODEPORT_NAT_FWD` | 45 | `IPV4_NO_SERVICE` |
| 21 | `IPV4_NODEPORT_DSR` | 46 | `IPV6_NO_SERVICE` |
| 22 | `IPV6_NODEPORT_DSR` | 47 | `MULTICAST_EP_DELIVERY` |
| 23 | `IPV4_FROM_HOST` | 48 | `IPV4_POLICY_DENIED` |
| 24 | `IPV6_FROM_HOST` | 49 | `IPV6_POLICY_DENIED` |
| 25 | `IPV6_NODEPORT_NAT_FWD` | | `CILIUM_CALL_SIZE` = 50 |

Population: for each tail program surviving §3.5 step 7, the loader sets
`cilium_calls[slot] = program` as *initial contents* of the fresh map (so the
map is fully populated before any entrypoint runs). A tail call to an empty
slot returns `DROP_MISSED_TAIL_CALL` (-140) with the slot in `ext_error`;
after pruning this indicates a loader bug and the test in §9.3 asserts none
occur for every config permutation. **DEVIATION** (mechanism only): the
reference marks tail programs with `btf_decl_tag("tail:cilium_calls/N")`;
flowsdn uses the ELF section name `classifier/tail/<N>` (tc objects) or
`xdp/tail/<N>` (xdp) emitted by an aya-ebpf attribute macro, plus the
`flowsdn-bpf-abi::tailcall::SLOTS` table (slot → symbol) that the loader
cross-checks against the object's sections. Slot numbers and the two global
PROG_ARRAYs are unchanged.

The two global arrays `cilium_call_policy` / `cilium_egresscall_policy`
(65536 slots, indexed by endpoint id) are `PIN_BY_NAME` and reused across
loads: slot `epid` is updated with `BPF_ANY` when the endpoint (re)loads and
deleted by the sweep (§3.4) or endpoint removal.

### 3.9 Attach mechanics

Common rules:

- Every attachment that the kernel can express as a `bpf_link` MUST be a
  link, pinned at the path in §2.1. Upgrades MUST use `BPF_LINK_UPDATE` on the
  pinned link (atomic program swap, no packet sees "no program"). `ENOLINK`
  from update means the link is defunct (its device or cgroup is gone): unpin
  it and fall through to a fresh attach. `ENOENT` means no link yet.
- The loader identifies its own objects by the `cil_` symbol prefix in tc
  filter names, tcx link program names and netkit link program names.

**tc SKB programs** (`attach_skb(device, prog, symbol, link_dir, direction)`):

| Step | Condition | Action |
|---|---|---|
| 1 | `enable-tcx` and device type is `netkit` | netkit link (below); no tcx, no clsact |
| 2 | `enable-tcx` | try tcx: link-update pinned link, else create tcx link (`BPF_TCX_INGRESS`/`_EGRESS`, anchor *tail*) and pin. On success remove any legacy `cil_*` clsact filters on that direction (tcx supersedes clsact evaluation) and stop |
| 3 | required tcx capability is absent or tcx is disabled | refuse startup with the missing capability or unsupported setting named; do not create a legacy clsact attachment (#54) |
| 4 | any other tcx error | fail the load (no silent fallback) |

Detach removes the link pin (tcx/netkit) and any legacy owned clsact filter left by a previous agent. Legacy-filter cleanup is takeover compatibility, not an alternative attach mode.
**DEVIATION** (ordering): flowsdn attaches with tcx anchor *last*, as the
reference does. tcx *ordering* relative to third-party tcx programs is not
guaranteed by either; see aya gap in §11.

**netkit** (`--datapath-mode=netkit|netkit-l2`, kernel ≥ 6.7): endpoint
ingress program attaches as `BPF_NETKIT_PEER`, egress as `BPF_NETKIT_PRIMARY`,
anchor tail, link pinned at the endpoint links dir, updated via
`BPF_LINK_UPDATE`. Inventory 03 defers the netkit *connector*; the attach
path is specified here so it is not redesigned later, and MUST be gated by
the same option.

**XDP** (`cil_xdp_entry` from the xdp object, one load per selected device):

1. Mode from `bpf-lb-acceleration`: `native` → `XDP_FLAGS_DRV_MODE`,
   `generic` → `XDP_FLAGS_SKB_MODE`, `best-effort` → try driver, tolerate
   failure and fall back to generic, `disabled` → detach from every device.
   Offload mode is not used.
2. Load permutations, in order, until the verifier accepts: (attach type
   `BPF_XDP`, `BPF_F_XDP_HAS_FRAGS` as compiled) → (attach type none, same
   flags) → (attach type `BPF_XDP`, frags flag flipped) → (attach type none,
   frags flipped). `EINVAL` from the kernel selects the next permutation.
3. Attach: link-update pinned `<devices>/<dev>/links/cil_xdp_entry`; else
   create an XDP link with the mode flags and pin; if that returns `EBUSY`
   (a netlink-attached program exists, e.g. from an older agent) or "not
   supported" (< 5.7), fall back to netlink `IFLA_XDP_FD` **without**
   `XDP_FLAGS_UPDATE_IF_NOEXIST` (clobbers any existing attachment).
4. Devices no longer selected are detached (link unpin, then netlink detach
   in both generic and driver mode); `cilium_wg0` is never touched.

**cgroup socket programs** (socket LB):

- Cgroup root: `/run/cilium/cgroupv2` (`--cgroup-root`). If not a cgroup2
  mount, the agent mounts `cgroup2` there. It is harmless to have several
  cgroup2 root mounts; the attach target MUST be the *root* cgroup so every
  pod netns is covered. cgroup v1-only hosts cannot run socket LB (fatal
  when the feature is enabled).
- Programs and attach types: `cil_sock4_connect` `CGROUP_INET4_CONNECT`,
  `cil_sock4_sendmsg` `CGROUP_UDP4_SENDMSG`, `cil_sock4_recvmsg`
  `CGROUP_UDP4_RECVMSG`, `cil_sock4_getpeername` `CGROUP_INET4_GETPEERNAME`,
  `cil_sock4_post_bind` `CGROUP_INET4_POST_BIND`, `cil_sock4_pre_bind`
  `CGROUP_INET4_BIND`, the six `cil_sock6_*` with the v6 attach types, and
  `cil_sock_release` `CGROUP_INET_SOCK_RELEASE`. Which of the 13 are attached
  is decided by the datapath spec (post_bind needs KPR + bind protection,
  pre_bind needs the health datapath, v6 programs load on v4-only hosts with
  IPv6 kernel support).
- Attach per program: link-update pinned `<cilium>/socketlb/links/cgroup/<symbol>`;
  `ENOLINK` → unpin and continue; else `BPF_LINK_CREATE` on the cgroup root
  fd and pin. A missing cgroup-link capability is a startup failure under
  the 6.6 minimum. If link create returns `EPERM` because a non-multi
  `PROG_ATTACH` from an older agent holds the hook, fall back
  to `BPF_PROG_ATTACH` with no flags (replaces the old program in place),
  and detach with `BPF_PROG_DETACH`. Programs the feature no longer needs
  are detached by both paths. This retained path handles takeover of an old
  attachment on a supported kernel; it does not enable older-kernel support.
- sockops: the reference has no `sock_ops` program in 1.20; none is specified.

**Socket iterators** (socket termination, deferred with socket LB per
inventory 03): `iter/tcp` and `iter/udp` programs `cil_sock_{tcp,udp}_destroy_v{4,6}`
attached with `BPF_LINK_CREATE` (`BPF_TRACE_ITER`), run to completion via
`read()` on the iterator fd, filter passed through the `.rodata` variable
`cilium_sock_term_filter`, reverse-sk maps injected by map replacement.
Requires kfunc `bpf_sock_destroy` (≥ 6.4) — the only program needing CO-RE/
ksym relocation.

### 3.10 Monitor and signal channels

- Transport is `BPF_MAP_TYPE_PERF_EVENT_ARRAY` `cilium_events`, `max_entries`
  = number of *possible* CPUs (the ELF says 0; the loader sets it). flowsdn
  keeps perf rather than `RINGBUF` because `cilium-dbg monitor`, Hubble and
  bpftool tooling read `cilium_events` by name and expect per-CPU rings with
  `PERF_RECORD_LOST` accounting; the ring-buffer switch is open decision §12.4.
- Sizing: one ring per possible CPU, **64 pages** each (page size from the
  kernel; 256 KiB per CPU at 4 KiB pages). `cilium_signals` uses 1 page per
  CPU. Rings are mmapped by the monitor agent; the fd of the pinned map is
  opened, not created, so a monitor restart does not disturb the datapath.
- Datapath side: `perf_event_output(ctx, &cilium_events, (cap_len << 32) |
  BPF_F_CURRENT_CPU, &msg, sizeof msg)`, so the sample is `struct || cap_len
  packet bytes`. `cap_len ≤ trace_payload_len` (128) or
  `trace_payload_len_overlay` (192) for overlay-classified packets.
- Rate limit: token bucket per usage class in `cilium_ratelimit` keyed
  `{usage=2 (events map) or 3 (socket events), netdev_idx}` with
  `events_map_rate_limit`/`events_map_burst_limit` from the node config;
  drops counted in `cilium_ratelimit_metrics[usage].dropped`.
- Userspace framing to listeners (`/var/run/cilium/monitor1_2.sock`): a
  stream of gob-encoded `Payload{Data []byte, CPU int, Lost uint64, Type int}`
  with `Type` 9 = `EventSample`, 2 = `RecordLost`; `Data[0]` is the message
  type byte of §4.6. The legacy 32-byte `Meta{Size u32, pad[28]}` prefix is
  not written by 1.2 listeners. Area 09 owns the gob implementation subset;
  this spec fixes only that `Data` is the raw perf sample bytes and that
  `PERF_RECORD_LOST` becomes one `RecordLost` payload with `Lost = n` per
  CPU.
- Signals: samples are `signal_msg` (§4.6) with `signal_nr` 0 `NAT_FILL_UP`,
  1 `CT_FILL_UP`, 2 `AUTH_REQUIRED`; `proto` 0 = IPv4, 1 = IPv6.

### 3.11 Map access from userspace

- **Lookup/update/delete** are plain syscalls; `update` uses `BPF_ANY`
  unless a caller needs `BPF_NOEXIST` (endpoint policy inserts) or
  `BPF_EXIST`.
- **Batch operations** (`BPF_MAP_LOOKUP_BATCH`, `LOOKUP_AND_DELETE_BATCH`,
  `UPDATE_BATCH`, `DELETE_BATCH`, kernel ≥ 5.6) are used for CT/NAT dumps and
  GC. Semantics the caller relies on: the kernel returns `ENOENT` when the
  cursor reaches the end with the last partial batch delivered; `ENOSPC` on
  LRU/hash maps means the output buffer cannot hold one whole bucket — the
  cursor is unchanged, so the caller MUST grow the buffer (double, up to 3
  retries from a start of `sqrt(2·max_entries)` rounded up) and retry the
  same cursor. Batches are not atomic with respect to concurrent datapath
  writes; an entry may be seen twice or missed if it moves buckets. Count
  operations (`BatchCount`) accept this.
- **Iteration under concurrent modification** (`get_next_key` walk, used
  where batch is unavailable or for small maps) follows the reference's
  *reliable dump*: keep `prev`, `current`, `next`; after `get_next_key(current)`,
  re-`lookup(current)`; if it vanished, restart from `prev` once (then from
  `next`), counting `interrupted`/`key_fallback`; cap total lookups at
  4 × `max_entries` and return `ErrMaxLookup` beyond that; `ENOENT` from
  `get_next_key` ends the walk with `completed = true`. Dump statistics
  (lookups, failed, interrupted, fallbacks, completed) are exported (§8).
- **LRU eviction as seen by GC**: LRU maps never return `E2BIG`; when full,
  the kernel evicts from a per-CPU free list (or the common list without
  `NO_COMMON_LRU`). GC therefore MUST NOT infer "map full" from update
  failures; it reads the fill ratio (count / max) and the datapath's
  `CT_FILL_UP`/`NAT_FILL_UP` signals. Because `NO_COMMON_LRU` sizes are
  rounded up by the kernel to a multiple of possible CPUs, the agent MUST
  round `max_entries` the same way before creating such maps (otherwise the
  compatibility check of §3.2 fails on every restart and recreates the map).
- **Per-CPU maps** (`cilium_metrics`, `cilium_policystats`,
  `cilium_snat_v{4,6}_alloc_retries`, `cilium_percpu_trace_id`,
  `cilium_xdp_scratch`): a lookup returns `possible_cpus` values, each padded
  to 8 bytes; consumers sum `count`/`bytes`/`packets` across CPUs for metrics
  and MUST treat the per-CPU array as opaque otherwise. Deleting a per-CPU
  hash entry drops all CPUs' values.
- **Map-in-map**: outer updates take the inner map *fd* as value; readers see
  the inner map *id*. Inner maps are created unpinned and released when the
  outer slot is overwritten or deleted and the creating fd is closed. Inner
  map spec must match the outer's declared inner spec (type, key/value size,
  max entries, flags).
- **Value cache and error resolver** (agent-owned maps: lxc, ipcache, ipmasq,
  encrypt, vtep, NAT, egress): the desired state per key is kept in memory;
  a failed update is retried by a controller with a 5 s minimum interval and
  a cap of 512 outstanding errors. flowsdn implements this once in the map
  wrapper crate and the table-driven reconciler (ADR-0004) uses the same
  primitive; the "two models" question of inventory 02 is resolved in favour
  of the reconciler for every map whose source of truth is a table, with the
  cache kept only for maps written from many call sites (lxc, ipcache).
- **Event buffers** (`bpf-map-event-buffers`): a per-map ring of the last N
  update/delete events with TTL, exposed by `GET /map/{name}/events`.

## 4. Data model

All structures are little-endian host layout except fields marked `be`
(network byte order). `#[repr(C)]` with explicit padding fields; where the C
struct is `__packed`, the Rust type is `#[repr(C, packed)]` and accessed
through copies. Offsets are bytes. Every type in this section is exported by
`flowsdn-bpf-abi` and is `no_std`, `Copy`, `aya::Pod`.

### 4.1 Building blocks

| Type | Size | Layout |
|---|---|---|
| `v4addr` | 4 | `addr[4]` (be32) |
| `v6addr` | 16, align 1 (packed) | `addr[16]` |
| `macaddr` | 8 | `addr[6]` @0, pad @6 (2). As a config value the pad is zero |
| `lpm_trie_key` | 4 | `prefixlen` u32 @0, counted from offset 4 of the enclosing key |
| `ipv4_ct_tuple` (packed) | 14 | `daddr` be32 @0, `saddr` be32 @4, `dport` be16 @8, `sport` be16 @10, `nexthdr` u8 @12, `flags` u8 @13. Address fields are named for the *reply* direction; ports for the original direction. `flags`: 0 OUT, 1 IN, 2 RELATED, 4 SERVICE |
| `ipv6_ct_tuple` (packed) | 38 | `daddr` 16 @0, `saddr` 16 @16, `dport` @32, `sport` @34, `nexthdr` @36, `flags` @37 |
| `lpm_v4_key` | 8 | `prefixlen` @0, `addr[4]` @4 |
| `lpm_v6_key` | 20 | `prefixlen` @0, `addr[16]` @4 |
| `lpm_val` | 1 | `flags` u8 |

### 4.2 CT and NAT values

`ct_entry` (56, align 8):

| Off | Size | Field |
|---|---|---|
| 0 | 16 | union: `nat_addr` v6addr (CT_EGRESS) **or** {`reserved0` u64 @0, `backend_id` u64 @8} (CT_SERVICE) |
| 16 | 8 | `packets` u64 |
| 24 | 8 | `bytes` u64 |
| 32 | 4 | `lifetime` u32 (mono seconds/8 scaled) |
| 36 | 2 | bitfield u16, LSB first: `rx_closing`:1, `tx_closing`:1, `reserved1`:1, `lb_loopback`:1, `seen_non_syn`:1, `node_port`:1, `proxy_redirect`:1, `dsr_internal`:1, `from_l7lb`:1, `reserved2`:1, `from_tunnel`:1, `reserved3`:5 |
| 38 | 2 | `rev_nat_index` u16 |
| 40 | 2 | `nat_port` be16 |
| 42 | 1 | `tx_flags_seen` u8 |
| 43 | 1 | `rx_flags_seen` u8 |
| 44 | 4 | `src_sec_id` u32 — **offset frozen** (proxies) |
| 48 | 4 | `last_tx_report` u32 |
| 52 | 4 | `last_rx_report` u32 |

`nat_entry` (32): `created` u64 @0, `needs_ct` u64 @8 (bit 0 only), `pad1` @16, `pad2` @24.
`ipv4_nat_entry` (40): `common` @0 (32); union @32: `to_saddr` be32 @32 + `to_sport` be16 @36 (aliases `to_daddr`/`to_dport`, `nat_info` = `lb4_reverse_nat`); pad @38 (2).
`ipv6_nat_entry` (56): `common` @0; union @32: `to_saddr` v6addr @32 + `to_sport` be16 @48 (aliases as above); pad @50 (6).

### 4.3 Load balancer

| Type | Size | Layout |
|---|---|---|
| `lb4_key` | 12 | `address` be32 @0, `dport` be16 @4, `backend_slot` u16 @6, `proto` u8 @8, `scope` u8 @9, `pad[2]` @10 |
| `lb6_key` | 24 | `address` v6addr @0, `dport` @16, `backend_slot` @18, `proto` @20, `scope` @21, `pad[2]` @22 |
| `lb4_service` / `lb6_service` | 12 | union u32 @0 {`backend_id` \| `affinity_timeout` (upper 8 bits algorithm 1 random / 2 maglev, lower 24 seconds) \| `l7_lb_proxy_port` host order}, `count` u16 @4, `rev_nat_index` u16 @6, `flags` u8 @8, `flags2` u8 @9, `qcount` u16 @10 |
| `lb4_backend` | 12 | `address` be32 @0, `port` be16 @4, `proto` u8 @6, `flags` u8 @7, `cluster_id` u16 @8, `zone` u8 @10, `pad` @11 |
| `lb6_backend` | 24 | `address` v6addr @0, `port` @16, `proto` @18, `flags` @19, `cluster_id` @20, `zone` @22, `pad` @23 |
| `lb4_health` / `lb6_health` | 12 / 24 | `peer` = `lb4_backend` / `lb6_backend` |
| `lb4_reverse_nat` (packed) | 6 | `address` be32 @0, `port` be16 @4 |
| `lb6_reverse_nat` (packed) | 18 | `address` v6addr @0, `port` be16 @16 |
| `lb4_affinity_key` (packed) | 16 | `client_id` @0 (8): union {`client_ip` u32 @0 \| `client_cookie` u64 @0}, `rev_nat_id` u16 @8, `netns_cookie`:1/`reserved`:7 u8 @10, `pad1` @11, `pad2` u32 @12 |
| `lb6_affinity_key` (packed) | 24 | `client_id` @0 (16): union {`client_ip` v6addr \| `client_cookie` u64}, `rev_nat_id` @16, bits @18, `pad1` @19, `pad2` u32 @20 |
| `lb_affinity_val` (packed) | 16 | `last_used` u64 @0, `backend_id` u32 @8, `pad` @12 |
| `lb_affinity_match` (packed) | 8 | `backend_id` u32 @0, `rev_nat_id` u16 @4, `pad` @6 |
| `lb4_src_range_key` | 12 | `prefixlen` @0 (static 32 bits + CIDR bits), `rev_nat_id` u16 @4, `pad` u16 @6, `addr` be32 @8 |
| `lb6_src_range_key` | 24 | `prefixlen` @0 (static 32), `rev_nat_id` @4, `pad` @6, `addr` v6addr @8 |
| `ipv4_revnat_tuple` | 16 | `cookie` u64 @0, `address` be32 @8, `port` be16 @12, `pad` u16 @14 |
| `ipv4_revnat_entry` | 8 | `address` be32 @0, `port` be16 @4, `rev_nat_index` u16 @6 |
| `ipv6_revnat_tuple` | 32 | `cookie` @0, `address` v6addr @8, `port` @24, `pad` @26, pad @28 (4) |
| `ipv6_revnat_entry` | 20 | `address` v6addr @0, `port` @16, `rev_nat_index` @18 |
| `skip_lb4_key` | 16 | `netns_cookie` u64 @0, `address` u32 @8, `port` u16 @12, `pad` @14 |
| `skip_lb6_key` | 32 | `netns_cookie` @0, `address` v6addr @8, `pad` u32 @24, `port` u16 @28, `pad2` @30 |
| `lb_act_key` | 4 | `svc_id` u16 @0, `zone` u8 @2, `pad` @3 |
| `lb_act_value` | 8 | `opened` u32 @0, `closed` u32 @4 |
| maglev inner value | 4·N | `u32[N]` backend ids, N = `bpf-lb-maglev-table-size` (default 16381; build-time stand-in 32749 → 130996 B). The registry patch MUST set the inner value size to 4·N |

### 4.4 Policy, endpoints, identities, nodes

| Type | Size | Layout |
|---|---|---|
| `policy_key` | 12 | `prefixlen` u32 @0, `sec_label` u32 @4, `egress`:1/`pad`:7 u8 @8, `protocol` u8 @9, `dport` be16 @10. Static prefix = 40 bits (sec_label + egress byte); `prefixlen` = 40 + 8 (protocol, if not wildcard) + port prefix bits (0..16). `AllPorts` = dport 0 with port bits 0; `SinglePortPrefixLen` = 16 |
| `policy_entry` | 12 | `proxy_port` be16 @0, `deny`:1/`reserved`:2/`lpm_prefix_length`:5 u8 @2 (prefix length beyond the static 40), `auth_type`:7/`has_explicit_auth_type`:1 u8 @3, `precedence` u32 @4, `cookie` u32 @8 |
| `policy_stats_key` | 12 | `endpoint_id` u16 @0, `pad1` @2, `prefix_len` u8 @3, `sec_label` u32 @4, `egress`:1/`pad`:7 @8, `protocol` @9, `dport` be16 @10 |
| `policy_stats_value` | 16 | `packets` u64 @0, `bytes` u64 @8 |
| `endpoint_key` (packed) | 20 | union {`ip4` v4addr @0 \| `ip6` v6addr @0} (16), `family` u8 @16 (1 = IPv4, 2 = IPv6), `key` u8 @17, `cluster_id` u16 @18 |
| `endpoint_info` | 48 | `ifindex` u32 @0, `unused` u16 @4, `lxc_id` u16 @6, `flags` u32 @8 (1 HOST, 2 ATHOSTNS, 4 NO_SNAT_V4, 8 NO_SNAT_V6), `rt_info` u32 @12, `mac` u64 @16, `node_mac` u64 @24, `sec_id` u32 @32, `parent_ifindex` u32 @36, `pad[2]` u32 @40 |
| `ipcache_key` (packed) | 24 | `prefixlen` u32 @0, `cluster_id` u16 @4, `pad1` u8 @6, `family` u8 @7, union {`ip4` @8 \| `ip6` @8} (16). Static prefix = 32 bits; full-match lookups use 32+32 (IPv4) or 32+128 (IPv6). **Frozen for Envoy** |
| `remote_endpoint_info` | 24 | `sec_identity` u32 @0, `tunnel_endpoint` union {`ip4` @4 \| `ip6` @4} (16), `pad` u16 @20, `key` u8 @22 (IPsec), flags u8 @23: bit0 `skip_tunnel`, bit1 `has_tunnel_ep`, bit2 `ipv6_tunnel_ep`, bit3 `remote_cluster`, bits 4–7 pad. **Frozen for Envoy** |
| `node_key` | 20 | `pad1` u16 @0, `pad2` u8 @2, `family` u8 @3, union {`ip4` @4 \| `ip6` @4} (16) |
| `node_value` | 4 | `id` u16 @0, `spi` u8 @2, `pad` @3 |
| `subnet_key` (packed) | 24 | `prefixlen` @0, `pad0` u16 @4, `pad1` u8 @6, `family` u8 @7, union ip @8 (16); static prefix 32 |
| `subnet_value` | 4 | `identity` u32 |

### 4.5 Telemetry, config and feature maps

| Type | Size | Layout |
|---|---|---|
| `metrics_key` | 8 | `reason` u8 @0 (0 forwarded, else drop reason), `dir`:2/`pad`:6 u8 @1 (1 ingress, 2 egress, 3 service), `line` u16 @2, `file` u8 @4, `reserved[3]` @5 |
| `metrics_value` | 16 | `count` u64 @0, `bytes` u64 @8 |
| `ratelimit_key` | 8 | `usage` u32 @0 (1 ICMPv6, 2 events map, 3 socket events), `netdev_idx` u32 @4 |
| `ratelimit_value` | 16 | `last_topup` u64 @0, `tokens` u64 @8 |
| `ratelimit_metrics_key` / `_value` | 4 / 8 | `usage` u32 / `dropped` u64 |
| `device_state` | 16 | `mac` macaddr @0, `l3`:1/`pad0`:7 u8 @8, `pad1` @9, `pad2` u16 @10, `pad3` u32 @12 |
| `xdp_scratch` | 28 | `META_PIVOT` = sizeof(`__sk_buff.cb`) 20 + 2·4; slots 0–4 mirror `cb[]`, slot 5 `RECIRC_MARKER`, slot 6 `XFER_MARKER` |
| `auth_key` | 12 | `local_sec_label` u32 @0, `remote_sec_label` u32 @4, `remote_node_id` u16 @8 (0 local), `auth_type` u8 @10, `pad` @11 |
| `auth_info` | 8 | `expiration` u64 |
| `edt_id` | 8 | `id` u32 @0, `direction` u8 @4, `pad[3]` @5 |
| `edt_info` | 56 | `bps` u64 @0, `t_last` u64 @8, union {`t_horizon_drop` \| `tokens`} u64 @16, `prio` u32 @24, `pad_32` u32 @28, `pad[3]` u64 @32 |
| `egress_gw_policy_key` | 12 | `prefixlen` @0 (static 32 + daddr bits), `saddr` be32 @4, `daddr` be32 @8 |
| `egress_gw_policy_entry` (v1, deferred) | 8 | `egress_ip` be32 @0, `gateway_ip` be32 @4 |
| `egress_gw_policy_entry_v2` | 28 | `egress_ip` @0, `gateway_ip` @4, `reserved[3]` u32 @8, `egress_ifindex` u32 @20, `reserved2` u32 @24 |
| `egress_gw_policy_key6` | 36 | `prefixlen` @0 (static 128), `saddr` v6addr @4, `daddr` v6addr @20 |
| `egress_gw_policy_entry6` | 40 | `egress_ip` v6addr @0, `gateway_ip` be32 @16, `reserved[3]` @20, `egress_ifindex` @32, `reserved2` @36 |
| `encrypt_config` (packed) | 1 | `encrypt_key` u8 |
| `l2_responder_v4_key` | 8 | `ip4` v4addr @0, `ifindex` u32 @4 |
| `l2_responder_v6_key` | 24 | `ip6` v6addr @0, `ifindex` u32 @16, `pad` u32 @20 |
| `l2_responder_stats` | 8 | `responses_sent` u64 |
| `ipv4_frag_id` (packed) | 12 | `daddr` be32 @0, `saddr` be32 @4, `id` be16 @8, `proto` u8 @10, `pad` @11 |
| `ipv6_frag_id` (packed) | 40 | `id` be32 @0, `proto` u8 @4, `pad[3]` @5, `saddr` v6addr @8, `daddr` v6addr @24 |
| `ipv4_frag_l4ports` / `ipv6_frag_l4ports` (packed) | 4 | `sport` be16 @0, `dport` be16 @2 |
| `srv6_vrf_key4` | 12 | `prefixlen` @0 (static 32), `src_ip` u32 @4, `dst_cidr` u32 @8 |
| `srv6_vrf_key6` | 36 | `prefixlen` @0 (static 128), `src_ip` v6addr @4, `dst_cidr` v6addr @20 |
| `srv6_policy_key4` | 12 | `prefixlen` @0 (static 32), `vrf_id` u32 @4, `dst_cidr` u32 @8 |
| `srv6_policy_key6` | 24 | `prefixlen` @0 (static 32), `vrf_id` u32 @4, `dst_cidr` v6addr @8 |
| `vtep_key` | 4 | `vtep_ip` u32 |
| `vtep_value` | 16 | `vtep_mac` u64 @0, `tunnel_endpoint` u32 @8, pad @12 |
| `mcast_group_v4` | 4 | be32 group address |
| `mcast_subscriber_v4` | 12 | `saddr` be32 @0, `ifindex` u32 @4, `pad1` u16 @8, `pad2` u8 @10, `flags` u8 @11 |
| `ct_buffer4` / `ct_buffer6`, `nodeport_nat_info` | object-private | in-program scratch; layout owned by the datapath spec, never read from userspace |

### 4.6 Notification layouts (perf samples)

Common header (8): `type` u8 @0, `subtype` u8 @1, `source` u16 @2 (endpoint id
of the emitting program: `LXC_ID` in lxc, `host_ep_id` in host, 0 in
overlay/xdp/wireguard/sock), `hash` u32 @4 (skb hash).
Capture header (16): common + `len_orig` u32 @8, `len_cap` u16 @12,
`version` u8 @14, `ext_version` u8 @15 (0; extension lengths are 0 in 1.20).

Message types: 0 unspec, 1 drop, 2 debug, 3 debug-capture, 4 trace, 5
policy-verdict, 6 capture (enum kept, no emitter), 7 trace-sock, 129
access-log (agent), 130 agent.

| Struct | Size / version | Layout after the header |
|---|---|---|
| `trace_notify` | 56, version 2 (decoders accept v0 32, v1 48) | `src_label` u32 @16, `dst_label` u32 @20, `dst_id` u16 @24, `reason` u8 @26, `flags` u8 @27 (bit0 IPv6), `ifindex` u32 @28, union {`orig_ip4` \| `orig_ip6`} @32 (16), `ip_trace_id` u64 @48. `subtype` = observation point 0..13 (`TO_LXC, TO_PROXY, TO_HOST, TO_STACK, TO_OVERLAY, FROM_LXC, FROM_PROXY, FROM_HOST, FROM_STACK, FROM_OVERLAY, FROM_NETWORK, TO_NETWORK, FROM_CRYPTO, TO_CRYPTO`); `reason` low 7 bits = CT status, bit 7 `ENCRYPTED` |
| `drop_notify` | 48, version 3 (v1 36, v2 40) | `src_label` @16, `dst_label` @20, `dst_id` u32 @24, `line` u16 @28, `file` u8 @30, `ext_error` s8 @31, `ifindex` u32 @32, `flags` u8 @36, `pad2[3]` @37, `ip_trace_id` u64 @40. `subtype` = drop reason (`drop_reasons.h`, datapath spec) |
| `debug_msg` | 20 | common header, `arg1` u32 @8, `arg2` @12, `arg3` @16; `subtype` = `DBG_*` |
| `debug_capture_msg` | 24 | capture header, `arg1` @16, `arg2` @20 |
| `policy_verdict_notify` | 40 | `remote_label` u32 @16, `verdict` s32 @20, `dst_port` u16 @24, `proto` u8 @26, bits u8 @27: `dir`:2, `ipv6`:1, `match_type`:3, `audited`:1, `l3`:1; `auth_type` u8 @28, `pad1[3]` @29, `cookie` u32 @32, `pad2` u32 @36 |
| `trace_sock_notify` | 40 (no common header) | `type` u8 @0 (=7), `xlate_point` u8 @1, `l4_proto` u8 @2, `ipv6`:1/`pad`:7 @3, `dst_port` u16 @4, `pad2` u16 @6, `sock_cookie` u64 @8, `cgroup_id` u64 @16, `dst_ip` union {v4 \| v6} @24 (16) |
| `signal_msg` (`cilium_signals`) | 16 | `signal_nr` u32 @0, union @4 {`proto` u32 \| `auth` `auth_key` (12)}; the emitter sends only `4 + sizeof(member)` bytes |

### 4.7 skb mark contract

Bits 8..15 are the magic (`MARK_MAGIC_KEY_MASK 0xFF00`, host-relevant nibble
`0x0F00`), bits 16..31 the payload, bits 0..7 either the upper 8 identity bits
(`MARK_MAGIC_IDENTITY`: identity = `(mark >> 16) | ((mark & 0xFF) << 16)`) or
the cluster id (`MARK_MAGIC_CLUSTER_ID` = `MARK_MAGIC_TO_PROXY`). Values are
frozen: `TO_PROXY 0x0200` (proxy port), `SNAT_DONE 0x0300`, `OVERLAY 0x0400`,
`EGW_DONE 0x0500`, `SKIP_TPROXY 0x0800`, `PROXY_EGRESS_EPID 0x0900` (endpoint
id), `PROXY_INGRESS 0x0A00`, `PROXY_EGRESS 0x0B00`, `HOST 0x0C00`, `DECRYPT
0x0D00` (= `HEALTH` for sock LB), `ENCRYPT 0x0E00` (key index in bits 12..15,
node id in 16..31), `IDENTITY 0x0F00`. `tc_index` bits 1/2/4/8/16 and the
`cb[]` slot aliases are datapath-internal (spec 02).

## 5. Algorithms

### 5.1 Map sizing

1. Explicitly set keys win. Otherwise, with `bpf-map-dynamic-size-ratio`
   r > 0 (default 0.0025): `budget = total_ram · r`;
   `default_total = 524288·S_ct + 262144·S_ct + 524288·S_nat + 524288·S_neigh + 262144·S_sockrev`
   where the element sizes are key+value of the **IPv6** variants (CT 38+56,
   NAT 38+56, neigh 16+8, sock-rev 32+20); each map gets
   `entries = default · budget / default_total`, rounded up to a multiple of
   possible CPUs when `bpf-distributed-lru` is on (the kernel rounds
   `NO_COMMON_LRU` maps up itself, and a mismatch would make §3.2 recreate the
   map every start), clamped to [min, 2^24] with mins TCP 2^17, ANY 2^16, NAT
   2^17, sock-rev 2^16, and NAT additionally capped at TCP+ANY.
2. `bpf-neigh-global-max` defaults to the NAT size.
3. `bpf-policy-map-max` is clamped to [256, 65536]; `cilium_policystats` is
   sized to policy-map-max × (expected endpoints) by registry patch.
4. LB maps default to `bpf-lb-map-max` unless the per-map key is set; the
   Maglev inner value size is `4 × bpf-lb-maglev-table-size` and the table
   size MUST be prime (validated by the LB spec).
5. Registry: sizes and flags are patches `{max_entries, flags, inner}` keyed
   by ELF map name, collected during startup wiring and frozen before the
   first load; the loader applies them to the object spec and the agent uses
   the same patched spec for `OpenOrCreate`, so both sides agree and §3.2
   never sees a self-inflicted incompatibility.

### 5.2 Reachability and dead-code elimination

Inputs: the object's programs (instruction streams with relocation metadata
naming the map and offset of every `ld_imm64` map-value load), the
`.rodata.config` values after patching, the set of entrypoints (sections
`classifier/entry`, `xdp/entry`, `cgroup/*`, `iter/*`) and tail slots.

Tier A (MUST, mirrors the reference):

1. Split each program into basic blocks (leaders: first instruction, branch
   targets, fall-throughs after branches/exits; each block ends at a branch,
   exit, or before a leader).
2. Walk blocks from the entry. When a block ends in `J{op}Imm rX, imm`,
   backtrack within the block (rolling into a single predecessor when the
   block top is reached) for `ldx{b,h,w,dw} rX = [rY + 0]` and then for the
   `ld_imm64 rY = map_value(.rodata.config, off)` that fed `rY`. If found,
   and the variable is `const`, evaluate the compare against the patched
   value: the branch is *always* or *never* taken and only that successor is
   visited. Any pattern mismatch is conservative: both successors are live.
   Each block is evaluated once.
3. A tail program is live if some live block of a live program tail-calls
   its slot (`tail_call_static` with constant r2/r3); the walk is transitive
   through slots. Unreachable tail programs are removed from the collection
   (step 7 of §3.5) so they are neither verified nor inserted.
4. A map is live if a live block of a live program references it; dead maps
   are removed and their loads poisoned (step 9).

Outputs: the pruned collection and, in debug mode, the list of maps the
*kernel* freed after load (maps referenced only by instructions the
verifier's own DCE removed) so the pass can be tuned.

Tier B (MAY; decision recorded in §12.1): physically elide dead blocks.
If implemented it MUST: remove whole blocks only; recompute every relative
jump offset (16-bit `off` and 32-bit `imm` for `JA` long jumps) over the
surviving stream; rewrite `.BTF.ext` `func_info` insn offsets, `line_info`
insn offsets (dropping entries for removed instructions) and `core_relo`
offsets; keep `ld_imm64` pairs together; and verify by reloading the object
that instruction counts fall and behavior is unchanged (§9.3). The kernel
already skips never-taken branches on frozen read-only data (≥ 5.2), so
Tier B buys instruction *count* (1M limit, program size) rather than
verifier *state* budget; it is justified only if a §12.2 matrix would
otherwise be needed.

### 5.3 Tail-call and entrypoint resolution

Entrypoints are the programs in `*/entry` sections; tail programs are in
`*/tail/<N>` sections. The loader MUST verify: every slot in
`flowsdn-bpf-abi::tailcall::SLOTS` that the object declares exists exactly
once; no two programs claim one slot; slot < 50. Population is initial map
contents (§3.8). Programs assigned to a `cilium_call_policy` slot are not
tail programs of the object; they are entrypoint-like (`cil_lxc_policy`,
`cil_lxc_policy_egress`, `cil_host_policy`) and are "attached" by array
insertion.

### 5.4 `.data.aux` per-CPU scratch

`DEFINE_AUX` globals live in `.data.aux`; `AUX(name)` computes
`&var + min(stride · cpu, max_off)`. The loader MUST: round the section size
up to the cache line (`stride`), set `.rodata.aux::_aux_stride = stride`,
replace the `.data.aux` map value with `possible_cpus · stride` zeroed bytes,
and set `_aux_max_off = possible_cpus · stride − stride`. **CONFIRMED**: the
C side reads `_aux_stride` and has no other assumption; the Go side uses
64 B on x86-64 and 128 B on arm64 (Go's `CacheLinePad`). flowsdn MUST use the
same per-target constants (64 / 128) rather than the runtime cache line, so
a Rust and a Go agent produce identical map value sizes on the same node.

The initial pure layout planner accepts only existing nonempty sections and
nonzero possible-CPU counts, rejects rounding or multiplication beyond the u32
map-value size ABI, and returns stride, total value size and maximum offset.
The owner still creates zeroed storage and checks kernel-specific size limits;
an absent scratch section does not require a layout. This arithmetic helper
performs no allocation or map mutation.

### 5.5 Upgrade of a whole node

Order at agent start: mount bpffs → open/create agent-owned global maps
(§3.2) → restore endpoints → sweep (§3.4) → load and attach host object
(`cilium_host` from/to, `cilium_net` to_host, each native device from/to,
then commit) → overlay/wireguard/xdp objects (each with its own commit) →
socket LB cgroup attach → per-endpoint reload (§3.6). Each object's commit is
independent; a failure in one object leaves the others either fully old or
fully new.

## 6. Configuration

### 6.1 Keys with effect in this area

| Key | Type / default | Effect |
|---|---|---|
| `bpf-root` | path, `/sys/fs/bpf` | bpffs root (§3.1) |
| `preallocate-bpf-maps` | bool, false | clears `NP` on CP maps |
| `bpf-distributed-lru` | bool, false | sets `NCL` on LRUF maps; rounds sizes to possible CPUs |
| `bpf-map-dynamic-size-ratio` | float (0,1], 0.0025; 0 disables | §5.1 |
| `bpf-ct-global-tcp-max`, `bpf-ct-global-any-max`, `bpf-nat-global-max`, `bpf-neigh-global-max`, `bpf-sock-rev-map-max`, `bpf-auth-map-max`, `bpf-fragments-map-max`, `egress-gateway-policy-map-max`, `bpf-policy-map-max`, `bpf-lb-*-map-max`, `bpf-lb-maglev-table-size` | int | map sizes (§2.2, §5.1); changing one recreates the map empty on next start (§3.2 step 5) |
| `max-connected-clusters` | 255 / 511 | per-cluster outer array size and `cluster_id_bits` |
| `enable-tcx` | bool, true | required for supported tc attachment; false is rejected, not a clsact fallback (§3.9, #54) |
| `bpf-filter-priority` | u16, 1 | retained compatibility setting for legacy-filter inspection/cleanup; no new clsact filter is installed |
| `datapath-mode` | `veth` | `netkit`/`netkit-l2` select netkit links |
| `bpf-lb-acceleration` | `disabled` | XDP mode |
| `cgroup-root` | `/run/cilium/cgroupv2` | socket LB attach target |
| `trace-payloadlen`, `trace-payloadlen-overlay` | 128 / 192 | `cap_len` bound, `.rodata.config` |
| `bpf-events-default-rate-limit`, `bpf-events-default-burst-limit` | 0 (off) | events token bucket |
| `monitor-aggregation` | `medium` | trace verbosity (`MONITOR_AGGREGATION` → `.rodata.config`) |
| `bpf-map-event-buffers` | map name→size | per-map event ring |
| `enable-ipv4`, `enable-ipv6`, `kube-proxy-replacement`, `enable-bpf-masquerade`, `enable-ipv4-fragments-tracking`, `enable-ipv6-fragments-tracking`, `enable-health-datapath`, `bpf-lb-algorithm`, `enable-ip-masq-agent`, `enable-srv6`, `enable-xdp-prefilter` | as reference | drive the disabled-map sweep (§3.4) |

### 6.2 Accepted but ignored

`bpf-compile-debug`, `bpf-dir`/`bpf-lib` (clang include paths), `enable-datapath-plugins`
(deferred), any `*-iptables-*` key (ADR-0003). Each logs once at startup.

### 6.3 Reference compile-time defines reclassified (layer 1)

Value-like → `.rodata.config` or registry: `CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES`,
`CILIUM_IPV6_FRAG_MAP_MAX_ENTRIES`, `CILIUM_LB_*_MAP_MAX_ENTRIES` (7),
`CT_CLOSE_TIMEOUT`, `CT_CONNECTION_LIFETIME_{TCP,NONTCP}`, `CT_REPORT_FLAGS`,
`CT_REPORT_INTERVAL`, `CT_SERVICE_CLOSE_REBALANCE`,
`CT_SERVICE_LIFETIME_{TCP,NONTCP}`, `CT_SYN_TIMEOUT`, `CT_MAP_SIZE_{TCP,ANY}`,
`DSR_ENCAP_MODE` (0 none / 1 IPIP / 2 Geneve), `ENCAP4_IFINDEX`,
`ENCAP6_IFINDEX`, `ENDPOINTS_MAP_SIZE`, `HOST_NETNS_COOKIE`,
`IPCACHE_MAP_SIZE`, `IPV4_DIRECT_ROUTING`, `IPV4_ENCRYPT_IFACE`,
`IPV4_GATEWAY`, `IPV4_RSS_PREFIX{,_BITS}`, `IPV6_RSS_PREFIX{,_BITS}`,
`IPV4_SNAT_EXCLUSION_DST_CIDR{,_LEN}`, `L2_RESPONDER_MAP{4,6}_SIZE`,
`LB_MAGLEV_LUT_SIZE`, `LB{4,6}_REVERSE_NAT_SK_MAP_SIZE`,
`LB{4,6}_SRC_RANGE_MAP_SIZE`, `METRICS_MAP_SIZE`, `MKE_HOST`,
`NODE_MAP_SIZE`, `NODEPORT_NEIGH{4,6}_SIZE`, `POLICY_PROG_MAP_SIZE`,
`POLICY_MAP_SIZE`, `POLICY_STATS_MAP_SIZE`, `SERVICE_NO_BACKEND_RESPONSE`,
`SNAT_COLLISION_RETRIES`, `SNAT_MAPPING_IPV{4,6}_SIZE`, `STRICT_IPV4_NET{,_SIZE}`,
`STRICT_IPV4_OVERLAPPING_CIDR`, `TUNNEL_MODE`, `VTEP_MAP_SIZE`,
`TRACE_SOCK_NOTIFY`, `MONITOR_AGGREGATION`, `VLAN_FILTER` (becomes a small
HASH map keyed `{ifindex, vlan}` per inventory 01).

Shape-like → `bool` `.rodata.config`: `DISABLE_EXTERNAL_IP_MITIGATION`,
`ENABLE_DSR`, `ENABLE_DSR_BYUSER`, `ENABLE_DSR_ICMP_ERRORS`,
`ENABLE_HEALTH_CHECK`, `ENABLE_HOST_FIREWALL`, `ENABLE_IP_MASQ_AGENT_IPV{4,6}`,
`ENABLE_IPV4`, `ENABLE_IPV6`, `ENABLE_L7_LB`, `ENABLE_MASQUERADE_IPV{4,6}`,
`ENABLE_MKE`, `ENABLE_NAT_46X64{,_GATEWAY}`, `ENABLE_NODEPORT`,
`ENABLE_NODEPORT_ACCELERATION`, `ENABLE_SCTP`, `ENABLE_SOCKET_LB_{FULL,HOST_ONLY,PEER}`,
`ENABLE_SRV6`, `ENABLE_SRV6_SRH_ENCAP`, `ENABLE_VTEP`,
`ENCRYPTION_STRICT_MODE_EGRESS`, plus the endpoint-level `DEBUG`,
`DROP_NOTIFY`, `TRACE_NOTIFY`, `POLICY_VERDICT_NOTIFY`, `ENABLE_ROUTING`,
`HOST_ENDPOINT`, `LOCAL_DELIVERY_METRICS`.

Flags-only: `PREALLOCATE_MAPS`, `NO_COMMON_MEM_MAPS` → registry flag patches.

## 7. Failure modes

| Failure | Behavior |
|---|---|
| bpffs cannot be mounted anywhere | fatal at startup |
| kernel lacks a required map type / flag (`RO` < 5.2, batch < 5.6, tcx < 6.6) | startup capability check (ADR-0001: no runtime probing beyond a refusing check) fails with the missing feature named; absence of the required tcx/netkit attach capability is fatal; no clsact fallback |
| pinned map incompatible with spec | agent-owned: recreated empty (connections in CT/NAT lost, logged with old/new attributes); loader-owned: replaced at commit, old map serves until then |
| `RO` mismatch | handled silently (§3.2 steps 3–4) |
| map full (`E2BIG` on HASH/LPM) | update fails; error resolver retries; pressure metric near 1.0; LRU maps never fail but evict — GC and `*_FILL_UP` signals are the only indication |
| batch `ENOSPC` | grow and retry same cursor, max 3 doublings, then error |
| iteration never completes | abort at 4 × max_entries lookups with `ErrMaxLookup`, stats exported |
| verifier rejects an object | load fails before any attach; datapath unchanged; log includes the verifier log; for XDP the permutation list is exhausted first |
| attach fails mid-object | no commit; new collection closed; old programs keep running (§3.6) |
| agent killed between policy-array insert and commit | endpoint may see missed tail calls until next regeneration (accepted, as in the reference); regeneration is idempotent |
| link defunct (`ENOLINK`) | unpin and re-attach fresh |
| device disappears during attach | error surfaced; endpoint regeneration retries |
| cgroup root is not cgroup2 and mount fails | socket LB disabled with error; other datapath continues |
| stale pins from a previous release | sweep removes them at start; a pin the sweep does not recognise is left alone and logged |
| `.rodata.config` symbol missing or wrong size in the object | load refused (build/ABI mismatch, §9.1 catches this in CI) |
| tail slot collision or unknown slot | load refused |
| perf ring overrun | `PERF_RECORD_LOST` → `RecordLost` payload, `monitor_lost_events` metric; datapath unaffected |
| events rate limit exceeded | notifications dropped, counted in `cilium_ratelimit_metrics` |

## 8. Observability

Metrics (reference names, labels kept so dashboards work):
`cilium_bpf_map_ops_total{map_name,operation,outcome}`,
`cilium_bpf_map_pressure{map_name}` (fill ratio, for maps with the pressure
metric enabled; `map_name` has the `_v2`/`_%05d` suffix stripped by the
reference regexps: `_v[0-9]+_reserved_N`, `_reserved_N`, `_netdev_ns_N`,
`_overlay_N`, `_v[0-9]+_N`, `_N`), `cilium_bpf_maps_virtual_memory_max_bytes`,
`cilium_bpf_progs_virtual_memory_max_bytes`, `cilium_datapath_conntrack_dump_resets_total{area,name,family}`
(dump `interrupted`), `cilium_datapath_conntrack_gc_*`, `cilium_lost_events_total{source}`
(perf ring / observer queue), `cilium_bpf_syscall_duration_seconds{operation,outcome}`.

Logs: every pin replaced, every map recreated (with old and new attributes),
every missing required attach capability, every XDP permutation tried, every defunct link,
every stale pin removed, the applied constants per object at debug level.

REST: `GET /map` (all maps, `models.BPFMap`), `GET /map/{name}` (dump via key/
value `Display`), `GET /map/{name}/events?follow=`. Status: `bpf-root`
mount status and `cilium-dbg bpf mountfs show`.

Monitor events emitted by this area: none (it carries them).

## 9. Test plan

### 9.1 Layout tests (unit, run on every build)

- For every type in §4: `size_of` and every field offset asserted against the
  constants in this document (table-driven).
- BTF cross-check: load the reference `.o` BTF fixtures (copied under
  `testdata/` with attribution per `docs/licensing.md`) and the flowsdn
  object BTF; for every map, assert key/value type names, sizes and member
  offsets are identical. This replaces the reference `bpf_alignchecker`
  startup check with a CI check (no runtime alignchecker on the node).
- For every `.rodata.config` variable in the ABI table: present in the
  object's `.rodata.config` datasec with the declared size.
- For every tail slot declared by an object: exactly one program in
  `*/tail/<N>`.
- Notification structs: encode fixtures with known bytes (one per type and
  version) and decode with the monitor decoder; compare with the reference
  Go decoder's expected field values (test vectors copied with attribution).

### 9.2 Pin / rename / migrate (privileged, kernel)

- Create-or-open: fresh create pins; reopen reuses and keeps contents;
  changed `max_entries` recreates empty and logs; `RO` add → reuse without
  flag; `RO` remove → recreate.
- Per-object rename produces exactly the names of §3.3 for endpoint id 1,
  65535, ifindex 1..; sweep removes malformed and dead-endpoint pins, deletes
  the `cilium_call_policy` slot, keeps live ones; disabled-feature list per
  option combination.
- `.data.aux` sizing on a mocked possible-CPU count 1, 3, 64 on both
  cache-line constants.
- Maglev inner value size follows `bpf-lb-maglev-table-size`.

### 9.3 Loader and upgrade protocol (privileged)

- Load lxc/host objects with every entry of the config permutation set
  (`complexity-tests`-style): no verifier failure; Tier A prunes; assert no
  `DROP_MISSED_TAIL_CALL` is produced when each entrypoint is run with
  `BPF_PROG_RUN` on a packet fixture exercising every slot reachable for that
  config.
- Upgrade: load object A, attach, commit; load object B (different tail set),
  attach via link update, commit; assert during the whole sequence that a
  `BPF_PROG_RUN`-driven traffic loop never observes a missed tail call and
  that the `cilium_calls_*` pin id changes exactly once at commit.
- Rollback: inject an attach failure on the second hook; assert pins and
  links still reference the old programs and the new collection is closed.
- Policy-array ordering: assert `cilium_call_policy[epid]` is populated
  before the ingress link exists.
- Reachability Tier A unit tests over hand-built instruction streams (branch
  on const true/false, unknown, multi-predecessor rollover, `JA`, tail-call
  transitive liveness, dead-map poison).

### 9.4 Attach matrix (privileged, per kernel in the verifier matrix)

For each required kernel of `docs/kernel-requirements.md` (6.6, 6.12, 6.18):
tcx attach/update/detach on veth; refusal when tcx is disabled or unavailable,
and cleanup of legacy owned clsact filters; netkit attach when the required
netkit capabilities are present (6.8 upstream minimum); XDP generic on veth with all four permutations,
driver mode where a driver supports it, `EBUSY` netlink fallback after a
pre-existing netlink attach; cgroup link attach/update, `EPERM` → `PROG_ATTACH`
fallback after a pre-existing non-multi attach, defunct-link recreation after
the cgroup is removed; perf reader lost-sample accounting under overload;
batch lookup `ENOSPC` growth on an LRU map; reliable dump with a concurrent
deleter.

### 9.5 e2e

cilium-dbg (`bpf ct list`, `bpf ipcache list`, `bpf policy get`, `bpf lb list`,
`monitor`) from the reference release runs unmodified against a flowsdn node
and decodes everything; Envoy from the cilium/proxy image resolves identities
from `cilium_ipcache_v2`.

## 10. Kernel and platform requirements

Map types: `HASH`, `LRU_HASH`, `PERCPU_HASH`, `LRU_PERCPU_HASH`, `ARRAY`,
`PERCPU_ARRAY`, `PROG_ARRAY`, `PERF_EVENT_ARRAY`, `LPM_TRIE`, `ARRAY_OF_MAPS`,
`HASH_OF_MAPS`. Flags: `BPF_F_NO_PREALLOC`, `BPF_F_NO_COMMON_LRU`,
`BPF_F_RDONLY_PROG` (≥ 5.2, also needed for `.rodata` freezing),
`BPF_F_XDP_HAS_FRAGS` (≥ 5.18, probed by permutation). Syscalls:
`BPF_OBJ_PIN/GET`, `BPF_OBJ_GET_INFO_BY_FD`, `BPF_MAP_FREEZE` (≥ 5.2),
`BPF_MAP_*_BATCH` (≥ 5.6), `BPF_LINK_CREATE`, `BPF_LINK_UPDATE` (≥ 5.7),
`BPF_LINK_GET_INFO_BY_FD`, `BPF_PROG_ATTACH/DETACH` (fallback), `BPF_PROG_TEST_RUN`
(tests), `BPF_PROG_BIND_MAP` (optional).

Program types: `SCHED_CLS`, `XDP`, `CGROUP_SOCK_ADDR`, `CGROUP_SOCK`,
`TRACING` (iter). Attach types: `BPF_TCX_INGRESS/EGRESS` (≥ 6.6),
`BPF_NETKIT_PRIMARY/PEER` (≥ 6.7), `BPF_XDP` link (≥ 5.7),
`BPF_CGROUP_INET{4,6}_{CONNECT,BIND,POST_BIND,GETPEERNAME}`,
`BPF_CGROUP_UDP{4,6}_{SENDMSG,RECVMSG}`, `BPF_CGROUP_INET_SOCK_RELEASE`
(≥ 5.9), cgroup links (≥ 5.7), `BPF_TRACE_ITER` for tcp/udp (≥ 5.9) with
kfunc `bpf_sock_destroy` (≥ 6.4). Netlink: inspect/delete legacy owned
bpf filters for takeover cleanup, `IFLA_XDP`, `IFLA_NETKIT_*` (netkit
device creation, area 03). Filesystems: bpffs, cgroup2. Sysctl:
`net.core.bpf_jit_enable=1`, `kernel.unprivileged_bpf_disabled=1` (area 03).

The general-use target is Linux 6.6 LTS; the supported kernel line is 6.12
on both architectures, as fixed by `docs/kernel-requirements.md` (#54).
Required capabilities are checked at startup, including tcx and cgroup links;
version strings are not a substitute for feature checks. Features above the
minimum, including netkit, retain their explicit capability requirements.
Legacy clsact attachment and older-kernel cgroup fallbacks are not implemented.
The cgroup `EPERM` takeover path and driver-specific XDP fallbacks remain
because they address existing attachments/drivers on supported kernels.
These are implementation and validation targets, not a claim that a working
loader has already passed the privileged matrix.

arm64: BPF bytecode and all layouts are identical to x86-64; the `.data.aux`
stride constant is 128 (§5.4); mixing BPF-to-BPF calls with tail calls needs
≥ 6.0 on arm64 (datapath spec constraint, not this area); `for_each_map_elem`
over `HASH_OF_MAPS` inner maps (multicast) needs ≥ 6.0 on arm64. XDP driver
mode depends on the NIC driver; MikroTik/Rose targets use generic mode.
`possible_cpus` is read from `/sys/devices/system/cpu/possible` on both.

## 11. Rust design notes

Crates (workspace members; names final for this area):

- **`flowsdn-bpf-abi`** — `#![no_std]`, no dependencies beyond `core` (and
  `aya-ebpf`/`aya` behind optional features for the `Pod` impls). One module
  per §4 subsection: `ct`, `nat`, `lb`, `policy`, `eps` (endpoint/ipcache/
  node/subnet), `telemetry`, `features`, `notify`, `mark`, `config`
  (`VARIABLES` table: name, kind, size, description, per-object membership),
  `tailcall` (`SLOTS`, `CILIUM_CALL_SIZE = 50`), `maps` (the §2.2 catalogue as
  a `const` table: name, type, key/value size, default max, flags, pin policy,
  sizing key). Bitfields are exposed through accessor methods on a plain
  integer field, never through Rust bitfield crates. Used by the BPF crates,
  the agent, `flowsdn-dbg`, the monitor and tests, so there is exactly one
  definition of every layout.
- **`flowsdn-bpf-sys`** — thin `libc::syscall(SYS_bpf, ...)` shims for what
  aya lacks: `map_create` with `inner_map_fd`, `map_{lookup,lookup_and_delete,
  update,delete}_batch` with cursor, `link_update`, `link_create` with
  `BPF_NETKIT_*` and tcx `relative_fd/id` + `expected_revision`, `prog_attach`
  without flags, `map_freeze`, `obj_get_info_by_fd` for map/link info.
  Everything else goes through aya.
- **`flowsdn-bpf-maps`** — typed map wrappers over `aya::maps::MapData` plus
  the shims: open-or-create with §3.2 logic, registry patches, value cache +
  error resolver, pressure metric, event ring, reliable dump, batch iterator,
  per-CPU aggregation, map-in-map (`OuterArray`, `OuterHash`), `MapCatalogue`.
- **`flowsdn-loader`** — object embedding (`include_bytes_aligned!` per hook
  family, both targets from one `bpfel-unknown-none` build), the §3.5
  pipeline over `aya_obj::Object` (renames, `set_global`, registry, tail
  slots, reachability Tier A, aux sizing, PIN_REPLACE tracking), the commit
  closure, attach backends (`tc`, `tcx`, `netkit`, `xdp`, `cgroup`, `iter`)
  behind one `Attach` trait with `attach / update / detach`, bpffs paths
  (§2.1), the mapsweeper.
- **`flowsdn-monitor`** — perf readers for `cilium_events` (64 pages) and
  `cilium_signals` (1 page), versioned decoders from `flowsdn-bpf-abi::notify`,
  payload framing to the socket (area 09 owns the gob subset).

aya gaps and how each is filled:

| Gap | Fill |
|---|---|
| map-in-map creation and `__array(values, ...)` inner specs | `flowsdn-bpf-sys::map_create(inner_map_fd)`; inner spec comes from the ABI catalogue, not BTF; outer update writes the fd. Upstream PR: `aya_obj` inner map parsing |
| batch ops | `flowsdn-bpf-sys` batch shims with `MapBatchCursor`-like opaque cursor; upstream PR later |
| `BPF_LINK_UPDATE` on a pinned link | `flowsdn-bpf-sys::link_update(link_fd, prog_fd, old_prog_fd?)`; aya has `PinnedLink::from_pin` to obtain the fd |
| netkit attach | `link_create` with `BPF_NETKIT_PRIMARY/PEER`; netkit device creation in area 03 |
| tcx ordering / `expected_revision` | aya 0.13 `TcAttachOptions::TcxOrder` with `LinkOrder::last()` suffices for anchor-tail; revision-checked ordering via the shim if ever needed |
| `BPF_F_XDP_HAS_FRAGS` on a program | set `prog_flags` on the `aya_obj` program before load (field exists; verify it is honoured; else shim `prog_load`) |
| BTF decl tags | not used (§3.7, §3.8 DEVIATIONS); tables in the ABI crate |
| `.rodata.config` `set_global` | confirmed by section-prefix match; loader additionally validates the datasec name |
| reachability analysis | new code over `aya_obj::Object` instruction slices (`Vec<Instruction>` with relocation info); ~1.5k lines |
| kfunc/ksym relocation for `bpf_sock_destroy` | aya supports `.ksyms` relocation since 0.13; validated on the target kernel in §9.4; feature deferred otherwise |
| `PROG_ATTACH` without flags | shim (aya's `CgroupAttachMode` always sets a flag) |
| possible-CPU count | `aya::util::nr_cpus()` reads `possible`; used for perf arrays, per-CPU maps and `.data.aux` |

Key types: `PinPolicy::{ByName, Replace, None}`, `PendingPins`, `Commit`
(FnOnce, must be called or explicitly dropped with rollback), `AttachTarget::{Tcx(dir), Clsact(dir,prio), Netkit(side), Xdp(mode), CgroupRoot(attach_type), Iter}`,
`ObjectSpec` (prepared, pre-load), `LoadedObject { collection, programs by
symbol, pending pins }`, `MapRegistry` (frozen after startup),
`ReliableDump`, `BatchIter<K,V>`, `PerCpuValues<V>`.

Dependencies: `aya`, `aya-obj`, `libc`, `rtnetlink`/`netlink-packet-route`
for clsact/filter/XDP-netlink, `nix` for mounts, `zerocopy` or `bytemuck`
(one, not both) for `Pod` byte views, `tracing`, `prometheus-client`.
Licenses per `docs/licensing.md`.

## 12. Open decisions

1. **Tier B instruction elision.** Options: (a) Tier A only, rely on the
   kernel's frozen-rodata pruning for verifier state; (b) implement Tier B
   with BTF.ext rewriting. Recommendation: (a) for the first milestone;
   measure instruction counts of the all-features lxc/host objects on the
   minimum kernel; adopt (b) only if a count exceeds 80% of the 1M limit.
2. **Resolved policy (#53): one object per hook family first.** Follow
   datapath spec §6.2: retain a shared object for x86-64 and arm64, use runtime
   configuration/pruning, and add a prebuilt feature variant only after measured
   all-features results on the minimum kernel exceed 800,000 instructions or
   480 B stack. No variant dimensions are selected without measurements;
   `{v4,v6,dual}`, DSR modes and other candidates remain experiments. ADR-0002
   delegates variant count to the datapath spec, so this reconciles existing
   decisions rather than requiring another user choice. No verifier result is
   claimed by resolving this policy.
3. **Resolved (#58, ADR-0011): per-endpoint policy-capable lxc objects.**
   Keep §3.7 per-endpoint map names and rodata. A shared local-delivery smoke
   object does not supersede this production policy-object contract. Any future
   shared design requires measured load/memory evidence and tooling compatibility.
4. **Resolved (#57, ADR-0011): `cilium_events` remains `PERF_EVENT_ARRAY`.**
   Preserve §3.10 framing and per-CPU lost-event accounting. A ring-buffer
   replacement needs a separate measured proposal, map name and reader.
5. **Resolved (#51, ADR-0011): §3.11 owns the map-writer split.**
   Table-backed desired state uses the table reconciler. Endpoint/ipcache
   multi-writer maps retain one shared value-cache/retry primitive; do not layer
   two independent retry owners on one map. The foundation table and reconciler
   now exist; live map adapters remain implementation work.
6. **Per-cluster CT/NAT and multicast map-in-map in the first release.**
   Recommendation: implement the map-in-map primitive now (Maglev needs it
   anyway), create the per-cluster and multicast outer maps only when
   clustermesh / multicast are enabled.
7. **Resolved kernel floor (#54).** Adopt the roll-up's Linux 6.6 LTS
   general minimum and 6.12 supported line on both architectures. Earlier 6.1
   recommendations in this spec were superseded by that roll-up. Require
   feature-based startup refusal; remove the older-kernel clsact attach path,
   retaining only legacy attachment cleanup/takeover where explicitly noted.
   Privileged verification of the target kernel matrix remains outstanding.
