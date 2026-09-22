# Connection tracking and NAT — specification

Status: draft. Derived from: `docs/inventory/01-bpf-programs.md`,
`docs/inventory/02-bpf-maps-loader.md`, reference cilium v1.20.1 (7d68cfb394)
paths `bpf/lib/conntrack.h`, `bpf/lib/conntrack_map.h`, `bpf/lib/nat.h`,
`bpf/lib/nat_46x64.h`, `bpf/lib/nodeport.h`, `bpf/lib/nodeport_egress.h`,
`bpf/lib/lb.h` (`lb4_local`, `lb4_rev_nat`), `bpf/lib/ipv4.h`, `bpf/lib/ipv6.h`,
`bpf/lib/ipfrag.h`, `bpf/lib/common.h`, `bpf/lib/time.h`, `bpf/lib/signal.h`,
`bpf/lib/drop_reasons.h`, `bpf/bpf_lxc.c`, `pkg/maps/ctmap/**`,
`pkg/maps/nat/**`, `pkg/maps/timestamp`, `pkg/bpf/map_linux.go` (batch
iterator, reliable dump), `pkg/option/config.go`, `pkg/defaults/defaults.go`,
`daemon/cmd/daemon_main.go` (flag defaults), `pkg/datapath/linux/config/config.go`,
`pkg/endpoint/bpf.go`, `pkg/metrics/metrics.go`, `cilium-dbg/cmd/bpf_ct_*.go`,
`cilium-dbg/cmd/bpf_nat_*.go`, `bpf/tests/*ct*`, `bpf/tests/*nat*`.
Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. Where the reference
behavior is kept for compatibility the consumer that depends on it is named
(cilium-dbg, Hubble, Envoy/cilium-proxy, other cluster). Deviations are marked
**DEVIATION** with the reason and the ADR.

Sibling specs: `01-bpf-map-abi-loader.md` owns exact map layouts, pinning and
the loader; this spec repeats only the fields whose semantics it defines.
`05-service-lb.md` owns service/backend selection, Maglev, affinity maps and
DSR encapsulation; this spec owns the CT entries those features create and
consult. `03-identity-ipcache.md` owns `src_sec_id` values.

## 1. Scope

In scope:

- Connection tracking (CT) for TCP, UDP, ICMP/ICMPv6 and SCTP over IPv4 and
  IPv6, in the eBPF datapath (lookup, create, update, TCP state, timeouts,
  reply and RELATED detection) and the userspace garbage collector (GC).
- The **global** CT maps (`cilium_ct4_global`, `cilium_ct_any4_global`,
  `cilium_ct6_global`, `cilium_ct_any6_global`) and the per-cluster
  `ARRAY_OF_MAPS` variants used by cluster-aware addressing.
- Service CT entries (`TUPLE_F_SERVICE`) created by the per-packet load
  balancer, versus plain ingress/egress entries.
- The SNAT engine: NAT tables (`cilium_snat_v4_external`,
  `cilium_snat_v6_external`), port allocation, collision retry, ICMP error
  translation, orphan detection; the two users of SNAT: NodePort/LB forwarding
  and BPF masquerading (including ip-masq-agent CIDRs and egress-gateway
  hooks as inputs).
- Reverse NAT of service replies via `rev_nat_index` and the
  `cilium_lb{4,6}_reverse_nat` maps (the CT side of it).
- IP fragment tracking (`cilium_ipv{4,6}_frag_datagrams`).
- Userspace: GC interval adaptation, batch iteration, orphan NAT purge,
  endpoint IP scrubbing, restart behavior, `cilium-dbg bpf ct|nat list|flush`
  compatibility, metrics and datapath signals.

Out of scope / later milestones:

- **NAT46/NAT64** (`ENABLE_NAT_46X64`, RFC 6052 gateway, `SVC_FLAG_NAT_46X64`):
  scope only, §3.14. Not in the first datapath milestone (ADR-0002).
- Per-endpoint ("local") CT maps. The reference at v1.20.1 has **no**
  per-endpoint CT maps: `pkg/maps/ctmap` defines exactly four global map types
  (`mapCount = 4`), and `--enable-endpoint-routes` does not change CT map
  selection. flowsdn implements global CT maps only. Old
  `cilium_ct{4,6}_<EPID>` / `cilium_ct_any{4,6}_<EPID>` pins found on a node
  MUST be treated as stale maps and removed by the loader's stale-map cleanup
  (`01-bpf-map-abi-loader.md`).
- Socket-level LB reverse NAT (`cilium_lb{4,6}_reverse_sk`), socket
  termination and the `cilium_lb_act` active-connection counters: `05-service-lb.md`.
- The iptables masquerade path: **DEVIATION** — does not exist (ADR-0003).

## 2. Compatibility contract

### 2.1 Map names, pin paths, layouts

All maps pinned under `<bpffs>/tc/globals/`. Types, sizes and flags are owned by
`01-bpf-map-abi-loader.md`; the names and key/value *semantics* below MUST
match because `cilium-dbg bpf ct list`, `cilium-dbg bpf nat list`, the
cilium/proxy Envoy image (reads `src_sec_id` directly from the CT maps) and
live connections across an agent upgrade depend on them.

| Map | Type | Key | Value | Max entries (config key) | Writers |
|---|---|---|---|---|---|
| `cilium_ct4_global` | LRU_HASH | `ipv4_ct_tuple` 14 B | `ct_entry` 56 B | `bpf-ct-global-tcp-max` | datapath creates/updates; GC deletes |
| `cilium_ct_any4_global` | LRU_HASH | `ipv4_ct_tuple` 14 B | `ct_entry` 56 B | `bpf-ct-global-any-max` | same; UDP, ICMP, SCTP and RELATED entries |
| `cilium_ct6_global` | LRU_HASH | `ipv6_ct_tuple` 38 B | `ct_entry` 56 B | `bpf-ct-global-tcp-max` | same |
| `cilium_ct_any6_global` | LRU_HASH | `ipv6_ct_tuple` 38 B | `ct_entry` 56 B | `bpf-ct-global-any-max` | same |
| `cilium_per_cluster_ct_{tcp4,any4,tcp6,any6}` | ARRAY_OF_MAPS | u32 cluster id | inner map fd | 256 | agent creates inner LRU maps (same key/value as global) per remote cluster |
| `cilium_snat_v4_external` | LRU_HASH | `ipv4_ct_tuple` 14 B | `ipv4_nat_entry` 40 B | `bpf-nat-global-max` | datapath; GC deletes |
| `cilium_snat_v6_external` | LRU_HASH | `ipv6_ct_tuple` 38 B | `ipv6_nat_entry` 56 B | `bpf-nat-global-max` | datapath; GC deletes |
| `cilium_per_cluster_snat_v{4,6}_external` | ARRAY_OF_MAPS | u32 | inner fd | 256 | agent |
| `cilium_snat_v{4,6}_alloc_retries` | PERCPU_ARRAY | u32 retries (0..32) | u32 count | 33 | datapath increments; `cilium-dbg bpf nat retries list` reads |
| `cilium_ipmasq_v4` / `_v6` | LPM_TRIE | `lpm_v4_key` 8 B / `lpm_v6_key` 20 B | 1 B | 16384 | agent (ip-masq-agent config) |
| `cilium_ipv4_frag_datagrams` | LRU_HASH | `ipv4_frag_id` 12 B | `ipv4_frag_l4ports` 4 B | `bpf-fragments-map-max` | datapath |
| `cilium_ipv6_frag_datagrams` | LRU_HASH | `ipv6_frag_id` 40 B | `ipv6_frag_l4ports` 4 B | `bpf-fragments-map-max` | datapath |
| `cilium_lb4_reverse_nat` / `lb6` | HASH | u16 `rev_nat_index` | `{address, port}` | 65536 | agent (owned by `05-service-lb.md`) |

Map selection by protocol: TCP → `cilium_ct{4,6}_global`; every other
`nexthdr` → `cilium_ct_any{4,6}_global`. With cluster-aware addressing and a
non-zero, non-local `cluster_id` the per-cluster inner map for that id is used
instead; a missing inner map is `DROP_CT_NO_MAP_FOUND` (-190) for CT and
`DROP_SNAT_NO_MAP_FOUND` (-191) for NAT.

### 2.2 CT tuple key

`ipv4_ct_tuple` / `ipv6_ct_tuple` are packed, field order fixed:

| Offset (v4 / v6) | Field | Type | Meaning |
|---|---|---|---|
| 0 / 0 | `daddr` | be32 / 16 B | **Original-direction source** address (names are correct for the reply direction) |
| 4 / 16 | `saddr` | be32 / 16 B | **Original-direction destination** address |
| 8 / 32 | `dport` | be16 | Original-direction destination port |
| 10 / 34 | `sport` | be16 | Original-direction source port |
| 12 / 36 | `nexthdr` | u8 | IP protocol |
| 13 / 37 | `flags` | u8 | Direction/scope byte, below |

`flags` values (bit set, not enum): `TUPLE_F_OUT = 0`, `TUPLE_F_IN = 1`,
`TUPLE_F_RELATED = 2`, `TUPLE_F_SERVICE = 4`. `RELATED` combines with `OUT`/`IN`.
`SERVICE` is never combined with `IN`. The Go/cilium-dbg dump renders
`SVC saddr:dport -> daddr:sport`, `IN daddr:sport -> saddr:dport` and
`OUT daddr:sport -> saddr:dport` (addresses swapped for display, "issue #5848")
— flowsdn's `flowsdn-dbg` output MUST be byte-for-byte compatible with the
`cilium-dbg bpf ct list` text and JSON (`CtMapRecord{Key, Value}`) formats.

For ICMP/ICMPv6: `dport` carries the echo identifier for ECHO requests,
`sport` for ECHO replies; both zero for error messages, which additionally set
`TUPLE_F_RELATED`. For protocols other than TCP/UDP/SCTP/ICMP with
`enable_extended_ip_protocols` both ports are zero.

### 2.3 CT entry value (`ct_entry`, 56 bytes)

| Offset | Size | Field | Semantics |
|---|---|---|---|
| 0 | 16 | union { `nat_addr` v6addr ; { `reserved0` u64 @0, `backend_id` u64 @8 } } | INGRESS/EGRESS entries: loopback/DSR NAT address. SERVICE entries: selected backend id (u32 stored in a u64) |
| 16 | 8 | `packets` | Accounting counter, only when `bpf-conntrack-accounting` |
| 24 | 8 | `bytes` | Same |
| 32 | 4 | `lifetime` | Absolute expiry in mono-time units (§3.6) |
| 36 | 2 | flags bitfield, bit 0 up | `rx_closing`(0) `tx_closing`(1) `reserved1/Nat64`(2) `lb_loopback`(3) `seen_non_syn`(4) `node_port`(5) `proxy_redirect`(6) `dsr_internal`(7) `from_l7lb`(8) `reserved2`(9) `from_tunnel`(10) bits 11..15 reserved |
| 38 | 2 | `rev_nat_index` | Service reverse-NAT index (host order in BPF, `cilium-dbg` prints `NetworkToHost16` of the raw bytes) |
| 40 | 2 | `nat_port` | be16, loopback/DSR NAT port |
| 42 | 1 | `tx_flags_seen` | OR of TCP flag low byte seen in the tx (egress) direction |
| 43 | 1 | `rx_flags_seen` | Same for rx (ingress) |
| 44 | 4 | `src_sec_id` | Source security identity of the original direction. **Offset MUST NOT change**: cilium/proxy reads it |
| 48 | 4 | `last_tx_report` | Mono-time of last monitor notification, tx |
| 52 | 4 | `last_rx_report` | Same, rx |

`cilium-dbg bpf ct list` prints: `expires=<lifetime> (remaining: N sec(s))
Packets= Bytes= RxFlagsSeen= LastRxReport= TxFlagsSeen= LastTxReport=
Flags=0x.... [ RxClosing TxClosing Nat64 LBLoopback SeenNonSyn NodePort
ProxyRedirect DSRInternal FromL7LB FromTunnel ] RevNAT= SourceSecurityID=
BackendID= NatPort=`. The remaining-time conversion needs the agent's clock
source (§3.6), obtained from `GET /healthz` (`ClockSource{mode, hertz}`) or
the runtime config file; flowsdn MUST expose the same `clock-source` field.

### 2.4 NAT entry value

`nat_entry` common header (32 B): `created` u64 @0 (mono-time), `needs_ct` u64
@8 (single bit used), `pad1` @16, `pad2` @24. `ipv4_nat_entry` (40 B) adds a
union at 32: `{to_saddr be32 @32, to_sport be16 @36}` for `TUPLE_F_OUT` keys,
`{to_daddr, to_dport}` (same bytes) for `TUPLE_F_IN` keys, aliased with
`lb4_reverse_nat {address, port}` for DSR. `ipv6_nat_entry` (56 B): address
16 B @32, port @48. `cilium-dbg bpf nat list` prints
`XLATE_SRC addr:port Created=<n>sec ago NeedsCT=<0|1>` for `OUT` keys and
`XLATE_DST` for `IN` keys.

### 2.5 Codes shared with Hubble and the monitor

Trace `reason` byte (Hubble decodes it): `TRACE_REASON_POLICY = CT_NEW = 0`,
`CT_ESTABLISHED = 1`, `CT_REPLY = 2`, `CT_RELATED = 3`. Drop reasons owned
by this spec: `DROP_INVALID -134`, `DROP_CT_INVALID_HDR -135`,
`DROP_CT_UNKNOWN_PROTO -137`, `DROP_CSUM_L3 -153`, `DROP_CSUM_L4 -154`,
`DROP_CT_CREATE_FAILED -155`, `DROP_FRAG_NOSUPPORT -157`, `DROP_NO_SERVICE
-158`, `DROP_NAT_46X64_DISABLED -161`, `DROP_UNKNOWN_CT -163`,
`DROP_NAT_NO_MAPPING -167`, `DROP_NAT_UNSUPP_PROTO -168`, `DROP_NAT_NOT_NEEDED
-173` (internal "punt to stack", never emitted as a drop), `DROP_FRAG_NOT_FOUND
-175`, `DROP_NAT46 -187`, `DROP_NAT64 -188`, `DROP_CT_NO_MAP_FOUND -190`,
`DROP_SNAT_NO_MAP_FOUND -191`, `DROP_FRAG_NOT_FOUND_WORLD -207`. Values MUST
match; Hubble and `cilium-dbg monitor` render them by number.

Datapath signals over `cilium_signals`: `SIGNAL_NAT_FILL_UP = 0`,
`SIGNAL_CT_FILL_UP = 1` with data `SIGNAL_PROTO_V4 = 0 | SIGNAL_PROTO_V6 = 1`.

### 2.6 Config keys

Every key in §6 is accepted under its reference name so existing
`cilium-config` ConfigMaps and Helm values keep working.

## 3. Behavior

### 3.1 Directions, scopes, statuses

- `CtDir ∈ {Egress, Ingress, Service}`. Egress = packet leaving a local
  endpoint (or the host, for host firewall / NodePort forward); Ingress =
  packet entering a local endpoint (or the host). Service = the per-packet LB
  entry keyed on the service VIP.
- `Scope ∈ {Forward, Reverse, Bidir}`: which orientation(s) of the packet's
  tuple are looked up (§3.2).
- Result `CtStatus ∈ {New, Established, Reply, Related}`.
- Entry-type filter `CtEntryTypes` bitmask `{Any=0, NodePort=1, Dsr=2, Svc=4}`
  restricts a lookup to entries created for a purpose (§3.2 step 4).

### 3.2 Tuple orientation and lookup order (normative)

Let a packet be `S:s → D:d` over protocol `p`, observed in direction `dir`
with direction flag `F(dir)` = `OUT` for Egress, `IN` for Ingress.

Key construction:

| Purpose | `daddr` | `saddr` | `dport` | `sport` | `flags` |
|---|---|---|---|---|---|
| **Forward key** (matches an entry whose original direction is this packet) | `S` | `D` | `d` | `s` | `F(dir)` |
| **Reverse key** (matches an entry whose original direction is the opposite of this packet) | `D` | `S` | `s` | `d` | `F(¬dir)`, i.e. `IN` for Egress lookups, `OUT` for Ingress |
| **Service key** | `D` (VIP) | `S` (client) | `s` | `d` (service port) | `SERVICE` |
| **Related key** (ICMP error whose inner packet was `S:s → D:d`) | as Reverse key | | 0 | 0 | Reverse `flags` | `RELATED` |

An entry is **always stored under its Forward key as seen by its creator**.
Hence a connection initiated by a local pod (`P:p → W:w`, created in Egress)
is stored as `{daddr=P, saddr=W, dport=w, sport=p, OUT}`; the same connection
initiated from outside (`W:w → P:p`, created in Ingress) is stored as
`{daddr=W, saddr=P, dport=p, sport=w, IN}`. The reply packet's Reverse key
equals the stored key in both cases, which is what makes reply detection a
plain lookup. This exact orientation MUST be preserved: `cilium-dbg`, the
GC's NAT correlation (§5.4) and the cilium/proxy `src_sec_id` lookups all
rebuild keys this way.

Lookup order per scope:

1. `Reverse` and `Bidir`: look up the Reverse key first. A hit is `Reply`, or
   `Related` if the tuple carries `TUPLE_F_RELATED`. For `Bidir` a miss falls
   through to step 2; for `Reverse` a miss is `New`.
2. `Forward`: look up the Forward key. Hit → `Established`; miss → `New`.
3. Rationale for reverse-first (kept): policy treats Reply/Related as
   "skip policy", so they MUST win over a coincidentally matching forward
   entry.
4. A hit whose entry does not satisfy `CtEntryTypes` is treated as a miss:
   `Svc` requires `entry.rev_nat_index == state.rev_nat_index`; `NodePort`
   requires `entry.node_port && entry.rev_nat_index != 0` and, when the
   caller supplies a non-zero `rev_nat_index`, equality; `Dsr` requires
   `entry.dsr_internal`. `Any` matches everything.

Which scope each program uses:

| Program point | dir | scope | notes |
|---|---|---|---|
| from-container (pod egress), no LB translation on this packet | Egress | Bidir | |
| from-container after per-packet LB rewrote the destination | Egress | Forward | replies to the service flow are never matched by the post-DNAT tuple (`rev_nat_index != 0` ⇒ Forward) |
| to-container / policy tail call (pod ingress) | Ingress | Bidir | |
| host firewall from-host / to-host | Egress / Ingress | Bidir | global maps, `src_sec_id = HOST` |
| per-packet LB service lookup (`lb_local`) | Service | Reverse (Service key) | filter `Svc` |
| NodePort forward (client→backend on the LB node) | Egress | Forward | filter `NodePort` |
| NodePort reverse DNAT of a backend reply | Ingress | Reverse | filter `NodePort` |
| SNAT engine with `needs_ct` (host-originated / egress-gateway) | Egress | Forward | plain entry, filter `Any` |
| Rev-SNAT engine with `needs_ct` | Ingress | Reverse | filter `Any` |
| Masquerade decision "is this a reply?" | Egress | Reverse-key existence only (`ct_is_reply`) | no state update |

`lazy` lookups (tuple already has ports, no `RELATED` handling) and full
lookups (ports extracted from the packet, ICMP classified) MUST produce the
same key for TCP/UDP/SCTP.

### 3.3 Entry creation

Who creates, and what goes into the entry:

| Creator | dir | Map | Related entry | Fields set |
|---|---|---|---|---|
| from-container on `New` (after policy allow) | Egress | `ct{4,6}` or `ct_any{4,6}` by proto | yes, in `ct_any*` | `src_sec_id` = endpoint identity, `rev_nat_index` (from LB), `proxy_redirect = proxy_port>0`, `from_l7lb`, `lb_loopback`, `nat_addr/nat_port` (loopback) |
| to-container on `New` (after policy allow) | Ingress | same | yes | `src_sec_id` = packet source identity, `from_tunnel`, `proxy_redirect`, `node_port` (copied from a matching NodePort Egress entry, §3.10), `lb_loopback` |
| host firewall | Egress/Ingress | same | yes | `src_sec_id` |
| `lb_local` on `New` | Service | same | no | `rev_nat_index`, `backend_id` |
| NodePort forward on `New` | Egress | same | no | `node_port=1`, `rev_nat_index`, `src_sec_id = WORLD` (or remote-cluster identity) |
| DSR backend node on `New` | Egress | same | no | `dsr_internal=1`, `nat_addr/nat_port` (client-visible service address) |
| SNAT with `needs_ct` on `New` | Egress | same | no | none (plain tracking so GC can reap the NAT mapping) |

Rules:

- `ct_create` MUST zero the entry, fill the fields above, set the initial
  timeout as if a first packet with `SYN` (TCP) or no flags (non-TCP) was
  seen (§3.5), and set `packets=1, bytes=len` when accounting is on.
- For TCP/UDP/SCTP created in Egress/Ingress a **Related entry** MUST also be
  written into the `_any` map with the Related key (same addresses, ports 0,
  `nexthdr = ICMP/ICMPv6`, `flags = tuple.flags | RELATED`) and the same
  value. Its purpose is to admit ICMP error messages about the flow. It is
  written *before* the main entry; if the main write then fails the related
  entry is left to expire.
- Map update failure (`-E2BIG`/`-ENOMEM` on a full LRU is rare; LRU evicts) is
  `DROP_CT_CREATE_FAILED` with the errno in `ext_err`. Service creation
  failure fails closed (`lb_local` drops).
- `Established` on a **stale** entry MUST recreate it (overwrite in place with
  fresh values) when `entry.rev_nat_index != state.rev_nat_index` (a
  non-service entry hit by a now-service flow or vice versa) or when
  `entry.proxy_redirect != (proxy_port > 0)` (L7 policy changed under an
  active flow). The old entry's counters are discarded.

### 3.4 Reply, RELATED and ICMP

- ICMP/ICMPv6 ECHO: tracked like a connection keyed on the identifier
  (`dport = id` in the request's Forward key; the reply's Reverse key places
  the id in the same position). Fragmented ICMP is `DROP_INVALID`.
- ICMP errors (v4: DEST_UNREACH, TIME_EXCEEDED, PARAMETERPROB; v6: PKT_TOOBIG,
  DEST_UNREACH, TIME_EXCEED, PARAMPROB): the tuple is built from the **outer**
  header (ports 0, `RELATED` set) and looked up in the `_any` map. A hit is
  `Related`; policy is skipped for Related just as for Reply. `FRAG_NEEDED` /
  `PKT_TOOBIG` additionally count `REASON_MTU_ERROR_MSG` in the metrics map.
  Note the reference does **not** parse the inner packet for CT (only for
  NAT, §3.11); an error whose outer addresses do not match a tracked pair is
  `New` and subject to policy.
- Other IP protocols: `DROP_CT_UNKNOWN_PROTO` unless
  `enable_extended_ip_protocols`, in which case tracked with ports 0.
- `Reply`/`Related` never create entries. Replies **do** refresh the
  timeout and counters of the matched entry (§3.5).

### 3.5 TCP state and timeout selection

Time base: `now = mono_now()` (§3.6). `lifetime` is always written as
`now + T` for the `T` chosen below, on **every** matched packet in either
direction while the entry is alive (`!(rx_closing && tx_closing)`).

TCP action from the packet's flags: `RST|FIN → Close`; `SYN && !ACK → Create`;
otherwise `Unspec`. Non-TCP and fragments without an L4 header → `Unspec`.

| Entry state | Packet | Effect on flags | `T` chosen |
|---|---|---|---|
| new (create) TCP | — | `seen_non_syn=0`, tx/rx flags = SYN in the creating direction | `CT_SYN_TIMEOUT` |
| new (create) non-TCP | — | — | `CT_CONNECTION_LIFETIME_NONTCP` (`CT_SERVICE_LIFETIME_NONTCP` for Service) |
| alive TCP, `seen_non_syn=0` | SYN only | none | `CT_SYN_TIMEOUT` |
| alive TCP | any packet without SYN (or with SYN+ACK) | `seen_non_syn=1` (sticky) | `CT_CONNECTION_LIFETIME_TCP` (`CT_SERVICE_LIFETIME_TCP` for Service) |
| alive non-TCP | any | — | `CT_CONNECTION_LIFETIME_NONTCP` / `_SERVICE_` |
| alive, `Close` in dir Ingress | FIN | `rx_closing=1` | as above, then if both closing: `CT_CLOSE_TIMEOUT` |
| alive, `Close` in dir Egress | FIN | `tx_closing=1` | same |
| alive, `Close` | RST, and the entry has **not** seen SYN in both directions | `rx_closing=tx_closing=1` | `CT_CLOSE_TIMEOUT` |
| alive, `Close` | RST, both SYNs seen | only this direction's closing bit | unchanged until both set |
| Service entry, `Close` | FIN or RST | `rx_closing=tx_closing=1` (only one direction is ever seen) | `CT_CLOSE_TIMEOUT` |
| closing (either bit) | `Create` (new SYN) | reset both closing bits, both flags-seen bytes, `seen_non_syn=0`; refresh timeout | caller receives `New` and **recreates** the entry (policy is re-evaluated; on deny the old entry remains) |
| Service entry closing, SYN, and `last_tx_report + CT_SERVICE_CLOSE_REBALANCE <= now` | SYN | — | treated as `New`: a fresh backend is selected (§3.8) |
| both closing | non-SYN | no timeout refresh | entry expires at `CT_CLOSE_TIMEOUT` |

`Close` also forces a monitor notification for that packet (`monitor =
TRACE_PAYLOAD_LEN`) and reports `closing=1` to the caller (active-connection
tracking). Counters: when `bpf-conntrack-accounting` is on, `packets += 1`,
`bytes += packet length` with atomic adds on every matched packet (create sets
`1`/`len`). Otherwise both stay 0. Racing CPUs may over-report notifications
or interleave flag bytes; this is accepted (all writes are whole 8/32-bit
stores; flags are OR-accumulated so they self-correct).

Timeout constants (seconds) and the config keys that set them. The BPF-side
compile-time defaults exist only as fallbacks; the agent MUST always supply
the flag values, so the **effective** defaults are the flag defaults:

| Constant | Flag | Effective default | Reference BPF fallback |
|---|---|---|---|
| `CT_CONNECTION_LIFETIME_TCP` | `bpf-ct-timeout-regular-tcp` | 8000 s | 21600 |
| `CT_CONNECTION_LIFETIME_NONTCP` | `bpf-ct-timeout-regular-any` | 60 s | 60 |
| `CT_SERVICE_LIFETIME_TCP` | `bpf-ct-timeout-service-tcp` | 8000 s | 21600 |
| `CT_SERVICE_LIFETIME_NONTCP` | `bpf-ct-timeout-service-any` | 60 s | 60 |
| `CT_SERVICE_CLOSE_REBALANCE` | `bpf-ct-timeout-service-tcp-grace` | 60 s | 30 |
| `CT_SYN_TIMEOUT` | `bpf-ct-timeout-regular-tcp-syn` | 60 s | 60 |
| `CT_CLOSE_TIMEOUT` | `bpf-ct-timeout-regular-tcp-fin` | 10 s | 10 |
| `CT_REPORT_INTERVAL` | `monitor-aggregation-interval` | 5 s | 5 |
| `CT_REPORT_FLAGS` | `monitor-aggregation-flags` | `syn,fin,rst` → 0x07 | 0xff |

In flowsdn these are `.rodata` config values patched at load, not compile-time
defines (ADR-0002 variant strategy is decided in the datapath spec).

### 3.6 Time base

`mono_now()` returns a u32: `ktime_get_ns() / 1e9` (seconds since boot), or
`jiffies64 >> 8` when the jiffies clock source is active. `sec_to_mono(s)` is
`s` or `(s * kernel_hz) >> 8` respectively. The clock source is chosen once at
agent start: jiffies if `enable-bpf-clock-probe` is set and the kernel exposes
jiffies (`/proc/kallsyms` `jiffies` symbol readable via the probe), else
ktime. The choice MUST be exported (`/healthz` `clock-source {mode, hertz}`,
runtime config JSON) because the GC and `cilium-dbg` convert `lifetime` with
it. Userspace "now" for GC: run a tiny BPF program that returns
`ktime_get_ns()` and divide by 1e9, or read jiffies and shift by 8. Monotonic
time is immune to wall-clock jumps; suspend/resume freezes ktime and inflates
apparent lifetimes (§7.3).

### 3.7 Monitor aggregation

On every matched packet the datapath computes whether to emit a trace event
(`monitor` = `TRACE_PAYLOAD_LEN` or 0). With aggregation level `medium`
(`MONITOR_AGGREGATION = 3`): emit if `last_{rx|tx}_report + CT_REPORT_INTERVAL
< now` **or** the packet adds a TCP flag not yet in `{rx|tx}_flags_seen`
(masked by `CT_REPORT_FLAGS`); on emit, store `flags_seen |= new` and
`last_report = now`. `New` and `Close` always emit. Levels `none`/`lowest`/
`low` emit per packet (rx suppressed at `lowest`/`low`); the CT fields are
still maintained. Hubble depends only on the emitted event and `reason`.

### 3.8 Service entries and backend affinity

`lb_local` (owned by `05-service-lb.md` for backend selection) drives the
Service CT entry:

1. Look up the Service key (Reverse scope, filter `Svc` with the service's
   `rev_nat_index`). Existing entry → `Existing` (the reference's lookup
   primitive reports this as `CT_REPLY`; the flowsdn internal API MUST name it
   `Existing`). If `svc.count == 0` on `New` → `DROP_NO_SERVICE`.
2. `New`: choose `backend_id` (session affinity map first if the service has
   affinity and the backend still exists; else the service's algorithm),
   store `backend_id` and `rev_nat_index` in a new Service entry. Creation
   failure drops (fail closed). A TCP SYN sets `state.syn` for ACT.
3. `Existing`: `backend_id = entry.backend_id`; look it up in the backend map.
   If the backend is **missing** or its state is not `ACTIVE`
   ("backend gone" / terminating):
   - if the backend still exists (terminating) and this packet is **not** a
     SYN: keep draining to it (break);
   - otherwise (backend deleted, or a new SYN to a terminating backend):
     re-select a backend (`svc.count == 0` → `DROP_NO_SERVICE`), and
     **update the existing Service entry in place** with the new
     `backend_id` and `rev_nat_index` (`ct_update_svc_entry`). An established
     TCP flow moved this way will see a RST from the new backend; that is
     accepted.
4. A closing Service entry (FIN/RST seen) hit by a SYN after
   `CT_SERVICE_CLOSE_REBALANCE` since its `last_tx_report` is treated as `New`
   (fresh selection); before the grace period the SYN reuses the old backend.
5. Session affinity (`enable-session-affinity`, `cilium_lb{4,6}_affinity`,
   `cilium_lb_affinity_match`) is updated with the chosen backend after every
   successful lookup; the Service CT entry remains the per-connection source
   of truth and affinity the per-client hint.
6. The Service key's `SERVICE` flag is used only for this lookup; the caller
   restores the tuple flags before the plain Egress lookup that follows.
7. `forced_backend` (L7 LB / local redirect): a Service entry is still
   created so ACT and rev-NAT work, except for L7 "punt proxy" services which
   skip CT entirely.
8. When the GC deletes a Service entry it reports `(rev_nat_index,
   backend_id)` to the active-connection-tracking counters as "failed" —
   `05-service-lb.md`.

### 3.9 Reverse NAT on replies and `rev_nat_index`

`rev_nat_index` (u16, > 0) identifies a `cilium_lb{4,6}_reverse_nat` entry
`{address = VIP, port = service port}`. Semantics on the CT side:

- Egress (from-container) entries carry the `rev_nat_index` of the service the
  pod connected to (0 for non-service flows). On `Reply`/`Related` arriving
  at the pod (to-container), if `entry.rev_nat_index != 0` or `entry.nat_port
  != 0` the datapath rewrites the reply's source `backend → VIP:port`
  (`lb_rev_nat`), using `nat_addr/nat_port` from the entry when set (loopback
  hairpin: the original source becomes the new destination as well), else the
  reverse-NAT map. Missing reverse-NAT map entry → no rewrite (not a drop).
- NodePort Egress entries (`node_port=1`) carry the service's
  `rev_nat_index`; the backend's reply, seen in Ingress with `Reply`, is
  rev-DNATed on the LB node using it (§3.10).
- Service entries carry it so `ct_entry_matches_types(Svc)` can tell apart
  entries of different services sharing a client tuple.
- A `Reply` on the pod egress path with `entry.node_port` and a
  TCP/UDP/SCTP protocol is tail-called to the NodePort reverse-DNAT program
  (compatibility path for pre-v1.19 entries and local backends).

### 3.10 NodePort forward, SNAT and reverse path

Client `C:c → Node:np` handled by the LB node (`bpf_host`/XDP):

1. Service lookup selects backend `B:b`; DNAT; tuple is now `C:c → B:b`.
2. CT Egress **Forward** lookup with filter `NodePort` and
   `state.rev_nat_index = svc.rev_nat_index`; `New` → create Egress entry
   `{daddr=C, saddr=B, dport=b, sport=c, OUT}` with `node_port=1`,
   `src_sec_id = WORLD_IPV{4,6}` (or the remote-cluster identity when
   inter-cluster SNAT is on; local/host identities are rejected with
   `DROP_INVALID_IDENTITY`). `Established` → no validation of stored fields.
3. If the backend is local: mark `XFER_PKT_NO_SVC`, deliver. Otherwise the
   packet leaves the node and MUST be SNATed to the node's address so the
   reply returns here: `snat_v4_nat` with target `{addr = node IP (per egress
   device; optionally via `enable_nodeport_source_lookup` FIB source lookup),
   min_port = nodeport_port_max + 1, max_port = 65535}`. In DSR modes the
   packet is instead encapsulated/option-tagged and no SNAT happens
   (`05-service-lb.md`); the backend node creates the `dsr_internal` entry.
4. Reply `B:b → Node:x` arrives at the LB node: rev-SNAT (§3.11) yields
   `B:b → C:c`; CT Ingress **Reverse** lookup with filter `NodePort` →
   `Reply` → `lb_rev_nat` with `entry.rev_nat_index` rewrites source to
   `Node:np`; FIB redirect to the client.
5. Reply from a **local** backend leaves via from-container: the pod's own
   Egress lookup returns `Reply` on the Ingress entry created at delivery,
   whose `node_port` bit was copied (at create time) from the existence of a
   matching NodePort Egress entry (`ct_has_nodeport_egress_entry`); the
   packet is tail-called to reverse DNAT.
6. `nodeport_rev_dnat_get_info` (used on the host egress path for replies
   that reach `to-netdev` without CT context) looks up the **Forward key with
   `OUT`** of the reply's reversed tuple: `node_port && rev_nat_index` →
   reverse-NAT map; `dsr_internal` → `nat_addr/nat_port` from the entry, else
   the DSR NAT entry.

### 3.11 SNAT engine

NAT keys use **natural packet orientation**: for an egress packet `S:s → D:d`
the mapping key is `{daddr=D, saddr=S, dport=d, sport=s, nexthdr, OUT}` with
value `{to_saddr=X, to_sport=x}`; the paired reverse key is the reply's
natural orientation `{daddr=X, saddr=D, dport=x, sport=d, IN}` with value
`{to_daddr=S, to_dport=s}`. Both share `created` and `needs_ct`.

Target: `{addr, min_port, max_port, from_local_endpoint, egress_gateway,
cluster_id, needs_ct, ifindex, tbid}`.

**Forward (`snat_nat`)**:

1. Protocol dispatch: TCP/UDP/SCTP load ports (fragment rules §3.13; without
   fragment tracking a fragment is `DROP_FRAG_NOSUPPORT`). Skip (punt) when
   `!from_local_endpoint && sport < nat_min_egress()` where `nat_min_egress
   = nodeport_port_max + 1` with NodePort, else `ephemeral_min` — host
   traffic below the NAT range needs no translation — except egress-gateway
   traffic, which is never skipped. ICMP: ECHO is NATed on the identifier
   (target port range widened to 0..65535); ECHOREPLY/REDIRECT punt;
   DEST_UNREACH (code ≤ 15) and TIME_EXCEEDED (TTL/FRAGTIME) go through
   **ICMP error translation**; other types `DROP_NAT_UNSUPP_PROTO`. Other
   protocols punt.
2. Lookup the `OUT` key. Hit with `to_saddr == target.addr && needs_ct ==
   entry.needs_ct`: ensure the `IN` reverse entry exists (recreate it if LRU
   evicted it), rewrite headers, done. Hit with a **stale** address (node IP
   changed) → delete both and fall through to allocation.
3. If `needs_ct`: a plain CT Egress Forward lookup/create on the pre-NAT
   tuple (so the GC can reap the mapping). `needs_ct` is set for
   host-originated traffic using the masquerade address, for egress-gateway
   traffic of non-local pods, and for host/host-netns-pod traffic detected by
   `MARK_MAGIC_HOST` or `ENDPOINT_F_HOST` (NAT conflict avoidance: the host's
   own source port is **reserved** by creating a mapping to itself, or
   translated if already taken).
4. **Port allocation** (`snat_new_mapping`): candidate = original source port
   if within `[min_port, max_port]`, else a pseudo-random port in range
   (`start + ((rand16 * (end-start+1)) >> 16)`, slightly biased). Try to
   insert the **reverse** (`IN`) key with `BPF_NOEXIST`; on collision the
   next candidate is `port + 1` clamped into range (random restart on the
   first retry), up to `SNAT_COLLISION_RETRIES = 32` attempts. Each attempt
   count `r` increments `cilium_snat_v{4,6}_alloc_retries[r]`. Exhaustion →
   `DROP_NAT_NO_MAPPING`. After a successful reverse insert, insert the `OUT`
   entry (`BPF_ANY`); on failure delete the reverse entry and return
   `DROP_NAT_NO_MAPPING`. Whenever `retries > SNAT_SIGNAL_THRES = 16` (before
   or after success) send `SIGNAL_NAT_FILL_UP` for the family.
5. Rewrite: source address (and L3 checksum by diff), source port (L4
   checksum incremental update; SCTP port change is `DROP_CSUM_L4` — SCTP is
   NATed address-only), pseudo-header checksum for TCP/UDP. ICMP has no
   pseudo-header; only the id change is folded into its checksum. Set
   `SNAT_DONE` on the skb so a second egress device does not translate again.

**ICMP error translation (forward)**: parse the inner IP header (RFC 5508);
build the mapping key from the **inner** packet reversed (`saddr = inner
daddr`, `daddr = inner saddr`, `OUT`), inner ports (TCP/UDP/SCTP) or inner
ECHOREPLY id; lookup; rewrite the inner destination to `to_saddr:to_sport`
and the outer source normally; if the inner L4 header is truncated before its
checksum, a checksum update failure is tolerated.

**Reverse (`snat_rev_nat`)**: tuple `{daddr=X, saddr=D, dport=x, sport=d,
IN}`; punt when `dport ∉ [min_port, max_port]`. Lookup; hit → ensure the `OUT`
entry exists (recreate from the reverse entry if evicted); if `needs_ct`, CT
Ingress Reverse lookup on the un-NATed tuple to refresh the tracking entry;
rewrite destination to `to_daddr:to_dport`. Miss → `DROP_NAT_NO_MAPPING`.
ICMP: ECHOREPLY on id; DEST_UNREACH/TIME_EXCEEDED by inner-packet lookup with
the `IN` key built from the inner packet (inner `daddr → saddr`), rewriting
inner source and the outer ICMP checksum by the computed diff (zero UDP inner
checksum means "no checksum": only the port diff applies).

### 3.12 Masquerade decision

Applies on `to-netdev` of a native device when `enable-bpf-masquerade &&
enable-ipv{4,6}-masquerade`. Inputs and order (first match decides):

1. Source == this device's masquerade address (`nat_ipv4_masquerade`, a
   per-device `.rodata` value): **NAT NEEDED with `needs_ct`** (reserve/translate
   the host's own port, §3.11 step 3).
2. Source is a local endpoint: extract ports; if the Reverse key with `IN`
   exists in the CT map (`ct_is_reply`) → **not needed** (reply to an inbound
   connection). Unknown L4 protocol is tolerated (continue).
3. Egress-gateway policy hook matches `(saddr, daddr)` → NAT NEEDED with the
   policy's egress IP and `ifindex`; `EGRESS_GATEWAY_NO_EGRESS_IP` →
   `DROP_NO_EGRESS_IP`; `needs_ct` if the source is not a local endpoint;
   route table id from the endpoint's `rt_info`. This precedes the exclusion
   CIDR on purpose.
4. Destination inside `IPV4_SNAT_EXCLUSION_DST_CIDR` → not needed. The CIDR is
   `ipv4-native-routing-cidr` when set (or, without ip-masq-agent, the
   cluster's native routing CIDR / pod CIDR); absent CIDR disables the check.
5. Source endpoint has `ENDPOINT_F_NO_SNAT_V{4,6}` (multi-pool IPAM opt-out) or
   is the host endpoint → not needed.
6. `enable-ip-masq-agent` and destination matches `cilium_ipmasq_v{4,6}`
   (LPM of non-masquerade CIDRs from the ip-masq-agent ConfigMap) → not needed.
7. Destination identity is a remote node: `enable-remote-node-masquerade` →
   NAT NEEDED; native routing → not needed; tunnel mode → needed unless the
   ipcache entry has `skip_tunnel`.
8. Source is a local endpoint → NAT NEEDED to the device's masquerade address.
9. Otherwise not needed.

Address selection: the agent assigns each masquerading device the primary
address of that device (first global-scope IPv4/IPv6 by the node-address
selection rules of `03-datapath-userspace-node.md`), or with
`enable-masquerade-to-route-source` the source address the FIB would pick for
the destination (`enable_nodeport_source_lookup`, `BPF_FIB_LOOKUP_SRC`).
`egress-masquerade-interfaces` restricts which devices run the masquerade
program. Port range as §3.10 step 3. **DEVIATION**: no iptables/ipset
fallback exists (ADR-0003); `enable-ipv4-masquerade` without
`enable-bpf-masquerade` is rejected at startup rather than silently falling
back.

### 3.13 Fragment tracking

`enable-ipv4-fragment-tracking` (default on) / `enable-ipv6-fragment-tracking`
(default off). `fraginfo` is a 64-bit summary of the IP header: bit 40
"fragmented" (MF set or offset ≠ 0), bit 41 "no L4 header" (offset ≠ 0), bits
32..39 protocol, low 32 bits the datagram id (16 for IPv4). Key
`ipv4_frag_id {daddr, saddr, id, proto, pad}` (12 B packed) / `ipv6_frag_id
{id be32, proto, pad[3], saddr, daddr}` (40 B); value `{sport, dport}` (4 B).

- A fragment **with** an L4 header (first fragment) loads its ports and, when
  fragmented, upserts the datagram entry (`BPF_ANY`); an update failure counts
  `REASON_FRAG_PACKET_UPDATE` and does not drop.
- A fragment **without** an L4 header looks up the datagram entry; miss →
  `DROP_FRAG_NOT_FOUND`. Out-of-order arrival (later fragment first) therefore
  drops that fragment.
- With tracking disabled, any fragment lacking an L4 header is
  `DROP_FRAG_NOSUPPORT`; NAT refuses to translate even the first fragment.
- Every fragment counts `REASON_FRAG_PACKET` in the metrics map.
- ICMP fragments are always `DROP_INVALID`.

### 3.14 Proxy interactions (what CT needs to know)

- `proxy_redirect` is set at create time when the policy verdict carries a
  proxy port; it is re-evaluated on every `Established` and a mismatch
  recreates the entry (§3.3). On `Reply`/`Related` with `proxy_redirect` the
  packet is redirected to the proxy unless it already came from the egress
  proxy (`tc_index` mark), so the proxy's own upstream connections are not
  looped.
- `from_l7lb` marks connections originated by an L7 LB proxy (packet from
  host with `FROM_HOST_L7_LB`); such flows skip egress policy and are
  delivered to the pod only via `cilium_host`.
- The cilium/proxy Envoy reads the CT maps directly to recover
  `src_sec_id` for accepted ingress connections: it builds the pod-ingress
  key from the accepted socket (`{daddr = client, saddr = pod, dport = pod
  port, sport = client port, IN}`) and reads offset 44. Layout and
  orientation are therefore a hard contract while Envoy is consumed as an
  external image (ADR-0001).

### 3.15 NAT46/NAT64 (scope only, later milestone)

Service-side 4-in-6 (`SVC_FLAG_NAT_46X64`): an IPv4 client reaching an IPv6
backend has its packet converted to IPv6 (`::ffff:a.b.c.d` synthesis) before
LB; CT tracks the converted IPv6 flow; the reply is converted back. The
RFC 6052 stateless gateway (`nat_46x64_prefix`, `CILIUM_CALL_IPV46_RFC6052` /
`IPV64_RFC6052`) translates without CT state. Both set `DROP_NAT46`/`DROP_NAT64`
on header conversion failure and `DROP_NAT_46X64_DISABLED` when compiled out.
Service translation is scheduled with milestone 2 load balancing (#79);
stateless RFC 6052 gateway support belongs to milestone 3. This scope
paragraph is not a complete translation algorithm or implementation claim.

## 4. Data model

### 4.1 In-program state

`CtState` (in-program only, never stored as-is): `nat_addr` (16 B), `nat_port`,
`rev_nat_index`, bits `loopback, node_port, dsr_internal, syn, proxy_redirect,
from_l7lb, from_tunnel, closing`, `src_sec_id`, `backend_id`. Filled by the
lookup on `Established`/`Reply` from the entry (Service: `backend_id`;
Ingress/Egress: the flags, `nat_addr`, `nat_port`) plus `rev_nat_index`;
supplied by the caller to create.

Tail-call buffers (`cilium_tail_call_buffer{4,6}`, PERCPU_ARRAY, unpinned, one
per object): `{tuple, ct_state, monitor u32, ret i32, l4_off i32 [, fraginfo
i64 for v6]}` carry a CT lookup result from the CT tail call into the policy
tail call. `cilium_nodeport_nat_buffer` carries `{nat_addr, nat_port}` from LB
into CT create (loopback). Scratch for `ct_entry` (56 B), tuples and
`snat_args {tuple, target}` lives in per-CPU "aux" maps to keep each program
under the 512-byte stack limit; flowsdn MUST do the same (§11).

### 4.2 Maps

See §2.1 for the catalogue; exact `MapSpec`s are in `01-bpf-map-abi-loader.md`.
Owner of CT/NAT/frag map *creation*: the agent, before any program load
(`OpenOrCreate`; incompatible pinned map → recreate empty, §7.5). Programs
reference them by name. Flags: `LRU_MEM_FLAVOR` = `BPF_F_NO_COMMON_LRU` when
`bpf-distributed-lru` else 0.

### 4.3 Userspace records

`CtMapRecord {Key: CtKey, Value: CtEntry}` and `NatMapRecord {Key, Value}` are
the JSON shapes of `cilium-dbg bpf ct|nat list -o json`. `GCFilter
{RemoveExpired bool, Time u32, MatchIPs set<(addr, netID)>, EmitCTEntryCB}`
is the GC's filter; `GCEvent {Key, Entry, NatMap}` is emitted per deleted CT
entry to the NAT-cleanup observer.

## 5. Algorithms

### 5.1 GC pass over one CT map

```
now := ct_cur_time(clock_source)
for (key, entry) in batch_iterate(map):
    if filter.RemoveExpired and entry.lifetime < now:  delete
    elif filter.MatchIPs ∩ {key.daddr, key.saddr} ≠ ∅:  delete   # endpoint scrub
    else:
        alive++ ; if key.flags == OUT: emit(key) to FQDN zombie tracker
on delete:
    map.delete(key)                       # ENOENT → skipped++ (LRU evicted it)
    if key.flags == SERVICE: act.count_failed(entry.rev_nat_index, entry.backend_id)
    emit GCEvent → NAT cleanup (§5.4)
```

Deletions on one map are serialized (one lock per map type) so the endpoint
scrub and the periodic pass do not interleave deletes. Both keys in a
`MatchIPs` comparison are the endpoint's IPv4 and IPv6 in the default network
(`netID 0`); per-cluster maps have no NAT counterpart and no endpoint scrub.

### 5.2 Batch iteration and consistency

Iterate with `BPF_MAP_LOOKUP_BATCH` on a cursor. Starting chunk size =
`2^ceil(log2(sqrt(2 * max_entries)))`; on `ENOSPC` (a hash bucket larger than
the buffer) double the chunk and retry the **same** cursor, up to 3 retries,
then fail the pass. `ENOENT` ends iteration. Guarantees: every key present
for the whole pass is visited exactly once; keys inserted or deleted during
the pass may or may not be visited; a key visited and then deleted by the
datapath before our `delete` yields `ENOENT` and is counted as skipped. The
pass is **not** a snapshot; an expired entry refreshed by a packet between
read and delete is deleted anyway (accepted: the connection recreates it).
A pass that fails is reported `uncompleted` and its interval math uses the
partial delete ratio.

Fallback (kernels without batch ops, NAT orphan scan): the reliable
`get_next_key` walk — after each `next_key`, re-`lookup` the current key; if
it vanished, resume from the previous key once (`KeyFallback`), else from the
returned next key (`Interrupted`, which may restart from the beginning); stop
after `4 × max_entries` lookups (`ErrMaxLookup`).

### 5.3 Interval adaptation

State: `expectedPrev` (last computed interval; `0` at start),
`actualPrev` (time since last pass start), `maxDeleteRatio` (max over maps of
`deleted / max_entries`). Constants: starting 5 min, min 10 s, max 12 h,
rounding 1 s.

```
if conntrack-gc-interval != 0: return it                     # fixed
if expectedPrev == 0: expectedPrev = 5m
elif 0 < actualPrev < expectedPrev:                          # woken early by signal
    ratio *= expectedPrev / actualPrev
if ratio > 0.25: next = max(round(expectedPrev * (1 - min(ratio, 0.9))), 10s)   # 1.3x..10x shorter
elif ratio < 0.05: next = min(round(expectedPrev * 1.5), 12h)                   # grow slowly
else: next = expectedPrev
if conntrack-gc-max-interval != 0: next = min(next, that)
export conntrack_gc_interval_seconds{global} = next
```

Full passes (all enabled families) commit `next` as the cached interval and
set a "force full GC" deadline = now + next. Signal-triggered partial passes
(one family) use `min(next, time until deadline)` so the other family cannot
starve. After the pass, unmute signals; wait for a signal (mute, drain the
queue, run only the signalled families) or the timer (run all). GC runs only
when the node has endpoints, except the initial pass which always runs.

### 5.4 NAT cleanup on CT delete

For a deleted CT entry with `flags == OUT` in a map that has a NAT
counterpart (global maps and per-cluster maps; not network-scoped maps):

- plain entry: NAT key = CT key with **addresses swapped** (natural
  orientation, `OUT`); lookup → `{to_saddr X, to_sport x}`; delete it and the
  reverse key `{daddr=X, saddr=CTkey.saddr… i.e. natural reply orientation,
  IN}`; deletes are silent.
- `dsr_internal` entry: delete the NAT key with **ports swapped**, `OUT`.

### 5.5 Orphan NAT purge

Run on signal-triggered passes (NAT or CT fill-up), or an explicit
`flowsdn-dbg bpf nat gc` request using the same scan, once per
(TCP map, any map) pair sharing a NAT map. Walk the NAT map (reliable dump):

- `IN` key `k` with value `v`: the owning CT Egress key is `{daddr=v.to_daddr,
  saddr=k.saddr, dport=k.sport, sport=v.to_dport, OUT}` (i.e. original
  `S:s → D:d` from `v` and `k`); missing in the CT map of `k.nexthdr` → orphan.
- `OUT` key `k`: owning CT key = `k` with addresses swapped, `OUT`; if missing,
  also try the DSR candidate `{daddr=k.daddr, saddr=k.saddr, dport=k.sport,
  sport=k.dport, OUT}` requiring `dsr_internal`; both missing → orphan.

Collect, then delete after the walk; count `IngressAlive/Deleted`,
`EgressAlive/Deleted`; refresh the NAT map pressure gauge with the alive
count. Orphans arise when the CT entry was LRU-evicted, or repurposed by the
datapath (stale-entry recreate) without the GC seeing it.

### 5.6 Endpoint lifecycle

- **First regeneration of a new endpoint** (not restored): scrub its IPv4/IPv6
  from all global CT maps (`MatchIPs`) in the background; the regeneration
  waits for completion before attaching. Restored endpoints skip the scrub
  (`SkipStateClean`) so their connections survive an agent restart.
- **Endpoint delete**: same scrub. Related entries share the IPs and are
  removed by the same match.
- **GC start**: after endpoint restore completes; the initial pass runs even
  with zero endpoints and a warning is logged if it has not finished within
  30 s; the CT pressure metric controller (batch count every 30 s) starts
  only after the initial pass.

### 5.7 Map sizing

Fixed sizes: `bpf-ct-global-tcp-max` (default 524288), `bpf-ct-global-any-max`
(262144), `bpf-nat-global-max` (default `(tcp + any) * 2 / 3` = 524288),
`bpf-neigh-global-max` (= NAT), each validated to `[1024, 16777216]`; NAT
MUST NOT exceed `tcp + any` (a default NAT size is capped to `2/3` of the sum,
an explicit one is rejected). `bpf-fragments-map-max` in `[256, 65536]`.

Dynamic sizing (`bpf-map-dynamic-size-ratio`, default 0.0025, disabled when 0
or > 1): `avail = total_ram * ratio`; `default_mem = Σ_m default_entries(m) *
element_size(m)` over CT-TCP, CT-any, NAT, neigh, sock-revnat; each map not
explicitly set gets `clamp(default_entries(m) * avail / default_mem, min(m),
16777216)` with `min` = 131072 (CT TCP), 65536 (CT any), 131072 (NAT), 65536
(sock rev-NAT); NAT is then capped to `2/3 (tcp + any)`. Reference vectors
(ratio 0.0025): 512 MiB → TCP 33140, any 16570, NAT 33140; 1 GiB → 66280 /
33140 / 66280; 4 GiB → 265121 / 132560 / 265121; 16 GiB → 1060485 / 530242 /
1060485. With `bpf-distributed-lru` every LRU size is rounded up to a multiple
of possible CPUs (capped down at 16777216) to match the kernel's rounding,
otherwise the pinned map would appear incompatible on every restart.

## 6. Configuration

| Key | Type | Default | Effect |
|---|---|---|---|
| `bpf-ct-global-tcp-max` | int | 524288 | TCP CT map size (both families); `ct-global-max-entries-tcp` legacy alias |
| `bpf-ct-global-any-max` | int | 262144 | non-TCP CT map size; alias `ct-global-max-entries-other` |
| `bpf-nat-global-max` | int | 524288 | NAT map size (both families) |
| `bpf-map-dynamic-size-ratio` | float | 0.0025 | §5.7; 0 disables |
| `bpf-distributed-lru` | bool | false | `BPF_F_NO_COMMON_LRU` on LRU maps; sizes rounded to CPUs |
| `preallocate-bpf-maps` | bool | false | affects hash maps only; LRU always preallocates |
| `bpf-ct-timeout-regular-tcp` | duration | 8000s | `CT_CONNECTION_LIFETIME_TCP` |
| `bpf-ct-timeout-regular-any` | duration | 60s | `CT_CONNECTION_LIFETIME_NONTCP` |
| `bpf-ct-timeout-service-tcp` | duration | 8000s | `CT_SERVICE_LIFETIME_TCP` |
| `bpf-ct-timeout-service-tcp-grace` | duration | 60s | `CT_SERVICE_CLOSE_REBALANCE` |
| `bpf-ct-timeout-service-any` | duration | 60s | `CT_SERVICE_LIFETIME_NONTCP` |
| `bpf-ct-timeout-regular-tcp-syn` | duration | 60s | `CT_SYN_TIMEOUT` |
| `bpf-ct-timeout-regular-tcp-fin` | duration | 10s | `CT_CLOSE_TIMEOUT` |
| `bpf-conntrack-accounting` | bool | false | packet/byte counters |
| `monitor-aggregation` | none/lowest/low/medium/max | medium | trace aggregation level |
| `monitor-aggregation-interval` | duration | 5s | `CT_REPORT_INTERVAL` |
| `monitor-aggregation-flags` | list | syn,fin,rst | `CT_REPORT_FLAGS` mask (fin=0x01 syn=0x02 rst=0x04 psh=0x08 ack=0x10 urg=0x20 ece=0x40 cwr=0x80; `all`/`none`) |
| `conntrack-gc-interval` | duration | 0 (adaptive) | fixed GC interval |
| `conntrack-gc-max-interval` | duration | 0 (12h) | cap on the adaptive interval |
| `enable-bpf-clock-probe` | bool | false | use jiffies time base when available |
| `enable-bpf-masquerade` | bool | false (Helm: true) | BPF masquerade; **DEVIATION**: required whenever masquerade is enabled (ADR-0003) |
| `enable-ipv4-masquerade` | bool | true | masquerade IPv4 pod traffic |
| `enable-ipv6-masquerade` | bool | true | masquerade IPv6 pod traffic |
| `enable-remote-node-masquerade` | bool | false | masquerade pod→remote-node traffic |
| `enable-masquerade-to-route-source` | bool | false | route-source address instead of device primary |
| `egress-masquerade-interfaces` | list | (all devices) | devices that masquerade |
| `ipv4-native-routing-cidr` / `ipv6-native-routing-cidr` | CIDR | — | `SNAT_EXCLUSION_DST_CIDR` |
| `enable-ip-masq-agent` | bool | false | `cilium_ipmasq_v{4,6}` non-masquerade CIDRs from `ip-masq-agent` ConfigMap |
| `node-port-range` | min-max | 30000-32767 | NAT port range lower bound = max + 1 |
| `enable-ipv4-fragment-tracking` | bool | true | §3.13 |
| `enable-ipv6-fragment-tracking` | bool | false | §3.13 |
| `bpf-fragments-map-max` | int | 8192 | frag map size |
| `enable-session-affinity` | bool | false | affinity map consulted before backend selection (§3.8) |
| `bpf-lb-affinity-map-max` | int | = `bpf-lb-map-max` | affinity map size |
| `bpf-lb-mode` | snat/dsr/hybrid/annotation | snat | dsr/hybrid create `dsr_internal` entries instead of SNAT (§3.10) |
| `tofqdns-idle-connection-grace-period` | duration | 0 | offset applied when CT GC marks FQDN zombie IPs alive |
| `enable-sctp` | bool | false | SCTP tracked and address-only NATed |
| `cluster-id` / cluster-aware addressing | — | — | per-cluster CT/NAT inner maps |

Accepted but ignored: `install-iptables-rules`, `iptables-*`,
`enable-ipv4-egress-gateway` iptables interactions, `enable-bpf-clock-probe`
on kernels without jiffies (auto-disabled with a log line as in the
reference).

## 7. Failure modes

### 7.1 Map full

CT and NAT maps are LRU: inserts evict the least recently used entry instead
of failing, so `DROP_CT_CREATE_FAILED` is rare (memory pressure). Eviction of
a live entry manifests as a mid-connection `New`: policy is re-evaluated (may
now deny), a NAT reverse entry may vanish (restored from the forward entry on
the next forward packet, §3.11) or become an orphan (§5.5). NAT port
exhaustion within a 32-attempt window → `DROP_NAT_NO_MAPPING`, plus
`SIGNAL_NAT_FILL_UP` which triggers an early GC and orphan purge. The
`cilium_bpf_map_pressure{map_name}` gauge (CT via batch count every 30 s;
NAT via orphan-scan alive count) is the operator signal.

### 7.2 GC falling behind

A pass longer than the interval simply delays the next one; the adaptive
algorithm shortens intervals when >25% of entries are expired. Only expiry
is affected — the datapath never depends on GC for correctness except NAT
port reuse. Metrics: `conntrack_gc_duration_seconds`, `_runs_total{status}`.

### 7.3 Clock behavior

Monotonic time: wall-clock jumps have no effect. Suspend/resume does not
advance ktime; entries appear younger. A jiffies/ktime **mismatch** between
datapath and GC (agent restarted with a different `enable-bpf-clock-probe`)
would expire everything or nothing: the effective clock source MUST be
persisted in the runtime config and reused for existing maps; changing it
requires flushing CT/NAT (§7.6).

### 7.4 Endpoint restart

Same IP restored → connections survive (no scrub). New endpoint reusing an IP
→ scrub deletes stale entries before attach. Agent restart → maps pinned,
programs keep running; GC resumes after restore.

### 7.5 Upgrade with a layout change

A changed key/value size or map flags makes the pinned map incompatible: the
agent unpins and recreates it **empty**, dropping all tracked connections
(NAT mappings included → in-flight NodePort/masqueraded flows break). The
reference avoids this by keeping `ct_entry`/tuple layouts frozen since 1.0
(names retained for that reason). flowsdn MUST do the same: any layout
change is a versioned rename (`cilium_ct4_global_v2` …) with old and new maps
coexisting during upgrade, the datapath consulting only the new one, and the
old pin removed by stale-map cleanup after all programs are re-attached.
Changing `max_entries` alone also triggers recreate (documented operator
impact).

### 7.6 Flush

`cilium-dbg bpf ct flush [global|<cluster id>]` runs the GC filter with
`Time = MaxUint32` (delete everything) and emits NAT cleanup per entry;
`cilium-dbg bpf nat flush` walks and deletes every NAT entry;
`cilium-dbg bpf nat retries flush` zeroes the histograms. flowsdn-dbg MUST
provide the same commands.

### 7.7 Missing kernel features

No batch ops (< 5.6): GC MUST fall back to the reliable walk; the pressure
controller is disabled. No jiffies helper: ktime. No LRU hash: unsupported
(startup refuses, ADR-0001).

## 8. Observability

Prometheus (namespace `cilium`, subsystem `datapath`, names kept for
dashboards):

| Metric | Type | Labels |
|---|---|---|
| `conntrack_gc_runs_total` | counter | `family` (ipv4/ipv6), `protocol` (TCP/non-TCP), `status` (completed/uncompleted) |
| `conntrack_gc_key_fallbacks_total` | counter | `family`, `protocol` |
| `conntrack_gc_entries` | gauge | `family`, `protocol`, `status` (alive/deleted) |
| `nat_gc_entries` | gauge (disabled by default) | `family`, `direction` (ingress/egress), `status` |
| `conntrack_gc_duration_seconds` | histogram | `family`, `protocol`, `status` |
| `conntrack_gc_interval_seconds` | gauge | `global` |
| `conntrack_dump_resets_total` | counter | `area=conntrack`, `name=dump_interrupts`, `family` |
| `signals_handled_total` | counter | `signal` (nat_fill_up/ct_fill_up), `data` (ipv4/ipv6), `status` |
| `cilium_bpf_map_pressure` | gauge | `map_name` |
| `cilium_bpf_map_ops_total` | counter | `map_name`, `operation`, `outcome` |

NAT statistics (`cilium-dbg bpf nat stats` / `nat_endpoint_max_connection`):
top-k of egress-IP × remote endpoint 3-tuple port utilization, computed by a
periodic NAT map walk; `05-service-lb.md`/agent status spec details.

Datapath metrics map reasons: `REASON_FRAG_PACKET`,
`REASON_FRAG_PACKET_UPDATE`, `REASON_MTU_ERROR_MSG`, plus every drop reason in
§2.5 by direction.

Monitor: trace events carry `reason` (§2.5) and are throttled per §3.7; drop
events carry the reason code and `ext_err` (errno of a failed map update).
Debug events (`DBG_CT_LOOKUP4_1/2`, `DBG_CT_MATCH`, `DBG_CT_VERDICT`,
`DBG_CT_CREATED4/6`) are emitted only with datapath debug.

Logs: GC start/finish (initial pass duration), interval recalculation
(expected/actual/new interval, ratio), orphan purge counts per family and
cluster, skipped deletes (debug), uncompleted passes (warn).

REST/status: `clock-source` in `/healthz`; `GET /map/{name}` and
`/map/{name}/events` for the NAT map (event buffer, `bpf-map-event-buffers`).

## 9. Test plan

Reference test cases reused as a checklist (names from `pkg/maps/ctmap`,
`pkg/maps/nat`, `bpf/tests`); flowsdn writes its own harness (ADR-0002).

Unit (userspace, no kernel):
- [ ] `TestMapKey`, `TestMaxEntries` — key encoding, size selection.
- [ ] `TestCalculateInterval`, `TestGetInterval` — §5.3 including the early-wake ratio adjustment and min/max clamps.
- [ ] `TestGCEnableDualStack`, `TestGCEnableRatchet` — partial passes never starve a family; forced-full deadline.
- [ ] `TestConvert` (timestamp) — ktime and jiffies conversions (`0x00ffff0012345678` at 100 Hz → `0x28f5999c834108f`).
- [ ] `Test_topk` — NAT stats heap.
- [ ] Dynamic sizing vectors from §5.7; LRU CPU alignment.
- [ ] Dump text/JSON formats identical to `cilium-dbg` fixtures (`bpf_ct_list_test.go`, `bpf_nat_list_test.go`).

Privileged (kernel, maps only):
- [ ] `TestPrivilegedCtGcIcmp` — related ICMP entries reaped with their flow.
- [ ] `TestPrivilegedCtGcTcp` — expired vs alive by `lifetime`; NAT pair deleted with the CT entry (address-swap correlation).
- [ ] `TestPrivilegedCtGcDsr` — DSR entries delete the port-swapped NAT key.
- [ ] `TestPrivilegedOrphanNatGC` — all four cases of §5.5 (IN/OUT orphan and alive, DSR candidate).
- [ ] `TestPrivilegedCount` — batch count matches inserted entries, ENOSPC retry path.
- [ ] `TestPrivilegedCtNetworkID` — network-scoped maps have no NAT counterpart.
- [ ] `TestPrivilegedPerClusterCTMaps`, `...Cleanup`, `TestPrivilegedPerClusterMaps` (NAT) — inner map create/delete per cluster id.
- [ ] `TestPrivilegedDumpBatch4`, `TestPrivilegedFlushNat`, `TestPrivilegedCountNat`.
- [ ] Endpoint scrub: entries with the IP in either address position are deleted; restored endpoint is not scrubbed.

BPF (`BPF_PROG_RUN` with packet fixtures):
- [ ] `conntrack/ct_update_timeout` — SYN → `CT_SYN_TIMEOUT`, non-SYN promotes; report throttling.
- [ ] `conntrack/ct_lookup` — Forward/Reverse/Bidir results, filter mask, closing-entry SYN returns `New`.
- [ ] `conntrack_svc/ct_lookup_svc` — Service key, `Svc` filter by `rev_nat_index`, rebalance grace.
- [ ] `ct4/ct4_syn`, `ct4/ct4_rst` — entry creation, RST before both SYNs closes both directions.
- [ ] Fixture: full TCP handshake → `seen_non_syn`, both `SYN` bits; FIN from each side → closing bits then `CT_CLOSE_TIMEOUT`; new SYN on closing entry recreates.
- [ ] Fixture: UDP idle — lifetime = `NONTCP` and refreshed by replies.
- [ ] Fixture: ICMP DEST_UNREACH for a tracked UDP flow → `Related`; unrelated error → `New`.
- [ ] `nat4_port_allocation_tcp/udp` — keep-port, clamp, `+1` retry, histogram, `SIGNAL_NAT_FILL_UP` after 16.
- [ ] `nat4_icmp_error_{tcp,udp,sctp,icmp}[_egress][_rfc1191]`, `nat4_icmp_error_tcp_snat_revnat`, `icmp_error_revnat` — inner-packet translation both ways, truncated inner TCP tolerated, zero UDP checksum.
- [ ] `tc_nodeport_snat_conflict_{host,pod,egressproxy}_ipv{4,6}` — host traffic reserves its port with `needs_ct`; pod SNAT avoids it.
- [ ] `tc_nodeport_lb4_nat_lb`, `tc_nodeport_lb4_nat_backend`, `xdp_nodeport_lb4_nat_*`, `nodeport_overlay_nat_lb`, `tc_nodeport_lb_nat_lb_dynamic` — NodePort forward creates `node_port` Egress entry; reply rev-SNAT + rev-DNAT.
- [ ] `tc_nodeport_lb_terminating_backend_{0,1}` — draining vs re-select on SYN; `ct_update_svc_entry` in place.
- [ ] Fixture: backend deleted → `Existing` re-selects and rewrites `backend_id`.
- [ ] `host_bpf_masq_{native,overlay}`, `hostfw_bpf_masq`, `remote_node_masquerade{,_skip}_test`, `skip_tunnel_nodeport_{masq,nat,revnat}` — decision order §3.12 including reply suppression and exclusion CIDR.
- [ ] `tc_nodeport_icmp{4,6}_snat{,_tunnel,_hostfw}` — ICMP echo NAT on identifier.
- [ ] `ipfrag_helpers_ipv4`, `ipfrag_helpers_ipv6{,_nofrag}`, `tc_nodeport_lb_fragments_{ew,ns}` — fraginfo encoding, first-fragment upsert, later-fragment lookup, `DROP_FRAG_NOT_FOUND`.
- [ ] `hairpin_sctp_flow` — loopback rev-NAT via `nat_addr/nat_port`.
- [ ] `inter_cluster_snat_clusterip_*` — per-cluster map selection.
- [ ] `tc_egressgw_snat`, `tc_egressgw_redirect_*` — egress-gateway `needs_ct` and ifindex redirect before SNAT.
- [ ] `tc_policy_reject_response_test` — Related ICMP admitted without policy.

e2e:
- [ ] Upgrade with unchanged layout keeps a long-lived TCP flow and a masqueraded UDP flow alive across agent restart.
- [ ] `cilium-dbg bpf ct list` from the reference CLI binary parses flowsdn maps.
- [ ] Envoy (cilium/proxy image) resolves `src_sec_id` for an L7-proxied ingress connection.

## 10. Kernel and platform requirements

- Map types: `LRU_HASH` (4.10), `PERCPU_ARRAY`, `ARRAY_OF_MAPS` (per-cluster),
  `LPM_TRIE` with `BPF_F_NO_PREALLOC` (ip-masq-agent), `HASH` (reverse NAT).
- `BPF_MAP_LOOKUP_BATCH` / `LOOKUP_AND_DELETE_BATCH` (5.6) for GC and counts;
  `get_next_key`/`lookup` fallback.
- Helpers: `ktime_get_ns`, `jiffies64` (5.5, optional), `get_prandom_u32`,
  `map_lookup/update/delete_elem` with `BPF_NOEXIST`, `skb_load/store_bytes`,
  `csum_diff`, `l3_csum_replace`, `l4_csum_replace` (`BPF_F_PSEUDO_HDR`),
  `perf_event_output` (signals, monitor), `fib_lookup` with
  `BPF_FIB_LOOKUP_SRC` (6.7, only for `enable_nodeport_source_lookup`),
  `redirect_neigh` (5.10) for the parent-interface reply redirect,
  `tail_call`. Atomic `xadd` (u64) for counters.
- XDP variants of the NodePort/NAT path need `xdp_adjust_meta` and software
  checksum handling (`01-bpf-programs` context abstraction).
- `BPF_F_NO_COMMON_LRU` for distributed LRU (4.10).
- Minimum kernel is set by the datapath spec; nothing here needs more than
  5.10 except the optional `BPF_FIB_LOOKUP_SRC`. x86-64 and arm64: layouts are
  packed/explicitly padded, no arch difference; possible-CPU count for LRU
  rounding read from `/sys/devices/system/cpu/possible`.

## 11. Rust design notes

- **`flowsdn-bpf-abi`** (no_std, shared by BPF and userspace): `#[repr(C,
  packed)] CtTuple4 {daddr: [u8;4], saddr, dport: u16be, sport, nexthdr: u8,
  flags: u8}`, `CtTuple6`, `#[repr(C)] CtEntry` (56 B, flags as a `u16` with
  const bit masks, `src_sec_id` at 44 asserted by a `const` size/offset test),
  `NatEntryCommon`, `NatEntry4/6`, `FragId4/6`, `FragPorts`, `TupleFlags`,
  `CtDir`, `CtScope`, `CtEntryTypes`, `CtStatus`, drop/trace/signal
  constants. `unsafe impl aya::Pod` in userspace only. Static asserts on every
  size and offset in §2.
- **Datapath crate (aya-ebpf)**: module `ct` with `lookup(map, tuple, dir,
  scope, types, state, flags) -> Result<CtStatus, DropReason>`,
  `create(...)`, `update_svc_entry`, `is_reply`, `has_nodeport_egress_entry`;
  module `nat` with `needs_masquerade`, `snat`, `rev_snat`, `new_mapping`;
  module `frag`. Generic over v4/v6 via a `Tuple` trait with associated
  `Addr`; everything `#[inline(always)]` except the big decision functions
  (`needs_masquerade`, `snat`) which the reference keeps `noinline` for
  verifier complexity — mirror that with `#[inline(never)]` and pass
  arguments through per-CPU scratch maps to respect the 512-byte stack.
  Scratch: `PerCpuArray<CtEntry>`, `PerCpuArray<CtTuple6>`,
  `PerCpuArray<SnatArgs>`. Time via `bpf_ktime_get_ns`/`bpf_jiffies64`
  behind a `.rodata` `enable_jiffies` global; timeouts as `.rodata` u32
  seconds converted once per packet. The allocation loop is verifier-bounded
  to 32 attempts; source-level unrolling is not required (ADR-0011, #73).
- **Userspace `flowsdn-ctgc`** (agent task, no Hive per ADR-0004): owns the
  opened CT/NAT/frag `aya::maps::MapData`, an `EndpointIps` snapshot source, a
  `Signals` receiver (perf reader for `cilium_signals`), a `Fence` for "endpoints
  restored", and exposes `scrub(ips)`, `flush()`, `run_once(filter)`. Batch
  iteration: aya lacks a batch-lookup API at the time of writing — implement
  `bpf(BPF_MAP_LOOKUP_BATCH)` over `MapData::fd()` locally (`flowsdn-bpf-sys`)
  with the chunk-doubling retry of §5.2, and upstream it. Deletes go through
  `HashMap::remove` ignoring `ENOENT`. Time via a tiny loaded program that
  returns `ktime_get_ns` (reference `GetMtime`) or `/proc` jiffies probe.
- `flowsdn-dbg bpf ct|nat` reuse the same crate for dump formatting; formats
  in §2.2–2.4 are golden-tested against reference output.
- Config: the typed config struct (ADR-0004) carries all §6 keys; the
  datapath receives them as `.rodata` patches (timeouts, `enable_jiffies`,
  `kernel_hz`, masquerade addresses, `nodeport_port_max`, `ephemeral_min`,
  `enable_remote_node_masquerade`, `enable_conntrack_accounting`,
  `enable_ipv{4,6}_fragments`).

## 12. Open decisions

1. **Resolved (#73, ADR-0011): verifier-bounded allocation loops.**
   Retain the 32-attempt bound; use bounded loops on the 6.6 floor rather than
   requiring source-level unrolling. Both architectures still require live
   verifier tests; a failed verifier result must be fixed before shipping.
2. **Resolved (#74, ADR-0011): effective TCP lifetime is 8000 seconds.**
   Both regular and service TCP defaults use §6 values. Patch them into BPF
   configuration; the 21600-second reference fallback is not the runtime default.
3. **Resolved (#75, ADR-0011): use `Existing` in the internal service CT API.**
   Preserve emitted CT/trace reason encodings; the internal enum name does not
   reinterpret the monitor result ignored by service lookups.
4. **Resolved (#76, ADR-0011): signal-triggered orphan scans.**
   Keep §5.5 scheduling, with an explicit `flowsdn-dbg bpf nat gc` manual
   trigger using the same scan. Do not add every-Nth-periodic scans. The CLI
   trigger and live signal integration remain implementation obligations.
5. **Batch delete.** Use `BPF_MAP_DELETE_BATCH` for expired keys instead of
   per-key deletes. Recommendation: yes, behind the same fallback; report the
   count of `ENOENT` from the batch result as `skipped`.
6. **Resolved (#78): retain standalone LRU capacity on restart.** A positive
   capacity-only change for LRU CT/NAT maps reuses the pinned map, preserves
   entries, and warns with requested and actual capacities. Both increases and
   decreases retain the existing capacity; no resize is implied. Type, layout
   or incompatible flags still require replacement. Map-in-map inner templates
   remain exact, including capacity. Spec 01 §3.2 and the loader planner own
   this policy; live pin/recreation integration remains required.
7. **Resolved (#79, ADR-0011): service NAT46/64 belongs to milestone 2.**
   Implement it with the load-balancer flag `SVC_FLAG_NAT_46X64`; translation
   and return traffic are acceptance requirements, not completed features.
   The independent stateless RFC 6052 gateway remains advanced networking
   in milestone 3; extending §3.15 is required before its implementation.

### Batch 6: deletion progress and restore evidence (#77, #232)

Expired-key deletion uses batch deletion with a cached unsupported fallback.
The processed count describes the successful prefix. A missing-key batch error
is not a count of all missing keys: retry the unprocessed suffix individually,
counting only observed single-key ENOENT as skipped. Other errors retain observed
progress and fail the pass. `flowsdn-bpf-loader::delete` implements this protocol
against a syscall adapter; production GC wiring and privileged batch-syscall
validation remain #292. Unsupported classification must distinguish malformed
arguments from a validated unsupported map/kernel capability.

The frozen CT value has expiry and mutable last-report fields, **no creation
timestamp**. Do not fabricate a creation time or silently extend its ABI.
Map-ID equality plus unchanged quiesced key/value observations can detect some
replacements, but cannot prove the same entry generation after delete/reinsert.
Use those limited assertions for restore tests; see spec 19's reuse contract.
