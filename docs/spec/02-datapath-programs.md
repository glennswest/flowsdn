# Datapath programs — specification

Status: draft. Derived from: `docs/inventory/01-bpf-programs.md`,
`docs/inventory/02-bpf-maps-loader.md`, `docs/inventory/05-policy-identity.md`
(§ BPF policy map), `docs/inventory/09-hubble-monitor.md` (event layouts, drop
table); reference cilium v1.20.1 (7d68cfb394) paths `bpf/bpf_lxc.c`,
`bpf/bpf_host.c`, `bpf/bpf_overlay.c`, `bpf/bpf_xdp.c`, `bpf/bpf_wireguard.c`,
`bpf/bpf_sock.c`, `bpf/lib/{common,policy,conntrack,nat,nodeport,nodeport_egress,
lb,fib,local_delivery,encap,tunnel,identity,proxy,trace,drop,drop_reasons,
ipfrag,ipv4,ipv6,lxc,classifiers,tailcall}.h`, `bpf/tests/*.c` (case names
only). Governed by ADR-0001..0004; ADR-0002 (Rust BPF, no C) and ADR-0003 (no
iptables) shape this document most.

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* the flowsdn datapath does and the exact data it exchanges with the
kernel, with its own agent, and with foreign nodes. It does not transcribe
reference code; where the reference is kept for compatibility, the consumer
that depends on it is named. Deviations are marked **DEVIATION**.

Sibling specs, referenced by name and not duplicated here:

- **01-bpf-map-abi-loader** — every map's key/value layout, sizing, pinning,
  renames, `.rodata` patching mechanics, reachability pruning, tail-call
  population, tc/tcx/netkit/XDP/cgroup attach, upgrade protocol.
- **03-identity-ipcache** — identity numbering (reserved, CIDR, remote-node
  scopes, cluster-mesh bit split), `cilium_ipcache_v2` and `cilium_lxc`
  semantics, aggregate identities.
- **04-conntrack-nat** — CT and NAT map contents, TCP state machine, timeouts,
  GC, SNAT mapping lifecycle, ICMP error translation.

This spec owns: what runs at each hook, the order of decisions per packet,
the metadata contract between programs and with userspace (mark, `cb[]`,
`tc_index`, tunnel key), the policy verdict computation as executed in BPF,
the datapath's *use* of CT/NAT/LB/ipcache, drop and trace emission, the
configuration constants the programs read, kernel requirements, the test
plan and the aya-ebpf design.

---

## 1. Scope

### 1.1 Program inventory and milestone assignment

Milestones: **M1** first shippable datapath (this spec's normative core),
**M2** kube-proxy-replacement completeness and L7, **M3** encryption,
egress, and long-tail features. Every program, hook and feature below carries
a milestone; anything marked M2/M3 is specified here only to the extent
needed to keep M1 forward-compatible (mark bits, cb slots, tail slots,
config names are reserved now).

| Program | Object | Hook | Milestone |
|---|---|---|---|
| `from_container` | lxc | tc/tcx ingress of pod veth (host side) / netkit primary | M1 |
| `to_container` | lxc | tc/tcx egress of pod veth; attached only when endpoint routes, host firewall or L7 LB require it | M1 |
| `lxc_policy` | lxc | not attached; slot `ep_id` of `cilium_call_policy` | M1 |
| `lxc_policy_egress` | lxc | slot `ep_id` of `cilium_egresscall_policy` (L7 LB return path) | M2 |
| `from_netdev` | host | tc/tcx ingress of each native device | M1 |
| `to_netdev` | host | tc/tcx egress of each native device | M1 |
| `from_host` | host | tc/tcx egress of `cilium_host` | M1 |
| `to_host` | host | tc/tcx ingress of `cilium_host` and of `cilium_net` | M1 |
| `host_policy` | host | slot `host_ep_id` of `cilium_call_policy` (host firewall) | M2 |
| `from_overlay` | overlay | tc/tcx ingress of `cilium_vxlan` / `cilium_geneve` | M1 |
| `to_overlay` | overlay | tc/tcx egress of the tunnel device | M1 |
| `xdp_entry` | xdp | XDP on native devices (driver or generic) | M2 |
| `from_wireguard` / `to_wireguard` | wireguard | tc/tcx on `cilium_wg0` | M3 |
| `sock4/6_connect`, `sendmsg`, `recvmsg`, `getpeername`, `pre_bind`, `post_bind`, `sock_release` | sock | cgroup v2 root | M2 |
| `sock_{tcp,udp}_destroy_v{4,6}` | sock_term | `iter/tcp`, `iter/udp` + kfunc `bpf_sock_destroy` | M3 |
| feature probes (`fib_lookup` flag support) | probes | load-only | M1 (loader, spec 01) |

Feature-to-milestone table (the code paths inside the programs above):

| Feature | M | Notes |
|---|---|---|
| Endpoint egress/ingress pipelines, IPv4 + IPv6, dual-stack | 1 | |
| CT lookup/create/refresh, reply and related detection | 1 | tables in spec 04 |
| L3/L4 identity policy, two-stage lookup, precedence, deny, audit mode, policy-verdict events | 1 | |
| Per-packet ClusterIP, NodePort, ExternalIP, HostPort, LoadBalancer; random backend selection; session affinity; source ranges; internal/external traffic policy | 1 | Maglev is M2 |
| NodePort SNAT to remote backend, rev-DNAT/rev-SNAT of replies | 1 | |
| BPF masquerade (v4/v6), ip-masq-agent exclusion CIDRs, SNAT exclusion CIDR | 1 | |
| VXLAN and Geneve overlay, VNI = identity | 1 | one code path, encap type is a constant |
| Host↔pod (`cilium_host`), BPF host routing (`redirect_neigh`/`redirect_peer`) | 1 | legacy stack routing: see §12 |
| Hairpin / loopback service access | 1 | |
| Fragment tracking (first-fragment L4 port cache) | 1 | |
| ICMP frag-needed pass-through in policy; TTL exceeded | 1 | full PMTU (DSR ICMP errors) is M2 |
| Monitor events: drop, trace, policy verdict, debug | 1 | |
| No-backend ICMP unreachable response | 1 | |
| Policy-deny ICMP response (`policy_deny_response_enabled`) | 2 | |
| DSR (IP option, IPIP, Geneve), hybrid per-service DSR, DSR ICMP errors | 2 | |
| Maglev backend selection | 2 | LUT in `HASH_OF_MAPS` |
| XDP NodePort acceleration, XDP prefilter | 2 | |
| Socket LB (cgroup programs), socket termination | 2 / 3 | |
| L7 proxy redirect (TPROXY via `sk_assign` + mark), L7 LB, `lxc_policy_egress` | 2 | |
| Host firewall (`host_policy`) | 2 | |
| Mutual auth (`cilium_auth_map`, `SIGNAL_AUTH_REQUIRED`) | 2 | |
| Local Redirect Policy skip-LB maps | 2 | |
| Active connection tracking counters | 2 | |
| IPsec (XFRM marks, `cilium_net` redirect), WireGuard hooks, strict modes | 3 | |
| Egress gateway (policy LPM, SNAT to egress IP, `MARK_MAGIC_EGW_DONE`) | 3 | |
| Bandwidth manager / EDT | 3 | |
| NAT46/64 (service and RFC 6052 gateway) | 3 | |
| SRv6, multicast, VTEP, L2 announcements, ARP responder, IP-option trace id | 3 | |
| Cluster-mesh per-cluster CT/SNAT maps, inter-cluster SNAT | 3 | |
| IPIP termination, ENI CONNMARK, MKE host detection | 3 | |
| Datapath plugins (`freplace` hooks) | dropped | ADR-0001 internals are free; no consumer |

### 1.2 Out of scope

Map layouts (spec 01), identity allocation (spec 03), CT/NAT semantics beyond
the datapath's calls into them (spec 04), the agent side of everything
(attach ordering is spec 01; endpoint regeneration is the agent spec).

---

## 2. Compatibility contract

Two classes of consumer depend on datapath-visible bits: **external** (Envoy
via TPROXY mark, XFRM policies, the nftables residual of ADR-0003, WireGuard
routing rules, `cilium-dbg`/Hubble decoders, other cluster nodes on the
wire) and **internal** (our own agent). Everything in this section is
external-facing and MUST match the reference bit-for-bit unless marked
**DEVIATION**.

### 2.1 `skb->mark` layout

```
 31                16 15  12 11   8 7        0
+-------------------+------+------+----------+
| payload (16 bits) | key  | magic| low byte |
+-------------------+------+------+----------+
```

**Resolved (#1, ADR-0011):** the entire mark layout below remains bit-compatible,
including internal magics; no private 32-bit identity packing is introduced.

- Bits 8..11 = magic, mask `0x0F00` (`MARK_MAGIC_HOST_MASK`).
- Bits 8..15 = "key mask" `0xFF00` (`MARK_MAGIC_KEY_MASK`); bits 12..15 carry
  the IPsec key index for `MARK_MAGIC_ENCRYPT`.
- Bits 16..31 = payload. Bits 0..7 = upper 8 bits of a 24-bit identity when
  the magic carries an identity, or the cluster id under `MARK_MAGIC_CLUSTER_ID`.
- Identity recovery for identity-carrying magics: `id = (mark >> 16) |
  ((mark & 0xFF) << 16)`. Identity storage: `mark = magic | ((id & 0xFFFF) << 16)
  | ((id >> 16) & 0xFF)` (`set_identity_mark`); with cluster-aware addressing
  the low byte instead holds `cluster_id` and only 16 bits of local identity
  travel in the payload (spec 03 owns the bit split).

| Constant | Value | Payload | External consumer |
|---|---|---|---|
| `MARK_MAGIC_TO_PROXY` | `0x0200` | proxy port in bits 16..31 | Envoy / DNS proxy TPROXY rule (nftables residual), `ip rule` for proxy return |
| `MARK_MAGIC_CLUSTER_ID` | `0x0200` (alias) | cluster id in bits 0..7 (and 16..31 when extended) | internal (never coexists with TO_PROXY on one packet) |
| `MARK_MAGIC_SNAT_DONE` | `0x0300` | — | internal |
| `MARK_MAGIC_OVERLAY` | `0x0400` | source identity | internal |
| `MARK_MAGIC_EGW_DONE` | `0x0500` | source identity | internal (M3) |
| `MARK_MAGIC_SKIP_TPROXY` | `0x0800` | — | nftables TPROXY chain skips it |
| `MARK_MAGIC_PROXY_EGRESS_EPID` | `0x0900` | source endpoint id | Envoy sets it on L7 LB upstream traffic |
| `MARK_MAGIC_PROXY_INGRESS` | `0x0A00` | source identity | Envoy sets it (upstream of ingress proxy) |
| `MARK_MAGIC_PROXY_EGRESS` | `0x0B00` | source identity | Envoy sets it |
| `MARK_MAGIC_HOST` | `0x0C00` | — | nftables residual sets it on host-originated traffic (ADR-0003) |
| `MARK_MAGIC_DECRYPT` | `0x0D00` | IPsec: node id; WireGuard: identity | XFRM input policy |
| `MARK_MAGIC_HEALTH` | `0x0D00` (alias, socket LB only) | — | health-check sockets; reset before tc |
| `MARK_MAGIC_ENCRYPT` | `0x0E00` | node id; key index in bits 12..15 | XFRM output policy (SPI = key index) |
| `MARK_MAGIC_IDENTITY` | `0x0F00` | source identity | `ip rule` for endpoint routes; WireGuard device |

MUST: the datapath MUST clear the mark to 0 when it consumes a
host-origin magic in `to_container`/`from_host` (`inherit_identity_from_host`
semantics, §3.2) so routing rules keyed on the mark do not fire twice.

### 2.2 `skb->tc_index` flags

`FROM_INGRESS_PROXY 1`, `FROM_EGRESS_PROXY 2`, `SKIP_NODEPORT 4`,
`SKIP_HEALTH_CHECK 8`, `SKIP_HOST_FIREWALL 16`. Consumer: internal only
(the same skb crosses `cilium_host` from host object to lxc object). Kept
identical because the L7 test fixtures depend on them.

### 2.3 `skb->cb[0..4]` slots

Five 32-bit slots, cleared on entry to every entry program (`bpf_clear_meta`),
carried across tail calls and across `redirect`/`redirect_peer` into the next
object. XDP uses the per-CPU `cilium_xdp_scratch` array with the same slot
numbering (spec 01).

| Slot | Primary name | Aliases (context) |
|---|---|---|
| 0 | `CB_SRC_LABEL` | `CB_PORT`, `CB_HINT`, `CB_PROXY_MAGIC`, `CB_ENCRYPT_MAGIC`, `CB_DST_ENDPOINT_ID`, `CB_SRV6_SID_1`, `CB_VERDICT` |
| 1 | `CB_DELIVERY_FLAGS` | `CB_NAT_46X64`, `CB_ADDR_V4`, `CB_ADDR_V6_1`, `CB_IPCACHE_SRC_LABEL`, `CB_SRV6_SID_2`, `CB_CLUSTER_ID_EGRESS`, `CB_TRACED`, `CB_FORCED_BACKEND_V4/V6_1` |
| 2 | `CB_CT_STATE`-adjacent | `CB_ADDR_V6_2`, `CB_SRV6_SID_3`, `CB_CLUSTER_ID_INGRESS`, `CB_NAT_FLAGS` |
| 3 | — | `CB_ADDR_V6_3`, `CB_FROM_HOST`, `CB_SRV6_SID_4` |
| 4 | `CB_CT_STATE` | `CB_ADDR_V6_4`, `CB_ENCRYPT_IDENTITY`, `CB_SRV6_VRF_ID` |

`CB_DELIVERY_FLAGS` bits: `REDIRECT 1`, `FROM_HOST 2`, `FROM_TUNNEL 4`,
`USE_REDIRECT_PEER 8`, `FROM_INGRESS_PROXY 16`, `FROM_EGRESS_PROXY 32`.
`CB_NAT_FLAGS_REVDNAT_ONLY 1`. Sentinel `FROM_HOST_L7_LB 0xFACADE42` in slot 3.
Internal contract; kept identical so reference test fixtures translate.

### 2.4 XDP → tc metadata (M2)

`data_meta` word `XFER_FLAGS`: `XFER_PKT_NO_SVC 1`, `XFER_PKT_SNAT_DONE 4`,
set via `xdp_adjust_meta(-4)`. tc programs MUST read and honour these when
present and treat absence as "no XDP ran".

### 2.5 Overlay wire format

**Resolved decision (#55, see §12.3): use the reference-compatible
wire encoding.** A mixed cluster during migration MUST forward pod traffic in
both directions with correct identities.

- VXLAN (UDP dst `tunnel_port`, default 8472) and Geneve (default 6081):
  `VNI = sec_identity << 8` as a 24-bit field, i.e. `tunnel_id` passed to
  `bpf_skb_set_tunnel_key` is the identity itself and the driver shifts it.
  Recovery: `identity = ntohl(vni_word) >> 8`.
- Identities `WORLD_IPV4 (9)` and `WORLD_IPV6 (10)` MUST be collapsed to
  `WORLD (2)` on the wire and re-split by ethertype on decap.
- `HOST (1)` MUST be rewritten to `LOCAL_NODE/REMOTE_NODE (6)` before encap;
  a received VNI decoding to `HOST` MUST be dropped (`DROP_INVALID_IDENTITY`).
- The tunnel key is read/written with `TUNNEL_KEY_WITHOUT_SRC_IP =
  offsetof(bpf_tunnel_key, local_ipv4)` (= 12 bytes) on tc; source port 0
  (kernel picks) on tc, hash-derived on XDP.
- Geneve DSR option (M2): class `0x014B`, type `0x81` (critical bit set),
  length 2 (IPv4: `addr be32, port be16, pad u16`) or 5 (IPv6: `addr[16],
  port, pad`) in 4-byte units. IPv4 DSR IP option: type `IPOPT_COPY|0x1a`,
  8 bytes `{type, len=8, port be16, addr be32}`. IPv6 DSR: 24-byte
  Destination Options header, option type `0x1B`, option length 20.
- Because identities are 24 bits on the wire, spec 03 MUST keep identity
  numbering within 24 bits and MUST keep the reference reserved values.

#### 2.5.1 Fixed codec contract and implementation boundary

The initial allocation-free ABI codecs cover the ordinary 8-byte VXLAN
header, version-zero Ethernet Geneve base header, and individual IPv4/IPv6
Geneve DSR options. They do not parse IP/UDP packets, validate complete
option chains, perform peer authorization, or establish mixed-cluster
interoperability. These remain datapath integration and validation work.

VXLAN has the network-order flag word `0x08000000`, followed by the VNI
word described above; extensions and other flag combinations are unsupported
by this initial codec. Geneve's first byte contains a two-bit zero version
and six-bit option length in four-byte units. Its second byte contains OAM
(bit 7, unsupported here), critical (bit 6), and six reserved zero bits.
The protocol is Ethernet bridging (`0x6558`, network order). The next three
bytes contain the VNI and the final reserved byte is zero. The base codec
preserves either critical-flag value and exposes the option word count;
callers must separately validate the indicated options and packet length.

The DSR option header is four bytes: network-order class `0x014b`, type
`0x81`, and a byte with three reserved zero bits followed by five length
bits. Length excludes the option header: IPv4 uses two words (12 total
bytes), IPv6 five words (24 total bytes). Addresses and ports are network
order; encoders zero the two padding bytes. These initial fixed-option
codecs require zero reserved bits/padding and reject other classes/types
or inconsistent lengths. This is an explicit bounded codec subset, not a
claim that every reference receive path rejects nonzero padding. Fixed
array input sizes prevent truncated option/header inputs from being passed
without a prior checked conversion by the packet parser.

Identity input exceeding 24 bits is rejected before any rewrite or shift;
HOST is rewritten to 6 on transmit and rejected on receive. WORLD is split
into 9/10 by inner IP family on dual-stack decapsulation and retained as 2
for single-stack operation. This layer does not validate identity ownership.

Reference ambiguity clarification (2026-09-09): the pinned reference
`7d68cfb394`, `bpf/lib/tunnel.h` established the base/option bit layouts
and padding sizes; `bpf/lib/overloadable_xdp.h` established the VXLAN flag,
Ethernet protocol and Geneve option-word accounting. Its DSR insertion does
not consistently set the base critical flag, despite the critical option
type. Therefore the base codec must not reject a known DSR option solely
because that base flag is clear. These reads resolved missing wire details;
implementation is independently written Rust from this contract.

### 2.6 Tail-call slot table

Internal, but `DROP_MISSED_TAIL_CALL` reports the slot in `ext_error`
(visible in Hubble), the reference complexity fixtures are indexed by it,
and the reference test checklist (§9) names tails by slot. flowsdn MUST use
this numbering in M1; renumbering is an open decision (§12.8).

| Slot | Name | Slot | Name |
|---|---|---|---|
| 1 | `DROP_NOTIFY` | 26 | `IPV4_FROM_LXC_CONT` |
| 2 | `ERROR_NOTIFY` | 27 | `IPV6_FROM_LXC_CONT` |
| 3 | (gap, reserved) | 28 | `IPV4_CT_INGRESS` |
| 4 | `HANDLE_ICMP6_NS` | 29 | `IPV4_CT_INGRESS_POLICY_ONLY` |
| 5 | `SEND_ICMP6_TIME_EXCEEDED` | 30 | `IPV4_CT_EGRESS` |
| 6 | `ARP` | 31 | `IPV6_CT_INGRESS` |
| 7 | `IPV4_FROM_LXC` (= `_FROM_NETDEV`, `_FROM_OVERLAY`, `_FROM_WIREGUARD`) | 32 | `IPV6_CT_INGRESS_POLICY_ONLY` |
| 8 | `IPV46_RFC6052` | 33 | `IPV6_CT_EGRESS` |
| 9 | `IPV64_RFC6052` | 34 | `SRV6_ENCAP` |
| 10 | `IPV6_FROM_LXC` (= v6 NETDEV/OVERLAY/WIREGUARD) | 35 | `SRV6_DECAP` |
| 11 | `IPV4_TO_LXC_POLICY_ONLY` (= `IPV4_TO_HOST_POLICY_ONLY`) | 36 | `IPV4_NODEPORT_NAT_INGRESS` |
| 12 | `IPV6_TO_LXC_POLICY_ONLY` | 37 | `IPV6_NODEPORT_NAT_INGRESS` |
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
| 25 | `IPV6_NODEPORT_NAT_FWD` | | `CILIUM_CALL_SIZE = 50` |

Per-endpoint delivery goes through two global `PROG_ARRAY`s indexed by
endpoint id: `cilium_call_policy` (ingress policy program of the endpoint;
`host_ep_id` slot holds `host_policy`) and `cilium_egresscall_policy`
(`lxc_policy_egress`). An empty slot MUST yield `DROP_EP_NOT_READY` (203),
never a fall-through.

### 2.7 Monitor event versions emitted

The datapath emits exactly these layouts on `cilium_events`
(decoders in spec 01 / Hubble spec):

| Type | Struct | Version emitted | Size (without capture) |
|---|---|---|---|
| 1 drop | `drop_notify` | 3 | 48 B |
| 2 debug | `debug_msg` | — | 20 B |
| 3 debug capture | `debug_capture_msg` | — | 24 B |
| 4 trace | `trace_notify` | 2 | 56 B |
| 5 policy verdict | `policy_verdict_notify` | — | 40 B |
| 7 trace-sock | `trace_sock_notify` | — | 40 B (M2) |

Common header `{u8 type, u8 subtype, u16 source, u32 hash}`; capture header
adds `{u32 len_orig, u16 len_cap, u8 version, u8 ext_version=0}`. `source` is
the endpoint id (`endpoint_id` in lxc, `host_ep_id` in host, 0 elsewhere).
`hash = bpf_get_hash_recalc`. Captured bytes follow the struct; the perf
flags word is `(cap_len << 32) | BPF_F_CURRENT_CPU`. `flags` bits shared by
drop and trace: `1 IPv6`, `2 L3 device`, `4 VXLAN`, `8 Geneve` (classifier).

Signals on `cilium_signals`: `SIGNAL_NAT_FILL_UP 0`, `SIGNAL_CT_FILL_UP 1`,
`SIGNAL_AUTH_REQUIRED 2` with `{u32 signal_nr, u32 data}`.

### 2.8 Drop reason numbering

The numeric table in inventory 09 (130..207, plus status codes 0..15) is the
contract with Hubble `flow.proto` and `cilium-dbg`. flowsdn MUST NOT reuse
retired values (130, 131, 138, 148, 149, 152, 159, 165, 186, 206). New drop
reasons MUST be allocated ≥ 208 and added to the Hubble spec in the same
change.

---

## 3. Behavior

Conventions in this section: "drop(X)" means emit a `drop_notify` with
subtype `X`, bump `cilium_metrics{reason=X, dir}`, return `TC_ACT_SHOT`
(or `XDP_DROP`). "pass" means `TC_ACT_OK` to the stack. Numbers in
parentheses are drop codes. "CT(dir, scope)" is a lookup as defined in §3.11.
Everything applies to IPv4 and IPv6 symmetrically unless stated; IPv6 first
walks extension headers (max 4, fragment header handled per §3.13; unknown
or malformed → `DROP_INVALID_EXTHDR` (156)).

### 3.1 Pipeline 1 — pod egress (`from_container`, veth ingress)

1. Read ethertype (L2 device; netkit L3 mode uses `eth_header_length=0`).
   Clear `cb[]`. Extract IP-option trace id if enabled (M3). Set
   `queue_mapping = 0` (veth GH-18311 workaround). Set EDT aggregate =
   `endpoint_id` (M3; MUST be a no-op when bandwidth manager is off).
2. Emit trace `FROM_LXC` (src = endpoint identity, dst unknown, reason
   unknown; subject to aggregation §3.16).
3. Unknown ethertype → drop(`UNSUPPORTED_L2` 166). ARP → tail `ARP` if
   `enable_arp_responder` (M3) else pass. Not IPv4/IPv6 → drop(`UNKNOWN_L3`
   139). Pull L3 header; failure → drop(`INVALID` 134).
4. Tail `IPV4_FROM_LXC` / `IPV6_FROM_LXC`.
5. **Source check**: if `enable_sip_verification`, `saddr` MUST equal the
   endpoint's configured address → else drop(`INVALID_SIP` 132).
6. **Per-packet service LB** (when socket LB is not "full"; always in M1):
   build `lb_key{daddr, dport, proto, scope=EXT}` from the tuple.
   `DROP_UNSUPP_SERVICE_PROTO` (159) for non TCP/UDP/SCTP/ICMP is *not* a
   drop here: skip LB. Service hit (east-west lookup):
   a. `SVC_FLAG_L7_LOADBALANCER` → record `proxy_port` in cb (M2).
   b. `lb_local`: select backend (§3.12), CT(SERVICE) create/refresh,
      hairpin detection: backend address == own endpoint address →
      `loopback=1`, SNAT source to `service_loopback_ipv4/6`.
   c. DNAT (`lb_xlate`): rewrite daddr/dport, L3/L4 csum incremental.
      Write failure → drop(`WRITE_ERROR` 141); csum failure →
      drop(`CSUM_L4` 154).
   d. No backend → if `enable_no_service_endpoints_routable` is false
      and the service is non-routable, drop(`NO_SERVICE` 158); else if
      `service_no_backend_response` tail `IPV4_NO_SERVICE` (ICMP
      unreachable back to the pod, §3.15); else pass.
   e. Store `{rev_nat_index, proxy_port, cluster_id, loopback}` in cb
      (`lb_ctx_store_state`).
7. Tail `IPV4_CT_EGRESS`: CT(EGRESS, FORWARD after LB) into the per-CPU
   `ct_buffer` (tuple, `ct_state`, monitor, status, `l4_off`, fraginfo).
   Fragment without L4 header and fragment tracking disabled →
   status is computed with zero ports and the packet is marked
   "untracked fragment" for policy. Header errors → drop(`CT_INVALID_HDR`
   135); unknown L4 for CT → drop(`CT_UNKNOWN_PROTO` 137).
8. Tail `IPV4_FROM_LXC_CONT` (inline when only one family is built):
   restore LB state from cb; buffer missing → drop(`INVALID_TC_BUFFER` 184).
9. **Destination identity**: `lookup_ip4_remote_endpoint(daddr,
   cluster_id)` (ipcache, full prefix). Miss → `WORLD_IPV4`/`WORLD_IPV6`.
   Remember `tunnel_endpoint`, `flag_skip_tunnel`, `key`.
10. **CT status switch**:
    - `NEW`, `ESTABLISHED`: if `proxy_port` from L7 LB → redirect to proxy
      first (M2). If `loopback` → skip policy. Else `policy_can_egress`
      (§3.10) with `src = endpoint identity, dst = dst identity`;
      `is_encap(dport, proto)` from a non-host identity →
      drop(`ENCAP_PROHIBITED` 170) before lookup. Verdict: deny →
      emit policy-verdict, then tail `IPV4_POLICY_DENIED` if
      `policy_deny_response_enabled` (M2) else drop(`POLICY` 133 /
      `POLICY_DENY` 181 / `POLICY_AUTH_REQUIRED` 189 with `ext_error` =
      auth type). Allow → emit policy-verdict (allow or audited), continue
      with `proxy_port` if the entry redirects.
    - `REPLY`, `RELATED`: skip policy. If the entry has `proxy_redirect`
      → redirect to proxy (M2). If `node_port` → tail `IPV4_NODEPORT_REVNAT`
      (reply to a NodePort connection that entered via this node, §3.6).
    - other → drop(`UNKNOWN_CT` 163).
11. **CT create/update**: `NEW` → `ct_create(EGRESS)` with `ct_state{
    rev_nat_index, loopback, proxy_redirect = proxy_port != 0, src_sec_id =
    endpoint identity, from_l7lb}`; also the RELATED ICMP entry in the
    `_any` map for TCP/UDP/SCTP. Failure → drop(`CT_CREATE_FAILED` 155,
    `ext_error` = errno). `ESTABLISHED` whose stored `rev_nat_index` or
    `proxy_redirect` disagree with this packet → recreate the entry.
12. **Forward** (`ipv4_forward_to_destination`), first match wins:
    a. `proxy_port != 0` → `ctx_redirect_to_proxy` (M2, §3.14), trace
       `TO_PROXY`.
    b. Local endpoint (`cilium_lxc` hit on daddr) and not routing through
       the stack:
       - endpoint has `ENDPOINT_F_HOST` (destination is the host itself)
         and (`enable_bpf_host_routing` or `enable_routing`) → pass to
         stack (host firewall hairpin in M2).
       - else `ipv4_local_delivery` (§3.9): rewrite MACs (`node_mac` →
         src, endpoint `mac` → dst), decrement TTL, and either
         `redirect_peer` into the target netns or tail
         `cilium_call_policy[dst_ep_id]` (§3.2 from step 6) with
         `CB_SRC_LABEL = src identity`, `CB_DELIVERY_FLAGS`.
    c. Multicast group (M3), SRv6 (M3), egress gateway hook (M3), VTEP (M3).
    d. `tunnel_mode` and destination has a tunnel endpoint and
       `!flag_skip_tunnel` and destination is not a remote node identity
       when native routing to nodes is preferred → **encap** (§3.3) to
       `tunnel_endpoint` with VNI = src identity, trace `TO_OVERLAY`,
       `redirect(encap_ifindex)`.
    e. IPsec / WireGuard (M3): set `MARK_MAGIC_ENCRYPT` /
       `MARK_MAGIC_IDENTITY`, pass to stack (redirect happens in
       `to_netdev`).
    f. `enable_bpf_host_routing` → `fib_redirect_v4` (§3.8) out of the
       native device (`BPF_FIB_LOOKUP_TBID` with endpoint `rt_info` when
       set, M3). `DROP_NO_FIB` (169) on lookup failure.
    g. Otherwise set `MARK_MAGIC_IDENTITY|identity` if `enable_identity_mark`,
       trace `TO_STACK`, pass.
13. Any drop from step 5 onward → `drop_notify` with `src = endpoint
    identity`, `dst = dst identity` (when known), `dst_id = 0`,
    `direction = EGRESS`.

### 3.2 Pipeline 2 — delivery into a pod (`to_container`, or `lxc_policy` via `cilium_call_policy`)

Entered either at the veth egress hook (`to_container`; packets from the
stack, from `cilium_host`, or via `redirect`) or as a tail call from the
host/overlay/wireguard object (`lxc_policy`), which skips steps 1–5.

1. Ethertype check → drop(`UNSUPPORTED_L2` 166). Clear cb. Trace id (M3).
2. If mark magic is `PROXY_EGRESS_EPID` (M2): `ep_id = mark >> 16`, clear
   mark, tail `cilium_egresscall_policy[ep_id]`; empty → drop(`EP_NOT_READY`
   203).
3. **Identity from mark** (`inherit_identity_from_host`): magic
   `PROXY_INGRESS` → identity from mark, set `tc_index |=
   FROM_INGRESS_PROXY`; `PROXY_EGRESS` → identity, `FROM_EGRESS_PROXY`;
   `IDENTITY` → identity; `HOST` → `HOST (1)`; anything else →
   `WORLD_IPV4`/`WORLD_IPV6` by ethertype (or `WORLD` if single-family).
   Then **mark := 0**. Trace `FROM_STACK` (or `FROM_PROXY` if a proxy
   magic was seen) with `src = identity, dst = endpoint identity, dst_id =
   endpoint_id`.
4. Host firewall hairpin (M2): identity `HOST` and endpoint routes → tail
   `cilium_call_policy[host_ep_id]` with `CB_FROM_HOST=1`,
   `CB_DST_ENDPOINT_ID`; empty → drop(`HOST_NOT_READY` 202).
5. Pull L3; ARP → pass; other → drop(`UNKNOWN_L3` 139). Store
   `CB_SRC_LABEL = identity`. Tail `IPV4_CT_INGRESS` (from `to_container`)
   or `IPV4_CT_INGRESS_POLICY_ONLY` (from `lxc_policy`).
6. CT(INGRESS, BIDIR) into `ct_buffer`. Tail `IPV4_TO_ENDPOINT` /
   `IPV4_TO_LXC_POLICY_ONLY` → `ipv4_policy`:
7. Read `CB_SRC_LABEL`, `CB_DELIVERY_FLAGS`, `CB_CLUSTER_ID_INGRESS`.
   Untracked fragment handling as in §3.13.
8. **CT status switch**:
   - `REPLY`/`RELATED`: if `ct_state.rev_nat_index != 0` or `nat_port != 0`
     → `lb_rev_nat` (undo hairpin/loopback SNAT: restore saddr:sport from
     `cilium_lb4_reverse_nat[rev_nat_index]` or from the stored
     `nat_addr:nat_port`, fix csums; `loopback` restores daddr too). If
     `proxy_redirect` → redirect to egress proxy (M2). Skip policy.
   - `NEW`: loopback detection — `saddr == service_loopback_ipv4` and the
     egress map holds a loopback entry for the flipped tuple → treat as
     hairpin, skip policy, `loopback=1`. Otherwise if the packet came from
     the ingress proxy (`tc_index` flag) skip policy (already enforced);
     else `policy_can_ingress` (§3.10) with `src = CB_SRC_LABEL, dst =
     endpoint identity`. Deny → verdict event + drop (133/181/189) or tail
     `IPV4_POLICY_DENIED` (M2). Allow → verdict event; `proxy_port`
     from the entry.
     Then `ct_create(INGRESS)` with `ct_state{src_sec_id = src identity,
     from_tunnel = CB_DELIVERY_FLAGS.FROM_TUNNEL, proxy_redirect =
     proxy_port != 0, loopback, rev_nat_index}` (+ RELATED entry).
   - `ESTABLISHED`: skip policy unless the stored `proxy_redirect`
     disagrees with a non-zero `proxy_port` recomputed from a policy
     lookup (M2: re-evaluate and recreate). Refresh happens in the lookup.
   - other → drop(`UNKNOWN_CT` 163).
9. `proxy_port != 0` → `ctx_redirect_to_proxy` (M2), trace `TO_PROXY`.
10. Otherwise trace `TO_LXC` (src identity, dst endpoint identity,
    `dst_id = endpoint_id`, reason = CT status, ifindex = `ingress_ifindex`).
    When entered from the host object (`CB_DELIVERY_FLAGS.REDIRECT`):
    `redirect_peer(endpoint ifindex)` if `USE_REDIRECT_PEER`, else
    `redirect(ifindex)`; from tunnel, set `pkt_type = PACKET_HOST` first.
    When entered at `to_container`: pass (the veth delivers).
11. Drops: `src = identity from mark/cb`, `dst = endpoint identity`,
    `dst_id = endpoint_id`, `direction = INGRESS`.

### 3.3 Pipeline 3 — overlay egress (`to_overlay`, tunnel device egress)

Encapsulation itself is done by the sender (pipeline 1 step 12d, pipeline 5,
NodePort SNAT egress): `bpf_skb_set_tunnel_key{tunnel_id = identity_on_wire,
remote_ipv4/6 = tunnel_endpoint, tunnel_ttl = 64}` with size
`TUNNEL_KEY_WITHOUT_SRC_IP`, optional Geneve TLV via
`bpf_skb_set_tunnel_opt` (M2 DSR), then `redirect(encap_ifindex, 0)`.
`identity_on_wire`: `HOST → LOCAL_NODE`, `WORLD_IPV4/6 → WORLD`. Missing
tunnel endpoint → drop(`NO_TUNNEL_ENDPOINT` 160).

`to_overlay`:
1. Clear cb. EDT departure (M3; on `DROP_EDT_HORIZON` 162 bump metrics and
   drop *without* a drop notification, rate-limiting is not an error).
2. `cluster_id` from `MARK_MAGIC_CLUSTER_ID` mark (M3).
3. `bpf_skb_get_tunnel_key` → identity = `get_id_from_tunnel_id(tunnel_id,
   proto)`. Set `MARK_MAGIC_OVERLAY | identity` on the skb (the physical
   device egress program uses it to know the packet is our tunnel traffic).
4. If NodePort is enabled and `MARK_MAGIC_SNAT_DONE` is not set →
   `handle_nat_fwd` (§3.7): rev-DNAT for replies, SNAT forward for
   NodePort/masquerade/inter-cluster. Errors → drop with
   `direction = EGRESS`, `src = identity`.
5. Pass to the tunnel driver.

### 3.4 Pipeline 4 — overlay ingress (`from_overlay`, tunnel device ingress)

1. Clear cb; clear `tc_index.SKIP_NODEPORT`; trace id (M3). Unknown
   ethertype → pass (driver noise). Pull L3 → drop(`INVALID` 134).
2. WireGuard strict ingress (M3): if `encryption_strict_ingress` and the
   packet lacks `MARK_MAGIC_DECRYPT` → drop(`UNENCRYPTED_TRAFFIC` 195); clear
   the magic bits afterwards.
3. `bpf_skb_get_tunnel_key` (try IPv4 key then `BPF_F_TUNINFO_IPV6`) →
   failure drop(`NO_TUNNEL_KEY` 147). `identity = get_id_from_tunnel_id`.
   Identity `HOST` → drop(`INVALID_IDENTITY` 171). Store `CB_SRC_LABEL`.
4. Trace `FROM_OVERLAY` (src identity, dst unknown, `ifindex =
   ingress_ifindex`). ARP with VTEP (M3) → tail `ARP`. Tail
   `IPV4_FROM_OVERLAY` / `IPV6_FROM_OVERLAY`.
5. Fragment info (§3.13). Multicast (M3). **NodePort from overlay**: if
   NodePort enabled and `tc_index.SKIP_NODEPORT` not set → `nodeport_lb4`
   (§3.6) with `src_sec_identity = CB_SRC_LABEL`; it may tail out (NAT
   egress, DSR, rev-NAT) or return with `XFER_PKT_NO_SVC` semantics
   meaning "not a service packet, continue".
6. VTEP source validation (M3; `DROP_INVALID_VNI` 183). Inter-cluster
   rev-SNAT tail (M3).
7. If identity is `REMOTE_NODE` or DSR-marked, refresh the identity from
   the ipcache for `saddr` (a remote node may have encapsulated with the
   node identity; the ipcache is authoritative for the pod).
8. Egress gateway reply redirect (M3, `MARK_MAGIC_EGW_DONE`).
9. `cilium_lxc` lookup on daddr:
   - local endpoint → `ipv4_local_delivery` with `from_tunnel = true`,
     `magic = MARK_MAGIC_IDENTITY`, `direction = INGRESS`, `cluster_id`;
     the endpoint's `lxc_policy` runs via `cilium_call_policy` (§3.2 step 6).
   - endpoint flagged host (`ENDPOINT_F_HOST`) → `ipv4_host_delivery`:
     rewrite MACs (`interface_mac` → src, `cilium_host_mac` → dst),
     decrement TTL, `redirect(cilium_host_ifindex, BPF_F_INGRESS)`.
   - no endpoint: if `enable_routing`-style native forwarding is off →
     set `MARK_MAGIC_IDENTITY|identity`, `ipv4_host_delivery`; else
     drop(`UNROUTABLE` 151).
10. Drops carry `src = identity`, `direction = INGRESS`.

### 3.5 Pipeline 5 — native device (`from_netdev` ingress, `to_netdev` egress)

**Ingress (`from_netdev`)**:
1. Clear cb; trace id (M3). VLAN filter: if the packet carries a VLAN tag
   not permitted for `(ifindex, vlan_id)` → drop(`VLAN_FILTERED` 182).
   Read `XFER_PKT_*` from XDP metadata (M2) into `tc_index.SKIP_NODEPORT` /
   snat-done state.
2. Ethertype: L3 devices (`eth_header_length = 0`) derive it from
   `skb->protocol`. Unknown → pass. ARP/NDP for L2 announcements (M3).
3. IPsec ESP with our marks (M3): `do_decrypt` → set `MARK_MAGIC_DECRYPT |
   node_id << 16`, redirect to `cilium_host` ingress; pass otherwise.
4. Trace `FROM_NETWORK` (src unknown → identity if a mark says so).
5. Tail `IPV4_FROM_NETDEV` (`handle_ipv4`):
   a. WireGuard strict (M3). Identity of the source: `lookup
      ip4_remote_endpoint(saddr)`; miss → `WORLD_IPV4`; a source that
      resolves to a *local* identity scope is treated as WORLD (spoof
      protection); `HOST`/`REMOTE_NODE` are permitted.
   b. If NodePort enabled and not `SKIP_NODEPORT` → `nodeport_lb4` (§3.6).
      It returns "continue" for non-service, non-reply traffic.
   c. Host firewall ingress lookup (M2) → cb.
   d. Tail `IPV4_CONT_FROM_NETDEV` (`handle_ipv4_cont`).
6. `handle_ipv4_cont`: host firewall verdict (M2). `cilium_lxc` lookup on
   daddr:
   - local endpoint and `enable_bpf_host_routing` → `ipv4_local_delivery`
     (`from_host=false`, `from_tunnel=false`, `magic = MARK_MAGIC_IDENTITY`,
     `direction = INGRESS`); the endpoint's ingress policy runs via
     `cilium_call_policy`.
   - local endpoint and legacy routing → set identity mark, pass to stack.
   - VTEP (M3). Hybrid routing: destination in a tunnel subnet → encap
     (M3, `hybrid_routing_enabled`).
   - unknown destination with `enable_routing` off → drop(`UNROUTABLE` 151)
     only when the packet is addressed into the pod CIDR; else pass.
7. Drops: `src = derived identity`, `direction = INGRESS`.

**Egress (`to_netdev`)**:
1. Clear cb (but preserve mark). Derive `src_sec_identity` from the mark:
   `HOST`, `OVERLAY`, `ENCRYPT` → `HOST`; `PROXY_EGRESS`, `IDENTITY`,
   `EGW_DONE` → identity from mark; none → `HOST` if the packet is from the
   host stack (no ingress ifindex), else unknown.
2. L7 LB EPID hairpin (M2). Host firewall egress policy (M2; skipped when
   `MARK_MAGIC_SNAT_DONE`).
3. Egress gateway redirect (M3). EDT (M3). IPsec redirect to `cilium_net`
   ingress for XFRM (M3). WireGuard redirect to `cilium_wg0` (M3). Strict
   mode drop (M3, 195). Health-check bypass (`SKIP_HEALTH_CHECK`).
4. If NodePort enabled and not `SNAT_DONE` → `handle_nat_fwd` (§3.7):
   rev-DNAT (reply to a NodePort/loopback connection leaving this node),
   then tail `IPV4_NODEPORT_SNAT_FWD`: NodePort SNAT to remote backend or
   masquerade (§3.7). `NAT_PUNT_TO_STACK` is *not* a drop.
5. Trace `TO_NETWORK` (src identity, dst unknown). Pass.
6. Drops: `direction = EGRESS`, `src = src_sec_identity`.

### 3.6 Pipeline 7 — NodePort / external service from outside (`nodeport_lb4`)

Called from `from_netdev`, `from_overlay`, XDP (M2), `from_wireguard` (M3).

1. Extract tuple (`lb_extract_tuple`): unsupported service protocol → mark
   `is_svc_proto = false` and skip to step 6 (rev-NAT still applies to
   ICMP errors under masquerade); unknown L4 → set `XFER_PKT_NO_SVC`,
   return continue.
2. `lb_lookup_service(key, east_west = false)`: exact `{addr, dport, proto,
   scope}` then protocol-wildcard (`proto = 0`) entry. **Wildcard hit with
   no protocol entry → drop(`NO_SERVICE` 158)** (prevents loops).
3. Service hit (`nodeport_svc_lb4`):
   a. Source-range check → drop(`NOT_IN_SRC_RANGE` 177) (inverted when
      `SVC_FLAG_SOURCE_RANGE_DENY`).
   b. ClusterIP-only service reached from outside → drop(`IS_CLUSTER_IP`
      174) unless `disable_external_ip_mitigation`.
   c. externalTrafficPolicy=Local from XDP → return to tc (M2).
   d. L7 LB service (M2): trace `TO_PROXY`, set `MARK_MAGIC_TO_PROXY |
      proxy_port << 16`; if `enable_tproxy` or `proxy_redirect_via_cilium_net`
      hairpin via `cilium_net`, else pass to stack.
   e. NAT46 service (M3).
   f. `lb_local` (backend selection §3.12, CT(SERVICE) create/refresh).
      No backend → `handle_nonroutable_endpoints` (drop `NO_SERVICE` 158
      unless `enable_no_service_endpoints_routable`) or, with
      `service_no_backend_response`, tail `IPV4_NO_SERVICE` (ICMP
      unreachable to the client, EDT aggregate 0).
   g. `backend_local = cilium_lxc hit on backend address`. HostPort with
      a non-local backend → drop(`INVALID` 134). L7 punt (M2).
   h. DNAT to backend unless `nodeport_skip_xlate` (DSR to remote backend
      keeps the service address on the wire, M2).
   i. If `backend_local || !dsr`: `src_sec_identity := WORLD_IPV4` (inter-
      cluster variant M3: keep the identity; reject local-scope or HOST
      identities with `INVALID_IDENTITY` 171). Reverse the tuple to
      FORWARD layout, `ct_lazy_lookup(EGRESS, FORWARD, CT_ENTRY_NODEPORT,
      rev_nat_index filter)`: `NEW` → `ct_create(EGRESS)` with
      `ct_state{node_port = 1, src_sec_id, rev_nat_index}`;
      `ESTABLISHED` → nothing; else drop(`UNKNOWN_CT` 163).
      `backend_local` → set `XFER_PKT_NO_SVC`, return continue (the packet
      proceeds to local delivery as an ordinary packet whose destination
      is the pod). Otherwise record the neighbour (`neigh_record_ip4`,
      source MAC → `cilium_nodeport_neigh4[saddr]`) for the reply path.
   j. Remote backend: EDT aggregate 0. DSR (M2) → store client addr/port
      in cb, tail `IPV4_NODEPORT_DSR`. Else store `CB_SRC_LABEL`,
      `CB_CLUSTER_ID_EGRESS`, tail `IPV4_NODEPORT_NAT_EGRESS`.
4. `IPV4_NODEPORT_NAT_EGRESS`: target `{addr = IPV4_DIRECT_ROUTING (or the
   tunnel endpoint source), min_port = nodeport_port_max+1, max_port =
   65535, needs_ct = false}`; `snat_v4_nat` (§3.7 step 3). Then if the
   backend node is reached over the tunnel (ipcache `tunnel_endpoint` and
   tunnel mode) → encap with VNI `WORLD` (the remote node sees WORLD as
   source) and `redirect(encap_ifindex)`; else set `MARK_MAGIC_SNAT_DONE`,
   `fib_redirect` (§3.8) to the backend node. Set `XFER_PKT_SNAT_DONE`.
5. **Replies from a remote backend** arrive at step 6 because the
   destination (our node IP : allocated port) is not a service.
6. Not a service: set `XFER_PKT_NO_SVC`. DSR info extraction (M2). NAT64
   reply detection (M3). Store `CB_SRC_LABEL`. If masquerade is enabled or
   `is_svc_proto` → tail `IPV4_NODEPORT_NAT_INGRESS`:
   `snat_v4_rev_nat` (lookup `cilium_snat_v4_external` with the ingress
   tuple; hit → rewrite daddr:dport back to the client/original, fix
   csums; ICMP errors translate the inner header §3.7). Then
   `nodeport_rev_dnat_get_info`/tail `IPV4_NODEPORT_REVNAT`: CT(INGRESS)
   lookup for a `node_port` entry → `lb_rev_nat` (restore the service
   address:port as source), `fib_redirect` toward the client using the
   recorded neighbour when the FIB has no neighbour. No NAT entry → the
   packet is not ours: continue to normal delivery.
7. `nodeport_rev_dnat_ipv4` failure modes: `DROP_NAT_NO_MAPPING` (167) is
   returned only when a mapping was expected (service protocol and a CT
   entry says node_port) — otherwise continue.

### 3.7 SNAT / masquerade decisions (`handle_nat_fwd`, `snat_v4_*`)

Executed on `to_netdev`, `to_overlay`, `to_wireguard` (M3) egress when
NodePort is enabled and `MARK_MAGIC_SNAT_DONE` is absent.

1. `nodeport_rev_dnat_fwd`: CT(INGRESS-side, reverse) lookup on the egress
   tuple; if it is a reply of a NodePort/loopback/L7-LB connection with
   `rev_nat_index` → `lb_rev_nat`, set `snat_done`. With
   `CB_NAT_FLAGS_REVDNAT_ONLY` stop here.
2. If not `snat_done`: store `CB_CLUSTER_ID_EGRESS`, `CB_SRC_LABEL`, tail
   `IPV4_NODEPORT_SNAT_FWD` → `snat_v4_needs_masquerade` decides, in this
   order, the first rule that applies:

   | # | Condition | Result |
   |---|---|---|
   | 1 | `saddr == nat_ipv4_masquerade` (host-originated with the masq address) | NAT with `needs_ct = true` (reserve or rewrite the port so it cannot alias a masqueraded flow) |
   | 2 | `saddr` is a local endpoint (`cilium_lxc`) and the CT map says the packet is a **reply** to an inbound connection (`ct_is_reply4`) | punt to stack (no NAT) |
   | 3 | egress gateway policy matches (M3) | NAT to egress IP (or `DROP_NO_EGRESS_IP` 204) |
   | 4 | `daddr` in `ipv4_snat_exclusion_dst_cidr` (native-routing CIDR or pod CIDR) | punt |
   | 5 | local endpoint has `ENDPOINT_F_NO_SNAT_V4` | punt |
   | 6 | `daddr` matches an ip-masq-agent LPM entry (`cilium_ipmasq_v4`) | punt |
   | 7 | `daddr` resolves in ipcache to a remote-node identity: if `enable_remote_node_masquerade` → NAT; else if native routing → punt; else (tunnel mode) if the remote node entry has `flag_skip_tunnel` → punt | as stated |
   | 8 | `saddr` is a local endpoint | NAT to `nat_ipv4_masquerade` |
   | 9 | otherwise | punt |

   `NAT_PUNT_TO_STACK` is encoded as `DROP_NAT_NOT_NEEDED` (173) internally
   and MUST NOT produce a drop notification.
3. `snat_v4_nat`: mapping lookup on the egress tuple in
   `cilium_snat_v4_external`. Hit whose `to_saddr` equals the target and
   whose `needs_ct` matches → reuse; ensure the reverse entry exists
   (recreate it if LRU evicted it). Stale hit → delete both directions and
   allocate anew. Miss → **allocate** (§5.3): pick a port in
   `[min_port, max_port]` (`nodeport_port_max+1 .. 65535`, or
   `ephemeral_min..65535` without NodePort); try to insert the reverse
   entry `{to_daddr = original saddr, to_dport = original sport}` with
   `BPF_NOEXIST`; on collision retry up to `SNAT_COLLISION_RETRIES = 32`
   with `port+1` clamped into range; record the retry count in
   `cilium_snat_v4_alloc_retries`; ≥ 16 retries → signal
   `SIGNAL_NAT_FILL_UP`; exhaustion → drop(`NAT_NO_MAPPING` 167). Then
   insert the forward entry. `needs_ct` → also `ct_create(EGRESS)` for the
   flow. Rewrite saddr:sport (ICMP: the identifier), fix csums
   (`CSUM_L3` 153 / `CSUM_L4` 154 on failure). Unsupported L4 →
   drop(`NAT_UNSUPP_PROTO` 168). Fragments without L4 header when fragment
   tracking is off → drop(`FRAG_NOSUPPORT` 157).
4. ICMP errors (Dest Unreachable, Time Exceeded, Parameter Problem) are
   translated using the *inner* header's tuple in both directions
   (`ENABLE_SNAT_ICMPV4` — always on in flowsdn); unknown codes →
   drop(`UNKNOWN_ICMP4_CODE` 143) only when the error cannot be matched.
5. On success set `MARK_MAGIC_SNAT_DONE` (host object) so `to_overlay`
   does not repeat the work.

### 3.8 Host routing (`fib_redirect`)

flowsdn uses **BPF host routing** as the primary forwarding mechanism
(`enable_bpf_host_routing = true`); see §12.4 for the legacy path.

1. `bpf_fib_lookup(family, ifindex = ingress dev, src, dst[, tbid])` with
   `BPF_FIB_LOOKUP_SKIP_NEIGH` when `supports_fib_lookup_skip_neigh` (the
   neighbour is resolved by `redirect_neigh`); `BPF_FIB_LOOKUP_DIRECT |
   BPF_FIB_LOOKUP_TBID` when a table id is given (M3 egress gateway / ENI).
2. Result `SUCCESS` or `NO_NEIGH` → continue; anything else →
   drop(`NO_FIB` 169).
3. Decrement TTL / hop limit with incremental csum (`TTL_EXCEEDED` 196 →
   drop in M1; ICMP time-exceeded generation is a later M2 obligation).
4. L3 output device (`cilium_devices[oif].l3` or this program on an L3
   device): push a 14-byte Ethernet header (`skb_change_head`) with the
   ethertype; failure → drop(`INVALID` 134 / `WRITE_ERROR` 141).
5. Redirect: if `bpf_redirect_neigh` is available → `redirect_neigh(oif,
   {family, nexthop from fib})`. Else if the FIB returned `SUCCESS` write
   `dmac/smac` from the FIB result and `redirect(oif)`. Else (`NO_NEIGH`)
   use the learned `cilium_nodeport_neigh4[dst]` MAC if allowed
   (`allow_neigh_map`, NodePort reply path) and `cilium_devices[oif].mac`
   as source; none → drop(`NO_FIB` 169).
6. Overlay object never uses `redirect_neigh` without an explicit nexthop.

`redirect_peer(ifindex)` is used for host→pod delivery when
`should_redirect_peer`: BPF host routing on, not from the host stack, and
(veth, or netkit with a real ingress ifindex). With endpoint routes and no
`redirect_peer`, delivery sets the identity mark and `redirect(ifindex)` to
the veth egress where `to_container` runs.

### 3.9 Local delivery (`ipv4_local_delivery`)

MAC ABI clarification (2026-09-09): the endpoint `mac` and `node_mac` u64
values store the six Ethernet bytes in their low six little-endian bytes.
This resolves the map-layout spec's previously uninterpreted u64 fields for
packet rewriting. Evidence: pinned reference `pkg/mac/mac.go:71–85` and
`pkg/mac/mac_test.go:62–66`. No reference implementation was copied.

Inputs: L3 offset, source identity, `magic` to use if a mark must be set,
destination `endpoint_info`, metric direction, `from_host`, `from_tunnel`,
`cluster_id`.

1. `ipv4_l3`: TTL decrement + csum; write `smac = ep.node_mac`, `dmac =
   ep.mac` (skipped for L3 devices). Failure → 141/134.
2. Metrics `REASON_FORWARDED` for the direction when
   `local_delivery_metrics` (per-endpoint option).
3. Ingress from the network (not `from_host`): rate-limit accept hook
   (token bucket per endpoint, `DROP_RATE_LIMITED` 198 when configured).
4. `use_redirect_peer = should_redirect_peer(from_host)`. If endpoint
   routes are enabled and not using `redirect_peer` (and netkit conditions):
   set identity mark (`magic | identity`), and `redirect(ep.ifindex)`
   (from tunnel without NodePort: `pkt_type = HOST`, pass).
5. Otherwise fill `CB_SRC_LABEL = identity`, `CB_DELIVERY_FLAGS{REDIRECT,
   USE_REDIRECT_PEER?, FROM_HOST?, FROM_TUNNEL?, FROM_INGRESS_PROXY?,
   FROM_EGRESS_PROXY?}`, `CB_CLUSTER_ID_INGRESS`, and tail
   `cilium_call_policy[ep.lxc_id]` → §3.2 step 6. Empty slot →
   drop(`EP_NOT_READY` 203).

### 3.10 Policy verdict computation (datapath side)

Map: the endpoint's `cilium_policy_v3_<epid>` LPM trie (spec 01). Key
(12 B) `{prefixlen u32, sec_label u32, egress:1 u8, protocol u8, dport
be16}`; value `{proxy_port be16, deny:1 reserved:2 lpm_prefix_length:5,
auth_type:7 has_explicit_auth_type:1, precedence u32, cookie u32}`. The LPM
prefix covers, in order, `sec_label` (32 bits), the direction byte (8),
`protocol` (8), `dport` (16). Lookups always use the full prefix (64 bits);
entries wildcard from the right: protocol may be wildcarded only when the
whole port is wildcarded, the port may be partially wildcarded
(CIDR-like) only with a fully specified protocol.

Inputs: `local_id` (the endpoint), `remote_id`, ethertype, `dport`,
`proto`, L4 offset, direction (`INGRESS` → key.egress=0; `EGRESS` → 1),
`is_untracked_fragment`.

```
key = {FULL_PREFIX, remote_id, egress, proto, dport}
if allow_icmp_frag_needed || enable_icmp_rule:
    if v4 && proto == ICMP:
        hdr = load icmphdr            # fail → DROP_INVALID
        if allow_icmp_frag_needed && type == DEST_UNREACH && code == FRAG_NEEDED:
            return ALLOW(proxy_port = 0)          # PMTU must always pass
        if enable_icmp_rule: key.dport = htons(type)   # type in high byte
    if v6 && proto == ICMPV6 && enable_icmp_rule: key.dport = htons(type)

specific  = lookup(key)                           # exact identity, LPM on L4
if specific && specific.precedence == MAX_PRECEDENCE (0xFFFFFFFF):
    chosen, other = specific, none                # deny with top precedence: no 2nd lookup
else:
    key.sec_label = aggregate_for_identity(remote_id)   # spec 03: 11/12/13/14 or self
    agg = lookup(key) if key.sec_label != remote_id else none
    if !agg && !specific && key.sec_label != 0:
        key.sec_label = 0; agg = lookup(key)      # legacy full wildcard
    if agg && (!specific
               || agg.precedence > specific.precedence
               || (agg.precedence == specific.precedence
                   && agg.lpm_prefix_length > specific.lpm_prefix_length)):
        chosen, other = agg, specific
    elif specific:
        chosen, other = specific, agg
    else:
        return DROP_FRAG_NOSUPPORT if is_untracked_fragment else DROP_POLICY (133)

account(chosen) if enable_policy_accounting        # cilium_policystats, key masked to chosen prefix
match_type = classify(chosen is specific?, chosen.lpm_prefix_length):
    specific: >8 bits → L3_L4 (2); >0 → L3_PROTO (5); 0 → L3_ONLY (1)
    aggregate: 0 → ALL (4); ≤8 → PROTO_ONLY (6); else L4_ONLY (3)
cookie = chosen.cookie
if chosen.deny: return DROP_POLICY_DENY (181)
proxy_port = chosen.proxy_port
auth = chosen.auth_type
if other && other.precedence == chosen.precedence
        && !chosen.has_explicit_auth_type && other.auth_type > auth:
    auth = other.auth_type                        # inherit from equally-ranked broader entry
if auth != 0:
    if !auth_lookup(local_id, remote_id, remote_node_id, auth) (M2):
        ext_err = auth; signal AUTH_REQUIRED; return DROP_POLICY_AUTH_REQUIRED (189)
return ALLOW(proxy_port)
```

Audit mode (`policy_audit_mode`, per endpoint or global): any drop verdict
from this function becomes `ALLOW(proxy_port = 0)` with `audited = 1`; the
packet is forwarded and the verdict event says so. Egress additionally
rejects `is_encap(dport, proto)` (UDP to `tunnel_port`) from non-host
identities with `DROP_ENCAP_PROHIBITED` (170) before the lookup.

Verdict event (`policy_verdict_notify`, when `policy_verdict_notify` is on
and the `policy_verdict_log_filter` bitmask admits the direction/verdict):
`remote_label = remote_id`, `verdict = -drop_reason | 0 | proxy_port`,
`dst_port`, `proto`, flags `{dir (1 ingress, 2 egress), ipv6, match_type,
audited, l3_dev}`, `auth_type`, `cookie`. Emitted for `NEW` connections
only (established flows do not re-verdict).

Precedence semantics (userspace computes them, spec for policy owns the
encoding): higher `precedence` wins; equal precedence → longer L4 prefix;
equal both → the specific-identity entry (an allow), because a deny and an
allow can never share a precedence value (deny verdict byte 255 vs allow 1).

### 3.11 CT interaction (datapath's use of spec 04)

- **Tuple**: `{daddr, saddr, dport, sport, nexthdr, flags}`. Extraction
  fills `daddr`/`saddr` straight from the IP header and `dport`/`sport`
  from L4 (ICMP echo: the identifier goes into `dport` for requests and
  `sport` for replies; ICMP errors set `TUPLE_F_RELATED` and zero ports;
  non-TCP/UDP/SCTP → `DROP_CT_UNKNOWN_PROTO`). Before a map operation the
  tuple is brought into the layout the scope requires by swapping the
  address pair (`ct_tuple_reverse`) and/or the port pair, so that a stored
  entry's address fields are named for the *reply* direction and its ports
  for the *original* direction; `flags` selects the direction:
  `TUPLE_F_OUT 0` (egress forward), `TUPLE_F_IN 1` (ingress forward),
  `TUPLE_F_RELATED 2`, `TUPLE_F_SERVICE 4`. Two implementations of this
  spec MUST produce byte-identical keys; spec 04 holds the worked example
  (A:a → B:b in both directions) and the test vectors.
- **Scopes**: `FORWARD` (one lookup, flags = OUT for EGRESS / IN for
  INGRESS; SERVICE always `TUPLE_F_SERVICE`), `REVERSE` (one lookup with
  the opposite flag), `BIDIR` (reverse first, then forward). Reverse hit
  → `REPLY`, or `RELATED` if the tuple carries `TUPLE_F_RELATED`
  (ICMP error whose inner header matched). REPLY/RELATED take precedence
  over ESTABLISHED because policy is skipped for them.
- **Who creates**: pipeline 1 creates EGRESS entries; pipeline 2 creates
  INGRESS entries; the LB creates SERVICE entries; NodePort from outside
  creates an EGRESS entry with `node_port = 1` on the LB node; SNAT with
  `needs_ct` creates EGRESS entries for host flows. The `_any` map gets a
  RELATED ICMP twin `{daddr, saddr, ICMP, 0, 0, flags|RELATED}` for every
  TCP/UDP/SCTP entry so ICMP errors are classified `RELATED`.
- **TCP flags**: SYN → `ACTION_CREATE` (a SYN against a closing entry
  resets closing/seen flags and returns `NEW` so the caller recreates);
  RST or FIN → `ACTION_CLOSE` (RST before both SYNs seen closes both
  directions; FIN closes the packet's direction; SERVICE closes both);
  else `ACTION_UNSPEC`. Lifetime refresh, `seen_non_syn`, report-interval
  monitor feedback, accounting (`enable_conntrack_accounting`) as in
  spec 04.
- **Entry type filter**: NodePort lookups pass `CT_ENTRY_NODEPORT` (+ a
  `rev_nat_index` filter) so an unrelated entry for the same tuple does
  not match; DSR uses `CT_ENTRY_DSR`; policy paths use `CT_ENTRY_ANY`.
- **Lazy lookups** (`ct_lazy_lookup`) are used where creation is
  conditional (NAT, NodePort) to avoid creating state for non-SYN
  packets of unknown flows.

### 3.12 Service backend selection (datapath side; LB spec owns the tables)

`lb_local(svc, key, tuple)`: CT(SERVICE, FORWARD) lookup keyed by
`{daddr = service, dport, proto, TUPLE_F_SERVICE}`. `ESTABLISHED` with a
`backend_id` whose backend still exists and is active (or terminating under
the service fallback rules) → reuse. **Resolved (#88, ADR-0011):** flowsdn
MUST NOT depend on the aliased service-slot `SVC_FLAG_QUARANTINED` bit 14:
writers leave it zero. Quarantine eligibility comes from the backend state
and active/quarantined slot ranges in spec 05 §3.4 and §4. Otherwise select: session
affinity (`cilium_lb4_affinity[{client_ip, rev_nat_id}]` if within
`affinity_timeout & 0xFFFFFF` seconds and `cilium_lb_affinity_match`
confirms membership) → else algorithm per `lb_selection_per_service ?
affinity_timeout >> 24 : lb_default_alg`: `RANDOM 1` = slot
`(get_prandom_u32() % count) + 1` → `cilium_lb4_services_v2[{key,
backend_slot}]` → backend id; `MAGLEV 2` (M2) = `cilium_lb4_maglev
[rev_nat_index][jhash(tuple, hash_init4_seed) % LUT_SIZE]` with sport
zeroed when affinity is on; `FIRST 3` = slot 1. `count == 0` →
`DROP_NO_SERVICE`. Backend lookup miss → `DROP_NO_SERVICE`; quarantined
backend/slot-range membership → re-select once. New selection → `ct_create(SERVICE)` /
`ct_update_svc_entry` with `backend_id`, `rev_nat_index`; write affinity.
Two-scope services (`SVC_FLAG_TWO_SCOPES`): `east_west` callers use scope
INT, NodePort callers scope EXT.

### 3.13 Fragments

`fraginfo` (64-bit): bits 0..31 fragment id (network order, 16 bits for
IPv4), bits 32..39 protocol, bit 40 `FRAGMENTED`, bit 41 `NO_L4_HEADER`.
IPv4: fragmented if `frag_off & 0x3fff`, no L4 header if `frag_off &
0x1fff`; IPv6 from the Fragment extension header (`& 0xfff9`, `& 0xfff8`).

When `enable_ipv4_fragments` (resp. v6): a fragment **with** L4 header
inserts `{daddr, saddr, id, proto} → {sport, dport}` into
`cilium_ipv4_frag_datagrams` (update failure only bumps
`REASON_FRAG_PACKET_UPDATE`); a fragment **without** L4 header looks the
ports up; miss → drop(`FRAG_NOT_FOUND` 175, or `FRAG_NOT_FOUND_WORLD` 207
when the source identity is WORLD). When fragment tracking is off, a
fragment without L4 header has zero ports in the tuple and is an
"untracked fragment": policy can match only fully port-wildcarded entries
(else `FRAG_NOSUPPORT` 157); NAT drops it (157).

### 3.14 Proxy redirect (M2, reserved contract)

`ctx_redirect_to_proxy(tuple, proxy_port, from_host)`: with
`enable_tproxy` and not from host: `mark |= MARK_MAGIC_TO_PROXY`; look up
the listening socket (`bpf_skc_lookup_tcp` / `bpf_sk_lookup_udp` on
`127.0.0.1:proxy_port` / `::1`), `bpf_sk_assign`, release; failures →
`PROXY_LOOKUP_FAILED` 178 / `PROXY_SET_FAILED` 179; non TCP/UDP →
`PROXY_UNKNOWN_PROTO` 180. Without TPROXY assist: `mark =
MARK_MAGIC_TO_PROXY | proxy_port << 16`, `pkt_type = HOST`, pass to the
stack where the nftables `tproxy` rule (ADR-0003) delivers it.

### 3.15 No-backend and policy-deny responses

`IPV4_NO_SERVICE` (M1): build an ICMPv4 Destination Unreachable / Port
Unreachable (ICMPv6 type 1 code 4) addressed to the original source with
the original IP header + 8 bytes of L4 as payload, swap MACs, `redirect`
back out of the ingress interface (`BPF_F_INGRESS` for pod veths). Rate
limited via `cilium_ratelimit`. `IPV4_POLICY_DENIED` (M2): same shape with
Administratively Prohibited (type 3 code 13 / ICMPv6 type 1 code 1).

### 3.16 Trace and drop emission

- Trace points and reasons: §2.7 and inventory 09. Aggregation
  (`monitor_aggregation` per endpoint / node): `0` emit all; `≥1` suppress
  all `FROM_*` points; `3` emit `TO_*` only when the CT lookup returned
  `monitor != 0` (new flow, closing flags, or `CT_REPORT_INTERVAL = 5 s`
  since the last report in that direction). `monitor` also caps the
  capture length: `TRACE_PAYLOAD_LEN` = `trace_payload_len` (default 128)
  or `trace_payload_len_overlay` (192) when the classifier says
  VXLAN/Geneve.
- Rate limit: token bucket `cilium_ratelimit[{usage=EVENTS_MAP}]` with
  `events_map_rate_limit` tokens per second and `events_map_burst_limit`
  bucket; 0 disables.
- Drop: `send_drop_notify(src, dst, dst_id, reason, ext_err, direction)`
  is a tail call to slot `DROP_NOTIFY` so the notification cost does not
  count against the calling program's verifier budget; it writes
  `drop_notify v3` with `file` (source file id, §2.7 of inventory 09) and
  `line`, then returns `TC_ACT_SHOT`. Metrics `cilium_metrics{reason,
  dir, line, file}` are bumped before the tail call. `drop_notify` can be
  switched off per endpoint (`drop_notify` option) — metrics still count.

### 3.17 Drop points by pipeline (M1 codes)

| Pipeline | Codes emitted |
|---|---|
| 1 pod egress | 166, 139, 134, 132, 158, 159, 141, 154, 135, 137, 184, 163, 133, 181, 189, 170, 155, 169, 203, 160, 196 |
| 2 pod ingress | 166, 139, 134, 184, 163, 133, 181, 189, 155, 141, 202, 203, 175, 207, 157 |
| 3 overlay egress | 162 (metrics only), 167, 168, 153, 154, 134 |
| 4 overlay ingress | 134, 147, 171, 183, 139, 151, 157, 175, 141, 158, 177, 174, 163, 167 |
| 5 native ingress | 182, 166, 139, 134, 151, 157, 158, 177, 174, 163, 167, 169, 141, 137 |
| 5 native egress | 134, 167, 168, 191, 153, 154, 142, 159, 141, 204 (M3) |
| 6 host→pod | as pipeline 5 ingress plus 203 |
| 7 NodePort | 158, 177, 174, 134, 163, 171, 167, 169, 141, 153, 154, 160, 147 |
| 8 hairpin | as 1 and 2 |
| 9 fragments | 175, 207, 157, 135 |
| 10 MTU | 136 (`FRAG_NEEDED`, M2 DSR), 196 |
| any tail | 140 (`MISSED_TAIL_CALL`, ext_err = slot), 165 unused |

### 3.18 Pipeline 6 — host → pod (`from_host`, `cilium_host` egress)

1. Clear cb; EDT aggregate 0 (M3). L7 LB EPID hairpin (M2).
2. `inherit_identity_from_host` (§3.2 step 3) — host stack traffic carries
   `MARK_MAGIC_HOST` set by the nftables residual, or an identity mark set
   by the proxy / by `from_overlay`'s host delivery. Mark := 0.
3. Trace `FROM_HOST` (src identity). `do_netdev(from_host = true)` → tail
   `IPV4_FROM_HOST`: host firewall egress lookup (M2) → tail
   `IPV4_CONT_FROM_HOST` → `handle_ipv4_cont` with `from_host = true`:
   local endpoint → `ipv4_local_delivery` (§3.9; `redirect_peer` is not
   used from the host, delivery is via `cilium_call_policy` or endpoint
   route redirect); otherwise tunnel mode and remote pod → encap with
   VNI = `HOST→LOCAL_NODE` (§3.3) else pass to stack (native routing).
   Packets from the proxy (`tc_index` proxy flags) set
   `MARK_MAGIC_SKIP_TPROXY` on the way out.

`to_host` (`cilium_host`/`cilium_net` ingress): host firewall ingress (M2,
tail `IPV4_TO_HOST_POLICY_ONLY`); IPsec rev-DNAT (M3); otherwise trace
`TO_HOST` and pass. In M1 the program is attached and is a pass-through
that emits the trace (so Hubble sees `to-host`).

### 3.19 Pipeline 8 — hairpin / loopback

Pod P (IP p) → Service S whose selected backend is P itself:
1. Pipeline 1 step 6b marks `loopback`, DNATs to `p:backend_port` and
   SNATs the source to `service_loopback_ipv4` (169.254.42.1 default) /
   `service_loopback_ipv6`; CT(SERVICE) entry and CT(EGRESS) entry with
   `lb_loopback = 1`; policy is skipped (the pod talks to itself).
2. Local delivery back into the same veth (`redirect_peer` to P's own
   ifindex). Pipeline 2 sees `NEW`, `saddr == service_loopback_ipv4` and an
   egress loopback entry for the flipped tuple → skip policy, create the
   INGRESS entry with `loopback`.
3. Reply from P to `service_loopback_ipv4:backend_port` → pipeline 1
   CT(EGRESS) → `REPLY` → pipeline 2 on the same veth → `lb_rev_nat(...,
   loopback = true)` restores `saddr = S`, `sport = service_port`, `daddr =
   p`.
Same-veth L7 LB hairpin (M2): `from_l7lb && ifindex != cilium_host_ifindex`
→ `redirect(ifindex, 0)`.

### 3.20 Pipeline 10 — MTU

The datapath does not compute path MTU in M1: pod and tunnel MTU are route
attributes set by the agent. `device_mtu` is consumed only by DSR
(`dsr_is_too_big` → ICMP Fragmentation Needed with `mtu - overhead`, M2)
and by the ICMPv6 error sampler (truncate to 1280 minus headers).
`allow_icmp_frag_needed` (default true) MUST let inbound ICMP Frag Needed
through policy (§3.10) so PMTU discovery works. Reason code
`REASON_MTU_ERROR_MSG 15` marks CT trace of translated ICMP errors.

---

## 4. Data model

Only datapath-internal structures; map key/values are in spec 01.

| Struct | Size | Fields | Where |
|---|---|---|---|
| `ct_buffer4` | 40 B | `ipv4_ct_tuple tuple` (14, padded), `ct_state state`, `u32 monitor`, `s32 ret`, `s32 l4_off`, `fraginfo_t` | per-CPU `cilium_tail_call_buffer4`, written by `*_CT_*` tails, read by the policy tail |
| `ct_buffer6` | 64 B | same with `ipv6_ct_tuple` (38) | `cilium_tail_call_buffer6` |
| `ct_state` | 32 B | `nat_addr (v6 union)`, `nat_port be16`, `rev_nat_index u16`, bits `loopback, node_port, dsr_internal, syn, proxy_redirect, from_l7lb, from_tunnel, closing`, `src_sec_id u32`, `backend_id u32` | in-program only |
| `nodeport_nat_info` | 20 B | `u32 saddr / v6addr`, `be16 sport` | per-CPU `cilium_nodeport_nat_buffer` between LB and CT create |
| `trace_ctx` | 8 B | `reason u8 (enum trace_reason)`, `monitor u32` | in-program |
| `fraginfo_t` | 8 B | §3.13 | in-program, cb, ct_buffer |
| `lb_ctx_state` | cb slots | `rev_nat_index u16`, `proxy_port be16` (slot 0 packed), `cluster_id` (slot 1), `loopback` bit | cb across `IPV4_CT_EGRESS` |
| `bpf_fib_lookup_padded` | 64 + 8 B | kernel `bpf_fib_lookup` + pad for 8-byte alignment | stack |
| `snat_v4_target` | 24 B | `addr be32, min_port u16, max_port u16, from_local_endpoint, egress_gateway, needs_ct bits, cluster_id u32, ifindex u32, tbid u32` | per-CPU aux |

All are `#[repr(C)]` in `flowsdn-bpf-abi` (§11.6). None is visible to
userspace except through the perf event structs of §2.7, whose layouts are
in spec 01.

---

## 5. Algorithms

### 5.1 Identity ↔ mark ↔ VNI

Given 24-bit `id` (spec 03 bit split with `cluster_id_bits` reserved at
the top when cluster-aware addressing is on):
- mark := `magic | ((id & 0xFFFF) << 16) | ((id >> 16) & 0xFF)`; with
  cluster-aware addressing the low byte is `cluster_id` and `id & 0xFFFF`
  is the local part.
- VNI := `id_on_wire` where `HOST → LOCAL_NODE (6)`, `WORLD_IPV4/6 → WORLD (2)`;
  on decap `WORLD → WORLD_IPV4/6` by ethertype when dual-stack.

### 5.2 Two-stage policy lookup

§3.10 pseudocode is normative. Cost bound: at most three LPM lookups per
NEW connection (specific, aggregate, id-0 fallback), one when the specific
entry has `MAX_PRECEDENCE`.

### 5.3 SNAT port allocation

```
range = [min_port, max_port]                    # closed
port  = sport if sport in range else clamp(range, prandom_u16)
for retries in 0..32:
    rtuple.dport = htons(port)
    if insert(rev_entry, NOEXIST) == OK: break
    port = clamp(range, port + 1)               # linear probe after first random pick
clamp(range, v) = start + ((v * (end - start + 1)) >> 16)   # biased but branch-free
retries_hist[retries] += 1
retries >= 16 → signal NAT_FILL_UP
32 without success → DROP_NAT_NO_MAPPING
```

### 5.4 Tuple hash for tunnel source port (XDP, M2)

`h = jhash_3words(saddr, daddr, (sport << 16) | dport ^ proto, hash_init4_seed)`;
`src_port = (h >> 16) ^ (h & 0xFFFF)`; tc uses 0 (kernel picks).

### 5.5 Incremental checksums

L3: `bpf_l3_csum_replace(ip_off + 10, old, new, 4)` for address rewrites;
TTL decrement via `csum + htons(0x0100)` fold. L4: `bpf_l4_csum_replace`
with `BPF_F_PSEUDO_HDR` for address changes and plain for port changes;
UDP zero checksum preserved (`BPF_F_MARK_MANGLED_0`); SCTP not
recomputed (CRC32c offload; the reference does not fix it either).
XDP (M2): software `csum_diff` fold, `CSUM_MANGLED_0` for UDP.

### 5.6 Monitor aggregation

`ct_update_timeout` returns `TRACE_PAYLOAD_LEN` when new TCP flags appear
in the direction's `*_flags_seen`, or when `now - last_{rx,tx}_report ≥
CT_REPORT_INTERVAL`; else 0. `emit_trace_notify(point, monitor)` as §3.16.

### 5.7 Time base

`bpf_mono_now()` = **`ktime_get_ns() / NSEC_PER_SEC`** (whole seconds since
boot) when `enable_jiffies` is false; otherwise `jiffies64() >>
BPF_MONO_SCALER` with `BPF_MONO_SCALER = 8`, and seconds convert as
`(s * kernel_hz) >> 8` (`bpf_sec_to_mono`). CT lifetimes, `last_*_report`
and `nat_entry.created` are in this unit; the agent (spec 04 GC) MUST use
the same conversion when comparing against the current time.

---

## 6. Configuration

### 6.1 `.rodata` constants read by the programs

Patched at load per spec 01 (`set_global`). Names are the reference's
(`__config_<name>`), so `cilium-dbg` config dumps stay readable.

**Node-level (present in every object)**

| Name | Type | Default | Effect |
|---|---|---|---|
| `cilium_net_ifindex`, `cilium_net_mac` | u32, mac | — | IPsec/proxy hairpin target |
| `cilium_host_ifindex`, `cilium_host_mac` | u32, mac | — | host delivery target (§3.4) |
| `service_loopback_ipv4` / `_ipv6` | be32 / v6 | 169.254.42.1 / fd00::… | hairpin SNAT source |
| `router_ipv6` | v6 | — | ICMPv6 responder source |
| `trace_payload_len`, `trace_payload_len_overlay` | u32 | 128, 192 | capture length |
| `direct_routing_dev_ifindex` | u32 | — | NodePort SNAT egress device |
| `supports_fib_lookup_skip_neigh`, `supports_fib_lookup_src` | bool | probed | FIB flags |
| `enable_nodeport_source_lookup` | bool | false | `BPF_FIB_LOOKUP_SRC` for SNAT source |
| `enable_ipip_termination` | bool | false | M3 |
| `tracing_ip_option_type` | u8 | 0 | M3 |
| `policy_deny_response_enabled` | bool | false | M2 |
| `cluster_id`, `cluster_id_bits` | u32, u8 | 0, 8 | spec 03 |
| `enable_conntrack_accounting` | bool | false | packets/bytes in CT |
| `debug_lb` | bool | false | LB debug events |
| `lb_default_alg`, `lb_selection_per_service` | u8, bool | RANDOM, false | §3.12 |
| `nodeport_port_min`, `nodeport_port_max` | u16 | 30000, 32767 | SNAT range start = max+1 |
| `hash_init4_seed`, `hash_init6_seed` | u32 | random per node | Maglev/tunnel hash |
| `nat_46x64_prefix` | v6 | 64:ff9b::/96 | M3 |
| `enable_tproxy` | bool | true | §3.14 |
| `events_map_rate_limit`, `events_map_burst_limit` | u32 | 0 | §3.16 |
| `enable_endpoint_routes` | bool | false | §3.9 step 4 |
| `enable_identity_mark` | bool | true | set `MARK_MAGIC_IDENTITY` on pass-to-stack |
| `enable_bpf_host_routing` | bool | **true** | §3.8 |
| `encryption_strict_ingress` | bool | false | M3 |
| `enable_jiffies`, `kernel_hz` | bool, u32 | false, probed | §5.7 |

**Object/endpoint-level**

| Name | Object | Effect |
|---|---|---|
| `interface_ifindex`, `interface_mac` | all | the attached device |
| `security_label` | lxc, host | endpoint identity (`SECLABEL`) |
| `host_ep_id` | lxc, host | slot of `host_policy`; `source` in events for host |
| `endpoint_id`, `endpoint_ipv4`, `endpoint_ipv6`, `endpoint_netns_cookie`, `rt_info` | lxc | `LXC_ID`, SIP check, LRP, FIB table |
| `enable_arp_responder` | lxc | M3 |
| `eth_header_length` | host | 14 or 0 (L3 device) |
| `enable_xdp_prefilter` | xdp | M2 |
| `enable_no_service_endpoints_routable` | sock, lxc, host | §3.6 3f |
| `device_mtu` | all | §3.20 |
| `tunnel_protocol` (1 VXLAN, 2 Geneve), `tunnel_port` | all | §2.5 |
| `vtep_mask`, `wg_ifindex`, `wg_port` | host | M3 |
| `enable_lrp` | lxc, sock | M2 |
| `enable_ipv4_fragments`, `enable_ipv6_fragments` | all | §3.13 |
| `enable_extended_ip_protocols` | lxc, host | allow IGMP/others through CT as `_any` |
| `enable_netkit` | lxc, host | §3.8 |
| `enable_remote_node_masquerade`, `nat_ipv4_masquerade`, `nat_ipv6_masquerade`, `ephemeral_min` | host, overlay | §3.7 |
| `proxy_redirect_via_cilium_net` | host | M2 |
| `allow_icmp_frag_needed` (true), `enable_icmp_rule` (false), `enable_policy_accounting` (false), `policy_verdict_log_filter` (0xFFFF) | lxc, host | §3.10 |
| `hybrid_routing_enabled`, `enable_l2_announcements`, `l2_announcements_max_liveness` | host | M3 |

**Constants that the reference had as `#define`s and that flowsdn makes
`.rodata` variables** (values, not toggles): `IPV4_GATEWAY`,
`IPV4_DIRECT_ROUTING` / `IPV6_DIRECT_ROUTING`, `IPV4/6_SNAT_EXCLUSION_DST_CIDR`
(+len), `ENCAP_IFINDEX` (`encap4_ifindex`, `encap6_ifindex`),
`HOST_NETNS_COOKIE`, `IPV4/6_RSS_PREFIX(_BITS)`, `EGRESS_GATEWAY_RT_TBID`,
`IPV4_ENCRYPT_IFACE`, `STRICT_IPV4_NET(_SIZE)`, `STRICT_IPV4_OVERLAPPING_CIDR`,
all `CT_*` timeouts (`ct_lifetime_tcp 8000`, `_nontcp 60`,
`ct_service_lifetime_tcp 8000` / `_nontcp 60`, `ct_service_close_rebalance 30`,
`ct_syn_timeout 60`, `ct_close_timeout 10`, `ct_report_interval 5`,
`ct_report_flags 0xff`), `monitor_aggregation` (u8), `VLAN_FILTER` (becomes
the `cilium_vlan_filter` HASH map keyed `{ifindex, vlan}` — **DEVIATION**:
the reference generates a `switch` into `node_config.h`; a map is the only
option without a compiler on the node, ADR-0002), `LB_MAGLEV_LUT_SIZE`
(`maglev_lut_size`, also a map size in spec 01). Map sizes are loader
parameters (spec 01), not program constants. The TCP values above are
the effective configured defaults (spec 04 §6; ADR-0011, #74); 21600 seconds
is the reference BPF fallback, not a flowsdn runtime default.

### 6.2 Feature toggles: what becomes a patched global, what becomes a build dimension

Verifier-budget reasoning. The reference keeps each object under the
verifier limits by `#ifdef` dead-code elimination at node-side compile
time. flowsdn has no compiler on the node (ADR-0001/0002), so the choices
are: (a) a `.rodata` boolean read through a volatile load, with the loader
pruning unreachable blocks before load (spec 01, "reachability pass") —
after pruning the verifier sees the same instructions the `#ifdef` build
would have produced; (b) a Cargo feature that produces a distinct ELF, for
cases where a toggle changes *shape* in a way pruning cannot recover
(different map definitions, different struct sizes, different program
sections) or where a single all-features object would exceed the
1,000,000-instruction verifier limit or the 512-byte stack even after
pruning; (c) always-on, when the reference's off-path is not a
configuration flowsdn supports (ADR-0001: no iptables fallbacks).

Rule: **default to (a)**. Promote to (b) only on measurement (§9.4 gate:
all-features object, floor kernel, after pruning, > 800k instructions or
any program > 480 B stack). Predicted promotions are listed; the decision
is recorded in §12.1.

| Macro (reference) | flowsdn | Milestone | Reasoning |
|---|---|---|---|
| `ENABLE_IPV4`, `ENABLE_IPV6` | (a) `enable_ipv4`, `enable_ipv6` | 1 | dual-stack is the common case; pruning removes the unused family's tails and maps |
| `ENABLE_NODEPORT` | (c) always on | 1 | kube-proxy replacement is the only mode (no iptables), matches ADR-0003 |
| `ENABLE_PER_PACKET_LB` | (a) `enable_per_packet_lb` (= !socket-LB-full) | 1 | |
| `ENABLE_HOST_FIREWALL`, `HOST_ENDPOINT` | (a) `enable_host_firewall` | 2 | `host_policy` program pruned when off |
| `ENABLE_SCTP` | (a) `enable_sctp` | 1 | small |
| `ENABLE_L7_LB` | (a) `enable_l7_lb` | 2 | |
| `ENABLE_EGRESS_GATEWAY(_COMMON)` | (a) `enable_egress_gateway` | 3 | candidate for (b) if host object overflows |
| `ENABLE_ROUTING` | (a) `enable_routing` (= !endpoint routes) | 1 | |
| `ENABLE_DSR`, `ENABLE_DSR_BYUSER`, `ENABLE_DSR_ICMP_ERRORS`, `DSR_ENCAP_MODE` | (a) `dsr_mode` u8 {off, option, ipip, geneve}, `dsr_byuser`, `dsr_icmp_errors` | 2 | **predicted (b)**: three encap bodies in one object roughly triples `nodeport` DSR code; measure first |
| `ENABLE_CLUSTER_AWARE_ADDRESSING`, `ENABLE_INTER_CLUSTER_SNAT` | (a) `cluster_id_bits != 0` / `enable_inter_cluster_snat` | 3 | per-cluster map-in-map lookups pruned when off |
| `ENABLE_IPSEC`, `ENABLE_NODE_ENCRYPTION`, `ENCRYPTION_STRICT_MODE_EGRESS` | (a) `enable_ipsec`, `enable_node_encryption`, `strict_mode_egress` | 3 | |
| `ENABLE_WIREGUARD` | (a) `enable_wireguard`; wireguard object built always | 3 | |
| `ENABLE_SRV6`, `ENABLE_SRV6_SRH_ENCAP` | (a) | 3 | candidate for (b) |
| `ENABLE_HEALTH_CHECK` | (a) `enable_health_check` | 2 | sock object |
| `ENABLE_NODEPORT_ACCELERATION` | (c) implied by attaching the xdp object | 2 | |
| `ENABLE_VTEP` | (a) `enable_vtep` | 3 | |
| `ENABLE_SNAT_ICMPV4` | (c) always on | 1 | no reason to ship without |
| `ENABLE_NAT_46X64`, `ENABLE_NAT_46X64_GATEWAY`, `NODEPORT_USE_NAT_46x64` | (a) `nat46x64_mode` u8 | 3 | |
| `ENABLE_MASQUERADE_IPV4/6`, `ENABLE_IP_MASQ_AGENT_IPV4/6` | (a) `enable_masquerade_ipv4/6`, `enable_ip_masq_agent_ipv4/6` | 1 | |
| `ENABLE_MULTICAST` | (a) `enable_multicast` | 3 | arm64 ≥ 6.0 for `for_each_map_elem` |
| `ENABLE_BANDWIDTH_MANAGER` | (a) `enable_bandwidth_manager` | 3 | |
| `ENABLE_ACTIVE_CONNECTION_TRACKING` | (a) | 2 | |
| `ENABLE_SOCKET_LB_FULL/HOST_ONLY/PEER/TCP/UDP` | (a) in the sock object | 2 | |
| `ENABLE_SIP_VERIFICATION` | (a) `enable_sip_verification` (default true) | 1 | |
| `ENABLE_MKE`, `MKE_HOST` | (a) `mke_host_classid` | 3 | |
| `ENABLE_EXTENDED_IP_PROTOCOLS` | (a) | 1 | already a CONFIG in the reference |
| `TUNNEL_MODE`, `HAVE_ENCAP` | (a) `tunnel_mode` (routing), `have_encap` (encap code present) | 1 | |
| `IS_BPF_LXC/HOST/OVERLAY/XDP/WIREGUARD/SOCK` | (b) one ELF per hook family | 1 | inherent |
| `PROG_TYPE` tc vs xdp, `ETH_HLEN` | (b) object / (a) `eth_header_length` | 1 / 1 | |
| `USE_LOOPBACK_LB` | (c) on in lxc | 1 | |
| `POLICY_AUDIT_MODE`, `POLICY_VERDICT_NOTIFY`, `DROP_NOTIFY`, `TRACE_NOTIFY`, `MONITOR_AGGREGATION`, `LOCAL_DELIVERY_METRICS`, `POLICY_ACCOUNTING` | (a) per-endpoint u8/bool globals | 1 | per-endpoint objects are patched individually (spec 01) |
| `DEBUG`, `SKIP_DEBUG`, `TRACE_SOCK_NOTIFY` | **(b) Cargo feature `debug-events`** | 1 | debug events add a `perf_event_output` at every step of every path; not shipped in release objects |
| `DISABLE_EXTERNAL_IP_MITIGATION`, `SERVICE_NO_BACKEND_RESPONSE` | (a) | 1 | |
| `PREALLOCATE_MAPS`, `NO_COMMON_MEM_MAPS`, `*_MAP_SIZE` | loader (spec 01) | 1 | map flags/sizes, not code |
| `VLAN_FILTER` | map (`cilium_vlan_filter`) | 1 | **DEVIATION** §6.1 |
| `BPF_TEST` | (b) Cargo feature `test-hooks` | 1 | test fixtures |
| `CONDITIONAL_PREALLOC`, `LRU_MEM_FLAVOR`, `BPF_F_RDONLY_PROG_COND` | loader | 1 | |

Net: two build dimensions (`debug-events`, `test-hooks`) plus the object
kind; ~45 runtime toggles. A third (`dsr_mode`) is expected after
measurement.

### 6.3 Agent flags accepted but without datapath effect

`--install-iptables-rules`, `--iptables-*`, `enable-ipv4-masquerade` in its
iptables meaning, `--bpf-lb-mode=snat|dsr` (kept, drives `dsr_mode`),
`--enable-bpf-clock-probe` (always probed), `--datapath-mode=veth|netkit`
(honoured), `--enable-l7-proxy` (M2). Documented in the Helm mapping.

---

## 7. Failure modes

| Failure | Behaviour |
|---|---|
| Missing kernel helper / program type at startup | Loader (spec 01) refuses to start with a named feature; ADR-0001 "startup check that refuses to run". No runtime probing in the datapath. |
| Tail-call slot empty | `DROP_MISSED_TAIL_CALL` (140), `ext_error = slot`; indicates a loader bug (pruning removed a reachable tail). |
| Endpoint policy program not yet inserted | `DROP_EP_NOT_READY` (203) for packets to that endpoint until the agent completes regeneration; `HOST_NOT_READY` (202) for host policy. |
| CT map full | LRU eviction; `SIGNAL_CT_FILL_UP` when insert fails; drop 155 with errno in `ext_error`. |
| NAT port exhaustion | drop 167 after 32 retries, `SIGNAL_NAT_FILL_UP` at 16. |
| Fragment cache miss | drop 175/207; first fragment arrives later → subsequent fragments pass. |
| FIB lookup failure | drop 169 (BPF host routing); packets are never silently passed to the stack for the kernel to route, so a misconfigured route is visible in Hubble. |
| Agent down | Pinned maps and attached programs keep forwarding; policy/service state freezes; CT GC stops (LRU protects the map). |
| Upgrade with changed `.rodata` names | Loader `set_global(must_exist)` fails → old programs stay attached. |
| Upgrade with changed cb/tail contract between objects | All objects of a node MUST come from one build; the loader attaches the whole set from one ELF bundle and commits pins only after every hook is attached (spec 01). |
| Mixed-version cluster (Cilium ↔ flowsdn nodes) | Wire format §2.5 is version-independent; identity numbering must agree (spec 03). |
| XDP driver rejects `HAS_FRAGS` or native mode | M2: fall back to generic; the tc path is complete without XDP. |
| Verifier rejects an object on a supported kernel | Startup failure with the verifier log; CI (§9.4) must have caught it. |

---

## 8. Observability

- Perf events per §2.7; the agent's monitor socket and Hubble decoders
  (spec 01 / Hubble spec) consume them unchanged.
- `cilium_metrics{reason, dir, line, file}` per drop and per forward at
  trace points (`REASON_FORWARDED 0`); Prometheus names
  `cilium_drop_count_total{reason, direction}`,
  `cilium_forward_count_total{direction}`, `cilium_drop_bytes_total`,
  `cilium_forward_bytes_total` — reference-compatible labels.
- `cilium_policystats` when `enable_policy_accounting`.
- `cilium_snat_v4_alloc_retries` histogram; `cilium_ratelimit_metrics`
  dropped counters.
- Signals: NAT/CT fill-up, auth required.
- Debug events (`debug-events` build): `DBG_*` codes of the reference,
  `debug_msg{arg1,arg2,arg3}` and `debug_capture_msg`.
- Verifier statistics (instruction count, stack depth per program) MUST
  be logged by the loader at attach time and exported as a gauge so budget
  regressions are visible in production, not only in CI.

---

## 9. Test plan

### 9.1 Harness

A Rust test crate (`flowsdn-bpf-tests`, privileged) that loads each ELF
with aya, populates maps from fixtures (ipcache, lxc, lb services/backends/
revnat, policy, CT/NAT, devices), builds packets with a Rust packet builder
(`etherparse`-class crate, no scapy), runs the program under test with
`BPF_PROG_RUN` (`bpf_prog_test_run_opts`, `ctx_in` for skb fields such as
mark/ifindex/cb where the kernel allows, data_in/data_out), and asserts on
return code, output packet bytes, map contents (CT/NAT entries), cb/mark
values and emitted perf events. Each reference test file becomes one Rust
test module; each `CHECK` name becomes one `#[test]`. Tests that need more
than `BPF_PROG_RUN` allows (redirect targets, `redirect_peer`) run in a
network namespace with veth pairs and assert on the receiving side.

### 9.2 Per-pipeline packet fixtures (M1 acceptance)

For each of pipelines 1–10: TCP SYN / SYN-ACK / ACK / FIN / RST, UDP,
ICMP echo, ICMP error carrying a tracked flow, SCTP INIT, IPv4 and IPv6,
fragment first/subsequent, oversized (MTU), VLAN-tagged (pipeline 5),
each with the expected verdict, rewritten headers, CT/NAT map deltas,
trace/drop/verdict events. Fixtures are data files (hex + expected) so
they can be shared with the e2e suite.

### 9.3 Reference test cases to port (checklist, grouped by reference file)

Legend: [1]/[2]/[3] milestone; names are the reference `CHECK` names,
kept so the two suites can be compared. Files with no named checks use a
single default case per file.

- **bpf_ct_tests.c** [1]: ct4 (lookup/create/flip/related).
- **conntrack_test.c** [1]: conntrack; conntrack_svc.
- **bpf_nat_tests.c** [1]: nat4_port_allocation_tcp; nat4_port_allocation_udp; nat4_icmp_error_{icmp,tcp,udp,sctp}; nat4_icmp_error_{icmp,tcp,udp,sctp}_egress; nat4_icmp_error_tcp_rfc1191; nat4_icmp_error_tcp_egress_rfc1191.
- **icmp_error_revnat.c** [1]: nat4_icmp_error_tcp_snat_revnat.
- **tc_nodeport_snat_conflict.c** [1]: tc_nodeport_snat_conflict_{pod,host,egressproxy}_{ipv4,ipv6}.
- **remote_node_masquerade_test.c / _skip_test.c** [1]: nat4_remote_node_masquerade_enabled_test; nat4_remote_node_masquerade_skipped_test.
- **host_bpf_masq_native.c / host_bpf_masq_overlay.c** [1]: default case each.
- **tc_nodeport_icmp{4,6}_snat.c / _tunnel.c** [1], **_hostfw.c** [2]: default cases.
- **tc_nodeport_lb4_nat_lb.c / tc_nodeport_lb6_nat_lb.c** [1]: tc_nodeport_local_backend; _local_backend_redirect; _local_backend_redirect_reply; _local_backend_reply; tc_nodeport_nat_fwd; _nat_fwd_original_renated; _nat_fwd_reply; _nat_fwd_reply_no_fib; _nat_fwd_reply_punt; _nat_fwd_restore; _nat_fwd_restore_original_entry; _nat_fwd_restore_reply; _nat_fwd_verify_restored_original_entry; tc_nodeport_nat_shared_backend_fwd; _shared_backend_reply; tc_nodeport_udp_local_backend.
- **tc_nodeport_lb4_nat_backend.c** [1]: tc_nodeport_nat_backend.
- **tc_nodeport_lb_nat_lb_dynamic.c** [1]: tc_nodeport_lb{4,6}_nat_lb_dynamic.
- **tc_nodeport_lb_no_backend.c** [1]: tc_nodeport_no_backend{4,6}; _2_reply.
- **tc_nodeport_lb_terminating_backend.c** [1]: _0; _1.
- **tc_nodeport_lb_wildcard_drop.c** [1]: tc_nodeport_lb{4,6}_wildcard_drop_{not_unknown,not_unknown2,unknown_dport,unknown_proto}.
- **tc_nodeport_test.c** [1]: hairpin_flow_{1_forward,2_forward_ingress,3_reverse,4_reverse_ingress}_{v4,v6}; tc_drop_no_backend; tc_drop_no_backend_v6.
- **hairpin_sctp_flow.c** [1]: hairpin_sctp_flow_{1..4}_v4.
- **tc_nodeport_lb_fragments_ew.c / _ns.c** [1]: default cases.
- **nodeport_overlay_nat_lb.c** [1]: nodeport_overlay_nat_1_fwd; _2_reply.
- **tc_nodeport_l3_dev.c / tc_nodeport_l3_dev_to_tunnel.c** [1]: ipv{4,6}_tc_nodeport_l3_to_remote_backend_via_tunnel; default.
- **tc_lb_clusterip.c** [1]: tc_lb{4,6}_{nonroutable,routable}_clusterip.
- **tc_lb_external_ips_ew.c / _ns.c** [1]: default cases.
- **tc_lb_no_backend_nonroutable.c** [1]: tc_lb_no_backend_nonroutable; _etp.
- **lb_tests.c** [1]: lb4_{tcp,udp}_{single,dual}_scope; lb4_proto_mismatch_{nowild,wild}_{single,dual}_scope.
- **tc_lxc_lb_hostport.c** [1]: tc_lxc_{v4,v6}_host_hostport_local_backend; _hostport_nodeport_range_no_match.
- **tc_lxc_lb_no_backend.c** [1]: tc_lxc{4,6}_no_backend.
- **tc_lxc_lb_nodeport.c** [1]: tc_lxc_{v4,v6}_{existing_conn_udp_first, existing_conn_udp_second, host_nodeport_local_backend, remote_nodeport_hairpin, remote_nodeport_hairpin_reply, remote_nodeport_local_backend, remote_nodeport_local_backend_reply}; [2] _remote_nodeport_dsr_local_backend(_reply).
- **session_affinity_test.c** [1]: session_affinity. **session_affinity_maglev_test.c** [2]: client_{1,2}_port_{1,2,3}.
- **tc_lxc_policy_drop.c** [1]: tc_lxc_policy_drop. **network_policy.c** [1]: network_policy_egress_allow. **tc_policy_reject_response_test.c** [2]: policy_reject_response_{v4,v6,v6_ingress}.
- **tc_redirect_{lxc,host,netdev}_{veth,netkit}.c, tc_redirect_host_{veth,netkit}_policy.c** [1]: default cases (redirect_peer vs redirect, policy tail).
- **skip_tunnel_from_lxc.c / skip_tunnel_from_host.c** [1]: 01..12 (`ipv{4,6}_from_{lxc,host}_{no_flags,skip_tunnel}_{no_subnet_entries,same_subnet,different_subnet}`).
- **skip_tunnel_nodeport_{masq,nat,revnat}.c** [1]: 01..04 each.
- **overlay.c** [1]: overlay_neigh_resolver. **fib_tests.c** [1]: fib_do_redirect_happy_path; fib_redirect*_fib_lookup_flags.
- **ipfrag.c** [1]: ipfrag_helpers_{ipv4,ipv6,ipv6_nofrag}. **ipv6_test.c** [1]: ipv6; ipv6_with_auth_hop_tcp; ipv6_without_extension_header; test_ipv6_sol_mc_helpers.
- **ipv6_ndp_from_netdev_test.c** [1]: 011/012/0211/0212/022 variants (NS to pod / node IP, multicast, noopt).
- **drop_notify_test.c** [1]: send_drop_notify. **ratelimit.c** [1]: ratelimit. **jhash_test.c** [2]: jhash. **builtins.c** [1]: builtin_{memcpy,memmove,memmove2,memzero,memcmp} (re-targeted at the Rust copy helpers §11.4).
- **bpf_skb_255_tests.c / bpf_skb_511_tests.c** [1]: set_and_get_identity; set_and_get_cluster_id; set_identity_mark_bits.
- **mock_skb_metadata.c** [1]: 01/02. **classifiers_l2_dev.c / _l3_dev.c** [1]: default. **_scapy_selftest.c** [1]: 1_basic_test; 1_test_large_pkts; 2_test_xlarge_pkts (packet builder self-test).
- **lxc_extended_protocols.c** [1]: lxc_igmp_egress; _policy; _policy_deny. **host_hostfw_extended_protocols.c / host_hostfw_igmp.c** [2].
- **wildcard_lookup.c** [2]: sock{4,6}_wildcard_lookup_test. **host_only_socket_lb_test.c** [2]: sock4_xlate_fwd_test. **skip_lb_xlate_socket_lb.c** [2]: sock{4,6}_xlate_fwd. **skip_lb_xlate_lrp_per_packet_lb.c** [2]: v{4,6}_local_redirect. **destroy_sock_socket_lb.c** [3]: sock_terminate.
- **host_proxy.c** [2]: proxy_v4_{1_host_to_world,2_proxy_to_world,3_host_to_pod,4_proxy_to_pod}. **l7_lb_hairpin_netdev.c** [2]: l7_lb_hairpin_{v4,v6}. **l7_lb_local_backend_{host,pod}.c** [2].
- **hostfw_host_iptables.c** [2] (as nftables residual): hostfw_iptables_host_ipv4_0{1,2}_pod, _0{3,4,5}_host. **hostfw_bpf_masq.c** [2]: hostfw_ipv4_bpf_masq_proxy_0{1,2}.
- **DSR** [2]: tc_nodeport_lb_dsr_lb.c (tc_nodeport_dsr_fwd{4,6}); tc_nodeport_lb_dsr_ipip.c (dsr_ipip{4,6}_fwd); tc_nodeport_lb{4,6}_dsr_backend.c (tc_nodeport_dsr_backend, _redirect, _redirect_reply, _reply); tc_nodeport_lb{4,6}_dsr_ipip_local.c (_l7punt, _pod); tc_geneve_dsr_legacy.c; tc_nodeport_l3_dev_lb_dsr_geneve_lb.c; nodeport_hybrid_dsr_test.c (test_nodeport_uses_dsr_ipv{4,6}_with_flag); host_kpr_dsr_{geneve_lb,option_lb,option_remote_node}.c; nodeport_geneve_dsr_lb_xdp.c; xdp_kpr_dsr_*.c; xdp_nodeport_lb_dsr_{lb,ipip}.c.
- **XDP** [2]: xdp_nodeport_lb4_nat_lb.c (xdp_nodeport_{etp_local,l7delegate_local,l7delegate_remote,local_backend,nat_fwd,nat_fwd_reply,nat_fwd_reply_no_fib}); xdp_nodeport_lb4_nat_backend.c; xdp_nodeport_lb4_nat_lb_tun_dynamic.c; xdp_nodeport_lb4_test.c (xdp_lb4_drop_no_backend; xdp_lb4_forward_to_other_node).
- **Encryption** [3]: encryption_helpers_{ipsec,ipsec_native,ipsec_tunnel,wireguard}.c (ctx_is_{encrypt,decrypt,wireguard}_success; do_decrypt{4,6}; ipsec_redirect{4,6}{,_over6}; ipsec_redirect_bad_identities{4,6}; ipsec_redirect_tunnel{4,6}_v{4,6}; wireguard_icmpv6_na_skip); encrypt_host_{ipsec,wireguard}{,_strict,_tunnel,_tunnel_strict}.c; decrypt_host_{ipsec,wireguard,wireguard_strict}.c (ipv{4,6}_strict_ingress_from_netdev; ipv4_strict_ingress_hostport_from_netdev); decrypt_overlay_wireguard.c (ipv4_wireguard_{mark,no_mark}_from_overlay); tc_nodeport_l3_wireguard.c.
- **Egress gateway** [3]: tc_egressgw_redirect_from_host.c (tc_egressgw_{drop_no_egress_ip,egress1,egress2_ifindex,egress3_rt_info,redirect,skip_excluded_cidr_redirect,skip_no_gateway_redirect} + _v6); tc_egressgw_redirect_from_overlay.c (+ _with_rt_info.c); tc_egressgw_snat.c (snat1, snat1_2_reply, snat2, tuple_collision1/2/2_reply, skip_excluded_cidr_snat, v6 variants); xdp_egressgw_reply.c.
- **Cluster mesh** [3]: inter_cluster_snat_clusterip_{client,backend}_{lxc,overlay}.c (01..03 syn/synack/ack).
- **Long tail** [3]: tc_srv6_{encap,decap}.c; mcast_tests.c; tc_l2_announcement{,6}.c; ip_options_trace_id.c (24 cases); l4lb_ipip_health_check_host.c; tc_nodeport_lb{4,6}_ipip_termination.c; eni_nlb_symetric_routing_host.c.

Total: 141 files, ~600 named cases; M1 covers ~55 files / ~300 cases.

### 9.4 Verifier tests per kernel

CI loads every object with the all-features config (all runtime toggles
true, `dsr_mode` each value) and with the M1 default config, after the
loader's pruning, on the 6.6 general minimum, the 6.12 supported line and
6.18, on x86-64 and arm64 per `docs/kernel-requirements.md`. This is the
required validation matrix; it is not evidence of completed verifier runs.
Records per program: instruction count (`verified_insns`), stack depth,
processed states. Gate: fail if any program exceeds 800,000 instructions
or 480 B stack; warn at +10 % vs the previous commit. This replaces the
reference's `complexity-tests/{510,61,netnext}` matrix.

### 9.5 End-to-end

`cilium-cli connectivity test` against a kind cluster and against the
stormcos cluster: the M1 subset (pod-to-pod same/other node, pod-to-service
ClusterIP/NodePort, pod-to-world with masquerade, host-to-pod, pod-to-host,
hairpin, policy allow/deny L3/L4, `--include-unsafe-tests` off) MUST pass
before M1 is declared; the flows MUST appear in `hubble observe` with the
expected trace points and verdicts. Mixed-cluster interop: one Cilium
v1.20.1 node and one flowsdn node in the same VXLAN cluster; pod-to-pod
and NodePort across the two MUST pass with correct identities in Hubble.

---

## 10. Kernel and platform requirements

### 10.1 Helpers by program type (M1 in bold, later milestones plain)

- tc (`SCHED_CLS`): **`map_lookup_elem`, `map_update_elem`,
  `map_delete_elem`, `tail_call`, `ktime_get_ns`, `get_prandom_u32`,
  `get_smp_processor_id`, `skb_load_bytes`, `skb_store_bytes`,
  `l3_csum_replace`, `l4_csum_replace`, `csum_diff`, `skb_pull_data`,
  `skb_change_type`, `skb_change_head`, `skb_adjust_room`,
  `skb_get_tunnel_key`, `skb_set_tunnel_key`, `redirect`, `redirect_peer`,
  `redirect_neigh`, `fib_lookup`, `get_hash_recalc`, `perf_event_output`**;
  `skb_set_tunnel_opt`, `skb_get_tunnel_opt` (DSR Geneve), `skb_change_tail`,
  `skb_change_proto` (NAT46/64), `clone_redirect`, `for_each_map_elem`
  (multicast), `skc_lookup_tcp`, `sk_lookup_udp`, `sk_lookup_tcp`,
  `sk_release`, `sk_assign` (L7), `jiffies64`, `map_lookup_percpu_elem`,
  `loop`.
- XDP (M2): `xdp_adjust_head`, `xdp_adjust_meta`, `xdp_adjust_tail`,
  `xdp_load_bytes`, `xdp_store_bytes`, `xdp_get_buff_len`, `redirect`,
  `fib_lookup`, `perf_event_output`, maps, `csum_diff`.
- cgroup sock_addr / sock (M2): `get_socket_cookie`, `get_netns_cookie`,
  `sk_lookup_tcp/udp`, `sk_release`, `set_retval`, `getsockopt/setsockopt`,
  `perf_event_output`, maps.
- iter (M3): `seq_write`, kfunc `bpf_sock_destroy`.

### 10.2 Minimum kernel

Resolved contract (#54, §12.2): **general minimum 6.6 LTS**, **supported
line 6.12 on both architectures**, matching `docs/kernel-requirements.md`.
Startup refuses missing required capabilities using feature checks, not version
strings. These are validation targets until the privileged matrix passes.
Features by kernel: bounded loops 5.3, `BPF_F_RDONLY_PROG` 5.2, 1M
instruction limit 5.2, `redirect_neigh`/`redirect_peer` 5.10, mixing
BPF-to-BPF calls with tail calls x86-64 5.10 / arm64 6.0, `bpf_loop` 5.17,
`XDP_HAS_FRAGS` 5.18, `xdp_load_bytes` 5.18, `map_lookup_percpu_elem` 5.19,
`BPF_FIB_LOOKUP_SKIP_NEIGH` 6.3, `bpf_sock_destroy` 6.4, `BPF_FIB_LOOKUP_TBID`
6.5, tcx 6.6, `BPF_FIB_LOOKUP_SRC` 6.7, netkit 6.8. 5.10 is not promised
(ADR-0002). Historical helper introduction versions do not lower the chosen
6.6 minimum. Features newer than that minimum retain their individual gates;
`to-verify` items must be validated on the selected matrix.

### 10.3 x86-64 vs arm64

One ELF per object for both (BPF bytecode is architecture-neutral); two
agent binaries. Differences that matter: (1) tail-call + subprogram mixing
needs arm64 ≥ 6.0 — flowsdn's floor covers it, so `#[inline(never)]`
subprograms MAY be used alongside tail calls (§12.8); (2) `for_each_map_elem`
on map-in-map inner maps: arm64 ≥ 6.0; (3) BPF atomics (`__sync_fetch_and_add`
for CT accounting and policy stats) need the arm64 JIT atomics support
(5.12+, LSE recommended); (4) unaligned 8/4/2-byte loads in the copy
helpers are fine on both JITs; (5) BIG TCP arm64 follows the kernel; (6)
the per-CPU aux stride is 64 B on x86-64 and 128 B on arm64 (spec 01).

### 10.4 XDP driver dependence (M2)

Native mode needs `ndo_bpf` and `ndo_xdp_xmit`; `xdp_adjust_meta` must be
honoured for `XFER_PKT_*` to reach tc (drivers that do not preserve
`data_meta` force generic mode). Generic mode works on veth/virtio and is
the expectation on MikroTik/arm64 targets. `XDP_TX` for hairpin replies,
`XDP_REDIRECT` for forwarding. No checksum offload in XDP → software
checksums.

### 10.5 Netlink / modules

tcx (legacy owned clsact filters are removed during takeover); VXLAN or Geneve module for the tunnel device;
`nf_tables` + `nft_tproxy`/`nft_socket` only when L7 is enabled
(ADR-0003); `sch_fq` for EDT (M3); cgroup v2 mounted for socket LB (M2).

---

## 11. Rust design notes (aya-ebpf)

### 11.1 Crate layout

```
crates/
  flowsdn-bpf-abi/      no_std, #[repr(C)] types shared by kernel and userspace:
                        marks, cb slots, tail slots (enum), drop reasons, trace
                        points, notify structs, fraginfo, ct_state, config struct
                        (the .rodata layout), map key/value types (spec 01).
  flowsdn-bpf/          the BPF programs. One Cargo package, target
                        bpfel-unknown-none, [[bin]] per object:
                          lxc, host, overlay, xdp, wireguard, sock, sock_term, probes
                        src/lib.rs holds the shared modules (the lib/*.h
                        equivalents): ct, nat, lb, nodeport, policy, fib,
                        local_delivery, encap, identity, trace, drop, ipv4, ipv6,
                        l3, l4, csum, copy, maps, config, ctx (skb/xdp abstraction).
                        Each bin = one ELF = one object of §1.1 with several
                        #[classifier] / #[xdp] / #[cgroup_sock_addr] entry points.
  flowsdn-bpf-tests/    privileged BPF_PROG_RUN harness (§9.1).
  flowsdn-datapath/     userspace: loader, config, attach (spec 01).
```

One package with one bin per hook family (rather than one crate per hook)
keeps the shared modules monomorphised per object through a `ctx` trait
(`SkbCtx` vs `XdpCtx`) and Cargo features (`object-lxc`, `object-host`, …)
selected per bin, which is how `IS_BPF_*` is expressed. Entry points are
named exactly as §1.1 (`from_container`, …) via `#[classifier(name =
"from_container")]`; tail programs are `#[classifier(name =
"tail_<slot>_<name>")]`, and `flowsdn-bpf-abi::TailSlot` is the single
source of truth; a build test loads the ELF and asserts every slot the
object uses has a program with that name (replaces BTF `tail:` decl tags,
which aya-ebpf cannot emit).

### 11.2 Tail calls

`#[map] static CALLS: ProgramArray = ProgramArray::with_max_entries(50, 0)`
(renamed per object by the loader, spec 01); invoked as
`unsafe { CALLS.tail_call(&ctx, TailSlot::Ipv4CtEgress as u32) }` — the
index is a compile-time constant so LLVM materialises `r3` as an immediate
and the x86-64 JIT emits a direct jump (the reference's `tail_call_static`
guarantee). The two global policy arrays are `ProgramArray` maps named
`cilium_call_policy` / `cilium_egresscall_policy` with dynamic index
(`ep_id`). A failed tail call falls through to `return
DROP_EP_NOT_READY / DROP_MISSED_TAIL_CALL` exactly as in §2.6. If the
constant-index guarantee cannot be verified in the generated bytecode
(§9.4 dumps the instruction), fall back to `core::arch::asm!` (BPF inline
asm is available on nightly with `asm_experimental_arch`).

### 11.3 Config globals and pruning

`.rodata` constants are `#[no_mangle] static __config_<name>: T` read
through `core::ptr::read_volatile(core::ptr::addr_of!(...))` behind a
`config!(name)` macro. Volatile loads are not CSE'd, so every use is a
distinct `ld_imm64 (map) ; ldx ; jmp` sequence the loader's reachability
pass (spec 01) recognises — the Rust analogue of the reference `CONFIG()`
`ll` asm. Never copy a config value into a local that outlives a branch;
the macro returns by value at the use site.

### 11.4 Copies and checksums

`copy::<const N: usize>(dst: *mut u8, src: *const u8)` implemented with
`read_unaligned/write_unaligned` of `u64/u32/u16/u8` chunks chosen by `N`
at compile time; `zero::<N>`, `eq::<N>` likewise; `#[inline(always)]`.
Non-constant `copy_nonoverlapping`/`copy_from_slice` are forbidden by a
build step that scans the ELF for `memcpy`/`memmove`/`memset`/`memcmp`
call relocations and fails (aya-ebpf ships loop-based fallbacks for these
symbols; they verify but cost unbounded budget). Header structs are read
via `ctx.load::<T>(off)` (`bpf_skb_load_bytes` into a `MaybeUninit<T>` on
the stack) and written with `ctx.store`. Checksums: `bpf_csum_diff`
folding helpers in `csum`, `l3_csum_replace`/`l4_csum_replace` via
`TcContext` methods (exist in aya-ebpf), software fold for XDP.

### 11.5 Stack and verifier hygiene

- Budget 512 B; target ≤ 384 B per program. Large scratch (`ct_buffer`,
  `bpf_fib_lookup`, NAT target, ICMP header build) lives in per-CPU
  `PerCpuArray` maps as in the reference; a `scratch::<T>() -> &mut T`
  helper wraps the lookup.
- No `Option<[u8; N]>`/enums with payload in hot paths (they spill);
  use out-pointers into scratch.
- Loops: only `for i in 0..CONST` with `CONST ≤ 8` (IPv6 ext headers 4,
  SNAT retries 32 is `#[unroll]`-equivalent via a `seq!`-style macro or
  `bpf_loop` when > 8); every loop has a constant bound the verifier sees.
- Bounds: every packet access goes through `ctx.load/store` (helper-based)
  or a checked `data..data_end` window; direct packet access only in XDP.
- Panics: `#[panic_handler]` → `unreachable_unchecked`; `#![deny(clippy::
  indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::
  arithmetic_side_effects)]`; a build step asserts the ELF contains no
  `core::panicking::*` symbol.
- Tails split state: CT lookup → policy → forward are separate programs
  (slots 30/26, 28/13) precisely to reset verifier state as the reference
  does; `#[inline(never)]` subprograms are allowed on the floor kernel
  (§10.3) and are preferred over tails for cold paths (§12.8).

### 11.6 Shared ABI and `no_std`

`flowsdn-bpf-abi` is `#![no_std]`, `#![forbid(unsafe_code)]` except
`zerocopy`/`bytemuck` derives, every struct `#[repr(C)]` (or
`#[repr(C, packed)]` where the reference is packed), with `const _: () =
assert!(size_of::<T>() == N)` for every layout in §4 and §2.7. Userspace
decoders and the BPF programs use the same type, which retires the
reference's `bpf_alignchecker` (spec 01 keeps a BTF cross-check against
the reference `.o` while migration interop matters).

### 11.7 Toolchain pinning

`rust-toolchain.toml` pins one nightly (aya-ebpf needs `-Z build-std=core`
for `bpfel-unknown-none`); `bpf-linker` pinned by exact version in
`Cargo.lock`/`cargo install --locked` and driven with `--cpu v3`
(`-C link-arg=--cpu=v3`) and `--btf` (needed only for map BTF/debug);
`-C debuginfo=2`, `opt-level=3`, `panic=abort`, `lto=fat`. Userspace uses
stable. Both are built on `<build-host>` (cross-project rules); the BPF ELF
is architecture-independent and built once. `-mcpu=v3` is the only ISA
level; no v2 fallback (floor kernel JITs support v3 on both arches).

### 11.8 aya-ebpf coverage and gaps (recalled from aya 0.13 / aya-ebpf 0.1.x; every row is **to-verify** against the pinned version before Phase 2 starts)

| Need | aya-ebpf status | Plan |
|---|---|---|
| Every kernel helper as a raw `unsafe fn` (`aya_ebpf::helpers::gen::bpf_*`, generated from `bpf_helper_defs.h`) | present for helpers in the header version the bindings were generated from; safe wrappers exist for only a few (`bpf_ktime_get_ns`, `bpf_get_prandom_u32`, `bpf_get_smp_processor_id`, probe reads, `bpf_redirect_map`) | wrap the ones we use (`fib_lookup`, `redirect_neigh`, `redirect_peer`, `sk_assign`, `skc_lookup_tcp`, `sk_lookup_udp`, `sk_release`, `skb_set/get_tunnel_key/opt`, `csum_diff`, `get_hash_recalc`, `skb_change_head/type/proto/tail`, `clone_redirect`, `jiffies64`, `map_lookup_percpu_elem`, `set_retval`, `for_each_map_elem`, `loop`) in `flowsdn-bpf::helpers` with typed args; confirm the bindings' header is ≥ 6.1 so `bpf_map_lookup_percpu_elem`/`bpf_set_retval` exist |
| `TcContext`: `load/store`, `l3/l4_csum_replace`, `adjust_room`, `change_type`, `change_proto`, `pull_data`, `clone_redirect`, `set_mark`, `len`, raw `skb` pointer | present | `cb[]`, `tc_index`, `queue_mapping`, `tstamp`, `ingress_ifindex`, `protocol` via the raw `__sk_buff` pointer (writable fields per the kernel) |
| `XdpContext`: `data/data_end/metadata` | present | metadata pointer for `XFER_*` |
| Map types: `HashMap`, `LruHashMap`, `PerCpuHashMap`, `LruPerCpuHashMap`, `Array`, `PerCpuArray`, `LpmTrie`, `ProgramArray`, `PerfEventArray`, `RingBuf` | present | `PerfEventArray::output` flags width: the `(cap_len << 32)` trick needs a `u64` flags argument — if the wrapper takes `u32`, call `bpf_perf_event_output` raw |
| `ARRAY_OF_MAPS` / `HASH_OF_MAPS` (Maglev, per-cluster CT/NAT, multicast) | **gap**: no map-in-map types in aya-ebpf (and legacy `maps`-section defs carry no inner spec) | declare a `#[repr(C)] bpf_map_def` static with the outer type in the `maps` section, look up with raw `bpf_map_lookup_elem` and cast the result to the inner map handle; the inner spec is supplied by the loader (spec 01). M2/M3 only |
| BTF-defined maps (`.maps` section, `pinning`, `__array(values)`) | **gap**: aya-ebpf emits legacy `bpf_map_def` in `maps`; pinning is a loader decision (`EbpfLoader::map_pin_path`) | acceptable: spec 01 owns pinning; map names are all the ELF needs to carry |
| `bpf_tail_call` with constant index → direct JIT jump | `ProgramArray::tail_call(ctx, idx)` is present; constant propagation is LLVM's | verify by disassembly in CI (§9.4); asm fallback (§11.2) |
| Inline BPF asm | rustc supports `asm!` on `target_arch = "bpf"` behind `asm_experimental_arch` (nightly) | available since we are on nightly anyway |
| `#[classifier]`, `#[xdp]`, `#[cgroup_sock_addr(connect4/6, sendmsg4/6, recvmsg4/6, getpeername4/6, bind4/6)]`, `#[cgroup_sock(post_bind4/6, sock_release)]` | present | |
| `iter/tcp`, `iter/udp` programs and kfunc `bpf_sock_destroy` (`.ksyms` relocation) | **gap/unknown**: `#[iter]` exists for task iterators at most; no kfunc declaration mechanism in aya-ebpf | M3; if still missing, implement kfunc relocation in `aya-obj` (upstream) or defer socket termination |
| `.rodata` globals patched by the loader (`EbpfLoader::set_global`) | present (matches by symbol name in `.rodata`/`.data`) | ensure statics land in `.rodata` (immutable `static`, not `static mut`) |
| Per-CPU aux data (`.data.aux` stride) | not modelled | use `PerCpuArray` scratch instead (§11.5) — **DEVIATION**, equivalent semantics |
| Loop-based `memcpy/memset` fallback symbols | present | banned by build check (§11.4) |
| BTF emission for maps/debug | `bpf-linker --btf` | optional in M1 |
| Bounded-loop and `bpf_loop` friendliness of Rust codegen | LLVM may rotate/unroll loops unpredictably | keep loop bodies tiny; CI verifier gate |

Gaps are recorded in the datapath work log and fixed upstream where
possible (ADR-0002).

### 11.9 Program-array population and object bundle

The loader (spec 01) reads `flowsdn-bpf-abi::TailSlot` + program names to
fill `cilium_calls`; per-endpoint objects are the same `lxc` ELF with
`.rodata` patched and maps renamed; the `host` ELF is loaded once per
attached device with `interface_ifindex`/`interface_mac`/`eth_header_length`
patched. All seven ELFs are embedded in the agent binary
(`include_bytes_aligned!`) so the node never sees a compiler or an object
file (ADR-0001).

---

### Identity scope classification

**Resolved (#66, ADR-0011):** local CIDR identity classification MUST follow
[spec 03 §4.5](03-identity-ipcache.md#45-bit-layout-and-clustermesh-ranges):
classify by the high scope byte for the supported nonzero-index identities,
including values above `0x0100_FFFF`. Do not cap classification at 65,535.
Local scoped identities are never encoded into identity marks or tunnel VNIs.
This is a documented deviation from the reference datapath bound, not a
claim that the full packet path has been validated.

## 12. Open decisions

1. **Resolved policy (#53): single object per hook family first.** The
   normative §6.2 default already selects runtime configuration plus pruning;
   §9.4 permits measured promotion to feature variants above 800,000
   instructions or 480 B stack on the floor kernel. Keep one BPF object shared
   by both architectures for each selected hook family/variant. ADR-0002
   explicitly delegates variant count here; its cross-architecture object
   requirement does not prohibit measured feature variants. No matrix or
   promotion dimension is selected before measurements, and no passing
   verifier measurements are claimed by this resolution.
2. **Resolved kernel floor (#54): 6.6 general minimum, 6.12 supported line.**
   The kernel roll-up fixes these targets for both architectures; this replaces
   the older 6.1 recommendation. Required features are checked at startup;
   missing tcx is a refusal, not a reason to attach via clsact. Preserve
   supported-kernel takeover cleanup and feature-specific gates. The remaining
   work is implementation and privileged validation, not another user decision
   between the superseded kernel recommendations.
3. **Wire compatibility with Cilium nodes — resolved (#55).** Use identical
   VXLAN/Geneve identity encoding, default ports, HOST rewrite, WORLD
   collapse and Geneve DSR TLV (§2.5). ADR-0001 boundary compatibility and
   spec 03's frozen identity allocation already select this policy; no
   private identity option or renumbering is introduced. Node-by-node
   migration remains the goal. Fixed wire codecs are not evidence of
   mixed-cluster forwarding: that requires packet-path integration and
   bidirectional identity/DSR tests against reference nodes. Any future
   private cluster mode requires a separate explicit decision.
4. **Resolved #56: BPF host routing only.** Reject legacy host routing;
   retain BPF endpoint-route delivery for IPAM modes requiring it. Preserve
   `enable_bpf_host_routing=true` in comparable rodata dumps until a separately
   reviewed ABI cleanup; do not remove it automatically after an unspecified
   release. FIB errors drop visibly instead of silently falling back to the
   stack. The validation/delivery plan is implemented in `flowsdn-encryption`;
   full host pipeline and provider endpoint-route tests remain required.
5. **Resolved (#57, ADR-0011): retain `PERF_EVENT_ARRAY`.**
   The monitor map and per-CPU framing follow spec 01 §3.10. No ring-buffer
   migration is implied by the current service milestone.
6. **Resolved (#58, ADR-0011): per-endpoint lxc objects for policy.**
   Preserve per-endpoint policy maps and rodata as specified in spec 01 §3.7.
   The shared initial local-delivery program is a foundation primitive, not
   evidence that the production policy-object contract has changed.
7. **Resolved (#59, ADR-0011): veth is the default pod device.**
   Netkit remains an explicit optional mode, gated on kernel support and
   successful feature probes (supported gate at least 6.8); it does not raise
   the general 6.6 minimum. Runtime validation of netkit remains outstanding.
8. **Resolved (#60, ADR-0011): preserve the specified tail-call slots.**
   Subprograms may implement internal cold helpers without replacing observable
   slot/error contracts. Moving a CT→policy edge requires later verifier and
   stack measurements on both architectures; no such optimization is assumed.
9. **Resolved (#61, ADR-0011): retain `cilium_*` map and pin names.**
   Spec 01 §2–3 owns the names and directories used by diagnostic tools.
   Compatible names alone do not establish safe live takeover.
10. **Resolved (#62): drop expired forwarding packets in M1.** IPv4 TTL
    and IPv6 hop limit of 0 or 1 must produce `TC_ACT_SHOT` before decrement
    can wrap; do not generate an ICMP error in the initial datapath. This
    retains the reference expiry-drop behavior. ICMP time-exceeded generation
    remains M2 work, requiring routing, rate limiting and packet-builder tests.
    `local_delivery::rewrite` implements both expiry checks and native routing
    shares that delivery helper. The endpoint kernel fixture tests both 0 and
    1 for IPv4 and IPv6 (`bpftest/src/bin/endpoint/packets.rs`); it does not
    establish ICMP generation or full production-path coverage.
11. **Resolved #63: debug events are an explicit build dimension.**
    Select `debug-events` only for diagnostic BPF objects; ordinary release
    objects exclude it and `test-hooks`. `cilium-dbg monitor --type debug`
    requires a debug build. `ObjectBuild` validates the release selection and
    names requested Cargo features. The present BPF crate has not implemented
    debug event instrumentation; this plan does not create an empty feature
    or claim those objects exist. Before delivery, wire the feature to actual
    emit sites and verify event presence/absence, object size and verifier
    acceptance on both architectures. Trace/drop compatibility is separate.

### Pinned helper audit (#254, 2026-09-22)

The BPF lockfile pins `aya-ebpf 0.2.1` and `aya-ebpf-bindings 0.2.0`.
All §11.8 helpers exist as raw `aya_ebpf::helpers::bpf_*` bindings in both
x86_64 and aarch64 generated modules. `crates/flowsdn-bpf/src/helper_coverage.rs`
is compiled with both project BPF binaries to guard symbol availability.
No hand-written helper-ID wrapper or assembly is needed for these rows.

| Helper | Generated helpers.rs line (both architectures) |
|---|---:|
| `bpf_fib_lookup` | 675 |
| `bpf_redirect_neigh` | 1547 |
| `bpf_redirect_peer` | 1579 |
| `bpf_sk_assign` | 1277 |
| `bpf_skc_lookup_tcp` | 985 |
| `bpf_sk_lookup_udp` | 862 |
| `bpf_sk_release` | 878 |
| `bpf_skb_set_tunnel_key` | 185 |
| `bpf_skb_get_tunnel_key` | 171 |
| `bpf_skb_set_tunnel_opt` | 283 |
| `bpf_skb_get_tunnel_opt` | 271 |
| `bpf_csum_diff` | 255 |
| `bpf_get_hash_recalc` | 324 |
| `bpf_skb_change_head` | 384 |
| `bpf_skb_change_type` | 307 |
| `bpf_skb_change_proto` | 295 |
| `bpf_skb_change_tail` | 354 |
| `bpf_clone_redirect` | 120 |
| `bpf_jiffies64` | 1219 |
| `bpf_map_lookup_percpu_elem` | 1974 |
| `bpf_set_retval` | 1887 |
| `bpf_for_each_map_elem` | 1654 |
| `bpf_loop` | 1830 |

This verifies the required post-6.1 interface symbols directly instead of
inferring coverage from an undocumented header-version label. Raw bindings are
unsafe and program-type restricted: use context-aware wrappers where available,
validate pointer lifetimes and verifier constraints at each call site. Symbol
availability does not establish kernel helper support or verifier acceptance;
#3, #256 and #257 retain those runtime obligations. The historical recalled
0.13/0.1.x table is superseded by this locked-source audit.
