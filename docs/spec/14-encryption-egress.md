# Transparent encryption (WireGuard, IPsec), egress gateway and ip-masq-agent — specification

Status: draft. Derived from: `docs/inventory/14-encryption-egress.md` (primary),
`docs/inventory/13-crds-k8s.md` (CiliumEgressGatewayPolicy schema, CiliumNode
fields), `docs/kernel-requirements.md` (§1 WireGuard/IPsec/egress rows, §2.6
config fragment, §4.3 sysctls, §4.4 netlink families); reference cilium v1.20.1
(7d68cfb394) paths `pkg/wireguard/{agent,types,fake}/`,
`pkg/datapath/linux/ipsec/`, `pkg/datapath/linux/ipsec.go`,
`pkg/datapath/linux/node_ids.go`, `pkg/common/ipsec/`, `pkg/maps/{encrypt,nodemap}/`,
`pkg/egressgateway/`, `pkg/maps/egressmap/`, `pkg/ipmasq/`, `pkg/maps/ipmasq/`,
`bpf/bpf_wireguard.c`, `bpf/lib/{wireguard,encrypt,ipsec,egress_gateway}.h`,
`Documentation/security/network/encryption*.rst`,
`Documentation/network/egress-gateway/`. Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes *what*
flowsdn does and the exact data it exchanges with the kernel, the cluster and its
peers. It does not transcribe reference code. Where reference behavior is kept for
compatibility the consumer is named (kernel, peer nodes running the reference,
cilium-dbg, Hubble, operator, clustermesh peers). Where flowsdn deviates the
paragraph is marked **DEVIATION** with the reason and the ADR.

Sibling specs, referenced rather than duplicated:

- `01-bpf-map-abi-loader.md` — map ABI and pinning for `cilium_encrypt_state`,
  `cilium_node_map_v2`, `cilium_egress_gw_policy_v4`/`_v4_v2`/`_v6`,
  `cilium_ipmasq_v4`/`v6`; `.rodata` config patching; the `bpf_wireguard` object
  and its `cilium_calls_wireguard_<ifindex>` tail-call map.
- `02-datapath-programs.md` — §2.1 mark values and masks, §3 the encrypt/decrypt
  hooks inside `to_netdev`/`from_netdev`/`from_overlay`, `from_wireguard`,
  `to_wireguard`, the egress-gateway hooks, and the M3 milestone assignment for
  all of them. **All BPF program behavior in this area is specified there**; this
  spec specifies only the userspace control plane and the exact data it puts in
  the maps and in the kernel's XFRM and WireGuard state.
- `03-identity-ipcache.md` — `remote_endpoint_info.key` (the encryption key index
  an ipcache entry carries), the `TunnelPeer`/`EncryptKey` metadata sources, and
  the `reserved:remote-node` / `reserved:host` identities the encrypt hooks test.
- `04-conntrack-nat.md` — §3.12 the masquerade decision, which contains both the
  egress-gateway hook ordering and the `cilium_ipmasq_v{4,6}` lookup; §3.11 SNAT
  port allocation, which bounds egress-gateway connection counts.
- `10-node-routing-nftables.md` — route table 200 and ip rule priority 1 for
  IPsec, the node model and `CiliumNode` publication, node ID allocation and
  `cilium_node_map_v2` ownership, the MTU table, the sysctl reconciler, and the
  encryption-related nftables residual (`notrack` on the encrypt/decrypt marks
  and on UDP 51871).
- `00-foundation-table-config.md` — the table crate, the generic reconciler, the
  config registry and the `Fence` startup barrier used throughout §3.

## 1. Scope

### 1.1 In scope

1. **WireGuard transparent encryption**: the `cilium_wg0` device, key material,
   public-key publication, peer and AllowedIPs management, node-to-node
   encryption, MTU, and both strict modes.
2. **IPsec transparent encryption**: the key file, SPI management and rotation,
   per-node-pair key derivation, the complete XFRM state/policy set, the ip rule
   and route table that make it work, encrypted overlay, and XFRM cleanup.
3. **Node IDs and the encrypt map**: allocation, restore and the datapath's
   peer→key resolution. (Allocation *mechanics* are owned by spec 10 §3.3.5;
   this spec specifies what encryption requires of them and what it writes.)
4. **Egress gateway**: the `CiliumEgressGatewayPolicy` CRD, the compilation from
   policies plus endpoints to egress-map entries, gateway selection, egress IP
   derivation, reconciliation and the feature's hard requirements.
5. **BPF ip-masq-agent**: config file, watch/reload, CIDR semantics.

### 1.2 Out of scope

| Excluded | Where it lives |
|---|---|
| Every BPF program body and hook ordering | spec 02 (milestone M3) |
| BPF map ABI, pinning, sizing, loader | spec 01 |
| Node ID allocator mechanics, table 200 routes, ip rules, MTU table, nftables residual | spec 10 |
| The masquerade decision that consults the egress and ip-masq maps | spec 04 §3.12 |
| Identity allocation and ipcache writes | specs 03, 06 |
| CRD client/watch plumbing and CRD registration | `13-crds-k8s-client.md` |
| Helm chart rendering and image packaging | packaging spec (wave 4); inventory 15 |
| **VTEP** integration | **deferred** (inventory 14 recommendation: beta, IPv4-only, niche). The `cilium_vtep_map` ABI is reserved in spec 01; no control plane is written. |
| **SRv6** | **deferred** (inventory 14: OSS ships maps and BPF only, with no control plane to mirror). Revisit with `15-bgp.md` if a BGP/VRF integration lands. |
| **ztunnel** (`encryption.type=ztunnel`) | `16-l7-envoy-dns.md` (L7/mesh); it is a per-node L4 mTLS proxy, not transparent encryption in the sense of this spec. |

### 1.3 Milestone placement

Everything in this spec is **M3** in spec 02's milestone scheme. Build order
within M3, from inventory README §build order item 9 and the risk assessment in
inventory 14: **WireGuard → egress gateway → ip-masq-agent → IPsec**. IPsec is
last because XFRM reconciliation and key rotation carry the most risk of silent
plaintext, and because WireGuard exercises every shared mechanism (node handler,
ipcache subscription, encrypt key publication, MTU) at a fraction of the
complexity.

## 2. Compatibility contract

These are the interfaces flowsdn MUST match bit-for-bit, with the consumer that
depends on each. Everything not listed is free.

### 2.1 Wire formats (peer nodes, which may run the reference)

| Item | Value | Consumer |
|---|---|---|
| WireGuard UDP port | **51871**, fixed, not configurable | peer nodes; firewall/SG rules; Hubble's `ctx_is_wireguard` heuristic (`sport == dport == 51871`) |
| WireGuard device fwmark | `0x0E00` (`MARK_MAGIC_ENCRYPT`) | the local datapath, to recognise already-encrypted egress |
| IPsec transport | ESP (IP proto 50), `mode tunnel`, `reqid 1` | peer nodes; cloud security groups |
| IPsec SPI on the wire | 1..15 | peer nodes; `IPsecMaxKeyVersion = 15` |
| IPsec cipher suites | `rfc4106(gcm(aes))` AEAD, or `<auth-algo>` + `<enc-algo>` pair (e.g. `hmac(sha256)` + `cbc(aes)`) | peer nodes; both sides derive the same per-pair key |
| Encapsulation inside encryption | tunnel mode: VXLAN/Geneve inside WireGuard; IPsec + tunnel: VXLAN/Geneve inside ESP ("encrypted overlay") | peer nodes |
| Egress-gateway redirect | VXLAN/Geneve to the gateway node carrying the source identity in the VNI, **even in native routing** | gateway node |

### 2.2 Kubernetes objects and files

| Item | Exact form | Consumer |
|---|---|---|
| CiliumNode WireGuard public key | annotation `network.cilium.io/wg-pub-key` (legacy alias `io.cilium.network.wg-pub-key` read, never written); `Node.WireguardPubKey`, base64 | peer agents, clustermesh |
| CiliumNode encryption key | `spec.encryption.key` (u8) and annotation `network.cilium.io/encryption-key`; `0xFF` for WireGuard, the active SPI for IPsec, `0` when off or opted out | peer agents; written by spec 10 §3.3 |
| CiliumNode boot ID | `spec.bootid`, from `/proc/sys/kernel/random/boot_id` | peer agents (IPsec per-pair key derivation) |
| IPsec key file | mounted from secret `cilium-ipsec-keys`, key `keys`, at `/etc/ipsec/keys` (Helm `encryption.ipsec.{secretName,keyFile,mountPath}`) | the cluster administrator's rotation procedure |
| WireGuard private key | `<state-dir>/cilium_wg0.key`, 32 raw bytes, mode `0600` | this node only; survives agent restart |
| ip-masq-agent config | file `ip-masq-agent` under `--ip-masq-agent-config-path` (default dir `/etc/config`), YAML **or** JSON with keys `nonMasqueradeCIDRs`, `masqLinkLocal`, `masqLinkLocalIPv6` | ConfigMap authors; identical to the upstream `ip-masq-agent` schema |
| `CiliumEgressGatewayPolicy` | `cilium.io/v2`, cluster-scoped, kind `CiliumEgressGatewayPolicy`, plural `ciliumegressgatewaypolicies`, short `cegp`, categories `cilium,ciliumpolicy`, **no status subresource**, printer column `Age` | users, GitOps, `cilium-dbg` |

### 2.3 BPF maps (ABI owned by spec 01 §4; this spec owns the contents)

| Map | Key → value | Written by |
|---|---|---|
| `cilium_encrypt_state` | `u32 (== 0)` → `encrypt_config{ encrypt_key u8 }` | IPsec agent (§3.2.7) |
| `cilium_node_map_v2` | `node_key`(20) → `node_value{ id u16, spi u8, pad u8 }` | node ID allocator (spec 10 §3.3.5); SPI supplied by this spec |
| `cilium_egress_gw_policy_v4` (v1, deferred) | `egress_gw_policy_key`(12) → `egress_gw_policy_entry`(8) | egress gateway (§3.4) |
| `cilium_egress_gw_policy_v4_v2` | `egress_gw_policy_key`(12) → `egress_gw_policy_entry_v2`(28) | egress gateway |
| `cilium_egress_gw_policy_v6` | `egress_gw_policy_key6`(36) → `egress_gw_policy_entry6`(40) | egress gateway |
| `cilium_ipmasq_v4` / `_v6` | `{prefixlen u32, addr}` → `{pad u8}`, LPM, 16384, `NO_PREALLOC` + `RDONLY_PROG` | ip-masq-agent (§3.5) |

### 2.4 Packet marks, masks and route tables

Defined normatively in spec 02 §2.1 and spec 10 §4.2; repeated here only where
this spec is the writer.

| Name | Value | Mask(s) used with it | Owner |
|---|---|---|---|
| `MARK_MAGIC_ENCRYPT` | `0x0E00` | `0x0F00` magic; `0xFF00` with the SPI in bits 12..15; `0xFFFFFF00` in XFRM OUT | WireGuard device fwmark; IPsec OUT state/policy |
| `MARK_MAGIC_DECRYPT` | `0x0D00` | `0x0F00`; `0xFFFF0F00` in XFRM IN | IPsec IN state; WireGuard `from_wireguard` |
| node ID in a mark | bits 16..31 | `0xFFFF0000` (`IPsecMarkMaskNodeID`) | IPsec |
| IPsec SPI in a mark | bits 12..15 | shift `12` (`IPsecXFRMMarkSPIShift`) | IPsec |
| XFRM OUT mark mask | `0xFFFFFF00` (`IPsecMarkMaskOut` = `0xFF00 \| 0xFFFF0000`) | — | IPsec |
| XFRM IN mark mask | `0xFFFF0F00` (`IPsecMarkMaskIn` = `0x0F00 \| 0xFFFF0000`) | — | IPsec |
| XFRM output-mark mask | `0xFFFFFF00` (`OutputMarkMask`) | clears node ID and SPI | IPsec |
| FWD policy priority | `0x0B9F` (`IPsecFwdPriority`, 2975) | — | IPsec |
| Route table / rule | table **200**, ip rule priority **1**, `fwmark 0x0D00/0x0F00` | — | spec 10 §3.2.4 installs; this spec requires |
| `MARK_MAGIC_EGW_DONE` | `0x0500` | `0x0F00` | egress gateway datapath (spec 02) |

`MagicMarkDecryptedOverlay = 0x1D00` is **defined but unused** at the reference
tag (no BPF or Go consumer). flowsdn MUST NOT emit it and MUST NOT reserve
behavior for it; the value is recorded here so the 0x1000 bit is not reused.
**DEVIATION** (documentation only): spec 02 §2.1's mark table does not list it;
this spec is the authority that it is dead.

### 2.5 Drop and trace codes

| Code | Name | Emitted when |
|---|---|---|
| 160 | `DROP_NO_TUNNEL_ENDPOINT` | egress-gateway redirect with no tunnel endpoint for the gateway |
| 194 | `DROP_NO_EGRESS_GATEWAY` | policy matched, `gateway_ip == 0.0.0.0` |
| 195 | `DROP_UNENCRYPTED_TRAFFIC` | strict mode egress or ingress |
| 197 | `DROP_NO_NODE_ID` | IPsec encrypt with no `cilium_node_map_v2` entry for the peer |
| 204 | `DROP_NO_EGRESS_IP` | gateway-side SNAT with `egress_ip == 0.0.0.0`/`::` |

Trace: `TRACE_FROM_CRYPTO` and `TRACE_TO_CRYPTO` observation points, and the
`ENCRYPTED` flag (bit 7 of `trace_notify.reason`). Hubble depends on all three.

### 2.6 Agent API and CLI

`GET /healthz` field `encryption` (spec 08 §4.6, 5 s probe):
`{mode: Disabled|IPsec|Wireguard|Ztunnel, msg, ipsec{...}, wireguard{...}}`.
`WireguardStatus` = `{node-encryption: Enabled|Disabled|OptedOut,
node-encrypt-opt-out-labels, interfaces[]{name, listen-port, public-key,
peer-count, peers[]{public-key, endpoint, last-handshake-time, allowed-ips[],
transfer-tx, transfer-rx}}}`. `cilium-dbg encrypt status` and `encrypt flush`,
`cilium-dbg bpf egress list`, and `cilium-dbg bpf nodeid list` MUST keep their
field names.

## 3. Behavior

### 3.1 WireGuard

#### 3.1.1 Device lifecycle

When `enable-wireguard` is false the agent MUST delete a leftover `cilium_wg0`
link at startup (best effort, errors logged and ignored) and do nothing else.

When enabled, startup MUST proceed in this order, holding the module's write lock:

| # | Step | Failure |
|---|---|---|
| 1 | Load or generate the private key (§3.1.2) | fatal |
| 2 | Compute a provisional link MTU (§3.1.6) | non-fatal; fall back to `EthernetMTU (1500) − 95` |
| 3 | `RTM_NEWLINK` kind `wireguard`, name `cilium_wg0`, MTU from step 2 | `EEXIST` → reuse the existing device; `EOPNOTSUPP` → **fatal** with a message that names the kernel: WireGuard is not supported, upgrade the kernel or install the module; any other errno → fatal |
| 4 | `net.ipv4.conf.cilium_wg0.rp_filter = 0` (only when `enable-ipv4`) | fatal |
| 5 | Open a generic-netlink handle for the `wireguard` family | fatal |
| 6 | Configure the device: private key, `listen_port = 51871`, `fwmark = 0x0E00`, **no** peer replacement, empty peer list | fatal |
| 7 | `RTM_SETLINK` up | fatal |

No routes, no ip rules and no IPv6 sysctls are created for the device. Steps 4
and 6 MUST both happen before step 7 so the device never carries traffic
without its fwmark.

Shutdown MUST unsubscribe from the node manager **before** closing the netlink
handle, so no in-flight node-validation callback can configure a closed device.
The link is **not** deleted on a clean shutdown; only a start with the feature
disabled removes it.

#### 3.1.2 Key material

The private key lives at `<state-dir>/cilium_wg0.key` as **32 raw bytes**
(not base64) with mode `0600`.

| Condition | Action |
|---|---|
| File absent | Generate a Curve25519 private key, write it `0600`, use it |
| File present, exactly 32 bytes | Use it verbatim. flowsdn MUST NOT clamp or re-derive it |
| File present, wrong length or unreadable | **Fatal.** No regeneration, no repair |

The last row is deliberate: silently generating a new key would change the
node's public key, and every peer would have to relearn it — under
node-to-node encryption that is exactly the bootstrap lock-out §3.1.7 exists
to avoid. An operator who wants a new key deletes the file.

#### 3.1.3 Public-key publication

Before node discovery starts (a `Fence`, spec 00), the module MUST set on
`LocalNode`, synchronously:

- `EncryptionKey = 0xFF` (`StaticEncryptKey`),
- `WireguardPubKey` = base64 of the public key,
- annotation `network.cilium.io/wg-pub-key` = the same string.

Spec 10 §3.3.4 then copies the annotations onto the `CiliumNode` and writes
`spec.encryption.key`. The public key travels as an **annotation**, never as a
spec field; the alias `io.cilium.network.wg-pub-key` MUST be accepted on read
and MUST NOT be written.

`0xFF` is a sentinel, not a key index. The datapath tests only
`remote_endpoint_info.key != 0`; for WireGuard the value carries no
information. Two consequences flowsdn MUST reproduce, because peers depend on
them:

- The **endpoint** encrypt-key for health and ingress IPs of a node is always
  `0xFF` when WireGuard is on, **even for a node that published
  `EncryptionKey = 0`** through the opt-out. Pod-to-pod stays encrypted
  regardless of the node-encryption opt-out.
- A remote node's key is honored for *node* traffic only when node encryption
  is enabled **and** the local node has not opted out.

#### 3.1.4 Peer construction

`NodeAdd`, `NodeUpdate` (new node only) and the periodic
`NodeValidateImplementation` all funnel into one upsert. The upsert MUST be a
no-op for the local node and for any node with an empty public key. `NodeDelete`
deletes the peer. Failures MUST be logged at warn and MUST NOT propagate: one
unreachable peer must not fail node processing, and the periodic validation is
the retry.

Upsert steps, in order:

1. Acquire the ipcache read lock **before** the module lock whenever the
   ipcache is consulted (§3.1.5). The ipcache calls into this module while
   holding its own lock; the reverse order deadlocks.
2. Parse the public key. Reject the **all-zero key** with an explicit error:
   it is reserved for the removal workaround in §3.1.5 and a node claiming it
   would let that node steal every AllowedIP.
3. **Duplicate key**: if the key is already mapped to a different node name,
   fail with an error naming both nodes and change nothing.
4. **Changed key**: delete the old peer first, then rebuild from scratch.
5. **New peer**: seed AllowedIPs from the ipcache when §3.1.5 requires it.
6. **Node IP changed** in either family: drop the reverse index entry and
   queue the old `/32` or `/128` for removal.
7. **Always** include the peer's own node IPs as AllowedIPs — `nodeIPv4/32`
   when IPv4 is enabled, `nodeIPv6/128` when IPv6 is — in **every** routing
   mode and irrespective of node encryption. Without them the peer cannot be
   selected at all.
8. **Endpoint address**, first match wins:
   - tunnel mode **and** an IPv6 underlay **and** IPv6 enabled **and** the node
     has an IPv6 → `[v6]:51871`;
   - else IPv4 enabled and present → `v4:51871`;
   - else IPv6 enabled and present → `[v6]:51871`;
   - else error.
   IPv6 is preferred **only** in the tunnel + IPv6-underlay case.
9. Apply to the kernel (§3.1.5).
10. **Only on success**, update the three indices: by node name, by public key,
    by node IP.

`wireguard-persistent-keepalive` (duration, default `0` = off) is set on every
peer configuration written, and MUST NOT be set on a removal or on the dummy
peer.

#### 3.1.5 AllowedIPs and the removal workaround

**Which entries contribute.** The module consults the ipcache only when

```
!tunnel_mode || wireguard-track-all-ips-fallback
```

- **Native routing**: subscribe to the ipcache. Every ipcache entry whose
  recorded host IP equals one of a peer's node IPs contributes its prefix
  (remote pod IPs, remote health and ingress IPs — everything with a host IP).
  Entries without a host IP never contribute; the node IPs themselves come from
  §3.1.4 step 7.
- **Tunnel routing**: do not subscribe and do not query. Only node IPs are
  AllowedIPs, because what crosses WireGuard is a VXLAN/Geneve packet between
  node IPs. This is **overlay-in-WireGuard** (§3.1.8).
- `wireguard-track-all-ips-fallback` (bool, default false, **hidden**) forces
  the native behavior in tunnel mode. It is an escape hatch, not a documented
  option.

**Incremental state.** Each peer holds three prefix sets: `allowed` (believed
to be on the device), `pending_insert`, `pending_remove`. Queueing a prefix for
insert MUST remove it from `pending_remove` and vice versa, so queueing is
idempotent and last-write-wins per prefix. A queue is drained only after the
kernel accepted the change; a failed apply leaves the queue intact for the next
`NodeValidateImplementation` pass. This is the whole recovery mechanism — there
is no separate retry loop.

**Applying a diff.** Exactly two netlink operations, in this order:

1. **Additions** (skipped when empty): one device configuration with
   `replace_peers = false` and a single peer entry carrying only the added
   prefixes. Because the per-peer replace-allowed-ips flag is **not** set, this
   is purely additive.
2. **Removals** (skipped when empty), the **dummy-peer workaround**:
   a. Configure a peer whose public key is the **all-zero key**, with the
      removed prefixes as its AllowedIPs and **no endpoint**. The WireGuard
      netlink API lets a peer take an AllowedIP from another simply by claiming
      it, so this detaches the prefixes from the real peer in one message.
   b. Delete the all-zero peer, which takes the claimed prefixes with it.

Additions MUST precede removals so a prefix moving between peers is never
briefly absent.

**Why not replace-all.** The WireGuard netlink API has no per-IP removal. The
alternative is the per-peer replace-allowed-ips flag, which wipes the list and
rebuilds it **non-atomically**: during the window the transmit path finds no
peer for those prefixes and drops packets, surfacing as `EHOSTUNREACH` from
`send`/`sendto`. The dummy peer bounds the window to two netlink messages, and
because it has no endpoint a packet that matches it during the window is
undeliverable rather than misrouted. This does not eliminate the drop window —
upstream issue **GH-33159** remains open — and flowsdn inherits it. §12 records
the option of closing it.

**Ipcache events.** The change callback runs with the ipcache lock held, so it
MUST take only the module lock and MUST NOT call back into the ipcache.

| Event | Condition | Action |
|---|---|---|
| Delete with an old host IP | that host IP maps to a known peer and the peer currently has the prefix | queue remove |
| Upsert with a new host IP | that host IP maps to a known peer and the peer does not have the prefix | queue insert |
| anything else | — | ignore |

Ignoring is safe: the upsert path re-seeds from the ipcache when a node first
becomes known. The event's encrypt key MUST be ignored here — it is a datapath
concern, and a node that opted out simply never publishes a public key.

#### 3.1.6 MTU

`WireguardOverhead = 95` (spec 10 §3.5 owns the MTU table and the full formula).

```
link_mtu = DeviceMTU − 95
if enable-ipv6 and link_mtu < 1280:  link_mtu = 1280   # log a warning
```

The 1280 clamp is required because the kernel refuses to bring up `inet6_dev`
below the IPv6 minimum and then silently discards all IPv6 reception. The clamp
applies in the reconciler; the provisional value computed at device creation
(§3.1.1 step 2) MAY skip it.

A **reconciler task** MUST follow the MTU table (spec 00 watch stream), read the
device's current MTU and issue `RTM_SETLINK` only when it differs, with
exponential backoff (100 ms → 1 min) on failure, reporting into the health
registry (`OK (<mtu>)` / degraded). Route MTU for pods is spec 10's
`RoutePostEncryptMTU` and the WireGuard branch of its formula takes precedence
over the IPsec branch.

In tunnel mode pod traffic is encapsulated **twice** (overlay, then WireGuard);
the route MTU subtracts both. Under CNI chaining the pod-facing MTU must be set
explicitly or pod traffic fragments.

#### 3.1.7 Node-to-node encryption and the opt-out

`encrypt-node` (default false, beta) additionally encrypts node→node,
pod→node and node→pod traffic. It sets the `enable_node_encryption` datapath
config (spec 02 §6) and changes three things in the encrypt hook (§3.1.9):
`HOST_ID` sources are no longer excluded, the proxy-mark bypass is compiled
out, and the ICMPv6 NA exclusion is compiled in.

**Opt-out.** `node-encryption-opt-out-labels`, a label selector, default
`node-role.kubernetes.io/control-plane`. A parse failure is fatal. The opt-out
applies **only when `encrypt-node` is true** and the selector matches the local
node's labels. Its effects:

- the local node publishes `EncryptionKey = 0`, so peers do **not** encrypt
  node traffic to it;
- the public key is still published, so **pod** traffic to and from the node
  stays encrypted;
- the local node also stops encrypting node traffic **towards** remote nodes;
- status reports `NodeEncryption: OptedOut`.

The reason is a bootstrap lock-out: with node encryption on, the connection a
node uses to publish a *new* public key would itself be encrypted with the
*old* one. A node that regenerates its key after a reboot or reprovision could
never announce it. Setting the selector to empty forces control-plane nodes in
and is documented as not recommended.

#### 3.1.8 Interaction with tunnel mode

| Routing mode | What crosses `cilium_wg0` | AllowedIPs needed | Name |
|---|---|---|---|
| Native | the pod-to-pod IP packet, with the source identity in `skb->mark` | node IPs **and** every remote pod prefix | WireGuard carries pod traffic directly |
| Tunnel | the finished VXLAN/Geneve packet between node IPs | node IPs only | **overlay-in-WireGuard** |

There is no "WireGuard-in-overlay" configuration: the encrypt hook in
`to_netdev` redirects an overlay-marked packet (`MARK_MAGIC_OVERLAY`) to
`cilium_wg0` **unconditionally**, before any ethertype, ipcache or policy check,
precisely so the encapsulated packet — which already carries the source identity
in its VNI — is what gets encrypted. The consequences are double encapsulation
(§3.1.6) and the fact that in tunnel mode the ipcache is not consulted at all
for AllowedIPs.

**Contrast with IPsec** (§3.2.6): IPsec in tunnel mode uses *encrypted overlay*,
a separate XFRM policy/state pair matching the node-IP pair, which achieves the
same "identity is encrypted on the wire" property by a different mechanism.

#### 3.1.9 What the datapath does (summary; normative text in spec 02)

Egress, in `to_netdev`, after the host-firewall, egress-gateway, bandwidth and
IPsec blocks and **before** the strict-mode check and `handle_nat_fwd`:

1. If the packet already carries `MARK_MAGIC_ENCRYPT` (the device's fwmark),
   skip the hook and mark the trace `ENCRYPTED`. Without this the path
   `netdev → cilium_wg0 → netdev` loops forever.
2. Tunnel mode: `MARK_MAGIC_OVERLAY` → redirect to `cilium_wg0`, unconditionally.
3. Unsupported ethertype → drop.
4. Under node encryption only: an **ICMPv6 Neighbour Advertisement is never
   sent over `cilium_wg0`** — the device is point-to-point and `NOARP`, so no
   neighbor entry could form. It passes in clear.
5. Look up the destination in the ipcache; resolve an unknown source identity
   from the ipcache too. A **lookup miss passes the packet in clear** — this is
   the propagation-window gap in §3.1.11.
6. Without node encryption only: `MARK_MAGIC_PROXY_INGRESS` and
   `MARK_MAGIC_SKIP_TPROXY` bypass the source-policy check, so all proxy
   traffic is encrypted. `MARK_MAGIC_PROXY_EGRESS` is deliberately *not*
   listed: its source identity is already trustworthy and passes normally.
7. Source policy: encrypt only if the source is a **cluster** identity, is not
   a **remote-node** identity, and (without node encryption) is not `HOST_ID`.
8. Encrypt iff the destination ipcache entry exists **and** its `key != 0`.
   Stamp the source identity into the mark as `MARK_MAGIC_IDENTITY` and
   redirect to the `cilium_wg0` ifindex.

Ingress, `from_wireguard` (tc ingress on `cilium_wg0`, attached
**unconditionally**): set `MARK_MAGIC_DECRYPT` with node id 0, emit
`TRACE_FROM_CRYPTO`, resolve the source identity from the ipcache, and then —
in tunnel mode without (NodePort **and** node encryption) — simply pass, because
the overlay program does delivery; the program stays attached only for the
decrypt mark, which strict ingress mode depends on. In native mode it tail-calls
into local or host delivery carrying that identity.

Egress on the device, `to_wireguard`, is attached **only** when

```
wireguard enabled && !tunnel_mode && l7-proxy enabled && kube-proxy-replacement
```

and MUST be actively **detached** otherwise. Its sole job is reverse-NAT for
encrypted kube-proxy-replacement traffic; it emits `TRACE_TO_CRYPTO` and never
drops or redirects on the success path. XDP is never attached to `cilium_wg0`.

Hubble labels a flow encrypted when it sees UDP with source port == destination
port == 51871 from a remote-node identity.

#### 3.1.10 Peer restore and garbage collection

A **one-shot task** with bounded retry (3 attempts, exponential 100 ms → 1 min)
MUST wait for **all** of these, in order, before reconciling the device against
the agent's view:

1. local Kubernetes cache sync,
2. ipcache revision ≥ 1,
3. kvstore node-discovery sync (a no-op in CRD mode),
4. IP/identity watcher sync (kvstore mode),
5. when ClusterMesh is configured: remote-cluster **nodes** synced, then
   remote-cluster **ipcache** synced.

Each wait MUST return cleanly on cancellation. Running GC before any of these
would delete peers for nodes that simply have not been observed yet.

Then, for every peer the kernel reports:

| Kernel peer | Action |
|---|---|
| public key known to the agent | queue removal of every AllowedIP the agent does not expect, then apply |
| public key unknown | delete the peer |

GC never removes a prefix the agent has queued for insertion and never touches
device-level settings.

#### 3.1.11 What is and is not encrypted

"default" = encrypted whenever WireGuard is on; "node-to-node" = encrypted only
with `encrypt-node`. Any pair not listed is **not** encrypted.

| Origin | Destination | Configuration | Mode |
|---|---|---|---|
| Pod | remote Pod | any | default |
| Pod | remote Node | any | node-to-node |
| Node | remote Pod | any | node-to-node |
| Node | remote Node | any | node-to-node |
| Pod | remote Pod via ClusterIP | any | default |
| Pod | remote Pod via non-ClusterIP service | socket LB | default |
| Pod | remote Pod via non-ClusterIP service | kube-proxy | node-to-node |
| External client | remote Pod via service | KPR + overlay, no DSR, no XDP | default |
| External client | remote Pod via service | native routing, no XDP | node-to-node |
| External client | remote Pod/Node via service | DSR Geneve, no XDP | default |
| Pod | remote Pod via L7 proxy or Ingress | L7 proxy / Ingress | default |
| Pod | egress-gateway node | egress gateway | default |
| Egress-gateway node | Pod | egress gateway, no XDP | default |

"Node" means the host or a host-network pod. For an external client the
client↔node leg is **never** encrypted; only the intermediate-node→destination-node
leg can be.

**Explicit gap list.** flowsdn MUST document each of these; none is fixed here:

| # | Gap | Cause |
|---|---|---|
| G1 | Traffic to an endpoint not yet in the ipcache leaves in clear | §3.1.9 step 5. Mitigate with egress policy restricting `reserved:world`, or with strict egress mode |
| G2 | Same-node traffic is never encrypted | Intentional; the plaintext is observable on the node anyway |
| G3 | N/S service traffic redirected between nodes with **XDP acceleration** is not encrypted | The XDP path runs before the tc encrypt hook |
| G4 | N/S service traffic with **DSR in a non-Geneve dispatch mode** is not encrypted | The DSR source identity is a remote-node identity, excluded by §3.1.9 step 7 |
| G5 | Egress-gateway **replies** with XDP are not encrypted | Same as G3 |
| G6 | IPv6 is not covered by strict **egress** mode | §3.1.12; IPv6 traffic can leak |
| G7 | Node-to-node traffic is not covered by strict **ingress** mode | Enforcement targets pod delivery only |
| G8 | Strict ingress can be bypassed through an interface flowsdn does not manage | Enforcement is per-interface BPF |
| G9 | ICMPv6 NA over WireGuard is impossible | §3.1.9 step 4; device is point-to-point/NOARP |
| G10 | Mixed WireGuard / non-WireGuard clusters in a ClusterMesh are unsupported | All clusters must enable it; UDP 51871 must be open between them |
| G11 | CNI chaining is unsupported for strict ingress (GH-15596) | — |
| G12 | Packets may drop while AllowedIPs change (GH-33159) | §3.1.5 |

#### 3.1.12 Strict mode

Two independent features. Both drop with code 195 (`DROP_UNENCRYPTED_TRAFFIC`).

**Egress** — `enable-encryption-strict-mode-egress`, with
`encryption-strict-egress-cidr` (IPv4 only) and
`encryption-strict-egress-allow-remote-node-identities`. **Applies to IPsec as
well as WireGuard.** It compiles `ENCRYPTION_STRICT_MODE_EGRESS`, the strict
network and prefix length, the node's IPv4 as the encrypt-interface address,
and an overlapping-CIDR flag set only when the node IP falls inside the strict
CIDR *and* remote-node identities are allowed.

The check runs in `to_netdev` **immediately after** the encrypt hook — so a
packet actually redirected to `cilium_wg0` has already returned and is never
judged. Decision, first match:

| # | Condition | Result |
|---|---|---|
| 1 | not IPv4 | **allow** (IPv6 is unprotected — gap G6) |
| 2 | header revalidation fails | **allow** (fail-open) |
| 3 | source is the router IP (`IPV4_GATEWAY`) or the node IP (`IPV4_ENCRYPT_IFACE`) | **allow** |
| 4 | tunnel mode **or** overlapping CIDR, and the destination resolves to a **remote-node** identity | **allow** |
| 5 | source **and** destination both inside the strict CIDR | **drop 195** |
| 6 | otherwise | allow |

Startup validation: a non-parsing or non-IPv4 CIDR is **fatal**; IPv6 being
enabled logs that IPv6 is unprotected; and if the node's IPv4 is inside the
strict CIDR while remote-node identities are **not** allowed, startup MUST fail
with a message saying the node would drop all its own traffic and naming the
flag that fixes it. flowsdn MUST reproduce that refusal — the failure mode it
prevents is a node that isolates itself.

**Ingress** — `enable-encryption-strict-mode-ingress`, **WireGuard only**;
combining it with IPsec MUST be refused at startup. Unlike egress it is a
runtime datapath config boolean (`encryption_strict_ingress`), not a compile-time
variant.

- In `from_netdev`, **before** NodePort/HostPort DNAT (so a HostPort packet
  addressed to the node IP is not judged against its post-DNAT pod backend): a
  packet not from the host, whose source is a **cluster** identity that is not a
  **remote-node** identity, destined to a local endpoint that is not
  host-delivery, is dropped unless it arrived carrying `MARK_MAGIC_DECRYPT`.
- In `from_overlay`: any packet without the decrypt mark is dropped. This block
  also requires `enable_identity_mark`.

Legitimate decrypted traffic never trips either check because `from_wireguard`
sets the decrypt mark before delivery (§3.1.9).

### 3.2 IPsec

IPsec and WireGuard are mutually exclusive; enabling both MUST be refused at
startup.

#### 3.2.1 The key file

One key per line. Lines are trimmed and split on runs of whitespace. There is
**no comment syntax and no blank-line tolerance**. The form is chosen by field
count alone:

```
AEAD      (4 fields): <spi> <aead-algo> <hex-key> <icv-len>
non-AEAD  (5 fields): <spi> <auth-algo> <hex-key> <enc-algo> <hex-key>
```

| Field count | Result |
|---|---|
| < 3 | error: missing key or invalid format |
| 3 | **error.** The reference indexes past the end and panics here; flowsdn MUST return an error. **DEVIATION** (bug fix) |
| 4 | AEAD |
| 5 | non-AEAD |
| > 5 | error: too many fields |

The historical trailing `[IP]` field of the 5-field form is **rejected** at this
tag (6 fields trips "too many fields").

**SPI.** A trailing `+` is stripped and then **entirely ignored**: per-node-pair
derivation is unconditional at this tag, so `+` is a documentation convention,
not a switch. The remainder MUST parse as a decimal integer (no `0x`), and MUST
be in **1..15**; `0` and `>15` are distinct errors.

**Keys.** A key of exactly `""` (two literal quote characters) decodes to a
zero-length key — this is how the null cipher/digest is expressed. Otherwise an
optional `0x` prefix is stripped and the remainder hex-decoded; odd length or
non-hex is an error.

**Algorithms.** The AEAD algorithm name MUST begin with `rfc`
(e.g. `rfc4106(gcm(aes))`). The 5-field form validates **nothing** about its
algorithm names; a bad name surfaces later as a netlink error.

**ICV length** MUST be 96, 128 or 256; anything else is an error.

**`KeyLen`** — the value that drives the rotation invariant and the MTU
calculation — is computed differently per form and flowsdn MUST reproduce the
asymmetry:

| Form | `KeyLen` |
|---|---|
| AEAD | `icv_len / 8` → 12, 16 or 32 |
| non-AEAD | the number of **hex characters** in the *auth* key after stripping `0x` |

MTU overhead is `EncryptionIPsecOverhead (77) + (KeyLen − 16)` (spec 10 §3.5).

**Which line wins.** Lines are applied **sequentially**; each is treated as a
full rotation against the accumulated in-memory key, and the last one that
parses wins. Two lines with the same SPI therefore fail on the second.

**Aborted loads.** There is no transaction and no rollback: lines before a
failure stay applied, and a superseded SPI's removal timestamp has already been
recorded. flowsdn MUST reproduce the *effect* — the previously loaded key stays
in force and the datapath keeps running — and SHOULD implement it as a
two-phase parse (parse all lines, then commit) so a partially applied file is
impossible. **DEVIATION** (robustness): parse-then-commit; the observable
behavior on a bad file is identical.

Failure disposition: at agent **start** a load error is fatal. In the **watcher**
it is logged, sets the health entry degraded, and the loop continues.

#### 3.2.2 Rotation detection and the SPI invariants

```
ongoing_rotation(active, current) =
    active != 0 && current != 0 && current == (active % 15) + 1
```

`active` is the SPI in `cilium_encrypt_state` (which survives an agent
restart); `current` is the SPI just loaded. The predicate is **successor with
15→1 wrap**, not "greater than". Any other relationship means "not a rotation",
and the new SPI is adopted and advertised immediately.

Two load-time invariants:

| Invariant | Violation |
|---|---|
| `KeyLen` MUST NOT change | error; the load aborts and the **old key stays in use until the agent restarts**. This is what the documentation calls "delaying the new key", and it exists to keep IPv6 pod-to-pod connectivity unbroken |
| SPI MUST change | error: rotation requires incrementing the key id |

The successor rule is **not** enforced at load time; only equality is checked.
A non-successor SPI loads fine and is adopted immediately, which is the
observable difference between a correct rotation and a botched one.

#### 3.2.3 Per-node-pair key derivation

```
derived = H( global_key ‖ src_node_ip ‖ dst_node_ip ‖ src_boot_id[0..36] ‖ dst_boot_id[0..36] )
          truncated to len(global_key)
H = SHA-256 when len(global_key) <= 32, else SHA-512
```

- IPs are canonicalized first: an IPv4 address contributes **4 bytes**, never
  the 16-byte v4-mapped form. Getting this wrong produces a silent key
  mismatch with any peer running the reference.
- Boot IDs enter as the **raw ASCII bytes of the UUID text, exactly 36 bytes**.
  They are not parsed to binary. A boot ID shorter than 36 bytes MUST be an
  error, not a panic.
- The OUT state on node A uses `(a, b, boot_a, boot_b)`; the IN state on A uses
  `(b, a, boot_b, boot_a)`. Note the IPs are **not** swapped for IN — for an IN
  state the source tunnel IP is already the remote. On B the pair is exactly
  mirrored, so each direction's SA key matches, and either node's reboot
  rekeys both directions automatically.

**Empty remote boot ID.** A node whose `spec.bootid` is empty MUST get **no
XFRM configuration at all** (checked after the default-drop policy and after
the local-node short-circuit). Deriving from an empty boot ID would produce
mismatched IN and OUT keys cluster-wide and a storm of
`XfrmInStateProtoError` drops.

**Reboot handling.** When a node update carries a different boot ID than the
previous one, the node is marked `RemoteRebooted` until an update completes
with every state successfully installed. `RemoteRebooted` changes exactly one
thing: a state that already exists byte-identically is **deleted and re-added**
instead of being left alone, because the boot-ID-dependent key must actually
reach the kernel. That swap is non-atomic; it is safe because the IN direction
can only lose a few encrypted packets, and the OUT direction is covered by the
surviving OUT policy plus the default-drop policy (§3.2.5f).

#### 3.2.4 XFRM objects: the common template

Every state, both directions, both families, overlay and not:

| Field | Value |
|---|---|
| Mode | tunnel |
| Proto | ESP |
| ESN | **true** |
| Replay window | **1024** |
| SPI | the current key SPI, 1..15 — the same small integer visible on the wire |
| Reqid | **1** (`DefaultReqID`), hard-coded |

Because ESN is on, the kernel message carries the ESN replay attribute with
window 1024 and a 32-word bitmap, and the **legacy replay-window field is 0**.
A read-back therefore reports replay window 0. flowsdn's state-comparison
logic MUST NOT treat that as a mismatch.

Mark construction:

```
encrypt_mark(spi, node_id) = { value: 0x0E00 | (spi << 12) | (node_id << 16), mask: 0xFFFFFF00 }
decrypt_mark(node_id)      = { value: 0x0D00 |                (node_id << 16), mask: 0xFFFF0F00 }
```

The IN mark deliberately carries **no SPI**: one IN state per (node id, tunnel
IP pair) serves every SPI. That is why only OUT objects are SPI-scoped and only
OUT policies are eligible for stale-SPI reclamation (§3.2.8).

#### 3.2.5 XFRM objects: the complete set per remote node, per family

Selectors named "wildcard" are `0.0.0.0/0` or `::/0`. "Tunnel IPs" are the
Cilium internal IPs unless stated.

| # | Object | Dir | Src / Dst selector | Mark (value / mask) | Output-mark (value / mask) | Prio | Action | Template |
|---|---|---|---|---|---|---|---|---|
| a | OUT state | out | local tunnel IP → remote tunnel IP (plain IPs) | `0x0E00\|spi<<12\|nid<<16` / `0xFFFFFF00` | `0x0E00` / `0xFFFFFF00` | — | — | — |
| b | IN state | in | remote tunnel IP → local tunnel IP | `0x0D00\|nid<<16` / `0xFFFF0F00` | `0x0D00`, or **`0` when zero-output-mark** / `0xFFFFFF00` | — | — | — |
| c | OUT policy, one per remote pod CIDR | out | wildcard → remote pod CIDR | `0x0E00\|spi<<12\|nid<<16` / `0xFFFFFF00` | — | **0** | allow | 1, **required**: ESP/tunnel, src=local tunnel IP, dst=remote tunnel IP, reqid 1, spi=current |
| d | IN policy | in | wildcard → wildcard | **none** | — | **0** | allow | 1, **optional**, with reqid, spi, src and dst all blanked |
| e | FWD policy | fwd | wildcard → wildcard | **none** | — | **0x0B9F (2975)** | allow | same blanked optional template as (d) |
| f | Default drop policy, once per family | out | wildcard → wildcard | **`0x0E00` / `0x0F00`** | — | **100** | **block** | — |
| g | Encrypted-overlay OUT, tunnel mode only | out | local **underlay** IP/32 → remote **underlay** IP/32 | as (c) | — | 0 | allow | as (c), with underlay IPs |
| h | Encrypted-overlay IN, tunnel mode only | in | wildcard → wildcard | as (b) | as (b) | 0 | allow | as (d) |

Notes that carry consequences:

- **(f) is installed first**, at the top of the per-family path, on **every**
  node update including the local node, before any boot-ID check or subnet
  branching. Lower XFRM priority number wins, so the per-node OUT policies
  (priority 0) always take precedence; the drop policy only catches
  encrypt-marked traffic that momentarily has no matching per-node policy. It
  matches on the mark specifically so unmarked host traffic is not blocked. It
  is the single thing standing between a policy-churn window and plaintext on
  the wire, and it is exempt from stale reclamation. flowsdn MUST install it
  before touching any OUT policy.
- **Zero output mark** on (b) is set from `enable-endpoint-routes`: the
  decrypted packet then emerges with `skb->mark == 0` so netfilter and
  conntrack are not confused and the stack routes it. In the reference it is
  only plumbed through the *subnet-encryption* paths; the single-CIDR paths
  hard-code false. flowsdn MUST plumb it through both — the single-CIDR path
  with endpoint routes is otherwise inconsistent with the datapath's
  endpoint-routes branch (§3.2.7). **DEVIATION**, accepted by ADR-0012 #176.
- **(g)/(h) use the underlay node IPs**, not the Cilium internal IPs; this is
  what encrypts the VXLAN/Geneve packet so the identity in the VNI is not on
  the wire in clear. Installed only when encapsulation is on and
  subnet-encryption is off; skipped with a warning if either underlay IP is
  missing.
- Two reference bugs flowsdn MUST **fix, not reproduce** (**DEVIATION**, both
  are latent IPv6 correctness faults, neither is observable by a peer):
  1. the IPv6 "exact match" mask used for (g) is an all-zero mask, making the
     selector `::/0` rather than `/128`;
  2. the IPv6 overlay IN policy uses the IPv4 wildcard CIDR as its selector.
- `UpsertIPsecEndpoint` MUST do nothing when the source and destination tunnel
  IPs are equal — the "never encrypt to yourself" rule.
- Policy install errors that mean "already exists" are ignored; state errors
  are always fatal to that upsert.

**Subnet-encryption variant** (ENI / Azure, selected when pod-subnet lists are
non-empty; auto-populated from the router info in those IPAM modes):

- N OUT state/policy pairs, one per **configured pod subnet** (not per remote
  alloc CIDR), with selector wildcard → pod subnet.
- **Two** IN state/policy pairs, not one: the first with the Cilium internal IP
  pair as tunnel endpoints, the second with the node internal IP pair (taken as
  the first address of the encryption interface). Both are installed regardless
  of `use-cilium-internal-ip-for-ipsec`, which selects only which pair the
  **OUT** side uses.
- No encrypted-overlay pair; the local node is skipped entirely.

#### 3.2.6 Routes, rules and the encryption interface

Spec 10 §3.2.4 and §3.3 own the netlink objects; this spec states the contract.

**ip rule**: priority **1**, `fwmark 0x0D00/0x0F00`, lookup table **200**,
proto `RTPROT_KERNEL` (2). The kernel protocol number is chosen so
`systemd-networkd`'s foreign-rule management does not garbage-collect it.
IPv4 is installed only when `enable-endpoint-routes` is **false**; IPv6 always.

**Table 200**:

| Route | Prefix | Device | Type | MTU |
|---|---|---|---|---|
| IN, one per **local** pod alloc CIDR | local CIDR | the encryption interface | `RTN_LOCAL` (scope host) | — |
| OUT, one per **remote** pod CIDR | remote CIDR | `cilium_host` | unicast | `RoutePostEncryptMTU` |

`RoutePostEncryptMTU` is the *undiminished* device MTU: at that point the packet
is already encrypted. OUT routes are installed only when subnet encryption is
off. In subnet-encryption mode the IN routes are one per configured pod subnet,
with the IPv4 ones skipped under `enable-endpoint-routes`.

**Teardown** when IPsec is disabled: delete the priority-1 rules for both
families (tolerating "not found", and "family unsupported" for IPv6), flush
table 200, and delete all Cilium XFRM objects (§3.2.9).

**Encryption interface selection.** There is no configuration knob:

1. the tunnel device when encapsulation is on;
2. otherwise `devices[0]` — the first detected device, deliberately, "any
   interface would work";
3. otherwise none.

The Helm value `encryption.ipsec.interface` and the agent flag
`--encrypt-interface` behind it are **gone** at this tag (the flag was a no-op
since 1.18 and has been removed; no template references the value). flowsdn
MUST NOT accept `--encrypt-interface`, and its Helm mapping MUST document
`encryption.ipsec.interface` as removed. The reference's own troubleshooting
documentation still recommends it and is stale.

#### 3.2.7 What the datapath does (summary; normative text in spec 02)

**SPI negotiation.** The peer's SPI comes from `cilium_node_map_v2`; the local
SPI from `cilium_encrypt_state`. Pick the **smaller**, because key ids increase
monotonically and the smaller one is certainly installed on both ends, with two
mirrored wrap cases resting on the assumption that two nodes are never more
than one key version apart:

```
if peer  == 15: return local == 1 ? 15 : local
if local == 15: return peer  == 1 ? 15 : peer
return min(local, peer)
```

A zero on either side propagates and means "no encryption".

**Encrypt.** Look up the peer's node entry by the ipcache tunnel endpoint. A
**missing node id is a hard drop**, code 197 (`DROP_NO_NODE_ID`) — expected
under normal churn (a new node whose CiliumNode has not arrived, a deleted
node, a node whose IP changed) and it stops once the CiliumNode propagates.
Build the mark `0x0E00 | spi<<12 | node_id<<16`, stash the source identity in
`cb[]` (and the mark too, because some kernels do not preserve `skb->mark`
across a same-netns redirect), rewrite the destination MAC and redirect to
**`cilium_net` ingress** so the XFRM output hook encrypts and recirculates.

**Decrypt**, in `from_netdev`:

| Case | Action |
|---|---|
| not yet decrypted, protocol is **not** ESP | pass through untouched |
| not yet decrypted, ESP, no node id for the **source** address | drop 197 |
| not yet decrypted, ESP | set `0x0D00 \| node_id<<16`, force `PACKET_HOST` (the frame may have been labelled other-host, which the IP stack would drop before XFRM ran), pass to the stack |
| already decrypted (mark `0x0D00` left by the IN state's output-mark) | clear the mark; **with endpoint routes** pass to the stack (which has per-endpoint routes); otherwise redirect into `cilium_host` |

The recirculation is why both the outer ESP packet and the decrypted inner
packet are visible on the same interface — expected, not a fault.

#### 3.2.8 Key rotation

**At start**, in order: read the active SPI from the BPF map (a lookup error is
fatal); load the key file (an error is fatal); then

- **not** a rotation → write the map and advertise the new SPI;
- **rotation across a restart** → **defer** the map write and keep advertising
  the **old** SPI. A one-shot task waits for the datapath to be initialized,
  then runs the publication sequence below and only then starts the key
  watcher. Publishing before the datapath is up would let peers send under the
  new key before the local IN states exist.

**Publication sequence** — this order is the whole correctness argument and
MUST NOT be reordered:

1. Re-validate **every** known node, installing states and policies for the new
   SPI. **IN states for all nodes exist first.**
2. Publish `EncryptionKey = new SPI` on `LocalNode` → CiliumNode / kvstore.
   Peers now start using the new SPI towards this node.
3. Write the new SPI into `cilium_encrypt_state`. Only now does this node's own
   datapath start emitting under it.

**Watcher.** Controlled by `enable-ipsec-key-watcher` (default true); when
false a rotation needs an agent restart. The **single key file path** is
watched; the reference uses a 5 s **polling** watcher that follows symlinks
(necessary for Kubernetes projected-secret symlink layouts) and compares size
plus a content checksum. flowsdn SHOULD use inotify on the containing
**directory** with the same symlink-following stat, because a projected secret
update replaces the symlink target rather than writing the file, and MUST
retain a periodic re-stat as a backstop. **DEVIATION** (mechanism only;
observable behavior identical).

On a create-or-write event: **sleep a jitter drawn uniformly from
`[0, ipsec-key-rotation-duration / 10)`** (30 s at the 5 m default), then load
and publish. The jitter exists to stop every agent in a large cluster
rewriting its CiliumNode at the same instant and overwhelming the API server.
Remove events are ignored. Errors degrade health and continue.

**Stale-key reclaim**, a timer every **1 minute**. Snapshot one timestamp for
the whole pass so results are consistent. An SPI is reclaimable when:

1. it is not the current SPI; **and**
2. it has a recorded replacement time — an SPI **first seen** in this pass gets
   its clock started **now** and is **not** reclaimed, so after an agent
   restart every unknown SPI gets a full rotation period; **and**
3. that replacement time is at least `ipsec-key-rotation-duration` old.

What is deleted:

| Object | Rule |
|---|---|
| States (IN and OUT) | any whose SPI is reclaimable |
| Policies | only `dir == out`, and **not** the default drop policy |

IN and FWD policies carry no mark, so their extracted SPI is 0 and they would
nominally qualify — the direction filter is what excludes them. The default
drop policy *is* an OUT policy with an encrypt mark whose SPI nibble is 0, so
it needs its own explicit exemption, matched on priority, action, direction,
mark value and mask, and both selectors.

Expected steady-state key count: **2 per remote node per enabled IP family**,
doubling to 4 during a rotation. A three-node dual-stack cluster has 8 keys per
node at rest.

#### 3.2.9 XFRM cleanup and stale-state handling

**State replace.** Scan for an exact match on source, destination, mark,
output-mark and SPI:

- match and **not** rebooted → **no-op**. This is the hot path: the periodic
  background sync validates every node's XFRM without changing anything, which
  is why the state-list cache (§3.2.10) matters.
- match and rebooted → delete, then add.
- no match → add. On **"already exists"**, delete every conflicting state, and
  retry the add **once**; if nothing was deleted, return the original error
  rather than retrying pointlessly.

**Conflict identification** MUST replicate the kernel's SA lookup, which hashes
on `(mark, dst, spi, proto, encap)` and therefore collides even when the
*source* differs. A state conflicts when:

```
same SPI
&& both marked or both unmarked
&& (unmarked || (new.value & new.mask & existing.mask) == existing.value)
&& dst addresses equal          # source is deliberately NOT compared
```

Address comparison MUST treat two unspecified addresses as equal regardless of
family, because netlink returns an unset IPv6 address as a nil IPv4 address.

The consequence is structural, and flowsdn's data model MUST respect it: the
kernel's hash keys force **one state per destination address**, i.e. per node
per direction.

**The general-vs-specific IN state problem.** When a node-scoped IN state
(mark `0xXXXX0D00/0xFFFF0F00`) coexists with a legacy general IN state (mark
`0x0D00/0x0F00`), a delete naming the specific state causes the kernel to
delete the **general** one. The workaround, required whenever deleting an
ingress state with a non-zero node id while a matching general state exists:

1. record the `XfrmInNoStates` counter and a timestamp; delete the general
   state;
2. delete the intended specific state;
3. re-add the general state, and log the elapsed time and the delta in
   `XfrmInNoStates` as the number of packets this cost.

If step 1 fails, do not attempt the delete. The counters are used **only** as a
delta-based drop measurement for observability; nothing branches on them.

**Per-node delete** (node deletion): delete every state and policy whose mark
mask covers the node-id field and whose encoded node id matches, states via the
safe-delete path above. Policies are always listed live, never from the cache.

**Bulk delete by request id.** Ownership is decided by: an unmarked policy is
Cilium's iff it is the FWD policy at priority 2975 or an IN policy with exactly
one blanked optional template; a marked policy or state is Cilium's iff its
mark value intersects `0x0D00` or `0x0E00`. This is a deliberately loose filter
and flowsdn MUST keep it loose, or a partial cleanup will leave objects behind
that a later add then collides with.

**When cleanup runs**: only on the configuration transition to IPsec-disabled —
which at agent startup is the initial config application, so it doubles as the
startup purge. It does **not** run on node delete (that is the per-node path)
and **not** on key rotation. A narrow variant deletes just the OUT policy for
one (node id, destination CIDR) and is used when a remote node loses an
alloc CIDR.

**Documented causes of stale state**, all of which leave out-of-sync
anti-replay counters and a permanent pod-to-pod disruption: kvstore lease
expiry after prolonged agent downtime; a manually recreated kvstore that the
agent joins too late to see the node delete/create events; and, in CRD mode,
deleting a CiliumNode and restarting the DaemonSet. The documented mitigation
is a **key rotation**, and flowsdn MUST keep that property: a rotation
re-derives and reinstalls every state.

#### 3.2.10 State-list cache and the output-mark probe

A **1-minute TTL cache** over the full XFRM state dump, controlled by
`enable-ipsec-xfrm-state-caching` (default true, hidden). Only *states* are
cached; policies are always dumped live. Every state mutation MUST invalidate
the cache **before** issuing the netlink call, and all state mutations MUST go
through the caching wrapper. Its purpose is the no-op path in the periodic
per-node validation, which would otherwise dump the whole SA database once per
node per sync.

**Output-mark probe.** Before starting, when IPsec **and** tunneling are both
enabled, add a throwaway XFRM state carrying both a mark and an output mark
with a non-trivial mask, read it back, and verify the output mark's mask
survived; delete it either way. Failure is **fatal**: XFRM output-mark masks
require Linux ≥ 4.19. In direct-routing mode the probe is not run.

Other startup gates, all fatal (§6 lists the flags):

| Combination | Why |
|---|---|
| IPsec + WireGuard | mutually exclusive |
| IPsec + L7 proxy without DNS-proxy transparent mode | proxied DNS would leave the node in clear; overridable only by a hidden insecure flag |
| IPsec + strict ingress mode | unsupported |
| IPsec + host firewall | unsupported |
| IPsec + a pinned local router IP | unsupported |
| IPsec (or WireGuard) without the CiliumNode CRD | boot IDs and keys travel on it |

#### 3.2.11 Known limitations

| # | Limitation |
|---|---|
| L1 | No CNI chaining (GH-15596) |
| L2 | Host policies are unsupported with IPsec |
| L3 | ≤ 65535 nodes per cluster or clustermesh — the node id is a `u16` |
| L4 | Decryption is limited to **one CPU core per SA**; high node-pair throughput is bounded by it |
| L5 | Same-node traffic is never encrypted |
| L6 | Key rotations MUST NOT overlap an upgrade or downgrade |
| L7 | Changing to an algorithm with a different auth key length during a rotation is refused; the old key stays until restart |
| L8 | Since encryption now happens **after** encapsulation, operators see ESP between nodes and MUST open ESP in cloud security groups and VPC firewall rules |
| L9 | Strict **ingress** mode is unavailable (§3.1.12); the egress variant works |
| L10 | Stale XFRM state (§3.2.9) is recoverable only by a key rotation |

### 3.3 Node IDs and the encrypt map

Spec 10 §3.3.5 owns the allocator; this section states what encryption requires
of it and what encryption writes.

**Range**: 1..65535. **ID 0 is reserved for the local node** and is never in the
map — a lookup of a local node IP returns 0 with "found". This is why a missing
node id and the local node are distinguishable in the datapath.

**Allocation** per remote node:

1. Look for an existing id across all of the node's addresses.
2. Compute "SPI changed" = no previous node, or the previous node's
   `EncryptionKey` differs. When the SPI is unchanged and an address already
   maps to the right id, the map write is skipped — an opportunistic refresh
   that also repairs a stale entry left by a missed delete.
3. If no id was found, allocate one. **Exhaustion MUST return an error and MUST
   NOT map any address to id 0** — doing so would later be misread as "this is
   the local node".
4. If some address is already mapped to a *different* id (a node deleted while
   the agent was down whose addresses were reused), unmap **all** of the node's
   addresses and retry allocation from scratch.
5. For each address write `cilium_node_map_v2`: `(family, ip) → {node_id, spi}`
   where `spi` is the **remote node's advertised `spec.encryption.key`**. Write
   the BPF map **first**; update the in-memory indexes only after it succeeds.

**Restore.** At startup, before any new allocation, iterate the pinned map,
rebuild both indexes, and remove each restored id from the free pool. Any entry
with **node id 0 is invalid** and MUST be deleted from the map. Restore is
mandatory, not an optimisation: XFRM marks encode the node id, and in-flight
encrypted traffic depends on ids being stable across an agent restart. If the
in-memory index is non-empty when restore runs, restore ran too late — that is
a startup-ordering bug and MUST be reported as one.

**Deallocation.** Verify every address of the node carries the same id (report
otherwise), unmap each address recorded under that id (reporting any address
that does not belong to the node), and return the id to the pool.

**How the datapath resolves a peer to a key.**

```
ipcache(dst).tunnel_endpoint  ─→  cilium_node_map_v2  ─→  {node_id, peer_spi}
                                                            │
cilium_encrypt_state[0].encrypt_key  ─→  local_spi   ───────┤
                                                            ▼
                                       spi = min-with-wrap(local_spi, peer_spi)
                                       mark = 0x0E00 | spi<<12 | node_id<<16
```

For **WireGuard** the chain stops at the ipcache: `remote_endpoint_info.key`
is the static `0xFF` and its only role is being non-zero.

`cilium_encrypt_state` is an array of exactly one entry, key 0, value one byte.
Its sole writer is the IPsec agent; it is the restart-surviving record of the
locally active SPI and therefore the input to rotation detection (§3.2.2).

### 3.4 Egress gateway

#### 3.4.1 The CRD

`CiliumEgressGatewayPolicy`, `cilium.io/v2`, **cluster-scoped**, kind
`CiliumEgressGatewayPolicy`, plural `ciliumegressgatewaypolicies`, singular
`ciliumegressgatewaypolicy`, short name `cegp`, categories `cilium` and
`ciliumpolicy`, printer column `Age` from `.metadata.creationTimestamp`,
**no status subresource** and no `status` field. `metadata` is the only required
top-level field; `spec` is optional at the schema level.

`spec` requires `destinationCIDRs`, `egressGateway` and `selectors`.

| Field | Type | Required | Validation | Meaning |
|---|---|---|---|---|
| `spec.selectors` | list of objects | **yes** | no `maxItems` | Source-pod selection rules, OR-ed |
| `spec.selectors[].podSelector` | label selector | no | `x-kubernetes-map-type: atomic` | Selects pods. Present but empty = all pods |
| `spec.selectors[].namespaceSelector` | label selector | no | atomic | Selects namespaces by cluster-scoped labels. Present but empty = all namespaces |
| `spec.selectors[].nodeSelector` | label selector | no | atomic | Restricts source pods to those on matching nodes. **Cannot be used alone** |
| `spec.destinationCIDRs` | list of strings | **yes** | CIDR pattern | Destinations the policy applies to; any match selects. IPv4 and IPv6 |
| `spec.excludedCIDRs` | list of strings | no | CIDR pattern | Destinations excluded from redirect and SNAT. Should be a subset of `destinationCIDRs`; one that is not simply never wins an LPM race and has no effect |
| `spec.egressGateway` | object | **yes** | — | Single gateway. **Ignored entirely when `egressGateways` is non-empty** |
| `spec.egressGateways` | list of objects | no | **`maxItems: 64`**, default `[]` | Multi-gateway list, same element shape |
| `…egressGateway.nodeSelector` | label selector | **yes** | atomic | Selects the gateway node |
| `…egressGateway.interface` | string | no | — | Egress interface name; its first address per family becomes the egress IP |
| `…egressGateway.egressIP` | string | no | `maxLength: 39`, CEL `self == '' \|\| isIP(self)` | Explicit SNAT source address, IPv4 or IPv6 |

Every label selector uses the standard `matchLabels` / `matchExpressions`
shape with the operator enum `In`, `NotIn`, `Exists`, `DoesNotExist`.

`interface` and `egressIP` are **not** mutually excluded by the schema; the
exclusion is enforced at parse time (§3.4.2).

The reference's CIDR `pattern` is one regex alternation whose IPv6 branch
contains transcription errors (`^s*` and `d` where `\s*` and `\d` were meant,
and unescaped dots), making it far more permissive than it appears. flowsdn
MUST publish a CRD whose IPv4 branch is equivalent and MUST validate with a
real prefix parser rather than the regex. **DEVIATION** (correctness): the
published IPv6 pattern is corrected. Any manifest the reference accepts and
that is a genuine prefix is still accepted.

#### 3.4.2 Parsing and validation

Rejections, in order, each dropping the **whole** policy (logged at warn and
retried through the workqueue rate limiter — never partially applied):

| Condition | Error |
|---|---|
| empty name | must have a name |
| `destinationCIDRs` is **null** | destination CIDRs can't be empty. A non-nil **empty list passes** — flowsdn reproduces this |
| a gateway entry is null | egress gateway can't be empty |
| a gateway sets both `interface` and `egressIP` | cannot specify both |
| an egress IP does not parse | failed to parse egress IP |
| a destination or excluded CIDR does not parse | failed to parse …CIDR |
| a `selectors[]` entry has **both** `namespaceSelector` and `podSelector` null | cannot have both nil namespace selector and nil pod selector |

`egressGateways` is parsed first; only if it yields nothing is `egressGateway`
parsed. An **invalid** entry in `egressGateways` still fails the whole policy.

**Namespace-selector translation.** Each `namespaceSelector` key `k` — in both
`matchLabels` and `matchExpressions` — becomes
`io.cilium.k8s.namespace.labels.<k>`. A **completely empty** namespace selector
becomes the single requirement `io.kubernetes.pod.namespace Exists`, i.e. all
namespaces. The translated namespace selector and the pod selector are then
**AND-ed into one endpoint selector** with every key carrying the `k8s:` source
prefix. Translation MUST operate on a copy: the input object MUST NOT be
mutated.

**Node selectors are flattened globally.** All non-null
`selectors[].nodeSelector` entries are collected into **one flat list**, and an
endpoint matches when (any endpoint selector matches its labels) **and** (the
node list is empty, or any node selector matches its node's labels). With
`selectors: [{pod: A, node: N}, {pod: B}]` a B-pod on an N-node is selected and
a B-pod elsewhere is **not**. This is a cross-product, not the per-entry pairing
the schema suggests. flowsdn MUST reproduce it deliberately; §12 records the
option of changing it.

**Which labels match.** Only the **security identity's** label set. Labels
excluded from identity (via `--labels`) can never match a policy.

**Endpoint eligibility.** An endpoint is skipped when its UID is empty (which is
what happens under CiliumEndpointSlice — hence the incompatibility), when it has
no networking metadata, or when it has no parseable addresses. A missing
identity is skipped without retry; an identity **lookup failure** is retried
under an exponential rate limiter (20 ms → 20 min) mirroring the identity
allocator's own backoff.

#### 3.4.3 Gateway selection

The node list is kept sorted ascending by **node name**, so every agent in the
cluster selects the same gateway.

**Single gateway:** walk nodes in name order; the first whose labels match the
`nodeSelector` and whose **internal IPv4** converts successfully becomes the
gateway (a node whose IPv4 does not convert is skipped, not fatal). If that node
is the local node, derive the egress IP and interface (§3.4.4); a derivation
error is logged and selection continues with the sentinel values. Stop at the
first match.

If no node matched, a sentinel config with `gateway_ip = 0.0.0.0` is still
emitted. **Map entries are still written and matching traffic is dropped, not
passed through.** This is deliberate: a policy whose gateway has vanished must
not silently leak pod traffic out of the node's own IP.

**Multi-gateway:** on every reconciliation pass, sort the resolved gateway
configs by **gateway IP** (`netip.Addr` ordering — not by node name), then

```
index = FNV-1a-32( CiliumEndpoint UID as raw bytes ) % number_of_resolved_gateways
```

The hash input is the CiliumEndpoint's UID **string** (e.g.
`c57b0909-b567-48a3-865a-c1d1a17b545d`) — not the pod name, not the pod IP.
Only gateway entries that actually resolved a node occupy a slot; an entry whose
`nodeSelector` matched nothing is dropped before the modulo.

Stability: assignment is stable for an endpoint's lifetime while the resolved
gateway set is unchanged. It is **not** stable when a `nodeSelector` is
added, removed or edited, when a matching node joins or leaves, **or when a
gateway node's internal IP changes** (the sort key moves). Because this is a
plain modulo and not consistent hashing, any such change reshuffles every
endpoint and **breaks existing connections** — upstream **GH-39245**. §3.4.8
specifies the optional improvement.

#### 3.4.4 Egress IP and interface derivation

Runs **only on the node that was selected as gateway**. Which families are
needed is derived from `destinationCIDRs` alone; `excludedCIDRs` do not
contribute. Start from `egress_ip4 = 0.0.0.0`, `egress_ip6 = ::`,
`egress_ifindex = 0`, not-configured.

| Case | Interface | Ifindex | Addresses |
|---|---|---|---|
| `interface` given | the named device | **set** | the device's *primary* address per needed family; a missing one is an error |
| `egressIP` given | the device that owns that address | **left at 0** | the given IP for its own family; the device's primary address for the other family when needed |
| neither | the device with the default route, per family | **set** | the device's first address per family. If the IPv6 default-route device differs from the IPv4 one, that is an error |

The `egressIP` case leaving the ifindex at 0 is not an oversight to fix: it is
what makes the datapath perform a **per-packet FIB lookup** and choose the
outgoing interface dynamically, which is the documented behavior of that
configuration. flowsdn MUST reproduce it.

On **any** error the function returns early, leaving the sentinels in place and
the node not marked as a configured gateway. The caller logs and proceeds; the
gateway then programs `egress_ip = 0` and **drops** matching traffic with code
204. Note the sentinel is the same value as "this node is not the gateway";
that is benign because only the gateway reaches the SNAT hook.

**No re-derivation on address changes.** Derivation runs only on policy, node
and initial-sync events — never on an endpoint event and never on a device or
address change. Changing a gateway's addressing requires re-applying the policy.
flowsdn MUST document this; §12 records the option of watching the device table.

**`rp_filter`.** For each interface that this node is a configured gateway on,
set `net.ipv4.conf.<iface>.rp_filter = 2` (loose). Failure is logged, not fatal.
There is no IPv6 equivalent, and the settings are **never removed** when a node
stops being a gateway.

#### 3.4.5 Map compilation

Three LPM tries, all `NO_PREALLOC | RDONLY_PROG`, all sized by
`egress-gateway-policy-map-max` (default 16384):

| Map | Key | Value |
|---|---|---|
| `cilium_egress_gw_policy_v4` (legacy) | `{prefixlen u32, saddr be32, daddr be32}` | `{egress_ip be32, gateway_ip be32}` |
| `cilium_egress_gw_policy_v4_v2` | same 12-byte key | `{egress_ip, gateway_ip, reserved[3] u32, egress_ifindex u32, reserved2 u32}` |
| `cilium_egress_gw_policy_v6` | `{prefixlen u32, saddr v6, daddr v6}` | `{egress_ip v6, gateway_ip **be32**, reserved[3], egress_ifindex, reserved2}` |

**`gateway_ip` is IPv4 in all three maps**, including the v6 one — the gateway
is always addressed by its internal IPv4, which is what makes the IPv4-underlay
requirement load-bearing. The `reserved[3]` hole exists so a v6 gateway IP can
be added later without an ABI break.

**Key construction.** One entry per (matched endpoint IP × CIDR):

```
prefixlen = 32  + destination_prefix.bits()      (v4)
prefixlen = 128 + destination_prefix.bits()      (v6)
saddr     = the endpoint IP, matched exactly
daddr     = the destination prefix address as written
```

The static prefix makes the source IP an exact match and the destination a
longest-prefix match; lookups always present the full length (64 or 256). The
destination address is stored **as written, not re-masked**, so a policy naming
`1.1.1.1/24` stores `1.1.1.1` with prefix length 24 — harmless for matching,
visible in dumps.

**Sentinels**, all in the `0.0.0.0/8` range:

| Field | Value | Meaning |
|---|---|---|
| `gateway_ip` | `0.0.0.0` | no gateway resolved → **drop 194** |
| `gateway_ip` | **`0.0.0.1`** | excluded CIDR → pass, bypass the gateway entirely |
| `egress_ip` | `0.0.0.0` / `::` | on the gateway: no egress IP → **drop 204**. On every other node: simply "not me" |

**How exclusions win.** For each endpoint IP, destination CIDRs are emitted
first, then excluded CIDRs with `gateway_ip = 0.0.0.1`. Because an excluded CIDR
is a subset of a destination CIDR, it is a **longer prefix on the same source
key**, and LPM selects it. `egress_ip` is still written with the real value on
an excluded entry; the datapath checks `gateway_ip` first, so it is irrelevant.

`egress_ip` and `egress_ifindex` are `0` on every node that is not the selected
gateway.

#### 3.4.6 Reconciliation

Three inputs and nothing else: `CiliumEgressGatewayPolicy`, `CiliumNode` and
`CiliumEndpoint`. There is no Pod, Namespace, Service or device watch; identity
labels are pulled synchronously at endpoint-upsert time.

Reconciliation MUST NOT run until **all three** streams have completed their
initial sync. Events are coalesced by a trigger with a minimum interval of
`egress-gateway-reconciliation-trigger-interval` (default **1 s**), and each
pass consumes an accumulated event bitmap:

| Event class | Work |
|---|---|
| endpoint update/delete, node update/delete, initial sync | rebuild every policy's matched-endpoint set **from scratch** |
| initial sync, policy add/delete, node update/delete | re-select gateways, re-derive the local egress IP and interface, re-apply `rp_filter` |
| always | write all three maps |

**Full diff, per map, independently:**

1. Dump the whole map into memory.
2. Treat every present key as stale.
3. Compute the desired set by walking every policy × matched endpoint ×
   CIDR, filtering by family (an entry is written to a v4 map only when both
   the endpoint IP and the destination are IPv4, and to the v6 map only when
   both are IPv6).
4. For each desired key: un-mark it stale, and write it **only if absent or
   different**. Comparison is `(egress_ip, gateway_ip)` for the legacy map and
   `(egress_ip, gateway_ip, egress_ifindex)` for the other two.
5. Delete everything still marked stale.

Write errors are logged and reconciliation remains degraded. Modern IPv4 v2
and enabled IPv6 maps are synchronized on every pass. With the explicit legacy
option, also synchronize legacy IPv4 first, followed by v4_v2 and v6, retaining
identical IPv4 keys/address pairs. A partial failure is not successful migration.
The reference reader falls back to legacy; flowsdn's new programs do not require
that fallback. Loaded reference readers are protected by the inspection and
migration gate in resolved decision #174 (§12.2).

Two reference behaviors flowsdn MUST **not** reproduce (**DEVIATION**, both are
latent correctness faults with no compatibility consequence):

1. the map-dump error is discarded, which would make every present entry look
   stale and delete the whole map — flowsdn MUST abort the pass on a dump
   error and retry;
2. policies are iterated in nondeterministic map order, so two policies
   producing the same key resolve arbitrarily and can flap between passes —
   flowsdn MUST iterate policies in a **deterministic order** (by name) so a
   collision resolves the same way every pass.

#### 3.4.7 Requirements and what happens when they are unmet

Checked at construction; each failure MUST **abort agent startup**, not
silently disable the feature:

| Requirement | On violation |
|---|---|
| `identity-allocation-mode = crd` | fatal: egress gateway is not supported in `<mode>` identity allocation mode |
| CiliumEndpointSlice **disabled** | fatal: not supported in combination with CiliumEndpointSlice (GH-24833) — CES endpoints carry no UID, which both the matcher and the multi-gateway hash need |
| `enable-ipv4-masquerade` **and** `enable-bpf-masquerade` | fatal, naming both flags |
| IPv4 tunnel underlay | fatal: egress gateway requires an IPv4 underlay |
| `enable-ipv6-masquerade` for IPv6 policies | **informational log only**, not fatal |
| kube-proxy replacement | documented as required; **not validated** in the reference. flowsdn MUST validate it and refuse to start. **DEVIATION** (the dependency is real — BPF masquerade implies the NodePort datapath, and the SNAT port arithmetic in §3.4.9 is defined against `--node-port-range`) |
| gateway in the same cluster (no ClusterMesh gateway) | documented; **not validated**. flowsdn SHOULD warn when a policy's gateway selector matches only remote-cluster nodes |

Note that a v6-only deployment still hard-requires IPv4 masquerade. That is a
consequence of `gateway_ip` being IPv4, not an oversight.

**Enabling the feature forces the tunnel device to be created and the MTU to be
adapted, even in native routing**, because a source node always encapsulates
redirected traffic to the gateway.

#### 3.4.8 What the datapath does (summary; normative text in spec 02)

**Source side**, in `to_netdev` on the host's native device — there is **no**
egress-gateway hook in the pod program:

1. Skip if the packet already carries `MARK_MAGIC_EGW_DONE` (`0x0500`), which
   means it arrived via the overlay already steered. That mark also carries the
   source identity, which is recovered here.
2. Skip if the source is `HOST_ID`.
3. Extract the connection tuple; skip replies — only outbound connections are
   redirected.
4. Refine the source and destination identities from the endpoint map and
   ipcache.
5. **Skip cluster destinations.** "Cluster" here means anything that is not
   `world` or a CIDR identity, so host, remote-node, kube-apiserver, health and
   every pod identity are excluded. This is what makes an in-cluster IP that
   happens to fall inside a destination CIDR not get redirected.
6. Look up the policy (v4_v2, then legacy). Miss → pass.
   `gateway_ip == 0.0.0.0` → **drop 194**. `gateway_ip == 0.0.0.1` → pass.
7. If the gateway is **this node**, fall through to the SNAT path on the same
   program without encapsulating.
8. Otherwise **encapsulate to the gateway's internal IPv4** with VXLAN or
   Geneve, carrying the source security identity in the tunnel header. This is
   why identity survives the hop and policy still applies at the far end, and
   it is why the tunnel device is mandatory.

**Gateway side**, in the masquerade decision (spec 04 §3.12 step 3), which sits
**before** the SNAT-exclusion CIDR check and before the ip-masq-agent lookup —
so **an egress-gateway policy overrides an ip-masq-agent non-masquerade CIDR**:

1. Skip when the destination resolves to a cluster identity: only traffic
   leaving the cluster is masqueraded with an egress IP.
2. Look up the policy; `egress_ip == 0` → **drop 204**. Otherwise SNAT to it.
3. Egress-gateway traffic is never skipped by the low-source-port heuristic.
4. Interface selection: if the packet is already marked done, or the policy's
   ifindex is the current interface, SNAT here. Otherwise use `redirect_neigh`
   when an ifindex is known, no custom routing table is needed and the device
   has an L2 header; else a FIB lookup, with `BPF_FIB_LOOKUP_DIRECT |
   BPF_FIB_LOOKUP_TBID` when a table id is present (from the endpoint's route
   info). A FIB result other than success or no-neighbour is **drop 169**.

On the **overlay ingress** at the gateway, a matching packet has its TTL
decremented, is stamped `MARK_MAGIC_EGW_DONE` with the source identity, has its
interface chosen, and is left for `to_netdev` to SNAT.

**Reply path**, compiled into both the tc host program and the XDP program:
reverse-tuple the policy lookup; if it matches and the destination has a tunnel
endpoint, re-encapsulate the reply back to the pod's node with the source
identity set to `world`. Without this the reply would leave the gateway
unencapsulated and be dropped or wrongly SNATed. Note the XDP variant is the
reason egress-gateway replies are **not encrypted** under XDP acceleration
(§3.1.11 gap G5).

Drop codes: 134 invalid, 169 no FIB, **194** no egress gateway, **204** no
egress IP.

#### 3.4.9 SNAT port limit

For a fixed `(egress IP, remote address, remote port)` tuple every connection
needs a distinct source port, drawn from above the NodePort range:

```
limit = 65535 − (upper bound of --node-port-range)   ≈ 32768 by default
```

Exceeding it evicts old NAT entries and eventually fails to allocate a port.
Widening it means **lowering** the NodePort range's upper bound. There is no
other workaround than fewer connections, more egress IPs, or more remote
addresses. Spec 04 §3.11 owns the allocator.

#### 3.4.10 Health-based failover and CRD status — **DEVIATION**, optional

Neither exists in the reference: gateway selection is label match plus lexical
node ordering (or an FNV modulo), with no liveness input, and the CRD has no
status subresource, so nothing in the API says which node was selected, whether
its egress IP resolved, or that a policy was rejected — a rejected policy is a
warn-level agent log. A gateway node that Kubernetes still reports as ready but
that cannot forward keeps being selected; the only failover is removing its
label or its CiliumNode, which reshuffles every multi-gateway assignment.

flowsdn SHOULD add both, behind flags defaulting to the reference behavior:

**(a) `egress-gateway-health-check` (default `off`).** When `on`, a gateway
candidate is eligible only while its node is reachable, reusing the existing
node health probe (`cilium-health`, spec 08) rather than adding a new one, with
a failure threshold and a hold-down so a single missed probe does not move
traffic. Selection then filters the candidate list before sorting, so the single
gateway falls to the next node in name order and the multi-gateway modulo runs
over the healthy subset.

**Recommendation: implement it, default it off.** It fixes a real
availability gap, and the cost is bounded because the probe already exists. It
must default off because turning it on changes the modulo denominator and thus
reshuffles multi-gateway assignments the moment any node is briefly unhealthy —
strictly worse than the static behavior for a cluster whose gateways are stable.
Pairing it with a rendezvous hash (§12 decision 6) removes that objection and
is the combination worth building.

**(b) A `status` subresource** on flowsdn's own CRD, written by the agent
running on the selected gateway (and by any agent for a parse failure), with:
observed generation; the selected gateway node name and IP per gateway entry;
the resolved egress IP, interface and ifindex; the number of matched endpoints;
the number of programmed map entries; and a `conditions` list carrying
`Accepted` (false with a reason for every rejection in §3.4.2) and, when health
checking is on, `GatewayReady`.

**Recommendation: implement it.** Adding a status subresource is backward
compatible — the reference's schema declares no subresources, and a client that
ignores `status` is unaffected — and it converts the area's worst operational
property, a silently dropped policy, into an observable one. The write must be
throttled and confined to the gateway node to avoid every agent contending on
the same object.

### 3.5 BPF ip-masq-agent

`enable-ip-masq-agent` (default false) and `ip-masq-agent-config-path`
(default `/etc/config/ip-masq-agent`). Requires BPF masquerade. When disabled
nothing is created.

**Config file**, YAML or JSON (JSON being a strict subset — the file is
converted to JSON and then decoded, and unknown fields are ignored):

```yaml
nonMasqueradeCIDRs: ["10.0.0.0/8", "fd00::/8"]
masqLinkLocal: false
masqLinkLocalIPv6: false
```

Exactly three field names. Each CIDR is parsed as a prefix and **masked**, so
`2.2.2.2/16` is stored and programmed as `2.2.0.0/16`, and the masked canonical
string is the diffing key. Both families may appear in one list.

**Defaults** apply only when the file is **absent** or **zero bytes**:

```
10.0.0.0/8       172.16.0.0/12   192.168.0.0/16   100.64.0.0/10
192.0.0.0/24     192.0.2.0/24    192.88.99.0/24   198.18.0.0/15
198.51.100.0/24  203.0.113.0/24  240.0.0.0/4
```

Eleven IPv4 prefixes; there are **no IPv6 defaults**. A file that parses but
whose `nonMasqueradeCIDRs` is null or empty is **not** "empty": the defaults do
**not** apply, and the result is the link-local entries alone. flowsdn MUST
reproduce this distinction — it is the difference between "no config" and
"config that masquerades everything".

**Link-local.** `169.254.0.0/16` is added unless `masqLinkLocal` is true;
`fe80::/10` unless `masqLinkLocalIPv6` is true. Both default false, so
link-local is non-masqueraded by default. They are added after the defaults and
regardless of whether any user CIDR was listed.

**Maps.** `cilium_ipmasq_v4` (key `{prefixlen u32, addr[4]}`) and
`cilium_ipmasq_v6` (key `{prefixlen u32, addr[16]}`), LPM, 16384 entries,
`NO_PREALLOC | RDONLY_PROG`, value one padding byte. The prefix length is the
**plain mask length with no static offset** — unlike the egress maps. Each map
is created only when its family's masquerade is enabled. The datapath looks the
destination up with a full-length key and, on a hit, does not SNAT (spec 04
§3.12 step 6) — after the egress-gateway hook, which therefore overrides it.

**Watch and reload.** Watch the **containing directory**, not the file: a
Kubernetes ConfigMap update swaps a symlinked `..data` directory and never
touches the file inode, so a file watch sees nothing. Create, write, chmod,
remove and rename all trigger a full re-read and diff. There is **no periodic
resync** in the reference; flowsdn SHOULD add a low-frequency re-read as a
backstop against a missed event. A watcher that cannot be created is a **fatal**
startup error.

**Startup restore.** Dump the pinned map into the in-memory "currently
programmed" view **before** the first update. Because the map is pinned and
survives an agent restart, this makes the first diff a no-op when the config is
unchanged, so masquerade behavior does not flap across a restart. A dump failure
is logged and startup continues with an empty view (producing redundant but
harmless writes).

**Diff sync**: additions first, then removals, keyed by the masked canonical
string. flowsdn MUST check the BPF write result and MUST NOT record an entry as
programmed when the write failed — the reference discards both results and can
therefore believe the map is correct forever after one failed write.
**DEVIATION** (correctness).

**Malformed config**: bad YAML, a wrong-shaped document, a non-string list
element or an unparseable prefix all abort the update **before** any in-memory
state changes. The error is logged at warn, the **BPF map keeps its previous
contents**, the agent does not exit and does not fall back to the defaults, and
the next event retries.

## 4. Data model

### 4.1 BPF maps written by this spec

Layouts and pinning are normative in spec 01 §4; repeated here only as the
writer's contract.

| Map | Type | Key | Value | Entries | Writer |
|---|---|---|---|---|---|
| `cilium_encrypt_state` | ARRAY | `u32` (always 0), 4 B | `{encrypt_key u8}`, 1 B | 1 | IPsec agent only |
| `cilium_node_map_v2` | HASH | `{pad1 u16, pad2 u8, family u8, ip [16]}`, 20 B | `{node_id u16, spi u8, pad u8}`, 4 B | `bpf-node-map-max`, ≥ 16384 | node ID allocator (spec 10) |
| `cilium_egress_gw_policy_v4` | LPM | `{prefixlen u32, saddr be32, daddr be32}`, 12 B | `{egress_ip be32, gateway_ip be32}`, 8 B | `egress-gateway-policy-map-max` | egress gateway |
| `cilium_egress_gw_policy_v4_v2` | LPM | same 12 B | `{egress_ip, gateway_ip, reserved[3] u32, egress_ifindex u32, reserved2 u32}`, 28 B | same | egress gateway |
| `cilium_egress_gw_policy_v6` | LPM | `{prefixlen u32, saddr v6, daddr v6}`, 36 B | `{egress_ip v6, gateway_ip be32, reserved[3], egress_ifindex, reserved2}`, 40 B | same | egress gateway |
| `cilium_ipmasq_v4` / `_v6` | LPM | `{prefixlen u32, addr}`, 8 / 20 B | `{pad u8}`, 1 B | 16384 | ip-masq-agent |

IPv4 addresses in a 16-byte field occupy the **low four bytes**, the rest zero.
`EGRESS_POLICY_MAP_SIZE` is emitted as a datapath constant **unconditionally**,
even when the feature is off.

### 4.2 Kernel objects

| Object | Family | Owner |
|---|---|---|
| link `cilium_wg0`, kind `wireguard`, MTU, up | rtnetlink | §3.1.1 |
| WireGuard device config: private key, listen port 51871, fwmark `0x0E00`, peers, allowed IPs | generic netlink, family `wireguard` | §3.1.4–5 |
| XFRM states and policies (§3.2.5), with mark, output-mark, ESN, replay window, templates | `NETLINK_XFRM` | §3.2 |
| ip rule prio 1 `fwmark 0x0D00/0x0F00 → table 200`; routes in table 200 | rtnetlink | spec 10, contract in §3.2.6 |
| `net.ipv4.conf.cilium_wg0.rp_filter = 0`; `net.ipv4.conf.<egress-iface>.rp_filter = 2` | procfs | §3.1.1, §3.4.4 |
| `notrack` on the encrypt/decrypt marks and on UDP 51871 | nftables (ADR-0003) | spec 10 §3.10 |

### 4.3 Files

| Path | Format | Mode |
|---|---|---|
| `<state-dir>/cilium_wg0.key` | 32 raw bytes | `0600` |
| `--ipsec-key-file` (Helm: `/etc/ipsec/keys`) | §3.2.1 | mounted secret |
| `<--ip-masq-agent-config-path>` | YAML or JSON, §3.5 | mounted ConfigMap |
| `/proc/sys/kernel/random/boot_id` | UUID text | read |
| `/proc/net/xfrm_stat` | procfs counters | read |

### 4.4 In-memory state

| Type | Contents |
|---|---|
| `WgPeer` | public key, endpoint, node IPv4/IPv6, `allowed`, `pending_insert`, `pending_remove` prefix sets |
| `WgPeerTable` | by node name, by public key, by node IP — all three updated only after a successful kernel write |
| `IpsecKey` | SPI, `KeyLen`, reqid, and one of AEAD or (auth, crypt) algorithm plus key material |
| `KeyRemovalTimes` | SPI → the instant it was superseded (§3.2.8) |
| `XfrmPlan` | the pure function `(local node, remote node, config) → desired states, policies, routes` |
| `XfrmStateCache` | the dump plus its 1-minute deadline (§3.2.10) |
| `PolicyConfig` | policy name, endpoint selectors, the flat node-selector list, destination and excluded CIDRs, gateway configs, matched endpoints, families needed |
| `GatewayConfig` | interface name, ifindex, egress IPv4/IPv6, gateway IPv4, whether the local node is this gateway |
| `EndpointMetadata` | UID, identity labels, IPs, node IP |
| `IpMasqState` | the config's CIDR set and the set believed to be in the map |

### 4.5 Node object fields consumed and produced

`spec.encryption.key` (`0xFF` for WireGuard, the advertised SPI for IPsec, `0`
when off or opted out); `spec.bootid`; annotation
`network.cilium.io/wg-pub-key`; annotation
`network.cilium.io/encryption-key`. Spec 10 §3.3 owns publication; §3.1.3 and
§3.2.8 own the values.

## 5. Algorithms

Each is stated once here as the interoperability contract; the surrounding
behavior is in §3.

**5.1 IPsec per-node-pair key** — §3.2.3. Two implementations interoperate only
if they agree on: concatenation order, IPv4 canonicalized to 4 bytes, boot IDs
as 36 raw ASCII bytes, SHA-256 below or at a 32-byte global key and SHA-512
above, and truncation to the global key's length.

**5.2 Minimum-SPI negotiation** — §3.2.7. Note it is not `min`: the two
wraparound cases return 15 when the other side is at 1.

**5.3 Rotation predicate** — `current == (active % 15) + 1`. Not "greater than".

**5.4 Stale-key reclaim eligibility** — §3.2.8: not current, has a recorded
replacement time (an SPI first seen this pass gets its clock started and is not
reclaimed), and that time is at least one rotation duration old.

**5.5 XFRM conflict identification** — §3.2.9: same SPI, both marked or both
unmarked, `new.value & new.mask & existing.mask == existing.value`, destination
equal, **source not compared**.

**5.6 WireGuard AllowedIPs diff** — §3.1.5: queue with mutual cancellation,
apply additions first, then removals via the all-zero dummy peer, then commit
the queues.

**5.7 Egress-gateway single selection** — nodes sorted by **name**, first label
match whose internal IPv4 converts.

**5.8 Egress-gateway multi selection** — gateways sorted by **IP**, then
`FNV-1a-32(endpoint UID bytes) mod n` over the *resolved* gateways only.

**5.9 Egress map key** — `prefixlen = static (32 or 128) + destination bits`,
source exact, destination longest-prefix; exclusions win by being longer.

**5.10 Full-diff reconciliation** — §3.4.6, with the two deviations: abort on a
dump error, and iterate policies in name order.

**5.11 Key-load jitter** — uniform over `[0, ipsec-key-rotation-duration / 10)`.

**5.12 Reconciler backoff** — the WireGuard MTU reconciler and the peer-GC task
use exponential backoff from 100 ms to 1 min; the CiliumEndpoint stream uses
20 ms to 20 min, matching the identity allocator.

## 6. Configuration

### 6.1 WireGuard

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-wireguard` | bool | `false` | Master switch. Mutually exclusive with `enable-ipsec` |
| `encrypt-node` | bool | `false` | Node-to-node encryption (beta), §3.1.7 |
| `node-encryption-opt-out-labels` | label selector | `node-role.kubernetes.io/control-plane` | §3.1.7. Parse failure is fatal. Empty forces control-plane nodes in |
| `wireguard-persistent-keepalive` | duration | `0` (off) | Set on every peer |
| `wireguard-track-all-ips-fallback` | bool | `false`, **hidden** | Force ipcache-derived AllowedIPs in tunnel mode |

### 6.2 IPsec

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-ipsec` | bool | `false` | Master switch |
| `ipsec-key-file` | string | `""` | Key file path; Helm renders `/etc/ipsec/keys` |
| `enable-ipsec-key-watcher` | bool | `true` | When false a rotation needs an agent restart |
| `ipsec-key-rotation-duration` | duration | `5m` | Stale-key reclaim age, and (÷10) the jitter bound |
| `enable-ipsec-xfrm-state-caching` | bool | `true`, **hidden** | The 1-minute state-list cache |
| `use-cilium-internal-ip-for-ipsec` | bool | `false`, **hidden** | Subnet-encryption OUT tunnel endpoints |
| `dnsproxy-insecure-skip-transparent-mode-check` | bool | `false`, **hidden** | Bypasses a fatal check; proxied DNS then leaves the node in clear |
| `bpf-node-map-max` | u32 | `16384` | `cilium_node_map_v2` size; values below 16384 are refused |

### 6.3 Strict mode (both encryption types where noted)

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-encryption-strict-mode-egress` | bool | `false` | §3.1.12; applies to IPsec too |
| `encryption-strict-egress-cidr` | CIDR | `""` | IPv4 only; a bad or non-IPv4 value is fatal |
| `encryption-strict-egress-allow-remote-node-identities` | bool | `false` | Required when the node IP is inside the strict CIDR |
| `enable-encryption-strict-mode-ingress` | bool | `false` | WireGuard only; with IPsec it is fatal |

### 6.4 Egress gateway and ip-masq-agent

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-egress-gateway` | bool | `false` | Master switch; forces tunnel-device creation |
| `egress-gateway-reconciliation-trigger-interval` | duration | `1s` | Debounce |
| `egress-gateway-policy-map-max` | int | `16384` | Sizes all three maps |
| `enable-ip-masq-agent` | bool | `false` | Master switch |
| `ip-masq-agent-config-path` | string | `/etc/config/ip-masq-agent` | The **directory** of this path is watched |

### 6.5 Helm mapping

| Helm value | Agent key |
|---|---|
| `encryption.enabled` + `encryption.type=wireguard\|ipsec` | `enable-wireguard` / `enable-ipsec` |
| `encryption.nodeEncryption` | `encrypt-node` |
| `encryption.wireguard.persistentKeepalive` | `wireguard-persistent-keepalive` |
| `encryption.ipsec.{secretName,keyFile,mountPath}` | mount + `ipsec-key-file` |
| `encryption.ipsec.keyWatcher` | `enable-ipsec-key-watcher` |
| `encryption.ipsec.keyRotationDuration` | `ipsec-key-rotation-duration` |
| `encryption.strictMode.egress.{enabled,cidr,allowRemoteNodeIdentities}` | the three egress strict keys |
| `encryption.strictMode.ingress.enabled` | `enable-encryption-strict-mode-ingress` |
| `egressGateway.{enabled,reconciliationTriggerInterval,maxPolicyEntries}` | the three egress-gateway keys |
| `ipMasqAgent.{enabled,config.*}` | `enable-ip-masq-agent` + the mounted ConfigMap |

### 6.6 Accepted and ignored, or rejected

| Key | Disposition |
|---|---|
| `encryption.ipsec.interface` (Helm) | **Accepted and ignored**, with a warning. It was already a no-op in the reference and its agent flag is gone (§3.2.6) |
| `--encrypt-interface` | **Rejected**: unknown flag. It does not exist at this tag |
| `--enable-ipsec-encrypted-overlay` | **Rejected**: encrypted overlay is unconditional in tunnel mode |
| `--enable-encryption-strict-mode`, `--encryption-strict-mode-cidr`, `--encryption-strict-mode-allow-remote-node-identities` | **Rejected**: the pre-1.18 names. The error names the `-egress` replacement |
| `--install-egress-gateway-routes` | **Rejected**: removed |
| `encryption.type=ztunnel` | Out of scope here (`16-l7-envoy-dns.md`) |
| `--enable-vtep`, `--enable-srv6` and their companions | **Rejected** while deferred (§1.2), with a message saying so |

**Resolved #19 — ENI route ownership.** Removal of the old egress-gateway
route-installation switch does not eliminate per-interface IPAM routing. ENI
uses priority 111 with table `10 + interface-number`; Azure alone retains
priority 110 and table `ifindex`. A lookup rule is insufficient without its
shared gateway host route and default route. IPAM supplies the gateway, CIDRs,
master MAC and interface number in its allocation response. The CNI ADD path
installs the pod rules **and** those routes through `RoutingInfo::Configure`;
the agent installs infrastructure endpoint routing and reconciles shared
gateway routes. This is the spec 07 §3.20 / spec 10 routing responsibility,
not an additional egress-gateway manager route writer. Endpoint deletion removes
its rules and preserves shared per-interface routes. Pinned-reference evidence:
`plugins/cilium-cni/cmd/interface.go:71`,
`pkg/datapath/linux/routing/routing.go` (`Configure`, `installRoutes`,
`ReconcileGatewayRoutes`, `computeTableIDFromIfaceNumber`), and
`daemon/infraendpoints/infra_ip_allocation.go:305–322`, commit `7d68cfb394`.
This confirms the ownership contract; ENI cloud runtime validation remains pending.

### 6.7 Mutually exclusive and fatal combinations

WireGuard + IPsec. IPsec + strict **ingress**. IPsec + host firewall. IPsec + a
pinned local router IP. IPsec + L7 proxy without DNS-proxy transparent mode
(overridable only by the hidden insecure flag). IPsec or WireGuard without the
CiliumNode CRD. IPsec + tunneling on a kernel without XFRM output-mark masks.
Egress gateway without CRD identities, without BPF+IPv4 masquerade, without
kube-proxy replacement, without an IPv4 underlay, or with CiliumEndpointSlice.
Strict egress with the node IP inside the strict CIDR and remote-node
identities disallowed.

## 7. Failure modes

| # | Failure | Behavior |
|---|---|---|
| F1 | **Key rotation mid-flight** — the file changes while nodes are at mixed SPIs | Both keys are installed simultaneously (key count doubles). Each pair uses the minimum SPI (§3.2.7), so a node still on the old key is still reachable. The old key is removed only one full `ipsec-key-rotation-duration` after it was superseded. Failure to complete inside that window is the documented cause of `XfrmInNoStates`; the remedy is a longer duration, not a faster reclaim |
| F2 | **Agent restarts mid-rotation** | The active SPI is recovered from `cilium_encrypt_state`; if the file's SPI is its successor, publication is **deferred** until the datapath is up and the old SPI keeps being advertised. Every SPI whose replacement time is unknown gets a fresh clock, so nothing is reclaimed for a full rotation period |
| F3 | **Key length changes during rotation** | The load is refused, the old key stays in use, and only an agent restart adopts the new one. This is deliberate: swapping key lengths live breaks IPv6 pod-to-pod |
| F4 | **Key file malformed** | At start: fatal. In the watcher: logged, health degraded, previous key retained, datapath unaffected |
| F5 | **XFRM state divergence** (kvstore lease expiry, kvstore recreated, CiliumNode deleted then agent restarted) | Anti-replay counters go out of sync and the node pair is permanently broken. Detected as sustained `cilium_ipsec_xfrm_error{error="state_protocol"}` or `no_state`. The **only** documented remedy is a key rotation, which re-derives and reinstalls every state. flowsdn MUST keep that property and SHOULD surface it in the status message |
| F6 | **Node ID missing for a peer** | Drop 197 at the source. Expected during churn (a CiliumNode not yet seen, a deleted node, a changed node IP) and self-clearing. Sustained drops mean the node watch is broken, not the encryption |
| F7 | **Node ID pool exhausted** (> 65535 nodes) | The node gets no ID and no XFRM configuration, and an error is reported. flowsdn MUST NOT map an address to ID 0 — that would be read as "local node" |
| F8 | **WireGuard peer churn** | AllowedIPs move via the dummy peer (§3.1.5) with a two-message window during which a moving prefix can drop packets (GH-33159). A failed apply leaves the queue intact and the periodic node validation retries; no separate retry loop exists |
| F9 | **Duplicate WireGuard public key across two nodes** | The second is refused with an error naming both nodes and no state changes. A cluster in this condition needs one node to regenerate its key |
| F10 | **WireGuard key file corrupt** | Fatal. Regenerating would silently change the node's public key and, under node encryption, could lock the node out of the API server |
| F11 | **Node encryption bootstrap lock-out** | Prevented by the opt-out label (§3.1.7). If an operator empties the selector and a control-plane node's key changes, that key must be written into the CiliumNode by hand |
| F12 | **Gateway node down** | Nothing happens. Selection has no liveness input; traffic keeps being encapsulated to a dead node and is lost. Removing the label or the CiliumNode fails over — and reshuffles every multi-gateway assignment. §3.4.10 specifies the optional fix |
| F13 | **Gateway selector matches nothing** | Map entries are still written with `gateway_ip = 0.0.0.0` and traffic is **dropped** (194), not leaked out of the node's own address |
| F14 | **Gateway egress IP cannot be derived** | The gateway drops with 204. Only the gateway is affected; the sentinel is indistinguishable from "not the gateway" in the map, which is why the check lives on the SNAT path |
| F15 | **Egress map full** | Writes fail and are logged; the pass continues and retries next interval. Visible as `cilium_bpf_map_pressure` approaching 1 |
| F16 | **Egress map dump fails** | flowsdn aborts the pass and retries. The reference would treat every entry as stale and delete the map (§3.4.6) |
| F17 | **Gateway address changes** | Nothing re-derives until the policy is re-applied or a node event arrives. Documented, not automatic |
| F18 | **SNAT ports exhausted at the gateway** | Old NAT entries are evicted, then allocation fails. §3.4.9 |
| F19 | **ip-masq-agent config malformed** | Update aborts before any state changes; the map keeps its contents; retried on the next event |
| F20 | **ip-masq-agent BPF write fails** | flowsdn does not record the entry as programmed and retries. The reference records it regardless and never re-attempts |
| F21 | **Restart with a layout change in an egress or node map** | Spec 01 §3 owns map-version migration; this spec requires only that node IDs be restored **before** any new allocation, or in-flight encrypted traffic breaks |
| F22 | **Kernel lacks WireGuard, or XFRM output-mark masks** | Fatal at startup with a message naming the kernel requirement (ADR-0001: refuse to run, no adaptive fallback) |

## 8. Observability

### 8.1 Metrics

Reference-compatible names; dashboards depend on them.

| Metric | Type | Labels | Source |
|---|---|---|---|
| `cilium_ipsec_xfrm_error` | gauge | `type` ∈ {`inbound`,`outbound`}, `error` | `/proc/net/xfrm_stat` |
| `cilium_ipsec_keys` | gauge | — | count of distinct SA key material |
| `cilium_ipsec_xfrm_states` | gauge | `direction` ∈ {`in`,`out`} | mark magic of each state |
| `cilium_ipsec_xfrm_policies` | gauge | `direction` ∈ {`in`,`out`,`fwd`} | policy direction |
| `cilium_bpf_map_pressure` | gauge | `map_name` for the three egress maps and both ip-masq maps | spec 01 |
| `cilium_drop_count_total` | counter | `reason` 160, 169, 194, 195, 197, 204 | datapath |
| `cilium_feature_adv_connect_and_lb_transparent_encryption` | gauge | mode (`wireguard`/`ipsec`), node-to-node, strict | set once at start |
| `cilium_feature_adv_connect_and_lb_egress_gateway_enabled` | gauge | — | set once at start |

`error` values: `other`, `no_buffer`, `header`, `no_state`, `state_protocol`,
`state_mode`, `state_sequence`, `state_expired`, `state_mismatched`,
`state_invalid`, `template_mismatched`, `no_policy`, `policy_blocked`, `policy`,
`forward_header`, `acquire` (inbound); `other`, `bundle_generation`,
`bundle_check`, `no_state`, `state_protocol`, `state_mode`, `state_sequence`,
`state_expired`, `policy_blocked`, `policy_dead`, `policy`, `state_invalid`
(outbound). Note `forward_header` and `acquire` are labelled `inbound` in the
reference even though they are not inbound errors; flowsdn keeps the labelling
for dashboard compatibility.

The two operationally load-bearing series: `policy_blocked` **outbound** counts
packets the default drop policy stopped from leaving in plaintext — a non-zero
value is the encryption working, not a fault; `no_state` **inbound** rising
means a key was reclaimed before every peer installed the new one.

**DEVIATION**, additions (no reference name to collide with):
`flowsdn_wireguard_peers`, `flowsdn_wireguard_peer_last_handshake_seconds`,
`flowsdn_egressgw_map_entries`, `flowsdn_egressgw_reconciliations_total`,
`flowsdn_egressgw_gateway_selected{policy,node}`. The last two make F12 and F16
observable without a CRD status.

### 8.2 Status and CLI

`GET /healthz` field `encryption`, refreshed every 5 s:
`{mode: Disabled|IPsec|Wireguard, msg, ipsec{…}, wireguard{…}}`, with
`WireguardStatus` as in §2.6. `cilium-dbg status` renders
`Encryption: Wireguard [NodeEncryption: Disabled, cilium_wg0 (Pubkey: …, Port: 51871, Peers: N)]`.

`cilium-dbg encrypt status` reports the mode, the **decryption interfaces**
(every link carrying the host ingress program), `Keys in use`, the maximum
sequence number (or `N/A`), and the total plus a per-field breakdown of the
XFRM error counters. `Keys in use` is the primary rotation signal: it doubles
at the start of a rotation and halves when reclaim completes.

`cilium-dbg encrypt flush` deletes XFRM objects, filtered by SPI, node id, or
`--stale` (everything whose encoded node id is non-zero and absent from
`cilium_node_map_v2`); `--stale` cannot be combined with the other filters.
Unfiltered it flushes everything and MUST prompt.

`cilium-dbg bpf egress list` renders the three maps with `gateway_ip` `0.0.0.0`
shown as **`Not Found`** and `0.0.0.1` as **`Excluded CIDR`**, reading v4_v2
first and falling back to the legacy map. `cilium-dbg bpf ipmasq list` and
`cilium-dbg bpf nodeid list` dump their maps.

### 8.3 Trace and drop events

`TRACE_FROM_CRYPTO` and `TRACE_TO_CRYPTO` observation points; the `ENCRYPTED`
flag in the trace reason. Hubble labels a flow WireGuard-encrypted from UDP with
source port == destination port == 51871 from a remote-node identity. Drop
reasons 160, 169, 194, 195, 197, 204.

### 8.4 Health entries

`encryption/wireguard-device`, `encryption/wireguard-mtu` (reporting the
applied MTU), `encryption/wireguard-peer-gc`, `encryption/ipsec-keyfile`,
`encryption/ipsec-xfrm`, `egressgw/reconciler`, `ipmasq/config`. Each degrades
with the underlying error and recovers on the next successful pass.

## 9. Test plan

Legend: **U** unit (no privileges), **P** privileged (netns, real kernel
objects), **E** end-to-end (cluster).

### 9.1 WireGuard

- U: key file — absent generates; 32 bytes loads; wrong length is an error, not a regeneration.
- U: endpoint selection across all four branches of §3.1.4 step 8, including tunnel + IPv6 underlay preferring IPv6.
- U: duplicate public key rejected, both node names in the error, no state change.
- U: changed public key removes the old peer first and rebuilds.
- U: the all-zero key is rejected as a node key.
- U: AllowedIPs queue — insert cancels a pending remove and vice versa; a failed apply leaves the queue intact.
- U: `needsIPCache` truth table over routing mode × the fallback flag.
- U: MTU formula and the 1280 clamp, with and without IPv6.
- U: opt-out selector matching, and that the endpoint encrypt key stays `0xFF` for an opted-out node.
- P: real `cilium_wg0` — creation, fwmark, listen port, `rp_filter`, deletion when disabled, `EOPNOTSUPP` surfaced as the kernel message.
- P: the dummy-peer removal path — prefix moves off the real peer and the dummy is gone afterwards; additions precede removals.
- P: peer GC removes an unknown peer and an unexpected AllowedIP, and does **not** run before every sync signal has fired.
- P: MTU reconciler follows the MTU table and issues no netlink call when the MTU already matches.
- E: pod-to-pod encryption; node-to-node encryption; the opt-out node; strict egress; strict ingress; ClusterMesh across two WireGuard clusters.
- E: **plaintext-leak detection** — a probe on the transmit path asserting no cluster-internal pod traffic leaves unencrypted, with the documented exemptions (ICMPv6 NA, the G1 propagation window, same-node traffic). This is the single highest-value test in the area; the reference runs its equivalent before and after every key rotation.

### 9.2 IPsec

- U: key file grammar — 4-field and 5-field forms; 3 fields is an **error, not a panic**; 6 fields rejected; SPI 0, 16 and non-numeric rejected; `+` stripped and ignored; `0x` accepted; `""` yields a zero-length key; ICV outside {96,128,256} rejected; an AEAD name not starting with `rfc` rejected.
- U: `KeyLen` — `icv/8` for AEAD, hex-character count for the pair form.
- U: last line wins; two lines with the same SPI fail; a failed load leaves the previous key in force (and, for flowsdn, leaves **nothing** partially applied).
- U: rotation predicate across 1→2, 15→1, 2→1, 1→1, 1→3, and zero on either side.
- U: key-length change refused; SPI unchanged refused.
- U: key derivation vectors — IPv4 as 4 bytes; boot IDs as 36 ASCII bytes; SHA-256 at 32 bytes and SHA-512 above; truncation; OUT on A equals IN on B for the same pair. **Cross-implementation vectors MUST be committed to the repository.**
- U: a short boot ID is an error, not a panic; an empty remote boot ID yields no XFRM objects.
- U: `XfrmPlan` golden output for every variant in §3.2.5 — native, tunnel with encrypted overlay, subnet encryption, endpoint routes — asserting every mark, mask, priority, ESN, replay window, reqid and template.
- U: minimum-SPI negotiation, all 15×15 pairs plus zeros.
- U: stale-reclaim eligibility, including the first-seen-gets-a-fresh-clock rule and the default-drop exemption.
- U: conflict identification — same SPI and destination with a differing source **does** conflict.
- P: state upsert is idempotent; an identical state is a no-op; `RemoteRebooted` forces delete-then-add.
- P: `EEXIST` recovery deletes the conflicting state and retries exactly once.
- P: the general-vs-specific IN state workaround — the specific state is deleted and the general one survives.
- P: the default drop policy exists before any OUT policy is installed.
- P: `DeleteXFRM` removes only Cilium-owned objects and leaves a foreign SA untouched.
- P: the output-mark probe passes on a supported kernel and its failure is fatal.
- P: the state cache — a repeated no-op validation issues one dump per TTL, and every mutation invalidates first.
- E: pod-to-pod over IPsec, native and tunnel (encrypted overlay); key rotation with a plaintext-leak probe **before and after**, asserting `Keys in use` doubles then halves; a node reboot re-keying via the boot ID; node churn leaving no XFRM leak.

### 9.3 Egress gateway

- U: every rejection in §3.4.2, and that parsing does **not** mutate the input object.
- U: the full family cross-product — v6 egress IP with v4 destinations, v4 with v6, dual-stack destinations with each of a v4 egress IP, a v6 egress IP and an interface — all six succeed.
- U: namespace-selector translation, including the empty-selector catch-all and the `k8s:` prefixing.
- U: the flattened node-selector cross-product of §3.4.2.
- U: gateway selection — name ordering; no match yields the drop sentinel; a node whose IPv4 does not convert is skipped.
- U: multi-gateway — sorted by IP, `FNV-1a-32(UID) mod n`, with vectors committed; only resolved gateways occupy slots.
- U: map key construction — prefix lengths 32+bits and 128+bits; the destination stored unmasked.
- U: sentinels — no gateway, excluded CIDR, no egress IP; and that excluded entries carry the real egress IP.
- U: exclusion wins by prefix length; a non-subset exclusion has no effect.
- U: full-diff — unchanged entries are not rewritten, stale entries are deleted, and a **dump error aborts the pass** (flowsdn's deviation).
- U: policies iterate in a deterministic order across repeated passes.
- P: end-to-end map contents through node, endpoint and policy add and delete; `egress_ip` and `egress_ifindex` are zero on non-gateway nodes; the `egressIP` case leaves the ifindex at 0.
- P: node-selector filtering by node IP, with both event orders around an endpoint IP change leaving no stale entries.
- P: `rp_filter = 2` is applied per gateway interface and accumulates across a policy change.
- P: each requirement in §3.4.7 aborts startup with its own message.
- E: connectivity through a gateway; excluded CIDRs; egress gateway with an L7 policy; multi-gateway assignment stability; egress gateway under WireGuard (and the documented XDP reply gap); upgrade with an egress-gateway policy in place.

### 9.4 ip-masq-agent

- U: masking (`2.2.2.2/16` → `2.2.0.0/16`); YAML and JSON both accepted; unknown fields ignored.
- U: the empty-vs-null distinction — a missing or zero-byte file yields the 11 defaults plus link-local; a file with a null `nonMasqueradeCIDRs` yields **only** link-local.
- U: `masqLinkLocal` and `masqLinkLocalIPv6` each suppress their prefix; there are no IPv6 defaults.
- U: diff sync — additions before removals; a failed write is **not** recorded as programmed (flowsdn's deviation).
- U: every malformed-config case leaves the previous state untouched.
- P: restore from a pre-populated pinned map writes nothing when the config is unchanged.
- P: a ConfigMap-style symlink swap in the watched directory triggers a reload.
- P: map key prefix length is the plain mask length, with no static offset.

### 9.5 Node IDs

- U: allocation, reuse across a node's addresses, and the SPI refresh.
- U: exhaustion returns an error and maps **nothing** to ID 0.
- U: an address mapped to a different ID triggers a full unmap and retry.
- P: restore rebuilds both indexes, removes restored IDs from the pool, deletes ID-0 entries, and reports if it ran after an allocation.

## 10. Kernel and platform requirements

Per `docs/kernel-requirements.md`: general minimum **6.6 LTS**, supported line
**6.12** (stormcos). Everything here works on both. ADR-0001 applies — a missing
requirement is a **startup refusal**, never an adaptive fallback.

| Feature | Requirement |
|---|---|
| WireGuard | `CONFIG_WIREGUARD` (in-tree from 5.6) and its crypto selects; the generic-netlink `wireguard` family; tcx ingress on `cilium_wg0`, and egress only when §3.1.9 requires it. **XDP is never attached to `cilium_wg0`.** ChaCha20-Poly1305 has NEON paths on arm64 — throughput only |
| IPsec | `XFRM=y XFRM_USER=m XFRM_ALGO=m XFRM_STATISTICS=y` (the last for `/proc/net/xfrm_stat`), `INET_ESP`/`INET6_ESP`, the XFRM tunnel and IPCOMP modules, and `CRYPTO_{AEAD,AEAD2,GCM,SEQIV,CBC,HMAC,SHA256,AES}`. `NETLINK_XFRM`. **XFRM output-mark masks require ≥ 4.19** and are probed (§3.2.10). `XFRM_OFFLOAD=y` optional. AES-GCM uses AES-NI on x86-64 and ARMv8-CE on arm64 — throughput only. **Decryption is single-core per SA on both architectures** |
| Egress gateway | LPM tries with `NO_PREALLOC` and `RDONLY_PROG`; `bpf_fib_lookup` and `bpf_redirect_neigh` (5.10); `BPF_FIB_LOOKUP_TBID` (6.4+) used only when a routing table id is present; `IP_MULTIPLE_TABLES`; a tunnel device (VXLAN or Geneve); optional XDP for the reply path |
| ip-masq-agent | LPM tries only |
| Node IDs / encrypt map | HASH and ARRAY maps; nothing beyond core BPF |

`/proc/sys/kernel/random/boot_id` MUST be readable when IPsec is enabled.
Sysctls written: `net.ipv4.conf.cilium_wg0.rp_filter = 0` and
`net.ipv4.conf.<egress-iface>.rp_filter = 2` (see `kernel-requirements.md` §4.3
for the persistence problem — `systemd-networkd` re-applies `rp_filter=1` on
hotplug). Netlink families: `NETLINK_ROUTE`, `NETLINK_XFRM`,
`NETLINK_GENERIC` (`wireguard`), `NETLINK_NETFILTER` (ADR-0003 residual).

No architecture-specific behavior. Both architectures are little-endian, so
the `#[repr(C)]` map layouts in §4.1 are byte-identical.

## 11. Rust design notes

### 11.1 `flowsdn-wireguard`

`rtnetlink` for the link (create, MTU, up) and procfs for the sysctl. For the
device configuration, generic netlink on the `wireguard` family. Two dependency
options:

- **`wireguard-control`** — a userspace wrapper that also supports the
  `wg`-userspace backend. Convenient, but it brings a backend flowsdn does not
  want and its key types would leak into the peer table.
- **`netlink-packet-wireguard` + `genetlink` + `netlink-sys`** — the
  lower-level path and the **recommended default**. The three operations
  needed (set device, set peer without replacing peers, remove peer) are a
  small, stable subset, and the dummy-peer trick (§3.1.5) needs precise control
  over the per-peer flags — in particular the ability to **not** set
  replace-allowed-ips, which is the whole point of the workaround.

**Resolved #258 — audited codec and bounded peer fragments.** The exact
`netlink-packet-wireguard = 0.4.0` published crate (MIT; `peer.rs`,
`attribute.rs`, `message.rs`) exposes caller-controlled `Flags` bitfields,
including empty flags, remove-peer, replace-AllowedIPs and update-only. Its
`Emitable` implementation serializes the supplied attributes; it has **no
fragmentation layer**. flowsdn therefore owns fragmentation in
`flowsdn-encryption::wireguard`, using that codec and `netlink-packet-core
= 0.8.0`. Tests decode with `netlink-packet-generic = 0.4.0`.

The planner accepts a device ifindex, caller-controlled replace-peers choice,
and peer operations with public key, flags, optional endpoint/keepalive and
validated address/prefix pairs. It emits one peer per message, splitting its
AllowedIPs without loss or duplication. The budget includes the 16-byte netlink
and 4-byte generic headers and is capped at 60,000 bytes, below the nested
attribute u16 limit. Device replace-peers occurs only in the first message;
peer replace-AllowedIPs and endpoint/keepalive occur only in that peer's first
fragment. Update-only remains on continuations. Remove-peer cannot carry
AllowedIPs, replace-AllowedIPs or endpoint settings. Empty replacement lists
still emit an operation. Reject invalid bounds/prefixes and duplicate peer keys
before returning a plan; no partial plan escapes on failure. Plans cap input at
65,535 peers and 1,000,000 total prefixes.

This follows the kernel [WireGuard generic-netlink contract](https://docs.kernel.org/netlink/specs/wireguard.html).
Published codec source: [version 0.4.0](https://docs.rs/crate/netlink-packet-wireguard/0.4.0/source/).
The future writer must serialize plans per device and await each kernel ACK,
stop on first error, retain the desired state and reconcile after partial
application; fragments are not an atomic transaction. Family discovery, sockets,
ACK processing, dummy-peer workflow integration and live kernel scale checks
remain pending. Unit tests establish wire fragmentation, not a running tunnel.

Key generation with `x25519-dalek`; the private key is 32 raw bytes and the
public key is base64 for publication.

Types: `Device` (the link and its parameters), `PeerTable` (the three indexes),
`Peer` (`allowed`, `pending_insert`, `pending_remove` as `HashSet<IpNet>`),
`AllowedIpDiff`. Two subscribers — node events and ipcache events — feed the
queues; one `MtuReconciler` task follows the MTU table; one `PeerGc` one-shot
awaits the sync fences (spec 00 `Fence`).

### 11.2 `flowsdn-ipsec`

**This is the crate with the real netlink gap.** `netlink-packet-xfrm` exists in
the rust-netlink organization and covers SA and SP add, delete, get and dump
including mark, output-mark, ESN, replay window, AEAD and templates — but there
is **no `rtnetlink`-style high-level async API for XFRM**, so a thin async
wrapper over `netlink-sys` is required regardless. Specific items to verify at
Phase 2 and hand-encode if missing:

| Item | Risk |
|---|---|
| `XFRMA_OUTPUT_MARK` **with a mask** | The mask is the 4.19 addition and the whole probe in §3.2.10 exists to check it. If the crate emits the value-only form, every IN state is wrong |
| `XFRMA_REPLAY_ESN_VAL` | ESN + window 1024 must produce a 32-word bitmap and a **zero** legacy replay window. A read-back reports window 0; comparison logic must not treat that as a diff |
| `XFRMA_MARK` on **policies** as well as states | The OUT policy's mark is what binds it to a node and SPI |
| `XFRMA_TMPL` with `optional`, and with reqid and SPI blanked | The blanked optional template is the *identity* of the catch-all IN and FWD policies (§3.2.9) |
| `XFRM_POLICY_BLOCK` as an action | The default drop policy. Without it there is no plaintext guard |
| Policy `priority` | 0, 100 and 2975 must all be settable |
| `XFRM_MSG_FLUSHSA` / `FLUSHPOLICY` | `encrypt flush` |
| IPv4-mapped IPv6 canonicalization | The kernel returns an unset IPv6 address as a nil IPv4; comparison MUST treat two unspecified addresses as equal |

Recommendation: wrap `netlink-packet-xfrm` behind a `Xfrm` trait with a
hand-encoded fallback per attribute, and upstream the gaps. Budget for
hand-encoding the ESN and output-mark attributes.

Structure: `KeyFile` (parse-then-commit, §3.2.1), `NodePairKeys` (`sha2`),
`XfrmPlan` — a **pure function** from `(local node, remote node, config)` to the
desired object set, which makes §9.2's golden tests possible without a kernel —
`XfrmReconciler` (diff against the cached dump), `StateCache`, `KeyWatcher`
(`notify` on the directory plus a periodic re-stat), `StaleReclaimer`, and a
`/proc/net/xfrm_stat` reader via `procfs`.

### 11.3 `flowsdn-egressgw`

Pure control plane. `kube` watchers for the three resources (the generated
types of `13-crds-k8s-client.md`); `ipnet`/`std::net::IpAddr` for CIDR math; `fnv` for the endpoint hash —
pinned, because the hash is an interoperability contract with every other agent
in the cluster; `aya` LPM handles for the three maps. Device and address lookup
reuses spec 10's device and node-address tables rather than issuing its own
netlink calls; the `rp_filter` write goes through spec 10's sysctl reconciler.

Types: `PolicyConfig`, `GatewayConfig`, `EndpointMetadata`, `EgressKey`/`Value`
(three `#[repr(C)]` pairs), `Reconciler` (debounced, full-diff). Policies are
kept in a `BTreeMap` keyed by name so iteration is deterministic (§3.4.6).

### 11.4 Shared

`flowsdn-ipmasq` is small enough to live inside the agent crate: `notify`,
`serde_yaml` through a JSON value, and two `aya` LPM handles.

Node IDs and the encrypt map belong to `flowsdn-node` (spec 10); this area
consumes them through a trait so `XfrmPlan` stays pure.

Concurrency: one task per reconciler consuming a table watch (spec 00), each
holding its own netlink socket. XFRM writes are serialized behind one handle —
the EEXIST recovery in §3.2.9 is a read-modify-write and is not safe to run
concurrently with itself.

## 12. Decision register (resolved and open)

1. **Encryption constants — resolved #173.** Keep WireGuard UDP port 51871 and IPsec
   reqid 1 fixed. Do not add configuration that silently changes interoperability or
   diagnostic selectors.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

2. **Resolved #174: modern maps by default, guarded migration option.**
   `egress-gateway-legacy-map=false` writes IPv4 v2 and enabled IPv6 maps only.
   Enabling the flowsdn option also synchronizes/prunes legacy IPv4 entries in
   lock-step. Inspect actual loaded readers: a legacy reader with the option
   off, disabled IPv4 or unknown reader ownership is fatal until the operator
   drains/detaches it or enables synchronized migration. Never infer safe takeover
   from the current binary's program set alone. A partial map write must keep
   reconciliation degraded; do not detach old readers until both maps match.
   The library plans enabled maps, not actual map writes or upgrade safety.

3. **Resolved #175: retain IPsec strict-ingress refusal until leak tests.**
   Startup validation rejects IPsec plus strict ingress. A later extension may
   accept IPsec decrypt marks only after plain/encrypted traffic, host/pod paths,
   key rotation, reconnect and mark-spoofing negative tests prove no plaintext
   bypass. This gate follows the first complete IPsec acceptance milestone;
   WireGuard strict ingress remains its existing independent contract. The
   validation helper is delivered, not the datapath extension.

4. **IPsec endpoint-route mark — resolved #176.** Apply zero output mark for enabled
   endpoint routes on both subnet-encryption and single-CIDR IN-state paths. Preserve
   the existing non-endpoint-route mark and mask behavior.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

5. **Node ID width — resolved #177.** Retain u16 node IDs and the existing mark layout.
   Allocate only 1..65535; zero remains local-node sentinel, never an overflow
   substitute. Exhaustion reports failure and must not install unsafe encryption state.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

6. **Resolved #178: reference modulo default, opt-in rendezvous.**
   `egress-gateway-selection=modulo` uses FNV-1a-32 of endpoint UID bytes modulo
   the count of resolved gateways sorted by numeric IPv4 address. Preserve
   duplicate slots. The optional `rendezvous` uses unsigned FNV-1a-64 over UID
   bytes followed by four IPv4 octets; highest score wins, ties choose the lowest
   numeric IPv4. It requires a coordinated all-flowsdn cohort using the same
   algorithm and gateway snapshot; reject unknown/mixed membership. Switching
   algorithm requires a drained/coordinated rollout and rebuilding all relevant
   maps, not a per-agent toggle during traffic. Health failover remains separately
   gated; this pure algorithm does not observe health or ensure distributed
   agreement. Removing a nonwinning gateway preserves the winner; adding a new
   gateway may move an endpoint to that new gateway. Runtime wiring, mixed-peer
   default comparisons and coordinated rollout tests remain required.

   Pinned-reference ambiguity audit (v1.20.1 `7d68cfb394`):
   `pkg/egressgateway/policy.go:363–366` selects standard `fnv.New32a()` over
   endpoint UID bytes; lines 377–385 sort by `gatewayIP.Compare` before modulo.
   The Rust implementation follows that specified algorithm, with independent
   standard FNV vectors and numeric-IP ordering tests. No reference code copied.

7. **Egress selectors — resolved #179.** Keep the reference globally flattened
   node-selector cross-product with pod/namespace matches from §3.4.2. Do not silently
   reinterpret selectors as paired per entry. An upstream proposal, if desired, is
   separate from this local decision.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

8. **Node and encryption ownership — resolved #180.** Spec 10 owns routing table 200,
   its IP rules, node-ID allocation and `cilium_node_map_v2` lifecycle. Spec 14 supplies
   encryption inputs and owns XFRM/WireGuard state; it does not introduce a second
   route/map writer.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

9. **Resolved #181: refuse VTEP and SRv6 while controllers are absent.**
   Keep both feature requests rejected with explicit not-implemented errors;
   map-only stubs must not advertise a working network. VTEP remains planned
   scope with an IPv4 interoperability gate against a concrete VTEP peer.
   Revisit SRv6 when BGP/VRF integration has an owning controller and executable
   routing, policy and isolation tests. These are staged capabilities, not silent
   removal from the complete project scope or a claim that their maps suffice.

10. **IPsec key forms — resolved #182.** Accept both AEAD and auth+crypt key-file forms
   with the §3.2.2 validation and key derivation. Preserve accepted legacy syntax
   including the ignored `+` suffix; do not narrow migration input to AEAD only. Warn
   about nonpreferred algorithms without exposing key material.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

### Additional resolved foundation decisions

- **#6:** all four cloud IPAM providers remain required for the first complete
  networking release (ADR-0001/spec 07). Foundation releases and intermediate
  checkpoints are not that acceptance gate. Per-interface routes, CiliumNode
  fields and provider test matrices remain in scope; no cloud client is delivered
  by this crate.
- **#7:** support IPv4 and IPv6 underlay. `auto` prefers enabled IPv4, otherwise
  enabled IPv6; an explicit family must be enabled, and tunnel peers lacking that
  address fail without cross-family fallback. WireGuard retains its distinct
  four-branch endpoint order in §3.1.4. Enabled node-address inputs only are passed
  to the helper. Live dual-underlay routing/encryption tests remain required.
- **#9:** WireGuard first, then egress gateway/ip-masq-agent, then full IPsec as
  §1.3 specifies. IPsec table 200, node-ID/SPI and XFRM/key-rotation work remain
  mandatory for complete encryption acceptance; intermediate WireGuard delivery
  never closes the IPsec implementation milestone.
- **#31:** support only native IPsec and overlay-inside-IPsec (the 1.18+ layering
  already specified at the pinned reference). Refuse pre-1.18 encrypted-overlay
  mode; drain/migrate before switching, with no uninterrupted takeover claim.
- **#32:** keep `encryption.ipsec.interface` accepted and ignored with a named
  warning when nonempty; selection remains node/device discovery (§3.2.6).
  Do not invent an `encrypt-interface` agent flag or silently select that device.

### Implemented validation boundary

`flowsdn-encryption` supplies family/endpoint selection, modern IPsec layering,
explicit configuration validation, legacy-map planning and deterministic gateway
selection. It does not provide WireGuard/XFRM operations, keys, map writers,
cloud IPAM, node watchers, liveness, leak prevention or safe live migration.
Unit tests establish the local decisions only. Spec 02 additionally owns tested
BPF host-routing/build-plan decisions; actual object instrumentation remains open.
