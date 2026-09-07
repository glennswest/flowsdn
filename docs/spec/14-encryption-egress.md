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
| CRD client/watch plumbing and CRD registration | spec 13 (wave 3) |
| Helm chart rendering | spec 15 (wave 3) |
| **VTEP** integration | **deferred** (inventory 14 recommendation: beta, IPv4-only, niche). The `cilium_vtep_map` ABI is reserved in spec 01; no control plane is written. |
| **SRv6** | **deferred** (inventory 14: OSS ships maps and BPF only, with no control plane to mirror). Revisit with spec 10-BGP. |
| **ztunnel** (`encryption.type=ztunnel`) | area 11 (L7/mesh); it is not transparent encryption in the sense of this spec. |

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
| `cilium_ipmasq_v4` / `_v6` | `{prefixlen u32, addr}` → `{pad u8}`, LPM, 16384, `NO_PREALLOC|RDONLY_PROG` | ip-masq-agent (§3.5) |

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
