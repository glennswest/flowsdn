# Encryption and egress features — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/wireguard/**`,
`pkg/datapath/linux/ipsec/**`, `pkg/datapath/linux/ipsec.go`,
`pkg/datapath/linux/node_ids.go`, `pkg/common/ipsec/**`, `pkg/maps/encrypt`,
`pkg/maps/nodemap`, `pkg/egressgateway/**`, `pkg/maps/egressmap`,
`pkg/maps/srv6map`, `pkg/datapath/vtep`, `pkg/maps/vtep`, `pkg/ipmasq/**`,
`pkg/maps/ipmasq`, `bpf/bpf_wireguard.c`, `bpf/lib/{wireguard,encrypt,ipsec,
egress_gateway,srv6,vtep}.h`, `Documentation/security/network/encryption*.rst`,
`Documentation/network/egress-gateway/**`.

`pkg/crypto/**` at this tag contains only `certificatemanager` and `certloader`
(TLS material for the L7 proxy / Hubble); it has nothing to do with transparent
encryption and is left to area 11.

## Purpose

Three loosely related things live here. (1) Transparent node-to-node
encryption of pod traffic with either WireGuard (kernel `cilium_wg0` device,
peers fed from CiliumNode events, allowed-IPs fed from the ipcache) or IPsec
(kernel XFRM states/policies per remote node, per-node-pair keys derived from
one pre-shared secret, key rotation by SPI increment). (2) Egress Gateway:
`CiliumEgressGatewayPolicy` selects pods and destination CIDRs and steers their
cluster-egress traffic through a chosen gateway node, which SNATs it to a
predictable egress IP; compiled to an LPM BPF map keyed by (pod IP, dst CIDR).
(3) Smaller egress/encap add-ons: BPF ip-masq-agent (non-masquerade CIDR list
from a file), VTEP integration (route selected CIDRs to external VXLAN
endpoints), and the SRv6 datapath (maps + BPF only; no OSS control plane).

## Components

| Path | Lines | Purpose |
|---|---|---|
| `pkg/wireguard/agent/agent.go` | 1035 | WireGuard agent: key gen/load, `cilium_wg0` create, peer upsert/delete, allowed-IPs from ipcache, MTU reconciler, peer GC, status |
| `pkg/wireguard/agent/cell.go` | 116 | Hive cell, flags, `ENABLE_WIREGUARD` / `ENABLE_NODE_ENCRYPTION` defines |
| `pkg/wireguard/agent/node_handler.go` | 61 | `node.Handler` impl → `updatePeer`/`deletePeer` |
| `pkg/wireguard/types/{types,option}.go` | 47 | Constants: port 51871, `cilium_wg0`, `cilium_wg0.key`, `StaticEncryptKey=0xFF`; flag names |
| `pkg/wireguard/fake/wireguard.go` | 60 | Fake agent for tests |
| `pkg/wireguard/agent/*_test.go` | 1118 | Unit + privileged cell test |
| `pkg/datapath/linux/ipsec/ipsec_linux.go` | 1550 | IPsec agent: key file parse, per-node key derivation, XFRM state/policy install, rotation, stale reclaim, keyfile watcher |
| `pkg/datapath/linux/ipsec/cell.go` | 145 | Hive cell, flags, `ENABLE_IPSEC` define |
| `pkg/datapath/linux/ipsec/types/*.go` | 84 | `Agent`/`Config` interfaces, `Parameters` struct |
| `pkg/datapath/linux/ipsec/xfrm_state_cache.go` | 74 | TTL cache (1 min) over `XfrmStateList` |
| `pkg/datapath/linux/ipsec/xfrm_collector.go` | 160 | Prometheus collector from `/proc/net/xfrm_stat` + counts of keys/states/policies |
| `pkg/datapath/linux/ipsec/probe_linux.go` | 79 | Probe for XFRM `output-mark` support (4.19+) using a dummy state |
| `pkg/datapath/linux/ipsec/*_test.go` | 1281 | Unit + privileged XFRM tests |
| `pkg/datapath/linux/ipsec.go` | 893 | Node-handler side: which XFRM policies/states/routes/rules to install per remote node (native, subnet, encrypted-overlay variants) |
| `pkg/datapath/linux/node_ids.go` | 400 | Node ID allocator (uint16, 1..65535), `cilium_node_map_v2` population with (IP → nodeID, SPI) |
| `bpf/lib/wireguard.h` | 169 | `wg_maybe_redirect_to_encrypt`, `ctx_is_wireguard` |
| `bpf/lib/encrypt.h` | 94 | `set_decrypt_mark`, `strict_allow` (egress strict mode), `encrypt_src_matches_policy` |
| `bpf/lib/ipsec.h` | 311 | `cilium_encrypt_state` map, `set_ipsec_encrypt`, `do_decrypt`, `ipsec_maybe_redirect_to_encrypt` |
| `bpf/bpf_wireguard.c` | 386 | `cil_from_wireguard` (tc ingress on `cilium_wg0`), `cil_to_wireguard` (tc egress) |
| `pkg/egressgateway/manager.go` | 925 | Egress GW manager: CEGP/CiliumNode/CiliumEndpoint event loop, reconciliation trigger, map sync, rp_filter relax |
| `pkg/egressgateway/policy.go` | 558 | CEGP parse → `PolicyConfig`; gateway selection; egress IP/iface derivation; multi-gateway hashing |
| `pkg/egressgateway/{cell,resource,endpoint,commands}.go` | 212 | Hive wiring, CEGP resource, CiliumEndpoint metadata, `cilium-dbg shell` commands |
| `pkg/egressgateway/*_test.go` + `testdata/*.txtar` | 2037 | Privileged manager tests, parser tests, script tests |
| `pkg/maps/egressmap/policy.go` | 589 | `cilium_egress_gw_policy_v4`, `_v4_v2`, `_v6` LPM maps; key/value layouts |
| `bpf/lib/egress_gateway.h` | 662 | Policy lookup, request redirect to gateway, gateway-side SNAT decision, reply redirect, FIB redirect on egress iface |
| `pkg/maps/srv6map/*.go` | 893 | `cilium_srv6_vrf_v{4,6}`, `cilium_srv6_policy_v{4,6}`, `cilium_srv6_sid` maps (no OSS writer) |
| `bpf/lib/srv6.h` | 475 | SRv6 encap (reduced / SRH) and decap |
| `pkg/datapath/vtep/*.go` | 287 | VTEP manager: `cilium_vtep_map` entries, routes in table 202 + ip rule |
| `pkg/maps/vtep/*.go` | 204 | `cilium_vtep_map` (hash, 8 entries) |
| `bpf/lib/vtep.h` | 29 | Map decl + `vtep_mask` config |
| `pkg/ipmasq/ipmasq.go` + `cell/` | 374 | ip-masq-agent: YAML config → `cilium_ipmasq_v{4,6}` LPM maps, fsnotify watcher |
| `pkg/maps/ipmasq/*.go` | 225 | Map definitions |
| `Documentation/security/network/encryption*.rst` | 1122 | ipsec 455, wireguard 370, ztunnel 202, overview 95 |
| `Documentation/network/egress-gateway/*.rst` | 606 | egress-gateway 546, troubleshooting 60 |

Non-test Go in scope: roughly 7.4k lines (wireguard 1.3k, ipsec agent 2.0k +
node side 1.3k, egress gw 2.3k + map 0.6k, srv6map 0.5k, vtep 0.4k, ipmasq
0.5k). BPF: ~2.3k lines of C headers plus `bpf_wireguard.c`.

## Features

### WireGuard transparent encryption

- **Enable**: `--enable-wireguard` (default false; Helm `encryption.enabled=true`,
  `encryption.type=wireguard`). Creates netlink link `cilium_wg0` (type
  `wireguard`), listen port **51871** (UDP, fixed, not configurable), private key
  persisted at `<state-dir>/cilium_wg0.key` (0600; generated on first run,
  reused thereafter). `net.ipv4.conf.cilium_wg0.rp_filter=0`. Device fwmark set
  to `MagicMarkWireGuardEncrypted` (= `MARK_MAGIC_ENCRYPT` 0x0E00) so
  WireGuard's own UDP output carries the encrypt mark (used by the datapath to
  skip re-encryption and by `ctx_is_encrypt`). If the kernel lacks WireGuard,
  startup fails with an explicit "not supported by the Linux kernel" error. On
  agent start with WireGuard disabled the device is deleted if present.
- **Key publication**: local node's public key is written to
  `LocalNode.WireguardPubKey` and annotation `network.cilium.io/wg-pub-key`
  (alias `io.cilium.network.wg-pub-key`) on the CiliumNode; also
  `LocalNode.EncryptionKey = 0xFF` (`StaticEncryptKey`) so remote ipcache
  entries carry `key != 0`, which is the datapath's "encrypt to this node"
  signal. In kvstore/clustermesh mode the same fields propagate via node
  objects; `clustermesh-apiserver` forwards keys; mixed WG/non-WG clusters in a
  mesh are unsupported.
- **Peer management**: node manager `NodeAdd/NodeUpdate/NodeValidateImplementation`
  → `updatePeer(nodeName, pubKey, nodeIPv4, nodeIPv6)`. Peer endpoint is
  `<nodeIP>:51871`; IPv6 endpoint preferred only when tunneling with an IPv6
  underlay, otherwise IPv4 first. Duplicate public keys across two node names
  are rejected; a node whose key changes has the old peer removed first. Node
  IPs themselves are always added as `/32`/`/128` AllowedIPs. `NodeDelete`
  removes the peer. Optional `--wireguard-persistent-keepalive` (duration,
  default 0 = off).
- **AllowedIPs**: in native routing mode (or `--wireguard-track-all-ips-fallback`,
  hidden) the agent subscribes to ipcache; every ipcache entry whose host IP maps
  to a known peer node is added to that peer's AllowedIPs (pod IPs, `/32`). In
  tunnel mode only node IPs are needed, because what gets encrypted is the
  VXLAN/Geneve packet between node IPs (overlay-in-wireguard).
  Removal of an AllowedIP cannot be done directly through the WG netlink API
  (only replace-all); the agent moves IPs to a dummy all-zero-key peer and then
  deletes that peer to avoid the transient blackhole of a replace. Still a known
  issue (GH-33159): packets may be dropped while AllowedIPs change; UDP sockets
  see `EHOSTUNREACH`.
- **Peer GC / restore**: a one-shot job waits for k8s cache sync, ipcache
  revision ≥1, kvstore sync, ip-identity watcher sync, and clustermesh
  nodes/ipcache sync, then removes peers not known and AllowedIPs not expected.
- **MTU**: device MTU = `DeviceMTU − 95` (`mtu.WireguardOverhead` accounts for
  padding; kernel default would be 1420). A `mtu-reconciler` job follows the
  MTU statedb table; clamps to IPv6 minimum (1280) when IPv6 is on. Note in
  tunnel mode pod traffic is encapsulated twice (overlay then WG). Route MTU
  for node routes accounts for encryption overhead (`RoutePostEncryptMTU`).
- **Node-to-node encryption**: `--encrypt-node` (default false; Helm
  `encryption.nodeEncryption`). Adds `ENABLE_NODE_ENCRYPTION` define; host-
  identity sources are then also encrypted. Opt-out selector
  `--node-encryption-opt-out-labels` (default
  `node-role.kubernetes.io/control-plane`): a matching local node publishes
  `EncryptionKey = 0` so peers do not encrypt node traffic to it (pod traffic is
  still encrypted). Rationale: avoid the bootstrap lock-out where the
  kube-apiserver connection used to publish a new pubkey is itself encrypted
  with the old one. Status reports `NodeEncryption: Enabled|OptedOut|Disabled`.
  Beta.
- **Datapath (`ENABLE_WIREGUARD`)**: `cil_to_netdev` (bpf_host.c) calls
  `wg_maybe_redirect_to_encrypt` for packets not already marked encrypted. In
  tunnel mode any overlay packet (`ctx_is_overlay`, mark 0x0400) is redirected to
  `cilium_wg0` unconditionally. Otherwise: look up dst in ipcache; if dst has
  `key != 0` and `encrypt_src_matches_policy(src)` holds (src is a cluster
  identity, not remote-node, and not HOST unless node encryption), set
  `MARK_MAGIC_IDENTITY` with source identity and `bpf_redirect(wg_ifindex)`.
  Without node encryption, proxy traffic (`MARK_MAGIC_PROXY_INGRESS`,
  `MARK_MAGIC_SKIP_TPROXY`) is always encrypted. ICMPv6 NA is never sent over
  `cilium_wg0` (device is POINTOPOINT|NOARP; neighbor entries would not form).
  `cil_from_wireguard` (tc ingress on `cilium_wg0`) sets `MARK_MAGIC_DECRYPT`,
  emits `TRACE_FROM_CRYPTO`, then in native mode tail-calls into local
  delivery / host delivery with the source identity from ipcache; in tunnel
  mode (unless NodePort+encrypt-node) it just returns OK. `cil_to_wireguard`
  (tc egress on `cilium_wg0`) is attached only when
  `NeedEgressOnWireGuardDevice`: native routing + L7 proxy + KPR, to run
  `handle_nat_fwd` rev-NAT for encrypted KPR traffic; emits `TRACE_TO_CRYPTO`.
  XDP is never attached to `cilium_wg0`. Hubble sees `ctx_is_wireguard` (UDP
  sport==dport==51871 from a remote-node identity) to label flows encrypted.
- **Strict mode, egress**: `--enable-encryption-strict-mode-egress` with
  `--encryption-strict-egress-cidr` (IPv4 only) and
  `--encryption-strict-egress-allow-remote-node-identities`. Compiles
  `ENCRYPTION_STRICT_MODE_EGRESS`, `STRICT_IPV4_NET`, `STRICT_IPV4_NET_SIZE`,
  optionally `STRICT_IPV4_OVERLAPPING_CIDR`. In `cil_to_netdev`, after the
  encrypt hook, `strict_allow()` drops (`DROP_UNENCRYPTED_TRAFFIC`, -195) any
  plaintext packet whose src and dst are both inside the strict CIDR, except
  from `IPV4_GATEWAY`/`IPV4_ENCRYPT_IFACE` and (in tunnel mode or overlapping
  CIDR) to remote-node identities. Startup fails if the node IP is inside the
  strict CIDR and allow-remote-node-identities is false. Applies to IPsec too.
  Note: the flag names in this task's brief (`enable-encryption-strict-mode`,
  `encryption-strict-mode-cidr`, `encryption-strict-mode-allow-remote-node-identities`)
  are the pre-1.18 names; at v1.20.1 they carry the `-egress` infix.
- **Strict mode, ingress** (`--enable-encryption-strict-mode-ingress`, WireGuard
  only): BPF config `encryption_strict_ingress`. In `cil_from_netdev`
  (bpf_host.c, before NodePort DNAT) a packet from a cluster identity that is
  not a remote node and that targets a local non-host endpoint is dropped
  unless it carries the decrypt mark; in `cil_from_overlay` any packet not
  marked decrypted is dropped when WG is on. Does not protect node-to-node
  traffic; relies on BPF being attached to every pod-routable interface.
- **Which traffic is encrypted** (from encryption-wireguard.rst): pod→remote pod
  (default); pod→remote node, node→remote pod, node→remote node (node-to-node
  mode only); pod→remote pod via ClusterIP (default); via NodePort with socket
  LB (default) but with kube-proxy only in node-to-node mode; external client
  → pod via service: default with KPR+overlay+no DSR+no XDP, node-to-node with
  native routing, default with DSR-Geneve; L7 proxy / Ingress traffic
  (default); egress gateway pod→gateway (default) and gateway→pod (default,
  unless XDP). Known gaps: N/S LB with XDP acceleration or DSR (non-Geneve)
  redirected between nodes is not encrypted; egress gateway replies with XDP
  are not encrypted; traffic to endpoints not yet in the ipcache leaves in
  clear (mitigate with policy or strict mode); IPv6 not covered by egress
  strict mode; CNI chaining unsupported (GH-15596).

### IPsec transparent encryption

- **Enable**: `--enable-ipsec` (default false; Helm `encryption.type=ipsec`).
  Key file `--ipsec-key-file` (Helm mounts secret `cilium-ipsec-keys`, key
  `keys`, at `/etc/ipsec`). `--enable-ipsec-key-watcher` (default true),
  `--ipsec-key-rotation-duration` (default 5m), hidden
  `--enable-ipsec-xfrm-state-caching` (default true),
  hidden `--use-cilium-internal-ip-for-ipsec` (default false), hidden
  `--dnsproxy-insecure-skip-transparent-mode-check`. There is **no**
  `--encrypt-interface` agent flag at this tag and the configmap template does
  not emit one; the documented Helm value `encryption.ipsec.interface` is a
  residue. The "encryption interface" is `getDefaultEncryptionInterface()`:
  the tunnel device when encapsulating, else `devices[0]`. There is also no
  `--enable-ipsec-encrypted-overlay` flag: since 1.18 encrypted overlay is
  automatic whenever IPsec and tunneling are both on. Probe
  `ProbeXfrmStateOutputMask` requires XFRM output-mark (Linux 4.19+).
- **Key file format** (one key per line; the last line wins and defines the
  current SPI):
  `[spi][+] rfc4106(gcm(aes)) <hex key> <icv-len>` (AEAD; algo must start with
  `rfc`; ICV 96/128/256 bits; `KeyLen = icv/8`) or
  `[spi][+] <auth-algo> <hex key> <enc-algo> <hex key>` (e.g. `hmac(sha256)` +
  `cbc(aes)`; `KeyLen` = hex length of auth key). A `0x` prefix is tolerated.
  SPI must be 1..15 (`IPsecMaxKeyVersion = 15`; 0 invalid). The `+` suffix is
  parsed and discarded — per-node keys are **always** derived at this tag
  (global keys were removed after GHSA-pwqm-x5x6-5586). Rotation: SPI must
  change and key length must not change (else the load errors and the old key
  stays); a rotation is "ongoing" iff new SPI == (active SPI % 15) + 1.
- **Per-node-pair key derivation**: `key_pair = H(globalKey ‖ srcNodeIP ‖
  dstNodeIP ‖ srcBootID[:36] ‖ dstBootID[:36])[:len(globalKey)]` with SHA-256
  when the key is ≤32 bytes, SHA-512 otherwise. OUT state on A uses
  (a, b, bootA, bootB); IN state on A uses (b, a, bootB, bootA). Node boot ID
  is read from the CiliumNode; a node with an empty BootID gets no XFRM config;
  a boot-ID change marks the node for non-atomic state replacement
  (`RemoteRebooted`).
- **XFRM objects installed** (per remote node, per family, by
  `pkg/datapath/linux/ipsec.go`; all `mode tunnel`, `proto esp`, `ESN on`,
  `replay-window 1024`, `reqid 1`):
  - OUT state: src=local tunnel IP, dst=remote tunnel IP, spi=current,
    mark `(nodeID<<16) | (spi<<12) | 0x0E00` mask `0xFFFFFF00`, output-mark
    `0x0E00` mask `0xFFFFFF00`.
  - IN state: src=remote, dst=local, mark `(nodeID<<16) | 0x0D00` mask
    `0xFFFF0F00`, output-mark `0x0D00` (or `0` in endpoint-routes mode) mask
    `0xFFFFFF00 | 0xFFFF0000`.
  - OUT policy: src `0.0.0.0/0`, dst = remote pod CIDR, dir out, same mark as
    OUT state, template (esp, tunnel, src/dst tunnel IPs, reqid, spi).
  - IN policy: src/dst wildcard, dir in, optional wildcard template.
  - FWD policy: src/dst wildcard, dir fwd, priority `0x0B9F`, optional
    template.
  - Default drop policy (once per family): dir out, wildcard, mark `0x0E00`
    mask `0x0F00`, action block, priority 100 — catches marked-for-encrypt
    traffic during non-atomic replacement so it never leaves in plaintext
    (`XfrmOutPolBlock`).
  - Encrypted overlay (tunnel mode): an extra OUT policy/state pair matching
    exactly `localNodeIP/32 → remoteNodeIP/32` with underlay IPs as tunnel
    endpoints, plus an IN state; this encrypts the VXLAN/Geneve packet so
    identities (VNI) are on the wire encrypted.
  - Subnet-encryption variant (ENI/Azure "pod subnets" set): OUT policy per
    pod subnet; IN states for both CiliumInternalIP and NodeInternalIP pairs.
  Tunnel IPs default to node internal IPs (CiliumInternalIP when
  `use-cilium-internal-ip-for-ipsec`).
- **Routes and rules**: ip rule priority 1, `fwmark 0x0D00/0x0F00 lookup 200`
  (`RouteTableIPSec`), v4 (skipped with endpoint routes) and v6. Table 200:
  local-type IN route for local pod CIDR on the encryption interface; OUT route
  per remote pod CIDR via `cilium_host` with `RoutePostEncryptMTU`. Routes use
  proto `RTProto` (Cilium's). Encrypt-route cleanup on disable.
- **Datapath (`ENABLE_IPSEC`)**: `cilium_encrypt_state` array map (1 entry,
  `struct encrypt_config { __u8 encrypt_key }`) holds the local active SPI.
  `cilium_node_map_v2` (hash, 16384 default, `--bpf-node-map-max`) maps node IP
  → `{node_id u16, spi u8}`. `set_ipsec_encrypt` picks
  `min(local_spi, peer_spi)` with 15→1 wraparound handling, builds mark
  `(node_id<<16) | (spi<<12) | 0x0E00`, stores identity in cb, and
  `ipsec_maybe_redirect_to_encrypt` redirects to `cilium_net` **ingress** so
  the XFRM output hook encrypts and recirculates to the stack. Missing node ID
  → `DROP_NO_NODE_ID` (-197). `do_decrypt` in `cil_from_netdev`: ESP packets
  get `MARK_MAGIC_DECRYPT | node_id<<16`, `PACKET_HOST`, pass to stack; the
  decrypted recirculated packet (mark 0x0D00) has its mark cleared and is
  redirected to `cilium_host` (or passed to the stack with endpoint routes).
  Mark layout: bits 0x0F00 magic, 0xF000 key index (SPI), upper 16 bits node
  ID; `MARK_MAGIC_KEY_MASK = 0xFF00`.
- **Key rotation flow**: fsnotify on the key file → jitter in
  `[0, rotation/10]` → `loadIPSecKeys` → `publishCurrentSPI`: (1)
  `AllNodeValidateImplementation` re-upserts XFRM for all nodes with the new
  SPI (IN states ready first), (2) `LocalNode.EncryptionKey = spi` (published
  to CiliumNode / kvstore; remote nodes update `cilium_node_map_v2`), (3) write
  the new SPI into `cilium_encrypt_state`. On agent restart mid-rotation the
  SPI publication is deferred until the datapath is initialized. A
  `stale-key-reclaimer` timer (1 min) deletes states and OUT policies whose SPI
  is not current and has been replaced ≥ `ipsec-key-rotation-duration` ago
  (default drop policy exempt; IN/FWD policies do not depend on SPI). Old keys
  never seen before are given a full rotation period.
- **XFRM stale-state handling**: `xfrmStateReplace` handles EEXIST by deleting
  the conflicting state (kernel lookup semantics: same spi, dst, and
  mark&mask) and re-adding; `safeDeleteXfrmState` temporarily removes a legacy
  `0xd00/0xf00` IN state when deleting a node-specific `0xXXXX0d00/0xffff0f00`
  state because the kernel deletes the general one otherwise (drop count
  logged from `XfrmInNoStates`). `DeleteXFRM(AllReqID)` on config change.
  Documented stale-state causes (kvstore lease expiry, CiliumNode delete +
  restart) and mitigation (rotate keys).
- **Status/metrics**: `cilium-dbg encrypt status` (mode, decryption interfaces,
  keys in use, max seq number, error count); `cilium-dbg encrypt flush`;
  Prometheus `cilium_ipsec_xfrm_error` by type/direction from
  `/proc/net/xfrm_stat`, key/state/policy counts.
- **Limitations** (encryption-ipsec.rst): no CNI chaining; host policies
  unsupported with IPsec; ≤65535 nodes (node ID is u16); decryption is single
  CPU core per tunnel; DNS proxy must be transparent mode when L7 proxy on;
  firewall must allow ESP between nodes (cloud SGs); key rotations must not
  overlap upgrades; changing key length during rotation is refused.

### Egress Gateway

- **Enable**: `--enable-egress-gateway` (Helm `egressGateway.enabled`).
  Requires `identity-allocation-mode=crd`, no CiliumEndpointSlice,
  `enable-ipv4-masquerade` + `enable-bpf-masquerade`, KPR, IPv4 underlay; IPv6
  policies additionally want `enable-ipv6-masquerade`. Enabling forces tunnel
  device creation (`tunnel.NewEnabler(true)`) because redirection to the
  gateway is always encapsulated even in native routing.
  `--egress-gateway-reconciliation-trigger-interval` (default 1s),
  `--egress-gateway-policy-map-max` (default 16384). There is **no**
  `install-egress-gateway-routes` flag at this tag; and the
  `EGRESS_GATEWAY_RT_TBID` compile-time hook defaults to 0 and is not set by
  OSS Go code (pod `network.cilium.io/fib-table-id` annotation exists behind
  `--fib-table-id-annotation` but is not wired into EGW).
- **CRD `CiliumEgressGatewayPolicy`** (cluster-scoped, `cilium.io/v2`, short
  `cegp`): `spec.selectors[]` each with `podSelector` (required unless
  `namespaceSelector` given), optional `namespaceSelector` (translated to
  `io.cilium.k8s.namespace.labels.*`; empty selector = all namespaces) and
  optional `nodeSelector` (restricts source pods to nodes with these labels;
  cannot be used alone); `spec.destinationCIDRs[]` (required; v4 and v6);
  `spec.excludedCIDRs[]`; `spec.egressGateway { nodeSelector (required),
  interface | egressIP }` and `spec.egressGateways[]` (max 64, same shape;
  when non-empty `egressGateway` is ignored). `interface` and `egressIP` are
  mutually exclusive (policy rejected). Only security-identity-relevant labels
  match.
- **Gateway selection**: for each gateway entry, nodes sorted by name; the
  first whose labels match is the gateway; its IPv4 node IP is `gatewayIP`.
  No match → `gatewayIP = 0.0.0.0` → datapath drops `DROP_NO_EGRESS_GATEWAY`
  (-194). Multi-gateway: gateways sorted by IP; each endpoint gets
  `gateways[fnv32a(endpointUID) % n]` (stable per endpoint until the gateway
  set changes; connections break when it does, GH-39245).
- **Egress IP / interface derivation** (only on the gateway node itself):
  `interface` → its ifindex and first/primary v4 and v6 addresses;
  `egressIP` → the device owning that IP, other family's primary as needed;
  neither → device with the IPv4 (and v6) default route. Failure →
  `egressIP = 0.0.0.0` → gateway drops `DROP_NO_EGRESS_IP` (-204). No
  automatic re-derivation on later address changes (re-apply the policy).
  Gateway node sets `net.ipv4.conf.<iface>.rp_filter=2` on egress interfaces.
- **Map compilation**: for every (matched endpoint IP × destinationCIDR) →
  key `(srcIP/32 + dstCIDR)` value `(egressIP, gatewayIP[, egressIfindex])`;
  for every excludedCIDR → same key with `gatewayIP = 0.0.0.1`
  (`ExcludedCIDRIPv4`, LPM makes the more specific excluded prefix win).
  egressIP is `0.0.0.0` on all non-gateway nodes. Full-diff reconciliation:
  dump map, compute desired, update changed, delete stale. Three maps written
  in lock-step: `cilium_egress_gw_policy_v4` (legacy value), `_v4_v2` (adds
  `egress_ifindex`), `_v6`.
- **Datapath** (`ENABLE_EGRESS_GATEWAY`, `ENABLE_EGRESS_GATEWAY_COMMON`):
  source side (`bpf_lxc` via NAT/`handle_nat_fwd`, and `cil_to_netdev` for
  host-routed cases): for non-reply, non-cluster-destination connections from
  a non-host identity, lookup policy; redirect → encapsulate to `gatewayIP`
  with `encap_and_redirect_with_nodeid` (VXLAN/Geneve, carries identity); if
  the gateway is the local node, fall through. Gateway side (`cil_from_overlay`
  and NAT in `cil_to_netdev`): `egress_gw_snat_needed_hook` → SNAT to
  `egress_ip` (skipped for cluster destinations); with `egress_ifindex`, use
  `redirect_neigh` or FIB lookup (`BPF_FIB_LOOKUP_TBID` when a table id is set)
  to leave via that interface. Replies at the gateway (`cil_from_netdev`/XDP):
  `egress_gw_reply_needs_redirect_hook` rev-SNATs and tunnels back to the pod's
  node. SNAT port range constraint: 65535 − upper `--node-port-range` ≈ 32768
  connections per (egressIP, remote addr:port) tuple; `nat-stats` table and
  `mapStatsInterval` (30s) in `cilium-dbg shell db/show nat-stats`.
- **Status/health**: no CRD status subresource; observability is
  `cilium-dbg bpf egress list`, `cilium-dbg shell` egress commands, map
  pressure metrics, drop reasons above, and Hubble. Reconciliation counter
  exposed internally.
- **Interplay**: ENI/cloud modes need operator-provisioned secondary
  interfaces/IPs; BPF masquerade is mandatory (iptables masquerade would race).
  Incompatible with ClusterMesh (gateway must be in-cluster), CES, kvstore
  identities. New pods have a window before policy applies (traffic egresses
  with node IP). IPv6: supported for destination/excluded CIDRs and egress IP
  (`_v6` map) but the `gateway_ip` is still IPv4 (IPv4 underlay required).
  WireGuard: pod→gateway and gateway→pod legs are encrypted (not replies with
  XDP).

### SRv6

- Flags `--enable-srv6` (default false) and `--srv6-encap-mode` (`reduced`
  default, else SRH; define `ENABLE_SRV6_SRH_ENCAP`). OSS contains only the
  maps (`cilium_srv6_vrf_v4/v6` LPM `(vrf_id? no: src_ip, dst_cidr) → vrf_id`,
  `cilium_srv6_policy_v4/v6` LPM `(vrf_id, dst_cidr) → SID`, `cilium_srv6_sid`
  hash `SID → vrf_id`, each 16384) and the BPF encap/decap paths. There is no
  OSS writer for these maps and no `CiliumSRv6*` CRD in
  `pkg/k8s/apis/cilium.io/{v2,v2alpha1}`; the control plane is Enterprise-only.
  Treat as datapath-only feature flag.

### VTEP integration (beta)

- `--enable-vtep`, `--vtep-endpoint` (list of VTEP IPs, ≤8), `--vtep-cidr`
  (list, one per endpoint), `--vtep-mask` (single mask applied to all CIDRs,
  BPF config `vtep_mask`), `--vtep-mac` (list), `--vtep-sync-interval`. IPv4
  only, tunnel mode. Map `cilium_vtep_map` (hash, `VTEP_MAP_SIZE` = 8):
  `vtep_ip → {vtep_mac u64, tunnel_endpoint u32}`; datapath encapsulates pod
  traffic to a VTEP CIDR toward the VTEP with the given MAC. With L7 proxy on,
  routes for each VTEP CIDR are installed in table 202 (`RouteTableVtep`) on
  `cilium_host` with MTU `1500−50` and an ip rule (`RulePriorityVtep`) so proxy
  traffic reaches the VTEP too.

### BPF ip-masq-agent

- `--enable-ip-masq-agent` (default false), `--ip-masq-agent-config-path`
  (default `/etc/config/ip-masq-agent`). Requires BPF masquerade
  (`ENABLE_IP_MASQ_AGENT_IPV4/6`). Config file (YAML or JSON, ConfigMap
  mounted): `nonMasqueradeCIDRs: [..]`, `masqLinkLocal: bool`,
  `masqLinkLocalIPv6: bool`. Missing/empty file → defaults (RFC1918
  10/8, 172.16/12, 192.168/16 plus 100.64/10, 192.0.0/24, 192.0.2/24,
  192.88.99/24, 198.18/15, 198.51.100/24, 203.0.113/24, 240/4). Link-local
  `169.254/16` and `fe80::/10` are added unless the respective flag is true.
  Written to `cilium_ipmasq_v4` / `cilium_ipmasq_v6` (LPM, 16384, key
  `{prefixlen, addr}`, value 1 pad byte). Datapath skips SNAT for destinations
  matching. Watches the config **directory** with fsnotify; restores from map on
  start; diff-syncs.

### Not present at this tag

- `enable-high-scale-ipcache` / high-scale ipcache mode: no flag, no code, no
  documentation section (only generic "high-scale" map sizing advice in
  kubeproxy-free.rst). Removed before 1.20; not part of scope.
- ztunnel (`encryption.type=ztunnel`, beta): Istio ztunnel per-node proxy for
  L4 mTLS driven by Cilium's xDS + CA. Documented in
  `encryption-ztunnel.rst`; implementation lives outside these paths
  (area 11). Noted for completeness only.

## Data model

### WireGuard
- `wgtypes.Config { PrivateKey, ListenPort 51871, FirewallMark 0x0E00, Peers[] }`;
  `wgtypes.PeerConfig { PublicKey, Endpoint udp, AllowedIPs[], PersistentKeepaliveInterval }`.
- Agent state: `peerByNodeName map[string]*peerConfig`, `nodeNameByNodeIP`,
  `nodeNameByPubKey`; `peerConfig { pubKey, endpoint, nodeIPv4/6, allowedIPs,
  needsInsert, needsRemove }` (queued diff, applied via ConfigureDevice).
- Node object fields consumed/produced: `Node.WireguardPubKey` (string,
  base64), `Node.EncryptionKey` (u8: 0xFF or 0), `Node.BootID`; annotation
  `network.cilium.io/wg-pub-key`.
- Ipcache entry `remote_endpoint_info.key` (u8) drives encryption decisions.
- Files: `<state-dir>/cilium_wg0.key` (32 raw bytes, mode 0600).
- API model `WireguardStatus { node-encryption, node-encrypt-opt-out-labels,
  interfaces[] { name, listen-port, public-key, peer-count, peers[] {
  public-key, endpoint, last-handshake-time, allowed-ips[], transfer-tx/rx } } }`.

### IPsec
- `ipSecKey { Spi u8, KeyLen, ReqID=1, Auth/Crypt/Aead *XfrmStateAlgo }`;
  `keysRemovalTime map[spi]time`.
- `types.Parameters { LocalBootID, RemoteBootID, Dir (IN|OUT|FWD bits),
  SourceSubnet, DestSubnet, SourceTunnelIP, DestTunnelIP, ReqID,
  RemoteNodeID u16, ZeroOutputMark, RemoteRebooted }`.
- BPF: `cilium_encrypt_state` (ARRAY, key u32 = 0, value `{u8 encrypt_key}`,
  1 entry, pinned, RDONLY_PROG). `cilium_node_map_v2` (HASH, key = node IP
  family/addr, value `{u16 node_id, u8 spi}`, 16384 default, pinned).
- Netlink: `XfrmState` (mode/proto/spi/reqid/esn/replay 1024/mark/output-mark/
  algo), `XfrmPolicy` (dir/src/dst/mark/priority/action/tmpls[]), routes in
  table 200, ip rules priority 1 with fwmark.
- Files: key file at `--ipsec-key-file`; `/proc/net/xfrm_stat` read for
  metrics and drop accounting.

### Egress gateway
- `EgressPolicyKey4 { PrefixLen u32 (=32+cidr bits), SourceIP [4]u8,
  DestCIDR [4]u8 }` → `EgressPolicyVal4 { EgressIP, GatewayIP }` (8 B) in
  `cilium_egress_gw_policy_v4`; `EgressPolicyVal4V2 { EgressIP, GatewayIP,
  Reserved [3]u32, EgressIfindex u32, Reserved2 u32 }` (28 B) in
  `cilium_egress_gw_policy_v4_v2`; `EgressPolicyKey6 { PrefixLen (=128+bits),
  SourceIP [16], DestCIDR [16] }` → `EgressPolicyVal6 { EgressIP [16],
  GatewayIP [4], Reserved [3]u32, EgressIfindex, Reserved2 }` in
  `cilium_egress_gw_policy_v6`. All `BPF_MAP_TYPE_LPM_TRIE`, `NO_PREALLOC`,
  `RDONLY_PROG`, pinned by name, `max_entries = egress-gateway-policy-map-max`
  (16384). Sentinels: gateway `0.0.0.0` = no gateway (drop), `0.0.0.1` =
  excluded CIDR (pass), egress IP `0.0.0.0`/`::` = not found (drop at gateway).
- `PolicyConfig { id, endpointSelectors[], nodeSelectors[], dstCIDRs[],
  excludedCIDRs[], policyGwConfigs[] {nodeSelector, iface, egressIP},
  gatewayConfigs[] {ifaceName, egressIfindex, egressIP4, egressIP6, gatewayIP,
  localNodeConfiguredAsGateway}, matchedEndpoints map[UID]*endpointMetadata,
  v4Needed, v6Needed }`; `endpointMetadata { labels, id=UID, ips[], nodeIP }`.
- Inputs: `CiliumEgressGatewayPolicy`, `CiliumNode` (labels, node IPs),
  `CiliumEndpoint` (UID, addressing, identity → labels via identity allocator).

### Others
- `cilium_ipmasq_v4/v6` LPM `{u32 prefixlen, addr}` → `{u8 pad}`, 16384.
- `cilium_vtep_map` HASH `{u32 vtep_ip}` → `{u64 vtep_mac, u32 tunnel_endpoint}`, 8.
- `cilium_srv6_vrf_v4/v6` LPM, `cilium_srv6_policy_v4/v6` LPM `(u32 vrf_id,
  dst cidr) → union v6addr SID`, `cilium_srv6_sid` HASH `SID → u32 vrf_id`,
  16384 each.

## External interfaces

- **Wire**: WireGuard UDP 51871 node-to-node (fixed); ESP (IP proto 50)
  node-to-node for IPsec, SPI 1..15 visible on the wire; VXLAN/Geneve inside
  WG (tunnel mode) or inside ESP (encrypted overlay); egress gateway redirect
  is VXLAN/Geneve to the gateway node with identity in VNI even in native
  routing.
- **Packet marks**: `MARK_MAGIC_HOST_MASK 0x0F00`; `MARK_MAGIC_ENCRYPT 0x0E00`
  (also the `cilium_wg0` fwmark); `MARK_MAGIC_DECRYPT 0x0D00` (IPsec: node ID in
  upper 16 bits; WG: source identity); `MARK_MAGIC_IDENTITY 0x0F00`;
  `MARK_MAGIC_OVERLAY 0x0400`; `MARK_MAGIC_EGW_DONE 0x0500`; key index at
  `0xF000` (IPsec SPI); XFRM marks/masks `0xFFFFFF00`, `0xFFFF0F00`, `0x0F00`.
  `MARK_MAGIC_HEALTH` aliases 0x0D00 (LB UAPI) — the collision is intentional.
- **Netlink objects**: link `cilium_wg0` (wireguard); WG generic-netlink device
  configuration; XFRM SA/SP add/update/delete/list/flush (families v4/v6); ip
  rules priority 1 fwmark→table 200 (IPsec), `RulePriorityVtep`→table 202;
  routes in tables 200 and 202 with Cilium's `RTProto`; sysctls
  `net.ipv4.conf.cilium_wg0.rp_filter=0`, `net.ipv4.conf.<egress-iface>.rp_filter=2`.
- **Kubernetes**: CiliumNode fields/annotations `wg-pub-key`, `encryption-key`
  (`network.cilium.io/encryption-key`), `spec.bootid`; `CiliumEgressGatewayPolicy`;
  secret `cilium-ipsec-keys` mounted as file; ConfigMap for ip-masq-agent
  mounted as file.
- **Agent API / CLI**: `/healthz` encryption section (`cilium-dbg status`
  shows `Encryption: Wireguard [cilium_wg0 (Pubkey: …, Port: 51871, Peers: N)]`
  or IPsec), `cilium-dbg debuginfo` `.encryption.wireguard`, `cilium-dbg
  encrypt status|flush`, `cilium-dbg bpf egress list`, `cilium-dbg shell --
  db/show nat-stats`. Hubble trace reasons `TRACE_FROM_CRYPTO`/`TRACE_TO_CRYPTO`,
  `TRACE_REASON_ENCRYPTED`; drop reasons -160 no tunnel endpoint, -194, -195,
  -197, -204.
- **Metrics**: `cilium_ipsec_xfrm_error{type,direction}`, IPsec key/state/policy
  counts, egress map pressure, NAT endpoint max connection.

## Dependencies

- Areas: 01 bpf-programs (bpf_host/lxc/overlay hooks named above), 02 maps
  (ipcache `remote_endpoint_info.key`/tunnel endpoint, node map, encrypt map),
  03 datapath userspace/node (node handler, routes, MTU table, devices table,
  node address table, sysctl reconciler, tunnel config), 04 LB (NodePort
  rev-NAT on `cilium_wg0`, DSR/XDP gaps, NAT SNAT for egress gateway), 05
  identity (identity allocator for CEP labels; identity_is_cluster/remote_node
  in BPF), 06 agent API/status, 12 clustermesh/kvstore (pubkey propagation, sync
  gating of peer GC), 13 CRDs (CEGP, CiliumNode fields), 15 Helm.
- Kernel: WireGuard module (5.6+ in-tree or out-of-tree), WG netlink;
  XFRM with output-mark (4.19+; `XFRM_OUTPUT_MARK` 4.14), ESN, AEAD
  `rfc4106(gcm(aes))` or `cbc(aes)`+`hmac(*)` ciphers; `bpf_redirect`,
  `bpf_redirect_neigh` (5.10, for egress-ifindex fast path), `bpf_fib_lookup`
  with `BPF_FIB_LOOKUP_TBID` (6.4+, optional), `bpf_skb_change_type`,
  LPM trie maps with `BPF_F_NO_PREALLOC`, `BPF_F_RDONLY_PROG`.
- External: Kubernetes API (CiliumNode/CEP/CEGP), kvstore in that mode,
  `/proc/net/xfrm_stat` (procfs), fsnotify.

## Kernel / platform requirements

- WireGuard path: `CONFIG_WIREGUARD`, tc(x) attach on `cilium_wg0` ingress
  (and egress when needed), no XDP on wg. Uses `BPF_PROG_TYPE_SCHED_CLS`,
  tail calls (`cilium_calls_wireguard*`), `bpf_redirect`, `bpf_redirect_peer`
  (local delivery), ipcache LPM lookups.
- IPsec path: XFRM with mark and output-mark; kernel ≥4.19 probed at start;
  RHEL 8.6 quirk worked around by carrying the mark in `cb[]` across
  redirects (`use_meta = true`). Decryption is single-core per SA.
- Egress gateway: LPM trie, FIB lookup helper, `redirect_neigh` optional,
  BPF masquerade (NAT maps), tunnel device, XDP optional for reply path.
- ip-masq-agent / VTEP / SRv6: LPM trie and hash maps only; SRv6 needs IPv6
  routing header manipulation via `bpf_skb_adjust_room`.
- Arch: nothing arch-specific beyond generic Cilium BPF; ESN/AEAD are kernel
  crypto (AES-NI / ARMv8 CE affect throughput only).

## Tests

- Unit: `pkg/wireguard/agent/agent_test.go` (peer config queueing, AllowedIPs
  restoration/GC, endpoint selection v4/v6/tunnel), `cell_test.go`
  (privileged: real device, pubkey publication, opt-out selector);
  `pkg/datapath/linux/ipsec/ipsec_linux_test.go` (key file parsing incl. bad
  SPI/len change/same SPI, privileged XFRM upsert IN/OUT/FWD idempotence,
  rebooted-node replacement, conflicting-state deletion, mark direction),
  `cell_test.go` (privileged: SPI publish, rotation detection, deferred SPI
  update, jitter), `xfrm_state_cache_test.go`; `pkg/common/ipsec` key
  counting; `pkg/egressgateway/manager_privileged_test.go` (CEGP parser, map
  contents across node/endpoint/policy events, node selector, endpoint store,
  multi-gateway hashing), `policy_test.go`, `script_test.go` with
  `testdata/test.txtar` and `test_egressip.txtar` (statedb devices/node
  addresses, interface altnames, rp_filter sysctl); `pkg/maps/egressmap`,
  `pkg/maps/srv6map`, `pkg/maps/ipmasq`, `pkg/ipmasq` (config parsing,
  defaults, link-local handling, diff sync).
- BPF unit tests (`bpf/tests`): `encrypt_host_wireguard{,_strict,_tunnel,
  _tunnel_strict}.c`, `decrypt_host_wireguard{,_strict}.c`,
  `decrypt_overlay_wireguard.c`, `tc_nodeport_l3_wireguard.c`,
  `encrypt_host_ipsec{,_strict,_tunnel,_tunnel_strict}.c`,
  `decrypt_host_ipsec.c`, `encryption_helpers_*`, `tc_egressgw_redirect_from_host.c`,
  `tc_egressgw_redirect_from_overlay{,_with_rt_info}.c`, `tc_egressgw_snat.c`,
  `xdp_egressgw_reply.c`, `tc_srv6_{encap,decap}.c`, `*_masq*.c`.
- CI: `conformance-ipsec-e2e.yaml` (matrix with encryption-node, key rotation
  action `ipsec-key-rotate`, bpftrace `check-encryption-leaks.bt` before and
  after rotation), cloud conformance workflows enable
  `egressGateway.enabled=true` and WireGuard and run cilium-cli connectivity
  tests incl. `egress-gateway-excluded-cidrs`; `tests-e2e-upgrade.yaml` has an
  `egress-gateway` matrix dimension; clustermesh workflows exercise WG across
  clusters.

## Rust mapping

- **WireGuard**: `wireguard-control` (userspace wrapper over WG genetlink and
  `wg` userspace socket) or the lower-level `netlink-packet-wireguard` +
  `netlink-sys`/`genetlink`; `rtnetlink` for link add/MTU/up and sysctl via
  procfs writes. Key generation with `x25519-dalek` (WG keys are Curve25519;
  `wireguard-control` re-exports key types). The dummy-peer AllowedIPs
  removal trick maps 1:1 onto `WGPEER_F_REPLACE_ALLOWEDIPS`. Structure:
  `flowsdn-wireguard` crate with `PeerTable` (nodeName → peer, reverse
  indexes), a `NodeEvent` subscriber and an `IpcacheEvent` subscriber feeding
  a diff-queue per peer, plus an MTU watcher. Small (~1.5k lines).
- **IPsec / XFRM**: `netlink-packet-xfrm` exists (rust-netlink org) and covers
  SA/SP add/del/get/dump incl. mark, output-mark, ESN, replay window, AEAD,
  templates; there is no high-level `rtnetlink`-style XFRM API so a thin async
  wrapper is needed. Key derivation with `sha2`. Structure: `flowsdn-ipsec`
  with `KeyFile` parser, `NodePairKeys`, `XfrmPlan` (pure function from
  (local node, remote node, config) → desired states/policies/routes/rules)
  and an `XfrmReconciler` that diffs against a cached kernel dump. Metrics from
  `/proc/net/xfrm_stat` via `procfs`.
- **Egress gateway**: pure control-plane in Rust: `kube` watchers for
  CEGP/CiliumNode/CEP, `ipnet`/`netip` for CIDRs, `fnv` for endpoint hashing,
  `aya` LPM trie map handles for the three policy maps, `rtnetlink` for device
  and address lookup (or reuse the devices/node-address tables from area 03),
  sysctl writes. Structure: `flowsdn-egressgw` with `PolicyConfig` compile and
  a debounced (1s) full-diff reconciler.
- **ip-masq-agent / VTEP / SRv6 maps**: tiny; `notify` for file watching,
  `serde_yaml`; aya LPM/hash maps.
- **Hard parts**:
  1. XFRM state correctness: kernel lookup/EEXIST semantics on (spi, dst,
     mark&mask), the general-vs-specific IN state deletion bug, output-mark
     probing, IPv4-mapped IPv6 address canonicalization, and encrypted-overlay
     policy ordering. Any mistake is silent plaintext or a blackhole; the
     default drop policy must exist before any OUT policy is touched.
  2. Key rotation without drops: ordering (IN states for all nodes → publish
     SPI → encrypt map), 15→1 wrap, min-SPI negotiation in BPF, jitter, stale
     reclaim timing, boot-ID-triggered non-atomic replacement, and behavior on
     agent restart mid-rotation.
  3. WireGuard AllowedIPs churn without drops (replace-all semantics), peer GC
     gating on many sync signals, and the node-encryption bootstrap opt-out.
  4. Egress gateway "HA": OSS only has deterministic hashing across a static
     gateway list; there is no health-based failover, no CRD status, and
     changing the gateway set breaks connections. Deciding whether flowsdn
     matches OSS behavior or adds active health failover (Enterprise-like) is a
     scope decision.
  5. Egress gateway SNAT port exhaustion (~32k per tuple) and the BPF-side
     ordering constraints with NodePort/HostPort DNAT.

## Recommendation

- WireGuard: **keep**. Simplest, most used, kernel does the crypto. Effort S–M
  (~2k Rust incl. tests).
- IPsec: **keep but stage after WireGuard**. Needed for FIPS/compliance users
  and for encrypted-overlay parity; XFRM reconciliation and rotation are the
  riskiest code in this area. Effort M (~4–6k Rust).
- Egress gateway: **keep** (control plane) — datapath hooks belong to area 01.
  Effort M (~3k Rust). Consider adding a CRD status and health-based gateway
  failover as a flowsdn improvement, tracked as a separate decision.
- ip-masq-agent: **keep**, S (<1k).
- VTEP: **defer** (beta, IPv4-only, niche), S if done.
- SRv6: **defer** — maps and BPF only in OSS, no control plane to mirror;
  revisit if a BGP/VRF integration lands in area 10.
- ztunnel, high-scale ipcache: **out of scope** here (not in these paths /
  not present).

Overall area effort: **M** (about 8–12k lines of Rust including the pure
planners and tests), with IPsec carrying most of the risk.

## Open questions

1. Do we reproduce the pre-1.18 "IPsec-in-overlay" layering or only the 1.18+
   "overlay-in-IPsec" (encrypted overlay)? Only the latter exists at v1.20.1;
   upgrade-from-1.17 migration code is not needed for a new implementation.
2. Fixed WireGuard port 51871 and fixed IPsec reqid 1: keep hard-coded for
   interoperability with Cilium tooling, or make configurable?
3. Should flowsdn honor the `+` suffix and per-tunnel keys only (as v1.20.1
   effectively does), and reject the legacy global-key format outright?
4. Egress gateway HA: mirror OSS hashing only, or design active gateway health
   (node liveness → reassignment) from the start? Also whether to add a
   `status` subresource to the CEGP-equivalent CRD.
5. Strict mode ingress with IPsec is unsupported in Cilium; is that a
   limitation we accept or design away (IPsec decrypt mark is available)?
6. Node ID as u16 caps clusters at 65535 nodes; keep the encoding (mark bit
   layout is shared with the whole datapath) or widen with a different mark
   scheme in area 01?
7. Confirm with area 03 who owns the IPsec ip rules/routes (table 200) and
   `cilium_node_map_v2` population — in Cilium both live in the node handler,
   not in the IPsec agent.
8. The `encryption.ipsec.interface` Helm value has no agent flag behind it at
   this tag; decide whether flowsdn drops it or wires it into encryption
   interface selection.
