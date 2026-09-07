# ADR-0003: No iptables. A small nftables residual replaces the iptables manager.

Date: 2026-09-07. Status: accepted (user decision).

## Decision

flowsdn does not install or depend on iptables, ipset or `xt_*` modules. The
reference's iptables manager (`pkg/datapath/iptables`, ~5k lines plus the
rename-reinstall-delete update model) is replaced by a small nftables layer
that programs only what the eBPF datapath cannot do itself.

## What the residual must cover

From inventory area 03, the rules the reference still installs and their
disposition in flowsdn:

| Reference iptables rule | flowsdn |
|---|---|
| Tunnel traffic NOTRACK / ACCEPT | nftables `notrack` on the tunnel port, or none if conntrack is not loaded |
| TPROXY redirect to Envoy + `xt_socket` mark | nftables `tproxy` + `socket transparent` in a prerouting chain |
| Proxy return-path NOTRACK / ACCEPT | nftables `notrack` |
| FORWARD accepts for cilium_host / cilium_net | nftables forward chain accept, only when the host runs a default-drop policy |
| "mark as from host" 0xC00 | nftables `meta mark set` |
| iptables MASQUERADE / SNAT / hairpin / node ipset | **none** — BPF masquerade is the only masquerade path (ADR-0001) |
| Encryption NOTRACK | nftables `notrack` |
| ENI CONNMARK 0x80 | nftables `ct mark` in ENI mode |
| Pod no-track ports (`io.cilium.no-track-port`) | nftables `notrack` per port |

The nftables layer speaks netlink directly (`nftnl`/`rustables`-class crate
or our own `netlink-packet-*` encoding), owns one table (`inet flowsdn`),
and replaces its contents atomically in a single transaction. No shelling
out to `nft`, no `iptables` binary in the image.

## Consequences

- Kernel: `nf_tables`, `nft_tproxy`, `nft_socket`, `nft_ct` modules are
  required only when the corresponding feature (L7 proxy, ENI, per-pod
  no-track) is enabled. With none enabled the residual installs nothing.
- Nothing in flowsdn depends on conntrack being present; where the reference
  used NOTRACK to avoid conntrack cost, flowsdn does the same via nftables
  and otherwise assumes the eBPF CT map is authoritative.
- The `--install-iptables-rules`, `--iptables-*` and `enable-ipv4-masquerade`
  (iptables variant) options have no effect and are documented as such in the
  Helm values mapping.
