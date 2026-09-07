# Changelog

## [Unreleased]

### 2026-09-07
- **chore:** Project created. Name check (GitHub, crates.io, npm, PyPI, .com/.io/.net/.org) clear.
- **docs:** Licensing analysis and clean-room protocol.
- **docs:** Scope decision (ADR-0001): full Cilium feature scope, boundary compatibility.
- **docs:** Reference pinned to Cilium v1.20.1 (7d68cfb394); inventory split into 15 areas.
- **docs:** ADR-0002 everything in Rust including BPF programs (aya-ebpf), no C. ADR-0003 no iptables; small nftables residual over netlink.
- **docs:** ADR-0004 no Hive/StateDB; explicit composition + `flowsdn-table` crate. Inventory roll-up drafted (12/15 areas) with build order.
- **docs:** Inventory complete: 15 areas, ~12.7k lines. Roll-up finalized (full-scope estimate 200–260k Rust lines).
- **docs:** Specs 00 foundation, 03 identity/ipcache, 04 conntrack/NAT. Kernel requirements roll-up: stormcos 6.12 line, general minimum 6.6, CONFIG fragment, verifier-risk analysis, test matrix.
- **docs:** Spec 01 BPF map ABI + loader. Spec wave 2 launched (05–10).
- **docs:** Spec 02 datapath programs (milestones M1/M2/M3, mark/VNI wire contract, 141-file test checklist). Spec wave 1 complete.
- **docs:** Spec wave 2 complete: 05 service load balancing, 06 policy engine, 07 IPAM, 08 endpoint + agent API, 09 CNI plugin, 10 node routing + nftables residual.
- **docs:** Spec 15 BGP control plane + own minimal Rust speaker: five CiliumBGP* CRDs, operator cluster→node compilation with router-ID pool, seven agent reconcilers in priority order, export policy model (default reject, first match wins), advertisement semantics incl. ETP/ITP, aggregation, VIP refcounting and loadBalancerClass gate, RFC subset (4271/4760/6793/2918/4724+8538/8950/1997/8092/2385), FSM + notification codes, never-import invariant, pluggable Advertiser trait with a RouterOS REST backend, 20-scenario acceptance suite plus GoBGP/RouterOS interop.
