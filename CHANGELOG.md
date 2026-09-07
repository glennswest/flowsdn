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
