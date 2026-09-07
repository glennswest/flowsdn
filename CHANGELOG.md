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
- **docs:** Spec 13 CRDs + Kubernetes client layer: catalogue of the 22 `cilium.io` CRDs (identity, served/storage versions, subresources, printer columns, schema-version label 1.33.11) with a normative vendor-the-YAML-verbatim rule and seven CI diff tests (SHA manifest, document round-trip, schema↔type diff with a known-diffs allowlist, instance round-trip, unknown-field tolerance, registration-payload golden, property test); slim type field subsets for Pod/Service/Node/Namespace/Secret/EndpointSlice/NetworkPolicy and the unknown-field rule; agent and operator watch sets with field/label selectors and zero resync; a 36-row API-server capability contract doubling as the rustkube compatibility checklist plus a `flowsdn-k8s-conformance` suite derived from it; annotation/label/taint catalogue and the default identity-label filter; client configuration, URL rotation, heartbeat and startup-vs-runtime unavailability; agent RBAC; k8s floor raised to 1.26 (DEVIATION from 1.21) with the tested range 1.33–1.36; crate `flowsdn-k8s`.
