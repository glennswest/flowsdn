# flowsdn — Project Instructions

Rust reimplementation of Cilium. Private repo `github.com/glennswest/flowsdn`.
Rule #1 in `AGENTS.md` applies: transfer via GitHub commits/pulls only; keep release history.
Cross-project rules referenced in the original spec (commit+push everything, changelog,
build on dev never on the Mac, cargo target dirs under `/build/cargo/flowsdn`).

## Reference source

Cilium is cloned read-only at `../cilium` (sibling directory, Mac), checked out at
**v1.20.1, commit 7d68cfb394**. All inventory and spec documents cite that commit.
Reference sizes at that tag: pkg/ 359k non-test Go lines, operator/ 48k, api/ 97k
(mostly generated), bpf/ 91k lines of C. It is a
reference for reading. Never edit it, never build from it, never copy from it
without following `docs/licensing.md`.

## Version

0.9.0 — initial map ABI, periodic refresh, foreground script execution and config default resolution; no networking agent yet. Version locations (when crates exist):
`Cargo.toml` workspace.package.version, `CHANGELOG.md` heading.

## Work plan

### Phase 0 — Inventory (COMPLETE 2026-09-07, except kernel-requirements roll-up)
- [x] Repo, license, NOTICE, clean-room protocol, ADR-0001 scope
- [x] Name check: flowsdn clear on GitHub, crates.io, npm, PyPI, .com/.io/.net/.org
- [x] Per-area inventory of the reference in `docs/inventory/` — 15 areas, files 01..15, running as parallel agents (started 2026-09-07):
      01 bpf-programs, 02 bpf-maps-loader, 03 datapath-userspace-node, 04 loadbalancer,
      05 policy-identity, 06 agent-endpoint-api, 07 ipam-cloud, 08 operator, 09 hubble-monitor,
      10 bgp, 11 l7-proxy-dns-auth-mesh, 12 clustermesh-kvstore, 13 crds-k8s,
      14 encryption-egress, 15 helm-images-ci-tests.
      All 15 done and committed 2026-09-07 (~12.7k lines).
- [x] ADR-0002 Rust only (BPF programs in aya-ebpf), ADR-0003 nftables residual
- [x] ADR-0004 no Hive / no StateDB
- [x] Roll-up scope table `docs/inventory/README.md` with sizes + keep/defer/replace + build order
- [x] Kernel requirements roll-up `docs/kernel-requirements.md` — stormcos line 6.12 (Rocky 10 kernel, both arches), general minimum 6.6 LTS

### Phase 1 — Specs (datapath first) — IN PROGRESS 2026-09-07
Spec template: `docs/spec/TEMPLATE.md`. Wave 1 running as parallel agents:
`00-foundation-table-config`, `01-bpf-map-abi-loader`, `02-datapath-programs`,
`03-identity-ipcache`, `04-conntrack-nat`, plus `docs/kernel-requirements.md`.
Wave 1 complete: 00 01 02 03 04 + kernel-requirements (~7.6k lines).
Wave 2 complete (2026-09-07): `05-service-loadbalancing`, `06-policy-engine`,
`07-ipam`, `08-endpoint-agent-api`, `09-cni-plugin`, `10-node-routing-nftables`.
Wave 3 running (launched 2026-09-07): `11-hubble-monitor`, `12-operator`,
`13-crds-k8s-client`, `14-encryption-egress`, `15-bgp`, `16-l7-envoy-dns`.
Wave 4 to launch: ClusterMesh, Gateway API/Ingress, packaging/Helm/CI, workspace scaffold.

### Phase 1b — Test harvest (ADR-0005), IN PROGRESS 2026-09-07
All harnesses in Rust; upstream test DATA harvested verbatim with provenance.
Running as parallel agents:
- `17-scripttest-harness` + harvest of 168 upstream `.txtar` scenarios -> `tests/scripttest/`
- `18-bpf-test-harness` + case harvest of 141 files / 397 CHECKs -> `tests/bpf/`
- `docs/test-port-plan.md` + `tests/golden/` + `tests/fuzz/` (3040 Go tests surveyed)
- `19-e2e-connectivity` (own Rust suite; cilium-cli is out-of-tree at v1.20.1)
Missing file = agent did not finish; rerun that spec.
- [ ] BPF map catalogue: every map, key/value layout, pinning, sizing
- [ ] Datapath programs: from-container, to-container, from-netdev, to-netdev,
      overlay, host, xdp, cgroup socket LB, sock ops
- [ ] Identity model and encoding (VNI, mark, ipcache)
- [ ] Conntrack + NAT
- [ ] Service LB: ClusterIP, NodePort, LB, DSR, Maglev, affinity, LRP
- [ ] Policy: L3/L4, identities, CIDR groups, ANP/BANP, host firewall
- [ ] IPAM: cluster-pool, kubernetes, multi-pool, crd, ENI, Azure, GCP, Alibaba
- [ ] Encryption: WireGuard, IPsec
- [ ] Egress gateway, egress IP
- [ ] BGP control plane (CiliumBGP* CRDs)
- [ ] Hubble: flow schema, observer API, relay, export
- [ ] Agent REST API, health, status
- [ ] Operator: identity GC, CEP/CES, node management, cloud IPAM
- [ ] CRD catalogue with OpenAPI schemas
- [ ] Helm values mapping
- [ ] L7 / Envoy integration (xDS, CiliumEnvoyConfig) — external image
- [ ] ClusterMesh
- [ ] Gateway API / Ingress

### Phase 1c — Backlog (COMPLETE 2026-09-07)
- [x] 290 issues filed from every open decision / to-verify / deferred item;
      index at `docs/open-decisions-index.md` with a "settle these first" ten
- [x] 8 fastetcd compatibility gaps filed on glennswest/fastetcd (#16-#23);
      #16 and #17 are blocking for ClusterMesh in production
- [ ] DECISION NEEDED FROM USER: whether to file the ~15 upstream Cilium defects
      found while reading (public repo, not ours) — listed across the specs

### Phase 2 — Code (dependency order)
- [ ] Workspace, CI (build on dev, x86-64 + arm64), cargo deny
- [ ] BPF maps + datapath crate (Aya)
- [ ] Agent: IPAM, endpoint mgmt, identity, ipcache
- [ ] Agent: policy → maps
- [ ] Agent: service LB → maps
- [ ] CNI plugin binary
- [ ] Encryption, egress, BGP
- [ ] Hubble API
- [ ] Operator incl. cloud IPAM
- [ ] Helm chart / manifests

## Conventions

- **Rust only. No C anywhere** (ADR-0002). `aya` for BPF loading, `aya-ebpf` for
  the BPF programs. **No iptables** (ADR-0003): a small nftables residual over netlink.
- Docs and specs are Markdown under `docs/`. One area per file.
- Every inventory/spec file names the reference paths it was derived from
  and the reference commit.
