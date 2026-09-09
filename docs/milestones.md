# Remaining implementation milestones

Baseline: v0.14.0, 377 passing foundation tests, 270 open issues on
2026-09-09. No operational agent or datapath exists at this baseline.
These four milestones cover the remaining scope of ADR-0001. They are ordered
by dependency, not equal effort or estimates of subscription consumption.

| Milestone | Deliverable | Completion evidence |
|---|---|---|
| 1 — Working pod networking | Rust eBPF loading and attachment, map lifecycle, agent startup/restore, endpoint management, identity/ipcache, basic IPAM, CNI, Kubernetes watches and node routing | Install on a disposable two-node cluster; create/delete pods; demonstrate same-node and cross-node IPv4/IPv6 traffic; restart the agent and recover connectivity; verify teardown and failure rollback |
| 2 — Services and network policy | Conntrack/NAT integration, ClusterIP, NodePort, external load balancing, socket LB, DSR, Maglev, affinity, L3/L4 identity/CIDR policy and host firewall | Exercise service/backend changes and return traffic; enforce allow/deny and policy updates on live traffic, including dual stack; execute applicable harvested cases through real adapters |
| 3 — Advanced networking and observability | Remaining IPAM modes and operator controllers, WireGuard/IPsec, egress gateway, BGP, Hubble, DNS/L7/Envoy integration, Gateway/Ingress and ClusterMesh | Demonstrate each subsystem through a feature acceptance matrix: encrypted traffic, egress selection, route advertisement, observable flows, L7 enforcement, gateway routing and cross-cluster services; recorded Rust cloud tests plus available live integration checks |
| 4 — Compatibility and release hardening | Complete boundary compatibility and outstanding feature gaps, packaging/Helm/images, upgrades/migration, CI, full test matrix and operational documentation | Validate install/upgrade/rollback, API/CRD/CLI compatibility, both architectures at runtime, supported kernels, failure/recovery and performance; publish reproducible artifacts with checksums and explicit support coverage |

Basic install manifests, test adapters and CI checks belong alongside the feature
that needs them; milestone 4 expands and hardens them. Conntrack/NAT primitives
needed for milestone 1 are implemented there. Advanced modes of a component
introduced in milestone 1 remain explicit milestone 3 deliverables.

## Backlog ownership

The existing issues mainly track decisions and verification, not all missing
implementation. Issue counts therefore do not measure completion percentages.
This table assigns every current area a primary milestone; prerequisites are
resolved earlier when required. Full feature scope is also tracked by the specs.

| Primary milestone | Issue area labels | Current issues | Specifications |
|---|---|---:|---|
| 1 | foundation, maps, datapath, agent, cni, node, identity, ipam, k8s | 103 | 00–04, 07–10, 13; kernel requirements |
| 2 | loadbalancer, policy | 25 | 04–06 |
| 3 | encryption, bgp, hubble, operator, l7, clustermesh, gateway | 87 | 07, 11–16, 20–21 |
| 4 | packaging, test | 55 | 17–19, 22; test-port plan |

Milestone 1 starts with a minimal Rust BPF program loaded and exercised in an
isolated network namespace, using real maps and attachment cleanup. That proves
the kernel/toolchain path before expanding packet processing and agent wiring.
It is an implementation checkpoint, not completion of milestone 1.

## Acceptance and release status

Each milestone records its demonstrated scenarios, remaining failures and
validation revision. Existing fixture counts and pure codec tests do not prove
live networking. Architecture compilation does not prove runtime support.
External dependencies, including ClusterMesh backend compatibility, remain
explicit blockers until verified. A scope change requires a decision record;
moving an issue or documenting a gap does not make the feature complete.

Versions are selected when a milestone passes its acceptance gates. Until then,
the latest published release remains v0.14.0. Earlier release history is retained.
