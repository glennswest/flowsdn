# ADR-0001: Scope is the full Cilium feature set, compatible at the boundaries

Date: 2026-09-07. Status: accepted.

## Decision

flowsdn reimplements the complete Cilium feature set in Rust. A feature is
dropped or replaced only when a decision record shows a better solution for
the same need. Cloud IPAM modes (AWS ENI, Azure, GCP, Alibaba) are in scope.

Compatibility is defined at the boundaries:

- CRDs under `cilium.io` with identical schemas and semantics
- Hubble gRPC observer/relay APIs
- Agent REST API (unix socket) used by `cilium-dbg` and health checks
- Helm values surface, or a documented mapping
- Kubernetes-facing behavior: NetworkPolicy, AdminNetworkPolicy, Services,
  EndpointSlices, Gateway API, Ingress

Internals are free. Notably:

- BPF programs are compiled at build time (Rust via Aya, or C via clang at
  build) and loaded with CO-RE. No compiler ships on the node.
- One static binary per component, `scratch` images, no distro base.
- No iptables/ipset dependency. Where Cilium has an iptables fallback,
  flowsdn has none; the eBPF path is the only path.
- One supported kernel line per architecture (stormcos), plus a documented
  minimum for general use. No runtime feature probing beyond a startup
  check that refuses to run.

## Consequences

- Envoy remains the L7 proxy initially, consumed as the cilium/proxy image
  running as its own DaemonSet. Replacing it with a Rust proxy is a separate
  decision (ADR to come) and a separate project.
- x86-64 and arm64 are both first-class from the first commit. One BPF
  object, two agent binaries.
- The inventory (`docs/inventory/`) is the scope table. Each area carries a
  keep / defer / replace mark with a reason.
