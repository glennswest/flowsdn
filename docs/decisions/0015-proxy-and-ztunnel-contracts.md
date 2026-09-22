# ADR-0015: Retain Envoy; use nftables for future ztunnel enrollment

Date: 2026-09-22. Status: accepted design decisions (#262, #203, #238).

ADR-0001 keeps the full L7 and mesh scope, ADR-0002 requires Rust project code,
and ADR-0003 forbids an iptables dependency. This record fixes the missing
replacement and enrollment boundaries; it does not announce working proxies.

## Envoy replacement (#262)

Retain the external, digest-pinned `cilium/proxy` Envoy DaemonSet as the supported
L7 execution target. Do not silently substitute a new Rust proxy. A Rust L7
proxy is a separate project with its own ownership, versioning and security
review; this repository's `flowsdn-proxy` crate supplies integration primitives,
not that replacement project.

A replacement proposal must demonstrate the complete spec16 boundary: original
source/destination and identity handling, transparent sockets/marks, HTTP/gRPC
policy and deny/auth behavior, TLS/SDS and secret rotation, Cilium NPDS/NPHDS
contracts, access-log/Hubble fidelity, Gateway/Ingress conformance and measured
behavior under reload, failure and load. It must include migration/rollback and
an explicit amendment of this decision before activation. No dependency is
removed, implementation commitment assigned to an unnamed project, or timeline
invented by recording these gates.

## ztunnel enrollment (#203)

Implement the eventual enrolled-pod firewall with Rust netlink operations over
nftables **inside the pod network namespace**. Do not permit an iptables binary,
xtables dependency, shell command or exception scoped to enrolled pods.
Preserve the ztunnel ZDS/namespace-FD enrollment, original-address, DNS, mark and
traffic-exclusion semantics in spec16. The nftables port must cover those
semantics before any pod is enrolled; translating only part of the rules is not
acceptable.

Use a narrowly owned nftables table and atomic transactions. Verify namespace
identity and authorized enrollment before entering the namespace. Roll back
failed enrollment, preserve unrelated firewall rules, and remove owned state on
unenrollment/restart recovery. Verify IPv4/IPv6 ingress and egress, exclusions,
DNS, proxy recursion prevention, process restart, concurrent enrollment and
unenrollment, and failed ZDS handoff in privileged tests. The implementation
remains required future work; an enabled-but-unimplemented ztunnel request must
be rejected rather than accepted without mTLS.

## ClusterMesh packaging (#238)

Follow the existing spec20 architecture: a Rust
`flowsdn-clustermesh-apiserver` with integrated kvstoremesh, paired with the
separately owned fastetcd backend. Do not add an interim upstream Go apiserver
or silently replace this choice with upstream etcd. The key-space and remote
protocol remain the compatibility contract; fastetcd still must pass the full
spec20 conformance and hardening gates before a production image is released.

The existing ClusterMesh library is planning code, not that server image.
Images, manifests, TLS/gRPC enforcement, backend conformance, peer-port
NetworkPolicy and hardening item #275 remain outstanding. The backend must not
be directly reachable by remote clients bypassing the in-process prefix front.
