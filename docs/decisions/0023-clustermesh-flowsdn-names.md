# ADR-0023: ClusterMesh uses flowsdn names, with no Cilium interop

Date: 2026-11-25. Status: accepted.
Issue: [#526](https://github.com/glennswest/flowsdn/issues/526) (master's ruling).
Supersedes: spec 20 §2, its interoperability contract, and the `cilium/` key
names of §2.5 and §4.1.

## Context

Spec 20 (ClusterMesh + kvstore) freezes the reference's kvstore key space
(`cilium/state/...`, `cilium/synced/...`, `cilium/cluster-config/...`), its
annotations (`service.cilium.io/global`, ...) and its value encodings, so that
a flowsdn cluster could mesh with Cilium v1.20 clusters in both directions.
The owner's rule since #294/#330 is "no Cilium in flowsdn, period". ADR-0017 and
ADR-0020 make flowsdn's own kinds (FlowsdnIdentity, FlowsdnNode, ...) the ones
flowsdn reads, and #339 lists the clustermesh prefixes as Cilium names still to
remove. Nothing on the platform meshes with a Cilium cluster.

## Decision

1. **Key space.** Every kvstore key in spec 20 §4.1 starts with `flowsdn/`
   instead of `cilium/`, keeping the remaining path. The inner
   `cilium/state/...` element of the synced-canary keys becomes
   `flowsdn/state/...`. Examples: `flowsdn/state/services/v1/<C>/<ns>/<name>`,
   `flowsdn/synced/<C>/flowsdn/state/identities/v1`, `flowsdn/.heartbeat`.
2. **Inputs.** The ClusterMesh apiserver and the agent read flowsdn's kinds
   (ADR-0017): FlowsdnIdentity, FlowsdnEndpoint, FlowsdnNode, and the rest.
   They never read `cilium.io` kinds.
3. **Annotations.** Spec 20 §2.5's annotations are `service.flowsdn.io/global`,
   `service.flowsdn.io/shared`, `service.flowsdn.io/affinity` and
   `service.flowsdn.io/global-sync-endpoint-slices` (Service), and
   `clustermesh.flowsdn.io/global` (Namespace). There are no `io.cilium/`
   aliases.
4. **Value encodings.** Spec 20 §4.2–4.8 (field names and JSON shapes) stay as
   specified, as flowsdn's own format. The cluster-config value type is named
   `FlowsdnClusterConfig` in code.
5. **No interop.** A flowsdn cluster meshes only with flowsdn clusters. There
   is no Cilium-compatibility mode, alias or migration in the kvstore.
   `cilium-dbg kvstore` and Cilium agents are not consumers.

## Consequences

- Every harvested script in `clustermesh`, `clustermesh-agent` and
  `mcsapi-coredns` asserts the reference's names. Each gets an expected-fail
  entry naming this ADR in its area's `DIVERGENCES.toml` once its fixture runs
  the flowsdn component (#526). Scripts are never edited (ADR-0005).
- `flowsdn-clustermesh`'s prefixes and ownership grants move to the
  `flowsdn/` names with the apiserver work. This covers that part of #339.
- Spec 20's compatibility checklist (§2.7, fastetcd) still applies to the etcd
  wire protocol, which is not a Cilium name.
