# ADR-0022: Host firewall from FlowsdnClusterwideNetworkPolicy host rules

Date: 2026-10-14. Status: accepted.
Issue: [#379](https://github.com/glennswest/flowsdn/issues/379) (part of
stormcos#558: the node's own firewall in eBPF, stormfw).

## Context

stormcos#558 makes the node firewall a CRD (`HostFirewallPolicy`, stormfw)
with two backends: on the Cilium flavour stormfw writes a
`CiliumClusterwideNetworkPolicy` with a `nodeSelector` and turns on the
reference's host firewall; on the flowsdn flavour flowsdn needs an eBPF host
policy with the same rule model, an audit mode and verdict counters. The
stormfw repository and its CRD schema do not exist yet. flowsdn already ships
`FlowsdnClusterwideNetworkPolicy` (#325): the reference schema, projected to
`flowsdn.io`, with agent RBAC to list and watch it. ADR-0021's policy maps and
programs serve Pods only.

## Decision

- **Input.** flowsdn enforces the host-policy part of
  FlowsdnClusterwideNetworkPolicy: specs with a `nodeSelector`. stormfw's
  flowsdn backend writes those exactly as its Cilium backend writes CCNPs, so
  flowsdn does not depend on stormfw's schema and one translation serves both
  flavours. Supported rule fields and what is reported instead are listed in
  `docs/runtime.md` (host firewall); unsupported rules are skipped, not
  approximated.
- **Endpoint.** The host is endpoint 65536 (above any 16-bit Pod endpoint ID)
  in ADR-0021's shared maps; `flowsdn_policy_ep` holds it under each uplink's
  interface index (interfaces holding the node's InternalIPs).
- **Programs.** `from_netdev` (uplink TCX ingress, after the NodePort
  program) and `to_netdev` (uplink egress) in the `local-delivery` object run
  ADR-0021's enforcement with a host scope: only packets whose destination
  (ingress) or source (egress) has the host identity are judged. Host egress
  policy is not enforced; `to_netdev` only remembers the node's own flows so
  their replies pass.
- **Precedence.** Host entries use spec 06 §3.5.2's tier-Normal values
  (allow `0xFFFFFF01`, deny `0xFFFFFFFF`). The compiler drops an allow a deny
  of its identity (or of every identity) covers and repeats a deny inside an
  allow at the allow's identity, so the datapath's lookups give "deny wins".
- **Remote nodes** get the remote-node identity (6) in the ipcache; an
  `ipBlock` keeps selecting them, as it does the host, so Pod policy is
  unchanged.
- **Mode.** `kubernetes.host-firewall: off|audit|enforce`, default `off`.
  On, the programs are attached and track host flows; enforcement on an
  uplink starts 60 s after the agent first wants it there (learning), and
  only when a host policy selects the node. Audit (setting, or the
  `policy.flowsdn.io/audit: "true"` annotation on a selecting policy) is an
  endpoint flag: refused packets are counted and passed. The stormcos
  Kubernetes-mode config ships `audit` (#402, stormfw's audit phase), and
  the host firewall does not hold NetworkPolicy back while the
  FlowsdnClusterwideNetworkPolicy list is unavailable (no CRD): the host
  endpoint simply has no rules until it is listed.
- **Counters.** Every enforcing program counts each decision (allowed new
  flow, drop, audit) in `flowsdn_policy_verdicts`, an LRU per-CPU hash keyed
  by endpoint, direction, verdict, protocol and port; `GET
  /v1/policy/verdicts` serves the sums for the console.
- **Ownership of attachment.** The API thread owns the `local-delivery`
  object, so it attaches and detaches the host programs to the uplinks the
  policy thread publishes in the shared view. Links are not pinned.

## Consequences

- No owner input is needed to land the flowsdn side; stormfw targets an
  existing CRD. If stormfw later wants a field the reference model lacks, it
  is added to both backends' translation, not to flowsdn's parser alone.
- Off by default: no node changes until stormfw (or an operator) sets the
  mode. The edition manifests leave it off.
- The flows table is shared with Pods (65536 LRU entries); tracking every
  host flow on a busy node shortens how long Pod flows stay remembered.
- Host egress rules are not covered (gap #477; stormfw's HostFirewallPolicy
  has none). The boot window is stormfw's boot-time program; flowsdn's part
  is the hand-over signal (`enforcing-on`, `pods` in `/v1/healthz`).

## Amendment: local Pods and every node address (#384, 2026-11-20)

stormfw needs the flowsdn backend to mean what the Cilium backend means for
one policy. Two of #384's gaps broke that: the reference judges a local
Pod's traffic to the host by the host policy, and gives every address of the
node the host identity. Without either, a Pod (or a client of an address
that is not an InternalIP) reached ports the policy limits to the node
network.

- **Local Pods.** `flowsdn_policy_ep` key 0 (`HOST_PODS`; no interface has
  index 0) holds the host endpoint for the veth path. `local_delivery` judges
  a packet to a host address by the host's ingress rules after the Pod's own
  egress; `to_container` remembers flows the host starts to a Pod (host
  egress, tracking only), so replies pass. It learns for 60 s like an uplink.
  The loader accepts index 0 only for the host endpoint.
- **Addresses.** With the firewall on, every global address of the node's
  interfaces (not `lo`, not a bridge or bond port, not link-local) is in the
  ipcache as the host, and the programs attach to every interface holding
  one.
- **Status.** `pods` and `addresses` in the health document; a
  `HostFirewall` node Event when the scope or state changes.
