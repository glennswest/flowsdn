# ADR-0021: Endpoint policy in one shared program pair and four shared maps

Date: 2026-10-13. Status: accepted.
Issue: [#292](https://github.com/glennswest/flowsdn/issues/292) (milestone 2:
identity/CIDR L3/L4 policy in the datapath).

## Context

Spec 01 and spec 02 §3.10 follow the reference: each endpoint gets its own
compiled program with its own `policy_v3_<endpoint>` LPM map, and policy runs
in tail-called programs. flowsdn loads one `local-delivery` object for every
endpoint and attaches the same programs to each host veth (spec 02 §3.9,
`egress: stack` in the stormcos edition). There is no per-endpoint compile,
no tail-call table, and the agent cannot use the kernel's netfilter conntrack
from BPF (kfuncs are not relocated by aya yet, #315).

## Decision

- **Programs.** `local_delivery` (host veth ingress) enforces the endpoint's
  egress, then delivers or hands to the stack as before; a new `to_container`
  (host veth egress) enforces its ingress. Delivery redirected by
  `local_delivery` or the uplink program reaches `to_container` through the
  target veth's egress hook. The endpoint is the interface the program runs
  on (`ifindex`), never a packet address, so a Pod cannot pick another Pod's
  policy by spoofing.
- **One policy map for all endpoints.** `flowsdn_policy` is a single LPM trie
  whose key is a 32-bit endpoint ID followed by the spec 06 §4.4 key; values
  are spec 06 entries unchanged. The endpoint is always fully specified, so
  the LPM semantics, the three lookups (identity, aggregate, wildcard 0) and
  the engine's obligations of spec 06 §3.8 are those of the per-endpoint map.
  Capacity is shared (65536 entries) rather than per endpoint.
- **Enforcement switch.** `flowsdn_policy_ep` maps the host interface index to
  the endpoint ID and the enforced directions. No entry: no enforcement and no
  tracking, which is the behaviour before this change.
- **Identity.** `flowsdn_ipcache` uses the spec 03 ipcache key and value
  layout; a miss is world (2).
- **Stateful policy without kernel conntrack.** `flowsdn_policy_ct` (LRU)
  records each flow an enforcing endpoint allowed, with its direction:
  `{flow, d}` is the established check and `{reverse(flow), !d}` the reply
  check. Expiry is lazy (TCP 6 h, 10 s after FIN/RST; other 60 s). This is not
  spec 04's conntrack: no NAT state, no related ICMP, no monitor feedback.
- **Agent.** A policy thread compiles Kubernetes NetworkPolicy from the
  controller's view (spec 06 §3.3 importer) into the maps, writing additions
  before removals. `ipBlock` peers get local CIDR identities in the ipcache;
  remote nodes are world, the local node is host.

## Consequences

- No per-endpoint program build or tail calls; one object serves every
  endpoint and policy changes are map writes.
- The policy map's capacity is shared; spec 06 §3.7.8 pressure becomes a
  node-wide limit.
- Flows open before a policy first selects a Pod are judged anew (their
  replies may drop) because unselected endpoints are not tracked.
- Spec 04 conntrack/NAT, policy verdict events, audit mode, authentication,
  proxy redirects and the host firewall remain unimplemented.
