# ADR-0020: No reference-project names in what flowsdn ships

Date: 2026-10-07. Status: accepted.
Owner direction: [#330](https://github.com/glennswest/flowsdn/issues/330)
(2026-10-06: "no cilium in flowsdn period"), following #294 and ADR-0019.

## Decision

Nothing flowsdn ships carries the reference project's name: binaries, the BPF
objects the agent embeds, the stormcos manifests, the Helm chart and its CRDs,
release archives, the agent image, configuration keys, API fields, BPF map and
pin names, annotations, label prefixes, taints and metric names. flowsdn uses
its own names (`flowsdn.io`, `flowsdn-*`, `flowsdn_*`, `sc net`).

- At run time flowsdn never reads or writes `cilium.io` resources or
  `cilium-*` objects, and has no compatibility layer for the reference CLI.
- Migrating a cluster from the reference project is a documented one-time
  conversion ([migration-from-cilium.md](../migration-from-cilium.md)), not
  runtime support.
- Map *layouts* and wire formats that were adopted from the reference stay
  where specs require them; only their names are flowsdn's.

This supersedes the compatibility-name parts of ADR-0001 (boundary
compatibility now means formats, not names), ADR-0013 (its remaining
compatibility names; #237 was already superseded by ADR-0019) and ADR-0017's
compatibility rows.

## What stays

- The reference as provenance: design documents (`docs/inventory/`,
  `docs/spec/`), vendored reference data (`crates/flowsdn-k8s/crds/`, harvested
  corpora) and the tools that generate flowsdn artifacts from them.
- Licence attribution: `NOTICE` and `LICENSE-*` files. Apache-2.0 requires the
  attribution to travel with material derived from the reference (the chart's
  CRD schemas, test data), so it is not removed.
- Test tooling that measures the reference flavor for comparison (the `perf`
  suite finds `cilium-agent` on a Cilium node, #321). The test image is not
  shipped.

## Enforcement

- `tools/check-no-cilium.sh` refuses the name in shipped files, binaries and
  objects included (bytes, any case), except `NOTICE`/`LICENSE*`. It runs in
  `test/build.sh` (golden agent, CNI and embedded objects),
  `deploy/release/build.sh` (each archive's contents) and
  `images/agent/build.sh` (the GNU Kubernetes agent and CNI).
- The test `no_cilium_in_shipped_manifests` covers `deploy/` manifests and the
  chart; `install/kubernetes/check.sh` covers the rendered chart.
- Names left in library code that does not ship yet (configuration catalogue,
  clustermesh prefixes, identity labels, packaging helpers) are #339's, with a
  repository-wide check.

## Consequences

BPF maps are `flowsdn_lxc` and `flowsdn_lb{4,6}_{services,backends,reverse_sk}`;
maps added since use the same prefix (`flowsdn_lb{4,6}_affinity`,
`flowsdn_lb_affinity_match`, `flowsdn_nodeport{4,6}_nat`, `flowsdn_nodeport6_fib`).
A node upgraded from an earlier flowsdn needs no pin migration: stormcos
releases reboot the node and bpffs pins do not survive a reboot. An agent
restarted in place on old pins creates new maps beside them and reprograms its
endpoints and Services from its state and the Kubernetes lists; the old pins
are left until the next reboot. The persisted endpoint key is `EndpointUID`.
