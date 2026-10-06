# ADR-0019: Milestone 4 release scope — golden plus standalone artifacts

Date: 2026-10-06. Status: accepted.
Owner direction: [#294](https://github.com/glennswest/flowsdn/issues/294)
(answer to the release-scope question, 2026-10-05: "2, just make sure they're
not in the actual stormcos golden, they're just dead weight").

## Decision

flowsdn has two delivery paths:

1. **The stormcos golden** stays the primary path. stormcos composes the
   `flowsdn` golden from the static agent (BPF objects embedded) and CNI it
   builds itself, and `deploy/stormcos/manifests*` install them. Nothing in the
   standalone path below is added to the golden: no chart, archive, checksum
   file or image.
2. **A standalone install** for clusters that do not run stormcos: release
   archives with checksums, published as GitHub Release assets, and a Helm
   chart (spec 22 §3.5). These are built by `deploy/release/build.sh` and the
   chart tooling, outside sc-build's golden path and outside stormcos's.

Publishing either is an explicit, recorded step after validation (spec 22
§3.9.3–3.9.4). A tag, push, sc-build pass or golden staging publishes nothing.

## What exists

- `bpf-objects.lock` (ADR-0013 #245, spec 22 §3.8.4) pins every BPF object's
  code hash and the exact bytes the agent embeds. `tools/bpf-objects-lock.sh
  check`, run by `test/build.sh`, rebuilds the objects and refuses a stale lock
  or embedded copy; the agent's unit tests check the embedded bytes against the
  lock without a BPF toolchain.
- `deploy/release/build.sh OUT_DIR [TARGET...]` builds static musl
  `flowsdn-agent` and `flowsdn-cni` for amd64 and arm64 and writes
  `flowsdn-<version>-<arch>.tar.gz` (binaries, `bpf-objects.lock`, LICENSE,
  NOTICE, README, REVISION) and `SHA256SUMS`. Archives are deterministic for a
  given set of binaries; cross-machine binary reproducibility has not been
  measured.

## Names: flowsdn's only

Owner decision on #294 (2026-10-06, accepting the recommendations): the chart's
objects are `flowsdn` (DaemonSet, ServiceAccount, ClusterRoles), `flowsdn-config`
and, later, `flowsdn-operator`; people moving over get a values migration note
([docs/helm.md](../helm.md)), and `sc net` (#298) is the status tool rather than
`cilium-cli`. And: **no Cilium in flowsdn, period** — no cilium-* object names,
labels, config keys or compatibility shims in the chart or manifests.

This supersedes ADR-0013 #237 (keep cilium object names) and spec 22 §2/§3.5–3.7
(a Cilium-compatible chart: reference object names, the reference values surface,
`flowsdn.io/cilium-compat`, `helm-diff` against the reference chart). It also ends
the manifest-level compatibility retained by ADR-0017:

- The CNI installs `flowsdn-cni` (and the golden's `flowsdn` link) and the
  conflist's plugin type is `flowsdn-cni`; there is no `cilium-cni` alias.
  `OVERWRITE_CILIUM` is `OVERWRITE_PLUGIN`.
- The agent socket and CNI delete queue live in `/var/run/flowsdn`
  (`flowsdn.sock`, `deleteQueue`); `CILIUM_SOCK` is `FLOWSDN_SOCK`.
- The shipped CRDs carry flowsdn names in every string (descriptions, enum
  values, printer columns): `FlowsdnInternalIP`, `io.flowsdn.k8s.policy.*`.
- A test (`no_cilium_in_shipped_manifests`) and `install/kubernetes/check.sh`
  refuse "cilium" in any manifest or chart file or rendering.

Names inside the code that the manifests do not show (BPF map/pin names,
interface names, the configuration catalogue) are a separate change, tracked
on #339, as the directive reaches them too.

## What the chart is

`install/kubernetes/flowsdn`: flowsdn's own values (docs/helm.md), the 22 CRDs in
`crds/`, RBAC, the `flowsdn-config` ConfigMap and the Kubernetes-mode agent
DaemonSet with the CNI install init container. `image.repository` is required: no
image is published, and `images/agent/build.sh` builds one. `deploy/release/build.sh`
packages it beside the archives in `SHA256SUMS`.

## Not changed

Milestone 4 acceptance still needs milestones 1–3 (#291–#293) accepted, runtime
runs on both architectures and the kernel/scale/performance checks. Neither
path above is evidence for those gates.
