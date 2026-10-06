# ADR-0019: Milestone 4 release scope — golden plus standalone artifacts

Date: 2026-10-06. Status: accepted (scope); chart object names open.
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

## Open: chart object names

The owner's answer selected option 2 but did not choose between the two naming
options asked with it, and the existing records disagree:

- ADR-0013 #237 / spec 22 §2 and §12.2: keep `cilium`, `cilium-config`,
  `cilium-operator` object names and selectors so `cilium-cli`, dashboards and
  existing values files work against a flowsdn install (drop-in replacement).
- ADR-0017 (#299): flowsdn's own resources use flowsdn identity, the resolved
  ConfigMap default is `flowsdn-config`, the taint `node.flowsdn.io/agent-not-ready`,
  and new independently designed artifacts use flowsdn names; cilium-named
  objects would collide with an installed Cilium.

The chart is not written until this is answered on #294; the answer decides
the chart's object names, selectors, ConfigMap name and whether the values
surface tracks the reference's (spec 22 §3.6).

## Not changed

Milestone 4 acceptance still needs milestones 1–3 (#291–#293) accepted, runtime
runs on both architectures and the kernel/scale/performance checks. Neither
path above is evidence for those gates.
