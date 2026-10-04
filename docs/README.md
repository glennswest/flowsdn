# Documentation guide

Current behavior was refreshed on 2026-10-03 against source through `7c8a095`
and `git log --since=2026-09-25`. Read the following as the operational entry
points, rather than treating specifications as a list of implemented features.

| Question | Current reference |
|---|---|
| Purpose, delivered features and golden delivery | [Project README](../README.md) |
| Executable configuration, defaults and ports | [Runtime reference](runtime.md) |
| HTTP methods, bounded reads and health meaning | [Standalone agent API](agent-api.md) |
| Edition manifests, host resources, CNI install | [stormcos integration](../deploy/stormcos/README.md) |
| Implemented libraries versus integrated runtime | [Implementation status](implementation-status.md) |
| Remaining networking acceptance | [Milestones](milestones.md), issues #291–#294 |
| Configuration library, separate from agent JSON | [Catalogue README](../crates/flowsdn-config/README.md) |
| Builds, tests and golden publication | [Build and publication](build-and-test.md) |
| Privileged fixture requirements | [BPF test harness](../crates/flowsdn-bpftest/README.md) |
| Test container (`/test short\|medium\|long`) | [test/README.md](../test/README.md) |

## Specifications and historical evidence

`spec/` records intended contracts and reference defaults; it includes
unimplemented controllers, listeners, commands, packaging and test harnesses.
A normative “must” is an acceptance requirement, not proof that current main
implements it. `inventory/` describes the pinned Cilium reference, not flowsdn.
`releases/` records the named release only; the latest foundation prerelease
remains v0.14.0 while main has additional executable runtime work.

`decisions/` records design choices. A closed decision issue or accepted ADR
does not prove delivery. In particular, the owner's #299 direction requires
flowsdn identity for owned CRDs; older text prescribing `cilium.io` ownership is
superseded. The library's registration plans now use `flowsdn.io/v1alpha1`
(ADR-0017). The earlier chart/image strategy does not describe the current
stormcos golden delivery path.

`validation/` and `workcycles/` are dated evidence for named revisions. Earlier
open-issue counts, runner availability and unsupported-path measurements should
be read at their recorded date. GitHub Actions is disabled and the obsolete
workflow was removed under #304. Current builds use sc-build and goldens use
stormcentral staging; see [the current build contract](build-and-test.md).
Historical runner/workflow records do not authorize re-enabling Actions. `velocity/` records observed time and usage with its stated cutoffs.
