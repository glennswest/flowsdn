# Documentation guide

Current behavior was audited on 2026-09-27 against source through `ce8f4d2`
and `git log --since=2026-09-18`. Read the following as the operational entry
points, rather than treating specifications as a list of implemented features.

| Question | Current reference |
|---|---|
| Purpose, delivered features and golden delivery | [Project README](../README.md) |
| Executable configuration, defaults and ports | [Runtime reference](runtime.md) |
| HTTP methods, bounded reads and health meaning | [Standalone agent API](agent-api.md) |
| Host resources, CNI and validation manifests | [stormcos integration](../deploy/stormcos/README.md) |
| Implemented libraries versus integrated runtime | [Implementation status](implementation-status.md) |
| Remaining networking acceptance | [Milestones](milestones.md), issues #291–#294 |
| Configuration library, separate from agent JSON | [Catalogue README](../crates/flowsdn-config/README.md) |
| Privileged fixture requirements | [BPF test harness](../crates/flowsdn-bpftest/README.md) |

## Specifications and historical evidence

`spec/` records intended contracts and reference defaults; it includes
unimplemented controllers, listeners, commands, packaging and test harnesses.
A normative “must” is an acceptance requirement, not proof that current main
implements it. `inventory/` describes the pinned Cilium reference, not flowsdn.
`releases/` records the named release only; the latest foundation prerelease
remains v0.14.0 while main has additional executable runtime work.

`decisions/` records design choices. A closed decision issue or accepted ADR
does not prove delivery. In particular, the owner's subsequent #299 direction
requires flowsdn identity for owned CRDs; older text prescribing `cilium.io`
ownership is not the current product direction. The library still needs that
migration. The earlier chart/image strategy also does not describe the current
stormcos golden delivery path.

`validation/` and `workcycles/` are dated evidence for named revisions. Earlier
open-issue counts, runner availability and unsupported-path measurements should
be read at their recorded date. The GitHub workflow is awaiting removal (#304);
current builds use stormcentral. No test was rerun merely by refreshing these
pages. `velocity/` records observed time and usage with its stated cutoffs.
