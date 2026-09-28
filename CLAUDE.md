# flowsdn — Project Instructions

Rust networking implementation for stormcos, with Cilium-compatible boundary
formats as a goal. Follow `AGENTS.md` and the session's cross-project rules.
GitHub is the transfer/results path. Build only through `sc-build` after push;
never build on this session VM or create persistent build-box checkouts.

## Current version and source state

Workspace package version and latest foundation prerelease: **0.14.0**.
Version locations: `Cargo.toml` workspace.package.version and release headings
in `CHANGELOG.md`; Cargo.lock records workspace packages when versions change.
Main contains unreleased endpoint agent/CNI work beyond that foundation release.
This documentation-only audit does not warrant a version bump or release.

As of 2026-09-27, source through `ce8f4d2` runs a standalone JSON-configured
agent over a Unix socket and a primary veth CNI. Persisted ownership, pinned
endpoint maps/TCX links, offline deletion, bounded endpoint reads and exact IPAM
summaries are implemented. No TCP listener, Kubernetes watches, complete
service/policy integration, operator executable or Hubble observer/relay exists.
See `docs/runtime.md`, `docs/agent-api.md`, `docs/implementation-status.md` and
`deploy/stormcos/README.md` before changing runtime behavior. Fixture traffic
and cross-architecture compilation do not establish two-node pod networking.

## Shipping and ownership

The stormcos flowsdn edition carries the static musl agent and CNI in the
`flowsdn` golden. A matching BPF object and the documented host resources are
required; the current golden recipe omits that object and has unverified host
CNI exposure (stormcos#145). Source pushes do not update nodes until a new golden is composed into
a release. Authority:
[stormcos/docs/goldens.md](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
After validated implementation work, flowsdn uses the special-component
`stormcentral component stage flowsdn` path specified by the session rules.
Documentation-only work is not a networking release. Cargo.lock pins select
which dependency revisions are built; sibling changes do not arrive implicitly.

The owner requires flowsdn identity for CRDs it owns (#299). Registration
plans use flowsdn.io/v1alpha1; explicit reference-schema migration is separate.
No live custom-resource controller or stored-instance migration is implemented.
Read compatibility formats separately from ownership/attribution. PVCs are
provided by the built-in stormblock driver, not a flowsdn storage controller.
Current build orchestration is stormcentral; removal of the obsolete GitHub
workflow is #304. Do not reactivate it while refreshing documentation.

## Work plan

### Stormcos integration — #296

- [x] Read issue/comments and existing deployment/API contract; preserve #299 at f35b620 on work/299-crd-identity with its sc-build pending.
- [x] Add a bounded Unix-socket liveness command and validation DaemonSet exec probe, with failure/timeout coverage; source review complete, remote tests pending.
- [ ] Keep operator and relay availability explicit: accepted architecture requires separate operator and relay processes.
- [ ] Vendor the verified reference CRD schema bundle and expose owned registration payloads, a prerequisite for a real leader-elected operator; implement client/election/controllers next.
- [ ] Implement Lease election state/optimistic writes with monotonic expiry observation and terminal leadership-loss behavior, then connect the authenticated client and leader-scope controllers.
- [ ] Validate multi-node allocation and lifecycle rather than treating process scaffolding as a complete operator.
- [ ] Push and validate via sc-build; close only when operator/network and deployment acceptance obligations are satisfied.

Current #296 work is isolated on work/296-stormcos-integration. Earlier #291
watch/transport source remains on work/291-watch-state. The old queued 816c8c9
build was canceled before execution in favor of consolidated f35b620 validation;
cancellation exposed stormcentral#118's helper exit error, recorded there.


### Owned Kubernetes identity — #299

- [x] Project registration into flowsdn.io/v1alpha1 with Flowsdn kinds, owned names/category and schema label; retain explicit reference-schema input only.
- [x] Cover registration rejection/migration and owned operator resource scopes; document runtime-name compatibility decisions and correct ownership specifications.
- [ ] Commit/push each unit, validate through sc-build, record results, release/stage as appropriate and close with evidence.

Work is isolated on work/299-crd-identity. #291 watch/transport checkpoints
remain on work/291-watch-state at 6bab09a; dependency resolution is pending.
The sc-build for main 816c8c9 remains queued and may publish formatting to main.
Do not merge unvalidated watch dependencies into this ownership change.


### Milestone 1 implementation — #291, 2026-09-27

- [x] Read acceptance and acknowledge open backlog; synchronize the previous audit already published upstream.
- [ ] Implement Rust loopback CNI dispatch and compatibility binary installation from spec 09 and ADRs 0012–0013; add failure and overwrite coverage.
- [ ] Push source, then validate with sc-build; preserve exact errors and measured results.
- [ ] Continue Kubernetes Node/Pod watch, identity/ipcache and remote routing integration, then disposable two-node IPv4/IPv6 acceptance.
- [ ] Close #291 only after every acceptance gate passes; stage the flowsdn golden after verified implementation.

User reports stormcentral#102 and sandbox Git writes fixed. Recheck through the
normal build path; never use a persistent checkout on the build host.


### Active audit — 2026-09-27

- [x] Refresh README, current runtime/deployment documentation and this context from code and history since 2026-09-18; preserve owner terminology and file uncovered promises.
- [x] Validate the 28 requested open issues against code/tests and comments; close with evidence or prioritize remaining work without implementation changes.
- [x] Mine open and closed issue comments updated since 2026-09-18; deduplicate findings in their owning repositories and file gaps/owner decisions.
Results: `docs/workcycles/2026-09-27-audit.md`; docs #300/#301 closed,
26 requested issues retained/prioritized, stormcos#145 and rustkube#127/#128
filed, existing cross-project trackers supplemented. Remote documentation
validation could not start because SSH rejected system configuration permissions.
A repeat 284-issue/231-comment sweep filed stormcentral#102 (P1) for that
blocker; the sandbox reports the config target as UID/GID 65534. No host
configuration was changed; UID mapping needs owner investigation.

- Documentation-only audit: no runtime changes, no version bump or networking release claim. Coordinator owns Git and issue mutations; reviewers have disjoint documentation/read-only scopes.


The active implementation plan is `docs/milestones.md`, tracked by #291–#294.
The inventory/specification phases are historical; source and validation records
now cover 31 crates plus Rust tools, while live integration remains unfinished.
Resolve implementation and measurement obligations independently of closed
design issues. Preserve compact work-item records in `docs/velocity/ledger.json`
and its README, with unknown telemetry recorded as null.

## Reference and conventions

The inventory/specification reference is Cilium **v1.20.1, `7d68cfb394`**.
Follow `docs/licensing.md`; reference data is not executable flowsdn coverage.
`docs/README.md` distinguishes current behavior, intended contracts and history.

- Project executable code, test harnesses and reusable tools are Rust. BPF uses
  aya-ebpf; no copied C datapath and no iptables dependency.
- Read the relevant spec and architecture decisions before implementation,
  including subsequent owner directions that supersede historical choices.
- Use bounded parallel review with disjoint ownership. The coordinator alone
  mutates Git and serializes shared-host validation.
- Commit/push each work step with changelog and affected docs; inspect diffs for
  secrets. Scratch stays in ignored `tmp/`. Preserve observed validation results
  without upgrading a library/unit test into a runtime support claim.
