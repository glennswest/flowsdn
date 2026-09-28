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

The owner requires flowsdn identity for CRDs it owns (#299). Current planning
code still hardcodes `cilium.io`; do not describe that migration as implemented.
Read compatibility formats separately from ownership/attribution. PVCs are
provided by the built-in stormblock driver, not a flowsdn storage controller.
Current builds/tests use sc-build after push and flowsdn goldens use
stormcentral component stage flowsdn. GitHub Actions is disabled; #304 removes
the obsolete workflow. Do not add an Actions runner or re-enable Actions.

## Work plan

### Remove obsolete GitHub workflow — #304

- [x] Read issue/comments and confirm GitHub Actions remains disabled through the read-only permissions API.
- [x] Remove crates.yml and replace active build/publication/runner promises with sc-build and stormcentral golden orchestration; source/docs review complete.
- [x] Validate #304 at 9e7144f through sc-build: workflow absence, locked xtask/packaging build and 16 passing tests; execution 412 seconds, scratch removed.
- [x] Request the flowsdn golden once: ea5a8e9a2762; main was f8d5cc8 when requested. The result is recorded below.
- [x] Recover staging result: job ea5a8e9a2762 selected flowsdn 4092ba1 but produced no golden; stormcos#155 tracks `named in ONLY and not staged: flowsdn`.
- [x] Revalidate pushed d54ee44 through sc-build: workflow absent, locked build and all 16 tooling tests passed (26 seconds); drive deleted. Verification recorded; #304 ready for closure. Golden repair belongs to stormcos#155; no runtime or version change.

Implementation checkpoints remain saved separately: #299 at f35b620 on
work/299-crd-identity (validation deferred before execution for current #304); #296 at 4a7eb49 on
work/296-stormcos-integration (schema/election/client source, unresolved new
transport lock dependencies and remote validation pending); #291 watch branch
is preserved. Do not overwrite these branches or claim them complete.


### Milestone 1 implementation — #291, resumed 2026-09-28

- [x] Read acceptance and acknowledge open backlog; synchronize the previous audit already published upstream.
- [x] Rust loopback/install source is on main; combined build/tests passed at bfc19b2 (86 tests across agent/CNI/Kubernetes). Namespace runtime fixture remains unrun.
- [x] Recover saved watch state/HTTPS transport in 67cb727; remote lock/format in 556877f; fix ambiguous loopback lookup in bfc19b2.
- [ ] Finish lint/dependency gates at c026bfb after the 86 passing tests; see docs/validation/2026-09-28-m1-recovery.md.
- [ ] Connect watch reconciliation, identity/ipcache and owned remote routes to the endpoint agent; review ADR acceptance in parallel.
- [ ] Push each source checkpoint before sc-build; preserve exact errors and measured results.
- [ ] Continue Kubernetes Node/Pod watch, identity/ipcache and remote routing integration, then disposable two-node IPv4/IPv6 acceptance.
- [ ] Close #291 only after every acceptance gate passes; stage the flowsdn golden after verified implementation.

Owner input needed before two-node acceptance: provide/register a disposable flowsdn pair or an existing managed target. Only a Cilium machine is registered; the referenced provisioning script requires prohibited root SSH. Do not repurpose it or close #291.

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
