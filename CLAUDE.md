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

The owner requires flowsdn identity for CRDs it owns (#299). Owned registration now projects `flowsdn.io/v1alpha1`; upstream schema input
is explicit migration only. See ADR-0017; full workspace verification passed at 9c1ea61.
Read compatibility formats separately from ownership/attribution. PVCs are
provided by the built-in stormblock driver, not a flowsdn storage controller.
Current builds/tests use sc-build after push and flowsdn goldens use
stormcentral component stage flowsdn. GitHub Actions is disabled; #304 removes
the obsolete workflow. Do not add an Actions runner or re-enable Actions.

## Work plan

### Test containers — #303, 2026-10-03

One image (`test/Containerfile`, context repo root) answers `/test short|medium|long`
per stormcentral docs/test-standard.md. Every suite runs the commit's own agent, CNI and
BPF objects in anonymous network/mount namespaces inside a privileged pod (declared in
`test/requires.toml`); nothing touches host links or the host bpffs. A read-only node
probe reports skip unless the node carries the flowsdn CNI.

- [x] `test/` crate `flowsdn-test`: report (JSON lines, exit 0/1/2), preflight (kernel >= 6.6, BTF, privileges -> skip/2), node probe, real agent+CNI driver.
- [x] short: two dual-stack endpoints, UDP both ways, DEL, no residue (< 2 min).
- [x] medium: short + each namespace-isolated fixture (smoke, endpoint, native-routing, cni-runtime, agent-runtime, packet/uplink ingress, loader-features, socket-live), logs under /results.
- [x] long: endpoint-churn waves sized from the pod's CPUs/memory; per-wave ADD latency and residue (agent fds/RSS, pins, state, links); slowdown or growing residue fails.
- [x] `test/build.sh`: pinned nightly via rustup + SHA-pinned bpf-linker 0.11.1, BPF objects, musl binaries staged in test/.stage.
- [x] sc-build at f5a97b9: workspace fmt/Clippy/build/tests, test/build.sh and podman build pass; the image run unprivileged reports exit 2 as designed.
- [ ] Run short/medium through `stormcentral test run flowsdn` on a test machine. pvetest1 push failed 507 (registry full, stormcentral#376); pvetest2 (flowsdn flavor; its 11.79 install failed) also 507s, run 39d1523f0c; C2NR0Q2 is off overnight. Proposed after stormcentral#376. Rerun `stormcentral test run flowsdn short|medium --tag <machine>` when a registry has space.

### Aya feature verification — #3, 2026-10-03

- [x] Read the issue. `.rodata.config`, XDP frags and TCX pin/update already passed kernel probes on 2026-09-22.
- [x] Confirmed from the aya-obj 0.3.0 source that kfunc relocation is absent; recorded in spec 01.
- [ ] Owner decision (asked on #3, wait-owner): use SOCK_DIAG for M3 and close as verified (recommended), implement a flowsdn kfunc relocation pass, or wait for upstream. Nothing implemented yet.

### Comment mining — 2026-09-28

- [x] Review all 32 updated issues and 25 recent comments; confirm no older comment edits in the window.
- [x] Search owning repositories; file stormcos#183 (P1) for supported testbed provisioning and supplement existing owner decision stormcentral#83 with the flowsdn pair requirement.
- [x] Mark stormcentral#83 needs-owner and link both trackers from #296; remaining findings already covered.
- [x] Publish source-comment mapping in docs/workcycles/2026-09-28-comment-mining.md and accounting. No implementation fixes, tests, golden or release.

### Stormcos integration — #296, resumed 2026-09-28

Latest recheck: 2026-09-28 20:47 UTC. Read the issue and linked decision/provisioning trackers again. No owner answer is recorded; managed inventory still has only one Cilium test machine (latest test failed). Stop implementation per the explicit user instruction; retain the saved branch and request the disposable pair/provisioning owner on #296. Canonical dependencies: stormcentral#83 (needs-owner) and stormcos#183 (P1). No runtime work or validation performed in this recheck.

- [x] Read #296 body/comments, open backlog, current deployment contract and saved branch at 4a7eb49. #299 ownership prerequisite is now implemented and verified.
- [x] Recheck managed test inventory: only one Cilium test machine is registered, no disposable flowsdn pair. No host has been selected or modified.
- [x] Stop implementation for the owner's target decision, as explicitly requested in this session; question posted on #296 and queue item moved successfully to wait-owner.
- [x] Pushed documentation at 46bf8f3 passed sc-build whitespace/file-presence checks (0 seconds); remote drive deleted. No compilation/runtime acceptance claimed. Local run-history write was sandbox-denied after remote success.
- [ ] After the owner designates/registers a disposable flowsdn pair, recover and review saved liveness/schema/election/registration work against current Fedora OpenSSL and flowsdn ownership; complete operator integration and relay/deployment contracts.
- [ ] Push before sc-build; verify operator/network acceptance before closure. Keep #291 integration and stormcos packaging dependencies explicit.

The separate operator/relay architecture is already specified; no new architecture
choice is requested. The missing decision is the disposable acceptance target.
Saved #296 code remains on work/296-stormcos-integration and is not validated
or merged by this audit. No runtime, version, golden or release change.

### Remove obsolete GitHub workflow — #304

- [x] Read issue/comments and confirm GitHub Actions remains disabled through the read-only permissions API.
- [x] Remove crates.yml and replace active build/publication/runner promises with sc-build and stormcentral golden orchestration; source/docs review complete.
- [x] Validate #304 at 9e7144f through sc-build: workflow absence, locked xtask/packaging build and 16 passing tests; execution 412 seconds, scratch removed.
- [x] Request the flowsdn golden once: ea5a8e9a2762; main was f8d5cc8 when requested. The result is recorded below.
- [x] Recover staging result: job ea5a8e9a2762 selected flowsdn 4092ba1 but produced no golden; stormcos#155 tracks `named in ONLY and not staged: flowsdn`.
- [x] Revalidate pushed d54ee44 through sc-build: workflow absent, locked build and all 16 tooling tests passed (26 seconds); drive deleted. Verification recorded; #304 ready for closure. Golden repair belongs to stormcos#155; no runtime or version change.

The saved #299 checkpoint f35b620 is recovered and validated on main at 9c1ea61.
Other implementation checkpoints remain saved separately: #296 at 4a7eb49 on
work/296-stormcos-integration (schema/election/client source, unresolved new
transport lock dependencies and remote validation pending); #291 watch branch
is preserved. Do not overwrite these branches or claim them complete.


### Owned Kubernetes identity — #299, resumed 2026-09-28

- [x] Read issue/comments and open backlog; inspect preserved implementation f35b620.
- [x] Recover owned flowsdn.io/v1alpha1 CRDs, explicit upstream migration projection and documented runtime compatibility-name decisions; reconcile with current OpenSSL transport.
- [x] Reviewed all four ownership requirements; source e02d811 and formatting 9c1ea61 pushed. No further owner decision needed.
- [x] Full workspace build, formatting/Clippy, 710 tests and both musl checks passed at 9c1ea61 (283 seconds); one existing namespace fixture ignored.
- [x] Requested golden cdb5f2d45638 once at 06fcc81; stormcos staging failed after 34 seconds with flowsdn not staged. Existing stormcos#155 updated; no golden produced. Source issue #299 is verified and ready for closure with these limits.

### Milestone 1 implementation — #291, resumed 2026-09-28

- [x] Read acceptance and acknowledge open backlog; synchronize the previous audit already published upstream.
- [x] Rust loopback/install source is on main; combined build/tests passed at bfc19b2 (86 tests across agent/CNI/Kubernetes). Namespace runtime fixture remains unrun.
- [x] Recover saved watch state/HTTPS transport in 67cb727; remote lock/format in 556877f; fix ambiguous loopback lookup in bfc19b2.
- [x] At 03685f2, Clippy passed and affected Kubernetes/loopback tests passed again; 86 broader tests passed earlier at bfc19b2.
- [x] Owner approved a Fedora-provided C TLS provider on 2026-09-28; choose system OpenSSL via kube openssl-tls.
- [x] Fedora OpenSSL validated at e1a1e7b: 33 tests, format/Clippy, both static CNI checks, dynamic system linkage and all dependency-policy gates passed (168 seconds). See the Fedora TLS validation record.
- [x] Filed stormcos#171 for GNU/Fedora OpenSSL golden runtime; #291 integration and cluster acceptance remain open.
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
