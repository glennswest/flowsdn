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

As of 2026-10-03, source through `7c8a095` runs a standalone JSON-configured
agent over a Unix socket and a primary veth + loopback CNI. The agent embeds its
`local-delivery` BPF object (`bpf-object` optional) and has `egress: fib|stack`;
`flowsdn-cni install` installs the plugin and `00-flowsdn.conflist` on a node.
Persisted ownership, pinned endpoint maps/TCX links, offline deletion, bounded
endpoint reads and exact IPAM summaries are implemented. No TCP listener,
Kubernetes watches in the agent (the k8s watch client is library only),
complete service/policy integration, operator executable or Hubble
observer/relay exists. See `docs/runtime.md`, `docs/agent-api.md`,
`docs/implementation-status.md` and `deploy/stormcos/README.md` before changing
runtime behavior. Fixture traffic and cross-architecture compilation do not
establish two-node pod networking. Docs were last refreshed from code on
2026-10-03 (`git log --since=2026-09-25`).

## Shipping and ownership

The stormcos flowsdn edition carries the static musl agent (BPF object
embedded) and CNI in the `flowsdn` golden; `deploy/stormcos/manifests/` runs it
as `image: flowsdn` with a CNI-install init container (stormcos#261 applies
them). Latest golden: golden-flowsdn-a7ee3f63195b at c6c96c7 (ClusterIP socket LB, #292). Source pushes do not update nodes until a new golden is composed into
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

### Network performance suite — #321 (P0), 2026-10-05

Owner: flowsdn "totally done" with performance comparisons against Cilium, the data for making it
primary. A `perf` suite (declared in test/requires.toml, budget 1800 s) runs unchanged on both
flavors: an orchestrator pod (pod network, host PID for agent cost, cluster read of nodes) places
server pods (same image, `flowsdn-perf server`) on its own node and on another node through the
Kubernetes API, and measures with Rust clients. JSON lines per metric with `flavor`.
`flowsdn-perf` is a GNU binary (flowsdn-k8s, Fedora OpenSSL, ADR-0016); `/test` stays static musl.

- [x] flowsdn-k8s: generic JSON request (`send_json`).
- [x] `test/perf` crate `flowsdn-perf` with all metric groups; unit tests (stats, DNS codec, loopback wire protocols, /proc parsing, node/endpoint parsing).
- [x] `/test perf` dispatch; requires.toml `[perf]`; Containerfile/build.sh; docs (test/README metric table), changelog.
- [x] sc-build at e397e16: fmt, Clippy, 705 tests, test/build.sh, podman build; `/test perf` execs flowsdn-perf in the image. Status on #321; format on stormcentral#412.
- [ ] Runs on both flavors: 8c822b3547 (C2NR0Q2) 507 on push (stormcentral#376); f0107a4784/f68f31432b no pvetest VMs until install. Proposed after stormcentral#376.

### ClusterIP service datapath — #292 (P0), 2026-10-05

Owner (stormcos#265, 2026-10-05): no kube-proxy at all; flowsdn routes ClusterIPs itself, kube-dns and
the `kubernetes` Service on a single flowsdn node first. Design: socket LB (spec 05 §3.8, retained for
milestone 2 by ADR-0011) — cgroup v2 connect/sendmsg/recvmsg/getpeername hooks (v4, v6, v4-mapped)
over the Cilium-format `cilium_lb{4,6}_services_v2`/`_backends_v3`/`_reverse_sk` maps; translation at
the socket, so no packet DNAT/conntrack and it works for pods and the host. The agent fills the maps
from Service + EndpointSlice watches (`kubernetes` feature) with a stateless diff against kernel map
contents (spec 05 §3.4 write order: backends, slots, master; stale master/slots/backends after).

- [x] BPF `socket-lb` object (8 cgroup programs, random backend slot, UDP reverse map); embedded in the agent (`bpf/socket-lb`, sha256 62a680ff…); test/build.sh stale check. Disassembly reviewed (full key init, 4-byte ctx loads, u64 user_ip6 store at aligned offset 8).
- [x] flowsdn-lb `socket` planner (stable IDs from kernel maps, spec 05 §3.4 order) with tests incl. every-intermediate-state resolution.
- [x] Loader `SocketLb` (load, pins under `<pin root>/socket-lb`, cgroup attach AllowMultiple, dump/apply).
- [x] flowsdn-k8s Service/EndpointSlice scopes; agent watches, services thread, `GET /v1/service`, `kubernetes.service-lb`/`cgroup-root`.
- [x] Manifests (RBAC, host cgroup at /run/flowsdn/cgroupv2), docs, changelog; `socket-lb-live` fixture in medium suite.
- [x] sc-build at c6c96c7: fmt, workspace + kubernetes Clippy -D warnings, 697 tests (0 failed, 1 ignored) + 40 agent kubernetes tests, GNU kubernetes release build, test/build.sh.
- [x] Golden golden-flowsdn-a7ee3f63195b at c6c96c7 (release request stormcos#255; carries the GNU kubernetes agent, stormcos#171). Status comment on #292 (5999829276).
- [ ] fixture-socket-lb-live on a kernel: run dbfc4e45b1 (C2NR0Q2) failed on push, registry full (stormcentral#376). Rerun `stormcentral test run flowsdn medium --tag <machine>`; live kube-dns check on a flowsdn node after release. Not implemented (stays open on #292): NodePort/LB/externalIPs, affinity, Maglev, DSR, NAT46/64, tc-level LB, socket termination, policy.

### Kubernetes-connected agent — #291 (P0), 2026-10-05

Master (stormcos#171): flowsdn builds the Kubernetes-connected agent (flowsdn-k8s, glibc, system
OpenSSL) first; stormcos packages its Fedora runtime. Two-node target settled: pvetest1 + pvetest2,
both flowsdn flavor (stormcentral#383, run by stormcentral#360). No stormcos node sets
`spec.podCIDR`, so the agent derives its pod CIDR as spec 07 §3.4 says (10.<last IPv4 byte>.0.0/16).

- [x] Agent cargo feature `kubernetes` (off by default; the musl golden build is unchanged).
- [x] Config `kubernetes{node-name, kubeconfig, auto-direct-node-routes, direct-routing-skip-unreachable}`; pools/gateways `auto` from the Node (spec 07 §3.4).
- [x] Node + cluster Pod watches (flowsdn-k8s, relist with backoff) on a controller thread.
- [x] Remote node routes `<podCIDR> via <nodeIP> proto kernel` (spec 10 §3.2.3/§5.2): conflict check, persisted set for prune across restarts.
- [x] IP cache view `GET /v1/ip` (pods, node IPs with reserved host/remote-node identities) and `GET /v1/node/routes`; health module for Kubernetes.
- [x] Forwarding sysctls (spec 10 §3.6); `deploy/stormcos/manifests-kubernetes/`; kube-proxy advice removed from docs (owner: no kube-proxy).
- [x] Docs, changelog. sc-build at 91fca2c: fmt, workspace Clippy -D warnings, 685 tests (0 failed, 1 ignored), agent `--features kubernetes` Clippy + 37 tests (incl. loopback-HTTPS controller test), musl agent/CNI, test/build.sh. GNU release agent links libssl/libcrypto.so.3, libz, libgcc_s, glibc.
- [x] Handed the build to stormcos#171 (comment 5998765683); #291 status comment; proposed after stormcos#171. Remaining: cluster identity allocation, two-node acceptance on pvetest1+2.

### aya kfunc watch — #315 (P2), 2026-10-05

Owner (via #3, option 1): M3 socket termination uses netlink SOCK_DIAG/SOCK_DESTROY; check aya
weekly for kfunc relocation and switch to bpf_sock_destroy when it lands. GitHub Actions is off
(#304) and stormcentral has no scheduled component jobs yet (stormcentral#384).

- [x] `tools/aya-kfunc-watch` probe + `tools/aya-kfunc-watch.sh` (aya release/main/pinned x bpf-linker pinned/latest; exit 0 missing, 3 relocates, 1 broken; `--file-issue`, `--load`).
- [x] Finding: aya main resolves `.ksyms` externs (aya-rs/aya#1372, unreleased); the Rust object from bpf-linker 0.11.1 has no `.ksyms` entry -> `ExternNotFound`. 0.14.0 -> `UnknownFunction`.
- [x] sc-build at ea8ddd2: watch exit 0 (missing everywhere); f9fd312: rustfmt, Clippy -D warnings, cargo metadata --locked (#316 fmt failure fixed and closed).
- [x] Docs (tool README, build-and-test, spec 01), changelog.
- [x] Asked stormcentral#384 for the weekly sc-build run (exit 3 -> P1 switch issue). #315 open for the switch; proposed after stormcentral#384.
- [ ] When the watch exits 3: bump aya, declare bpf_sock_destroy into `.ksyms`, eBPF termination with SOCK_DESTROY fallback, a test per path.

### Services for the flowsdn edition — #292 (P0 via stormcos#265), 2026-10-05

Master: in the flowsdn edition no kube-proxy runs, so ClusterIPs don't route; agree with
stormcos on #265 whether flowsdn's service handling lands now or the edition runs kube-proxy.
flowsdn's service datapath (milestone 2) needs k8s watches, service maps and socket/tc LB
integration that do not exist yet, so kube-proxy is the fast route. Two `egress: stack` bugs
block it: same-node pod->pod is redirected in BPF (replies from a local backend such as CoreDNS
skip conntrack's reverse DNAT), and non-IP frames are dropped (the pod's ARP replies, so the host
cannot deliver routed packets to an IPv4 pod).

- [x] BPF: in stack mode local_delivery hands every frame to the host stack; embedded object rebuilt from sc-build output (sha256 cc22678a…) at f19cba3.
- [x] Docs/changelog (README, runtime.md, implementation-status, deploy/stormcos/README.md, agent README) at 26b7aea.
- [x] sc-build at 26b7aea: fmt, workspace Clippy -D warnings, 676 tests (0 failed, 1 ignored), test/build.sh embedded-object check passed (194 s).
- [x] Golden golden-flowsdn-84a7153fcfd0 at 26b7aea (release request stormcos#255). Agreed on stormcos#265: the edition runs rustkube-node kube-proxy (iptables) until milestone 2; stormcos applies flowsdn's manifests, ip_forward, masquerade.
- [x] #292 stays open (milestone 2 not delivered); status comment; proposed after #291.
- [ ] Live check on a flowsdn node once stormcos ships kube-proxy: a pod resolves kubernetes.default via 10.96.0.10 and reaches 10.96.0.1:443.

### Comment mining — 2026-10-04 (since 2026-10-04)

- [x] Read the 24 comments on 33 issues updated since 2026-10-04. Everything was already filed (stormcos#266, #261; stormcentral#249, #376, #383, #384; stormconsole#83; flowsdn#314). Added the #383 decision to stormcentral#360 and the #256 row recommendation to #309. No fixes. stormcentral#383 settled the two-node pair: pvetest1 + pvetest2, both installed with the flowsdn flavor through #360. That makes the "Owner input needed before two-node acceptance" line under #291 stale.

### Comment mining — 2026-10-03 (since 2026-09-29)

- [x] Read comments on the 32 issues updated since 2026-09-29. Filed stormcentral#383 (Decide: second flowsdn-flavor machine, P1, needs-owner), flowsdn#314 (aya kfunc relocation, P3), stormcentral#384 (scheduled jobs with secrets, P3) and stormconsole#83 (flowsdn plugin, P3). Commented on #291 (pvetest1 is cilium, so it isn't a flowsdn pair), stormcentral#360 and stormcentral#367 (the golden no longer needs the toolchain). No fixes.

### Docs refresh from code — 2026-10-03

- [x] Read `git log --since=2026-09-25` and compared README, docs/, crate READMEs, deploy/ and CLAUDE.md to the code.
- [x] README/runtime/deploy: embedded BPF object, `egress`, `flowsdn-cni install` + conflist, edition manifests, golden 600aa332b66d; validation examples fixed (#308).
- [x] Seccomp no-op under stormpump, ADR-0006 correction (#308); kernel-requirements stormcos-kernel correction and spec 13 protobuf fact (#309).
- [x] Changelog; comments on #308/#309. No code, version or golden change.

### __sk_buff ctx_in matrix — #256, 2026-10-03

Spec 18 §3.3(d)/§9.1: set each __sk_buff field through BPF_PROG_TEST_RUN ctx_in, read it in
the program, write some back, read ctx_out; record a per-kernel table on 6.6/6.12/6.18.

- [x] BPF `skb-ctx` (observe + write programs) and `skb-ctx-matrix` harness (flowsdn-bpftest); JSON table, exit 1 if a relied-upon field is unusable. Built and Clippy-clean at 2c1ee75.
- [x] Added to the test container's medium suite; stormcentral's runner built the image (run ca5226ff48) but the push hit 507 (stormcentral#376).
- [x] Owner decision (2026-10-05, option 1): the rows are the kernels stormcos ships (7.2.5-100.fc43 today); spec 18 §3.3(d)/§9.1/§10.2 and kernel-requirements §5.3 updated.
- [ ] Run `stormcentral test run flowsdn medium` on a test machine; close #256 when fixture-skb-ctx-matrix passes and record the per-field table in spec 18.
  2026-10-05: C2NR0Q2 run 5763251dcb hit 507 on push (registry full, stormcentral#376); pvetest1/2 refused (installing 11.80). Proposed after stormcentral#376.

### stormcos flowsdn edition pod network — #296 (P0), 2026-10-03

Master: 11.79-flowsdn on pvetest2 has no pod network (stormcos#261): no flowsdn manifests;
stormcos applied cilium's. Deliver manifests stormcos ships in the flowsdn edition. Findings:
the golden has the agent and CNI but no BPF object, the CNI is not in the host /opt/cni/bin,
nothing writes /etc/cni/net.d, and stormcos runs no kube-proxy (Cilium replaced it). The
BPF FIB-redirect path drops pod->host traffic and bypasses netfilter, so ClusterIPs could
not work even with kube-proxy.

- [x] BPF/loader/agent: `egress: stack` hands non-endpoint traffic to the host stack (.rodata.config global); agent adds host /32,/128 routes to endpoints in that mode.
- [x] Agent embeds the local-delivery object (used when `bpf-object` is absent); committed object, rebuild check in test/build.sh.
- [x] CNI `install` subcommand: copy plugin (+loopback) into host /opt/cni/bin, write /etc/cni/net.d/00-flowsdn.conflist atomically.
- [x] deploy/stormcos/manifests: ServiceAccount/RBAC, ConfigMap, DaemonSet (image `flowsdn` -> golden), single-node pool.
- [x] sc-build at a98a3e5: fmt, workspace Clippy, 676 tests, test/build.sh (embedded object check), static musl agent/CNI.
- [x] Posted the stormcos side on stormcos#261 (apply manifests, run kube-proxy, forwarding/masquerade). Golden golden-flowsdn-600aa332b66d at 4627158 (release request stormcos#255; first attempt hit a stage-platform sync error).
- [ ] Live check on pvetest2 (container probe) after stormcos ships the edition change; pvetest2 did not answer on :6443 tonight.

### Policy oracle decision — #103, 2026-10-03

- [x] Adopt spec 06's recommendation in ADR-0018 (ADR-0011–0013 precedent: choice + normative spec; compiler connection stays a #292 obligation). Confirmed mapstate never calls oracle::evaluate.
- [x] sc-build at 31b3ba2: flowsdn-policy Clippy -D warnings; 29 tests (kernel_map 6, mapstate 4, oracle 5, primitives 10, simulator 4) and a 4096-case kernel_map soak (31.9 s) pass. #103 closed.

### Milestone 2 acceptance — #292, 2026-10-03

- [x] Read the issue and docs/milestones.md: milestone 2 depends on milestone 1's pod network; service/policy code is primitives only.
- [x] Commented on #292 and proposed it after #291. Nothing implemented.

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
- [x] Owner decision (2026-10-05, option 1): SOCK_DIAG SOCK_DESTROY for M3; close #3 as verified; kfunc watch is #315.
- [x] Release kernel 7.2.5-100.fc43 (koji kernel-core config) has INET_DIAG/TCP/UDP_DIAG and INET_DIAG_DESTROY=y, DEBUG_INFO_BTF=y; recorded in kernel-requirements, inventory 02, spec 01. #3 closed.

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
