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

As of 2026-10-09, source through `eed1aca` runs a standalone JSON-configured
agent over a Unix socket (`/var/run/flowsdn/flowsdn.sock` in the manifests) and a
primary veth + loopback CNI (`flowsdn-cni`, conflist `00-flowsdn.conflist`). The
agent embeds its `local-delivery` BPF object (and, with the `kubernetes` feature,
`socket-lb`; both pinned by `bpf-objects.lock`) and has `egress: fib|stack`. With
the `kubernetes` feature (GNU build, Fedora OpenSSL; in the golden since
golden-flowsdn-4e9e3f0bc876, run by `manifests-kubernetes/`) it watches Nodes/Pods/Services/EndpointSlices, adds
remote pod-CIDR routes, translates ClusterIP/externalIP/LoadBalancer/NodePort at the
socket (cgroup hooks, ClientIP affinity, traffic policy Local), serves external
NodePort/LB/externalIP traffic on the uplink (TCX, IPv4 and IPv6, SNAT to other
nodes' backends), writes Events and the `flowsdn.io/pod-networks` annotation.
`http-listen` is a loopback read-only TCP listener (#297). Not implemented:
identity allocation (#291), policy enforcement in the datapath (the NetworkPolicy
importer/simulator in flowsdn-policy is library only), the operator executable,
CRD registration (#337), Hubble observer/relay (#293), Maglev/DSR. See
`docs/runtime.md`, `docs/agent-api.md`, `docs/implementation-status.md` and
`deploy/stormcos/README.md` before changing runtime behavior. Fixture traffic and
cross-architecture compilation do not establish two-node pod networking. Docs
were last refreshed from code on 2026-10-09 (`git log --since=2026-10-02`).

## Shipping and ownership

The stormcos flowsdn edition carries the agent (static musl and GNU Kubernetes
mode) and CNI in the `flowsdn` golden; `deploy/stormcos/manifests-kubernetes/` runs it
as `image: flowsdn` with a CNI-install init container (stormcos#261 applies
them). Latest golden: golden-flowsdn-de1d63ada483 at 1254993 (DSR, Maglev, host firewall, flowsdn policy kinds, NAT46/64; features off by default, kernel test runs only). Earlier: golden-flowsdn-760c3a2e89d6 at 9732b71 (NetworkPolicy enforcement, #292; stormcos#528). Before it: golden-flowsdn-a690ebee2ba7 at 4447eeb (IPv6 NodePort, identity allocation, network-status; stormcos#494). Goldens before golden-flowsdn-4b40a980ad16 carry a socket LB that cannot attach on 7.2 (cda5799). Source pushes do not update nodes until a new golden is composed into
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

### Service NAT46/64 on the uplink — #292 (P0), 2026-11-06

Queue released #292 (12.62 carries registry 9912c98), but 12.62-flowsdn is still composing and pvetest2 is on 12.61-flowsdn: medium and perf wait for the install. Next row meanwhile (ADR-0011 #79; RFC 6052 gateway stays milestone 3).
`kubernetes.nat46x64` bool, default false. A scope-1 frontend with no backends of its own family and some of the other family on other nodes gets `SVC_FLAG_NAT_46X64` and those backends. `nodeport_ingress` translates (bpf_skb_change_proto), always SNATs to this node's address of the backend's family on a port in 61000-65535, redirects by the FIB; the backend's reply is translated back at uplink ingress.
Local backends are excluded: a pod's reply to the node's address is local input and never reaches the uplink. Refused, passing untouched: IPv4 options, fragments, zero UDP checksum, a packet that outgrows the MTU. Socket LB untranslated (an AF_INET socket cannot reach IPv6).
Maps: `flowsdn_nodeport4_xlate` (v4 key -> v6-sized value), reply/forward on the v6 side stay in `flowsdn_nodeport6_nat` with FLOW_XLATE and v4-mapped addresses; a NAT64 port is reserved in `flowsdn_nodeport4_nat`.

- [x] BPF, planner flag, agent setting, loader maps, socket-lb-live NAT46/64 step, object + lock, docs (spec 04/05 notes), changelog. kernel-check at 512a2ca on 7.2.11-200.fc44: 18 pass, 0 fail, 2 skip; socket-lb-live 25 PASS incl. NAT46/64 (first run). HEAD has the same lock.
- [x] sc-build at 51794d9: fmt, workspace + kubernetes Clippy -D warnings (+ indexing, arithmetic), 848 workspace + 93 kubernetes agent tests (0 failed, 1 ignored), chart-check.
- [x] Stage requested at 5167d1f; status on #292. 12.62 and 12.62-flowsdn tombstoned (did not boot clean on pvetest1). #292 proposed --after-release flowsdn>=5167d1f.
- [ ] Then: medium on pvetest2 once it runs that release; perf on pvetest2 and pvetest1. Next BPF rows (IPIP/Geneve DSR, DSR ICMP errors) wait for that node run. Check GSO/offload on real NICs and two-node traffic for NAT46/64 and DSR.

### Kernel check in a build VM — #292 (P0), #370, 2026-11-06

stormblock-registry#150 is fixed (v0.55.1) but reaches pvetest1/2 only with a release, so main's Maglev + host-firewall objects stay unloaded on 7.2.
Build VMs have /dev/kvm (0666), qemu and a readable /lib/modules/<release>/vmlinuz (7.2.11-200.fc44), so no root is needed: `cargo xtask kernel-check`
packs test/.stage + ip, nft, kmod (+ libs) + kernel/net modules into an initramfs (Rust newc writer), boots the build VM's own kernel in qemu with /test
as PID 1 (`rdinit=/test`, flowsdn.suite=medium), reads the JSON lines on the serial port. Not a hardware pass: it does not replace the pve medium, perf or live acceptance.

- [x] xtask `kernel` module + tests; /test PID 1 mode (test/src/vm_init.rs).
- [x] First runs found socket-lb unloadable on 7.2 since 38f1c27 (Maglev index, `R0 unbounded memory access`); fixed with a volatile read, object + lock rebuilt.
      Run with the fix on 7.2.11-200.fc44: 18 pass, 0 fail, 2 skip (node probes), socket-lb-live 23 PASS, policy-live 13 PASS.
- [x] Docs (build-and-test, test/README, xtask README), changelog; stage precondition for #370.
- [x] Full sc-build at 23ee542 (fmt, Clippy x2, 845 workspace tests, kubernetes agent tests, chart-check); stage a492ebac8856 requested; #370 closed.
- [ ] Hardware medium + perf wait for a release carrying stormblock-registry v0.55.1.

### DSR on the uplink NodePort path — #292 (P0), 2026-11-06

Next row, since kernel-check lifts the "unverified objects" hold. Spec 05 §3.12, spec 02 §2.5 wire format, `opt` dispatch only. Scope-1 master with `FWD_MODE_DSR` and a backend on
another node: `nodeport_ingress` keeps the client source, DNATs, adds the IPv4 option (0x9a, len 8, port, addr) or IPv6 24-byte Destination Options (type 0x1B, len 20) on a TCP SYN or a UDP
packet that fits the MTU (too big: no option, DSR ICMP errors not done), FIB-redirects. Backend node's `nodeport_ingress` records the REPLY entry from the option; `nodeport_egress` already rewrites the reply's source.
`kubernetes.lb-mode: snat|dsr|hybrid` (default snat), annotation `service.flowsdn.io/forwarding-mode: dsr|snat`. ipip/geneve dispatch: not done.

- [x] BPF, planner flag, agent setting + annotation, socket-lb-live DSR step, object + lock, docs, changelog. kernel-check at 2e886e4 on 7.2.11: 18 pass, 0 fail, 2 skip; DSR PASS.
- [x] kernel-check at 9ad4b2b (18 pass, 0 fail, 2 skip; same lock as HEAD). sc-build at 2e8cb60: fmt, Clippy x2 -D warnings, 846 workspace + 92 kubernetes agent tests (0 failed, 1 ignored), chart-check.
- [x] Golden golden-flowsdn-5ec614dc2136 is at 07c64f2, mid-DSR (pushed while its stage waited): object without DSR, `lb-mode` inert. Staged again after this line.
- [ ] Item proposed after stormblock-registry>=9912c98 in a release: `stormcentral test run flowsdn medium --tag pvetest2`, then perf on pvetest2 and pvetest1. Then NAT46/64 (ADR-0011 #79, not started), IPIP/Geneve DSR, DSR ICMP errors, two-node DSR traffic.

### Pod rules of the flowsdn policy kinds — #292 (P0), 2026-11-06

stormcos#271 closed today (pvetest1/2 on 12.61 take forge test images): medium b2db11018c at 0fbbb1c queued on pvetest2
(socket-lb-live Maglev for #292, policy-live host steps for #379). Pass -> stage golden, then perf (live NetworkPolicy + ClusterIP).
Meanwhile the next row, agent only (no BPF object change): FlowsdnNetworkPolicy and FlowsdnClusterwideNetworkPolicy
`endpointSelector` specs to the endpoint policy maps (#331 leaves the agent watch to #292). `kubernetes.flowsdn-policy` bool,
default false (stormcos#303: CRDs are not applied, and the policy thread waits for this list). Rules: ingress/ingressDeny/egress/egressDeny,
from/to Entities, CIDR, CIDRSet, Endpoints (spec 06 §3.2.9 namespace + cluster injection), toPorts with named ports; `enableDefaultDeny`
(§3.2.8: true iff the direction has rules; false adds a wildcard allow, §3.6); denies win over allows, also NetworkPolicy's.
§3.2.1 combination matrix fails the whole resource. Skipped + reported: L7, ICMP, FQDN, toServices, groups, nodes, reserved selectors.
`ingress: [{}]` allows nothing (as the host firewall, ADR-0022), though spec 06 §3.2.1 reads it as wildcard (noted there).

- [x] flowsdn-k8s scope; host_policy parser both directions + pod specs; policy compiler merge; setting; tests (d867024).
- [x] Docs (runtime, agent-api, implementation-status, milestones, deploy README, spec 06 note), changelog.
- [x] sc-build at 7805ca8: fmt, workspace + kubernetes Clippy -D warnings (+ indexing, arithmetic), workspace + kubernetes agent tests:
      931 passed, 0 failed, 1 ignored, incl. 9 new compiler tests. No object change, so test/build.sh not rerun.
- [ ] Medium b2db11018c errored: stormblock-registry#150 (by-digest forge fetch, tag 404; every fetched run on the
      pve pair since 12.61, evidence on the issue, master told). When fixed: `stormcentral test run flowsdn medium --tag pvetest2`; pass ->
      stage the golden; perf on pvetest2 and pvetest1. New BPF rows (DSR, NAT46/64) wait: Maglev and host-firewall objects are still unverified on 7.2.

### Manifests carry addonmanager Reconcile — #388 (P1), 2026-11-04

stormcos#668: the applier defaults to EnsureExists, so flowsdn's objects never update over kept data and can never be
pruned on a flavour switch (rustkube#236 prunes only Reconcile). Golden ships `manifests-kubernetes/*.yaml` (top level; `manifests/`
without the Kubernetes agent), so both sets get `addonmanager.kubernetes.io/mode: Reconcile` as label and annotation (the annotation for
appliers before rustkube#299), with a test. `crds/` is not in the golden (stormcos#303 open) and stays unmarked.

- [x] Label + annotation on every object in both sets; test; README, changelog (0072c3a). sc-build at 0072c3a: fmt, workspace Clippy
      -D warnings, 831 tests (0 failed, 1 ignored), chart-check; removing one annotation fails the new test (expect-fail run).
- [x] Golden requested (`component stage flowsdn --no-wait`). Not run on a node: a flavour switch on server1 is stormcos#668's acceptance.
      A node already holding unmarked flowsdn objects under a cilium release (server1) is not pruned: they are in no inventory (told stormcos#668).

### Install check to Rust — #375 (P3), 2026-10-13

Owner: "is the shell not rustable?" flowsdn's install check is `install/kubernetes/check.sh` (the chart check:
helm lint, renders, version match, 22 CRDs, kinds, no Cilium names, guards refuse). No shipped artifact
carries shell (golden = agent + CNI binaries, CNI `install` is Rust; the packaged chart excludes check.sh), so
the check belongs in build tooling, not the node binaries: `cargo xtask chart-check` (Rust, drives helm via
std::process), check.sh deleted, deploy/release/build.sh calls it.

- [x] xtask `chart` module + pure checks with unit tests; release build.sh; delete check.sh (f1b4c1e, fmt 1d6f422).
- [x] Docs (helm.md, build-and-test, ADR-0019/0020, xtask README), changelog. sc-build at 1d6f422: fmt --check, xtask Clippy
      -D warnings, 16 xtask tests, `cargo xtask chart-check` passes (lint, 22 CRDs, 4 guards refuse); at f1b4c1e a wrong
      Chart.yaml version makes it fail. #375 closed. Build-only scripts (tools/, test/build.sh, release/image build.sh) remain.

### Cloud fixture machinery — #391 (P3), 2026-11-03

ADR-0007 §1-3 / spec 07 §9.1, the provider-independent half (capture and scenarios need a provider client that
sends requests, #293, and an account). New crate `flowsdn-cloud-fixture`: fixture model (`NNN-<op>.json`
{request{method,path,headers,body}, response{status,headers,body}}, `scenario.toml`), loader that scans first;
`scrub` (deterministic placeholders per scenario in reserved forms: AWS ids `<p>-5c7b…`, account `0000000000NN`,
GUIDs `00000000-0000-4000-8000-…`, public IPs 203.0.113.0/24 / 2001:db8::/32, hosts `host-N.scrubbed.invalid`;
credential headers, signature params and token JSON keys -> `scrubbed`); `scan` (same classes in real form);
`replay` (in-order match on method, path + canonical query, canonical JSON/form body without volatile signing
params; closest-interaction report; strict unused check); `server` (loopback HTTP/1.1, Content-Length + chunked,
never proxies). `cargo xtask cloud-scan` over tests/cloud.

- [x] Crate + unit tests; xtask cloud-scan; Cargo.lock by hand (6683890, fmt 27bcbb7). sc-build at 6683890: crate +
      xtask Clippy -D warnings (+ indexing, arithmetic), 21 + 16 tests, `cargo xtask cloud-scan` clean (no tree).
- [x] Docs (crate README, spec 07 §9.1 note, ADR-0007 status, xtask README, build-and-test, implementation-status),
      changelog; xtask test scans the committed tests/cloud in every build.
- [x] Full workspace sc-build at 90a5bc9: fmt, Clippy x2, 830 tests (0 failed, 1 ignored), cloud-scan clean.
- [x] Status on #391; proposed after #293. Open: cloud-record capture, 14 scenarios/provider, `--check` (#260),
      smithy replay; need a provider client that sends requests and an account per provider.

### Cloud drift job — #260 (P3), 2026-11-03

- [x] Blocked on code: no recorder xtask, tests/cloud fixtures, replay, or provider that sends requests (Azure crate is a
      planner; spec 07 is milestone 3). Filed #391 (ADR-0007 §1-4 + `--check`); #260 proposed after it. Runner exists
      (stormcentral#384 schedules + secrets). Owner provides accounts/read-only creds once #391 exists.

### Test image lock check fails at 3c470aa — #292 (P0), 2026-11-03

stormcentral#846 closed 2026-10-19, but every test image at 3c470aa failed `test/build.sh`'s lock check (db5d9fc564,
52ddea67d7): local-delivery's stack offsets depended on the checkout path (flowsdn-bpf-abi is outside the
flowsdn-bpf workspace, so cargo hashes its absolute path into -C metadata). pvetest1/2 refuse runs (stormcos#271:
their sbregistry takes no forge test images); C2NR0Q2 accepts.

- [x] Wrapper replaces -C metadata of flowsdn's crates with a path-free hash (e161dd7). sc-build: three paths, identical
      code = committed lock; fmt, Clippy x2, 808 tests, test/build.sh. #389 was my diagnostic's bare `diff` (closed).
- [ ] Medium c7a3d99110 at e161dd7 on C2NR0Q2 skipped: a pve pass comes first (#791), and pvetest1/2 refuse runs until a
      release carries stormcos#271 (shipped there). Status 6613574893; #292 proposed after stormcos#271. Then
      `stormcentral test run flowsdn medium --tag pvetest2` (Maglev step; #379 host steps); pass -> stage; then perf.

### Host firewall (host-policy plugin) — #379 (P2), 2026-10-14

stormcos#558 (stormfw): HostFirewallPolicy -> Cilium host firewall (CCNP + nodeSelector) or flowsdn. Input here is
the same model: `FlowsdnClusterwideNetworkPolicy` (flowsdn.io/v1alpha1, already shipped, RBAC list/watch) with
`spec.nodeSelector` (and `specs[]`), so stormfw translates to FCNP as it does to CCNP. No stormfw schema needed.
Design (ADR-0022): host endpoint ID 65536 in the ADR-0021 maps; `flowsdn_policy_ep` entries keyed by each uplink
ifindex (interfaces holding this node's InternalIPs); local-delivery gets `from_netdev` (uplink TCX ingress:
enforce only when the destination's ipcache identity is host) and `to_netdev` (uplink egress: track host-sourced
flows so replies pass). `kubernetes.host-firewall: off|audit|enforce` (default off): on attaches the programs
and tracks host flows; ingress enforcement starts 60 s after attach (learning). Audit flag (enforce bit 4):
would-be drops counted and passed; FCNP annotation `policy.flowsdn.io/audit: "true"` puts the host in audit.
Verdict counters `flowsdn_policy_verdicts` (LRU per-CPU {endpoint, port, proto, dir, verdict} -> packets/bytes)
for every enforced endpoint; `GET /v1/policy/verdicts`. Rules: ingress/ingressDeny with fromEntities, fromCIDR,
fromCIDRSet, fromEndpoints, toPorts (port, endPort, protocol); precedence per spec 06 §3.5.2 (allow FF01, deny
FFFFFFFF), denies propagated over allows they cover. Remote nodes get ipcache identity remote-node (6); ipBlock
keeps selecting them (as the host). Not covered: host egress policy, pod-to-host on veths, L7/FQDN/ICMP rules.

- [x] ABI (AUDIT bit, HOST_ENDPOINT, verdict key/value); BPF from_netdev/to_netdev, scope + audit + counters (8b02e45).
- [x] Loader: verdict map, attach_host/detach_host; nodeport links first in TCX order (8b02e45).
- [x] flowsdn-k8s: ClusterwidePolicies scope, Node labels. Agent: setting, host_policy compiler (+ tests), remote-node
      ipcache, API thread host attach tick, /v1/policy/verdicts, health (8b02e45).
- [x] policy-live host steps; object + lock (12ec054); ADR-0022, docs, changelog (eaab1f5). sc-build at 12ec054: fmt,
      Clippy x2, 890 tests (0 failed, 1 ignored), test/build.sh. Status 6172466673; stormcos#558 told the interface.
- [ ] Medium 71c495971d at 12ec054 queued on pvetest2 (stormcentral#846: pvetest2 does not come up; C2NR0Q2 refuses).
      `stormcentral test show 71c495971d`: policy-live host steps (+ socket-lb-live Maglev for #292). Pass -> stage
      the golden (`stormcentral component stage flowsdn`), close #379 with the run.
- [x] 2026-11-03: 71c495971d errored (apiserver /readyz); later images failed the lock check (fixed e161dd7, #292).
- [x] 2026-11-06: policy-live 13 PASS incl. 5 host steps, kernel-check at 9ad4b2b on 7.2.11 (same object as golden-flowsdn-e23d9621fbd6 at 9fe5661). `shipped`. Hardware medium runs with #292;
      a live firewall on a real uplink needs stormcos#303 and is on #384. stormfw exists but is empty and paused (stormfw#1).

### Maglev on the uplink NodePort path — #292 (P0), 2026-10-14

Golden golden-flowsdn-2321f5468852 (flowsdn@6d5b744, stormcos#528) carries everything below through UDP
termination (built in the 12.23 wave after stormcentral#841). Live perf waits on stormcentral#846. Next #292
row: Maglev (spec 05 §3.13/§5.1, spec 02 §3.12) for external traffic (scope-1 frontends, `nodeport_ingress`).
Design: BTF `HashOfMaps` `flowsdn_lb{4,6}_maglev` (u16 service id -> inner ARRAY 1 x `u32[16381]`, spec 01
§2.2); the planner builds each Maglev frontend's LUT with `flowsdn_lb::maglev::table` (seed bytes 0-3 of the
default `JLfvgnHc2kaSUFaI`), writes it after backends and before the master (algorithm byte 2), deletes stale
LUTs after masters. BPF: master algorithm 2 + LUT -> `lut[jhash(tuple, seed) % M]` (v4 jhash_3words, v6 the
reference's two-round mix; sport 0 with affinity), else random slot. Agent: `kubernetes.lb-algorithm`
(random|maglev, default random), annotation `service.flowsdn.io/lb-algorithm`. M and seeds fixed (cluster-wide).

- [x] ABI jhash/tuple hash + constants; planner LUTs + ops + tests; loader outer maps (pin check, dump, apply) (38f1c27).
- [x] BPF selection in nodeport4_in/new_flow6_in; agent setting + annotation; socket-lb-live Maglev step (38f1c27).
- [x] Docs (spec 05/02 notes, runtime, agent-api, implementation-status, milestones, README), changelog (c096990).
      Object + lock from sc-build at 21b7d3a (21ce52d). sc-build at fb44da4: fmt, Clippy x2, 877 tests (0 failed,
      1 ignored), test/build.sh (lock matches, no-cilium). Catalogue provenance lines remapped (#358 fragility).
- [ ] Medium 17f361a64f at fb44da4 errored: pvetest2 did not come up (stormcentral#846, commented); C2NR0Q2 refuses
      (12.21 install failed). Status comment 6171634972; #292 proposed after stormcentral#846. When a machine runs:
      `stormcentral test run flowsdn medium --tag pvetest2`; if socket-lb-live passes (Maglev step), stage the golden
      (`stormcentral component stage flowsdn`); then the perf run (live policy + ClusterIP).
- [ ] Medium on a 7.2 machine (socket-lb-live Maglev step), then stage.

### UDP socket termination — #292 (P0), 2026-10-13

Spec 05 §3.8 "Socket termination" (owner #3: netlink SOCK_DESTROY, not the kfunc). When UDP backends leave
the socket LB's services, destroy the sockets it translated to them (cookie in `_reverse_sk` with that
backend) in the host netns and each local pod's netns. Pod netns: the CNI also sends the observed
`CNI_NETNS` (stormcos: /run/netns/<sandbox>, persistent) as `container-netns-path`; the agent enters it only
when the namespace's cookie equals the endpoint's `NetnsCookie` (#130's rule kept: a path is not proof).
The DaemonSet mounts host /run/netns (HostToContainer). EOPNOTSUPP -> `socket-termination` degraded.

- [x] connector `sock_diag` (dump UDP v4/v6, destroy by id+cookie, enter netns by path + cookie check); unit tests (c703fb4).
- [x] loader `SocketLb::reverse_sockets`; agent services thread: removed UDP backends -> cookies -> destroy.
- [x] CNI sends container-netns-path; agent keeps it; manifests/chart mount /run/netns; spec 09/05 notes.
- [x] socket-lb-live termination step; docs, changelog. sc-build at 8c77624: fmt, Clippy x2, 858 tests. Medium d1d0a2bec6
      on pvetest2 (12.21-flowsdn, 7.2.8): socket-lb-live 22 PASS incl. termination, policy-live 8, node-service-dns/-programmed
      pass (#368); node-service-kubernetes wrongly expected a TCP peer = ClusterIP (fixed 228925e). Test image at 228925e
      hit a path-dependent BPF build (RUSTFLAGS remaps hashed into -C metadata), fixed 00d59f9 (rustc wrapper; same objects).
- [x] Medium 3a2829dedb at e140887 on pvetest2 (7.2.8): 23 pass, 0 fail, incl. node-service-dns/-programmed/-kubernetes
      (fixed probe), socket-lb-live 22 PASS, policy-live 8 PASS.
- [ ] Golden: #827 fixed (2026-10-14), but build 745f3ee2edf9 aborts on stormcentral#841 (sc-build-out mounts the
      multipath path /dev/nvme0c0n1; commented). Stage again when #841 is fixed.
- [ ] Live policy + ClusterIP on pvetest2 (12.21-flowsdn carries 760c3a2e89d6): perf 7899f5fca9 (policy-deny-enforced,
      policy-remove-restored, policy-rules-100/1000, svc-*-clusterip) errored: pvetest2 did not come up within 30 min of
      power-on (stormcentral#846, commented). Earlier perf runs failed at setup on stormpump#102 (SA token behind
      Fedora's /var/run symlink), fixed in golden-stormpump-236d2ed1dadd. Rerun
      `stormcentral test run flowsdn perf --tag pvetest2` when #846 is fixed.

### Network policy in the datapath — #292 (P0), 2026-10-13

Next #292 row: identity/CIDR L3/L4 policy enforced in BPF (Kubernetes NetworkPolicy first). Design
(ADR-0021): one shared program pair on each endpoint's host veth, so no per-endpoint object:
`local_delivery` (veth ingress = pod egress) and new `to_container` (veth egress = pod ingress).
Maps: `flowsdn_policy_ep` (host-veth ifindex -> endpoint id + enforce bits; absent = no policy, today's
behaviour), `flowsdn_ipcache` (IpCacheKey LPM -> identity; miss = world), `flowsdn_policy` (LPM:
32-bit endpoint id + spec 06 §3.8 PolicyKey/PolicyEntry, same three lookups), `flowsdn_policy_ct`
(LRU, {tuple, direction}: established = {p, d}, reply = {reverse(p), !d}; lazy expiry). Always pass:
non-IP, NDP, ICMP frag-needed/PTB; ingress from host (1). pvetest2's 12.16-flowsdn install failed,
so no flowsdn node runs tests right now (pvetest1 medium d98fac3ee3 at 728f595 passed, cilium flavor).

- [x] ABI (EndpointPolicyKey, PolicyEndpoint, PolicyCtKey/Value), BPF policy module + `to_container`, loader maps/egress attach (778c0f0, PolicyMaps 3073f32).
- [x] `policy-live` fixture (BPF_PROG_TEST_RUN: deny/allow/aggregate/port LPM/CT reply/host/NDP); medium suite.
- [x] Object + lock via sc-build (330f46a; max frame 240 B by r10 scan). Clippy x2 + tests passed at 778c0f0 (fmt pending).
- [x] Agent: NetworkPolicy watch, `policy.rs` compiler (+ tests), policy thread, ipcache, RBAC (b1ef8b0).
- [x] Docs (ADR-0021, runtime, agent-api, implementation-status, milestones, spec 06/02 notes), changelog (82a42a4).
- [x] Restore keeps a restored endpoint's pinned policy entry (d8e0db9). sc-build at d8e0db9: fmt, Clippy x2, 856 tests (0 failed, 1 ignored) + kubernetes agent tests. Status comment 6150239436.
- [x] Medium a75ea7d2c5 failed: 7.2 verifier "R4 !read_ok" (Option spill), fixed 3baa8c6/5bcbc3e. Medium 083bcf346f at 5bcbc3e on C2NR0Q2: 18 pass, policy-live 8 PASS.
- [x] Golden golden-flowsdn-760c3a2e89d6 (flowsdn@9732b71, release request stormcos#528).
- [ ] Live NetworkPolicy + ClusterIP acceptance on a flowsdn node once a release carries it (pvetest2's 12.16-flowsdn install failed). Was: Medium a75ea7d2c5 at 6362125 on C2NR0Q2 (leased to another session until 17:28Z; pvetest1/2 refuse: 12.16 installs failed): `stormcentral test show a75ea7d2c5`. If policy-live passes, `stormcentral component stage flowsdn`; else fix the verifier finding.

### node-service probe takes the env as the ClusterIP — #368 (P0), 2026-10-10

On stormcos `KUBERNETES_SERVICE_HOST` is the apiserver's node address, so node-service-dns/-programmed fail
on a working node (medium c61945e336, ef8e24151d on pvetest2). Fix in test/src/services.rs: the `kubernetes`
Service's address comes from kube-dns (the DNS answer), its port and programmed state from the agent's
`GET /v1/service` row `default/kubernetes` (ClusterIP, scope external); connect to that ClusterIP:port.

- [x] Code + tests, test/README, changelog (c791491, fmt 1f1ed95). sc-build at c791491: Clippy -D warnings (+ indexing, arithmetic), 8 flowsdn-test tests.
- [x] Medium d1d0a2bec6 on pvetest2 (12.21-flowsdn): node-service-dns and -programmed pass on a working flowsdn node. #368 closed.

### nodeport_ingress stack — #369 (P1), 2026-10-09

Medium ef8e24151d on 7.2: "combined stack size of 3 calls is 768". Measured from the committed object
(BPF r10 offsets per function): nodeport_ingress 2 B -> ingress6 376 B -> snat_reply6 368 / new_flow6 264 /
snat_forward6 248 (ingress4 432 B, no BPF callee but memcpy). Fix: flatten the v6 chain. `ingress6` only
classifies (tuple, flow lookup) into a per-CPU `flowsdn_nodeport6_scratch` slot and returns a step; the
classifier calls the leaf (`snat_reply6`, `new_flow6`, `nodeport_forward6`), so the deepest chain is main + one function.

- [x] Code a59dbdd/f8c49c1, docs d2ec163, object + lock ded9b10. Frames now (verifier rounds to 16 with JIT, which
      reproduces 768 = 16+384+368): v6 worst 16+408 (snat_reply6) = 424, v4 16+432 = 448. sc-build at ded9b10:
      fmt, workspace + kubernetes Clippy -D warnings, 837 tests (0 failed, 1 ignored), test/build.sh (lock matches).
      musl build's pre-existing time_t warning filed as #373.
- [x] Medium on 7.2: pvetest2 67ee5a2bae errored (apiserver never ready), C2NR0Q2 62e589e10b errored (registry
      never listed the image); pvetest1 ef10df8ce1 at 238a767 (7.2.8-200.fc44): 20 pass incl. fixture-socket-lb-live
      (21 PASS: IPv4 + IPv6 NodePort local and SNAT via nodeport_ingress/egress test runs); the 2 failures are
      node-service-dns/-programmed (#368). #369 closed.
- [x] Golden golden-flowsdn-a690ebee2ba7 (flowsdn@4447eeb, release request stormcos#494); also carries #291 identity, #371 network-status, IPv6 NodePort.

### Multus network-status — #371 (P2), 2026-10-09

Owner (stormcos#249): multi-NIC is the Multus/NPWG standard as is. flowsdn writes the standard
`k8s.v1.cni.cncf.io/network-status` entry for its interface beside `flowsdn.io/pod-networks`.
Design: the entry (`name` flowsdn = conflist name, interface, ips, mac, `default` true: flowsdn
attaches only the primary) is derived from the pod-networks value, merged into the Pod's array
(other plugins' entries kept; flowsdn's replaced by name or interface), written with the Pod's
resourceVersion as precondition (a 409 retries next tick on the fresh view).

- [x] flowsdn-k8s keeps the network-status annotation on Pods; agent tagging entry + merge; patch both (b7a1ede).
- [x] Tests; docs (agent-api, runtime, deploy README, README, implementation-status, helm, k8s README); changelog (956bd1a).
- [x] sc-build at 45a5289: fmt --check, workspace + kubernetes Clippy -D warnings, workspace + kubernetes agent
      tests (837 results, 0 failed, 1 ignored). #371 closed. Live check (a Pod carrying both) comes with the next
      golden, which waits on #369 (nodeport_ingress stack, staging blocked).

### Uncompiled upstream WireGuard-tunnel cases — #266, 2026-10-07

Owner: report nothing upstream; close with flowsdn's handling (upstream_dead, ten decision vectors).

- [x] Spec 14 retargets the deferred packet-case ports to #293; changelog.
- [x] Verified by the full workspace sc-build at 481bacb (flowsdn-bpf-abi encryption tests); #266 closed.

### HTTPS-redirect matcher — #281, 2026-10-07

Owner: report nothing upstream, ever; close with the local fix (d95e957).

- [x] Fix on main (crates/flowsdn-gateway/src/matcher.rs, tests/https_redirect.rs); spec 21 §12 + defect record, changelog.
- [x] Verified by the full workspace sc-build at 481bacb (795 tests incl. tests/https_redirect.rs; gateway crate and lock unchanged since); #281 closed.

### No Cilium in what ships — #330 (P1), 2026-10-07

Owner: "no cilium in flowsdn period." Chart/manifests/CRDs already Cilium-free with a test (#294, #325).
What ships = golden (static agent + embedded BPF objects + CNI), GNU Kubernetes agent, release archives,
image, manifests, chart. Remaining shipped names: BPF map/pin names (`cilium_lxc`, `cilium_lb{4,6}_*`),
the persisted `CiliumEndpointUID` key. bpffs pins don't survive the reboot a stormcos release does, so
renamed maps need no legacy-pin migration. Library-only names (config catalogue, clustermesh prefixes,
identity labels, packaging, proxy probe) stay #339's.

- [x] BPF `flowsdn_lxc`, `flowsdn_lb{4,6}_{services,backends,reverse_sk}`; loader, fixtures, docs (5628875).
- [x] State key `EndpointUID`; health comment; embedded objects + lock rebuilt via sc-build (a6ec683).
- [x] `tools/check-no-cilium.sh` in test/build.sh, release build.sh, images/agent/build.sh; ADR-0020;
      docs/migration-from-cilium.md; changelog. sc-build at a6ec683: fmt, Clippy x2, 779 tests, chart,
      test/build.sh, both release archives, image: every check clean.
- [x] Golden golden-flowsdn-7c9c52699a50 (flowsdn@a4afafc, stormcos#310); `shipped`; library names stay #339.

### Pod and container tagging — #328 (P1), 2026-10-06

Owner: tag pods/containers OVN-style. The agent already persists pod ns/name/UID and the sandbox
(CNI_CONTAINERID) per endpoint; nothing is written back, and no flow producer exists (Hubble, #293).
No identity is allocated yet (#291), so `identity` is absent until it is. Pod names stay out of BPF
maps (endpoint ID -> metadata in the agent, as the reference does).

- [x] flowsdn-k8s Pod: ownerReferences, containerStatuses (name, ID), `flowsdn.io/*` annotations (56d09f0).
- [x] flowsdn-hubble `endpoint`: Workload, EndpointInfo (Hubble `Endpoint` JSON), `describe` (56d09f0).
- [x] Agent `tagging.rs` (pod-networks value, endpoint `pod`), View.annotation_patches, `flowsdn-annotate`
      thread, API publishes endpoints after every non-GET and at startup; RBAC pods patch (f1d9327).
- [x] Docs (agent-api, runtime, deploy README), changelog (c42f971). rustfmt via sc-build (#342),
      no-indexing test fix (#343) at 2038efa.
- [x] Verified by sc-build (2038efa onward; last full run 481bacb: fmt, Clippy x2, 795 tests incl. the
      tagging, k8s Pod, hubble endpoint and agent API tests). In golden-flowsdn-4b40a980ad16 (5e97790, stormcos#310).
- [x] Told #332, #293, stormconsole#83, stormcos#318 the fields. `shipped`; flows name pods once the
      observer (#293) uses flowsdn_hubble::endpoint; identity once #291 allocates.

### Console plugin support — #297 (P1), 2026-10-05

The plugin is stormconsole's (stormconsole#83). flowsdn's part: the console (host network) needs a
loopback port to default to; the API was Unix-socket only. Flows wait for Hubble (#296 §3, #293).

- [x] Agent `http-listen` (loopback only, refused otherwise): read-only TCP listener, GET routes and the statedb query; mutations 403 (no auth on TCP; they stay on the 0600 socket). Tests.
- [x] Edition manifests set `http-listen: 127.0.0.1:9878`; docs (agent-api, runtime, deploy README), changelog.
- [x] sc-build at b02c59f: the three listener tests pass with and without `kubernetes` (full suite 718 passed at b6bcf1d). In golden-flowsdn-eda35249a55e (stormcos#310). stormconsole#83 told port, routes and the /var/run/flowsdn socket move. `shipped`; flows wait for Hubble (#293).

### Advanced networking acceptance — #293 (P0), 2026-10-05

- [x] Assessed against code at f13b757 (comment 6007305400): IPAM modes/operator, encryption, egress gateway, BGP, Hubble, L7/Envoy, Gateway, ClusterMesh are primitives only; no agent wiring or operator executable.
- [x] Every acceptance row needs the live cluster (#291) and services/policy (#292); proposed after #292. Nothing checked.
- [ ] When #291/#292 pass: pick the subsystem order (likely Hubble first for the console, #297), implement each with live acceptance.

### CLI and Kubernetes integration — #298 (P1), 2026-10-06

`sc` is stormcos's CLI, so `sc net` is stormcos's to build. flowsdn provides the API, the CRD columns and the events.
Schemas and columns for the 22 CRDs shipped with #325.

- [x] Agent events (core/v1, `kubernetes` feature): Pod `EndpointCreated`/`EndpointCreateFailed`/`IPAllocationFailed`; Node `PodCIDRSelected`/`DirectRouteFailed`/`ServiceLBUnavailable`/`SysctlFailed`; aggregated, bounded, non-blocking. RBAC events create/update (manifests-kubernetes, chart).
- [x] Stable API: agent-api.md stability section, `api::ROUTES` pinned to the doc table; healthz member `agent` (no Cilium).
- [x] Printer columns for the 5 kinds the reference leaves bare; test every column path is in the schema.
- [x] sc-build at 4eb41c2 (fmt, workspace + kubernetes Clippy, 47 agent+kubernetes tests) and 5623bcb (720 workspace tests, chart check); stormcos#318 for `sc net`; first hardware run's failures filed as #341.
- [x] Golden golden-flowsdn-7728d7c136fb (release request stormcos#310); closed.

### Build failure on HEAD~1 — #317 (2026-10-06)

- [x] Cause: sc-build's checkout is depth 1 without fetch access (confirmed: `is-shallow-repository` true, 1 commit, deepen refused), so `git diff --check HEAD~1 HEAD` cannot run there. The LVM warning title is stormcentral#150/#162.
- [x] docs/build-and-test.md: history checks run in the session checkout before push; changelog. #340 is the same failure (my repro).

### flowsdn.io CRD set — #325 (P0), 2026-10-06

Owner: "for flowsdn, we need a complete set of kubernetes crds and related." Design per spec 13 §3.1:
vendor the 22 reference CRDs verbatim (pinned 7d68cfb394, Apache-2.0), project them to flowsdn.io
with `migration_registration_payload`, add flowsdn short names, generate the shipped manifests;
the YAML is the schema artifact, Rust types are checked against it. Per-group types/status
controllers, operator registration and the live run are split into sub-issues.

- [x] Vendored `crates/flowsdn-k8s/crds/{v2,v2alpha1}` + SHA256SUMS + LICENSE-CILIUM + NOTICE; `tools/vendor-crds.sh`.
- [x] `flowsdn_k8s::crd` generates `deploy/stormcos/manifests-kubernetes/crds/` (projection + `fs*` short names); test checks shipped == generated.
- [x] `flowsdn_k8s::schema` validator + CEL subset; 88 examples (minimal/realistic/reject × 22) pass.
- [x] RBAC (agent flowsdn-crds, operator 63-flowsdn-operator-rbac.yaml) with a test; docs/crds.md; spec 13 amendment; changelog.
- [x] sc-build at 2f6fab1: fmt, workspace + kubernetes Clippy -D warnings, 717 tests (0 failed, 1 ignored).
- [x] Follow-ups: #331 policy, #332 endpoint/identity/node, #333 pools/L2, #334 BGP, #335 Envoy/Gateway, #336 egress/LRP/plugin, #337 registration + gate, #338 live run; stormcos#303 applies crds/; #298 commented.

### Release hardening acceptance — #294 (P0), 2026-10-06

- [x] Assessed each acceptance row against code at 8e70ce2 (comment 6007288302): no Helm chart, no bpf-objects.lock, no arm64 runtime, no matrix run; gate needs #291–#293 accepted first.
- [x] Owner answer (2026-10-05): option 2 — also a standalone install (Helm chart + GitHub Release binaries/checksums), but none of it in the stormcos golden ("dead weight"). The cilium-* vs flowsdn-* object-name sub-question was not answered.
- [x] ADR-0019 + spec 22 amendment, ADR-0013 #237 note, build-and-test, README, changelog.
- [x] bpf-objects.lock (#245): `tools/bpf-objects-lock.sh write|check`; test/build.sh checks it; agent unit test checks embedded bytes. Lock values from sc-build at 561d6b1.
- [x] `deploy/release/build.sh` → flowsdn-<ver>-{amd64,arm64}.tar.gz + SHA256SUMS (static agent/CNI, lock, LICENSE, NOTICE). sc-build at 9bf69e8: fmt, agent Clippy -D warnings, agent tests (lock test ok), test/build.sh lock check, both archives static. Not published.
- [x] Chart object-name question posted on #294; `wait-owner` set (2026-10-06). Recommended flowsdn-* (ADR-0017).
- [x] Owner (2026-10-06): flowsdn-* names (master's recommendation: values migration note, `sc net` instead of cilium-cli) and "no Cilium in flowsdn, period": no cilium-* object names, labels, config keys or compatibility shims in the chart or manifests.
- [x] ADR-0019/spec 22/ADR-0013 #237/ADR-0017 amended; #339 tracks Cilium names left in code (BPF/pin names, catalogue).
- [x] CNI: /var/run/flowsdn socket/queue, FLOWSDN_SOCK, OVERWRITE_PLUGIN, `flowsdn-cni` (+ `flowsdn` link), conflist type flowsdn-cni; manifests follow (0040f60, b6bcf1d).
- [x] Shipped CRDs Cilium-free (crd::flowsdn_text); examples follow; test no_cilium_in_shipped_manifests over deploy/ and install/kubernetes.
- [x] Chart install/kubernetes/flowsdn + check.sh; images/agent; release packages chart; docs/helm.md (values, migration note).
- [x] sc-build at b6bcf1d: fmt, workspace + kubernetes Clippy, 718 tests (0 failed, 1 ignored), chart check, test/build.sh, release (archives + chart + SHA256SUMS); image built and ran at cd18738.
- [ ] Golden via `component stage flowsdn` (CNI + manifests change together); live chart install and upgrade/rollback need a cluster; M4 stays open on #291–#293.

### Presentation — #302 (P1), 2026-10-05

- [x] `docs/presentation.md`: Marp deck, 11 slides, every claim checked against code/docs (specs count, CNI CHECK, routes, config keys, milestones, golden). Linked from README and docs/README; changelog.
- [x] Comparison slides (owner follow-up): what ships, and scale/memory with Cilium's published figures. Render: 13 slides.
- [x] sc-build: marp-cli rendered HTML (11 slides); PDF needs a Chromium the build box lacks (#324 closed). #302 closed.

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
- [x] `perf-scale` ramp (steps of 100 pods until a step fails; owner request) at 5dc4de3: Clippy clean, tests pass, test/build.sh.
- [ ] 2026-11-06 later: 12.62 carried registry 9912c98, but it did not boot clean on pvetest1 and is tombstoned with 12.62-flowsdn. pvetest1 refuses runs (its last install, 12.62, failed: "runs no known release"); perf fad9ef6c97 on pvetest2 (12.61-flowsdn) stopped at the same `no ready golden` pull. No perf number yet. `cni-ready-after-boot`: answered, it is `boot_phase_network_ms` in the install records (stormcentral#365), so the suite keeps skipping it and the table takes it from there. #321 proposed --after-release flowsdn>=5167d1f (golden-flowsdn-de1d63ada483 at 1254993). Then perf on pvetest2 and pvetest1, table, perf-scale at night; the first run will likely need fixes.
- [ ] 2026-11-06: stormcos#271 is shipped; runs now stop at ImagePullBackOff (stormblock-registry#150, every component's run on the pair). Fixed in registry v0.55.1 (9912c98), not in a release yet. #321 proposed
      `--after-release registry>=9912c98`. Then perf on pvetest2 (flowsdn) and pvetest1 (Cilium), table here, perf-scale at night. Suite has never completed on a cluster; expect fixes on first run. `cni-ready-after-boot` still skips (stormcentral#365 closed: check whether its boot-progress records give the number).
- [ ] 2026-11-03: pvetest1 and pvetest2 refuse runs (stormcos#271: sbregistry takes no forge test images; shipped
      there, waits for a release). stormpump#102 and stormcentral#846 are fixed. Suite builds and tests pass at e161dd7
      (test/build.sh). Status 6613654069; #321 proposed after stormcos#271. Then perf on pvetest2 + pvetest1, table, perf-scale.
- [ ] 2026-10-07 05:10: queued `testhost install pvetest2 11.88-flowsdn` (5707cef6ce) behind stormbootx's 11.80 (pve 1 GB short, stormcentral#506); #321 proposed after #506. Then `stormcentral test run flowsdn perf --tag pvetest2`. stormcentral#383 closed: pair, any flavor with --any-flavor. Earlier 04:30: pvetest2 VM removed again (stormbootx install 11.80 queued); a075717758, c1b47e866d, bc56944e01 lost. Evidence on stormcentral#383; #321 proposed after it. Requeue perf/short/medium on pvetest2 when it runs 11.88-flowsdn. Earlier: perf on pvetest1 (cilium) now d22c56d8da (47a8caf4ba errored: node never settled, stormcentral#413/stormblock#278); pvetest2's e7c0bf65d8 errored (VM removed) — requeue `stormcentral test run flowsdn perf --tag pvetest2` after install 5b46948417. Compare, post the table on #321, then perf-scale at night on each. Waiting on the build backlog; #321 proposed after stormcentral#472.
- [ ] Runs on both flavors (perf by day, perf-scale at night on a pve VM): 8c822b3547 (C2NR0Q2) 507 on push (stormcentral#376); f0107a4784/f68f31432b no pvetest VMs until install. Proposed after stormcentral#376.

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
- [x] 2026-10-06: live ClusterIP checks in the test suite's node probe (node-service-dns/-kubernetes/-programmed, test/src/services.rs); sc-build at 1375983 (Clippy, 6 tests).
- [x] 2026-10-07: ClientIP session affinity in the socket LB (58f072d, f67de31): affinity maps, affinity-match planning (removed before its backend), master flag+timeout; socket-lb-live affinity check (runs with medium). sc-build at f67de31: 785 tests, Clippy x2, test/build.sh.
- [x] 2026-10-07 (f44242b, 15dfb37; sc-build at f44242b: Clippy -D warnings, flowsdn-policy tests incl. 6 importer tests): Kubernetes NetworkPolicy importer `flowsdn_policy::k8s` (spec 06 §3.3 with flowsdn label keys, ADR-0020): full LabelSelector, ipBlock CIDR peers with except, ports (named, endPort), policyTypes default-deny markers that allow nothing, derived-from labels; unit tests incl. deny-all/no-ingress guards. Next after it: identities for pods, then selector resolution -> map state -> BPF policy map.
- [x] 2026-10-07 (345e9f7 + fix; sc-build: Clippy, 8 k8s tests incl. end-to-end decisions and compiled-map agreement): lower `k8s` entries to the simulator (`Selector::Kubernetes`), ipBlock peers reported unsupported until CIDR identities; end-to-end tests NetworkPolicy -> evaluate vs compile agreement (#103 obligation for this frontend).
- [ ] 2026-10-07: NodePort/LB/externalIP from outside the cluster (IPv4 first), local backends only (no SNAT yet):
  - [x] flowsdn-lb: `Service.scope`; scope 1 = this node's backends, for traffic arriving on the uplink (scope 0 stays the socket LB's).
  - [x] agent: scope-1 copies of NodePort/ExternalIPs/LoadBalancer frontends with local backends.
  - [x] BPF socket-lb: `nodeport_ingress` (uplink tcx ingress: scope-1 lookup, DNAT, csums, LRU CT `flowsdn_nodeport4_ct`) and `nodeport_egress` (reply src rewrite).
  - [x] loader + agent: attach to the uplink (the device of the route to the other nodes / default route), `kubernetes.node-port` (default on).
  - [x] 2026-10-07 late: builds back (build VMs). HEAD failed the catalogue provenance test after doc edits (#355, fixed b222bbc); the test image failed on build VMs (nightly without rust-src, fixed d926c61). Medium 562800fc6d at d926c61 on pvetest2 (7.2.8-200.fc44): 20 pass incl. fixture-socket-lb-live with the NodePort uplink programs; the 2 failures are node-service-dns/-programmed, the node's pre-rename flowsdn (/var/run/cilium socket, pre-cda5799 ALLOW_MULTI).
  - [x] sc-build at d926c61: 743 tests (0 failed, 1 ignored); fmt, workspace + kubernetes Clippy -D warnings. Golden golden-flowsdn-4a0daa7c4bfc (flowsdn@f445c3d, stormcos#310) carries the external NodePort programs.
  - [ ] Short on pvetest2 once a release carries 4a0daa7c4bfc (node-service-* = kube-dns/kubernetes acceptance, stormcos#265).
  - [x] (done: medium 562800fc6d passed, golden 4a0daa7c4bfc) (sc-build at 481bacb: 795 tests, Clippy x2, test/build.sh) Hardware check of the NodePort programs: medium 9171dc0361 errored (dev.g8.lo shut down for good, owner 2026-10-07: builds move to build VMs, stormcentral#107; no sc-build or test-image build until then); 3348be6265 queued on pvetest1 (master installing 11.91 there). Then stage the golden. fixture `socket-lb-live`: test_run DNAT and reverse with checksum checks; docs; changelog; embedded object + lock via sc-build; medium on pvetest2.
  - [x] 2026-10-08: SNAT to other nodes' backends (IPv4, externalTrafficPolicy Cluster): scope-1 frontends carry
        every backend unless eTP Local; `nodeport_ingress` decides local vs remote by FIB (output device = arrival
        uplink -> remote), SNATs to the FIB source address (BPF_FIB_LOOKUP_SRC, 6.7+) on a port 61000-65535,
        TTL-1, redirects (fib MACs, or redirect_neigh); the reply is reverse-NATed at uplink ingress and redirected
        to the client. Map `flowsdn_nodeport4_nat` (16-byte values) replaces `flowsdn_nodeport4`. socket-lb-live
        test-runs it with ctx ifindex = a dummy uplink. Done: a793819 (code), 3db1750 (docs), 92fe61b (fmt),
        85cab87 (object + lock). sc-build at 85cab87: fmt, workspace + kubernetes Clippy -D warnings, 795 tests
        (0 failed, 1 ignored), test/build.sh (lock, no-cilium). Medium 5c35ef74e4 on pvetest2: 20 pass incl.
        fixture-socket-lb-live with SNAT (node-service-dns/-programmed = old node flowsdn). Golden
        golden-flowsdn-cc0835c8a1db (flowsdn@347581a, stormcos#310). Two-node live check waits for #291's pair.
        sc-build can't hand files back from build VMs: the object came back as base64 in the build log.
- [ ] 2026-10-08: IPv6 NodePort/LB/externalIP from outside the cluster (the agent already writes IPv6 scope-1
        frontends): `nodeport6_in/out` in socket-lb mirroring IPv4 (no IP checksum; L4 pseudo-header csum,
        hop limit, FIB v6 with BPF_FIB_LOOKUP_SRC, SNAT ports 61000-65535), map `flowsdn_nodeport6_nat`;
        loader map table; socket-lb-live v6 local + SNAT steps; docs, changelog; object + lock via sc-build.
  - [x] Code 7b788ee, docs af375ea. 512-byte stack: per-family paths are BPF subprograms (286da84), the v6 FIB
        params live in per-CPU `flowsdn_nodeport6_fib`, v6 path split (68a8ddc), ip6_words/bytes by transmute
        (byte destructuring spilled, 0fad164). Object + lock 53bffc7. sc-build at 53bffc7: fmt, Clippy x2
        -D warnings, 743 tests (0 failed, 1 ignored), test/build.sh (lock, no-cilium).
  - [ ] Medium on pvetest2 (socket-lb-live IPv6 steps under the 7.2 verifier): 87e7e01b34 and 22950509a8 errored,
        test-image build still goes to retired dev.g8.lo (stormcentral#526, commented). Rerun
        `stormcentral test run flowsdn medium --tag pvetest2` when #526 is fixed; then stage the golden.
- [ ] ClusterIP acceptance on pvetest2: ad78ba9a43 errored (pvetest2's VM gone; master's 11.88-flowsdn install 5b46948417 queued). Requeued after reinstall as fc93b9bdde (short; errored 60 min waiting for a build slot, filed stormcentral#504) then c1b47e866d at 8d2f677; perf a075717758. Golden golden-flowsdn-17ccc00a7b9f carries affinity. Golden golden-flowsdn-6e707dca7687 carries the frontend kinds behind the build-slot backlog (stormcentral#472); #292 proposed after it. `stormcentral test show 6c0b6820bd`: the node-service-* lines are the kube-dns/kubernetes acceptance; fix what fails, then comment stormcos#265.
- [x] 2026-10-07 (b381f6e, cd99e1c; sc-build 782 tests, Clippy x2): Service types for in-cluster clients through the socket LB: externalIPs, LoadBalancer ingress IPs, NodePort on every node InternalIP; internalTrafficPolicy Local for ClusterIPs (backends on this node); `flags.type` per frontend; frontends refresh on Node changes. External clients need tc NodePort (still open).
- [ ] fixture-socket-lb-live on a kernel: run dbfc4e45b1 (C2NR0Q2) failed on push, registry full (stormcentral#376). Rerun `stormcentral test run flowsdn medium --tag <machine>`; live kube-dns check on a flowsdn node after release. Not implemented (stays open on #292): NodePort/LB/externalIPs, affinity, Maglev, DSR, NAT46/64, tc-level LB, socket termination, policy.

### stormcos needs: operator and relay — #296 (P1), 2026-10-09 (closed 2026-10-13)

§1 manifests, §4 API, §5 --help/--version/healthz done (validated 2026-10-09). Remaining §2 operator, §3 relay.

- [x] Found: remote routes come only from Node `spec.podCIDRs`; stormcos sets none, so two flowsdn nodes
      install no routes to each other (derived pools are local). Docs: runtime.md, deploy README.
- [x] §3 answered on #296: no observer/relay; console shows flows unavailable; observer is #293.
- [x] Owner decision posted on #296 (`wait-owner`): pod CIDRs/operator duties — A controller-manager node
      IPAM, B flowsdn-operator (#337), C agent derives every node's CIDR with collision refusal.
- [x] Decided 2026-10-13 (master, owner "yes, decide them"): C now, A (rustkube node IPAM) later, B only if A can't.
- [x] Agent (e9738f0, fmt 2a27b04): `node_cidrs` = spec.podCIDRs, else the derived rule for families whose local pool is `auto`;
      `desired_routes` -> RoutePlan {routes, collisions}; overlapping CIDRs get no route; `pod-cidrs` health
      error + `PodCIDRCollision` Event. Tests (pvetest1/2 pair, collisions, overlap).
- [x] Docs (runtime, deploy README, implementation-status, spec 07 note), changelog (71add3c). sc-build at 2a27b04:
      fmt --check, workspace + kubernetes Clippy -D warnings, 865 tests (0 failed, 1 ignored) incl. the 4 route tests.
      #296 closed (§2 C, §3 answered; operator #337, two-node live check #291/day-2). Golden waits on stormcentral#827.

### Cluster identity allocation — #291 (P0), 2026-10-09

Two-node acceptance waits: owner (stormcentral#360, 2026-10-08) made multi-node day-2, P2; test runs also
wait on stormcentral#526. Implementable now: spec 03 §3.3 CRD-mode allocator over `flowsdn.io/v1alpha1`
FlowsdnIdentity (RBAC create/update already shipped; CRDs applied by stormcos#303). Overlaps #332's
identity line; GC stays the operator's (#332).

- [x] flowsdn-k8s: Namespace and FlowsdnIdentity scopes; Pod `serviceAccountName` (519e7b3).
- [x] flowsdn-identity filter defaults with flowsdn keys (`io.flowsdn.k8s.*`, ADR-0020/#339).
- [x] Agent `identity.rs`: pod labels (spec 03 §3.1), canonical key, reconcile (oldest object, create on a
      free id 256..65535, 409 retry, heartbeat removal, recreate when deleted while held); tests.
- [x] Controller identities thread; `/v1/ip` identity, endpoint `status.identity` + `pod.identity`,
      `GET /v1/identity`; `kubernetes.identity-allocation`, `kubernetes.cluster-name`.
- [x] Docs (agent-api, runtime, implementation-status, milestones, deploy README, spec 03 note), changelog (6f9cccb).
- [x] sc-build at 598a77d: fmt, Clippy x2 -D warnings, 833 tests (0 failed, 1 ignored) incl. loopback-API
      identity create; chart check, test/build.sh, agent image (no-cilium clean). Fixes #361–#366 closed.
      Build env adds -D clippy::indexing-slicing and arithmetic-side-effects; format via
      `sc-build 'cargo fmt --all && git diff'` and `git apply` (no local cargo). Status on #291.
- [x] Golden golden-flowsdn-a690ebee2ba7 (stormcos#494) after the #369 fix. Was: Medium c61945e336 found socket-lb unloadable on 7.2 since 0fad164 (user_ip6
      copy through ctx+8): fixed a97f870/27e10fe (object + lock). Medium ef8e24151d: cgroup programs load;
      `nodeport_ingress` "combined stack size of 3 calls is 768" (IPv4 NodePort too). Do not stage main
      until that passes medium on pvetest2 (comment on #292). Test runs work again despite stormcentral#526.

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
- [x] 2026-11-03: stormcentral#384 closed, but no schedule is set (`schedule list` empty); asked the master. Watch at
      a6c6c1a: missing everywhere. aya 0.16.0 resolves .ksyms; bpf-linker 0.13.0 (#317) keeps a declaration in .ksyms
      only with section + debug info rustc doesn't emit. An LLVM IR shim (as bpf-linker's test does) is the only way
      today; not tried (auto-mode denied the ad-hoc run of an unpinned linker) and it is not Rust (project rule).
      Filed stormcentral#1163 (schedule never set); #315 proposed after it. Tool fmt + Clippy at 4f22330.
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

### Docs refresh from code — 2026-10-09 (since 2026-10-02)

- [x] README, docs/, deploy READMEs, crate READMEs, release archive README and CLAUDE.md checked against code through eed1aca; 4a1b564. Closed #353, #354. Filed #359 (P2: startup checks kernel-requirements promises are absent). Docs only; no build, version or golden change.

### Comment mining — 2026-10-10 (since 2026-10-09)

- [x] Read the 23 comments (and new issue bodies) on the 49 issues updated since 2026-10-09. Filed stormblock#388 (P1: ext4 `bit already cleared` on ublkb0 after a keep-data reinstall, from #374). Closed #372 (fixed f8c49c1). Added: stormcentral#512 (C2NR0Q2 62e589e10b), stormcentral#500 (pvetest2 67ee5a2bae), #374 (link to stormblock#388). #296's §2 decision is already needs-owner. No fixes.

### Comment mining — 2026-10-09 (since 2026-10-08)

- [x] Read the 30 comments on the 44 issues updated since 2026-10-08. Filed #368 (P1: node-service probe takes KUBERNETES_SERVICE_HOST as the ClusterIP; pvetest2 runs current flowsdn and kube-dns is programmed), #369 (P1: nodeport_ingress stack 768 > 512, blocks staging), #370 (P2: no verifier load before stage). Added: stormcentral#150 (three more wrong titles), stormcentral#526 (runs complete again), stormcos#303 (identity allocation needs crds/), #296 (rustkube has no node IPAM). #296's §2 decision is already needs-owner. No fixes.

### Comment mining — 2026-10-08 (since 2026-10-07)

- [x] Read the comments on the 30 issues updated since 2026-10-07. Filed #357 (P2: long run db2ce13b29 errored, #303 closed waiting for it) and #358 (P3: catalogue provenance by line number, #355). Closed #356 (fixed at 53bffc7). Added: #354 (golden cc0835c8a1db), #292 and #321 (stormcos#310/#309 shipped in 11.95), stormcentral#512 (pvetest2 seal failure), stormcentral#543 (BPF object via base64 log). No fixes.

### Comment mining — 2026-10-07 (since 2026-10-06)

- [x] Read 66 comments on the 46 issues updated since 2026-10-06. Filed #354 (P3: docs name golden a7ee3f63195b as latest; pre-4b40a980ad16 goldens' socket LB can't attach on 7.2). Closed #352 (owner answered on #266/#281) and #349 (fixed in ab652c4). Added: #338 (stormcentral#376 closed; waits on stormcos#303), #292 (stormcentral#107/#517 closed, builds may work), #321 (stormpump#102 fixed in golden-stormpump-236d2ed1dadd, stormcos#309). No fixes.

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
- [x] fixture-skb-ctx-matrix passed on 7.2.8-200.fc44 (a0cd56f37c); table in spec 18 §9.1; #256 closed.
  2026-10-07: first hardware run failed (6ac1a6d42c, detail lost; summary line added b862b4a). 05:10 UTC: medium 580fc985ad queued on pvetest1; server3 (blade, 11.88 passed) refuses runs in its power-off window — queue `stormcentral test run flowsdn medium --tag server3` after 11:00 UTC. Medium 4cd55c046c at c66d495 queued on pvetest1 (also serves #303/#341); proposed after stormcentral#472.
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
- [x] 2026-10-06: medium run 6ac1a6d42c at 53a346a on C2NR0Q2 (stormcos 11.88): short + 8 fixtures pass, node probes skip (cilium flavor); 4 fail (#341).
- [x] #341 fixes at b862b4a: socket fixtures mount a private cgroup2; endpoint test names the refused packet case; skb-ctx-matrix one-line summary. sc-build at 9a7f46b: fmt, workspace + kubernetes Clippy, 777 tests (0 failed, 1 ignored), chart check, test/build.sh.
- [ ] 2026-10-07 10:40: medium a6d91042ac on pvetest2 (11.88-flowsdn): 15 pass / 4 fail. Fixed: socket-LB links created with ALLOW_MULTI (EINVAL; real agent bug, #292), endpoint short-frame refusal on 7.2, three-line failure summary, probe socket at /var/run/flowsdn (node-agent failed, so the ClusterIP checks never ran). sc-build at 8285d21/0c9e1d0. Requeued medium+short at 0c9e1d0; skb-ctx-matrix cause still unknown (summary now shows it). Earlier 09:30: after the DNS outage both pve VMs were gone (580fc985ad, d22c56d8da errored no VM). Reinstalling pvetest2 11.88-flowsdn; then queue medium (#303/#256/#341), short (#292) and perf (#321) on it. Earlier: medium bc56944e01 on pvetest2 (4cd55c046c errored: pvetest1 never settled, stormblock#278). Was: 4cd55c046c on pvetest1 (cd1396f7e0 on C2NR0Q2 errored: apiserver down, machine fenced). Was: medium run cd1396f7e0 at 9a7f46b on C2NR0Q2 queued (2026-10-06 21:10 UTC; 39 runs queued there, build-box stalls). #303 proposed after stormcentral#472; status on #303/#341. When it finishes: `stormcentral test show cd1396f7e0` (rerun if it was dropped). Then fix the kernel findings (endpoint test-run EINVAL case, skb-ctx fields), close #341 and #303.
- [x] Short and medium on hardware: pvetest2 11.88-flowsdn, medium a0cd56f37c (20 pass; every fixture incl. skb-ctx matrix and socket-lb-live; only node-service-dns/-programmed fail = the node's pre-fix flowsdn, #292), short dc492b2815. #341 and #256 closed. Long queued db2ce13b29. #303 closed. pvetest1 push failed 507 (registry full, stormcentral#376); pvetest2 (flowsdn flavor; its 11.79 install failed) also 507s, run 39d1523f0c; C2NR0Q2 is off overnight. Proposed after stormcentral#376. Rerun `stormcentral test run flowsdn short|medium --tag <machine>` when a registry has space.

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
now cover 32 crates plus Rust tools, while live integration remains unfinished.
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
