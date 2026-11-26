# Work plan — moved out of CLAUDE.md

Kept here whole, newest notes as they were. Write new intentions here.

## Work plan

### Node model in spec 10's tables — #576 (P3), 2026-11-26

Staged; each stage committed and verified (kernel tests keep passing).
- [x] Stage 1 (2a80d18, strict sc-build passed): `flowsdn-node` crate: rows (`devices`, `routes`, `neighbors`, `node-addresses`, `desired-routes`,
      `forwardable-ips`, `desired-neighbors`) with Keyed/TableRender (harvested columns), `node-addresses` derivation
      (§3.1.6), `RouteManager` (owners, AD selection), `RouteTarget` over `RouteOps` (flowsdn-reconcile). Unit tests.
- [x] Stage 2 (e3f7fb2: xtask check, test/build.sh, kernel-check 26/0/2): direct node routes (`route_loop`) become an owner of
      `desired-routes`, reconciled through `RouteTarget` (connector ops); the persisted routes file stays as the owned set prune reads.
- [x] Stage 3 (a9f6a26): uplink table routes are the `uplinks` owner; rules are `desired-rules` (`flowsdn_node::rules`).
- [x] Stage 4 (aff3a36): `neighbors.rs` (#469) through `forwardable-ips` → `desired-neighbors` (`flowsdn_node::neighbors`).
- [x] Docs (spec 10 amendment, runtime, changelog) at 4caf950; sc-build: xtask check, test/build.sh, kernel-check 26/0/2
      (uplinks-live, neighbors-live pass). Staged golden-flowsdn-0e22d7d5c9e0; shipped. Then #520 (scripttest node adapters).

### The flowsdn golden builds here — #598 (P1, stormcentral#1836), 2026-11-26
- [x] `deploy/build-image.sh flowsdn OUT` (entered as `deploy/build-golden.sh`, the `tree` contract): stormcos
      `build-goldens.sh`'s flowsdn stage (8932-9070 at f7f7ccb) moved unchanged; `deploy/check-image.sh` carries
      `stage-build.sh`'s flowsdn checks; `deploy/test/compare-stage.sh` builds both ways and diffs the trees.
- [x] Verified on a build VM (e1af60e, `compare-stage.sh f7f7ccb`): check-image PASS, the stage's checks PASS, the
      trees byte-identical (81 paths).
- [x] Hand-off on stormcentral#1836 (step 3: flip `kind=tree`); stormcos#1669 lists what to delete after the flip.

### Direct-route findings after the #576 move — #498 (P1, reopened), 2026-11-26
- [x] Both findings hold in the #576 code: `direct_routes::plan` checks each selected hop and the first InternalIP only
      for the plain route (4bc7cb209712); `ConnectorOps::delete` deletes flowsdn's route by destination (8299a1f6238f).
- [x] Regression from #576 fixed (ed881c2): a desired route whose check failed or was skipped lost its installed route
      (no row → delete/prune). `Holding` keeps it, as before #576. Test `stale_routes_go_and_held_ones_stay`.
- [x] 9845e1e: xtask check, test/build.sh, kernel-check 26/0/2. Staged golden-flowsdn-dfcab0ddb2c6; re-shipped (`--commit ed881c2`).

### IPv6 egress gateway — #580 (P3), 2026-11-26

- [x] `flowsdn_egress_gw_policy_v6` + `flowsdn_egress_gw_nexthop6` (the gateway's IPv6 InternalIP as next hop: native
      routing deviation), source redirect, gateway SNAT on the IPv6 masquerade path (preset NAT address in the slot);
      loader; planner (`Maps`), controller; scripttest dump reads `maps.v4`; docs.
- [x] Object + lock rebuilt; kernel-check 26/0/2 (`PASS IPv6 egress gateway`); strict sc-build at 95200cb; staged
      golden-flowsdn-cf08afe18670; closed. #595 was this work's own intermediate failure.

### Datapath plugins — #566 (P3), 2026-11-26

- [x] Asked (no plugins vs flowsdn's own vs Cilium-compatible); `wait-owner` refused: gaps are session work. Built the
      recommended option: no datapath plugins (spec 01 decision); the operator posts a `NotApplied` Warning Event per
      FlowsdnDatapathPlugin per term; `events` create in its RBAC. 14f79f1, fmt 467e580; strict sc-build passed; staged
      golden-flowsdn-f0ed2dfbe418; closed (no plugin objects on any node to show it on).

### Metrics: the operator half — #420, 2026-11-26

- [x] Agent proof line to `/dev/kmsg` (c10c88b, under #489).
- [x] Operator `GET /metrics` on `--metrics-listen` (127.0.0.1:9967 in the edition; not cilium's mTLS :9963), its own
      thread, `flowsdn_operator_*` (leader, CRDs, identity/node GC, BGP). b86e270, fmt 05a112f; strict sc-build passed.
- [x] Filed stormcos#1650 (ironprom job + check row). Staged golden-flowsdn-6f6aa3364852; re-shipped `--commit 05a112f`.

### Host firewall short-circuit finding — #484 / #487 (P0, reopened), 2026-11-26

- [x] Fix verified 2026-11-20 (kernel suite, negative control). Reopened only because the node proof
      `log:health agent.(api|kubernetes) OK` cannot be seen: agent pod stderr never reaches syslog (see #418 below).
- [x] Asked on #484 how agent health becomes visible on a node. `stormcentral wait-owner` refused: findings are
      session work, never the owner's ("fix it"). So the recommended option was built: the agent mirrors health
      transitions to `/dev/kmsg` (stormpump's log service follows it into syslog); both edition DaemonSets mount it.
- [x] Strict sc-build at 936dedb (xtask check + test/build.sh) passed; staged golden-flowsdn-896f02036e02
      (stormcos#1502). #484, #487 and #418 re-shipped with the same proof and `--commit 936dedb`; they close when a
      pvetest install of a release carrying it shows the line. Also fixed #593 (agent tokio dev-dep lacked test-util).
- [x] 2026-11-26: 14.07-flowsdn (936dedb) on pvetest1 still failed: stormpump tags every /dev/kmsg record `kernel`
      and its collector (what stormcentral stores) drops kernel lines below warning, so the info-level agent lines
      never arrive. Filed stormpump#329 (forward records with a non-kernel facility, tagged by their prefix). Did not
      raise the lines to warning. #484 and #487 parked after stormpump#329. The other issues shipped on this proof will
      fail the same way until it lands; park each likewise when it comes back.
- [x] #488 came back (14.07): parked after stormpump#329.
- [x] stormpump#329 fixed at 65b74d3 (shipped, not yet released). #484, #487, #488 parked `--after-release
      stormpump>=65b74d3`; re-ship each with its proof when handed back. Park the other health-proof issues the same way.
- [x] #489 (its own quarantine-line proof) parked the same way.
- [x] 2026-11-26: #484 handed back. Release 14.08-flowsdn (composed, not yet installed) carries golden-flowsdn-cf08afe18670
      and stormpump@d3d2858 (contains 65b74d3). Re-shipped with the same proof and `--commit 936dedb`; it closes on
      14.08-flowsdn's first passing install. #487, #488, #489 (its own proof, `--commit c10c88b`) #490, #496, #497 and #499 re-shipped the same way. Re-ship the other parked issues the same
      way when they come back.
- [x] 2026-11-26: parked all 27 remaining issues reopened on the health proof (#392, #418, #448-#499 range, #513) the
      same way in one pass (`--after-release stormpump>=65b74d3`; `--after stormpump#329` is refused once it shipped).
- [x] #488 (socket-lb findings, fixed 2026-11-20 at ff03ffd) reopened on the same proof: re-shipped the same way
      (`--commit 936dedb`). The other issues reopened on that proof go back the same way when each is handed out.
- [x] #489 (quarantine, fixed 2026-11-20) and #420 have their own `log:` proofs (startup lines). c10c88b sends both
      lines to `/dev/kmsg` as well; strict sc-build passed; staged golden-flowsdn-4f5bfc1d2c2f. #489 re-shipped with
      `--commit c10c88b`; #420 goes back the same way when it is handed out.
- [x] #490 (policy findings, fixed 2026-11-20 at 6a8b207) re-shipped on the health proof, `--commit 936dedb`.
- [x] #496 (host-policy finding, fixed 2026-11-21 at 50dcc66) re-shipped the same way.
- [x] #497 (uplink monitor findings, fixed 2026-11-21 at fdee984) re-shipped the same way.
- [x] #498 (direct-route findings, fixed 2026-11-21 at 000ffb2) re-shipped the same way.
- [x] #499 (ECMP pairing finding, fixed 2026-11-21 at 4a12712) re-shipped the same way.

### No stubs: proof on a node — #418 (reopened), 2026-11-26

Reopened by stormcentral: 14.06-flowsdn on pvetest1 (install pvetest1-1795671725) did not show `health agent.(api|kubernetes) OK`.
- [x] Cause 1: the agent is a DaemonSet pod and pod stderr is not forwarded to syslog (only stormpump host processes are), so a `log:` proof cannot see agent lines on any node.
- [x] Cause 2: stormfw (host process) probes `/v1/healthz` with HTTP/1.0 and got 505 on every boot ("boot program stays why=flowsdn /v1/healthz answers 505"). Fixed at 27d30cf (HTTP/1.0 served; responses close). Its strict sc-build was still running when the P0 #484 preempted this.
- [x] Repo-wide stub-wording grep empty (CHANGELOG/work-plan quotes reworded; clustermesh README said "not implemented", now says not built / runs in #567).
- [x] 27d30cf passed the strict build. The proof route is settled under #484 (the agent writes `/dev/kmsg`); re-shipped with it.

### MCS-API CoreDNS configuration — #569, 2026-11-25

- [x] Asked on #569: the issue conflicts with spec 20 §12 decision 11 (#279), which stages MCS incl.
      `clusterset.local` DNS after the legacy mesh import (#568); no ServiceExport/ServiceImport controller existed or
      was filed. Master decided (2026-11-25): keep the order. Filed #592 (MCS controllers), proposed after #568; #569
      parked after #568 and #592. Nothing built.

### ClusterMesh apiserver sync — #567, 2026-11-25

- [x] Owner decision (master, in chat 2026-11-25): option 1, flowsdn's own etcd v3 client (hand-written prost
      messages, h2, Fedora OpenSSL per ADR-0016, no rustls); kvstore trait, memory backend and SyncStore built here;
      tests on the memory backend and fastetcd (SC_TOOLS); Cilium certificate names renamed to flowsdn's.
- [x] `flowsdn-kvstore`: trait (+ `txn`, `lease_for` for §12 decision 9), memory backend, SyncStore, etcd backend
      (gRPC over h2, TLS, limiter, leases, paginated list, watch/relist, client-side lock, status checker).
- [x] `flowsdn-clustermesh`: `flowsdn/` prefixes and grants (#339 part); export converters (§4.2-4.6), IP owner
      arbitration, global namespaces.
- [x] `flowsdn-agent clustermesh-apiserver` (a mode, as the operator is): watches (FlowsdnNode, FlowsdnIdentity,
      FlowsdnEndpoint, Service, EndpointSlice, Namespace), four SyncStores with canaries, cluster config claim and
      enforcement, heartbeat, `/readyz`.
- [x] Tests: memory backend everywhere; fastetcd (plain and mTLS) via `SC_TOOLS=fastetcd`.
- [x] Docs (spec 20 amendment incl. certificate names, runtime, status, changelog).
- [x] Strict sc-build at 4bc9748 with `SC_TOOLS=fastetcd`: `cargo xtask check` and test/build.sh, exit 0
      (fastetcd tests ran: 6 backend tests incl. mTLS, the apiserver sync test). cargo-deny is not on the build VMs;
      new crates (h2, prost, tokio-openssl, anyhow, itertools) checked by hand against deny.toml.
- Not built (spec 20 #567 amendment): endpoint-slice export, prefix front, kvstoremesh, metrics, dialer aliases,
  h2 keepalive pings, remote-client status mode, local-lock GC, image/manifests. Importing remote clusters is #568.
- [x] Staged after verification: stormcentral reported "nothing new to record: golden-flowsdn-29b49b86b5e8 already
      holds this content" (its build 12c83da038d5), so the clustermesh-apiserver mode is in that golden.

### flowsdn.io BGP kinds — #334, 2026-11-25

Types, the operator's node config generation and conditions, and the agent's status projection. The agent's
reconcilers/speaker are #570/#571; they feed the projection built here.
- [x] Rust types of the five FlowsdnBGP* kinds with T-CRD-3/4/5/7 (`tests/kinds.rs`), peer config defaults, the
      advertisement CEL rules in the controller.
- [x] Operator: compile cluster configs into FlowsdnBGPNodeConfig (spec 15 §3.2: selection, override merge,
      first-owner-wins, update only on change, stale delete, `ip-pool` router IDs) and the cluster/peer conditions.
- [x] Agent: FlowsdnBGPNodeConfig status from peer state (§3.8: omission, established time, 5-error cap, 32 KiB
      condition, flush cadence and backoff) for #570 to drive.
- [x] Docs (crds.md, runtime, spec 13/15 amendments, status), changelog.
- [x] Strict sc-build at 501137a: `cargo xtask check` (fmt --check, workspace clippy -D warnings, workspace tests
      with all features, musl checks) and test/build.sh, exit 0. Self-inflicted build issues #587-#590 closed. #334 closed.
- [x] Staged from main at 5e4c2c2: golden-flowsdn-a96bddd213fa, release request stormcos#1502.
- Not run on a cluster: the operator BGP pass is unit-tested against recorded API calls only; status writing waits
  for the agent control plane (#570) and speaker (#571).

### Boot-time comparison against the cilium flavor — #586, 2026-11-25

- [x] Stage comparison from stormcentral's install records and metric samples (12.86 → 14.03, each flavor's paired gate installs). flowsdn reaches node Ready, all pods and reboot node Ready sooner in every pair. 14.03: 29.2 / 42.5 / 16.0 s against cilium's 43.7 / 71.0 / 20.1 s. The network phase is 12–18 s against 25–39 s, and the first CNI ADD after a reboot is 0.5–0.8 s against 3.4–4.6 s.
- [x] The one slower flowsdn run (12.97, same-time pair) lost its time before the network (initramfs, handover, console lag: shared host). Its network phase was 18.2 s against 39.1 s.
- [x] The slowdown since 12.96 is in phases both flavors share (bootloader/kernel/initramfs, kubelet start → apiserver), not in the agent, BPF load or CNI. Caveat: since 13.00 the cilium flavor runs on a machine that lays 4 drives with parity.
- [ ] Waiting on the owner (posted on #586): close #586 as not a flowsdn regression, or name the numbers it was read from. Optionally file the shared boot-phase slowdown on stormcos.

### DNS proxy, toFQDNs, DNS rules — #536 (P3), 2026-11-25

- [x] Datapath: UDP redirect, proxy-egress mark read as the source identity; `flowsdn-l7::dns` (messages, patterns, cache, proxy); agent (rules, compiler, settings, policy thread hold, netlink routing); `dns-live`; docs.
- [x] local-delivery object + lock rebuilt; kernel-check on 7.3.4-200.fc44: 26 pass, 0 fail, 2 skip; `dns-live` 6/6 PASS, `proxy-live` PASS.
- [x] Strict sc-build at c1c8105: fmt --check, `cargo xtask check`, test/build.sh, kernel-check 26 pass 0 fail 2 skip (`dns-live` 6/6). Staged; closed.
- Not built (documented): per-endpoint caches, restore, transparent upstream mode, zombies, L7 flows into Hubble.

### L7 proxy core — #577 (P3), 2026-11-25

- [x] local-delivery egress redirect (mark, sk_assign, proxy port in the flow entry), `flowsdn-l7` (listener, ports, route, record), `proxy-live`, docs.
- [x] local-delivery object + lock rebuilt; kernel-check on 7.3.4-200.fc44: 25 pass, 0 fail, 2 skip, `proxy-live` PASS (original destination, source, identity, data both ways, fail closed).
- [x] Strict sc-build at f56ea87: fmt --check, `cargo xtask check`, test/build.sh, kernel-check 25 pass 0 fail 2 skip (`proxy-live` PASS). Staged.
- Not in this step: ingress-direction and Service (`l7_lb_proxy_port`) redirects and the upstream leg: #582 (proposed); #578 waits on it.

### Egress gateway — #564 (P3), 2026-11-25

- [x] ABI (`egress.rs`), socket-lb (redirect to the gateway, gateway SNAT on the masquerade path), loader map, agent planning (`egress_gateway.rs`) in the services thread every 1 s, watch, settings, `GET /v1/egress-gateway`, docs.
- [x] Object + lock rebuilt from 8db53fc (socket-lb sha256 e9154ca9…); kernel-check on 7.3.4-200.fc44: 24 pass, 0 fail, 2 skip, `socket-lb-live` egress gateway PASS.
- [x] Strict sc-build at b96d289: fmt --check, `cargo xtask check`, test/build.sh, kernel-check 24 pass 0 fail 2 skip (egress gateway PASS). Staged.
- IPv6 (`flowsdn_egress_gw_policy_v6`) not built: #580 (proposed).

### ADR: Rust L7 proxy in the agent — #563 (P3), 2026-11-25

- [x] ADR-0024 (in-agent module `flowsdn-l7`, BPF TPROXY only, no xDS or CEC, order DNS → HTTP → Ingress → Gateway API, Kafka refused, OpenSSL TLS with agent-read Secrets, conformance via the upstream suites). Spec 16/21 amendments, ADR-0015/ADR-0001 notes, docs index.
- Parked behind it, picked up when something on the platform needs L7: #536, #537, #543, #474, #335 (only FlowsdnGatewayClassConfig), #525 (divergences).
- [x] 2026-11-25 (#543): filed #577 (proxy core) and #578 (Ingress stage 1), not proposed (the ruling: not started until L7 is needed). #543 is proposed --after #577 and #578; #474 --after #543.
- [x] 2026-11-25 (#537, #536): both proposed --after #577. #537 is HTTP only (Kafka refused, ADR-0024).
- [x] 2026-11-25 (#537): #577 is done; #537 is proposed --after #582. HTTP ingress rules need the ingress redirect, and both directions need the upstream leg to keep the source identity (#582).
- [x] 2026-11-25 (#578): handed out ahead of the proxy core; #577 is already queued, so #578 is proposed --after #577 (it needs the in-agent proxy to serve the model).

### Local redirect policy and skip-LB — #565 (P3), 2026-11-25

- [x] socket-lb skip maps and the scope-2 own-Service copy; planner, loader, watch (Pod ports/readiness, RedirectPolicies), agent planning (`local_redirect.rs`), the `flowsdn-lrp` thread (re-plan every 2 s, `status.ok`), `GET /v1/lrp`, RBAC, docs.
- [x] BPF object + lock rebuilt from 92bf7ca (socket-lb sha256 96d50a27…), committed at 1ae2a67. Strict sc-build at 1ae2a67: fmt --check, `cargo xtask check`, test/build.sh, kernel-check on 7.3.4-200.fc44 (24 pass, 0 fail, 2 skip; `socket-lb-live` local redirect and skip-LB steps PASS). Staged.

### scripttest step A: table store, lifecycle, fake Kubernetes — #516 (P3), 2026-11-25

Done on branch `scripttest-fixtures-516`, merged to main. The five areas run in the corpus gate: 8 PASS, 6 XFAIL (recorded), 0 FAIL. #517-#526 are unblocked.
- [x] Corpus gate with DIVERGENCES.toml (ADR-0005), `db/*`, Fixture + `hive/*`, fake Kubernetes client + `k8s/*`, health and metrics commands.
- [x] hive-health, metrics, k8sclient pass (k8sclient/fake XFAIL); dynamicconfig and k8s-tables XFAIL with their ADRs.

### scripttest IPAM adapters — #517 (P3), 2026-11-25

Needs step A (#516) first; open. Parked --after #516. With this, every scripttest adapter gap (#517-#526) waits on #516.
- [x] After #516: IPAM fixture, `ipam/*`, `allocator/*` (§3.3.12), DIVERGENCES.toml x3.
- [x] 2026-11-25: done. `ipam/start` over the agent's Node pod-CIDR source. Four partial divergences (CiliumNode/CiliumPodIPPool inputs, ADR-0020; the `podippools` StateDB table, ADR-0004). Gate 8 PASS, 15 XFAIL, 0 FAIL.

### scripttest policy, identity and endpoint adapters — #518 (P3), 2026-11-25

Needs step A (#516) first; open. Parked --after #516.
- [x] After #516: policy fixture, `policy/*`, `identity/*`, `endpoint/*`, `policyrepo/*` (§3.3.10), DIVERGENCES.toml.
- [x] 2026-11-25: done. The policy fixture (identity/allocate via the agent's allocator, endpoint/create, policy/import via the FlowsdnNetworkPolicy parser). Five partial divergences on the CiliumNetworkPolicy import lines (ADR-0020). Gate 8 PASS, 11 XFAIL, 0 FAIL.

### scripttest privileged node-model adapters — #520 (P3), 2026-11-25

Needs step A (#516) first; open. Parked --after #516.
- [ ] After #516: netns fixture, `link/*`, `addr/*`, `route/*`, `sysctl/*`, reconciler drivers (§3.3.7-8), in kernel-check.
- [x] 2026-11-25: the areas compare spec 10's node-model tables, which the agent lacks. As ruled for #519, filed #576 (tables + desired-route/neighbor reconcilers); #520 is proposed --after #576. subnet: ADR-0017 divergence (live ConfigMap).

### scripttest load-balancer adapters — #519 (P3), 2026-11-25

Needs step A (#516) first; open. Parked --after #516. `redirectpolicy` also needs #565 (LRP agent side; #336 did
only the types) or a recorded divergence.
- [ ] After #516: `lb/*`, `skiplbmap`, `svc/set-proxy-redirect`, `test/*`, `http/get` (§3.3.5-6), DIVERGENCES.toml x3.
- [x] 2026-11-25: master decided option 1. Filed #573 (LB state in spec 05 tables, reconciled into the socket-LB maps); #519 is proposed --after #573 and #565.
- [x] (superseded) 2026-11-25: blocked on a decision (comment on #519). The agent's LB is a stateless translation to socket-LB map writes, with none of spec 05 §4.1's services/frontends/backends tables, which the corpus's 285 `db/cmp` assertions read. Options: build the tables (reconciled into the maps through flowsdn-reconcile; recommended, as its own gap), or an ADR superseding spec 05 §4.1 / ADR-0004's LB clause. Nothing built.

### scripttest Hubble exporter adapters — #521 (P3), 2026-11-25

Needs step A (#516) and the Hubble observer (#293) first; both open. Parked --after both.
- [ ] After #516 and #293: `config/*`, `event/send`, `file/*`, `exporters/count` (§3.3.13), DIVERGENCES.toml.

### Egress, redirect and plugin kinds — #336 (P2), 2026-11-25

Types for the three kinds + T-CRD-3/4/5/7 (generator: pattern/CEL-aware string candidates, oneOf branches). Agent
features split: #564 egress gateway (spec 14 §3.4), #565 LRP + skip-LB (spec 05 §3.9), #566 datapath plugins
(spec 01 defers; specify first). #523 re-pointed to #564.
- [x] Types, tests, docs, changelog (branch kinds-336).
- [x] Branch sc-build at 1dc1898 (8/8 kinds tests, check 0 failed); merged; sc-build at 030fa0c: fmt --check, `cargo xtask
      check` 1049/0. No runtime change, no stage. Closed; features in #564 #565 #566.

### scripttest operator adapters — #522 (P3), 2026-11-25

Needs step A (#516) first, per the issue and spec 17 §3.9; #516 is open. Parked --after #516.
- [ ] After #516: operator fixture, kvstore fake (§3.3.11, §3.3.14), DIVERGENCES.toml for 2 areas.
- [x] 2026-11-25: the scripts need the operator's unbuilt kvstore duties. Filed #572 (after #446); #522 is proposed --after #572 and #446. Keys and kinds diverge under ADR-0023/0017.

### scripttest egress gateway adapters — #523 (P3), 2026-11-25

Needs step A (#516) and FlowsdnEgressGatewayPolicy (#336) first; both open. Parked --after both.
- [x] After #516 and #336: `egress/policy-maps-dump` (§3.3.14), the `egressgateway` DIVERGENCES.toml.
- [x] 2026-11-25: `egress/policy-maps-dump` over flowsdn's planner (tests/egress.rs); egressgateway recorded as expected-fail (Cilium kinds, ADR-0020; spec 10 tables, #576).

### scripttest BGP adapters — #524 (P3), 2026-11-25

Needs step A (#516) first, per the issue and spec 17 §3.9; #516 is open. Parked --after #516.
- [ ] After #516: BGP test peer (§3.6.6), `bgp/*`, `gobgp/*` (§3.3.9), DIVERGENCES.toml for 2 areas.
- [x] 2026-11-25: the scripts need the unbuilt BGP control plane and speaker. Filed #570 (reconcilers + Advertiser, after #334) and #571 (in-tree speaker). #524 is proposed --after #570, #571 and #334. The input kinds diverge under ADR-0017/0020 (FlowsdnBGP*, not CiliumBGP*).

### scripttest ClusterMesh adapters — #526 (P3), 2026-11-25

Needs step A (#516: Fixture, table store, lifecycle, fake Kubernetes adapters) first, per the issue and spec 17 §3.9;
#516 is open. Parked --after #516.
- [ ] After #516: kvstore fake, clustermesh-apiserver fixture (§3.3.11), DIVERGENCES.toml for 3 areas.
- [x] 2026-11-25: master decided flowsdn names (ADR-0023, spec 20 amendment). Filed #567 (apiserver sync §3.8), #568 (remote-service import §3.7, after #519) and #569 (MCS CoreDNS). #526 is proposed --after #567, #568, #569 and #519; nothing is built here until they close.
- [x] (superseded) 2026-11-25: blocked on an owner decision (comment on #526). The question is whether the kvstore key space stays `cilium/` (spec 20 §2 interop) or becomes flowsdn's under "no Cilium, period" (#294/#330, #339 open). Independently, the scripts need the unbuilt `flowsdn-clustermesh-apiserver` sync (spec 20 §3.8), the agent's remote-cluster importer (§3.7), MCS CoreDNS config, and #519's LB tables. Nothing built.

### scripttest Envoy config adapters — #525 (P3), 2026-11-25

Envoy-specific (fake Envoy, `envoy/cmp`, CEC → xDS): under the master's ruling (never Envoy) #563 decides what replaces
that contract and already lists #525 in its scope. Parked --after #563; the `envoyconfig` area stays unasserted.
- [x] After #563: port to the Rust proxy's config, or record ADR-0005 divergences.
- [x] 2026-11-25: done under ADR-0024. envoyconfig runs and is recorded as expected-fail (no Envoy/xDS/CEC); the fake Envoy and `envoy/cmp` are not built.

### toFQDNs and DNS rules — #536 (P3), 2026-11-25

Applied the master's L7 ruling (on #543): the DNS proxy is in the agent (spec 16 §3.6) but uses the shared proxy-port
redirect (§3.3, spec 06) that the Rust L7 proxy ADR decides, so it is parked behind #563 and the DNS proxy was added
to #563's scope. Not built; rules stay refused and reported (fail closed). If the master reads the ruling differently,
this is the place to override.
- [ ] After #563.

### ICMP errors of source-NATed flows — #534 (P3), 2026-11-25

Frontend's node, `nodeport_ingress`: icmp_error4_in/6_in hand FLOW_SNAT flows to snat_error4_in/6_in (to the
backend quoting `backend -> nat:natport`, from nat; reservation must name the client); new snat_icmp_in4/6 (own frames,
before masquerade) take the backend side's errors via the SNAT_REPLY entry (to the client quoting `client -> frontend`,
from the frontend when the backend sent it). Quote per the packet each host sent (the issue text said `nat -> backend`
for the backend's quote; a host matches by the packet it sent). Kernel step icmp_errors_snat.
- [x] Code, kernel step, docs, changelog (branch snat-icmp-534).
- [x] Branch build at 79b11a4: first run failed on a 1-in-27 flake in #494's live-flow step (flows made after the round
      filled the pool); retry passed 24/0/2. Fixed the test (live flows first). Merged; object + lock 35fa763 (socket-lb
      sha256 fd3456c7…). Strict sc-build at 35fa763: fmt, `cargo xtask check` 1046/0, lock matches, kernel-check 24/0/2
      first run. Not seen on a node. Stage requested; closed.

### L7 HTTP/Kafka policy rules — #537 (P3), 2026-11-25

Covered by the master's L7 ruling (on #543): C now, B when it comes (a Rust L7 proxy in the agent, ADR #563 first),
never Envoy. Not built; rules stay refused and reported (fail closed). Ruling posted; parked --after #563.
- [ ] After #563.

### NAT46/64 in the socket LB — #542 (P3), 2026-11-25

lookup4/6 return `Lookup::Other(id, rev)` for NAT46X64 masters; forward6 resolves it in the other family's backend map
(NAT46: native IPv6; NAT64: `::ffff:` + IPv4) and remembers UDP in LB6_REVERSE_SK; reverse6 tries LB6 first for
`::ffff:` peers; forward4 refuses Other. services.rs translates the scope-0 copy too. Kernel: TCP + connected UDP
(unconnected UDP across families is refused by the kernel itself), EPERM for AF_INET.
- [x] Code, kernel step, docs, changelog (branch socket-nat46-542).
- [x] Branch build at 6abc803 (kernel-check 24/0/2, every socket NAT46/64 line). Merged; object + lock e6b8d85
      (socket-lb sha256 5a9f6d50…). Strict sc-build at e6b8d85: fmt --check, `cargo xtask check` 1046/0, lock matches,
      kernel-check 24/0/2. Not seen on a node. Stage requested; closed.

### Controller test hang — #555 (P2), 2026-11-25

Seen once (58fe0c5, 30+ min, then passed). Client requests time out at 90 s, but `wait_for_pools` retries forever
and the test's 30 s deadline starts after it. Test body now under a 240 s watchdog naming its phase.
- [x] Watchdog, changelog.
- [x] sc-build at 52e3ac3: fmt, `cargo xtask check` 1046/0 (the test ok once; the 30-run loop lacked
      `--features kubernetes` and ran nothing). Rerun at 6abc803 with the feature: 30/30 passed, 10.2-10.4 s each,
      no hang reproduced. Closed: a recurrence now fails naming its phase (and sc-build files it).

### Gateway API controller — #543 (P3), 2026-11-25

Not started: spec 21 §1.3 forbids either controller before P1-P6 (Envoy config apply + xDS + Envoy DaemonSet,
L7 LB redirect, secret sync, operator runtime, KPR) and stage 2 before stage 1 (Ingress) is golden-clean. None of
P1-P4 or stage 1 exists; #537 leaves the proxy choice (Envoy vs Rust, ADR-0001/#262) open. Asked on the issue
(A: spec 16 Envoy path first, recommended; B: Rust proxy ADR; C: defer milestone 4 L7). `wait-owner` refused (#1680,
gap label); waiting for the owner or master's answer.
- [x] Master (2026-11-25): C now, B when it comes, never A: a Rust L7 proxy in the agent, its ADR first. Filed #563
      (P3); #543 and #474 parked --after #563; ruling posted on both; amendments to spec 16 and spec 21.

### BPF corpus: monotonic gate and re-harvest — #544 (P3), 2026-11-25

No parent commit in sc-build (#317): the monotonic gate is a committed record, tests/bpf/COVERAGE.toml, equal to
ported(m) (build.rs + xtask cases refuse below and above). `cargo xtask reharvest [--fetch]`: sparse shallow clone of
bpf/tests at 7d68cfb394; `--check` byte for byte. Evidence build at 2a26b02: fetch at the pinned commit, old file
refused at line 1 ("the same cases"), regenerated, corpus 4 + harvester 10 tests ok, reharvest byte match.
CASES.toml regenerated with the old provenance header kept as the tool's HEADER.
- [x] Code, tests, docs (spec 18 §9.4 + amendment, build-and-test.md), changelog.
- [x] sc-build at 09f307f: fmt --check, `cargo xtask check` 1046/0 (both new tests ok, coverage equals the record,
      re-harvest skipped without a reference), `cargo xtask reharvest --fetch`: byte for byte. Merged; no stage
      (tests and tools only). Closed.

### Performance suite vs Cilium — #321 (P1), status 2026-11-25

`stormcentral test run flowsdn perf`: no test machine can take a run (13.00-flowsdn failed on pvetest1/2, 13.00 on
pvetest3; others no known release; server8 in the power-off window). Suite unchanged; status posted; `wait-hardware`.
- [ ] Clean installs of both flavors on a pair; perf on each; side-by-side table; perf-scale at night.

### Milestone 2 acceptance — #292 (P1), status 2026-11-25

Datapath in source and kernel-checked (strict sc-build e983c71: 1044/0, kernel-check 24/0/2; stage d90ff71b54b7).
Remaining is hardware: perf (cross-node) + medium on pvetest1+pvetest2 with a release carrying d90ff71b54b7 or later,
and harvested scripts through real adapters. Status comment posted; `wait-hardware` (pvetest1 pair).
- [ ] Hardware run result from the master; then close or file what it finds.
### NAT46/64 reservations expire — #494 (P3), 2026-11-25

Built on the #450 branch (one socket-lb object rebuild). `expired` no longer exempts FLOW_XLATE; reservations get
pad2 at creation; `renew6`/`renew4` (own frames) renew from the dispatch of STEP_XLATE_REPLY/FORWARD (uplink ingress,
gateway egress, nodeport_endpoint); forward STALE -> new_flow46/64/gateway64_new; claim_port drops the XLATE4 reply
entry of a reclaimed XLATE reservation. Kernel: nat_expiry NAT46/NAT64 rounds + two live flows.
- [x] Code, kernel test, runtime.md, changelog.
- [x] Branch build at 32ab901 (kernel-check 24/0/2, all NAT expiry lines incl. live flows). Merged with #450; object +
      lock 9fbae6e (socket-lb sha256 4ec054a7…). Strict sc-build at 9fbae6e: fmt --check, `cargo xtask check` 1044/0,
      lock matches, kernel-check 24/0/2. Stage requested; closed.

### NAT46/64 to local backends — #450 (P3), 2026-11-25

Master (2026-11-25): option 1, the endpoint path. Built as a socket-lb classifier `nodeport_endpoint` on each local
endpoint's veth TCX ingress (first, before local-delivery) instead of local-delivery reading socket-lb's maps: same
flow state and reply translation as the uplink, no map sharing between objects. new_flow46/64 drop the out-device
= uplink check; services.rs translates local backends (not ETP Local); loader attach_endpoint; agent attach loop.
- [x] Code, kernel step `nat46x64_local`, docs, changelog. Clippy fix (UplinkSettings), step moved to :30098.
- [x] Branch build at 537d7b0 (kernel-check 24/0/2, `PASS NAT46/64 to local backends`); merged with #494, strict sc-build
      at 9fbae6e as #494. Not seen on a node. Stage requested; closed.

### Flows since: dates and order — #552 (P3), 2026-11-25

Findings 3c7298844c45 (day vs month/leap year in `flows::parse_time`) and 8fb1b606e6dc (`Events::newest` filters
all, sorts by time, then limits). Tests in flows_tests.rs; agent-api.md; changelog.
- [x] Code, tests, docs.
- [x] Verified in the e983c71 strict sc-build (clippy fix #560); stage with #447. Closed.

### toGroups peers — #530 (P3), 2026-11-25

Master (2026-11-25): A, not built (no AWS). Spec 06 in place + amendment, runtime.md, implementation-status; covered by
`authentication_and_to_groups_are_refused` (da36d96, #472).
- [x] Docs, changelog.
- [x] Verified in the e983c71 strict sc-build. Closed.

### Mutual authentication — #472 (P3), 2026-11-25

Master (2026-11-25): A, not built (deprecated upstream, no SPIRE, refusal fails closed). Spec 16 in place (line count
kept) + amendment, ADR-0013 #202 row; test `authentication_and_to_groups_are_refused` (shared with #530).
- [x] Docs, test, changelog.
- [x] Verified in the e983c71 strict sc-build (test ok after #559 fix). Closed.

### DSR by IPIP and Geneve — #447 (P3), 2026-11-25

Master (2026-11-25): option 1, BPF-only on the uplinks, native routing, the reference's wire format (spec 02 §2.5).
Design:
- `kubernetes.lb-dsr-dispatch: opt|ipip|geneve` (reference `bpf-lb-dsr-dispatch`, default `opt`) -> socket-lb map
  `flowsdn_dsr_config`; loader `SocketLb::set_dsr_dispatch`/`dsr_dispatch`.
- Which packets carry the frontend is unchanged: a TCP SYN or a UDP packet that still fits the MTU with the added
  room (opt 8/24, ipip 20/40, geneve 62/94 bytes for IPv4/IPv6); later packets are plain DNAT, too-big first
  packets source-NAT, as for the option. (The reference L4LB encapsulates every packet; per-flow reply entries make
  the first packet enough here, and MTU behaviour stays the option's.)
- ipip (IPv4 in IPv4 / IPv6 in IPv6): the client's packet unchanged inside an outer header from this node's address
  (FIB source) to the backend; the backend's node checks the inner destination is a DSR frontend and the outer
  destination one of its backends (taking that backend's port), strips the outer header, DNATs the inner packet to
  the backend and leaves the reply entry.
- geneve: the inner packet DNATed (as now), wrapped in Ethernet + Geneve (VNI 2, WORLD; the DSR option, class
  0x014b type 0x81 with the frontend) + UDP 6081 (checksum 0) + outer IP to the FIB's next hop (the backend's
  node). The backend's node checks frontend and backend as for the option, strips everything up to the inner IP
  header, and leaves the reply entry.
- Receiving is not gated by this node's setting: any valid encapsulated DSR packet is accepted, so a rolling change
  of the setting does not drop flows; invalid ones (frontend not DSR, destination not a backend) are dropped.
- Kernel test: socket-lb-live DSR step per mode and family: forward frame layout and checksums, backend decap and
  reply rewrite, forged frontend / non-backend dropped.
- [x] BPF (IPv4, IPv6), loader, agent setting, kernel step `dsr_encap`, docs. Build fixes on the way: encap4 stack
      (#556: own frame; #561: beside ingress4 via the `flowsdn_dsr_encap4` slot, combined 752 > 512), loader MAPS
      count (#557), clippy (#558). Object + lock from 0de9ad6 (socket-lb sha256 97a51810…), committed at e983c71.
- [x] Strict sc-build at e983c71: fmt --check, `cargo xtask check` 1044 passed 0 failed, test/build.sh (lock matches),
      kernel-check 7.3.4 24/0/2, `PASS DSR by encapsulation`. Not seen between two nodes. Stage requested; closed.

### Maglev in the socket LB — #453 (P3), 2026-11-25

Master (2026-11-25): A, not a gap; the reference has no socket-LB Maglev (§3.13 LUT only for uplink frontends; guide:
E-W "not subject to Maglev"). Spec 05 §3.13 in place + amendment, runtime.md, implementation-status.md, changelog.
- [x] Docs.
- [x] sc-build at 8171e1d: fmt --check, `cargo xtask check` 1042 passed 0 failed. `gap` label removed; closed.

### debug-events / test-hooks build dimensions — #464 (P3), 2026-11-25

Owner (master, 2026-11-25): A, drop both. Spec 02 §6.2 rows + net line, §8 debug events, §12 item 11 in place (line
count kept) + amendment; guard test `flowsdn-bpftest/tests/build_dimensions.rs` (no `[features]` in flowsdn-bpf).
- [x] Docs, test, changelog.
- [x] sc-build at 58fe0c5: 1st run hung in agent tests/kubernetes.rs (30+ min, cancelled, filed #555); 2nd run fmt
      --check, `cargo xtask check` 1042 passed 0 failed, `flowsdn_bpf_has_no_build_dimensions` ok. No stage; closed.

### FlowsdnEndpoint DELETE retry — #551 (P1), 2026-11-24

Finding 86abd1e1de01: `Writer::sync` removed the written entry before DELETE, so a failed DELETE was never retried.
Now the entry stays until 2xx/404/409; a same-named new Pod (different pod_uid) is skipped until the old is deleted.
- [x] Code, test `a_failed_delete_is_retried_until_it_succeeds`, runtime.md, changelog.
- [x] sc-build at 611d9b6: fmt --check, `cargo xtask check` 1041 passed 0 failed. Lock unchanged since e8c0062
      (kernel-check 24/0/2). Stage requested; closed.

### CRD registration after a raced create — #550 (P1), 2026-11-24

Finding 6d1718ddfed1: `register` took POST 409 as Created and skipped `needs_update`. Now 409 -> GET -> same update
path as an existing CRD (`Current` if it is this schema). Spec 13 §3.2 step 2 and F14 amended in place (line count kept).
- [x] Code, tests (`a_raced_create_of_an_older_schema_is_updated`, `..._this_schema_is_left_alone`), spec 13, changelog.
- [x] sc-build at 94e407e (detached, result on #550): fmt --check, `cargo xtask check` 1040 passed 0 failed, both new
      tests ok. Lock unchanged since e8c0062 (kernel-check 24/0/2). Stage requested with #549; closed.

### L2 announcer election ignores interface eligibility — #549 (P1), 2026-11-24

Finding 27c1663186dc: the rendezvous hash elected among every Ready selected node, and `interfaces_for` ran only on
the winner, so a winner without a matching device left the address unowned. Interfaces are node-local, so the hash
cannot see them. Fix as spec 05 §3.11 step 5 (the reference): a per-Service Lease
`kube-system/flowsdn-l2announce-<ns>-<name>`, contended only by eligible nodes (Ready, selected, an interface, ETP
Local endpoint). New thread `flowsdn-l2-lease`: contend/renew 2 s, 15 s duration, release when ineligible, collect
unheld/unrenewed Leases every 60 s (RBAC leases list/delete).
- [x] Code + tests 567e877 (`only_nodes_with_a_matching_interface_contend`, `stale_announcement_leases_are_collected`,
      `held_until_and_release`); runtime.md, implementation-status, agent-api, RBAC, changelog.
- [x] 567e877 failed clippy type_complexity + fmt (#553), c236282 fmt (#554); fixed in e8c0062. Strict sc-build at
      e8c0062: fmt --check, `cargo xtask check` (all new l2/lease tests ok, 0 failed), test/build.sh, kernel-check
      24/0/2. `l2-announce-live` exercises only the responder, not the election; no two-node live check (no pair).
      Stage requested; closed.

### Secret scan false positives — #546 (P1), 2026-11-23

- [x] gitleaks 8.30.1 (pinned sha256, scratch) reproduced the 29 findings at 5d3dc92. All are false positives: 5 Rust
      `let key = Ipv[46]RevnatTuple`, 06 PROVENANCE placeholder, upstream base64 `Hello world` / `Cilium123`, and 13
      upstream conformance TLS fixtures (blob ids == cilium 7d68cfb394). `.gitleaks.toml`: 4 anchored regexes plus 13
      exact paths. The keys stay unredacted (Cilium parses the PEM). Re-scan with BASE+allowlist: no leaks. A planted
      fake key in another file is still found.
- [x] 47b9843. sc-build at 47b9843 (`cargo build --locked && cargo test --locked`): exit 0, 974 passed 0 failed.
      Allowlist and docs only, so no image or stage. Closed; the next nightly scan confirms.

### BPF corpus generator and §9.4 checks — #473 (P3), 2026-11-21

- [x] `crates/flowsdn-bpftest/src/corpus.rs` (parse + §9.4 checks, generated assertions, §5.3 summary), shared by
      `build.rs` (fails the build, writes `$OUT_DIR/ported/<stem>.rs` and `coverage.txt`), `tests/corpus.rs` and
      `cargo xtask cases` (also printed by `cargo xtask check`). toml as build/dev dep (Cargo.lock edited by hand).
      Spec 18 §9.4/§11.3 and PORTED.toml header updated; monotonic + re-harvest split to #544.
- [x] 0fef694 + rustfmt 0fcfb63. sc-build at 0fcfb63: 1035 passed 0 failed (3 corpus tests), `cargo xtask check` prints
      the report (M1 10/279, M2 16/417, M3 16/625, 609 unported). Test tooling only: no image; closed.

### IPv6 BPF masquerade — #513 (P3), 2026-11-21

- [x] socket-lb `flowsdn_masq6_*`; egress in three frames (`masq6` classify, `masq_new6` claim, `masq_out6` rewrite:
      one frame overflowed 512 B); ingress `STEP_MASQ_REPLY`, `masq_icmp_in6`. Loader `set_masquerade6`; agent
      `masquerade_prefixes6`, IPv6 `non-masquerade-cidrs`.
- [x] 100eed7 feature, d0ccf9f split + fmt, e91c2c8 object + lock. Strict sc-build at e91c2c8: 1032 passed 0 failed,
      lock matches, kernel-check 24/0/2, `PASS IPv6 BPF masquerade` (IPv4 masquerade and the gateway still pass).
      Stage requested; shipped; closed.

### PacketDrop Events — #470 (P3), 2026-11-21

Reference: pkg/hubble/dropeventemitter (7d68cfb394), read into tmp/ref470.
- [x] ABI/BPF: `PolicyEvent.reason` (pad byte): no rule (policy_denied), deny rule (policy_deny), auth (auth_required),
      from `allowed()`; `/v1/policy/events` `reason`, `/v1/flows` `drop_reason` by it.
- [x] policy compile: per endpoint and direction the applied policies (`Kind/name`, namespaced and clusterwide), into
      the View for `-extended`.
- [x] Agent emitter (`drop_events.rs`): DENIED (not audit) Pod drops whose reason is listed -> Warning `PacketDrop` on
      the Pod (UID), reference message (`Incoming packet dropped (r) from ns/pod (ip) TCP/80.`), `-extended` adds
      `Applied policies: …`; `flowsdn_hubble::drop_events::Gate` (interval dedupe, per-second limit). Settings
      `kubernetes.hubble-drop-events{,-interval,-reasons,-extended,-rate-limit}`.
- [x] Tests, docs; ecd1e15 feature, 6243beb object + lock, 690e18f test fix. Strict sc-build at 690e18f: 1032
      passed 0 failed (emitter, settings, applied tests), lock matches, kernel-check 24/0/2, policy-live `reason
      (policy_denied)` and `its drop event says policy_deny`. Stage requested; shipped; closed.

### Flows on the loopback listener — #485 (P3), 2026-11-21

- [x] `GET /v1/flows` (`flows.rs`): policy events (#452) as flow records, sides resolved from the Kubernetes view (Pod,
      node, reserved/CIDR identity), `?limit=`, `?since=` (RFC 3339 parser). Tests; agent-api.md "Flow record shape",
      runtime.md, CHANGELOG. #452 closed first (verified by #448's build).
- [x] sc-build at a2c5f80 (fmt, `cargo xtask check` 1028 passed 0 failed incl. the three flow tests and
      documented routes, test/build.sh lock matches). Image requested; shipped; closed.

### ICMP type rules in network policy — #448 (P3), 2026-11-21

Split: toFQDNs and DNS rules -> #536 (DNS proxy), HTTP/Kafka L7 -> #537 (L7 proxy). #448 is the ICMP part.
- [x] Datapath: ICMP/ICMPv6 policy port = type (always; reference default true). Agent: `icmps` fields -> port rules
      (number or frozen name, IPv4/IPv6, max 40, not with toPorts), Pod and host, allow and deny; `PortRange::single`.
- [x] e69dc15 feature, 3687de2 object + lock, c29f814 test fix. Strict sc-build at c29f814: `cargo xtask check` 1025
      passed 0 failed, lock matches, kernel-check 24/0/2 (host CNI skips), `PASS ICMP type rules`. Stage requested;
      shipped; closed.

### DSR ICMP error translation — #449 (P3), 2026-11-21

- [x] socket-lb: backend node's egress (`icmp_error4_out`/`6_out`, REPLY entry: DSR or node-local) and frontend node's
      ingress (`icmp_error4_in`/`6_in`, FORWARD entry; DSR redirected by the FIB, local to the stack); quoted IPv6
      Destination Options header skipped; masquerade shares `icmp4_inner`/`set_inner4`. SNAT flows split to #534.
- [x] socket-lb-live `icmp_errors`; README, implementation-status, runtime.md; object + lock e3c462a; clippy 3468d3f.
- [x] Strict sc-build at 3468d3f: fmt, `cargo xtask check` (1024 tests, 0 failed), test/build.sh (lock matches),
      kernel-check 24 pass / 0 fail / 2 skip (host CNI paths), `PASS ICMP errors of Service flows`. Stage requested
      (b0a74be2bbe6); shipped; closed.

### Policy verdict events — #452 (P3), 2026-11-21

- [x] bpf-abi `PolicyEvent` (64 B); local-delivery `flowsdn_policy_events` RingBuf, emitted in `count` (Flow.remote);
      loader `PolicyEvents::drain`, `take_policy_events`; agent `policy_events` reader thread (100 ms, 4096 kept) and
      `GET /v1/policy/events`. Tests; agent-api.md, runtime.md. Consumers: #485 (flows), #293.
- [x] sc-build: object + lock (ae3f058). Strict run at 8c86141: fmt, `cargo xtask check`, test/build.sh and kernel-check
      `PASS policy events` passed, then policy-live failed at the host firewall load ("fd 12 is not pointing to valid
      bpf_map"): the test dropped the ring and closed the map fd the later-loaded programs use. Fixed at 92ecf56.
- [x] Strict sc-build + kernel-check covering 92ecf56: at c29f814 (#448's), `documented_routes_are_the_served_routes`
      and `events_are_kept_and_rendered` ok, policy-live `PASS policy events` and every host-firewall step after it,
      kernel-check 24/0/2. Images requested with #449/#448; shipped; closed.

### Node peers in policy rules — #451 (P3), 2026-11-21

- [x] host_policy: `Peer::Nodes` from `{from,to}Nodes` (plain-key selectors); policy: `node_peers` (local -> HOST,
      remote -> per-address scope-2 identities). Tests; policy-live node-peer case. `toGroups` split to #530 (decision
      posted, wait-owner: AWS only).
- [x] 490ee68, test fix + fmt cd36143. sc-build at cd36143 (no fmt diff): `cargo xtask check` (1023 tests, 0 failed),
      kernel-check on 7.3.4: 24/0/2; policy-live node-peer case passed. Staged; shipped; closed.

### RFC 6052 NAT46/64 gateway — #454 (P3), 2026-11-21

- [x] socket-lb.rs: `flowsdn_gw64_config`/`_sources`; egress `gateway64` (classifies into INGRESS6, creates the
      NAT64-style flow) dispatched to `to_v4` from the top level; replies via the existing XLATE4 path. Loader:
      `set_gateway64`/`gateway64`. Agent: `nat46x64-gateway`(+`-prefix`), `gateway64_sources`, services thread.
      Spec 04 §3.15 amended (catalogue citation +13). Tests.
- [x] b57e845; clippy 14fb341; the first object failed the verifier (gateway64 stack 504 + caller = 528), split into
      classify + new-flow frames bce31d8; object + lock 6cc9417 (socket-lb sha256 9c40fef9…). Strict sc-build at 6cc9417:
      `cargo xtask check` (1022 tests, 0 failed), lock check, kernel-check on 7.3.4: 24/0/2; socket-lb-live gateway step
      passed. Staged; shipped; closed.

### Health probes and history — #456 (P3), 2026-11-21

- [x] flowsdn-health `collector` (Collector, Thresholds 5/15/60 s, stale, ran_once, spawn) and `history` (History
      append/rotate 10 MB x3, read). Agent: kubernetes probe thread; `/v1/healthz` from `healthz_agent`; Facts from the
      probe; ModuleHealth history file + `GET /v1/health/history`. Tests; agent-api.md, runtime.md.
- [x] 11283ef, fmt + clippy 9b0baa6. sc-build at 9b0baa6 (no fmt diff): `cargo xtask check` (1021 tests, 0 failed),
      kernel-check on 7.3.4: 24 pass 0 fail 2 skip. Staged; shipped; closed.

### scripttest subsystem adapters — #455 split, 2026-11-21

- [x] #455 covered all of spec 17 §3.3's subsystem command groups (168 scripts, 12 areas). Split along §3.9's porting
      order into #516 (A: `db/*`, `hive/*`, health/metrics, fake Kubernetes — first, everything builds on it), #517
      IPAM, #518 policy/identity, #519 load balancer (+ redirect policy, needs #336), #520 privileged node model, #521
      Hubble exporter (needs #293), #522 operator, #523 egress gateway (needs #336), #524 BGP, #525 Envoy (needs #335),
      #526 ClusterMesh. #516 proposed; the rest proposed `--after flowsdn#516`. Nothing built under #455; closed as
      superseded.

### BPF masquerade (IPv4) — #460 (P3), 2026-11-21

- [x] socket-lb.rs: `flowsdn_masq4_sources`/`_exclude` LPM; egress `masquerade4` (TCP/UDP via `tuple4`, echo via
      `icmp4`) with `masq_flow4` on `claim_port`; ingress `masq_reply4` (SNAT_REPLY + FLOW_MASQ) and `masq_icmp4_in`
      (echo reply, ICMP errors). Loader: maps pinned, `set_masquerade`/`masquerade`. Agent: `bpf-masquerade`,
      `non-masquerade-cidrs`, `masquerade_prefixes`, services thread keeps the maps and attaches uplinks. Tests.
      IPv6 filed as #513.
- [x] Code 6968504; Prefix4 alias f4d8bf1; first object failed the verifier (combined stack 608: masq_icmp_in nested
      in ingress4), dispatch moved to the top level 866ce17; object + lock + fmt 64fb465 (socket-lb sha256 cb1faad6…).
- [x] Strict sc-build at 64fb465: fmt --check, `cargo xtask check` (1016 tests, 0 failed), lock check, kernel-check on
      7.3.4: 24 pass 0 fail 2 skip; socket-lb-live 31 PASS incl. BPF masquerade. Staged; shipped; closed. IPv6: #513.

### IPv4 fragments in Service translation — #458 (P3), 2026-11-21

- [x] socket-lb.rs: `FRAGS4` (`flowsdn_nodeport4_frags`, LRU 8192), `tuple4` records first-fragment ports and gives
      later fragments `NO_L4`; `rewrite4` rewrites only the IP header for them; `closes` and new flows skip them.
      Loader pins the map. socket-lb-live `fragments` step.
- [x] Code 4c06d52; object + lock + fmt 96cdb27 (socket-lb sha256 463e0c01…); clippy fix 052e21d (#512).
- [x] Strict sc-build at 052e21d: fmt --check, `cargo xtask check` (1015 tests, 0 failed), lock check, kernel-check on
      7.3.4: 24 pass 0 fail 2 skip; socket-lb-live 30 PASS incl. IPv4 fragments. Staged; shipped; closed.

### Topology-aware routing hints — #459 (P3), 2026-11-21

- [x] k8s: parse `hints.forZones`/`forNodes`; services: `Topology` + `by_topology` (kube-proxy rules) on ready endpoints
      for traffic policy Cluster; node zone from `topology.kubernetes.io/zone`. Unit tests; runtime.md, status.
- [x] 357b09e, fmt 316c831. Strict sc-build at 316c831: fmt --check, `cargo xtask check` (1015 tests, 0 failed),
      kernel-check on 7.3.4: 24 pass 0 fail 2 skip. Stage 0e2222ff69f6; shipped; closed.

### SCTP Services — #457 (P3), blocked 2026-11-20

- [ ] Blocked: no `sctp.ko` on nodes (stormcos stages no `kernel-modules-extra`, stormcos#1512) nor on build VMs, so
      kernel-check cannot run SCTP cases (stormcentral#1631). Proposed `--after stormcos#1512`; when it returns, check
      #1631 too. Then: SCTP in services.rs/planner, `IPPROTO_SCTP` in socket-LB connect4/6 (verify the hook fires for
      SCTP), uplink address + port rewrite (CRC32c update for ports), socket-lb-live SCTP cases. Nothing built before.

### Pod policy audit mode — #461 (P3), 2026-11-20

- [x] `kubernetes.policy-audit-mode` → View.policy_audit: AUDIT on enforced Pod rows and quarantine rows; no endpoint
      manager quarantine in audit mode; `policy.audit` status; node-config key. Unit test; policy-live `pod_audit`.
- [x] 568ab53, fmt 58ed7ff. Strict sc-build at 58ed7ff: fmt --check, `cargo xtask check` (1014 tests, 0 failed),
      kernel-check on 7.3.4: 24 pass 0 fail 2 skip; policy-live Pod audit step passed. Stage 1c8f8bd571a8; shipped; closed.

### Flows open before a policy selects a Pod — #462 (P3), 2026-11-20

- [x] policy.rs: a known local endpoint no policy selects gets a tracking row (flags 0) when Pod policy is on;
      `Desired.tracking` + status. Tests updated/new; policy-live tracking step. runtime.md, implementation-status.
- [x] d7c8fd4, tests eb3163b/bf28423/702ec0b. Build at 702ec0b: 1013 tests 0 failed, kernel-check 24/0/2; policy-live 22
      PASS incl. the tracking-row step. Golden golden-flowsdn-ac66536240cb; shipped; closed.

### Three minor findings — #500 (P3), 07c7d1dd3eec 48b8dc5f6c4b 921b14b1e023, 2026-11-20

- [x] bgp-proto: ROUTE-REFRESH length → 7/1 with the complete message (decode, receive, message). cloud-fixture canon:
      re-escape `%&=` after decoding. agent: `Manager::restore_held` on the `open_waiting` Store (api::run), cni-runtime
      restart uses it and checks the lock is held. Tests per finding; runtime.md state-dir row.
- [x] 28aa30b, wire test + fmt 259002a. Build at 702ec0b (with #462): fmt clean, `cargo xtask check` (1013 tests, 0
      failed), kernel-check on 7.3.4: 24 pass 0 fail 2 skip; cni-runtime restores on the state lock it waited for. Golden
      golden-flowsdn-ac66536240cb (built from 702ec0b); shipped; closed.

### External ClusterIP access with Maglev — #465 (P3), 2026-11-20

- [x] `kubernetes.lb-external-clusterip` → `ServiceInfo.external_clusterip`; `frontends` adds a scope-1 ClusterIP copy
      (internalTrafficPolicy, Maglev). Node-config key. Unit tests; socket-lb-live `external_clusterip` step. runtime.md,
      spec 05 §3.13 amendment.
- [x] 1be85d6, key count + fmt 3645bf0 (#505), spec 05 catalogue citations +4 2de4fcd (#506). Strict sc-build at
      2de4fcd: fmt --check, `cargo xtask check` (1010 tests, 0 failed), kernel-check on 7.3.4: 24 pass 0 fail 2 skip;
      socket-lb-live 29 PASS incl. external ClusterIP. Stage 244abe9f7de1; shipped; closed.

### ICMP errors as related traffic — #463 (P3), 2026-11-20

- [x] policy.rs: `inner4`/`inner6`/`inner_ports` parse the embedded packet (sender must be the outer destination);
      `related` checks `flowsdn_policy_ct` read-only for the flow both ways before the normal lookup. policy-live cases.
- [x] Code 5f56e70; object + lock + fmt 9e2215c (local-delivery sha256 53c3c98b…, 849072 bytes).
- [x] Strict sc-build at 9e2215c: fmt --check, `cargo xtask check` (1009 tests, 0 failed), lock check, kernel-check on
      7.3.4: 24 pass 0 fail 2 skip; policy-live 21 PASS incl. the related-errors step. Stage 3b17a213133a; shipped; closed.

### ECMP pairing keeps every reachable carrier — #499 (P1), finding 607157057c7a, 2026-11-20

- [x] `nexthops`: after the cyclic pairs (and the all-pairs fallback), a carrier without a path takes the first gateway it
      reaches. Unit test; runtime.md.
- [x] 4a12712, fmt 77ed6fa (#504). Strict sc-build at 77ed6fa: fmt --check, `cargo xtask check` (1009 tests, 0 failed),
      kernel-check on 7.3.4: 24 pass 0 fail 2 skip (uplinks-live passes). Stage 50a9f9c9fcc7; shipped; closed.

### Direct routes: per-path reachability, delete by destination — #498 (P1), findings 4bc7cb209712 8299a1f6238f, 2026-11-20

- [x] `reachable_hops` (each hop's gateway, first InternalIP only for the plain route); `stale_routes` + delete by
      destination (owned kernel route, any gateway). Unit tests; uplinks-live one-hop step. runtime.md.
- [x] 000ffb2, fmt 9b832cd. Strict sc-build at 9b832cd: fmt --check, `cargo xtask check` (1008 tests, 0 failed, incl. the
      2 new), kernel-check on 7.3.4: 24 pass 0 fail 2 skip; uplinks-live one-hop step passed. Stage e38e6bea60a2; shipped;
      closed.

### Uplink monitor: IPv6 NA, sysctl retry, failover retry — #497 (P1), findings 0cf4d2dfd14d 19c970eb0774 aa68f32f5233, 2026-11-20

- [x] `multihome::unsolicited_na`; monitor queues IPv6 (not link-local); `apply::tune_pending` (tuned only on success);
      `uplinks::reconcile_moves` (held = succeeded changes), also in uplinks-live. Unit tests; l2-announce-live NA step.
- [x] fdee984, fmt/clippy 5d0ad60. Strict sc-build at 5d0ad60: fmt --check, `cargo xtask check` (2012 tests, 0 failed,
      incl. the 3 new), kernel-check on 7.3.4: 24 pass 0 fail 2 skip; l2-announce-live: NA moved the entry to
      02:00:00:00:04:97 (STALE); uplinks-live passes with reconcile_moves. First run: qemu abort on the build VM before any
      guest output (stormcentral#1626), rerun passed. Stage e795736f321d; shipped; closed.

### Whole-resource validation for host and Pod rules — #496 (P1), finding 5c9e6d072bfa, 2026-11-20

- [x] `host_policy::resource_error` validates every spec of an object once; `pod_policies` and `select` both skip the
      object whole on an error (select reports it only when `pod_rules` is off, else pod_policies does). Test in
      host_policy_tests.rs; runtime.md (Pod rules Refused, host firewall Policies).
- [x] 50dcc66, compile fix 40a09de; sc-build at 40a09de: fmt clean, `cargo xtask check` (clippy -D warnings, 1003 tests,
      0 failed, incl. the new one). Stage build 890aa006eb92; `shipped` with proof `log:health agent\.(api|kubernetes) OK`. Closed.

### Cloud fixture scan decodes bodies — #493 (P1), finding b48aa19bda04, 2026-11-20

- [x] `scan_text`: the raw rules, plus every rule over each escaped JSON string literal decoded (recursive, depth 8),
      hit at the literal's opening quote. Tests in scan.rs (JSON body credential, nested, clean, IP) and fixture.rs
      (`write` refuses and removes, `load` refuses). Scrubber unchanged (a miss is now refused at write).
- [x] e06a935, fmt 7ddbdba; strict sc-build at 7ddbdba: fmt --check, `cargo xtask check` (1002 tests, 0 failed, incl. the 2
      new). Developer tooling only (fixture crate, xtask), no image. Closed.

### Cloud fixture writer validates before deleting — #492 (P1), finding 580a411b7925, 2026-11-20

- [x] `fixture::write`: metadata must survive `Meta::parse(to_toml())` unchanged (name `[a-z0-9-]+`, date, operations),
      every operation name valid, interactions non-empty, destination exactly `<root>/<provider>/<name>` — all before
      any remove/create. Test: `..`, `../gcp`, `a/b`, empty, uppercase, an absolute path; bad operation/date keep the
      old copy.
- [x] 2f53bc3, fmt d313458; strict sc-build at d313458: fmt --check, `cargo xtask check` (1000 tests, 0 failed). Developer
      tooling only (xtask), no image. Closed.

### Policy identity findings — #490 (P1), 2026-11-20

- [x] a84713ccfa49: each remote node address gets its own identity `2<<24 | n` (address order) in the ipcache; the
      datapath aggregates scope 2 to AGGREGATE_REMOTE_NODE (14); entities remote-node and cluster add 14; cidr_peer
      inserts the identities of exactly the node addresses inside the CIDR minus exceptions.
- [x] fd362d87218c: egress named ports via `egress_named`: the wildcard peer expands to the identities whose Pods name
      the port; an identity's Pods must agree on the mapping, else nothing + a problem. Never identity 0.
- [x] Tests (two nodes /32 + except; external, unnamed, same-identity different mapping); policy-live scope-2 step.
      Code 6a8b207, docs fcd35f7, fmt 5e664b4. kernel-check at 5e664b4 on 7.3.4: 24 pass 0 fail 2 skip, 999 tests 0 failed,
      policy-live 20 PASS. Stage, ship, close.

### New endpoints isolated until their policy is installed — #489 (P1), finding bd9892ebb241, 2026-11-20

- [x] Manager `set_quarantine` (on in Kubernetes mode with network-policy or flowsdn-policy and shared policy maps):
      `install` writes `flowsdn_policy_ep[ifindex] = {id, INGRESS|EGRESS|QUARANTINE(8)}` before attaching (restored
      endpoints untouched). Compiler: a local endpoint whose Pod/labels are unknown keeps the quarantine row;
      `Desired.local` lists known endpoints; the sweep (`stale_row`) keeps a quarantine row of an unknown endpoint.
      No datapath change (unknown flag bits are ignored). Unsynced watches: no reconcile, quarantine holds.
- [x] Tests: policy_tests (quarantine kept / released / replaced; sweep), cni-runtime (real ADD: no UDP either way
      until the row is lifted). sc-build + kernel-check; docs; stage; close.
- [x] Code 3add1e8, fixture fix (cid3 is the forced-rollback case: endpoint 4), docs 7f1308a, fmt 3eeac0c. kernel-check
      on 7.3.4: 24 pass 0 fail 2 skip, 997 tests 0 failed; cni-runtime quarantine PASS. Strict sc-build at 3eeac0c.

### socket-lb review findings — #488 (P1), 2026-11-20

- [x] 0252b1736f32 (security): the backend node accepts a DSR option only when its frontend has a node-local master
      with FWD_MODE_DSR and the destination is one of its backends (slots 1..=count, at most 256); otherwise drop.
      `dsr4`/`dsr6` run from the classifier on their own frames (IPv6: new STEP_DSR).
- [x] 08ad0c4a7dca: a new remote flow is DSR only when its first packet carries the option (IPv4 bare header + SYN or
      UDP that fits with it; IPv6 fits); otherwise SNAT.
- [x] 1cb155baca89: NAT reservation expiry without changing the pinned value layout: 16-bit last-seen seconds in
      `pad2`, FLOW_CLOSING (8) on FIN/RST; lifetimes TCP 21600 s / closing 10 s / UDP 60 s; claim reclaims an expired
      reservation (deleting its stale forward entry); a forward flow whose reservation no longer names it is new.
- [x] socket-lb-live steps per finding; objects + lock; kernel-check; docs; stage; close.
- [x] DSR fixes 5ebae69 + object; kernel-check (DSR only) 24/0/2. NAT expiry + scratch keys (first link failed on the
      BPF stack limit in new_flow6/ingress4: keys moved to `flowsdn_nodeport_natkeys`), object ff03ffd (sha256
      505f361c…). kernel-check at ff03ffd on 7.3.4: 24 pass 0 fail 2 skip, 995 tests 0 failed, fmt clean; socket-lb-live
      28 PASS incl. NAT expiry TCP 2941→2929/3000, UDP 2945→2955/3000. NAT46/64 reservations excluded: #494 (gap).

### XDP prefilter and /v1/prefilter — #467 (P3), 2026-11-20

In scope (spec 02 M2, spec 01 maps deferred, spec 00 `enable-xdp-prefilter` default false). Plan:
- [x] BPF (local-delivery): `xdp_prefilter` + `flowsdn_cidr_v{4,6}_{fix,dyn}` (hash for /32,/128; LPM otherwise;
      1024, NO_PREALLOC); drop on source match, else pass. Object + lock via sc-build.
- [x] Loader: attach (native, else generic) / detach per interface, map insert/delete/clear.
- [x] Agent: `kubernetes.xdp-prefilter` (default false) attaches to the uplinks with a MAC; state {revision from 1,
      deny set}; `GET/PATCH/DELETE /v1/prefilter` (Prefilter {spec{revision,deny},status{realized}}; PATCH/DELETE
      body PrefilterSpec: revision mismatch 500, invalid CIDR 461, absent CIDR on DELETE 500; off: 500 "not
      enabled"); maps cleared at start (state not persisted, as the reference).
- [x] Tests: unit (state, routes with a fake map), fixture `prefilter-live` (test-run drop/pass v4/v6 fix+dyn,
      real attach/detach on a veth); docs (agent API, runtime, spec 08/01/02 amendments), changelog.
- [x] Code 453d9cf, docs 550620a, object + lock b7ca248 (sha256 2cc7ca08…), fmt acadbb2. kernel-check at b7ca248 on
      7.3.4: 24 pass 0 fail 2 skip; prefilter-live 4 PASS (native XDP on a veth dropped a denied peer's UDP). Strict
      sc-build at acadbb2: 995 tests 0 failed, lock matches. Stage, ship, close.

### cgroup-dump-metadata and map events routes — #468 (P3), 2026-11-20

Scope question: only cilium-dbg calls them; `/map/{name}/events` needs the `/map`, `/map/{name}` cache API flowsdn
does not have (untracked) plus `bpf-map-event-buffers` (off by default in the reference); cgroup metadata needs
rustkube-node's cgroup layout. Nothing in flowsdn consumes them.
- [x] Asked (A: drop from scope; B: build all incl. /map family; C: cgroup route only), recommended A; `wait-owner`.
- [x] Owner (master, 2026-11-24): A. /map, /map/{name}, /map/{name}/events, /cgroup-dump-metadata stay absent (404).
- [x] Spec 08 §1/§2.2/rows 32–35/decision 6 in place (line count kept) + amendment; test
      `dropped_cilium_dbg_routes_stay_absent`; changelog.
- [x] Strict sc-build at 40d59e2 (40b7ca9 failed fmt, auto-filed #547, fixed): fmt --check, `cargo xtask check`
      (1036 tests, 0 failed), `dropped_cilium_dbg_routes_stay_absent` ok. Docs/test only: no stage. Closed.

### L2 neighbor management — #469 (P3), 2026-11-20

Spec 10 §3.4/§5.7. Forwardable IPs: remote nodes' InternalIPs (backends feed the reference's table only with XDP
acceleration, which flowsdn has not: out). Selected devices: uplinks (#408) with a MAC. Setting
`kubernetes.l2-neigh-discovery` (reference `enable-l2-neigh-discovery`, default false). rtnetlink 0.23 /
netlink-packet-route 0.33 have FibMatch|LookupTable, Oif, MultiPath, NeighbourFlags::ExtLearned,
NeighbourExtFlags::Managed, NeighbourState::None (read from the crates.io sources, checksums = Cargo.lock).
- [x] connector `neighbor.rs`: `next_hops(ip, oif)` (RTM_GETROUTE FIB match; gateway / multipath gateways on oif /
      on-link; ENETUNREACH/EHOSTUNREACH = none), `learned()`, `add_managed`, `delete_neighbor`, `probe_managed()`.
- [x] agent `neighbors.rs`: planner (forwardable, devices, desired, prune diff), calculator (15 s limit, 5 min
      resync), thread `flowsdn-neighbors`, health part `neighbors`, start probe fatal when on.
- [x] fixture `neighbors-live`, unit tests, docs: code 43f9272, docs 3ef0fee, fmt eb25789. sc-build (fmt fallback) +
      kernel-check on 7.3.4: 990 tests 0 failed, 23 pass 0 fail 2 skip, neighbors-live 5 PASS (kernel resolved the
      managed entry: `managed extern_learn REACHABLE`). Strict sc-build at eb25789 green. Stage, ship, close.

### PacketDrop Events — #470 (P3), 2026-11-20

Blocked on #452: the policy programs emit no per-flow events (no ring buffer or perf map in local-delivery); #452 builds
that event and the agent reader. #470 then adds the pod-UID lookup, the emitter on the Event writer
(`flowsdn-hubble::drop_events` admission), the `hubble-drop-events*` settings and a kernel test (a policy-denied flow:
one rate-limited PacketDrop Event).
- [x] Proposed `--after flowsdn#452`.

### CRD hash manifest bound to SCHEMA_VERSION — #471 (P3), 2026-11-20

- [x] `crds/SCHEMA_VERSIONS` (version  sha256-of-SHA256SUMS lines), T-CRD-1b + refusal unit test in
      crates/flowsdn-k8s/tests/crds.rs, vendor-crds.sh prints the digest, spec 12 (same line count), crds.md, changelog.
- [x] 5754463, fmt 2d921c0; strict sc-build at 2d921c0 (fmt --check, `cargo xtask check`, 982 tests 0 failed). Closed.

### Mutual authentication gap — #472 (P3), 2026-11-20

Scope question, not code: needs SPIRE (no platform component runs it; stormcert workload identities are design only),
deprecated upstream in 1.20, refusal already fails closed (#202). #202's resolution keeps it formally in scope.
- [x] Asked the owner (A: out of scope, refusal permanent; B: reference build + SPIRE; C: own on stormcert), recommended
      A; `wait-owner`.
- [ ] On A: amend ADR-0013 #202 row and spec 16 §3.8/§12.10 (append), changelog; close. On B/C: plan the build.

### Review finding 9353481628e3 again — #487 (P0), 2026-11-20

The service filed the finding fixed under #484 as a new issue: the line it names (`LinkOrder::first()`, correct: NodePort
must precede the firewall) is unchanged, so it did not close by itself. Fix already on main (8cf7cfb, object 6925607,
test host-chain-live 8859ca6); host-chain-live 4 PASS again at 485fb99 (kernel-check 22/0/2). No new code.
- [x] `shipped` (same proof as #484), #487 closed with the evidence.

### Host firewall egress rules — #477 (P3), 2026-11-20

The datapath already enforces generically (`to_netdev` egress=1 SCOPE_HOST; `to_container` egress=1 SCOPE_HOST_PODS):
only the agent was missing. Plan: parse egress/egressDeny with `to*` peers into `HostPolicies.egress_rules`
(+ `enforce_egress` from enableDefaultDeny.egress), compile to HOST_ENDPOINT egress entries, set EGRESS after learning
on the uplinks and HOST_PODS; `egress-enforced` in health; policy-live steps; docs (runtime, ADR-0022, status, README).
- [x] Code + unit tests + policy-live + docs: 485fb99, fmt b543e7b. sc-build at 485fb99 (fmt fallback): `cargo xtask
      check` 980 tests 0 failed, test/build.sh, kernel-check on 7.3.4: 22 pass 0 fail 2 skip; policy-live 19 PASS incl.
      the 3 host egress steps.
- [x] Strict sc-build at b543e7b passed: fmt --check, `cargo xtask check` (980 tests, 0 failed), test/build.sh.
- [x] Resumed after #487. No new stage: golden-flowsdn-69cac9dd7617 (flowsdn@7f1308a) already carries 485fb99. Later
      kernel-check at 5e664b4 (7.3.4): 24 pass 0 fail 2 skip, policy-live 20 PASS incl. the 3 host egress steps.
      `shipped` (proof: agent health OK in the install log); #477 closed. Live run with a nodeSelector egress policy: #478.

### Host firewall first live run — #478 (P3), 2026-11-20

Needs a flowsdn node whose golden has the operator (CRDs, 66daa9b; stormcos#303 closed for it) and the #484 fix
(6925607: NodePort TCX programs no longer bypass the firewall on the uplink). pvetest2's 12.97-flowsdn has flowsdn
2b801ce: neither.
- [x] Proposed `--after-install flowsdn>=6925607@pvetest2`.
- [ ] Then on pvetest2: `HostFirewall` Event, `/v1/healthz` `kubernetes.policy.host-firewall`, `/v1/policy/verdicts`
      audit rows (audit is the edition's setting); kubelet/API/SSH alive through the 60 s learning window; HOST_PODS
      judged; a non-InternalIP node address is the host's. Enforce via a FlowsdnNodeConfig `kubernetes.host-firewall`
      (#480) for the node. Ship with the Event proof; close.

### #408 on real hardware — #417 (P2), 2026-11-20

Owner (on #417, 2026-11-20): the proof runs on a flowsdn test machine (server1-8 or the Dell), pulling a cable more
than once on its 25G ports; forge1 moves to flowsdn separately. Choice: **C2NR0Q2 (Dell R230)**, the only one with
two 25G ports: ConnectX-4 Lx 15b3:1015, eth0 5c:06:22:06:f9:6c (g16 reservation 192.168.30.1) and eth1
5c:06:22:06:f9:6d (192.168.30.2, the machine's address), both on 192.168.16.0/20 and both receiving (stormdrive
readings). server1-8 have one ixgbe + one mlx4 port each, not 25G pairs. 12.97-flowsdn already carries #408 (8480160).
- [x] Master note: `testhost edit C2NR0Q2 --set flavor=flowsdn`, then install the newest flowsdn release on it.
- [x] Proposed `--after-install flowsdn>=8480160@C2NR0Q2`.
- [ ] Then `wait-owner --action`: pull/replug eth0 (30.1) twice and eth1 (30.2) once, 30 s apart.
- [ ] Proof: Node Events UplinkLeft/UplinkJoined on C2NR0Q2 ("2 of 2 carrying" after each return); ship, close #417
      and #408's done-when (2x25G throughput: a measurement on the same run, perf suite).

### Operator executable gap — #446 (P2), 2026-11-20

Binary and manifests done by #337 (`flowsdn-agent operator`, 64-flowsdn-operator.yaml). Left: a test-standard test.
- [x] `node-operator` in the node probe: `flowsdn-perf operator` (GNU, API client) reads Lease
      kube-system/flowsdn-operator (holder, renewed within 3 durations) and CRD flowsdnidentities Established;
      requires.toml cluster_read leases + customresourcedefinitions; skip without STORM_API. Unit tests for the verdict.
- [x] 8cd444d, fmt ce58192. sc-build at ce58192: fmt --check, `cargo xtask check` (978 tests, 0 failed, incl. 3 verdict
      tests), test/build.sh.
- [ ] Proposed `--after-install flowsdn>=66daa9b@pvetest2` (pvetest2's 12.97-flowsdn has flowsdn 2b801ce, no
      operator). Then a short run on pvetest2 (node-operator pass), ship with the Lease proof, close.

### Operator GC and FlowsdnEndpointSlice batching — #479 (P2), 2026-11-20

The operator exists now (#337). Parts:
- [x] FlowsdnIdentity GC (spec 03 §3.6, flowsdn names): every `--identity-gc-interval` (900 s; 0 off) while leading.
      Alive = some FlowsdnEndpoint `status.identity.id` or FlowsdnEndpointSlice `endpoints[].id` names it; lifesign =
      alive, or resourceVersion changed since the last list (an upsert), or operator start for one seen in the first
      list. Expired (> `--identity-heartbeat-timeout`, 1800 s) and not alive: pass 1 PUT `io.flowsdn.heartbeat=<now>`,
      a later pass DELETE with {uid, resourceVersion}; 409/404 skipped. `--identity-gc-rate-limit` (2500) deletes per
      `--identity-gc-rate-interval` (60 s); the rest wait for the next run (the operator loop also renews the Lease).
      No FlowsdnEndpoint GC exists (Pod-owned, cascaded), so it is not a precondition here (spec amendment).
- [x] FlowsdnNode GC (spec 12 §3.9): every `--nodes-gc-interval` (300 s; 0 off); no ownerReferences, no
      `flowsdn.io/do-not-gc: true`, no Node of its name: candidate; still so one interval later: DELETE (404 ok).
- [x] RBAC, docs (runtime, spec 03/12 amendments appended, README, crds, status), changelog: 144e595; test fix + fmt
      52b381c. sc-build at 52b381c: fmt --check, `cargo xtask check` (Clippy -D warnings, 975 tests, 0 failed, 1 ignored;
      9 operator_gc tests + operator flags). Stage requested at the next commit.
- [ ] FlowsdnEndpointSlice batching: agents learn peers from the cluster-wide Pod watch and read no other node's
      FlowsdnEndpoint, so slices would have no reader. Decided A (master, 2026-11-20, on the issue): not built; docs updated. Ship the GC (stage 433eefa2e1bd,
      proof: the operator Lease held on pvetest2), close #479.
- [x] 6c90338 docs; sc-build at 6c90338 (fmt --check, `cargo xtask check`, 980 tests 0 failed). `shipped` (proof: operator
      Lease held on pvetest2); #479 closed.

### FlowsdnEndpoint/FlowsdnNode seen on a node — #482 (P2), 2026-11-20

Verification only (no code). Needs a flowsdn-flavor node whose golden has the writers (d39aa94) and the operator that
registers the CRDs (66daa9b, #337; stormcos#303 closed in its favour). pvetest2 (the only flowsdn-flavor test machine)
runs 12.97-flowsdn: flowsdn golden at 2b801ce, which has the writers but not the operator, so the kinds are not served.
- [x] Proposed `--after-install flowsdn>=66daa9b@pvetest2`.
- [ ] Then: FlowsdnNode for the node (owner Node, InternalIPs, pod CIDRs); a FlowsdnEndpoint per non-host-network Pod
      (owner Pod, addresses, identity); deleting a Pod removes it. `shipped` with proof
      `api:/apis/flowsdn.io/v1alpha1/flowsdnnodes ~ "name":"{name}"`; close.

### NodePort TCX programs short-circuit the host firewall — #484 (P0), finding 9353481628e3, 2026-11-20

`nodeport_ingress`/`nodeport_egress` attach first on the uplink's TCX hooks and return TC_ACT_OK (TCX_PASS) for
everything they do not redirect or drop; TCX stops the chain there, so `from_netdev`/`to_netdev` (attached last)
never ran on an uplink with NodePort on. Fix: both classifiers return TCX_NEXT (-1) where they returned TC_ACT_OK
(redirect and drop unchanged), so the host firewall judges the (translated) packet.
- [x] BPF `next()` at both entry points 8cf7cfb, socket-lb object + lock 6925607 (sha256 af7b97f9…).
- [x] socket-lb-live expects TCX_NEXT; new fixture `host-chain-live` 8859ca6 (fmt 4fa00b0).
- [x] Negative control at 8859ca6 (old object, SC_BUILD_EXPECT_FAIL): kernel-check 7.3.4 21 pass, 1 fail: host-chain-live
      "peer to host TCP 7002: OK: the host firewall did not run after the NodePort program" (the finding reproduced).
- [x] kernel-check at 6925607 on 7.3.4-200.fc44: 22 pass, 0 fail, 2 skip; host-chain-live 4 PASS, socket-lb-live 26 PASS,
      policy-live 16 PASS. Strict sc-build at 4fa00b0: fmt --check, `cargo xtask check` (966 tests, 0 failed), test/build.sh.
- [x] Stage 345b0b270728; `shipped` (proof: agent health OK in the install log); #484 closed.

### FlowsdnNodeConfig as an agent configuration source — #480 (P2), 2026-11-20

Decision (master 2026-11-20, on the issue, from the owner's standing rules): (A) — `spec.defaults` keys are flowsdn's own
agent settings for the nodes `nodeSelector` picks; every key it accepts works; read at agent start.
- [x] `node_config.rs`: allowed keys (node-scoped settings: egress, device-mtu, pools/gateways, kubernetes.* except
      node-name/kubeconfig/cgroup-root/cluster-name; no paths); configs selected by nodeSelector, applied in name
      order (later wins); value JSON-parsed else string; each key validated by parsing the whole config with it,
      refused (with the reason) otherwise; not served (404) = none.
- [x] api::run: before connect, fetch the Node's labels and `<POD_NAMESPACE|kube-system>` FlowsdnNodeConfigs (retry
      60 s, then fail), re-parse. `/v1/healthz` `node-config` {applied: key -> config, refused}; refused keys are
      Warning Events on the Node.
- [x] Code 42bf7d0 (+ a config's keys applied together when valid, for pool/gateway pairs), loopback fetch test
      413f2ad, docs 78c4f31 (+ spec 00 amendment appended at the end: catalogue line cites unaffected), fmt 5460b5a.
      sc-build at 5460b5a: fmt --check, `cargo xtask check` (Clippy -D warnings, 966 tests, 0 failed, 1 ignored: 5
      node_config tests, the loopback controller test reading the Node and a selecting config), test/build.sh.
- [x] Stage 4ad788e8db11; `shipped`; needs-owner removed; #480 closed. (#483 was my fmt-only build; closed by the pass.)

### Socket termination gaps — #392 (P3), 2026-11-20

TCP: spec 05 §3.8 (flowsdn's own) already decides it: UDP always, TCP only with the reference's hidden
`lb-sock-terminate-all-protos` (default false) -> `kubernetes.lb-sock-terminate-all-protos`, default false. The socket
LB records only UDP translations in `_reverse_sk` (as the reference), so with it TCP sockets are matched by the
removed backend's address and port (a direct connection to that port is ended too; documented).
- [x] connector `sock_diag`: protocol-generic dump/destroy (`sockets(proto)`), `destroy_to(gone, udp_cookies, tcp)`
      shared by the agent and the fixture.
- [x] agent: startup reconcile (first successful programming: UDP backends in `_reverse_sk` that no Service has
      now); 50 ms batching (`Batch`: gone backends collect, one pass per 50 ms); the setting.
- [x] socket-lb-live: TCP termination step + startup reconcile shape; unit tests for Batch and selection.
- [x] Code 8f9018d, fmt a86adc3, docs 347c16e (spec 05 amendment kept at 5 lines: catalogue cites lines below).
      sc-build at 347c16e: fmt --check, `cargo xtask check` (Clippy -D warnings, 961 tests, 0 failed, 1 ignored, incl.
      batch, stale/terminable selection, sock_diag ends), test/build.sh, kernel-check on 7.3.4: 21 pass, 0 fail,
      2 skip; socket-lb-live: UDP destroy through the shared destroy_to, TCP left alone by default and ended with
      all protocols, a connection to another backend kept.
- [x] Stage 91e10462367b; `shipped` (proof: agent health OK in the install log). #392 closed.

### CRD registration by the operator, agent CRD readiness gate — #337 (P1), 2026-11-20

Also builds the operator executable of gap #446. Packaging: `flowsdn-agent operator` (a mode of the agent binary, as
`cni install` is), so the golden stormcos builds (GNU agent + its OpenSSL runtime, `-p flowsdn-agent --features
kubernetes`) already carries it; no stormcos change. rustkube serves CRD Established/NamesAccepted and
PartialObjectMetadata lists (checked in its source).
- [x] flowsdn-k8s: `crd::shipped_crds()` (the generated `crds/*.yaml`, include_str: no reference text in a binary);
      `register` (spec 13 §3.2 steps 2-5: GET, POST/409 ok, update when schema absent / label missing / older,
      poll 500 ms x 60 s, Established, NamesAccepted=False fatal) with an injected request fn; metadata-only
      CRD list (`Accept: …as=PartialObjectMetadataList…`).
- [x] Agent `operator` mode: Lease kube-system/flowsdn-operator (lease.rs), registration when leading and every
      5 min; `--skip-crd-creation`; POD_NAME identity.
- [x] Agent gate: required set from settings (identities, LB pools, L2 policies, endpoints, nodes, policy kinds as
      enabled); flowsdn.io watchers start only after all are present; `kubernetes.crd-wait-timeout` (s, 300) fatal.
- [x] Manifest 64-flowsdn-operator.yaml: Deployment, hostNetwork (the agent waits on it), tolerate all,
      system-cluster-critical, `image: flowsdn`, `/flowsdn-agent operator`.
- [x] Code a2f0206..f36885a, docs 7975a2b, fmt 66daa9b. sc-build at 66daa9b: fmt --check, `cargo xtask check`
      (Clippy -D warnings, 958 tests, 0 failed, 1 ignored: 9 registration, 3 operator, CLI, gate settings, and the
      loopback-API controller test whose CRD list withholds FlowsdnIdentity's CRD at first), test/build.sh, the
      release GNU Kubernetes agent: check-no-cilium clean, `operator --help`.
- [x] Stage d13d0b2581be; `shipped` with proof: Lease kube-system/flowsdn-operator has a `flowsdn-operator-` holder.
      Told stormcos#303 (applying crds/ now optional) and #446 (test on a node left). #478/#482 moved to
      --after-install flowsdn>=66daa9b (still also after stormcos#303). #337 closed.

### flowsdn.io endpoint, identity and node kinds — #332 (P1), 2026-11-20

Operator parts (identity GC, node GC, FlowsdnEndpointSlice batching) need the operator executable (gap #446):
split to #479, proposed after #446. FlowsdnIdentity allocation itself shipped with #291. Here:
- [x] `flowsdn_k8s::kinds`: serde types for FlowsdnEndpoint, FlowsdnEndpointSlice, FlowsdnIdentity, FlowsdnNode,
      FlowsdnNodeConfig (one field per schema property, ObjectMeta, `Kind` trait with paths). Drafted from the
      vendored schemas by a throwaway script in tmp/ (not committed), then kept by hand. Deviation from spec 13
      §11.2: no `#[derive(CustomResource)]` (three of the five kinds have no `spec`) and no schemars/proptest:
      T-CRD-3 is schema-driven (an every-field and a required-only instance round-trip, the type's own output is
      admitted by `flowsdn_k8s::schema` strict validation); T-CRD-7 is seeded random schema-valid documents.
- [x] Agent: FlowsdnEndpoint per local Pod (POST with ownerReference -> Pod controller: true; status by JSON patch
      with a UID `test` op; DELETE on removal), carrying #328's pod facts; 404 (CRD absent, stormcos#303) is not
      an error. Events on the Pod for endpoint failures.
- [x] Agent: its own FlowsdnNode (addresses, health, pod CIDRs, bootid; ownerReference -> Node).
- [x] FlowsdnNodeConfig: what it overrides is the owner's call (agent JSON keys vs reference option names); split to
      #480 with a recommendation, wait-owner.
- [x] Code bb17770..d39aa94 (types, JSON-patch client, endpoint writer, node writer, fmt); docs d090be7, spec 13
      amendment 2dc4f80. sc-build at d39aa94: fmt --check, `cargo xtask check` (Clippy -D warnings, 944 tests, 0 failed,
      1 ignored: 6 kinds tests, 6 endpoint and 5 node writer tests), test/build.sh (lock check, no-cilium clean).
- [x] Stage 4b0daa98d949 requested. Seeing it on a node needs stormcos#303 (CRDs): #482, proposed after it. #332 closed.

### Host firewall follow-ups — #384 (P3), 2026-11-20

Which of the four gaps stormfw's HostFirewallPolicy (stormfw#1: ingress rules only; one policy, two backends, so the
flowsdn backend must mean what the Cilium host firewall means) needs:
- host **egress** policy: not needed (HostFirewallPolicy has no egress rules). Stays absent; `to_netdev` only tracks.
- **boot window**: stormfw's own boot program (stormfw#1 step 3). flowsdn's part is the hand-over signal, already in
  `/v1/healthz` (`kubernetes.policy.host-firewall`: `learning`, `enforcing-on`); documented for stormfw.
- **pod-to-node**: needed. Cilium judges local pods' traffic to the host by the host policy; without it any pod reaches
  engine :9090 / registry :5100 / sshd :22 that the default policy limits to the node or admin network.
  Design: `flowsdn_policy_ep` key 0 (`HOST_PODS`, no real ifindex) holds the host endpoint for the veth path;
  `local_delivery` (after the pod's egress) judges packets to a host address as host ingress, `to_container`
  remembers flows the host starts to pods (host egress, tracking only). Own 60 s learning, like an uplink.
- **addresses/interfaces without an InternalIP**: needed. Only InternalIPs + gateways had the host identity, so a
  packet to the node's other addresses (an admin NIC, a SLAAC IPv6 on the uplink) was never judged. With the host
  firewall on: every global address on the node's interfaces is host, and the programs attach to every interface
  holding one (not lo, not a bridge/bond port).
- [x] BPF + ABI + agent + tests (policy-live pod-to-host steps; compiler tests), docs, changelog (277deb7 BPF, object +
      lock from sc-build at 277deb7 in e084a5b, HostFirewall Event 1b1dabb, fmt 16a2f29, docs bf822fb).
- [x] sc-build at 16a2f29: fmt, `cargo xtask check` (Clippy -D warnings, 927 tests, 0 failed, 1 ignored, incl. the 2 new).
      kernel-check at e084a5b (same lock as HEAD) on 7.3.4-200.fc44: 21 pass, 0 fail, 2 skip; policy-live 16 PASS incl.
      3 new local-Pod steps.
- [x] Filed gap #477 (host egress) and #478 (first live run, needs stormcos#303). Stage efbada592d08 requested; shipped
      with proof: the `HostFirewall` Event; #384 closed.

### LoadBalancer Services end to end — #475 (P0), 2026-11-19

stormlb#37 / stormstorefront#1 `edge-lb` (LoadBalancer, ETP Local). The datapath (uplink TCX node-local frontends for
`status.loadBalancer.ingress`, Local = this node's backends) exists; missing: the address and the announcement.
Design (the operator executable is gap #446, so both run in the Kubernetes-mode agent):

- [x] watch: Service labels/creation/`loadBalancerClass`/`ipFamilies`/requested IPs (`spec.loadBalancerIP`,
      `lbipam.flowsdn.io/ips`); Node Ready; scopes for FlowsdnLoadBalancerIPPool and FlowsdnL2AnnouncementPolicy.
- [x] `lb_ipam.rs` (pure): pools (blocks cidr|start-stop, allowFirstLastIPs, disabled, serviceSelector incl.
      `io.kubernetes.service.{namespace,name}`, overlap -> PoolConflict on the newer), deterministic allocation
      (keep valid ingress, then requested, then lowest free per family), pool conditions.
- [x] `lease.rs` (pure): client-go style Lease decisions (expiry by local observation, not peer clocks).
- [x] controller thread `flowsdn-lb-ipam`: holds Lease kube-system/flowsdn-lb-ipam, merge-patches `services/<n>/status`
      (resourceVersion precondition) and pool `/status` conditions. Setting `kubernetes.lb-ipam` (default on).
- [x] `l2_announce.rs` (pure): policies (serviceSelector, nodeSelector, interfaces regex, loadBalancerIPs/externalIPs),
      rendezvous election over Ready selected nodes (ETP Local: nodes with a ready local endpoint) -> this node's
      (ip, interfaces). Setting `kubernetes.l2-announcements` (default on; nothing is announced without a policy).
- [x] connector `announce.rs`: AF_PACKET ARP responder + NDP NA responder (cBPF filter for NS, solicited-node
      multicast membership), GARP/unsolicited NA on takeover; responder thread.
- [x] RBAC (services/status patch, leases, pools/status), docs (runtime, agent-api, crds, stormcos README with a pool +
      policy example), CHANGELOG; kernel fixture `l2-announce-live` (veth pair: arping/NS answered by the responder).
- [x] Code at 1890331, lints/fmt 561470c, 7d1e222. sc-build at 7d1e222: `cargo fmt` no diff, `cargo xtask check` (Clippy
      -D warnings incl. indexing/arithmetic, 925 tests, 0 failed; the loopback-API controller test sees the Lease created
      as `local` and edge-lb's status patched with 192.0.2.240, resourceVersion-guarded, and the pool's conditions).
- [x] kernel-check at 47a6fa6 on 7.3.4-200.fc44: 21 pass, 0 fail, 2 skip. l2-announce-live: the other namespace's kernel
      holds a0's MAC REACHABLE for 192.0.2.240 and 2001:db8:30::f0 (1 ARP reply, 1 NA), 192.0.2.241 unresolved, no host
      address added. (First run failed on the fixture's sysfs ifindex read, #476.)
- [x] Stage requested (build bef7524486e3); `shipped` with proof: Lease kube-system/flowsdn-lb-ipam has a holder. Shape posted on
      stormcos#385 (pool + policy, `loadBalancerIPs: true`), which edge-lb's address needs. Comment on #475 says what was verified.

### spec 21 stub marker — #445 (P0), 2026-11-19

- [x] §2 exempt list: `HTTPRouteParentRefPort` stated as absent, gap #474
  (matches `EXEMPT_FEATURES`). Line count unchanged.
- [x] sc-build at e83f833 passed (114s); marker grep clean; #445 closed.

### spec 20 stub markers — #444 (P0), 2026-11-19

- [x] F11 (fastetcd#129), double-write row (config validation message,
  #274), §10 per-cluster CT/NAT maps absent. Line counts unchanged (catalogue
  cites spec 20:1544–1586).
- [x] sc-build at 45db4ee (exit 0); marker grep finds nothing; #444 closed.

### spec 18 stub marker — #443 (P0), 2026-11-19

- [x] §11.3: no generated stub tests for unported cases (counted in the
  report instead); generator and §9.4 test absent, filed gap #473.
- [x] sc-build at b420922 (exit 0); marker grep finds nothing; #473 proposed; #443 closed.

### spec 16 stub markers — #442 (P0), 2026-11-19

- [x] §mutual auth: state the code's refusal (host_policy.rs skips the rule,
  `policy` problem, fails closed); mesh-auth flags absent; §4.7 auth map
  absent; file mutual-auth gap. ztunnel/ADS "unimplemented" wording. Keep
  line counts above spec 16:1500.
- [x] Filed and proposed #472; sc-build at eb67a4c (exit 0); #442 closed.

### spec 15 stub markers — #441 (P0), 2026-11-19

- [x] Scope list (BFD, TCP-AO, …) as out of scope; DelayOpen absent from the
  FSM; speaker runtime pieces name #293 (kinds #334, registration #337).
- [x] sc-build at 19e14a1 (exit 0); marker grep finds nothing; #441 closed.

### spec 13 stub marker — #440 (P0), 2026-11-19

- [x] §0 status: types/tests per group are #331–#336, registration and the
  readiness gate #337. Also correct spec 12/#471: the hash manifest exists
  (T-CRD-1); only its binding to SCHEMA_VERSION is the gap.
- [x] sc-build at e08647d (exit 0); marker grep finds nothing; #440 closed.

### spec 12 stub markers — #439 (P0), 2026-11-19

- [x] Schema version paragraph: hash-manifest check is a new gap (before
  #337 ships); label key is `io.flowsdn.…` in code. Metrics row: none until
  #420/#446. Keep line counts above spec 12:1493.
- [x] Filed and proposed #471; sc-build at d94e1fd (exit 0); #439 closed.

### spec 11 stub markers — #438 (P0), 2026-11-19

- [x] §11 config row (line 2548, a catalogue provenance line: keep it one
  line with the option names): PacketDrop emitter absent, new gap; §11
  ring note and §12.3: no stub wording.
- [x] Filed and proposed #470; sc-build at eb983a1 (exit 0); #438 closed.

### spec 10 stub markers — #437 (P0), 2026-11-19

- [x] §3.4 neighbor management: no code; file gap (managed neighbors + probe),
  state the no-fallback deviation (#132) plainly. §3.7 item 12 MKE net_cls:
  out of scope (cgroup v2 only). Batch 6 "unimplemented" wording. Keep line
  counts above spec 10:1382 (catalogue provenance).
- [x] Filed and proposed #469; sc-build at 9b805c1 (exit 0); #437 closed.

### spec 09 stub markers — #436 (P0), 2026-11-19

- [x] GC verb: state #125's resolution (code 1 `plugin version does not allow
  GC`, no mutation, as the reference; runtime.rs) in §2 table, §3.7, §12.3.
- [x] sc-build at 4af4db0 (exit 0); marker grep finds nothing; #436 closed.

### spec 07 stub markers — #434 (P0), 2026-11-19

- [x] Reword the four markers (and §3.10's "unimplemented"): v1.19 ENI is out
  of scope (deviation, not a gap); Azure CreateInterface/ReleaseIPs and
  Alibaba AllocateStaticIP are specified as errors the provider returns.
  Cloud providers themselves are #293/#446. Keep line counts (catalogue
  cites 07-ipam.md:1273).
- [x] sc-build at 33411fb (exit 0); marker grep finds nothing; #434 closed.

### spec 08 stub marker — #435 (P0), 2026-11-19

- [x] Spec 08 / ADR-0012 #118: routes not built are absent (404, as the agent
  already answers), not registered 501s (owner, stormcentral#1455); file gaps
  for the prefilter routes and for cgroup-dump-metadata / map events. Keep
  line counts above spec 08:1338 (catalogue provenance).
- [x] Filed and proposed #467/#468; sc-build at c0f990b (exit 0); #435 closed.

### spec 05 stub marker — #433 (P0), 2026-11-19

- [x] §3 Maglev amendment: socket-LB Maglev is gap #453; external ClusterIP
  access (with its Maglev) filed as a new gap; spec names both.
- [x] Filed and proposed #465; first edit added a line and broke the
  catalogue provenance test (#466, the #358 line-number fragility); kept
  the original line count. sc-build at 151b0b9 (exit 0); #433 closed.

### spec 02 stub marker — #432 (P0), 2026-11-19

- [x] Remove `flowsdn_encryption::ObjectBuild` (unused; names Cargo features
  `debug-events`/`test-hooks` that flowsdn-bpf does not have); spec 02 item 11
  states the #63 decision as design with the build as a new gap issue.
- [x] Filed and proposed #464; sc-build at 59e8fff (exit 0); marker grep
  finds nothing; #432 closed. Next: queued P0 stub issues #433–#445.

### runtime.md stub markers — #430 (P0), 2026-11-19

- [x] docs/runtime.md socket-LB and Pod-policy limit lists: each limit names
  its gap issue (existing #336/#392/#447/#448/#450/#452/#453; new ones filed
  and proposed for SCTP, non-first IPv4 fragments, topology hints, BPF
  masquerade, Pod audit mode, flows open before a policy, related ICMP errors).
- [x] Filed and proposed #457–#463; sc-build at 96a2bd7 (exit 0); marker
  grep finds nothing; #430 closed.

### spec 01 stub marker — #431 (P0), 2026-11-19

- [x] tcx/cgroup-link-only attach stated as the 6.6-minimum design (as #426);
  not a gap.
- [x] sc-build at 5703f88 (exit 0); marker grep finds nothing; #431 closed.

### 0.7.0 release-notes stub markers — #429 (P0), 2026-11-19

- [x] docs/releases/0.7.0.md: health and script paragraphs as history; filed
  and proposed #456 (health probe scheduling/history); adapters are #455.
- [x] sc-build at 382d8d4 (exit 0); marker grep finds nothing; #429 closed.

### 0.2.0 release-notes stub marker — #427 (P0), 2026-11-19

- [x] docs/releases/0.2.0.md says what that release lacked and what arrived
  later; filed and proposed #455 (scripttest subsystem command adapters).
- [x] sc-build at 040098b (exit 0); marker grep finds nothing; #427 closed.

### 0.4.0 release-notes stub marker — #428 (P0), 2026-11-19

- [x] docs/releases/0.4.0.md says what that release lacked and where each part
  arrived (0.5.0, 0.7.0, 0.9.0/0.10.0, main after 0.14.0). History, not a gap.
- [x] sc-build at a49f1ae (exit 0); marker grep finds nothing; #428 closed.

### kernel-requirements stub marker — #426 (P0), 2026-11-19

- [x] Pod-attach row: tcx-only is the accepted 6.6 minimum (legacy clsact
  cleanup-only, kernels without tcx refused), stated as such; not a gap.
- [x] sc-build at d22d813 (exit 0); marker grep finds nothing; #426 closed.

### implementation-status stub markers — #425 (P0), 2026-11-19

- [x] "Not implemented: …" list replaced by open gap issues; filed and proposed
  #451 (node/group peers), #452 (policy verdict events), #453 (Maglev in
  socket LB), #454 (RFC 6052 gateway); `gap` label on #332. 0.3.0 history
  line now says when streams/initialization/pruning arrived. Docs only.
- [x] sc-build at 5f91ec6 (exit 0); marker grep finds nothing; #425 closed.

### README stub markers — #424 (P0), 2026-11-19

- [x] README intro and "Not implemented in the agent" list replaced by open gap
  issues; filed #449 (DSR ICMP errors), #450 (NAT46/64 local/socket LB);
  `gap` label on #384, #392, #337, #293. CRD paragraph corrected (the agent
  writes FlowsdnIdentity, reads the policy kinds). Docs only: no image.
- [x] sc-build at ac2d6f1 (exit 0); marker grep finds nothing in README.md; #424 closed.

### CLAUDE.md stub marker — #423 (P0), 2026-11-19

- [x] Unbuilt list in CLAUDE.md replaced by open gap issues; filed and
  proposed #446 (operator executable), #447 (DSR IPIP/Geneve), #448
  (L7/FQDN/ICMP policy). Docs only: no image.
- [x] sc-build at c70dec4: the marker grep finds nothing in CLAUDE.md; #423 closed.

### Network-level metrics — #420 (P2), 2026-11-18

stormcos#64 scrapes every level with the node's ironprom; a flowsdn node served
nothing for the network level.
- [x] Agent `metrics-listen` (loopback `IP:port`, not the `http-listen` one;
  manifests `127.0.0.1:9962`): `GET /metrics`, Prometheus text 0.0.4,
  `flowsdn_*` names, from live state on each scrape (series in
  `docs/agent-api.md#metrics`). Policy map pressure walks the keys per scrape.
- [x] Unit tests: exposition well-formed and values from fixtures, failures
  reported as `flowsdn_metrics_source_failing` (no zeros), config validation,
  both shipped configs set 9962. Docs (agent-api, runtime, README, deploy
  README, implementation-status), changelog.
- Follow-ups: other drop reasons need datapath counters (#421); operator
  metrics wait for an operator executable (#337); ironprom job and
  check-metrics rows are stormcos#1045.
- [x] sc-build `cargo xtask check` passed at f7097dc (fmt, Clippy -D warnings,
  workspace tests incl. `api::metrics::tests::*`); the 1a611f4 fmt failure
  (#422) closed itself. Stage requested (build dca023a7d325).

### No stubs — #418, 2026-11-18

Owner: "lets get rid of stubs please" … "stubs are lies".
- [x] Health API: rows computed from the agent's live state (API/endpoint count, restore, Kubernetes controller sync and errors, policy maps), refreshed once a second and on each health request; transitions logged (`health agent.<scope> <Level>: …`). Hardcoded `controllers` row gone.
- [x] Promises removed: bpf-loader README/kernel.rs (pinned ABI mismatch refuses startup, never replaced), scripttest README (`db/cmp`), flowsdn-table doc (metrics).
- [x] Refusals reworded; endpoint PUT labels/datapath-configuration/properties 400 (was 501); 404 "no such API route".
- [x] sc-build at 2ba23b6: `cargo xtask check` passed (fmt, Clippy -D warnings, all-features workspace tests incl. `rows_follow_the_live_state_and_change_only_when_it_does`). the stub-wording grep over crates empty outside tests.
- [x] Stage requested (build 9c1dd348152c); `shipped` with proof `log:health agent\.(api|kubernetes) OK`.

### Selector peers before the identity list — #401, 2026-11-13
- Behaviour kept: fail closed (the issue's recommendation; allowing a selected
  peer needs an identity number the datapath can match). stormcos#303 (apply
  `crds/`) is the real fix for a node that never serves the CRD.
- Done: `policy::compile` reports a problem naming the policies with selector
  peers while identity allocation is on and `identities_synced` is false; it
  reaches `/v1/healthz` through the policy loop's `errors["policy"]`. Unit test
  added; docs/runtime.md updated.
- [x] sc-build at 763ce9a: `cargo xtask check` passed (fmt, Clippy -D warnings,
  workspace tests all features); `policy::` tests 25 passed incl. the new one.
  Stage 47c384afb5c5 requested. `shipped` with proof: the node's apiserver lists
  `flowsdn.io/v1alpha1` FlowsdnIdentity (the condition that ends the window).

### Runtime FEC monitor and cable hotplug — #409 (P0), 2026-11-13

Owner: watch every port's FEC and link for the node's whole life, set FEC live from the speed -> FEC table when a port is down or wrong,
and bring a re-plugged cable up with no reboot (forge1 ConnectX-4 Lx, 25G on dsw1).
Found: no speed -> FEC table exists. stormbootx reads one `fec_pin = rs` from the boot media (`config.rs` `stated_fec_pin`), and
the running node does not read it. stormpump already gives a port that gets carrier later its address (docs/network.md, #75).
Owner decision posted (comment 6868716919: A boot-media conf / B one stormcos setting written to both / C flowsdn only; recommended B);
`wait-owner` set. No code yet.

- [x] Question with recommendation on #409; wait-owner.
- [x] Owner answered 2026-11-13: B, one stormcos node setting written to both (stormcos#958 delivers it). Correction the same day:
      the trigger is **module presence** (SFP/QSFP insert), the key is the **module's EEPROM class** (SFF-8024 compliance, e.g.
      25GBASE-CR CA-L/CA-S/CA-N, SR) plus configured speed, never the negotiated speed; no table answer -> walk RS, BaseR, off.
- [ ] Blocked 2026-11-13 on stormcos#958 (needs-owner): who writes FEC at runtime, stormpump on every node (A, recommended:
      forge1 is a cilium node, stormpump owns host ports and the console) or flowsdn (B). Under A flowsdn only reads and reports
      (module class, configured/active FEC, link; FEC get ioctl already on `wip/408-uplinks`); under B flowsdn also writes.
      The module-class -> FEC setting's format is stormcos's to define there too. Moved `--after stormcos#958`.
- [ ] (superseded by the correction above) On the answer: file the stormcentral/stormcos (setting) and stormbootx (per-speed lookup) halves, then the flowsdn monitor:
      netlink link watch, ethtool-netlink FEC get/set, fix only on a sustained down/mismatch (never one sample), table looked up by
      the port's highest supported speed, per-port speed/FEC (configured, active)/link in network status. Re-join waits on #408.

### Both NICs on a node — #408 (P1), 2026-11-13

Owner: load balance and combined throughput of two ports, discovered and not hard-coded (forge1 2x25G, no switch config).
flowsdn does not own host ports: stormpump bridges the boot port (`stormbr0`, .203) and DHCPs the second (.204).
Two designs (A: stormpump balance-alb bond, one address; B: flowsdn ECMP over the per-port addresses + failover /32 + GARP).
Owner decision posted (comment 6868495074, recommended B); `wait-owner` set. No code yet.

- [x] Question with recommendation on #408; wait-owner.
- [x] Owner answered 2026-11-13: **B, routed, two addresses** (each port keeps its address, flowsdn spreads flows, a port's address
      moves to the live port when its link drops).
- [x] Filed the other halves: stormpump#234 (tolerate the failover /32), rustkube-node#366 (publish both InternalIPs),
      stormblock#596 (NVMe/TCP multipath, one connection per address).
- [x] 2026-11-14 resumed on `wip/408-uplinks`: monitor (`uplinks_monitor.rs`), kernel side (`uplinks_apply.rs`, shared with
      the `uplinks-live` kernel fixture), ECMP direct routes, NodePort/host firewall on every uplink, `kubernetes.uplinks`,
      `GET /v1/uplinks`, docs. Build-failure issues #410-#412 are this branch's intermediate runs.
- [x] uplinks-live kernel fixture (two veth uplinks, the agent's own discovery/plan/kernel code): found two bugs on the way
      (sysfs is per mount, so the fixture mounts its own; table deletes used scope universe so scope-link subnet routes stayed).
- [x] Merged to main at 8480160. sc-build there: `cargo xtask check` (fmt, workspace Clippy -D warnings, 901 tests, 0 failed,
      1 ignored, musl x86_64 + aarch64) and kernel-check medium on 7.2.11: 20 pass, 0 fail, 2 skip (uplinks-live: 64 flows over
      both ports, each address on its port, u1 down -> flows on u0 + .204/32 on u0 with GARP, u1 back -> /32 removed; twice; single
      cleans up).
- [x] Stage a522a71052f0 requested at 1da24f3; `shipped` with proof: an `UplinkJoined` Event "... 2 of 2 carrying" in `default`
      (a test machine with two ports on its subnet). Comment on #408 says what was verified. The done-when on forge1 needs forge1
      on the flowsdn flavour (cilium node today, stormcos#958) and a cable pull; peers' second InternalIP is rustkube-node#366.
- (history) Paused 2026-11-13 for P0 #409. WIP on branch `wip/408-uplinks` (not built yet): `flowsdn-connector/src/multihome.rs`
  (ECMP route, rules, address delete, GARP, FEC ioctl) and `flowsdn-agent/src/uplinks.rs` (+ tests: settings, select,
  moves, nexthops, desired rules/tables, view JSON). Next: `uplinks_monitor.rs` (500 ms carrier tick, one address dump,
  moves + GARP x3, state file `uplink-moves.json`, sysctls fib_multipath_hash_policy/ignore_routes_with_linkdown/
  arp_ignore/arp_announce/rp_filter/ndisc_notify on uplinks, rules/tables reconcile on change + 30 s); `DesiredRoute.gateways`
  + route thread uses `View::hops` (reconcile on uplink generation); NodePort attach on uplink names; `kubernetes.uplinks`
  setting; `GET /v1/uplinks` + healthz summary; docs; sc-build.
- [ ] flowsdn side (in progress): uplink set = every port holding a node address, discovered from the kernel (not the config);
      a continuous netlink link monitor (join/leave logged with a timestamp); per-flow ECMP (L4 hash) for remote pod CIDRs over the
      live ports; uplink programs on every port; failover /32 + gratuitous ARP on a live port while a port is down, removed on return;
      `uplinks` setting (policy active-active|active-backup, weights); per-port link/speed/FEC/bytes in network status.

- [x] 2026-11-26: reopened by stormcentral because the proof (`UplinkJoined` … `2 of 2 carrying`) was checked on
      pvetest1, which has one port (eth0 in stormbr0), so it can't match there. Re-shipped with
      `on C2NR0Q2 api:/api/v1/namespaces/default/events ~ …; 2 of 2 carrying`, `--commit 8480160`, per #417 (the Dell's two
      25G ports). No code change. The cable pulls follow C2NR0Q2's flowsdn install (stormblock#603).
### Agent EAGAIN on a just-joined worker — #404 (P1), 2026-11-10

Paired test 1439e5f1ee (12.74.7-flowsdn): storm-003102 joined as worker; its agent printed the pod CIDRs, then `Error: EAGAIN`,
CrashLoopBackOff. Cause in code: the next step, `Store::open`, takes `<state-dir>/agent.lock` with a non-blocking flock; EWOULDBLOCK
(= EAGAIN) came back bare. So another agent held /var/lib/flowsdn: the node's former SNO agent, invisible to the new apiserver,
never stopped. Fix here: wait for the lock (log the holder at once and every 30 s), holder line in agent.lock (POD_NAME/POD_NAMESPACE
env, pid, since, cgroup), context on state errors. The leftover SNO agent itself belongs to the join (stormcluster / rustkube-node): filed there.

- [x] Code + tests, manifests/chart env, docs (runtime, deploy README, agent README, spec 22 note), changelog (d8ccb24, fmt 73f085e).
- [x] sc-build at 73f085e: fmt, workspace + kubernetes Clippy -D warnings (+ indexing, arithmetic), workspace + kubernetes agent tests
      (0 failed, 1 ignored) incl. the two new state tests, chart-check. kernel-check there on 7.2.11: 19 pass, 0 fail, 2 skip.
- [x] Leftover SNO agent filed as stormcluster#112 (P1; rustkube-node SIGKILLs after grace, so the SNO pod was never stopped).
      Stage 132e928ffd1c requested; #404 closed. The paired join still needs stormcluster#112; the agent's log now names the holder.

### Host firewall in audit in the shipped config — #402 (P1), 2026-11-10

stormfw (stormcos#877) renders HostFirewallPolicy into a FlowsdnClusterwideNetworkPolicy; with `host-firewall: off`
nothing is counted, so audit -> enforce has no data. Set `kubernetes.host-firewall: audit` in
`manifests-kubernetes/61-flowsdn-config.yaml` (the set the golden carries; the static set has no `kubernetes`).
Blocker found: stormcos#303 (CRDs) is open, and the policy thread waits for the FCNP list whenever the host firewall
is on, so NetworkPolicy would stall. Fix first: only `flowsdn-policy` waits for that list; until it is listed the host
endpoint has no rules (flags 0, as while learning), so nothing is dropped. Gate moved to `View::policy_lists_ready` with tests.

- [x] Gate + tests; config; docs (runtime, deploy README, ADR-0022, README, implementation-status), changelog (59ea545).
- [x] sc-build at 72e03f9 (fmt fix for #403): fmt, workspace + kubernetes Clippy -D warnings, 953 tests (0 failed, 1 ignored)
      incl. the two new ones, chart-check. kernel-check at 72e03f9 on 7.2.11: 19 pass, 0 fail, 2 skip (host firewall audit step PASS).
- [x] Stage b4dc877d5d46 requested; #402 closed. On a node: `kubernetes.policy.host-firewall.mode` audit in /v1/healthz, comes with a release.

### Agent start log — #397, 2026-11-06

stormcos#804 fix 16. Timestamps on every agent line (health_api's gmtime_r + ms), a `ready` line with time since start, a 404 retried at 1 s flat for a watch's first minute, a line when a watch recovers. Late identities: isolation does not wait for them, but `podSelector` peers allow nothing until the list succeeds (policy.rs peers(); #401). Fixes #373's time_t warning on the way (the stamp reuses that code).

- [x] Code + tests, docs, changelog (cd1ab4c, fmt e6719bb). sc-build at e6719bb: fmt, Clippy x2 (+ indexing, arithmetic), 852 + 97 tests. kernel-check there: 19 pass, 0 fail, 2 skip, musl build under -D warnings; ready 62-122 ms in six lab agents (no Kubernetes).
- [x] Loopback test at 4ef892c: identities 404 until 8 s, one 404 line, `listed` at 8.4 s; fmt, kubernetes Clippy, test passes.
- [ ] Stage; node numbers (Kubernetes mode, real CRD) come with a release.

### CNI ADD timing — #396, 2026-11-06

stormcos#804: warm plain-pod ADD 130 ms (85 on the previous release, busier host) against Cilium's 76 ms; target < 50 ms on a VM, < 100 ms on an HDD server. Issue's guess: object load per endpoint. Code says not (one object per agent; tcx attach per veth). First suspect: 4 fsyncs per endpoint in the agent's state store on a disk-backed /var/lib/flowsdn. Measure first.
Plan: plugin times its steps and POSTs them; agent times PUT's steps; `GET /v1/cni/timing` gives p50/p99 by step; medium test `cni-add-timing` (warm ADDs, state on a real ext4 disk in kernel-check, which boots with a virtio disk). Then cut the largest.

- [x] Timing, test, kernel-check numbers. Before, on ext4 in kernel-check (p50 us): total 124970: endpoint 55908 (agent-state 34292, agent-install 12044), lookup 20489, allocate 19911, config 17635, link 10623. The issue's object-load guess is wrong (one load per agent).
- [x] Largest: the API loop's `sleep(20 ms)`, about 58 ms over the three trivial requests, plus up to 9 in the PUT. Polls now: total 66-76 ms. Then state syncs contents only: at 7079995, two runs alone: total 45346 / 46136, wall 48035 / 48175, agent-state 19607 / 17622 at fsync 22184 / 24641. The same commit beside my full build: agent-state 106 ms, so never compare across a parallel build.
- [x] Docs (agent-api, spec 08 note, test README, build-and-test), changelog. #399 was my fake agent refusing the report (closed by a pass). #400 filed: stale <id>_next can stop ADDs.
- [ ] Node number (kubelet sandbox/cni in stormcos docs/SPEED.md) with a release; bursts unmeasured.

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
- [x] 2026-11-25: stormcentral#1163 done: `flowsdn-aya-kfunc-watch` runs `pinned release main` every 168 h (exit 3
      files the P1 switch issue); its first run (job 205a34271f) exited 0. No aya, aya-ebpf or bpf-linker release since
      11-03. Added a `pr:<number>` source (informational, never exit 3). Watch at 63731a9 with `pr:1495` (aya-rs/aya#1495,
      open: extern-symbol kfunc resolution against vmlinux BTF, for struct_ops): missing everywhere; 0.14.0
      `UnknownFunction`, 0.16.0 / main 2756d04 / #1495 head 885c7fc `ExternNotFound` with bpf-linker 0.11.1 and 0.13.0.
      #315 stays open for the switch (owner decision #3 covers the wait).
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

