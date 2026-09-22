# Go unit-test port plan

Status: draft, 2026-09-07. Derived from a survey of cilium/cilium **v1.20.1**,
commit **7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc** (Apache-2.0). Governed by
[ADR-0005](decisions/0005-test-strategy.md) — *harvest the data, write every
harness in Rust*. Areas and their scope decisions come from
[`docs/inventory/README.md`](inventory/README.md).

Companion deliverables produced with this plan:
`tests/golden/` (1,196 harvested data fixtures) and
`tests/fuzz/SEEDS.md` (the 19 fuzz targets).

**Amendments.** 2026-09-07 — §3 area 03 and §6 open question 2 updated: the
2,592-line iptables/ipset coverage gap is closed by
`docs/spec/10-node-routing-nftables.md` §9.1, written before the nftables code
as this plan required.

---

## 1. The measurements

The source counts immediately below are measurements of the pinned reference.
The later planning factors and extrapolated totals are explicitly separate.
The commands allow the source survey to be repeated at a newer tag.

```
$ grep -rhoE '^func Test[A-Za-z0-9_]*\(' --include='*_test.go' pkg daemon operator | wc -l
3040
$ find pkg daemon operator -name '*_test.go' | xargs wc -l | tail -1
272416 total
```

Widening to every non-vendor Go root the plan covers — adding `cilium-dbg/`,
`bugtool/`, `clustermesh-apiserver/`, `tools/`, `test/` and `api/`:

| Measure | Count |
|---|---:|
| `_test.go` files (non-vendor) | 892 |
| Packages containing tests | 385 |
| `func Test*` in `pkg/`, `daemon/`, `operator/` | 3,040 |
| `func Test*` across all covered roots | **3,080** |
| Test lines in `pkg/`, `daemon/`, `operator/` | 272,416 |
| Test lines across all covered roots | **275,545** |
| `func Benchmark*` | 212 |
| `func TestPrivileged*` (need root / a kernel) | **230**, in 53 packages |
| Files whose shape is table-driven (`[]struct` table or `for _, tt := range`) | 348 of 892 |
| `func Fuzz*` | 19, in 9 packages |
| `testdata` / `golden` / `fixtures` directories (non-vendor) | 44 |
| `.txtar` scenario files | 168, in 29 directories |

Two figures worth holding onto: **230 of the 3,080 tests need a kernel**, so
7.5% of the corpus can only run in a privileged CI lane; and **348 of 892 test
files are table-driven**, which is the reason `harvest` is a real disposition
and not wishful thinking.

### Dispositions

| Disposition | Meaning | Go test lines | Share |
|---|---|---:|---:|
| **port** | Rewrite the cases in Rust against flowsdn's equivalent code. The behaviour is flowsdn's behaviour. | 188,730 | 68.5% |
| **harvest** | The test is table-driven or golden-file based. The data moves (to `tests/golden/` or `tests/scripttest/`); only the runner is rewritten. | 31,557 | 11.5% |
| **replace** | The reference tests an implementation detail flowsdn does not have — Hive cells, StateDB internals, iptables rule generation, `ebpf-go` loading, Go concurrency primitives. flowsdn writes its own tests for its own design; the *property* survives, the *test* does not. | 22,161 | 8.0% |
| **drop** | Tests a deferred or dropped feature, with a named decision. | 14,129 | 5.1% |
| _long tail_ | 176 packages under 245 test lines each, mixed disposition, rolled up per area. | 18,968 | 6.9% |
| | | **275,545** | 100% |

### Measured port ratios and conditional planning model

The former ×0.45 port factor is withdrawn. The earlier claim that a faithful
Rust port of the policy suite had measured about 9,500 lines was unsupported;
that policy port is not complete and provides no calibration observation.

The completed Maglev and CIDRset unit-test ports provide two actual observations
(§6.5 records the case mapping and Linux validation):

| Port | Rust test code lines | Static fixture lines | Pinned Go test lines | Code ratio | Code plus data ratio |
|---|---:|---:|---:|---:|---:|
| Maglev | 123 | 3 | 249 | 0.494 | 0.506 |
| CIDRset | 193 | 55 | 764 | 0.253 | 0.325 |
| Combined | **316** | **58** | **1013** | **316/1013 = 0.312** | **374/1013 = 0.369** |

These are physical-line ratios for two algorithmic test ports, not engineering
hours, a representative project sample, or a confidence interval. The Go Maglev
denominator includes a benchmark/harness that was not ported. Fixture formatting
also affects the count. Do not use these ratios to assert a measured total for
policy, controllers, networking integration, or the project as a whole.

For sensitivity analysis only, retain the following explicit planning inputs:

| Disposition | Conditional factor | Evidence or assumption |
|---|---:|---|
| port | 316/1013 code-only; 374/1013 including static data | Measured on the two ports above; applying either to other packages is an **unvalidated extrapolation**. |
| harvest | ×0.10 | Unvalidated historical runner-size assumption. |
| replace | ×0.35 | Unvalidated historical replacement-suite assumption. |
| drop | ×0 | No test port in this disposition; no statement about implementation work. |
| long tail | ×0.35 | Unvalidated historical blended assumption. |

Using the disposition counts above, the arithmetic is reproducible:

- Conditional port component: `188730 × 316 / 1013 = 58873.327` code lines,
  or `188730 × 374 / 1013 = 69679.191` lines including static data.
- Other modeled components: `31557 × 0.10 + 22161 × 0.35 + 18968 × 0.35
  = 17550.850` lines; these factors have not been calibrated.
- Conditional totals, rounded only after summation: **76,424 code-only** or
  **87,230 with the port component's static data included**. The latter is not
  a complete fixture inventory: other disposition factors remain unchanged.

These totals replace the old aggregate calculation as labeled planning
scenarios, not validated effort estimates. No per-area redistribution is
supported by this two-module sample. Broader calibration must measure actual
completed ports before changing that conclusion.

The model also excludes, deliberately:

- the **168 txtar scenarios** (`tests/scripttest/`, sibling agent) — running
  them is harness work, not per-test work;
- the **397 `CHECK` cases** in `bpf/tests` (`flowsdn-bpftest`, sibling agent);
- `flowsdn-cptest` and `flowsdn-connectivity`, both specified by ADR-0005 §3.

### Reference counts and withdrawn historical area estimates

Reference counts below remain the original survey. The last column is retained
only to identify the withdrawn historical allocation; it must not be used as a
current estimate or summed into the conditional scenarios above.

| Area | Packages | `Test*` | Go test lines | Historical Rust-line allocation (**withdrawn**) |
|---|---:|---:|---:|---:|
| 01 BPF datapath programs | 0 | 0 | 0 | 0 (owned by `flowsdn-bpftest`) |
| 02 BPF maps + loader | 20 | 122 | 9,935 | 3,700 |
| 03 Datapath userspace + node | 37 | 210 | 17,884 | 6,400 |
| 04 Load balancer | 14 | 119 | 11,628 | 5,000 |
| 05 Policy + identity | 30 | 401 | 40,875 | 18,000 |
| 06 Agent core, endpoints, API | 85 | 549 | 34,156 | 13,500 |
| 07 IPAM incl. cloud | 30 | 256 | 19,674 | 8,500 |
| 08 Operator | 35 | 394 | 37,301 | 7,600 |
| 09 Hubble + monitor | 48 | 293 | 29,581 | 12,900 |
| 10 BGP | 7 | 38 | 10,247 | 4,500 |
| 11 L7 proxy, DNS, auth, mesh | 27 | 387 | 29,659 | 9,700 |
| 12 ClusterMesh + kvstore | 19 | 125 | 12,986 | 4,100 |
| 13 CRDs + k8s integration | 16 | 127 | 15,134 | 6,100 |
| 14 Encryption + egress | 9 | 48 | 5,862 | 2,400 |
| 15 Helm, images, CI, tests | 8 | 11 | 623 | 200 |
| **Total** | **385** | **3,080** | **275,545** | **~102,600** |

The old ~102,600-line allocation and its inferred “third of the work” claim
are withdrawn. Test LOC cannot establish engineering effort or reconcile the
inventory's implementation-size estimate. The reference scope and required
test behaviors remain unchanged; this calibration does not authorize scope cuts.

---

## 2. Per-area plan

Each table lists every package in the area with at least 245 test lines,
individually; smaller packages are rolled up. Reference counts are exact for
the pinned survey. Any effort figures in these historical area descriptions
are withdrawn planning allocations as explained in §1, not calibrated results.


### Area 01 — BPF datapath programs

Inventory: [`docs/inventory/01-bpf-programs.md`](inventory/01-bpf-programs.md) · Spec: docs/spec/02-datapath-programs.md

**No Go test package maps to this area.** The reference's datapath programs
are C, and their tests are the 141 C files / 397 `CHECK` cases under `bpf/tests`,
which a sibling agent owns under ADR-0005 §3 (`flowsdn-bpftest`). The Go
packages that *drive* those programs are counted under area 02 (loader, maps)
and area 03 (attachment, devices). Nothing in this port plan covers area 01;
the `bpf/tests` checklist is the deliverable there.

Effort here is therefore **0 lines of ported Go test**, and separately a
**397-case checklist** owned by `flowsdn-bpftest`.

### Area 02 — BPF maps + loader

Inventory: [`docs/inventory/02-bpf-maps-loader.md`](inventory/02-bpf-maps-loader.md) · Spec: docs/spec/01-bpf-map-abi-loader.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/datapath/loader` | 37 | 3,931 | Object cache keyed by config hash; ELF template hashing; TC/TCX attach, upgrade, downgrade, stale-filter cleanup; XDP attach permutations; tunnel/IPIP/host device setup; verifier run. 26 of 37 are TestPrivileged*. | **replace** |
| `pkg/bpf` | 33 | 1,926 | Map create/open/pin/unpin/recreate, upgrade-in-place, batch iterator, reliable dump with callback under concurrent mutation, per-CPU dump, event subscribe, unused-map and unused-tailcall elimination. 23 of 33 privileged. | **replace** |
| `pkg/maps/ctmap` | 10 | 1,329 | CT map key encoding and MaxEntries sizing; GC for ICMP/TCP/DSR flows; orphan-NAT GC; per-cluster CT map create/lookup/cleanup; network-ID handling; entry counting. Almost all privileged. | **port** |
| `pkg/bpf/analyze` | 15 | 677 | Static analysis of a loaded ELF to find unreachable tail calls and unused maps. | **replace** |
| `pkg/maps/ctmap/gc` | 4 | 332 | CT GC driver: interval computation, batch sizing, deletion accounting. | **port** |
| `pkg/maps/nat` | 4 | 271 | NAT map batch dump (v4), per-cluster NAT map lifecycle, NAT flush semantics. | **port** |
| _14 further packages in this area_ | 19 | 1,469 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **122** | **9,935** | | |

**Effort: ~3,700 Rust test lines.** (port 3pkg/1,932; replace 3pkg/6,534; tail 1,469)

`pkg/datapath/loader` and `pkg/bpf` are the two largest packages here and
both are **replace**: they test cilium's own ELF-template/`ebpf-go` loading
strategy, and flowsdn loads with `aya` against programs it compiled itself
(ADR-0002). The *properties* survive — attach/detach idempotence, TCX-vs-TC
upgrade and downgrade, stale-filter cleanup, XDP attach over an existing link,
reliable dump under concurrent mutation, unused-map elimination — and each one
should become a flowsdn test, but the reference's assertions are about
structures flowsdn does not have.

The **port** rows are the ABI ones: `pkg/maps/ctmap` and `pkg/maps/nat` pin the
key/value byte layouts and the GC semantics that `docs/spec/04-conntrack-nat.md`
declares byte-compatible. Those tests must be ported case for case.

`pkg/alignchecker` (128 lines) checks Go struct offsets against a compiled BPF
object's BTF. flowsdn needs the equivalent — `#[repr(C)]` offsets against the
`aya-ebpf` object's BTF — but written against its own object, so **replace**,
and it belongs in CI as a build gate rather than a unit test.

### Area 03 — Datapath userspace + node

Inventory: [`docs/inventory/03-datapath-userspace-node.md`](inventory/03-datapath-userspace-node.md) · Spec: docs/spec/10-node-routing-nftables.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/node/manager` | 15 | 2,039 | Node lifecycle add/update/delete across multiple sources with precedence; node labels; ipcache entries derived from nodes incl. health IP; node encryption key propagation; cluster-size-dependent resync interval; background sync; startup pruning of stale nodes; ipset membership. | **port** |
| `pkg/datapath/iptables` | 19 | 1,908 | iptables/ip6tables rule text generation, custom-chain rename, proxy rules, masquerade command sets, no-track rules, ipset NAT commands, reconciliation loop. | **drop** |
| `pkg/datapath/linux` | 18 | 1,845 | Node handler: route, neighbor, tunnel-endpoint and encryption updates on node add/update/delete; MTU changes; direct-routing device selection. | **port** |
| `pkg/datapath/tables` | 12 | 1,514 | Node-address derivation from the device/address tables: which addresses are node addresses, whitelist filtering, loopback and host-device handling, sort order, fallback addresses, updates on IP change. | **replace** |
| `pkg/datapath/connector` | 8 | 1,407 | veth pair and netkit setup, naming, MTU, sysctls, peer index resolution, IP configuration inside the netns. | **port** |
| `pkg/datapath/sockets` | 7 | 741 | Socket destroy/lookup via sock_diag for NAT and service-backend termination; filter matching. | **port** |
| `pkg/datapath/linux/config` | 11 | 727 | Datapath config header/constant emission: which value each config key produces for lxc, host and overlay programs. | **port** |
| `pkg/datapath/iptables/ipset` | 6 | 684 | ipset create/add/remove/list and the reconciliation loop over them. | **drop** |
| `pkg/datapath/l2responder` | 9 | 673 | L2 responder map reconciliation from the L2-announce table: which (IP, ifindex) pairs are programmed and when they are withdrawn. | **port** |
| `pkg/datapath/linux/route` | 7 | 576 | Route add/replace/delete via netlink, route equality, table selection, MTU and proto fields, IPv6 handling. | **port** |
| `pkg/cgroups/manager` | 5 | 510 | cgroup path resolution for pods/containers across cgroup v1/v2 and runtimes; cgroup ID lookup. | **port** |
| `pkg/datapath/linux/routing` | 7 | 501 | Per-ENI/per-interface routing rule + table installation and teardown, priority and mark selection. | **port** |
| `pkg/datapath/linux/bandwidth` | 4 | 484 | Bandwidth manager: EDT/fq setup on devices, per-endpoint rate to throttle-map value. | **port** |
| `pkg/datapath/linux/probes` | 27 | 416 | Kernel feature probes: which helper/map/prog types are available and the resulting feature flags. 27 tests, mostly privileged. | **replace** |
| `pkg/node/sync` | 3 | 367 | Local node <-> k8s Node/CiliumNode field synchronisation and conflict handling. | **port** |
| `pkg/node` | 3 | 318 | Local node address selection: internal/external IPv4/IPv6, router IP, cilium_host IP. | **port** |
| `pkg/nodediscovery` | 2 | 302 | Node discovery: what the agent publishes into CiliumNode on start and on address change. | **port** |
| `pkg/node/types` | 6 | 286 | Node type conversion to/from CiliumNode and the kvstore node model; address list handling. | **port** |
| `pkg/datapath/linux/route/reconciler/scripttest` | 2 | 284 | Route reconciler scenarios expressed as txtar scripts. | **harvest** |
| `pkg/datapath/linux/sysctl` | 4 | 260 | sysctl read/write incl. per-device paths and the reconciling sysctl table. | **port** |
| `pkg/datapath/gneigh` | 3 | 257 | Gratuitous ARP/NA emission on address change. | **port** |
| _16 further packages in this area_ | 32 | 1,785 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **210** | **17,884** | | |

**Effort: ~6,400 Rust test lines.** (drop 2pkg/2,592; harvest 1pkg/284; port 16pkg/11,293; replace 2pkg/1,930; tail 1,785)

The two **drop** rows are ADR-0003: `pkg/datapath/iptables` (1,908 lines,
19 tests) and `pkg/datapath/iptables/ipset` (684 lines) test the exact text of
generated `iptables-restore` input and `ipset` commands. flowsdn emits nftables
over netlink, so there is no rule text to assert on. **This is the single
largest deliberate loss of coverage in the plan (2,592 Go test lines).** The
behaviours those tests protect — masquerade exclusion, no-track for host ports,
proxy redirect rules, encryption bypass, ordering against the reconciliation
loop — must be re-derived as nftables assertions in
`docs/spec/10-node-routing-nftables.md` §9. Do not treat "drop" here as "not
needed". **Done 2026-09-07**: that spec's §9.1 enumerates the 45 replacement
cases (N1–N45), marks each unit or netns, and tabulates which reference
assertions have no equivalent because BPF does the job.

`pkg/datapath/tables` is **replace** for ADR-0004 (no StateDB): the node-address
derivation rules are worth keeping exactly, but the test's shape is a StateDB
table observation.

`pkg/datapath/linux/probes` is **replace** because the probe set is a function
of the kernel floor, and flowsdn's floor is different
(`docs/kernel-requirements.md`).

### Area 04 — Load balancer

Inventory: [`docs/inventory/04-loadbalancer.md`](inventory/04-loadbalancer.md) · Spec: docs/spec/05-service-loadbalancing.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `operator/pkg/lbipam` | 43 | 3,621 | LB IPAM: allocation happy path, pool/range add/extend/shrink/disable/delete with pending services, conflict resolution between overlapping pools, sharing keys (same port, different protocols, cross-namespace, cross-cluster), requested IPs, IP-family requests, LB class matching, pool selectors incl. namespace selectors, allow-first-and-last-IP toggling, restart/re-alloc on init. | **port** |
| `pkg/loadbalancer/reconciler` | 3 | 2,118 | BPF ops: the exact map write/delete sequence the reconciler issues for service and backend changes, including ordering, orphan cleanup and socket termination on backend removal. Privileged. | **port** |
| `pkg/loadbalancer/writer` | 13 | 1,562 | Service/frontend/backend upsert-delete; conflicting sources; initializers; wildcard-address reconciler; backend health across sources; backend selection under trafficDistribution (PreferClose zone fallback, terminating-backend handling, missing zone hints, same-node preference). | **port** |
| `pkg/loadbalancer` | 22 | 1,416 | Service/frontend/backend key types: L3n4Addr equality, byte encoding, YAML/JSON forms and string forms; service flags encoding; NodePort range parsing; frontend lookup by tuple; backend listing by service name and address; proxy-redirect equality; forwarding-mode (hybrid DSR/SNAT) resolution; source-range enablement. | **port** |
| `pkg/l2announcer` | 18 | 1,193 | L2 announcement policy selection, lease/leader election, which (service, device, IP) tuples get announced, and withdrawal on policy or endpoint change. | **port** |
| `pkg/loadbalancer/tests` | 3 | 429 | 51 txtar scenarios covering the whole LB control plane end to end. | **harvest** |
| `pkg/act` | 5 | 329 | Active connection tracking counters per service/zone. | **port** |
| `pkg/maglev` | 4 | 249 | Maglev permutation generation, table reproducibility across runs, disruption bound on backend removal, weighted backends with removal. | **port** |
| `pkg/loadbalancer/healthserver` | 1 | 245 | 3 txtar scenarios for the per-service health HTTP server (kube-proxy compatible /healthz). | **harvest** |
| _5 further packages in this area_ | 7 | 466 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **119** | **11,628** | | |

**Effort: ~5,000 Rust test lines.** (harvest 2pkg/674; port 7pkg/10,488; tail 466)

`pkg/loadbalancer/tests` looks tiny at 429 Go lines but is the most
valuable row in the area: those 429 lines are a runner over **51 txtar
scenarios** that exercise the whole LB control plane. They are `tests/scripttest`
work, not Rust-test-writing work, which is why ADR-0005 calls the scripttest
harness "the single highest leverage item in the whole test plan".

`pkg/loadbalancer/reconciler` is 3 test functions over 2,118 lines because
`TestBPFOps` is one enormous table of (input change, expected map operations).
That table is the reconciler-ordering contract and must be ported literally —
it is where "the service is briefly wrong during an update" bugs live.

`pkg/maglev` is only 249 lines and 4 tests, and it is in the top 20 anyway:
`TestReproducible` and `TestBackendRemoval` are the entire cross-node
determinism guarantee.

### Area 05 — Policy + identity

Inventory: [`docs/inventory/05-policy-identity.md`](inventory/05-policy-identity.md) · Spec: docs/spec/06-policy-engine.md, docs/spec/03-identity-ipcache.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/policy` | 164 | 21,034 | The policy engine. mapstate (3463 lines): deny-preferred insert, LPM ancestors, broader/narrower key covering, subset keys with same identity, incremental AccumulateMapChanges (allow and deny), ordered-map validation. l4_filter (2748): L3/L4/L7 merge, wildcarding, TLS/SNI/listener merge, named ports, default-allow L7. rule (2502): rule sanitization, ICMP, entities, port ranges, labels. distillery (2139) + distillery_precedence (1066): full resolve with tier precedence, deny precedence, FQDN incremental deletion, CIDR entity selection. repository (1535) + repository_deny (737): enforcement computation, wildcard rules ingress/egress incl. deny, replace-by-resource, snapshots. resolve (1252) + resolve_deny (630): EndpointPolicy lookup incl. port ranges. selectorcache (737): selector add/remove, identity updates, transactional update, skip-update optimisation. | **port** |
| `pkg/ipcache` | 36 | 3,488 | ipcache metadata precedence: source precedence (HighestPrecedenceSource), sorted-by-resource-ID merging, parent-label merging, CIDR resource consolidation incl. non-canonical prefixes, pod-CIDR shadowing and shadowed-CIDR revival, override identity, FQDN label resolution, tunnel-peer and encrypt-key metadata, inherited CIDR prefix labels, named-port move on identity change, revision waiting, failed-allocate injection, kvstore IP-identity watcher. | **port** |
| `pkg/policy/api` | 34 | 2,779 | CNP rule validation: CIDR regex, endpoint/FQDN/node selector sanitization, L4 proto parsing, L7 rules vs non-TCP protocols, port ranges vs DNS rules, ICMP field limits and family, too-many-ports, qualified-name parsing, JSON/DeepEqual round-trips, default-deny sanitization. | **port** |
| `pkg/labels` | 37 | 1,841 | Label parse and canonical key form: source:key=value parsing, k8s label conversion, sorted list, kvstore format, comparison and ordering, CIDR label generation from a prefix, IP-string-to-label, label-array intersection and Has, selector match expressions, validation. | **port** |
| `pkg/container/bitlpm` | 15 | 1,675 | CIDR trie and unsigned-key LPM trie: upsert (incl. return value), exact lookup, longest-prefix match, Ancestors and AncestorsRange, Descendants incl. shortest-prefix-first ordering, delete, common-prefix and bit-value-at primitives. | **port** |
| `pkg/policy/k8s` | 6 | 1,242 | k8s NetworkPolicy/CNP/CCNP -> policy repository plumbing and resource-based replacement. | **port** |
| `pkg/identity/cache` | 16 | 1,224 | Identity allocation: local identity cache, reserved identity lookup by labels, next-numeric-ID bumping, allocator reset, allocate-locally path, checkpoint/restore of local identities, event-watcher batching, cluster-ID and cluster-name validators, observe stream. | **port** |
| `pkg/allocator` | 10 | 905 | The kvstore-backed allocator: master-key/slave-key handling, ID selection under contention, prefix masking, cached allocation, local-key sync incl. sync with identity allocations, k8s delete handling, remote kvstore watch, cache validators. | **port** |
| `pkg/maps/policymap` | 8 | 701 | Policy map entry encoding: wildcarding, port/proto string form, entry ordering, dump-to-slice for allow and deny, delete of a nonexistent key, stats map. Mostly privileged. | **port** |
| `pkg/kvstore/allocator` | 6 | 699 | Identity allocation over the kvstore: key encoding, lease handling, GC interaction. | **port** |
| `pkg/policy/utils` | 7 | 685 | Policy helper utilities: rule-label derivation, resource naming. | **port** |
| `pkg/policy/test` | 2 | 669 | 5 txtar scenarios for the policy control plane. | **harvest** |
| `pkg/identity` | 11 | 581 | Identity numeric-space rules: local vs cluster-scoped, cluster ID shift and extraction, reserved identity set and lookup by labels, scope-for-labels, identity from label array. | **port** |
| `pkg/policy/types` | 3 | 525 | Key/MapStateEntry types, traffic direction, port-proto packing, precedence constants. | **port** |
| `pkg/idpool` | 9 | 366 | ID pool: lease/release/reuse, exhaustion, concurrent allocation. | **port** |
| `pkg/labelsfilter` | 4 | 329 | Label prefix include/exclude config parsing and the filter precedence that decides which pod labels reach identity. | **port** |
| `pkg/identity/basicallocator` | 4 | 269 | Basic numeric ID allocator over a range. | **port** |
| `pkg/policy/compute` | 4 | 268 | Precomputed policy tier priorities. | **port** |
| `pkg/policy/cell` | 1 | 245 | Hive cell wiring for the policy repository. | **replace** |
| _11 further packages in this area_ | 24 | 1,350 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **401** | **40,875** | | |

**Effort: ~18,000 Rust test lines.** (harvest 1pkg/669; port 17pkg/38,611; replace 1pkg/245; tail 1,350)

This is the area to get right. 401 test functions, 40,875 test lines, and
`pkg/policy` alone is 164 functions over 21,034 lines — **7.6% of the reference's
entire test estate in one package**.

Everything substantive here is **port**. There is no honest way to replace it:
the deny-precedence rules, the LPM ancestor/descendant relations between policy
keys, the wildcard and named-port merge rules, and the incremental
`AccumulateMapChanges` path are the specification, and the tests are the only
place several of them are written down. `pkg/policy/mapstate_test.go` (3,463
lines) and `distillery_precedence_test.go` (1,066 lines) should be ported
before any flowsdn policy code is considered done.

`pkg/ipcache` (36 tests, 3,488 lines) is the second half: metadata precedence by
source, merging by resource ID, CIDR consolidation including non-canonical
prefixes, pod-CIDR shadowing and shadowed-CIDR revival. These are
order-independence properties, and hand-written cases catch only some of them —
pair the port with the proposed `fuzz_ipcache_metadata_precedence` target in
`tests/fuzz/SEEDS.md`.

`pkg/policy/cell` is the only **replace** (Hive wiring, ADR-0004).

### Area 06 — Agent core, endpoints, API

Inventory: [`docs/inventory/06-agent-endpoint-api.md`](inventory/06-agent-endpoint-api.md) · Spec: docs/spec/08-endpoint-agent-api.md, docs/spec/00-foundation-table-config.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/endpoint` | 34 | 3,494 | Endpoint state machine and regeneration: the 8 states and their transitions, WaitForPolicyRevision incl. superseded and skipped revisions, incremental updates during policy generation, restore from the state directory (dir-name parsing, partition by restore status, restore failure), CiliumEndpoint status construction, redirect installation with deny and with equal/unequal priority, label update, named-port identity labels, DNS-rules v2 unmarshalling, source-IP-verification annotation, event-queue shutdown deadlock regression, CIDR label computation before and after restore. | **port** |
| `pkg/metrics/features` | 35 | 2,433 | Which feature-usage metrics are emitted for a given DaemonConfig. | **replace** |
| `pkg/endpointmanager` | 29 | 2,303 | Endpoint manager: lookup by ID/IP/container/pod, ID allocation and reuse, endpoint expose/remove ordering, restore, host endpoint handling, policy-revision propagation, GC of stale endpoints. | **port** |
| `pkg/crypto/certloader` | 30 | 2,072 | TLS certificate and key loading, watched reload on file change, client and server config construction, mutual-TLS setup, error paths on partial writes. | **port** |
| `pkg/option` | 38 | 1,927 | DaemonConfig: flag parsing and validation for 539 flags, defaults, mutually exclusive combinations, derived values, config-file merging. | **port** |
| `daemon/cmd` | 14 | 1,568 | Daemon start-up wiring, flag registration and the cell graph. | **replace** |
| `cilium-dbg/cmd` | 16 | 1,470 | CLI command output shapes for status, endpoint, service, policy, bpf subcommands. | **port** |
| `pkg/rate` | 30 | 906 | Rate limiter and API limiter: adjustment of parallel requests and rate from observed latency, wait cancellation, metrics. | **port** |
| `pkg/metrics` | 12 | 858 | Metric registration and the enabled-metrics set. | **replace** |
| `pkg/health/server` | 3 | 841 | cilium-health server: probe scheduling, node/endpoint connectivity result aggregation. | **port** |
| `pkg/health/client` | 14 | 801 | 8 golden files: exact rendered health status output for healthy/unhealthy x all-nodes x verbose. | **harvest** |
| `pkg/dial` | 6 | 752 | Dialer resolution: service-name to cluster IP, fallback and retry. | **port** |
| `pkg/types` | 17 | 721 | IPv4/IPv6/MAC repr(C) datapath types and their byte order. | **port** |
| `pkg/mountinfo` | 4 | 646 | Detection of bpffs and cgroup2 mounts from /proc/self/mountinfo. | **port** |
| `pkg/container` | 14 | 612 | Generic Go containers (ring buffer, immutable map, set). | **replace** |
| `pkg/slices` | 10 | 540 | Generic slice helpers. | **replace** |
| `pkg/dynamicconfig` | 8 | 539 | Dynamic config table and its reconciliation. | **replace** |
| `pkg/kpr/initializer` | 2 | 506 | kube-proxy-replacement feature resolution: which combination of flags is valid and what it enables. | **port** |
| `pkg/fswatcher` | 4 | 488 | File watcher: create/modify/delete/rename events, symlink and directory handling. | **port** |
| `pkg/command` | 5 | 464 | Command-line output formatting (JSON/table/jsonpath). | **port** |
| `pkg/controller` | 14 | 396 | The controller (periodic retrying task) primitive. | **replace** |
| `pkg/completion` | 13 | 379 | Completion/WaitGroup primitive for proxy ACKs. | **replace** |
| `bugtool/cmd` | 5 | 376 | Envoy config-dump redaction: input and expected redacted output. | **harvest** |
| `pkg/option/resolver` | 4 | 342 | Config-source resolution order across ConfigMap, node config and CRD. | **port** |
| `pkg/lock` | 11 | 341 | Go mutex wrappers and deadlock detection. | **replace** |
| `daemon/infraendpoints` | 4 | 325 | Host and ingress endpoint creation at start-up. Privileged. | **port** |
| `pkg/counter` | 7 | 320 | Prefix and int counters used by ipcache/policy. | **port** |
| `pkg/container/set` | 2 | 317 | Small-set container. | **replace** |
| `pkg/driftchecker` | 3 | 311 | Config drift detection between the ConfigMap and the running agent. | **replace** |
| `pkg/dynamiclifecycle` | 2 | 300 | Dynamic cell lifecycle. | **replace** |
| `pkg/hive/health` | 3 | 300 | Hive health reporting tree. | **replace** |
| `pkg/hive` | 6 | 285 | The Hive dependency-injection framework itself. | **replace** |
| `pkg/endpointcleanup` | 1 | 279 | Cleanup of CiliumEndpoints without a local endpoint. | **port** |
| `daemon/cmd/cni` | 4 | 278 | CNI config file generation and installation. | **port** |
| `pkg/logging` | 9 | 268 | Logging setup and slog handlers. | **replace** |
| `pkg/metrics/features/operator` | 6 | 257 | Operator feature-usage metrics. | **replace** |
| _49 further packages in this area_ | 130 | 5,141 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **549** | **34,156** | | |

**Effort: ~13,500 Rust test lines.** (harvest 2pkg/1,177; port 18pkg/18,134; replace 16pkg/9,704; tail 5,141)

The largest area by package count (85) and the most mixed. Roughly a
third of the Go test lines here test framework rather than behaviour: `pkg/hive`,
`pkg/hive/health`, `pkg/controller`, `pkg/eventqueue`, `pkg/completion`,
`pkg/lock`, `pkg/container`, `pkg/slices`, `pkg/dynamiclifecycle`,
`pkg/dynamicconfig`, `pkg/metrics*` — all **replace** under ADR-0004 and general
"Rust has its own primitives". That is 9,704 Go test lines that produce
flowsdn tests of a different shape, not fewer tests.

`pkg/endpoint` (34 tests, 3,494 lines) is the one that must be ported faithfully:
the 8-state endpoint machine, `WaitForPolicyRevision` including superseded and
skipped revisions, and restore-from-state-directory. The restore path is where a
silent bug costs the whole node's connectivity after an agent restart.

`pkg/option` (38 tests, 1,927 lines) is a **port** because
`docs/spec/00-foundation-table-config.md` commits flowsdn to reference-compatible
config keys; the validation matrix is the compatibility test.

Two **harvest** rows: `pkg/health/client` (8 `.golden` files, now in
`tests/golden/06-health-cli-output/`) and `bugtool/cmd` (the Envoy config-dump
redaction pair, now in `tests/golden/06-bugtool-envoy-config/`).

### Area 07 — IPAM incl. cloud

Inventory: [`docs/inventory/07-ipam-cloud.md`](inventory/07-ipam-cloud.md) · Spec: docs/spec/07-ipam.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/ipam` | 39 | 3,629 | Agent IPAM: allocate-next with and without expiration, expiration timer, allocated-IP dump, IP-not-available error, mark-for-release without allocate, exclude-IP, address-family derivation, IPAM metadata (pool from pod/namespace annotation) incl. the legacy allocator, node-store static-IP status, CIDR-pool first/last-IP policy and reclaim of a still-advertised released CIDR, multi-pool manager (release all CIDRs, release unused CIDR with and without pre-alloc, update-node retries, wait for all pools, neededIPCeil watermark math, pending allocations per pool), ENI allocation result construction incl. prefix delegation and ip-masq, ENI pool accessor, VPC CIDR derivation, native-routing CIDR autodetection. | **port** |
| `pkg/aws/ipam` | 33 | 2,519 | ENI node manager: default allocation, pre-allocate and min-allocate watermarks (incl. min-allocate 20 and combined), ENI creation with SG tags and interface-tag exclusion, exceeding ENI capacity, prefix delegation, subnet selection (by ID, by tags, same route table as node subnet, untracked subnets), security-group selection by tags, max-allocatable IPv4 computation, capacity accounting, static IP incl. already-associated and primary-ENI cases, instance-not-running and instance-deleted paths, many-nodes scaling, ENI garbage collection, IPv6 prefix allocation, CIDR release preparation. | **port** |
| `operator/pkg/ipam/allocator/multipool` | 16 | 2,258 | Multi-pool CIDR allocator: pool add/upsert/delete, pool errors, shrink with CIDRs in use, orphan CIDRs (after restart, released, not stolen from another pool), keep-old-CIDRs on pool update, node handler and its retries, addrs-in-prefix math, first/last-IP policy, node migration, status update on failure. | **port** |
| `operator/pkg/ipam/allocator/podcidr` | 10 | 2,063 | Cluster-pool pod-CIDR manager: upsert/delete/resync, allocate specific IPNets, allocate next, release, split pod CIDRs, sync to k8s, and the duplicate-IPv6-causes-IPv4-duplication regression. | **port** |
| `operator/pkg/ipam/nodemanager` | 17 | 1,620 | Cloud-IPAM node manager watermark math: calculate needed IPs, calculate excess IPs, static-IP resolution, release with abort and with IP reassignment, multi-pool allocation tracking and CIDR release, sync to API server for a nonexistent node, many-nodes scaling. | **port** |
| `pkg/azure/ipam` | 12 | 964 | Azure IPAM: pre-allocate and min-allocate watermarks, subnet discovery, resync preserving other nodes subnets, capacity accounting incl. multi-NIC and use-primary variants, max-allocatable IPv4, deterministic status-field ordering. | **port** |
| `pkg/ip` | 29 | 944 | IP/CIDR primitives: coalesce CIDRs, range-to-CIDRs, CIDR partitioning around an excluded prefix, spanning CIDR, next/previous IP, count IPs, prefix-to-IPs with limits and edge cases, unique-addr keeping, netip JSON round-trip and deep-copy, CIDR overlap. | **port** |
| `pkg/ipam/cidrset` | 8 | 764 | CIDR set allocator: allocate/occupy/release, index-to-CIDR-block mapping, bit-for-CIDR computation, full-allocation behaviour, IPv6, invalid subnet mask size. | **port** |
| `pkg/ipam/metadata` | 11 | 762 | Pool selection from pod and namespace annotations and its precedence. | **port** |
| `pkg/ipalloc` | 17 | 635 | Generic IP range allocator: allocate/allocate-next/free, exhaustion, IPv6. | **port** |
| `pkg/alibabacloud/ipam` | 6 | 454 | Alibaba ENI: capacity accounting, max-allocatable IPv4, interface creation, candidate/empty interface selection, IP allocation preparation, ENI index allocation. | **port** |
| `pkg/ipam/service/ipallocator` | 11 | 408 | Range-based IP allocator used by the ClusterIP path. | **port** |
| `pkg/azure/api` | 5 | 392 | Azure API client request/response shaping. | **port** |
| `pkg/ipam/migration` | 1 | 326 | IPAM mode migration expressed as a txtar script. | **harvest** |
| `operator/pkg/ipam` | 2 | 270 | 2 txtar scenarios for operator IPAM (multipool). | **harvest** |
| _15 further packages in this area_ | 39 | 1,666 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **256** | **19,674** | | |

**Effort: ~8,500 Rust test lines.** (harvest 2pkg/596; port 13pkg/17,412; tail 1,666)

Almost entirely **port**, and unusually mechanical: these are arithmetic
tests. The watermark math (`TestCalculateNeededIPs`, `TestCalculateExcessIPs`,
`Test_neededIPCeil`, `TestNodeManagerMinAllocate20`,
`TestNodeManagerMinAllocateAndPreallocate`) is pure function-of-inputs and ports
almost line for line, which makes it cheap coverage of something that is
expensive to get wrong: an off-by-one in pre-allocate either starves pods or
burns cloud IP quota, and neither shows up until scale.

`operator/pkg/ipam/allocator/podcidr` carries an explicitly named regression,
`TestNodesPodCIDRManager_DuplicateIPv6CausesIPv4Duplication`. Port that one by
name.

`pkg/ip` (29 tests, 944 lines) and `pkg/ipam/cidrset` (8 tests, 764 lines) are
the CIDR arithmetic primitives — coalescing, range-to-CIDR, partitioning around
an excluded prefix, index-to-CIDR-block. Cheap to port, and every layer above
depends on them.

The two AWS mock packages (`pkg/aws/api/mock`, `pkg/azure/api/mock`) are test
doubles for cloud APIs; flowsdn needs equivalents but built on its own SDK
types, so they fall in the long tail as **replace**.

### Area 08 — Operator

Inventory: [`docs/inventory/08-operator.md`](inventory/08-operator.md) · Spec: docs/spec/12-operator.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `operator/pkg/model/translation` | 59 | 5,474 | Model -> CiliumEnvoyConfig translation. Golden YAML in and out. | **harvest** |
| `operator/pkg/gateway-api` | 54 | 4,835 | Gateway API reconcilers and the status conditions they set. 604 golden YAML files. | **harvest** |
| `operator/pkg/ciliumendpointslice` | 32 | 2,466 | CES controller: batching CEPs into slices, slice sizing modes (identity vs FCFS), rate limiting, update/delete propagation, restart reconciliation. | **port** |
| `operator/pkg/gateway-api/helpers` | 24 | 2,450 | Gateway API helper predicates over the golden object sets. | **harvest** |
| `operator/pkg/bgp` | 9 | 2,321 | Operator-side BGP: cluster config to per-node config, peer config resolution. | **port** |
| `operator/pkg/model/ingestion` | 26 | 2,023 | k8s objects -> internal model. 324 golden YAML files. | **harvest** |
| `operator/pkg/ingress` | 6 | 1,792 | Ingress reconciler and its status/service handling. | **harvest** |
| `operator/pkg/gateway-api/indexers` | 16 | 1,613 | Field indexers over Gateway API objects. | **harvest** |
| `operator/pkg/ciliumidentity` | 18 | 1,534 | Identity controller: identity creation from pod labels, reference counting, GC of unused identities, CID <-> pod mapping. | **port** |
| `operator/pkg/gateway-api/routechecks` | 8 | 1,340 | Route acceptance checks (hostname, backend refs, filters) over golden objects. | **harvest** |
| `operator/pkg/model` | 17 | 1,334 | The internal model types and their equality/normalisation. | **port** |
| `operator/pkg/model/translation/gateway-api` | 23 | 1,163 | Gateway-API-specific model -> CEC translation. 207 golden YAML files. | **harvest** |
| `operator/watchers` | 14 | 1,124 | 3 txtar scenarios for operator watchers. | **harvest** |
| `operator/pkg/secretsync` | 6 | 985 | Secret mirroring into the Cilium secrets namespace. | **port** |
| `operator/auth/spire` | 5 | 894 | SPIRE-backed mutual auth identity provisioning. | **drop** |
| `operator/api` | 7 | 709 | Operator REST API handlers and health. | **port** |
| `operator/pkg/ingress/annotations` | 9 | 609 | Ingress annotation parsing. | **harvest** |
| `operator/pkg/nodeipam` | 3 | 589 | Node IPAM service LB IP assignment from node addresses. | **port** |
| `operator/pkg/ztunnel/reconciler` | 9 | 515 | ztunnel (ambient mesh) reconciler. | **drop** |
| `operator/pkg/networkpolicy/external-groups` | 5 | 478 | toGroups / external-group (AWS security group) policy resolution. | **drop** |
| `operator/pkg/gateway-api/policychecks` | 1 | 449 | Gateway API policy attachment checks. | **harvest** |
| `operator/identitygc` | 4 | 439 | Identity GC: heartbeat store, mark-and-sweep across CEP references, rate limiting. | **port** |
| `operator/pkg/model/translation/ingress` | 3 | 395 | Ingress model -> CEC. 14 golden YAML files. | **harvest** |
| `operator/unmanagedpods` | 9 | 288 | Detection and reporting of pods with no Cilium endpoint. | **port** |
| `operator/pkg/gateway-api/watch-handlers` | 2 | 254 | Which Gateway API objects a change enqueues. | **harvest** |
| _10 further packages in this area_ | 25 | 1,228 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **394** | **37,301** | | |

**Effort: ~7,600 Rust test lines.** (drop 3pkg/1,887; harvest 13pkg/23,521; port 9pkg/10,665; tail 1,228)

The disposition split here is unusual: **13 packages / 23,521 Go test
lines are harvest**, because the Gateway API and Ingress pipelines are already
expressed as golden YAML — 1,149 files, now under `tests/golden/08-operator-*/`.
The Rust work is one comparison runner per pipeline stage, not 23k lines of
tests. That is why area 08 has the third-largest Go test corpus but a modest
effort number.

Gateway API itself is **deferred** by `docs/inventory/README.md` ("defer Gateway
API/Ingress until Envoy path exists"), so the harvested fixtures sit unused
until that work starts. Harvesting now is deliberate: the acceptance criteria
land before the implementation.

Three **drop** rows, each with a named decision: `operator/auth/spire` and
`operator/pkg/ztunnel/*` (inventory 08 "Drop SPIRE (deprecated 1.20), ztunnel";
mutual auth is also deprecated per inventory 11) and
`operator/pkg/networkpolicy/external-groups` (inventory 05 "Defer ... toGroups").

The genuine **port** work is the controllers: CES (`ciliumendpointslice`, 32
tests), identity GC, endpoint GC, CID management, node IPAM, secret sync.

### Area 09 — Hubble + monitor

Inventory: [`docs/inventory/09-hubble-monitor.md`](inventory/09-hubble-monitor.md) · Spec: docs/spec/11-hubble-monitor.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/hubble/filters` | 35 | 5,533 | Every flow filter and its composition: source/destination IP, IP version, port, protocol, verdict, drop reason, identity, label selector, pod, service, FQDN and DNS query, node and node-name pattern, cluster name, network interface, traffic direction, reply, TCP flags, trace ID and IP trace ID, UUID, workload include/exclude, encrypted, event type, CEL expressions. Includes an equivalence check between the fast and the general filter path. | **port** |
| `pkg/hubble/parser/threefour` | 24 | 2,729 | L3/L4 flow decoding from the datapath record: trace, drop and policy-verdict notifications; VXLAN and Geneve overlay decoding; ICMP; original IP in trace notify; proxy port; local endpoint enrichment; drop reason and trace reason decoding; local identity decoding; traffic direction and is-reply determination; CIDR label filtering; debug capture; custom monitor and packet decoders. | **port** |
| `pkg/hubble/exporter` | 33 | 2,721 | Flow-log exporters: file rotation, filters, field masks, dynamic reload of the exporter set, aggregation. Config fixtures are YAML. | **port** |
| `pkg/hubble/peer` | 9 | 1,705 | Peer service: peer list construction from the node manager, change notifications, TLS name handling. | **port** |
| `pkg/monitor` | 26 | 1,592 | Monitor payload decoding for every event type and the agent-side event dispatch. | **port** |
| `pkg/hubble/relay/observer` | 5 | 1,526 | Relay fan-out: merging flow streams from many peers, ordering, per-peer error handling, node-status events. | **port** |
| `pkg/hubble/relay/pool` | 5 | 1,433 | Relay peer connection pool: connect, reconnect with backoff, peer add/remove. | **port** |
| `pkg/hubble/container` | 18 | 1,262 | The flow ring buffer: write/read semantics, wrap-around, readers falling behind, oldest-flow lookup. | **port** |
| `pkg/hubble/metrics/api` | 10 | 1,183 | Metric handler registry, context options (labels/namespace/dns/ip contexts) and label resolution. | **port** |
| `pkg/hubble/parser/seven` | 15 | 1,014 | L7 flow decoding: HTTP, DNS, and the generic L7 record; latency computation. | **port** |
| `pkg/hubble/observer` | 13 | 931 | Local observer: ring reader, filters applied server-side, GetFlows/GetAgentEvents/GetDebugEvents. | **port** |
| `pkg/policy/correlation` | 4 | 914 | Correlating a policy-verdict flow back to the rules that allowed or denied it. | **port** |
| `pkg/hubble/monitor` | 3 | 675 | Monitor-socket consumer feeding the observer. | **port** |
| `pkg/hubble/dropeventemitter` | 7 | 488 | Emitting k8s Events for dropped packets. | **port** |
| `pkg/hubble/parser/sock` | 1 | 467 | Socket-trace event decoding. | **port** |
| `pkg/hubble/peer/types` | 2 | 430 | Peer address and TLS-name types. | **port** |
| `pkg/hubble/metrics` | 6 | 395 | Metric config parsing. 8 YAML fixtures. | **harvest** |
| `pkg/hubble/relay/server` | 1 | 384 | Relay gRPC server wiring and TLS. | **port** |
| `pkg/hubble/metrics/flows-to-world` | 6 | 338 | flows-to-world metric: which flows count as world-bound. | **port** |
| `pkg/monitor/format` | 3 | 324 | cilium-dbg monitor rendering of every event type. | **port** |
| `pkg/hubble/metrics/http` | 6 | 288 | HTTP metric handler: status/method/path labels and latency histogram. | **port** |
| `pkg/hubble/parser/agent` | 1 | 277 | Agent-event decoding. | **port** |
| `pkg/hubble/testutils` | 1 | 246 | Fakes used by the other Hubble tests. | **replace** |
| _25 further packages in this area_ | 59 | 2,726 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **293** | **29,581** | | |

**Effort: ~12,900 Rust test lines.** (harvest 1pkg/395; port 21pkg/26,214; replace 1pkg/246; tail 2,726)

Everything substantive is **port**. Two rows dominate.

`pkg/hubble/parser/threefour` (24 tests, 2,729 lines) decodes the datapath's
perf records into flows. It is the only place in the reference where the
on-the-wire monitor record layout is asserted against a decoded result, so it is
simultaneously a decoder test and the best available check that flowsdn's
`#[repr(C)]` notification structs match `docs/spec/11-hubble-monitor.md`. Port it
before writing the Hubble server.

`pkg/hubble/filters` (35 tests, 5,533 lines) is the filter algebra. Note
`TestBenchmarkFiltersAreEquivalent`, which asserts the fast path and the general
path agree — that is a differential property and should become a `proptest` in
flowsdn rather than a fixed case list.

`pkg/monitor` + `pkg/monitor/format` cover the gob monitor socket and the
`cilium-dbg monitor` renderer; inventory 09 says flowsdn implements a subset of
the gob socket, so port the decoding tests and scope the formatting tests to the
subset.

Hubble Relay (`relay/observer`, `relay/pool`, `relay/server`, `peer`) is a
separate binary in flowsdn; its ~5,000 Go test lines port as a unit with that
binary, not with the agent.

### Area 10 — BGP

Inventory: [`docs/inventory/10-bgp.md`](inventory/10-bgp.md) · Spec: docs/spec/15-bgp.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/bgp/manager/reconciler` | 24 | 7,884 | Every BGP reconciler: neighbor (static peer, source interface address), pod-CIDR advertisement, pod-IP-pool advertisement, service LB/externalIP/clusterIP advertisement incl. VIP sharing and peer-IP change, interface advertisement, default-gateway reconciler and its trackers, route-policy statements merge and soft reset, CRD status conditions incl. partial failure and status-report disable. | **port** |
| `pkg/bgp/gobgp` | 6 | 907 | The GoBGP adapter: session config, path advertisement and withdrawal through GoBGP APIs. | **replace** |
| `pkg/bgp/manager` | 2 | 513 | BGP manager lifecycle: instance create/update/delete from CiliumBGPClusterConfig. | **port** |
| `pkg/bgp/types` | 2 | 417 | BGP path/prefix/family types, route-policy types, attribute encoding. | **port** |
| `pkg/bgp/api` | 2 | 262 | BGP REST API handlers (peers, routes, route policies). | **port** |
| _2 further packages in this area_ | 2 | 264 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **38** | **10,247** | | |

**Effort: ~4,500 Rust test lines.** (port 4pkg/9,076; replace 1pkg/907; tail 264)

Small area, one dominant package: `pkg/bgp/manager/reconciler` is 24
tests over 7,884 lines — 77% of the area's test lines — and it is the entire
"what do we advertise, when do we withdraw it" contract. **port**, and port all
of it: pod-CIDR, pod-IP-pool, service ClusterIP/ExternalIP/LoadBalancer
advertisement, VIP sharing, peer-IP change, route-policy merge and soft reset,
and the CRD status conditions including partial failure.

`pkg/bgp/gobgp` is **replace**: inventory 10 says flowsdn writes its own minimal
speaker instead of embedding GoBGP, so a test of the GoBGP adapter has no
counterpart. The session/state-machine tests flowsdn needs are new work not
represented anywhere in this table, and that is the risk in area 10 — the
reference gets its BGP protocol correctness from GoBGP and therefore does not
test it.

`pkg/bgp/test` (235 lines) is a runner over **20 txtar scenarios**; those go to
`tests/scripttest`.

### Area 11 — L7 proxy, DNS, auth, mesh

Inventory: [`docs/inventory/11-l7-proxy-dns-auth-mesh.md`](inventory/11-l7-proxy-dns-auth-mesh.md) · Spec: docs/spec/16-l7-envoy-dns.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/envoy` | 85 | 6,286 | The xDS driver: ADS server lifecycle, resource upsert/update/delete with ACK/NACK handling and revert, multiple versions in flight before ACK/NACK, listener add/remove with completion callbacks, port-allocation callbacks and what they wait for, strict-ADS snapshot consistency, admin and metrics listeners, NPHDS (ipcache -> Envoy) upsert/delete/full-state, NPDS network-policy computation from L4 policy incl. wildcard, deny, named ports, TLS interception, not-enforced directions and filter coalescing by resolved port, k8s Secret -> Envoy secret conversion incl. TLS session keys limits, restorer promise handling, locality bootstrap. | **port** |
| `pkg/ciliumenvoyconfig` | 28 | 2,904 | 12 txtar scenarios: CEC/CCEC -> listeners, services and backend sync. | **harvest** |
| `pkg/fqdn/dnsproxy` | 31 | 2,723 | DNS proxy: request/response interception, allowed-name matching against the FQDN selectors, rule lookup per endpoint, response rewriting, TTL handling, UDP and TCP paths, error responses, concurrency. Privileged. | **port** |
| `pkg/envoy/xds` | 29 | 2,721 | The xDS protocol machinery: resource sets, versioning, watch/ack semantics, stream handling. | **port** |
| `pkg/ztunnel/xds` | 15 | 1,779 | ztunnel xDS. | **drop** |
| `pkg/auth` | 27 | 1,563 | Mutual authentication handshake and auth map management. | **drop** |
| `pkg/xds/experimental/client` | 13 | 1,484 | Experimental xDS client (delta and SotW). | **port** |
| `pkg/fqdn` | 25 | 1,426 | DNS cache: TTL expiry, zombie entries and their GC, per-endpoint caches, restore across restart, IP-to-name reverse lookup. | **port** |
| `pkg/envoy/xdsnew` | 50 | 1,361 | The rewritten xDS server: snapshot cache, per-type resource versions, ACK tracking. | **port** |
| `pkg/fqdn/service` | 8 | 1,260 | The standalone DNS-proxy gRPC service. | **port** |
| `pkg/ztunnel/reconciler` | 4 | 774 | ztunnel reconciler. | **drop** |
| `pkg/fqdn/namemanager` | 5 | 734 | Mapping FQDN selectors to names and the resulting identity/ipcache updates. | **port** |
| `pkg/proxy` | 4 | 674 | Proxy redirect lifecycle: create/update/remove, port allocation and reuse across restart. | **port** |
| `pkg/ztunnel/iptables` | 11 | 547 | ztunnel iptables rules. | **drop** |
| `pkg/ztunnel/zds` | 9 | 526 | ztunnel ZDS socket protocol. | **drop** |
| `pkg/envoy/xdsnew/callbacks` | 15 | 504 | xDS server callbacks and their ordering. | **port** |
| `pkg/auth/spire` | 7 | 481 | SPIRE client for mutual auth. | **drop** |
| `pkg/envoy/policy` | 7 | 449 | L7 policy -> Envoy NPDS rule conversion helpers. | **port** |
| `pkg/proxy/proxyports` | 3 | 375 | Proxy port allocation and persistence across restart. | **port** |
| `pkg/proxy/accesslog` | 0 | 285 | Envoy access-log record types and their parsing (benchmarks only, no Test funcs). | **port** |
| _7 further packages in this area_ | 11 | 803 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **387** | **29,659** | | |

**Effort: ~9,700 Rust test lines.** (drop 6pkg/5,670; harvest 1pkg/2,904; port 13pkg/20,282; tail 803)

Six **drop** rows totalling 5,670 Go test lines, all mesh/auth:
`pkg/ztunnel/{xds,reconciler,iptables,zds,ca}` (inventory 11: ztunnel
defer-then-keep; the iptables one is doubly dropped by ADR-0003) and
`pkg/auth` + `pkg/auth/spire` (inventory 11: mutual auth deprecated in 1.20).
If ztunnel is later un-deferred, these rows come back as **port**.

`pkg/envoy` is the biggest single package outside `pkg/policy`: 85 tests, 6,286
lines. The valuable half is the NPDS computation — L4 policy to Envoy network
policy, including wildcards, deny, named ports, TLS interception, not-enforced
directions and filter coalescing by resolved port. That is the flowsdn/Envoy
contract and Envoy is consumed as an external image (ADR-0001), so getting it
wrong is not caught anywhere else. The other half — ACK/NACK bookkeeping,
multiple versions in flight, port-allocation callbacks — is xDS protocol
behaviour that flowsdn reimplements and must test just as hard.

`pkg/fqdn/dnsproxy` (31 tests, 2,723 lines, privileged) is the DNS proxy. Port
it; a DNS proxy that fails open is a policy bypass.

### Area 12 — ClusterMesh + kvstore

Inventory: [`docs/inventory/12-clustermesh-kvstore.md`](inventory/12-clustermesh-kvstore.md) · Spec: (spec pending, wave 4)

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/clustermesh/mcsapi` | 9 | 2,987 | MCS-API: ServiceExport/ServiceImport reconciliation, derived services, EndpointSlice mirroring, IP-family intersection. | **drop** |
| `pkg/kvstore` | 28 | 2,280 | The kvstore client contract: get/set/update/create-only/delete with and without a lock, list-and-watch, lease manager (expiry, parallel, release-prefix, cancel-if-expired, key-has-lease), paginated list, rate limiting, endpoint shuffling, key path and scope validation, local locks. | **port** |
| `pkg/kvstore/store` | 19 | 1,219 | Shared store: local key sync, remote observation, key deletion and restoration, sync-controller semantics. | **port** |
| `pkg/clustermesh` | 10 | 1,197 | Agent-side ClusterMesh: remote cluster add/remove, config watching, per-cluster node/service/identity/ipcache stores and their status. | **port** |
| `pkg/clustermesh/common` | 10 | 1,033 | Remote cluster config file discovery, reload on change, connection status. | **port** |
| `pkg/clustermesh/kvstoremesh` | 6 | 872 | kvstoremesh: reflecting remote cluster keys into the local kvstore, per-prefix sync state. | **port** |
| `pkg/clustermesh/types` | 9 | 543 | Cluster ID validation, cluster-scoped identity encoding, addressing types. | **port** |
| `pkg/clustermesh/operator` | 6 | 500 | Operator-side ClusterMesh wiring. | **port** |
| `clustermesh-apiserver/mcsapi-coredns-cfg` | 4 | 365 | MCS-API CoreDNS config generation. | **drop** |
| `pkg/clustermesh/kvstoremesh/reflector` | 3 | 300 | kvstoremesh reflector loop. | **port** |
| `pkg/clustermesh/namespace` | 1 | 295 | Namespace synchronisation across clusters. | **port** |
| `pkg/clustermesh/endpointslicesync` | 2 | 273 | Global-service EndpointSlice synchronisation. | **drop** |
| `clustermesh-apiserver/clustermesh` | 3 | 262 | 9 txtar scenarios for the clustermesh apiserver. | **harvest** |
| `pkg/clustermesh/store` | 4 | 251 | ClusterMesh store types (node, service, identity, ipcache) and their key encoding. | **port** |
| _5 further packages in this area_ | 11 | 609 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **125** | **12,986** | | |

**Effort: ~4,100 Rust test lines.** (drop 3pkg/3,625; harvest 1pkg/262; port 10pkg/8,490; tail 609)

Three **drop** rows: `pkg/clustermesh/mcsapi` (2,987 lines),
`pkg/clustermesh/mcsapi/types`, `pkg/clustermesh/endpointslicesync` and
`clustermesh-apiserver/mcsapi-coredns-cfg` — inventory 12 "Defer MCS-API,
EndpointSlice v2". That is 3,625 Go test lines deferred, the second-largest
deliberate omission after iptables.

`pkg/kvstore` (28 tests, 2,280 lines) is a **port** with a twist: inventory 12
replaces the etcd sidecar with **fastetcd**, so these tests double as the
fastetcd compatibility suite. Every one of `TestLeaseManager*`,
`TestCreateOnly`, `Test*IfLocked`, `TestPaginatedList` and `TestListAndWatch` is
an assertion about etcd semantics that fastetcd must satisfy. Port them and run
them against fastetcd first, before any ClusterMesh code exists — that is the
cheapest way to find out whether the substitution holds.

`pkg/kvstore`'s `TestScript` and `clustermesh-apiserver/clustermesh` are txtar
runners (1 + 9 scenarios) and go to `tests/scripttest`.

### Area 13 — CRDs + k8s integration

Inventory: [`docs/inventory/13-crds-k8s.md`](inventory/13-crds-k8s.md) · Spec: docs/spec/13-crds-k8s-client.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/k8s` | 51 | 6,488 | k8s object handling: CNP/CCNP/KNP parsing into rules (ingress/egress, allow-all, L4 allow-all, port ranges, named ports, empty port, unknown proto, empty from, deny-all, no-ingress, cluster label, CIDR and IPBlock rules, policy labels, peer parsing), object equality for CNP/Pod/Node/Namespace/annotations, transform-to-slim functions, CEP <-> CoreCEP conversion, EndpointSlice v1 parsing, Node and CiliumNode parsing incl. annotations and address types, pod metadata extraction, named-port identity labels, the StateDB reflector and on-demand tables. | **port** |
| `pkg/k8s/resource` | 17 | 2,055 | The Resource[T] abstraction: informer-backed store with event subscription, retries and completion. | **replace** |
| `pkg/k8s/watchers` | 9 | 984 | Which resources the agent watches and how events are dispatched. | **port** |
| `pkg/k8s/utils` | 12 | 978 | Slim object conversion, label extraction, service-affinity and topology helpers. | **port** |
| `pkg/k8s/apis/cilium.io/utils` | 4 | 891 | CNP -> rule label derivation and namespace qualification. | **port** |
| `pkg/k8s/apis/cilium.io/v2` | 6 | 832 | CNP/CCNP Parse(), deep-copy and JSON round-trips. | **port** |
| `pkg/k8s/client` | 6 | 810 | 5 txtar scenarios for the k8s client (config, user agent, rate limiting). | **harvest** |
| `pkg/k8s/apis/cilium.io/v2/validator` | 7 | 656 | CRD OpenAPI validation of CNP/CCNP documents. | **port** |
| `pkg/k8s/informer/benchmarks` | 0 | 540 | Informer benchmarks only, no Test functions. | **replace** |
| `pkg/k8s/apis/crdhelpers` | 7 | 285 | CRD registration, schema version annotations and update logic. | **port** |
| `pkg/k8s/client/testutils` | 3 | 265 | Fake client fixtures used by the txtar tests. | **harvest** |
| _5 further packages in this area_ | 5 | 350 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **127** | **15,134** | | |

**Effort: ~6,100 Rust test lines.** (harvest 2pkg/1,075; port 7pkg/11,114; replace 2pkg/2,595; tail 350)

`pkg/k8s` is 51 tests over 6,488 lines and is really three things: CNP/
CCNP/KNP parsing into rules (the largest part, and arguably area 05 work),
object equality and slim-type conversion, and Node/CiliumNode parsing. All
**port**.

The KNP parsing tests (`TestParseNetworkPolicy*`, ~20 functions) are worth
special attention: they define how upstream `NetworkPolicy` semantics map onto
Cilium rules, including the awkward cases — empty `from`, empty ports, unknown
protocol, no ingress section, deny-all. flowsdn accepts the same objects, so
these are compatibility tests, not implementation tests.

`pkg/k8s/resource` (17 tests, 2,055 lines) is **replace**: `Resource[T]` is the
Hive-flavoured informer abstraction (ADR-0004). flowsdn needs the same
guarantees — store completeness before first event delivery, retry with backoff,
event ordering per key — expressed against its own client.

`pkg/k8s/informer/benchmarks` has 0 `Test*` functions (benchmarks only) — a
reminder that the "3,040 tests" figure is functions, not assertions.

### Area 14 — Encryption + egress

Inventory: [`docs/inventory/14-encryption-egress.md`](inventory/14-encryption-egress.md) · Spec: docs/spec/14-encryption-egress.md

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| `pkg/egressgateway` | 8 | 2,037 | Egress gateway policy -> egress map entries: policy parsing, endpoint and node selection, gateway election, excluded CIDRs, policy update and delete, node-not-gateway path. Privileged. | **port** |
| `pkg/datapath/linux/ipsec` | 17 | 1,281 | IPsec XFRM state and policy construction, the state cache, key rotation and SPI handling, per-node state, cleanup of stale states. | **port** |
| `pkg/wireguard/agent` | 4 | 1,118 | WireGuard: peer add/update/remove from node events, key handling, allowed-IP computation, device setup. Privileged. | **port** |
| `pkg/ipmasq` | 8 | 583 | ip-masq-agent config parsing (non-masquerade CIDRs, masq-link-local) and the resulting map entries. | **port** |
| `pkg/maps/srv6map` | 3 | 355 | SRv6 policy/SID/VRF maps. | **drop** |
| _4 further packages in this area_ | 8 | 488 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **48** | **5,862** | | |

**Effort: ~2,400 Rust test lines.** (drop 1pkg/355; port 4pkg/5,019; tail 488)

Smallest substantive area: 48 test functions, 5,862 lines. Everything
kept is **port**.

`pkg/datapath/linux/ipsec` (17 tests, 1,281 lines) is the risk that inventory 14
already names ("IPsec XFRM + rotation is the risk"). The XFRM state cache, SPI
handling and key-rotation tests are the only written specification of the
rotation protocol. Port them first, and pair them with the harvested
`tests/golden/14-ipsec-xfrm-stat/` counter fixture.

`pkg/egressgateway` (8 tests, 2,037 lines, privileged) covers gateway election
and the resulting egress map entries; inventory 14 flags egress-gateway
HA/status as a candidate flowsdn improvement, so expect to *add* cases here
rather than only port them. Its 2 txtar scenarios go to `tests/scripttest`.

`pkg/maps/srv6map` is **drop** — inventory 14 "defer VTEP, SRv6".

### Area 15 — Helm, images, CI, tests

Inventory: [`docs/inventory/15-helm-images-ci-tests.md`](inventory/15-helm-images-ci-tests.md) · Spec: (spec pending, wave 4)

| Reference package | `Test*` | Test lines | What it pins down | Disposition |
|---|---:|---:|---|---|
| _8 further packages in this area_ | 11 | 623 | Small helper, type and mock packages, each under 245 test lines. | mixed |
| **Area total** | **11** | **623** | | |

**Effort: ~200 Rust test lines.** (; tail 623)

Barely a test area in the reference: 11 test functions, 623 lines,
spread over `tools/` linters and `test/` helpers. The real content of area 15 is
CI configuration and the harnesses themselves, which ADR-0005 §3 specifies as
four Rust binaries.

`test/controlplane` has exactly 1 `Test*` function (the suite entry point) and
its value is entirely in the 18 YAML object sets, now harvested to
`tests/golden/controlplane/`.

`tools/statedblint` and `tools/metricslint` are Go static-analysis passes with no
flowsdn counterpart — **drop**, subsumed by `clippy` and a metrics-naming test.

The connectivity suite is **not in this tree** at v1.20.1 (ADR-0005 Context);
`flowsdn-connectivity` is new work, not a port.

---

## 3. Ranking: the 20 packages to port first

Ranked by *how much behaviour flowsdn can get wrong silently* — that is, wrong
in a way that produces no crash, no error log and no failing integration test,
but wrong traffic. A package scores high when it is (a) a byte-level or
cross-node contract, (b) order- or precedence-dependent, or (c) arithmetic whose
error mode is a quiet leak rather than a fault.

| # | Package | `Test*` | Lines | Why first | Fails silently as |
|---:|---|---:|---:|---|---|
| 1 | `pkg/policy` (`mapstate_test.go`, `distillery_precedence_test.go`) | 164 | 21,034 | Deny precedence, LPM key covering, wildcard shadowing and the incremental `AccumulateMapChanges` path. The tests *are* the specification of deny-over-allow. | Traffic that should be denied is allowed. Nothing logs. |
| 2 | `pkg/ipcache` | 36 | 3,488 | Metadata precedence by source, merging by resource ID, CIDR consolidation incl. non-canonical prefixes, pod-CIDR shadowing, shadowed-CIDR revival. Order-independence is the contract. | An IP maps to the wrong identity, so the wrong policy applies to it. |
| 3 | `pkg/maps/ctmap` | 10 | 1,329 | CT key encoding, `MaxEntries` sizing, GC for TCP/ICMP/DSR, orphan-NAT GC. Byte-for-byte ABI shared with `cilium-dbg`/`bpftool`. | Connections tracked under the wrong key; return traffic dropped, or GC frees a live entry. |
| 4 | `pkg/identity/cache` + `pkg/allocator` | 26 | 2,129 | Identity allocation under contention: local cache, next-NID bumping, checkpoint/restore, master/slave keys, `TestSyncLocalKeysWithIdentityAllocations`. | Two nodes allocate different identities for one workload. Policy silently stops matching cluster-wide. |
| 5 | `pkg/loadbalancer/reconciler` (`TestBPFOps`) | 3 | 2,118 | The exact map write/delete *sequence* per service change, with orphan cleanup. Ordering, not just end state. | A window during every service update in which traffic goes to a removed backend. |
| 6 | `pkg/labels` | 37 | 1,841 | Parsing, canonical key form, sorted list, kvstore format, CIDR label derivation. Feeds the identity key. | Two canonicalisations of one label set ⇒ two identities. Same failure as #4, different cause. |
| 7 | `pkg/container/bitlpm` | 15 | 1,675 | CIDR/LPM trie: longest-prefix match, `Ancestors`, `Descendants` incl. shortest-prefix-first ordering. Under both ipcache and policy. | Wrong CIDR rule wins. Carries a checked-in fuzz corpus (`tests/fuzz/corpus/FuzzUint8/`). |
| 8 | `pkg/maglev` | 4 | 249 | `TestReproducible` and `TestBackendRemoval` — the cross-node determinism and disruption bound. 249 lines for the whole guarantee. | Two nodes build different Maglev tables; connections break on rehash, only under load. |
| 9 | `pkg/hubble/parser/threefour` | 24 | 2,729 | Decoding trace/drop/policy-verdict records, VXLAN and Geneve overlay, original IP, proxy port. The only assertion anywhere that the notification struct layout is right. | Every flow is misattributed. Observability lies, quietly and consistently. |
| 10 | `pkg/policy/api` | 34 | 2,779 | CNP validation: selectors, L4 proto, L7-vs-non-TCP, port ranges vs DNS, ICMP limits, default-deny sanitization. The accept/reject boundary. | A rule that should be rejected is accepted and then means something different than the author intended. |
| 11 | `pkg/ipam` | 39 | 3,629 | Watermark math, expiration timers, multi-pool release paths, `Test_neededIPCeil`, `Test_pendingAllocationsPerPool`. | IPs leak until the pool empties, or pods stall waiting for an address that was never requested. |
| 12 | `operator/pkg/ipam/nodemanager` | 17 | 1,620 | `TestCalculateNeededIPs`, `TestCalculateExcessIPs`, release-with-abort, release-with-IP-reassignment. Pure arithmetic, cheap to port. | Cloud IP quota burns, or a release races an allocation and takes a live IP. |
| 13 | `pkg/loadbalancer/writer` | 13 | 1,562 | Backend selection under `trafficDistribution`: PreferClose zone fallback, terminating backends, missing zone hints, same-node preference. | Traffic crosses zones (cost) or lands on a terminating backend (resets). |
| 14 | `pkg/kvstore` | 28 | 2,280 | Lease manager, create-only, conditional-if-locked ops, paginated list, list-and-watch. **Doubles as the fastetcd compatibility suite** (inventory 12). | A lease semantic fastetcd implements differently ⇒ stale identities or a split ClusterMesh. |
| 15 | `pkg/envoy` (NPDS half) | 85 | 6,286 | L4 policy → Envoy network policy: wildcards, deny, named ports, TLS interception, not-enforced directions, filter coalescing by resolved port. Envoy is an external image, so nothing else checks this. | L7 policy is enforced differently than L3/L4 policy says. |
| 16 | `pkg/maps/policymap` | 8 | 701 | Policy map entry encoding and wildcarding; the byte form of everything `pkg/policy` computes. | The right decision is computed and the wrong bytes are written. |
| 17 | `pkg/ip` + `pkg/ipam/cidrset` | 37 | 1,708 | Coalesce, range-to-CIDR, partition-around-excluded-prefix, index-to-CIDR-block, bit-for-CIDR. Primitive arithmetic under everything above. | Off-by-one in a prefix boundary; one address at the edge of every pool behaves differently. |
| 18 | `pkg/endpoint` | 34 | 3,494 | The 8-state machine, `WaitForPolicyRevision` incl. superseded/skipped, restore from the state directory. | After an agent restart, an endpoint comes back with the wrong policy revision and no error. |
| 19 | `pkg/bgp/manager/reconciler` | 24 | 7,884 | What is advertised and when it is withdrawn, incl. VIP sharing, peer-IP change, route-policy soft reset. | A withdrawn prefix stays advertised; traffic is blackholed at the fabric, not at the node. |
| 20 | `pkg/datapath/linux/ipsec` | 17 | 1,281 | XFRM state/policy construction, state cache, SPI handling, key rotation. Inventory 14 names this the area's risk. | Rotation leaves a stale SA; traffic silently falls back to cleartext or is dropped. |

Together these 20 rows (22 packages) are **655 test functions and 69,816 Go
test lines** — 25.3% of the reference's test estate, covering by the argument
above most of what can go wrong without anyone noticing.

### Correctness-critical specifics called out

- **Conntrack / NAT semantics** — `pkg/maps/ctmap` (#3), `pkg/maps/nat`,
  `pkg/maps/ctmap/gc`. 1,932 Go test lines, nearly all `TestPrivileged*`, so
  they need the privileged CI lane from day one. The key layout is a published
  ABI (`docs/spec/04-conntrack-nat.md`); add a `fuzz_ct_key_roundtrip` target
  (`tests/fuzz/SEEDS.md`) because a field-order error is invisible to
  hand-written cases that construct and read back through the same code.
- **Policy map state and deny precedence** — `pkg/policy/mapstate_test.go`
  (3,463 lines), `distillery_precedence_test.go` (1,066),
  `repository_deny_test.go` (737), `resolve_deny_test.go` (630),
  `l4_filter_deny_test.go` (488). 6,384 lines specifically about deny. Port all
  of it, and carry `FuzzDenyPreferredInsert`, `FuzzAccumulateMapChange` and both
  `FuzzDistillPolicy` differential targets — the latter with its 27 harvested
  regression seeds, which are exactly the rule sets that once broke this.
- **Identity allocation races** — `pkg/identity/cache` (16 tests),
  `pkg/allocator` (10), `pkg/kvstore/allocator` (6),
  `pkg/identity/basicallocator` (4). Watch `TestAllocateCached`,
  `TestSyncLocalKeys`, `TestSyncLocalKeysWithIdentityAllocations`,
  `TestCheckpointRestore` and `TestBumpNextNumericIdentity`; they are the
  crash-and-restart cases. Add `fuzz_identity_key_canonical`.
- **Service reconciler ordering** — `pkg/loadbalancer/reconciler`'s `TestBPFOps`
  is one table of expected map operations per input change. Port the table
  verbatim; assert on the *sequence*, not the final map contents, or the test
  proves nothing about the update window.
- **ipcache metadata precedence** — `pkg/ipcache/metadata_test.go`. The names to
  port first: `TestHighestPrecedenceSource`, `Test_sortedByResourceIDsAndSource`,
  `Test_metadata_mergeParentLabels`, `TestIPCacheCIDRResourceConsolidation` (and
  its `NonCanonical` sibling), `TestIPCachePodCIDRShadowing`,
  `TestIPCacheShadowedCIDRRevivalUsesCurrentAttributes`, `TestOverrideIdentity`.
  Add `fuzz_ipcache_metadata_precedence` for insertion-order independence.
- **Maglev determinism** — `pkg/maglev` is 4 tests. `TestReproducible` must
  become a cross-process check in flowsdn (compute the table twice, in two
  processes, compare), not a same-process one, because the failure mode is
  hash-iteration-order nondeterminism that a single process hides.
  `TestWeightedBackendWithRemoval` bounds disruption. Add
  `fuzz_maglev_determinism`.
- **IPAM watermark math** — `Test_neededIPCeil`, `Test_pendingAllocationsPerPool`
  (`pkg/ipam`); `TestCalculateNeededIPs`, `TestCalculateExcessIPs`
  (`operator/pkg/ipam/nodemanager`); `TestNodeManagerMinAllocate20`,
  `TestNodeManagerMinAllocateAndPreallocate`, `TestIpamPreAllocate8`,
  `TestIpamMinAllocate10`. Pure functions; port them literally and early — they
  are the cheapest high-value lines in the whole plan.
- **CIDR / LPM handling** — `pkg/container/bitlpm` (15 tests, with a fuzz
  corpus), `pkg/ip` (29), `pkg/ipam/cidrset` (8), `pkg/cidr` (8). Note
  `TestDescendantsShortestPrefixFirst`: the *iteration order* of descendants is
  load-bearing for ipcache, not an implementation detail.
- **Label parsing and canonical key form** — `pkg/labels` (37 tests over 7 files:
  `labels`, `array`, `arraylist`, `cidr`, `k8s`, `validation`). The ones that
  matter for identity: `TestParseLabel`, `TestLabelsK8sStringMap`,
  `TestSortMap`, `TestLabelArraySorted`, `BenchmarkLabel_FormatForKVStore`'s
  subject (the kvstore format), `TestGetCIDRLabels`, `TestLabelToPrefix`. Plus
  `pkg/labelsfilter` (4 tests) for include/exclude precedence, which decides
  *which* labels reach the key at all. Carry `FuzzNewLabels`, `FuzzLabelsParse`
  and `FuzzLabelsfilterPkg`.

---

## 4. Sequencing

Against `docs/inventory/README.md`'s build order:

| Build-order step | Port these first | Rust test lines |
|---|---|---:|
| 1. table/config/netlink | `pkg/option`, `pkg/ip`, `pkg/cidr`, `pkg/container/bitlpm`, `pkg/labels` | ~3,000 |
| 2. BPF map ABI + loader, datapath M1 | `pkg/maps/ctmap`, `pkg/maps/nat`, alignment gate; `bpf/tests` checklist (sibling) | ~700 |
| 3. agent skeleton, IPAM, CNI | `pkg/ipam`, `pkg/ipam/cidrset`, `pkg/ipam/metadata`, `pkg/datapath/connector`, `pkg/endpoint`, `pkg/endpointmanager` | ~5,600 |
| 4. identity + ipcache + policy | `pkg/policy`, `pkg/ipcache`, `pkg/policy/api`, `pkg/identity*`, `pkg/allocator`, `pkg/kvstore/allocator`, `pkg/maps/policymap` | ~14,400 |
| 5. service LB | `pkg/loadbalancer*`, `pkg/maglev`, `operator/pkg/lbipam` + the 51 txtar scenarios | ~5,000 |
| 6. node model, routes, nftables | `pkg/node*`, `pkg/datapath/linux*`, **new** nftables assertions replacing the dropped iptables tests | ~6,400 |
| 7. monitor + Hubble | `pkg/hubble/parser/threefour`, `pkg/hubble/filters`, `pkg/monitor` | ~12,900 |
| 8. operator + CRDs | `pkg/k8s`, `operator/pkg/ciliumendpointslice`, `operator/identitygc` + the harvested golden YAML | ~13,700 |
| 9. WireGuard, IPsec, egress | `pkg/wireguard/agent`, `pkg/datapath/linux/ipsec`, `pkg/egressgateway` | ~2,400 |
| 10. BGP | `pkg/bgp/manager/reconciler` + 20 txtar scenarios + **new** speaker state-machine tests | ~4,500 |
| 11. Envoy, DNS proxy | `pkg/envoy` (NPDS), `pkg/fqdn*` | ~9,700 |
| 12. ClusterMesh | `pkg/kvstore` (**run against fastetcd before writing ClusterMesh code**), `pkg/clustermesh*` | ~4,100 |

The right-hand column is the withdrawn historical allocation for packages
*named on that row*, not
the historical area total, so it sums to ~82,400 rather than ~102,600; both
allocations are withdrawn by the §1 calibration update. The remainder was the
long tail and the `replace` work that follows the code it tests.

The one out-of-order recommendation: **port `pkg/kvstore`'s 28 tests against
fastetcd at step 1, not step 12.** They are 2,280 Go test lines that answer
"does the etcd substitution hold?", and the answer changes the design of areas
05 and 12. Finding out at step 12 is expensive.

---

## 5. What this plan does not cover

- **`bpf/tests`** — 141 C files, 397 `CHECK` cases. Sibling agent,
  `flowsdn-bpftest`, BSD-2-Clause (ADR-0005 §2).
- **`.txtar` scenarios** — 168 files. Sibling agent, `tests/scripttest/`.
- **The connectivity suite** — not in the tree at v1.20.1 (cilium-cli moved to
  its own repo). `flowsdn-connectivity` is new work.
- **`api/` generated code** — 97k lines, mostly generated; its tests are
  round-trip tests of generated types and are subsumed by flowsdn's own
  serde round-trips.
- **Ginkgo e2e (`test/k8s`, `test/ginkgo-ext`)** — the legacy e2e suite. Not
  counted here and not ported; superseded by `flowsdn-connectivity`.

---

## 6. Open questions

1. **Resolved #246: trusted privileged kernel lane.** Run unprivileged checks
   on every push. Privileged suites belong in disposable VMs on designated
   trusted CI capacity, testing the supported kernel floor/line from
   `docs/kernel-requirements.md`. Once operational, the reviewed-commit lane
   gates merge; missing required kernel capabilities fail the gate. Fork PR code
   must not execute automatically with host privilege or secrets; use an explicit
   trusted review boundary and isolated VM lifecycle. This is lane placement and
   policy, not evidence of runner provisioning, branch-protection installation
   or execution of the 230-test inventory. CI wiring and those runs remain work.
2. **The dropped iptables coverage.** ~~2,592 Go test lines vanish under ADR-0003
   with no automatic replacement.~~ **Resolved #247, confirmed 2026-09-22.**
   `docs/spec/10-node-routing-nftables.md` §9.1 now enumerates the replacement
   before any nftables code exists: 45 cases (N1–N45) across feature-gate
   presence/absence, golden rulesets, determinism and idempotent re-apply,
   transaction atomicity, foreign-table coexistence, teardown, the
   accepted-and-ignored iptables keys, and reconciler convergence — plus a table
   of the reference assertions with no equivalent because BPF does the job
   (the whole `ipset` package, the masquerade/SNAT/hairpin rules, ruleset-as-
   proxy-port-store) naming what proves each of those instead.
3. **Policy port granularity — resolved #248.** Implement and validate file-sized
   behavior groups, with deny/mapstate semantics first: `mapstate`,
   `distillery_precedence`, `repository_deny`, `resolve_deny`, and
   `l4_filter_deny`. Preserve scenario provenance and independently specified
   expectations; do not transliterate Go implementation code. The initial Rust
   policy library provides atomic validation and a limited independent L3/L4
   oracle, not completion of these five suites. Full mapstate optimization and
   fuzz agreement remain tracked by #103.

4. **BGP protocol unit-suite gap — #249 validated.** Independent Rust wire
   codecs, OPEN/UPDATE encoders, session FSM, timers, connection ownership and
   error transcripts now have a passing focused `flowsdn-bgp-proto` suite.
   Spec15 §9.2 maps the cases to `tests/wire.rs`, `encoders.rs`, `session.rs`
   and `ownership.rs`, including malformed-frame notification bytes and a
   100001-announcement bounded-observation transcript. This closes the missing
   protocol-unit-suite item, not the complete speaker milestone. Real socket
   transport, TCP authentication, export/reconciler integration and independent
   GoBGP interoperability remain required. This replacement work is not measured
   by the Maglev/CIDRset calibration or added to its conditional totals.
5. **Effort model calibration — #250 validated 2026-09-22.**
   The pure algorithms and Rust ports now cover every named upstream unit-test
   category. Calibration mapping:

   | Pinned Go test | Rust evidence |
   |---|---|
   | Maglev TestPermutations | `every_upstream_permutation_count_size_and_chunking_case`: all 8 backend counts × 3 sizes × 6 chunk counts; no internal worker pool, so partition invariance replaces scheduling coverage |
   | TestReproducible | `weighted_vector_and_permutation`, exact copied 251-entry RLE data and reversed input |
   | TestBackendRemoval | `removal_disruption`, valid replacement IDs and fewer than 11 retained-owner changes in 1021 slots |
   | TestWeightedBackendWithRemoval | `weighted_removal`, same disruption threshold and exact counts 16/98/832/75 |
   | CIDR FullyAllocated / IndexToCIDRBlock / GetBitforCIDR / Occupy / CIDRSetv6 / InvalidSubNetMaskSize | `all_upstream_table_rows`: all 52 static rows (2/15/14/14/3/4), exact results and errors; occupancy verifies all selected bits plus total count, then idempotent release |
   | CIDR RandomishAllocation / AllocationOccupied | `upstream_full_roundtrip_and_half_occupied_workflows`: both IPv4/IPv6 inputs; all 256 blocks; release/reallocate equality; last 128 occupied scenario |

   Additional Rust tests cover invalid inputs, cross-family ownership, cursor
   wrapping and hash vectors. The original physical-line denominators are 249
   (`pkg/maglev/maglev_test.go`, including its benchmark/harness) and 764
   (`pkg/ipam/cidrset/cidr_set_test.go`). The benchmark is not a unit-test
   requirement and has not been ported; no performance calibration is claimed.
   Linux execution and Clippy passed. Formatted Rust test LOC: Maglev 123
   plus 3 fixture lines versus 249 Go lines (0.494 code-only; 0.506 including
   data); CIDRset 193 plus 55 fixture lines versus 764 (0.253; 0.325).
   Combined: 316 code lines / 1013 = 0.312; 374 including data / 1013 = 0.369.
   This observed two-module range replaces the unvalidated ×0.45 test-LOC
   assumption for these ports only. It is not a whole-project engineering
   time estimate; the original Maglev denominator includes an unported benchmark.
