# ADR-0011: Foundation and packet-path decision resolutions

Date: 2026-09-21. Status: accepted design decisions.

## Scope and evidence

This audit reads the full GitHub issue bodies, their cited specifications and
existing ADRs against the reference baseline v1.20.1 (`7d68cfb394`). It resolves
bounded design questions; it does not claim the networking subsystems are
implemented or validated. The current execution order is
[the four milestones](../milestones.md), not the historical phase numbers in
issue text. Historical inventories remain observations of their original date;
the resolved specifications and this record take precedence over their questions.

Rows below state the issue's acceptance request, the selected contract and its
source, and the work that remains. A decision issue can close after the contract
is recorded even when its implementation remains in the milestone/spec checklist.
An issue requesting measurement, a working feature, or tests cannot close on that
basis. No privileged checks were run for this documentation audit.

## Resolutions

| Issue | Requested acceptance | Decision and supporting evidence | Remaining implementation / acceptance |
|---|---|---|---|
| #1 | Decide which skb mark fields stay bit-compatible. | Preserve the whole layout, including internal magics and split 24-bit identity encoding. Spec 01 §4.7 and spec 02 §2 already freeze it; spec 02 now states the decision explicitly. Envoy, XFRM and diagnostic boundaries must agree. | Implement and test mark consumers; no mixed-node forwarding claim. |
| #2 | Decide whether socket LB remains in scope and its ordering. | Retain cgroup socket hooks and per-packet LB; socket LB belongs to milestone 2. Spec 05 §3.8 now says so, consistent with the milestone's explicit socket-LB deliverable. Per-packet primitives can land first without deleting socket-LB scope. | Socket attachment, host/pod namespace behavior and privileged tests. |
| #5 | Assign stale-map cleanup after versioned renames. | Spec 01 §3.4 explicitly assigns cleanup to the startup mapsweeper after endpoint restoration. Only the sweep removes global pins; the low-level loader does not own stale-version discovery. | Implement known-name sweep and crash/unknown-pin tests. |
| #8 | Confirm native nftables rather than shelling out to iptables. | ADR-0003 already requires direct netlink, one owned nftables table and no iptables binary. Existing iptables-legacy policy is not translated or managed by flowsdn; deployments must reconcile conflicting host policy separately. | Native residual and coexistence/failure validation; no interoperability claim for unmanaged legacy rules. |
| #10 | Confirm the shared table choice covers LB consumers. | ADR-0004's shared table/reconciler model covers service/frontends/backends and Hubble, Envoy, REST and L2 views. Spec 00 §3.2 separates status so status-only updates do not wake data consumers; spec 05 §4 names the tables. The table and reconciler crates exist. | Integrate LB writers and those consumers; foundation tables alone do not implement LB. |
| #11 | Confirm wildcard NodePort surrogates are required. | Keep `0.0.0.0` and `::` surrogate entries. Spec 05 §3.5 and §3.8 explicitly require them for socket host lookups; concrete NodePort address expansion does not replace them. | Writer and socket-LB lookup tests for both families. |
| #12 | Preserve hostns-only, LRP skip-LB and termination interaction. | Spec 05 §3.8 now explicitly retains LRP skip checks and disables pod-netns termination whenever hostns-only is true, regardless of the termination flag. Host-netns termination remains independent. | Config and socket namespace matrix tests when termination lands. |
| #14 | Decide whether StateDB policy-command diffing is a parity requirement. | It is not: ADR-0004 and spec 06 §2 exclude the Hive shell `policy/mapstate/*` and `policyrepo/*` command surface. Policy-map reconciliation and compatible REST/map diagnostics remain required. No StateDB engine is introduced for debug-command parity. | Policy compiler/reconciler and supported diagnostics; excluded shell commands are not an implementation gap. |
| #47 | Resolve the registry retry maximum conflict. | `lb-retry-backoff-max=1m`, following the explicit source resolution in spec 05 §6. Spec 00 §3.2.3 and §6.4 are corrected; minimum remains `1s`. | The Rust catalogue must use `1m` and a focused regression must pass before closing this issue. The audit found its old `1s` value; documentation alone is insufficient. |
| #51 | Finalize cache versus reconciler after the table crate exists. | Adopt spec 01 §3.11: table-backed maps use the reconciler; lxc/ipcache multi-writer maps use one common desired-value cache/retry primitive. One retry owner per map prevents competing convergence loops. `flowsdn-table` and `flowsdn-reconcile` now supply the foundation. | Build live map adapters and error recovery; no live adapter completion claimed. |
| #57 | Choose perf array versus ring buffer for monitor events. | Keep `cilium_events` as `PERF_EVENT_ARRAY`, preserving per-CPU ordering, framing and lost-event accounting. Specs 01/02 and the kernel roll-up now agree; no automatic ring-buffer migration is scheduled. | Implement reader/producer integration and overload tests. A future alternative requires a measured proposal and its own map/reader contract. |
| #58 | Choose per-endpoint versus shared policy-capable lxc objects. | Retain per-endpoint objects, rodata and policy-map names (spec 01 §3.7). The shared initial local-delivery smoke object does not settle policy-map selection or supersede this contract. | Production policy objects, endpoint load/memory measurement and lifecycle tests. |
| #59 | Select the default pod device. | Veth is default. Netkit is explicit and optional, gated by kernel/features with the reference's at-least-6.8 requirement; the general 6.6 floor stays unchanged. Spec 02 and the kernel roll-up agree. | Netkit implementation/probes and runtime tests; no netkit support claim from version checking alone. |
| #60 | Decide tail slots versus subprograms. | Preserve the specified tail-call slots and error contract. Cold internal helpers may use subprograms; replacing CT→policy boundaries requires verifier/stack evidence on both architectures. | Full program implementation and measurements; no speculative slot removal. |
| #61 | Select map/pin namespace. | Keep the `cilium_*` names and spec 01 directories, including diagnostic-tool-visible policy maps. | Loader/pinning implementation and tool compatibility tests. Name parity does not prove in-place migration safety. |
| #64 | Decide active duplicate-identity convergence versus GC. | Keep duplicates until ordinary release/GC; do not renumber live endpoints merely to prefer the oldest allocation. Spec 03 §12 now selects the low-churn reference behavior. | Identity allocator/restart/GC implementation and tests. |
| #66 | Resolve userspace/datapath local-identity upper bound. | Classify supported local identities by scope byte across the full nonzero 24-bit index range. Spec 03 §4.5 already states the deviation; spec 02 now explicitly references it. Existing numeric identity primitives support the range, but are not packet-path evidence. | Integrate classification into each packet consumer and test above `0x0100_FFFF`; never encode scoped identities into marks/VNIs. |
| #69 | Choose well-known identity default. | Keep `enable-well-known-identities=true`, consistent with spec 03 §4.4/§6 and the Rust config catalogue. Explicit false disables it. | Allocator shortcut behavior and enabled/disabled tests. |
| #73 | Choose bounded loops versus forced unrolling for port allocation. | Use a verifier-bounded 32-attempt loop on the 6.6 minimum. Spec 04 no longer leaves source unrolling undecided. | Both-architecture live verifier tests and allocation collision/exhaustion tests. |
| #74 | Resolve effective regular/service TCP lifetime. | Both defaults are 8000 seconds (spec 04 §3 and §6); loader configuration must not accidentally use the reference's 21600-second fallback. | Datapath timeout and GC integration tests. |
| #75 | Select the service CT internal result API. | Use `Existing` internally, preserving emitted CT/trace reason bytes. Spec 04 §3 now requires that name rather than recommending it. | CT/service integration and trace compatibility tests. |
| #76 | Decide orphan-NAT scan schedule and manual trigger. | Signal-triggered scans plus explicit `flowsdn-dbg bpf nat gc`; no every-Nth-periodic scan. Spec 04 §5.5 and §12 now agree. | Signal integration, manual command and orphan/DSR tests remain required. |
| #79 | Place NAT46/64 in the milestone order. | Service translation lands with milestone 2 LB and `SVC_FLAG_NAT_46X64`. The independent stateless RFC 6052 gateway is advanced networking in milestone 3. Spec 04 §3.15 distinguishes these paths. | Complete translation algorithms and live forward/reply tests; scheduling is not implementation. |
| #80 | Decide bit-exact Maglev versus binary-key hashing. | Freeze spec 05 §5.1: canonical hash strings, bytewise order and MurmurHash3 x64-128. No binary-key alternative within compatible mode. | Generator and reference vector/mixed-node tests. |
| #81 | Choose weighted Maglev f64 versus fixed point. | Use the specified IEEE-754 double counters and truncation exactly; do not substitute fixed point. | Weighted golden vectors and cross-architecture equality tests. |
| #84 | Choose built-in active backend probes versus hook only. | Hook only, matching the reference extension boundary. External integrations/API may set `Unhealthy`; Kubernetes readiness still drives its ordinary backend state. No in-tree TCP/HTTP prober is selected. | Implement the hook/state overlay and test interactions. |
| #85 | Choose LB class names and aliases. | Retain only specified `io.cilium/*` classes; do not implicitly claim `flowsdn.io/*` aliases. | Ownership/class tests with existing manifests. |
| #86 | Select service topology default. | Default false, matching spec 05 §6 and the Rust catalogue. Explicit enablement applies the specified hint rules. Chart mapping must preserve the default. | Reflector and chart tests. |
| #88 | Reconcile the quarantined backend-slot flag between specs. | Writers MUST leave service-slot bit 14 zero; backend state and slot ranges carry quarantine. Spec 02 §3.12 no longer depends on this alias for reuse/selection; spec 05 §4 remains authoritative. | Backend-change/reselection tests proving no hidden dependency on bit 14. |
| #90 | Correct spec 00 to the resolved one-minute retry maximum. | Spec 00 §3.2.3, §6.4 and §12 now match spec 05 §6. This is the requested cross-document edit. | Runtime catalogue/regression acceptance is separately tracked by #47. |
| #91 | Choose all-address versus NodePort-only health listener. | Preserve `:<port>` for healthCheckNodePort; cloud probes can target node addresses outside the NodePort set. The independent KPR healthz listener remains separately configured. | Listener lifecycle, bind-failure and address-family tests. |
| #94 | Decide `toServices` remote-backend expansion and headless behavior. | Keep spec 06 §3.2.5: generated selectors for selector Services, backend CIDRs for selector-less Services (including selector-less headless Services), and re-resolution on changes. Use the local LB table view; do not add a separate remote-cluster query or union. Entries already in that view are not discarded merely by origin. | Resolver/watch tests including headless and mesh cases. |
| #95 | Decide treatment of removed Requires semantics. | Retain schema fields, accept and ignore them, warn once per affected rule on import. Spec 06 now states the compiler contract, not only a recommendation. | Importer/schema tests and warning surface. Removing fields needs an explicit versioned compatibility decision. |
| #100 | Decide reserved policy-entry bits 1–2 ownership. | Write zero, ignore on read; do not reclaim before 1.0. Any later reuse still requires a versioned map/tool migration contract. Spec 06 §4.4 and §12 agree. | Reader/writer compatibility tests. |

## Issues deliberately left open in this range

The audit does not close the remaining open issues numbered 1–100. In particular:

- #3, #4, #19, #25, #30, #35, #37, #39, #40, #41, #50, #70, #87 and #89
  require source, platform, feature, consumer or measurement evidence beyond
  this decision audit. A recommendation or existing prose is not that evidence.
- #29, #36, #48, #83 and #98 include implementation, fixture or regression
  obligations not delivered by these edits. #98 also mentions an upstream
  report; none is filed by this record.
- #6, #7, #9, #15–18, #20–24, #26–28, #31–34, #38, #44–46, #52,
  #56, #62, #63, #65, #67, #68, #71, #72, #77, #78, #82, #92, #93,
  #96, #97 and #99 need further cross-area decisions or contract work.
  Their current recommendations remain proposals, not newly accepted choices.

#47 is conditional on the separately implemented catalogue fix and its
validation. Every other resolution above satisfies a documentation/design ask,
not a feature-implementation acceptance gate. Release and milestone claims must
continue to use demonstrated outcomes rather than the number of closed issues.
