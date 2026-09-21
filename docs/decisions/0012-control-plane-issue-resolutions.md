# ADR-0012: Control-plane compatibility and ownership decisions

Date: 2026-09-21. Status: accepted.

## Scope and acceptance

These decisions resolve the bounded design questions listed below against the
pinned v1.20.1 specifications. They preserve ADR-0001 full feature scope and
ADR-0002 Rust-only implementation. Except for #129, each listed issue asks for a choice or a specification
correction; acceptance is the recorded choice and matching normative
specification, not completion of its implementation. #129 remains open: its
verification request needs evidence beyond the strengthened ownership contract.

The initial agent/CNI runtime remains a subset. Cloud controllers, Hubble,
encryption and BGP are not declared implemented or validated by this record.
The remaining implementation and validation obligations below are mandatory
under the existing specifications and milestones. Unlisted issues stay open;
no missing benchmark, provider capture, migration run or interoperability
result is substituted with a design decision.

## #104: ENI pool compatibility

**Decision / acceptance:** Keep writing `spec.ipam.pool` in ENI mode alongside status
and multi-pool fields. Preserve status-before-spec ordering; remove no compatibility
field merely because the flowsdn agent does not consume it.

**Evidence:** Spec 07 §3.15 and §4.1 already require the operator snapshot.

**Remaining:** Cloud writer replay must verify old-reader fields and write ordering.

## #106: Azure mirror fields

**Decision / acceptance:** Read and write `interfaces[].cidr` and `addresses[].subnet`
as mirrors of the current fields, without a feature flag. A future incompatible removal
requires a separate migration decision.

**Evidence:** Spec 07 §3.10 currently requires fallback reads but only recommends writes.

**Remaining:** Recorded Azure responses and CR round trips must cover both legacy-only
input and mirrored output.

## #107: VMSS update serialization

**Decision / acceptance:** Serialize mutating Azure operations per full VMSS resource
ID, across all nodes of that scale set, retaining per-node serialization. Hold the
asynchronous permit through long-running-operation completion or terminal failure;
a cancelled caller stops waiting but the owning reconciler retains the permit
until the remote operation is terminal or its cancellation is confirmed. On
restart, recover/reconcile in-flight remote operations before issuing a new
mutation to that scale set. Different scale sets remain independent.

**Evidence:** Spec 07 §3.10 describes conflicts between concurrent instance updates.

**Remaining:** Replay concurrent updates to one versus two VMSS resources, cancellation, and failed polls.

## #108: AWS pagination fallback

**Decision / acceptance:** Keep the `OperationNotPermitted` fallback from page size 0 to
1000 for the provider client lifetime. Log once when switching and retry; do not
override an explicitly configured nonzero size.

**Evidence:** Spec 07 §3.9 already specifies the lifetime switch.

**Remaining:** Replay initial rejection, retried pagination, subsequent calls, and explicit sizes.

## #110: ENI IPv6 compatibility

**Decision / acceptance:** Keep the reference model: one /80 prefix per node, no IPv6
secondary-address allocation, and no IPv6-prefix release. This preserves the specified
API behavior and does not assert that IPv6-only EKS is validated.

**Evidence:** Spec 07 §3.9 and §3.14 describe prefix allocation and release exclusion.

**Remaining:** Provider replay must cover IPv6 demand, restart with an existing prefix,
and exclusion from release.

## #111: Deterministic Alibaba release

**Decision / acceptance:** Choose the eligible secondary ENI with the most free
releasable addresses; break ties by ascending ENI ID. Sort candidate IPs numerically
before taking the requested count. Primary and used addresses remain excluded.

**Evidence:** Spec 07 §3.11 already adopts most-free selection over reference map order.

**Remaining:** Permutation tests must prove identical ENI/IP choice, including ties and exclusions.

## #112: Alibaba credentials

**Decision / acceptance:** Support environment access keys, ECS RAM-role metadata
credentials, and OIDC RRSA from the initial Alibaba implementation. RRSA exchanges the
projected token with `AssumeRoleWithOIDC`; refresh expiring credentials and never log
tokens or signing material.

**Evidence:** Spec 07 §3.11 names all three sources; ADR-0007 requires HTTP-layer replay.

**Remaining:** Credential selection, expiry, failed exchange, and scrubbed RRSA
request/response scenarios remain required.

## #113: Unused pod CIDR status field

**Decision / acceptance:** Retain the `status.ipam.pod-cidrs` type for wire decoding and
schema compatibility. No flowsdn controller writes or uses it as allocation authority.

**Evidence:** Spec 07 §3.5 and §4.1 already label this accepted but never written.

**Remaining:** Round-trip incoming data and assert no controller-generated writes to the field.

## #114: Reference endpoint restore

**Decision / acceptance:** Read reference-written `ep_config.json` using §4.2, including
`dockerID`, `OpLabels`, legacy `DNSRules` (accepted and ignored), and `DNSRulesV2`;
tolerate unrelated `ep_config.h`. Restore does not import the reference runtime
configuration. Responder cleanup follows the process-ownership safeguards in decision
#117.

**Evidence:** Spec 08 §3.6–3.7 and §4.2 define the migration schema under ADR-0001.

**Remaining:** Full reference fixtures and live restore/migration remain required;
current endpoint persistence is only an initial subset.

## #116: Endpoint conflict status

**Decision / acceptance:** Return 409 with the API Error body for live attachment-ID or
IP ownership conflicts on endpoint PUT. Preserve 400 for malformed or otherwise invalid
requests. This is the existing documented deviation from the reference implementation.

**Evidence:** Spec 08 §3.3 step 5, §4.3, and §9 already require 409.

**Remaining:** Router tests must distinguish duplicate attachment/IP, malformed input,
and unknown endpoint cases.

## #117: Health responder process model

**Decision / acceptance:** Create the health namespace socket on a dedicated OS thread
using `setns`, then hand the socket to the runtime. Do not change a shared runtime
worker namespace. Keep the agent PID in the compatibility pidfile. A stale PID alone
never authorizes signalling: verify the process is the former health responder in the
expected namespace, protect against PID reuse, and otherwise report/leave the unrelated
process alone.

**Evidence:** Spec 08 §3.10 already chooses the in-process model; stale pidfile wording
needs ownership safeguards.

**Remaining:** Namespace isolation, thread failure, responder restart, and
stale/reused/unrelated PID tests remain required.

## #118: Unimplemented API routes

**Decision / acceptance:** Register recognized but not-yet-implemented method/path pairs
and return 501 with the standard Error body. Unknown paths remain 404; invalid methods
are handled separately. A 501 explicitly reports an unfinished feature and does not
remove it from scope.

**Evidence:** Spec 08 §2 and §4.3 already require explicit 501 responses.

**Remaining:** Route matrix tests must cover implemented, recognized-unimplemented,
unknown, and method-mismatch requests; initial runtime coverage is incomplete.

## #119: Adaptive API limiting

**Decision / acceptance:** Implement the adaptive auto-adjust algorithm specified in
§3.11 with its configuration and metrics; fixed limits are not a replacement for that
contract.

**Evidence:** Spec 08 §3.11 and §6 specify the compatibility limiter.

**Remaining:** Deterministic-clock tests must cover adjustment, saturation,
cancellation, fairness, and emitted metrics.

## #123: CNI installation names

**Decision / acceptance:** Install both `cilium-cni` and `flowsdn-cni` as names for the
same executable; generated conflists retain `type: cilium-cni`. Custom conflists using
either name remain valid.

**Evidence:** Spec 09 §3.12 already specifies the compatibility name and additional hard link.

**Remaining:** Installer tests must cover atomic replacement, existing names, and dispatch under both names.

## #124: Rust loopback plugin

**Decision / acceptance:** Implement loopback in Rust as an entry point of the CNI
executable, installed under `loopback` (with `flowsdn-loopback` permitted as an
additional name). Dispatch by invocation name and configuration type, with normal CNI
version/error handling. Do not bundle the Go loopback binary.

**Evidence:** Spec 09 ADR-0002 requires Rust; §3.12 still contradicted that rule by bundling upstream Go.

**Remaining:** Loopback ADD/CHECK/DEL, repeated calls, IPv4/IPv6, version negotiation
and installer tests remain required.

## #129: Rollback endpoint ownership (verification still open)

**Decision / acceptance:** Keep explicit endpoint deletion after successful PUT followed
by CNI failure. Rollback targets only the endpoint created by that attempt, uses
attachment/generation ownership checks against replacement races, and releases only its
own allocations. Endpoint-local policy removal and reference-counted identity release
must preserve every other endpoint.

**Evidence:** Spec 08 §3.8 scopes teardown and guards IP/CEP ownership; spec 03
§3.2–3.3 reference-count identities.

**Remaining:** Fault injection must include two endpoints sharing an identity and
replacement racing rollback; the safety contract is decided, not yet fully demonstrated.

## #132: Managed neighbors

**Decision / acceptance:** Use kernel-managed neighbors with `NTF_EXT_MANAGED` on the
supported kernel floor. Do not add the `NTF_USE` refresher fallback. Fail the startup
capability check when enabled neighbor management cannot be supported.

**Evidence:** Spec 10 §3.4 and the accepted 6.6 minimum already specify this deviation.

**Remaining:** Privileged tests must verify resolution, refresh, owned-entry pruning,
and refusal on a failed capability check.

## #136: Address scope default

**Decision / acceptance:** Set `address-scope-max` to 254 (`RT_SCOPE_HOST`). Retain the
unconditional `cilium_host` link-scope exception and the independent
loopback/IPv6-link-local filtering rules.

**Evidence:** Spec 10 Pinned reference `pkg/defaults/defaults_linux.go` uses
`int(netlink.SCOPE_HOST)`; `defaults_unspecified.go` pins 0xfe. This resolves
conflicting 252/253 guesses in §3.1.6 and §6.

**Remaining:** Config registration and scope-boundary tests at 253/254/255 plus the host
exception remain required.

## #137: Device filter lifetime

**Decision / acceptance:** Keep `devices` immutable after startup while continuing
dynamic device discovery and hotplug reconciliation. Preserve ordered first-match exact
names, trailing `+` prefix matching, and `!` exclusions from §3.1.2; reject other glob
syntax.

**Evidence:** Spec 10 §3.1.2 and §6 already distinguish filtering configuration from live device state.

**Remaining:** Grammar, exclusion ordering, immutable-update rejection, and hotplug tests remain required.

## #138: Endpoint routes

**Decision / acceptance:** Support `enable-endpoint-routes` as specified, including
per-endpoint delivery routes, encryption delivery variants, hairpin handling and netkit
scrub attributes. It remains a full feature obligation for cloud IPAM and chaining.

**Evidence:** Spec 10 §3.2.3 and spec 08 deletion/route ownership already contain the contract.

**Remaining:** Privileged cloud/chaining, decrypt, hairpin and netkit acceptance is still required.

## #139: Rule event reconciliation

**Decision / acceptance:** Subscribe to IPv4 and IPv6 rule notifications to enqueue
prompt reconciliation after rule changes. Keep periodic full resync to recover missed
events, coalesce bursts, and avoid self-triggered busy loops.

**Evidence:** Spec 10 §7 already recommends subscription after rule flush; §10 names both groups.

**Remaining:** Rule deletion/flush, event loss and repeated self-generated notification tests remain required.

## #144: Flow Summary compatibility

**Decision / acceptance:** Populate deprecated `Summary` for both L3/L4 and L7 flows
using the existing layer-derived strings. Lazy generation or a bounded cache may
optimize cost but must not change field presence or text.

**Evidence:** Spec 11 §3.9 and §3.12.3 define the strings; §4.13 retains field 100000.

**Remaining:** Golden protobuf/JSON and compact CLI rendering tests remain required; no
performance claim is made.

## #146: Drop reason names

**Decision / acceptance:** Keep numeric values, protobuf enum names, and monitor display
strings separately as specified. In particular 136 retains `CT_MISSING_TCP_ACK_FLAG`
with monitor text `Fragmentation needed`; 161 retains `FAILED_TO_INSERT_INTO_PROXYMAP`
with `NAT 46/64 not enabled`.

**Evidence:** Spec 11 §4.8 explicitly records these mismatches as compatibility data.

**Remaining:** Golden decoding, JSON enum serialization and filtering tests must cover both values.

## #173: Encryption constants

**Decision / acceptance:** Keep WireGuard UDP port 51871 and IPsec reqid 1 fixed. Do not
add configuration that silently changes interoperability or diagnostic selectors.

**Evidence:** Spec 14 §2 compatibility table and §3.1/§3.2 use these values.

**Remaining:** Mixed-peer and tooling tests remain required; a documented constant is
not encryption validation.

## #176: IPsec endpoint-route mark

**Decision / acceptance:** Apply zero output mark for enabled endpoint routes on both
subnet-encryption and single-CIDR IN-state paths. Preserve the existing
non-endpoint-route mark and mask behavior.

**Evidence:** Spec 14 §3.2.5 describes the discrepancy; §3.2.7 expects stack delivery with endpoint routes.

**Remaining:** Privileged single-CIDR/subnet, IPv4/IPv6 and endpoint-route on/off tests
must prove decrypted delivery and no plaintext leakage.

## #177: Node ID width

**Decision / acceptance:** Retain u16 node IDs and the existing mark layout. Allocate
only 1..65535; zero remains local-node sentinel, never an overflow substitute.
Exhaustion reports failure and must not install unsafe encryption state.

**Evidence:** Spec 10 §3.3.5 and spec 14 §2/§7 define the ABI and failure.

**Remaining:** Boundary/exhaustion and restore tests remain required; this does not
claim a tested 65535-node deployment.

## #179: Egress selectors

**Decision / acceptance:** Keep the reference globally flattened node-selector
cross-product with pod/namespace matches from §3.4.2. Do not silently reinterpret
selectors as paired per entry. An upstream proposal, if desired, is separate from this
local decision.

**Evidence:** Spec 14 §3.4.2 explains the existing-manifest semantic difference.

**Remaining:** Multi-entry policy fixtures must distinguish cross-product from paired semantics.

## #180: Node and encryption ownership

**Decision / acceptance:** Spec 10 owns routing table 200, its IP rules, node-ID
allocation and `cilium_node_map_v2` lifecycle. Spec 14 supplies encryption inputs and
owns XFRM/WireGuard state; it does not introduce a second route/map writer.

**Evidence:** Spec 14 Both specifications already state this split in their scope and data-model tables.

**Remaining:** Integration tests must cover startup ordering, node changes/deletion and
restoration without duplicate writers.

## #182: IPsec key forms

**Decision / acceptance:** Accept both AEAD and auth+crypt key-file forms with the
§3.2.2 validation and key derivation. Preserve accepted legacy syntax including the
ignored `+` suffix; do not narrow migration input to AEAD only. Warn about nonpreferred
algorithms without exposing key material.

**Evidence:** Spec 14 §2 and §3.2.2 already require both forms for existing secrets.

**Remaining:** Parser vectors, invalid lengths/algorithms, compatibility suffixes and
peer key derivation tests remain required.

## #188: BGP policy names

**Decision / acceptance:** Preserve the exact policy names generated by §3.7, including
`peer-<name>-export` and address-family/resource naming. Names are CLI and scenario
compatibility data.

**Evidence:** Spec 15 §3.7 and §4.1 expose the names outside the implementation.

**Remaining:** The twenty scenario expectations and REST/CLI fixtures remain required.

## #189: Ignored BGP override port

**Decision / acceptance:** Retain `CiliumBGPNodeConfigOverride.peers[].localPort` in the
schema and decoded type, but ignore it exactly as specified. Do not reinterpret it as a
local TCP source-port binding.

**Evidence:** Spec 15 §2 and §4.5 already mark the field ignored.

**Remaining:** Schema round-trip and session-configuration tests must prove that setting it has no effect.

## #190: ClusterIP advertisements

**Decision / acceptance:** Keep ClusterIP in the advertisement enum. When configured
while `bpf.lbExternalClusterIP` is disabled, warn at reconciliation naming that setting;
do not reject the advertisement solely for that reason. Operators may supply external
reachability separately.

**Evidence:** Spec 15 §4.3 includes the enum; §10 had contradictory MUST-NOT-offer text.

**Remaining:** Reconcile warning/acceptance tests and actual external ClusterIP datapath
tests remain separate obligations.

## #192: BGP backend scope

**Decision / acceptance:** Keep `bgp-backend` a node-level setting. Both in-tree BGP and
RouterOS backends remain in scope under the shared advertiser contract; do not mix
next-hop/status models per peer in one instance.

**Evidence:** Spec 15 §3.17 and §6 already make backend selection per node.

**Remaining:** Configuration validation and common contract tests for each backend remain required.
