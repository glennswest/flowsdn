# Dependency capability source audit — 2026-09-22

Scope: issues #25 and #30; coordinator-selected snapshots fastetcd `cf53856`
and rustkube `e45acc7`. This is a source inventory with bounded test execution recorded below;
it does not establish deployed-server conformance. Paths below are
relative to the named dependency repository. No dependency repository was edited.

## fastetcd: ClusterMesh prerequisites (#25)

| Required behavior | Source evidence | Executable Rust evidence (passed on Linux) |
|---|---|---|
| Txn compare on version | `crates/server/src/conv.rs` maps protobuf Version to MVCC Version; `crates/storage/src/mvcc/store.rs::eval_compare` | Storage `txn_success_branch_runs_when_compares_pass`, `txn_failure_branch_runs_when_compares_fail`, `txn_compare_on_absent_key_uses_zero_record`; these use `cmp_version_eq`. Server `txn_success_branch_runs_when_compare_holds` tests **value**, not version; an explicit gRPC version-zero CAS remains useful integration coverage. |
| Limited range Count/More | MVCC `range_in_ctx` counts matching keys before limiting; server `kv.rs` forwards both fields | Storage `range_limit_marks_more` asserts More and total Count=3; `count_only_returns_count_without_values`. |
| Stale-watch compaction | Server watch cancels and returns compact revision | `watch_grpc::watch_at_compacted_revision_returns_canceled` asserts created+canceled+compact_revision=2 for start revision1. The client must convert this wire result into its compacted/relist path. |
| Per-key lease | Lease attachment preserved in KV conversion | `etcd_client_compat::lease_grant_attach_revoke_via_etcd_client` asserts returned lease ID and revocation cascade. |
| Per-key mod_revision | MVCC revision records and server KV conversion | `kv_grpc::put_then_range_round_trips` asserts mod_revision1; storage `second_put_increments_version_keeps_create_rev` exercises updates. |
| ResponseHeader.cluster_id | `crates/server/src/state.rs` constructs headers from configured cluster ID | `kv_grpc::put_then_range_round_trips` asserts header cluster_id7. This alone does not test identity persistence across cluster reconfiguration. |

Run in a checkout of the stated fastetcd revision:

```text
cargo test -p fastetcd-storage --lib
cargo test -p fastetcd-server --test kv_grpc --test watch_grpc --test etcd_client_compat
```

Executed on Linux at the stated revision: **53 storage tests and 20 server
integration tests passed** (8 etcd-client, 6 KV, 6 watch). The server integration
fixtures start temporary local servers themselves. These
commands cover the named prerequisites; they do not establish flowsdn watch
resumption, deployment interoperability, or multi-node failure recovery.

## rustkube: API-server matrix (#30)

| Capability | Current source finding | Existing test / missing reproducible probe | flowsdn consequence |
|---|---|---|---|
| CEL validation | Absent from CRD write path; `crd.rs::validate_crd` checks resource registration, not object schema | No CEL evaluator/test found. C3: submit missing spec/specs and violate oldSelf immutability. | Validate before using policies; do not trust server acceptance as validation. |
| CRD schema defaulting | Absent from CR create/update paths; listKind/name defaults are separate | C4: omit ICMP family and read back; no schema-default test found. | Apply specified client-side defaults. |
| x-kubernetes-list-type=map | No schema-driven list-map machinery found | C6: repeated same-key list entry through update/patch; schema-lite strategic merge is not proof. | Reconcile complete keyed lists with resourceVersion protection. |
| Strategic merge patch | Partial: `handlers/resource.rs::strategic_merge_key` recognizes fixed field names, including conditions/type; not arbitrary schema | `strategic_merge_conditions_by_type`; C15 HTTP nodes/status still needed | Use documented JSON patch/merge-patch contracts; no general Kubernetes strategic-merge claim. |
| Status subresources | Routes exist and status PUT preserves spec; incomplete isolation: `crd_update_ns` writes the supplied body, including status. Status PUT uses freshly read RV rather than the submitted RV | `kubelet_pod_status_put_shape_is_safe` is a shape test, not CRD C12. Probe main endpoint status overwrite and stale status PUT. | Route availability does not establish status concurrency/isolation; required C12 remains failing/pending remediation. |
| spec.nodeName/status.phase selectors | Generic dotted-field resolver and list/watch filtering exist | `selector::tests::test_field_selector` covers metadata.name only. C18 needs pods split by node and phase. | Keep selector use behind confirmed capability; fallback to local filtering where allowed. |
| PartialObjectMetadata | Negotiation and projection exist in resource/watch handlers | `partial_object_metadata_projection`; C20 HTTP list/watch negotiation still needed | Capability plausible from source; no deployed-server pass. |
| Watch bookmarks | Idle bookmarks and WatchList end marker implemented | `initial_events_end_bookmark_is_annotated`, `selectors_and_watch_flags_decode` | Bookmarks remain optional hints; stream progress runtime probe pending. |
| Stale revision →410/relist | Not satisfied by audited path: `watch_cache.rs` falls back to storage for old RV; `pkg/storage/src/adapter.rs::watch` loops events without handling canceled/compact_revision | C23: compact backing store past requested RV, open watch, demand HTTP410 or ERROR Status410. No matching test found. | Cannot certify gap-free watch/relist; server capability blocker, not merely a client filtering fallback. |
| Protobuf content type | Middleware and typed codecs implemented, with bounded supported type universe | apimachinery `pod_round_trips_quantity_intorstring_bytes_and_maps`, `lease_json_round_trips_through_protobuf`; apiserver `path_gvk_derivation`; C21 HTTP probe pending | JSON-first client remains valid; no global protobuf-negotiation pass. |
| Leases | Resource kind/API-version routing and storage CAS exist | Codec lease test does not prove contention. C26: two stale-RV writers on one Lease, require exactly one success | Leader-election integration requires contention probe. |
| CRD Established | `establish_crd_status` generates NamesAccepted/Established=True | `establishes_names_conditions_and_stored_versions`, `all_served_versions_register`; conflicting-plural C1 still needed | Positive establishment exists; conflict validation not established by positive-condition test. |

Run existing unit suites in a checkout of the stated rustkube revision:

```text
cargo test -p apiserver --lib
cargo test -p apimachinery --lib
```

Executed at the stated rustkube revision: **126 apiserver and 58 apimachinery
unit tests passed** on Linux. The table names actual tests and explicitly
separates uncovered HTTP probes.
No command is offered as a substitute for those missing probes. The complete
spec13 C1–C36 standalone conformance runner remains an implementation obligation;
this audit does not claim it exists or passes. In particular rustkube at this
snapshot cannot be certified against all Required rows by running unit tests.
