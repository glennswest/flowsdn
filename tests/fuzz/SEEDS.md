# Fuzz targets — reference survey and flowsdn plan

Reference: cilium/cilium **v1.20.1**, commit **7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc**,
Apache-2.0. Surveyed 2026-09-07. Governed by
[ADR-0005](../../docs/decisions/0005-test-strategy.md).

## Counting

```
$ grep -rn '^func Fuzz[A-Za-z0-9_]*(' --include='*.go' . --exclude-dir=vendor | wc -l
19
$ grep -c compile_native_go_fuzzer test/fuzzing/oss-fuzz-build.sh
19
```

19 `Fuzz*` functions in 9 packages, and all 19 are registered with OSS-Fuzz in
`test/fuzzing/oss-fuzz-build.sh`. `test/fuzzing/go-fuzz.sh` re-parses that build
script to run them locally (`FUZZ_TIME` seconds each). There is no fuzz target
anywhere in `bpf/` and none in `daemon/` or `operator/`.

Sixteen of the nineteen use `github.com/AdaLogics/go-fuzz-headers`
(`fuzz.NewConsumer(data)` → `GenerateStruct` / `CreateSlice` / `FuzzMap` /
`GetString` / …), which is a *structure-aware* decoder over a flat byte slice.
Its Rust analogue is `arbitrary::Arbitrary` + `cargo-fuzz`, and the mapping is
near mechanical: `GenerateStruct(&T{})` becomes `#[derive(Arbitrary)]` on `T`,
`CreateSlice` becomes `Vec<T>`, `GetUint16` becomes `u.arbitrary::<u16>()`.
The three that do not use it (`FuzzLabelsParse`, `FuzzMatchpatternValidate*`,
`FuzzNewLabels`, `FuzzUint8`) take raw `[]byte`/`string` and map to
`fuzz_target!(|data: &[u8]|)` directly.

## Seed corpora on disk

Only **two** of the nineteen targets have a checked-in corpus. Everything else
starts from an empty corpus plus one inline `f.Add` seed (there is exactly one
`f.Add` call in the whole tree, in `FuzzUint8`).

```
$ find . -path ./vendor -prune -o -type d -name fuzz -print
./pkg/policy/testdata/fuzz          # FuzzDistillPolicy — 27 files
./pkg/container/bitlpm/testdata/fuzz # FuzzUint8 — 3 files
$ grep -rn 'f\.Add(' --include='*fuzz_test.go' pkg
pkg/container/bitlpm/fuzz_test.go:22: f.Add([]byte{0b1111_1111, 4})
```

Both corpora are copied verbatim to `corpus/FuzzDistillPolicy/` (27 files) and
`corpus/FuzzUint8/` (3 files); see `corpus/PROVENANCE` for the format and the
conversion note. The files are in Go's `testing.F` corpus format
(`go test fuzz v1` header line, then a Go `[]byte("…")` literal) and need a
one-off unquoting pass before `cargo-fuzz` can read them.

## The 19 targets

`Rec.` column: **carry** = write the equivalent target in flowsdn;
**carry (adapted)** = carry the property but against flowsdn's own type;
**skip** = the target guards a Go-specific hazard flowsdn does not have.

| # | Target | Reference file | What it fuzzes | Input shape | Seeds on disk | Rec. | Priority |
|---|---|---|---|---|---:|---|---|
| 1 | `FuzzDistillPolicy` | `pkg/policy/simulate_fuzz_test.go:27` | **Differential**: generates a random rule set, resolves it to map state, then evaluates a fixed set of flows against *both* the compiled map state and an independent reference simulator, and fails if the verdicts diverge. | Raw `[]byte`, decoded by `makeFuzzEntries()` into a packed sequence of rule descriptors (direction, default-deny, selector, port range, protocol, deny flag). | **27** | **carry** | **1** |
| 2 | `FuzzDistillPolicyWithAggregates` | `pkg/policy/simulate_fuzz_test.go:299` | Same differential property, but with the aggregate/reserved identities in play (`world`, `world-ipv4`, `remote-node`, `kube-apiserver`, a node identity, a CIDR identity). This is where identity-precedence bugs surface. | Same, via `makeFuzzEntriesAggregated()`. | 0 (shares 1's corpus dir in practice) | **carry** | **1** |
| 3 | `FuzzDenyPreferredInsert` | `pkg/policy/fuzz_test.go:44` | `MapState.insertWithChanges()` at `MaxDenyPrecedence` with an arbitrary `Key`+`MapStateEntry`. Catches panics and broken invariants in the deny-preferred insert path. | go-fuzz-headers `GenerateStruct(&Key{})` + `GenerateStruct(&MapStateEntry{})`. | 0 | **carry** | **1** |
| 4 | `FuzzAccumulateMapChange` | `pkg/policy/fuzz_test.go:56` | `MapChanges.AccumulateMapChanges()` + `SyncMapChanges()` with arbitrary add/delete identity slices, port, protocol, redirect and deny flags. The incremental-update path, which is the one that silently corrupts state rather than crashing. | Slices of `NumericIdentity`, a `u16` port, a `u8` protocol, two bools. | 0 | **carry** | **1** |
| 5 | `FuzzResolvePolicy` | `pkg/policy/fuzz_test.go:19` | Full pipeline: arbitrary `api.Rule` → `Sanitize()` → repository add → `resolvePolicyLocked()` → `DistillPolicy()`. Endpoint selector is forced to one that matches so policy is actually evaluated. | `GenerateStruct(&api.Rule{})` — the whole CNP rule struct. | 0 | **carry** | **2** |
| 6 | `FuzzUint8` | `pkg/container/bitlpm/fuzz_test.go:16` | LPM trie invariants: bytes are read as `(value, prefix_len)` pairs, inserted, then `Len()`, `Ancestors()`-returns-longest-prefix and delete-decrements-`Len()` are asserted. A real property test, not just a crash hunt. | Raw `[]byte`, pairs. One inline `f.Add([]byte{0xFF, 4})`. | **3** | **carry** | **2** |
| 7 | `FuzzCiliumNetworkPolicyParse` | `pkg/k8s/apis/cilium.io/v2/fuzz_test.go:13` | `CiliumNetworkPolicy.Parse()` — CRD object → internal rule list, including label derivation and cluster-name handling. | `GenerateStruct(&CiliumNetworkPolicy{})` + a cluster-name string. | 0 | **carry** | **2** |
| 8 | `FuzzCiliumClusterwideNetworkPolicyParse` | `pkg/k8s/apis/cilium.io/v2/fuzz_test.go:23` | Same for CCNP (no namespace, different default label set). | `GenerateStruct(&CiliumClusterwideNetworkPolicy{})` + cluster name. | 0 | **carry** | **2** |
| 9 | `FuzzMatchpatternValidate` | `pkg/fqdn/matchpattern/fuzz_test.go:7` | `matchpattern.Validate()` — the FQDN `matchPattern` mini-language (`*`, `*.example.com`, escaping) compiled to a regexp. A pattern that compiles to a catastrophically backtracking regexp is a DNS-proxy DoS. | Raw `string`. | 0 | **carry** | **2** |
| 10 | `FuzzMatchpatternValidateWithoutCache` | `pkg/fqdn/matchpattern/fuzz_test.go:13` | Same, bypassing the compiled-pattern cache — catches divergence between the cached and uncached paths. | Raw `string`. | 0 | **carry (adapted)** — only if flowsdn caches compiled patterns; fold into #9 otherwise. | 3 |
| 11 | `FuzzLabelsParse` | `pkg/k8s/slim/k8s/apis/labels/fuzz_test.go:7` | `labels.Parse()` on the upstream k8s label-selector string grammar. | Raw `string`. | 0 | **carry** | **2** |
| 12 | `FuzzNewLabels` | `pkg/labels/fuzz_test.go:8` | `Label.UnmarshalJSON()` — the JSON form of a Cilium label, including the `source:key=value` shorthand. Feeds the canonical-key-form invariant. | Raw `[]byte` (JSON). | 0 | **carry** | **2** |
| 13 | `FuzzLabelsfilterPkg` | `pkg/labelsfilter/fuzz_test.go:18` | `ParseLabelPrefixCfg()` on a generated label-prefix-config JSON file plus `Filter()` on a generated label map. Exercises the include/exclude prefix precedence rules that decide which pod labels reach identity. | Generated `[]string` prefixes, `[]string` node prefixes, a `labelPrefixCfg` struct marshalled to a temp JSON file, a `map[string]string`, a source string. | 0 | **carry** | **2** |
| 14 | `FuzzMapSelectorsToNamesLocked` | `pkg/fqdn/namemanager/fuzz_test.go:16` | `NameManager.mapSelectorsToNamesLocked()` — an arbitrary `api.FQDNSelector` (`matchName` / `matchPattern`) resolved against the DNS cache. | `GenerateStruct(&api.FQDNSelector{})`. | 0 | **carry** | 3 |
| 15 | `FuzzParserDecode` | `pkg/hubble/parser/fuzz_test.go:22` | `parser.Decode()` on an arbitrary `MonitorEvent` whose payload is one of `PerfEvent`, `AgentEvent`, `LostEvent` — i.e. the ring-buffer bytes coming off the datapath. **The only target on an attacker-adjacent wire format.** | An int selecting the payload kind, then `GenerateStruct` of that payload; `PerfEvent.Data` is the raw perf record. | 0 | **carry** | **1** |
| 16 | `FuzzFormatEvent` | `pkg/monitor/format/fuzz_test.go:21` | `MonitorFormatter.FormatEvent()` on an arbitrary `payload.Payload` — the `cilium-dbg monitor` renderer. Guards against a malformed datapath record panicking the CLI. Upstream deliberately calls `runtime.GC()` per iteration and swallows panics with `recover()`, which makes it slow and weakens it. | `GenerateStruct(&payload.Payload{})` with `len(Data) > 0`. | 0 | **carry (adapted)** — in Rust the formatter must not panic at all, so drop the `recover()` equivalent and let a panic fail the run. | 3 |
| 17 | `FuzzJSONService` | `pkg/loadbalancer/fuzz_test.go:93` | Round-trip property: `Service` → JSON → `Service`, then assert `TableRow()` is identical. Guarantees the REST/`cilium-dbg` table view survives serialisation. | `GenerateWithCustom(&Service{})` with custom generators producing valid `netip.Addr` and printable strings. | 0 | **carry (adapted)** — flowsdn has no StateDB (ADR-0004), but it does have a table crate and the same REST contract, so the property survives as "row rendering is invariant under serde round-trip". | 3 |
| 18 | `FuzzJSONFrontend` | `pkg/loadbalancer/fuzz_test.go:97` | Same for `Frontend`. | Same. | 0 | **carry (adapted)** | 3 |
| 19 | `FuzzJSONBackend` | `pkg/loadbalancer/fuzz_test.go:101` | Same for `Backend`. | Same. | 0 | **carry (adapted)** | 3 |

Every one of the nineteen is recommended for flowsdn in some form. None is
recommended **skip**: there is no target here whose only value is guarding a
Go-specific hazard. The three "adapted" groups (10, 16, 17–19) change shape
rather than disappear.

## What is missing from the reference's fuzz estate

The reference fuzzes the *policy compiler* thoroughly and almost nothing else.
Given ADR-0005's premise that flowsdn's risk is in the same places, these are
the targets flowsdn **should add that have no reference equivalent**:

| Proposed target | Property | Why it matters here |
|---|---|---|
| `fuzz_ct_key_roundtrip` | Conntrack tuple → `#[repr(C)]` key bytes → tuple is the identity, for both address families and both directions. | The CT/NAT key layout is a byte-for-byte ABI (`docs/spec/01-bpf-map-abi-loader.md`). A one-field mis-order is invisible until traffic breaks. |
| `fuzz_maglev_determinism` | For an arbitrary backend set and weights, two independent computations of the lookup table are identical, and removing a backend perturbs at most the expected fraction of entries. | Maglev must be *bit-identical across nodes*, not merely correct. A differential fuzz against a straight-line reference implementation is the only cheap way to be sure. |
| `fuzz_lpm_prefix_map` | Insert/lookup/delete invariants on the CIDR/LPM structure, and agreement between the userspace trie and what the BPF LPM map would answer. | Generalises `FuzzUint8` (#6) from `u8` to real v4/v6 prefixes, which is where ipcache precedence lives. |
| `fuzz_ipcache_metadata_precedence` | For an arbitrary set of `(prefix, resource, source, labels)` upserts applied in an arbitrary order, the resolved identity per prefix is independent of insertion order. | Order-independence is the whole contract of ipcache metadata merging, and it is exactly the kind of thing that passes every hand-written test. |
| `fuzz_identity_key_canonical` | Label set → canonical identity key → label set round-trips, and two label sets that differ only in ordering or duplicate entries produce the same key. | Two nodes that canonicalise differently allocate two identities for one workload. Silent, and it breaks policy cluster-wide. |
| `fuzz_cnp_yaml_parse` | Arbitrary bytes into the CRD deserialiser must not panic and must not accept a rule that later panics the policy compiler. | flowsdn parses CRDs with serde, not Go reflection; the failure modes are different and untested by the reference. |

## Rust tooling

`cargo-fuzz` (libFuzzer) with `arbitrary` for structure-aware inputs, corpora
under `tests/fuzz/corpus/<target>/`, and the differential targets (#1, #2, plus
the proposed `fuzz_maglev_determinism`) additionally runnable as bounded
`proptest` cases in normal CI so they are not fuzzing-only. Fuzz targets that
require kernel access (any BPF map interaction) run only in the privileged CI
lane; the rest run on every PR for a short budget, mirroring
`test/fuzzing/go-fuzz.sh`'s `FUZZ_TIME` approach.
