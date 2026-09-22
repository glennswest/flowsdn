# tests/golden — harvested data fixtures

Data-shaped test fixtures copied verbatim from the reference implementation
(cilium/cilium **v1.20.1**, commit **7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc**,
Apache-2.0) on **2026-09-07**, under
[ADR-0005](../../docs/decisions/0005-test-strategy.md): *harvest the data, write
every harness in Rust*. No Go or C test **code** was copied.

Each subdirectory carries a `PROVENANCE` file naming the exact reference path,
the commit, the license, the copy date, what the fixture pins down, which
flowsdn spec consumes it, and whether anything was modified.

## What was harvested

| Directory | Files | Bytes | Reference path | What it pins down | Consumed by |
|---|---:|---:|---|---|---|
| `04-loadbalancer-benchmark/` | 2 | 840 | `pkg/loadbalancer/benchmark/testdata` | Service + EndpointSlice seeds for LB control-plane scaling | `docs/spec/05-service-loadbalancing.md` §9 |
| `06-bugtool-envoy-config/` | 2 | 1,022,767 | `bugtool/cmd/testdata` | Envoy `/config_dump` before/after bugtool's TLS-secret redaction pass | `docs/spec/08-endpoint-agent-api.md`, `docs/spec/16-l7-envoy-dns.md` |
| `06-health-cli-output/` | 8 | 4,550 | `pkg/health/client/testdata` | Exact rendered `cilium-health status` text for {all healthy, one unhealthy, eleven unhealthy} × {default, `--all-nodes`, `--verbose`} | `docs/spec/08-endpoint-agent-api.md` §8 |
| `08-operator-gateway-api/` | 604 | 1,353,711 | `operator/pkg/gateway-api/testdata` | Gateway API conformance as data: parentRef resolution, hostname intersection, ReferenceGrant, exact `Accepted`/`ResolvedRefs`/`Programmed` condition reasons | `docs/spec/12-operator.md` (deferred area) |
| `08-operator-model-ingestion/` | 324 | 234,234 | `operator/pkg/model/ingestion/testdata` | k8s objects → internal model: which listeners, matchers, redirects, rewrites, mirrors, timeouts and weights come from which fields | `docs/spec/12-operator.md`, `docs/spec/16-l7-envoy-dns.md` |
| `08-operator-model-translation-gateway-api/` | 207 | 352,128 | `operator/pkg/model/translation/gateway-api/testdata` | model → CiliumEnvoyConfig: listener/filter-chain/HCM/route/cluster shape, host-network, ext-authz, XFF, gRPC-Web | `docs/spec/12-operator.md`, `docs/spec/16-l7-envoy-dns.md` |
| `08-operator-model-translation-ingress/` | 14 | 55,687 | `operator/pkg/model/translation/ingress/testdata` | Ingress → CEC: path/host rules, default backend, proxy protocol, force-HTTPS | `docs/spec/12-operator.md` |
| `09-hubble-exporter-config/` | 5 | 2,021 | `pkg/hubble/exporter/testdata` (YAML only) | Flow-log config schema; four rejection cases (empty, duplicate names, duplicate paths, malformed) | `docs/spec/11-hubble-monitor.md` §6 |
| `09-hubble-metrics-config/` | 8 | 1,390 | `pkg/hubble/metrics/testdata` | Hubble metrics handler config, `contextOptions` label dimensions, one invalid config | `docs/spec/11-hubble-monitor.md` §6, §8 |
| `13-k8s-objects/` | 2 | 1,804 | `pkg/k8s/testutils/testdata` | Real API-server CiliumNode and core/v1 Service, as decode/round-trip fixtures | `docs/spec/13-crds-k8s-client.md` §2 |
| `14-ipsec-xfrm-stat/` | 1 | 778 | `cilium-dbg/cmd/fixtures/proc/net` | `/proc/net/xfrm_stat` counter names → IPsec error classes | `docs/spec/14-encryption-egress.md` §8 |
| `controlplane/` | 19 | 151,308 | `test/controlplane` (YAML + `k8s_versions.txt`) | Node label add/remove/change → derived CiliumNode labels, captured against API-server v1.24, v1.25 and v1.26 | `docs/spec/13-crds-k8s-client.md`, `docs/spec/10-node-routing-nftables.md`; run by `flowsdn-cptest` |
| **Total** | **1,196** | **3,181,218** | | | |

Counts are `find -type f ! -name PROVENANCE | wc -l` and the concatenated byte
count, measured 2026-09-07.

## The one modification

`06-bugtool-envoy-config/envoy-config-input.json` had its four EC private-key
PEM blobs replaced with the literal placeholder

```
-----BEGIN EC PRIVATE KEY-----
REDACTED-BY-FLOWSDN-HARVEST-NOT-A-KEY
-----END EC PRIVATE KEY-----
```

so that no PEM private key — not even a synthetic upstream test key — is
committed to this repository. The JSON structure and every other field are
unchanged, and the expected output file is byte-identical, so the assertion the
fixture exists to make (does the redactor scrub `private_key`,
`certificate_chain` and `trusted_ca`?) is unaffected. Certificate (public)
blobs are unchanged. Every other file in this tree is byte-identical to the
reference; each `PROVENANCE` states which.

## What was deliberately *not* harvested here

| Corpus | Where it goes instead | Why |
|---|---|---|
| **`.txtar` script tests** — 168 files across **29** directories (LB tests 51, BGP test 20, redirect policy 12, CiliumEnvoyConfig 12, clustermesh-apiserver 9, policy test 5, k8s client testutils 5, linux datapath 5, route reconciler scripttest 5, hubble exporter scripts 4, neighbor test 4, device scripttest 4, pkg/clustermesh 4, metrics 3, healthserver 3, dynamicconfig 3, operator watchers 3, k8s tables 2, egressgateway 2, operator nodesgc 2, operator ipam/multipool 2, subnet 1, kvstore 1, podippool 1, ipam migration 1, hive health 1, BGP reconciler 1, contrib example 1, mcsapi-coredns-cfg 1) | `tests/scripttest/` | Owned by a sibling agent; ADR-0005 §3 makes them the `flowsdn-scripttest` harness's input. **Not touched by this harvest.** |
| **`bpf/tests/**`** — 141 C files, 397 `CHECK` cases | owned by a sibling agent | ADR-0005 §2: GPL-2.0-only OR BSD-2-Clause, taken under BSD-2-Clause, and only case names/packet shapes/assertions port. |
| `pkg/bpf/testdata` — 5 `.o`, 5 `.c`, `Makefile`, 1 `.h` | not harvested | Compiled BPF objects and the C that produced them. flowsdn's loader tests must be fed objects built from flowsdn's own `aya-ebpf` programs (ADR-0002), so a reference `.o` proves nothing about our loader. |
| `pkg/alignchecker/testdata` — 1 `.o`, 1 `.c` | not harvested | Same reason. The struct-alignment check is against flowsdn's own object. |
| `tools/metricslint/pkg/analyzer/testdata` — 1 `.go` | not harvested | Go source for a Go static-analysis pass. flowsdn has no equivalent lint. |
| `pkg/policy/testdata/fuzz`, `pkg/container/bitlpm/testdata/fuzz` — 30 files | `tests/fuzz/corpus/` | Fuzz seed corpora; see `tests/fuzz/SEEDS.md`. |
| `test/controlplane/suite/**` and the suite's `*.go` | not harvested | Test *code*. `flowsdn-cptest` is written in Rust (ADR-0005 §3). |
| `examples/**` YAML | not harvested | Documentation examples; no test reads them (verified: no `_test.go` under `pkg/`, `daemon/`, `operator/` references `examples/`). |
| PCAP fixtures | none exist | Searched the whole non-vendor tree for `*.pcap*`: **zero files**. The reference's packet fixtures are C structs in `bpf/tests`, not capture files. |
| Certificate fixture files | none exist | Searched for `*.pem`, `*.crt`, `*.key`, `*.cert` outside `vendor/`: **zero files**. `pkg/crypto/certloader`'s 30 tests generate their key material in Go at run time, so there is nothing to copy — flowsdn generates its own with `rcgen`. |
| `.table` / protobuf-text golden files | none exist | Searched for `*.table`, `*.textproto`, `*.pb.txt`: **zero files**. Expected StateDB table output lives inline inside the `.txtar` files, which is the sibling agent's corpus. |

## Re-harvesting

The primary harvest tracks one reference tag (ADR-0005 "Consequences").
The explicit #36 exception under `controlplane-legacy/` preserves removed
control-plane fixtures from pinned v1.16.0 and v1.17.0 with per-file provenance;
it does not change the primary tag or reinterpret old outputs as current behavior.
To move the primary corpus to a newer tag, re-run the copy, diff, and update every `PROVENANCE` commit line in
the same change. Do not hand-edit fixtures: divergences flowsdn chooses
deliberately are recorded as expected-divergence annotations in the harness,
not by mutating the data.

## Recovered historical control-plane cases

[`controlplane-legacy/`](controlplane-legacy/README.md) adds HostPort, dual-stack
Service, graceful-termination and NodePort inputs and golden outputs removed by
v1.20.1. The 100 tagged source records occupy 68 unique static files; shared
inputs are deduplicated, differing expected outputs stay versioned. A Rust
verification/restoration tool checks exact pinned Git objects. Runtime adapters
remain pending; no Go/shell harness was copied.
