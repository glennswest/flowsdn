# ADR-0005: Harvest the reference's tests. All harnesses in Rust.

Date: 2026-09-07. Status: accepted (user decision: harvest QE/QA tests, in Rust).

## Context

The reference carries a large and genuinely good test estate. Measured at
v1.20.1:

| Corpus | Size | Nature |
|---|---|---|
| txtar script tests | **168 files** (LB 51, BGP 20, redirect policy 12, Envoy config 12, clustermesh 9, policy 5, k8s client 5, linux datapath 5, route reconciler 5, hubble exporter 4, neighbor 4, device 4, …) | **Declarative data**: a command script plus embedded input YAML and expected-output tables |
| BPF unit tests | **141 C files, 397 `CHECK` cases** | Packet fixtures + assertions, run under `BPF_PROG_RUN` |
| Control-plane golden tests | 18 YAML fixtures + suite | k8s input → expected agent state |
| Go unit tests | **3040 `Test*` functions**, 222k lines | Code; many table-driven with harvestable tables |
| Go fuzz targets | 19 | Seeds are data |
| Other testdata/golden dirs | 44 directories | Mixed data |

The connectivity test suite is **not in this tree** at v1.20.1 — `cilium-cli`
moved to its own repository. Inventory 15's "adopt cilium-cli connectivity
test" therefore means consuming an external Go binary, which conflicts with
"tests in Rust". Resolved below.

## Decision

**1. Harvest data verbatim; write every harness in Rust.**

The txtar scripts, YAML fixtures, expected-output tables, golden files and
fuzz seeds are *data*. Copying them verbatim is the sensible engineering
choice already permitted by `docs/licensing.md`. Each harvested file (or its
directory) carries a header or `PROVENANCE` file naming the reference path,
the commit `7d68cfb394`, and the applicable license, with a matching `NOTICE`
entry. No Go or C test *code* is copied.

**2. Licensing per corpus.**

| Corpus | Reference license | flowsdn action |
|---|---|---|
| txtar, testdata YAML, golden files, fuzz seeds (outside `bpf/`) | Apache-2.0 | Copy verbatim with attribution |
| `bpf/tests/**` | GPL-2.0-only OR BSD-2-Clause | Take **BSD-2-Clause**; port case *names, packet shapes and assertions*, not C code |
| Documentation-derived behaviors | CC BY 4.0 | Cite in the spec, not the test |

**3. Four Rust harnesses.**

- `flowsdn-scripttest` — interprets the txtar format: the `#!` flag line, the
  command script, embedded files, and `cmp`-style assertions. Commands are a
  registry of Rust closures (`hive start` → `agent start`, `k8s/add`,
  `db/cmp`, `lb/maps-dump`, `test/init-wait`, …). This is the single highest
  leverage item in the whole test plan: it makes 168 scenario files run
  against flowsdn with no per-file work.
- `flowsdn-bpftest` — userspace-driven `BPF_PROG_RUN` with declarative packet
  builders, running the real programs and asserting on verdict, packet bytes
  and map state. The 397 `CHECK` cases become a checklist.
- `flowsdn-cptest` — control-plane golden tests: feed k8s objects, snapshot
  agent state, compare to golden.
- `flowsdn-connectivity` — a Rust reimplementation of the connectivity suite
  (pod-to-pod, pod-to-service, NodePort, DNS, policy allow/deny, encryption,
  egress) run as a binary against a live cluster. **DEVIATION**: not the
  upstream Go `cilium-cli`; upstream may still be run manually for
  cross-checking during bring-up.

**4. Naming preservation (resolved #213).** The audited rewrite set is empty
for the pinned harvested script corpus. Keep reference flags, command names,
map/metric symbols and embedded paths. `cargo xtask audit-corpus --check`
compares a reviewed inventory and rejects unclassified startup names. See
`tests/scripttest/NAMING.md` for all six non-agent-catalogue inputs. If a future
reference bump requires a rename, use an explicit reviewed mapping in a Rust
tool with provenance and differential checks; never hand-edit harvested data.

## Consequences

- The test corpus is a first-class deliverable, specified in
  `docs/spec/17-scripttest-harness.md`, and the scripttest harness is built early —
  before the load balancer, since 51 of its scenarios are LB tests.
- Divergences flowsdn chooses deliberately (ADR-0002/0003 especially: no
  iptables rules to assert on, different kernel floor) will make some
  harvested scenarios fail by design. Each such file is annotated with an
  expected-divergence marker rather than deleted, so a re-harvest still works.
- A harvested corpus tracks one reference tag. Bumping the tag is a
  deliberate, reviewed operation.

## Control-plane harness contract (2026-09-21, #261)

The fourth harness is specified in [spec 23](../spec/23-control-plane-golden-tests.md).
Its deterministic event/fence protocol, manifest, state comparison, normalization,
failure and cleanup behavior are normative. The spec resolves the missing
contract; implementing adapters and demonstrating corpus coverage remain #294.


## External conformance artifact exception (#290)

Amended 2026-09-22. The Ingress controller conformance suite and Gateway API
conformance suite named in spec21 §§9.4–9.5 may run as **upstream-owned,
published binaries or immutable upstream-published container images**. Their
implementation language does not turn them into flowsdn-authored harnesses.
Pin release/version and cryptographic artifact digest, verify source/provenance,
and retain the exact invocation and conformance report with release evidence.
If a suitable published artifact does not exist, the gate remains blocked;
this exception does not authorize compiling a Go suite from source.

All flowsdn-authored orchestration, wrappers, fixtures generators and test code
remain Rust. Do not copy, modify or author Go; do not add a Go toolchain or Go
source build to this repository's CI. The exception does not extend to arbitrary
upstream unit tests, helper programs or cilium-cli connectivity tests; the four
Rust harnesses and their corpus obligations above remain unchanged.

This records permission to consume these two specification-owned artifacts,
not evidence that CI integration, trusted artifact pins or conformance runs
have been delivered. Spec21's profiles and individually owned exemptions
remain the acceptance contract.

## Amendment: older control-plane fixtures (#36)

The four removed control-plane families may use static data from pinned
v1.16.0 and v1.17.0 alongside the primary v1.20.1 reference. Each recovered
input/expected file carries exact tag, commit, source path and Git blob identity
in a manifest, with license attribution. Differing old expectations stay
separate; no old expectation silently overrides current behavior. The Rust
harvester verifies bytes without executing old Go tests. Adapter implementation
and compatibility decisions remain separate acceptance work.
