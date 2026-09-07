# <Area> — specification

Status: draft. Derived from: `docs/inventory/<files>`, reference cilium v1.20.1
(7d68cfb394) paths `<list>`. Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes
*what* flowsdn does and the exact data it exchanges. It does not transcribe
reference code. Where the reference behavior is kept for compatibility, say
so and name the consumer that depends on it (cilium-dbg, Hubble, Envoy,
operator, other cluster). Where flowsdn deviates, mark **DEVIATION** with the
reason and the ADR.

## 1. Scope
What is in and out of this spec; pointers to sibling specs.

## 2. Compatibility contract
The exact interfaces that MUST match the reference: map names and layouts,
CRD fields, API paths, wire formats, file formats, config keys. Tables.

## 3. Behavior
Normative description of every feature in scope. One subsection per feature.
State machines as tables (state, event, next state, action). Pipelines as
ordered steps with the decision at each step.

## 4. Data model
Every struct, map, CRD, file. Field name, type, size, offset where layout
matters (`#[repr(C)]` targets), default, meaning. BPF maps: type, key, value,
max entries and the config key that sizes it, flags, pin path, owner.

## 5. Algorithms
Anything non-obvious: hashing (Maglev, identity), allocation, reconciliation
order, retry/backoff, GC. Enough detail that two implementers produce
interoperable results.

## 6. Configuration
Every config key that affects this area: name (reference-compatible), type,
default, validation, effect. Keys accepted but ignored (with reason).

## 7. Failure modes
What happens on each failure: missing kernel feature, map full, API server
unavailable, restart mid-operation, upgrade with layout change.

## 8. Observability
Metrics (names, labels — reference-compatible where dashboards depend on
them), monitor events, log fields, status/health exposure.

## 9. Test plan
Test cases as a checklist, derived from the reference's tests and
documented behaviors. Mark which are unit, privileged (kernel), e2e.

## 10. Kernel and platform requirements
BPF helpers, map/program types, netlink families, modules, minimum kernel,
x86-64 vs arm64 notes.

## 11. Rust design notes
Crate boundaries, key types and traits, chosen dependencies, aya gaps to
fill. Not code.

## 12. Open decisions
Numbered. Each with options and a recommendation.
