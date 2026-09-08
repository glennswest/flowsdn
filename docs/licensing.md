# Licensing and clean-room protocol

## Reference implementation licenses

| Component | Repo | License | What we may do |
|---|---|---|---|
| Agent, operator, CLI, Hubble, Go libraries | cilium/cilium (everything outside `bpf/`) | Apache-2.0 | Read freely. Copy only with attribution in file header + NOTICE. |
| BPF datapath | cilium/cilium `bpf/` | GPL-2.0-only OR BSD-2-Clause | Take under BSD-2-Clause if copied. Read freely. |
| Envoy build with Cilium filters | cilium/proxy | Apache-2.0 | Consume as an external image unchanged. |
| Hubble UI | cilium/hubble-ui | Apache-2.0 | Consume unchanged; we implement the server API it talks to. |
| Documentation | docs.cilium.io | CC BY 4.0 | Use as a spec source with attribution. |
| Helm chart | cilium/cilium `install/kubernetes` | Apache-2.0 | Value names may be reused; they are an interface, not code. |

## Trademarks

"Cilium" and "Hubble" are trademarks of The Linux Foundation. flowsdn uses
those words only to describe compatibility ("Hubble-compatible API",
"accepts CiliumNetworkPolicy"). CRD group names (`cilium.io`) are retained
because they are the compatibility interface; this is nominative use.

## Clean-room protocol

The default path from reference code to flowsdn code is through a spec:

1. **Inventory** (`docs/inventory/`): what exists, where, how big, what it
   depends on. Written by reading the reference.
2. **Spec** (`docs/spec/`): behavior, data model, wire formats, map layouts,
   protocols, config, failure modes, test cases. Written by reading the
   reference and its docs. A spec describes *what*, never transcribes *how*.
3. **Code** (crates): written from the spec. Authors of code work from the
   spec document. Consulting the reference while coding is permitted only to
   resolve an ambiguity in the spec, and the resolution is written back into
   the spec, not left in the code.

Direct copying is permitted where it is the sensible engineering choice
(constant tables, protobuf definitions, CRD OpenAPI schemas, test vectors)
and must carry the source path, commit, and license in the file header, and
an entry in `NOTICE`.

## BPF program licensing

BPF programs declare a license in their `license` section. Some kernel
helpers are GPL-only. flowsdn BPF programs declare `Dual BSD/GPL` so any
helper is available and the object remains redistributable under BSD-2-Clause.

## Rust dependencies

Permitted: MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, MPL-2.0 (file-level
copyleft, acceptable), Unicode. Not permitted without a decision record:
GPL, LGPL, AGPL, SSPL, BUSL. The workspace policy in `deny.toml` is enforced
with `cargo xtask deny` against the locked dependency graph.
