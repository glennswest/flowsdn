# Historical control-plane fixtures

Recovery for #36 adds four test families removed before the pinned v1.20.1
corpus. The existing `../controlplane` Node/CiliumNode fixtures remain unchanged.
These files are Apache-2.0 Cilium test data, attributed in [PROVENANCE](PROVENANCE).

| Family | Files per tag | Scenario and expected state |
|---|---:|---|
| `pod/hostport` | 10 | Create a HostPort pod, replace its completed owner, then delete the old pod without removing the replacement's service. Three LB golden states. |
| `services/dualstack` | 15 | IPv4/IPv6 Service/EndpointSlice inputs and LB outputs for Kubernetes 1.24, 1.25 and 1.26. |
| `services/graceful-termination` | 9 | Active backend becomes terminating, then is removed; three golden states. Enable terminating-endpoint handling in the adapter. |
| `services/nodeport` | 16 | NodePort inputs and per-node golden LB state for Kubernetes 1.24, 1.25 and 1.26. |

There are **100 logical source records and 68 stored files**. The 32 YAML
inputs/manifests are identical at v1.16.0 and v1.17.0, so both manifest rows
point to the same v1.17.0 fixture. All 18 golden outputs differ and remain
separate under their source tags. For example, HostPort's historical frontend
protocol changes from `NONE` to `TCP`; do not normalize that difference away.
The manifest, rather than a directory walk of v1.16.0, defines its complete set.

For each scenario, feed `init.yaml`, then `state1.yaml`, `state2.yaml`, etc.
The corresponding `lbmapN.golden` supplies expected state; NodePort has separate
node-named outputs. `manifests/` records capture topology/setup, not additional
state transitions. Only the Rust adapter may perform runtime operations.

Verify every row and stored byte against a local Cilium checkout containing the
pinned tags:

```text
cargo run -p flowsdn-harvest-controlplane -- --check /path/to/cilium tests/golden/controlplane-legacy
```

`--restore` instead copies the manifest-selected static source objects. It
validates source tags, commits, Git blob identities, byte counts and shared-file
consistency before writing fixtures. It neither fetches tags nor executes the
upstream suite. Do not hand-edit recovered fixtures; record an explicit adapter
expectation/divergence when historical behavior differs from current semantics.

**Runtime adapters remain pending.** Recovery and byte verification establish
fixture provenance, not correctness of flowsdn's Kubernetes conversion, LB
reconciliation or datapath. Both tagged output sets need independent adapters
and explicit version expectations before they can serve as execution gates.
