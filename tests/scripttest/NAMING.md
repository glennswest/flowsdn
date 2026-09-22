# Corpus naming audit

Run `cargo xtask audit-corpus` to generate `naming-audit.json`, then
`cargo xtask audit-corpus --check` to verify the reviewed snapshot. This parses
168 harvested archives without executing their commands or editing their data.
The mechanical rewrite set is empty: keep compatibility flags, command aliases,
map/metric symbols and embedded paths. Missing adapters do not justify renaming.

All six startup flags absent from the 539-entry **agent** catalogue retain their
reference names. Source provenance is Cilium v1.20.1, commit `7d68cfb394`:

| Flag | Owner and reference evidence |
|---|---|
| `enable-cluster-pool-to-multi-pool-migration` | Operator multipool migration; `operator/pkg/ipam/allocator/multipool/multipool.go:43–53` |
| `synchronize-k8s-nodes` | Operator kvstore node GC; `operator/pkg/kvstore/nodesgc/cell.go:22–26` |
| `enable-example` | Retained tutorial input, unused by the pinned fixture (its args are not parsed); `contrib/examples/script/example_test.go` and `testdata/example.txtar` |
| `probe-tcp-md5` | BGP test fixture; `pkg/bgp/test/script_test.go:67` |
| `test-peering-ips` | BGP test fixture; `pkg/bgp/test/script_test.go:64` |
| `use-kernel-managed-arp-ping` | Neighbor test fixture; `pkg/datapath/neighbor/test/script_test.go:134–138` |

The snapshot records every occurrence and fails comparison when the corpus
changes; unclassified startup flags fail even after regeneration. The symbol
list includes metrics as well as map-like names and is not a BPF map inventory.
This gate does not validate runtime flag values, implement missing area commands,
or establish networking conformance. Those remain separate harness gates.
