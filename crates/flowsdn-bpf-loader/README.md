# Map lifecycle planning

Dependency-free map compatibility decisions from map ABI/loader spec §3.2.
Missing pins require creation; compatible maps are reused. The sole flag
relaxation permits an existing read-write map to satisfy a program-read-only
specification. Other differences report every changed compatibility attribute.

Agent-owned replacements create empty maps; loader-owned replacements remain
staged until the program-attachment commit. A decision performs no mutation,
content migration or attachment. Unknown flags remain part of exact comparison;
this planner never adds flags to make a map compatible.

Standalone LRU capacity changes retain the pinned capacity and return warning
metadata; structural changes still replace. Node-ID map planning instead refuses
incompatible replacement to preserve IDs encoded in encryption marks.

Nested-map planning gates CT/NAT, multicast and Maglev by their own features,
validates supported outer/inner shapes and compares complete inner templates.
Inner capacity remains exact, including for LRU inner maps. Cluster arrays reserve
the inclusive cluster-zero slot. The caller must validate map-type/flag
combinations, BTF compatibility and actual kernel descriptor operations.
Kernel probing, bpffs operations, live-map compatibility, and planned map
replacement transactions are not implemented yet.

The optional `kernel` feature provides Aya object ownership for the integration
classifier: endpoint-map updates, validated endpoint addresses and MACs, ingress
attachments, explicit detach and cleanup when the owner is dropped. Duplicate
attachments fail without replacing the existing link. This adapter does not yet
implement persistent pins, production policy wiring or agent restart recovery.

Auxiliary scratch planning uses target-specific 64/128-byte strides, possible
CPU counts and checked map-value sizing. It exposes patch values and clamped
CPU offsets; the caller provides zeroed storage. Empty sections and zero CPU
counts fail before allocation. Kernel-specific map limits remain caller checks.

Typed tail inventories validate declared slots against exactly one program per
slot, using the frozen ABI numbering. Global endpoint-policy arrays are separate.
ELF section/name parsing, reachability and program-array population are not yet
implemented; callers supply the typed declarations and program slots.
