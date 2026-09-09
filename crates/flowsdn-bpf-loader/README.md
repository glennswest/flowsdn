# Map lifecycle planning

Dependency-free map compatibility decisions from map ABI/loader spec §3.2.
Missing pins require creation; compatible maps are reused. The sole flag
relaxation permits an existing read-write map to satisfy a program-read-only
specification. Other differences report every changed compatibility attribute.

Agent-owned replacements create empty maps; loader-owned replacements remain
staged until the program-attachment commit. A decision performs no mutation,
content migration or attachment. Unknown flags remain part of exact comparison;
this planner never adds flags to make a map compatible.

The caller must validate map-type/flag combinations and inner-map schemas.
Kernel probing, Aya integration, bpffs operations, live-map compatibility,
transaction execution and rollback are not implemented by this crate yet.
