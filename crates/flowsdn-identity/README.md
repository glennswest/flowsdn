# Identity primitives

Dependency-free identity foundations from identity specification §§4.4–4.5.
The numeric module uses only `core`; the crate also exposes the separate label
module and supports allocation through `alloc` without requiring `std`.

`NumericIdentity` validates the supported global, local and remote-node scopes.
Reserved holes remain readable but are classified separately from numbers that
can be allocated. The fifteen named reserved identities, ten well-known numbers,
deprecated numbers and user-reserved range are explicit. Local CIDR identities
are recognized across the complete 24-bit scope index, including indices above
65535.

`ClusterEncoding` supports the 255- and 511-cluster layouts, inclusive allocation
ranges, aggregation, numeric remote-identity checks and the configured mark
collision restriction. `WireIdentity` serializes 24-bit network-order fields
without truncation. Tunnel encoding folds family-specific world identities;
receive conversion distinguishes single- and dual-stack worlds.

This is not an identity allocator or a policy decision engine. Remote numeric
validation does not check label ownership, cluster names or capability agreement.
There is no CRD/kvstore integration, checkpoint storage, lease management,
well-known label matching, or live datapath compatibility claim.
