# Identity primitives

Identity foundations from identity specification §§4.4–4.5.
The default features have no dependencies: numeric primitives use `core`, while
labels, fixed mappings and CIDR conversion use `alloc` without requiring `std`.

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

The CIDR module masks network prefixes, encodes canonical label keys and checks
same-family containment. Both address families omit CIDR identity labels for
`/0`; callers select the appropriate world label. General selector matching
and Kubernetes label synthesis remain separate.

The optional `filter` feature enables identity/node label filtering and JSON
prefix-file decoding, using the workspace regex and JSON libraries. Built-in
include rules are exclusion exceptions; user includes enable whitelist mode.
File prefixes are literal, CLI additions are regular expressions. The caller
loads files, handles diagnostics and validates source-specific label grammars.

`fixed::FixedIdentities` validates complete user-reserved mappings in 128–255
before exposing lookups. It rejects built-in identity names, duplicate numeric
IDs, duplicate names and empty names. Names are case-sensitive opaque values;
validation neither allocates identities nor grants endpoint ownership.
