# flowsdn-clustermesh

Configuration and compatibility plans, cross-cluster PodCIDR overlap checks,
read-range authorization, and cluster UUID ownership transaction planning.

Identity allocation defaults to CRD; explicit kvstore remains a supported design
choice. Double-write modes and non-legacy service selection are rejected.
The resync default is five minutes. Deferred MCS/mirroring flags produce warnings.

Ownership plans require a durable cluster UUID and an unleased owner record,
plus atomic value/revision comparisons before writing the leased config. Callers
must persist UUIDs, execute transactions atomically and reread on conflicts.
A guard cannot constrain unmodified reference writers or administrative deletion.

No live clients, TLS, CN authentication, transport enforcement, controllers,
allocator, lease manager, scheduler or persistent bootstrap are implemented.
The range checker consumes already authenticated roles; it is not an auth server.
Tests exercise local plans and synthetic store state, not deployment conformance.
