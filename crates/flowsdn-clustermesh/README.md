# flowsdn-clustermesh

Configuration and compatibility plans, cross-cluster PodCIDR overlap checks,
read-range authorization, cluster UUID ownership transaction planning, and the
apiserver's export converters.

Every kvstore key and read grant uses flowsdn's names (ADR-0023):
`flowsdn/.heartbeat`, `flowsdn/cache/`, `flowsdn/cluster-config/<cluster>`,
`flowsdn/synced/`, `flowsdn/state/`, plus the durable owner record
`flowsdn/cluster-owners/<cluster>`. There are no `cilium/` keys or aliases.

`export` turns flowsdn's kinds and core objects, given as whole JSON objects,
into key names and value bytes (spec 20 §3.8.2, §4.2–4.6): the node record
from a FlowsdnNode, the identity label string from a FlowsdnIdentity, the
`IPIdentityPair`s of a FlowsdnEndpoint with IP ownership arbitration, the
`ClusterService` of a Service (`service.flowsdn.io/global`/`shared`) and its
EndpointSlices, the published cluster config, the global-namespace decision
(`clustermesh.flowsdn.io/global`), the synced canary keys and key joining.
The converters are pure and byte-stable; `flowsdn-agent clustermesh-apiserver`
runs them into the kvstore (#567). EndpointSlice export (§4.7), service exports
(§4.8) and the PodCIDR stripping of cloud IPAM modes are not built (spec 20 #567 amendment; MCS is #592).

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

Verified-certificate principal binding now feeds the range checker, with exact
CN mapping, authority-bound tokens and current-binding revocation checks. This
is not TLS verification: a trusted TLS adapter must validate the certificate
before binding, and a future server must revoke already-open watches too.
