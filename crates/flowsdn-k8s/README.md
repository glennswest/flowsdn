# flowsdn-k8s

Kubernetes contract primitives from specification 13: version floor and
capability checks, the 22-resource registration plan and payload projection,
namespace and endpoint-mode plans, guarded node JSON-patch construction, and
a hash-verified embedded reference schema bundle.

Owned CRDs use `flowsdn.io/v1alpha1`, `Flowsdn` kinds, `flowsdn`-prefixed
plural/singular names, matching list kinds, and the sole category `flowsdn`.
No upstream short names are registered. `registration_payload` accepts owned
documents; explicit `migration_registration_payload` accepts verified reference
`cilium.io` documents and projects their storage schema into a new owned CRD.
Both functions emit only the owned API identity and one served storage version,
without upstream version deprecation flags or warnings. Kind, names and scope
must match the resource catalogue. Re-projecting an owned payload is idempotent.

The shared `io.flowsdn.k8s.crd.schema.version` label records reference schema
provenance (`1.33.11`), independently of the owned API version. Schema contents,
subresources and printer columns are retained from the input storage version;
projection adapts exact upstream API group/version and known kind values in
`group`, `apiVersion` and `kind` schema defaults, enums and constants. This
includes BGP peer references and policy Envoy references. Other compatibility
field values and descriptive provenance remain unchanged. It does not
copy stored custom resources, modify upstream CRDs, or claim that a schema has
been hash-verified. Callers must verify input schemas separately.

Node fallback patches test UID and resourceVersion before any mutation. Callers
must probe capabilities, send to nodes/status, and reread/rebuild after conflicts.

`schemas::registration_payloads()` verifies the version-bound manifest and all
22 embedded reference YAML hashes, parses every document, and returns the complete
owned registration set. All seven dual-version reference definitions remain
intact in the corpus; only their storage schemas are projected. The actual
BGP group/kind defaults occur in deprecated v2alpha1 schemas and do not leak
into the selected v2 storage projection. Tests exercise the real policy kind
enums and prove other selected schema content is preserved. See
[corpus provenance](crds/PROVENANCE.md). The raw YAML is reference data and
must not be applied as flowsdn installation manifests.

The `client` module provides verified HTTPS JSON transport with per-request token
rotation and bounded lists, frames and operator request/response bodies. Generic
operator calls retain HTTP status for optimistic concurrency and use explicit
per-call deadlines; they do not retry writes. URLs are restricted to the supported
built-in and flowsdn endpoints; upstream CRD writes are rejected. Watch frames
preserve partial bytes and deadlines across task cancellation.

The `watch` module stages bounded Node/local-Pod lists and atomically publishes
complete snapshots. Resource versions are opaque; bookmarks and UID-safe deletion
are supported. No runtime driver currently connects these modules to the agent.
New transport dependencies must be resolved remotely and committed before locked
validation; this source checkpoint is not a validated operator or pod network.

This crate does not implement runtime probes, informer drivers, controllers,
resource types, CEL admission or stored-instance migration. Tests use both the
verified reference corpus and synthetic documents with local patch application;
they do not establish Kubernetes conformance or performance. JSON is baseline;
protobuf remains an open measurement question.
