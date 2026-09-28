# flowsdn-k8s

Kubernetes contract primitives from specification 13: version floor and
capability checks, the 22-resource registration plan and payload projection,
namespace and endpoint-mode plans, and guarded node JSON-patch construction.

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

This crate does not implement an HTTP client, probes, informers, controllers,
vendored CRD schemas, schema hash validation, resource types, CEL admission or
storage migration. Tests use synthetic documents and local patch application;
they do not establish Kubernetes conformance or performance. JSON is baseline;
protobuf remains an open measurement question.
