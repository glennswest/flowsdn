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

This crate does not implement probes, running informers, controllers,
vendored CRD schemas, schema hash validation, resource types, CEL admission or
storage migration. Tests use synthetic documents and local patch application;
they do not establish Kubernetes conformance or performance. JSON is baseline;
protobuf remains an open measurement question.

## Built-in watch state

`watch::WatchState` projects slim Node and local Pod documents into the existing
`flowsdn-table`. It stages bounded list pages and publishes only after a complete
consistent list. An interrupted or invalid relist preserves the last snapshot.
Watch errors and disconnects require a new list; bookmarks advance the opaque
resource version without changing rows. Deletes require a matching UID, protecting
recreated Pods. Off-node Pod data rejects an ignored local field selector.

The caller still must connect the transport to this state, issue pagination
requests, apply retry/backoff and implement agent reconciliation. The state
layer alone does not establish Kubernetes connectivity or pod networking.

## HTTPS transport checkpoint (Fedora OpenSSL)

`client::JsonClient` loads an explicit kubeconfig or in-cluster configuration,
requires verified HTTPS, and reads a token-file credential for each request.
Credential file reads are asynchronous, bounded and restricted to regular files
(including projected-secret symlink targets). Credential errors omit token data.

Built-in Node/Pod request paths preserve the local-node selector and percent-encode
opaque continuation/resource-version values. Raw JSON list and newline watch
frames have byte/time limits. HTTP failures do not collect unbounded response
bodies. Partial frame bytes and deadlines survive cancellation; EOF, malformed
frames, timeouts and watch ERROR events require relisting.

The owner selected Fedora system OpenSSL via kube `openssl-tls` with default
features disabled; see [ADR-0016](../../docs/decisions/0016-fedora-openssl.md).
Build with Fedora `openssl-devel` and `pkgconf-pkg-config`. Vendoring is disabled;
TLS consumers require the matching Fedora GNU/OpenSSL runtime. The former
ring dependency-policy failure is resolved; see the [verified TLS checkpoint](../../docs/validation/2026-09-28-fedora-tls.md).
This remains a library checkpoint, not agent controller integration.
