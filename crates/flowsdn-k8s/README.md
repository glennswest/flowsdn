# flowsdn-k8s

Kubernetes compatibility primitives from specification 13: version floor and
capability checks, the 22-resource registration plan and payload projection,
namespace and endpoint-mode plans, and guarded node JSON-patch construction.
The schema label constant is shared with the operator.

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

## HTTPS transport checkpoint (not yet validated)

`client::JsonClient` loads an explicit kubeconfig or in-cluster configuration,
requires verified HTTPS, and reads a token-file credential for each request.
Credential file reads are asynchronous, bounded and restricted to regular files
(including projected-secret symlink targets). Credential errors omit token data.

Built-in Node/Pod request paths preserve the local-node selector and percent-encode
opaque continuation/resource-version values. Raw JSON list and newline watch
frames have byte/time limits. HTTP failures do not collect unbounded response
bodies. Partial frame bytes and deadlines survive cancellation; EOF, malformed
frames, timeouts and watch ERROR events require relisting.

This checkpoint still needs dependency lock resolution and remote compilation.
Protocol/unit tests are provided; real HTTPS integration and agent controller
orchestration are not verified. The implementation follows the pinned
[kube 4.2.0 client API](https://docs.rs/kube/4.2.0/kube/struct.Client.html).
