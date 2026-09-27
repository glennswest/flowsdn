# flowsdn-k8s

Kubernetes compatibility primitives from specification 13: version floor and
capability checks, the 22-resource registration plan and payload projection,
namespace and endpoint-mode plans, and guarded node JSON-patch construction.
The schema label constant is shared with the operator.

Node fallback patches test UID and resourceVersion before any mutation. Callers
must probe capabilities, send to nodes/status, and reread/rebuild after conflicts.

This crate does not implement an HTTP client, probes, running informers, controllers,
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

The caller still must implement authenticated transport, raw response bounds,
selectors, pagination requests, retry/backoff and agent reconciliation. The state
layer alone does not establish Kubernetes connectivity or pod networking.
