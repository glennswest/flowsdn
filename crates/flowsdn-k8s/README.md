# flowsdn-k8s

Kubernetes compatibility primitives from specification 13: version floor and
capability checks, the 22-resource registration plan and payload projection,
namespace and endpoint-mode plans, and guarded node JSON-patch construction.
The schema label constant is shared with the operator.

Node fallback patches test UID and resourceVersion before any mutation. Callers
must probe capabilities, send to nodes/status, and reread/rebuild after conflicts.

This crate does not implement an HTTP client, probes, informers, controllers,
vendored CRD schemas, schema hash validation, resource types, CEL admission or
storage migration. Tests use synthetic documents and local patch application;
they do not establish Kubernetes conformance or performance. JSON is baseline;
protobuf remains an open measurement question.
