# flowsdn-gateway

Initial specification 21 library: GatewayClassConfig semantic validation and
Accepted-condition projection; distinct header/query matcher types for HTTPS
redirect planning; reference-compatible reason strings; conformance target
and implementation-evidence checks.

No Kubernetes watcher/status writer, Ingress/Gateway controller, Envoy protobuf
translation, published conformance runner or live compatibility claim is
provided. The matcher types are planning types, not the serialized model ABI.
The conformance test uses a synthetic catalogue; the complete pinned upstream
feature corpus, golden set and live suite remain milestone 4 acceptance work.
Validation expects a resource after CRD defaulting and leaves it untouched.
