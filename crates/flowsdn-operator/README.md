# flowsdn-operator

Library primitives from operator specification 12:

- terminal leadership-loss and partial-start failure planning;
- required-CRD observation, startup-fence and readiness planning;
- validated, stepped CES rate-table selection and change detection;
- taint desired-state calculation and flowsdn ownership name constants.

There is no operator executable, Lease client, controller, token bucket, HTTP
server or metrics collector yet. The caller must execute lifecycle actions,
watch CRDs, perform compare-before-replace taint patches, and reconfigure its
existing limiter without resetting queues. Tests exercise planning behavior;
they do not establish live Kubernetes or mixed-cluster compatibility.

Owned resources use `flowsdn.io`, the controller identity
`io.flowsdn/gateway-controller`, object prefixes `flowsdn-gateway-` and
`flowsdn-ingress-`, and the `flowsdn-secrets` namespace. The default readiness
taint is `node.flowsdn.io/agent-not-ready`; removing it preserves Cilium
taints. These names do not grant ownership of existing Cilium resources.
