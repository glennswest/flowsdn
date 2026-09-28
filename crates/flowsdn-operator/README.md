# flowsdn-operator

Library primitives from operator specification 12:

- optimistic Kubernetes Lease request planning with UID/resourceVersion guards and preserved metadata,
  locally observed expiry, renewal deadlines and terminal loss/release actions;
- terminal leadership-loss and partial-start failure planning;
- required-CRD observation, startup-fence and readiness planning;
- validated, stepped CES rate-table selection and change detection;
- taint desired-state calculation and flowsdn ownership name constants.

There is no operator executable, authenticated Lease transport, controller, token bucket, HTTP
server or metrics collector yet. The caller must execute lifecycle actions,
watch CRDs, perform compare-before-replace taint patches, and reconfigure its
existing limiter without resetting queues. Tests exercise planning behavior;
they do not establish live Kubernetes or mixed-cluster compatibility.

Owned resources use `flowsdn.io`, the controller identity
`io.flowsdn/gateway-controller`, object prefixes `flowsdn-gateway-` and
`flowsdn-ingress-`, and the `flowsdn-secrets` namespace. The default readiness
taint is `node.flowsdn.io/agent-not-ready`; removing it preserves Cilium
taints. These names do not grant ownership of existing Cilium resources.

## Lease election integration

`lease::Election` emits bounded-deadline GET/POST/PUT plans for an explicit
`coordination.k8s.io/v1` Lease. Use an owned name such as
`flowsdn-operator-resource-lock`, not the upstream operator's lock. Supply the
operator namespace explicitly (resolve an empty configuration to `default`)
and generate `<hostname>-<10 random lowercase-alnum characters>` once per
process. The engine validates identity syntax; the driver owns randomness.

The default lease/renew/retry/request durations are 15/10/2/5 seconds.
Validation also requires `renew + request <= lease`. Pass monotonic elapsed
time to every call and a UTC RFC3339 wall timestamp only for request serialization.
UTC `Z`/`+00:00` forms are validated and normalized to Kubernetes MicroTime
(six fractional digits, truncating finer precision); missing acquire times are
initialized during own renewal. Other timezone offsets must be normalized by
the caller.
Takeover depends on how long an unchanged record was observed locally, never
the server's clock. Metadata-only resourceVersion changes do not extend the
observation window. A changed UID resets follower observation and terminates
an existing leader. Success requires the matching request ID and a confirmed
write response with the expected UID, new resourceVersion and Lease fields.

The driver must authenticate requests, bound raw response bytes, enforce each
absolute request deadline across connect/write/read, and poll even while a
request is in flight. Honor `WaitUntil` deadlines; retry waits are clipped to
the leadership deadline. Deliver network failures with `status=None`; conflict
responses retry through a new read. Treat engine errors as fatal configuration
or clock failures, cancelling duties rather than continuing on uncertain state.
A timeout or late response does not grant leadership.

`Acquired` maps to the existing lifecycle's `LeaseAcquired` event. `Renewed`
does not restart duties. `CancelAndExit` cancels in-flight HTTP and leader duties
and exits immediately; there is no follower demotion. Clean shutdown or failed
leader startup calls `release`, cancels duties before executing
`CancelAndRelease`, and exits after `Released` or a terminal failure. Release
clears the holder with the last confirmed UID/resourceVersion; it never deletes
the Lease or overwrites a replacement owner. These plans do not run a controller
or establish live multi-replica acceptance. Tests use a simulated optimistic API
server to exercise acquisition races, local expiry, stale replies and release.
