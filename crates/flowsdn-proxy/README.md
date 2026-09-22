# flowsdn-proxy

Integration primitives for specification 16: an endpoint-regeneration ACK
barrier, topology-derived DNS transparent-mode selection with explicit
configuration precedence, and FQDN local-scope identity validation.

The barrier binds replies to the node, type, sent version and stream epoch.
NACK, cancellation or deadline expiry cannot grant publication. The caller
must cancel superseded endpoint attempts, execute rollback, and atomically
check the returned attempt/revision before updating BPF state. Reconnect and
superseding responses require fresh acknowledgements.

No Envoy replacement, xDS server, DNS sockets, identity allocator, ztunnel
firewall or networking integration is implemented. Envoy remains the external
L7 execution target under ADR-0015.
