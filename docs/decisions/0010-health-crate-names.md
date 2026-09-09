# ADR-0010: Separate module health from network health checking

Date: 2026-09-09. Status: accepted.

Resolve issue #122 by adopting spec 08's recommendation. `flowsdn-health`
owns the module health registry, reporters and readiness evaluation described
by spec 00. `flowsdn-healthcheck` is reserved for spec 08's active network
probes, health endpoint management and health API. The existing
`flowsdn-health-responder` name remains reserved for the responder component.

The registry crate is already implemented. This decision does not introduce
empty checker or responder crates, or claim that either component works.
Future checker code can depend on the registry without a naming collision.
