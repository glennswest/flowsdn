# Observer primitives

Building blocks with no external dependencies from the Hubble/monitor specification:

- Numeric IP/CIDR filters, allow/deny composition and explicit CEL rejection.
- Checked v0–v3 drop headers with packet-length boundaries. Raw ifindex remains
  available; Flow.interface is omitted for drops for reference compatibility.
- Explicit global-over-legacy address preference and flowsdn emitter identity.
- Reference-compatible exporter node-name projection and bounded PacketDrop
  dedupe/rate admission with failed-write completion tokens.
- A realized-policy snapshot contract and direction/verdict correlation.
- A bounded single-owner memory ring model with reserved newest slot, cursor
  loss reporting and fresh-instance restart semantics.

These helpers do not start a server, read perf events, implement a CLI or export
flows. The ring is synchronous, not the production concurrent observer. Its
capacity bounds event references, while ingestion must also bound event sizes.
Policy lookup adapters must use realized snapshots, not desired policy.

IP filtering intentionally treats alternate IPv6 spellings as equal. An old
Hubble CLI filtering a local export file uses its own legacy predicate and may
still require canonical spelling. The server-side primitive cannot change that
client code. Full Observer/gRPC integration remains outstanding.
