# Milestone 1: executable CNI, routing and endpoint restoration

Validated 2026-09-09 on Linux 6.17.1, Rust 1.95 and the pinned BPF nightly.
Source baseline: `9f85e6e`, plus Linux formatting in this record commit.
This is implementation progress inside milestone 1, not its Kubernetes gate.

- Sixteen BPF packet cases validate MAC rewrites, hop/checksum updates and drops.
- Real endpoint namespaces exercise CNI transactions, allocation, rollback,
  retry, map deletion/reinsertion and object attachment cleanup.
- Two router namespaces forward IPv4/IPv6 through two BPF hops. Namespace-local
  nftables FORWARD drops prevent Linux forwarding from masking BPF failures.
  Route removal and object detach block traffic; restoration recovers traffic.
- The CNI executable performs ADD/CHECK/DEL against an isolated Unix test API
  using real IPAM and the real endpoint manager. Bidirectional IPv4/IPv6 works.
  Fabricated missing addresses fail CHECK; duplicate DEL succeeds; HTTP503
  produces a durable offline deletion record.
- Dropping and restoring the endpoint manager preserves IDs, restores IPAM and
  reloads BPF ownership; CHECK and both traffic directions recover. The HTTP
  fixture stays alive during this test: this is not daemon-process recovery.
- Eight IPAM, twelve loader, twenty-two CNI, nine API-client and six endpoint
  state tests passed in focused runs. These include queue capacity/concurrency,
  malformed response rollback, health wire decoding, namespace entry errors,
  atomic state publication, exclusive ownership and stable ID allocation.
- Focused Clippy and formatting checks passed. New userspace components compile
  for x86-64 and arm64 Linux musl. Both workspace dependency policies passed;
  duplicate-version and unused-license-allowance warnings remain nonfatal.
  Architecture compile checks do not establish arm64 runtime support.

Live integration found and fixed missing-interface netlink error handling and
redundant MAC updates flushing gateway neighbors. Review also corrected health
and expiration wire-contract discrepancies, malformed-family allocation leaks,
malformed successful endpoint-response cleanup and DEL namespace-entry errors.

Native routing currently requires resolved Ethernet neighbors and forwarding.
Unresolved neighbors, fragments, IPv6 extension headers and unsupported L4
protocols fail closed. Kernel minimum-version runtime coverage, full policy
and identity wiring, agent serving, Kubernetes discovery and the two-node
cluster acceptance gate remain outstanding. No release was published.
