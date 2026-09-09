# flowsdn-ipam

Host-scope IPv4 and IPv6 allocation from IPAM specification sections 3.1,
3.4 and 5.5. `HostScope` provides random-start linear scanning, specific
allocation and restore, owner inspection, persistent exclusions and idempotent
release. `Ipam` combines optional family allocators in the `default` pool,
allocating IPv6 first and releasing the new IPv6 allocation if IPv4 fails.
Callers serialize access using exclusive mutable access or an external lock.

Sparse bitmap words keep storage proportional to allocations. IPv6 prefixes
retain their full address range, including /96 and /64. `capacity()` returns
the total range after first/last reservations, including excluded addresses;
it is independent of the number currently allocated. A /0 IPv6 prefix with
both endpoint reservations disabled returns `CapacityOverflow`, because its
2^128 addresses cannot be represented by the `u128` capacity API. Other /0
options are supported.

Both endpoints are reserved by default for prefixes larger than two addresses,
including IPv6. Small prefixes reserve neither. Explicit exclusions reject
specific allocation; scanning retains encountered exclusions with the
`<owner> (excluded)` owner. Release leaves the exclusion in effect. Restore
uses normal allocation checks; host scope has no upstream writes to defer.

This crate does not yet provide pool metadata selection, timers, agent REST
handlers, cloud allocation or operator integration.

Run `cargo test -p flowsdn-ipam` to exercise exhaustion, address boundaries,
exclusions, restore and dual-stack rollback.
