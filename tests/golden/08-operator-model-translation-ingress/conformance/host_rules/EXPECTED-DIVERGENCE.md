# HTTPS matcher audit (#281)

This harvested scenario reaches the affected force-HTTPS translator path in
Cilium `7d68cfb394`. Its secure input route has no user header or query matchers,
so exchanging those empty lists causes **no byte divergence in this golden**.
The wildcard authority matcher belongs to the separate nonredirect host and
is unaffected. Preserve the harvested output unchanged.

When either user list is nonempty, flowsdn intentionally emits header matchers
under `match.headers` and query matchers under `match.queryParameters`.
The adjacent `flowsdn-https-matchers` synthetic regression exercises both lists
with the same name and different values; it is not harvested reference output.
No public upstream issue has been filed; external coordination remains pending.
