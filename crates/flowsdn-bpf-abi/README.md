# Map ABI foundation

Dependency-free `no_std` layouts and explicit byte codecs from map ABI spec
§§4.1–4.4: IPv4/IPv6 connection tuples, conntrack and NAT values, service and
backend layouts, address-only LPM keys, the frozen ipcache key and remote
endpoint value. Packed types use by-value accessors for
multi-byte host fields. Network-order fields use byte-array wrappers.

Layout assertions compile on every target; independent byte fixtures check
endianness, field directions, prefix bounds and padding. Raw decoding preserves
unknown bits. Constructors validate prefix lengths but leave address
canonicalization to the owning IP-prefix type.

The CT service union preserves raw storage; its backend setter clears reserved
bytes. NAT flag updates retain unknown bits. See [LB coverage](LB-COVERAGE.md)
for supported service layouts and the unresolved L7 union interpretation.

This is a subset of the map catalogue. Affinity, policy layouts, Aya integration,
map operations and BPF loading remain forthcoming.
No verifier, live-map or mixed-cluster compatibility is claimed by these tests.
