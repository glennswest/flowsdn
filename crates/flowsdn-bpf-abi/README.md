# Map ABI foundation

Dependency-free `no_std` layouts and explicit byte codecs from map ABI spec
§§4.1 and 4.4: IPv4/IPv6 connection tuples, address-only LPM keys, the frozen
ipcache key and remote endpoint value. Packed types use by-value accessors for
multi-byte host fields. Network-order fields use byte-array wrappers.

Layout assertions compile on every target; independent byte fixtures check
endianness, field directions, prefix bounds and padding. Raw decoding preserves
unknown bits. Constructors validate prefix lengths but leave address
canonicalization to the owning IP-prefix type.

This is the first subset of the map catalogue. CT/NAT values, service and policy
layouts, Aya integration, map operations and BPF loading remain forthcoming.
No verifier, live-map or mixed-cluster compatibility is claimed by these tests.
