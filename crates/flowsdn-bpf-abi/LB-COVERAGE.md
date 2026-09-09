# Load-balancer ABI coverage

The `lb` module implements 15 distinct layouts from map ABI specification
§4.3: both service keys, the shared service value, both backend values, packed
reverse-NAT values, source-range keys, socket reverse-NAT tuples and entries,
and activity key/value. Health values alias backend layouts; both service
families alias the shared value. Compile-time assertions cover every size and
field offset. Codecs preserve raw padding and unknown flag bits.

Service flags and backend states follow service specification §4.3. The
source-range constructor counts 32 static prefix bits plus the supplied CIDR
bits, validates family bounds, and initializes padding. It preserves address
host bits for the owning IP-prefix type to canonicalize. Raw decoding does not
validate service semantics or prefix bounds.

The service union remains a raw little-endian `u32`. Affinity helpers expose
the unambiguous upper algorithm byte and lower 24 timeout bits; the backend-ID
view preserves all 32 bits. No L7 proxy-port conversion is provided: map ABI
specification §4.3 says host order while service specification §2 says
`htons(proxy_port)`. This disagreement needs resolution before L7 integration.

Affinity, skip-LB and variable-length Maglev layouts are deferred. This module
does not implement map creation, service reconciliation, Aya integration or
live datapath compatibility checks.
