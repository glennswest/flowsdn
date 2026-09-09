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

The `affinity` module adds six fixed layouts: IPv4/IPv6 affinity keys, the
affinity value and match key, and both skip-LB keys. Their sizes and every
field offset have compile-time assertions. Packed numeric accessors return
copies. Client unions retain all 8 or 16 raw bytes, and the network-namespace
cookie discriminator changes only bit zero while preserving reserved bits.
Cookie constructors zero padding and unused union bytes. The raw timestamp
has no clock-unit conversion in this ABI layer.

Skip-LB address/port integers follow the unmarked host-order fields in map ABI
specification §4.3 and its little-endian rule in §4; IPv6 addresses remain
network bytes. No conversion from an IPv4 address object into the affinity
union is implied by its raw byte storage.

Variable-length Maglev layouts remain deferred. These modules do not implement
map creation, service reconciliation, Aya integration or live datapath
compatibility checks.
