# flowsdn-api-client

Synchronous HTTP/1.1 over Unix sockets for the CNI-facing agent API. Helpers
cover configuration, IPAM allocation/release, endpoint creation/deletion,
container-wide deletion and endpoint health. Path and query components use
percent encoding; allocation expiration is an HTTP header.

`Client::new(socket_path, timeout)` applies one deadline to connection, writes
and response reads. Each request uses a fresh connection. Responses preserve
HTTP status, raw body bytes and optional decoded JSON; HTTP 404 and 503 remain
responses, distinct from transport failures. Ordinary requests never retry.

`put_endpoint_unbounded_response` retains bounded connection/writes and byte
limits, but leaves regeneration response timing to the agent, as CNI ADD
requires. Use it only where the agent owns that operation's deadline.

The client uses `httparse` for response headers and chunk sizes. Defaults cap
headers/trailers at 16 KiB, decoded bodies at 4 MiB and received bytes at 8 MiB.
Content-Length, chunked bodies and connection-close framing are supported;
ambiguous framing, truncation and malformed responses fail. Compression,
protocol upgrades, streaming APIs, TCP/TLS and automatic retries are outside
this crate's current scope.

Run `cargo test -p flowsdn-api-client` for Unix fake-agent wire, framing,
status, bounds and deadline tests.
