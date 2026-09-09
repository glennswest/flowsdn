# CNI executable and transactions

The initial library implements the primary CNI 1.0/1.1 ADD transaction from
specification 09 §3.4. It parses required environment and pod arguments, orders
dual-stack addressing, produces the CNI result and coordinates reverse-order
cleanup. A post-create failure deletes the endpoint before removing its link
and releasing addresses. Cleanup failures are retained without replacing the
primary error or preventing later cleanup.

`AddBackend` supplies agent and platform operations. Allocation must be atomic;
link creation must undo partial creation before returning an error. The adapter
must fetch and validate agent configuration before calling `add`, and endpoint
creation must wait for successful regeneration. The transaction cannot make an
asynchronous endpoint ready by itself.

`cargo build -p flowsdn-cni` also builds the `flowsdn-cni` executable. Its initial
scope is primary veth networking with CNI 1.0/1.1 and host-scope IPAM. It uses
the Unix agent API and native Rust netlink for ADD, verifies agent health and
previous addresses for CHECK, supports STATUS and VERSION, and performs
idempotent DEL with durable offline fallback. GC returns the specified
unsupported-version error. Chaining, delegated/cloud IPAM and legacy result
conversion remain outstanding and unsupported modes fail before allocation.

The executable uses `CILIUM_SOCK` for a custom agent socket. The optional
`FLOWSDN_DELETE_QUEUE` override selects a queue directory for isolated testing;
the default preserves the Cilium queue location. This executable is not a
complete networking installation: the deployable agent and cluster integration
are still being implemented.

The queue writes complete SHA-256-named records, deduplicates retries, and
coordinates writers with agent replay through shared/exclusive locks. A second
directory lock enforces the 256-entry cap across cooperating flowsdn writers;
mixed implementations that do not take that lock can race their capacity checks.
Both container JSON and attachment-string replay formats are supported.

Tests combine real IPAM with failure injection, validate HTTP wire behavior,
exercise queue concurrency and persistence, and check malformed response cleanup.
