# CNI ADD transaction

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

This is not an installed CNI executable. Agent HTTP transport, native veth
configuration, offline DEL, CHECK/STATUS/VERSION, chaining and legacy result
conversion remain outstanding. Unsupported versions and chaining are rejected
before allocation. Tests combine failure injection with the real host IPAM
allocator to verify ownership and rollback, rather than simulating allocation
success with constant addresses.
