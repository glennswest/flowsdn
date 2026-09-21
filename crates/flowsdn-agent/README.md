# Agent endpoint ownership

The initial library owns primary endpoint IDs, published endpoint state,
host-scope allocations and live endpoint maps/attachments. Creation stages
state before installing the datapath and publishes it after installation.
Deletion retains ownership on failure so the operation can be retried.
Restore validates saved host interface identity and address ownership before
rebuilding maps and attachments in a fresh object.

State storage holds an exclusive agent lock, ignores incomplete regeneration
directories, rejects mismatched IDs and duplicate attachments, and preserves
unknown JSON fields. New IDs use the lowest free number in 1–4095; restore
can reserve historical nonzero u16 IDs.

The initial `flowsdn-agent --config PATH` executable serves the primary CNI
workflow over a mode-0600 Unix socket. It restores endpoint ownership, acquires
the offline deletion lock, replays queued deletions, then exposes the API.
Queue lock/list/delete failures stop startup and retain valid failed entries
for a later restart; malformed entries are logged and discarded. This interim
behavior avoids silently losing deletions before endpoint GC exists.

The JSON configuration requires `socket-path`, `state-dir`, `bpf-object`,
`device-mtu` and `route-mtu`, plus at least one of `ipv4-pool`/`ipv6-pool` in
CIDR form and the corresponding `ipv4-gateway`/`ipv6-gateway`. The optional
`delete-queue` defaults to `deleteQueue` beside the socket. Gateways are excluded
from allocation; route MTU cannot exceed device MTU. The supplied BPF object
must be the trusted `local-delivery` build. Run with Linux network/BPF privileges
and configure CNI to use the same socket and queue.

The bounded HTTP/1.1 subset supports config/health, allocation/release, endpoint
creation/query/health and attachment/container deletion. Allocation expiration
is ten minutes when requested. Unknown routes return 404 in this initial subset;
full route registration with explicit 501 responses remains required by ADR-0012.
Endpoint health checks live host-link identity and incomplete teardown, but
cannot yet detect external replacement of BPF programs or policy convergence.
Requests are serialized with two-second read and write budgets and 4 MiB bodies.
These initial limits and socket permissions are narrower than the full API spec.

Identity/policy reconciliation, Kubernetes watches, stale-pod garbage collection
and graceful shutdown remain outstanding. Programs/maps are not pinned for
process-independent ownership: traffic stops while the agent is down and recovers
after successful restore. Missing host links remove stale state during restore;
changed live host-link identities fail startup. The state parser currently accepts
primary workload endpoints; host/ingress endpoints and full reference migration
are not yet supported.
