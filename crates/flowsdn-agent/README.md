# Agent endpoint ownership

The initial library owns primary endpoint IDs, published endpoint state,
host-scope allocations and live endpoint maps/attachments. Creation stages
state before installing the datapath and publishes it after installation.
Deletion retains ownership on failure so the operation can be retried.
Restore validates saved host interface identity and address ownership before
restoring maps and attachments. With `bpf-pin-root` configured, restore validates
and reuses pinned map/TCX ownership; without it, ownership is process-local.

State storage holds an exclusive agent lock, ignores incomplete regeneration
directories, rejects mismatched IDs and duplicate attachments, and preserves
unknown JSON fields. New IDs use the lowest free number through `endpoint-id-max` (default 4095,
configurable in 1–65535); restore can reserve historical nonzero u16 IDs.
This allocator bound does not resize the endpoint BPF map.

The initial `flowsdn-agent --config PATH` executable serves the primary CNI
workflow over a mode-0600 Unix socket. It restores endpoint ownership, acquires
the offline deletion lock, replays queued deletions, then exposes the API.
Queue lock/list/delete failures stop startup and retain valid failed entries
for a later restart; malformed entries are logged and discarded. This interim
behavior avoids silently losing deletions before endpoint GC exists.

The JSON configuration requires `socket-path`, `state-dir`, `device-mtu` and
`route-mtu`, plus at least one of `ipv4-pool`/`ipv6-pool` in CIDR form and the
corresponding `ipv4-gateway`/`ipv6-gateway`. The optional `delete-queue` defaults
to `deleteQueue` beside the socket. Gateways are excluded from allocation; both
MTUs must be at least 1280 and route MTU cannot exceed device MTU. Optional
`bpf-pin-root` enables persistent map/TCX ownership in a dedicated writable
bpffs directory; omitted/null/empty disables pinning.

The `local-delivery` BPF object built from this commit is embedded
(`bpf/local-delivery`, rebuilt by `tools/build-bpf.sh`; `test/build.sh` refuses
a copy whose code differs). An omitted or empty `bpf-object` loads it; a path
loads that trusted build instead. `egress` is `fib` (default: BPF FIB-redirects
traffic that is not to a local endpoint) or `stack` (every endpoint frame, same-node
pod-to-pod included, goes to the host stack, and each endpoint address gets a
host route over its host link); anything else
fails startup. See [the runtime guide](../../docs/runtime.md) for every key and
default. Run with Linux network/BPF privileges and configure CNI to use the same
socket and queue.

The bounded HTTP/1.1 subset supports config/health, allocation/release, endpoint
creation/list/detail/health, exact IPAM pool summaries, module health, health
StateDB queries and attachment/container deletion. The complete methods and
response shapes are in [the API contract](../../docs/agent-api.md). Allocation expiration
is ten minutes when requested. Unknown routes return 404 in this initial subset;
full route registration with explicit 501 responses remains required by ADR-0012.
Endpoint health checks live host-link identity and incomplete teardown, but
cannot yet detect external replacement of BPF programs or policy convergence.
Requests are serialized with two-second read and write budgets and 4 MiB bodies.
These initial limits and socket permissions are narrower than the full API spec.

With the `kubernetes` feature (GNU target, Fedora OpenSSL) and a `kubernetes`
config section, the agent watches Nodes and Pods, resolves `auto` pools from its
Node and owns direct routes to the other nodes' pod CIDRs. With `service-lb`
(default on) it also watches Services and EndpointSlices and load balances
ClusterIPs at the socket with the embedded `socket-lb` object (`bpf/socket-lb`,
checked like `local-delivery`), attached to `cgroup-root`; see
[runtime](../../docs/runtime.md#kubernetes-mode). Identity allocation, policy
reconciliation, stale-pod garbage collection and graceful shutdown remain
outstanding. Configured pins allow endpoint maps
and TCX links to survive agent process absence. Without pinning, traffic depends
on the live process and recovers after successful restore. This does not establish
rolling upgrades or automatic recovery from incompatible BPF objects. Missing host links remove stale state during restore;
changed live host-link identities fail startup. The state parser currently accepts
primary workload endpoints; host/ingress endpoints and full reference migration
are not yet supported.

`--help` and `--version` exit successfully without loading configuration. The
daemon opens no Hubble/relay service; its only TCP listener is the optional
read-only loopback `http-listen` (#297). `/v1/healthz` reports API
availability after restore, not complete pod-network readiness. stormcos ships
the static musl agent and CNI in a golden; the edition manifests and runtime
resources are documented in [the deployment contract](../../deploy/stormcos/README.md).

`flowsdn-agent cni install --source PATH` installs the supplied Rust CNI binary
under primary compatibility names and the loopback entry point. See the
[CNI installation reference](../flowsdn-cni/README.md#install-binaries) for
destination and overwrite controls. This command does not load BPF, start the
API or publish a conflist; `flowsdn-cni install` also writes the conflist.
