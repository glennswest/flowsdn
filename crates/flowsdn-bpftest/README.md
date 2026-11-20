# Kernel smoke harness

This implements the first self-test from specification 18 §9.1. It loads the
Rust `smoke` classifier, verifies six packet round trips and shared map updates,
then tests live UDP pass/drop/recovery, explicit detach and owner-drop cleanup.
It is test infrastructure, not the networking agent or a production firewall.

Requirements: Linux 6.6+, BPF and network namespace privileges, `ip`, the
userspace Rust toolchain and the BPF crate's pinned nightly. Install
`bpf-linker` 0.11.1 from its [official release](https://github.com/aya-rs/bpf-linker/releases/tag/v0.11.1)
and place it on `PATH`. Its x86-64 Linux archive has SHA-256
`e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8`.

From the repository root:

```sh
CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS='-C debuginfo=2 -C link-arg=--btf' \
  cargo +nightly-2026-04-03 build --manifest-path crates/flowsdn-bpf/Cargo.toml \
  --target bpfel-unknown-none -Z build-std=core --release --locked
cargo build -p flowsdn-bpftest --locked
```

Run the resulting `flowsdn-bpftest` executable with the path to the resulting
`bpfel-unknown-none/release/smoke` object. Both outputs use `CARGO_TARGET_DIR`
when configured; otherwise they use their workspace's normal Cargo target
directory. Run with the required privileges. The harness creates an anonymous
network namespace before changing loopback and fails if isolation is unavailable.
No host interfaces or persistent BPF pins are used. The namespace disappears
when the process exits. Only the smoke map's last packet length is observed;
it is not a concurrency-safe packet counter.

Ordinary `cargo test` does not execute these privileged checks. Failure exits
nonzero; an unavailable kernel feature is a failure, not a silent pass.
The smoke harness tests TC/IPv4 loopback. Neither harness covers XDP or the
full harvested BPF case corpus.

Run `flowsdn-endpoint-test` with the `local-delivery` BPF object to exercise
two endpoint namespaces. Sixteen kernel packet cases check MAC rewriting,
hop limits, IPv4 checksums and malformed-packet rejection. Live IPv4/IPv6 UDP
checks map deletion/reinsertion, detach and fresh-object reload. The fixture
uses the CNI ADD transaction, real host-scope allocation and an injected
post-creation failure to verify endpoint, link and address rollback and retry.
Endpoint setup now uses the native Rust connector. The fixture retains `ip`
for isolated setup/inspection; it is not the CNI executable.

Run `uplinks-live` with no arguments to check several uplinks (#408) on a real
kernel. Two veth uplinks in an anonymous namespace go through the agent's own
discovery, plan and kernel code (`flowsdn_agent::uplinks`). The checks:
- per-flow ECMP to a pod CIDR uses both ports over 64 TCP flows (`ip route get`);
- each address leaves through its own port;
- a port without carrier is skipped at once and its address is held as a /32
  on the live port, with a gratuitous ARP;
- the /32 goes when carrier returns, twice over;
- `single` removes every rule and table entry.

Run `l2-announce-live` with no arguments to check the L2 announcer's answers
(#475) on a real kernel. Two namespaces share a veth pair; this process answers
for 192.0.2.240 and 2001:db8:30::f0 on its end with `flowsdn_connector::announce`
(the agent's sockets and answers), and a worker in the other namespace sends UDP
to them. The checks:
- the worker's kernel accepts the ARP reply and the Neighbor Advertisement and
  holds this end's MAC for both addresses;
- an address that is not announced stays unresolved;
- neither address is added to this end's host.

Run `native-routing` with the same BPF object for two router namespaces and
two endpoints. It tests dual-stack traffic, route removal/restoration and
object detach/reload. Mandatory namespace-local nftables FORWARD drops prevent
ordinary Linux forwarding from masking BPF failures. This fixture additionally
requires `nft`; routes and neighbors are provisioned explicitly, with no
Kubernetes discovery controller.

Run `cni-runtime` with the `flowsdn-cni` executable path followed by the BPF
object path to exercise the executable's ADD/CHECK/DEL workflow. Its Unix
test server drives real IPAM and BPF operations; checks include live dual-stack
UDP, missing-address detection, duplicate deletion and HTTP503 offline queueing.
The test server is not a deployable agent.

Run `agent-runtime` with the CNI executable, agent executable and BPF object
paths to exercise the real standalone process. It checks dual-stack ADD/CHECK,
restart recovery, offline deletion replay, partial teardown health, retries and
persisted-state cleanup. It also checks module-health query wire rows, native
health JSON and rejection of other table queries across process restarts. Pinned
TCX links retain forwarding during downtime; restart reuses the endpoint map
and rejects pins belonging to other interfaces. The fixture also exercises
recovery from durable intent with missing BPF publication.

The BPF crate is a separate workspace with its own lockfile and toolchain.
Format it separately with `cargo +nightly-2026-04-03 fmt --manifest-path
crates/flowsdn-bpf/Cargo.toml`. Its dependency policy must also be checked
against the repository's `deny.toml`.

Run `socket-lb-live` with the `socket-lb` BPF object for the ClusterIP socket
LB (#292). In an anonymous network namespace it loads the object through the
agent's `SocketLb` owner, attaches the eight cgroup programs to a temporary
child of its own cgroup, and programs frontends with the agent's planner
(`flowsdn_lb::socket`), checking that the kernel maps then equal the plan. It
checks TCP connect over IPv4, IPv6 and IPv4-mapped IPv6; unconnected and
connected UDP with the reply source and `getpeername` reverse translated; EPERM
for a frontend without backends; an untouched non-frontend address; a backend
move; both of two backends chosen over 64 connects; ClientIP affinity (32
connects on one backend, then a move when that backend leaves); and frontend
removal down to empty maps. It restores its cgroup membership on exit.

Run `policy-live` with the `local-delivery` BPF object for endpoint network
policy in the datapath (#292, ADR-0021). In an anonymous network namespace it
loads the object through the agent's `LocalDelivery` owner and test-runs
`to_container` (pod ingress) and `local_delivery` (pod egress, stack mode) on
frames with a dummy device's ifindex as the endpoint's host veth, writing the
policy-endpoint, ipcache and policy maps through the owner. It checks: an
endpoint without a policy entry passes and is not tracked; default deny when
enforced; the host, ARP, neighbour discovery and fragmentation-needed pass;
identity + protocol + port and port-range (LPM) allows; IPv6; non-first
fragments dropped; the reply of an allowed flow passing enforced egress
(conntrack) while a new egress flow is dropped; the aggregate-cluster and
wildcard identities; a top-precedence deny over a broader allow; ICMP echo
replies by conntrack only; maps reading back as written; and removal of
enforcement.

Run `neighbors-live` with no arguments for managed neighbors (#469, spec 10
§3.4). In anonymous network namespaces, with an uplink `a0` and a peer holding
the gateway and an on-link address, it checks the managed-neighbor startup
probe; next hops from FIB-match lookups (gateway, on-link, unreachable); the
agent's reconcile making `extern_learn` + `managed` entries, removing a stray
learned entry and leaving a static one; the kernel resolving a managed entry by
itself; and an address no longer forwardable losing its entry.

Run `host-chain-live` with the `local-delivery` and `socket-lb` BPF objects
for the uplink's whole TCX chain (#484). It attaches the host firewall
(`from_netdev`/`to_netdev`, last) and the NodePort programs
(`nodeport_ingress`/`nodeport_egress`, first) to a veth uplink as the agent
does, enforces host ingress with only world TCP 7001 allowed, and drives real
connections from a peer in its own network namespace: 7001 connects, 7002 does
not and its drop is counted, and a connection the host starts is in the policy
flow map with its reply let in. Test-running either program alone cannot show
that the first one hands packets on to the second.

`socket-live` and `socket-lb-live` use the cgroup v2 hierarchy at
`/sys/fs/cgroup`. Where a container has none there (stormcos's privileged test
pods, #341), they mount cgroup2 at that path in a private mount namespace of
their own process, which shows their own cgroup namespace and vanishes when
they exit; the host's mounts and cgroup root are never used.

When `flowsdn-endpoint-test`'s BPF_PROG_TEST_RUN packet checks fail, the error
names the case and frame size (for example `case ipv4-short (30 bytes): test
run refused: errno 22`). `skb-ctx-matrix` ends a failing run with one line
naming the kernel, the zero-ctx baseline result and the unusable relied-upon
fields, since the test suite reports only a fixture log's last line.
