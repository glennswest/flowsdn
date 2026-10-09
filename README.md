# flowsdn

flowsdn is a Rust networking stack for stormcos, implementing a CNI plugin and
an eBPF endpoint datapath. Its broader goal is Cilium-compatible networking,
services, policy and observability. **That full stack is not implemented yet.**

## What works today

As of 2026-10-09 (source through `eed1aca`), the executable pair is
`flowsdn-agent` and `flowsdn-cni`. The agent provides persisted endpoint
ownership, IPv4/IPv6 host-scope allocation and a bounded HTTP API over a Unix
socket. The primary veth CNI supports ADD, CHECK, DEL, STATUS and VERSION,
including queued offline deletion, and the same executable is the loopback
plugin. With `bpf-pin-root` configured, pinned endpoint maps and TCX links
preserve forwarding across agent downtime; restoration checks interface ownership.

- **The BPF objects are embedded.** The agent carries `local-delivery` (and,
  in Kubernetes mode, `socket-lb`) built from its own commit and loads them
  when `bpf-object` is not configured. `bpf-objects.lock` records their
  hashes; `test/build.sh` rebuilds them and refuses a stale embedded copy.
- **Two egress modes.** `egress: fib` (default) FIB-redirects non-local traffic
  in BPF for native routing. `egress: stack` hands every frame from an
  endpoint to the host stack (routing, netfilter), same-node
  pod-to-pod included, and adds a host `/32`/`/128` route per endpoint address.
  The stormcos edition uses `stack`.
- **Node CNI installation.** `flowsdn-cni install` copies the plugin into the
  host's `/opt/cni/bin` (`flowsdn-cni`, `flowsdn`, and `loopback`
  if absent) and atomically writes `/etc/cni/net.d/00-flowsdn.conflist`.
- **Kubernetes mode** (agent `kubernetes` cargo feature, GNU build with Fedora
  OpenSSL; the build the golden carries). Node and cluster Pod watches; `auto`
  pools from the Node's pod CIDR (or `10.<last IPv4 byte>.0.0/16`); direct
  routes `<podCIDR> via <nodeIP>` to every other node with conflict checks and
  pruning; forwarding sysctls; `GET /v1/ip`, `/v1/node/routes`, `/v1/service`.
- **Services without kube-proxy** (`kubernetes.service-lb`, default on, #292).
  Service + EndpointSlice watches program the `socket-lb` cgroup programs
  (`connect`/`sendmsg`/`recvmsg`/`getpeername`, IPv4/IPv6/IPv4-mapped, TCP/UDP):
  ClusterIPs, externalIPs, LoadBalancer ingress IPs and NodePorts for clients
  on the node, with `internalTrafficPolicy`/`externalTrafficPolicy: Local` and
  ClientIP session affinity.
- **NodePort/LB/externalIP from outside the cluster** (`kubernetes.node-port`,
  default on). `nodeport_ingress`/`nodeport_egress` on the uplink's TCX hooks
  DNAT to this node's backends or, for `externalTrafficPolicy: Cluster`, SNAT
  and FIB-redirect to other nodes' backends; IPv4 and IPv6.
- **Kubernetes Events and pod tagging.** Events on Pods and the Node
  (`EndpointCreated`, `IPAllocationFailed`, `PodCIDRSelected`, …) and the
  `flowsdn.io/pod-networks` annotation on local Pods, with flowsdn's entry in
  the Multus `k8s.v1.cni.cncf.io/network-status` beside it (#298, #328, #371).
- **stormcos edition manifests.** [`deploy/stormcos/manifests-kubernetes/`](deploy/stormcos/manifests-kubernetes/)
  (RBAC, ConfigMap, DaemonSet, the 22 CRDs) is what the edition ships;
  [`manifests/`](deploy/stormcos/manifests/) is the older single-node,
  static-pool set without Service handling.

Privileged fixtures in the test container's `medium` suite have exercised
same-node IPv4/IPv6 delivery, native routing between router namespaces, the
socket LB and the IPv4 NodePort/SNAT programs, on a stormcos 7.2 kernel
(pvetest2). Those fixtures are **not acceptance of a two-node Kubernetes
network**: two-node acceptance (#291) and live ClusterIP acceptance on a node
(#292) are still open, and the IPv6 NodePort programs have not run on a kernel yet.

The Kubernetes-mode agent also allocates cluster identities for its Pods
(FlowsdnIdentity objects, #291). Not implemented in the agent: a BPF ipcache,
network policy in the datapath, flowsdn's own masquerade, Maglev, DSR,
NAT46/64, socket termination, CRD controllers, an operator process and the
Hubble observer/relay. Libraries also implement configuration resolution,
identity and map layouts, a Kubernetes NetworkPolicy importer and policy
simulator, Maglev tables, BGP codecs/session state, encryption and egress
plans, proxy ACK handling, flow filtering and cloud request plans. A library or
passing unit test does not imply the feature runs in the agent. See the
[current implementation assessment](docs/implementation-status.md).

The package version and latest published foundation prerelease remain
**0.14.0**. Current main contains unreleased runtime work beyond that prerelease.
A stormcos golden's pinned source revision identifies what a node actually runs;
the package version alone does not distinguish these unreleased commits.

## Interfaces and configuration

- `flowsdn-agent --config PATH` reads a standalone **JSON** configuration.
  `--help`/`-h` and `--version`/`-V` exit successfully without starting the agent.
- The agent's HTTP API uses the configured mode-0600 Unix socket; the optional
  `http-listen` adds a read-only listener on a loopback port (403 for anything
  that changes state), for the stormcos console; non-loopback addresses are
  refused. There is no Hubble service on 4244, metrics listener or relay.
- `GET /v1/healthz` reports API availability after restore and deletion replay;
  it does not mean the pod network or policy controllers are ready.
  `/v1/health/modules` reports unavailable controllers as degraded.
- Endpoint list/detail, IPAM summaries, allocation, CNI publication/deletion
  and the Kubernetes-mode `/v1/ip`, `/v1/node/routes` and `/v1/service` views
  (16 routes, `api::ROUTES`) are documented in the [agent API](docs/agent-api.md). This is a subset
  of the reference REST shape, not complete Cilium CLI/API compatibility.
- The [runtime configuration reference](docs/runtime.md) lists every standalone
  key, required value, default and CNI override. The separate 539-key
  [configuration library](crates/flowsdn-config/README.md) is a compatibility
  catalogue, **not** the executable's accepted CLI or active feature set.

flowsdn ships 22 custom resources in `flowsdn.io/v1alpha1` ([CRD reference](docs/crds.md),
#325): `Flowsdn*` kinds, `fs*` short names and the `flowsdn` category, with the
reference schemas (validation, status subresources, printer columns) projected
from vendored Cilium v1.20.1 CRDs. The manifests are generated into
`deploy/stormcos/manifests-kubernetes/crds/`, with examples and offline
accept/reject validation for every kind. No controller reads or writes them
yet: the daemon does not register or reconcile CRDs, and flowsdn must not adopt
or garbage-collect existing `cilium.io` objects.

Compatibility concerns data shape (CNI result, agent API, BPF map layouts),
not names: nothing flowsdn ships carries the reference project's name. The CNI
type is `flowsdn-cni`, the socket `/var/run/flowsdn/flowsdn.sock`, the BPF maps
`flowsdn_*`, and `tools/check-no-cilium.sh` checks the shipped files on every
build ([ADR-0020](docs/decisions/0020-no-reference-names-shipped.md)). Moving a
cluster from Cilium is a one-time conversion ([migration](docs/migration-from-cilium.md)).
See the [resource identity decision](docs/decisions/0017-flowsdn-resource-identity.md)
for CRD ownership boundaries.

## How it ships in stormcos

flowsdn ships as the **`flowsdn` golden** in the stormcos flowsdn edition: the
Kubernetes-mode agent (`/flowsdn-agent`, GNU build with its Fedora glibc/OpenSSL
runtime and the BPF objects embedded, stormcos#171), the static musl CNI
(`/opt/cni/bin/flowsdn`) and `nft` for the node's masquerade. Nodes clone it
copy-on-write and mount it at `/pallets/flowsdn`. The latest golden,
`golden-flowsdn-a690ebee2ba7`, was staged from `4447eeb` (IPv6 NodePort,
identity allocation, network-status). A source push
alone does not update nodes: the revision must be staged into a new golden and
composed into a stormcos release.

On a node, the edition's DaemonSet runs `image: flowsdn`. The stormcos kubelet
(stormpump runtime) roots a container named `…/flowsdn` on the flowsdn golden,
so nothing is pulled. Its init container runs `/opt/cni/bin/flowsdn install` to
put the plugin and conflist on the host; the agent runs privileged in the host
network namespace with `/var/run/flowsdn` and `/var/lib/flowsdn` from the host.
The edition runs no kube-proxy: Services go through the agent's socket LB and
uplink NodePort programs (`kubernetes.service-lb`, `kubernetes.node-port`,
#292), for every pod and host process. The node provides forwarding and the
masquerade for off-node egress. The edition uses the Kubernetes-mode manifests
(`deploy/stormcos/manifests-kubernetes/`): pod CIDRs from the Node, direct
routes to the other nodes' pods (#291) and Service load balancing (#292). The
older static `manifests/` set has no Service handling. Applying the manifests
is stormcos's side ([stormcos#261](https://github.com/glennswest/stormcos/issues/261)).
See the [deployment contract](deploy/stormcos/README.md).

Outside stormcos, a standalone install is a Helm chart
([`install/kubernetes/flowsdn`](install/kubernetes/flowsdn), [docs](docs/helm.md))
with an agent image (`images/agent`) and release archives
(`deploy/release/build.sh`: static agent and CNI per architecture plus
`SHA256SUMS`); none of it is in the golden, and none is published yet (#294).

The authority for the golden lifecycle is
[stormcos's golden documentation](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
Dependency versions and Git revisions in `Cargo.lock` remain build inputs; a
sibling dependency's new commit is not selected automatically.
There is no operator or relay binary to deploy. Storage/PVC provisioning belongs
to stormcos's built-in stormblock driver, not to flowsdn.

## What changed since 2026-10-02

- Services (#292): socket-LB ClusterIPs, then externalIPs, LoadBalancer IPs and
  NodePorts for in-cluster clients, traffic policies and ClientIP affinity;
  uplink NodePort programs with node-local backends, SNAT to other nodes'
  backends (IPv4) and IPv6. The socket LB attaches on the 7.2 kernel since
  `cda5799` (no `BPF_F_ALLOW_MULTI`).
- Policy library (#292): Kubernetes NetworkPolicy importer and lowering to the
  policy simulator, with evaluate-versus-compiled-map agreement tests. Not
  wired into the agent.
- Agent: Kubernetes Events, stable route list and an `agent` healthz member
  (#298); `flowsdn.io/pod-networks` and Multus `network-status` (#371) annotations and pod/container fields on
  `/v1/endpoint` and `/v1/ip` (#328); read-only loopback `http-listen` (#297).
- CRDs: 22 `flowsdn.io/v1alpha1` kinds generated from vendored schemas, with
  printer columns and offline validation ([CRD reference](docs/crds.md), #325).
- Release scope: the stormcos golden, plus standalone archives and a Helm chart kept out of it, flowsdn names only ([ADR-0019](docs/decisions/0019-release-scope.md), [chart](docs/helm.md), #294); `bpf-objects.lock` (#245).
- No reference-project names in anything shipped, checked on every build by `tools/check-no-cilium.sh`; BPF maps renamed `flowsdn_*` ([ADR-0020](docs/decisions/0020-no-reference-names-shipped.md), [migration](docs/migration-from-cilium.md), #330).
- Tests: the `short`/`medium`/`long` [test container](test/README.md) ran on
  hardware (#303, #256 `skb-ctx-matrix`); `perf` and `perf-scale` suites
  compare flowsdn with Cilium (#321, not run yet).

Remaining acceptance is tracked by [four milestones](docs/milestones.md):
working Kubernetes pod networking (#291), services/policy (#292), advanced
networking/observability (#293), and compatibility/release hardening (#294).
The console plugin (stormconsole#83) and `sc net` (stormcos#318) are built by
their own projects on flowsdn's API, events and CRD columns.

## Building, testing and reading the repository

Use Linux and the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
cargo xtask check
cargo test --workspace --all-features --release --locked
cargo xtask deny
```

`check` runs formatting, Clippy, tests and compile checks for x86-64/arm64 Linux
musl for non-TLS dependency closures, including feature-gated fixtures.
TLS consumers use native GNU checks and require Fedora OpenSSL; target
sysroots and runtime checks are needed for cross-architecture TLS validation. `deny` requires `cargo-deny`. Build output
uses standard Cargo configuration. Privileged runtime fixtures have additional
requirements documented in [flowsdn-bpftest](crates/flowsdn-bpftest/README.md);
cross-compilation alone does not prove runtime support.

On test machines, stormcentral runs the [test container](test/README.md) (`/test
short|medium|long`) against the commit's own agent, CNI and BPF objects, and
`/test perf|perf-scale` (`flowsdn-perf`) on the cluster's own network.

Maintainer builds and tests run with `sc-build` after a commit is pushed; it
fetches that revision into a disposable build directory. GitHub Actions is
disabled and no GitHub workflow builds, tests or publishes this project.
flowsdn goldens use `stormcentral component stage flowsdn`; stormcentral records
the golden and files the release request. See [build and publication](docs/build-and-test.md)
for the actual commands and the distinction from ordinary Cargo development.

For a short overview, see the [presentation](docs/presentation.md) (a Marp deck).
Start with the [documentation guide](docs/README.md), current runtime/API and
deployment references. `docs/spec/` defines intended contracts;
`docs/inventory/` describes Cilium v1.20.1 (`7d68cfb394`); historical decisions,
workcycles and release records are not lists of enabled features. Test corpora
are data until a working adapter executes them. Project tools and harnesses are
Rust; fixture data uses txtar, JSON, YAML and TOML.

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and the
[licensing and clean-room rules](docs/licensing.md).

## Fedora TLS build boundary

The Kubernetes client links Fedora system OpenSSL
([ADR-0016](docs/decisions/0016-fedora-openssl.md)); building it needs
`openssl-devel` and `pkgconf-pkg-config`. The default agent build and the CNI
do not link it and stay static musl (the release archives). The
Kubernetes-mode agent is a GNU build; the golden carries its Fedora runtime
([stormcos#171](https://github.com/glennswest/stormcos/issues/171)).
