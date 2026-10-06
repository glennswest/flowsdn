# flowsdn

flowsdn is a Rust networking stack for stormcos, implementing a CNI plugin and
an eBPF endpoint datapath. Its broader goal is Cilium-compatible networking,
services, policy and observability. **That full stack is not implemented yet.**

## What works today

As of 2026-10-03 (source through `7c8a095`), the executable pair is
`flowsdn-agent` and `flowsdn-cni`. The standalone agent provides persisted
endpoint ownership, host-pool IPv4/IPv6 allocation and a bounded HTTP API over a
Unix socket. The primary veth CNI supports ADD, CHECK, DEL, STATUS and VERSION,
including queued offline deletion, and the same executable is the loopback
plugin. With `bpf-pin-root` configured, pinned endpoint maps and TCX links
preserve forwarding across agent downtime; restoration checks interface ownership.

- **The BPF object is embedded.** The agent carries the `local-delivery` object
  built from its own commit and loads it when `bpf-object` is not configured, so
  a node needs nothing beside the binary. `test/build.sh` rebuilds the object
  and refuses an embedded copy whose code differs.
- **Two egress modes.** `egress: fib` (default) FIB-redirects non-local traffic
  in BPF for native routing. `egress: stack` hands every frame from an
  endpoint to the host stack (routing, netfilter), same-node
  pod-to-pod included, and adds a host `/32`/`/128` route per endpoint address. The stormcos edition uses `stack`.
- **Node CNI installation.** `flowsdn-cni install` copies the plugin into the
  host's `/opt/cni/bin` (`flowsdn-cni`, `flowsdn`, and `loopback`
  if absent) and atomically writes `/etc/cni/net.d/00-flowsdn.conflist`.
- **stormcos edition manifests.** [`deploy/stormcos/manifests/`](deploy/stormcos/manifests/)
  holds the ServiceAccount/RBAC, agent ConfigMap and DaemonSet that stormcos
  applies in the flowsdn edition: one node per cluster, static IPv4 pool.

Privileged fixtures have exercised same-node IPv4/IPv6 delivery, explicit native
routing between isolated router namespaces, duplicate attachment, rollback and
restart. Those fixtures are **not acceptance of a two-node Kubernetes network**,
and the edition has not yet been checked live on a stormcos node. The agent
still lacks Node/Pod watches, remote-route reconciliation, integrated
service/policy controllers, an operator process and Hubble observer/relay.
The Kubernetes watch client and HTTPS transport exist as a library and are not
wired into the agent.

Libraries also implement configuration resolution, identity and map layouts,
policy and service planning, Maglev tables, BGP codecs/session state, encryption
and egress plans, proxy ACK handling, flow filtering and cloud request plans.
A library or passing unit test does not imply the feature runs in the agent.
See the [current implementation assessment](docs/implementation-status.md).

The package version and latest published foundation prerelease remain
**0.14.0**. Current main contains unreleased runtime work beyond that prerelease.
A stormcos golden's pinned source revision identifies what a node actually runs;
the package version alone does not distinguish these unreleased commits.

## Interfaces and configuration

- `flowsdn-agent --config PATH` reads a standalone **JSON** configuration.
  `--help`/`-h` and `--version`/`-V` exit successfully without starting the agent.
- The agent's HTTP API uses the configured mode-0600 Unix socket; the optional
  `http-listen` adds a read-only listener on a loopback port (403 for anything
  that changes state), for the stormcos console. There is no Hubble service on 4244, metrics listener or relay.
- `GET /v1/healthz` reports API availability after restore and deletion replay;
  it does not mean the pod network or policy controllers are ready.
  `/v1/health/modules` reports unavailable controllers as degraded.
- Endpoint list/detail, IPAM summaries, allocation and CNI publication/deletion
  routes are documented in the [agent API](docs/agent-api.md). This is a subset
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

Compatibility concerns data shape: the agent serves only the Unix-socket REST
subset documented above, while Hubble observer/relay remain planned. Existing
CNI aliases and specified interface/BPF names are retained for executable lookup,
datapath ABI and restoration compatibility; they do not identify upstream-owned
resources as ours. New configuration/controller defaults use flowsdn names.
See the [resource identity decision](docs/decisions/0017-flowsdn-resource-identity.md)
for migration boundaries and the runtime-name rationale.

## How it ships in stormcos

flowsdn ships as the **`flowsdn` golden** in the stormcos flowsdn edition: the
static musl agent (`/flowsdn-agent`, BPF object embedded) and CNI
(`/opt/cni/bin/flowsdn`) are sealed into the golden. Nodes clone it
copy-on-write and mount it at `/pallets/flowsdn`. The latest golden,
`golden-flowsdn-a7ee3f63195b`, was staged from `c6c96c7`. A source push alone
does not update nodes: the revision must be staged into a new golden and
composed into a stormcos release.

On a node, the edition's DaemonSet runs `image: flowsdn`. The stormcos kubelet
(stormpump runtime) roots a container named `…/flowsdn` on the flowsdn golden,
so nothing is pulled. Its init container runs `/opt/cni/bin/flowsdn install` to
put the plugin and conflist on the host; the agent runs privileged in the host
network namespace with `/var/run/flowsdn` and `/var/lib/flowsdn` from the host.
The edition runs no kube-proxy. ClusterIP Services go through flowsdn's own
socket load balancing in the Kubernetes-mode agent (#292): its cgroup
`connect`/`sendmsg`/`recvmsg`/`getpeername` programs send a socket aimed at a
ClusterIP:port straight to a ready EndpointSlice backend, before routing,
for every pod and host process. The static single-node manifests have no
Service handling. The node provides masquerade for off-node egress. A
multi-node cluster uses the Kubernetes-mode manifests
(`deploy/stormcos/manifests-kubernetes/`): pod CIDRs from the Node, direct
routes to the other nodes' pods (#291), and ClusterIP socket LB (#292). Applying the
manifests is stormcos's side
([stormcos#261](https://github.com/glennswest/stormcos/issues/261)). See the
[deployment contract](deploy/stormcos/README.md).

The authority for the golden lifecycle is
[stormcos's golden documentation](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
Dependency versions and Git revisions in `Cargo.lock` remain build inputs; a
sibling dependency's new commit is not selected automatically.
There is no operator or relay binary to deploy. Storage/PVC provisioning belongs
to stormcos's built-in stormblock driver, not to flowsdn.

## What changed since 2026-09-25

- CNI: Rust loopback entry point, `flowsdn-agent cni install --source PATH`
  (plugin names and loopback only) and `flowsdn-cni install` (also writes the
  conflist).
- Agent: optional `bpf-object` with the embedded object as default; `egress`
  key (`fib`/`stack`) with host routes in stack mode.
- Kubernetes library: bounded Node/Pod watch transport over Fedora system
  OpenSSL ([ADR-0016](docs/decisions/0016-fedora-openssl.md)); owned CRDs use
  `flowsdn.io/v1alpha1` ([ADR-0017](docs/decisions/0017-flowsdn-resource-identity.md), #299).
- Policy: the simulator is the map-state oracle ([ADR-0018](docs/decisions/0018-policy-simulator-oracle.md), #103).
- Release scope: the stormcos golden, plus standalone archives and a Helm chart kept out of it, flowsdn names only ([ADR-0019](docs/decisions/0019-release-scope.md), [chart](docs/helm.md), #294).
- Deployment: stormcos edition manifests and the reproducible
  `tools/build-bpf.sh` object build (#296).
- Tests: the `short`/`medium`/`long` [test container](test/README.md) (#303) and
  the `__sk_buff` `ctx_in` matrix probe `skb-ctx-matrix` (#256).
- Build: the disabled GitHub workflow was removed; builds run through `sc-build`
  and goldens through `stormcentral component stage flowsdn` (#304).

Remaining acceptance is tracked by [four milestones](docs/milestones.md):
working Kubernetes pod networking (#291), services/policy (#292), advanced
networking/observability (#293), and compatibility/release hardening (#294).
Open product items include the console plugin (#297), `sc net` integration
(#298) and a presentation (#302).

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
short|medium|long`) against the commit's own agent, CNI and BPF objects.

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
`openssl-devel` and `pkgconf-pkg-config`. The shipped agent and CNI do not use
that client yet and stay static musl. A Kubernetes-connected agent needs a
GNU/OpenSSL runtime in its golden ([stormcos#171](https://github.com/glennswest/stormcos/issues/171)).
