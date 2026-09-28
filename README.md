# flowsdn

flowsdn is a Rust networking stack for stormcos, implementing a CNI plugin and
an eBPF endpoint datapath. Its broader goal is Cilium-compatible networking,
services, policy and observability. **That full stack is not implemented yet.**

## What works today

As of 2026-09-27 (source through `ce8f4d2`), the executable pair is
`flowsdn-agent` and `flowsdn-cni`. The standalone agent provides persisted
endpoint ownership, host-pool IPv4/IPv6 allocation and a bounded HTTP API over a
Unix socket. The primary veth CNI supports ADD, CHECK, DEL, STATUS and VERSION,
including queued offline deletion. With `bpf-pin-root` configured, pinned endpoint
maps and TCX links preserve forwarding across agent downtime; restoration checks interface ownership.

Privileged fixtures have exercised same-node IPv4/IPv6 delivery, explicit native
routing between isolated router namespaces, duplicate attachment, rollback and
restart. Those fixtures are **not acceptance of a two-node Kubernetes network**.
The agent still lacks Node/Pod watches, remote-route reconciliation, integrated
service/policy controllers, an operator process and Hubble observer/relay.

Libraries also implement configuration resolution, identity and map layouts,
policy and service planning, Maglev tables, BGP codecs/session state, encryption
and egress plans, proxy ACK handling, flow filtering and cloud request plans.
A library or passing unit test does not imply the feature runs in the agent.
See the [current implementation assessment](docs/implementation-status.md).

The package version and latest published foundation prerelease remain
**0.14.0**. Current main contains unreleased runtime work beyond that prerelease.
A stormcos golden's pinned source revision identifies what a node actually runs;
the package version alone does not distinguish these unreleased commits.

The Rust CNI executable now includes a loopback adapter, and
`flowsdn-agent cni install --source PATH` installs the primary compatibility
names and loopback binary. See [installation](crates/flowsdn-cni/README.md#install-binaries).
These additions are awaiting live validation and do not complete cluster acceptance.

## Interfaces and configuration

- `flowsdn-agent --config PATH` reads a standalone **JSON** configuration.
  `--help`/`-h` and `--version`/`-V` exit successfully without starting the agent.
- The agent opens **no TCP ports**. Its HTTP API uses the configured mode-0600
  Unix socket. There is no Hubble service on 4244, metrics listener or relay.
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

flowsdn-owned CRD plans use `flowsdn.io/v1alpha1`, `Flowsdn*` kinds and the
`flowsdn` category. An explicit migration projection reads upstream CRD schemas
and emits flowsdn registration payloads; it is not a live Cilium policy reader
or an instance migration service. The standalone daemon does not register or
reconcile CRDs, and flowsdn must not adopt or garbage-collect existing
`cilium.io` objects.

Compatibility concerns data shape: the agent serves only the Unix-socket REST
subset documented above, while Hubble observer/relay remain planned. Existing
CNI aliases and specified interface/BPF names are retained for executable lookup,
datapath ABI and restoration compatibility; they do not identify upstream-owned
resources as ours. New configuration/controller defaults use flowsdn names.
See the [resource identity decision](docs/decisions/0016-flowsdn-resource-identity.md)
for migration boundaries and the runtime-name rationale.

## How it ships in stormcos

flowsdn ships as the **`flowsdn` golden** in the stormcos flowsdn edition: static
musl agent and CNI binaries are sealed into the release and mounted under
`/pallets/flowsdn`. The golden contains `/flowsdn-agent` and
`/opt/cni/bin/flowsdn` internally; host CNI exposure still needs verification
against the separate host CNI mount. Nodes clone
the golden copy-on-write. This delivery path does not pull a flowsdn container
image. A source push alone does not update nodes: the selected revision must be
built into a new golden and composed into a stormcos release.

The authority for that lifecycle is
[stormcos's golden documentation](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
This authority moved from stormpump to stormcos on 2026-09-22.
Dependency versions and Git revisions in `Cargo.lock` remain build inputs; a
sibling dependency's new commit is not selected automatically.

The agent also requires a matching `local-delivery` BPF object, mounted bpffs,
persistent state, host networking and Linux BPF/network privileges. Shipping
only the two binaries is insufficient to start this datapath. The current golden
recipe omits the BPF object; that and host CNI exposure are tracked in
[stormcos#145](https://github.com/glennswest/stormcos/issues/145). The
[deployment contract and validation manifests](deploy/stormcos/README.md)
describe these resources, CNI ownership and Unix-socket supervision. The example
DaemonSet uses an image placeholder and is not an installable production chart.
There is no operator or relay binary to deploy. Storage/PVC provisioning belongs
to stormcos's built-in stormblock driver, not to flowsdn.

## What changed since 2026-09-18

The history through `ce8f4d2` adds the standalone agent and persisted recovery,
configuration/CNI ownership checks, persistent BPF attachment, endpoint inventory
and exact IPAM read APIs, deployment examples and successful help/version flags.
It also adds operator/Kubernetes/Hubble and advanced-networking library
primitives, independent policy checks, kernel probes and an opt-in amd64 seccomp
profile. [Implementation status](docs/implementation-status.md) links the source
and validation records and separates those additions from the remaining gates.

Remaining acceptance is tracked by [four milestones](docs/milestones.md):
working Kubernetes pod networking (#291), services/policy (#292), advanced
networking/observability (#293), and compatibility/release hardening (#294).
The console plugin (#297), `sc net` integration (#298), presentation (#302) and
short/medium/long component test containers (#303) remain separate work.

## Building, testing and reading the repository

Use Linux and the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
cargo xtask check
cargo test --workspace --all-features --release --locked
cargo xtask deny
```

`check` runs formatting, Clippy, tests and compile checks for x86-64/arm64 Linux
musl, including feature-gated fixtures. `deny` requires `cargo-deny`. Build output
uses standard Cargo configuration. Privileged runtime fixtures have additional
requirements documented in [flowsdn-bpftest](crates/flowsdn-bpftest/README.md);
cross-compilation alone does not prove runtime support.

Current project builds are dispatched through stormcentral. The retained
GitHub Actions workflow is historical configuration awaiting removal in
[#304](https://github.com/glennswest/flowsdn/issues/304), not the current build
service. This documentation audit adds no new runtime validation claim.

Start with the [documentation guide](docs/README.md), current runtime/API and
deployment references. `docs/spec/` defines intended contracts;
`docs/inventory/` describes Cilium v1.20.1 (`7d68cfb394`); historical decisions,
workcycles and release records are not lists of enabled features. Test corpora
are data until a working adapter executes them. Project tools and harnesses are
Rust; fixture data uses txtar, JSON, YAML and TOML.

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and the
[licensing and clean-room rules](docs/licensing.md).
