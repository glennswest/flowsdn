# Current runtime configuration and deployment

This describes the executable code as of 2026-09-27, including changes since
2026-09-18. The standalone agent owns local endpoints and host-scope IPAM; it
is not yet a Kubernetes network controller. The broader configuration catalogue
and specifications describe library contracts and planned integrations, not
additional options accepted by this executable.

## Agent configuration

Run `flowsdn-agent --config PATH` with a JSON file. `--help`/`-h` and
`--version`/`-V` succeed without reading configuration. There is no config-reload
API or generic compatibility flag parser. Configuration is read once at startup,
limited to 1 MiB. The authoritative reader is
[`Config::read`](../crates/flowsdn-agent/src/api.rs).

| Key | Required/default | Meaning |
|---|---|---|
| `socket-path` | Required nonempty string | Unix HTTP socket; created with mode 0600. |
| `state-dir` | Required nonempty string | Durable endpoint state; exclusive ownership lock. |
| `bpf-object` | Required nonempty string | Matching `local-delivery` BPF ELF, supplied separately from the agent binary. |
| `bpf-pin-root` | Omitted, null or empty: disabled | Dedicated bpffs directory for persistent map and TCX ownership. |
| `delete-queue` | Omitted, null or empty: `deleteQueue` in the socket's parent directory | Durable CNI offline deletion queue. |
| `ipv4-pool` | Omitted, null or empty: disabled | IPv4 host allocation CIDR. |
| `ipv6-pool` | Omitted, null or empty: disabled | IPv6 host allocation CIDR. At least one family must be enabled. |
| `ipv4-gateway` | Required when IPv4 is enabled | IPv4 router address, excluded from allocation. Must be absent/empty when IPv4 is disabled. |
| `ipv6-gateway` | Required when IPv6 is enabled | IPv6 router address, excluded from allocation. Must be absent/empty when IPv6 is disabled. |
| `device-mtu` | Required integer, at least 1280 | Device MTU. |
| `route-mtu` | Required integer, at least 1280 | Route MTU; must not exceed device MTU. |
| `endpoint-id-max` | `4095` | Integer in `1..=65535`; bounds ID allocation, not BPF map capacity. |

Unknown JSON keys are currently ignored; they do not enable features. Gateway
addresses must match their family and cannot be unspecified, multicast,
loopback, or IPv4 broadcast addresses. The full example is
[the standalone ConfigMap](../deploy/stormcos/50-config.yaml).

The CNI executable is invoked through CNI environment variables and JSON on
stdin, not the agent's command-line interface. Its agent socket defaults to
`/var/run/cilium/cilium.sock`, overridden by `CILIUM_SOCK`; its offline queue
defaults to `/var/run/cilium/deleteQueue`, overridden by `FLOWSDN_DELETE_QUEUE`.
These are environment overrides, not CNI JSON keys. When using custom agent
paths, configure both sides consistently. The golden carries the plugin at its internal `/opt/cni/bin/flowsdn` path.
The host CNI invocation path must be provided separately: the image mounts the
flowsdn golden at `/pallets/flowsdn`, while `/opt/cni/bin` is a separate volume.
Do not infer host installation merely from the file existing inside the golden.

## CNI input

The CNI entry point reads at most 1 MiB from stdin. `CNI_COMMAND` selects ADD,
CHECK, DEL, STATUS or VERSION; GC is unsupported. VERSION returns supported
versions without contacting the agent. The other supported commands require
`cniVersion` equal to `1.0.0` or `1.1.0`.

| Input | Behavior/default |
|---|---|
| JSON `name` | Required nonempty network name for ADD/CHECK. |
| JSON `type` | The runtime uses `flowsdn` to select the installed plugin; this executable does not validate it. |
| JSON `chaining-mode` | Absent/empty; a nonempty string is rejected. |
| JSON `ipam.type` | Absent/empty; delegated IPAM is rejected. Allocation comes from the agent. |
| JSON `prevResult` | Absent/null for primary ADD; CHECK uses prior interfaces, IPs and routes for validation. |
| `CNI_CONTAINERID`, `CNI_IFNAME`, `CNI_NETNS`, `CNI_PATH` | Required nonempty environment values for ADD/CHECK. Interface names must be shorter than 16 bytes and contain neither slash nor NUL. |
| `CNI_ARGS` | Optional semicolon-separated `key=value` pairs. `K8S_POD_NAME`, `K8S_POD_NAMESPACE`, `K8S_POD_UID` default to empty metadata. |
| `CILIUM_SOCK` | Default `/var/run/cilium/cilium.sock`. |
| `FLOWSDN_DELETE_QUEUE` | Default `/var/run/cilium/deleteQueue` for offline DEL. |

MTUs, gateways and pools come from the agent response, not extra CNI JSON
options. DEL tolerates missing container/interface values and namespace for
idempotent cleanup; unknown commands fail. See the authoritative
[request parser](../crates/flowsdn-cni/src/lib.rs) and
[command implementation](../crates/flowsdn-cni/src/runtime.rs).

## Loopback CNI

The CNI executable also dispatches by `loopback`/`flowsdn-loopback` basename or
configuration type. This adapter operates on namespace `lo` independently of
the agent: ADD raises it and returns its addresses, CHECK requires UP, and DEL
lowers it (a missing namespace succeeds). VERSION and STATUS require no namespace.
Only CNI 1.0.0/1.1.0 are currently supported. Install the compatibility names with `flowsdn-agent cni install --source PATH`;
`CNI_DIR` and overwrite controls are described in [the CNI crate](../crates/flowsdn-cni/README.md).

## Ports and APIs

The agent opens **no TCP or UDP listener**. HTTP/1.1 is served on `socket-path`.
It does not serve Hubble gRPC on port 4244, a relay, a metrics listener, or a
Kubernetes Service endpoint. Port numbers in subsystem specifications or
library configuration must not be used as evidence that the daemon listens.

The [API contract](agent-api.md) lists every supported method and response
shape: config, endpoint inventory/detail/publication/deletion, host IPAM,
module health and the read-only health StateDB query. Requests are processed
serially, one per connection, with 16 KiB headers, 4 MiB bodies and a two-second
request budget. There is no pagination, watch endpoint or HTTP authentication;
access is controlled by socket permissions. Pending leases requesting
expiration time out after 600 seconds.

`GET /v1/healthz` reports initial API availability after restoration and queued
deletion replay. `/healthz` and `/readyz` are not implemented. Module health
explicitly marks Kubernetes, identity and policy controllers as unavailable.
The config response's `ipam-mode: kubernetes` is a compatibility value: actual
allocation uses the configured local pools, without Kubernetes PodCIDR lookup.

## Runtime behavior and shipping

The agent and CNI implement native veth attachment, local IPv4/IPv6 allocation,
endpoint persistence, teardown and offline deletion replay. Configured bpffs
pins retain endpoint maps and TCX ownership across process absence and allow
validated reuse at restore. This does not establish rolling upgrade support.
Kubernetes Node/Pod watches, automatic remote routes/neighbors, uplink ingress
attachment and identity/policy reconciliation are not wired into this daemon.
An independent routing fixture is evidence for the routing primitive, not a
working two-node Kubernetes deployment.

stormcos ships flowsdn as a **golden** containing static musl agent and CNI
binaries. The current recipe seals a 64 MiB golden with `/flowsdn-agent` and
`/opt/cni/bin/flowsdn`; it does not include the required `local-delivery` BPF
object. Nodes clone goldens copy-on-write; this delivery path does not pull
an OCI image. The golden/release authority is
[stormcos's golden documentation](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
The builder and its authority moved from stormpump to stormcos on 2026-09-22.
The flowsdn edition and composition are owned by stormcos; source changes reach
nodes through a rebuilt golden and composed release, not through a Git push
alone. The version still reported by the current workspace is `0.14.0`; the
subsequent agent work is unreleased in this repository's version history.

The [deployment contract](../deploy/stormcos/README.md) specifies the required
BPF object, writable bpffs and durable state, host network namespace and
privileges. Its DaemonSet is a validation example with an image placeholder,
not a published production image. A host-supervised golden can provide these
resources directly. The missing object and host CNI exposure are tracked in
[stormcos#145](https://github.com/glennswest/stormcos/issues/145). The example CNI ConfigMap does not install itself into the
host's CNI configuration directory.

`flowsdn-operator` and `flowsdn-hubble` are libraries, without operator or relay
service binaries. Their duties have not moved into the agent. Kubernetes CRD
projection still uses the Cilium API group; the ownership correction requested
in [#299](https://github.com/glennswest/flowsdn/issues/299) remains pending.
Compatibility with Cilium formats is an integration goal, not a claim that
all Cilium APIs, CRDs, CLIs or networking features work today.
