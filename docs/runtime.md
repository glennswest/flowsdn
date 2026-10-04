# Current runtime configuration and deployment

This describes the executable code as of 2026-10-03 (source through
`7c8a095`), including changes since 2026-09-25. The standalone agent owns local endpoints and host-scope IPAM; it
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
| `bpf-object` | Omitted, null or empty: the object embedded in the agent | A `local-delivery` BPF ELF to load instead of the embedded one (built from this commit by `tools/build-bpf.sh`; `test/build.sh` refuses an embedded copy whose code differs). |
| `egress` | `fib` | `fib`: a destination that is not a local endpoint is FIB-redirected in BPF (native routing between router namespaces). `stack`: it goes to the host stack (routing, netfilter, kube-proxy), and every endpoint also gets host `/32`/`/128` routes over its host link. The stormcos edition uses `stack`. |
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
loopback, or IPv4 broadcast addresses. An invalid `egress` value fails startup.
Examples: the stormcos edition's
[ConfigMap](../deploy/stormcos/manifests/61-flowsdn-config.yaml) and the
dual-stack [validation ConfigMap](../deploy/stormcos/50-config.yaml) (pinned).

The CNI executable is invoked through CNI environment variables and JSON on
stdin, not the agent's command-line interface. Its agent socket defaults to
`/var/run/cilium/cilium.sock`, overridden by `CILIUM_SOCK`; its offline queue
defaults to `/var/run/cilium/deleteQueue`, overridden by `FLOWSDN_DELETE_QUEUE`.
These are environment overrides, not CNI JSON keys. When using custom agent
paths, configure both sides consistently.

## Installing the CNI on a node

The CNI executable treats a first argument `install` as the node installer (a runtime never
passes arguments). It copies its own executable into `$CNI_DIR/bin` and writes
the network configuration, then prints a JSON report (`installed`, `conflist`,
`plugin_replaced`, `loopback_replaced`, `warnings`); failure exits 1.

| Environment | Default | Meaning |
|---|---|---|
| `HOST_PREFIX` | `/host` | Prefix for the two defaults below. |
| `CNI_DIR` | `$HOST_PREFIX/opt/cni` | Its `bin/` gets `cilium-cni` (copied atomically), hardlinks `flowsdn-cni` and `flowsdn`, and `loopback`. |
| `CNI_CONF_DIR` | `$HOST_PREFIX/etc/cni/net.d` | Gets `00-flowsdn.conflist`, written atomically with mode 0644. |
| `OVERWRITE_CILIUM` | `true` | `false` keeps an existing regular `cilium-cni` and relinks the aliases to it. |
| `OVERWRITE_LOOPBACK` | `false` | `true` replaces an existing `loopback`; otherwise it is copied only when absent. Loopback failures are warnings. |

The conflist is `{"cniVersion":"1.1.0","name":"flowsdn","plugins":[{"type":"cilium-cni"}]}`:
no chained plugins, no delegated IPAM. The `00-` prefix sorts ahead of a
leftover `05-cilium.conflist`. `flowsdn-agent cni install --source PATH` does the
binary half only (same variables, no conflist). Neither removes an installation.

## CNI input

The CNI entry point reads at most 1 MiB from stdin. `CNI_COMMAND` selects ADD,
CHECK, DEL, STATUS or VERSION; GC is unsupported. VERSION returns supported
versions without contacting the agent. The other supported commands require
`cniVersion` equal to `1.0.0` or `1.1.0`.

| Input | Behavior/default |
|---|---|
| JSON `name` | Required nonempty network name for ADD/CHECK. |
| JSON `type` | The runtime uses it to select the installed binary: the installed conflist names `cilium-cni`; `flowsdn` and `flowsdn-cni` are hardlinks to it. This executable does not validate it (except `loopback`/`flowsdn-loopback`, which select the loopback adapter). |
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
Only CNI 1.0.0/1.1.0 are currently supported. The installers above publish the
`loopback` name.

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
validated reuse at restore. Without a pin root, links belong to the process and
are reinstalled from state at restart, briefly pausing endpoint traffic. This
does not establish rolling upgrade support. In `egress: stack` mode the agent
replaces a host route to each endpoint address over its host link; deleting the
link removes the routes.

Kubernetes Node/Pod watches, automatic remote routes/neighbors, uplink ingress
attachment and identity/policy reconciliation are not wired into this daemon.
The watch client and HTTPS transport in `flowsdn-k8s` are library code only.
An independent routing fixture is evidence for the routing primitive, not a
working two-node Kubernetes deployment.

stormcos ships flowsdn as a **golden** containing the static musl agent
(`/flowsdn-agent`, BPF object embedded) and CNI (`/opt/cni/bin/flowsdn`). Nodes
clone goldens copy-on-write and mount it at `/pallets/flowsdn`; nothing is
pulled. The latest golden is `golden-flowsdn-600aa332b66d`, staged from
`4627158`. The golden/release authority is
[stormcos's golden documentation](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
The flowsdn edition and composition are owned by stormcos; source changes reach
nodes through a newly staged golden and composed release, not through a Git
push alone. The workspace version is still `0.14.0`; the subsequent agent work
is unreleased in this repository's version history.

The [deployment contract](../deploy/stormcos/README.md) describes the edition
manifests (`deploy/stormcos/manifests/`): a DaemonSet with `image: flowsdn`
(the golden itself under the stormpump runtime), an init container running
`flowsdn-cni install`, and the agent with `egress: stack` and a static
single-node IPv4 pool. Whether stormcos applies them is
[stormcos#261](https://github.com/glennswest/stormcos/issues/261); the node must
also run kube-proxy and provide forwarding/masquerade.

`flowsdn-operator` and `flowsdn-hubble` are libraries, without operator or relay
service binaries. Their duties have not moved into the agent. CRD registration
plans use flowsdn's own `flowsdn.io/v1alpha1` group with `Flowsdn*` kinds
([ADR-0017](decisions/0017-flowsdn-resource-identity.md), #299); `cilium.io`
schemas are read only by the explicit migration projection. The agent does not
register or reconcile CRDs. Compatibility with Cilium formats is an integration
goal, not a claim that all Cilium APIs, CRDs, CLIs or networking features work today.

## Fedora TLS build boundary

The Kubernetes client selects Fedora system OpenSSL under
[ADR-0016](decisions/0016-fedora-openssl.md). Building TLS consumers requires `openssl-devel` and
`pkgconf-pkg-config`; runtime requires matching `openssl-libs`, GNU/glibc,
OpenSSL configuration/provider files and certificate trust. Vendoring is disabled.
The current agent/CNI do not use this client and remain static musl. A
Kubernetes-connected agent needs a different golden runtime
([stormcos#171](https://github.com/glennswest/stormcos/issues/171)).
