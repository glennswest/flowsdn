# StormOS / stormcos integration contract

These examples describe the **current standalone endpoint runtime**. They do
not install a functioning Kubernetes pod network. They address the deployment
boundary in [issue #296](https://github.com/glennswest/flowsdn/issues/296) while
its operator, Kubernetes and relay requirements remain open.

The executable accepts `--config PATH`, whose content is JSON. The ConfigMap
in [50-config.yaml](50-config.yaml) is a complete example of the keys that the
current executable reads. It does not consume the full compatibility config
catalogue, Kubernetes Node PodCIDRs, Cilium Helm values, or generic Cilium
command-line flags. The pool/gateway values are illustrative and must not
conflict with the node's network. Each enabled family needs a gateway; it is
excluded from allocation. Both MTUs must be at least 1280 and route MTU must
not exceed device MTU. This example is native veth mode; no encapsulation or
service load balancing is enabled by these keys. `endpoint-id-max` bounds the
ID allocator, not the capacity of the current fixed-size endpoint BPF map.

## Required host resources

| Resource | Contract |
|---|---|
| Agent executable | Trusted `flowsdn-agent`, same architecture as the kernel; execute as root with Linux BPF/network privileges. The example's source hostPath must be adjusted to the actual golden layout. |
| BPF object | Trusted `local-delivery` ELF from the matching source/ABI build, installed separately at the configured `bpf-object` path. Shipping only agent and CNI binaries is insufficient. |
| Kernel | Supported Linux with TCX (6.6 or newer), BPF syscall support, and readable kernel BTF at `/sys/kernel/btf/vmlinux`; see [kernel requirements](../../docs/kernel-requirements.md). |
| Network namespace | The agent must operate in the host network namespace so it can validate and attach to host veths. Use `hostNetwork: true` for a pod. |
| bpffs | `/sys/fs/bpf` must already be mounted as bpffs, writable and shared with the host. The dedicated `bpf-pin-root` holds endpoint map/TCX ownership. A normal directory is not a substitute. |
| State | `/var/lib/flowsdn` must be durable, writable and owned by one agent. Startup takes an exclusive state lock. Preserve it together with its matching pins. |
| Runtime directory | `/var/run/cilium` must be shared with the host CNI process. The compatibility socket is `cilium.sock`, mode 0600, and the offline queue is `deleteQueue`. This directory should remain available across agent process restarts. |
| CNI executable | `/opt/cni/bin/flowsdn` must already exist on the host, as the golden provides. No copy-binaries init container is included. The container runtime also needs its ordinary CNI loopback setup. |
| Host PID/IPC namespaces | Not required by the present agent. The host-invoked CNI receives the sandbox namespace path from the container runtime and performs namespace/link configuration itself. |
| Kubernetes credentials | Not used by this runtime. The sample disables ServiceAccount token mounting and grants no API permissions. |

[60-agent-validation.yaml](60-agent-validation.yaml) expresses these mounts and
namespaces. It deliberately contains an image placeholder: Kubernetes still
requires a trusted container image even when the executable is bind-mounted
from a golden. No flowsdn runtime image is claimed to exist at that placeholder.
Replace it with a pinned image digest and verify the two `File` hostPaths.
The golden must also carry the matching BPF object; there is no init-container
download. PID 1 already owns bpffs mounting, so no mount-bpffs init container is
included. `HostToContainer` shares existing mounts without granting the pod a
bidirectional mount channel.

The DaemonSet selects only nodes explicitly labelled
`flowsdn.io/validation-node=a`; use exactly one node with its example pool.
`OnDelete` avoids implying that rolling datapath upgrades are accepted. Its
privileged security context is an explicit validation baseline, **not** a
measured minimum-capability production profile. The restricted seccomp work in
[deploy/seccomp](../seccomp) does not establish every future agent feature's
syscall requirements. Do not run this owner alongside an active Cilium agent,
another flowsdn supervisor, or a network operator reconciling Cilium workloads.
A host-supervised golden can instead provide the same resources directly; no
DaemonSet, image pull, ServiceAccount or RBAC is then needed.

The CNI file in [90-cni-example.yaml](90-cni-example.yaml) is staging data only.
It selects the host binary named `flowsdn`, with no chained plugin or delegated
IPAM. Applying that ConfigMap does not write the host CNI directory. The current
plugin uses `CILIUM_SOCK` and `FLOWSDN_DELETE_QUEUE` environment overrides, not
JSON socket/queue keys; the example uses its built-in paths so no environment
overrides are required. Do not activate it as a node's primary CNI until the
network acceptance gates below are met.

## API and supervision

See the [agent API contract](../../docs/agent-api.md) for supported methods,
response shapes and unimplemented routes. HTTP runs over the Unix socket only.
There is no agent TCP listener, Kubernetes Service, Hubble observer listener on
4244, or relay endpoint to expose. No Service manifest or guessed container
port is included.

`GET /v1/healthz` on the Unix socket is the present liveness check after startup
restore and offline-deletion replay complete. It is **not** an assertion of
Kubernetes/network readiness. `/v1/health/modules` reports the missing
controllers as degraded. A supervisor that only accepts a TCP HTTP path must
add Unix-socket probing or an explicit local adapter; pointing it at `/healthz`
on an invented TCP port would repeatedly restart a functioning process. The
sample therefore supplies no unsupported Kubernetes HTTP probe. Keep readiness
for pod-network use gated on the actual cluster tests.

## Current behavior and remaining integration

The endpoint/CNI fixture validates same-node IPv4/IPv6 traffic, endpoint
ownership, duplicate ADD, offline deletion and process restoration. With the
configured pin root, endpoint maps and TCX links persist through process
absence; restore reuses validated map ownership. This does not establish
arbitrary upgrade compatibility or automatic cleanup of orphaned pod state.

The separate native-routing fixture demonstrates IPv4/IPv6 traffic across two
isolated router namespaces with explicit routes and neighbors, and confirms
that missing routes or detached BPF stop forwarding. It is not a two-node
Kubernetes installation. This agent does not watch Nodes or Pods, learn remote
PodCIDRs, install remote routes/neighbors, attach the uplink ingress program,
or reconcile identity and policy. Assigning different static pools alone does
not provide those behaviors. Its config response's compatibility value
`ipam-mode: kubernetes` must not be interpreted as an active Kubernetes IPAM
controller; allocations currently come from the configured host pools.

`flowsdn-operator` is a library, not a deployed controller. The agent does not
absorb operator duties: pool allocation, identity/node lifecycle, CRD garbage
collection and coordinated multi-node allocation remain to be implemented.
`flowsdn-hubble` is also a library; the current executable exposes neither the
Hubble observer gRPC service nor a relay. A console must show these capabilities
as unavailable, rather than infer that a relay is unnecessary.

Before comparing two StormOS nodes as a working pod network, complete the
Node/Pod and routing integrations, select and implement multi-node IPAM
ownership, install CNI under one owner, and demonstrate same-node/cross-node
IPv4/IPv6, pod churn, agent restart/recovery and cleanup. Service routing,
network policy, operator controllers and flow/relay APIs have their own
[implementation acceptance gates](../../docs/milestones.md). No example here
marks those gates complete.
