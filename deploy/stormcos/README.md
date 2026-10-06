# StormOS / stormcos integration contract

## The flowsdn edition's manifests (#296, stormcos#261)

[`manifests/`](manifests/) is what stormcos applies in the flowsdn edition in
place of the cilium manifests (10–75). It contains a ServiceAccount and
read-only RBAC, the agent ConfigMap and the agent DaemonSet:

- **Image.** The DaemonSet runs the node's flowsdn golden (`image: flowsdn`):
  `/flowsdn-agent`, and `/opt/cni/bin/flowsdn` with the BPF object embedded in
  the agent. Nothing is pulled.
- **CNI install.** An init container runs `flowsdn install`. It copies the
  plugin into the node's `/opt/cni/bin` (as `cilium-cni`, `flowsdn-cni`,
  `flowsdn` and, if absent, `loopback`) and atomically writes
  `/etc/cni/net.d/00-flowsdn.conflist`. The `00-` prefix means a leftover
  `05-cilium.conflist` cannot win.
- **Agent.** It runs `egress: stack`. Every frame from a pod, pod-to-pod on
  the node included, goes to the node's stack, and each pod gets a host
  route, so the node's routing and netfilter see every pod flow.

What the node must provide besides the manifests:

- **Services.** Not with these manifests. The owner chose flowsdn's own
  service handling over kube-proxy (stormcos#265). It is the Kubernetes-mode
  agent's socket LB (#292, below), so ClusterIPs need `manifests-kubernetes/`.
- **Off-node egress.** `net.ipv4.ip_forward=1` and a masquerade for
  `10.244.0.0/24` leaving the node. flowsdn does not masquerade yet.
- **Kernel.** 6.6 or newer, with TCX and BTF.

**Limits.** This is one node per cluster: the pool is static and this agent
does not read Node podCIDRs or route to other nodes. Kubernetes mode, below,
lifts that. Without a pin root, an agent restart briefly pauses pod traffic
while it reinstalls endpoints from state.

## Kubernetes mode: more than one node (#291)

[`manifests-kubernetes/`](manifests-kubernetes/) replaces `manifests/` once
the golden carries the GNU agent built with `cargo build --release -p
flowsdn-agent --features kubernetes` and its Fedora OpenSSL runtime
([stormcos#171](https://github.com/glennswest/stormcos/issues/171)). The static
musl agent refuses its configuration. The differences:

- The pod mounts its service account token and gets `K8S_NODE_NAME`. The agent
  lists and watches Nodes and Pods with in-cluster credentials; the kubelet
  points `KUBERNETES_SERVICE_HOST` at the node's apiserver.
- `ipv4-pool: auto`. Each node's pool is its Node's first IPv4 `podCIDRs`
  entry, else `10.<last byte of its InternalIP>.0.0/16` (spec 07 §3.4).
  stormcos sets no podCIDR, so pvetest1 (192.168.31.172) gets
  `10.172.0.0/16` and pvetest2 `10.173.0.0/16`. Node addresses ending in
  96–111 would derive a pool inside the Service range; give such nodes a
  podCIDR.
- `auto-direct-node-routes`. The agent installs `<other node's podCIDR> via
  <its InternalIP> proto kernel` and removes routes for nodes that leave, so
  nodes on one L2 segment reach each other's pods without a tunnel. A node
  that is only reachable through a router is reported as an error.
- The agent sets `net.ipv4.ip_forward`, `net.ipv4.conf.all.forwarding` (IPv6
  forwarding with an IPv6 pool) to 1 and `net.ipv4.conf.all.rp_filter` to 0.
- `service-lb` (#292): ClusterIP Services without kube-proxy. The agent also
  watches Services and EndpointSlices (RBAC adds `services` and
  `discovery.k8s.io/endpointslices`, read-only) and attaches its socket-lb
  programs to the host's cgroup v2 root, mounted from the host's
  `/sys/fs/cgroup` at `/run/flowsdn/cgroupv2` (`cgroup-root`). A socket that
  connects or sends to a ClusterIP:port (TCP or UDP, IPv4, IPv6 or
  IPv4-mapped) is pointed at a random ready backend before routing; UDP
  replies are shown as from the ClusterIP. That covers kube-dns
  (10.96.0.10:53) and the `kubernetes` Service (10.96.0.1:443 -> the
  apiserver). NodePort, LoadBalancer IPs, externalIPs and session affinity
  are not handled; a ClusterIP:port with no ready backend fails `connect`
  with EPERM. Without a pin root the programs detach when the agent exits,
  and ClusterIPs stop working until it is back.

Off-node egress still needs a masquerade, now for the node's derived pool.
Moving a node from the static pool to `auto` needs its endpoints gone (a fresh
install or a drain): restore refuses addresses outside the pool. Status is on
the agent socket and the read-only loopback port: `GET /v1/healthz` (`kubernetes`
member), `GET /v1/node/routes`, `GET /v1/ip` and `GET /v1/service`.

The DaemonSet carries no probe: the agent's health is on its Unix socket only
(see below). It runs privileged as a validation baseline, not a measured
minimum-capability profile. The stormpump runtime enforces no seccomp profile
and drops no capabilities, so [deploy/seccomp](../seccomp) is a no-op on stormcos.

## Golden delivery

The golden carries `/flowsdn-agent` (with the `local-delivery` BPF object
embedded; the Kubernetes-mode agent also embeds `socket-lb`) and `/opt/cni/bin/flowsdn`, both static musl, mounted on a node at
`/pallets/flowsdn`. The stormcos kubelet's stormpump runtime maps an image name
to `/pallets/<last path component>`, so `image: flowsdn` roots the container on
the golden; a different last component (for example `flowsdn-runtime`) is a
registry pull instead. The init container puts the plugin on the host, so the
golden's internal CNI path does not have to be exposed separately. The latest
golden is `golden-flowsdn-a7ee3f63195b` (`c6c96c7`). The authoritative
[golden documentation](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md)
is stormcos's.

## Standalone validation examples

The numbered files beside `manifests/` (`10-namespace.yaml`, `50-config.yaml`,
`60-agent-validation.yaml`, `90-cni-example.yaml`) are the earlier
single-node validation setup, in its own `flowsdn-system` namespace. They differ
from the edition in using a bpffs pin root and dual-stack pools, and in not
installing CNI. Do not apply them together with the edition manifests.

The executable accepts `--config PATH`, whose content is JSON; every key is in
[the runtime reference](../../docs/runtime.md). It does not consume the full
compatibility config catalogue, Kubernetes Node PodCIDRs, Cilium Helm values,
or generic Cilium command-line flags. Pool/gateway values are illustrative and
must not conflict with the node's network. `endpoint-id-max` bounds the ID
allocator, not the capacity of the fixed-size endpoint BPF map.

| Resource | Contract |
|---|---|
| Agent executable | `/flowsdn-agent` from the golden (`image: flowsdn`), same architecture as the kernel; root with Linux BPF/network privileges. |
| BPF object | Embedded in the agent. Set `bpf-object` only to load a different `local-delivery` build of the matching source. |
| Kernel | Linux with TCX (6.6 or newer), BPF syscall support and readable BTF at `/sys/kernel/btf/vmlinux`; see [kernel requirements](../../docs/kernel-requirements.md). |
| Network namespace | Host network namespace (`hostNetwork: true`), so the agent can attach to host veths. |
| bpffs | Only with `bpf-pin-root`: `/sys/fs/bpf` mounted as bpffs, writable and shared with the host. PID 1 mounts it; the example adds no mount init container. |
| State | `/var/lib/flowsdn` durable, writable and owned by one agent (exclusive lock). Keep it together with its matching pins. |
| Runtime directory | `/var/run/cilium` shared with the host CNI process: `cilium.sock` (mode 0600) and `deleteQueue`. |
| CNI executable | On the host's `/opt/cni/bin`. The validation example does not install it; run `flowsdn-cni install` (as the edition's init container does) or install it by hand. |
| Kubernetes credentials | Not used. The examples mount no ServiceAccount token. |

[60-agent-validation.yaml](60-agent-validation.yaml) selects only nodes labelled
`flowsdn.io/validation-node=a`; use exactly one node with its example pool.
`OnDelete` avoids implying that rolling datapath upgrades are accepted. Do not
run it alongside an active Cilium agent or another flowsdn agent.
[90-cni-example.yaml](90-cni-example.yaml) is staging data only: applying the
ConfigMap does not write the host CNI directory.

## API and supervision

See the [agent API contract](../../docs/agent-api.md) for supported methods,
response shapes and unimplemented routes. HTTP runs over the Unix socket and,
read-only, on the node's loopback at `127.0.0.1:9878` (`http-listen`; the agent
is on the host network). That port is for the stormcos console plugin
(stormconsole#83, spec flowsdn#297): endpoints, IPAM, health, config and the
statedb query; mutations return 403 and stay on the socket. There is no
Kubernetes Service, Hubble observer listener on 4244, or relay endpoint to
expose, so the flow view waits for Hubble. No Service manifest is included.

`GET /v1/healthz` on the Unix socket is the present liveness check after startup
restore and offline-deletion replay complete. It is **not** an assertion of
Kubernetes/network readiness. `/v1/health/modules` reports the missing
controllers as degraded. A TCP HTTP probe must use `GET /v1/healthz` on the
loopback port; bare `/healthz` does not exist, and a probe pointed at it would
repeatedly restart a functioning process. The
manifests therefore supply no Kubernetes HTTP probe. Keep readiness
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

## Fedora TLS build boundary

The Kubernetes client selects Fedora system OpenSSL under
[ADR-0016](../../docs/decisions/0016-fedora-openssl.md). Its runtime needs
matching `openssl-libs`, GNU/glibc, OpenSSL configuration/provider files and
certificate trust. The current agent/CNI do not use this client and stay static
musl; a Kubernetes-connected agent needs its golden packaging changed.

Runtime packaging for that integration is tracked in
[stormcos#171](https://github.com/glennswest/stormcos/issues/171).

Existing `/var/run/cilium` compatibility paths do not establish upstream ownership.
The [resource identity decision](../../docs/decisions/0017-flowsdn-resource-identity.md)
separates retained runtime paths, interface/map names and CNI aliases from
flowsdn-owned Kubernetes resources.
