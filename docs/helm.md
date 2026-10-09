# The flowsdn Helm chart

`install/kubernetes/flowsdn` installs flowsdn on a Kubernetes cluster that does not
run stormcos (ADR-0019, #294). stormcos nodes get flowsdn from the golden and
`deploy/stormcos/manifests*`; none of the chart is in the golden.

The chart creates, in the release namespace (use `kube-system`):

- the 22 `flowsdn.io` CRDs (the chart's `crds/`, generated with the stormcos copies;
  see [CRD reference](crds.md));
- ServiceAccount `flowsdn`, ClusterRoles/Bindings `flowsdn` (Nodes, Pods, Namespaces,
  Services, EndpointSlices read-only; Events create/update, #298; Pods patch for the
  `flowsdn.io/pod-networks` annotation, #328) and `flowsdn-crds` (spec 13 §4.7);
- ConfigMap `flowsdn-config` with the agent's `agent.json` ([runtime reference](runtime.md));
- DaemonSet `flowsdn`: an `install-cni` init container (`flowsdn-cni install`: the
  plugin into the node's CNI bin directory as `flowsdn-cni`, `flowsdn` and, if absent
  or `cni.overwriteLoopback`, `loopback`; `00-flowsdn.conflist` into its conf
  directory) and the Kubernetes-mode agent (`K8S_NODE_NAME` from the downward API),
  privileged on the host network, with the host's `/sys/fs/cgroup` at
  `/run/flowsdn/cgroupv2` for the socket LB and `/var/run/flowsdn`, `/var/lib/flowsdn`
  from the host.

Every object, label, path and key is flowsdn's (owner, #294: no Cilium in flowsdn);
`install/kubernetes/check.sh` and the `flowsdn-k8s` tests refuse any that is not.

## Install

There is no published image yet. Build it from a commit with
`images/agent/build.sh OUT_DIR` (GNU Kubernetes-mode agent with Fedora OpenSSL and the
static CNI on `fedora-minimal:43`; `localhost/flowsdn-agent:<version>` and an OCI
archive), push it to your registry, then:

```sh
helm install flowsdn install/kubernetes/flowsdn --namespace kube-system \
  --set image.repository=registry.example/flowsdn-agent
```

The packaged chart (`flowsdn-<version>.tgz`) and the static binary archives come from
`deploy/release/build.sh`, with `SHA256SUMS`. Nothing is uploaded by a build; a GitHub
Release is a separate, recorded step.

Requirements: Linux 6.6 or newer with TCX and BTF, cgroup v2, no kube-proxy needed for
Services (`agent.serviceLB`), nodes on one L2 segment for direct routes, and a
masquerade for pod traffic leaving the cluster (flowsdn does not masquerade yet).
NodePort from outside the cluster to another node's backend takes its SNAT address
from `BPF_FIB_LOOKUP_SRC` (Linux 6.7 or newer); on 6.6 only local backends work.

## Values

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `""` (required) | Registry/repository of the agent image. Rendering fails without it. |
| `image.tag` | chart `appVersion` | Image tag. |
| `image.pullPolicy` | `IfNotPresent` | |
| `serviceAccount.name` | `flowsdn` | |
| `agent.ipv4Pool` / `agent.ipv6Pool` | `auto` / `""` | Pod pool per family. `auto`: from the Node's `spec.podCIDRs`, else `10.<last byte of InternalIP>.0.0/16`. One family at least. |
| `agent.ipv4Gateway` / `agent.ipv6Gateway` | `""` | Router address, required with a fixed pool. |
| `agent.egress` | `stack` | `stack` or `fib` (runtime reference). |
| `agent.deviceMTU` / `agent.routeMTU` | `1500` | |
| `agent.endpointIdMax` | `4095` | |
| `agent.httpListen` | `127.0.0.1:9878` | Read-only loopback API; `""` disables it. |
| `agent.bpfPinRoot` | `""` | bpffs directory for maps/links that survive agent restarts; mounts the host's `/sys/fs/bpf`. |
| `agent.autoDirectNodeRoutes` | `true` | Routes to other nodes' pod CIDRs via their InternalIP. |
| `agent.directRoutingSkipUnreachable` | `false` | Skip, instead of reporting, nodes behind a router. |
| `agent.serviceLB` | `true` | ClusterIP Services at the socket, without kube-proxy. |
| `agent.extraConfig` | `{}` | Keys merged (deeply) into `agent.json`, e.g. `{kubernetes: {node-port: false}}` to leave NodePort/LB traffic from outside the cluster alone; `node-port` has no value of its own and is on by default. |
| `agent.resources`, `priorityClassName`, `nodeSelector`, `tolerations`, `updateStrategy`, `podLabels`, `podAnnotations` | see `values.yaml` | DaemonSet scheduling. |
| `cni.install` | `true` | Run the `install-cni` init container. |
| `cni.binPath` / `cni.confPath` | `/opt/cni/bin` / `/etc/cni/net.d` | Host CNI directories. |
| `cni.overwriteLoopback` | `false` | Replace an existing `loopback` plugin. |

## Coming from another CNI's chart

flowsdn's values are its own, not another chart's. For an install coming from the
Cilium chart, the settings that have a flowsdn equivalent today:

| Cilium chart value | flowsdn value |
|---|---|
| `image.repository`, `image.tag` | `image.repository`, `image.tag` |
| `ipam.mode=kubernetes` (Node `podCIDRs`) | `agent.ipv4Pool=auto` (the default) |
| `ipam.operator.clusterPoolIPv4PodCIDRList` (one node) | `agent.ipv4Pool` + `agent.ipv4Gateway` |
| `ipv6.enabled` | `agent.ipv6Pool` (`auto` or a CIDR) |
| `routingMode=native`, `autoDirectNodeRoutes` | `agent.autoDirectNodeRoutes` (native routing is the only mode) |
| `directRoutingSkipUnreachable` | `agent.directRoutingSkipUnreachable` |
| `kubeProxyReplacement=true` (ClusterIP, NodePort, LoadBalancer, externalIPs) | `agent.serviceLB=true` (default), `kubernetes.node-port` via `agent.extraConfig` (default on) |
| `sessionAffinity: ClientIP`, `internalTrafficPolicy`/`externalTrafficPolicy: Local` | honoured with `agent.serviceLB` |
| `MTU` | `agent.deviceMTU`, `agent.routeMTU` |
| `bpf.root` / persistent maps | `agent.bpfPinRoot` |
| `cni.binPath`, `cni.confPath` | `cni.binPath`, `cni.confPath` |
| `resources`, `nodeSelector`, `tolerations`, `updateStrategy`, `podLabels`, `podAnnotations`, `priorityClassName` | the same under `agent.` |

Not available yet, so these have no flowsdn value: tunnels (`tunnelProtocol`), the
operator, Hubble, encryption, egress gateway, BGP, L2 announcements, Envoy/L7,
Gateway API/Ingress, ClusterMesh, masquerade, Maglev, DSR and network policy
enforcement (milestones 2–3, #292/#293). Services are partly there: ClusterIP,
NodePort, LoadBalancer ingress IPs and externalIPs from pods and node processes go
through the socket LB; from outside the cluster `node-port` handles NodePort, LB and
external IPs on the node's uplink, IPv4 and IPv6 with SNAT to other nodes' backends.
The IPv6 external path has passed sc-build but not yet a hardware run. Their custom resources exist
([CRD reference](crds.md)) but nothing acts on them. Status comes from `kubectl get
flowsdn`, the agent's API and `sc net` (#298); there is no `cilium-cli` support.

Moving a cluster: flowsdn does not adopt another CNI's objects or pinned state. Drain
and replace node by node (the other CNI's agent removed from the node, its conflist
and leftover state cleaned up by the operator of that CNI), then let the flowsdn
DaemonSet schedule there. Policies are rewritten as `flowsdn.io` kinds
([CRD reference](crds.md#moving-over-from-cilium)).

## Not yet validated

`helm lint`, rendering, the guards and the name rule are checked on every build
(`install/kubernetes/check.sh`, run by `deploy/release/build.sh`). The chart has not
been installed on a live cluster, and upgrade/rollback between chart versions is not
yet measured; both are milestone 4 gates on #294.
