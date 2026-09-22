# ClusterMesh fastetcd ingress policy

`network-policy.yaml` is the shipped peer-port restriction for the future
ClusterMesh deployment. It is a policy artifact, not a complete workload
manifest or evidence of deployed enforcement.

Install it in the same namespace as the store pods (default `kube-system`).
Every store pod must carry both labels:

```yaml
app.kubernetes.io/name: fastetcd
app.kubernetes.io/instance: flowsdn-clustermesh
```

Only pods with those same labels **in that namespace** receive TCP 2380 Raft
peer access. Separate same-namespace pods labelled
`flowsdn.io/clustermesh-client: "true"` receive TCP 2379 client access, without
Raft access. A store pod used as a client must also have the client label.
Containers in the same pod can use loopback; NetworkPolicy cannot isolate them.
Namespace administrators must restrict who can assign these authorization labels.

The policy selects ingress isolation for all other ports, including metrics.
An operator needing metrics, remote ClusterMesh clients or another namespace
must add a narrowly scoped, separate rule for the relevant client/metrics port.
Do not add a broad source rule covering 2380. Cross-namespace client rules should
combine a namespaceSelector and podSelector in the **same** `from` item; external
client CIDRs may be allowed on 2379 only after the service/ingress source-address
behavior has been verified. No external client CIDR is enabled by this default.
Egress is not isolated by this policy.

Apply alongside the workload:

```text
kubectl apply -f deploy/clustermesh/network-policy.yaml
```

Required deployment validation: confirm selectors match actual store pods;
confirm a same-namespace store can reach 2380, an authorized client can reach 2379
but cannot reach 2380, an unlabelled pod cannot reach either, and an identically
labelled pod in another namespace cannot reach 2380. Repeat against direct pod
addresses and the service path. These tests have **not** been run here. They
require a NetworkPolicy-enforcing CNI. Kubernetes policies combine additively:
another policy granting broad ingress can defeat these restrictions. Host-network
pods and host traffic need separate platform controls; use ordinary pod networking.

The source audit of fastetcd `cf53856` confirms client 2379 versus peer 2380
(`crates/server/src/main.rs` defaults), discarded peer TLS flags, and one TLS
configuration cloned into both listeners. The peer headless service is reachable
within the cluster; lack of an external Service is not network isolation.
The existing hardening item is [fastetcd#23](https://github.com/glennswest/fastetcd/issues/23)
(open at this audit); no duplicate was filed. It requires separate peer identity
and trust configuration, or explicit rejection of unsupported peer TLS flags.
This NetworkPolicy complements mTLS and does not repair the shared-identity gap.
