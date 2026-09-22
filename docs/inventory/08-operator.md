# cilium-operator — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `operator/**` (all of it
except `operator/pkg/ipam/**` and `operator/pkg/lbipam/**`, which are referenced
only), `api/v1/operator/openapi.yaml`, `pkg/k8s/apis/cell.go`,
`pkg/k8s/apis/cilium.io/client/register.go`, `pkg/k8s/apis/crdhelpers/`,
`pkg/k8s/synced/crd.go`, `pkg/clustermesh/{endpointslicesync,mcsapi,operator,namespace}`,
`install/kubernetes/cilium/templates/cilium-operator/`,
`Documentation/cmdref/cilium-operator*.md`.

Out of scope here (other inventories): cloud IPAM internals (`pkg/ipam`,
`pkg/aws`, `pkg/azure`, `pkg/alibabacloud`, `operator/pkg/ipam/**`) → 07-ipam;
LB IPAM (`operator/pkg/lbipam`) → load-balancer inventory; the ClusterMesh
kvstore protocol itself → clustermesh inventory; BGP speaker → bgp inventory.

## Purpose

`cilium-operator` is the single-leader, cluster-scoped control plane companion
to the per-node agent. It does the work that must happen exactly once per
cluster: create/upgrade the Cilium CRDs, garbage-collect stale
CiliumIdentity/CiliumEndpoint/CiliumNode objects, batch CiliumEndpoints into
CiliumEndpointSlices, hand out pod CIDRs (cluster-pool IPAM) and LB IPs, clear
the `node.cilium.io/agent-not-ready` taint and set the node
`NetworkUnavailable=False` condition once the agent is Ready on a node, restart
pods that started before Cilium was ready, mirror Services/EndpointSlices into
the kvstore for ClusterMesh, and translate Ingress / Gateway API objects into
`CiliumEnvoyConfig` + `Service` + `EndpointSlice` that the agents' Envoy
consumes. It is a Go hive of ~45 cells; everything after leader election lives
in a nested "leader lifecycle" that is only started once the Lease is won and
is torn down (process exits) when it is lost.

## Components

Line counts are non-test Go (`wc -l`), tests listed separately. Whole
`operator/**` is 47,932 non-test / 47,254 test lines; in scope after removing
IPAM (6,778) and LB IPAM (2,516) is **38,638 non-test lines**.

| Path | Lines | Purpose |
|---|---|---|
| `operator/main.go` | 15 | `hive.New(cmd.Operator())`; `cmd.Execute` |
| `operator/cmd/` (root, flags, leader_election, lifecycle, metrics, status) | 1,208 (+29 test) | Cobra command, hive assembly, flag registration, leader election, `metrics list`/`status` subcommands |
| `operator/option/config.go` | 111 | `OperatorConfig` (only 4 fields survive: `SyncK8sServices`, `IPAMInstanceTags`, `KubeProxyReplacement`, `EnableGatewayAPI`) |
| `operator/api/` | 392 (+709 test) | go-swagger server for `/healthz`, `/metrics/`, `/cluster`; `--operator-api-serve-addr` |
| `operator/metrics/` | 331 (+141) | Prometheus registry cell, `--enable-metrics`, `--operator-prometheus-*`, TLS cert loader |
| `operator/k8s/` | 293 | `ResourcesCell`: shared `resource.Resource[T]` informers (Services, ServiceExports, EndpointSlices, LBIPPools, CiliumIdentity, CiliumPodIPPool, CEP, CES, CiliumNode, Pods, Namespaces) + `HasCEWithIdentity` index |
| `operator/identitygc/` | 769 (+439) | Identity GC (CRD mode + kvstore mode), heartbeat store, rate limiter, metrics |
| `operator/endpointgc/` | 336 (+239) | CiliumEndpoint orphan GC |
| `operator/endpointslicegc/` | 124 (+110) | One-shot `DeleteCollection` of CES when CES is disabled |
| `operator/unmanagedpods/` | 331 (+288) | Restart pods (default `k8s-app=kube-dns`) that have no CEP |
| `operator/watchers/` | 2,082 (+1,124) | Node taint/condition sync, CiliumNode GC, Service→kvstore sync, EndpointSlice→kvstore export sync, legacy CEP/pod/node informers |
| `operator/doublewrite/` | 283 | Metric reporter comparing CRD vs kvstore identities (double-write migration mode) |
| `operator/auth/` + `auth/spire` | 113 + 13 + 772 (+894) | SPIRE client used to delete auth identity entries during identity GC (mutual auth is **deprecated in 1.20**) |
| `operator/pkg/ciliumendpointslice/` | 2,855 (+2,466) | CES controller: default + slim managers, fast/standard workqueues, dynamic rate limit, priority namespaces |
| `operator/pkg/ciliumidentity/` | 1,385 (+1,534) | Operator-managed CiliumIdentity allocation (`identity-management-mode=operator|both`) |
| `operator/pkg/ciliumpod/` | 55 | `--cilium-pod-namespace/--cilium-pod-labels` shared config |
| `operator/pkg/client/` | 18 | k8s clientset cell wrapper |
| `operator/pkg/controller-runtime/` | 153 (+125) | Provides a `sigs.k8s.io/controller-runtime` Manager + Scheme to hive cells (Ingress, Gateway API, secretsync, CEC, nodeipam) |
| `operator/pkg/gateway-api/` | 5,502 (+4,835) | GatewayClass / Gateway / GAMMA / GatewayClassConfig / EndpointSlice reconcilers, status writers, secret sync hooks |
| `operator/pkg/gateway-api/helpers` | 1,177 (+2,450) | GVK tables, ReferenceGrant checks, ListenerSet/TCP/UDP feature probes |
| `operator/pkg/gateway-api/indexers` | 944 (+1,613) | Field indexers: routes-by-backend, routes-by-gateway, secrets, BackendTLSPolicy |
| `operator/pkg/gateway-api/routechecks` | 1,482 (+1,340) | Route acceptance checks (parentRef, hostnames, kinds, ReferenceGrant, GAMMA) |
| `operator/pkg/gateway-api/policychecks` | 139 (+449) | BackendTLSPolicy validation |
| `operator/pkg/gateway-api/predicates` | 105 (+81) | Event filters (only our GatewayClass, our EndpointSlices) |
| `operator/pkg/gateway-api/watch-handlers` | 1,292 (+254) | Enqueue mappers: Secret/ConfigMap/Namespace/Node/Service/ReferenceGrant/route → Gateway |
| `operator/pkg/gateway-api/testdata` | 604 files, 42,721 lines | Golden input/output YAML for gateway + gamma translation |
| `operator/pkg/ingress/` + `annotations` | 1,242 + 211 (+1,792 + 609) | Ingress reconciler (shared/dedicated), annotations |
| `operator/pkg/model/` | 1,333 (+1,334) | Shared intermediate model (`Model`, `HTTPListener`, `TLSPassthroughListener`, `HTTPRoute`, filters, `Backend`, …) |
| `operator/pkg/model/ingestion/` | 2,377 (+2,023) | Ingress / Gateway API / GAMMA objects → `model.Model` |
| `operator/pkg/model/translation/` | 3,418 (+5,474) | `model.Model` → `CiliumEnvoyConfig` (Envoy listener/HCM/route/cluster protobufs) |
| `operator/pkg/model/translation/gateway-api` | 748 (+1,163) | Gateway-specific wrapper: Service, EndpointSlices, host-network |
| `operator/pkg/model/translation/ingress` | 206 (+395) | Dedicated Ingress wrapper |
| `operator/pkg/secretsync/` | 914 (+985) | Generic Secret + ConfigMap fan-in sync into `cilium-secrets` |
| `operator/pkg/ciliumenvoyconfig/` | 680 (+140) | L7 LB for Services annotated `service.cilium.io/lb-l7`; `--loadbalancer-l7*`, `--proxy-*-timeout-seconds` |
| `operator/pkg/networkpolicy/` + `external-groups` + `secretsync` | 326 + 1,241 + 107 + 342 (+478) | CNP/CCNP informational validator (writes `.status.conditions`), external groups → CiliumCIDRGroup sync, policy TLS secret sync |
| `operator/pkg/bgp/` | 1,391 (+2,321) | `CiliumBGPClusterConfig` → per-node `CiliumBGPNodeConfig`, router-ID allocation, status conditions |
| `operator/pkg/nodeipam/` | 394 (+589) | Node IPAM for `LoadBalancerClass: io.cilium/node` Services |
| `operator/pkg/kvstore/locksweeper` | 124 (+143) | Sweeps stale kvstore locks |
| `operator/pkg/kvstore/nodesgc` | 263 (+115) | `--synchronize-k8s-nodes`: GC kvstore node entries with no k8s Node |
| `operator/pkg/ztunnel/` + `config` + `reconciler` | 68 + 77 + 357 (+620) | Manages the ztunnel DaemonSet when `--enable-ztunnel` |
| `operator/pkg/workqueuemetrics/` | 122 | client-go workqueue → Prometheus adapter |
| `pkg/clustermesh/endpointslicesync` | 1,331 | Remote ClusterService → local EndpointSlices (`--clustermesh-enable-endpoint-sync`) |
| `pkg/clustermesh/mcsapi` | 2,442 | MCS-API ServiceExport/ServiceImport controllers + CRD install |
| `pkg/clustermesh/operator` | 900 | Operator-side remote cluster connection manager (`/cluster` API) |
| `pkg/clustermesh/namespace` | 145 | Global-namespace manager (`--clustermesh-default-global-namespace`) |
| `pkg/k8s/apis/cell.go`, `cilium.io/client/register.go`, `crdhelpers/register.go` | ~700 | CRD create/update with schema-version label |
| Reference only: `operator/pkg/ipam/**` | 6,778 (+6,332) | cluster-pool/multi-pool/cloud allocators → 07-ipam |
| Reference only: `operator/pkg/lbipam/` | 2,516 (+3,621) | LB IPAM → load balancer inventory |

## Features

### Process, binaries, leader election, HA

- **Five binaries from one `main`**: `cilium-operator` (all IPAM providers,
  build tags `ipam_provider_aws,azure,operator,alibabacloud`),
  `cilium-operator-generic` (`ipam_provider_operator`), `-aws`, `-azure`,
  `-alibabacloud`. `binaryName = filepath.Base(os.Args[0])` selects the
  default `--ipam` (`cluster-pool` / `eni` / `azure` / `alibabacloud`) and a
  `PreRunE` rejects `--ipam` values the binary does not compile in (with a hint
  naming the right binary). The only flag differences between variants are the
  cloud flags (see table). Helm ships `cilium-operator-generic` by default.
- **Leader election**: client-go `leaderelection.RunOrDie` on a
  `coordination.k8s.io/Lease` named `cilium-operator-resource-lock` in the
  operator's namespace (falls back to `default` when `--k8s-namespace` is
  empty). Identity = `hostname-<10 random chars>`. Defaults
  `--leader-election-lease-duration=15s`, `--leader-election-renew-deadline=10s`,
  `--leader-election-retry-period=2s`,
  `--leader-election-resource-lock-timeout=0` (→ `max(1s, renew/2)`).
  `ReleaseOnCancel=true`. **`OnStoppedLeading` is `logging.Fatal`** — the
  process exits rather than continuing as a follower; correctness of shared
  k8s/kvstore state depends on there never being two leaders.
- **Hive split**: `InfrastructureCells` (pprof, gops, health history, k8s
  client, kvstore client, metrics, shell.sock) and `ControlPlaneCells`
  (cluster info, health/metrics handlers, API server) start on every replica;
  `ControlPlaneLeaderCells` (everything else) are wrapped in
  `WithLeaderLifecycle` and start only in `OnStartedLeading`. `isLeader`
  atomic is flipped by `legacyCell`'s start hook and read by `/healthz`.
- **HA**: Helm `operator.replicas: 2`, podAntiAffinity, `maxUnavailable: 100%`
  when replicas==1. Non-leaders serve `/healthz` (kvstore + apiserver check
  only) and `/metrics`. `hostNetwork: true` by default in Helm (port 9234
  hostPort). Minimal k8s version is enforced at start
  (`k8sversion.MinimalVersionConstraint`).
- **k8s client**: `--operator-k8s-client-qps=100`, `--operator-k8s-client-burst=200`
  (agent defaults are lower). `--enable-k8s-api-discovery` forced on.
- **Config sources**: flags, env (`CILIUM_*` via `BindEnv`), `--config` file,
  `--config-dir` (one file per key — this is how the Helm ConfigMap
  `cilium-config` is consumed). Several keys are read **only** from viper, not
  registered as flags: `enable-gateway-api` (set to `"true"` in the ConfigMap
  by Helm when `gatewayAPI.enabled`), and hidden flags
  `disable-endpoint-crd`, `enable-egress-gateway`, `enable-local-redirect-policy`,
  `enable-srv6`, `kube-proxy-replacement`, `enable-k8s-network-policy`,
  `enable-cilium-network-policy`, `enable-cilium-clusterwide-network-policy`,
  `enable-cilium-node-crd`, `ces-controller-mode`, `register-dummy-external-group`.

### Full flag table (`cilium-operator`, from `Documentation/cmdref/cilium-operator.md`)

Type is the pflag type; default in parentheses; blank default = zero value.
Variant column: G = also in `-generic`, A = `-aws`, Z = `-azure`, L =
`-alibabacloud`; blank = all five.

| Flag | Type (default) | Meaning | Variant |
|---|---|---|---|
| `--alibaba-cloud-release-excess-ips` | bool | Release excess ENI IPs | L |
| `--alibaba-cloud-vpc-id` | string | VPC for AlibabaCloud ENI | L |
| `--auto-create-cilium-pod-ip-pools` | map | Create CiliumPodIPPools at start (multi-pool) | G |
| `--aws-enable-prefix-delegation` | bool | Allocate /28 prefixes to ENIs | A |
| `--aws-max-results-per-call` | int32 (0) | EC2 Describe* page size | A |
| `--aws-release-excess-ips` | bool | Release excess ENI IPs | A |
| `--aws-use-primary-address` | bool | Use ENI primary IP for pods | A |
| `--azure-resource-group` | string | RG of cluster nodes | Z |
| `--azure-subscription-id` | string | Azure subscription | Z |
| `--azure-use-primary-address` | bool | Use primary IPConfiguration | Z |
| `--azure-user-assigned-identity-id` | string | Managed identity client ID | Z |
| `--ces-max-ciliumendpoints-per-ces` | int (100) | Max CEPs per CES | |
| `--ces-rate-limits` | string (`[{"nodes":0,"limit":10,"burst":20}]`) | JSON list of `{nodes,limit,burst}` steps; chosen by CiliumNode count | |
| `--cilium-endpoint-gc-interval` | duration (5m) | CEP GC period; 0 = run once | |
| `--cilium-pod-labels` | string (`k8s-app=cilium`) | Selector for agent pods (taint/condition sync) | |
| `--cilium-pod-namespace` | string | Namespace of agent pods (default `--k8s-namespace`) | |
| `--cluster-id` | uint32 | ClusterMesh cluster ID | |
| `--cluster-name` | string (`default`) | ClusterMesh cluster name | |
| `--cluster-pool-ipv4-cidr` | strings | Cluster-pool pod CIDRs (v4) | G |
| `--cluster-pool-ipv4-mask-size` | int (24) | Per-node v4 mask | G |
| `--cluster-pool-ipv6-cidr` | strings | Cluster-pool pod CIDRs (v6) | G |
| `--cluster-pool-ipv6-mask-size` | int (112) | Per-node v6 mask | G |
| `--clustermesh-cache-ttl` | duration (0) | Revoke remote cache after disconnect | |
| `--clustermesh-concurrent-service-endpoint-syncs` | int (5) | EndpointSlice sync workers | |
| `--clustermesh-config` | string | ClusterMesh config dir | |
| `--clustermesh-default-global-namespace` | bool (true) | Namespaces global unless annotated | |
| `--clustermesh-enable-endpoint-sync` | bool | Sync remote endpoints into local EndpointSlices | |
| `--clustermesh-enable-mcs-api` | bool | MCS-API ServiceExport/Import | |
| `--clustermesh-endpoint-updates-batch-period` | duration (500ms) | EndpointSlice batching | |
| `--clustermesh-endpoints-per-slice` | int (100) | Remote EPS size | |
| `--clustermesh-mcs-api-install-crds` | bool (true) | Install MCS CRDs | |
| `--clustermesh-sync-timeout` | duration (1m) | Initial remote sync timeout | |
| `--config` | string | Config file | |
| `--config-dir` | string | Dir with one file per option (ConfigMap) | |
| `--controller-group-metrics` | strings | Controller groups to expose metrics for (`all`/`none`) | |
| `--default-lb-service-ipam` | string (`lbipam`) | `lbipam`/`nodeipam`/`none` when no LoadBalancerClass | |
| `--double-write-metric-reporter-interval` | duration (1m) | Double-write identity comparison period | |
| `--ec2-api-endpoint` | string | Custom EC2 endpoint | A |
| `--enable-cilium-endpoint-slice` | bool | Enable CES controller | |
| `--enable-cilium-operator-server-access` | strings (`*`) | Allowed operator API endpoints | |
| `--enable-cluster-pool-to-multi-pool-migration` | bool | One-shot migration | G |
| `--enable-gateway-api-alpn` | bool | Advertise h2,http/1.1 ALPN | |
| `--enable-gateway-api-app-protocol` | bool | GEP-1911 backend protocol via `appProtocol` | |
| `--enable-gateway-api-proxy-protocol` | bool | PROXY protocol on all Gateway listeners | |
| `--enable-gateway-api-secrets-sync` | bool (true) | Sync Gateway TLS secrets into secrets ns | |
| `--enable-gops` | bool (true) | gops agent | |
| `--enable-ingress-controller` | bool | Ingress controller | |
| `--enable-ingress-proxy-protocol` | bool | PROXY protocol on Ingress listeners | |
| `--enable-ingress-secrets-sync` | bool (true) | Sync Ingress TLS secrets | |
| `--enable-ipsec` | bool | Used by CES slim mode + ipsec operator cell | |
| `--enable-ipv4` / `--enable-ipv6` | bool (true/true) | Address families | |
| `--enable-k8s` | bool (true) | k8s clientset | |
| `--enable-k8s-api-discovery` | bool | Discovery API (forced true) | |
| `--enable-l7-proxy` | bool (true) | Policy validation input | |
| `--enable-lb-ipam` | bool (true) | LB IPAM | |
| `--enable-metrics` | bool | Prometheus endpoint | |
| `--enable-node-ipam` | bool | Node IPAM | |
| `--enable-node-selector-labels` | bool | Node-label identities (validation) | |
| `--enable-policy` | string (`default`) | Policy enforcement mode (validation) | |
| `--enable-policy-secrets-sync` | bool | Sync policy TLS secrets | |
| `--enable-wireguard` | bool | CES slim encryption key input | |
| `--enable-ztunnel` | bool | Manage ztunnel DaemonSet | |
| `--enforce-ingress-https` | bool (true) | 308 redirect http→https for TLS hosts | |
| `--eni-gc-interval` | duration (5m) | Dangling ENI GC | A |
| `--eni-gc-tags` | map | Tag filter for ENI GC | A |
| `--eni-tags` | map | Tags on created ENIs | A |
| `--excess-ip-release-delay` | int (180) | Seconds before releasing excess IPs | A/Z/L |
| `--gateway-api-hostnetwork-enabled` | bool | Listeners on host network, no Service | |
| `--gateway-api-hostnetwork-nodelabelselector` | string | Nodes to expose on | |
| `--gateway-api-secrets-namespace` | string (`cilium-secrets`) | Target ns for synced secrets | |
| `--gateway-api-service-externaltrafficpolicy` | string (`Cluster`) | `Cluster`/`Local` for generated Services | |
| `--gateway-api-use-remote-address` | bool (true) | Envoy `use_remote_address` | |
| `--gateway-api-xff-num-trusted-hops` | uint32 | XFF trusted hops | |
| `--gops-port` | uint16 (9891) | gops port | |
| `--identity-allocation-mode` | string (`kvstore`) | `crd`/`kvstore`/`doublewrite-readkvstore`/`doublewrite-readcrd` | |
| `--identity-gc-interval` | duration (15m) | Identity GC period | |
| `--identity-gc-rate-interval` | duration (1m) | Rate-limit window | |
| `--identity-gc-rate-limit` | int (2500) | Max deletes per window | |
| `--identity-heartbeat-timeout` | duration (30m) | Identity unused-for-this-long → delete | |
| `--identity-management-mode` | string (`agent`) | `agent`/`operator`/`both` | |
| `--ingress-default-lb-mode` | string (`dedicated`) | `dedicated`/`shared` | |
| `--ingress-default-request-timeout` | duration (0) | Route timeout | |
| `--ingress-default-secret-name` / `-namespace` | string | Fallback TLS secret | |
| `--ingress-default-xff-num-trusted-hops` | uint32 | XFF hops | |
| `--ingress-hostnetwork-enabled` | bool | Host-network Ingress | |
| `--ingress-hostnetwork-http-listener-port` | uint32 | Shared HTTP host port | |
| `--ingress-hostnetwork-https-listener-port` | uint32 | Shared HTTPS host port | |
| `--ingress-hostnetwork-nodelabelselector` | string | Nodes to expose on | |
| `--ingress-hostnetwork-shared-listener-port` | uint32 | Single shared host port | |
| `--ingress-hostnetwork-tls-passthrough-listener-port` | uint32 | Passthrough host port | |
| `--ingress-lb-annotation-prefixes` | strings (`lbipam.cilium.io, service.beta.kubernetes.io, service.kubernetes.io, cloud.google.com`) | Annotation prefixes copied Ingress→Service | |
| `--ingress-secrets-namespace` | string (`cilium-secrets`) | Target ns | |
| `--ingress-shared-lb-service-name` | string (`cilium-ingress`) | Shared Service name | |
| `--ingress-use-remote-address` | bool (true) | Envoy `use_remote_address` | |
| `--instance-tags-filter` | map | EC2 instance tag filter | A |
| `--ipam` | string (per binary) | IPAM backend | |
| `--ipam-default-ip-pool` | string (`default`) | Multi-pool default pool | G |
| `--k8s-api-server-urls` | strings | API server URLs | |
| `--k8s-client-connection-keep-alive` | duration (30s) | | |
| `--k8s-client-connection-timeout` | duration (30s) | | |
| `--k8s-heartbeat-timeout` | duration (30s) | apiserver heartbeat | |
| `--k8s-kubeconfig-path` | string | | |
| `--k8s-namespace` | string | Operator namespace (Lease, secrets) | |
| `--k8s-service-proxy-name` | string | `service-proxy-name` label filter | |
| `--kvstore` | string | `etcd` or empty | |
| `--kvstore-lease-ttl` | duration (15m) | | |
| `--kvstore-max-consecutive-quorum-errors` | uint (2) | | |
| `--kvstore-opt` | map | e.g. `etcd.config=/var/lib/etcd-config/etcd.config` | |
| `--leader-election-lease-duration` | duration (15s) | | |
| `--leader-election-renew-deadline` | duration (10s) | | |
| `--leader-election-resource-lock-timeout` | duration (0) | HTTP timeout for lock ops | |
| `--leader-election-retry-period` | duration (2s) | | |
| `--limit-ipam-api-burst` | int (20) | Cloud API burst | |
| `--limit-ipam-api-qps` | float (4) | Cloud API QPS | |
| `--loadbalancer-l7` | string | `envoy` enables L7 LB for annotated Services | |
| `--loadbalancer-l7-algorithm` | string (`round_robin`) | | |
| `--loadbalancer-l7-ports` | strings | Ports auto-redirected | |
| `--log-driver` / `--log-opt` | strings / map | Logging | |
| `--max-connected-clusters` | uint32 (255) | 255 or 511; shrinks identity space | |
| `--mesh-auth-spiffe-trust-domain` | string (`spiffe.cilium`) | deprecated | |
| `--mesh-auth-spire-agent-socket` | string (`/run/spire/sockets/agent/agent.sock`) | deprecated | |
| `--mesh-auth-spire-server-address` | string (`spire-server.spire.svc:8081`) | deprecated | |
| `--mesh-auth-spire-server-connection-timeout` | duration (10s) | deprecated | |
| `--metrics-sampling-interval` | duration (5m) | Internal metric sampling | |
| `--multi-pool-migration-workers` | int (16) | | G |
| `--nodes-gc-interval` | duration (5m) | CiliumNode GC; 0 disables | |
| `--operator-api-serve-addr` | string (`localhost:9234`) | Operator REST API | |
| `--operator-k8s-client-burst` | int (200) | | |
| `--operator-k8s-client-qps` | float32 (100) | | |
| `--operator-pprof` | bool | pprof server | |
| `--operator-pprof-address` | string (`localhost`) | | |
| `--operator-pprof-block-profile-rate` | int | | |
| `--operator-pprof-mutex-profile-fraction` | int | | |
| `--operator-pprof-port` | uint16 (6061) | | |
| `--operator-prometheus-enable-tls` | bool | | |
| `--operator-prometheus-serve-addr` | string (`:9963`) | Metrics listen | |
| `--operator-prometheus-tls-cert-file` / `-key-file` / `-client-ca-files` | string / string / strings | mTLS for metrics | |
| `--parallel-alloc-workers` | int (50) | IPAM workers | |
| `--pod-restart-selector` | string (`k8s-app=kube-dns`) | Unmanaged pods to restart; empty = all | |
| `--policy-default-local-cluster` | bool (true) | Policy assumes local cluster | |
| `--policy-external-group-sync-interval` | duration (10m) | External group CIDR refresh | |
| `--policy-secrets-namespace` | string (`cilium-secrets`) | | |
| `--proxy-idle-timeout-seconds` | int (60) | Envoy upstream idle | |
| `--proxy-stream-idle-timeout-seconds` | int (300) | Envoy stream idle | |
| `--remove-cilium-node-taints` | bool (true) | Remove `node.cilium.io/agent-not-ready` when agent Ready | |
| `--set-cilium-is-up-condition` | bool (true) | Patch `NetworkUnavailable=False reason=CiliumIsUp` | |
| `--set-cilium-node-taints` | bool (false) | Add the taint when agent scheduled but not Ready | |
| `--shell-sock-path` | string (`/var/run/cilium/shell.sock`) | Hive shell | |
| `--skip-crd-creation` | bool | Do not create/update CRDs | |
| `--subnet-ids-filter` / `--subnet-tags-filter` | strings / map | ENI subnet filters | A |
| `--synchronize-k8s-nodes` | bool (true) | GC stale kvstore node keys | |
| `--synchronize-k8s-services` | bool (true) | Mirror Services (+EndpointSlices) to kvstore | |
| `--taint-sync-workers` | int (10) | Node taint workers | |
| `--unmanaged-pod-watcher-interval` | duration (15s) | Unmanaged pod check; 0 disables | |
| `--validate-network-policy` | bool (true) | CNP/CCNP validator | |
| `--version` | bool | | |
| `--ztunnel-ca-type` | string (`internal`) | `spire`/`internal` | |

Flags **absent in 1.20** that older docs mention: `cnp-status-*` (CNP status
propagation removed), `ces-slice-mode` (identity/fcfs slicing removed),
`ces-write-qps-*` (replaced by `--ces-rate-limits`), `bgp-announce-*`,
`enable-bgp-control-plane` (agent-side only; operator reads it from viper for
CRD list), `mesh-auth-enabled`/`mesh-auth-mutual-enabled` (present but marked
deprecated).

### CRD registration (`apis.RegisterCRDsCell`, first leader cell)

- Skipped when `--skip-crd-creation` or no k8s. Iterates
  `synced.AllCiliumCRDResourceNames()` and for each calls
  `crdhelpers.CreateUpdateCRD` with the pregenerated CRD YAML embedded in the
  binary (`pkg/k8s/apis/cilium.io/client/crds/**`).
- **Always** created: `CiliumIdentity` (v2), `CiliumPodIPPool` (v2alpha1),
  `CiliumLoadBalancerIPPool` (v2), `CiliumL2AnnouncementPolicy` (v2alpha1),
  `CiliumNodeConfig` (v2).
- **Conditional**: `CiliumEndpoint` unless `disable-endpoint-crd`;
  `CiliumEndpointSlice` (v2alpha1) if `enable-cilium-endpoint-slice`;
  `CiliumNode` if `enable-cilium-node-crd` (default true);
  `CiliumNetworkPolicy` / `CiliumClusterwideNetworkPolicy` per their enable
  flags; `CiliumCIDRGroup` if either policy CRD; `CiliumEgressGatewayPolicy` if
  `enable-egress-gateway`; `CiliumLocalRedirectPolicy` if
  `enable-local-redirect-policy`; `CiliumEnvoyConfig` +
  `CiliumClusterwideEnvoyConfig` if `enable-envoy-config`;
  `CiliumBGPClusterConfig`, `CiliumBGPPeerConfig`, `CiliumBGPAdvertisement`,
  `CiliumBGPNodeConfig`, `CiliumBGPNodeConfigOverride` if
  `enable-bgp-control-plane`; `CiliumDatapathPlugin` (v2alpha1) if
  `enable-datapath-plugins`; `CiliumGatewayClassConfig` (v2alpha1) if
  `enable-gateway-api`. MCS-API `ServiceExport`/`ServiceImport` CRDs are
  installed by the mcsapi cell when `--clustermesh-mcs-api-install-crds`.
- **Versioning**: each CRD carries label
  `io.cilium.k8s.crd.schema.version` = `1.33.11` (constant
  `CustomResourceDefinitionSchemaVersion`). `NeedsUpdateV1Factory` parses the
  installed CRD's label as semver and updates only when missing or `LT` the
  binary's version; update is a full `Update` of the CRD object with retry on
  conflict, then `waitForV1CRD` polls until `Established`. No downgrade
  protection beyond "never write an older schema".

### Identity GC (`operator/identitygc`)

- Mode from `--identity-allocation-mode`. `crd` → CRD GC; `kvstore` → kvstore
  GC; `doublewrite-*` → both (workerpool of 2). Requires k8s and requires
  CEP GC enabled (`cilium-endpoint-gc-interval != 0`) in CRD/double-write modes
  (validated by an `Invoke` in root.go).
- **CRD mode** (`crd_gc.go`): controller `crd-identity-gc` with
  `RunInterval = --identity-gc-interval` (15m). An identity is **alive** if any
  CEP in the store has `status.identity.id == identity.Name`
  (`k8s.HasCEWithIdentity`, an informer index) or, when CES is enabled, any
  CES lists that `IdentityID`. Alive identities get `markAlive(now)` in an
  in-memory `heartbeatStore`. A not-alive identity whose last lifesign is
  older than `--identity-heartbeat-timeout` (30m; identities never seen count
  from process start, so a fresh leader waits one full timeout) is handled in
  two passes: pass 1 annotates it `io.cilium.heartbeat=<RFC3339Nano now>`
  ("marked for later deletion"); pass 2 (next run, still unused) deletes with
  `Preconditions{UID, ResourceVersion}` after `rateLimiter.Wait` (2500/min)
  and after deleting the SPIRE auth entry. Also watches CiliumIdentity events
  to markAlive on upsert (any write to the CID resets its clock). Conflict on
  delete is logged and skipped.
- **kvstore mode** (`kvstore_gc.go`): `allocator.NewAllocatorForGC` over
  `cilium/state/identities/v1/` with min/max ID bounded by cluster ID
  (`GetMinimalAllocationIdentity`/`GetMaximumAllocationIdentity`). Loop:
  `RunGC(ctx, rateLimiter, keysToDeletePrev)` — the allocator's two-phase GC
  (mark unused keys this round, delete those still unused next round), sleep
  `interval - duration`; warns if a run exceeds the interval. Deletes matching
  auth identities afterwards.
- Metrics: `identity_gc_runs{outcome,identity_type}`,
  `identity_gc_entries{outcome=alive|deleted,identity_type}`,
  `identity_gc_latency`.

### CiliumEndpoint GC (`operator/endpointgc`)

- Controller `to-k8s-ciliumendpoint-gc`, `RunInterval = --cilium-endpoint-gc-interval`
  (5m). If interval is 0 **or** `disable-endpoint-crd`, runs **once** at start
  (only if the CEP CRD exists) and deletes **every** CEP (cleanup of a disabled
  feature).
- Periodic orphan detection per CEP: skip if younger than the interval; for
  each `ownerReference` of kind `Pod` look the pod up in the Pod store (by
  owner name, CEP namespace); if the CEP has a non-Pod owner it is never GC'd;
  if no Pod owner, look up a Pod named like the CEP. Pod present and
  `IsPodRunning(status)` → keep; present but not running → delete; pod absent
  → delete. Delete uses `PropagationPolicy=Background` and
  `Preconditions{UID}`. Metric `endpoint_gc_objects{outcome}`.

### CiliumEndpointSlice controller (`operator/pkg/ciliumendpointslice`)

- Enabled by `--enable-cilium-endpoint-slice`. When disabled,
  `endpointslicegc` runs a one-shot `DeleteCollection` of all CES
  (`PropagationPolicy=Orphan`, retry 3× with 1–5 min backoff).
- CES objects are cluster-scoped, named `ces-<random>`, carry `namespace` and
  `endpoints[]` of `CoreCiliumEndpoint{name, id (identity), pod-uid,
  networking, encryption, named-ports, service-account}`. Only CEPs with
  `status.networking` and `status.identity` set are placed.
- **Slicing**: the v1.20 controller has **no `ces-slice-mode`**; the only
  grouping key is **namespace** — a CEP goes into the largest existing CES of
  its namespace that still has room (`getLargestAvailableCESForNamespace`),
  else a new CES; cap `--ces-max-ciliumendpoints-per-ces` (100). Identity-
  and FCFS-slicing from older releases are gone.
- **Modes** (hidden `--ces-controller-mode`): `default` — sources are CEP
  objects written by agents (`defaultManager`, `defaultReconciler`); `slim` —
  sources are **Pods + CiliumIdentity + CiliumNode** directly
  (`slimManager`, `slimReconciler`); the operator computes each pod's identity
  key from pod+namespace labels (`getPodCIDKey`) and the node's encryption key
  (IPsec/WireGuard), so agents need not write CEPs at all. Slim mode is the
  path toward `disable-endpoint-crd` + `identity-management-mode=operator`.
- **Queues**: two client-go rate-limited queues sharing one exponential
  failure limiter (1s→100s, 15 retries): `cilium_endpoint_slice_fast` for
  namespaces annotated `cilium.io/ces-namespace=priority`, `standard` for the
  rest; fast is drained first. Sync batching `DefaultCESSyncTime=500ms`.
- **Dynamic rate limit** (`--ces-rate-limits`): JSON `[{nodes,limit,burst}]`
  sorted by `nodes`; the entry with the largest `nodes <= len(CiliumNodes)`
  is applied to a `golang.org/x/time/rate` limiter gating apiserver writes;
  re-evaluated on CiliumNode events.
- Startup: `syncCESsInLocalCache` replays CES then CEP stores to rebuild the
  CEP→CES map before reconciling (avoids duplicating slices after restart).
- Metrics: `ces_sync_total{outcome}`, `ces_queueing_delay_seconds{queue}`,
  `number_of_ceps_per_ces`, `number_of_cep_changes_per_ces{opcode}`.
- **Agent side** (`pkg/k8s/watchers/cilium_endpoint_slice*.go`): when CES is
  enabled the agent does **not** watch CEPs of other nodes; it watches CES and
  fans each `CoreCiliumEndpoint` into the same `endpointUpdated`/
  `endpointDeleted` path (ipcache + policy) that CEP events use, diffing
  old/new CES on update and deleting only when the CEP is in no remaining CES.
  The agent still **writes** its own CEPs (default mode).

### Operator-managed identities (`operator/pkg/ciliumidentity`)

- `--identity-management-mode=operator|both`: the operator watches Pods,
  Namespaces, CiliumIdentity (and CES) and **creates** CiliumIdentity objects
  for every distinct `(pod labels ∪ namespace labels)` security-relevant
  label set (`GetRelevantLabelsForPod`), reusing an existing CID with the same
  key if present, and re-labels all pods of a namespace on namespace label
  change. Deletion stays with `identitygc`. Two workqueues (pods, CIDs);
  metrics `cid_controller_work_queue_event_count`, `_latency`. RBAC adds
  `create` on `ciliumidentities` only in these modes.
- `doublewrite` cell: every `--double-write-metric-reporter-interval` (1m)
  lists CRD and kvstore identities and exports
  `doublewrite_{crd,kvstore}_identities` and
  `doublewrite_{crd,kvstore}_only_identities` gauges for migration monitoring.

### Node management (`operator/watchers`)

- **Node taint / condition sync** (`NodeTaintSyncCell`, `node_taint*.go`):
  informer on Pods in `--cilium-pod-namespace` with `--cilium-pod-labels`
  (transformed to just `nodeName + conditions` to save memory), indexed by
  `spec.nodeName`; every pod add/update enqueues its node name onto a
  rate-limited workqueue drained by `--taint-sync-workers` (10). Per node:
  `nodeHasCiliumPod` → `(scheduled, running)` where running means a pod with
  no `deletionTimestamp` whose latest `Ready` condition is `True`.
  - running && `--remove-cilium-node-taints` && taint present → JSON-patch
    `/spec/taints` (with a `test` op on the old value for optimistic
    concurrency) removing key `node.cilium.io/agent-not-ready`
    (`defaults.AgentNotReadyNodeTaint`; agent flag
    `--agent-not-ready-taint-key` can rename it).
  - running && `--set-cilium-is-up-condition` && condition absent → strategic
    `PatchStatus` adding `NodeCondition{Type: NetworkUnavailable,
    Status: False, Reason: "CiliumIsUp", Message: "Cilium is running on this
    node"}`. **Cilium does not set NetworkUnavailable=True itself**; it only
    clears the one the cloud-controller/kubelet may have set, and uses
    `Reason=CiliumIsUp` as its idempotency marker (`HasCiliumIsUpCondition`).
  - scheduled && !running && `--set-cilium-node-taints` → add the taint with
    `Effect: NoSchedule`, empty value.
  - Kubelet-integration meaning: Helm installs the taint on nodes via
    cloud-init/kubeadm (`node.cilium.io/agent-not-ready=true:NoExecute` in
    docs) so workload pods cannot start without CNI; the operator is the sole
    remover. Errors retry with rate limiting; NotFound drops the key; after 6
    silent retries it logs at Warn.
- **CiliumNode GC** (`CiliumNodeGCCell`, `--nodes-gc-interval` 5m, 0
  disables): controller iterates CiliumNode store; a CiliumNode with no
  matching k8s Node, **no ownerReferences**, and not annotated
  `cilium.io/do-not-gc=true` is added to a candidate map with a timestamp; on a
  later run, if still orphaned for ≥ interval it is deleted (two-pass hysteresis).
  If `enable-cilium-node-crd=false` the predicate is "delete everything"
  (cleanup). CiliumNode objects are otherwise created by agents (owner ref to
  Node) and their `spec.ipam.podCIDRs` are filled by the operator's
  cluster-pool allocator (see 07-ipam; entry
  `operator/pkg/ipam/allocator/podcidr`, driven by
  `--cluster-pool-ipv{4,6}-cidr/-mask-size`, writes `spec.ipam.podCIDRs` and
  `status.ipam.operator-status.error` on the CiliumNode).
- **kvstore nodes GC** (`kvstore/nodesgc`, `--synchronize-k8s-nodes`): after
  k8s Node store sync, deletes `cilium/state/nodes/v1/<cluster>/<node>` keys
  for nodes that no longer exist in k8s. `kvstore/locksweeper`: removes stale
  lock keys left by crashed agents.

### Unmanaged pods (`operator/unmanagedpods`)

- Every `--unmanaged-pod-watcher-interval` (15s; 0 disables; also disabled if
  `disable-endpoint-crd`): list pods matching `--pod-restart-selector`
  (default `k8s-app=kube-dns`); a **Running, non-hostNetwork** pod with no
  CiliumEndpoint of the same namespace/name is a restart candidate; deletes it
  (kubelet/ReplicaSet recreates) with a per-pod `minimalPodRestartInterval`
  of 5m and forgets restart history after 10m. Metric `unmanaged_pods` gauge.
  RBAC `delete pods` is only granted when Helm
  `operator.unmanagedPodWatcher.restart` is true.

### ClusterMesh operator parts (details → clustermesh inventory)

- `ServiceSyncCell` (`--synchronize-k8s-services`, requires kvstore): converts
  every non-headless k8s Service annotated `service.cilium.io/global=true` (or
  in a global namespace) into a `ClusterService` under
  `cilium/state/services/v1/<cluster>/` in the kvstore, using
  `store.SyncStore` (WorkQueue-backed, retried). Only when
  `ServiceModeV2.ShouldExportLegacyServices()`.
- `EndpointSliceExportSyncCell`: exports `EndpointSlice`s of shared services
  as `ClusterEndpointSlice` keys (service mode v2).
- `endpointslicesync.Cell` (`--clustermesh-enable-endpoint-sync`): the reverse
  — remote ClusterServices become local `discovery.k8s.io/EndpointSlice`s
  labelled for the local Service (so kube-proxy-less/DNS integrations see
  remote endpoints); `--clustermesh-endpoints-per-slice`,
  `--clustermesh-endpoint-updates-batch-period`,
  `--clustermesh-concurrent-service-endpoint-syncs`.
- `mcsapi.Cell` + `ServiceExportSyncCell`: MCS-API ServiceExport → kvstore,
  ServiceImport + derived `Service` creation locally.
- `cmoperator.Cell`: remote cluster connections from `--clustermesh-config`,
  exposed on `/cluster` and `cilium-operator status clustermesh`.
- `clustercfgcell`: writes `cilium/cluster-config/<name>` (ID, capabilities).
- `heartbeat.Cell`: writes `cilium/.heartbeat` key every
  `kvstore-lease-ttl/…` so agents can detect a stale kvstore.

### Gateway API (`operator/pkg/gateway-api`)

- Enabled by viper key `enable-gateway-api`; **requires
  `kube-proxy-replacement=true`** (else disabled with a warning). Library
  `sigs.k8s.io/gateway-api v1.6.1`. Controller name
  `io.cilium/gateway-controller`.
- Startup precondition: discovers CRDs with retry (200ms→5s backoff, 30s
  total). **Required** (all `gateway.networking.k8s.io/v1`): GatewayClass,
  Gateway, HTTPRoute, GRPCRoute, TLSRoute, ReferenceGrant, BackendTLSPolicy.
  **Optional** (enable extra support when present): ListenerSet (v1),
  TCPRoute, UDPRoute, `multicluster.x-k8s.io/v1beta1` ServiceImport.
  Missing required CRDs → cell degraded, controllers not started (not fatal).
- Reconcilers (controller-runtime): `gatewayClassReconciler` (accepts classes
  whose `controllerName` matches; validates `parametersRef` →
  `CiliumGatewayClassConfig`), `gatewayReconciler`, `gammaReconciler`
  (HTTPRoutes whose parentRef is a **Service** — service mesh / GAMMA),
  `gatewayClassConfigReconciler` (status on `CiliumGatewayClassConfig`),
  `endpointSliceReconciler` (keeps operator-owned frontend EndpointSlices).
- **Gateway reconcile output**: for each Gateway of an accepted class,
  ingestion (`model/ingestion/gateway.go: GatewayAPI(input) *model.Model`)
  collects listeners + all attached routes (HTTP/GRPC/TLS/TCP/UDP, filtered by
  `allowedRoutes`, hostnames, ReferenceGrant for cross-namespace backends and
  certificateRefs), then `translation/gateway-api.Translate(model)` produces:
  one `CiliumEnvoyConfig` in the Gateway's namespace named
  `cilium-gateway-<gw>` (listeners, HCM, RouteConfiguration, clusters with
  `services[]` backend refs so the agent resolves endpoints), one
  `Service` `cilium-gateway-<gw>` of type LoadBalancer (or hostNetwork: no
  Service, listeners bound to node IPs on nodes matching
  `--gateway-api-hostnetwork-nodelabelselector`), and frontend
  `EndpointSlice`s pointing at the Envoy listener addresses. Addresses from
  the Service `status.loadBalancer` are copied to `gateway.status.addresses`;
  Gateway `infrastructure.labels/annotations` and `addresses` (static IP →
  `lbipam.cilium.io/ips`) are propagated to the Service. Owner references
  from Gateway → Service/EPS/CEC give GC on delete; `cleanupOwnedResources`
  handles the rest.
- Status written: GatewayClass `Accepted`; Gateway `Accepted`, `Programmed`
  (reasons `NoResources`, `AddressNotAssigned`, `ListenersNotValid`,
  `InvalidParameters`, `UnsupportedAddress`…); per-Listener `Accepted`,
  `Programmed`, `ResolvedRefs`, `Conflicted` (`HostnameConflict`,
  `ProtocolConflict`, `InvalidCertificateRef`, `RefNotPermitted`,
  `InvalidRouteKinds`, `UnsupportedProtocol`); Route `Accepted`/`ResolvedRefs`
  per parentRef (`NoMatchingParent`, `NoMatchingListenerHostname`,
  `NotAllowedByListeners`, `BackendNotFound`, `InvalidKind`,
  `RefNotPermitted`, `UnsupportedValue`).
- Supported route features (from `model` + translation): path/header/query/
  method matching, weighted backends, request/response header modifiers,
  redirect (scheme/host/port/path/status), URL rewrite, request mirror (incl.
  cross-ns with ReferenceGrant and ServiceImport), CORS, external auth,
  timeouts, retries, direct response, BackendTLSPolicy (upstream TLS with CA
  from ConfigMap), GRPC-Web, TLS passthrough (TLSRoute), TCP/UDP routes,
  ListenerSets. Conformance run in CI with profiles
  `GATEWAY-HTTP, GATEWAY-TLS, GATEWAY-GRPC, GATEWAY-TCP, GATEWAY-UDP,
  MESH-HTTP, MESH-GRPC`.
- Secrets sync: when `--enable-gateway-api-secrets-sync`, registers with the
  generic `secretsync` cell: Secrets referenced by any Gateway (and
  ListenerSet) `certificateRefs` are copied into
  `--gateway-api-secrets-namespace`, named `<ns>-<name>`; ConfigMaps
  referenced by BackendTLSPolicy `caCertificateRefs` likewise. Agents read
  only from that namespace (their RBAC is scoped to it).
- Flags: `--enable-gateway-api-{secrets-sync,proxy-protocol,app-protocol,alpn}`,
  `--gateway-api-{secrets-namespace,service-externaltrafficpolicy,
  xff-num-trusted-hops,use-remote-address,hostnetwork-enabled,
  hostnetwork-nodelabelselector}`; Envoy timeouts from
  `--proxy-idle-timeout-seconds` / `--proxy-stream-idle-timeout-seconds`.

### Ingress controller (`operator/pkg/ingress`)

- `--enable-ingress-controller`; IngressClass `cilium`; also handles Ingresses
  with no class when the `cilium` IngressClass carries
  `ingressclass.kubernetes.io/is-default-class=true` (watches IngressClass to
  re-enqueue). `Owns(Service)`, `Owns(EndpointSlice)`, `Owns(CEC)`.
- **LB modes**: annotation `ingress.cilium.io/loadbalancer-mode`
  (`dedicated`|`shared`; default `--ingress-default-lb-mode`, `dedicated`).
  Dedicated: per-Ingress `Service` `cilium-ingress-<name>` (type from
  `ingress.cilium.io/service-type`, default LoadBalancer; NodePort ports via
  `insecure-node-port`/`secure-node-port` annotations; `loadbalancer-class`,
  `service-external-traffic-policy`), an `EndpointSlice`, and a CEC in the
  Ingress namespace. Shared: one CEC `cilium-ingress` in the operator
  namespace built from **all** shared Ingresses (`buildSharedResources`), one
  Service `--ingress-shared-lb-service-name` (created by Helm, not the
  operator). Annotations/labels matching `--ingress-lb-annotation-prefixes`
  are copied from Ingress to the Service.
- Other annotations: `ingress.cilium.io/tls-passthrough` (SNI passthrough →
  `TLSPassthroughListener`), `force-https` (per-Ingress override of
  `--enforce-ingress-https`, 308 redirect), `request-timeout`,
  `host-listener-port` (host-network dedicated). Old `io.cilium.ingress/…`
  aliases accepted.
- Default TLS: `--ingress-default-secret-namespace/-name` used when an Ingress
  TLS block names no secret. Secrets sync into `--ingress-secrets-namespace`
  when `--enable-ingress-secrets-sync`.
- Host network mode: `--ingress-hostnetwork-enabled` with either one
  `--ingress-hostnetwork-shared-listener-port` or separate http/https/
  passthrough ports; node selector as for Gateway.
- Status: `ingress.status.loadBalancer.ingress` mirrored from the (dedicated
  or shared) Service. Conformance: `cilium/ingress-controller-conformance` in CI.

### Model + translation (`operator/pkg/model`, `.../translation`)

- `model.Model{HTTP []HTTPListener, TLSPassthrough []TLSPassthroughListener}`.
  `HTTPListener{Name, Sources []FullyQualifiedResource, Address, Port,
  Hostname, TLS []TLSSecret, Routes []HTTPRoute, Service *Service,
  Infrastructure, ForceHTTPtoHTTPSRedirect, Gamma, ALPN, ProxyProtocol…}`;
  `HTTPRoute{PathMatch, HeadersMatch, QueryParamsMatch, Method, Backends
  []Backend, BackendHTTPFilters, DirectResponse, RequestHeaderFilter,
  ResponseHeaderModifier, RequestRedirect, Rewrite, RequestMirrors, CORS,
  ExternalAuth, Timeout, Retry, IsGRPC, GRPCWeb…}`;
  `Backend{Name, Namespace, Port *BackendPort, Weight, AppProtocol, TLS
  *BackendTLSOrigination}`.
- `translation.Config{SecretsNamespace, ServiceConfig{ExternalTrafficPolicy},
  HostNetworkConfig{Enabled, NodeLabelSelector}, IPConfig, ListenerConfig
  {UseProxyProtocol, UseAlpn, StreamIdleTimeoutSeconds}, ClusterConfig
  {IdleTimeoutSeconds, UseAppProtocol}, RouteConfig{HostNameSuffixMatch},
  OriginalIPDetectionConfig{XFFNumTrustedHops, UseRemoteAddress}}`.
  `CECTranslator.Translate(ns, name, model) → *CiliumEnvoyConfig` builds
  Envoy v3 protobufs (`envoy_listener.go`, `envoy_http_connection_manager.go`,
  `envoy_route_configuration.go`, `envoy_virtual_host.go`,
  `envoy_cluster.go` + mutators) and packs them as `Any` into
  `spec.resources[]`, sets `spec.services[]` (frontend Service the agent
  redirects) and `spec.backendServices[]` (for endpoint resolution). Listener
  naming and SNI/filter-chain matching (`filterChainMatch`) are the part that
  agent-side `pkg/envoy` depends on. The ~42k lines of testdata are golden
  CECs for this.

### Secret / ConfigMap sync (`operator/pkg/secretsync`)

- Generic controller: registrations from Ingress, Gateway API and network
  policy (`--enable-policy-secrets-sync`, `--policy-secrets-namespace`) each
  give `{RefObject, EnqueueFunc, CheckFunc, SecretsNamespace}`; the reconciler
  watches source Secrets (indexed) and copies them as
  `<srcns>-<srcname>` with an ownership annotation, deletes copies no longer
  referenced, and resyncs periodically with jitter. Same for ConfigMaps
  (BackendTLSPolicy CA bundles).

### Other leader cells

- `ciliumenvoyconfig.Cell` (`--loadbalancer-l7=envoy`): for Services annotated
  `service.cilium.io/lb-l7=enabled` creates a CEC that makes Envoy the L7 load
  balancer for that Service (`--loadbalancer-l7-algorithm`,
  `--loadbalancer-l7-ports`).
- `networkpolicy.Cell`: **validator** (`--validate-network-policy`) parses
  every CNP/CCNP and writes `status.conditions` (Valid/Invalid with message)
  via `UpdateStatus` — informational only, the agent enforces regardless. This
  is the only remaining CNP status writer (the old `cnp-status-update` node
  status map is gone). `external-groups`: resolves `toGroups` (AWS
  provider) into `CiliumCIDRGroup` objects every
  `--policy-external-group-sync-interval`.
- `bgp.Cell`: watches `CiliumBGPClusterConfig` + `CiliumBGPNodeConfigOverride`
  + Nodes; for each node matching `nodeSelector` upserts a
  `CiliumBGPNodeConfig` (owner ref to ClusterConfig), allocates router IDs
  from a pool when configured, sets conditions `ConflictingClusterConfigs`,
  `MissingPeerConfigs`, `NoMatchingNode`, `MissingAuthSecret`; deletes
  NodeConfigs for deselected nodes. Also updates `CiliumBGPPeerConfig` status.
- `nodeipam.Cell` (`--enable-node-ipam`): assigns node IPs as LB ingress for
  Services with `loadBalancerClass: io.cilium/node`.
- `ztunnel.Cell` (`--enable-ztunnel`, `--ztunnel-ca-type`): reconciles a
  ztunnel DaemonSet + CA.
- `auth.Cell`/`spire`: SPIRE entry deletion for identity GC (deprecated).
- `ipsec.OperatorCell`, `wgAgent.OperatorCell`: expose enable flags for CES
  slim encryption-key computation.
- `features.Cell`: `cilium_operator_feature_*` gauges describing enabled
  features.

### Operator API, health, metrics, debug

- REST (go-swagger, `api/v1/operator/openapi.yaml`) on
  `--operator-api-serve-addr` (`localhost:9234`; Helm exposes 9234 hostPort):
  `GET /healthz` (200 `ok` / 500 `<err>` / 501 when disabled) — checks
  kvstore `Status().State == ok` if kvstore enabled and apiserver
  `ServerVersion()`; `GET /metrics/` (JSON list of `Metric{name, labels,
  value}`); `GET /cluster` (list of `RemoteCluster` status). Access list
  `--enable-cilium-operator-server-access`. Listener uses
  `SO_REUSEADDR|SO_REUSEPORT` so two replicas on one host don't conflict.
  Kubelet liveness/readiness probes hit `/healthz` on 9234.
- Prometheus on `--operator-prometheus-serve-addr` (`:9963`) when
  `--enable-metrics`; optional TLS/mTLS. Namespace `cilium_operator_`. Metrics:
  Go/process collectors, `errors_warnings_total`, controller-runtime
  certificate metrics, workqueue metrics, hive/job metrics,
  `identity_gc_{runs,entries,latency}`, `endpoint_gc_objects`,
  `unmanaged_pods`, `ces_sync_total`, `ces_queueing_delay_seconds`,
  `number_of_ceps_per_ces`, `number_of_cep_changes_per_ces`,
  `cid_controller_work_queue_{event_count,latency}`, `doublewrite_*`,
  `lbipam_{conflicting_pools,ips_available,ips_used,services_matching,
  services_unsatisfied,event_processing_time_seconds}`, `ztunnel_*`,
  IPAM (`ipam_*`, see 07), BGP (`bgp_*`), feature gauges.
- CLI: `cilium-operator metrics list`, `status [clustermesh]`,
  `troubleshoot {kvstore,clustermesh}`, `hive [dot-graph]`, `shell`
  (`/var/run/cilium/shell.sock`), `completion`; hidden `--cmdref`.
- pprof `--operator-pprof*` (localhost:6061), gops :9891.

## Data model

CRDs the operator **creates/updates** (list above, `cilium.io` group,
`v2` unless noted): CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy,
CiliumCIDRGroup, CiliumEndpoint, CiliumEndpointSlice (v2alpha1),
CiliumIdentity, CiliumNode, CiliumNodeConfig, CiliumLocalRedirectPolicy,
CiliumEgressGatewayPolicy, CiliumEnvoyConfig, CiliumClusterwideEnvoyConfig,
CiliumBGPClusterConfig, CiliumBGPPeerConfig, CiliumBGPAdvertisement,
CiliumBGPNodeConfig, CiliumBGPNodeConfigOverride, CiliumLoadBalancerIPPool,
CiliumL2AnnouncementPolicy (v2alpha1), CiliumPodIPPool (v2alpha1),
CiliumGatewayClassConfig (v2alpha1), CiliumDatapathPlugin (v2alpha1); plus
MCS `ServiceExport`/`ServiceImport` (`multicluster.x-k8s.io/v1beta1`).

Objects the operator **writes as a controller**:

| Object | Writer | Key fields |
|---|---|---|
| `CiliumIdentity` | identitygc (annotate `io.cilium.heartbeat`, delete), ciliumidentity (create/update `security-labels`) | name = numeric ID; `security-labels` map |
| `CiliumEndpoint` | endpointgc (delete only) | |
| `CiliumEndpointSlice` | CES controller | `namespace`, `endpoints[].{name,id,pod-uid,networking,encryption,named-ports,service-account}` |
| `CiliumNode` | podcidr allocator (`spec.ipam.podCIDRs`, `status.ipam.operator-status`), CiliumNode GC (delete) | annotation `cilium.io/do-not-gc` |
| `Node` | taint sync: `spec.taints` (JSON patch), `status.conditions` (strategic patch) | taint `node.cilium.io/agent-not-ready`, condition `NetworkUnavailable/False/CiliumIsUp` |
| `Pod` | unmanagedpods (delete) | |
| `CiliumEnvoyConfig` | ingress, gateway-api, ciliumenvoyconfig | `spec.services[]`, `spec.backendServices[]`, `spec.resources[]` (Envoy `Any`) |
| `Service`, `EndpointSlice` | ingress, gateway-api, mcsapi, endpointslicesync, nodeipam (`status.loadBalancer`) | owner refs to Ingress/Gateway |
| `Secret`, `ConfigMap` | secretsync (copies into `cilium-secrets`) | name `<ns>-<name>` |
| `CiliumBGPNodeConfig` | bgp | owner ref to `CiliumBGPClusterConfig` |
| `CiliumCIDRGroup` | external-groups | |
| `CiliumPodIPPool` | `--auto-create-cilium-pod-ip-pools` | |
| `Lease` `cilium-operator-resource-lock` | leader election | `holderIdentity` |
| `CustomResourceDefinition` | RegisterCRDs | label `io.cilium.k8s.crd.schema.version=1.33.11` |
| Status subresources | CNP/CCNP `.status.conditions`; Gateway API `*/status`; Ingress `status.loadBalancer`; BGP `*/status`; CiliumGatewayClassConfig, CiliumLoadBalancerIPPool `/status` | |

kvstore keys written (etcd): `cilium/state/services/v1/<cluster>/<ns>/<svc>`
(ClusterService JSON), ClusterEndpointSlice keys, `cilium/.heartbeat`,
`cilium/cluster-config/<cluster>`; deleted: `cilium/state/identities/v1/id/*`
+ `.../value/*` (identity GC), `cilium/state/nodes/v1/<cluster>/*`
(nodes GC), stale `.../locks/*`.

Files on disk: `/var/run/cilium/shell.sock`, health history under
`/var/run/cilium/state`. No BPF maps, no netlink.

## External interfaces

- Kubernetes API (client-go informers via `pkg/k8s/resource` and a
  controller-runtime Manager with its own cache — two informer stacks in one
  process). RBAC per
  `install/kubernetes/cilium/templates/cilium-operator/clusterrole.yaml`
  (summarised): core `pods` get/list/watch (+`delete` if unmanaged-pod
  restart); `configmaps/cilium-config` patch; `nodes` list/watch/patch and
  `nodes/status` patch (gated on taint/condition Helm values);
  `discovery.k8s.io/endpointslices` get/list/watch (+CRUD for clustermesh
  sync / ingress / gateway); `services` get/list/watch (+CRUD for ingress /
  gateway / mcsapi), `services/status` update/patch, `services/finalizers`;
  `namespaces`, `serviceaccounts`, (`secrets` when ingress/gateway/bgp/secret
  sync) get/list/watch; `events` create/patch (endpointslice sync);
  `cilium.io`: CNP/CCNP full CRUD + `/status`; `ciliumendpoints`,
  `ciliumidentities` delete/list/watch; `ciliumidentities` update (+create in
  operator identity mode); `ciliumnodes` create/update/get/list/watch (+delete
  if node GC) and `/status`; `ciliumendpointslices`, `ciliumenvoyconfigs`,
  all five BGP kinds, `ciliumcidrgroups` full CRUD; BGP `/status`;
  `ciliumloadbalancerippools`, `ciliumpodippools`, `ciliumbgppeerconfigs`,
  `ciliumdatapathplugins` get/list/watch; `ciliumpodippools` create;
  `ciliumloadbalancerippools/status` patch; `ciliumendpointslices`
  deletecollection; `apiextensions.k8s.io/customresourcedefinitions`
  create/get/list/watch and `update` restricted by `resourceNames` to the 22
  Cilium CRDs (+MCS), `/status` update for BGP CRDs;
  `coordination.k8s.io/leases` create/get/update; Ingress:
  `networking.k8s.io/ingresses,ingressclasses` get/list/watch,
  `ingresses/status,finalizers` update; Gateway API: all kinds get/list/watch,
  `gatewayclasses` patch, all `*/status` update/patch,
  `ciliumgatewayclassconfigs` (+`/status`), `configmaps` get/list/watch; MCS:
  `serviceimports`/`serviceexports` (+status/finalizers).
- etcd (kvstore) via `pkg/kvstore` gRPC; service-name → ClusterIP resolution
  without CoreDNS (`dial.ResourceServiceResolverCell`).
- SPIRE server gRPC (deprecated); cloud APIs (out of scope).
- HTTP: `:9234` operator API, `:9963` metrics, `localhost:6061` pprof, `:9891` gops.
- Consumers: agents read CiliumNode `spec.ipam.podCIDRs`, CES, CID, CEC,
  synced Secrets in `cilium-secrets`, kvstore services; kubelet/scheduler read
  the node taint and `NetworkUnavailable` condition.

## Dependencies

Inventory areas: 01-agent-core (option.Config, defaults, hive), 03-policy
(CNP types, label→identity key `pkg/identity/key`), 05-identity/ipcache
(`pkg/allocator`, `pkg/kvstore/allocator`, `pkg/identity`), 07-ipam
(`operator/pkg/ipam`, CiliumNode spec), 09-clustermesh (`pkg/clustermesh/*`,
`pkg/kvstore/store`), 10-envoy/L7 (CEC types, `pkg/envoy` listener naming),
load-balancer inventory (LB IPAM, `service.cilium.io/*` annotations), bgp
inventory (BGP CRD types). Libraries: client-go, controller-runtime,
`sigs.k8s.io/gateway-api v1.6.1`, `sigs.k8s.io/mcs-api`, Envoy go-control-plane
protobufs, go-swagger runtime, `golang.org/x/time/rate`, `cilium/hive`,
`cilium/workerpool`, `blang/semver`. External services: kube-apiserver
(mandatory), etcd (optional — needed for kvstore identity mode, service sync,
ClusterMesh), SPIRE (deprecated), Envoy in agents (consumes CEC).

## Kernel / platform requirements

None. Pure userspace k8s controller; runs anywhere the apiserver is
reachable. Uses `SO_REUSEPORT` on the API listener (Linux/BSD). Helm runs it
with `hostNetwork: true` so it can reach the apiserver before CNI is up on
the node it lands on — the Rust port must keep that deployment property.

## Tests

- Unit: 47,254 test lines across `operator/**`; heaviest are model/translation
  (5,474 + golden `testdata` 604 files / 42,721 lines: every Gateway and GAMMA
  scenario as `input/*.yaml` → `output/*.yaml` CEC), gateway-api reconcilers
  (4,835) and helpers/routechecks/indexers, lbipam (3,621), CES (2,466),
  ciliumidentity (1,534), ingress (1,792 + 609), identitygc (439: CRD heartbeat
  two-pass semantics, kvstore GC via fake backend), endpointgc (239: owner-ref
  and pod-state matrix), watchers (1,124 incl. `script_test.go` txtar scripts
  `servicesync.txtar`, `endpointslice-export-sync.txtar`,
  `globalnamespace-services.txtar` driving fake k8s + fake kvstore), node
  taint (`node_taint_test.go`, `node_taint_cell_test.go`: taint removal,
  condition set, set-taint when not ready, deletionTimestamp handling),
  unmanagedpods (288), kvstore nodesgc txtar (`enabled`/`disabled`), api
  (709: healthz states, access list, reuseport), spire client (894).
- No privileged tests (no kernel interaction).
- CI (`.github/workflows`): `conformance-gateway-api.yaml` (upstream
  Gateway API conformance suite, profiles HTTP/TLS/GRPC/TCP/UDP + MESH-HTTP/
  MESH-GRPC, report uploaded), `conformance-ingress.yaml`
  (`cilium/ingress-controller-conformance` fork, shared + dedicated + host
  network matrices), `tests-ces-migrate.yaml` (enable/disable CES on a live
  cluster, checks connectivity and CES GC), `conformance-clustermesh.yaml`,
  `conformance-mcs-api.yaml`, `tests-clustermesh-upgrade.yaml`,
  `tests-e2e-upgrade.yaml` (operator upgrade/rollback incl. CRD update path),
  `conformance-multi-pool.yaml`, `conformance-{aks,eks,gke}.yaml` (cloud
  operator binaries), `conformance-kind-proxy-embedded.yaml` (kube-proxy
  replacement needed by Gateway API). Behaviours pinned: single leader,
  CRD upgrade in place, taint removal gates workload scheduling
  (`cilium connectivity test` waits on it), CES ↔ CEP equivalence, Gateway
  status conditions and generated Service/CEC shapes, Ingress LB status.

## Rust mapping

Recommended shape: one `flowsdn-operator` binary built on **kube-rs**
(`kube`, `kube-runtime`, `kube-derive`, `k8s-openapi`) using the
`kube_runtime::Controller` pattern (watch + reflector store + reconcile
closure with `Action::requeue`) — that is the direct analogue of both
`pkg/k8s/resource` and controller-runtime, so the two-informer-stack split in
Go collapses into one. Structure:

- `operator/main.rs`: clap flags (generate the table above verbatim; keep
  names so Helm ConfigMap keys work), `config-dir` loader, tracing, tokio.
- `leader`: `kube-leader-election` crate or ~200 lines over
  `coordination.k8s.io/Lease` with the same 15/10/2 s defaults; on loss
  `std::process::exit` — replicate the fatal semantics, do not try to
  become a follower with live state.
- `crds`: embed CRD YAML (`include_str!`) generated from the Rust types with
  `kube::CustomResource` derive **or** vendor Cilium's YAML unchanged (safer
  for wire compatibility with existing agents); keep label
  `io.cilium.k8s.crd.schema.version` and the `semver` compare
  (`semver` crate).
- `gc::identity`, `gc::endpoint`, `gc::ciliumnode`, `gc::kvstore_nodes`:
  periodic tasks over reflector stores; `governor` for the 2500/min limiter;
  the CRD identity two-pass annotation protocol must be byte-identical
  (`io.cilium.heartbeat`, RFC3339Nano) because agents and older operators
  read it. kvstore mode needs the etcd allocator GC from the identity
  inventory (`etcd-client` crate).
- `node_taint`: `Controller` on agent Pods mapped to Node names; JSON patch
  with `test` op (`json-patch` crate) and `PatchStatus` via `Patch::Strategic`
  — the `Reason=CiliumIsUp` marker and taint key must match so mixed-version
  clusters and kubelet expectations hold.
- `ces`: reflector on CEP (default) or Pods+CID+CiliumNode (slim); two
  priority `tokio` queues; `governor` limiter re-tuned on node count;
  namespace-grouped bin-packing. Must emit identical CES JSON (field names
  `id`, `pod-uid`, `named-ports`, `service-account`).
- `unmanaged_pods`, `secretsync`, `ciliumenvoyconfig`, `networkpolicy
  validator`, `bgp` (CRD→CRD fan-out), `nodeipam`: straightforward
  `Controller`s, S each.
- `ingress` + `gateway_api` + `model` + `translation`: define the
  `model::Model` types in Rust, port ingestion (Gateway API types from the
  `gateway-api` crate — check it tracks v1.6 incl. ListenerSet/BackendTLSPolicy;
  otherwise derive them), and translation to Envoy v3 protobufs
  (`envoy-types` crate, prost) packed as `Any` into CEC. The golden testdata
  (604 files) is the acceptance test: port it as fixtures and diff
  canonicalised JSON. This is **the hard part**: ~13k lines of Go across
  ingestion/translation/reconcilers/routechecks/status plus 42k lines of
  fixtures, and every listener/filter-chain naming detail is coupled to the
  agent's Envoy integration.
- `api`: `axum` on 9234 with `/healthz`, `/metrics/`, `/cluster`;
  `prometheus`/`metrics-exporter-prometheus` on 9963 with the same metric
  names.
- `clustermesh`: service/EPS export to etcd and EndpointSlice import — share
  the `ClusterService` JSON codec with the clustermesh inventory.

Risks: (1) wire compatibility with Go agents during a mixed rollout (CES/CID
JSON, heartbeat annotation, CEC listener names, `cilium-secrets` naming);
(2) Gateway API surface moves fast (v1.6.1 today) and conformance is the only
real spec; (3) kube-rs has no equivalent of controller-runtime field indexers
— replicate with reflector-derived `HashMap`s; (4) the operator reads ~15
agent flags from the shared ConfigMap; the Rust side must accept the agent's
key names too; (5) `hostNetwork` + `SO_REUSEPORT` must be kept for two
replicas per node in small clusters.

## Recommendation

- **Keep (core)**: leader election, CRD registration/upgrade, identity GC
  (CRD + kvstore), CEP GC, CiliumNode GC, node taint/condition sync,
  unmanaged-pod restart, CES controller (default mode first; slim mode
  second), operator API/health/metrics, cluster-pool podCIDR handoff (owned by
  07-ipam), service→kvstore sync, kvstore nodes GC, secret sync. These are
  what a Cilium-compatible cluster needs on day one. Effort **M** (≈ 6–8k
  Rust lines).
- **Keep but defer**: Gateway API + Ingress + model/translation + GAMMA. Ship
  after agents' Envoy/CEC path exists in flowsdn. Effort **L→XL** (≈ 12–18k
  Rust lines plus fixture port); Ingress alone (dedicated mode, no TLS
  passthrough) is an **M** subset once the translator exists.
- **Keep, small**: BGP CRD fan-out (**S–M**), nodeipam (**S**), CNP validator
  (**S**), external-groups (**S**, AWS provider only), MCS-API + EndpointSlice
  sync (**M**, with clustermesh).
- **Replace/drop**: double-write identity mode + reporter (migration aid for
  kvstore→CRD; only needed if we support both modes), SPIRE/mutual auth
  (deprecated upstream in 1.20), ztunnel DaemonSet management (experimental),
  the four cloud binary variants (one binary with feature flags; provider
  selection at runtime), `cilium-operator` legacy all-in-one name, gops/hive
  shell (use tokio-console / tracing instead), `--cmdref`.

Total in-scope effort: **L** (≈ 20k lines Rust) counting Gateway API; **M**
without it.

## Decisions and remaining questions

1. **Resolved #156:** agents publish CEPs; default CES mode ships first. Slim
   remains a required second mode with operator identities and shared derivation
   fixtures. No slim controller is delivered by the current planning library.
2. Resolved #20: CRD allocation is primary (spec20); kvstore remains supported
   scope with separate conformance gates. Allocation backend is distinct from
   identity-management ownership (#161).
3. Resolved #21: hand-declared schema-backed types owned by flowsdn-k8s,
   pinned to Gateway API 1.6.1; spec21§12.11 owns seven required profiles and
   staged capabilities. Type generation and controller integration remain pending.
4. **Resolved #158:** keep `node.cilium.io/agent-not-ready`, including the
   existing custom-key option. Key-only removal preserves unrelated taints.
   Any future default-key migration must remove both keys.
5. **Resolved #157:** retain `io.cilium.k8s.crd.schema.version` and 1.33.x,
   initially 1.33.11. The canonical constant belongs to `flowsdn-k8s`; YAML hash
   coupling and live upgrade checks remain registration release gates.
6. **Resolved #160:** keep `/healthz`, `/v1/metrics/` and `/v1/cluster`; HTTP
   handlers remain required. Spec12 adds `/readyz` so missing external CRDs
   cannot turn a readiness failure into a liveness restart (#164).
7. **Resolved #162:** retain multi-step CES rate configuration at all cluster
   sizes. The operator library implements validated selection; controller,
   token-bucket integration and CES bin-packing remain required by spec12.
