# Helm chart, container images, CI and test estate — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `install/kubernetes/cilium/**`,
`images/**`, `plugins/cilium-cni/*.sh`, `tools/mount`, `tools/sysctlfix`, `test/**`,
`bpf/tests/**`, `bpf/complexity-tests/**`, `pkg/datapath/loader/verifier*_test.go`,
`.github/workflows/**`, `.github/actions/**`, `Documentation/operations/system_requirements.rst`,
`Documentation/operations/upgrade.rst`, `Documentation/contributing/testing/*.rst`,
`Documentation/contributing/release/organization.rst`, `contrib/**`, `VERSION`.

## Purpose

This area is everything that surrounds the agent binary: how Cilium is packaged
(the OCI images and what they contain), how it is deployed (the Helm chart — values,
ConfigMap, DaemonSets/Deployments, init containers, RBAC, privileges, host mounts),
what the cluster and kernel must provide (system requirements), how upgrades are
constrained (preflight, `upgradeCompatibility`), and how the whole thing is tested
(BPF unit tests under `BPF_PROG_RUN`, verifier-complexity matrix per kernel,
control-plane golden tests, legacy ginkgo e2e, and the GitHub Actions estate that
drives `cilium-cli connectivity test` across kind/LVH kernels and EKS/GKE/AKS).
For flowsdn this area defines the *contract* a replacement must honour: the same
Helm values, the same `cilium-config` keys, the same host mounts and capabilities
(or fewer), and the same acceptance tests.

## Components

| Path | Lines | Purpose |
|---|---|---|
| `install/kubernetes/cilium/values.yaml` | 4591 | Helm values (174 top-level keys, ~1580 leaf keys); generated from `values.yaml.tmpl` (4637) by `install/kubernetes/Makefile` |
| `install/kubernetes/cilium/values.schema.json` | 6673 | JSON schema enforced by `helm lint`/install (types, enums) |
| `install/kubernetes/cilium/templates/*.yaml, *.tpl, NOTES.txt` | 2612 (15 files) | `cilium-configmap.yaml` (1591, the values→config-key map), `validate.yaml` (258, 48 `fail` guards), `_helpers.tpl`, CA secret/bundle, ingress/gateway class, secrets namespace, resource quota, flowlog/dynamic-metrics ConfigMaps |
| `templates/cilium-agent/` | 1844 (9) | DaemonSet (1154), ClusterRole (167), Role (151), bindings, SA, Service, ServiceMonitor, dashboards |
| `templates/cilium-operator/` | 1452 (12) | Deployment (463), ClusterRole (484), Role, PDB, secret, SA, metrics |
| `templates/cilium-envoy/` | 531 (7) | Standalone Envoy DaemonSet (349), bootstrap ConfigMap, node-locality RBAC |
| `templates/cilium-preflight/` | 585 (6) | Preflight DaemonSet (image pre-pull + envoy pre-pull) and CNP-validator Deployment |
| `templates/cilium-nodeinit/` | 160 (2) | Node-init DaemonSet running `files/nodeinit/startup.bash` on the host via nsenter |
| `templates/clustermesh-apiserver/` | 1431 (24) | Deployment (etcd-init, etcd, apiserver, kvstoremesh), services, TLS (helm/cronjob/certmanager/provided), users ConfigMap |
| `templates/clustermesh-config/` | 135 (3) | `cilium-clustermesh` secret (remote cluster etcd configs), kvstoremesh secret |
| `templates/clustermesh-coredns-mcsapi/` | 265 (8) | Job auto-configuring CoreDNS for MCS-API `clusterset.local` |
| `templates/hubble/` | 992 (25) | peer Service, metrics Service, ServiceMonitor, dashboards, TLS generation (helm/cronjob/certmanager/provided) |
| `templates/hubble-relay/` | 453 (7) | Relay Deployment, ConfigMap, Service, PDB |
| `templates/hubble-ui/` | 504 (9) | UI Deployment (nginx frontend + backend), Ingress, RBAC |
| `templates/spire/` | 677 (15) | SPIRE server StatefulSet + agent DaemonSet + bundle ConfigMap (mutual auth beta) |
| `templates/standalone-dns-proxy/`, `templates/ztunnel/` | 115 + 215 | Alpha standalone DNS proxy DaemonSet; Istio ztunnel DaemonSet for `encryption.type=ztunnel` |
| `install/kubernetes/cilium/files/**` | 19313 (12) | Grafana dashboards (bulk), `nodeinit/startup.bash` (178) and `prestop.bash` (60), `agent/poststart-eni.bash`, `cilium-envoy/configmap/bootstrap-config.yaml`, `spire/*.bash` |
| `install/kubernetes/cilium/README.md` | 1084 | helm-docs generated values reference |
| `images/**/Dockerfile` | 633 (8) | builder, runtime, cilium, operator, hubble-relay, clustermesh-apiserver, standalone-dns-proxy, cache |
| `images/**/*.sh, *.go` | 768 (21) | `runtime/install-runtime-deps.sh`, `build-cni.sh`, `build-gops.sh`, `build-iptables-wrapper.sh`, `cilium/init-container.sh`, image tag/digest scripts |
| `plugins/cilium-cni/install-plugin.sh`, `cni-uninstall.sh` | 67 | CNI binary install into `/host/opt/cni/bin`; conf removal on preStop |
| `tools/mount/main.go`, `tools/sysctlfix/main.go` | 178 | Static Go helpers copied to the host and run via `nsenter` by init containers |
| `test/controlplane/**` | 5852 (34) | Control-plane integration tests: k8s objects in → fake datapath state out, per k8s version fixtures |
| `test/k8s/*.go` + `manifests/**` | 4402 + 2182 | Legacy ginkgo e2e (K8sAgent*, K8sDatapath*) run by `conformance-ginkgo` |
| `test/helpers/**`, `test/ginkgo-ext/` | 7321 + 1082 | ginkgo harness helpers (kubectl wrappers, cilium exec, etc.) |
| `test/{bigtcp,vtep,bpf,fuzzing,config,logger}` | 692 | BIG TCP netperf script, VTEP kind scenario, sample XDP prog, oss-fuzz build |
| `bpf/tests/*.c` | 35501 (141) | BPF unit/integration tests (330 PKTGEN, 397 CHECK programs) |
| `bpf/tests/*.h, lib/*.h` | 12270 (47) | Harness macros (`common.h`), fake map/endpoint/ipcache/lb/policy helpers, packet generator |
| `bpf/tests/bpftest/*.go` | 1152 (3) | Go driver: loads each `.o`, runs PKTGEN→SETUP→CHECK under `BPF_PROG_RUN`, decodes protobuf results, coverbee coverage |
| `bpf/tests/scapy/*.py` | 1277 (19) | scapy packet definitions compiled to `output/scapy_bytes.h` |
| `bpf/complexity-tests/**` | 2352 (100) | Build permutations (`510/`, `61/`, `netnext/` × bpf_lxc/host/overlay/sock/wireguard/xdp) for the verifier matrix |
| `pkg/datapath/loader/verifier*_test.go` | 877 (2) | `TestPrivilegedVerifier`: compiles+loads every permutation, records insns processed / stack depth |
| `.github/workflows/*` | 17462 (62) | CI: lint, images, 30+ conformance/e2e workflows |
| `.github/actions/**` | 8220 (127) | Reusable matrices (`e2e/*.yaml`, `ginkgo/*.yaml`, `gke|eks|azure|aws-cni/k8s-versions.yaml`), cli-test-config, ipsec-key-rotate, bpftrace leak check, LVH kind |
| `Documentation/operations/system_requirements.rst` | 541 | Kernel/CONFIG/mount/port/privilege requirements |
| `Documentation/operations/upgrade.rst` | 692 | Preflight, helm upgrade, rollback, identity migration, CNP validation |
| `Documentation/contributing/testing/*.rst` | 2215 (7) | bpf, ci, e2e, e2e_legacy, unit, scalability |
| `contrib/scripts/*` | 3016 (39) | `kind.sh`, `print-downgrade-version.sh`, `verifier_diff.py`, `check-*` lint scripts, `bugtool-multinode-gather.sh` |
| `contrib/{systemd,k8s,testing,coccinelle}` | 1315 (30) | `cilium.service`, `sys-fs-bpf.mount`, kind cluster configs, coccinelle BPF semantic patches |

## Features

### F1. Helm values tree (top level, defaults, meaning)

174 top-level keys. Format: `key = default :: meaning`. Sections asked for in depth
follow in F2.

- `agent = true` :: render the agent DaemonSet (set false with `preflight.enabled=true` for preflight-only)
- `agentNotReadyTaintKey = "node.cilium.io/agent-not-ready"` :: taint the operator removes when the agent is ready
- `affinity = {podAntiAffinity: required k8s-app=cilium}` :: one agent per node
- `aksbyocni.enabled = false`, `azure.enabled = false`, `azure.nodeSpec.azureInterfaceName = ""`, `alibabacloud.{enabled,nodeSpec.vSwitches,vSwitchTags,securityGroups,securityGroupTags}`, `eni.*` (12 keys: awsEnablePrefixDelegation, awsReleaseExcessIPs, ec2APIEndpoint, eniTags, gcInterval, gcTags, iamRole, instanceTagsFilter, nodeSpec{firstInterfaceIndex, subnetIDs, subnetTags, securityGroups, securityGroupTags, excludeInterfaceTags, usePrimaryAddress, disablePrefixDelegation, deleteOnTermination}, subnetIDsFilter, subnetTagsFilter), `gke.enabled = false` :: cloud IPAM integrations; each forces `ipam` mode, `enable-endpoint-routes=true`, `auto-create-cilium-node-resource=true`
- `annotateK8sNode = false` :: write `io.cilium.network.*` annotations on the Node
- `annotations = {}`, `podAnnotations = {}`, `podLabels = {}`, `commonLabels = {}`, `name = cilium`, `namespaceOverride = ""`
- `apiRateLimit = null` :: override agent API rate-limit table (`api-rate-limit`)
- `authentication.enabled = false`, `.queueSize = 1024`, `.rotatedIdentitiesQueueSize = 1024`, `.gcInterval = 5m0s`, `.mutual.port = 4250`, `.mutual.connectTimeout = 5s`, `.mutual.spire.{enabled=false, install.*, serverAddress, trustDomain=spiffe.cilium, adminSocketPath=/run/spire/sockets/admin.sock, agentSocketPath=/run/spire/sockets/agent/agent.sock, connectionTimeout=30s}` :: mutual auth (mesh-auth-*) with SPIRE (beta)
- `autoDirectNodeRoutes = false` :: install PodCIDR routes to peer nodes on a shared L2
- `bandwidthManager.{enabled=false, bbr=false, bbrHostNamespaceOnly=false}` :: EDT rate limiting via `kubernetes.io/egress-bandwidth`
- `bgpControlPlane` (F2), `bpf` (F2), `cgroup` (F2), `cni` (F2), `daemon` (F2)
- `bpfClockProbe = false` :: probe for `jiffies` clock source
- `certgen.*` (14) :: image `quay.io/cilium/certgen:v0.4.9`, CronJob for hubble/clustermesh certs when `tls.auto.method=cronJob`
- `ciliumEndpointSlice.{enabled=false, rateLimits=[{nodes:0,limit:10,burst:20},{nodes:100,limit:50,burst:100}]}`
- `cleanBpfState = false`, `cleanState = false` :: make `clean-cilium-state` init container wipe `/sys/fs/bpf` (and all state)
- `cluster.{name=default, id=0}` :: ClusterMesh identity (name ≤32 chars, id 1–255/511)
- `clustermesh.*` (F2)
- `configDriftDetection.{enabled=true, driftChecker=true, ignoredKeys=[]}` :: watch `cilium-config`, expose `cilium_drift_checker_config_delta`
- `connectivityProbeFrequencyRatio = null` :: health probe frequency vs. load [0,1]
- `conntrackGCInterval = ""` (0s=auto), `conntrackGCMaxInterval = ""`
- `crdWaitTimeout = ""` (5m) :: exit if CRDs absent
- `dashboards.*` :: Grafana dashboard ConfigMaps
- `datapathPlugins.{enabled=false, stateDir=/var/run/cilium/plugins}` :: custom BPF injection (CiliumDatapathPlugin)
- `debug.{enabled=false, verbose=null (flow|kvstore|envoy|datapath|policy|tagged), metricsSamplingInterval=5m}`
- `defaultLBServiceIPAM = lbipam` (lbipam|nodeipam|none), `enableLBIPAM = true`, `nodeIPAM.enabled = false`
- `devices = ""` :: native devices for NodePort/masquerade/host-fw (auto-detect if empty); `forceDeviceDetection = false`
- `directRoutingSkipUnreachable = false`
- `disableEndpointCRD = false`
- `dnsPolicy = ""`
- `dnsProxy.*` (11): `dnsRejectResponseCode=refused`, `enableDnsCompression=true`, `endpointMaxIpPerHostname=1000`, `idleConnectionGracePeriod=0s`, `maxDeferredConnectionDeletes=10000`, `minTtl=0`, `preAllocateIdentities=true`, `preCache=""` (deprecated), `proxyPort=0`, `proxyResponseMaxDelay=100ms`, `socketLingerTimeout=10`
- `egressGateway.{enabled=false, reconciliationTriggerInterval=1s}` (+ optional `maxPolicyEntries`)
- `enableCriticalPriorityClass = true` :: use `system-node-critical`/`system-cluster-critical`
- `enableIPv4BIGTCP = false`, `enableIPv6BIGTCP = false`
- `enableIPv4Masquerade = null` (true unless ENI), `enableIPv6Masquerade = true`, `enableMasqueradeRouteSource = false`
- `enableInternalTrafficPolicy = true`, `enableNoServiceEndpointsRoutable = true`, `enableNonDefaultDenyPolicies = true`, `enableXTSocketFallback = true`
- `encryption.*` (F2)
- `endpointHealthChecking.enabled = true` :: `lxc_health` endpoint per node
- `endpointLockdownOnMapOverflow = false`
- `endpointPolicyUpdateTimeoutDuration = ""` (10s)
- `endpointRoutes.enabled = false` :: per-endpoint routes instead of `cilium_host`
- `envoy.*` (F2), `envoyConfig.{enabled=false, retryInterval=15s, secretsNamespace{create,name=cilium-secrets}}`
- `etcd.{enabled=false, endpoints=[https://CHANGE-ME:2379], ssl=false}` :: kvstore mode
- `extraArgs = []`, `extraConfig = {}` (free-form additional `cilium-config` keys), `extraContainers`, `extraEnv`, `extraHostPathMounts`, `extraInitContainers`, `extraVolumeMounts`, `extraVolumes`
- `gatewayAPI.*`, `ingressController.*`, `l2announcements`, `l2podAnnouncements`, `loadBalancer`, `nodePort`, `hostFirewall`, `socketLB`, `kubeProxyReplacement` (F2)
- `healthCheckICMPFailureThreshold = 3`, `healthChecking = true`, `healthPort = 9879`
- `hubble.*` (F2)
- `identityAllocationMode = crd` (crd|kvstore|doublewrite-readkvstore|doublewrite-readcrd), `identityChangeGracePeriod = ""` (5s), `identityManagementMode = agent` (agent|operator|both)
- `image.{override, repository=quay.io/cilium/cilium, tag=v1.20.1, pullPolicy=IfNotPresent, digest="", useDigest=false}`, `imagePullSecrets = []`
- `initResources = {}`, `resources = {}`
- `installNoConntrackIptablesRules = false`, `iptablesRandomFully = false`
- `ipMasqAgent.enabled = false` :: eBPF ip-masq-agent with `/etc/config/ip-masq-agent` ConfigMap
- `ipam.*` (F2), `ipv4.enabled = true`, `ipv6.enabled = false`, `ipv4NativeRoutingCIDR = ""`, `ipv6NativeRoutingCIDR = ""`, `nativeRoutingCIDRFromClusterPool = false`
- `k8s.{requireIPv4PodCIDR=false, requireIPv6PodCIDR=false, apiServerURLs=null}`, `k8sServiceHost = ""` ("auto" → cluster-info lookup), `k8sServicePort = ""`, `k8sServiceHostRef.{name,key}`, `k8sServiceLookupConfigMapName`, `k8sServiceLookupNamespace`, `kubeConfigPath = ""`
- `k8sClientRateLimit.{qps(10), burst(20), operator.qps(100), operator.burst(200)}`, `k8sClientExponentialBackoff.{enabled=true, backoffBaseSeconds=1, backoffMaxDurationSeconds=120}`
- `k8sNetworkPolicy.enabled = true`, `k8sClusterNetworkPolicy.enabled = false`
- `keepDeprecatedLabels = false`, `keepDeprecatedProbes = false`
- `l2NeighDiscovery.enabled = false`
- `l7Proxy = true` :: L7 policy support; gates Envoy
- `livenessProbe.{failureThreshold=10, periodSeconds=30, requireK8sConnectivity=false}`, `readinessProbe.{failureThreshold=3, periodSeconds=30}`, `startupProbe.{failureThreshold=300, periodSeconds=2}`
- `localRedirectPolicy = false` (deprecated), `localRedirectPolicies.{enabled=false, addressMatcherCIDRs=null}`
- `logSystemLoad = false`
- `maglev = {}` (`tableSize`, `hashSeed`)
- `minReadySeconds = 0`, `updateStrategy = {RollingUpdate, maxUnavailable: 2}`, `rollOutCiliumPods = false`, `terminationGracePeriodSeconds = 1`
- `monitor.enabled = false` :: `cilium-monitor` sidecar container
- `MTU = 0` :: override auto-detected MTU for cilium_host/vxlan/lxc devices
- `nat.{mapStatsEntries=32, mapStatsInterval=30s}`
- `nat46x64Gateway.enabled = false`
- `nodeinit.*` (F5), `preflight.*` (F5)
- `nodeSelector = {kubernetes.io/os: linux}`, `tolerations = [{operator: Exists}]`, `priorityClassName = ""`, `scheduling.mode = anti-affinity` (anti-affinity|kube-scheduler)
- `nodeSelectorLabels = false` :: node-label based identity
- `operator.*` (F2)
- `pmtuDiscovery.{enabled=false, packetizationLayerPMTUDMode=blackhole}`
- `podSecurityContext.{appArmorProfile.type=Unconfined, seccompProfile.type=Unconfined}`
- `policyCIDRMatchMode = null` (`nodes`), `policyDenyResponse = none` (none|icmp), `policyEnforcementMode = default` (default|always|never)
- `pprof.{enabled=false, address=localhost, port=6060, mutexProfileFraction=0, blockProfileRate=0}`
- `preferIpv6 = false`
- `prometheus.{enabled=false, port=9962, metricsService=false, metrics=null, controllerGroupMetrics=[...], serviceMonitor.*}`
- `rbac.create = true`
- `resourceQuotas.{enabled=false, cilium.hard.pods=10k, operator.hard.pods=15}`
- `routingMode = ""` (tunnel), `tunnelProtocol = ""` (vxlan|geneve), `tunnelPort = 0` (8472/6081), `tunnelSourcePortRange = "0-0"`, `underlayProtocol = ""` (ipv4|ipv6|auto)
- `sctp.enabled = false`
- `secretsNamespaceAnnotations = {}`, `secretsNamespaceLabels = {}`
- `securityContext.*` (F3)
- `serviceAccounts.{cilium, operator, envoy, relay, ui, preflight, nodeinit, clustermeshApiserver, clustermeshcertgen, hubblecertgen, corednsMCSAPI, ztunnel}.{create,name,automount,annotations}`
- `serviceNoBackendResponse = reject` (reject|drop)
- `sleepAfterInit = false` :: replace agent command with `sleep` loop (uninstall aid)
- `standaloneDnsProxy.*` (alpha; requires `dnsProxy.proxyPort != 0`)
- `synchronizeK8sNodes = true`
- `sysctlfix.enabled = true` :: run `apply-sysctl-overwrites` init container
- `tls.{secretsBackend (deprecated), readSecretsOnlyFromSecretsNamespace, secretsNamespace{create=true,name=cilium-secrets}, secretSync.enabled, ca{cert,key,certValidityDuration=1095}, caBundle{enabled=false,name=cilium-root-ca.crt,key=ca.crt,useSecret=false}}`
- `tmpVolume = {}` :: override the `/tmp` emptyDir
- `upgradeCompatibility = null` :: e.g. "1.7"…"1.19": pins defaults to the minor that was first installed (F6)
- `vtep.{enabled=false, endpoint, cidr, mask, mac}` :: VXLAN tunnel endpoint integration (beta)
- `waitForKubeProxy = false` :: `wait-for-kube-proxy` init container
- `wellKnownIdentities.enabled = false`

### F2. Deep sections

**`bpf` (32 keys)**: `autoMount.enabled=true` (mount bpffs if absent), `root=/sys/fs/bpf`,
`preallocateMaps=false`, `authMapMax` (524288), `ctAccounting=false`, `ctTcpMax` (524288),
`ctAnyMax` (262144), `datapathMode=veth` (auto|veth|netkit|netkit-l2), `disableExternalIPMitigation=false`,
`distributedLRU.enabled=false` (per-CPU LRU backing), `enableTCX=true`, `events.default.{rateLimit,burstLimit}`,
`events.{drop,policyVerdict,trace}.enabled=true`, `hostLegacyRouting` (null→true in ConfigMap unless set),
`lbAlgorithmAnnotation=false`, `lbExternalClusterIP=false`, `lbMapMax=65536`, `lbModeAnnotation=false`,
`lbSourceRangeAllTypes=false`, `mapDynamicSizeRatio` (0.0025), `masquerade` (null→false), `monitorAggregation=medium`,
`monitorFlags=all`, `monitorInterval=5s`, `monitorTraceIPOption=0`, `natMax` (524288), `neighMax` (524288),
`nodeMapMax`, `policyMapMax=16384`, `policyMapPressureMetricsThreshold` (0.1), `policyStatsMapMax=65536`,
`tproxy` (null→false), `vlanBypass` ([]).

**`ipam`**: `mode=cluster-pool` (cluster-pool|kubernetes|multi-pool|eni|azure|alibabacloud|crd|delegated-plugin),
`ciliumNodeUpdateRate=15s`, `multiPoolPreAllocation=""`, `installUplinkRoutesForDelegatedIPAM=false`,
`operator.{clusterPoolIPv4PodCIDRList=[10.0.0.0/8], clusterPoolIPv4MaskSize=24, clusterPoolIPv6PodCIDRList=[fd00::/104], clusterPoolIPv6MaskSize=120, autoCreateCiliumPodIPPools={}, externalAPILimitBurstSize(20), externalAPILimitQPS(4.0)}`,
`nodeSpec.{ipamMinAllocate, ipamPreAllocate, ipamMaxAllocate, ipamStaticIPTags=[]}`.

**`encryption`**: `enabled=false`, `type=ipsec` (ipsec|wireguard|ztunnel), `nodeEncryption=false` (WireGuard only),
`strictMode.egress.{enabled,cidr,allowRemoteNodeIdentities}`, `strictMode.ingress.enabled`,
`ipsec.{keyFile=keys, mountPath=/etc/ipsec, secretName=cilium-ipsec-keys, interface="", keyWatcher=true, keyRotationDuration=5m}`,
`wireguard.persistentKeepalive=0s`, `ztunnel.{ca.type=internal|spire, image quay.io/cilium/ztunnel:v1.0.0, caAddress=https://localhost:15012, healthPort=15021, resources, updateStrategy, secrets.bootstrapRootCert, ...}`.

**`egressGateway`**: `enabled=false`, `reconciliationTriggerInterval=1s`, (`maxPolicyEntries` → `egress-gateway-policy-map-max`).

**`bgpControlPlane`**: `enabled=false`, `secretsNamespace.{create=false, name=kube-system}`, `statusReport.enabled=true`,
`routerIDAllocation.{mode=default|ip-pool, ipPool=""}`, `legacyOriginAttribute.enabled=false`.

**`clustermesh`**: `useAPIServer=false`, `maxConnectedClusters=255` (255|511), `cacheTTL=0s`,
`enableEndpointSliceSynchronization=false`, `defaultGlobalNamespace=true`, `policyDefaultLocalCluster=true`,
`config.{enabled=false, domain=mesh.cilium.io, clusters=[]}`, `mcsapi.{enabled=false, installCRDs=true, corednsAutoConfigure.*}`,
`apiserver.*` (28 keys): image `quay.io/cilium/clustermesh-apiserver:v1.20.1`, `healthPort=9880`, `etcdQPS=50`,
`etcd.{storageMedium=Disk, init.*, securityContext drop ALL}`, `kvstoremesh.{enabled=true, healthPort=9881, etcdQPS=100, kvstoreMode=internal|external}`,
`service.{type=NodePort, nodePort=32379, externalTrafficPolicy, internalTrafficPolicy, enableSessionAffinity=HAOnly, loadBalancer*}`,
`replicas=1`, `tls.{authMode=migration (legacy|migration|cluster), auto.{enabled=true, method=helm|cronJob|certmanager, certValidityDuration=365, schedule, server.extraDnsNames/IpAddresses}}`,
`metrics.{enabled=true, port=9962, kvstoremesh.port=9964, etcd.{mode=basic, port=9963}}`, `podSecurityContext runAsUser 65532`.

**`gatewayAPI`**: `enabled=false`, `enableProxyProtocol=false`, `useRemoteAddress=true`, `enableAppProtocol=false`,
`enableAlpn=false`, `xffNumTrustedHops=0`, `externalTrafficPolicy=Cluster`, `gatewayClass.create=auto`,
`secretsNamespace.{create=true, name=cilium-secrets, sync=true}`, `hostNetwork.{enabled=false, nodes.matchLabels}`.

**`ingressController`**: `enabled=false`, `default=false`, `loadbalancerMode=dedicated|shared`, `enforceHttps=true`,
`enableProxyProtocol=false`, `useRemoteAddress=true`, `xffNumTrustedHops=0`,
`ingressLBAnnotationPrefixes=[lbipam.cilium.io, nodeipam.cilium.io, service.beta.kubernetes.io, service.kubernetes.io, cloud.google.com]`,
`defaultSecretNamespace/Name`, `secretsNamespace.{create,name,sync}`, `service.{name=cilium-ingress, type=LoadBalancer, insecureNodePort, secureNodePort, loadBalancerClass, loadBalancerIP, allocateLoadBalancerNodePorts, externalTrafficPolicy=Cluster}`,
`hostNetwork.{enabled=false, sharedListenerPort=8080, httpPort=0, httpsPort=0, tlsPassthroughPort=0, nodes.matchLabels}`.

**`l2announcements.enabled=false`** (+ `leaseDuration`, `leaseRenewDeadline`, `leaseRetryPeriod`); **`l2podAnnouncements.{enabled=false, interfacePattern}`**.

**`loadBalancer`**: `acceleration=disabled` (disabled|native|best-effort — XDP), `serviceTopology=false`,
`l7.{backend=disabled|envoy, ports=[], algorithm=round_robin}`, plus optional `mode` (snat|dsr|hybrid), `algorithm` (random|maglev),
`dsrDispatch` (opt|ipip|geneve), `reflectorWaitTime`.

**`nodePort`**: `addresses=null`, `bindProtection=true`, `autoProtectPortRange=true`, `enableHealthCheck=true`,
`enableHealthCheckLoadBalancerIP=false`, `enableDynamicSourceLookup=false` (+ optional `range`, `directRoutingDevice`).

**`hostFirewall.enabled=false`**; **`socketLB.enabled=false`** (+ `hostNamespaceOnly`, `terminatePodConnections`, `tracing`);
**`kubeProxyReplacement="false"`** ("true"|"false"; the template also still accepts legacy "strict"),
`kubeProxyReplacementHealthzBindAddr=""`.

**`routingMode=""`→tunnel / `tunnelProtocol=""`→vxlan / `underlayProtocol`→auto / `autoDirectNodeRoutes=false` / `ipv4.enabled=true` / `ipv6.enabled=false`.**

**`cni`**: `install=true`, `uninstall=false`, `chainingMode=null` (none|aws-cni|flannel|generic-veth|portmap), `chainingTarget`,
`exclusive=true` (rename foreign confs to `*.cilium_bak`), `logFile=/var/run/cilium/cilium-cni.log`, `customConf=false`,
`confPath=/etc/cni/net.d`, `binPath=/opt/cni/bin`, `configMap=""`, `configMapKey=cni-config`,
`confFileMountPath=/tmp/cni-configuration`, `hostConfDirMountPath=/host/etc/cni/net.d`,
`resources={requests 100m/10Mi, limits 1/1Gi}`, `enableRouteMTUForCNIChaining=false`, `iptablesRemoveAWSRules=true`.

**`daemon`**: `runPath=/var/run/cilium`, `configSources=null` ("config-map:cilium-config,cilium-node-config"),
`allowedConfigOverrides`, `blockedConfigOverrides`, `enableSourceIPVerification=true`.

**`cgroup`**: `autoMount.{enabled=true, resources={}}`, `hostRoot=/run/cilium/cgroupv2`.

**`hubble`** (16): `enabled=true`, `hostUsers`, `listenAddress=":4244"`, `socketPath=/var/run/cilium/hubble.sock`,
`preferIpv6=false`, `skipUnknownCGroupIDs` (true), `peerService.{targetPort=4244, clusterDomain=cluster.local}`,
`metrics.{enabled=null (list), enableOpenMetrics=false, port=9965, tls.{enabled, server.{existingSecret, mtls}}, serviceMonitor, dashboards, dynamic.{enabled, config.configMapName=cilium-dynamic-metrics-config}}`,
`networkPolicyCorrelation.enabled=true`, `redact.{enabled=false, http.{urlQuery=false, userInfo=true, headers.allow/deny}}`,
`tls.{enabled=true, auto.{enabled=true, method=helm|cronJob|certmanager, certValidityDuration=365, schedule="0 0 1 */4 *"}, server.{existingSecret, extraDnsNames, extraIpAddresses}}`,
`export.{static.{enabled=false, filePath=/var/run/cilium/hubble/events.log, fieldMask, fieldAggregate, aggregationInterval, allowList, denyList, fileMaxSizeMb=10, fileMaxBackups=5, fileCompress}, dynamic.{enabled=false, config.configMapName=cilium-flowlog-config, content}}`,
`dropEventEmitter.{enabled=false, interval=2m, reasons=[auth_required, policy_denied]}`,
`relay.{enabled=false, replicas=1, listenHost="", listenPort=4245, service.{type=ClusterIP, nodePort=31234}, tls.{client, server.{enabled=false, mtls=false, relayName=ui.hubble-relay.cilium.io}}, retryTimeout, sortBufferLenMax, sortBufferDrainTimeout, prometheus.{enabled=false, port=9966}, gops.{enabled=true, port=9893}, pprof.port=6062, logOptions, image quay.io/cilium/hubble-relay:v1.20.1, ...}`,
`ui.{enabled=false, standalone, replicas=1, backend.image quay.io/cilium/hubble-ui-backend:v0.13.5, frontend.image quay.io/cilium/hubble-ui:v0.13.5, service.{type=ClusterIP, nodePort=31235}, baseUrl=/, ingress.*}`.

**`operator`** (37): `enabled=true`, `replicas=2`, `image.{repository=quay.io/cilium/operator, tag=v1.20.1, suffix="" (-generic|-aws|-azure|-alibabacloud), *Digest}`,
`hostNetwork=true`, `hostUsers=true`, `dnsPolicy`, `updateStrategy={RollingUpdate, maxSurge 25%, maxUnavailable 50%}`,
`affinity (anti-affinity io.cilium/app=operator)`, `topologySpreadConstraints`, `tolerations (4)`,
`podSecurityContext.seccompProfile.type=RuntimeDefault`, `securityContext={drop ALL, allowPrivilegeEscalation false}`,
`endpointGCInterval=5m0s`, `nodeGCInterval=5m0s`, `identityGCInterval=15m0s`, `identityHeartbeatTimeout=30m0s`,
`pprof.port=6061`, `prometheus.{enabled=true, port=9963, tls, serviceMonitor}`, `dashboards`, `skipCRDCreation=false`,
`removeNodeTaints=true`, `setNodeTaints` (null→=removeNodeTaints), `setNodeNetworkStatus=true`,
`unmanagedPodWatcher.{restart=true, intervalSeconds=15, selector (k8s-app=kube-dns)}`, `podDisruptionBudget`, `extraArgs/Env/Volumes/HostPathMounts`.

**`envoy`** (52): `enabled=null` (→true for new installs, i.e. `upgradeCompatibility>=1.16`; false if `l7Proxy=false`),
`xdsMode=null` (→"ads" for `upgradeCompatibility>=1.20`, else "split"), `baseID=0`,
`image quay.io/cilium/cilium-envoy:v1.37.5-...` (digest pinned), `log.{format, format_json, path, defaultLevel, accessLogBufferSize=4096, accessLogEnabled=true}`,
`connectTimeoutSeconds=2`, `initialFetchTimeoutSeconds=30`, `maxConcurrentRetries=128`, `clusterMaxConnections=1024`,
`clusterMaxPendingRequests=1024`, `clusterMaxRequests=1024`, `maxGlobalDownstreamConnections=50000`, `httpRetryCount=3`,
`maxRequestsPerConnection=0`, `maxConnectionDurationSeconds=0`, `idleTimeoutDurationSeconds=60`, `streamIdleTimeoutDurationSeconds=300`,
`xffNumTrustedHopsL7PolicyIngress/Egress=0`, `useOriginalSourceAddress=true`, `policyRestoreTimeoutDuration` (3m), `httpUpstreamLingerTimeout`,
`healthPort=9878`, `terminationGracePeriodSeconds=1`, `bootstrapConfigMap`, `nodeLocality.enabled=false`,
`securityContext.{privileged=false, seLinuxOptions spc_t, capabilities.envoy=[NET_ADMIN, SYS_ADMIN], capabilities.keepCapNetBindService=false}`,
`podSecurityContext.appArmorProfile.type=Unconfined`, probes (startup 105×2s, liveness 10×30s, readiness 3×30s),
`debug.admin.{enabled=false, port=9901}`, `prometheus.{enabled=true, port=9964, serviceMonitor}`, `rollOutPods`, `extra*`.

### F3. Agent DaemonSet: containers, init containers, capabilities, mounts

Pod: `hostNetwork: true`, `hostUsers: true` (k8s ≥1.33), `priorityClassName: system-node-critical`,
`serviceAccountName: cilium`, `terminationGracePeriodSeconds: 1`, pod securityContext AppArmor+seccomp
`Unconfined`, `hostAliases` for ClusterMesh when `clustermesh.config.enabled` without kvstoremesh.

Main container `cilium-agent`: `command: cilium-agent --config-dir=/tmp/cilium/config-map`;
probes hit `http://127.0.0.1:9879/healthz` (startup 300×2s, liveness 10×30s, readiness 3×30s);
lifecycle `postStart` runs `files/agent/poststart-eni.bash` (removes AWS VPC-CNI iptables rules unless chaining to aws-cni),
`preStop` runs `/cni-uninstall.sh`. hostPorts: `healthPort` 9879, hubble peer 4244, prometheus 9962, envoy-metrics 9964
and envoy-admin 9901 (embedded Envoy only), hubble-metrics 9965. Env: `K8S_NODE_NAME`, `CILIUM_K8S_NAMESPACE`,
`CILIUM_CLUSTERMESH_CONFIG=/var/lib/cilium/clustermesh/`, `GOMEMLIMIT` (from resources.limits.memory),
`KUBERNETES_SERVICE_HOST/PORT`, `KUBE_CLIENT_BACKOFF_BASE/DURATION`.

Capabilities (non-privileged default; `securityContext.privileged=true` replaces all of this with `privileged: true`):

| Container | `capabilities.add` (drop ALL) | Why (from values.yaml comments) |
|---|---|---|
| `cilium-agent` | CHOWN, KILL, NET_ADMIN, NET_RAW, IPC_LOCK, SYS_MODULE, SYS_ADMIN, SYS_RESOURCE, DAC_OVERRIDE, FOWNER, SETGID, SETUID, SYSLOG | socket perms; kill envoy child; routes/links; raw sockets; mmap ring; iptables module loading; BPF + netns switching (SYS_ADMIN; PERFMON/BPF would suffice on ≥5.8 but are commented out); RLIMIT; package-install leftovers (DAC_OVERRIDE/FOWNER/SETGID/SETUID); dmesg/kptr |
| init `config` | NET_ADMIN | runs `cilium-dbg build-config` |
| init `mount-cgroup` | SYS_ADMIN, SYS_CHROOT, SYS_PTRACE | mount cgroup2 in host mount ns via nsenter |
| init `apply-sysctl-overwrites` | SYS_ADMIN, SYS_CHROOT, SYS_PTRACE | write `/etc/sysctl.d` on host via nsenter |
| init `mount-bpf-fs` | **privileged: true** (always) | Bidirectional mount propagation needs privileged |
| init `wait-for-node-init` | none | busy-wait on bootstrap file |
| init `clean-cilium-state` | NET_ADMIN, SYS_MODULE, SYS_ADMIN, SYS_RESOURCE | `cilium-dbg post-uninstall-cleanup` |
| init `wait-for-kube-proxy` | **privileged: true** | runs `iptables-*-save` |
| init `install-cni-binaries` | drop ALL only | copies `cilium-cni` + `loopback` |
| `cilium-envoy` (separate DS) | NET_ADMIN, SYS_ADMIN (starter drops all after fork; optional NET_BIND_SERVICE) | IP_TRANSPARENT sockets; nsenter |
| `cilium-envoy` init `envoy-bootstrap-locality` | drop ALL, runAsUser 0 | writes service-zone file |
| `nodeinit` | SYS_MODULE, NET_ADMIN, SYS_ADMIN, SYS_CHROOT, SYS_PTRACE; `hostPID: true` | nsenter into PID 1 to run bash on host |
| `cilium-operator`, `hubble-relay`, `hubble-ui`, `clustermesh-apiserver` (all containers), `preflight` | drop ALL, no adds; relay/ui/apiserver run as 65532 | |
| `ztunnel` | privileged false, runAsUser 0 | |

Init containers, in order, and what each does:

1. `config` (if `daemon.configSources` unset or starts with `config-map:`): `cilium-dbg build-config
   [--source=… --allow-config-keys=… --deny-config-keys=… --k8s-kubeconfig-path=… --k8s-api-server-urls=…]`
   merges `cilium-config` ConfigMap + `CiliumNodeConfig` CRs into files under `/tmp/cilium/config-map`
   (emptyDir shared with the agent). Otherwise the ConfigMap is mounted directly.
2. `mount-cgroup` (`cgroup.autoMount.enabled`): `cp /usr/bin/cilium-mount /hostbin/cilium-mount; nsenter
   --cgroup=/hostproc/1/ns/cgroup --mount=/hostproc/1/ns/mnt ${BIN_PATH}/cilium-mount $CGROUP_ROOT; rm …`.
   `cilium-mount` = `pkg/cgroups.CheckOrMountCgrpFS` (mount cgroup2 at `/run/cilium/cgroupv2` in the host ns).
   Mounts: `/proc`→`/hostproc`, `cni.binPath`→`/hostbin`.
3. `apply-sysctl-overwrites` (`sysctlfix.enabled`): same trick with `cilium-sysctlfix`, which writes
   `/etc/sysctl.d/99-zzz-override_cilium.conf` (`-net.ipv4.conf.lxc*.rp_filter=0`, `-net.ipv4.conf.cilium_*.rp_filter=0`,
   `net.ipv4.conf.all.rp_filter=0`) and restarts `systemd-sysctl.service` over D-Bus.
4. `mount-bpf-fs` (`bpf.autoMount.enabled` and not privileged): `mount | grep "/sys/fs/bpf type bpf" || mount -t bpf bpf /sys/fs/bpf`
   with `/sys/fs/bpf` mounted `Bidirectional`.
5. `wait-for-node-init` (`nodeinit.enabled` + `bootstrapFile`): `until test -s /tmp/cilium-bootstrap.d/cilium-bootstrap-time; do sleep 1; done`.
6. `clean-cilium-state` (always): `/init-container.sh` → `cilium-dbg post-uninstall-cleanup -f --bpf-state` if
   `clean-cilium-bpf-state=true`, `--all-state` if `clean-cilium-state=true` (env from ConfigMap keys, optional).
   Mounts `/sys/fs/bpf`, cgroup root (HostToContainer), `/var/run/cilium`.
7. `wait-for-kube-proxy` (`waitForKubeProxy` and KPR not true): loop over `iptables-nft-save -t mangle`,
   `ip6tables-nft-save`, `iptables-legacy-save`, `ip6tables-legacy-save` until `KUBE-IPTABLES-HINT|KUBE-PROXY-CANARY` chain exists.
8. `install-cni-binaries` (`cni.install`): `/install-plugin.sh` copies `/cni/loopback` (if absent) and
   `/opt/cni/bin/cilium-cni` atomically into `/host/opt/cni/bin`.
9. `extraInitContainers`.

hostPath volumes on the agent pod (complete list):

| Volume | hostPath | type | Mounted at | Notes |
|---|---|---|---|---|
| `cilium-run` | `daemon.runPath` = `/var/run/cilium` | DirectoryOrCreate | `/var/run/cilium` | state dir, API socket, hubble socket, envoy sockets |
| `cilium-netns` | `/var/run/netns` | DirectoryOrCreate | `/var/run/cilium/netns` (HostToContainer) | enter pod netns |
| `bpf-maps` | `/sys/fs/bpf` | DirectoryOrCreate | `/sys/fs/bpf` (Bidirectional on agent + mount-bpf-fs) | pinned maps/progs |
| `hostproc` | `/proc` | Directory | `/hostproc` (init containers only) | nsenter targets |
| `cilium-cgroup` | `cgroup.hostRoot` = `/run/cilium/cgroupv2` | DirectoryOrCreate | same path (HostToContainer) | cgroup/sockops attach |
| `cni-path` | `cni.binPath` = `/opt/cni/bin` | DirectoryOrCreate | `/host/opt/cni/bin` (install init), `/hostbin` (mount/sysctl inits) | |
| `etc-cni-netd` | `cni.confPath` = `/etc/cni/net.d` | DirectoryOrCreate | `/host/etc/cni/net.d` | agent writes `05-cilium.conflist` |
| `lib-modules` | `/lib/modules` | — | `/lib/modules` (ro) | iptables/xt module autoload |
| `xtables-lock` | `/run/xtables.lock` | FileOrCreate | `/run/xtables.lock` | iptables lock shared with kube-proxy |
| `host-proc-sys-net` | `/proc/sys/net` | Directory | `/host/proc/sys/net` | sysctl writes (`procfs=/host/proc`) |
| `host-proc-sys-kernel` | `/proc/sys/kernel` | Directory | `/host/proc/sys/kernel` | |
| `spire-agent-socket` | `dir(authentication.mutual.spire.adminSocketPath)` | DirectoryOrCreate | same | if SPIRE |
| `envoy-sockets` | `/var/run/cilium/envoy/sockets` | DirectoryOrCreate | same | if Envoy DaemonSet |
| `kube-config` | `kubeConfigPath` | FileOrCreate | same (ro) | optional |
| `cilium-bootstrap-file-dir` | `dir(nodeinit.bootstrapFile)` = `/tmp/cilium-bootstrap.d` | DirectoryOrCreate | same | if nodeinit |
| `extraHostPathMounts[]` | user | user | user | |

Non-hostPath mounts: `tmp` emptyDir (`/tmp`), `cilium-config-path` ConfigMap (`/tmp/cilium/config-map`, when no
`config` init), `etcd-config-path`/`etcd-secrets`, `clustermesh-secrets` (projected: `cilium-clustermesh`,
`clustermesh-apiserver-remote-cert`, `clustermesh-apiserver-local-cert`, CA), `ip-masq-agent` ConfigMap
(`/etc/config`), `cni-configuration` ConfigMap, `cilium-ipsec-secrets` (`/etc/ipsec`), `cilium-ztunnel-secrets`
(`/etc/ztunnel`), `hubble-tls` (`/var/lib/cilium/tls/hubble`), `hubble-metrics-tls`, `hubble-dynamic-metrics-config`
(`/dynamic-metrics-config`), `hubble-flowlog-config` (`/flowlog-config`).

Optional sidecar `cilium-monitor` (`monitor.enabled`): `/bin/bash -c "cilium-dbg monitor"` sharing `/var/run/cilium`.

### F4. ConfigMap `cilium-config`: values → keys

`templates/cilium-configmap.yaml` (1591 lines) emits **426 distinct keys**. Keys are the agent/operator
flag names with `-` (viper). The table lists the mapping (defaults resolved). Cloud-specific keys
(eni-*, azure-*, alibabacloud-*, 25 keys) are omitted; they mirror `eni.*`/`azure.*`/`alibabacloud.*` 1:1.

| config key | Helm value(s) | condition / default |
|---|---|---|
| `kvstore`, `kvstore-opt`, `etcd-config` | `etcd.enabled`, `etcd.endpoints`, `etcd.ssl` | etcd mode only; `{"etcd.config":"/var/lib/etcd-config/etcd.config"}` |
| `identity-allocation-mode` | `identityAllocationMode` | |
| `identity-heartbeat-timeout`, `identity-gc-interval`, `cilium-endpoint-gc-interval`, `nodes-gc-interval` | `operator.identityHeartbeatTimeout/identityGCInterval/endpointGCInterval/nodeGCInterval` | |
| `disable-endpoint-crd` | `disableEndpointCRD` | |
| `identity-change-grace-period` | `identityChangeGracePeriod` | |
| `debug`, `debug-verbose`, `metrics-sampling-interval` | `debug.enabled/verbose/metricsSamplingInterval` | |
| `agent-health-port`, `cluster-health-port` | `healthPort`, `clusterHealthPort` | |
| `enable-policy`, `policy-cidr-match-mode`, `policy-audit-mode` | `policyEnforcementMode`, `policyCIDRMatchMode`, `policyAuditMode` | |
| `prometheus-serve-addr`, `metrics`, `controller-group-metrics`, `enable-metrics` | `prometheus.port/metrics/controllerGroupMetrics` | `:9962` |
| `proxy-prometheus-port`, `proxy-admin-port` | `envoy.prometheus.port`, `envoy.debug.admin.port` | |
| `operator-prometheus-serve-addr`, `operator-prometheus-enable-tls`, `operator-prometheus-tls-*` | `operator.prometheus.*` | |
| `skip-crd-creation` | `operator.skipCRDCreation` | |
| `enable-envoy-config`, `envoy-config-retry-interval`, `envoy-secrets-namespace` | `envoyConfig.*` (auto-true for ingress/gateway) | |
| `enable-ingress-controller`, `enforce-ingress-https`, `enable-ingress-proxy-protocol`, `enable-ingress-secrets-sync`, `ingress-secrets-namespace`, `ingress-lb-annotation-prefixes`, `ingress-default-lb-mode`, `ingress-shared-lb-service-name`, `ingress-default-xff-num-trusted-hops`, `ingress-use-remote-address`, `ingress-default-secret-namespace/name`, `ingress-hostnetwork-*` (5), `ingress-hostnetwork-nodelabelselector` | `ingressController.*` | |
| `enable-gateway-api`, `enable-gateway-api-secrets-sync`, `enable-gateway-api-proxy-protocol`, `enable-gateway-api-app-protocol`, `enable-gateway-api-alpn`, `gateway-api-xff-num-trusted-hops`, `gateway-api-use-remote-address`, `gateway-api-service-externaltrafficpolicy`, `gateway-api-secrets-namespace`, `gateway-api-hostnetwork-enabled`, `gateway-api-hostnetwork-nodelabelselector` | `gatewayAPI.*` | |
| `enable-policy-secrets-sync`, `policy-secrets-only-from-secrets-namespace`, `policy-secrets-namespace` | `tls.secretSync.enabled`, `tls.readSecretsOnlyFromSecretsNamespace`, `tls.secretsNamespace.name` | |
| `loadbalancer-l7`, `loadbalancer-l7-ports`, `loadbalancer-l7-algorithm` | `loadBalancer.l7.*` | `envoy` |
| `enable-ipv4`, `enable-ipv6`, `prefer-ipv6` | `ipv4.enabled`, `ipv6.enabled`, `preferIpv6` | |
| `clean-cilium-state`, `clean-cilium-bpf-state` | `cleanState`, `cleanBpfState` | |
| `custom-cni-conf`, `read-cni-conf`, `write-cni-conf-when-ready`, `cni-exclusive`, `cni-log-file`, `cni-uninstall`, `cni-chaining-mode`, `cni-chaining-target`, `cni-external-routing`, `enable-route-mtu-for-cni-chaining` | `cni.*` | `write-cni-conf-when-ready=/host/etc/cni/net.d/05-cilium.conflist` |
| `enable-bpf-clock-probe` | `bpfClockProbe` | |
| `enable-bpf-tproxy` | `bpf.tproxy` | default false |
| `monitor-aggregation`, `monitor-aggregation-interval`, `monitor-aggregation-flags` | `bpf.monitorAggregation/Interval/Flags` | |
| `bpf-events-default-rate-limit`, `bpf-events-default-burst-limit`, `bpf-events-{drop,policy-verdict,trace}-enabled` | `bpf.events.*` | |
| `bpf-map-dynamic-size-ratio` | `bpf.mapDynamicSizeRatio` | 0.0025 |
| `enable-host-legacy-routing` | `bpf.hostLegacyRouting` | default "true" |
| `bpf-node-map-max`, `bpf-auth-map-max`, `bpf-ct-global-tcp-max`, `bpf-ct-global-any-max`, `bpf-conntrack-accounting`, `bpf-nat-global-max`, `bpf-neigh-global-max`, `bpf-policy-map-max`, `bpf-policy-map-pressure-metrics-threshold`, `bpf-policy-stats-map-max`, `bpf-lb-map-max` | `bpf.nodeMapMax/authMapMax/ctTcpMax/ctAnyMax/ctAccounting/natMax/neighMax/policyMapMax/policyMapPressureMetricsThreshold/policyStatsMapMax/lbMapMax` | ct maxes default 0 (auto) |
| `endpoint-policy-update-timeout` | `endpointPolicyUpdateTimeoutDuration` | |
| `bpf-lb-external-clusterip`, `bpf-lb-source-range-all-types`, `bpf-lb-algorithm-annotation`, `bpf-lb-mode-annotation`, `bpf-distributed-lru`, `preallocate-bpf-maps` | `bpf.lbExternalClusterIP/lbSourceRangeAllTypes/lbAlgorithmAnnotation/lbModeAnnotation/distributedLRU.enabled/preallocateMaps` | algorithm-annotation forced true with Gateway API |
| `cluster-name`, `cluster-id` | `cluster.name`, `cluster.id` | |
| `routing-mode`, `tunnel-protocol`, `tunnel-port`, `tunnel-source-port-range`, `underlay-protocol` | `routingMode` (native if eni/gke), `tunnelProtocol` (vxlan), `tunnelPort`, `tunnelSourcePortRange`, `underlayProtocol` | |
| `service-no-backend-response`, `policy-deny-response`, `mtu` | `serviceNoBackendResponse`, `policyDenyResponse`, `MTU` | |
| `enable-endpoint-routes`, `auto-create-cilium-node-resource` | `endpointRoutes.enabled`; forced true by eni/gke/azure/alibabacloud | |
| `enable-l7-proxy` | `l7Proxy` | |
| `enable-standalone-dns-proxy`, `standalone-dns-proxy-server-port` | `standaloneDnsProxy.*` | |
| `enable-identity-mark`, `enable-local-node-route` | `enableIdentityMark`; false for chaining | |
| `enable-ipv4-masquerade`, `enable-ipv6-masquerade`, `enable-ipv4-big-tcp`, `enable-ipv6-big-tcp`, `enable-masquerade-to-route-source`, `egress-masquerade-interfaces` | `enableIPv4Masquerade` (true unless ENI), `enableIPv6Masquerade`, `enableIPv4BIGTCP`, `enableIPv6BIGTCP`, `enableMasqueradeRouteSource`, `egressMasqueradeInterfaces` | |
| `enable-tcx`, `datapath-mode`, `enable-bpf-masquerade` | `bpf.enableTCX`, `bpf.datapathMode`, `bpf.masquerade` (false) | |
| `enable-ip-masq-agent` | `ipMasqAgent.enabled` | plus `ip-masq-agent` ConfigMap |
| `enable-ipsec`, `ipsec-key-file`, `enable-ipsec-key-watcher`, `ipsec-key-rotation-duration` | `encryption.enabled && type=ipsec`, `encryption.ipsec.*` | `/etc/ipsec/keys` |
| `enable-wireguard`, `wireguard-persistent-keepalive`, `encrypt-node` | `encryption.enabled && type=wireguard`, `encryption.wireguard.persistentKeepalive`, `encryption.nodeEncryption` | |
| `enable-ztunnel`, `ztunnel-ca-type` | `encryption.type=ztunnel`, `encryption.ztunnel.ca.type` | |
| `enable-encryption-strict-mode-ingress/egress`, `encryption-strict-egress-cidr`, `encryption-strict-egress-allow-remote-node-identities` | `encryption.strictMode.*` | |
| `enable-xt-socket-fallback`, `install-no-conntrack-iptables-rules`, `iptables-random-fully`, `iptables-lock-timeout`, `disable-iptables-feeder-rules` | `enableXTSocketFallback`, `installNoConntrackIptablesRules`, `iptablesRandomFully`, `iptablesLockTimeout`, `disableIptablesFeederRules` | |
| `auto-direct-node-routes`, `direct-routing-skip-unreachable` | `autoDirectNodeRoutes`, `directRoutingSkipUnreachable` | |
| `enable-bandwidth-manager`, `enable-bbr`, `enable-bbr-hostns-only` | `bandwidthManager.*` | |
| `enable-local-redirect-policy`, `lrp-address-matcher-cidrs` | `localRedirectPolicies.*` | |
| `ipv4-native-routing-cidr`, `ipv6-native-routing-cidr` | `ipv4NativeRoutingCIDR`/`ipv6NativeRoutingCIDR` or first cluster-pool CIDR when `nativeRoutingCIDRFromClusterPool` | |
| `enable-ipv4-fragment-tracking` | `fragmentTracking` | |
| `enable-nat46x64-gateway`, `enable-host-firewall` | `nat46x64Gateway.enabled`, `hostFirewall.enabled` | |
| `devices`, `force-device-detection` | `devices`, `forceDeviceDetection` | |
| `kube-proxy-replacement`, `kube-proxy-replacement-healthz-bind-address` | `kubeProxyReplacement`, `kubeProxyReplacementHealthzBindAddr` | default "false" (upgradeCompatibility ≥1.14) |
| `enable-no-service-endpoints-routable` | `enableNoServiceEndpointsRoutable` | |
| `bpf-lb-sock`, `bpf-lb-sock-hostns-only`, `bpf-lb-sock-terminate-pod-connections`, `trace-sock` | `socketLB.enabled/hostNamespaceOnly/terminatePodConnections/tracing` | hostns-only forced true with Gateway API |
| `node-port-range`, `nodeport-addresses`, `direct-routing-device`, `enable-health-check-nodeport`, `enable-dynamic-source-lookup-nodeport`, `enable-health-check-loadbalancer-ip`, `node-port-bind-protection`, `enable-auto-protect-node-port-range` | `nodePort.*` | |
| `bpf-lb-mode`, `bpf-lb-algorithm`, `bpf-lb-acceleration`, `bpf-lb-dsr-dispatch`, `enable-service-topology`, `lb-reflector-wait-time` | `loadBalancer.mode/algorithm/acceleration/dsrDispatch/serviceTopology/reflectorWaitTime` | |
| `bpf-lb-maglev-table-size`, `bpf-lb-maglev-hash-seed` | `maglev.tableSize/hashSeed` | |
| `ip-tracing-option-type`, `enable-l2-neigh-discovery` | `bpf.monitorTraceIPOption`, `l2NeighDiscovery.enabled` | |
| `pprof`, `pprof-address`, `pprof-port`, `pprof-mutex-profile-fraction`, `pprof-block-profile-rate`, `operator-pprof*` | `pprof.*`, `operator.pprof.*` | |
| `log-system-load`, `log-opt` | `logSystemLoad`, `logOptions` | |
| `k8s-require-ipv4-pod-cidr`, `k8s-require-ipv6-pod-cidr`, `k8s-api-server-urls`, `k8s-kubeconfig-path`, `k8s-service-proxy-name`, `k8s-client-qps`, `k8s-client-burst`, `operator-k8s-client-qps/burst` | `k8s.*`, `kubeConfigPath`, `k8sClientRateLimit.*` | |
| `install-uplink-routes-for-delegated-ipam` | `ipam.installUplinkRoutesForDelegatedIPAM` | |
| `enable-k8s-networkpolicy`, `enable-k8s-cluster-network-policy`, `enable-endpoint-lockdown-on-policy-overflow` | `k8sNetworkPolicy.enabled`, `k8sClusterNetworkPolicy.enabled`, `endpointLockdownOnMapOverflow` | |
| `enable-endpoint-health-checking`, `enable-health-checking`, `health-check-icmp-failure-threshold` | `endpointHealthChecking.enabled`, `healthChecking`, `healthCheckICMPFailureThreshold` | |
| `enable-well-known-identities`, `enable-node-selector-labels`, `node-labels`, `synchronize-k8s-nodes` | `wellKnownIdentities.enabled`, `nodeSelectorLabels`, `nodeLabels`, `synchronizeK8sNodes` | |
| `operator-api-serve-addr` | — | `127.0.0.1:9234` / `[::1]:9234` |
| `enable-hubble`, `hubble-socket-path`, `hubble-event-queue-size`, `hubble-event-buffer-capacity`, `hubble-lost-event-send-interval`, `hubble-listen-address`, `hubble-disable-tls`, `hubble-tls-cert-file`, `hubble-tls-key-file`, `hubble-tls-client-ca-files`, `hubble-prefer-ipv6`, `hubble-skip-unknown-cgroup-ids`, `hubble-network-policy-correlation-enabled` | `hubble.*` | TLS files under `/var/lib/cilium/tls/hubble/` |
| `hubble-metrics-server`, `hubble-metrics-server-enable-tls`, `hubble-metrics-server-tls-*`, `enable-hubble-open-metrics`, `hubble-metrics`, `hubble-dynamic-metrics-config-path` | `hubble.metrics.*` | `:9965`; `/dynamic-metrics-config/dynamic-metrics.yaml` |
| `hubble-redact-enabled`, `hubble-redact-http-urlquery`, `hubble-redact-http-userinfo`, `hubble-redact-http-headers-allow/deny` | `hubble.redact.*` | |
| `hubble-export-file-max-size-mb`, `hubble-export-file-max-backups`, `hubble-export-file-compress`, `hubble-export-aggregation-interval`, `hubble-export-file-path`, `hubble-export-fieldmask`, `hubble-export-fieldaggregate`, `hubble-export-allowlist`, `hubble-export-denylist`, `hubble-flowlogs-config-path` | `hubble.export.static.*`, `hubble.export.dynamic.*` | `/flowlog-config/flowlogs.yaml` |
| `hubble-drop-events`, `hubble-drop-events-interval`, `hubble-drop-events-reasons` | `hubble.dropEventEmitter.*` | |
| `ipam`, `ipam-min-allocate`, `ipam-pre-allocate`, `ipam-max-allocate`, `ipam-static-ip-tags`, `ipam-multi-pool-pre-allocation`, `ipam-cilium-node-update-rate`, `cluster-pool-ipv4-cidr`, `cluster-pool-ipv4-mask-size`, `cluster-pool-ipv6-cidr`, `cluster-pool-ipv6-mask-size`, `auto-create-cilium-pod-ip-pools`, `limit-ipam-api-burst`, `limit-ipam-api-qps` | `ipam.*` | `aksbyocni` forces cluster-pool |
| `enable-node-ipam`, `default-lb-service-ipam`, `enable-lb-ipam` | `nodeIPAM.enabled`, `defaultLBServiceIPAM`, `enableLBIPAM` | |
| `api-rate-limit` | `apiRateLimit` | |
| `enable-egress-gateway`, `egress-gateway-reconciliation-trigger-interval`, `egress-gateway-policy-map-max` | `egressGateway.*` | |
| `enable-vtep`, `vtep-endpoint`, `vtep-cidr`, `vtep-mask`, `vtep-mac` | `vtep.*` | |
| `crd-wait-timeout` | `crdWaitTimeout` | |
| `enable-l2-announcements`, `l2-announcements-lease-duration`, `l2-announcements-renew-deadline`, `l2-announcements-retry-period`, `enable-l2-pod-announcements`, `l2-pod-announcements-interface-pattern` | `l2announcements.*`, `l2podAnnouncements.*` | |
| `enable-bgp-control-plane`, `bgp-secrets-namespace`, `enable-bgp-control-plane-status-report`, `bgp-router-id-allocation-mode`, `bgp-router-id-allocation-ip-pool`, `enable-bgp-legacy-origin-attribute` | `bgpControlPlane.*` | |
| `enable-pmtu-discovery`, `packetization-layer-pmtud-mode` | `pmtuDiscovery.*` | |
| `procfs`, `bpf-root`, `cgroup-root` | — , `bpf.root`, `cgroup.hostRoot` | `procfs=/host/proc` unless privileged |
| `vlan-bpf-bypass`, `disable-external-ip-mitigation` | `bpf.vlanBypass`, `bpf.disableExternalIPMitigation` | |
| `enable-cilium-endpoint-slice`, `ces-rate-limits`, `identity-management-mode` | `ciliumEndpointSlice.*`, `identityManagementMode` | |
| `enable-sctp`, `dns-policy-unload-on-shutdown`, `annotate-k8s-node` | `sctp.enabled`, `dnsPolicyUnloadOnShutdown`, `annotateK8sNode` | |
| `remove-cilium-node-taints`, `set-cilium-node-taints`, `set-cilium-is-up-condition`, `unmanaged-pod-watcher-interval`, `pod-restart-selector` | `operator.removeNodeTaints/setNodeTaints/setNodeNetworkStatus/unmanagedPodWatcher.*` | |
| `dnsproxy-enable-transparent-mode`, `dnsproxy-socket-linger-timeout`, `tofqdns-dns-reject-response-code`, `tofqdns-enable-dns-compression`, `tofqdns-endpoint-max-ip-per-hostname`, `tofqdns-idle-connection-grace-period`, `tofqdns-max-deferred-connection-deletes`, `tofqdns-min-ttl`, `tofqdns-pre-cache`, `tofqdns-proxy-port`, `tofqdns-proxy-response-max-delay`, `tofqdns-preallocate-identities` | `dnsProxy.*` | transparent mode default true (≥1.12) |
| `agent-not-ready-taint-key` | `agentNotReadyTaintKey` | |
| `mesh-auth-enabled`, `mesh-auth-queue-size`, `mesh-auth-rotated-identities-queue-size`, `mesh-auth-gc-interval`, `mesh-auth-mutual-enabled`, `mesh-auth-mutual-listener-port`, `mesh-auth-spire-agent-socket`, `mesh-auth-mutual-connect-timeout`, `mesh-auth-spire-server-address`, `mesh-auth-spire-server-connection-timeout`, `mesh-auth-spire-admin-socket`, `mesh-auth-spiffe-trust-domain` | `authentication.*` | |
| `proxy-xff-num-trusted-hops-ingress/egress`, `proxy-connect-timeout`, `proxy-initial-fetch-timeout`, `proxy-max-active-downstream-connections`, `proxy-max-requests-per-connection`, `proxy-max-connection-duration-seconds`, `proxy-idle-timeout-seconds`, `proxy-max-concurrent-retries`, `proxy-use-original-source-address`, `proxy-cluster-max-connections/pending-requests/requests`, `http-retry-count`, `http-stream-idle-timeout`, `envoy-node-locality-enabled`, `external-envoy-proxy`, `envoy-base-id`, `envoy-http-upstream-linger-timeout`, `envoy-policy-restore-timeout`, `envoy-log`, `envoy-default-log-level`, `envoy-access-log-enabled`, `envoy-access-log-buffer-size`, `envoy-keep-cap-netbindservice`, `envoy-xds-mode` | `envoy.*` | `external-envoy-proxy` = envoy DaemonSet enabled |
| `max-connected-clusters`, `clustermesh-cache-ttl`, `clustermesh-enable-endpoint-sync`, `clustermesh-enable-mcs-api`, `clustermesh-mcs-api-install-crds`, `clustermesh-default-global-namespace`, `policy-default-local-cluster` | `clustermesh.*` | |
| `nat-map-stats-entries`, `nat-map-stats-interval` | `nat.*` | |
| `enable-non-default-deny-policies`, `enable-source-ip-verification`, `connectivity-probe-frequency-ratio` | `enableNonDefaultDenyPolicies`, `daemon.enableSourceIPVerification`, `connectivityProbeFrequencyRatio` | |
| `enable-dynamic-config`, `enable-drift-checker`, `ignore-flags-drift-checker` | `configDriftDetection.*` | |
| `enable-datapath-plugins`, `datapath-plugins-state-dir` | `datapathPlugins.*` | |
| any | `extraConfig.*` | appended verbatim |

### F5. Other workloads in the chart

- **cilium-operator** Deployment: 2 replicas, `hostNetwork: true`, `cilium-operator-<variant> --config-dir=/tmp/cilium/config-map --debug=$(CILIUM_DEBUG)`, ports 9234 (API, localhost), 9963 metrics, 9891 gops; leader election via Lease; anti-affinity; PDB optional.
- **cilium-envoy** DaemonSet (default on for new installs): `/usr/bin/cilium-envoy-starter [--keep-cap-net-bind-service] -- [--service-zone @/var/run/cilium/envoy-locality-config/service-zone] -c /var/run/cilium/envoy/bootstrap-config.json --base-id N --log-level …`; hostNetwork; probes on 127.0.0.1:9878/healthz; mounts hostPath `/var/run/cilium/envoy/sockets`, `/var/run/cilium/envoy/artifacts`, `/sys/fs/bpf`, ConfigMap `cilium-envoy-config` (bootstrap from `files/cilium-envoy/configmap/bootstrap-config.yaml` rendered to JSON). Agent↔Envoy talk over xDS unix sockets in the shared hostPath.
- **hubble-relay** Deployment: `hubble-relay serve [--debug]`, config at `/etc/hubble-relay/config.yaml`, TLS at `/var/lib/hubble-relay/tls`, port 4245, runs as 65532, distroless.
- **hubble-ui** Deployment: `frontend` (nginx, port 8081, conf from ConfigMap) + `backend` (gRPC to relay, client certs at `/var/lib/hubble-ui/certs`).
- **clustermesh-apiserver** Deployment: init `etcd-init` (`clustermesh-apiserver etcdinit --etcd-data-dir=/var/run/etcd`), `etcd` (embedded `/usr/bin/etcd` v3.7.1, client TLS, 2379, metrics 9963), `apiserver` (`clustermesh-apiserver clustermesh --cluster-name --cluster-id --kvstore-opt etcd.config=/var/lib/cilium/etcd-config.yaml --cluster-users-enabled …`, health 9880, metrics 9962), `kvstoremesh` (`clustermesh-apiserver kvstoremesh --clustermesh-config=/var/lib/cilium/clustermesh --max-connected-clusters …`, health 9881, metrics 9964). Service NodePort 32379.
- **clustermesh-config**: secret `cilium-clustermesh` with one `<cluster>` etcd config per remote cluster (from `clustermesh.config.clusters[]`, with `ips[]`/`address`/`port`/tls) — consumed by agents (and kvstoremesh).
- **spire**: namespace `cilium-spire`, `spire-server` StatefulSet (1Gi PVC, RSA-4096 CA, `Cilium SPIRE CA`), `spire-agent` DaemonSet (`hostPID`, `hostNetwork`, sockets at `/run/spire/sockets`), init busybox waits via `files/spire/*.bash`.
- **nodeinit** DaemonSet (`quay.io/cilium/startup-script`): `hostPID`, `hostNetwork`; runs `files/nodeinit/startup.bash` on the host via `nsenter --target=1 --mount -- /bin/bash`: dumps link/route/addr, deletes a `cbr0` bridge, on GKE installs a kubelet wrapper that stops containerd, removes non-Cilium CNI confs, writes a minimal `05-cilium.conf` and fixes `/etc/containerd/config.toml` (`conf_template`), or on generic hosts rewrites kubelet flags to `--network-plugin=cni --cni-bin-dir=…` and restarts kubelet; finally writes the bootstrap timestamp file. `prestop.bash` reverses. Needed only for GKE/COS style nodes.
- **preflight** (`preflight.enabled=true agent=false operator.enabled=false`): DaemonSet with `clean-cilium-state` no-op (`/bin/echo`), `cilium-pre-flight-check` (`/bin/sh` that touches `/tmp/ready` — its only job is to pre-pull `image`), `cilium-pre-flight-envoy` (pre-pulls the envoy image); Deployment `cnp-validator` runs `cilium-dbg preflight validate-cnp` (with `validateCNPs=true`). PDBs; ClusterRole identical to the agent's.
- **standalone-dns-proxy** DaemonSet (alpha), **ztunnel** DaemonSet (Istio ambient proxy, `runAsUser 0`, mounts `/var/run/cilium`, `/etc/ztunnel`).
- **Misc**: `cilium-secrets` Namespace (+ Roles for agent read / operator write per namespace), `cilium-ca` Secret (helm-generated CA shared by hubble/clustermesh), `cilium-ingress` Service (shared mode), `IngressClass cilium`, `GatewayClass cilium` (+ ValidatingAdmissionPolicy), `ResourceQuota` for priority classes, `cilium-flowlog-config`/`cilium-dynamic-metrics-config` ConfigMaps, ServiceMonitors, Grafana dashboards.

### F6. `upgradeCompatibility` and validation

`cilium-configmap.yaml` computes version-gated defaults with `semverCompare` against
`default "<N>" .Values.upgradeCompatibility`: ≥1.8 → `bpf-map-dynamic-size-ratio=0.0025`,
`enable-bpf-masquerade=true`, `enable-bpf-clock-probe=true`, ipam cluster-pool, operator API
`127.0.0.1:9234`; ≥1.10 → `enable-bpf-masquerade=false`; ≥1.12 → azure `use-primary-address=false`,
`dnsproxy-enable-transparent-mode=true`; ≥1.14 → `kube-proxy-replacement=false`; ≥1.18 → ENI masquerade off.
`_helpers.tpl`: ≥1.16 → Envoy DaemonSet on; ≥1.17 → TLS secret sync on; ≥1.20 → `envoy-xds-mode=ads`.
Setting `upgradeCompatibility: "1.13"` therefore keeps a 1.13-era cluster on embedded Envoy and split xDS.

`validate.yaml` has 48 `fail` guards: removed values (`enableCiliumEndpointSlice`, `ciliumEndpointSlice.sliceMode`,
`encryption.{keyFile,...}`, `proxy.prometheus`, `endpointStatus`, `remoteNodeIdentity`, `containerRuntime.integration`,
`etcd.managed`, `tunnel`, `enableK8sEventHandover`, `enableCnpStatusUpdates`, clustermesh CA values), mutual
exclusions (`k8sServiceHostRef` vs `k8sServiceHost`), dependency rules (Hubble UI needs relay; relay needs hubble;
ingress/gateway need `l7Proxy=true` and an explicit `kubeProxyReplacement`; SPIRE needs authentication on;
CES needs endpoint CRD; clustermesh-apiserver incompatible with `disableEndpointCRD`; kvstoremesh modes;
`maxConnectedClusters ∈ {255,511}`; cluster name regex/length/`default` with id≠0; ENI+policy bug guard;
`standaloneDnsProxy` needs `dnsProxy.proxyPort`; `bpf.tproxy` incompatible with netkit; `ipam.mode=eni` needs `eni.enabled`).

### F7. Container images and their contents

Build chain: `cilium-llvm` (clang/llc 19.1.7, BPF backend only) + `cilium-bpftool` (7.7.0) + `cilium/iptables`
(1.8.8 debs) → **`cilium-runtime`** (Ubuntu 26.04 rootfs, flattened onto `scratch`) → **`cilium-builder`**
(runtime + Go 1.26.5 + cross gcc/binutils + protoc + scapy/jinja2) → **`cilium/cilium`** (builder output
copied onto runtime, Envoy copied from `cilium-envoy` image).

Measured `quay.io/cilium/cilium:v1.20.1`, Linux amd64, on 2026-09-22
(#37). Platform manifest SHA-256:
`f70030cc1ee5aad3e15a5b37324a5f3dd4ec039c082a22c589d439fbaf3ac68d`.
The compressed layers total **257,673,835 bytes**; this is not the installed
filesystem size. [Measurement record](../validation/cilium-image-sizes-2026-09-22.json).

| Path | Measured regular-file bytes |
|---|---:|
| `/usr/bin/cilium-agent` | 133,639,800 |
| `/usr/bin/cilium-dbg` | 98,423,408 |
| `/usr/bin/cilium-health` | 12,820,128 |
| `/usr/bin/cilium-health-responder` | 5,919,568 |
| `/usr/bin/cilium-bugtool` | 11,638,504 |
| `/usr/bin/hubble` | 74,596,544 |
| `/usr/bin/cilium-mount` | 7,643,008 |
| `/usr/bin/cilium-sysctlfix` | 2,953,544 |
| `/usr/bin/cilium-envoy-bootstrap-locality` | 26,305,592 |
| `/opt/cni/bin/cilium-cni` | 17,270,840 |
| `/usr/bin/cilium-envoy` | 75,271,288 |
| `/usr/bin/cilium-envoy-starter` | 574,592 |
| `/usr/local/bin/clang` | 85,062,048 |
| `/usr/local/bin/llc` | 39,595,000 |
| `/usr/local/bin/bpftool` | 6,726,832 |
| `/usr/bin/gops` | 3,858,594 |
| `/cni/loopback` | 2,965,666 |
| `/usr/sbin/iptables-wrapper` | 2,265,250 |

`/usr/bin/cilium` is a symlink to `cilium-dbg`, not another binary copy.
Measurements use manifest-ordered tar headers from the pulled image; selected
paths occur once and no whiteout entries occur. These replace the previous
binary estimates. Grouped userland, BPF-source and script footprints were not
measured; no estimate of their total or of other component images is retained.
The agent image also contains runtime Ubuntu tooling and BPF C sources;
operator, relay, ClusterMesh and standalone DNS images require separate pulls
before publishing their sizes. Contents and execution roles are catalogued in F8.

### F8. External binaries the agent executes at runtime

From `exec.Command`/`pkg/command/exec` callers (excluding tests and bugtool):

| Binary | Call site | When |
|---|---|---|
| `clang` (`--version` probe, then `clang <StandardCFlags> -mcpu=v3|v2 … -c bpf_lxc.c -o -`) | `pkg/datapath/loader/compile.go` | every datapath (re)compile: endpoint, host, overlay, xdp, wireguard, sock programs, plus `-E` for config dumps. `llc` is shipped but the loader invokes only `clang` |
| `iptables`, `ip6tables` (via wrapper → nft/legacy; `--version`, `-w`, `-t … -A/-I/-D`, `-S`, restore) | `pkg/datapath/iptables/iptables.go` | at start and on device/proxy/masquerade changes unless fully BPF (KPR + bpf masquerade + no L7 TPROXY fallback) |
| `ipset` (`ipset create/add/del`, `ipset restore` from stdin) | `pkg/datapath/iptables/ipset/*.go` | node IP sets `cilium_node_set_v4/v6` used by iptables masquerade exclusion |
| `ip route add …` / `ip -6 route add …` | `pkg/health/health_connectivity_endpoint.go` via `route.ToIPCommand` | inside the `cilium-health` netns to route from the health endpoint |
| `cilium-health --listen 4240 --pidfile …` | `pkg/health/health_connectivity_endpoint.go` | spawned once per node in the `lxc_health` netns |
| `cilium-envoy-starter` / `cilium-envoy --version` | `pkg/envoy/standalone_envoy.go` | embedded-Envoy mode only |
| `ip xfrm state list reqid 1` | `cilium-dbg/cmd/encrypt_status.go` | CLI only |
| `etcd` | `clustermesh-apiserver/etcdinit` | clustermesh-apiserver only |
| `bash`, `mount`, `grep`, `nsenter`, `cp`, `rm`, `sleep`, `iptables-*-save` | init containers / lifecycle hooks in the DaemonSet | pod start/stop |

Notably *not* exec'd: `tc` (attach via netlink/tcx through `cilium/ebpf`), `bpftool`, `ethtool` (ioctl),
`modprobe` (no module loading in Go; kernel autoloads xt modules when iptables runs, hence `/lib/modules` +
`SYS_MODULE`), `sysctl` (written through `/host/proc/sys` files), `mount` for bpffs/cgroup (Go `unix.Mount`
in `pkg/bpf`/`pkg/cgroups`, or the `mount-bpf-fs` init container).

### F9. `cilium-cli` (out of tree)

`cilium-cli` is not vendored; CI pins `cilium/cilium-cli@7ca7fc53… # v0.19.7` (`.github/actions`,
`CILIUM_CLI_VERSION`). Commands the repo relies on (CI + docs): `cilium install` (Helm-based; auto-detects
kube-apiserver host/port for KPR, cluster type, sets `--nodes-without-cilium`), `cilium upgrade`,
`cilium status [--wait]` (checks DaemonSet/Deployment readiness, `cilium-dbg status` per pod, image
versions, warnings), `cilium config {get,set}`, `cilium preflight {migrate-identity, manifest}`,
`cilium sysdump` (bugtool + k8s objects), `cilium hubble {enable, disable, port-forward, ui}`,
`cilium clustermesh {enable, connect, status, inspect-policy-default-local-cluster}`,
`cilium bgp {peers, routes}`, `cilium encrypt create-key`, `cilium connectivity test`, `cilium connectivity perf`.

`cilium connectivity test` is the acceptance suite. It deploys `client`, `client2`, `client3`, `echo-same-node`,
`echo-other-node`, `host-netns`, `host-netns-non-cilium`, external targets (`--external-target=bing.com.`,
`--external-cidr=8.0.0.0/8`, `--external-ip=8.8.4.4`, `--external-other-ip=8.8.8.8`, optional IPv6 variants),
performs feature detection from `cilium-config`/`cilium status --output json` (so tests skip when a feature is off),
and optionally validates Hubble flows (`--flow-validation=enabled|disabled`, `--hubble=true`). CI defaults
(`.github/actions/cli-test-config`): `--collect-sysdump-on-failure --log-code-owners --code-owners=… --external-*`
plus `--include-unsafe-tests`, `--include-conn-disrupt-test` (with `conn-disrupt-test-setup/check` actions across
upgrades), `--test-concurrency`, `--junit-file`, `--expected-drop-reasons`, `--multi-cluster=<ctx>`.
Test selection by name/prefix with negation: `--test='no-policies/'`, `--test='!/pod-to-world'`, etc.

Test names referenced by this repo's CI/docs (all exist in cilium-cli v0.19): `no-unexpected-packet-drops`,
`no-policies`, `no-policies-extra`, `no-policies-from-outside`, `allow-all-except-world`, `allow-all-with-metrics-check`,
`client-ingress`, `client-ingress-knp`, `client-egress`, `client-egress-knp`, `client-egress-expression`,
`client-egress-to-echo-service-account`, `client-egress-l7`, `client-egress-l7-method`, `client-egress-l7-named-port`,
`client-egress-tls-sni`, `client-egress-l7-tls-headers`, `client-egress-l7-set-header`, `client-egress-only-dns`,
`client-egress-to-cidr-deny`, `client-egress-to-cidr-deny-default`, `client-egress-to-echo-deny`,
`client-ingress-to-echo-named-port-deny`, `client-egress-to-echo-expression-deny`, `client-ingress-from-other-client-icmp-deny`,
`echo-ingress`, `echo-ingress-knp`, `echo-ingress-l7`, `echo-ingress-l7-named-port`, `echo-ingress-from-other-client-deny`,
`echo-ingress-auth-always-fail`, `echo-ingress-mutual-auth-spiffe`, `all-ingress-deny`, `all-ingress-deny-knp`,
`all-ingress-deny-from-outside`, `all-egress-deny`, `all-egress-deny-knp`, `all-entities-deny`, `cluster-entity`,
`cluster-entity-multi-cluster`, `host-entity-egress`, `host-entity-ingress`, `to-entities-world`, `to-cidr-external`,
`to-cidr-external-knp`, `from-cidr-host-netns`, `pod-to-node-cidrpolicy`, `dns-only`, `to-fqdns`, `pod-to-world`,
`pod-to-cidr`, `pod-to-host`, `host-to-pod`, `pod-to-controlplane-host`, `pod-to-k8s-on-controlplane`,
`pod-to-controlplane-host-cidr`, `pod-to-k8s-on-controlplane-cidr`, `outside-to-nodeport`, `north-south-loadbalancing`,
`north-south-loadbalancing-with-l7-policy`, `local-redirect-policy`, `local-redirect-policy-with-node-dns`,
`egress-gateway`, `egress-gateway-excluded-cidrs`, `egress-gateway-with-l7-policy`, `pod-to-ingress-service`,
`pod-to-ingress-service-deny-*`, `pod-to-ingress-service-allow-ingress-identity`, `outside-to-ingress-service`,
`outside-to-ingress-service-deny-*`, `pod-to-pod-encryption`, `pod-to-pod-with-l7-policy-encryption`,
`node-to-node-encryption`, `strict-mode-encryption`, `host-firewall-ingress`, `host-firewall-egress`, `health`,
`clustermesh-endpointslice-sync`, `check-log-errors` (scans agent logs for `level=error`), `no-interrupted-connections`
(conn-disrupt), `network-perf` (`connectivity perf`, netperf TCP_RR/TCP_STREAM/UDP pod-to-pod and host-net).
Each test = scenario (curl/ping/DNS from client pod to target) × policy (CNP/CCNP/KNP applied by the test) ×
expected verdict, plus Hubble flow matching (drop reason, policy verdict) when enabled. Roughly 32–70 tests,
250–300 actions depending on enabled features.

### F10. Test estate

- **BPF unit/integration tests** (`bpf/tests`, 141 `.c`, 330 `PKTGEN`/397 `CHECK` programs): each `.c` is compiled
  standalone with the loader's exact cflags (`clang_cflags.go`, `-mcpu=v3`, `-g`) and includes the real datapath
  (`bpf_lxc.c`, `bpf_host.c`, `bpf_overlay.c`, `bpf_xdp.c`, `bpf_wireguard.c`). Programs are `PKTGEN("tc","name")`
  (craft packet, scapy-generated bytes from `scapy/*.py` via `output/scapy_bytes.h`), `SETUP("tc","name")`
  (populate fake maps from `lib/*.h`: ipcache, lb, policy, endpoint, node, egressgw, ipsec; then tail-call the entry
  program), `CHECK("tc","name")` (inspect resulting packet at `data+4`, maps, `test_log/test_fatal`). Results are a
  hand-rolled protobuf in `suite_result_map` decoded by `bpftest/bpf_test.go` (`trf.proto`), which runs each object in
  a fresh netns under `BPF_PROG_RUN` and optionally instruments coverage with `coverbee`. Families: `tc_nodeport_*` (SNAT/DSR/
  IPIP/Geneve/fragments/ICMP/IPv6/wildcard/terminating), `tc_lb_*`, `tc_lxc_*`, `tc_redirect_{lxc,host,netdev}_{veth,netkit}`,
  `tc_egressgw_*`, `tc_l2_announcement*`, `tc_srv6_*`, `tc_geneve_dsr_legacy`, `tc_policy_reject_response_test`,
  `xdp_nodeport_*`, `xdp_kpr_dsr_*`, `xdp_egressgw_reply`, `skip_tunnel_*`, `skip_lb_xlate_*`, `encrypt_host_*`/`decrypt_host_*`
  (ipsec/wireguard, strict, tunnel), `host_*` (masq, hostfw IGMP/extended protocols, proxy, socket LB), `l7_lb_*`,
  `inter_cluster_snat_*`, `session_affinity*`, `ipfrag`, `ipv6_ndp`, `mcast_tests`, `conntrack_test`, `bpf_nat_tests`,
  `bpf_ct_tests`, `fib_tests`, `lb_tests`, `jhash_test`, `builtins`, `network_policy`, `drop_notify_test`, `ratelimit`,
  `ip_options_trace_id`, `classifiers_*`, `eni_nlb_symetric_routing_host`, `remote_node_masquerade*`. Run by `make run_bpf_tests`
  inside cilium-builder; CI: `lint-bpf-checks` + `conformance-runtime` (privileged, LVH 6.18).
- **Verifier complexity** (`tests-datapath-verifier.yaml`, "ci-verifier"): kernels 5.15 (`ci-kernel 510` permutations),
  6.1, 6.6, 6.12, 6.18 (`61`); runs `TestPrivilegedVerifier` in an LVH VM against the checkout; for each of
  `bpf_lxc/host/overlay/sock/wireguard/xdp` and every permutation in `bpf/complexity-tests/<kernel>/<prog>/*.txt`
  (macro define sets) it compiles, loads, parses the verifier log for `insns processed`/stack depth and writes
  `verifier-complexity.json`; `contrib/scripts/verifier_diff.py` diffs against the base branch.
- **Control-plane tests** (`test/controlplane`): single Go test binary; cases register via `suite.AddTestCase`;
  `NewControlPlaneTest(t, clusterName, k8sVersion)` boots the whole agent hive with fake k8s clientsets and a fake
  datapath (`fakenode.Handler`, statedb tables), feeds objects from `init.yaml`/`stateN.yaml` (`kind: List` of real
  captured `Node`/`CiliumNode`/… objects, generated per k8s version by `generate.sh` against kind) and asserts on the
  fake datapath (or compares golden files, `-update` regenerates). In 1.20 only `node/ciliumnodes` (k8s 1.24–1.26
  fixtures) and `node/nodehandler` remain; the former services/nodeport golden cases were removed.
- **Ginkgo e2e** (`test/k8s`, run by `conformance-ginkgo` on kind inside LVH): suites `K8sAgentChaosTest` (restart
  agent, long-lived connections survive, graceful shutdown/SIGTERM), `K8sAgentFQDNTest` (FQDN policy across restarts,
  multiple specs), `K8sAgentPerNodeConfigTest` (CiliumNodeConfig v2 overrides), `K8sAgentPolicyTest` (basic L3/L4/L7,
  namespaces, clusterwide, external, multi-node fromEntities/toEntities, kube-apiserver entity, host policy,
  ingress CIDR L4), `K8sAgentHubbleTest` (L3/L4/L7 flows, relay, TLS cert), `K8sDatapathServicesTest` (E/W ClusterIP/
  NodePort; N/S with TC/XDP × direct/vxlan/geneve × SNAT/DSR/Hybrid × Random/Maglev, externalTrafficPolicy=Local,
  IPsec, host-fw, sessionAffinity, HealthCheckNodePort, bind protection, TFTP/DNS proxy port collision, security
  id propagation over tunnel), `K8sDatapathLRPTests`, `K8sDatapathBandwidthTest`, pod MAC address, `K8sAgentPolicyTest
  Basic`. Focus groups f01–f19 mapped in `.github/actions/ginkgo/main-focus.yaml`; k8s×kernel pairs in
  `main-k8s-versions.yaml`: 1.36/6.18 (latest, one node without Cilium), 1.35/6.12, 1.34/6.6, 1.33/6.1 (stable).
- **Go unit / privileged / integration**: `make tests-privileged` (`PRIVILEGED_TESTS=true`, needs root+bpffs),
  `make integration-tests` (starts etcd container), `integration-test.yaml` runs on amd64 and arm64 runners,
  `conformance-race` (race detector on a reduced ginkgo focus), `tests-cifuzz`.
- **Upstream conformance**: `k8s-kind-network-e2e` (Kubernetes `e2e.test` `[sig-network]` minus
  `Alpha|Beta|…|KubeProxy|LoadBalancer|Netpol`), `k8s-kind-network-policies-e2e` (netpol e2e), `conformance-k8s-network-policies`
  (cyclonus), `conformance-gateway-api` (upstream Gateway API conformance, `make gateway-api-conformance`),
  `conformance-ingress`, `conformance-mcs-api`.
- **Other scenario dirs**: `test/bigtcp` (kind + netperf for BIG TCP), `test/vtep` (kind + VXLAN responder VM),
  `test/bpf/xdp.c` (sample), `test/fuzzing` (oss-fuzz).

### F11. GitHub workflows (62) — what each tests

| Workflow | What |
|---|---|
| `tests-e2e-upgrade` (ci-e2e-upgrade) | kind in LVH; matrix from `.github/actions/e2e/{ipsec,kube-proxy,lb,misc,netkit,wireguard}.yaml` (41 configs); installs previous stable (`print-downgrade-version.sh stable` → 1.19.x), runs connectivity test, upgrades to PR image with conn-disrupt check, tests, downgrades, tests; bpftrace `check-encryption-leaks.bt`; features: KPR on/off, kube-proxy iptables/none, vxlan/geneve/native, endpoint-routes, egress-gw, ingress, BGP, host-fw, LRP+node-local-dns, kvstore, IPv6-only, IPv6 underlay, netkit/netkit-l2, DSR/SNAT, XDP `testing-only`, WireGuard (node encryption, strict ingress/egress), IPsec (both key types, strict), CES, `envoy.xdsMode=split`, `socketLB.hostNamespaceOnly` |
| `conformance-ipsec-e2e` (ci-ipsec-e2e) | the `ipsec.yaml` slice (10 configs) with key rotation (`ipsec-key-rotate` action) between test runs |
| `conformance-ztunnel-e2e` | `encryption.type=ztunnel`, kernels 6.6 and 6.12, KPR |
| `conformance-ginkgo` (ci-ginkgo) | legacy ginkgo suites above, kind in LVH, k8s 1.33/1.35/1.36 on PRs, +1.34 scheduled |
| `conformance-runtime` (ci-runtime) | privileged Go tests + BPF unit tests in LVH 6.18 |
| `tests-datapath-verifier` (ci-verifier) | verifier complexity on 5.15/6.1/6.6/6.12/6.18 |
| `conformance-clustermesh` (ci-clustermesh) | two kind clusters; matrix: kvstoremesh vs clustermesh mode, encryption disabled/wireguard/ipsec, kube-proxy none, auth modes legacy/migration/cluster, maxConnectedClusters 255/511, multi-pool IPAM; connectivity test with `--multi-cluster` |
| `tests-clustermesh-upgrade` | same, across versions |
| `conformance-mcs-api` | MCS-API (ServiceExport/Import) conformance + coredns auto-config |
| `conformance-eks` (ci-eks) / `conformance-kpr-eks` | real EKS (k8s 1.33/1.34 with ENI prefix delegation/1.35), ENI IPAM, addons `coredns kube-proxy`; KPR variants add `bpf-masq-v4`, `advanced-features`, ipsec, wireguard, `bpf-datapath=netkit|netkit-l2`; cluster pool managed by `eks-cluster-pool-manager` |
| `conformance-aws-cni` | EKS with `vpc-cni` chaining (`cni.chainingMode=aws-cni`), k8s 1.32–1.35, one config KPR, one WireGuard |
| `conformance-gke` (ci-gke) / `conformance-kpr-gke` | GKE 1.31–1.35, configs `no-tunnel` and `tunnel` (`--datapath-mode=tunnel`); KPR + ipsec/wireguard variants; ESP firewall rule actions |
| `conformance-aks` (ci-aks) / `conformance-kpr-aks` | AKS BYOCNI 1.31–1.35 (`--helm-set loadBalancer.l7.backend=envoy azure.resourceGroup …`); ipsec uses AzureLinux node SKU |
| `conformance-ipsec` | fan-out wrapper: aks/eks/gke with `{"ipsec": true}` |
| `conformance-delegated-ipam` | `ipam.mode=delegated-plugin` |
| `conformance-multi-pool` | multi-pool IPAM with optional encryption |
| `conformance-gateway-api`, `conformance-ingress`, `conformance-kind-proxy-embedded` | L7 stacks; embedded Envoy variant; KPR true |
| `conformance-l3-l4`, `conformance-l7` | connectivity test restricted to L3/L4 or L7 |
| `conformance-kubespray` | kubespray-provisioned cluster |
| `k8s-kind-network-e2e`, `k8s-kind-network-policies-e2e`, `conformance-k8s-network-policies` | upstream k8s e2e / cyclonus |
| `tests-smoke`, `tests-smoke-conformance`, `tests-smoke-ipv6` | fast kind install + connectivity test (IPv4, IPv6) |
| `tests-ces-migrate` | CiliumEndpointSlice migration |
| `hubble-cli-integration-test` | hubble CLI against relay |
| `integration-test` | Go integration tests on amd64 and arm64 |
| `conformance-race` | race detector |
| `build-images-{ci,releases,beta,base}` | multi-arch `linux/amd64,linux/arm64` image builds; base image (runtime/builder) rebuilds via renovate |
| `lint-bpf-checks`, `lint-go`, `lint-build-commits`, `lint-workflows`, `lint-images-base`, `lint-ariane-config`, `codeql`, `documentation`, `push-chart-ci` | static checks; Helm chart pushed per CI build |
| housekeeping | `auto-approve`, `ci-images-cache-cleaner`, `ci-images-garbage-collect`, `eks-cluster-delete`, `feature-summary-report`, `greetings`, `update-label-backport-pr`, `wait-for-status-check`, `common-post-jobs`, `build-go-caches` |

Kernel versions under test (LVH `quay.io/lvh-images/kind` images, `.github/actions/e2e/kernel-versions.yml`):
**rhel8.10 (4.18), 5.15, 6.1, 6.6, 6.12, 6.18** (all `-20260810.013220`). Occurrences across matrices: 6.12 ×17,
6.18 ×9, 6.6 ×7, 5.15 ×7, 6.1 ×5, rhel8.10 ×3. There is no bpf-next job in 1.20.1. No dedicated perf/benchmark
workflow (`netperf` only appears in `test/bigtcp` and the connectivity `network-perf` test; `make bench` exists locally).

### F12. System requirements (docs)

- Arch: amd64, arm64. Kernel ≥ 5.10 (or RHEL 8.10's 4.18). clang+LLVM ≥ 18.1 only when running natively.
  etcd ≥ 3.1.0 for kvstore mode.
- Required `CONFIG_*`: `BPF`, `BPF_EVENTS`, `BPF_SYSCALL`, `NET_CLS_BPF`, `BPF_JIT`, `NET_CLS_ACT`, `NET_SCH_INGRESS`,
  `DEBUG_INFO_BTF`, `CRYPTO_SHA1`, `CRYPTO_USER_API_HASH`, `CGROUPS`, `CGROUP_BPF`, `PERF_EVENTS`, `SCHEDSTATS`.
  iptables masquerade: `NETFILTER_XT_SET`, `IP_SET`, `IP_SET_HASH_IP`, `NETFILTER_XT_MATCH_COMMENT`. Tunnel/routing:
  `VXLAN`, `GENEVE`, `FIB_RULES`. L7/FQDN: `NETFILTER_XT_TARGET_TPROXY`, `_TARGET_MARK`, `_TARGET_CT`, `_MATCH_MARK`,
  `_MATCH_SOCKET` (xt_socket missing → `enable-xt-socket-fallback` disables `ip_early_demux`). IPsec: `XFRM*`,
  `INET{,6}_ESP/IPCOMP/XFRM_TUNNEL/TUNNEL`, `CRYPTO_{AEAD,GCM,SEQIV,CBC,HMAC,SHA256,AES}`. Bandwidth manager:
  `NET_SCH_FQ`. Netkit: `NETKIT`.
- Feature × min kernel: multicast amd64 ≥5.10 / arm64 ≥6.0; IPv6 BIG TCP ≥5.19; IPv4 BIG TCP ≥6.3; netkit ≥6.8.
- Mounts: bpffs at `/sys/fs/bpf` (auto-mounted; `contrib/systemd/sys-fs-bpf.mount`), cgroup2 at
  `/run/cilium/cgroupv2` (auto-mounted). Privileges: `CAP_SYS_ADMIN` (documented minimum) + host netns.
- Routing tables reserved: 200 (IPsec), 202 (VTEP), 2004/2005 (to/from proxy), `10+ifindex` per ENI.
- Ports: 4240 health, 4244 hubble, 4245 relay, 4250 mutual auth, 4251 spire agent health, 6060/6061/6062 pprof,
  9878 envoy health, 9879 agent health, 9890/9891/9893 gops, 9901 envoy admin, 9962/9963/9964 metrics,
  8472/udp vxlan, 6081/udp geneve, 51871/udp WireGuard, ESP for IPsec, 2379-2380 etcd.

### F13. Upgrade notes

Preflight is required (`preflight.enabled=true agent=false operator.enabled=false`): pre-pulls agent and
envoy images on every node and validates CNPs. Upgrade path: latest patch of current minor → `helm upgrade`
to next minor (all components together), rollback by `helm rollback`. Known impact: L7 proxy restarts reset
proxied connections; new policy is applied after the node finishes; monitor loses events beyond buffer.
Identity migration kvstore→CRD via `cilium preflight migrate-identity`. Version-specific removals are enforced by
`validate.yaml` (F6). Release cadence: feature release about every six months (`X.Y.0`), three stable branches
maintained, monthly pre-releases from `main`, ~6-week feature freeze, RCs every two weeks. `VERSION` = `1.20.1`;
there is no `stable.txt` in tree (it lives on the release infrastructure).

### F14. contrib scripts of interest

`contrib/scripts/kind.sh` (kind cluster with N workers, kube-proxy mode, ip-family), `kind-setup-dns.sh`,
`print-downgrade-version.sh` (previous stable/patch from `VERSION`), `print-chart-version.sh`, `verifier_diff.py`,
`bugtool-multinode-gather.sh`, `check-*` lints (datapathconfig, k8s codegen, viper flags, log newlines,
preflight clusterrole == agent clusterrole), `builder.sh` (run make in cilium-builder), `microk8s-import.sh`;
`contrib/systemd/{cilium.service, cilium-etcd.service, sys-fs-bpf.mount, cilium.sysusers}` (native install:
`ExecStart=/usr/bin/cilium-agent $CILIUM_OPTS`); `contrib/k8s/{k8s-cilium-exec.sh, nsexec, clear-kubeproxy-iptables.yaml,
k8s-unmanaged.sh}`; `contrib/testing/kind-*.yaml` (clustermesh pair, egress-gw values); `contrib/coccinelle/*.cocci`
(BPF C semantic patches: tail calls, alignment, null checks, hexdump ban).

## Data model

- Helm values (schema in `values.schema.json`); `cilium-config` ConfigMap (426 string keys) and optional
  `CiliumNodeConfig` CRs merged by `cilium-dbg build-config` into `/tmp/cilium/config-map/<key>` files
  (one file per key, agent reads with `--config-dir`).
- Secrets: `cilium-ipsec-keys` (`keys` = `<spi> <algo> <key> [<key2>]`), `cilium-ca`, `hubble-server-certs`,
  `hubble-relay-client-certs`, `hubble-relay-server-certs`, `hubble-metrics-server-certs`, `cilium-clustermesh`
  (per-cluster etcd yaml + certs), `clustermesh-apiserver-{server,admin,remote,local}-cert`, `cilium-etcd-secrets`.
- Host filesystem: `/var/run/cilium` (`cilium.sock`, `hubble.sock`, `state/<epid>/` dirs with `ep_config.json`,
  `envoy/{sockets,artifacts}`, `cilium-cni.log`, `health-endpoint.pid`), `/sys/fs/bpf/tc/globals/*` pinned maps,
  `/run/cilium/cgroupv2`, `/etc/cni/net.d/05-cilium.conflist` (+ `*.cilium_bak`), `/opt/cni/bin/{cilium-cni,loopback}`,
  `/etc/sysctl.d/99-zzz-override_cilium.conf`, `/tmp/cilium-bootstrap.d/cilium-bootstrap-time`.
- Test fixtures: `test/controlplane/**/{init,stateN}.yaml` (`v1 List` of k8s objects), `bpf/complexity-tests/<k>/<prog>/*.txt`
  (macro sets), `bpf/tests/output/scapy_bytes.h`, `verifier-complexity.json` records `{kernel, program, insns, stack}`.

## External interfaces

- Kubernetes objects rendered by the chart (F3–F5); RBAC (agent ClusterRole: get/list/watch on networkpolicies,
  endpointslices, namespaces/services/pods/nodes/secrets, all `cilium.io` CRDs list/watch; create events;
  patch nodes/status; leases; create/update/patch/delete on ciliumidentities/ciliumendpoints/ciliumnodes(+status),
  ciliuml2announcementpolicies/status, ciliumbgpnodeconfigs/status; ClusterNetworkPolicy read. Operator ClusterRole
  adds CRD create/update, services/endpointslices CRUD, ingress/gateway status, MCS-API, taints/node status, pod delete;
  operator Role in each secrets namespace to CRUD secrets; agent Role read `cilium-config` + secrets in cilium-secrets).
  Verb details per CRD are in the CRD inventory.
- Helm chart repo `helm.cilium.io`; images on `quay.io/cilium/*` (digests pinned in values for envoy, certgen, hubble-ui,
  spire, startup-script, ztunnel).
- Host contracts: bpffs `Bidirectional` propagation, `/run/xtables.lock`, CNI conf/bin dirs, systemd D-Bus
  (`systemd-sysctl.service` restart by sysctlfix), `nsenter` into PID 1 mount/cgroup ns.
- CI contracts: LVH VM images `quay.io/lvh-images/kind:<kernel>-<date>`, `quay.io/cilium/kindest-node:v1.3x`,
  cilium-cli action, cloud credentials.

## Dependencies

Areas: CRDs/RBAC (verbs), daemon config (`pkg/option` flag names = ConfigMap keys), datapath loader (clang),
iptables/ipset datapath, health, Envoy, Hubble, ClusterMesh, BGP, all feature areas (their Helm switches live here).
External: Helm ≥3, Kubernetes ≥1.31 tested (charts use `appArmorProfile` ≥1.30, `hostUsers` ≥1.33),
Envoy image (`cilium/proxy`), etcd, SPIRE, certgen, hubble-ui, ztunnel, cilium-cli, LVH, kind, cloud APIs.

## Kernel / platform requirements

See F12. The chart itself assumes: cgroup v2 available, bpffs mountable, `nsenter` into host mount ns
(so `SYS_ADMIN`+`SYS_CHROOT`+`SYS_PTRACE` for two init containers), a privileged container for bpffs mount
propagation, `/lib/modules` for xt module autoload, and a systemd host for sysctl persistence (sysctlfix
degrades gracefully when D-Bus is absent). arm64 is a first-class build target (all images multi-arch,
integration tests on arm64 runners) but the LVH kernel matrix is amd64 only.

## Tests

Summarised in F10–F11. What they pin down for flowsdn:

- BPF unit tests pin exact packet transformations (NAT/DSR/Geneve option/IPIP, tunnel encap headers, ICMP error
  revnat, fragments, policy drop codes, monitor drop notifications, encryption marks) — a datapath rewrite must
  either reuse these `.c` tests unchanged (if the BPF C is kept) or re-express them.
- Verifier matrix pins that every program permutation loads on 5.15/6.1/6.6/6.12/6.18 within complexity limits.
- Control-plane tests pin "k8s objects → datapath tables" without depending on the Go implementation.
- Ginkgo pins agent restart semantics (connections survive restart, policy stays enforced while agent down), FQDN
  proxy behaviour, N/S LB matrix, LRP, bandwidth.
- Connectivity test pins the user-visible contract (policy verdicts, LB, encryption, egress gateway, ingress,
  host firewall, Hubble flow content, no unexpected drops, no log errors, no interrupted connections on upgrade).
- Upgrade/downgrade workflows pin 1.19↔1.20 compatibility of pinned maps and config.

## Rust mapping

**Helm chart — keep value-compatible.** flowsdn should ship the same chart layout (`values.yaml` keys, the
`cilium-config` key names, the same object names `cilium`, `cilium-operator`, `cilium-envoy`, `cilium-config`,
`cilium-secrets`) so that `cilium install`/`cilium upgrade`, `cilium status`, `cilium connectivity test` feature
detection and existing user values work unchanged. Concretely: fork `install/kubernetes/cilium` (Apache-2.0 chart),
keep `cilium-configmap.yaml` and `validate.yaml` verbatim, change only `image.repository`, init containers and
`securityContext`. The agent must accept `--config-dir` with one-file-per-key, and the flag-name set must be the 426
keys above (unknown keys must be ignored with a warning, as Cilium does, to tolerate `extraConfig`). `cilium-dbg
build-config` (ConfigMap + CiliumNodeConfig merge) becomes a subcommand of the flowsdn binary; `config` init
container stays (it only needs the k8s API).

**Scratch image — what a native agent still needs from the host.** With clang, iptables, ipset, cilium-health,
Envoy and the shell removed, the residual requirements are:

| Need | Cilium mechanism | flowsdn plan |
|---|---|---|
| Load BPF, pin maps, attach tcx/XDP/cgroup/sockops | `CAP_SYS_ADMIN` (or `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN` on ≥5.8) | ship with `BPF, PERFMON, NET_ADMIN, NET_RAW, IPC_LOCK, SYS_RESOURCE` (≥5.8 kernels; 5.10 is the floor) and offer `SYS_ADMIN` as a values switch for RHEL 4.18 |
| bpffs mounted and visible with `Bidirectional` | privileged `mount-bpf-fs` init | keep as the single privileged init container *or* mount via `unix::mount` from the agent when `CAP_SYS_ADMIN` is present; document `sys-fs-bpf.mount` as the preferred host-side fix |
| cgroup2 root for sock LB | `cilium-mount` via nsenter | native `mount(cgroup2)` in agent if `SYS_ADMIN`, else keep init container with the flowsdn binary in place of `cilium-mount` (same `SYS_ADMIN, SYS_CHROOT, SYS_PTRACE`) — no bash needed if the init container's `command` is the static binary itself and the copy-to-host trick is replaced by a bind-mounted binary from the image |
| rp_filter sysctls surviving `systemd-sysctl` | `cilium-sysctlfix` writes `/etc/sysctl.d` + D-Bus | same logic in Rust (`zbus`); write via `/host/etc/sysctl.d` hostPath instead of nsenter, or set per-interface sysctls at link creation through `/host/proc/sys/net` (already mounted) and skip the file when D-Bus is unavailable |
| Netlink (links, routes, rules, neigh, xfrm, wireguard) | `NET_ADMIN` | `rtnetlink`/`netlink-packet-*`; `wireguard-uapi`; xfrm via `netlink-packet-xfrm` |
| Enter pod/health netns | `SYS_ADMIN` (`setns`) + `/var/run/netns` | keep `SYS_ADMIN` or `CAP_SYS_PTRACE`-free `setns` on fds opened from `/proc/<pid>/ns/net` — requires `SYS_ADMIN`; keep the hostPath `/var/run/netns` |
| iptables/ipset rules (masquerade, proxy TPROXY/mark, feeder rules, no-conntrack) | exec `iptables`/`ipset` + `xtables.lock` + `/lib/modules` + `SYS_MODULE` | replace by native nftables over netlink (`nftnl`/`rustables`) with a `cilium_*` table, and default to BPF masquerade + BPF TPROXY so the rule set is empty when KPR is on; drop `SYS_MODULE`, `/lib/modules`, `/run/xtables.lock` unless the nft path is enabled (kernel autoloads `nf_tables` on first netlink use only if loaded; document `nf_tables` as required) |
| BPF compile per endpoint | exec `clang` | ahead-of-time compiled objects embedded in the binary (`aya`/`libbpf-rs` skeletons), per-endpoint parameters via config maps / `.rodata` relocation (Cilium already moved most per-endpoint state to `bpf_lxc.json` config); removes ~150 MB and `DAC_OVERRIDE/FOWNER/SETUID/SETGID` |
| Health endpoint | exec `cilium-health` in a netns + `ip route add` | in-process thread that `setns` into `lxc_health`, listens 4240, routes via rtnetlink |
| L7 proxy | `cilium-envoy` binary or DaemonSet | keep the upstream `cilium-envoy` DaemonSet image (out of scope to rewrite); embedded mode dropped |
| CNI plugin | `/opt/cni/bin/cilium-cni` copied by init | static Rust `flowsdn-cni` copied by an init container whose `command` is `["/flowsdn", "install-cni"]` (no shell) |
| Clean state, uninstall | `/init-container.sh`, `/cni-uninstall.sh` (bash) | `flowsdn cleanup --bpf-state|--all-state`, `flowsdn cni-uninstall` subcommands; preStop hook `exec` the binary |
| Probes | httpGet 127.0.0.1:9879 | same |
| Sidecar/debug | `cilium-dbg`, bash, bpftool | `flowsdn-dbg` (thin client of the unix API) and `kubectl debug` ephemeral containers with the Cilium image for bpftool/tcpdump; document that the scratch image has no shell |

Resulting agent `capabilities.add` proposal: `NET_ADMIN, NET_RAW, BPF, PERFMON, IPC_LOCK, SYS_RESOURCE, SYS_ADMIN
(for setns/mount; removable when netns entry is delegated to the CNI plugin path only), KILL, CHOWN`. hostPaths that
remain: `/var/run/cilium`, `/var/run/netns`, `/sys/fs/bpf`, `/run/cilium/cgroupv2`, `/proc/sys/net`, `/proc/sys/kernel`,
`/opt/cni/bin`, `/etc/cni/net.d`, plus `/proc` for the two nsenter-style inits if kept. Dropped: `/lib/modules`,
`/run/xtables.lock` (unless nft mode), spire/envoy sockets unchanged.

**Init containers become**: `config` (Rust binary, same RBAC), `mount-cgroup`/`apply-sysctl-overwrites` (Rust
binary executed directly with nsenter semantics implemented via `setns(CLONE_NEWNS)` on `/hostproc/1/ns/mnt` —
no `nsenter` or `cp` needed), `mount-bpf-fs` (privileged; `flowsdn mount-bpffs`), `clean-cilium-state`
(`flowsdn cleanup`), `install-cni-binaries` (`flowsdn install-cni`). `wait-for-kube-proxy` and `wait-for-node-init`
need a shell loop today; implement as `flowsdn wait --for=...`. `nodeinit` stays a separate upstream image (GKE only).

**Images**: `flowsdn` = `FROM scratch` + static musl binary + `/etc/ssl/certs`, ~30–40 MB; `flowsdn-operator`
same pattern (Cilium's operator already is scratch); reuse upstream `hubble-relay`, `hubble-ui`, `cilium-envoy`,
`clustermesh-apiserver` images unchanged in v1 (the chart references them by value). Multi-arch amd64+arm64 as
per the cross-project build rules (podman, scratch).

**Tests flowsdn can reuse directly**:
1. `cilium connectivity test` (cilium-cli v0.19.7) against a flowsdn cluster — feature detection reads
   `cilium-config` keys and `cilium status`, so key-compatibility is what makes this work; target the `tests-smoke*`
   set first, then `e2e/kube-proxy.yaml` and `lb.yaml` configs, then encryption.
2. `bpf/tests` harness — if flowsdn keeps the BPF C datapath, the `.c` tests, `common.h`, `lib/*.h`, scapy
   defs and the Go driver run unchanged (driver is Go; a Rust port of `bpftest/bpf_test.go` (1152 lines,
   `BPF_PROG_RUN` + protobuf decode) is small and removes the Go dependency from the test loop).
3. Verifier matrix — reuse `bpf/complexity-tests/**` permutation files and LVH kernels 5.15/6.1/6.6/6.12/6.18;
   port `TestPrivilegedVerifier` (877 lines) to Rust (`aya` load + verifier log parse).
4. Control-plane fixtures — the `init.yaml`/`stateN.yaml` k8s object lists are implementation-agnostic; a Rust
   harness that feeds them through a fake kube client into the flowsdn reconcilers and asserts on statedb-equivalent
   tables reuses the data (only `node/ciliumnodes` remains in 1.20.1; more golden cases exist in older tags).
5. Upstream conformance: Kubernetes sig-network e2e skip list, cyclonus, Gateway API and MCS-API conformance
   suites, unchanged.
6. Ginkgo `test/k8s` — not reusable as-is (Go helpers exec `cilium-dbg` inside pods, 7k lines of harness); treat
   as a checklist of behaviours (restart resilience, FQDN across restart, N/S LB matrix).

Candidate crates: `kube`/`k8s-openapi` (client, CRDs), `aya` or `libbpf-rs` (load/attach/maps, tcx via `aya`
≥0.13), `rtnetlink`, `netlink-packet-route/-xfrm`, `nftables`/`rustables`, `wireguard-uapi`, `nix` (`setns`,
`mount`, `capset`), `caps`, `zbus` (systemd), `tokio`, `serde_yaml` (config-dir), `prometheus-client`, `tonic`
(Hubble/xDS gRPC), `clap` (flag names must match ConfigMap keys). Hard parts: exact `cilium status`-compatible
JSON for cilium-cli, per-key semantics of 426 config keys, keeping BPF pinned-map layouts compatible for
upgrade-in-place from Cilium (only if in-place migration is a goal; otherwise a clean-state install is simpler),
and the nsenter-style init containers without a shell.

## Recommendation

**keep (as contract), replace (as implementation)**. Keep the Helm chart, ConfigMap key space, object names,
hostPath set and probe endpoints; replace all shell/init scripts and external binaries with subcommands of a
single static Rust binary; drop clang/iptables/ipset/bash/Envoy from the agent image. Reuse upstream images for
Envoy, Hubble relay/UI, clustermesh-apiserver, nodeinit, certgen, SPIRE. Adopt cilium-cli connectivity test,
BPF unit test harness, verifier matrix and LVH kernel set as flowsdn's acceptance gates.
Effort: chart fork + config plumbing **M** (2–8k: values passthrough, flag registry, build-config, validate);
init/cleanup/CNI-install/mount/sysctl subcommands **S–M**; native nftables replacement for the iptables
rule set **M**; test harness ports (bpftest driver, verifier runner, controlplane fixture loader) **M**;
CI workflow port (kind+LVH matrix, cloud jobs) **M**.

## Open questions

1. Minimum kernel for flowsdn: if 5.10/5.15 is kept, `CAP_BPF`/`CAP_PERFMON` exist (≥5.8) but the RHEL 4.18
   path (rhel8.10 in the matrix) still needs `SYS_ADMIN` — support both via a values switch, or drop 4.18?
2. Resolved #33: follow ADR0003/spec22: BPF-only masquerade, nftables residual
   including NOTRACK, compatibility warnings for ignored iptables controls.
   Kube-proxy coexistence remains governed by routing validation.
3. Embedded Envoy mode (`envoy.enabled=false`) requires the Envoy binary in the agent image — drop it and force
   the DaemonSet (upgradeCompatibility <1.16 users)?
4. Resolved #38: verified host-managed mounts or configured init helpers;
   wrong filesystem types fail closed (spec22 packaging policy).
5. Should `cilium status` JSON and the agent unix API (`/var/run/cilium/cilium.sock`, OpenAPI) be reproduced
   bit-for-bit so cilium-cli, hubble and bugtool keep working, or is a `flowsdn-cli` fork acceptable?
6. **Resolved #35:** pin cilium-cli v0.19.7 at commit
   `7ca7fc53c20275f5c10ef5f3557076691fd1d720`, matching the reference pin.
   `ci/acceptance-matrix.json` selects the supported 6.6/6.12/6.18 lines and
   spec19’s 12 configurations, with one privileged VM at a time and two build
   jobs. Gate changes on three 6.12 configurations; rotate remaining rows
   nightly and require all supported rows before release. Do not schedule
   unsupported 5.15/6.1 or adopt the upstream 41-config fleet. This is the
   resource-budget decision; workflow provisioning and measured runtimes remain
   release obligations, not claimed results.
7. **Resolved #36:** recovered the removed HostPort, dual-stack services, graceful-termination
   and NodePort static inputs/goldens from pinned v1.16.0/v1.17.0 into
   `tests/golden/controlplane-legacy`: 100 source records, 68 unique files,
   exact per-file provenance and Rust verification. Runtime adapters remain pending.
8. **Resolved #37:** F7 now records measured bytes from the pulled v1.20.1
   image with immutable digest and machine-readable validation evidence.
