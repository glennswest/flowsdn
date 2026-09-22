# IPAM and cloud IPAM modes — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/ipam/**`,
`pkg/ipam/types`, `pkg/ipam/service/**`, `pkg/ipam/cidrset`, `pkg/ipam/metadata`,
`pkg/ipam/podippool`, `pkg/ipam/cell`, `pkg/ipam/api`, `pkg/ipalloc`, `pkg/aws/**`,
`pkg/azure/**`, `pkg/alibabacloud/**`, `pkg/nodediscovery/**` (cloud spec seeding),
`pkg/datapath/linux/routing` (per-endpoint ENI/Azure rules), `operator/pkg/ipam/**`,
`operator/option/config.go`, `operator/watchers/cilium_node_gc_cell.go`,
`pkg/k8s/apis/cilium.io/v2/types.go` (CiliumNode), `pkg/k8s/apis/cilium.io/v2alpha1/ippool_types.go`
(CiliumPodIPPool), `plugins/cilium-cni/chaining/{awscni,azure,generic-veth}`,
`plugins/cilium-cni/cmd/interface.go`, `daemon/infraendpoints/infra_ip_allocation.go`.

This area is HIGH PRIORITY for flowsdn: the cloud modes are documented completely.

## Purpose

IPAM decides which IP a pod (or Cilium's own router/health/ingress endpoints) gets
on a node, and in the cloud modes also makes the VPC aware of that IP (secondary
IPs / prefixes on ENIs, Azure IP configurations, Alibaba ENI private IPs). The
agent side (`pkg/ipam`) exposes one `Allocator` interface with several backends:
a per-node CIDR bitmap (`kubernetes`, `cluster-pool`), a CIDR-list pool manager
driven by the operator through `CiliumNode.spec.ipam.pools` (`multi-pool`, and
since 1.20 also `eni`), a per-IP CRD pool driven by the operator through
`CiliumNode.spec.ipam.pool` (`crd`, `azure`, `alibabacloud`), and a no-op for
`delegated-plugin`. The operator side (`operator/pkg/ipam`) owns the cluster-wide
view: it carves pod CIDRs (cluster-pool, multi-pool) or talks to the cloud API to
attach interfaces and IPs (ENI, Azure, Alibaba), writes the result into
`CiliumNode`, and runs the excess-IP release handshake. The datapath consequence
of cloud IPAM is a per-endpoint policy-routing setup (ip rules + per-interface
route tables) installed by the CNI plugin from `AllocationResult` metadata.

## Components

Line counts are `wc -l` of non-test Go files unless stated (tests listed in
"Tests").

| Path | Lines | Purpose |
|---|---|---|
| `pkg/ipam/ipam.go` | 271 | `IPAM` struct, `ConfigureAllocator()` mode switch, owner bookkeeping, `ExcludeIP` |
| `pkg/ipam/allocator.go` | 494 | `AllocateIP*`, `AllocateNext*`, `ReleaseIP`, expiration timers, `Dump`, agent metrics |
| `pkg/ipam/types.go` | 199 | `AllocationResult`, `Allocator` interface, `Pool`, `IPAM` fields |
| `pkg/ipam/hostscope.go` | 84 | bitmap allocator over one CIDR (`kubernetes`, `cluster-pool`) |
| `pkg/ipam/noop_allocator.go` | 47 | `delegated-plugin` allocator (all ops return not supported) |
| `pkg/ipam/pool.go` | 417 | `cidrPool`: one `ipallocator.Range` per CIDR, release of excess CIDRs, unreachable-route cleanup |
| `pkg/ipam/multipool.go` | 277 | `multiPoolAllocator` (per family), pool readiness waits, `startLocalNodeAllocCIDRsSync` |
| `pkg/ipam/multipool_manager.go` | 1000 | `multiPoolManager`: demand computation, `CiliumNode.spec.ipam.pools` read/write, pending allocations, static IP wait |
| `pkg/ipam/eni.go` | 757 | ENI mode on the agent: device configurator (MTU/up/addr/rp_filter), native-routing-CIDR autodetect, `eniPoolAccessor`, `eniMultiPoolAllocator` enrichment |
| `pkg/ipam/crd.go` | 984 | `nodeStore` + `crdAllocator` for `crd`/`azure`/`alibabacloud`: CiliumNode informer, agent side of release handshake, `Status.IPAM.Used` sync |
| `pkg/ipam/option/option.go` | 48 | mode names, release-handshake state strings, `ENIPDBlockSizeIPv4 = 16` |
| `pkg/ipam/types/types.go` | 1788 (incl. generated deepcopy/deepequal) | `IPAMSpec`, `IPAMStatus`, `AllocationMap`, `IPAMPoolSpec`, `Limits`, `Subnet`, `VirtualNetwork`, `RouteTable`, `InstanceMap`, `PoolQuota` |
| `pkg/ipam/cell/cell.go`, `ipam_init.go` | 444 | hive cell, `--only-masquerade-default-pool`, REST handler wiring, alloc-CIDR autocomplete from `--ipv4-range` / node annotations |
| `pkg/ipam/api/ipam_api_handler.go` | 168 | `POST /ipam`, `POST /ipam/{ip}`, `DELETE /ipam/{ip}` handlers |
| `pkg/ipam/metadata/manager.go`, `cell.go` | 400 | maps pod owner -> pool via `ipam.cilium.io/*` annotations, namespace annotations, `CiliumPodIPPool` selectors |
| `pkg/ipam/podippool/podippool.go` | 171 | statedb table `LocalPodIPPool` reflected from `CiliumPodIPPool` |
| `pkg/ipam/service/ipallocator/allocator.go` | 324 | `Range` bitmap allocator over a prefix (k8s-derived), `NewCIDRRange`, first/last IP options |
| `pkg/ipam/service/allocator/*.go` | 264 | bitmap `Interface`, big.Int-backed `AllocationBitmap` |
| `pkg/ipam/cidrset/cidr_set.go` | 287 | `CidrSet`: carve fixed-size node CIDRs out of a cluster prefix (k8s-derived) |
| `pkg/ipalloc/ipalloc.go`, `adapter.go` | 756 | generic `Allocator[T]` (`HashAllocator`, block list); used by LB-IPAM and BGP, not by pod IPAM |
| `pkg/aws/api/api.go` | 1172 | EC2 client wrapper: describe/create/attach/modify ENI, assign/unassign IPs and prefixes, EIP association, rate limiter, pagination fallback |
| `pkg/aws/api/mock/mock.go` | 848 | in-memory EC2 mock used by tests |
| `pkg/aws/ipam/node.go` | 1238 | per-node ENI `NodeOperations`: allocation prep, ENI creation, subnet/SG selection, prefix delegation, release |
| `pkg/aws/ipam/instances.go` | 415 | `InstancesManager`: cached VPCs/subnets/SGs/route tables/ENIs, resync |
| `pkg/aws/ipam/limits/limits.go` | 191 | `LimitsGetter`: per-instance-type limits from `DescribeInstanceTypes` |
| `pkg/aws/ipam/eni_gc.go` | 75 | dangling ENI garbage collector |
| `pkg/aws/metadata/metadata.go` | 103 | IMDS: instance-id, instance-type, mac, vpc-id, subnet-id, AZ |
| `pkg/aws/types/types.go` | 251 (+670 generated) | `ENISpec`, `ENI`, `ENIStatus`, `AwsVPC`, `AwsSubnet`, `SecurityGroup` |
| `pkg/azure/api/api.go` | 1267 | ARM client: NIC listing (VM + VMSS), subnet lookup, IP-configuration assignment, public IP (static IP) assignment |
| `pkg/azure/ipam/node.go`, `instances.go` | 546 | per-node/instances manager for Azure |
| `pkg/azure/metadata/metadata.go` | 79 | Azure IMDS: subscriptionId, resourceGroupName, azEnvironment |
| `pkg/azure/types/*.go` | 171 (+255 generated) + `azureid` 69 | `AzureSpec`, `AzureStatus`, `AzureInterface`, `AzureAddress`, `AzureSubnet`, resource-ID parsing |
| `pkg/alibabacloud/api/api.go` | 734 | ECS/VPC client wrapper: describe instances/ENIs/vSwitches/VPCs/SGs, create/attach/delete ENI, assign/unassign IPs |
| `pkg/alibabacloud/ipam/node.go`, `instances.go` | 807 | per-node/instances manager for Alibaba ENI |
| `pkg/alibabacloud/ipam/limits/limits.go` | 68 | instance-type limits from `DescribeInstanceTypes` |
| `pkg/alibabacloud/metadata/metadata.go` | 76 | Alibaba metadata: instance-id, instance-type, region-id, zone-id, vpc-id, vpc-cidr-block |
| `pkg/alibabacloud/types/*.go` | 242 (+584 generated) | `Spec`, `ENI`, `ENIStatus`, `VPC`, `VSwitch`, ENI index tag |
| `pkg/nodediscovery/nodediscovery_{eni,azure,alibabacloud}.go`, `eni/eni.go` | 340 | agent seeds `CiliumNode.spec.{eni,azure,alibaba-cloud,ipam}` from IMDS + flags + CNI conf |
| `pkg/nodediscovery/cell.go` | 106 | node-level flags: `ipam-{min,pre,max}-allocate`, `ipam-static-ip-tags`, `eni-*` |
| `pkg/datapath/linux/routing/routing.go`, `info.go` | 578 | per-endpoint ip rules and per-interface route tables for ENI/Azure/delegated modes |
| `operator/pkg/ipam/cell.go` | 46 | `--parallel-alloc-workers`, `--limit-ipam-api-{qps,burst}` |
| `operator/pkg/ipam/aws.go` | 126 | AWS operator flags and allocator start |
| `operator/pkg/ipam/azure.go` | 94 | Azure operator flags and allocator start |
| `operator/pkg/ipam/alibabacloud.go` | 86 | Alibaba operator flags and allocator start |
| `operator/pkg/ipam/clusterpool.go` | 116 | `--cluster-pool-ipv{4,6}-cidr`, `--cluster-pool-ipv{4,6}-mask-size` |
| `operator/pkg/ipam/multipool.go` | 41 | multi-pool cell registration |
| `operator/pkg/ipam/cloud_allocator.go`, `nodewatcher.go` | 185 | generic cloud allocator lifecycle, CiliumNode watch -> `NodeEventHandler` |
| `operator/pkg/ipam/allocator/types.go` | 38 | `NodeEventHandler`, `CiliumNodeGetterUpdater` interfaces |
| `operator/pkg/ipam/allocator/aws/aws.go` | 160 | `AllocatorAWS.Init/Start`: SDK config, endpoint override, GC tags, `NodeManager` |
| `operator/pkg/ipam/allocator/azure/azure.go` | 88 | `AllocatorAzure.Init/Start`: IMDS-derived subscription/RG/cloud |
| `operator/pkg/ipam/allocator/alibabacloud/alibabacloud.go` | 108 | `AllocatorAlibabaCloud.Init/Start`: region from metadata, VPC endpoints |
| `operator/pkg/ipam/allocator/clusterpool/*.go` | 163 | cluster-pool operator: `CIDRAllocator` sets + `NodesPodCIDRManager` |
| `operator/pkg/ipam/allocator/podcidr/podcidr.go` | 948 | `NodesPodCIDRManager`: per-node pod CIDR allocation, k8s sync queue |
| `operator/pkg/ipam/allocator/multipool/*.go` | 1719 | `PoolAllocator`, `NodeHandler`, pool spec parsing, cluster-pool -> multi-pool migration |
| `operator/pkg/ipam/nodemanager/node.go` | 1563 | per-node reconciliation: watermarks, allocation/release actions, handshake, CiliumNode sync |
| `operator/pkg/ipam/nodemanager/node_manager.go` | 590 | `NodeManager`, `NodeOperations` / `AllocationImplementation` interfaces, resync, worker pool |
| `operator/pkg/ipam/metrics/metrics.go` | 362 | operator IPAM Prometheus metrics |
| `operator/pkg/ipam/stats/stats.go` | 29 | `InterfaceStats` |
| `plugins/cilium-cni/chaining/{awscni,azure}` | ~30 | register `aws-cni` / `azure` chaining modes onto `generic-veth` |
| `plugins/cilium-cni/cmd/interface.go` (ENI part) | ~80 | builds `RoutingInfo` from `IPAMAddressResponse` and calls `Configure` |

Approximate non-test totals: agent IPAM core ~8.3k, AWS ~3.7k (+0.85k mock),
Azure ~2.1k (+0.3k mock), Alibaba ~1.9k (+0.36k mock), operator IPAM ~7.6k,
`pkg/ipalloc` 0.76k, routing 0.58k. Grand total ~25k lines of Go excluding tests.

## Features

Mode selection: agent flag `--ipam` (`option.IPAM`), default `cluster-pool`
(`daemon/cmd/daemon_main.go:358`). Helm `ipam.mode` (default `"cluster-pool"`).
Operator reads the same `DaemonConfig.IPAM` and starts the matching allocator
cell (`operator/pkg/ipam/cloud_allocator.go:startCloudAllocator` checks
`b.DaemonCfg.IPAM != mode`). Valid values (`pkg/ipam/option/option.go`):
`kubernetes`, `crd`, `eni`, `azure`, `cluster-pool`, `multi-pool`,
`alibabacloud`, `delegated-plugin`.

### `kubernetes` (host-scope from Node.spec.podCIDR)
- Who allocates: kubelet/kube-controller-manager assigns `Node.spec.podCIDRs`;
  agent reads them (node annotations / `k8s.Init`) into `LocalNode.IPv{4,6}AllocCIDR`
  and runs `hostScopeAllocator` (`pkg/ipam/hostscope.go`) over the CIDR. Operator
  does nothing for IPAM.
- `--k8s-require-ipv4-pod-cidr` (default false): fail if Node has no IPv4 podCIDR.
- `--ipv4-range` / `--ipv6-range` (default `auto`): explicit per-node prefix,
  overrides k8s (`pkg/ipam/cell/ipam_init.go`). Default fallback prefix
  `defaults.DefaultIPv4Prefix/<len>` derived from node IP / IPv6 range.
- GKE Dataplane V2 relies on this mode: Helm `gke.enabled=true` forces
  `routing-mode: native`, `enable-endpoint-routes: "true"`,
  `enable-health-check-loadbalancer-ip: "true"`, and IPAM stays `kubernetes`
  (`install/kubernetes/cilium/templates/cilium-configmap.yaml:547-558,902`).
  There is no GCP API code in Cilium; `grep -rw gke pkg/ operator/` yields only
  two comments about the GKE NEG controller in Gateway/Ingress translation.
  Docs: `Documentation/network/concepts/ipam/gke.rst`.

### `cluster-pool` (default)
- Who allocates: operator carves per-node CIDRs from
  `--cluster-pool-ipv4-cidr` (list, Helm `ipam.operator.clusterPoolIPv4PodCIDRList`
  default `["10.0.0.0/8"]`) with `--cluster-pool-ipv4-mask-size` (default 24), and
  `--cluster-pool-ipv6-cidr` / `--cluster-pool-ipv6-mask-size` (default 112)
  (`operator/pkg/ipam/clusterpool.go`). `operator/pkg/ipam/allocator/clusterpool/cidralloc`
  wraps `pkg/ipam/cidrset.CidrSet`; `allocator/podcidr.NodesPodCIDRManager` writes
  `CiliumNode.spec.ipam.podCIDRs` and syncs to k8s every `updateK8sInterval = 15s`
  batch, reporting failures in `status.ipam.operator-status.error`.
- Agent: same `hostScopeAllocator` as `kubernetes`, reading the first CIDR from
  `spec.ipam.podCIDRs`. Multiple CIDRs per node are tracked in
  `status.ipam.pod-cidrs[cidr].status` (`released|depleted|in-use`).
- Validation: `cluster-pool-ipv4-cidr must be provided when using ClusterPool`,
  must not be set when IPv4 disabled (`allocator/clusterpool/clusterpool.go:49-72`).
- Helm `nativeRoutingCIDRFromClusterPool` derives native routing CIDR from the
  single cluster-pool CIDR.

### `multi-pool` (CiliumPodIPPool)
- Who allocates: operator `PoolAllocator` (`allocator/multipool/pool_allocator.go`)
  holds one `cidrSets` per pool (v4 and v6) and per node; agent requests IPs per
  pool through `CiliumNode.spec.ipam.pools.requested[]` and the operator answers
  in `spec.ipam.pools.allocated[]`. Agent removes released CIDRs from
  `allocated`; operator adds new ones. Operator detects a multi-pool agent by
  `len(spec.ipam.pools.requested) > 0 && len(status.ipam.used) == 0`
  (`nodemanager/node.go:isMultiPoolNodeLocked`).
- Pools come from `CiliumPodIPPool` (cluster-scoped, `cpip`) or are auto-created
  from operator flag `--auto-create-cilium-pod-ip-pools` (Helm
  `ipam.operator.autoCreateCiliumPodIPPools.<name>.ipv4.{cidrs,maskSize}`), syntax
  `<pool>=ipv4-cidrs:<cidr>[,<cidr>];ipv4-mask-size:<n>[;allow-first-ip:<bool>][;allow-last-ip:<bool>]`.
- Pod -> pool selection (`pkg/ipam/metadata/manager.go`): pod annotation
  `ipam.cilium.io/ipv4-pool` / `ipam.cilium.io/ipv6-pool` / `ipam.cilium.io/ip-pool`,
  else the same annotations on the Namespace, else `CiliumPodIPPool.spec.podSelector`
  + `namespaceSelector` (synthetic labels `io.kubernetes.pod.namespace`,
  `io.kubernetes.pod.name`; more than one matching pool = allocation failure and a
  warning event), else `--ipam-default-ip-pool` (default `default`).
- Pre-allocation: agent flag `--ipam-multi-pool-pre-allocation` (map
  `pool=count`, default `{default: "8"}` when empty,
  `pkg/option/config.go:2828`). Demand formula (`multipool_manager.go`):
  `needed = neededIPCeil(inUse + pending, preAlloc)` where `neededIPCeil` rounds up
  so at least one full `preAlloc` buffer is always free (16 -> 32 for 1..16 in use).
  Pending allocations expire after `pendingAllocationTTL = 5m`; pools are refreshed
  by `refreshPoolInterval = 1m`; startup waits up to `waitForPoolTimeout = 3m`.
- `--only-masquerade-default-pool` (agent, requires `--enable-bpf-masquerade`):
  sets `AllocationResult.SkipMasquerade` for non-default pools (BGP use case).
- Operator flags: `--enable-cluster-pool-to-multi-pool-migration` (default false),
  `--multi-pool-migration-workers` (16), `--ipam-default-ip-pool` (`default`).
  Migration script test: `pkg/ipam/migration/testdata/from-cluster-pool-migration.txtar`.
- Orphan handling: CIDRs found in `spec.ipam.pools.allocated` that the operator
  does not know are tracked as orphans until the pool exists (`markOrphan`,
  `reconcileOrphanCIDRs`).

### `crd` (manual CiliumNode pool)
- Who allocates: a user or external controller writes `CiliumNode.spec.ipam.pool`
  (`map[ip]{owner,resource}`); agent `crdAllocator` (`pkg/ipam/crd.go`) picks
  from it and reports `status.ipam.used`. In `crd` mode only, an entry with
  `owner == <pod owner>` is a pinned IP for that owner (`nodeStore.allocateNext`).
- Agent waits at startup until `len(spec.ipam.pool) >= required` where required =
  `min-allocate` else `pre-allocate` else 2 (if health checking) else 1
  (`hasMinimumIPsInPool`), logging "Check if cilium-operator pod is running".
- CiliumNode status updates rate-limited by `--ipam-cilium-node-update-rate`
  (default 15s, trigger `crd-allocator-node-refresher`).

### `eni` (AWS)
- Who allocates: operator (`AllocatorAWS`) creates/attaches ENIs and assigns
  secondary IPs or /28 prefixes; agent consumes. In v1.20 the agent uses the
  multi-pool manager with `eniPoolAccessor` (`pkg/ipam/eni.go`): allocated CIDRs
  are derived from `status.eni.enis[*].{addresses (as /32), prefixes (/28),
  ipv6-prefixes (/80)}` into a single `default` pool with `allowFirstIP` and
  `allowLastIP`; demand is linear `inUse + preAllocate` (`LinearPreAlloc: true`)
  so the operator can recover usage as `requested - pre-allocate`. Legacy 1.19
  agents (CRD allocator, `status.ipam.used` populated) are still served by the
  operator's per-IP handshake path (`PrepareIPRelease`/`ReleaseIPs`, marked
  "1.19 and below", to be removed in 1.21).
- Agent seeds `spec.eni` from IMDS + flags (`pkg/nodediscovery/eni/eni.go`):
  `instance-id`, `instance-type`, `availability-zone`, `vpc-id`, `node-subnet-id`,
  plus flags `--eni-first-interface-index` (default 0), `--eni-use-primary-address`
  (false), `--eni-disable-prefix-delegation` (false), `--eni-delete-on-termination`
  (true), `--eni-subnet-ids`, `--eni-subnet-tags`, `--eni-security-groups`,
  `--eni-security-group-tags`, `--eni-exclude-interface-tags`, `--ipam-min-allocate`,
  `--ipam-pre-allocate`, `--ipam-max-allocate`, `--ipam-static-ip-tags`. CNI
  custom netconf (`cni.customConf`) `ipam.{min-allocate,pre-allocate}` and
  `eni.*` override the flags per node.
- Operator flags (`operator/pkg/ipam/aws.go`): `--aws-release-excess-ips` (false),
  `--excess-ip-release-delay` (180 s), `--aws-enable-prefix-delegation` (false),
  `--eni-tags` (k=v), `--eni-gc-tags` (default
  `io.cilium/cilium-managed=true, io.cilium/cluster-name=<cluster-name or EKS
  cluster tag>`), `--eni-gc-interval` (5m, 0 disables; deletes at most
  `ENIGarbageCollectionMaxPerInterval = 25` per run), `--aws-use-primary-address`
  (false), `--ec2-api-endpoint` (sets `BaseEndpoint = https://<value>`),
  `--aws-max-results-per-call` (0 = let AWS choose, auto-switch to 1000 on
  `OperationNotPermitted`), `--subnet-ids-filter`, `--subnet-tags-filter`,
  `--instance-tags-filter` (shared with Alibaba), `--parallel-alloc-workers` (50),
  `--limit-ipam-api-qps` (4.0), `--limit-ipam-api-burst` (20). Helm `eni.*`
  mirrors these; `eni.iamRole` sets the IRSA role annotation on the operator SA.
  Not present in v1.20.1: `update-ec2-adapter-limit-via-api`,
  `aws-instance-limit-mapping` — limits now always come from the EC2 API (below).
- Instance limits (`pkg/aws/ipam/limits/limits.go`): `LimitsGetter` calls
  `DescribeInstanceTypes` (paginated) and stores
  `{Adapters=MaximumNetworkInterfaces, IPv4=Ipv4AddressesPerInterface,
  IPv6=Ipv6AddressesPerInterface, HypervisorType, IsBareMetal}`; refresh trigger
  min interval 1m, API timeout 5s, retry count 2; a miss triggers a refresh. There
  is no embedded JSON limits table anymore.
- ENI creation (`pkg/aws/ipam/node.go:CreateInterface`): subnet selection order
  is `spec.eni.subnet-ids` -> `spec.eni.subnet-tags` -> node's own subnet if it
  has `>= limits.IPv4` free -> any subnet sharing a route table with the node
  subnet -> any subnet in VPC+AZ with most free IPs (`findSuitableSubnet`;
  route-table mismatch is logged). Security groups: `spec.eni.security-groups` ->
  `security-group-tags` -> eth0's groups. Description `Cilium-CNI (<instance-id>)`,
  tags `--eni-tags` merged with GC tags. Attachment index starts at
  `first-interface-index`, retried up to `maxAttachRetries = 5` on index conflict;
  on attach failure the ENI is deleted. `ModifyNetworkInterface` sets
  `delete-on-termination`. Number of IPs on create: `min(MaxIPsToAllocate,
  limits.IPv4-1)` (or prefixes `limits.IPv4-1`); on `InsufficientCidrBlocks` the
  create is retried without prefixes.
- Prefix delegation: enabled when `--aws-enable-prefix-delegation` and instance
  is nitro or bare metal and `spec.eni.disable-prefix-delegation` is not true and
  no ENI already carries plain secondary IPs (`IsPrefixDelegated`). Each /28 =
  16 IPs (`ENIPDBlockSizeIPv4`). IPv6 uses /80 prefixes (`AssignENIIPv6Prefix`).
  `GetMaximumAllocatableIPv4 = (Adapters - firstIndex) * (IPv4-1) [* 16 if PD]`;
  `GetMinimumAllocatableIPv4 = min(8, (Adapters-index)*(IPv4-1))`.
- Static IP: `spec.ipam.static-ip-tags` selects an Elastic IP by tags;
  `AssociateEIP` attaches it to the primary ENI and the result is written to
  `status.ipam.assigned-static-ip`; agent blocks startup until set
  (`waitForStaticIP`).
- ENI exclusion: `spec.eni.exclude-interface-tags` (ENI.IsExcludedBySpec) and
  ENIs with index `< first-interface-index` are never used for pods.
- Agent device configuration (`configureENINetlinkDevice`): for each new ENI in
  status: set MTU (`mtu.GetDeviceMTU()`), link up; unless `use-primary-address`,
  add the ENI primary IP `/<subnet bits>` to the link, delete a networkd-style
  subnet route in `main` with that src, and `sysctl -w net.ipv4.conf.<dev>.rp_filter=0`.
  Waits for the link by MAC with up to 15 tries (100 ms .. 30 s backoff), then
  re-fetches after 1 s to survive `eth0 -> ensX` rename.
- Native routing CIDR autodetect (`startENINativeRoutingCIDRSync`): the VPC
  primary CIDR from `status.eni.enis[*].vpc.primary-cidr` becomes
  `LocalNode.IPv4NativeRoutingCIDR` unless `--ipv4-native-routing-cidr` is set,
  in which case it must overlap the VPC CIDR (fatal otherwise). Agent waits up
  to 5 minutes for the operator to populate it.
- `AllocationResult` enrichment (`buildENIAllocationResult`): `PrimaryMAC =
  eni.mac`, `CIDRs = VPC primary + secondary CIDRs + native routing CIDRs +
  ip-masq-agent non-masq CIDRs`, `GatewayIP = subnet first IP + 1` (v4) or
  `fe80:ec2::1` (v6), `InterfaceNumber = eni.number`.
- Helm `eni.enabled=true` defaults `routingMode` to `native`.

### `azure`
- Who allocates: operator (`AllocatorAzure`) adds IP configurations to the
  VM/VMSS NIC; agent uses the CRD allocator over `spec.ipam.pool` (per-IP map,
  `resource = interface ID`). No interface creation (`CreateInterface` returns
  an error; Azure NIC count is fixed at VM creation).
- Operator flags (`operator/pkg/ipam/azure.go`): `--azure-subscription-id`
  (default from IMDS `instance/compute/subscriptionId`), `--azure-resource-group`
  (default from IMDS `resourceGroupName`), `--azure-user-assigned-identity-id`
  (MSI client ID; empty = `DefaultAzureCredential` chain incl. env-var service
  principal), `--azure-use-primary-address` (false). Cloud selected from IMDS
  `azEnvironment`: `AzurePublicCloud`, `AzureUSGovernmentCloud`, `AzureChinaCloud`.
  Helm `azure.{subscriptionID,resourceGroup,tenantID,clientID,clientSecret,
  userAssignedIdentityID,usePrimaryAddress}`; `azure.nodeSpec.azureInterfaceName`.
- Agent seeds `spec.azure.interface-name` (`--azure-interface-name` /
  CNI conf) and `spec.ipam.{min,pre,max}-allocate`
  (`pkg/nodediscovery/nodediscovery_azure.go`). Instance ID is the k8s
  `providerID` (`azure://` prefix) parsed by `pkg/azure/types/azureid`.
- Limits: fixed `InterfaceAddressLimit = 256` per NIC (minus 1 when the primary
  is not exposed). `GetMinimumAllocatableIPv4 = 8`.
- Allocation (`pkg/azure/ipam/node.go:PrepareIPAllocation`): pick the interface
  matching `spec.azure.interface-name` (or any) with free slots; pool ID is the
  subnet ID (prefers the interface's own subnet); `AllocateIPs` calls
  `AssignPrivateIpAddressesVMSS` (`VirtualMachineScaleSetVMs.BeginUpdate` with new
  `ipconfig-<random>` entries, copying ASGs, poll to completion) or
  `AssignPrivateIpAddressesVM` (`Interfaces.CreateOrUpdate`). Static IP: public IP
  from a `PublicIPPrefix` selected by tags (`AssignPublicIPAddressesVM[SS]`).
- Agent `AllocationResult` (`crd.go:buildAllocationResult`): `PrimaryMAC =
  iface.mac`, `GatewayIP = iface.gateway` (subnet first IP + 1), `CIDRs = subnet
  CIDR + native routing CIDR + ip-masq-agent CIDRs`, `InterfaceNumber = "0"`.
  Datapath uses the compat egress priority for Azure (see External interfaces).
- Release: `PrepareIPRelease`/`ReleaseIPs` are no-ops (Azure never releases
  secondary IP configurations), `ReleaseExcessIPs` is passed as `false`.
- Deprecated CRD fields kept for one release: `AzureInterface.cidr`
  (use `subnet.cidr`), `AzureAddress.subnet` (issue #46074).
- AKS BYOCNI (`aksbyocni.enabled`) is not Azure IPAM: it forces tunnel mode with
  cluster-pool; `azure.enabled` is incompatible with BYOCNI clusters.

### `alibabacloud`
- Who allocates: operator (`AllocatorAlibabaCloud`) creates/attaches ENIs and
  assigns private IPs; agent uses the CRD allocator over `spec.ipam.pool`
  (`resource = network-interface-id`).
- Operator flags (`operator/pkg/ipam/alibabacloud.go`): `--alibaba-cloud-vpc-id`
  (default: operator's own VPC from metadata), `--alibaba-cloud-release-excess-ips`
  (false), `--instance-tags-filter` (max `MaxInstanceTags`). Region from metadata
  `region-id`; clients built with `ecs.NewClientWithProvider` / `vpc.NewClientWithProvider`
  (SDK default credential chain: env AK/SK, RAM role, ECS RAM role via metadata),
  `Network = "vpc"` endpoints (`ecs-vpc.<region>.aliyuncs.com`) so no public egress.
- Agent seeds `spec.alibaba-cloud.{instance-type, availability-zone, vpc-id,
  cidr-block, vswitches, vswitch-tags, security-groups, security-group-tags}` from
  metadata and flags (`nodediscovery_alibabacloud.go`).
- Limits: `limits.UpdateFromAPI` via `DescribeInstanceTypes`
  (`EniQuantity`, `EniPrivateIpAddressQuantity`, `EniIpv6AddressQuantity`).
  `GetMaximumAllocatableIPv4 = (Adapters-1) * IPv4` (primary ENI reserved).
- ENI creation (`pkg/alibabacloud/ipam/node.go:CreateInterface`): vSwitch chosen by
  `spec.vswitches` IDs else VPC+AZ+tags with most free IPs and `>= toAllocate`
  (`FindOneVSwitch`); first allocation capped at `maxENIIPCreate` (10); SG order
  `security-groups` -> `security-group-tags` -> primary ENI's groups; ENI index is
  stored as tag `cilium-eni-index` (`types.FillTagWithENIIndex`) since Alibaba has
  no attachment index; `AttachNetworkInterface` then `WaitENIAttached`.
- Agent `AllocationResult`: `PrimaryMAC = eni.mac-address`, `CIDRs = [vswitch
  cidr]`, `GatewayIP = last IP of vSwitch - 2` (Alibaba reserves the third-to-last
  address), `InterfaceNumber = cilium-eni-index tag`.
- Release handshake: same 4-state protocol as AWS legacy path when
  `--alibaba-cloud-release-excess-ips`, `excess-ip-release-delay` fixed at 0.

### `delegated-plugin`
- Cilium CNI calls another IPAM plugin (CNI spec delegation); agent uses
  `noOpAllocator`. Requires native routing, `--local-router-ipv4/6` (router IP
  not from a pool), `endpointHealthChecking.enabled=false`, BPF masquerade with
  `ipMasqAgent` (iptables masquerade needs a pod CIDR). Optional
  `--install-uplink-routes-for-delegated-ipam` (false) installs ingress/egress
  routes via uplink. `RoutingInfo` is also used in this mode (see below).

### CNI chaining onto a cloud CNI (`aws-cni`, `azure`)
- `plugins/cilium-cni/chaining/awscni` and `.../azure` register the mode names
  onto `GenericVethChainer`. The cloud CNI creates the veth and assigns the IP;
  Cilium creates the endpoint with `DatapathConfiguration{RequireArpPassthrough:
  true, RequireEgressProg: true, ExternalIpam: true, RequireRouting: disabled}`.
  IPAM mode is then irrelevant to pods (CI uses `ipam.mode=cluster-pool` with
  `eni.enabled=false`, `routingMode=native`, `enableIPv4Masquerade=false`,
  `cni.chainingMode=aws-cni`). Policy works because the endpoint still exists in
  the agent and its IP is inserted in ipcache with the pod identity; the
  host-facing egress program on the veth enforces ingress policy and reverse
  NAT. `aws-cni` chaining excludes cluster IDs with bit 0x80 set
  (`pkg/clustermesh/types/option.go:72`) and changes iptables masquerade rules
  (`pkg/datapath/iptables/iptables.go:1384`).

### Cross-cutting
- IP release handshake (CRD-based cloud modes; documented in Data model).
- Expiration timers: `POST /ipam` with header `expiration: true` starts a
  `defaults.IPAMExpiration = 10m` timer; the CNI stops it via
  `expiration-uuid` after endpoint creation; otherwise the IP is auto-released.
- `--enable-unreachable-routes` (false): on pod deletion an `unreachable` route
  for the released IP is added in `main`; removed again when the IP leaves
  `spec.ipam.pool` / the CIDR is released (`crd.go`, `pool.go:cleanupUnreachableRoutes`).
- Router/health/ingress IPs (`daemon/infraendpoints/infra_ip_allocation.go`) are
  allocated from the same allocator with `AllocateNextFamilyWithoutSyncUpstream`;
  in ENI/Azure modes the health endpoint gets its own `RoutingInfo`
  (`GetHealthEndpointRouting`) and `--local-router-ipv4/6` can pin the router IP.
- CiliumNode GC (operator `--nodes-gc-interval`, default 5m): deletes CiliumNodes
  whose k8s Node is gone.
- Egress gateway: in v1.20.1 there is no `install-egress-gateway-routes`,
  `enable-ipv4-egress-gateway` or `egress-multi-home-ip-rule-compat` flag
  (grep over `pkg/ daemon/ plugins/ operator/` finds none); the compat priority
  is chosen purely by IPAM mode. `--enable-egress-gateway` is generic and the
  egress-gateway package has no ENI-specific code. Historically the egress
  gateway on ENI needed the pod's `from <podIP>` rule to be lower priority than
  the egress-gateway rule; the v2 priority 111 scheme is what remains.
- `--egress-masquerade-interfaces` (`MasqueradeInterfaces []string`): limits
  iptables masquerade to the named interfaces; with ENI the recommendation is
  `eth+` / `ens+` so secondary ENIs are covered.

## Data model

### CiliumNode (`cilium.io/v2`, cluster-scoped) — IPAM-relevant schema
`spec` (`NodeSpec`, `pkg/k8s/apis/cilium.io/v2/types.go`):
- `instance-id` (string): cloud instance ID (EC2 `i-...`, Azure providerID, ECS ID).
- `ipam` (`IPAMSpec`, `pkg/ipam/types/types.go`):
  - `pool` (`map[ip]AllocationIP{owner,resource}`): IPv4 addresses available to
    the node (crd/azure/alibaba). Written by operator (or user in `crd`).
  - `ipv6-pool`: same for IPv6.
  - `pools` (`IPAMPoolSpec`): `requested[] {pool, needed{ipv4-addrs,ipv6-addrs}}`
    written by agent; `allocated[] {pool, allowFirstIP, allowLastIP, cidrs[]}`
    operator adds, agent removes (multi-pool; ENI mode writes `requested` only,
    `allocated` is derived from `status.eni`).
  - `podCIDRs[]`: cluster-pool node CIDRs (operator writes).
  - `min-allocate` (int, min 0): minimum IPs at bootstrap.
  - `max-allocate` (int): hard cap; pre-allocate shrinks toward 0 near it.
  - `pre-allocate` (int): free buffer target; default 8 (`defaults.IPAMPreAllocation`)
    when 0.
  - `max-above-watermark` (int): extra IPs allowed above `pre-allocate` to reduce
    API calls (e.g. fill a new ENI).
  - `static-ip-tags` (map): tags selecting an EIP / public IP prefix.
- `eni` (`awsTypes.ENISpec`): `instance-type`, `first-interface-index` (*int),
  `security-groups[]`, `security-group-tags`, `subnet-ids[]`, `subnet-tags`,
  `node-subnet-id`, `vpc-id`, `availability-zone`, `exclude-interface-tags`,
  `delete-on-termination` (*bool, default true), `use-primary-address` (*bool,
  default false), `disable-prefix-delegation` (*bool, default false).
- `azure` (`AzureSpec`): `interface-name`.
- `alibaba-cloud` (`alibabaCloudTypes.Spec`): `instance-type`, `availability-zone`,
  `vpc-id`, `cidr-block`, `vswitches[]`, `vswitch-tags`, `security-groups[]`,
  `security-group-tags`.

`status` (`NodeStatus`):
- `ipam` (`IPAMStatus`): `used` (`AllocationMap`, agent-written, CRD allocator),
  `ipv6-used`, `pod-cidrs` (`map[cidr]{status: released|depleted|in-use}`),
  `operator-status.error` (string), `release-ips` (`map[ip]IPReleaseStatus`),
  `release-ipv6s`, `assigned-static-ip`.
- `eni` (`ENIStatus`): `enis[id]` -> `ENI{id, ip, mac, availability-zone,
  description, number, subnet{id,cidr}, vpc{id,primary-cidr,cidrs[]},
  addresses[], prefixes[] (/28), ipv6-prefixes[] (/80), security-groups[], tags,
  public-ip}`. Operator-written (`PopulateStatusFields`).
- `azure` (`AzureStatus`): `interfaces[]` -> `AzureInterface{id, ip, name, mac,
  state, addresses[]{ip,subnet(deprecated),state}, security-group,
  subnet{id,cidr}, gateway, cidr(deprecated)}`.
- `alibaba-cloud` (`ENIStatus`): `enis[id]` -> `ENI{network-interface-id,
  mac-address, type (Primary|Secondary), instance-id, security-groupids[],
  vpc{vpc-id,cidr,ipv6-cidr,secondary-cidrs[]}, zone-id,
  vswitch{vswitch-id,cidr,ipv6-cidr}, primary-ip-address, private-ipsets[], tags}`.

### IP release handshake (`status.ipam.release-ips`)
Enum (`IPReleaseStatus`, `pkg/ipam/option/option.go`):
`marked-for-release` (operator), `ready-for-release` (agent ACK),
`do-not-release` (agent NACK: in use or not owned), `released` (operator).
Operator side (`operator/pkg/ipam/nodemanager/node.go:handleIPRelease`): an IP is
a candidate once it has been excess for `--excess-ip-release-delay` seconds
(tracked in `ipsMarkedForRelease`), then written as `marked-for-release`. Agent
(`pkg/ipam/crd.go:updateLocalNodeResource`) answers on every CiliumNode update:
if the IP is not in `spec.ipam.pool` -> `do-not-release`; if allocated locally ->
`do-not-release`; else `ready-for-release`. Operator releases `ready-for-release`
IPs via `UnassignPrivateIpAddresses`/`UnassignENIPrefixes`, removes them from
`spec.ipam.pool` and sets `released`; agent deletes the map entry once the IP is
absent from the pool (and removes its unreachable route). The handshake aborts
from any state but `released` if the IP stops being excess
(`abortNoLongerExcessIPs`). Agents never allocate IPs in `marked-for-release`,
`ready-for-release` or `released` state (`isIPInReleaseHandshake`).
Multi-pool/ENI-1.20 nodes do not use this map: the agent drops a CIDR from
`spec.ipam.pools.allocated`, the operator waits `excess-ip-release-delay`
(`multiPoolCIDRsMarkedForRelease`) and releases via `PrepareCIDRRelease` /
`ReleaseCIDRs` (prefixes first, then /32s).

### Operator watermark math (`nodemanager/node.go`)
- `calculateNeededIPs(available, used, preAllocate, minAllocate, maxAllocate) =
  clamp(max(preAllocate + used - available, minAllocate - available), 0,
  maxAllocate - available)`.
- `calculateExcessIPs(available, used, preAllocate, minAllocate, maxAboveWatermark)`:
  0 while `used <= minAllocate + maxAboveWatermark` and `available <= min+maxAbove`;
  otherwise `max(available - used - preAllocate - maxAboveWatermark, 0)`.
- `MaxIPsToAllocate = NeededIPs + max-above-watermark + surgeAllocate`
  (surge = pending pods on the node from the operator pod store).
- `getMaxAllocate` = `spec.ipam.max-allocate` if > 0 (warns if above instance
  limit), else instance maximum from `GetMaximumAllocatableIPv4`.

### CiliumPodIPPool (`cilium.io/v2alpha1`, cluster-scoped, short `cpip`)
`spec.ipv4 {cidrs[] (format=cidr, min 1), maskSize (1..32, immutable)}`,
`spec.ipv6 {cidrs[], maskSize (1..128, immutable)}`, `allowFirstIP` (bool,
immutable, ignored for /31,/32,/127,/128), `allowLastIP` (same), `podSelector`
(LabelSelector), `namespaceSelector` (LabelSelector). No status.

### Agent-internal structs that leak
- `AllocationResult{IP, IPPoolName, CIDRs[], PrimaryMAC, GatewayIP,
  ExpirationUUID, InterfaceNumber, SkipMasquerade}` -> REST
  `IPAMAddressResponse{ip, gateway, cidrs, master-mac, expiration-uuid,
  interface-number, skip-masquerade}` -> CNI `RoutingInfo`.
- `ipamTypes.Limits{Adapters, IPv4, IPv6, HypervisorType, IsBareMetal}`.
- `ipamTypes.Subnet{ID, Name, CIDR, IPv6CIDR, AvailabilityZone,
  VirtualNetworkID, AvailableAddresses, AvailableIPv6Addresses, Tags}`,
  `VirtualNetwork{ID, PrimaryCIDR, CIDRs, IPv6CIDRs}`, `RouteTable{ID,
  VirtualNetworkID, Subnets}`, `PoolQuota{AvailabilityZone, AvailableIPs,
  AvailableIPv6s}`, `InstanceMap` (instance -> interface map, the cloud cache).
- Persisted files: none specific to IPAM; router IP restoration compares the
  k8s CiliumNode with `node_config.h`/`cilium_host` state.

## External interfaces

### Agent REST (`api/v1/openapi.yaml`, unix socket)
- `POST /ipam?family=&owner=&pool=` header `expiration: bool` ->
  `IPAMResponse{address{ipv4,ipv6}, ipv4{...}, ipv6{...}, host-addressing}`.
- `POST /ipam/{ip}?owner=&pool=` allocate a specific IP (restore path).
- `DELETE /ipam/{ip}?pool=` release (refused if an endpoint still owns it).

### Kubernetes
- Watches: own `CiliumNode` (field selector `metadata.name=<node>`),
  `CiliumPodIPPool` (statedb reflector), Pods and Namespaces (pool metadata).
- Writes: `CiliumNode` spec (`ipam.pools`, seeded `eni/azure/alibaba-cloud/ipam`)
  and status (`ipam.used`, `release-ips`) via `Update`/`UpdateStatus`, rate
  limited by `--ipam-cilium-node-update-rate` (15s) / `ipam-node-k8s-sync-<node>`
  trigger (10 ms min interval, operator).
- Operator watches all `CiliumNode`s (`nodewatcher.go`) and Pods (surge); the
  `podcidr` manager batches k8s updates every 15s.
- Annotations consumed: `ipam.cilium.io/ip-pool`, `ipam.cilium.io/ipv4-pool`,
  `ipam.cilium.io/ipv6-pool` on Pod and Namespace.

### Cloud APIs
- AWS EC2 (SDK v2, ops named in `pkg/aws/api/api.go`): `DescribeInstances`,
  `DescribeNetworkInterfaces` (paginated; filters `attachment.instance-id`,
  `subnet-id`, `tag:*`, `status=available` for GC), `DescribeVpcs`,
  `DescribeSubnets`, `DescribeRouteTables`, `DescribeSecurityGroups`,
  `DescribeInstanceTypes`, `DescribeAddresses`, `CreateNetworkInterface`,
  `AttachNetworkInterface`, `ModifyNetworkInterfaceAttribute`,
  `DeleteNetworkInterface`, `AssignPrivateIpAddresses` (IPs or
  `Ipv4PrefixCount`), `AssignIpv6Addresses` (`Ipv6PrefixCount=1`),
  `UnassignPrivateIpAddresses`, `AssociateAddress`, `DescribeTags`
  (EKS cluster-name detection). IMDS: `GetInstanceIdentityDocument` (region),
  `instance-id`, `instance-type`, `mac`, `network/interfaces/macs/<mac>/{vpc-id,
  subnet-id}`, `placement/availability-zone`. Error strings handled:
  `InsufficientCidrBlocks`, `InvalidParameterValue` + "There aren't sufficient
  free Ipv4 addresses or prefixes", `OperationNotPermitted`,
  `InvalidNetworkInterface.InUse`-style attachment index conflicts.
- Azure ARM (`armnetwork` v9, `armcompute` v8): `Interfaces.{List,Get,
  CreateOrUpdate, ListVirtualMachineScaleSetNetworkInterfaces,
  ListVirtualMachineScaleSetVMNetworkInterfaces}`, `VirtualMachineScaleSets.List`,
  `VirtualMachineScaleSetVMs.{Get,Update}`, `VirtualMachines.Get`, `Subnets.Get`,
  `PublicIPPrefixes.List`, `PublicIPAddresses.{Get,ListVirtualMachineScaleSetVMPublicIPAddresses}`.
  IMDS `http://169.254.169.254/metadata/instance/compute/{subscriptionId,
  resourceGroupName, azEnvironment}` with header `Metadata: true`.
- Alibaba (`alibaba-cloud-sdk-go` ecs/vpc): `DescribeInstances`,
  `DescribeNetworkInterfaces`, `DescribeVSwitches`, `DescribeVpcs`,
  `DescribeSecurityGroups`, `DescribeInstanceTypes`, `CreateNetworkInterface`,
  `AttachNetworkInterface`, `DeleteNetworkInterface`,
  `AssignPrivateIpAddresses`, `UnassignPrivateIpAddresses`, `ListTagResources`.
  Metadata `http://100.100.100.200/latest/meta-data/{instance-id,
  instance/instance-type, region-id, zone-id, vpc-id, vpc-cidr-block}`.
- All three go through `pkg/api/helpers.NewAPILimiter(qps, burst)` and
  `ObserveAPICall(op, status, duration)`.

### Netlink objects created by the agent / CNI
Per endpoint in ENI/Azure (and delegated) mode (`pkg/datapath/linux/routing`):
- Ingress rule: `priority 20 (RulePriorityIngress) to <podIP>/32 lookup main`,
  protocol `RTPROT_KERNEL`. Not installed for the host (cilium_host) IP.
- Egress rule(s): ENI: `priority 111 (RulePriorityEgressv2) from <podIP>/32
  [to <VPC CIDR>] lookup <10 + eni.number>` (`RouteTableInterfacesOffset = 10`).
  Azure: compat `priority 110 (RulePriorityEgress) from <podIP>/32 lookup
  <ifindex>` (table id = interface ifindex, `useCompatEgressPriority` is true only
  for `IPAMAzure`). With masquerade enabled and mode ENI/Azure one rule per
  CIDR in `RoutingInfo.CIDRs`; otherwise a single catch-all `from` rule.
- Per-interface table `<tableID>`: `<gateway>/32 dev <eni> scope link` and
  `default via <gateway>` (IPv6: `<gw>/128 dev`, `default via fe80:ec2::1 dev`).
  Installed by the CNI (`interface.go`) and reconciled by the agent
  (`ReconcileGatewayRoutes` against the statedb route table).
- ENI device: address `<primary>/<bits>` added, subnet route in `main` deleted,
  MTU set, `rp_filter=0` on the ENI device (only when primary address not used
  for pods). `RulePriorityNodeport = 109` sits just before egress.
- Unreachable routes `unreachable <ip>/32 table main` when
  `--enable-unreachable-routes`.

### Sysctls
`net.ipv4.conf.<eni>.rp_filter = 0` (ENI mode).

### Prometheus metrics
Agent: `cilium_ipam_capacity{family,cidr}` (cidr label only in kubernetes /
cluster-pool), `cilium_ipam_events_total{action=allocate|release,family}`.
Operator (`cilium_operator_ipam_*`): `available_ips`, `used_ips`, `needed_ips`
(per node), `ip_allocation_ops`, `ip_release_ops`, `interface_creation_ops`,
`interface_candidates`, `empty_interface_slots`, `available_ips_per_subnet`,
`nodes{category=total|in-deficit|at-capacity}`, `resync_total`,
`allocation_duration_seconds`, `release_duration_seconds`,
`background_sync_duration_seconds`, trigger metrics `<name>_queued_total`,
`_folds`, `_duration_seconds`, `_latency_seconds`; cloud API
`cilium_operator_{ec2,azure,alibabacloud}_api_duration_seconds` and
`..._rate_limit_duration_seconds` via `api/helpers`.

## Dependencies

- Inventory areas: node discovery / LocalNodeStore (native routing CIDR, alloc
  CIDRs), endpoint manager (release on delete, `EndpointDeleted`), CNI plugin
  (consumes `IPAMAddressResponse`, installs rules), datapath routing/statedb
  route table (`ReconcileGatewayRoutes`), ipcache (chaining modes), ip-masq-agent
  (non-masq CIDRs into `AllocationResult.CIDRs`), MTU (`GetDeviceMTU`), k8s
  client/resources (`LocalCiliumNodeResource`, `CiliumPodIPPoolResource`), hive
  jobs/statedb, operator leader election (IPAM cell runs under
  `WithLeaderLifecycle`).
- Kernel: netlink `RTM_NEWRULE`/`RTM_NEWROUTE` with `FRA_TABLE` > 255 (per-ENI
  tables 10+N and ifindex-based tables), `rp_filter` sysctl, `unreachable`
  routes. No BPF in this area.
- External services: Kubernetes API (CRDs), AWS EC2 + IMDSv2, Azure ARM + IMDS,
  Alibaba ECS/VPC OpenAPI + metadata. No kvstore involvement.
- Go SDKs used: `github.com/aws/aws-sdk-go-v2/{config,service/ec2,feature/ec2/imds}`,
  `github.com/Azure/azure-sdk-for-go/sdk/{azcore,azidentity,resourcemanager/network/armnetwork/v9,resourcemanager/compute/armcompute/v8}`,
  `github.com/aliyun/alibaba-cloud-sdk-go/{sdk,services/ecs,services/vpc}`.

## Kernel / platform requirements

Not a datapath area. Requirements: policy routing (`CONFIG_IP_MULTIPLE_TABLES`,
`CONFIG_IPV6_MULTIPLE_TABLES`), FIB rules with `from`/`to` selectors, ability to
disable `rp_filter` per interface. Cloud NIC hotplug must surface via netlink
(ENA driver on AWS; the agent waits and re-fetches links by MAC because udev
renames `eth1` to `ensX`). arm64 and x86-64 behave identically; Graviton
instances are nitro so prefix delegation is available.

## Tests

Unit (non-privileged) line counts: `pkg/ipam` 3629 (`multipool_test.go` 1677:
demand rounding, CIDR release, restore; `eni_test.go` 822: pool accessor CIDR
derivation, prefix/address dedup, native-CIDR autodetect, allocation result
enrichment; `crd_test.go` 318: release handshake states, owner pinning),
`pkg/ipam/types` 119, `cidrset` 764, `metadata` 762 (annotation precedence,
selector conflicts), `service/ipallocator` 408, `service/allocator` 42,
`podippool/script_test.go` 70 (txtar), `pkg/ipam/migration/script_test.go` 326
(cluster-pool -> multi-pool txtar), `pkg/ipalloc` 635.
Cloud: `pkg/aws/ipam` 2519 (node_manager_test 1276: watermarks, ENI creation,
release delay, prefix delegation, subnet/route-table selection; node_ipv6_test
141), `pkg/aws/api` 196 + mock 203, `limits` 122, `pkg/azure/ipam` 964 +
`api` 392 + types 117 + mock 111, `pkg/alibabacloud/ipam` 454 + types 68.
Operator: `nodemanager` 1620 (`node_test.go` 741: `calculateNeededIPs`,
`calculateExcessIPs`, handshake transitions, multi-pool detection),
`allocator/multipool` 2258 (pool allocator, orphan CIDRs, node handler,
migration), `allocator/podcidr` 2063, `cidralloc` 94, `operator/pkg/ipam`
`multipool_script_test.go` + `podcidroverlap_test.go` 270, metrics mock 27.
Privileged: `pkg/ipam/pool_privileged_test.go` 80 (unreachable routes),
`pkg/datapath/linux/routing/routing_test.go` 349 (rule/route install and delete
for ENI and Azure priorities), `info_test.go` 152.
E2E (`.github/workflows`): `conformance-eks.yaml` (ENI; matrix includes
`eni.awsEnablePrefixDelegation=true`, `bpf.masquerade=true`,
`egressGateway.enabled=true`, wireguard/ipsec), `conformance-kpr-eks.yaml`,
`conformance-aws-cni.yaml` (chaining), `conformance-aks.yaml` /
`conformance-kpr-aks.yaml` (Azure IPAM with `azure.resourceGroup`, dual-stack
cluster-pool CIDRs), `conformance-gke.yaml` / `conformance-kpr-gke.yaml`
(`ipv4NativeRoutingCIDR` from cluster), `conformance-multi-pool.yaml`
(auto-created pools, `ipMasqAgent`, `endpointRoutes`), `conformance-delegated-ipam.yaml`
(kind with host-local conflists), `eks-cluster-pool-manager.yaml`. No Alibaba
CI. Legacy ginkgo `test/` has no IPAM-specific suites left.

## Rust mapping

Structure that falls out of the reference:
- `flowsdn-ipam` (agent): `trait Allocator` mirroring the Go interface
  (`allocate`, `allocate_without_sync`, `allocate_next*`, `release`, `dump`,
  `capacity`, `restore_finished`), with backends `HostScope` (bitmap over one
  prefix — `ipnet` + a `bitvec`/`roaring` bitmap), `MultiPool` (per-pool
  `BTreeMap<Prefix, Range>` plus the demand calculator and CiliumNode
  read/write through a `PoolSpecAccessors` trait so ENI can reuse it), `Crd`
  (per-IP map + handshake responder), `NoOp`. Expiration timers become
  `tokio::time::sleep` tasks keyed by `(ip, pool)` with a UUID guard.
- `flowsdn-ipam-types`: serde structs for `IPAMSpec`, `IPAMStatus`, `ENISpec`,
  `ENI`, `AzureInterface`, Alibaba `ENI`, `CiliumPodIPPool`, using
  `ipnet::IpNet` / `std::net::IpAddr` with the exact JSON tags above
  (`omitempty`/`omitzero` semantics -> `skip_serializing_if`). kube-rs
  `CustomResource` derives for CiliumNode and CiliumPodIPPool; keep the CRD
  wire format byte-compatible so Cilium operators and flowsdn agents can be
  mixed during migration.
- `flowsdn-operator-ipam`: `NodeManager` with a semaphore-bounded worker pool
  (`--parallel-alloc-workers`), per-node reconcile task with exponential backoff
  (Go: min 10 ms, max 5 min, reset after 10 min), the watermark functions as
  pure functions (trivially unit-testable), the 4-state handshake and the
  multi-pool CIDR release timer, and a `trait NodeOperations` +
  `trait AllocationImplementation` exactly as in `node_manager.go:39-152`.
- Cloud backends behind `NodeOperations`:
  - AWS: `aws-sdk-ec2` + `aws-config` (IRSA via `WebIdentityTokenCredentialsProvider`
    from `AWS_WEB_IDENTITY_TOKEN_FILE`/`AWS_ROLE_ARN`, IMDS via `aws-config::imds`;
    both are in the default chain) and `aws-sdk-ec2` paginators for
    `describe_network_interfaces`/`describe_instances`/`describe_instance_types`.
    `BaseEndpoint` override maps to `.endpoint_url()`. Availability: mature, official.
  - Azure: `azure_identity` (`ManagedIdentityCredential` with user-assigned
    client ID, `DefaultAzureCredential` incl. workload identity and
    `AZURE_CLIENT_{ID,SECRET}`/`AZURE_TENANT_ID`), `azure_mgmt_network` and
    `azure_mgmt_compute` (autorust-generated, `azure-sdk-for-rust`
    `services/mgmt/*`). These management crates are generated and less
    polished than `azure_core`; expect to pin versions and handle the
    long-running `BeginUpdate` poller manually. IMDS is a plain `reqwest` GET
    with `Metadata: true`. Cloud selection by `azEnvironment` maps to
    `azure_core::cloud` endpoints.
  - Alibaba: no official Rust SDK. Options: `alibaba-cloud-sdk-rust`
    (community, incomplete) or write a small RPC-style client (~600 lines) for
    the dozen ECS/VPC actions above using the OpenAPI v2 signature (HMAC-SHA1
    `Signature` query parameter or the newer ROA/RPC V3 with `Authorization:
    ACS3-HMAC-SHA256`), plus credential chain (env AK/SK, RAM role from
    `http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>`,
    OIDC RRSA). Budget for this as new code.
  - GCP: nothing to implement; `ipam=kubernetes` + native routing. If a future
    GKE-specific integration is wanted, `google-cloud-rust` (`google-cloud-compute-v1`)
    with workload identity is available, but the reference has no such code.
- Per-endpoint routing: `rtnetlink` (Rust netlink) for `RTM_NEWRULE` with
  `FRA_PRIORITY`, `FRA_TABLE`, `FRA_SRC`/`FRA_DST`, `RTA_PROTOCOL = kernel` and
  the per-interface tables; sysctl via `/proc/sys`. Keep the exact priorities
  20/110/111/109 and table offset 10 for coexistence with Cilium-installed
  state during upgrades.
- Rate limiting: `governor` for QPS/burst; metrics via `prometheus` crate with
  the same names.

Risks and hard parts:
- Dual-writer CiliumNode protocol (agent and operator both write the same
  object, agent uses `Update` on spec and `UpdateStatus` on status) with
  optimistic concurrency; the Go code retries on conflict and relies on
  `DeepEqual` skipping. Must preserve field ownership exactly or Cilium
  operators paired with flowsdn agents will fight.
- 1.19-compat path (CRD allocator for ENI) is dead weight for a clean-room
  implementation; drop it and only implement the multi-pool ENI protocol, but
  keep the per-IP CRD path because Azure and Alibaba still need it.
- Prefix delegation state machine (nitro check, mixed IP/prefix rejection,
  subnet-out-of-prefixes fallback) and the AWS API error-string matching.
- Azure VMSS update is a long-running operation on a shared VM object; racing
  updates from parallel workers is the classic failure (Go serialises per node
  but not per VMSS).
- Alibaba client is greenfield in Rust.
- Timing knobs (15 s node update rate, 1 m resync, 180 s release delay, 5 m
  ENI GC, 3 m pool wait, 5 m native-CIDR wait) are behaviourally visible and
  should be kept as defaults.

## Recommendation

keep — IPAM is mandatory and the cloud modes are the stated priority.
Implement in this order: `kubernetes`/`cluster-pool` (agent hostscope + operator
podcidr), `multi-pool` (agent manager + operator pool allocator; also carries
ENI), `eni` (operator AWS backend, agent device configurator, routing rules),
`azure`, `alibabacloud`, `crd`, `delegated-plugin`. Drop the 1.19 ENI
compatibility path and the deprecated Azure `cidr`/`subnet` mirror fields.
Effort: agent IPAM core M (~5k), operator core + cluster/multi-pool M (~6k),
AWS L-boundary (~5k incl. tests), Azure M (~3k), Alibaba M (~3k incl. the
client), routing S (~1k). Overall XL (~23k lines of Rust).

## Open questions

- Should flowsdn ship the legacy per-IP ENI path at all, given the operator
  auto-detects multi-pool agents? Recommendation above says no, but a
  mixed-version cluster (Cilium 1.19 agents + flowsdn operator) would need it.
- Azure: is `azure_mgmt_network`/`azure_mgmt_compute` maintained enough, or
  should flowsdn call the ARM REST endpoints directly with `azure_core`
  pipelines (fewer dependencies, ~1k lines)?
- Alibaba: community crate vs. hand-written signer; also whether to support
  RRSA (OIDC) from day one.
- Egress gateway on ENI: the reference has removed the compat flags; confirm
  with the egress-gateway inventory that priority 111 alone is sufficient and
  no route installation is expected from IPAM.
- `--aws-max-results-per-call` auto-fallback to 1000 on `OperationNotPermitted`
  is an incident response baked into code; keep or replace with explicit config?
- GKE: do we want a real GCP integration (alias IP ranges via compute API) or
  stay with `ipam=kubernetes`? The reference offers no precedent.
- IPv6 on ENI is partial in the reference (`/80` prefixes, no IPv6 secondary
  IP path); decide on parity or better.

Decision #109: GKE remains Kubernetes PodCIDR/native routing integration; no separate Compute API allocator. See spec 07 §3.12 and its validated packaging contract.
