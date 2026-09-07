# Harvested txtar script-test corpus

168 `.txtar` scenario files copied verbatim from cilium/cilium at
**v1.20.1, commit `7d68cfb394`**, on **2026-09-07**, under **Apache-2.0**.

These files are **data**, not code. ADR-0005 ("Harvest the reference's tests.
All harnesses in Rust.") makes them a first-class deliverable: they are the
single highest-leverage item in the flowsdn test plan, because they make 168
scenarios run against flowsdn with no per-file authoring work. The harness that
interprets them, `flowsdn-scripttest`, is specified in
[`docs/spec/17-scripttest-harness.md`](../../../docs/spec/17-scripttest-harness.md).

**Do not edit these files.** Every deviation flowsdn chooses is expressed in the
harness or in an expected-divergence marker file (spec 17 §3.8), never by editing
a harvested script — a re-harvest at a newer reference tag must stay a `cp`.
Mechanical rewrites (flag renames, map-name renames) belong in a script under
`tools/`, per ADR-0005 §4.

Each area directory carries a `PROVENANCE` file with its exact upstream path,
the commit, the license, the copy date, and a statement that the copies are
unmodified. `NOTICE` carries the matching top-level attribution.

## What a file looks like

```
#! --lb-test-fault-probability=0.0        <- flag line: agent config for this scenario

# Add some node addresses                 <- section comment; also a retry boundary
db/insert node-addresses addrv4.yaml      <- command line
db/cmp node-addresses nodeaddrs.table

# Check BPF maps
lb/maps-dump lbmaps.actual
* cmp lbmaps.expected lbmaps.actual       <- '*' = retry this section until it passes

-- addrv4.yaml --                         <- embedded file, materialized into $WORK
addr: 10.0.0.1
...
-- lbmaps.expected --
SVC: ID=1 ADDR=10.96.50.104:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 ...
```

Everything before the first `-- name --` line is the script; everything after is
an archive of files written into the script's working directory before it runs.

## Areas

| Area | Files | Embedded | Reference path | What it exercises |
|---|---:|---:|---|---|
| `loadbalancer` | 51 | 481 | `pkg/loadbalancer/tests/testdata` | Service load balancing end to end: ClusterIP, NodePort, LoadBalancer, ExternalIPs, HostPort, DSR/hybrid modes, Maglev vs random, session affinity, source ranges, topology-aware and prefer-same-node/zone hints, graceful termination, quarantine, KPR transitions, restart/prune/resync, LB BPF map contents. |
| `bgp` | 20 | 227 | `pkg/bgp/test/testdata` | BGP control plane against live GoBGP peers: session establishment (v4/v6, multi-instance, TCP-MD5 auth), pod CIDR / pod IP pool / service advertisement, aggregation, path attributes, route policies, traffic policy and KPR interactions. PRIVILEGED: creates test interfaces and peers over real TCP. |
| `envoyconfig` | 12 | 139 | `pkg/ciliumenvoyconfig/testdata` | CiliumEnvoyConfig / CiliumClusterwideEnvoyConfig translation into Envoy xDS resources (listeners, clusters, endpoints, routes), backend services, headless services, ingress, terminating endpoints, label selection. |
| `redirectpolicy` | 12 | 141 | `pkg/loadbalancer/redirectpolicy/testdata` | CiliumLocalRedirectPolicy: address matchers and CIDR restrictions, named ports, service matchers, pod readiness gating, node-local DNS scenario, and the SkipLB map. |
| `clustermesh` | 9 | 58 | `clustermesh-apiserver/clustermesh/testdata` | clustermesh-apiserver: synchronizing CiliumNode, CiliumIdentity, CiliumEndpoint / CiliumEndpointSlice and cluster config into the kvstore, MCS-API service exports, global namespace policy, CRD upgrade paths. |
| `datapath-linux` | 5 | 29 | `pkg/datapath/linux/testdata` | Native device detection from the host network: wildcard and negated --devices patterns, forced detection, ordering, and the resulting devices table. PRIVILEGED: uses real netlink in a namespace. |
| `k8sclient` | 5 | 39 | `pkg/k8s/client/testutils/testdata` | The fake Kubernetes clientset itself: object trackers, add/update/delete/get/list, optimistic-concurrency conflicts, resource-version and UID redaction, status subresource updates, resync. |
| `policy` | 5 | 10 | `pkg/policy/test/testdata` | Policy repository and selector cache: importing/removing policies, identity allocation, kube-apiserver entity rules (allow/deny/duplicate-delete), endpoint regeneration and policy revision waits, flow verdict lookups. |
| `route-reconciler` | 5 | 22 | `pkg/datapath/linux/route/reconciler/scripttest/testdata` | Desired-routes table reconciled into the kernel routing table: owners, multipath, priorities, initializers, restart persistence, periodic refresh. PRIVILEGED. |
| `clustermesh-agent` | 4 | 31 | `pkg/clustermesh/testdata` | Agent-side clustermesh consumption: remote cluster services into the local service tables, multi-port services, service affinity, clusters without local endpoints. |
| `device` | 4 | 23 | `pkg/datapath/linux/device/scripttest/testdata` | Desired-devices table reconciled into links: device owners, VLAN creation and re-creation, initializers, restart persistence. PRIVILEGED. |
| `hubble-exporter` | 4 | 22 | `pkg/hubble/exporter/testdata/scripts` | Hubble flow-log exporters: dynamic exporter configuration add/delete/reload, filters, aggregation, file output contents and exporter counts. |
| `neighbor` | 4 | 20 | `pkg/datapath/neighbor/test/testdata` | Forwardable-IP and neighbor-entry reconciliation into the kernel ARP/NDP table, including kernel-managed ARP ping mode and refresh-count metrics. PRIVILEGED. |
| `dynamicconfig` | 3 | 9 | `pkg/dynamicconfig/testdata` | Dynamic configuration sources and precedence: ConfigMap, CiliumNodeConfig and Node-annotation sources feeding the dynamic-config table. |
| `lb-healthserver` | 3 | 39 | `pkg/loadbalancer/healthserver/testdata` | The NodePort service health-check HTTP server: per-service listeners, local-endpoint counts, IPv6, and proxy-redirect (Envoy) interaction. |
| `metrics` | 3 | 7 | `pkg/metrics/testdata` | The metrics registry and sampler: listing registered and sampled metrics in table/json/yaml, plotting sampled series, HTML output. |
| `operator-watchers` | 3 | 18 | `operator/watchers/testdata` | Operator watchers: service synchronization to the kvstore, global-namespace filtering, EndpointSlice export sync. |
| `egressgateway` | 2 | 22 | `pkg/egressgateway/testdata` | Egress gateway policy evaluation and the resulting egress policy BPF map contents, including egress IP selection. |
| `ipam-multipool` | 2 | 18 | `operator/pkg/ipam/testdata/multipool` | Operator multi-pool IPAM allocator: allocating CIDRs from multiple pools and migrating from cluster-pool. |
| `k8s-tables` | 2 | 11 | `pkg/k8s/tables/testdata` | Reflection of core Kubernetes objects (Pods, Namespaces) into agent tables. |
| `nodes-gc` | 2 | 23 | `operator/pkg/kvstore/nodesgc/testdata` | Operator garbage collection of stale node entries in the kvstore, enabled and disabled. |
| `bgp-reconciler` | 1 | 15 | `pkg/bgp/manager/reconciler/testdata` | A single BGP reconciler driven directly (init / reconcile / cleanup) for route policies, without a live peer. |
| `example` | 1 | 2 | `contrib/examples/script/testdata` | The upstream tutorial script showing the bare framework (a custom command, call counts, stdout matching). Useful as the harness's own smoke test. |
| `hive-health` | 1 | 13 | `pkg/hive/health/testdata` | The module health registry: health tree output, degraded detection, health history. |
| `ipam-migration` | 1 | 8 | `pkg/ipam/migration/testdata` | IPAM initializer: restoring endpoint allocations across restart, cluster-pool to multi-pool migration, allocation and dump. |
| `kvstore` | 1 | 2 | `pkg/kvstore/testdata` | kvstore client value transcoding (EndpointSlice values to JSON) and list/update/delete. |
| `mcsapi-coredns` | 1 | 3 | `clustermesh-apiserver/mcsapi-coredns-cfg/testdata` | clustermesh-apiserver MCS-API CoreDNS configuration generation. |
| `podippool` | 1 | 7 | `pkg/ipam/podippool/testdata` | CiliumPodIPPool reflection into the pod IP pool table. |
| `subnet` | 1 | 5 | `pkg/subnet/testdata` | Subnet table reflection and the subnet BPF map dump. |

**Total: 168 scripts, 1444 embedded files, 29 areas.**

"Embedded" counts `-- name --` sections across the area's scripts, i.e. the YAML
inputs, `.table` expectations and `.expected` golden files carried inside the
archives.

Areas marked PRIVILEGED drive real netlink in a network namespace and must run
as root; the harness gates them on the `[privileged]` condition (spec 17 §3.2.4).

## Command surface

118 distinct commands appear across the corpus. Grouped:

| Group | Commands | Drives |
|---|---|---|
| generic file/assert | `cmp` `cmpenv` `empty` `grep` `stdout` `stderr` `cat` `cp` `mv` `rm` `mkdir` `replace` `sed` `echo` `env` `exec` `sleep` `stop` `skip` `break` `wait` | the harness itself |
| agent lifecycle | `hive` `hive/start` `hive/stop` `hive/recreate` | agent fixture start/stop/restart |
| table store | `db` `db/cmp` `db/show` `db/empty` `db/insert` `db/delete` `db/get` `db/list` `db/prefix` `db/initialized` | `flowsdn-table` (spec 00) |
| fake Kubernetes | `k8s/add` `k8s/update` `k8s/delete` `k8s/get` `k8s/list` `k8s/resync` `k8s/summary` `k8s/svc/update-status` | fake clientset + reflectors (spec 13) |
| load balancer | `lb/maps-dump` `lb/maps-empty` `lb/maps-snapshot` `lb/maps-restore` `lb/prune` `skiplbmap` `svc/set-proxy-redirect` | LB maps + reconciler (spec 05) |
| test hooks | `test/init-wait` `test/bpfops-reset` `test/bpfops-summary` `test/set-node-labels` `test/set-node-ip` `test/set-is-service-healthchecked` `test/update-backend-health` `set-node-labels` | LB writer / local node store |
| netlink (privileged) | `netns/create` `link/add` `link/set` `link/del` `addr/add` `route/add` `route/replace` `route/del` `route/list` `sysctl/set` | real netlink in a netns |
| reconcilers | `add-device` `add-route` `add-owner` `remove-owner` `add-initializer` `finish-initializer` `forwardable-ip/register-initializer` `forwardable-ip/finish-initializer` `reconciler/init` `reconciler/reconcile` `reconciler/cleanup` | device/route/neighbor reconcilers (spec 10) |
| BGP | `bgp/peers` `bgp/routes` `bgp/route-policies` `gobgp/add-server` `gobgp/delete-server` `gobgp/add-peer` `gobgp/wait-state` `gobgp/peers` `gobgp/routes` `gobgp/advertise-route` | BGP speaker + a real peer (spec 15) |
| policy / identity | `policy/import` `policy/remove` `policy/lookup-flow` `policyrepo/selectorcache` `identity/allocate` `endpoint/create` `endpoint/delete` `endpoint/regen-all` `endpoint/wait-for-policy-revision` | policy engine (spec 06), identity (spec 03) |
| kvstore / clustermesh | `kvstore/update` `kvstore/delete` `kvstore/list` | kvstore client (spec 12) |
| IPAM | `ipam/start` `ipam/allocate` `ipam/restore-endpoint` `ipam/restore-finished` `ipam/dump` `allocator/allocated-pools` | IPAM (spec 07) |
| observability | `metrics` `metrics/plot` `metrics/html` `health` `health/ok` `health/history` `event/send` `config/add` `config/delete` `exporters/count` `file/read` `file/exists` | metrics + health (spec 00), Hubble export (spec 11) |
| misc datapath | `egress/policy-maps-dump` `subnet/map-dump` `envoy/cmp` `http/get` | egress gw (spec 14), subnet map, Envoy xDS (spec 16) |
| example | `example/hello` `example/counts` | harness smoke test only |

Full argument-by-argument documentation of every one of these is in spec 17 §3.3.

## Re-harvesting

```
# from the flowsdn repo root, with ../cilium checked out at the desired tag
tools/harvest-txtar.sh   # (to be written; ADR-0005 §4)
```

A re-harvest replaces file contents wholesale and rewrites each `PROVENANCE`.
It must not produce a diff in any `.txtar` beyond what upstream changed.
