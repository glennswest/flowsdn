# Agent process, endpoint lifecycle and external API — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `daemon/**`, `pkg/hive/**`,
`pkg/option/**`, `pkg/defaults`, `pkg/endpoint/**`, `pkg/endpointmanager/**`,
`pkg/endpointstate`, `pkg/status`, `pkg/health/**`, `cilium-health/`, `pkg/api`,
`api/v1/openapi.yaml`, `api/v1/health/openapi.yaml`, `api/v1/{server,client,models}`,
`plugins/cilium-cni/**`, `pkg/controller`, `pkg/lock`, `pkg/rate`, `pkg/logging`,
`pkg/command`, `pkg/components`, `pkg/pidfile`, `pkg/version`, `pkg/promise`,
`pkg/time`, `pkg/trigger`, `pkg/dynamicconfig`, `pkg/dynamiclifecycle`, `cilium-dbg/**`,
`bugtool/**`.

All line counts are non-test Go lines (`find -name '*.go' -not -name '*_test.go' | xargs wc -l`).

## Purpose

This area is the agent *as a process*: how `cilium-agent` boots, which order its
subsystems come up in, how it persists and restores per-pod state across restarts, and
every interface a third party talks to it through — the REST API over
`/var/run/cilium/cilium.sock`, the CNI plugin that the kubelet execs, the health
prober that runs between nodes, the debug CLI, and bugtool. It is also the
*configuration surface*: every flag in the table below is a key of the `cilium-config`
ConfigMap and the thing flowsdn must accept for a drop-in swap. The datapath, policy
engine, LB, IPAM backends and Hubble are other areas; here they appear only as things
that must exist before an endpoint can be regenerated.

## Components

| Path | Lines | Purpose |
|---|---|---|
| `daemon/cmd/` | 4984 | `cilium-agent` cobra root, global flag registration (204 `flags.*` calls in `daemon_main.go`), hive cell composition (`cells.go`), startup validation (`daemon.go`), endpoint restore (`endpoint_restore.go`, 841), host-IP sync |
| `daemon/cmd/cni/` | ~700 | Writes `/etc/cni/net.d/05-cilium.conflist` when agent ready; `cni-exclusive`, chaining templates |
| `daemon/healthz/` | ~400 | Agent `/healthz` on `127.0.0.1:9879` and kube-proxy-replacement `/healthz` on `:10256` |
| `daemon/infraendpoints/` | ~700 | Host, ingress and health "infra" endpoints; router/health IP (re)allocation |
| `daemon/restapi/` | ~400 | `GET/PATCH /config` handlers, `GET /policy*` handlers, API rate-limiter cell |
| `pkg/hive/` (+`health/`) | 1966 | Thin wrapper over `github.com/cilium/hive v1.0.4`: module decorators, job groups, StateDB metrics, `Fence`, module health table, shell socket |
| `pkg/option/` | 4867 | `DaemonConfig` (227 exported fields), flag-name constants, `config-dir` loader, per-endpoint runtime `Option` library, `agent-runtime-config.json` dump |
| `pkg/defaults/` | 694 | All path/port/timer constants (below) |
| `pkg/endpoint/` | 12233 | `Endpoint` struct, state machine, regeneration pipeline (`policy.go`, `bpf.go`), restore/serialisation (`restore.go`), directory swap (`directory.go`), status log, event queue, REST handlers (`api/`), deletion queue, BPF-prog watchdog |
| `pkg/endpointmanager/` | 2766 | ID allocation (1..4095), lookup indexes, periodic GC and regeneration, CiliumEndpoint (CEP) k8s sync controller, host endpoint labels, policy-map pressure metric |
| `pkg/endpointstate/` | 42 | `Restorer` promise interface consumed by health, CNI deletion queue, watchdog |
| `pkg/status/` | 1737 | Status collector: 29 named probes feeding `GET /healthz` (`StatusResponse`) |
| `pkg/health/` + `cilium-health/` | 3065 + 284 | cilium-health server on `/var/run/cilium/health.sock` (`/v1beta`), ICMP+HTTP prober, `/hello` responder on `:4240`, the `cilium-health-ep` endpoint in its own netns, `cilium-health` CLI |
| `pkg/api/` | 589 | Socket permissions (group `cilium`, mode 0660), `--enable-cilium-api-server-access` allow/deny, 403 handler |
| `api/v1/` | 97040 | go-swagger generated server/client/models from `openapi.yaml` (3941 lines) and `health/openapi.yaml` (193) |
| `plugins/cilium-cni/` | 2437 | CNI binary: ADD/DEL/CHECK/STATUS, chaining plugins, delegated IPAM, offline deletion queue |
| `pkg/controller/` | 908 | Named retry loop with backoff, exposed in `StatusResponse.Controllers` |
| `pkg/lock/` | 715 | Mutex wrappers with optional deadlock detection (`lockdebug` tag), `SortableMutex`, `StoppableWaitGroup`, `lockfile/` (flock) |
| `pkg/rate/` | 1083 | `APILimiter`/`APILimiterSet`: rate + parallelism limiter with auto-adjust, used on `/endpoint` ops |
| `pkg/logging/` | 2888 | slog setup: `text`/`text-ts`/`json`/`json-ts`, syslog driver, klog bridge, 787 field-name constants |
| `pkg/trigger/` | 226 | Debounced trigger with `MinInterval` and reasons |
| `pkg/dynamicconfig/` | 504 | StateDB table of `cilium-config` keys reflected from ConfigMap/CiliumNodeConfig (priority-merged) |
| `pkg/dynamiclifecycle/` | 556 | StateDB-reconciled feature enable/disable of cell lifecycles at runtime |
| `pkg/{command,components,pidfile,version,promise,time}` | 455/23/130/134/134/131 | small utilities (see Data model) |
| `cilium-dbg/` | 12230 | Debug CLI (`cilium-dbg`), 60+ leaf commands |
| `bugtool/` | 1411 | `cilium-bugtool` archive collector |

## Features

- **Hive dependency injection**: agent = `cell.Module("agent", Infrastructure, ControlPlane, datapath.Cell)`. ~90 cells listed in `daemon/cmd/cells.go`. Each cell can `cell.Config(defaultStruct)` (flags auto-registered from `Flags(*pflag.FlagSet)`), `cell.Provide` constructors, `cell.Invoke` side effects, append `cell.Lifecycle` hooks (OnStart/OnStop, run in dependency order), get a `job.Group` (OneShot/Timer/Observer jobs) and a `cell.Health` reporter. Env prefix `CILIUM_`. Timeouts: `hive-start-timeout` 5m, `hive-stop-timeout` 1m, `hive-log-threshold` 100ms (slow hook logged).
- **Config loading**: cobra + viper. `--config-dir` (Helm mounts `cilium-config` ConfigMap at `/tmp/cilium/config-map`; the init container runs `cilium-dbg build-config --dest /tmp/cilium/config-map` which resolves `config-map:cilium-config`, `cilium-node-config:<ns>` (CiliumNodeConfig CRs) and `node:<name>` annotations, in that priority). Each file name = flag name, content = value. Env vars `CILIUM_<FLAG_UPPER_UNDERSCORE>`. `--config` YAML file also accepted. After parse, `DaemonConfig.Populate`, `Validate`, then `StoreInFile` writes `<state-dir>/agent-runtime-config.json` (rotated `-1`, `-2`) and `StoreViperInFile`; `ValidateUnchanged` on restart refuses to change immutable options.
- **Runtime-mutable options** (`PATCH /config`, `cilium-dbg config Debug=enable`): `Debug`, `DebugLB`, `DebugPolicy`, `DebugTagged`, `DropNotification`, `TraceNotification`, `TraceSockNotification`, `PolicyVerdictNotification`, `PolicyAuditMode`, `MonitorAggregationLevel`, `SourceIPVerification`, `PolicyTracing`. Per-endpoint subset (`PATCH /endpoint/{id}/config`): same minus `DebugTagged`/`TraceSock`/`PolicyTracing`. Each maps to a C `#define` in `ep_config.h` (`DEBUG`, `DROP_NOTIFY`, `TRACE_NOTIFY`, `POLICY_VERDICT_NOTIFY`, `POLICY_AUDIT_MODE`, `MONITOR_AGGREGATION`, `ENABLE_SIP_VERIFICATION`, `POLICY_DEBUG`, `DEBUG_TAGGED`).
- **Dynamic config / dynamic lifecycle**: `config-sources` (hidden flag, default `[{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]`) reflected into StateDB table `DynamicConfig{Key{Name,Source},Value,Priority}`; `dynamic-lifecycle` lets feature cells (currently only a few) be started/stopped when a key flips, without agent restart.
- **Endpoint lifecycle**: create via `PUT /endpoint/{id}` (CNI), restore from disk, regenerate on policy/label/config change, GC unhealthy (`endpoint-gc-interval` 5m, link check), periodic regen (`endpoint-regen-interval` 2m), delete via `DELETE /endpoint/{id}` or offline queue.
- **State restore on restart** (`--restore=true`): reads `<state-dir>/<id>/ep_config.json`, re-allocates IPs and identities, keeps datapath running, regenerates in background; stale `lxc*` veths and stale `cilium_lxc` map entries removed.
- **CiliumEndpoint sync**: per-endpoint controller `sync-to-k8s-ciliumendpoint (<id>)` creates/patches the CEP CR (disabled by `disable-endpoint-crd`); CEP UID recorded in the endpoint to avoid clobbering another owner's CEP.
- **Health checking**: `enable-health-checking` (node-to-node ICMP+HTTP:4240), `enable-endpoint-health-checking` (a real endpoint `cilium-health-ep` with veth `lxc_health`, own netns, running `cilium-health-responder`), results in `cilium-dbg status --verbose` and `cilium-health status`, metrics `cilium_node_health_connectivity_*`.
- **Status API**: `GET /healthz` returns `StatusResponse` with ~30 sub-statuses; used by kubelet liveness via `127.0.0.1:9879/healthz`, by `cilium-dbg status`, by CNI (`GET /config` for `IpamMode`, addressing, MTU, datapath mode).
- **API access control**: `--enable-cilium-api-server-access` (default `*`); operation names are `Method+PascalPath` e.g. `PutEndpointID`, `GetConfig`; denied ops return 403. Six ops are required for CNI/kubelet: `GetConfig`, `GetHealthz`, `PutEndpointID`, `DeleteEndpointID`, `PostIPAM`, `DeleteIPAMIP`.
- **API rate limiting**: `--api-rate-limit "endpoint-create=rate-limit:10/m,rate-burst:2"`; limiter names `endpoint-create|delete|get|patch|list` with defaults (create: 0.5/s burst 4, 4 parallel, min 2, est 2s, auto-adjust, max wait 60s; delete: 4 parallel, est 200ms; get: 4/s burst 4, max wait 10s; patch: 0.5/s, max wait 15s; list: 1/s burst 4).
- **CNI config management**: `write-cni-conf-when-ready=/host/etc/cni/net.d/05-cilium.conflist`, `read-cni-conf` (custom source, from `cni-configuration` ConfigMap mounted by Helm when `cni.customConf`), `cni-chaining-mode` (`none|aws-cni|flannel|generic-veth|portmap`), `cni-chaining-target` (insert into an existing conflist), `cni-exclusive` (rename other `*.conf*` to `*.cilium_bak`), `cni-log-file` (default `/var/run/cilium/cilium-cni.log`), `cni-external-routing`.
- **Shell / StateDB**: hive shell on `/var/run/cilium/shell.sock` (`cilium-dbg shell -- <cmd>`; script commands registered by cells: `db` tables, `health`, `metrics/html`, `endpoint/list|create|delete|regen-all|wait-for-policy-revision`, `bgp/peers|routes|route-policies`, `policy/mapstate/entries|topk`, `health/history`). StateDB HTTP dump at `/statedb/dump` on the API socket.
- **Observability hooks**: gops on `127.0.0.1:9890`, pprof (`pprof` flag, port 6060), Prometheus (`prometheus-serve-addr`), `GET /debuginfo`, bugtool.

## Data model

### Filesystem layout (defaults from `pkg/defaults`)

| Path | Meaning |
|---|---|
| `/var/run/cilium` (`--state-dir` is actually `RunDir`; mode 0775) | runtime root |
| `/var/run/cilium/cilium.sock` (env `CILIUM_SOCK`), group `cilium`, 0660 | agent REST API |
| `/var/run/cilium/health.sock` (env `CILIUM_HEALTH_SOCK`) | cilium-health REST API (`/v1beta`) |
| `/var/run/cilium/shell.sock` | hive shell |
| `/var/run/cilium/monitor1_2.sock` | monitor event stream (area 09) |
| `/var/run/cilium/hubble.sock` | Hubble observer gRPC (area 09) |
| `/var/run/cilium/envoy/sockets/{admin,xds}.sock` | Envoy (area 11) |
| `/var/run/cilium/cilium.pid` | agent pidfile |
| `/var/run/cilium/deleteQueue/` + `lockfile` | CNI offline deletion queue (`*.delete` files, `EndpointBatchDeleteRequest` JSON) |
| `/var/run/cilium/certs` | `CertsDirectory` |
| `/var/run/cilium/netns` | `NetNsPath` |
| `/var/run/cilium/state` (0770) — agent `chdir`s here | **state dir**: `globals/node_config.h`, `templates/`, `agent-runtime-config.json`, `health-endpoint.pid`, per-endpoint dirs |
| `/var/run/cilium/state/<id>/` | endpoint dir: `ep_config.h` (C header for the BPF build), `ep_config.json` (persisted `Endpoint`) |
| `/var/run/cilium/state/<id>_next/` | in-progress regeneration; swapped in with `renameat2(RENAME_EXCHANGE)` |
| `/var/run/cilium/state/<id>_next_fail/` | failed build kept for debugging; removed on next success |
| `/var/lib/cilium` (`--lib-dir`), `/var/lib/cilium/bpf` (`BpfDir`) | BPF sources/objects (area 02) |
| `/sys/fs/bpf` (`--bpf-root`, fallback `/run/cilium/bpffs`), `tc/globals/` | pinned maps |
| `/run/cilium/cgroupv2` (`--cgroup-root`) | cgroup2 mount |
| `/var/run/cilium/cilium-cni.log` | CNI plugin log |
| `/tmp/cilium/config-map` | resolved config dir written by `cilium-dbg build-config` |

Restore reads only dirs whose name is a bare numeric ID; `_next`/`_next_fail` dirs are
deleted (`partitionEPDirNamesByRestoreStatus`). If the JSON is unparseable the dir is
removed and counted as failed.

### Persisted endpoint (`ep_config.json`, `serializableEndpoint`)

Field (JSON key when it differs): `ID` uint16; `ContainerID` (`dockerID`); `ContainerNetnsPath`;
`IfName` (host veth); `IfIndex`; `ParentIfIndex`; `ContainerIfName`; `IsSecondaryInterface`;
`Labels` (`OpLabels`: Custom/OrchestrationIdentity/Disabled/OrchestrationInfo label sets);
`LXCMAC`; `IPv6`; `IPv6IPAMPool`; `IPv4`; `IPv4IPAMPool`; `NodeMAC`; `SecurityIdentity`
(`SecLabel`: numeric ID + labels); `Options` (`IntOptions` map of the runtime options above);
`DNSRules` (legacy, ignored) / `DNSRulesV2` (restored L7 DNS rules keyed by port/proto);
`DNSHistory` (`fqdn.DNSCache`); `DNSZombies`; `K8sPodName`; `K8sNamespace`; `K8sUID`;
`DatapathConfiguration` (`models.EndpointDatapathConfiguration`: `disable-sip-verification`,
`external-ipam`, `install-endpoint-route`, `require-arp-passthrough`, `require-egress-prog`,
`require-routing`); `CiliumEndpointUID`; `Properties` (`property-fake-endpoint`,
`property-at-host-network-namespace`, `property-without-bpf-endpoint`,
`property-skip-bpf-policy`, `property-skip-bpf-regeneration`, `property-cep-owner`,
`property-cep-name`, `property-skip-masquerade-v4/v6`, `property-rt-info`); `NetnsCookie`
uint64; `RTInfo` uint32 (FIB table id).

Not persisted (rebuilt): state, policy revision, proxy redirects/statistics, controllers,
realized/desired policy, status log. The JSON is also embedded as a comment at the top
of `ep_config.h`; both files are written with `renameio` (temp + rename) into the `_next`
dir. `SyncEndpointHeaderFile` rewrites `ep_config.h` in place on DNS-rule changes via a
trigger.

### Endpoint state machine (`pkg/endpoint/endpoint.go` `setState`)

States (`models.EndpointState`): `waiting-for-identity`, `ready`,
`waiting-to-regenerate`, `regenerating`, `disconnecting`, `disconnected`, `restoring`,
`invalid`. Allowed transitions:

| from | to |
|---|---|
| `""` (new) | `waiting-for-identity`, `restoring` |
| `waiting-for-identity` | `ready`, `disconnecting`, `invalid` |
| `ready` | `waiting-for-identity`, `disconnecting`, `waiting-to-regenerate`, `restoring` |
| `waiting-to-regenerate` | `disconnecting`, `restoring` (→`waiting-for-identity`/self explicitly rejected, returns false) |
| `regenerating` | `waiting-for-identity`, `disconnecting`, `waiting-to-regenerate`, `restoring` |
| `restoring` | `disconnecting`, `restoring` |
| `disconnecting` | `disconnected` |
| `disconnected`, `invalid` | terminal |

`waiting-to-regenerate → regenerating → ready` is done by the build path (`BuilderSetStateLocked`),
not `setState`. Invalid transitions are logged (`Invalid state transition skipped`) and
recorded in the status log as a Warning; `cilium_endpoint_state` gauge tracks counts.

### Regeneration (`policy.go` `regenerate`, `bpf.go` `regenerateBPF`)

Levels: `RegenerateWithoutDatapath` (`no-rebuild`: policy map + proxy only) and
`RegenerateWithDatapath` (`rewrite+load`). Reasons (strings surfaced in status log and
metrics): `DaemonConfigUpdate`, `DeviceConfigurationChanged`, `PeriodicRegeneration`,
`EndpointUpdate`, `EndpointInit`, `EndpointRestore`, `LabelsUpdate`, `AnnotationsUpdate`,
`PolicyUpdate`, `SelectorPolicyStale`, `RegenerationFailure`, `DeferredRegeneration`,
`DeamonTrigger` (sic). Steps: acquire build mutex → serialised via event queue → wait
policy repository revision ≥ `PolicyRevisionToWaitFor` → compute `SelectorPolicy`/`EndpointPolicy`
→ `runPreCompilationSteps` (create `_next` dir, open/create per-endpoint policy map
`cilium_policy_v2_<id>`, dump it, write `ep_config.h`+json, proxy redirects) →
`EndpointHash` (skip compile if unchanged) → `orchestrator.ReloadDatapath` (area 02) →
`lxcMap.WriteEndpoint` (`cilium_lxc`) → wait proxy ACKs → policy-map sync → CT GC once
(`ctCleaned`) → `synchronizeDirectories` swap → set `policyRevision`, wake
`WaitForPolicyRevision` waiters. Concurrency: `endpointBuildQueue` semaphore of
`runtime.NumCPU()` builds. Failure → `endpoint-<id>-regeneration-recovery` controller retries
(1 s RunInterval). `regeneration.Fence` (hive fence) blocks the first regeneration until
LB init and ClusterMesh IP-identity sync (`clustermesh-ip-identities-sync-timeout`) are done.

### Endpoint identity/labels

`OpLabels`: `Custom` (API), `OrchestrationIdentity` (k8s pod labels filtered by
`labels`/`label-prefix-file`, namespace labels prefixed `io.cilium.k8s.namespace.labels.`),
`Disabled`, `OrchestrationInfo` (non-identity). New endpoints without labels get
`reserved:init`. Identity resolved by `runIdentityResolver` controller
`resolve-identity-<id>`; k8s metadata by `resolve-labels-<id>` controller (jittered by
`identity-change-grace-period` 5 s / `cilium-identity-max-jitter` 30 s).

### Endpoint IDs

`epIDAllocator`: `idpool` 1..4095 (`maxID = 4095`); `reuse(id)` on restore; IDs used as
`cilium_policy_v2_<id>` map suffix and lxc map `LxcID`. `models.Endpoint.ID` is int64 on
the wire. Lookups by: cilium ID, CNI attachment ID (`<containerID>:<containerIfName>`),
container ID, IPv4, IPv6, CEP name (`<ns>/<pod>`), pod name, namespace, service account.
Prefixes for `GET /endpoint/{id}`: `cilium-local:`, `cilium-global:`, `cni-attachment-id:`,
`container-id:`, `container-name:`, `pod-name:`, `cep-name:`, `ipv4:`, `ipv6:`.

### REST models that matter (from `api/v1/models`)

- `EndpointChangeRequest` (PUT body): `addressing{ipv4,ipv4-pool-name,ipv4-expiration-uuid,ipv6,...}`, `container-id`, `container-interface-name`, `container-netns-path`, `datapath-configuration`, `datapath-map-id`, `host-mac`, `id`, `interface-index`, `interface-name`, `is-secondary-interface`, `k8s-namespace`, `k8s-pod-name`, `k8s-uid`, `labels[]`, `mac`, `netns-cookie`, `parent-interface-index`, `pid`, `policy-enabled`, `properties{}`, `state` (required), `sync-build-endpoint`.
- `Endpoint`: `id`, `spec{label-configuration,options}`, `status{controllers,external-identifiers,health,identity,labels{derived,disabled,realized,security-relevant},log[],namedPorts,networking{addressing[],container-interface-name,host-addressing,host-mac,interface-index,interface-name,mac},policy{proxy-policy-revision,proxy-statistics,realized,spec},realized,state}`.
- `DaemonConfigurationStatus` (GET /config, consumed by CNI): `addressing`, `ipam-mode`, `datapath-mode`, `configured-datapath-mode`, `route-mtu`, `device-mtu`, `device-headroom/tailroom`, `gro/gso-max-size(-v4)`, `masquerade`, `masquerade-protocols`, `ip-local-reserved-ports`, `enable-route-mtu-for-cni-chaining`, `install-uplink-routes-for-delegated-ipam`, `packetization-layer-pmtud-mode`, `enable-bbr-host-namespace-only`, `daemon-configuration-map` (full DaemonConfig), `immutable`, `realized{options,policy-enforcement}`, `k8s-configuration`, `k8s-endpoint`, `kvstore-configuration`, `node-monitor`.
- `IPAMResponse` (POST /ipam): `address{ipv4,ipv6,pool names,expiration uuids}`, `host-addressing`, `ipv4/ipv6{ip,gateway,cidrs[],master-mac,interface-number,expiration-uuid,skip-masquerade}`.
- `StatusResponse` (GET /healthz): `cilium`, `kubernetes`, `kvstore`, `cluster{ciliumHealth,nodes,self}`, `cluster-mesh`, `controllers[]`, `ipam{allocations,ipv4[],ipv6[]}`, `kube-proxy-replacement`, `masquerading`, `encryption`, `hubble`, `hubble-metrics`, `host-firewall`, `bandwidth-manager`, `bpf-maps{dynamic-size-ratio,maps[]}`, `identity-range`, `routing`, `datapath-mode`, `attach-mode`, `clock-source`, `cni-chaining`, `cni-file`, `ipv4/ipv6-big-tcp`, `srv6`, `node-monitor`, `proxy`, `auth-certificate-provider`, `client-id`, `stale{probe:time}`.
- Health API: `HealthStatusResponse{local{name},nodes[]{name,host{primary-address{ip,icmp,http},secondary-addresses},health-endpoint{primary-address,secondary-addresses},endpoint(deprecated)},probeInterval,timestamp}`; `ConnectivityStatus{status,latency(ns),lastProbed}`; `HealthResponse{cilium(StatusResponse),systemLoad,uptime}`.

### Small utility semantics worth preserving

- `controller.ControllerParams`: `Group`, `Health`, `DoFunc`, `StopFunc`, `RunInterval`, `MaxRetryInterval`, `ErrorRetryBaseDuration` (exponential backoff on error), `NoErrorRetry`, `Jitter`, `CancelDoFuncOnUpdate`, `Context`. Controllers are named, listed in `StatusResponse.Controllers` and `cilium-dbg status --all-controllers`, and per-endpoint in `Endpoint.status.controllers`. Metrics `cilium_controllers_runs_total`, `_runs_duration_seconds`, `_failing`, `_group_runs_total` (per `controller-group-metrics`).
- `trigger.Parameters{MinInterval, TriggerFunc(reasons), Name}`; `rate.Limiter` (token bucket); `promise.New[T]() (Resolver, Promise)` with `Await(ctx)`/`Map`; `pkg/time` wraps std time with `MaxInternalTimerDelay` test knob; `pidfile.Write/Read/Kill`; `version.Version` = `"<ver> go version <go> <os>/<arch>"` parsed back by `FromString`; `components.IsCiliumAgent()` checks `os.Args[0]`.
- `lock.RWMutex` = `sync.RWMutex` unless built with `-tags lockdebug` (deadlock detection, 30 s timeout).

## External interfaces

### Startup order (`daemon/cmd/cells.go`, `daemon.go`, `daemon_main.go`)

1. cobra `cilium-agent` → `InitConfig` (config-dir/env/file) → `initDaemonConfigAndLogging` (`SetupLogging`, `Populate`) → `initEnv`: require root, `EnableMapPreAllocation`/`DistributedLRU`, compute `BpfDir=<lib-dir>/bpf`, `StateDir=<run-dir>/state`; mkdir run/state/lib/envoy-socket dirs; `rlimit.RemoveMemlock`; mkdir `state/globals`; `chdir(StateDir)`; check BPF template dir; `probes.CreateHeaderFiles` (feature macros in `bpf/include/bpf/*`); write pidfile; validate `allow-localhost`, `kvstore`/`identity-allocation-mode` combos; `Config.Validate`.
2. `hive.Run` with `Infrastructure` module: pprof, gops, health history (`<state-dir>` history dir), k8s client, kvstore client, **CNI config manager cell**, metrics, `metricsmap`, `iptrace`, `ratelimitmap`, **API server cell** (`configureAPIServer`: unix listener only, 60 s read/write timeout, `/statedb/` mux), CRD sync (`k8sSynced.CRDSyncCell` waits for all Cilium CRDs), shell server, `healthz` (9879 + 10256).
3. `ControlPlane`: `infraendpoints` (router/health/ingress IP allocation, host endpoint, ingress endpoint), `hostIPSyncCell`, **`endpointRestoreCell`**, local node store, controller cell, k8s resources/tables, `endpoint.Cell` (`EndpointManager`, `Regenerator`, creator, API handlers, deletion queue, watchdog), node manager, neighbor discovery, cert manager, `daemonCell`/`daemonConfigCell`, maglev, LB, proxy, envoy, CEC, restapi, bgp, signal, auth, identity, ipcache, ipam, egressgw, ipmasq, kpr, policy (+commands, compute, k8s, directory), clustermesh, l2announcer, nodediscovery, cgroup manager, nat stats, k8s watchers, dynamicconfig, dynamiclifecycle, driftchecker, hubble, features, source, fqdn, health, healthconfig, status, debugapi, svcrouteconfig, ztunnel, subnet. Then `datapath.Cell` (area 03).
4. Lifecycle OnStart hooks in dependency order. Key ones for endpoints:
   - `endpointRestoreCell` OnStart: `clearStaleCiliumEndpointVeths` (deletes host veths whose peer is an `lxc*` veth also in host ns — i.e. orphan pairs), `readOldEndpointsFromDisk` (parse every `<state-dir>/<id>/ep_config.json`), notify `RestorationNotifier`s (IPAM, ipcache…) with the *possible* set.
   - `daemonConfigInitialization`: `StoreInFile`, `StoreViperInFile`, `ValidateUnchanged`.
   - `daemonLegacyInitialization` OnStart → `configureDaemon`: wait CRD sync promise; `UpdateCiliumNodeResource` for cluster-pool/multi-pool/eni; `WaitForNodeInformation`; direct-routing device detection (error if required by KPR/WG/IPsec and absent); `FinishKubeProxyReplacementInit`; host-firewall needs `devices`; `K8sWatcher.InitK8sSubsystem`; `IPAMInitializer.ConfigureAndStartIPAM`; **`RestoreOldEndpoints`** (validate each: health endpoints dropped and their dirs removed; pod must exist in informer cache and be scheduled on this node else `DeleteK8sCiliumEndpointSync`+skip; `ValidateConnectorPlumbing` (host link exists); re-allocate IPv4/IPv6 via `AllocateIPWithoutSyncUpstream` (with `bypass-ip-availability-upon-restore` escape hatch); datapath-mode compatibility check veth vs netkit — refuses to start if existing endpoints use an incompatible link type); `InfraIPAllocator.AllocateIPs` (router IP preferred from filesystem `cilium_host` over CiliumNode; health IPs; ingress IPs); `NodeDiscovery.StartDiscovery`; `AnnotateK8sNode`; `IPAMInitializer.RestoreFinished`; `InitIdentityAllocator`; `SyncHostIPs.StartAndWaitFirst`; IPsec key watcher; `ValidatePostInit`. Sends monitor `AgentStart` event; OnStop `pidfile.Clean`.
5. Jobs after start: `finish-endpoint-restore` (`InitRestore`): wait k8s caches synced (`k8s-sync-timeout` 3m) → wait policy directory watcher (`policy-dir` static YAML) → wait ipcache revision ≥ 1 → `regenerateRestoredEndpoints`: `RestoreEndpoint` into manager for each (reuse ID, expose), remove `toClean` endpoints (`NoIdentityRelease`, `NoIPRelease`), then in background `RegenerateAfterRestore` per endpoint (identity re-allocation via controller `restoring-ep-identity (<id>)`, wait `WaitForInitialGlobalIdentities`, wait fence, `RegenerateWithDatapath`) and `WaitForInitialPolicy`. Three channels expose progress: `endpointRestoreComplete` (restored into manager), `endpointInitialPolicyComplete`, `endpointRegenerateComplete`. Consumers via `endpointstate.Restorer` promise: cilium-health (waits restore-without-regen), CNI deletion queue (same), BPF prog watchdog, infra endpoints.
6. Host endpoint (`init-host-endpoint` job; labels `reserved:host` + node labels), ingress endpoint (`reserved:ingress`, when `enable-envoy-config`/ingress), health endpoint (`reserved:health`) are created as endpoints too, so every node has at least the host endpoint in `cilium-dbg endpoint list`.
7. CNI conf file written by `write-cni-file` controller once the API is up (the kubelet treats a node as NotReady until a CNI conf exists — this is the "agent ready" signal). `cilium-agent` pod readinessProbe/livenessProbe hit `127.0.0.1:9879/healthz` (header `brief: true`, `require-k8s-connectivity`).
8. Shutdown: `unloadDNSPolicies` (`dnsproxy-unload-on-shutdown` removes wildcard L7 DNS rules so pods keep resolving while Envoy/DNS proxy is down), OnStop hooks reverse order, state on disk left intact for the next agent.

**What must exist before an endpoint regenerates**: BPF fs mounted and `globals/node_config.h` written (datapath init), `cilium_lxc`/`cilium_ipcache`/policy maps opened, IPAM restored (so the IP can be re-claimed), identity allocator initialised and initial global identities listed (kvstore or CRD list), k8s pod/namespace caches synced (labels), policy repository at revision ≥ 1 with directory policies ingested, ipcache revision ≥ 1, LB initialised (fence), ClusterMesh IP sync (fence, bounded by timeout), proxy (Envoy) ports allocated if redirects.

### Restart/upgrade continuity

- Datapath keeps forwarding during restart: BPF programs and pinned maps persist; the agent does not detach on stop. Per-endpoint policy maps are reopened and *dumped* before the first regeneration so that a diff, not a wipe, is applied (`policyMapDump`). `cilium_lxc` entries for IPs not restored are deleted after restore.
- `policyRevision` is per-endpoint and in-memory; the policy repository starts at revision 1 on each boot. `cilium-dbg policy wait <rev>` and `WaitForEndpointsAtPolicyRev` work within one agent lifetime only. CNI `PUT /endpoint` with `sync-build-endpoint=true` waits for the first regeneration (`WaitForFirstRegeneration`).
- `agent-runtime-config.json` from the previous run is what `ValidateUnchanged` compares against; immutable options (e.g. `enable-ipv4/6`, `tunnel-protocol`, `routing-mode`, `datapath-mode` link type for existing endpoints) cannot be changed without draining.
- IP expiration: `POST /ipam` allocations start a 10 min expiration timer (`IPAMExpiration`) unless `expiration=false`; `PUT /endpoint` with matching `ipv4-expiration-uuid` stops it. Prevents leaks when CNI ADD dies between the two calls.
- Deletion queue: when the agent is down the CNI writes `/var/run/cilium/deleteQueue/<file>.delete`; on start the agent takes the exclusive flock on `deleteQueue/lockfile` *before* serving the API, replays queued deletes (by container ID), then unlocks (`unlock-lockfile` job after the server cell starts). The CNI takes a shared lock while enqueueing; refuses when the directory has too many entries.

### Agent REST API (`api/v1/openapi.yaml`, basePath `/v1`, unix socket only)

Operation IDs are `Method+PascalPath` (e.g. `PutEndpointID`, `GetEndpointIDConfig`) — that is also the `--enable-cilium-api-server-access` token. Consumers: **cni** = `plugins/cilium-cni`, **dbg** = `cilium-dbg`, **health** = cilium-health server/CLI, **kubelet** = via 9879 (not the socket), **operator** = `operator/cmd/status.go`, **hubble** = Hubble does *not* use the REST API (in-process). Rate-limited ops marked (RL).

| Method path | Tag | Params | Responses | Consumers / notes |
|---|---|---|---|---|
| `GET /healthz` | daemon | headers `brief`, `require-k8s-connectivity` | 200 `StatusResponse` | dbg status, health server (waits for it before serving), operator, encrypt status, monitor |
| `GET /cluster/nodes` | daemon | header `client-id` | 200 `ClusterNodeStatus{client-id,nodes-added[],nodes-removed[],self}` | health prober (incremental node list), dbg node list |
| `GET /config` | daemon | – | 200 `DaemonConfiguration{spec,status}` | **cni** (first call on every ADD), dbg config/kvstore/troubleshoot |
| `PATCH /config` | daemon | body `DaemonConfigurationSpec{options,policy-enforcement}` | 200, 400, 403, 500 | dbg config `X=enable`; triggers `RegenerateAllEndpoints(ReasonDaemonConfigUpdate)` |
| `GET /endpoint` | endpoint | query `labels[]` | 200 `[]Endpoint`, 404, 429 | dbg endpoint list, monitor, policy wait (RL `endpoint-list`) |
| `DELETE /endpoint` | endpoint | body `EndpointBatchDeleteRequest{container-id}` | 200, 206 int (partial), 400, 404, 429, 503 | cni DEL by container ID (RL `endpoint-delete`) |
| `GET /endpoint/{id}` | endpoint | path id (prefixes above) | 200 `Endpoint`, 400, 404, 429 | dbg endpoint get, cni CHECK (RL `endpoint-get`) |
| `PUT /endpoint/{id}` | endpoint | body `EndpointChangeRequest` | 201 `Endpoint`, 400, 403, 409 exists, 429, 500, 503 | **cni ADD**, generic-veth chainer, health endpoint (in-process) (RL `endpoint-create`) |
| `PATCH /endpoint/{id}` | endpoint | body `EndpointChangeRequest` | 200, 400, 403, 404, 429, 500, 503 | state changes only `ready`/`waiting-for-identity`; address/label/mac updates → regenerate (RL `endpoint-patch`) |
| `DELETE /endpoint/{id}` | endpoint | path id | 200, 206 int, 400, 403, 404, 429, 503 | **cni DEL**, dbg endpoint disconnect (RL `endpoint-delete`) |
| `GET /endpoint/{id}/config` | endpoint | – | 200 `EndpointConfigurationStatus{immutable,realized}`, 404 | dbg endpoint config |
| `PATCH /endpoint/{id}/config` | endpoint | body `EndpointConfigurationSpec{options,label-configuration}` | 200, 400, 403, 404, 429, 500, 503 | dbg endpoint config `Debug=enable` (RL patch) |
| `GET /endpoint/{id}/labels` | endpoint | – | 200 `LabelConfiguration{spec{user},status{derived,disabled,realized,security-relevant}}` | dbg endpoint labels |
| `PATCH /endpoint/{id}/labels` | endpoint | body `LabelConfigurationSpec{user[]}` | 200, 403, 404, 429, 500, 503 | dbg endpoint labels `-a/-d` |
| `GET /endpoint/{id}/log` | endpoint | – | 200 `EndpointStatusLog[]{code,message,state,timestamp}` (ring of 256) | dbg endpoint log |
| `GET /endpoint/{id}/healthz` | endpoint | – | 200 `EndpointHealth{bpf,connected,overallHealth,policy}` | dbg endpoint health |
| `GET /identity` | policy | query `labels[]` | 200 `[]Identity{id,labels[],labelsSHA256}`, 404, 520, 521 | dbg identity list |
| `GET /identity/{id}` | policy | path id | 200 `Identity`, 400, 404, 520, 521 | dbg identity get |
| `GET /identity/endpoints` | policy | – | 200 `[]IdentityEndpoints{identity,refCount}` | dbg identity list --endpoints |
| `POST /ipam` | ipam | query `family` (ipv4/ipv6), `owner`, `pool`, `expiration` (header bool) | 201 `IPAMResponse`, 403, 502 | **cni ADD** (`owner=<ns>/<pod>`, expiration true) |
| `POST /ipam/{ip}` | ipam | path ip, query `owner`, `pool` | 200, 400, 403, 409, 500, 501 | allocate a specific IP (dbg not wired; used by tests) |
| `DELETE /ipam/{ip}` | ipam | path ip, query `pool` | 200, 400, 403, 404, 500, 501 | **cni** rollback on failed ADD |
| `GET /policy` | policy | – | 200 `Policy{revision,policy(json rules)}`, 404 | dbg policy get |
| `GET /policy/selectors` | policy | – | 200 `SelectorCache[]{identities[],selector,users}` | dbg policy selectors |
| `GET /policy/subject-selectors` | policy | – | 200 `SelectorCache` | dbg policy selectors --subject (local subjects) |
| `GET /lrp` | service | – | 200 `[]LRPSpec` | dbg lrp list |
| `GET /service` | service | – | 200 `[]Service{spec,status}` | dbg service list |
| `GET /prefilter` | prefilter | – | 200 `Prefilter{spec{deny[],revision},status}`, 500 | dbg prefilter list (XDP prefilter CIDRs) |
| `PATCH /prefilter` | prefilter | body `PrefilterSpec` | 200, 403, 461, 500 | dbg prefilter update |
| `DELETE /prefilter` | prefilter | body `PrefilterSpec` | 200, 403, 461, 500 | dbg prefilter delete |
| `GET /debuginfo` | daemon | – | 200 `DebugInfo{cilium-version,kernel-version,cilium-nodemonitor,cilium-status,cilium-memory-map,endpoint-list,policy,service-list,subsystem{}, encryption}`, 500 | dbg debuginfo, dbg version (daemon version), bugtool |
| `GET /cgroup-dump-metadata` | daemon | – | 200 `CgroupDumpMetadata{pod-metadatas[]}`, 500 | dbg cgroups list |
| `GET /map` | daemon | – | 200 `BPFMapList{maps[]{name,path,cache-enabled,cache{...}}}` | dbg map list |
| `GET /map/{name}` | daemon | path name | 200 `BPFMap`, 404 | dbg map get (userspace cache view, not BPF dump) |
| `GET /map/{name}/events` | daemon | path name, query `follow` | 200 stream (JSON lines), 404 | dbg map events (`bpf-map-event-buffers`) |
| `GET /fqdn/cache` | policy | query `matchpattern`, `cidr`, `source` | 200 `[]DNSLookup`, 400, 404 | dbg fqdn cache list |
| `DELETE /fqdn/cache` | policy | query `matchpattern` | 200, 400, 403 | dbg fqdn cache clean |
| `GET /fqdn/cache/{id}` | policy | path endpoint id + same query | 200 `[]DNSLookup`, 400, 404 | dbg fqdn cache list -e |
| `GET /fqdn/names` | policy | – | 200 `NameManager{DNSPollNames[],FQDNPolicySelectors[]}`, 400 | dbg fqdn names |
| `GET /ip` | policy | query `cidr`, `labels[]` | 200 `[]IPListEntry{cidr,identity,hostIP,metadata{name,namespace,source}}`, 400, 404 | dbg ip list/get (ipcache) |
| `GET /node/ids` | daemon | – | 200 `[]NodeID{id,ips[]}` | dbg nodeid list |
| `GET /bgp/peers` | bgp | – | 200 `[]BgpPeer`, 500, 501 | dbg bgp peers |
| `GET /bgp/routes` | bgp | query `table_type`, `afi`, `safi`, `router_asn`, `neighbor` | 200 `[]BgpRoute`, 500, 501 | dbg bgp routes |
| `GET /bgp/route-policies` | bgp | query `router_asn` | 200 `[]BgpRoutePolicy`, 500, 501 | dbg bgp route-policies |
| `GET /statedb/dump`, `/statedb/query` (not in swagger) | – | – | JSON | dbg statedb, `statedb.RemoteTable` |

Header `X-Cilium-Client-Version`? — not used; the client passes nothing. Errors are
`models.Error` (string). HTTP 429 comes from the API limiter with `Retry-After`.

Deprecated/removed since older releases (not in 1.20 spec, so out of scope): `PUT/DELETE /policy`,
`GET /metrics/`, `/recorder`, `/service/{id}` writes.

### cilium-health API (`api/v1/health/openapi.yaml`, basePath `/v1beta`, `/var/run/cilium/health.sock`)

| Method path | Response | Consumer |
|---|---|---|
| `GET /healthz` | `HealthResponse{cilium(StatusResponse),systemLoad{last1min,last5min,last15min},uptime}` | `cilium-health get`, `cilium-health ping` |
| `GET /status` | `HealthStatusResponse` (last probe) | `cilium-health status`, dbg status (via statedb health table in 1.20) |
| `PUT /status/probe` | `HealthStatusResponse` (runs a synchronous probe of all nodes) | `cilium-health status --probe` |

### Other listeners the agent opens

| Listener | Purpose |
|---|---|
| `127.0.0.1:9879` and `[::1]:9879` (`agent-health-port`) `GET /healthz` | kubelet liveness/readiness/startup probes; returns 200/500 from `StatusCollector.GetStatus(brief=true)`; header `require-k8s-connectivity` |
| `kube-proxy-replacement-healthz-bind-address` (e.g. `0.0.0.0:10256`) `GET /healthz` | kube-proxy compatible `{"lastUpdated","currentTime"}` for cloud LB health checks |
| `:4240` (`cluster-health-port`) HTTP `GET /hello` on all node IPs + inside `cilium-health-ep` | health probe responder (plain `net/http`) |
| `9890` gops (`enable-gops`, `gops-port`), `pprof-address:pprof-port` | debugging |
| `prometheus-serve-addr` (default `:9962` via Helm) | metrics |
| `/var/run/cilium/shell.sock` | hive shell |

### Health checking architecture (`pkg/health`, `cilium-health`)

- Server (`pkg/health/server`) runs inside the agent (`health.Cell`): waits for
  `WaitForEndpointRestoreWithoutRegeneration`, then `launchCiliumNodeHealth` (REST on
  `health.sock`, `/hello` responder bound on every local node address at `:4240`) and, if
  `enable-endpoint-health-checking`, `launchAsEndpoint`: creates a netns, a veth/netkit pair
  `lxc_health`, an `Endpoint` with labels `reserved:health`, IPv4/IPv6 from the node's
  `IPv4HealthIP`/`IPv6HealthIP` (allocated from the pod CIDR, published in CiliumNode
  `.spec.health`), execs `cilium-health-responder --listen 4240 --pidfile
  <state-dir>/health-endpoint.pid` inside the netns, installs routes via `cilium_host`
  (per `getHealthRoutes`), optional endpoint routes (`enable-endpoint-routes`) and
  ENI-style rules when `GetHealthEndpointRouting()` is set. A controller
  (`cilium-health-ep`, 60 s) pings it and relaunches after 5 min without success. On agent
  restart the old health endpoint dir is deleted and the endpoint recreated.
- Prober (`prober.go`): node list from `GET /cluster/nodes` (incremental with `client-id`);
  per node probes primary and secondary addresses of **host** (node IP) and **health
  endpoint** (health IP) with ICMP echo (`go-ping`, `HealthCheckICMPFailureThreshold` 3
  requests, 100 ms apart) and HTTP `GET http://<ip>:4240/hello` (10 s timeout). Probe
  interval = `ClusterSizeDependantInterval(10 s + ratio·100 s, #IPs)` with
  `connectivity-probe-frequency-ratio` 0.5 → base 60 s, growing logarithmically with
  cluster size; per-probe rate limiter spreads requests evenly across the interval.
  Results → `HealthStatusResponse` and metrics `cilium_node_health_connectivity_status{type=node|endpoint,protocol=icmp|http,address_type=primary|secondary,status}`,
  `cilium_node_health_connectivity_latency_seconds`.
- Network requirements: ICMP echo and TCP/4240 allowed node↔node and node↔health-IP
  (health IPs live in pod CIDR, so tunnel/native routing must carry them; the host
  firewall auto-allows `reserved:health`). Requires `NET_RAW` for ICMP.
- `cilium-health` CLI: `get` (`GET /healthz`), `ping`, `status [--probe] [--succinct] [--verbose] [-o json]`; `-H`/`CILIUM_HEALTH_SOCK`.

### Status collector (`pkg/status`)

Probes (name → interval override): `kvstore`, `kubernetes` (backoff to 2 min cluster-size
dependant on failure, 10 s success), `ipam`, `node-monitor`, `cluster`, `cilium-health`,
`l7-proxy`, `controllers`, `clustermesh`, `hubble`, `hubble-metrics`, `encryption`,
`kube-proxy-replacement`, `auth-cert-provider`, `cni-config`, `masquerading`, `bigtcp-v6`,
`bigtcp-v4`, `bandwidth-manager`, `host-firewall`, `routing`, `clock-source`, `bpf-maps`,
`cni-chaining`, `identity-range`, `SRv6`, `attach-mode`, `datapath-mode`,
`configured-datapath-mode`. Defaults: `status-collector-interval` 5 s,
`status-collector-warning-threshold` 15 s (probe marked stale, appears in `stale{}`),
`status-collector-failure-threshold` 1 m (probe cancelled, error recorded),
`status-collector-probe-check-timeout`, `status-collector-stackdump-path` (dump goroutines
when probes hang). `GET /healthz` returns 500 until every probe ran once
("Not all probes executed at least once") and when `cilium`/`kvstore`/`kubernetes`(if
required) are Failure.

### CNI plugin (`plugins/cilium-cni`)

- Binary `cilium-cni`, installed by the `install-cni-binaries` init container to
  `/opt/cni/bin`. `skel.PluginMainFuncs{Add,Del,Check,Status}`, supports CNI spec
  `0.1.0, 0.2.0, 0.3.0, 0.3.1, 0.4.0, 1.0.0, 1.1.0` (STATUS verb from 1.1.0). `runtime.LockOSThread`
  in init (netns switching). Logging to `log-file` (default `/var/run/cilium/cilium-cni.log`),
  `log-format`, `enable-debug`; optional gops when debug.
- NetConf JSON (`types.NetConf`): standard fields + `mtu`, `enable-route-mtu`, `eni{}`,
  `azure{}`, `alibaba-cloud{}`, `ipam{type,…,IPAMSpec}`, `enable-debug`, `log-format`,
  `log-file`, `chaining-mode`. Agent-written default conflist:
  `{"cniVersion":"0.3.1","name":"cilium","plugins":[{"type":"cilium-cni","enable-debug":…,"log-file":"…"}]}`
  (mode `none`); `portmap` adds the upstream `portmap` plugin with `capabilities.portMappings`;
  `flannel`/`aws-cni`/`generic-veth` set `chaining-mode` and, with `cni-chaining-target`,
  the `{"type":"cilium-cni","chaining-mode":…}` entry is spliced into the existing
  conflist's `plugins[]` (replacing an earlier `cilium-cni` entry if present). Azure
  chaining is `generic-veth` with `cni-chaining-mode=generic-veth`. Chaining plugin registry
  (`chaining/api`): `aws-cni`, `flannel` → `GenericVethChainer`, `generic-veth`; the
  name `cilium` is reserved; `portmap` is treated as no chaining.
- CNI args (`ArgsSpec`): `K8S_POD_NAME`, `K8S_POD_NAMESPACE`, `K8S_POD_UID`. Exit codes:
  `CniErrPluginNotAvailable` 50, `CniErrHealthzGet` 100, `CniErrUnhealthy` 101.
- **ADD** (`cmd.Add`): parse conf → logging → client on `CILIUM_SOCK` with 30 s connect
  timeout → `GET /config` (fatal if agent not up: kubelet retries) → `OnConfigReady` hooks
  → if `prevResult` present or `chaining-mode` set: run chainer (generic-veth: find the
  veth inside the pod netns created by the other CNI, read its IPs/MAC, find host peer,
  `PUT /endpoint/{id}` with `RequireArpPassthrough`, `RequireEgressProg`,
  `RequireRouting=!cni-external-routing`, `ExternalIpam=true`, `SyncBuildEndpoint`; sets
  `rp_filter=0`… and returns prevResult). Otherwise: open pinned netns, delete any
  existing `args.IfName` in it; **IPAM**: `ipam-mode=delegated-plugin` →
  `cniInvoke.DelegateAdd(conf.ipam.type)` (host-local, azure, etc.) and translate result
  into `IPAMResponse` (gateway/routes/uplink interface); any other mode →
  `POST /ipam?family=&owner=<ns>/<pod>&pool=&expiration=true` (ENI/Azure/AlibabaCloud
  return `master-mac`/`gateway`/`cidrs` for per-ENI routing) → release on any later
  failure. Build `EndpointChangeRequest{container-id, k8s pod/ns/uid, container-interface-name,
  state=waiting-for-identity, datapath-configuration{external-ipam for delegated},
  parent-interface-index (ENI: ifindex from master MAC), netns-cookie}` → create link
  pair with `connector.NewLinkPair(mode veth|netkit|netkit-l2, LinkConfig{MTU, GRO/GSO
  BIG-TCP sizes, headroom/tailroom})` → move peer into netns, set MAC/names → configure IPs
  and routes inside netns (`prepareIP`: /32 + /128 addresses, default routes via
  `169.254.42.1`-style host addressing with `route-mtu`; ENI/Azure/delegated with
  `install-uplink-routes-for-delegated-ipam`: `interfaceAdd` installs per-ENI rules/routes
  on host) → `reserveLocalIPPorts` (`ip_local_reserved_ports` sysctl from agent config,
  `container-ip-local-reserved-ports`), enable IPv6 in netns, PL-PMTUD and congestion
  control sysctls (`EnableBBRHostNamespaceOnly`) → `SyncBuildEndpoint=true` →
  **`PUT /endpoint/{id}`** (blocks until first regeneration; 60 s API max wait) → set pod
  MAC from `Status.Networking.Mac` if annotation set → return `Result{interfaces[host,
  container], ips[], routes[]}` in the requested `cniVersion`.
- **DEL**: parse → chainer `Delete` if chaining, else `DeletionFallbackClient.EndpointDelete(containerID, ifName)`:
  tries `DELETE /endpoint/{id}` via `cni-attachment-id:<cid>:<ifname>`; if the agent is
  unreachable (socket dir missing, connection refused, agent starting up → retries 5 s)
  it enqueues `EndpointBatchDeleteRequest{container-id}` to `/var/run/cilium/deleteQueue/`
  under a shared flock; agent-side errors (404/400) are not queued. Then `DelegateDel`
  for delegated IPAM, then remove the interface from the netns if it still exists (netns
  gone ⇒ success).
- **CHECK**: `GET /config`, `GET /endpoint/cni-attachment-id:…`, verifies interface in netns
  matches `prevResult` (`verifyInterface`), chainer `Check`. **STATUS** (1.1.0): `GET /healthz`
  (exit 100/101), chainer `Status`, `DelegateStatus` for delegated IPAM.
- IPAM modes (`pkg/ipam/option`): `kubernetes`, `crd`, `eni`, `azure`, `cluster-pool`,
  `multi-pool`, `alibabacloud`, `delegated-plugin`. There is no `dhcp`/`none` mode in
  cilium; "none" only exists for `cni-chaining-mode`. `ipam=delegated-plugin` disables
  agent IPAM entirely (`ExternalIpam=true` on endpoints; restore skips IP re-allocation).
- Hooks (`WithOnConfigReady`, `WithOnIPAMReady`, `WithOnLinkConfigReady`,
  `WithOnInterfaceConfigReady`) let downstream builds extend the plugin.

### Logging format (parsed by Hubble/tools)

`--log-driver` (`syslog` optional), `--log-opt format=text|text-ts|json|json-ts,level=…`
(also `syslog.level`, `syslog.facility`, `syslog.tag`, `syslog.network`, `syslog.address`).
Default `text-ts`: slog `TextHandler` → `time=2026-09-07T12:00:00.123456789Z level=info msg="…" subsys=daemon key=value …`;
`json-ts` → `{"time":…,"level":"info","msg":…,"subsys":…}`; the `-ts`-less forms drop
`time` (container runtimes add it). Levels: `debug info warn error panic fatal`
(`fatal` is `LevelError+16`, exits; `panic` `+8`). Every module logger carries
`subsys=<module-id>`; `error` key is `error`; 787 named fields in `pkg/logging/logfields`
(`endpointID`, `containerID`, `k8sPodName`, `identity`, `policyRevision`, `ipAddr`, …).
klog (client-go) is bridged into slog.

### Netlink / sysctl touched by this area

Agent: veth cleanup (`LinkDel` of orphan host veths), health netns creation (`netns.New`),
health veth pair `lxc_health`, routes inside health netns, `net.ipv4.conf.<if>.rp_filter`
etc. via `connector`. CNI: link pair creation, `ip_local_reserved_ports`,
`net.ipv6.conf.all.disable_ipv6=0` in pod netns, `net.ipv4.tcp_mtu_probing`
(`packetization-layer-pmtud-mode`), `net.ipv4.tcp_congestion_control=bbr` (BBR),
per-ENI `ip rule`/`ip route` tables (ENI/Azure/delegated uplink routes).

## Dependencies

- Inventory areas: 02 (loader/orchestrator: `ReloadDatapath`, `WriteEndpointConfig`, `EndpointHash`, `lxcmap`, `policymap`), 03 (devices, MTU, connector veth/netkit, node addressing, iptables), 05 (identity allocator, policy repository, selector cache, labels filter), 07 (IPAM `POST /ipam`, restore re-allocation, ENI routing), 09 (monitor agent `AgentStart`, Hubble reads endpoint manager), 11 (proxy redirects, DNS rules in `ep_config.json`, Envoy sockets), 12 (kvstore for identities, ClusterMesh fence), 13 (CEP/CES sync, CiliumNode, CRD sync wait).
- External: kubelet (CNI exec, 9879 probes), Kubernetes API (pods/namespaces/CEP/CiliumNode), etcd when `kvstore`, Envoy (only for L7).
- Go libs replaced in Rust: `cilium/hive` (DI), `statedb`, go-swagger, cobra/viper/pflag, `containernetworking/cni` skel, `vishvananda/netlink`, `go-ping`.

## Kernel / platform requirements

No BPF in this area itself. Needs: `renameat2(RENAME_EXCHANGE)` (Linux ≥ 3.15) for atomic
endpoint-dir swap; network namespaces (`setns`, `/proc/<pid>/ns/net`, netns cookies
`SO_NETNS_COOKIE` Linux ≥ 5.7 optional); veth or netkit (Linux ≥ 6.7 for netkit);
`flock` on tmpfs; `CAP_NET_ADMIN`, `CAP_NET_RAW` (ICMP prober), `CAP_SYS_ADMIN`/`BPF`
for the rest of the agent; memlock rlimit removal. Arch-neutral.

## Tests

- Unit (Go, lines): `daemon` 2545 (`policy_test.go` 992 and `endpoint_restore_test.go`
  are `PrivilegedTest` — need root/netlink), `pkg/endpoint` 3827 (state transitions,
  restore round-trip of `ep_config.json` incl. legacy `DNSRules`, directory swap,
  redirect/proxy port bookkeeping, status log ring), `pkg/endpointmanager` 2303 (ID
  allocator reuse/release, lookups, GC mark/sweep, CEP synchroniser create/patch/UID
  takeover, policy-map pressure), `pkg/option` 2269 (flag parsing, `config-dir`,
  `Validate` combos, map options), `pkg/health` 1695 (prober node maps, IPv6
  preference, client tree formatting), `pkg/api` 291 (allow/deny flag → path set),
  `plugins/cilium-cni` 663 (netconf parsing, deletion queue, chaining registry),
  `pkg/rate` 906 (limiter auto-adjust), `pkg/controller` 396, `pkg/lock` 430,
  `pkg/status` 230, `pkg/dynamicconfig` 539 (+3 `.txtar` script tests),
  `pkg/dynamiclifecycle` 300, `cilium-dbg` 1470 (mostly BPF map output formatting
  with fixtures), `bugtool` 376 (secret masking of Envoy dumps).
- `test/controlplane`: hive-based control-plane tests that boot the agent cells with fake
  k8s/datapath and golden files.
- CI workflows touching this area: `conformance-delegated-ipam.yaml`
  (`ipam=delegated-plugin` with host-local), `conformance-aws-cni.yaml` (aws-cni chaining),
  `conformance-aks.yaml`/`conformance-gke.yaml` (azure/gke chaining), `tests-e2e-upgrade.yaml`
  (restart/upgrade with endpoint restore, "no drops during upgrade"), `conformance-runtime.yaml`
  (agent without k8s), `tests-smoke*.yaml`, `k8s-kind-network-e2e.yaml`.
- Behaviours pinned: endpoints survive agent restart with same IP/identity/ID; stale
  `_next` dirs are discarded; a pod whose informer object is missing is *not* restored and
  its CEP is deleted; CNI DEL succeeds with the agent down; `PUT /endpoint` returns 409 on
  duplicate ID/attachment; `GET /healthz` is 500 until probes ran.

## Rust mapping

- **Process/DI**: do *not* mirror hive. Use a plain `tokio` runtime with an explicit
  `Agent` struct built in a hand-written order (the order above is the spec), each
  subsystem a `struct` with `async fn start(&self, ready: Readiness) -> Result` and
  `Arc<Notify>`/`tokio::sync::watch` for "fence" style barriers (`WaitForEndpointRestore…`,
  ipcache revision ≥ 1, LB init). Hive's real value — per-module health reporting, job
  groups, and flags-from-struct — maps to: a `health` registry (`DashMap<ModuleId, Status>`
  exposed over the API and `flowsdn-dbg`), `tokio::task::JoinSet` per module with
  cancellation via `CancellationToken`, and `clap` derive with `#[serde]` structs per
  subsystem. Keep a `Fence` type (list of named futures awaited before first regeneration).
  StateDB is optional; a few `RwLock<BTreeMap>` tables plus `watch` channels cover the
  agent's needs; keep the `/statedb/dump` route name only if `cilium-dbg statedb`
  compatibility is wanted (defer).
- **Config**: `clap` (long flags, env prefix `CILIUM_`) + a loader that reads the
  `config-dir` (file-per-key) and YAML; generate the option list from the table below so
  every `cilium-config` key parses (unknown keys → warning, not error, to survive Helm
  drift). `figment` or hand-rolled layering. Persist `agent-runtime-config.json` with
  `serde_json` and implement `ValidateUnchanged`.
- **REST API**: `axum` on `tokio::net::UnixListener` (`hyperlocal` not needed with axum
  0.7 `serve` + `UnixListener`), `serde` models hand-written from `openapi.yaml`
  (generated code is 97k Go lines; the useful surface is ~40 routes and ~120 structs —
  write them by hand, keep JSON field names byte-identical, `#[serde(rename_all =
  "kebab-case")]` mostly). Set socket group/mode with `nix::unistd::chown`/`fchmod`.
  Implement the allow/deny `Method+PascalPath` middleware and the `governor`-style
  limiter for `/endpoint` (rate + semaphore + auto-adjust; write it, it is ~300 lines).
  `cilium-dbg` and `cilium-health` from upstream can then be used unchanged against
  flowsdn for conformance.
- **Endpoint**: `Endpoint` as an actor (`mpsc` event queue per endpoint, one task),
  state enum with a `transition(to) -> Result` table identical to the Go one, status-log
  ring (`VecDeque<StatusLogEntry>` cap 256). Persist `ep_config.json` with `serde_json`
  (same field names, incl. `dockerID`, `OpLabels`, `SecLabel`, `DNSRulesV2`); write
  `ep_config.h` via a template (area 02 defines its content). Directory swap with
  `nix::fcntl::renameat2(RENAME_EXCHANGE)`; `tempfile::NamedTempFile::persist` for
  rename-into-place. Build queue = `tokio::sync::Semaphore(num_cpus)`.
- **Endpoint manager**: `RwLock<EndpointIndex>` with maps by id/IP/attachment/CEP name;
  ID pool 1..4095 (`BitVec`); periodic GC and regeneration `tokio::time::interval`.
  CEP sync via `kube-rs` (area 13).
- **Health**: `surge-ping` (ICMP, needs raw socket) + `hyper` client for `/hello`;
  responder = tiny `hyper` server; health endpoint = spawn `flowsdn-health-responder` in a
  netns (`nix::sched::setns`), reuse the endpoint creation path. Health REST on
  `health.sock` with `axum`.
- **CNI plugin**: `cni-plugin` crate (or hand-rolled: read `CNI_COMMAND`, `CNI_ARGS`,
  stdin JSON; print `Result`), `rtnetlink`/`netlink-packet-route` for veth/netkit and
  addresses/routes, `nix` for netns, `reqwest`+unix socket or `hyper` for the agent API,
  `fs2` flock for the deletion queue. Must be a small static binary (no tokio
  multi-thread; `current_thread` is fine) — kubelet execs it per pod.
- **Status collector**: one `tokio` task per probe with `timeout`, stale/failed tracking;
  serialise to `StatusResponse`.
- **Logging**: `tracing` + `tracing-subscriber` with a custom formatter producing slog's
  `time=… level=… msg=… subsys=…` and JSON layouts; keep field names from `logfields`
  where tools grep them (`endpointID`, `containerID`, `k8sPodName`, `identity`).
- **Controllers**: a `Controller` future with backoff (`backon`/`tokio-retry`), named, listed
  in status.
- **cilium-dbg**: start by *not* rewriting it — run upstream `cilium-dbg` against flowsdn's
  socket (REST-only commands work; `bpf *` commands read pinned maps directly and work if
  map names/layouts match area 02). Rewrite later as `flowsdn-dbg` with `clap`; the
  command tree below is the checklist.
- Hard parts: exact restore semantics (identity re-allocation before k8s caches, CEP
  ownership), `PUT /endpoint` blocking-until-regenerated with cancellation on CNI
  timeout, the chained-CNI conflist splicing, the interplay of the deletion-queue lock
  with API server start, and keeping `StatusResponse` shape stable for `cilium-dbg status`
  and Helm probes.

## Recommendation

**keep** (core of the agent; drop-in compatibility requires it). Replace hive with
explicit tokio composition; keep the REST API, socket paths, state-dir layout, `ep_config.json`
schema, state machine, CNI behaviour and config keys byte-compatible. Defer: StateDB
HTTP dump, hive shell (`shell.sock`) and its script commands, `dynamiclifecycle`,
`prefilter` API (XDP prefilter, rarely used), `cgroup-dump-metadata`, `map/{name}/events`,
bugtool (use upstream binary or a shell script first), `preflight`/`post-uninstall-cleanup`
subcommands. Effort: **L** (agent skeleton + config ~3k, REST models/routes ~5k, endpoint
+ manager + restore ~5k, health ~2k, CNI ~2.5k, status/controllers/logging ~2k ≈ 19–20k
lines of Rust; XL if `flowsdn-dbg` and bugtool are rewritten in the same phase).

## Open questions

- Do we commit to reading *old cilium* `ep_config.json` (in-place migration from Cilium
  to flowsdn on a live node) or only flowsdn-written state? The former forces keeping
  every legacy JSON key (`dockerID`, `DNSRules` v1) and the `OpLabels` shape.
- `datapath-mode=netkit` endpoints cannot coexist with veth ones on restore; do we keep
  that restriction or implement per-endpoint mode?
- Which `cilium-dbg` commands must work on day one (drives which REST routes are P0):
  proposal `status`, `endpoint list/get`, `config`, `identity`, `ip list`, `service list`,
  `policy get`, `node list`, `debuginfo`, plus all `bpf *` (map-compat).
- API rate limiter auto-adjust: keep the adaptive algorithm or fixed limits?
- Health prober: reuse cluster-size-dependent interval formula exactly (metrics
  dashboards assume ~60 s at small size)?
- Do we expose `/statedb/*` at all, or provide `flowsdn-dbg` native table dumps?

## Appendix A — full agent flag table (the `cilium-config` key surface)

Extracted from every `flags.<Type>(name, default, help)` registration reachable from the
agent hive (`daemon/**`, `pkg/**`; operator-only flags excluded). 539 flags. Type is the
pflag type. Defaults shown as resolved constants where the extractor could follow them;
`def.X`/`cfg.X`/`r.X` means "default struct literal in the named file" (34 rows). Hidden
flags are included. The `File` column is where flowsdn should look for semantics.

| Flag (`cilium-config` key) | Type | Default | Meaning | File |
|---|---|---|---|---|
| `agent-health-port` | Int | `9879` | TCP port for agent health status API | `daemon/healthz/agenthealth.go` |
| `agent-health-require-k8s-connectivity` | Bool | `true` | Require Kubernetes connectivity in agent health endpoint | `daemon/healthz/agenthealth.go` |
| `agent-labels` | StringSlice | `[]string{}` | Additional labels to identify this agent in monitor events | `pkg/proxy/accesslog/cell.go` |
| `agent-liveness-update-interval` | Duration | `1 * time.Second` | Interval at which the agent updates liveness time for the datapath | `pkg/datapath/agentliveness/agent_liveness.go` |
| `agent-not-ready-taint-key` | String | `"node." + CiliumK8sAnnotationPrefix + "agent-not-ready"` | Key of the taint indicating that Cilium is not ready on the node | `daemon/cmd/daemon_main.go` |
| `alibabacloud-security-group-tags` | StringToString | `map[string]string{}` | List of tags to use when evaluating what security groups to use for the ENI at the node level | `pkg/nodediscovery/cell.go` |
| `alibabacloud-security-groups` | StringSlice | `[]string{}` | List of security groups to attach to any ENI that is created and attached to the instance at the node level | `pkg/nodediscovery/cell.go` |
| `alibabacloud-vswitch-tags` | StringToString | `map[string]string{}` | List of tags to use when evaluating what VSwitches to use for ENI and IP allocation at the node level | `pkg/nodediscovery/cell.go` |
| `alibabacloud-vswitches` | StringSlice | `[]string{}` | List of VSwitches to use for ENI and IP allocation at the node level | `pkg/nodediscovery/cell.go` |
| `allocator-list-timeout` | Duration | `3 * time.Minute` | Timeout for listing allocator state before exiting | `daemon/cmd/daemon_main.go` |
| `allow-icmp-frag-needed` | Bool | `true` | Allow ICMP Fragmentation Needed type packets for purposes like TCP Path MTU. | `daemon/cmd/daemon_main.go` |
| `allow-localhost` | String | `auto` | Policy when to allow local stack to reach local endpoints { auto \| always \| policy } | `daemon/cmd/daemon_main.go` |
| `allow-unsafe-policy-skb-usage` | Bool | `false` | Allow the daemon to continue to operate even if conflicting clustermesh ID configuration is detected which may impact the ability for Cilium to enforce network policy bot | `pkg/clustermesh/types/option.go` |
| `annotate-k8s-node` | Bool | `false` | Annotate Kubernetes node | `daemon/cmd/daemon_main.go` |
| `any-proto` | Bool | `false` | Restore backends with ANY protocol | `pkg/loadbalancer/maps/cmds.go` |
| `api-rate-limit` | String | `` | API rate limiting configuration (example: --api-rate-limit endpoint-create=rate-limit:10/m,rate-burst:2) | `daemon/restapi/api_limits.go` |
| `auto-create-cilium-node-resource` | Bool | `true` | Automatically create CiliumNode resource for own node on startup | `daemon/cmd/daemon_main.go` |
| `auto-direct-node-routes` | Bool | `false` | Enable automatic L2 routing between nodes | `daemon/cmd/daemon_main.go` |
| `azure-interface-name` | String | `` | InterfaceName the cilium-operator will use to allocate all the IPs on at the node level | `pkg/nodediscovery/cell.go` |
| `bgp-router-id-allocation-ip-pool` | String | `` | IP pool to allocate the BGP router-id from when the mode is 'ip-pool' | `daemon/cmd/daemon_main.go` |
| `bgp-router-id-allocation-mode` | String | `default` | BGP router-id allocation mode. Currently supported values: 'default' or 'ip-pool' | `daemon/cmd/daemon_main.go` |
| `boot-id-file` | String | `/proc/sys/kernel/random/boot_id` | Path to filename of the boot ID | `daemon/cmd/daemon_main.go` |
| `bpf-auth-map-max` | Int | `1 << 19` | Maximum number of entries in auth map | `daemon/cmd/daemon_main.go` |
| `bpf-conntrack-accounting` | Bool | `false` | Enable CT accounting for packets and bytes (default false) | `daemon/cmd/daemon_main.go` |
| `bpf-ct-global-any-max` | Int | `2 << 17` | Maximum number of entries in non-TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-global-tcp-max` | Int | `2 << 18` | Maximum number of entries in TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-timeout-regular-any` | Duration | `60*time.Second` | Timeout for entries in non-TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-timeout-regular-tcp` | Duration | `8000*time.Second` | Timeout for established entries in TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-timeout-regular-tcp-fin` | Duration | `10*time.Second` | Teardown timeout for entries in TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-timeout-regular-tcp-syn` | Duration | `60*time.Second` | Establishment timeout for entries in TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-timeout-service-any` | Duration | `60*time.Second` | Timeout for service entries in non-TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-timeout-service-tcp` | Duration | `8000*time.Second` | Timeout for established service entries in TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-ct-timeout-service-tcp-grace` | Duration | `60*time.Second` | Timeout for graceful shutdown of service entries in TCP CT table | `daemon/cmd/daemon_main.go` |
| `bpf-distributed-lru` | Bool | `false` | Enable per-CPU BPF LRU backend memory | `daemon/cmd/daemon_main.go` |
| `bpf-events-default-burst-limit` | Int | `0` | Maximum number of messages that can be written to BPF events map in 1 second (if set, --%s value must also be specified). If both --%s and --%s are 0 or not specified, no | `daemon/cmd/daemon_main.go` |
| `bpf-events-default-rate-limit` | Int | `0` | Limit of average number of messages per second that can be written to BPF events map (if set, --%s value must also be specified). If both --%s and --%s are 0 or not speci | `daemon/cmd/daemon_main.go` |
| `bpf-events-drop-enabled` | Bool | `true` | Expose 'drop' events for Cilium monitor and/or Hubble | `daemon/cmd/daemon_main.go` |
| `bpf-events-policy-verdict-enabled` | Bool | `true` | Expose 'policy verdict' events for Cilium monitor and/or Hubble | `daemon/cmd/daemon_main.go` |
| `bpf-events-trace-enabled` | Bool | `true` | Expose 'trace' events for Cilium monitor and/or Hubble | `daemon/cmd/daemon_main.go` |
| `bpf-filter-priority` | Int | `1` | Priority of TC BPF filter | `daemon/cmd/daemon_main.go` |
| `bpf-fragments-map-max` | Int | `8192` | Maximum number of entries in fragments tracking map | `daemon/cmd/daemon_main.go` |
| `bpf-lb-acceleration` | String | `disabled` | BPF load balancing acceleration via XDP ("%s", "%s") | `daemon/cmd/daemon_main.go` |
| `bpf-lb-affinity-map-max` | Int | `0` | Maximum number of entries in Cilium BPF lbmap for session affinities (if this isn't set, the value of --%s will be used.) | `pkg/loadbalancer/config.go` |
| `bpf-lb-algorithm` | String | `LBAlgorithmRandom` | BPF load balancing algorithm ("random", "maglev") | `pkg/loadbalancer/config.go` |
| `bpf-lb-algorithm-annotation` | Bool | `false` | Enable service-level annotation for configuring BPF load balancing algorithm | `pkg/loadbalancer/config.go` |
| `bpf-lb-dsr-dispatch` | String | `DSRDispatchOption` | BPF load balancing DSR dispatch method ("opt", "ipip", "geneve") | `pkg/loadbalancer/config.go` |
| `bpf-lb-enable-wildcard-entries` | Bool | `true` | Enable service load balancer wildcard entries. | `pkg/loadbalancer/config.go` |
| `bpf-lb-external-clusterip` | Bool | `false` | Enable external access to ClusterIP services (default false) | `pkg/loadbalancer/config.go` |
| `bpf-lb-ipip-sock-mark` | Bool | `false` | BPF load balancing logic to force socket marked traffic via IPIP | `daemon/cmd/daemon_main.go` |
| `bpf-lb-maglev-hash-seed` | String | `userCfg.HashSeed` | Maglev cluster-wide hash seed (base64 encoded) | `pkg/maglev/maglev.go` |
| `bpf-lb-maglev-map-max` | Int | `0` | Maximum number of entries in Cilium BPF lbmap for maglev (if this isn't set, the value of --%s will be used.) | `pkg/loadbalancer/config.go` |
| `bpf-lb-maglev-table-size` | Uint | `userCfg.TableSize` | Maglev per service backend table size (parameter M, one of: %v) | `pkg/maglev/maglev.go` |
| `bpf-lb-map-max` | Int | `DefaultLBMapMaxEntries` | Maximum number of entries in Cilium BPF lbmap | `pkg/loadbalancer/config.go` |
| `bpf-lb-mode` | String | `LBModeSNAT` | BPF load balancing mode ("snat", "dsr", "hybrid") | `pkg/loadbalancer/config.go` |
| `bpf-lb-mode-annotation` | Bool | `false` | Enable service-level annotation for configuring BPF load balancing mode | `pkg/loadbalancer/config.go` |
| `bpf-lb-nat46x64` | Bool | `false` | BPF load balancing support for NAT46 and NAT64 | `daemon/cmd/daemon_main.go` |
| `bpf-lb-rev-nat-map-max` | Int | `0` | Maximum number of entries in Cilium BPF lbmap for reverse NAT (if this isn't set, the value of --%s will be used.) | `pkg/loadbalancer/config.go` |
| `bpf-lb-rss-ipv4-src-cidr` | String | `` | BPF load balancing RSS outer source IPv4 CIDR prefix for IPIP | `daemon/cmd/daemon_main.go` |
| `bpf-lb-rss-ipv6-src-cidr` | String | `` | BPF load balancing RSS outer source IPv6 CIDR prefix for IPIP | `daemon/cmd/daemon_main.go` |
| `bpf-lb-service-backend-map-max` | Int | `0` | Maximum number of entries in Cilium BPF lbmap for service backends (if this isn't set, the value of --%s will be used.) | `pkg/loadbalancer/config.go` |
| `bpf-lb-service-map-max` | Int | `0` | Maximum number of entries in Cilium BPF lbmap for services (if this isn't set, the value of --%s will be used.) | `pkg/loadbalancer/config.go` |
| `bpf-lb-sock` | Bool | `false` | Enable socket-based LB for E/W traffic | `pkg/kpr/kpr.go` |
| `bpf-lb-sock-hostns-only` | Bool | `false` | Skip socket LB for services when inside a pod namespace, in favor of service LB at the pod interface. Socket LB is still used when in the host namespace. Required by serv | `daemon/cmd/daemon_main.go` |
| `bpf-lb-sock-terminate-pod-connections` | Bool | `true` | Enable terminating connections to deleted service backends when socket-LB is enabled | `daemon/cmd/daemon_main.go` |
| `bpf-lb-source-range-all-types` | Bool | `false` | Propagate loadbalancerSourceRanges to all corresponding service types | `pkg/loadbalancer/config.go` |
| `bpf-lb-source-range-map-max` | Int | `0` | Maximum number of entries in Cilium BPF lbmap for source ranges (if this isn't set, the value of --%s will be used.) | `pkg/loadbalancer/config.go` |
| `bpf-map-dynamic-size-ratio` | Float64 | `0.0025` | Ratio (0.0-1.0] of total system memory to use for dynamic sizing of CT, NAT and policy BPF maps | `daemon/cmd/daemon_main.go` |
| `bpf-map-event-buffers` | Var | `option.NewMapOptions(&option.Config.BPFMapEventBuffers, option.Config.BPFMapEventBuffersValidator)` | Configuration for BPF map event buffers: (example: --bpf-map-event-buffers cilium_ipcache_v2=enabled_1024_1h) | `daemon/cmd/daemon_main.go` |
| `bpf-nat-global-max` | Int | `int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)` | Maximum number of entries for the global BPF NAT table | `daemon/cmd/daemon_main.go` |
| `bpf-neigh-global-max` | Int | `int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)` | Maximum number of entries for the global BPF neighbor table | `daemon/cmd/daemon_main.go` |
| `bpf-node-map-max` | Uint32 | `DefaultMaxEntries` | Sets size of node bpf map which will be the max number of unique Node IPs in the cluster | `pkg/maps/nodemap/cell.go` |
| `bpf-policy-map-full-reconciliation-interval` | Duration | `15*time.Minute` | Interval for full reconciliation of endpoint policy map | `daemon/cmd/daemon_main.go` |
| `bpf-policy-map-max` | Int | `16384` | Maximum number of entries in endpoint policy map (per endpoint) | `pkg/maps/policymap/cell.go` |
| `bpf-policy-map-pressure-metrics-threshold` | Float64 | `0.1` | Sets threshold for emitting pressure metrics of policy maps | `pkg/endpointmanager/config.go` |
| `bpf-policy-stats-map-max` | Int | `1 << 16` | Maximum number of entries in bpf policy stats map | `pkg/maps/policymap/cell.go` |
| `bpf-root` | String | `` | Path to BPF filesystem | `daemon/cmd/daemon_main.go` |
| `bpf-sock-rev-map-max` | Int | `0` | Maximum number of entries for the SockRevNAT BPF map | `pkg/loadbalancer/config.go` |
| `bypass-ip-availability-upon-restore` | Bool | `false` | Bypasses the IP availability error within IPAM upon endpoint restore | `daemon/cmd/daemon_main.go` |
| `certificates-directory` | String | `/var/run/cilium/certs` | Root directory to find certificates specified in L7 TLS policy enforcement | `pkg/crypto/certificatemanager/certificate_manager.go` |
| `cgroup-root` | String | `` | Path to Cgroup2 filesystem | `daemon/cmd/daemon_main.go` |
| `cluster-health-port` | Int | `4240` | TCP port for cluster-wide network connectivity health API | `daemon/cmd/daemon_main.go` |
| `cluster-id` | Uint32 | `0` | Unique identifier of the cluster | `pkg/clustermesh/types/option.go` |
| `cluster-name` | String | `default` | Name of the cluster. It must consist of at most 32 lower case alphanumeric characters and '-', start and end with an alphanumeric character. | `pkg/clustermesh/types/option.go` |
| `clustermesh-cache-ttl` | Duration | `0` | The time to live for the cache of a remote cluster after connectivity is lost. If the connection is not re-established within this duration, the cached data is revoked to | `pkg/clustermesh/common/config.go` |
| `clustermesh-config` | String | `` | Path to the ClusterMesh configuration directory | `pkg/clustermesh/common/config.go` |
| `clustermesh-default-global-namespace` | Bool | `true` | Mark all namespaces as global by default unless overridden by annotation | `pkg/clustermesh/namespace/config.go` |
| `clustermesh-enable-mcs-api` | Bool | `false` | Enable Cluster Mesh MCS-API support | `pkg/clustermesh/mcsapi/types/config.go` |
| `clustermesh-mcs-api-install-crds` | Bool | `true` | Install and manage the MCS API CRDs. Only applicable if MCS API support is enabled. | `pkg/clustermesh/mcsapi/types/config.go` |
| `clustermesh-service-v2` | String | `c.ServiceModeV2.String()` | ClusterMesh service v2 rollout mode: prefer-legacy, prefer-endpointslice, or only-endpointslice | `pkg/clustermesh/types/option.go` |
| `clustermesh-sync-timeout` | Duration | `1 * time.Minute` | Timeout waiting for the initial synchronization of information from remote clusters | `pkg/clustermesh/wait/synced.go` |
| `cmdref` | String | `` | Path to cmdref output directory | `daemon/cmd/daemon_main.go` |
| `cni-chaining-mode` | String | `none` | Enable CNI chaining with the specified plugin | `daemon/cmd/cni/config/config.go` |
| `cni-chaining-target` | String | `` | CNI network name into which to insert the Cilium chained configuration. Use '*' to select any network. | `daemon/cmd/cni/config/config.go` |
| `cni-exclusive` | Bool | `false` | Whether to remove other CNI configurations | `daemon/cmd/cni/config/config.go` |
| `cni-external-routing` | Bool | `false` | Whether the chained CNI plugin handles routing on the node | `daemon/cmd/cni/config/config.go` |
| `cni-log-file` | String | `/var/run/cilium/cilium-cni.log` | Path where the CNI plugin should write logs | `daemon/cmd/cni/config/config.go` |
| `config` | String | `` | `Configuration file (default "$HOME/ciliumd.yaml")` | `daemon/cmd/daemon_main.go` |
| `config-dir` | String | `` | `Configuration directory that contains a file for each option` | `daemon/cmd/daemon_main.go` |
| `config-sources` | String | ``[{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]`` | Ordered list of configuration sources | `pkg/dynamicconfig/cell.go` |
| `config-sources-overrides` | String | ``{"allowConfigKeys":null,"denyConfigKeys":null}`` | List of configuration keys that are allowed and not allowed to be overridden. Allowed config keys takes precedence over deny config keys. | `pkg/dynamicconfig/cell.go` |
| `ConfigKey` | String | ``[]`` | List of dynamic lifecycle features and their configuration including the dependencies | `pkg/dynamiclifecycle/cell.go` |
| `connectivity-probe-frequency-ratio` | Float64 | `0.5` | Ratio of the connectivity probe frequency vs resource usage, a float in [0, 1]. 0 will give more frequent probing, 1 will give less frequent probing. Probing frequency is | `daemon/cmd/daemon_main.go` |
| `conntrack-gc-interval` | Duration | `0` | Overwrite the connection-tracking garbage collection interval | `pkg/maps/ctmap/gc/gc.go` |
| `conntrack-gc-max-interval` | Duration | `0` | Set the maximum interval for the connection-tracking garbage collection | `pkg/maps/ctmap/gc/gc.go` |
| `container-ip-local-reserved-ports` | String | `auto` | Instructs the Cilium CNI plugin to reserve the provided comma-separated list of ports in the container network namespace. Prevents the container from using these ports as | `daemon/cmd/daemon_main.go` |
| `controller-group-metrics` | StringSlice | `[]string{}` | List of controller group names for which to enable metrics. Accepts 'all' and 'none'. The set of controller group names available is not guaranteed to be stable between C | `pkg/controller/cell.go` |
| `count` | Int | `0` | Maxiumum number of endpoints to display | `pkg/policy/commands/topk.go` |
| `crd-wait-timeout` | Duration | `5 * time.Minute` | Cilium will exit if CRDs are not available within this duration upon startup | `pkg/k8s/synced/cell.go` |
| `datapath-mode` | String | `veth` | Datapath mode name (%s, %s, %s, %s) | `daemon/cmd/daemon_main.go` |
| `datapath-plugins-state-dir` | String | `/var/run/cilium/plugins` | Parent directory for per-plugin subdirectories containing UNIX sockets for talking to a Cilium datapath plugin. | `pkg/datapath/plugins/cell.go` |
| `debug` | Bool | `false` | Enable debugging mode | `daemon/cmd/daemon_main.go` |
| `debug-verbose` | StringSlice | `[]string{}` | List of enabled verbose debug groups | `daemon/cmd/daemon_main.go` |
| `deriveFlag` | String | `masqInterface` | Device name from which Cilium derives the IP addr for BPF masquerade | `pkg/datapath/orchestrator/orchestrator.go` |
| `devices` | StringSlice | `[]string{}` | List of devices facing cluster/external network (used for BPF NodePort, BPF masquerading and host firewall); supports '+' as wildcard in device name, e.g. 'eth+'; support | `pkg/datapath/linux/devices_controller.go` |
| `diff` | Bool | `false` | Display the difference from the existing policy map. | `pkg/policy/commands/mapstate_diff.go` |
| `direct-routing-device` | String | `` | Device name used to connect nodes in direct routing mode (used by BPF NodePort, BPF host routing; if empty, automatically set to a device with k8s InternalIP/ExternalIP o | `pkg/datapath/tables/direct_routing_device.go` |
| `direct-routing-skip-unreachable` | Bool | `false` | Enable skipping L2 routes between nodes on different subnets | `daemon/cmd/daemon_main.go` |
| `disable-drain-on-disconnection` | Bool | `false` | Do not drain cached data upon cluster disconnection | `pkg/clustermesh/kvstoremesh/kvstoremesh.go` |
| `disable-endpoint-crd` | Bool | `false` | Disable use of CiliumEndpoint CRD | `daemon/cmd/daemon_main.go` |
| `disable-envoy-version-check` | Bool | `false` | Do not perform Envoy version check | `pkg/envoy/config/config.go` |
| `disable-external-ip-mitigation` | Bool | `false` | Disable ExternalIP mitigation (CVE-2020-8554, default false) | `daemon/cmd/daemon_main.go` |
| `disable-iptables-feeder-rules` | StringSlice | `[]string{}` | Chains to ignore when installing feeder rules. | `pkg/datapath/iptables/cell.go` |
| `dns-max-ips-per-restored-rule` | Int | `1000` | Maximum number of IPs to maintain for each restored DNS rule | `pkg/fqdn/service/cell.go` |
| `dns-policy-unload-on-shutdown` | Bool | `false` | Unload DNS policy rules on graceful shutdown | `daemon/cmd/daemon_main.go` |
| `dnsproxy-concurrency-limit` | Int | `0` | Limit concurrency of DNS message processing | `daemon/cmd/daemon_main.go` |
| `dnsproxy-concurrency-processing-grace-period` | Duration | `0` | Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing | `pkg/fqdn/service/cell.go` |
| `dnsproxy-enable-transparent-mode` | Bool | `false` | Enable DNS proxy transparent mode | `daemon/cmd/daemon_main.go` |
| `dnsproxy-insecure-skip-transparent-mode-check` | Bool | `false` | Allows DNS proxy transparent mode to be disabled even if encryption is enabled. Enabling this flag and disabling DNS proxy transparent mode will cause proxied DNS traffic | `pkg/datapath/linux/ipsec/cell.go` |
| `dnsproxy-lock-count` | Int | `131` | Array size containing mutexes which protect against parallel handling of DNS response names. Preferably use prime numbers | `daemon/cmd/daemon_main.go` |
| `dnsproxy-lock-timeout` | Duration | `500 * time.Millisecond` | Timeout when acquiring the locks controlled by --%s | `daemon/cmd/daemon_main.go` |
| `dnsproxy-socket-linger-timeout` | Int | `10` | Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server. If set to 0, the connection is closed immediately (with TCP RST). If set t | `daemon/cmd/daemon_main.go` |
| `egress` | Bool | `false` | Look up the egress policy verdict | `pkg/policy/lookup_script_cmds.go` |
| `egress-gateway-policy-map-max` | Int | `1 << 14` | Maximum number of entries in egress gateway policy map | `pkg/maps/egressmap/policy.go` |
| `egress-gateway-reconciliation-trigger-interval` | Duration | `1 * time.Second` | Time between triggers of egress gateway state reconciliations | `pkg/egressgateway/manager.go` |
| `egress-masquerade-interfaces` | StringSlice | `[]string{}` | Limit iptables-based egress masquerading to interfaces selector | `daemon/cmd/daemon_main.go` |
| `enable` | Bool | `true` | Enable bypassing host firewall for Kubernetes API server access. | `pkg/k8s/hostfirewallbypass/cell.go` |
| `enable-active-connection-tracking` | Bool | `false` | Count open and active connections to services, grouped by zones defined in fixed-zone-mapping. | `pkg/maps/act/act.go` |
| `enable-auto-protect-node-port-range` | Bool | `true` | Append NodePort range to net.ipv4.ip_local_reserved_ports if it overlaps with ephemeral port range (net.ipv4.ip_local_port_range) | `daemon/cmd/daemon_main.go` |
| `enable-bandwidth-manager` | Bool | `def.EnableBandwidthManager` | Enable BPF bandwidth manager | `pkg/datapath/linux/bandwidth/types/config.go` |
| `enable-bbr` | Bool | `def.EnableBBR` | Enable BBR for the bandwidth manager | `pkg/datapath/linux/bandwidth/types/config.go` |
| `enable-bbr-hostns-only` | Bool | `def.EnableBBRHostnsOnly` | Enable BBR only in the host network namespace. | `pkg/datapath/linux/bandwidth/types/config.go` |
| `enable-bgp-control-plane` | Bool | `false` | Enable the BGP control plane. | `daemon/cmd/daemon_main.go` |
| `enable-bgp-control-plane-status-report` | Bool | `true` | Enable the BGP control plane status reporting | `daemon/cmd/daemon_main.go` |
| `enable-bgp-legacy-origin-attribute` | Bool | `false` | Enable LoadBalancerIP routes to be advertised with BGP Origin Attribute set to INCOMPLETE | `pkg/bgp/option/config.go` |
| `enable-bpf-clock-probe` | Bool | `false` | Enable BPF clock source probing for more efficient tick retrieval | `daemon/cmd/daemon_main.go` |
| `enable-bpf-masquerade` | Bool | `false` | Masquerade packets from endpoints leaving the host with BPF instead of iptables | `daemon/cmd/daemon_main.go` |
| `enable-bpf-tproxy` | Bool | `false` | Enable BPF-based proxy redirection (beta), if support available | `daemon/cmd/daemon_main.go` |
| `enable-cilium-clusterwide-network-policy` | Bool | `true` | Enable support for Cilium Clusterwide Network Policy | `daemon/cmd/daemon_main.go` |
| `enable-cilium-endpoint-slice` | Bool | `false` | Enable the CiliumEndpointSlice watcher in place of the CiliumEndpoint watcher (beta) | `daemon/cmd/daemon_main.go` |
| `enable-cilium-network-policy` | Bool | `true` | Enable support for Cilium Network Policy | `daemon/cmd/daemon_main.go` |
| `enable-ciliumnode-crd` | Bool | `true` | Enable use of CiliumNode CRD | `daemon/cmd/daemon_main.go` |
| `enable-datapath-plugins` | Bool | `false` | Enable use of datapath plugins and the CiliumDatapathPlugins CRD | `daemon/cmd/daemon_main.go` |
| `enable-drift-checker` | Bool | `true` | Enables support for config drift checker | `pkg/driftchecker/cell.go` |
| `enable-dynamic-config` | Bool | `true` | Enables support for dynamic agent config | `pkg/dynamicconfig/cell.go` |
| `enable-dynamic-lifecycle-manager` | Bool | `false` | Enables support for dynamic lifecycle management | `pkg/dynamiclifecycle/cell.go` |
| `enable-dynamic-source-lookup-nodeport` | Bool | `def.NodePortEnableDynamicSourceLookup` | Enable dynamic source IP resolution for SNAT via linux's routing table. The kernel must support this feature. | `pkg/loadbalancer/config.go` |
| `enable-egress-gateway` | Bool | `false` | Enable egress gateway | `daemon/cmd/daemon_main.go` |
| `enable-encryption-strict-mode-egress` | Bool | `false` | Enable strict mode encryption enforcement for egress traffic | `daemon/cmd/daemon_main.go` |
| `enable-encryption-strict-mode-ingress` | Bool | `false` | Enable strict mode encryption enforcement for ingress traffic | `daemon/cmd/daemon_main.go` |
| `enable-endpoint-health-checking` | Bool | `true` | Enable connectivity health checking between virtual endpoints | `pkg/healthconfig/cell.go` |
| `enable-endpoint-lockdown-on-policy-overflow` | Bool | `false` | When an endpoint's policy map overflows, shutdown all (ingress and egress) network traffic for that endpoint. | `daemon/cmd/daemon_main.go` |
| `enable-endpoint-routes` | Bool | `false` | Use per endpoint routes instead of routing via cilium_host | `daemon/cmd/daemon_main.go` |
| `enable-envoy-config` | Bool | `false` | Enable Envoy Config CRDs | `daemon/cmd/daemon_main.go` |
| `enable-extended-ip-protocols` | Bool | `false` | Enable traffic with extended IP protocols in datapath | `daemon/cmd/daemon_main.go` |
| `enable-gateway-api` | Bool | `false` | Enables Envoy secret sync for Gateway API related TLS secrets | `pkg/envoy/config/config.go` |
| `enable-gops` | Bool | `def.EnableGops` | Enable gops server | `pkg/gops/cell.go` |
| `enable-health-check-loadbalancer-ip` | Bool | `false` | Enable access of the healthcheck nodePort on the LoadBalancerIP. Needs --enable-health-check-nodeport to be enabled | `pkg/loadbalancer/config.go` |
| `enable-health-check-nodeport` | Bool | `true` | Enables a healthcheck nodePort server for NodePort services with 'healthCheckNodePort' being set | `pkg/loadbalancer/config.go` |
| `enable-health-checking` | Bool | `true` | Enable connectivity health checking | `pkg/healthconfig/cell.go` |
| `enable-heartbeat` | Bool | `false` | KVStoreMesh will maintain heartbeat in destination etcd cluster | `pkg/clustermesh/kvstoremesh/kvstoremesh.go` |
| `enable-host-firewall` | Bool | `false` | Enable host network policies | `daemon/cmd/daemon_main.go` |
| `enable-host-legacy-routing` | Bool | `false` | Enable the legacy host forwarding model which does not bypass upper stack in host namespace | `daemon/cmd/daemon_main.go` |
| `enable-hubble` | Bool | `false` | Enable hubble server | `pkg/hubble/cell/config.go` |
| `enable-hubble-open-metrics` | Bool | `false` | Enable exporting hubble metrics in OpenMetrics format. | `pkg/hubble/metrics/cell/cell.go` |
| `enable-icmp-rules` | Bool | `true` | Enable ICMP-based rule support for Cilium Network Policies | `daemon/cmd/daemon_main.go` |
| `enable-identity-mark` | Bool | `true` | Enable setting identity mark for local traffic | `daemon/cmd/daemon_main.go` |
| `enable-ingress-controller` | Bool | `false` | Enables Envoy secret sync for Ingress controller related TLS secrets | `pkg/envoy/config/config.go` |
| `enable-ip-masq-agent` | Bool | `false` | Enable BPF ip-masq-agent | `pkg/ipmasq/cell/config.go` |
| `enable-ipip-termination` | Bool | `false` | Enable plain IPIP/IP6IP6 termination | `daemon/cmd/daemon_main.go` |
| `enable-ipsec` | Bool | `false` | Enable IPsec | `pkg/datapath/linux/ipsec/cell.go` |
| `enable-ipsec-key-watcher` | Bool | `true` | Enable watcher for IPsec key. If disabled, a restart of the agent will be necessary on key rotations. | `pkg/datapath/linux/ipsec/cell.go` |
| `enable-ipsec-xfrm-state-caching` | Bool | `true` | Enable XfrmState cache for IPSec. Significantly reduces CPU usage in large clusters. | `pkg/datapath/linux/ipsec/cell.go` |
| `enable-ipv4` | Bool | `true` | Enable IPv4 support | `daemon/cmd/daemon_main.go` |
| `enable-ipv4-big-tcp` | Bool | `false` | Enable IPv4 BIG TCP option which increases device's maximum GRO/GSO limits for IPv4 | `pkg/datapath/linux/bigtcp/config.go` |
| `enable-ipv4-fragment-tracking` | Bool | `true` | Enable IPv4 fragments tracking for L4-based lookups | `daemon/cmd/daemon_main.go` |
| `enable-ipv4-masquerade` | Bool | `true` | Masquerade IPv4 traffic from endpoints leaving the host | `daemon/cmd/daemon_main.go` |
| `enable-ipv6` | Bool | `true` | Enable IPv6 support | `daemon/cmd/daemon_main.go` |
| `enable-ipv6-big-tcp` | Bool | `false` | Enable IPv6 BIG TCP option which increases device's maximum GRO/GSO limits for IPv6 | `pkg/datapath/linux/bigtcp/config.go` |
| `enable-ipv6-fragment-tracking` | Bool | `true` | Enable IPv6 fragments tracking for L4-based lookups | `daemon/cmd/daemon_main.go` |
| `enable-ipv6-masquerade` | Bool | `true` | Masquerade IPv6 traffic from endpoints leaving the host | `daemon/cmd/daemon_main.go` |
| `enable-ipv6-ndp` | Bool | `false` | Enable IPv6 NDP support | `daemon/cmd/daemon_main.go` |
| `enable-k8s` | Bool | `true` | Enable the k8s clientset | `pkg/k8s/client/config.go` |
| `enable-k8s-api-discovery` | Bool | `false` | Enable discovery of Kubernetes API groups and resources with the discovery API | `pkg/k8s/client/config.go` |
| `enable-k8s-cluster-network-policy` | Bool | `false` | Enable support for K8s ClusterNetworkPolicy | `daemon/cmd/daemon_main.go` |
| `enable-k8s-networkpolicy` | Bool | `true` | Enable support for K8s NetworkPolicy | `daemon/cmd/daemon_main.go` |
| `enable-l2-announcements` | Bool | `false` | Enable L2 announcements | `daemon/cmd/daemon_main.go` |
| `enable-l2-neigh-discovery` | Bool | `false` | Enables L2 neighbor discovery, even when XDP acceleration is disabled | `pkg/datapath/neighbor/config.go` |
| `enable-l2-pod-announcements` | Bool | `false` | Enable announcing Pod IPs with Gratuitous ARP and NDP | `pkg/datapath/gneigh/cells.go` |
| `enable-l7-proxy` | Bool | `true` | Enable L7 proxy for L7 policy enforcement | `daemon/cmd/daemon_main.go` |
| `enable-local-node-route` | Bool | `true` | Enable installation of the route which points the allocation prefix of the local node | `daemon/cmd/daemon_main.go` |
| `enable-local-redirect-policy` | Bool | `false` | Enable Local Redirect Policy | `daemon/cmd/daemon_main.go` |
| `enable-masquerade-to-route-source` | Bool | `false` | Masquerade packets to the source IP provided from the routing layer rather than interface address | `daemon/cmd/daemon_main.go` |
| `enable-mke` | Bool | `false` | Enable BPF kube-proxy replacement for MKE environments | `daemon/cmd/daemon_main.go` |
| `enable-monitor` | Bool | `true` | Enable the monitor unix domain socket server | `pkg/monitor/agent/cell.go` |
| `enable-nat46x64-gateway` | Bool | `false` | Enable NAT46 and NAT64 gateway | `daemon/cmd/daemon_main.go` |
| `enable-no-service-endpoints-routable` | Bool | `true` | Enable routes when service has 0 endpoints | `pkg/svcrouteconfig/cell.go` |
| `enable-node-ipam` | Bool | `r.EnableNodeIPAM` | Enable Node IPAM | `pkg/nodeipamconfig/cell.go` |
| `enable-node-selector-labels` | Bool | `false` | Enable use of node label based identity | `daemon/cmd/daemon_main.go` |
| `enable-non-default-deny-policies` | Bool | `true` | Enable use of non-default-deny policies | `daemon/cmd/daemon_main.go` |
| `enable-pmtu-discovery` | Bool | `false` | Enable path MTU discovery to send ICMP fragmentation-needed replies to the client | `daemon/cmd/daemon_main.go` |
| `enable-policy` | String | `default` | Enable policy enforcement | `daemon/cmd/daemon_main.go` |
| `enable-policy-secrets-sync` | Bool | `mc.EnablePolicySecretsSync` | Enables Envoy secret sync for Secrets used in CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy | `pkg/crypto/certificatemanager/certificate_manager.go` |
| `enable-remote-node-masquerade` | Bool | `false` | Masquerade packets from endpoints leaving the host destined to a remote node in BPF masquerading mode. This option requires to set enable-bpf-masquerade to true. | `daemon/cmd/daemon_main.go` |
| `enable-route-mtu-for-cni-chaining` | Bool | `false` | Enable route MTU for pod netns when CNI chaining is used | `pkg/mtu/cell.go` |
| `enable-sctp` | Bool | `false` | Enable SCTP support (beta) | `daemon/cmd/daemon_main.go` |
| `enable-service-topology` | Bool | `false` | Enable support for service topology aware hints | `pkg/loadbalancer/config.go` |
| `enable-srv6` | Bool | `false` | Enable SRv6 support (beta) | `daemon/cmd/daemon_main.go` |
| `enable-stale-cilium-endpoint-cleanup` | Bool | `true` | Enable running cleanup init procedure of local CiliumEndpoints which are not being managed. | `pkg/endpointcleanup/cell.go` |
| `enable-standalone-dns-proxy` | Bool | `false` | Enables standalone DNS proxy | `pkg/fqdn/service/cell.go` |
| `enable-tcx` | Bool | `true` | Attach endpoint programs using tcx if supported by the kernel | `daemon/cmd/daemon_main.go` |
| `enable-tracing` | Bool | `false` | Enable tracing while determining policy (debugging) | `daemon/cmd/daemon_main.go` |
| `enable-unreachable-routes` | Bool | `false` | Add unreachable routes on pod deletion | `daemon/cmd/daemon_main.go` |
| `enable-vtep` | Bool | `false` | Enable VXLAN Tunnel Endpoint (VTEP) Integration (beta) | `daemon/cmd/daemon_main.go` |
| `enable-well-known-identities` | Bool | `true` | Enable well-known identities for known Kubernetes components | `pkg/policy/cell/cell.go` |
| `enable-wireguard` | Bool | `false` | Enable WireGuard | `pkg/wireguard/agent/cell.go` |
| `enable-xdp-prefilter` | Bool | `false` | Enable XDP prefiltering | `daemon/cmd/daemon_main.go` |
| `enable-xt-socket-fallback` | Bool | `true` | Enable fallback for missing xt_socket module | `pkg/datapath/iptables/cell.go` |
| `enable-ztunnel` | Bool | `false` | Use zTunnel as Cilium's encryption infrastructure | `pkg/ztunnel/config/config.go` |
| `encrypt-node` | Bool | `false` | Enables encrypting traffic from non-Cilium pods and host networking (only supported with WireGuard, beta) | `daemon/cmd/daemon_main.go` |
| `encryption-strict-egress-allow-remote-node-identities` | Bool | `false` | Allows unencrypted traffic from pods to remote node identities within the strict mode CIDR. This is required when tunneling is used or direct routing is used and the node | `daemon/cmd/daemon_main.go` |
| `encryption-strict-egress-cidr` | String | `` | In strict-mode-egress encryption, all unencrypted traffic coming from this CIDR and going to this same CIDR will be dropped. | `daemon/cmd/daemon_main.go` |
| `endpoint` | String | `` | Endpoint, either numeric ID or <namespace/name>, to stage this policy | `pkg/policy/commands/mapstate_diff.go` |
| `endpoint-bpf-prog-watchdog-interval` | Duration | `30 * time.Second` | Interval to trigger endpoint BPF programs load check watchdog | `pkg/endpoint/watchdog/ep-bpfprog-watchdog.go` |
| `endpoint-gc-interval` | Duration | `5 * time.Minute` | Periodically monitor local endpoint health via link status on this interval and garbage collect them if they become unhealthy, set to 0 to disable | `pkg/endpointmanager/config.go` |
| `endpoint-policy-update-timeout` | Duration | `10 * time.Second` | Timeout duration for Endpoint policy updates | `pkg/endpointmanager/config.go` |
| `endpoint-queue-size` | Int | `25` | Size of EventQueue per-endpoint | `daemon/cmd/daemon_main.go` |
| `endpoint-regen-interval` | Duration | `2 * time.Minute` | Periodically recalculate and re-apply endpoint configuration. Set to 0 to disable | `pkg/endpointmanager/config.go` |
| `eni-delete-on-termination` | Bool | `true` | Whether the ENI should be deleted when the associated instance is terminated at the node level | `pkg/nodediscovery/cell.go` |
| `eni-disable-prefix-delegation` | Bool | `false` | Whether ENI prefix delegation should be disabled on this node at the node level | `pkg/nodediscovery/cell.go` |
| `eni-exclude-interface-tags` | StringToString | `map[string]string{}` | List of tags to use when excluding ENIs for Cilium IP allocation at the node level | `pkg/nodediscovery/cell.go` |
| `eni-first-interface-index` | Int | `0` | Index of the first ENI to use for IP allocation at the node level | `pkg/nodediscovery/cell.go` |
| `eni-security-group-tags` | StringToString | `map[string]string{}` | List of tags to use when evaluating what AWS security groups to use for the ENI at the node level | `pkg/nodediscovery/cell.go` |
| `eni-security-groups` | StringSlice | `[]string{}` | List of security groups to attach to any ENI that is created and attached to the instance at the node level | `pkg/nodediscovery/cell.go` |
| `eni-subnet-ids` | StringSlice | `[]string{}` | List of subnet ids to use when evaluating what AWS subnets to use for ENI and IP allocation at the node level | `pkg/nodediscovery/cell.go` |
| `eni-subnet-tags` | StringToString | `map[string]string{}` | List of tags to use when evaluating what AWS subnets to use for ENI and IP allocation at the node level | `pkg/nodediscovery/cell.go` |
| `eni-use-primary-address` | Bool | `false` | Whether an ENI's primary address should be available for allocations on the node at the node level | `pkg/nodediscovery/cell.go` |
| `envoy-access-log-buffer-size` | Uint | `4096` | Envoy access log buffer size in bytes | `pkg/envoy/config/config.go` |
| `envoy-access-log-enabled` | Bool | `true` | Enable access log forwarding for integration with Hubble. | `pkg/envoy/config/config.go` |
| `envoy-base-id` | Uint64 | `0` | Envoy base ID | `pkg/envoy/config/config.go` |
| `envoy-config-retry-interval` | Duration | `15*time.Second` | Interval in which an attempt is made to reconcile failed EnvoyConfigs. If the duration is zero, the retry is deactivated. | `pkg/ciliumenvoyconfig/config.go` |
| `envoy-config-timeout` | Duration | `2*time.Minute` | Timeout that determines how long to wait for Envoy to N/ACK CiliumEnvoyConfig resources | `pkg/ciliumenvoyconfig/config.go` |
| `envoy-default-log-level` | String | `` | Default log level of Envoy application log that is configured if Cilium debug / verbose logging isn't enabled. If not defined, the default log level of the Cilium Agent i | `pkg/envoy/config/config.go` |
| `envoy-http-upstream-linger-timeout` | Int | `-1` | Time in seconds to block Envoy worker thread while an upstream HTTP connection is closing. If set to 0, the connection is closed immediately (with TCP RST). If set to -1, | `pkg/envoy/config/config.go` |
| `envoy-keep-cap-netbindservice` | Bool | `false` | Keep capability NET_BIND_SERVICE for Envoy process | `pkg/envoy/config/config.go` |
| `envoy-log` | String | `` | Path to a separate Envoy log file, if any | `pkg/envoy/config/config.go` |
| `envoy-node-locality-enabled` | Bool | `false` | Enable Envoy node-locality support for zone-aware routing | `pkg/envoy/config/config.go` |
| `envoy-policy-restore-timeout` | Duration | `3*time.Minute` | Maximum time to wait for endpoint policy restoration before starting serving resources to Envoy | `pkg/envoy/config/config.go` |
| `envoy-secrets-namespace` | String | `r.EnvoySecretsNamespace` | EnvoySecretsNamespace is the namespace having secrets used by CEC | `pkg/envoy/config/config.go` |
| `envoy-xds-mode` | String | `split` | `xDS server implementation for Envoy proxy configuration. Valid values are "split" for the existing per-resource-type xDS server | `pkg/envoy/config/config.go` |
| `exclude-local-address` | StringSlice | `[]string{}` | Exclude CIDR from being recognized as local address | `daemon/cmd/daemon_main.go` |
| `exclude-node-label-patterns` | StringSlice | `[]string{}` | List of k8s node label regex patterns to be excluded from CiliumNode | `daemon/cmd/daemon_main.go` |
| `external-envoy-proxy` | Bool | `false` | whether the Envoy is deployed externally in form of a DaemonSet or not | `daemon/cmd/daemon_main.go` |
| `families` | String | `ipv4/unicast,ipv6/unicast` | Comma-separated list of AFI/SAFIs enabled for the peer. If not specified, ipv4/unicast and ipv6/unicast are enabled. | `pkg/bgp/test/commands/gobgp.go` |
| `fib-table-id-annotation` | Bool | `false` | Enable parsing of the network.cilium.io/fib-table-id pod annotation for pod egress routing | `daemon/cmd/daemon_main.go` |
| `filename` | StringSlice | `nil` | YAML or JSON policy resource to stage | `pkg/policy/commands/mapstate_diff.go` |
| `fixed-identity-mapping` | Var | `option.NewMapOptions(&option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator)` | Key-value for the fixed identity mapping which allows to use reserved label for fixed identities, e.g. 128=kv-store,129=kube-dns | `daemon/cmd/daemon_main.go` |
| `force-device-detection` | Bool | `false` | Forces the auto-detection of devices, even if specific devices are explicitly listed | `pkg/datapath/linux/devices_controller.go` |
| `format` | String | `table` | Output format, one of: table, json or yaml | `pkg/metrics/cmd.go` |
| `fqdn-regex-compile-lru-size` | Uint | `1024` | Size of the FQDN regex compilation LRU. Useful for heavy but repeated DNS L7 rules with MatchName or MatchPattern | `daemon/cmd/daemon_main.go` |
| `gateway-api-secrets-namespace` | String | `r.GatewayAPISecretsNamespace` | GatewayAPISecretsNamespace is the namespace having tls secrets used by CEC, originating from Gateway API | `pkg/envoy/config/config.go` |
| `global-ready-timeout` | Duration | `10 * time.Minute` | KVStoreMesh will be considered ready even if any remote clusters have failed to synchronize within this duration | `pkg/clustermesh/kvstoremesh/kvstoremesh.go` |
| `gops-port` | Uint16 | `def.GopsPort` | Port for gops server to listen on | `pkg/gops/cell.go` |
| `health-check-icmp-failure-threshold` | Int | `3` | Number of ICMP requests sent for each run of the health checker. If at least one ICMP response is received, the node or endpoint is marked as healthy. | `daemon/cmd/daemon_main.go` |
| `hive-log-threshold` | Duration | `100 * time.Millisecond` | Time limit after which a slow hook is logged at Info level | `pkg/hive/hive.go` |
| `hive-start-timeout` | Duration | `5 * time.Minute` | Maximum time to wait for startup hooks to complete before timing out | `pkg/hive/hive.go` |
| `hive-stop-timeout` | Duration | `time.Minute` | Maximum time to wait for stop hooks to complete before timing out | `pkg/hive/hive.go` |
| `http-idle-timeout` | Uint | `0` | Time after which a non-gRPC HTTP stream is considered failed unless traffic in the stream has been processed (in seconds); defaults to 0 (unlimited) | `pkg/envoy/config/config.go` |
| `http-max-grpc-timeout` | Uint | `0` | Time after which a forwarded gRPC request is considered failed unless completed (in seconds). A "grpc-timeout" header may override this with a shorter value; defaults to  | `pkg/envoy/config/config.go` |
| `http-normalize-path` | Bool | `true` | Use Envoy HTTP path normalization options, which currently includes RFC 3986 path normalization, Envoy merge slashes option, and unescaping and redirecting for paths that | `pkg/envoy/config/config.go` |
| `http-request-timeout` | Uint | `60*60` | Time after which a forwarded HTTP request is considered failed unless completed (in seconds); Use 0 for unlimited | `pkg/envoy/config/config.go` |
| `http-retry-count` | Uint | `3` | Number of retries performed after a forwarded request attempt fails | `pkg/envoy/config/config.go` |
| `http-retry-timeout` | Uint | `0` | Time after which a forwarded but uncompleted request is retried (connection failures are retried immediately); defaults to 0 (never) | `pkg/envoy/config/config.go` |
| `http-stream-idle-timeout` | Uint | `5*60` | Set Envoy the amount of time in seconds that the connection manager will allow a stream to exist with no upstream or downstream activity. | `pkg/envoy/config/config.go` |
| `hubble-disable-tls` | Bool | `true` | Allow Hubble server to run on the given listen address without TLS. | `pkg/hubble/cell/certloader.go` |
| `hubble-drop-events` | Bool | `false` | Emit packet drop Events related to pods (alpha) | `pkg/hubble/dropeventemitter/cell.go` |
| `hubble-drop-events-extended` | Bool | `false` | Include L4 network policies in drop event message | `pkg/hubble/dropeventemitter/cell.go` |
| `hubble-drop-events-interval` | Duration | `2 * time.Minute` | Minimum time between emitting same events | `pkg/hubble/dropeventemitter/cell.go` |
| `hubble-drop-events-rate-limit` | Int64 | `1` | Rate limit for the drop event emitter in events per second (0 for no rate limit) | `pkg/hubble/dropeventemitter/cell.go` |
| `hubble-drop-events-reasons` | StringSlice | `def.K8sDropEventsReasons` | Drop reasons to emit events for | `pkg/hubble/dropeventemitter/cell.go` |
| `hubble-dynamic-metrics-config-path` | String | `` | Filepath with dynamic configuration of hubble metrics. | `pkg/hubble/metrics/cell/cell.go` |
| `hubble-event-buffer-capacity` | Int | `observeroption.Default.MaxFlows.AsInt()` | Capacity of Hubble events buffer. The provided value must be one less than an integer power of two and no larger than 65535 (ie: 1, 3, ..., 2047, 4095, ..., 65535) | `pkg/hubble/cell/config.go` |
| `hubble-event-queue-size` | Int | `0` | Buffer size of the channel to receive monitor events. | `pkg/hubble/cell/config.go` |
| `hubble-export-aggregation-interval` | Duration | `0` | Interval at which to aggregate before exporting Hubble flows. 0s disables aggregation. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-allowlist` | String | `` | Specify allowlist as JSON encoded FlowFilters to Hubble exporter. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-denylist` | String | `` | Specify denylist as JSON encoded FlowFilters to Hubble exporter. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-fieldaggregate` | StringSlice | `[]string{}` | Specify list of fields to use for aggregation in Hubble exporter. Empty list disables aggregation. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-fieldmask` | StringSlice | `[]string{}` | Specify list of fields to use for field mask in Hubble exporter. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-file-compress` | Bool | `false` | Compress rotated Hubble export files. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-file-max-backups` | Int | `5` | Number of rotated Hubble export files to keep. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-file-max-size-mb` | Int | `10` | Size in MB at which to rotate Hubble export file. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-export-file-path` | String | `` | Filepath to write Hubble events to. By specifying `stdout` the flows are logged instead of written to a rotated file. | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-flowlogs-config-path` | String | `` | Filepath with configuration of hubble flowlogs | `pkg/hubble/exporter/cell/cell.go` |
| `hubble-listen-address` | String | `` | `An additional address for Hubble server to listen to | `pkg/hubble/cell/config.go` |
| `hubble-lost-event-send-interval` | Duration | `hubbleDefaults.LostEventSendInterval` | Interval at which lost events are sent from the Observer server, if any. | `pkg/hubble/cell/config.go` |
| `hubble-metrics` | String | `` | List of Hubble metrics to enable. | `pkg/hubble/metrics/cell/cell.go` |
| `hubble-metrics-server` | String | `` | Address to serve Hubble metrics on. | `pkg/hubble/metrics/cell/cell.go` |
| `hubble-metrics-server-enable-tls` | Bool | `false` | Run the Hubble metrics server on the given listen address with TLS. | `pkg/hubble/metrics/cell/certloader.go` |
| `hubble-metrics-server-tls-cert-file` | String | `` | Path to the public key file for the Hubble metrics server. The file must contain PEM encoded data. | `pkg/hubble/metrics/cell/certloader.go` |
| `hubble-metrics-server-tls-client-ca-files` | StringSlice | `[]string{}` | Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided,  | `pkg/hubble/metrics/cell/certloader.go` |
| `hubble-metrics-server-tls-key-file` | String | `` | Path to the private key file for the Hubble metrics server. The file must contain PEM encoded data. | `pkg/hubble/metrics/cell/certloader.go` |
| `hubble-monitor-events` | StringSlice | `[]string{}` | Cilium monitor events for Hubble to observe: [%s]. By default, Hubble observes all monitor events. | `pkg/hubble/cell/config.go` |
| `hubble-network-policy-correlation-enabled` | Bool | `true` | Enable network policy correlation of Hubble flows | `pkg/hubble/parser/cell/config.go` |
| `hubble-prefer-ipv6` | Bool | `false` | Prefer IPv6 addresses for announcing nodes when both address types are available. | `pkg/hubble/cell/config.go` |
| `hubble-redact-enabled` | Bool | `false` | Hubble redact sensitive information from flows | `pkg/hubble/parser/cell/config.go` |
| `hubble-redact-http-headers-allow` | StringSlice | `[]string{}` | HTTP headers to keep visible in flows | `pkg/hubble/parser/cell/config.go` |
| `hubble-redact-http-headers-deny` | StringSlice | `[]string{}` | HTTP headers to redact from flows | `pkg/hubble/parser/cell/config.go` |
| `hubble-redact-http-urlquery` | Bool | `false` | Hubble redact http URL query from flows | `pkg/hubble/parser/cell/config.go` |
| `hubble-redact-http-userinfo` | Bool | `true` | Hubble redact http user info from flows | `pkg/hubble/parser/cell/config.go` |
| `hubble-skip-unknown-cgroup-ids` | Bool | `true` | Skip Hubble events with unknown cgroup ids | `pkg/hubble/parser/cell/config.go` |
| `hubble-socket-path` | String | `hubbleDefaults.SocketPath` | Set hubble's socket path to listen for connections | `pkg/hubble/cell/config.go` |
| `hubble-tls-cert-file` | String | `cfg.TLSCertFile` | Path to the public key file for the Hubble server. The file must contain PEM encoded data. | `pkg/hubble/cell/certloader.go` |
| `hubble-tls-client-ca-files` | StringSlice | `cfg.TLSClientCAFiles` | Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided,  | `pkg/hubble/cell/certloader.go` |
| `hubble-tls-key-file` | String | `cfg.TLSKeyFile` | Path to the private key file for the Hubble server. The file must contain PEM encoded data. | `pkg/hubble/cell/certloader.go` |
| `identity-allocation-mode` | String | `kvstore` | Method to use for identity allocation | `daemon/cmd/daemon_main.go` |
| `identity-allocation-sync-interval` | Duration | `5 * time.Minute` | Periodic synchronization interval of the allocated identities | `pkg/identity/cache/cell/cell.go` |
| `identity-allocation-timeout` | Duration | `2 * time.Minute` | Timeout for identity allocation operations | `pkg/identity/cache/cell/cell.go` |
| `identity-change-grace-period` | Duration | `5 * time.Second` | Time to wait before using new identity on endpoint identity change | `daemon/cmd/daemon_main.go` |
| `identity-management-mode` | String | `agent` | Configure whether Cilium Identities are managed by cilium-agent, cilium-operator, or both | `pkg/identity/cache/cell/cell.go` |
| `identity-max-jitter` | Duration | `30 * time.Second` | Maximum jitter time to begin processing CiliumIdentity updates | `daemon/cmd/daemon_main.go` |
| `identity-restore-grace-period` | Duration | `30 * time.Second` | Time to wait before releasing unused restored CIDR identities during agent restart | `daemon/cmd/daemon_main.go` |
| `ignore-flags-drift-checker` | StringSlice | `[]string{}` | Ignores specified flags during drift checking | `pkg/driftchecker/cell.go` |
| `ingress` | Bool | `false` | Look up the ingress policy verdict | `pkg/policy/lookup_script_cmds.go` |
| `ingress-secrets-namespace` | String | `r.IngressSecretsNamespace` | IngressSecretsNamespace is the namespace having tls secrets used by CEC, originating from Ingress controller | `pkg/envoy/config/config.go` |
| `install-iptables-rules` | Bool | `true` | Install base iptables rules for cilium to mainly interact with kube-proxy (and masquerading) | `daemon/cmd/daemon_main.go` |
| `install-no-conntrack-iptables-rules` | Bool | `false` | Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. | `daemon/cmd/daemon_main.go` |
| `install-uplink-routes-for-delegated-ipam` | Bool | `false` | Install ingress/egress routes through uplink on host for Pods when working with delegated IPAM plugin. | `daemon/cmd/daemon_main.go` |
| `instance` | String | `` | Name of a Cilium router instance. Lists policies of all instances if omitted. | `pkg/bgp/commands/route_polices.go` |
| `ip-masq-agent-config-path` | String | `/etc/config/ip-masq-agent` | ip-masq-agent configuration file path | `pkg/ipmasq/cell/config.go` |
| `ip-tracing-option-type` | Uint8 | `0` | Specifies what IPv4 option type should be used to extract trace information from a packet; a value of 0 (default) disables IP tracing. | `daemon/cmd/daemon_main.go` |
| `ipam` | String | `cluster-pool` | Backend to use for IPAM | `daemon/cmd/daemon_main.go` |
| `ipam-cilium-node-update-rate` | Duration | `15*time.Second` | Maximum rate at which the CiliumNode custom resource is updated | `daemon/cmd/daemon_main.go` |
| `ipam-default-ip-pool` | String | `default` | Name of the default IP Pool when using multi-pool | `daemon/cmd/daemon_main.go` |
| `ipam-max-allocate` | Int | `0` | Maximum number of IPs that can be allocated at the node level | `pkg/nodediscovery/cell.go` |
| `ipam-min-allocate` | Int | `0` | Minimum number of IPs that must be allocated when the node is first bootstrapped at the node level | `pkg/nodediscovery/cell.go` |
| `ipam-multi-pool-pre-allocation` | Var | `option.NewMapOptions(&option.Config.IPAMMultiPoolPreAllocation)` | Defines the minimum number of IPs a node should pre-allocate from each pool (default %s=8) | `daemon/cmd/daemon_main.go` |
| `ipam-pre-allocate` | Int | `0` | Number of IP addresses that must be available for allocation in the IPAMspec at the node level | `pkg/nodediscovery/cell.go` |
| `ipam-static-ip-tags` | StringToString | `map[string]string{}` | List of tags to determine the pool of IPs from which to attribute a static IP to the node at the node level, this currently works with AWS and Azure | `pkg/nodediscovery/cell.go` |
| `ipsec-key-file` | String | `` | Path to IPsec key file | `pkg/datapath/linux/ipsec/cell.go` |
| `ipsec-key-rotation-duration` | Duration | `5 * time.Minute` | Maximum duration of the IPsec key rotation. The previous key will be removed after that delay. | `pkg/datapath/linux/ipsec/cell.go` |
| `iptables-lock-timeout` | Duration | `5 * time.Second` | Time to pass to each iptables invocation to wait for xtables lock acquisition | `pkg/datapath/iptables/cell.go` |
| `iptables-random-fully` | Bool | `false` | Set iptables flag random-fully on masquerading rules | `pkg/datapath/iptables/cell.go` |
| `ipv4-native-routing-cidr` | String | `` | Allows to explicitly specify the IPv4 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for tha | `daemon/cmd/daemon_main.go` |
| `ipv4-node` | String | `auto` | IPv4 address of node | `daemon/cmd/daemon_main.go` |
| `ipv4-pod-subnets` | StringSlice | `[]string{}` | List of IPv4 pod subnets to preconfigure for encryption | `daemon/cmd/daemon_main.go` |
| `ipv4-range` | String | `auto` | Per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16 | `daemon/cmd/daemon_main.go` |
| `ipv4-service-loopback-address` | String | `169.254.42.1` | IPv4 source address to use for SNAT when a Pod talks to itself over a Service. | `daemon/infraendpoints/cell.go` |
| `ipv4-service-range` | String | `auto` | Kubernetes IPv4 services CIDR if not inside cluster prefix | `daemon/cmd/daemon_main.go` |
| `ipv6-cluster-alloc-cidr` | String | `IPv6ClusterAllocCIDRBase + "/64"` | IPv6 /64 CIDR used to allocate per node endpoint /96 CIDR | `daemon/cmd/daemon_main.go` |
| `ipv6-mcast-device` | String | `` | Device that joins a Solicited-Node multicast group for IPv6 | `daemon/cmd/daemon_main.go` |
| `ipv6-native-routing-cidr` | String | `` | Allows to explicitly specify the IPv6 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for tha | `daemon/cmd/daemon_main.go` |
| `ipv6-node` | String | `auto` | IPv6 address of node | `daemon/cmd/daemon_main.go` |
| `ipv6-pod-subnets` | StringSlice | `[]string{}` | List of IPv6 pod subnets to preconfigure for encryption | `daemon/cmd/daemon_main.go` |
| `ipv6-range` | String | `auto` | Per-node IPv6 endpoint prefix, e.g. fd02:1:1::/96 | `daemon/cmd/daemon_main.go` |
| `ipv6-service-loopback-address` | String | `fe80::1` | IPv6 source address to use for SNAT when a Pod talks to itself over a Service. | `daemon/infraendpoints/cell.go` |
| `ipv6-service-range` | String | `auto` | Kubernetes IPv6 services CIDR if not inside cluster prefix | `daemon/cmd/daemon_main.go` |
| `k8s-api-server-urls` | StringSlice | `[]string{}` | Kubernetes API server URLs | `pkg/k8s/client/config.go` |
| `k8s-client-burst` | Int | `20` | Burst value allowed for the K8s client | `pkg/k8s/client/config.go` |
| `k8s-client-connection-keep-alive` | Duration | `30 * time.Second` | Configures the keep alive duration of K8s client connections. K8 client is disabled if the value is set to 0 | `pkg/k8s/client/config.go` |
| `k8s-client-connection-timeout` | Duration | `30 * time.Second` | Configures the timeout of K8s client connections. K8s client is disabled if the value is set to 0 | `pkg/k8s/client/config.go` |
| `k8s-client-qps` | Float32 | `10.0` | Queries per second limit for the K8s client | `pkg/k8s/client/config.go` |
| `k8s-heartbeat-timeout` | Duration | `30 * time.Second` | Configures the timeout for api-server heartbeat, set to 0 to disable | `pkg/k8s/client/config.go` |
| `k8s-kubeconfig-path` | String | `` | Absolute path of the kubernetes kubeconfig file | `pkg/k8s/client/config.go` |
| `k8s-namespace` | String | `` | Name of the Kubernetes namespace in which Cilium is deployed in | `daemon/cmd/daemon_main.go` |
| `k8s-require-ipv4-pod-cidr` | Bool | `false` | Require IPv4 PodCIDR to be specified in node resource | `daemon/cmd/daemon_main.go` |
| `k8s-require-ipv6-pod-cidr` | Bool | `false` | Require IPv6 PodCIDR to be specified in node resource | `daemon/cmd/daemon_main.go` |
| `k8s-service-proxy-name` | String | `` | Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label) | `pkg/k8s/resource_ctors.go` |
| `k8s-sync-timeout` | Duration | `3 * time.Minute` | Timeout after last K8s event for synchronizing k8s resources before exiting | `daemon/cmd/daemon_main.go` |
| `keep-config` | Bool | `false` | When restoring state, keeps containers' configuration in place | `daemon/cmd/daemon_main.go` |
| `keys-only` | Bool | `false` | Only output the listed keys | `pkg/kvstore/commands.go` |
| `kube-proxy-replacement` | Bool | `false` | Enable kube-proxy replacement | `pkg/kpr/kpr.go` |
| `kube-proxy-replacement-healthz-bind-address` | String | `` | The IP address with port for kube-proxy replacement health check server to serve on (set to '0.0.0.0:10256' for all IPv4 interfaces and '[::]:10256' for all IPv6 interfac | `daemon/healthz/kube_proxy_healthz.go` |
| `kvstore` | String | `defaultBackend` | Key-value store type | `pkg/kvstore/cell.go` |
| `kvstore-lease-ttl` | Duration | `15 * time.Minute` | Time-to-live for the KVstore lease. | `pkg/kvstore/cell.go` |
| `kvstore-max-consecutive-quorum-errors` | Uint | `2` | Max acceptable kvstore consecutive quorum errors before recreating the etcd connection | `pkg/kvstore/cell.go` |
| `kvstore-opt` | StringToString | `make(map[string]string)` | Key-value store options e.g. etcd.address=127.0.0.1:4001 | `pkg/kvstore/cell.go` |
| `l2-announcements-lease-duration` | Duration | `15*time.Second` | Duration of inactivity after which a new leader is selected | `daemon/cmd/daemon_main.go` |
| `l2-announcements-renew-deadline` | Duration | `5*time.Second` | Interval at which the leader renews a lease | `daemon/cmd/daemon_main.go` |
| `l2-announcements-retry-period` | Duration | `2*time.Second` | Timeout after a renew failure, before the next retry | `daemon/cmd/daemon_main.go` |
| `l2-pod-announcements-interface-pattern` | String | `` | Regex matching interfaces used for sending gratuitous ARP and NDP messages | `pkg/datapath/gneigh/cells.go` |
| `label-prefix-file` | String | `` | Valid label prefixes file path | `daemon/cmd/daemon_main.go` |
| `labels` | StringSlice | `[]string{}` | List of label prefixes used to determine identity of an endpoint | `daemon/cmd/daemon_main.go` |
| `lb-init-wait-timeout` | Duration | `1 * time.Minute` | Amount of time to wait for initialization before reconciling BPF maps | `pkg/loadbalancer/config.go` |
| `lb-pressure-metrics-interval` | Duration | `5 * time.Minute` | Interval for reporting pressure metrics for load-balancing BPF maps. 0 disables reporting. | `pkg/loadbalancer/config.go` |
| `lb-reflector-wait-time` | Duration | `500 * time.Millisecond` | Maximum time the K8s reflector waits to fill its event buffer | `pkg/loadbalancer/config.go` |
| `lb-retry-backoff-max` | Duration | `time.Second` | Maximum amount of time to wait before retrying LB operation | `pkg/loadbalancer/config.go` |
| `lb-retry-backoff-min` | Duration | `time.Second` | Minimum amount of time to wait before retrying LB operation | `pkg/loadbalancer/config.go` |
| `lb-sock-terminate-all-protos` | Bool | `false` | Enable terminating connections to deleted service backends for both TCP and UDP | `pkg/loadbalancer/config.go` |
| `lb-state-file` | String | `` | Synchronize load-balancing state from the specified file | `pkg/loadbalancer/reflectors/file.go` |
| `lb-state-file-interval` | Duration | `time.Second` | Amount of time to wait for load-balancing state file to settle before processing it | `pkg/loadbalancer/reflectors/file.go` |
| `lb-test-fault-probability` | Float32 | `def.TestFaultProbability` | Probability for fault injection in LBMaps (0..1) | `pkg/loadbalancer/config.go` |
| `levels` | StringSlice | `[]string{types.LevelOK, types.LevelDegraded, types.LevelStopped}` | Output only health reports with the specified state (i.e. ok,degraded,stopped) | `pkg/hive/health/command.go` |
| `lib-dir` | String | `/var/lib/cilium` | Directory path to store runtime build environment | `daemon/cmd/daemon_main.go` |
| `local-max-addr-scope` | String | `fmt.Sprintf("%d", defaults.AddressScopeMax)` | Maximum local address scope for ipcache to consider host addresses | `daemon/cmd/daemon_main.go` |
| `local-router-ipv4` | String | `` | Link-local IPv4 used for Cilium's router devices | `daemon/cmd/daemon_main.go` |
| `local-router-ipv6` | String | `` | Link-local IPv6 used for Cilium's router devices | `daemon/cmd/daemon_main.go` |
| `log-driver` | StringSlice | `[]string{}` | Logging endpoints to use for example syslog | `daemon/cmd/daemon_main.go` |
| `log-opt` | Var | `option.NewMapOptions(&option.Config.LogOpt)` | `Log driver options for cilium-agent | `daemon/cmd/daemon_main.go` |
| `log-system-load` | Bool | `false` | Enable periodic logging of system load | `daemon/cmd/daemon_main.go` |
| `lrp-address-matcher-cidrs` | StringSlice | `[]string{}` | Limit address matches to specific CIDRs | `pkg/loadbalancer/redirectpolicy/config.go` |
| `match` | String | `` | Output only health reports where the reporter ID path contains the substring | `pkg/hive/health/command.go` |
| `max-connected-clusters` | Uint32 | `255` | Maximum number of clusters to be connected in a clustermesh. Increasing this value will reduce the maximum number of identities available. Valid configurations are [255,  | `pkg/clustermesh/types/option.go` |
| `max-controller-interval` | Uint | `0` | Maximum interval (in seconds) between controller runs. Zero is no limit. | `daemon/cmd/daemon_main.go` |
| `max-internal-timer-delay` | Duration | `0 * time.Second` | Maximum internal timer value across the entire agent. Use in test environments to detect race conditions in agent logic. | `daemon/cmd/daemon_main.go` |
| `mesh-auth-enabled` | Bool | `false` | Enable authentication processing & garbage collection (beta) | `pkg/auth/cell.go` |
| `mesh-auth-gc-interval` | Duration | `5 * time.Minute` | Interval in which auth entries are attempted to be garbage collected | `pkg/auth/cell.go` |
| `mesh-auth-queue-size` | Int | `1024` | Queue size for the auth manager | `pkg/auth/cell.go` |
| `mesh-auth-signal-backoff-duration` | Duration | `1 * time.Second` | Time to wait betweeen two authentication required signals in case of a cache mismatch | `pkg/auth/cell.go` |
| `metrics` | StringSlice | `metrics` | Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo, -metric_bar to disable metric_bar) | `pkg/metrics/registry.go` |
| `metrics-sampling-interval` | Duration | `5 * time.Minute` | Set the internal metrics sampling interval | `pkg/metrics/sampler.go` |
| `mke-cgroup-mount` | String | `` | Cgroup v1 net_cls mount path for MKE environments | `daemon/cmd/daemon_main.go` |
| `monitor-aggregation` | String | `None` | Level of monitor aggregation for traces from the datapath | `daemon/cmd/daemon_main.go` |
| `monitor-aggregation-flags` | StringSlice | `[]string{"syn", "fin", "rst"}` | TCP flags that trigger monitor reports when monitor aggregation is enabled | `daemon/cmd/daemon_main.go` |
| `monitor-aggregation-interval` | Duration | `5*time.Second` | Monitor report interval when monitor aggregation is enabled | `daemon/cmd/daemon_main.go` |
| `monitor-queue-size` | Int | `0` | Size of the event queue when reading monitor events | `pkg/monitor/agent/cell.go` |
| `mtu` | Int | `0` | Overwrite auto-detected MTU of underlying network | `pkg/mtu/cell.go` |
| `multicast-enabled` | Bool | `false` | Enables multicast in Cilium | `pkg/maps/multicast/mcast.go` |
| `nat-map-stats-entries` | Int | `32` | Number k top stats entries to store locally in statedb | `pkg/maps/nat/stats/cell.go` |
| `nat-map-stats-interval` | Duration | `30 * time.Second` | Interval upon which nat maps are iterated for stats | `pkg/maps/nat/stats/cell.go` |
| `no-age` | Bool | `false` | Do not show Age column for testing purpose | `pkg/bgp/commands/routes.go` |
| `no-uptime` | Bool | `false` | Do not show Uptime for testing purpose | `pkg/bgp/commands/peer.go` |
| `node-encryption-opt-out-labels` | String | `node-role.kubernetes.io/control-plane` | Label selector for nodes which will opt-out of node-to-node encryption | `pkg/wireguard/agent/cell.go` |
| `node-labels` | StringSlice | `[]string{}` | List of label prefixes used to determine identity of a node (used only when enable-node-selector-labels is enabled) | `daemon/cmd/daemon_main.go` |
| `node-port-acceleration` | String | `disabled` | BPF NodePort acceleration via XDP ("%s", "%s") | `daemon/cmd/daemon_main.go` |
| `node-port-bind-protection` | Bool | `true` | Reject application bind(2) requests to service ports in the NodePort range | `daemon/cmd/daemon_main.go` |
| `node-port-range` | StringSlice | `[]string{fmt.Sprintf("%d", NodePortMinDefault), fmt.Sprintf("%d", NodePortMaxDefault)}` | Set the min/max NodePort port range | `pkg/loadbalancer/config.go` |
| `nodeport-addresses` | StringSlice | `nil` | A whitelist of CIDRs to limit which IPs are used for NodePort. If not set, primary IPv4 and/or IPv6 address of each native device is used. | `pkg/datapath/tables/node_address.go` |
| `num` | Int | `10` | Maxiumum number of rows per endpoint to display | `pkg/policy/commands/topk.go` |
| `only-masquerade-default-pool` | Bool | `false` | When using multi-pool IPAM, only masquerade flows from the default IP pool. This will preserve source IPs for pods from non-default IP pools. Useful when combining multi- | `pkg/ipam/cell/cell.go` |
| `out` | String | `` | Output file | `pkg/metrics/cmd.go` |
| `output` | String | `plain` | Output format. One of: (plain, json) | `pkg/kvstore/commands.go` |
| `packetization-layer-pmtud-mode` | String | `plpmtudModeBlackhole.String()` | Enables kernel packetization layer path mtu discovery on Pod netns (if empty will use host setting) | `pkg/mtu/cell.go` |
| `password` | String | `` | Authentication password used for the peer. | `pkg/bgp/test/commands/gobgp.go` |
| `per-cluster-ready-timeout` | Duration | `15 * time.Second` | Remote clusters will be disregarded for readiness checks if a connection cannot be established within this duration | `pkg/clustermesh/kvstoremesh/kvstoremesh.go` |
| `policy-accounting` | Bool | `true` | Maintain packet and byte counters for every policy entry | `daemon/cmd/daemon_main.go` |
| `policy-audit-mode` | Bool | `false` | Enable policy audit (non-drop) mode | `daemon/cmd/daemon_main.go` |
| `policy-cidr-match-mode` | StringSlice | `[]string{}` | The entities that can be selected by CIDR policy. Supported values: 'nodes', 'pods' | `daemon/cmd/daemon_main.go` |
| `policy-default-local-cluster` | Bool | `true` | Control whether policy rules assume by default the local cluster if not explicitly selected | `pkg/clustermesh/types/option.go` |
| `policy-deny-response` | String | `none` | How to handle pod egress traffic dropped by network policy: either drop the packet ("none") or reject with an ICMP Destination Unreachable ("icmp") | `daemon/cmd/daemon_main.go` |
| `policy-queue-size` | Uint | `100` | Size of queue for policy-related events | `pkg/policy/cell/cell.go` |
| `policy-secrets-namespace` | String | `mc.PolicySecretsNamespace` | PolicySecretsNamesapce is the namespace having secrets used in CNP and CCNP | `pkg/crypto/certificatemanager/certificate_manager.go` |
| `policy-secrets-only-from-secrets-namespace` | Bool | `mc.PolicySecretsOnlyFromSecretsNamespace` | Configures the agent to only read policy Secrets from the policy-secrets-namespace | `pkg/crypto/certificatemanager/certificate_manager.go` |
| `policy-trigger-interval` | Duration | `1 * time.Second` | Time between triggers of policy updates (regenerations for all endpoints) | `daemon/cmd/daemon_main.go` |
| `pprof` | Bool | `def.Pprof` | Enable serving pprof debugging API | `pkg/pprof/cell.go` |
| `pprof-address` | String | `def.PprofAddress` | Address that pprof listens on | `pkg/pprof/cell.go` |
| `pprof-block-profile-rate` | Int | `def.PprofBlockProfileRate` | Enable goroutine blocking profiling and set the rate of sampled events in nanoseconds (set to 1 to sample all events [warning: performance overhead]) | `pkg/pprof/cell.go` |
| `pprof-mutex-profile-fraction` | Int | `def.PprofMutexProfileFraction` | Enable mutex contention profiling and set the fraction of sampled events (set to 1 to sample all events) | `pkg/pprof/cell.go` |
| `pprof-port` | Uint16 | `def.PprofPort` | Port that pprof listens on | `pkg/pprof/cell.go` |
| `preallocate-bpf-maps` | Bool | `true` | Enable BPF map pre-allocation | `daemon/cmd/daemon_main.go` |
| `prefer-ipv6` | Bool | `false` | Prefer IPv6 addresses over IPv4 when both are available | `daemon/cmd/daemon_main.go` |
| `prepend-iptables-chains` | Bool | `true` | Prepend custom iptables chains instead of appending | `pkg/datapath/iptables/cell.go` |
| `procfs` | String | `/proc` | Path to the host's proc filesystem mount | `pkg/datapath/linux/sysctl/cell.go` |
| `prometheus-serve-addr` | String | `` | IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off) | `pkg/metrics/registry.go` |
| `proxy-admin-port` | Int | `0` | Port to serve Envoy admin interface on. | `pkg/envoy/config/config.go` |
| `proxy-cluster-max-connections` | Uint32 | `1024` | Maximum number of connections on Envoy clusters | `pkg/envoy/config/config.go` |
| `proxy-cluster-max-pending-requests` | Uint32 | `1024` | Maximum number of pending requests on Envoy clusters | `pkg/envoy/config/config.go` |
| `proxy-cluster-max-requests` | Uint32 | `1024` | Maximum number of requests on Envoy clusters | `pkg/envoy/config/config.go` |
| `proxy-connect-timeout` | Uint | `2` | Time after which a TCP connect attempt is considered failed unless completed (in seconds) | `pkg/envoy/config/config.go` |
| `proxy-gid` | Uint | `1337` | Group ID for proxy control plane sockets. | `pkg/envoy/config/config.go` |
| `proxy-idle-timeout-seconds` | Int | `60` | Set Envoy upstream HTTP idle connection timeout in seconds. Does not apply to connections with pending requests. | `pkg/envoy/config/config.go` |
| `proxy-initial-fetch-timeout` | Uint | `30` | Time after which an xDS stream is considered timed out (in seconds) | `pkg/envoy/config/config.go` |
| `proxy-max-active-downstream-connections` | Int64 | `50000` | Set Envoy HTTP option max_active_downstream_connections | `pkg/envoy/config/config.go` |
| `proxy-max-concurrent-retries` | Uint32 | `128` | Maximum number of concurrent retries on Envoy clusters | `pkg/envoy/config/config.go` |
| `proxy-max-connection-duration-seconds` | Int | `0` | Set Envoy HTTP option max_connection_duration seconds. Default 0 (disable) | `pkg/envoy/config/config.go` |
| `proxy-max-requests-per-connection` | Int | `0` | Set Envoy HTTP option max_requests_per_connection. Default 0 (disable) | `pkg/envoy/config/config.go` |
| `proxy-portrange-max` | Uint16 | `20000` | End of port range that is used to allocate ports for L7 proxies. | `pkg/proxy/proxyports/proxyports.go` |
| `proxy-portrange-min` | Uint16 | `10000` | Start of port range that is used to allocate ports for L7 proxies. | `pkg/proxy/proxyports/proxyports.go` |
| `proxy-prometheus-port` | Int | `0` | Port to serve Envoy metrics on. Default 0 (disabled). | `pkg/envoy/config/config.go` |
| `proxy-use-original-source-address` | Bool | `true` | Controls if Cilium's Envoy BPF metadata listener filter for L7 policy enforcement redirects should be configured to use original source address when extracting the metada | `pkg/proxy/cell.go` |
| `proxy-xff-num-trusted-hops-egress` | Uint32 | `0` | Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the egress L7 policy enforcement Envoy listeners. | `pkg/envoy/config/config.go` |
| `proxy-xff-num-trusted-hops-ingress` | Uint32 | `0` | Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the ingress L7 policy enforcement Envoy listeners. | `pkg/envoy/config/config.go` |
| `rate` | Bool | `false` | Plot the rate of change | `pkg/metrics/cmd.go` |
| `read-cni-conf` | String | `` | CNI configuration file to use as a source for --%s. If not supplied, a suitable one will be generated. | `daemon/cmd/cni/config/config.go` |
| `restore` | Bool | `true` | Restores state, if possible, from previous daemon | `daemon/cmd/daemon_main.go` |
| `restored-proxy-ports-age-limit` | Uint | `15` | Time after which a restored proxy ports file is considered stale (in minutes) | `pkg/proxy/proxyports/proxyports.go` |
| `route-metric` | Int | `0` | Overwrite the metric used by cilium when adding routes to its 'cilium_host' device | `daemon/cmd/daemon_main.go` |
| `router-id` | String | `` | router-id of the server. Defaults to server ip if not provided. | `pkg/bgp/test/commands/gobgp.go` |
| `routing-mode` | String | `tunnel` | Routing mode (%q or %q) | `daemon/cmd/daemon_main.go` |
| `sampled` | Bool | `false` | Show sampled metrics | `pkg/metrics/cmd.go` |
| `server-name` | String | `` | Name of the GoBGP server instance. Can be omitted if only one instance is active. | `pkg/bgp/test/commands/gobgp.go` |
| `service-no-backend-response` | String | `reject` | Response to traffic for a service without backends | `daemon/cmd/daemon_main.go` |
| `SkipCRDCreation` | Bool | `false` | When true, Kubernetes Custom Resource Definitions will not be created | `pkg/k8s/apis/cell.go` |
| `socket-path` | String | `RuntimePath + "/cilium.sock"` | Sets daemon's socket path to listen for connections | `daemon/cmd/daemon_main.go` |
| `srv6-encap-mode` | String | `reduced` | Encapsulation mode for SRv6 ("srh" or "reduced") | `daemon/cmd/daemon_main.go` |
| `standalone-dns-proxy-server-port` | Int | `10095` | Global port on which the gRPC server for standalone DNS proxy should listen | `pkg/fqdn/service/cell.go` |
| `state-dir` | String | `/var/run/cilium` | Directory path to store runtime state | `daemon/cmd/daemon_main.go` |
| `static-cnp-path` | String | `` | Directory path to watch and load static cilium network policy yaml files. | `pkg/policy/directory/cell.go` |
| `status-collector-failure-threshold` | Duration | `1 * time.Minute` | The duration after which a probe is considered failed | `pkg/status/cell.go` |
| `status-collector-interval` | Duration | `5 * time.Second` | The interval between probe invocations | `pkg/status/cell.go` |
| `status-collector-probe-check-timeout` | Duration | `5 * time.Minute` | The timeout after which all probes should have finished at least once | `pkg/status/cell.go` |
| `status-collector-stackdump-path` | String | `/run/cilium/state/agent.stack.gz` | The path where probe stackdumps should be written to | `pkg/status/cell.go` |
| `status-collector-warning-threshold` | Duration | `15 * time.Second` | The duration after which a probe is declared as stale | `pkg/status/cell.go` |
| `subject` | Bool | `false` | Dump the subject selector cache instead of the peer selector cache | `pkg/policy/repository.go` |
| `subnet-topology` | String | `` | Comma and/or semicolon separated list of subnets in CIDR notation representing the subnet topology. | `pkg/subnet/config.go` |
| `timeout` | Duration | `30 * time.Second` | Maximum amount of time to wait for the peering state | `pkg/bgp/test/commands/gobgp.go` |
| `tofqdns-dns-reject-response-code` | String | `refused` | DNS response code for rejecting DNS requests, available options are '%v' | `daemon/cmd/daemon_main.go` |
| `tofqdns-enable-dns-compression` | Bool | `true` | Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present | `pkg/fqdn/service/cell.go` |
| `tofqdns-endpoint-max-ip-per-hostname` | Int | `1000` | Maximum number of IPs to maintain per FQDN name for each endpoint | `daemon/cmd/daemon_main.go` |
| `tofqdns-idle-connection-grace-period` | Duration | `0 * time.Second` | Time during which idle but previously active connections with expired DNS lookups are still considered alive (default 0s) | `daemon/cmd/daemon_main.go` |
| `tofqdns-max-deferred-connection-deletes` | Int | `10000` | Maximum number of IPs to retain for expired DNS lookups with still-active connections | `daemon/cmd/daemon_main.go` |
| `tofqdns-min-ttl` | Int | `0` | The minimum time, in seconds, to use DNS data for toFQDNs policies | `daemon/cmd/daemon_main.go` |
| `tofqdns-pre-cache` | String | `` | DNS cache data at this path is preloaded on agent startup | `daemon/cmd/daemon_main.go` |
| `tofqdns-preallocate-identities` | Bool | `true` | Preallocate identities for ToFQDN selectors. This reduces proxied DNS response latency. Disable if you have many ToFQDN selectors. | `pkg/fqdn/namemanager/cell.go` |
| `tofqdns-proxy-port` | Int | `0` | Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port. | `daemon/cmd/daemon_main.go` |
| `tofqdns-proxy-response-max-delay` | Duration | `100 * time.Millisecond` | The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information. | `daemon/cmd/daemon_main.go` |
| `trace-payloadlen` | Int | `128` | Length of payload to capture when tracing native packets. | `daemon/cmd/daemon_main.go` |
| `trace-payloadlen-overlay` | Int | `192` | Length of payload to capture when tracing overlay packets. | `daemon/cmd/daemon_main.go` |
| `trace-sock` | Bool | `true` | Enable tracing for socket-based LB | `daemon/cmd/daemon_main.go` |
| `tunnel-port` | Uint16 | `0` | Tunnel port (default %d for "vxlan" and %d for "geneve") | `pkg/datapath/tunnel/tunnel.go` |
| `tunnel-protocol` | String | `vxlan` | Encapsulation protocol to use for the overlay ("vxlan" or "geneve") | `pkg/datapath/tunnel/tunnel.go` |
| `tunnel-source-port-range` | String | `0-0` | Tunnel source port range hint (default %s) | `pkg/datapath/tunnel/tunnel.go` |
| `underlay-protocol` | String | `auto` | IP family for the underlay ("ipv4", "ipv6", or "auto") | `pkg/datapath/tunnel/tunnel.go` |
| `use-cilium-internal-ip-for-ipsec` | Bool | `false` | Use the CiliumInternalIPs (vs. NodeInternalIPs) for IPsec encapsulation | `pkg/datapath/linux/ipsec/cell.go` |
| `use-full-tls-context` | Bool | `false` | If enabled, persist ca.crt keys into the Envoy config even in a terminatingTLS block on an L7 Cilium Policy. This is to enable compatibility with previously buggy behavio | `pkg/envoy/config/config.go` |
| `values-only` | Bool | `false` | Only output the listed values | `pkg/kvstore/commands.go` |
| `version` | Bool | `false` | Print version information | `daemon/cmd/daemon_main.go` |
| `vlan-bpf-bypass` | StringSlice | `[]string{}` | List of explicitly allowed VLAN IDs, '0' id will allow all VLAN IDs | `daemon/cmd/daemon_main.go` |
| `vtep-cidr` | StringSlice | `[]string{}` | List of VTEP CIDRs that will be routed towards VTEPs for traffic cluster egress | `pkg/datapath/vtep/cell.go` |
| `vtep-endpoint` | StringSlice | `[]string{}` | List of VTEP IP addresses | `pkg/datapath/vtep/cell.go` |
| `vtep-mac` | StringSlice | `[]string{}` | List of VTEP MAC addresses for forwarding traffic outside the cluster | `pkg/datapath/vtep/cell.go` |
| `vtep-mask` | String | `255.255.255.0` | VTEP CIDR Mask for all VTEP CIDRs | `daemon/cmd/daemon_main.go` |
| `vtep-sync-interval` | Duration | `1 * time.Minute` | Interval for VTEP sync | `pkg/datapath/vtep/cell.go` |
| `wireguard-persistent-keepalive` | Duration | `0` | The Wireguard keepalive interval as a Go duration string | `pkg/wireguard/agent/cell.go` |
| `wireguard-track-all-ips-fallback` | Bool | `false` | Force WireGuard to track all IPs | `pkg/wireguard/agent/cell.go` |
| `with-attrs` | Bool | `false` | Show path attributes (excluding NEXT_HOP and MP_REACH_NLRI) | `pkg/bgp/commands/routes.go` |
| `write-cni-conf-when-ready` | String | `` | Write the CNI configuration to the specified path when agent is ready | `daemon/cmd/cni/config/config.go` |
| `xds-node-id` | String | `` | NodeID for xDS client | `pkg/xds/experimental/client/cell.go` |
| `xds-server-address` | String | `` | Address of xDS server | `pkg/xds/experimental/client/cell.go` |
| `xds-use-sotw-protocol` | Bool | `true` | Use State Of The World, non-incremental version of xDS protocol | `pkg/xds/experimental/client/cell.go` |
| `ztunnel-endpoint-event-channel-buffer-size` | Int | `1` | Buffer size for the ztunnel endpoint event channel | `pkg/ztunnel/config/config.go` |

## Appendix B — cilium-dbg command tree and backend

`cilium-dbg` global flags: `-H/--host` (`unix:///var/run/cilium/cilium.sock`, env
`CILIUM_SOCK`), `--config` (`$HOME/.cilium.yaml`), `-D/--debug`, `--log-driver`,
`--log-opt`. Output `-o json|yaml|jsonpath=…` on most list/get commands.

| Command | Backend |
|---|---|
| `bgp peers` / `bgp routes <available\|advertised> <afi> <safi> [vrouter asn] [peer addr]` / `bgp route-policies [vrouter asn]` | `GET /bgp/peers`, `GET /bgp/routes`, `GET /bgp/route-policies` |
| `bpf auth list\|flush` | pinned map `cilium_auth_map` (direct) |
| `bpf bandwidth list` | `cilium_throttle` (direct) |
| `bpf config list` | `cilium_runtime_config` (direct) |
| `bpf ct list [cluster id]\|flush` | `cilium_ct{4,6}_global`, `cilium_ct_any{4,6}_global`, per-cluster maps (direct) |
| `bpf egress list` | `cilium_egress_gw_policy_v4(_v2)/v6` (direct) |
| `bpf endpoint list\|delete` | `cilium_lxc` (direct) |
| `bpf frag list` | `cilium_ipv{4,6}_frag_datagrams` (direct) |
| `bpf ipcache list\|get\|match\|update\|delete` | `cilium_ipcache(_v2)` (direct) |
| `bpf ipmasq list` | `cilium_ipmasq_v4/v6` (direct) |
| `bpf lb list [--revnat\|--frontends\|--backends\|--source-ranges]`, `bpf lb maglev list` | `cilium_lb{4,6}_services_v2/backends_v3/reverse_nat/source_range/maglev` (direct) |
| `bpf metrics list\|flush` | `cilium_metrics` (direct) |
| `bpf fs show` | mountinfo |
| `bpf multicast group add\|delete\|list`, `bpf multicast subscriber add\|delete\|list` | `cilium_mcast_*` (direct) |
| `bpf nat list [cluster id]\|flush`, `bpf nat retries list\|flush` | `cilium_snat_v{4,6}_external`, `_alloc_retries` (direct) |
| `bpf nodeid list` | `cilium_node_map(_v2)` (direct) |
| `bpf policy get [--all] [--numeric]\|list\|add\|delete` | `cilium_policy_v2_<epid>` (direct; uses `GET /endpoint` for ids) |
| `bpf sha list\|get <sha>` | `<state-dir>/templates/<sha>` + `cilium_calls_*` |
| `bpf socknat list` | `cilium_lb{4,6}_reverse_sk` (direct) |
| `bpf srv6 sid\|policy\|vrf` | `cilium_srv6_*` (direct) |
| `bpf vtep list\|update\|delete` | `cilium_vtep_map` (direct) |
| `build-config --node-name $K8S_NODE_NAME [--dest /tmp/cilium/config-map] [--source …]` | k8s API: ConfigMap `cilium-config`, CiliumNodeConfig, node annotations → files (init container) |
| `cgroups list` | `GET /cgroup-dump-metadata` |
| `cmdman`, `completion`, `version` | local; `version` daemon half from `GET /debuginfo` |
| `config [Opt=enable\|disable …] [-a] [--list-options] [-r]`, `config get <name>` | `GET /config`, `PATCH /config` |
| `debuginfo [--output markdown,json,html] [-f] [--output-directory]` | `GET /debuginfo` |
| `encrypt status\|flush\|dump-xfrm` | netlink xfrm + `GET /healthz` (encryption section) |
| `endpoint list [-l labels]`, `get <id\|-l>`, `config <id> [Opt=…]`, `labels <id> -a/-d`, `log <id>`, `health <id>`, `disconnect <id>` | `GET /endpoint`, `GET /endpoint/{id}`, `GET/PATCH /endpoint/{id}/config`, `GET/PATCH /endpoint/{id}/labels`, `GET /endpoint/{id}/log`, `GET /endpoint/{id}/healthz`, `DELETE /endpoint/{id}` |
| `envoy admin certs\|clusters\|config\|listeners\|logging [list\|set global\|set loggers]\|metrics\|serverinfo` | Envoy admin over `/var/run/cilium/envoy/sockets/admin.sock` |
| `fqdn cache list [-e id] [--matchpattern] [--cidr] [--source]`, `fqdn cache clean`, `fqdn names` | `GET /fqdn/cache`, `GET /fqdn/cache/{id}`, `DELETE /fqdn/cache`, `GET /fqdn/names` |
| `identity list [LABELS] [--endpoints]`, `identity get <id\|-l>` | `GET /identity`, `GET /identity/endpoints`, `GET /identity/{id}` |
| `ip list [-n] [--verbose]`, `ip get <cidr\|-l>` | `GET /ip` |
| `kvstore get\|set\|delete [--recursive] <key>` (`--kvstore`, `--kvstore-opt`) | etcd directly (config discovered via `GET /config`) |
| `loadinfo` | `/proc/loadavg`, `/proc/meminfo` |
| `lrp list` | `GET /lrp` |
| `map list [--verbose]`, `map get <name>`, `map events <name> [--follow]` | `GET /map`, `GET /map/{name}`, `GET /map/{name}/events` |
| `metrics list [-p pattern]` | scrapes the agent's Prometheus endpoint |
| `monitor [--type] [--from/--to/--related-to] [-v] [--hex] [-j]` | `/var/run/cilium/monitor1_2.sock` + `GET /endpoint` for names |
| `node list`, `nodeid list` | `GET /cluster/nodes`, `GET /node/ids` |
| `policy get`, `policy selectors [--subject]`, `policy wait <revision> [--max-wait]` | `GET /policy`, `GET /policy/selectors`, `GET /policy/subject-selectors`, polls `GET /endpoint` |
| `post-uninstall-cleanup [--all-state] [--bpf-state] [-f]` | local: unpin maps, delete `cilium_*` links, iptables, `/var/run/cilium` |
| `prefilter list\|update\|delete --cidr …` | `GET/PATCH/DELETE /prefilter` |
| `preflight migrate-identity`, `preflight validate-cnp` | k8s + kvstore directly |
| `service list [--clustermesh-affinity]` | `GET /service` |
| `shell [-- cmd]` | `/var/run/cilium/shell.sock` (hive script commands) |
| `statedb [table]` | `GET /statedb/dump` on the API socket |
| `status [--brief] [--verbose] [--all-*] [--require-k8s-connectivity]` | `GET /healthz` (+ statedb `health` table for module health lines) |
| `sysdump` | prints instructions to use `cilium-cli sysdump` |
| `troubleshoot kvstore`, `troubleshoot clustermesh [clusters…]` | reads config/secrets, dials etcd directly |

## Appendix C — bugtool collection list (`bugtool/cmd/configuration.go`)

`cilium-bugtool [--archive] [-o tar|gz] [--archive-prefix] [--exec-timeout 30s]
[--parallel-workers N] [--dry-run] [--config <json>] [--host <api>] [--envoy-dump]
[--envoy-metrics] [--get-pprof …]`. Output dir `cilium-bugtool-<ts>-*/{cmd,conf}`, tar to
stdout or `/tmp`. Commands (each output → one file, secrets masked in Envoy dumps):

- System: `cat /proc/net/{xfrm_stat,softnet_stat,snmp,netstat,snmp6}`, `dev_snmp6/*`, `ps auxfw`, `hostname`, `ip a`, `ip -4/-6 r`, `ip -d -s -s l`, `ip -4/-6 n`, `ss -t/-u -p -a -i -s -n -e`, `uname -a`, `top -b -n 1`, `uptime`, `dmesg --time-format=iso`, `sysctl -a`, `bpftool map/prog/net show`, `taskset -pc 1`, `iptables-save -c` (+ nft/legacy, v6), `ip -d rule`, `ipset list`, `ip -s xfrm policy/state`, `gops memstats/stack/stats $(pidof cilium-agent)`, `ls -la /proc/<pid>/fd`, `lsmod`, `tc qdisc show`, `tc -d -s qdisc show`, `find /sys/fs/bpf -ls`; per interface `tc filter show dev X ingress/egress`, `tc chain show`, `tc class show`; per routing table `ip -4/-6 route show table N`; `ethtool -i/-S/-k` per NIC; `bpftool cgroup tree <cgroup2 mount>`.
- BPF map dumps: `bpftool map dump pinned /sys/fs/bpf/tc/globals/<name>` for ~70 names (`cilium_lxc`, `cilium_ipcache(_v2)`, `cilium_ct*`, `cilium_snat*`, `cilium_lb*`, `cilium_policy` call map, `cilium_metrics`, `cilium_node_map(_v2)`, `cilium_encrypt_state`, `cilium_egress_gw_policy_*`, `cilium_srv6_*`, `cilium_vtep_map`, `cilium_l2_responder_*`, `cilium_ratelimit*`, `cilium_skip_lb*`, `cilium_auth_map`, `cilium_runtime_config`, `cilium_throttle`, `cilium_ipmasq_*`, `cilium_*_frag_datagrams`, `cilium_nodeport_neigh*`, `cilium_lb*_health/reverse_sk/affinity/maglev/source_range`, `cilium_calls_overlay_2`, `cilium_calls_wireguard*`, `cilium_calls_xdp*`, `cilium_events`, `cilium_signals`).
- Files: `/proc/sys/net/core/bpf_jit_enable`, `/proc/kallsyms`, `/proc/buddyinfo`, `/proc/pagetypeinfo`, `/etc/resolv.conf`, `/var/log/{docker,daemon}.log`, `/var/log/messages`, `/var/run/cilium/cilium-cni.log`, `/proc/sys/kernel/random/boot_id`; kernel config (`/proc/config(.gz)`, `/boot/config-$(uname -r)`); `cp -r /var/run/cilium/state` (all `ep_config.*`).
- cilium-dbg: `debuginfo --output=markdown,json -f`, `metrics list`, `shell -- metrics/html`, `shell -- health/history`, `bpf metrics list`, `fqdn cache list`, `config -a`, `encrypt status`, `endpoint list [-o json]`, `bpf auth/bandwidth/config list`, `bpf lb list` (+`--revnat/--frontends/--backends/--source-ranges`), `bpf lb maglev list`, `bpf egress/vtep/endpoint list`, `bpf ct list --time-diff`, `bpf nat list`, `bpf nat retries list`, `bpf ipmasq list`, `bpf ipcache list`, `bpf policy get --all --numeric`, `bpf sha list`, `bpf fs show`, `bpf recorder list`, `ip list -n -o json`, `map list --verbose`, `map events cilium_ipcache/cilium_lxc -o json`, `service list [-o json]`, `recorder list`, `status --verbose`, `identity list`, `policy get`, `policy selectors -o json`, `node list [-o json]`, `bpf nodeid list`, `lrp list`, `cgroups list -o json`, `statedb`, `shell -- bgp/peers [-f detailed]`, `shell -- bgp/routes -a {in,loc,out} ipv{4,6} unicast`, `shell -- bgp/route-policies`, `shell -- policy/mapstate/entries`, `shell -- policy/mapstate/topk`, `troubleshoot kvstore`, `troubleshoot clustermesh`, `bpf frag list`.
- cilium-health: `status --verbose`, `status -o json`.
- Optional: Envoy admin `config_dump?include_eds`, `listeners`, `clusters`, `server_info` (secret-masked), pprof traces.

For flowsdn observability this list is the minimum: every `cilium-dbg` command above that
is REST-backed implies a route; `cp -r state` implies the state-dir layout; the BPF map
names imply area 02's pin names.
