# Registry specification gaps

The catalogue records all 539 declarations from foundation specification §6.4.
488 defaults resolve directly from explicit literals or simple numeric/duration
expressions; 33 more resolve from explicit owning-spec declarations. The remaining
18 defaults below require specification clarification or an explicit default
override with provenance. No referenced implementation
was consulted to fill these gaps.

The table does not provide help text or hidden-flag metadata for any key.
The four `Var` options additionally require their owning area validators.
A complete typed registry is therefore not a production-readiness guarantee.

Runtime/dynamic keys retain their classification; neither is made hot-reloadable
by schema registration. Deprecated key aliases and the four inventory-name
renames are separate interfaces; inventory identifiers are not extra input aliases.

| Key | Type | Unresolved expression |
|---|---|---|
| `derive-masq-ip-addr-from-device` | String | `masqInterface` |
| `enable-gops` | Bool | `def.EnableGops` |
| `enable-policy-secrets-sync` | Bool | `mc.EnablePolicySecretsSync` |
| `envoy-secrets-namespace` | String | `r.EnvoySecretsNamespace` |
| `gops-port` | Uint16 | `def.GopsPort` |
| `ipv6-cluster-alloc-cidr` | String | `IPv6ClusterAllocCIDRBase + "/64"` |
| `lb-test-fault-probability` | Float32 | `def.TestFaultProbability` |
| `levels` | StringSlice | `[]string{types.LevelOK, types.LevelDegraded, types.LevelStopped}` |
| `local-max-addr-scope` | String | `fmt.Sprintf("%d", defaults.AddressScopeMax)` |
| `log-opt` | Var | `option.NewMapOptions(&option.Config.LogOpt)` |
| `metrics` | StringSlice | `metrics` |
| `monitor-aggregation` | String | `None` |
| `packetization-layer-pmtud-mode` | String | `plpmtudModeBlackhole.String()` |
| `pprof` | Bool | `def.Pprof` |
| `pprof-address` | String | `def.PprofAddress` |
| `pprof-block-profile-rate` | Int | `def.PprofBlockProfileRate` |
| `pprof-mutex-profile-fraction` | Int | `def.PprofMutexProfileFraction` |
| `pprof-port` | Uint16 | `def.PprofPort` |

## Owning-spec resolutions

The exact foundation-table expressions remain intact in Rust metadata.
`Definition::default_provenance()` identifies the declaration used to resolve
each parser input. Empty list/map values use an empty parser string. Numeric
NAT and neighbour defaults are fixed defaults, not dynamic sizing calculations.

| Key | Resolved parser input | Owning declaration |
|---|---|---|
| `agent-not-ready-taint-key` | `node.cilium.io/agent-not-ready` | [spec 12, line 1415](../../docs/spec/12-operator.md#L1415) |
| `bpf-lb-algorithm` | `random` | [spec 05, line 926](../../docs/spec/05-service-loadbalancing.md#L926) |
| `bpf-lb-dsr-dispatch` | `opt` | [spec 05, line 925](../../docs/spec/05-service-loadbalancing.md#L925) |
| `bpf-lb-maglev-hash-seed` | `JLfvgnHc2kaSUFaI` | [spec 05, line 929](../../docs/spec/05-service-loadbalancing.md#L929) |
| `bpf-lb-maglev-table-size` | `16381` | [spec 05, line 928](../../docs/spec/05-service-loadbalancing.md#L928) |
| `bpf-lb-map-max` | `65536` | [spec 05, line 917](../../docs/spec/05-service-loadbalancing.md#L917) |
| `bpf-lb-mode` | `snat` | [spec 05, line 923](../../docs/spec/05-service-loadbalancing.md#L923) |
| `bpf-map-event-buffers` | `(empty)` | [spec 03, line 851](../../docs/spec/03-identity-ipcache.md#L851) |
| `bpf-nat-global-max` | `524288` | [spec 04, line 804](../../docs/spec/04-conntrack-nat.md#L804) |
| `bpf-neigh-global-max` | `524288` | [spec 01, line 193](../../docs/spec/01-bpf-map-abi-loader.md#L193) |
| `bpf-node-map-max` | `16384` | [spec 14, line 1715](../../docs/spec/14-encryption-egress.md#L1715) |
| `clustermesh-service-v2` | `prefer-legacy` | [spec 20, line 1548](../../docs/spec/20-clustermesh-kvstore.md#L1548) |
| `enable-bandwidth-manager` | `false` | [spec 10, line 1381](../../docs/spec/10-node-routing-nftables.md#L1381) |
| `enable-bbr` | `false` | [spec 10, line 1382](../../docs/spec/10-node-routing-nftables.md#L1382) |
| `enable-bbr-hostns-only` | `false` | [spec 10, line 1382](../../docs/spec/10-node-routing-nftables.md#L1382) |
| `enable-dynamic-source-lookup-nodeport` | `false` | [spec 05, line 940](../../docs/spec/05-service-loadbalancing.md#L940) |
| `enable-node-ipam` | `false` | [spec 12, line 1452](../../docs/spec/12-operator.md#L1452) |
| `fixed-identity-mapping` | `(empty)` | [spec 03, line 836](../../docs/spec/03-identity-ipcache.md#L836) |
| `gateway-api-secrets-namespace` | `cilium-secrets` | [spec 21, line 1697](../../docs/spec/21-gateway-api-ingress.md#L1697) |
| `hubble-drop-events-reasons` | `auth_required,policy_denied` | [spec 11, line 2523](../../docs/spec/11-hubble-monitor.md#L2523) |
| `hubble-event-buffer-capacity` | `4095` | [spec 11, line 2474](../../docs/spec/11-hubble-monitor.md#L2474) |
| `hubble-lost-event-send-interval` | `1s` | [spec 11, line 2477](../../docs/spec/11-hubble-monitor.md#L2477) |
| `hubble-socket-path` | `/var/run/cilium/hubble.sock` | [spec 11, line 2472](../../docs/spec/11-hubble-monitor.md#L2472) |
| `hubble-tls-cert-file` | `(empty)` | [spec 11, line 2480](../../docs/spec/11-hubble-monitor.md#L2480) |
| `hubble-tls-client-ca-files` | `(empty)` | [spec 11, line 2482](../../docs/spec/11-hubble-monitor.md#L2482) |
| `hubble-tls-key-file` | `(empty)` | [spec 11, line 2481](../../docs/spec/11-hubble-monitor.md#L2481) |
| `ingress-secrets-namespace` | `cilium-secrets` | [spec 21, line 1714](../../docs/spec/21-gateway-api-ingress.md#L1714) |
| `ipam-multi-pool-pre-allocation` | `default=8` | [spec 07, line 1247](../../docs/spec/07-ipam.md#L1247) |
| `kvstore` | `(empty)` | [spec 20, line 1507](../../docs/spec/20-clustermesh-kvstore.md#L1507) |
| `node-port-range` | `30000,32767` | [spec 05, line 919](../../docs/spec/05-service-loadbalancing.md#L919) |
| `policy-secrets-namespace` | `cilium-secrets` | [spec 12, line 1449](../../docs/spec/12-operator.md#L1449) |
| `policy-secrets-only-from-secrets-namespace` | `false` | [spec 16, line 1479](../../docs/spec/16-l7-envoy-dns.md#L1479) |
| `socket-path` | `/var/run/cilium/cilium.sock` | [spec 08, line 1319](../../docs/spec/08-endpoint-agent-api.md#L1319) |

## Conflicting or inapplicable declarations

- `monitor-aggregation`: specs 01 line 1018 and 04 line 816 specify `medium`,
  while spec 11 line 2456 specifies `none`. No default is selected.
- `lb-test-fault-probability`: spec 05 line 958 specifies `0`, while spec 17
  line 1299 specifies `0.1` for the LB script area. It remains unresolved
  until that contextual distinction is represented explicitly.
- `enable-policy-secrets-sync`: spec 16 §3.5.4 calls `true` the documented
  default for new clusters; its line 1477 and spec 12 line 1448 say `false`.
- `local-max-addr-scope`: spec 10 line 1362 gives `252`, but its open decision
  at lines 2000–2004 still requires the numeric default to be resolved.
- `packetization-layer-pmtud-mode`: the empty CNI default in spec 09 line 911
  is a different configuration surface from the agent's symbolic blackhole mode.
- `log-opt`: spec 12 line 1359 gives an empty map for the operator; this does
  not independently establish the agent's default.

Resolving empty defaults for `fixed-identity-mapping` and
`bpf-map-event-buffers`, or the `default=8` IPAM preallocation default, does
not implement their area validators. All four Var validators remain required.
