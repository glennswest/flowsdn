# Registry specification gaps

The catalogue records all 539 declarations from foundation specification §6.4.
488 defaults resolve directly from explicit literals or simple numeric/duration
expressions. The remaining 51 defaults below require an owning specification
or an explicit default override with provenance. No referenced implementation
was consulted to fill these gaps.

The table does not provide help text or hidden-flag metadata for any key.
The four `Var` options additionally require their owning area validators.
A complete typed registry is therefore not a production-readiness guarantee.

Runtime/dynamic keys retain their classification; neither is made hot-reloadable
by schema registration. Deprecated key aliases and the four inventory-name
renames are separate interfaces; inventory identifiers are not extra input aliases.

| Key | Type | Unresolved expression |
|---|---|---|
| `agent-not-ready-taint-key` | String | `"node." + CiliumK8sAnnotationPrefix + "agent-not-ready"` |
| `bpf-lb-algorithm` | String | `LBAlgorithmRandom` |
| `bpf-lb-dsr-dispatch` | String | `DSRDispatchOption` |
| `bpf-lb-maglev-hash-seed` | String | `userCfg.HashSeed` |
| `bpf-lb-maglev-table-size` | Uint | `userCfg.TableSize` |
| `bpf-lb-map-max` | Int | `DefaultLBMapMaxEntries` |
| `bpf-lb-mode` | String | `LBModeSNAT` |
| `bpf-map-event-buffers` | Var | `option.NewMapOptions(&option.Config.BPFMapEventBuffers, option.Config.BPFMapEventBuffersValidator)` |
| `bpf-nat-global-max` | Int | `int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)` |
| `bpf-neigh-global-max` | Int | `int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)` |
| `bpf-node-map-max` | Uint32 | `DefaultMaxEntries` |
| `clustermesh-service-v2` | String | `c.ServiceModeV2.String()` |
| `derive-masq-ip-addr-from-device` | String | `masqInterface` |
| `enable-bandwidth-manager` | Bool | `def.EnableBandwidthManager` |
| `enable-bbr` | Bool | `def.EnableBBR` |
| `enable-bbr-hostns-only` | Bool | `def.EnableBBRHostnsOnly` |
| `enable-dynamic-source-lookup-nodeport` | Bool | `def.NodePortEnableDynamicSourceLookup` |
| `enable-gops` | Bool | `def.EnableGops` |
| `enable-node-ipam` | Bool | `r.EnableNodeIPAM` |
| `enable-policy-secrets-sync` | Bool | `mc.EnablePolicySecretsSync` |
| `envoy-secrets-namespace` | String | `r.EnvoySecretsNamespace` |
| `fixed-identity-mapping` | Var | `option.NewMapOptions(&option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator)` |
| `gateway-api-secrets-namespace` | String | `r.GatewayAPISecretsNamespace` |
| `gops-port` | Uint16 | `def.GopsPort` |
| `hubble-drop-events-reasons` | StringSlice | `def.K8sDropEventsReasons` |
| `hubble-event-buffer-capacity` | Int | `observeroption.Default.MaxFlows.AsInt()` |
| `hubble-lost-event-send-interval` | Duration | `hubbleDefaults.LostEventSendInterval` |
| `hubble-socket-path` | String | `hubbleDefaults.SocketPath` |
| `hubble-tls-cert-file` | String | `cfg.TLSCertFile` |
| `hubble-tls-client-ca-files` | StringSlice | `cfg.TLSClientCAFiles` |
| `hubble-tls-key-file` | String | `cfg.TLSKeyFile` |
| `ingress-secrets-namespace` | String | `r.IngressSecretsNamespace` |
| `ipam-multi-pool-pre-allocation` | Var | `option.NewMapOptions(&option.Config.IPAMMultiPoolPreAllocation)` |
| `ipv6-cluster-alloc-cidr` | String | `IPv6ClusterAllocCIDRBase + "/64"` |
| `kvstore` | String | `defaultBackend` |
| `lb-test-fault-probability` | Float32 | `def.TestFaultProbability` |
| `levels` | StringSlice | `[]string{types.LevelOK, types.LevelDegraded, types.LevelStopped}` |
| `local-max-addr-scope` | String | `fmt.Sprintf("%d", defaults.AddressScopeMax)` |
| `log-opt` | Var | `option.NewMapOptions(&option.Config.LogOpt)` |
| `metrics` | StringSlice | `metrics` |
| `monitor-aggregation` | String | `None` |
| `node-port-range` | StringSlice | `[]string{fmt.Sprintf("%d", NodePortMinDefault), fmt.Sprintf("%d", NodePortMaxDefault)}` |
| `packetization-layer-pmtud-mode` | String | `plpmtudModeBlackhole.String()` |
| `policy-secrets-namespace` | String | `mc.PolicySecretsNamespace` |
| `policy-secrets-only-from-secrets-namespace` | Bool | `mc.PolicySecretsOnlyFromSecretsNamespace` |
| `pprof` | Bool | `def.Pprof` |
| `pprof-address` | String | `def.PprofAddress` |
| `pprof-block-profile-rate` | Int | `def.PprofBlockProfileRate` |
| `pprof-mutex-profile-fraction` | Int | `def.PprofMutexProfileFraction` |
| `pprof-port` | Uint16 | `def.PprofPort` |
| `socket-path` | String | `RuntimePath + "/cilium.sock"` |
