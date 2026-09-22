# Layer 7: Envoy integration, DNS proxy / FQDN policy, mutual auth, service mesh — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/envoy/**`,
`pkg/proxy/**`, `pkg/ciliumenvoyconfig/**`, `pkg/xds/**`, `pkg/fqdn/**`,
`standalone-dns-proxy/**`, `pkg/auth/**`, `pkg/ztunnel/**`,
`pkg/k8s/apis/cilium.io/v2/{cec,ccec}_types.go`,
`vendor/github.com/cilium/proxy/go/cilium/api/*.pb.go`,
`api/v1/standalone-dns-proxy/standalone-dns-proxy.proto`,
`bpf/lib/proxy.h`, `bpf/lib/auth.h`, `bpf/lib/signal.h`,
`Documentation/security/`, `Documentation/network/servicemesh/`.

Line counts are `wc -l` over `*.go` excluding `*_test.go` unless noted.

## Purpose

This area is everything in the agent that sits above L4 and needs a user-space
proxy or a user-space handshake. Four sub-systems share one mechanism (the
policy map's `proxy_port` field plus the `MARK_MAGIC_TO_PROXY` skb mark and
TPROXY / `bpf_sk_assign` redirection to a localhost listener) and one
abstraction (`pkg/proxy.Redirect`):

1. **Envoy integration** (`pkg/envoy`, `pkg/proxy`, `pkg/ciliumenvoyconfig`):
   the agent runs (or attaches to) a `cilium-envoy` process, feeds it over a
   unix-socket xDS gRPC server (LDS/RDS/CDS/EDS/SDS plus the Cilium-specific
   NPDS `cilium.NetworkPolicy` and NPHDS `cilium.NetworkPolicyHosts` types),
   and receives L7 access logs back over a second unix socket. It enforces HTTP
   L7 policy, TLS interception, and serves Ingress / Gateway API /
   `CiliumEnvoyConfig` L7 load balancing.
2. **DNS proxy and `toFQDNs` policy** (`pkg/fqdn`, `standalone-dns-proxy`): a
   transparent DNS proxy written in Go (miekg/dns) that enforces L7 DNS rules
   (`matchName` / `matchPattern`), records the answers into a per-endpoint DNS
   cache, and turns resolved IPs into ipcache entries carrying `fqdn:` labels
   so `toFQDNs` selectors resolve to identities. A new out-of-process
   "standalone DNS proxy" (SDP) speaks a gRPC protocol to the agent so DNS
   keeps working through agent restarts.
3. **Mutual authentication** (`pkg/auth`): datapath signals
   `SIGNAL_AUTH_REQUIRED` when a policy entry demands `authentication.mode:
   required`; the agent performs a TLS 1.3 handshake with the *remote node's
   agent* using SPIFFE SVIDs from a SPIRE agent, then writes an expiry into
   `cilium_auth_map`. Deprecated as of v1.20 (issue #47132).
4. **Istio ambient / ztunnel** (`pkg/ztunnel`): Cilium acts as the ztunnel
   control plane — it enrolls pods into the node-local ztunnel via the ZDS unix
   socket (passing the pod netns fd with `SCM_RIGHTS`), installs Istio's
   in-pod iptables rules inside the pod netns, serves an Istio workload-xDS
   (delta ADS) and an Istio CA (`IstioCertificateService`) on
   `127.0.0.1:15012`. Selected by `encryption.type=ztunnel`, beta.

Notable v1.20 facts that change the scope for flowsdn: **Kafka L7 rules and
the generic proxylib `l7proto` rules are gone from the policy API**
(`api.L7Rules` has only `HTTP` and `DNS`; there is no `kafka` word left in
`pkg/policy` or `pkg/envoy`), the L7 visibility annotation
(`policy.cilium.io/proxy-visibility`) is gone, and mutual auth is deprecated.
The Envoy side of the contract still carries `KafkaRules`/`L7Rules` messages,
but the agent never populates them.

## Components

| Path | Lines | Purpose |
|---|---|---|
| `pkg/envoy/xds_server.go` | 1291 | Legacy "split" xDS server: one gRPC service per type, `AddListener`/`UpdateNetworkPolicy`/`UpsertEnvoyResources`. |
| `pkg/envoy/xds_server_ads.go` | 1340 | ADS server on go-control-plane snapshot cache (`envoy-xds-mode=ads|strict-ads`); same `XDSServer` interface, snapshot diff/revert on NACK. |
| `pkg/envoy/xds_server_ondemand.go` | 124 | `onDemandXdsStarter`: starts embedded Envoy on first listener/resource when `external-envoy-proxy=false`. |
| `pkg/envoy/model.go` | 1153 | Builds Envoy protos: listener addresses, `cilium.bpf_metadata` filter, HTTP/TCP filter chains, and the full `cilium.NetworkPolicy` from `policy.L4Policy` (precedence, wildcards, TLS, SNI). |
| `pkg/envoy/resources.go` | 301 | Type URL constants; NPHDS cache upsert/delete from ipcache events. |
| `pkg/envoy/standalone_envoy.go` | 645 | Writes `bootstrap.pb`, execs `cilium-envoy-starter`/`cilium-envoy`, restarts on crash, pipes Envoy logs into slog. |
| `pkg/envoy/accesslog_server.go` + `accesslog.go` | 327 | Unix-datagram access log server (`access_log.sock`), `cilium.LogEntry` → `accesslog.LogRecord`. |
| `pkg/envoy/envoyadminclient.go` | 141 | HTTP over `admin.sock`: log level, `/quitquitquit`, `/server_info` version. |
| `pkg/envoy/secretsync.go` | 256 | k8s `Secret` → Envoy SDS `Secret` (tls cert, CA validation ctx, session ticket keys). |
| `pkg/envoy/cell.go`, `config/config.go` | 497 | Hive wiring, all `envoy-*`/`proxy-*`/`http-*` flags. |
| `pkg/envoy/grpc.go`, `grpcnew.go` | 299 | gRPC service registrations (split: 7 services; ADS: `AggregatedDiscoveryService`). |
| `pkg/envoy/nphds_adapter.go`, `locality.go`, `localendpointstore.go`, `artifact_copier.go`, `versioncheck.go`, `utils.go` | 641 | ipcache→NPHDS, zone-aware locality bootstrap, policy-name→endpoint map for access log correlation, copying `/usr/bin/cilium-envoy*` artifacts to hostPath, Envoy version check. |
| `pkg/envoy/policy/` | 596 | `EnvoyL7RulesTranslator` (HTTP rule → `HeaderMatcher`/`HeaderMatch`), deterministic sorting of NPDS protos. |
| `pkg/envoy/xds/` | 2093 | Generic xDS engine (split mode): `Cache`, `AckingResourceMutatorWrapper` (ACK/NACK completions), `Server.HandleRequestStream`, `ResourceWatcher`. |
| `pkg/envoy/xdsnew/` | 1772 | ADS engine: `ciliumSnapshot` over go-control-plane `cache`, `CompletionCallbacks` (per node/type version ordering), JSON serializer for restore. |
| `pkg/envoy/resource/envoy.go` | 288 | Blank imports registering ~150 Envoy extension protos so CEC `Any` payloads unmarshal. |
| `pkg/proxy/proxy.go`, `redirect.go`, `envoyproxy.go`, `dns.go`, `crd.go`, `types/` | 705 | `Proxy` abstraction: `CreateOrUpdateRedirect`, `RemoveRedirect`; redirect implementations for `http`, `tls`, `dns`, `crd`. |
| `pkg/proxy/proxyports/` | 803 | Proxy port allocation in `[proxy-portrange-min, max]`, static names, `/proc/net/*` collision check, `proxy_ports_state.json` restore. |
| `pkg/proxy/routes.go` | 375 | ip rules/routes for to-proxy (table 2004) and from-proxy (table 2005). |
| `pkg/proxy/accesslog/` | 700 | `LogRecord` (HTTP/DNS/L7), `ProxyAccessLogger`, monitor notifier (`MessageTypeAccessLog`). |
| `pkg/proxy/cell.go`, `endpoint/` | 195 | Hive wiring, `EndpointUpdater`/`EndpointInfoSource` interfaces the proxies need from endpoints. |
| `pkg/ciliumenvoyconfig/` | 2829 | CEC/CCEC reflector → statedb tables → `CECResourceParser` (qualify names, inject Cilium filters, allocate ports) → reconciler pushing `xds.Resources`; L7 LB `ProxyRedirect` into the service table. |
| `pkg/k8s/apis/cilium.io/v2/cec_types.go`, `ccec_types.go` | ~250 | `CiliumEnvoyConfig`, `CiliumClusterwideEnvoyConfig` CRDs. |
| `pkg/xds/experimental/client/` | 982 | An xDS *client* (SOTW + delta) used by experimental features; not part of the Envoy path. |
| `pkg/fqdn/dnsproxy/` | 2379 | `DNSProxy`: miekg/dns servers (UDP+TCP, v4+v6), `IP_TRANSPARENT`/`IP_RECVORIGDSTADDR` session factory, per-endpoint allow regex tables, restored rules, `SharedClients` upstream pooling, `SO_MARK` on upstream sockets. |
| `pkg/fqdn/cache.go` | 1338 | `DNSCache` (name→IPs with TTL, reverse index, per-host limit), `DNSZombieMappings` (IPs kept alive by CT). |
| `pkg/fqdn/namemanager/` | 1393 | `NameManager`: FQDN selectors → regex → names → IPs → ipcache metadata (`fqdn:` labels), GC, identity preallocation, REST `fqdn/cache` API. |
| `pkg/fqdn/service/` | 1009 | `FQDNData` gRPC server for the standalone DNS proxy. |
| `pkg/fqdn/messagehandler/` | 379 | `NotifyOnDNSMsg`: metrics, access log, `UpdateGenerateDNS`, waits for ipcache/policy before releasing the response. |
| `pkg/fqdn/restore/`, `matchpattern/`, `re/`, `bootstrap/`, `rules/`, `lookup/`, `dns/`, `proxy/`, `cell/` | 1135 | Restore format for DNS rules, `matchPattern` → regex, regex LRU, bootstrap ordering with endpoint restore, endpoint lookup adaptors. |
| `standalone-dns-proxy/` | 1726 | Separate binary: gRPC client to agent, statedb tables mirroring rules/identities, reuses `pkg/fqdn/dnsproxy`. |
| `api/v1/standalone-dns-proxy/standalone-dns-proxy.proto` | 148 | `FQDNData` service definition. |
| `pkg/auth/` | 2164 | `AuthManager`, `mutualAuthHandler` (TLS 1.3 over TCP to peer agent), auth map cache/writer/GC, SPIRE delegate client, SPIFFE ↔ identity mapping. |
| `pkg/maps/authmap/` | ~200 | `cilium_auth_map` Go binding. |
| `pkg/ztunnel/` | 6222 (≈3200 generated `pb/`) | ZDS server, in-pod iptables, namespace enrollment reconciler, Istio workload xDS, Istio CA. |
| `bpf/lib/proxy.h` | ~410 | `ctx_redirect_to_proxy*`, TPROXY via `sk_lookup_*` + `sk_assign`. |
| `bpf/lib/auth.h`, `bpf/lib/signal.h` | ~120 | `auth_lookup`, `SIGNAL_AUTH_REQUIRED`. |

Totals (non-test): pkg/envoy 11,854; pkg/proxy 2,749; pkg/ciliumenvoyconfig
2,829; pkg/xds 982; pkg/fqdn 7,633; standalone-dns-proxy 1,726; pkg/auth
2,164; pkg/ztunnel 6,222 — **≈36,200 lines of Go**, plus ≈31,300 lines of
tests. Downstream consumers not counted here: `operator/pkg/model` (8,082),
`operator/pkg/gateway-api` (10,886), `operator/pkg/ingress` (1,453) generate
CECs; `pkg/hubble/parser/seven` decodes access logs.

## Features

### Envoy / L7 policy

- **HTTP L7 policy** — `PortRule.rules.http[]` with `path`, `method`, `host`
  (all anchored regexes → Envoy `HeaderMatcher{SafeRegex}` on `:path`,
  `:method`, `:authority`), `headers[]` (`"Name: value"` → exact match;
  `"Name"` → present match), `headerMatches[]` (`name`, `value` or
  `secret{namespace,name}`, `mismatch: LOG|ADD|DELETE|REPLACE`) → Cilium
  `HeaderMatch` with `MismatchAction`. Requires `--enable-l7-proxy` (Helm
  `l7Proxy: true`, default). Denied requests get HTTP 403 with body
  `--http-403-msg` ("Access denied").
- **gRPC policy** — no separate parser; documented as HTTP rules on `:path`
  `/<pkg.Service>/<Method>` with HTTP/2 (`Documentation/security/grpc.rst`).
- **Kafka / generic proxylib L7** — *removed* in v1.20 (no `kafka` or
  `l7proto` in `api.L7Rules`). flowsdn does not need them.
- **TLS interception / visibility** — `PortRule.terminatingTLS` and
  `originatingTLS` (`TLSContext{secret, trustedCA, certificate, privateKey}`)
  plus `serverNames[]` (SNI allow-list) → NPDS `PortNetworkPolicyRule.
  {DownstreamTlsContext, UpstreamTlsContext, ServerNames}`. Three secret
  modes: SDS (default new clusters, `--enable-policy-secrets-sync`, secrets
  mirrored to `--policy-secrets-namespace` and referenced by
  `TlsSdsSecret`/`ValidationContextSdsSecret`), read-all-secrets, or
  `--policy-secrets-only-from-secrets-namespace` inline
  (`--use-full-tls-context` retains old buggy `ca.crt` inlining, deprecated).
  Envoy listener gets a `cilium.tls_wrapper` transport socket on a
  `transport_protocol: tls` filter chain, plus `tls_inspector`.
- **Per-port precedence / deny / pass semantics** — NPDS rules carry
  `Precedence` and `verdict{PassPrecedence|Deny}`; wildcard-port rules are
  emitted as a `PortNetworkPolicy{Port:0}` and prune lower-precedence
  per-port rules (`model.go:414-734`). Policy tiers are honored.
- **Embedded vs external Envoy** — `--external-envoy-proxy=false`: agent
  execs `cilium-envoy-starter -l <lvl> -c bootstrap.pb --base-id N
  --log-format ...`, restarts on crash. `true` (Helm `envoy.enabled: true`,
  the default DaemonSet mode): Envoy runs in a separate `cilium-envoy`
  DaemonSet sharing the hostPath sockets dir; the agent only serves xDS.
  `ArtifactCopier` copies `cilium-envoy` binaries for the external DS.
- **xDS modes** — `--envoy-xds-mode=split|ads|strict-ads` (default `split`).
  Split registers LDS, RDS, CDS, EDS, SDS, NPDS, NPHDS as separate gRPC
  services; ADS registers `AggregatedDiscoveryService` on a go-control-plane
  snapshot cache and Envoy's bootstrap uses ADS config source.
- **Envoy admin and metrics** — `--proxy-admin-port` adds an Envoy listener
  on an internal address proxying to the admin unix socket; `--proxy-
  prometheus-port` adds `envoy-prometheus-metrics-listener` routing to
  `/stats/prometheus`. Both guarded by `InternalAddressConfig` CIDRs
  (RFC1918 + loopback).
- **Access logs to Hubble** — `--envoy-access-log-enabled` (default true);
  `cilium.LogEntry` protobufs arrive on `access_log.sock`; converted to
  `accesslog.LogRecord`, sent via monitor agent as `MessageTypeAccessLog`,
  decoded by `pkg/hubble/parser/seven` into `flow.Layer7{Http|Dns}`.
- **Tunables** — `proxy-connect-timeout` (2s), `proxy-initial-fetch-timeout`
  (30s), `proxy-gid` (1337), `proxy-max-active-downstream-connections`
  (50000, via overload manager), `proxy-max-requests-per-connection`,
  `proxy-max-connection-duration-seconds`, `proxy-idle-timeout-seconds`
  (60), `proxy-max-concurrent-retries` (128), `proxy-cluster-max-
  {connections,requests,pending-requests}` (1024), `http-normalize-path`
  (true: RFC3986 normalize, merge slashes, unescape+redirect),
  `http-request-timeout` (3600s), `http-idle-timeout` (0), `http-max-grpc-
  timeout` (0), `http-retry-count` (3, on 5xx), `http-retry-timeout`,
  `http-stream-idle-timeout` (300s), `proxy-xff-num-trusted-hops-{ingress,
  egress}`, `envoy-policy-restore-timeout` (3m), `envoy-http-upstream-
  linger-timeout` (-1), `envoy-log`, `envoy-default-log-level`, `envoy-base-
  id`, `envoy-keep-cap-netbindservice`, `envoy-node-locality-enabled`,
  `envoy-access-log-buffer-size` (reference 4096; flowsdn 16384 per spec 16 #199), `disable-envoy-version-check`,
  `proxy-use-original-source-address` (bpf_metadata `use_original_source_
  address` for policy listeners), `proxy-portrange-min/max` (10000-20000),
  `restored-proxy-ports-age-limit` (15m), `enable-bpf-tproxy` (default false:
  use mark+ip rule instead of `bpf_sk_assign`).
- **CiliumEnvoyConfig / CiliumClusterwideEnvoyConfig** — `--enable-envoy-
  config` (Helm `envoyConfig.enabled`). Raw Envoy resources plus `services[]`
  (L7 LB: the named Service's traffic is redirected to a CEC listener),
  `backendServices[]` (EDS populated from Cilium's service/backend table),
  `nodeSelector`. Timeouts `envoy-config-timeout` (2m), `envoy-config-retry-
  interval` (15s). Annotations `cec.cilium.io/inject-cilium-filters`,
  `cec.cilium.io/use-original-source-address`, `cec.cilium.io/is-l7lb`.
- **Ingress / Gateway API** — operator translates Ingress/Gateway objects
  into CECs (`operator/pkg/model/translation/cec_translator.go`); the agent
  path is identical to user CECs. Agent flags `enable-ingress-controller`,
  `enable-gateway-api`, `ingress-secrets-namespace`, `gateway-api-secrets-
  namespace`, `envoy-secrets-namespace` control which namespaces the
  `secretSyncer` mirrors into SDS.

### DNS proxy / toFQDNs

- **L7 DNS rules** — `rules.dns[]{matchName|matchPattern}` on egress port
  rules; the datapath redirects matching flows to the `cilium-dns-egress`
  proxy port; the proxy allows/rejects by regex per (endpoint, dst port/proto,
  selector). Reject reply configurable: `--tofqdns-dns-reject-response-code=
  refused|nameError` (default REFUSED).
- **`toFQDNs` L3 selectors** — `matchName` (exact, lower-cased, FQDN-ified)
  and `matchPattern` (`*` = `[-a-zA-Z0-9_]*`, `**.` at the prefix = any
  number of subdomains). Resolved IPs are inserted into ipcache with
  `fqdn:<name>` labels; identities are allocated as CIDR-style local
  identities (`--tofqdns-preallocate-identities`, default true, allocates
  identities for the selector before any lookup to cut response latency).
- **DNS cache** — `--tofqdns-min-ttl` (0), `--tofqdns-endpoint-max-ip-per-
  hostname` (1000), `--tofqdns-max-deferred-connection-deletes` (10000
  zombies kept alive while CT sees the connection), `--tofqdns-idle-
  connection-grace-period` (0s), `--tofqdns-proxy-response-max-delay` (100ms:
  response is held until ipcache/policy is updated, then released),
  `--tofqdns-pre-cache` (deprecated, removed v1.21), `--tofqdns-proxy-port`
  (0 = OS-assigned; must be fixed for SDP), `--fqdn-regex-compile-lru-size`,
  `--dns-policy-unload-on-shutdown`.
- **Proxy internals** — `--dnsproxy-concurrency-limit` (semaphore),
  `--dnsproxy-concurrency-processing-grace-period`, `--dnsproxy-lock-count`
  (131 name mutexes) / `--dnsproxy-lock-timeout` (500ms), `--dnsproxy-socket-
  linger-timeout` (10s), `--dnsproxy-enable-transparent-mode` (default false
  — upstream socket binds the *pod's* IP with `IP_TRANSPARENT` so the DNS
  server sees the pod as client), `--tofqdns-enable-dns-compression`,
  `--dns-max-ips-per-restored-rule`. DNS over TCP and UDP both supported
  (same L4 protocol is used upstream as downstream); EDNS0 buffer sizes are
  honored for compression/truncation; `SharedClients` multiplexes many
  requests on one upstream socket per (proto, client, server).
- **Restore across restarts** — DNS rules per endpoint are serialized into
  the endpoint's header/state (`restore.DNSRules = map[PortProto]IPRules`
  with `RuleRegex` + IP/CIDR set); `DNSCache` and zombies are JSON in the
  endpoint state; proxy ports in `/run/cilium/state/proxy_ports_state.json`.
- **REST API** — `GET/DELETE /fqdn/cache`, `GET /fqdn/cache/{id}`,
  `GET /fqdn/names` (name manager model).
- **Standalone DNS proxy (alpha)** — `--enable-standalone-dns-proxy`,
  `--standalone-dns-proxy-server-port` (Helm `standaloneDnsProxy.{enabled,
  serverPort}`, requires `dnsProxy.proxyPort != 0`). A second container/binary
  runs the same `dnsproxy.DNSProxy` fed by a gRPC stream of rules and
  identity→IP mappings; keeps resolving cached names while the agent is down
  but cannot allocate identities for new names.

### Mutual authentication (deprecated in v1.20)

- Policy `authentication.mode: disabled|required|test-always-fail` on any
  ingress/egress rule. Datapath `auth_lookup(local_id, remote_id,
  remote_node_id, auth_type)` in `cilium_auth_map`; miss/expired →
  `DROP_POLICY_AUTH_REQUIRED` + `SIGNAL_AUTH_REQUIRED` perf event carrying
  `auth_key`. Flags `mesh-auth-enabled` (deprecated), `mesh-auth-queue-size`
  (1024), `mesh-auth-gc-interval` (5m), `mesh-auth-signal-backoff-duration`
  (hidden), `mesh-auth-mutual-listener-port` (Helm 4250), `mesh-auth-mutual-
  connect-timeout` (5s), `mesh-auth-spire-admin-socket`, `mesh-auth-spiffe-
  trust-domain` (`spiffe.cilium`), `mesh-auth-rotated-identities-queue-size`.
  Helm `authentication.mutual.spire.*` optionally installs SPIRE.

### Istio ambient / ztunnel (beta)

- `--enable-ztunnel` (Helm `encryption.type: ztunnel`, `encryption.ztunnel.
  ca.type: internal`, image `quay.io/cilium/ztunnel:v1.0.0` as DaemonSet
  `ztunnel-cilium`). Namespaces labelled `io.cilium/mtls-enabled=true` are
  enrolled: every endpoint in them gets Istio in-pod iptables rules and an
  `AddWorkload` over ZDS with its netns fd; ztunnel then terminates/originates
  HBONE mTLS on ports 15008/15001/15006 inside the pod netns. Cilium serves
  workload discovery (`istio.workload.Address`) and issues SPIFFE certs
  (`spiffe://<td>/ns/<ns>/sa/<sa>`, 30-day) from an internal CA.
- Compatibility notes for running *Istio proper* alongside Cilium
  (`Documentation/network/servicemesh/istio.rst`): `bpf-lb-sock-hostns-only=
  true`, `cni-exclusive=false`. No Cilium code involved.

## Data model

### Envoy contract (cilium/proxy protos, `vendor/github.com/cilium/proxy/go/cilium/api`)

Type URLs: `type.googleapis.com/cilium.NetworkPolicy`,
`type.googleapis.com/cilium.NetworkPolicyHosts`,
`type.googleapis.com/cilium.health_check.event_sink.pipe`, plus standard
`envoy.config.listener.v3.Listener`, `route.v3.RouteConfiguration`,
`cluster.v3.Cluster`, `endpoint.v3.ClusterLoadAssignment`,
`transport_sockets.tls.v3.Secret`.

gRPC services (split mode): `/cilium.NetworkPolicyDiscoveryService/
{StreamNetworkPolicies,FetchNetworkPolicies,DeltaNetworkPolicies}`,
`/cilium.NetworkPolicyHostsDiscoveryService/{StreamNetworkPolicyHosts,
FetchNetworkPolicyHosts,DeltaNetworkPolicyHosts}` — request/response are
plain `envoy.service.discovery.v3.DiscoveryRequest/Response`. Delta variants
return unimplemented.

`npds.proto`:

| Message | Fields (number: type) |
|---|---|
| `NetworkPolicy` | 1 `endpoint_ips` repeated string; 2 `endpoint_id` uint64; 3 `ingress_per_port_policies` repeated PortNetworkPolicy; 4 `egress_per_port_policies`. Resource name = decimal endpoint ID. |
| `PortNetworkPolicy` | 1 `port` uint32 (0 = wildcard); 4 `end_port`; 2 `protocol` SocketAddress.Protocol (always TCP today); 3 `rules` repeated PortNetworkPolicyRule (sorted). |
| `PortNetworkPolicyRule` | 10 `precedence` uint32; oneof verdict {1 `pass_precedence` uint32, 8 `deny` bool}; 9 `proxy_id` uint32 (proxy port of the `listener:` named CRD listener); 5 `name`; 7 `remote_policies` repeated uint32 (identities, sorted; empty = any); 3 `downstream_tls_context`; 4 `upstream_tls_context`; 6 `server_names`; 2 `l7_proto`; oneof l7 {100 `http_rules`, 101 `kafka_rules` (unused), 102 `l7_rules` (unused)}. |
| `TLSContext` | 1 `trusted_ca`; 2 `certificate_chain`; 3 `private_key`; 4 `server_names`; 5 `validation_context_sds_secret`; 6 `tls_sds_secret`; 7 `alpn_protocols`. |
| `HttpNetworkPolicyRules` | 1 `http_rules` repeated HttpNetworkPolicyRule (sorted). |
| `HttpNetworkPolicyRule` | 1 `headers` repeated envoy `route.v3.HeaderMatcher`; 2 `header_matches` repeated HeaderMatch. |
| `HeaderMatch` | 1 `name`; 2 `value`; 3 `match_action` {CONTINUE_ON_MATCH=0, FAIL_ON_MATCH, DELETE_ON_MATCH}; 4 `mismatch_action` {FAIL_ON_MISMATCH=0, CONTINUE_ON_MISMATCH, ADD_ON_MISMATCH, DELETE_ON_MISMATCH, REPLACE_ON_MISMATCH}; 5 `value_sds_secret`. |
| `KafkaNetworkPolicyRules/Rule`, `L7NetworkPolicyRules/Rule` | present in proto; never emitted by the v1.20 agent. |
| `NetworkPoliciesConfigDump` | 1 `networkpolicies` (admin config_dump). |

`nphds.proto`: `NetworkPolicyHosts{1 policy uint64 (identity), 2 host_addresses
repeated string CIDRs}`; resource name = identity decimal string. In
production NPHDS is disabled (`BpfMetadata.use_nphds=false`): Envoy reads
identities straight from the pinned `cilium_ipcache` BPF map.

`bpf_metadata.proto` — listener filter `cilium.bpf_metadata`:
`BpfMetadata{1 bpf_root string ("/sys/fs/bpf"), 2 is_ingress, 3
use_original_source_address, 4 is_l7lb, 5 ipv4_source_address, 6
ipv6_source_address, 7 enforce_policy_on_l7lb, 8 proxy_id (=proxy port), 9
policy_update_warning_limit Duration, 10 l7lb_policy_name, 11
original_source_so_linger_time optional uint32, 12 ipcache_name
("cilium_ipcache"), 13 use_nphds, 14 cache_entry_ttl, 15 cache_gc_interval,
16 cilium_config_source ConfigSource}`. This filter is what recovers the
original destination and the source identity: it reads `SO_MARK`
(`MARK_MAGIC_PROXY_{INGRESS,EGRESS}` + identity in the upper 16 bits, or
`MARK_MAGIC_PROXY_EGRESS_EPID` + endpoint id), looks the addresses up in the
ipcache map, and sets the upstream socket options (mark, `IP_TRANSPARENT`
original source) — there is no `SO_ORIGINAL_DST`; TPROXY preserves the
original dst on the accepted socket.

`network_filter.proto` — network filter `cilium.network`:
`NetworkFilter{1 proxylib, 2 proxylib_params, 5 access_log_path}`.
`l7policy.proto` — HTTP filter `cilium.l7policy`: `L7Policy{1
access_log_path, 3 denied_403_body}`. `tls_wrapper.proto` — transport
sockets `cilium.tls_wrapper` with empty `Upstream/DownstreamTlsWrapperContext`
(the actual TLS material comes from NPDS `TLSContext`/SDS). `websocket.proto`
(`WebSocketClient/Server`) and `health_check_sink.proto`
(`HealthCheckEventPipeSink{path}`) exist but the agent does not emit them.

`accesslog.proto` (written by Envoy to `access_log.sock` as one protobuf per
datagram, max `envoy-access-log-buffer-size`):
`LogEntry{1 timestamp uint64 ns, 15 is_ingress, 3 entry_type
{Request=0,Response,Denied}, 4 policy_name, 17 proxy_id, 5 cilium_rule_ref, 6
source_security_id, 16 destination_security_id, 7 source_address, 8
destination_address, oneof l7 {100 http HttpLogEntry, 101 kafka, 102
generic_l7 L7LogEntry}}`. `HttpLogEntry{1 http_protocol {HTTP10,HTTP11,HTTP2},
2 scheme, 3 host, 4 path, 5 method, 6 headers KeyValue[], 7 status, 8
missing_headers, 9 rejected_headers}`. `L7LogEntry{1 proto, 2 fields map}`.

### Envoy bootstrap and listener shape the agent must reproduce

Static clusters in `bootstrap.pb`: `egress-cluster`, `egress-cluster-tls`,
`ingress-cluster`, `ingress-cluster-tls` — all `ORIGINAL_DST` +
`CLUSTER_PROVIDED` LB, `use_downstream_protocol_config` HTTP options (TLS
variants add `auto_sni` and `cilium.tls_wrapper` upstream transport socket);
`xds-grpc-cilium` (STATIC, pipe `xds.sock`, HTTP/2) and `/envoy-admin`
(STATIC, pipe `admin.sock`). Admin on pipe `admin.sock` mode 0660. Bootstrap
extensions: `envoy.bootstrap.internal_listener`; overload manager
`global_downstream_max_connections`. Envoy node id
`host~127.0.0.1~no-id~localdomain`; the split server records ACKs by node IP
`127.0.0.1`.

Policy listener (`getListenerConf`): name `cilium-{http,tls}-{ingress,
egress}` (or CEC listener), address `127.0.0.1:<port>` (+ `[::1]` additional
address), `transparent: true`, `socket_options` deferred to bpf_metadata,
listener filters `envoy.filters.listener.tls_inspector` and
`cilium.bpf_metadata`; filter chains: for HTTP a raw chain and (if TLS) a
`transport_protocol: tls` chain, each `cilium.network` →
`http_connection_manager{stat_prefix "proxy", websocket upgrade,
use_remote_address, skip_xff_append, xff_num_trusted_hops, http filters
[cilium.l7policy, envoy.filters.http.router], inline route config: "*" with
a gRPC route (max_stream_duration.grpc_timeout_header_max) and a default
route to the {egress,ingress}-cluster[-tls], retry_on 5xx}`; for TLS-only
(`ParserTypeTLS`) `cilium.network` → `tcp_proxy` chains matched on
`raw_buffer` / `tls`.

### Proxy port / redirect

`proxyports.ProxyPort{ProxyType http|tls|dns|crd, Ingress bool, ProxyPort
uint16 json:"port", isStatic, configured, rulesPort, nRedirects}`; static
names `cilium-http-egress`, `cilium-http-ingress`, `cilium-tls-egress`,
`cilium-tls-ingress`, `cilium-dns-egress`. Persisted to
`/run/cilium/state/proxy_ports_state.json` and reused on restart (ports
released after `portReuseDelay` 5m; a stale file older than
`restored-proxy-ports-age-limit` is ignored). Allocation picks a random port
in range, avoiding ports open in `/proc/net/{tcp,udp}{,6}`. The datapath sees
only the port: `struct policy_entry.proxy_port` (`__be16`) in the per-endpoint
policy map; `svc.l7_lb_proxy_port` for L7 LB services.

`proxy.Redirect{listener *ProxyPort, dstPort uint16, endpointID uint16,
name}`; `RedirectImplementation{UpdateRules(policy.L7DataMap) revert; Close()}`.
`accesslog.LogRecord` (JSON tags): `Type request|response|sample, Verdict
forwarded|denied|redirected|error, NodeAddressInfo, ObservationPoint
ingress|egress, SourceEndpoint/DestinationEndpoint EndpointInfo{ID, IPv4,
IPv6, Port, Identity, Labels}, IPVersion, TransportProtocol, ServiceInfo,
DropReason, Timestamp, HTTP{Code, Method, URL, Protocol, Headers,
MissingHeaders, RejectedHeaders}, DNS{Query, IPs, TTL, CNAMEs,
ObservationSource, RCode, QTypes, AnswerTypes}, L7{Proto, Fields}`.

### CEC CRDs (`cilium.io/v2`)

`CiliumEnvoyConfig` (namespaced) / `CiliumClusterwideEnvoyConfig` share
`CiliumEnvoyConfigSpec{services []ServiceListener{name, namespace, ports
[]uint16, listener string}, backendServices []Service{name, namespace,
number []string (port names/numbers)}, resources []XDSResource (an
`anypb.Any` — arbitrary Envoy v3 protos, JSON with `@type`), nodeSelector
LabelSelector}`. Parser rules: all listener/route/cluster/secret names are
qualified `<namespace>/<name>/<resource>`; listeners without an explicit
address get `127.0.0.1:<allocated proxy port>` and (unless `internal_listener`)
the `cilium.bpf_metadata` filter (`is_l7lb`, `proxy_id`); `cilium.network`
and `cilium.l7policy` are injected before `tcp_proxy` / before the router
filter when `inject-cilium-filters` (implicit if `services` is non-empty);
upstream `cilium.l7policy` is injected before `upstream_codec` in cluster
`HttpProtocolOptions`; SDS secret configs are pointed at `xds-grpc-cilium`;
circuit breakers default from the `proxy-cluster-max-*` flags. Duplicate
`FilterChainMatch` in one listener is rejected. Statedb tables:
`ciliumenvoyconfigs` (CEC) and `envoy-resources` (EnvoyResource keyed by
origin `cec`/`backendsync` + name; reconciler pushes to Envoy and retries on
port-binding NACK by reallocating ports).

### FQDN

`fqdn.DNSCache` — `forward map[name]ipEntries`, `reverse map[ip]nameEntries`,
`cacheEntry{Name, LookupTime, ExpirationTime, TTL, IPs}`, `perHostLimit`,
`minTTL`. JSON-marshalled into endpoint state. `DNSZombieMappings{Name→
{IP, Names, AliveAt, DeletePendingAt}, max, perHostLimit}` keeps
"expired but connection still in CT" IPs. `restore.DNSRules map[PortProto
uint32 (port<<16|proto)] []IPRule{Re RuleRegex, IPs map[RuleIPOrCIDR]struct{}}`.
`matchpattern` translation: lower-case, trim trailing dot handling
(`dns.FQDN`), `.`→`[.]`, `**.`→`([-a-zA-Z0-9_]+([.][-a-zA-Z0-9_]+){0,})[.]`,
`*`→`[-a-zA-Z0-9_]*`, anchored `^...$`, `MaxFQDNLength 255`. Name manager
ipcache metadata: resource `fqdn-name-manager:<name>` (source `Generated`),
labels `fqdn:<selector pattern>` per matching selector; identities preallocated
per selector (v4/v6 CIDR-identity labels).

### Standalone DNS proxy protocol (`standalonednsproxy.FQDNData`, gRPC, plaintext, `localhost:<standalone-dns-proxy-server-port>`)

- `rpc StreamPolicyState(stream PolicyStateResponse) returns (stream
  PolicyState)` — agent pushes full snapshots `PolicyState{egress_l7_dns_policy
  []DNSPolicy{source_endpoint_id, dns_pattern[], dns_servers[]{dns_server_
  identity, port, proto}}, request_id, identity_to_endpoint_mapping
  []{identity, endpoint_info[]{id, ip[]}}, identity_to_prefix_mapping
  []{identity, prefix[]}}`; SDP replies `PolicyStateResponse{response
  ResponseCode, request_id}`. Any error → stream is torn down and SDP
  re-subscribes.
- `rpc UpdateMappingRequest(FQDNMapping) returns (UpdateMappingResponse)` —
  SDP reports `FQDNMapping{fqdn, record_ip[] bytes, ttl, source_identity,
  source_ip bytes, response_code, metrics_data{processing_stats (ns
  timings), dns_response_data{is_response, cnames, qtypes, answer_types},
  source_port, server_addr, server_identity, protocol, allowed,
  error_message, error_type}}`; agent runs the same `NotifyOnDNSMsg` path
  (cache, ipcache, access log, metrics) and answers `ResponseCode`
  (`NO_ERROR, FORMAT_ERROR, SERVER_FAILURE, NOT_IMPLEMENTED, ERROR_INVALID_
  ARGUMENT, ERROR_ENDPOINT_NOT_FOUND, REFUSED`).
- Agent-side tables (`pkg/fqdn/service`): `PolicyRules{identity → DNSPolicy[]}`
  and `identityToIPs`, fed from `SelectorPolicy` updates and ipcache events.
  SDP side (`standalone-dns-proxy/pkg/client`): `DNSRules{epID<<32|PortProto
  → L7DataMap}`, `IPtoEndpointInfo`, `PrefixToIdentity` statedb tables, used
  to implement `ProxyLookupHandler` without BPF access. SDP runtime dir
  `/var/run/standalone-dns-proxy`, debug shell `shell.sock`.

### Auth map

BPF `cilium_auth_map` (hash): key `auth_key{__u32 local_sec_label, __u32
remote_sec_label, __u16 remote_node_id (0 = local), __u8 auth_type, __u8
pad}`; value `auth_info{__u64 expiration}` in units of ns/512 since epoch.
Size `--bpf-auth-map-max` (Helm `authentication.*`, `AuthMapEntries`).
`auth_type` values come from policy `AuthType` (1 = SPIRE mutual TLS;
`test-always-fail` uses its own). Agent keeps an in-memory cache
(`authMapCache`) restored from the map at start; GC deletes entries for
deleted nodes (by node ID), deleted identities, endpoints without auth
policy, and expired entries every `mesh-auth-gc-interval`.

### ztunnel

ZDS (Istio's protocol, `pkg/ztunnel/pb/zds_ztunnel.pb.go`): unix `SOCK_SEQPACKET`
server at `/var/run/cilium/ztunnel.sock`; ztunnel connects and sends
`ZdsHello{version}`; agent sends `WorkloadRequest{oneof payload: Add
AddWorkload{uid, WorkloadInfo{name, namespace, service_account,
trust_domain}} (+ netns fd as SCM_RIGHTS ancillary data), Keep KeepWorkload
{uid}, Del DelWorkload{uid}, SnapshotSent}`; ztunnel answers
`WorkloadResponse{Ack{error}}`. Initial snapshot = Add for every enrolled
endpoint then `SnapshotSent`. Workload xDS: gRPC `AggregatedDiscoveryService`
(delta only) on `127.0.0.1:15012` with TLS from `/etc/ztunnel/{bootstrap,ca}-
{private.key,root.crt}`; resources `type.googleapis.com/istio.workload.
Address` (`Address{Workload{uid, name, namespace, service_account, addresses,
network, tunnel_protocol HBONE, ...}}` derived from CiliumEndpointSlices of
enrolled namespaces) and `istio.security.Authorization` (always empty). CA:
`/istio.v1.auth.IstioCertificateService/CreateCertificate` — CSR must carry
exactly one `spiffe://<td>/ns/<ns>/sa/<sa>` URI SAN and an endpoint with that
ns/sa must exist locally; 30-day cert.

## External interfaces

- Unix sockets under `<run-dir>/envoy/sockets/` (default
  `/var/run/cilium/envoy/sockets/`): `xds.sock` (gRPC, mode 0660, group
  `proxy-gid`), `access_log.sock` (SOCK_DGRAM protobuf `cilium.LogEntry`),
  `admin.sock` (Envoy admin HTTP). `<run-dir>/envoy/bootstrap.pb`.
- Envoy process: `cilium-envoy-starter [--keep-cap-net-bind-service --]
  cilium-envoy -l <level> -c bootstrap.pb --base-id N --log-format <fmt>`;
  version check via `cilium-envoy --version` or admin `/server_info`.
- Mark bits (`bpf/lib/common.h`, `linux_defaults/mark.go`, mask `0x0F00`):
  `MARK_MAGIC_TO_PROXY 0x0200` (+ proxy port << 16), `MARK_MAGIC_PROXY_INGRESS
  0x0A00` / `MARK_MAGIC_PROXY_EGRESS 0x0B00` (+ identity << 16, set on
  upstream sockets by bpf_metadata and by the DNS proxy with `SO_MARK`),
  `MARK_MAGIC_PROXY_EGRESS_EPID 0x0900` (+ endpoint id), `MARK_MAGIC_SKIP_
  TPROXY 0x0800`, `MARK_MAGIC_HOST 0x0C00`, `MARK_MAGIC_IDENTITY 0x0F00`.
  Policy verdict → `CB_PROXY_MAGIC` cb slot carries `proxy_port << 16` across
  tail calls.
- Netlink: ip rule prio 9 `fwmark 0x200/0xF00 lookup 2004` with `local
  0.0.0.0/0 dev lo table 2004` (and the v6 twin) so redirected packets are
  delivered locally; ip rules prio 10 `fwmark 0xA00/0xF00` and `0xB00/0xF00
  lookup 2005` with `<cilium_host ip>/32 dev cilium_host scope link` and
  `default via <cilium_host ip> dev cilium_host mtu <mtu>` (needed with IPsec/
  WireGuard so proxy upstream traffic enters the BPF datapath on
  `cilium_host`). Protocol `RTPROT_KERNEL`.
- TPROXY: with `--enable-bpf-tproxy` the tc program does
  `sk_lookup_{tcp,udp}` for the listener socket at `127.0.0.1:<proxy_port>`
  (ingress path) and `bpf_sk_assign`; otherwise it relies on the mark + ip
  rule and the listener's `IP_TRANSPARENT`. Host egress can't `sk_assign`, so
  `ctx_redirect_to_proxy_host_egress` marks and redirects the packet into
  `cilium_host` ingress.
- Socket options set by the DNS proxy: listener `SO_MARK` (to-proxy magic),
  `SO_REUSEADDR/SO_REUSEPORT`, `IP_TRANSPARENT`/`IPV6_TRANSPARENT`,
  `IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR` (original dst from cmsg);
  upstream `SO_MARK = MARK_MAGIC_PROXY_EGRESS | identity<<16`,
  `IP_TRANSPARENT` (transparent mode binds pod IP), `SO_LINGER`
  (`dnsproxy-socket-linger-timeout`).
- gRPC TCP: `localhost:<standalone-dns-proxy-server-port>` (SDP, plaintext,
  keepalive), `127.0.0.1:15012` (ztunnel xDS + CA, TLS), TCP
  `<remote node>:<mesh-auth-mutual-listener-port>` (mTLS handshake between
  agents, TLS 1.3, SNI `<identity>.<trust-domain>`, cert URI SAN
  `spiffe://<trust-domain>/identity/<numeric id>`).
- SPIRE Delegated Identity API over `unix://<mesh-auth-spire-admin-socket>`
  (`SubscribeToX509SVIDs` with selector `cilium:mutual-auth`,
  `SubscribeToX509Bundles`).
- ZDS unix seqpacket `/var/run/cilium/ztunnel.sock`; iptables/ip6tables
  executed inside pod netns (chains `CILIUM_PREROUTING`/`CILIUM_OUTPUT` in
  mangle+nat, marks `0x111`/`0x539` mask `0xfff`, route table 100, rule prio
  32764, ports 15008/15001/15006).
- Files: `/run/cilium/state/proxy_ports_state.json`; Envoy artifacts copied
  to a hostPath for the external DaemonSet; ztunnel CA material under
  `/etc/ztunnel/`.
- Kubernetes: reads `Secret`s in `envoy-secrets-namespace`, `ingress-
  secrets-namespace`, `gateway-api-secrets-namespace`, `policy-secrets-
  namespace`; CEC/CCEC informers; node labels (for CEC `nodeSelector`);
  CiliumEndpointSlices and Namespaces (ztunnel).
- Metrics: `cilium_proxy_*`, `cilium_fqdn_*`, `cilium_policy_l7_*`,
  xDS ACK/NACK metrics, SDP `--sdp-prometheus-serve-addr`.

## Dependencies

- **Policy engine (area: policy)** — `policy.L4Policy`, `PerSelectorPolicy
  {L7Parser, L7Rules, Listener, TerminatingTLS, OriginatingTLS, ServerNames,
  Priority, IsDeny, Authentication}`, `L7DataMap`, `CachedSelector` snapshots,
  policy revision ACK (`ep.OnProxyPolicyUpdate(rev)`), `Verdict`/`Precedence`
  types. The Envoy NPDS document is a pure function of these.
- **Endpoint manager** — `EndpointUpdater{GetID, GetIPv4/6Address,
  GetIdentity, GetPolicyNames, GetListenerProxyPort, OnProxyPolicyUpdate,
  OnDNSPolicyUpdateLocked}`, endpoint restore promise (Envoy waits up to
  `envoy-policy-restore-timeout` before serving), endpoint state files for
  DNS cache/rules.
- **ipcache** — NPHDS feed, `fqdn:` metadata upserts with revision waits,
  Envoy reads `cilium_ipcache` directly, SDP mirrors identity→prefix.
- **Datapath (areas: bpf policy, lb)** — policy map `proxy_port`, service
  `l7_lb_proxy_port`, marks, `cilium_auth_map`, signal perf ring
  (`SIGNAL_AUTH_REQUIRED`), CT for zombie liveness, node ID map (remote
  node id in auth key).
- **Service/LB tables** — `loadbalancer.ProxyRedirect{ProxyPort, Ports}` on
  services for CEC L7 LB; backend table → EDS.
- **Monitor / Hubble** — `MessageTypeAccessLog` payload.
- **k8s client / statedb / hive** — reflectors and reconcilers.
- **External**: `cilium-envoy` image (`quay.io/cilium/cilium-envoy:v1.37.5-
  ...`) built from github.com/cilium/proxy with the Cilium filters; SPIRE
  server + agent (deprecated path); Istio ztunnel image
  (`quay.io/cilium/ztunnel:v1.0.0`); go-control-plane (xDS protos, snapshot
  cache), miekg/dns.

## Kernel / platform requirements

- `bpf_sk_assign` (5.7+) and `bpf_sk_lookup_tcp/udp` for `enable-bpf-tproxy`;
  without it, TPROXY-by-mark needs `IP_TRANSPARENT` sockets and fib rules
  only.
- `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR` (and v6 equivalents),
  `SO_MARK` (CAP_NET_ADMIN), `SO_REUSEPORT`, `SCM_RIGHTS` fd passing,
  `setns`-free netns handling via pinned netns paths (`netns.OpenPinned`).
- Envoy binary is arm64/amd64 (cilium/proxy publishes both); the agent
  cross-compiles nothing here.
- Envoy's `cilium.bpf_metadata` opens the pinned `cilium_ipcache` map under
  `bpf_root` — Envoy must run with access to `/sys/fs/bpf` and the same
  `proxy-gid` group for the unix sockets.
- ztunnel in-pod mode needs iptables (legacy or nft) reachable from the
  agent and `CAP_SYS_ADMIN` to enter the pod netns.

## Tests

- **Unit** (≈31k lines): `pkg/envoy/xds_server_test.go` (2639) and
  `xds_server_ads_test.go` (1182) pin listener/cluster/policy proto shapes
  and ACK/NACK/revert behavior; `pkg/envoy/xds/server_e2e_test.go` (1661)
  drives full xDS streams with a fake Envoy; `xds/ack_test.go` completion
  semantics; `xdsnew/cache_test.go` snapshot consistency;
  `pkg/envoy/standalone_envoy_test.go` (1307, privileged: execs Envoy)
  bootstrap and restart; `model_test`/`policy/*_test` NPDS generation and
  sort stability; `secretsync_test` k8s→SDS; `pkg/ciliumenvoyconfig/
  cec_resource_parser_test.go` (2125) name qualification, filter injection,
  port allocation, and `script_test.go` (statedb script tests for CEC →
  Envoy resources and L7 LB redirects); `pkg/proxy/proxyports_test`
  allocation/restore, `routes_test` (privileged: netlink);
  `pkg/fqdn/dnsproxy/proxy_test.go` (1772, privileged: binds sockets) covers
  allow/reject, restore, TCP/UDP, concurrency limit, `shared_client_test`
  (658) multiplexing; `pkg/fqdn/cache_test.go` (1426) TTL/limit/zombie GC;
  `namemanager/manager_test`, `bench_test`, fuzz tests for matchpattern and
  name manager; `pkg/fqdn/service/service_test.go` (1260) SDP streaming;
  `standalone-dns-proxy/pkg/client/client_test.go` (604); `pkg/auth/*_test`
  (2044) handshake with fake cert provider, GC by node/identity/endpoint,
  cache; `pkg/ztunnel/*` (3825) ZDS server with fake ztunnel (privileged),
  in-pod iptables (privileged), stream processor diffs, CA CSR validation.
- **BPF unit tests** `bpf/tests/host_proxy.c`, `l7_lb_hairpin_netdev.c`,
  `l7_lb_local_backend_*.c` pin the proxy redirect and L7 LB datapath.
- **e2e / CI**: `.github/workflows/conformance-l7.yaml` (runs
  `tests-e2e-upgrade.yaml` with `test-l7-only`), `conformance-kind-proxy-
  embedded.yaml` (`envoy.enabled=false`, `envoy.xdsMode=split`,
  `loadBalancer.l7.backend=envoy`, connectivity tests matching
  `l7|sni|check-log-errors`), `conformance-ingress.yaml`, `conformance-
  gateway-api.yaml`, `conformance-ztunnel-e2e.yaml` (kernels 6.6/6.12,
  `encryption: ztunnel`), plus L7 cases inside `conformance-{eks,gke,aks,
  aws-cni}` and `tests-e2e-upgrade`. Legacy ginkgo `test/k8s/fqdn.go` and
  `test/k8s/manifests/fqdn-proxy-*.yaml` cover toFQDNs with proxy restarts.
  Connectivity tests come from the `cilium-cli` module (not vendored in this
  tree).

## Rust mapping

### 1. xDS control plane for Envoy (tonic)

- Protos: vendor `envoyproxy/data-plane-api` v3 (listener, route, cluster,
  endpoint, tls Secret, discovery, bootstrap, HCM, tcp_proxy, tls_inspector,
  router, upstream_codec, overload, internal_listener) and the eight
  `cilium/proxy` `.proto` files; build with `tonic-build`/`prost-build`.
  Existing crates (`envoy-types` / `envoy-control-plane`) lag behind and
  lack the Cilium types — generate directly from the pinned protos so the
  `cilium-envoy` image version and the proto set move together.
- Serve on `xds.sock` with `tonic` over `tokio::net::UnixListener`
  (`chmod 0660`, `chown` to proxy gid). Implement **SOTW only**: Envoy's
  Cilium build only uses SOTW for NPDS/NPHDS, and the reference returns
  unimplemented for delta. Choose one of the two reference modes, not both:
  the split server (seven services, per-type cache, ACK by node IP) is the
  default and the simpler contract; ADS needs a snapshot cache with the
  `ciliumSnapshot` consistency rule (listeners and clusters they reference
  must be in the same snapshot). Recommendation: implement split first, keep
  the bootstrap generator able to emit either config source.
- Core: a per-type `Cache{version u64, resources BTreeMap<name, Any>}`,
  version bump on every mutation, `ResourceWatcher` that answers a pending
  `DiscoveryRequest` when `version > last_acked`, and an ACK tracker that
  resolves completion futures (`tokio::sync::oneshot`/`Notify`) when Envoy
  echoes `version_info`, or fails them on `error_detail` (NACK) and reverts
  the mutation. This is ~1.5k lines; the reference's `completion.WaitGroup`
  maps to `futures::join_all` with a timeout (`envoy-config-timeout`,
  `proxy-initial-fetch-timeout`).
- NPDS document builder: pure function `(EndpointPolicy) -> cilium.
  NetworkPolicy` with the same sort keys (`envoy/policy/sort.go`) so protos
  are byte-stable across agents; unit tests should compare against golden
  outputs captured from the Go reference for the same policy inputs.
- Bootstrap: write `bootstrap.pb` (prost encode of `Bootstrap`) with the
  four ORIGINAL_DST clusters, the pipe clusters and admin; spawn
  `cilium-envoy-starter` with `tokio::process`, restart with backoff, pipe
  stderr JSON lines into `tracing`. Envoy admin over `hyper` +
  `hyperlocal`/unix connector.
- Access log server: `tokio::net::UnixDatagram` on `access_log.sock`, prost
  decode `LogEntry`, map to the L7 flow record and push to the Hubble/monitor
  ring (area: observability). Correlate `policy_name` → endpoint via a local
  map identical to `LocalEndpointStore`.
- Routes/rules: `rtnetlink` crate for tables 2004/2005 and fwmark rules;
  proxy port allocator with `/proc/net/*` scan (or `netlink-packet-sock-diag`)
  and a JSON state file.
- Secret sync: k8s `Secret` watch (`kube-rs`) → SDS `Secret` protos with the
  same naming (`<namespace>/<name>`) and TLS session ticket key handling.
- CEC: `kube-rs` `CustomResource` derive for `CiliumEnvoyConfig`/
  `CiliumClusterwideEnvoyConfig`; the `resources[]` field is `Any` JSON —
  decoding requires the `@type` → message registry that
  `pkg/envoy/resource/envoy.go` achieves with blank imports. In Rust,
  generate a `match type_url` table for the ~150 extension types
  (`prost-reflect` with a compiled descriptor set is the clean way to
  validate arbitrary `Any` and re-encode). The parser (qualify names,
  inject filters, allocate ports, EDS from the service table) is mechanical
  but large: budget ~3k lines including tests.

### 2. DNS proxy (hickory-proto)

- `hickory-proto` for wire parsing (`Message`, EDNS OPT, TC bit, compression
  on encode via `BinEncoder` with max size = client's EDNS bufsize or 512),
  not `hickory-server` (its handler model hides the transparent-socket
  details). Sockets via `socket2` + `tokio`: UDP listeners with
  `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`, `SO_MARK`, reading `recvmsg`
  cmsgs (`nix::sys::socket::recvmsg` with `ControlMessageOwned::Ipv4OrigDstAddr`)
  to recover the original destination; TCP listener with `IP_TRANSPARENT`;
  upstream sockets with `SO_MARK = 0x0B00 | identity << 16`, optional
  `IP_TRANSPARENT` bind to the pod IP, `SO_LINGER`. UDP responses must be
  sent from a per-response socket bound to the *original destination*
  (server IP:53) so the pod sees a reply from its resolver — mirror
  `sessionUDP.WriteResponse`.
- Policy check: `(endpoint id, dst port/proto) → Vec<(selector, Regex)>`
  with the `matchpattern` → regex translation ported verbatim (it is 144
  lines and fuzz-tested); use `regex` with a size-bounded LRU
  (`lru` crate) as `pkg/fqdn/re`. Same reject code semantics (REFUSED
  default, NXDOMAIN optional).
- Cache + name manager: `DNSCache` and zombies are straightforward
  `BTreeMap`s; the hard part is the *ordering contract*: on an allowed
  response the proxy must (a) update the cache, (b) compute affected
  selectors → labels, (c) upsert ipcache metadata and wait for the ipcache/
  policy revision to be applied to BPF, (d) only then write the DNS response
  back, bounded by `proxy-response-max-delay` (100 ms). Implement as an
  async pipeline with per-name locks (`dnsproxy-lock-count` striped mutexes)
  and a semaphore (`tokio::sync::Semaphore`) for the concurrency limit.
- Restore: serialize the same JSON shapes (`DNSRules`, cache dump) so an
  agent swap does not drop connections; the SDP protocol is the better
  long-term answer (see below).
- Standalone DNS proxy: implement `FQDNData` with tonic on both sides from
  `standalone-dns-proxy.proto`; a Rust SDP is the same DNS proxy binary with
  a gRPC-fed rule table instead of in-process policy, so build the proxy as
  a library crate with a `PolicySource` trait from day one.

### 3. Mutual auth / SPIFFE

- Deprecated upstream; implement only if a flowsdn user needs it. Crates:
  `spiffe` (Workload API client; the reference uses the *Delegated Identity*
  admin API instead, which the `spiffe` crate does not cover — a tonic client
  generated from `spire-api-sdk` protos is needed), `rustls` for the TLS 1.3
  handshake with a custom `ServerCertVerifier` checking the URI SAN
  `spiffe://<td>/identity/<id>`, `x509-parser`/`rustls-webpki` for chains,
  `aya`/`libbpf-rs` map access for `cilium_auth_map` and the signal perf
  ring. ~2k lines; the GC rules are the fiddly part.

### 4. ztunnel control plane

- ZDS: `tokio::net::UnixListener` cannot do `SOCK_SEQPACKET`; use `socket2`
  + `nix::sys::socket::sendmsg` with `ControlMessage::ScmRights` for the
  netns fd, then wrap the fd in `tokio::io::unix::AsyncFd`. Protos from
  Istio (`zds.proto`, `workload.proto`, `ca.proto`) via tonic-build. In-pod
  iptables via `iptables`/`ip6tables` exec inside `setns` (spawn a helper
  thread with `nix::sched::setns`). Workload xDS is delta-ADS only. CA:
  `rcgen` + `x509-parser` for CSR validation and signing. ~4k lines.

### 5. Replacing Envoy with a Rust proxy (longer term)

Surface the replacement must cover to drop `cilium-envoy`:

- Transport: TPROXY listeners on `127.0.0.1:<port>` for TCP with original-
  dst recovery, `SO_MARK`-derived source identity and endpoint id, upstream
  connect to original dst with `IP_TRANSPARENT` original-source and the
  `MARK_MAGIC_PROXY_{INGRESS,EGRESS}|identity<<16` mark (so the datapath
  applies policy/encryption to the upstream leg), `SO_LINGER` control,
  `use_downstream_protocol` (HTTP/1.1 ↔ HTTP/2 passthrough, WebSocket
  upgrade).
- HTTP: full HTTP/1.1 and HTTP/2 termination (`hyper`/`h2`), path
  normalization (RFC3986 + merge slashes + escaped-slash redirect), the
  `cilium.l7policy` semantics (per-connection identity → rule set lookup,
  regex on `:path`/`:method`/`:authority`, header exact/present matchers,
  `HeaderMatch` mismatch actions that *rewrite* requests — add/delete/
  replace headers, secret values from SDS), 403 body, retries on 5xx,
  request/stream idle timeouts, gRPC timeout header handling, XFF trusted
  hops, access-log emission in the same `LogEntry` shape (or directly as
  Hubble flows).
- TLS: `rustls` termination with per-rule server cert/key (terminatingTLS)
  and origination with CA validation and SNI (originatingTLS), SNI
  allow-list without termination (tls_inspector + tcp_proxy), ALPN, SDS-
  style live secret updates.
- Policy: consume the same NPDS document (keep the proto as the internal
  contract so the agent side is unchanged), precedence/pass/deny semantics,
  wildcard-port rules, `remote_policies` identity sets, hot updates with
  ACK back to the agent so policy revision tracking still works.
- L7 LB (Ingress/Gateway/CEC): this is the big one — arbitrary Envoy
  listeners, routes, clusters with weighted clusters, header/path rewrites,
  redirects, timeouts/retries, circuit breakers, EDS backends, TLS
  termination with SNI-selected certs, HTTP/2 and gRPC, plus whatever
  extensions users put in CEC `resources`. A Rust proxy can realistically
  cover the policy-enforcement listeners (items above, ~15–20k lines with
  `hyper`/`tower`/`rustls`, comparable to what `pingora`/`linkerd2-proxy`
  spend on the same features) but not arbitrary CEC; Ingress/Gateway would
  need a purpose-built router (e.g. on `pingora`) with a translator from the
  operator model rather than from Envoy protos.

## Recommendation

- **Envoy driving (xDS server, bootstrap, access log, ports, routes, secret
  sync): keep, reimplement in Rust — L.** It is the only way to get L7 HTTP
  policy, TLS interception, Ingress and Gateway API on day one, and the
  contract is well defined (this document plus the protos). Use the split
  xDS mode; pin the `cilium-envoy` image and proto set together. ~8–10k
  lines including tests.
- **CEC / CCEC parsing and L7 LB redirect: keep but phase 2 — M.** Needed
  by Ingress/Gateway; the `Any` handling and name qualification are
  mechanical. ~3–4k lines.
- **DNS proxy + toFQDNs + name manager: keep, reimplement — L.** Core to
  egress policy; no Envoy dependency. Build it as a library so the same code
  runs in-agent and as the standalone proxy; implement the `FQDNData` gRPC
  protocol from the start and treat the JSON restore files as legacy. ~8k
  lines.
- **Standalone DNS proxy binary: keep — S** once the library exists.
- **Mutual authentication (SPIRE): defer.** Deprecated upstream; ztunnel is
  the successor for mTLS. Do not spend effort unless a user requires it.
- **ztunnel integration: defer, then keep — M.** Beta upstream, but it is
  the sanctioned mTLS path; the protocol surface is small and well specified
  by Istio. Revisit once the endpoint manager and CES reflector exist.
- **Replacing Envoy with a Rust proxy: defer (XL).** Only the policy-
  enforcement listener subset is realistic; Ingress/Gateway parity with
  arbitrary Envoy config is not. Keep the NPDS proto as the internal policy
  contract so a future Rust L7 filter can be dropped in behind the same xDS
  server.

## Open questions

- Which `cilium-envoy` image tag flowsdn pins, and whether to build
  `bootstrap.pb` in split or ADS mode — Cilium is moving toward ADS (`envoy-
  xds-mode=ads|strict-ads` are new in v1.20) and may drop split later.
- Does flowsdn want `external-envoy-proxy` DaemonSet mode only (simplest:
  no process management, only sockets on a hostPath), or also embedded? The
  DaemonSet mode also decides who copies the Envoy artifacts.
- **#70 source audit:** the image revision `766ccfb37260a43e9d228837aa84ce3faf9f64e7`
  uses nonempty `BpfMetadata.ipcache_name` to select the map; only an empty
  field falls back to `cilium_ipcache`. Spec 16 §3.2.5 records pinned source
  links and a four-case executable image probe, all passed on 2026-09-22;
  exact key/value ABI compatibility remains a separate requirement.
- Whether `enable-bpf-tproxy` (sk_assign) becomes the only mode in flowsdn;
  it removes the fwmark ip rules but requires kernel ≥ 5.7 and tc ingress
  only (host egress still needs the mark path).
- **Resolved #24:** preserve the NPDS/new-listener ACK barrier. The proxy
  library has a bounded attempt state machine; actual xDS and endpoint-map
  publication remain required (spec16 §3.1.5).
- **Resolved #197:** derive transparent mode from SDP enablement only when
  unset; an explicit effective true/false overrides the derived default.
  Socket behavior and Hubble source-attribution tests remain required.
- How the Hubble flow record for L7 is produced when Envoy is external:
  reuse `LogEntry` protobuf over the unix datagram socket (keeps cilium/proxy
  unchanged) — the flowsdn default is now 16384 (#199), with detected truncation
  dropped and counted; validate runtime datagram sizes for
  header-heavy requests or raise the default.
- Whether to support the SDS-less "inline secrets" TLS modes at all, or only
  SDS (`enable-policy-secrets-sync`), which is the documented default for new
  clusters.
- **Resolved #204:** FQDN shares the full local identity range owned by spec03,
  with selector preallocation, shared reference counts and restore withholding.
  No separate numeric partition; only scope validation is implemented here.

ADR-0015 resolves #262 (retain Envoy; separate replacement proposal/gates) and
#203 (future nftables enrollment inside pod namespaces, no iptables exception).
Neither decision delivers a Rust L7 replacement or ztunnel enrollment.
