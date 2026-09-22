# Layer 7 enforcement: Envoy integration and the DNS proxy — specification

Status: draft. Derived from: `docs/inventory/11-l7-proxy-dns-auth-mesh.md`; reference
cilium v1.20.1 (7d68cfb394) paths `pkg/envoy/**`, `pkg/envoy/xds/**`,
`pkg/envoy/xdsnew/**`, `pkg/envoy/policy/**`, `pkg/proxy/**`,
`pkg/proxy/proxyports/**`, `pkg/proxy/accesslog/**`, `pkg/ciliumenvoyconfig/**`,
`pkg/fqdn/**`, `standalone-dns-proxy/**`, `pkg/auth/**`, `pkg/ztunnel/**`,
`pkg/k8s/apis/cilium.io/v2/{cec,ccec}_types.go`,
`pkg/crypto/certificatemanager/`, `pkg/secretsync/names/`,
`vendor/github.com/cilium/proxy/go/cilium/api/*.pb.go`,
`api/v1/standalone-dns-proxy/standalone-dns-proxy.proto`,
`install/kubernetes/cilium/files/cilium-envoy/configmap/bootstrap-config.yaml`.
Governed by ADR-0001 (Envoy stays as an external image), ADR-0002 (Rust only),
ADR-0003 (nftables residual), ADR-0004 (no Hive/StateDB).

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* flowsdn does and the exact bytes it exchanges with `cilium-envoy`, with
pods and with the standalone DNS proxy. It does not transcribe reference code.
Deviations are marked **DEVIATION** with the reason and the ADR.

---

## 1. Scope

In scope:

- The agent→Envoy control plane: the xDS transport over a unix socket, the
  `cilium.*` protobuf contract (NPDS, NPHDS, `bpf_metadata`, `network`,
  `l7policy`, `tls_wrapper`, `accesslog`), the bootstrap flowsdn generates, the
  listener/filter-chain shape per redirect kind, ACK/NACK and versioning, and
  the access-log socket whose records become Hubble L7 flows.
- Redirect lifecycle: proxy port allocation, reuse and persistence; how the port
  reaches the datapath; teardown.
- `CiliumEnvoyConfig` / `CiliumClusterwideEnvoyConfig`: schema, validation, raw
  Envoy resource passthrough, name qualification, filter injection, service and
  backend-service wiring, node selection, and the Ingress / Gateway API path
  that generates these objects.
- L7 policy semantics for the two rule kinds that exist at v1.20: HTTP and DNS,
  including TLS interception and secret sources.
- The DNS proxy: interception, request/response handling, `matchName` /
  `matchPattern`, the response-hold ordering contract, cache, zombies, TTL, GC,
  restore, concurrency limits, configuration.
- The standalone DNS proxy (SDP) and its gRPC protocol.
- Mutual authentication and ztunnel: **deferred**, with the datapath contract
  documented so nothing has to be redesigned later.

Out of scope (owned by sibling specs; referenced, never duplicated):

- Which policy rules produce a redirect, the proxy id string, listener
  priorities, and the `proxy_port` field inside a policy map entry —
  `06-policy-engine.md` §3.2.6, §3.5.2, §4.3, §4.5.
- The skb mark values, `ctx_redirect_to_proxy*`, and the BPF TPROXY path —
  `02-datapath-programs.md` §2.1, §3.14.
- The `cilium_ipcache_v2` map that Envoy reads directly, its key/value layout
  and pin path — `03-identity-ipcache.md` §4.8 and `01-bpf-map-abi-loader.md`
  §4.1, §4.9. The map name is passed to Envoy explicitly; see §3.2.5 here.
- ip rules, route tables 2004/2005 and the nftables `tproxy`/`socket`/`notrack`
  residual — `10-node-routing-nftables.md` §3.10.3, §4.5.
- Endpoint regeneration ordering and the "wait for proxy" barrier —
  `08-endpoint-agent-api.md`.
- Hubble flow encoding of the L7 record — Hubble spec (wave 3).
- Ingress/Gateway API object → model translation in the operator — operator spec
  (wave 3). This spec owns only the CEC that the operator emits.

---

## 2. Compatibility contract

These interfaces MUST match the reference byte for byte, because a third party
depends on them.

| Interface | Consumer | What is frozen |
|---|---|---|
| `cilium.NetworkPolicy` and the rest of the `cilium.*` protos (§4.1) | `cilium-envoy` image (ADR-0001) | field numbers, oneof tags, enum values, semantics |
| Type URLs `type.googleapis.com/cilium.NetworkPolicy`, `.../cilium.NetworkPolicyHosts` and the five standard v3 URLs (§3.1.4) | Envoy | exact strings |
| gRPC service names `cilium.NetworkPolicyDiscoveryService`, `cilium.NetworkPolicyHostsDiscoveryService` and the standard `envoy.service.*.v3.*` services (§3.1.3) | Envoy | method paths |
| Unix sockets `<run-dir>/envoy/sockets/{xds.sock,access_log.sock,admin.sock}`, mode 0660, group `proxy-gid` | Envoy DaemonSet (shared hostPath) | paths, modes, ownership, socket types |
| `access_log.sock` framing: `SOCK_SEQPACKET`, one `cilium.LogEntry` protobuf per packet | Envoy | socket type and framing |
| Envoy node id `host~127.0.0.1~no-id~localdomain`; split-mode ACKs keyed by node IP `127.0.0.1` | Envoy, agent ACK tracking | string format |
| `BpfMetadata.ipcache_name` = the pinned ipcache map name (`cilium_ipcache_v2`) and `bpf_root` | Envoy `cilium.bpf_metadata` filter | must name the map flowsdn actually pins (spec 03 §4.8) |
| skb marks `MARK_MAGIC_TO_PROXY 0x0200`, `MARK_MAGIC_PROXY_INGRESS 0x0A00`, `MARK_MAGIC_PROXY_EGRESS 0x0B00`, `MARK_MAGIC_PROXY_EGRESS_EPID 0x0900` | Envoy sets these on upstream sockets; datapath reads them | values and the identity/EPID placement in bits 16..31 |
| `CiliumEnvoyConfig` / `CiliumClusterwideEnvoyConfig` CRD schema (§4.4) | users, operator (Ingress/Gateway), `cilium-dbg` | field names, defaulting, name qualification `<namespace>/<name>/<resource>` |
| CEC annotations `cec.cilium.io/{inject-cilium-filters,use-original-source-address,is-l7lb}` | operator, users | names and boolean semantics |
| `standalonednsproxy.FQDNData` gRPC service (§4.6) | standalone DNS proxy binary | messages, field numbers, response codes |
| DNS restore format `restore.DNSRules` keyed by `PortProto` (`1<<24 \| proto<<16 \| port`) (§4.5) | agent across restart, `cilium-dbg` | JSON shape and key encoding |
| Metrics `cilium_proxy_redirects`, `cilium_policy_l7_total`, `cilium_proxy_upstream_reply_seconds`, `cilium_xds_events_count`, `cilium_fqdn_*` (§8) | dashboards | names and labels |
| REST `GET/DELETE /fqdn/cache`, `GET /fqdn/cache/{id}`, `GET /fqdn/names` | `cilium-dbg` | paths and payloads (spec 08 owns the server) |

Interfaces flowsdn owns and MAY change: the internal `Redirect` abstraction, the
xDS cache implementation, the proxy-ports state file schema (`<state-dir>/proxy-ports.json`,
**DEVIATION** from the reference `proxy_ports_state.json`, agreed in spec 10 §3.10.3),
and everything under `flowsdn-xds` / `flowsdn-dnsproxy`.

---

## 3. Behavior

### 3.1 The agent→Envoy contract

#### 3.1.1 Deployment model

flowsdn runs Envoy as a **separate DaemonSet** (`cilium-envoy`) built from
`github.com/cilium/proxy` and consumed unchanged (ADR-0001, `docs/licensing.md`).
The image tag and the generated protobuf set MUST be pinned together; a proto
regenerated from a different `cilium/proxy` revision than the running image is a
build error, not a runtime surprise.

- The agent MUST support `external-envoy-proxy=true` (Envoy in its own
  DaemonSet, sharing `<run-dir>/envoy/sockets/` and `/sys/fs/bpf` through
  hostPath). This is the only mode the agent supports at M1.
- **DEVIATION** (ADR-0001, one binary per component, `scratch` images): the
  agent does **not** fork, supervise or restart an Envoy process, does not ship
  `cilium-envoy-starter`, and does not copy Envoy artifacts to a hostPath.
  `external-envoy-proxy=false` MUST be rejected at startup with
  `embedded Envoy is not supported; run the cilium-envoy DaemonSet`. The
  reference's `ArtifactCopier` and `onDemandXdsStarter` have no counterpart.
  Consequence: nothing in flowsdn parses Envoy's stderr, and Envoy's log level
  is changed only through the admin socket (§3.1.8).
- The agent MUST still be able to **emit** a bootstrap document (§3.1.6), because
  the DaemonSet's bootstrap is rendered by the flowsdn chart from the same
  builder, and because `flowsdn-dbg envoy bootstrap` prints it for support.

#### 3.1.2 Transport

- The agent MUST serve gRPC over a unix stream socket at
  `<run-dir>/envoy/sockets/xds.sock` (`run-dir` default `/var/run/cilium`).
- The socket MUST be removed if stale, created, `chmod 0660`, and `chown -1:<proxy-gid>`
  (default gid 1337) before the server accepts.
- The socket directory MUST be created mode 0777 if absent (Envoy's container may
  run as a different uid).
- gRPC MUST be HTTP/2 without TLS. Envoy reaches it through the static cluster
  `xds-grpc-cilium` whose endpoint is a `Pipe` at that path.
- The server MUST accept multiple concurrent streams from one Envoy process
  (Envoy opens one stream per resource type in split mode) and MUST tolerate a
  stream being torn down and re-established at any point without losing the
  resource cache.

#### 3.1.3 Server modes and the default

The reference offers `envoy-xds-mode = split | ads | strict-ads`, default
`split`.

- flowsdn MUST implement **split** mode and MUST make it the default.
  Split registers one gRPC service per resource type, each with its own cache,
  version counter and ACK tracking. It is the simpler contract: a NACK affects
  exactly one type, and no cross-type snapshot consistency rule exists.
- flowsdn MUST implement **SOTW** (state-of-the-world) only. `Delta*` methods
  MUST return `UNIMPLEMENTED`; the reference does the same and the Cilium Envoy
  build never uses them.
- `ads` and `strict-ads` are **deferred**. The flag MUST be accepted; values
  other than `split` MUST be rejected at startup with
  `envoy-xds-mode=<v> is not supported; only "split" is implemented`
  (**DEVIATION**, recorded in §12 decision 1 — upstream is moving toward
  ADS and flowsdn will follow when the image requires it). The bootstrap
  generator MUST already be able to emit either config source so the switch is
  a code change in one function, not a redesign.

Services registered in split mode (all take
`envoy.service.discovery.v3.DiscoveryRequest` and return `DiscoveryResponse`):

| gRPC service | Type URL served |
|---|---|
| `envoy.service.listener.v3.ListenerDiscoveryService` | `type.googleapis.com/envoy.config.listener.v3.Listener` |
| `envoy.service.route.v3.RouteDiscoveryService` | `type.googleapis.com/envoy.config.route.v3.RouteConfiguration` |
| `envoy.service.cluster.v3.ClusterDiscoveryService` | `type.googleapis.com/envoy.config.cluster.v3.Cluster` |
| `envoy.service.endpoint.v3.EndpointDiscoveryService` | `type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment` |
| `envoy.service.secret.v3.SecretDiscoveryService` | `type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret` |
| `cilium.NetworkPolicyDiscoveryService` (`Stream`/`Fetch`/`Delta NetworkPolicies`) | `type.googleapis.com/cilium.NetworkPolicy` |
| `cilium.NetworkPolicyHostsDiscoveryService` (`Stream`/`Fetch`/`Delta NetworkPolicyHosts`) | `type.googleapis.com/cilium.NetworkPolicyHosts` |

`type.googleapis.com/cilium.health_check.event_sink.pipe` exists in the proto set
and MUST NOT be emitted.

#### 3.1.4 Ordering and the restore barrier

- Listeners MUST NOT be served before endpoint policy restoration has completed
  or `envoy-policy-restore-timeout` (default 3m) has elapsed. Serving a listener
  first would open a proxy port with no policy behind it, and traffic redirected
  to it would be allowed unconditionally.
- The LDS stream MUST additionally wait for the **first NPDS ACK** from the node
  before answering its first request (`afterTypeURL` in the reference). This
  guarantees Envoy has a policy document before it has a socket.
- NPHDS MUST be served but is **disabled in production**: `BpfMetadata.use_nphds`
  is false, so Envoy resolves identities from the pinned ipcache map instead.
  flowsdn MUST keep the NPHDS cache fed from ipcache events (identity → CIDR
  list, resource name = identity in decimal) so that a future Envoy without BPF
  map access, and the test harness, both work.

#### 3.1.5 Versioning, ACK and NACK

The version scheme is a per-(type URL) monotonically increasing `u64` rendered as
a decimal string. `version_info` is a property of the resources; `response_nonce`
is a property of the stream. flowsdn MUST reuse the reference's arithmetic:

1. Each mutation of a type's cache increments that type's version and wakes every
   watcher on that type.
2. A response carries `version_info = <version>` and `nonce = <version>` (the
   same number). Envoy echoes them in the next request.
3. On receiving a request:
   - `version_info == ""` and `response_nonce == ""` → new stream, no prior state.
     Parse both as 0.
   - Non-empty values MUST parse as `u64`; otherwise the stream MUST be
     terminated with `invalid version info` / `invalid response nonce`.
   - `version_info > response_nonce` after the client has received at least one
     response is protocol-invalid; terminate the stream.
   - `version_info == response_nonce` (and at least one response was received) →
     **ACK** of `version_info`.
   - `version_info < response_nonce` → **NACK**: every version after
     `version_info` up to and including `response_nonce` is rejected.
     `error_detail.message` carries Envoy's reason.
4. A NACK MUST increment `cilium_xds_events_count{type_url,status="nack"}`, MUST
   be logged at warn with the detail, and MUST NOT be answered with a resend.
   The server waits for the next version bump before sending again; resending the
   same rejected version is a hot loop (§7).
5. Until the first ACK arrives, `version_info` from Envoy is stale and MUST be
   reported to ACK observers as version `0`, never as the value Envoy sent.
6. A node's ACK is recorded against the node IP parsed from the Envoy node id
   (`host~127.0.0.1~no-id~localdomain` → `127.0.0.1`). Malformed node ids MUST
   terminate the stream (`invalid node format`).

**Completion.** Every mutation submitted with a completion (listener add,
network policy update, CEC resource push) MUST resolve when the ACK for a version
≥ the mutation's version arrives for that type and node, and MUST fail on NACK.
The caller supplies a deadline: `envoy-config-timeout` (2m) for CEC pushes and
`proxy-initial-fetch-timeout` (30s) elsewhere. On failure the mutation MUST be
**reverted** — the cache returns to the pre-mutation contents and the version is
bumped again so Envoy converges on the old, known-good document.

**Endpoint policy revision.** A `cilium.NetworkPolicy` push is part of endpoint
regeneration. The endpoint's policy revision MUST NOT be advanced, and the BPF
policy map MUST NOT be switched to a new proxy port, until the NPDS ACK for that
push has been observed (spec 08 owns the pipeline; this spec
owns the signal). A timeout MUST be treated as a regeneration failure and retried
with backoff; it MUST NOT silently proceed.

Decision #24 preserves this barrier without a weaker fallback. For a new
listener/port, its LDS acknowledgement is an additional prerequisite. Retain the
old acknowledged port and policy revision until every required acknowledgement
succeeds. Bind replies to the Envoy node, type URL, actually sent response
version/nonce and stream epoch; stale replies and pre-first-ACK resume values
cannot complete new work. A newer acknowledged version may satisfy an earlier
mutation only when that response includes the mutation. NACK, timeout and
cancellation return no publication permit and require rollback/retry.

`flowsdn-proxy::ack` implements this per-attempt state machine using monotonic
caller ticks. A newer sent response revokes that type's readiness until its ACK;
reconnect clears the attempt's acknowledgements. Commit is one-shot and checks
the deadline again. The endpoint owner must cancel superseded attempts and
atomically verify the permit's attempt/revision against its current desired
state before BPF publication. The xDS transport, cache reversion and endpoint
pipeline integration remain required; the library does not perform them.

#### 3.1.6 Bootstrap flowsdn generates

The bootstrap is a `envoy.config.bootstrap.v3.Bootstrap`. In DaemonSet mode it is
rendered by the chart to a ConfigMap key `bootstrap-config.json` mounted at
`/var/run/cilium/envoy/bootstrap-config.json`; the agent's builder MUST produce
an identical document so the two never drift.

- `node.id = "host~127.0.0.1~no-id~localdomain"`, `node.cluster = "ingress-cluster"`.
- `dynamic_resources.lds_config` and `.cds_config` = the Cilium xDS config
  source: `ApiConfigSource{api_type: GRPC, transport_api_version: V3,
  set_node_on_first_message_only: true, grpc_services: [EnvoyGrpc{cluster_name:
  "xds-grpc-cilium"}]}`, `resource_api_version: V3`,
  `initial_fetch_timeout = proxy-initial-fetch-timeout` (30s).
  In a future ADS mode, `ads_config` is set instead and LDS/CDS point at an
  `Ads{}` source with a 1 ms initial fetch timeout.
- Static clusters (all with `connect_timeout = proxy-connect-timeout`, default 2s,
  and circuit breakers from `proxy-cluster-max-{connections,requests,pending-requests}`
  (1024 each) and `proxy-max-concurrent-retries` (128)):

  | Cluster | Type | LB policy | Notes |
  |---|---|---|---|
  | `egress-cluster` | `ORIGINAL_DST` | `CLUSTER_PROVIDED` | `HttpProtocolOptions{use_downstream_protocol_config, idle_timeout = proxy-idle-timeout-seconds, max_requests_per_connection, max_connection_duration}`; `cleanup_interval = connect_timeout + 0.5s` |
  | `egress-cluster-tls` | `ORIGINAL_DST` | `CLUSTER_PROVIDED` | same, plus transport socket `cilium.tls_wrapper` with an empty `UpstreamTlsWrapperContext` |
  | `ingress-cluster` | `ORIGINAL_DST` | `CLUSTER_PROVIDED` | as `egress-cluster` |
  | `ingress-cluster-tls` | `ORIGINAL_DST` | `CLUSTER_PROVIDED` | as `egress-cluster-tls` |
  | `xds-grpc-cilium` | `STATIC` | `ROUND_ROBIN` | one endpoint, `Pipe{path: <sockets>/xds.sock}`, explicit HTTP/2 |
  | `/envoy-admin` | `STATIC` | `ROUND_ROBIN` | one endpoint, `Pipe{path: <sockets>/admin.sock}` |

  The TLS variants MUST NOT set `auto_sni` / `auto_san_validation`: the
  `cilium.network` filter already forwards SNI from downstream, and setting both
  crashes Envoy.
- `admin.address = Pipe{path: <sockets>/admin.sock, mode: 0660}`.
- `bootstrap_extensions = [envoy.bootstrap.internal_listener]` (CEC internal
  listeners depend on it).
- `overload_manager.resource_monitors = [envoy.resource_monitors.global_downstream_max_connections{max_active_downstream_connections = proxy-max-active-downstream-connections}]`
  (default 50000).
- Static listeners rendered only by the chart, not by the agent:
  `envoy-prometheus-metrics-listener` on `proxy-prometheus-port` routing
  `/metrics` → cluster `/envoy-admin` with `prefix_rewrite: /stats/prometheus`;
  `envoy-admin-listener` on `proxy-admin-port` (loopback only) proxying `/`;
  `envoy-health-listener` routing `/healthz` → `/ready`. All three MUST carry an
  `internal_address_config` of RFC1918 + loopback CIDRs (§3.1.7) so remote
  clients are never treated as internal.
- `cluster_manager.local_cluster_name = "/cilium-locality-cluster"` and the
  matching static cluster only when `envoy-node-locality-enabled` is set; the
  node's `topology.kubernetes.io/zone` label MUST be present or startup fails.

#### 3.1.7 Listener and filter chain per redirect

For each policy-enforcement redirect the agent creates one listener named
`cilium-{http,tls}-{ingress,egress}` (the same five static names as the proxy
ports, minus DNS which never reaches Envoy). CEC listeners keep their own
qualified names (§3.4).

Listener shape:

- `address` = `127.0.0.1:<proxy port>` when IPv4 is enabled, `[::1]:<port>` when
  only IPv6; when both are enabled, the other family is added as an
  `additional_addresses` entry. Both MUST resolve to the loopback of the host
  netns.
- Listener filters, in this order:
  1. `envoy.filters.listener.tls_inspector` (always first; it must run before
     chain matching so `transport_protocol: tls` can select a chain),
  2. `cilium.bpf_metadata` with the `BpfMetadata` message of §3.2.5.
- Filter chains, for `ParserTypeHTTP`:
  - chain 0 (no `filter_chain_match`): `cilium.network` (empty `NetworkFilter`)
    then `envoy.filters.network.http_connection_manager`, upstream cluster
    `{egress,ingress}-cluster`;
  - chain 1 (`filter_chain_match.transport_protocol = "tls"`, transport socket
    `cilium.tls_wrapper` with an empty `DownstreamTlsWrapperContext`): the same
    two filters, upstream cluster `{egress,ingress}-cluster-tls`.
- Filter chains, for `ParserTypeTLS` (SNI-only enforcement, no HTTP parsing): the
  same two chains but `cilium.network` (with `access_log_path` set) followed by
  `envoy.filters.network.tcp_proxy`, matched on `raw_buffer` and `tls`.

`HttpConnectionManager` configuration:

- `stat_prefix = "proxy"`; `upgrade_configs = [{upgrade_type: "websocket"}]`;
  `use_remote_address = true`; `skip_xff_append = true`;
  `xff_num_trusted_hops = proxy-xff-num-trusted-hops-{ingress,egress}` (default 0).
- `http_filters = [cilium.l7policy, envoy.filters.http.router]`, in that order.
  `cilium.l7policy` carries `L7Policy{access_log_path: <sockets>/access_log.sock,
  denied_403_body: <http-403-msg>}`.
- `internal_address_config.cidr_ranges` = `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `127.0.0.1/32` (IPv4) and `::1/128` (IPv6);
  `unix_sockets = false`.
- `stream_idle_timeout = http-stream-idle-timeout` (300s; 0 disables).
- Inline route config, one virtual host `default_route` with `domains: ["*"]` and
  exactly two routes, in order:
  1. `match{prefix: "/", grpc: {}}` → cluster, `timeout = http-request-timeout`
     (3600s), `max_stream_duration.grpc_timeout_header_max = http-max-grpc-timeout`
     (0 = unlimited), retry `5xx` × `http-retry-count` (3) with
     `per_try_timeout = http-retry-timeout`;
  2. `match{prefix: "/"}` → same cluster, same timeout and retry policy, plus
     `idle_timeout = http-idle-timeout` when that is non-zero.
  The gRPC route must come first so `grpc-timeout` handling applies only to gRPC.
- When `http-normalize-path` (default true): `normalize_path = true`,
  `merge_slashes = true`,
  `path_with_escaped_slashes_action = UNESCAPE_AND_REDIRECT`. Turning this off
  makes path-based policy bypassable and MUST be logged as a warning at startup.

#### 3.1.8 Admin interface

The agent MUST speak HTTP over `<sockets>/admin.sock` for exactly three
operations: set the Envoy log level (`POST /logging?level=<lvl>`), read
`/server_info` for the version check, and `POST /quitquitquit` on graceful
shutdown when flowsdn owns the Envoy lifecycle (it does not, in DaemonSet mode —
so `/quitquitquit` MUST NOT be issued). The agent MUST map its own log level to
spdlog levels: panic→off, fatal→critical, error→error, warn→warning, info→info,
debug→info unless flow debug is on, and debug+`envoy-log` tracing→trace.
`envoy-default-log-level`, when set, overrides everything but the trace case.

Version check: unless `disable-envoy-version-check` is set, the agent MUST read
`/server_info` and refuse to serve xDS if the running Envoy's version does not
match the version the protos were generated against. **DEVIATION**: the reference
also shells out to `cilium-envoy --version`; flowsdn has no Envoy binary in its
image and uses the admin socket only.

#### 3.1.9 Access log socket

- The agent MUST listen on `<sockets>/access_log.sock` as a **`SOCK_SEQPACKET`
  (unixpacket) listener**, not a datagram socket, `chmod 0660`, group `proxy-gid`.
  Each Envoy listener opens one connection; the listener's worker threads share
  it, so the server MUST handle many concurrent connections.
- Each received packet is one `cilium.LogEntry` protobuf. Reads use a buffer of
  `envoy-access-log-buffer-size` bytes (default 4096). A read whose flags contain
  `MSG_TRUNC` MUST discard the record and log a warning naming the flag — a
  truncated protobuf must never be partially decoded. Header-heavy requests are
  the common cause; the message MUST tell the operator to raise the size.
- A record that fails to decode MUST be discarded and counted, never fatal.
- Decoded records are converted to the internal `LogRecord` (§4.3) and pushed to
  the monitor/Hubble ring as `MessageTypeAccessLog` (Hubble spec decodes them into
  `flow.Layer7{Http}`).
- The record's `policy_name` MUST be resolved through a local
  `policy name → endpoint` map maintained by the agent (Envoy knows endpoints
  only by the names the agent gave it), and the endpoint's proxy statistics
  updated with `(proxy="envoy", protocol="TCP", port, proxy_id, ingress, request,
  verdict)`. An unknown `policy_name` MUST NOT drop the flow; only the statistics
  update is skipped.
- `envoy-access-log-enabled` (default true) gates the whole server. When false,
  `L7Policy.access_log_path` and `NetworkFilter.access_log_path` MUST be left
  empty so Envoy does not connect.

### 3.2 The `cilium.*` messages flowsdn emits

#### 3.2.1 `NetworkPolicy` (NPDS)

One resource per endpoint. The **resource name is the endpoint's policy name**;
the agent uses the endpoint's IP addresses as names (`GetPolicyNames`), and an
endpoint with no IPs (the host endpoint in some configurations) produces no
resource at all and MUST be skipped without error.

| Field | # | Type | Meaning |
|---|---|---|---|
| `endpoint_ips` | 1 | repeated string | the endpoint's IPv4 and IPv6 addresses |
| `endpoint_id` | 2 | uint64 | local endpoint id |
| `ingress_per_port_policies` | 3 | repeated `PortNetworkPolicy` | sorted, §5.2 |
| `egress_per_port_policies` | 4 | repeated `PortNetworkPolicy` | sorted, §5.2 |

If a direction is not enforced, the agent MUST emit the allow-all document for
that direction: a single `PortNetworkPolicy{protocol: TCP}` with `port` 0 and no
rules. UDP and SCTP L4 policy is not sent to Envoy (Envoy only proxies TCP);
their absence is not an allow.

#### 3.2.2 `PortNetworkPolicy`

| Field | # | Type | Meaning |
|---|---|---|---|
| `port` | 1 | uint32 | 0 = wildcard (any port) |
| `end_port` | 4 | uint32 | port range end; 0 when not a range |
| `protocol` | 2 | `envoy.config.core.v3.SocketAddress.Protocol` | always `TCP` |
| `rules` | 3 | repeated `PortNetworkPolicyRule` | sorted, §5.2 |

A wildcard-port policy (`port = 0`) carries the rules that apply to every port.
Where a port-specific policy exists, lower-precedence wildcard rules MUST be
pruned from it (they can never win) and the surviving wildcard rules merged in,
so that Envoy can evaluate one port's rule list without consulting the wildcard
list. The pruning rule is: within a port, keep only rules whose precedence is
≥ the highest precedence of a port-specific `allow-all` or `deny-all` rule that
already covers the same peers.

#### 3.2.3 `PortNetworkPolicyRule` — precedence, pass and deny

| Field | # | Type | Meaning |
|---|---|---|---|
| `precedence` | 10 | uint32 | the policy engine's precedence (spec 06 §3.5.2); **higher wins** |
| `pass_precedence` | 1 | uint32 (oneof `verdict`) | set iff the verdict is *pass*: evaluation skips to rules with precedence below this value (the tier's last priority converted to a pass precedence) |
| `deny` | 8 | bool (oneof `verdict`) | set iff the verdict is *deny* |
| `proxy_id` | 9 | uint32 | proxy port of the `listener:`-named CRD listener when the rule has an explicit listener; 0 otherwise. Envoy ignores a rule whose non-zero `proxy_id` does not equal the listener's own `proxy_id` |
| `name` | 5 | string | human-readable rule name (diagnostics only) |
| `remote_policies` | 7 | repeated uint32, packed | the numeric identities this rule matches, **sorted ascending**; empty = matches any peer |
| `downstream_tls_context` | 3 | `TLSContext` | terminating TLS (§3.5.3) |
| `upstream_tls_context` | 4 | `TLSContext` | originating TLS (§3.5.3) |
| `server_names` | 6 | repeated string | SNI allow-list, sorted |
| `l7_proto` | 2 | string | unused by flowsdn |
| `http_rules` | 100 | `HttpNetworkPolicyRules` (oneof `l7`) | §3.5.1 |
| `kafka_rules` | 101 | (oneof `l7`) | **MUST NOT be emitted** — removed from the policy API at v1.20 |
| `l7_rules` | 102 | (oneof `l7`) | **MUST NOT be emitted** — generic proxylib is gone |

Construction rules the agent MUST follow:

1. Neither verdict field set = **allow**. Exactly one of `pass_precedence` /
   `deny` may be set.
2. If the rule's selector is a wildcard, `remote_policies` MUST be left empty
   (an explicit list of every identity would be both huge and racy). If the
   selector currently selects **no** identities, the rule MUST be discarded
   entirely, not emitted with an empty list — an empty list means "any".
3. A deny rule MUST NOT carry L7 rules, TLS contexts or a proxy id, and MUST be
   marked as *not short-circuitable* so Envoy keeps evaluating after an allow
   match to find it.
4. A rule with no per-selector policy (pure L3/L4 allow) is emitted with only
   precedence and `remote_policies`; everything in L7 is allowed and no TLS
   applies.
5. A rule that is empty except for its precedence carries no information and MAY
   be dropped, except where it is the only rule for a port (then it is the
   allow-all for that port).
6. Rules are sorted with §5.2 before emission. Sorting MUST be stable and total,
   because an unstable order produces a different protobuf for identical policy
   and causes a pointless Envoy update on every regeneration.

#### 3.2.4 `TLSContext`, `HttpNetworkPolicyRule`, `HeaderMatch`

`TLSContext`: `trusted_ca` (1), `certificate_chain` (2), `private_key` (3),
`server_names` (4), `validation_context_sds_secret` (5), `tls_sds_secret` (6),
`alpn_protocols` (7). Fields 1–3 are inline PEM (legacy path); 5–6 name SDS
resources (`<policy-secrets-namespace>/<hashed secret name>`) and are the
required path when secret sync is enabled. Exactly one of the two styles is used
per context; mixing them is a bug.

`HttpNetworkPolicyRules{http_rules: repeated HttpNetworkPolicyRule}` (field 1).
`HttpNetworkPolicyRule{headers: repeated envoy.config.route.v3.HeaderMatcher (1),
header_matches: repeated HeaderMatch (2)}`. A request matches a rule iff **every**
entry in `headers` matches and every `header_matches` entry either matches or is
handled by its mismatch action.

`HeaderMatch{name (1), value (2), match_action (3), mismatch_action (4),
value_sds_secret (5)}`.
`match_action ∈ {CONTINUE_ON_MATCH=0, FAIL_ON_MATCH=1, DELETE_ON_MATCH=2}`;
`mismatch_action ∈ {FAIL_ON_MISMATCH=0, CONTINUE_ON_MISMATCH=1, ADD_ON_MISMATCH=2,
DELETE_ON_MISMATCH=3, REPLACE_ON_MISMATCH=4}`. An empty `value` with
`FAIL_ON_MISMATCH` is a presence match. `value_sds_secret` replaces `value` when
the match value comes from a Secret.

#### 3.2.5 `BpfMetadata` — the listener filter

This is the filter that recovers the original destination and the source
identity. There is no `SO_ORIGINAL_DST` involved: TPROXY delivers the packet to
the listener with the original destination intact on the accepted socket, and the
filter reads `SO_MARK` for the identity.

| Field | # | Value flowsdn sets |
|---|---|---|
| `bpf_root` | 1 | the bpffs root, default `/sys/fs/bpf` (spec 01 §3.1) |
| `is_ingress` | 2 | true for the ingress listeners |
| `use_original_source_address` | 3 | `proxy-use-original-source-address` (default true) for policy listeners; the CEC annotation for CEC listeners |
| `is_l7lb` | 4 | false for policy listeners, true for CEC listeners marked L7 LB |
| `ipv4_source_address` / `ipv6_source_address` | 5, 6 | the node's Ingress IPs, only for L7-LB listeners |
| `enforce_policy_on_l7lb` | 7 | true when an ingress source address was set |
| `proxy_id` | 8 | the listener's proxy port |
| `policy_update_warning_limit` | 9 | unset |
| `l7lb_policy_name` | 10 | unset for policy listeners |
| `original_source_so_linger_time` | 11 | `envoy-http-upstream-linger-timeout` when ≥ 0, only for HTTP listeners |
| **`ipcache_name`** | 12 | **`cilium_ipcache_v2`** — the pinned name of flowsdn's ipcache (spec 03 §4.8, spec 01 §4.1). The proto's implicit default is `cilium_ipcache`, which flowsdn does **not** pin; the field MUST therefore be set explicitly on every listener, and a listener emitted without it is a bug that manifests as Envoy seeing every peer as WORLD |
| `use_nphds` | 13 | false |
| `cache_entry_ttl` / `cache_gc_interval` | 14, 15 | unset (Envoy defaults) |
| `cilium_config_source` | 16 | unset in split mode; the ADS config source in ADS mode |

Envoy reads the pinned map at `<bpf_root>/tc/globals/cilium_ipcache_v2` and needs
read access to bpffs and membership in `proxy-gid` for the sockets. On the
upstream leg the filter sets `SO_MARK = MARK_MAGIC_PROXY_{INGRESS,EGRESS} |
identity << 16` (or `MARK_MAGIC_PROXY_EGRESS_EPID | endpoint_id << 16` when
`is_l7lb`) and, when `use_original_source_address` is set, binds the original
source with `IP_TRANSPARENT`. The datapath depends on those marks (spec 02 §2.1,
spec 10 §3.10.3).

#### 3.2.6 `NetworkFilter`, `L7Policy`, `tls_wrapper`, `NetworkPolicyHosts`

- `cilium.network` — `NetworkFilter{proxylib (1), proxylib_params (2),
  access_log_path (5)}`. flowsdn MUST leave `proxylib`/`proxylib_params` empty
  (proxylib is gone) and MUST set `access_log_path` only on TCP-proxy chains; on
  HTTP chains the access log path lives in `cilium.l7policy` instead.
- `cilium.l7policy` — `L7Policy{access_log_path (1), denied_403_body (3)}`.
  `denied_403_body` is `http-403-msg` (default `Access denied`).
- `cilium.tls_wrapper` — transport socket with an empty
  `UpstreamTlsWrapperContext` / `DownstreamTlsWrapperContext`. All TLS material
  comes from the NPDS `TLSContext` or SDS; the wrapper carries no configuration.
- `cilium.NetworkPolicyHosts{policy: uint64 (1), host_addresses: repeated string (2)}`,
  resource name = the identity in decimal. Fed from ipcache events; served, not
  used (see §3.1.4).

### 3.3 Redirect lifecycle

#### 3.3.1 Proxy ports

A proxy port is a `(name, type, direction)` triple with an allocated TCP/UDP
port. Five are predefined:

| Name | Type | Direction | Listener |
|---|---|---|---|
| `cilium-http-ingress` | http | ingress | Envoy |
| `cilium-http-egress` | http | egress | Envoy |
| `cilium-tls-ingress` | tls | ingress | Envoy |
| `cilium-tls-egress` | tls | egress | Envoy |
| `cilium-dns-egress` | dns | egress | the agent's DNS proxy |

CEC listeners add dynamic entries of type `crd`, keyed by the listener's
qualified name, with no direction (they are addressed by name).

State per port: `type`, `ingress`, `port` (u16), `is_static` (true only for the
DNS proxy, whose listener cannot be reconfigured once bound), `configured`
(allocated and being set up), `acknowledged` (Envoy ACKed at least once — never
reset by a later NACK), `rules_port` (the port currently programmed into the
datapath rules), `n_redirects` (reference count).

Allocation (`§5.4`): the requested port if it is free, otherwise a random port
from a permutation of `[proxy-portrange-min, proxy-portrange-max]`
(10000–20000), skipping ports already allocated and ports already open locally.
"Open locally" MUST be determined by reading the kernel's socket tables, not by
attempting a bind. Previously-used-but-released ports are considered only on a
second pass, so a reconfigured listener tends to get its old port back.

Persistence: the allocated set MUST be written to `<state-dir>/proxy-ports.json`
(spec 10 §3.10.3) on every change, atomically (write-temp + rename). On start the
file is read and the ports pre-allocated so that a restarted agent reuses the
ports the still-running Envoy DaemonSet is already listening on. A file older
than `restored-proxy-ports-age-limit` (15 minutes) MUST be ignored. A released
port MUST NOT be reused for `portReuseDelay` = 5 minutes, so that in-flight
connections to the old listener are not misrouted.

#### 3.3.2 Creating a redirect

Input: the policy engine's `ProxyPolicy` (parser type, listener name, port,
protocol, direction, per-selector policies) and a proxy id string
`"<epid>:<ingress|egress>:<PROTO>:<port>:<listener>"` (spec 06 §4.3).

1. If a redirect with this id exists and its proxy port has the requested type,
   update the rules in place and return the existing port. This is the common
   path and MUST NOT churn ports.
2. Otherwise remove the stale redirect and create a new one:
   a. find the proxy port by (type, listener, direction) and take a reference;
   b. try the previously restored port first;
   c. up to **5** attempts: allocate a port (reallocating on retries), then
      create the implementation — for `dns`, register the rules with the DNS
      proxy (the port is static, so no Envoy round trip); for everything else,
      add the Envoy listener (§3.1.7) with a completion;
   d. on success set the rules on the redirect and register it.
3. The Envoy completion callback decides the port's fate: on ACK the port is
   **acknowledged** and the datapath rules for it are installed (nftables TPROXY
   rules per spec 10 §3.10.3, and the ip rule / table 2004 if not already
   present) even if the surrounding endpoint regeneration later fails — this
   deliberately avoids port churn. On NACK an unacknowledged, non-static port is
   released so the next attempt picks a different one (a NACK is usually
   "address already in use").
4. The allocated port is returned to the policy engine, which writes it into the
   policy map entry's `proxy_port` field (spec 06 §4.5, `htons`-encoded). The
   datapath then redirects matching packets (spec 02 §3.14).

#### 3.3.3 The datapath redirect

Summarised here; owned by specs 02 and 10.

- Policy verdict ALLOW with `proxy_port != 0` → `ctx_redirect_to_proxy`.
- With `enable-bpf-tproxy` (default false) and not from the host: set
  `MARK_MAGIC_TO_PROXY` on the skb, `sk_lookup_{tcp,udp}` for
  `127.0.0.1:<proxy_port>` / `[::1]:<proxy_port>`, `bpf_sk_assign`, release.
- Without it: set `mark = MARK_MAGIC_TO_PROXY (0x0200) | proxy_port << 16`,
  `pkt_type = HOST`, pass to the stack. nftables `mangle prerouting` matches the
  exact mark and `tproxy`-es to `127.0.0.1:<pp>` / `[::1]:<pp>`, rewriting the
  mark to `0x0200`; ip rule pref 9 `fwmark 0x200/0xf00 lookup 2004` and table
  2004's `local default dev lo` deliver it locally. A `socket transparent` rule
  ahead of the TPROXY rules re-marks packets belonging to an existing transparent
  socket so established connections skip TPROXY.
- Host egress cannot `sk_assign`; it marks and redirects into `cilium_host`
  ingress instead.
- The proxy's **upstream** leg carries `MARK_MAGIC_PROXY_{INGRESS,EGRESS} |
  identity << 16`; ip rules pref 10 send those to table 2005 (`<cilium_host ip>/32
  dev cilium_host` + default via `cilium_host`) so the upstream leg re-enters the
  BPF datapath — required with IPsec or WireGuard.
- `notrack` rules exist for both directions so conntrack is not consulted for
  proxy traffic.

Original destination recovery: for TCP through Envoy, TPROXY preserves the
original destination on the accepted socket and `cilium.bpf_metadata` reads it
plus the mark. For the DNS proxy, the listening sockets set
`IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR` and the original destination is
read from the `recvmsg` control message (§3.6.2).

#### 3.3.4 Tearing a redirect down

1. The policy engine drops the redirect from the endpoint policy; the endpoint
   manager calls remove with the proxy id.
2. The implementation is closed: for Envoy, the listener resource is deleted from
   the LDS cache with a completion (Envoy drains it); for DNS, the endpoint's
   rules for that `(port, proto)` are dropped and the regexes released to the LRU.
3. The proxy port's reference count is decremented. At zero the port is released
   **after** `portReuseDelay` (5 min) and the datapath rules for it removed.
   A static port (DNS) is never released while the agent runs.
4. `<state-dir>/proxy-ports.json` is rewritten.
5. Reverting a failed regeneration performs exactly the same steps, plus deletes
   the registered redirect.

On graceful shutdown the agent MUST leave the datapath rules and the DNS proxy
rules in place unless `dns-policy-unload-on-shutdown` is set, so that traffic
keeps being enforced across an agent restart.

### 3.4 CiliumEnvoyConfig and CiliumClusterwideEnvoyConfig

#### 3.4.1 Schema

Both CRDs share `CiliumEnvoyConfigSpec` (§4.4). `CiliumEnvoyConfig` is
namespaced; `CiliumClusterwideEnvoyConfig` is cluster-scoped. Gated by
`enable-envoy-config` (Helm `envoyConfig.enabled`); with `enable-l7-proxy=false`
the feature is inert and MUST log a warning naming the flag.

- `services[]` (`ServiceListener{name, namespace, ports []uint16, listener}`) —
  the named Service's frontends are redirected to the named Envoy listener (L7
  load balancing). `namespace` defaults to the CEC's namespace for CEC and to
  `default` for CCEC. Empty `ports` means all frontend ports. Empty `listener`
  means the first listener in `resources`.
- `backendServices[]` (`Service{name, namespace, number []string}`) — the named
  Services' backends are synced to Envoy via EDS but their traffic is not
  redirected. `number` filters by port name or number.
- `resources[]` — a list of `Any` (JSON with `@type`) holding arbitrary Envoy v3
  protos. Only these five type URLs are accepted:
  `envoy.config.listener.v3.Listener`, `envoy.config.route.v3.RouteConfiguration`,
  `envoy.config.cluster.v3.Cluster`, `envoy.config.endpoint.v3.ClusterLoadAssignment`,
  `envoy.extensions.transport_sockets.tls.v3.Secret`.
- `nodeSelector` — a label selector; nil means all nodes. Each agent MUST apply
  only the CECs whose selector matches its own node labels, and MUST re-evaluate
  on node label change (adding and removing resources accordingly).

Annotations: `cec.cilium.io/inject-cilium-filters` (default: true iff `services`
is non-empty), `cec.cilium.io/use-original-source-address`,
`cec.cilium.io/is-l7lb`.

#### 3.4.2 Parsing and rewriting

For each CEC, in the order below:

1. **Decode** each `resources[]` entry. An entry with an empty `type_url` (left
   behind by a failed JSON unmarshal) MUST be skipped, not rejected. An entry
   whose type URL is not one of the five MUST be rejected with a message naming
   the type. Decoding arbitrary Envoy extension messages nested in `Any` requires
   a descriptor registry covering the ~150 extension types (§11.2).
2. **Qualify every name** to `<namespace>/<name>/<resource>`: listeners, route
   configurations, clusters, cluster load assignments, secrets, plus every
   cross-reference — `Rds.route_config_name`, `RouteAction.cluster` and
   `weighted_clusters`, `TcpProxy.cluster`/weighted clusters,
   `SdsSecretConfig.name`, and `EnvoyInternalAddress.server_listener_name`.
   Qualification is unconditional (`ForceNamespace`), so a CEC can never
   reference another CEC's resources by accident.
3. **Fill in config sources.** Any `Rds` or `SdsSecretConfig` without a
   `config_source` gets the Cilium xDS source (cluster `xds-grpc-cilium`), so RDS
   and SDS come from the agent.
4. **Allocate an address** for every non-internal listener that has none:
   `127.0.0.1:<allocated crd proxy port>` (+ the other family as an additional
   address). The allocation takes a reference on the port and registers a
   callback that acknowledges the port when Envoy ACKs and releases it when the
   resource is withdrawn.
5. **Inject `cilium.bpf_metadata`** into every non-internal listener that does
   not already have it, with `is_l7lb` from the CEC, `proxy_id` = the listener's
   port, `use_original_source_address` from the annotation, and
   `original_source_so_linger_time` only when the listener has an HTTP connection
   manager. Internal listeners get nothing.
6. **Inject Cilium filters** when the listener's address was allocated by flowsdn
   *or* `inject-cilium-filters` is set, and the listener is not internal:
   `cilium.network` immediately before the first `http_connection_manager` or
   `tcp_proxy` filter in each chain (skipped if already present), and
   `cilium.l7policy` immediately before `envoy.filters.http.router` in each HCM.
7. **Inject the upstream filter** when downstream filters were injected for at
   least one listener: `cilium.l7policy` before `envoy.filters.http.upstream_codec`
   in each cluster's `HttpProtocolOptions`. Clusters whose transport socket is an
   upstream TLS or QUIC context are treated as ALPN-capable and get an explicit
   protocol config where one is missing.
8. **Circuit breakers**: clusters without thresholds get defaults from
   `proxy-cluster-max-{connections,requests,pending-requests}` and
   `proxy-max-concurrent-retries`.
9. **Disable `SO_REUSEPORT`** on non-internal listeners when `enable-bpf-tproxy`
   is on: BPF TPROXY and `SO_REUSEPORT` are incompatible.
10. **Validate**: every resource must have a name; duplicate qualified names
    within one CEC are rejected; each listener is proto-validated; a listener
    containing two filter chains with identical `filter_chain_match` is rejected
    (`contains filter chains with duplicate matching rules`); every EDS endpoint
    referencing an internal listener must reference one that exists in the same
    CEC. Validation runs only for **new** resources; already-applied resources
    are re-pushed unvalidated so a validator change cannot strand a live config.

#### 3.4.3 Service and backend wiring

- For each `services[]` entry the agent MUST attach a proxy redirect to the named
  service's frontends in the load-balancer tables: `ProxyRedirect{proxy_port,
  ports}` where `proxy_port` is the named listener's allocated port (spec 05 owns
  the service table; the datapath reads `svc.l7_lb_proxy_port`). Removing the CEC
  MUST remove the redirect.
- For each `services[]` and `backendServices[]` entry the agent MUST publish a
  `ClusterLoadAssignment` per (service, port) derived from the backend table,
  named `<namespace>/<service name>:<port>`, and keep it updated as backends
  change. These EDS resources have origin `backendsync` and are versioned
  independently of the CEC's own resources.
- Reconciliation is incremental: the desired resource set per origin+name is
  diffed against what Envoy has, and only the difference is pushed. A failed push
  is retried every `envoy-config-retry-interval` (15s, 0 disables) with the
  completion deadline `envoy-config-timeout` (2m). A NACK that names a port
  binding failure MUST cause the listener's port to be reallocated and the
  resource re-pushed; any other NACK MUST NOT reallocate (§7).

#### 3.4.4 Ingress and Gateway API

`enable-ingress-controller` and `enable-gateway-api` do not add an agent-side
data path. The operator translates `Ingress` and Gateway API objects into CEC or
CCEC objects; from the agent's point of view they are ordinary CECs, usually
carrying `is-l7lb` and an ingress source address. The agent's only extra duties
are secret mirroring (§3.5.4) from `ingress-secrets-namespace` and
`gateway-api-secrets-namespace`, and honouring `nodeSelector`.

### 3.5 L7 policy semantics

Only two parser types exist at v1.20: **HTTP** and **DNS**. Kafka and the generic
proxylib `l7proto` are gone from the policy API and MUST NOT be implemented.
gRPC is expressed as HTTP rules matching `:path` `/<pkg.Service>/<Method>` over
HTTP/2; there is no separate parser.

#### 3.5.1 HTTP

`PortRuleHTTP{path, method, host, headers[], headerMatches[]}` translates to one
`HttpNetworkPolicyRule`:

| Source | Produces |
|---|---|
| `path` | `HeaderMatcher{name: ":path", string_match: safe_regex(<path>)}` |
| `method` | `HeaderMatcher{name: ":method", string_match: safe_regex(<method>)}` |
| `host` | `HeaderMatcher{name: ":authority", string_match: safe_regex(<host>)}` |
| `headers[]` `"Name: value"` | `HeaderMatcher{name: "Name", string_match: exact("value")}` (split on the first space; a trailing `:` is trimmed from the name) |
| `headers[]` `"Name"` | `HeaderMatcher{name: "Name", present_match: true}` |
| `headerMatches[]` with `mismatch` absent or `FAIL` and an inline/secret value | a plain `HeaderMatcher` exact match (fail-on-mismatch needs no rewriting, so it is expressed as an ordinary matcher) |
| `headerMatches[]` with `mismatch` absent or `FAIL` and no value at all | `HeaderMatcher{present_match: true}` |
| `headerMatches[]` with `mismatch` ∈ {LOG, ADD, DELETE, REPLACE} | a `HeaderMatch` with `mismatch_action` ∈ {CONTINUE, ADD, DELETE, REPLACE}`_ON_MISMATCH` and either `value` or `value_sds_secret` |
| `headerMatches[]` whose Secret could not be read | `HeaderMatcher{name, string_match: exact(""), invert_match: true}` — a matcher that can never match, so the rule is dead. This is deliberate: a missing secret must fail closed, and Envoy treats an empty exact match as matching anything |

Rules are anchored regexes as written by the user; flowsdn MUST NOT add anchors
the user did not write (the reference passes them through unchanged), and MUST
reject a rule whose regex does not compile at policy validation time (spec 06).

`headers` MUST be sorted deterministically before emission (§5.2);
`header_matches` MUST NOT be sorted (it is a list with rewrite side effects whose
order is the user's).

**Short-circuiting.** A rule set may be evaluated with early exit only if no rule
has side effects. A rule containing any `header_matches` entry has side effects
(it can add, delete or replace headers) and MUST mark the whole port's rule set
as non-short-circuitable, as must any deny rule.

**Non-match is denied.** If no `HttpNetworkPolicyRule` in any applicable
`PortNetworkPolicyRule` matches, Envoy rejects the request with **HTTP 403** and
body `http-403-msg` (default `Access denied`), and emits an access-log entry of
type `Denied` carrying `missing_headers` / `rejected_headers`. This is what makes
an L7 rule list a whitelist. Where a direction is not default-deny, the policy
engine appends a wildcard L7 rule (`{}` for HTTP) so that unmatched traffic is
still allowed through the proxy (spec 06 §3.4); that wildcard is what turns
"L7 visibility" into "allow all, but log".

#### 3.5.2 DNS

`rules.dns[]{matchName | matchPattern}` on an egress port rule. Validation (spec
06 §3.2.6) requires a port, forbids ingress, forbids port ranges. The agent never
sends DNS rules to Envoy; they are programmed into the DNS proxy (§3.6.3).

#### 3.5.3 TLS interception

Three shapes, all on a `toPorts` rule:

1. **`terminatingTLS`** — the proxy terminates the client's TLS. Produces
   `PortNetworkPolicyRule.downstream_tls_context`. The secret must carry
   `tls.crt` and `tls.key`.
2. **`originatingTLS`** — the proxy originates TLS toward the upstream. Produces
   `upstream_tls_context`. The secret carries `ca.crt` for validation, and
   optionally a client certificate.
3. **`serverNames[]`** — an SNI allow-list. Produces `server_names`, sorted.
   Without termination this is enforced by `tls_inspector` + the TLS filter chain
   with `tcp_proxy`, so the payload is never decrypted. Combining `serverNames`
   with L7 rules but *without* `terminatingTLS` is a policy validation error
   (spec 06 §5.11) — you cannot parse HTTP you have not decrypted.

The listener's TLS filter chain (`transport_protocol: tls`, transport socket
`cilium.tls_wrapper`) is what carries these; the wrapper takes its certificates
from the NPDS rule or SDS at connection time, which is why the same listener can
serve many different rules' certificates.

#### 3.5.4 Secret sources

Three modes, in order of preference:

1. **SDS with secret sync** (`enable-policy-secrets-sync = true`, the documented
   default for new clusters): the agent mirrors referenced `Secret`s into
   `policy-secrets-namespace` under the name
   `cilium-sync-secret-<sha256(kind\0namespace\0name)>` and references them from
   NPDS as `tls_sds_secret` / `validation_context_sds_secret` /
   `value_sds_secret` = `<policy-secrets-namespace>/<synced name>`. The agent
   needs read access to one namespace only.
2. **Read-all-secrets** (`enable-policy-secrets-sync = false`,
   `policy-secrets-only-from-secrets-namespace = false`): the agent reads the
   Secret from its own namespace and inlines the PEM into the `TLSContext`.
   Requires cluster-wide Secret read and is the reason mode 1 exists.
3. **Namespace-restricted inline** (`policy-secrets-only-from-secrets-namespace = true`):
   only `policy-secrets-namespace` is read; SDS names are used.

`use-full-tls-context` retains the old behaviour of inlining `ca.crt` into a
terminating context (which makes Envoy demand a client certificate). It is
deprecated; flowsdn MUST accept the flag, MUST default it to false, and MUST log
a deprecation warning when it is set. Local files under `certificates-directory`
(`/var/run/cilium/certs`) take precedence over Kubernetes Secrets when present,
as in the reference.

The secret syncer also mirrors Secrets from `envoy-secrets-namespace`,
`ingress-secrets-namespace` and `gateway-api-secrets-namespace` into SDS
`Secret` resources (TLS certificate, CA validation context, and session ticket
keys), named `<namespace>/<name>`.

### 3.6 The DNS proxy

#### 3.6.1 Interception

A `toFQDNs` or `rules.dns` policy compiles to a redirect on the DNS port with the
static proxy port `cilium-dns-egress` (§3.3). The datapath redirects the pod's
DNS query to that port exactly like any other redirect; the pod is never
reconfigured and never learns the proxy exists. Because the DNS proxy is *in the
agent*, the port is static (`is_static`): once bound it cannot move, and it is
never released while the agent runs.

`tofqdns-proxy-port` (default 0 = OS-assigned) fixes the port. It **MUST** be set
to a non-zero value when the standalone DNS proxy is enabled, because the SDP
binds it instead.

#### 3.6.2 Sockets

The proxy binds four listeners: UDP and TCP, on IPv4 and IPv6 loopback, all on
the same port.

- Listening sockets set `SO_REUSEADDR`, `SO_REUSEPORT`,
  `IP_TRANSPARENT` / `IPV6_TRANSPARENT`, and
  `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR`.
- The **original destination** (the DNS server the pod addressed) is read from
  the `recvmsg` control message. It is required for both the policy check
  (rules are per destination port/proto and per server identity) and for
  forwarding.
- The **UDP response MUST be sent from a socket bound to the original
  destination** (server IP:53) with `IP_TRANSPARENT`, so that the pod's resolver
  sees a reply from the address it queried. A reply from the proxy's own address
  is discarded by every resolver.
- The **upstream** socket sets `SO_MARK = MARK_MAGIC_PROXY_EGRESS (0x0B00) |
  identity << 16`, so the datapath applies egress policy and encryption to the
  proxy's own query, and `SO_LINGER` = `dnsproxy-socket-linger-timeout` (10s).
- **Transparent mode** (`dnsproxy-enable-transparent-mode`, default false
  without SDP, derived true with SDP unless explicitly overridden): the
  upstream socket additionally binds the *pod's* address with `IP_TRANSPARENT`,
  so the DNS server sees the pod as the client. It MUST be skipped when the
  source is the host endpoint, the source is loopback, the destination identity
  is outside the cluster, or the destination is the local host — in those cases
  binding the pod address breaks return routing.
- Upstream sockets are pooled per `(protocol, client address, server address)` so
  many concurrent queries for one pod share one socket and one ephemeral port.
  The pool is what makes transparent mode affordable.

#### 3.6.3 Rules and matching

Per endpoint, per `(destination port, protocol)`, the proxy holds a list of
`(selector, compiled regex, allowed destination IP set)`. A query is allowed iff
some entry matches: the destination server's IP is in the entry's IP set (an
empty set is a wildcard) **and** the query name matches the entry's regex.

`matchName` → the name lower-cased and FQDN-ified (trailing dot added), then
escaped to an anchored literal regex.
`matchPattern` → §5.5.

Regexes are compiled through a bounded LRU (`fqdn-regex-compile-lru-size`,
default 1024) shared across endpoints, and reference-counted so a regex used by
several rules is compiled once.

A rejected query gets an immediate response with rcode
`tofqdns-dns-reject-response-code` (`refused` → REFUSED, default; `nameError` →
NXDOMAIN). Every other failure (cannot parse the message, cannot find the
endpoint, cannot find the original destination, upstream error) gets SERVFAIL.
An upstream **timeout** gets **no response at all** — the pod's resolver retries,
which is the correct behaviour and matches the reference.

#### 3.6.4 Request and response pipeline

For each message, in order:

1. Acquire the concurrency semaphore (§3.6.8). Failure → SERVFAIL, no forwarding.
2. Parse the request. Extract qname, qtypes.
3. Resolve the source endpoint from the source IP. No endpoint → SERVFAIL.
4. Resolve the original destination (IP, port, protocol) and look the server's
   IP up in the ipcache for its identity; a miss defaults to the appropriate
   `world` identity.
5. Policy check (§3.6.3). Denied → send the reject rcode **first**, then run the
   notification path so metrics and the access log record the denial.
6. Forward upstream **over the same L4 protocol** the client used, so a client
   that retried over TCP after truncation stays on TCP.
7. On the response: parse it, run the notification path (§3.6.5) — which is where
   the response is *held* — then set `response.Id` back to the client's original
   id (the pooled upstream socket may have rewritten it), set `Compress` per
   §3.6.6, and write it.
8. Record the server address in the set of used DNS servers (used for the
   restore path's IP set).

#### 3.6.5 The response hold — mandatory ordering

When an allowed response carries answers (`RCODE == NOERROR` and at least one
address record), the proxy MUST perform the following **before** the response
reaches the pod:

1. Take the per-name lock (§3.6.8).
2. Insert the answer into the endpoint's DNS cache with the effective TTL
   (§3.6.7), and force-expire any zombie entries for the same (name, IP) pairs.
   This must happen before step 3 so that a regeneration triggered by step 3
   serialises a cache that already contains the new IPs.
3. Serialise the endpoint's state (cache + rules) to its state file.
4. Ask the name manager to recompute which FQDN selectors now match this name,
   upsert the resulting ipcache metadata (resource `fqdn-name-manager:<name>`,
   source `Generated`, labels `fqdn:<selector pattern>`), allocate identities as
   needed, and **wait for the ipcache/policy revision to be applied to the BPF
   maps**.
5. Release the name lock, then write the response.

The wait is bounded by `tofqdns-proxy-response-max-delay` (default 100 ms). On
timeout the response is released anyway and
`cilium_proxy_datapath_update_timeout_total` is incremented with a log line
naming the flag.

**Why the ordering is mandatory.** The pod will connect to the returned IP within
microseconds of receiving the response. If the response is delivered before the
ipcache carries the `fqdn:` label and before the endpoint's policy map contains
an entry for the resulting identity, the very first packet is dropped by policy.
The pod's application sees a connection failure on a name its policy explicitly
allows. Holding the response is the only way to close that race, and the per-name
lock is what stops two concurrent lookups of the same name from each concluding
"someone else already did the work" and both releasing early.

#### 3.6.6 EDNS, truncation and compression

- The client's EDNS0 OPT record, when present, gives the UDP payload size the
  client accepts. The proxy MUST honour it when deciding whether the response
  fits.
- `tofqdns-enable-dns-compression` (default true): the response is compressed
  when it is larger than the client's advertised buffer size, or larger than 512
  bytes when the client advertised none. Compression is applied only when it is
  needed, so that responses stay byte-identical to upstream in the common case.
- The proxy MUST NOT alter the TC bit or re-truncate: it forwards the upstream
  server's decision. A client that retries over TCP is handled by §3.6.4 step 6.

#### 3.6.7 Cache, zombies, TTL and GC

**DNS cache** (per endpoint): forward index name → entries, reverse index IP →
names. An entry is `{name, lookup_time, expiration_time, ttl, ips}`.

- The effective TTL is `max(ttl, tofqdns-min-ttl)` (default min 0, i.e. the
  server's TTL is used as-is).
- `tofqdns-endpoint-max-ip-per-hostname` (default 1000) caps the IPs kept per
  name per endpoint; over-limit entries are evicted oldest-first.
- GC runs periodically: expired entries are removed; each removed IP that is
  still referenced by an active connection becomes a **zombie**.

**Zombies** (`DNSZombieMappings`): an IP whose DNS entry expired but which
conntrack still shows in use. A zombie keeps the ipcache entry and the identity
alive so an in-flight connection is not killed by the name expiring.

- Bounded by `tofqdns-max-deferred-connection-deletes` (default 10000) globally
  and by the per-host limit.
- A zombie is marked alive whenever the conntrack GC sweep sees its IP; a zombie
  not seen for `tofqdns-idle-connection-grace-period` (default 0s) after its
  entry expired is deleted.
- Over-limit eviction prefers the least recently alive.
- A new answer for the same (name, IP) force-expires the zombie (§3.6.5 step 2).

**Name manager GC** removes ipcache metadata for names that no selector matches
any more, and releases the identities. `cilium_fqdn_gc_deletions_total` counts
the names removed.

**Identity preallocation** (`tofqdns-preallocate-identities`, default true): when
an FQDN selector is first registered, identities for its label set are allocated
before any lookup, so step 4 of §3.6.5 usually does not have to round-trip to the
identity allocator. This interacts with the local identity range (spec 03).

#### 3.6.8 Concurrency and locking

- `dnsproxy-concurrency-limit` (default 0 = unlimited) is a semaphore over
  in-flight DNS messages. When it is exhausted:
  - with `dnsproxy-concurrency-processing-grace-period` = 0 (default), acquisition
    is a non-blocking try; failure is immediate;
  - otherwise acquisition blocks up to the grace period and then fails as a
    timeout.
  Either failure MUST: increment `cilium_fqdn_semaphore_rejected_total`, log at
  error **rate-limited** (a burst of rejections must not itself become the load),
  emit the access-log record with verdict `error`, and answer **SERVFAIL**. It
  MUST NOT forward the query.
- `dnsproxy-lock-count` (default 131, prime) striped mutexes are keyed by qname
  hash and serialise §3.6.5 per name. Acquisition taking longer than
  `dnsproxy-lock-timeout` (500 ms) MUST log a warning naming both flags; it is
  a warning, not a failure — the lock is still taken.

#### 3.6.9 Restore across restarts

Two artefacts survive an agent restart:

1. **Per-endpoint DNS rules**, serialised into the endpoint's state file as
   `restore.DNSRules` = `map<PortProto, []IPRule>` where `PortProto` is
   `1<<24 | proto<<16 | port` and `IPRule = {Re: <regex string>, IPs: set of IP
   or CIDR}`. `dns-max-ips-per-restored-rule` (default 1000) caps the IP set per
   rule. A nil IP set is a wildcard.
2. **The DNS cache and zombies**, JSON in the same endpoint state file.

On start the proxy MUST load the restored rules before binding, and enforce them
for endpoints that have not yet been regenerated. Restored rules are matched by
IP (the identity for the server may not exist yet), which is why the IP set is
serialised alongside the regex. Restored rules for an endpoint are dropped as
soon as that endpoint's real rules are installed, and on endpoint deletion.

Restored rules referencing addresses from a remote cluster MUST be dropped on
load (they cannot be validated locally).

The proxy port itself is restored from `<state-dir>/proxy-ports.json` (§3.3.1),
so the datapath rules and the listener agree across the restart.

### 3.7 The standalone DNS proxy

#### 3.7.1 Why it exists

The in-agent DNS proxy dies with the agent. During an agent restart — an upgrade,
a crash, a rollout — every DNS query from every pod on the node with a `toFQDNs`
policy is unanswered, and the restore path (§3.6.9) only closes the gap after the
new agent has bound its sockets. The standalone DNS proxy (SDP) moves the
sockets into a separate process with its own lifecycle: it keeps answering from
its rule table while the agent is down. It cannot allocate identities for
*new* names while the agent is down (the response hold has no one to talk to), so
lookups of already-known names keep working and genuinely new names fail closed.

**Decision (#201): flowsdn ships it.** The DNS proxy MUST be built as a library
crate (`flowsdn-dnsproxy`) with a `PolicySource` trait from the first commit; the
in-agent proxy implements it against the policy engine and the SDP implements it
against the gRPC stream. Building the library first and the binary second costs
almost nothing; retrofitting the split later is a rewrite. The binary is small
(§11.3) and it removes the single worst availability artefact of the design.

#### 3.7.2 Protocol

`standalonednsproxy.FQDNData`, gRPC, plaintext, TCP `localhost:<standalone-dns-proxy-server-port>`
(default 10095), with keepalives. Two methods:

- `rpc StreamPolicyState(stream PolicyStateResponse) returns (stream PolicyState)` —
  the SDP opens the stream; the **agent** pushes full snapshots
  `PolicyState{egress_l7_dns_policy[], request_id, identity_to_endpoint_mapping[],
  identity_to_prefix_mapping[]}` and the SDP acknowledges each with
  `PolicyStateResponse{response, request_id}`. Snapshots are complete, never
  deltas: a snapshot replaces the SDP's whole table. Any error on either side
  tears the stream down and the SDP re-subscribes with backoff.
- `rpc UpdateMappingRequest(FQDNMapping) returns (UpdateMappingResponse)` — the
  SDP reports each allowed response's `{fqdn, record_ip[], ttl, source_identity,
  source_ip, response_code, metrics_data}`. The agent runs the same notification
  path as the in-agent proxy (cache, ipcache, access log, metrics) and answers a
  `ResponseCode`. **The SDP MUST hold the DNS response until this RPC returns**,
  which is how the §3.6.5 ordering contract survives the process split.

Response codes: `NO_ERROR=1`, `FORMAT_ERROR=2`, `SERVER_FAILURE=3`,
`NOT_IMPLEMENTED=4`, `ERROR_ENDPOINT_NOT_FOUND=5`, `ERROR_INVALID_ARGUMENT=6`,
`REFUSED=7` (`UNSPECIFIED=0`).

`MetricsData` carries what the agent needs to emit the same metrics and access
log records it would have emitted itself: `ProcessingStats` (total, processing,
upstream, semaphore-acquire, policy-check nanoseconds), `DNSResponseData`
(is_response, cnames, qtypes, answer_types), source port, server address and
identity, protocol, allowed, error message, and a structured `ProxyErrorType`
(`NONE`, `PROXY`, `TIMEOUT`, `SEMAPHORE_FAILED`, `SEMAPHORE_TIMED_OUT`) so the
error classification survives serialisation.

Enabling it requires `enable-standalone-dns-proxy=true`,
`standalone-dns-proxy-server-port != 0` **and** `tofqdns-proxy-port != 0`. The
agent MUST refuse to start with a clear message if the SDP is enabled and the DNS
proxy port is left OS-assigned.

The SDP's runtime directory is `/var/run/standalone-dns-proxy`. It MUST NOT
require BPF map access: everything it needs (endpoint IP → id, IP → identity)
arrives in `PolicyState`.

### 3.8 Mutual authentication — deferred

Mutual authentication (SPIFFE/SPIRE) is **deferred**. It is deprecated upstream at
v1.20 and ztunnel is the successor for mTLS. flowsdn MUST NOT implement the
handshake, the SPIRE delegated-identity client or the auth manager at this time.

What flowsdn MUST do now, so the datapath does not have to be redesigned later:

- Reserve and document the map (§4.7). The datapath spec's policy entry already
  carries an `auth_type` byte (spec 06 §4.5).
- Accept `authentication.mode` in the policy API. `disabled` is the only value
  that may be honoured; `required` and `test-always-fail` MUST be **rejected at
  policy validation** with `mutual authentication is not implemented`, rather
  than silently allowed — silently allowing would turn an authentication
  requirement into a plain allow, which is a security regression.
- Accept and ignore the `mesh-auth-*` flags, documented as no-ops (§6).

The contract a future implementation must satisfy: the datapath's `auth_lookup`
consults `cilium_auth_map` with `(local_sec_label, remote_sec_label,
remote_node_id, auth_type)`; a miss or an expired entry drops the packet with
`DROP_POLICY_AUTH_REQUIRED` and raises a `SIGNAL_AUTH_REQUIRED` perf event
carrying the key; userspace performs the handshake with the peer node's agent and
writes an expiry into the map; GC removes entries for deleted nodes, deleted
identities, endpoints without auth policy, and expired entries.

### 3.9 ztunnel — deferred

Istio ambient / ztunnel integration is **deferred** (beta upstream). Summary of
the handoff, recorded so the eventual implementation starts from a specification
rather than from reading Istio:

- **ZDS**: a `SOCK_SEQPACKET` unix server at `/var/run/cilium/ztunnel.sock`.
  ztunnel connects and sends `ZdsHello{version}`. The agent sends
  `WorkloadRequest{oneof: Add AddWorkload{uid, WorkloadInfo{name, namespace,
  service_account, trust_domain}} | Keep KeepWorkload{uid} | Del DelWorkload{uid}
  | SnapshotSent}`; an `Add` carries the pod's **netns file descriptor as
  `SCM_RIGHTS` ancillary data**. ztunnel replies `WorkloadResponse{Ack{error}}`.
  The initial exchange is an `Add` for every enrolled endpoint followed by
  `SnapshotSent`.
- **Enrolment**: namespaces labelled `io.cilium/mtls-enabled=true`; every endpoint
  in them requires the nftables implementation of the reference traffic
  redirection semantics inside the pod netns
  (marks `0x111`/`0x539` mask `0xfff`, route table 100, rule priority 32764,
  ports 15008/15001/15006) and an `AddWorkload`.
- **Workload xDS**: delta-only ADS on `127.0.0.1:15012` over TLS, serving
  `type.googleapis.com/istio.workload.Address` derived from CiliumEndpointSlices,
  and an always-empty `istio.security.Authorization`.
- **CA**: `/istio.v1.auth.IstioCertificateService/CreateCertificate`; the CSR must
  carry exactly one URI SAN `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` and a local
  endpoint with that namespace/service-account must exist. 30-day certificates.

ADR-0015 selects Rust nftables transactions inside the pod namespace. There
is no iptables exception. The marks/routes/ports and ZDS behavior above remain
the compatibility contract, with privileged enrollment/rollback tests required
before activation; until then explicit ztunnel enablement is rejected.

---

## 4. Data model

### 4.1 `cilium/proxy` protobuf set

flowsdn MUST generate Rust types from the pinned `.proto` files of
`github.com/cilium/proxy` (Apache-2.0; copying the `.proto` files is explicitly
permitted by `docs/licensing.md` with header attribution and a `NOTICE` entry):
`npds.proto`, `nphds.proto`, `bpf_metadata.proto`, `network_filter.proto`,
`l7policy.proto`, `tls_wrapper.proto`, `accesslog.proto`,
`health_check_sink.proto`, `websocket.proto`. Field-by-field layouts are in
§3.2. `websocket.proto` (`WebSocketClient`/`WebSocketServer`) and
`health_check_sink.proto` (`HealthCheckEventPipeSink{path}`) MUST be generated
but never emitted.

### 4.2 `cilium.LogEntry` (access log)

| Field | # | Type |
|---|---|---|
| `timestamp` | 1 | uint64, nanoseconds |
| `entry_type` | 3 | enum `{Request=0, Response=1, Denied=2}` |
| `policy_name` | 4 | string (the NPDS resource name = an endpoint IP) |
| `cilium_rule_ref` | 5 | string |
| `source_security_id` | 6 | uint32 |
| `source_address` | 7 | string `ip:port` |
| `destination_address` | 8 | string `ip:port` |
| `is_ingress` | 15 | bool |
| `destination_security_id` | 16 | uint32 |
| `proxy_id` | 17 | uint32 |
| `http` | 100 | `HttpLogEntry` (oneof `l7`) |
| `kafka` | 101 | never produced |
| `generic_l7` | 102 | `L7LogEntry{proto, fields map}` — never produced |

`HttpLogEntry{http_protocol (1) ∈ {HTTP10=0, HTTP11=1, HTTP2=2}, scheme (2),
host (3), path (4), method (5), headers (6) repeated KeyValue, status (7),
missing_headers (8), rejected_headers (9)}`.

### 4.3 Internal `LogRecord`

The common record produced by both Envoy (from `LogEntry`) and the DNS proxy, and
the input to the Hubble L7 flow encoder. Fields (JSON names preserved for the
`flowsdn-dbg` dump): `type` ∈ `request|response|sample`; `verdict` ∈
`forwarded|denied|redirected|error`; `node_address_info`; `observation_point` ∈
`ingress|egress`; `source_endpoint` and `destination_endpoint`
(`{id, ipv4, ipv6, port, identity, labels}`); `ip_version`; `transport_protocol`;
`service_info`; `drop_reason`; `timestamp`; and exactly one of
`http{code, method, url, protocol, headers, missing_headers, rejected_headers}`,
`dns{query, ips, ttl, cnames, observation_source, rcode, qtypes, answer_types}`,
`l7{proto, fields}`.

For DNS the observation point is **always egress**, regardless of whether the
record describes a request or a response; the direction is expressed by `type`.

### 4.4 CEC / CCEC CRDs (`cilium.io/v2`)

```
CiliumEnvoyConfigSpec {
  services         []ServiceListener   // {name, namespace, ports []uint16, listener string}
  backendServices  []Service           // {name, namespace, number []string}   (JSON key "number")
  resources        []XDSResource       // anypb.Any, JSON with "@type"; required
  nodeSelector     *LabelSelector      // nil = all nodes
}
```

`CiliumEnvoyConfig` short name `cec`, namespaced; `CiliumClusterwideEnvoyConfig`
short name `ccec`, cluster-scoped. Both are storage version v2 and print the
creation timestamp as `Age`. The `resources` field round-trips through
protobuf-JSON, so unknown fields inside a resource are an error at decode time,
not silently dropped.

### 4.5 DNS restore format

`DNSRules = map<PortProto, []IPRule>` where `PortProto: u32`:

| Bits | Meaning |
|---|---|
| 0–15 | port |
| 16–23 | IP protocol number (v2 only) |
| 24 | 1 for v2; absent (0) for the legacy protocol-agnostic v1 |
| 25–31 | zero |

`IPRule{Re: RuleRegex, IPs: set<RuleIPOrCIDR>}`. `RuleIPOrCIDR` marshals as a
bare IP when it is a single address and as a CIDR otherwise, so the JSON is
compatible with both the v1 (IP) and v2 (prefix) readers. A nil/absent IP set is
a wildcard.

flowsdn MUST read both v1 and v2 keys (an upgrade from a Cilium-managed node) and
MUST write v2.

### 4.6 SDP protocol messages

See §3.7.2 for semantics. Message list, for the code generator:
`PolicyState{egress_l7_dns_policy (1), request_id (2), identity_to_endpoint_mapping (3),
identity_to_prefix_mapping (4)}`;
`DNSPolicy{source_endpoint_id (1), dns_pattern (2), dns_servers (3)}`;
`DNSServer{dns_server_identity (1), dns_server_port (2), dns_server_proto (3)}`;
`IdentityToEndpointMapping{identity (1), endpoint_info (2)}`;
`EndpointInfo{id (1), ip (2) repeated bytes}`;
`IdentityToPrefixMapping{identity (1), prefix (2) repeated bytes}`;
`PolicyStateResponse{response (1), request_id (2)}`;
`FQDNMapping{fqdn (1), record_ip (2), ttl (3), source_identity (4), source_ip (5),
response_code (6), metrics_data (7)}`;
`MetricsData{processing_stats (1), dns_response_data (2), source_port (3),
server_addr (4), server_identity (5), protocol (6), allowed (7), error_message (8),
error_type (9)}`;
`ProcessingStats{total_time_ns (1), processing_time_ns (2), upstream_time_ns (3),
semaphore_acquire_time_ns (4), policy_check_time_ns (5)}`;
`DNSResponseData{is_response (1), cnames (2), qtypes (3), answer_types (4)}`;
`UpdateMappingResponse{response (1)}`.

### 4.7 `cilium_auth_map` (reserved, not implemented)

| | Layout |
|---|---|
| Type | `BPF_MAP_TYPE_HASH` |
| Key | `auth_key{ local_sec_label u32 @0, remote_sec_label u32 @4, remote_node_id u16 @8 (0 = local), auth_type u8 @10, pad u8 @11 }` — 12 bytes |
| Value | `auth_info{ expiration u64 }` — 8 bytes, units of 512 ns since boot-time epoch |
| Max entries | `bpf-auth-map-max` |
| Pin | `<bpf_root>/tc/globals/cilium_auth_map` |
| Owner | agent (deferred) |

`auth_type` 1 = SPIRE mutual TLS. Spec 01 owns the map catalogue; this entry is
reserved there so the numbering does not move when the feature lands.

### 4.8 Files

| Path | Written by | Content |
|---|---|---|
| `<state-dir>/proxy-ports.json` | agent | allocated proxy ports (§3.3.1) |
| `<state-dir>/<epid>/…` endpoint state | agent | DNS rules (§4.5), DNS cache, zombies |
| `<run-dir>/envoy/sockets/xds.sock` | agent | gRPC, 0660, group `proxy-gid` |
| `<run-dir>/envoy/sockets/access_log.sock` | agent | SOCK_SEQPACKET, 0660, group `proxy-gid` |
| `<run-dir>/envoy/sockets/admin.sock` | Envoy | HTTP admin, 0660 |
| `<run-dir>/envoy/bootstrap-config.json` | chart (ConfigMap) | Envoy bootstrap (§3.1.6) |

---

## 5. Algorithms

### 5.1 Emitting a `NetworkPolicy` from an endpoint policy

The NPDS document MUST be a **pure function** of the endpoint's selector policy,
the selector snapshot, the endpoint's IPs and id, and the redirect port map.
Purity is what makes the document diffable: two agents with the same policy input
must produce byte-identical protobufs, and a regeneration that changed nothing
must produce the same bytes so no Envoy update is sent.

Per direction:

1. If the direction is not enforced, emit the allow-all wildcard and stop.
2. For each L4 filter, for each selector in it, build a `PortNetworkPolicyRule`
   per §3.2.3. Discard rules whose selector currently selects nothing.
3. Group rules by `(port, end_port)`; track, per port, the highest-precedence
   port-specific allow-all and deny-all rule.
4. Merge the wildcard-port (`port = 0`) rule set into each port's set, dropping
   wildcard rules whose precedence is below that port's allow-all/deny-all
   precedence.
5. Sort rules (§5.2), then sort the port policies (§5.2).
6. Track, per precedence level, whether the rule set can be short-circuited
   (§3.5.1). A single non-short-circuitable rule poisons its precedence level.

### 5.2 Deterministic ordering

`PortNetworkPolicy` list: by protocol ascending, then port ascending, then rule
count ascending, then element-wise by rule comparison.

`PortNetworkPolicyRule` comparison, in order:
1. **precedence descending** (highest precedence first — this is the evaluation
   order, so the sort is also the semantics);
2. rules without HTTP rules before rules with them;
3. when both have HTTP rules: fewer rules first, then element-wise by HTTP rule
   comparison;
4. fewer `remote_policies` first, then element-wise ascending numeric identity.

`HttpNetworkPolicyRule` comparison: fewer `headers` first, then element-wise by
`HeaderMatcher` comparison (name, then match kind, then match value).
`remote_policies` and `server_names` are sorted ascending within a rule.
`header_matches` is **not** sorted.

### 5.3 xDS version and watch

Per type URL: `version: u64`, `resources: BTreeMap<String, Any>`. Every mutation
increments `version` and notifies watchers. A watcher for a stream holds
`(last_sent_nonce, last_acked_version, requested_names)` and wakes when
`version > last_sent_nonce`. The response contains the resources named in the
request (or all of them when the request names none), `version_info` and `nonce`
both set to the new version. A pending watch is cancelled and restarted whenever
a new request arrives on that stream for that type.

### 5.4 Proxy port allocation

```
allocate(requested, min, max):
  open = ports currently open locally (from the kernel socket tables)
  if requested != 0 and available(requested, reuse=false): return requested
  perm = random permutation of [0, max-min]
  for reuse in [false, true]:
    for r in perm:
      p = min + r
      if available(p, reuse): return p
  error "no available proxy ports"

available(p, reuse) =
     p != 0
  && !(p in allocated and (allocated[p] == in_use or !reuse))
  && p not in open
```

`allocated` maps port → in-use flag; a released port stays in the map with the
flag cleared so the second pass can reuse it.

### 5.5 `matchPattern` → regex

1. Trim surrounding whitespace; lower-case.
2. If the pattern is entirely asterisks with an optional trailing dot
   (`*`, `**`, `**.`, `***`, …), the result is
   `(^([-a-zA-Z0-9_]+[.])+$)|(^[.]$)` (anchored form) or `.*` (un-anchored form
   used when or-ing several patterns together).
3. Otherwise: FQDN-ify (append a trailing dot if absent), then
   a. replace every `.` with `[.]`,
   b. replace a **prefix** of two or more asterisks followed by `[.]` with
      `([-a-zA-Z0-9_]+([.][-a-zA-Z0-9_]+){0,})[.]` — this is what makes `**.x`
      match any number of subdomain labels *and* `x` itself,
   c. replace every remaining run of one or more asterisks with
      `[-a-zA-Z0-9_]*` — a single `*` matches within one label only, never across
      a dot,
   d. anchor: `^…$`.

Validation before translation: the pattern must be ≤ 255 characters
(`MaxFQDNLength`) after trimming, and must match `^[-a-zA-Z0-9_.*]+$`. A
`matchName` is FQDN-ified, lower-cased and escaped as a literal.

Two implementations must produce the *same matches*, not necessarily the same
regex string — but flowsdn MUST produce the same string as the reference, because
the string is serialised into the restore file (§4.5) and read back by a
possibly-different version.

### 5.6 Response-hold state machine

| State | Event | Next | Action |
|---|---|---|---|
| idle | request received | limited | acquire semaphore, else → error |
| limited | parsed, endpoint+destination resolved | checked | policy check |
| checked | denied | done | send reject rcode, log, release |
| checked | allowed | forwarding | forward upstream with `SO_MARK` |
| forwarding | upstream timeout | done | log, **no response**, release |
| forwarding | upstream error | done | SERVFAIL, log, release |
| forwarding | response, no A/AAAA or rcode ≠ 0 | done | write response, log |
| forwarding | response with answers | holding | take name lock, update cache, sync state file, upsert ipcache, await datapath revision |
| holding | datapath applied | done | release lock, write response |
| holding | `tofqdns-proxy-response-max-delay` elapsed | done | count timeout, release lock, write response anyway |

---

## 6. Configuration

Keys are reference-compatible names. "Ignored" keys are accepted so existing
`cilium-config` ConfigMaps apply unchanged.

### 6.1 L7 proxy and Envoy

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-l7-proxy` | bool | true | master switch; false rejects all L7 policy (spec 06) |
| `external-envoy-proxy` | bool | true | **DEVIATION**: only `true` is supported (§3.1.1) |
| `envoy-xds-mode` | string | `split` | only `split` supported (§3.1.3) |
| `proxy-gid` | uint | 1337 | group for the control-plane sockets |
| `proxy-connect-timeout` | uint (s) | 2 | cluster connect timeout |
| `proxy-initial-fetch-timeout` | uint (s) | 30 | xDS config source initial fetch |
| `proxy-max-active-downstream-connections` | int64 | 50000 | overload manager |
| `proxy-max-requests-per-connection` | int | 0 | 0 = unlimited |
| `proxy-max-connection-duration-seconds` | int | 0 | 0 = unlimited |
| `proxy-idle-timeout-seconds` | int | 60 | upstream idle |
| `proxy-max-concurrent-retries` | u32 | 128 | circuit breaker |
| `proxy-cluster-max-connections` / `-requests` / `-pending-requests` | u32 | 1024 | circuit breakers |
| `proxy-xff-num-trusted-hops-ingress` / `-egress` | u32 | 0 | HCM XFF |
| `proxy-use-original-source-address` | bool | true | `BpfMetadata.use_original_source_address` for policy listeners |
| `proxy-portrange-min` / `-max` | u16 | 10000 / 20000 | proxy port range |
| `restored-proxy-ports-age-limit` | uint (min) | 15 | stale-file threshold |
| `proxy-prometheus-port` | int | 0 | chart-rendered Envoy metrics listener; 0 disables |
| `proxy-admin-port` | int | 0 | chart-rendered Envoy admin listener; 0 disables |
| `envoy-access-log-enabled` | bool | true | access log server + filter paths |
| `envoy-access-log-buffer-size` | uint | 16384 | seqpacket read buffer; valid range 1–1048576 bytes |
| `envoy-policy-restore-timeout` | duration | 3m | restore barrier (§3.1.4) |
| `envoy-http-upstream-linger-timeout` | int (s) | -1 | `original_source_so_linger_time`; -1 = unset |
| `envoy-node-locality-enabled` | bool | false | zone-aware bootstrap; requires the zone label |
| `envoy-default-log-level` | string | "" | Envoy log level override |
| `disable-envoy-version-check` | bool | false | skip the `/server_info` check |
| `http-normalize-path` | bool | true | RFC3986 normalise + merge slashes + unescape/redirect |
| `http-request-timeout` | uint (s) | 3600 | route timeout; 0 = unlimited |
| `http-idle-timeout` | uint (s) | 0 | non-gRPC route idle timeout |
| `http-max-grpc-timeout` | uint (s) | 0 | `grpc_timeout_header_max` |
| `http-retry-count` | uint | 3 | retries on 5xx |
| `http-retry-timeout` | uint (s) | 0 | per-try timeout |
| `http-stream-idle-timeout` | uint (s) | 300 | HCM stream idle |
| `http-403-msg` | string | `Access denied` | `L7Policy.denied_403_body` |
| `enable-bpf-tproxy` | bool | false | `sk_assign` path; also disables listener `SO_REUSEPORT` |
| `enable-envoy-config` | bool | false | CEC/CCEC |
| `envoy-config-timeout` | duration | 2m | CEC ACK deadline |
| `envoy-config-retry-interval` | duration | 15s | CEC retry; 0 disables |
| `envoy-secrets-namespace` | string | — | secret sync source |
| `enable-ingress-controller` / `ingress-secrets-namespace` | bool / string | false / — | secret sync for Ingress |
| `enable-gateway-api` / `gateway-api-secrets-namespace` | bool / string | false / — | secret sync for Gateway API |
| `enable-policy-secrets-sync` | bool | false | SDS mode for policy secrets |
| `policy-secrets-namespace` | string | — | destination namespace for synced policy secrets |
| `policy-secrets-only-from-secrets-namespace` | bool | false | read policy secrets from that namespace only |
| `use-full-tls-context` | bool | false | deprecated `ca.crt` inlining; warns |
| `certificates-directory` | string | `/var/run/cilium/certs` | local certificate/secret override |

Accepted and **ignored**: `envoy-log`, `envoy-base-id`,
`envoy-keep-cap-netbindservice` (all embedded-Envoy only; §3.1.1).

### 6.2 DNS proxy and FQDN

| Key | Type | Default | Effect |
|---|---|---|---|
| `tofqdns-proxy-port` | int | 0 | fixed DNS proxy port; 0 = OS-assigned. MUST be non-zero with SDP |
| `tofqdns-dns-reject-response-code` | string | `refused` | `refused` \| `nameError` |
| `tofqdns-min-ttl` | int (s) | 0 | TTL floor |
| `tofqdns-endpoint-max-ip-per-hostname` | int | 1000 | per-name IP cap per endpoint |
| `tofqdns-max-deferred-connection-deletes` | int | 10000 | zombie cap |
| `tofqdns-idle-connection-grace-period` | duration | 0s | zombie liveness grace |
| `tofqdns-proxy-response-max-delay` | duration | 100ms | response hold bound (§3.6.5) |
| `tofqdns-enable-dns-compression` | bool | true | compress oversized responses |
| `tofqdns-preallocate-identities` | bool | true | preallocate identities per selector |
| `dns-max-ips-per-restored-rule` | int | 1000 | IP cap per restored rule |
| `dns-policy-unload-on-shutdown` | bool | false | drop DNS rules on graceful shutdown |
| `fqdn-regex-compile-lru-size` | uint | 1024 | regex LRU (hidden) |
| `dnsproxy-concurrency-limit` | int | 0 | in-flight message semaphore; 0 = unlimited |
| `dnsproxy-concurrency-processing-grace-period` | duration | 0 | wait before rejecting |
| `dnsproxy-lock-count` | int | 131 | striped per-name mutexes (hidden) |
| `dnsproxy-lock-timeout` | duration | 500ms | warn threshold (hidden) |
| `dnsproxy-socket-linger-timeout` | int (s) | 10 | upstream `SO_LINGER` |
| `dnsproxy-enable-transparent-mode` | bool | false; derived true with SDP when unset | bind the pod's address upstream; explicit false/true wins (#197) |
| `enable-standalone-dns-proxy` | bool | false | SDP gRPC server |
| `standalone-dns-proxy-server-port` | int | 10095 | SDP gRPC port |

Accepted and **ignored**: `tofqdns-pre-cache` (removed upstream at v1.21),
`dnsproxy-insecure-skip-transparent-mode-check`.

### 6.3 Deferred features

Accepted and **ignored**, with a warning when set to a non-default value:
`mesh-auth-enabled`, `mesh-auth-queue-size`, `mesh-auth-gc-interval`,
`mesh-auth-signal-backoff-duration`, `mesh-auth-mutual-listener-port`,
`mesh-auth-mutual-connect-timeout`, `mesh-auth-spire-admin-socket`,
`mesh-auth-spiffe-trust-domain`, `mesh-auth-rotated-identities-queue-size`,
`bpf-auth-map-max`. An explicit `enable-ztunnel=true` must instead be rejected
until the ADR-0015 nftables enrollment path is implemented; never accept it
as an ignored request for mesh encryption. Note that `authentication.mode: required`
in a policy is a **validation error**, not an ignored setting (§3.8).

---

## 7. Failure modes

| Failure | Behaviour |
|---|---|
| **Envoy not running / socket not connected** | xDS caches keep accepting mutations; completions time out and fail their regenerations. Redirects whose listener never ACKed keep their port unacknowledged, so **no datapath rules are installed** and traffic is not redirected into a black hole. Health status reports `envoy: not connected`. The agent MUST NOT crash and MUST NOT drop the cache — a reconnect resumes from the current version |
| **Envoy restarts** | New streams arrive with `version_info` = the last version it ACKed and an empty nonce. Treated as a fresh stream; the full current state is sent. Ports are reused from `<state-dir>/proxy-ports.json`, so listeners come back on the same ports and the datapath rules stay valid |
| **NACK on a listener** | The mutation is reverted, the completion fails, the port is released if it was never acknowledged, and the redirect creation is retried with a new port up to 5 times. The server MUST NOT resend the rejected version |
| **NACK loop** (Envoy rejects every version) | Because a NACK never triggers a resend, the loop is bounded by the rate of genuine mutations. The agent MUST rate-limit the NACK log line, MUST surface `cilium_xds_events_count{status="nack"}` and MUST report the type URL and detail in `flowsdn-dbg status`. A CEC whose resources are structurally invalid keeps NACKing on every reconcile: the retry interval (15s) bounds it, and the CEC's status MUST record the last error |
| **Proxy port exhaustion** | Allocation fails after both passes over the 10000-port range; the redirect creation fails and the endpoint regeneration retries with backoff. `cilium_policy_missing_proxy_redirects` rises. Policy entries needing the missing redirect are omitted, which is fail-closed only if the direction is default-deny — this is why the metric must be alerted on |
| **`proxy-ports.json` missing, corrupt or stale** | Treated as absent: all ports are freshly allocated. Listeners move, datapath rules are reinstalled. Traffic in flight to old ports is lost. A stale file (older than `restored-proxy-ports-age-limit`) MUST be ignored rather than trusted |
| **Access log socket backs up** | Envoy's writes fail; Envoy drops records. The agent MUST NOT block Envoy: the reader is a dedicated task per connection, and record handling that cannot keep up drops the record and counts it, never applies backpressure into the socket |
| **Truncated access log record** | Discarded with a warning naming `envoy-access-log-buffer-size` (§3.1.9) |
| **DNS proxy overload** | The concurrency semaphore rejects; SERVFAIL is returned immediately, `cilium_fqdn_semaphore_rejected_total` rises, the log is rate-limited. This is a deliberate load-shed: forwarding beyond the limit would exhaust upstream sockets and make every query slow instead of some queries fail fast |
| **ipcache update lag** (§3.6.5 step 4 slow) | The response is held up to `tofqdns-proxy-response-max-delay` and then released regardless, incrementing `cilium_proxy_datapath_update_timeout_total`. The pod may see a brief policy drop on its first connection. Sustained occurrences indicate the identity allocator or the policy map writer is the bottleneck |
| **Name lock contention** | A warning names `dnsproxy-lock-count` and `dnsproxy-lock-timeout`; processing continues |
| **Upstream DNS timeout** | No response is written; the client's resolver retries. Counted in `cilium_proxy_upstream_reply_seconds{error="timeout"}` |
| **Endpoint not found for a DNS source IP** | SERVFAIL. Happens transiently while an endpoint is being created; the client retries |
| **Agent restart with DNS policy active** | Restored rules (§3.6.9) enforce from before the sockets bind. Names already in the cache keep resolving; new names are enforced against the restored regex + IP set. With the SDP enabled, nothing is interrupted at all except identity allocation for genuinely new names |
| **CEC references a missing internal listener** | The whole CEC is rejected at parse with a message naming the cluster and the listener; previously applied resources for that CEC are left in place |
| **CEC with duplicate filter chain matches** | Rejected at parse. The reference notes this check is order-sensitive and some configs still get rejected later by Envoy; a late NACK is handled as above |
| **Secret referenced by a policy is missing** | The header match becomes a matcher that can never match (§3.5.1) and the TLS context is emitted without material, so the rule fails closed. A warning names the Secret |
| **Node labels change so a CEC no longer selects this node** | Its resources are withdrawn from Envoy and its ports released, exactly as if the CEC were deleted |
| **Upgrade with a changed proto set** | The version check (§3.1.8) refuses to serve xDS to an Envoy whose version does not match the pinned image. Startup fails loudly rather than emitting protos the running Envoy cannot parse |

---

## 8. Observability

### 8.1 Metrics

| Metric | Type / labels | Meaning |
|---|---|---|
| `cilium_proxy_redirects` | gauge, `protocol_l7` | redirects installed, by proxy type |
| `cilium_policy_l7_total` | counter, `rule` ∈ {received, forwarded, denied, parse_errors}, `proxy_type` ∈ {fqdn, envoy} | L7 requests handled |
| `cilium_proxy_upstream_reply_seconds` | histogram, `error`, `protocol_l7`, `scope` | time to an upstream reply; `scope` ∈ {total, processing, upstream, semaphore, policy_generation, qname_lock, update_ep_cache, update_nm_cache, policy_check, dataplane} |
| `cilium_proxy_datapath_update_timeout_total` | counter (disabled by default) | response-hold timeouts (§3.6.5) |
| `cilium_policy_missing_proxy_redirects` | gauge | policy entries skipped for an unrealised redirect (spec 06) |
| `cilium_xds_events_count` | counter, `type_url`, `status` ∈ {ack, nack, cancel} | xDS stream events |
| `cilium_fqdn_gc_deletions_total` | counter | names removed by FQDN GC |
| `cilium_fqdn_active_names` | gauge, `endpoint` (disabled by default) | unexpired names per endpoint |
| `cilium_fqdn_active_ips` | gauge, `endpoint` (disabled by default) | unexpired IPs per endpoint |
| `cilium_fqdn_alive_zombie_connections` | gauge, `endpoint` (disabled by default) | zombies per endpoint |
| `cilium_fqdn_selectors` | gauge | registered `toFQDNs` selectors |
| `cilium_fqdn_semaphore_rejected_total` | counter (disabled by default) | DNS requests rejected by the semaphore |

### 8.2 Access log → Hubble

Both proxies produce a `LogRecord` (§4.3). The record is emitted as a monitor
event of type `MessageTypeAccessLog` and decoded by the Hubble parser into
`flow.Layer7{Http | Dns}`. The mapping:

| `LogRecord` | Hubble flow |
|---|---|
| `type` request/response | `Layer7.type` REQUEST / RESPONSE |
| `verdict` forwarded / denied / error | `Flow.verdict` FORWARDED / DROPPED / ERROR |
| `observation_point` | `Flow.traffic_direction` |
| `source_endpoint` / `destination_endpoint` (id, ips, port, identity, labels) | `Flow.source` / `Flow.destination` |
| `http{code, method, url, protocol, headers}` | `Layer7.http` |
| `dns{query, ips, ttl, cnames, rcode, qtypes, answer_types, observation_source}` | `Layer7.dns` |
| `drop_reason` | `Flow.drop_reason_desc` |

Latency fields from `ProcessingStats` (SDP) or the local stat context populate
the flow's L7 latency where Hubble has a field for it.

### 8.3 Logs and status

- Every listener add/remove, NACK (with type URL and detail), port allocation and
  release, CEC parse failure, and secret sync action MUST be logged with
  structured fields (`listener`, `proxy_port`, `type_url`, `endpoint_id`,
  `dns_name`, `error`).
- `flowsdn-dbg status` MUST report: Envoy connected/not, xDS versions and last
  ACK per type, the proxy port range and the number of ports in use, the DNS
  proxy port and whether the SDP is connected.
- `GET /fqdn/cache`, `GET /fqdn/cache/{id}`, `GET /fqdn/names` and
  `DELETE /fqdn/cache` expose and clear the DNS cache (spec 08 owns the server;
  this spec owns the content).
- Envoy's own `/stats/prometheus` is exposed by the chart-rendered listener on
  `proxy-prometheus-port`; flowsdn does not scrape or re-export it.

---

## 9. Test plan

Unit (u), privileged/kernel (p), end-to-end (e).

**xDS engine**
- [ ] u — version increments on every mutation; watchers wake exactly once
- [ ] u — ACK resolves completions at or above the mutation version
- [ ] u — NACK fails the completion, reverts the cache, bumps the version
- [ ] u — NACK does not resend the rejected version
- [ ] u — first-stream handling: empty version and nonce parse as 0
- [ ] u — `version_info > nonce` terminates the stream
- [ ] u — non-numeric version or nonce terminates the stream
- [ ] u — malformed node id terminates the stream
- [ ] u — pre-first-ACK versions are reported to observers as 0
- [ ] u — `Delta*` methods return UNIMPLEMENTED
- [ ] e — full stream against a fake Envoy: connect, ACK, NACK, disconnect, reconnect, resume

**NPDS generation**
- [ ] u — golden protobufs for a matrix of policies (allow, deny, pass, wildcard port, port range, HTTP rules, TLS contexts, SNI, listener reference), byte-compared
- [ ] u — sort stability: shuffling the input rule order yields identical bytes
- [ ] u — a selector with zero selections drops the rule; a wildcard selector emits an empty `remote_policies`
- [ ] u — deny rules carry no L7/TLS/proxy_id and poison short-circuiting
- [ ] u — wildcard-port merge and lower-precedence pruning
- [ ] u — endpoint with no IPs produces no resource and no error
- [ ] u — `ipcache_name` is set on every emitted `BpfMetadata`

**HTTP rule translation**
- [ ] u — path/method/host → safe-regex matchers on `:path`/`:method`/`:authority`
- [ ] u — `"Name: value"` → exact, `"Name"` → present
- [ ] u — every `mismatch` value maps to the right `MismatchAction`
- [ ] u — a missing Secret yields the never-matching inverted empty exact matcher
- [ ] u — a Secret reference yields `value_sds_secret` with the hashed synced name
- [ ] u — `header_matches` present ⇒ not short-circuitable

**Bootstrap and listeners**
- [ ] u — generated bootstrap equals the chart's `bootstrap-config.json` for the same inputs
- [ ] u — listener shape per parser type: filter order, chain matches, cluster names, TLS variant
- [ ] u — HCM route config: gRPC route first, retry policy, timeouts, normalisation flags

**Proxy ports and redirects**
- [ ] u — allocation avoids allocated and locally-open ports; second pass reuses released ports
- [ ] u — restore from the state file; stale file ignored
- [ ] u — reuse delay honoured
- [ ] u — create/update/remove lifecycle, reference counting, port released only at zero
- [ ] u — ACK installs datapath rules; NACK releases an unacknowledged port
- [ ] u — a static (DNS) port is never released
- [ ] p — nftables TPROXY rules and ip rules/tables installed and removed (netlink)

**CEC**
- [ ] u — name qualification for listeners, routes, clusters, secrets, and every cross-reference
- [ ] u — filter injection: `cilium.network`, `cilium.l7policy`, upstream `cilium.l7policy`
- [ ] u — `bpf_metadata` injection with `is_l7lb`, `proxy_id`, ingress source addresses
- [ ] u — address allocation for listeners without an address; internal listeners untouched
- [ ] u — duplicate filter chain match rejected; missing internal listener rejected; unknown type URL rejected
- [ ] u — circuit breaker defaults; `SO_REUSEPORT` disabled with BPF TPROXY
- [ ] u — `nodeSelector` add/remove on node label change
- [ ] u — EDS from the backend table for `services` and `backendServices`
- [ ] e — Ingress and Gateway API conformance through the operator-generated CECs

**DNS proxy**
- [ ] u — `matchPattern` → regex table, including `*`, `**.`, all-asterisk forms, case and trailing dot; property test that a name matching the reference regex matches ours
- [ ] u — `matchName` literal escaping
- [ ] u — allow, reject (REFUSED and NXDOMAIN), SERVFAIL paths
- [ ] u — cache TTL floor, per-host limit, expiry, reverse index
- [ ] u — zombie creation, liveness marking, grace period, over-limit eviction, force-expire on new answer
- [ ] u — restore rules round-trip through JSON, v1 and v2 `PortProto` keys
- [ ] u — concurrency limit: immediate rejection with no grace period; timeout with one
- [ ] u — response hold: response is not written before the datapath revision is applied; released on timeout
- [ ] u — per-name lock serialises concurrent lookups of the same name
- [ ] p — UDP and TCP listeners bind with `IP_TRANSPARENT`; original destination recovered from cmsg
- [ ] p — UDP response is sourced from the original destination address
- [ ] p — upstream socket carries `SO_MARK = 0x0B00 | identity<<16`
- [ ] p — transparent mode binds the pod address; skipped for host/loopback/world/local-host destinations
- [ ] p — EDNS buffer size honoured; compression applied only when needed
- [ ] e — `toFQDNs` connectivity with an agent restart mid-flight

**SDP**
- [ ] u — snapshot apply and ack; stream teardown and re-subscribe
- [ ] u — `UpdateMappingRequest` drives the same notification path as the in-agent proxy
- [ ] u — every `ResponseCode` and `ProxyErrorType` round-trips
- [ ] e — agent restart with the SDP running: cached names keep resolving

**Access log**
- [ ] u — `LogEntry` → `LogRecord` for request, response and denied entries
- [ ] u — truncated and undecodable records are discarded, not fatal
- [ ] u — unknown `policy_name` does not drop the flow
- [ ] p — seqpacket socket accepts multiple connections concurrently

**Negative / config**
- [ ] u — `external-envoy-proxy=false` refused at startup
- [ ] u — `envoy-xds-mode=ads` refused at startup
- [ ] u — SDP enabled with `tofqdns-proxy-port=0` refused at startup
- [ ] u — `authentication.mode: required` rejected at policy validation

---

## 10. Kernel and platform requirements

- `IP_TRANSPARENT` / `IPV6_TRANSPARENT`, `IP_RECVORIGDSTADDR` /
  `IPV6_RECVORIGDSTADDR`, `SO_MARK` (needs `CAP_NET_ADMIN`), `SO_REUSEADDR`,
  `SO_REUSEPORT`, `SO_LINGER` — all long-standing.
- `nf_tables` plus `nft_tproxy` and `nft_socket` when `enable-bpf-tproxy=false`
  (the default). With `enable-bpf-tproxy=true`: `bpf_sk_lookup_tcp` /
  `bpf_sk_lookup_udp` / `bpf_sk_assign` (kernel ≥ 5.7) on the tc ingress path;
  host egress still uses the mark path, so the nftables residual is not fully
  removed either way (spec 10 §3.10.3).
- `SOCK_SEQPACKET` unix sockets for the access log (and, when ztunnel lands,
  `SCM_RIGHTS` fd passing).
- bpffs mounted and readable by the Envoy container, which must open
  `<bpf_root>/tc/globals/cilium_ipcache_v2` (spec 01 §3.1, spec 03 §4.8), and
  must share `proxy-gid` for the control sockets.
- The `cilium-envoy` image is published for amd64 and arm64; flowsdn cross-compiles
  nothing for it. Both architectures are first-class (ADR-0001).
- No requirement on conntrack: proxy traffic is `notrack`-ed and the BPF CT map is
  authoritative (ADR-0003).
- Minimum kernel is set by `docs/kernel-requirements.md`; nothing in this area
  raises it above the general 6.6 LTS floor.

---

## 11. Rust design notes

### 11.1 Crates

| Crate | Contents |
|---|---|
| `flowsdn-envoy-proto` | generated types for the `cilium/proxy` protos and the subset of `envoyproxy/data-plane-api` v3 we emit; a compiled descriptor set for `Any` handling |
| `flowsdn-xds` | the xDS server: transport, per-type caches, watchers, ACK/NACK tracking, completions, bootstrap builder, admin client, access-log server |
| `flowsdn-envoy-policy` | the pure `EndpointPolicy → cilium.NetworkPolicy` function plus the sort implementation; no I/O, exhaustively golden-tested |
| `flowsdn-cec` | CEC/CCEC reflector, resource parser, EDS from the backend table, reconciler |
| `flowsdn-dnsproxy` | the DNS proxy as a **library**: sockets, matcher, cache, zombies, restore, with a `PolicySource` trait and a `Notifier` trait |
| `flowsdn-dnsproxy-standalone` | the SDP binary: `flowsdn-dnsproxy` + a tonic `FQDNData` client |
| `flowsdn-fqdn` | name manager, ipcache metadata production, GC, the `/fqdn/*` REST model (in-agent only) |

### 11.2 xDS server

- Generate protos with `tonic-build` / `prost-build` from vendored `.proto` files
  pinned alongside the `cilium-envoy` image digest. Do **not** depend on
  `envoy-types` or `envoy-control-plane`: they lag the data-plane-api and carry
  none of the `cilium.*` types, and a version skew here is a silent wire
  incompatibility.
- Serve with `tonic` over `tokio::net::UnixListener`; set the mode and group with
  `std::os::unix::fs` + `nix::unistd::chown` after bind and before accept.
- Per-type cache: `RwLock<TypeCache>` with `version: u64` and
  `BTreeMap<String, prost_types::Any>`; `tokio::sync::watch` per type for wakeups.
  Completions are `tokio::sync::oneshot` resolved by the ACK tracker;
  `futures::future::try_join_all` plus `tokio::time::timeout` replaces the
  reference's `completion.WaitGroup`.
- Raw Envoy resources from CEC are `Any` values whose inner type may be any of
  ~150 extension messages. `prost-reflect` with a compiled `FileDescriptorSet`
  (built once at compile time from the data-plane-api protos) is the clean way
  to decode, mutate (qualify names, inject filters) and re-encode them without
  generating Rust types for every extension. Where we must mutate a known type
  (Listener, HCM, TcpProxy, Cluster, RouteConfiguration, SdsSecretConfig) use the
  generated type; use `prost-reflect` for validation and passthrough of the rest.
- Access log server: `tokio::net::UnixListener` cannot create a `SOCK_SEQPACKET`
  socket, so create it with `socket2` (`Type::SEQPACKET`), set non-blocking, and
  wrap with `tokio::io::unix::AsyncFd`; read with `recvmsg` so `MSG_TRUNC` is
  observable.
- Admin client: `hyper` with a unix connector.
- Proxy port allocator: read `/proc/net/{tcp,udp}{,6}` (or
  `netlink-packet-sock-diag`) for the open-port snapshot; persist with
  write-temp + `rename`.
- Routes and rules: `rtnetlink` for tables 2004/2005 and the fwmark rules
  (implemented in the node/routing crate per spec 10; this crate only asks).
- Secret sync: `kube-rs` watch → SDS `Secret` protos with the reference's naming.

### 11.3 DNS proxy

- Wire handling with `hickory-proto` (`Message`, `BinEncoder` with a max size
  from the client's EDNS buffer or 512, OPT record access), **not**
  `hickory-server` — its handler model hides the transparent-socket details this
  design depends on.
- Sockets with `socket2` + `tokio`: `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`,
  `SO_MARK`, `SO_REUSEPORT`; `nix::sys::socket::recvmsg` with
  `ControlMessageOwned::Ipv4OrigDstAddr` / `Ipv6OrigDstAddr` for the original
  destination; a per-response socket bound to the original destination for UDP
  replies.
- Matcher: `regex` behind an `lru`-bounded compile cache, reference-counted.
  The `matchPattern` translation (§5.5) is small and fuzz-tested upstream; port
  it exactly and fuzz it here too.
- Concurrency: `tokio::sync::Semaphore` for the message limit; a fixed array of
  `tokio::sync::Mutex` (count = `dnsproxy-lock-count`) indexed by a hash of the
  qname for the per-name lock. Use an async mutex, not a blocking one: the
  critical section awaits the datapath revision.
- Cache and zombies: `BTreeMap`-based, snapshot-cheap; serialise with `serde_json`
  into the endpoint state file in the reference's shapes.
- `PolicySource` trait: `fn rules_for(endpoint_id, port_proto) -> RuleSet` and a
  change stream. In-agent implementation reads the policy engine; SDP
  implementation reads the gRPC-fed table. `Notifier` trait: `async fn
  on_dns_message(...) -> Result<()>` — in-agent it runs the §3.6.5 pipeline, in
  the SDP it is the `UpdateMappingRequest` RPC. This is the whole split; both
  binaries share every other line.

### 11.4 Surface a Rust proxy must cover to replace Envoy

Recorded now so the NPDS proto stays the internal contract and a Rust L7 filter
can be dropped in behind the same xDS server.

1. **Transport**: TPROXY listeners on loopback for TCP; original-destination
   recovery; source identity and endpoint id from `SO_MARK`; upstream connect to
   the original destination with `IP_TRANSPARENT` original-source and the
   `MARK_MAGIC_PROXY_{INGRESS,EGRESS} | identity<<16` mark; `SO_LINGER` control;
   downstream-protocol passthrough (HTTP/1.1 ↔ HTTP/2) and WebSocket upgrade.
2. **HTTP**: full HTTP/1.1 and HTTP/2 termination (`hyper`/`h2`); RFC3986 path
   normalisation, merge slashes, escaped-slash unescape-and-redirect; the
   `cilium.l7policy` semantics (per-connection identity → rule set, regex on
   `:path`/`:method`/`:authority`, exact/present header matchers, `HeaderMatch`
   mismatch actions that *rewrite* the request, SDS-sourced values); 403 with the
   configured body; 5xx retries; request/stream idle timeouts; `grpc-timeout`
   handling; XFF trusted hops; access-log emission in the same `LogEntry` shape.
3. **TLS**: `rustls` termination with per-rule certificates (terminatingTLS) and
   origination with CA validation and SNI (originatingTLS); SNI allow-listing
   without termination; ALPN; live secret updates.
4. **Policy**: consume the same `cilium.NetworkPolicy` document; precedence, pass
   and deny semantics; wildcard-port rules; `remote_policies` identity sets; hot
   updates with an ACK back to the agent so revision tracking is unchanged.
5. **L7 LB (CEC / Ingress / Gateway)**: arbitrary Envoy listeners, routes,
   weighted clusters, header and path rewrites, redirects, timeouts, retries,
   circuit breakers, EDS backends, SNI-selected certificates, HTTP/2 and gRPC,
   plus whatever extensions users put in `resources`.

**Feasibility judgement.** Items 1–4 — the policy-enforcement listeners — are
realistic: roughly 15–20k lines with `hyper`/`tower`/`rustls`, comparable to what
`linkerd2-proxy` or `pingora` spend on the same feature set, and the contract is
already fully specified by this document. Item 5 is **not** realistically
replaceable: `resources[]` is by construction "any Envoy configuration", and
Ingress/Gateway parity would mean reimplementing Envoy's routing extension
surface. The tractable end state is therefore a **split**: a Rust proxy for
policy enforcement (where the config is generated by flowsdn and bounded), and
Envoy retained for CEC-driven L7 load balancing, or a purpose-built Rust router
fed from the operator's Ingress/Gateway model rather than from Envoy protos. That
split is a future ADR, not a v1 goal; keeping NPDS as the internal contract is
what buys the option.

---

## 12. Decisions and remaining questions

Resolved entries are normative decisions from [ADR-0013](../decisions/0013-integration-issue-resolutions.md); their implementation and acceptance tests remain required.

1. **Resolved — #193.** Implement split SOTW xDS first, with split as the default and a
   bootstrap builder supporting both config-source shapes. Reject unimplemented ADS
   modes explicitly. ADS remains in the full compatibility scope; implementing it is
   required before claiming parity for those modes.

2. **Resolved — #194.** Pin the external Envoy image by immutable digest. Review the
   digest, source revision, vendored protobuf set and generated bindings together; a tag
   alone is insufficient.

3. **Resolved — #195.** Use the external Envoy DaemonSet, as ADR-0001 already specifies.
   Reject embedded mode and chart settings that would require it; preserve the xDS and
   admin socket interfaces.

4. **Resolved — #196.** Keep both BPF socket assignment and the nftables mark/TPROXY
   path. Default enable-bpf-tproxy to false; enabling it does not remove required host-
   egress residual rules. A later default change requires explicit validation and a
   documented config migration.

5. **Resolved #197: default transparent DNS on with SDP, off otherwise.**
   When the effective key is unset/default-sourced, derive its value from
   `enable-standalone-dns-proxy`. An explicit flag/env/file true or false wins
   after normal source precedence. The `flowsdn-proxy::transparent_dns` helper
   accepts that resolved optional override; it does not open sockets or change
   upstream source addresses. Configuration provenance must identify derived
   defaults, and actual socket/source-attribution tests remain required.

6. **Resolved — #198.** Support all three secret-source modes in §3.5.4. New chart
   installations should explicitly select SDS with secret sync, while retaining the raw
   agent flag default and existing configuration precedence. Grant cluster-wide Secret
   reads only for the selected read-all mode.

7. **Access log buffer size default — resolved #199.** Use 16384 bytes,
   configurable in 1–1048576. `flowsdn-proxy::accesslog::Reader` owns a Unix
   datagram socket or accepted SOCK_SEQPACKET connection and uses `recvmsg`
   flags to distinguish truncation from an exactly full record. Truncated
   records are discarded in full, increment a saturating drop counter, and
   invoke a warning hook naming the configured buffer size; the server adapter
   logs `envoy-access-log-buffer-size` with this warning. Bytes remain binary,
   with no UTF-8 conversion. EINTR retries and WouldBlock remains caller-visible.
   Zero-length seqpacket reads report EmptyOrClosed because recvmsg cannot
   distinguish an empty packet from orderly shutdown; datagram empty records
   remain valid binary records. Tests cover header-heavy 8192-byte records,
   exactly 16384, over-limit 20000, legacy 4096 and independent following messages.
   Listener permissions, protobuf decoding, Hubble forwarding and operational
   warning rate limiting remain adapter work; this primitive is not wired to
   the Hubble server.
   *Recommendation: (b),* with the metric and warning retained. The cost is a
   larger per-connection read buffer; the benefit is not silently losing the
   exact flows an operator is most likely to be investigating.

8. **Resolved — #200.** Keep NPHDS serving alongside direct ipcache access. Production
   defaults may continue to use the pinned map, but the fallback and test feed must stay
   available.

9. **Resolved — #201.** Include the standalone DNS proxy in the feature scope. Build the
   DNS engine as flowsdn-dnsproxy with a PolicySource interface shared by in-agent and
   standalone consumers. Preserve the response-hold and fail-closed ordering of §3.7.

10. **Resolved — #202.** Until mutual authentication is implemented, reject required and
   test-always-fail authentication modes at policy validation. Never convert an
   authentication requirement into allow. This rejection does not remove mutual
   authentication from the full feature scope.

11. **Resolved #203:** [ADR-0015](../decisions/0015-proxy-and-ztunnel-contracts.md)
    selects Rust nftables transactions in the enrolled pod namespace, without
    an iptables exception. Enrollment and its privileged tests remain required;
    reject enablement while unimplemented, never silently omit mTLS.
12. **Resolved #204: FQDN shares spec03's complete local scope.** No separate
    FQDN numeric partition or allocator is introduced. Range and ownership are
    defined in spec03; preallocate selector identities before policy publication,
    maintain shared reference counts, and restore/withhold requested IDs before
    new allocations. The proxy helper validates that requested/restore IDs have
    local scope, including indices beyond 65535. It proves no allocation
    ownership or restore implementation; those remain the identity owner's work.
13. **Resolved #262:** ADR-0015 retains external Envoy and records concrete
    prerequisites for any separately proposed Rust replacement. This repository's
    `flowsdn-proxy` library is not an L7 replacement or performance claim.
14. **Resolved #24:** the NPDS/new-listener ACK barrier in §3.1.5 remains
    mandatory. State-machine tests cover stale replies, NACK, reconnect,
    cancellation and timeout including timeout after readiness; actual endpoint
    and xDS integration remain required.
