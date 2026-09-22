# Observability: monitor event pipeline and Hubble — inventory

Reference: cilium v1.20.1 (commit 7d68cfb394). Paths: `pkg/monitor/**`,
`pkg/monitor/{agent,api,format,payload}`, `pkg/hubble/**`, `pkg/hubble/relay/**`,
`hubble-relay/**`, `hubble/**` (in-tree CLI), `api/v1/{flow,observer,peer,relay}/*.proto`,
`pkg/hubble/dropeventemitter`, `bpf/lib/{notify,drop,trace,trace_sock,policy_log,dbg,classifiers}.h`
(struct layouts only), `install/kubernetes/cilium/templates/hubble-ui/`.

Not present in v1.20.1: `pkg/recorder`, `api/v1/recorder/recorder.proto`, the
`RecorderCapture` monitor message and the Hubble `Recorder` gRPC service. The
pcap recorder feature was removed upstream before this tag; the only trace left
is the enum slot `CILIUM_NOTIFY_CAPTURE = 6` in `bpf/lib/notify.h` (reserved,
never emitted; no Go decoder for type 6) and commits "bpf: common: remove unused
CAPTURE_* macros" / "bpf: remove stale ENABLE_CAPTURE from build tests".
`ServiceUpsert`/`ServiceDelete` agent notifications are likewise gone from
`pkg/monitor/api` (the proto enum values 11/12 and messages remain,
`[deprecated = true]`, for wire compatibility).

## Purpose

The datapath emits fixed-layout C structs into the `cilium_events`
`BPF_MAP_TYPE_PERF_EVENT_ARRAY`. The monitor agent (`pkg/monitor/agent`) reads
the per-CPU perf ring, fans every record out to (a) in-process *consumers* and
(b) external *listeners* on the unix socket `/var/run/cilium/monitor1_2.sock`
(gob-encoded `payload.Payload`), and also injects agent-originated events
(`MessageTypeAgent` JSON notifications, `MessageTypeAccessLog` L7 proxy
records) into the same stream. `pkg/monitor` holds the Go decoders for each
message type plus the human/JSON formatter used by `cilium-dbg monitor`.

Hubble is the primary consumer: `pkg/hubble/monitor` bridges monitor events into
a bounded channel; `pkg/hubble/parser` decodes them into `flow.Flow` protobufs,
enriching with endpoint / identity / ipcache / DNS-history / service-frontend /
link-name lookups pulled live from agent state; `pkg/hubble/observer` stores
`v1.Event`s in a lock-free ring buffer and serves the `Observer` gRPC API over
`/var/run/cilium/hubble.sock` and optionally TCP `:4244` (TLS/mTLS). Side
outputs from the same decoded-flow hook chain: Prometheus metrics
(`pkg/hubble/metrics`), JSON flow-log export with rotation
(`pkg/hubble/exporter`), and Kubernetes `PacketDrop` Events
(`pkg/hubble/dropeventemitter`). `pkg/hubble/peer` serves the `Peer` gRPC
service (node add/update/delete stream); `hubble-relay` consumes it to discover
every node's Hubble server and fans out `GetFlows` cluster-wide, merging by
timestamp through a bounded priority queue. `hubble/` is the in-tree Hubble
CLI (the separate cilium/hubble repository was merged into cilium; the CLI is
now built from here).

## Components

| Path | Lines (non-test / test) | Purpose |
|---|---|---|
| `pkg/monitor/api/types.go` | 476 / 150 (pkg) | Message type constants, trace observation points, `AgentNotify*` JSON sub-types, policy verdict match types |
| `pkg/monitor/api/drop.go` | 133 | Drop reason code → string table (`DropReason`, `DropReasonExt`) |
| `pkg/monitor/api/files.go` | 47 | BPF source file id → filename table |
| `pkg/monitor/api/agent_notify_linux.go` | 38 | gob `Decode`/`Dump` for `AgentNotify` |
| `pkg/monitor/api/monitor_event_interface_linux.go` | 83 | `MonitorEvent` interface, `Verbosity`, `DumpArgs` |
| `pkg/monitor/payload/monitor_payload.go` | 97 / 39 | `Payload{Data,CPU,Lost,Type}` gob framing, `Meta{Size,_[28]}` |
| `pkg/monitor/datapath_drop.go` | 289 / 321 | `DropNotify` v0–v3 decoder + dump |
| `pkg/monitor/datapath_trace.go` | 451 / 432 | `TraceNotify` v0–v2 decoder, trace reasons, dump |
| `pkg/monitor/datapath_policy.go` | 195 / 173 | `PolicyVerdictNotify` decoder + dump |
| `pkg/monitor/datapath_sock_trace.go` | 116 / 91 | `TraceSockNotify` decoder |
| `pkg/monitor/datapath_debug.go` | 618 / 228 | `DebugMsg`, `DebugCapture`, `DBG_*` subtype table + message formatter |
| `pkg/monitor/dissect.go` | 669 / 347 | gopacket dissection of captured bytes → summary / `DissectSummary` JSON (incl. VXLAN/Geneve inner) |
| `pkg/monitor/logrecord.go` | 199 | `LogRecordNotify` (L7 accesslog) gob decoder + dump |
| `pkg/monitor/types.go`, `notifications/` | 28 + 13 | helpers, `RegenNotificationInfo` interface |
| `pkg/monitor/format/` | 201 / 324 | `MonitorFormatter`: type / from / to / related-to filtering, dispatch to `Dump` |
| `pkg/monitor/agent/agent.go` | 454 / 133 | perf reader, consumer + listener fan-out, `SendEvent` for agent events, `MonitorStatus` |
| `pkg/monitor/agent/{listener1_2,server,cell,consumer,listener}.go` | 375 / 31 | unix socket server, per-listener queue, hive cell, interfaces |
| `pkg/hubble/cell/` | 704 / 17 | hive wiring, `hubble-*` core flags, TLS certloader |
| `pkg/hubble/monitor/consumer.go` | 269 / 675 | `MonitorConsumer` → observer channel, lost-event accounting |
| `pkg/hubble/observer/` | 907 / 931 | `LocalObserverServer`: decode loop, ring write, `GetFlows`/`GetAgentEvents`/`GetDebugEvents`/`ServerStatus`/`GetNamespaces` |
| `pkg/hubble/observer/{observeroption,types,namespace}` | 258+68+113 | hook options (`OnMonitorEvent`, `OnDecodedFlow`, …), `MonitorEvent` types, namespace tracker |
| `pkg/hubble/container/` | 529 / 1262 | lock-free ring buffer + `RingReader` |
| `pkg/hubble/parser/parser.go` | 204 / 171 | dispatcher: perf/agent/lost → `v1.Event` |
| `pkg/hubble/parser/threefour/` | 888 / 2729 | L2/L3/L4 decode, verdict / direction / reply / identity, enrichment |
| `pkg/hubble/parser/seven/` | 689 / 1014 | L7 accesslog → `Layer7{DNS,HTTP,Kafka}`, redaction, trace-context |
| `pkg/hubble/parser/sock/` | 276 / 467 | `TraceSockNotify` → `FlowType_SOCK` flow (cgroup → pod) |
| `pkg/hubble/parser/agent/`, `debug/` | 150+103 / 277+237 | `AgentNotifyMessage` → `AgentEvent`; `DebugMsg` → `DebugEvent` |
| `pkg/hubble/parser/common/` | 253 | `EndpointResolver` (identity conflict rules), label filtering |
| `pkg/hubble/parser/{getters,options,fieldmask,fieldaggregate,errors,cell}` | 82+149+112+45+42+243 | getter interfaces, redact options, field-mask copy, hive wiring of getters to agent state |
| `pkg/hubble/filters/` | 2041 / 5533 | 25 `FlowFilter` field → predicate builders, CEL |
| `pkg/hubble/metrics/` (+`api`, `cell`, 10 handlers) | 530+907+303+~1990 / ~3000 | Prometheus handlers, context options, dynamic config watcher |
| `pkg/hubble/exporter/` (+`cell`) | 1359+280 / 2721+79 | JSON flow-log exporter, lumberjack rotation, dynamic flowlogs config, aggregation |
| `pkg/hubble/dropeventemitter/` | 500 / 488 | k8s `PacketDrop` Events |
| `pkg/hubble/peer/` (+`cell`,`serviceoption`,`types`) | 417+100+76+207 / 1705+57+430 | `Peer.Notify` service, node handler, TLS server-name derivation |
| `pkg/hubble/server/` (+`serveroption`) | 100+170 | gRPC server assembly (health, reflection, TLS) |
| `pkg/hubble/relay/{server,observer,pool,queue,defaults}` | 491+763+680+105+57 / 384+1526+1433+175 | relay: peer manager, fan-out, sort/merge, backoff |
| `hubble-relay/` | 542 | relay `main`, `serve` cobra command (flags) |
| `hubble/` | 6199 / 4802 | in-tree Hubble CLI (`observe`, `list`, `status`, `watch`, `reflect`, `config`, `version`) |
| `api/v1/flow/flow.proto` | 1033 | `Flow` and all event/enum messages — compatibility contract |
| `api/v1/observer/observer.proto` | 302 | `Observer` service |
| `api/v1/peer/peer.proto` | 58 | `Peer` service |
| `api/v1/relay/relay.proto` | 39 | `NodeStatusEvent`, `NodeState` |
| `pkg/hubble/testutils/` | 764 / 246 | fake getters used across tests |

Totals: `pkg/monitor/**` 4,482 / 2,269; `pkg/hubble/**` 18,175 / 26,323 (of
which relay 2,134 / 3,518); `hubble-relay` 542; `hubble` CLI 6,199 / 4,802;
protos 1,432.

## Features

- **Monitor unix socket (`monitor1_2`)** — `--enable-monitor` (default true)
  serves `unix:///var/run/cilium/monitor1_2.sock`. Each accepted connection is a
  `listenerv1_2` with a bounded channel (`--monitor-queue-size`; default
  `min(possibleCPUs*1024, 16384)`); full queue drops the message for that
  listener only. Stream = consecutive gob-encoded `payload.Payload` values.
- **Perf reader** — attaches to pinned map `cilium_events` (perf event array,
  one entry per possible CPU) with `defaults.MonitorBufferPages = 64` pages per
  CPU; started lazily on the first listener/consumer and stopped when none
  remain. `PERF_RECORD_LOST` is turned into `Payload{Type: RecordLost, Lost: n,
  CPU}`. `MonitorStatus{Cpus, Npages, Pagesize, Lost, Unknown}` is exposed in
  the agent status API.
- **Agent-originated events** — `Agent.SendEvent(typ, event)`: for
  `MessageTypeAgent` the `AgentNotifyMessage` is JSON-encoded into
  `AgentNotify{Type, Text}`; then `[1 byte typ][gob(event)]` is wrapped in a
  `Payload{Type: EventSample, CPU: 0}`. Consumers receive the *unencoded* Go
  value (`NotifyAgentEvent(typ, message)`), listeners the gob bytes.
- **Message type filter / formatter** — `cilium-dbg monitor --type drop|debug|capture|trace|l7|agent|policy-verdict|trace-sock`,
  `--from/--to/--related-to <endpoint id>`, `-v/-vv/-j`, `--hex`, `--numeric`.
- **Monitor aggregation** — `--monitor-aggregation {none|disabled|lowest|low|medium|max|maximum|0..4}`
  (option `monitor-aggregation`, alias `monitor-aggregation-level`),
  `--monitor-aggregation-interval` (default 5s), `--monitor-aggregation-flags`
  (TCP flags that always emit). Datapath levels: `TRACE_AGGREGATE_NONE=0`,
  `TRACE_AGGREGATE_RX=1` (suppress all `TRACE_FROM_*` points),
  `TRACE_AGGREGATE_ACTIVE_CT=3` (only emit when CT `monitor` field set, i.e.
  new/closing connections or the interval elapsed). Socket traces use
  `TRACE_SOCK_AGGREGATE_{NONE=0,RECV=1,CONNECT=3}`.
- **Per-event-type datapath switches** — `--bpf-events-drop-enabled`,
  `--bpf-events-policy-verdict-enabled`, `--bpf-events-trace-enabled` (all
  default true); `--bpf-events-default-rate-limit` / `--bpf-events-default-burst-limit`
  (token bucket in `_send_trace_notify`, topup every 1 s; 0 = off).
- **Capture length** — `--trace-payloadlen` (default 128) native,
  `--trace-payloadlen-overlay` (default 192) for VXLAN/Geneve-classified
  packets; per-connection `monitor` override from CT.
- **Hubble server** — `--enable-hubble` (default false in agent; Helm
  `hubble.enabled: true`). `--hubble-socket-path` (default
  `/var/run/cilium/hubble.sock`), `--hubble-listen-address` (e.g. `:4244`,
  Helm `hubble.listenAddress`), `--hubble-disable-tls`, `--hubble-tls-cert-file`,
  `--hubble-tls-key-file`, `--hubble-tls-client-ca-files` (presence enables
  mTLS). `--hubble-prefer-ipv6` (deprecated → `--prefer-ipv6`).
- **Event buffering** — `--hubble-event-buffer-capacity` (ring; must be
  2^n−1, ≤ 65535, default 4095), `--hubble-event-queue-size` (monitor→observer
  channel; default `min(NumCPU*1024, 16384)`), `--hubble-lost-event-send-interval`
  (default 1s), `--hubble-monitor-events` (subset of the type names; default all).
- **Parser options** — `--hubble-skip-unknown-cgroup-ids` (drop sock traces
  whose cgroup id has no pod), `--hubble-redact-enabled`,
  `--hubble-redact-http-urlquery`, `--hubble-redact-http-userinfo`,
  `--hubble-redact-http-headers-allow`, `--hubble-redact-http-headers-deny`
  (redacted value is the literal `HUBBLE_REDACTED`),
  `--hubble-network-policy-correlation-enabled` (fills
  `ingress/egress_allowed_by/denied_by` from the endpoint's policy map).
- **Metrics** — `--hubble-metrics "drop:destinationContext=pod;sourceContext=pod,flow,..."`,
  `--hubble-metrics-server` (Helm port 9965), `--enable-hubble-open-metrics`,
  `--hubble-metrics-server-enable-tls` + `--hubble-metrics-server-tls-{cert-file,key-file,client-ca-files}`,
  `--hubble-dynamic-metrics-config-path` (YAML, polled every 10 s).
- **Export** — static: `--hubble-export-file-path` (`stdout` = log instead of
  file), `--hubble-export-file-max-size-mb` (10), `--hubble-export-file-max-backups`
  (5), `--hubble-export-file-compress`, `--hubble-export-allowlist` /
  `--hubble-export-denylist` (JSON-encoded `FlowFilter`s),
  `--hubble-export-fieldmask`, `--hubble-export-fieldaggregate`,
  `--hubble-export-aggregation-interval`. Dynamic: `--hubble-flowlogs-config-path`
  (YAML, polled every 5 s, multiple named exporters, per-exporter `end` time).
- **Drop events to k8s** — `--hubble-drop-events` (alpha), `--hubble-drop-events-interval`
  (2m dedupe), `--hubble-drop-events-reasons` (default `auth_required,policy_denied`),
  `--hubble-drop-events-extended` (append correlated policy names),
  `--hubble-drop-events-rate-limit` (default 1/s; 0 = unlimited).
- **Peer service** — served on the same gRPC server; Helm `hubble.peerService`
  creates the `hubble-peer` Service (`GRPCServiceName = "hubble-grpc"`, port
  4244). TLS server name per node: `<node-with-dots-replaced>.<cluster>.hubble-grpc.cilium.io`.
- **Hubble Relay** — `hubble-relay serve` with `--peer-service` (default
  `unix:///var/run/cilium/hubble.sock`), `--listen-address` (`:4245`),
  `--health-listen-address` (`:4222`), `--metrics-listen-address`,
  `--retry-timeout` (30s), `--sort-buffer-len-max` (100),
  `--sort-buffer-drain-timeout` (1s), `--cluster-name`, TLS client
  (`--tls-hubble-client-cert-file`, `--tls-hubble-client-key-file`,
  `--tls-hubble-server-ca-files`, `--disable-client-tls`) and server
  (`--tls-relay-server-cert-file`, `--tls-relay-server-key-file`,
  `--tls-relay-client-ca-files`, `--disable-server-tls`), plus deprecated
  `--tls-client-*`/`--tls-server-*` aliases, `--pprof*`, `--gops*`,
  `--log-format`, `--log-level`.
- **Hubble UI** — backend talks gRPC to `hubble-relay:443` (TLS) or `:80`;
  nginx frontend proxies `<baseUrl>api` → `127.0.0.1:8090`.

## Data model

### Perf ring framing

Every BPF sample begins with `NOTIFY_COMMON_HDR` (8 bytes, native endian):

```
off  size  field
0    u8    type        CILIUM_NOTIFY_*  (== payload.Data[0])
1    u8    subtype     per-type meaning
2    u16   source      EVENT_SOURCE (endpoint id of program, 0 for host/overlay)
4    u32   hash        skb hash
```

Packet-carrying types add `NOTIFY_CAPTURE_HDR` (total 16 bytes):

```
8    u32   len_orig    original packet length
12   u16   len_cap     bytes of packet appended after the struct
14   u8    version     per-message layout version (NOTIFY_CAPTURE_VER = 1 base)
15   u8    ext_version downstream extension version (0 upstream)
```

The packet bytes follow the struct at `DataOffset() = lengthForVersion +
extensionLengthForExtVersion`. `ctx_event_output` passes `(cap_len << 32) |
BPF_F_CURRENT_CPU`, so the perf sample is `struct || cap_len bytes`.

Message types (`bpf/lib/notify.h` == `pkg/monitor/api.MessageType*`):

| code | C name | Go name | string |
|---|---|---|---|
| 0 | `CILIUM_NOTIFY_UNSPEC` | `MessageTypeUnspec` | — |
| 1 | `CILIUM_NOTIFY_DROP` | `MessageTypeDrop` | `drop` |
| 2 | `CILIUM_NOTIFY_DBG_MSG` | `MessageTypeDebug` | `debug` |
| 3 | `CILIUM_NOTIFY_DBG_CAPTURE` | `MessageTypeCapture` | `capture` |
| 4 | `CILIUM_NOTIFY_TRACE` | `MessageTypeTrace` | `trace` |
| 5 | `CILIUM_NOTIFY_POLICY_VERDICT` | `MessageTypePolicyVerdict` | `policy-verdict` |
| 6 | `CILIUM_NOTIFY_CAPTURE` | (none — recorder removed) | — |
| 7 | `CILIUM_NOTIFY_TRACE_SOCK` | `MessageTypeTraceSock` | `trace-sock` |
| 129 | — (agent) | `MessageTypeAccessLog` | `l7` |
| 130 | — (agent) | `MessageTypeAgent` | `agent` |

0–128 reserved for datapath, 129–255 for agent.

### `DropNotify` (`struct drop_notify`, type 1, subtype = drop reason)

```
off  size  field                          Go field
0-15       NOTIFY_CAPTURE_HDR
16   u32   src_label                      SrcLabel (identity)
20   u32   dst_label                      DstLabel
24   u32   dst_id  (0 for egress)         DstID
28   u16   line                           Line
30   u8    file                           File   (see file table)
31   s8    ext_error                      ExtError
32   u32   ifindex                        Ifindex
36   u8    flags  (cls_flags_t)           Flags        [v2+]
37   u8[3] pad2
40   u64   ip_trace_id                    IPTraceID    [v3]
48         DROP_EXTENSION (empty upstream)
```

Versions: v0/v1 → 36-byte header, v2 → 40, v3 → 48 (`dropNotifyV{1,2,3}Len`).
Decoder rejects `version > 3`. `Flags` bits: `1<<0` IPv6, `1<<1` L3 device,
`1<<2` VXLAN, `1<<3` Geneve (identical for `TraceNotify`; these are
`CLS_FLAG_IPV6/L3_DEV/VXLAN/GENEVE` from `classifiers.h`).

### `TraceNotify` (`struct trace_notify`, type 4, subtype = observation point)

```
off  size  field                          Go field
0-15       NOTIFY_CAPTURE_HDR             (ObsPoint = subtype)
16   u32   src_label                      SrcLabel
20   u32   dst_label                      DstLabel
24   u16   dst_id                         DstID (endpoint id, or proxy port for TO_PROXY)
26   u8    reason                         Reason (TRACE_REASON_*, bit 0x80 = encrypted)
27   u8    flags                          Flags
28   u32   ifindex                        Ifindex
32   16B   union { orig_ip4; orig_ip6 }   OrigIP [v1+]  (pre-SNAT source)
48   u64   ip_trace_id                    IPTraceID [v2]
56         TRACE_EXTENSION (empty upstream)
```

Versions: v0 → 32 bytes, v1 → 48, v2 → 56 (`NOTIFY_TRACE_VER = 2` current).
Decoder rejects `version > 2`.

Observation points (`enum trace_point`, `TraceObservationPoints`):

| code | C | string | flow.proto `TraceObservationPoint` |
|---|---|---|---|
| 0 | `TRACE_TO_LXC` | `to-endpoint` | `TO_ENDPOINT = 101` (parser maps subtype 0 → 101) |
| 1 | `TRACE_TO_PROXY` | `to-proxy` | `TO_PROXY = 1` |
| 2 | `TRACE_TO_HOST` | `to-host` | `TO_HOST = 2` |
| 3 | `TRACE_TO_STACK` | `to-stack` | `TO_STACK = 3` |
| 4 | `TRACE_TO_OVERLAY` | `to-overlay` | `TO_OVERLAY = 4` |
| 5 | `TRACE_FROM_LXC` | `from-endpoint` | `FROM_ENDPOINT = 5` |
| 6 | `TRACE_FROM_PROXY` | `from-proxy` | `FROM_PROXY = 6` |
| 7 | `TRACE_FROM_HOST` | `from-host` | `FROM_HOST = 7` |
| 8 | `TRACE_FROM_STACK` | `from-stack` | `FROM_STACK = 8` |
| 9 | `TRACE_FROM_OVERLAY` | `from-overlay` | `FROM_OVERLAY = 9` |
| 10 | `TRACE_FROM_NETWORK` | `from-network` | `FROM_NETWORK = 10` |
| 11 | `TRACE_TO_NETWORK` | `to-network` | `TO_NETWORK = 11` |
| 12 | `TRACE_FROM_CRYPTO` | `from-crypto` | `FROM_CRYPTO = 12` |
| 13 | `TRACE_TO_CRYPTO` | `to-crypto` | `TO_CRYPTO = 13` |

Trace reasons (`enum trace_reason` == CT state values; `pkg/monitor` names):

| code | Go const | string | flow.proto `TraceReason` |
|---|---|---|---|
| 0 | `TraceReasonPolicy` (CT_NEW) | `new` | `NEW = 1` |
| 1 | `TraceReasonCtEstablished` | `established` | `ESTABLISHED = 2` |
| 2 | `TraceReasonCtReply` | `reply` | `REPLY = 3` |
| 3 | `TraceReasonCtRelated` | `related` | `RELATED = 4` |
| 4 | `TraceReasonCtDeprecatedReopened` | `reopened` | `REOPENED = 5` (deprecated) |
| 5 | `TraceReasonUnknown` | `unknown` | `TRACE_REASON_UNKNOWN = 0` |
| 6 | `TraceReasonSRv6Encap` | `srv6-encap` | `SRV6_ENCAP = 6` |
| 7 | `TraceReasonSRv6Decap` | `srv6-decap` | `SRV6_DECAP = 7` |
| 8 | `TraceReasonDeprecatedEncryptOverlay` | `encrypt-overlay` | `ENCRYPT_OVERLAY = 8` (deprecated) |
| 0x80 | `TraceReasonEncryptMask` | prefix `encrypted ` | → `IP.encrypted = true` |

Mapping rule (`decodeTraceReason`): reason `< 5` → proto value `reason+1`;
`== 5` → 0; `≥ 6` → same value.

### `PolicyVerdictNotify` (`struct policy_verdict_notify`, type 5) — fixed 40 bytes

```
off  size  field                          Go field
0-15       NOTIFY_CAPTURE_HDR
16   u32   remote_label                   RemoteLabel (src identity if ingress, dst if egress)
20   s32   verdict                        Verdict  (<0 = -drop_reason, 0 = allow, >0 = proxy port redirect)
24   u16   dst_port                       DstPort  (network order in BPF; Go reads native then swaps in getters)
26   u8    proto                          Proto
27   u8    dir:2, ipv6:1, match_type:3, audited:1, l3:1   Flags
28   u8    auth_type                      AuthType  (flow.proto AuthType: 0 DISABLED, 1 SPIRE, 2 TEST_ALWAYS_FAIL)
29   u8[3] pad1
32   u32   cookie                         Cookie
36   u32   pad2
40         POLICY_VERDICT_EXTENSION
```

Flag masks: direction `0x3` (1 = `PolicyIngress`, 2 = `PolicyEgress`), IPv6
`0x4`, match type `0x38 >> 3`, audited `0x40`, L3 device `0x80`. Match types:
0 none, 1 `L3-Only`, 2 `L3-L4`, 3 `L4-Only`, 4 `all`, 5 `L3-Proto`, 6
`Proto-Only`. Verdict → `flow.Verdict`: `<0` DROPPED (and `drop_reason =
-verdict`), `>0` REDIRECTED, `0 && audited` AUDIT, else FORWARDED.

### `DebugMsg` (`struct debug_msg`, type 2) — 20 bytes, no capture header

```
0-7        NOTIFY_COMMON_HDR   (subtype = DBG_* code)
8    u32   arg1
12   u32   arg2
16   u32   arg3
```

### `DebugCapture` (`struct debug_capture_msg`, type 3) — 24 bytes + packet

```
0-15       NOTIFY_CAPTURE_HDR  (subtype = DBG_CAPTURE_* code)
16   u32   arg1
20   u32   arg2
```

Capture points: 0 unspec, 1–3 reserved, 4 `DBG_CAPTURE_DELIVERY`, 5 `FROM_LB`,
6 `AFTER_V46`, 7 `AFTER_V64`, 8 `PROXY_PRE`, 9 `PROXY_POST`, 10 `SNAT_PRE`,
11 `SNAT_POST` (same numbers in `flow.DebugCapturePoint`).

Debug subtypes (`bpf/lib/dbg.h` enum, 0..68): 0 UNSPEC, 1 GENERIC, 2
LOCAL_DELIVERY, 3 ENCAP, 4 LXC_FOUND, 5 POLICY_DENIED, 6 CT_LOOKUP, 7
CT_LOOKUP_REV, 8 CT_MATCH, 9 CT_CREATED, 10 CT_CREATED2, 11 ICMP6_HANDLE, 12
ICMP6_REQUEST, 13 ICMP6_NS, 14 ICMP6_TIME_EXCEEDED, 15 CT_VERDICT, 16 DECAP,
17 PORT_MAP, 18 ERROR_RET, 19 TO_HOST, 20 TO_STACK, 21 PKT_HASH, 22–29
LB6_{LOOKUP_FRONTEND, LOOKUP_FRONTEND_FAIL, LOOKUP_BACKEND_SLOT,
LOOKUP_BACKEND_SLOT_SUCCESS, LOOKUP_BACKEND_SLOT_V2_FAIL, LOOKUP_BACKEND_FAIL,
REVERSE_NAT_LOOKUP, REVERSE_NAT}, 30–37 same for LB4, 38 LB4_LOOPBACK_SNAT, 39
LB4_LOOPBACK_SNAT_REV, 40 CT_LOOKUP4, 41 RR_BACKEND_SLOT_SEL, 42
REV_PROXY_LOOKUP, 43 REV_PROXY_FOUND, 44 REV_PROXY_UPDATE, 45 L4_POLICY, 46
NETDEV_IN_CLUSTER, 47 NETDEV_ENCAP4, 48 CT_LOOKUP4_1, 49 CT_LOOKUP4_2, 50
CT_CREATED4, 51 CT_LOOKUP6_1, 52 CT_LOOKUP6_2, 53 CT_CREATED6, 54 SKIP_PROXY,
55 L4_CREATE, 56 IP_ID_MAP_FAILED4, 57 IP_ID_MAP_FAILED6, 58 IP_ID_MAP_SUCCEED4,
59 IP_ID_MAP_SUCCEED6, 60 LB_STALE_CT, 61 INHERIT_IDENTITY, 62 SK_LOOKUP4, 63
SK_LOOKUP6, 64 SK_ASSIGN, 65 L7_LB, 66 SKIP_POLICY, 67 LB6_LOOPBACK_SNAT, 68
LB6_LOOPBACK_SNAT_REV. `flow.DebugEventType` matches this numbering exactly.

**Reference bug to not copy:** `pkg/monitor/datapath_debug.go`'s iota list omits
`DbgSkipPolicy`, so `DbgLb6LoopbackSnat = 66` and `DbgLb6LoopbackSnatRev = 67`
there are off by one vs. `dbg.h` (67/68) and `flow.proto`. The Hubble debug
parser casts the raw subtype straight to `flow.DebugEventType`, so Hubble is
correct; only `cilium-dbg monitor -v` text for those two codes is wrong.

### `TraceSockNotify` (`struct trace_sock_notify`, type 7) — fixed 40 bytes, no common header

```
off  size  field
0    u8    type          (= 7)
1    u8    xlate_point   0 UNKNOWN, 1 PRE_DIRECTION_FWD, 2 POST_DIRECTION_FWD, 3 PRE_DIRECTION_REV, 4 POST_DIRECTION_REV
2    u8    l4_proto      0 UNKNOWN, 1 TCP, 2 UDP
3    u8    ipv6:1, pad:7   (Flags & 0x1)
4    u16   dst_port
6    u16   pad2
8    u64   sock_cookie
16   u64   cgroup_id
24   16B   dst_ip (v4 in first 4 bytes)
40         TRACE_SOCK_EXTENSION
```

Emitted by `bpf_sock.c` (cgroup hooks). Parser builds `FlowType_SOCK`,
`Verdict_TRANSLATED` for POST_* points / `TRACED` otherwise, source endpoint
via `PodMetadataGetter(cgroup_id)`.

### Drop reasons (`pkg/monitor/api/drop.go`; `DropMin = 130`, codes < 130 are non-drop statuses)

| code | string | flow.proto `DropReason` |
|---|---|---|
| 0 | Success | — |
| 2 | Invalid packet | — (`DropInvalid`) |
| 3 | Interface | — |
| 4 | Interface Decrypted | — |
| 5 | LB, sock cgroup: No backend slot entry found | — |
| 6 | LB, sock cgroup: No backend entry found | — |
| 7 | LB, sock cgroup: Reverse entry update failed | — |
| 8 | LB, sock cgroup: Reverse entry stale | — |
| 9 | Fragmented packet | — |
| 10 | Fragmented packet entry update failed | — |
| 11 | Missed tail call to custom program (unused) | — |
| 12 | Interface Decrypting | — |
| 13 | Interface Encrypting | — |
| 14 | LB: sock cgroup: Reverse entry delete succeeded | — |
| 15 | MTU error message | — |
| 130 | Invalid source mac (unused) | `INVALID_SOURCE_MAC` (deprecated) |
| 131 | Invalid destination mac (unused) | `INVALID_DESTINATION_MAC` (deprecated) |
| 132 | Invalid source ip | `INVALID_SOURCE_IP` |
| 133 | Policy denied | `POLICY_DENIED` |
| 134 | Invalid packet | `INVALID_PACKET_DROPPED` |
| 135 | CT: Truncated or invalid header | `CT_TRUNCATED_OR_INVALID_HEADER` |
| 136 | Fragmentation needed | `CT_MISSING_TCP_ACK_FLAG` (name mismatch in proto, value kept) |
| 137 | CT: Unknown L4 protocol | `CT_UNKNOWN_L4_PROTOCOL` |
| 138 | CT: Can't create entry from packet (unused) | `CT_CANNOT_CREATE_ENTRY_FROM_PACKET` (deprecated) |
| 139 | Unsupported L3 protocol | `UNSUPPORTED_L3_PROTOCOL` |
| 140 | Missed tail call | `MISSED_TAIL_CALL` |
| 141 | Error writing to packet | `ERROR_WRITING_TO_PACKET` |
| 142 | Unknown L4 protocol | `UNKNOWN_L4_PROTOCOL` |
| 143 | Unknown ICMPv4 code | `UNKNOWN_ICMPV4_CODE` |
| 144 | Unknown ICMPv4 type | `UNKNOWN_ICMPV4_TYPE` |
| 145 | Unknown ICMPv6 code | `UNKNOWN_ICMPV6_CODE` |
| 146 | Unknown ICMPv6 type | `UNKNOWN_ICMPV6_TYPE` |
| 147 | Error retrieving tunnel key | `ERROR_RETRIEVING_TUNNEL_KEY` |
| 148 | Error retrieving tunnel options (unused) | `ERROR_RETRIEVING_TUNNEL_OPTIONS` (deprecated) |
| 149 | Invalid Geneve option (unused) | `INVALID_GENEVE_OPTION` (deprecated) |
| 150 | Unknown L3 target address | `UNKNOWN_L3_TARGET_ADDRESS` |
| 151 | Stale or unroutable IP | `STALE_OR_UNROUTABLE_IP` |
| 152 | No matching local container found (unused) | `NO_MATCHING_LOCAL_CONTAINER_FOUND` (deprecated) |
| 153 | Error while correcting L3 checksum | `ERROR_WHILE_CORRECTING_L3_CHECKSUM` |
| 154 | Error while correcting L4 checksum | `ERROR_WHILE_CORRECTING_L4_CHECKSUM` |
| 155 | CT: Map insertion failed | `CT_MAP_INSERTION_FAILED` |
| 156 | Invalid IPv6 extension header | `INVALID_IPV6_EXTENSION_HEADER` |
| 157 | IP fragmentation not supported | `IP_FRAGMENTATION_NOT_SUPPORTED` |
| 158 | Service backend not found | `SERVICE_BACKEND_NOT_FOUND` |
| 160 | No tunnel/encapsulation endpoint (datapath BUG!) | `NO_TUNNEL_OR_ENCAPSULATION_ENDPOINT` |
| 161 | NAT 46/64 not enabled | `FAILED_TO_INSERT_INTO_PROXYMAP` (name mismatch, value kept) |
| 162 | Reached EDT rate-limiting drop horizon | `REACHED_EDT_RATE_LIMITING_DROP_HORIZON` |
| 163 | Unknown connection tracking state | `UNKNOWN_CONNECTION_TRACKING_STATE` |
| 164 | Local host is unreachable | `LOCAL_HOST_IS_UNREACHABLE` |
| 165 | No configuration available to perform policy decision (unused) | `NO_CONFIGURATION_AVAILABLE_TO_PERFORM_POLICY_DECISION` |
| 166 | Unsupported L2 protocol | `UNSUPPORTED_L2_PROTOCOL` |
| 167 | No mapping for NAT masquerade | `NO_MAPPING_FOR_NAT_MASQUERADE` |
| 168 | Unsupported protocol for NAT masquerade | `UNSUPPORTED_PROTOCOL_FOR_NAT_MASQUERADE` |
| 169 | FIB lookup failed | `FIB_LOOKUP_FAILED` |
| 170 | Encapsulation traffic is prohibited | `ENCAPSULATION_TRAFFIC_IS_PROHIBITED` |
| 171 | Invalid identity | `INVALID_IDENTITY` |
| 172 | Unknown sender | `UNKNOWN_SENDER` |
| 173 | NAT not needed | `NAT_NOT_NEEDED` |
| 174 | Is a ClusterIP | `IS_A_CLUSTERIP` |
| 175 | First logical datagram fragment not found | `FIRST_LOGICAL_DATAGRAM_FRAGMENT_NOT_FOUND` |
| 176 | Forbidden ICMPv6 message | `FORBIDDEN_ICMPV6_MESSAGE` |
| 177 | Denied by LB src range check | `DENIED_BY_LB_SRC_RANGE_CHECK` |
| 178 | Socket lookup failed | `SOCKET_LOOKUP_FAILED` |
| 179 | Socket assign failed | `SOCKET_ASSIGN_FAILED` |
| 180 | Proxy redirection not supported for protocol | `PROXY_REDIRECTION_NOT_SUPPORTED_FOR_PROTOCOL` |
| 181 | Policy denied by denylist | `POLICY_DENY` |
| 182 | VLAN traffic disallowed by VLAN filter | `VLAN_FILTERED` |
| 183 | Incorrect VNI from VTEP | `INVALID_VNI` |
| 184 | Failed to update or lookup TC buffer | `INVALID_TC_BUFFER` |
| 185 | No SID was found for the IP address | `NO_SID` |
| 186 | SRv6 state was removed during tail call | `MISSING_SRV6_STATE` (deprecated) |
| 187 | L3 translation from IPv4 to IPv6 failed (NAT46) | `NAT46` |
| 188 | L3 translation from IPv6 to IPv4 failed (NAT64) | `NAT64` |
| 189 | Authentication required | `AUTH_REQUIRED` |
| 190 | No conntrack map found | `CT_NO_MAP_FOUND` |
| 191 | No nat map found | `SNAT_NO_MAP_FOUND` |
| 192 | Invalid ClusterID | `INVALID_CLUSTER_ID` |
| 193 | Unsupported packet protocol for DSR encapsulation | `UNSUPPORTED_PROTOCOL_FOR_DSR_ENCAP` |
| 194 | No egress gateway found | `NO_EGRESS_GATEWAY` |
| 195 | Traffic is unencrypted | `UNENCRYPTED_TRAFFIC` |
| 196 | TTL exceeded | `TTL_EXCEEDED` |
| 197 | No node ID found | `NO_NODE_ID` |
| 198 | Rate limited | `DROP_RATE_LIMITED` |
| 199 | IGMP handled | `IGMP_HANDLED` |
| 200 | IGMP subscribed | `IGMP_SUBSCRIBED` |
| 201 | Multicast handled | `MULTICAST_HANDLED` |
| 202 | Host datapath not ready | `DROP_HOST_NOT_READY` |
| 203 | Endpoint policy program not available | `DROP_EP_NOT_READY` |
| 204 | No Egress IP configured | `DROP_NO_EGRESS_IP` |
| 205 | Punt to proxy | `DROP_PUNT_PROXY` |
| 206 | No device | (not in proto) |
| 207 | First logical datagram fragment not found from world | `DROP_FRAG_NOT_FOUND_WORLD` |

`DropReasonExt(reason, ext_error)` appends `", <ext_error>"` when non-zero.
Code 159 is unassigned.

BPF file ids (`files.go` ↔ `bpf/lib/source_info.h`): 1 `bpf_host.c`, 2
`bpf_lxc.c`, 3 `bpf_overlay.c`, 4 `bpf_xdp.c`, 5 `bpf_sock.c`, 7
`bpf_wireguard.c`; 101 `drop.h`, 102 `srv6.h`, 103 `icmp6.h`, 104
`nodeport.h`, 105 `lb.h`, 106 `mcast.h`, 107 `ipv4.h`, 108 `conntrack.h`, 109
`local_delivery.h`, 110 `trace.h`, 111 `encap.h`, 112 `host_firewall.h`, 113
`nodeport_egress.h`, 114 `ipv6.h`, 115 `classifiers.h`.

### Agent notifications (`MessageTypeAgent = 130`)

`AgentNotify{Type AgentNotification(u32), Text string}` gob-encoded after the
type byte; `Text` is JSON. JSON dump form:
`{"type":"agent","subtype":"<name>","message":<Text>}`.

| code | const | string | JSON payload struct | flow.AgentEventType |
|---|---|---|---|---|
| 0 | `AgentNotifyUnspec` | unspecified | — | `AGENT_EVENT_UNKNOWN = 0` |
| 1 | `AgentNotifyGeneric` | Message | free text | (1 reserved) |
| 2 | `AgentNotifyStart` | Cilium agent started | `TimeNotification{time RFC3339Nano}` | `AGENT_STARTED = 2` |
| 3 | `AgentNotifyEndpointRegenerateSuccess` | Endpoint regenerated | `EndpointRegenNotification{id,labels,error}` | `ENDPOINT_REGENERATE_SUCCESS = 5` |
| 4 | `AgentNotifyEndpointRegenerateFail` | Failed endpoint regeneration | same | `ENDPOINT_REGENERATE_FAILURE = 6` |
| 5 | `AgentNotifyPolicyUpdated` | Policy updated | `PolicyUpdateNotification{labels,revision,rule_count}` | `POLICY_UPDATED = 3` |
| 6 | `AgentNotifyPolicyDeleted` | Policy deleted | same | `POLICY_DELETED = 4` |
| 7 | `AgentNotifyEndpointCreated` | Endpoint created | `EndpointNotification{…,pod-name,namespace}` | `ENDPOINT_CREATED = 7` |
| 8 | `AgentNotifyEndpointDeleted` | Endpoint deleted | same | `ENDPOINT_DELETED = 8` |
| 9 | `AgentNotifyIPCacheUpserted` | IPCache entry upserted | `IPCacheNotification{cidr,id,old-id,host-ip,old-host-ip,encrypt-key,namespace,pod-name}` | `IPCACHE_UPSERTED = 9` |
| 10 | `AgentNotifyIPCacheDeleted` | IPCache entry deleted | same | `IPCACHE_DELETED = 10` |

`MessageTypeAccessLog = 129` carries a gob `accesslog.LogRecord` (see the proxy
inventory); Hubble's `seven` parser turns it into an L7 flow.

### Monitor socket payload (gob)

```go
type Payload struct { Data []byte; CPU int; Lost uint64; Type int }  // Type: 9 EventSample, 2 RecordLost
type Meta    struct { Size uint32; _ [28]byte }                      // legacy 32-byte prefix, unused by 1.2 listeners
```

### Hubble internal types

`observerTypes.MonitorEvent{UUID, Timestamp, NodeName, Payload}` where Payload
is `*PerfEvent{Data, CPU}`, `*AgentEvent{Type, Message any}` or
`*LostEvent{Source, NumLostEvents, CPU, First, Last}`. `v1.Event{Timestamp,
Event any}` where Event is `*flow.Flow`, `*flow.LostEvent`, `*flow.AgentEvent`
or `*flow.DebugEvent`.

Ring (`pkg/hubble/container`): `Capacity` must be `2^n − 1` (1..65535; default
`Capacity4095`); `dataLen = mask+1`, one slot permanently reserved so `Cap() =
dataLen − 1`. Single monotonically increasing `write` counter (`atomic.Uint64`),
entries stored via `atomic.StorePointer`. Readers derive a cycle number
(`idx >> cycleExp`) and detect overwrite: reading a slot whose cycle is older
than `writeCycle − 1` (or ≥ `writeCycle + halfCycle`) yields a synthetic
`LostEvent{Source: HUBBLE_RING_BUFFER, NumEventsLost: 1}`. `readFrom` blocks on
a `notifyCh` that `Write` closes-and-replaces. `LastWriteParallel() = write − 2`
(the slot at `write−1` may still be mid-store).

### Files on disk

- `/var/run/cilium/monitor1_2.sock`, `/var/run/cilium/hubble.sock` (mode set by
  `api.SetDefaultPermissions` when root).
- Hubble export file at `--hubble-export-file-path`; rotated by
  `cilium/lumberjack/v2` as `<name>-<timestamp>.<ext>[.gz]`.
- Dynamic metrics YAML (`--hubble-dynamic-metrics-config-path`):

```yaml
metrics:
  - name: drop                      # handler name
    contextOptions:
      - name: sourceContext
        values: [pod, namespace]    # "|"-alternatives become list entries
      - name: labelsContext
        values: [source_namespace, destination_namespace]
    includeFilters: [ <flow.FlowFilter JSON> ]
    excludeFilters: [ ... ]
```

- Dynamic flow-log YAML (`--hubble-flowlogs-config-path`):

```yaml
flowLogs:
  - name: all                       # unique
    filePath: /var/run/cilium/hubble/events.log   # unique; "stdout" allowed
    fieldMask: [time, source.namespace, ...]
    fieldAggregate: [source.namespace, destination.namespace]
    aggregationInterval: 30s
    includeFilters: [...]
    excludeFilters: [...]
    fileMaxSizeMb: 10
    fileMaxBackups: 5
    fileCompress: false
    end: "2026-12-31T00:00:00Z"     # exporter goes inactive after this
```

## External interfaces

### `flow.proto` — `message Flow` (field numbers are the contract)

| # | field | type | notes |
|---|---|---|---|
| 1 | `time` | Timestamp | |
| 34 | `uuid` | string | per-node generated (`bufuuid`) |
| 41 | `emitter` | `Emitter{name=1, version=2}` | `"cilium"`, agent version |
| 2 | `verdict` | `Verdict` | 0 UNKNOWN, 1 FORWARDED, 2 DROPPED, 3 ERROR, 4 AUDIT, 5 REDIRECTED, 6 TRACED, 7 TRANSLATED |
| 3 | `drop_reason` | uint32 (deprecated) | raw code |
| 35 | `auth_type` | `AuthType` | 0 DISABLED, 1 SPIRE, 2 TEST_ALWAYS_FAIL |
| 4 | `ethernet` | `Ethernet{source=1,destination=2}` | MAC strings |
| 5 | `IP` | `IP{source=1, destination=2, ipVersion=3, encrypted=4, source_xlated=5}` | `IPVersion`: 0 IP_NOT_USED, 1 IPv4, 2 IPv6 |
| 6 | `l4` | `Layer4` oneof `protocol` | `TCP=1{source_port,destination_port,flags TCPFlags}`, `UDP=2`, `ICMPv4=3{type,code}`, `ICMPv6=4`, `SCTP=5{…,chunk_type}`, `VRRP=6{type,vrid,priority}`, `IGMP=7{type,group_address}` |
| 39 | `tunnel` | `Tunnel{protocol=1 (0 UNKNOWN,1 VXLAN,2 GENEVE), IP=2, l4=3, vni=4}` | outer headers when overlay-classified |
| 7 | reserved | | |
| 8 | `source` | `Endpoint` | |
| 9 | `destination` | `Endpoint` | |
| 10 | `Type` | `FlowType` | 0 UNKNOWN_TYPE, 1 L3_L4, 2 L7, 3 SOCK |
| 11 | `node_name` | string | `cluster/node` |
| 37 | `node_labels` | repeated string | |
| 12 | reserved | | |
| 13 | `source_names` | repeated string | DNS names (from dst endpoint's DNS history) |
| 14 | `destination_names` | repeated string | |
| 15 | `l7` | `Layer7{type=1 (0 UNKNOWN,1 REQUEST,2 RESPONSE,3 SAMPLE), latency_ns=2, oneof record: dns=100, http=101, kafka=102 (deprecated)}` | |
| 16 | `reply` | bool (deprecated) | |
| 17,18 | reserved | | |
| 19 | `event_type` | `CiliumEventType{type=1, sub_type=2}` | raw monitor type/subtype |
| 20 | `source_service` | `Service{name=1,namespace=2}` | |
| 21 | `destination_service` | `Service` | |
| 22 | `traffic_direction` | `TrafficDirection` | 0 UNKNOWN, 1 INGRESS, 2 EGRESS |
| 23 | `policy_match_type` | uint32 | see match types above |
| 24 | `trace_observation_point` | `TraceObservationPoint` | |
| 36 | `trace_reason` | `TraceReason` | |
| 38 | `file` | `FileInfo{name=1, line=2}` | drop site |
| 40 | `ip_trace_id` | `IPTraceID{trace_id=1, ip_option_type=2}` | |
| 25 | `drop_reason_desc` | `DropReason` | |
| 26 | `is_reply` | BoolValue | nil when unknown |
| 27 | `debug_capture_point` | `DebugCapturePoint` | |
| 28 | `interface` | `NetworkInterface{index=1, name=2}` | |
| 29 | `proxy_port` | uint32 | |
| 30 | `trace_context` | `TraceContext{parent=1 TraceParent{trace_id=1}}` | W3C traceparent from L7 |
| 31 | `sock_xlate_point` | `SocketTranslationPoint` | 0..4 as above |
| 32 | `socket_cookie` | uint64 | |
| 33 | `cgroup_id` | uint64 | |
| 100000 | `Summary` | string (deprecated) | human summary; CLI still prints it |
| 150000 | `extensions` | `google.protobuf.Any` | |
| 21001 | `egress_allowed_by` | repeated `Policy{name=1,namespace=2,labels=3,revision=4,kind=5}` | |
| 21002 | `ingress_allowed_by` | repeated Policy | |
| 21004 | `egress_denied_by` | repeated Policy | |
| 21005 | `ingress_denied_by` | repeated Policy | |
| 21006 | `policy_log` | repeated string | |
| 21007 | `aggregate` | `Aggregate{ingress_flow_count=1, egress_flow_count=2, unknown_direction_flow_count=3}` | exporter aggregation |

`Endpoint{ID=1, identity=2, namespace=3, labels=4, pod_name=5, workloads=6
(Workload{name=1,kind=2}), cluster_name=7}`. `TCPFlags{FIN=1,SYN=2,RST=3,PSH=4,
ACK=5,URG=6,ECE=7,CWR=8,NS=9}`. `SCTPChunkType`: 0 UNSUPPORTED, 1 INIT, 2
INIT_ACK, 3 SHUTDOWN, 4 SHUTDOWN_ACK, 5 SHUTDOWN_COMPLETE, 6 ABORT.
`DNS{query=1, ips=2, ttl=3, cnames=4, observation_source=5, rcode=6, qtypes=7,
rrtypes=8}`. `HTTP{code=1, method=2, url=3, protocol=4, headers=5
HTTPHeader{key,value}}`. `Kafka{error_code, api_version, api_key,
correlation_id, topic}` (deprecated).

`FlowFilter` (all repeated, OR within a field, AND across fields; a request's
`whitelist` is OR of filters, `blacklist` likewise): `uuid=29`, `source_ip=1`,
`source_ip_xlated=34`, `source_pod=2`, `source_fqdn=7`, `source_label=10`,
`source_service=16`, `source_workload=26`, `source_cluster_name=37`,
`destination_ip=3`, `destination_pod=4`, `destination_fqdn=8`,
`destination_label=11`, `destination_service=17`, `destination_workload=27`,
`destination_cluster_name=38`, `traffic_direction=30`, `verdict=5`,
`drop_reason_desc=33`, `interface=35`, `event_type=6`
(`EventTypeFilter{type, match_sub_type, sub_type}`), `http_status_code=9`,
`protocol=12`, `source_port=13`, `destination_port=14`, `reply=15`,
`dns_query=18`, `source_identity=19`, `destination_identity=20`,
`http_method=21`, `http_path=22`, `http_url=31`, `http_header=32`,
`tcp_flags=23`, `node_name=24`, `node_labels=36`, `ip_version=25`,
`trace_id=28`, `ip_trace_id=39`, `encrypted=40`,
`experimental.cel_expression=999.1`. Pod/fqdn/node filters accept prefix
(`ns/`) and glob patterns; ports and status codes accept ranges/prefixes.

Other top-level messages: `LostEvent{source=1 (0 UNKNOWN, 1
PERF_EVENT_RING_BUFFER, 2 OBSERVER_EVENTS_QUEUE, 3 HUBBLE_RING_BUFFER),
num_events_lost=2, cpu=3, first=4, last=5}`; `AgentEvent{type=1, oneof
notification: unknown=100, agent_start=101, policy_update=102,
endpoint_regenerate=103, endpoint_update=104, ipcache_update=105,
service_upsert=106 (dep), service_delete=107 (dep)}`; `DebugEvent{type=1,
source=2 Endpoint, hash=3, arg1=4, arg2=5, arg3=6, message=7, cpu=8}`;
`EventType{UNKNOWN=0, EventSample=9, RecordLost=2}`.

### `observer.proto` — `service Observer`

| rpc | request | response |
|---|---|---|
| `GetFlows` | `GetFlowsRequest{number=1, first=9, follow=3, blacklist=5, whitelist=6, since=7, until=8, field_mask=10, experimental=999, extensions=150000}` | stream `GetFlowsResponse{oneof: flow=1, node_status=2 (relay.NodeStatusEvent), lost_events=3; node_name=1000, time=1001}` |
| `GetAgentEvents` | `{number=1, first=9, follow=2, since=7, until=8}` | stream `{agent_event=1, node_name=1000, time=1001}` |
| `GetDebugEvents` | same shape | stream `{debug_event=1, node_name=1000, time=1001}` |
| `GetNodes` | `{}` | `{nodes: Node{name, version, address, state relay.NodeState, tls TLS{enabled, server_name}, uptime_ns, num_flows, max_flows, seen_flows}}` — local server returns `Unimplemented`; relay implements |
| `GetNamespaces` | `{}` | `{namespaces: Namespace{cluster=1, namespace=2}}` |
| `ServerStatus` | `{}` | `{num_flows, max_flows, seen_flows, uptime_ns, num_connected_nodes, num_unavailable_nodes, unavailable_nodes, version, flows_rate}` |

`ExportEvent` (used by the exporter JSON lines): oneof `flow=1, node_status=2,
lost_events=3, agent_event=4, debug_event=5`; `node_name=1000`, `time=1001`.

Semantics pinned by `local_observer.go`: `first && follow` →
`InvalidArgument`; `first` w/o `since` → start at `OldestWrite()`; `follow &&
number==0 && since==nil` → start at `LastWriteParallel()` (live tail only);
otherwise walk backwards applying filters until `number` matches or `since`
exceeded, then replay forward. `until` is checked forward. Lost-event
responses are coalesced per `LostEventSendInterval`. `field_mask` allocates one
`Flow` and copies only masked paths. gRPC metadata `hubble-server-version` is
attached by the server.

### `peer.proto` — `service Peer`

`Notify(NotifyRequest{}) returns (stream ChangeNotification{name=1, address=2,
type=3 (0 UNKNOWN, 1 PEER_ADDED, 2 PEER_DELETED, 3 PEER_UPDATED), tls=4
TLS{server_name=1}})`. On connect the server replays all known nodes as
`PEER_ADDED`; a node IP change is sent as `PEER_DELETED(old)` +
`PEER_ADDED(new)`; other node updates as `PEER_UPDATED`. Address is
`<nodeIP>:<hubblePort>` (family order per `--prefer-ipv6`). Per-stream send
buffer default from `serviceoption.WithMaxSendBufferSize`.

### `relay.proto`

`NodeStatusEvent{state_change=1, node_names=2, message=3}`; `NodeState`: 0
UNKNOWN, 1 NODE_CONNECTED, 2 NODE_UNAVAILABLE, 3 NODE_GONE, 4 NODE_ERROR.

### gRPC server assembly

`pkg/hubble/server`: `grpc.NewServer` with optional
`credentials.NewTLS(certloader)`, `grpc_prometheus` metrics, health service
(`grpc_health_v1`), `reflection.Register`, observer + peer registered on the
same listener(s): unix socket always, TCP when `--hubble-listen-address` set.

### Hubble Relay wire behavior

- `PeerManager` connects to `--peer-service`, consumes `Peer.Notify`, keeps a
  map of peers; per peer a gRPC `ClientConn` to `address` with TLS server name
  from the notification (`RemoteClientBuilder`), reconnect with
  `backoff.Exponential{Min: 1s, Max: 1m, Factor: 2.0}` (+jitter), connection
  check every `connCheckInterval`, retry timeout 30s; status counted per
  `connectivity.State` in `hubble_relay_pool_peer_connection_status`.
- `GetFlows` fan-out: for every peer with a READY/IDLE conn open a client
  `GetFlows` with the same request (metadata forwarded); errors aggregated per
  10s window into `node_status` events; in `follow` mode peers are re-scanned
  every 2s (`PeerUpdateInterval`) and new ones joined. Results go through a
  min-heap `PriorityQueue` keyed on `GetFlowsResponse.time`, size `min(100,
  number*peers)`; when full the oldest pops; a `sort-buffer-drain-timeout`
  (1s) ticker flushes entries older than `now − timeout`. Sends
  `NODE_CONNECTED` / `NODE_UNAVAILABLE` status events first.
- `GetNodes`/`ServerStatus` query each peer's `ServerStatus` and aggregate
  (`num_connected_nodes`, `unavailable_nodes`, summed flows, averaged rate).
  `GetAgentEvents`/`GetDebugEvents` are `Unimplemented` on relay.
- Metadata key `hubble-relay-version` on outgoing calls.

### Hubble UI integration

Helm `templates/hubble-ui/deployment.yaml`: backend container env
`EVENTS_SERVER_PORT=8090`, `FLOWS_API_ADDR=hubble-relay:443` +
`TLS_TO_RELAY_ENABLED=true`, `TLS_RELAY_SERVER_NAME=<hubble.relay.tls.server.relayName>`,
`TLS_RELAY_CA_CERT_FILES=/var/lib/hubble-ui/certs/hubble-relay-ca.crt`,
`TLS_RELAY_CLIENT_CERT_FILE/KEY_FILE` (secret `hubble-ui-client-certs`), or
`FLOWS_API_ADDR=hubble-relay:80` without TLS. The backend only uses the
Observer API via relay: `GetFlows` (follow, with whitelist/blacklist built
from UI filters), `GetNodes`, `GetNamespaces`, `ServerStatus`. nginx
(`_nginx.tpl`) listens `8081`, `location <baseUrl>api` → `http://127.0.0.1:8090`
(grpc-web), `/healthz`.

### In-tree `hubble` CLI

`hubble/` builds the `hubble` binary (`hubble observe [flows|agent-events|debug-events]`,
`hubble list nodes|namespaces`, `hubble status`, `hubble watch peers`,
`hubble reflect`, `hubble config`, `hubble version`). It is the former
cilium/hubble repository merged in; largest files `pkg/printer/printer.go`
(1065; compact/dict/json/jsonpb/tab output, colouring) and
`cmd/observe/flows_filter.go` (846; every `--from-*/--to-*/--*` flag → a
`FlowFilter` pair). Talks only Observer gRPC, default target
`unix:///var/run/cilium/hubble.sock`, `--server`, `--tls`, `--tls-ca-cert-files`,
`--tls-client-cert-file/--tls-client-key-file`, `--tls-server-name`,
`--tls-allow-insecure`. Wire compatibility with any Rust server therefore
reduces to `observer.proto` + `flow.proto` field-for-field.

## Dependencies

- **Datapath inventory** (`bpf/lib/*.h`): struct layouts above; `cilium_events`
  map (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`, max_entries = possible CPUs, pinned
  under `/sys/fs/bpf/tc/globals/cilium_events`); `EVENT_SOURCE`, `get_hash`,
  `ctx_classify`, `compute_capture_len`, `ratelimit_check_and_take`.
- **Endpoint manager** (`GetEndpointInfo(ip)`, `LookupCiliumID(id)`,
  `ep.DNSHistory.LookupIP`, `GetPolicyCorrelationInfoForKey`) — inventories for
  endpoints and FQDN proxy.
- **Identity allocator** (`LookupIdentityByID`), **ipcache**
  (`LookupSecIDByIP`, `GetK8sMetadata`), **LB StateDB** `Table[*Frontend]`
  (`LookupFrontendByTuple` TCP then UDP, `ScopeExternal`), **link cache**
  (ifindex → name), **cgroup manager** (`GetPodMetadataForContainer(cgroup_id)`),
  **node manager** (`Notifier` for peer service), **node types**
  (`GetAbsoluteNodeName`).
- **Proxy accesslog** (`pkg/proxy/accesslog.LogRecord`) for L7 flows.
- **k8s client** (dropeventemitter `EventRecorder`; pod object refs).
- External libs in reference: `cilium/ebpf/perf`, `gopacket` (layers:
  Ethernet, IPv4, IPv6, TCP, UDP, SCTP, ICMPv4, ICMPv6, VRRPv2, IGMPv1or2,
  VXLAN, Geneve), `google.golang.org/grpc` + `grpc_prometheus`,
  `prometheus/client_golang`, `cilium/lumberjack/v2`, `google/cel-go` (CEL
  filter), `sigs.k8s.io/yaml`.

## Kernel / platform requirements

Userspace-only apart from: `perf_event_open` per CPU + mmap of `64 pages ×
page_size` rings (`PERF_RECORD_SAMPLE`/`PERF_RECORD_LOST`); `bpf_obj_get` on the
pinned `cilium_events` map (the perf reader takes fd ownership via
`perf.NewReader`). No arch-specific code; all struct decoding is *native
endian* (`binary.NativeEndian`), so an aarch64 reimplementation must not assume
little-endian unless it also assumes the datapath and reader share a host —
which they do. Bitfield byte (`dir:2,ipv6:1,match_type:3,audited:1,l3:1`) is
LSB-first on both x86-64 and arm64 with clang. `TraceSockNotify` needs
`bpf_get_socket_cookie`/`bpf_get_current_cgroup_id` on the datapath side only.

## Tests

- **Unit**: `pkg/monitor/datapath_*_test.go` decode every version from byte
  fixtures (incl. truncated data, version > max, `DataOffset` per version),
  `dissect_test.go` (VXLAN/Geneve inner headers, summaries), `format_test.go` +
  `fuzz_test.go` (formatter over random payloads), `payload` gob round-trip,
  `agent_test.go` (listener register/remove, perf reader start/stop).
- `pkg/hubble/container` (1,262 lines): ring wrap-around, cycle arithmetic,
  concurrent writers/readers, `NextFollow` wake-ups, lost-event synthesis.
- `pkg/hubble/parser/threefour` (2,729): full flows for drop/trace/policy
  verdict/debug-capture, IPv4/IPv6/overlay, direction and reply inference,
  identity conflict rules, SNAT `source_xlated`, ICMP/SCTP/VRRP/IGMP decode.
  `seven` (1,014): DNS/HTTP/Kafka records, redaction of query/userinfo/headers,
  traceparent extraction, latency. `sock` (467). `agent`/`debug`.
- `pkg/hubble/filters` (5,533): every filter, glob/prefix semantics, CEL.
- `pkg/hubble/observer` (931): `GetFlows` positioning (`number`, `first`,
  `since`/`until`, `follow`), field masks, lost-event interval, namespace list.
- `pkg/hubble/metrics` (~3,000): label sets per handler, context options
  parsing (`ContextOptionsHelp` grammar), pod-deletion cleanup, dynamic reload
  add/remove/update, include/exclude filters.
- `pkg/hubble/exporter` (2,800): rotation config, dynamic reload hash/ end time,
  field mask, aggregation counts, `script_test.go` (hive script tests).
- `pkg/hubble/relay` (3,518): pool connect/backoff/status, `sortFlows` ordering
  and drain, error aggregation windows, `GetNodes` merge.
- `pkg/hubble/peer` (1,705): handler add/update/delete translation, address
  family preference, TLS name, buffer overflow behaviour.
- **e2e**: `test/k8s/hubble.go` (`K8sAgentHubbleTest`): L3/L4 flow visible via
  `hubble observe`, TLS certificate served, L3/L4 and L7 via hubble-relay,
  FQDN policy flows via relay. `cilium-cli/connectivity` tests use Hubble flows
  to validate drops/forwards in every conformance workflow (all
  `.github/workflows/conformance-*.yaml` enable `hubble.enabled=true` and
  `hubble.relay.enabled=true`).

## Rust mapping

**Protobuf / gRPC (`prost` + `tonic`)** — the four `.proto` files compile
unchanged with `tonic-build`; `flow.proto` uses `google.protobuf.{Any,
Timestamp, BoolValue, UInt32Value, Int32Value, FieldMask}` (use
`prost-types`; `prost-wkt-types` if JSON with canonical wrapper encoding is
needed for export). Keep the reference field numbers exactly — the Hubble CLI
and UI are external consumers. Two Go-isms to reproduce deliberately: (1) the
exporter writes `ExportEvent` as protojson (`json.Marshal(protojson)`), so
field names are the proto JSON names (`"IP"`, `"l4"`, `"Type"`, `"Summary"`);
`prost` has no protojson — use `pbjson`/`pbjson-build` or serialize by hand,
and test against a captured Go export line. (2) `field_mask` copy is done
reflectively in Go; in Rust either generate a per-field match from the
descriptor at build time or restrict masks to a known path set.
`ServerStatus.version` and metadata `hubble-server-version` should be set.
Unix + TCP listeners: `tonic` with `tokio::net::UnixListener` via
`tonic::transport::server::Connected` stream; TLS via `tonic`'s `rustls`
feature (server cert + optional client CA set = mTLS) with a
certloader-equivalent that reloads on file change.

**Perf ring / monitor agent** — `aya`/`libbpf-rs` `PerfEventArray` readers
(one per CPU, 64 pages each). Native-endian fixed-layout decoding is a natural
fit for `zerocopy`/`bytemuck` `#[repr(C)]` structs with per-version tail
handling (v0/v1/v2/v3 lengths as constants; reject unknown versions;
`DataOffset` = header len + ext len). The monitor unix socket's gob framing is
the one truly Go-specific piece: `cilium-dbg monitor` and any third-party
listener expect a gob stream of `Payload`. Options: implement the tiny gob
subset needed (one struct type, four fields — a few hundred lines, well
specified) to stay compatible with existing tooling, or declare the 1.2 socket
out of scope and expose only Hubble. Recommend implementing the gob subset;
it is small and unlocks reuse of `cilium-dbg monitor` for debugging the new
datapath.

**Ring buffer** — the Go ring is a single-writer, multi-reader, lock-free
structure over `*Event` pointers with cycle-based overwrite detection. In Rust:
`Vec<AtomicPtr<Arc<Event>>>` or a `Box<[ArcSwapOption<Event>]>` (`arc-swap`)
indexed by `write & mask`, `AtomicU64` write counter, a `tokio::sync::Notify`
for followers; the cycle arithmetic (`cycleExp`, `halfCycle`) transfers
verbatim. Capacity constraint `2^n − 1 ≤ 65535` can be kept for flag
compatibility; internally it is just a power-of-two slot array with one
reserved slot. `Arc<Flow>` sharing lets many `GetFlows` streams read without
copying; field masks copy into a fresh message per stream.

**Pipeline** — `monitor consumer → bounded mpsc (hubble-event-queue-size) →
decode task → ring`; side hooks (`OnDecodedFlow`: metrics, exporter, drop
emitter, namespace tracker) run inline in the decode task as in Go. Lost-event
accounting has three sources with distinct semantics (perf `LostSamples`,
mpsc `try_send` failure coalesced per 1 s, ring overwrite) — keep all three;
Hubble UI shows them.

**Parser enrichment — the coupling point.** `threefour::Decode` calls, per
packet, `EndpointGetter::GetEndpointInfo(ip)` (twice), `IPGetter::LookupSecIDByIP`
+ `GetK8sMetadata` (fallback), `IdentityGetter::GetIdentity(id)` (labels),
`ServiceGetter::GetServiceByAddr(ip,port)` (StateDB frontend table, TCP then
UDP), `DNSGetter::GetNamesOf(epID, ip)` (endpoint DNS history), `LinkGetter`
(ifindex → name) and optionally the endpoint's policy map for correlation. In
Go these are direct in-process interface calls into the agent's endpoint
manager, identity cache, ipcache, LB StateDB and link cache. For flowsdn this
fixes the rule that the Hubble decoder must run **inside the agent process**
with read access to those state tables (or against read-only snapshots pushed
to it). Define a `trait FlowEnricher` mirroring the six getter traits and
implement it over the flowsdn endpoint/identity/service/ipcache state
(inventories 02/03/05/06); the `EndpointResolver` identity-conflict table
(six special cases where datapath identity and userspace identity legitimately
disagree — TO_OVERLAY host/remote-node, FROM_ENDPOINT health/world, FROM_HOST
world/kube-apiserver, TO_ENDPOINT host/remote-node) must be ported as-is or
Hubble output will regress vs. the reference. The label-filter step
(`SortAndFilterLabels` — drop `cidr:` labels except for CIDR identities, sort)
is also part of the contract.

**Packet dissection** — `gopacket` has no drop-in; use `etherparse` (Ethernet,
VLAN, IPv4/6 + extensions, TCP/UDP/ICMPv4/v6) plus hand parsers for SCTP
(common header + first chunk type), VRRPv2 (type/vrid/priority), IGMPv1/2
(type/group), VXLAN (8-byte header, VNI) and Geneve (variable options). Inner
overlay parsing repeats the same stack. About 800 lines.

**Filters** — 25 filter builders over `FlowFilter`; straightforward closures
`Box<dyn Fn(&Event) -> bool>`. Nonempty experimental CEL expressions are
rejected with `InvalidArgument` (#145; spec 11 §12.5). Supported Pod/FQDN/node
patterns retain glob and `ns/` semantics, with independent implementation/tests.

**Metrics** — `prometheus` crate `IntCounterVec`/`HistogramVec` with dynamic
label names computed from context options at handler init (the Go code
appends context label names to fixed labels — labels must be decided before
registration). Ten handlers ≈ 1,200 lines; dynamic YAML reload by polling
(10 s) with hash comparison and unregister/re-register, exactly as reference.
Handler names and metric names (`hubble_drop_total`, `hubble_flows_processed_total`,
`hubble_flows_to_world_total`, `hubble_dns_queries_total`,
`hubble_dns_responses_total`, `hubble_dns_response_types_total`,
`hubble_icmp_total`, `hubble_policy_verdicts_total`,
`hubble_port_distribution_total`, `hubble_sctp_chunk_types_total`,
`hubble_tcp_flags_total`, `hubble_http_requests_total`,
`hubble_http_responses_total`, `hubble_http_request_duration_seconds`,
`hubble_lost_events_total`) and their label sets (`drop: reason, protocol`;
`flow: protocol, type, subtype, verdict`; `flows-to-world: protocol, verdict[,
port]`; `dns: rcode, qtypes, ips_returned[, query]` / `type, qtypes[, query]`;
`icmp: family, type`; `policy: direction, match, action`; `port-distribution:
protocol, port`; `sctp: chunk_type, family`; `tcp: flag, family`; `http:
method, protocol[, status], reporter` and `httpV2: method, protocol, status,
reporter` / duration `method, reporter`) are what Grafana dashboards depend on.

**Exporter** — `serde_json` lines of `ExportEvent`; rotation via a small
lumberjack port (size-based, N backups, gzip) — no maintained crate matches
lumberjack's naming exactly, but naming only matters to log shippers; keep
`fileMaxSizeMb`/`fileMaxBackups`/`fileCompress` semantics. Aggregation keyed
on masked fields with interval flush is ~200 lines.

**Relay** — `tonic` client per peer, `tokio::select!` fan-in, `BinaryHeap`
keyed on timestamp with the same `min(100, number*peers)` cap and 1s drain,
exponential backoff via `backoff`/`tokio-retry`. Peer discovery reuses the
Peer service stream. ~2,500 lines.

**Drop event emitter** — needs a k8s `Event` writer (`kube` crate
`events::Recorder`), dedupe map keyed on (pod, reason, peer) with 2 m interval,
`governor` for the rate limit.

Risks / hard parts: protojson fidelity for the exporter and `hubble observe -o
json` compatibility; `field_mask` handling; keeping the drop/trace/debug tables
in lock-step with the flowsdn datapath (generate both sides from one table);
the identity-conflict heuristics in `EndpointResolver`; making the enrichment
lock-free enough to keep up with the perf ring at aggregation level `none`.

## Recommendation

**keep** the monitor pipeline and Hubble server/parser/filters/ring/peer
(they are the observability contract with the ecosystem — Hubble CLI, Hubble
UI, Grafana dashboards, Tetragon/other consumers) — effort **L** (~12–16k
lines: decoders 1.5k, dissection 0.8k, parser+enrichment 2.5k, ring+observer
2k, filters 1.5k, metrics 1.5k, exporter 1k, peer+server+TLS 1k, monitor
socket+gob 0.8k). **keep** metrics and exporter with the same names/format
(dashboards and log shippers depend on them). **keep** the relay as a separate
binary — effort **M** (~2.5k). **defer** drop-event-emitter (alpha upstream,
small, needs k8s event plumbing) and CEL filters. **keep** the gob monitor server subset for `cilium-dbg monitor`;
flowsdn's own monitor client uses Observer RPCs (#141), with no gob decoder. **do not** reimplement the pcap recorder —
it is gone from the reference. Do not port `cilium-dbg monitor`'s text
formatter beyond what is needed for debugging (JSON output via Hubble covers
it), and fix the `DBG_SKIP_POLICY` off-by-one rather than copying it.

## Open questions

- **Resolved #141:** retain the gob socket server compatibility surface;
  implement flowsdn's own monitor client over Observer, without a gob decoder.
  Runtime server and client implementation remain outstanding (spec 11 §12.1).
- **Resolved #22:** `flowsdn-bpf-abi` owns shared Rust numeric tables for BPF
  and userspace. No C headers under ADR-0002. Complete table generation and
  independent pinned-protobuf parity tests remain required (spec 11 §11.6).
- `flow.proto` field 136/161 names (`CT_MISSING_TCP_ACK_FLAG`,
  `FAILED_TO_INSERT_INTO_PROXYMAP`) no longer match the monitor strings
  ("Fragmentation needed", "NAT 46/64 not enabled"). Keep the proto names for
  compatibility, or fork the proto? (Keeping is safer; the CLI prints
  `drop_reason_desc` enum names.)
- Should the Rust observer keep Go's `Summary` (deprecated field 100000)
  populated? The Hubble CLI compact output still prefers it when present for
  L7 flows.
- **Resolved #23:** `PolicySnapshot::correlation_info` is the Hubble-facing
  contract over the realized endpoint policy map and `RuleOrigin` (spec 06
  §§4.3–4.4). The policy owner supplies specificity resolution, labels, logs
  and the realized revision; missing state yields no correlation. The trait
  and verdict projection exist, while its live adapter remains outstanding.
- **Resolved #150:** accept both preferences and warn on explicit legacy
  input. Explicit global wins, including false; otherwise legacy, then false.
  Preserve provenance until resolution (spec 11 §12.10).
- Resolved #152/#239: packaging owns issuance (Helm default, cert-manager,
  supplied Secrets or digest-pinned upstream certgen CronJob). All methods
  retain spec11 server-name and authentication requirements.
