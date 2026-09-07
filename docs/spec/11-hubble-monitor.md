# Observability: monitor pipeline and Hubble — specification

Status: draft. Derived from: `docs/inventory/09-hubble-monitor.md`, reference
cilium v1.20.1 (7d68cfb394) paths `pkg/monitor/**` (`agent`, `api`, `format`,
`payload`, the `datapath_*.go` decoders, `dissect.go`, `logrecord.go`),
`pkg/hubble/**` (`cell`, `monitor`, `observer`, `container`, `parser/**`,
`filters`, `metrics`, `exporter`, `peer`, `server`, `relay`,
`dropeventemitter`), `hubble-relay/**`, `hubble/**` (in-tree CLI),
`api/v1/{flow,observer,peer,relay}/*.proto`, and — for struct layouts only —
`bpf/lib/{notify,drop,trace,trace_sock,policy_log,dbg,source_info,classifiers}.h`.
Governed by ADR-0001 (compatibility at the boundaries), ADR-0002 (Rust only),
ADR-0004 (no Hive, no StateDB).

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* flowsdn does and the exact bytes it exchanges. Where reference behavior
is kept for compatibility, the consumer that depends on it is named
(`cilium-dbg monitor`, `hubble` CLI, Hubble UI, hubble-relay, Grafana
dashboards, log shippers). Where flowsdn deviates, the item is marked
**DEVIATION** with a reason.

Sibling specs this one builds on, and does not repeat:

- `01-bpf-map-abi-loader.md` §3.10 and §4.6 — the `cilium_events` perf channel
  (map name, per-CPU sizing, `(cap_len << 32) | BPF_F_CURRENT_CPU` output
  flags) and the **byte layouts** of every notification struct. This spec
  defines the *semantic interpretation* of those bytes; spec 01 owns the
  offsets.
- `02-datapath-programs.md` §2.7 (versions emitted), §2.8 (drop reason
  numbering is a joint contract), §3.16–3.17 (which pipeline emits which
  event, drop points per pipeline), §5.6 (datapath-side aggregation).
- `03-identity-ipcache.md` §4.4 (numeric identity table), §4.6 (source
  precedence), §3.7 (ipcache model) — the identity and ipcache enrichment
  sources.
- `08-endpoint-agent-api.md` §3.9.1 (endpoint manager indexes), §4.1
  (in-memory endpoint fields incl. `dns_history`, `desired_policy`) — the
  endpoint tables the parser reads.
- `05-service-loadbalancing.md` — the frontend table the parser queries for
  `source_service` / `destination_service`.
- `00-foundation-table-config.md` — the config-key registry that carries the
  `hubble-*` and `monitor-*` keys listed in §6.

## 1. Scope

In scope:

- **The monitor pipeline** (§3.1–3.6): per-CPU perf ring consumption, lost
  event accounting, wakeup policy, the agent-internal event bus (consumers and
  listeners), the `monitor1_2.sock` listener protocol including the exact gob
  wire bytes, listener queue sizing and drop policy, agent-originated event
  injection, and the aggregation levels the agent configures in the datapath.
- **Event decoding** (§3.7, §4.2–4.9): every notification type, every version
  length, field semantics, and the complete frozen numeric tables — message
  types, trace observation points, trace reasons and the encrypt mask, debug
  subtypes, debug capture points, drop reasons paired with their `flow.proto`
  enum names, BPF source-file ids, policy match types, agent notification
  subtypes.
- **The Hubble flow parser** (§3.8–3.12): L2/L3/L4/L7 dissection, the six
  enrichment sources expressed as one `FlowEnricher` trait, endpoint
  resolution and the identity-conflict rules, verdict and drop-reason mapping,
  traffic-direction and reply determination, and the `Flow` protobuf field by
  field with field numbers.
- **The ring buffer** (§3.13, §5.2): capacity as `2^n − 1`, cycle-based
  overwrite detection, reader positioning for `GetFlows`, and what a slow
  reader observes.
- **The gRPC surface** (§3.14–3.17): `Observer` (all six RPCs, `GetFlows`
  with all 25 filter fields and their AND/OR composition), `Peer.Notify`, the
  relay's fan-out (peer discovery, sort buffer, drain timing, backoff, per-peer
  error surfacing), and TLS/mTLS with server-name derivation.
- **Metrics** (§3.18, §8): all 11 handlers with metric names, labels, options,
  context-option grammar, and the dynamic metrics YAML schema.
- **Export** (§3.19): file path, rotation, compression, field masks,
  allow/deny filter lists, the dynamic flow-log config schema, aggregation and
  redaction.
- Configuration keys and defaults (§6), failure modes (§7), test plan (§9),
  kernel/platform requirements (§10), Rust crate design (§11), open decisions
  (§12).

Out of scope (owned elsewhere):

- The `cilium_events` map itself, its sizing, its pin path, and the datapath
  side of rate limiting: `01-bpf-map-abi-loader.md`, `02-datapath-programs.md`.
- The L7 access-log record produced by the DNS proxy and Envoy: the L7 spec
  owns `LogRecord`; this spec owns only the `LogRecord → flow.Layer7` mapping.
- The pcap recorder (`pkg/recorder`, `api/v1/recorder`, the `Recorder` gRPC
  service). It is **gone from the reference at v1.20.1**; only the reserved
  enum slot `CILIUM_NOTIFY_CAPTURE = 6` remains. flowsdn MUST NOT implement it
  and MUST keep slot 6 reserved.
- The Hubble UI (consumed unchanged as an upstream image; flowsdn implements
  only the server side it talks to, via relay).
- The `hubble` CLI itself. flowsdn does not ship one; the upstream `hubble`
  binary MUST work unmodified against flowsdn's Observer service. That is the
  reason `flow.proto` and `observer.proto` are frozen field-for-field.
- CEL filters (`FlowFilter.experimental.cel_expression`) — **deferred**, see
  §12.5.
- The Kubernetes `PacketDrop` event emitter (`pkg/hubble/dropeventemitter`) —
  **deferred**, alpha upstream; its flags are accepted and ignored (§6.5).

## 2. Compatibility contract

Everything in this section is frozen: an upstream consumer breaks if it
changes.

### 2.1 Sockets, addresses and file paths

| Item | Value | Consumer |
|---|---|---|
| Monitor listener socket | `/var/run/cilium/monitor1_2.sock` (unix stream) | `cilium-dbg monitor`, third-party listeners |
| Hubble Observer socket | `/var/run/cilium/hubble.sock` (unix stream) | `hubble` CLI, hubble-relay's peer target |
| Hubble TCP listener | `--hubble-listen-address`, conventionally `:4244` | hubble-relay, Hubble UI backend |
| Hubble metrics listener | `--hubble-metrics-server`, conventionally `:9965` | Prometheus |
| Relay listener | `:4245` | `hubble` CLI, Hubble UI backend |
| Relay health listener | `:4222` (gRPC health) | k8s probes |
| Relay peer target | `unix:///var/run/cilium/hubble.sock` | relay → agent |
| Hubble peer Service name | `hubble-peer`, gRPC service name `hubble-grpc`, port 4244 | Helm, relay |
| TLS server name domain | `cilium.io` | certificate issuance |
| Export file | `--hubble-export-file-path`, rotated `<base>-<timestamp><ext>[.gz]` | log shippers |

Unix sockets MUST be created with the same permission policy as the agent's
other sockets (spec 08 §3.11.1): group-owned by `--socket-group` where set,
mode `0660`, when the agent runs as root.

### 2.2 Wire formats

| Format | Frozen by | Section |
|---|---|---|
| perf sample bytes (`struct \|\| cap_len packet bytes`) | datapath ↔ any monitor reader | spec 01 §4.6, this spec §4.2–4.7 |
| gob stream of `payload.Payload` on `monitor1_2.sock` | `cilium-dbg monitor` | §3.5, §4.10 |
| `flow.proto`, `observer.proto`, `peer.proto`, `relay.proto` field numbers and enum values | `hubble` CLI, Hubble UI, relay, third-party Observer clients | §4.11–4.15 |
| protojson (`UseProtoNames: true`) of `observer.ExportEvent`, one compact object per line | log shippers, `hubble observe -o jsonpb` | §3.19.2 |
| Prometheus metric names and label sets | Grafana dashboards | §8.1 |
| Dynamic metrics YAML, dynamic flow-log YAML | operators' ConfigMaps | §4.16, §4.17 |

### 2.3 Numeric tables shared with the datapath

Message types (§4.1), trace observation points (§4.3), trace reasons (§4.3),
drop reasons (§4.8), debug subtypes (§4.6), debug capture points (§4.6), BPF
source-file ids (§4.9), policy match types (§4.5) and the numeric identity
table (spec 03 §4.4) are a **single source of truth shared between the BPF
programs, the decoder and `flow.proto`**. flowsdn MUST generate the BPF-side
constants, the userspace enums and a `flow.proto`-equivalence test from one
table (§11.6). A value MUST NOT be reused after retirement; new drop reasons
are allocated ≥ 208 (spec 02 §2.8).

### 2.4 Deliberate reference bugs *not* reproduced

1. **`DBG_SKIP_POLICY` off-by-one.** The reference's Go `iota` list in
   `pkg/monitor/datapath_debug.go` omits `DbgSkipPolicy`, so its
   `DbgLb6LoopbackSnat` = 66 and `DbgLb6LoopbackSnatRev` = 67 disagree with
   `bpf/lib/dbg.h` (67, 68) and with `flow.proto`
   (`DBG_LB6_LOOPBACK_SNAT = 67`, `DBG_LB6_LOOPBACK_SNAT_REV = 68`).
   The Hubble debug parser casts the raw subtype straight to
   `flow.DebugEventType`, so Hubble is already correct; only
   `cilium-dbg monitor -v` text is wrong for those two codes.
   **DEVIATION**: flowsdn uses the `dbg.h` / `flow.proto` numbering
   everywhere, including the text formatter. Reason: the table is generated
   once (§2.3) and cannot hold two numberings; the divergent values are
   debug-only and have no persisted consumers. (ADR-0001 — compatibility is
   defined against the protobuf, which is the published interface.)
2. **`flow.proto` drop-reason names 136 and 161** no longer match their
   monitor strings (`CT_MISSING_TCP_ACK_FLAG` vs "Fragmentation needed";
   `FAILED_TO_INSERT_INTO_PROXYMAP` vs "NAT 46/64 not enabled"). flowsdn
   **keeps both** — the proto name because `hubble observe` prints
   `drop_reason_desc` enum names and filters accept them, the monitor string
   because `cilium-dbg monitor` prints it. This is not a deviation; it is the
   reference's mismatch preserved deliberately. See §12.6.
3. `TraceObservationPoint` 0 is `TO_LXC` in the datapath but
   `UNKNOWN_POINT = 0` in `flow.proto`; the parser maps datapath subtype 0 to
   `TO_ENDPOINT = 101`. Preserved exactly (§4.3).

### 2.5 Configuration keys

Every key in §6 keeps its reference name and default so an existing
`cilium-config` ConfigMap and an existing Helm values file work unchanged
(ADR-0001). Keys accepted but without effect are listed in §6.5.

---

## 3. Behavior

### 3.1 Pipeline overview

```
 BPF programs ──perf_event_output──▶ cilium_events (per-CPU perf rings)
                                          │
                                  [monitor agent: one reader task]
                                          │
                    ┌─────────────────────┴──────────────────────┐
                    ▼                                            ▼
          consumers (in-process)                       listeners (monitor1_2.sock)
                    │                                            │
                    │                                    gob(Payload) per conn
        bounded mpsc (hubble-event-queue-size)
                    │
          [hubble decode task]  parser: threefour | seven | sock | agent | debug
                    │                    ▲
                    │                    └── FlowEnricher (six sources, §3.10)
                    ├──▶ OnDecodedFlow hooks: metrics, exporter, namespace tracker
                    ▼
              ring buffer (2^n − 1 slots)
                    │
             RingReader per GetFlows stream ──▶ filters ──▶ field mask ──▶ gRPC
```

Agent-originated events (`MessageTypeAgent`, `MessageTypeAccessLog`) are
injected at the fan-out point, not through the perf ring (§3.4).

### 3.2 Perf ring consumption

- flowsdn MUST open the **pinned** `cilium_events` map by path rather than
  create it (spec 01 §3.10); the datapath owns the map, and a monitor restart
  MUST NOT disturb it.
- One reader per **possible** CPU (`max_entries` of the map), each mmapping
  `MonitorBufferPages = 64` pages (`--monitor-buffer-pages` is not a flag in
  the reference; 64 is a constant). At a 4 KiB page size that is 256 KiB per
  CPU.
- **Wakeup policy**: watermark of **1 byte** — the reader is woken as soon as
  any sample is written, `wakeup_events` is not used. This is the reference's
  default (`perf.NewReader` with zero `ReaderOptions`) and flowsdn MUST keep it:
  raising the watermark trades tail latency in `hubble observe --follow` for
  throughput, and the ring is already the bottleneck under load. Making the
  watermark configurable is §12.2.
- The reader task is **started lazily** on the first subscriber (listener or
  consumer) and **stopped when the last one goes away**. This is not an
  optimisation detail: with no reader mapped, the kernel discards samples at
  `perf_event_output` time and the datapath pays almost nothing. flowsdn MUST
  keep this behavior. Because Hubble registers a consumer for the agent's
  whole lifetime, in a Hubble-enabled deployment the reader is effectively
  always running.
- Records are read round-robin across the per-CPU rings (epoll over the event
  fds). Ordering between CPUs is **not** guaranteed and consumers MUST NOT
  assume it; ordering within one CPU is guaranteed.
- A record with `LostSamples > 0` is a `PERF_RECORD_LOST` and carries no
  sample bytes. It MUST be turned into:
  - `MonitorStatus.lost += n`,
  - a consumer notification `notify_perf_event_lost(n, cpu)`, and
  - a listener `Payload{Data: none, CPU: cpu, Lost: n, Type: RecordLost(2)}`.
- A record that cannot be parsed as a known perf record type increments
  `MonitorStatus.unknown` and is otherwise ignored. A read error of `EBADFD`
  terminates the reader task (the map fd was closed).
- Trailing garbage: the kernel pads samples to 8 bytes, so a record may carry
  up to 7 bytes of trailing garbage from the ring. Decoders MUST use the
  struct's own length fields (`len_cap`, the version-derived struct length) to
  bound the packet slice and MUST NOT trust `record.len`.

`MonitorStatus`, exposed at `GET /v1/healthz` and in `cilium status`
(spec 08 §4.6):

| Field | Meaning |
|---|---|
| `cpus` | `max_entries` of `cilium_events` = possible CPUs |
| `npages` | 64 |
| `pagesize` | `sysconf(_SC_PAGESIZE)` |
| `lost` | cumulative `PERF_RECORD_LOST` count across all CPUs |
| `unknown` | cumulative unparseable-record count |

When the events map has not been attached yet the status is absent (null), not
zeroed.

### 3.3 The agent-internal event bus

The monitor agent holds two disjoint sets behind one lock:

| | Consumers | Listeners |
|---|---|---|
| Who | in-process (Hubble) | external processes on `monitor1_2.sock` |
| Receives | the decoded Go/Rust value (raw sample bytes + CPU, or an agent event as a typed value) | gob-encoded `Payload` bytes |
| Backpressure | its own bounded channel; overflow is counted as `OBSERVER_EVENTS_QUEUE` loss | per-listener bounded queue; overflow drops that message for that listener only |
| Registration | `register_consumer` / `remove_consumer` | on `accept()` / on write error or EOF |

Notification methods a consumer MUST implement:

| Method | Called with |
|---|---|
| `notify_perf_event(data, cpu)` | one perf sample |
| `notify_perf_event_lost(num_lost, cpu)` | a `PERF_RECORD_LOST` |
| `notify_agent_event(typ, message)` | an agent-originated event, **unencoded** |

Fan-out is synchronous under the agent lock in the reference. flowsdn SHOULD
instead hold a read-lock over an `ArcSwap` of the subscriber list and send
without blocking, because the reference's single mutex is the documented
throughput limit at aggregation level `none` (§12.3). Semantics that MUST be
preserved: every subscriber sees the same event, exactly once, in per-CPU
order; a slow subscriber MUST NOT block the reader or any other subscriber.

### 3.4 Agent-originated event injection

`send_event(typ, event)`:

1. Notify all **consumers** with the unencoded value. Hubble's parser
   dispatches on `typ` (`MessageTypeAgent` → agent parser,
   `MessageTypeAccessLog` → L7 parser).
2. If there are **no listeners**, stop. The encoding below is expensive and
   MUST be skipped.
3. For `MessageTypeAgent`, convert `AgentNotifyMessage{type, notification}`
   into `AgentNotify{type: u32, text: String}` by JSON-encoding
   `notification` into `text` (§4.5 lists the JSON structs).
4. Build the byte buffer `[1 byte typ] || gob(event)` where `event` is the
   `AgentNotify` (type 130) or the access-log `LogRecord` (type 129).
5. Wrap it as `Payload{data: buf, cpu: 0, lost: 0, type: EventSample(9)}` and
   enqueue to every listener.

Note the consequence, which is a compatibility fact and not a bug: for agent
events, `Data[0]` is the message type and `Data[1..]` is **gob**, whereas for
datapath events `Data` is the raw C-struct perf sample. A decoder MUST branch
on `Data[0]` before choosing a decoding strategy.

`cpu = 0` for all agent events; it is a placeholder, not a real CPU.

### 3.5 The `monitor1_2.sock` listener protocol

This section is the exact wire contract with `cilium-dbg monitor`.

**Transport.** `AF_UNIX` `SOCK_STREAM` at `/var/run/cilium/monitor1_2.sock`.
There is **no handshake, no banner, no version negotiation**. The server writes
nothing until it has an event to deliver. The client writes nothing, ever.
Version 1.0 of the protocol (a 32-byte `Meta{size u32, _ [28]u8}` prefix plus a
per-message gob type descriptor) is dead in the reference and MUST NOT be
implemented; a 1.0 socket is not served.

**Framing.** The stream is a single Go `encoding/gob` session per connection,
carrying a sequence of `Payload` values:

```
Payload {
    Data []byte    // field 0
    CPU  int       // field 1  (signed)
    Lost uint64    // field 2  (unsigned)
    Type int       // field 3  (signed) — 9 EventSample, 2 RecordLost
}
```

The **type definition is transmitted once**, immediately before the first
value; every subsequent message is value-only. A Rust implementation MUST
therefore keep per-connection encoder state (a "have I sent the type
descriptor yet" flag), not encode each payload independently.

**Gob primitives needed** (this is the whole subset; §11.5):

| Encoding | Rule |
|---|---|
| `uint` | if `x ≤ 0x7F`, one byte `x`; else one byte `0x100 − byte_len(x)` (`0xFF` for 1 byte, `0xFE` for 2, …) followed by `byte_len` **big-endian** bytes. **Not** LEB128/protobuf varint. |
| `int` | `u = if i < 0 { (!i << 1) \| 1 } else { i << 1 }`, then encode `u` as `uint` |
| `[]byte`, `string` | `uint` length, then the raw bytes |
| struct | `(uint field_delta, value)*` with the field counter starting at `−1` and deltas strictly positive and increasing, terminated by `uint 0` |
| zero fields | **omitted entirely** — no delta, no value. Nested struct fields are the exception and are always emitted. |
| message | `uint(body_byte_count)` followed by the body |

`Payload` MUST NOT be given `MarshalBinary`/`UnmarshalBinary`-equivalent
semantics: Go's gob would then emit a `BinaryMarshalerT` descriptor and the
reference client would fail. Emit the plain struct wire type.

**Type ids.** Builtin ids are fixed (`bool 1, int 2, uint 3, float 4, bytes 5,
string 6, complex 7, interface 8`), user ids start at 65. Because `[]uint8` is
treated as the builtin `bytes` type and never gets its own definition,
**exactly one** type-definition message is ever sent on this socket, with id
**65** and the unqualified name `"Payload"`.

**Message 1 — the type definition (57 bytes on the wire, sent once):**

```
38 ff 81 03 01 01 07 50 61 79 6c 6f 61 64 01 ff
82 00 01 04 01 04 44 61 74 61 01 0a 00 01 03 43
50 55 01 04 00 01 04 4c 6f 73 74 01 06 00 01 04
54 79 70 65 01 04 00 00 00
```

Annotated:

| Bytes | Meaning |
|---|---|
| `38` | body length 56 |
| `ff 81` | `int(−65)` — a negative id introduces a type definition |
| `03` | delta 3 → `wireType.StructT` (field index 2) |
| `01` | delta 1 → `structType` field 0, the embedded `CommonType` |
| `01 07 "Payload"` | `CommonType.Name` |
| `01 ff 82` | `CommonType.Id = int(65)` |
| `00` | end `CommonType` |
| `01 04` | delta 1 → `structType.Field`, slice of 4 `fieldType` |
| `01 04 "Data" 01 0a 00` | field `Data`, type id `int(5)` = bytes |
| `01 03 "CPU" 01 04 00` | field `CPU`, type id `int(2)` = int |
| `01 04 "Lost" 01 06 00` | field `Lost`, type id `int(3)` = uint |
| `01 04 "Type" 01 04 00` | field `Type`, type id `int(2)` = int |
| `00` | end `structType` |
| `00` | end `wireType` |

**Message 2..N — value messages.** `uint(body_len) int(65) <struct body>`.
There is **no** extra `0x00` singleton marker between the type id and the first
field delta; that marker exists only for non-struct top-level values.

`Payload{data: [1,2,3], cpu: 0, lost: 0, type: 9}`:

```
0a ff 82 01 03 01 02 03 03 12 00
│  │     │  │  └──────┘ │  │  └── struct terminator
│  │     │  │  data     │  └── int(9) = 9<<1 = 0x12
│  │     │  └── byte-slice length 3
│  │     └── delta 1 → field 0 (Data)
│  └── int(65) — the type id
└── body length 10
```

`Payload{data: none, cpu: 3, lost: 5, type: 2}` (a lost record):

```
09 ff 82 02 06 01 05 01 04 00
```

`02` = delta 2 → field 1 `CPU`, `06` = `int(3)`; `01` → field 2 `Lost`,
`05` = **`uint(5)`, not zig-zagged**; `01` → field 3 `Type`, `04` = `int(2)`.
`Data` is empty and therefore omitted.

`Payload{}` (all zero) is `03 ff 82 00`.

Traps a Rust encoder MUST avoid:

1. `Lost` is unsigned and `CPU`/`Type` are signed. Sending `Lost: 5` as `0x0a`
   decodes as 10.
2. A 4 KiB perf sample makes the body ~4110 bytes, so the message length
   prefix uses the multi-byte form. The Go decoder rejects bodies ≥ 2^30.
3. Fields are matched **by name** on decode, so ordering is technically free,
   but flowsdn MUST emit `Data, CPU, Lost, Type` with ids `5, 2, 3, 2` to be
   byte-identical.
4. The reference client reuses one `Payload` value across `Decode` calls and
   gob merges into it, so an omitted field retains the previous message's
   value on the client. flowsdn MUST replicate omit-on-zero rather than
   force-sending zeros; sending zeros would produce a different (still valid)
   stream but the byte-identity test in §9.1 would fail.

**Fields consumed by the reference client** (all four are live):
`Type` selects the branch, `Data` + `CPU` render a sample, `Lost` + `CPU`
render a lost record; any other `Type` prints an "unknown event" line.

**Listener queue sizing and drop policy.** Each accepted connection gets a
bounded queue of `--monitor-queue-size` entries; when the flag is 0 (the
default) the size is `min(possible_cpus × 1024, 16384)`. Enqueue is
**non-blocking**: a full queue drops that message for that listener only, logs
at debug level, and does not affect other listeners, consumers, or the reader.
A write error or a disconnected peer removes the listener and closes its
queue; if it was the last subscriber the perf reader stops (§3.2).

**DEVIATION (none, deliberately).** flowsdn implements this protocol rather
than dropping it, resolving inventory 09's first open question. Reason: it is
~400 lines of well-specified encoder, it makes `cilium-dbg monitor` usable
against flowsdn from day one, and it is the only debugging path that does not
depend on the whole Hubble stack being up. See §12.1 for the read side.

### 3.6 Monitor aggregation

Aggregation is decided in the **datapath** (spec 02 §3.16, §5.6); the agent's
job is to parse the level and program it into the endpoint/node config.

| String | Level | Datapath effect |
|---|---|---|
| `""`, `none`, `disabled`, `0` | 0 `TRACE_AGGREGATE_NONE` | emit every trace point |
| `lowest`, `1` | 1 `TRACE_AGGREGATE_RX` | suppress all `TRACE_FROM_*` points |
| `low`, `2` | 2 | as level 1 (reserved for additional suppression) |
| `medium`, `3` | 3 `TRACE_AGGREGATE_ACTIVE_CT` | emit `TRACE_TO_*` only when the CT entry's `monitor` field is set — a new connection, a connection carrying newly-seen TCP flags, or `CT_REPORT_INTERVAL` elapsed |
| `max`, `maximum`, `4` | 4 | as level 3 |

Parsing: match the lowercased string first; otherwise parse as an integer and
reject anything outside 0..4 with `monitor aggregation level must be between 0
and 4`. `monitor-aggregation-level` is an accepted alias for
`monitor-aggregation`. `--monitor-aggregation-interval` (default 5s) is
`CT_REPORT_INTERVAL`. `--monitor-aggregation-flags` is the set of TCP flags
that always force an emission (default `syn,fin,rst`).

Socket traces use their own levels `TRACE_SOCK_AGGREGATE_{NONE=0, RECV=1,
CONNECT=3}`.

Aggregation changes **which events exist**, so every downstream number
(Hubble flow counts, metrics, exported lines) depends on it. Operators MUST be
told this; the status output MUST report the effective level
(`Format` names: `None`, `Lowest`, `Low`, `Medium`, `Max`).

### 3.7 Decoding dispatch

The first byte of a perf sample (`Data[0]`) selects the decoder:

| `Data[0]` | Decoder | Produces |
|---|---|---|
| 1 drop | `drop_notify` (§4.4) | `flow.Flow`, `FlowType_L3_L4` |
| 2 debug | `debug_msg` (§4.6) | `flow.DebugEvent` |
| 3 debug capture | `debug_capture_msg` (§4.6) | `flow.Flow` with `debug_capture_point` |
| 4 trace | `trace_notify` (§4.3) | `flow.Flow`, `FlowType_L3_L4` |
| 5 policy verdict | `policy_verdict_notify` (§4.5) | `flow.Flow`, `FlowType_L3_L4` |
| 6 capture | **reserved, never emitted** | — (a sample with type 6 MUST be counted as unknown, not decoded) |
| 7 trace-sock | `trace_sock_notify` (§4.7) | `flow.Flow`, `FlowType_SOCK` |
| 129 access log | gob `LogRecord` | `flow.Flow`, `FlowType_L7` |
| 130 agent | gob `AgentNotify` | `flow.AgentEvent` |

Rules that apply to every datapath decoder:

- Layouts are **native endian**. The datapath and the reader are the same
  host, so this is well-defined; a decoder MUST NOT hard-code little-endian
  (spec 01 §4.6). The bitfield byte in `policy_verdict_notify` is LSB-first
  on both x86-64 and arm64.
- A sample shorter than the struct length for its declared version MUST be
  rejected with a decode error, counted, and dropped. It MUST NOT panic and
  MUST NOT be partially decoded.
- A `version` greater than the maximum this build knows MUST be rejected
  (drop: `> 3`; trace: `> 2`). A version *lower* than the current one MUST be
  accepted and the missing tail fields left at their zero values — this is how
  a new agent reads events from a not-yet-reloaded datapath across an upgrade.
- The packet bytes begin at `data_offset = struct_len(version) +
  ext_len(ext_version)`. `ext_version` is 0 upstream and all extension lengths
  are 0; a nonzero `ext_version` this build does not know MUST be rejected.
- The captured packet slice is `data[data_offset .. data_offset + len_cap]`
  and MUST be bounds-checked against the actual sample length.

---

## 4. Data model

Byte offsets are in `01-bpf-map-abi-loader.md` §4.6. This section gives the
**semantics** of each field and the frozen numeric tables.

### 4.1 Message types (frozen)

| Code | C name | Name | Emitter |
|---|---|---|---|
| 0 | `CILIUM_NOTIFY_UNSPEC` | — | never |
| 1 | `CILIUM_NOTIFY_DROP` | `drop` | datapath |
| 2 | `CILIUM_NOTIFY_DBG_MSG` | `debug` | datapath |
| 3 | `CILIUM_NOTIFY_DBG_CAPTURE` | `capture` | datapath |
| 4 | `CILIUM_NOTIFY_TRACE` | `trace` | datapath |
| 5 | `CILIUM_NOTIFY_POLICY_VERDICT` | `policy-verdict` | datapath |
| 6 | `CILIUM_NOTIFY_CAPTURE` | — | **reserved, never emitted** (pcap recorder removed upstream) |
| 7 | `CILIUM_NOTIFY_TRACE_SOCK` | `trace-sock` | datapath (cgroup socket programs) |
| 129 | — | `l7` | agent (`MessageTypeAccessLog`) |
| 130 | — | `agent` | agent (`MessageTypeAgent`) |

Codes 0–128 are reserved for the datapath, 129–255 for the agent. The name
strings are the values accepted by `cilium-dbg monitor --type` and by
`--hubble-monitor-events`.

### 4.2 Common and capture headers

`NOTIFY_COMMON_HDR` (8 B): `type` u8, `subtype` u8, `source` u16, `hash` u32.

- `source` is the endpoint id of the **emitting program**, not of the packet's
  endpoint: `endpoint_id` in the lxc programs, the host endpoint id in the host
  program, 0 in overlay/xdp/wireguard/sock. Direction inference (§3.11) depends
  on this.
- `hash` is `bpf_get_hash_recalc`; it is carried through to
  `DebugEvent.hash` and otherwise unused.

`NOTIFY_CAPTURE_HDR` (16 B) adds `len_orig` u32, `len_cap` u16, `version` u8,
`ext_version` u8.

- `len_orig` is the **pre-truncation** packet length; `len_cap` is how many
  bytes actually follow the struct. `len_orig > len_cap` means truncation, and
  the parser MUST NOT treat a short dissection as an error in that case.
- `version` selects the struct length (per type, §4.3/§4.4); `ext_version`
  selects the downstream-extension length and is 0 upstream.

### 4.3 `trace_notify` (type 4) — semantics

`subtype` is the **observation point**; `version` 2 is current (v0 = 32 B,
v1 = 48 B adds `orig_ip`, v2 = 56 B adds `ip_trace_id`).

| Field | Semantics |
|---|---|
| `src_label`, `dst_label` | datapath security identities of the two ends |
| `dst_id` | destination endpoint id; **for `TO_PROXY` it is the proxy port instead** and becomes `Flow.proxy_port` |
| `reason` | low 7 bits = CT state (table below); bit 7 (`0x80`, `TraceReasonEncryptMask`) = the packet was/will be encrypted → `Flow.IP.encrypted = true` |
| `flags` | bit 0 IPv6, bit 1 L3 device, bit 2 VXLAN, bit 3 Geneve (`CLS_FLAG_*` from `classifiers.h`; identical bits in `drop_notify`) |
| `ifindex` | interface index → `Flow.interface` |
| `orig_ip` | pre-SNAT source address, 16 B union; unspecified when no translation happened |
| `ip_trace_id` | correlation id carried in an IP option → `Flow.ip_trace_id.trace_id` |

**Trace observation points (frozen).** `TraceObservationPoint` in
`flow.proto` reuses the datapath numbers except for slot 0.

| Datapath | C name | `--type` string | `flow.proto` |
|---|---|---|---|
| 0 | `TRACE_TO_LXC` | `to-endpoint` | `TO_ENDPOINT = 101` |
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

Mapping rule the parser MUST implement:

```
if subtype != 0 { trace_observation_point = subtype }
else            { trace_observation_point = TO_ENDPOINT (101) }
```

`flow.proto` reserves 0 as `UNKNOWN_POINT` so that a JSON export never carries
a meaningful zero. This is a deliberate reference quirk, kept.

**Trace reasons (frozen).** These are CT state values, so the numbering is
shared with spec 04.

| Datapath | Name | String | `flow.proto` |
|---|---|---|---|
| 0 | `CT_NEW` / `TraceReasonPolicy` | `new` | `NEW = 1` |
| 1 | `CT_ESTABLISHED` | `established` | `ESTABLISHED = 2` |
| 2 | `CT_REPLY` | `reply` | `REPLY = 3` |
| 3 | `CT_RELATED` | `related` | `RELATED = 4` |
| 4 | `CT_REOPENED` (deprecated) | `reopened` | `REOPENED = 5` (deprecated) |
| 5 | `TraceReasonUnknown` | `unknown` | `TRACE_REASON_UNKNOWN = 0` |
| 6 | `SRv6Encap` | `srv6-encap` | `SRV6_ENCAP = 6` |
| 7 | `SRv6Decap` | `srv6-decap` | `SRV6_DECAP = 7` |
| 8 | `EncryptOverlay` (deprecated) | `encrypt-overlay` | `ENCRYPT_OVERLAY = 8` (deprecated) |
| `0x80` | `TraceReasonEncryptMask` | text prefix `encrypted ` | sets `IP.encrypted` |

Conversion (the off-by-one is deliberate and MUST be reproduced exactly):

```
r = reason & !0x80
if r == 5 { TRACE_REASON_UNKNOWN (0) }
else if r < 5 { r + 1 }
else { r }
```

Derived predicates the parser needs:

| Predicate | Definition |
|---|---|
| `is_known(r)` | `r != TraceReasonUnknown (5)` |
| `is_reply(r)` | `r == CT_REPLY (2)` |
| `is_encap(r)` | `r == SRv6Encap (6)` |
| `is_decap(r)` | `r == SRv6Decap (7)` |
| `is_encrypted` | `reason & 0x80 != 0` |

### 4.4 `drop_notify` (type 1) — semantics

`subtype` is the **drop reason** (§4.8); `version` 3 is current (v0/v1 = 36 B,
v2 = 40 B adds `flags`, v3 = 48 B adds `ip_trace_id`). Version > 3 is rejected.

| Field | Semantics |
|---|---|
| `src_label`, `dst_label` | datapath identities |
| `dst_id` | u32 destination endpoint id; **0 on egress drops** |
| `line`, `file` | source location of the drop → `Flow.file = {name: file_table[file], line}` |
| `ext_error` | i8 extended reason; appended to the human string as `", <n>"` when nonzero (e.g. the tail-call slot for `MISSED_TAIL_CALL`) |
| `ifindex` | present, but **not** used to populate `Flow.interface` (reference behavior, kept — see §12.7) |
| `flags` | same bits as `trace_notify` |

### 4.5 `policy_verdict_notify` (type 5) — semantics

Fixed 40 B, no version field.

| Field | Semantics |
|---|---|
| `remote_label` | the **remote** identity: the source identity on ingress, the destination identity on egress. The local side is left as identity 0 so the parser falls back to userspace state (§3.10). |
| `verdict` | i32: `< 0` → dropped with `drop_reason = -verdict`; `> 0` → redirected to that proxy port; `0` → allowed (or audited) |
| `dst_port` | destination port, network byte order in the struct |
| `proto` | IP protocol number |
| `flags` | `dir` bits `0x3`, `ipv6` `0x4`, `match_type` `(f & 0x38) >> 3`, `audited` `0x40`, `l3_device` `0x80` |
| `auth_type` | `flow.AuthType`: 0 `DISABLED`, 1 `SPIRE`, 2 `TEST_ALWAYS_FAIL` |
| `cookie` | socket/policy cookie, not surfaced in `Flow` |

Direction: `1 = PolicyIngress`, `2 = PolicyEgress`.

**Policy match types (frozen)** → `Flow.policy_match_type`:

| Value | Name | String |
|---|---|---|
| 0 | `PolicyMatchNone` | `none` |
| 1 | `PolicyMatchL3Only` | `L3-Only` |
| 2 | `PolicyMatchL3L4` | `L3-L4` |
| 3 | `PolicyMatchL4Only` | `L4-Only` |
| 4 | `PolicyMatchAll` | `all` |
| 5 | `PolicyMatchL3Proto` | `L3-Proto` |
| 6 | `PolicyMatchProtoOnly` | `Proto-Only` |

Verdict mapping:

```
verdict < 0            -> DROPPED,    drop_reason = -verdict
verdict > 0            -> REDIRECTED
verdict == 0, audited  -> AUDIT
verdict == 0           -> FORWARDED
```

### 4.6 `debug_msg` (type 2) and `debug_capture_msg` (type 3)

`debug_msg` is 20 B (common header + `arg1`, `arg2`, `arg3` u32) and carries
**no packet**. `debug_capture_msg` is 24 B (capture header + `arg1`, `arg2`)
and does carry a packet.

`debug_msg` becomes a `flow.DebugEvent`, not a `Flow`:

| `DebugEvent` field | Source |
|---|---|
| `type = 1` | `DebugEventType(subtype)` — see the table below |
| `source = 2` | endpoint resolved from the common header's `source` id; nil when 0 |
| `hash = 3`, `arg1 = 4`, `arg2 = 5`, `arg3 = 6` | wrapped `UInt32Value` |
| `message = 7` | the per-subtype human rendering |
| `cpu = 8` | wrapped `Int32Value` of the ring's CPU |

`debug_capture_msg` becomes a `Flow` with `debug_capture_point =
DebugCapturePoint(subtype)` and, for a subset of subtypes, an interface or a
proxy port derived from `arg1` (§3.11).

**Debug capture points (frozen)** — identical numbering in
`flow.DebugCapturePoint`:

| Value | Name |
|---|---|
| 0 | `DBG_CAPTURE_POINT_UNKNOWN` |
| 1–3 | reserved |
| 4 | `DBG_CAPTURE_DELIVERY` |
| 5 | `DBG_CAPTURE_FROM_LB` |
| 6 | `DBG_CAPTURE_AFTER_V46` |
| 7 | `DBG_CAPTURE_AFTER_V64` |
| 8 | `DBG_CAPTURE_PROXY_PRE` |
| 9 | `DBG_CAPTURE_PROXY_POST` |
| 10 | `DBG_CAPTURE_SNAT_PRE` |
| 11 | `DBG_CAPTURE_SNAT_POST` |

**Debug subtypes (frozen, 0..68)** — the `dbg.h` / `flow.DebugEventType`
numbering, which is the one flowsdn uses everywhere (§2.4 DEVIATION):

| # | Name | # | Name | # | Name |
|---|---|---|---|---|---|
| 0 | `UNKNOWN` | 24 | `LB6_LOOKUP_BACKEND_SLOT` | 47 | `NETDEV_ENCAP4` |
| 1 | `GENERIC` | 25 | `LB6_LOOKUP_BACKEND_SLOT_SUCCESS` | 48 | `CT_LOOKUP4_1` |
| 2 | `LOCAL_DELIVERY` | 26 | `LB6_LOOKUP_BACKEND_SLOT_V2_FAIL` | 49 | `CT_LOOKUP4_2` |
| 3 | `ENCAP` | 27 | `LB6_LOOKUP_BACKEND_FAIL` | 50 | `CT_CREATED4` |
| 4 | `LXC_FOUND` | 28 | `LB6_REVERSE_NAT_LOOKUP` | 51 | `CT_LOOKUP6_1` |
| 5 | `POLICY_DENIED` | 29 | `LB6_REVERSE_NAT` | 52 | `CT_LOOKUP6_2` |
| 6 | `CT_LOOKUP` | 30 | `LB4_LOOKUP_FRONTEND` | 53 | `CT_CREATED6` |
| 7 | `CT_LOOKUP_REV` | 31 | `LB4_LOOKUP_FRONTEND_FAIL` | 54 | `SKIP_PROXY` |
| 8 | `CT_MATCH` | 32 | `LB4_LOOKUP_BACKEND_SLOT` | 55 | `L4_CREATE` |
| 9 | `CT_CREATED` | 33 | `LB4_LOOKUP_BACKEND_SLOT_SUCCESS` | 56 | `IP_ID_MAP_FAILED4` |
| 10 | `CT_CREATED2` | 34 | `LB4_LOOKUP_BACKEND_SLOT_V2_FAIL` | 57 | `IP_ID_MAP_FAILED6` |
| 11 | `ICMP6_HANDLE` | 35 | `LB4_LOOKUP_BACKEND_FAIL` | 58 | `IP_ID_MAP_SUCCEED4` |
| 12 | `ICMP6_REQUEST` | 36 | `LB4_REVERSE_NAT_LOOKUP` | 59 | `IP_ID_MAP_SUCCEED6` |
| 13 | `ICMP6_NS` | 37 | `LB4_REVERSE_NAT` | 60 | `LB_STALE_CT` |
| 14 | `ICMP6_TIME_EXCEEDED` | 38 | `LB4_LOOPBACK_SNAT` | 61 | `INHERIT_IDENTITY` |
| 15 | `CT_VERDICT` | 39 | `LB4_LOOPBACK_SNAT_REV` | 62 | `SK_LOOKUP4` |
| 16 | `DECAP` | 40 | `CT_LOOKUP4` | 63 | `SK_LOOKUP6` |
| 17 | `PORT_MAP` | 41 | `RR_BACKEND_SLOT_SEL` | 64 | `SK_ASSIGN` |
| 18 | `ERROR_RET` | 42 | `REV_PROXY_LOOKUP` | 65 | `L7_LB` |
| 19 | `TO_HOST` | 43 | `REV_PROXY_FOUND` | **66** | **`SKIP_POLICY`** |
| 20 | `TO_STACK` | 44 | `REV_PROXY_UPDATE` | **67** | **`LB6_LOOPBACK_SNAT`** |
| 21 | `PKT_HASH` | 45 | `L4_POLICY` | **68** | **`LB6_LOOPBACK_SNAT_REV`** |
| 22 | `LB6_LOOKUP_FRONTEND` | 46 | `NETDEV_IN_CLUSTER` | | |
| 23 | `LB6_LOOKUP_FRONTEND_FAIL` | | | | |

The three bold rows are where the reference's Go table is wrong (§2.4). Names
are prefixed `DBG_` in `flow.proto` (`DBG_SKIP_POLICY = 66`).

The per-subtype human `message` rendering is debug-only, is not a compatibility
surface, and MUST NOT gate the implementation. flowsdn SHOULD implement it for
the subtypes it actually emits (spec 02) and render the rest as
`<name> arg1=<a> arg2=<b> arg3=<c>`. Note that the reference never wires an
interface-name resolver into its debug parser, so its `LXC_FOUND` messages
render an empty interface name; flowsdn MUST pass the link resolver in.

### 4.7 `trace_sock_notify` (type 7) — semantics

40 B with **no common header** — `type` is at byte 0 and there is no `subtype`,
`source` or `hash`.

| Field | Semantics |
|---|---|
| `xlate_point` | 0 `UNKNOWN`, 1 `PRE_DIRECTION_FWD`, 2 `POST_DIRECTION_FWD`, 3 `PRE_DIRECTION_REV`, 4 `POST_DIRECTION_REV` (same numbering as `flow.SocketTranslationPoint`) |
| `l4_proto` | 0 unknown, 1 TCP, 2 UDP |
| `flags` | bit 0 = IPv6 |
| `dst_port` | destination port |
| `sock_cookie` | `bpf_get_socket_cookie` → `Flow.socket_cookie` |
| `cgroup_id` | `bpf_get_current_cgroup_id` → `Flow.cgroup_id`, and the key for pod resolution |
| `dst_ip` | 16 B union; IPv4 in the first 4 bytes |

`EventType` for these flows is `{type: 7, sub_type: xlate_point}`.

### 4.8 Drop reasons (frozen)

`DropMin = 130`. Codes below 130 are **status codes**, not drops; they never
appear as a `drop_notify` subtype and have no `flow.proto` enum. Code 159 is
unassigned. Retired codes MUST NOT be reused.

Status codes (0–15), used in datapath metrics and `cilium-dbg` output only:

| Code | String |
|---|---|
| 0 | Success |
| 2 | Invalid packet (`DropInvalid`) |
| 3 | Interface |
| 4 | Interface Decrypted |
| 5 | LB, sock cgroup: No backend slot entry found |
| 6 | LB, sock cgroup: No backend entry found |
| 7 | LB, sock cgroup: Reverse entry update failed |
| 8 | LB, sock cgroup: Reverse entry stale |
| 9 | Fragmented packet |
| 10 | Fragmented packet entry update failed |
| 11 | Missed tail call to custom program (unused) |
| 12 | Interface Decrypting |
| 13 | Interface Encrypting |
| 14 | LB: sock cgroup: Reverse entry delete succeeded |
| 15 | MTU error message |

Drop reasons (130–207). The third column is the `flow.DropReason` enum name,
which is what `hubble observe` prints in `drop_reason_desc` and what
`FlowFilter.drop_reason_desc` accepts. "(unused)" marks codes the datapath no
longer emits; "(dep)" marks proto values `[deprecated = true]`.

| Code | Monitor string | `flow.DropReason` |
|---|---|---|
| 130 | Invalid source mac (unused) | `INVALID_SOURCE_MAC` (dep) |
| 131 | Invalid destination mac (unused) | `INVALID_DESTINATION_MAC` (dep) |
| 132 | Invalid source ip | `INVALID_SOURCE_IP` |
| 133 | Policy denied | `POLICY_DENIED` |
| 134 | Invalid packet | `INVALID_PACKET_DROPPED` |
| 135 | CT: Truncated or invalid header | `CT_TRUNCATED_OR_INVALID_HEADER` |
| 136 | Fragmentation needed | `CT_MISSING_TCP_ACK_FLAG` *(name mismatch, kept)* |
| 137 | CT: Unknown L4 protocol | `CT_UNKNOWN_L4_PROTOCOL` |
| 138 | CT: Can't create entry from packet (unused) | `CT_CANNOT_CREATE_ENTRY_FROM_PACKET` (dep) |
| 139 | Unsupported L3 protocol | `UNSUPPORTED_L3_PROTOCOL` |
| 140 | Missed tail call | `MISSED_TAIL_CALL` |
| 141 | Error writing to packet | `ERROR_WRITING_TO_PACKET` |
| 142 | Unknown L4 protocol | `UNKNOWN_L4_PROTOCOL` |
| 143 | Unknown ICMPv4 code | `UNKNOWN_ICMPV4_CODE` |
| 144 | Unknown ICMPv4 type | `UNKNOWN_ICMPV4_TYPE` |
| 145 | Unknown ICMPv6 code | `UNKNOWN_ICMPV6_CODE` |
| 146 | Unknown ICMPv6 type | `UNKNOWN_ICMPV6_TYPE` |
| 147 | Error retrieving tunnel key | `ERROR_RETRIEVING_TUNNEL_KEY` |
| 148 | Error retrieving tunnel options (unused) | `ERROR_RETRIEVING_TUNNEL_OPTIONS` (dep) |
| 149 | Invalid Geneve option (unused) | `INVALID_GENEVE_OPTION` (dep) |
| 150 | Unknown L3 target address | `UNKNOWN_L3_TARGET_ADDRESS` |
| 151 | Stale or unroutable IP | `STALE_OR_UNROUTABLE_IP` |
| 152 | No matching local container found (unused) | `NO_MATCHING_LOCAL_CONTAINER_FOUND` (dep) |
| 153 | Error while correcting L3 checksum | `ERROR_WHILE_CORRECTING_L3_CHECKSUM` |
| 154 | Error while correcting L4 checksum | `ERROR_WHILE_CORRECTING_L4_CHECKSUM` |
| 155 | CT: Map insertion failed | `CT_MAP_INSERTION_FAILED` |
| 156 | Invalid IPv6 extension header | `INVALID_IPV6_EXTENSION_HEADER` |
| 157 | IP fragmentation not supported | `IP_FRAGMENTATION_NOT_SUPPORTED` |
| 158 | Service backend not found | `SERVICE_BACKEND_NOT_FOUND` |
| 159 | *(unassigned)* | — |
| 160 | No tunnel/encapsulation endpoint (datapath BUG!) | `NO_TUNNEL_OR_ENCAPSULATION_ENDPOINT` |
| 161 | NAT 46/64 not enabled | `FAILED_TO_INSERT_INTO_PROXYMAP` *(name mismatch, kept)* |
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
| 186 | SRv6 state was removed during tail call | `MISSING_SRV6_STATE` (dep) |
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
| 206 | No device | *(no proto value)* |
| 207 | First logical datagram fragment not found from world | `DROP_FRAG_NOT_FOUND_WORLD` |

Rendering: `drop_reason_ext(reason, ext_error)` yields the string above, plus
`", <ext_error>"` when `ext_error != 0`; an unknown code renders as
`"<reason>, <ext_error>"`.

`Flow.drop_reason` (field 3, deprecated) carries the raw number and
`Flow.drop_reason_desc` (field 25) the same number typed as the enum. Both MUST
be set; the CLI reads the second, older consumers the first.

### 4.9 BPF source-file ids (frozen)

Used for `Flow.file.name` on drops. Keep in sync with the datapath's
`source_info.h`.

| Id | File | Id | File |
|---|---|---|---|
| 1 | `bpf_host.c` | 107 | `ipv4.h` |
| 2 | `bpf_lxc.c` | 108 | `conntrack.h` |
| 3 | `bpf_overlay.c` | 109 | `local_delivery.h` |
| 4 | `bpf_xdp.c` | 110 | `trace.h` |
| 5 | `bpf_sock.c` | 111 | `encap.h` |
| 6 | *(available)* | 112 | `host_firewall.h` |
| 7 | `bpf_wireguard.c` | 113 | `nodeport_egress.h` |
| 101 | `drop.h` | 114 | `ipv6.h` |
| 102 | `srv6.h` | 115 | `classifiers.h` |
| 103 | `icmp6.h` | | |
| 104 | `nodeport.h` | | |
| 105 | `lb.h` | | |
| 106 | `mcast.h` | | |

An unknown id renders as `unknown(<n>)`.

**DEVIATION**: flowsdn's datapath is Rust (ADR-0002), so the file names are
`.rs` modules, not `.c`/`.h` files. flowsdn keeps the *numbering* — a drop from
the equivalent code path MUST report the same id — and MUST keep the reference
names in the id→name table, because operators, runbooks and upstream issue
reports all refer to them. New sites get ids ≥ 116 with flowsdn module names.

### 4.10 Agent notifications (type 130)

Wire form: `AgentNotify { type: u32, text: String }`, gob-encoded after the
type byte, where `text` is a JSON document. The `cilium-dbg monitor -j`
rendering is exactly
`{"type":"agent","subtype":"<name>","message":<text>}`.

| Code | Constant | Subtype string | JSON payload | `flow.AgentEventType` |
|---|---|---|---|---|
| 0 | `Unspec` | `unspecified` | — | `AGENT_EVENT_UNKNOWN = 0` |
| 1 | `Generic` | `Message` | free text | *(proto value 1 reserved)* |
| 2 | `Start` | `Cilium agent started` | `TimeNotification` | `AGENT_STARTED = 2` |
| 3 | `EndpointRegenerateSuccess` | `Endpoint regenerated` | `EndpointRegenNotification` | `ENDPOINT_REGENERATE_SUCCESS = 5` |
| 4 | `EndpointRegenerateFail` | `Failed endpoint regeneration` | `EndpointRegenNotification` | `ENDPOINT_REGENERATE_FAILURE = 6` |
| 5 | `PolicyUpdated` | `Policy updated` | `PolicyUpdateNotification` | `POLICY_UPDATED = 3` |
| 6 | `PolicyDeleted` | `Policy deleted` | `PolicyUpdateNotification` | `POLICY_DELETED = 4` |
| 7 | `EndpointCreated` | `Endpoint created` | `EndpointNotification` | `ENDPOINT_CREATED = 7` |
| 8 | `EndpointDeleted` | `Endpoint deleted` | `EndpointNotification` | `ENDPOINT_DELETED = 8` |
| 9 | `IPCacheUpserted` | `IPCache entry upserted` | `IPCacheNotification` | `IPCACHE_UPSERTED = 9` |
| 10 | `IPCacheDeleted` | `IPCache entry deleted` | `IPCacheNotification` | `IPCACHE_DELETED = 10` |

Proto values 11 `SERVICE_UPSERTED` and 12 `SERVICE_DELETED` are deprecated;
their agent-side constants no longer exist and flowsdn MUST NOT emit them, but
the enum values and the `ServiceUpsertNotification` / `ServiceDeleteNotification`
messages MUST stay in the proto for wire compatibility.

JSON payload structs (field names are the JSON keys, `omitempty` as marked):

| Struct | Fields |
|---|---|
| `TimeNotification` | `time` (RFC3339Nano string) |
| `PolicyUpdateNotification` | `labels[]?`, `revision`?, `rule_count` |
| `EndpointRegenNotification` | `id`?, `labels[]`?, `error`? |
| `EndpointNotification` | the `EndpointRegenNotification` fields, plus `pod-name`?, `namespace`? |
| `IPCacheNotification` | `cidr`, `id`, `old-id`?, `host-ip`?, `old-host-ip`?, `encrypt-key`, `namespace`?, `pod-name`? |

Mapping into `flow.AgentEvent` is by (Rust enum variant, `type`) pair; a
mismatch between the payload shape and the type code MUST fall through to
`AGENT_EVENT_UNKNOWN` with
`AgentEventUnknown { type: "<numeric type>", notification: "<JSON>" }` rather
than being dropped. Field mappings:

- `TimeNotification.time` → `TimeNotification.time` (a parse failure yields a
  nil timestamp, not an error).
- `IPCacheNotification.old-id` → `old_identity` as `UInt32Value`, absent when
  null. `host-ip`/`old-host-ip` are rendered as strings, empty when unset.
- Every notification's `labels` is copied verbatim, unsorted and unfiltered.

### 4.11 Monitor socket payload

```rust
struct Payload { data: Vec<u8>, cpu: i32, lost: u64, r#type: i32 }
const EVENT_SAMPLE: i32 = 9;   // == PERF_RECORD_SAMPLE
const RECORD_LOST:  i32 = 2;   // == PERF_RECORD_LOST
```

The legacy `Meta { size: u32, _pad: [u8; 28] }` 32-byte prefix belongs to
protocol 1.0 and MUST NOT be written.

### 4.12 Internal event types

```
MonitorEvent { uuid, timestamp, node_name, payload }
  payload = PerfEvent  { data: Vec<u8>, cpu: i32 }
          | AgentEvent { typ: i32, message: AgentMessage }
          | LostEvent  { source, num_lost: u64, cpu: i32, first, last }

Event { timestamp, inner }
  inner = Flow | LostEvent | AgentEvent | DebugEvent
```

`uuid` is generated per node per event and becomes `Flow.uuid`; it MUST be
unique within a node and MUST NOT be assumed unique across the cluster.

`LostEventSource` (frozen): 0 `UNKNOWN_LOST_EVENT_SOURCE`, 1
`PERF_EVENT_RING_BUFFER`, 2 `OBSERVER_EVENTS_QUEUE`, 3 `HUBBLE_RING_BUFFER`.
All three real sources MUST be reported distinctly; the Hubble UI
distinguishes them and they diagnose different problems (§7).

---

## 3 (continued). Behavior — the Hubble flow parser

### 3.8 Parser dispatch

The parser is a dispatcher over `MonitorEvent`:

| Input | Condition | Sub-parser | Result |
|---|---|---|---|
| `PerfEvent` | `data[0] == 2` | debug | `DebugEvent` — returned **immediately**, without `time` or `node_name` |
| `PerfEvent` | `data[0] == 7` | sock | `Flow`, `FlowType_SOCK` |
| `PerfEvent` | any other | threefour | `Flow`, `FlowType_L3_L4` |
| `AgentEvent` | `typ == 129` | seven | `Flow`, `FlowType_L7` |
| `AgentEvent` | `typ == 130` | agent | `AgentEvent` |
| `LostEvent` | — | — | `LostEvent` |

Empty data MUST yield `ErrEmptyData`; an unhandled `data[0]` MUST yield
`ErrInvalidType`. Both are *counted and skipped*, never fatal.

After a sub-parser returns a `Flow`, the dispatcher sets, in this order:

1. `emitter = { name: "cilium", version: <agent version> }` — **DEVIATION**:
   flowsdn sets `name = "flowsdn"` and its own version. Reason: `Emitter`
   exists precisely to identify the producer, the Hubble CLI prints it
   verbatim, and claiming to be Cilium would be both wrong and a trademark
   problem (`docs/licensing.md`). No consumer keys off the value.
2. `uuid` from the `MonitorEvent`.
3. `time` and `node_name` from the `MonitorEvent` (`node_name` is
   `<cluster>/<node>`), set *after* decode "for compatibility with old
   clients" — the L7 sub-parser sets its own `time` from the access-log record
   and is then overwritten.
4. `node_labels` from the local node.

`--hubble-monitor-events` restricts which `data[0]` values are decoded at all;
the default (empty list) means all of them. Filtering happens before decode, so
excluded types cost nothing.

### 3.9 Packet dissection (`threefour`)

Input is `data[packet_offset ..]` plus four booleans derived from the
notification flags:

```
is_l3_device = tn.l3_dev | dn.l3_dev | pvn.l3_dev
is_ipv6      = tn.ipv6   | dn.ipv6   | pvn.ipv6
is_vxlan     = tn.vxlan  | dn.vxlan            // policy verdict has no such flag
is_geneve    = tn.geneve | dn.geneve
```

Entry layer selection:

| Condition | Entry layer |
|---|---|
| `!is_l3_device` | Ethernet |
| `is_l3_device && is_ipv6` | IPv6 |
| `is_l3_device && !is_ipv6` | IPv4 |

An **empty** payload MUST return zero values with no error (a trace with
`len_cap = 0` is normal at aggregation levels above 0).

Layers decoded and the fields they set:

| Layer | Sets | `Summary` |
|---|---|---|
| Ethernet | `ethernet.{source,destination}` as MAC strings | `Ethernet` |
| IPv4 / IPv6 | `IP.{source,destination,ipVersion}` | `IPv4` / `IPv6` |
| TCP | `l4.TCP{source_port, destination_port, flags{FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS}}` | `TCP Flags: <joined>` |
| UDP | `l4.UDP{ports}` | `UDP` |
| SCTP | `l4.SCTP{ports, chunk_type}` | `SCTP` |
| ICMPv4 / ICMPv6 | `l4.ICMPv4/ICMPv6{type, code}`, ports stay 0 | `ICMPv4 <typecode>` / `ICMPv6 <typecode>` |
| VRRPv2 | `l4.VRRP{type, vrid, priority}` | `VRRP <type>` |
| IGMPv1/v2 | `l4.IGMP{type, group_address}` | `IGMP <type>` |

`Summary` is assigned per layer as the loop proceeds, so it ends up describing
the **last** layer decoded. TCP flag joining order is fixed: `SYN, ACK, RST,
FIN, PSH, URG, ECE, CWR, NS`, joined with `", "`.

`chunk_type` is `payload[0]` of the SCTP layer mapped to
`SCTPChunkType` (1 `INIT`, 2 `INIT_ACK`, 3 `SHUTDOWN`, 4 `SHUTDOWN_ACK`,
5 `SHUTDOWN_COMPLETE`, 6 `ABORT`, everything else 0 `UNSUPPORTED`); an empty
payload yields 0.

Unsupported layers MUST be ignored, not treated as errors.

#### 3.9.1 Overlay (VXLAN / Geneve) dissection

When `is_vxlan` or `is_geneve`, the **outer UDP payload** is re-parsed with a
VXLAN- or Geneve-entry decoder. If that yields no layers, or the first layer is
not the expected tunnel header, the flow keeps its outer headers and `tunnel`
is left unset.

On success:

1. `tunnel = { protocol: VXLAN|GENEVE, IP: <the outer IP>, l4: <the outer L4>,
   vni: <VNI> }`.
2. `ethernet`, `IP`, `l4`, both addresses, both ports and `Summary` are
   **cleared**, then repopulated from the inner layers by the same per-layer
   switch.

Consequences that MUST be preserved:

- After a successful tunnel decode, `Flow.IP` / `Flow.l4` describe the **inner**
  packet and `Flow.tunnel` the outer one. Without the clearing step, a flow
  would carry the node IPs as if they were the workload IPs.
- Endpoint, identity, service and DNS enrichment all use the **inner**
  addresses.
- A truncated capture that contains the tunnel header but no complete inner
  headers yields `tunnel` set and `IP`/`l4`/`ethernet` nil. This is valid
  output, not an error.
- `is_vxlan`/`is_geneve` come from the datapath's classifier, so a UDP packet
  on port 8472 that the classifier did not flag is **not** parsed as an
  overlay.
- The capture length for overlay-classified packets is
  `--trace-payloadlen-overlay` (192) rather than `--trace-payloadlen` (128),
  precisely so the inner headers fit.

The packet decoder MUST be a swappable component; the trait boundary is
exactly

```rust
trait PacketDecoder {
    fn decode(&self, payload: &[u8], flow: &mut Flow,
              is_l3_device: bool, is_ipv6: bool, is_vxlan: bool, is_geneve: bool)
        -> Result<(Option<IpAddr>, Option<IpAddr>, u16, u16), DecodeError>;
}
```

### 3.10 Enrichment: the `FlowEnricher` trait

Six live agent state sources are consulted per packet. In the reference these
are six in-process Go interfaces; flowsdn expresses them as one trait so the
coupling is explicit and testable:

```rust
pub trait FlowEnricher: Send + Sync {
    // 1. endpoint manager (spec 08 §3.9.1)
    fn endpoint_by_ip(&self, ip: IpAddr) -> Option<EndpointInfo>;
    fn endpoint_by_id(&self, id: u16) -> Option<EndpointInfo>;

    // 2. identity allocator (spec 03)
    fn identity(&self, id: u32) -> Option<Identity>;      // -> labels

    // 3. ipcache (spec 03 §3.7)
    fn lookup_sec_id_by_ip(&self, ip: IpAddr) -> Option<IpcacheIdentity>;
    fn k8s_metadata(&self, ip: IpAddr) -> Option<K8sMetadata>;   // ns + pod

    // 4. LB frontends (spec 05)
    fn service_by_addr(&self, ip: IpAddr, port: u16) -> Option<Service>;

    // 5. per-endpoint DNS history (spec 08 §4.1 `dns_history`)
    fn names_of(&self, source_ep_id: u32, ip: IpAddr) -> Vec<String>;

    // 6. link cache and cgroup manager
    fn if_name(&self, ifindex: u32) -> Option<String>;
    fn pod_metadata_for_cgroup(&self, cgroup_id: u64) -> Option<PodMetadata>;
}

pub trait EndpointInfo {
    fn id(&self) -> u64;
    fn identity(&self) -> NumericIdentity;
    fn pod_name(&self) -> &str;
    fn namespace(&self) -> &str;
    fn labels(&self) -> &Labels;
    fn pod(&self) -> Option<&Pod>;                 // for workload metadata
    fn policy_correlation_info(&self, key: PolicyKey) -> Option<PolicyCorrelationInfo>;
}
```

This fixes a structural rule: **the Hubble decoder runs inside the agent
process**, with read access to the endpoint, identity, ipcache, service and
link tables, or against read-only snapshots pushed to it. There is no
out-of-process Hubble.

Lookup details:

- `service_by_addr` queries the frontend table for TCP first, then UDP, at
  external scope, and returns only `{name, namespace}`.
- `names_of` reads the endpoint's DNS history and MUST return names **without**
  trailing dots.
- `if_name` is a cached ifindex→name map; a miss yields an empty name, not an
  error.
- `pod_metadata_for_cgroup` returns `{name, namespace, ips[]}`.

Every getter MUST be optional (absent enricher ⇒ that field is simply left
unset). The parser MUST NOT fail a flow because an enrichment source is
unavailable (§7.4).

Because these lookups happen on every packet at aggregation level `none`, they
MUST be lock-free or read-lock-only against a snapshot. A `RwLock` held across
the whole decode is the reference's throughput ceiling and MUST NOT be copied.

### 3.11 Endpoint resolution and the identity-conflict rules

`resolve_endpoint(ip, datapath_identity, ctx)` where
`ctx = { src_ip, src_label_id, dst_ip, dst_label_id, trace_observation_point }`.

**Conflict rule (normative).** The datapath-reported identity **always wins**
when it is non-zero:

```
if datapath_id == 0 (IdentityUnknown) { use the userspace identity }
else                                  { use datapath_id }
```

The six special cases below do **not** change the result — they suppress a
rate-limited (30 s, 1 event) "stale identity observed" debug log for
disagreements that are known-legitimate. They MUST be implemented, because
without them the log floods and operators chase phantom bugs; and they MUST
NOT be turned into value overrides, because that would change Hubble output.

All six additionally require `ip == ctx.src_ip && datapath_id == ctx.src_label_id`
(i.e. they apply only to the source side of the flow):

| # | Observation point | Datapath identity | Userspace identity | Why they legitimately differ |
|---|---|---|---|---|
| 1 | `TO_OVERLAY` | `remote-node` (6) | `host` (1) | on encap, a `HOST_ID` source seclabel is rewritten to the local-node id before the trace is emitted |
| 2 | `TO_OVERLAY` | non-reserved | `host` (1) | an IPsec-encrypted packet carries the local `cilium_host` IP as source but the originating pod's seclabel |
| 3 | `FROM_ENDPOINT` | `health` (4) or non-reserved | any world identity (2, 9, 10) | packets from an endpoint's link-local address are intercepted by the from-container program; link-local addresses are not in the ipcache, so userspace says world |
| 4 | `FROM_HOST` | a world identity | `kube-apiserver` (7) | a masquerade reversal arrives without a packet mark, so the host program computes world |
| 5 | `FROM_HOST` or `TO_OVERLAY` | any, **and** the IP resolves to a local endpoint | `host` (1) | DNS-proxied packets leave with the host's source IP but retain the original pod's identity |
| 6 | `TO_ENDPOINT` | non-reserved | `host` (1) or `remote-node` (6) | the receiving side of case 5 — source IP is the proxy's, identity is the original pod's |

**Local branch** (`endpoint_by_ip` hits) — `is_local_endpoint = true`:

```
Endpoint {
  ID:           endpoint id,
  identity:     resolved identity,
  cluster_name: labels["io.cilium.k8s.policy.cluster"],
  namespace:    endpoint namespace,
  labels:       sort_and_filter_labels(labels, resolved identity),
  pod_name:     endpoint pod name,
  workloads:    [{kind, name}] derived from the pod's owner reference, if any,
}
```

Note that labels are filtered against the **resolved** identity, which may be
the datapath's, not the endpoint's own.

**Remote branch**: start from the datapath identity; if the ipcache has an
entry for the IP, run the conflict rule against it; take namespace and pod name
from the ipcache's Kubernetes metadata; then look the numeric identity up in
the identity allocator for labels and cluster name. An identity-allocator miss
logs at debug and leaves labels empty — it MUST NOT fail the flow. A remote
endpoint has **no** `ID` and **no** `workloads`.

**`sort_and_filter_labels(labels, identity)`** is part of the contract:

```
if identity.has_local_scope() { labels = filter_cidr_labels(labels) }
labels.sort()
```

`filter_cidr_labels` keeps every non-`cidr:` label unchanged and, among the
`cidr:` labels, keeps **only the one with the longest prefix**. It decodes each
`cidr:` label by stripping the prefix and replacing `-` with `:` (the IPv6
label encoding), parsing it as a CIDR; unparsable labels are warned about and
dropped; a `/0` label is dropped entirely. The single winner is appended before
the sort. Without this, a CIDR identity with a hundred nested prefixes produces
a hundred labels on every flow.

### 3.12 Field derivation (`threefour`)

Order of operations after dissection:

1. **SNAT unwrap** (trace only). If `orig_ip` is specified:
   - the enrichment source IP becomes `orig_ip` (the pre-translation address);
   - if `orig_ip != IP.source` (the header address), then
     `IP.source_xlated = IP.source` and `IP.source = orig_ip`.
   If they are equal, neither field is rewritten.
   `IP.encrypted = (reason & 0x80) != 0`.
2. **Identities**: see the table below.
3. **Endpoint resolution** for source and destination (§3.11).
4. **Services** from `service_by_addr(src_ip, src_port)` and
   `service_by_addr(dst_ip, dst_port)`.
5. Field assignment.

**Identity extraction per event type:**

| Event | `source.identity` | `destination.identity` |
|---|---|---|
| drop | `src_label` | `dst_label` |
| trace | `src_label` | `dst_label` |
| policy verdict, ingress | `remote_label` | 0 → userspace fallback |
| policy verdict, egress | 0 → userspace fallback | `remote_label` |
| debug capture | 0 | 0 |

**Verdict:**

| Event | Verdict |
|---|---|
| drop | `DROPPED` |
| trace | `FORWARDED` |
| policy verdict | per §4.5 (`DROPPED` / `REDIRECTED` / `AUDIT` / `FORWARDED`) |
| debug capture | `VERDICT_UNKNOWN` |

**Drop reason:** `drop.subtype` for drops; `-verdict` for a negative policy
verdict; 0 otherwise. `drop_reason_desc` is the same value typed as the enum.
`file` is set only for drops, from `{name: file_table[file], line}`.

**Traffic direction** (normative, this is the subtlest function in the parser).
`src_ep` below is the **resolved** source endpoint id (0 when the source is not
a local endpoint); `notify.source` is the id of the *emitting program*.

```
if drop && drop.source != 0 {
    // Drops are assumed never to be reply packets.
    return if drop.source == src_ep { EGRESS } else { INGRESS }
}
if trace && trace.source != 0 && trace.reason_is_known() {
    let is_source_ep = trace.source == src_ep;
    let is_snated    = trace.orig_ip.is_specified();
    let is_reply     = trace.reason_is_reply();
    if is_source_ep != is_reply { return EGRESS }   // xor
    if is_snated               { return EGRESS }
    return INGRESS
}
if policy_verdict {
    return if pvn.dir == PolicyIngress { INGRESS } else { EGRESS }
}
return TRAFFIC_DIRECTION_UNKNOWN
```

Trace events with `source == 0` (overlay, xdp, wireguard, sock programs) or an
unknown trace reason therefore yield `UNKNOWN`, as do debug captures.

**`is_reply`** (a `BoolValue`, so "unknown" is distinct from "false"):

| Event | `is_reply` |
|---|---|
| trace, known reason, not SRv6 encap/decap | `Some(reason == CT_REPLY)` |
| trace, SRv6 encap or decap | `None` |
| trace, unknown reason | `None` |
| policy verdict with `verdict >= 0` | `Some(false)` — a forwarded verdict is emitted for the first packet of a connection |
| policy verdict with `verdict < 0` (denied) | `None` |
| drop, debug capture | `None` |
| L7 | `Some(record type == Response)` — never `None` |

`Flow.reply` (field 16, deprecated) mirrors `is_reply` with `None ⇒ false`.

**Other fields:**

| Field | Derivation |
|---|---|
| `auth_type` | `AuthType(pvn.auth_type)`; 0 for every other event type |
| `policy_match_type` | `(pvn.flags & 0x38) >> 3`; 0 otherwise |
| `trace_reason` | §4.3 conversion; `TRACE_REASON_UNKNOWN` for non-trace events |
| `ip_trace_id` | `{trace_id: dn.ip_trace_id \| tn.ip_trace_id, ip_option_type: <config>}`; **absent when the id is 0** |
| `event_type` | `{type: data[0], sub_type: <the event's subtype / observation point>}` |
| `debug_capture_point` | `DebugCapturePoint(dbg.subtype)`; absent otherwise |
| `interface` | `tn.ifindex`, or `dbg.arg1` for capture subtypes `DELIVERY, FROM_LB, AFTER_V46, AFTER_V64, SNAT_PRE, SNAT_POST`. **`drop.ifindex` is deliberately not used** (reference behavior; §12.7). Absent when the index is 0; the name is resolved through the link cache and may be empty. |
| `proxy_port` | `tn.dst_id` when the observation point is `TO_PROXY`; `ntohl(dbg.arg1)` for capture subtypes `PROXY_PRE`/`PROXY_POST`; 0 otherwise |
| `source_names` | `names_of(destination_endpoint.id, src_ip)` |
| `destination_names` | `names_of(source_endpoint.id, dst_ip)` |

The DNS-name lookups are **crossed** on purpose: the names by which the
*source* address is known are the ones the *destination* endpoint resolved,
because DNS history is recorded per querying endpoint. Getting this backwards
silently produces empty `source_names`/`destination_names` in the common case,
which is why it is called out here.

### 3.12.1 Network policy correlation

Runs last, only when `--hubble-network-policy-correlation-enabled` (default
true) and only for **policy verdict** events.

1. Classify: `allowed = verdict ∈ {FORWARDED, REDIRECTED}`;
   `denied = verdict == DROPPED && drop_reason_desc ∈ {POLICY_DENY, POLICY_DENIED}`;
   `audited = verdict == AUDIT`. If none hold, stop.
2. Build the lookup key:
   - `EGRESS` → `endpoint_id = source.ID`, `remote_identity = destination.identity`
   - `INGRESS` → `endpoint_id = destination.ID`, `remote_identity = source.identity`
   - protocol and port: TCP/UDP/SCTP → that protocol and the **destination
     port**; ICMPv4/ICMPv6 → that protocol with `dport = icmp.type`;
     VRRP/IGMP → that protocol with `dport = 0`; no L4 → protocol `ANY`,
     port 0.
3. If `dport == 0 || proto == 0`, stop. VRRP, IGMP and L3-only flows are
   therefore never correlated.
4. `endpoint_by_id(endpoint_id)` then
   `policy_correlation_info(Key{identity, dport, proto, direction})` against the
   endpoint's realized policy map (spec 06). A miss stops.
5. Convert the returned rule labels into `Policy{name, namespace, labels,
   revision, kind}` entries derived from the `io.cilium.k8s.policy.*` labels.
6. Assign:

| Direction | Classification | Field |
|---|---|---|
| egress | allowed | `egress_allowed_by` (21001) |
| egress | denied or **audited** | `egress_denied_by` (21004) |
| ingress | allowed | `ingress_allowed_by` (21002) |
| ingress | denied or **audited** | `ingress_denied_by` (21005) |

`policy_log` (21006) is set from the matched rules' log values regardless of
direction and verdict, with duplicates elided.

Note that `AUDIT` populates the *denied-by* fields — the rule that *would have*
denied. That is intentional and is what the CLI's audit-mode output expects.

### 3.12.2 Socket flows (`sock`)

1. `ip_version` from `flags & 0x1`.
2. Source IP from `pod_metadata_for_cgroup(cgroup_id)`: take the **first** pod
   IP whose family matches. If there is no metadata, or no matching IP, the
   source address is unset.
3. If the source address is unset and `--hubble-skip-unknown-cgroup-ids`
   (default **true**), the event is skipped entirely (`ErrEventSkipped`) — it
   is not emitted as a flow with an empty source.
4. Source port is always 0 (a socket trace does not know it). Destination is
   `dst_ip:dst_port`.
5. Endpoint resolution runs with **zero identities** and no observation point,
   so the userspace identity always wins.
6. **Reverse-path swap**: for `PRE_DIRECTION_REV` (3) and `POST_DIRECTION_REV`
   (4), swap source/destination IPs, ports and endpoints. The pod thus becomes
   the *destination* on the reverse points, and because the ports were swapped
   too, the pod-side port is 0 and the service/backend port lands on the source
   side.
7. Fields: `verdict` = `TRANSLATED` for the `POST_*` points and `TRACED` for the
   `PRE_*` points (`VERDICT_UNKNOWN` for 0); `l4` is TCP or UDP ports only, no
   flags; `sock_xlate_point`, `socket_cookie`, `cgroup_id` are set;
   `event_type = {7, xlate_point}`; `Summary` is `TCP`, `UDP` or `Unknown`.
   `traffic_direction` stays `UNKNOWN`, `is_reply` stays absent, and
   `interface`, `tunnel` and `ethernet` are never set.
   Source and destination names and services are resolved as in §3.12.

### 3.12.3 L7 flows (`seven`)

Input is the proxy access-log record (owned by the L7 spec). The record MUST
NOT be mutated — it may be shared with other consumers.

1. Parse the record's RFC3339Nano timestamp; a parse failure aborts the whole
   decode.
2. `IP` from the record's IP version and the two endpoint addresses; when the
   version is neither v4 nor v6, `IP` is left nil.
3. DNS names are resolved crossed, as in §3.12.
4. Endpoints are built directly from the record's endpoint structs:
   `{ID, identity, cluster_name from the k8s cluster label, namespace, labels
   (sorted, **not** CIDR-filtered), pod_name}`. Namespace and pod name are
   filled from the ipcache when the record does not carry them. Workloads are
   then added by looking the IP up in the endpoint manager, so **workloads
   appear only for node-local endpoints**.
   The record's source endpoint always maps to `Flow.source` and its
   destination endpoint to `Flow.destination`; ingress vs egress surfaces only
   through `traffic_direction`.
5. `l4` is TCP, UDP or SCTP ports from the record's transport protocol;
   anything else yields no `l4`.
6. `verdict`: `Denied → DROPPED`, `Forwarded → FORWARDED`,
   `Redirected → REDIRECTED`, `Error → ERROR`, else `VERDICT_UNKNOWN`.
   `drop_reason` is 0 and `drop_reason_desc` is `DROP_REASON_UNKNOWN`.
7. `Type = L7`; `event_type = {129, 0}`; `traffic_direction` from the record's
   observation point; `policy_match_type = 0`.
8. `l7.type` is `REQUEST` / `RESPONSE` / `SAMPLE`; the record's `dns` or `http`
   sub-record selects the `Layer7.record` oneof. A record with neither yields
   a `Layer7` carrying only `type`.
   **Kafka is not produced.** `flow.Kafka` and `Layer7.kafka = 102` stay in the
   proto as deprecated, but the reference's access-log has no Kafka record at
   v1.20.1 and flowsdn MUST NOT emit one.
9. **Latency** (`l7.latency_ns`): keyed on the HTTP `X-Request-Id` header. On a
   request, store the timestamp in an LRU (default capacity 10000); on a
   response, take **and remove** the stored timestamp and compute
   `now - request_time` in nanoseconds, clamped at 0. A cache miss, a missing
   request id, or a `SAMPLE` yields 0.
10. **Trace context**: HTTP only. If a `traceparent` header is present, parse it
    per W3C Trace Context and take the trace id as a hex string. On a request
    with a non-empty `X-Request-Id`, cache it under that id; on a response,
    look it up and remove it. Result is
    `trace_context.parent.trace_id`.
11. **DNS record**: `qtypes` are the string forms of the query types. A request
    sets only `{query, observation_source, qtypes}`; a response additionally
    sets `{ips, ttl, cnames, rcode, rrtypes}`.
12. **HTTP record**: headers are emitted in **sorted key order**, one
    `HTTPHeader` per value, each passed through the redaction filter. Requests
    set `{method, protocol, url, headers}`; responses and samples add `code`.

**Redaction.** The replacement string is the literal `HUBBLE_REDACTED`.

| Setting | Default | Effect |
|---|---|---|
| `--hubble-redact-enabled` | false | master switch for header redaction |
| `--hubble-redact-http-urlquery` | false | clears the URL query and fragment |
| `--hubble-redact-http-userinfo` | **true** | replaces a URL password with `HUBBLE_REDACTED` when the URL carries `user:password@` |
| `--hubble-redact-http-headers-allow` | `[]` | header names kept verbatim; everything else redacted |
| `--hubble-redact-http-headers-deny` | `[]` | header names redacted; everything else kept |

Header filter, in order: if redaction is disabled → keep; if both lists are
empty → **redact everything**; if the lowercased name is in allow → keep; if it
is in deny → redact; if allow is non-empty → redact; otherwise keep. Specifying
both lists is a configuration error and MUST be rejected at startup.

Note the URL-password rule is gated on `--hubble-redact-http-userinfo` alone,
not on `--hubble-redact-enabled`; since it defaults to true, a URL password is
redacted even with redaction "off". This is deliberate and MUST be preserved:
it is a credential leak otherwise.

**`Summary`** (deprecated field 100000, still preferred by the CLI's compact
output for L7 flows):

| Case | Format |
|---|---|
| HTTP request | `<protocol> <method> <url>` |
| HTTP response | `<protocol> <code> <latency_ms>ms (<method> <url>)` |
| DNS request | `DNS Query <query> <qtypes joined by ,>` |
| DNS response | `DNS Answer <answer> TTL: <ttl> (<Proxy\|Query> <query> <qtypes>)` where `<answer>` is `RCode: <rcode>` for a nonzero rcode, else the quoted IP list plus `CNAMEs: <list>` |
| generic L7 | `<proto> Fields: <fields>` |
| `SAMPLE` | empty |

flowsdn MUST populate `Summary` for L7 flows. For L3/L4 flows it is the last
decoded layer's description (§3.9) and SHOULD also be populated, because
`hubble observe -o compact` falls back to it. See §12.4.

---

## 3 (continued). Behavior — storage and the gRPC surface

### 3.13 The ring buffer

**Capacity.** `--hubble-event-buffer-capacity` MUST be one less than a power of
two and at most 65535 (`1, 3, 7, …, 4095, …, 65535`); default **4095**.
Validation is the bit test `n > 0 && n <= 65535 && (n & (n+1)) == 0`, and an
invalid value MUST be a startup error naming the accepted values.

Derived quantities, given `n`:

```
mask       = n
data_len   = n + 1                    // the allocated slot count
cycle_exp  = log2(data_len)           // 12 for n = 4095
cycle_mask = u64::MAX >> cycle_exp
half_cycle = (u64::MAX >> cycle_exp) >> 1
cap        = data_len - 1             // == n; one slot is permanently unreadable
```

`Cap()` is `data_len − 1`, so a requested capacity of 4095 allocates a
4096-entry array and one slot is always reserved for the in-flight write.
`Len()` is `write` while `write < data_len`, then `Cap()`.

**Writer** (single writer, many readers):

```
lock(notify);
write   = write_counter.fetch_add(1) + 1;      // counter first
slot    = (write - 1) & mask;
store(slot, entry);                            // pointer store second
close_and_replace(notify_ch);                  // wake all followers
unlock(notify);
```

The counter is bumped **before** the pointer is stored. That ordering is why:

```
last_write()          = write - 1
last_write_parallel() = write - 2   // the slot at write-1 may be mid-store
oldest_write()        = if write > data_len { write - data_len } else { 0 }
```

An entry MUST never be null; null is the sentinel for "never written".

**Reader — the overwrite detection (normative):**

```
read_idx       = read & mask
event          = load(read_idx)
last_write     = write_counter.load() - 1
last_write_idx = last_write & mask
read_cycle     = read >> cycle_exp
write_cycle    = last_write >> cycle_exp
prev_cycle     = (write_cycle - 1) & cycle_mask
max_cycle      = (write_cycle + half_cycle) & cycle_mask

match {
  // in the current cycle, behind the writer
  read_cycle == write_cycle && read_idx < last_write_idx =>
      if event.is_none() { Eof } else { Ok(event) },

  // in the previous cycle, ahead of the writer's index
  read_cycle == prev_cycle && read_idx > last_write_idx =>
      if event.is_none() { Ok(lost_event()) }   // ring not yet full: about to be overwritten
      else               { Ok(event) },

  // reader ahead of writer: nothing to read yet
  read_cycle >= write_cycle && read_cycle < max_cycle => Eof,

  // reader lapped by writer
  _ => Ok(lost_event()),
}
```

Three properties that MUST be preserved:

1. The slot at `last_write_idx` is **never** readable (`<` and `>`, never `==`).
2. `half_cycle` is what disambiguates "reader ahead" from "reader lapped" in
   modular arithmetic; without it a wrapped counter produces silent
   mis-reads.
3. **Overwrite is signalled in band, as a value, not as an error.** The only
   error `read` returns is end-of-stream. A lapped reader gets

   ```
   Event { timestamp: now, inner: LostEvent {
       source: HUBBLE_RING_BUFFER, num_events_lost: 1, cpu: None } }
   ```

   with `num_events_lost = 1` per detection — **not** the size of the gap —
   and the `hubble_lost_events_total{source="hubble_ring_buffer"}` counter is
   incremented. Callers (`GetFlows` positioning, the flow-rate calculation)
   check for a lost event *before* checking for end-of-stream, so modelling
   overwrite as an error changes their behavior.

**Follow mode.** `read_from(read)` loops with the same classification and, when
the reader has caught the writer, sleeps on the notify channel. The sleep MUST
be race-protected: after deciding to sleep, re-read the write counter while
holding the notify lock and retry the same position if it changed; otherwise
install/observe the notify channel and await it. Missing this loses a wake-up
and stalls a follower until the next write.

**RingReader** holds a ring handle and an index:

| Operation | Effect |
|---|---|
| `next()` | read at `idx`; on success `idx += 1`; on end-of-stream `idx` is **not** advanced, so the reader can be retried |
| `previous()` | read at `idx`; on success `idx -= 1` |
| `next_follow(ctx)` | lazily spawn a `read_from` task feeding a channel of capacity **1000**; return the next event, `idx += 1`; `None` on cancellation |

**What a slow reader observes.** A reader that falls more than `cap` events
behind gets one synthetic `LostEvent` per overwritten slot, interleaved in
position order with the events it can still read. It does **not** get an error
and its stream does not terminate. In `GetFlows` those per-slot lost events are
coalesced (§3.14) into one `LostEvent` per `--hubble-lost-event-send-interval`
with a real count and a first/last timestamp range.

### 3.14 `Observer.GetFlows`

**Validation.** `first && follow` MUST be rejected with `InvalidArgument`
("first cannot be specified with follow"). That is the *only* request
validation; it applies identically to `GetAgentEvents` and `GetDebugEvents`.

**Filter construction.** `whitelist` and `blacklist` are each built from the
request's repeated `FlowFilter`s (§3.16). An unparseable filter is an error
returned to the client before any event is sent.

**Positioning (normative).** In precedence order:

| Condition | Start index |
|---|---|
| `first && since == None` | `oldest_write()` — the beginning of the ring |
| `follow && number == 0 && since == None` | `last_write_parallel()` — live tail only, no history |
| otherwise | the rewind scan below |

The rewind scan walks **backwards** from `last_write_parallel()` for at most
`ring.len()` steps:

```
for i in (0..ring.len()).rev() {
    e = reader.previous();
    if e is a LostEvent with source == HUBBLE_RING_BUFFER {
        idx += 1;            // we went one too far — that slot is gone
        break;
    }
    if e is an error { return the error }
    if e is any LostEvent || !filters.apply(whitelist, blacklist, e) { continue }
    event_count += 1;
    if since.is_some() {
        if e.timestamp < since { idx += 1; break }   // one too far
    } else if event_count == number {
        break;
    }
    idx -= 1;
}
```

Consequences that MUST be preserved:

- `since` takes precedence over `number`: a request with both walks back until
  the timestamp boundary, not until `number` matches.
- The scan applies the filters, so `--last N` returns N *matching* flows, not
  the last N flows of which some match.
- Lost events are skipped by the scan and never counted.
- Hitting the overwrite boundary stops the scan; a request for more history
  than the ring holds silently returns what exists.
- `until` plays **no** role in positioning. It is only a stop condition.
- An empty ring makes the first `previous()` return end-of-stream; the RPC then
  returns cleanly with an empty stream, not an error.

**Streaming.** For each event, in order:

1. If the lost-event coalescer has elapsed, emit a `LostEvent` response first
   (see below).
2. Get the next event:
   - in follow mode, from the follow channel (unbounded in time; note that
     `--follow --number N` streams **unbounded** after the initial rewind — the
     `number` cap applies only to the non-follow path);
   - otherwise, stop with end-of-stream once `number` events have been sent.
3. A `LostEvent` is **exempt** from the time range and from all filters
   (ring-buffer timestamps are only monotonic for real events).
4. `until != None && ts > until` terminates the whole stream (relying on
   monotonic timestamps). `since != None && ts < since` skips the event.
5. Apply `whitelist.match_one() && blacklist.match_none()`.
6. For a `Flow`: run the delivery hooks — **an error here aborts the RPC**,
   unlike the decode-loop hooks which only log. Then, if the request carries a
   field mask, copy the masked paths into one **per-stream reusable** `Flow`
   and send that.
7. Send `GetFlowsResponse { flow | lost_events | node_status, node_name, time }`.

**Counting.** Only `Flow` responses increment the `number` counter. Lost events
explicitly do not, so `--last 20` returns 20 flows regardless of loss.

**Lost-event coalescing.** Ring-buffer lost events are accumulated into
`{count, first, last}`; the accumulator is considered elapsed when
`now − first >= lost_event_send_interval` (default 1 s). The window therefore
starts at the **first** lost event, not at the last flush. On flush, one
response is emitted with `source = HUBBLE_RING_BUFFER`, the accumulated count
and the first/last timestamps, and the accumulator is cleared. Lost events from
any other source are forwarded immediately, uncoalesced.

A zero interval disables coalescing (every lost event is sent immediately);
the flag validation MUST reject values `<= 0` so this cannot happen by
accident.

**Field mask.** `field_mask` is a `google.protobuf.FieldMask` over `Flow`.
Validation requires **every** path to resolve against the `Flow` descriptor; a
single bad path rejects the whole mask with `invalid fieldmask`. The mask is
normalized (sorted, redundant sub-paths removed, so `["source.ID","source"]`
collapses to `["source"]`) and stored as a path tree. Application:

- leaf: set the field from the source, or clear it if the source does not have
  it;
- **oneof member**: recurse only when the source's active oneof arm is that
  same field. Without this rule, masking `l4.TCP` on a UDP flow materializes an
  empty `TCP` message.
- other message field: recurse, allocating the destination sub-message on first
  use.
- Fields absent from the mask are left untouched in the destination, which is
  why the destination is a pre-allocated, reused message.

**Metadata.** The server MUST attach `hubble-server-version` to responses.

### 3.15 The other Observer RPCs

| RPC | Local server | Relay |
|---|---|---|
| `GetFlows` | full | fan-out (§3.17) |
| `GetAgentEvents` | full | `Unimplemented` |
| `GetDebugEvents` | full | `Unimplemented` |
| `GetNodes` | **`Unimplemented`** | full |
| `GetNamespaces` | full | merged across peers |
| `ServerStatus` | full | aggregated |

`GetAgentEvents` / `GetDebugEvents` share `GetFlows`' positioning and time
range but support **no filtering at all** (no `whitelist`/`blacklist` fields
exist), no field mask, no delivery hooks and no lost-event coalescing. Events
of the wrong kind are skipped without counting.

`GetNamespaces` returns the namespaces the node has observed, sorted by
`(cluster, namespace)`. The tracker records `{cluster, namespace}` for the
source and destination of every decoded flow whose namespace is non-empty,
**refreshing the timestamp on every sighting**, and evicts entries not seen for
`namespace_ttl = 1 h`, sweeping every `cleanup_interval = 5 min`.

`ServerStatus`:

| Field | Value |
|---|---|
| `version` | the flowsdn server version |
| `max_flows` | `ring.cap()` |
| `num_flows` | `ring.len()` |
| `seen_flows` | lifetime count of decoded flows (incremented only after all decode hooks pass) |
| `uptime_ns` | since the observer started |
| `flows_rate` | flows per second over the trailing minute (below) |

`flows_rate` walks backwards from `last_write_parallel()`, counting `Flow`
events newer than `now − 60 s`, and stops at the first ring-buffer lost event
or at end-of-stream. If it stopped early, the denominator shrinks to the actual
observed span (`now − oldest counted timestamp`) rather than staying 60 s, so a
ring holding ten seconds of traffic reports the true rate. An error computing
the rate MUST be logged and reported as 0, not returned.

### 3.16 Filters

**Composition (normative, three levels):**

```
apply(whitelist, blacklist, ev) = whitelist.match_one(ev) && blacklist.match_none(ev)

match_all(fs, ev)  = fs.iter().all(|f| f(ev))     // empty => true
match_one(fs, ev)  = fs.is_empty() || fs.iter().any(|f| f(ev))
match_none(fs, ev) = fs.is_empty() || !fs.iter().any(|f| f(ev))
```

1. **Within one field** (`source_pod: [a, b]`): OR.
2. **Across fields inside one `FlowFilter`**: AND — one closure per
   `FlowFilter` that requires every per-field predicate to hold.
3. **Across the `whitelist` list**: OR. **Across the `blacklist` list**: NOR.
   An empty list is vacuously true in both cases, so an empty whitelist means
   "everything" and an empty blacklist means "nothing excluded".

**The 25 filter fields.** Builder order matters only for cost; CEL is placed
last deliberately.

| Field(s) | # | Semantics |
|---|---|---|
| `uuid` | 29 | exact string |
| `event_type` | 6 | `EventTypeFilter{type, match_sub_type, sub_type}`. `type == 0` means "any type". `sub_type` is compared **only** when `match_sub_type` is set, because 0 is a legitimate sub-type. Agent events match `type == 130` with `sub_type = AgentEventType`; debug events `type == 2` with `sub_type = DebugEventType`. A **`LostEvent` always matches** — there is no way to filter lost events out. |
| `verdict` | 5 | enum membership |
| `drop_reason_desc` | 33 | requires `verdict == DROPPED` **and** enum membership |
| `reply` | 15 | `[]bool`. An `is_reply` of "unknown" on a `DROPPED` flow is treated as `false`; unknown on any other verdict never matches. Empty list ⇒ match. |
| `encrypted` | 40 | `[]bool` against `IP.encrypted`; empty list ⇒ match |
| `source_identity`, `destination_identity` | 19, 20 | numeric `u32` exact |
| `protocol` | 12 | lowercased name. L4: `icmp` (matches v4 **or** v6), `icmpv4`, `icmpv6`, `tcp`, `udp`, `sctp`, `vrrp`, `igmp`. L7: `dns`, `http`. Anything else is a build error. |
| `source_ip`, `destination_ip`, `source_ip_xlated` | 1, 3, 34 | each entry is either a plain address or a CIDR. Plain addresses are compared as **strings** against the flow's rendered address; CIDRs are parsed and tested with prefix containment. (The string comparison means a non-canonical spelling of an IPv6 address does not match; kept for compatibility, noted in §12.8.) |
| `ip_version` | 25 | enum membership; a flow with no IP layer has version `IP_NOT_USED (0)` and therefore matches a filter listing `IP_NOT_USED` |
| `source_pod`, `destination_pod`, `source_service`, `destination_service` | 2, 4, 16, 17 | `ns/name` split (below), namespace **exact**, name **prefix** |
| `source_workload`, `destination_workload` | 26, 27 | per entry: `(name empty ∨ name == w.name) ∧ (kind empty ∨ kind == w.kind)` over the endpoint's workloads |
| `source_fqdn`, `destination_fqdn` | 7, 8 | glob (below) against `source_names` / `destination_names` |
| `dns_query` | 18 | unanchored RE2 against `l7.dns.query` |
| `source_label`, `destination_label`, `node_labels` | 10, 11, 36 | Kubernetes label-selector syntax with Cilium source-prefix translation (below); OR across the list |
| `source_port`, `destination_port` | 13, 14 | **exact u16 values only — there is no range syntax.** A non-numeric or out-of-range entry is a build error. The port is taken from TCP, then UDP, then SCTP; a flow with any other L4 (or none) never matches. |
| `http_status_code` | 9 | either a full 3-digit code matching `^[1-5][0-9]{2}$`, or a 1–2 digit prefix followed by `+` matching `^[1-5][0-9]?\+$` (`4+`, `40+`). Anything else is a build error. A flow with no HTTP record, or `code == 0`, never matches. |
| `http_method` | 21 | case-insensitive exact |
| `http_path` | 22 | unanchored RE2 against the parsed URL's path; an unparseable URL never matches |
| `http_url` | 31 | unanchored RE2 against the raw URL |
| `http_header` | 32 | matches if any flow header equals a filter header on **both** key and value, case-sensitively |
| `tcp_flags` | 23 | **subset test**: every flag set in a filter entry must be set in the flow (extra flags in the flow are fine) — AND within an entry, OR across entries. An all-false entry matches any TCP flow that has a flags field. |
| `node_name` | 24 | `cluster/node` glob (below) |
| `source_cluster_name`, `destination_cluster_name` | 37, 38 | exact; an empty string in the list is a build error |
| `traffic_direction` | 30 | enum membership |
| `trace_id` | 28 | exact string against `trace_context.parent.trace_id` |
| `ip_trace_id` | 39 | exact `u64` |
| `interface` | 35 | per entry: `(index == 0 ∨ index == iface.index) ∧ (name empty ∨ name == iface.name)` |
| `experimental.cel_expression` | 999.1 | **deferred** (§12.5) |

The five HTTP sub-filters are gated: if an `event_type` filter is present, at
least one entry must have `type == 129`, otherwise the build fails with
"filtering by http status code requires the event type filter to only match
'l7' events". This MUST be reproduced — it turns a silently-empty result into a
clear error.

**`ns/name` splitting** (used by pod and service filters):

| Input | `(namespace, name)` |
|---|---|
| `xwing` | `("default", "xwing")` — **an unqualified name means the `default` namespace** |
| `kube-system/` | `("kube-system", "")` — namespace only |
| `/xwing` | `("", "xwing")` — any namespace |
| `a/b/c` | `("a", "b")` — extra segments silently dropped |
| `""` | build error |

Namespace comparison is exact; the name is a prefix match. A flow whose
endpoint has neither namespace nor name never matches.

**FQDN and node-name globs.** Patterns are trimmed, one trailing dot is
stripped, and the result is lowercased, then compiled into a single anchored
alternation. Within a pattern, `.` is a literal dot, `*` expands to
`[-.0-9a-z]*`, and `[-0-9_a-z]` pass through; **any other character is a build
error**. An empty pattern, or a second trailing dot, is a build error.

Node-name patterns additionally split on `/`: one element means "node pattern,
any cluster"; two mean `cluster/node`; three or more is an error. An empty
element on either side is a wildcard. At match time a flow's node name without
a `/` is first qualified with the local cluster name.

**Label selectors.** Labels are parsed into `source:key=value` form. Each
selector string is rewritten before parsing: a key carrying a source prefix
(`k8s:foo`) becomes `k8s.foo` (only the **first** colon is replaced), and a key
with no prefix (`example.com`) becomes `any.example.com`. The full Kubernetes
selector grammar is then supported (`=`, `!=`, `in`, `notin`, `!key`, comma-
separated conjunctions). OR across the list.

### 3.17 Peer service and relay fan-out

#### 3.17.1 `Peer.Notify`

A stream of `ChangeNotification{name, address, type, tls}`. On connect the
server replays every known node as `PEER_ADDED`; the subscription to the node
manager MUST be established only *after* the streaming task is running, because
the subscribe call synchronously replays all existing nodes into an unbuffered
channel.

| Node event | Notifications |
|---|---|
| add | `PEER_ADDED` |
| delete | `PEER_DELETED` |
| update, same full name, same address | none |
| update, same full name, different address | `PEER_UPDATED` |
| update, different full name | `PEER_DELETED(old)` then `PEER_ADDED(new)` |

`name` is the cluster-qualified node name. `address` is `<node ip>:<hubble
port>`, with the family chosen by the preference order (`--prefer-ipv6` swaps
IPv6 ahead of IPv4); the check is strict (an IPv4-mapped IPv6 address is not
accepted as IPv6). An empty address is legal and means "no reachable address".
`tls` is present iff the Hubble server has TLS enabled, and carries the derived
server name (§3.17.4).

**Backpressure.** Each stream has a send buffer capped at
`max_send_buffer_size` (default **65536** notifications). On overflow the
stream is **terminated** with "server stream send was blocked for too long" —
it is not throttled and notifications are not dropped silently. A relay that
cannot keep up therefore reconnects and gets a fresh full replay, which is the
correct recovery.

#### 3.17.2 Peer discovery and connection management (relay)

The relay connects to `--peer-service` (default the agent's unix socket) and
consumes `Peer.Notify`. Three concurrent tasks:

1. **Notification watcher.** On any failure — building the client, opening the
   stream, or receiving — close the client, mark the peer service
   disconnected, wait `--retry-timeout` (30 s) and retry. `PEER_ADDED` and
   `PEER_UPDATED` upsert; `PEER_DELETED` removes.
2. **Connection manager.** Connects a peer immediately when it is upserted
   (ignoring backoff), and re-checks every peer every `conn_check_interval`
   (**2 minutes**).
3. **Status reporter.** Every `conn_status_interval` (5 s), tallies peers by
   connection state into `hubble_relay_pool_peer_connection_status{status}`.

Upsert is a no-op when the peer is unchanged (name, TLS enabled, TLS server
name and address all equal) — this MUST be checked, or every notification
would tear down and rebuild a working connection.

**Backoff.** Exponential with `min = 1 s`, `max = 1 min`, `factor = 2.0`, plus
jitter, counted per peer. A successful connection resets the attempt counter
and clears the next-attempt time. Because gRPC channel creation is lazy, a
"successful" connect only means the channel was constructed; actual
reachability is judged from the channel state.

**Availability** for fan-out purposes: a peer is available when it has a
channel whose state is neither transient-failure nor shutdown.

#### 3.17.3 `GetFlows` fan-out

```
peers → per-peer GetFlows streams → merged channel
      → error aggregation (10 s window)
      → sort buffer (min-heap, drain 1 s)
      → client
```

1. Before any flow, send a `NODE_CONNECTED` status event naming the peers that
   were reached, then a `NODE_UNAVAILABLE` status event naming those that were
   not.
2. Open a `GetFlows` stream to every available peer with the **same** request;
   incoming gRPC metadata is forwarded to the peers.
3. In follow mode, re-scan the peer list every `peer_update_interval` (**2 s**)
   and join newly-arrived peers. A set of already-connected nodes prevents
   duplicate dials; a peer whose stream errors is removed from the set so a
   later scan retries it, and an error status event is pushed into the stream.
4. `EOF`, cancellation and gRPC `Canceled` from a peer are clean terminations,
   not errors.

**Sort buffer.** A min-heap keyed on the response timestamp, sized

```
qlen = if number * peer_count in 1..sort_buffer_max_len { number * peer_count }
       else { sort_buffer_max_len }          // sort_buffer_max_len = 100
```

- When the heap is full, the **oldest** entry is popped and emitted to make
  room. The buffer is therefore lossy-in-order under load — it emits before the
  sort window has elapsed rather than dropping or blocking.
- When no new response arrives for `--sort-buffer-drain-timeout` (**1 s**),
  every entry older than `now − drain_timeout` is flushed in timestamp order.
  The timer is re-armed each loop iteration, so it measures inter-arrival
  idleness, not wall-clock periods.
- On upstream close the heap is fully drained.

This is why the agent's `--hubble-lost-event-send-interval` also defaults to
1 s: the two windows are meant to match.

**Error aggregation.** At most one `NODE_ERROR` status is pending at a time.
A new error with an **identical message** merges its node names into the
pending one; an error with a different message flushes the pending one
immediately and starts a fresh `--error-aggregation-window` (**10 s**) timer.
The timer is armed once per pending response and is not extended by merges.
Non-error status events are forwarded immediately. Channel close flushes.

The message of a `NODE_ERROR` is the error string, except that a gRPC status
with code `Unknown` is unwrapped to its message.

**`GetNodes`.** One `Node` per peer. Unavailable peers get
`NODE_UNAVAILABLE` and are not queried. Available peers get `NODE_CONNECTED`
and are queried concurrently for `ServerStatus` to fill `version`,
`uptime_ns`, `max_flows`, `num_flows`, `seen_flows`; a peer whose RPC fails is
downgraded to `NODE_ERROR` and **does not fail the call**.

**`ServerStatus` aggregation:**

| Field | Rule |
|---|---|
| `max_flows`, `num_flows`, `seen_flows`, `flows_rate` | summed across peers |
| `uptime_ns` | the **maximum** (the oldest node) — deliberately not summed |
| `num_connected_nodes` | `peers − unavailable` |
| `num_unavailable_nodes` | peers never connected **plus** peers whose status RPC failed |
| `unavailable_nodes` | the names, **capped at 10** |
| `version` | the relay version |

**`GetNamespaces`** queries every peer, merges into a fresh tracker, and
returns the sorted de-duplicated union. Partial results are returned on peer
failure rather than failing the call.

**Metadata.** The relay attaches `hubble-relay-version` on outgoing calls and
forwards incoming metadata to the peers.

**Health.** A separate gRPC health server on `:4222` reports `SERVING` for both
the empty service name and `hubble.server.Observer` iff the peer service is
connected **and** at least one peer is available; it is re-evaluated every 5 s
and starts as `NOT_SERVING`.

#### 3.17.4 TLS and server-name derivation

Minimum TLS version is **1.3** on the agent's TCP listener, the relay's server
listener, and both client sides.

| Endpoint | Server cert | Client CA (⇒ mTLS) |
|---|---|---|
| agent unix socket | never TLS | — |
| agent TCP `:4244` | `--hubble-tls-cert-file` / `--hubble-tls-key-file` unless `--hubble-disable-tls` | `--hubble-tls-client-ca-files` |
| agent metrics | `--hubble-metrics-server-tls-*` when `--hubble-metrics-server-enable-tls` | `--hubble-metrics-server-tls-client-ca-files` |
| relay server `:4245` | `--tls-relay-server-cert-file` / `-key-file` unless `--disable-server-tls` | `--tls-relay-client-ca-files` |
| relay → agent | client cert `--tls-hubble-client-cert-file` / `-key-file` unless `--disable-client-tls` | verifies against `--tls-hubble-server-ca-files` |

Presence of a client-CA list is what enables mTLS; there is no separate switch.

**Certificate reloading.** The TLS config MUST re-read the key pair and CA pool
**per handshake**, so rotated certificates take effect without a restart. On
the client side the credentials are re-derived on every handshake for the same
reason. At startup, when TLS is enabled but the files do not exist yet, the
server MUST wait for them (logging every 30 s) rather than failing — this is
what makes Helm's certificate-generating Job work regardless of ordering.

**Server name per node:**

```
tls_server_name(node_name, cluster_name):
    if node_name.is_empty() { return "" }
    nn = node_name.replace('.', '-')
    cn = (if cluster_name.is_empty() { "default" } else { cluster_name }).replace('.', '-')
    format!("{nn}.{cn}.hubble-grpc.cilium.io")
```

Dots are replaced with hyphens so that every node's server name sits at the
same DNS domain level (Kubernetes permits dots in node names). Example:
`moseisley.tatooine.hubble-grpc.cilium.io`.

The relay uses the same function with the literal node name `hubble-peer` when
its peer target is remote rather than a unix socket, so the peer Service's
certificate must be issued for `hubble-peer.<cluster>.hubble-grpc.cilium.io`.

The domain `cilium.io` is retained because it is baked into issued
certificates and into the Helm chart; changing it would break every existing
deployment's certificates. This is nominative use, consistent with
`docs/licensing.md`.

`GRPCClientConnBuilder` MUST reject the two inconsistent combinations up front:
a TLS config with no server name, and a server name with no TLS config.

### 3.18 Metrics pipeline

The metrics subsystem is a set of **handlers**, each registering its own
Prometheus collectors at init and consuming every decoded flow. It is inert
unless `--hubble-metrics-server` is set.

- `--hubble-metrics` and `--hubble-dynamic-metrics-config-path` are **mutually
  exclusive**; setting both MUST be a startup error.
- `--hubble-metrics` is one string split on **any whitespace** into specs of
  the form `name[:opt[=val][;opt[=val]]…]`. Only the **first** colon splits the
  name from the options, so later colons belong to the options.
- Each option splits on the first `=`. With no `=`, the value list is a single
  empty string — this is what makes bare flags like `any-drop` "present". For
  `labelsContext` the value splits on `,`; for every other option it splits on
  `|`. Empty items are dropped in both splits.
- **Presence, not truth, enables most flags**: `port=false` still enables the
  `port` label. The sole exception is `exemplars`, which requires the literal
  value `true`.
- An **unknown handler name is not fatal** — it is logged and skipped.
- `http` and `httpV2` **conflict**; enabling both MUST be a hard error.
- Include/exclude filters are **YAML-only**; there is no command-line syntax
  for them.

Per flow, each handler applies its own protocol/verdict gate and its allow/deny
filters (built exactly as in §3.16) before emitting.

**Dynamic configuration** is polled every **10 s**; the file's raw bytes are
hashed (first 8 bytes of the MD5, little-endian) and the callback runs only on
change. Read, parse and validation errors leave the running configuration
untouched.

Validation, all of which reject the **entire** config:

1. an empty `name` at any index;
2. a duplicate `name`;
3. a change to a previously-seen metric's `contextOptions`. **Label sets cannot
   change at runtime** — Prometheus collectors are registered with a fixed
   label list. Only filters may change live.

Reload reconciliation, in order:

1. **Remove** handlers absent from the new config, unregistering their
   collectors. This happens first so that a `http` → `httpV2` swap in one
   reload succeeds.
2. For each entry in the new config: unchanged → no-op; same name, changed
   filters → rebuild the filter lists only (registration untouched); new name →
   create and register. A failure to create one handler is logged and skipped,
   not fatal.

**Pod-deletion cleanup.** On endpoint deletion, after a **1 minute** grace
period, series carrying that pod are deleted from every handler's collectors:

| Condition | Deleted by partial label match |
|---|---|
| any source context identifier is exactly `pod` | `source = "<ns>/<name>"` |
| any destination context identifier is exactly `pod` | `destination = "<ns>/<name>"` |
| `labelsContext` contains **both** `source_pod` and `source_namespace` | `{source_namespace, source_pod}` |
| `labelsContext` contains **both** `destination_pod` and `destination_namespace` | `{destination_namespace, destination_pod}` |

Only the exact `pod` identifier triggers cleanup; `pod-name`, `workload`,
`identity`, `app`, `dns` and `ip` series are never reaped, and the
`labelsContext` path needs both the pod and namespace labels.

**DEVIATION**: in the reference, cleanup is wired only on the *static* metrics
path — the dynamic path starts the reaper but never populates the handler list
it reads, so dynamically-configured pod-labelled metrics leak unboundedly.
flowsdn wires cleanup on **both** paths. Reason: it is an unbounded memory leak
and a cardinality explosion in exactly the configuration operators are steered
towards; no consumer depends on the leak. (ADR-0001 — compatibility is at the
metric names and labels, not at the leak.)

### 3.19 Export

#### 3.19.1 Export pipeline

Per event, in order:

1. Apply the exporter's allow/deny filter lists (§3.16 composition).
2. Run the export hooks. A hook error is **logged, not fatal**; a hook
   returning "stop" ends processing for that event. (This is how the dynamic
   exporter's `end` time is enforced — see §3.19.4.)
3. If aggregation is active **and** the event is a `Flow`, add it to the
   aggregator and return; every other event type bypasses aggregation.
4. Convert to `observer.ExportEvent` and encode one line.

#### 3.19.2 Line format

Each line is a compact JSON object followed by `\n`, produced by **protojson
with `UseProtoNames: true`**:

- field names are the **proto** names (`IP`, `Type`, `Summary`, `l4`,
  `source_names`, `trace_observation_point`), not lowerCamelCase JSON names;
- enums are their **names** (`"FORWARDED"`, `"POLICY_DENIED"`), not numbers;
- `Timestamp` is an RFC3339 string;
- 64-bit integers are strings;
- `Any` is expanded with `@type`;
- unset fields are omitted.

The output is compacted, so protojson's deliberate whitespace randomisation
does not appear on the wire. This is the format log shippers parse and
`hubble observe -o jsonpb` produces; it MUST be byte-compatible. §9.1 requires
a golden-line test against a captured reference export.

`ExportEvent` carries `flow | node_status | lost_events | agent_event |
debug_event` plus `node_name` (1000) and `time` (1001).

**Note on `node_name`:** the reference sets `node_name` from the *flow* for
flow events but from the bare node name for lost/agent/debug events, whereas
the Observer API uses the cluster-qualified name everywhere.
**DEVIATION**: flowsdn uses the cluster-qualified name (`<cluster>/<node>`)
consistently in the exporter. Reason: an inconsistent `node_name` within one
log file cannot be correlated by a log shipper, and the qualified form is a
superset. Recorded as a behavior change in §12.9.

#### 3.19.3 Rotation

Size-based rotation with `fileMaxSizeMb` (default 10), `fileMaxBackups`
(default 5) and `fileCompress` (default false); rotated files are named
`<base>-<timestamp><ext>` with `.gz` appended when compressed.
`--hubble-export-file-path stdout` writes to stdout with a no-op close instead
of a file, and is the default when no path is set.

#### 3.19.4 Dynamic flow logs

`--hubble-flowlogs-config-path` is polled every **5 s**, with one synchronous
initial load at startup. Schema:

```yaml
flowLogs:
  - name: all                                     # required, unique
    filePath: /var/run/cilium/hubble/events.log   # required, unique; "stdout" allowed
    fieldMask: [time, source.namespace]
    fieldAggregate: [source.namespace, destination.namespace]
    aggregationInterval: 30s
    includeFilters: [ <FlowFilter as protobuf JSON> ]
    excludeFilters: [ ... ]
    fileMaxSizeMb: 10
    fileMaxBackups: 5
    fileCompress: false
    end: "2026-12-31T00:00:00Z"
```

Validation rejects: a null entry, an empty `name`, a duplicate `name`, an empty
`filePath`, a duplicate `filePath`. `fileMaxSizeMb` and `fileMaxBackups` of 0
fall back to the defaults.

Reconciliation compares each named exporter's effective configuration
(everything except `name`; filter lists compare as sets, so order and
duplicates are irrelevant) and rebuilds only the ones that changed, stopping
the old instance first. Names absent from the new config are removed.

**`end` semantics.** An expired exporter is **not** removed and its file handle
stays open; instead every event is silently dropped by an export hook, and its
`up` gauge reads 0. This MUST be preserved — operators watch the gauge, and
removing the exporter would also remove the gauge.

#### 3.19.5 Aggregation

Active only when `fieldAggregate` is non-empty **and** the interval is `> 0`; a
non-empty aggregate with a zero interval MUST log a warning and export raw
events.

For each flow:

1. Project the flow through the `fieldAggregate` mask into a fresh message.
2. The aggregation key is a **canonical serialization of the projected
   message** — the timestamp is deliberately added *after* key computation so
   it does not participate in the key.
3. Create or update the group, incrementing the ingress, egress or
   unknown-direction counter according to the flow's traffic direction.

The stored representative flow keeps the timestamp of the **first** flow in the
group. On each interval tick (and once more on shutdown) every group is emitted
as one `ExportEvent` whose flow carries
`aggregate {ingress_flow_count, egress_flow_count, unknown_direction_flow_count}`,
and the map is replaced. Encoder errors are logged and the map is cleared
regardless, so a transient write failure loses one interval rather than
accumulating unboundedly.

**DEVIATION**: the reference keys on `proto.Marshal` output, which protobuf
explicitly does not guarantee to be canonical. flowsdn MUST use a deterministic
encoding (fields in tag order, no unknown fields) or an explicit key struct.
Reason: a non-canonical key silently splits one group into several. No wire
format changes.

#### 3.19.6 Allow/deny lists on the command line

`--hubble-export-allowlist` and `--hubble-export-denylist` take **whitespace-
separated, concatenated JSON objects**, not a JSON array:

```
--hubble-export-allowlist '{"source_pod":["default/"]} {"verdict":["DROPPED"]}'
```

Each object is one `FlowFilter`; allow is OR across the list, deny is NOR,
exactly as in §3.16.

---

## 4 (continued). Data model — the protobuf contract

### 4.13 `flow.Flow` field by field (frozen)

Field numbers are the compatibility contract with the `hubble` CLI, the Hubble
UI, hubble-relay and every third-party Observer client. They MUST NOT change.
The number ordering below is the declaration order in the reference `.proto`,
which is not numeric order; keep it, because generated Rust field order follows
it and diffs stay readable.

| # | Field | Type | Set by / meaning |
|---|---|---|---|
| 1 | `time` | `Timestamp` | monitor event timestamp, set by the dispatcher |
| 34 | `uuid` | string | per-node event uuid |
| 41 | `emitter` | `Emitter{name=1, version=2}` | `"flowsdn"` + version (**DEVIATION**, §3.8) |
| 2 | `verdict` | `Verdict` | §3.12 |
| 3 | `drop_reason` | uint32 *(deprecated)* | raw drop code |
| 35 | `auth_type` | `AuthType` | policy verdict only |
| 4 | `ethernet` | `Ethernet{source=1, destination=2}` | MAC strings; absent for L3 devices |
| 5 | `IP` | `IP{source=1, destination=2, ipVersion=3, encrypted=4, source_xlated=5}` | inner addresses when tunnelled |
| 6 | `l4` | `Layer4` oneof | see §4.14 |
| 39 | `tunnel` | `Tunnel{protocol=1, IP=2, l4=3, vni=4}` | outer headers when overlay-classified |
| 7 | *reserved* | | removed upstream; MUST stay reserved |
| 8 | `source` | `Endpoint` | |
| 9 | `destination` | `Endpoint` | |
| 10 | `Type` | `FlowType` | 0 `UNKNOWN_TYPE`, 1 `L3_L4`, 2 `L7`, 3 `SOCK` |
| 11 | `node_name` | string | `<cluster>/<node>` |
| 37 | `node_labels` | repeated string | `key=value` |
| 12 | *reserved* | | |
| 13 | `source_names` | repeated string | DNS names of the source, from the **destination** endpoint's history |
| 14 | `destination_names` | repeated string | mirror of the above |
| 15 | `l7` | `Layer7` | set iff `Type == L7` |
| 16 | `reply` | bool *(deprecated)* | `is_reply` with unknown ⇒ false |
| 17, 18 | *reserved* | | |
| 19 | `event_type` | `CiliumEventType{type=1, sub_type=2}` | raw monitor type and subtype |
| 20 | `source_service` | `Service{name=1, namespace=2}` | |
| 21 | `destination_service` | `Service` | |
| 22 | `traffic_direction` | `TrafficDirection` | 0 unknown, 1 `INGRESS`, 2 `EGRESS` |
| 23 | `policy_match_type` | uint32 | §4.5 |
| 24 | `trace_observation_point` | `TraceObservationPoint` | §4.3 |
| 36 | `trace_reason` | `TraceReason` | §4.3 |
| 38 | `file` | `FileInfo{name=1, line=2}` | drop site; drops only |
| 40 | `ip_trace_id` | `IPTraceID{trace_id=1, ip_option_type=2}` | absent when the id is 0 |
| 25 | `drop_reason_desc` | `DropReason` | the enum form of field 3 |
| 26 | `is_reply` | `BoolValue` | **absent when unknown** — distinct from false |
| 27 | `debug_capture_point` | `DebugCapturePoint` | debug captures only |
| 28 | `interface` | `NetworkInterface{index=1, name=2}` | §3.12 |
| 29 | `proxy_port` | uint32 | §3.12 |
| 30 | `trace_context` | `TraceContext{parent=1 TraceParent{trace_id=1}}` | W3C traceparent from L7 |
| 31 | `sock_xlate_point` | `SocketTranslationPoint` | sock flows only |
| 32 | `socket_cookie` | uint64 | sock flows only |
| 33 | `cgroup_id` | uint64 | sock flows only |
| 100000 | `Summary` | string *(deprecated)* | human summary; the CLI's compact output still prefers it |
| 150000 | `extensions` | `Any` | |
| 21001 | `egress_allowed_by` | repeated `Policy` | §3.12.1 |
| 21002 | `ingress_allowed_by` | repeated `Policy` | §3.12.1 |
| 21004 | `egress_denied_by` | repeated `Policy` | §3.12.1 (also set for AUDIT) |
| 21005 | `ingress_denied_by` | repeated `Policy` | §3.12.1 (also set for AUDIT) |
| 21006 | `policy_log` | repeated string | de-duplicated log values of matched rules |
| 21007 | `aggregate` | `Aggregate{ingress_flow_count=1, egress_flow_count=2, unknown_direction_flow_count=3}` | exporter aggregation only |

Field 21003 is unused and MUST stay unused.

### 4.14 Supporting messages and enums (frozen)

```
Endpoint      { ID=1, identity=2, namespace=3, labels=4, pod_name=5,
                workloads=6 (Workload{name=1, kind=2}), cluster_name=7 }
Ethernet      { source=1, destination=2 }
IP            { source=1, destination=2, ipVersion=3, encrypted=4, source_xlated=5 }
Layer4 oneof  { TCP=1, UDP=2, ICMPv4=3, ICMPv6=4, SCTP=5, VRRP=6, IGMP=7 }
TCP           { source_port=1, destination_port=2, flags=3 }
UDP           { source_port=1, destination_port=2 }
SCTP          { source_port=1, destination_port=2, chunk_type=3 }
ICMPv4/v6     { type=1, code=2 }
VRRP          { type=1, vrid=2, priority=3 }
IGMP          { type=1, group_address=2 }
TCPFlags      { FIN=1, SYN=2, RST=3, PSH=4, ACK=5, URG=6, ECE=7, CWR=8, NS=9 }
Tunnel        { protocol=1, IP=2, l4=3, vni=4 }
Layer7        { type=1, latency_ns=2, oneof record { dns=100, http=101, kafka=102 (dep) } }
DNS           { query=1, ips=2, ttl=3, cnames=4, observation_source=5,
                rcode=6, qtypes=7, rrtypes=8 }
HTTP          { code=1, method=2, url=3, protocol=4, headers=5 (HTTPHeader{key=1,value=2}) }
Service       { name=1, namespace=2 }
Policy        { name=1, namespace=2, labels=3, revision=4, kind=5 }
FileInfo      { name=1, line=2 }
IPTraceID     { trace_id=1, ip_option_type=2 }
NetworkInterface { index=1, name=2 }
CiliumEventType  { type=1, sub_type=2 }
EventTypeFilter  { type=1, match_sub_type=2, sub_type=3 }
LostEvent     { source=1, num_events_lost=2, cpu=3, first=4, last=5 }
DebugEvent    { type=1, source=2, hash=3, arg1=4, arg2=5, arg3=6, message=7, cpu=8 }
AgentEvent    { type=1, oneof notification {
                  unknown=100 (AgentEventUnknown{type=1, notification=2}),
                  agent_start=101, policy_update=102, endpoint_regenerate=103,
                  endpoint_update=104, ipcache_update=105,
                  service_upsert=106 (dep), service_delete=107 (dep) } }
Aggregate     { ingress_flow_count=1, egress_flow_count=2,
                unknown_direction_flow_count=3 }
```

Enums:

| Enum | Values |
|---|---|
| `Verdict` | 0 `VERDICT_UNKNOWN`, 1 `FORWARDED`, 2 `DROPPED`, 3 `ERROR`, 4 `AUDIT`, 5 `REDIRECTED`, 6 `TRACED`, 7 `TRANSLATED` |
| `FlowType` | 0 `UNKNOWN_TYPE`, 1 `L3_L4`, 2 `L7`, 3 `SOCK` |
| `AuthType` | 0 `DISABLED`, 1 `SPIRE`, 2 `TEST_ALWAYS_FAIL` |
| `IPVersion` | 0 `IP_NOT_USED`, 1 `IPv4`, 2 `IPv6` |
| `TrafficDirection` | 0 unknown, 1 `INGRESS`, 2 `EGRESS` |
| `L7FlowType` | 0 unknown, 1 `REQUEST`, 2 `RESPONSE`, 3 `SAMPLE` |
| `SCTPChunkType` | 0 `UNSUPPORTED`, 1 `INIT`, 2 `INIT_ACK`, 3 `SHUTDOWN`, 4 `SHUTDOWN_ACK`, 5 `SHUTDOWN_COMPLETE`, 6 `ABORT` |
| `Tunnel.Protocol` | 0 `UNKNOWN`, 1 `VXLAN`, 2 `GENEVE` |
| `SocketTranslationPoint` | 0 unknown, 1 `PRE_DIRECTION_FWD`, 2 `POST_DIRECTION_FWD`, 3 `PRE_DIRECTION_REV`, 4 `POST_DIRECTION_REV` |
| `LostEventSource` | 0 unknown, 1 `PERF_EVENT_RING_BUFFER`, 2 `OBSERVER_EVENTS_QUEUE`, 3 `HUBBLE_RING_BUFFER` |
| `EventType` | 0 `UNKNOWN`, 2 `RecordLost`, 9 `EventSample` (the perf record types) |
| `TraceObservationPoint`, `TraceReason`, `DropReason`, `DebugEventType`, `DebugCapturePoint`, `AgentEventType` | §4.3, §4.6, §4.8, §4.10 |

### 4.15 `observer.proto`, `peer.proto`, `relay.proto` (frozen)

```
service Observer {
  GetFlows(GetFlowsRequest)            returns (stream GetFlowsResponse)
  GetAgentEvents(GetAgentEventsRequest) returns (stream GetAgentEventsResponse)
  GetDebugEvents(GetDebugEventsRequest) returns (stream GetDebugEventsResponse)
  GetNodes(GetNodesRequest)            returns (GetNodesResponse)
  GetNamespaces(GetNamespacesRequest)  returns (GetNamespacesResponse)
  ServerStatus(ServerStatusRequest)    returns (ServerStatusResponse)
}

GetFlowsRequest  { number=1, follow=3, blacklist=5, whitelist=6, since=7,
                   until=8, first=9, field_mask=10, experimental=999,
                   extensions=150000 }   // field 2 reserved
GetFlowsResponse { oneof { flow=1, node_status=2, lost_events=3 },
                   node_name=1000, time=1001 }
GetAgentEventsRequest  { number=1, follow=2, since=7, until=8, first=9 }
GetAgentEventsResponse { agent_event=1, node_name=1000, time=1001 }
GetDebugEventsRequest  { number=1, follow=2, since=7, until=8, first=9 }
GetDebugEventsResponse { debug_event=1, node_name=1000, time=1001 }
GetNodesResponse { nodes=1 }
Node  { name=1, version=2, address=3, state=4, tls=5, uptime_ns=6,
        num_flows=7, max_flows=8, seen_flows=9 }
TLS   { enabled=1, server_name=2 }
GetNamespacesResponse { namespaces=1 }
Namespace { cluster=1, namespace=2 }
ServerStatusResponse { num_flows=1, max_flows=2, seen_flows=3, uptime_ns=4,
                       num_connected_nodes=5, num_unavailable_nodes=6,
                       unavailable_nodes=7, version=8, flows_rate=9 }
ExportEvent { oneof { flow=1, node_status=2, lost_events=3, agent_event=4,
                      debug_event=5 }, node_name=1000, time=1001 }

service Peer { Notify(NotifyRequest) returns (stream ChangeNotification) }
ChangeNotification { name=1, address=2, type=3, tls=4 }
ChangeNotificationType { 0 UNKNOWN, 1 PEER_ADDED, 2 PEER_DELETED, 3 PEER_UPDATED }
peer.TLS { server_name=1 }

NodeStatusEvent { state_change=1, node_names=2, message=3 }
NodeState { 0 UNKNOWN_NODE_STATE, 1 NODE_CONNECTED, 2 NODE_UNAVAILABLE,
            3 NODE_GONE, 4 NODE_ERROR }
```

Note `GetFlowsRequest.follow` is field **3** but `GetAgentEventsRequest.follow`
and `GetDebugEventsRequest.follow` are field **2**. This asymmetry is real and
MUST be preserved.

The gRPC health service (`grpc.health.v1.Health`) and server reflection MUST be
registered on every listener; `hubble status` and `grpcurl` depend on them. The
health service name for the observer is `hubble.server.Observer`.

### 4.16 Dynamic metrics YAML

```yaml
metrics:
  - name: drop                       # handler name; required, unique
    contextOptions:
      - name: sourceContext
        values: [pod, namespace]     # a list; "|" and "," are NOT re-split here
      - name: labelsContext
        values: [source_namespace, destination_namespace]
    includeFilters: [ <FlowFilter as protobuf JSON> ]
    excludeFilters: [ ... ]
```

Parsed as YAML→JSON, so nested `FlowFilter`s use protobuf JSON field names
(`source_pod`, `destination_pod`). Unlike the command-line form, `values` is
already a list and is not split further; a presence-only flag is expressed as
`values: [""]` or by omitting `values` entirely.

### 4.17 Dynamic flow-log YAML

Schema and semantics in §3.19.4.

