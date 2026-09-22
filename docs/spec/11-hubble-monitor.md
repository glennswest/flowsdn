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

- **The monitor pipeline** (§3.1–3.6): per-CPU perf ring consumption, lost-event
  accounting, wakeup policy, the agent-internal event bus, the `monitor1_2.sock`
  listener protocol with its exact gob wire bytes, listener queue sizing and
  drop policy, agent-event injection, and the aggregation levels.
- **Event decoding** (§3.7, §4.1–4.12): every notification type, every version
  length, field semantics, and the complete frozen numeric tables — message
  types, trace observation points, trace reasons with the encrypt mask, debug
  subtypes, capture points, drop reasons paired with their `flow.proto` names,
  source-file ids, policy match types, agent notification subtypes.
- **The Hubble flow parser** (§3.8–3.12.3): L2/L3/L4/L7 dissection, the six
  enrichment sources as one `FlowEnricher` trait, endpoint resolution and the
  identity-conflict rules, verdict and drop-reason mapping, direction and reply
  determination, and the `Flow` protobuf field by field (§4.13).
- **The ring buffer** (§3.13, §5.2): capacity as `2^n − 1`, cycle-based
  overwrite detection, reader positioning for `GetFlows`, slow-reader behavior.
- **The gRPC surface** (§3.14–3.17): `Observer` (six RPCs, `GetFlows` with all
  25 filter fields and their AND/OR composition), `Peer.Notify`, the relay's
  fan-out, and TLS/mTLS with server-name derivation.
- **Metrics** (§3.18, §8.1): all 11 handlers with names, labels, options, the
  context-option grammar, and the dynamic metrics YAML schema.
- **Export** (§3.19): path, rotation, compression, field masks, allow/deny
  lists, the dynamic flow-log schema, aggregation and redaction.
- Configuration (§6), failure modes (§7), tests (§9), kernel requirements
  (§10), Rust crate design (§11), open decisions (§12).

Out of scope (owned elsewhere):

- The `cilium_events` map, its sizing and pin path, and the datapath side of
  rate limiting: specs 01 and 02.
- The L7 access-log record itself — the L7 spec owns `LogRecord`; this spec
  owns only the `LogRecord → flow.Layer7` mapping.
- The pcap recorder (`pkg/recorder`, `api/v1/recorder`, the `Recorder`
  service). It is **gone from the reference at v1.20.1**; only the reserved
  slot `CILIUM_NOTIFY_CAPTURE = 6` remains. flowsdn MUST NOT implement it and
  MUST keep slot 6 reserved.
- The Hubble UI (consumed unchanged upstream; flowsdn implements the server
  side it talks to, via relay).
- The `hubble` CLI. flowsdn ships none; the upstream binary MUST work
  unmodified against flowsdn's Observer service — which is why `flow.proto` and
  `observer.proto` are frozen field-for-field.
- CEL filters — **deferred**, §12.5. The Kubernetes `PacketDrop` event emitter
  — **deferred**, alpha upstream; its flags are accepted and ignored (§6.5).

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
unavailable (§7).

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
   therefore never correlated. This also omits valid ICMP type 0, including
   IPv4 echo reply: it is a preserved reference correlation limitation, not
   an invalid-packet determination. Pinned `pkg/policy/correlation/correlation.go`
   at `7d68cfb394` checks zero at line 46 after mapping ICMP type to dport at
   lines 122–127 (inspected 2026-09-22). No deviation is adopted here.
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

**Realized-policy adapter contract (#23).** `flowsdn-hubble::correlation`
provides `PolicySnapshot::correlation_info(endpoint_id, Key) -> Option<PolicyMatch>`.
`Key` carries remote identity, host-order destination port (or ICMP type),
protocol and direction. The endpoint selects one immutable **realized** policy
snapshot before decoding; the result carries that snapshot's revision and all
matched `RuleOrigin` label sets/log strings (spec 06 §§4.3–4.4), not the current
repository head or pending desired revision. The policy owner performs the same
identity/protocol/port-prefix specificity and effective-entry lookup as its
realized map; Hubble must not substitute an exact-key-only lookup. An absent
endpoint, unavailable snapshot or lookup miss returns `None`, leaving correlation
fields absent. Logs are deduplicated; audit verdicts populate denied-by fields.
The pure trait and verdict projection are implemented and mock-tested. The
realized-policy adapter, rule-label-to-protobuf conversion and live correlation
remain required; no implemented endpoint currently claims populated policy fields.

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
decoded layer's description (§3.9) and MUST also be populated, because
`hubble observe -o compact` falls back to it (ADR-0012 #144). Lazy generation
or a bounded cache may reduce cost without changing output strings or field
presence.

### 3.13 The ring buffer

**Capacity.** `--hubble-event-buffer-capacity` MUST be one less than a power of
two and at most 65535 (`1, 3, 7, …, 4095, …, 65535`); default **4095**. The
validation is `n > 0 && n <= 65535 && (n & (n+1)) == 0`, and an invalid value
MUST be a startup error naming the accepted values. Derived quantities:

```
mask = n;  data_len = n + 1;  cycle_exp = log2(data_len)
cycle_mask = u64::MAX >> cycle_exp;  half_cycle = cycle_mask >> 1
cap  = data_len - 1   // == n; one slot is permanently unreadable
```

`len()` is `write` while `write < data_len`, then `cap()`.

**Writer** (single writer, many readers):

```
lock(notify);
write = write_counter.fetch_add(1) + 1;   // counter first
store((write - 1) & mask, entry);         // pointer second
close_and_replace(notify_ch);             // wake all followers
unlock(notify);
```

That ordering is why `last_write() = write - 1` but
`last_write_parallel() = write - 2` (the slot at `write-1` may be mid-store),
and `oldest_write() = if write > data_len { write - data_len } else { 0 }`.
An entry MUST never be null; null is the "never written" sentinel.

**Reader — overwrite detection (normative):**

```
read_idx = read & mask;  event = load(read_idx)
last_write = write_counter.load() - 1;  last_write_idx = last_write & mask
read_cycle = read >> cycle_exp;  write_cycle = last_write >> cycle_exp
prev_cycle = (write_cycle - 1) & cycle_mask
max_cycle  = (write_cycle + half_cycle) & cycle_mask

match {
  read_cycle == write_cycle && read_idx < last_write_idx =>
      if event.is_none() { Eof } else { Ok(event) },
  read_cycle == prev_cycle && read_idx > last_write_idx =>
      if event.is_none() { Ok(lost_event()) }   // ring not yet full: about to be overwritten
      else               { Ok(event) },
  read_cycle >= write_cycle && read_cycle < max_cycle => Eof,   // reader ahead
  _ => Ok(lost_event()),                                        // reader lapped
}
```

Three properties MUST be preserved:

1. The slot at `last_write_idx` is **never** readable (`<` and `>`, never `==`).
2. `half_cycle` is what distinguishes "reader ahead" from "reader lapped" in
   modular arithmetic; without it a wrapped counter silently mis-reads.
3. **Overwrite is signalled in band as a value, not as an error.** The only
   error `read` returns is end-of-stream. A lapped reader gets
   `Event{ timestamp: now, inner: LostEvent{ source: HUBBLE_RING_BUFFER,
   num_events_lost: 1, cpu: None } }` — count **1 per detection**, not the gap
   size — and `hubble_lost_events_total{source="hubble_ring_buffer"}` is
   incremented. `GetFlows` positioning and the flow-rate calculation both check
   for a lost event *before* checking for end-of-stream, so modelling overwrite
   as an error changes their behavior.

**Follow mode.** `read_from(read)` uses the same classification and sleeps on
the notify channel when it catches the writer. The sleep MUST be race-protected:
after deciding to sleep, re-read the write counter while holding the notify
lock and retry the same position if it changed. Missing this loses a wake-up
and stalls a follower until the next write.

**RingReader** holds a ring handle and an index: `next()` reads at `idx` and
advances only on success (so an at-EOF reader can be retried); `previous()`
reads and decrements; `next_follow()` lazily spawns a `read_from` task feeding
a channel of capacity **1000**.

**What a slow reader observes.** A reader more than `cap` events behind gets one
synthetic `LostEvent` per overwritten slot, interleaved in position order with
the events it can still read. It does **not** get an error and its stream does
not terminate. In `GetFlows` those per-slot events are coalesced (§3.14) into
one `LostEvent` per `--hubble-lost-event-send-interval` with a real count and a
first/last range.

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
| `source_ip`, `destination_ip`, `source_ip_xlated` | 1, 3, 34 | each entry is either a plain address or a CIDR. Both filter entries and flow addresses are parsed; exact addresses use numeric equality and CIDRs use same-family prefix containment. Non-canonical IPv6 spellings match. IPv4-mapped IPv6 remains IPv6, distinct from IPv4. This is the deliberate deviation in §12.8. |
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
subscribing synchronously replays all existing nodes into an unbuffered channel.

| Node event | Notifications |
|---|---|
| add | `PEER_ADDED` |
| delete | `PEER_DELETED` |
| update, same full name, same address | none |
| update, same full name, different address | `PEER_UPDATED` |
| update, different full name | `PEER_DELETED(old)` then `PEER_ADDED(new)` |

`name` is the cluster-qualified node name. `address` is `<node ip>:<hubble
port>`, family chosen by the preference order (`--prefer-ipv6` puts IPv6
first); the check is strict, so an IPv4-mapped IPv6 address is not accepted as
IPv6. An empty address is legal and means "no reachable address". `tls` is
present iff the Hubble server has TLS enabled and carries the derived server
name (§3.17.4).

**Backpressure.** Each stream buffers at most `max_send_buffer_size` (default
**65536**) notifications; on overflow the stream is **terminated** with "server
stream send was blocked for too long" rather than throttled or silently
dropping. A relay that cannot keep up reconnects and gets a full replay, which
is the correct recovery.

#### 3.17.2 Peer discovery and connection management (relay)

The relay consumes `Peer.Notify` from `--peer-service`. Three concurrent tasks:

1. **Notification watcher.** Any failure — building the client, opening the
   stream, or receiving — closes the client, marks the peer service
   disconnected, waits `--retry-timeout` (30 s) and retries. `PEER_ADDED` and
   `PEER_UPDATED` upsert; `PEER_DELETED` removes.
2. **Connection manager.** Connects a peer immediately on upsert (ignoring
   backoff) and re-checks every peer every `conn_check_interval` (**2 min**).
3. **Status reporter.** Every 5 s, tallies peers by connection state into
   `hubble_relay_pool_peer_connection_status{status}`.

Upsert MUST be a no-op when the peer is unchanged (name, TLS enabled, TLS
server name and address all equal) — otherwise every notification tears down a
working connection. Backoff is §5.5. Because gRPC channel creation is lazy, a
"successful" connect only means the channel was constructed; reachability is
judged from the channel state. A peer is **available** when it has a channel
whose state is neither transient-failure nor shutdown.

#### 3.17.3 `GetFlows` fan-out

```
peers → per-peer GetFlows streams → merged channel
      → error aggregation (10 s window) → sort buffer (min-heap, 1 s drain) → client
```

1. Before any flow, send a `NODE_CONNECTED` status naming the reached peers,
   then a `NODE_UNAVAILABLE` status naming the rest.
2. Open a `GetFlows` stream to every available peer with the **same** request;
   incoming gRPC metadata is forwarded.
3. In follow mode, re-scan the peer list every `peer_update_interval` (**2 s**)
   and join new peers. A connected-node set prevents duplicate dials; a peer
   whose stream errors is removed from the set so a later scan retries it, and
   an error status is pushed into the stream.
4. `EOF`, cancellation and gRPC `Canceled` from a peer are clean terminations.

**Sort buffer**: §5.4. This is why the agent's
`--hubble-lost-event-send-interval` also defaults to 1 s — the two windows are
meant to match.

**Error aggregation.** At most one `NODE_ERROR` is pending at a time. A new
error with an **identical message** merges its node names into the pending one;
a different message flushes the pending one immediately and starts a fresh
`error-aggregation-window` (**10 s**). The timer is armed once per pending
response and is not extended by merges. Non-error status events are forwarded
immediately; channel close flushes. The message is the error string, except
that a gRPC status with code `Unknown` is unwrapped to its message.

**`GetNodes`.** One `Node` per peer. Unavailable peers get `NODE_UNAVAILABLE`
and are not queried. Available peers get `NODE_CONNECTED` and are queried
concurrently for `ServerStatus` to fill `version`, `uptime_ns`, `max_flows`,
`num_flows`, `seen_flows`; a peer whose RPC fails is downgraded to `NODE_ERROR`
and **does not fail the call**.

**`ServerStatus` aggregation:**

| Field | Rule |
|---|---|
| `max_flows`, `num_flows`, `seen_flows`, `flows_rate` | summed |
| `uptime_ns` | the **maximum** (the oldest node) — deliberately not summed |
| `num_connected_nodes` | `peers − unavailable` |
| `num_unavailable_nodes` | never-connected peers **plus** peers whose status RPC failed |
| `unavailable_nodes` | the names, **capped at 10** |
| `version` | the relay version |

**`GetNamespaces`** queries every peer and returns the sorted, de-duplicated
union; partial results are returned on peer failure rather than failing.

**Metadata.** The relay attaches `hubble-relay-version` on outgoing calls and
forwards incoming metadata to peers.

**Health.** A separate gRPC health server on `:4222` reports `SERVING` for both
the empty service name and `hubble.server.Observer` iff the peer service is
connected **and** at least one peer is available; re-evaluated every 5 s,
starting as `NOT_SERVING`.

#### 3.17.4 TLS and server-name derivation

Minimum TLS version is **1.3** on the agent's TCP listener, the relay's server
listener and both client sides.

| Endpoint | Server cert | Client CA (⇒ mTLS) |
|---|---|---|
| agent unix socket | never TLS | — |
| agent TCP `:4244` | `--hubble-tls-cert-file` / `-key-file` unless `--hubble-disable-tls` | `--hubble-tls-client-ca-files` |
| agent metrics | `--hubble-metrics-server-tls-*` when `--hubble-metrics-server-enable-tls` | `--hubble-metrics-server-tls-client-ca-files` |
| relay server `:4245` | `--tls-relay-server-cert-file` / `-key-file` unless `--disable-server-tls` | `--tls-relay-client-ca-files` |
| relay → agent | client cert `--tls-hubble-client-cert-file` / `-key-file` unless `--disable-client-tls` | verifies against `--tls-hubble-server-ca-files` |

Presence of a client-CA list is what enables mTLS; there is no separate switch.

**Certificate reloading.** The TLS config MUST re-read the key pair and CA pool
**per handshake** so rotation needs no restart; the client side re-derives its
credentials per handshake for the same reason. At startup, when TLS is enabled
but the files do not yet exist, the server MUST wait (logging every 30 s)
rather than failing — this is what makes Helm's certificate-generating Job work
regardless of ordering.

**Server name per node:**

```
tls_server_name(node_name, cluster_name):
    if node_name.is_empty() { return "" }
    nn = node_name.replace('.', '-')
    cn = (if cluster_name.is_empty() { "default" } else { cluster_name }).replace('.', '-')
    format!("{nn}.{cn}.hubble-grpc.cilium.io")
```

Dots become hyphens so every node's server name sits at the same DNS domain
level (Kubernetes permits dots in node names), e.g.
`moseisley.tatooine.hubble-grpc.cilium.io`. The relay uses the same function
with the literal node name `hubble-peer` when its peer target is remote, so the
peer Service's certificate must be issued for
`hubble-peer.<cluster>.hubble-grpc.cilium.io`.

The domain `cilium.io` is retained because it is baked into issued certificates
and the Helm chart; changing it would break every existing deployment. This is
nominative use, consistent with `docs/licensing.md`.

The client-connection builder MUST reject the two inconsistent combinations up
front: a TLS config with no server name, and a server name with no TLS config.

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

---

## 5. Algorithms

### 5.1 The gob subset encoder

```
encode_uint(x):  if x <= 0x7F { [x as u8] }
                 else { let b = big_endian_trimmed(x);
                        [(0x100 - b.len()) as u8] ++ b }        // NOT LEB128
encode_int(i):   encode_uint(if i < 0 { ((!i) << 1) | 1 } else { i << 1 })
encode_bytes(s): encode_uint(s.len()) ++ s
encode_struct(fields):
    let mut last = -1i64;
    for (idx, v) in fields.non_zero() {                          // zero fields omitted
        encode_uint((idx - last) as u64); encode_value(v); last = idx;
    }
    encode_uint(0)
message(body):   encode_uint(body.len()) ++ body
```

The single type-definition message is the constant byte string in §3.5; no
general `wireType` encoder is needed. A gob *decoder* is only required if
flowsdn ever consumes a 1.2 stream (§12.1).

### 5.2 Ring cycle arithmetic

`cycle(pos) = pos >> cycle_exp`, `cycle_mask = u64::MAX >> cycle_exp`,
`half_cycle = cycle_mask >> 1`. `half_cycle` splits the modular cycle space so
that "reader ahead by less than half a cycle" (nothing to read) is
distinguishable from "reader lapped". Two implementations that both use the
§3.13 classification interoperate; one that compares raw positions without the
cycle projection does not.

### 5.3 Lost-event coalescing

An interval range counter holds `{count, first, last}`; it is elapsed when
`count > 0 && now - first >= interval`, so the window starts at the **first**
loss, not the last flush.

The observer-queue variant adds one rule: the counter is cleared **only if the
synthetic lost event was successfully enqueued**. If the queue is still full
the count keeps accumulating and is retried on every subsequent send. Clearing
unconditionally would lose the loss count exactly when loss is worst. The
"queue is full" warning fires only on the 0→1 transition, rate-limited to one
per 30 s.

### 5.4 Relay sort-merge

```
loop select {
  r = upstream.recv() => { if heap.len() == qlen { emit(heap.pop_min()) }   // evict oldest
                           heap.push(r) }
  _ = idle_for(drain_timeout) => { for r in heap.pop_all_older_than(now - drain_timeout) { emit(r) } }
  _ = cancelled() => return,
}
// upstream closed: drain the heap in timestamp order
```

`qlen = min(sort_buffer_max_len, number × peer_count)` when the product is
nonzero, else `sort_buffer_max_len`. The idle timer is re-armed each iteration,
so it measures inter-arrival idleness. The buffer never drops and never blocks;
under load it emits earlier than the full sort window, so ordering degrades
gracefully rather than the stream stalling.

### 5.5 Backoff

Peer reconnection: exponential, `min = 1 s`, `max = 1 min`, `factor = 2.0`,
jittered, counted per peer; the counter and next-attempt time reset on a
successful channel construction, and an explicit peer update bypasses the
backoff so a config change is not delayed by up to a minute. The relay's own
stream to the peer service uses a flat `--retry-timeout` (30 s) instead.

### 5.6 Config hashing and aggregation keys

Both dynamic watchers hash the **raw file bytes**, not the parsed structure, so
a comment-only edit counts as a change. Any 64-bit hash is acceptable; it is
exposed only as `hubble_dynamic_exporter_config_hash`.

The exporter's aggregation key MUST be a deterministic encoding of the masked
flow (§3.19.5), with the timestamp excluded.

---

## 6. Configuration

### 6.1 Monitor pipeline

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-monitor` | bool | `true` | serve `monitor1_2.sock` |
| `monitor-queue-size` | int | `0` → `min(possible_cpus × 1024, 16384)` | per-listener queue depth (§3.5) |
| `monitor-aggregation` (alias `monitor-aggregation-level`) | string | `none` | §3.6 |
| `monitor-aggregation-interval` | duration | `5s` | `CT_REPORT_INTERVAL` |
| `monitor-aggregation-flags` | string list | `syn,fin,rst` | TCP flags that always emit |
| `bpf-events-drop-enabled` | bool | `true` | emit drop notifications |
| `bpf-events-policy-verdict-enabled` | bool | `true` | emit policy verdict notifications |
| `bpf-events-trace-enabled` | bool | `true` | emit trace notifications |
| `bpf-events-default-rate-limit` | uint | `0` (off) | tokens/s in the events-map token bucket |
| `bpf-events-default-burst-limit` | uint | `0` (off) | bucket size |
| `trace-payloadlen` | int | `128` | captured bytes, native path |
| `trace-payloadlen-overlay` | int | `192` | captured bytes, VXLAN/Geneve-classified |

### 6.2 Hubble server

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-hubble` | bool | `false` | start the Hubble server (Helm sets `true`) |
| `hubble-socket-path` | string | `/var/run/cilium/hubble.sock` | unix listener, always plaintext |
| `hubble-listen-address` | string | `""` | additional TCP listener, e.g. `:4244` |
| `hubble-event-buffer-capacity` | int | `4095` | ring capacity; MUST be `2^n − 1 ≤ 65535` |
| `hubble-event-queue-size` | int | `0` → `min(num_cpus × 1024, 16384)` | monitor→observer channel |
| `hubble-monitor-events` | string list | `[]` (all) | subset of `drop debug capture trace l7 agent policy-verdict trace-sock` |
| `hubble-lost-event-send-interval` | duration | `1s` | lost-event coalescing window; MUST be `> 0` |
| `hubble-prefer-ipv6` | bool | `false` | **deprecated** → global `prefer-ipv6` (§6.5) |
| `hubble-disable-tls` | bool | `true` | run the TCP listener without TLS |
| `hubble-tls-cert-file` | string | `""` | server certificate |
| `hubble-tls-key-file` | string | `""` | server key |
| `hubble-tls-client-ca-files` | string list | `[]` | client CAs; non-empty ⇒ mTLS |

### 6.3 Parser

| Key | Type | Default | Effect |
|---|---|---|---|
| `hubble-skip-unknown-cgroup-ids` | bool | `true` | drop sock traces whose cgroup id has no pod |
| `hubble-network-policy-correlation-enabled` | bool | `true` | fill `*_allowed_by` / `*_denied_by` |
| `hubble-redact-enabled` | bool | `false` | enable header redaction |
| `hubble-redact-http-urlquery` | bool | `false` | clear URL query and fragment |
| `hubble-redact-http-userinfo` | bool | **`true`** | redact a URL password even when redaction is off |
| `hubble-redact-http-headers-allow` | string list | `[]` | headers kept; mutually exclusive with the deny list |
| `hubble-redact-http-headers-deny` | string list | `[]` | headers redacted |

### 6.4 Metrics and export

| Key | Type | Default | Effect |
|---|---|---|---|
| `hubble-metrics-server` | string | `""` | metrics listen address; **empty disables the whole subsystem** |
| `hubble-metrics` | string | `""` | whitespace-separated handler specs; exclusive with the dynamic path |
| `hubble-dynamic-metrics-config-path` | string | `""` | YAML polled every 10 s |
| `enable-hubble-open-metrics` | bool | `false` | OpenMetrics output; required for exemplars |
| `hubble-metrics-server-enable-tls` | bool | `false` | TLS on the metrics listener |
| `hubble-metrics-server-tls-cert-file` / `-key-file` | string | `""` | |
| `hubble-metrics-server-tls-client-ca-files` | string list | `[]` | non-empty ⇒ mTLS |
| `hubble-export-file-path` | string | `""` (stdout) | export target; `stdout` logs instead of writing a file |
| `hubble-export-file-max-size-mb` | int | `10` | rotation size |
| `hubble-export-file-max-backups` | int | `5` | rotated files kept |
| `hubble-export-file-compress` | bool | `false` | gzip rotated files |
| `hubble-export-allowlist` | string | `""` | whitespace-separated JSON `FlowFilter` objects |
| `hubble-export-denylist` | string | `""` | as above |
| `hubble-export-fieldmask` | string list | `[]` | flow paths to keep |
| `hubble-export-fieldaggregate` | string list | `[]` | flow paths to aggregate on |
| `hubble-export-aggregation-interval` | duration | `0s` (off) | aggregation flush interval |
| `hubble-flowlogs-config-path` | string | `""` | dynamic flow-log YAML, polled every 5 s |

### 6.5 Deprecated and unsupported inputs

| Key | Reason |
|---|---|
| `hubble-prefer-ipv6` | deprecated upstream in favour of the global `prefer-ipv6`; flowsdn accepts it and warns whenever explicitly supplied; explicit global `prefer-ipv6` wins even when false, otherwise this legacy value is used, otherwise false (§12.10) |
| `hubble-drop-events`, `hubble-drop-events-interval`, `hubble-drop-events-reasons`, `hubble-drop-events-extended`, `hubble-drop-events-rate-limit` | the Kubernetes `PacketDrop` event emitter is **deferred** (§1). Accepted and ignored so an existing ConfigMap loads; setting `hubble-drop-events=true` MUST log a warning that the feature is not implemented. Defaults are `false`, `2m`, `[auth_required, policy_denied]`, `false`, `1`. |
| `FlowFilter.experimental.cel_expression` | CEL is deferred; a request carrying it MUST be rejected with `InvalidArgument` naming the unsupported field rather than silently ignored (a silently-ignored filter returns *more* data than asked for, which is a disclosure risk) |

### 6.6 Relay flags

| Flag | Default |
|---|---|
| `--peer-service` | `unix:///var/run/cilium/hubble.sock` |
| `--listen-address` | `:4245` |
| `--health-listen-address` | `:4222` |
| `--metrics-listen-address` | `""` |
| `--cluster-name` | `default` |
| `--retry-timeout` | `30s` |
| `--sort-buffer-len-max` | `100` |
| `--sort-buffer-drain-timeout` | `1s` |
| `--tls-hubble-client-cert-file` / `--tls-hubble-client-key-file` | `""` |
| `--tls-hubble-server-ca-files` | `[]` |
| `--tls-relay-server-cert-file` / `--tls-relay-server-key-file` | `""` |
| `--tls-relay-client-ca-files` | `[]` |
| `--disable-client-tls` / `--disable-server-tls` | `false` |
| `--log-format`, `--log-level` | `""` |

Deprecated aliases `--tls-client-cert-file`, `--tls-client-key-file`,
`--tls-server-cert-file`, `--tls-server-key-file` MUST be accepted with a
warning. `--pprof*` and `--gops*` are **not** implemented
(**DEVIATION**, ADR-0004: diagnostics are `tracing` and `tokio-console`); they
are accepted and ignored.

Internal constants that are not flags: `error-aggregation-window` 10 s,
`peer-update-interval` 2 s, `conn-check-interval` 2 min, `conn-status-interval`
5 s, backoff 1 s..1 min ×2, health-check interval 5 s, unavailable-node report
cap 10.

---

## 7. Failure modes

| Failure | Detection | Behavior |
|---|---|---|
| **Perf ring overrun** (datapath outruns the reader) | `PERF_RECORD_LOST` | `MonitorStatus.lost` increases; a `LostEvent{source: PERF_EVENT_RING_BUFFER, num_events_lost: n, cpu}` is delivered to consumers and a `RecordLost` payload to listeners; `hubble_lost_events_total{source="perf_event_ring_buffer"}` increases. Flows are **lost, not delayed**. Operator remedies, in order: raise `monitor-aggregation`, enable `bpf-events-default-rate-limit`, disable event classes with `bpf-events-*-enabled`, provision CPU. |
| **Observer queue full** (parser outruns by the decode task) | non-blocking send fails | coalesced `LostEvent{source: OBSERVER_EVENTS_QUEUE}` with `{count, first, last}`; `hubble_lost_events_total{source="observer_events_queue"}`; a rate-limited warning naming `hubble-event-queue-size`. The count is retried until it can be enqueued (§5.3). |
| **Ring overwritten under a slow reader** | cycle check (§3.13) | that reader receives a synthetic `LostEvent{source: HUBBLE_RING_BUFFER}` per lapped slot, coalesced per `hubble-lost-event-send-interval` into one response with a real count; the stream continues. Other readers are unaffected. Remedy: raise `hubble-event-buffer-capacity`, or narrow the client's filters. |
| **Monitor listener too slow** | full per-listener queue | that listener's message is dropped, logged at debug. Other listeners, consumers and the reader are unaffected. There is no per-listener loss counter — **DEVIATION**: flowsdn adds `flowsdn_monitor_listener_dropped_total` (§8.2), because silent per-listener loss is undiagnosable. |
| **Listener disconnects mid-write** | write error / EOF | the listener is removed and its queue closed; if it was the last subscriber the perf reader stops. |
| **Malformed or truncated perf sample** | length or version check | counted, logged at debug, dropped. MUST NOT panic and MUST NOT abort the reader. |
| **Unknown message type / unknown version** | dispatch or version check | `ErrInvalidType` — counted and skipped silently (these are expected during a rolling upgrade where the datapath is newer than the agent). |
| **Parser missing an enrichment source** | getter returns `None` | the field is left unset and the flow is still emitted. A missing endpoint yields an endpoint with only an identity; a missing identity yields empty labels; a missing link name yields an interface with only an index. The parser MUST NOT drop a flow because enrichment failed. The single exception is a sock trace with an unresolvable cgroup id when `hubble-skip-unknown-cgroup-ids` is true, which is skipped by design. |
| **Identity disagreement between datapath and userspace** | §3.11 | the datapath identity wins; a rate-limited debug log fires unless the disagreement matches one of the six known-legitimate patterns. |
| **Policy correlation lookup misses** | endpoint or policy-map miss | the `*_allowed_by` / `*_denied_by` fields are left empty; the flow is still emitted. |
| **Field mask with an invalid path** | validation | the whole `GetFlows` request is rejected with `InvalidArgument`. |
| **Filter build error** (bad glob, bad port, bad status prefix) | validation | the request is rejected before any event is sent, with a message naming the field. |
| **Export file cannot be written** | writer error | logged; the exporter keeps running and retries on the next event. An aggregation flush that fails still clears its map, losing one interval rather than growing without bound. |
| **Dynamic config file unreadable or invalid** | poll | logged, the reconfiguration-failure counter increments, the **previous configuration keeps running**. |
| **Dynamic metrics config changes a label set** | validation | the whole config is rejected with an explicit message; label sets cannot change without a restart. |
| **Relay peer down** | channel state / stream error | the peer is reported `NODE_UNAVAILABLE` (never connected) or `NODE_ERROR` (stream failed) in the response stream itself, not as an RPC error. `GetFlows` continues with the remaining peers. Reconnection is exponential (§5.5); in follow mode the peer rejoins within `peer-update-interval`. |
| **Relay peer service down** | stream error | the relay retries every 30 s; the health service reports `NOT_SERVING`; existing per-peer connections keep working until they fail on their own. |
| **Relay slow client** | sort buffer full | the oldest buffered response is emitted early; ordering degrades, nothing is dropped or blocked. |
| **Peer stream send buffer overflow** | 65536 pending notifications | the `Peer.Notify` stream is terminated; the client reconnects and gets a full replay. |
| **TLS certificate files absent at startup** | file check | the server waits, logging every 30 s, rather than failing — the Helm certificate Job may run after the agent starts. |
| **TLS certificate rotated** | per-handshake reload | new connections use the new material with no restart; existing connections are unaffected. |
| **Agent restart** | — | the ring buffer, all in-flight streams, and the namespace tracker are **lost**; the perf map is not disturbed (it is opened, not created), so the datapath keeps running and no packet is affected. Clients reconnect and start from the new empty ring. There is no persistence and none is planned (§12.11). |
| **Upgrade with a notification layout change** | version byte | a newer datapath emitting version *n+1* is rejected by an older agent (counted as an unknown version); a newer agent reading version *n* accepts it and leaves the new tail fields zero. The upgrade order is therefore agent-first, and the datapath's version bump is the second step. |

---

## 8. Observability

### 8.1 Metrics (reference-compatible; Grafana dashboards depend on these)

All handler metrics live in the `hubble` namespace. **Label order is not
uniform** — two families exist and both MUST be reproduced, because a
Prometheus `*Vec` is positional:

- **context-first**: `drop`, `dns`, `http`, `httpV2` — context labels precede
  the fixed labels.
- **fixed-first**: `flow`, `flows-to-world`, `icmp`, `policy`,
  `port-distribution`, `sctp`, `tcp` — the fixed labels precede the context
  labels.

`CTX` below stands for the context labels produced by the handler's context
options (§8.1.2).

| Handler | Metric | Type | Labels (in order) | Gate |
|---|---|---|---|---|
| `drop` | `hubble_drop_total` | counter | `CTX…, reason, protocol` | `verdict == DROPPED` |
| `flow` | `hubble_flows_processed_total` | counter | `protocol, type, subtype, verdict, CTX…` | all flows |
| `flows-to-world` | `hubble_flows_to_world_total` | counter | `protocol, verdict, [port,] CTX…` | destination has a `reserved:world*` label, `event_type` and `l4` present; non-dropped replies skipped |
| `dns` | `hubble_dns_queries_total` | counter | `CTX…, rcode, qtypes, ips_returned, [query]` | L7 DNS |
| `dns` | `hubble_dns_responses_total` | counter | `CTX…, rcode, qtypes, ips_returned, [query]` | L7 DNS |
| `dns` | `hubble_dns_response_types_total` | counter | `CTX…, type, qtypes, [query]` | one increment per RR type |
| `http` *(deprecated)* | `hubble_http_requests_total` | counter | `CTX…, method, protocol, reporter` | L7 HTTP request or response |
| `http` | `hubble_http_responses_total` | counter | `CTX…, method, protocol, status, reporter` | |
| `http` | `hubble_http_request_duration_seconds` | histogram | `CTX…, method, reporter` | observed on responses only |
| `httpV2` | `hubble_http_requests_total` | counter | `CTX…, method, protocol, status, reporter` | **responses only** |
| `httpV2` | `hubble_http_request_duration_seconds` | histogram | `CTX…, method, reporter` | |
| `icmp` | `hubble_icmp_total` | counter | `family, type, CTX…` | ICMPv4/v6 |
| `policy` | `hubble_policy_verdicts_total` | counter | `direction, match, action, CTX…` | policy verdict (skipping host-source) and L7 |
| `port-distribution` | `hubble_port_distribution_total` | counter | `protocol, port, CTX…` | verdict `FORWARDED`/`REDIRECTED`, `l4` present, **not** a reply |
| `sctp` | `hubble_sctp_chunk_types_total` | counter | `chunk_type, family, CTX…` | verdict `FORWARDED`/`REDIRECTED`, SCTP with a known chunk type |
| `tcp` | `hubble_tcp_flags_total` | counter | `flag, family, CTX…` | verdict `FORWARDED`/`REDIRECTED`, TCP with flags |

Histogram buckets are the Prometheus defaults
(`.005 .01 .025 .05 .1 .25 .5 1 2.5 5 10`).

There is **no `kafka` handler**; the reference removed it and flowsdn MUST NOT
add one.

Label value derivations that matter:

| Label | Value |
|---|---|
| `drop.reason` | `drop_reason_desc` enum name |
| `flow.type` / `flow.subtype` | `L7`+`DNS`/`HTTP`; `Drop`+`""`; `Capture`+`""`; `Trace`+the observation-point string; `PolicyVerdict`+`""`; otherwise `Unknown`+the decimal event type |
| `verdict`, `action` | `Verdict` enum name (`action` lowercased) |
| `protocol` | the flow's L4/L7 protocol name |
| `family` | `IPv4` / `IPv6` |
| `tcp.flag` | one increment per set flag: `FIN`; `SYN-ACK` if both SYN and ACK else `SYN`; `RST`. ACK, PSH and URG alone are **not** counted. |
| `icmp.type` | the ICMP type/code rendered as a name |
| `policy.direction` | lowercased traffic direction |
| `policy.match` | lowercased policy match-type string for L3/L4; `l7/dns` or `l7/http` for L7 |
| `port-distribution.port` | destination port for TCP/UDP/SCTP; `0` for ICMP/VRRP/IGMP |
| `dns.rcode` | `Policy denied` when dropped; empty for requests; the DNS rcode name for responses (0–11, 16–23); empty for an unmapped code |
| `dns.qtypes` | the query types joined with `,` |
| `dns.ips_returned` | the answer count as a decimal |
| `http.reporter` | `client` for egress, `server` for ingress, `unknown` otherwise |
| `http.status` | the decimal status code |

`httpV2` uses source/destination **inverted** relative to `http`, so that
response-derived series carry the request's perspective. Label *names* do not
change.

Handler options:

| Handler | Option | Default | Effect |
|---|---|---|---|
| `flows-to-world` | `any-drop` | off | count all drops, not only `POLICY_DENIED` |
| `flows-to-world` | `port` | off | add the `port` label |
| `flows-to-world` | `syn-only` | off | count only non-reply TCP SYNs |
| `dns` | `query` | off | add the `query` label (**high cardinality**) |
| `dns` | `ignoreAAAA` | off | skip queries whose only qtype is `AAAA` |
| `http`, `httpV2` | `exemplars=true` | off | attach `traceID` exemplars; requires OpenMetrics |

`exemplars` is the only option that requires an explicit value; every other
option is enabled by presence alone.

Pipeline metrics, not handler metrics:

| Metric | Type | Labels |
|---|---|---|
| `hubble_lost_events_total` | counter | `source` ∈ `perf_event_ring_buffer`, `observer_events_queue`, `hubble_ring_buffer` |
| `hubble_metrics_http_handler_requests_total` | counter | `code` |
| `hubble_metrics_http_handler_request_duration_seconds` | histogram | `code` |
| `hubble_dynamic_exporter_exporters_total` | gauge | `status` ∈ `active`, `inactive` |
| `hubble_dynamic_exporter_up` | gauge | `name` |
| `hubble_dynamic_exporter_reconfigurations_total` | counter | `op` |
| `hubble_dynamic_exporter_config_hash` | gauge | — |
| `hubble_dynamic_exporter_config_last_applied` | gauge | — |
| `hubble_relay_pool_peer_connection_status` | gauge | `status` ∈ `IDLE`, `CONNECTING`, `READY`, `TRANSIENT_FAILURE`, `SHUTDOWN`, `NIL_CONNECTION` — all six MUST be emitted, zero-initialised |

gRPC server metrics (`grpc_server_started_total`, `grpc_server_handled_total`,
`grpc_server_msg_received_total`, `grpc_server_msg_sent_total`, and
`grpc_server_handling_seconds` under OpenMetrics) MUST be registered on both
the agent's Hubble server and the relay.

#### 8.1.1 Metric spec grammar

```
--hubble-metrics "name[:opt[=v[|v]…][;opt…]] name2 …"
```

Whitespace separates specs; the **first** colon separates the handler name from
its options; `;` separates options; the first `=` separates an option name from
its values; values split on `|`, except `labelsContext` which splits on `,`.

#### 8.1.2 Context options

| Option | Meaning |
|---|---|
| `sourceContext`, `destinationContext` | how to label the two endpoints |
| `sourceIngressContext`, `sourceEgressContext` | direction-specific overrides for the source |
| `destinationIngressContext`, `destinationEgressContext` | direction-specific overrides for the destination |
| `labelsContext` | a fixed set of extra labels |

Option names are matched case-insensitively; an unrecognised option name is
silently ignored, which is how handler-specific options coexist in the same
list.

Context identifiers (`|`-separated; the **first non-empty value wins**, and all
empty yields `""`):

| Identifier | Value |
|---|---|
| `identity` | the endpoint's labels joined with `,` |
| `namespace` | the namespace |
| `pod` | `<namespace>/<pod>`, or just the pod when there is no namespace |
| `pod-name` | the pod name alone |
| `dns` | `source_names` / `destination_names` joined with `,` |
| `ip` | `IP.source` / `IP.destination` |
| `reserved-identity` | `reserved:kube-apiserver` if present, else the first `reserved:` label, else empty |
| `workload` | `<namespace>/<workload name>` |
| `workload-name` | the workload name alone |
| `app` | the first of `k8s:app.kubernetes.io/name`, `k8s:k8s-app`, `k8s:app` |

An unknown identifier is a startup error.

`labelsContext` accepts exactly, and emits in exactly this order:
`source_ip`, `source_pod`, `source_namespace`, `source_workload`,
`source_workload_kind`, `source_app`, `destination_ip`, `destination_pod`,
`destination_namespace`, `destination_workload`, `destination_workload_kind`,
`destination_app`, `traffic_direction`. Any other value is a startup error.
Duplicates collapse and user ordering is ignored. `traffic_direction` renders
as the lowercased direction, or the literal `unknown`.

Emitted label names, in order: every enabled `labelsContext` label in the fixed
order above, then `source` (only if any of the three source lists is
non-empty), then `destination` (likewise). Per flow, a direction-specific list
is used when it is configured and the flow's direction matches; otherwise the
plain list.

### 8.2 flowsdn-only metrics

**DEVIATION** — additions, no removals:

| Metric | Type | Labels | Why |
|---|---|---|---|
| `flowsdn_monitor_listener_dropped_total` | counter | `listener` | per-listener queue drops are otherwise invisible (§7) |
| `flowsdn_monitor_decode_errors_total` | counter | `kind` ∈ `short`, `bad_version`, `unknown_type` | decode failures are otherwise only a debug log |
| `flowsdn_hubble_enrichment_misses_total` | counter | `source` ∈ `endpoint`, `identity`, `ipcache`, `service`, `dns`, `link`, `cgroup` | distinguishes "no data" from "wrong data" (§7) |

### 8.3 Logs

| Event | Level | Fields |
|---|---|---|
| perf reader started / stopped | info | start time |
| unknown perf record | debug | (counted in `MonitorStatus.unknown`) |
| listener registered / removed | debug | listener count, protocol version |
| per-listener queue full | debug | listener id |
| observer queue full | warn, rate-limited 1/30 s, only on the 0→1 transition | names `hubble-event-queue-size`, references `hubble_lost_events_total` |
| stale identity observed | debug, rate-limited 1/30 s | ip, datapath identity, userspace identity, observation point |
| decode error | debug | event type, length, version |
| dynamic config reload | info on change, warn on failure | file path, hash |
| peer connect / disconnect / backoff | info / debug | peer name, address, next attempt |
| waiting for TLS material | info, every 30 s | file paths |

### 8.4 Status exposure

`MonitorStatus` (§3.2) is reported in the agent status API and rendered by
`cilium status`. The effective monitor aggregation level MUST be reported
alongside it, because it explains a low event rate.

The Hubble subsystem reports into the agent health registry (ADR-0004): the
observer's ring occupancy and `seen_flows`, the metrics server's listen state,
each exporter's active/inactive state, and the number of connected monitor
listeners.

---

## 9. Test plan

Derived from the reference's test names. `[u]` unit, `[p]` privileged (kernel +
loaded datapath), `[e]` end-to-end.

### 9.1 Wire-format golden tests `[u]`

These make the compatibility claims real; each needs a captured artefact from a
running reference deployment under `tests/golden/`.

- [ ] The gob type-definition message is byte-identical to the 57-byte string
      in §3.5; the three value messages in §3.5 match byte for byte.
- [ ] A captured `cilium-dbg monitor` byte stream is reproduced exactly from
      the same payload sequence.
- [ ] The real upstream `cilium-dbg monitor` attaches to a flowsdn
      `monitor1_2.sock` and renders drop, trace, policy-verdict, debug,
      debug-capture, trace-sock, agent and l7 events plus a lost record.
- [ ] One exported line per event kind is byte-identical to a captured
      reference export line (protojson, proto names, enum names, RFC3339
      timestamps, uint64 as strings).
- [ ] Upstream `hubble observe -o json`, `-o jsonpb` and `-o compact` produce
      identical output against flowsdn and the reference for the same fixtures.

### 9.2 Decoders `[u]` (from `pkg/monitor/datapath_*_test.go`)

- [ ] `drop_notify` v0–v3 from byte fixtures; `data_offset` per version;
      version 4 rejected; truncated input rejected without panic.
- [ ] `trace_notify` v0–v2; version 3 rejected; `orig_ip` v4 and v6;
      `is_encrypted`; the flag bits; `reason_is_known`/`is_reply`/`is_encap`/
      `is_decap`; the reason→proto conversion for all of 0..8.
- [ ] `policy_verdict_notify`: four verdict classes, seven match types, both
      directions, the audited and L3-device bits, three auth types.
- [ ] `debug_msg` and `debug_capture_msg`; every subtype renders a message;
      `DBG_SKIP_POLICY = 66`, `DBG_LB6_LOOPBACK_SNAT = 67`, `…_REV = 68` (§2.4).
- [ ] `trace_sock_notify`: both families, all five xlate points.
- [ ] `ext_version != 0` rejected for every capture-header type.
- [ ] A table test asserting the datapath constants, the userspace enums and
      `flow.proto` agree on every numeric table (§2.3, §11.6).

### 9.3 Monitor agent `[u]` + `[p]`

- [ ] `[u]` `send_event` delivers identical bytes to every listener; removing
      one listener does not affect others; registering on a stopped agent
      closes immediately; a full queue drops for that listener only.
- [ ] `[p]` the perf reader starts on the first subscriber and stops on the
      last; with no subscriber, samples are not read.
- [ ] `[p]` `PERF_RECORD_LOST` bumps `MonitorStatus.lost` and yields both a
      consumer notification and a `RecordLost` payload.
- [ ] `[p]` `MonitorStatus` reports possible CPUs, 64 pages, the real page size.
- [ ] `[u]` aggregation-level parsing: every string, integers 0..4, rejection
      outside the range, the alias key.

### 9.4 Packet dissection `[u]` (from `dissect_test.go`)

- [ ] Every layer in §3.9; L3-device entry for both families; SCTP chunk type
      including the empty payload; the TCP flag order and `Summary` string.
- [ ] VXLAN and Geneve: `tunnel` carries the outer headers and VNI, `IP`/`l4`
      the inner ones, outer values cleared.
- [ ] A truncated overlay capture: `tunnel` set, inner headers absent, no error.
- [ ] A UDP packet on the tunnel port the classifier did **not** flag is not
      parsed as overlay.
- [ ] Empty payload ⇒ no error. Fuzzing over random payloads never panics.

### 9.5 Flow parser `[u]` (from `parser/threefour`, `seven`, `sock`, `agent`, `debug`)

- [ ] Full flows for drop, trace, policy verdict and debug capture.
- [ ] Traffic direction for every branch of §3.12 (drop with/without a matching
      source endpoint; trace across every combination of `is_source_ep`,
      `is_reply`, `is_snated`; trace with `source == 0`; unknown reason; both
      policy-verdict directions; debug capture).
- [ ] `is_reply` for every case in the §3.12 table, including the SRv6 `None`.
- [ ] `source_xlated` set from `orig_ip` on SNAT, unset when they are equal.
- [ ] Each of the six identity-conflict cases suppresses the log and keeps the
      datapath identity.
- [ ] CIDR label filtering: longest prefix wins, `/0` dropped, IPv6 `-`→`:`,
      unparsable dropped, output sorted.
- [ ] Crossed DNS-name resolution; `proxy_port` from `TO_PROXY` and the proxy
      capture subtypes; `interface` from `tn.ifindex` and the six capture
      subtypes but **not** from `dn.ifindex`; `ip_trace_id` absent when zero.
- [ ] Local vs remote endpoint construction (remote has no `ID`, no workloads).
- [ ] Policy correlation: allowed/denied/audited × ingress/egress; the ICMP
      `dport = type` rule; VRRP/IGMP and L3-only skipped; `policy_log` always
      set; the flag disabling it yields empty policy fields.
- [ ] L7: DNS request/response, HTTP request/response, header sorting, invalid
      and nil URLs; latency from the request/response pair with cache miss ⇒ 0,
      negative clamped, `SAMPLE` ⇒ 0; traceparent extraction and its cache;
      redaction of URL query, URL password **with redaction disabled**, allow
      list, deny list, neither list (redact everything); both lists ⇒ startup
      error; `Summary` for each of the six cases.
- [ ] Sock: each xlate point including the reverse-path swap; unknown cgroup id
      skipped when the flag is true and emitted with an empty source when false.
- [ ] Agent: every subtype maps to the right oneof; a type/payload mismatch
      falls through to `AGENT_EVENT_UNKNOWN` carrying the JSON.
- [ ] Debug: CPU, resolved source endpoint and message present.

### 9.6 Ring buffer `[u]` (from `pkg/hubble/container`)

- [ ] `NewCapacity` accepts every `2^n − 1` up to 65535 and nothing else;
      `cap() == n`, `data_len == n + 1`.
- [ ] Write/read at, before and after the wrap point; `LastWrite`,
      `LastWriteParallel`, `OldestWrite` on empty, partial and wrapped rings.
- [ ] A lapped reader gets a `LostEvent` and **no error**; the slot at
      `last_write_idx` is never returned; `previous()` at the boundary.
- [ ] `read_from` wake-ups: a write between the "should I sleep" check and the
      sleep does not lose the wake-up (race detector / loom).
- [ ] Concurrent writer with many readers: no torn reads, prefix-consistent
      sequences.

### 9.7 Observer `[u]`

- [ ] `first && follow` ⇒ `InvalidArgument`.
- [ ] Positioning: `first`; `follow` with no number and no since; `number`;
      `since`; `since` **and** `number` (since wins); `number` larger than the
      ring; an empty ring. `until` terminates but does not position.
- [ ] Lost events do not count toward `number` and bypass filters and the time
      range; coalescing produces the right count and first/last.
- [ ] Field mask: valid paths, one invalid path rejecting the whole request,
      normalization, and the oneof rule (masking `l4.TCP` on a UDP flow does
      not materialize an empty `TCP`).
- [ ] `ServerStatus` fields including `flows_rate` with a full, partial
      (shrinking denominator) and empty ring.
- [ ] `GetNamespaces` sorting, de-duplication, TTL expiry; `GetNodes` returns
      `Unimplemented`; hook ordering and each hook's stop semantics;
      `GetAgentEvents`/`GetDebugEvents` positioning and the absence of filters.

### 9.8 Filters `[u]` (from `pkg/hubble/filters`, 5.5k reference lines)

One test per field, plus:

- [ ] AND across fields, OR within a field, OR across the whitelist, NOR across
      the blacklist, and the empty-list identities.
- [ ] `ns/name` parsing for `xwing`, `kube-system/`, `/xwing`, `a/b/c`, `""`.
- [ ] Glob compilation: `*`, literal dots, trailing-dot stripping, invalid
      runes, empty pattern, double trailing dot. Node-name patterns with 0, 1
      and 2 slashes, plus local-cluster qualification at match time.
- [ ] Label-selector translation (`k8s:foo`→`k8s.foo`, bare→`any.`) and the
      full selector grammar.
- [ ] Ports exact only (a range or non-numeric is a build error; ICMP never
      matches). HTTP status prefixes `404`, `4+`, `40+` accepted; `6+`, `x`,
      `4++` rejected. TCP-flag subset semantics including an all-false entry.
- [ ] `event_type` with `type == 0`, with and without `match_sub_type`; a lost
      event always matches. `reply` unknown-on-dropped treated as false.
- [ ] IP filters: parsed address equivalence and CIDR containment, both families;
      alternate IPv6 spelling, host bits in prefixes, /0 and full-width masks,
      family isolation and invalid input rejection.
- [ ] HTTP filters rejected when the event-type filter excludes L7.
- [ ] A benchmark asserting the filter path stays within budget at aggregation
      level `none`.

### 9.9 Metrics `[u]`

- [ ] Every handler's label set **and order**, in both families.
- [ ] Every handler option, including presence-without-value and the
      `exemplars=true` exception.
- [ ] `http` + `httpV2` ⇒ hard error; an unknown handler name ⇒ skipped with a
      log; static + dynamic config ⇒ startup error.
- [ ] Context-option parsing: every identifier, the `|` first-non-empty rule,
      the direction-specific overrides, `labelsContext` fixed ordering and its
      rejection of unknown values.
- [ ] Dynamic reload: add, remove, filter-only update, a `contextOptions`
      change rejected, an invalid file leaving the running config in place, an
      `http`→`httpV2` swap in one reload.
- [ ] Pod-deletion cleanup for all four conditions and the negative cases
      (`pod-name`, `workload`, a single `labelsContext` label) — **and on the
      dynamic path** (the §3.18 DEVIATION).

### 9.10 Exporter `[u]`

- [ ] Rotation by size, backup count, compression; the `stdout` target.
- [ ] Allow/deny parsing of concatenated JSON objects; field mask applied.
- [ ] Aggregation: key computation, per-direction counts, interval flush, final
      flush on shutdown, a zero interval warning with raw export, non-flow
      events bypassing aggregation.
- [ ] Dynamic reload: add, remove, change, invalid file; the `end` time making
      an exporter a silent no-op while keeping its gauge at 0; duplicate `name`
      and duplicate `filePath` rejected.

### 9.11 Relay and peer service `[u]`

- [ ] Peer manager: connect, backoff progression, reconnect, an unchanged
      upsert not tearing down the connection, the status tally.
- [ ] `sortFlows` ordering, eviction when full, drain timeout, final drain;
      queue sizing `min(100, number × peers)`.
- [ ] Error aggregation: identical messages merged, a different message
      flushing, the 10 s window, flush on close.
- [ ] `GetNodes` merge across connected/unavailable/erroring peers;
      `ServerStatus` math including `uptime_ns` as a maximum and the 10-node
      cap; `GetAgentEvents`/`GetDebugEvents` ⇒ `Unimplemented`.
- [ ] Follow mode joins a peer that appears mid-stream within 2 s; health is
      `SERVING` only with a connected peer service and ≥ 1 available peer.
- [ ] Peer: add/update/delete translation including rename ⇒ delete+add and
      same-address update ⇒ nothing; address-family preference both ways
      including the IPv4-mapped-IPv6 rejection; `tls_server_name` with dots in
      the node name, dots in the cluster name, an empty cluster, an empty node;
      send-buffer overflow terminates the stream; subscription happens after
      the streaming task starts (no deadlock on the initial replay).

### 9.12 TLS `[u]` + `[e]`

- [ ] mTLS enabled by the presence of a client CA list, on all four listeners;
      minimum TLS 1.3 enforced.
- [ ] Certificate rotation takes effect on the next handshake without restart;
      startup waits for absent certificate files instead of failing.
- [ ] A TLS config without a server name, and a server name without a TLS
      config, are both rejected.

### 9.13 End-to-end `[e]` (from `test/k8s/hubble.go` and the connectivity suites)

- [ ] An L3/L4 flow between two pods is visible via `hubble observe` on the
      node, and through hubble-relay from outside it.
- [ ] An L7 (HTTP and DNS) flow is visible through relay; an FQDN-policy flow
      shows `source_names`/`destination_names`.
- [ ] A policy-denied flow shows `DROPPED`, `POLICY_DENIED` and a populated
      `ingress_denied_by`.
- [ ] The Hubble TLS certificate is served and validated.
- [ ] The upstream Hubble UI renders flows, the service map and the namespace
      list against a flowsdn relay.
- [ ] Every connectivity-test assertion that reads Hubble flows passes
      unchanged.
- [ ] A rolling upgrade with the datapath one notification version ahead of the
      agent produces "unknown version" counts and no crash.

---

## 10. Kernel and platform requirements

This area is almost entirely userspace. Its kernel surface is:

| Requirement | Used for |
|---|---|
| `perf_event_open` per CPU with `PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_BPF_OUTPUT` | the monitor rings |
| `mmap` of `(64 + 1) × page_size` per CPU | the ring buffers |
| `PERF_RECORD_SAMPLE` and `PERF_RECORD_LOST` | events and loss accounting |
| `epoll` over the per-CPU event fds | multiplexed reading |
| `bpf(BPF_OBJ_GET)` on the pinned `cilium_events` map | attaching without creating |
| `AF_UNIX` `SOCK_STREAM` + `fchown`/`fchmod` | the two unix sockets |

No feature here raises the minimum kernel beyond what
`docs/kernel-requirements.md` already sets for the datapath. `ENODEV` from
`perf_event_open` on an offline CPU MUST be tolerated: that CPU is skipped and
the reader continues.

**Endianness.** All notification decoding is native-endian, because the
datapath and the reader are the same host. Decoders MUST use native-endian
reads explicitly rather than assuming little-endian, so the arm64 build is
correct by construction rather than by accident. The bitfield byte in
`policy_verdict_notify` is LSB-first on both x86-64 and arm64 with the
toolchains in use; §9.2 includes a fixture that pins this on both
architectures.

**Alignment.** The notification structs are `#[repr(C)]` and naturally aligned
on both architectures. Decoders MUST NOT transmute a perf sample slice directly
into a struct reference — samples are only 8-byte aligned at the ring level and
may carry up to 7 bytes of trailing padding — but MUST copy through a
`FromBytes`-style checked conversion.

x86-64 and arm64 are both first-class (ADR-0001). Nothing in this area is
architecture-specific beyond the two points above.

---

## 11. Rust design notes

### 11.1 Crates

| Crate | Contents | Approx. size |
|---|---|---|
| `flowsdn-monitor` | perf reader, the event bus, the gob subset encoder, the `monitor1_2.sock` server, all notification decoders, the text formatter | 3.5k |
| `flowsdn-hubble` | the parsers, `FlowEnricher`, the ring buffer, the observer service, filters, field masks, metrics handlers, the exporter, the peer service, the gRPC server assembly and TLS | 11k |
| `flowsdn-hubble-relay` | the relay binary: peer pool, fan-out, sort-merge, error aggregation, health | 2.5k |
| `flowsdn-proto` (shared) | generated `flow`, `observer`, `peer`, `relay` types plus the protojson layer | generated |

`flowsdn-monitor` MUST NOT depend on `flowsdn-hubble`: `cilium-dbg monitor`
support has to work in a build with Hubble disabled. The numeric tables live in
`flowsdn-bpf-abi` (§11.6) and both depend on it. The initial drop-decoder
helper resides in `flowsdn-hubble`; move the reusable codec into the ABI/monitor
layer when the monitor crate is introduced, without reversing this dependency.

### 11.2 Protobuf and gRPC

- `prost` + `tonic`, generated with `tonic-build` from the four unmodified
  `.proto` files. Field numbers come from the files, so they cannot drift.
- Well-known types (`Any`, `Timestamp`, `BoolValue`, `UInt32Value`,
  `Int32Value`, `FieldMask`) via `prost-types`.
- **protojson fidelity** is required for the exporter and for
  `hubble observe -o jsonpb` compatibility (§3.19.2). `prost` has no protojson,
  so generate a `pbjson` layer with `pbjson-build`, configured to emit
  **original proto field names** rather than lowerCamelCase, and pin it with
  the golden-line test in §9.1. If `pbjson` cannot be configured for proto
  names, hand-write the serializer for `ExportEvent` and its transitive types;
  it is mechanical and the golden test bounds the risk.
- **Field masks** need per-field reflection, which `prost` does not provide.
  Two options: generate a path→setter match arm table from the descriptor set
  at build time (preferred — it is total and fast), or restrict masks to a
  fixed known path set. The build-time table also gives the oneof rule for free
  because the descriptor knows the containing oneof.
- Listeners: `tonic` over a `tokio::net::UnixListener` stream for the unix
  socket, plus an optional TCP listener. TLS via `tonic`'s `rustls` feature,
  with a certificate resolver that re-reads the material per handshake
  (`rustls::server::ResolvesServerCert`) so §3.17.4 rotation works.
- gRPC reflection via `tonic-reflection`; health via `tonic-health`.

### 11.3 Perf ring

`aya`'s `PerfEventArray` gives per-CPU `PerfEventArrayBuffer`s. Open the pinned
map (`Map::from_pin`), take one buffer per possible CPU, register their fds
with a `tokio` `AsyncFd` each, and read on readiness. Do not use a blocking
poll loop: one task per CPU with `AsyncFd` keeps the reader inside the runtime
and lets the shutdown path be a plain `select!`.

Decoding is `#[repr(C)]` structs plus `zerocopy` (`FromBytes` + a checked
`read_from_prefix`), one struct per version with the shorter versions as
prefixes. Version dispatch is a `match` on the version byte returning the
struct length; the tail fields are filled from the longer variant.

### 11.4 Ring buffer

`Box<[ArcSwapOption<Event>]>` indexed by `write & mask`, with an `AtomicU64`
write counter and a `tokio::sync::Notify` (or a watch channel) for followers.
The cycle arithmetic in §5.2 transfers verbatim. `Arc<Flow>` sharing means many
`GetFlows` streams read without copying; only the field-mask path allocates,
into the stream's own reusable message.

The reference's `atomic.StorePointer` maps to `ArcSwapOption::store`; the
counter-before-store ordering and `last_write_parallel() = write − 2` MUST be
kept, and the store MUST be `Release` with the load `Acquire`.

### 11.5 The gob subset encoder

A few hundred lines: `encode_uint`, `encode_int`, `encode_bytes`, a
`Payload`-specific `encode_struct`, and one `const TYPE_DEF: [u8; 57]`. Per
connection, hold a `sent_type_def: bool`. No general gob machinery is needed
and none should be written — the surface is exactly one struct type.

### 11.6 Shared numeric tables

**Resolved ownership (#22): `flowsdn-bpf-abi`** owns the Rust source tables
shared by both BPF and userspace; no C header generator is introduced under
ADR-0002. The ABI crate declares message
types, trace observation points, trace reasons, drop reasons with their
`flow.proto` names and their human strings, debug subtypes, capture points and
source-file ids. It generates:

1. the constants the BPF programs use,
2. the Rust enums the decoder uses,
3. parity tests against the pinned `flow.proto` enum names and numbers.
   These must compare independent reference data, not two views of the Rust
   table. Complete enum generation and protobuf parity coverage remain
   implementation obligations; assigning ownership does not claim completion.

This is what makes §2.3 enforceable rather than aspirational, and it is where
the `DBG_SKIP_POLICY` fix (§2.4) lives.

### 11.7 Packet dissection

`etherparse` covers Ethernet, VLAN, IPv4/IPv6 with extension headers, TCP, UDP,
ICMPv4 and ICMPv6. Hand parsers are needed for:

| Protocol | What is needed |
|---|---|
| SCTP | the 12-byte common header plus the first chunk's type byte |
| VRRPv2 | version/type byte, VRID, priority |
| IGMPv1/v2 | type byte, group address |
| VXLAN | the 8-byte header, VNI from bytes 4..7 |
| Geneve | the 8-byte base header, variable-length options, VNI |

About 800 lines total. The overlay path re-runs the same stack on the inner
payload.

The decoder is a trait object (§3.9) so it can be swapped in tests and so the
dissection cost can be measured in isolation. Unlike the reference, which keeps
one mutex-guarded reusable decoder with shared layer structs, flowsdn SHOULD
make the decoder stateless and return an owned result — the reference's shared
state is the reason it needs a mutex on the hot path, and it is the same lock
that limits throughput at aggregation level `none`.

### 11.8 Filters

25 builders producing `Box<dyn Fn(&Event) -> bool + Send + Sync>`. Compile
globs and label selectors **once at build time**, not per event. The three-level
composition is three small combinators (§3.16). Glob patterns compile to a
single anchored `regex` alternation; label selectors need a small selector
parser (`k8s-openapi`'s is not usable standalone, so this is ~200 lines).

CEL expressions are rejected before stream creation with `InvalidArgument`
(§12.5). No interpreter or optional executable feature is currently included.

### 11.9 Enrichment

`FlowEnricher` (§3.10) is implemented over the agent's `flowsdn-table` handles
(ADR-0004). Every lookup MUST be a snapshot read, not a lock acquisition:
`flowsdn-table`'s persistent-map snapshots make this natural, and it removes
the reference's central bottleneck. The decode task takes one snapshot set per
event batch rather than per lookup.

### 11.10 Metrics

The `prometheus` crate's `IntCounterVec` / `HistogramVec`, with label names
computed from the context options **before** registration — a `*Vec` is
positional and its cardinality is fixed at construction, which is also why
§3.18 forbids changing a label set on reload. Eleven handlers, roughly 1.5k
lines. Dynamic reload is a 10 s poll with a byte hash and
unregister/re-register.

### 11.11 Exporter

`serde_json` lines over the `pbjson` `ExportEvent`. Rotation is a small
size-based writer (open, count bytes, rename to `<base>-<timestamp><ext>`,
gzip when configured, prune to `max_backups`); no maintained crate matches the
reference's naming, and naming only matters to log shippers, so the semantics
of `fileMaxSizeMb` / `fileMaxBackups` / `fileCompress` are what must match.
Aggregation is a `HashMap<Vec<u8>, AggregateValue>` flushed on an interval,
about 200 lines.

### 11.12 Relay

One `tonic` client per peer, `tokio::select!` fan-in into an `mpsc`, a
`BinaryHeap` with a `Reverse` wrapper for the sort buffer, and `tokio::time`
for the drain and aggregation windows. Backoff via a small explicit
implementation rather than a crate — the parameters are three constants and the
per-peer attempt counter has to be reset on success, which most crates do not
expose cleanly.

### 11.13 Concurrency shape

```
task: perf reader (one per CPU)  ──▶ broadcast to subscribers (ArcSwap list)
task: listener writer (one per connection, owns a bounded mpsc)
task: hubble decode (single)     ──▶ ring write
task per GetFlows stream         ──▶ RingReader + filters + field mask
task: metrics poll (10 s), exporter poll (5 s), namespace sweep (5 min)
```

The decode task is single-threaded by design: it owns the enrichment snapshots
and the hook chain, and the reference's ordering guarantees depend on it. If it
becomes the bottleneck, the fix is a sharded decode with a re-ordering write
into the ring, which is §12.3, not a lock.

---

### 11.14 Implemented primitive boundary

`flowsdn-hubble` currently provides parsed IP predicates and filter-list algebra,
CEL rejection, address preference resolution, checked drop-header decoding,
emitter constants, a realized-policy correlation trait/projection, and a bounded
**single-owner synchronous ring model**. Its `&mut self` writer makes ownership
explicit; it is not the concurrent Observer service or lock-free fan-out. The
model reserves the newest slot, uses wrapping sequence distances with cursors
less than half the u64 space apart, and reports one loss per overwritten cursor
position. It retains at most capacity+1 event references; readers may retain
their own `Arc`s. Payload sizes must be bounded by the ingestion adapter.
Production cycle equivalence, async wakeup races, cancellation, protobufs,
perf ingestion, enrichment, metrics, exporters and the gRPC/monitor servers
remain unimplemented. No runtime throughput or loss benchmark is claimed.

## 12. Decision register (resolved and open)

**12.1 Resolved #141: Observer-based flowsdn monitor client.** Keep the
`monitor1_2.sock` server and its bounded gob subset encoder for existing
`cilium-dbg monitor`. The future `flowsdn-dbg monitor` command uses Observer
RPCs; do not implement a gob decoder. Server encoder, gRPC adapter and command
remain runtime work; this fixes the compatibility surface and client design.

**12.2 Perf reader wakeup policy (#142 remains open).** Preserve the 1-byte
watermark and no `wakeup_events` override initially. The primitive constant
records this default; it is not a perf reader. No throughput/follow-latency
benchmark has been run, so the issue's measurement gate is unmet. A batching
change requires measured latency and loss results before adoption.

**12.3 Decode-task scaling (#143 remains open).** Initial implementation must
use one decode task with snapshot enrichment and one ring writer. Sharding, if
needed, must sequence results before that writer. The production task and CI
throughput/latency benchmark gate are not implemented; synchronous ring unit
tests do not satisfy this acceptance.

**12.4. Flow Summary compatibility — resolved #144.** Populate deprecated `Summary` for
both L3/L4 and L7 flows using the existing layer-derived strings. Lazy generation or a
bounded cache may optimize cost but must not change field presence or text.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

**12.5 Resolved #145: reject CEL expressions.** Any nonempty expression
list, including an empty expression string, fails filter construction with
`InvalidArgument` naming `experimental.cel_expression`. An absent or empty
list adds no predicate. Never silently ignore an expression. The validation
primitive and rejection tests exist; request parsing and gRPC status mapping
remain adapter obligations. An interpreter requires a separate later change.

**12.6. Drop reason names — resolved #146.** Keep numeric values, protobuf enum names,
and monitor display strings separately as specified. In particular 136 retains
`CT_MISSING_TCP_ACK_FLAG` with monitor text `Fragmentation needed`; 161 retains
`FAILED_TO_INSERT_INTO_PROXYMAP` with `NAT 46/64 not enabled`.
   See [ADR-0012](../decisions/0012-control-plane-issue-resolutions.md).

**12.7 Resolved #147: preserve reference drop-interface omission.** Decode
`drop_notify.ifindex` for raw monitor consumers, but keep `Flow.interface`
absent for drops, including nonzero ifindex. The v0–v3 checked decoder and
projection helper enforce this behavior. This chooses option (a); no claim is
made about Hubble UI accepting a newly populated drop interface. A future
deviation needs the issue's UI compatibility check before adoption.

**12.8 Resolved #148: numeric IP equality, deliberate deviation.** Parse
plain addresses on both sides just as CIDRs are parsed; match alternate IPv6
spellings numerically. Invalid filter addresses fail construction; invalid or
absent flow addresses do not match. Preserve IPv4/IPv6 family separation, even
for IPv4-mapped IPv6, and mask host bits when testing prefix membership. Scoped
IPv6 literals are rejected: packet flow addresses have no zone identifier.

Pinned-CLI review (Cilium v1.20.1 `7d68cfb394`, inspected 2026-09-22):
`hubble/cmd/observe/flows_filter.go:416–435` passes `from-ip`, `to-ip`, `ip`
and `snat-ip` values into protobuf fields without textual matching in the
online path. No online CLI protocol requires textual identity. The old CLI's
**offline** input reader (`io_reader_observer.go:90–99,222`) invokes the
reference filter library itself, whose `pkg/hubble/filters/ip.go:32–79` uses
string equality for plain IPs. Consequently an old CLI filtering an exported
file retains its old non-canonical-address mismatch; changing the server does
not change offline CLI code. This limitation is explicit rather than a claim
of identical offline filtering. The new Rust predicate tests numeric equality,
prefix boundaries and allow/deny semantics; live Observer integration is pending.

**12.9 Exporter `node_name` inconsistency.** §3.19.2 proposes always using the
cluster-qualified name where the reference mixes qualified and bare. Options:
(a) match exactly; (b) always qualified. **Recommend (b)** as a DEVIATION,
confirmed against a real log-shipper pipeline in e2e.

**12.10 Resolved #150: explicit global preference wins.** Accept both
`prefer-ipv6` and deprecated `hubble-prefer-ipv6`; warn whenever the latter is
explicitly supplied. If global preference was explicitly set, it wins, including
`false`; otherwise use an explicitly supplied legacy value, then default false.
Resolve ordinary source precedence for each key first, then this cross-key
precedence. Preserve configuration provenance until resolution. The pure
resolver covers all nine absent/false/true combinations. Registry/runtime wiring
and warning emission remain configuration-adapter obligations.

**12.11 Resolved #151: memory-only ring, exporter for retained history.**
Restart creates an empty ring, resets its sequence space and invalidates every
old stream/cursor. Do not add mmap persistence or reuse cursors across instances.
Use `hubble-export-file-path` for history outside the agent lifetime; production
retention requires an implemented exporter and persistent storage, neither
provided by the ring primitive. Export is not a lossless crash journal: events
not yet exported, failed writes and volatile filesystem buffers can still be
lost. Ring unit tests cover bounded retention, per-position in-band loss, newest
slot reservation, sequence wrap and construction of a fresh empty instance.

**12.12 Resolved #152: packaging owns certificate issuance.** Spec 22 #239
keeps Helm default, cert-manager/user Secrets and digest-pinned upstream certgen
for CronJob mode. Every issuer preserves §3.17.4 names and authentication.
The planning helper does not generate certificates or render the chart.

**12.13 Kubernetes `PacketDrop` event emitter.** Deferred (§1) — alpha
upstream, ~500 lines, needs a k8s event recorder plus dedupe and rate limiting.
Options: (a) never; (b) after the k8s client crate lands; (c) replace with a
Prometheus alert on `hubble_drop_total`. **Recommend (b)**, low priority.

**12.14 Resolved #154: identify the producer as flowsdn.** Set
`emitter.name = "flowsdn"` and version to the flowsdn package version. Do not
add an override or impersonate the compatibility target. Shared constants and
a version test establish the source of truth; protobuf dispatcher integration
remains required. Reconsider an override only for a demonstrated consumer need.
