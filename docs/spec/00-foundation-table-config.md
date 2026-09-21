# Foundation: table store, configuration registry, fences and health — specification

Status: draft. Derived from: `docs/inventory/06-agent-endpoint-api.md` (startup
order, flag table, config-dir loading, runtime-config file), `04-loadbalancer.md`
(how the LB reconciler consumes tables), `03-datapath-userspace-node.md`
(device/route/node-address tables), `08-operator.md` (operator flags and shared
ConfigMap keys); reference cilium v1.20.1 (7d68cfb394) paths `pkg/hive/**`,
`pkg/hive/health/**`, `pkg/option/**` (incl. `resolver/`), `pkg/dynamicconfig/**`,
`pkg/dynamiclifecycle/cell.go`, `pkg/driftchecker/`, `pkg/datapath/tables/**`,
`daemon/cmd/daemon_main.go` (`daemonConfigInitialization`),
`cilium-dbg/cmd/build-config.go`, `vendor/github.com/cilium/statedb/{README.md,
doc.go,types.go,write_txn.go,graveyard.go,deletetracker.go,http.go}`,
`vendor/github.com/cilium/statedb/reconciler/{types,config,reconciler,incremental,retries}.go`,
`vendor/github.com/cilium/hive/{hive.go,cell/config.go,cell/health.go}`.
Governed by ADR-0001..0004; this spec implements ADR-0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes *what*
flowsdn does and the exact data it exchanges. It does not transcribe reference
code. Where the reference behavior is kept for compatibility, the consumer that
depends on it is named (cilium-dbg, Helm, operator, kubelet). Where flowsdn
deviates, the paragraph is marked **DEVIATION** with the reason and the ADR.

## 1. Scope

Three foundation pieces that every other flowsdn crate builds on. None of them is
externally visible on the wire except through the configuration keys (Helm
ConfigMap contract) and the status API (module health).

- **(A) `flowsdn-table`** — the in-memory table store that replaces StateDB:
  tables with a primary key, secondary indexes, per-table revisions, snapshot
  reads, change streams with tombstones, and one generic reconciler helper.
  Consumers at this tag: load balancer (services/frontends/backends, LRP,
  skip-LB), datapath (devices, routes, neighbors, node addresses, sysctl, L2
  announce entries, bandwidth qdiscs, desired routes/devices), dynamic config,
  module health, ipcache/identity mirrors (specified in their own specs).
- **(B) `flowsdn-config`** — the configuration registry that replaces Hive's
  per-cell flag registration and viper: sources, precedence, normalization,
  typed kinds, validation, immutability, the runtime-config file, dynamic keys,
  unknown-key handling, and the complete key table (section 6.4).
- **(C) `flowsdn-fence`** (fences) and `flowsdn-health` (module health
  registry) — startup ordering without a DI container, and the per-module
  health model that `GET /healthz` and `cilium-dbg status` read.

Out of scope here: the agent REST API routes themselves (spec "Agent REST API,
health, status"), the endpoint state machine (spec "Agent core"), per-area table
schemas beyond the examples used to pin semantics, the operator's own flag
table (spec "Operator"; the registry mechanism is the same), and Helm value →
key mapping (spec "Helm values mapping").

## 2. Compatibility contract

| Interface | MUST match | Consumer |
|---|---|---|
| Config key names (539 in section 6.4) | byte-identical, dash-separated lower case | Helm `cilium-config` ConfigMap, `cilium-dbg build-config`, CiliumNodeConfig CRs, operator reading agent keys |
| Config-dir layout | one file per key, file name = key, content = value, trailing whitespace trimmed; symlinked `..data` directory layout as written by `build-config` | Helm mounts ConfigMap at `/tmp/cilium/config-map`; init container writes resolved dir |
| Environment variables | `CILIUM_` + key upper-cased with `-` → `_` | Helm templates (`CILIUM_K8S_NAMESPACE`, `CILIUM_CLUSTERMESH_CONFIG`, …), users |
| `--config` YAML file | keys as above, optional; default search `$HOME/ciliumd.yaml` | operators, tests |
| Node annotation overrides | prefix `config.cilium.io/<key>=<value>` on Node labels and annotations | `build-config` source `node:` |
| CiliumNodeConfig | `cilium.io/v2` `spec.defaults{}` + `spec.nodeSelector`, lexicographic name priority | `build-config` source `cilium-node-config:` |
| `config-sources` / `config-sources-overrides` | JSON as emitted by `build-config` (section 6.2) | dynamic config reflector, drift checker |
| `<state-dir>/agent-runtime-config.json` (+`-1`, `-2` rotation) | file names and rotation; content is flowsdn's own schema (section 6.6) | bugtool (`cp -r state`), humans |
| Runtime options (`PATCH /config`, `PATCH /endpoint/{id}/config`) | option names `Debug`, `DebugLB`, `DebugPolicy`, `DebugTagged`, `DropNotification`, `TraceNotification`, `TraceSockNotification`, `PolicyVerdictNotification`, `PolicyAuditMode`, `MonitorAggregationLevel`, `SourceIPVerification`, `PolicyTracing`; values `enable`/`disable`/integer for aggregation | `cilium-dbg config`, `cilium-dbg endpoint config` |
| Module health rows | fields `ID`, `Level` (`OK`/`Degraded`/`Stopped`), `Message`, `Error`, `LastOK`, `Updated`, `Stopped`, `Final`, `Count`; ID string `<module>.<component...>` | `cilium-dbg status` (reads table `health` via `/statedb/query`, see 8.4), `cilium_hive_status` metrics |
| Metrics | `cilium_hive_status{level}`, `cilium_hive_degraded_status{module}`, controller/reconciler metrics named in section 8 | dashboards |

Everything else in this spec is internal. In particular **there is no
`cilium/statedb` wire, HTTP or Go-API compatibility** (ADR-0004).

## 3. Behavior

### 3.1 Table store (A)

A **table** holds immutable rows of one type `T`. Each row has exactly one
**primary key** (bytes, derived from the row by a caller-supplied function) and
zero or more **secondary index** keys per index. Tables are independent: there
are no cross-table transactions (3.1.8).

#### 3.1.1 Write operations

| Operation | Precondition | Effect | Result |
|---|---|---|---|
| `insert(row)` | none | if a row with the same primary key exists it is replaced (upsert), else added; table revision `+1`; row stamped with the new revision; all secondary indexes updated | previous row (if any) and new revision |
| `insert_if_revision(row, expected)` | existing row's revision `== expected` | as `insert` | `Err(RevisionMismatch{current})` without changing the table otherwise |
| `modify(key, f)` | none | `f(Option<&T>) -> Option<T>` applied under the table write lock; `Some` → upsert, `None` when row exists → delete, `None` when absent → no-op | as above |
| `delete(key)` | none | removes the row; table revision `+1`; a **tombstone** `{key, revision}` is recorded for change streams (3.1.5) | removed row (if any) |
| `delete_if_revision(key, expected)` | as `insert_if_revision` | as `delete` | as above |
| `delete_all()` | none | one tombstone per row, one revision increment per row | count |
| `batch(|w| …)` | none | several operations under one write lock; readers observe either none or all of them (single-table atomicity) | — |

Rows MUST be treated as immutable once inserted: `T: Clone` and the store hands
out shared references (`Arc<T>` or by-value clones). A writer that wants to
change a row clones it, edits the clone, and re-inserts. There is no in-place
mutation API. (The reference detects re-insertion of the same pointer at
runtime; Rust ownership makes the check unnecessary.)

Every write MUST update the primary index and every secondary index before the
write is published; a reader MUST never observe a row present in one index and
absent in another.

#### 3.1.2 Indexes

- One primary index per table: **unique**, key = bytes. Ordering is bytewise
  lexicographic on the key.
- Any number of secondary indexes, each declared **unique** or **non-unique**,
  each producing zero or more keys per row (multi-key indexes are allowed, e.g.
  "all labels of a row").
- A non-unique index stores `secondary_key ++ 0x00 ++ primary_key` so that
  `list(secondary_key)` is a prefix scan and iteration order within one
  secondary key is primary-key order.
- Inserting a row whose unique-secondary key collides with a *different*
  primary key MUST fail with `Err(UniqueViolation{index, key})` and leave the
  table unchanged.
- Key encodings MUST be order-preserving where callers rely on `lower_bound`/
  `prefix`: big-endian fixed-width integers, IPv4 mapped into 16-byte IPv6
  form (as `netip.Addr.As16()` in the reference) so v4 and v6 sort within one
  index, strings as UTF-8 bytes, composite keys as concatenation of fixed-width
  parts with a `0x00` separator after variable-width parts.

#### 3.1.3 Read operations

All reads operate on a **snapshot**: a snapshot is taken in O(1) and is
unaffected by later writes. Reads never block writers and writers never block
readers; at most one writer per table at a time.

| Read | Semantics |
|---|---|
| `get(index, key) -> Option<(Arc<T>, Revision)>` | unique index lookup |
| `list(index, key) -> impl Iterator` | all rows with that secondary key (non-unique index) |
| `prefix(index, key_prefix)` | rows whose index key starts with the prefix, key order |
| `lower_bound(index, key)` | rows with index key `>= key`, key order |
| `all()` | all rows in primary-key order |
| `by_revision(from)` | rows with revision `>= from` in revision order (the revision index) |
| `len()`, `revision()` | row count and current table revision of the snapshot |

Iteration order guarantees: `all`, `prefix`, `lower_bound` and `list` return rows
in ascending key order of the index queried; `by_revision` in ascending
revision order. Two iterations of the same snapshot return the same sequence.

#### 3.1.4 Revisions

- Each table has a `u64` revision starting at `0` for an empty table.
- Every successful `insert`/`delete` increments it by exactly one and stamps the
  row (or tombstone) with the new value. A failed conditional write does not
  consume a revision.
- Revisions are per table and are **not** persisted; every process start begins
  at `0`. Nothing in flowsdn may compare revisions across tables or across
  restarts.
- A row's revision is the revision of the write that last set it; the table
  keeps a **revision index** (revision → row) so `by_revision(from)` is a range
  scan, not a full scan.

#### 3.1.5 Change streams (`watch`)

`watch(from_revision) -> ChangeStream<T>` returns an async stream of
`Change { row: Arc<T> | Tombstone{key}, revision }` for every write with
`revision > from_revision`, in revision order, including deletions as
tombstones. Rules:

- **Coalescing.** If the same primary key is written several times before the
  consumer catches up, the stream MAY deliver only the latest state (with the
  latest revision) — consumers MUST be written as "reconcile the current
  row", not as event replay. The reference gives the same guarantee (a change
  iterator yields each object at most once per `Next` call).
- **Tombstone retention.** A tombstone MUST be retained until every open
  `ChangeStream` on the table has acknowledged a revision `>=` the tombstone's
  revision; `ChangeStream::ack(revision)` (or dropping the stream) advances the
  per-stream low-water mark. Tombstones below the minimum low-water mark are
  garbage-collected by the table (rate-limited, at most once per second per
  table). A re-insert of the same key drops its pending tombstone (the newer
  insert supersedes the delete).
- **Bounded catch-up.** A stream created with `from_revision` lower than the
  oldest retained tombstone MUST yield `Change::Resync` first and then the full
  current table as inserts; consumers MUST treat `Resync` as "compare desired
  vs. realized and prune". This is the only situation in which a deletion can
  be missed.
- **Initial population.** `watch(0)` yields every current row as an insert
  before any live change.
- **Wakeups.** A stream that is drained blocks until the next write to the
  table. Implementations SHOULD wake a stream only on writes to the table it
  watches (per-table notifier); finer-grained (per-key) watches are NOT
  required (**DEVIATION** from StateDB's per-radix-node watch channels — the
  consumers listed in section 1 all watch whole tables or resync anyway;
  ADR-0004).

`get_watch(index, key) -> (Option<(Arc<T>,Revision)>, WatchHandle)` MAY be
provided for single-row waiters (e.g. `WatchKey` in dynamic config) and MUST at
minimum wake when the table changes.

#### 3.1.6 Initialization ("initializers")

A table has a set of named **initializers**. A data source that populates the
table registers one at construction and marks it complete after its first full
sync, after publishing its initial rows. Registration starts open and the owner
MUST call `seal_initializers()` once all sources have registered, including when
there are no sources. `table.initialized()` is true only after sealing and
completion of all registered sources; `wait_initialized()` awaits that monotonic
condition. Late, duplicate and blank registrations fail. Dropping a source
handle does not mark success; completion is idempotent. Reconcilers MUST NOT prune before `initialized()` is true. This is
the `RegisterInitializer`/`Initialized` contract the LB reconciler relies on
(inventory 04: restore-from-maps then wait `lb-init-wait-timeout` for all
initializers before the first reconcile; prune only after init).

#### 3.1.7 Memory bounds

- Rows: unbounded by the store; owners size their tables (the LB tables are
  bounded by cluster size, BPF-mirror tables by map size).
- Tombstones: bounded by the slowest change-stream consumer; a stream that has
  not acknowledged for longer than `table.tombstone_max_age` (default 10 min)
  or whose backlog exceeds `table.tombstone_max_count` (default 65 536) is
  **force-resynced**: its low-water mark is advanced, tombstones are dropped and
  the stream receives `Resync`. Both are compile-time defaults overridable per
  table at construction, not config keys.
- Snapshots: a held snapshot keeps its version of the persistent maps alive;
  cost is O(changes since the snapshot). Holding a snapshot across an `await`
  point is allowed and expected (reconcilers do it).
- Metrics `flowsdn_table_objects{table}`, `flowsdn_table_tombstones{table}`,
  `flowsdn_table_revision{table}`, `flowsdn_table_resync_total{table,stream}`
  expose these bounds (section 8).

#### 3.1.8 Deliberately not provided (ADR-0004)

| StateDB feature | flowsdn | Reason |
|---|---|---|
| Cross-table write transactions (`WriteTxn(tableA, tableB)`) | not provided; the LB `Writer` holds one `Mutex` around its three tables and performs the writes in a fixed order (services → frontends → backends) so readers see at most a transient extra/missing frontend, which the reconciler tolerates | ADR-0004 §2; the only multi-table writer in the reference is the LB writer |
| Transaction `Abort()` | not provided; `batch()` cannot roll back; callers validate before writing | same |
| HTTP dump/query (`/statedb/dump`, `/statedb/query`, `/statedb/changes`) | not provided, except the single `health` table read-only compatibility route in 8.4 | ADR-0004 consequences |
| Query language / `FromString` on indexes, `db/show`, `db/cmp` script commands | not provided; tests use typed Rust assertions and golden JSON dumps | ADR-0004 |
| Hive shell (`shell.sock`) and script commands | not provided | ADR-0004 |
| Per-node radix-tree watch channels | whole-table notifier (3.1.5) | simplicity; consumers do not need finer granularity |
| `Modify` with merge function across pointer identity checks | `modify(key, f)` closure | Rust ownership |
| Table metrics via hive `statedb_metrics.go` (`cilium_statedb_*`) | replaced by `flowsdn_table_*` (section 8) | not a compatibility surface |

### 3.2 Reconciler helper (A)

`Reconciler<T>` turns a table of *desired* rows into operations on a *target*
(BPF map, netlink object, file). It is one async task per reconciler.

Inputs: the table, a `Target` implementation (`update(&T) -> Result`,
`delete(&T::Key) -> Result`, `prune(all desired rows) -> Result`, optional
`update_batch`/`delete_batch`), a `Status` accessor pair (3.2.2), and options
(3.2.4).

#### 3.2.1 Loop

```
state: stream = table.watch(0); retries = RetryQueue; last_prune = never
loop:
  wait for: stream has changes | retries.next_due | prune tick | explicit prune | shutdown
  snapshot = table.snapshot()
  round = []                                  # bounded by round_size
  for change in stream.drain(up to round_size):
      if change is Tombstone   -> delete(key); on Err -> retries.push(key, delete=true)
      elif status(row) in {Pending, Refreshing} -> update(row); record result
      else skip (already Done/Error from an earlier round, nothing new)
  for item in retries.due(now) while round < round_size:
      re-run its operation with the *current* row from snapshot (skip if the row changed
      revision since the failure — the change stream will deliver it)
  commit statuses (3.2.2) in one table batch
  if table.initialized() and (prune due or explicit): prune(snapshot.all())
  health: OK("N object(s)") if retries empty else Degraded("N error(s)", joined errors)
```

- Rounds are bounded by `round_size` (default 1000) so status commits and
  health updates are not starved by a large burst. Between rounds the loop
  waits on the rate limiter (default 1000 rounds/s → effectively unbounded).
- Operations MUST be idempotent: the same row may be updated again after a
  retry, a refresh, a resync or a restart.
- `update` receives a clone of the row and MAY annotate it (e.g. allocated IDs);
  the annotation is written back together with the status in the same commit
  (this is how the LB reconciler stores `Frontend.ID` and NodePort expansions).

#### 3.2.2 Per-row status without polluting the row

Status is stored **beside** the row, not inside it, in a companion table
`<name>-status` keyed by the same primary key, so the *desired* row written by
data sources contains only desired state and a row is never re-marked Pending
because a reconciler wrote its status.

```
ReconcileStatus {
  kind:        Pending | Refreshing | Done | Error      (u8)
  id:          u64      # monotonically increasing token assigned when a row becomes Pending
  updated_at:  Instant/SystemTime
  error:       Option<String>
  retries:     u32      # consecutive failures, reset on success
  next_retry:  Option<SystemTime>
}
```

Rules:

- A write to the desired table sets the status to `Pending` with a fresh `id`
  (the store does this in the same batch via a registered hook; a data source
  never touches the status table).
- After `update` the reconciler writes `Done` or `Error{error}` **only if** the
  status still has the same `id` it read before the operation. If the desired
  row changed meanwhile (new `id`), the result is discarded and the new
  revision is processed on the next round. This is the reference's
  `CompareAndSwap`-on-revision then "same pending ID" fallback, expressed on the
  status table.
- `Refreshing` is `Pending` with a hint that the target should force a rewrite
  even if it believes the row is unchanged (used by periodic refresh, 3.2.4).
- Multiple reconcilers on one table each own their own status table
  (`<table>-status-<reconciler>`); a row is "fully reconciled" when all are
  `Done`. The REST/API layer that reports per-object status (e.g. `GET
  /service` `status.realized`) reads the status table(s), never the row.
- `wait_until_reconciled(revision)` returns when every row with revision `<=
  revision` has been attempted at least once and reports the lowest revision
  still in the retry queue (the *retry low-water mark*), so callers can wait for
  "attempted" and separately for "succeeded".

**DEVIATION**: the reference embeds `reconciler.Status` inside the object and
re-inserts the object (bumping its revision) to record status. flowsdn keeps
status in a side table so revisions of the desired table reflect only desired
changes, which makes `watch` consumers other than the reconciler (Hubble, REST,
L2 announcer) not wake on status-only writes. ADR-0004 §2.

#### 3.2.3 Retry with exponential backoff

- On `Err` from `update`/`delete`: `retries += 1`, `next_retry = now +
  min(max_backoff, min_backoff * 2^retries)`; the error is recorded in the
  status and in the reconciler's health.
- The retry queue is keyed by primary key; a newer failure replaces the older
  entry (keeping the incremented count). A success, or a table change for that
  key, clears the entry.
- Defaults: `min_backoff` 100 ms, `max_backoff` 1 min (StateDB defaults). Areas
  MAY override: the LB reconciler uses `lb-retry-backoff-min`/`-max` (1 s / 1 min
  as resolved by spec 05 §6 and ADR-0011, #47/#90).
- Failed `prune` is not retried; it runs again at the next prune interval and
  is reported through health.

#### 3.2.4 Full sync (prune + refresh) and batching

- **Prune** runs once when the table first becomes initialized and then every
  `prune_interval` (default 1 h; LB uses 30 min per inventory 04). `prune`
  receives an iterator over all desired rows and MUST remove target entries not
  in the set. `Reconciler::prune_now()` triggers one out-of-band prune (a
  1-slot channel; concurrent calls coalesce).
- **Refresh** marks rows whose status `updated_at` is older than
  `refresh_interval` (default 30 min; 0 disables) as `Refreshing`, at most
  `refresh_rate` rows/s (default 100), iterating by revision so a refresh pass
  is O(rows) once per interval.
- **Batch coalescing**: when the target implements `update_batch`/`delete_batch`,
  a round hands all changes of the round to the target in two calls (deletes
  first, then updates) and reads per-entry results; otherwise operations are
  issued one by one. Batch size = the round (≤ `round_size`).
- Startup order for a reconciler that mirrors into BPF maps: (1) restore IDs and
  realized state from the pinned maps, (2) `wait_initialized()` on the table
  bounded by a per-area timeout (`lb-init-wait-timeout`), (3) first incremental
  round, (4) first prune. This ordering is what prevents scaling services to
  zero while data sources are still warming up (inventory 04).

### 3.3 Configuration registry (B)

#### 3.3.1 Sources and precedence

Highest first. A key set by a higher source hides the same key from lower
sources; sources never merge values of one key.

1. **Command-line flags** (`--key=value`, `--key value`).
2. **Environment** `CILIUM_<KEY>` where `<KEY>` = key upper-cased with `-`
   replaced by `_` (`enable-ipv4` → `CILIUM_ENABLE_IPV4`). Legacy alternate
   names listed in 6.3 are honored when the canonical variable is unset.
3. **Config directory** (`--config-dir`, Helm default `/tmp/cilium/config-map`):
   every regular file (following symlinks; directories skipped; unreadable
   files warned and skipped) is one key; file name = key, value = file content
   with leading/trailing whitespace trimmed. A non-existent directory given
   explicitly is a fatal error.
4. **Config file** (`--config <path>`, else `$HOME/ciliumd.yaml` if present):
   YAML mapping of key → value. **DEVIATION (precedence)**: in the reference
   the config-dir is merged into viper's config-file layer and a config file
   read afterwards *replaces that whole layer* (viper `ReadInConfig` assigns a
   fresh map), so when both are present every config-dir value is silently
   discarded, not layered. flowsdn layers them per key with dir above file, so
   a ConfigMap key always wins over a file key and nothing is discarded. Helm
   never sets `--config`, so no deployment observes the difference; reason:
   least surprise, ADR-0004 §3. The file therefore sits between dir and
   defaults in the order above.
5. **CiliumNodeConfig-derived and node-annotation-derived values** are *not* a
   separate runtime source for the agent process: `cilium-dbg build-config`
   (init container) resolves `config-map` → `cilium-node-config` → `node`
   sources (in `--source` order; later sources override earlier ones subject
   to the allow/deny lists, 6.2) and writes the merged result as the config
   directory. flowsdn ships the same resolver as `flowsdn-agent build-config`
   (or accepts the upstream init container unchanged). Inside the agent these
   values therefore arrive through source 3. The *dynamic* reflection of the
   same sources at runtime is 3.3.6.
6. **Defaults** from the key table (6.4).

The registry records, for every key, which source supplied the effective value
(`Source::{Flag, Env, Dir, File, Default}`) for logging and for
`GET /config` (`daemon-configuration-map`) and drift checking.

#### 3.3.2 Key normalization

- Canonical key form: lower-case ASCII, words separated by `-`.
- On input from any source the registry normalizes `_` → `-` and upper → lower
  before lookup, so `enable_ipv4`, `ENABLE_IPV4` (env body) and `enable-ipv4`
  are one key. This mirrors mapstructure's dash-insensitive match in hive and
  viper's env replacer.
- The four keys that the inventory lists under Go constant names (`ConfigKey`,
  `deriveFlag`, `enable`, `SkipCRDCreation`) are registered under their real
  names (`dynamic-lifecycle-config`, `derive-masq-ip-addr-from-device`,
  `enable-k8s-host-firewall-bypass`, `skip-crd-creation`); section 6.4 marks
  them `renamed`.
- Deprecated aliases MUST be mapped when the canonical key is absent:
  `monitor-aggregation-level` → `monitor-aggregation`,
  `ct-global-max-entries-tcp` → `bpf-ct-global-tcp-max`,
  `ct-global-max-entries-other` → `bpf-ct-global-any-max`.

#### 3.3.3 Typed value kinds and parsing

Every key has one kind. All sources deliver strings (flags, env, files) or
scalars (YAML); parsing is uniform:

| Kind | pflag types covered | Accepted textual forms |
|---|---|---|
| `Bool` | Bool | `true/false`, `1/0`, `t/f`, `yes/no`, `on/off` (case-insensitive) |
| `Int` | Int, Int8, Int16, Int32, Int64 | decimal, optional sign; range-checked to the declared width |
| `UInt` | Uint, Uint8, Uint16, Uint32, Uint64 | decimal; range-checked |
| `Float` | Float32, Float64 | decimal / scientific |
| `Duration` | Duration | Go duration syntax `300ms`, `1h30m`, `0`; bare integers are **nanoseconds** as in Go's `time.Duration` cast (kept for compatibility; a warning is logged because it is almost always a mistake) |
| `String` | String | verbatim |
| `List` | StringSlice | split on `,`; if the result is a single element it is split again on whitespace; `--k a --k b` from flags appends. `"foo,bar baz"` → `["foo","bar baz"]` |
| `Map` | StringToString, Var(MapOptions) | `k1=v1,k2=v2`; for `Var` keys the area-specific validator runs (e.g. `fixed-identity-mapping` id range and reserved label, `bpf-map-event-buffers` `enabled_<size>_<ttl>`) |
| `Enum` | String with fixed value set | one of the listed values (e.g. `routing-mode` ∈ {`tunnel`,`native`}); case-sensitive |
| `Cidr`, `Ip`, `HostPort` | String parsed early | `netip::Prefix`, `netip::Addr`, `host:port` |

Parsing happens at load, per key, and a parse failure for a *known* key is
fatal with the message `option <key>: <error>` (the reference validates
config-dir values against the flag type before merging and exits on failure).

#### 3.3.4 Unknown keys

A key present in any source but absent from the table is **accepted and
ignored with one warning** `unknown configuration key <key> (source <src>)`;
it does not fail startup, so a newer Helm chart or a downstream ConfigMap does
not brick the node. All unknown keys are listed under
`GET /config` → `status.daemon-configuration-map.unknown-keys[]` and in the
Helm mapping document. **DEVIATION**: the reference silently skips unknown
config-dir keys (`validateConfigMap` `continue`s on `flags.Lookup == nil`) and
viper keeps them unused; flowsdn warns. Reason: operability; ADR-0004 §3.

Keys classed `script` in 6.4 are hive-shell command flags that the inventory's
extractor picked up; they are registered so the count matches and so an
operator who copies them into a ConfigMap gets the same "accepted, ignored"
warning rather than a fatal error.

#### 3.3.5 Load, validate, freeze

```
load():  defaults → file → dir → env → flags     (each layer overrides)
         normalize keys; map deprecated aliases; parse each known key by kind
         (fatal on parse error); collect unknown keys (warn)
derive(): compute derived fields (BpfDir = lib-dir/bpf, StateDir = state-dir/state,
         dynamic map sizes from bpf-map-dynamic-size-ratio, tunnel-port default
         by protocol, …) — owned by the area specs, executed here
validate(): cross-key rules (3.3.7); first error is fatal with `--<key>` named
freeze(): produce `Arc<Config>`; from now on only runtime options (3.3.8) change
store():  write agent-runtime-config.json (6.6)
```

Validation failures are fatal at startup, never degraded: a node with an
invalid config MUST NOT come up half-configured.

#### 3.3.6 Dynamic configuration

Reference behavior: with `enable-dynamic-config=true` (default) the agent
reflects the sources listed in `config-sources` (JSON array; default the
`cilium-config` ConfigMap) plus any CiliumNodeConfig and Node-annotation source
into a table `cilium-configs` of rows `{Key{Name, Source}, Value, Priority}`.
Priority for a key from source index `i` of `n` sources: first source → `n`;
later sources → `n - i` if the key is overridable, `n + i` if not (allow list
wins over deny list; empty lists → everything overridable). `GetKey(name)`
returns the lowest-priority-number row. Only two consumers read it at this tag:
`subnet-topology` (pkg/subnet) and `dynamic-lifecycle-config`
(dynamiclifecycle). Everything else is read once at startup. The
**drift checker** (`enable-drift-checker`, default true) compares every key in
the table against the running value and reports module health `Degraded` with
the list of drifted keys, excluding `ignore-flags-drift-checker`.

flowsdn:

- MUST provide the `dynamic-config` table (`flowsdn-table`) with the same row
  shape and priority rule, populated by a k8s reflector over the configured
  sources (ConfigMap watch; CiliumNodeConfig list filtered by node labels; Node
  labels/annotations with prefix `config.cilium.io/`).
- MUST implement the drift checker as a module reporting into health (8.3):
  `Degraded("configuration drift", "<key>: running=<v1> configured=<v2>, …")`.
  This is how "reloadable at runtime" is bounded: **no key in the 539 table is
  hot-reloaded by the registry itself**. Keys classed `dynamic` (currently
  `subnet-topology`) are read by their owning module through
  `watch_key(name)`; keys classed `runtime` change through `PATCH /config`
  (3.3.8). All others require a restart, which drift checking makes visible.
- `enable-dynamic-lifecycle-manager` / `dynamic-lifecycle-config` are accepted
  and ignored (ADR-0004: no cell lifecycles to toggle; deferred per inventory 06).

#### 3.3.7 Validation rules (cross-key)

Registry-level (owned here; area rules live in their specs but run in the same
phase):

| Rule | Error when |
|---|---|
| `routing-mode ∈ {tunnel, native}` | otherwise |
| `enable-ipv6-ndp` requires `enable-ipv6` and non-empty `ipv6-mcast-device` | violated |
| `route-metric >= 0` | negative |
| `ipv6-cluster-alloc-cidr` parses as `/64` | otherwise |
| `cluster-name` ≤ 32 chars, lower-case alnum and `-`, alnum at both ends; `cluster-id` ≤ max for `max-connected-clusters` (255 → 255, 511 → 511) | violated |
| map sizes: each `bpf-*-max` within `[min, max]` documented per map in the map ABI spec; `bpf-map-dynamic-size-ratio ∈ (0, 1]` | violated |
| `ipv4-native-routing-cidr` / `ipv6-native-routing-cidr` required when `routing-mode=native` and masquerade enabled without `ipv4-range` auto | violated |
| `ipam=delegated-plugin` forbids `enable-ipv4-masquerade` (BPF), `enable-endpoint-health-checking`, and requires `enable-endpoint-routes` | violated |
| `enable-vtep` requires `vtep-mask` to parse | violated |
| `allow-localhost ∈ {auto, always, policy}`; `kvstore` + `identity-allocation-mode` combos as in inventory 06 step 1 | violated |
| `enable-ipv4 || enable-ipv6` | both false |

#### 3.3.8 Runtime-mutable options

The 12 option names in section 2 are the only runtime-mutable values. They are
held outside the frozen `Config` in an `Options` map (`name → i64`), mutated by
`PATCH /config` (daemon set) and `PATCH /endpoint/{id}/config` (endpoint set
= daemon set minus `DebugTagged`, `TraceSockNotification`, `PolicyTracing`).
Their initial values derive from config keys (`debug`, `monitor-aggregation`,
`policy-audit-mode`, `enable-tracing`, `trace-sock`, `bpf-events-*-enabled`).
A change triggers `RegenerateAllEndpoints(DaemonConfigUpdate)` and is
persisted per endpoint in `ep_config.json` `Options` (agent core spec). These
values are excluded from the immutability check (3.3.9).

#### 3.3.9 Immutability and `ValidateUnchanged`

Reference semantics (read from `daemon_main.go:1230-1275`, `config.go:3297-3392`):
after validation the agent writes `agent-runtime-config.json`, computes a
SHA-256 over the JSON of the config **excluding the runtime options**, and a
job named `validate-unchanged-daemon-config` re-computes the sum every 61 s;
on mismatch it re-reads the file it wrote and logs a `Config differs:` diff.
It is an **in-process invariant** ("nothing mutated the global config after
init"), not a restart check. Restart-time immutability is enforced separately
and only for `datapath-mode` (refuse to start if restored endpoints use an
incompatible link type).

flowsdn:

- The in-process guard is satisfied by construction: `Config` is an immutable
  `Arc`; there is nothing to re-checksum. The `validate-unchanged-daemon-config`
  controller name is still registered (it appears in `StatusResponse.controllers`
  and `cilium-dbg status --all-controllers`) and always reports success.
- **DEVIATION (extension)**: on start, if `agent-runtime-config-1.json` (the
  previous run's file, after rotation) exists and parses, the registry compares
  the **immutable set** (keys classed `immutable` in 6.4) between the previous
  and the current run. Any difference is logged at error level with old/new
  values; if endpoints are being restored (`restore=true` and at least one
  `<state-dir>/<id>/ep_config.json` exists) the agent MUST refuse to start,
  otherwise it continues. Reason: changing these keys with live endpoints
  silently breaks the datapath (map layouts, address families, encapsulation);
  the reference only catches `datapath-mode`. Open decision 12.3 covers the
  refuse-vs-warn choice.
- A previous file that fails to parse (schema change across versions) MUST be
  logged at warning level and skipped, never fatal.

### 3.4 Fences and health (C)

#### 3.4.1 Fence

A `Fence` is a named barrier: a set of named waiters registered before start,
awaited by dependents. Semantics from `pkg/hive/fence.go`:

- `add(name, future)` MUST be called before the fence is *sealed* (the agent
  seals all fences when construction finishes, before any module starts);
  adding after sealing or adding a duplicate name is a programming error
  (panic in debug, error in release).
- `wait(ctx)` awaits every registered waiter, in registration order,
  logging `Fence waiting {name, remaining}` / `Fence done {name, duration}`;
  the first error (or cancellation) aborts with `"<name>: <error>"`.
  `wait` may be called any number of times; completed waiters are not re-run.
- A `Fence` with no waiters resolves immediately.

The startup graph of inventory 06 (External interfaces → "Startup order" and
"What must exist before an endpoint regenerates") is expressed as these named
fences. Names are stable identifiers used in logs and in health.

| Fence | Waiters (name → satisfied when) | Dependents |
|---|---|---|
| `config` | `config-loaded` → 3.3.5 `freeze()` done and file stored | everything |
| `datapath-base` | `bpffs-mounted`, `node-config-header` (`globals/node_config.h`), `maps-opened` (lxc, ipcache, policy call maps, CT, NAT, LB) | endpoint regeneration, ipcache, LB reconciler, policy |
| `k8s-crds` | `crd-sync` → all Cilium CRDs established (`crd-wait-timeout` 5 m, fatal on expiry) | k8s watchers, IPAM (crd/cluster-pool), identity (crd mode) |
| `k8s-caches` | one waiter per informer (`pods`, `namespaces`, `ciliumnodes`, `cep`/`ces`, policies, services/endpointslices) → initial list done; overall bound `k8s-sync-timeout` 3 m (fatal) | endpoint restore finish, policy repository, LB initializers |
| `node-info` | `node-discovered` (`WaitForNodeInformation`), `direct-routing-device` (only when KPR/WG/IPsec require it) | datapath config, IPAM, encryption |
| `ipam-restored` | `ipam-configured`, `endpoints-read-from-disk` (possible-restore set announced to IPAM/ipcache) | endpoint restore, infra IP allocation |
| `identity-init` | `identity-allocator-initialized`, `initial-global-identities` (kvstore list or CRD list, `allocator-list-timeout` 3 m) | endpoint regeneration, ipcache |
| `policy-ready` | `policy-repository-rev1`, `policy-dir-loaded` (`static-cnp-path` ingested) | endpoint regeneration (`WaitForInitialPolicy`) |
| `ipcache-ready` | `ipcache-rev1` → ipcache table revision ≥ 1 | endpoint regeneration |
| `lb-init` | `lb-initializers-complete` (all registered LB data sources synced, bounded by `lb-init-wait-timeout` 1 m — timeout is *not* fatal, it releases the fence with a warning) | first endpoint regeneration, LB reconciler prune |
| `clustermesh-sync` | `clustermesh-ip-identities` bounded by `clustermesh-ip-identities-sync-timeout` (release with warning on timeout) | first endpoint regeneration |
| `regeneration` | composite: `datapath-base`, `identity-init`, `policy-ready`, `ipcache-ready`, `lb-init`, `clustermesh-sync` | `Endpoint::regenerate` (first regeneration per endpoint); the reference `regeneration.Fence` |
| `endpoint-restore` | `restored-into-manager` (`endpointRestoreComplete`), then `initial-policy` (`endpointInitialPolicyComplete`), then `regenerated` (`endpointRegenerateComplete`) — three sub-fences | cilium-health server and CNI deletion-queue replay wait for the first only; BPF-program watchdog and infra endpoints likewise |
| `api-ready` | `delete-queue-lock-held`, `api-listening` (socket created, mode 0660, group `cilium`) | CNI conf writer (`write-cni-conf-when-ready`) |
| `agent-ready` | `api-ready`, `endpoint-restore.restored-into-manager`, `status-probes-ran-once` | `GET /healthz` readiness (3.4.2), `write-cni-file` controller |

Timeouts: the only global start deadline is `hive-start-timeout` (default 5 m),
kept as the registry key and applied to the whole `build()`+start phase
(exceeding it is fatal, matching the reference). `hive-stop-timeout` (1 m) is
kept as the shutdown deadline; `hive-log-threshold` is accepted and ignored
(there are no hooks to time). See 6.5.

#### 3.4.2 Readiness and liveness derivation

`GET /healthz` on `127.0.0.1:9879` (kubelet) and on the API socket
(`cilium-dbg status`) return `StatusResponse`. The overall verdict is derived:

| Condition | HTTP | `cilium.state` |
|---|---|---|
| not every status probe has run once (`status-collector-probe-check-timeout` 5 m) | 500 | `Failure`, msg `Not all probes executed at least once` |
| `agent-ready` fence not released | 500 | `Warning`, msg names the pending waiter |
| kvstore probe `Failure` when kvstore is configured | 500 | `Failure` |
| kubernetes probe `Failure` and header `require-k8s-connectivity: true` (or `agent-health-require-k8s-connectivity`, default true) | 500 | `Failure` |
| any module health `Degraded` | 200 | `Warning` (details in `cilium.msg` when `brief` is false) |
| otherwise | 200 | `Ok` |

Liveness (kubelet livenessProbe, `brief: true`) uses the same handler; a
deadlocked agent fails it because probes stop running. Startup probe: same,
with the kubelet's own failure threshold covering the 5 m start deadline.

#### 3.4.3 Module health model

Each module (a named subsystem constructed in `build()`) receives a
`HealthReporter` scoped to its identifier; sub-components derive scopes with
`new_scope(name)`. Identifier string = `<module>[.<component>]*` joined with
`.` (e.g. `agent.datapath.loader`, `agent.loadbalancer.bpf-reconciler`).

```
HealthStatus {
  id:       Identifier             # "agent.lb.reconciler"
  level:    OK | Degraded | Stopped
  message:  String
  error:    String                 # empty unless Degraded
  last_ok:  Timestamp              # last transition to/refresh of OK
  updated:  Timestamp
  stopped:  Timestamp              # zero unless Stopped
  final:    String                 # message given to stopped()
  count:    u64                    # number of updates to this id
}
```

Operations: `ok(msg)`, `degraded(msg, err)`, `stopped(reason)` (keeps the last
level, marks stopped), `close()` (removes the row entirely), `new_scope(name)`.
Semantics from `cell.Health`: a module SHOULD report `ok` only once it has
stabilized; a freshly constructed scope has *no* row (unknown) until its first
report. The registry is a `flowsdn-table` table named `health`, primary key
`id`, so the status API, metrics and the history file are ordinary readers.

- **History**: every upsert/stop/close is appended as one JSON line to
  `<state-dir>/<binary-name>-health-history.log` (reference: `HistoryDir` =
  state dir); rotated at 10 MB, 3 files kept. Replayed by `flowsdn-dbg health
  history` (the reference's `cilium-dbg shell -- health/history`).
- **Metrics**: `cilium_hive_status{level}` gauge (count of rows per level) and
  `cilium_hive_degraded_status{module}` (count of degraded rows per top-level
  module). Names kept for dashboards even though there is no hive.
- **Surface in the status API**: 8.4.

## 4. Data model

### 4.1 Table store

```
Table<T>            { name: &'static str, primary: Indexer<T>, secondary: [Indexer<T>],
                      inner: RwLock<Version>, notify: watch::Sender<Revision>,
                      initializers: Set<String>, streams: Map<StreamId, LowWater> }
Version             { rev: u64, by_key: OrdMap<Bytes, Row<T>>,        # persistent maps
                      by_rev: OrdMap<u64, Bytes>,
                      idx[i]: OrdMap<Bytes, Bytes|()>,                # unique: key→pk; non-unique: (key++0x00++pk)→()
                      tombstones: OrdMap<u64, Bytes> }                # rev → pk
Row<T>              { value: Arc<T>, rev: u64 }
Indexer<T>          { name, unique: bool, keys: fn(&T) -> SmallVec<Bytes> }
Change<T>           Insert{row: Arc<T>, rev} | Delete{key: Bytes, rev} | Resync
ChangeStream<T>     { table, from: u64, acked: u64 }
```

Key encoding helpers (order-preserving): `u16/u32/u64` big-endian; `bool` one
byte; `netip::Addr` 16 bytes (v4 mapped); `netip::Prefix` 16 bytes + 1 byte
length; `&str` UTF-8 (variable, must be last or followed by `0x00`).

### 4.2 Reconciler status table

```
ReconcileStatus     { kind: Kind(u8), id: u64, updated_at: SystemTime,
                      error: Option<String>, retries: u32, next_retry: Option<SystemTime> }
Kind                Pending=1 | Refreshing=2 | Done=3 | Error=4     (0 = unset, never stored)
```

Serialized (JSON, for `GET /service` and dumps) as
`{"kind":"Pending"|"Refreshing"|"Done"|"Error","id":n,"updated-at":RFC3339,"error":"…"}`
— the reference `reconciler.Status` field names, so `cilium-dbg service list`
renders `status.realized` unchanged.

### 4.3 Reference tables this crate must be able to express

Not owned here (their specs own them) but used to validate the design:

| Table | Primary key | Secondary indexes | Owner spec |
|---|---|---|---|
| `services` | `ServiceName` (`[cluster/]ns/name`) | — | LB |
| `frontends` | `L3n4Addr` (16 B addr + 4 B cluster + 2 B port + 1 B proto + 1 B scope) unique | `service` (non-unique) | LB |
| `backends` | `(ServiceName, L3n4Addr, source-priority)` | `address` (non-unique) | LB |
| `devices` | `ifindex` (u32) | `name` (unique, incl. alt names → multi-key), `selected` (bool, non-unique) | datapath |
| `routes` | `(table u32, ifindex u32, dst prefix)` | `link` (ifindex) | datapath |
| `neighbors` | `(ifindex, addr)` | `link`, `ip` | datapath |
| `node-addresses` | `(addr, device-name)` | `name` (device), `node-port` (bool) | datapath |
| `sysctl` | `name` (`a.b.c` string) | — | datapath |
| `l2-announce` | `(ip, interface)` | `origin` (ns/name, multi-key) | LB/L2 |
| `dynamic-config` | `(name, source)` | `name` (non-unique) | this spec |
| `health` | `id` string | — | this spec |

### 4.3a `TableRender` — the text rendering contract

**Added 2026-09-07 by amendment.** Resolves open decision 12.1 of
`17-scripttest-harness.md`. The reference has a `TableWritable` interface that
`db/cmp` uses to render a table as aligned text; spec 17's harvested corpus
contains **478 `.table` expectation files** that pin both the column order and
the per-cell formatting of that rendering. Without an equivalent, those files
cannot be compared against and the corpus is worthless. The design therefore
carries a rendering trait from the start, not as a test-only afterthought.

Every table type registered with `flowsdn-table` MUST implement:

```text
trait TableRender {
    /// Column names, in the order they are rendered. Stable across releases:
    /// a rename or reorder is a breaking change to the test corpus and MUST
    /// be accompanied by a corpus update in the same commit.
    fn header() -> &'static [&'static str];

    /// One rendered cell per header column, same order, same length.
    fn row(&self) -> Vec<String>;
}
```

Normative requirements:

1. `row()` MUST return exactly `header().len()` cells.
2. Cell text MUST NOT contain a tab or a newline. Spec 17 verified that no
   harvested `.table` section contains a tab, so the renderer emits
   space-aligned columns only; the tab-splitting path exists in the *parser*
   for `--update` round-trips, never in the writer.
3. Formatting MUST be deterministic and locale-independent: no map iteration
   order, no floating-point default formatting, no timestamps rendered as
   relative durations unless the reference does so for that column.
4. Columns are separated by at least three spaces, and each column is padded
   to the width of the widest cell including the header. This is what makes
   the reference's character-offset column splitting work, which spec 17
   documents as the matching mechanism.
5. Rendering is a pure function of the row. It MUST NOT consult other tables,
   the clock, or the environment.

The `db/cmp` command matches rows **positionally and in order**, so a table's
default iteration order is part of its contract: it MUST be the primary-key
order unless the owning spec states otherwise and the corpus agrees.

**Consequence for every table-owning spec (04, 05, 07, 08, 10, 11, 12, 14,
15, 20):** each MUST state its tables' column list and per-column formatting,
and MUST cross-check it against the harvested `.table` files for its area
before its crate is written. A mismatch found later is a corpus-wide churn.

### 4.4 Configuration registry

```
KeySpec             { name: &'static str, kind: Kind, default: Value, help: &'static str,
                      class: {Normal, Immutable, Runtime, Dynamic, Ignored{adr}, Script},
                      hidden: bool, deprecated_aliases: &[&str], validator: Option<fn> }
Value               Bool(bool) | Int(i64) | UInt(u64) | Float(f64) | Duration(Duration)
                    | Str(String) | List(Vec<String>) | Map(BTreeMap<String,String>)
Layer               { source: Source, values: BTreeMap<String, String> }   # raw strings
Resolved            { values: BTreeMap<String, (Value, Source)>, unknown: Vec<(String, Source)> }
Config              typed struct, one field per non-script key, generated from the KeySpec table
                    (build script or macro) so field ↔ key ↔ default cannot drift
Options             { map: RwLock<BTreeMap<&'static str, i64>> }          # runtime-mutable
```

### 4.5 `agent-runtime-config.json`

Written to `<state-dir>/state/agent-runtime-config.json` after `freeze()`;
before writing, existing `agent-runtime-config-1.json` → `-2.json`, current →
`-1.json` (renames; failures logged, not fatal). Content:

```json
{
  "flowsdn-version": "x.y.z",
  "written-at": "RFC3339",
  "reference-compat": "cilium-1.20.1",
  "config": { "<key>": <json value>, … },          // all 539 keys minus `script`, canonical names, effective values
  "sources": { "<key>": "flag|env|dir|file|default" },
  "unknown-keys": { "<key>": "<raw value>" },
  "immutable-keys": [ "<key>", … ]                   // the set compared on the next start
}
```

**DEVIATION**: the reference writes Go's default JSON encoding of the 227-field
`DaemonConfig` struct (PascalCase field names, no tags) plus a second
`viper-agent-config.yaml` (all viper settings). flowsdn writes the key-named
form above and no viper file. Nothing machine-reads the reference file except
the agent itself; bugtool copies it verbatim. Reason: keying by config key is
the only stable schema; ADR-0004 §3. In-place migration from a Cilium state dir
is open decision 12.4.

### 4.6 Files

| Path | Written by | Read by |
|---|---|---|
| `<state-dir>/state/agent-runtime-config{,-1,-2}.json` | registry (3.3.5) | registry on next start (3.3.9), bugtool |
| `<state-dir>/state/<bin>-health-history.log{,.1,.2}` | health registry | `flowsdn-dbg health history` |
| `--config-dir` (default none; Helm `/tmp/cilium/config-map`) | `build-config` / kubelet ConfigMap mount | registry |
| `$HOME/ciliumd.yaml` or `--config` | operator | registry |

## 5. Algorithms

### 5.1 Table write (single-table atomicity)

1. Take the table's write lock (async mutex; one writer).
2. Clone the current `Version` handle (O(1), persistent structures share
   structure).
3. For each operation: compute primary key; compute old row; compute new
   secondary keys and old secondary keys; apply deltas to `by_key`, `by_rev`
   (delete old rev, insert new), each `idx[i]` (remove old keys not in new,
   insert new keys not in old — unchanged keys untouched), `tombstones`
   (insert on delete; remove pending tombstone for the key on insert).
4. `rev += 1` per operation; unique violations are detected in step 3 before
   any mutation of the clone is made visible — on error drop the clone, keep
   the old version, release the lock.
5. Publish: swap the `Version` pointer (an `ArcSwap`/`RwLock<Arc<Version>>`
   write), run status hooks (3.2.2) as part of the same batch if the table has
   a status companion, `notify.send(rev)`.

Cost: O(log n) per index per operation; snapshot O(1).

### 5.2 Change stream drain

```
drain(max):
  v = table.current_version()
  out = []
  for (rev, pk) in v.tombstones.range(acked+1 ..):      # deletes first, in rev order
      out.push(Delete{pk, rev})
  for (rev, pk) in v.by_rev.range(acked+1 ..):           # then live rows changed since ack
      out.push(Insert{v.by_key[pk], rev})
  sort out by rev; truncate to max; acked = last.rev (or v.rev if none)
  if oldest retained tombstone rev > acked_before_drain + 1 and stream had acked something:
      emit Resync first (a deletion may have been GC'd)
```

Coalescing follows from reading `by_rev` (each key appears once, at its latest
revision).

### 5.3 Tombstone GC

Triggered after every batch that produced tombstones, rate-limited to one run
per second per table: `low = min(stream.acked for stream in streams,
table.rev)`; drop `tombstones.range(..=low)`. Streams exceeding
`tombstone_max_age` or `tombstone_max_count` are force-resynced first
(3.1.7). Metrics record the low-water mark and the count removed.

### 5.4 Reconciler retry queue

Two orderings over the same items: a min-heap by `next_retry` (what to run
next) and a min-heap by `original_revision` (the retry low-water mark returned
by `wait_until_reconciled`). `push(key, err)` upserts the item, `retries += 1`,
`next_retry = now + min(max, min * 2^retries)`; `clear(key)` on success or on
a newer table change for that key; `due(now)` pops items with `next_retry <=
now`. A timer is armed for the earliest `next_retry`.

### 5.5 Config layering

```
resolved = {}
for layer in [defaults, file, dir, env, flags]:           # ascending precedence
    for (raw_key, raw_val) in layer:
        key = canonical(raw_key)                          # lower, '_'→'-', alias map
        if key not in KEYS: unknown[key] = (raw_val, layer.source); continue
        resolved[key] = (parse(KEYS[key].kind, raw_val)?, layer.source)   # error is fatal
```

Flags are pre-parsed by `clap` into strings (or lists) and fed as the top
layer so that one parser (`parse(kind, str)`) is authoritative for all sources;
`clap`'s own typed parsing is not used for values, only for tokenization and
`--help`.

### 5.6 Dynamic-config priority

For `n` sources in `config-sources` order, key `k` from source index `i`:
`priority = n` if `i == 0`; else if allow-list non-empty: `n - i` when `k` in
allow-list else `n + i`; else if `k` in deny-list: `n + i`; else `n - i`.
Effective value for a name = row with the smallest priority; ties broken by
source string order. Identical to the reference so that a ConfigMap that works
with Cilium overrides the same way with flowsdn.

### 5.7 Startup sequence (fence graph)

```
main:  parse flags → registry.load/derive/validate/freeze/store   [fence config]
       require root; mkdir run/state/lib dirs; rlimit memlock; chdir state; pidfile
       build(): construct every module, wiring handles and registering fence waiters
       seal fences
       start modules concurrently (each `async fn start(&self) -> Result`) under the
         5 m start deadline; each awaits the fences it depends on internally
       [agent-ready] → write CNI conf → serve readiness 200
shutdown: cancel token; modules stop in reverse construction order under the 1 m stop
       deadline; state on disk left intact; pidfile removed
```

A module that fails `start()` MUST make the agent exit non-zero (the reference
fails the hive); a fence waiter that times out with a *fatal* bound exits
likewise; the non-fatal bounds (`lb-init-wait-timeout`,
`clustermesh-ip-identities-sync-timeout`) release the fence and report
`Degraded` on the owning module.

## 6. Configuration

### 6.1 Keys owned by this spec

| Key | Type | Default | Effect |
|---|---|---|---|
| `config` | string | `""` (search `$HOME/ciliumd.yaml`) | YAML config file |
| `config-dir` | string | `""` | file-per-key directory; fatal if given and missing |
| `config-sources` | string (JSON) | `[{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]` | dynamic-config sources; written by `build-config` |
| `config-sources-overrides` | string (JSON) | `{"allowConfigKeys":null,"denyConfigKeys":null}` | override allow/deny lists |
| `enable-dynamic-config` | bool | `true` | run the dynamic-config reflector |
| `enable-drift-checker` | bool | `true` | run the drift checker module |
| `ignore-flags-drift-checker` | list | `[]` | keys excluded from drift reporting |
| `hive-start-timeout` | duration | `5m` | start deadline for `build()` + module start |
| `hive-stop-timeout` | duration | `1m` | shutdown deadline |
| `state-dir` | string | `/var/run/cilium` | run dir; runtime-config and history under `<state-dir>/state` |
| `debug`, `debug-verbose` | bool, list | `false`, `[]` | initial value of runtime option `Debug`; verbose groups |
| `version` | bool | `false` | print version and exit |
| `status-collector-*` (5 keys) | duration/string | see 6.4 | probe scheduling for 3.4.2 |
| `agent-health-port`, `agent-health-require-k8s-connectivity` | int, bool | `9879`, `true` | readiness endpoint |

### 6.2 `build-config` resolver (init container)

`flowsdn-agent build-config --node-name $K8S_NODE_NAME [--dest
/tmp/cilium/config-map] [--source …] [--allow-config-keys …]
[--deny-config-keys …]`. Sources are `config-map:[<ns>/]<name>` (default
`cilium-config` in `$CILIUM_K8S_NAMESPACE`), `cilium-node-config:<ns>` (all
CiliumNodeConfig in the namespace whose `nodeSelector` matches the node's
labels; empty selector = all nodes; nil selector = none; merged in
lexicographic name order, later wins with a warning), `node:[<name>]`
(labels then annotations with prefix `config.cilium.io/`). Later sources
override earlier ones except keys blocked by the override lists (allow-list
takes precedence; blocked keys are dropped with a warning). Output: a
Kubernetes-style atomic directory (`..data_<unix>` directory, `..data`
symlink swapped via `..data.tmp`, one symlink per key) plus the two synthetic
keys `config-sources` and `config-sources-overrides` recording what was used.
Keys containing a path separator are refused. A missing ConfigMap is logged
and skipped, not fatal.

### 6.3 Environment aliases

Canonical `CILIUM_<KEY>` for every key. Legacy fallbacks kept (used only when
the canonical variable is unset): `CILIUM_PREPEND_IPTABLES_CHAINS` (ignored
key, still parsed), plus any listed in the agent core spec. `CILIUM_SOCK`,
`CILIUM_HEALTH_SOCK`, `CILIUM_K8S_NAMESPACE`, `K8S_NODE_NAME` are process
environment read by other specs, not registry keys.

### 6.4 The registry key table (539 keys)

Reproduced from inventory 06 appendix A (name, pflag type, default) — the
duplication is intended so this spec is self-contained. Column **Class**:
empty = ordinary read-once key; `immutable` = compared across restarts (3.3.9);
`runtime` = seeds a runtime-mutable option (3.3.8); `dynamic` = read through
the dynamic-config table by its owner (3.3.6); `ignored` = accepted and ignored
(6.5); `script` = hive-shell command flag, not a ConfigMap key, accepted and
ignored (3.3.4); `renamed` = inventory row carried a Go constant name. Defaults
are the inventory's resolved constants; `def.X`/`cfg.X`/`r.X`/`userCfg.X`/
`hubbleDefaults.X`/`mc.X`/`metrics`/`masqInterface` mean "default struct
literal in the reference file named in inventory 06" and are resolved to
literals by the owning area spec. Types are pflag names; the kind mapping is
3.3.3. Meanings are in inventory 06 and are not repeated.

| Key | pflag type | Default | Class |
|---|---|---|---|
| `agent-health-port` | Int | `9879` |  |
| `agent-health-require-k8s-connectivity` | Bool | `true` |  |
| `agent-labels` | StringSlice | `[]string{}` |  |
| `agent-liveness-update-interval` | Duration | `1 * time.Second` |  |
| `agent-not-ready-taint-key` | String | `"node." + CiliumK8sAnnotationPrefix + "agent-not-ready"` |  |
| `alibabacloud-security-group-tags` | StringToString | `map[string]string{}` |  |
| `alibabacloud-security-groups` | StringSlice | `[]string{}` |  |
| `alibabacloud-vswitch-tags` | StringToString | `map[string]string{}` |  |
| `alibabacloud-vswitches` | StringSlice | `[]string{}` |  |
| `allocator-list-timeout` | Duration | `3 * time.Minute` |  |
| `allow-icmp-frag-needed` | Bool | `true` |  |
| `allow-localhost` | String | `auto` |  |
| `allow-unsafe-policy-skb-usage` | Bool | `false` |  |
| `annotate-k8s-node` | Bool | `false` |  |
| `any-proto` | Bool | `false` | script |
| `api-rate-limit` | String | `` |  |
| `auto-create-cilium-node-resource` | Bool | `true` |  |
| `auto-direct-node-routes` | Bool | `false` |  |
| `azure-interface-name` | String | `` |  |
| `bgp-router-id-allocation-ip-pool` | String | `` |  |
| `bgp-router-id-allocation-mode` | String | `default` |  |
| `boot-id-file` | String | `/proc/sys/kernel/random/boot_id` |  |
| `bpf-auth-map-max` | Int | `1 << 19` |  |
| `bpf-conntrack-accounting` | Bool | `false` |  |
| `bpf-ct-global-any-max` | Int | `2 << 17` | immutable |
| `bpf-ct-global-tcp-max` | Int | `2 << 18` | immutable |
| `bpf-ct-timeout-regular-any` | Duration | `60*time.Second` |  |
| `bpf-ct-timeout-regular-tcp` | Duration | `8000*time.Second` |  |
| `bpf-ct-timeout-regular-tcp-fin` | Duration | `10*time.Second` |  |
| `bpf-ct-timeout-regular-tcp-syn` | Duration | `60*time.Second` |  |
| `bpf-ct-timeout-service-any` | Duration | `60*time.Second` |  |
| `bpf-ct-timeout-service-tcp` | Duration | `8000*time.Second` |  |
| `bpf-ct-timeout-service-tcp-grace` | Duration | `60*time.Second` |  |
| `bpf-distributed-lru` | Bool | `false` | immutable |
| `bpf-events-default-burst-limit` | Int | `0` |  |
| `bpf-events-default-rate-limit` | Int | `0` |  |
| `bpf-events-drop-enabled` | Bool | `true` | runtime |
| `bpf-events-policy-verdict-enabled` | Bool | `true` | runtime |
| `bpf-events-trace-enabled` | Bool | `true` | runtime |
| `bpf-filter-priority` | Int | `1` |  |
| `bpf-fragments-map-max` | Int | `8192` |  |
| `bpf-lb-acceleration` | String | `disabled` |  |
| `bpf-lb-affinity-map-max` | Int | `0` |  |
| `bpf-lb-algorithm` | String | `LBAlgorithmRandom` |  |
| `bpf-lb-algorithm-annotation` | Bool | `false` |  |
| `bpf-lb-dsr-dispatch` | String | `DSRDispatchOption` |  |
| `bpf-lb-enable-wildcard-entries` | Bool | `true` |  |
| `bpf-lb-external-clusterip` | Bool | `false` |  |
| `bpf-lb-ipip-sock-mark` | Bool | `false` |  |
| `bpf-lb-maglev-hash-seed` | String | `userCfg.HashSeed` | immutable |
| `bpf-lb-maglev-map-max` | Int | `0` |  |
| `bpf-lb-maglev-table-size` | Uint | `userCfg.TableSize` | immutable |
| `bpf-lb-map-max` | Int | `DefaultLBMapMaxEntries` | immutable |
| `bpf-lb-mode` | String | `LBModeSNAT` |  |
| `bpf-lb-mode-annotation` | Bool | `false` |  |
| `bpf-lb-nat46x64` | Bool | `false` |  |
| `bpf-lb-rev-nat-map-max` | Int | `0` |  |
| `bpf-lb-rss-ipv4-src-cidr` | String | `` |  |
| `bpf-lb-rss-ipv6-src-cidr` | String | `` |  |
| `bpf-lb-service-backend-map-max` | Int | `0` |  |
| `bpf-lb-service-map-max` | Int | `0` |  |
| `bpf-lb-sock` | Bool | `false` | immutable |
| `bpf-lb-sock-hostns-only` | Bool | `false` |  |
| `bpf-lb-sock-terminate-pod-connections` | Bool | `true` |  |
| `bpf-lb-source-range-all-types` | Bool | `false` |  |
| `bpf-lb-source-range-map-max` | Int | `0` |  |
| `bpf-map-dynamic-size-ratio` | Float64 | `0.0025` | immutable |
| `bpf-map-event-buffers` | Var | `option.NewMapOptions(&option.Config.BPFMapEventBuffers, option.Config.BPFMapEventBuffersValidator)` |  |
| `bpf-nat-global-max` | Int | `int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)` | immutable |
| `bpf-neigh-global-max` | Int | `int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)` | immutable |
| `bpf-node-map-max` | Uint32 | `DefaultMaxEntries` |  |
| `bpf-policy-map-full-reconciliation-interval` | Duration | `15*time.Minute` |  |
| `bpf-policy-map-max` | Int | `16384` | immutable |
| `bpf-policy-map-pressure-metrics-threshold` | Float64 | `0.1` |  |
| `bpf-policy-stats-map-max` | Int | `1 << 16` |  |
| `bpf-root` | String | `` | immutable |
| `bpf-sock-rev-map-max` | Int | `0` |  |
| `bypass-ip-availability-upon-restore` | Bool | `false` |  |
| `certificates-directory` | String | `/var/run/cilium/certs` |  |
| `cgroup-root` | String | `` | immutable |
| `cluster-health-port` | Int | `4240` |  |
| `cluster-id` | Uint32 | `0` | immutable |
| `cluster-name` | String | `default` | immutable |
| `clustermesh-cache-ttl` | Duration | `0` |  |
| `clustermesh-config` | String | `` |  |
| `clustermesh-default-global-namespace` | Bool | `true` |  |
| `clustermesh-enable-mcs-api` | Bool | `false` |  |
| `clustermesh-mcs-api-install-crds` | Bool | `true` |  |
| `clustermesh-service-v2` | String | `c.ServiceModeV2.String()` |  |
| `clustermesh-sync-timeout` | Duration | `1 * time.Minute` |  |
| `cmdref` | String | `` | ignored |
| `cni-chaining-mode` | String | `none` |  |
| `cni-chaining-target` | String | `` |  |
| `cni-exclusive` | Bool | `false` |  |
| `cni-external-routing` | Bool | `false` |  |
| `cni-log-file` | String | `/var/run/cilium/cilium-cni.log` |  |
| `config` | String | `` |  |
| `config-dir` | String | `` |  |
| `config-sources` | String | ``[{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]`` |  |
| `config-sources-overrides` | String | ``{"allowConfigKeys":null,"denyConfigKeys":null}`` |  |
| `dynamic-lifecycle-config` | String | ``[]`` | renamed (inventory row `ConfigKey`); ignored |
| `connectivity-probe-frequency-ratio` | Float64 | `0.5` |  |
| `conntrack-gc-interval` | Duration | `0` |  |
| `conntrack-gc-max-interval` | Duration | `0` |  |
| `container-ip-local-reserved-ports` | String | `auto` |  |
| `controller-group-metrics` | StringSlice | `[]string{}` |  |
| `count` | Int | `0` | script |
| `crd-wait-timeout` | Duration | `5 * time.Minute` |  |
| `datapath-mode` | String | `veth` | immutable |
| `datapath-plugins-state-dir` | String | `/var/run/cilium/plugins` |  |
| `debug` | Bool | `false` | runtime |
| `debug-verbose` | StringSlice | `[]string{}` |  |
| `derive-masq-ip-addr-from-device` | String | `masqInterface` | renamed (inventory row `deriveFlag`) |
| `devices` | StringSlice | `[]string{}` |  |
| `diff` | Bool | `false` | script |
| `direct-routing-device` | String | `` |  |
| `direct-routing-skip-unreachable` | Bool | `false` |  |
| `disable-drain-on-disconnection` | Bool | `false` |  |
| `disable-endpoint-crd` | Bool | `false` |  |
| `disable-envoy-version-check` | Bool | `false` |  |
| `disable-external-ip-mitigation` | Bool | `false` |  |
| `disable-iptables-feeder-rules` | StringSlice | `[]string{}` | ignored |
| `dns-max-ips-per-restored-rule` | Int | `1000` |  |
| `dns-policy-unload-on-shutdown` | Bool | `false` |  |
| `dnsproxy-concurrency-limit` | Int | `0` |  |
| `dnsproxy-concurrency-processing-grace-period` | Duration | `0` |  |
| `dnsproxy-enable-transparent-mode` | Bool | `false` |  |
| `dnsproxy-insecure-skip-transparent-mode-check` | Bool | `false` |  |
| `dnsproxy-lock-count` | Int | `131` |  |
| `dnsproxy-lock-timeout` | Duration | `500 * time.Millisecond` |  |
| `dnsproxy-socket-linger-timeout` | Int | `10` |  |
| `egress` | Bool | `false` | script |
| `egress-gateway-policy-map-max` | Int | `1 << 14` |  |
| `egress-gateway-reconciliation-trigger-interval` | Duration | `1 * time.Second` |  |
| `egress-masquerade-interfaces` | StringSlice | `[]string{}` | ignored |
| `enable-k8s-host-firewall-bypass` | Bool | `true` | renamed (inventory row `enable`) |
| `enable-active-connection-tracking` | Bool | `false` |  |
| `enable-auto-protect-node-port-range` | Bool | `true` |  |
| `enable-bandwidth-manager` | Bool | `def.EnableBandwidthManager` |  |
| `enable-bbr` | Bool | `def.EnableBBR` |  |
| `enable-bbr-hostns-only` | Bool | `def.EnableBBRHostnsOnly` |  |
| `enable-bgp-control-plane` | Bool | `false` |  |
| `enable-bgp-control-plane-status-report` | Bool | `true` |  |
| `enable-bgp-legacy-origin-attribute` | Bool | `false` |  |
| `enable-bpf-clock-probe` | Bool | `false` |  |
| `enable-bpf-masquerade` | Bool | `false` | immutable |
| `enable-bpf-tproxy` | Bool | `false` |  |
| `enable-cilium-clusterwide-network-policy` | Bool | `true` |  |
| `enable-cilium-endpoint-slice` | Bool | `false` |  |
| `enable-cilium-network-policy` | Bool | `true` |  |
| `enable-ciliumnode-crd` | Bool | `true` |  |
| `enable-datapath-plugins` | Bool | `false` |  |
| `enable-drift-checker` | Bool | `true` |  |
| `enable-dynamic-config` | Bool | `true` |  |
| `enable-dynamic-lifecycle-manager` | Bool | `false` | ignored |
| `enable-dynamic-source-lookup-nodeport` | Bool | `def.NodePortEnableDynamicSourceLookup` |  |
| `enable-egress-gateway` | Bool | `false` |  |
| `enable-encryption-strict-mode-egress` | Bool | `false` |  |
| `enable-encryption-strict-mode-ingress` | Bool | `false` |  |
| `enable-endpoint-health-checking` | Bool | `true` |  |
| `enable-endpoint-lockdown-on-policy-overflow` | Bool | `false` |  |
| `enable-endpoint-routes` | Bool | `false` | immutable |
| `enable-envoy-config` | Bool | `false` |  |
| `enable-extended-ip-protocols` | Bool | `false` |  |
| `enable-gateway-api` | Bool | `false` |  |
| `enable-gops` | Bool | `def.EnableGops` | ignored |
| `enable-health-check-loadbalancer-ip` | Bool | `false` |  |
| `enable-health-check-nodeport` | Bool | `true` |  |
| `enable-health-checking` | Bool | `true` |  |
| `enable-heartbeat` | Bool | `false` |  |
| `enable-host-firewall` | Bool | `false` | immutable |
| `enable-host-legacy-routing` | Bool | `false` |  |
| `enable-hubble` | Bool | `false` |  |
| `enable-hubble-open-metrics` | Bool | `false` |  |
| `enable-icmp-rules` | Bool | `true` |  |
| `enable-identity-mark` | Bool | `true` |  |
| `enable-ingress-controller` | Bool | `false` |  |
| `enable-ip-masq-agent` | Bool | `false` |  |
| `enable-ipip-termination` | Bool | `false` |  |
| `enable-ipsec` | Bool | `false` | immutable |
| `enable-ipsec-key-watcher` | Bool | `true` |  |
| `enable-ipsec-xfrm-state-caching` | Bool | `true` |  |
| `enable-ipv4` | Bool | `true` | immutable |
| `enable-ipv4-big-tcp` | Bool | `false` |  |
| `enable-ipv4-fragment-tracking` | Bool | `true` | immutable |
| `enable-ipv4-masquerade` | Bool | `true` |  |
| `enable-ipv6` | Bool | `true` | immutable |
| `enable-ipv6-big-tcp` | Bool | `false` |  |
| `enable-ipv6-fragment-tracking` | Bool | `true` | immutable |
| `enable-ipv6-masquerade` | Bool | `true` |  |
| `enable-ipv6-ndp` | Bool | `false` |  |
| `enable-k8s` | Bool | `true` |  |
| `enable-k8s-api-discovery` | Bool | `false` |  |
| `enable-k8s-cluster-network-policy` | Bool | `false` |  |
| `enable-k8s-networkpolicy` | Bool | `true` |  |
| `enable-l2-announcements` | Bool | `false` |  |
| `enable-l2-neigh-discovery` | Bool | `false` |  |
| `enable-l2-pod-announcements` | Bool | `false` |  |
| `enable-l7-proxy` | Bool | `true` | immutable |
| `enable-local-node-route` | Bool | `true` |  |
| `enable-local-redirect-policy` | Bool | `false` |  |
| `enable-masquerade-to-route-source` | Bool | `false` |  |
| `enable-mke` | Bool | `false` |  |
| `enable-monitor` | Bool | `true` |  |
| `enable-nat46x64-gateway` | Bool | `false` |  |
| `enable-no-service-endpoints-routable` | Bool | `true` |  |
| `enable-node-ipam` | Bool | `r.EnableNodeIPAM` |  |
| `enable-node-selector-labels` | Bool | `false` |  |
| `enable-non-default-deny-policies` | Bool | `true` |  |
| `enable-pmtu-discovery` | Bool | `false` |  |
| `enable-policy` | String | `default` |  |
| `enable-policy-secrets-sync` | Bool | `mc.EnablePolicySecretsSync` |  |
| `enable-remote-node-masquerade` | Bool | `false` |  |
| `enable-route-mtu-for-cni-chaining` | Bool | `false` |  |
| `enable-sctp` | Bool | `false` |  |
| `enable-service-topology` | Bool | `false` |  |
| `enable-srv6` | Bool | `false` |  |
| `enable-stale-cilium-endpoint-cleanup` | Bool | `true` |  |
| `enable-standalone-dns-proxy` | Bool | `false` |  |
| `enable-tcx` | Bool | `true` | immutable |
| `enable-tracing` | Bool | `false` | runtime |
| `enable-unreachable-routes` | Bool | `false` |  |
| `enable-vtep` | Bool | `false` |  |
| `enable-well-known-identities` | Bool | `true` |  |
| `enable-wireguard` | Bool | `false` | immutable |
| `enable-xdp-prefilter` | Bool | `false` |  |
| `enable-xt-socket-fallback` | Bool | `true` | ignored |
| `enable-ztunnel` | Bool | `false` |  |
| `encrypt-node` | Bool | `false` |  |
| `encryption-strict-egress-allow-remote-node-identities` | Bool | `false` |  |
| `encryption-strict-egress-cidr` | String | `` |  |
| `endpoint` | String | `` | script |
| `endpoint-bpf-prog-watchdog-interval` | Duration | `30 * time.Second` |  |
| `endpoint-gc-interval` | Duration | `5 * time.Minute` |  |
| `endpoint-policy-update-timeout` | Duration | `10 * time.Second` |  |
| `endpoint-queue-size` | Int | `25` |  |
| `endpoint-regen-interval` | Duration | `2 * time.Minute` |  |
| `eni-delete-on-termination` | Bool | `true` |  |
| `eni-disable-prefix-delegation` | Bool | `false` |  |
| `eni-exclude-interface-tags` | StringToString | `map[string]string{}` |  |
| `eni-first-interface-index` | Int | `0` |  |
| `eni-security-group-tags` | StringToString | `map[string]string{}` |  |
| `eni-security-groups` | StringSlice | `[]string{}` |  |
| `eni-subnet-ids` | StringSlice | `[]string{}` |  |
| `eni-subnet-tags` | StringToString | `map[string]string{}` |  |
| `eni-use-primary-address` | Bool | `false` |  |
| `envoy-access-log-buffer-size` | Uint | `4096` |  |
| `envoy-access-log-enabled` | Bool | `true` |  |
| `envoy-base-id` | Uint64 | `0` |  |
| `envoy-config-retry-interval` | Duration | `15*time.Second` |  |
| `envoy-config-timeout` | Duration | `2*time.Minute` |  |
| `envoy-default-log-level` | String | `` |  |
| `envoy-http-upstream-linger-timeout` | Int | `-1` |  |
| `envoy-keep-cap-netbindservice` | Bool | `false` |  |
| `envoy-log` | String | `` |  |
| `envoy-node-locality-enabled` | Bool | `false` |  |
| `envoy-policy-restore-timeout` | Duration | `3*time.Minute` |  |
| `envoy-secrets-namespace` | String | `r.EnvoySecretsNamespace` |  |
| `envoy-xds-mode` | String | `split` |  |
| `exclude-local-address` | StringSlice | `[]string{}` |  |
| `exclude-node-label-patterns` | StringSlice | `[]string{}` |  |
| `external-envoy-proxy` | Bool | `false` |  |
| `families` | String | `ipv4/unicast,ipv6/unicast` | script |
| `fib-table-id-annotation` | Bool | `false` |  |
| `filename` | StringSlice | `nil` | script |
| `fixed-identity-mapping` | Var | `option.NewMapOptions(&option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator)` |  |
| `force-device-detection` | Bool | `false` |  |
| `format` | String | `table` | script |
| `fqdn-regex-compile-lru-size` | Uint | `1024` |  |
| `gateway-api-secrets-namespace` | String | `r.GatewayAPISecretsNamespace` |  |
| `global-ready-timeout` | Duration | `10 * time.Minute` |  |
| `gops-port` | Uint16 | `def.GopsPort` | ignored |
| `health-check-icmp-failure-threshold` | Int | `3` |  |
| `hive-log-threshold` | Duration | `100 * time.Millisecond` | ignored |
| `hive-start-timeout` | Duration | `5 * time.Minute` |  |
| `hive-stop-timeout` | Duration | `time.Minute` |  |
| `http-idle-timeout` | Uint | `0` |  |
| `http-max-grpc-timeout` | Uint | `0` |  |
| `http-normalize-path` | Bool | `true` |  |
| `http-request-timeout` | Uint | `60*60` |  |
| `http-retry-count` | Uint | `3` |  |
| `http-retry-timeout` | Uint | `0` |  |
| `http-stream-idle-timeout` | Uint | `5*60` |  |
| `hubble-disable-tls` | Bool | `true` |  |
| `hubble-drop-events` | Bool | `false` |  |
| `hubble-drop-events-extended` | Bool | `false` |  |
| `hubble-drop-events-interval` | Duration | `2 * time.Minute` |  |
| `hubble-drop-events-rate-limit` | Int64 | `1` |  |
| `hubble-drop-events-reasons` | StringSlice | `def.K8sDropEventsReasons` |  |
| `hubble-dynamic-metrics-config-path` | String | `` |  |
| `hubble-event-buffer-capacity` | Int | `observeroption.Default.MaxFlows.AsInt()` |  |
| `hubble-event-queue-size` | Int | `0` |  |
| `hubble-export-aggregation-interval` | Duration | `0` |  |
| `hubble-export-allowlist` | String | `` |  |
| `hubble-export-denylist` | String | `` |  |
| `hubble-export-fieldaggregate` | StringSlice | `[]string{}` |  |
| `hubble-export-fieldmask` | StringSlice | `[]string{}` |  |
| `hubble-export-file-compress` | Bool | `false` |  |
| `hubble-export-file-max-backups` | Int | `5` |  |
| `hubble-export-file-max-size-mb` | Int | `10` |  |
| `hubble-export-file-path` | String | `` |  |
| `hubble-flowlogs-config-path` | String | `` |  |
| `hubble-listen-address` | String | `` |  |
| `hubble-lost-event-send-interval` | Duration | `hubbleDefaults.LostEventSendInterval` |  |
| `hubble-metrics` | String | `` |  |
| `hubble-metrics-server` | String | `` |  |
| `hubble-metrics-server-enable-tls` | Bool | `false` |  |
| `hubble-metrics-server-tls-cert-file` | String | `` |  |
| `hubble-metrics-server-tls-client-ca-files` | StringSlice | `[]string{}` |  |
| `hubble-metrics-server-tls-key-file` | String | `` |  |
| `hubble-monitor-events` | StringSlice | `[]string{}` |  |
| `hubble-network-policy-correlation-enabled` | Bool | `true` |  |
| `hubble-prefer-ipv6` | Bool | `false` |  |
| `hubble-redact-enabled` | Bool | `false` |  |
| `hubble-redact-http-headers-allow` | StringSlice | `[]string{}` |  |
| `hubble-redact-http-headers-deny` | StringSlice | `[]string{}` |  |
| `hubble-redact-http-urlquery` | Bool | `false` |  |
| `hubble-redact-http-userinfo` | Bool | `true` |  |
| `hubble-skip-unknown-cgroup-ids` | Bool | `true` |  |
| `hubble-socket-path` | String | `hubbleDefaults.SocketPath` |  |
| `hubble-tls-cert-file` | String | `cfg.TLSCertFile` |  |
| `hubble-tls-client-ca-files` | StringSlice | `cfg.TLSClientCAFiles` |  |
| `hubble-tls-key-file` | String | `cfg.TLSKeyFile` |  |
| `identity-allocation-mode` | String | `kvstore` | immutable |
| `identity-allocation-sync-interval` | Duration | `5 * time.Minute` |  |
| `identity-allocation-timeout` | Duration | `2 * time.Minute` |  |
| `identity-change-grace-period` | Duration | `5 * time.Second` |  |
| `identity-management-mode` | String | `agent` |  |
| `identity-max-jitter` | Duration | `30 * time.Second` |  |
| `identity-restore-grace-period` | Duration | `30 * time.Second` |  |
| `ignore-flags-drift-checker` | StringSlice | `[]string{}` |  |
| `ingress` | Bool | `false` | script |
| `ingress-secrets-namespace` | String | `r.IngressSecretsNamespace` |  |
| `install-iptables-rules` | Bool | `true` | ignored |
| `install-no-conntrack-iptables-rules` | Bool | `false` |  |
| `install-uplink-routes-for-delegated-ipam` | Bool | `false` |  |
| `instance` | String | `` | script |
| `ip-masq-agent-config-path` | String | `/etc/config/ip-masq-agent` |  |
| `ip-tracing-option-type` | Uint8 | `0` |  |
| `ipam` | String | `cluster-pool` | immutable |
| `ipam-cilium-node-update-rate` | Duration | `15*time.Second` |  |
| `ipam-default-ip-pool` | String | `default` |  |
| `ipam-max-allocate` | Int | `0` |  |
| `ipam-min-allocate` | Int | `0` |  |
| `ipam-multi-pool-pre-allocation` | Var | `option.NewMapOptions(&option.Config.IPAMMultiPoolPreAllocation)` |  |
| `ipam-pre-allocate` | Int | `0` |  |
| `ipam-static-ip-tags` | StringToString | `map[string]string{}` |  |
| `ipsec-key-file` | String | `` |  |
| `ipsec-key-rotation-duration` | Duration | `5 * time.Minute` |  |
| `iptables-lock-timeout` | Duration | `5 * time.Second` | ignored |
| `iptables-random-fully` | Bool | `false` | ignored |
| `ipv4-native-routing-cidr` | String | `` |  |
| `ipv4-node` | String | `auto` |  |
| `ipv4-pod-subnets` | StringSlice | `[]string{}` |  |
| `ipv4-range` | String | `auto` | immutable |
| `ipv4-service-loopback-address` | String | `169.254.42.1` |  |
| `ipv4-service-range` | String | `auto` |  |
| `ipv6-cluster-alloc-cidr` | String | `IPv6ClusterAllocCIDRBase + "/64"` | immutable |
| `ipv6-mcast-device` | String | `` |  |
| `ipv6-native-routing-cidr` | String | `` |  |
| `ipv6-node` | String | `auto` |  |
| `ipv6-pod-subnets` | StringSlice | `[]string{}` |  |
| `ipv6-range` | String | `auto` | immutable |
| `ipv6-service-loopback-address` | String | `fe80::1` |  |
| `ipv6-service-range` | String | `auto` |  |
| `k8s-api-server-urls` | StringSlice | `[]string{}` |  |
| `k8s-client-burst` | Int | `20` |  |
| `k8s-client-connection-keep-alive` | Duration | `30 * time.Second` |  |
| `k8s-client-connection-timeout` | Duration | `30 * time.Second` |  |
| `k8s-client-qps` | Float32 | `10.0` |  |
| `k8s-heartbeat-timeout` | Duration | `30 * time.Second` |  |
| `k8s-kubeconfig-path` | String | `` |  |
| `k8s-namespace` | String | `` |  |
| `k8s-require-ipv4-pod-cidr` | Bool | `false` |  |
| `k8s-require-ipv6-pod-cidr` | Bool | `false` |  |
| `k8s-service-proxy-name` | String | `` |  |
| `k8s-sync-timeout` | Duration | `3 * time.Minute` |  |
| `keep-config` | Bool | `false` |  |
| `keys-only` | Bool | `false` | script |
| `kube-proxy-replacement` | Bool | `false` | immutable |
| `kube-proxy-replacement-healthz-bind-address` | String | `` |  |
| `kvstore` | String | `defaultBackend` |  |
| `kvstore-lease-ttl` | Duration | `15 * time.Minute` |  |
| `kvstore-max-consecutive-quorum-errors` | Uint | `2` |  |
| `kvstore-opt` | StringToString | `make(map[string]string)` |  |
| `l2-announcements-lease-duration` | Duration | `15*time.Second` |  |
| `l2-announcements-renew-deadline` | Duration | `5*time.Second` |  |
| `l2-announcements-retry-period` | Duration | `2*time.Second` |  |
| `l2-pod-announcements-interface-pattern` | String | `` |  |
| `label-prefix-file` | String | `` |  |
| `labels` | StringSlice | `[]string{}` |  |
| `lb-init-wait-timeout` | Duration | `1 * time.Minute` |  |
| `lb-pressure-metrics-interval` | Duration | `5 * time.Minute` |  |
| `lb-reflector-wait-time` | Duration | `500 * time.Millisecond` |  |
| `lb-retry-backoff-max` | Duration | `time.Minute` |  |
| `lb-retry-backoff-min` | Duration | `time.Second` |  |
| `lb-sock-terminate-all-protos` | Bool | `false` |  |
| `lb-state-file` | String | `` |  |
| `lb-state-file-interval` | Duration | `time.Second` |  |
| `lb-test-fault-probability` | Float32 | `def.TestFaultProbability` |  |
| `levels` | StringSlice | `[]string{types.LevelOK, types.LevelDegraded, types.LevelStopped}` | script |
| `lib-dir` | String | `/var/lib/cilium` | immutable |
| `local-max-addr-scope` | String | `fmt.Sprintf("%d", defaults.AddressScopeMax)` |  |
| `local-router-ipv4` | String | `` |  |
| `local-router-ipv6` | String | `` |  |
| `log-driver` | StringSlice | `[]string{}` |  |
| `log-opt` | Var | `option.NewMapOptions(&option.Config.LogOpt)` |  |
| `log-system-load` | Bool | `false` |  |
| `lrp-address-matcher-cidrs` | StringSlice | `[]string{}` |  |
| `match` | String | `` | script |
| `max-connected-clusters` | Uint32 | `255` | immutable |
| `max-controller-interval` | Uint | `0` |  |
| `max-internal-timer-delay` | Duration | `0 * time.Second` |  |
| `mesh-auth-enabled` | Bool | `false` |  |
| `mesh-auth-gc-interval` | Duration | `5 * time.Minute` |  |
| `mesh-auth-queue-size` | Int | `1024` |  |
| `mesh-auth-signal-backoff-duration` | Duration | `1 * time.Second` |  |
| `metrics` | StringSlice | `metrics` |  |
| `metrics-sampling-interval` | Duration | `5 * time.Minute` |  |
| `mke-cgroup-mount` | String | `` |  |
| `monitor-aggregation` | String | `None` | runtime |
| `monitor-aggregation-flags` | StringSlice | `[]string{"syn", "fin", "rst"}` |  |
| `monitor-aggregation-interval` | Duration | `5*time.Second` |  |
| `monitor-queue-size` | Int | `0` |  |
| `mtu` | Int | `0` |  |
| `multicast-enabled` | Bool | `false` |  |
| `nat-map-stats-entries` | Int | `32` |  |
| `nat-map-stats-interval` | Duration | `30 * time.Second` |  |
| `no-age` | Bool | `false` | script |
| `no-uptime` | Bool | `false` | script |
| `node-encryption-opt-out-labels` | String | `node-role.kubernetes.io/control-plane` |  |
| `node-labels` | StringSlice | `[]string{}` |  |
| `node-port-acceleration` | String | `disabled` |  |
| `node-port-bind-protection` | Bool | `true` |  |
| `node-port-range` | StringSlice | `[]string{fmt.Sprintf("%d", NodePortMinDefault), fmt.Sprintf("%d", NodePortMaxDefault)}` |  |
| `nodeport-addresses` | StringSlice | `nil` |  |
| `num` | Int | `10` | script |
| `only-masquerade-default-pool` | Bool | `false` |  |
| `out` | String | `` | script |
| `output` | String | `plain` | script |
| `packetization-layer-pmtud-mode` | String | `plpmtudModeBlackhole.String()` |  |
| `password` | String | `` | script |
| `per-cluster-ready-timeout` | Duration | `15 * time.Second` |  |
| `policy-accounting` | Bool | `true` |  |
| `policy-audit-mode` | Bool | `false` | runtime |
| `policy-cidr-match-mode` | StringSlice | `[]string{}` |  |
| `policy-default-local-cluster` | Bool | `true` |  |
| `policy-deny-response` | String | `none` |  |
| `policy-queue-size` | Uint | `100` |  |
| `policy-secrets-namespace` | String | `mc.PolicySecretsNamespace` |  |
| `policy-secrets-only-from-secrets-namespace` | Bool | `mc.PolicySecretsOnlyFromSecretsNamespace` |  |
| `policy-trigger-interval` | Duration | `1 * time.Second` |  |
| `pprof` | Bool | `def.Pprof` | ignored |
| `pprof-address` | String | `def.PprofAddress` | ignored |
| `pprof-block-profile-rate` | Int | `def.PprofBlockProfileRate` | ignored |
| `pprof-mutex-profile-fraction` | Int | `def.PprofMutexProfileFraction` | ignored |
| `pprof-port` | Uint16 | `def.PprofPort` | ignored |
| `preallocate-bpf-maps` | Bool | `true` | immutable |
| `prefer-ipv6` | Bool | `false` |  |
| `prepend-iptables-chains` | Bool | `true` | ignored |
| `procfs` | String | `/proc` |  |
| `prometheus-serve-addr` | String | `` |  |
| `proxy-admin-port` | Int | `0` |  |
| `proxy-cluster-max-connections` | Uint32 | `1024` |  |
| `proxy-cluster-max-pending-requests` | Uint32 | `1024` |  |
| `proxy-cluster-max-requests` | Uint32 | `1024` |  |
| `proxy-connect-timeout` | Uint | `2` |  |
| `proxy-gid` | Uint | `1337` |  |
| `proxy-idle-timeout-seconds` | Int | `60` |  |
| `proxy-initial-fetch-timeout` | Uint | `30` |  |
| `proxy-max-active-downstream-connections` | Int64 | `50000` |  |
| `proxy-max-concurrent-retries` | Uint32 | `128` |  |
| `proxy-max-connection-duration-seconds` | Int | `0` |  |
| `proxy-max-requests-per-connection` | Int | `0` |  |
| `proxy-portrange-max` | Uint16 | `20000` |  |
| `proxy-portrange-min` | Uint16 | `10000` |  |
| `proxy-prometheus-port` | Int | `0` |  |
| `proxy-use-original-source-address` | Bool | `true` |  |
| `proxy-xff-num-trusted-hops-egress` | Uint32 | `0` |  |
| `proxy-xff-num-trusted-hops-ingress` | Uint32 | `0` |  |
| `rate` | Bool | `false` | script |
| `read-cni-conf` | String | `` |  |
| `restore` | Bool | `true` |  |
| `restored-proxy-ports-age-limit` | Uint | `15` |  |
| `route-metric` | Int | `0` |  |
| `router-id` | String | `` | script |
| `routing-mode` | String | `tunnel` | immutable |
| `sampled` | Bool | `false` | script |
| `server-name` | String | `` | script |
| `service-no-backend-response` | String | `reject` |  |
| `skip-crd-creation` | Bool | `false` | renamed (inventory row `SkipCRDCreation`) |
| `socket-path` | String | `RuntimePath + "/cilium.sock"` | immutable |
| `srv6-encap-mode` | String | `reduced` |  |
| `standalone-dns-proxy-server-port` | Int | `10095` |  |
| `state-dir` | String | `/var/run/cilium` | immutable |
| `static-cnp-path` | String | `` |  |
| `status-collector-failure-threshold` | Duration | `1 * time.Minute` |  |
| `status-collector-interval` | Duration | `5 * time.Second` |  |
| `status-collector-probe-check-timeout` | Duration | `5 * time.Minute` |  |
| `status-collector-stackdump-path` | String | `/run/cilium/state/agent.stack.gz` |  |
| `status-collector-warning-threshold` | Duration | `15 * time.Second` |  |
| `subject` | Bool | `false` | script |
| `subnet-topology` | String | `` | dynamic |
| `timeout` | Duration | `30 * time.Second` | script |
| `tofqdns-dns-reject-response-code` | String | `refused` |  |
| `tofqdns-enable-dns-compression` | Bool | `true` |  |
| `tofqdns-endpoint-max-ip-per-hostname` | Int | `1000` |  |
| `tofqdns-idle-connection-grace-period` | Duration | `0 * time.Second` |  |
| `tofqdns-max-deferred-connection-deletes` | Int | `10000` |  |
| `tofqdns-min-ttl` | Int | `0` |  |
| `tofqdns-pre-cache` | String | `` |  |
| `tofqdns-preallocate-identities` | Bool | `true` |  |
| `tofqdns-proxy-port` | Int | `0` |  |
| `tofqdns-proxy-response-max-delay` | Duration | `100 * time.Millisecond` |  |
| `trace-payloadlen` | Int | `128` |  |
| `trace-payloadlen-overlay` | Int | `192` |  |
| `trace-sock` | Bool | `true` | runtime |
| `tunnel-port` | Uint16 | `0` | immutable |
| `tunnel-protocol` | String | `vxlan` | immutable |
| `tunnel-source-port-range` | String | `0-0` |  |
| `underlay-protocol` | String | `auto` |  |
| `use-cilium-internal-ip-for-ipsec` | Bool | `false` |  |
| `use-full-tls-context` | Bool | `false` |  |
| `values-only` | Bool | `false` | script |
| `version` | Bool | `false` |  |
| `vlan-bpf-bypass` | StringSlice | `[]string{}` |  |
| `vtep-cidr` | StringSlice | `[]string{}` |  |
| `vtep-endpoint` | StringSlice | `[]string{}` |  |
| `vtep-mac` | StringSlice | `[]string{}` |  |
| `vtep-mask` | String | `255.255.255.0` |  |
| `vtep-sync-interval` | Duration | `1 * time.Minute` |  |
| `wireguard-persistent-keepalive` | Duration | `0` |  |
| `wireguard-track-all-ips-fallback` | Bool | `false` |  |
| `with-attrs` | Bool | `false` | script |
| `write-cni-conf-when-ready` | String | `` |  |
| `xds-node-id` | String | `` |  |
| `xds-server-address` | String | `` |  |
| `xds-use-sotw-protocol` | Bool | `true` |  |
| `ztunnel-endpoint-event-channel-buffer-size` | Int | `1` |  |

### 6.5 Keys accepted and ignored

| Key(s) | Reason |
|---|---|
| `install-iptables-rules`, `iptables-lock-timeout`, `iptables-random-fully`, `prepend-iptables-chains`, `disable-iptables-feeder-rules`, `enable-xt-socket-fallback`, `egress-masquerade-interfaces` | ADR-0003: no iptables; nftables residual is configured by the datapath spec's own keys. `install-no-conntrack-iptables-rules` is **not** ignored — it selects the nftables `notrack` rule set. |
| `hive-log-threshold` | ADR-0004: no lifecycle hooks to time. `hive-start-timeout`/`hive-stop-timeout` are honored (6.1). |
| `enable-dynamic-lifecycle-manager`, `dynamic-lifecycle-config` | ADR-0004: no cells to start/stop; deferred (inventory 06). |
| `enable-gops`, `gops-port`, `pprof`, `pprof-address`, `pprof-port`, `pprof-block-profile-rate`, `pprof-mutex-profile-fraction` | Go runtime facilities. flowsdn exposes `tokio-console` on a flowsdn-specific key (agent core spec). |
| `cmdref` | reference documentation generator |
| all `script` rows | not configuration |

Ignored keys still parse by kind (a malformed value is still an error) so that
a typo is caught, and appear in `GET /config` with `"effect": "ignored"`.

### 6.6 Runtime-config file — see 4.5.

### 6.7 Immutable set — the 41 keys classed `immutable` in 6.4.

Chosen because changing them with live endpoints changes BPF map layouts or
sizes (`bpf-*-max`, `preallocate-bpf-maps`, `bpf-distributed-lru`,
`bpf-map-dynamic-size-ratio`, `bpf-policy-map-max`, `bpf-lb-map-max`),
address families and ranges (`enable-ipv4/6`, `ipv4/6-range`,
`ipv6-cluster-alloc-cidr`), encapsulation and routing (`routing-mode`,
`tunnel-protocol`, `tunnel-port`, `enable-endpoint-routes`,
`enable-bpf-masquerade`), identity space (`cluster-id`, `cluster-name`,
`max-connected-clusters`, `identity-allocation-mode`), IPAM mode (`ipam`),
link type (`datapath-mode`), LB hashing (`bpf-lb-maglev-*`,
`kube-proxy-replacement`, `bpf-lb-sock`), attach mode (`enable-tcx`), state
paths (`state-dir`, `lib-dir`, `bpf-root`, `cgroup-root`, `socket-path`), or
program feature sets (`enable-wireguard`, `enable-ipsec`,
`enable-host-firewall`, `enable-l7-proxy`, `enable-ipv*-fragment-tracking`).
Area specs MAY add keys to the set; they MUST NOT remove these.

### 6.8 Runtime options — see 3.3.8.  6.9 Dynamic keys — see 3.3.6.

## 7. Failure modes

| Failure | Behavior |
|---|---|
| Unknown config key | warn once, continue, list in `GET /config` (3.3.4) |
| Known key, unparsable value (any source) | fatal at startup: `option <key>: <error>` |
| Cross-key validation error | fatal at startup, names the key(s) |
| `--config-dir` given but missing | fatal |
| `--config` given but unreadable | fatal; implicit `$HOME/ciliumd.yaml` missing → silent |
| Runtime-config file unwritable | error logged, startup continues (state dir is tmpfs; the reference fails start — **DEVIATION**: continue, because the file is diagnostic only in flowsdn's schema; ADR-0004 §3) |
| Previous runtime-config unparsable | warn, skip immutability comparison |
| Immutable key changed, endpoints to restore | refuse to start, error lists keys (3.3.9); without endpoints: error log, continue |
| Immutable key changed detected mid-run | impossible by construction; `validate-unchanged-daemon-config` controller always OK |
| Dynamic-config reflector cannot reach the API server | table stays at last state; drift checker keeps last verdict; health `Degraded` on `agent.dynamic-config` after `k8s-heartbeat-timeout` |
| Drift detected | health `Degraded` on `agent.drift-checker` listing keys; no automatic reload |
| Table unique-index violation | write returns `Err`, table unchanged, caller decides (LB writer: log + skip frontend; reference logs `frontend ownership conflict`) |
| Change-stream consumer too slow | forced `Resync` (3.1.7); consumer must prune |
| Reconciler `update` fails | status `Error`, retry with backoff, health `Degraded` with count; other rows unaffected |
| Reconciler `prune` fails | logged, health `Degraded`, retried at next prune interval |
| Fence waiter times out (fatal bound) | agent exits non-zero with `<fence>: <waiter>: timeout` |
| Fence waiter times out (non-fatal bound) | fence released, owner module `Degraded`, startup continues |
| Module `start()` errors | agent exits non-zero; state on disk untouched |
| Health history file unwritable | warn once; in-memory table unaffected |
| Restart mid-operation | tables are rebuilt from sources; reconcilers restore realized state from targets (maps) before first reconcile; revisions restart at 0 |
| Upgrade with new keys | new keys default; old unknown keys warn |
| Upgrade with a key removed by flowsdn | key moved to `ignored` with a changelog entry; never removed from the table |

## 8. Observability

### 8.1 Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `flowsdn_table_objects` gauge | `table` | rows |
| `flowsdn_table_tombstones` gauge | `table` | retained tombstones |
| `flowsdn_table_revision` gauge | `table` | current revision |
| `flowsdn_table_write_duration_seconds` histogram | `table` | write lock hold time |
| `flowsdn_table_resync_total` counter | `table`, `stream` | forced resyncs |
| `flowsdn_reconciler_duration_seconds` histogram | `module`, `name`, `op=update|delete|prune` | operation latency |
| `flowsdn_reconciler_errors_current` gauge | `module`, `name` | rows in retry queue |
| `flowsdn_reconciler_errors_total` counter | `module`, `name` | failed operations |
| `flowsdn_reconciler_prune_duration_seconds`, `flowsdn_reconciler_prune_errors_total` | `module`, `name` | |
| `cilium_hive_status` gauge | `level` | health rows per level (name kept) |
| `cilium_hive_degraded_status` gauge | `module` | degraded rows per module (name kept) |
| `cilium_controllers_runs_total`, `cilium_controllers_runs_duration_seconds`, `cilium_controllers_failing`, `cilium_controllers_group_runs_total` | as reference | the `validate-unchanged-daemon-config` and `write-cni-file` controllers report here |
| `flowsdn_config_unknown_keys` gauge | — | count of unknown keys |
| `flowsdn_config_drift_keys` gauge | — | keys drifted per drift checker |

### 8.2 Logs

`subsys=table`, `subsys=config`, `subsys=fence`, `subsys=health`. Fields:
`table`, `key`, `configKey`, `configSource`, `name` (fence waiter), `remaining`,
`duration`, `error`. Config load logs every key whose effective source is not
`default` at debug level and every override (`Source overrides key`) at info,
matching the resolver's messages.

### 8.3 Health

Modules defined by this spec: `agent.config` (OK after freeze; Degraded on
unwritable runtime-config), `agent.dynamic-config`, `agent.drift-checker`,
`agent.table.<name>` (Degraded when a stream was force-resynced in the last
prune interval), `agent.<owner>.<reconciler>` (3.2.1).

### 8.4 Status API surfacing

- `GET /healthz` `StatusResponse.cilium` derived per 3.4.2; `controllers[]`
  includes the registry's controllers; module health does not have a field in
  the swagger `StatusResponse` at this tag, so it is exposed as:
- `GET /statedb/query` **compatibility route, `health` table only**: accepts
  the `QueryRequest` JSON body used by `statedb.RemoteTable` (`{"table":
  "health","index":"id","key":<base64 key>,"lowerbound":bool}`) and streams
  `{"rev": n, "obj": HealthStatus}` JSON objects (one per row; a terminal
  `{"err": "<message>"}` object on failure), Content-Type `application/json`. This is what `cilium-dbg status`
  calls after printing the status to render "Modules Health" (it queries
  `LowerBound("agent")`). Any other table returns 404. **DEVIATION** from the
  ADR's "no HTTP dump": one read-only table for one known client; no `dump`,
  no `changes`. Open decision 12.5.
- `GET /health/modules` (flowsdn-native, JSON array of `HealthStatus`) for
  `flowsdn-dbg` and humans.
- `GET /config` `status.daemon-configuration-map` carries every key (canonical
  name → effective value), `sources`, `unknown-keys`, `immutable`
  (the runtime-immutable subset, as the reference's `immutable` object),
  `realized.options` (runtime options).

## 9. Test plan

Unit unless marked. **priv** = needs root/netlink/BPF; **e2e** = cluster.

Table store:
- [ ] insert/upsert/delete revisions increase by one; failed conditional write consumes no revision
- [ ] unique secondary violation leaves table unchanged (all indexes)
- [ ] non-unique index `list` returns primary-key order; multi-key indexer (labels) indexes each key
- [ ] `prefix`/`lower_bound` ordering on u32, u64, addr (v4 and v6 interleaved), composite keys
- [ ] snapshot isolation: reader holds snapshot across 10k writes, sees none
- [ ] `watch(0)` yields all rows then live changes; deletion arrives as tombstone
- [ ] coalescing: 100 writes to one key before drain → one change with latest revision
- [ ] tombstone retained until slowest stream acks; GC after ack; re-insert cancels tombstone
- [ ] forced resync by count and by age; `Resync` precedes inserts; metrics increment
- [ ] initializers: `initialized()` false until all marked; `wait_initialized` wakes
- [ ] concurrency (loom or stress): N writers on one table serialize; no lost update; readers never see partial index state
- [ ] property test: table state equals a `BTreeMap` model after random op sequences; every change stream, when applied to an empty mirror, converges to the table (with resyncs)
- [ ] memory: 1M rows of 64 B; snapshot cost; bench insert/get/prefix (target ≥ 1M inserts/s single-threaded, informational)

Reconciler:
- [ ] Pending → Done on success; Error with message on failure; retry count and next_retry follow 100 ms·2^n capped at max
- [ ] status write discarded when desired row changed during the operation (id mismatch); new revision processed
- [ ] deletes processed before updates in a round; batch target receives one call each
- [ ] prune not called before initialized; called once on init and per interval; `prune_now` coalesces
- [ ] refresh marks rows older than interval as Refreshing at the configured rate
- [ ] `wait_until_reconciled` returns attempted revision and retry low-water mark; both advance
- [ ] health OK/Degraded transitions with error count
- [ ] fault injection (probability p) against an in-memory target converges (mirrors `lb-test-fault-probability` tests)
- [ ] end-to-end with a fake BPF map target: LB frontend table → map entries, prune removes stale, restart restores IDs (shared fixture with the LB spec)

Config registry:
- [ ] all 539 keys registered; defaults equal 6.4; no duplicates after normalization
- [ ] precedence: flag > env > dir > file > default, one key set at every layer
- [ ] normalization: `enable_ipv4`, `ENABLE-IPV4` file names, `CILIUM_ENABLE_IPV4` resolve to `enable-ipv4`
- [ ] deprecated alias mapped only when canonical absent
- [ ] every kind parses its accepted forms and rejects garbage (table-driven); Duration bare-integer warning
- [ ] List splitting: `foo,bar`, `"foo bar"`, `foo,bar baz`, env and flag repetition
- [ ] Map validators for `fixed-identity-mapping`, `bpf-map-event-buffers`
- [ ] unknown key → warning, listed, not fatal; `script` keys likewise; ignored keys still type-checked
- [ ] config-dir: symlinked `..data` layout, directory entries skipped, unreadable file skipped, missing dir fatal
- [ ] cross-key validation table 3.3.7, one negative test per rule
- [ ] runtime-config written, rotated `-1`/`-2`, content matches 4.5; unwritable → continues
- [ ] immutability: previous file with changed `routing-mode` + endpoint dir → refuse; without endpoint dir → warn; unparsable previous → skip
- [ ] `build-config`: source order, allow/deny lists, CiliumNodeConfig selector nil/empty/matching, lexicographic merge warning, node label and annotation prefix, atomic directory layout, path-separator keys refused (fixtures from the reference's `resolver_test.go` cases)
- [ ] dynamic-config priority function against the reference's `getPriorityForKey` cases; `get_key` picks lowest priority
- [ ] drift checker: drifted key → Degraded listing it; ignored key not reported
- [ ] `GET /config` payload includes sources, unknown keys, immutable subset (golden JSON)
- [ ] **e2e**: upstream `cilium-dbg config` and `cilium-dbg config Debug=enable` against flowsdn; Helm-rendered `cilium-config` ConfigMap loads with zero unknown-key warnings for the default chart

Fences and health:
- [ ] fence with no waiters resolves; add-after-seal panics in debug; duplicate name rejected
- [ ] waiter error aborts with `<name>: <err>`; cancellation propagates
- [ ] composite `regeneration` fence releases only when all sub-fences released
- [ ] non-fatal timeout releases fence and degrades owner; fatal timeout exits
- [ ] health: first report creates row; `stopped` keeps level and sets timestamps; `close` removes; `new_scope` id joining; `count` increments
- [ ] history file appended per event, rotated at size
- [ ] metrics `cilium_hive_status{level}` and `cilium_hive_degraded_status{module}` match table
- [ ] readiness derivation table 3.4.2, one case per row (brief and full)
- [ ] `/statedb/query` compat: `cilium-dbg status` renders Modules Health against flowsdn (**e2e**); other tables 404
- [ ] startup-order integration test with fake k8s and fake datapath: fences release in the documented order; a stuck `k8s-caches` waiter fails after `k8s-sync-timeout`

## 10. Kernel and platform requirements

None for the table store, config registry, fences or health: pure userspace,
arch-neutral. Requires a writable `<state-dir>/state` (tmpfs is fine; ~100 KB
for runtime-config files and up to 30 MB for health history). `build-config`
needs Kubernetes API access (ConfigMap get, CiliumNodeConfig list, Node get).
x86-64 and arm64 identical; no `unsafe` in these crates.

## 11. Rust design notes

Crates (workspace members, all `#![forbid(unsafe_code)]`):

- **`flowsdn-table`** — `Table<T: Send + Sync + 'static>`, `Indexer<T>`,
  `Snapshot<T>`, `ChangeStream<T>`, `Change<T>`, key-encoding helpers
  (`key::u32be`, `key::addr`, `key::prefix`, `key::str`, `key::composite`),
  `Initializers`. Persistent maps: **`imbl`** (`OrdMap`, maintained fork of
  `im`, MIT/MPL-2.0 — allowed) for `by_key`, `by_rev`, indexes and
  tombstones. Publication via `arc_swap::ArcSwap<Version>`; writer lock
  `tokio::sync::Mutex`; notifier `tokio::sync::watch::Sender<Revision>`
  (single value = current revision; every stream holds a `Receiver` and calls
  `changed().await` then drains — this gives coalescing for free and no
  unbounded queue). Metrics via `metrics` facade (`prometheus` exporter in the
  agent). Trait `Keyed { fn primary_key(&self) -> Bytes }` for rows.
  Alternative considered: `rpds` (persistent maps, MPL-2.0) — comparable;
  `imbl` chosen for `OrdMap::range` and `Arc`-based sharing (`imbl` is
  thread-safe by default; `im`'s `Rc` variant is not).
- **`flowsdn-table::reconciler`** (module, same crate) — `Reconciler<T,
  Tgt: Target<T>>`, `Target` trait (`update`, `delete`, `prune`, optional
  `update_batch`/`delete_batch` default-implemented over the singles),
  `ReconcileStatus`, `RetryQueue` (two `BinaryHeap`s + `HashMap` as in 5.4),
  `Options`. Runs on `tokio`; rate limiting with `governor` or a hand-rolled
  token bucket (`governor` is MIT).
- **`flowsdn-config`** — `KeySpec` table as a `const` array generated from a
  `keys.toml` (name, kind, default, class, help) by a build script that also
  emits the typed `Config` struct and its `From<Resolved>`; a unit test
  asserts the array has exactly the 539 names of section 6.4. Layers:
  `clap` (derive disabled; the flag set is generated from `KeySpec` with
  `Arg::new(name).long(name)` so help text and hidden flags stay in one
  place), `std::env`, dir reader, `serde_yaml` for the file. **Hand-rolled
  layering** rather than `figment`: figment's profile/merge model does not
  express "warn on unknown key", per-kind parsing of raw strings, or source
  attribution per key, which are the three things this registry must do;
  `serde` is used for the runtime-config JSON (`serde_json`) and for the
  `config-sources` JSON. `Options` (runtime-mutable) is a separate
  `Arc<RwLock<…>>` handed to the REST layer and endpoint manager.
  `build-config` uses `kube` (`kube-client` + `k8s-openapi`) and writes the
  atomic directory with `std::fs` + `symlink`.
- **`flowsdn-fence`** — `Fence` = `Vec<(&'static str, Pin<Box<dyn Future<Output=Result<(),
  FenceError>> + Send>>)>` behind a `Mutex`, plus `sealed: AtomicBool`; waiters
  are usually `tokio::sync::watch::Receiver<bool>` or `oneshot` wrappers
  (`Fence::watch_waiter(name, rx)`) and `tokio::time::timeout` for bounds.
  `wait()` uses `futures::future::try_join_all`-style sequential awaiting to
  keep the log order deterministic. No dependency on the table crate.
- **`flowsdn-health`** — `HealthRegistry` wrapping a `flowsdn_table::Table<HealthStatus>`,
  `HealthReporter` (cheap clone, holds `Arc<Registry>` + `Identifier`),
  `Identifier` (`SmallVec<[Arc<str>; 4]>`), history writer (append-only file
  with size rotation, `serde_json` lines), Prometheus gauges. The
  `/statedb/query` compat route and `/health/modules` live in the REST crate
  and read this registry.

Key traits and types shared with area crates: `Keyed`, `Indexer<T>`,
`Target<T>`, `HealthReporter`, `Fence`, `Config` (the typed struct),
`Options`. Nothing in these crates depends on aya, netlink or kube except
`build-config` (kube), which lives behind a feature flag so the agent's
foundation crates stay small.

Sizing estimate (Rust, incl. tests): table + reconciler ~3.5k, config
registry + generator + build-config ~3k, fence + health ~1k.

## 12. Open decisions

1. **Resolved by ADR-0008 (#42): whole-table notifiers.** Per-key watches remain deferred until profiling establishes a need. Original alternatives: whole-table notifiers (3.1.5) vs. per-key wakeups.
   Options: (a) table-level only; (b) add `watch_key` implemented by a
   per-key `Notify` map populated on demand. Recommendation: (a) now; revisit
   if dynamic-config or ipcache consumers show wakeup storms in profiling.
2. **Resolved by ADR-0009 (#43): separate reconciliation status.** Original alternatives: (a) side table (this spec);
   (b) embed `ReconcileStatus` in rows as the reference does, simpler for
   `GET /service`. Recommendation: (a); the LB REST handler joins two tables,
   which is trivial with shared primary keys.
3. **Immutable-key change with endpoints present: refuse or warn.**
   (a) refuse (this spec); (b) warn and continue, relying on the datapath's own
   incompatibility detection. Recommendation: (a), matching the reference's
   `datapath-mode` precedent; provide `--force-config-change` escape hatch
   (flowsdn-specific key, defaults false) for operators who drained by hand.
4. **Read Cilium's `agent-runtime-config.json` for in-place migration.**
   The reference file is PascalCase field names of `DaemonConfig`. (a) ignore
   it (this spec: warn "unparsable previous", skip); (b) implement a one-time
   translator for the immutable subset. Recommendation: (a) unless the
   migration story (agent core spec open question 1) commits to live
   Cilium → flowsdn swaps.
5. **`/statedb/query` compat for the `health` table.** (a) provide it (this
   spec) so upstream `cilium-dbg status` prints module health; (b) drop it and
   accept that `cilium-dbg status` prints the status but exits with a
   "Failed while streaming remote health data table" error when health
   checking is enabled — which makes the upstream tool unusable, so (b) is not
   really an option; (c) also serve `/statedb/dump` for `cilium-dbg statedb`.
   Recommendation: (a); (c) only if `flowsdn-dbg` is delayed.
6. **Resolved (#47/#90, ADR-0011): `lb-retry-backoff-max` is `1m`.**
   The §6.4 registry follows spec 05 §6; `lb-retry-backoff-min` remains `1s`.
7. **Unknown keys: warn vs. fail in CI.** Add a `--strict-config` flowsdn key
   (default false) that turns unknown keys into a fatal error, for CI charts.
   Recommendation: yes, S effort.
8. **Resolved (#49): duration bare integers are nanoseconds with a warning.** The implemented parser and regression tests preserve Go's nanosecond interpretation (this spec,
   with warning) or treat bare integers as seconds. Recommendation: keep Go
   semantics for compatibility; Helm never emits bare integers for durations.

## Implementation amendment — 2026-09-08

ADR-0008 records the choices for #42 (whole-table watches) and #205 (explicit
`TableRender::headers`/`cells`). The first implementation slice supplies only
indexed snapshots and writes. Its secondary index representation is an ordered
key tuple; no zero-separator encoding leaks into exact-key query semantics.
Change streams, tombstone retention, initialization, metrics and reconciliation
remain pending. The core's range-query APIs currently return collected rows;
streaming range iterators may replace those allocations before scale tuning.
