# Scripttest harness (`flowsdn-scripttest`) — specification

Status: draft. Derived from: `docs/decisions/0005-test-strategy.md`,
`docs/inventory/README.md`, the harvested corpus at
`tests/scripttest/corpus/` (168 files, 29 areas), reference cilium v1.20.1
(7d68cfb394) paths `vendor/github.com/cilium/hive/script/**`,
`vendor/github.com/cilium/hive/{hive,script}.go`,
`vendor/github.com/cilium/statedb/script.go`,
`pkg/loadbalancer/tests/script_test.go`, `pkg/loadbalancer/maps/cmds.go`,
`pkg/loadbalancer/maps/test_utils.go`, `pkg/k8s/client/testutils/fake.go`,
`pkg/testutils/scriptnet/scriptnet.go`, `pkg/bgp/test/commands/*.go`,
`pkg/ciliumenvoyconfig/script_test.go`, and the per-area `*_test.go` command
registrations enumerated in §3.3. Governed by ADR-0001..0005.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes
*what* flowsdn does and the exact data it exchanges. It does not transcribe
reference code. Where the reference behavior is kept for compatibility, say
so and name the consumer that depends on it. Where flowsdn deviates, mark
**DEVIATION** with the reason and the ADR.

---

## 1. Scope

`flowsdn-scripttest` is the Rust test harness that executes the harvested
txtar corpus. It is the first of the four harnesses named in ADR-0005 §3 and
by a wide margin the highest leverage: 168 scenario files, 1444 embedded
fixtures, covering load balancing, BGP, policy, IPAM, clustermesh, Envoy
config, Hubble export, device/route/neighbor reconciliation and the
Kubernetes reflection layer — all runnable with **no per-file authoring
work**, provided the harness is faithful.

**In scope**

- The txtar container format and how embedded files become a working directory (§3.1, §4.1).
- The script language: prefixes, conditions, quoting, variable expansion, backgrounding, retry semantics (§3.2).
- The complete command registry: every one of the 118 command names that appears anywhere in the corpus, its arguments, its semantics, and the flowsdn subsystem it drives (§3.3).
- The two flowsdn-specific comparison formats the corpus depends on: the `.table` column format for `db/cmp` and the LB map-dump line format for `lb/maps-dump` (§4.2, §4.3).
- How an agent instance is constructed per script without a DI container (ADR-0004), and how `#!` flags reach `flowsdn-config` (§3.5).
- The fakes and their required fidelity (§3.6).
- The expected-divergence marker mechanism required by ADR-0005 (§3.7).
- Parallelism, isolation, temp directories, failure reporting (§3.8).
- Porting order against the build order in `docs/inventory/README.md` (§3.9).

**Out of scope**

- `flowsdn-bpftest`, `flowsdn-cptest`, `flowsdn-connectivity` — the other
  three harnesses of ADR-0005, each specified separately.
- The behavior being *asserted*. What `db/cmp services services.table` should
  contain is spec 05's problem; this spec only says how the comparison works.
- The `tools/` re-harvest script (ADR-0005 §4).
- The interactive REPL (`cilium-dbg shell` equivalent). The `break` command is
  specified because one corpus workflow documents it, but an interactive
  terminal is optional (open decision 12.7).

**Sibling specs**: 00 (table store, config registry, health), 05 (LB), 06
(policy), 07 (IPAM), 10 (devices/routes/neighbors), 11 (Hubble), 12
(operator), 13 (k8s client), 15 (BGP), 16 (Envoy/DNS).

---

## 2. Compatibility contract

The corpus is the interface. The harness MUST accept every harvested file
byte-for-byte; a re-harvest at a newer reference tag must be a `cp`.

| Interface | MUST match reference | Why / who depends on it |
|---|---|---|
| txtar container: `-- name --` marker line, comment = everything before the first marker | exactly | 168 harvested files; `golang.org/x/tools/txtar` is the de-facto format |
| `#!` first line carrying flags | exactly | 66 of 168 files carry one |
| Command prefixes `!`, `?`, `*`, `!*` and their meanings | exactly | 571 `*`-prefixed lines, 24 `!`, 11 `!*` |
| Condition syntax `[cond]`, `[!cond]`, `[prefix:suffix]` | exactly | `[privileged]`, `[!kernel-can-manage-arp-ping]` |
| `#` section semantics: a section is the retry unit | exactly | load-bearing for reconciler assertions (§3.2.6) |
| Single-quote quoting with `''` for a literal quote | exactly | `policy/import 'json'`, `grep '^pattern'` |
| `$VAR` / `${VAR}` expansion, undefined → empty | exactly | `$WORK`, `$HEALTHPORT`, `$SERVING1` |
| Generic command names and flags: `cmp -q`, `cmpenv`, `empty -q -t`, `grep --count -q`, `stdout`, `stderr`, `sed`, `replace`, `cp`, `mv`, `rm`, `mkdir`, `cat`, `echo`, `env --from-stdout`, `exec`, `sleep`, `stop`, `skip`, `wait`, `break` | exactly | used across all areas |
| `db/*` command names, flags (`--timeout`, `--grep`, `-o/--out`, `--columns`, `-f/--format`, `-i/--index`) and the `.table` column format | exactly | 616 `db/cmp` + 97 `db/empty` + 37 `db/show` invocations |
| `k8s/*` command names and flags (`--strict`, `-o/--out`, `--show-redacted`) | exactly | 325 `k8s/add` + 145 `k8s/update` + 130 `k8s/delete` |
| `lb/maps-dump` output line format (§4.3) | exactly | 106 invocations compared against `.expected` goldens |
| `db/cmp` internal retry with a 5 s default deadline | exactly | reconciler convergence; changing it turns flakes into failures |
| `*` retry interval schedule | see §3.2.6 | 571 lines |
| Environment variables `WORK`, `TMPDIR`, `DATADIR`, `PWD`, `/`, `:` | exactly | `$WORK` appears in 23 places incl. a `#!` flag value |
| `-scripttest.update` / `--update` behavior: rewrite the `.txtar` in place | exactly | the documented authoring workflow for `.table`, `.expected` and `envoy/cmp` files |

**Not** a compatibility surface: the harness's own CLI, its log format, its
diff rendering, its parallelism strategy, and every implementation detail of a
fake.

---

## 3. Behavior

### 3.1 The txtar container

A `.txtar` file is UTF-8 text with two parts.

**Part 1 — the comment**, which is *the script*. It is every byte from the
start of the file up to (not including) the first line that matches the
archive marker. If no marker exists, the entire file is the script.

**Part 2 — the archive**, a sequence of files. A file begins at a line
matching exactly

```
-- <name> --
```

The harness MUST match this as: the line, after stripping a trailing `\n`,
begins with `-- `, ends with ` --`, and the middle is the name with
surrounding whitespace trimmed. A file's data is every line after its marker
up to the next marker or end of file. A trailing newline is guaranteed to
exist on the data of every non-final file; the harness MUST NOT add or strip
one beyond what the format prescribes.

Names in the corpus are all single path segments (verified: zero names
contain `/`). The harness MUST nevertheless support nested names for
forward compatibility, creating parent directories as needed.

**Materialization.** Before the first command runs, the harness MUST, for each
archive file in order:

1. Expand `$VAR` in the *name* against the script environment.
2. Resolve the name against the working directory.
3. Reject (fail the script) any name that resolves outside the working
   directory, comparing against the working directory path with a trailing
   separator appended, so that `/work-other` is not accepted for `/work`.
4. Create parent directories (mode 0777 & ~umask).
5. Write the data (mode 0666 & ~umask), truncating.

Archive data is **not** variable-expanded. Expansion of *contents* happens
only in `cmpenv` and in the expected file read by `db/cmp` (§4.2).

**The `#!` line.** If the script's first line begins with `#!`, everything
after `#!` up to the first `\n`, trimmed, split on single spaces, is the
**flag vector** for this script's agent instance (§3.5). The line remains part
of the script and is *also* interpreted as an ordinary `#` section comment,
which means it opens the first section. 66 of the 168 harvested files carry
one; `k8sclient/fake.txtar` carries a bare `#!` (empty vector) and
`loadbalancer/*.txtar` carries `#! ` with a trailing space — splitting on `" "`
yields one empty-string argument, which the flag parser MUST tolerate and
ignore. Flag values may contain `$WORK`, which MUST be substituted with the
script's working directory before parsing (`loadbalancer/file.txtar`:
`--lb-state-file=$WORK/state.yaml`).

### 3.2 The script language

#### 3.2.1 Lines

The script is processed line by line, `\n`-separated, with a final line
lacking `\n` still interpreted.

- A line whose first character is `#` is a **section comment**. It starts a new
  section (§3.2.6) and is logged verbatim. No command runs.
- A blank line, or a line containing only whitespace and a `#` comment, is
  ignored and does not affect section boundaries.
- Any other line is a **command line**.

#### 3.2.2 Tokenizing a command line

Tokens are separated by any of space, tab, carriage return, newline, or `#`.
An unquoted `#` terminates the line (end-of-line comment).

Single quotes group text: inside a quoted run, separators are literal and
variable expansion is disabled. Two consecutive single quotes inside a quoted
run produce one literal single quote (`'Don''t'` → `Don't`). An unterminated
quote is a parse error.

A token is assembled from fragments, each marked quoted or unquoted. Unquoted
fragments are variable-expanded at run time (§3.2.5); quoted fragments are
not. Fragments concatenate without separators, so `'a'b` is one token `ab`
whose first half is literal.

#### 3.2.3 Prefixes

The leading tokens of a command line, before the command name, may be
prefixes. Each prefix token MUST be a single unquoted fragment.

| Prefix | Name | Meaning |
|---|---|---|
| *(none)* | `Success` | the command must succeed |
| `!` | `Failure` | the command must fail; succeeding is an error |
| `?` | `SuccessOrFailure` | either outcome is accepted; the script continues |
| `*` | `SuccessRetry` | retry the whole section until the command succeeds (§3.2.6) |
| `!*` | `FailureRetry` | retry the whole section until the command fails |

At most one status prefix per line; a second is a parse error. `?` does not
appear in the corpus but MUST be supported.

**Status checking.** After a command runs:

- No error and status is `Failure`/`FailureRetry` → error `unexpected success`.
- An error that is a *stop* sentinel → propagate as-is (halts the script, script passes).
- An error surfaced from `wait` on background commands → propagate as-is, ignoring the line's own status.
- An error and status is `Success`/`SuccessRetry` → the command failed.
- An error and status is `Failure`/`FailureRetry`, but the error is a context cancellation or deadline → still a failure. A negative assertion must not be satisfied by the harness giving up.
- Otherwise the error was expected: log it and continue.

#### 3.2.4 Conditions

Prefix tokens of the form `[tag]` guard the line: it runs only if the
condition holds. `[!tag]` negates. Multiple conditions on one line all must
hold. `[tag:suffix]` selects a *prefix condition*, whose evaluator receives
the suffix; using a suffix with a non-prefix condition, or omitting one from a
prefix condition, is an error, as is an unknown tag. An empty `[]` is a parse
error.

Conditions used in the corpus:

| Tag | Kind | True when | Files |
|---|---|---|---|
| `privileged` | bool | the harness runs with the privileges to create netns/links/BPF maps (effective uid 0, or `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_BPF`) | 5 lines in `loadbalancer/`, gating `stop` and metrics assertions |
| `kernel-can-manage-arp-ping` | bool | the running kernel supports kernel-managed ARP ping (`NTF_MANAGED` neighbor entries, ≥ 5.16) | `neighbor/neighbor-reconciler-kernel-arp.txtar` |

The harness MUST additionally provide, for forward compatibility with a
re-harvest at a newer tag:

| Tag | Kind | True when |
|---|---|---|
| `root` | bool | effective uid is 0 |
| `linux`, `darwin` | bool | target OS (**DEVIATION**: reference spells these `GOOS:linux`; flowsdn accepts both `[linux]` and `[os:linux]`) |
| `amd64`, `arm64` | bool | target arch (also `[arch:amd64]`) |
| `exec:<name>` | prefix, cached | `<name>` is on the harness process's `PATH` |
| `short` | bool | the run requested short tests |
| `verbose` | bool | the run requested verbose output |
| `kernel:<ver>` | prefix, cached | running kernel ≥ `<ver>` (flowsdn addition; see §3.7) |
| `divergence:<id>` | prefix | the named expected divergence is active (§3.7) |

Condition results for `exec:`, `kernel:` and any other process-global
predicate MUST be computed once per harness process and cached, since scripts
run in parallel.

#### 3.2.5 Variable expansion

Unquoted fragments are expanded with `$name` and `${name}` syntax against the
script's environment map. An undefined name expands to the empty string. A
command may declare that specific argument positions are *regexp arguments*
(`grep`, `stdout`, `stderr`, `sed`, `metrics`, `metrics/plot` — always "the
first argument that does not begin with `-`, or the one after `--`"), in which
case expanded values are regex-quoted so a path cannot become a pattern.

The environment always contains:

| Name | Value |
|---|---|
| `WORK` | the script's working directory (absolute) |
| `PWD` | the current working directory, updated by `cd` |
| `TMPDIR` | `$WORK/tmp`, created before the script starts |
| `DATADIR` | the directory the `.txtar` was read from — i.e. `tests/scripttest/corpus/<area>` |
| `/` | the platform path separator |
| `:` | the platform path-list separator |

`/` and `:` MUST NOT be exported to subprocesses. All other variables MUST be.
Setting a variable replaces any previous binding.

#### 3.2.6 Sections and retry — the load-bearing part

A **section** is the run of command lines since the most recent `#` line (or
since the start of the script). Sections exist for two reasons: log grouping,
and **retry scope**.

When a command whose status prefix is `*` or `!*` does not meet its
expectation, the harness MUST NOT retry that command alone. It MUST re-run
**every command in the current section, in order, from the beginning**, and
keep doing so until either the whole section runs through with all
expectations met, or the script's context is cancelled.

This is why the corpus is written the way it is. A typical assertion block is

```
# Check BPF maps
lb/maps-dump lbmaps.actual
* cmp lbmaps.expected lbmaps.actual
```

The retry re-runs `lb/maps-dump`, refreshing `lbmaps.actual` from the live map
state, and only then re-compares. Retrying `cmp` alone would spin forever on a
stale file. **Any implementation that retries only the marked command is
wrong** and will hang 106 load-balancer assertions.

Retry timing:

| Property | Value |
|---|---|
| First wait | `retry_interval` |
| Subsequent waits | previous × 2, capped at `max_retry_interval` |
| `retry_interval` default | 100 ms |
| `max_retry_interval` default | 500 ms |
| Load-balancer suite override (reference) | 20 ms / 500 ms |
| Overall bound | **none of its own** — retry continues until the script context is cancelled |

The absence of a per-command deadline is deliberate: the bound is the
per-script timeout (§3.8.3). The harness MUST log, before each retry, the
command that failed and the delay about to elapse, and on success log the
retry count and total elapsed time, so a slow-but-passing script is visible.

`s.RetryCount` MUST be exposed to commands: `db/cmp` and `envoy/cmp` change
their update-mode behavior based on it (§3.4).

Sections also carry timing: the harness SHOULD emit the section header, then
the elapsed seconds when the section closes, then the accumulated log for
that section — suppressing the log for a successful section when running
quietly.

#### 3.2.7 Backgrounding and `wait`

A command line whose last token is a bare unquoted `&` runs in the background.
Only commands declared *async* may be backgrounded; backgrounding any other is
an error. A backgrounded command's stdout/stderr are not published; the
harness clears both buffers.

`wait` (no arguments) waits for every background command in start order,
logging each one's output, concatenating their stdouts into the stdout buffer
and their stderrs into the stderr buffer, applying each command's own status
expectation, and clearing the background list. Errors from several background
commands are joined.

At the end of a script the harness MUST cancel the context and perform an
implicit `wait`, and MUST report an error if any background command ended in
an unexpected state.

*No harvested file uses `&` or `wait`.* Both are specified because the format
requires them and a re-harvest may introduce them; implementing them is
cheap.

#### 3.2.8 stdout / stderr buffers

Every foreground command may publish a stdout string and a stderr string.
These replace the buffers; they are readable by the `stdout`, `stderr`, `cmp`,
`cmpenv`, `empty` and `cp` commands under the pseudo-names `stdout` and
`stderr`. A command that publishes nothing leaves the buffers as the previous
command left them **only if it produced no wait function at all**; a command
that runs and produces empty output clears them.

#### 3.2.9 Halting

- `stop [msg]` halts the script immediately and the script **passes**. Used by
  `neighbor/neighbor-reconciler-kernel-arp.txtar` to skip on old kernels and
  by three `loadbalancer/` scripts under `[privileged]`.
- `skip [msg]` halts the script and marks it **skipped**.
- Any unmet expectation halts the script and marks it **failed**; no
  subsequent command runs.

### 3.3 Command registry

Every command name below was extracted mechanically from the first token of
every command line in all 168 harvested files, after stripping status and
condition prefixes. Counts are corpus invocation counts. A command the corpus
never uses but that belongs to a registered group is marked *(unused)* and is
still REQUIRED, because the groups are registered wholesale and a re-harvest
will reach them.

#### 3.3.1 Generic — always registered

| Command | Args / flags | Semantics | Uses |
|---|---|---|---|
| `cmp` | `file1 file2`, `-q/--quiet` | Byte-compare. `file1` may be `stdout`/`stderr`. By convention file1 is actual, file2 expected, but three `loadbalancer` scripts pass expected first — the command is symmetric, so the harness MUST NOT assume an order. On mismatch: log a unified diff (unless `-q`) and fail. Honors update mode (§3.4). | 416 |
| `cmpenv` | as `cmp` | As `cmp`, but expands `$VAR` in **both** texts before comparing. | *(unused)* |
| `empty` | `file`, `-q/--quiet`, `-t/--trim` | Assert the file (or `stdout`/`stderr`) is empty. `-t` strips leading/trailing newlines first. On failure log a diff against `<empty>`. | 16 |
| `grep` | `'pattern' file`, `--count=N`, `-q` | Multiline (`(?m)`) regex search in a file. Succeeds on ≥1 match, or exactly `N` with `--count`. Logs the matched line unless `-q`. Arg 0 is a regexp arg. | 81 |
| `stdout` | `'pattern'`, `--count=N`, `-q` | Same, over the stdout buffer. | 38 |
| `stderr` | `'pattern'`, `--count=N`, `-q` | Same, over the stderr buffer. | *(unused)* |
| `cat` | `files...` | Concatenate to the stdout buffer. | 1 |
| `cp` | `src... dst` | Copy files; `src` may be `stdout`/`stderr`. Multiple sources require `dst` to be a directory. | 43 |
| `mv` | `old new` | Rename. | 2 |
| `rm` | `path...` | Remove recursively, chmod-ing unwritable directories first. | *(unused)* |
| `mkdir` | `path...` | Create directories including parents. | *(unused)* |
| `cd` | `dir` | Change the script's working directory; updates `PWD`. | *(unused)* |
| `chmod` | `perm paths...` | Numeric mode only. | *(unused)* |
| `exists` | `file...`, `--readonly`, `--exec` | Assert existence and optionally non-writability / executability. | *(unused)* |
| `symlink` | `path -> target` | Create a symlink. | *(unused)* |
| `replace` | `[old new]... file` | Literal string replacement, applied in one pass. `old`/`new` are unescaped as if Go-quoted, so `\n` and `\t` work. Odd argument count required. | 104 |
| `sed` | `regexp replacement file` | Regex replace **line by line** (the file is split on `\n`, each line substituted, rejoined). Arg 0 is a regexp arg. `$1`-style capture references in `replacement`. | 78 |
| `echo` | `string...` | Space-joined, newline-terminated, to stdout buffer. | 1 |
| `env` | `[key[=value]...]`, `--from-stdout` | With no args: dump the environment to stdout. `key=value` sets. Bare `key` prints `key=value`. `--from-stdout` sets each named key to the trimmed stdout buffer. | 23 |
| `exec` | `program args...` | Run a subprocess in the working directory with the script environment. Publishes its stdout and stderr. Async: may be backgrounded. On context cancel: send SIGINT, wait a grace period (100 ms default), then SIGKILL. | 76 |
| `sleep` | `duration` | Sleep a Go-style duration (`10ms`, `1s`, `1m`). Async. Cancellable. | 14 |
| `stop` | `[msg]` | Halt, script passes. | 5 |
| `skip` | `[msg]` | Halt, script skipped. | *(unused)* |
| `wait` | — | Wait for background commands (§3.2.7). | *(unused)* |
| `break` | — | Drop into an interactive prompt (§3.8.5). | *(unused)* |
| `help` | `[regex]`, `-v` | List commands and usage to the log. Also reachable as `-h`/`--help` on any command. | *(unused)* |

`exec` in `datapath-linux/*.txtar` runs only `ip link add|set`, `ip addr add`
and `ip route add` — 76 invocations, all `iproute2`. These scripts are
privileged and run inside a dedicated network namespace (§3.6.4).

#### 3.3.2 Agent lifecycle

| Command | Args | Semantics |
|---|---|---|
| `hive` | `[start\|stop]` | With `start`/`stop`: an alias for the commands below (backwards compatibility; **115 corpus uses are all `hive start`/`hive stop`**). With no arguments: print the object graph. **DEVIATION**: flowsdn has no DI container (ADR-0004), so the no-argument form prints the fixture's component list, start-hook order and fence graph (spec 00 §3.4.1) instead. Nothing in the corpus asserts on that output. |
| `hive/start` | — | Start the agent instance: run every start hook in registration order under a 60 s deadline. 57 uses. |
| `hive/stop` | — | Stop it: run stop hooks in reverse order under a 60 s deadline. 17 uses. |
| `hive/recreate` | `[flags...]` | Tear down the agent instance and build a fresh one, **retaining the fake Kubernetes API and the BPF map state, discarding all in-memory tables**. This models an agent restart across a process boundary. The instance MUST already be stopped. Extra flags override the `#!` vector for the replacement instance. 6 uses (`loadbalancer`, `device`, `neighbor`, `route-reconciler`). |

`hive/recreate` also re-registers the command table: the new instance's
commands replace the old ones in the engine, while the generic commands and
the k8s commands (which are bound to the *retained* fake client, not the
per-instance one) are re-inserted. Getting this wrong silently keeps a
dangling reference to the dead instance's tables and produces assertions that
never converge.

#### 3.3.3 Table store — `flowsdn-table` (spec 00)

All names, flags and formats are compatibility surface.

| Command | Args / flags | Semantics | Uses |
|---|---|---|---|
| `db` | — | Describe the store: one row per table with name, object count, tombstone count, index names, pending initializers, row type and last-writer info. | 2 |
| `db/cmp` | `table file`, `--timeout=<dur>` (default **5 s**), `--grep=<re>` | Compare the table against a `.table` file (§4.2), **retrying internally** until equal or the timeout expires. Retries are driven by the table's change watch, not by polling. On timeout, fail with a rendered row-level diff. Honors update mode. | **616** |
| `db/show` | `table`, `-o/--out=file`, `--columns=a,b`, `-f/--format=table\|yaml\|json` | Render the whole table. `--columns` is table-format only. | 37 |
| `db/empty` | `table...` | Assert each named table has zero rows. Note: **no internal retry** — the corpus wraps 88 of the 97 uses in `*`. | 97 |
| `db/insert` | `table path...` | Deserialize each YAML file into a row and insert it. | 58 |
| `db/delete` | `table path...` | Deserialize each YAML file far enough to build the primary key, and delete. | 11 |
| `db/get` | `table key`, `-i/--index=`, `-o`, `--columns`, `-f`, `--delete` | First row matching the key. | 17 |
| `db/list` | `table key`, same flags | All rows matching the key. | 6 |
| `db/prefix` | `table key`, same flags | All rows whose key starts with `key`. | 12 |
| `db/lowerbound` | `table key`, same flags | All rows with key ≥ `key`. | *(unused)* |
| `db/initialized` | `[table...]`, `--timeout=` (default 5 s) | Block until all (or the named) tables report initialized. | 11 |
| `db/watch` | `table` | Stream changes. | *(unused)* |
| `db/dump` | `-o/--out=` | Dump the whole store as JSON. | *(unused)* |

For query commands, arguments beginning with `-` are stably sorted to the
front before flag parsing, so `db/get foo -i name` and `db/get -i name foo`
are equivalent; a key that legitimately starts with `-` must be quoted.

**Requirement on spec 00.** `db/cmp`, `db/show` and the query commands need
each row type to expose an ordered column header and an ordered vector of
rendered cells. Spec 00's `flowsdn-table` does not currently specify such a
trait. This spec REQUIRES adding one — working name `TableRender` with
`fn header() -> &'static [&'static str]` and `fn row(&self) -> Vec<String>` —
and it must be implemented for every table any harvested script inspects (see
§3.9 for the per-milestone list). Recorded as open decision 12.1.

#### 3.3.4 Fake Kubernetes (spec 13)

| Command | Args / flags | Semantics | Uses |
|---|---|---|---|
| `k8s/add` | `files...` | Load YAML (single or multi-document, `kubectl get -o yaml` shape), determine each object's GVR from `apiVersion`+`kind`, and add it to the object trackers. Objects are offered to every tracker (typed, slim, CRD); success in any one is success. | 325 |
| `k8s/update` | `files...`, `--strict` | As above but update. Default is a patch-style update that ignores resource-version conflicts; `--strict` enables optimistic concurrency and fails on conflict (`k8sclient/conflicts.txtar`). | 145 |
| `k8s/delete` | `files...` | Delete the objects named by the files. | 130 |
| `k8s/get` | `resource ns/name`, `-o/--out=`, `--show-redacted=resource-version,uid` | Fetch one object, marshal as YAML. `resource` accepts `v1.pods`, `pods`, or a close match — the harness MUST log which resource it resolved to when the match is inexact. By default `metadata.resourceVersion` and `metadata.uid` are redacted, because they are non-deterministic; `--show-redacted` un-redacts the named fields (`k8sclient/redact.txtar`, `k8sclient/uid.txtar`). | 28 |
| `k8s/list` | `resource namespace`, same flags | List; empty namespace means all. | 4 |
| `k8s/resync` | `resource [files...]` | Atomically close every watch on the resource, drop all tracked objects of it, insert the replacements, and restart the watches at a new revision. Models an API-server relist. Logs the number of watches restarted, the new revision and the replacement count. | 3 |
| `k8s/summary` | `[out-file]` | Per tracker, per resource, the object count. | 2 |
| `k8s/resources` | — | List known resources. | *(unused)* |
| `k8s/svc/update-status` | `ns/name file` | Write a Service `.status` through the status subresource. Registered by the k8s-client suite only. | 1 |

#### 3.3.5 Load balancer (spec 05)

| Command | Args / flags | Semantics | Uses |
|---|---|---|---|
| `lb/maps-dump` | `[out-file]` | Dump every LB BPF map in the line format of §4.3, sorted. To stdout, or to a file. When a fault-injecting wrapper is installed it MUST be bypassed — a dump must never fail. | 106 |
| `lb/maps-empty` | — | Assert the dump is empty. Test-only. | 35 |
| `lb/maps-snapshot` | — | Copy the current map contents into an in-memory snapshot held by the fixture. Test-only. | 3 |
| `lb/maps-restore` | `--any-proto` | Write the snapshot back **without clearing first**. `--any-proto` rewrites backends to protocol ANY, modelling a pre-upgrade agent's maps (`loadbalancer/migrate-any-proto.txtar`). Test-only. | 3 |
| `lb/prune` | — | Trigger a full prune of the LB maps. | 6 |
| `skiplbmap` | `file` | Dump the SkipLB map to a file. | 14 |
| `svc/set-proxy-redirect` | `ns/name [proxy-port]` | Set (or clear) a service's proxy-redirect port, simulating a local Envoy listener. Registered by both the health-server and BGP suites. | 2 |

#### 3.3.6 Test hooks

Registered only when the fixture is in test mode. These reach past the public
API into the writer / local node store, which is exactly why they exist.

| Command | Args | Semantics | Uses |
|---|---|---|---|
| `test/init-wait` | — | Block until the LB subsystem's initialization wait function returns. | 8 |
| `test/update-backend-health` | `ns/name backend-addr healthy` | Set one backend's health flag directly. `backend-addr` parses as `addr:port/proto`. | 6 |
| `test/set-node-labels` | `key=value...` | Replace the local node's label set. | 7 |
| `test/set-node-ip` | `ip` | Set the local node's single external IP. | 1 |
| `test/set-is-service-healthchecked` | `annotation` | Install a predicate that treats a service as health-checked iff it carries the named annotation with a non-empty value. | 1 |
| `test/bpfops-reset` | — | Reset the LB reconciler's in-memory ID bookkeeping and restore it from the maps. Models a restart of just that component. | 2 |
| `test/bpfops-summary` | — | Print the reconciler's internal state summary to stdout. | 3 |
| `set-node-labels` | `key=value...` | The Envoy-config suite's own copy of `test/set-node-labels`, registered under a bare name. | 2 |

#### 3.3.7 Netlink, privileged (spec 10)

All of these operate on the script's own network namespace (§3.6.4).

| Command | Args | Uses |
|---|---|---|
| `netns/create` | `<name>` — create an ephemeral namespace | 11 |
| `netns/switch` | `<name>` — make it current for subsequent commands | *(unused)* |
| `netns/list` | — | *(unused)* |
| `link/add` | `<name> <type>` (`dummy`, `veth`, `vlan`, `bridge`, …; type-specific `key=value` follow) | 20 |
| `link/set` | `<name> [key[=value]]...` (`up`, `down`, `master=`, `mtu=`, `netns=`, `addr=`) | 44 |
| `link/del` | `<name>` | 1 |
| `link/list` | — | *(unused)* |
| `addr/add` | `<address> <interface>` | 29 |
| `route/add` | `<destination>` plus `key=value` (`via=`, `dev=`, `table=`, `priority=`, `proto=`) | 9 |
| `route/replace` | as `route/add` | 1 |
| `route/del` | as `route/add` | 3 |
| `route/list` | — | 9 |
| `sysctl/set` | `<parameter parts...> <value>` | 5 |
| `sysctl/get` | `<parameter parts...>` | *(unused)* |

#### 3.3.8 Reconciler drivers (spec 10, spec 15)

| Command | Args | Semantics | Uses |
|---|---|---|---|
| `add-device` | `owner device-file` | Insert a desired device (YAML) attributed to an owner. | 10 |
| `add-route` | `owner route-file` | Insert a desired route attributed to an owner. | 11 |
| `add-owner` | `name` | Register a route owner. | 9 |
| `remove-owner` | `name` | Deregister an owner; its objects must be withdrawn. | 4 |
| `add-initializer` | `name` | Register a table initializer, holding the table un-initialized. | 2 |
| `finish-initializer` | `name` | Complete it. | 2 |
| `forwardable-ip/register-initializer` | `name` | Same, for the forwardable-IP table. | 1 |
| `forwardable-ip/finish-initializer` | `name` | Same. | 1 |
| `reconciler/init` | `instance-name` | Initialize one BGP reconciler under test in isolation. | 2 |
| `reconciler/reconcile` | `instance-name` | Run one reconcile pass synchronously. | 8 |
| `reconciler/cleanup` | `instance-name` | Tear the instance down. | 2 |

#### 3.3.9 BGP (spec 15)

Cilium-side observation:

| Command | Args / flags | Uses |
|---|---|---|
| `bgp/peers` | `[-o/--out=file] [--format=] [--no-uptime]` — list peers; `--no-uptime` suppresses the non-deterministic column | 5 |
| `bgp/routes` | `<table type> <afi> <safi>`, `[--no-age]` — list routes from `available`/`advertised` tables | 7 |
| `bgp/route-policies` | `[-o/--out=] [-i/--instance=]` | 11 |

Peer-side control of real GoBGP instances. **DEVIATION**: flowsdn will not
embed a Go BGP daemon. §3.6.6 specifies the replacement.

| Command | Args / flags | Uses |
|---|---|---|
| `gobgp/add-server` | `asn ip port`, `[-r] [--router-id=]` | 30 |
| `gobgp/delete-server` | `name` | 1 |
| `gobgp/add-peer` | `ip remote-asn`, `[-s] [--server-asn=]` | 30 |
| `gobgp/wait-state` | `peer state`, `[-s -t] [--server-asn=] [--timeout=]` | 32 |
| `gobgp/peers` | `[-o -s] [--out=] [--server-asn=]` | 11 |
| `gobgp/routes` | `[afi] [safi]`, `[-o -s] [--out=] [--server-asn=]` | 97 |
| `gobgp/advertise-route` | `<prefix>` | 8 |

The `#!` flag `--test-peering-ips=<csv>` allocates the peering addresses for a
script. **The harness MUST reject duplicate peering IPs across concurrently
scheduled scripts**, because these tests peer over real TCP on real
addresses; upstream fails setup loudly on a duplicate and so must flowsdn.

#### 3.3.10 Policy, identity, endpoints (specs 03, 06, 08)

| Command | Args | Uses |
|---|---|---|
| `policy/import` | `'policy'` — a JSON policy rule set as a single quoted argument | 10 |
| `policy/remove` | `'policy'` — labels selecting rules to remove | 2 |
| `policy/lookup-flow` | `from-id to-id proto port` — the verdict for a flow between two numeric identities | 6 |
| `policyrepo/selectorcache` | — dump the selector cache model | 6 |
| `policyrepo/list` / `policyrepo/add` / `policyrepo/bump-revision` | — | *(unused)* |
| `identity/allocate` | `labels` | 12 |
| `identity/list`, `identity/release` | `[numeric-id]` | *(unused)* |
| `endpoint/create` | `'id' 'labels'` | 9 |
| `endpoint/delete` | `id` | 2 |
| `endpoint/regen-all` | `policy-rev` | 5 |
| `endpoint/wait-for-policy-revision` | `policy-rev` | 7 |
| `endpoint/list` | — | *(unused)* |

#### 3.3.11 kvstore and clustermesh (spec 12)

| Command | Args / flags | Uses |
|---|---|---|
| `kvstore/update` | `key value-file` | 22 |
| `kvstore/delete` | `key` | 6 |
| `kvstore/list` | `prefix [out-file]`, `-o/--output=plain\|json`, `--keys-only`, `--values-only` — keys sorted; each key printed as `# <key>` unless `--values-only`; values transcoded to JSON where the key's schema is known | 84 |

#### 3.3.12 IPAM (spec 07)

| Command | Args | Uses |
|---|---|---|
| `ipam/start` | — run the IPAM initializer's configure-and-start | 1 |
| `ipam/restore-endpoint` | `ip-address owner` | 6 |
| `ipam/restore-finished` | — | 1 |
| `ipam/allocate` | `owner` — allocate the next pod IPs from the default pool | 14 |
| `ipam/dump` | `output-file` | 1 |
| `allocator/allocated-pools` | `node-name` — operator multi-pool allocator state | 2 |

#### 3.3.13 Observability (spec 00, spec 11)

| Command | Args / flags | Uses |
|---|---|---|
| `metrics` | `[match-regex]`, `-o/--out=`, `-s/--sampled`, `-f/--format=table\|json\|yaml` — the regex arg is regex-quoted on expansion | 16 |
| `metrics/plot` | `[match-regex]`, `-o/--out=`, `--rate` — ASCII line graph of a sampled series | 1 |
| `metrics/html` | `-o/--out=` — HTML page of the sampled series | 1 |
| `health` | `[reporter-id-prefix]` — log the health reporter tree | 7 |
| `health/ok` | `[reporter-id-prefix]` — fail if anything is degraded | 4 |
| `health/history` | — | 1 |
| `config/add` | `file` — add/update a Hubble exporter configuration | 7 |
| `config/delete` | `file` | 7 |
| `event/send` | `file` — feed one flow event to all active exporters | 17 |
| `exporters/count` | `expected` — assert the number of active exporters | 2 |
| `file/read` | `source dest` — copy an exporter output file into the working directory for comparison | 7 |
| `file/exists` | `path` | 7 |

`file/read` and `file/exists` exist separately from `cp`/`exists` because
exporter output paths live outside the script working directory.

#### 3.3.14 Remaining subsystem commands

| Command | Args | Semantics | Uses |
|---|---|---|---|
| `egress/policy-maps-dump` | `[out-file]` | Dump the egress-gateway policy BPF map (spec 14). | 4 |
| `subnet/map-dump` | `[out-file]` | Dump the subnet BPF map. | 2 |
| `envoy/cmp` | `file` | Compare the fake Envoy's current xDS resource set against a sectioned expected file (§4.4). | 25 |
| `http/get` | `url file` | HTTP GET into a file; used against the NodePort health server. | 18 |
| `example/hello` | `name` | Tutorial command. | 1 |
| `example/counts` | — | Tutorial command. | 1 |

The `example` area exists to exercise the framework itself and MUST be the
harness's own smoke test (§9.1).

### 3.4 Update mode

The harness MUST support an `--update` mode (reference spelling
`-scripttest.update`), which is how `.table`, `.expected` and `envoy/cmp`
files are authored.

Semantics:

1. `cmp`, `db/cmp` and `envoy/cmp`, on mismatch and with update enabled,
   record `expected-file-name → actual-content` in a per-script update map and
   **succeed** instead of failing.
2. `cmp` MUST refuse to update when either side is empty, logging a hint to
   use the `empty` command instead.
3. `cmp` MUST NOT capture the actual value on the first two retry rounds when
   the line is `*`-prefixed. It waits for `RetryCount ≥ 2` so the system has
   settled; without this, update mode records a transient state and bakes a
   race into the golden file.
4. `db/cmp` records the actual table rendering after its own internal timeout
   expires, i.e. after it has already retried for the full window.
5. `envoy/cmp` sleeps 500 ms before comparing in update mode, for the same
   reason.
6. After the script finishes, the harness rewrites the `.txtar`: for each
   recorded name that exists as an archive member, replace that member's data,
   then re-serialize the whole archive and write it back to the original path.
   Names that are not archive members are ignored. The comment (the script)
   is never modified.

Update mode MUST be off by default and MUST be refused in CI.

### 3.5 Constructing an agent instance per script

The reference builds a `hive` — a dependency-injection container — per script,
and reaches into it for the command set. **ADR-0004 removes the hive.** The
flowsdn equivalent is an explicit fixture.

#### 3.5.1 The fixture

A `Fixture` is a plain struct built by an area-specific `FixtureBuilder`:

```
Fixture {
    config:      Arc<flowsdn_config::Resolved>,   // frozen; from the #! vector
    tables:      TableSet,                        // the flowsdn-table instances
    fences:      FenceGraph,                      // spec 00 §3.4.1
    health:      HealthRegistry,
    metrics:     MetricsRegistry + Sampler,
    k8s:         Arc<FakeClient>,                 // RETAINED across recreate
    lbmaps:      Arc<dyn LbMaps>,                 // RETAINED across recreate
    netns:       Option<NetNsHandle>,             // privileged areas only
    components:  Vec<Box<dyn Component>>,         // start/stop hooks, in order
    commands:    CommandTable,
    runtime:     tokio::runtime::Runtime,         // current-thread, per script
}
```

A `Component` is the ADR-0004 replacement for a hive cell: it owns its
background tasks and exposes `start(&mut self) -> Result<()>` and
`stop(&mut self) -> Result<()>`. `hive/start` runs `start` in registration
order; `hive/stop` runs `stop` in reverse. Registration order is written once
per area, by hand, in that area's builder — this is the explicit composition
ADR-0004 asks for, and it is *shorter* than the reference's cell graph because
a test fixture wires only what the area needs.

The builder is not generic over areas: there is one builder per area
(`fixtures::loadbalancer`, `fixtures::bgp`, …), each ~50–150 lines, each
returning the command table for its area merged with the generic and k8s
tables. This is deliberate. A single "build everything" fixture would make
every script pay for every subsystem and would couple unrelated milestones.

#### 3.5.2 Flags from `#!` to `flowsdn-config`

1. Take the `#!` vector (§3.1), or an empty vector.
2. Substitute `$WORK` with the script's working directory in every element
   (textual, before parsing — the config layer never sees `$WORK`).
3. Append the extra flags given to `hive/recreate`, if any. Later wins.
4. Prepend the area's **defaults**, which are ordinary flag settings applied
   before the script's own, so a script can override them. The load-balancer
   area's defaults, taken from the reference, are:

   | Key | Value | Why |
   |---|---|---|
   | `kube-proxy-replacement` | `true` | the suite assumes KPR unless a script disables it |
   | `lb-retry-backoff-min` | `10ms` | keep reconciler retries fast under test |
   | `lb-retry-backoff-max` | `10ms` | " |
   | `bpf-lb-maglev-table-size` | `1021` | the `.expected` Maglev dumps encode this table size |

   Other areas add their own; each area's builder documents its defaults in
   one table, and a harness test asserts the tables are non-empty where the
   corpus depends on them.
5. Parse the resulting vector through the **same `flowsdn-config` key
   registry** the agent uses (spec 00 §3.3): same names, same kinds, same
   validation, same unknown-key handling. A `#!` flag naming a key that does
   not exist MUST fail the script loudly — that is the signal that a
   compatibility key is missing, and it is one of the most valuable things
   this corpus tells us.
6. Add the test-only keys the corpus uses that are not agent keys:
   `--lb-test-fault-probability` (§3.6.3) and `--test-peering-ips`
   (§3.3.9). These MUST be registered in a separate test-key registry so they
   can never leak into a production config.
7. Freeze. `hive/recreate` builds a new frozen config from step 1.

Config keys appearing in `#!` lines across the corpus — a useful early
checklist for spec 00 §6.4 — include: `bpf-lb-algorithm`,
`bpf-lb-algorithm-annotation`, `bpf-lb-external-clusterip`,
`bpf-lb-enable-wildcard-entries`, `bpf-lb-map-max`, `bpf-lb-mode`,
`bpf-lb-mode-annotation`, `bpf-lb-source-range-all-types`, `cluster-id`,
`cluster-name`, `clustermesh-default-global-namespace`,
`clustermesh-enable-mcs-api`, `clustermesh-service-v2`, `config-sources`,
`devices`, `enable-cilium-endpoint-slice`, `enable-health-check-nodeport`,
`enable-cluster-pool-to-multi-pool-migration`,
`enable-no-service-endpoints-routable`, `enable-service-topology`,
`force-device-detection`, `ipam`, `ipam-default-ip-pool`,
`kube-proxy-replacement`, `lb-pressure-metrics-interval`, `lb-state-file`,
`lb-state-file-interval`, `lrp-address-matcher-cidrs`, `metrics`,
`metrics-sampling-interval`, `probe-tcp-md5`, `synchronize-k8s-nodes`,
`use-kernel-managed-arp-ping`.

#### 3.5.3 What `hive/recreate` must and must not preserve

| Preserved | Discarded |
|---|---|
| the fake Kubernetes object trackers and their revisions | every table in `flowsdn-table` |
| the LB BPF map contents (and any other map fixture) | all reconciler in-memory state |
| the network namespace and its links/addresses/routes | the health registry, fences, metrics |
| the working directory and its files | background tasks (must be joined before rebuild) |
| the script environment | |

This division is the whole point: it is what makes "restart the agent and
check it does not churn the datapath" testable at all (`loadbalancer/resync`,
`prune-deleted-on-restart`, `reuse`, `device/persistance`,
`route-reconciler/persistance`).

### 3.6 Fakes and their required fidelity

#### 3.6.1 Fake Kubernetes client (spec 13)

The single most exercised fake: 610 corpus invocations.

MUST provide:

- Object trackers keyed by group/version/resource, holding typed objects.
  Several trackers coexist (full types, slim types, CRD types); an add is
  offered to each and succeeds if any accepts. `k8s/summary` prints them by
  name, so the tracker set is observable and must be stable.
- A monotonic revision counter, advanced on every mutation, exposed as
  `metadata.resourceVersion`.
- Watches with a start revision, delivering added/modified/deleted events in
  revision order, restartable.
- Optimistic concurrency: `k8s/update --strict` must reject a stale
  `resourceVersion` with a conflict; the default update path must not.
- Status subresource writes distinct from spec writes.
- Deterministic UIDs. `k8sclient/uid.txtar` asserts on them, so they MUST be
  derived (e.g. UUIDv5 over namespace/name/kind), not random.
- Resource-name resolution from `v1.pods`, `pods`, `Pod`, with closest-match
  fallback and a log line when the match was inexact.
- Redaction of `resourceVersion` and `uid` on `k8s/get`/`k8s/list` unless
  `--show-redacted` names them.
- `k8s/resync`: stop watches, replace contents, restart at a new revision.

MUST NOT: contact a real API server, validate against real OpenAPI schemas
(the corpus contains deliberately invalid objects), or default fields the real
API server would default — the harvested YAML is already in post-default form.

#### 3.6.2 Fake / unpinned BPF maps

Two implementations behind one trait per map family:

- **In-memory** — an ordered map with the same key and value byte layouts as
  the real map (spec 01). Used unprivileged. This is what makes 51
  load-balancer scripts runnable on a developer laptop and in unprivileged CI.
- **Real but unpinned** — actual `BPF_MAP_TYPE_*` maps created with
  `bpf(BPF_MAP_CREATE)` and *not* pinned to `/sys/fs/bpf`, so concurrent
  scripts cannot collide. Used under `[privileged]`.

Both MUST produce byte-identical `lb/maps-dump` output for the same logical
state; the harness SHOULD run a differential test asserting this (§9.3).

Required fidelity: key/value layout, iteration producing every entry exactly
once, `max_entries` enforcement returning the same error as the kernel
(`bpf-lb-map-max=1000` in one script exists to hit map pressure), and inner-map
semantics for the Maglev map-in-map.

#### 3.6.3 Fault injection

`--lb-test-fault-probability=<p>` wraps the LB map implementation so each
operation fails with probability `p`. The reference **defaults it to 0.1** and
25 scripts explicitly set `0.0`. That default is load-bearing: it is how the
suite proves the reconciler is retry-correct.

The harness MUST:

- Default to 0.1 for the load-balancer area.
- Seed the RNG **per script from a stable hash of the script's path**, so a
  failure reproduces. The seed MUST be printed on failure.
- Bypass the wrapper for `lb/maps-dump`, `lb/maps-empty`,
  `lb/maps-snapshot` and `lb/maps-restore` — assertions must never see
  injected faults.

#### 3.6.4 Network namespace (privileged areas)

`datapath-linux`, `device`, `neighbor`, `route-reconciler` and `bgp` need real
netlink. The harness MUST, for a script in one of those areas:

1. Create a fresh network namespace, named after the script.
2. Pin the executing OS thread to it for the whole script (a namespace is a
   thread property; a work-stealing runtime will silently execute netlink
   calls in the wrong namespace). This is why the per-script tokio runtime is
   **current-thread** (§3.5.1).
3. Route `netns/*`, `link/*`, `addr/*`, `route/*`, `sysctl/*` and `exec`
   through it.
4. Destroy it on exit, including on panic and on timeout.

Unprivileged runs MUST skip these areas with a clear "requires privileges"
message, not fail them.

**No fake netlink.** A fake netlink layer that is faithful enough to be worth
asserting against is as much work as the real thing and tests nothing real.
The privileged/unprivileged split is the answer.

#### 3.6.5 Fake Envoy (spec 16)

An xDS server endpoint that accepts flowsdn's resource pushes, keeps the
current resource set per type URL, ACKs, and can render itself in the sectioned
format of §4.4. It MUST count policy-trigger events (the corpus asserts on
`policy-trigger-count`). It does **not** need to be a real Envoy or to validate
resources beyond decoding them.

#### 3.6.6 BGP peer

**DEVIATION (ADR-0002).** The reference embeds GoBGP as a library. flowsdn
will not link Go. Options, in preference order:

(a) A minimal Rust BGP peer inside the harness — spec 15 already specifies a
    Rust speaker; a test peer reuses its FSM and message codecs, and the
    `gobgp/*` commands become a thin façade over it. Keeps the command names
    (compatibility surface) while dropping the Go dependency.
(b) Drive an external `gobgp`/`gobgpd` binary if present, gated on
    `[exec:gobgpd]`.

(a) is the recommendation; (b) is a useful cross-check during bring-up.
Recorded as open decision 12.4. Note the risk in (a): a bug shared between the
speaker and the test peer is invisible. Mitigate by running the 20 BGP
scripts against (b) periodically, and by keeping spec 15's separate
GoBGP/RouterOS interop suite.

#### 3.6.7 kvstore

An in-memory key/value store with prefix listing, watches and the same value
encodings as the real backend. Required by 112 invocations across
`clustermesh`, `kvstore`, `nodes-gc`, `operator-watchers`.

### 3.7 Expected-divergence markers (ADR-0005)

ADR-0005 requires that scenarios which must fail because of a deliberate
flowsdn divergence are **annotated, not deleted**, so a re-harvest still
works. Since harvested files MUST NOT be edited, the annotation lives beside
them.

**Mechanism.** A sidecar file per area:
`tests/scripttest/corpus/<area>/DIVERGENCES.toml`, written by flowsdn (not
harvested), listing entries:

```toml
[[divergence]]
id      = "no-iptables-masq"
script  = "loadbalancer/hostport.txtar"      # or "<area>/*.txtar"
adr     = "ADR-0003"
kind    = "expected-fail"                     # expected-fail | skip | partial
reason  = "asserts on an iptables masquerade rule; flowsdn uses nftables"
lines   = [42, 43]                            # optional, for kind = "partial"
```

Semantics:

| `kind` | Harness behavior |
|---|---|
| `expected-fail` | Run the script. If it fails → report **XFAIL** (not a failure). If it *passes* → report **XPASS**, which is a **failure**: the divergence is stale and the entry must be removed. |
| `skip` | Do not run. Report **SKIP** with the reason. Use only when running would hang or damage state. |
| `partial` | Run, but treat a failure originating on one of the listed line numbers as XFAIL. Any other failure is a real failure. |

Rules:

- Every entry MUST name an ADR. An entry without one is rejected at load time.
- `id` MUST be unique across the corpus and is usable as a
  `[divergence:<id>]` condition, so a *flowsdn-authored* script (never a
  harvested one) can branch on it.
- The harness prints a divergence summary at the end of a run: how many
  XFAIL, how many XPASS, and per ADR. A rising XFAIL count is a design signal
  worth reviewing.
- `DIVERGENCES.toml` files are excluded from the re-harvest.

Anticipated divergence classes at the time of writing: ADR-0003 (no iptables
rules to assert on), ADR-0002 (no Go-derived artifacts, e.g. GoBGP-specific
output shapes), ADR-0004 (`hive` with no argument prints something different),
and kernel-floor differences where the reference tolerates an older kernel.

### 3.8 Execution model

#### 3.8.1 Parallelism and isolation

- Scripts run **in parallel** by default, one task per script, with a
  concurrency limit defaulting to the CPU count.
- Each script gets its **own fixture, own tables, own maps, own fake k8s, own
  working directory, own tokio current-thread runtime**. Nothing is shared
  between scripts except read-only harness configuration and cached condition
  results.
- Privileged areas run with their own network namespace (§3.6.4).
- BGP scripts additionally reserve their `--test-peering-ips`; the harness
  MUST detect a duplicate across the whole scheduled set **before running
  anything** and fail the run with the offending pair named.
- Global mutable state is forbidden. Two places in the reference are global
  and must not be reproduced: the Kubernetes version/capability singleton and
  the node name. Both MUST be fixture fields in flowsdn. (The reference
  acknowledges this as a known defect.)
- A `--no-parallel` switch MUST exist, and MUST be implied by `break`.

#### 3.8.2 Temporary directories

Per script: a fresh directory, removed on success and **kept on failure**,
with its path printed. `$WORK` names it, `$WORK/tmp` is created and named by
`$TMPDIR`. `$DATADIR` points at the corpus area directory, so a script can
reference files it did not embed.

#### 3.8.3 Timeouts

| Level | Default | Note |
|---|---|---|
| Whole run | none | CI supplies one |
| Per script | 10 s for load balancer (reference value), 60 s otherwise | overridable per area and by `--timeout` |
| Grace period on cancel | max(100 ms, 5 % of remaining) | for subprocess cleanup |
| `hive/start`, `hive/stop` | 60 s | |
| `db/cmp`, `db/initialized` | 5 s | per invocation, overridable with `--timeout` |
| `*` retry | bounded only by the script timeout | §3.2.6 |

The per-script timeout is what actually bounds `*`. A script that hangs must
report **which section it was retrying and the last diff**, not just "timed
out" — otherwise the most common failure in this suite is undiagnosable.

#### 3.8.4 Failure reporting

On failure the harness MUST print, in this order:

1. `<file>:<line>: <command> <args>: <error>`.
2. The accumulated section log, including every `> command` line, `[stdout]`,
   `[stderr]` and `[condition not met]` marker, so the reader sees the exact
   sequence that led here.
3. For a comparison failure, a diff. For `cmp`/`empty`, a unified diff with
   file names. For `db/cmp`, a **row-level** diff in the table's own column
   layout: `  ` for equal rows, `-` for a row present in the table but not
   expected, `+` for an expected row not found — aligned so the columns line
   up (§4.2).
4. The retry count and elapsed time if the section was being retried.
5. `$WORK`, the RNG seed if fault injection was on, the flag vector, and — if
   privileged — the namespace name.
6. A hint that `--update` regenerates expected files, and that it must not be
   committed without reading the diff.

Every failure MUST be attributable to a `<file>:<line>` in the harvested
script. Line numbers are 1-based over the whole `.txtar`, including the `#!`
line, so an editor jumps to the right place.

#### 3.8.5 Interactive debugging

When the deferred interactive feature is implemented, `break` opens a prompt
on the controlling terminal, executing single command
lines against the live fixture with the full command table, until EOF. It
requires `--no-parallel` (a raw-mode terminal shared with parallel logging is
unusable). A `--break-on-error` switch MUST enter the prompt at the point of
failure, except on a parse error. Both are developer conveniences; a
non-interactive fallback that dumps every table and map on failure MUST exist
and is what CI uses.

### 3.9 Porting order

Against the build order in `docs/inventory/README.md`. An area is *runnable*
when the fixture, fakes and commands its scripts use exist. The harness itself
lands at step 1, before the load balancer, as ADR-0005 requires.

| Build step | Areas unlocked | Files | What must exist first |
|---|---:|---:|---|
| 1. `flowsdn-table`, config registry, netlink | `example` | 1 | engine, txtar, generic commands, `example/*` |
| 1b. + `db/*`, health, metrics | `hive-health`, `metrics` | 4 | `TableRender` (§3.3.3), health registry, metrics sampler |
| + fake k8s (spec 13) | `k8sclient`, `k8s-tables`, `dynamicconfig` | 10 | object trackers, watches, redaction, resync |
| 2. BPF map ABI + loader | *(no scripts alone)* | 0 | in-memory + unpinned map backends |
| 3. IPAM | `podippool`, `ipam-migration`, `ipam-multipool` | 4 | `ipam/*`, `allocator/*` |
| 4. Identity + policy | `policy` | 5 | `policy/*`, `identity/*`, `endpoint/*`, `policyrepo/*` |
| **5. Service LB** | **`loadbalancer`, `redirectpolicy`, `lb-healthserver`** | **66** | `lb/*`, `test/*`, `skiplbmap`, `http/get`, fault injection |
| 6. Node model, routes, devices, neighbors | `datapath-linux`, `device`, `route-reconciler`, `neighbor`, `subnet` | 19 | netns fixture, `link/*` `addr/*` `route/*` `sysctl/*`, reconciler drivers — **privileged** |
| 7. Hubble | `hubble-exporter` | 4 | `config/*`, `event/send`, `file/*`, `exporters/count` |
| 8. Operator, CRDs | `operator-watchers`, `nodes-gc` | 5 | operator fixture, kvstore fake |
| 9. Encryption, egress | `egressgateway` | 2 | `egress/policy-maps-dump` |
| 10. BGP | `bgp`, `bgp-reconciler` | 21 | test peer (§3.6.6), `bgp/*`, `gobgp/*` — **privileged** |
| 11. Envoy | `envoyconfig` | 12 | fake Envoy, `envoy/cmp`, `set-node-labels` |
| 12. ClusterMesh | `clustermesh`, `clustermesh-agent`, `mcsapi-coredns` | 14 | kvstore fake, clustermesh-apiserver fixture |

Cumulative: 15 files by the end of step 1b + k8s, 24 by step 4, **90 by step
5**, 109 by step 6, 168 by step 12. Step 5 is where the investment pays for
itself, which is why ADR-0005 orders the harness before the load balancer.

---

## 4. Data model

### 4.1 The txtar archive

| Element | Form |
|---|---|
| Comment | `[u8]` — everything before the first marker; UTF-8 in practice |
| Marker | a full line: `-- ` + name + ` --` |
| File name | one path segment in the whole corpus; general form is a relative slash-separated path |
| File data | `[u8]` from the line after the marker to the next marker or EOF |
| Serialization (for `--update`) | comment, then for each file the marker line and its data; data that does not end in `\n` gains one |

Extension counts across the corpus, indicating what the archive members are:
`.yaml` 612 (Kubernetes objects and table rows), `.table` 478 (expected table
renderings), `.expected` 255 (map dumps, metrics, kvstore listings, Envoy
resources), `.json` 47, none 16, `.txt` 15, `.1`/`.2`/`.v1`–`.v5` 14
(successive expected states), `.empty` 3, `.tmpl` 3, `.graph` 1,
`.not-expected` 1.

### 4.2 `.table` — the `db/cmp` comparison format

This is the most-used assertion in the corpus (616 invocations) and its rules
are precise.

**The file.** Line 1 is the **header**: column names separated by runs of
spaces (and/or tabs). Remaining non-blank lines are expected rows, in order.
Blank and whitespace-only lines are removed everywhere before processing —
including between rows — so the trailing blank lines that most harvested files
carry are harmless. The whole file is `$VAR`-expanded before parsing.

**Column selection.** Each header name is matched **case-insensitively**
against the table's own header. A name not present is an error naming the
available columns. The file MAY list a subset of the table's columns, and MAY
list them in any order; only the listed columns are compared. This is how the
corpus ignores non-deterministic columns.

**Column positions.** Parsing the header yields, for each name, its **starting
character offset**. Those offsets — not the header text — define the row
layout. For row line *i* and columns at offsets `p0=0, p1, p2, …`, field *k*
is `line[p_k .. p_{k+1}]` with trailing spaces and tabs stripped; the last
field is `line[p_last..]`, likewise stripped. A row shorter than an offset
yields empty fields from there on.

Consequently **the header must be aligned over the data**: a column's values
must begin exactly under its name. This is a real constraint on hand-written
files and the reason `--update` exists. Leading indentation of the whole block
does not matter as long as header and rows share it.

**Tab mode.** If the header line contains a tab, the file is in tab mode:
fields are split on tabs rather than by offset. No harvested `.table` section
contains a tab (verified across all 2065 table lines), so tab mode is
dead weight in practice — but it MUST be implemented, because `--update`
regenerates files through a tab-writer and a future harvest could contain one.

**Row matching.** Rows are compared **positionally and in order**: the table's
rows in primary-key order are zipped with the file's rows. Row *n* of the table
must equal row *n* of the file, field by field, as exact strings. Surplus table
rows produce `-` diff lines; surplus file rows produce `+`. There is no
set-semantics matching and no sorting — **the expected file must be in the
table's key order**.

**`--grep=<re>`.** When given, a table row is rendered to its line form first
and dropped if the regex does not match. Filtering happens before the
positional zip, so a grep-filtered comparison must list exactly the surviving
rows.

**Retry.** The comparison repeats until equal or `--timeout` (default 5 s)
expires, waking on the table's change notification rather than polling. This
internal retry is why 610 of the 616 `db/cmp` uses need no `*` prefix.

**Rendering for the diff and for `--update`.** The actual rows are re-joined
using the *file's* column offsets — pad with spaces to each offset, or emit a
tab in tab mode — so the diff aligns with the expected file and an updated
file keeps the same shape.

Worked example. Given the file

```
Name         Source   PortNames   TrafficPolicy   Flags
test/echo    k8s      http=80     Cluster
test/echo2   k8s      http2=80    Cluster
```

offsets are `[0, 13, 22, 34, 50]`; row 1's fields are
`["test/echo", "k8s", "http=80", "Cluster", ""]` — note the fifth field is
empty because the line ends before offset 50, and the table's `Flags` column
must therefore render empty for that row.

### 4.3 `lb/maps-dump` — the LB map-dump format

One line per map entry, **all lines sorted lexicographically** as the final
step, output with a trailing newline if non-empty. Compatibility surface: 106
invocations compare against `.expected` goldens.

| Map | Line |
|---|---|
| Service | `SVC: ID=<revnat-id> ADDR=<addr> SLOT=<slot> <slotinfo> COUNT=<n> QCOUNT=<n> FLAGS=<flags>` |
| Backend | `BE: ID=<id> ADDR=<addr> STATE=<state>` |
| Reverse NAT | `REV: ID=<id> ADDR=<addr>` |
| Affinity match | `AFF: ID=<revnat-id> BEID=<backend-id>` |
| Source range | `SRCRANGE: ID=<revnat-id> CIDR=<prefix>` |
| Maglev | `MAGLEV: ID=<revnat-id> INNER=[<id>(<count>), …]` |

Address rendering, used by `SVC`, `BE` and `REV`:

- IPv4: `a.b.c.d:port`. IPv6: `[a::b]:port` — brackets mandatory.
- `SVC` and `BE` append `/<proto>` where proto is `TCP`, `UDP`, `SCTP` or
  `ANY` (from the numeric protocol field).
- `SVC` appends `/i` when the frontend's scope is *internal*.
- `REV` carries no protocol and no scope suffix.

`SVC` slot info depends on the slot:

- slot 0, L7-LB flag set: `L7Proxy=<port>`.
- slot 0, otherwise: `LBALG=<algorithm> AFFTimeout=<seconds>`, where algorithm
  renders as `undef`, `random` or `maglev`.
- slot > 0: `BEID=<backend-id>`.

`FLAGS` is the service flag set rendered as flag names joined by `+` (the
reference builds a `", "`-joined string and replaces the separator; flowsdn
MUST emit `+` directly, in the reference's flag order).

`MAGLEV` compacts the 1021-entry (or `bpf-lb-maglev-table-size`) backend array
into `id(count)` pairs, sorted by **count descending, then backend id
ascending**. `INNER=[1(358), 2(357), 3(153), 4(153)]` is a real corpus line
and its ordering is exactly this rule.

An **ID-sanitizing** mode exists (`<zero>` / `<non-zero>` instead of numbers)
for cases where fault injection makes ID allocation non-deterministic. No
harvested file uses it; implement it, default off.

`egress/policy-maps-dump`, `subnet/map-dump` and `skiplbmap` follow the same
shape — one line per entry, sorted — with their own key/value fields, defined
in specs 14, 10 and 05 respectively.

### 4.4 `envoy/cmp` — the sectioned resource format

A flat text file of sections:

```
<section-name>:
  <indented line>
  <indented line>
<section-name>:
  …
```

Section names are `policy-trigger-count` plus one section per xDS resource,
named `<type>:<resource-name>` (e.g.
`clusters:default/cilium-ingress-.../default:details:9080`). Every section
except `policy-trigger-count` holds a protobuf text-format rendering of one
message; comparison is **semantic** — decode both sides into the message type
and compare structurally — not textual, so field-order differences are not
failures. `policy-trigger-count` holds one integer.

The file is regenerated with `--update` and is explicitly not meant to be
hand-maintained; the harness MUST say so in its failure hint.

### 4.5 Harness files it owns

| Path | Owner | Purpose |
|---|---|---|
| `tests/scripttest/corpus/<area>/*.txtar` | harvested, read-only | scenarios |
| `tests/scripttest/corpus/<area>/PROVENANCE` | flowsdn | attribution |
| `tests/scripttest/corpus/<area>/DIVERGENCES.toml` | flowsdn | §3.7 |
| `tests/scripttest/corpus/README.md` | flowsdn | index |
| `tools/harvest-txtar.sh` | flowsdn | re-harvest (ADR-0005 §4) |

---

## 5. Algorithms

### 5.1 Script execution

```
parse archive -> (script_bytes, files)
flags   := parse_shebang(script_bytes)          # §3.1
state   := new_state(workdir, base_env + WORK/TMPDIR/DATADIR)
materialize(files, state)                        # §3.1
fixture := build_fixture(area, flags, state)     # §3.5
engine  := commands(fixture) + generic + k8s
section := []
for each line, lineno in script_bytes:
    if line starts with '#':  close_section(ok); section = []; continue
    cmd := parse(line)                            # §3.2.2, §3.2.3, §3.2.4
    if cmd is None: continue                      # blank
    section.push(cmd)
    if not conditions_hold(cmd): log; continue
    err := run(cmd)
    if err is None: continue
    if cmd.retries:
        backoff := 100ms
        loop:
            wait(backoff); backoff = min(backoff*2, 500ms)
            err = None
            for c in section:                     # WHOLE SECTION, in order
                err = run(c); if err: break
            if err is None: break
            if ctx.cancelled: fail
    else if err is Stop: close_section(ok); return Pass
    else: return Fail(lineno, cmd, err)
close_section(ok)
cancel(ctx); wait_background(); return Pass
```

### 5.2 `db/cmp` inner loop

```
header      := table.header()
lines       := expand_env(read(file)).lines().filter(non_blank)
names, offs := split_header(lines[0])
idxs        := map_columns_case_insensitive(names, header)   # error if unknown
tabs        := lines[0].contains('\t')
expected    := lines[1..]
deadline    := now + timeout
loop:
    (rows, watch) := table.snapshot_and_watch()
    actual := []
    diff   := []
    exp    := expected
    equal  := true
    for row in rows:
        cells := take(row.render(), idxs)
        line  := join_by_offsets(cells, offs, tabs)
        if grep is Some(re) and not re.matches(line): continue
        actual.push(line)
        if exp.is_empty(): diff.push("-" + line); equal = false; continue
        want := split_by_offsets(exp[0], offs, tabs)
        if cells == want { diff.push("  " + line) }
        else { diff.push("-" + line); diff.push("+" + exp[0]); equal = false }
        exp = exp[1..]
    for rest in exp: diff.push("+" + rest); equal = false
    if equal: return Ok
    select:
        ctx.cancelled -> return Err(cancelled)
        deadline      -> if update { record(file, render(actual)); return Ok }
                         else      { return Err(mismatch, diff) }
        watch fires   -> continue
```

Note the comparison is on the **split field vectors**, not the joined lines —
so trailing-whitespace differences in the expected file cannot cause a false
mismatch, while a genuinely different value does.

### 5.3 Exponential backoff

`d0 = retry_interval`; `d_{n+1} = min(2 * d_n, max_retry_interval)`. Defaults
100 ms → 500 ms; load-balancer area 20 ms → 500 ms. No jitter (the reference
has none; adding it would change nothing since the bound is the script
timeout). No cap on attempts.

### 5.4 Scheduling

Collect the file set (glob per area, or a filter expression). Validate
cross-script resource claims (BGP peering IPs) before launching anything.
Partition into privileged and unprivileged; if unprivileged, mark the
privileged partition skipped. Launch up to `--jobs` concurrently, each on its
own current-thread runtime on its own OS thread. Report as results arrive;
print the summary last.

---

## 6. Configuration

Harness CLI (not a compatibility surface, except where noted):

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--area=<name>` | string, repeatable | all | restrict to areas |
| `--run=<regex>` | string | all | restrict by script name |
| `--jobs=<n>` | int | CPU count | parallelism |
| `--no-parallel` | bool | false | one at a time; implied by `--break*` |
| `--timeout=<dur>` | duration | per area | per-script deadline |
| `--update` | bool | false | rewrite expected files (§3.4). Reference name `-scripttest.update`, which MUST also be accepted |
| `--break-on-error` | bool | false | interactive prompt at failure |
| `--verbose` | bool | false | dump every section log, set the `verbose` condition |
| `--debug` | bool | false | agent log level debug |
| `--keep-work` | bool | on failure | keep `$WORK` |
| `--seed=<u64>` | int | derived from path | fault-injection seed |
| `--list` | bool | false | list scripts and their areas, run nothing |
| `--divergences=<path>` | path | per area | override the divergence file |

Test-only config keys the corpus sets through `#!`, registered separately from
agent keys (§3.5.2):

| Key | Type | Default | Effect |
|---|---|---|---|
| `lb-test-fault-probability` | f64 | 0.1 (LB area) | §3.6.3 |
| `test-peering-ips` | list of IPs | empty | §3.3.9; must be unique across the run |

---

## 7. Failure modes

| Situation | Required behavior |
|---|---|
| Unknown command name | Fail the script at that line: `unknown command`. Never skip silently — a missing command is the most common porting gap and must be loud. |
| Unknown condition tag | Fail the script, naming the tag. |
| Unknown config key in `#!` | Fail the script, naming the key and pointing at spec 00 §6.4. This is a feature: the corpus is a key-coverage checklist. |
| Malformed txtar (unterminated quote, missing command, empty condition) | Parse error with file and line. Parse errors MUST NOT trigger `--break-on-error`. |
| Archive name escaping the working directory | Fail before running anything. |
| Table named in `db/*` does not exist | Fail, listing the tables that do. |
| Column named in a `.table` header does not exist | Fail, listing the table's columns. |
| `db/cmp` timeout | Fail with the last computed diff, the elapsed time, and the row counts on both sides. |
| `*` retry outlives the script timeout | Fail naming the section, the last error, the retry count, and the last diff. |
| Fixture start hook fails | Fail the script with the component name and the fence that did not open. |
| Background task panics | Fail the script; a panic in a fixture task MUST NOT be swallowed. |
| Script panics | Catch, mark failed, and still tear down the namespace and the fixture. |
| Privileged area, unprivileged run | SKIP with "requires CAP_NET_ADMIN/CAP_SYS_ADMIN"; never fail. |
| Duplicate BGP peering IPs across scripts | Fail the whole run before executing, naming both scripts. |
| Namespace leak after a failure | Teardown runs on the failure and panic paths; a leak check at run end reports any leftover namespace named after a script. |
| `--update` used in CI | Refuse, with an error naming the environment variable that indicated CI. |
| XPASS (a divergence entry whose script now passes) | Fail the run. |

---

## 8. Observability

The harness is a test tool, not a service; "observability" here means the run
report.

**Per script**: name, area, result (`PASS`/`FAIL`/`SKIP`/`XFAIL`/`XPASS`),
wall time, retry count, `$WORK` if kept.

**Per run**: counts by result; the divergence summary grouped by ADR (§3.7);
the slowest ten scripts; total wall time; the parallelism actually achieved.
Machine-readable output (`--format=json`) SHOULD be available for CI trend
tracking — in particular, tracking *retry counts over time* is an early
warning that a reconciler is getting slower, which the pass/fail signal hides.

**Log content per script** mirrors the reference so that a failure is
readable next to an upstream one: the section comment, a `> ` line per
executed command, `[stdout]`/`[stderr]` blocks, `[condition not met]`,
`(command "…" failed, retrying in …)`, `(command "…" succeeded after N retries
in T)`.

The harness MUST NOT emit agent metrics to a global registry; each fixture
owns its own, or the 106 metrics assertions will see other scripts' values.

---

## 9. Test plan

Tests **of the harness**, distinct from the corpus it runs.

### 9.1 Unit — parser and format (all unprivileged)

- [ ] txtar: comment-only file; archive-only file; no trailing newline; CRLF rejected or normalized (decide, 12.6); marker-like line inside file data is a new file (per format).
- [ ] `#!`: absent; bare `#!`; `#! ` with trailing space (must not produce a spurious flag); `$WORK` substitution; flags containing `=` and commas.
- [ ] Tokenizer: `'a''b'` → `a'b`; `'a'b` → `ab`; unterminated quote is an error; `#` mid-line truncates; `#` inside quotes is literal; tabs as separators.
- [ ] Prefixes: each of `!`, `?`, `*`, `!*`; duplicate prefix is an error; prefix with no command is an error.
- [ ] Conditions: `[a]`, `[!a]`, `[a] [b]`, `[p:s]`, `[]` error, unknown tag error, suffix misuse both ways.
- [ ] Expansion: undefined → empty; `${x}` and `$x`; regexp args are quoted; quoted fragments not expanded.
- [ ] **Section retry re-runs the whole section** — the single most important harness test. Construct a script whose first command increments a counter and whose second succeeds only on the third value; assert the counter reached 3.
- [ ] Backoff schedule: 100, 200, 400, 500, 500, …
- [ ] `.table` parsing: offsets from a spaces header; a subset of columns; out-of-order columns; case-insensitive names; short rows yielding empty fields; the worked example of §4.2 exactly; tab-mode header.
- [ ] `.table` join: round-trip split→join is the identity for every harvested `.table` section (property test over all 478 files).
- [ ] Map-dump line rendering: one golden per line kind, IPv4 and IPv6, internal scope, each protocol, L7 slot 0, slot > 0, Maglev compaction ordering with ties.
- [ ] Update mode: rewrite preserves the comment byte-for-byte; only named members change; empty-file refusal; the `RetryCount ≥ 2` gate.

### 9.2 Integration — the harness against itself

- [ ] `example/example.txtar` passes (step 1 gate).
- [ ] A synthetic script per generic command, asserting success and the negated form.
- [ ] A synthetic script exercising `&` + `wait`, since no harvested file does.
- [ ] A synthetic script exercising `?`, likewise.
- [ ] `stop` yields PASS; `skip` yields SKIP; an unmet expectation yields FAIL with the right line number.
- [ ] `hive/recreate` preserves k8s and map state and discards tables — assert all three.
- [ ] Divergence entries: `expected-fail` on a deliberately failing script → XFAIL; make it pass → XPASS → run fails; `skip`; `partial` with a line list.
- [ ] Failure output contains file, line, command, section log, diff, `$WORK`, seed.

### 9.3 Fidelity

- [ ] Differential: every load-balancer script produces byte-identical `lb/maps-dump` output under the in-memory backend and the real-unpinned backend (privileged).
- [ ] Fault injection is reproducible: the same seed produces the same failure sequence; a failure message contains the seed; replaying the seed reproduces.
- [ ] Fake k8s: UIDs are deterministic across runs; `--strict` conflicts; resync restarts watches; redaction on/off.
- [ ] Parallel isolation: run the whole corpus with `--jobs=1` and with `--jobs=N`; results identical.
- [ ] Namespace hygiene: after a full privileged run, no leftover namespaces.

### 9.4 Corpus gates (CI)

- [ ] Every `.txtar` parses, and every command it names is registered — run as a **static check that does not execute anything**. This gate can pass long before the subsystems exist and is the cheapest possible early warning of a missing command.
- [ ] Every `.txtar` in the repo is byte-identical to the reference at `7d68cfb394` (a re-harvest diff check; requires the reference checkout, so it is an optional job).
- [ ] Every area has a `PROVENANCE`.
- [ ] Every `DIVERGENCES.toml` entry names an existing script and an existing ADR.
- [ ] The per-milestone runnable set from §3.9 actually runs green at that milestone (a table of area → milestone, checked in CI).

---

## 10. Kernel and platform requirements

The harness runs unprivileged on Linux and macOS for the pure-userspace areas
(`example`, `hive-health`, `metrics`, `k8sclient`, `k8s-tables`,
`dynamicconfig`, `policy`, `envoyconfig`, `clustermesh*`, `kvstore`,
`nodes-gc`, `operator-watchers`, `ipam*`, `podippool`, `hubble-exporter`, and
the load-balancer areas on the in-memory map backend) — 141 of 168 files.

Privileged Linux is required for:

| Area | Needs |
|---|---|
| `datapath-linux`, `device`, `route-reconciler`, `neighbor` | `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` (netns), `iproute2` on `PATH`, netlink `NETLINK_ROUTE` |
| `neighbor/neighbor-reconciler-kernel-arp.txtar` | kernel ≥ 5.16 for `NTF_MANAGED` — gated by `[kernel-can-manage-arp-ping]`, and the script `stop`s cleanly when absent |
| `bgp` | `CAP_NET_ADMIN`, plus the ability to bind the peering addresses; ports are ephemeral |
| `loadbalancer` under `[privileged]` | `CAP_BPF` + `CAP_NET_ADMIN` for real map creation; `bpf` syscall; no pinning, so no `/sys/fs/bpf` requirement |

Per `docs/kernel-requirements.md`: general minimum 6.6 LTS, so `NTF_MANAGED`
is always present on a supported flowsdn host — but the condition MUST still
be evaluated, because developers run this on older kernels.

x86-64 and arm64 are equivalent for the harness. Nothing here is
endianness-sensitive except the map-dump rendering, which reads
network-order fields explicitly (§4.3).

macOS: unprivileged areas only; the netns, netlink and BPF fixtures compile
out. Per the cross-project rule, the authoritative run is on `<build-host>`.

---

## 11. Rust design notes

### 11.1 Crate layout

```
crates/
  flowsdn-scripttest/          # the engine — no flowsdn agent dependency
    src/txtar.rs               # parse + serialize (~200 lines)
    src/parse.rs               # line -> Command (~250)
    src/engine.rs              # sections, retry, status, background (~400)
    src/state.rs               # env, cwd, stdout/stderr, update map (~200)
    src/cmds/                  # the generic command set (~800)
    src/cond.rs                # conditions (~120)
    src/diff.rs                # unified diff + table diff (~200)
    src/report.rs              # results, divergences, summary (~250)
    src/table.rs               # .table parse/split/join (~200)
  flowsdn-scripttest-fixtures/ # depends on the agent crates
    src/fixture.rs             # Fixture, Component, build/start/stop/recreate
    src/fakes/{k8s,bpfmaps,envoy,kvstore,bgp_peer}.rs
    src/netns.rs
    src/areas/{loadbalancer,bgp,policy,...}.rs   # one builder + command table each
  flowsdn-scripttest-bin/      # the runner: scheduling, CLI, reporting
```

The split matters: `flowsdn-scripttest` MUST NOT depend on any agent crate, so
it stays testable in isolation, compiles fast, and could be published
separately. The fixtures crate is where the agent enters.

### 11.2 The command trait

```rust
pub trait Cmd: Send + Sync {
    fn usage(&self) -> &Usage;
    /// Returns either a completed result, or a Wait for async/background commands.
    fn run(&self, st: &mut State, args: &[String]) -> Result<Option<Wait>, CmdError>;
}

pub type Wait = Box<dyn FnOnce(&mut State) -> Result<Output, CmdError> + Send>;

pub struct Output { pub stdout: String, pub stderr: String }

pub struct Usage {
    pub summary:     &'static str,
    pub args:        &'static str,
    pub detail:      &'static [&'static str],
    pub flags:       Option<fn(&mut FlagSet)>,
    pub is_async:    bool,
    pub regexp_args: Option<fn(&[String]) -> Vec<usize>>,
}
```

Most commands are a closure; provide
`fn command(usage: Usage, f: impl Fn(&mut State, &[String]) -> Result<Option<Wait>, CmdError>) -> Arc<dyn Cmd>`
so an area's table is a `HashMap<&'static str, Arc<dyn Cmd>>` literal.

`State` holds the working directory, the environment map, the stdout/stderr
buffers, the parsed flags for the current command, `retry_count`,
`update: bool`, `file_updates: HashMap<String, String>`, the background list,
and the log buffer. Commands take `&mut State`; the engine guarantees no
concurrent access.

Blocking vs async: the engine is **synchronous**. Commands that need the agent
runtime call `fixture.runtime.block_on(...)`. This keeps the engine free of
async plumbing, matches the reference's shape, and is correct because a script
is inherently sequential. The one place asynchrony is visible is background
commands, which get a `Wait` closure that blocks when `wait` runs it.

### 11.3 Dependencies

| Need | Choice | Note |
|---|---|---|
| txtar | **write our own** | ~200 lines, no crate is worth the dependency; the format is three rules and we need byte-exact re-serialization for `--update` |
| `.table` split/join | own | §4.2 is specific enough that a generic table crate would fight us |
| flag parsing per command | `clap` (builder API, `no_binary_name`, `allow_hyphen_values`) or a 150-line hand-rolled parser | must accept `-o=x`, `-o x`, `--out=x`, `--out x`, `-q`, and clustered shorts; the corpus uses all of these. Recommendation: hand-rolled, because clap's error behavior on unknown flags is hard to make match and the surface is tiny. Open decision 12.3. |
| diff | `similar` (MIT) for unified text diffs | mature, no transitive weight; `diffy` is an alternative |
| regex | `regex` | note: Go's RE2 syntax ≈ `regex`'s; the corpus's patterns are simple. `(?m)` is prepended to every `grep`/`stdout`/`stderr` pattern |
| YAML for `db/insert`, `k8s/*` | `serde_yaml` (or `serde_yml`) | must accept multi-document |
| durations | `humantime` or own parser | must accept Go forms: `10ms`, `1.5s`, `1m`, `2h45m` |
| glob | `glob` | |
| terminal (for `break`) | `rustyline` | optional feature, off by default |
| protobuf text format (`envoy/cmp`) | `prost` + `prost-reflect` | needed for semantic comparison; feature-gated with the Envoy area |
| temp dirs | `tempfile` | |

All are MIT/Apache-2.0/BSD; `cargo deny` per `docs/licensing.md`.

### 11.4 Notes

- **Line numbers**: track them from the raw byte stream including the `#!`
  line, so failure locations match an editor's view of the `.txtar`.
- **The retry loop re-runs commands, not closures**: keep the parsed `Command`
  values for the current section, and re-run them through the same
  `run_command` path (flags re-parsed each time, `RetryCount` incremented).
  Caching a partially-applied closure will break `db/cmp`'s update gate.
- **`State::path`**: every file argument goes through one function that joins
  against the current working directory and returns an absolute path. Two
  pseudo-names, `stdout` and `stderr`, bypass it — implement that in one
  helper (`actual_file_data`) used by `cmp`, `cmpenv`, `empty` and `cp`.
- **`#![forbid(unsafe_code)]`** in the engine crate. The fixtures crate needs
  `unsafe` only for `setns`/`unshare`; isolate it in `netns.rs`.
- **No global state.** Concretely: no `once_cell` singleton for node name,
  Kubernetes version, or metric registry. The reference's globals here are a
  known defect; do not inherit them.

---

## 12. Decisions and remaining questions

Resolved entries are normative decisions from [ADR-0013](../decisions/0013-integration-issue-resolutions.md); their implementation and acceptance tests remain required.

**12.1 Resolved by ADR-0008 (#205): explicit `TableRender`.** Spec 00 §4.3a and `flowsdn-table` now define ordered headers and cells; a convenience derive remains optional future work. Original decision context: `db/cmp`, `db/show` and the query commands
need each row type to expose an ordered header and ordered rendered cells.
Spec 00 does not define one. Options: (a) add a `TableRender` trait to
`flowsdn-table` and implement it for every row type — matches the reference,
makes `flowsdn-dbg`'s table output fall out for free; (b) derive the rendering
from `serde::Serialize` — less code, but column order and cell formatting
become accidents of the struct definition and the 478 harvested `.table` files
pin both. **Recommendation: (a)**, with a derive macro for the common case.
This is a change to spec 00 and should be made before any table is written.

**12.2 Resolved — #206.** Use one explicit fixture builder per area (§3.5.1), sharing
ordinary helper functions where useful. Do not require a generic dependency-injection or
composable-builder framework.


**12.3 Resolved — #207.** Use command-owned Rust flag parsing, not a global clap parser
for script commands. Preserve lenient handling for commands that declare no flags and
let their registered handler interpret arguments. This does not constrain CLI parsing
outside the script language.


**12.4 BGP test peer.** Rust peer reusing spec 15's speaker vs driving an
external `gobgpd` (§3.6.6). **Recommendation: build the Rust peer**, and keep
an `[exec:gobgpd]`-gated cross-check job so a shared bug is caught.

**12.5 Resolved — #209.** Run all 51 load-balancer scripts with the in-memory map
backend on every applicable PR and with both in-memory and real BPF map backends
nightly. Compare the same normalized output and report backend identity.


**12.6 Line endings.** Implementation decision, 2026-09-08 (#210): reject
CRLF with a line-numbered error, following recommendation (a). Never normalize
archived fixture bytes. The original alternatives follow for context.

The corpus is LF-only. Should the parser normalize
CRLF? (a) reject with a clear error; (b) normalize. **Recommendation: (a)** —
a CRLF `.txtar` in this repo means someone edited a harvested file, which is
exactly what must not happen, and a hard error surfaces it.

**12.7 Resolved #211: non-interactive diagnostics first.** The engine exposes
`diagnostic_dump` for fixture failure handling: current stdout/stderr and all
registered tables, stable ordering, one-MiB UTF-8 cap, explicit render errors
and truncation. Environment values are excluded. External map adapters and
automatic area failure wiring remain pending. Interactive break remains deferred
until the LB area is green, behind an explicit feature flag.

**12.8 Resolved — #212.** Store flowsdn-authored scripts in
tests/scripttest/flowsdn/<area>/*.txtar and run them through the same engine. Keep
tests/scripttest/corpus as the provenance-bearing harvested input, protected by the §9.4
checksum gate.


**12.9 Resolved #213: preserve reference naming; audit mechanically.**
`cargo xtask audit-corpus` parses all harvested archives without execution,
inventories command symbols, startup flag names and preserved cilium_ symbols,
and compares flags with the configuration catalogue. `--check` compares the
reviewed `tests/scripttest/naming-audit.json` snapshot. The rewrite set is empty:
compatibility names stay stable. Flags outside the agent catalogue must be
classified as area-fixture inputs or remaining adapter work, not renamed blindly.
This inventory does not claim all commands are registered or runnable; those
separate §9.4 gates remain open. No Go/shell harvester is introduced.

**12.10 Resolved — #214.** A reference-tag bump is a dedicated PR containing corpus,
provenance, divergence and generated-index changes only. The repository maintainer
reviews it, with review by each affected area owner. Report before/after harness
outcomes and XFAIL deltas. The diff budget is the explained harvest delta, not an
arbitrary line limit: every addition, removal and changed expectation must be accounted
for. Fix harness incompatibilities separately before accepting the bump.


### Variable-expansion implementation clarification (0.5.0)

Unbraced variable names accept ASCII letters, digits and underscores, plus the
single-character `/` and `:` separator names. Braces allow other environment
names. Empty or unterminated braces are parse errors; a dollar without a name
is literal. Expansion is single-pass and does not split arguments. Quoted
fragments remain literal; regex mode quotes only substituted values.
