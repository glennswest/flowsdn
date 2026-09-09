# Script harness core

The parser preserves txtar fixture bytes and script quote boundaries. The
synchronous engine executes registered commands with expected-status assertions,
conditions and explicit stdout/stderr buffers.

`State::with_workspace(parent, datadir)` creates a private working directory
under a caller-selected parent. `Engine::run_archive` expands fixture names,
materializes their unchanged contents, and executes the script. `WORK`, `PWD`,
`TMPDIR` and `DATADIR` are initialized for that state. Dropping the last cloned
state removes its owned directory. No process cwd or environment is changed.

File commands use directory capabilities: reads are confined to WORK or the
explicit DATADIR; writes are confined to WORK, including when symlinks occur.
DATADIR is exposed only for reads. File size and aggregate cat output are bounded
to 8 MiB. `cmp` and `cp` preserve arbitrary bytes; text operations reject invalid
UTF-8. `cd` changes the state's cwd independently of other scripts.

Variable substitution checks its output budget before appending; command
arguments share an 8 MiB budget. Each diagnostic is limited to 64 KiB, and
built-in commands share a cumulative log limit of 1 MiB or 4096 entries.
Diagnostic-limit failures halt execution even behind `!` or `?`. File opens
are nonblocking on Unix, and descriptor checks reject nonregular files before
reading or truncating them. FIFO paths cannot suspend fixture setup or commands.

Implemented commands: `echo`, `env`, `stdout`, `stderr`, `stop`, `cmp`, `cmpenv`,
`empty`, `cat`, `grep`, `cp`, `replace`, `sed`, `mkdir`, `cd`, `exists`, `mv`,
`chmod`, `symlink`, `rm`, `exec` and `wait` through `run_async`.

`mv` performs a rename, including replacement of an existing destination file.
`exists --readonly` checks that write permission bits are absent; `--exec`
checks that an execute permission bit is present. These assertions are
independent of whether the test process runs as root. `chmod` accepts octal
modes through `07777`; symbolic modes are unsupported. Linux permission changes
use an owned path descriptor and require procfs, avoiding blocking FIFO opens
and allowing recovery from mode `000`.

`symlink path -> target` preserves relative target text, including dangling
targets. Absolute targets are explicitly unsupported by the capability
workspace; following a link outside WORK fails. `rm` removes a symlink itself,
repairs owned directory permissions before recursion, and accepts missing paths.
It stops after 128 levels or 4096 entries. The owned WORK root cannot itself be
removed, renamed or chmod-ed, including through a symlink alias for chmod.

`replace` applies pairs in one pass, using the first matching pair at each byte
position; empty search strings are currently rejected. Escapes include control
characters, hexadecimal bytes, octal bytes and Unicode code points. `sed` works
line by line; quote capture replacements such as `'$1'` so script environment
expansion does not consume them. Comparison failures produce a whole-file
unified diff unless quiet mode is selected.

Networking adapters, update mode,
agent fixture flags remain unimplemented. Unsupported commands and execution
syntax fail explicitly.
Section comments and asynchronous retry attempts are logged. Successful
synthetic scripts do not imply that the harvested networking corpus passes.

`Engine::run_async(script, state, &RunOptions)` runs Linux processes.
`RunOptions` supplies a deadline (60 seconds by default), cloneable cancellation
handle and SIGINT grace interval (100 milliseconds by default, capped at five
seconds). The synchronous `run` rejects `exec` and `wait`, including negative assertions.
Conditions, expansion and expected exit status use the same engine logic.

A child starts in the state's capability-resolved current directory, with null
stdin and only the script environment; separator variables `/` and `:` are
omitted. A bare executable name requires an explicit script `PATH`. Each output
stream is limited to 8 MiB and must be UTF-8. Cancellation, deadlines and output
limits cannot satisfy `!` or `?`. Cancellation sends SIGINT, then SIGKILL after
the grace interval, and reaps the direct child. Descendants in its process group
are terminated before reaping, while the leader's process identity remains reserved. Dropping
the run future triggers the same supervisor cleanup; keep the Tokio runtime
alive until cleanup finishes and leave child wait-status ownership to the
supervisor. Interactive stdin remains deferred.

Execute only trusted scripts: subprocesses inherit the caller's operating-system
permissions and can access files beyond WORK. Capability confinement applies to
the generic file commands, not to arbitrary executable code. A process that
creates another session can escape process-group cleanup; OS isolation is the
caller's responsibility when stronger containment is required.

Run the real-child Rust regression suite with
`cargo test -p flowsdn-scripttest --features process-fixture`. The helper binary
is enabled only by that feature and is not part of the normal build.

A bare trailing `&` backgrounds `exec`; other implemented commands cannot be
backgrounded. Launch clears both output buffers and snapshots the script cwd and
environment. `wait` accepts no arguments or flags. It drains jobs in launch
order, checks each job's original expected status, logs its output, concatenates
stdout and stderr separately, and clears the job list. An empty wait clears both
buffers. Ordinary failures are joined; cancellation, deadlines, ownership loss,
and resource limits remain fatal. Errors returned by `wait` ignore its own
status prefix because each job's status has already been checked. A successful
`! wait` is still an unexpected success, including when no jobs are queued.

At most 32 jobs may be queued between waits. Their retained output shares an
8 MiB combined stdout/stderr budget checked before capture appends. Output log
entries show at most 32 KiB per stream, with an explicit truncation marker; the
existing total log limit still applies. Script completion, stop and errors
cancel remaining jobs and implicitly wait for cleanup, reporting unexpected
background outcomes. Dropping the async run future also triggers cleanup of all
remaining jobs. Explicitly wait before script end when jobs should finish
normally.

Async `* command` and `!* command` retry the entire current section through the
failed assertion, including all preceding commands. Every replay reevaluates
conditions and expands arguments again. Environment changes, files, cwd and
output side effects persist; there is no state rollback. `State::retry_count`
starts at zero for each section and increments before every replay, so adapters
can distinguish retries. During an active replay, an ordinary mismatch in an
earlier command starts another replay (§5.1); an unmarked failure after the
retrying assertion has succeeded remains terminal.

Backoff defaults to 100, 200, 400, then 500 milliseconds. Configure
`RunOptions::retry_interval` and `max_retry_interval` for other suites. Intervals
must be nonzero and the initial interval cannot exceed the cap. The script
context is the time bound; existing command/log resource budgets still apply.
Logs include the failing command, next delay, successful replay count and elapsed
time. Cancellation/deadline diagnostics name the section and last failed command.
Cancellation, output limits, ownership errors and other harness errors never
trigger a retry. Synchronous execution rejects retry syntax with an explicit
`run_async` requirement.

Before a replay, jobs launched by the failed attempt are cancelled and reaped;
completed errors are checked, and caller cancellation, deadlines and fatal
capture errors remain terminal. Internal replay cancellation is distinguished
from caller cancellation. Prior-section jobs remain queued. Cleanup discards
attempt-job output without resetting script buffers or fixture state. Combining
a retry prefix directly with background execution (`* exec ... &` or
`!* exec ... &`) remains an explicitly unsupported gap; use a foreground retry
assertion after launching background work.

`Engine::register_table::<T>(name, Arc<Table<T>>)` binds rows implementing
`Keyed + TableRender` to one fixture engine. Duplicate table names fail without
replacing the existing binding, and the `db/show` / `db/empty` command names are
reserved. Independent engines keep independent bindings.

`db/empty table...` checks current snapshots once; use `* db/empty` when the
whole section should retry. `db/show table` renders one immutable snapshot in
primary-key order. Header spelling and default order come directly from
`TableRender`; `--columns=Name,ID` selects exact-case names in the requested
order. The writer uses character widths, pads each column to its widest cell
including the header, and separates columns by three spaces. Empty tables still
print a header. Malformed row widths and cells containing tabs or line breaks
are rejected. The future `db/cmp` command has its separately specified
case-insensitive expected-header matching; it is not implemented yet.

`db/show` accepts `--columns`, `-o`/`--out`, and `-f`/`--format=table`, with
separate or `=` values and flags before or after the table name. An output file
uses the existing confined, nonblocking writer and leaves output buffers intact;
without `-o`, rendering replaces stdout and clears stderr. Invalid formats,
columns and row data are checked before opening an output file. JSON/YAML
serialization, row deserialization, typed index queries and asynchronous
`db/cmp` remain explicit gaps.

Rendering is bounded to 8 MiB of retained cell text and 8 MiB of final output,
65,536 rows, 128 columns and 65,536 selected cells. Padding amplification is
checked before appending. Adapter-provided `TableRender::cells` runs as trusted
Rust code; the harness checks its returned data but cannot bound allocations
inside that callback. Synthetic table adapters do not imply that harvested
networking fixtures execute.
