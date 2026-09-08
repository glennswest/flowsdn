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
`empty`, `cat`, `grep`, `cp`, `replace`, `sed`, `mkdir`, `cd`.

`replace` applies pairs in one pass, using the first matching pair at each byte
position; empty search strings are currently rejected. Escapes include control
characters, hexadecimal bytes, octal bytes and Unicode code points. `sed` works
line by line; quote capture replacements such as `'$1'` so script environment
expansion does not consume them. Comparison failures produce a whole-file
unified diff unless quiet mode is selected.

Retry sections, background jobs, subprocesses, networking adapters, update mode,
agent fixture flags, and `mv`, `rm`, `chmod`, `exists`, `symlink` remain
unimplemented. Unsupported commands and execution syntax fail explicitly.
Section comments are logged, but retry prefixes are rejected. Successful
synthetic scripts do not imply that the harvested networking corpus passes.
