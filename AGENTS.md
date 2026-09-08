# flowsdn working rules

## Rule #1 — GitHub is the transfer and results path

- Commit and push changes to GitHub, then clone or pull them on dev.g8.lo.
- Never rsync, scp, or otherwise copy working trees or build results between hosts.
- Commit source changes, lockfiles, formatting fixes, and validation records back
  to GitHub from the host where they were produced, then pull on other hosts.
- Publish distributable build artifacts through GitHub Releases.
- Commit and push at each completed work step so validated work is preserved.
- Maintain CHANGELOG.md and a versioned GitHub release history. Release only
  after validation, and distinguish foundation prereleases from usable networking.

## Development

Read CLAUDE.md, README.md, the architecture decisions and the relevant spec.
Build and test on dev.g8.lo, never on the Mac. Set
CARGO_TARGET_DIR=/build/cargo/flowsdn and TMPDIR=/build/tmp.
Write Rust from the specifications; follow docs/licensing.md.

## Shared build host disk discipline

- /build is the spinning drive (/dev/sdc); root is the smaller SSD.
- Follow neighboring projects: target output under /build/cargo/flowsdn,
  temporary files under /build/tmp, artifacts under /build/images or /build/cache.
- Inspect disk space before and after builds. Limit build concurrency on this
  shared host; default CARGO_BUILD_JOBS=2 unless capacity is checked.
- After publishing or committing results, run cargo clean --target-dir
  /build/cargo/flowsdn and remove only temporary files created by this task.
- Never clean another project's targets, shared caches, or installed toolchains.

Before builds, verify test -c /dev/null. A regular-file replacement caused
compiler probes to ingest diagnostic output on 2026-09-08; see the validation
record. Never replace or truncate a device node as part of cleanup.

## Time, token and velocity accounting

Maintain docs/velocity/ledger.json and its README at every work-item boundary
and before release. Record UTC start/end, elapsed wall-clock seconds, task ID,
agent/session, primary crate (or project/shared), usage counter baselines and
endpoints, commits/releases and validated outcomes. Follow the recording rules
in docs/velocity/README.md. Keep build/test, infrastructure and approval waits
visible when their bounds are observed. Unknown active work time stays null.

Use local session token_usage_record telemetry when available; deduplicate
responses and commit only sanitized counters/timestamps. Never commit transcript
content. Distinguish cached input, uncached input, output, and reasoning subsets.
Do not allocate shared usage to multiple crates or sum overlapping elapsed
windows. Track parallel agent-hours separately from project wall-clock time.
Include a brief elapsed/usage update when reporting each finished milestone.

## Source language and public documentation

All committed executable project code, tests, fixture generators, harvesters
and reusable tools must be Rust. Temporary Python used only for editing is
permitted; do not commit Python scripts. Static txtar, YAML, TOML and JSON test
data are permitted. Keep internal operating rules and actual machine names,
addresses and filesystem paths out of customer-facing documentation, help
messages and release notes. Public build instructions use standard Cargo
configuration; internal builds still use the required shared-host paths above.
