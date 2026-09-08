# flowsdn working rules

## Rule #1 — GitHub is the transfer and results path

- Commit and push changes to GitHub, then clone or pull them on dev.g8.lo.
- Never rsync, scp, or otherwise copy working trees or build results between hosts.
- Commit source changes, lockfiles, formatting fixes, and validation records back
  to GitHub from the host where they were produced, then pull on other hosts.
- Publish distributable build artifacts through GitHub Releases.
- Maintain CHANGELOG.md and a versioned GitHub release history. Release only
  after validation, and distinguish foundation prereleases from usable networking.

## Development

Read CLAUDE.md, README.md, the architecture decisions and the relevant spec.
Build and test on dev.g8.lo, never on the Mac. Set
CARGO_TARGET_DIR=/build/cargo/flowsdn and TMPDIR=/build/tmp.
Write Rust from the specifications; follow docs/licensing.md.
