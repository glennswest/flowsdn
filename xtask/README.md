# Build tasks

`cargo xtask check` runs all workspace checks. `cargo xtask plan BASE` prints a
JSON array of packages affected since the merge base of `BASE` and `HEAD`.
`cargo xtask check-changed BASE` checks those packages and their transitive
workspace dependents. Dependency kinds include normal, build and dev edges.

Selection uses committed changes only. Root dependency/build settings, shared
fixtures and unknown or removed package paths conservatively select the entire
workspace. Documentation-only changes outside package roots select nothing.
Package-local data and documentation select their owning crate because source
can include them. Renames are treated as a deletion and an addition.

Cargo retains its usual per-package incremental cache when the caller retains
its target directory. This selector does not provision CI runners or implement
remote cache storage. `cargo xtask deny` remains a separate whole-workspace gate.
