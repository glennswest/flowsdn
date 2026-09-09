# flowsdn-config

Typed configuration resolution for the foundation specification, section 3.3.
Callers provide a `Registry` of `KeySpec` entries and source-tagged `Entry`
values. Resolution applies defaults, file, directory, environment and flag
values in that order, preserving the winning source for each key.

The `catalogue` module declares all 539 keys in specification §6.4, including
their original default expressions, pflag types, six behavior classes, three
deprecated aliases and four inventory-name renames. **488 defaults are resolved;
51 remain explicit gaps.** [The gap list](REGISTRY-GAPS.md) records unresolved
expressions, missing help/hidden metadata and area-validator requirements.

`complete_registry` refuses construction until every missing default has an
explicit, typed resolution with provenance. It returns the constructed schema
and an audit list of supplied resolutions; success does not replace domain
validation or make an agent production-ready. `partial_known_defaults_registry`
is explicitly incomplete, exposes omitted keys, and rejects input for a known
omitted key instead of treating it as unknown. It is intended for staged owners
and tests. Runtime and dynamic classifications preserve ownership semantics;
neither makes the immutable registry hot-reloadable.

The core supports key normalization, the three deprecated key aliases, all
specified textual value kinds, numeric range checking and warnings for unknown
keys, ignored keys and bare integer durations. List flags append within their
layer; values from different layers replace each other. Canonical input keys
take priority over aliases even when the alias comes from a higher source.
Defaults alone do not suppress aliases. Invalid known values are rejected even
if a stronger source would replace them.

`Resolved` exposes immutable values and diagnostics for callers to validate,
derive and share. Ignored and script keys remain visible with their class so
callers can report them without activating functionality. Duration values are
signed 64-bit nanoseconds. Floating-point values must be finite. CIDR parsing
preserves the supplied address, including host bits.

The `sources` module reads file-per-key directories, YAML config files and
environment snapshots. Directory values are trimmed; projected ConfigMap
symlinks are followed, directories and special files are skipped, and unreadable
files produce diagnostics. An explicit config file must exist; otherwise the
loader checks `ciliumd.yaml` under the supplied home directory.

YAML input is a single flat mapping of scalar keys and values. Scalar text is
preserved until typed parsing, including large integers. Scalar aliases and
quoted/block strings are supported. Duplicate normalized keys, nested containers,
null values and explicit YAML tags are rejected. List and map options use their
textual comma-separated forms. Environment loading excludes the process-only
variables listed in the specification and accepts caller-supplied legacy aliases;
a canonical variable wins even when its value is empty.

`validation::foundation` checks registered foundation settings and the
dependencies of enabled features: address families and NDP, routing and localhost
modes, route metrics, IPv6 allocation prefixes, cluster naming and ID bounds,
dynamic map ratios, policy-map bounds, delegated IPAM, VTEP mask parsing and
identity backend selection. A required dependency missing from the schema is an
error. `validation::map_sizes` accepts additional bounds from map owners.
Native-routing CIDR derivation and its automatic-range exceptions remain with
the IPAM/routing integration; this validator does not yet enforce that rule.
Validation of a VTEP mask does not enable the deferred VTEP feature.

Keys marked `Class::Immutable` are compared across parsed snapshots using
`immutable::check`. Changes refuse startup when restoration is enabled and
endpoint state exists; other changes are reported for diagnostics. Missing
previous state is accepted, and an unparseable previous snapshot produces a
warning. The caller provides decoded snapshots and actual endpoint-state
presence.

`runtime` serializes and decodes snapshots with version, RFC3339 timestamp and
reference compatibility metadata. It retains typed values and source provenance,
effective unknown raw values, and immutable-key membership; script keys are
excluded. Decoding never fills defaults for keys absent in the previous file.
`check_previous` reads prior state and feeds it into the immutable-change check.
Unknown-key source provenance is retained in the `sources` object as well.
Snapshot input and output are limited to 16 MiB. Prior-state reads use a
nonblocking, no-follow open and validate the opened file descriptor; symlinks,
special files and oversized input produce an unparseable-history warning.

`runtime::store` stages and syncs the new snapshot, preserves current availability
through history rotation, and atomically publishes the staged file. It keeps
the two prior snapshots when rotation succeeds. All storage/rotation failures
are returned as nonfatal diagnostics; a published snapshot can still have a
history or directory-sync warning. Callers serialize writers for the supplied
state directory and check previous state before publishing a changed config.
Temporary files are cleaned on completion/failure. Unix snapshot files use
mode 0600, and final-path symlinks are replaced without writing their targets.

This core still requires the 51 unresolved production defaults,
CLI argument parsing, area-specific map validators, all cross-key rules,
derived settings or dynamic config reflection. Legacy alias
definitions are supplied by the owning area's schema.
