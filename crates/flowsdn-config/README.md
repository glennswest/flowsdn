# flowsdn-config

Typed configuration resolution for the foundation specification, section 3.3.
Callers provide a `Registry` of `KeySpec` entries and source-tagged `Entry`
values. Resolution applies defaults, file, directory, environment and flag
values in that order, preserving the winning source for each key.

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

This initial core does not yet include the complete 539-key agent catalogue,
CLI argument parsing, area-specific map validators,
cross-key validation, derived settings, runtime persistence or dynamic config
reflection. Legacy alias definitions are supplied by the owning area's schema.
