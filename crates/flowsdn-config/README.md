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

This initial core does not yet include the complete 539-key agent catalogue,
file or environment loading, CLI argument parsing, area-specific map validators,
cross-key validation, derived settings, runtime persistence or dynamic config
reflection. `Entry::environment` only handles the standard `CILIUM_` prefix;
legacy environment aliases belong to the pending loader.
