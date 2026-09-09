# BPF inventory harvester

A Rust tool that reads the pinned reference and extracts test identifiers,
feature flags, include structure, entrypoints and milestone assignments. It
never compiles the reference or copies C code into the generated inventory.

```sh
cargo run --locked -p flowsdn-harvest-bpf-cases -- \
  --reference /path/to/reference-checkout --check tests/bpf/CASES.toml

cargo run --locked -p flowsdn-harvest-bpf-cases -- \
  --reference /path/to/reference-checkout --output tests/bpf/CASES.toml
```

The reference commit and a clean `bpf/tests` tree are checked before extraction.
`--check` compares every inventory field, ignoring only the generator identity
and harvest date. Ordering within the file/case arrays is significant.
`--date YYYY-MM-DD` overrides the reproducible default of 2026-09-07.

The expression evaluator deliberately implements the limited conditional syntax
used by the original harvester. Unsupported expressions select their branch
conservatively; this is an inventory extractor, not a complete C preprocessor.
The pinned reference is the compatibility test: 142 translation units and 625
cases, with exact feature, config and milestone parity. The 23 previously
unresolved entrypoints have audited classifications recorded in spec 18
§4.3.1. Guards require syntactic evidence patterns and reject missing patterns
or mismatched objects. They do not prove control flow or detect arbitrary
source changes that retain those patterns. The CLI requires the exact pinned
commit and a clean `bpf/tests` tree; a future reference tag requires a fresh
audit even when the patterns still match. Unknown cases may remain unresolved. Library tests may
invoke the function under test from SETUP or CHECK without entering an attached
datapath program.

Static fixture data remain TOML. The generator and its tests are Rust.
