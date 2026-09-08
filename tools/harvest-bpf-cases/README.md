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
cases, with exact feature, config, entrypoint and milestone parity.

Static fixture data remain TOML. The generator and its tests are Rust.
