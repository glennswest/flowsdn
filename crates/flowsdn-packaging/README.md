# Deployment policy primitives

Pure Rust plans for BPF-only masquerade validation, legacy compatibility keys,
verified host mounts versus init helpers, certificate ownership, distribution
visibility, evidence retention and a historical privileged-dispatch policy.

The library does not render a Helm chart, mount a filesystem, issue certificates,
upload artifacts or configure a runner. Those adapters must enforce the plans
and perform the specified runtime checks before deployment support is claimed.

The dispatch policy is a library primitive, not an active GitHub integration.
GitHub Actions is disabled; maintainers build/test with sc-build after pushing
and request flowsdn goldens through stormcentral stage. See the current
[build and publication contract](../../docs/build-and-test.md).
