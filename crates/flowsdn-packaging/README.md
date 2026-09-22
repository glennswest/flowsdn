# Deployment policy primitives

Pure Rust plans for BPF-only masquerade validation, legacy compatibility keys,
verified host mounts versus init helpers, certificate ownership, distribution
visibility, evidence retention and trusted privileged CI dispatch.

The library does not render a Helm chart, mount a filesystem, issue certificates,
upload artifacts or configure a runner. Those adapters must enforce the plans
and perform the specified runtime checks before deployment support is claimed.
