# flowsdn-encryption

Encryption/routing configuration validation, underlay and WireGuard endpoint
selection, IPsec layering, legacy egress-map migration planning, and deterministic
gateway selection. Reference FNV-1a-32 modulo remains default. Optional rendezvous
requires coordinated all-flowsdn selection and identical gateway membership.

This crate does not install WireGuard/XFRM state, load keys, synchronize BPF maps,
resolve gateways, prove peer membership, observe health or perform migration.
Build-feature plans name required diagnostic features; the BPF instrumentation
and diagnostic objects remain unimplemented. Tests validate local plans and hash
vectors, not encryption or reference packet-path interoperability.
