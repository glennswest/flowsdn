# flowsdn

A Rust reimplementation of the Cilium networking stack: eBPF datapath, CNI,
kube-proxy replacement, identity-based network policy, encryption, egress,
BGP, cloud IPAM, and a Hubble-compatible observability API.

Goals:

- **Boundary-compatible with Cilium.** Same CRDs and semantics, same Hubble
  gRPC observer API, same agent REST API, documented Helm value mapping.
  Existing Cilium manifests, `cilium` and `hubble` CLIs keep working.
- **Free inside.** Precompiled eBPF (no clang on the node), one static binary
  per component, `scratch` container images, no iptables dependency.
- **Two architectures.** x86-64 and arm64, one BPF object for both.
- **Everything.** Full feature scope unless a documented decision records a
  better solution.

Status: **spec phase**. See `docs/inventory/` for the feature inventory of
the reference implementation and `docs/spec/` for the specifications that
the code is written from.

## Layout

```
docs/inventory/   per-area inventory of the reference implementation
docs/spec/        flowsdn specifications, one document per area
docs/decisions/   architecture decision records
docs/licensing.md clean-room protocol and license analysis
```

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
