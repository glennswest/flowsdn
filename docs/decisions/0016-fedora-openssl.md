# ADR-0016: Fedora OpenSSL for Kubernetes TLS

Date: 2026-09-28. Status: accepted owner direction; library validation passed at e1a1e7b.

The owner selected a C provider from Fedora to resolve the TLS dependency
conflict in #291/#306. Use Fedora's system OpenSSL through kube's
`openssl-tls` backend, with kube defaults disabled. This narrowly supersedes
ADR-0002's C-dependency prohibition for OpenSSL and its binding build probes.
Project executable code and BPF remain Rust; no C source is vendored here.

Use Fedora `openssl-devel` and `pkgconf-pkg-config` at build time, and matching
`openssl-libs` at runtime. Cargo's `openssl`/`openssl-sys` are Rust bindings;
the cryptographic implementation must come from the distribution package.
`OPENSSL_NO_VENDOR=1` is forced in Cargo configuration. Dependency policy bans
`openssl-src`, vendored features, ring, AWS-LC, bindgen and unrelated C helpers;
`cc` is permitted only as a direct dependency of `openssl-sys` for header probes.
This is not approval for arbitrary C dependencies or alternate TLS providers.

TLS consumers use Fedora-compatible GNU/glibc targets, not static musl.
CNI and other packages whose dependency closure does not use OpenSSL retain
musl compile checks. Native checks cover TLS consumers; cross-architecture
TLS builds need matching Fedora sysroots and runtime validation, not merely
reusing native headers. xtask reports the packages excluded from musl checks.

The standalone agent does not yet depend on the Kubernetes client. Before
wiring it in, stormcos packaging must carry the GNU loader, matching glibc and
OpenSSL libraries, OpenSSL configuration/provider modules and crypto-policy
files as required, and certificate trust. A shared-library agent cannot replace
a static binary in a scratch golden without that runtime. CNI can remain static.
The packaging owner must validate both supported architectures.

Verified HTTPS, hostname/certificate checks, explicit cluster roots and rotated
credentials remain required. This decision does not approve insecure TLS,
claim FIPS compliance, or complete live cluster acceptance.

References: [kube TLS configuration](https://docs.rs/crate/kube/4.2.0),
[system OpenSSL detection](https://docs.rs/openssl/latest/openssl/),
[Fedora OpenSSL development package](https://packages.fedoraproject.org/pkgs/openssl/openssl-devel/).
