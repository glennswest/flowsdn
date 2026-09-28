# Fedora system OpenSSL checkpoint — #291/#306

Owner direction on 2026-09-28 selected a Fedora C TLS provider. ADR-0016
narrows the earlier dependency rule to permit distribution OpenSSL and its
Rust binding/header probes; vendored OpenSSL and unrelated C backends remain banned.

Source c66d35a and managed lock/format e1a1e7b were pushed before validation.
At e1a1e7b, sc-build passed the locked build and all 33 tests (22 Kubernetes,
11 xtask), formatting, Clippy with warnings denied, and all-target CNI compile
checks for x86_64 and aarch64 musl. The three HTTPS tests establish successful
explicit-root trust, unknown-root rejection and hostname mismatch rejection.
The TLS executable dynamically linked system libssl.so.3 and libcrypto.so.3;
Fedora 43 installed openssl-devel/openssl-libs 3.5.4-3.fc43 and pkg-config
reported 3.5.4. No vendored OpenSSL was resolved.

cargo-deny 0.20.2 was installed inside the disposable build volume. Its locked
check reported advisories, bans, licenses and sources all OK. Duplicate-version
warnings remain warnings under the existing policy. No license allowlist was
expanded. Build-tool dependencies are separate from the project dependency graph.

Managed execution took 168 seconds after storage/slot waiting; lock/format
preparation took 6 seconds. Device preflight passed. The build volume had 147 GiB
available initially and 145 GiB finally, and sc-build removed it. The validation
request began around 17:03 UTC; execution started around 17:20 UTC. These waits
are included in the ledger's elapsed interval, not added to it.

This validates the TLS library checkpoint only. The standalone agent still needs
watch, identity/ipcache and remote-route integration. stormcos#171 owns Fedora
GNU/OpenSSL runtime packaging for the future Kubernetes-connected agent; #291
was moved behind it. Two-node test-container acceptance remains outstanding.
No golden or networking release is claimed for this incomplete milestone.
