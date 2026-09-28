# Owned Kubernetes identity — #299

Recovered source e02d811 integrates saved implementation f35b620 with the current
Fedora TLS transport. The managed formatter pushed 9c1ea61 before validation.

## Verified behavior

All 22 registered resource plans use flowsdn.io/v1alpha1, Flowsdn-prefixed kinds,
flowsdn-prefixed plurals, list kinds and the sole flowsdn category. Normal
registration rejects upstream identity. Explicit migration projects the reference
storage-version schema into a separate flowsdn resource; identity constraints
are updated while unrelated values and descriptions remain intact. Reprojection
is idempotent. Spoofed identities, wrong scope/version and webhook conversion
are rejected. No upstream objects are adopted or mutated by these pure planners.

Configuration and operator defaults now attribute owned resources to flowsdn,
including the ConfigMap, taint, secret namespace, controller and Gateway
conditions. Tests verify defaults and their decision provenance. ADR-0017
records why existing interface/BPF names, runtime paths and CNI aliases remain
compatibility contracts. README states the actual API and migration boundaries.

## Managed validation

At pushed 9c1ea6163ec936b79a77b8692b5c75381b76f65b, sc-build ran:

```sh
CARGO_BUILD_JOBS=2 cargo build --workspace --locked
CARGO_BUILD_JOBS=2 cargo xtask check
```

The workspace build, formatting and all-target/all-feature Clippy with warnings
denied passed. All 710 tests passed. The existing loopback_namespace fixture
remained ignored because it requires Linux user/network namespaces. xtask also
passed all-target/all-feature compile checks for 33 non-OpenSSL packages on
x86_64-unknown-linux-musl and aarch64-unknown-linux-musl. flowsdn-k8s uses native
Fedora OpenSSL checks, which passed; it is intentionally excluded from musl.
Existing time_t deprecation warnings appeared during cross-compilation.

Execution took 283 seconds after the queue wait. Device preflight passed; the
disposable volume had 147 GiB available initially and 142 GiB finally. The helper
removed the drive. Dependency policy previously passed at e1a1e7b; #299 changes
no manifests, lockfile or policy. Independent source review found all four issue
requirements covered without a further owner decision.

These are library projection and configuration tests, not live CRD admission,
instance migration or two-node networking acceptance. The standalone daemon
still does not register CRDs. Milestone 1 remains open. Per the milestone release
contract, package version remains 0.14.0 until milestone acceptance; the breaking
owned API change is recorded in Unreleased. Golden staging is requested separately.
