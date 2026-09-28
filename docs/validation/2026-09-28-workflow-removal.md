# Workflow removal validation — #304

Validated source: `9e7144fec889` on `main`. This change deletes
`.github/workflows/crates.yml` and updates build/publication guidance; it changes
no executable code or package version.

`sc-build` fetched the pushed source into its disposable checkout. The invocation
checked that `crates.yml` was absent and `git ls-files .github/workflows` was
empty, then ran:

```sh
cargo build -p xtask -p flowsdn-packaging --locked
cargo test -p xtask -p flowsdn-packaging --locked
```

Both commands passed. Packaging: **7 passed**, xtask: **9 passed**, no failures
or ignored tests. Packaging doc tests contained no cases. Build execution was
**412 seconds**, including dependency fetching and Cargo cache-lock waits;
shared-slot waiting preceded execution. The helper reported exit 0 and removed
the scratch checkout. The device preflight passed and available build-volume
space was 653 GiB before, 652 GiB after.

Read-only `gh api repos/glennswest/flowsdn/actions/permissions` returned
`enabled: false`; Actions was not re-enabled. Source/docs review confirmed
current instructions use push → sc-build and explicit stormcentral staging;
upstream workflow references and dated historical records remain provenance.
The historical privileged-dispatch policy library remains tested but does not
activate GitHub execution.

This verification covers the workflow removal and its build/tooling surface.
It does not establish networking, operator, relay or cross-architecture runtime
acceptance. Earlier implementation work remains on its documented branches.
