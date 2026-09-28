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

## Completion verification

On 2026-09-28 the same locked build/test commands passed again through
`sc-build` at pushed revision `d54ee442ce7b`: 7 packaging tests and 9 xtask
tests, zero failures. Workflow absence and device preflight checks passed.
Build execution took 26 seconds; the private volume had 147 GiB available
before and after, and the helper reported exit 0 and drive deletion. Actions
permissions remained `enabled: false`. Subsequent changes are documentation
and accounting only; `600b7d2` removes the last automatic CI coverage-publication
promise. No executable code changed and no version bump is warranted.

The previously requested golden job `ea5a8e9a2762` selected flowsdn `4092ba1`
with stormcos `9b4b8d67fb58`, but produced no golden:
`ERROR: named in ONLY and not staged: flowsdn`. The owning failure is already
tracked in [stormcos#155](https://github.com/glennswest/stormcos/issues/155).
No duplicate stage request was submitted and no golden or release is claimed.
This separate staging failure does not invalidate workflow-removal validation.
