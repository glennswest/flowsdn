# Builds, tests and publication

GitHub Actions is disabled for flowsdn. The obsolete `crates.yml` workflow was
removed under [#304](https://github.com/glennswest/flowsdn/issues/304). There is
no Actions runner to provision, enablement variable to set, or tag workflow
that automatically builds, tests or publishes artifacts.

## Development and maintainer validation

Ordinary development uses the Cargo commands in the [README](../README.md).
Maintainer sessions use the managed build service after committing and pushing:

```sh
git push
sc-build
# Or select the existing broader project checks:
sc-build 'cargo xtask check'
```

`sc-build` fetches the exact pushed commit, runs the command in a disposable
build directory and removes that checkout on success or failure. Its default
command is `cargo build && cargo test`. There is no persistent checkout to use
on the build host. Do not copy working trees or run builds on the session VM.
A wait for a shared build slot is normal; let the request finish rather than
submitting duplicate builds. Record the revision, command and actual result.

Commit and push fixes before the next validation run. Formatting or lockfile
changes produced remotely must also return through GitHub before their disposable
checkout is removed. Cargo caches are managed by the build service, not by a
GitHub cache action. The affected-crate selector in `xtask` remains a local
planning utility; retaining it does not schedule a workflow or certify a gate.

Running-component acceptance follows the stormcos test standard: test containers
built from `test/`, run as Jobs on the test machines, with hardware/kernel/resource
requirements declared rather than assuming a particular machine. flowsdn's image
is described in [test/README.md](../test/README.md): `test/build.sh` builds the
BPF objects with `tools/build-bpf.sh`, refuses a stale embedded
`local-delivery` or `socket-lb` in the agent, builds the static musl binaries
and the GNU `flowsdn-perf` (the `perf` suite, #321); and stormcentral
runs `/test short|medium|long` with `stormcentral test run flowsdn <suite>`.
Running it on a test machine is still open
([#303](https://github.com/glennswest/flowsdn/issues/303)).
Unit tests, cross-compilation and namespace fixtures alone do not establish
multi-node Kubernetes acceptance.

`tools/aya-kfunc-watch.sh` checks whether the latest aya release, aya main or
the latest bpf-linker can now relocate the `bpf_sock_destroy` kfunc. It exits 0
while they can't, 3 once one can, and 1 if the check itself breaks. It is meant
to run weekly through stormcentral
([stormcentral#384](https://github.com/glennswest/stormcentral/issues/384)).
See [its README](../tools/aya-kfunc-watch/README.md) and
[#315](https://github.com/glennswest/flowsdn/issues/315).

## Goldens and release artifacts

After an implementation is pushed and verified, request the flowsdn golden once:

```sh
stormcentral component stage flowsdn --url "$STORMCENTRAL_URL"
```

flowsdn is a special component built through stormcos stage mode. Ordinary
components use `stormcentral component build <component>` instead; that is not
the flowsdn path. Staging waits for its turn, records an immutable golden and
files the release request. The release orchestrator composes ready goldens into
a release train and runs its gates. Do not build a golden by another path or
wait idle for a release after completing component work.

GitHub remains the source-transfer and results path. Distributable artifacts
may be explicitly published through GitHub Releases after validation; pushing
a commit or tag does not trigger an Actions build, image push, tarball upload or
release attachment. Record only artifacts actually produced and published.
Documentation-only changes do not claim a new networking release.

## Older specifications and evidence

Historical runner audits, workflow runs and release records describe their named
revision and date. Upstream workflow paths in inventories and specifications
remain source provenance. Test matrices still describe required coverage, but
GitHub-hosted/self-hosted Actions execution and automatic workflow publication
are superseded by this build contract.
