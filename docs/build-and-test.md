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

The build checkout holds **only the pushed commit**: a depth-1 clone with no
parent and no access to fetch more (#317). Commands that compare against history
(`git diff --check HEAD~1 HEAD`, `git log`, `cargo xtask plan BASE`) fail there.
Run change checks such as `git diff --check origin/main..HEAD` (whitespace) in the
session checkout before pushing; they read Git objects and build nothing. Give
sc-build whole-tree commands (`cargo metadata --locked`, `cargo fmt --check`,
builds and tests). The `WARNING: Sum of all thin volume sizes ...` line at the top
of every job is the build host's LVM notice (stormcentral#162), not a failure; the
real error follows it.

Commit and push fixes before the next validation run. Formatting or lockfile
changes produced remotely must also return through GitHub before their disposable
checkout is removed. Cargo caches are managed by the build service, not by a
GitHub cache action. The affected-crate selector in `xtask` remains a local
planning utility; retaining it does not schedule a workflow or certify a gate.

Running-component acceptance follows the stormcos test standard: test containers
built from `test/`, run as Jobs on the test machines, with hardware/kernel/resource
requirements declared rather than assuming a particular machine. flowsdn's image
is described in [test/README.md](../test/README.md): `test/build.sh` builds the
BPF objects with `tools/build-bpf.sh`, checks them and the agent's embedded
`local-delivery` and `socket-lb` against `bpf-objects.lock`, builds the static
musl binaries and the GNU `flowsdn-perf` (the `perf` suites, #321), and runs
`tools/check-no-cilium.sh` on what the golden ships (agent, CNI, embedded
objects; #330). stormcentral runs `/test short|medium|long|perf|perf-scale`
with `stormcentral test run flowsdn <suite> --tag <machine>`. Short and medium
have passed on hardware (pvetest2, 11.88-flowsdn: medium a0cd56f37c, short
dc492b2815; #303 closed); `perf` and the two-node runs still wait for machines
(#321, #291). Unit tests, cross-compilation and namespace fixtures alone do not
establish multi-node Kubernetes acceptance.

`cargo xtask cloud-scan` scans the recorded cloud fixtures under
`tests/cloud/**` for unscrubbed credentials and identifiers (ADR-0007 §2) and
loads each scenario. The xtask's unit test runs the same scan, so every
`sc-build` gates them. No build holds cloud credentials.

`tools/aya-kfunc-watch.sh` checks whether the latest aya release, aya main or
the latest bpf-linker can now relocate the `bpf_sock_destroy` kfunc. It exits 0
while they can't, 3 once one can, and 1 if the check itself breaks. It is meant
to run weekly as a stormcentral scheduled job
([stormcentral#384](https://github.com/glennswest/stormcentral/issues/384)),
which files the P1 switch issue on exit 3.
See [its README](../tools/aya-kfunc-watch/README.md) and
[#315](https://github.com/glennswest/flowsdn/issues/315).

## Kernel check in a build VM

`cargo xtask kernel-check [SUITE]` (default `medium`) runs the commit's test
suite on a real kernel without root (#370, #292). A build job cannot load a BPF
object, but a build VM has `/dev/kvm`, qemu and a readable kernel, so the check
boots `/lib/modules/$(uname -r)/vmlinuz` with an initramfs of `test/.stage`,
`ip`, `nft`, `kmod` and the network modules, with `/test` as PID 1
(`test/src/vm_init.rs`), and reads the suite's JSON lines and every fixture's
log off the serial port. A guest that ends without a result, a skipped datapath
or a summary with no pass all fail it.

```bash
sc-build 'test/build.sh && cargo xtask kernel-check'
```

The guest's /tmp is an ext4 image on a virtio disk when `mkfs.ext4` is there, so what the
agent syncs reaches a disk. Timings from it are not a node's: read `cni-add-timing` with
the fsync number it prints, and don't run another build beside one you mean to compare.

**Before `component stage flowsdn`, this must pass at the commit (or one with
the same `bpf-objects.lock`), and the stage's comment names it.** It catches what
the lock cannot: the lock proves the committed bytes match a rebuild, not that
the kernel accepts them. Its first run refused `socket-lb`, which had passed
sc-build and sat on main for three weeks with no machine to run it on: `R0
unbounded memory access` on the Maglev table index.

A stage builds main's head when its turn comes, not the commit you checked, so
push nothing that changes code or objects until the stage has started. Stage
`5ec614dc2136` took 07c64f2, a commit in the middle of the DSR work.

It does not replace a hardware run: the kernel is the build VM's Fedora kernel
rather than a stormcos release's, there is no node, cluster or real NIC, and the
node probes skip. Fixtures that need a live cluster (`perf`) cannot run in it.

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

Standalone release archives (ADR-0019, for clusters without stormcos) are
built with `deploy/release/build.sh OUT_DIR [TARGET...]`, for example
`sc-build 'deploy/release/build.sh "$TMPDIR/release"'`: static musl
`flowsdn-agent` and `flowsdn-cni` for amd64 and arm64 in
`flowsdn-<version>-<arch>.tar.gz` (with `bpf-objects.lock`, LICENSE, NOTICE,
README and REVISION), the Helm chart `flowsdn-<version>.tgz` when `helm` is
installed (after `cargo xtask chart-check`), and `SHA256SUMS` over both.
The archives' agent is the default musl build: it embeds `local-delivery` only
and refuses a `kubernetes` section, so it has no Node/Pod watches or socket LB;
the chart uses the GNU Kubernetes-mode agent image from `images/agent/build.sh`
(`localhost/flowsdn-agent:<version>`, optionally an OCI archive). Every script
runs `tools/check-no-cilium.sh` on its output. None of this is part of the
flowsdn golden, and nothing uploads it; sc-build deletes it with its drive, so
publication needs its own recorded step.

`bpf-objects.lock` pins the BPF objects (#245). `test/build.sh` runs
`tools/bpf-objects-lock.sh check` on the objects it builds and fails on a stale
lock or embedded copy. After changing `crates/flowsdn-bpf`, rebuild through
sc-build (`tools/build-bpf.sh "$TMPDIR/bpf" && tools/bpf-objects-lock.sh write
"$TMPDIR/bpf" && cat bpf-objects.lock`) and commit the new embedded objects and
lock; the agent's unit tests check the embedded bytes against it. sc-build hands
no files back from the build VMs, so the objects come back through the build log
(for example base64-encoded; stormcentral#543).
Documentation-only changes do not claim a new networking release.

## Older specifications and evidence

Historical runner audits, workflow runs and release records describe their named
revision and date. Upstream workflow paths in inventories and specifications
remain source provenance. Test matrices still describe required coverage, but
GitHub-hosted/self-hosted Actions execution and automatic workflow publication
are superseded by this build contract.
