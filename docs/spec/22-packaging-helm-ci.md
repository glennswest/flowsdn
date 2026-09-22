# Packaging, container images, Helm chart and CI — specification

Status: draft. Derived from: `docs/inventory/15-helm-images-ci-tests.md` (primary),
`docs/kernel-requirements.md` §4.5–4.6 and §5.3, `docs/licensing.md`,
`docs/spec/00-foundation-table-config.md` (§6 config key space, §6.2
`build-config`), `docs/spec/02-datapath-programs.md` (§6.2 build dimensions,
§9.4 verifier gate), `docs/spec/09-cni-plugin.md` (§3.12 install/uninstall,
§6.3 Helm mapping), `docs/spec/19-e2e-connectivity.md` (acceptance gates), and
the section 11 crate lists of specs `00`–`16`. Reference cilium v1.20.1
(7d68cfb394) paths `install/kubernetes/**`, `images/**`, `.github/workflows/**`,
`.github/actions/**`, `Makefile*`, `contrib/**`. Governed by ADR-0001 (full
scope, boundary compatibility), ADR-0002 (Rust only, no C), ADR-0003 (no
iptables), ADR-0004 (no Hive/StateDB), ADR-0005 (harvest tests, Rust harnesses),
and the cross-project rules in `../CLAUDE.md` (build on `<build-host>`, cargo
target dirs under `<cargo-target-dir>`, nothing persists on the SSD).

Normative language: MUST / SHOULD / MAY as in RFC 2119. **DEVIATION** marks a
deliberate difference from the reference with its reason and ADR.

**Amendments.** 2026-09-07 — §3.8.1 states the **ADR-0006** single-repository /
single-workspace decision explicitly and names its two later extraction
candidates; §3.10.2 gains the **ADR-0007** cloud-fake pull-request jobs and the
weekly live-cloud drift-detection job, and the "cloud conformance jobs are
deferred" note is corrected, since ADR-0007 supersedes it.

## 1. Scope

In scope: the set of binaries flowsdn ships and how each is targeted, sized and
built; the container images and their multi-arch construction with podman; the
Helm chart as a compatibility contract over the reference's values surface; the
Cargo workspace, the two Rust toolchains and the BPF object build; versioning,
tagging and artifact publication; the CI workflow set, its kernel × architecture
matrix and its relationship to `<build-host>`; the local developer loop.

Out of scope, owned elsewhere: the meaning of any individual config key (spec
`00` §6.4); CNI plugin behaviour (spec `09`); the datapath variant set and what
each `.rodata` gate does (spec `02` §6.2); the connectivity suite's scenarios
(spec `19`); the scripttest and BPF harness designs (specs `17`, `18`); CRD
YAML vendoring (spec `13` §4.2); RBAC verb detail (spec `13`).

This spec owns the *shape* of the DaemonSet, Deployments and ConfigMap; the
per-container capability sets and hostPath list; and the mapping from Helm
values to config keys. It does not own the keys themselves.

## 2. Compatibility contract

These are the interfaces a flowsdn install MUST present so that `cilium-cli`
(`install`, `upgrade`, `status`, `config get/set`, `sysdump`, `clustermesh`,
`hubble enable`), the reference's Grafana dashboards, existing user
`values.yaml` files and a mixed Cilium/flowsdn cluster keep working.

| Interface | Value | Consumer that depends on it |
|---|---|---|
| Helm release object names | `cilium` (DaemonSet, SA, ClusterRole, Service), `cilium-operator`, `cilium-envoy`, `cilium-config` (ConfigMap), `cilium-secrets` (Namespace), `hubble-relay`, `hubble-ui`, `clustermesh-apiserver` | `cilium-cli` resolves components by these names; `cilium status` fails on any rename |
| Chart values keys | the reference's ~1580 leaf keys, unchanged in name, type and default | user `values.yaml`, `cilium install --helm-set` in CI |
| ConfigMap keys | the reference's 426 keys as rendered by `cilium-configmap.yaml` (inventory 15 §F4), all of which appear in the spec `00` §6.4 registry | `cilium-cli` feature detection, `cilium config get`, the drift checker |
| Agent config surface | `--config-dir` with one file per key; unknown keys ignored with a warning (spec `00` §3.3) | `extraConfig`, `CiliumNodeConfig`, forward compat |
| Probe endpoints and ports | `127.0.0.1:9879/healthz` (agent), `:9878` (Envoy), `:9880/:9881` (clustermesh), `:9962/:9963/:9964/:9965/:9966` metrics, `:4240` health, `:4244` Hubble peer, `:4245` relay | probes, ServiceMonitors, dashboards |
| Node labels/taints | `node.cilium.io/agent-not-ready` taint key, `io.cilium/app`, `k8s-app=cilium` | operator taint removal, anti-affinity, `cilium status` |
| CRD group | `cilium.io` with the reference schemas (spec `13`) | mixed clusters, existing policies |
| Pinned BPF map paths | `/sys/fs/bpf/tc/globals/cilium_*` (spec `01` §2.1) | Envoy `cilium.bpf_metadata`, `bpftool`, mixed-node debugging |
| CNI binary name and conflist | `/opt/cni/bin/cilium-cni`, `/etc/cni/net.d/05-cilium.conflist` (spec `09`) | kubelet, chained plugins |
| Chart annotation | `flowsdn.io/cilium-compat: "1.20"` on `Chart.yaml` | tooling that needs to know which reference minor the values surface tracks |

**DEVIATION (chart name).** The chart is named `flowsdn`, not `cilium`. The
*objects it creates* keep the reference names. A chart rename is observable only
by `helm list`; an object rename would break `cilium-cli` and every dashboard.

**DEVIATION (image references).** `image.repository` and friends default to
flowsdn images (§3.9.4). The value names are unchanged, so `--set
image.repository=` still works.

## 3. Behavior

### 3.1 The binary set

flowsdn ships **six** shipped binaries plus one dev-only tool. Everything that
the reference does with a shell script, a helper Go binary copied onto the host,
or `nsenter` becomes a subcommand of the agent binary (§3.2), because a
`scratch` image has no shell (ADR-0001).

| Binary | Package | Target triples | libc | Stripped size budget | Separate or subcommand |
|---|---|---|---|---|---|
| `flowsdn` | `flowsdn-agent` | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` | **static musl** | **≤ 60 MiB** (incl. embedded BPF objects and the vendored CRD YAML) | Separate; multi-call — `agent`, `build-config`, `cni`, `mount-bpffs`, `mount-cgroup`, `sysctl-fix`, `cleanup`, `wait`, `preflight`, `version` |
| `flowsdn-cni` | `flowsdn-cni` | same two | **static musl** | **≤ 6 MiB** (spec `09` §11 sets < 5 MiB as the target; 6 MiB is the CI gate) | **Separate binary, deliberately.** The kubelet execs it once per sandbox operation; it must not pay the agent's link-time or page-in cost, and it must not contain tokio |
| `flowsdn-operator` | `flowsdn-operator` | same two, × 4 feature variants | **static musl** | **≤ 45 MiB** generic, **≤ 90 MiB** cloud variants (AWS/Azure SDKs) | Separate; subcommands `run` (default), `version`, `preflight` |
| `flowsdn-dbg` | `flowsdn-dbg` | same two, plus `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin` for the release archive | musl in the image, gnu/darwin for the workstation archive | **≤ 25 MiB** | Separate; ships inside the agent image *and* as a standalone release artifact |
| `flowsdn-relay` | `flowsdn-hubble-relay` | same two | **static musl** | **≤ 25 MiB** | Separate binary and image (spec `11` rewrites the relay) |
| `flowsdn-dnsproxy` | `flowsdn-dnsproxy-standalone` | same two | **static musl** | **≤ 20 MiB** | Separate binary and image (spec `16`; alpha, off by default) |
| `flowsdn-connectivity` | `flowsdn-connectivity` | same two, plus `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` | musl for the in-cluster job, gnu/darwin for the workstation | **≤ 30 MiB** | Separate; the spec `19` acceptance suite, run **out of cluster** against a kubeconfig, and optionally as a Job |
| `xtask` | `xtask` | host only | host | — | Dev-only, never shipped (§3.11) |

Not shipped as binaries, contrary to the reference:

- **`cilium-health`** — the reference execs `cilium-health` inside the
  `lxc_health` netns. flowsdn runs the health responder as an in-process thread
  that `setns`es into that netns (`docs/kernel-requirements.md` §1, "Health"
  row). No binary, no `ip route add` exec.
- **`cilium-mount`, `cilium-sysctlfix`, `cilium-envoy-bootstrap-locality`** —
  static Go helpers the reference *copies onto the host* and runs under
  `nsenter`. They become `flowsdn mount-cgroup`, `flowsdn sysctl-fix` and
  (when the Envoy DaemonSet is enabled) `flowsdn envoy-locality`, run directly
  from the image with the host paths bind-mounted. Nothing is copied to the
  host, so there is no cleanup and no version skew between the copied helper
  and the running agent.
- **`cilium-bugtool`** — folded into `flowsdn-dbg bugtool`. It has no external
  binaries to shell out to (no `ip`, `ss`, `tc`, `bpftool`, `iptables-save` in
  the image); it collects the same information over netlink, `bpf(2)` and the
  agent API. What it genuinely cannot reproduce (`tcpdump`) is documented as an
  ephemeral-container workflow.
- **`clustermesh-apiserver`** — see §3.4, decision D-3: v1 reuses the upstream
  image; a `flowsdn-clustermesh-apiserver` binary lands with the ClusterMesh
  spec (`20`).

Size budgets are enforced by CI (`xtask size-check`, §3.10) against
`docs/size-budget.toml`; exceeding a budget fails the PR, and the report is a
build artifact so the trend is visible (§9).

**Why one multi-call agent binary.** The reference's agent image carries eleven
Go binaries totalling ~450 MB because each statically links its own copy of the
runtime, the k8s client and the API models. One multi-call binary shares all of
that. For the agent, `argv[0]`-style dispatch is not used; dispatch is on
`argv[1]`, and every init container's `command` is `["/flowsdn", "<subcommand>",
...]`. `flowsdn-cni` is the one binary excluded from the merge, because its cost
model is per-pod-operation exec latency, not image size. Its loopback entry
point uses executable-name dispatch as specified in spec `09` (#240).

### 3.2 Init and lifecycle subcommands

Each replaces one reference init container, lifecycle hook or shell script.
Every one of these MUST be idempotent: the kubelet restarts init containers on
pod restart, and a partially-completed run must converge on re-run without
manual cleanup.

| Subcommand | Replaces | Behaviour | Idempotency |
|---|---|---|---|
| `flowsdn build-config --node-name … [--dest /tmp/cilium/config-map] [--source …] [--allow-config-keys …] [--deny-config-keys …]` | init `config` (`cilium-dbg build-config`) | Spec `00` §6.2: resolve `config-map` → `cilium-node-config` → `node` sources in order, write a Kubernetes-style atomic directory (`..data_<unix>` dir, `..data` symlink swapped through `..data.tmp`, one symlink per key) plus the synthetic `config-sources` / `config-sources-overrides` keys | **Yes.** Writes a new timestamped data dir and swaps one symlink; a crash before the swap leaves the previous dir intact; a crash after leaves an orphan dir, removed on the next successful run (keep the newest two). Re-running with identical inputs produces an identical directory and MUST NOT swap (compare content hash first) so the agent's inotify does not fire |
| `flowsdn mount-bpffs [--path /sys/fs/bpf]` | init `mount-bpf-fs` (`mount \| grep … \|\| mount -t bpf`) | `statfs(path)`; if `f_type == BPF_FS_MAGIC (0xcafe4a11)` exit 0 silently. Else `mkdir -p` and `mount("bpf", path, "bpf", 0, NULL)`. Exit non-zero with the `sys-fs-bpf.mount` unit named in the message if the mount fails | **Yes.** The `statfs` check makes the second run a no-op. Never unmounts |
| `flowsdn mount-cgroup [--root /run/cilium/cgroupv2]` | init `mount-cgroup` (`cp cilium-mount /hostbin; nsenter …`) | `statfs("/sys/fs/cgroup")`; if it is `CGROUP2_SUPER_MAGIC (0x63677270)` **and** `--prefer-host` (default true), print the host root and exit 0 — nothing is mounted. Otherwise `mkdir -p <root>` and `mount("none", root, "cgroup2", 0, NULL)`. The resolved root is written to `<state-dir>/cgroup-root` for the agent | **Yes.** `statfs` on the target short-circuits a second mount. **DEVIATION:** no `cp` to the host, no `nsenter`, no `SYS_CHROOT`/`SYS_PTRACE` — the container mounts into its own mount namespace with `Bidirectional` propagation on the hostPath, which is what actually makes the mount visible to the host |
| `flowsdn sysctl-fix [--sysctl-dir /host/etc/sysctl.d] [--procfs /host/proc]` | init `apply-sysctl-overwrites` (`cilium-sysctlfix` via nsenter + D-Bus) | Render `99-zzz-override_flowsdn.conf` (`-net.ipv4.conf.lxc*.rp_filter=0`, `-net.ipv4.conf.cilium_*.rp_filter=0`, `net.ipv4.conf.all.rp_filter=0`) and write it **only if the content differs**; then ask systemd to re-apply via `zbus` (`RestartUnit("systemd-sysctl.service")`). If D-Bus is absent (no systemd host) log at INFO and exit 0 — the agent sets per-device sysctls at link creation through `/host/proc/sys/net` anyway (`docs/kernel-requirements.md` §4.3) | **Yes.** Compare-then-write; the D-Bus restart is idempotent by nature. Removing the file on uninstall is `flowsdn cleanup --all-state` |
| `flowsdn cleanup [--bpf-state] [--all-state] [--force]` | init `clean-cilium-state` (`/init-container.sh` → `cilium-dbg post-uninstall-cleanup`) | Read `clean-cilium-bpf-state` / `clean-cilium-state` from the config dir if the flags are absent, exactly as the reference reads the two env vars. `--bpf-state`: unpin every map/prog/link under `/sys/fs/bpf/tc/globals/cilium_*` and `/sys/fs/bpf/cilium/**`, detach tcx/netkit/XDP/cgroup links flowsdn owns. `--all-state`: additionally remove `cilium_host`/`cilium_net`/`cilium_vxlan`/`cilium_geneve`/`cilium_wg0`/`cilium_ipip*` links, flowsdn's routes and rules (tables 200, 202, 2004, 2005), the `inet flowsdn` nftables table, `<state-dir>/state/**`, `/etc/sysctl.d/99-zzz-override_flowsdn.conf` and the conflist | **Yes.** Every step is "remove if present"; `ENOENT`/`ENODEV` are success. Never touches a link, route, rule or nft table it does not own (ownership by name prefix and by the nft table name) |
| `flowsdn cni install` | init `install-cni-binaries` (`/install-plugin.sh`) | Spec `09` §3.12: `mkdir -p $CNI_DIR/bin`; copy `loopback` if absent or `OVERWRITE_LOOPBACK=true`; copy the plugin to `.cilium-cni.new` and `rename(2)` it onto `cilium-cni`; hard-link `flowsdn-cni` to the same inode | **Yes.** `rename(2)` is atomic even over a binary the kubelet is executing; re-running overwrites with the same bytes. A failed loopback copy is ignored |
| `flowsdn cni uninstall` | agent `preStop` (`/cni-uninstall.sh`) | Spec `09` §3.12: exit unless `cni-uninstall=true`; unless `CILIUM_CUSTOM_CNI_CONF=true`, delete regular files in `$CNI_CONF_DIR` whose name contains `cilium` and ends `.conf`/`.conflist`. `*.cilium_bak` is left alone; the binary is never removed | **Yes.** Deletion of an absent file is success |
| `flowsdn wait --for=node-init [--file /tmp/cilium-bootstrap.d/cilium-bootstrap-time] [--timeout 5m]` | init `wait-for-node-init` (`until test -s …; do sleep 1; done`) | Poll for a non-empty file with a 1 s interval and inotify where available; exit 0 on success, non-zero with a clear message on timeout | **Yes.** Read-only |
| `flowsdn wait --for=kube-proxy [--timeout 5m]` | init `wait-for-kube-proxy` (privileged; four `iptables-*-save` loops) | **DEVIATION (ADR-0003).** No `iptables` binary exists. Detection order: (1) query `NETLINK_NETFILTER` for a chain named `KUBE-IPTABLES-HINT` or `KUBE-PROXY-CANARY` in tables `ip mangle`/`ip nat` — `iptables-nft` rules *are* nftables objects and are visible this way, needing only `CAP_NET_ADMIN`, not privileged; (2) if `/proc/net/ip_tables_names` exists and lists `mangle` or `nat`, the host runs legacy xtables and the chain is not visible over nftables netlink — in that case fall back to (3) watching the kube-proxy DaemonSet's pod on this node via the k8s API and waiting for it to be `Ready`. Method (3) is also the only method when `waitForKubeProxy` is set on a cluster whose kube-proxy runs in ipvs mode | **Yes.** Read-only. **Capability reduction:** the reference's `wait-for-kube-proxy` init container is `privileged: true`; flowsdn's needs `NET_ADMIN` only (methods 1–2) or nothing at all (method 3) |
| `flowsdn preflight validate-cnp` | `cilium-dbg preflight validate-cnp` in the CNP-validator Deployment | Parse every CNP/CCNP through the spec `06` `Sanitize` path, report the same error strings, exit non-zero if any fails | **Yes.** Read-only |
| `flowsdn preflight pull` | preflight DaemonSet's `/bin/sh -c 'touch /tmp/ready'` containers | Their only job is to *pre-pull the image*; the container body is irrelevant. flowsdn's is `["/flowsdn", "preflight", "pull"]`, which writes `/tmp/ready` and sleeps until SIGTERM | **Yes** |
| `flowsdn version [--json]` | `cilium version` | Prints §9.1 build metadata | **Yes** |

**`sleepAfterInit`** (the reference replaces the agent `command` with a `sleep`
loop as an uninstall aid) has no shell to run in. It maps to `["/flowsdn",
"agent", "--sleep-after-init"]`, which performs the init work and then idles.

**The `monitor` sidecar** (`monitor.enabled`) becomes `["/flowsdn-dbg",
"monitor"]` instead of `/bin/bash -c "cilium-dbg monitor"`.

### 3.3 Container images

Every flowsdn image is `FROM scratch` (ADR-0001, ADR-0002). There is no OS
layer, no shell, no package manager, no `clang`, no `iptables`, no `bpftool`.

| Image | Contents | Est. uncompressed size |
|---|---|---|
| `flowsdn` (agent) | `/flowsdn` (multi-call), `/flowsdn-cni`, `/flowsdn-dbg`, `/cni/loopback` (the Rust `flowsdn-cni` artifact installed under its loopback entry point; spec `09`), `/etc/ssl/certs/ca-certificates.crt`, `/etc/passwd` + `/etc/group` (two lines each, so `runAsUser` works for the non-root containers of other images that share this base pattern), `/LICENSE`, `/NOTICE` | **~100 MiB** (vs ~500–650 MiB for `quay.io/cilium/cilium`) |
| `flowsdn-operator{,-aws,-azure,-alibabacloud}` | `/flowsdn-operator`, CA bundle, licences | 45–95 MiB |
| `flowsdn-relay` | `/flowsdn-relay`, CA bundle, licences | ~25 MiB |
| `flowsdn-dnsproxy` | `/flowsdn-dnsproxy`, CA bundle, licences | ~20 MiB |
| `flowsdn-connectivity` | `/flowsdn-connectivity`, CA bundle, licences | ~30 MiB |

Notes on the contents.

- **BPF objects are inside the agent binary**, not on disk
  (`include_bytes_aligned!`, §3.8.4). There is no `/var/lib/cilium/bpf`, no
  header tree, and no per-endpoint compile — which is the single biggest reason
  the image is 5× smaller than the reference's.
- **The CA bundle is present but usually unused.** TLS to the API server uses
  the service-account CA at
  `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`; TLS to cloud APIs
  uses `webpki-roots` compiled into the binary. `/etc/ssl/certs` exists for the
  corporate-proxy case and costs ~230 KiB.
- **No timezone database.** All timestamps are UTC and RFC 3339.
- **No `/tmp`.** The Helm chart mounts an `emptyDir` there
  (`tmpVolume`), as the reference does.

#### 3.3.1 Labels

Every image MUST carry the OCI annotations plus flowsdn-specific labels. All
values are build inputs; none are computed at build time from the clock (§3.8.7).

```
org.opencontainers.image.title=flowsdn
org.opencontainers.image.description=eBPF networking, security and observability — Rust
org.opencontainers.image.version=<semver, no leading v>
org.opencontainers.image.revision=<full git sha>
org.opencontainers.image.created=<SOURCE_DATE_EPOCH as RFC 3339>
org.opencontainers.image.source=https://github.com/glennswest/flowsdn
org.opencontainers.image.url=https://github.com/glennswest/flowsdn
org.opencontainers.image.documentation=https://github.com/glennswest/flowsdn/tree/main/docs
org.opencontainers.image.licenses=Apache-2.0
org.opencontainers.image.vendor=flowsdn
org.opencontainers.image.base.name=scratch
io.flowsdn.component=agent|operator|relay|dnsproxy|connectivity
io.flowsdn.rust.toolchain=<stable version from rust-toolchain.toml>
io.flowsdn.bpf.toolchain=<nightly-YYYY-MM-DD>/<bpf-linker version>
io.flowsdn.bpf.objects=<sha256 of bpf-objects.lock>
io.flowsdn.kernel.min=6.6
io.flowsdn.kernel.line=6.12
io.flowsdn.reference=cilium/cilium@7d68cfb394 (v1.20.1)
io.flowsdn.chart.compat=1.20
```

`io.flowsdn.bpf.objects` is what makes "does this image contain the datapath I
verified?" answerable without unpacking; it is the same hash the verifier
budget report is keyed by (§9.2).

#### 3.3.2 Multi-arch construction with podman

Per the user's rules: **podman, always; `scratch` base; OCI is a build-time
input only.** The build runs on `<build-host>`; nothing is built on the Mac.

```bash
# On <build-host>. Binaries are already cross-built (§3.8.5) into
# <cargo-target-dir>/<triple>/release/.
export SOURCE_DATE_EPOCH=$(git -C "$SRC" show -s --format=%ct HEAD)
export REG=sbregistry:5100            # or ghcr.io/glennswest, see §3.9.4
export VER=0.4.0

for arch in amd64 arm64; do
  podman build \
    --platform "linux/${arch}" \
    --timestamp "${SOURCE_DATE_EPOCH}" \
    --squash-all \
    --file images/agent/Containerfile \
    --build-arg TRIPLE="$( [ $arch = amd64 ] && echo x86_64 || echo aarch64 )-unknown-linux-musl" \
    --build-arg VERSION="${VER}" \
    --build-arg REVISION="$(git rev-parse HEAD)" \
    --tag "${REG}/flowsdn:${VER}-${arch}" \
    <cargo-target-dir>
done

podman manifest create "${REG}/flowsdn:${VER}"
podman manifest add "${REG}/flowsdn:${VER}" "containers-storage:${REG}/flowsdn:${VER}-amd64"
podman manifest add "${REG}/flowsdn:${VER}" "containers-storage:${REG}/flowsdn:${VER}-arm64"
podman manifest push --all "${REG}/flowsdn:${VER}" "docker://${REG}/flowsdn:${VER}"
podman manifest inspect "${REG}/flowsdn:${VER}"   # assert 2 manifests, correct arch/os
```

Rules:

1. `--squash-all` produces exactly one layer. With four files in the image
   there is nothing to gain from layer reuse and everything to gain from a
   byte-identical single layer (§3.8.7).
2. `--timestamp` sets every file mtime and the config `created` to
   `SOURCE_DATE_EPOCH`, which is the commit time, never `now`.
3. The `Containerfile` is `FROM scratch` + `COPY` + `LABEL` + `ENTRYPOINT`
   only. **No `RUN`.** A `RUN` in a scratch image is impossible anyway (no
   shell), which is a useful forcing function: everything that would have been
   a `RUN` is a build step outside the image.
4. The manifest list is created locally and pushed with `--all`; the per-arch
   tags are pushed too (they are what `kind load` and `podman save` use).
5. `podman save --format oci-archive` of the *manifest list* produces the
   release tarball (§3.9.4).

#### 3.3.3 The Containerfile shape (agent)

```
FROM scratch
ARG TRIPLE
ARG VERSION
ARG REVISION
COPY ${TRIPLE}/release/flowsdn        /flowsdn
COPY ${TRIPLE}/release/flowsdn-cni    /flowsdn-cni
COPY ${TRIPLE}/release/flowsdn-dbg    /flowsdn-dbg
COPY ${TRIPLE}/release/flowsdn-cni    /cni/loopback
COPY assets/ca-certificates.crt       /etc/ssl/certs/ca-certificates.crt
COPY assets/passwd                    /etc/passwd
COPY assets/group                     /etc/group
COPY LICENSE NOTICE                   /
LABEL org.opencontainers.image.version="${VERSION}" …
ENTRYPOINT ["/flowsdn"]
CMD ["agent"]
```

`ENTRYPOINT ["/flowsdn"]` with `CMD ["agent"]` means the Helm chart's init
containers specify only `args: ["mount-bpffs"]`, which reads well and keeps the
manifest short.

### 3.4 Upstream images reused unchanged

flowsdn does not rebuild what it does not reimplement. Each reuse is justified
below; each carries a `NOTICE` entry per `docs/licensing.md`.

| Image | Reference tag at v1.20.1 | Reused? | Justification |
|---|---|---|---|
| `quay.io/cilium/cilium-envoy` | `v1.37.5-…` (digest-pinned), multi-arch | **Yes, unchanged** | ADR-0001 keeps Envoy as the L7 proxy; replacing it is a separate project. The image is Apache-2.0 (`cilium/proxy`), already multi-arch, digest-pinned by the chart, and the agent↔Envoy contract is xDS over a unix socket (spec `16`) — an interface, not a link-time dependency. Rebuilding Envoy would import a C++ toolchain into a project whose first rule is "no C" |
| `quay.io/cilium/hubble-ui`, `hubble-ui-backend` | `v0.13.5`, digest-pinned | **Yes, unchanged** | The UI is a React application; the backend is a thin gRPC-web proxy. flowsdn implements the *server API they speak* (spec `11`), which is the part that matters. Apache-2.0. Rewriting a web UI in Rust buys nothing |
| `quay.io/cilium/hubble-relay` | `v1.20.1` | **No — flowsdn ships `flowsdn-relay`** | Spec `11` §11.1 specifies `flowsdn-hubble-relay` (~2.5k lines). The relay is pure Rust-shaped work (peer pool, fan-out, sort-merge) and reusing the Go relay would mean shipping a Go binary in a Rust project for no benefit. It also needs to speak our peer service |
| `quay.io/cilium/certgen` | `v0.4.9`, digest-pinned | **Yes for v1**, replace later (D-4) | Only used when `tls.auto.method=cronJob`; the default (`helm`) generates certificates in the chart with no image at all. Reimplementing X.509 issuance is 1–2k lines of `rcgen` + `kube` for a path most installs never take. Revisit once `flowsdn certgen` costs less than the reuse |
| `quay.io/cilium/startup-script` (nodeinit) | `1782916218-36ae25f`, digest-pinned | **Yes, unchanged** | `nodeinit` exists to run **bash on the host** via `nsenter --target=1` for GKE/COS-style nodes: rewriting kubelet flags, editing `/etc/containerd/config.toml`, deleting `cbr0`. That is host administration, not networking; it is inherently a shell job, it runs once at node bootstrap, and flowsdn has no better answer. Off by default (`nodeinit.enabled=false`) |
| `ghcr.io/spiffe/spire-server`, `spire-agent`, `docker.io/library/busybox` | `1.15.2`, `1.38.0`, digest-pinned | **Yes, unchanged** | Mutual auth is deferred (spec `16`). SPIRE is a third-party product; the busybox is SPIRE's own init |
| `quay.io/cilium/clustermesh-apiserver` | `v1.20.1` | **Yes for v1** (D-3) | Contains an embedded `etcd` v3.7.1 plus the apiserver and kvstoremesh. The ClusterMesh spec (`20`) is wave 4; until it lands, reusing the upstream image gives working ClusterMesh against a flowsdn agent because the contract is the etcd key space, not the binary. When spec `20` lands, flowsdn ships `flowsdn-clustermesh-apiserver` + the upstream static `etcd` binary in a scratch image |
| `quay.io/cilium/ztunnel` | `v1.0.0`, digest-pinned | **Yes, unchanged** | Istio's ambient proxy; `encryption.type=ztunnel` is deferred (spec `16`) |
| `quay.io/cilium/operator*` | `v1.20.1` | **No — flowsdn ships `flowsdn-operator`** | Spec `12` |

Reuse of an upstream image never changes the values that reference it: the
chart keeps `envoy.image.*`, `certgen.image.*`, `nodeinit.image.*` and the
digests as shipped by the reference chart, refreshed on each reference-tag bump
(§3.9.5).

### 3.5 The Helm chart

Layout, mirroring the reference so a `diff` between the two trees is a review
tool rather than a puzzle:

```
install/kubernetes/flowsdn/
  Chart.yaml                 name: flowsdn; version = appVersion = flowsdn semver
  values.yaml                the reference's key surface (§3.6), generated
  values.schema.json         generated from values.yaml + the key registry
  README.md                  helm-docs output
  templates/
    cilium-configmap.yaml    values -> the 426 config keys (generated, §3.6.1)
    validate.yaml            the reference's 48 guards + flowsdn's (§3.6.5)
    _helpers.tpl
    cilium-agent/            DaemonSet, ClusterRole, Role, bindings, SA, Service, ServiceMonitor
    cilium-operator/         Deployment, ClusterRole, Role, PDB, SA, metrics
    cilium-envoy/            unchanged from the reference (upstream image)
    cilium-preflight/        DaemonSet + cnp-validator Deployment
    cilium-nodeinit/         unchanged from the reference (upstream image)
    hubble/                  peer Service, metrics, TLS
    hubble-relay/            Deployment, ConfigMap, Service, PDB
    hubble-ui/               unchanged from the reference (upstream images)
    clustermesh-*/           unchanged from the reference for v1 (§3.4)
    spire/                   unchanged from the reference
    standalone-dns-proxy/
  files/                     Grafana dashboards (reference, CC BY 4.0 / Apache-2.0 per file)
```

#### 3.5.1 Agent DaemonSet

Pod: `hostNetwork: true`, `hostUsers: true`, `dnsPolicy: ClusterFirstWithHostNet`,
`priorityClassName: system-node-critical` (when `enableCriticalPriorityClass`),
`serviceAccountName: cilium`, `terminationGracePeriodSeconds: 1`,
`nodeSelector: {kubernetes.io/os: linux}`, `tolerations: [{operator: Exists}]`,
`updateStrategy: RollingUpdate maxUnavailable: 2`, pod anti-affinity on
`k8s-app=cilium` — all as the reference.

Pod `securityContext`: `appArmorProfile.type: Unconfined`,
`seccompProfile.type: Unconfined` (as the reference; a seccomp profile that
allows `bpf(2)`, `perf_event_open(2)`, `setns(2)` and `mount(2)` is future work,
D-8).

| Container | Command | Ports | Purpose |
|---|---|---|---|
| `cilium-agent` (main) | `/flowsdn agent --config-dir=/tmp/cilium/config-map` | hostPorts 9879 health, 4244 hubble-peer, 9962 prometheus, 9965 hubble-metrics | the agent |
| `cilium-monitor` (optional sidecar, `monitor.enabled`) | `/flowsdn-dbg monitor` | — | shares `/var/run/cilium` |

**DEVIATION:** hostPorts 9964 (envoy-metrics) and 9901 (envoy-admin) are not
declared on the agent pod, because embedded Envoy does not exist in flowsdn
(spec `16`); they live on the `cilium-envoy` DaemonSet only.

Probes, unchanged from the reference so `cilium status` and operator taint
removal behave identically:

| Probe | Endpoint | Settings |
|---|---|---|
| startup | `httpGet 127.0.0.1:9879 /healthz`, header `brief: true` | `failureThreshold: 300`, `periodSeconds: 2` (10 min budget) |
| liveness | same | `failureThreshold: 10`, `periodSeconds: 30`, `initialDelaySeconds: 5` |
| readiness | same | `failureThreshold: 3`, `periodSeconds: 30` |

`livenessProbe.requireK8sConnectivity` maps to
`agent-health-require-k8s-connectivity` (spec `00` §6.1).

Lifecycle:

- `postStart`: **none.** The reference runs `poststart-eni.bash` to delete AWS
  VPC-CNI iptables rules. **DEVIATION (ADR-0003):** flowsdn installs no iptables
  and does not edit anyone else's; ENI chaining requires
  `AWS_VPC_K8S_CNI_EXTERNALSNAT=true` on the VPC CNI, documented in the values
  comment for `cni.iptablesRemoveAWSRules` (§3.6.3).
- `preStop`: `exec: ["/flowsdn", "cni", "uninstall"]`.

Init containers, in order. Every `command` is the flowsdn binary; **no shell,
no `cp`, no `nsenter`**:

| # | Name | Gate | Command | Capabilities (`drop: [ALL]`, then add) |
|---|---|---|---|---|
| 1 | `config` | `daemon.configSources` unset or `config-map:*` | `["/flowsdn","build-config","--node-name","$(K8S_NODE_NAME)"]` | **none** (reference adds `NET_ADMIN`; flowsdn's resolver only talks to the API server and writes an emptyDir) |
| 2 | `mount-cgroup` | `cgroup.autoMount.enabled` | `["/flowsdn","mount-cgroup","--root","$(CGROUP_ROOT)"]` | `SYS_ADMIN` (reference: `SYS_ADMIN, SYS_CHROOT, SYS_PTRACE`) |
| 3 | `apply-sysctl-overwrites` | `sysctlfix.enabled` | `["/flowsdn","sysctl-fix"]` | `SYS_ADMIN` if the D-Bus restart is wanted; otherwise **none** with a plain hostPath write (reference: `SYS_ADMIN, SYS_CHROOT, SYS_PTRACE`) |
| 4 | `mount-bpf-fs` | `bpf.autoMount.enabled` and not `flowsdn.hostMounts.bpffs` | `["/flowsdn","mount-bpffs"]` | **`privileged: true`** — unchanged from the reference. `Bidirectional` mount propagation requires it; this is the one privileged container and it exits in milliseconds. Set `flowsdn.hostMounts.bpffs=true` (host provides `sys-fs-bpf.mount`) to remove it entirely |
| 5 | `wait-for-node-init` | `nodeinit.enabled` and `nodeinit.bootstrapFile` | `["/flowsdn","wait","--for=node-init"]` | none |
| 6 | `clean-cilium-state` | always | `["/flowsdn","cleanup"]` | `NET_ADMIN, BPF, SYS_ADMIN` (reference: `NET_ADMIN, SYS_MODULE, SYS_ADMIN, SYS_RESOURCE`) |
| 7 | `wait-for-kube-proxy` | `waitForKubeProxy` and KPR ≠ true | `["/flowsdn","wait","--for=kube-proxy"]` | `NET_ADMIN` (reference: **privileged**) |
| 8 | `install-cni-binaries` | `cni.install` | `["/flowsdn","cni","install"]` | none |
| 9 | `extraInitContainers` | user | user | user |

#### 3.5.2 Capability sets

Derived from `docs/kernel-requirements.md` §4.5. `securityContext.privileged=true`
remains a values switch (needed on hosts whose runtime profile filters `CAP_BPF`),
and when set it replaces the per-container sets exactly as the reference does.

| Container | `drop` | `add` | Removed vs the reference, and why |
|---|---|---|---|
| `cilium-agent` | `ALL` | `NET_ADMIN, NET_RAW, BPF, PERFMON, IPC_LOCK, SYS_ADMIN` (+ `CHOWN` when `envoy.enabled` or Hubble sockets need a proxy gid; + `NET_BIND_SERVICE` when `bgpControlPlane` uses a port < 1024) | `SYS_MODULE` (no iptables/xt modules, ADR-0003; the remaining modules autoload via the kernel's own `request_module`), `SYS_RESOURCE` (BPF memory is memcg-accounted since 5.11 and the floor is 6.6), `DAC_OVERRIDE, FOWNER, SETGID, SETUID` (package-install leftovers; scratch image, no runtime compile), `SYSLOG` (no dmesg/kptr reads), `KILL` (no embedded Envoy child to kill) |
| init `config` | `ALL` | — | `NET_ADMIN` |
| init `mount-cgroup` | `ALL` | `SYS_ADMIN` | `SYS_CHROOT, SYS_PTRACE` (no `nsenter`) |
| init `apply-sysctl-overwrites` | `ALL` | `SYS_ADMIN` | `SYS_CHROOT, SYS_PTRACE` |
| init `mount-bpf-fs` | — | `privileged: true` | unchanged (propagation) |
| init `clean-cilium-state` | `ALL` | `NET_ADMIN, BPF, SYS_ADMIN` | `SYS_MODULE, SYS_RESOURCE` |
| init `wait-for-kube-proxy` | `ALL` | `NET_ADMIN` | was `privileged: true` |
| init `wait-for-node-init`, `install-cni-binaries` | `ALL` | — | unchanged |
| `cilium-envoy` (upstream image) | `ALL` | `NET_ADMIN, SYS_ADMIN` (+ `NET_BIND_SERVICE` when `keepCapNetBindService`) | unchanged — not our image |
| `cilium-operator`, `hubble-relay`, `hubble-ui`, `clustermesh-apiserver`, preflight | `ALL` | — | unchanged; `runAsUser: 65532`, `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true` (the last is a **flowsdn addition** — a scratch image with no writable state can enforce it) |
| `nodeinit` (upstream image) | — | `SYS_MODULE, NET_ADMIN, SYS_ADMIN, SYS_CHROOT, SYS_PTRACE`, `hostPID: true` | unchanged — it runs bash on the host by design |

`CAP_BPF` and `CAP_PERFMON` require kernel ≥ 5.8; the flowsdn floor is 6.6
(`docs/kernel-requirements.md` §2.5), so they are always available. On a
container runtime too old to know the names, the chart falls back to
`SYS_ADMIN` — guarded by `flowsdn.legacyCapabilities` (§3.6.4).

#### 3.5.3 hostPath mounts

| Volume | hostPath | Type | Mounted at | flowsdn still needs it? |
|---|---|---|---|---|
| `cilium-run` | `daemon.runPath` = `/var/run/cilium` | `DirectoryOrCreate` | `/var/run/cilium` | **Yes.** `cilium.sock`, `hubble.sock`, `state/<epid>/`, envoy sockets — the compatibility surface for `cilium-dbg`, Hubble and Envoy |
| `cilium-netns` | `/var/run/netns` | `DirectoryOrCreate` | `/var/run/cilium/netns` (`HostToContainer`) | **Yes.** `setns` into the health endpoint netns |
| `bpf-maps` | `/sys/fs/bpf` | `DirectoryOrCreate` | `/sys/fs/bpf` (`Bidirectional` on agent + `mount-bpf-fs`) | **Yes.** Pinned maps, programs and links |
| `cilium-cgroup` | `cgroup.hostRoot` = `/run/cilium/cgroupv2` | `DirectoryOrCreate` | same (`HostToContainer`) | **Yes** when the host is hybrid/v1; on a unified host the agent uses `/sys/fs/cgroup` directly and this mount is inert |
| `cni-path` | `cni.binPath` = `/opt/cni/bin` | `DirectoryOrCreate` | `/host/opt/cni/bin` (install init only) | **Yes.** **Reduced:** the reference also mounts it as `/hostbin` on the `mount-cgroup` and `apply-sysctl` inits so it can `cp` helpers onto the host. flowsdn copies nothing, so those two mounts are gone |
| `etc-cni-netd` | `cni.confPath` = `/etc/cni/net.d` | `DirectoryOrCreate` | `/host/etc/cni/net.d` | **Yes.** The agent writes `05-cilium.conflist` |
| `host-proc-sys-net` | `/proc/sys/net` | `Directory` | `/host/proc/sys/net` | **Yes.** Per-device sysctls (`procfs=/host/proc`) |
| `host-proc-sys-kernel` | `/proc/sys/kernel` | `Directory` | `/host/proc/sys/kernel` | **Yes.** `random/boot_id` for IPsec, `unprivileged_bpf_disabled`, `timer_migration` |
| `host-etc-sysctld` | `/etc/sysctl.d` | `DirectoryOrCreate` | `/host/etc/sysctl.d` | **New in flowsdn.** Replaces the reference's `nsenter`-to-host write for `sysctl-fix` |
| `hostproc` | `/proc` | `Directory` | `/hostproc` (init containers) | **Dropped.** It existed only as an `nsenter --target=1` source |
| `lib-modules` | `/lib/modules` | — | `/lib/modules` (ro) | **Dropped (ADR-0003).** It existed for `xt_*`/`ip_set` autoload when the agent execs `iptables`. flowsdn's remaining modules (`vxlan`, `geneve`, `nf_tables`, `wireguard`, `sch_fq`, `xfrm_user`) autoload through the kernel's own `request_module` on first netlink use, from the host's module tree, with no container mount and no `CAP_SYS_MODULE` |
| `xtables-lock` | `/run/xtables.lock` | `FileOrCreate` | `/run/xtables.lock` | **Dropped (ADR-0003).** Nothing takes the xtables lock |
| `envoy-sockets` | `/var/run/cilium/envoy/sockets` | `DirectoryOrCreate` | same | **Yes** when the Envoy DaemonSet is on |
| `spire-agent-socket` | `dir(authentication.mutual.spire.adminSocketPath)` | `DirectoryOrCreate` | same | Yes when SPIRE is on (deferred feature) |
| `kube-config` | `kubeConfigPath` | `FileOrCreate` | same (ro) | Yes, optional |
| `cilium-bootstrap-file-dir` | `dir(nodeinit.bootstrapFile)` | `DirectoryOrCreate` | same | Yes when `nodeinit.enabled` |
| `extraHostPathMounts[]` | user | user | user | Yes |

Net effect: **three hostPaths removed** (`/proc`, `/lib/modules`,
`/run/xtables.lock`), **one added** (`/etc/sysctl.d`), two `/hostbin` mounts
removed from init containers.

#### 3.5.4 Operator Deployment and the other workloads

- **`cilium-operator` Deployment** — unchanged in shape: `replicas: 2`,
  `hostNetwork: true`, leader election via a `coordination/v1` Lease, anti-
  affinity on `io.cilium/app=operator`, `priorityClassName:
  system-cluster-critical`, ports 9234 (API, localhost), 9963 (metrics), PDB
  optional. Command `["/flowsdn-operator","run","--config-dir=/tmp/cilium/config-map"]`.
  Image suffix (`""`/`-aws`/`-azure`/`-alibabacloud`) is preserved as a values
  contract; the four images are four Cargo feature builds of one package
  (§3.8.2). Liveness: `httpGet 127.0.0.1:9234/healthz`; readiness:
  `httpGet 127.0.0.1:9234/readyz` also requires the CRD fence (spec 12 #164).
  Missing CRDs keep readiness false without inducing liveness restarts.
  Dashboard migration: [metrics compatibility](../compatibility/metrics.md).
- **`cilium-envoy` DaemonSet** — template unchanged (upstream image).
- **`hubble-relay` Deployment** — command `["/flowsdn-relay","serve"]`, config
  at `/etc/hubble-relay/config.yaml`, TLS at `/var/lib/hubble-relay/tls`, port
  4245, `runAsUser: 65532`.
- **`hubble-ui`, `spire`, `clustermesh-*`, `nodeinit`, `ztunnel`** — templates
  unchanged (upstream images).
- **preflight** — DaemonSet with `["/flowsdn","preflight","pull"]` containers
  (image pre-pull) and a `cnp-validator` Deployment running
  `["/flowsdn","preflight","validate-cnp"]`. The preflight ClusterRole MUST stay
  byte-identical to the agent's; the reference lints this
  (`contrib/scripts/check-preflight-clusterrole.sh`) and flowsdn keeps the lint.
- **standalone-dns-proxy** DaemonSet — `["/flowsdn-dnsproxy"]`, alpha, requires
  `dnsProxy.proxyPort != 0`.

### 3.6 Values surface

#### 3.6.1 The mapping is generated, not forked

The reference's `cilium-configmap.yaml` is 1591 lines of Go template producing
426 keys. Forking it means maintaining a Go template by hand against a Rust key
registry, and the two will drift silently.

**flowsdn generates `templates/cilium-configmap.yaml`, `values.yaml` and
`values.schema.json`** from two inputs:

1. `crates/flowsdn-config/keys.toml` — the 539-key registry of spec `00` §6.4
   (name, kind, default, class, help).
2. `install/kubernetes/mapping.toml` — for each config key, the Helm value(s)
   that feed it, the condition, and the version-gated default
   (`upgradeCompatibility`), transcribed once from inventory 15 §F4.

`cargo xtask chart gen` emits the three files; `cargo xtask chart check` fails
if the working tree differs from the generated output (so the generated files
are committed and reviewable).

**The gate that makes this a real contract** is `cargo xtask helm-diff`:
render the reference chart at the pinned tag and the flowsdn chart with the
*same* values file, extract both `cilium-config` ConfigMaps, and diff the key
sets and values. Every difference must appear in `install/kubernetes/known-diffs.toml`
with a class (`ignored`, `renamed`, `new`, `deviation`) and a reason. An
unexplained difference fails CI. This runs across a corpus of values files:
chart defaults, each of the reference's 41 e2e matrix configs (inventory 15
§F11), and the `contrib/testing/*.yaml` sets.

#### 3.6.2 Mapping rule

**Every value listed in inventory 15 §F4 maps to the same config key with the
same condition and the same version-gated default, unless it appears in
§3.6.3–3.6.5 below.** Restating 426 rows here would duplicate §F4 and guarantee
drift; the normative artefact is `mapping.toml`, and §F4 is its source.

The families, for orientation:

| Family | Values → keys | Status |
|---|---|---|
| Identity/cluster | `cluster.*`, `identityAllocationMode`, `identityChangeGracePeriod`, `identityManagementMode` → `cluster-name`, `cluster-id`, `identity-allocation-mode`, … | unchanged |
| Address families and routing | `ipv4/ipv6.enabled`, `routingMode`, `tunnelProtocol`, `tunnelPort`, `underlayProtocol`, `autoDirectNodeRoutes`, `ipv4NativeRoutingCIDR` | unchanged |
| BPF sizing and behaviour | the 32 `bpf.*` keys → `bpf-*-max`, `bpf-map-dynamic-size-ratio`, `preallocate-bpf-maps`, `enable-tcx`, `datapath-mode`, `monitor-aggregation*`, `bpf-events-*` | unchanged; `bpf.masquerade` see §3.6.3 |
| KPR / LB | `kubeProxyReplacement`, `nodePort.*`, `loadBalancer.*`, `maglev.*`, `socketLB.*` | unchanged |
| Policy | `policyEnforcementMode`, `policyCIDRMatchMode`, `policyAuditMode`, `k8sNetworkPolicy.*`, `hostFirewall.enabled`, `enableNonDefaultDenyPolicies` | unchanged |
| IPAM | the whole `ipam.*` tree plus `eni.*`, `azure.*`, `alibabacloud.*`, `gke.*`, `aksbyocni.*` | unchanged |
| Encryption / egress | `encryption.*`, `egressGateway.*`, `ipMasqAgent.enabled` | unchanged except `encryption.type=ztunnel` (deferred, warns) |
| Hubble | the 16-key `hubble.*` tree → `enable-hubble`, `hubble-*` (37 keys) | unchanged |
| Envoy / L7 | `l7Proxy`, the 52-key `envoy.*` tree, `envoyConfig.*`, `ingressController.*`, `gatewayAPI.*` | unchanged except `envoy.enabled=false` (§3.6.3) |
| CNI | `cni.*` → `cni-*`, `write-cni-conf-when-ready` (spec `09` §6.3) | unchanged except `cni.iptablesRemoveAWSRules` (§3.6.3) |
| Operator | the 37-key `operator.*` tree | unchanged |
| ClusterMesh | `clustermesh.*` (28 apiserver keys) | unchanged |
| BGP, L2, LRP, VTEP, bandwidth, BIG TCP, pmtu, sctp, nat, dnsProxy, authentication, configDriftDetection, datapathPlugins | as §F4 | unchanged |
| Free-form | `extraConfig.*` appended verbatim; `extraArgs`, `extraEnv`, `extraVolumes`, `extraHostPathMounts`, `extraContainers`, `extraInitContainers` | unchanged |

#### 3.6.3 Accepted and ignored (rendered, warned about, no effect)

An ignored value is still accepted by `values.schema.json`, still rendered into
`cilium-config` (so `cilium config get` sees it and drift detection is quiet),
and produces **two** warnings: one from `helm install` via `NOTES.txt`, and one
from the agent at startup (`GET /config` reports `"effect": "ignored"`, spec
`00` §6.5).

**iptables family — ADR-0003.**

| Value | Config key | Why ignored |
|---|---|---|
| `iptablesLockTimeout` | `iptables-lock-timeout` | no xtables lock is taken |
| `iptablesRandomFully` | `iptables-random-fully` | no iptables MASQUERADE rule exists |
| `disableIptablesFeederRules` | `disable-iptables-feeder-rules` | no feeder chains |
| `prependIptablesChains` (deprecated) | `prepend-iptables-chains` | ditto |
| `enableXTSocketFallback` | `enable-xt-socket-fallback` | `nft_socket` replaces `xt_socket`; the `ip_early_demux=0` workaround is unnecessary (`docs/kernel-requirements.md` §4.3) |
| `egressMasqueradeInterfaces` | `egress-masquerade-interfaces` | BPF masquerade selects devices by `devices`; there is no iptables interface match |
| `cni.iptablesRemoveAWSRules` | — | flowsdn does not edit another CNI's rules; set `AWS_VPC_K8S_CNI_EXTERNALSNAT=true` on the VPC CNI instead |
| `bpf.masquerade=false` **when** `enableIPv4Masquerade` or `enableIPv6Masquerade` is true | `enable-bpf-masquerade` | **Not ignored — rejected.** There is no iptables masquerade path to fall back to, so silently accepting `false` would silently break egress. `validate.yaml` fails with an explicit message (§3.6.5) |

`installNoConntrackIptablesRules` is **honoured**, not ignored: it selects the
nftables `notrack` rule set in the `inet flowsdn` table (ADR-0003, spec `10`).

**Runtime-compilation family — ADR-0002.** The reference has no Helm value
literally named "clang", because the compiler is an image implementation detail.
What ADR-0002 removes is therefore expressed in these values:

| Value | Status | Why |
|---|---|---|
| `sleepAfterInit` | **honoured, reimplemented** | mapped to `--sleep-after-init` on the agent instead of replacing `command` with a shell `sleep` loop; a scratch image has no shell |
| `monitor.enabled` | **honoured, reimplemented** | sidecar command is `/flowsdn-dbg monitor`, not `/bin/bash -c` |
| `envoy.enabled=false` (embedded Envoy) | **rejected** | The reference's embedded mode requires the Envoy *binary inside the agent image* — impossible under ADR-0002's scratch/no-C image and pointless under ADR-0001's "Envoy stays an external DaemonSet". `validate.yaml` fails with a message pointing at `upgradeCompatibility` |
| `envoy.xdsMode=split` | **rejected** | spec `16` implements SOTW split xDS only in the sense of the socket layout; the value's `ads`/`split` distinction is honoured, see spec `16`. Recorded here so the diff tool has an entry |
| `preflight.*` container commands | **honoured, reimplemented** | `/bin/sh -c 'touch /tmp/ready'` → `/flowsdn preflight pull` |
| `securityContext.capabilities.*` lists that name `SYS_MODULE`, `SYS_RESOURCE`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`, `SYSLOG`, `KILL` | **accepted, filtered with a warning** | The chart strips capabilities flowsdn does not need (§3.5.2) rather than granting them because a user's values file listed them. `flowsdn.strictCapabilities=false` disables the filtering for debugging |
| `debug.verbose` including `datapath` | **honoured** | selects a debug BPF object variant plus `trace_printk`; not a runtime compile |
| `nodeinit.*` | **honoured, upstream image** | §3.4 |

**Deferred features** (accepted, warned, no effect until their spec lands):
`encryption.type=ztunnel` and the whole `encryption.ztunnel.*` tree;
`authentication.mutual.spire.*`; `datapathPlugins.*`;
`clustermesh.mcsapi.*` (until spec `20`).

#### 3.6.4 Renamed, with aliases retained

Renames are kept to the minimum, because every rename is a break in the
compatibility contract of §2.

| Old name (alias, still accepted) | New canonical name | Reason |
|---|---|---|
| `bpf.hostLegacyRouting` → `enable-host-legacy-routing` | key retained, **default flips to `false`** | flowsdn's BPF host routing is the only path that exists on the 6.6+ floor; legacy routing is the fallback for old kernels flowsdn does not support. The value name is unchanged; only the default moves. Recorded as a `deviation` diff |
| `monitor-aggregation-level`, `ct-global-max-entries-tcp`, `ct-global-max-entries-other` | `monitor-aggregation`, `bpf-ct-global-tcp-max`, `bpf-ct-global-any-max` | The reference already treats these as deprecated aliases; spec `00` §3.3.2 maps them |
| `ConfigKey`, `deriveFlag`, `enable`, `SkipCRDCreation` (Go constant names in the reference's flag registry) | `dynamic-lifecycle-config`, `derive-masq-ip-addr-from-device`, `enable-k8s-host-firewall-bypass`, `skip-crd-creation` | Spec `00` §3.3.2 — these are reference bugs, not renames of a user-facing surface |

No Helm *value* is renamed. Aliases live at the config-key layer, where spec
`00`'s registry already resolves them.

#### 3.6.5 New to flowsdn

All new values live under a `flowsdn:` top-level key so they can never collide
with a future reference key. All default to the behaviour a Cilium user expects.

| Value | Default | Effect |
|---|---|---|
| `flowsdn.kernelCheck.mode` | `fail` | `fail` \| `warn`. The startup check of `docs/kernel-requirements.md` §4.7 refuses to run below the floor; `warn` is for kernel bring-up only |
| `flowsdn.hostMounts.bpffs` | `false` | `true` = the host mounts bpffs (`sys-fs-bpf.mount`); removes the privileged `mount-bpf-fs` init container entirely |
| `flowsdn.hostMounts.cgroup2` | `false` | `true` = the host's unified cgroup2 root is used; removes the `mount-cgroup` init container |
| `flowsdn.strictCapabilities` | `true` | filter capabilities flowsdn does not need out of user-supplied lists (§3.6.3) |
| `flowsdn.legacyCapabilities` | `false` | `true` = use `SYS_ADMIN` instead of `BPF`+`PERFMON` for runtimes that do not know the newer names |
| `flowsdn.nft.tableName` | `flowsdn` | the single `inet` table the residual owns (ADR-0003) |
| `flowsdn.bpf.objectVariant` | `auto` | pin a datapath object variant (spec `02` §6.2) instead of selecting from config; debugging only |
| `flowsdn.verifierReport.enabled` | `false` | write `verifier-budget.json` into `/var/run/cilium/` at load; used by the CI gate and by support bundles |
| `flowsdn.dbg.enabled` | `true` | ship `/flowsdn-dbg` in the image (set false for a minimal image) |
| `flowsdn.tokioConsole.{enabled,port}` | `false`, `6669` | replaces the Go `pprof`/`gops` values, which are ignored (spec `00` §6.5) |

#### 3.6.6 `validate.yaml`

flowsdn keeps all 48 reference guards verbatim (removed values, mutual
exclusions, dependency rules, cluster-name regex, `maxConnectedClusters ∈
{255,511}`, …) and adds:

1. `bpf.masquerade=false` with any masquerade enabled → fail (§3.6.3).
2. `envoy.enabled=false` with `l7Proxy=true` → fail: "embedded Envoy is not
   supported; set `envoy.enabled=true` or `l7Proxy=false`".
3. `upgradeCompatibility < "1.16"` → fail for the same reason (it implies
   embedded Envoy).
4. `kubeProxyReplacement=false` **and** `waitForKubeProxy=false` **and** no
   kube-proxy detected → warn only (this is a legitimate configuration).
5. `bpf.datapathMode=netkit*` with a declared kernel line < 6.8 → fail.
6. `securityContext.privileged=false` with `flowsdn.legacyCapabilities=false`
   on a cluster whose nodes are known to lack `CAP_BPF` → cannot be checked at
   template time; the agent's startup check covers it.

### 3.7 Upgrade path from a Cilium install

An honest assessment. Three questions matter: do the CRDs survive, do the
pinned BPF maps survive, and can a running agent hand over to a different
implementation without dropping traffic?

**What is shared and does survive.**

- **CRDs and their contents.** Spec `13` vendors the reference's CRD YAML
  verbatim and registers the same group/versions. `CiliumIdentity`,
  `CiliumEndpoint`, `CiliumNode` (including `spec.ipam` allocations),
  `CiliumEndpointSlice`, all policy CRDs and all BGP CRDs are read and written
  identically. `operator.skipCRDCreation=true` lets flowsdn adopt an existing
  set without touching it.
- **The `cilium-config` ConfigMap.** Same name, same keys (§3.6). A flowsdn
  agent starts against a ConfigMap written by the reference chart.
- **Identity allocation.** CRD mode allocates the same numeric space with the
  same label key encoding (spec `03`), so identities allocated by Cilium remain
  valid for flowsdn and vice versa.
- **Pinned map names and layouts.** Spec `01` keeps `/sys/fs/bpf/tc/globals/
  cilium_*` byte-compatible, which is what makes Envoy's `cilium.bpf_metadata`
  and `bpftool` work against both.

**What does not survive, and why in-place upgrade is not offered for v1.**

| Obstacle | Detail |
|---|---|
| Per-endpoint state | The reference's `/var/run/cilium/state/<epid>/ep_config.json` describes a *compiled object* and its `#define` set. flowsdn's endpoints reference an embedded object variant plus `.rodata` values (spec `02` §6.2). The formats are not interchangeable, so endpoint restore across implementations is not possible without a converter that has no other use |
| Program and link pins | Both implementations pin under `/sys/fs/bpf/cilium/**`, but the *program* bytes differ entirely and the link trees are laid out per implementation. A flowsdn agent cannot `BPF_LINK_UPDATE` a link created by the reference onto its own program unless the program types, attach types and the pin path agree exactly — which they do for tcx on a device, but the per-endpoint `cilium_calls_<epid>` program arrays and the per-endpoint policy maps are populated with different tail-call slot semantics |
| Conntrack and NAT entries | The entry layouts are compatible by spec (spec `04`), but the `src_sec_id` and flag semantics are validated by the *program*, and a half-migrated node would have entries created by one datapath consumed by another. Not worth the risk for the value it buys |
| Envoy mode | An install with `upgradeCompatibility < 1.16` runs embedded Envoy, which flowsdn rejects (§3.6.6). Those installs must move to the Envoy DaemonSet before migrating |

**The supported migration is a per-node drain-and-replace, which is a
cluster-level rolling migration with no cluster downtime.**

1. `helm upgrade` the *reference* release to its latest patch and confirm
   health (the reference's own upgrade requirement).
2. Run the flowsdn preflight (`preflight.enabled=true agent=false
   operator.enabled=false`): pre-pulls the flowsdn images on every node and
   validates every CNP against the flowsdn parser. Fix anything it reports
   *before* touching a node.
3. Install the flowsdn operator alongside, with `skipCRDCreation=true`, or
   leave the reference operator running until the last node is migrated —
   the operator duties are idempotent and identity/CEP GC is safe from either.
4. Per node: `kubectl cordon`; `kubectl drain --ignore-daemonsets`; delete the
   reference agent pod on that node; run `flowsdn cleanup --all-state` (as a
   one-shot Job with the agent image and the same hostPaths — this removes the
   reference's pins, links, devices, routes, rules and iptables leftovers);
   label the node so the flowsdn DaemonSet's `nodeSelector` picks it up;
   wait for `Ready`; `kubectl uncordon`.
5. When the last node is migrated, `helm uninstall` the reference release with
   `--no-hooks` and delete its DaemonSet/Deployments, leaving the CRDs.

**Mixed clusters work during the migration.** Spec `02` §9.5 requires exactly
this as an acceptance test: one Cilium v1.20.1 node and one flowsdn node in one
VXLAN cluster, with pod-to-pod and NodePort traffic across the boundary and
correct identities in Hubble. That is the property that makes a rolling
migration possible; it is a first-class test, not an assumption.

**Downgrade** is the same procedure in reverse, with `flowsdn cleanup
--all-state` before reinstalling the reference agent.

**In-place upgrade of flowsdn by flowsdn** (version N → N+1) *is* supported and
is the normal `helm upgrade` rolling update: pinned maps are opened by name with
the layout-change handling of spec `01` §3.2, links are replaced with
`BPF_LINK_UPDATE`, and endpoint state is restored from
`/var/run/cilium/state/<epid>/`. The `conn-disrupt` test of spec `19` gates it.

### 3.8 Build system

#### 3.8.1 Workspace layout

**One private repository, one Cargo workspace** — ADR-0006, and it is a
decision rather than a default: `flowsdn-bpf-abi` is compiled into both the
aya-ebpf programs and the agent, so a `#[repr(C)]` change is only correct if
both sides move in the same commit, and a split would put version skew exactly
there. The ordinary change here is cross-crate (a conntrack field touches the
ABI crate, the programs, the loader, the GC task, the dbg dump format and the
harvested `.table` expectations), the harvested corpora cut across every
boundary a split could draw, and the deliverable is one sealed image, not a set
of independently versioned libraries. flowsdn therefore ships **one version, one
lockfile, one `deny.toml`, one MSRV**, all configured at the workspace root
(§3.8.8), and CI pays for this with per-crate caching and change detection
(§3.10.6) so a documentation edit does not rebuild the BPF programs.

Two crates in §3.8.2 have a plausible audience outside flowsdn and are the
**only** ones ADR-0006 names as candidates for later extraction and publication
— `flowsdn-bgp-proto` (a BGP message codec and FSM with no flowsdn types in its
interface; nothing comparable exists in Rust today) and `flowsdn-scripttest` (a
txtar-driven script test engine useful to any project that wants the
reference's testing style). Extraction is a deliberate, later decision taken
when a crate has external users and its API has stopped moving; until then both
live in the workspace like everything else, and no spec may assume they are
separately versioned.

One `Cargo.lock`, `resolver = "2"`. Members under
`crates/`; the BPF package is a workspace *exclusion* with its own lock and
toolchain (§3.8.3) — the one exception, forced by the second toolchain, not a
repository boundary.

```
flowsdn/
  Cargo.toml            [workspace] members = ["crates/*", "xtask"], exclude = ["crates/flowsdn-bpf"]
  rust-toolchain.toml   stable, pinned
  deny.toml             §3.8.8
  Cross.toml            §3.8.5
  bpf-objects.lock      sha256 per object variant (§3.8.4)
  crates/…
  xtask/
  install/kubernetes/flowsdn/
  images/{agent,operator,relay,dnsproxy,connectivity}/Containerfile
  tests/{scripttest,bpf,golden,fuzz}/     harvested corpora (ADR-0005)
  tests/cloud/<provider>/<scenario>/      recorded cloud responses (ADR-0007)
  tools/                                  re-harvest and rewrite scripts
  docs/
```

#### 3.8.2 Every crate named across specs 00–22

Purpose and principal dependencies. "Spec" is the spec that defines it.
`F` = foundation (no aya, no kube, no netlink).

| Crate | Spec | Purpose | Depends on |
|---|---|---|---|
| `flowsdn-table` | 00 | `Table<T>`, indexes, snapshots, change streams, the reconciler helper | `imbl`, `arc_swap`, `tokio`, `metrics` — F |
| `flowsdn-config` | 00 | the 539-key registry, layering, `build-config` resolver, typed `Config`, runtime `Options` | `clap`, `serde_yaml`, `kube` (feature-gated) — F |
| `flowsdn-fence` | 00 | startup ordering primitive replacing Hive lifecycle | `tokio` — F |
| `flowsdn-health` | 00 | health registry, reporters, history file, gauges | `flowsdn-table` — F |
| `flowsdn-lease` | 12, 05 | `coordination/v1` leader election, shared by operator and L2 announcements | `kube` |
| `flowsdn-version` | 22 | build metadata struct, `flowsdn_build_info`, `version --json` | none (build script) — F |
| `flowsdn-ip` | 03, 07 | IP/CIDR newtypes with the reference's string forms | `ipnet` — F |
| `flowsdn-bpf-abi` | 01, 02, 04 | `no_std` `#[repr(C)]` layouts shared by kernel and userspace; map catalogue; tail-slot table | `core` only — F |
| `flowsdn-bpf-sys` | 01 | raw `bpf(2)` shims aya lacks (map-in-map, batch, `LINK_UPDATE`, netkit) | `libc` |
| `flowsdn-bpf-maps` | 01 | typed map wrappers, open-or-create, pressure metrics, reliable dump, batch iterator | `aya`, `flowsdn-bpf-sys`, `flowsdn-bpf-abi` |
| `flowsdn-loader` | 01 | object embedding, `set_global`, reachability pruning, attach backends, bpffs layout, mapsweeper | `aya`, `aya-obj`, `flowsdn-bpf-maps` |
| `flowsdn-bpf` | 02 | **the BPF programs**; `bpfel-unknown-none`; one `[[bin]]` per object family | `aya-ebpf`, `flowsdn-bpf-abi` — *excluded from the workspace* |
| `flowsdn-datapath` | 02 | userspace side of the datapath: variant selection, config → `.rodata`, orchestrator | `flowsdn-loader`, `flowsdn-table` |
| `flowsdn-labels` | 03 | `Label`/`Labels`/`LabelArray`, canonical strings, filters, pod label synthesis | `regex`, `lasso` — F |
| `flowsdn-identity` | 03 | `NumericIdentity`, reserved tables, local cache, `IdentityBackend` + CRD backend | `flowsdn-labels`, `kube` |
| `flowsdn-ipcache` | 03 | prefix metadata store, flattened view, BPF injector | `flowsdn-identity`, `flowsdn-table`, `flowsdn-bpf-maps` |
| `flowsdn-ctgc` | 04 | conntrack/NAT GC, batch dump, signal handling, `bpf ct|nat` dump formats | `flowsdn-bpf-maps`, `flowsdn-bpf-sys` |
| `flowsdn-lb` | 05 | service/frontend/backend model, tables, writer, k8s reflector, reconciler, Maglev, health server | `flowsdn-table`, `flowsdn-k8s`, `flowsdn-lb-maps` |
| `flowsdn-lb-maps` | 05 | `LbMaps` trait, aya implementation and the fake used by golden tests | `flowsdn-bpf-maps` |
| `flowsdn-lrp` | 05 | local redirect policy CRD, validation, controller, skip-LB table | `flowsdn-lb`, `kube` |
| `flowsdn-lbipam` | 05 | operator LB IPAM pools, sharing, status patching | `kube`, `ipnet` |
| `flowsdn-l2announce` | 05 | L2 announcement policy, leader election, responder | `flowsdn-lease`, `socket2` |
| `flowsdn-policy-api` | 06 | serde types for CNP/CCNP/KNP/ANP, sanitisation, translators | `schemars`, `kube` — F-ish |
| `flowsdn-policy` | 06 | the engine: selector cache, repository, L4 filters, map state, resolve, compute | `flowsdn-policy-api`, `flowsdn-identity`, `flowsdn-table` |
| `flowsdn-policy-k8s` | 06 | watchers for the five policy kinds, `toServices` resolution | `flowsdn-k8s`, `flowsdn-policy` |
| `flowsdn-ipam-types` | 07 | `CiliumNode`/`CiliumPodIPPool` types, limits, subnets, tags | `kube`, `serde` — F |
| `flowsdn-ipam` | 07 | agent IPAM: `Allocator` trait, host-scope, cluster-pool, multi-pool, CRD, REST | `flowsdn-ipam-types`, `flowsdn-table` |
| `flowsdn-routing-cloud` | 07, 09 | per-ENI rules/routes, shared by agent and CNI plugin | `netlink-packet-route` |
| `flowsdn-operator-ipam` | 07, 12 | node manager, watermarks, cluster-pool allocator, CIDR sets, API limiter | `flowsdn-ipam-types`, `governor` |
| `flowsdn-ipam-aws` | 07 | EC2/ENI provider | `aws-sdk-ec2`, `aws-config` |
| `flowsdn-ipam-azure` | 07 | Azure provider | `azure_mgmt_network`, `azure_identity` |
| `flowsdn-ipam-alibaba` | 07 | Alibaba provider (own signed RPC client) | `reqwest`, `hmac` |
| `flowsdn-endpoint` | 08 | endpoint actor, state machine, regeneration, restore, status log | `flowsdn-policy`, `flowsdn-loader`, `flowsdn-identity` |
| `flowsdn-endpoint-manager` | 08 | endpoint table, id pool, build permits, subscribers | `flowsdn-endpoint`, `flowsdn-table` |
| `flowsdn-api-models` | 08, 09 | serde structs generated once from the reference `openapi.yaml` | `serde` — F |
| `flowsdn-api-client` | 09 | typed blocking client over the unix socket, shared with `flowsdn-dbg` | `flowsdn-api-models`, `ureq` |
| `flowsdn-controller` | 08 | named controllers with backoff, surfaced in status | `tokio` — F |
| `flowsdn-status` | 08 | `cilium status` model and collectors | `flowsdn-health` |
| `flowsdn-cni` | 09 | the CNI plugin binary; **no tokio** | `flowsdn-connector`, `flowsdn-netns`, `flowsdn-api-client` |
| `flowsdn-connector` | 09 | veth/netkit link pair creation, shared with the agent | `netlink-packet-route` |
| `flowsdn-netns` | 09 | `setns` helper with the thread-per-entry model | `nix` |
| `flowsdn-cni-conf` | 09 | conflist rendering, splicing, cleanup — pure functions over an `Fs` trait | `serde_json` — F |
| `flowsdn-netlink` | 10 | typed async rtnetlink: links, addrs, routes, rules, neighbours, qdiscs, sysctl, event stream | `rtnetlink`, `netlink-packet-route` |
| `flowsdn-node` | 10 | devices, node addresses, host devices, route/rule/neighbour reconcilers, MTU, node manager, node IDs, CiliumNode publisher | `flowsdn-netlink`, `flowsdn-table`, `flowsdn-k8s` |
| `flowsdn-nft` | 10 | the nftables residual over `NETLINK_NETFILTER` (ADR-0003) | `netlink-sys` (or `rustables`) |
| `flowsdn-socketlb` | 05, 10 | cgroup socket program attach and lifecycle | `flowsdn-loader` |
| `flowsdn-health-responder` | 08 | in-netns ICMP/TCP health responder thread (replaces `cilium-health`) | `flowsdn-netns`, `socket2` |
| `flowsdn-healthcheck` | 08 | active network health probes, endpoint management and health API (ADR-0010) | `flowsdn-health`, `flowsdn-netns` |
| `flowsdn-monitor` | 01, 11 | perf readers, event bus, gob-subset encoder, `monitor1_2.sock`, decoders, text formatter | `flowsdn-bpf-abi`, `aya` |
| `flowsdn-hubble` | 11 | parsers, enricher, ring buffer, observer service, filters, metrics, exporter, peer service, TLS | `flowsdn-proto`, `tonic` |
| `flowsdn-hubble-relay` | 11 | relay binary: peer pool, fan-out, sort-merge, health | `flowsdn-proto`, `tonic` |
| `flowsdn-proto` | 11, 16 | generated Hubble/flow/observer/peer/relay types + protojson | `prost`, `tonic-build` — F |
| `flowsdn-operator` | 12 | the operator binary and all leader duties | `flowsdn-lease`, `flowsdn-operator-ipam`, `flowsdn-lbipam`, `flowsdn-k8s` |
| `flowsdn-k8s` | 13 | client construction, URL rotation, heartbeat, slim types, CRD types + vendored YAML, watch→table wiring, indexers | `kube`, `k8s-openapi`, `tower` |
| `flowsdn-crds` | 13 | the vendored CRD YAML as `include_str!` plus registration payloads (module of `flowsdn-k8s`) | — |
| `flowsdn-store` | 12, 20 | shared key-value store abstraction used by ClusterMesh and identity | `flowsdn-table` |
| `flowsdn-kvstore` | 12, 20 | etcd client for kvstore mode and ClusterMesh | `etcd-client` |
| `flowsdn-wireguard` | 14 | `cilium_wg0` lifecycle, peers, AllowedIPs diffing, MTU | `netlink-packet-wireguard`, `x25519-dalek` |
| `flowsdn-ipsec` | 14 | XFRM states/policies, SPI rotation, key derivation | `netlink-packet-xfrm` |
| `flowsdn-egressgw` | 14 | CEGP parsing, gateway selection, egress map reconciliation, ip-masq-agent | `flowsdn-bpf-maps`, `flowsdn-table` |
| `flowsdn-bgp-proto` | 15 | BGP wire codec, `no_std`-friendly, fuzzed | `bytes` — F |
| `flowsdn-bgp` | 15 | speaker: FSM, timers, RIBs, export policy, MD5 | `flowsdn-bgp-proto`, `tokio`, `socket2` |
| `flowsdn-bgp-routeros` | 15 | RouterOS REST `Advertiser` backend | `reqwest` |
| `flowsdn-bgp-cp` | 15 | control plane: CRDs, seven reconcilers, status writer | `flowsdn-bgp`, `kube` |
| `flowsdn-envoy-proto` | 16 | generated `cilium/proxy` + data-plane-api v3 types | `prost` — F |
| `flowsdn-xds` | 16 | xDS server: transport, caches, ACK/NACK, bootstrap builder, access-log server | `flowsdn-envoy-proto`, `tonic` |
| `flowsdn-envoy-policy` | 16 | pure `EndpointPolicy → cilium.NetworkPolicy` + deterministic sort | `flowsdn-policy` — F |
| `flowsdn-cec` | 16 | CEC/CCEC reflector, parser, EDS, reconciler | `flowsdn-xds`, `flowsdn-lb` |
| `flowsdn-dnsproxy` | 16 | DNS proxy **as a library** behind `PolicySource`/`Notifier` traits | `hickory-proto`, `tokio` |
| `flowsdn-dnsproxy-standalone` | 16 | the SDP binary | `flowsdn-dnsproxy`, `tonic` |
| `flowsdn-fqdn` | 16 | name manager, ipcache metadata production, GC, `/fqdn/*` REST | `flowsdn-dnsproxy`, `flowsdn-ipcache` |
| `flowsdn-clustermesh` | 20 | remote cluster mesh (wave 4) | `flowsdn-kvstore`, `flowsdn-store` |
| `flowsdn-agent` | 08, 22 | **binary**: composition root, multi-call dispatch, all subcommands of §3.2 | everything above |
| `flowsdn-dbg` | 22 | **binary**: CLI over the unix API, `monitor`, `bugtool`, map dumps | `flowsdn-api-client`, `flowsdn-bpf-maps` |
| `flowsdn-scripttest` | 17 | txtar harness running the 168 harvested scenarios | `flowsdn-table`, fakes |
| `flowsdn-bpf-tests` | 18 | privileged `BPF_PROG_RUN` harness + packet builders | `aya`, `flowsdn-bpf-abi` |
| `flowsdn-cptest` | 17 | control-plane golden tests over harvested k8s fixtures | `flowsdn-k8s`, fakes |
| `flowsdn-connectivity` | 19 | **binary**: the acceptance suite | `kube`, `reqwest` |
| `xtask` | 22 | the build/dev driver (§3.11) | `clap`, `xshell` |

#### 3.8.3 Two toolchains

| Toolchain | Where | Pin | What it builds |
|---|---|---|---|
| **stable** | `rust-toolchain.toml` at the repo root: `channel = "1.9x.0"`, `components = ["rustfmt","clippy","rust-src"]`, `targets = ["x86_64-unknown-linux-musl","aarch64-unknown-linux-musl"]` | exact patch version, bumped in its own commit with the CI matrix green | every userspace crate, every binary, every test harness |
| **pinned nightly** | `crates/flowsdn-bpf/rust-toolchain.toml`: `channel = "nightly-YYYY-MM-DD"`, `components = ["rust-src"]` | exact date; bumped only when aya-ebpf or a verifier result demands it | `flowsdn-bpf` for `bpfel-unknown-none` with `-Z build-std=core` |

`bpf-linker` is pinned by exact version in `xtask` and installed with
`cargo install --locked bpf-linker@<version>`; its LLVM must match the pinned
nightly's (ADR-0002; LLVM ≥ 19). CI records both in the image labels
(`io.flowsdn.bpf.toolchain`) so an object can always be traced to the toolchain
that produced it.

Rationale for the split: the BPF target needs `build-std`, which is nightly-only,
and nightly moves fast enough that pinning the *whole* workspace to it would
make every dependency bump a nightly-compatibility exercise. The BPF package is
a workspace exclusion precisely so its toolchain, profile and lockfile are
independent.

#### 3.8.4 Building and embedding the BPF objects

```
cargo xtask bpf                       # build every variant
  → cargo +nightly-YYYY-MM-DD build --release -Z build-std=core \
       --target bpfel-unknown-none --features <variant features> --bin <family>
     RUSTFLAGS="-C target-cpu=v3 -C link-arg=--btf"
  → <cargo-target-dir>/bpfel-unknown-none/release/<family>
  → post-process: assert no `memcpy|memmove|memset|memcmp|core::panicking`
     relocations remain (spec 02 §11.4); assert every tail slot the object uses
     has a program with the expected name (spec 02 §11.1)
  → copy to target/bpf/<family>-<variant>.o, sha256 into bpf-objects.lock
```

Release profile for the BPF package (ADR-0002, `docs/kernel-requirements.md`
§2.2): `opt-level = 3`, `lto = true`, `codegen-units = 1`, `panic = "abort"`,
`overflow-checks = false`, `debug = true` (line info and BTF).

The objects reach the agent through `flowsdn-loader`'s build script:

- If `FLOWSDN_BPF_OBJDIR` is set (CI, and the normal `xtask` path), the build
  script reads objects from there.
- Otherwise it invokes `cargo xtask bpf` itself, so a bare `cargo build` works
  for a newcomer at the cost of one nightly build.
- Either way it emits `OUT_DIR/bpf_objects.rs` containing one
  `include_bytes_aligned!` per variant plus a `const OBJECTS: &[ObjectEntry]`
  table (name, variant features, sha256, byte slice), and it verifies each
  sha256 against `bpf-objects.lock`.

`bpf-objects.lock` is **committed**. A rebuild that changes a hash is a real
change to the datapath and must appear in the diff; CI's `bpf-reproducible` job
rebuilds from scratch and fails if the lock does not match. This is also what
makes the verifier budget report (§9.2) attributable to an exact object.

**One object per arch is not needed**: BPF bytecode is `bpfel` for both x86-64
and arm64 (`docs/kernel-requirements.md` §5.1). The same objects are embedded in
both agent binaries.

#### 3.8.5 Cross compilation

Native builds run on `<build-host>` (x86-64). arm64 uses `cross`:

```toml
# Cross.toml
[build.env]
passthrough = ["FLOWSDN_BPF_OBJDIR", "SOURCE_DATE_EPOCH", "CARGO_TARGET_DIR"]

[target.aarch64-unknown-linux-musl]
image = "ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5"
```

```bash
ssh <build-user>@<build-host> '
  export CARGO_TARGET_DIR=<cargo-target-dir>
  export CROSS_CONTAINER_ENGINE=podman
  cd <checkout> && cross build --release --target aarch64-unknown-linux-musl \
     -p flowsdn-agent -p flowsdn-cni -p flowsdn-operator -p flowsdn-dbg \
     -p flowsdn-hubble-relay -p flowsdn-connectivity'
```

Rules from `../CLAUDE.md`, restated because they are load-bearing here:

- `CARGO_TARGET_DIR=<cargo-target-dir>` **always**. The SSD root is for
  working trees only; a target dir on `/` has filled it before, and the failure
  mode is `rustc-LLVM ERROR: IO failure on output stream`, which reads as a
  broken toolchain.
- Images and tarballs go to `/build/images`; downloaded assets to `/build/cache`.
- **Never write a disk or container image into `/tmp` on dev** — it is a tmpfs
  sized at half of RAM (7.8 GiB), and a sparse image there consumes RAM that is
  never returned.
- Check before and after: `df -h / /build; du -sh /build/* | sort -rh | head`.
- Unmount anything loop-mounted, including on the failure path.

`cross` needs `binfmt_misc` for the arm64 *test* runs; unit tests for arm64 run
in a QEMU `virt` VM (§3.10), not under `cross`, because the privileged tests
need a real kernel.

#### 3.8.6 Static linking

All shipped binaries are `*-unknown-linux-musl` and fully static. `crt-static`
is the musl default. `rustls` (never OpenSSL) removes the last C dependency —
enforced by `deny.toml` banning `openssl-sys` (§3.8.8). `aws-lc-rs` is likewise
banned in favour of `ring` or `rustls`'s pure-Rust provider; if a pinned
dependency drags in `aws-lc-sys`, that is a C dependency and needs an ADR.

#### 3.8.7 Reproducible builds

Target: **two builds of the same commit on two machines produce byte-identical
binaries, layers and image digests.** Method:

1. `SOURCE_DATE_EPOCH = git show -s --format=%ct HEAD`, exported to the
   compiler, the linker and podman (`--timestamp`).
2. `RUSTFLAGS` includes
   `--remap-path-prefix=$PWD=/flowsdn --remap-path-prefix=$CARGO_HOME=/cargo`,
   so absolute build paths never enter the binary.
3. `CARGO_INCREMENTAL=0`, `codegen-units = 1` in the release profile.
4. Build metadata is *injected*, never sampled: the build script reads
   `FLOWSDN_VERSION`, `FLOWSDN_REVISION`, `SOURCE_DATE_EPOCH` from the
   environment and falls back to `git` only for a dev build (which is then
   marked `dirty`). No `chrono::Utc::now()` at build time anywhere.
5. Image layers are single (`--squash-all`) with `--timestamp`, so file order
   and mtimes are fixed.
6. The BPF objects are pinned by `bpf-objects.lock` and reproduced by the same
   nightly + `bpf-linker` pin.

Verification: the nightly `reproducible` job builds the release commit twice
(once on `<build-host>`, once on a GitHub hosted runner with the same toolchain)
and compares `sha256` of every binary and the pushed manifest digest. A
mismatch fails and the diff is bisected with `diffoscope` where available.

#### 3.8.8 `cargo deny`

`deny.toml` implements `docs/licensing.md` mechanically.

```toml
[licenses]
allow = ["MIT","Apache-2.0","Apache-2.0 WITH LLVM-exception","BSD-2-Clause",
         "BSD-3-Clause","ISC","Zlib","MPL-2.0","Unicode-3.0","CC0-1.0"]
confidence-threshold = 0.93
# Every exception is an explicit decision with an ADR reference in the comment.
exceptions = []

[bans]
multiple-versions = "warn"
wildcards = "deny"
deny = [
  { name = "openssl-sys",  reason = "C dependency; rustls only (ADR-0002)" },
  { name = "openssl" },
  { name = "aws-lc-sys",   reason = "C dependency (ADR-0002)" },
  { name = "libnftnl-sys", reason = "C dependency and GPL-2.0 (ADR-0002, licensing.md)" },
  { name = "bindgen",      reason = "implies a C header somewhere" },
  { name = "cc",           reason = "implies a C compiler in the build (ADR-0002)" },
]

[advisories]
yanked = "deny"
unmaintained = "workspace"   # deny for direct deps, warn for transitive
ignore = []                  # every entry needs an expiry date and an issue

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-git = []               # empty; a git dependency needs a decision record
```

`GPL`, `LGPL`, `AGPL`, `SSPL` and `BUSL` are absent from `allow`, which denies
them by construction. `MPL-2.0` is allowed (file-level copyleft), which is what
lets `imbl` in (spec `00` §11).

A companion check, `cargo xtask notice`, regenerates `NOTICE` from the resolved
dependency graph plus the harvested-corpus provenance files (ADR-0005) and fails
if the working tree differs. `cargo deny check` and `xtask notice` are both PR
gates.

### 3.9 Versioning and release

#### 3.9.1 Scheme

Semantic versioning per `../CLAUDE.md`. Pre-1.0: `0.MINOR.PATCH`, where MINOR
may break, PATCH is fixes only. The auto-increment guideline from the user's
global rules applies to the *docs and spec* phase (10–50 lines → patch, 51–400 →
minor, 401+ → major, read as MINOR pre-1.0).

`1.0.0` is declared when: the spec `19` acceptance suite passes on the 6.12
line on both arches, the verifier gate is green on 6.6/6.12/6.18, in-place
flowsdn→flowsdn upgrade passes the conn-disrupt test, and the Helm values
surface has no unexplained `helm-diff` entries.

#### 3.9.2 Version locations that must match

Enforced by `cargo xtask version check` (a PR gate) and set by
`cargo xtask version set X.Y.Z`:

| Location | Field |
|---|---|
| `Cargo.toml` | `[workspace.package] version` (every crate inherits with `version.workspace = true`) |
| `crates/flowsdn-bpf/Cargo.toml` | `version` (separate workspace) |
| `install/kubernetes/flowsdn/Chart.yaml` | `version` **and** `appVersion` |
| `install/kubernetes/flowsdn/values.yaml` | `image.tag`, `operator.image.tag`, `hubble.relay.image.tag`, `standaloneDnsProxy.image.tag`, `preflight.image.tag` |
| `install/kubernetes/flowsdn/README.md` | helm-docs header (regenerated) |
| `CHANGELOG.md` | the released heading |
| `CLAUDE.md` | the `## Version` line |
| image labels | `org.opencontainers.image.version` (from `FLOWSDN_VERSION`) |
| `flowsdn version` output | from `flowsdn-version`'s build script |

Chart version tracks the flowsdn version exactly (one stream, no independent
chart versioning). The reference minor whose values surface is tracked lives in
the `flowsdn.io/cilium-compat` annotation, not in the version.

#### 3.9.3 Release procedure

1. Land all work; `CHANGELOG.md` `[Unreleased]` is complete.
2. `cargo xtask version set X.Y.Z` → commit `chore(release): vX.Y.Z` (version
   bump is its own commit, per `../CLAUDE.md`).
3. Transform `CHANGELOG.md`: move `[Unreleased]` content under
   `## [vX.Y.Z] — YYYY-MM-DD`, regrouped into `Added` / `Fixed` / `Changed` /
   `Breaking` / `Documentation` from the `feat:`/`fix:`/`refactor:`/`perf:`/
   `BREAKING:`/`docs:` prefixes; open a fresh `[Unreleased]`.
4. `git tag vX.Y.Z && git push origin vX.Y.Z`.
5. The `release` workflow (§3.10) builds, tests, publishes and attaches
   artifacts. It re-derives the version from the tag and **fails if it does not
   match `xtask version check`**.

#### 3.9.4 Artifacts, and the GHCR question

The user's MikroTik/stormcos rules say: *CI attaches `docker save` tarballs to
GitHub releases; stormcos preloads them into the node image store at image-build
time; GHCR is deliberately not used; nothing on the start path pulls.*

flowsdn is a Kubernetes CNI, and a Helm chart names images by reference. Those
two facts look like a conflict; they are not, and the reconciliation is worth
stating precisely:

> **The stormcos rule forbids a *pull on the start path*, not an image
> *reference*.** An image that is preloaded into the node's image store with
> `imagePullPolicy: IfNotPresent` is never pulled — the kubelet finds it locally
> and starts it. The reference in the manifest is a name, not a network
> operation.

Therefore:

| Artifact | Where | Why |
|---|---|---|
| `flowsdn-<component>-<version>-<arch>.oci.tar` (`podman save --format oci-archive`), plus a manifest-list archive | **GitHub release assets, every release — mandatory** | This is what stormcos preloads at node-image build time. It is the supply path for the fleet and it keeps the start path pull-free |
| `sha256sums.txt`, `sbom-<component>.cdx.json`, `verifier-budget.json`, `binary-sizes.json` | GitHub release assets | Verification and trend data (§9) |
| `flowsdn-<version>.tgz` (Helm chart) + `index.yaml` | GitHub release assets, and a `gh-pages` chart repo when the repo goes public | `helm install` from a URL |
| `flowsdn-dbg`, `flowsdn-connectivity` for `linux-{amd64,arm64}` and `darwin-arm64` | GitHub release assets | workstation tools |
| Container images | **`sbregistry:5100`** (the private fleet registry) as the source of truth while the repo is private | The chart's default `image.repository` |
| Container images | **GHCR (`ghcr.io/glennswest/flowsdn`) — recommended, and only once the repo is public** | Public consumers of a public CNI need a public registry; a tarball is not an installation method for someone who is not on this fleet |

**Recommendation.** Publish tarballs unconditionally and to `sbregistry:5100`
unconditionally; add GHCR as a *mirror* at the moment the repository becomes
public, and never as the sole source. Set `image.pullPolicy: IfNotPresent` as
the chart default (it already is in the reference) and document
`flowsdn.preloaded=true` as the stormcos posture, which additionally sets
`imagePullPolicy: Never` so a misconfigured node fails loudly instead of
reaching for a registry. This satisfies the fleet rule exactly (no pull on the
start path, golden preload, no auto-updater) while leaving flowsdn installable
by anyone else.

`quay.io` is not used: flowsdn has no account there and the reference's use of
it is not a contract.

#### 3.9.5 Reference-tag bumps

The pinned reference (`cilium v1.20.1`, `7d68cfb394`) appears in: the vendored
CRD YAML (spec `13`), the harvested test corpora (ADR-0005), the reused image
digests (§3.4), and `mapping.toml`. Bumping it is a deliberate, reviewed
operation with its own workflow: re-run `tools/reharvest.sh`, refresh the
digests, re-run `xtask helm-diff`, and land the diff of `known-diffs.toml` as
the review artefact.

### 3.10 CI

#### 3.10.1 Where jobs run

| Class | Runner | Why |
|---|---|---|
| lint, fmt, clippy, `cargo deny`, `xtask notice`, `xtask version check`, `helm lint`, `xtask chart check`, `xtask helm-diff`, doc link check | GitHub hosted `ubuntu-latest` | cheap, no kernel needed |
| userspace unit tests (x86-64), scripttest, cptest, golden tests, **cloud-fake replay** | GitHub hosted | no kernel needed (fakes per ADR-0005; recorded cloud responses per ADR-0007, replayed against a local server — no network egress, no credentials) |
| **BPF build, verifier gate, privileged BPF tests, privileged netlink tests, image builds, cross arm64, kind e2e** | **self-hosted runner on `<build-host>`**, labels `[self-hosted, linux, x64, dev-g8]` | needs KVM (LVH/QEMU VMs), needs podman, needs the pinned nightly + `bpf-linker`, and needs `/build` — per `../CLAUDE.md` heavy builds run on dev, never on the Mac and not on an ephemeral hosted runner where a 30-minute cold `cargo build` is the norm |
| arm64 e2e, arm64 privileged tests | **Rose cluster node**, nightly, label `[self-hosted, linux, arm64, rose]` | real arm64 hardware and real NIC drivers; LVH publishes no arm64 kernels (`docs/kernel-requirements.md` §5.3) |
| arm64 verifier + BPF unit tests | `<build-host>` under QEMU TCG | CPU-light; the verifier is arch-independent, so this row guards only JIT-support gates |

Every `<build-host>` job MUST:
- set `CARGO_TARGET_DIR=<cargo-target-dir>`, `TMPDIR=/build/tmp`;
- write VM images and OCI archives under `/build/images`;
- run a pre-flight `df` guard that fails the job with a clear message if `/`
  has < 20 GiB or `/build` < 100 GiB free, rather than failing later as
  `rustc-LLVM ERROR: IO failure on output stream`;
- run an `always()` cleanup step that unmounts every loop mount it made.

#### 3.10.2 Workflow set

This matrix is normative planned acceptance, not a report that every workflow
exists. In particular, cloud replay and the weekly live drift job still require
implementation and validation; #259 resolves their documentation, not #260.
Encryption acceptance also requires the `e2e-encryption` PR gate of spec 19:
both WireGuard and IPsec with positive encrypted and negative plaintext capture
assertions (#230). A missing required capability must fail, not pass by skipping.

| Workflow | Trigger | Gates | Approx. runtime |
|---|---|---|---|
| `lint` | PR | `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`, `cargo deny check`, `xtask notice`, `xtask version check`, `taplo fmt --check`, spec cross-reference check | 6 min |
| `chart` | PR | `helm lint`, `helm template` against 6 values profiles, `xtask chart check` (generated files match), **`xtask helm-diff`** against the reference render with `known-diffs.toml`, `kubeconform` against k8s 1.31–1.36 schemas | 5 min |
| `unit` | PR | `cargo test --workspace` (x86-64 hosted) + `cargo test --workspace --target aarch64…` under QEMU user emulation for the pure crates | 12 min |
| `bpf-build` | PR (dev-g8) | pinned nightly + `bpf-linker`, build every object variant, no-`memcpy`/no-panic relocation check, tail-slot name check, `bpf-objects.lock` match | 9 min |
| `verifier` | PR (dev-g8) | load every variant with the all-features `.rodata` and with the default config in LVH 6.6 and 6.12 VMs, x86-64. **Fail** if any program > 800 000 processed instructions or > 480 B stack (spec `02` §9.4); **warn** at +10 % vs `docs/verifier-baseline.json`. Emits `verifier-budget.json` and a PR comment table | 14 min |
| `bpf-tests` | PR (dev-g8) | `flowsdn-bpf-tests` under `BPF_PROG_RUN` in an LVH 6.12 VM (ADR-0005 corpus, `tests/bpf/CASES.toml`) | 18 min |
| `privileged` | PR (dev-g8) | `cargo test --features privileged -- --ignored` in a 6.12 VM: map open/create, tcx/netkit/XDP/cgroup attach, netlink, nftables residual, netns | 15 min |
| `scripttest` | PR | `cargo test -p flowsdn-scripttest` over the 168 harvested txtar scenarios (unprivileged, fakes) | 7 min |
| `cloud-fixture-scan` | **PR** | pattern scan over `tests/cloud/**` for credentials, real account identifiers, ARNs, subscription/tenant IDs, tokens and signatures (ADR-0007 §2). Runs **before** any job reads a fixture and blocks them on failure, so a leak is caught at the gate rather than replayed | 1 min |
| `cloud-fakes` | **PR** | `cargo test -p flowsdn-ipam-aws -p flowsdn-ipam-azure -p flowsdn-ipam-alibaba -p flowsdn-operator-ipam --features cloud-replay`, one matrix leg per provider, against the recorded fixtures in `tests/cloud/<provider>/<scenario>/` replayed at the **HTTP layer** so each SDK's signing, retry, pagination and error mapping stay in the tested path (ADR-0007 §3; spec `07` §9.1). Strict mode: an unmatched request *or* an unused recorded interaction fails. Hosted runner — no kernel, no cluster, **no credentials** | 8 min |
| `images` | PR (dev-g8) | build all five images for both arches, assemble the manifest lists, **do not push**; `xtask size-check`; assert the image has exactly the expected file list and no shell | 16 min |
| `e2e-smoke` | PR (dev-g8) | kind on LVH 6.12 x86-64, 2 nodes, `helm install` the built chart, `flowsdn-connectivity` M1 subset per spec `19` (pod-to-pod same/other node, ClusterIP, NodePort, pod-to-world, host-to-pod, DNS, policy allow/deny), plus `check-log-errors` and `no-unexpected-packet-drops` | 22 min |
| `e2e-matrix` | **nightly** (dev-g8) | the reduced config set from `docs/kernel-requirements.md` §5.3: {vxlan+KPR, native+KPR+DSR, geneve+DSR-geneve, WireGuard, IPsec, egress gateway, host firewall, IPv6-only, netkit} on 6.12; 6.6 and 6.18 rows with the vxlan+KPR config | 3 h |
| `e2e-arm64` | **nightly** (rose) | vxlan+KPR and native+DSR on the Rose cluster | 50 min |
| `upgrade` | **nightly** (dev-g8) | flowsdn N-1 → N `helm upgrade` with `--include-conn-disrupt-test`; then N → N-1 downgrade; the Cilium→flowsdn drain migration of §3.7 as a scripted scenario | 70 min |
| `mixed-cluster` | **nightly** (dev-g8) | one Cilium v1.20.1 node + one flowsdn node in one kind cluster; pod-to-pod and NodePort across the boundary; identities correct in Hubble (spec `02` §9.5) | 30 min |
| `verifier-matrix` | **nightly** | verifier on {6.6, 6.12, 6.18} × {x86-64, arm64}; updates the trend, non-blocking on the 6.18 canary row | 45 min |
| `reproducible` | **nightly** | build the head commit twice on two machines, compare binary and manifest digests (§3.8.7) | 40 min |
| `fuzz` | **nightly** | `cargo fuzz run` for each target (BGP codec, policy distill, CNI netconf, gob encoder) for 15 min each against the harvested seeds | 60 min |
| `release` | tag `v*` (dev-g8) | everything the PR gates run, then: build+push images to `sbregistry:5100` (+ GHCR when public), `podman save` archives, package the chart, generate SBOMs, create the GitHub release with all assets, verify `xtask version check` against the tag | 55 min |
| `chart-publish` | push to `main` | publish a `-dev.<sha>` chart to the CI chart repo so `cilium install --chart-directory` equivalents work off main | 4 min |
| `cloud-drift` | **weekly**, scheduled | re-run `cargo xtask cloud-record` against the live throwaway account for each provider and diff the normalized result against the committed `tests/cloud/**` fixtures; open or update one issue per provider on a difference. **Gates nothing.** ADR-0007 §5 | 20 min |

`cloud-fixture-scan` and `cloud-fakes` are **required checks**: under ADR-0007
the cloud IPAM modes of spec `07` §3.9–3.12 are a pull-request gate rather than
an untested surface, and `cloud-fakes` MUST fail rather than fall back to a live
endpoint when a fixture is missing.

**`cloud-drift` is the only job in this repository that holds cloud
credentials**, and they are read-only where the provider supports it. No
pull-request job, no nightly job and no release job may be given a cloud
credential; a workflow that requests one fails review. This is why the drift
check is scheduled rather than triggered: a fixture set goes stale silently when
a provider changes its API, and detecting that is worth one credentialed job a
week, while making it block merges would put a third party's availability on the
critical path of every change.

Deliberately **not** ported from the reference: the ginkgo suites (7k lines of
Go harness; ADR-0005 keeps them as a behaviour checklist), `conformance-race`
(Rust has no data races to detect in safe code; `loom` tests cover the few
`unsafe` spots), `codeql` (replaced by clippy + `cargo deny` + `cargo audit`),
the reference's **live** cloud conformance jobs (EKS/AKS/GKE clusters per PR —
superseded by ADR-0007: the control plane those jobs guarded is covered by
`cloud-fakes` at a fraction of the cost and with no credentials, and what they
additionally covered — datapath on a real cloud — remains an acknowledged gap,
spec `19` §11 item 9), and `lint-images-base` (there is no base image).

#### 3.10.3 Kernel and architecture matrix

Straight from `docs/kernel-requirements.md` §5.3, restated as CI rows:

| Kernel | x86-64 image | arm64 image | Verifier | BPF unit | Privileged userspace | e2e |
|---|---|---|---|---|---|---|
| 6.6 (minimum) | LVH `6.6` | upstream 6.6.y QEMU `virt` | PR | PR | nightly | nightly |
| 6.12 (supported line) | LVH `6.12` + a Rocky 10 `el10` VM | Rocky 10 `aarch64` VM / Rose node | PR (both) | PR (both) | PR (both) | **PR** (x86, Rocky kernel); nightly arm64 |
| 6.18 (next) | LVH `6.18` | upstream 6.18.y | PR (x86), nightly (arm64) | nightly | nightly | nightly |
| latest / bpf-next | when published | — | nightly, non-blocking | — | — | — |
| 4.18 (rhel8), 5.15, 6.1 | — | — | not run — below the floor | | | |

#### 3.10.4 How the verifier budget gate is enforced

1. `xtask verifier --kernel <k> --arch <a>` boots the matching VM, loads every
   object variant produced by `xtask bpf` after the loader's reachability pass
   (so the measurement is of the *code that actually loads*), with the
   all-features `.rodata` configuration and with the default configuration.
2. For each program it parses the verifier log for `processed N insns (limit
   1000000)` and `stack depth A+B+C`, and records `{object, variant, program,
   kernel, arch, insns, stack, states, map_count, obj_sha}`.
3. Output `verifier-budget.json`, compared against the committed
   `docs/verifier-baseline.json`:
   - **fail** if `insns > 800_000` or `stack > 480` (spec `02` §9.4);
   - **fail** if a program that previously loaded now fails to load — an
     unresolved `core::panicking` relocation surfaces here as a load error, not
     a complexity error (`docs/kernel-requirements.md` §3.3 item 7);
   - **warn** at `insns > baseline × 1.10`;
   - post a PR comment with the per-program delta table.
4. `xtask verifier --update-baseline` regenerates the baseline; that change must
   be a reviewed commit, which is the whole point.

The oldest verifier in the matrix (6.6, x86-64) is the row to watch, and the
`bpf_host` NodePort family is the program family to watch, per
`docs/kernel-requirements.md` §3.2.

#### 3.10.5 How the harvested suites are run (ADR-0005)

- **scripttest** — `cargo test -p flowsdn-scripttest`. The 168 `.txtar`
  scenarios under `tests/scripttest/` run against fakes (fake k8s client, fake
  LB maps, in-memory tables), so no kernel and no privileges. Scenarios flowsdn
  diverges from by design carry an expected-divergence marker rather than being
  deleted, so a re-harvest at a newer reference tag still works. A marker
  without a reason fails the test.
- **BPF tests** — `cargo test -p flowsdn-bpf-tests -- --ignored` inside the LVH
  6.12 VM, driven by `tests/bpf/CASES.toml` (the harvested 141-file / 397-`CHECK`
  checklist). Packet fixtures are built by declarative builders, not scapy.
- **control-plane golden** — `cargo test -p flowsdn-cptest`, feeding the
  harvested `init.yaml`/`stateN.yaml` k8s object lists through the reconcilers
  and comparing table snapshots to golden files. `--update-golden` regenerates.
- **fuzz seeds** — `tests/fuzz/corpus/**` with `PROVENANCE`, driven nightly.

#### 3.10.6 Caching

| Cache | Key | Notes |
|---|---|---|
| Cargo registry + git checkouts | `Cargo.lock` hash | hosted runners; `actions/cache` |
| `sccache` object cache | rustc version + target + `Cargo.lock` | on `<build-host>` a persistent local cache under `/build/cache/sccache`, capped at 40 GiB with `SCCACHE_CACHE_SIZE` |
| `target/` on dev | not cached across toolchain bumps — deleted by `xtask clean --toolchain-changed` | avoids the classic "stale artefacts from a different rustc" failure |
| BPF nightly toolchain + `bpf-linker` | pinned versions | installed once on dev, re-installed only when the pin changes |
| LVH / Rocky VM images | image digest | under `/build/cache/vm`, never `/tmp` |
| Built container images | commit sha | `containers-storage` on dev; a GC step keeps the last 20 |
| helm chart repo index | — | rebuilt each publish |

A weekly `cache-gc` workflow prunes `/build/cache` and `/build/cargo` to keep
`/build` under 70 % and reports the result, so the disk never becomes an
incident.

### 3.11 Developer workflow

`cargo xtask` is the single entry point. A thin `Makefile` forwards the same
names (`make build` → `cargo xtask build`) for muscle memory, but it contains no
logic — all of it is Rust in `xtask/`, which is testable and cross-platform.

| Target | What it does |
|---|---|
| `xtask build [--target …] [--remote]` | build the workspace; `--remote` (the default on macOS) rsyncs to `<build-host>` and builds there with `CARGO_TARGET_DIR=<cargo-target-dir>` |
| `xtask bpf` | build every BPF object variant with the pinned nightly (§3.8.4) |
| `xtask test [--privileged] [--kernel 6.12]` | unit tests locally; with `--privileged`, inside a VM on dev |
| `xtask verifier [--kernel] [--arch] [--update-baseline]` | §3.10.4 |
| `xtask image [--component agent] [--arch …] [--push]` | podman build + manifest (§3.3.2) |
| `xtask chart {gen,check,lint,diff}` | generate/verify the chart, `helm lint`, `helm-diff` vs the reference (§3.6.1) |
| `xtask kind {up,down,load}` | create a kind cluster on dev with a chosen kernel/LVH image and node count; `load` does `podman save` + `kind load image-archive` |
| `xtask deploy [--context …]` | `helm upgrade --install flowsdn ./install/kubernetes/flowsdn` with the locally built images |
| `xtask e2e [--test …]` | run `flowsdn-connectivity` against the current context (spec `19`) |
| `xtask size-check`, `xtask notice`, `xtask deny`, `xtask version {check,set}` | the corresponding PR gates, runnable locally |
| `xtask clean [--toolchain-changed] [--all]` | remove target dirs under `<cargo-target-dir>`; never touches anything else on `/build` |

**The local loop against kind**, end to end:

```bash
# From the Mac. Everything heavy happens on dev.
cargo xtask kind up --nodes 3 --kernel 6.12          # LVH VM on dev, kind inside it
cargo xtask build --remote                            # cross-build both arches on dev
cargo xtask image --component agent --arch amd64
cargo xtask kind load                                 # podman save | kind load
cargo xtask deploy --set debug.enabled=true
kubectl -n kube-system rollout status ds/cilium
cargo xtask e2e --test 'no-policies/'
cargo xtask kind down
```

Iterating on the agent only: `xtask build --remote -p flowsdn-agent && xtask
image --component agent && xtask kind load && kubectl -n kube-system rollout
restart ds/cilium` — about 90 s warm.

Iterating on the datapath: `xtask bpf && xtask verifier --kernel 6.12` first
(fast, catches complexity and panic-path regressions before a cluster is
involved), then the image loop.

**Rule, restated because it is the one people break:** editing on the Mac is
fine; believing a Mac build is not. `cargo test` reports 258 tests on macOS and
303 on dev — the 45 that differ are the ones touching `io_uring`, `ublk`,
`/dev/kmsg`, `mlockall` and the whole storage and BPF path. `xtask` therefore
defaults to `--remote` on macOS and prints a one-line reminder when it does.

## 4. Data model

Files this spec owns.

| File | Format | Purpose |
|---|---|---|
| `Cargo.toml` (workspace root) | TOML | members, `[workspace.package]` version/edition/license, `[workspace.dependencies]` pinning every shared dep in one place, `[workspace.lints]` (§11) |
| `rust-toolchain.toml`, `crates/flowsdn-bpf/rust-toolchain.toml` | TOML | the two toolchain pins (§3.8.3) |
| `bpf-objects.lock` | TOML: `[[object]] name, variant, features, sha256` | pins the built datapath; committed; verified by the build script and CI |
| `deny.toml` | TOML | §3.8.8 |
| `Cross.toml` | TOML | arm64 cross image and env passthrough |
| `docs/size-budget.toml` | TOML: `binary → max_bytes`, `image → max_bytes` | §3.1 budgets, enforced by `xtask size-check` |
| `docs/verifier-baseline.json` | JSON array of `{object,variant,program,kernel,arch,insns,stack,states,map_count}` | §3.10.4 baseline; updated by a reviewed commit |
| `install/kubernetes/mapping.toml` | TOML: `[[map]] key, values, condition, since` | the values→config-key mapping, input to chart generation (§3.6.1) |
| `install/kubernetes/known-diffs.toml` | TOML: `[[diff]] key, class, reason, adr` | every explained difference from the reference's rendered ConfigMap |
| `install/kubernetes/flowsdn/Chart.yaml` | YAML | `name: flowsdn`, `version`/`appVersion` = flowsdn semver, `kubeVersion: ">= 1.26.0-0"` (spec `13` raises the floor from the reference's 1.21), `annotations."flowsdn.io/cilium-compat": "1.20"`, `artifacthub.io/crds` from spec `13` |
| `install/kubernetes/flowsdn/values.yaml`, `values.schema.json`, `templates/cilium-configmap.yaml` | generated | §3.6.1 |
| `images/*/Containerfile` | Containerfile | §3.3.3 |
| release assets | see §3.9.4 | |

Build metadata struct (`flowsdn-version`, emitted by a build script, printed by
`flowsdn version --json`, exported as `flowsdn_build_info` labels):

```
version, revision, dirty(bool), build_date(RFC3339 from SOURCE_DATE_EPOCH),
rustc, bpf_toolchain, bpf_linker, bpf_objects_sha, target_triple,
features(list), reference("cilium/cilium@7d68cfb394"), chart_compat("1.20")
```

## 5. Algorithms

**5.1 Chart generation.** For each row of `mapping.toml`: look up the key in
`keys.toml` for its kind and default; emit a Go-template fragment that renders
`<key>: "<value>"` guarded by the row's condition, with `semverCompare` guards
for version-gated defaults (inventory 15 §F6: ≥1.8, ≥1.10, ≥1.12, ≥1.14, ≥1.16,
≥1.17, ≥1.18, ≥1.20). Rows in `known-diffs.toml` with class `ignored` still emit
(so the key exists) but additionally emit a `NOTES.txt` warning line. Output is
deterministic (rows sorted by key) so the generated file diffs cleanly.

**5.2 `helm-diff`.** Render `install/kubernetes/cilium` at the pinned reference
tag and `install/kubernetes/flowsdn`, both with values file *V*. Extract
`.data` of the `cilium-config` ConfigMap from each. Compute three sets:
`only_in_reference`, `only_in_flowsdn`, `differing_values`. Every member must
match a `known-diffs.toml` entry by key; anything unmatched fails. Run for each
*V* in the corpus (defaults, 41 e2e configs, `contrib/testing/*`). Complexity is
O(keys × configs) ≈ 426 × 45, trivially fast.

**5.3 Multi-arch manifest.** §3.3.2. Build per-arch with `--platform`, add both
to a local manifest list, push with `--all`, then verify: `podman manifest
inspect` must report exactly two manifests with `os=linux` and
`architecture ∈ {amd64, arm64}` and the same config labels.

**5.4 Reproducibility check.** Build twice; for each shipped binary compare
`sha256`; for each image compare the manifest digest. On mismatch, run
`diffoscope` on the two binaries and attach the report. Common causes, in the
order to check them: an un-remapped path, a `SystemTime::now()` in a build
script, a `HashMap` iteration order leaking into generated code, and a
dependency that embeds its own build timestamp.

**5.5 Size gate.** `xtask size-check` reads `docs/size-budget.toml`, measures
`stat -c %s` of each stripped binary and the `podman inspect` size of each
image, fails on exceedance, and always writes `binary-sizes.json` so the trend
is chartable even when the gate passes.

**5.6 Version bump.** `xtask version set X.Y.Z` rewrites every location in
§3.9.2 by parsing rather than regex where a parser exists (TOML via `toml_edit`
preserving formatting and comments; YAML via `serde_yaml` round-trip for
`Chart.yaml`; targeted line edits for Markdown), then re-runs `xtask version
check` on its own output.

## 6. Configuration

Environment variables the build honours:

| Variable | Default | Effect |
|---|---|---|
| `CARGO_TARGET_DIR` | **must** be `<cargo-target-dir>` on dev | `../CLAUDE.md`; `xtask` sets it and refuses to run on dev without it |
| `SOURCE_DATE_EPOCH` | commit time | reproducibility (§3.8.7) |
| `FLOWSDN_VERSION`, `FLOWSDN_REVISION` | derived from git | injected build metadata; CI sets them explicitly |
| `FLOWSDN_BPF_OBJDIR` | unset | pre-built BPF objects; when unset the build script runs `xtask bpf` |
| `FLOWSDN_REMOTE_HOST` | `<build-user>@<build-host>` | `xtask --remote` target |
| `CROSS_CONTAINER_ENGINE` | `podman` | never docker (user rule) |
| `SCCACHE_DIR`, `SCCACHE_CACHE_SIZE` | `/build/cache/sccache`, `40G` | §3.10.6 |
| `TMPDIR` | `/build/tmp` on dev | **never** `/tmp` (tmpfs, §3.8.5) |
| `FLOWSDN_REGISTRY` | `sbregistry:5100` | image push target |

Helm values owned by this spec: the `flowsdn.*` tree of §3.6.5. Config keys
owned: none — every key belongs to an area spec; this spec only maps values onto
them.

## 7. Failure modes

| Failure | Symptom | flowsdn behaviour |
|---|---|---|
| bpffs not mounted and `mount-bpf-fs` disabled | agent cannot pin maps | startup check fails with one line naming `sys-fs-bpf.mount` and `flowsdn.hostMounts.bpffs` (`docs/kernel-requirements.md` §4.7). No silent degradation |
| cgroup2 root absent / hybrid hierarchy | socket LB cannot attach | `mount-cgroup` mounts a private root; if it cannot, the agent refuses socket LB and says so; other features continue |
| `CAP_BPF` filtered by the runtime profile | every `bpf(2)` fails with `EPERM` | startup check names `flowsdn.legacyCapabilities=true` and `securityContext.privileged=true` as the two remedies |
| Kernel below 6.6 | many helpers missing | startup check refuses to run with the missing feature named; `flowsdn.kernelCheck.mode=warn` overrides for bring-up only |
| Verifier rejects a program on a node whose kernel is older than CI's oldest row | agent fails to load the datapath | the agent logs the full verifier log for that program and exits; the CI gate exists so this cannot reach a release, and the log is the bug report |
| `bpf-objects.lock` mismatch at build time | build script error | fail with "the datapath changed; run `xtask bpf` and commit `bpf-objects.lock`" — never silently rebuild |
| Image built on the Mac | wrong target, missing Linux-only code | `xtask image` refuses to run on macOS with a message pointing at `--remote` |
| `/` full on dev | `rustc-LLVM ERROR: IO failure on output stream` and a dozen unrelated crate failures | the `df` guard fails the job first with "SSD root is for working trees only; target dirs go to <cargo-target-dir>" |
| `/tmp` full on dev (tmpfs) | `no storage space` from an unrelated writer | `TMPDIR=/build/tmp` in every job; the guard checks it |
| Leaked loop mounts | a tmpfs stays full after a job | `always()` cleanup step unmounts; a nightly job reports stray `/build/tmp/tmp.*` mounts |
| `helm-diff` reports an unexplained key | PR fails | either the mapping is wrong (fix it) or the divergence is intended (add a `known-diffs.toml` entry with a reason and an ADR) |
| Reference chart bumped upstream | `helm-diff` fails wholesale | reference-tag bumps are a deliberate operation (§3.9.5), not a passive dependency |
| Registry unreachable at install time on a stormcos node | pods `ImagePullBackOff` | should not happen: images are preloaded and `imagePullPolicy: IfNotPresent`; with `flowsdn.preloaded=true` the policy is `Never`, so the failure is immediate and legible instead of a retry loop |
| Upstream reused image (Envoy, hubble-ui) yanked or re-tagged | pods fail to pull | all reused images are **digest-pinned** in values, as the reference pins them; a digest cannot be re-pointed |
| `cargo deny` flags a new transitive GPL dependency | PR fails | no exception without an ADR (`docs/licensing.md`); the fix is a different dependency, not an `ignore` entry |
| Nightly toolchain bump breaks `flowsdn-bpf` | BPF build fails | the pin is exact and separate; the workspace keeps building on stable while the BPF pin is fixed in its own PR |
| arm64 e2e runner (Rose) offline | nightly arm64 rows skip | jobs are `continue-on-error: false` but `if: always()` reporting; a skipped arm64 row blocks a **release**, not a PR |
| Two agents on one node during migration | both try to own the same pins | prevented by the drain procedure (§3.7) and by an exclusive `flock` on `<state-dir>/agent.lock`; the second agent exits with a clear message |

## 8. Observability of the build

Everything here is *about the build*, not the runtime; runtime observability is
each area spec's §8.

| Signal | Where |
|---|---|
| `flowsdn version --json` | full build metadata (§4) from every binary |
| `flowsdn_build_info{version,revision,rustc,bpf_toolchain,bpf_objects_sha,target}` gauge = 1 | agent, operator and relay metrics endpoints; this is how "which build is on this node" is answered from Prometheus, and how a partially-rolled DaemonSet is spotted |
| Image labels | §3.3.1; `podman inspect` / `crane config` answers the same question without a running pod |
| `verifier-budget.json` | CI artifact per run **and** a release asset; trended per program per kernel. The chart to keep is `bpf_host` NodePort insns on 6.6 x86-64 |
| `binary-sizes.json` | CI artifact + release asset; trended per binary and per image |
| SBOM (`sbom-<component>.cdx.json`, CycloneDX via `cargo cyclonedx`) | release asset; the input to `cargo audit`-style post-release CVE tracking |
| Build provenance | GitHub artifact attestations on the release assets; verifiable with `gh attestation verify` |
| `sha256sums.txt` | release asset covering every binary, archive and chart |
| CI job durations and cache hit rates | a nightly `ci-health` job summarising the last 7 days; a PR gate whose p50 exceeds its §3.10.2 budget by 50 % opens an issue |
| `/build` disk usage | reported by the `df` guard at the start and end of every dev job; the weekly `cache-gc` job records the trend |

## 9. Test plan

Unit (u), integration (i), privileged (p), end-to-end (e).

**Binaries and subcommands**

- [ ] (u) `flowsdn <subcommand>` dispatch table: every subcommand of §3.2 is reachable, `--help` renders, unknown subcommand exits 2 with usage.
- [ ] (p) `mount-bpffs` on a host without bpffs mounts it; second run is a no-op; `statfs` reports `BPF_FS_MAGIC` after both.
- [ ] (p) `mount-cgroup` with a unified host root does nothing and prints the host root; with a hybrid host mounts a private root; second run is a no-op.
- [ ] (i) `sysctl-fix` writes the file once; a second run with identical content does not rewrite (mtime unchanged); with D-Bus absent it exits 0 and logs INFO.
- [ ] (p) `cleanup --bpf-state` removes exactly flowsdn's pins and leaves a foreign pin (`/sys/fs/bpf/other`) untouched; `--all-state` additionally removes devices, routes, rules and the nft table, and leaves a foreign nft table untouched.
- [ ] (i) `cni install` twice is idempotent; the second run replaces the binary atomically while a reader holds the old inode open.
- [ ] (i) `cni uninstall` with `cni-uninstall=false` is a no-op; with `true` removes only `*cilium*.conf{,list}` and leaves `*.cilium_bak`.
- [ ] (i) `wait --for=kube-proxy` detects `KUBE-IPTABLES-HINT` over nftables netlink on an `iptables-nft` host; falls back to the API-server method on a legacy-xtables host; times out cleanly.
- [ ] (i) `build-config` produces a byte-identical directory for identical inputs and does not swap `..data`; produces a new data dir when a key changes; leaves at most two data dirs.
- [ ] (u) `size-check` fails when a binary exceeds its budget.

**Images**

- [ ] (i) Every image's file list matches the expected set exactly — no shell, no `/bin`, no `/usr`, no CA bundle in images that do not need one.
- [ ] (i) `podman manifest inspect` reports two manifests with the right `os`/`architecture`, and both carry the full label set of §3.3.1.
- [ ] (i) The agent image runs `["/flowsdn","version","--json"]` on both arches and the reported `bpf_objects_sha` equals `bpf-objects.lock`'s hash.
- [ ] (i) Reused upstream images are referenced by digest in `values.yaml`, and every one has a `NOTICE` entry.
- [ ] (i) Two builds of the same commit produce identical image digests (§5.4).

**Chart**

- [ ] (u) `xtask chart check`: the committed generated files match a fresh generation.
- [ ] (i) `helm lint` and `helm template` succeed for the defaults and all 45 corpus values files.
- [ ] (i) `kubeconform` passes against k8s 1.31–1.36 schemas.
- [ ] (i) **`helm-diff`**: for every corpus values file, every ConfigMap key difference from the reference render is explained in `known-diffs.toml`.
- [ ] (u) Every value in §3.6.3 renders, emits a `NOTES.txt` warning, and is reported by the agent as `"effect": "ignored"`.
- [ ] (u) Every rejected combination in §3.6.6 fails `helm template` with the expected message.
- [ ] (u) `flowsdn.strictCapabilities=true` strips `SYS_MODULE` from a user-supplied capability list; `false` keeps it.
- [ ] (i) The rendered agent DaemonSet has exactly the hostPaths of §3.5.3 — a regression that reintroduces `/lib/modules` or `/run/xtables.lock` fails.
- [ ] (i) The preflight ClusterRole is byte-identical to the agent ClusterRole.
- [ ] (e) `cilium-cli status` against a flowsdn install reports all components healthy (this is the single best proof of the §2 contract).

**Build system**

- [ ] (u) `bpf-objects.lock` mismatch fails the build with the documented message.
- [ ] (i) The BPF post-processing check catches an injected `memcpy` relocation and an injected `core::panicking` reference.
- [ ] (i) `cargo deny check` fails on an injected GPL dependency and on an injected `openssl-sys`.
- [ ] (u) `xtask version check` fails when any one of the §3.9.2 locations disagrees.
- [ ] (i) `xtask notice` fails when a dependency is added without a NOTICE update.
- [ ] (i) A cross-built arm64 binary is `ET_EXEC`/static (`ldd` reports "not a dynamic executable") for every shipped binary.

**CI and matrix**

- [ ] (p) The verifier gate fails a deliberately bloated program (> 800 k insns) and reports the program name.
- [ ] (p) The verifier gate fails a program with an unresolved panic relocation, distinguishing "failed to load" from "too complex" in the message.
- [ ] (p) `flowsdn-bpf-tests` runs the `CASES.toml` corpus on 6.12 and reports per-case results.
- [ ] (i) `flowsdn-scripttest` runs all 168 harvested scenarios; every expected-divergence marker carries a reason.
- [ ] (e) `e2e-smoke` on kind 6.12 passes the spec `19` M1 subset plus `check-log-errors` and `no-unexpected-packet-drops`.
- [ ] (e) `upgrade`: flowsdn N-1 → N with `--include-conn-disrupt-test` shows no interrupted connections.
- [ ] (e) `mixed-cluster`: pod-to-pod and NodePort across a Cilium node and a flowsdn node, with correct identities in Hubble.
- [ ] (e) The §3.7 Cilium→flowsdn drain migration runs end to end as a script on a 3-node kind cluster and ends with `cilium-cli status` healthy.
- [ ] (i) The `df` guard fails a job when `/build` is artificially filled, with the documented message.

## 10. Kernel and platform requirements

This spec adds none of its own; it *encodes* `docs/kernel-requirements.md`:

- The **capability sets** of §3.5.2 come from §4.5 of that document. `CAP_BPF`
  and `CAP_PERFMON` require ≥ 5.8 and the floor is 6.6, so they are always
  available; `SYS_ADMIN` remains only for `mount(2)` and `setns(2)`.
- The **hostPath set** of §3.5.3 comes from §4.6 ("what a scratch image needs on
  disk").
- The **CI matrix** of §3.10.3 is §5.3 verbatim.
- The **kernel config fragment** of §2.6 is what a node must satisfy; the chart
  cannot check it, and the agent's startup check (§4.7) is the enforcement
  point. `flowsdn.kernelCheck.mode` is the only escape hatch.
- **Build hosts**: `<build-host>` (x86-64 Linux) for everything heavy; a Rose
  cluster node (arm64) for nightly arm64 e2e. macOS is an editor.
- **Container runtime for building**: podman only (user rule). Docker is not
  used anywhere, including in `cross` (`CROSS_CONTAINER_ENGINE=podman`).
- **kind and LVH**: LVH `quay.io/lvh-images/kind:<kernel>-<date>` images are
  x86-64 only; arm64 VMs are built from Rocky 10 `aarch64` or upstream tarballs
  with the §2.6 fragment.

## 11. Rust design notes

**`xtask` is the build system.** A `xtask/` binary crate in the workspace,
invoked as `cargo xtask <cmd>`, with `clap` (derive) for the command tree and
`xshell` for process execution. It is Rust, so it is type-checked, unit-testable
and identical on macOS and Linux — which matters because half its job is
deciding *not* to run locally and to dispatch to `<build-host>` instead. No `make`
logic, no shell scripts in CI beyond a two-line invocation of `xtask`.

**Workspace lints**, declared once in `[workspace.lints.rust]` /
`[workspace.lints.clippy]` and inherited by every crate:

```
unsafe_code = "deny"                 # per-crate `allow` with a comment where needed
missing_debug_implementations = "warn"
clippy::indexing_slicing = "deny"    # in the BPF crate especially: a panic path
clippy::arithmetic_side_effects = "deny"   # ditto (kernel-requirements §3.3 item 7)
clippy::unwrap_used = "deny"         # allow in tests
clippy::expect_used = "warn"
clippy::todo = "deny"
```

`unsafe_code = "deny"` at the workspace level with narrow per-crate exceptions
(`flowsdn-bpf-sys`, `flowsdn-netns`, `flowsdn-bpf`, the `Pod` impls in
`flowsdn-bpf-abi`) makes the unsafe surface enumerable from `Cargo.toml`.

**Profiles.**

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"          # binaries; test profile keeps unwind
strip = "symbols"
debug = 0
[profile.release-debug]  # inherits release, for bugtool-grade backtraces
inherits = "release"
debug = 1
strip = "none"
```

`flowsdn-cni` overrides to `opt-level = "s"` — exec latency is dominated by
page-in, not by code quality (spec `09` §11).

**Feature flags** are used for exactly three things and never for anything else:
(a) the four operator cloud variants (`aws`, `azure`, `alibabacloud`; default =
generic), (b) `privileged` on test targets, (c) the BPF object variants inside
`flowsdn-bpf` (spec `02` §6.2). Features MUST be additive; the operator's cloud
features are mutually exclusive by convention and a `compile_error!` enforces it.

**Build scripts** are kept to three: `flowsdn-version` (metadata injection),
`flowsdn-loader` (BPF object embedding), `flowsdn-config` (generate the typed
`Config` from `keys.toml`). Each is deterministic, reads only declared inputs
(`cargo:rerun-if-changed`, `cargo:rerun-if-env-changed`), and never calls the
network or the clock.

**`include_bytes_aligned!`** — the BPF objects need 8-byte alignment for
`aya_obj` parsing; the macro wraps `include_bytes!` in a `#[repr(align(8))]`
struct. Written locally (six lines) rather than depending on a crate.

**Generated-code policy.** Generated files that a human reviews (the chart
templates, `values.yaml`, `values.schema.json`, the vendored CRD YAML) are
**committed** and checked by CI. Generated files nobody reviews (protobuf
types, the typed `Config`, `bpf_objects.rs`) live in `OUT_DIR` and are not
committed. The line is "would a reviewer want to see this change in a diff?".

## 12. Decisions and remaining questions

Resolved entries are normative decisions from [ADR-0013](../decisions/0013-integration-issue-resolutions.md); their implementation and acceptance tests remain required.

1. **Resolved #236: GHCR is a public mirror.** Keep release archives and a
   configured deployment registry as the primary distribution paths. Enable the
   GHCR mirror only when the repository is public; mirror the same digest.
   The planning library does not upload images or change repository visibility.

2. **Resolved — #237.** Keep cilium, cilium-config and cilium-operator chart object
   names and existing selectors for compatibility. A branding rename requires a
   separately designed migration; no automatic rename is planned at 1.0.

3. **ClusterMesh apiserver image.** Options: (a) reuse upstream until spec `20`;
   (b) ship a Rust apiserver + upstream `etcd` binary immediately; (c) replace
   etcd too. **Recommendation: (a) → (b).** Reuse now; ship
   `flowsdn-clustermesh-apiserver` with the upstream static `etcd` when spec `20`
   lands. (c) is a separate project (the contract is the etcd key space and the
   remote-cluster protocol, and replacing etcd changes both).

4. **Resolved #239/#152: certificate ownership follows TLS method.** Helm is
   the default issuer; cert-manager and user-provided Secrets remain supported.
   CronJob mode uses the upstream certgen image pinned by digest. No new Rust
   issuer ships in this stage; revisit after milestone 4 acceptance. Every
   issuer must honor spec 11 server names and client-auth requirements.

5. **Resolved — #240.** Ship a Rust loopback entry point from the flowsdn-cni
   executable, installed as loopback (also addressable as flowsdn-loopback). Spec 09
   owns dispatch and CNI semantics. Do not bundle the upstream Go loopback executable.

6. **arm64 e2e hardware.** Options: (a) Rose cluster nightly (current plan);
   (b) a cloud arm64 runner (Graviton) per PR; (c) QEMU TCG for e2e too.
   **Recommendation: (a)**, with (b) as a paid upgrade if arm64 regressions
   start reaching releases. (c) is too slow for e2e and would test QEMU's
   virtio-net rather than a real driver.

7. **Resolved #242: privileged runners accept trusted dispatch only.**
   Hosted runners handle pull requests. The privileged lane requires an
   approved workflow_dispatch from this repository on refs/heads/main; it
   never checks out an arbitrary ref or fork input. Reject pull_request_target
   and automatic PR/push events for this lane. Promotion of a reviewed fork
   change to trusted main precedes privileged testing. The Rust policy helper
   fails closed; actual workflow wiring remains a milestone 4 gate.

8. **seccomp profile.** The reference ships `seccompProfile: Unconfined` for the
   agent. flowsdn's syscall surface is much smaller (no exec of anything, ever)
   and therefore profileable. **Recommendation:** ship a `RuntimeDefault`-plus-
   `bpf/perf_event_open/setns/mount` profile as an opt-in
   (`flowsdn.seccomp.enabled`) at 1.0, generated from a syscall trace of the
   privileged test suite, and make it the default at 1.1 once it has run in
   anger. A scratch image with no shell and no exec is the ideal case for this,
   and it is a genuine security improvement over the reference.

9. **Resolved #244: publish charts through OCI and public Pages.** OCI is
   the primary chart transport; enable Pages for helm repo add when the
   repository is public. Both transports publish the same validated chart.
   Signing, index updates and publication remain release-pipeline work.

10. **Resolved — #245.** Commit bpf-objects.lock alongside source changes that alter the
   produced bytecode. CI rebuilds with pinned inputs and verifies hashes; the same hash
   identifies verifier baselines and release objects. CI artifacts supplement, not
   replace, the reviewed lock.

### Packaging policy implementation (#33/#38/#235/#236/#239/#242/#244)

`flowsdn-packaging` provides pure deployment and CI plans. Renderers, mount
helpers, dispatchers and uploaders must consume and enforce these plans before
runtime support is claimed. It does not invoke external programs or mutate hosts.

For #33, preserve §3.6 ignored-with-warning keys and nftables NOTRACK behavior.
Reject disabled BPF masquerade whenever either address family requests
masquerading. Do not conflate this with banning all kube-proxy coexistence:
that remains governed by routing validation. No iptables fallback is provided.

For #38, both installation models are supported: host-managed filesystems must
already have the correct statfs type; missing/wrong types fail without a mount
fallback. General installations may schedule the configured init helper, but
must verify filesystem type afterward. Directory existence is insufficient.
Optional cgroup features may be disabled independently; required bpffs must pass.

For #235, retain a 10,000,000-byte quick set on every run for seven days and full
failure evidence up to 2 GiB for fourteen days. Failure quick sets share the
fourteen-day retention. Use 100,000 retained flows nightly and 1,000,000 for PR
runs. Existing manifest/truncation ordering remains mandatory; these are caps,
not a claim that the collector or upload workflow exists.
