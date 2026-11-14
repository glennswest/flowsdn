# flowsdn — Project Instructions

Rust networking implementation for stormcos, with Cilium-compatible boundary
formats as a goal. Follow `AGENTS.md` and the session's cross-project rules.
GitHub is the transfer/results path. Build only through `sc-build` after push;
never build on this session VM or create persistent build-box checkouts.

## Current version and source state

Workspace package version and latest foundation prerelease: **0.14.0**.
Version locations: `Cargo.toml` workspace.package.version and release headings
in `CHANGELOG.md`; Cargo.lock records workspace packages when versions change.
Main contains unreleased endpoint agent/CNI work beyond that foundation release.
This documentation-only audit does not warrant a version bump or release.

As of 2026-11-10, source through `d50a453` runs a standalone JSON-configured
agent over a Unix socket (`/var/run/flowsdn/flowsdn.sock` in the manifests) and a
primary veth + loopback CNI (`flowsdn-cni`, conflist `00-flowsdn.conflist`). The
agent embeds its `local-delivery` BPF object (and, with the `kubernetes` feature,
`socket-lb`; both pinned by `bpf-objects.lock`) and has `egress: fib|stack`. With
the `kubernetes` feature (GNU build, Fedora OpenSSL; in the golden since
golden-flowsdn-4e9e3f0bc876, run by `manifests-kubernetes/`) it watches Nodes/Pods/Services/EndpointSlices, adds
remote pod-CIDR routes, translates ClusterIP/externalIP/LoadBalancer/NodePort at the
socket (cgroup hooks, ClientIP affinity, traffic policy Local), serves external
NodePort/LB/externalIP traffic on the uplink (TCX, IPv4 and IPv6, SNAT to other
nodes' backends), writes Events and the `flowsdn.io/pod-networks` annotation.
`http-listen` is a loopback read-only TCP listener (#297). Several uplinks (#408, 8480160): every port on a
node address's subnet with carrier carries per-flow ECMP routes, with source rules per address, a failover /32 + GARP
while a port is down, `GET /v1/uplinks` and `kubernetes.uplinks`; kernel-checked by `uplinks-live`, not yet on a two-port node. Also implemented: identity allocation (#291), NetworkPolicy enforcement in the
datapath (ADR-0021), flowsdn policy kinds (`kubernetes.flowsdn-policy`), host
firewall (`audit` in the stormcos config), UDP socket termination, Maglev, DSR by
IP option, NAT46/64 (the last three off by default, kernel test runs only), CNI
ADD timing (`/v1/cni/timing`), `cargo xtask kernel-check`. Not implemented: the
operator executable, CRD registration (#337), Hubble observer/relay (#293), TCP
socket termination, DSR by IPIP/Geneve, L7/FQDN/ICMP policy. See
`docs/runtime.md`, `docs/agent-api.md`, `docs/implementation-status.md` and
`deploy/stormcos/README.md` before changing runtime behavior. Fixture traffic and
cross-architecture compilation do not establish two-node pod networking. Docs
were last refreshed from code on 2026-10-09 (`git log --since=2026-10-02`).

## Shipping and ownership

The stormcos flowsdn edition carries the agent (static musl and GNU Kubernetes
mode) and CNI in the `flowsdn` golden; `deploy/stormcos/manifests-kubernetes/` runs it
as `image: flowsdn` with a CNI-install init container (stormcos#261 applies
them). Latest golden: golden-flowsdn-de1d63ada483 at 1254993 (DSR, Maglev, host firewall, flowsdn policy kinds, NAT46/64; features off by default, kernel test runs only). Earlier: golden-flowsdn-760c3a2e89d6 at 9732b71 (NetworkPolicy enforcement, #292; stormcos#528). Before it: golden-flowsdn-a690ebee2ba7 at 4447eeb (IPv6 NodePort, identity allocation, network-status; stormcos#494). Goldens before golden-flowsdn-4b40a980ad16 carry a socket LB that cannot attach on 7.2 (cda5799). Source pushes do not update nodes until a new golden is composed into
a release. Authority:
[stormcos/docs/goldens.md](https://github.com/glennswest/stormcos/blob/main/docs/goldens.md).
After validated implementation work, flowsdn uses the special-component
`stormcentral component stage flowsdn` path specified by the session rules.
Documentation-only work is not a networking release. Cargo.lock pins select
which dependency revisions are built; sibling changes do not arrive implicitly.

The owner requires flowsdn identity for CRDs it owns (#299). Owned registration now projects `flowsdn.io/v1alpha1`; upstream schema input
is explicit migration only. See ADR-0017; full workspace verification passed at 9c1ea61.
Read compatibility formats separately from ownership/attribution. PVCs are
provided by the built-in stormblock driver, not a flowsdn storage controller.
Current builds/tests use sc-build after push and flowsdn goldens use
stormcentral component stage flowsdn. GitHub Actions is disabled; #304 removes
the obsolete workflow. Do not add an Actions runner or re-enable Actions.

## Work plan and history

Moved to [docs/work-plan.md](docs/work-plan.md) (CLAUDE.md is loaded into every session; its size made the session's context thrash). Nothing was dropped. Not loaded by default: `grep -n '^##' docs/work-plan.md`, then read only the section you need. Write new intentions and progress there, not here.

## Reference and conventions

The inventory/specification reference is Cilium **v1.20.1, `7d68cfb394`**.
Follow `docs/licensing.md`; reference data is not executable flowsdn coverage.
`docs/README.md` distinguishes current behavior, intended contracts and history.

- Project executable code, test harnesses and reusable tools are Rust. BPF uses
  aya-ebpf; no copied C datapath and no iptables dependency.
- Read the relevant spec and architecture decisions before implementation,
  including subsequent owner directions that supersede historical choices.
- Use bounded parallel review with disjoint ownership. The coordinator alone
  mutates Git and serializes shared-host validation.
- Commit/push each work step with changelog and affected docs; inspect diffs for
  secrets. Scratch stays in ignored `tmp/`. Preserve observed validation results
  without upgrading a library/unit test into a runtime support claim.
