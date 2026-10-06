# ADR-0017: flowsdn resource identity and compatibility names

Date: 2026-09-27. Status: accepted. Owner direction: [#299](https://github.com/glennswest/flowsdn/issues/299).

## Kubernetes ownership

flowsdn-owned custom resources use `flowsdn.io/v1alpha1`, `Flowsdn*` kinds,
`flowsdn*` resource names and the sole category `flowsdn`. For example,
`FlowsdnNode` has plural `flowsdnnodes` and CRD name
`flowsdnnodes.flowsdn.io`. Registration has one served/storage version,
`v1alpha1`. This is an initial flowsdn API, not a claim to upstream's API maturity.
The owned list kind is `<FlowsdnKind>List`. Upstream short names are omitted; they would collide with an installed Cilium. Each kind instead registers one flowsdn short name, the upstream one with `fs` in place of Cilium's `c`/`cilium` (`fsnp`, `fsep`, ...; `plan::SHORT_NAMES`, #325).
The schema-version label is `io.flowsdn.k8s.crd.schema.version`.

The normal registration planner accepts flowsdn identity only. An explicit
migration projection accepts a reference `cilium.io` CRD and projects its
storage-version schema, scope, subresources and printer columns into flowsdn
identity. Within schema properties named `group`, `kind` and `apiVersion`,
known upstream identity values in `default`, `enum` and `const` are projected
to their owned equivalents, so embedded references target flowsdn resources.
Descriptions and arbitrary compatibility fields remain unchanged. This is an
in-memory schema transformation, not a cluster migration
command or a running policy reader. It does not copy object UIDs, ownership,
finalizers or stored instances from another controller.

Existing `cilium.io` CRDs and instances MUST NOT be adopted, reconciled, patched,
deleted or garbage-collected by flowsdn. A conflict under flowsdn's own identity
must be evaluated as an ownership conflict, never resolved by taking upstream
ownership. A future explicit instance importer must create distinct flowsdn
objects with flowsdn ownership and leave the source intact. Reading an upstream
format remains a legitimate compatibility goal, but no live Cilium policy
controller or instance importer is claimed by the registration library.

Reference schemas, fixtures, source paths, checksums and license attribution
retain their original names. No global replacement of `cilium` is appropriate.
This decision supersedes ownership and served-version requirements in spec 13
and the earlier #166/#184 decisions for flowsdn's own registration. Preservation
of upstream multi-version schemas remains a reference/migration verification
obligation; flowsdn does not register those versions into the upstream group.

## Node-visible names

**Amended by ADR-0019 (#294):** the owner ruled out Cilium names in flowsdn. The CNI
alias rows and runtime paths below are replaced: the CNI is `flowsdn-cni`
(conflist type `flowsdn-cni`, no `cilium-cni`), and the socket and queue live
in `/var/run/flowsdn`. Interface and BPF names are being renamed separately (#339).

| Surface | Decision and reason |
|---|---|
| Agent/CNI executable identity | Keep `flowsdn-agent` and `flowsdn-cni`. Do not ship renamed `cilium-dbg` or `cilium-cli` executables. Future flowsdn CLI entry points use flowsdn names. |
| CNI compatibility aliases | Retain `cilium-cni`, `flowsdn-cni` and existing deployment alias `flowsdn` for the same executable. CNI `type` resolves an executable by filename; removing the alias would break existing conflists. `loopback` is the standard plugin entry point. |
| Existing interface names, including `cilium_host`, `cilium_net`, `cilium_wg0` where specified | Retain as explicit datapath compatibility names where implementation/spec contracts use them. Route/link lookup and restore must agree on names; renaming active links is a networking migration, not a branding edit. Listing a planned interface here does not mean the daemon creates it today. |
| Runtime socket/state paths such as `/var/run/cilium` | Retain documented compatibility paths for existing client and restore contracts. A path name does not establish ownership; persisted flowsdn ownership remains authoritative. |
| Existing BPF names, including `cilium_call_policy`, `cilium_node_map_v2`, `cilium_events` | Retain established ABI, pin and tooling names. Existing descriptors and pinned-state restoration depend on stable names/layouts. An existing foreign map or link is never proof of flowsdn ownership. |
| ConfigMap and taint defaults | Resolved configuration defaults become `flowsdn-config` and `node.flowsdn.io/agent-not-ready`. Preserve original catalogue expressions as reference provenance. The standalone JSON agent does not yet consume a live ConfigMap or manage the taint. |
| Controller attribution | New flowsdn controller, service and secret-namespace defaults use flowsdn names; Gateway condition ownership uses `gamma.flowsdn.io`. Reference corpus identifiers stay unchanged. |
| Future Hubble compatibility | Protocol and certificate-name compatibility are separate contracts. They do not imply a running observer, relay, TCP listener or ownership of upstream Kubernetes resources. |

The configuration catalogue changes these resolved defaults while preserving
its original `default_expression` values as reference provenance:

| Option | flowsdn resolved default |
|---|---|
| `agent-not-ready-taint-key` | `node.flowsdn.io/agent-not-ready` |
| `config-sources` | ConfigMap `kube-system/flowsdn-config` |
| `gateway-api-secrets-namespace` | `flowsdn-secrets` |
| `ingress-secrets-namespace` | `flowsdn-secrets` |
| `policy-secrets-namespace` | `flowsdn-secrets` |

These are library defaults, not five new accepted standalone agent flags. The
encryption planner's existing `ciliumnode_crd` field keeps its source-compatible
spelling but refers to the owned `FlowsdnNode` resource.

Retaining a compatibility name does not grant permission to adopt another
implementation's host resources. Agent state and ownership checks remain the
authority for mutation and cleanup. New independently designed artifacts should
use flowsdn names; changing the retained contracts requires explicit migration
and restore tests.

## Actual API support

The standalone agent serves the documented subset of endpoint/IPAM/health HTTP
routes over its Unix socket. It does not expose complete upstream REST or CLI
compatibility. Hubble observer/relay and live custom-resource controllers remain
planned. Registration and migration projection tests establish payload behavior,
not cluster interoperability or milestone acceptance.
