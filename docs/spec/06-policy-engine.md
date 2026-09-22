# Network policy engine — specification

Status: draft. Derived from: `docs/inventory/05-policy-identity.md` (primary),
`docs/inventory/13-crds-k8s.md`, `docs/inventory/06-agent-endpoint-api.md`,
`docs/inventory/11-l7-proxy-dns-auth-mesh.md`; reference cilium v1.20.1
(7d68cfb394) paths `pkg/policy/{repository,rules,rule,resolve,l4,mapstate,
portrange,aggregate,selectorcache,selectorcache_selector,proxyid,trigger,
lookup}.go`, `pkg/policy/types/{entry,policyentry,types,selector,requirements,
auth,update}.go`, `pkg/policy/api/**`, `pkg/policy/utils/parserules.go`,
`pkg/policy/k8s/{cilium_network_policy,service,cell,watcher}.go`,
`pkg/policy/cell/{identity_updater,policy_importer}.go`, `pkg/policy/compute/`,
`pkg/policy/cookie/`, `pkg/k8s/{network_policy,cluster_network_policy}.go`,
`pkg/k8s/apis/cilium.io/utils/utils.go`, `pkg/maps/policymap/`,
`pkg/endpoint/{bpf,policy,endpoint}.go` (policy-map apply, lockdown, revision),
`api/v1/openapi.yaml` (`/policy*`), `bpf/lib/policy.h` (entry layout only).
Governed by ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes
*what* flowsdn does and the exact data it exchanges. It does not transcribe
reference code. Where the reference behavior is kept for compatibility, say
so and name the consumer that depends on it (cilium-dbg, Hubble, Envoy,
operator, other cluster). Where flowsdn deviates, mark **DEVIATION** with the
reason and the ADR.

## 1. Scope

In scope: everything between a policy object arriving from Kubernetes (or a
file) and the entries written into an endpoint's `cilium_policy_v3_<epid>`
map:

- the policy language of `CiliumNetworkPolicy` (CNP) and
  `CiliumClusterwideNetworkPolicy` (CCNP), its validation, and the namespace
  and cluster label injection that turns a CRD `spec` into rules;
- translation of Kubernetes `NetworkPolicy` (KNP) and of
  `policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy` (KCNP);
- the tier / priority / verdict / precedence model and how conflicting rules
  resolve;
- the rule repository and its revision, the selector cache, per-identity
  selector policies, per-endpoint endpoint policies and the map-state
  builder, including incremental updates on identity churn, redirect
  entries, authentication requirements, port ranges and aggregate identities;
- enforcement modes, default-deny decisions, audit mode, host firewall
  subjects;
- the normative summary of the datapath contract this engine programs
  against, policy revision semantics, endpoint regeneration triggers, the
  read-only REST API, configuration, failure modes, observability and tests.

Out of scope, with owning spec: label model, identity numbering, aggregate
table, ipcache writes for policy CIDRs and CIDR groups (`03-identity-ipcache`,
built on, never redefined here); `policy_key` / `policy_entry` byte layout,
map pinning, sizing and the call maps (`01-bpf-map-abi-loader`); the BPF
verdict computation and verdict-event emission (`02-datapath-programs` §3.10,
§5.2 — §3.8 here is the summary); DNS name resolution, `fqdn:` label
production and the DNS proxy (DNS/L7 spec — this spec covers only the policy
side of `toFQDNs`); translation of `L7Rules`, TLS contexts and listeners to
Envoy xDS, and the SPIRE/auth map (L7 spec; the redirect *entry* and
`auth_type` byte are specified here); endpoint state machine and proxy port
allocation (agent core spec; the contract used is fixed in §3.7.6); CNP
status writing and `toGroups` derivative policies (operator spec; `toGroups`
is **deferred**, inventory 05); `--static-cnp-path` (deferred).

## 2. Compatibility contract

| Interface | Consumer | MUST match |
|---|---|---|
| `CiliumNetworkPolicy` / `CiliumClusterwideNetworkPolicy` (`cilium.io/v2`) schema and semantics (§3.2) | users, Helm, cilium-cli, Hubble, operator status | every field name, validation rule, default, and the namespace/cluster injection (§3.2.9) |
| `NetworkPolicy` (`networking.k8s.io/v1`) semantics (§3.3) | Kubernetes conformance (cyclonus suite) | translation rules byte-for-byte in resulting labels/selectors |
| `ClusterNetworkPolicy` (`policy.networking.k8s.io/v1alpha2`) semantics (§3.4) | network-policy-api conformance | tier, priority, action, subject and peer translation |
| `cilium_policy_v3_<epid>` key and entry encoding (§4.4, §4.5) | BPF datapath (spec 02), `cilium-dbg bpf policy`, Envoy (reads `precedence`? no — reads nothing; keeps map name for `--bpf-root` tooling) | key prefix rules, `precedence` bit layout, flag bits, `auth_type` byte, aggregate identities |
| Reserved / aggregate identities, `aggregate_for` (spec 03 §4.4) | BPF datapath, Hubble | used as is |
| Entity → selector mapping (§3.2.3) | users (`fromEntities`), Hubble correlation | table frozen |
| Synthesized rule labels `reserved:io.cilium.policy.derived-from=…` (§4.8) | Hubble policy correlation, `cilium-dbg policy` | exact strings |
| Policy labels `k8s:io.cilium.k8s.policy.{derived-from,name,namespace,uid}` (§3.2.9) | Hubble (`flow.Policy`), cilium-cli, users' `labels` selectors | exact keys and values |
| Selector cache key strings (§4.2) | `cilium-dbg policy selectors` output, Hubble debugging | string forms |
| Proxy id `"<epid>:<ingress\|egress>:<PROTO>:<port>:<listener>"` (§4.3) | proxy/L7 spec, `cilium-dbg endpoint get` (`policy.l4`) | format |
| Listener priorities HTTP 101, TLS 116, DNS 121, CRD 126, max 126 (§3.2.6) | Envoy listener selection, users' `listener.priority` | values |
| REST `GET /policy`, `/policy/selectors`, `/policy/subject-selectors` (§4.6) | `cilium-dbg policy get\|selectors`, health checks | models |
| Monitor agent notifications `Policy updated` / `Policy deleted` (§4.7) | Hubble, `cilium-dbg monitor` | JSON |
| Verdict notification `policy_verdict_notify` (spec 01 §4.6) | Hubble, `cilium-dbg monitor` | flowsdn only fills `cookie` |
| Metrics names (§8) | Grafana dashboards | names and label sets |
| Config keys (§6) | `cilium-config` ConfigMap, Helm | names and defaults |
| Endpoint runtime option `PolicyAuditMode`, `PolicyVerdictNotification` | `cilium-dbg endpoint config` | option names (spec 00 §2) |

Not compatible, by decision (ADR-0004; confirmed #14 by ADR-0011): `cilium-dbg shell` commands
`policy/mapstate/{entries,topk,stage}`, `policyrepo/*`, `policy/import`
(ADR-0004, no hive shell); the hive-script `.txtar` harness (replaced by Rust
integration tests, §9). `GET /policy` is kept even though the reference marks
it deprecated because `cilium-dbg policy get` still calls it at 1.20.1.

## 3. Behavior

### 3.1 Sources and the intermediate representation

Every policy source is translated into a flat list of **policy entries**
(§4.1) and handed to the repository as one *policy update* per resource:

| Source | Resource id (spec 03 §3.7) | Source (spec 03 §4.6) | Gate |
|---|---|---|---|
| `CiliumNetworkPolicy` | `cnp/<ns>/<name>` | `custom-resource` | `enable-cilium-network-policy` (true) |
| `CiliumClusterwideNetworkPolicy` | `ccnp//<name>` | `custom-resource` | `enable-cilium-clusterwide-network-policy` (true) |
| `NetworkPolicy` | `netpol/<ns>/<name>` | `k8s` | `enable-k8s-networkpolicy` (true) |
| `ClusterNetworkPolicy` (v1alpha2) | `kcnp//<name>` | `k8s` | `enable-k8s-cluster-network-policy` (**false**) |
| static YAML file | `file//<path>` | `directory` | `static-cnp-path` — **deferred**, key accepted and ignored |
| synthesized default rules (§3.6) | none (tier 255, never in the repository) | — | — |

A policy update carries `(entries, resource id, source, receive time,
optional done channel)`. Applying it **replaces** every entry previously held
for that resource (§3.7.1). Deleting the object is an update with zero
entries. Both CNP `spec` and `specs[]` are flattened into the same resource
id; the entry index within the resource orders ties (§3.5.4).

Every entry names: tier, priority (float), verdict (Allow/Deny/Pass),
direction, whether the subject is a node, the subject label selector, the
peer selectors (`L3`), the port rules (`L4`, including ICMP rendered as
ports), an optional authentication requirement, the rule labels, the log
string, and the `DefaultDeny` flag. The CNP language (§3.2), KNP (§3.3) and
KCNP (§3.4) all end here; from §3.5 on nothing knows which API produced an
entry except through its labels.

### 3.2 CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy

A CNP/CCNP object is `{ spec?: Rule, specs?: [Rule] }` plus metadata. A rule
(`api.Rule`) is:

```
endpointSelector | nodeSelector   exactly one (a rule with neither, or both, is rejected)
ingress[]      IngressRule        allow
ingressDeny[]  IngressDenyRule    deny (no L7, no auth)
egress[]       EgressRule         allow
egressDeny[]   EgressDenyRule     deny
labels[]       "source:key=value" strings; missing source becomes `unspec`
description    free text
enableDefaultDeny { ingress?: bool, egress?: bool }
log { value: string }            (stored; see §3.2.8)
```

At least one of the four rule lists MUST be non-empty. `nodeSelector` marks
the entry `Node = true` (host firewall subject, §3.6.4); its keys are
prefixed `node:` at injection time (§3.2.9).

#### 3.2.1 Subject and peers

**Resolved (#95, ADR-0011):** `fromRequires` and `toRequires` remain accepted
schema fields, are ignored in compilation, and produce one warning per
affected rule on import. They do not constrain peers.

Ingress peers (`IngressCommonRule`): `fromEndpoints[]`, `fromRequires[]`
(**deprecated, no effect at 1.20** — accepted, ignored; the reference has no
remaining consumer), `fromCIDR[]`, `fromCIDRSet[]`, `fromEntities[]`,
`fromGroups[]` (deferred), `fromNodes[]`. Egress peers add `toServices[]`,
`toFQDNs[]` (allow only), `toGroups[]` (deferred), `toNodes[]`.

Peer semantics are a **union**: an entry's `L3` is the concatenation, in
this order, of endpoint selectors, node selectors, entity selectors, CIDR
selectors, CIDR-set selectors, FQDN selectors, group selectors. One entry per
`ingress[i]`/`egress[i]` element; the L4 part applies to every peer of that
element. A rule element whose peer lists are all absent (`nil`) selects the
**wildcard** (all peers, §3.7.5). A peer list that is present but **empty**
(`fromEndpoints: []`) selects **nothing**: the whole `L3` becomes empty-set
and the entry has no effect except that it still counts as "a rule selects
this endpoint" for default-deny (§3.6). flowsdn MUST preserve the
present-but-empty distinction through YAML/JSON decoding (`Option<Vec<_>>`).

Combination restrictions (`Sanitize`): within one ingress element, at most
one of {`fromEndpoints`, `fromCIDR`, `fromCIDRSet`, `fromEntities`,
`fromNodes`, `fromGroups`} MAY be combined with another only for the pairs
the reference permits; the reference rejects "combining X and Y is not
supported yet" for every pair except (`fromEndpoints`|`fromEntities` with
each other is allowed; CIDR forms with each other are allowed). flowsdn MUST
reproduce the reference matrix exactly (`l3Members` in
`pkg/policy/api/rule_validation.go`): the allowed combinations are
`fromEndpoints`+`fromEntities`, `fromCIDR`+`fromCIDRSet`, and any single
member; egress additionally allows `toServices` only alone or with
`toEndpoints`, and `toFQDNs` only with `toPorts`. `toServices` combined with
`toPorts` is rejected unless every L3 member present supports L4
(`l3DependentL4Support`: `toServices` does not). `fromNodes`/`toNodes`
require `enable-node-selector-labels`, else the rule is rejected with
`FromNodes/ToNodes rules can only be applied when the "enable-node-selector-labels" flag is set`.
Unknown entity names are rejected (`unsupported entity: <name>`).

#### 3.2.2 Endpoint selectors

An `EndpointSelector` is a Kubernetes `LabelSelector` (`matchLabels`,
`matchExpressions` with `In`, `NotIn`, `Exists`, `DoesNotExist`) whose keys
carry a label source prefix. Keys without a prefix get the `any:` source
when compiled for matching and the `k8s:` prefix when injected from a CRD
(§3.2.9). A `$`-prefixed key is `reserved:`. The string form used as the
cache key (§4.2) is the Kubernetes `LabelSelector.String()` rendering of the
prefixed selector (e.g. `k8s:app=foo,k8s:io.kubernetes.pod.namespace=default`);
flowsdn MUST produce byte-identical strings because they appear in
`GET /policy/selectors` and `cilium-dbg`. An empty selector `{}` selects
everything (wildcard); `reserved:none` selects nothing and is used for
`toFQDNs` placeholders.

Matching (`Requirements`): each requirement is `(label, operator, values)`
with the label parsed by `ParseSelectLabel` (spec 03 §3.1); `any:` matches a
label of any source with the same key; `Exists`/`DoesNotExist` ignore the
value; `In`/`Equals` require presence and membership; `NotIn` is satisfied
by absence. Requirements are sorted by extended key so equivalent selectors
have one key. A `cidr:` label in a selector matches a `cidr:` label of an
identity when the selector's prefix contains the identity's address and is
not longer (spec 03 §4.1).

#### 3.2.3 Entities (frozen table)

Entities expand to endpoint selectors (`reserved:` labels unless stated):

| Entity | Selectors |
|---|---|
| `all` | `{}` (wildcard) |
| `world` | `world`, `world-ipv4`, `world-ipv6`, `aggregate-world` |
| `world-ipv4` | `world-ipv4` |
| `world-ipv6` | `world-ipv6` |
| `host` | `host` |
| `init` | `init` |
| `ingress` | `ingress` |
| `remote-node` | `remote-node`, `aggregate-remote-node` |
| `health` | `health` |
| `unmanaged` | `unmanaged` |
| `none` | `none` |
| `kube-apiserver` | `kube-apiserver` |
| `cluster` | *cluster set* + `k8s:io.cilium.k8s.policy.cluster=<local cluster name>` |
| `cluster-mesh` | *cluster set* + `aggregate-cluster-mesh` + `k8s:io.cilium.k8s.policy.cluster Exists` |

*cluster set* = `host`, `remote-node`, `init`, `ingress`, `health`,
`unmanaged`, `kube-apiserver`, `aggregate-cluster`. The `cluster` entity is
resolved at startup from `cluster-name` (`InitEntities`). The aggregate
selectors exist so that a `world`/`cluster`/`remote-node` entity yields a
single aggregate key (11/12/13/14) instead of one key per identity (§3.7.5);
they select exactly the reserved aggregate identities, which no real
endpoint ever has.

#### 3.2.4 CIDR peers

`fromCIDR`/`toCIDR` (`CIDRSlice`): strings `a.b.c.d/len`, `x::/len` or a
bare address (becomes `/32` or `/128`). The mask MUST be contiguous
(`CIDR cannot specify non-contiguous mask`). Each becomes a **CIDR selector**
(§4.2) whose single requirement is `cidr:<encoded prefix> Exists`.

`fromCIDRSet`/`toCIDRSet` (`CIDRRule`): exactly one of `cidr`,
`cidrGroupRef`, `cidrGroupSelector` (else `one of cidr, cidrGroupRef, or
cidrGroupSelector is required` / `more than one … may not be set`), plus
`except[]`. Every `except` MUST be contained in `cidr` when `cidr` is given
(`allow CIDR prefix %s does not contain %s`). Compilation:

- `cidr` → requirement `cidr:<prefix> Exists`;
- `cidrGroupRef: <name>` → requirement
  `cidrgroup:io.cilium.policy.cidrgroupname/<name> Exists` (label key
  `LabelPrefixGroupName/<name>`, source `cidrgroup`);
- `cidrGroupSelector` → the selector's requirements with the `cidrgroup:`
  source, matched in **encoded** form (`<key>+<value>` keys, spec 03 §4.1);
- each `except` → requirement `cidr:<except prefix> DoesNotExist`.

`except` is therefore **not** a deny rule: it narrows the selector so that
identities whose `cidr:` label is inside an excepted prefix are not
selected. Because a peer identity carries exactly one `cidr:` label (its
own prefix), an identity for a prefix that *straddles* an `except` (e.g.
`10.0.0.0/8` allowed except `10.1.0.0/16`, peer identity `10.0.0.0/9`) is
**selected** by the selector. This does not permit skipping allocation of the
excepted prefix: the importer MUST allocate both the allow and exception
prefixes and wait for their identity/policy synchronization before publishing
rules. Longest-prefix ipcache lookup then assigns traffic in the exception its
more-specific identity, which the selector excludes (#97). Missing that
allocation would incorrectly let excepted addresses use the covering identity.

Pinned-reference confirmation (`7d68cfb394`):
`pkg/policy/types/selector.go:CIDRSelector.GetCIDRPrefixes` enumerates all
prefix requirements, including exception-only ones; `pkg/policy/cidr.go` unions
them; `pkg/policy/cell/policy_importer.go:updatePrefixes` allocates them before
repository updates and prunes stale prefixes afterward. `flowsdn-policy`'s
`CidrRule` and `PrefixUpdate` implement the validated planning sets, not the
ipcache publication barrier itself. These library types currently require a
base prefix: a selector containing only exception requirements still needs an
importer planning path. That implementation gap does not relax the requirement
to allocate its exception prefixes before publication.

A CIDR selector matches an identity only if that identity is *eligible*:
it has a world label; or it is a node identity and
`policy-cidr-match-mode` contains `nodes`; or it is neither world nor node
and the mode contains `pods`. With `pods` mode, a requirement on
`reserved:world`/`world-ipv4`/`world-ipv6` is also satisfied by any identity
carrying a `cidr:` label of the matching family (so `toEntities: [world]`
keeps working for pods that inherited CIDR labels).

The CIDR prefixes referenced by every entry of a resource are inserted into
the ipcache under that resource id with the policy's source (spec 03 §3.7
"policy importer" row) **before** the repository is updated, and removed
after the rules referencing them are gone (§3.7.1). Prefix insertion from
`toServices` uses the generated CIDR rules of §3.2.5.

#### 3.2.5 `toServices`

`toServices[]` items are `k8sService { serviceName, namespace? }` or
`k8sServiceSelector { selector: LabelSelector, namespace? }` (empty
namespace = any). Resolution happens in the CNP watcher against the
load-balancer service and backend tables (spec LB), producing a *translated*
rule before it is compiled:

- for each Service whose name or labels match: if the Service has a pod
  `selector`, append to `toEndpoints` a **generated** endpoint selector
  `k8s:<selector labels>, k8s:io.kubernetes.pod.namespace=<svc namespace>`
  (so traffic to the backends is allowed by identity, and the usual
  namespace/cluster injection of §3.2.9 applies);
- otherwise (selector-less Service: headless without selector, or
  ExternalName/manual Endpoints), append to `toCIDRSet` one **generated**
  `CIDRRule { cidr: <backend address>/32|/128 }` per *preferred* backend
  address (the LB spec's `PreferredBackendsByAddress` set);
- the watcher indexes which CNPs reference which Service and re-translates
  and re-imports the CNP whenever a matching Service's labels, selector or
  backend set changes (changes are debounced at 50 ms), or when a Service
  that previously matched stops matching.

Generated selectors/CIDR rules are flagged `Generated` so they are not
rendered back to the user in `GET /policy` differently from the reference
(the flag is JSON-hidden). ClusterMesh global services: only backends present
in the local LB tables are used; the reference behaves the same (inventory 05
open question resolved by observation of `ResolveToServices`).

#### 3.2.6 L4 and the L7 handoff

`toPorts[]` (`PortRule`) — up to **40** `ports[]` entries per rule
(`too many ports, the max is 40`): `{ port: string, endPort?: int32,
protocol?: TCP|UDP|SCTP|ICMP|ICMPv6|ANY }`. `port` is a decimal number
(0..65535) or an IANA service **name** (named port, resolved per endpoint /
per peer identity, §3.7.5); `port` empty or `"0"` with `protocol` means "all
ports of that protocol" (`0/ANY` = everything). `endPort` ≥ `port` defines a
range; ranges are not allowed with DNS rules (`DNS rules do not support port
ranges`) nor with named ports. Protocol defaults to `TCP` when omitted in
KNP; in CNP an omitted protocol means `ANY`.

**Validation decision #98:** an explicit `endPort` together with numeric
`port: "0"` MUST be rejected, including an explicit zero or 65535 end. Port
zero without `endPort` remains the wildcard. The low-level map ABI still
encodes zero-based masked blocks correctly; rejecting ambiguous API ranges
prevents the reference's zero-start wildcard bug entering the importer.

`PortRule` also carries the L7 handoff, which this spec only classifies:

| Present | Parser type | Default listener priority | Redirect target |
|---|---|---|---|
| none | none | 0 (no redirect) | — |
| `terminatingTLS` / `originatingTLS` / `serverNames[]` | `tls` | 116 | Envoy |
| `rules.dns[]` | `dns` | 121 | the agent's DNS proxy |
| `rules.http[]` (TCP only) | `http` | 101 | Envoy |
| `listener { envoyConfig{kind,name}, name, priority }` | `crd` | 126, or `listener.priority` if non-zero | Envoy (CEC listener) |

Validation: exactly one of `rules.http`, `rules.dns` may be set (`multiple L7
protocol rule types specified in single rule`); DNS rules need a port
(`port 53 must be specified for DNS rules`) and are not allowed on ingress
(`DNS rules are not allowed on ingress`); L7 rules other than DNS require TCP
(`L7 rules can only apply to TCP (not %s) except for DNS rules`); L7 rules
with port `0` are rejected (`L7 rules can not be used when a port is 0`);
`listener` is not allowed on ingress nor together with `rules`; `serverNames`
require TLS termination when L7 rules are present; empty server names are
rejected; any L7 rule when `enable-l7-proxy` is false is rejected (`L7
policy is not supported since L7 proxy is not enabled`); L7 on host ingress
(`nodeSelector`) is rejected (`L7 policy is not supported on host ingress
yet`). Only HTTP and DNS exist as parsers at 1.20 (Kafka is gone); the
listener names use `ResourceQualifiedName(namespace, cecName,
listenerName)` — a CNP referencing kind `CiliumEnvoyConfig` resolves in the
policy's namespace, `CiliumClusterwideEnvoyConfig` cluster-wide, and a CCNP
naming a namespaced `CiliumEnvoyConfig` is rejected at compile time.

Parser types merge when two rules meet at the same port/protocol/peer
(§5.11): `none` promotes to anything; `tls` promotes to `http` (not to
`dns`/`crd`, never demotes); any other pair conflicts.

Deny rules (`PortDenyRule`) carry `ports[]` only.

`icmps[]` (`ICMPRule { fields[] { family?: IPv4|IPv6, type: int|name } }`, up
to **40** fields) requires `enable-icmp-rules` and MUST NOT be combined with
`toPorts` in the same element. Each field becomes a port rule with protocol
`ICMP` (family absent or `IPv4`) or `ICMPv6`, and `port` = the ICMP type
number; the name tables (IPv4: `EchoReply 0, DestinationUnreachable 3,
Redirect 5, Echo/EchoRequest 8, RouterAdvertisement 9, RouterSelection 10,
TimeExceeded 11, ParameterProblem 12, Timestamp 13, TimestampReply 14,
Photuris 40, ExtendedEchoRequest 42, ExtendedEchoReply 43`; IPv6:
`DestinationUnreachable 1, PacketTooBig 2, TimeExceeded 3, ParameterProblem
4, EchoRequest 128, EchoReply 129, MulticastListenerQuery 130,
…Report 131, …Done 132, RouterSolicitation 133, RouterAdvertisement 134,
NeighborSolicitation 135, NeighborAdvertisement 136, RedirectMessage 137,
RouterRenumbering 138, ICMPNodeInformationQuery 139, …Response 140,
InverseNeighborDiscoverySolicitation 141, …Advertisement 142,
HomeAgentAddressDiscoveryRequest 144, …Reply 145, MobilePrefixSolicitation
146, …Advertisement 147, DuplicateAddressRequestCodeSuffix 157,
…ConfirmationCodeSuffix 158, ExtendedEchoRequest 160, ExtendedEchoReply
161`) are frozen. The datapath places the type in `dport` when
`enable_icmp_rule` is set (spec 02 §3.10).

#### 3.2.7 Authentication

`authentication { mode: disabled | required | test-always-fail }` on an
allow element. It maps to `AuthType` 0 / 1 (`spire`) / 2 and is carried as
an **explicit** auth requirement (`AuthRequirement = type | 0x80`) on every
map entry the element produces. Entries without an explicit mode may
*derive* one from a broader entry with the same identity (§5.5); the
datapath likewise inherits from an equal-precedence broader entry (spec 02
§3.10). Mutual authentication itself is deprecated in 1.20 and not
implemented (spec 03 §3.6 **DEVIATION**); `required` therefore compiles to
entries with `auth_type = 1` that the datapath drops with
`DROP_POLICY_AUTH_REQUIRED` unless an auth-map entry exists — i.e. the
policy behaves as written even without an authenticator. Two rules for the
same peer/port with different explicit modes fail to compile
(`cannot merge conflicting authentication types`). Pass rules combined with
auth rules selecting the same subject are rejected before import publication
(#93), including combinations spread across KCNP/CNP resources. The candidate
resource replacement is validated together with the surviving subject rules;
rejection leaves the previous rules and revision intact. Emit a clear import
error/status explaining the unsupported Pass/authentication combination instead
of partially enforcing it. The resolved-subject repository primitive implements
this atomic validation; Kubernetes status propagation remains controller work.

#### 3.2.8 `enableDefaultDeny`, `labels`, `description`, `log`

`enableDefaultDeny.{ingress,egress}` default to **true** when
`enable-non-default-deny-policies` is false, and otherwise default to
"true iff the rule has any rule of that direction". An entry with
`DefaultDeny = false` contributes its allows/denies without switching the
subject into default-deny for that direction (§3.6). An allow with L7 rules
in a direction that is *not* default-deny gets a wildcard L7 rule appended
(HTTP: `{}`; DNS: `matchPattern: "*"`) so unmatched L7 traffic is still
allowed through the proxy.

`labels[]` are user labels attached to every entry of the rule (after the
policy labels, sorted); they are what `GET /policy` and Hubble show and
what `cilium-dbg policy delete --labels` (removed) used to key on.
`description` is stored and echoed only. `log.value` is stored on the
entry; the reference's cookie allocator (§5.13) is present but **not wired**
at 1.20.1, so every map entry carries `cookie = 0` and the verdict event's
`cookie` is 0. flowsdn MUST keep cookie zero for the reference-compatible verdict contract (#99).

#### 3.2.9 CRD → rule: namespace and cluster injection (`ParseToCiliumRule`)

Given a CNP in namespace `ns` (empty for CCNP), cluster name `c`
(`cluster-name`, or the any-cluster value when `policy-default-local-cluster`
is false), name and UID, for each `spec`/`specs[i]`:

1. **Subject.** `endpointSelector` keys are re-encoded with source prefix
   `k8s:` unless they already carry a source (`reserved:`, `any:`, `k8s:`,
   …). For a CNP, `k8s:io.kubernetes.pod.namespace=<ns>` is **added**
   (overriding any user value; a differing user value logs a warning).
   `nodeSelector` keys get prefix `node:`; nothing else is added and the
   entry is `Node = true`.
2. **Peers** `fromEndpoints`/`toEndpoints` get, in order:
   - keys re-encoded with `k8s:` as above;
   - if the selector has a `reserved:`-prefixed key: no further change;
   - else if it has no `k8s:io.kubernetes.pod.namespace` / `any:…` key:
     for a CCNP (`ns == ""`) add `k8s:io.kubernetes.pod.namespace Exists`
     unless the **subject** selects `reserved:init` (so `{}` in a CCNP means
     "all pods", not host/world); for a CNP add
     `k8s:io.kubernetes.pod.namespace=<ns>` unless the selector already has
     a `k8s:io.cilium.k8s.namespace.labels.*` (or `any:` variant) key;
   - add `k8s:io.cilium.k8s.policy.cluster=<c>` unless a cluster key is
     present or `c` is the any-cluster value.
3. **`fromNodes`/`toNodes`** selectors are `k8s:`-encoded, then get
   `reserved:remote-node Exists` and the cluster label as in step 2.
4. CIDR, entity, service, FQDN, group lists and `toPorts`/`icmps`/
   `authentication` are copied unchanged.
5. **Labels**: `k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy`
   (or `CiliumClusterwideNetworkPolicy`), `k8s:io.cilium.k8s.policy.name=<name>`,
   `k8s:io.cilium.k8s.policy.namespace=<ns>` (CNP only),
   `k8s:io.cilium.k8s.policy.uid=<uid>`, followed by the user labels with
   missing source set to `unspec`, all sorted.
6. `Sanitize()` runs on the result; a failing rule fails the whole
   resource (nothing from it is imported; the error is logged, counted in
   `cilium_policy_change_total{outcome="fail"}` and reported in CNP status
   by the operator).

Then `RulesToPolicyEntries` produces one entry per ingress / ingressDeny /
egress / egressDeny element with `Tier = Normal (200)`, `Priority = 0`,
verdict by list, `DefaultDeny` from §3.2.8, `L3` per §3.2.1, `L4` = `toPorts`
+ ICMP-derived port rules (deny lists converted to plain port rules).

#### 3.2.10 CIDR groups

`CiliumCIDRGroup` (`cilium.io/v2`, `spec.externalCIDRs[]`) is consumed by the
ipcache writer (spec 03 §3.7); the policy side only compiles
`cidrGroupRef`/`cidrGroupSelector` (§3.2.4). A CNP is not re-imported when a
group changes; the selector cache picks up the new identities.

### 3.3 Kubernetes NetworkPolicy translation

For `NetworkPolicy` in namespace `ns` (`default` if empty), cluster name
`c`:

1. **Subject**: `spec.podSelector` with `k8s:` prefixes plus
   `k8s:io.kubernetes.pod.namespace=<ns>` added to `matchLabels`
   (`matchExpressions` copied).
2. **Ingress**: for each `spec.ingress[i]`: if `from` is non-empty, one entry
   per peer; else one entry with the wildcard peer. If `ports` is non-empty
   every entry of the element gets the same `L4`. Egress symmetric over
   `spec.egress[i]`/`to`.
3. **Peer** (`NetworkPolicyPeer`):
   - `ipBlock` → `CIDRRule { cidr, except[] }` (§3.2.4); nothing else in the
     peer is consulted;
   - otherwise start from `podSelector` (`{}` if absent) and, unless `c` is
     the any-cluster value or the selector already constrains
     `io.cilium.k8s.policy.cluster`, add `io.cilium.k8s.policy.cluster=<c>`;
   - with `namespaceSelector`: rewrite each namespace key `k` to
     `io.cilium.k8s.namespace.labels.<k>` (matchLabels and matchExpressions);
     an empty namespace selector becomes `io.kubernetes.pod.namespace Exists`
     (all namespaces); the final selector is the **AND** of the rewritten
     namespace selector and the pod selector, all keys `k8s:`-prefixed;
   - without `namespaceSelector`: pod selector plus
     `io.kubernetes.pod.namespace=<ns>` (same namespace), `k8s:`-prefixed.
4. **Ports** (`NetworkPolicyPort`): protocol default `TCP` (`UDP`, `SCTP`
   accepted, others rejected); `port` absent → `"0"`; numeric or **named**
   port passed as its string; `endPort` copied. Each port becomes its own
   `PortRule`.
5. **policyTypes / implicit default deny**: if no ingress entry was produced
   and (`Ingress` ∈ `policyTypes` or `Egress` ∉ `policyTypes`), add one
   ingress entry with empty (`nil`) `L3` and `L4` — a default-deny marker
   that allows nothing; if no egress entry was produced and `Egress` ∈
   `policyTypes`, add the egress marker likewise.
6. Every entry: `Tier = Normal`, `Verdict = Allow`, `DefaultDeny = true`,
   `Priority = 0`, labels
   `k8s:io.cilium.k8s.policy.derived-from=NetworkPolicy`, `.name` (the
   `io.cilium.policy-name` / legacy alias annotation overrides the object
   name), `.namespace=<ns>`, `.uid`.

Note the marker entries of step 5 have `L3 == nil`, which §3.7.5 treats as
the **wildcard**; combined with `L4 == nil` it still yields no keys because
the wildcard L3 with no L4 would allow everything — the reference relies on
`resolveL4Policy` producing an L4 filter only when `L4` or `L3` is set.
flowsdn MUST NOT produce an allow for these markers; §9 lists
`TestParseNetworkPolicyDenyAll` and `TestParseNetworkPolicyNoIngress` as the
guards.

### 3.4 ClusterNetworkPolicy (network-policy-api v1alpha2) translation

Gate: `enable-k8s-cluster-network-policy` (default false). Tier:
`spec.tier = Admin` → `Admin (100)`, `Baseline` → `Baseline (250)`.
`basePriority = spec.priority` (0..1000). For `spec.ingress[i]` /
`spec.egress[i]`: `priority = basePriority + i/100` (float; rule order within
the object is a strict sub-priority), `verdict` from `action`: `Accept` →
Allow, `Deny` → Deny, `Pass` → Pass.

`protocols[]` → one `PortRule` each: `TCP|UDP|SCTP { destinationPort { number
| range { start, end } } }` → `{ port: start, endPort: end }`; a bare
`destinationNamedPort: "<name>"` → `{ port: "<name>", protocol: ANY }`.

Peers (`from[]` / `to[]`), one entry per peer:

| Peer | Selector |
|---|---|
| `pods { namespaceSelector, podSelector }` | AND of namespace selector rewritten to `io.cilium.k8s.namespace.labels.<k>` (empty → `io.kubernetes.pod.namespace Exists`) and pod selector; plus cluster label unless present / any-cluster |
| `namespaces` | rewritten namespace selector alone |
| `nodes` (egress only) | requires `enable-node-selector-labels` (else the object is rejected); two selectors: `node:<selector>` + `reserved:host Exists`, and `node:<selector>` + `reserved:remote-node Exists`, each with the cluster label |
| `networks[]` (egress) | one CIDR selector per prefix |
| `domainNames[]` (egress, `Accept` only, requires `enable-l7-proxy`) | one FQDN selector per name: a name starting with `*` becomes `matchPattern` (`*.x` → `**.x`? no: a single leading `*` is doubled to `**` so that `*.example.com` also matches `example.com` — the reference prepends `*` unless the name already starts with `**`); other names are `matchName`. Additionally one **extra allow entry** is emitted for the same priority/tier: peer `k8s-app=kube-dns`, ports `dns` and `dns-tcp` (named), `rules.dns` = the same names, so the DNS proxy sees the lookups |
| absent peer fields | `Accept`: the peer is skipped; `Deny`/`Pass`: the entry becomes a wildcard **Deny** |

An element with no `from`/`to` at all yields one wildcard entry with the
element's verdict. Subject: `spec.subject.namespaces` → rewritten namespace
selector; `spec.subject.pods` → the namespaced-pod selector (no cluster
label). Every entry: `DefaultDeny = false` (KCNP never switches a subject to
default-deny by itself), labels
`k8s:io.cilium.k8s.policy.derived-from=ClusterNetworkPolicy`, `.name`, `.uid`.

`AdminNetworkPolicy` / `BaselineAdminNetworkPolicy` (v1alpha1) are **not**
supported, as in the reference.

### 3.5 Tiers, priorities, verdicts, precedence

#### 3.5.1 Frozen values

| Tier | Value | Source |
|---|---|---|
| `Admin` | 100 | KCNP `tier: Admin` |
| `Normal` | 200 | CNP, CCNP, KNP |
| `Baseline` | 250 | KCNP `tier: Baseline` |
| `DefaultPolicy` | 255 | synthesized rules (§3.6) |

Lower tier value = evaluated first (higher precedence). Within a tier, lower
**priority** (float) = higher precedence; CNP/KNP have priority 0. Verdicts:
`Allow`, `Deny`, `Pass`. A `Pass` verdict means "this tier has no opinion for
the matched traffic; continue with the next tier", and it is only reachable
from KCNP.

#### 3.5.2 Datapath precedence encoding (frozen)

`Precedence` is a `u32` where *higher wins*:

```
precedence = ((LowestPriority - dpPriority) << 8) | byte
LowestPriority = 2^24 - 1 ; dpPriority ∈ 0..LowestPriority (0 = highest)
byte: deny 255 | allow-without-redirect 1 | redirect 2..254 | pass 0
redirect byte: listener priority lp = 0 → 2 ; lp ∈ 1..126 → 255 - lp (254..129)
MaxPrecedence      = 0xFFFF_FFFF  (priority 0, deny)   — lockdown deny, "invalid" entries
MaxAllowPrecedence = 0xFFFF_FF01  (priority 0, allow)  — allow-all when a direction is unenforced
```

`dpPriority` is the *datapath* priority computed in §5.1 from tier and API
priority. Inverse decoding: `Priority = LowestPriority - (p >> 8)`,
`ListenerPriority = 255 - (p & 0xFF)`, `IsDeny = byte == 255`,
`IsPass = byte == 0`. Pass entries are **never written** to the map; their
precedence exists only in userspace to re-rank passed-to entries (§5.6).
Deny normalizes proxy port, listener priority and auth requirement to 0.

#### 3.5.3 Conflict resolution at one key

Between two entries that would occupy the **same map key** `(identity,
direction, proto, port-prefix)`:

1. higher `Precedence` wins;
2. equal precedence is only possible for equal `(tier, priority, verdict
   class)`; two allows merge (L7 rules union, §5.11); two denies are the
   same entry; deny vs allow cannot tie (byte 255 vs ≤ 254);
3. redirect vs plain allow at the same priority: the redirect has a higher
   byte and wins, so L7 visibility always survives a broader plain allow.

Between entries with **different keys** that both match a packet the
datapath decides (spec 02 §3.10): higher precedence; then longer L4 prefix;
then the specific-identity entry over the aggregate/wildcard one. Userspace
builds the map so that the datapath's answer equals "the highest-precedence
matching rule, deny beating allow at equal tier/priority regardless of L4
specificity" — the invariant every algorithm in §5 exists to keep.

#### 3.5.4 Rule ordering

Rules selecting a subject are sorted by `(tier, priority, resource id
string, entry index)`. The resource/index tiebreak MUST be applied so two
agents produce identical datapath priorities for the same set of KCNPs.

### 3.6 Enforcement modes and default rules

Per identity and per direction, the repository decides *enforced?* and
*default-deny?* (`computePolicyEnforcementAndRules`):

| Step | Condition | Result |
|---|---|---|
| 1 | identity has `reserved:host` and `enable-host-firewall` is false | not enforced either direction, no rules |
| 2 | `enable-policy = never` | not enforced, no rules |
| 3 | collect rules whose subject matches (§3.6.1): cluster-scoped rules (`rulesByNamespace[""]`) then rules of the identity's `k8s:io.kubernetes.pod.namespace` | `rulesIngress`, `rulesEgress`; `hasDefaultDeny` per direction if any matching rule has `DefaultDeny`; `hasPass` per direction if any is `Pass` |
| 4 | `enable-policy = always`, or identity has `reserved:init` | both directions enforced and default-deny |
| 5 | otherwise | direction enforced iff it has ≥1 rule |

Then, per enforced direction, synthesized rules are appended at tier
`DefaultPolicy (255)` with priority `last.priority + 1` if the last rule is
already tier 255 else 0, subject = exactly this identity's labels, verdict
and labels (§4.8) as follows:

- not default-deny (only `enableDefaultDeny: false` rules or KCNP) →
  **wildcard allow** (`allow-any-ingress` / `allow-any-egress`);
- default-deny, ingress, subject is not the host identity, and
  `allow-localhost` resolves to `always` (`auto` resolves to `always` at
  startup; `policy` never synthesizes) → allow from `reserved:host`
  (`allow-localhost-ingress`);
- default-deny and `hasPass` → **wildcard deny** (`deny-any-ingress` /
  `deny-any-egress`) so a `Pass` from the last tier lands on an explicit
  verdict instead of the implicit drop (needed because pass re-ranking,
  §5.6, requires a real lower-tier entry).

A direction that is **not enforced** gets five allow-all entries (identity
0 and the four aggregates, spec 03 §4.4) with `MaxAllowPrecedence` and
labels `allow-any-*` (§3.7.5 `allowAllIdentities`); the datapath then never
misses for that direction. Both "unenforced" and "enforced with only
non-default-deny rules" allow everything at L3/L4, but the latter can carry
deny entries and redirects.

#### 3.6.1 Subject matching

A rule with `Node = false` matches an identity through the **subject
selector cache** (a second selector cache holding only subject selectors,
so `GET /policy/subject-selectors` can show them); it never matches the host
identity (1). A rule with `Node = true` matches **only** the host identity
and is evaluated by direct label matching against the host's current label
array (spec 03 §3.9 — host labels change at runtime and are pushed
asynchronously), so `nodeSelector: {}` selects the local node. Remote nodes
are never subjects.

#### 3.6.2 Audit mode

`policy-audit-mode` (global, runtime-mutable) or the per-endpoint option
`PolicyAuditMode=Enabled` sets the endpoint's `policy_audit_mode` datapath
flag; the engine's output is unchanged — the datapath forwards what it would
drop and marks the verdict event `audited` (spec 02 §3.10). flowsdn MUST
expose the option through `PATCH /endpoint/{id}/config` and
`PATCH /config` exactly as spec 00 §2 lists.

#### 3.6.3 Enforcement status for the API

`GET /endpoint/{id}` reports `policy-enabled` ∈ `none`, `ingress`, `egress`,
`both`, and `audit-ingress`, `audit-egress`, `audit-both` when audit mode
is on, derived from the per-direction *enforced* bit above.

#### 3.6.4 Host firewall

With `enable-host-firewall`, the host endpoint (identity 1) is a policy
subject like any other: `nodeSelector` rules (CCNP) select it, KCNP
`subject` never does (subjects are pods/namespaces), and its map is the
host endpoint's `cilium_policy_v3_<host epid>` read by `host_policy`
(spec 02 §3.2, M2). Ingress L7 on host is rejected at validation; egress L7
from the host is compiled like any other redirect. Per-node identities
(`enable-node-selector-labels`) let `fromNodes`/`toNodes` and KCNP `nodes`
select remote nodes by `node:` labels; without it those selectors are
rejected.

### 3.7 Compilation pipeline

```
policy update (entries, resource)                       §3.7.1
   │  ipcache CIDR upsert → WaitForRevision (≤10 s)
   ▼
repository: replace-by-resource, revision += 1          §3.7.1
   │  affected identities = subjects of old ∪ new rules
   ▼
per identity: selector policy                           §3.7.2–§3.7.4
   │  rules → tier priorities → L4 filters per (port,proto[,name]) per tier
   │  peer selectors registered in the selector cache
   ▼
per endpoint: endpoint policy = distill(selector policy, redirects)   §3.7.5
   │  map state (LPM trie of keys → entries) via insertWithChanges
   ▼
endpoint regeneration: policy map add/delete, proxy update            §3.7.6
   ▲
   │  identity add/delete → selector cache → MapChanges → consume     §3.7.7
```

#### 3.7.1 Repository and revision

The repository holds rules indexed by resource id, by key
`(resource, index)`, and by subject namespace (the value of the subject
selector's `io.kubernetes.pod.namespace` equality match, `""` when the
subject has no such match — cluster-wide). It carries an atomic `revision`
starting at 1.

`ReplaceByResource(entries, resource)`:

1. lock; collect the subject identities currently selected by every old rule
   of the resource; delete the old rules (their peer selectors stay
   referenced until step 4);
2. insert the new rules; each registers its subject selector in the subject
   selector cache and its peer selectors in the peer selector cache (so that
   selections are already populated when the rule is first compiled);
   collect their subject identities;
3. `revision += 1`;
4. release the old rules' selectors (after the new ones were added, so a
   selector shared by old and new is never dropped and re-added);
5. return (affected identities, new revision, old rule count).

Updates are applied by one **importer** task in arrival order, batched:
for a batch, first every referenced CIDR prefix is upserted into the
ipcache under the resource id (spec 03 §3.7) and the importer waits for the
ipcache revision (bounded 10 s, skipped during startup, timeout only
warns); then each update is applied to the repository; then prefixes no
longer referenced by any rule of the resource are removed from the ipcache;
then the affected identities' selector policies are recomputed to the new
revision and their endpoints regenerated, while every other endpoint has its
policy revision advanced without regeneration (§3.9). Each update's
`DoneChan`, when present, receives the end revision. A monitor notification
`Policy updated` (rules > 0) or `Policy deleted` is emitted per update
(§4.7). Metrics: `cilium_policy_change_total{source, operation, outcome}`,
`cilium_policy_implementation_delay{source}` from `ProcessingStartTime`.

A `TriggerPolicyUpdates(reason)` (config change, e.g. `enable-policy` or
host firewall toggles) bumps the revision, recomputes every local identity's
policy and regenerates all endpoints.

#### 3.7.2 Selector cache

Two caches (peer, subject) of *cached selectors*, each keyed by the
selector's string key (§4.2) and holding the set of numeric identities it
currently selects, a monotonically increasing `SelectorId`, the set of
*users* (L4 filters / rules), and a `namespace` shortcut: the selector's
required namespaces (from its `io.kubernetes.pod.namespace` `In`/`=` match)
or none. The cache also holds every known identity (`id → labels`) with its
namespace label.

- `AddSelectors(user, selectors)`: for each selector, find by key or create
  and populate by scanning all cached identities (CIDR and FQDN selectors
  scan every identity; label selectors scan only identities of their
  namespaces, or all if no namespace requirement); register the user;
  return the cached selectors. New selections become visible at
  `Commit()` (the repository commits after compiling an identity's policy).
- `RemoveSelectors(selectors, user)`: unregister; the selector is dropped at
  zero users. For FQDN selectors the DNS name manager is notified on first
  add / last remove (`identityNotifier`; DNS spec).
- `UpdateIdentities(added, deleted)` (§5.9) recomputes only selectors whose
  namespace shortcut admits the changed identities (`""` selectors see
  everything), bumps the selector **revision**, and queues user
  notifications `IdentitySelectionUpdated(selector, added, deleted)` +
  `IdentitySelectionCommit(snapshot)` delivered in FIFO order by one task.
  The call returns `mutated = true` when an identity's labels changed in
  place (same number, different labels) — only the host identity does this
  legitimately — and the caller then triggers a full policy recompute
  instead of incremental deltas.
- `GetSelectorSnapshot()` returns an immutable view `(revision, selectorId →
  identities)`; endpoint policies are computed against a snapshot so that
  incremental changes after it are exactly the `MapChanges` accumulated
  since (§3.7.7).
- `CanSkipUpdate(added, deleted)` returns true if all added identities are
  already cached with equal labels and no deleted identity exists — used by
  the ipcache pipeline to avoid useless waits.

The wildcard selector (`{}`) is cached like any other but users skip
enumerating its selections (§3.7.5). The `reserved:none` selector
(`EndpointSelectorNone`) selects nothing and is exempt from merge
conflicts.

#### 3.7.3 Selector policy (per identity)

For identity `I` at repository revision `R`: apply §3.6 to get the enforced
bits and the sorted rule lists; compute tier base priorities (§5.1); then
for each rule in order, for each port rule in its `L4` (or one implicit
"all ports, any protocol" if `L4` is empty), for each `(port, endPort,
protocol)` — with `ANY` protocol expanded to exactly one filter with
protocol 0 — build an **L4 filter** (§4.3) and merge it into the tier's L4
policy map keyed by `(port, endPort, u8proto)` or `(portName, proto)` for
named ports (§5.11). Rules with different tiers never merge (the maps are
per tier). The resulting `SelectorPolicy { revision, ingress: [tier →
L4PolicyMap], egress: …, tierBasePriority[], ingressEnabled, egressEnabled,
features }` is shared by every endpoint with identity `I`, reference
counted, and *attached* to the selector cache so its filters receive
incremental identity updates. Compilation errors (merge conflicts) fail the
identity's policy; the endpoint keeps its previous policy and reports the
error in its status (`policy-revision` stays behind, `cilium-dbg endpoint
get` shows the failure).

Per-identity computation runs on a dedicated worker fed by (a) policy
updates naming affected identities, (b) local-identity-manager add events
(first endpoint with a new identity), (c) full recomputes. Results are
stored in a table keyed by identity (`flowsdn-table`, ADR-0004) with the
revision they were computed at; endpoints wait on the table for their
identity's result at ≥ the desired revision. Removing the last endpoint of an
identity detaches and drops its selector policy.

**Features** (bit set, computed while attaching): `deny`, `redirect`,
`ordered` (any non-zero datapath priority), `auth`, `pass`, `namedPort`.
`precedenceFeatures = deny | redirect | ordered`. The features select which
insertion algorithm the map-state builder runs (§5.4–§5.6); when none is set
the builder may skip all covering/covered scans.

#### 3.7.4 L4 filter to per-selector policies

An L4 filter has one `PerSelectorPolicy` (possibly `nil` = plain allow at
the rule's priority) per cached peer selector. `createL4Filter` sets a
non-nil per-selector policy when any of: an L7 parser applies, the rule has
`authentication`, the verdict is not Allow, or the datapath priority is
non-zero. The per-selector policy carries: parser type, L7 rules
(wildcard-augmented per §3.2.8), TLS contexts (resolved via the secret
manager; a missing secret fails compilation — `TestCreateL4FilterMissingSecret`),
server names, listener name and priority, datapath priority, verdict,
authentication. `IsRedirect() = parser != none`. Its **precedence** is
`Priority.ToPrecedence(deny, redirect, listenerPriority)` (§3.5.2).

#### 3.7.5 Endpoint policy and map state

`DistillPolicy(selectorPolicy, owner, redirects)` builds the endpoint's
**map state** (§4.4) from a selector snapshot taken under the cache's read
lock, registering the endpoint policy as a user of the selector policy
*before* the lock is released so no incremental change is lost or
duplicated:

1. if a direction is not enforced: insert the five allow-all keys (identity
   0, 14, 13, 11, 12; proto 0; port 0) with `MaxAllowPrecedence` for that
   direction;
2. for each direction, for each tier in ascending order (Admin first), with
   `tierPriority = tierBasePriority[tier]` and `nextTierPriority =
   tierBasePriority[tier+1]` (or `LowestPriority` for the last tier), for
   each L4 filter → `toMapState`:
   - **port**: `filter.port`; if 0 and the filter has a `portName`: ingress →
     resolve against the endpoint's own named ports (`GetIngressNamedPort`;
     unresolvable → the filter yields nothing); egress → resolve per peer
     identity through the named-port map fed by the ipcache (spec 03 §3.10),
     one key per `(identity, resolved port)`;
   - **keys**: `KeyForDirection(dir).WithPortProto(proto, port)`; a range
     `(port, endPort)` expands to one key per masked port of §5.2 with the
     corresponding prefix length; a single port has prefix 16; port 0 has
     prefix 0; proto 0 implies port 0;
   - for each `(cachedSelector, perSelectorPolicy)`:
     - skip a non-wildcard selector when the filter also has the wildcard
       selector with a *datapath-equivalent* policy (same precedence,
       parser, listener, auth requirement) and the port is not the
       wildcard port (`selectorCoveredByWildcard`) — the L4-only key already
       covers it;
     - identities = the selector's selections in the snapshot; for the
       **wildcard** selector the identities are exactly `AllAggregates =
       {0, 14, 13, 11, 12}` — never an enumeration;
     - **entry** (`makeMapStateEntry`): if the policy is a redirect, look up
       the proxy port by proxy id (§4.3) in `redirects`; a missing port
       yields an *invalid* entry that is skipped (the endpoint creates the
       redirect and distills again — §3.7.6); otherwise
       `newMapStateEntry(priority, tierPriority, nextTierPriority, origin,
       proxyPort, listenerPriority, verdict, authRequirement)`: Pass →
       pass-metadata entry (§5.6), else `NewMapStateEntry` (§3.5.2, deny
       normalizes redirect/auth to 0);
     - for each identity, for each key: `insertWithChanges(tierMaxPrecedence
       = tierPriority.ToDenyPrecedence(), key.with(identity), entry,
       features)` (§5.4).

L3-only rules (no `L4`) produce keys with proto 0 / port 0 for each peer
identity; L4-only rules (wildcard peer) produce the five aggregate keys with
the port; L3+L4 rules produce per-identity port keys. The result is an
`EndpointPolicy { selectorPolicy, snapshot, mapState, mapChanges, redirects }`.

#### 3.7.6 Realizing an endpoint policy (contract with the agent core spec)

Regeneration with a new policy: (1) obtain the selector policy for the
endpoint's identity at ≥ desired revision (§3.7.3); (2) create every
redirect the policy needs (`RedirectFilters()` → proxy ports, keyed by
proxy id); (3) distill; (4) push the network policy to Envoy / DNS proxy and
wait for the ACK when there are listeners; (5) write the BPF map (§5.10,
full sync of desired vs realized); (6) publish the realized policy and set
the endpoint's `policyRevision`. Because redirects are created before the
distill, a distill never sees an "unrealized redirect" except in the
incremental path, where it is retried at the next regeneration. Proxy ids
and the `Redirects` map are constant for the lifetime of one
`EndpointPolicy`; a redirect appearing later forces a new policy.

#### 3.7.7 Incremental updates on identity churn

When identities are added or deleted (ipcache pipeline, CRD watcher, local
allocation — spec 03 §3.3/3.4/3.8):

1. `UpdateIdentities(added, deleted)` on the peer selector cache (and the
   subject cache); users (L4 filters) receive per-selector deltas and
   accumulate **map changes** on every endpoint policy attached to their
   selector policy: for each selector that changed and each key of the
   filter (§3.7.5 key rules; wildcard selectors without a named port are
   skipped), `(add|delete, tier, tierMaxPrecedence, key.with(identity),
   entry)`; egress named ports accumulate identity-wide deletes
   (`AccumulateMapDeletesByID`) since the concrete ports of a gone identity
   are no longer known;
2. `IdentitySelectionCommit(snapshot)` moves the accumulated changes to the
   *synced* set together with the snapshot, discarding changes whose
   snapshot is not newer than the endpoint policy's first revision (they
   are already reflected in the distilled state);
3. the identity updater then asks every endpoint to `ApplyPolicyMapChanges`:
   `ConsumeMapChanges` sorts synced changes by tier ascending and applies
   each through `insertWithChanges` (adds) or `deleteIdWithChanges` (delete
   every key of that identity; when no identity index exists, delete that
   key), producing `ChangeState { adds, deletes, old }`; the endpoint writes
   the adds and deletes to the BPF map (§5.10) and re-pushes the Envoy
   policy when it has Envoy redirects, is an ingress endpoint, or
   `enable-envoy-config` is set;
4. completion is reported back through wait groups; the ipcache pipeline
   MUST NOT write a new prefix into `cilium_ipcache_v2` before the adds have
   reached every policy map, and MUST remove identities from policy maps
   only after the map no longer references them (spec 03 §3.8 steps 4–5).
   The updater batches concurrent requests and bounds the wait per batch
   with `endpoint-policy-update-timeout` (10 s; timeouts are logged and
   counted, not fatal).

**Egress named-port deviation (#96):** selector changes that remove contributions
for an identity MUST recompute that identity's named-port keys from every surviving
selector and the committed named-port snapshot before producing the changeset.
Do not blindly delete a shared key and wait for a later full distill to restore
it. The `NamedPortState` library implements selector-owned resolved contributions
and atomically computes upserts/deletes, including restoration of a shadowed
lower-precedence contribution. Full mapstate values, named-port resolution and
kernel writes still belong to the endpoint policy compiler/controller.

A **mutated** identity (labels changed under the same number) bypasses
incremental deltas: the updater triggers a full recompute of all identity
policies and regeneration of all endpoints (only the host identity does
this in practice).

Incremental delete correctness relies on three facts the reference states
and flowsdn MUST keep: (a) a covering key has the same identity as the
covered one or an aggregate identity; (b) only specific-identity keys are
ever added or deleted incrementally (aggregate keys exist only from the full
distill); (c) identity deletion removes every key of that identity in one
transaction. Hence a key bailed or deleted because of a covering key never
needs reinstating when the covering key goes away.

#### 3.7.8 Policy map size and overflow

Each endpoint map holds `bpf-policy-map-max` entries (default 16384,
clamped to 256..65536). The endpoint tracks *desired* (map state) and
*realized* (last successful sync) states and a pressure gauge
`desired.len / max`. Emit an alarm when `desired.len / max >= 0.9`, including
before overflow; compute the boundary exactly as `ceil(9 * max / 10)` (#102).
Keep `enable-endpoint-lockdown-on-policy-overflow=false` for configuration
compatibility. This does not imply that missing denies are safe: report failed
application as degraded/incomplete, retain retries, and retain the pre-1.0
security review. `flowsdn-policy::pressure` computes the alarm/overflow/action
plan; it does not install lockdown keys or emit runtime metrics. On apply:

- if `enable-endpoint-lockdown-on-policy-overflow` is set and
  `desired.len > max`: **lockdown** — delete every existing entry and
  install the ten *all-traffic* deny keys (identity 0 and the four
  aggregates × ingress/egress, proto 0, port 0) with `MaxPrecedence`;
  realized state is reset; the endpoint reports `ErrPolicyEntryMaxExceeded`
  until a later policy fits, at which point a full recompute is forced
  (`ErrComingOutOfLockdown`). Adds are performed only after enough deletes
  freed space (the reference adds the deny keys after deleting as many
  entries as there are deny keys);
- otherwise adds are attempted first and deletes second ("add before
  delete" avoids transient drops); if `realized.len + adds > max`, deletes
  go first and a warning notes a possible transient drop; failed adds
  (`E2BIG`/`ENOSPC`) are counted, the endpoint's status records
  `ErrPolicyEntryMaxExceeded`, and the `sync-policymap-<epid>` controller
  retries a full desired-vs-dumped reconciliation every
  `bpf-policy-map-full-reconciliation-interval` (15 m) and on demand. A deny
  key that could not be inserted means **fail-open** for the traffic it
  should have denied; an allow key that could not be inserted means
  fail-closed. This asymmetry is why lockdown exists.

### 3.8 Datapath contract (normative summary; spec 02 §3.10 / §5.2 govern)

For a NEW connection with remote identity `r`, direction `d`, protocol `p`,
destination port `q` (ICMP type in `q` when `enable_icmp_rule`), the
datapath performs at most three LPM lookups on the endpoint's map with the
full 64-bit prefix `(r, d, p, q)`, then `(aggregate_for(r), d, p, q)` if `r`
is not its own aggregate, then `(0, d, p, q)` if both missed and the
aggregate was not 0. A specific hit with `precedence == MaxPrecedence` ends
the search (top-priority deny). Between a specific hit `s` and an aggregate
hit `a`, `a` is chosen iff `a.precedence > s.precedence`, or equal precedence
and `a.lpm_prefix_length > s.lpm_prefix_length`; otherwise `s`. No hit →
`DROP_POLICY` (133) (or `DROP_FRAG_NOSUPPORT` for untracked fragments).
Chosen `deny` → `DROP_POLICY_DENY` (181). Otherwise `auth = chosen.auth_type`,
replaced by the other entry's `auth_type` when the other has equal
precedence, the chosen has no explicit auth type, and the other's is
greater; non-zero `auth` without an auth-map entry → `DROP_POLICY_AUTH_REQUIRED`
(189) with `ext_error = auth`. Otherwise ALLOW with `proxy_port` (non-zero =
redirect to that local proxy port). Audit mode turns every drop into ALLOW
with `proxy_port = 0` and `audited = 1`. `policy-verdict` events (type 5)
carry `remote_label = r`, `verdict` (−drop reason, 0, or proxy port),
`dst_port`, `proto`, direction, IPv6, `match_type` (0 none, 1 L3-only,
2 L3/L4, 3 L4-only, 4 all, 5 L3+proto, 6 proto-only, from which entry and
which prefix length was chosen), `audited`, `auth_type`, `cookie`.
Accounting increments `cilium_policystats[{epid, chosen prefix len, r, d, p,
q masked to the chosen prefix}]` when `enable_policy_accounting`.

The engine's obligations toward this: every entry's `lpm_prefix_length`
equals the key's prefix beyond the static 40 bits; port prefixes are only
combined with a fully specified protocol; protocol 0 implies port prefix 0;
`precedence`, `deny`, `auth_type`, `has_explicit_auth_type`, `proxy_port`
and `cookie` are written exactly as §4.4/§4.5 encode them; and the map
never contains a specific-identity entry that is shadowed in a way the two
lookups cannot resolve (that is what §5.4–§5.7 guarantee). The datapath
never sees Pass.

### 3.9 Revision semantics and regeneration triggers

- Repository revision `R` increases by one per resource replacement and per
  forced trigger. Each selector policy records the revision it was computed
  at; each endpoint has `desiredPolicyRevision` (set when told to
  regenerate) and `policyRevision` (set when the datapath reflects it, only
  ever increasing).
- After an import batch `[R0 → R1]`, endpoints whose identity is in the
  affected set are regenerated with reason `policy rules added/removed`;
  every other endpoint gets `SetPolicyRevision(R1)` directly — its map is
  provably unchanged.
- `WaitForPolicyRevision(rev)` (used by `cilium-dbg policy wait`, CNP status
  `localPolicyRevision`, tests) completes when `policyRevision ≥ rev`, or
  the endpoint is deleted, or the context ends.
- Regeneration reasons that recompute policy: policy update, endpoint labels
  / identity change, endpoint init and restore, config change
  (`TriggerPolicyUpdates`), proxy redirect creation, periodic regeneration,
  and coming out of lockdown. Incremental identity updates do **not**
  regenerate.
- `cilium_policy_max_revision` gauge = current `R`; `cilium_policy` gauge =
  number of rules in the repository (entries, not CRDs).

### 3.10 REST API (read-only)

| Path | Returns |
|---|---|
| `GET /policy` | `Policy { revision: int64, policy: string }` where `policy` is the JSON array of all entries (§4.1 JSON form); 404 when the repository is empty (reference behavior); marked deprecated upstream, kept for `cilium-dbg policy get` |
| `GET /policy/selectors` | `SelectorCache = [SelectorIdentityMapping]` for the **peer** cache |
| `GET /policy/subject-selectors` | the same model for the **subject** cache |

`SelectorIdentityMapping { selector: string (cache key), labels:
LabelArrayList (rule labels of every user, deduplicated), identities:
[int], users: int }`. `PUT/DELETE /policy` do not exist at this tag (policy
mutation via REST was removed); flowsdn MUST return 404/405 for them, not
implement them.

## 4. Data model

### 4.1 Policy entry (IR)

| Field | Type | Meaning |
|---|---|---|
| `tier` | `u8` (`Tier`) | 100 / 200 / 250 / 255 |
| `priority` | `f64` | KCNP `spec.priority + i/100`; 0 otherwise; synthesized: last+1 |
| `verdict` | `Allow` / `Deny` / `Pass` | |
| `ingress` | bool | direction |
| `node` | bool | subject is the host (`nodeSelector`) |
| `subject` | `LabelSelector` | compiled endpoint/node selector |
| `l3` | `Vec<Selector>` | `None`/empty → wildcard (`WildcardSelectors`); present-but-empty peer list → empty vec = selects nothing |
| `l4` | `Vec<PortRule>` | including ICMP-derived port rules; empty → all traffic |
| `authentication` | `Option<{ mode }>` | allow only |
| `labels` | `LabelArray` | policy + user labels, sorted |
| `log` | `{ value: String }` | |
| `default_deny` | bool | §3.2.8 |

JSON form for `GET /policy`: the reference marshals the entries as JSON
(`JSONMarshalRules`), field names as in the Go struct (`Tier`, `Priority`,
`Authentication`, `Log`, `Subject`, `L3`, `L4`, `Labels`, `DefaultDeny`,
`Verdict`, `Ingress`, `Node`), selectors rendered as their Kubernetes
`LabelSelector` JSON (label selectors) or as their key string (CIDR/FQDN).
flowsdn MUST emit the same shape (`serde` with `PascalCase`).

`PolicyUpdate { rules: Vec<PolicyEntry>, resource: ResourceId, source:
Source, processing_start: Instant, done: Option<oneshot::Sender<u64>> }`.

### 4.2 Selectors and their keys

| Kind | Key string (cache key) | Requirements | Matches identity when |
|---|---|---|---|
| `LabelSelector` | Kubernetes `LabelSelector.String()` of the source-prefixed selector, e.g. `k8s:app=foo,k8s:io.kubernetes.pod.namespace=ns` (`{}` for the wildcard) | parsed requirements sorted by extended key | all requirements hold on the identity's label array |
| `CIDRSelector` (from `CIDR`) | `cidr:<prefix>` (`CIDR.SelectorKey()`) | `cidr:<enc> Exists` | eligible (§3.2.4) and prefix contains the identity's `cidr:` label |
| `CIDRSelector` (from `CIDRRule`) | `<cidr key | cidrgroup:io.cilium.policy.cidrgroupname/<ref> | group selector string>` + (`-` + comma-joined excepts if any) | as §3.2.4 plus `DoesNotExist` per except | as above, none of the excepts contain the identity's prefix |
| `FQDNSelector` | `MatchName: <n>, MatchPattern: <p>` | the `api.FQDNSelector` | identity carries `fqdn:<matchName or matchPattern>` (the label the DNS name manager attaches, DNS spec) |
| `Groups` (deferred) | `cidrgroup:extgrp.cilium.io/<hash>` | label `cidrgroup:extgrp.cilium.io/<hash>` Exists | operator-derived identities |

Metrics class per selector: `world` (CIDR selectors and the `world` entity
selectors), `cluster` (the `cluster` entity selectors), `fqdn`, `other`.

`SelectorSnapshot { revision: u64, selections: persistent map SelectorId →
sorted identity slice }`. `CachedSelector` API: `selections()`,
`selections_at(snapshot)`, `metadata_labels()` (rule labels of users),
`selects(id)`, `is_wildcard()`, `is_none()`.

### 4.3 Compiled policy

```
SelectorPolicy { revision, ingress: L4DirectionPolicy, egress: L4DirectionPolicy,
                 ingress_enabled, egress_enabled }
L4DirectionPolicy { port_rules: Vec<L4PolicyMap> (index = tier), tier_base_priority: Vec<Priority>, features }
L4PolicyMap { by_port: HashMap<(port u16, end_port u16, proto u8), L4Filter>,
              by_name: HashMap<(port_name, proto), L4Filter> }
L4Filter { tier, port, end_port, port_name, protocol (L4Proto string), u8proto, ingress,
           wildcard: Option<CachedSelector>, per_selector: HashMap<CachedSelector, Option<PerSelectorPolicy>>,
           rule_origin: HashMap<CachedSelector, RuleOrigin> }
PerSelectorPolicy { l7_parser, l7_rules, terminating_tls, originating_tls, server_names, listener,
                    listener_priority: u8, priority: Priority (u32, 24-bit), verdict, authentication }
RuleOrigin = set of (rule labels, log string) — feeds Hubble correlation and equivalence (§5.7)
EndpointPolicy { selector_policy: Arc<SelectorPolicy>, snapshot, map_state, map_changes, owner,
                 redirects: HashMap<ProxyId, u16> }
ProxyId = "<endpoint id>:<ingress|egress>:<PROTOCOL string>:<port>:<listener>"
ProxyStatsKey = "<ingress|egress>:<PROTOCOL>:<port>:<proxy port>"
```

### 4.4 Map state key and entry

Userspace key (`Key`, 8 bytes, host order):

| Field | Type | Meaning |
|---|---|---|
| `bits` | u8 | bit 7 = direction (0 ingress, 1 egress); bits 0..4 = port prefix length 0..16 |
| `nexthdr` | u8 | protocol, 0 = wildcard |
| `dest_port` | u16 | masked port; 0 with prefix 0 = all ports |
| `identity` | u32 | numeric identity; 0/11/12/13/14 = aggregates |

`LPMKey = (bits, nexthdr, dest_port)`; trie prefix length over LPMKey =
1 when `nexthdr == 0`, else `9 + port prefix len` (direction bit first, then
8 protocol bits, then port bits). `Covers(k, c)`: same or wildcard identity,
same or wildcard protocol, equal or broader port. `EndPort() = dest_port +
(0xFFFF >> prefix)`.

Entry (`MapStateEntry`): `precedence u32`, `proxy_port u16` (host order),
`auth_requirement u8` (bit 7 explicit, bits 0..6 type), `cookie u32`,
`invalid` (userspace only: pass-only or unrealized-redirect placeholder).
Internal bookkeeping: `passes: Option<Arc<Vec<PassMeta>>>`,
`derived_from: RuleOrigin`.

BPF encoding (layout in spec 01 §4.4; values fixed here):

```
policy_key.prefixlen  = 40 + (nexthdr != 0 || dest_port != 0 ? 8 : 0) + (dest_port != 0 ? port prefix len : 0)   [reference]
policy_key.sec_label  = identity ; egress = direction bit ; protocol = nexthdr ; dport = htons(dest_port)
policy_entry.proxy_port = htons(proxy_port)
policy_entry.flags byte @2: bit0 deny = (precedence & 0xFF == 255); bits1..2 reserved = 0; bits3..7 lpm_prefix_length = prefixlen - 40
policy_entry byte @3: auth_type = auth_requirement & 0x7F ; has_explicit_auth_type = auth_requirement >> 7
policy_entry.precedence = precedence ; cookie = cookie
```

**DEVIATION (encoding of a range whose first masked port is 0).** The
reference derives the key's prefix from `dest_port != 0`, so a port range
starting at 0 (e.g. `0–1023`, one masked port `{0, /6}`) is written with
prefix 48 — *all ports* — while userspace believes it wrote ports 0–1023
(fail-open). flowsdn MUST derive `prefixlen` from the key's port prefix
length field: `40 + (nexthdr != 0 ? 8 + port_prefix_len : 0)`, and MUST
handle the key identically on both sides. At the API import boundary,
§3.2.6 rejects explicit ranges beginning at zero (#98). The lower-level codec
fix remains useful for accurate dumps/restores and internally constructed keys;
it does not authorize accepting a rejected API range.

The `reserved:2` bits (bits 1–2 of the flags byte) were `wildcard_protocol`
and `wildcard_dport` in Cilium 1.16 and are kept zero "for 1.17"
(`bpf/lib/policy.h`). flowsdn MUST write 0 and MUST ignore them on read
(dump/upgrade); reuse is §12 item 9.

**Verification (2026-09-09, issue #13).** Read the declaration in
`bpf/lib/policy.h:71–80` at the pinned reference commit
`7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc`. On the supported
little-endian targets, the flag byte is deny at bit 0, reserved at bits 1–2,
and the five-bit LPM length at bits 3–7; the next byte is the seven-bit auth
type followed by its explicit bit. The Rust ABI encodes these bytes explicitly
and does not reuse the reserved bits. This resolves the inventory ambiguity;
no reference executable code was copied.

Map: `cilium_policy_v3_<epid>` (LPM trie, `bpf-policy-map-max`, NO_PREALLOC,
RDONLY_PROG) and `cilium_policystats` — layouts, pins and sizing in spec 01.

### 4.5 Precedence and pass metadata

`Priority` u32 (24-bit), `Precedence` u32 as §3.5.2; `ListenerPriority` u8
(0..126). `PassMeta { precedence: base(priority) | 0, tier_max_precedence:
tier_base.to_deny(), tier_min_precedence: next_tier_base.to_pass() + 0x100 }`
— `tier_min` is one priority level above the next tier's first level; an
entry `e` is *in the same tier* as a pass iff `tier_min ≤ e.precedence ≤
tier_max`. `passes` holds at most one meta per tier, ascending by
`tier_min_precedence`.

### 4.6 REST models

`Policy { revision: int64, policy: string }`; `SelectorCache:
[SelectorIdentityMapping { selector: string, labels: [[string]], identities:
[int], users: int }]` (§3.10). `LabelArrayList` renders labels as
`source:key=value` strings (spec 03 §4.9).

### 4.7 Monitor notifications

Agent notification types `Policy updated` / `Policy deleted` with payload
`PolicyUpdateNotification { "labels": [string], "revision": u64,
"rule_count": int }` — labels are the union of the update's rule labels
(each `source:key=value`), `rule_count` the number of entries added (update)
or removed (delete).

### 4.8 Synthesized rule labels (frozen strings)

`reserved:io.cilium.policy.derived-from=` + `allow-any-ingress` |
`allow-any-egress` | `allow-localhost-ingress` | `deny-any-ingress` |
`deny-any-egress`. Hubble shows them as the matching "rule" for traffic
allowed/denied by default handling.

## 5. Algorithms

### 5.1 Tier base priorities (`computeTierPriorities` + `resolveL4Policy`)

Input: the subject's rules sorted per §3.5.4. Let `T = tier of last rule`,
`levels[t] = 0`, `passes[t] = 0` for `t ∈ 0..=T`.

1. Walk rules; per tier count `levels[t]` = number of distinct `priority`
   values (≥ 1 when the tier has rules), and `passes[t]` = number of distinct
   priority levels containing at least one `Pass` rule. Rules out of
   `(tier, priority)` order are a bug (`ErrUnorderedTiers`/`ErrUnorderedRules`).
   Round each used tier's `levels[t]` up to a multiple of 10 (churn
   damping: adding a rule rarely shifts other tiers).
2. For `t = T-1 down to 0`: `levels[t] += (passes[t] + 1) × levels[t+1]`,
   then round up to a multiple of 10. (Every pass level needs room for the
   whole next tier to be re-ranked beneath it; unused tiers inherit the
   next tier's size so the arithmetic below is uniform.)
3. If `levels[0] > LowestPriority` → `ErrTooManyPriorityLevels` (the
   identity's policy fails).
4. `base[0] = 0`; for `t = 1..=T`: `base[t] = base[t-1] + levels[t-1] -
   levels[t]`. `passGap[t] = levels[t+1]` (0 for `T`).
5. Assign datapath priorities: `p = base[tier]` at the first rule of each
   tier, `inc = 1`; when the API priority changes within a tier, `p += inc`,
   `inc = 1`; after a `Pass` rule on a tier `< T`, `inc = passGap[tier] + 1`
   (reserve the next tier's whole range right below the pass). Overflow past
   `LowestPriority` → `ErrTooManyPriorityLevels`.

Result: `tierBasePriority[t] = base[t]`, and each rule's `PerSelectorPolicy.priority`.

### 5.2 Port range → masked ports (`PortRangeToMaskedPorts`)

`(start, end)` → list of `(port, mask)`; a key's port prefix length is
`16 − trailing zero bits of mask` (`LeadingZeros16(!mask)`):

```
if start == 0 && (end == 0 || end == 0xFFFF): [(0, 0)]              # all ports
if end <= start:                              [(start, 0xFFFF)]     # single port
common = leading_zeros16(start ^ end); mask = 0xFFFF >> common
if start & mask == 0 && !end & mask == 0:     [(start, 0xFFFF << (16-common))]   # aligned block
middle_bit = 15 - common; middle = 1 << middle_bit
# lower half: from start up to middle-1
b = trailing_zeros16(start | middle); emit (start & (0xFFFF<<b), 0xFFFF<<b)
for b in b+1 .. middle_bit: if start bit b == 0: emit (start + (1<<b)) masked at b
# upper half: from middle to end
b = trailing_zeros16(!end | middle); emit (end masked at b)
for b in b+1 .. middle_bit: if end bit b == 1: emit (end - (1<<b)) masked at b
```

Worst case (1–65535) is 16 keys per identity; `keysForRange(key, port,
endPort)` = `[key]` when `port == 0 || endPort <= port`, else one
`key.WithPortPrefix(port, prefix)` per masked port. Test vectors: §9.

### 5.3 Key iteration primitives on the map state

The map state is `entries: HashMap<Key, Entry>` plus an LPM trie over
`LPMKey` (25-bit space: direction, protocol, port) whose nodes hold the set
of identities present at that exact LPM key, plus an optional `byId` index
(identity → keys) built when incremental deletes by identity are expected.
Iterators used below (all over the trie):

- `CoveringBroaderOrEqualKeys(k)`: ancestors-or-equal LPM keys with identity
  `k.identity` or `aggregate_for(k.identity)`;
- `BroaderOrEqualKeys(k)`: as above, but for an aggregate `k` also every
  specific identity at those LPM keys (order unspecified);
- `CoveredNarrowerOrEqualKeys(k)`: descendants-or-equal LPM keys with the
  same identity; for an aggregate `k` every identity;
- `NarrowerOrEqualKeys(k)`: as above, plus the aggregate identity for a
  specific `k`;
- `CoveringKeysWithSameID(k)` / `SubsetKeysWithSameID(k)`: ancestors /
  descendants, same identity only, in LPM order;
- `LPMAncestors(k)`: ancestors in LPM order (used by the userspace
  `lookup` that mirrors the datapath for tests).

Deletion during descendant iteration MUST be safe (iterators hold enough
state).

### 5.4 `insertWithChanges` (no Pass rules)

Inputs: `tierMax` (the tier's deny precedence at its base priority), `key`,
`entry`, `features`, `changes`.

```
if aggregateIsEquivalent(key, entry): return         # §5.7
if features.pass:  insertWithPasses(...) ; return    # §5.6 (auth+pass rejected at import, #93)
if entry.is_deny():
    for (k, v) in CoveringBroaderOrEqualKeys(key):
        if v.valid && (v.precedence > entry.precedence
                       || v.precedence == entry.precedence && k != key): return   # bail
    for (k, v) in CoveredNarrowerOrEqualKeys(key):
        if v.precedence < entry.precedence
           || v.precedence == entry.precedence && k != key: delete(k, v, changes)
else:
    if features.auth: authPreferredInsert(key, entry, changes); pruneAggregated(key, entry, changes); return
    if features ∩ precedenceFeatures ≠ ∅:
        for (k, v) in CoveringBroaderOrEqualKeys(key):
            if v.valid && v.precedence > entry.precedence: return                   # bail
        for (k, v) in CoveredNarrowerOrEqualKeys(key):
            if v.precedence < entry.precedence: delete(k, v, changes)
pruneAggregated(key, entry, changes)                  # §5.7
add(key, entry, changes)
```

`add` records `changes.adds` and, when overwriting, `changes.old` (unless the
key was added in this same round); `delete` records `changes.deletes` and
`old`. A deny at equal precedence to a *different* covering deny bails and a
covered equal-precedence deny with a different key is deleted: the broader
deny alone is enough, which is how "an L3-only deny beats a narrower allow
at the same tier/priority" and "identical denies collapse" both hold. Allows
at equal precedence are kept side by side (the datapath's LPM/L3 tie-break
picks the intended one) unless one is an aggregate duplicate (§5.7).

### 5.5 `authPreferredInsert` (allow entries when any rule has `authentication`)

```
explicit = entry.auth.is_explicit()
for (k, v) in CoveringKeysWithSameID(key):                  # LPM order, broadest first
    if v.precedence > entry.precedence:
        if v.is_deny() || !explicit: return                  # bail
        entry.proxy_port = v.proxy_port; entry.precedence = v.precedence; break
        # a more specific explicit auth survives under a broader higher-precedence allow,
        # inheriting its redirect and rank
    if !derived && !explicit && k.port_proto != key.port_proto
       && v.auth.is_explicit()
       && v.precedence.allow_precedence() >= entry.precedence.allow_precedence():
        entry.auth = v.auth.as_derived(); derived = true     # inherit from the most specific covering explicit auth
for (k, v) in SubsetKeysWithSameID(key):
    if v.precedence < entry.precedence:
        if v.auth.is_explicit(): v.proxy_port, v.precedence = entry.proxy_port, entry.precedence; keep   # override redirect, keep auth
        else: delete(k, v); continue
    if !propagated && explicit && k.port_proto != key.port_proto:
        if v.is_deny() || v.auth.is_explicit(): propagated = true; continue   # stops at the next explicit boundary
        v.auth = entry.auth.as_derived()                     # propagate downward as derived
add(key, entry)
```

Only *derived* auth types are ever overwritten; explicit ones are never
copied downward as explicit. `allow_precedence()` masks the byte to 1 so a
redirect and a plain allow at the same priority compare equal here.

### 5.6 `insertWithPasses` (any Pass rule in the policy)

Pass entries are inserted **before** any lower-tier entry (tiers are walked
ascending, and incremental changes are sorted by tier), so a pass is always
already present when the entries it passes to arrive.

Inserting a **pass** `P` (exactly one meta, `P.precedence ≤ tierMax`):

1. for `v` in `CoveringBroaderOrEqualKeys(key)`: bail if `v.valid &&
   tierMax ≥ v.precedence > P.precedence` (a same-tier higher-precedence
   allow/deny already decides), or if `v` has a pass meta of the same tier
   with `precedence ≥ P.precedence`;
2. for `(k, v)` in `CoveredNarrowerOrEqualKeys(key)`: `pruneCovered(k, v,
   key, entry, P.precedence)` (below);
3. add the pass entry (an `invalid` map-state entry with `passes = [P]`; it
   is not written to BPF, but it occupies the key in userspace and may later
   be merged with an allow/deny at the same key).

Inserting an **allow/deny** `E` with `agg = aggregate_for(key.identity)`:

1. Scan `BroaderOrEqualKeys(key)`; for each `(k, v)` let `covering =
   key.identity != agg || k.identity == agg` (a specific key is covered by
   same-identity and aggregate keys; an aggregate key is covered only by
   aggregate keys — specific keys found here are *non-covering* siblings):
   - for each pass meta `m` of `v`: if `m.tier_min > E.precedence` (pass from
     a higher tier): if non-covering, remember `l34 += key.with(k.identity)`
     (a new specific key must be created so the pass reaches that identity)
     and skip its other passes; else `passes.collect(m)` (keep the highest
     per tier); else if covering and `m.precedence > E.precedence` (same
     tier, higher pass): **return** (bail);
   - if `v.valid && (v.precedence > E.precedence || E.is_deny() &&
     v.precedence == E.precedence && k != key)`: if covering: bail
     immediately when `v.precedence ≤ tierMax` (same tier), else remember
     `bailPrecedence = max(bailPrecedence, v.precedence)` (a higher tier
     already decided — but a pass could still outrank it); if non-covering
     and `v.precedence ≤ tierMax`: `done += key.with(k.identity)` (that
     sibling must not get an l34 key).
2. `keys = l34 − done` (work queue).
3. `bail = bailPrecedence > 0`. For `(k, v)` in `NarrowerOrEqualKeys(key)`
   with `covering = key.identity == agg || k.identity == key.identity`: if
   `!bail && covering`: `pruneCovered(k, v, key, E, E.precedence)`; and
   `collectNarrowerPasses`: if `v` has a pass with `precedence > tierMax`
   (higher tier) at a narrower key, push `k` (with `key.identity` when `k`
   is the aggregate) onto `keys` unless done — the passed-to entry must also
   exist at that narrower key.
4. If `passes` is non-empty: `prec = E.inherit(passes)` where
   `inherit = E.precedence − Σ m.tier_min + Σ m.precedence` (relocates `E`
   into the level band right below each covering pass, preserving its low
   byte); if `prec > bailPrecedence`: prune `CoveredNarrowerOrEqualKeys(key)`
   at `prec`, add `E` with `precedence = prec`, `bail = true`.
5. If `!bail`: add `E` unchanged.
6. For each `key'` popped from `keys` (may grow while iterating): reset
   `passes`, `bailPrecedence`, `l34`; rescan `BroaderOrEqualKeys(key')` as in
   step 1 except that same-tier covering bails only record
   `bailPrecedence` when above `tierMax`; enqueue new `l34 − done`; compute
   `prec = E.inherit(passes)`; if `prec > bailPrecedence`: prune covered keys
   at `prec` and add `E` at `key'` with `precedence = prec`. (These keys
   would be trivially covered by the main key without their passes, so they
   are added only with an inherited precedence.)

`pruneCovered(k, v, key, entry, prec)`: drop from `v` every pass meta that is
same-tier-and-lower-or-equal than `prec` (`Delete`); the allow/deny part is
removed if `!v.valid`, or `v.precedence < prec`, or `v.is_deny() &&
v.precedence == prec && k != key`, or (`k.lpm == key.lpm` and
`aggregates(key.identity, k.identity)` and `v.equivalent(entry)`). If both
parts go, delete the key; if one goes, update in place (`invalidate()` for
the verdict part, new `passes` slice for the metadata part — the slice may
be shared and MUST be cloned before mutation).

`PassMetas::collect` keeps one meta per tier (higher precedence wins);
`merge` unions two lists with the same rule; `is_different_tier_or_higher(p)`
= `!(tier_min ≤ p ≤ tier_max) || precedence > p`.

### 5.7 Aggregate deduplication

- `aggregateIsEquivalent(key, entry)`: if `key.identity` is not itself an
  aggregate and an entry exists at `key.with(aggregate_for(identity))` that
  is *equivalent*, skip the insert.
- `pruneAggregated(key, entry)`: if `key.identity` is an aggregate, for every
  identity present at exactly `key.lpm` that `aggregate_for` maps to
  `key.identity`, delete its entry when equivalent to `entry`.
- **Equivalent** = identical `MapStateEntry` (precedence, proxy port, auth
  requirement, cookie, invalid), identical pass metadata, and identical
  rule-origin **log string** (so two rules differing only in `log.value`
  keep separate entries — they will produce different cookies once §12
  item 8 lands).

Only entries at the *same prefix length* are pruned: an entry between the
aggregate and the specific one in the LPM order could otherwise change the
answer.

### 5.8 Wildcard expansion and L4-only coverage

Wildcard selector → identities `{0, 14, 13, 11, 12}` (the datapath falls
from specific → aggregate → 0). Specific selectors whose per-selector policy
is datapath-equivalent to the wildcard's are skipped when the port is
specific (§3.7.5); with the wildcard port (L3-only) they are kept because the
L3-only key has a different LPM prefix (the datapath prefers the
longer-prefix aggregate key otherwise). Entities that map to aggregate
selectors (`world`, `remote-node`, `cluster`, `cluster-mesh`) produce
aggregate keys plus the reserved singletons (`host`, `init`, …) — never one
key per pod.

### 5.9 Identity update propagation (`UpdateIdentities`)

```
lock; next_rev = rev + 1
namespaces = {"" : []}
for id in deleted: if cached: namespaces[cached.ns] |= {}; remove from cache; else warn & drop from `deleted`
for (id, labels) in added:
    if cached with equal labels: drop from `added`; continue
    if cached (labels differ): mutated = true (debug for host id 1, warn otherwise)
    cache.insert(id, labels); ns = labels[k8s:io.kubernetes.pod.namespace]
    namespaces[ns] += id ; if ns != "": namespaces[""] += id
for (ns, ns_added) in namespaces: for sel in selectors.by_namespace(ns):
    updated |= sel.update_selections(ns_added, deleted, wg)   # queue user notifications per selector
if updated: snapshot = commit(); queue_commit_notification(snapshot, wg)
return mutated
```

`by_namespace("")` yields selectors without a namespace requirement (they
see identities of every namespace), `by_namespace(ns)` selectors requiring
`ns`. A selector requiring several namespaces (`In`) is indexed under each.
The wait group completes when every notified user has accumulated its map
changes; the identity updater then batches `UpdatePolicyMaps` across
endpoints and closes the batch's done channel, which the ipcache pipeline
awaits (spec 03 §3.8 step 4). Metrics: `cilium_policy_selector_cache_operation_duration_seconds{operation=identity_updates, scope=lock|operation}`.

### 5.10 Policy map apply and full reconciliation

Incremental (`ApplyPolicyMapChanges`): §3.7.8 ordering; each add is
`Update(key, entry)`, each delete `DeleteKey(key)` where a delete of a key
also present in `adds` is skipped; `ENOENT` on delete is not an error; other
errors are counted and the whole apply reports failure (retried by the sync
controller). Full sync (new policy or controller): dump the map; for every
key in desired but not realized or with a different value → `Update`; for
every dumped key not in desired → `Delete`; then realized = desired. The
periodic controller (`sync-policymap-<epid>`, every
`bpf-policy-map-full-reconciliation-interval`) compares desired against a
fresh **dump** so external edits (`cilium-dbg bpf policy add/delete`) are
undone. Map pressure gauge updated on every apply; `cilium_bpf_map_pressure`
with `map_name=cilium_policy_v3` is exported when above
`bpf-policy-map-pressure-metrics-threshold` (0.1).

### 5.11 Merging L4 filters (`mergePortProto`)

Two filters for the same `(port, endPort, proto)` (or named port) and tier
merge per cached selector `cs`:

- `cs` absent in the existing filter → move it (change selector user);
  a wildcard selector becomes the filter's `wildcard`;
- `cs` present: release the duplicate selector reference; `reserved:none`
  is never merged (toFQDN placeholders); equal policies → merge rule
  origins only; otherwise compare `priority` (lower wins) then
  `HasPrecedenceOver` (deny beats anything; allow beats pass): the winner
  replaces or is kept; equal rank non-identical **allows** merge:
  `L7Parser.merge` (§3.2.6, conflict → error `cannot merge conflicting L7
  parsers`), redirect/listener merge (`mergeRedirect`: different listeners
  or CRD vs non-CRD → error; listener priority = the more urgent),
  `authentication` (one side nil → take the other; both set and different →
  error), TLS contexts likewise (`cannot merge conflicting terminating /
  originating TLS contexts`), `serverNames` union (SNI + L7 rules without
  TLS termination → error), L7 rules: an empty side is expanded to the
  parser's wildcard rule before union, HTTP/DNS rule lists are unioned
  without duplicates.
- Filters of different tiers never meet (`cannot merge filters with
  different tiers` is an internal error).

A compile error for one identity does not affect other identities.

### 5.12 `toServices` resolution

§3.2.5. Selector matching of `k8sServiceSelector.selector` is a plain label
match against the Service's `metadata.labels` (no source prefixes; keys
compared verbatim, `any:`-style). Namespace filter: `sel.namespace == "" ||
== svc.namespace`. Re-resolution candidates: on a label change every CNP
with `toServices`; otherwise only CNPs indexed for that Service name.

### 5.13 Log cookies (present, unwired)

A per-agent bakery maps `log.value` strings to 32-bit cookies (`cookie =
bitset index + 1`, never 0), with generation-based sweeping of unused values.
At 1.20.1 no caller allocates cookies and every entry has `cookie = 0`.
flowsdn MUST retain cookie zero in the compatibility implementation (#99).
Preserve `log.value` in rule metadata. A nonzero-cookie feature needs an explicit
producer/consumer protocol decision and Hubble resolution before activation;
it is not silently enabled or declared implemented by this choice. The full
log feature remains in scope; there is currently no bakery implementation.

## 6. Configuration

| Key | Type | Default | Effect |
|---|---|---|---|
| `enable-policy` | `default\|always\|never` | `default` | §3.6; runtime-mutable via `TriggerPolicyUpdates` |
| `policy-audit-mode` | bool | false | §3.6.2 (runtime) |
| `policy-accounting` | bool | true | datapath `enable_policy_accounting` |
| `bpf-events-policy-verdict-enabled` | bool | true | verdict events (runtime) |
| `enable-host-firewall` | bool | false | host identity becomes a subject |
| `enable-icmp-rules` | bool | false | `icmps[]` accepted; datapath `enable_icmp_rule` |
| `enable-non-default-deny-policies` | bool | true | `enableDefaultDeny` honored (§3.2.8) |
| `allow-localhost` | `auto\|always\|policy` | `auto` | §3.6 (`auto` → `always`) |
| `enable-cilium-network-policy` | bool | true | CNP watcher |
| `enable-cilium-clusterwide-network-policy` | bool | true | CCNP watcher |
| `enable-k8s-networkpolicy` | bool | true | KNP watcher |
| `enable-k8s-cluster-network-policy` | bool | false | KCNP watcher (§3.4) |
| `enable-node-selector-labels` | bool | false | `fromNodes`/`toNodes`, KCNP `nodes`, per-node identities (spec 03) |
| `policy-cidr-match-mode` | list of `nodes`, `pods` | `[]` | CIDR selector eligibility (§3.2.4) |
| `policy-default-local-cluster` | bool | true | cluster label injection uses `cluster-name`; false → any-cluster |
| `cluster-name` | string | `default` | `cluster` entity, injected label |
| `enable-l7-proxy` | bool | true | L7 rules accepted |
| `bpf-policy-map-max` | int | 16384 | clamped 256..65536, immutable (spec 01) |
| `bpf-policy-stats-map-max` | int | 65536 | clamped 1024..16777216, rounded to CPU multiple (spec 01) |
| `bpf-policy-map-full-reconciliation-interval` | duration | 15m | §5.10 |
| `bpf-policy-map-pressure-metrics-threshold` | float | 0.1 | §5.10 |
| `enable-endpoint-lockdown-on-policy-overflow` | bool | false | §3.7.8 |
| `endpoint-policy-update-timeout` | duration | 10s | §3.7.7 batch wait bound |
| `policy-trigger-interval` | duration | 1s | minimum spacing of full recompute triggers |
| `policy-queue-size` | uint | 100 | importer queue depth (spec 00 `queue` semantics) |
| `policy-deny-response` | `none\|icmp` | `none` | datapath M2 (spec 02) |
| `hubble-network-policy-correlation-enabled` | bool | true | Hubble spec; needs `RuleOrigin` |
| `static-cnp-path` | path | `""` | accepted, **ignored** (deferred) |
| `enable-policy-secrets-sync`, `policy-secrets-namespace`, `policy-secrets-only-from-secrets-namespace` | | | L7 spec (TLS secret resolution) |
| `allow-unsafe-policy-skb-usage` | bool | false | datapath (spec 02) |

`identity-change-grace-period`, `enable-well-known-identities`,
`fixed-identity-mapping` and `labels` filters are spec 03's and affect which
identities the selectors see.

## 7. Failure modes

| Failure | Behavior |
|---|---|
| CRD fails validation (`Sanitize`) | resource not imported; previous rules of the resource **stay** (the reference does not remove them on a failed re-parse); warning log; `cilium_policy_change_total{outcome=fail}`; operator writes CNP status |
| Compile conflict for one identity (L7/TLS/auth merge, too many priority levels) | that identity's endpoints keep their last good policy; endpoint status shows the error; other identities unaffected; retried at the next revision |
| Redirect port allocation fails / proxy not ready | entries needing the redirect are omitted (invalid entries skipped); regeneration retried with backoff; `cilium_policy_missing_proxy_redirects` counts |
| Policy map full without lockdown | adds fail, `ErrPolicyEntryMaxExceeded`, fail-open for missing denies / fail-closed for missing allows; sync controller retries; pressure metric 1.0 |
| Policy map full with lockdown | endpoint drops everything until desired fits (§3.7.8) |
| ipcache revision wait times out (10 s) | warning "may cause policy drops"; import proceeds |
| Identity update batch exceeds `endpoint-policy-update-timeout` | logged, counted; ipcache write proceeds — a new identity may be dropped by default-deny endpoints until their maps catch up |
| API server unavailable | watchers keep last state; no rule churn; identities as spec 03 §7.1 |
| Agent restart | repository rebuilt from informers; endpoints restored with their previous map contents (map pins survive) and regenerated at the new revision; until then the old map enforces (revision 1 special-cases the ipcache wait) |
| Upgrade from the reference | same map name/layout; entries written by 1.20 (`reserved` bits 0, cookie 0) are read back unchanged; a full sync at first regeneration rewrites the map from the flowsdn desired state; §4.4 DEVIATION affects only ranges starting at port 0 |
| Kernel lacks LPM trie with 12-byte keys | fatal at startup (spec 01) |

## 8. Observability

Metrics (reference names):

| Metric | Labels | Meaning |
|---|---|---|
| `cilium_policy` (gauge) | — | entries in the repository |
| `cilium_policy_max_revision` (gauge) | — | repository revision |
| `cilium_policy_change_total` (counter) | `source` (`k8s`, `custom-resource`, `directory`…), `operation` (`add`, `update`, `delete`), `outcome` (`success`, `fail`) | imports |
| `cilium_policy_endpoint_enforcement_status` (gauge) | `enforcement` (`none`, `ingress`, `egress`, `both`) | endpoints per status |
| `cilium_policy_implementation_delay` (histogram) | `source` | receive → datapath |
| `cilium_policy_incremental_update_duration` (histogram) | `scope` | identity-update apply time |
| `cilium_policy_missing_proxy_redirects` (gauge) | — | entries skipped for unrealized redirects |
| `cilium_policy_l7_total` (counter) | `rule`, `proxy_type` | L7 spec |
| `cilium_policy_selector_match_count_max` (gauge) | `class` (`fqdn`, `cluster`, `world`, `other`) | max identities per peer selector |
| `cilium_policy_selector_cache_selectors` / `_identities` (gauge) | `type=peer` | cache sizes |
| `cilium_policy_selector_cache_operation_duration_seconds` (histogram) | `operation` (`add_selector`, `remove_selector`, `identity_updates`), `scope` (`lock`, `operation`), `type` | latency |
| `cilium_endpoint_detached_selector_policy_time_stats_seconds` | `scope` | selector policy lifetime |
| `cilium_bpf_map_pressure` (gauge) | `map_name=cilium_policy_v3` | max over endpoints, above threshold |
| `cilium_bpf_map_ops_total` | `map_name`, `operation`, `outcome` | map writes (spec 01) |
| `cilium_policy_verdict_total`-style counters are Hubble's (Hubble spec) | | |

Monitor: `policy-verdict` events (type 5, datapath); agent notifications
§4.7. Logs: fields `policyRevision`, `resource`, `identity`,
`endpointSelector`, `policyKey`, `policyEntry`, `policyPrecedence`, `version`
(selector snapshot), `addedPolicyID`/`deletedPolicyID`; per-endpoint policy
debug logger enabled by the `Debug`/`DebugPolicy` endpoint options. Health:
the importer and the identity updater report degraded on repeated
timeouts; an endpoint in lockdown reports it in `GET /endpoint/{id}`.
`cilium-dbg` served: `policy get`, `policy selectors`, `policy wait`,
`bpf policy get|list|add|delete` (maps), `endpoint get` (`policy.realized/
spec`, `policy-revision`, `policy-enabled`).

## 9. Test plan

Unit unless marked. Reference test names are the checklist; each MUST have a
Rust counterpart with the same scenario (names may be snake_case).

**Precedence, tiers, pass** (`pkg/policy`): TestComputeTierPriorities,
TestPerSelectorPolicyGetPrecedence, TestOrderedPolicyValidation,
TestMapState_orderedMapStateValidation, TestMapState_passValidation,
TestPassMetasCollect, TestPassMetasMerge, TestMergePortProtoIdenticalPolicyDifferentPriority,
TestMergePortProtoRejectsDifferentTiers, distillery_precedence_test cases.
Add: encode/decode round trip of every `(priority, verdict, listener
priority)` (property test), `inherit` arithmetic with two covering passes.

**Map state** : TestMapState_insertWithChanges, TestMapState_denyPreferredInsertWithSubnets,
TestDenyPreferredInsertLogic, TestMapState_AccumulateMapChanges(_Ordered,
Deny), TestMapState_BroaderOrEqualKeys, TestMapState_CoveredNarrowerOrEqualKeys,
TestMapState_CoveringBroaderOrEqualKeys, TestMapState_CoveringKeysWithSameID,
TestMapState_LPMAncestors, TestMapState_NarrowerOrEqualKeys,
TestMapState_SubsetKeysWithSameID, TestMapStateWithIngress(Deny,
DenyWildcard, Wildcard), TestMapState_Get_stacktrace, TestNamedPortRulesDeleteByID,
TestAllAggregates, TestIsAggregate, TestPolicyKeyTrafficDirection,
TestMustParseKey, TestEndpointPolicy_Lookup_PortRange(_L4Only),
TestEndpointPolicy_AllowsIdentity, TestEndpointPolicy_GetRuleMeta.
Fuzzers: FuzzDenyPreferredInsert, FuzzAccumulateMapChange,
FuzzDistillPolicy, FuzzDistillPolicyWithAggregates, FuzzResolvePolicy, and
the brute-force simulator (`pkg/policy/testutils/simulate.go`,
`simulate_fuzz_test.go`): every generated policy is evaluated by (a) the
map-state builder + a userspace replica of §3.8 and (b) a naive "highest
precedence rule wins, deny beats allow at equal tier/priority" oracle; the
verdicts MUST agree. The 27 seed corpus files under
`pkg/policy/testdata/fuzz/` MUST be imported as regression fixtures (test
vectors, permitted copy per `docs/licensing.md`, with attribution).

**Port ranges**: TestPortRange, TestEgressPortRangePrecedence; vectors:
`(80,80)→[{80,ffff}]`, `(0,65535)→[{0,0}]`, `(1,65535)→16 keys`,
`(1024,2047)→[{1024,fc00}]`, `(0,1023)→[{0,fc00}]` (the §4.4 DEVIATION case).

**L4/L7 merge**: TestCreateL4Filter(AuthRequired, MissingSecret),
TestMergeL4PolicyIngress/Egress, TestMergeL7PolicyIngress/Egress(WithMultipleSelectors),
TestMergeTLSHTTPPolicy, TestMergeTLSSNIPolicy, TestMergeTLSTCPPolicy,
TestMergeListenerPolicy, TestMergeListenerReference, TestParserTypeMerge,
TestRedirectType, TestMergeIdenticalAllowAllL3AndMismatchingParsers,
TestMergingWithDifferentEndpointSelectedDenyAllL7, TestL3L4L7Merge,
TestL4WildcardMerge, Test_MergeRules, Test_MergeRulesWithNamedPorts,
TestDefaultAllowL7Rules, TestHTTPWildcardInDefaultAllow,
TestDNSWildcardInDefaultAllow, TestDNSWildcardWithL3FilterInDefaultAllow,
TestDenyRuleNoWildcardInDefaultAllow, TestProxyID, BenchmarkProxyID.

**Wildcards, entities, shadowing**: TestWildcardL3RulesIngress/Egress(Deny,
FromEntities, ToEntities, DenyFromEntities, DenyToEntities),
TestWildcardL4RulesIngress/Egress(Deny), TestWildcardCIDRRulesEgress(Deny),
TestEgressWildcardCIDRMatchesWorld, TestL3Wildcarding,
TestL3RuleShadowedByL3AllowAll, TestL3RuleWithL7Rule(Partially)ShadowedByL3AllowAll,
TestL3AllowRuleShadowedByL3DenyAll, TestL3DenyRuleShadowedByL3DenyAll,
TestL3L4AllowRuleWithByL3DenyAll, TestL3WithIngressDenyWildcard,
TestL3WithLocalHostWildcardd, TestL7WithIngressWildcard,
TestL7WithLocalHostWildcard, TestIngressAllowAllL4Overlap(NamedPort),
TestIngressAllowAllNamedPort, TestIngressL4AllowAll(NamedPort),
TestEgressL4AllowAll(Entity), TestEgressL3AllowAllEntity, TestEgressL4AllowWorld,
TestEgressCIDRTCPPort, TestEgressNamedPortToMapStateUnion,
TestEgressNamedPortWildcardOptimization, TestGetEgressNamedPorts,
TestICMPPolicy, TestPolicyEntityValidationIngress/Egress/EntitySelectorsFill,
Test_EnsureEntitiesSelectableByCIDR, TestGetCIDRPrefixes, TestMergeDenyAllL3,
TestMinikubeGettingStartedDeny, TestL3Policy, TestL4Policy, TestL3RuleLabels,
TestL4RuleLabels, TestRuleLog, TestRuleOrigin, TestOriginMerge,
TestRuleWithNoEndpointSelector, TestEgressRuleRestrictions.

**Repository / enforcement**: TestComputePolicyEnforcementAndRules,
TestComputePolicyDenyEnforcementAndRules, TestRepositorySnapshot,
TestRegenerateCIDRDenyPolicyRules, Benchmark{Regenerate,Resolve}*.

**Selector cache**: TestAddRemoveSelector, TestIdentityUpdates,
TestIdentityUpdatesMultipleUsers, TestMultipleIdentitySelectors,
TestSelectorCacheCanSkipUpdate, TestSelectorManagerCanGetBeforeSet,
Test_IncrementalFQDNDeletion, BenchmarkSelectorCacheIdentityUpdates;
`pkg/policy/types`: TestCIDRRuleToCIDRSelectors, TestLabelSelectorToRequirements,
BenchmarkMatches*. Add: namespace-index correctness (a selector with
`In [a,b]` sees identities of both), host identity mutation → `mutated`.

**API validation** (`pkg/policy/api`): TestEndpointSelectorSanitize,
TestInvalidEndpointSelectors, TestEndpointSelectorMarshalling,
TestRuleMarshalling, TestRulesDeepEqual, TestSanitizeDefaultDeny,
TestTooManyPortsRule, TestTooManyICMPFields, TestWrongICMPFieldFamily,
TestICMPRuleWithOtherRuleFailed, TestICMPFieldUnmarshal,
TestPortRangesNotAllowedWithDNSRules, TestPortRuleDNSSanitize,
TestL7RuleRejectsEmptyPort, TestL7RulesWithNonTCPProtocols,
TestL7RulesWithNodeSelector, TestPrivilegedNodeSelector, TestCIDRsanitize,
TestCIDRRegex, TestFQDNSelectorSanitize, TestHTTPRuleRegexes,
TestToServicesSanitize, TestParseL4Proto, TestValidateL4Proto,
TestInvalidIPProtocolRules, TestParseQualifiedName,
TestIngress/EgressCommonRuleDeepEqual/Marshalling.

**Kubernetes translation** (`pkg/k8s`): TestParseNetworkPolicy,
TestParseNetworkPolicyClusterLabel, TestParseNetworkPolicyDenyAll,
TestParseNetworkPolicyEgress, TestParseNetworkPolicyEgressAllowAll,
TestParseNetworkPolicyEgressL4AllowAll, TestParseNetworkPolicyEgressL4PortRangeAllowAll,
TestParseNetworkPolicyEmptyFrom, TestParseNetworkPolicyEmptyPort,
TestParseNetworkPolicyIngressAllowAll, TestParseNetworkPolicyIngressL4AllowAll,
TestParseNetworkPolicyMultipleSelectors, TestParseNetworkPolicyNamedPort,
TestParseNetworkPolicyNoIngress, TestParseNetworkPolicyNoSelectors,
TestParseNetworkPolicyUnknownProto, TestParsePorts, TestIPBlockToCIDRRule,
Test_parseNetworkPolicyPeer, TestGetPolicyLabelsv1, TestNetworkPolicyExamples,
TestCIDRPolicyExamples, TestParseClusterNetworkPolicy,
TestToSlimLabelSelectorMatchExpressionsValues, Test_TransformToCNP/CCNP,
Test_EqualV2CNP; `pkg/policy/k8s`: TestPolicyWatcher_updateToServicesPolicies(TransformToEndpoint),
Test_hasMatchingToServices, TestServiceEventStream, TestCIDRGroupDuplicateLabelKeys;
`pkg/k8s/apis/cilium.io/utils` ParseToCiliumRule cases (namespace injection,
CCNP `Exists`, `reserved:init` exemption, cluster label).

**Integration** (replaces the `.txtar` scripts `test.txtar`,
`kube-apiserver-allow.txtar`, `kube-apiserver-deny.txtar`,
`kube-apiserver-duplicate-delete.txtar`, `shared-identity-teardown.txtar`,
and `pkg/policy/cell` TestAddReplaceRemoveRule, `pkg/policy/compute`
TestRecomputeIdentityPolicy, TestIdentityManagerObserver,
TestGetAuthTypesAndSnapshot): import/replace/remove by resource with revision
propagation to unaffected endpoints; kube-apiserver identity 7 allow and
deny; duplicate delete idempotence; last endpoint of an identity tears down
the shared selector policy; identity add → policy maps before ipcache;
lockdown enter/exit.

**Privileged** (`pkg/maps/policymap`): TestPrivilegedPolicyMapDumpToSlice,
TestPrivilegedDenyPolicyMapDumpToSlice, TestPrivilegedStatMap,
TestPolicyMapWildcarding, TestNewEntryFromPolicyEntry,
TestPolicyEntriesDump_Less; plus a BPF-harness test that the two-stage lookup
(spec 02 §3.10) agrees with the userspace `lookup` replica on the fuzz
corpus.

**Correlation** (`pkg/policy/correlation`): TestCorrelatePolicy(_PortRange,
Audit, ImplicitDeny) — Hubble spec, but they exercise `RuleOrigin`.

**E2E**: cyclonus KNP conformance (`conformance-k8s-network-policies`),
`conformance-l3-l4`, `conformance-l7`, cilium-cli connectivity policy/deny/
host-firewall/FQDN/CIDR-group suites; network-policy-api KCNP conformance
when the gate is on.

## 10. Kernel and platform requirements

Userspace crate except for map writes: `BPF_MAP_TYPE_LPM_TRIE` with 12-byte
keys and `BPF_F_NO_PREALLOC`/`BPF_F_RDONLY_PROG` (spec 01; kernel ≥ 4.11 for
LPM, flowsdn floor 6.6), `BPF_MAP_TYPE_LRU_PERCPU_HASH` for stats, batch
lookup/dump for reconciliation (falls back to iteration). Endianness: key
`dport` and entry `proxy_port` are big-endian in the map, `precedence`,
`sec_label`, `cookie` host-endian u32 — both arches little-endian, no
arch-specific behavior. No netlink, no modules.

## 11. Rust design notes

Crates (building on spec 03's `flowsdn-labels`, `flowsdn-identity`,
`flowsdn-ipcache`):

- **`flowsdn-policy-api`**: serde types for `Rule`, `IngressRule`,
  `EgressRule`, deny variants, `PortRule`, `L7Rules` (`http`, `dns` — the
  parsing of their contents lives in the L7 crate; here they are opaque
  values with `Eq`/`Hash`), `CIDRRule`, `FQDNSelector`, `ICMPRule`,
  `Service`, `Groups`, `EndpointSelector` (wrapping
  `k8s_openapi::LabelSelector`-shaped type with a cached key string),
  `Entity` enum with the frozen table, `Sanitize` (all §3.2 error strings
  verbatim), `ParseToCiliumRule` (namespace/cluster injection), the KNP and
  KCNP translators (`kube` typed structs for `networking.k8s.io/v1` and a
  local definition of `policy.networking.k8s.io/v1alpha2` — the upstream Go
  types are Apache-2.0 and may be copied as schema with attribution), and
  `rules_to_policy_entries`. `schemars` for the CRD OpenAPI schema (CRD
  spec). `Option<Vec<_>>` everywhere a nil/empty distinction is observable.
- **`flowsdn-policy`** (the engine):
  - `types`: `Tier(u8)`, `Verdict`, `Priority(u32)`, `Precedence(u32)` with
    the exact bit ops, `ListenerPriority(u8)`, `AuthType`/`AuthRequirement`,
    `Key`/`LpmKey` (`#[repr(C)]` mirror `PolicyKey`/`PolicyEntry` from the
    maps crate with `From` conversions implementing §4.4 including the
    DEVIATION), `MapStateEntry`, `PassMeta`, `PolicyEntry`, `PolicyUpdate`,
    `ResourceId` (spec 03's type).
  - `selector`: `Selector` enum `{ Label(LabelSelector), Cidr(CidrSelector),
    Fqdn(FqdnSelector) }` with `key()`, `matches(&LabelArray)`,
    `namespaces()`; `Requirement { label, op, values: SmallVec }`; label
    strings interned (spec 03).
  - `selectorcache`: `SelectorCache { selectors: HashMap<Arc<str>, Arc<CachedSelector>>,
    by_namespace: HashMap<Namespace, Vec<SelectorId>>, identities:
    HashMap<NumericIdentity, (LabelArray, Namespace)>, revision,
    selections: im::HashMap<SelectorId, Arc<[NumericIdentity]>> }`; user
    notifications through a bounded `mpsc` consumed by one task in FIFO
    order; `Snapshot = (revision, im::HashMap clone)`; `WaitGroup` =
    `Arc<AtomicUsize>` + `Notify`.
  - `repository`: rules by resource / key / namespace; `revision:
    AtomicU64`; `replace_by_resource`, `compute_enforcement`,
    `resolve(identity) -> Result<Arc<SelectorPolicy>>`; the importer task
    (`tokio` mpsc, batch drain) and the `IpcacheWriter` trait from spec 03.
  - `l4`: `L4Filter`, `PerSelectorPolicy`, `L4PolicyMap`, `merge_port_proto`,
    `create_l4_filter`, `L7ParserType::merge`, feature bits.
  - `mapstate`: `MapState { entries: HashMap<Key, Entry>, trie: LpmTrie25<IdSet>,
    by_id: Option<HashMap<NumericIdentity, SmallVec<Key>>> }`; our own 25-bit
    trie (direction, proto, port) with node payload `IdSet`
    (`SmallVec<[NumericIdentity; 4]>` / `HashSet` above 8) and descendant
    iterators that snapshot the path (safe deletion); `insert_with_changes`,
    `auth_preferred_insert`, `insert_with_passes`, `prune_aggregated`,
    `ChangeState`, `MapChanges`, `lookup()` replica of §3.8 for tests;
    `Entry::equivalent` includes the rule-origin log string.
  - `resolve`: `SelectorPolicy`, `EndpointPolicy`, `distill`, `to_map_state`,
    `keys_for_range`, `PortRangeToMaskedPorts`, `ProxyId` formatting.
  - `compute`: per-identity worker (`tokio` task, `flowsdn-table` table
    `identity → (Arc<SelectorPolicy>, revision)` with `watch()` for endpoint
    waits), `IdentityUpdater` implementing spec 03's trait (batched wait
    groups, `endpoint-policy-update-timeout`).
  - `cookie`: future bakery support; the compatibility path keeps cookie zero (#99).
  - `rest`: handlers for the three GET routes producing spec 03-style models.
- **`flowsdn-policy-k8s`**: `kube-rs` watchers for KNP, KCNP, CNP, CCNP,
  CiliumCIDRGroup; `toServices` resolver over the LB tables
  (`flowsdn-table` watch streams instead of StateDB `Changes`; 50 ms
  debounce); CNP status is the operator's.

Performance targets (single node, 16k-entry map, 5k identities): full
distill of a 500-rule identity policy ≤ 50 ms; incremental identity add
touching 200 endpoints ≤ 20 ms end-to-end before the ipcache write; selector
cache `UpdateIdentities` of 100 identities against 2k selectors ≤ 5 ms
(namespace index makes it O(affected)); map apply ≤ 1 µs per entry (batch
update syscalls where the kernel supports `BPF_MAP_UPDATE_BATCH` on LPM
tries — it does not at 6.12, so per-entry updates; keep the "adds before
deletes" order). Memory: an `Entry` MUST fit in 24 bytes without pass
metadata (`Option<Arc<..>>` for passes, interned `RuleOrigin` handle).

No Hive (ADR-0004): construction order — selector caches → repository →
identity computer → importer → k8s watchers; the endpoint manager registers
its `PolicyOwner` callbacks; the ipcache registers the `IdentityUpdater`.

## 12. Decisions and remaining implementation

The policy library is an initial implementation of the primitives named below.
Closed design choices do not claim Kubernetes, REST or datapath integration.



1. **Resolved #92.** Pin the KCNP watcher contract to policy.networking.k8s.io/v1alpha2 and keep enable-k8s-cluster-network-policy off by default. Do not silently reinterpret a future API version; its translation requires review. The library publishes the target/default constants; watcher and CRD integration remain required.

2. **Resolved #93.** Reject Pass plus explicit authentication across the candidate policy for a subject before replacement. SubjectRepository validates the complete replacement and preserves the prior contents/revision on error; CRD import/status wiring remains required.

3. **Resolved (#94, ADR-0011): `toServices` uses the local LB-table view.**
   Keep §3.2.5 selector/headless behavior and re-resolution on service changes.
   Do not add a separate remote-cluster backend query or union. This does not
   discard entries already present in the selected local table view.
4. **Resolved (#95, ADR-0011): accept and ignore `fromRequires`/`toRequires`.**
   Keep the schema fields and emit one warning per affected rule on import.
   They must not become effective allow/deny constraints; schema removal needs
   a separately versioned compatibility decision.
5. **Resolved #96.** Recompute resolved egress named-port contributions from surviving selectors after deletion. NamedPortState returns one replacement changeset and restores lower-precedence surviving contributions. This is a deliberate deviation; full compiler/kernel synchronization remains required.

6. **Resolved #97.** Allocate exception-only prefixes as well as allow prefixes before policy publication; prune after replacement. Pinned-reference evidence and library base-plus-exceptions planning are in §3.2.4. Exception-only selector planning and actual ipcache barriers remain required.

7. **Resolved #98.** Reject numeric zero with an explicit endPort at API validation, keeping zero-without-endPort as wildcard. PortRange implements this validation; tests/corpus/port-ranges.tsv includes zero-start regression seeds and masked-port tests exhaustively check accepted ranges. Accurate zero-based low-level ABI encoding is retained. No upstream report was filed; this selects the issue's validation alternative.

8. **Resolved #99.** Keep cookie zero in the reference-compatible verdict-event contract and retain log.value metadata. A future nonzero-cookie option requires matched Hubble resolution and its own activation contract; no unsupported runtime cookie feature is claimed.

9. **Resolved (#100, ADR-0011): preserve reserved flag bits 1–2.**
   Write zero and ignore them on read; do not reclaim them before 1.0.
   A version number alone does not authorize incompatible reuse afterward:
   any reuse requires an explicit versioned map/tooling migration contract.
10. **Resolved #101.** Keep HTTP 404 when an initialized policy repository contains no rules. SubjectRepository::read_status provides the empty/nonempty decision, while the actual agent handler and compatible JSON rendering remain unimplemented (501 until that route is implemented).

11. **Resolved #102.** Retain lockdown default false for compatibility and alarm at pressure >= 0.9 with exact integer rounding. pressure() provides the tested planning primitive, not a live metric or map write. Overflow must remain a reported enforcement failure; runtime lockdown and pre-1.0 security review remain required.

12. **Simulator — #103 remains open for the complete oracle gate.**
    `oracle::evaluate` remains independent of optimized lookup construction.
    A new `mapstate::MapState` compiles the current resolved exact/wildcard
    identity L3/L4 rule domain into identity/protocol buckets and disjoint port
    intervals, then coalesces equivalent adjacent answers. Lookup uses a binary
    search, without scanning policy rules. It independently implements sorted
    tier/priority/verdict/redirect ranking and Pass handling; it never invokes
    the oracle evaluator or its matching/ranking helpers. Invalid replacement
    preserves the previous index.

    The test gate compares all 65,536 ports for representative Pass, deny,
    redirect, identity/direction and protocol combinations. Another deterministic
    generated-policy test checks 192 seeds, reversed insertion order, every
    generated port-boundary equivalence class, both directions, and known/unknown
    identity/protocol classes. Signed-zero priorities and equal redirect candidates
    are regression cases. These gates must pass for interval coalescing changes.

    This index is not the kernel LPM mapstate of §§5.4–5.8. Authentication
    inheritance, aggregate identities, cookies/origins, selectors/default-deny
    synthesis, named-port integration, 27 reference seeds, and sustained fuzz
    comparison against the complete kernel-map builder remain outstanding.
    Both current paths explicitly reject authentication, rather than treating
    matching unsupported errors as evidence of semantic equality. Closing #103
    requires those remaining gates; local resolved-policy comparisons do not
    establish Kubernetes policy enforcement.

### Simulator source clarification

Pinned-reference review for #103 (`7d68cfb394`,
`pkg/policy/testutils/simulate.go`): the brute-force simulator first selects
subject/direction rules and derives default-deny, then resolves peers and ports
before tier/priority/verdict ordering. It treats nil peers as matching nothing,
empty peers as matching everything, and Pass as skipping the rest of its tier.
The current Rust `Rule` domain starts after subject/peer/named-port resolution
and expects synthesized defaults explicitly. That missing frontend must not be
hidden by calling the interval index a complete simulator port. Source was read
to resolve scope ambiguity; no reference implementation code was copied.
