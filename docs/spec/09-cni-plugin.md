# CNI plugin and CNI configuration management — specification

Status: draft. Derived from: `docs/inventory/06-agent-endpoint-api.md` (CNI
plugin section, config keys, deletion queue, `GET /config` fields),
`docs/inventory/03-datapath-userspace-node.md` (endpoint connector, sysctls,
MTU), `docs/inventory/15-helm-images-ci-tests.md` (install init container,
hostPath volumes, `cni.*` Helm values), `docs/inventory/07-ipam-cloud.md`
(delegated IPAM, per-ENI routing); reference cilium v1.20.1 (7d68cfb394) paths
`plugins/cilium-cni/{main.go,cmd/*.go,types/types.go,lib/deletion_queue.go,
chaining/**,install-plugin.sh,cni-uninstall.sh}`, `pkg/datapath/connector/**`,
`daemon/cmd/cni/**`, `pkg/endpoint/api/{endpoint_api_manager,
endpoint_api_handler,endpoint_deletion_queue}.go`, `pkg/netns/netns_linux.go`,
`pkg/mac/mac.go`, `pkg/datapath/linux/routing/routing.go`,
`pkg/datapath/linux/linux_defaults/linux_defaults.go`, `pkg/client/client.go`,
`pkg/defaults/defaults.go`, `daemon/restapi/config.go`, `api/v1/openapi.yaml`
(`/ipam`, `/ipam/{ip}`, `/endpoint/{id}`, `EndpointChangeRequest`,
`EndpointDatapathConfiguration`, `IPAMResponse`), vendored
`containernetworking/cni/pkg/{skel,types}`, and the CC BY 4.0 documentation
`Documentation/installation/cni-chaining*.rst`,
`Documentation/network/kubernetes/configuration.rst`. Governed by
ADR-0001..0004.

Normative language: MUST / SHOULD / MAY as in RFC 2119. A spec describes
*what* flowsdn does and the exact data it exchanges. It does not transcribe
reference code. Where the reference behavior is kept for compatibility, say
so and name the consumer that depends on it (kubelet, container runtime,
cilium-dbg, Helm, other CNI plugins). Where flowsdn deviates, mark
**DEVIATION** with the reason and the ADR.

Sibling specs referenced by name: `08-endpoint-agent-api` (endpoint create /
delete API, `PUT /endpoint/{id}` semantics, `GET /config`,
`EndpointChangeRequest` model owner), `07-ipam` (`POST /ipam`,
`DELETE /ipam/{ip}`, pool selection, expiration timers), `03-identity-ipcache`
(how a new endpoint IP becomes an ipcache entry), `02-datapath-programs`
(what is attached to the `lxc*` device), `01-bpf-map-abi-loader` (attach
mechanics, `cilium_lxc`), `00-foundation-table-config` (fences `api-ready`,
`agent-ready`, config registry, controllers).

## 1. Scope

In scope:

- The CNI plugin binary the kubelet (via the container runtime) executes for
  every pod sandbox: the ADD, DEL, CHECK, STATUS and VERSION verbs, the network
  configuration it accepts, the arguments it reads, the agent API calls it
  makes, the kernel objects it creates (link pair, addresses, routes, rules,
  sysctls), the result it prints, its error codes, logging and rollback.
- The offline deletion queue used when the agent is not reachable during DEL,
  including the agent side that drains it.
- The chaining modes (`aws-cni`, `flannel`, `generic-veth`, `azure`,
  `portmap`) and the delegated IPAM mode (`ipam=delegated-plugin`).
- The agent's CNI configuration manager: what it writes under
  `/etc/cni/net.d`, when, how it splices into a foreign conflist, how it
  renames competing configurations, and how it reports status.
- Installation of the plugin binary into `/opt/cni/bin` and its removal.
- The netkit connector interface, as a specified-but-deferred variant of the
  veth connector.

Out of scope, with owning spec: what the agent does with
`PUT /endpoint/{id}` after it validates the request — endpoint ID
allocation, identity resolution, regeneration, `cilium_lxc` and ipcache
updates, host-side endpoint route installation when `enable-endpoint-routes`
is set, CEP creation (`08-endpoint-agent-api`, `03-identity-ipcache`,
`01-bpf-map-abi-loader`); IPAM pool selection and address lifetimes
(`07-ipam`); the BPF programs attached to the created device
(`02-datapath-programs`); the per-ENI routing tables installed on the host in
cloud IPAM modes — this spec fixes only the plugin's call into that routine
and its inputs (`07-ipam`); MTU computation (`03` datapath userspace spec,
the plugin only consumes `device-mtu` and `route-mtu`).

## 2. Compatibility contract

The kubelet, the container runtime, other CNI plugins in a chain and the
delegated IPAM plugins are the consumers. None of them is under our control.
Everything they observe MUST match the reference.

| Interface | Consumer | MUST match |
|---|---|---|
| Binary name `cilium-cni` in the CNI bin dir (conflist `type`) | container runtime (execs `<binPath>/<type>`), existing custom conflists (`cni.customConf`) | name; see open decision 12.1 for the `flowsdn-cni` alias |
| CNI spec versions `0.1.0 0.2.0 0.3.0 0.3.1 0.4.0 1.0.0 1.1.0` | runtime negotiates via `VERSION` | exact list, `VERSION` output JSON `{"cniVersion":…,"supportedVersions":[…]}` |
| Verbs `ADD DEL CHECK STATUS VERSION` | runtime | GC is not implemented (section 3.7) |
| Environment `CNI_COMMAND CNI_CONTAINERID CNI_NETNS CNI_IFNAME CNI_ARGS CNI_PATH` and stdin JSON | runtime | as CNI spec; `CNI_ARGS` keys section 4.2 |
| Network configuration JSON fields (section 4.1) | Helm-rendered conflists, user conflists, chained plugins | field names and types |
| Conflist file `/etc/cni/net.d/05-cilium.conflist` and its three templates (section 4.5) | kubelet (file presence = node Ready), Istio/other tools that rewrite it, `cilium-dbg status` (`cni-file`) | path, `name`, `cniVersion`, plugin entries |
| Renaming foreign configs to `<name>.cilium_bak` | operators, `cni-uninstall`, re-chaining | suffix |
| Chained entry `{"type":"cilium-cni","chaining-mode":…,"enable-debug":…,"log-file":…}` spliced into `plugins[]` | aws-cni, other conflists | shape and position rule (section 3.9) |
| Agent API calls and models (section 4.6) | flowsdn agent (spec 08/07) — kept byte-compatible so the upstream `cilium-cni` binary also works against a flowsdn agent during migration | paths, query params, JSON |
| Deletion queue dir `/var/run/cilium/deleteQueue/`, lockfile `lockfile`, `*.delete` files | flowsdn agent, upstream agent on mixed upgrade | layout, content, flock protocol |
| Result JSON (`interfaces`, `ips`, `routes`) | runtime, kubelet (pod IP), chained plugins (`prevResult`) | shape section 4.4 |
| CNI error codes 50 / 100 / 101 (plugin-defined) and 1 / 4 / 7 / 11 / 999 (spec), process exit status always 1 on error | runtime retry logic (reads the JSON `code`) | numbers and `msg` strings |
| Host device name `lxc<12 hex>`, altname `cilium_cni:<ifname>` on the pod device | `cilium-dbg`, device selection filters (inventory 03: `lxc` prefix excluded), MTU updater, `cilium_cni:` ownership check, operators' tooling | format |
| Log file `/var/run/cilium/cilium-cni.log`, slog text format | bugtool, operators | path default, field names |
| Config keys `cni-*`, `write-cni-conf-when-ready`, `read-cni-conf`, `container-ip-local-reserved-ports`, `install-uplink-routes-for-delegated-ipam`, `enable-route-mtu-for-cni-chaining` | Helm `cilium-config` ConfigMap | names, defaults, semantics (section 6) |
| Helm values `cni.*` | chart users | names; mapping in section 6.3 |

## 3. Behavior

### 3.1 Process model

The plugin is a short-lived process. One invocation handles exactly one verb
for one sandbox and exits. It MUST:

1. Read `CNI_COMMAND`. With no `CNI_COMMAND`, print to **stderr** the about
   string `flowsdn CNI plugin <version> (cilium-cni compatible)` followed by
   `CNI protocol versions supported: 0.1.0, 0.2.0, 0.3.0, 0.3.1, 0.4.0, 1.0.0, 1.1.0`
   and exit 0 (a missing `CNI_COMMAND` from a runtime, i.e. with stdin not a
   TTY, is instead CNI error 4).
2. For `VERSION`: read `cniVersion` from stdin (may be absent), print
   `{"cniVersion":"<requested or 1.1.0>","supportedVersions":["0.1.0","0.2.0","0.3.0","0.3.1","0.4.0","1.0.0","1.1.0"]}`.
3. For any other verb: validate the required environment for that verb
   (ADD/CHECK/DEL: `CNI_CONTAINERID`, `CNI_NETNS` (DEL: optional),
   `CNI_IFNAME`, `CNI_PATH`; STATUS: none beyond `CNI_COMMAND`), read all of
   stdin as JSON, check `cniVersion` is in the supported list (CNI error 1
   `ErrIncompatibleCNIVersion` otherwise; STATUS additionally requires
   `cniVersion >= 1.1.0`), dispatch.
4. On success write the result JSON to stdout (ADD only; DEL/CHECK/STATUS
   write nothing) and exit 0. On failure write a CNI error object
   `{"cniVersion":…,"code":N,"msg":"…","details":"…"}` to stdout and exit
   with process status **1** — always 1, whatever `N` is. The runtime reads
   the CNI code from the JSON, never from the exit status (reference skel
   behaviour; libcni ignores the status when it can parse the object).
   Unstructured errors MUST be wrapped as code 999 (`ErrInternal`) with the
   error text as `msg`.

A thread that enters a network namespace MUST be pinned and MUST either
restore the original namespace before doing anything else or terminate
(section 10, section 11). The whole plugin MUST be safe to run concurrently
many times on one node: the kubelet parallelises sandbox creation.

### 3.2 Configuration and argument parsing (all verbs)

1. Parse stdin into `NetConf` (section 4.1). Unknown fields MUST be ignored.
   If the document is a conflist (has `plugins[]`) — which only happens when
   the agent reads `read-cni-conf` — select the entry with `type ==
   "cilium-cni"`; the runtime itself always hands the plugin a single plugin
   entry with `name`/`cniVersion` copied from the list.
2. If `prevResult` is present, convert it to the internal 1.x `Result`
   representation regardless of the `cniVersion` it was produced in.
3. Set up logging (section 8) from `enable-debug`, `log-format`, `log-file`
   *before* anything that can fail, so the failure is logged.
4. Parse `CNI_ARGS` (`;`-separated `KEY=value`) into the argument set of
   section 4.2. Unknown keys MUST be ignored (`IgnoreUnknown` is implied;
   the reference sets it via `CommonArgs`). A malformed pair is a fatal
   error (ADD/DEL: 999; CHECK/STATUS: code 7 `InvalidArgs`).

### 3.3 Connecting to the agent

The agent socket is `$CILIUM_SOCK` if set, else `/var/run/cilium/cilium.sock`.

- ADD, CHECK and STATUS MUST connect with a **30 s** budget
  (`ClientConnectTimeout`): attempt to open the socket and call
  `GET /config`; on any failure sleep 500 ms and retry until the budget is
  spent. Failure is fatal: ADD/CHECK error text MUST include the reference
  hint `Is the agent running?` when the socket path appears in the error;
  CHECK returns CNI code 11 `ErrTryAgainLater` / `DaemonDown`; STATUS returns
  code 50 `CniErrPluginNotAvailable` / `DaemonDown`.
- DEL MUST use the **1.5 s** deletion-client budget (section 3.6) — the
  kubelet's DEL deadline is short and a slow failure is worse than queueing.
- The `GET /config` response `status` (a `DaemonConfigurationStatus`,
  inventory 06) is the plugin's entire view of agent configuration. The
  fields consumed are listed in section 4.3. The plugin MUST NOT read the
  agent's ConfigMap, flags or files directly.

### 3.4 ADD

Ordered steps. Every step names the failure behaviour; on any failure after
step 7 the rollback of section 3.4.1 runs and the error is returned.

1. **Parse** (3.2), **connect** (3.3), fetch `conf = GET /config`.
2. **Chaining decision.** If `prevResult` is present in the input:
   - resolve the chainer (section 3.9 rule). If a chainer is found, run its
     ADD and print its result in the requested `cniVersion`; **stop here**.
   - if `chaining-mode` names an unknown chainer → error `invalid
     chaining-mode <x>`.
   - if no chainer resolves → error `CNI PrevResult supplied, but not in
     chaining mode -- this is invalid, please set chaining-mode in CNI
     configuration`. A `prevResult` without chaining is never valid: the
     plugin would otherwise create a second interface in a sandbox another
     plugin already configured.
   Without `prevResult`, chaining fields are ignored and the plugin runs the
   primary flow below.
3. **Open the sandbox netns** at `CNI_NETNS` (a bind-mount path such as
   `/var/run/netns/cni-…` or `/proc/<pid>/ns/net`). Failure → error
   `opening netns pinned at <path>`.
4. **Remove a stale interface**: inside the netns, delete any link named
   `CNI_IFNAME` if it exists (a previous ADD that failed after moving the
   peer, or a runtime retry). "Not found" is success.
5. **IPAM.**
   - `conf.ipam-mode == "delegated-plugin"` → delegated IPAM (section 3.10).
   - otherwise → `POST /ipam?owner=<K8S_POD_NAMESPACE>/<K8S_POD_NAME>`
     with header `expiration: true`, no `family` and no `pool` query parameter. Pool selection is the
     agent's (spec 07: pod/namespace annotations, `CiliumPodIPPool`
     selectors, default pool). The agent returns both families when both are
     enabled (dual-stack); the plugin MUST NOT make one call per family.
     Response `IPAMResponse` (section 4.6). `address` missing → error
     `invalid IPAM response, missing addressing`.
   - Register the release action: `DELETE /ipam/{ip}?pool=<pool>` for each
     allocated family (`ipv4-pool-name` / `ipv6-pool-name`), or the delegated
     plugin's DEL. It runs on any later failure. Release errors are logged at
     warn and never override the original error.
   - Validate `host-addressing` has an IP in at least one family (`Either
     IPv4 or IPv6 addressing must be provided`) and that at least one family
     is *both* allocated and enabled in `host-addressing.<fam>.enabled`
     (`IPAM did provide neither IPv4 nor IPv6 address`). A family counts as
     enabled for the rest of ADD only if both hold.
6. **Build the endpoint request skeleton** (`EndpointChangeRequest`,
   section 4.6): `container-id = CNI_CONTAINERID`, `container-interface-name
   = CNI_IFNAME`, `k8s-pod-name/-namespace/-uid` from `CNI_ARGS`, `state =
   "waiting-for-identity"`, `labels = []`, empty `addressing`, empty
   `datapath-configuration`, empty `properties`. Then per IPAM mode:
   - `delegated-plugin`: `datapath-configuration.external-ipam = true` (the
     agent must never release or re-allocate this IP).
   - `eni`: if IPv4 is enabled, resolve `parent-interface-index` from
     `ipam.ipv4.master-mac` by scanning host links for a non-slave link with
     that MAC (ambiguous or missing MAC is logged at error and the field left
     0; it only serves the IPv4 masquerade reply path).
7. **Create the link pair** (section 3.8) with
   `LinkConfig{endpoint_id = "<CNI_CONTAINERID>:<CNI_IFNAME>", peer_ifname =
   CNI_IFNAME, peer_netns, device_mtu = conf.device-mtu, gro/gso v4/v6 max
   sizes = conf.gro-max-size, gso-max-size, gro-max-size-v4, gso-max-size-v4,
   headroom/tailroom = conf.device-headroom/-tailroom}` in the mode
   `conf.datapath-mode` (`veth` | `netkit` | `netkit-l2`; `auto` never
   reaches the plugin — the agent resolves it before reporting). From here
   on, failure deletes the host link (which deletes the peer).
   Fill the request: `interface-name` and `interface-index` = host link;
   for L2 modes (`veth`, `netkit-l2`) `mac` = peer MAC and `host-mac` = host
   MAC (L3 netkit has neither). Result `interfaces[0] = {name: <host>, mac:
   <host MAC if L2>}`.
8. **Addressing, per enabled family, IPv6 first then IPv4** (order fixes
   `ips[]` order in the result):
   - copy `ipam.address.<fam>`, `<fam>-pool-name`, `ipam.<fam>.expiration-uuid`
     into `addressing`; if `ipam.<fam>.skip-masquerade` set
     `properties["skip-masquerade-v4"|"skip-masquerade-v6"] = true`.
   - compute the container routes (section 3.4.2) with `mtu = conf.route-mtu`
     and the gateway = `host-addressing.<fam>.ip`; append
     `{address: <ip>/32|/128, gateway: <router ip>, interface: 1}` to
     `ips[]` and the two routes to `routes[]`.
   - the IP string from IPAM MAY carry a prefix length (delegated IPAM
     returns `a.b.c.d/nn`); only the address is used, the prefix is always
     replaced by /32 or /128.
9. **Host-side per-interface routing** when `conf.ipam-mode ∈ {eni, azure,
   alibabacloud}` or (`delegated-plugin` and
   `conf.install-uplink-routes-for-delegated-ipam`): for each enabled family
   whose `ipam.<fam>.gateway` is non-empty, install the rules and routes of
   section 5.3 with `master-mac`, `interface-number`, `cidrs` and
   `masquerade-protocols.<fam>`. An empty gateway means "already set up",
   skip silently.
10. **Configure the sandbox** (inside the netns, one entry):
    1. reserve local ports: if `conf.ip-local-reserved-ports` is non-empty,
       write `net.ipv4.ip_local_reserved_ports = <existing>,<conf value>`
       (kernel merges overlaps; failure is a warning, not fatal);
    2. if IPv6 is enabled, write `net.ipv6.conf.all.disable_ipv6 = 0`
       (warning on failure);
    3. bring `CNI_IFNAME` up; for each enabled family add the address
       (IPv6 with `IFA_F_NODAD`), then the routes sorted most-specific first
       (`EEXIST` on a route is success), then the rules (none in the primary
       flow); failure here is fatal;
    4. read the peer MAC to report.
11. **Netns cookie**: inside the netns open an `AF_INET` stream socket and
    read `SO_NETNS_COOKIE`; `netns-cookie` = decimal string. `ENOPROTOOPT`
    (kernel < 5.14) → `"0"` and an info log; the reference remembers the
    failure per process, which is meaningless for a one-shot binary and MUST
    NOT be reproduced.
12. **Create the endpoint**: set `sync-build-endpoint = true`,
    `container-netns-path = /var/run/cilium/netns/<basename(CNI_NETNS)>`
    (the path the agent will later use to re-enter the namespace — the agent
    bind-mounts under `/var/run/cilium/netns`; if it does not, the field is
    informational), then `PUT /endpoint/{id}` with `id =
    cni-attachment-id:<CNI_CONTAINERID>:<CNI_IFNAME>` and the request body.
    The call blocks until the agent has finished the first regeneration
    (BPF programs attached, `cilium_lxc` and ipcache written, policy
    computed) or fails. Responses: 201 → continue with the returned
    `Endpoint`; 400 (invalid: duplicate attachment id, IP in use, reserved
    labels) / 409 / 500 (creation or regeneration failed) / 503 (API not
    ready) / 429 → fatal, rollback. The plugin MUST NOT apply a timeout of
    its own to this call: the agent bounds the wait (spec 08; reference
    `EndpointGenerationTimeout` 330 s, cut earlier by the API server's 60 s
    write timeout, which surfaces as a connection error and triggers
    rollback). There is no asynchronous creation: without
    `sync-build-endpoint` the runtime would start the container before
    policy exists, which the reference forbids (GH-4409).
13. **MAC override**: if `endpoint.status.networking.mac` is non-empty (the
    pod carried the `cni.cilium.io/mac-address` annotation and the agent
    accepted it) and the mode is L2, set that MAC on `CNI_IFNAME` inside the
    netns; the reported container MAC becomes this value.
14. **Post-create sysctls** (inside the netns): if
    `conf.packetization-layer-pmtud-mode` is non-empty write
    `net.ipv4.tcp_base_mss = 1024`, `net.ipv4.tcp_mtu_probing = <mode>`,
    `net.ipv4.tcp_mtu_probe_floor = 48` (warnings on failure; `tcp_base_mss`
    needs 5.11); if `conf.enable-bbr-host-namespace-only` write
    `net.ipv4.tcp_congestion_control = cubic` (fatal on failure — the pod
    would otherwise inherit BBR from the host and the bandwidth manager's
    EDT accounting would be wrong).
15. Append `interfaces[1] = {name: CNI_IFNAME, mac: <container MAC>,
    sandbox: CNI_NETNS}`, print the result converted to the requested
    `cniVersion` (0.1.0/0.2.0 collapse to `ip4`/`ip6`; 0.3.x/0.4.0 drop
    `interface` fields that 1.0.0 added), exit 0.

#### 3.4.1 Rollback

Rollback runs in reverse registration order on any failure after the
corresponding step succeeded, each action independently and logged at warn
if it fails:

| Registered at | Action |
|---|---|
| step 7 | delete the host link by index (peer disappears with it, wherever it is) |
| step 5 | release IPs: `DELETE /ipam/{ip}?pool=…` per family, or delegated DEL |
| step 12 (failure *of* the PUT) | nothing extra: a failed `PUT /endpoint` leaves no endpoint (the agent removes it with `NoIPRelease`); a successful PUT followed by a later failure (steps 13–15) MUST issue `DELETE /endpoint/cni-attachment-id:<cid>:<ifname>` before releasing IPs, otherwise the agent would hold an endpoint on a dead device until its GC finds the missing link |

**DEVIATION** (last row): the reference does not delete the endpoint when
steps 13–15 fail; the endpoint lingers until `endpoint-gc-interval` (5 m)
notices the link is gone and the IP is double-released or leaked. flowsdn
deletes it explicitly. Same observable end state, sooner.

The per-ENI host rules of step 9 are not rolled back by the plugin; the
agent's `DELETE /endpoint` path removes them (`07-ipam`) and a later ADD for
the same IP replaces them.

#### 3.4.2 Container addressing and routes

The pod device carries a host-scoped address and no on-link subnet; all
traffic leaves via the router (the `cilium_host` address, reported as
`host-addressing.<fam>.ip`; inventory 06's "169.254.42.1-style" remark
describes the old docker plugin, not this path):

| Family | Address | Route 1 (scope link) | Route 2 |
|---|---|---|---|
| IPv4 | `<pod ip>/32` | `<router v4>/32 dev <ifname>` | `default via <router v4> dev <ifname> mtu <route-mtu>` |
| IPv6 | `<pod ip>/128` (`IFA_F_NODAD`) | `<router v6>/128 dev <ifname>` | `::/0 via <router v6> dev <ifname> mtu <route-mtu>` |

`route-mtu` is the agent's computed path MTU after tunnel/encryption
overhead (inventory 03). Routes are created with `RTPROT_BOOT` (the netlink
default; the plugin does not set a protocol), `RT_TABLE_MAIN`; the scope-link
route has no gateway, the default route `RT_SCOPE_UNIVERSE`. The same two
routes per family go into the result's `routes[]` (with `mtu`; CNI 1.1.0
added the field — for older versions it is dropped by conversion).

The host side gets **no** route from the plugin. With `enable-endpoint-routes`
the agent installs `<pod ip>/32 dev lxc… proto kernel` itself during
regeneration and removes it on delete (spec 08 / datapath userspace spec);
without it, delivery to the pod is a BPF redirect from `cilium_host`.

### 3.5 Link pair creation (veth)

Names and identities:

- Host device: `lxc` + first **12** hex characters of `sha256("<CNI_CONTAINERID>:<CNI_IFNAME>")`
  (15 characters; `IFNAMSIZ − len("tmp") − 1`). Inventory 03's "[:10]" is a
  transcription slip; 12 is what the reference computes and what the
  documentation example `lxcb3901b7f9c02` shows.
- Peer is created in the host netns under a temporary name `tmp` + first 5
  characters of `CNI_CONTAINERID` (so two concurrent ADDs never collide on
  the final `eth0`), moved into the sandbox, then renamed to `CNI_IFNAME`.
- After the rename the peer gets the alternative name `cilium_cni:<CNI_IFNAME>`
  (`IFLA_PROP_LIST`/`IFLA_ALT_IFNAME`). The agent's MTU updater and any
  ownership check use "altname present" as the definition of "created by
  us". Failure to set it is a warning.

Attributes at creation (`RTM_NEWLINK` with `IFLA_LINKINFO kind=veth` and
`VETH_INFO_PEER`):

| Attribute | Host side | Peer |
|---|---|---|
| MAC | random, locally administered unicast: 6 random bytes, `b[0] = (b[0] \| 0x02) & 0xfe`, set at creation | same scheme |
| `txqueuelen` | 1000 | default |
| MTU | `device-mtu` | `device-mtu` |
| GRO/GSO max size (IPv6 fields) | `gro-max-size`/`gso-max-size` if > 0 | same |
| GRO/GSO IPv4 max size | `gro-max-size-v4`/`gso-max-size-v4` if > 0 | same |
| admin state | UP | UP (set inside the netns at step 10.3) |
| sysctl | `net.ipv4.conf.<host>.rp_filter = 0` | — |

Both MACs MUST be set explicitly at creation (they are random anyway) so
that `addr_assign_type == NET_ADDR_SET`; otherwise systemd ≥ 242
(`MACAddressPolicy=persistent`) rewrites the MAC asynchronously and the
datapath, which learned the MAC at endpoint creation, drops every packet.
There is no fixed host-side MAC convention in v1.20.1; the `node_mac` in
`cilium_lxc` is whatever was generated here and the datapath rewrites L2
headers from that map, so a fixed value would buy nothing. The
`sysctlfix` init container additionally writes
`net.ipv4.conf.lxc*.rp_filter=0` into `/etc/sysctl.d` (inventory 15) so
systemd-sysctl cannot undo the per-device write.

No other sysctl is written by the plugin on the host or on the pod device.
`accept_ra`, `forwarding`, `proxy_ndp`/`proxy_arp` and friends are set on
`cilium_host`/`cilium_net` and on selected native devices by the agent's
loader (inventory 03: `net.ipv4.conf.all.rp_filter=0`, per-device
`forwarding=1` and `rp_filter=0` on `cilium_host`/`cilium_net`,
`rp_filter=2` on the primary ENI). Container-side sysctls are exactly those
of steps 10.1, 10.2 and 14.

### 3.6 DEL

DEL MUST be idempotent and MUST succeed whenever the sandbox is gone, so the
kubelet's retry loop terminates. It returns an error only for conditions that
are genuinely recoverable by a retry.

1. Parse (3.2); no agent connection yet.
2. Chaining: resolve the chainer by the rule of 3.9 (DEL always carries
   `prevResult`, so `chaining-mode`/network name decide). A chainer runs its
   own DEL (section 3.9) and DEL ends. An unknown `chaining-mode` is an error.
3. **Endpoint delete with offline fallback** for id
   `cni-attachment-id:<CNI_CONTAINERID>:<CNI_IFNAME>` (section 5.1). Only the
   client-failure class (`ErrClientFailure`: could not take the queue lock or
   write the queue file) is returned to the runtime; agent-side 400/404/206
   are logged at warn and DEL continues.
4. If `ipam.type` is set in the netconf (delegated IPAM), invoke the
   delegated plugin's DEL (section 3.10) **before** touching the netns —
   the namespace may already be gone and the IP must not leak. Its error is
   returned.
5. Open `CNI_NETNS`. `ENOENT` → log at warn, **exit 0** (the interface died
   with the namespace; kubernetes/kubernetes#133081). Any other open error
   → return error (retryable).
6. Inside the netns delete `CNI_IFNAME`. Failure is logged at warn and
   ignored (deleting the host `lxc` link, which the agent does when it
   removes the endpoint, takes the peer with it).
7. Exit 0.

DEL without a prior successful ADD (the runtime calls DEL after a failed ADD,
CNI spec requirement) hits: agent returns 404 → warn → netns may or may not
exist → exit 0. Duplicate DEL: same.

### 3.7 CHECK, STATUS, GC

**CHECK** (CNI ≥ 0.4.0) verifies without mutating:

1. Parse; parse failures return code 7 `ErrInvalidNetworkConfig`
   (`InvalidNetworkConfig`, `InvalidLoggingConfig`, `InvalidArgs`).
2. Connect (30 s); failure → code 11 `ErrTryAgainLater` `DaemonDown` so the
   runtime does not treat a restarting agent as a broken sandbox.
3. Chainer present → its CHECK (generic-veth: endpoint health only).
4. Otherwise `GET /endpoint/cni-attachment-id:<cid>:<ifname>/healthz`;
   transport/404 → code **100** `HealthzFailed` `failed to retrieve
   container health: …`; `overallHealth == "Failure"` → code **101**
   `Unhealthy` `container is unhealthy in agent`.
5. Enter the netns; the link `CNI_IFNAME` MUST exist and MUST carry every
   address that `prevResult.ips[]` attributes (via `interface` index) to the
   sandbox interface named `CNI_IFNAME`. Missing link or address → code 999
   with `expected ip <x> on interface <ifname>`. MTU and routes are not
   verified (reference limitation; MAY be added — open decision 12.4).

**STATUS** (CNI 1.1.0) answers "can this node take an ADD right now":

1. Parse (code 7 on failure), connect (30 s; failure → **50**
   `CniErrPluginNotAvailable` `DaemonDown`).
2. Chainer present → its STATUS (generic-veth: agent `GET /healthz`).
3. `GET /healthz` on the agent; failure → 50 `DaemonHealthzFailed`.
4. If `ipam.type` is set, invoke the delegated plugin's STATUS and return its
   error verbatim.
5. Exit 0 with no output.

Code 50 is the CNI-spec value for "plugin not available, retry later"; the
kubelet keeps the node NotReady while STATUS fails.

**GC** (CNI 1.1.0): the reference registers no GC handler, so the skel
answers `ErrIncompatibleCNIVersion` (1) `plugin version does not allow GC`.
flowsdn MUST do the same at this tag. Implementing GC (delete endpoints whose
`cni.dev/valid-attachments` does not list them) is open decision 12.3.

### 3.8 Connector modes and the netkit interface

`conf.datapath-mode` selects the connector. The plugin implements `veth`;
`netkit` and `netkit-l2` are **deferred** (inventory 03, spec 01) but their
contract is fixed here so the veth code is written against it.

| Aspect | `veth` | `netkit` (L3) | `netkit-l2` |
|---|---|---|---|
| Link kind | `veth` | `netkit`, `IFLA_NETKIT_MODE = L3` | `netkit`, mode L2 |
| MACs | random both sides | none; `mac`/`host-mac` omitted from the endpoint request and `interfaces[].mac` omitted | random both sides |
| Extra attrs | — | `IFLA_NETKIT_POLICY = FORWARD`, `IFLA_NETKIT_PEER_POLICY = BLACKHOLE`, `IFLA_NETKIT_SCRUB = NONE` (primary), `IFLA_NETKIT_PEER_SCRUB = DEFAULT`, `IFLA_NETKIT_HEADROOM/TAILROOM = device-headroom/-tailroom` | same |
| Post-create validation | peer found by name | both ends MUST be netkit; peer headroom/tailroom MUST equal primary's (mismatch is fatal); primary's below requested is a warning | same |
| Program attach | tc/tcx on host `lxc` (agent) | netkit link program on the primary (agent) | same |
| Packet from pod with no program | delivered to host stack | dropped (peer policy BLACKHOLE) | dropped |
| Kernel | any supported | ≥ 6.7 `CONFIG_NETKIT`; scrub attrs 6.13 when `enable-endpoint-routes` | same |
| Agent preconditions (agent-side, reported as `datapath-mode`) | — | BPF host routing, BPF masquerade, KPR, no `enable-bpf-tproxy`; `auto` falls back to veth | same |

Everything else in 3.4 (naming, temp name, rename, altname, MTU, GRO/GSO,
`rp_filter` on the primary, addresses, routes, sysctls) is identical across
modes. The `rtnetlink` crate lacks `IFLA_NETKIT_*`; a local extension is
required (inventory 03, section 11).

### 3.9 Chaining modes

Chaining means another CNI plugin created the sandbox interface and assigned
addresses; flowsdn attaches policy/visibility to that interface and never
allocates or routes. The plugin is then the last (or a later) entry in the
runtime's `plugins[]` and receives `prevResult`.

**Chainer resolution rule** (used identically by ADD, DEL, CHECK, STATUS):

1. If `chaining-mode` is non-empty → look it up in the registry; unknown →
   error `invalid chaining-mode <x>`.
2. Else if the network `name` is neither `cilium` nor `portmap` and matches a
   registered chainer name → that chainer (implicit selection by network
   name, kept for old conflists named `aws-cni`, `flannel`, …).
3. Else → no chaining.

Registry (name → behaviour): `aws-cni`, `flannel`, `azure`, `generic-veth`
all map to the **generic veth chainer**. The name `cilium` MUST be rejected
at registration. `portmap` is not a chainer: it marks that the upstream
`portmap` plugin follows in the chain and is otherwise the primary flow.
`none` exists only on the agent side (`cni-chaining-mode`), never in a
netconf.

**Generic veth chainer**

| Verb | Behaviour |
|---|---|
| ADD | (1) parse `prevResult`; (2) in the sandbox find the first `veth` link, read its name, MAC, first IPv4 address and IPv6 address (prefer the global-unicast one when several), and its peer index; error if no veth, no MAC, no IP of either family, or no peer; (3) if `enable-route-mtu` (netconf) or `conf.enable-route-mtu-for-cni-chaining`: replace every IPv4 and IPv6 route in the sandbox whose `mtu != route-mtu` with the same route at `route-mtu`; (4) look up the peer in the host netns by index → host name/MAC/index; (5) `PUT /endpoint/cni-attachment-id:<cid>:<ifname>` with `addressing{ipv4,ipv6}`, `container-id`, `state=waiting-for-identity`, `host-mac`, `interface-index`, `mac`, `interface-name`, `container-interface-name`, k8s pod/ns/uid, `sync-build-endpoint=true`, `datapath-configuration{require-arp-passthrough=true, require-egress-prog=true, external-ipam=true, require-routing=false}`; (6) if the returned `status.networking.mac` differs from the observed MAC, set it on the sandbox veth and patch `prevResult.interfaces[]`; (7) return `prevResult` unchanged otherwise. No IPAM, no routes added, no sysctls. |
| DEL | endpoint delete with offline fallback (5.1); only `ErrClientFailure` propagates |
| CHECK | `GET /endpoint/…/healthz` → 100 / 101 as in 3.7; no netns inspection |
| STATUS | agent `GET /healthz` → 50 on failure |

The four datapath flags mean: ARP between the Linux stack and the pod passes
through (the other plugin relies on it); a host-facing egress program is
attached to implement ingress policy and reverse NAT because the host route
points straight at the veth; the IP is not ours; routing is Linux's. Policy
identity for the pod comes from the ipcache entry the agent creates for the
observed IP (`03-identity-ipcache`), the same as in the primary flow.

**Agent-side defaults per chaining mode** (`cni-chaining-mode`):

| Mode | `cni-chaining-target` default | `cni-external-routing` default | conflist written |
|---|---|---|---|
| `none` | — | false | template `none` |
| `portmap` | — | false | template `portmap` |
| `flannel` | — | false | template `flannel` |
| `aws-cni` | `aws-cni` (network name) | **true** | splice into the found network |
| `generic-veth` / `azure` | must be set by the user (Helm `cni.chainingTarget`) or `read-cni-conf` used | false | splice, or user file |
| (empty) with `cni-chaining-target` set | as given | false | mode becomes `generic-veth` |

`cni-external-routing=true` makes the agent set
`install-endpoint-route=false` on every created endpoint even with
`enable-endpoint-routes` (the other plugin owns the host routes). Limitations
documented upstream and inherited: no L7 policy (GH-12454) and no IPsec
(GH-15596) when chained; existing pods must be restarted to be chained.

### 3.10 Delegated IPAM (`ipam=delegated-plugin`)

The agent's IPAM is disabled (`07-ipam`: no-op allocator, `POST /ipam`
returns 501). The netconf's `ipam` object names another CNI IPAM plugin
(`host-local`, `azure-vnet-ipam`, …) found on `CNI_PATH`.

- **DelegateAdd**: exec `<CNI_PATH>/<ipam.type>` with `CNI_COMMAND=ADD` and
  the plugin's own environment and stdin (the full netconf, unchanged — the
  delegate reads its `ipam` section). Parse its result (any version) into
  1.x. Translate into an `IPAMResponse`: `host-addressing = conf.addressing`;
  for each `ips[]` entry, by family and only if `conf.addressing.<fam>` is
  non-null: `address.<fam> = <ip/prefix as returned>`, `<fam> =
  {ip, gateway = ips[].gateway, master-mac, interface-number = "0"}`. At most
  one IP per family is assumed (Kubernetes pod contract). `master-mac` comes
  from the first `interfaces[]` entry with empty `sandbox`: its `mac`, else
  the MAC of the host link named `name`; absent → empty. If parsing or
  translation fails after the delegate succeeded, DelegateDel MUST run.
- **DelegateDel**: exec the delegate with `CNI_COMMAND=DEL`, same stdin. Used
  by rollback (3.4.1) and by DEL step 4.
- **DelegateStatus**: exec with `CNI_COMMAND=STATUS` (STATUS step 4).
- The endpoint is created with `external-ipam=true`; the agent's restore
  path skips IP re-allocation and its GC never releases the IP
  (`endpointmanager` `NoIPRelease`).
- Routes: the container gets the standard 3.4.2 routes toward
  `host-addressing.<fam>.ip`, *not* the delegate's `gateway`; the delegate's
  gateway is only used for the host-side uplink rules when
  `install-uplink-routes-for-delegated-ipam` is set (step 9, section 5.3),
  the case where the delegate hands out IPs from a secondary NIC.

### 3.11 Agent: CNI configuration manager

Runs in the agent (a controller named `write-cni-file`, group
`write-cni-file`, retry base 10 s, exposed in `cilium-dbg status
--all-controllers`). It exists so the kubelet sees a CNI configuration only
once the node can actually take ADDs.

Preconditions to start writing: fence `agent-ready` (spec 00: API listening,
deletion-queue lock released, endpoints restored, status probes ran once).
Before that the status is `Failure: CNI controller not started`. If
`write-cni-conf-when-ready` is empty the manager is `Disabled: CNI
configuration management disabled` and nothing below happens.

Each run:

1. Compute `dir, file = split(write-cni-conf-when-ready)` (Helm:
   `/host/etc/cni/net.d/05-cilium.conflist`).
2. Produce contents:
   - `read-cni-conf` set → read that file verbatim (the `cni-configuration`
     ConfigMap mounted at `/tmp/cni-configuration/cni-config`). Not rendered,
     not validated beyond being readable; it is also parsed on demand to
     expose `mtu` (an MTU override source) and `chaining-mode`.
   - else `cni-chaining-target` set → find the target network (section 5.2)
     and splice the chained entry into it.
   - else → render the template for `lower(cni-chaining-mode)` from section
     4.5. Unknown mode → error `invalid CNI chaining mode: <x>` (retried
     forever, status Failure — the node stays NotReady, which is the correct
     outcome for a misconfiguration).
3. `mkdir -p dir`; if the existing file is byte-identical do nothing; else
   write atomically (temp file in `dir` + rename), mode **0600**.
4. Always rename the legacy `05-cilium.conf` (if `file` is not that name)
   to `05-cilium.conf.cilium_bak`.
5. If `cni-exclusive`: for every regular file in `dir` other than `file`
   whose name ends in `.conf`, `.conflist` or `.json`, rename to
   `<name>.cilium_bak`. Never delete. Never touch `*.cilium_bak`.
6. Status → `Ok: successfully wrote CNI configuration file to <path>` or
   `Failure: failed to write CNI configuration file <path>: <err>`. Exposed
   as `cni-file` in `GET /healthz` (`StatusResponse.cni-file`) and
   `cni-chaining` reports the mode.

A directory watcher (inotify on `dir`) re-triggers the controller on any
event **only when `cni-exclusive` is true**; without exclusivity another
component (Istio CNI) is allowed to rewrite our file and we must not fight
it. Watcher setup failure is a warning.

Stop: the controller is removed; the file is **not** deleted by the agent.
Removal is the `preStop` hook's job (section 3.12) and only when
`cni-uninstall=true`.

### 3.12 Install and uninstall of the binary

Installation is an init container (`install-cni-binaries`, drops all
capabilities, mounts `cni.binPath` at `/host/opt/cni/bin`). flowsdn provides
it as the agent image with subcommand `flowsdn-agent cni install` (inventory
15 recommends a subcommand over a shell script; `scratch` images have no
shell). Behaviour, identical to the reference script:

- `HOST_PREFIX` (default `/host`), `CNI_DIR` (default
  `$HOST_PREFIX/opt/cni`); `mkdir -p $CNI_DIR/bin`.
- Copy `loopback` if `OVERWRITE_LOOPBACK=true` or absent; failure is
  ignored (rarely needed). The reference builds `loopback` from
  `containernetworking/plugins` with `CGO_ENABLED=0`; flowsdn ships the
  upstream binary unchanged in the image (Apache-2.0, NOTICE entry) — open
  decision 12.2 for a Rust loopback.
- Copy the plugin to `$CNI_DIR/bin/.cilium-cni.new`, then `rename` to
  `$CNI_DIR/bin/cilium-cni` (atomic replace of a binary the kubelet may be
  executing right now) unless `OVERWRITE_CILIUM=false` and it exists.
  **DEVIATION**: additionally install `flowsdn-cni` as a hard link to the
  same file so operators can tell which implementation is present; the
  conflist keeps `type: cilium-cni` (see 12.1).

Uninstall is the agent pod's `preStop` (`flowsdn-agent cni uninstall`):
if the config key `cni-uninstall` (read from `/tmp/cilium/config-map/
cni-uninstall`) is not `true`, exit. If `CILIUM_CUSTOM_CNI_CONF != true`,
delete regular files in `$CNI_CONF_DIR` (default `$HOST_PREFIX/etc/cni/net.d`)
whose name contains `cilium` and ends in `.conf` or `.conflist`. Foreign
`*.cilium_bak` files are left for the operator. The binary is never removed.

## 4. Data model

### 4.1 Network configuration (stdin JSON, `NetConf`)

Standard CNI fields: `cniVersion`, `name`, `type` (= `cilium-cni`),
`capabilities{}`, `ipam{type,…}`, `dns{}`, `prevResult` (raw; only meaningful
in chains), plus runtime-injected `args`, `runtimeConfig` (ignored). Plugin
fields:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enable-debug` | bool | false | debug logging; reference also starts gops — flowsdn does not (**DEVIATION**, no Go runtime) |
| `log-format` | string | `text-ts` | `text`, `text-ts`, `json`, `json-ts` (section 8) |
| `log-file` | string | `""` | append log here in addition to stderr |
| `chaining-mode` | string | `""` | explicit chainer name (3.9) |
| `mtu` | int | 0 | consumed only by the agent's config manager (`read-cni-conf`) as an MTU override source; the plugin ignores it |
| `enable-route-mtu` | bool | false | generic-veth chainer: rewrite sandbox route MTUs to `route-mtu` |
| `ipam` | object | — | standard `type` plus the `IPAMSpec` fields (`07-ipam`: `pool`, `pre-allocate`, `min-allocate`, `max-allocate`, `max-above-watermark`, …) — the spec fields are parsed for cloud conflists but unused by the plugin |
| `eni`, `azure`, `alibaba-cloud` | object | — | cloud node specs accepted in conflists written by the operator for CiliumNode bootstrap; parsed, unused by the plugin |

A conflist passed whole (only via `read-cni-conf`) is `{ "plugins": [ NetConf… ] }`.

### 4.2 CNI_ARGS

| Key | Used for |
|---|---|
| `K8S_POD_NAME` | IPAM owner `<ns>/<name>`, `k8s-pod-name`, log field `k8sPodName` |
| `K8S_POD_NAMESPACE` | as above, `k8s-namespace` |
| `K8S_POD_UID` | `k8s-uid` (the agent uses it to detect a stale pod informer entry) |
| `K8S_POD_INFRA_CONTAINER_ID` | accepted, ignored (`CNI_CONTAINERID` is authoritative) |
| `IgnoreUnknown` | accepted; unknown keys are always ignored |

All optional; without `K8S_POD_*` the owner is `/` and the agent falls back
to non-k8s labels (`reserved:init`).

### 4.3 Agent configuration consumed (`GET /config` → `status`)

`addressing{ipv4{ip,enabled,alloc-range,address-type},ipv6{…}}`,
`ipam-mode`, `datapath-mode`, `route-mtu`, `device-mtu`, `device-headroom`,
`device-tailroom`, `gro-max-size`, `gso-max-size`, `gro-max-size-v4`,
`gso-max-size-v4`, `masquerade-protocols{ipv4,ipv6}`,
`ip-local-reserved-ports`, `enable-route-mtu-for-cni-chaining`,
`install-uplink-routes-for-delegated-ipam`,
`packetization-layer-pmtud-mode`, `enable-bbr-host-namespace-only`. The agent
computes `ip-local-reserved-ports` as: the literal
`container-ip-local-reserved-ports` unless it is `auto`; `auto` → empty
unless the transparent DNS proxy is on, then the WireGuard listen port
(51871) if WireGuard is enabled plus the tunnel port if tunnelling is on,
comma-joined.

### 4.4 Result (stdout on ADD, CNI 1.x shape before version conversion)

```
{
  "cniVersion": "<requested>",
  "interfaces": [
    {"name": "lxc<12hex>", "mac": "<host mac>"},                   // index 0, omitted mac in L3 netkit
    {"name": "<CNI_IFNAME>", "mac": "<pod mac>", "sandbox": "<CNI_NETNS>"}   // index 1
  ],
  "ips": [ {"address": "<v6>/128", "gateway": "<router v6>", "interface": 1},
           {"address": "<v4>/32",  "gateway": "<router v4>", "interface": 1} ],
  "routes": [ {"dst": "<router v6>/128"}, {"dst": "::/0", "gw": "<router v6>", "mtu": N},
              {"dst": "<router v4>/32"},  {"dst": "0.0.0.0/0", "gw": "<router v4>", "mtu": N} ],
  "dns": {}
}
```

IPv6 entries precede IPv4 when both are present. `dns` is always empty (the
kubelet configures pod DNS). Chained ADD returns the received `prevResult`
(possibly with a patched MAC).

### 4.5 Conflist templates written by the agent

Rendered with `Debug` = agent `debug`, `LogFile` = `cni-log-file`,
`ChainingMode` = `cni-chaining-mode`; string values JSON-escaped.
`cniVersion` is **1.0.0** (inventory 06 quoted 0.3.1 from an older tag; the
v1.20.1 templates say 1.0.0).

`none`:
```
{"cniVersion":"1.0.0","name":"cilium","plugins":[
  {"type":"cilium-cni","enable-debug":<Debug>,"log-file":"<LogFile>"}]}
```
`portmap` (HostPort without KPR):
```
{"cniVersion":"1.0.0","name":"portmap","plugins":[
  {"type":"cilium-cni","enable-debug":<Debug>,"log-file":"<LogFile>"},
  {"type":"portmap","capabilities":{"portMappings":true}}]}
```
`flannel`:
```
{"cniVersion":"1.0.0","name":"flannel","plugins":[
  {"type":"flannel","delegate":{"hairpinMode":true,"isDefaultGateway":true}},
  {"type":"portmap","capabilities":{"portMappings":true}},
  {"type":"cilium-cni","chaining-mode":"flannel","enable-debug":<Debug>,"log-file":"<LogFile>"}]}
```
Chained entry (spliced, section 5.2):
```
{"type":"cilium-cni","chaining-mode":"<ChainingMode>","enable-debug":<Debug>,"log-file":"<LogFile>"}
```
Whitespace of the reference templates (multi-line, two-space indent) SHOULD
be reproduced so that a flowsdn agent and an upstream agent alternating on a
node do not rewrite the file on every start (the byte-compare in 3.11 step
3).

### 4.6 Agent API exchanged

| Call | Request | Success | Failure handling |
|---|---|---|---|
| `GET /config` | — | 200 `DaemonConfiguration{status}` | fatal (3.3) |
| `POST /ipam?owner=<ns>/<pod>` with header `expiration: true` (`family`, `pool` empty) | — | 201 `IPAMResponse{address{ipv4,ipv4-pool-name,ipv4-expiration-uuid,ipv6,…}, ipv4{ip,gateway,cidrs[],master-mac,expiration-uuid,interface-number,skip-masquerade}, ipv6{…}, host-addressing{ipv4{ip,enabled,…},ipv6{…}}}` | 403 / 502 fatal |
| `DELETE /ipam/{ip}?pool=<pool>` | — | 200 | 400/403/404/500/501 logged at warn |
| `PUT /endpoint/{id}` `id=cni-attachment-id:<cid>:<ifname>` | `EndpointChangeRequest` (below) | 201 `Endpoint{id,status{networking{mac,addressing,…},…}}` | 400 invalid, 409 exists, 429, 500 failed, 503 not ready → fatal |
| `DELETE /endpoint/{id}` | — | 200; 206 (deleted with errors) | 400 invalid, 404 not found, 429 → warn, continue; 503 → queue (5.1) |
| `DELETE /endpoint` | `EndpointBatchDeleteRequest{container-id}` | 200/206 | as above; used when the interface name is unknown |
| `GET /endpoint/{id}/healthz` | — | 200 `EndpointHealth{overallHealth,…}` | CHECK codes 100/101 |
| `GET /healthz` | — | 200 | STATUS code 50 |

`EndpointChangeRequest` fields sent by the primary ADD (all others omitted):
`container-id`, `container-netns-path`, `container-interface-name`,
`interface-name`, `interface-index`, `parent-interface-index` (ENI),
`mac`, `host-mac` (L2 modes), `addressing{ipv4, ipv4-pool-name,
ipv4-expiration-uuid, ipv6, ipv6-pool-name, ipv6-expiration-uuid}`,
`k8s-pod-name`, `k8s-namespace`, `k8s-uid`, `labels: []`, `state:
"waiting-for-identity"`, `sync-build-endpoint: true`, `netns-cookie`
(decimal string), `datapath-configuration{external-ipam}` (delegated only),
`properties{skip-masquerade-v4|v6: true}` (when IPAM says so). The
expiration UUIDs let the agent stop the allocation's expiry timer when the
endpoint is accepted — an ADD that dies between IPAM and PUT leaks nothing
(`07-ipam`). The agent adds `install-endpoint-route`, `require-egress-prog`,
`require-routing=false` itself when `enable-endpoint-routes` is on; the
plugin MUST NOT set them (spec 08 owns the merge).

### 4.7 Deletion queue on disk

- Directory `/var/run/cilium/deleteQueue/`, mode 0755, created by whichever
  side gets there first.
- Lockfile `/var/run/cilium/deleteQueue/lockfile`, `flock(2)`.
- Entry file `<sha256hex(contents)>.delete`, mode 0644, contents one of:
  - JSON `EndpointBatchDeleteRequest` `{"container-id":"<cid>"}` when the
    interface name is unknown (batch delete of every endpoint of that
    container), or
  - the bare string `<cid>:<ifname>` (an attachment id without prefix) for
    a single endpoint.
  The agent distinguishes by attempting JSON decode first.
- Hard cap **256** entries; the 257th enqueue fails (`deletion queue
  directory … has too many entries; aborting`) and DEL returns an error so
  the kubelet retries later instead of the queue growing without bound.

### 4.8 Link configuration (plugin-internal, mirrors the agent's connector)

`LinkConfig{endpoint_id: String, host_ifname, peer_ifname, peer_netns:
Option<NetNs>, gro_v6, gso_v6, gro_v4, gso_v4: u32, device_mtu: u32,
device_headroom, device_tailroom: u16}`; `LinkPair{host: LinkInfo, peer:
LinkInfo, mode}` with `LinkInfo{index, name, mac: Option<[u8;6]>}`.

## 5. Algorithms

### 5.1 Endpoint delete with offline fallback

Goal: an endpoint deletion requested while the agent is down or restarting
must not be lost, and must not race the agent's own restore/replay.

```
delete(cid, ifname):
  (fallback, err) = try_delete()
  if !fallback: return err                       // success, or agent-side 4xx/2xx
  lock = shared_flock(queue lockfile, timeout 1.5 s)   // mkdir -p first
  if lock fails: return ErrClientFailure
  (fallback, err) = try_delete()                 // re-check under the lock
  if fallback: enqueue(cid, ifname) or ErrClientFailure
  unlock; return err

try_delete():
  if no client yet:
     connect with 1.5 s budget (GET /config loop, 500 ms steps)
     on failure:
        if dir(socket) exists && socket does not exist:   // agent is bootstrapping
            up to 3 times: sleep 5 s, retry connect; log "Agent is starting up…"
        if still no client: return (fallback=true, err)
  if ifname == "": DELETE /endpoint {container-id: cid}
  else:            DELETE /endpoint/cni-attachment-id:<cid>:<ifname>
  503 → (true, err); any other error → (false, err); ok → (false, nil)
```

Agent side (`08-endpoint-agent-api`, replay job `cni-deletion-queue`): after
endpoints are restored into the manager (fence
`endpoint-restore.restored-into-manager`), take the **exclusive** flock
(mkdir first; if the lock cannot be taken, log a warning and proceed — a
missed deletion is recoverable by GC, a stuck agent is not), glob
`*.delete`, for each: JSON decode → `DeleteEndpointByContainerID`, else
`DeleteEndpoint(<contents>)`; remove the file regardless of outcome; then
hold the lock until the API server is listening (fence `api-ready` has
`delete-queue-lock-held`), then release. Correctness argument: while the
socket exists the plugin talks to the API and never touches the queue;
while it does not exist the plugin's shared lock excludes the agent's
exclusive one, so a file is either processed by replay or written after
replay finished and the API is up — in which case the plugin's second
`try_delete` under the lock succeeds and no file is written. The
"bootstrapping" heuristic (dir present, socket absent) only reduces lock
contention during a restart.

### 5.2 Locating a network for chaining (`cni-chaining-target`)

List regular files in the conflist directory with extensions `.conflist`,
`.conf`, `.json`, `.cilium_bak`; sort by name; skip our own output file.
For each: parse as JSON object; skip unreadable/invalid (warn); read `name`;
accept if `cni-chaining-target == "*"` or equals `name`. If the object has a
non-empty `plugins[]` it is a conflist — use its bytes; otherwise wrap the
single plugin: `{"name": <target>, "cniVersion": <its cniVersion>,
"plugins": [<object>]}`. No match → error `no matching CNI configurations
found (will retry)` (controller retries; the node stays NotReady until the
other CNI has installed its file). Then splice: find the index of the first
`plugins[].type == "cilium-cni"`; set `plugins[<index>]` to the chained
entry, or append when absent. The edit MUST be a raw-JSON path set that
leaves every other byte of the document untouched (field order, unknown
fields, `disableCheck`, …), because the owning plugin may compare or
re-parse its own file. Including `.cilium_bak` in the search is what makes
`cni-exclusive=true` compatible with chaining: our previous run renamed the
target, and we still find it.

### 5.3 Host-side per-interface routing (cloud IPAM and delegated uplink)

Inputs: pod IP, `gateway`, coalesced `cidrs` (minimal covering set, per
family), `master-mac`, `interface-number`, `ipam-mode`, `masquerade` for the
family, `device-mtu`. Installed on the host by the plugin (owned and removed
by the agent on endpoint delete):

| Object | Value |
|---|---|
| ingress rule | priority **20**, `to <pod ip>/32`, lookup `main`, proto `kernel` |
| egress rules | priority **111** (`RulePriorityEgressv2`; **110** in compat mode when the agent reports the legacy priority — `07-ipam`), `from <pod ip>/32` `to <cidr>` for each coalesced CIDR when masquerading is on, else a single `from <pod ip>/32` without `to`; lookup table `10 + interface-number` (`RouteTableInterfacesOffset`) |
| per-interface table `10 + n` | `<gateway>/32 dev <uplink> scope link`, `default via <gateway> dev <uplink>`; IPv6: `<gateway>/128` + `::/0 via` |
| uplink | resolved from `master-mac` among non-slave links; its MTU set to `device-mtu` |

`interface-number` is `"0"` for delegated IPAM (the delegate cannot tell us),
so all delegated pods share table 10. Detailed semantics, ENI compat mode
and the delete side are `07-ipam`'s.

### 5.4 Result version conversion

Internal representation is CNI 1.1.0. Emitting for `cniVersion` V:
`1.0.0`/`1.1.0` → as is (1.0.0 drops route `mtu`, `table`, `scope`);
`0.3.0`–`0.4.0` → same shape without 1.x-only fields; `0.1.0`/`0.2.0` →
`{ip4:{ip,gateway,routes[]}, ip6:{…}, dns}` taking the first IP per family
and routes by family. `prevResult` inbound is converted the other way with
`interface` indexes preserved where they exist.

## 6. Configuration

### 6.1 Agent keys (config registry, spec 00)

| Key | Type | Default | Effect |
|---|---|---|---|
| `write-cni-conf-when-ready` | path | `""` | enable the config manager; dir+file of the output |
| `read-cni-conf` | path | `""` | copy this file instead of rendering; also MTU/chaining-mode source |
| `cni-chaining-mode` | `none\|aws-cni\|flannel\|generic-veth\|portmap\|azure` | `none` | template / chained entry; empty normalises to `none`, or to `generic-veth` when a target is set |
| `cni-chaining-target` | network name or `*` | `""`; `aws-cni` when mode is `aws-cni` | splice target |
| `cni-exclusive` | bool | `false` (Helm sets `true`) | rename foreign configs; enables the directory watcher |
| `cni-external-routing` | bool | `false`; `true` when mode is `aws-cni` | chained plugin owns host routes → `install-endpoint-route=false` |
| `cni-log-file` | path | `/var/run/cilium/cilium-cni.log` | rendered into `log-file` |
| `debug` | bool | false | rendered into `enable-debug` |
| `cni-uninstall` | bool | false | preStop removes the conflist |
| `container-ip-local-reserved-ports` | `auto` or `p[,p-q]*` | `auto` | reserved ports written into every pod netns (4.3); validated by regex `^(\d+(-\d+)?)(,\d+(-\d+)?)*$` |
| `install-uplink-routes-for-delegated-ipam` | bool | false | 3.4 step 9 for delegated IPAM |
| `enable-route-mtu-for-cni-chaining` | bool | false | generic-veth route MTU rewrite |
| `packetization-layer-pmtud-mode` | `""\|1\|2` | `""` | pod netns `tcp_mtu_probing` |
| `enable-bbr-host-namespace-only` | bool | false | pod netns `tcp_congestion_control=cubic` |
| `datapath-mode` | `veth\|netkit\|netkit-l2\|auto` | `veth` | connector; reported resolved in `GET /config` |
| `enable-endpoint-routes` | bool | false | agent installs host routes (not the plugin) |
| `ipam` | mode | `cluster-pool` | `delegated-plugin` switches the plugin to 3.10 |

Accepted and ignored: none specific to this area. `cni.iptablesRemoveAWSRules`
/ `poststart-eni.bash` (removes AWS VPC-CNI iptables rules) has no flowsdn
equivalent — **DEVIATION** per ADR-0003: flowsdn installs no iptables and
does not edit anyone else's; the operator must disable the VPC CNI's SNAT
rules (`AWS_VPC_K8S_CNI_EXTERNALSNAT=true`) when chaining. Documented in the
Helm mapping.

### 6.2 Plugin-side fields

Section 4.1. Environment: `CILIUM_SOCK` (socket path override), `CNI_*` per
spec. No files are read besides stdin, the socket, `/proc/sys`, the netns
path and the deletion queue.

### 6.3 Helm mapping (`cni.*`, inventory 15)

`install` → run the install init container; `uninstall` → `cni-uninstall`;
`chainingMode` → `cni-chaining-mode`; `chainingTarget` →
`cni-chaining-target`; `exclusive` → `cni-exclusive`; `logFile` →
`cni-log-file`; `customConf` → mount `configMap[configMapKey]` at
`confFileMountPath/cni-config` and set `read-cni-conf` to it, and set
`CILIUM_CUSTOM_CNI_CONF=true` for preStop; `confPath` →
`hostConfDirMountPath` hostPath and `write-cni-conf-when-ready =
<hostConfDirMountPath>/05-cilium.conflist`; `binPath` → hostPath for the
installer; `enableRouteMTUForCNIChaining` →
`enable-route-mtu-for-cni-chaining`; `resources` → init container
resources.

## 7. Failure modes

| Failure | Where | Behaviour |
|---|---|---|
| Agent socket absent / connection refused | ADD | retry 500 ms up to 30 s, then error 999 `unable to connect to Cilium agent: … Is the agent running?`; kubelet retries sandbox creation |
| Agent up, API returns 503 (not ready) | ADD `PUT /endpoint` | fatal, rollback; kubelet retries |
| Agent down | DEL | offline queue (5.1); exit 0 after queueing; error only if lock/write fails |
| Agent down | CHECK | code 11 try-again-later |
| Agent down | STATUS | code 50; node NotReady |
| Queue has > 256 entries | DEL | error, kubelet retries later |
| IPAM exhausted / pool missing | ADD | `POST /ipam` 502 → fatal; nothing to roll back |
| `PUT /endpoint` 400 "already exists" (duplicate ADD for same cid:ifname) | ADD | fatal, rollback releases the *new* IP and deletes the *new* veth; the existing endpoint is untouched (its device has a different name only if `CNI_IFNAME` differs — same name means the reference and flowsdn both deleted the old sandbox interface at step 4, leaving the old endpoint on a dead device until GC; open decision 12.5) |
| `PUT /endpoint` 400 "IP already in use" | ADD | fatal, rollback |
| Regeneration fails or exceeds the agent's bound | ADD | 500 or connection cut at 60 s → rollback; agent removes the endpoint without releasing the IP (the plugin releases it) |
| veth create `EEXIST` on `lxc<hash>` | ADD | fatal: a previous endpoint for the same `cid:ifname` still exists — its DEL has not happened; rollback releases IP; kubelet retries |
| Sandbox netns gone | ADD | fatal at step 3 |
| Sandbox netns gone | DEL | exit 0 |
| `SO_NETNS_COOKIE` unsupported | ADD | cookie `"0"`, info log; socket-LB features needing the cookie degrade (spec 04) |
| `tcp_base_mss` sysctl missing (< 5.11) | ADD | warning |
| `cubic` unavailable | ADD | fatal (explicit config demands it) |
| MAC annotation unparsable | agent | 400 → fatal |
| `prevResult` present, no chaining | ADD | fatal with the fixed message |
| Unknown `chaining-mode` | all verbs | fatal |
| Delegate plugin missing from `CNI_PATH` | ADD | `failed to invoke delegated plugin ADD for IPAM` fatal; DEL returns the delegate error (retryable) |
| `cni-chaining-target` network not yet present | agent | controller retries every 10 s (backoff), status Failure, node NotReady |
| Conflist dir unwritable | agent | status Failure, retries |
| Foreign plugin rewrites our file | agent | rewritten on next run only with `cni-exclusive` (watcher) |
| Agent restart between IPAM and PUT | ADD | PUT fails → rollback release; if release also fails the expiration timer (`expiration=true`) frees the IP (`07-ipam`) |
| Plugin killed by runtime timeout mid-ADD | — | no rollback runs: IP expires via timer; veth `lxc<hash>` orphaned until the runtime's DEL (agent 404 → plugin deletes the sandbox side; host side removed when the agent's link GC or next ADD with the same hash fails `EEXIST` → open decision 12.5) |
| Mixed versions: upstream `cilium-cni` binary with flowsdn agent, or vice versa | — | works by contract (section 2); the queue file formats and API models are identical |

## 8. Observability

**Plugin logging.** Default sink stderr (the runtime captures it into its
own log); `log-file` appends to a file with rotation (reference: size-based,
7 compressed backups; flowsdn: same cap — the exact size threshold is open
decision 12.6). Format `text-ts` (default): `time=<RFC3339Nano> level=<lvl>
msg="…" subsys=cilium-cni k=v …`; `text` drops `time`; `json`/`json-ts` are
the JSON equivalents. Level `debug` when `enable-debug`. Every record of one
invocation carries `eventUUID` (fresh UUIDv4), `containerID`, `netNSName`,
`interface`, `args`, `path`; after argument parsing also `k8sNamespace` and
`k8sPodName`. Field names are the reference `logfields` names so
`bugtool` greps keep working. `cilium-cni.log` is collected by bugtool
(inventory 06).

**CNI error codes** (the `code` field of the error object on stdout; the
process exit status is 1 for every error and 0 otherwise).

| Code | Name | Verb | Meaning |
|---|---|---|---|
| 1 | `ErrIncompatibleCNIVersion` | any | unsupported `cniVersion`; STATUS/GC below 1.1.0 |
| 4 | `ErrInvalidEnvironmentVariables` | any | missing required `CNI_*`, unknown `CNI_COMMAND` |
| 7 | `ErrInvalidNetworkConfig` | CHECK, STATUS | `InvalidNetworkConfig`, `InvalidLoggingConfig`, `InvalidArgs` |
| 11 | `ErrTryAgainLater` | CHECK | `DaemonDown` |
| 50 | `CniErrPluginNotAvailable` | STATUS | `DaemonDown`, `DaemonHealthzFailed` |
| 100 | `CniErrHealthzGet` | CHECK | `HealthzFailed` |
| 101 | `CniErrUnhealthy` | CHECK | `Unhealthy` |
| 999 | `ErrInternal` | ADD, DEL | any other error; `msg` is the error text |

**Agent side.** Controller `write-cni-file` metrics
(`cilium_controllers_runs_total{status}`, `…_failing`), status fields
`cni-file` (message + state) and `cni-chaining` in `GET /healthz`; log
lines `Wrote CNI configuration file`, `Renaming non-Cilium CNI configuration
file`, `Found CNI network for chaining`, `Generated chained cilium CNI
configuration`. Deletion queue replay logs per file at error on failure.
Endpoint creation itself is observed through spec 08's metrics
(`cilium_endpoint_regenerations_total`, `cilium_endpoint_regeneration_time_stats_seconds`)
and the `cilium_ipam_*` metrics of spec 07; the plugin adds no metrics
endpoint (it lives milliseconds).

## 9. Test plan

Reference tests kept as a checklist (`plugins/cilium-cni/{types,lib,
chaining/api}/*_test.go`, `daemon/cmd/cni/*_test.go`,
`pkg/datapath/connector/*_test.go`) plus CNI conformance and kubelet cases.

Unit (no root):

- [ ] NetConf parsing: plain conf; conflist with `cilium-cni` entry
      selected; ENI/Azure conflists with `ipam` spec fields and cloud
      objects; `ipam.type` extraction; malformed JSON error; unknown fields
      ignored (`TestReadCNIConf*`).
- [ ] `prevResult` conversion from every supported version to 1.x and back.
- [ ] `CNI_ARGS` parsing with unknown keys, empty string, malformed pair.
- [ ] Chainer registry: `cilium` rejected, duplicate rejected; resolution
      rule for explicit mode, implicit by name, `portmap` name, plain
      `cilium` (`TestRegistration`, `TestNonChaining`).
- [ ] Host ifname hash: `lxc` + 12 hex of sha256(`cid:ifname`); temp name
      `tmp` + 5; altname string.
- [ ] Random MAC: bit 1 of byte 0 set, bit 0 clear, 10⁴ samples.
- [ ] Container route set per family with MTU; sort order most-specific
      first; result `ips[].interface == 1`; IPv6 before IPv4.
- [ ] Delegated IPAM translation: `master-mac` from `mac`, from `name`,
      absent; IP with and without prefix; family disabled in agent
      addressing → skipped.
- [ ] Deletion client state machine (`TestDeletionFallbackClient`): client
      creation fails never/once/always; delete returns 503 never/once/twice/
      always; assert queue file presence, contents (JSON vs attachment id),
      count, `ErrClientFailure` only on lock/write failure; 257th entry
      fails.
- [ ] Queue lock (`TestQueueLock`): shared lock acquired while no exclusive
      holder; times out at 1.5 s while the agent holds exclusive; re-check
      under lock avoids a stale file.
- [ ] Conf manager rendering (`TestRenderCNIConfUnchained`): each template
      with debug on/off and a log path containing `"`; unknown mode error.
- [ ] Conf manager chaining (`TestRenderCNIConfChained`): no network →
      error; AWS conflist → entry appended, other bytes preserved; conflist
      already containing `cilium-cni` → replaced in place; single `.conf`
      → wrapped into a list; `*` target picks the first by sorted name;
      `.cilium_bak` source found.
- [ ] `cni-exclusive` cleanup (`TestCleanupOtherCNI`): `.conf`,
      `.conflist`, `.json` renamed, own file and other extensions kept,
      legacy `05-cilium.conf` renamed even without exclusivity.
- [ ] Install (`TestInstallCNIConfFile`): byte-identical file not
      rewritten; changed file replaced atomically with mode 0600.
- [ ] Config normalisation (`TestConfig`): `aws-cni` implies target and
      external routing; target without mode → `generic-veth`; empty →
      `none`.
- [ ] Error object rendering for every row of the section 8 table; exit
      status 1 on every error path, 0 on success; about string on stderr
      when `CNI_COMMAND` is unset.

Privileged (kernel, netns sandbox):

- [ ] veth pair creation with all attributes; peer moved and renamed; altname
      present; `rp_filter` 0 on host side; MTU/GRO/GSO applied both ends
      (`TestPrivilegedSetupVethPair`, `TestPrivilegedNewLinkPair`,
      `TestPrivilegedConfigureLinkPair`).
- [ ] Link pair delete removes both ends (`TestPrivilegedLinkPairDelete`).
- [ ] netkit pair creation and buffer-margin validation on ≥ 6.7
      (`TestPrivilegedSetupNetkitPair`) — deferred with the connector.
- [ ] Sandbox configuration: addresses (v6 NODAD), routes idempotent on
      `EEXIST`, reserved ports merge, `disable_ipv6=0`, PMTUD sysctls,
      congestion control.
- [ ] Netns cookie read; `ENOPROTOOPT` path on a kernel without it (mock).
- [ ] Per-ENI rules/routes install (5.3) with coalesced CIDRs and masquerade
      on/off.
- [ ] Thread pinning: after `Do(netns)` the calling thread is back in the
      original namespace (compare `/proc/thread-self/ns/net` inode).
- [ ] Full ADD/DEL against a fake agent socket (record requests; return
      canned `IPAMResponse`/`Endpoint`): verify the exact request bodies of
      4.6, the result JSON, and rollback on injected failure at each step
      (IP released, veth gone, endpoint deleted where applicable).

E2E (kind / real cluster, `conformance-*` equivalents):

- [ ] CNI conformance against `containernetworking/cni` test harness for
      each version 0.1.0–1.1.0: ADD result shape, DEL idempotency, CHECK,
      STATUS, VERSION.
- [ ] Kubelet interaction: rapid ADD/DEL of 200 pods; DEL without ADD; two
      ADDs with the same `CNI_CONTAINERID`/`CNI_IFNAME` (second fails 400,
      first pod stays healthy — see 12.5); pod deleted while the agent is
      down → DEL exits 0, queue file present, agent restart drains it and
      the CEP is removed; ADD while the agent is restarting → succeeds
      within 30 s or kubelet retries.
- [ ] Dual-stack pod: two `ips[]`, IPv6 first, routes for both, both
      `DELETE /ipam` on rollback.
- [ ] `ipam=delegated-plugin` with `host-local` and `cni.customConf=true`
      (reference `conformance-delegated-ipam`): pod IPs from host-local
      ranges, DEL releases via host-local, STATUS proxies host-local STATUS,
      `install-uplink-routes-for-delegated-ipam` variant.
- [ ] `aws-cni` chaining (reference `conformance-aws-cni`): conflist splice
      into `10-aws.conflist`, generic-veth ADD, policy enforced, no routes
      changed, `enable-route-mtu-for-cni-chaining` rewrites MTUs.
- [ ] `flannel` and `portmap` templates: HostPort works with `portmap` when
      KPR is off.
- [ ] `cni-exclusive` renames a pre-existing foreign conflist; disabling it
      lets Istio CNI append to ours without a rewrite loop.
- [ ] Agent NotReady → no conflist → node NotReady; conflist appears only
      after `agent-ready`; `cni-uninstall=true` preStop removes it.
- [ ] Upstream `cilium-cni` binary against the flowsdn agent, and
      `flowsdn-cni` against an upstream agent, both pass the ADD/DEL cases.
- [ ] `datapath-mode=netkit` smoke (deferred with the connector).

## 10. Kernel and platform requirements

- **Namespace entry**: `setns(fd, CLONE_NEWNET)` on a pinned thread; open
  the original via `/proc/thread-self/ns/net` before switching and restore
  after. The thread that switched MUST NOT be returned to a pool: flowsdn
  runs each netns block on a dedicated OS thread that is joined (or on the
  main thread in a single-threaded binary). `/proc` must be mounted in the
  plugin's mount namespace (it runs on the host).
- **Netlink**: `NETLINK_ROUTE` — `RTM_NEWLINK` (veth with `VETH_INFO_PEER`;
  netkit `IFLA_NETKIT_*` deferred), `RTM_SETLINK` (`IFLA_MTU`, `IFLA_NET_NS_FD`,
  `IFLA_IFNAME` rename, `IFLA_ADDRESS`, `IFLA_TXQLEN`, `IFLA_GRO_MAX_SIZE`,
  `IFLA_GSO_MAX_SIZE`, `IFLA_GRO_IPV4_MAX_SIZE`, `IFLA_GSO_IPV4_MAX_SIZE`
  (6.3+), `IFLA_PROP_LIST`/`IFLA_ALT_IFNAME` (5.5+)), `RTM_DELLINK`,
  `RTM_GETLINK` dump, `RTM_NEWADDR` (`IFA_F_NODAD`), `RTM_NEWROUTE`
  (`RTA_GATEWAY`, `RTA_METRICS/RTAX_MTU`, `RTA_TABLE`), `RTM_NEWRULE`
  (`FRA_PRIORITY`, `FRA_SRC/DST`, `FRA_TABLE`, `FRA_PROTOCOL`), `RTM_GETADDR`,
  `RTM_GETROUTE`, `RTM_GETRULE`.
- **Sockets**: `AF_INET/SOCK_STREAM` for `SO_NETNS_COOKIE` (5.14+; optional),
  `AF_UNIX/SOCK_STREAM` HTTP/1.1 client.
- **sysctl paths** (procfs `/proc/sys/`): `net/ipv4/conf/<dev>/rp_filter`,
  `net/ipv6/conf/all/disable_ipv6`, `net/ipv4/ip_local_reserved_ports`,
  `net/ipv4/tcp_congestion_control`, `net/ipv4/tcp_base_mss` (5.11+),
  `net/ipv4/tcp_mtu_probing`, `net/ipv4/tcp_mtu_probe_floor` (5.11+).
- **Filesystem**: `flock(2)` on the queue lockfile; `rename(2)` atomicity
  within one filesystem for the conflist and binary install.
- Minimum kernel: as `docs/kernel-requirements.md` (6.6 general, 6.12
  stormcos); nothing here needs more, netkit aside (6.7 / 6.13).
- x86-64 and arm64: no architecture-specific code; `IFNAMSIZ` 16 on both.

## 11. Rust design notes

**Crates.** `flowsdn-cni` (binary), `flowsdn-connector` (link pair, shared
with the agent which needs the same code for infra/health endpoints),
`flowsdn-netns` (setns helper), `flowsdn-api-client` (typed client over the
unix socket, shared with `flowsdn-dbg`), `flowsdn-api-models` (serde structs
generated once from `api/v1/openapi.yaml`, spec 08). The agent-side config
manager and deletion-queue replay live in the agent crate and reuse
`flowsdn-cni-conf` (template rendering, splice, cleanup — pure functions,
unit-tested without a filesystem via a `Fs` trait).

**Startup budget.** The kubelet execs the plugin once per sandbox
operation; target < 5 ms from exec to first syscall and a stripped static
binary well under 5 MB (`musl`, `panic=abort`, `lto=fat`,
`codegen-units=1`, `opt-level="s"` acceptable). Therefore: **no tokio**.
Everything is synchronous: blocking unix-socket HTTP/1.1 via a minimal
client (`ureq` with a unix transport, or `hyper` on a hand-rolled
current-thread executor — prefer the former; the plugin makes 3–5 requests),
blocking netlink via `netlink-sys` + `netlink-packet-route` (the async
`rtnetlink` crate pulls tokio; use its packet types only), `nix` for
`setns`, `flock`, `getsockopt`, `serde_json` for stdin/stdout/models, `sha2`
for the ifname hash, `rand` (`getrandom`) for MACs, `uuid` v4 for the event
id. Logging: `tracing` with a compact custom formatter emitting the slog
layouts of section 8; no `tracing-appender` background thread — write
synchronously, rotate by size at open.

**Namespaces.** `NetNs::open(path) -> NetNs(OwnedFd)`; `NetNs::enter(|| …)`
spawns a `std::thread` that does `setns`, runs the closure, and exits (never
restores — a fresh thread per entry is cheaper and safer than restore
bookkeeping; the reference restores because Go's scheduler reuses threads).
The closure returns `Result<T, Error>`; netlink sockets MUST be opened
*inside* the closure (a socket is bound to the netns it was created in).

**Errors.** One `CniError { code: u32, msg: String, details: String }`
implementing `From` for every internal error (→ 999) and constructed
explicitly for the coded cases. `main` prints it as JSON and exits 1.

**Rollback.** A `Rollback` stack of `Box<dyn FnOnce()>` pushed after each
successful step; drained in reverse on error, each in `catch_unwind`, each
logged. Nothing runs on success.

**Connector API.** `Connector::create(mode, LinkConfig) -> Result<LinkPair>`,
`LinkPair::delete()`, `Mode::{Veth, Netkit, NetkitL2}` with
`is_layer2()`. `IFLA_NETKIT_*` constants and a `Netkit` link-info encoder as
a local module until `netlink-packet-route` grows them (inventory 03).

**Agent client.** Same crate the agent tests use; `connect_with_budget(dur)`
implements the 500 ms poll on `GET /config`. Typed errors expose the HTTP
status so DEL can distinguish 503 (queue) from 404 (ignore).

**Agent install subcommand.** `flowsdn-agent cni install|uninstall` as in
3.12; embed the plugin binary and `loopback` in the agent image at
`/opt/cni/bin/` and `/cni/loopback`.

**Testing hooks.** The four extension hooks of the reference
(`OnConfigReady`, `OnIPAMReady`, `OnLinkConfigReady`,
`OnInterfaceConfigReady`) exist for downstream forks; flowsdn provides the
same four as a `trait Hooks` with default no-op methods, wired at compile
time, so the ADD function can be tested with a recording implementation.

## 12. Open decisions

1. **Binary name.** Options: (a) install only `cilium-cni` and write
   `type: cilium-cni` (maximum compatibility with custom conflists and the
   upstream migration story); (b) `flowsdn-cni` everywhere and require users
   to change custom conflists; (c) install both names, write `cilium-cni`.
   Recommendation: (c) now, revisit (b) at 1.0 when a Helm major can carry
   the change. Nominative use of the name is covered by `docs/licensing.md`.
2. **`loopback` plugin.** Ship the upstream Go binary (Apache-2.0, NOTICE
   entry; violates the spirit of "one static Rust binary" but is 2 MB and
   rarely used) or write the 60-line Rust equivalent in `flowsdn-cni`
   (`type: loopback` dispatch on `argv[0]`/conf `type`). Recommendation:
   Rust, as a second entry point of the same binary, after M1.
3. **CNI GC verb.** Not implemented by the reference. Implementing it would
   let flowsdn delete endpoints whose attachment is not in
   `cni.dev/valid-attachments` and replace part of the endpoint GC.
   Recommendation: defer; keep the `ErrIncompatibleCNIVersion` answer.
4. **CHECK depth.** Add MTU and route verification to CHECK. Cheap, but a
   stricter CHECK can make a runtime tear down pods after an agent MTU
   change. Recommendation: verify MTU and the two routes, but only report
   (debug log) until conformance behaviour of runtimes is understood.
5. **Duplicate ADD for an existing `cid:ifname`.** Reference behaviour is a
   400 with a leaked veth until GC when `CNI_IFNAME` matches. Options: (a)
   keep; (b) make the plugin treat "endpoint exists" as success and return
   the existing endpoint's addressing (idempotent ADD, which CNI 1.1.0
   encourages); (c) delete the old endpoint first. Recommendation: (b) when
   the existing endpoint's netns cookie matches the current sandbox,
   otherwise (c). Needs `GET /endpoint/cni-attachment-id:…` before PUT and a
   spec 08 change to expose the cookie.
6. **Log rotation threshold.** The reference caps at 7 compressed backups
   with the hook's default size. Fix a size (recommendation 100 MB) in this
   spec once the log volume of a busy node is measured.
7. **Rollback deletes the endpoint (3.4.1 DEVIATION).** Confirm with spec 08
   that `DELETE /endpoint` on an endpoint whose first regeneration just
   completed has no side effect on other endpoints (policy map
   recomputation is per endpoint; identity release is refcounted).
   Recommendation: keep the deviation.
8. **`container-netns-path` semantics.** The plugin reports
   `/var/run/cilium/netns/<basename>`; the reference agent does not create
   that mount at this tag (field kept for the health/infra endpoints).
   Decide in spec 08 whether flowsdn's agent bind-mounts sandbox namespaces
   there (useful for re-entering pods after a plugin crash) or the field is
   dropped from the request.

Implementation clarification (2026-09-09): expiration is an HTTP header,
not a query parameter. Confirmed against reference `api/v1/openapi.yaml`
`ipam-expiration` at the pinned reference commit; aligns this spec with
spec 07 §3.2. No executable reference code was copied.

Implementation clarification (2026-09-09): endpoint health uses camel-case
`overallHealth` and the enum `OK`, `Bootstrap`, `Pending`, `Warning`, `Failure`,
`Disabled`. Confirmed against pinned reference `api/v1/openapi.yaml` and
`api/v1/models/endpoint_health_status.go`; aligns with spec 08 §4.5. Missing
or malformed health responses are retrieval errors, never healthy results.
