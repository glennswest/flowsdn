# ADR-0024: The L7 proxy is a Rust proxy in the agent; no Envoy, no xDS

Date: 2026-11-25. Status: accepted.
Issue: [#563](https://github.com/glennswest/flowsdn/issues/563) (master's ruling on #543).
Supersedes: ADR-0015's "Envoy replacement" section (#262), ADR-0001's Envoy
consequence, and spec 16 §3.1/§3.4 and spec 21 §1.3 P1–P2 as flowsdn's plan.

## Context

The master ruled on #543 that the L7 proxy question is "C now, B when it comes;
never A". The standing rule is that everything but the kernel and qemu is Rust,
so Envoy (`cilium/proxy`, C++) is not an option on this platform. The L7 proxy
is a Rust proxy in the agent, and this record decides how. Nothing on the
platform needs L7 today, so no proxy work starts as a side effect of a gap. The
issues below wait for this record and are picked up when something needs them.

Spec 16 (L7/Envoy/DNS) and spec 21 (Gateway API/Ingress) were written for the
reference's design. An external Envoy DaemonSet is configured over xDS (NPDS,
LDS, CDS, RDS, EDS, SDS) from the agent, and
`CiliumEnvoyConfig`/`CiliumClusterwideEnvoyConfig` objects are written by the
operator's Ingress and Gateway translators. ADR-0015 kept that Envoy and listed
the gates a Rust replacement must pass.

## Decision

### 1. Where it runs

The L7 proxy is a module of the agent process (a new `flowsdn-l7` crate, linked
into `flowsdn-agent`). It runs on its own threads and runtime so that proxy load
does not delay the agent's controllers, and it reads the agent's state
directly: identities and the ipcache, endpoint policy, Services, Secrets.

There is no second process and no supervisor. A proxied connection does not
survive an agent restart, as the reference's in-agent DNS proxy's do not. The
datapath and policy maps keep enforcing across the restart (spec 16 §3.3.4), so
nothing is allowed that should not be. A panic in the proxy is a panic of the
agent, so proxy code is held to the agent's lints (no `unwrap`, no indexing, no
unchecked arithmetic), and parsers of untrusted input are bounded.

### 2. How traffic reaches it

The datapath contract does not change. A policy verdict with a `proxy_port`
(spec 06 §4.5) and a Service with an `l7_lb_proxy_port` (spec 05 §3.4) redirect
to the proxy as spec 02 §3.14 says. flowsdn uses only the BPF TPROXY path:
`bpf_sk_assign` to the proxy's transparent listener (`IP_TRANSPARENT`). The
nftables `tproxy` rules of spec 16 §3.3.3 are not built, since ADR-0003 leaves
nftables only as a residual and the BPF path covers the same cases.

The upstream leg carries `MARK_MAGIC_PROXY_{INGRESS,EGRESS} | identity << 16`
as in the reference, so it re-enters the datapath. The original destination
comes from the accepted socket. The source identity comes from the agent's
ipcache in process; there is no map read on the proxy's side and no NPHDS.

Proxy ports keep spec 16 §3.3: allocation, reference counts, reuse delay, and
`<state-dir>/proxy-ports.json` across restarts, so that policy map entries stay
valid until regeneration. A listener is bound before its port is published in
a policy map entry. This is the in-process form of the ACK barrier of spec 16
§3.1.5 and decision #24: nothing is redirected to a port that has no listener
with its rules.

### 3. What it implements, in this order

1. **The proxy core.** Transparent listeners, the redirect lifecycle, identity
   and original-destination recovery, and L7 records into the agent's flow
   pipeline (spec 16 §4.3 `LogRecord`, Hubble). There is no access-log socket.
2. **DNS (#536).** The DNS proxy of spec 16 §3.6 becomes this proxy's DNS
   listener: the same redirect (the static `cilium-dns-egress` port of §3.3.1)
   and the same lifecycle as the HTTP listeners, with §3.6's matching, response
   hold, cache and restore. toFQDNs then follows #536. The standalone DNS proxy
   (§3.7) is not built.
3. **HTTP policy (#537).** `toPorts[].rules.http`: method, path, host and
   headers, HTTP/1.1 and HTTP/2, with denials answered 403 as the reference
   does (spec 16 §3.5.1), then TLS interception (§3.5.3). **Kafka rules are
   not built:** the reference removed them from the policy API at v1.20
   (spec 16 §3.5), so they stay refused and reported, as today.
4. **Ingress (spec 21 stage 1)**, then **Gateway API (#543, #474)**, both as
   proxy listeners (item 4 below).
5. **TLS and secrets.** The proxy terminates and originates TLS with the
   platform's OpenSSL (ADR-0016) and reads Secrets through the agent's
   Kubernetes client. There is no SDS and no copy into a separate secrets
   namespace: spec 12 §3.14's secret sync is not built, and its RBAC need
   becomes the agent's read of the referenced Secrets.

### 4. Configuration: no xDS, no Envoy config kinds

Nothing speaks xDS. The `cilium.*` NPDS/NPHDS protobufs, the bootstrap, the
admin socket and the `xds.sock` server of spec 16 §3.1–§3.2 are not built. The
proxy reads its rules from the agent's endpoint policy directly.

Ingress and Gateway API are translated to spec 21 §4's `Model` by each agent
from the objects it watches (the front ends of spec 21 §3.1), and the proxy
serves the model. There is no intermediate object. The operator keeps what
needs one writer: status (spec 21 §3.11), the generated Services and
EndpointSlices (§2.3), and GatewayClass acceptance.

`FlowsdnEnvoyConfig` and `FlowsdnClusterwideEnvoyConfig` (#335) are retired.
They are no longer registered or watched, and a user's Envoy configuration has
no meaning on flowsdn. `FlowsdnGatewayClassConfig` stays (spec 21 §3.11.8).

### 5. Conformance without Envoy

- **Gateway API:** the upstream Gateway API conformance suite runs against
  flowsdn on a cluster, the external Go suite ADR-0005 permits (#290).
- **Ingress:** the `ingress-controller-conformance` suite runs the same way.
- **Translation goldens:** the harvested spec 21 §9 ingestion goldens (Ingress
  and Gateway objects to the `Model`, `output-listeners.yaml`) remain binding,
  because the model is kept.
- **Envoy goldens:** the translator's CiliumEnvoyConfig/Envoy-resource goldens
  have nothing to compare and become recorded divergences under this ADR, as do
  the Envoy scripttest areas (#525).
- **L7 policy:** spec 16's policy cases run against the proxy in the agent's
  tests and in kernel tests, with real sockets redirected by the datapath.

ADR-0015's gates become the acceptance criteria of the implementing issues, not
preconditions of a separate project. These are original source, destination and
identity handling, transparent sockets and marks, HTTP/gRPC policy and denies,
TLS and secret rotation, Hubble fidelity, Gateway and Ingress conformance, and
measured behavior under reload, failure and load. There is no migration from
Envoy, since no flowsdn release ever ran one.

## Consequences

- Spec 16 §3.1, §3.2 and §3.4 (the Envoy contract, its protobufs and
  CiliumEnvoyConfig) and spec 21 §1.3 P1–P2 describe the reference's design, not
  flowsdn's. Amendments to both specs record this; P1–P2 become "the agent's
  proxy serves the model", and P4 (secret sync) is dropped.
- Issues follow this order and stay parked until something on the platform
  needs L7:
  - #536 (DNS) and #537 (HTTP; Kafka stays refused);
  - Ingress, then #543 and #474 (Gateway API);
  - #335 (only `FlowsdnGatewayClassConfig` is still built);
  - #525 (Envoy scripttest areas: recorded divergences).
- `flowsdn-proxy`'s existing integration primitives (proxy ports, the ACK state
  machine, restore validation) are reused where they fit. The xDS parts are not
  carried forward.
- One binary per node keeps L7 inside the agent's memory and failure domain.
  This is the trade-off the ruling accepts; a separate agent-owned process can
  be reconsidered by a new record if measured isolation needs it.
