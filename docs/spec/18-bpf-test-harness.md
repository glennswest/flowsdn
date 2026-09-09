# BPF test harness (`flowsdn-bpftest`) — specification

Status: draft. Derived from: `docs/decisions/0005-test-strategy.md` (ADR-0005,
which governs this document), `docs/decisions/0002-rust-only-no-c.md`,
`docs/decisions/0003-nftables-residual.md`, `docs/spec/02-datapath-programs.md`
§9 (the case checklist this document mechanises), `docs/spec/01-bpf-map-abi-loader.md`
§§3.5–3.9, `docs/kernel-requirements.md` §5.3; reference cilium v1.20.1
(7d68cfb394) paths `bpf/tests/common.h`, `bpf/tests/pktgen.h`,
`bpf/tests/scapy.h`, `bpf/tests/lib/*.h`, `bpf/tests/bpftest/{bpf_test.go,
trf.proto}`, `bpf/tests/scapy/*.py`, and all 141 `bpf/tests/*.c`
(**names, flags and structure only** — see §2.4).

Normative language: MUST / SHOULD / MAY as in RFC 2119. This spec describes
*what* `flowsdn-bpftest` does, the exact data it exchanges with the kernel and
with the datapath under test, and the exact inventory of behaviour it is
obliged to cover. It does not transcribe reference code. Deviations from the
reference harness are marked **DEVIATION** with the reason and the ADR.

Sibling documents, referenced and not duplicated:

- **02-datapath-programs** — the programs under test, their pipelines, drop
  codes, monitor events, `.rodata` constants and the verifier budget gate
  (§9.4) that this harness feeds.
- **01-bpf-map-abi-loader** — map layouts, `.rodata.config` patching
  (`set_global`), reachability pruning, tail-call table, attach mechanics.
  The harness reuses the production loader; it does not have its own.
- **11-hubble-monitor** — the perf-event decoders the harness uses to assert
  on emitted `DropNotify` / `TraceNotify` / `PolicyVerdictNotify` / `DebugMsg`.
- **17-scripttest-harness** — the txtar scenario harness. Shares the address
  book, the map-dump renderer and the packet fixture format (§6.3).
- **`tests/bpf/CASES.toml`** — the machine-readable harvest of the reference's
  case inventory. Normative: every case listed there MUST be either ported,
  or carry a documented disposition in `tests/bpf/PORTED.toml` (§4.4).

---

## 1. Scope

### 1.1 In scope

`flowsdn-bpftest` is the privileged Rust test harness that replaces the
reference's C BPF unit-test estate: **141 compiled translation units, 397
`CHECK` sections written in `.c` files, 625 effective cases once shared test
headers are expanded** (measured in §4.1). It:

- builds packets declaratively in Rust (Ethernet / VLAN / ARP / IPv4 with
  options / IPv6 with extension headers / TCP / UDP / SCTP / ICMPv4 / ICMPv6 /
  IGMP / ESP / VXLAN / Geneve with options, plus arbitrary payload), with
  correct or deliberately-wrong checksums;
- loads a real `flowsdn-bpf` object through the production loader with a
  per-case `.rodata.config`, a populated `cilium_calls` program array and a
  fresh, seeded set of maps;
- runs one entrypoint under `BPF_PROG_TEST_RUN` for `SCHED_CLS` and `XDP`
  programs;
- asserts on the return code, the mutated packet bytes, the mutated
  `__sk_buff` context (mark, `cb[]`, ifindex, …), map contents (CT, NAT, LB,
  ipcache, endpoints, policy, metrics), and emitted monitor events;
- reports verifier statistics (instructions, stack depth, states) so the CI
  gate in spec 02 §9.4 can enforce budgets;
- runs cases that `BPF_PROG_TEST_RUN` cannot express (real `redirect` /
  `redirect_peer` / `redirect_neigh` delivery, tcx/netkit attach behaviour)
  in a network namespace with veth or netkit pairs and asserts on the
  receiving side.

### 1.2 Out of scope

Loader unit tests and pin/rename/upgrade protocol tests (spec 01 §9); txtar
control-plane scenarios (spec 17); k8s golden tests (`flowsdn-cptest`); live
cluster connectivity (`flowsdn-connectivity`, spec 19). Verifier *budget
policy* belongs to spec 02 §9.4 — this harness only produces the numbers.

---

## 2. Compatibility contract

The harness is internal. Almost nothing about it is a compatibility surface.
The four things that are:

### 2.1 Case names

Every reference `CHECK` name is kept **verbatim** as the flowsdn test function
name, so that `flowsdn-bpftest` output and `go test ./bpf/tests/...` output can
be diffed line-for-line during bring-up and after a reference tag bump. Names
that are not valid Rust identifiers do not occur in the corpus (all 625 are
`[a-z0-9_]+`), so no mangling table is needed. Test paths are
`bpftest::<reference_file_stem>::<check_name>`; e.g.
`bpftest::tc_nodeport_lb4_nat_lb::tc_nodeport_local_backend`.

### 2.2 Reference-derived constants

The address book, MAC book and port book of `bpf/tests/pktgen.h` are kept
value-for-value, because keeping them makes every ported expectation
(checksums, NAT'd ports, rewritten addresses) directly comparable with the
reference. They live in `tests/fixtures/addresses.toml` (§6.3) and are shared
with spec 17 and spec 19. Representative rows (full table in the fixture file):

| Symbol | Value | Role |
|---|---|---|
| `v4_pod_one` … `v4_pod_three` | `192.168.0.1` … `.3` | local pods |
| `v4_pod_{one,two,three}_on_node_two` | `192.168.1.1` … `.3` | remote pods |
| `v4_pod_cidr_on_node_two` / size | `192.168.1.0` / 24 | remote pod CIDR |
| `v4_node_one` … `v4_node_three` | `10.0.10.1` … `.3` | node IPs |
| `v4_svc_one` … `v4_svc_three` | `172.16.10.1` … `.3` | service frontends |
| `v4_ext_one` … `v4_ext_three` | `110.0.11.1`, `120.0.12.2`, `130.0.13.3` | external clients |
| `v4_svc_loopback` | `10.245.255.31` | hairpin loopback source |
| `v6_pod_one` / `v6_node_one` / `v6_svc_one` | `fd04::1` / `fd05::1` / `fd10::1` | v6 equivalents |
| `mac_one` … `mac_six`, `mac_host` | fixed 6-byte constants | endpoint / node / LB MACs |
| `tcp_src_one/two/three` | 22330 / 33440 / 44550 | client ports |
| `tcp_svc_one/two/three` | 80 / 443 / 53 | service ports |

### 2.3 `tests/bpf/CASES.toml` schema

The harvest file is consumed by a code generator (§11.3) and by CI coverage
reporting. Its `[meta]`, `[[file]]` and `[[file.case]]` field names are frozen;
adding fields is a minor change, renaming or removing one is breaking. The
schema is documented in the file's own header comment.

### 2.4 Licensing and clean-room

`bpf/tests/**` in the reference is licensed `GPL-2.0-only OR BSD-2-Clause`.
Per ADR-0005 §2 and `docs/licensing.md`, flowsdn takes it under
**BSD-2-Clause** and ports **case names, packet shapes and assertions** — never
C code. Concretely:

- `tests/bpf/CASES.toml` contains only identifiers and counts, mechanically
  extracted by `tools/harvest-bpf-cases (Rust)`. It carries a `PROVENANCE` block in
  its header naming the repository, tag `v1.20.1`, commit `7d68cfb394`,
  directory `bpf/tests`, and the license election; `tests/bpf/PROVENANCE`
  carries the full BSD-2-Clause text and the taken/not-taken inventory. The
  top-level `NOTICE` MUST carry a roll-up line for this directory alongside the
  existing ADR-0005 harvested-test-data block (the scripttest half of that
  harvest elects Apache-2.0; this half elects BSD-2-Clause, so the two are
  listed separately).
- No reference test body, assertion expression, packet-builder call sequence
  or expected byte value is transcribed. flowsdn case bodies are written from
  spec 02 (the behaviour) and this spec (the harness), with the harvested name
  and shape as the checklist entry. Where a reference expectation is
  numerically load-bearing and not derivable from the spec — a specific
  post-rewrite IPv4 or TCP checksum, for instance — the flowsdn test MUST
  compute it from the packet builder rather than hard-coding the reference's
  literal, and the *value* is then a computed fact, not a copied one.
- The reference's scapy-generated byte tables (`bpf/tests/scapy/*.py` →
  `output/scapy_bytes.h`) are **not** harvested. flowsdn regenerates the same
  packet shapes with its own builder (§3.2). A one-time byte-for-byte
  cross-check against the reference's generated header is permitted during
  bring-up as a read-only verification; the reference bytes are not committed.

---

## 3. Behavior

### 3.1 The reference model, and where flowsdn diverges

The reference expresses a case as **three BPF programs** in ELF sections
`<progtype>/test/<name>/{pktgen,setup,check}`, driven by a Go harness
(`bpf/tests/bpftest/bpf_test.go`):

1. `pktgen` runs first with an empty 3520-byte `data_in` (`4096 - 256 - 320`)
   and a 256-byte `__sk_buff` `ctx_in` for tc programs (an empty ctx for XDP);
   it writes the packet into the context with `bpf_skb_adjust_room`-style
   tailroom growth and returns 0. `data_out` and `ctx_out` become the next
   stage's input.
2. `setup` seeds maps by calling ordinary BPF map helpers, then
   `tail_call_static()`s into the datapath entrypoint under test through a
   per-file `entry_call_map` program array. The entrypoint's verdict is the
   program's return value, which the Go harness **prepends to `data_out` as
   four native-endian bytes** so the next stage can read it.
3. `check` parses that 4-byte status prefix and the rewritten packet with
   direct packet access, asserts with C macros (`assert`, `test_fatal`,
   `assert_metrics_count`), and writes a hand-rolled protobuf `SuiteResult`
   (`bpf/tests/bpftest/trf.proto`) into an 8192-byte `suite_result_map` array,
   including `bpf_trace_printk`-style log records. Status codes are
   `TEST_ERROR 100`, `TEST_PASS 101`, `TEST_FAIL 102`, `TEST_SKIP 103`.

Around that, the Go driver: creates one netns per `.o` file; strips pinning
from every map; **deletes every program that is not `XDP`, `SchedACT` or
`SchedCLS`** because `BPF_PROG_TEST_RUN` does not support the others; runs
sub-tests in alphabetical order because maps are shared across all cases in a
file; drains `cilium_events` through a perf reader and renders DEBUG messages
into the test log; and, on a packet-comparison failure, marshals a
`scapy_assert_map` entry to JSON and shells out to a Python/scapy script
(`bpf/tests/scapy/trace_diff_pkts.py`) to render a layer-aware diff.

flowsdn keeps the **three-stage conceptual model** and discards the
implementation.

**DEVIATION (ADR-0002).** All three stages are ordinary userspace Rust. Only
the datapath program under test runs in the kernel. Reasons:

- Writing `pktgen`/`setup`/`check` in `aya-ebpf` would triple the BPF surface
  under test, consume verifier budget on test scaffolding, require the
  BPF nightly toolchain for anything a developer wants to run, and reproduce
  in Rust a protobuf-encoder-written-in-BPF whose only purpose was to get a
  string back out of the kernel.
- Everything the in-BPF stages existed to do is available from userspace:
  maps are seeded and read with `bpf(2)` (`aya::maps`), the packet comes back
  in `data_out`, the verdict comes back in the syscall's `retval` field, the
  context comes back in `ctx_out`, and log lines are `println!`.
- Consequently the following reference machinery has **no flowsdn analogue and
  is deliberately not reimplemented**: `test_init()`/`test_finish()`, the
  `TEST()`/`CHECK()` do-while macros, `suite_result_map`, the varint/protobuf
  writer, `trf.proto`, `test_log`'s 12-argument `__bpf_log_arg` ladder, the
  four `TEST_*` status codes, the four-byte status prefix hack,
  `scapy_assert_map`, `scapy_memcpy`/`scapy_memcmp`, and the Python diff
  script. That is roughly 550 lines of C macro machinery replaced by
  `assert_eq!`.

What is **kept** from the reference model, because it is load-bearing:

| Reference mechanism | flowsdn |
|---|---|
| Three ordered stages, pktgen output feeding setup feeding check | Three phases of one `#[test]`: `build`, `arrange`, `assert` (§3.2–3.4) |
| One netns for the run | One netns per test process (§3.6) |
| Map state seeded before the run, asserted after | Same, from userspace |
| Program array populated so tail calls resolve | Populated by the production loader (§3.5) |
| `cilium_events` DEBUG output attached to the failing test | Same, decoded by `flowsdn-monitor` (§8.2) |
| Skip a case when the feature is unavailable on this kernel | `TestOutcome::Skip { reason }` (§3.8) |
| `BPF_PROG_TEST_RUN` limited to tc and XDP | Same limit; other program types are tested by direct-call wrappers or excluded (§3.9) |

### 3.2 Stage 1 — packet generation

A case builds its packet with `PacketBuilder`, a layered, declarative builder.
It MUST be usable without a kernel (Tier 0, §10.3) so packet construction is
testable on any host including macOS.

```
let pkt = PacketBuilder::new()
    .eth(mac::CLIENT, mac::LB)                 // or .eth_vlan(.., vid, pcp)
    .ipv4(ip::CLIENT, ip::FRONTEND)            // ttl/tos/id/df default per §3.2.1
    .tcp(port::CLIENT, port::FRONTEND).syn()
    .payload(payload::DEFAULT)                 // b"Should not change!!"
    .build();                                  // -> Packet { bytes, layers }
```

Normative requirements:

1. **Layers.** `eth`, `eth_vlan`, `arp`, `ipv4`, `ipv4_opts(&[IpOption])`,
   `ipv6`, `ipv6_ext(&[ExtHeader])` (hop-by-hop, routing, fragment,
   destination options, authentication header), `tcp`, `udp`, `sctp`, `icmp4`,
   `icmp6`, `igmp`, `esp`, `vxlan(vni)`, `geneve(vni, &[GeneveOption])`,
   `raw(&[u8])`, `payload(&[u8])`, `payload_len(n)` (n bytes of a
   deterministic pattern). Nesting is unrestricted, so
   `eth → ipv4 → udp → vxlan → eth → ipv6 → tcp` is one expression.
   Maximum nesting depth 8 (the reference's `PKT_BUILDER_LAYERS` is 7; one
   more covers IPIP-in-Geneve).
2. **Lengths and next-protocol fields** are computed at `build()`, walking the
   layer stack outward-in: IPv4 `tot_len`/`ihl`/`protocol`, IPv6
   `payload_len`/`next_header`, UDP `len`, TCP `doff`, SCTP chunk lengths,
   VXLAN/Geneve `proto_type`/`opt_len`, Ethernet `h_proto`.
3. **Checksums** are computed at `build()`: IPv4 header checksum, TCP/UDP/
   ICMPv6 checksums over the correct pseudo-header (v4 or v6), ICMPv4 checksum,
   SCTP CRC32c, IGMP checksum, inner and outer independently for encapsulated
   packets. `udp` MAY be built with a zero checksum
   (`.udp(..).checksum(Checksum::Zero)`), which the overlay paths rely on.
4. **Deliberately-wrong values** are first-class:
   `.checksum(Checksum::Bad)` (correct value XOR `0xffff`),
   `.checksum(Checksum::Exact(0x1234))`, `.ipv4().tot_len_override(n)`,
   `.ipv4().ihl_override(n)`, `.truncate(n)`. The wildcard-drop, fragment and
   malformed-packet cases need these.
5. **Fragments.** `.ipv4().frag(FragSpec { id, offset, mf })` and
   `.ipv6_ext(&[ExtHeader::Fragment { id, offset, mf }])`. A helper
   `fragment(pkt, mtu) -> Vec<Packet>` splits a built packet the way the stack
   would, for the `ipfrag` and `tc_nodeport_lb_fragments_*` cases.
6. **Determinism.** `build()` is a pure function of the builder. No random IDs,
   no clock. IPv4 `id` defaults to `0`, TTL to `64`, IPv6 hop limit to `64`,
   TCP window to `65535`, TCP seq/ack to fixed constants. The same builder
   expression MUST produce identical bytes on every run, every host and every
   architecture (the builder writes big-endian wire fields explicitly, never
   via `#[repr(C)]` struct transmute).
7. **Introspection.** `Packet` retains `layers: Vec<LayerSpan>` — the byte
   range and kind of each layer — so the diff renderer (§3.4.6) can label
   offsets, and so an assertion can name a field
   (`pkt.ipv4().unwrap().dst_addr()`) rather than an offset.
8. **Size.** `data_in` is 3520 bytes by default (matching the reference's
   `4096 − 256 head − 320 tail`), configurable per case up to the kernel's
   `BPF_PROG_TEST_RUN` maximum. `data_out` is allocated at
   `data_in.len() + 256 + 2` per the `cilium/ebpf` note the reference driver
   cites (the kernel may grow the packet; the extra room avoids `ENOSPC`).

#### 3.2.1 Defaults

`.ipv4()` defaults: version 4, ihl 5, tos 0, id 0, flags 0, frag off 0,
ttl 64, checksum computed. `.ipv6()`: version 6, tclass 0, flow label 0,
hop limit 64. `.tcp()`: seq `0x10203040`, ack_seq 0, doff 5, window 65535,
urg_ptr 0, no flags set (a case calls `.syn()`, `.ack()`, `.fin()`, `.rst()`,
`.psh()`, or `.flags(u8)`). `.vxlan()`: flags `0x08`, reserved zero.
`.geneve()`: version 0, `oam` and `critical` clear, `proto_type` computed.

### 3.3 Stage 2 — setup (arrange)

The setup phase does three things, in this order.

**(a) Choose the object and its configuration.** A case declares the object
(`lxc`, `host`, `overlay`, `xdp`, `wireguard`) and a `DatapathConfig` — the
typed form of the `.rodata.config` variable set frozen in spec 01 §3.7. The
reference expresses this as `#define ENABLE_*` (compile-time) plus
`ASSIGN_CONFIG(type, name, value)` (load-time). Under ADR-0002 **both** become
`.rodata.config` values, so a flowsdn case sets them uniformly:

```
let cfg = DatapathConfig::defaults()
    .enable_ipv4(true)
    .enable_nodeport(true)
    .enable_bpf_host_routing(true)
    .interface_ifindex(DEFAULT_IFACE)
    .nodeport_port_min(30000).nodeport_port_max(30001);
```

The harvest records, per reference file, exactly which symbols were active
(`features`) and which `ASSIGN_CONFIG` globals were set (`configs`), so this
call is mechanically derivable from `CASES.toml` — see §11.3. Setting a name
that is not in `flowsdn-bpf-abi::config::VARIABLES` MUST be a compile error
(the builder is a generated typed struct, not a string map).

**(b) Load.** The harness calls the **production loader**
(`flowsdn_datapath::Loader`, spec 01 §3.5) with:

- pinning disabled — every map is an anonymous fd owned by the `Ebpf` handle,
  so teardown is automatic and nothing touches the host's bpffs;
- `set_global` applied for every `DatapathConfig` field;
- the reachability/pruning pass enabled exactly as in production, so the object
  the test verifies is the object production loads;
- `cilium_calls` populated from `flowsdn_bpf_abi::TailSlot` by the loader, and
  `cilium_call_policy` / `cilium_egresscall_policy` populated by the case
  (§3.5).

Using the production loader is normative. The reference builds a bespoke
`entry_call_map` per test file with libbpf `__array` initialisers, which means
the tail-call wiring under test is test-specific; flowsdn tests the wiring it
ships.

**(c) Seed maps.** Typed seeding helpers mirror the reference's
`bpf/tests/lib/*.h` groups, which the harvest records per file as `seeds`:

| Reference helper group | flowsdn API (all on `&mut TestMaps`) |
|---|---|
| `lib/endpoint.h` | `maps.endpoints().add_v4(ip, ifindex, ep_id, flags, sec_id, parent_ifindex, ep_mac, node_mac)`, `.add_v6(..)`, `.add_v4_with_rt_info(..)`, `.del_v4(ip)` |
| `lib/ipcache.h` | `maps.ipcache().add_v4(ip, cluster_id, sec_id, tunnel_ep, key)`, `.add_v4_masked(prefix, len, ..)`, `.add_v4_with_flags(..)`, `.add_world_v4()`, v6 forms, `.add_v4_ipv6_underlay(..)` |
| `lib/lb.h` | `maps.lb().add_service_v4(addr, port, proto, backend_count, revnat_id)`, `.add_nodeport_service_v4(..)`, `.add_hostport_service_v4(..)`, `.add_l7_service_v4(..)`, `.add_service_with_flags_v4(..)`, `.upsert_backend(..)`, `.add_backend_v4(svc, slot, id, backend_ip, backend_port, proto, flags)`, `.del_service_v4(..)`, v6 forms |
| `lib/policy.h` | `maps.policy(ep_id).allow_ingress_l3_l4(sec_label, proto, dport, range)`, `.allow_ingress_l3(..)`, `.deny_ingress_l4(..)`, `.allow_ingress_all()`, `.deny_ingress_all()`, egress forms, `.delete_*` forms, and `wildcard_bits(proto, dport, port_range)` |
| `lib/node.h` | `maps.nodes().add_v4(ip, node_id, spi)` and v6 |
| `lib/network_device.h`, `lib/subnet.h` | `maps.devices().add(ifindex, ..)`, `maps.subnets().add_v4(cidr, ..)` |
| `lib/egressgw_policy.h`, `lib/egressgw.h` | `maps.egressgw().add_policy(src, dst_cidr, gateway, egress_ip)` (M3) |
| `lib/metrics.h`, `lib/clear.h` | `maps.metrics().sum(reason, dir)`, `maps.clear_all()` |
| CT / NAT (reference cases build entries inline) | `maps.ct().insert_v4(tuple, entry)`, `.get_v4(tuple)`, `.dump()`; `maps.nat().insert_v4(..)`, `.get_v4(..)`, `.dump()` (spec 04 types) |

All helpers take the `#[repr(C)]` ABI types from `flowsdn-bpf-abi`, so a
seeding mistake is a type error rather than a byte-layout bug. Each helper
returns the key it wrote, so a later assertion can address the same entry
without restating it.

**(d) Set the context.** For `SCHED_CLS`, the case may set input `__sk_buff`
fields:

```
let ctx = SkbCtx::new()
    .mark(MARK_MAGIC_HOST)
    .ifindex(DEFAULT_IFACE)
    .cb([0, 0, 0, 0, 0])
    .priority(0);
```

The kernel's `bpf_prog_test_run_skb` accepts a `struct __sk_buff` as `ctx_in`
and copies a defined subset into the synthesised skb, rejecting the run if any
non-copied field is non-zero. The subset flowsdn relies on is `priority`,
`mark`, `cb[0..5]`, `ifindex`, `tstamp`, `wire_len`, `gso_segs`, `gso_size`,
`hwtstamp`. **to-verify:** whether `ifindex` selects a real device in the
current netns (and therefore requires the harness to create one before the
run) or is advisory, and whether `tc_index` and `ingress_ifindex` are settable,
differ across the 6.6/6.12/6.18 rows of the kernel matrix; §9.1 pins this down
with a harness self-test on every matrix row before the corpus is trusted.
Where a field turns out not to be settable, the affected cases move to the
netns tier (§3.7). Like the reference, flowsdn sends a 256-byte `ctx_in`
buffer (larger than `sizeof(struct __sk_buff)`, zero-padded) so that kernels
that grow the struct keep working.

For XDP, `bpf_prog_test_run_xdp` accepts a `struct xdp_md` carrying
`data`, `data_end`, `data_meta`, `ingress_ifindex` and `rx_queue_index`, and
validates the ifindex/queue against a real device. **to-verify** on each
matrix row; the reference sidesteps it entirely by passing an empty ctx, and
flowsdn defaults to the same, opting in only for the cases that need
`ingress_ifindex` or `data_meta` (the XDP→tc metadata contract, spec 02 §2.4).

### 3.4 Stage 3 — check (assert)

The run itself:

```
let run = harness.run(Entry::FromNetdev, &pkt, ctx)?;   // repeat = 1
```

`run` returns `RunResult { verdict, packet, ctx, duration, }`. `verdict` is a
`Verdict` newtype over the syscall's `retval`, rendered by name
(`TC_ACT_OK`, `TC_ACT_SHOT`, `TC_ACT_REDIRECT`, `XDP_PASS`, `XDP_DROP`,
`XDP_TX`, `XDP_REDIRECT`, `XDP_ABORTED`) so a failure message reads
`expected TC_ACT_REDIRECT (7), got TC_ACT_SHOT (2)`.

**`repeat` MUST be 1 for correctness cases.** `BPF_PROG_TEST_RUN`'s repeat
loop re-runs the program on the same input without resetting map state, so the
second iteration of a NodePort case takes the "existing CT entry" path and the
assertions become meaningless. `repeat > 1` is available only in the
throughput mode of §8.3, which asserts nothing about state.

The assertion vocabulary:

**3.4.1 Verdict.** `run.assert_verdict(TC_ACT_REDIRECT)`. For drops, the
paired assertion is on the drop reason carried in the monitor event
(§3.4.5) — the verdict alone does not distinguish drop reasons.

**3.4.2 Packet fields.** Two styles, both available:

- *Structured*: `run.packet.eth().src()`, `.ipv4().dst_addr()`,
  `.tcp().dest()`, `.vxlan().vni()`, `.inner().ipv4()`. Each accessor returns
  `Result<_, ParseError>` and a failed parse produces a message naming the
  offset and what was found. This is the default and covers the majority of
  reference assertions, which are field comparisons.
- *Whole-packet*: `run.assert_packet_eq(&expected, mask)` where `expected` is
  another `Packet` built with the same builder, and `mask` is a `FieldMask`
  (§3.4.3). This is the analogue of the reference's `ASSERT_CTX_BUF_OFF`
  scapy comparison, without scapy.

**3.4.3 Masking volatile fields.** `FieldMask` is built from layer-aware
selectors, not byte offsets, so it survives a header-length change:

```
FieldMask::none()
    .ignore(Field::Ipv4Id)                 // kernel-chosen on encap
    .ignore(Field::Ipv4Checksum)           // implied by any ignored v4 field
    .ignore(Field::UdpSourcePort)          // tunnel source port is a flow hash
    .ignore(Field::UdpChecksum)
    .ignore(Field::TcpTimestampOption)
    .ignore_range(Layer::Payload, 4..8);
```

Rules: (1) ignoring any field that feeds a checksum implicitly ignores that
checksum, and the harness says so in the diff header, so a masked test cannot
silently stop checking a checksum it still could check; (2) `FieldMask::none()`
is the default and a case that needs a mask MUST state why in a comment;
(3) the mask is reported in the failure output so a reader can see what was
not compared.

**3.4.4 Context.** `run.ctx.mark()`, `.cb(i)`, `.ifindex()`, `.tstamp()`, with
`assert_mark(MARK_MAGIC_IDENTITY | (id << 16))` and a renderer that decodes
the mark and `cb[]` slots by the spec 02 §2.1/§2.3 contract, so a failure
prints `mark: expected MARK_MAGIC_PROXY_EGRESS|id=1234 (0x04d20a00), got
MARK_MAGIC_HOST (0x0c00)`.

**3.4.5 Maps.** Three forms:

- point lookup: `maps.ct().get_v4(&tuple).expect("CT entry created")` then
  field assertions on the `#[repr(C)]` value, with volatile fields (`lifetime`,
  `last_tx_report`, `last_rx_report`) masked by a `CtEntryMask` unless the case
  is specifically about ageing;
- delta: `let before = maps.snapshot(); … ; maps.assert_delta(before,
  Delta::new().added_ct_v4(1).added_nat_v4(1).unchanged(Map::Ipcache))` — a
  whole-map-set diff that catches unintended writes, which the reference cannot
  express at all;
- counters: `maps.metrics().sum(DROP_POLICY_DENY, Dir::Ingress) == 1`, summing
  the per-CPU `cilium_metrics` values exactly as the reference's
  `assert_metrics_count` macro does, but in userspace and without the
  128-CPU cap.

**3.4.6 Monitor events.** After the run the harness drains `cilium_events`
(and, on kernels with it, the ring-buffer variant) and decodes each sample with
the spec 11 decoders:

```
run.events().assert_one(Event::Drop(DropNotify {
    reason: DROP_POLICY,
    src_label: 1234,
    dst_label: IDENTITY_HOST,
    ..Default::default()          // remaining fields not compared
}));
run.events().assert_none_matching(|e| matches!(e, Event::Trace(_)));
```

Volatile fields (timestamp, CPU, `orig_len` when monitor aggregation is on,
the payload tail) are excluded from comparison by default and can be opted
into. `DebugMsg` events are never asserted on; they are captured and printed
with the failure (§8.2), matching what the reference driver does with its
`MonitorFormatter`.

**3.4.7 Readable failure output.** On any packet mismatch the harness prints:

1. a one-line summary (`packet differs at Layer::Ipv4 field dst_addr`);
2. the mask in force;
3. a **layer-annotated side-by-side hexdump** of expected and actual, with
   differing bytes highlighted and each layer's span labelled, e.g.

```
        Ethernet                          expected              actual
  0000  de ad be ef de ef  13 37 …        (same)
        IPv4  src=110.0.11.1  dst=?
  000e  45 00 00 3b 00 00  40 00          45 00 00 3b 00 00  40 00
  0018  40 06 42 12 6e 00  0b 01          40 06 3f 08 6e 00  0b 01
                    ^^ ^^                            ^^ ^^   checksum
  001e  c0 a8 00 01                       ac 10 0a 01
        ^^^^^^^^^^^                       ^^^^^^^^^^^        ipv4.dst
```

4. a structured field diff listing every differing field by name with both
   values rendered in their natural form (IPs dotted, ports decimal, flags
   symbolic);
5. the captured `cilium_events` DEBUG log for the run, in order.

This replaces the reference's out-of-process Python/scapy renderer. It is
implemented with `similar` for the byte diff and hand-written renderers for
the field diff (§11.4); it MUST NOT shell out to anything.

### 3.5 Tail calls and stubbed neighbours

Every entrypoint tail-calls, so the program array must be populated before the
run or the case fails with a spurious `DROP_MISSED_TAIL_CALL`. The harness:

1. lets the production loader fill `cilium_calls` for the loaded object from
   `TailSlot` (spec 01 §3.8), so all 50 slots that the object defines are
   resolvable;
2. fills `cilium_call_policy[ep_id]` for the endpoint under test, with either
   the real `lxc_policy` program from the same object — the default, because
   it is what production does — or, when the case is about the *caller* and
   not the policy verdict, with a **stub program** `mock_policy_verdict`
   from `flowsdn-bpf-testprogs`, a tiny separate BPF object whose only job is
   to return a value the harness seeds in a one-entry array map. The reference
   does exactly this with its `mock_handle_policy` / `mock_policy_call_map`
   pair; flowsdn keeps the technique but puts the stub in its own object so no
   test artefact ever links into the datapath crate;
3. fills `cilium_egresscall_policy[ep_id]` the same way for M2 L7 cases.

Tail-call depth is 33; no flowsdn pipeline approaches it, but the harness
records the observed depth from the verifier log (§8.1) so a regression is
visible.

### 3.6 Helper mocking — the hard problem

The reference redefines kernel helpers with the C preprocessor at the top of a
test file:

```
#define fib_lookup        mock_fib_lookup
#define ctx_redirect      mock_ctx_redirect
#define tail_call_dynamic mock_tail_call_dynamic
#define bpf_sock_destroy  mock_bpf_sock_destroy
```

so that `bpf_fib_lookup` returns a scripted neighbour, `bpf_redirect` reports
whether the *intended* ifindex was right without a real device, and so on.
**Rust has no preprocessor**, and ADR-0002 forbids adding one. Three options
were considered; the decision is open (§12.1) and the M1 plan is (a):

(a) **Feature-gated indirection shim (M1 plan).** Every helper the corpus mocks
is called through a single `#[inline(always)]` wrapper in
`flowsdn_bpf::helpers`. Under `--features testmock` the wrapper's body reads a
mock table instead of calling the helper: `mock_fib` (a `HashMap` keyed on the
lookup's destination, valued with `{ ifindex, smac, dmac, ret }`),
`mock_redirect` (an array recording `(ifindex, flags)` and returning a seeded
verdict). The harness seeds those maps like any other. Cost: the object under
test is built with an extra feature, so it is not bit-identical to production.
Mitigations, all normative: the shim is one function call deep and the
surrounding code is textually identical; CI loads the **non-mock** object too
and fails if its verifier statistics differ from the mock object's by more than
5 %; and every case that asserts on a *redirect target* also exists in the
netns tier (§3.7) running the production object, at least once per pipeline.

(b) **`freplace` (BPF_PROG_TYPE_EXT).** Make each mockable wrapper a global
(non-inlined) subprogram with BTF `func_info`, and at test time attach an
extension program over it. The production object stays bit-identical. Costs:
needs BTF and trampolines (x86 ≥ 5.10, arm64 ≥ 6.0 — inside the flowsdn
floor), forces the wrappers to be non-inlined in production too (which costs
verifier budget on the hot path), and spec 02 §1.1 explicitly drops `freplace`
datapath plugins. Re-evaluated at M2.

(c) **No mocking; netns for everything.** Correct and slow: every redirect case
needs real devices, and `fib_lookup` needs real routes and neighbours, which
turns a 5 ms case into a 200 ms one and makes failures harder to read. Rejected
as the default; used for the cases in §3.7.

### 3.7 The netns tier

Cases that `BPF_PROG_TEST_RUN` cannot express run in a network namespace:

- delivery assertions — `bpf_redirect`, `bpf_redirect_peer`,
  `bpf_redirect_neigh` actually move the packet, and the assertion is on what
  arrives at the peer;
- the tc_redirect corpus (`tc_redirect_{lxc,host,netdev}_{veth,netkit}.c` and
  the `_policy` variants), which is about *which* redirect helper is used and
  what the peer sees;
- attach-mode behaviour (tcx ordering, netkit primary/peer), which is spec 01's
  §9.4 matrix but shares this harness's fixtures;
- `fib_lookup` against a real FIB, as the cross-check for the mocked cases.

Shape: a `NetnsFixture` builds, inside a fresh netns, a veth or netkit pair, a
`cilium_host`/`cilium_net` pair, addresses, routes and neighbour entries from a
declarative description; attaches the production object with the production
attach code (spec 01 §3.9); injects the built packet with an `AF_PACKET`
`SOCK_RAW` send on the ingress side; and captures on the peer with a second
`AF_PACKET` socket with a BPF filter. Assertions reuse §3.4's packet
vocabulary. The netns tier is a minority of cases (target: under 40 of 625)
and is marked in `PORTED.toml` with `tier = "netns"`.

### 3.8 Skips

A case whose feature is unavailable on the running kernel MUST *skip*, not
fail, with a machine-readable reason, matching the reference's `TEST_SKIP`.
Reasons are an enum (`KernelTooOld { need, have }`, `MissingHelper(name)`,
`MissingMapType(name)`, `MissingModule(name)`, `NotImplementedYet(milestone)`),
so CI can distinguish "this kernel row cannot run this" from "we have not
written this yet". A run summary prints counts per reason and the CI gate
fails if a case skips on a kernel row where the matrix says it must run.

### 3.9 Program types `BPF_PROG_TEST_RUN` cannot run

`BPF_PROG_TEST_RUN` supports `SCHED_CLS`, `SCHED_ACT`, `XDP`, and a few others
(`FLOW_DISSECTOR`, `RAW_TRACEPOINT`, `SK_LOOKUP`, `SYSCALL`, `CGROUP_SOCKOPT`,
`CGROUP_SOCK_ADDR` since 5.12 with `bpf_attr.test.ctx_in` as
`struct bpf_sock_addr`). The reference driver simply deletes every program that
is not XDP/`SchedACT`/`SchedCLS`. Consequently, and this is worth stating
plainly because it changes what the M2 socket-LB cases mean:

- `wildcard_lookup.c`, `host_only_socket_lb_test.c`,
  `skip_lb_xlate_socket_lb.c`, `skip_lb_xlate_lrp_per_packet_lb.c` and
  `destroy_sock_socket_lb.c` declare their sections as `CHECK("xdp", …)`. They
  compile `bpf_sock.c` / `bpf_sock_term.c` into an **XDP** program and call
  `sock4_xlate_fwd()`, `sock6_wildcard_lookup_full()` or the socket-terminate
  logic **as an ordinary function**, with a hand-built `struct bpf_sock_addr`
  on the stack and, in the `sock_destroy` case, the kfunc `#define`d to a mock.
  They are direct-call unit tests wearing an XDP costume, not runs of the
  cgroup programs.
- flowsdn reproduces this deliberately, and names it: such cases are
  `tier = "direct"` in `PORTED.toml`, and their flowsdn form is a
  `#[classifier]`/`#[xdp]` wrapper in `flowsdn-bpf-testprogs` that calls the
  library function under test. `CASES.toml` records `entrypoint = "direct"`
  for all 109 such cases, which also covers the pure library units
  (`bpf_ct_tests.c`, `conntrack_test.c`, `bpf_nat_tests.c`, `lb_tests.c`,
  `fib_tests.c`, `ipfrag.c`, `ipv6_test.c`, `ratelimit.c`, `builtins.c`,
  `jhash_test.c`, `mcast_tests.c`, `ip_options_trace_id.c`,
  `drop_notify_test.c`).
- Where flowsdn can do better than a costume, it does: `CGROUP_SOCK_ADDR`
  programs *are* runnable under `BPF_PROG_TEST_RUN` on the flowsdn kernel
  floor (5.12+), so at M2 the socket-LB cases SHOULD be re-expressed as real
  `connect4`/`connect6`/`sendmsg` runs with a `bpf_sock_addr` `ctx_in`, and
  the direct-call form kept only as a fast unit check. Recorded as open
  decision §12.5.
- `iter/tcp` / `iter/udp` with the `bpf_sock_destroy` kfunc (M3) has no
  `BPF_PROG_TEST_RUN` path at all. It gets a netns-tier test with real sockets.

### 3.10 Cases that are unportable or meaningless under ADR-0002 / ADR-0003

Recorded per case in `PORTED.toml` with `disposition`; summarised here.

| Reference cases | Disposition | Why |
|---|---|---|
| `builtins.c` — `builtin_memcpy`, `builtin_memmove`, `builtin_memmove2`, `builtin_memzero`, `builtin_memcmp` (5) | **retarget** | They test the reference's C `__builtin_*` overrides in `bpf/include/bpf/builtins.h`. flowsdn has no C builtins; the equivalent is `flowsdn_bpf::copy::{copy::<N>, zero::<N>, eq::<N>}` (spec 02 §11.4). Ported as (a) host-compiled `#[test]`s over the same widths and alignments, and (b) one `BPF_PROG_TEST_RUN` case per width group confirming the BPF codegen, plus the existing build check that the ELF contains no `memcpy`/`memmove`/`memset`/`memcmp` relocation. The generator `bpf/tests/builtin_gen` and the five `builtin_*.h` tables have no analogue. |
| `_scapy_selftest.c` — `1_basic_test`, `1_test_large_pkts`, `2_test_xlarge_pkts` (3) | **meaningless; replaced** | A self-test of the reference's scapy→C byte-table pipeline. flowsdn has no scapy and no generated byte tables. Replaced by the packet builder's own Tier-0 unit tests (§9.2), which are strictly stronger because they check construction *and* parsing round-trip. |
| `mock_skb_metadata.c` — `01`, `02` (2) | **meaningless; replaced** | Tests the reference harness's own `mock_skb_meta_map` mechanism for faking skb metadata that `BPF_PROG_TEST_RUN` would not carry. flowsdn sets those fields through `ctx_in` and reads them back through `ctx_out`; the mechanism is the kernel's, and §9.1's harness self-tests cover it. |
| `hostfw_host_iptables.c` — `hostfw_iptables_host_ipv4_01_pod` … `_05_host` (5) | **partially meaningless; retarget** | The scenarios are about traffic that an iptables rule has already marked, and about the host firewall's interaction with iptables-owned `MARK_MAGIC_HOST`. Under ADR-0003 there is no iptables. The *host-firewall* half of each scenario is portable and is ported; the *iptables interaction* half is replaced by nftables-residual tests in the netns tier (spec 10 §9), where the equivalent `meta mark set` rule is installed by the flowsdn nftables layer. Renamed `hostfw_host_nftables_*` and cross-referenced to the original name in `PORTED.toml`. |
| `hostfw_bpf_masq.c` — `hostfw_ipv4_bpf_masq_proxy_01`, `_02` (2) | **port** | Despite the name, these are about BPF masquerade + host firewall + proxy mark, all of which flowsdn keeps. No iptables dependency in the assertions. |
| `eni_nlb_symetric_routing_host.c` (2) | **port, M3, cloud-gated** | Depends on the ENI CONNMARK 0x80 behaviour, which under ADR-0003 is an nftables `ct mark` rule. The datapath half is portable; the mark is set by the harness rather than by a rule. |
| `destroy_sock_socket_lb.c` — `sock_terminate` (1) | **port with a caveat** | As §3.9 explains, the reference case mocks the `bpf_sock_destroy` kfunc away, so upstream it does not test socket termination — it tests the surrounding lookup. flowsdn ports the lookup case at that fidelity **and** adds a real netns-tier test with live sockets at M3, because the kfunc is the part that can break. |
| `jhash_test.c` — `jhash` (1) | **retarget** | Hash correctness is a pure function; it becomes a Tier-0 `#[test]` with the same input vectors plus a `BPF_PROG_TEST_RUN` case asserting the BPF build produces identical output (the interesting failure is codegen, not algorithm). Its M2 relevance is Maglev, which needs the userspace and BPF hashes to agree — a property the reference does not test and flowsdn does. |
| `bpf/tests/encrypt_host_wireguard_tunnel` (10) | **port; upstream dead** | The file is missing its `.c` extension upstream, so the build never compiles it and its ten cases never run. flowsdn ports the WireGuard-over-tunnel encrypt-host set anyway; `CASES.toml` marks the file `upstream_dead = true`. |
| Everything gated on a milestone flowsdn has not reached | **deferred, not dropped** | 138 M2 and 208 M3 cases. `PORTED.toml` carries `status = "deferred"` with the milestone; the coverage gate (§8.4) measures against the milestone's own denominator, so M1 can be green with M3 unported. |

Nothing else in the corpus is unportable. In particular, all 23 cases whose
`entrypoint` the harvester could not resolve (§4.3) are portable; they are
merely awaiting a human classification of which pipeline they exercise.

---

## 4. Data model

### 4.1 The harvest

`tests/bpf/CASES.toml` is the machine-readable inventory. **TOML was chosen
over Markdown**, and the reasons are worth stating because ADR-0005 leaves the
choice open:

- it is *input*, not documentation: `flowsdn-bpftest`'s build step reads it to
  generate one `#[test]` stub per case, so a case cannot be silently forgotten;
- CI computes coverage from it (`ported / total`, per milestone, per pipeline)
  and gates on the M1 denominator;
- re-harvesting at a newer reference tag produces a diffable file, so
  `git diff tests/bpf/CASES.toml` is exactly the list of cases the bump added,
  removed or renamed — the operation ADR-0005 calls "deliberate and reviewed";
- a Markdown table of 625 rows across 12 columns is unreadable *and*
  unparseable, which is the worst of both. Human-readable views are generated
  (`cargo xtask cases --md`, `--summary`) rather than maintained.

Structure (schema frozen per §2.3):

```toml
[meta]                      # reference identity, counts, harvest date
[[file]]                    # one per reference translation unit (142)
path, ctx, milestone, milestone_reason, objects, units, seeds,
features, configs, shared_headers, case_count, upstream_dead
  [[file.case]]             # one per effective CHECK (625)
  name, progtype, stages, entrypoint, milestone, defined_in
```

Measured totals at `v1.20.1` / `7d68cfb394`:

| Quantity | Count |
|---|---|
| Translation units compiled upstream | 141 |
| Translation units present but never compiled | 1 (`encrypt_host_wireguard_tunnel`) |
| `CHECK` sections written directly in `.c` files | 397 |
| `CHECK` sections written in shared test headers | 79 |
| **Effective cases after header expansion** | **625** |
| — M1 | 279 |
| — M2 | 138 |
| — M3 | 208 |
| Cases with a `PKTGEN` stage | 409 sections, expanded per including file |
| Cases with a `SETUP` stage | 370 sections, expanded per including file |
| tc-section cases / XDP-section cases | 566 / 59 |

By flowsdn entrypoint (spec 02 §1.1):

| Entrypoint | Cases | Entrypoint | Cases |
|---|---|---|---|
| `from_netdev` | 186 | `from_host` | 22 |
| `to_netdev` | 164 | `from_overlay` | 21 |
| `direct` (library / costume, §3.9) | 112 | `to_container` | 13 |
| `from_container` | 63 | `lxc_policy` | 3 |
| `xdp_entry` | 26 | `to_overlay` | 3 |
| `lxc_policy_egress` | 4 | `from_wireguard` | 4 |
| `to_wireguard` | 4 | *unresolved* (§4.3) | 0 |

By object pulled into the translation unit:

| Object | Files | Object | Files |
|---|---|---|---|
| `host` | 72 | `overlay` | 8 |
| *(library unit test, no object)* | 23 | `sock` | 3 |
| `lxc` | 20 | `wireguard` | 2 |
| `xdp` | 13 | `sock_term` | 1 |

### 4.2 How the harvest is produced

`tools/harvest-bpf-cases (Rust)` (a Rust workspace crate with regex and TOML support) walks each `bpf/tests/*.c` with a small
`#ifdef`/`#ifndef`/`#if`/`#elif`/`#else`/`#endif`-aware preprocessor and a
`#define`/`#undef` table, following test-local `#include "…"` edges. This
matters: 16 shared test headers contain 79 `CHECK` sections that are
instantiated differently per including `.c` (`tc_nodeport_lb_fragments.h` picks
`netdev_receive_packet` under `NORTH_SOUTH_TEST` and `pod_send_packet` under
`EAST_WEST_TEST`; `kpr_dsr_lb.h` picks section prefix `"xdp"` or `"tc"` from
`ATTACHMENT_XDP`), so a naive `grep` for `CHECK(` produces both the wrong
count and the wrong attribution. The tool records, per translation unit:

- `features` — every active `ENABLE_*` / `TUNNEL_*` / `DSR_*` / `ENCAP*` /
  `IS_BPF_*` / `ENCRYPT*` symbol, which under ADR-0002 becomes a
  `.rodata.config` boolean or value (spec 01 §3.7 layer 1);
- `configs` — every `ASSIGN_CONFIG` global set, which becomes a `set_global`
  call (spec 01 §3.7 layer 2);
- `objects` — which datapath object the unit pulls in, from
  `lib/bpf_{host,lxc,overlay,xdp}.h` and direct `#include "bpf_*.c"`;
- `units` — which datapath library modules a unit test exercises directly;
- `seeds` — which map-seeding helper groups the file's SETUP stage uses;
- `entrypoint` — resolved by following the SETUP stage's `return` to the entry
  helper it tail-calls, through up to three levels of local function or macro
  indirection, supplemented by the guarded evidence audit in §4.3.1.

Re-running the tool against a newer reference tag is the whole re-harvest
procedure (ADR-0005 §4).

### 4.3 Fidelity limits of the harvest

Stated so nobody mistakes the file for ground truth:

- **The 23 formerly unresolved cases are classified in §4.3.1.** Their
  audited evidence is checked by the Rust harvester. Unknown cases still remain
  `unresolved`; changing an audited setup or target mapping requires a new
  review rather than silently retaining its label.
- **`#if` expressions the evaluator cannot compute are assumed true**, which
  over-approximates the feature set of a handful of files. This is the safe
  direction (a superset of features means a superset of behaviour to test).
- **Milestones are derived, not authored.** `milestone_reason` records the rule
  that fired: an explicit spec 02 §9.3 group membership, a gating feature, an
  object, or the M1 default. Per-case milestone may be lower than its file's
  when the file is gated on a later-milestone feature only some of its cases
  use — e.g. `tc_lxc_lb_nodeport.c` defines `ENABLE_DSR` but only its four
  `*_dsr_*` cases are M2. Corrections are made in the tool's override tables,
  never by editing the generated file.

#### 4.3.1 Resolved entrypoint ambiguities (#267–272)

Reference ambiguity audit, 2026-09-09: Cilium v1.20.1,
`7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc`. This records behavior and
identifier relationships read under `docs/licensing.md`; no C implementation
or assertion sequence is copied into flowsdn. Rust regression inputs are
synthetic structural examples.

| Issue | Translation unit / cases | Resolved entrypoint | Evidence |
|---|---|---|---|
| #267 | `icmp_error_revnat.c`: `nat4_icmp_error_tcp_snat_revnat` | `direct` | SETUP invokes `snat_v4_rev_nat` directly and returns a test result; it does not enter a datapath program. |
| #268 | `ipv6_test.c`: `ipv6_without_extension_header`, `ipv6_with_auth_hop_tcp` | `direct` | SETUP returns sentinel values 123 / 1234; CHECK invokes `ipv6_hdrlen`. |
| #269 | `tc_nodeport_l3_dev.c`: four ingress and four egress cases | `from_netdev` / `to_netdev` | The shared SETUP helper passes its `is_ingress` parameter to program-array slot selection: slot 0 / 1 target `cil_from_netdev` / `cil_to_netdev`. |
| #272 | `tc_nodeport_l3_wireguard.c`: the same eight shared cases | `from_wireguard` / `to_wireguard` | The WireGuard inclusion selects the corresponding object and slot 0 / 1 target `cil_from_wireguard` / `cil_to_wireguard`. |
| #270, #271 | `l7_lb_local_backend_host.c`, `l7_lb_local_backend_pod.c`: IPv4 / IPv6 cases in each | `lxc_policy_egress` | SETUP calls `tail_call_egress_policy`; its mocked program-array dispatch targets `cil_lxc_policy_egress`. The host/pod variants simulate different callers, not different first programs under test. |

The `direct` classification covers library functions invoked in either SETUP
or CHECK. The mere presence of SETUP does not imply a datapath entrypoint.
The existing `progtype`, object, feature and milestone metadata remain intact:
these labels do not establish a runnable port, kernel support or test tier by
themselves. In particular, the WireGuard entrypoints retain the WireGuard
object and M3 milestone; the L7 cases retain the lxc object and M2 milestone.

The audit consulted these reference paths and locations:

- `bpf/tests/icmp_error_revnat.c`: SETUP at lines 73–122 and CHECK beginning
  at 124; the direct reverse-NAT operation is in SETUP.
- `bpf/tests/ipv6_test.c`: SETUP/CHECK pairs at lines 32–77 and 131–175.
- `bpf/tests/tc_nodeport_l3_dev.c` and `tc_nodeport_l3_wireguard.c`: inclusion
  mode definitions; `bpf/tests/tc_nodeport_l3_dev.h`: object includes at 60–78,
  entry array at 83–100, common SETUP at 182–227 and all eight SETUP call sites
  at 520–650. The first boolean argument determines direction independently
  of IP family and host/pod destination.
- `bpf/tests/l7_lb_local_backend_host.c` and `l7_lb_local_backend_pod.c`:
  configuration/include wrappers; `bpf/tests/l7_lb_local_backend.h`: mocked
  policy array and dispatch at 39–65, caller distinction at 67–91 and SETUP
  calls at 111–118 / 168–175. `bpf/bpf_lxc.c` at 2555–2584 confirms the
  egress-policy entrypoint's L7 return-path role.
- `bpf/bpf_wireguard.c` at 250–254 / 346–351 confirms ingress/egress program
  declarations. Supporting identifier searches also consulted
  `bpf/lib/policy.h`, `bpf/lib/tailcall.h` and `bpf/tests/lib/policy.h`.

The harvester applies these audited resolutions only to the exact listed
file/case identities, checking setup arguments, called helper, array targets
and included object as applicable. Comments and quoted strings cannot satisfy
evidence checks; ambiguous object sets are rejected. Each receives `entrypoint_resolution =
"spec-18 §4.3.1 audited evidence"`. Missing or changed evidence is an error;
unknown identities continue through the generic resolver and may remain
unresolved. The pinned-reference re-harvest must preserve all 625 cases and
all unrelated fields while reproducing these 23 resolutions.

### 4.4 `tests/bpf/PORTED.toml`

The hand-maintained companion, keyed on `(file, name)` from `CASES.toml`:

```toml
[[port]]
file = "bpf/tests/tc_nodeport_lb4_nat_lb.c"
name = "tc_nodeport_local_backend"
status = "ported"          # ported | deferred | retargeted | replaced | dropped
tier = "progrun"           # progrun | netns | direct | tier0
rust = "bpftest::tc_nodeport_lb4_nat_lb::tc_nodeport_local_backend"
```

with optional `disposition` (prose, required for `retargeted` / `replaced` /
`dropped`), `renamed_to`, `milestone_override`, `issue`. A `[[port]]` entry
whose key is absent from `CASES.toml` is an error (catches a reference-tag bump
that renamed a case); a `CASES.toml` case with no `[[port]]` entry counts as
unported in the coverage number.

### 4.5 Runtime types

| Type | Purpose |
|---|---|
| `PacketBuilder`, `Packet`, `LayerSpan`, `FieldMask`, `Field`, `Layer` | §3.2, §3.4 |
| `DatapathConfig` | generated typed view of `.rodata.config` (spec 01 §3.7) |
| `TestMaps` | typed handles to every map in the loaded collection, plus `snapshot()`/`assert_delta()` |
| `SkbCtx`, `XdpCtx` | `ctx_in`/`ctx_out` wrappers with named accessors |
| `Harness` | owns the netns, the loaded `Ebpf`, the perf reader and the stats collector |
| `RunResult { verdict, packet, ctx, events, duration }` | one `BPF_PROG_TEST_RUN` |
| `Verdict` | `retval` with a name table per program type |
| `VerifierStats { insns, stack_depth, states, peak_states, xlated_len, jited_len }` | §8.1 |
| `TestOutcome` | `Pass` / `Fail(Report)` / `Skip(SkipReason)` |

---

## 5. Algorithms

### 5.1 Case scheduling and map isolation

The reference shares one map set across every case in a `.c` file, runs
sub-tests in alphabetical order "to make test results repeatable if programs
rely on the order of execution", and has cases that delete their own entries in
the CHECK stage. That is a documented order dependence, and it is a bug
generator.

**flowsdn requires per-case isolation.** Every case observes a map set that
contains exactly what it seeded. The implementation balances that against the
cost of re-verifying an object (tens of milliseconds each, times 625):

1. Cases are grouped by **config signature** — the hash of
   `(object, DatapathConfig)`. Within a process, the first case in a group
   loads the object; subsequent cases in the same group reuse the loaded
   collection.
2. Between cases in a group the harness **clears every map**: hash-family maps
   by `BPF_MAP_LOOKUP_AND_DELETE_BATCH` (or iterate-and-delete where batch is
   unavailable), array-family maps by writing zeroes, LPM tries by iterate and
   delete, program arrays left alone (they are wiring, not state). It then
   **asserts the clear succeeded** by re-counting every map; a non-empty map
   after clearing fails the *next* case immediately with a distinctive error,
   rather than corrupting it.
3. `FLOWSDN_BPFTEST_ISOLATION=reload` forces a fresh load per case. CI runs the
   grouped mode on the PR gate and the `reload` mode nightly; a case that
   passes in one mode and fails in the other is an order dependence and is
   treated as a bug in the case.
4. Case order within a group is randomised with a seed printed in the run
   header (`--seed` to reproduce), which is the opposite of the reference's
   alphabetical determinism and is chosen deliberately: order dependence should
   surface, not be papered over.

### 5.2 Verifier statistics extraction

Two sources, both used, because neither is sufficient:

- **The verifier log.** Load with `log_level = 4` (`BPF_LOG_LEVEL_STATS`) and a
  large buffer; the terminal line carries `processed N insns (limit 1000000)
  max_states_per_insn M total_states T peak_states P mark_read R` and the
  per-subprogram lines carry `stack depth D` (and `D+E` when subprograms
  nest). Parsed with a strict regex; a parse failure is a hard error, not a
  silent zero, because a silently-zero budget is worse than no budget.
- **`BPF_OBJ_GET_INFO_BY_FD`** on the loaded program fd gives `verified_insns`
  (5.16+), `xlated_prog_len`, `jited_prog_len` and `nr_jited_func_lens`.
  `verified_insns` is authoritative where present and is cross-checked against
  the log; a mismatch is reported.

Output is one JSON document per (object, config-variant, kernel, arch) under
`target/bpf-stats/`, which spec 02 §9.4's gate consumes. Its schema:

```json
{ "object": "host", "variant": "all-features", "kernel": "6.12.0-55.el10",
  "arch": "x86_64", "programs": [
    { "name": "from_netdev", "insns": 412873, "stack_depth": 328,
      "total_states": 20114, "peak_states": 1782,
      "xlated_len": 61304, "jited_len": 39912, "tail_depth_observed": 4 } ] }
```

### 5.3 Coverage computation

`ported(m) = |{ c ∈ CASES : c.milestone ≤ m ∧ PORTED[c].status ∈ {ported,
retargeted, replaced} }|`, `total(m) = |{ c ∈ CASES : c.milestone ≤ m }|`
minus cases with `status = "dropped"`. The M1 gate is `ported(1) == total(1)`
before M1 is declared (spec 02 §9.5). Between now and then the gate is
monotonic: a PR may not decrease `ported(m)` for any `m`.

---

## 6. Configuration

### 6.1 Environment and flags

| Key | Type | Default | Effect |
|---|---|---|---|
| `FLOWSDN_BPFTEST_OBJDIR` | path | `target/bpfel-unknown-none/release` | where the `flowsdn-bpf` ELFs are found |
| `FLOWSDN_BPFTEST_ISOLATION` | `group` \| `reload` | `group` | §5.1 |
| `FLOWSDN_BPFTEST_SEED` | u64 | random, printed | case-order seed |
| `FLOWSDN_BPFTEST_STATS` | path | unset | write `VerifierStats` JSON here |
| `FLOWSDN_BPFTEST_DUMP` | `off` \| `fail` \| `all` | `fail` | dump packet/ctx before and after each stage — the analogue of the reference's `-dump-ctx` |
| `FLOWSDN_BPFTEST_EVENTS` | `off` \| `fail` \| `all` | `fail` | attach the decoded `cilium_events` stream to test output |
| `FLOWSDN_BPFTEST_KEEP_NETNS` | bool | false | leave the netns for post-mortem (`ip netns exec`) |
| `FLOWSDN_BPFTEST_TIER` | csv of tiers | all | restrict to `tier0,progrun,netns,direct` |
| `FLOWSDN_BPFTEST_MOCK` | `shim` \| `none` | `shim` | §3.6; `none` selects the production object and skips cases that need a mock |

Standard `cargo nextest` filters select individual cases; the reference's
`-test <prefix>` flag maps to `cargo nextest run -E 'test(/^bpftest::tc_nodeport/)'`.

### 6.2 Per-case configuration

A case's `DatapathConfig` is its configuration surface; there is no separate
file format. Config defaults come from `DatapathConfig::defaults()`, which MUST
equal the agent's defaults for the same keys, asserted by a Tier-0 test — so a
default that changes in the agent cannot silently change what the corpus tests.

### 6.3 Shared fixtures

Three artefacts are shared across harnesses and are therefore versioned as
data, not code:

| Fixture | Path | Consumers |
|---|---|---|
| Address / MAC / port book (§2.2) | `tests/fixtures/addresses.toml` | `flowsdn-bpftest`, `flowsdn-scripttest` (spec 17), `flowsdn-connectivity` (spec 19) |
| Packet fixtures — a named packet as a builder expression *and* its rendered hex, so a change in the builder that changes bytes is caught | `tests/fixtures/packets/*.toml` | `flowsdn-bpftest`, spec 19's traffic generator, spec 02 §9.2's per-pipeline acceptance set |
| Map-dump renderer — the same code that renders `lb/maps-dump`, `ct/dump`, `ipcache/dump` for scripttest assertions | `flowsdn-datapath::dump` | `flowsdn-bpftest` §3.4.5 failure output, `flowsdn-scripttest` `cmp` assertions, `flowsdn-dbg` |

The third is the important one: it means a scripttest scenario and a bpftest
case that disagree about a map's contents disagree in the same textual
representation, so the two suites' failures are directly comparable. The
scripttest corpus itself (txtar files) shares no fixture *values* with the BPF
corpus — upstream's txtar scenarios use their own addressing — so the address
book is shared as a *facility*, not as a coupling.

---

## 7. Failure modes

| Failure | Harness behaviour |
|---|---|
| Object fails to load (verifier rejection) | Hard fail the whole config group with the full verifier log, the offending instruction, and the `DatapathConfig` that produced it. Never retried with a reduced config — a config the loader would accept in production must load here. |
| `BPF_PROG_TEST_RUN` returns `EINVAL` for a `ctx_in` field | Fail with the field name and the kernel version, and point at the §3.3(d) to-verify list. A whole matrix row failing this way is a spec bug, not a case bug. |
| `BPF_PROG_TEST_RUN` returns `ENOTSUPP` for the program type | Skip with `SkipReason::ProgTypeNotRunnable`, and fail if the case is not marked `tier = "direct"` or `"netns"`. |
| `data_out` too small (`ENOSPC`) | Retry once with a doubled buffer, then fail with the required size. The kernel may grow a packet by up to the tailroom it was given. |
| Map full during seeding | Hard fail naming the map and its `max_entries`; a case that needs a bigger map states so in its `DatapathConfig`. |
| Map not empty after inter-case clear (§5.1) | Fail the *next* case immediately with `IsolationViolation { map, remaining }`; do not run it against dirty state. |
| Perf ring overflow while draining `cilium_events` | Report lost-sample count in the test output; fail only if the case asserts on events. Ring size is `64 × PAGE_SIZE` per CPU, which is 4 MiB/CPU on a 64 KiB-page arm64 kernel — never hard-code 4096 (kernel-requirements §1). |
| Netns creation fails (no `CAP_SYS_ADMIN` / no `CONFIG_NET_NS`) | Skip the netns tier with a reason; do not silently run those cases in the host netns. |
| Verifier-log parse failure (§5.2) | Hard error. A missing statistic must never be reported as zero. |
| Test process panics mid-case | `cargo nextest`'s process-per-test isolation contains it; the netns and all map fds die with the process. This is the main reason nextest is the supported runner (§11.5). |
| Reference tag bumped, case renamed | `CASES.toml` regenerates; `PORTED.toml` keys no longer resolve; the consistency test (§9.4) fails with the added/removed/renamed lists. Deliberate, per ADR-0005. |

---

## 8. Observability

### 8.1 Per-run statistics

Every load records `VerifierStats` (§5.2) and every run records wall-clock
duration and, when `repeat > 1`, the kernel's own `duration` (ns per
iteration). Emitted as JSON for CI and as a table at the end of an interactive
run.

### 8.2 Datapath logs

`cilium_events` is drained during and after each run. `DebugMsg` /
`DebugCapture` samples are decoded with the spec 11 decoders and printed with
the failing case, in emission order, prefixed with the program name — the
direct analogue of the reference driver's `MonitorFormatter` goroutine, and the
reason the reference's in-BPF `test_log` machinery is not needed. Under
`FLOWSDN_BPFTEST_EVENTS=all` they print for passing cases too.

### 8.3 Throughput mode

`cargo xtask bpftest --bench` re-runs a selected case with `repeat =
1_000_000` and reports ns/packet per pipeline. It asserts nothing (map state
mutates across iterations, §3.4) and is never a gate; it exists so that a
change that doubles the cost of `from_container` is visible before it reaches a
cluster. Numbers are recorded per kernel row for trend-watching.

### 8.4 Coverage reporting

`cargo xtask cases --summary` prints, and CI publishes, the §5.3 numbers:
ported/total overall, per milestone, per pipeline, per reference file; the list
of unported M1 cases; the list of cases skipped on each kernel row with the
reason. The M1 number is the one that appears in the project status.

### 8.5 What is deliberately not measured

The reference wires `coverbee` into the harness to produce line-level coverage
of the BPF C source. flowsdn does not: `coverbee` instruments by rewriting the
BPF CFG, which changes the program the verifier sees (the reference has a
`-no-test-coverage` regex and a `-instrumentation-log` flag precisely because
this breaks the verifier on complex programs). Coverage of the datapath is
measured instead by the case-inventory number (§8.4), which counts *behaviour*
rather than lines and cannot be gamed by instrumenting. Revisit if a
verifier-safe Rust/BPF coverage tool appears (§12.6).

---

## 9. Test plan (for the harness itself)

The harness is test infrastructure, so its own bugs are silent. It gets its own
tests, at the tiers of §10.3.

### 9.1 Harness self-tests, privileged (run first on every kernel matrix row)

- [ ] `BPF_PROG_TEST_RUN` round-trip: a trivial `#[classifier]` that returns
      `TC_ACT_OK` and copies `data_in` to `data_out` unchanged — asserts the
      syscall plumbing, buffer sizing and verdict decoding.
- [ ] `ctx_in`/`ctx_out` field matrix: for each of `mark`, `priority`,
      `cb[0..5]`, `ifindex`, `tstamp`, `wire_len`, `gso_segs`, `gso_size`,
      `hwtstamp`, `tc_index`, `ingress_ifindex`: set it, read it back in the
      program, mutate it, read it back in `ctx_out`. Records a per-kernel
      capability table and **resolves the §3.3(d) to-verify list**. A field the
      matrix says is unusable moves its dependent cases to the netns tier.
- [ ] XDP `ctx_in` matrix: same for `xdp_md`'s `ingress_ifindex`,
      `rx_queue_index`, `data_meta`; establishes whether a real device is
      required.
- [ ] packet growth: a program that calls `bpf_skb_adjust_room` /
      `bpf_skb_change_head` and grows the packet by more than the default
      tailroom — asserts the `ENOSPC` retry path of §7.
- [ ] `repeat` semantics: a program that increments a map counter; assert
      `repeat = N` runs it N times, documenting why correctness cases use 1.
- [ ] map clear: seed every map family (hash, LRU hash, per-CPU hash, array,
      per-CPU array, LPM trie, prog array, map-in-map), clear, assert empty —
      asserts §5.1 step 2 on every kernel (batch ops are 5.6+, per-CPU batch
      semantics differ).
- [ ] perf ring: emit more samples than the ring holds, assert the lost-sample
      count is reported and not silently dropped.
- [ ] netns lifecycle: create, attach with tcx, run, tear down, assert no
      leaked links, maps, devices or netns after 1000 iterations.
- [ ] verifier-stats parse: load a program on each kernel row, assert both
      sources (§5.2) agree and that the parse is not silently zero.

### 9.2 Packet builder, unprivileged (Tier 0, runs on any host)

- [ ] Round-trip: for every layer combination in a generated matrix
      (~400 combinations), `build()` then parse, assert every field survives.
- [ ] Checksums: cross-check IPv4/TCP/UDP/ICMPv4/ICMPv6/SCTP-CRC32c against an
      independent implementation (`etherparse` where it has one, a
      hand-written reference where it does not), over randomised inputs
      (`proptest`, ≥ 10 000 cases).
- [ ] Encapsulation: VXLAN and Geneve with and without options, inner v4 and
      v6, assert outer lengths and inner checksums are independent.
- [ ] Deliberate corruption: `Checksum::Bad` differs from `Checksum::Good` in
      exactly the checksum field; `tot_len_override` does not disturb anything
      else.
- [ ] Fragmentation: `fragment(pkt, mtu)` reassembles to the original for v4
      and v6, with correct `MF`/offset/`id` on every shard.
- [ ] Determinism: the same expression produces identical bytes across 1000
      builds, and on both endiannesses (a cross-compiled test on the arm64
      row).
- [ ] Golden: every `tests/fixtures/packets/*.toml` builds to its recorded hex
      (this is what catches an accidental default change).

### 9.3 Assertion vocabulary, unprivileged

- [ ] `FieldMask` semantics: masking a checksummed field implies masking its
      checksum; the mask is reported; an empty mask compares everything.
- [ ] Diff renderer: for a set of crafted expected/actual pairs, assert the
      rendered output names the right layer and field, highlights the right
      byte ranges, and is stable (snapshot-tested with `insta`).
- [ ] Verdict, mark and `cb[]` renderers decode every value in the spec 02
      §2.1/§2.3 contract.
- [ ] Monitor-event matcher: default-masked fields are not compared;
      `assert_none_matching` is not vacuously true.
- [ ] Map delta: `assert_delta` detects an addition, a removal, a mutation and
      an unexpected write to an unrelated map.

### 9.4 Harvest consistency, unprivileged

- [ ] `CASES.toml` parses, and its `[meta]` counts equal the sums of its rows.
- [ ] Every `PORTED.toml` key resolves to a `CASES.toml` case.
- [ ] Every `status = "ported"` entry names a Rust test path that exists (the
      generated stub list is the oracle).
- [ ] Every `retargeted` / `replaced` / `dropped` entry has a `disposition`.
- [ ] Coverage is monotonic against the previous commit (§5.3).
- [ ] Re-running `tools/harvest-bpf-cases (Rust)` against the pinned reference
      commit reproduces `CASES.toml` byte-for-byte (guards silent hand edits).
      Skipped with a clear message when the reference clone is absent.

### 9.5 The corpus itself

The 625 cases of `CASES.toml` are the test plan for the *datapath*, not for the
harness; they live in spec 02 §9.3 as a checklist and here as data. The gate is
§5.3: `ported(1) == total(1)` before M1 ships.

---

## 10. Kernel and platform requirements

### 10.1 Syscalls and program types

`bpf(2)` commands: `BPF_PROG_LOAD` (with `log_level = 4`), `BPF_MAP_CREATE`,
`BPF_MAP_{LOOKUP,UPDATE,DELETE}_ELEM`, `BPF_MAP_GET_NEXT_KEY`,
`BPF_MAP_LOOKUP_BATCH`, `BPF_MAP_LOOKUP_AND_DELETE_BATCH` (5.6),
`BPF_PROG_TEST_RUN`, `BPF_OBJ_GET_INFO_BY_FD`, `BPF_BTF_LOAD`,
`BPF_LINK_CREATE` (netns tier). `perf_event_open(2)` for `cilium_events`.
`unshare(CLONE_NEWNET)` / `setns(2)` for the netns. `AF_PACKET` raw sockets in
the netns tier.

Program types run under `BPF_PROG_TEST_RUN`: `BPF_PROG_TYPE_SCHED_CLS` and
`BPF_PROG_TYPE_XDP` for M1; `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (5.12) at M2 if
§12.5 is decided that way. `BPF_PROG_TYPE_TRACING` iterators are never run this
way (§3.9).

### 10.2 Kernel matrix

The harness runs on every row of `docs/kernel-requirements.md` §5.3:

| Row | Kernel | x86-64 | arm64 | BPF unit tests |
|---|---|---|---|---|
| Minimum | 6.6 LTS | LVH `6.6` | upstream 6.6.y VM | PR gate (x86), nightly (arm64) |
| Supported line | 6.12 (Rocky 10 `el10` and upstream 6.12.y) | Rocky 10 VM + LVH `6.12` | Rocky 10 `aarch64` VM, 4 KiB and 64 KiB pages | PR gate (both) |
| Next | 6.18 LTS | LVH `6.18` | upstream 6.18.y VM | nightly |
| Canary | latest / bpf-next | LVH latest | — | — |
| Not run | 4.18, 5.15, 6.1 | — | — | — |

Notes. The corpus needs `BPF_PROG_TEST_RUN` and a netns — **no NIC, no
cluster, no kube-apiserver** — so it runs inside the same VMs as the verifier
job. The arm64 rows exist because the JIT differs, not the verifier: they catch
tail-call/subprogram mixing, atomics, unaligned access and the 64 KiB-page perf
ring, none of which the x86 rows can. The 64 KiB-page arm64 row is
non-negotiable for the perf-ring assertions (§7).

`VerifierStats` are recorded on every row and fed to spec 02 §9.4's gate: fail
above 800 000 instructions or 480 B stack for any program in any config
variant; warn at +10 % against the previous commit. The config variants are the
flowsdn analogue of the reference's `bpf/complexity-tests/{510,61,netnext}`
option files: at minimum `m1-default`, `all-features`, and one per `dsr_mode`
value.

### 10.3 Privilege tiers

| Tier | Needs | Where it runs |
|---|---|---|
| **Tier 0** — packet builder, masks, renderers, ABI layout asserts, harvest consistency, map key/value codecs, monitor decoders | nothing | `cargo test` on any host, macOS included; part of the normal edit loop |
| **`direct`** — library functions in a tc/XDP wrapper (§3.9) | `CAP_BPF` + `CAP_PERFMON` | Linux VM |
| **`progrun`** — the main corpus | `CAP_BPF`, `CAP_PERFMON`, `CAP_IPC_LOCK` (perf mmap), `CAP_NET_ADMIN` (`CGROUP_SOCK*` load at M2), `CAP_SYS_ADMIN` (netns) | Linux VM |
| **`netns`** — real delivery, attach behaviour | the above plus `CONFIG_VETH`, `CONFIG_NETKIT` (6.7+), `CONFIG_NET_NS` | Linux VM |

**Unprivileged execution is not possible for anything above Tier 0, and the
harness does not pretend otherwise.** `unshare -Urn` gives `CAP_BPF` inside a
user namespace, but `bpf(2)` checks program-load capability against the initial
user namespace for `SCHED_CLS`, `XDP` and cgroup program types, so a rootless
run cannot load the datapath. The supported answer is root inside a throwaway
VM — which is what CI does, and what a developer gets from
`cargo xtask bpftest --vm 6.12`, a one-command wrapper that boots the matching
LVH or Rocky image, mounts the workspace, and runs `cargo nextest` inside.
Tier-0 tests exist precisely so the inner loop does not require that.

`RLIMIT_MEMLOCK` is not raised: BPF memory is memcg-accounted from 5.11 and the
floor is 6.6. The perf mmap still counts against memlock, hence `CAP_IPC_LOCK`.

### 10.4 CI without a cluster

The whole corpus is cluster-free by construction. The CI job is: build the
`flowsdn-bpf` ELFs on `<build-host>` (cross-project rule: never on the Mac), boot
each matrix VM, `cargo nextest run -p flowsdn-bpftest`, collect
`target/bpf-stats/*.json` and the coverage summary, and publish both. No kind,
no Docker network, no CNI, no image registry. Wall-clock target for the PR gate
is under 8 minutes per kernel row with the grouped isolation mode (§5.1); the
`reload` mode and the arm64 TCG rows run nightly.

---

## 11. Rust design notes

### 11.1 Crate layout

```
crates/
  flowsdn-bpftest/          the harness. Library + the generated test binary.
    src/
      pkt/                  PacketBuilder, Packet, layers, checksums, fragment
      assert/               FieldMask, diff renderer, verdict/mark/cb decoders
      run/                  bpf_prog_test_run wrapper, SkbCtx/XdpCtx, RunResult
      maps/                 TestMaps, seeding helpers, snapshot/delta, clear
      load/                 config-signature grouping, loader integration, stats
      netns/                NetnsFixture, veth/netkit, AF_PACKET inject/capture
      events/               perf drain + spec-11 decode + matchers
      harvest/              CASES.toml / PORTED.toml models and consistency
    tests/                  the generated corpus, one module per reference file
    build.rs                generates test stubs from CASES.toml (§11.3)
  flowsdn-bpf-testprogs/    tiny BPF objects used only by tests: mock_policy_verdict,
                            the direct-call wrappers of §3.9, the §9.1 self-test
                            programs. Never linked into flowsdn-bpf.
tests/
  bpf/CASES.toml            the harvest (generated)
  bpf/PORTED.toml           dispositions (hand-maintained)
  fixtures/addresses.toml   shared address book
  fixtures/packets/*.toml   shared packet fixtures
tools/
  harvest-bpf-cases/        the Rust harvester
```

`flowsdn-bpftest` depends on `flowsdn-datapath` (the production loader),
`flowsdn-bpf-abi` (the shared `#[repr(C)]` types) and `flowsdn-monitor` (event
decoders). It MUST NOT depend on `flowsdn-agent`: a datapath test that needs
the agent is a scripttest scenario, not a bpftest case.

### 11.2 `BPF_PROG_TEST_RUN` and aya

**GAP (to-verify).** As recalled at aya 0.13, aya exposes no
`BPF_PROG_TEST_RUN` wrapper — there is no `Program::test_run`, and
`aya::programs` offers attach and pin APIs only. cilium/ebpf, which the
reference uses, has `Program.Run(*RunOptions)` with `Data`, `DataOut`,
`Context`, `ContextOut`, `Repeat`, `Flags`, `CPU`. Every row here is to-verify
against the pinned aya version before Phase 2 starts:

| Need | aya status (to-verify) | Plan |
|---|---|---|
| `BPF_PROG_TEST_RUN` with `data_in/out`, `ctx_in/out`, `repeat`, `flags`, `cpu`, `duration`, `retval` | **absent** | Implement `flowsdn_bpftest::run::prog_test_run` directly over `libc::syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, size)` taking a `BorrowedFd` from `aya::programs::ProgramFd`. ~120 lines. Upstream it to aya as `Program::test_run` (ADR-0002 says fix gaps upstream where possible). |
| Program fd access (`AsFd` on a loaded program) | present via `ProgramFd` | — |
| `log_level = 4` on load and access to the verifier log on **success** | aya exposes the log on *failure* (`ProgramError::LoadError { verifier_log }`); the success-path log is what §5.2 needs | If unavailable, load with `EbpfLoader::verifier_log_level(VerifierLogLevel::STATS)` and, failing that, do the stats load through the same raw-syscall path with our own log buffer, discarding that fd and letting aya do the real load. Wasteful but honest; upstream a `verifier_log()` accessor. |
| `BPF_OBJ_GET_INFO_BY_FD` → `bpf_prog_info.verified_insns` | `aya::programs::ProgramInfo` exists; `verified_insns` coverage unknown | raw syscall fallback in the same module |
| Batch map ops (`BPF_MAP_LOOKUP_AND_DELETE_BATCH`) for §5.1 clearing | unknown | iterate-and-delete fallback, selected by a probe at harness start |
| Anonymous (unpinned) maps and full teardown on drop | present | — |
| `PerfEventArray` reader with lost-sample count | present (`AsyncPerfEventArray` / `PerfEventArray`) | use the sync reader; lost count from the perf record header |
| netns manipulation | out of scope for aya | `nix::sched::{unshare, setns}` + `rtnetlink` for devices; the netns tier reuses `flowsdn-datapath`'s netlink code |

The raw-syscall shim is confined to one module with one `unsafe` block per
command and its own Tier-0 tests against a trivial program, so the rest of the
harness stays safe Rust.

### 11.3 Test generation from the harvest

`build.rs` reads `tests/bpf/CASES.toml` and `tests/bpf/PORTED.toml` and emits,
per reference file, a module containing one item per case:

- `status = "ported"` → nothing (the hand-written test already exists in
  `tests/<file_stem>.rs`; the generator emits a compile-time assertion that a
  function with that path exists, so a rename breaks the build);
- `status = "deferred"` → `#[test] #[ignore = "deferred to M2"] fn <name>() {
  unimplemented!() }`, so `cargo nextest list` shows the complete corpus and the
  unported count is visible in every run, not only in a report;
- `status ∈ {retargeted, replaced}` → a stub whose `#[ignore]` reason quotes the
  `disposition`, keeping the reference name discoverable by `grep`.

This is the mechanism that makes "625 cases" a checklist the compiler enforces
rather than a number in a document.

### 11.4 Dependencies

| Need | Choice | Licence | Why |
|---|---|---|---|
| Packet parsing and checksum reference | `etherparse` | MIT/Apache-2.0 | Solid Ethernet/VLAN/IPv4(+options)/IPv6(+ext headers)/UDP/TCP/ICMPv4/ICMPv6 with pseudo-header checksums, `no_std`-capable, no C. **Used for parsing and as the checksum cross-check**, not as the builder. |
| Packet **building** | hand-rolled `PacketBuilder` | — | etherparse's builder cannot express what half the corpus needs: deliberately-wrong checksums and lengths, SCTP, IGMP, ESP/AH, VXLAN, Geneve with options, ARP, arbitrary nesting, or layer-span introspection for the diff renderer. Wrapping it to add those is more code than writing the ~800-line builder, and would leave the "wrong on purpose" cases fighting the library. Decision: build ours, keep etherparse as the independent oracle in §9.2 — two implementations that must agree is a stronger test than one library used twice. |
| Byte diff | `similar` | Apache-2.0 | the diff engine under the hexdump renderer |
| Snapshot tests of the renderer's own output | `insta` | Apache-2.0 | §9.3 only. **Not** used for packet expectations: a snapshot of a packet is an opaque blob that nobody reviews, and accepting a changed snapshot is one keystroke. Packet expectations are built, not snapshotted. |
| Property tests | `proptest` | MIT/Apache-2.0 | §9.2 checksum and round-trip fuzzing |
| Test runner | `cargo-nextest` | MIT/Apache-2.0 | process-per-test isolation (§7), per-test timeouts, JUnit output, filter expressions |
| TOML | `toml` + `serde` | MIT/Apache-2.0 | harvest models |
| Syscalls, netns | `libc`, `nix` | MIT / MIT | §11.2 |
| Loader, ABI, decoders | `flowsdn-datapath`, `flowsdn-bpf-abi`, `flowsdn-monitor` | — | in-tree |

All licences are on `docs/licensing.md`'s permitted list; `cargo deny` enforces
it. **No Python, no scapy, no `bpftool`, no shelling out**, anywhere in the
harness — the reference's diff path shells out to Python and its coverage path
shells out to Go tooling, and both become Rust here.

### 11.5 Runner semantics

Network namespaces are a **per-thread** property, so a harness that runs tests
as threads in one process must `setns` on the calling thread and can never let
a case's netns leak to another test's thread. That is achievable but fragile.
`cargo nextest` runs each test in its own process, which makes netns, map fds,
loaded programs and panics all naturally scoped. `cargo nextest` is therefore
the **supported** runner; plain `cargo test` works for Tier 0 and is rejected
at runtime for the privileged tiers with a message saying why. The config-group
optimisation of §5.1 is applied *within* a nextest process by grouping cases
into a small number of test functions per config signature when the group is
large — measured, and only where it matters.

---

## 12. Open decisions

1. **Helper mocking mechanism (§3.6).** Options: (a) feature-gated
   `#[inline(always)]` shim reading mock maps under `--features testmock`;
   (b) `freplace`/`BPF_PROG_TYPE_EXT` over non-inlined helper wrappers;
   (c) no mocking, netns for everything. **Recommendation: (a) for M1**, with
   the 5 % verifier-statistics divergence check and the netns cross-check per
   pipeline as the fidelity guard, and (b) re-evaluated at M2 once the
   datapath's subprogram structure is settled. Rationale: (a) is the only
   option that is cheap now and does not force production code shape; (b) is
   strictly better on fidelity but costs hot-path inlining and contradicts
   spec 02 §1.1's decision to drop `freplace`; (c) is a 40× slowdown on the
   majority of the corpus.

2. **Map isolation strategy (§5.1).** Options: (a) group by config signature
   and clear between cases (fast, needs correct clearing); (b) reload per case
   (slow, trivially correct); (c) the reference's model of sharing per file
   with alphabetical ordering. **Recommendation: (a) as the default with (b)
   nightly and available by env var**, and (c) explicitly rejected — the
   reference's own cases that delete their own entries in the CHECK stage are
   the evidence that shared state costs more than it saves.

3. **`CASES.toml` vs `CASES.md`.** Decided in favour of TOML (§4.1) with
   generated Markdown views. Recorded here rather than silently, because
   ADR-0005 left it open and a future re-harvest maintainer will want the
   reasoning. Revisit only if the file stops being machine-consumed.

4. **How much of the reference's `pktgen` default-value set to adopt.**
   Options: (a) adopt the defaults exactly (§3.2.1), so ported expectations —
   especially checksums — match the reference's numerically; (b) choose
   flowsdn defaults and recompute every expectation. **Recommendation: (a)**,
   because it makes the two suites' failures comparable during bring-up, which
   is the entire reason for keeping the case names. Cost: flowsdn inherits a
   few arbitrary constants (TTL 64, TCP window 65535, `default_data`) for no
   reason other than lineage; acceptable, and documented as such in the fixture
   file.

5. **Socket-LB cases at M2 (§3.9).** Options: (a) keep the reference's
   direct-call-in-an-XDP-wrapper form; (b) run the real `CGROUP_SOCK_ADDR`
   programs under `BPF_PROG_TEST_RUN` with a `bpf_sock_addr` `ctx_in` (5.12+,
   inside the floor); (c) both. **Recommendation: (c)** — (b) as the real test,
   (a) retained as a fast unit check — but the work is M2 and the decision can
   wait until the socket-LB spec lands. Note that (b) tests something upstream
   does not test at all.

6. **BPF code coverage (§8.5).** Options: (a) none, rely on the case inventory;
   (b) port the reference's `coverbee` approach; (c) wait for a verifier-safe
   Rust/BPF coverage tool. **Recommendation: (a) now, (c) watched.** (b) is
   rejected: CFG-rewriting instrumentation changes the program the verifier
   sees, which is why the reference needs a regex to disable it per file and a
   log to debug when it breaks the verifier.

7. **Netns-tier packet injection.** Options: (a) `AF_PACKET` `SOCK_RAW` send on
   the ingress device; (b) a `tc` action that injects; (c) a userspace TAP.
   **Recommendation: (a)** — simplest, no extra kernel objects, and the capture
   side is symmetric. Revisit if `AF_PACKET` send turns out to bypass the tcx
   ingress hook on some kernel (to-verify in §9.1's netns lifecycle test).

8. **Where the packet fixtures live relative to spec 19.** Options: (a) one
   `tests/fixtures/packets/` shared by bpftest and the e2e traffic generator;
   (b) separate sets. **Recommendation: (a)**, per spec 02 §9.2's requirement
   that fixtures be data files shareable with the e2e suite; the risk is that
   an e2e-driven change to a fixture silently changes a bpftest expectation,
   mitigated by the golden test in §9.2 that pins every fixture's rendered
   hex.

9. **Whether `flowsdn-bpf-testprogs` may use the datapath's own library
   modules.** Options: (a) yes, so a direct-call wrapper calls the real
   function; (b) no, to keep the test crate from constraining the datapath's
   internal API. **Recommendation: (a)** — the whole point of the 109
   `direct` cases is to call the real function — with the constraint that
   `flowsdn-bpf` exposes those functions behind a `#[doc(hidden)] pub mod
   testable` so the surface is explicit and its growth is visible in review.

10. **Reference tag bump cadence.** Options: (a) pin `v1.20.1` until M1 ships;
    (b) track upstream minor releases. **Recommendation: (a)** — ADR-0005 says
    a harvested corpus tracks one tag and bumping is deliberate; bumping mid-M1
    would churn `CASES.toml` and `PORTED.toml` for cases that are not yet
    ported anyway. Re-harvest once after M1, as a single reviewed commit.
