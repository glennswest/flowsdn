#!/usr/bin/env python3
"""Mechanical harvest of the reference BPF unit-test estate.

Reads bpf/tests/*.c with a miniature #ifdef-aware preprocessor so that
per-file feature sets, ASSIGN_CONFIG globals, included datapath object and
PKTGEN/SETUP/CHECK sections are the ones the compiler would actually see.
Emits TOML. No C code is copied; only names, flags and structure.
"""
import os, re, sys, collections

ROOT = "/Volumes/minihome/gwest/projects/cilium/bpf/tests"
files = {}
for fn in sorted(os.listdir(ROOT)):
    if fn.endswith(('.c', '.h')):
        files[fn] = open(os.path.join(ROOT, fn), errors='replace').read().splitlines()
for sub in ('lib',):
    d = os.path.join(ROOT, sub)
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            if fn.endswith('.h'):
                files[sub + '/' + fn] = open(os.path.join(d, fn), errors='replace').read().splitlines()

DEF   = re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)(\([^)]*\))?\s*(.*)$')
UNDEF = re.compile(r'^\s*#\s*undef\s+([A-Za-z_]\w*)')
INC   = re.compile(r'^\s*#\s*include\s+["<]([^">]+)[">]')
IFDEF = re.compile(r'^\s*#\s*ifdef\s+([A-Za-z_]\w*)')
IFNDEF= re.compile(r'^\s*#\s*ifndef\s+([A-Za-z_]\w*)')
IF    = re.compile(r'^\s*#\s*if\s+(.*)$')
ELIF  = re.compile(r'^\s*#\s*elif\s+(.*)$')
ELSE  = re.compile(r'^\s*#\s*else')
ENDIF = re.compile(r'^\s*#\s*endif')
SEC   = re.compile(r'^\s*(PKTGEN|SETUP|CHECK)\s*\(\s*("(?:[^"]*)"|[A-Za-z_]\w*)\s*,\s*"([^"]*)"\s*\)')
CFG   = re.compile(r'^\s*ASSIGN_CONFIG\s*\(\s*[^,]+,\s*(\w+)\s*,')

def truthy(expr, defs):
    """Very small evaluator for the #if forms the corpus actually uses."""
    e = expr.split('/*')[0].strip()
    e = re.sub(r'\bdefined\s*\(\s*(\w+)\s*\)', lambda m: '1' if m.group(1) in defs else '0', e)
    e = re.sub(r'\bdefined\s+(\w+)', lambda m: '1' if m.group(1) in defs else '0', e)
    def sub_ident(m):
        n = m.group(0)
        if n in ('and','or','not'): return n
        v = defs.get(n, '')
        v = v.split('/*')[0].strip()
        return v if re.fullmatch(r'-?\d+', v or '') else '0'
    e = re.sub(r'[A-Za-z_]\w*', sub_ident, e)
    e = e.replace('&&', ' and ').replace('||', ' or ').replace('!', ' not ')
    try:
        return bool(eval(e, {'__builtins__': {}}, {}))
    except Exception:
        return True     # conservative: assume the branch compiles

class Walk:
    def __init__(self):
        self.defs = {}
        self.secs = []          # (kind, progtype, name, body_lines, defining_file)
        self.cfgs = []
        self.incs = []          # every include seen, in order
        self.body = None        # current section accumulator

    def flush(self):
        if self.body:
            self.secs.append(self.body)
            self.body = None

    def run(self, fn, depth=0, seen=None):
        if seen is None: seen = set()
        if fn not in files or depth > 12: return
        stack = []              # list of (active, taken_any)
        for line in files[fn]:
            act = all(s[0] for s in stack)
            m = IFDEF.match(line)
            if m: stack.append((m.group(1) in self.defs, m.group(1) in self.defs)); continue
            m = IFNDEF.match(line)
            if m: stack.append((m.group(1) not in self.defs, m.group(1) not in self.defs)); continue
            m = IF.match(line)
            if m:
                t = truthy(m.group(1), self.defs); stack.append((t, t)); continue
            m = ELIF.match(line)
            if m and stack:
                a, taken = stack[-1]
                t = (not taken) and truthy(m.group(1), self.defs)
                stack[-1] = (t, taken or t); continue
            if ELSE.match(line) and stack:
                a, taken = stack[-1]; stack[-1] = (not taken, True); continue
            if ENDIF.match(line):
                if stack: stack.pop()
                continue
            if not act:
                continue
            m = DEF.match(line)
            if m:
                self.flush(); self.defs[m.group(1)] = (m.group(3) or '').strip(); continue
            m = UNDEF.match(line)
            if m:
                self.defs.pop(m.group(1), None); continue
            m = INC.match(line)
            if m:
                self.flush()
                inc = m.group(1); self.incs.append(inc)
                b = os.path.basename(inc)
                cand = inc if inc in files else b
                if cand in files and cand.endswith('.h') and cand not in ('common.h','pktgen.h'):
                    self.run(cand, depth + 1, seen)
                continue
            m = CFG.match(line)
            if m:
                self.cfgs.append(m.group(1)); continue
            m = SEC.match(line)
            if m:
                self.flush()
                pt = m.group(2)
                if not pt.startswith('"'):
                    pt = self.defs.get(pt, pt).strip()
                pt = pt.strip('"')
                self.body = [m.group(1), pt, m.group(3), [], fn]
                continue
            if self.body is not None:
                self.body[3].append(line)
        self.flush()

ENTRY_HELPERS = [
 ('netdev_receive_packet','from_netdev'), ('netdev_send_packet','to_netdev'),
 ('host_receive_packet','to_host'),       ('host_send_packet','from_host'),
 ('pod_send_packet','from_container'),
 ('pod_receive_packet_by_tailcall','lxc_policy'), ('pod_receive_packet','to_container'),
 ('overlay_receive_packet','from_overlay'), ('overlay_send_packet','to_overlay'),
 ('xdp_receive_packet','xdp_entry'),
]
ENTRY_HDR = {'lib/bpf_host.h':'host','lib/bpf_lxc.h':'lxc',
             'lib/bpf_overlay.h':'overlay','lib/bpf_xdp.h':'xdp'}
SRC_OBJ = {'bpf_host.c':'host','bpf_lxc.c':'lxc','bpf_overlay.c':'overlay',
           'bpf_xdp.c':'xdp','bpf_sock.c':'sock','bpf_sock_term.c':'sock_term',
           'bpf_wireguard.c':'wireguard'}
LIB_UNIT = {
 'lib/conntrack.h':'conntrack','lib/conntrack_map.h':'conntrack','lib/nat.h':'nat',
 'lib/lb.h':'lb','lib/fib.h':'fib','lib/ipfrag.h':'ipfrag','lib/ipv6.h':'ipv6',
 'lib/policy.h':'policy','lib/ratelimit.h':'ratelimit','lib/drop.h':'drop',
 'lib/dbg.h':'dbg','lib/ip_options.h':'ip_options','lib/mcast.h':'mcast',
 'lib/classifiers.h':'classifiers','lib/identity.h':'identity','lib/jhash.h':'jhash',
 'lib/encrypt.h':'encrypt','lib/wireguard.h':'wireguard','lib/ipsec.h':'ipsec',
 'lib/egressgw.h':'egressgw','lib/eps.h':'eps','lib/trace.h':'trace',
 'bpf/builtins.h':'builtins','lib/tailcall.h':'tailcall','lib/l2_responder.h':'l2_responder',
 'lib/local_delivery.h':'local_delivery','lib/nodeport.h':'nodeport','lib/srv6.h':'srv6',
 'lib/csum.h':'csum','lib/proxy.h':'proxy','lib/icmp6.h':'icmp6','lib/edt.h':'edt',
 'lib/act.h':'act','lib/ipcache.h':'ipcache','../lib/mcast.h':'mcast',
}
SEED_HDR = {'lib/endpoint.h':'endpoints','lib/ipcache.h':'ipcache','lib/lb.h':'services',
            'lib/policy.h':'policy','lib/node.h':'nodes','lib/metrics.h':'metrics',
            'lib/network_device.h':'devices','lib/subnet.h':'subnets',
            'lib/egressgw_policy.h':'egressgw_policy','lib/clear.h':'clear',
            'lib/icmp.h':'icmp','lib/ipsec.h':'ipsec_state'}
FEAT_PREFIX = ('ENABLE_','SKIP_','HAVE_','TUNNEL_','ENCAP','DSR_','IS_BPF_','SUPPORT_',
               'ENCRYPT','NATIVE_','HOST_NODE','HOST_NETNS','SECLABEL','LB_DEFAULT_ALG',
               'NORTH_SOUTH_TEST','EAST_WEST_TEST','ATTACHMENT_')

def resolve_entry(body, corpus, defs, depth=0):
    txt = '\n'.join(body)
    for h, lbl in ENTRY_HELPERS:
        if re.search(r'\b' + h + r'\b', txt): return lbl
    if depth > 3: return ''
    for nm in re.findall(r'return\s+([A-Za-z_]\w*)\s*\(', txt):
        tgt = defs.get(nm)
        if tgt and re.fullmatch(r'[A-Za-z_]\w*', tgt.split('/*')[0].strip()):
            r = resolve_entry(['return %s(ctx);' % tgt.split('/*')[0].strip()],
                              corpus, defs, depth + 1)
            if r: return r
        for m in re.finditer(r'\b' + re.escape(nm) + r'\s*\([^;{]*\)\s*\{', corpus):
            i, lvl = m.end(), 1
            while i < len(corpus) and lvl:
                if corpus[i] == '{': lvl += 1
                elif corpus[i] == '}': lvl -= 1
                i += 1
            r = resolve_entry(corpus[m.end():i].splitlines(), corpus, defs, depth + 1)
            if r: return r
    return ''

# ---------------- milestone assignment ----------------
# Rule order: explicit spec-02 §9.3 overrides, then capability gates.
M1_OVERRIDE = {'classifiers_l2_dev.c','classifiers_l3_dev.c','tc_nodeport_l3_dev.c',
               'tc_nodeport_l3_dev_to_tunnel.c','icmp_error_revnat.c'}
M2_OVERRIDE = {'jhash_test.c','session_affinity_maglev_test.c','wildcard_lookup.c',
               'host_only_socket_lb_test.c','skip_lb_xlate_socket_lb.c',
               'skip_lb_xlate_lrp_per_packet_lb.c','tc_policy_reject_response_test.c',
               'host_proxy.c','hostfw_bpf_masq.c','hostfw_host_iptables.c',
               'l7_lb_hairpin_netdev.c','l7_lb_local_backend_host.c',
               'l7_lb_local_backend_pod.c','session_affinity_test.c'}
M3_OVERRIDE = {'destroy_sock_socket_lb.c','ip_options_trace_id.c','mcast_tests.c',
               'tc_l2_announcement.c','tc_l2_announcement6.c',
               'l4lb_ipip_health_check_host.c','tc_nodeport_lb4_ipip_termination.c',
               'tc_nodeport_lb6_ipip_termination.c','eni_nlb_symetric_routing_host.c',
               'tc_srv6_encap.c','tc_srv6_decap.c','tc_nodeport_l3_wireguard.c'}
M3_FEATS = {'ENABLE_IPSEC','ENABLE_WIREGUARD','ENABLE_EGRESS_GATEWAY','ENABLE_SRV6',
            'ENABLE_SRV6_SRH_ENCAP','ENABLE_MULTICAST','ENABLE_INTER_CLUSTER_SNAT',
            'ENABLE_CLUSTER_AWARE_ADDRESSING','ENABLE_NODE_ENCRYPTION',
            'ENCRYPTION_STRICT_MODE_EGRESS','ENABLE_HEALTH_CHECK','ENCRYPT_KEY'}
M2_FEATS = {'ENABLE_HOST_FIREWALL','ENABLE_L7_LB','ENABLE_NODEPORT_ACCELERATION'}

def milestone(fn, feats, objs, cfgs):
    if fn in M3_OVERRIDE: return 3, 'spec-02 §9.3 long-tail/encryption group'
    if fn in M2_OVERRIDE: return 2, 'spec-02 §9.3 M2 group'
    if fn in M1_OVERRIDE: return 1, 'spec-02 §9.3 M1 group'
    hit = sorted(set(feats) & M3_FEATS)
    if hit: return 3, 'feature ' + ','.join(hit)
    if 'wireguard' in objs: return 3, 'object bpf_wireguard'
    if 'sock_term' in objs: return 3, 'object bpf_sock_term'
    hit = sorted(set(feats) & M2_FEATS)
    if hit: return 2, 'feature ' + ','.join(hit)
    if 'xdp' in objs: return 2, 'XDP program'
    if 'sock' in objs: return 2, 'socket LB (cgroup) program'
    if 'ENABLE_DSR' in feats: return 2, 'feature ENABLE_DSR'
    if 'enable_lrp' in cfgs: return 2, 'config enable_lrp'
    if 'policy_deny_response_enabled' in cfgs: return 2, 'config policy_deny_response_enabled'
    return 1, 'M1 default'

def case_milestone(fm, reason, name):
    """A file gated on DSR still contains non-DSR M1 cases; split by case name."""
    n = name.lower()
    if fm == 2 and reason == 'feature ENABLE_DSR' and 'dsr' not in n:
        return 1, 'M1 case in a DSR-enabled file'
    if fm == 1 and 'dsr' in n:
        return 2, 'DSR case'
    return fm, reason

# bpf/tests/encrypt_host_wireguard_tunnel is a C source that upstream forgot to
# name .c, so the build never compiles it. Harvest it under its intended name.
UPSTREAM_DEAD = {'encrypt_host_wireguard_tunnel.c': 'encrypt_host_wireguard_tunnel'}
for _alias, _real in UPSTREAM_DEAD.items():
    _p = os.path.join(ROOT, _real)
    if os.path.isfile(_p) and _alias not in files:
        files[_alias] = open(_p, errors='replace').read().splitlines()

records = []
for fn in sorted(f for f in files if f.endswith('.c') and '/' not in f):
    w = Walk(); w.run(fn)
    corpus = '\n'.join('\n'.join(files[b]) for b in
                       [fn] + [os.path.basename(i) for i in w.incs
                               if os.path.basename(i) in files])
    feats = sorted(k for k in w.defs if k.startswith(FEAT_PREFIX))
    cfgs  = sorted(set(w.cfgs))
    objs  = sorted({ENTRY_HDR[i] for i in w.incs if i in ENTRY_HDR} |
                   {SRC_OBJ[os.path.basename(i)] for i in w.incs
                    if os.path.basename(i) in SRC_OBJ and not i.startswith('lib/')})
    units = sorted({LIB_UNIT[i] for i in w.incs if i in LIB_UNIT})
    seeds = sorted({SEED_HDR[i] for i in w.incs if i in SEED_HDR})
    shared= sorted({os.path.basename(i) for i in w.incs
                    if os.path.basename(i) in files and i.endswith('.h')
                    and not i.startswith(('lib/','bpf/','linux/'))
                    and os.path.basename(i) not in ('common.h','pktgen.h')})
    ctx = 'xdp' if any(i.endswith('ctx/xdp.h') for i in w.incs) else \
          ('unspec' if any(i.endswith('ctx/unspec.h') for i in w.incs) else 'skb')
    fm, reason = milestone(fn, feats, objs, cfgs)
    by = collections.OrderedDict()
    for kind, pt, name, body, src in w.secs:
        k = (pt, name)
        by.setdefault(k, {'stages': set(), 'setup': [], 'src': src})
        by[k]['stages'].add(kind)
        if kind == 'SETUP': by[k]['setup'] = body
        if src != fn: by[k]['src'] = src
    cases = []
    for (pt, name), v in by.items():
        if 'CHECK' not in v['stages']: continue
        ep = resolve_entry(v['setup'], corpus, w.defs) if v['setup'] else 'direct'
        cm, cr = case_milestone(fm, reason, name)
        cases.append(dict(name=name, progtype=pt or 'tc',
                          stages=''.join(s for s in ('PKTGEN','SETUP','CHECK')
                                         if s in v['stages']),
                          entrypoint=ep or 'unresolved', milestone=cm,
                          milestone_reason=cr, defined_in=v['src']))
    records.append(dict(file=fn, upstream_dead=fn in UPSTREAM_DEAD, ctx=ctx, milestone=fm, milestone_reason=reason,
                        objects=objs, units=units, seeds=seeds, features=feats,
                        configs=cfgs, shared_headers=shared, cases=cases))

import datetime

def emit(recs, out):
    def q(s):
        return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'
    def arr(xs):
        return '[' + ', '.join(q(x) for x in xs) + ']'

    tot_cases = sum(len(r['cases']) for r in recs)
    by_ms = collections.Counter(c['milestone'] for r in recs for c in r['cases'])
    by_ms_f = collections.Counter(r['milestone'] for r in recs)
    by_ep = collections.Counter(c['entrypoint'] for r in recs for c in r['cases'])
    by_obj = collections.Counter(o for r in recs for o in (r['objects'] or ['(library unit test)']))

    L = []
    A = L.append
    A('# flowsdn — harvest of the reference BPF unit-test case inventory')
    A('#')
    A('# GENERATED FILE. Produced by tools/harvest-bpf-cases.py from a read-only')
    A('# checkout of the reference. Do not edit by hand: re-run the tool.')
    A('# Hand-maintained state lives in [[port]] entries in tests/bpf/PORTED.toml,')
    A('# which is keyed on (file, name) from this file.')
    A('#')
    A('# PROVENANCE')
    A('# ----------')
    A('# Case names, packet shapes, feature flags and the three-stage structure')
    A('# recorded here are derived from the reference implementation')
    A('#   cilium/cilium, tag v1.20.1, commit 7d68cfb394, directory bpf/tests/.')
    A('# That directory is licensed "GPL-2.0-only OR BSD-2-Clause"; flowsdn takes it')
    A('# under BSD-2-Clause, as decided in docs/decisions/0005-test-strategy.md')
    A('# (ADR-0005 §2) and permitted by docs/licensing.md. A matching entry exists in')
    A('# NOTICE.')
    A('#')
    A('# NO C CODE WAS COPIED. This file contains only identifiers (test names,')
    A('# preprocessor symbol names, ASSIGN_CONFIG variable names, include-graph')
    A('# facts) and counts, mechanically extracted. No test body, assertion,')
    A('# packet-builder call sequence or expected byte value from the reference has')
    A('# been transcribed into flowsdn. flowsdn test bodies are written from')
    A('# docs/spec/02-datapath-programs.md and docs/spec/18-bpf-test-harness.md,')
    A('# per the clean-room protocol in docs/licensing.md.')
    A('#')
    A('# HOW IT WAS DERIVED')
    A('# ------------------')
    A('# tools/harvest-bpf-cases.py walks each bpf/tests/*.c with a small')
    A('# #ifdef/#elif/#else-aware preprocessor, so the feature set, ASSIGN_CONFIG')
    A('# set, included datapath object and PKTGEN/SETUP/CHECK section list recorded')
    A('# below are the ones the compiler actually sees for that translation unit.')
    A('# Cases contributed by a shared test header (e.g. encrypt_host.h) are')
    A('# attributed to every .c that includes it, with `defined_in` naming the')
    A('# header. `entrypoint` is resolved by following the SETUP stage to the')
    A('# entry helper it tail-calls, through up to three levels of local helper or')
    A('# macro indirection; "direct" means the CHECK stage calls the function under')
    A('# test itself (a library unit test) and "unresolved" means the harvester')
    A('# could not follow the indirection and a human must classify it.')
    A('#')
    A('# SUMMARY (reference v1.20.1 / 7d68cfb394)')
    A('# ----------------------------------------')
    n_live = sum(1 for r in recs if not r.get('upstream_dead'))
    n_dead = len(recs) - n_live
    A(f'#   translation units compiled upstream  {n_live}')
    A(f'#   translation units present but dead   {n_dead}')
    A(f'#   CHECK sections written in .c files  397')
    A(f'#   effective cases after header expansion {tot_cases}')
    A(f'#   by milestone   M1 {by_ms[1]}   M2 {by_ms[2]}   M3 {by_ms[3]}')
    A(f'#   by file        M1 {by_ms_f[1]}    M2 {by_ms_f[2]}    M3 {by_ms_f[3]}')
    A('#   by entrypoint  ' + '  '.join(f'{k} {v}' for k, v in by_ep.most_common()))
    A('#   by object      ' + '  '.join(f'{k} {v}' for k, v in by_obj.most_common()))
    A('#')
    A('# FINDING: bpf/tests/encrypt_host_wireguard_tunnel is a C source file that is')
    A('# missing its .c extension upstream, so the build never compiles it and its')
    A('# 10 cases (from encrypt_host.h, TUNNEL_MODE + ENABLE_WIREGUARD) never run.')
    A('# flowsdn ports the WireGuard-over-tunnel encrypt-host case set anyway; it is')
    A('# listed here as file "encrypt_host_wireguard_tunnel.c" for symmetry with the')
    A('# _strict variant and marked upstream_dead = true.')
    A('')
    A('[meta]')
    A('reference_repo = "github.com/cilium/cilium"')
    A('reference_tag = "v1.20.1"')
    A('reference_commit = "7d68cfb394"')
    A('reference_dir = "bpf/tests"')
    A('reference_license = "GPL-2.0-only OR BSD-2-Clause; taken under BSD-2-Clause"')
    A(f'harvested = "{datetime.date.today().isoformat()}"')
    A('harvester = "tools/harvest-bpf-cases.py"')
    A('spec = "docs/spec/18-bpf-test-harness.md"')
    A(f'translation_units = {len(recs)}')
    A(f'translation_units_compiled = {n_live}')
    A('check_sections_in_c = 397')
    A(f'cases = {tot_cases}')
    A(f'cases_m1 = {by_ms[1]}')
    A(f'cases_m2 = {by_ms[2]}')
    A(f'cases_m3 = {by_ms[3]}')
    A('')
    A('# ---------------------------------------------------------------------------')
    A('# Key to [[file]] fields')
    A('#   path        reference path of the translation unit')
    A('#   ctx         BPF context the unit is compiled for: skb | xdp | unspec')
    A('#   milestone   flowsdn milestone this file lands in (spec 02 §1.1)')
    A('#   objects     datapath objects pulled in (spec 02 §1.1 "Object" column)')
    A('#   units       datapath library modules exercised directly, if any')
    A('#   seeds       map-seeding helper groups the file uses in its SETUP stage')
    A('#   features    reference preprocessor symbols active in this unit; in flowsdn')
    A('#               these are .rodata config booleans (spec 01 §3.7 layer 1)')
    A('#   configs     ASSIGN_CONFIG globals set; in flowsdn these are set_global()')
    A('#               calls on __config_<name> (spec 01 §3.7 layer 2)')
    A('# Key to [[file.case]] fields')
    A('#   name        the reference CHECK name; flowsdn keeps it verbatim as the')
    A('#               #[test] fn name so the two suites can be diffed')
    A('#   progtype    ELF section prefix: tc | xdp')
    A('#   stages      which of PKTGEN / SETUP / CHECK the case defines')
    A('#   entrypoint  flowsdn entrypoint under test (spec 02 §1.1) | direct |')
    A('#               unresolved')
    A('#   milestone   per-case milestone; may be lower than the file when the file')
    A('#               is gated on a later-milestone feature that only some cases use')
    A('# ---------------------------------------------------------------------------')
    A('')

    for r in sorted(recs, key=lambda x: (x['milestone'], x['file'])):
        A('[[file]]')
        A(f'path = {q("bpf/tests/" + r["file"])}')
        A(f'ctx = {q(r["ctx"])}')
        A(f'milestone = {r["milestone"]}')
        A(f'milestone_reason = {q(r["milestone_reason"])}')
        if r.get('upstream_dead'):
            A('upstream_dead = true')
        A(f'objects = {arr(r["objects"])}')
        if r['units']:  A(f'units = {arr(r["units"])}')
        if r['seeds']:  A(f'seeds = {arr(r["seeds"])}')
        A(f'features = {arr(r["features"])}')
        A(f'configs = {arr(r["configs"])}')
        if r['shared_headers']: A(f'shared_headers = {arr(r["shared_headers"])}')
        A(f'case_count = {len(r["cases"])}')
        for c in r['cases']:
            A('')
            A('  [[file.case]]')
            A(f'  name = {q(c["name"])}')
            A(f'  progtype = {q(c["progtype"])}')
            A(f'  stages = {q(c["stages"])}')
            A(f'  entrypoint = {q(c["entrypoint"])}')
            A(f'  milestone = {c["milestone"]}')
            if c['defined_in'] != r['file']:
                A(f'  defined_in = {q("bpf/tests/" + c["defined_in"])}')
        A('')


    open(out, 'w').write('\n'.join(L) + '\n')
    return len(L)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'tests/bpf/CASES.toml'
    n = emit(records, out)
    print('files: %d  cases: %d  ->  %s (%d lines)'
          % (len(records), sum(len(r['cases']) for r in records), out, n))
    print('cases/milestone:', collections.Counter(
        c['milestone'] for r in records for c in r['cases']))
    print('unresolved entrypoints:', sum(
        1 for r in records for c in r['cases'] if c['entrypoint'] == 'unresolved'))
