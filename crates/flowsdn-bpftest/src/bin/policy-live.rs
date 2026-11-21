//! Endpoint network policy against the real kernel (#292, ADR-0021): the
//! local-delivery object's `local_delivery` (pod egress) and `to_container`
//! (pod ingress) programs test-run on frames as if on an endpoint's host
//! veth (a dummy device in a private network namespace), with the policy,
//! ipcache and policy-endpoint maps written through the loader. Covers an
//! unenforced endpoint, a tracking row whose flows survive enforcement
//! (#462), default deny, the host exception, neighbour
//! discovery and ARP, identity + protocol + port and port-range (LPM) allows,
//! the aggregate cluster identity and the wildcard identity, a top-precedence
//! deny, replies of allowed flows in the other direction (conntrack), ICMP
//! echo, ICMP and ICMPv6 errors about remembered flows as related traffic
//! (#463), IPv6, fragments, and removing enforcement. The host firewall
//! (#379): `from_netdev`/`to_netdev` as if on an uplink, for the host
//! endpoint: only traffic to the host's own address is judged, remote-node,
//! world and port rules, a deny over an allow, replies of flows the host
//! started, audit mode, learning (no flags), and the verdict counters. Local
//! Pods' traffic to the host (#384): the endpoint programs judge it by the
//! host endpoint's `HOST_PODS` entry (pod port rules, replies of flows the
//! host started to the Pod, audit, removal). Host egress (#477): `to_netdev`
//! judges the host's own packets by egress rules (allow, drop, deny,
//! forwarded traffic, replies both ways, audit) and `to_container` the
//! host's packets to a local Pod.
use flowsdn_bpf_abi::{
    IpCacheKey, RemoteEndpointInfo,
    policy::{
        EndpointPolicyKey, HOST_ENDPOINT, HOST_PODS, PolicyEndpoint, PolicyEntry, PolicyKey,
        enforce, verdict,
    },
};
use flowsdn_bpf_loader::kernel::{Egress, LocalDelivery, Object};
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd},
    process::Command,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[path = "testrun/syscall.rs"]
mod syscall;

const OK: u32 = 0;
const SHOT: u32 = 2;
const ENDPOINT: u16 = 7;
const POD: [u8; 4] = [10, 0, 0, 7];
const POD6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
const PEER: [u8; 4] = [10, 0, 1, 5];
const PEER6: [u8; 16] = [0xfd, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
const OTHER: [u8; 4] = [10, 0, 1, 6];
const CLUSTER: [u8; 4] = [10, 0, 1, 7];
const NODE: [u8; 4] = [10, 0, 0, 1];
const WORLD: [u8; 4] = [8, 8, 8, 8];
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const SYN: u8 = 2;
const ACK: u8 = 16;

fn ip(args: &[&str]) -> Result<()> {
    if Command::new("ip").args(args).status()?.success() {
        Ok(())
    } else {
        Err(format!("ip {} failed", args.join(" ")).into())
    }
}
fn ifindex(name: &str) -> Result<u32> {
    let out = Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .split(':')
        .next()
        .ok_or("ip link output")?
        .trim()
        .parse()?)
}

fn ether(kind: [u8; 2]) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
    frame.extend_from_slice(&kind);
    frame
}
/// IPv4 with `l4` after a 20-byte header; `fragment` is the offset field.
fn v4(proto: u8, src: [u8; 4], dst: [u8; 4], fragment: u16, l4: &[u8]) -> Vec<u8> {
    let mut frame = ether([0x08, 0x00]);
    let total = u16::try_from(l4.len().saturating_add(20)).unwrap_or(u16::MAX);
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[0, 1]);
    frame.extend_from_slice(&fragment.to_be_bytes());
    frame.extend_from_slice(&[64, proto, 0, 0]);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(l4);
    frame
}
fn v6(next: u8, src: [u8; 16], dst: [u8; 16], l4: &[u8]) -> Vec<u8> {
    let mut frame = ether([0x86, 0xdd]);
    let payload = u16::try_from(l4.len()).unwrap_or(u16::MAX);
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&payload.to_be_bytes());
    frame.extend_from_slice(&[next, 64]);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(l4);
    frame
}
fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    l4
}
fn udp(sport: u16, dport: u16) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&[0, 12, 0, 0, b'p', b'o', b'l', b'i']);
    l4
}
/// An ICMP or ICMPv6 error `kind`/`code` carrying `inner` (an IP frame,
/// Ethernet header stripped).
fn icmp_error(kind: u8, code: u8, inner: &[u8]) -> Vec<u8> {
    let mut l4 = vec![kind, code, 0, 0, 0, 0, 0, 0];
    l4.extend_from_slice(inner.get(14..).unwrap_or_default());
    l4
}
fn icmp(kind: u8, id: u16) -> Vec<u8> {
    let mut l4 = vec![kind, 0, 0, 0];
    l4.extend_from_slice(&id.to_be_bytes());
    l4.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    l4
}

struct Lab {
    delivery: LocalDelivery,
    ifindex: u32,
}
impl Lab {
    /// Test-run the pod-ingress (`to_container`) or pod-egress
    /// (`local_delivery`) program on `frame` arriving on the endpoint's veth.
    fn verdict(&self, egress: bool, frame: &[u8]) -> Result<u32> {
        let program = if egress {
            self.delivery.program()?
        } else {
            self.delivery.to_container_program()?
        };
        let fd = program.fd()?.as_fd().as_raw_fd();
        let mut ctx = [0u8; 192];
        ctx.get_mut(40..44)
            .ok_or("ctx")?
            .copy_from_slice(&self.ifindex.to_ne_bytes());
        let mut out = vec![0u8; 512];
        let mut ctx_out = [0u8; 192];
        Ok(syscall::run(fd, frame, &mut out, &ctx, &mut ctx_out)?.0)
    }
    fn expect(&self, what: &str, egress: bool, frame: &[u8], want: u32) -> Result<()> {
        let got = self.verdict(egress, frame)?;
        if got != want {
            let name = |v| if v == OK { "pass" } else { "drop" };
            return Err(format!("{what}: {} instead of {}", name(got), name(want)).into());
        }
        Ok(())
    }
    fn ingress(&self, what: &str, frame: &[u8], want: u32) -> Result<()> {
        self.expect(what, false, frame, want)
    }
    fn egress(&self, what: &str, frame: &[u8], want: u32) -> Result<()> {
        self.expect(what, true, frame, want)
    }
    fn enforce(&mut self, flags: u32) -> Result<()> {
        self.delivery.policy().set_policy_endpoint(
            self.ifindex,
            PolicyEndpoint {
                endpoint: u32::from(ENDPOINT),
                flags,
            },
        )
    }
    fn identity(&mut self, address: IpAddr, identity: u32) -> Result<()> {
        let key = match address {
            IpAddr::V4(a) => IpCacheKey::v4(a.octets(), 32, 0),
            IpAddr::V6(a) => IpCacheKey::v6(a.octets(), 128, 0),
        }
        .map_err(|_| "ipcache prefix")?;
        self.delivery.policy().upsert_ipcache(
            key,
            RemoteEndpointInfo {
                sec_identity: identity,
                ..Default::default()
            },
        )
    }
    /// One entry: `port_prefix` bits of `port` for `proto` (0: any L4).
    fn rule(&mut self, rule: Rule) -> Result<()> {
        let key = PolicyKey::new(
            rule.identity,
            rule.egress,
            rule.proto,
            rule.port,
            rule.port_prefix,
        )
        .map_err(|_| "policy key")?;
        let prefix = if rule.proto == 0 {
            0
        } else {
            rule.port_prefix.saturating_add(8)
        };
        let precedence = if rule.deny { u32::MAX } else { 1 };
        let entry = PolicyEntry::new(0, rule.deny, prefix, 0, false, precedence, 0)
            .map_err(|_| "policy entry")?;
        self.delivery
            .policy()
            .upsert_policy(EndpointPolicyKey::new(ENDPOINT, key), entry)
    }
}
#[derive(Clone, Copy)]
struct Rule {
    identity: u32,
    egress: bool,
    proto: u8,
    port: u16,
    port_prefix: u8,
    deny: bool,
}
fn allow(identity: u32, egress: bool, proto: u8, port: u16, port_prefix: u8) -> Rule {
    Rule {
        identity,
        egress,
        proto,
        port,
        port_prefix,
        deny: false,
    }
}

fn run(object: &[u8]) -> Result<()> {
    ip(&["link", "add", "ep0", "type", "dummy"])?;
    ip(&["link", "set", "ep0", "up"])?;
    let delivery = LocalDelivery::load_object(Object::Bytes(object), Egress::Stack)?;
    let mut lab = Lab {
        delivery,
        ifindex: ifindex("ep0")?,
    };
    let syn = |src, dport| v4(TCP, src, POD, 0, &tcp(40000, dport, SYN));

    lab.ingress("no policy endpoint", &syn(PEER, 80), OK)?;
    lab.egress(
        "no policy endpoint",
        &v4(UDP, POD, WORLD, 0, &udp(5000, 53)),
        OK,
    )?;
    if !lab.delivery.policy().policy_flows()?.is_empty() {
        return Err("an endpoint without a policy entry was tracked".into());
    }
    println!("PASS endpoint without a policy entry: both programs pass, nothing tracked");

    // #462: a tracking row (flags 0, a Pod no policy selects) judges nothing
    // but remembers flows, so connections opened before a policy first
    // selects the Pod keep working once it does.
    lab.enforce(0)?;
    lab.egress(
        "tracking: the Pod opens TCP 443",
        &v4(TCP, POD, PEER, 0, &tcp(43000, 443, SYN)),
        OK,
    )?;
    lab.ingress(
        "tracking: a peer opens TCP 5432",
        &v4(TCP, OTHER, POD, 0, &tcp(44000, 5432, SYN)),
        OK,
    )?;
    if lab.delivery.policy().policy_flows()?.len() < 2 {
        return Err("a tracking row did not remember its flows".into());
    }
    lab.enforce(enforce::INGRESS)?;
    lab.ingress(
        "enforced: the reply of the TCP 443 flow opened while tracking",
        &v4(TCP, PEER, POD, 0, &tcp(443, 43000, SYN | ACK)),
        OK,
    )?;
    lab.ingress(
        "enforced: the TCP 5432 flow opened while tracking",
        &v4(TCP, OTHER, POD, 0, &tcp(44000, 5432, ACK)),
        OK,
    )?;
    lab.ingress(
        "enforced: a new TCP 5432 flow",
        &v4(TCP, OTHER, POD, 0, &tcp(44001, 5432, SYN)),
        SHOT,
    )?;
    println!(
        "PASS tracking row: flows opened before enforcement keep working once ingress is enforced; new ones are judged"
    );

    lab.identity(IpAddr::V4(Ipv4Addr::from(PEER)), 300)?;
    lab.identity(IpAddr::V4(Ipv4Addr::from(OTHER)), 301)?;
    lab.identity(IpAddr::V4(Ipv4Addr::from(CLUSTER)), 302)?;
    lab.identity(IpAddr::V4(Ipv4Addr::from(NODE)), 1)?;
    lab.identity(IpAddr::V6(Ipv6Addr::from(PEER6)), 300)?;
    lab.enforce(enforce::INGRESS)?;
    lab.ingress("ingress enforced, no rules", &syn(PEER, 80), SHOT)?;
    lab.ingress("from the host", &syn(NODE, 80), OK)?;
    let mut arp = ether([0x08, 0x06]);
    arp.extend_from_slice(&[0; 28]);
    lab.ingress("ARP", &arp, OK)?;
    let solicit = v6(58, PEER6, POD6, &[135, 0, 0, 0, 0, 0, 0, 0]);
    lab.ingress("neighbour solicitation", &solicit, OK)?;
    let frag_needed = v4(ICMP, PEER, POD, 0, &[3, 4, 0, 0, 0, 0, 0, 0]);
    lab.ingress("fragmentation needed", &frag_needed, OK)?;
    lab.egress(
        "egress not enforced",
        &v4(UDP, POD, WORLD, 0, &udp(5001, 53)),
        OK,
    )?;
    println!(
        "PASS default deny on ingress; host, ARP, neighbour discovery and fragmentation-needed pass; egress not enforced"
    );

    lab.rule(allow(300, false, TCP, 80, 16))?;
    lab.rule(allow(301, false, TCP, 8080, 14))?;
    lab.ingress("identity 300 TCP 80", &syn(PEER, 80), OK)?;
    lab.ingress("identity 300 TCP 81", &syn(PEER, 81), SHOT)?;
    lab.ingress(
        "identity 300 UDP 80",
        &v4(UDP, PEER, POD, 0, &udp(40000, 80)),
        SHOT,
    )?;
    lab.ingress("identity 301 TCP 80", &syn(OTHER, 80), SHOT)?;
    lab.ingress("identity 301 TCP 8082 (8080/14)", &syn(OTHER, 8082), OK)?;
    lab.ingress("identity 301 TCP 8084", &syn(OTHER, 8084), SHOT)?;
    println!("PASS identity, protocol, port and port-range (LPM) allows; everything else dropped");

    let syn6 = |dport| v6(TCP, PEER6, POD6, &tcp(40000, dport, SYN));
    lab.ingress("IPv6 identity 300 TCP 80", &syn6(80), OK)?;
    lab.ingress("IPv6 identity 300 TCP 81", &syn6(81), SHOT)?;
    lab.ingress(
        "IPv4 fragment after the first",
        &v4(UDP, CLUSTER, POD, 0x00b9, &[0; 8]),
        SHOT,
    )?;
    println!("PASS IPv6 identity and port; non-first fragments dropped where enforced");

    lab.enforce(enforce::INGRESS | enforce::EGRESS)?;
    lab.egress(
        "reply to the allowed TCP 80 flow",
        &v4(TCP, POD, PEER, 0, &tcp(80, 40000, SYN | ACK)),
        OK,
    )?;
    lab.ingress(
        "established TCP 80 flow",
        &v4(TCP, PEER, POD, 0, &tcp(40000, 80, ACK)),
        OK,
    )?;
    lab.egress(
        "new egress, egress enforced, no rules",
        &v4(TCP, POD, PEER, 0, &tcp(41000, 9999, SYN)),
        SHOT,
    )?;
    let tracked = lab.delivery.policy().policy_flows()?;
    if !tracked
        .iter()
        .any(|(key, _)| key.egress == 0 && key.daddr.get(..4) == Some(&POD[..]))
    {
        return Err(format!("no ingress flow tracked: {} entries", tracked.len()).into());
    }
    println!(
        "PASS conntrack: the reply of an allowed ingress flow passes enforced egress; a new egress flow does not"
    );

    lab.rule(allow(11, false, 0, 0, 0))?;
    lab.ingress(
        "cluster identity 302 via aggregate-cluster",
        &v4(UDP, CLUSTER, POD, 0, &udp(40000, 53)),
        OK,
    )?;
    lab.ingress(
        "world via aggregate-cluster",
        &v4(UDP, WORLD, POD, 0, &udp(40000, 53)),
        SHOT,
    )?;
    lab.rule(allow(0, true, 0, 0, 0))?;
    lab.egress(
        "egress to world via the wildcard identity",
        &v4(TCP, POD, WORLD, 0, &tcp(42000, 443, SYN)),
        OK,
    )?;
    lab.rule(Rule {
        deny: true,
        ..allow(300, false, TCP, 22, 16)
    })?;
    lab.ingress(
        "deny for 300 over the aggregate allow",
        &syn(PEER, 22),
        SHOT,
    )?;
    lab.ingress("aggregate allow for 302 on port 22", &syn(CLUSTER, 22), OK)?;
    println!(
        "PASS aggregate-cluster and wildcard identities; a top-precedence deny wins over a broader allow"
    );

    for (identity, egress) in [(0, true), (11, false)] {
        lab.delivery.policy().remove_policy(EndpointPolicyKey::new(
            ENDPOINT,
            PolicyKey::new(identity, egress, 0, 0, 0).map_err(|_| "key")?,
        ))?;
    }
    lab.rule(allow(300, true, ICMP, 0, 0))?;
    lab.egress(
        "echo request to 300",
        &v4(ICMP, POD, PEER, 0, &icmp(8, 77)),
        OK,
    )?;
    lab.ingress("its echo reply", &v4(ICMP, PEER, POD, 0, &icmp(0, 77)), OK)?;
    lab.ingress(
        "an echo reply nobody asked for",
        &v4(ICMP, PEER, POD, 0, &icmp(0, 78)),
        SHOT,
    )?;
    println!("PASS ICMP echo: the request is allowed by protocol, its reply by conntrack");
    related_errors(&lab)?;

    let entries = lab.delivery.policy().policy_entries()?;
    if entries.len() != 4
        || entries
            .iter()
            .any(|(k, _)| k.endpoint != u32::from(ENDPOINT))
    {
        return Err(format!("policy map holds {} entries, expected 4", entries.len()).into());
    }
    if lab.delivery.policy().ipcache_entries()?.len() != 5 {
        return Err("ipcache does not hold the 5 written prefixes".into());
    }
    lab.delivery.policy().remove_policy_endpoint(lab.ifindex)?;
    lab.ingress("enforcement removed", &syn(PEER, 81), OK)?;
    lab.egress(
        "enforcement removed",
        &v4(TCP, POD, PEER, 0, &tcp(41000, 9999, SYN)),
        OK,
    )?;
    println!("PASS maps read back as written; removing the policy endpoint stops enforcement");
    host(&mut lab)?;
    host_egress(&mut lab)?;
    remote_node_aggregate(&mut lab)
}

/// ICMP errors as related traffic (#463). Ingress is enforced with no ICMP
/// rule; egress allows ICMP (not ICMPv6) to identity 300 only. Tracked: the
/// ingress TCP flows PEER6:40000 -> POD6:80 and OTHER:40000 -> POD:8082 and
/// the echo POD -> PEER id 77.
fn related_errors(lab: &Lab) -> Result<()> {
    let echo77 = v4(ICMP, POD, PEER, 0, &icmp(8, 77));
    lab.ingress(
        "host unreachable from a router about the tracked echo",
        &v4(ICMP, OTHER, POD, 0, &icmp_error(3, 1, &echo77)),
        OK,
    )?;
    lab.ingress(
        "time exceeded about the tracked echo",
        &v4(ICMP, WORLD, POD, 0, &icmp_error(11, 0, &echo77)),
        OK,
    )?;
    lab.ingress(
        "host unreachable about an echo nobody sent",
        &v4(
            ICMP,
            OTHER,
            POD,
            0,
            &icmp_error(3, 1, &v4(ICMP, POD, PEER, 0, &icmp(8, 99))),
        ),
        SHOT,
    )?;
    lab.ingress(
        "an error whose embedded packet the Pod did not send",
        &v4(
            ICMP,
            OTHER,
            POD,
            0,
            &icmp_error(3, 1, &v4(ICMP, OTHER, PEER, 0, &icmp(8, 77))),
        ),
        SHOT,
    )?;
    // Egress ICMP to 301 has no rule: only a related error passes.
    let tcp8082 = v4(TCP, OTHER, POD, 0, &tcp(40000, 8082, ACK));
    lab.egress(
        "port unreachable to 301 about the tracked TCP 8082 flow's packet",
        &v4(ICMP, POD, OTHER, 0, &icmp_error(3, 3, &tcp8082)),
        OK,
    )?;
    let untracked = v4(TCP, OTHER, POD, 0, &tcp(40000, 9, ACK));
    lab.egress(
        "port unreachable to 301 about an untracked flow",
        &v4(ICMP, POD, OTHER, 0, &icmp_error(3, 3, &untracked)),
        SHOT,
    )?;
    let tcp80_6 = v6(TCP, PEER6, POD6, &tcp(40000, 80, ACK));
    lab.egress(
        "ICMPv6 port unreachable about the tracked IPv6 TCP 80 flow",
        &v6(58, POD6, PEER6, &icmp_error(1, 4, &tcp80_6)),
        OK,
    )?;
    let other6 = v6(TCP, PEER6, POD6, &tcp(40001, 80, ACK));
    lab.egress(
        "ICMPv6 port unreachable about an untracked IPv6 flow",
        &v6(58, POD6, PEER6, &icmp_error(1, 4, &other6)),
        SHOT,
    )?;
    lab.ingress(
        "ICMPv6 time exceeded (no rule) about an untracked flow",
        &v6(
            58,
            PEER6,
            POD6,
            &icmp_error(3, 0, &v6(TCP, POD6, PEER6, &tcp(80, 40001, ACK))),
        ),
        SHOT,
    )?;
    lab.ingress(
        "ICMPv6 time exceeded about the tracked flow's reply",
        &v6(
            58,
            PEER6,
            POD6,
            &icmp_error(3, 0, &v6(TCP, POD6, PEER6, &tcp(80, 40000, ACK))),
        ),
        OK,
    )?;
    println!(
        "PASS ICMP and ICMPv6 errors about tracked flows pass as related, both directions; errors about other flows are judged as new"
    );
    Ok(())
}

const HOST_ADDR: [u8; 4] = [192, 0, 2, 20];
const REMOTE_NODE: [u8; 4] = [192, 0, 2, 30];
const ADMIN: [u8; 4] = [198, 51, 100, 9];

/// Test-run a host firewall program on `frame` as if on uplink `ifindex`.
fn host_verdict(lab: &mut Lab, program: &str, ifindex: u32, frame: &[u8]) -> Result<u32> {
    let fd = lab
        .delivery
        .host_program(program)?
        .fd()?
        .as_fd()
        .as_raw_fd();
    let mut ctx = [0u8; 192];
    ctx.get_mut(40..44)
        .ok_or("ctx")?
        .copy_from_slice(&ifindex.to_ne_bytes());
    let mut out = vec![0u8; 512];
    let mut ctx_out = [0u8; 192];
    Ok(syscall::run(fd, frame, &mut out, &ctx, &mut ctx_out)?.0)
}
fn host_rule(
    lab: &mut Lab,
    identity: u32,
    proto: u8,
    port: u16,
    prefix: u8,
    deny: bool,
) -> Result<()> {
    host_rule_in(lab, false, (identity, proto, port, prefix), deny)
}
/// A host endpoint entry in either direction: (identity, protocol, port,
/// port prefix).
fn host_rule_in(
    lab: &mut Lab,
    egress: bool,
    (identity, proto, port, prefix): (u32, u8, u16, u8),
    deny: bool,
) -> Result<()> {
    let key = PolicyKey::new(identity, egress, proto, port, prefix).map_err(|_| "policy key")?;
    let lpm = if proto == 0 {
        0
    } else {
        prefix.saturating_add(8)
    };
    let precedence = if deny { u32::MAX } else { 0xFFFF_FF01 };
    let entry =
        PolicyEntry::new(0, deny, lpm, 0, false, precedence, 0).map_err(|_| "policy entry")?;
    lab.delivery
        .policy()
        .upsert_policy(EndpointPolicyKey::for_endpoint(HOST_ENDPOINT, key), entry)
}

/// The host firewall on uplink `up0` (#379).
fn host(lab: &mut Lab) -> Result<()> {
    ip(&["link", "add", "up0", "type", "dummy"])?;
    ip(&["link", "set", "up0", "up"])?;
    let up0 = ifindex("up0")?;
    lab.identity(IpAddr::V4(Ipv4Addr::from(HOST_ADDR)), 1)?;
    lab.identity(IpAddr::V4(Ipv4Addr::from(REMOTE_NODE)), 6)?;
    // Remote nodes: anything but 9100 (the deny repeated at their identity,
    // as the agent writes it); world: TCP 22 only; everyone: not 9100.
    host_rule(lab, 6, 0, 0, 0, false)?;
    host_rule(lab, 6, TCP, 9100, 16, true)?;
    host_rule(lab, 2, TCP, 22, 16, false)?;
    host_rule(lab, 0, TCP, 9100, 16, true)?;
    let set = |lab: &mut Lab, flags| {
        lab.delivery.policy().set_policy_endpoint(
            up0,
            PolicyEndpoint {
                endpoint: HOST_ENDPOINT,
                flags,
            },
        )
    };
    let to_host = |src, dport| v4(TCP, src, HOST_ADDR, 0, &tcp(40000, dport, SYN));
    let check = |lab: &mut Lab, what: &str, program: &str, frame: &[u8], want| -> Result<()> {
        let got = host_verdict(lab, program, up0, frame)?;
        if got != want {
            let name = |v| if v == OK { "pass" } else { "drop" };
            return Err(format!("host {what}: {} instead of {}", name(got), name(want)).into());
        }
        Ok(())
    };

    // Learning: no flags, every flow passes and is remembered.
    set(lab, 0)?;
    check(
        lab,
        "learning, admin:8081",
        "from_netdev",
        &to_host(ADMIN, 8081),
        OK,
    )?;
    if !lab
        .delivery
        .policy()
        .policy_flows()?
        .iter()
        .any(|(k, _)| k.daddr.get(..4) == Some(HOST_ADDR.as_slice()) && k.dport.get() == 8081)
    {
        return Err("a flow to the host was not learned without flags".into());
    }
    println!(
        "PASS host firewall learning: unenforced uplink passes and remembers flows to the host"
    );

    set(lab, enforce::INGRESS)?;
    check(lab, "admin:22", "from_netdev", &to_host(ADMIN, 22), OK)?;
    check(lab, "admin:80", "from_netdev", &to_host(ADMIN, 80), SHOT)?;
    check(
        lab,
        "remote node:80",
        "from_netdev",
        &to_host(REMOTE_NODE, 80),
        OK,
    )?;
    check(
        lab,
        "remote node:9100",
        "from_netdev",
        &to_host(REMOTE_NODE, 9100),
        SHOT,
    )?;
    check(
        lab,
        "learned admin:8081",
        "from_netdev",
        &to_host(ADMIN, 8081),
        OK,
    )?;
    check(
        lab,
        "forwarded to a pod",
        "from_netdev",
        &v4(TCP, ADMIN, POD, 0, &tcp(40000, 80, SYN)),
        OK,
    )?;
    check(lab, "ARP", "from_netdev", &ether([0x08, 0x06]), OK)?;
    println!(
        "PASS host firewall enforce: world TCP 22 allowed, port 80 dropped; remote node allowed except 9100 (deny over allow); learned flows and forwarded traffic pass; ARP passes"
    );

    // A flow the host starts: remembered on the way out, its reply passes.
    check(
        lab,
        "host to admin:443",
        "to_netdev",
        &v4(TCP, HOST_ADDR, ADMIN, 0, &tcp(41000, 443, SYN)),
        OK,
    )?;
    check(
        lab,
        "reply admin:443",
        "from_netdev",
        &v4(TCP, ADMIN, HOST_ADDR, 0, &tcp(443, 41000, SYN | ACK)),
        OK,
    )?;
    check(
        lab,
        "unsolicited admin:443",
        "from_netdev",
        &v4(TCP, ADMIN, HOST_ADDR, 0, &tcp(443, 41001, SYN | ACK)),
        SHOT,
    )?;
    println!("PASS host firewall: replies of flows the host started pass; unsolicited ones do not");

    set(lab, enforce::INGRESS | enforce::AUDIT)?;
    check(
        lab,
        "audit admin:8080",
        "from_netdev",
        &to_host(ADMIN, 8080),
        OK,
    )?;
    let counts = lab.delivery.policy().policy_verdicts()?;
    let seen = |port: u16, kind: u8| {
        counts.iter().any(|(k, v)| {
            k.endpoint == HOST_ENDPOINT
                && k.egress == 0
                && k.dport.get() == port
                && k.verdict == kind
                && v.packets >= 1
        })
    };
    for (port, kind, what) in [
        (22, verdict::ALLOWED, "allowed 22"),
        (80, verdict::DENIED, "denied 80"),
        (9100, verdict::DENIED, "denied 9100"),
        (8080, verdict::AUDIT, "audit 8080"),
    ] {
        if !seen(port, kind) {
            return Err(format!("verdict counters lack {what}: {counts:?}").into());
        }
    }
    println!(
        "PASS host firewall audit: a would-be drop passes and is counted; verdict counters hold allowed, denied and audit rows"
    );
    lab.delivery.policy().remove_policy_endpoint(up0)?;
    check(
        lab,
        "removed admin:80",
        "from_netdev",
        &to_host(ADMIN, 80),
        OK,
    )?;
    println!("PASS host firewall removed: the uplink passes everything");
    pods_to_host(lab)
}

/// Local Pods' traffic to the host (#384): `local_delivery` judges it by
/// the `HOST_PODS` entry, `to_container` remembers flows the host starts.
fn pods_to_host(lab: &mut Lab) -> Result<()> {
    lab.identity(IpAddr::V4(Ipv4Addr::from(POD)), 400)?;
    host_rule(lab, 400, TCP, 9090, 16, false)?;
    let to_host = |sport, dport| v4(TCP, POD, HOST_ADDR, 0, &tcp(sport, dport, SYN));
    lab.egress(
        "no HOST_PODS entry, pod to host:80",
        &to_host(42000, 80),
        OK,
    )?;
    let set = |lab: &mut Lab, flags| {
        lab.delivery.policy().set_policy_endpoint(
            HOST_PODS,
            PolicyEndpoint {
                endpoint: HOST_ENDPOINT,
                flags,
            },
        )
    };
    set(lab, enforce::INGRESS)?;
    lab.egress("pod to host:9090", &to_host(42001, 9090), OK)?;
    lab.egress("pod to host:80", &to_host(42002, 80), SHOT)?;
    lab.egress("pod to host:9100", &to_host(42003, 9100), SHOT)?;
    lab.egress(
        "pod to a peer:80",
        &v4(TCP, POD, PEER, 0, &tcp(42004, 80, SYN)),
        OK,
    )?;
    println!(
        "PASS host firewall on pods: a pod reaches the host's allowed port, other host ports drop, traffic to other pods is not judged"
    );
    lab.ingress(
        "host to pod:8080",
        &v4(TCP, HOST_ADDR, POD, 0, &tcp(43000, 8080, SYN)),
        OK,
    )?;
    lab.egress(
        "reply pod:8080 to host",
        &v4(TCP, POD, HOST_ADDR, 0, &tcp(8080, 43000, SYN | ACK)),
        OK,
    )?;
    lab.egress(
        "unsolicited pod:8080 to host",
        &v4(TCP, POD, HOST_ADDR, 0, &tcp(8080, 43001, SYN | ACK)),
        SHOT,
    )?;
    println!(
        "PASS host firewall on pods: replies to flows the host started to a pod pass; unsolicited ones do not"
    );
    set(lab, enforce::INGRESS | enforce::AUDIT)?;
    lab.egress("audit pod to host:81", &to_host(42005, 81), OK)?;
    let counted = lab
        .delivery
        .policy()
        .policy_verdicts()?
        .iter()
        .any(|(k, v)| {
            k.endpoint == HOST_ENDPOINT
                && k.egress == 0
                && k.dport.get() == 81
                && k.verdict == verdict::AUDIT
                && v.packets >= 1
        });
    if !counted {
        return Err("no audit verdict for pod to host:81".into());
    }
    lab.delivery.policy().remove_policy_endpoint(HOST_PODS)?;
    lab.egress("HOST_PODS removed, pod to host:82", &to_host(42006, 82), OK)?;
    println!(
        "PASS host firewall on pods: audit passes and counts; removing HOST_PODS stops judging"
    );
    Ok(())
}

/// Host egress policy (#477): `to_netdev` judges packets from the node's
/// addresses on the uplink, `to_container` the host's packets to a local
/// Pod (`HOST_PODS`), by the host endpoint's egress entries.
fn host_egress(lab: &mut Lab) -> Result<()> {
    let up0 = ifindex("up0")?;
    // World: TCP 443 only; every identity: never TCP 25; the local Pod
    // (identity 400, from pods_to_host): TCP 8080.
    host_rule_in(lab, true, (2, TCP, 443, 16), false)?;
    host_rule_in(lab, true, (0, TCP, 25, 16), true)?;
    host_rule_in(lab, true, (400, TCP, 8080, 16), false)?;
    let set = |lab: &mut Lab, index: u32, flags| {
        lab.delivery.policy().set_policy_endpoint(
            index,
            PolicyEndpoint {
                endpoint: HOST_ENDPOINT,
                flags,
            },
        )
    };
    let check = |lab: &mut Lab, what: &str, program: &str, frame: &[u8], want| -> Result<()> {
        let got = host_verdict(lab, program, up0, frame)?;
        if got != want {
            let name = |v| if v == OK { "pass" } else { "drop" };
            return Err(format!(
                "host egress {what}: {} instead of {}",
                name(got),
                name(want)
            )
            .into());
        }
        Ok(())
    };
    let out = |dst, sport, dport, flags| v4(TCP, HOST_ADDR, dst, 0, &tcp(sport, dport, flags));
    set(lab, up0, enforce::INGRESS | enforce::EGRESS)?;
    check(
        lab,
        "host to admin:443",
        "to_netdev",
        &out(ADMIN, 45000, 443, SYN),
        OK,
    )?;
    check(
        lab,
        "host to admin:80",
        "to_netdev",
        &out(ADMIN, 45001, 80, SYN),
        SHOT,
    )?;
    check(
        lab,
        "host to admin:25",
        "to_netdev",
        &out(ADMIN, 45002, 25, SYN),
        SHOT,
    )?;
    check(
        lab,
        "forwarded pod to admin:80",
        "to_netdev",
        &v4(TCP, POD, ADMIN, 0, &tcp(45003, 80, SYN)),
        OK,
    )?;
    // A connection to the host that ingress allows: its replies leave.
    check(
        lab,
        "admin to host:22",
        "from_netdev",
        &v4(TCP, ADMIN, HOST_ADDR, 0, &tcp(45004, 22, SYN)),
        OK,
    )?;
    check(
        lab,
        "reply host:22 to admin",
        "to_netdev",
        &out(ADMIN, 22, 45004, SYN | ACK),
        OK,
    )?;
    // The reply of the allowed 443 flow comes back in.
    check(
        lab,
        "reply admin:443 to host",
        "from_netdev",
        &v4(TCP, ADMIN, HOST_ADDR, 0, &tcp(443, 45000, SYN | ACK)),
        OK,
    )?;
    println!(
        "PASS host egress on the uplink: world TCP 443 allowed, 80 dropped, 25 denied; forwarded traffic not judged; replies of allowed flows pass both ways"
    );

    set(lab, HOST_PODS, enforce::EGRESS)?;
    lab.ingress(
        "host to pod:8080",
        &v4(TCP, HOST_ADDR, POD, 0, &tcp(46000, 8080, SYN)),
        OK,
    )?;
    lab.ingress(
        "host to pod:81",
        &v4(TCP, HOST_ADDR, POD, 0, &tcp(46001, 81, SYN)),
        SHOT,
    )?;
    lab.egress(
        "reply pod:8080 to host",
        &v4(TCP, POD, HOST_ADDR, 0, &tcp(8080, 46000, SYN | ACK)),
        OK,
    )?;
    println!(
        "PASS host egress to local Pods: the host reaches the pod's allowed port, not another; the reply passes"
    );

    set(
        lab,
        up0,
        enforce::INGRESS | enforce::EGRESS | enforce::AUDIT,
    )?;
    check(
        lab,
        "audit host to admin:8443",
        "to_netdev",
        &out(ADMIN, 45010, 8443, SYN),
        OK,
    )?;
    let counted = lab
        .delivery
        .policy()
        .policy_verdicts()?
        .iter()
        .any(|(k, v)| {
            k.endpoint == HOST_ENDPOINT
                && k.egress == 1
                && k.dport.get() == 8443
                && k.verdict == verdict::AUDIT
                && v.packets >= 1
        });
    if !counted {
        return Err("no egress audit verdict for host to admin:8443".into());
    }
    let denied = lab
        .delivery
        .policy()
        .policy_verdicts()?
        .iter()
        .any(|(k, _)| {
            k.endpoint == HOST_ENDPOINT
                && k.egress == 1
                && k.dport.get() == 80
                && k.verdict == verdict::DENIED
        });
    if !denied {
        return Err("no egress denied verdict for host to admin:80".into());
    }
    lab.delivery.policy().remove_policy_endpoint(up0)?;
    lab.delivery.policy().remove_policy_endpoint(HOST_PODS)?;
    check(
        lab,
        "removed host to admin:80",
        "to_netdev",
        &out(ADMIN, 45011, 80, SYN),
        OK,
    )?;
    println!(
        "PASS host egress audit: a would-be drop passes and is counted; egress denied rows counted; removal stops judging"
    );
    Ok(())
}

/// A remote node address with an identity of its own (scope 2, #490):
/// judged by its specific entry, then the remote-node aggregate (14), as the
/// agent writes `remote-node` rules.
fn remote_node_aggregate(lab: &mut Lab) -> Result<()> {
    const NODE_B: [u8; 4] = [192, 0, 2, 31];
    let up0 = ifindex("up0")?;
    lab.identity(IpAddr::V4(Ipv4Addr::from(NODE_B)), (2 << 24) | 1)?;
    lab.delivery.policy().set_policy_endpoint(
        up0,
        PolicyEndpoint {
            endpoint: HOST_ENDPOINT,
            flags: enforce::INGRESS,
        },
    )?;
    let frame = v4(TCP, NODE_B, HOST_ADDR, 0, &tcp(47000, 5555, SYN));
    let got = host_verdict(lab, "from_netdev", up0, &frame)?;
    if got != SHOT {
        return Err(format!("node B without a remote-node rule: verdict {got}").into());
    }
    host_rule(lab, 14, 0, 0, 0, false)?;
    let again = v4(TCP, NODE_B, HOST_ADDR, 0, &tcp(47001, 5555, SYN));
    let got = host_verdict(lab, "from_netdev", up0, &again)?;
    if got != OK {
        return Err(format!("node B with a remote-node (14) rule: verdict {got}").into());
    }
    lab.delivery.policy().remove_policy_endpoint(up0)?;
    println!(
        "PASS a remote node address's own identity (scope 2) is dropped without a rule and allowed by one at the remote-node aggregate (14)"
    );
    Ok(())
}

fn main() -> Result<()> {
    let object = std::env::args_os()
        .nth(1)
        .ok_or("usage: policy-live PATH_TO_LOCAL_DELIVERY_OBJECT")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    let bytes = std::fs::read(&object)?;
    run(&bytes)
}
