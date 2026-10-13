//! Endpoint network policy against the real kernel (#292, ADR-0021): the
//! local-delivery object's `local_delivery` (pod egress) and `to_container`
//! (pod ingress) programs test-run on frames as if on an endpoint's host
//! veth (a dummy device in a private network namespace), with the policy,
//! ipcache and policy-endpoint maps written through the loader. Covers an
//! unenforced endpoint, default deny, the host exception, neighbour
//! discovery and ARP, identity + protocol + port and port-range (LPM) allows,
//! the aggregate cluster identity and the wildcard identity, a top-precedence
//! deny, replies of allowed flows in the other direction (conntrack), ICMP
//! echo, IPv6, fragments, and removing enforcement.
use flowsdn_bpf_abi::{
    IpCacheKey, RemoteEndpointInfo,
    policy::{EndpointPolicyKey, PolicyEndpoint, PolicyEntry, PolicyKey, enforce},
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
        self.delivery.set_policy_endpoint(
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
        self.delivery.upsert_ipcache(
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
    lab.egress("no policy endpoint", &v4(UDP, POD, WORLD, 0, &udp(5000, 53)), OK)?;
    if !lab.delivery.policy_flows()?.is_empty() {
        return Err("an endpoint without a policy entry was tracked".into());
    }
    println!("PASS endpoint without a policy entry: both programs pass, nothing tracked");

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
    let tracked = lab.delivery.policy_flows()?;
    if !tracked
        .iter()
        .any(|(key, _)| key.egress == 0 && key.daddr.get(..4) == Some(&POD[..]))
    {
        return Err(format!("no ingress flow tracked: {} entries", tracked.len()).into());
    }
    println!("PASS conntrack: the reply of an allowed ingress flow passes enforced egress; a new egress flow does not");

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
    lab.ingress("deny for 300 over the aggregate allow", &syn(PEER, 22), SHOT)?;
    lab.ingress("aggregate allow for 302 on port 22", &syn(CLUSTER, 22), OK)?;
    println!(
        "PASS aggregate-cluster and wildcard identities; a top-precedence deny wins over a broader allow"
    );

    for (identity, egress) in [(0, true), (11, false)] {
        lab.delivery.remove_policy(EndpointPolicyKey::new(
            ENDPOINT,
            PolicyKey::new(identity, egress, 0, 0, 0).map_err(|_| "key")?,
        ))?;
    }
    lab.rule(allow(300, true, ICMP, 0, 0))?;
    lab.egress("echo request to 300", &v4(ICMP, POD, PEER, 0, &icmp(8, 77)), OK)?;
    lab.ingress("its echo reply", &v4(ICMP, PEER, POD, 0, &icmp(0, 77)), OK)?;
    lab.ingress(
        "an echo reply nobody asked for",
        &v4(ICMP, PEER, POD, 0, &icmp(0, 78)),
        SHOT,
    )?;
    println!("PASS ICMP echo: the request is allowed by protocol, its reply by conntrack");

    let entries = lab.delivery.policy_entries()?;
    if entries.len() != 4 || entries.iter().any(|(k, _)| k.endpoint != u32::from(ENDPOINT)) {
        return Err(format!("policy map holds {} entries, expected 4", entries.len()).into());
    }
    if lab.delivery.ipcache_entries()?.len() != 5 {
        return Err("ipcache does not hold the 5 written prefixes".into());
    }
    lab.delivery.remove_policy_endpoint(lab.ifindex)?;
    lab.ingress("enforcement removed", &syn(PEER, 81), OK)?;
    lab.egress(
        "enforcement removed",
        &v4(TCP, POD, PEER, 0, &tcp(41000, 9999, SYN)),
        OK,
    )?;
    println!("PASS maps read back as written; removing the policy endpoint stops enforcement");
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
