//! The DNS proxy, DNS rules and `toFQDNs` on a real kernel (#536, spec 16
//! §3.6, ADR-0024 step 2). Two Pods, each in a network namespace of its own
//! behind a veth whose host side runs the local-delivery object's endpoint
//! programs: `client` (10.0.0.7) and `dns` (10.0.1.53, also holding
//! 10.0.1.80 and 10.0.1.81, where it serves TCP 80). The agent's own policy
//! compiler (`flowsdn_agent::policy::compile`) turns a FlowsdnNetworkPolicy
//! into the maps:
//!
//! - client egress: `dns` on port 53 with `rules.dns` `*.example.com`, and
//!   `toFQDNs` `api.example.com` on TCP 80;
//! - dns ingress: client on 53 and on TCP 80.
//!
//! The `flowsdn-l7` DNS proxy runs on the host with the agent's
//! `dns_proxy::Answerer`; its hold recompiles and applies the maps before an
//! answer is released, as the agent's policy thread does.
//!
//! * DNS rules, allowed: the client's UDP query for `api.example.com` is
//!   answered (10.0.1.80) from 10.0.1.53:53, the address it asked; the
//!   proxy's upstream query reached the server through the server's ingress
//!   policy as the client's identity (the proxy mark, spec 16 §3.6.2). Over
//!   TCP too.
//! * DNS rules, refused: `evil.example.org` is answered REFUSED by the proxy
//!   and never reaches the server.
//! * `toFQDNs`, allowed: the client connects to 10.0.1.80:80 at once (the
//!   hold programmed it first).
//! * `toFQDNs`, refused: 10.0.1.81:80 (answered for another name) is
//!   dropped.
//! * Expiry: once the 2 s TTL passes and the cache expires it, a new
//!   connection to 10.0.1.80:80 is dropped.
//!
//! Usage: `dns-live LOCAL_DELIVERY_OBJECT`. It needs iproute2 and root, as
//! kernel-check gives it.
use flowsdn_agent::{
    dns_proxy::{self, Answerer},
    kubernetes::{LocalEndpoint, NodeInfo, PodInfo, View},
    policy::Desired,
};
use flowsdn_bpf_abi::{IpCacheKey, MapBytes, policy::EndpointPolicyKey};
use flowsdn_bpf_loader::kernel::{Egress, LocalDelivery, Object};
use flowsdn_l7::dns::{
    self as l7dns, Config,
    message::{self, rcode},
    proxy::DnsProxy,
};
use nix::sched::{CloneFlags, unshare};
use serde_json::json;
use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const TIMEOUT: Duration = Duration::from_secs(3);
const API: [u8; 4] = [10, 0, 1, 80];
const WWW: [u8; 4] = [10, 0, 1, 81];
const API_TTL: u32 = 2;

fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn ip(args: &[&str]) -> Result<String> {
    let output = Command::new("ip").args(args).output()?;
    ensure(
        output.status.success(),
        &format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    Ok(String::from_utf8(output.stdout)?)
}
fn isolate() -> Result<()> {
    let before = std::fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(
        std::fs::read_link("/proc/self/ns/net")? != before,
        "namespace isolation failed",
    )
}
fn ifindex(name: &str) -> Result<u32> {
    Ok(ip(&["-o", "link", "show", "dev", name])?
        .split(':')
        .next()
        .map(str::trim)
        .ok_or("no ifindex")?
        .parse()?)
}

/// A Pod process: its own namespace, then lines in and out.
struct Pod {
    child: Child,
    input: ChildStdin,
    lines: std::io::Lines<BufReader<ChildStdout>>,
}
impl Pod {
    fn spawn(role: &str) -> Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg(role)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().ok_or("pod stdin")?;
        let mut lines = BufReader::new(child.stdout.take().ok_or("pod stdout")?).lines();
        ensure(
            lines.next().transpose()?.as_deref() == Some("READY"),
            &format!("{role} did not isolate"),
        )?;
        Ok(Self {
            child,
            input,
            lines,
        })
    }
    fn ask(&mut self, line: &str) -> Result<String> {
        writeln!(self.input, "{line}")?;
        self.input.flush()?;
        Ok(self.lines.next().transpose()?.ok_or("pod ended")?)
    }
}

/// Pod side: wait for `GO <address commands>`, then answer commands.
fn pod(role: &str) -> Result<()> {
    isolate()?;
    let mut out = std::io::stdout();
    writeln!(out, "READY")?;
    out.flush()?;
    let mut lines = BufReader::new(std::io::stdin()).lines();
    let go = lines.next().transpose()?.ok_or("no GO")?;
    ensure(go == "GO", "pod: expected GO")?;
    ip(&["link", "set", "lo", "up"])?;
    if role == "client" {
        ip(&["addr", "add", "10.0.0.7/24", "dev", "eth0"])?;
        ip(&["link", "set", "eth0", "up"])?;
        ip(&["route", "add", "default", "via", "10.0.0.1"])?;
    } else {
        ip(&["addr", "add", "10.0.1.53/24", "dev", "eth0"])?;
        ip(&["addr", "add", "10.0.1.80/32", "dev", "eth0"])?;
        ip(&["addr", "add", "10.0.1.81/32", "dev", "eth0"])?;
        ip(&["link", "set", "eth0", "up"])?;
        ip(&["route", "add", "default", "via", "10.0.1.1"])?;
    }
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    if role == "dns" {
        serve_dns(&seen)?;
    }
    writeln!(out, "UP")?;
    out.flush()?;
    for line in lines {
        let line = line?;
        let words: Vec<&str> = line.split_whitespace().collect();
        let reply = match words.as_slice() {
            ["SEEN"] => format!(
                "SEEN {}",
                seen.lock().map_err(|_| "seen lock")?.join(",")
            ),
            ["UDP", server, name] => client_query(server, name, false),
            ["TCPDNS", server, name] => client_query(server, name, true),
            ["CONNECT", target] => connect(target),
            _ => break,
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    Ok(())
}

/// The DNS server Pod: UDP and TCP 53 answering api.example.com. (10.0.1.80,
/// TTL 2) and www.example.com. (10.0.1.81), and TCP 80 answering `world`.
fn serve_dns(seen: &Arc<Mutex<Vec<String>>>) -> Result<()> {
    let answer = move |query: &[u8]| -> Option<Vec<u8>> {
        let question = message::question(query)?;
        let records: Vec<(&str, u32, IpAddr)> = match question.name.as_str() {
            "api.example.com." => vec![("api.example.com", API_TTL, IpAddr::from(API))],
            "www.example.com." => vec![("www.example.com", 60, IpAddr::from(WWW))],
            _ => Vec::new(),
        };
        message::response(query, &records)
    };
    let udp = UdpSocket::bind("0.0.0.0:53")?;
    let udp_seen = Arc::clone(seen);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        while let Ok((length, from)) = udp.recv_from(&mut buffer) {
            let Some(query) = buffer.get(..length) else {
                continue;
            };
            if let Some(q) = message::question(query) {
                if let Ok(mut seen) = udp_seen.lock() {
                    seen.push(format!("udp:{}", q.name));
                }
            }
            if let Some(reply) = answer(query) {
                let _ = udp.send_to(&reply, from);
            }
        }
    });
    let tcp = TcpListener::bind("0.0.0.0:53")?;
    let tcp_seen = Arc::clone(seen);
    std::thread::spawn(move || {
        for stream in tcp.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).is_err() {
                continue;
            }
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut query).is_err() {
                continue;
            }
            if let Some(q) = message::question(&query) {
                if let Ok(mut seen) = tcp_seen.lock() {
                    seen.push(format!("tcp:{}", q.name));
                }
            }
            if let Some(reply) = answer(&query) {
                let mut out = u16::try_from(reply.len()).unwrap_or(0).to_be_bytes().to_vec();
                out.extend_from_slice(&reply);
                let _ = stream.write_all(&out);
            }
        }
    });
    let web = TcpListener::bind("0.0.0.0:80")?;
    std::thread::spawn(move || {
        for stream in web.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 5];
            if stream.read_exact(&mut request).is_ok() {
                let _ = stream.write_all(b"world");
            }
        }
    });
    Ok(())
}

/// The client's query: `OK <rcode> <ips> FROM <source>` or `FAIL <error>`.
fn client_query(server: &str, name: &str, tcp: bool) -> String {
    let result = (|| -> Result<String> {
        let server: SocketAddr = server.parse()?;
        let query = message::query(0x4242, name, message::TYPE_A);
        let question = message::question(&query).ok_or("query")?;
        let (reply, from) = if tcp {
            let mut stream = TcpStream::connect_timeout(&server, TIMEOUT)?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            let mut out = u16::try_from(query.len())?.to_be_bytes().to_vec();
            out.extend_from_slice(&query);
            stream.write_all(&out)?;
            let mut length = [0u8; 2];
            stream.read_exact(&mut length)?;
            let mut reply = vec![0u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut reply)?;
            (reply, server)
        } else {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.set_read_timeout(Some(TIMEOUT))?;
            socket.send_to(&query, server)?;
            let mut buffer = [0u8; 4096];
            let (length, from) = socket.recv_from(&mut buffer)?;
            (buffer.get(..length).ok_or("length")?.to_vec(), from)
        };
        let answers = message::answers(&reply, &question).ok_or("not an answer")?;
        let ips: Vec<String> = answers.ips.iter().map(ToString::to_string).collect();
        Ok(format!("OK {} {} FROM {from}", answers.rcode, ips.join(",")))
    })();
    result.unwrap_or_else(|e| format!("FAIL {e}"))
}

fn connect(target: &str) -> String {
    let result = (|| -> Result<String> {
        let target: SocketAddr = target.parse()?;
        let mut stream = TcpStream::connect_timeout(&target, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.write_all(b"hello")?;
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply)?;
        Ok(String::from_utf8_lossy(&reply).into_owned())
    })();
    match result {
        Ok(reply) => format!("OK {reply}"),
        Err(e) => format!("FAIL {e}"),
    }
}

fn pod_info(name: &str, address: &str, app: &str) -> Result<PodInfo> {
    Ok(PodInfo {
        namespace: "shop".into(),
        name: name.into(),
        node: "n1".into(),
        ips: vec![address.parse()?],
        labels: [("app".to_owned(), app.to_owned())].into_iter().collect(),
        service_account: "default".into(),
        ..PodInfo::default()
    })
}

/// The agent's view of this node: both Pods local, their identities, the
/// policy, and the proxy's port.
fn view(client_ifindex: u32, dns_ifindex: u32, proxy_port: u16) -> Result<View> {
    let policy = json!({"apiVersion":"flowsdn.io/v1alpha1","kind":"FlowsdnNetworkPolicy",
        "metadata":{"name":"dns-live","namespace":"shop"},
        "specs":[
            {"endpointSelector":{"matchLabels":{"app":"client"}},"egress":[
                {"toEndpoints":[{"matchLabels":{"app":"dns"}}],
                 "toPorts":[{"ports":[{"port":"53","protocol":"ANY"}],
                             "rules":{"dns":[{"matchPattern":"*.example.com"}]}}]},
                {"toFQDNs":[{"matchName":"api.example.com"}],
                 "toPorts":[{"ports":[{"port":"80","protocol":"TCP"}]}]}]},
            {"endpointSelector":{"matchLabels":{"app":"dns"}},"ingress":[
                {"fromEndpoints":[{"matchLabels":{"app":"client"}}],
                 "toPorts":[{"ports":[{"port":"53","protocol":"ANY"},
                                      {"port":"80","protocol":"TCP"}]}]}]}
        ]});
    let endpoint = |id: u16, name: &str, interface: &str, ifindex: u32| LocalEndpoint {
        id,
        namespace: "shop".into(),
        name: name.into(),
        interface: interface.into(),
        ifindex,
        ..LocalEndpoint::default()
    };
    let mut view = View {
        local_node: "n1".into(),
        cluster_name: "default".into(),
        identity: true,
        flowsdn_policy: true,
        nodes: vec![NodeInfo {
            name: "n1".into(),
            internal_ips: vec!["10.0.0.1".parse()?],
            ..NodeInfo::default()
        }],
        pods: vec![
            pod_info("client", "10.0.0.7", "client")?,
            pod_info("dns", "10.0.1.53", "dns")?,
        ],
        pods_synced: true,
        nodes_synced: true,
        namespaces: [("shop".to_owned(), BTreeMap::new())].into_iter().collect(),
        namespaces_synced: true,
        identities_synced: true,
        endpoints: vec![
            endpoint(7, "client", "ep0", client_ifindex),
            endpoint(8, "dns", "ep1", dns_ifindex),
        ],
        endpoints_published: true,
        pod_policies: vec![policy],
        pod_policies_synced: true,
        clusterwide_synced: true,
        dns_proxy_port: proxy_port,
        ..View::default()
    };
    let filter = flowsdn_identity::filter::LabelFilter::identity(&[])?;
    for ((pod, _, labels), id) in view.pod_label_sets(&filter).into_iter().zip(300u32..) {
        view.identities
            .insert(id, flowsdn_agent::identity::label_strings(&labels));
        view.pod_identities.insert(pod, id);
    }
    Ok(view)
}

/// Bring the maps to `desired` (the policy thread's `apply_policy`).
fn apply(delivery: &mut LocalDelivery, desired: &Desired) -> Result<()> {
    let maps = delivery.policy();
    let entries: BTreeMap<[u8; 16], _> = maps
        .policy_entries()?
        .into_iter()
        .map(|(k, v)| (k.to_bytes(), v))
        .collect();
    let ipcache: BTreeMap<[u8; 24], _> = maps
        .ipcache_entries()?
        .into_iter()
        .map(|(k, v)| (k.to_bytes(), v))
        .collect();
    for (key, value) in &desired.entries {
        if entries.get(key) != Some(value) {
            maps.upsert_policy(EndpointPolicyKey::from_bytes(*key), *value)?;
        }
    }
    for (key, value) in &desired.ipcache {
        if ipcache.get(key) != Some(value) {
            maps.upsert_ipcache(IpCacheKey::from_bytes(*key), *value)?;
        }
    }
    for (ifindex, value) in &desired.endpoints {
        maps.set_policy_endpoint(*ifindex, *value)?;
    }
    for key in ipcache.keys().filter(|k| !desired.ipcache.contains_key(*k)) {
        maps.remove_ipcache(IpCacheKey::from_bytes(*key))?;
    }
    for key in entries.keys().filter(|k| !desired.entries.contains_key(*k)) {
        maps.remove_policy(EndpointPolicyKey::from_bytes(*key))?;
    }
    Ok(())
}

/// The agent's policy pass: compile, apply, publish the DNS rules.
fn pass(
    state: &Mutex<(View, LocalDelivery)>,
    answerer: &Mutex<Option<Arc<Answerer>>>,
) -> std::result::Result<(), String> {
    let mut guard = state.lock().map_err(|_| "state lock")?;
    let (view, delivery) = &mut *guard;
    view.fqdn.expire(dns_proxy::now());
    let desired = flowsdn_agent::policy::compile(view, &[]);
    if !desired.problems.is_empty() {
        return Err(desired.problems.join("; "));
    }
    apply(delivery, &desired).map_err(|e| e.to_string())?;
    if let Some(answerer) = answerer.lock().map_err(|_| "answerer lock")?.as_ref() {
        answerer.publish(&desired.dns);
    }
    Ok(())
}

fn run(object: &[u8]) -> Result<()> {
    isolate()?;
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    let mut client = Pod::spawn("client")?;
    let mut dns = Pod::spawn("dns")?;
    ip(&["link", "set", "lo", "up"])?;
    for (host, pod, address) in [
        ("ep0", &client, "10.0.0.1/24"),
        ("ep1", &dns, "10.0.1.1/24"),
    ] {
        ip(&["link", "add", host, "type", "veth", "peer", "name", "eth0"])?;
        ip(&["link", "set", "eth0", "netns", &pod.child.id().to_string()])?;
        ip(&["addr", "add", address, "dev", host])?;
        ip(&["link", "set", host, "up"])?;
    }
    for command in flowsdn_l7::route::ip_commands("-4") {
        let args: Vec<&str> = command.iter().map(String::as_str).collect();
        ip(&args)?;
    }
    let mut delivery = LocalDelivery::load_object(Object::Bytes(object), Egress::Stack)
        .map_err(|e| format!("load local-delivery: {e}"))?;
    for interface in ["ep0", "ep1"] {
        delivery
            .attach(interface)
            .map_err(|e| format!("attach to {interface}: {e}"))?;
    }
    let (ep0, ep1) = (ifindex("ep0")?, ifindex("ep1")?);

    // The proxy first (its port goes into the policy), then the policy.
    let state = Arc::new(Mutex::new((view(ep0, ep1, 0)?, delivery)));
    let slot: Arc<Mutex<Option<Arc<Answerer>>>> = Arc::new(Mutex::new(None));
    let (learn_state, learn_slot) = (Arc::clone(&state), Arc::clone(&slot));
    let answerer = Answerer::new(Box::new(move |names, ips, ttl| {
        let changed = learn_state
            .lock()
            .map(|mut s| s.0.fqdn.insert(names, ips, ttl, dns_proxy::now()))
            .unwrap_or(false);
        !changed || pass(&learn_state, &learn_slot).is_ok()
    }));
    *slot.lock().map_err(|_| "slot")? = Some(Arc::clone(&answerer));
    let config = Config {
        upstream_timeout: Duration::from_secs(2),
        ..Config::default()
    };
    let policy: Arc<dyn l7dns::Policy> = answerer.clone();
    let proxy = DnsProxy::start(0, false, policy, config)
        .map_err(|e| format!("DNS proxy: {e}"))?;
    state.lock().map_err(|_| "state")?.0.dns_proxy_port = proxy.port();
    pass(&state, &slot)?;
    {
        let guard = state.lock().map_err(|_| "state")?;
        let entries = guard.1.policy().policy_entries()?;
        let redirected = entries
            .iter()
            .filter(|(k, v)| k.egress == 1 && k.dport.get() == 53 && v.proxy_port.get() == proxy.port())
            .count();
        ensure(redirected == 2, &format!("port 53 TCP and UDP to the proxy: {redirected}"))?;
    }
    println!(
        "PASS policy compiled by the agent: client egress to dns:53 with DNS rule *.example.com \
         through proxy port {}, toFQDNs api.example.com on TCP 80; dns ingress from client on 53 and 80",
        proxy.port()
    );

    for pod in [&mut client, &mut dns] {
        writeln!(pod.input, "GO")?;
        pod.input.flush()?;
        ensure(
            pod.lines.next().transpose()?.as_deref() == Some("UP"),
            "pod did not come up",
        )?;
    }

    let got = client.ask("UDP 10.0.1.53:53 api.example.com")?;
    ensure(
        got == format!("OK {} 10.0.1.80 FROM 10.0.1.53:53", rcode::NOERROR),
        &format!("allowed UDP query: {got}"),
    )?;
    let seen = dns.ask("SEEN")?;
    ensure(
        seen == "SEEN udp:api.example.com.",
        &format!("the server's view: {seen}"),
    )?;
    println!(
        "PASS DNS rule allows: api.example.com answered 10.0.1.80 from 10.0.1.53:53 (the address \
         queried); the upstream query passed the server's ingress policy as the client's identity"
    );
    let got = client.ask("CONNECT 10.0.1.80:80")?;
    ensure(got == "OK world", &format!("toFQDNs allowed address: {got}"))?;
    println!("PASS toFQDNs allows: the client reaches 10.0.1.80:80 right after the answer (the hold)");

    let got = client.ask("UDP 10.0.1.53:53 evil.example.org")?;
    ensure(
        got.starts_with(&format!("OK {} ", rcode::REFUSED)),
        &format!("refused query: {got}"),
    )?;
    let seen = dns.ask("SEEN")?;
    ensure(
        !seen.contains("evil"),
        &format!("a refused query reached the server: {seen}"),
    )?;
    println!("PASS DNS rule refuses: evil.example.org answered REFUSED by the proxy, never forwarded");

    let got = client.ask("TCPDNS 10.0.1.53:53 www.example.com")?;
    ensure(
        got.starts_with(&format!("OK {} 10.0.1.81", rcode::NOERROR)),
        &format!("TCP query: {got}"),
    )?;
    let got = client.ask("CONNECT 10.0.1.81:80")?;
    ensure(
        got.starts_with("FAIL"),
        &format!("an address of a name toFQDNs does not select must be dropped: {got}"),
    )?;
    println!(
        "PASS toFQDNs refuses: www.example.com (asked over TCP, answered 10.0.1.81) is not \
         api.example.com, and the client's connection to 10.0.1.81:80 is dropped"
    );

    std::thread::sleep(Duration::from_secs(u64::from(API_TTL) + 1));
    pass(&state, &slot)?;
    let got = client.ask("CONNECT 10.0.1.80:80")?;
    ensure(
        got.starts_with("FAIL"),
        &format!("after the TTL the address must be dropped: {got}"),
    )?;
    println!("PASS toFQDNs expiry: after the {API_TTL} s TTL a new connection to 10.0.1.80:80 is dropped");

    drop(client.input);
    drop(dns.input);
    let _ = client.child.wait();
    let _ = dns.child.wait();
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().ok_or("usage: dns-live LOCAL_DELIVERY_OBJECT")?;
    if first == "client" || first == "dns" {
        return pod(first.to_str().unwrap_or_default());
    }
    run(&std::fs::read(first)?)
}
