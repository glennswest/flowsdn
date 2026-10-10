//! ClusterIP Services on a flowsdn node (#292): from this pod's own network,
//! before the suite isolates itself, so the node's socket LB is what answers.
//! kube-dns at the pod's nameserver (its ClusterIP) resolves the `kubernetes`
//! Service with the reply from the ClusterIP, the agent reports kube-dns and
//! that `kubernetes` ClusterIP programmed, and a TCP connect to it succeeds
//! with the ClusterIP as its peer. The Service's address comes from DNS and
//! the agent, never `KUBERNETES_SERVICE_HOST`: on stormcos the kubelet points
//! that at the apiserver's node address (#368). Run only where the node is
//! the flowsdn flavor.
use crate::report::Report;
use flowsdn_api_client::{Client, Method};
use serde_json::Value;
use std::{
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    path::Path,
    time::{Duration, Instant},
};

const DNS_TRIES: usize = 3;
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// The first nameserver and the cluster domain (the `svc.<domain>` search
/// entry the kubelet writes; `cluster.local` without one).
pub fn resolv_conf(text: &str) -> Option<(IpAddr, String)> {
    let mut nameserver = None;
    let mut domain = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") if nameserver.is_none() => {
                nameserver = words.next().and_then(|w| w.parse().ok());
            }
            Some("search") => {
                domain = domain
                    .or_else(|| words.find_map(|w| w.strip_prefix("svc.").map(str::to_owned)));
            }
            _ => {}
        }
    }
    Some((
        nameserver?,
        domain.unwrap_or_else(|| "cluster.local".into()),
    ))
}

/// A recursive query for `name` (A, or AAAA for `v6`) with transaction `id`.
pub fn query(id: u16, name: &str, v6: bool) -> Result<Vec<u8>, String> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|n| (1..=63).contains(n))
            .ok_or_else(|| format!("invalid DNS label in {name}"))?;
        packet.push(len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0, if v6 { 28 } else { 1 }, 0, 1]);
    Ok(packet)
}

fn u16_at(packet: &[u8], at: usize) -> Result<u16, String> {
    let bytes = packet
        .get(at..at.saturating_add(2))
        .ok_or("truncated DNS reply")?;
    Ok(u16::from_be_bytes([
        *bytes.first().ok_or("truncated")?,
        *bytes.get(1).ok_or("truncated")?,
    ]))
}

/// The offset after a (possibly compressed) name starting at `at`.
fn skip_name(packet: &[u8], mut at: usize) -> Result<usize, String> {
    loop {
        let len = *packet.get(at).ok_or("truncated DNS name")?;
        if len & 0xc0 == 0xc0 {
            return Ok(at.saturating_add(2));
        }
        at = at.saturating_add(1);
        if len == 0 {
            return Ok(at);
        }
        at = at.saturating_add(usize::from(len));
    }
}

/// The A/AAAA addresses answering query `id`; an error for a wrong ID, a
/// non-response or a non-zero rcode.
pub fn answers(packet: &[u8], id: u16) -> Result<Vec<IpAddr>, String> {
    if u16_at(packet, 0)? != id {
        return Err("DNS reply for another query".into());
    }
    let flags = u16_at(packet, 2)?;
    if flags & 0x8000 == 0 {
        return Err("DNS packet is not a response".into());
    }
    if flags & 0x000f != 0 {
        return Err(format!("DNS rcode {}", flags & 0x000f));
    }
    let questions = u16_at(packet, 4)?;
    let count = u16_at(packet, 6)?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(packet, at)?.saturating_add(4);
    }
    let mut found = Vec::new();
    for _ in 0..count {
        at = skip_name(packet, at)?;
        let kind = u16_at(packet, at)?;
        let length = usize::from(u16_at(packet, at.saturating_add(8))?);
        let start = at.saturating_add(10);
        let data = packet
            .get(start..start.saturating_add(length))
            .ok_or("truncated DNS answer")?;
        match (kind, <[u8; 4]>::try_from(data), <[u8; 16]>::try_from(data)) {
            (1, Ok(v4), _) => found.push(IpAddr::from(v4)),
            (28, _, Ok(v6)) => found.push(IpAddr::from(v6)),
            _ => {}
        }
        at = start.saturating_add(length);
    }
    Ok(found)
}

fn resolve(server: IpAddr, name: &str, v6: bool) -> Result<(Vec<IpAddr>, SocketAddr), String> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse()
    } else {
        "[::]:0".parse()
    }
    .map_err(|e| format!("{e}"))?;
    let socket = UdpSocket::bind(bind).map_err(|e| format!("UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(DNS_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let target = SocketAddr::new(server, 53);
    let mut last = String::new();
    for attempt in 0..DNS_TRIES {
        let id = 0x5a00_u16.wrapping_add(u16::try_from(attempt).unwrap_or(0));
        // Unconnected: the reply's source shows recvmsg's reverse translation.
        socket
            .send_to(&query(id, name, v6)?, target)
            .map_err(|e| format!("send to {target}: {e}"))?;
        let mut buffer = [0u8; 1500];
        match socket.recv_from(&mut buffer) {
            Ok((size, from)) => {
                let reply = buffer.get(..size).ok_or("reply size")?;
                return Ok((answers(reply, id)?, from));
            }
            Err(e) => last = format!("no reply from {target} in {DNS_TIMEOUT:?}: {e}"),
        }
    }
    Err(last)
}

/// The `default/kubernetes` ClusterIP frontends (cluster scope) in the
/// agent's `GET /v1/service` rows, with whether each is realized.
pub fn kubernetes_frontends(rows: &[Value]) -> Vec<(SocketAddr, bool)> {
    rows.iter()
        .filter(|row| {
            let flag = |key: &str| {
                row.pointer(&format!("/spec/flags/{key}"))
                    .and_then(Value::as_str)
            };
            flag("namespace") == Some("default")
                && flag("name") == Some("kubernetes")
                && flag("type") == Some("ClusterIP")
                && row
                    .pointer("/spec/frontend-address/scope")
                    .and_then(Value::as_str)
                    != Some("node-local")
        })
        .filter_map(|row| {
            let ip = row
                .pointer("/spec/frontend-address/ip")
                .and_then(Value::as_str)?
                .parse::<IpAddr>()
                .ok()?;
            let port = row
                .pointer("/spec/frontend-address/port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())?;
            Some((
                SocketAddr::new(ip, port),
                row.pointer("/status/realized").is_some(),
            ))
        })
        .collect()
}

/// Whether `ip:port` is a realized frontend in `GET /v1/service` rows.
pub fn programmed(rows: &[Value], ip: IpAddr, port: u16) -> bool {
    rows.iter().any(|row| {
        row.pointer("/status/realized/frontend-address/ip")
            .and_then(Value::as_str)
            == Some(ip.to_string().as_str())
            && row
                .pointer("/status/realized/frontend-address/port")
                .and_then(Value::as_u64)
                == Some(u64::from(port))
    })
}

/// The `kubernetes` Service target: the agent's realized frontend at an
/// address kube-dns gave (`resolved`; any realized one when DNS failed),
/// with kube-dns's own frontend `dns`:53 realized too.
pub fn kubernetes_target(
    rows: &[Value],
    dns: IpAddr,
    resolved: Option<&[IpAddr]>,
) -> Result<SocketAddr, String> {
    if !programmed(rows, dns, 53) {
        return Err(format!("kube-dns {dns}:53 is not a programmed frontend"));
    }
    let frontends = kubernetes_frontends(rows);
    if frontends.is_empty() {
        return Err(format!(
            "no default/kubernetes ClusterIP among {} frontends",
            rows.len()
        ));
    }
    let wanted = |target: &SocketAddr| {
        target.is_ipv4() == dns.is_ipv4()
            && resolved.is_none_or(|addresses| addresses.contains(&target.ip()))
    };
    let mut matching = frontends.iter().filter(|(target, _)| wanted(target));
    match matching.clone().find(|(_, realized)| *realized) {
        Some((target, _)) => Ok(*target),
        None => match matching.next() {
            Some((target, _)) => Err(format!("kubernetes {target} is not programmed yet")),
            None => Err(format!(
                "kube-dns answered {resolved:?}; the agent has kubernetes at {:?}",
                frontends.iter().map(|(t, _)| *t).collect::<Vec<_>>()
            )),
        },
    }
}

pub fn probe(report: &mut Report, socket: &Path) {
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let Some((dns, domain)) = resolv_conf(&resolv) else {
        report.fail(
            "node-service-dns",
            Duration::ZERO,
            "no nameserver in /etc/resolv.conf",
        );
        return;
    };
    let name = format!("kubernetes.default.svc.{domain}");
    let resolved = report.check("node-service-dns", || {
        let (addresses, from) = resolve(dns, &name, dns.is_ipv6())?;
        if from != SocketAddr::new(dns, 53) {
            return Err(format!(
                "reply came from {from}, not the ClusterIP {dns}:53 (no reverse translation)"
            ));
        }
        if addresses.is_empty() {
            return Err(format!("{name} has no address"));
        }
        let detail = format!("{name} -> {addresses:?} via kube-dns {dns}:53");
        Ok((addresses, detail))
    });
    let target = report.check("node-service-programmed", || {
        let client = Client::new(socket, Duration::from_secs(2));
        let reply = client
            .request(Method::Get, "/v1/service", None)
            .map_err(|e| format!("GET /v1/service: {e}"))?;
        let rows = reply
            .json
            .as_ref()
            .and_then(Value::as_array)
            .ok_or_else(|| format!("GET /v1/service returned {}", reply.status))?;
        let target = kubernetes_target(rows, dns, resolved.as_deref())?;
        Ok((
            target,
            format!(
                "{} frontends; kube-dns {dns}:53 and kubernetes {target} programmed",
                rows.len()
            ),
        ))
    });
    report.check("node-service-kubernetes", || {
        let target = target.ok_or("no programmed kubernetes ClusterIP to connect to")?;
        let start = Instant::now();
        let stream = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)
            .map_err(|e| format!("connect {target}: {e}"))?;
        let peer = stream.peer_addr().map_err(|e| e.to_string())?;
        if peer != target {
            return Err(format!(
                "connected, but the peer shows {peer}, not {target}"
            ));
        }
        Ok((
            (),
            format!(
                "TCP {target} connected in {} ms",
                start.elapsed().as_millis()
            ),
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_gives_the_nameserver_and_cluster_domain() {
        let text = "search ns.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\nnameserver 10.96.0.11\noptions ndots:5\n";
        assert_eq!(
            resolv_conf(text),
            Some(("10.96.0.10".parse().expect("ip"), "cluster.local".into()))
        );
        assert_eq!(
            resolv_conf("nameserver fd00::a\n"),
            Some(("fd00::a".parse().expect("ip"), "cluster.local".into()))
        );
        assert_eq!(resolv_conf("search a\n"), None);
    }

    #[test]
    fn query_and_answers_round_trip_with_compression() {
        let q = query(7, "kubernetes.default.svc.cluster.local", false).expect("query");
        assert_eq!(q.get(..4), Some([0, 7, 1, 0].as_slice()));
        assert_eq!(
            q.get(q.len().saturating_sub(4)..),
            Some([0, 1, 0, 1].as_slice())
        );
        assert!(query(1, "bad..name", false).is_err());
        // The reply: the question echoed, then an A and an AAAA answer whose
        // names are pointers to the question (0xc00c).
        let mut reply = q.clone();
        if let Some(header) = reply.get_mut(2..8) {
            header.copy_from_slice(&[0x81, 0x80, 0, 1, 0, 2]);
        }
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 10, 96, 0, 1]);
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 5, 0, 16]);
        reply.extend_from_slice(
            &"fd00::1"
                .parse::<std::net::Ipv6Addr>()
                .expect("v6")
                .octets(),
        );
        assert_eq!(
            answers(&reply, 7),
            Ok(vec![
                "10.96.0.1".parse().expect("ip"),
                "fd00::1".parse().expect("ip")
            ])
        );
        assert!(answers(&reply, 8).is_err(), "another query's reply");
        let mut failed = reply.clone();
        if let Some(flags) = failed.get_mut(3) {
            *flags = 0x83;
        }
        assert_eq!(answers(&failed, 7), Err("DNS rcode 3".into()));
        assert!(answers(&q, 7).is_err(), "a query is not a response");
        assert!(answers(reply.get(..reply.len().saturating_sub(3)).expect("cut"), 7).is_err());
    }

    fn row(name: &str, kind: &str, ip: &str, port: u16, scope: &str, realized: bool) -> Value {
        let spec = serde_json::json!({
            "id": 1,
            "frontend-address": {"ip": ip, "port": port, "protocol": "TCP", "scope": scope},
            "flags": {"type": kind, "name": name, "namespace": if name == "kubernetes" { "default" } else { "kube-system" }},
        });
        if realized {
            serde_json::json!({"spec": spec.clone(), "status": {"realized": spec}})
        } else {
            serde_json::json!({"spec": spec, "status": {}})
        }
    }

    #[test]
    fn kubernetes_target_comes_from_dns_and_the_agent_not_the_environment() {
        let dns: IpAddr = "10.96.0.10".parse().expect("ip");
        let cluster: IpAddr = "10.96.0.1".parse().expect("ip");
        let rows = vec![
            row("kube-dns", "ClusterIP", "10.96.0.10", 53, "external", true),
            row(
                "kubernetes",
                "NodePort",
                "192.168.31.173",
                443,
                "external",
                true,
            ),
            row("kubernetes", "ClusterIP", "fd00::1", 443, "external", true),
            row(
                "kubernetes",
                "ClusterIP",
                "10.96.0.1",
                443,
                "node-local",
                true,
            ),
            row(
                "kubernetes",
                "ClusterIP",
                "10.96.0.1",
                443,
                "external",
                true,
            ),
        ];
        let want = SocketAddr::new(cluster, 443);
        assert_eq!(
            kubernetes_target(&rows, dns, Some(&[cluster][..])),
            Ok(want)
        );
        assert_eq!(kubernetes_target(&rows, dns, None), Ok(want));
        // #368: the apiserver's node address is not the Service.
        let node: IpAddr = "192.168.31.173".parse().expect("ip");
        assert!(kubernetes_target(&rows, dns, Some(&[node][..])).is_err());
        let other_dns: IpAddr = "10.96.0.11".parse().expect("ip");
        assert!(kubernetes_target(&rows, other_dns, Some(&[cluster][..])).is_err());
        let unrealized = vec![
            row("kube-dns", "ClusterIP", "10.96.0.10", 53, "external", true),
            row(
                "kubernetes",
                "ClusterIP",
                "10.96.0.1",
                443,
                "external",
                false,
            ),
        ];
        assert_eq!(
            kubernetes_target(&unrealized, dns, Some(&[cluster][..])),
            Err("kubernetes 10.96.0.1:443 is not programmed yet".into())
        );
        assert!(
            kubernetes_target(
                rows.get(..1).expect("kube-dns row"),
                dns,
                Some(&[cluster][..])
            )
            .is_err()
        );
    }
}
