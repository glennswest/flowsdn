//! DNS lookup latency through the pod's resolver (kube-dns): an A or AAAA
//! query over UDP to the first `nameserver` of /etc/resolv.conf, timed to
//! the matching answer.
use crate::stats::Samples;
use std::{
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

/// `nameserver` and the cluster domain (from a `<ns>.svc.<domain>` search
/// entry) of a resolv.conf.
pub fn resolver(conf: &str, namespace: &str) -> Option<(IpAddr, String)> {
    let mut server = None;
    let mut domain = None;
    let prefix = format!("{namespace}.svc.");
    for line in conf.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") if server.is_none() => {
                server = words.next().and_then(|w| w.parse().ok());
            }
            Some("search") => {
                for word in words {
                    if let Some(rest) = word.strip_prefix(&prefix) {
                        domain = Some(rest.trim_end_matches('.').to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    Some((server?, domain.unwrap_or_else(|| "cluster.local".into())))
}

/// A recursive query for `name` (no trailing dot needed).
pub fn query(id: u16, name: &str, kind: u16) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(name.len().saturating_add(18));
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let length = u8::try_from(label.len()).ok().filter(|n| (1..64).contains(n))?;
        packet.push(length);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&[0, 1]);
    Some(packet)
}

/// `(rcode, answer count)` of a response to query `id`, or None if it is not one.
pub fn response(packet: &[u8], id: u16) -> Option<(u8, u16)> {
    let header: [u8; 12] = packet.get(..12)?.try_into().ok()?;
    let [i0, i1, flags, rcode, _, _, a0, a1, ..] = header;
    if u16::from_be_bytes([i0, i1]) != id || flags & 0x80 == 0 {
        return None;
    }
    Some((rcode & 0x0f, u16::from_be_bytes([a0, a1])))
}

/// Look `name` up `count` times; every lookup must answer NOERROR with at
/// least one record. Returns the samples.
pub fn lookups(server: IpAddr, name: &str, kind: u16, count: usize) -> io::Result<Samples> {
    let local: SocketAddr = if server.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect((server, 53))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut samples = Samples::default();
    let mut buffer = [0u8; 1500];
    for n in 0..count {
        let id = u16::try_from(n % 65_536).unwrap_or(0);
        let packet = query(id, name, kind)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad DNS name"))?;
        let sent = Instant::now();
        socket.send(&packet)?;
        loop {
            let size = socket.recv(&mut buffer)?;
            if let Some((rcode, answers)) = response(buffer.get(..size).unwrap_or_default(), id) {
                if rcode != 0 || answers == 0 {
                    return Err(io::Error::other(format!(
                        "{name}: rcode {rcode}, {answers} answers"
                    )));
                }
                samples.push(sent.elapsed());
                break;
            }
        }
    }
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_gives_server_and_cluster_domain() {
        let conf = "search perf.svc.cluster.example svc.cluster.example cluster.example\n\
                    nameserver 10.96.0.10\nnameserver 10.96.0.11\noptions ndots:5\n";
        let (server, domain) = resolver(conf, "perf").expect("resolver");
        assert_eq!(server, "10.96.0.10".parse::<IpAddr>().expect("ip"));
        assert_eq!(domain, "cluster.example");
        let (_, domain) = resolver("nameserver fd00::a\n", "perf").expect("default");
        assert_eq!(domain, "cluster.local");
        assert!(resolver("search a\n", "perf").is_none());
    }

    #[test]
    fn query_and_response_codec() {
        let packet = query(0x1234, "kube-dns.kube-system.svc.cluster.local.", TYPE_A)
            .expect("query");
        assert_eq!(packet.get(..2), Some([0x12, 0x34].as_slice()));
        assert_eq!(packet.get(12), Some(&8));
        assert_eq!(packet.len(), 12 + 1 + 8 + 1 + 11 + 1 + 3 + 1 + 7 + 1 + 5 + 1 + 4);
        assert!(query(1, "a..b", TYPE_A).is_none());
        assert!(query(1, &"x".repeat(64), TYPE_A).is_none());
        let mut reply = packet.clone();
        if let Some(flags) = reply.get_mut(2) {
            *flags |= 0x80;
        }
        if let Some(count) = reply.get_mut(7) {
            *count = 1;
        }
        assert_eq!(response(&reply, 0x1234), Some((0, 1)));
        assert_eq!(response(&reply, 0x1235), None);
        assert_eq!(response(&packet, 0x1234), None, "a query is not a response");
        assert_eq!(response(&[0; 4], 0), None);
    }
}
