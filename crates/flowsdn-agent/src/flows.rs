//! Flows (#485): `GET /v1/flows`, the policy decision events (#452) as flow
//! records for the console's Flows tab, newest first. Each side is the Pod
//! the address belongs to (Hubble's flow `Endpoint`, with namespace on both
//! sides) or a reserved peer (`host`, `remote-node`, `world`, …), with its
//! address and port. A record is a decision of the endpoint programs: the
//! first packet of a flow that was allowed, dropped or passed in audit mode
//! on an endpoint whose policy is enforced or tracked. Packets of remembered
//! flows add none, and the datapath counts no bytes or packets per flow and
//! does not record which rule decided, so records carry neither.
use super::policy_events::Events;
use super::*;
use crate::host_policy::{
    AGGREGATE_REMOTE_NODE, AGGREGATE_WORLD, HEALTH, HOST, INGRESS, INIT, KUBE_APISERVER,
    REMOTE_NODE, UNMANAGED, WORLD,
};
use crate::kubernetes::View;
use flowsdn_bpf_abi::policy::{HOST_ENDPOINT, PolicyEvent, verdict};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};

/// Records returned without `?limit=`.
pub(super) const DEFAULT_LIMIT: usize = 100;

/// The event's address as an [`IpAddr`].
fn address(family: u8, bytes: [u8; 16]) -> IpAddr {
    if family == flowsdn_bpf_abi::FAMILY_V4 {
        let [a, b, c, d, ..] = bytes;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    }
}

/// A reserved identity's name (spec 03), or None for a Pod or CIDR one.
fn reserved(identity: u32) -> Option<&'static str> {
    Some(match identity {
        HOST => "host",
        WORLD | AGGREGATE_WORLD | 9 | 10 => "world",
        UNMANAGED => "unmanaged",
        HEALTH => "health",
        INIT => "init",
        REMOTE_NODE | AGGREGATE_REMOTE_NODE => "remote-node",
        KUBE_APISERVER => "kube-apiserver",
        INGRESS => "ingress",
        _ => return None,
    })
}

/// One side of a flow: `ip` is its address, `local` the endpoint ID when it
/// is this node's endpoint (the host's included), `identity` the remote
/// identity the datapath judged when it is the remote side.
fn side(
    view: Option<&View>,
    ip: IpAddr,
    port: Option<u16>,
    local: Option<u32>,
    identity: Option<u32>,
) -> Value {
    let pod = view.and_then(|view| {
        view.pods
            .iter()
            .find(|pod| !pod.host_network && pod.ips.contains(&ip))
    });
    let mut value = if local == Some(HOST_ENDPOINT) {
        json!({"reserved": "host"})
    } else if let Some(pod) = pod {
        let mut info = pod.endpoint_info();
        info.id = local.and_then(|id| u16::try_from(id).ok()).unwrap_or(0);
        info.identity = view
            .and_then(|view| view.pod_identity(&pod.namespace, &pod.name))
            .or(identity);
        info.to_json()
    } else if let Some(node) = view.and_then(|view| {
        view.nodes
            .iter()
            .find(|node| node.internal_ips.contains(&ip))
    }) {
        let local_node = view.is_some_and(|view| view.local_node == node.name);
        json!({
            "reserved": if local_node { "host" } else { "remote-node" },
            "node_name": node.name,
        })
    } else {
        match identity {
            Some(id) => match reserved(id) {
                Some(name) => json!({"reserved": name, "identity": id}),
                None => json!({"identity": id}),
            },
            None => json!({}),
        }
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("ip".into(), json!(ip.to_string()));
        if let Some(port) = port {
            object.insert("port".into(), json!(port));
        }
    }
    value
}

/// One flow record (see docs/agent-api.md).
fn record(view: Option<&View>, time: SystemTime, event: &PolicyEvent) -> Value {
    let v4 = event.family == flowsdn_bpf_abi::FAMILY_V4;
    let protocol = match (event.protocol, v4) {
        (6, _) => json!("TCP"),
        (17, _) => json!("UDP"),
        (132, _) => json!("SCTP"),
        (1, true) => json!("ICMPv4"),
        (58, false) => json!("ICMPv6"),
        (other, _) => json!(other),
    };
    // ICMP has no ports: the event's are the echo identifier.
    let ports = matches!(event.protocol, 6 | 17 | 132);
    let egress = event.egress != 0;
    let (source_local, destination_local) = if egress {
        (Some(event.endpoint), None)
    } else {
        (None, Some(event.endpoint))
    };
    let (source_identity, destination_identity) = if egress {
        (None, Some(event.remote))
    } else {
        (Some(event.remote), None)
    };
    let source = side(
        view,
        address(event.family, event.saddr),
        ports.then(|| event.sport.get()),
        source_local,
        source_identity,
    );
    let destination = side(
        view,
        address(event.family, event.daddr),
        ports.then(|| event.dport.get()),
        destination_local,
        destination_identity,
    );
    let mut value = json!({
        "time": super::health_api::timestamp(Some(time)).unwrap_or_default(),
        "verdict": match event.verdict {
            verdict::ALLOWED => "FORWARDED",
            verdict::DENIED => "DROPPED",
            verdict::AUDIT => "AUDIT",
            _ => "VERDICT_UNKNOWN",
        },
        "traffic_direction": if egress { "EGRESS" } else { "INGRESS" },
        "protocol": protocol,
        "source": source,
        "destination": destination,
    });
    if event.verdict == verdict::DENIED
        && let Some(object) = value.as_object_mut()
    {
        let reason = super::policy_events::reason_name(event.reason)
            .map_or_else(|| "DROP_REASON_UNKNOWN".to_owned(), str::to_uppercase);
        object.insert("drop_reason".into(), json!(reason));
    }
    value
}

/// `GET /v1/flows`: the newest `limit` records at or after `since`, newest
/// first, with how many decisions the agent has seen and keeps.
pub(super) fn json(
    events: &Events,
    view: Option<&View>,
    limit: usize,
    since: Option<SystemTime>,
) -> Value {
    let (seen, kept, newest) = events.newest(limit, since);
    let flows: Vec<Value> = newest
        .iter()
        .map(|(time, event)| record(view, *time, event))
        .collect();
    json!({"seen": seen, "kept": kept, "flows": flows})
}

/// An RFC 3339 time (`2026-11-21T10:00:00Z`, `…T10:00:00.5+01:00`); None
/// when it is not one or is before 1970.
pub(super) fn parse_time(text: &str) -> Option<SystemTime> {
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = text.get(range)?;
        digits
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| digits.parse().ok())?
    };
    let separators = [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|(at, byte)| text.as_bytes().get(*at) != Some(byte))
        || !matches!(text.as_bytes().get(10), Some(b'T' | b't' | b' '))
    {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    // The month's length, with the Gregorian leap years (finding
    // 3c7298844c45): 2026-02-30 is refused, not read as March 2.
    let divides = |n: i64| year.checked_rem(n) == Some(0);
    let leap = divides(4) && (!divides(100) || divides(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=12).contains(&month)
        || !(1..=days).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = text.get(19..)?;
    let mut nanos: u32 = 0;
    if let Some(fraction) = rest.strip_prefix('.') {
        let length = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if length == 0 {
            return None;
        }
        let digits = fraction.get(..length)?;
        let padded = format!("{:0<9}", digits.get(..length.min(9))?);
        nanos = padded.parse().ok()?;
        rest = fraction.get(length..)?;
    }
    let offset: i64 = match rest {
        "Z" | "z" => 0,
        _ => {
            let negative = match rest.as_bytes().first() {
                Some(b'+') => false,
                Some(b'-') => true,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes().get(3) != Some(&b':') {
                return None;
            }
            let hours: i64 = rest.get(1..3)?.parse().ok()?;
            let minutes: i64 = rest.get(4..6)?.parse().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let total = hours
                .checked_mul(3600)?
                .checked_add(minutes.checked_mul(60)?)?;
            if negative {
                total.checked_neg()?
            } else {
                total
            }
        }
    };
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?
        .checked_sub(offset)?;
    UNIX_EPOCH.checked_add(Duration::new(u64::try_from(seconds).ok()?, nanos))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = y.checked_div_euclid(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let shifted = if month > 2 {
        month.checked_sub(3)?
    } else {
        month.checked_add(9)?
    };
    let doy = shifted
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

#[cfg(test)]
#[path = "flows_tests.rs"]
mod tests;
