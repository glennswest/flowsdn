//! Policy decision events (#452): the endpoint programs emit one into the
//! `flowsdn_policy_events` ring buffer per decision they count (a new flow
//! allowed, a drop, an audit pass); a reader thread keeps the newest
//! [`KEPT`] in memory with their wall-clock time, for `GET
//! /v1/policy/events`.
use super::*;
use flowsdn_bpf_abi::policy::{HOST_ENDPOINT, PolicyEvent, drop_reason, verdict};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, PoisonError},
    time::SystemTime,
};

/// Events kept.
pub(super) const KEPT: usize = 4096;
/// How often the reader drains the ring buffer.
const POLL: Duration = Duration::from_millis(100);

/// The kept events with their wall-clock time, oldest first, and how many
/// the reader has seen.
type Kept = (VecDeque<(SystemTime, PolicyEvent)>, u64);
#[derive(Clone, Default)]
pub(super) struct Events {
    inner: Arc<Mutex<Kept>>,
}
impl Events {
    /// Keep `events`, read at `now` (`monotonic`: the clock the programs
    /// stamp them with, in ns).
    pub(super) fn push(&self, events: Vec<PolicyEvent>, now: SystemTime, monotonic: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        for event in events {
            let age = Duration::from_nanos(monotonic.saturating_sub(event.time_ns));
            inner
                .0
                .push_back((now.checked_sub(age).unwrap_or(now), event));
            if inner.0.len() > KEPT {
                inner.0.pop_front();
            }
            inner.1 = inner.1.saturating_add(1);
        }
    }
    /// The newest `limit` at or after `since`, newest first, with how many
    /// were seen and are kept (for `GET /v1/flows`, #485).
    pub(super) fn newest(
        &self,
        limit: usize,
        since: Option<SystemTime>,
    ) -> (u64, usize, Vec<(SystemTime, PolicyEvent)>) {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let newest = inner
            .0
            .iter()
            .rev()
            .take_while(|(time, _)| since.is_none_or(|since| *time >= since))
            .take(limit)
            .copied()
            .collect();
        (inner.1, inner.0.len(), newest)
    }
    /// `GET /v1/policy/events`: the newest `limit`, newest first, and how
    /// many were seen since the agent started.
    pub(super) fn json(&self, limit: usize) -> Value {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let events: Vec<Value> = inner
            .0
            .iter()
            .rev()
            .take(limit)
            .map(|(time, event)| event_json(*time, event))
            .collect();
        json!({"seen": inner.1, "kept": inner.0.len(), "events": events})
    }
}

/// A refusal's reason as the reference names it (`hubble-drop-events-reasons`,
/// Hubble's `DropReason` in lower case); None for 0 (not judged: malformed,
/// a later fragment) and allowed packets.
pub(super) fn reason_name(reason: u8) -> Option<&'static str> {
    match reason {
        drop_reason::POLICY_DENIED => Some("policy_denied"),
        drop_reason::POLICY_DENY => Some("policy_deny"),
        drop_reason::AUTH_REQUIRED => Some("auth_required"),
        _ => None,
    }
}

fn address(family: u8, bytes: [u8; 16]) -> String {
    if family == flowsdn_bpf_abi::FAMILY_V4 {
        let [a, b, c, d, ..] = bytes;
        std::net::Ipv4Addr::new(a, b, c, d).to_string()
    } else {
        std::net::Ipv6Addr::from(bytes).to_string()
    }
}
fn event_json(time: SystemTime, event: &PolicyEvent) -> Value {
    let protocol = match (event.protocol, event.family == flowsdn_bpf_abi::FAMILY_V4) {
        (6, _) => json!("TCP"),
        (17, _) => json!("UDP"),
        (132, _) => json!("SCTP"),
        (1, true) => json!("ICMPv4"),
        (58, false) => json!("ICMPv6"),
        (other, _) => json!(other),
    };
    let mut value = json!({
        "time": super::health_api::timestamp(Some(time)).unwrap_or_default(),
        "endpoint": if event.endpoint == HOST_ENDPOINT { json!("host") } else { json!(event.endpoint) },
        "direction": if event.egress != 0 { "egress" } else { "ingress" },
        "verdict": match event.verdict {
            verdict::ALLOWED => "allowed",
            verdict::DENIED => "denied",
            verdict::AUDIT => "audit",
            _ => "unknown",
        },
        "remote-identity": event.remote,
        "ifindex": event.ifindex,
        "protocol": protocol,
        "source": address(event.family, event.saddr),
        "destination": address(event.family, event.daddr),
        "source-port": event.sport.get(),
        "destination-port": event.dport.get(),
    });
    if let (Some(reason), Some(object)) = (reason_name(event.reason), value.as_object_mut()) {
        object.insert("reason".into(), json!(reason));
    }
    value
}

/// The monotonic clock in ns (what `bpf_ktime_get_ns` reads).
fn monotonic() -> u64 {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map(|t| {
            u64::try_from(t.tv_sec())
                .unwrap_or(0)
                .saturating_mul(1_000_000_000)
                .saturating_add(u64::try_from(t.tv_nsec()).unwrap_or(0))
        })
        .unwrap_or(0)
}

/// Read `ring` into `events` for the life of the process.
/// With `drops` (`kubernetes.hubble-drop-events`, #470), each batch also
/// goes to the `PacketDrop` emitter, which reads the Pods from the view.
pub(super) fn spawn(
    mut ring: flowsdn_bpf_loader::kernel::PolicyEvents,
    events: Events,
    mut drops: Option<(super::drop_emitter::Emitter, crate::kubernetes::Shared)>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("policy-events".into())
        .spawn(move || {
            loop {
                let batch = ring.drain(KEPT);
                if !batch.is_empty() {
                    let now = monotonic();
                    if let Some((emitter, view)) = drops.as_mut() {
                        let written = {
                            let view = crate::kubernetes::lock(view);
                            emitter.process(Duration::from_nanos(now), &batch, &view)
                        };
                        for drop in written {
                            crate::events::pod(
                                &drop.namespace,
                                &drop.name,
                                &drop.uid,
                                crate::events::Type::Warning,
                                super::drop_emitter::REASON,
                                drop.message,
                            );
                        }
                    }
                    events.push(batch, SystemTime::now(), now);
                }
                std::thread::sleep(POLL);
            }
        })
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(n: u8, verdict_kind: u8) -> PolicyEvent {
        PolicyEvent {
            time_ns: 1_000_000_000,
            endpoint: 7,
            remote: 300,
            ifindex: 40,
            saddr: [10, 0, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            daddr: [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            sport: flowsdn_bpf_abi::Be16([0x9c, n]),
            dport: flowsdn_bpf_abi::Be16([0, 80]),
            protocol: 6,
            family: flowsdn_bpf_abi::FAMILY_V4,
            egress: 0,
            verdict: verdict_kind,
            reason: 0,
            pad: [0; 3],
        }
    }

    /// #452: events are kept newest first with their wall time and decoded
    /// fields; the oldest go past [`KEPT`].
    #[test]
    fn events_are_kept_and_rendered() {
        let events = Events::default();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        events.push(
            vec![event(1, verdict::ALLOWED), event(2, verdict::DENIED)],
            now,
            3_000_000_000,
        );
        let out = events.json(10);
        assert_eq!(out.get("seen"), Some(&json!(2)));
        let first = out.pointer("/events/0").expect("newest");
        assert_eq!(first.get("verdict"), Some(&json!("denied")));
        assert_eq!(first.get("protocol"), Some(&json!("TCP")));
        assert_eq!(first.get("source"), Some(&json!("10.0.1.5")));
        assert_eq!(first.get("destination"), Some(&json!("10.0.0.7")));
        assert_eq!(first.get("destination-port"), Some(&json!(80)));
        assert_eq!(first.get("source-port"), Some(&json!(0x9c02)));
        assert_eq!(first.get("remote-identity"), Some(&json!(300)));
        assert_eq!(first.get("direction"), Some(&json!("ingress")));
        // Stamped 2 s before the read: 2 s before `now`.
        assert_eq!(first.get("time"), Some(&json!("2027-01-15T07:59:58Z")));
        assert_eq!(
            events
                .json(1)
                .get("events")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        let many: Vec<PolicyEvent> = (0..KEPT.saturating_add(5))
            .map(|_| event(3, verdict::AUDIT))
            .collect();
        events.push(many, now, 3_000_000_000);
        let out = events.json(usize::MAX);
        assert_eq!(out.get("kept"), Some(&json!(KEPT)));
        let seen = u64::try_from(KEPT).expect("small").saturating_add(7);
        assert_eq!(out.get("seen").and_then(Value::as_u64), Some(seen));
    }
}
