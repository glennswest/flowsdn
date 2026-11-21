//! Kubernetes `PacketDrop` Events (#470, the reference's
//! `hubble-drop-events` emitter, `pkg/hubble/dropeventemitter`): a Warning
//! Event on a local Pod each time the policy programs drop its traffic for a
//! listed reason. Ingress drops go on the destination Pod, egress drops on
//! the source Pod; the host firewall's drops and audit-mode passes have no
//! Event. The message is the reference's: `Incoming packet dropped
//! (policy_denied) from shop/web-1 (10.1.0.5) TCP/80.` or `Outgoing packet
//! dropped (…) to …`, with `-extended` the policies applied to the Pod in
//! that direction. [`flowsdn_hubble::drop_events::Gate`] admits one Event per
//! Pod, reason and message per interval, and at most `-rate-limit` a second;
//! the agent's Event writer then aggregates repeats as the kubelet does.
use crate::kubernetes::{DropEvents, View};
use flowsdn_bpf_abi::policy::{HOST_ENDPOINT, PolicyEvent, verdict};
use flowsdn_hubble::drop_events::{Gate, Key};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

/// Pods, reasons and messages remembered for the interval at once; a new one
/// past this waits for an old one to expire.
const KEYS: usize = 4096;
/// The Event's reason.
pub(super) const REASON: &str = "PacketDrop";

/// One `PacketDrop` Event to write: the Pod and the message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Drop {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub message: String,
}

pub(super) struct Emitter {
    settings: DropEvents,
    gate: Gate,
}
impl Emitter {
    pub(super) fn new(settings: DropEvents) -> crate::state::Result<Self> {
        let gate = Gate::new(settings.interval, KEYS, settings.rate_limit)?;
        Ok(Self { settings, gate })
    }
    /// The Events `events` call for at `now` (monotonic), as the gate admits
    /// them.
    pub(super) fn process(
        &mut self,
        now: Duration,
        events: &[PolicyEvent],
        view: &View,
    ) -> Vec<Drop> {
        let mut out = Vec::new();
        for event in events {
            let Some(drop) = self.render(event, view) else {
                continue;
            };
            let key = Key {
                pod_uid: if drop.uid.is_empty() {
                    format!("{}/{}", drop.namespace, drop.name)
                } else {
                    drop.uid.clone()
                },
                reason: REASON.to_owned(),
                message: drop.message.clone(),
            };
            // The writer queues without reporting back: a write is taken as
            // done, so its key stays for the interval.
            if let Ok(ticket) = self.gate.admit(now, key) {
                self.gate.finish(ticket, true);
                out.push(drop);
            }
        }
        out
    }
    /// The Event for one decision, or None when it calls for none.
    fn render(&self, event: &PolicyEvent, view: &View) -> Option<Drop> {
        if event.verdict != verdict::DENIED
            || event.endpoint == HOST_ENDPOINT
            || !self.settings.reasons.contains(&event.reason)
        {
            return None;
        }
        let reason = super::policy_events::reason_name(event.reason)?;
        let id = u16::try_from(event.endpoint).ok()?;
        let endpoint = view.endpoints.iter().find(|e| e.id == id)?;
        let ingress = event.egress == 0;
        let remote_ip = address(
            event.family,
            if ingress { event.saddr } else { event.daddr },
        );
        let peer = peer(view, remote_ip, event.remote);
        let l4 = match event.protocol {
            6 => format!("TCP/{}", event.dport.get()),
            17 => format!("UDP/{}", event.dport.get()),
            132 => "SCTP".to_owned(),
            1 => "ICMPv4".to_owned(),
            58 => "ICMPv6".to_owned(),
            _ => String::new(),
        };
        let mut message = if ingress {
            format!("Incoming packet dropped ({reason}) from {peer} {l4}.")
        } else {
            format!("Outgoing packet dropped ({reason}) to {peer} {l4}.")
        };
        if self.settings.extended
            && let Some(applied) = view.applied_policies.get(&(id, ingress))
        {
            let list = |clusterwide: bool| {
                applied
                    .iter()
                    .filter(|(c, _)| *c == clusterwide)
                    .map(|(_, name)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let mut parts = Vec::new();
            let namespaced = list(false);
            if !namespaced.is_empty() {
                parts.push(format!("Applied policies: {namespaced}."));
            }
            let clusterwide = list(true);
            if !clusterwide.is_empty() {
                parts.push(format!("Applied clusterwide policies: {clusterwide}."));
            }
            if !parts.is_empty() {
                message.push(' ');
                message.push_str(&parts.join(" "));
            }
        }
        let uid = if endpoint.uid.is_empty() {
            view.pods
                .iter()
                .find(|p| p.namespace == endpoint.namespace && p.name == endpoint.name)
                .map(|p| p.uid.clone())
                .unwrap_or_default()
        } else {
            endpoint.uid.clone()
        };
        Some(Drop {
            namespace: endpoint.namespace.clone(),
            name: endpoint.name.clone(),
            uid,
            message: cut(message),
        })
    }
}

/// The message within the Event writer's limit, cut on a character boundary.
fn cut(mut message: String) -> String {
    if message.len() > crate::events::MESSAGE_MAX {
        let mut end = crate::events::MESSAGE_MAX;
        while !message.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        message.truncate(end);
    }
    message
}

fn address(family: u8, bytes: [u8; 16]) -> IpAddr {
    if family == flowsdn_bpf_abi::FAMILY_V4 {
        let [a, b, c, d, ..] = bytes;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    }
}

/// The reference's `endpointToString`: `namespace/pod (ip)` for a Pod, the
/// reserved identity's name and address for one, else the address.
fn peer(view: &View, ip: IpAddr, identity: u32) -> String {
    if let Some(pod) = view
        .pods
        .iter()
        .find(|p| !p.host_network && p.ips.contains(&ip))
    {
        return format!("{}/{} ({ip})", pod.namespace, pod.name);
    }
    let name = match identity {
        crate::host_policy::HOST => "host",
        crate::host_policy::WORLD => "world",
        crate::host_policy::UNMANAGED => "unmanaged",
        crate::host_policy::HEALTH => "health",
        crate::host_policy::INIT => "init",
        crate::host_policy::REMOTE_NODE => "remote-node",
        crate::host_policy::KUBE_APISERVER => "kube-apiserver",
        crate::host_policy::INGRESS => "ingress",
        9 => "world-ipv4",
        10 => "world-ipv6",
        // Each other node's address has its own identity (#490); the
        // reference names them all remote-node.
        id if id & !0x00ff_ffff == crate::policy::REMOTE_NODE_SCOPE => "remote-node",
        _ => return ip.to_string(),
    };
    format!("{name} ({ip})")
}

#[cfg(test)]
#[path = "drop_emitter_tests.rs"]
mod tests;
