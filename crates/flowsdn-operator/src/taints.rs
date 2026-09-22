//! Pure desired-taint calculation. Kubernetes patches must still test the exact
//! observed array before replacing it; this library performs no API writes.
pub const AGENT_NOT_READY_KEY: &str = "node.cilium.io/agent-not-ready";
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Taint { pub key: String, pub value: String, pub effect: String }
pub fn remove_not_ready(observed: &[Taint], configured_key: &str) -> Vec<Taint> {
    observed.iter().filter(|taint| taint.key != configured_key).cloned().collect()
}
pub fn add_not_ready(observed: &[Taint], configured_key: &str) -> Vec<Taint> {
    let mut desired = observed.to_vec();
    if !observed.iter().any(|taint| taint.key == configured_key) {
        desired.push(Taint { key: configured_key.to_owned(), value: String::new(), effect: "NoSchedule".into() });
    }
    desired
}
