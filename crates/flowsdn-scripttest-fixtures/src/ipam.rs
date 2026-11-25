//! The IPAM areas (#517, spec 17 §3.3.12): `ipam/start` over flowsdn's agent
//! IPAM source. In Kubernetes mode the agent takes its pools from its own
//! Node's pod CIDRs (spec 07 §3.4, `wait_for_pools`), read with the agent's
//! Node parser ([`flowsdn_k8s::watch::Scope::Nodes`]); it reads no CiliumNode
//! (ADR-0020). The harvested scripts give the node only as a `cilium.io/v2`
//! CiliumNode, so `ipam/start` reports what the agent would: no Node.
use crate::{fixture::lock, k8s::FakeClient};
use flowsdn_k8s::watch::{Resource, Scope};
use flowsdn_scripttest::{CommandError, Control, Engine, State};
use std::sync::{Arc, Mutex};

/// The node the harvested IPAM scripts run as.
pub const NODE: &str = "test-node";

fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}

/// Register `ipam/start` against `client`'s Nodes.
pub fn register(engine: &mut Engine, client: &Arc<Mutex<FakeClient>>) -> Result<(), String> {
    let c = Arc::clone(client);
    engine.register_command("ipam/start", false, move |state: &mut State, _: &[String]| {
        let client = lock(&c);
        let node = client
            .list("v1.nodes", "")
            .into_iter()
            .filter_map(|object| Scope::Nodes.parse(object).ok())
            .find_map(|row| match row {
                Resource::Node(node) if node.metadata.name == NODE => Some(node),
                _ => None,
            })
            .ok_or_else(|| {
                fail(format!(
                    "the Node {NODE} is not registered: flowsdn's IPAM takes its pools from the \
                     Node's pod CIDRs and reads no CiliumNode"
                ))
            })?;
        let cidrs: Vec<String> = node
            .pod_cidrs
            .iter()
            .map(|(ip, len)| format!("{ip}/{len}"))
            .collect();
        drop(client);
        state.publish(format!("pools: {}\n", cidrs.join(", ")), "");
        Ok(Control::Continue)
    })?;
    Ok(())
}
