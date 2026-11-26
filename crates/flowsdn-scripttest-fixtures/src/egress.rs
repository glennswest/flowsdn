//! The egress gateway area (#523, spec 17 §3.3.14): `egress/policy-maps-dump`
//! over flowsdn's own planner ([`flowsdn_agent::egress_gateway::plan`]),
//! fed from the fake API's FlowsdnEgressGatewayPolicies, Pods, Nodes and
//! Namespaces, as the agent's watches feed it. The dump is the reference's
//! line format, one entry per line, sorted:
//! `source_ip=… dest_cidr=… egress_ip=… egress_ifindex=… gateway_ip=…`
//! (the destination's address only, as the reference prints it).
use crate::{fixture::lock, k8s::FakeClient};
use flowsdn_agent::{
    egress_gateway::{Interface, Local, plan},
    kubernetes::{NodeInfo, PodInfo},
};
use flowsdn_bpf_abi::{MapBytes, egress::EgressGw4Value};
use flowsdn_k8s::watch::{Resource, Scope};
use flowsdn_scripttest::{CommandError, Control, Engine, State};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

/// The node the harvested egress gateway scripts run as.
pub const NODE: &str = "kind-worker";
const POLICIES: &str = "flowsdn.io.v1alpha1.flowsdnegressgatewaypolicies";

/// The dump of what flowsdn would program on [`NODE`].
pub fn dump(client: &FakeClient) -> String {
    let parse = |resource: &str, scope: Scope| -> Vec<Resource> {
        client
            .list(resource, "")
            .into_iter()
            .filter_map(|object| scope.parse(object).ok())
            .collect()
    };
    let pods: Vec<PodInfo> = parse("v1.pods", Scope::Pods)
        .into_iter()
        .filter_map(|row| match row {
            Resource::Pod(pod) => Some(PodInfo {
                namespace: pod.metadata.namespace.clone(),
                name: pod.metadata.name.clone(),
                node: pod.node_name.clone(),
                host_network: pod.host_network,
                ips: pod.pod_ips.clone(),
                labels: pod.labels.clone(),
                uid: pod.metadata.uid.clone(),
                ..PodInfo::default()
            }),
            _ => None,
        })
        .collect();
    let nodes: Vec<NodeInfo> = parse("v1.nodes", Scope::Nodes)
        .into_iter()
        .filter_map(|row| match row {
            Resource::Node(node) => Some(NodeInfo {
                name: node.metadata.name.clone(),
                internal_ips: node.internal_ips.clone(),
                labels: node.labels.clone(),
                ..NodeInfo::default()
            }),
            _ => None,
        })
        .collect();
    let namespaces: BTreeMap<String, BTreeMap<String, String>> =
        parse("v1.namespaces", Scope::Namespaces)
            .into_iter()
            .filter_map(|row| match row {
                Resource::Namespace(ns) => Some((ns.metadata.name.clone(), ns.labels.clone())),
                _ => None,
            })
            .collect();
    let policies: Vec<serde_json::Value> = client.list(POLICIES, "").into_iter().cloned().collect();
    let interfaces: [Interface; 0] = [];
    let local = Local {
        node: NODE,
        interfaces: &interfaces,
        primary: None,
    };
    let (entries, _) = plan(&policies, &pods, &namespaces, &nodes, &local);
    let mut out = String::new();
    for ((_, data), value) in entries.v4 {
        let value = EgressGw4Value::from_bytes(value);
        let [a, b, c, d, e, f, g, h] = data;
        out.push_str(&format!(
            "source_ip={} dest_cidr={} egress_ip={} egress_ifindex={} gateway_ip={}\n",
            Ipv4Addr::from([a, b, c, d]),
            Ipv4Addr::from([e, f, g, h]),
            Ipv4Addr::from(value.egress_ip),
            value.egress_ifindex,
            Ipv4Addr::from(value.gateway_ip)
        ));
    }
    out
}

fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}

/// Register `egress/policy-maps-dump [file]`.
pub fn register(engine: &mut Engine, client: &Arc<Mutex<FakeClient>>) -> Result<(), String> {
    let c = Arc::clone(client);
    engine.register_command(
        "egress/policy-maps-dump",
        false,
        move |state: &mut State, args: &[String]| {
            let text = dump(&lock(&c));
            match args {
                [] => state.publish(text, ""),
                [file] => state.write_text(file, &text)?,
                _ => return Err(fail("egress/policy-maps-dump takes at most a file")),
            }
            Ok(Control::Continue)
        },
    )?;
    Ok(())
}
