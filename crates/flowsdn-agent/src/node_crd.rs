//! The FlowsdnNode writer (#332, spec 13 §3.9, spec 10 §3.3.2): the agent
//! keeps the cluster-scoped FlowsdnNode named after its Node, owned by the
//! Node, with the Node's labels, its InternalIPs (`spec.addresses`), the pod
//! CIDRs this agent allocates from (`spec.ipam.podCIDRs`: the Node's, or
//! the ones it derives) and the kernel's boot ID; its status lists the
//! addresses in use by local endpoints (`status.ipam.used`, owner
//! `<namespace>/<pod>`).
//!
//! [`NodeWriter::sync`] reads the object, creates it (`POST`) when absent,
//! replaces it (`PUT`, the read's resourceVersion) when its labels, owner
//! or spec differ, and writes the status (`PUT …/status`) when that
//! differs. What was written is not re-read for five minutes unless it
//! changes. A 404 on the create means the kind is not served (its CRD is not
//! applied): retried after a minute, not an error. Deleting the FlowsdnNode
//! of a removed Node is the operator's (#479); the owner reference lets
//! Kubernetes do it meanwhile.
use crate::endpoint_crd::{Send, UNSERVED_RETRY};
use crate::kubernetes::{View, node_cidrs};
use flowsdn_k8s::kinds::{
    AllocationIp, FlowsdnNode, FlowsdnNodeSpec, FlowsdnNodeSpecAddress, FlowsdnNodeSpecIpam,
    FlowsdnNodeStatus, FlowsdnNodeStatusIpam, Kind, OwnerReference,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How long a FlowsdnNode written as wanted is trusted without a read.
pub const RESYNC: Duration = Duration::from_secs(300);

/// The FlowsdnNode the view asks for: none before the Node is known (its
/// UID is the owner reference). `bootid` is the kernel's boot ID.
pub fn desired(view: &View, bootid: &str) -> Option<FlowsdnNode> {
    let node = view
        .nodes
        .iter()
        .find(|n| n.name == view.local_node && !n.uid.is_empty())?;
    let mut object = FlowsdnNode::named(&node.name);
    object.metadata.labels = (!node.labels.is_empty()).then(|| node.labels.clone());
    object.metadata.owner_references = Some(vec![OwnerReference {
        api_version: "v1".into(),
        kind: "Node".into(),
        name: node.name.clone(),
        uid: node.uid.clone(),
        ..OwnerReference::default()
    }]);
    let addresses: Vec<FlowsdnNodeSpecAddress> = node
        .internal_ips
        .iter()
        .map(|ip| FlowsdnNodeSpecAddress {
            ip: Some(ip.to_string()),
            r#type: Some("InternalIP".into()),
        })
        .collect();
    let cidrs: Vec<String> = node_cidrs(node, view.derive)
        .iter()
        .map(|(ip, prefix)| crate::kubernetes::cidr_text(*ip, *prefix))
        .collect();
    object.spec = FlowsdnNodeSpec {
        addresses: (!addresses.is_empty()).then_some(addresses),
        bootid: (!bootid.is_empty()).then(|| bootid.to_owned()),
        ipam: (!cidrs.is_empty()).then(|| FlowsdnNodeSpecIpam {
            pod_cidrs: Some(cidrs),
            ..FlowsdnNodeSpecIpam::default()
        }),
        ..FlowsdnNodeSpec::default()
    };
    let mut used = BTreeMap::new();
    for endpoint in &view.endpoints {
        for cidr in endpoint
            .value
            .pointer(&format!(
                "/{}/ip_addresses",
                crate::tagging::DEFAULT_NETWORK
            ))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let ip = cidr.split_once('/').map_or(cidr, |(ip, _)| ip);
            used.insert(
                ip.to_owned(),
                AllocationIp {
                    owner: Some(format!("{}/{}", endpoint.namespace, endpoint.name)),
                    resource: None,
                },
            );
        }
    }
    object.status = Some(FlowsdnNodeStatus {
        ipam: Some(FlowsdnNodeStatusIpam {
            used: Some(used),
            ..FlowsdnNodeStatusIpam::default()
        }),
        ..FlowsdnNodeStatus::default()
    });
    Some(object)
}

/// The kernel's boot ID, empty when unreadable.
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|t| t.trim().to_owned())
        .unwrap_or_default()
}

/// The writer's memory between passes.
#[derive(Default)]
pub struct NodeWriter {
    written: Option<(Value, Instant)>,
    unserved: Option<Instant>,
}

/// One pass: Ok(true) when the kind is served, Ok(false) when not, Err for a
/// refused or failed write.
pub type Result = std::result::Result<bool, String>;

fn refused(status: u16, body: &Value) -> String {
    format!(
        "HTTP {status} {}",
        body.get("message").and_then(Value::as_str).unwrap_or("")
    )
}

/// The parts the writer owns: metadata labels and owner references, spec.
fn owned(object: &Value) -> Value {
    json!({
        "labels": object.pointer("/metadata/labels"),
        "ownerReferences": object.pointer("/metadata/ownerReferences"),
        "spec": object.get("spec"),
    })
}

impl NodeWriter {
    pub fn sync(&mut self, desired: Option<&FlowsdnNode>, send: &mut Send<'_>) -> Result {
        let Some(desired) = desired else {
            return Ok(true);
        };
        let want = serde_json::to_value(desired).map_err(|e| e.to_string())?;
        if self
            .written
            .as_ref()
            .is_some_and(|(last, at)| *last == want && at.elapsed() < RESYNC)
        {
            return Ok(true);
        }
        if self.unserved.is_some_and(|at| at.elapsed() < UNSERVED_RETRY) {
            return Ok(false);
        }
        self.unserved = None;
        let name = desired.metadata.name.clone().unwrap_or_default();
        let path = FlowsdnNode::path("", &name);
        let (code, mut current) = send(http::Method::GET, &path, None)?;
        match code {
            200..=299 => {}
            404 => {
                let mut create = want.clone();
                if let Some(object) = create.as_object_mut() {
                    object.remove("status");
                }
                let collection = FlowsdnNode::collection("");
                match send(http::Method::POST, &collection, Some(&create))? {
                    (200..=299, created) => current = created,
                    (404, _) => {
                        self.unserved = Some(Instant::now());
                        return Ok(false);
                    }
                    // Created by another writer meanwhile: next pass.
                    (409, _) => return Ok(true),
                    (code, body) => return Err(refused(code, &body)),
                }
            }
            code => return Err(refused(code, &current)),
        }
        if owned(&current) != owned(&want) {
            let mut replace = want.clone();
            if let (Some(object), Some(version)) = (
                replace.pointer_mut("/metadata").and_then(Value::as_object_mut),
                current.pointer("/metadata/resourceVersion").cloned(),
            ) {
                object.insert("resourceVersion".into(), version);
            }
            if let Some(object) = replace.as_object_mut() {
                // The status is written through its subresource below.
                match current.get("status") {
                    Some(status) => object.insert("status".into(), status.clone()),
                    None => object.remove("status"),
                };
            }
            match send(http::Method::PUT, &path, Some(&replace))? {
                (200..=299, replaced) => current = replaced,
                // Changed meanwhile: read again next pass.
                (409, _) => return Ok(true),
                (code, body) => return Err(refused(code, &body)),
            }
        }
        if current.get("status") != want.get("status") {
            let mut update = current.clone();
            if let Some(object) = update.as_object_mut() {
                object.insert(
                    "status".into(),
                    want.get("status").cloned().unwrap_or(Value::Null),
                );
            }
            match send(http::Method::PUT, &format!("{path}/status"), Some(&update))? {
                (200..=299, _) => {}
                (409, _) => return Ok(true),
                (code, body) => return Err(refused(code, &body)),
            }
        }
        self.written = Some((want, Instant::now()));
        Ok(true)
    }
}

#[cfg(test)]
#[path = "node_crd_tests.rs"]
mod tests;
