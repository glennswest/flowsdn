//! Pod and container identity for flow and drop records (#328, spec 11): the
//! Hubble flow `Endpoint` (`ID`, `identity`, `namespace`, `labels`,
//! `pod_name`, `workloads`) plus the sandbox and node, the workload derived
//! from a Pod's owner, and the one-line `ns/pod (container) → ns/pod:port`
//! form. The observer looks peers up by IP in the agent's endpoint and IP
//! cache views; nothing here reads the kernel.
use serde_json::{Map, Value, json};
use std::net::IpAddr;

/// A Pod's controlling workload (`kind` as Kubernetes spells it).
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Workload {
    pub kind: String,
    pub name: String,
}

/// The workload of a Pod from its controller owner, as the reference derives
/// it: a ReplicaSet named `<deployment>-<pod-template-hash>` whose Pod carries
/// that `pod-template-hash` label belongs to the Deployment; any other
/// controller is the workload itself. No controller owner means none.
pub fn workload<'a>(
    owners: impl IntoIterator<Item = (&'a str, &'a str, bool)>,
    pod_template_hash: Option<&str>,
) -> Option<Workload> {
    let (kind, name, _) = owners.into_iter().find(|(_, _, controller)| *controller)?;
    if kind == "ReplicaSet"
        && let Some(hash) = pod_template_hash.filter(|hash| !hash.is_empty())
        && let Some(deployment) = name
            .strip_suffix(hash)
            .and_then(|rest| rest.strip_suffix('-'))
            .filter(|rest| !rest.is_empty())
    {
        return Some(Workload {
            kind: "Deployment".into(),
            name: deployment.into(),
        });
    }
    Some(Workload {
        kind: kind.into(),
        name: name.into(),
    })
}

/// One side of a flow: what flowsdn knows about the address.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EndpointInfo {
    /// The local endpoint ID (0 for a remote Pod or a non-endpoint).
    pub id: u16,
    /// The security identity; None until identity allocation exists.
    pub identity: Option<u32>,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    /// The sandbox (CNI `CNI_CONTAINERID`); empty for remote Pods.
    pub container_id: String,
    pub node: String,
    pub labels: Vec<String>,
    pub workloads: Vec<Workload>,
}
impl EndpointInfo {
    /// Hubble's flow `Endpoint` in its JSON form, with flowsdn's additions
    /// (`pod_uid`, `container_id`, `node_name`) where known. Empty fields are
    /// left out, as protobuf JSON does.
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        if self.id != 0 {
            object.insert("ID".into(), json!(self.id));
        }
        if let Some(identity) = self.identity {
            object.insert("identity".into(), json!(identity));
        }
        for (key, value) in [
            ("namespace", &self.namespace),
            ("pod_name", &self.pod_name),
            ("pod_uid", &self.pod_uid),
            ("container_id", &self.container_id),
            ("node_name", &self.node),
        ] {
            if !value.is_empty() {
                object.insert(key.into(), json!(value));
            }
        }
        if !self.labels.is_empty() {
            object.insert("labels".into(), json!(self.labels));
        }
        if !self.workloads.is_empty() {
            object.insert(
                "workloads".into(),
                Value::Array(
                    self.workloads
                        .iter()
                        .map(|w| json!({"name":w.name,"kind":w.kind}))
                        .collect(),
                ),
            );
        }
        Value::Object(object)
    }
    /// `ns/pod (container)`: the sandbox ID shortened to 12 characters, as
    /// container runtimes print it; `ns/pod` without one.
    pub fn name(&self) -> Option<String> {
        if self.namespace.is_empty() || self.pod_name.is_empty() {
            return None;
        }
        let pod = format!("{}/{}", self.namespace, self.pod_name);
        let id = self.container_id.rsplit("://").next().unwrap_or_default();
        Some(if id.is_empty() {
            pod
        } else {
            format!("{pod} ({})", id.get(..12).unwrap_or(id))
        })
    }
}

/// Resolves a flow's addresses to endpoints (the agent's endpoint list and
/// IP cache). None means flowsdn knows nothing about the address.
pub trait Resolver {
    fn endpoint(&self, address: IpAddr) -> Option<EndpointInfo>;
}

/// `ns/pod (container) → ns/pod:port`; an unknown side is its bare address.
/// `port` 0 (no L4 port) is left out.
pub fn describe(
    resolver: &impl Resolver,
    source: IpAddr,
    destination: IpAddr,
    port: u16,
) -> String {
    // Only the destination carries the port, so only it needs IPv6 brackets.
    let side = |address: IpAddr, bracket: bool| {
        resolver
            .endpoint(address)
            .and_then(|e| e.name())
            .unwrap_or_else(|| match address {
                IpAddr::V6(_) if bracket => format!("[{address}]"),
                _ => address.to_string(),
            })
    };
    let source = side(source, false);
    if port == 0 {
        format!("{source} → {}", side(destination, false))
    } else {
        format!("{source} → {}:{port}", side(destination, true))
    }
}
