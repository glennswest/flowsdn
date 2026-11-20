//! The FlowsdnEndpoint writer (#332, spec 13 §3.9): one `flowsdn.io`
//! FlowsdnEndpoint per local Pod endpoint, in the Pod's namespace and named
//! after it, owned by the Pod (`controller: true`, so Kubernetes deletes it
//! with the Pod if the agent does not).
//!
//! [`desired`] is what the view says each object holds: the endpoint ID,
//! state, service account, identity and its labels, the node's address and
//! the endpoint's addresses, named ports, the runtime identifiers (sandbox,
//! CNI attachment, Pod name), and whether policy is enforced in each
//! direction. The Pod's workload and containers (#328) have no field in the
//! schema; they stay in `GET /v1/endpoint` and the Pod's annotation.
//!
//! [`Writer::sync`] brings the API server to it: create (`POST`); on a 409
//! read the object and adopt it when it is owned by the same Pod, else
//! delete it (UID precondition) and create again; update the status with a
//! JSON patch whose first op tests the object's UID; delete (UID
//! precondition) when the endpoint goes. A 404 on a create means the kind is
//! not served (its CRD is not applied, stormcos#303): nothing is retried for
//! a minute and it is not an error. A write the server refuses is a Warning
//! Event on the Pod (`FlowsdnEndpointFailed`).
use crate::kubernetes::{LocalEndpoint, PodInfo, View};
use flowsdn_k8s::kinds::{
    AddressPair, FlowsdnEndpoint, FlowsdnEndpointStatus, FlowsdnEndpointStatusExternalIdentifiers,
    FlowsdnEndpointStatusIdentity, FlowsdnEndpointStatusNetworking, FlowsdnEndpointStatusPolicy,
    FlowsdnEndpointStatusPolicyDirection, Kind, NamedPort, OwnerReference,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How long a create that found the kind unserved waits before the next try.
pub const UNSERVED_RETRY: Duration = Duration::from_secs(60);

/// (namespace, name) of a Pod.
pub type Key = (String, String);

/// One FlowsdnEndpoint as it should be: the Pod's UID and the object.
#[derive(Clone, Debug, PartialEq)]
pub struct Desired {
    pub pod_uid: String,
    pub object: FlowsdnEndpoint,
}

/// The FlowsdnEndpoints the view asks for: none before the Pod list and the
/// endpoints are known. With two endpoints for one Pod (a sandbox being
/// replaced) the newest ID wins, as for the annotations.
pub fn desired(view: &View) -> BTreeMap<Key, Desired> {
    let mut out = BTreeMap::new();
    if !(view.pods_synced && view.endpoints_published) {
        return out;
    }
    let mut newest: BTreeMap<Key, &LocalEndpoint> = BTreeMap::new();
    for endpoint in &view.endpoints {
        let key = (endpoint.namespace.clone(), endpoint.name.clone());
        let entry = newest.entry(key).or_insert(endpoint);
        if endpoint.id > entry.id {
            *entry = endpoint;
        }
    }
    for (key, endpoint) in newest {
        let Some(pod) = view.local_pod(&endpoint.namespace, &endpoint.name, &endpoint.uid) else {
            continue;
        };
        if pod.host_network || pod.uid.is_empty() || !object_name(&pod.name) {
            continue;
        }
        out.insert(
            key,
            Desired {
                pod_uid: pod.uid.clone(),
                object: object(view, endpoint, pod),
            },
        );
    }
    out
}

/// A Pod name is a DNS subdomain, so it is a valid object name too; refuse
/// anything else rather than send it.
fn object_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn protocol_name(protocol: u8) -> Option<&'static str> {
    match protocol {
        6 => Some("TCP"),
        17 => Some("UDP"),
        132 => Some("SCTP"),
        _ => None,
    }
}

/// The policy state of one direction from the policy thread's status.
fn direction(enforcing: bool) -> FlowsdnEndpointStatusPolicyDirection {
    FlowsdnEndpointStatusPolicyDirection {
        enforcing,
        state: Some(
            if enforcing {
                "enforcing"
            } else {
                "non-enforcing"
            }
            .into(),
        ),
        ..FlowsdnEndpointStatusPolicyDirection::default()
    }
}

/// The object for `endpoint` of `pod`.
pub fn object(view: &View, endpoint: &LocalEndpoint, pod: &PodInfo) -> FlowsdnEndpoint {
    let network = endpoint.value.get(crate::tagging::DEFAULT_NETWORK);
    let field = |key: &str| {
        network
            .and_then(|n| n.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let mut pair = AddressPair::default();
    for cidr in network
        .and_then(|n| n.get("ip_addresses"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let address = cidr.split_once('/').map_or(cidr, |(ip, _)| ip);
        let slot = if address.contains(':') {
            &mut pair.ipv6
        } else {
            &mut pair.ipv4
        };
        if slot.is_none() {
            *slot = Some(address.to_owned());
        }
    }
    let node_ip = view
        .nodes
        .iter()
        .find(|n| n.name == view.local_node)
        .and_then(|n| n.internal_ips.first())
        .map(ToString::to_string);
    let sandbox = field("sandbox");
    let interface = field("interface");
    let identity =
        view.pod_identity(&pod.namespace, &pod.name)
            .map(|id| FlowsdnEndpointStatusIdentity {
                id: Some(i64::from(id)),
                labels: view.identities.get(&id).cloned(),
            });
    let (ingress, egress) = view
        .policy_status
        .get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| e.get("id").and_then(Value::as_u64) == Some(u64::from(endpoint.id)))
        .map_or((false, false), |e| {
            let flag = |key: &str| e.get(key).and_then(Value::as_bool).unwrap_or(false);
            (flag("ingress-enforced"), flag("egress-enforced"))
        });
    let named_ports: Vec<NamedPort> = pod
        .named_ports
        .iter()
        .filter_map(|(protocol, name, port)| {
            Some(NamedPort {
                name: Some(name.clone()),
                port: Some(i64::from(*port)),
                protocol: Some(protocol_name(*protocol)?.into()),
            })
        })
        .collect();
    let state = if view.identity && identity.is_none() {
        "waiting-for-identity"
    } else {
        "ready"
    };
    let status = FlowsdnEndpointStatus {
        id: Some(i64::from(endpoint.id)),
        state: Some(state.into()),
        service_account: (!pod.service_account.is_empty()).then(|| pod.service_account.clone()),
        identity,
        networking: Some(FlowsdnEndpointStatusNetworking {
            addressing: vec![pair],
            node: node_ip,
        }),
        named_ports: (!named_ports.is_empty()).then_some(named_ports),
        external_identifiers: Some(FlowsdnEndpointStatusExternalIdentifiers {
            container_id: (!sandbox.is_empty()).then(|| sandbox.clone()),
            cni_attachment_id: (!sandbox.is_empty() && !interface.is_empty())
                .then(|| format!("{sandbox}:{interface}")),
            k8s_namespace: Some(pod.namespace.clone()),
            k8s_pod_name: Some(pod.name.clone()),
            pod_name: Some(format!("{}/{}", pod.namespace, pod.name)),
            ..FlowsdnEndpointStatusExternalIdentifiers::default()
        }),
        policy: Some(FlowsdnEndpointStatusPolicy {
            ingress: Some(direction(ingress)),
            egress: Some(direction(egress)),
        }),
        ..FlowsdnEndpointStatus::default()
    };
    let mut object = FlowsdnEndpoint::named(&pod.name);
    object.metadata.namespace = Some(pod.namespace.clone());
    object.metadata.owner_references = Some(vec![OwnerReference {
        api_version: "v1".into(),
        kind: "Pod".into(),
        name: pod.name.clone(),
        uid: pod.uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }]);
    object.status = Some(status);
    object
}

/// One request: method, path, body. Returns the HTTP status and the body.
pub type Send<'a> =
    dyn FnMut(http::Method, &str, Option<&Value>) -> Result<(u16, Value), String> + 'a;

/// What the writer last wrote for a Pod: the object's UID and its status.
#[derive(Clone, Debug, PartialEq)]
struct Written {
    uid: String,
    pod_uid: String,
    status: Value,
}

/// The writer's memory between passes.
#[derive(Default)]
pub struct Writer {
    written: BTreeMap<Key, Written>,
    /// When a create last found the kind unserved.
    unserved: Option<Instant>,
}

/// One pass's result: failures (Pod key, text) and whether the kind is served.
#[derive(Debug, Default, PartialEq)]
pub struct Outcome {
    pub failures: Vec<(Key, String)>,
    pub unserved: bool,
}

fn message(status: u16, body: &Value) -> String {
    format!(
        "HTTP {status} {}",
        body.get("message").and_then(Value::as_str).unwrap_or("")
    )
}

fn uid_of(body: &Value) -> String {
    body.pointer("/metadata/uid")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn owner_uid(body: &Value) -> String {
    body.pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|r| r.get("controller") == Some(&Value::Bool(true)))
        .and_then(|r| r.get("uid"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

impl Writer {
    /// The Pods whose FlowsdnEndpoint this writer holds.
    pub fn held(&self) -> usize {
        self.written.len()
    }

    /// Bring the API server to `desired`.
    pub fn sync(&mut self, desired: &BTreeMap<Key, Desired>, send: &mut Send<'_>) -> Outcome {
        let mut outcome = Outcome::default();
        let gone: Vec<Key> = self
            .written
            .iter()
            .filter(|(k, w)| desired.get(*k).is_none_or(|d| d.pod_uid != w.pod_uid))
            .map(|(k, _)| k.clone())
            .collect();
        for key in gone {
            if let Some(written) = self.written.remove(&key) {
                let body = json!({"preconditions": {"uid": written.uid}});
                match send(
                    http::Method::DELETE,
                    &FlowsdnEndpoint::path(&key.0, &key.1),
                    Some(&body),
                ) {
                    Ok((200..=299 | 404 | 409, _)) => {}
                    Ok((status, body)) => outcome.failures.push((key, message(status, &body))),
                    Err(error) => outcome.failures.push((key, error)),
                }
            }
        }
        if self
            .unserved
            .is_some_and(|at| at.elapsed() < UNSERVED_RETRY)
        {
            outcome.unserved = true;
            return outcome;
        }
        self.unserved = None;
        for (key, want) in desired {
            let status = serde_json::to_value(&want.object.status).unwrap_or(Value::Null);
            let result = match self.written.get(key) {
                Some(written) if written.status == status => continue,
                Some(written) => {
                    self.update(key, written.uid.clone(), &want.pod_uid, &status, send)
                }
                None => self.create(key, want, &status, send),
            };
            match result {
                Ok(()) => {}
                Err(Failure::Unserved) => {
                    self.unserved = Some(Instant::now());
                    outcome.unserved = true;
                    return outcome;
                }
                Err(Failure::Text(text)) => outcome.failures.push((key.clone(), text)),
            }
        }
        outcome
    }

    fn create(
        &mut self,
        key: &Key,
        want: &Desired,
        status: &Value,
        send: &mut Send<'_>,
    ) -> Result<(), Failure> {
        let body = serde_json::to_value(&want.object).map_err(|e| Failure::Text(e.to_string()))?;
        let collection = FlowsdnEndpoint::collection(&key.0);
        match send(http::Method::POST, &collection, Some(&body)).map_err(Failure::Text)? {
            (200..=299, created) => {
                self.remember(key, uid_of(&created), &want.pod_uid, status.clone());
                Ok(())
            }
            (404, _) => Err(Failure::Unserved),
            (409, _) => self.adopt(key, want, status, send),
            (status, body) => Err(Failure::Text(message(status, &body))),
        }
    }

    /// An object of that name exists: keep it when the same Pod owns it
    /// (an agent restart), else replace it (an older Pod of the same name).
    fn adopt(
        &mut self,
        key: &Key,
        want: &Desired,
        status: &Value,
        send: &mut Send<'_>,
    ) -> Result<(), Failure> {
        let path = FlowsdnEndpoint::path(&key.0, &key.1);
        let (code, existing) = send(http::Method::GET, &path, None).map_err(Failure::Text)?;
        if !(200..=299).contains(&code) {
            // Gone meanwhile, or unreadable: the next pass creates it again.
            return if code == 404 {
                Ok(())
            } else {
                Err(Failure::Text(message(code, &existing)))
            };
        }
        let uid = uid_of(&existing);
        if owner_uid(&existing) == want.pod_uid {
            let current = existing.get("status").cloned().unwrap_or(Value::Null);
            self.remember(key, uid.clone(), &want.pod_uid, current.clone());
            if current != *status {
                return self.update(key, uid, &want.pod_uid, status, send);
            }
            return Ok(());
        }
        let body = json!({"preconditions": {"uid": uid}});
        match send(http::Method::DELETE, &path, Some(&body)).map_err(Failure::Text)? {
            // Created again on the next pass.
            (200..=299 | 404 | 409, _) => Ok(()),
            (code, body) => Err(Failure::Text(message(code, &body))),
        }
    }

    fn update(
        &mut self,
        key: &Key,
        uid: String,
        pod_uid: &str,
        status: &Value,
        send: &mut Send<'_>,
    ) -> Result<(), Failure> {
        let patch = json!([
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "replace", "path": "/status", "value": status},
        ]);
        let path = FlowsdnEndpoint::path(&key.0, &key.1);
        match send(http::Method::PATCH, &path, Some(&patch)).map_err(Failure::Text)? {
            (200..=299, _) => {
                self.remember(key, uid, pod_uid, status.clone());
                Ok(())
            }
            // Recreated under another UID, or gone: start over next pass.
            (404 | 409 | 422, _) => {
                self.written.remove(key);
                Ok(())
            }
            (code, body) => Err(Failure::Text(message(code, &body))),
        }
    }

    fn remember(&mut self, key: &Key, uid: String, pod_uid: &str, status: Value) {
        self.written.insert(
            key.clone(),
            Written {
                uid,
                pod_uid: pod_uid.to_owned(),
                status,
            },
        );
    }
}

enum Failure {
    Unserved,
    Text(String),
}

#[cfg(test)]
#[path = "endpoint_crd_tests.rs"]
mod tests;
