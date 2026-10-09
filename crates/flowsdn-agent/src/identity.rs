//! Cluster identity allocation (spec 03 §3.2–§3.3, CRD mode) over
//! `flowsdn.io/v1alpha1` FlowsdnIdentity objects, with flowsdn's label keys
//! (ADR-0020). Pure data: the controller feeds the identity list and the
//! local Pods' label sets, carries out the returned writes and reports how
//! each one ended. Deleting unused identities is the operator's GC (#332);
//! an agent never deletes one.
use flowsdn_identity::{
    filter::LabelFilter,
    labels::{Label, Labels},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE: &str = "k8s";
pub const POD_NAMESPACE: &str = "io.kubernetes.pod.namespace";
/// Every label key flowsdn adds to a Pod's identity starts with this; Pod
/// labels that do are dropped, so a Pod cannot claim another's identity.
pub const AGENT_PREFIX: &str = "io.flowsdn.k8s";
pub const NAMESPACE_LABELS: &str = "io.flowsdn.k8s.namespace.labels";
pub const SERVICE_ACCOUNT: &str = "io.flowsdn.k8s.policy.serviceaccount";
pub const POLICY_CLUSTER: &str = "io.flowsdn.k8s.policy.cluster";
/// Cluster 0's global range with 255 meshed clusters (spec 03 §4.5).
pub const MIN_ID: u32 = 256;
pub const MAX_ID: u32 = 65_535;
pub const API_VERSION: &str = "flowsdn.io/v1alpha1";
pub const KIND: &str = "FlowsdnIdentity";

/// The identity labels of a Pod (spec 03 §3.1, flowsdn keys): its own labels
/// without `io.flowsdn.k8s*` keys, its Namespace's labels under
/// [`NAMESPACE_LABELS`], the namespace, service account and cluster; then
/// only what `filter` retains. A label the label model refuses (an empty
/// key) is left out.
pub fn pod_labels(
    namespace: &str,
    labels: &BTreeMap<String, String>,
    namespace_labels: Option<&BTreeMap<String, String>>,
    service_account: &str,
    cluster: &str,
    filter: &LabelFilter,
) -> Labels {
    let mut set = Labels::new();
    let mut add = |key: &str, value: &str| {
        if let Ok(label) = Label::new(SOURCE, key, value) {
            set.insert(label);
        }
    };
    for (key, value) in labels.iter().filter(|(k, _)| !k.starts_with(AGENT_PREFIX)) {
        add(key, value);
    }
    for (key, value) in namespace_labels.into_iter().flatten() {
        add(&format!("{NAMESPACE_LABELS}.{key}"), value);
    }
    add(POD_NAMESPACE, namespace);
    if !service_account.is_empty() {
        add(SERVICE_ACCOUNT, service_account);
    }
    add(POLICY_CLUSTER, cluster);
    filter.partition(&set).0
}

/// `<source>:<key>=<value>` per label, as the API and flows print them.
pub fn label_strings(labels: &Labels) -> Vec<String> {
    labels
        .iter()
        .map(|l| format!("{}:{}={}", l.source(), l.key(), l.value()))
        .collect()
}

/// The well-known identities (spec 03 §4.4, on by default per ADR-0011 #69)
/// a flowsdn cluster can have: the cluster DNS ones. 105 and 113 name the
/// reference's operator, which flowsdn never runs, so they never match.
pub fn well_known(labels: &Labels, cluster: &str) -> Option<u32> {
    let key = labels.canonical_key();
    let dns = |account: &str, extra: &[(&str, &str)], metadata: bool| {
        let mut set = Labels::new();
        let mut pairs = vec![
            ("k8s-app", "kube-dns"),
            (POD_NAMESPACE, "kube-system"),
            (SERVICE_ACCOUNT, account),
            (POLICY_CLUSTER, cluster),
        ];
        pairs.extend_from_slice(extra);
        let namespace_key = format!("{NAMESPACE_LABELS}.kubernetes.io/metadata.name");
        if metadata {
            pairs.push((&namespace_key, "kube-system"));
        }
        for (k, v) in pairs {
            if let Ok(label) = Label::new(SOURCE, k, v) {
                set.insert(label);
            }
        }
        set.canonical_key()
    };
    const EKS: &str = "eks.amazonaws.com/component";
    // Each without and (8 higher) with the namespace metadata label.
    [
        (102, 110, "kube-dns", None),
        (103, 111, "kube-dns", Some("kube-dns")),
        (104, 112, "coredns", None),
        (106, 114, "coredns", Some("coredns")),
    ]
    .into_iter()
    .flat_map(|(id, with_ns, account, eks)| {
        [(id, account, eks, false), (with_ns, account, eks, true)]
    })
    .find_map(|(id, account, eks, metadata)| {
        let extra: Vec<(&str, &str)> = eks.map(|c| (EKS, c)).into_iter().collect();
        (dns(account, &extra, metadata) == key).then_some(id)
    })
}

/// A FlowsdnIdentity as the allocator needs it. `labels` is None when its
/// `security-labels` are not labels (an empty key); such an object only
/// takes its number.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Object {
    pub id: u32,
    pub labels: Option<Labels>,
    pub created: String,
    pub heartbeat: bool,
    pub resource_version: String,
}
impl Object {
    pub fn new(
        id: u32,
        security_labels: &BTreeMap<String, String>,
        created: &str,
        heartbeat: bool,
        resource_version: &str,
    ) -> Self {
        let labels = security_labels
            .iter()
            .map(|(key, value)| {
                let (source, key) = key.split_once(':').unwrap_or(("unspec", key));
                Label::new(source, key, value)
            })
            .collect::<Result<Labels, _>>()
            .ok();
        Self {
            id,
            labels,
            created: created.into(),
            heartbeat,
            resource_version: resource_version.into(),
        }
    }
    fn key(&self) -> Option<String> {
        self.labels.as_ref().map(Labels::canonical_key)
    }
}

/// The identity a label set resolves to among `objects` (spec 03 §3.3 step
/// 3): the oldest object with exactly these labels, ties to the lowest
/// number, so every agent converges on the same one.
pub fn oldest(objects: &[Object]) -> BTreeMap<String, &Object> {
    let mut found: BTreeMap<String, &Object> = BTreeMap::new();
    for object in objects {
        let Some(key) = object.key() else { continue };
        let entry = found.entry(key).or_insert(object);
        if (&object.created, object.id) < (&entry.created, entry.id) {
            *entry = object;
        }
    }
    found
}

/// A write for the controller to send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Create the object (a new number, or one this node holds that was
    /// deleted: spec 03 §3.3 steps 4 and 8).
    Create { id: u32, labels: Labels },
    /// Update the object without the heartbeat annotation (step 3 acquire).
    Acquire {
        id: u32,
        labels: Labels,
        resource_version: String,
    },
}
impl Action {
    pub fn id(&self) -> u32 {
        match self {
            Self::Create { id, .. } | Self::Acquire { id, .. } => *id,
        }
    }
    /// The object path below the collection, and the body.
    pub fn path(&self, collection: &str) -> String {
        match self {
            Self::Create { .. } => collection.into(),
            Self::Acquire { id, .. } => format!("{collection}/{id}"),
        }
    }
    pub fn body(&self) -> Value {
        let (id, labels, version) = match self {
            Self::Create { id, labels } => (id, labels, None),
            Self::Acquire {
                id,
                labels,
                resource_version,
            } => (id, labels, Some(resource_version)),
        };
        let security: Map<String, Value> = labels
            .iter()
            .map(|l| (format!("{}:{}", l.source(), l.key()), json!(l.value())))
            .collect();
        let mut metadata = json!({"name": id.to_string()});
        if let Some(object) = metadata.as_object_mut() {
            // Object labels for `kubectl get -l`: the namespace (spec 03 §4.3).
            if let Some(ns) = labels.get(POD_NAMESPACE).filter(|l| l.source() == SOURCE) {
                object.insert("labels".into(), json!({ POD_NAMESPACE: ns.value() }));
            }
            if let Some(version) = version {
                object.insert("resourceVersion".into(), json!(version));
            }
        }
        json!({"apiVersion":API_VERSION,"kind":KIND,"metadata":metadata,"security-labels":security})
    }
}

/// How a write ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Done,
    /// 409: the number is taken (create) or the object changed (update).
    Conflict,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Held {
    id: u32,
    /// The object exists with these labels (seen, or created by this node).
    verified: bool,
    /// The identity list has shown it: only then does its absence mean it
    /// was deleted (a create this node just made may not be listed yet).
    seen: bool,
}

/// The identities this node holds for its Pods' label sets.
#[derive(Debug, Default)]
pub struct Allocator {
    held: BTreeMap<String, Held>,
}
impl Allocator {
    /// One pass over the label sets of this node's Pods (canonical key ->
    /// labels) against the complete identity list. Never call it before the
    /// list is complete (spec 03 §3.3 step 1). `start` picks where the search
    /// for a free number begins (random, so two nodes rarely race).
    pub fn reconcile(
        &mut self,
        desired: &BTreeMap<String, Labels>,
        objects: &[Object],
        cluster: &str,
        start: u32,
    ) -> Vec<Action> {
        // Release (step 7): no API call; the operator GCs unused objects.
        self.held.retain(|key, _| desired.contains_key(key));
        let by_id: BTreeMap<u32, &Object> = objects.iter().map(|o| (o.id, o)).collect();
        let by_key = oldest(objects);
        let mut actions = Vec::new();
        for (key, labels) in desired {
            if let Some(id) = well_known(labels, cluster) {
                self.held.insert(
                    key.clone(),
                    Held {
                        id,
                        verified: true,
                        seen: true,
                    },
                );
                continue;
            }
            if let Some(held) = self.held.get_mut(key) {
                match by_id.get(&held.id) {
                    Some(object) if object.key().as_ref() == Some(key) => {
                        held.verified = true;
                        held.seen = true;
                        if object.heartbeat {
                            actions.push(acquire(object, labels));
                        }
                        continue;
                    }
                    // The number now carries other labels: look up again.
                    Some(_) => {
                        self.held.remove(key);
                    }
                    // Deleted while held: recreate it (step 8).
                    None if held.seen => {
                        actions.push(Action::Create {
                            id: held.id,
                            labels: labels.clone(),
                        });
                        continue;
                    }
                    // Our create has not been answered or listed yet.
                    None => continue,
                }
            }
            if let Some(object) = by_key.get(key) {
                self.held.insert(
                    key.clone(),
                    Held {
                        id: object.id,
                        verified: true,
                        seen: true,
                    },
                );
                if object.heartbeat {
                    actions.push(acquire(object, labels));
                }
                continue;
            }
            let used: BTreeSet<u32> = by_id
                .keys()
                .copied()
                .chain(self.held.values().map(|h| h.id))
                .collect();
            if let Some(id) = free(&used, start) {
                self.held.insert(
                    key.clone(),
                    Held {
                        id,
                        verified: false,
                        seen: false,
                    },
                );
                actions.push(Action::Create {
                    id,
                    labels: labels.clone(),
                });
            }
        }
        actions
    }
    /// Record how a create ended. A refused new number is dropped, so the
    /// next pass looks up or leases again (step 4/5); a recreate that meets
    /// an existing object is settled by the next pass's comparison.
    pub fn created(&mut self, key: &str, id: u32, outcome: Outcome) {
        let Some(held) = self.held.get_mut(key).filter(|h| h.id == id) else {
            return;
        };
        match outcome {
            Outcome::Done => held.verified = true,
            Outcome::Conflict | Outcome::Failed if !held.verified => {
                self.held.remove(key);
            }
            Outcome::Conflict | Outcome::Failed => {}
        }
    }
    /// The identity held for a label set, once its object is known to exist.
    pub fn get(&self, key: &str) -> Option<u32> {
        self.held.get(key).filter(|h| h.verified).map(|h| h.id)
    }
    /// Label sets waiting for an identity (none, or not yet created).
    pub fn waiting(&self, desired: &BTreeMap<String, Labels>) -> usize {
        desired.keys().filter(|key| self.get(key).is_none()).count()
    }
}

fn acquire(object: &Object, labels: &Labels) -> Action {
    Action::Acquire {
        id: object.id,
        labels: labels.clone(),
        resource_version: object.resource_version.clone(),
    }
}

/// The first number from `start` (wrapped into the range) that no object
/// and no held identity uses; None when the range is full.
pub fn free(used: &BTreeSet<u32>, start: u32) -> Option<u32> {
    let span = MAX_ID.saturating_sub(MIN_ID).saturating_add(1);
    (0..span)
        .filter_map(|offset| {
            MIN_ID.checked_add(start.wrapping_add(offset).checked_rem(span)?)
        })
        .find(|id| !used.contains(id))
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
