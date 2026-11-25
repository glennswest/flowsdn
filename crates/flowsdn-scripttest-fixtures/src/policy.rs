//! The policy area (#518, spec 17 §3.3.10): `identity/allocate`,
//! `endpoint/create` and `policy/import` over flowsdn's own code.
//!
//! - `identity/allocate <labels>`: a `reserved:` set is its reserved number
//!   (`reserved:host` wins, as the host identity carries other reserved
//!   labels); any other set goes through the agent's CRD-mode allocator
//!   ([`flowsdn_agent::identity::Allocator`]) against an in-memory identity
//!   list, whose creates are applied here.
//! - `endpoint/create <identity> <labels>`: an endpoint with the next ID.
//! - `policy/import <file>`: each document as the agent's FlowsdnNetworkPolicy
//!   watch parses it ([`flowsdn_k8s::watch::Scope::PodPolicies`]). The
//!   harvested scripts import `cilium.io/v2` CiliumNetworkPolicies, which
//!   flowsdn refuses by kind (ADR-0017, ADR-0020): their divergence.
use crate::fixture::lock;
use flowsdn_agent::identity::{self, Action, Allocator, Object};
use flowsdn_identity::{
    labels::{Label, Labels},
    numeric::ReservedIdentity,
};
use flowsdn_k8s::watch::Scope;
use flowsdn_scripttest::{CommandError, Control, Engine, State};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}

/// The policy fixture's state.
#[derive(Debug, Default)]
pub struct Policies {
    allocator: Allocator,
    identities: Vec<Object>,
    /// Endpoint ID -> (identity, labels).
    endpoints: BTreeMap<u16, (u32, String)>,
    imported: Vec<serde_json::Value>,
}

/// `k8s:app=test,reserved:host` as a label set.
fn label_set(text: &str) -> Result<Labels, String> {
    let mut labels = Labels::new();
    for part in text.split(',').filter(|p| !p.is_empty()) {
        labels.insert(Label::parse(part).map_err(|e| format!("{part}: {e}"))?);
    }
    if labels.is_empty() {
        return Err("no labels".into());
    }
    Ok(labels)
}

impl Policies {
    /// The numeric identity of `labels`.
    pub fn allocate(&mut self, labels: &Labels) -> Result<u32, String> {
        let reserved: Vec<&str> = labels
            .iter()
            .filter(|l| l.source() == "reserved")
            .map(Label::key)
            .collect();
        if !reserved.is_empty() {
            if reserved.len() != labels.len() {
                return Err("reserved and other labels in one set".into());
            }
            let name = if reserved.contains(&"host") {
                "host"
            } else if let [only] = reserved.as_slice() {
                only
            } else {
                return Err(format!("no reserved identity for {}", reserved.join(",")));
            };
            return ReservedIdentity::from_name(name)
                .map(|r| r.numeric().get())
                .ok_or_else(|| format!("unknown reserved identity {name}"));
        }
        let key = labels.canonical_key();
        let desired = BTreeMap::from([(key.clone(), labels.clone())]);
        // Creates are answered at once here, so two passes settle.
        for _ in 0..2 {
            let actions = self.allocator.reconcile(
                &desired,
                &self.identities,
                "default",
                identity::MIN_ID,
            );
            for action in actions {
                if let Action::Create { id, labels } = action {
                    let security: BTreeMap<String, String> = labels
                        .iter()
                        .map(|l| (format!("{}:{}", l.source(), l.key()), l.value().to_owned()))
                        .collect();
                    self.identities
                        .push(Object::new(id, &security, "", false, "1"));
                }
            }
        }
        identity::oldest(&self.identities)
            .get(&key)
            .map(|o| o.id)
            .ok_or_else(|| "the allocator gave no identity".into())
    }
}

fn publish(state: &mut State, text: String) -> Result<Control, CommandError> {
    state.publish(text, "");
    Ok(Control::Continue)
}

/// Register the policy area's commands on `engine`.
pub fn register(engine: &mut Engine, policies: &Arc<Mutex<Policies>>) -> Result<(), String> {
    let p = Arc::clone(policies);
    engine.register_command("identity/allocate", false, move |state: &mut State, args: &[String]| {
        let [labels] = args else {
            return Err(fail("identity/allocate takes one label set"));
        };
        let labels = label_set(labels).map_err(fail)?;
        let id = lock(&p).allocate(&labels).map_err(fail)?;
        publish(state, format!("{id}\n"))
    })?;
    let p = Arc::clone(policies);
    engine.register_command("endpoint/create", false, move |state: &mut State, args: &[String]| {
        let [identity, labels] = args else {
            return Err(fail("endpoint/create takes an identity and a label set"));
        };
        let identity: u32 = identity
            .parse()
            .map_err(|_| fail(format!("identity {identity:?} is not a number")))?;
        label_set(labels).map_err(fail)?;
        let mut policies = lock(&p);
        let id = policies
            .endpoints
            .keys()
            .next_back()
            .map_or(Some(1), |last| last.checked_add(1))
            .ok_or_else(|| fail("endpoint IDs exhausted"))?;
        policies.endpoints.insert(id, (identity, labels.clone()));
        drop(policies);
        publish(state, format!("{id}\n"))
    })?;
    let p = Arc::clone(policies);
    engine.register_command("policy/import", false, move |state: &mut State, args: &[String]| {
        let [file] = args else {
            return Err(fail("policy/import takes a file"));
        };
        let text = state.read_text(file)?;
        let documents = flowsdn_k8s::crd::yaml_documents(&text)
            .map_err(|e| fail(format!("{file}: {e}")))?;
        for document in documents.into_iter().filter(|d| !d.is_null()) {
            Scope::PodPolicies
                .parse(&document)
                .map_err(|e| fail(format!("{file}: {e} (flowsdn reads FlowsdnNetworkPolicy)")))?;
            lock(&p).imported.push(document);
        }
        Ok(Control::Continue)
    })?;
    Ok(())
}
