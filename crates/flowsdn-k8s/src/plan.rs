//! Declarative plans; callers still need discovery, admission and controllers.
use crate::{Error, SCHEMA_VERSION, SCHEMA_VERSION_LABEL};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const REGISTRATION_PLURALS: [&str; 22] = [
    "ciliumnetworkpolicies",
    "ciliumclusterwidenetworkpolicies",
    "ciliumcidrgroups",
    "ciliumendpoints",
    "ciliumendpointslices",
    "ciliumidentities",
    "ciliumnodes",
    "ciliumnodeconfigs",
    "ciliumlocalredirectpolicies",
    "ciliumegressgatewaypolicies",
    "ciliumenvoyconfigs",
    "ciliumclusterwideenvoyconfigs",
    "ciliumloadbalancerippools",
    "ciliuml2announcementpolicies",
    "ciliumpodippools",
    "ciliumbgpclusterconfigs",
    "ciliumbgppeerconfigs",
    "ciliumbgpadvertisements",
    "ciliumbgpnodeconfigs",
    "ciliumbgpnodeconfigoverrides",
    "ciliumgatewayclassconfigs",
    "ciliumdatapathplugins",
];
pub const DUAL_VERSION_PLURALS: [&str; 7] = [
    "ciliumcidrgroups",
    "ciliumloadbalancerippools",
    "ciliumbgpclusterconfigs",
    "ciliumbgppeerconfigs",
    "ciliumbgpadvertisements",
    "ciliumbgpnodeconfigs",
    "ciliumbgpnodeconfigoverrides",
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListScope {
    AllNamespaces,
}
/// GatewayClass parametersRef supplies an explicit namespace, which need not be
/// the installation namespace. Node configuration also selects across namespaces.
pub fn operator_config_scope(plural: &str) -> Result<ListScope, Error> {
    match plural {
        "ciliumnodeconfigs" | "ciliumgatewayclassconfigs" => Ok(ListScope::AllNamespaces),
        _ => Err(Error(
            "resource is not an operator namespaced configuration resource".into(),
        )),
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EndpointOptions {
    pub enable_ces: bool,
    pub slim: bool,
    pub disable_endpoint_crd: bool,
    pub operator_managed_identities: bool,
    pub mixed_reference_agents: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointPlan {
    pub write_cep: bool,
    pub watch_ces: bool,
    pub slim: bool,
}
impl EndpointOptions {
    pub fn plan(self) -> Result<EndpointPlan, Error> {
        if self.slim
            && (!self.enable_ces
                || !self.disable_endpoint_crd
                || !self.operator_managed_identities
                || self.mixed_reference_agents)
        {
            return Err(Error("slim CES requires CES, disabled CEP, operator identities and no mixed reference agents".into()));
        }
        if !self.slim && self.disable_endpoint_crd {
            return Err(Error(
                "CEP must remain enabled outside slim CES mode".into(),
            ));
        }
        Ok(EndpointPlan {
            write_cep: !self.disable_endpoint_crd,
            watch_ces: self.enable_ces,
            slim: self.slim,
        })
    }
}
/// Build the registration projection from an already verified vendored document.
/// This validates registration invariants, not the OpenAPI schema or its hash.
pub fn registration_payload(document: &Value) -> Result<Value, Error> {
    let spec = document
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| Error("missing CRD spec".into()))?;
    if spec.get("group").and_then(Value::as_str) != Some("cilium.io") {
        return Err(Error("unexpected CRD group".into()));
    }
    let names = spec
        .get("names")
        .and_then(Value::as_object)
        .ok_or_else(|| Error("missing CRD names".into()))?;
    let plural = names
        .get("plural")
        .and_then(Value::as_str)
        .ok_or_else(|| Error("missing plural".into()))?;
    if !REGISTRATION_PLURALS.contains(&plural) {
        return Err(Error("unknown CRD plural".into()));
    }
    let scope = spec
        .get("scope")
        .and_then(Value::as_str)
        .filter(|s| matches!(*s, "Namespaced" | "Cluster"))
        .ok_or_else(|| Error("invalid scope".into()))?;
    let versions = spec
        .get("versions")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error("missing versions".into()))?;
    let mut seen = BTreeSet::new();
    let mut storage = None;
    for version in versions {
        let name = version
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error("missing version name".into()))?;
        if !seen.insert(name) {
            return Err(Error("duplicate version".into()));
        }
        let served = version
            .get("served")
            .and_then(Value::as_bool)
            .ok_or_else(|| Error("missing served flag".into()))?;
        let stores = version
            .get("storage")
            .and_then(Value::as_bool)
            .ok_or_else(|| Error("missing storage flag".into()))?;
        if stores && (!served || storage.replace(name).is_some()) {
            return Err(Error("exactly one served storage version required".into()));
        }
    }
    if storage.is_none() {
        return Err(Error("missing storage version".into()));
    }
    if DUAL_VERSION_PLURALS.contains(&plural)
        && (storage != Some("v2")
            || versions.len() != 2
            || !versions.iter().any(|v| {
                v.get("name").and_then(Value::as_str) == Some("v2alpha1")
                    && v.get("served") == Some(&json!(true))
                    && v.get("deprecated") == Some(&json!(true))
            }))
    {
        return Err(Error(
            "graduated CRDs must retain deprecated served v2alpha1 and storage v2".into(),
        ));
    }
    let mut projected_names = serde_json::Map::new();
    for field in ["kind", "plural", "singular", "shortNames", "categories"] {
        if let Some(value) = names.get(field) {
            projected_names.insert(field.into(), value.clone());
        }
    }
    for required in ["kind", "plural", "singular"] {
        if projected_names
            .get(required)
            .and_then(Value::as_str)
            .is_none_or(|v| v.is_empty())
        {
            return Err(Error(format!("missing name {required}")));
        }
    }
    let mut projected_spec = json!({"group":"cilium.io", "names":projected_names, "scope":scope, "versions":versions, "preserveUnknownFields":false});
    if let Some(conversion) = spec.get("conversion") {
        if conversion.get("strategy").and_then(Value::as_str) != Some("None") {
            return Err(Error("conversion must be absent or None".into()));
        }
        projected_spec
            .as_object_mut()
            .ok_or_else(|| Error("invalid projected spec".into()))?
            .insert("conversion".into(), conversion.clone());
    }
    Ok(
        json!({"apiVersion":"apiextensions.k8s.io/v1", "kind":"CustomResourceDefinition", "metadata":{"name":format!("{plural}.cilium.io"), "labels":{SCHEMA_VERSION_LABEL:SCHEMA_VERSION}}, "spec":projected_spec}),
    )
}
