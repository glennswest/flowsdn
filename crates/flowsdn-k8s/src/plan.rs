//! Declarative plans; callers still need discovery, admission and controllers.
use crate::{Error, SCHEMA_VERSION, SCHEMA_VERSION_LABEL};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const API_GROUP: &str = "flowsdn.io";
pub const API_VERSION: &str = "v1alpha1";

pub const REGISTRATION_PLURALS: [&str; 22] = [
    "flowsdnnetworkpolicies",
    "flowsdnclusterwidenetworkpolicies",
    "flowsdncidrgroups",
    "flowsdnendpoints",
    "flowsdnendpointslices",
    "flowsdnidentities",
    "flowsdnnodes",
    "flowsdnnodeconfigs",
    "flowsdnlocalredirectpolicies",
    "flowsdnegressgatewaypolicies",
    "flowsdnenvoyconfigs",
    "flowsdnclusterwideenvoyconfigs",
    "flowsdnloadbalancerippools",
    "flowsdnl2announcementpolicies",
    "flowsdnpodippools",
    "flowsdnbgpclusterconfigs",
    "flowsdnbgppeerconfigs",
    "flowsdnbgpadvertisements",
    "flowsdnbgpnodeconfigs",
    "flowsdnbgpnodeconfigoverrides",
    "flowsdngatewayclassconfigs",
    "flowsdndatapathplugins",
];
/// Reference-only version constraint used by explicit migration input.
pub const DUAL_VERSION_PLURALS: [&str; 7] = [
    "ciliumcidrgroups",
    "ciliumloadbalancerippools",
    "ciliumbgpclusterconfigs",
    "ciliumbgppeerconfigs",
    "ciliumbgpadvertisements",
    "ciliumbgpnodeconfigs",
    "ciliumbgpnodeconfigoverrides",
];
// Suffixes, scope and reference storage version. Owned resources always use v1alpha1.
type ResourceIdentity = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);
const RESOURCES: [ResourceIdentity; 22] = [
    (
        "NetworkPolicy",
        "networkpolicy",
        "networkpolicies",
        "Namespaced",
        "v2",
    ),
    (
        "ClusterwideNetworkPolicy",
        "clusterwidenetworkpolicy",
        "clusterwidenetworkpolicies",
        "Cluster",
        "v2",
    ),
    ("CIDRGroup", "cidrgroup", "cidrgroups", "Cluster", "v2"),
    ("Endpoint", "endpoint", "endpoints", "Namespaced", "v2"),
    (
        "EndpointSlice",
        "endpointslice",
        "endpointslices",
        "Cluster",
        "v2alpha1",
    ),
    ("Identity", "identity", "identities", "Cluster", "v2"),
    ("Node", "node", "nodes", "Cluster", "v2"),
    (
        "NodeConfig",
        "nodeconfig",
        "nodeconfigs",
        "Namespaced",
        "v2",
    ),
    (
        "LocalRedirectPolicy",
        "localredirectpolicy",
        "localredirectpolicies",
        "Namespaced",
        "v2",
    ),
    (
        "EgressGatewayPolicy",
        "egressgatewaypolicy",
        "egressgatewaypolicies",
        "Cluster",
        "v2",
    ),
    (
        "EnvoyConfig",
        "envoyconfig",
        "envoyconfigs",
        "Namespaced",
        "v2",
    ),
    (
        "ClusterwideEnvoyConfig",
        "clusterwideenvoyconfig",
        "clusterwideenvoyconfigs",
        "Cluster",
        "v2",
    ),
    (
        "LoadBalancerIPPool",
        "loadbalancerippool",
        "loadbalancerippools",
        "Cluster",
        "v2",
    ),
    (
        "L2AnnouncementPolicy",
        "l2announcementpolicy",
        "l2announcementpolicies",
        "Cluster",
        "v2alpha1",
    ),
    (
        "PodIPPool",
        "podippool",
        "podippools",
        "Cluster",
        "v2alpha1",
    ),
    (
        "BGPClusterConfig",
        "bgpclusterconfig",
        "bgpclusterconfigs",
        "Cluster",
        "v2",
    ),
    (
        "BGPPeerConfig",
        "bgppeerconfig",
        "bgppeerconfigs",
        "Cluster",
        "v2",
    ),
    (
        "BGPAdvertisement",
        "bgpadvertisement",
        "bgpadvertisements",
        "Cluster",
        "v2",
    ),
    (
        "BGPNodeConfig",
        "bgpnodeconfig",
        "bgpnodeconfigs",
        "Cluster",
        "v2",
    ),
    (
        "BGPNodeConfigOverride",
        "bgpnodeconfigoverride",
        "bgpnodeconfigoverrides",
        "Cluster",
        "v2",
    ),
    (
        "GatewayClassConfig",
        "gatewayclassconfig",
        "gatewayclassconfigs",
        "Namespaced",
        "v2alpha1",
    ),
    (
        "DatapathPlugin",
        "datapathplugin",
        "datapathplugins",
        "Cluster",
        "v2alpha1",
    ),
];
/// flowsdn short names, keyed by the plural suffix (#325). Upstream short names
/// (`cnp`, `cep`, ...) are never registered: they would collide with an
/// installed Cilium (ADR-0017). Each is the upstream one with an `fs` prefix
/// in place of Cilium's `c`/`cilium`.
pub const SHORT_NAMES: [(&str, &str); 22] = [
    ("networkpolicies", "fsnp"),
    ("clusterwidenetworkpolicies", "fscnp"),
    ("cidrgroups", "fscg"),
    ("endpoints", "fsep"),
    ("endpointslices", "fses"),
    ("identities", "fsid"),
    ("nodes", "fsn"),
    ("nodeconfigs", "fsnc"),
    ("localredirectpolicies", "fslrp"),
    ("egressgatewaypolicies", "fsegp"),
    ("envoyconfigs", "fsec"),
    ("clusterwideenvoyconfigs", "fscec"),
    ("loadbalancerippools", "fslbippool"),
    ("l2announcementpolicies", "fsl2announcement"),
    ("podippools", "fspip"),
    ("bgpclusterconfigs", "fsbgpcluster"),
    ("bgppeerconfigs", "fsbgppeer"),
    ("bgpadvertisements", "fsbgpadvert"),
    ("bgpnodeconfigs", "fsbgpnode"),
    ("bgpnodeconfigoverrides", "fsbgpnodeoverride"),
    ("gatewayclassconfigs", "fsgcc"),
    ("datapathplugins", "fsdp"),
];
/// The short name registered for an owned or reference plural suffix.
pub fn short_name(plural_suffix: &str) -> Option<&'static str> {
    SHORT_NAMES
        .iter()
        .find(|(suffix, _)| *suffix == plural_suffix)
        .map(|(_, short)| *short)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListScope {
    AllNamespaces,
}
/// GatewayClass parametersRef supplies an explicit namespace, which need not be
/// the installation namespace. Node configuration also selects across namespaces.
pub fn operator_config_scope(plural: &str) -> Result<ListScope, Error> {
    match plural {
        "flowsdnnodeconfigs" | "flowsdngatewayclassconfigs" => Ok(ListScope::AllNamespaces),
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
/// Project a flowsdn-owned CRD document into the registration payload.
/// Callers must verify schemas before this structural projection; it does not
/// validate OpenAPI or hashes, perform HTTP writes, or migrate stored objects.
pub fn registration_payload(document: &Value) -> Result<Value, Error> {
    project_registration(document, false)
}

/// Explicitly adapt a verified reference CRD schema into a NEW flowsdn-owned
/// registration document. This never registers or modifies cilium.io resources.
/// It is schema projection, not migration of existing custom resource instances.
pub fn migration_registration_payload(document: &Value) -> Result<Value, Error> {
    project_registration(document, true)
}

fn project_registration(document: &Value, migration: bool) -> Result<Value, Error> {
    let fail = |message: &str| Error(message.into());
    let group = if migration { "cilium.io" } else { API_GROUP };
    let prefix = if migration { "cilium" } else { "flowsdn" };
    let kind_prefix = if migration { "Cilium" } else { "Flowsdn" };
    let spec = document
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| fail("missing CRD spec"))?;
    if spec.get("group").and_then(Value::as_str) != Some(group) {
        return Err(fail("unexpected CRD group for registration mode"));
    }
    let names = spec
        .get("names")
        .and_then(Value::as_object)
        .ok_or_else(|| fail("missing CRD names"))?;
    let plural = names
        .get("plural")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("missing plural"))?;
    let &(kind, singular, plural_suffix, scope, reference_storage) = RESOURCES
        .iter()
        .find(|resource| plural == format!("{prefix}{}", resource.2))
        .ok_or_else(|| fail("unknown CRD plural"))?;
    let expected_kind = format!("{kind_prefix}{kind}");
    let expected_singular = format!("{prefix}{singular}");
    if names.get("kind").and_then(Value::as_str) != Some(expected_kind.as_str())
        || names.get("singular").and_then(Value::as_str) != Some(expected_singular.as_str())
        || spec.get("scope").and_then(Value::as_str) != Some(scope)
    {
        return Err(fail(
            "CRD identity or scope does not match resource catalogue",
        ));
    }
    if let Some(list_kind) = names.get("listKind")
        && list_kind.as_str() != Some(format!("{expected_kind}List").as_str())
    {
        return Err(fail("unexpected CRD listKind"));
    }
    if let Some(name) = document.pointer("/metadata/name")
        && name.as_str() != Some(format!("{plural}.{group}").as_str())
    {
        return Err(fail("CRD metadata.name does not match identity"));
    }
    if let Some(conversion) = spec.get("conversion")
        && conversion.get("strategy").and_then(Value::as_str) != Some("None")
    {
        return Err(fail("conversion must be absent or None"));
    }
    let versions = spec
        .get("versions")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| fail("missing versions"))?;
    let mut seen = BTreeSet::new();
    let mut storage = None;
    for version in versions {
        let name = version
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| fail("missing version name"))?;
        if !seen.insert(name) {
            return Err(fail("duplicate version"));
        }
        let served = version
            .get("served")
            .and_then(Value::as_bool)
            .ok_or_else(|| fail("missing served flag"))?;
        let stores = version
            .get("storage")
            .and_then(Value::as_bool)
            .ok_or_else(|| fail("missing storage flag"))?;
        if stores && (!served || storage.replace(version).is_some()) {
            return Err(fail("exactly one served storage version required"));
        }
    }
    let storage = storage.ok_or_else(|| fail("missing storage version"))?;
    let storage_name = storage.get("name").and_then(Value::as_str);
    if migration {
        if storage_name != Some(reference_storage) {
            return Err(fail("unexpected reference storage version"));
        }
        if DUAL_VERSION_PLURALS.contains(&plural) {
            if versions.len() != 2
                || !versions.iter().any(|v| {
                    v.get("name").and_then(Value::as_str) == Some("v2alpha1")
                        && v.get("served") == Some(&json!(true))
                        && v.get("deprecated") == Some(&json!(true))
                })
            {
                return Err(fail(
                    "graduated reference CRDs require served deprecated v2alpha1 and storage v2",
                ));
            }
        } else if versions.len() != 1 {
            return Err(fail("unexpected reference version set"));
        }
    } else if versions.len() != 1 || storage_name != Some(API_VERSION) {
        return Err(fail("owned CRDs require a single served storage v1alpha1"));
    }
    if storage
        .pointer("/schema/openAPIV3Schema")
        .and_then(Value::as_object)
        .is_none()
    {
        return Err(fail("missing storage OpenAPI schema"));
    }
    // Only storage schema semantics, subresources and printer columns survive.
    // Reference API versions/deprecation notices and upstream aliases do not.
    let mut projected_version = json!({"name":API_VERSION,"served":true,"storage":true});
    for field in ["schema", "subresources", "additionalPrinterColumns"] {
        if let Some(value) = storage.get(field) {
            projected_version
                .as_object_mut()
                .ok_or_else(|| fail("invalid projected version"))?
                .insert(field.into(), value.clone());
        }
    }
    if let Some(schema) = projected_version.pointer_mut("/schema/openAPIV3Schema") {
        project_schema_identity(schema);
    }
    let owned_plural = format!("flowsdn{plural_suffix}");
    let owned_kind = format!("Flowsdn{kind}");
    let short = short_name(plural_suffix).ok_or_else(|| fail("missing short name"))?;
    let projected_names = json!({"plural":owned_plural,"singular":format!("flowsdn{singular}"),"kind":owned_kind,"listKind":format!("Flowsdn{kind}List"),"shortNames":[short],"categories":["flowsdn"]});
    let mut projected_spec = json!({"group":API_GROUP,"names":projected_names,"scope":scope,"versions":[projected_version],"preserveUnknownFields":false});
    if spec.contains_key("conversion") {
        projected_spec
            .as_object_mut()
            .ok_or_else(|| fail("invalid projected spec"))?
            .insert("conversion".into(), json!({"strategy":"None"}));
    }
    Ok(
        json!({"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":format!("{owned_plural}.{API_GROUP}"),"labels":{SCHEMA_VERSION_LABEL:SCHEMA_VERSION}},"spec":projected_spec}),
    )
}

// Reference schemas contain actual cross-CRD kind enums and group/kind defaults
// (BGP peerConfigRef and policy envoyConfig), not just descriptive prose. Rewrite
// only identity constraints under named schema properties; labels, annotations,
// arbitrary strings and upstream descriptions remain compatibility data.
fn project_schema_identity(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
                for field in ["kind", "group", "apiVersion"] {
                    if let Some(identity) = properties.get_mut(field).and_then(Value::as_object_mut)
                    {
                        for constraint in ["default", "const", "enum"] {
                            if let Some(value) = identity.get_mut(constraint) {
                                project_identity_value(field, value);
                            }
                        }
                    }
                }
            }
            for keyword in ["properties", "patternProperties", "definitions", "$defs"] {
                if let Some(children) = object.get_mut(keyword).and_then(Value::as_object_mut) {
                    for child in children.values_mut() {
                        project_schema_identity(child);
                    }
                }
            }
            for keyword in [
                "items",
                "additionalProperties",
                "not",
                "allOf",
                "anyOf",
                "oneOf",
            ] {
                if let Some(child) = object.get_mut(keyword) {
                    project_schema_identity(child);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                project_schema_identity(value);
            }
        }
        _ => {}
    }
}
fn project_identity_value(field: &str, value: &mut Value) {
    match value {
        Value::String(text) => {
            if field == "group" && text == "cilium.io" {
                *text = API_GROUP.into();
            } else if field == "apiVersion"
                && matches!(text.as_str(), "cilium.io/v2" | "cilium.io/v2alpha1")
            {
                *text = format!("{API_GROUP}/{API_VERSION}");
            } else if field == "kind"
                && let Some(resource) = RESOURCES
                    .iter()
                    .find(|resource| text.as_str() == format!("Cilium{}", resource.0).as_str())
            {
                *text = format!("Flowsdn{}", resource.0);
            }
        }
        Value::Array(values) => {
            for value in values {
                project_identity_value(field, value);
            }
        }
        _ => {}
    }
}
