//! CRD registration by the operator (spec 13 §3.2, #337) and the agent's
//! CRD readiness gate's list.
//!
//! The payloads are the generated manifests in `crds/` (the files stormcos
//! can also apply), embedded at build time: the operator binary carries
//! flowsdn's CRDs, never the reference text they were projected from.
//! `tests/crds.rs` checks those files are the projection of the vendored
//! schemas, and `tests/register.rs` that they parse back to it.
//!
//! [`register`] runs steps 2-5 for one CRD against an injected request
//! function, so it is tested without a server: `GET`; on 404 `POST` (409 is
//! success: another operator raced); update when the cluster's copy has no
//! schema, no schema-version label, or an older one (a newer one is left
//! alone), re-reading and `PUT`ting every 500 ms for up to 60 s on 409; then
//! wait (500 ms, 60 s) for `Established=True`. `NamesAccepted=False` is
//! fatal and names the conflict.
use crate::{Error, SCHEMA_VERSION, SCHEMA_VERSION_LABEL, crd::yaml_documents};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;

/// The CRD collection path.
pub const CRDS_PATH: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
/// The metadata-only list content type (spec 13 §3.2): never the schemas.
pub const METADATA_LIST_ACCEPT: &str = "application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io,application/json;as=PartialObjectMetadataList;v=v1beta1;g=meta.k8s.io,application/json";
/// Poll interval and the number of polls (500 ms x 120 = 60 s).
pub const POLL: Duration = Duration::from_millis(500);
pub const POLLS: u32 = 120;

/// The shipped CRD manifests, by plural.
pub const SHIPPED: [(&str, &str); 22] = [
    (
        "flowsdnnetworkpolicies",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnnetworkpolicies.yaml"),
    ),
    (
        "flowsdnclusterwidenetworkpolicies",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnclusterwidenetworkpolicies.yaml"),
    ),
    (
        "flowsdncidrgroups",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdncidrgroups.yaml"),
    ),
    (
        "flowsdnendpoints",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnendpoints.yaml"),
    ),
    (
        "flowsdnendpointslices",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnendpointslices.yaml"),
    ),
    (
        "flowsdnidentities",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnidentities.yaml"),
    ),
    (
        "flowsdnnodes",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnnodes.yaml"),
    ),
    (
        "flowsdnnodeconfigs",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnnodeconfigs.yaml"),
    ),
    (
        "flowsdnlocalredirectpolicies",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnlocalredirectpolicies.yaml"),
    ),
    (
        "flowsdnegressgatewaypolicies",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnegressgatewaypolicies.yaml"),
    ),
    (
        "flowsdnenvoyconfigs",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnenvoyconfigs.yaml"),
    ),
    (
        "flowsdnclusterwideenvoyconfigs",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnclusterwideenvoyconfigs.yaml"),
    ),
    (
        "flowsdnloadbalancerippools",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnloadbalancerippools.yaml"),
    ),
    (
        "flowsdnl2announcementpolicies",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnl2announcementpolicies.yaml"),
    ),
    (
        "flowsdnpodippools",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnpodippools.yaml"),
    ),
    (
        "flowsdnbgpclusterconfigs",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnbgpclusterconfigs.yaml"),
    ),
    (
        "flowsdnbgppeerconfigs",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnbgppeerconfigs.yaml"),
    ),
    (
        "flowsdnbgpadvertisements",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnbgpadvertisements.yaml"),
    ),
    (
        "flowsdnbgpnodeconfigs",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnbgpnodeconfigs.yaml"),
    ),
    (
        "flowsdnbgpnodeconfigoverrides",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdnbgpnodeconfigoverrides.yaml"),
    ),
    (
        "flowsdngatewayclassconfigs",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdngatewayclassconfigs.yaml"),
    ),
    (
        "flowsdndatapathplugins",
        include_str!("../../../deploy/stormcos/manifests-kubernetes/crds/flowsdndatapathplugins.yaml"),
    ),
];

/// Every shipped CRD as a registration payload: (CRD name, document).
pub fn shipped_crds() -> Result<Vec<(String, Value)>, Error> {
    SHIPPED
        .iter()
        .map(|(plural, text)| {
            let docs = yaml_documents(text).map_err(|e| Error(format!("{plural}: {e}")))?;
            let [document] = docs.as_slice() else {
                return Err(Error(format!("{plural}: expected one document")));
            };
            Ok((format!("{plural}.flowsdn.io"), document.clone()))
        })
        .collect()
}

/// `MAJOR.MINOR.PATCH` as numbers; None when it does not parse.
fn semver(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.').map(|p| p.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

/// Whether the cluster's copy of a CRD must be replaced by this build's.
pub fn needs_update(existing: &Value) -> bool {
    if existing.pointer("/spec/versions/0/schema").is_none() {
        return true;
    }
    let label = existing
        .pointer("/metadata/labels")
        .and_then(|l| l.get(SCHEMA_VERSION_LABEL))
        .and_then(Value::as_str);
    match (label.and_then(semver), semver(SCHEMA_VERSION)) {
        (Some(theirs), Some(ours)) => theirs < ours,
        _ => true,
    }
}

/// The `PUT` body: the cluster's object with this build's labels and spec,
/// `preserveUnknownFields: false` stated (the server keeps the old value
/// otherwise), and its resourceVersion kept.
pub fn update_body(existing: &Value, payload: &Value) -> Value {
    let mut body = existing.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("status");
        let mut spec = payload.get("spec").cloned().unwrap_or(Value::Null);
        if let Some(spec) = spec.as_object_mut() {
            spec.insert("preserveUnknownFields".into(), Value::Bool(false));
        }
        object.insert("spec".into(), spec);
    }
    if let (Some(metadata), Some(labels)) = (
        body.get_mut("metadata").and_then(Value::as_object_mut),
        payload.pointer("/metadata/labels"),
    ) {
        metadata.insert("labels".into(), labels.clone());
    }
    body
}

/// `Established=True` yet; an error when `NamesAccepted=False`.
pub fn established(existing: &Value) -> Result<bool, Error> {
    let conditions = existing
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let status = |kind: &str| {
        conditions
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some(kind))
    };
    if let Some(names) = status("NamesAccepted")
        && names.get("status").and_then(Value::as_str) == Some("False")
    {
        let name = existing
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let why = names.get("message").and_then(Value::as_str).unwrap_or("");
        return Err(Error(format!("CRD {name}: names not accepted: {why}")));
    }
    Ok(status("Established")
        .and_then(|c| c.get("status"))
        .and_then(Value::as_str)
        == Some("True"))
}

/// One request: method, path, body; the HTTP status and body back.
pub type Send<'a> =
    dyn FnMut(http::Method, &str, Option<&Value>) -> Result<(u16, Value), Error> + 'a;

fn refused(what: &str, status: u16, body: &Value) -> Error {
    Error(format!(
        "{what}: HTTP {status} {}",
        body.get("message").and_then(Value::as_str).unwrap_or("")
    ))
}

/// What [`register`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Registered {
    Created,
    Updated,
    Current,
}

/// Register one CRD (spec 13 §3.2 steps 2-5). `wait` sleeps between polls.
pub fn register(
    name: &str,
    payload: &Value,
    send: &mut Send<'_>,
    wait: &mut dyn FnMut(Duration),
) -> Result<Registered, Error> {
    let path = format!("{CRDS_PATH}/{name}");
    let (status, existing) = send(http::Method::GET, &path, None)?;
    let mut done = match status {
        200 => Registered::Current,
        404 => match send(http::Method::POST, CRDS_PATH, Some(payload))? {
            (200..=299 | 409, _) => Registered::Created,
            (status, body) => return Err(refused(&format!("create {name}"), status, &body)),
        },
        status => return Err(refused(&format!("read {name}"), status, &existing)),
    };
    if done == Registered::Current && needs_update(&existing) {
        let mut current = existing;
        let mut updated = false;
        for _ in 0..POLLS {
            if !needs_update(&current) {
                updated = true;
                break;
            }
            match send(http::Method::PUT, &path, Some(&update_body(&current, payload)))? {
                (200..=299, _) => {
                    updated = true;
                    break;
                }
                (409, _) => {}
                (status, body) => return Err(refused(&format!("update {name}"), status, &body)),
            }
            wait(POLL);
            match send(http::Method::GET, &path, None)? {
                (200, again) => current = again,
                (status, body) => return Err(refused(&format!("read {name}"), status, &body)),
            }
        }
        if !updated {
            return Err(Error(format!("update {name}: still conflicting after 60 s")));
        }
        done = Registered::Updated;
    }
    for _ in 0..POLLS {
        match send(http::Method::GET, &path, None)? {
            (200, current) if established(&current)? => return Ok(done),
            (200 | 404, _) => {}
            (status, body) => return Err(refused(&format!("read {name}"), status, &body)),
        }
        wait(POLL);
    }
    Err(Error(format!("CRD {name}: not Established after 60 s")))
}

/// The CRD names in a metadata-only (or full) list.
pub fn listed_names(list: &Value) -> BTreeSet<String> {
    list.get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.pointer("/metadata/name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}
