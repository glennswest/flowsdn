//! Owned CRD registration planning; no HTTP writes or admission claims.
//!
//! The elected driver supplies a freshly fetched object for each plan. Execute
//! writes only while the same Lease remains held. A 409/AlreadyExists, timeout,
//! or any uncertain response requires a fresh GET and re-plan, never replaying
//! an old PUT. Neither a successful write nor this plan establishes readiness:
//! observe fresh Established status afterward. Skip mode is strictly read-only.
use flowsdn_k8s::{SCHEMA_VERSION, SCHEMA_VERSION_LABEL, plan::{API_VERSION, registration_payload}};
use serde_json::{Value, json};
use std::{cmp::Ordering, fmt};

pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY: &str = "flowsdn-operator";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for Error {}
fn invalid(message: &str) -> Error { Error(message.into()) }

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Create(Value),
    /// The body carries these exact fetched identity/concurrency preconditions.
    /// The driver MUST PUT to the named object, not use a blind create/patch.
    Replace { object: Value, uid: String, resource_version: String },
    Observe,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub action: Action,
    pub established: bool,
}

/// `desired` must originate from the verified schema bundle. The structural
/// re-projection below validates its identity but does not authenticate arbitrary
/// schemas. Existing unmarked/foreign objects are collisions, never adopted.
pub fn plan(desired: &Value, fetched: Option<&Value>, skip_creation: bool) -> Result<Plan, Error> {
    let desired = registration_payload(desired).map_err(|e| Error(e.to_string()))?;
    let Some(existing) = fetched else {
        return Ok(Plan {
            action: if skip_creation { Action::Observe } else { Action::Create(mark_created(desired)?) },
            established: false,
        });
    };
    validate_identity(&desired, existing)?;
    let uid = required(existing, "/metadata/uid")?;
    let resource_version = required(existing, "/metadata/resourceVersion")?;
    if !skip_creation && existing.pointer("/metadata/labels").and_then(|v| v.get(MANAGED_BY_LABEL)).and_then(Value::as_str) != Some(MANAGED_BY) {
        return Err(invalid("owned CRD name collision: object is not managed by flowsdn-operator"));
    }
    let established = observed_established(existing)?;
    if skip_creation || is_terminating(existing) {
        return Ok(Plan { action: Action::Observe, established });
    }
    let installed_version = existing.pointer("/metadata/labels").and_then(|v| v.get(SCHEMA_VERSION_LABEL)).and_then(Value::as_str).and_then(Semver::parse);
    let target_version = Semver::parse(SCHEMA_VERSION).ok_or_else(|| invalid("invalid compiled schema version"))?;
    let comparison = installed_version.map(|v| v.compare(&target_version));
    // A newer label takes priority even over missing schema: repairing with
    // this older binary would be a downgrade. Keep it untouched and unready.
    if comparison == Some(Ordering::Greater) || (comparison == Some(Ordering::Equal) && has_schema(existing)) {
        return Ok(Plan { action: Action::Observe, established });
    }
    let mut replacement = existing.clone();
    let object = replacement.as_object_mut().ok_or_else(|| invalid("invalid CRD object"))?;
    object.remove("status"); // Never claim server-maintained CRD admission status.
    object.insert("spec".into(), desired.get("spec").ok_or_else(|| invalid("missing desired spec"))?.clone());
    let metadata = object.get_mut("metadata").and_then(Value::as_object_mut).ok_or_else(|| invalid("invalid existing metadata"))?;
    if !metadata.contains_key("labels") { metadata.insert("labels".into(), json!({})); }
    let labels = metadata.get_mut("labels").and_then(Value::as_object_mut).ok_or_else(|| invalid("invalid existing labels"))?;
    labels.insert(SCHEMA_VERSION_LABEL.into(), json!(SCHEMA_VERSION));
    Ok(Plan { action: Action::Replace { object: replacement, uid: uid.into(), resource_version: resource_version.into() }, established: false })
}

fn mark_created(mut desired: Value) -> Result<Value, Error> {
    desired.pointer_mut("/metadata/labels").and_then(Value::as_object_mut).ok_or_else(|| invalid("missing desired labels"))?.insert(MANAGED_BY_LABEL.into(), json!(MANAGED_BY));
    Ok(desired)
}
fn required<'a>(object: &'a Value, path: &str) -> Result<&'a str, Error> {
    object.pointer(path).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| Error(format!("missing CRD field {path}")))
}
fn validate_identity(desired: &Value, existing: &Value) -> Result<(), Error> {
    for path in ["/apiVersion", "/kind", "/metadata/name", "/spec/group", "/spec/scope", "/spec/names/plural", "/spec/names/singular", "/spec/names/kind", "/spec/names/listKind"] {
        if existing.pointer(path) != desired.pointer(path) { return Err(Error(format!("CRD identity collision at {path}"))); }
    }
    if existing.pointer("/metadata/namespace").is_some_and(|value| value.as_str() != Some("") && !value.is_null()) {
        return Err(invalid("CRD must be cluster-scoped"));
    }
    Ok(())
}
fn has_schema(object: &Value) -> bool {
    let Some(versions) = object.pointer("/spec/versions").and_then(Value::as_array) else { return false; };
    let mut supported = versions.iter().filter(|v| v.get("name").and_then(Value::as_str) == Some(API_VERSION));
    let Some(version) = supported.next() else { return false; };
    supported.next().is_none() && version.get("served") == Some(&json!(true))
        && version.pointer("/schema/openAPIV3Schema/type").and_then(Value::as_str) == Some("object")
}
fn observed_established(object: &Value) -> Result<bool, Error> {
    let mut established = None;
    let mut accepted = None;
    let mut terminating = None;
    if let Some(conditions) = object.pointer("/status/conditions") {
        for condition in conditions.as_array().ok_or_else(|| invalid("invalid CRD conditions"))? {
            let target = match condition.get("type").and_then(Value::as_str) {
                Some("Established") => &mut established,
                Some("NamesAccepted") => &mut accepted,
                Some("Terminating") => &mut terminating,
                _ => continue,
            };
            if target.replace(condition.get("status").and_then(Value::as_str).ok_or_else(|| invalid("invalid CRD condition status"))?).is_some() {
                return Err(invalid("duplicate CRD condition"));
            }
        }
    }
    if accepted == Some("False") { return Err(Error(format!("CRD {} NamesAccepted=False: resource name conflict", required(object, "/metadata/name")?))); }
    Ok(established == Some("True") && terminating != Some("True")
        && !object.pointer("/metadata/deletionTimestamp").is_some_and(|v| !v.is_null())
        && has_schema(object))
}

fn is_terminating(object: &Value) -> bool {
    object.pointer("/metadata/deletionTimestamp").is_some_and(|v| !v.is_null())
        || object.pointer("/status/conditions").and_then(Value::as_array).is_some_and(|conditions| conditions.iter().any(|c| c.get("type").and_then(Value::as_str) == Some("Terminating") && c.get("status").and_then(Value::as_str) == Some("True")))
}

// Strict SemVer comparison. Numeric identifiers compare by digit count then
// bytes, avoiding overflow and accidental downgrade of very large versions.
struct Semver<'a> { core: [&'a str; 3], prerelease: Option<&'a str> }
impl<'a> Semver<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let (base, build) = value.split_once('+').map_or((value, None), |(a, b)| (a, Some(b)));
        if build.is_some_and(|s| !identifiers(s, false)) { return None; }
        let (core, prerelease) = base.split_once('-').map_or((base, None), |(a, b)| (a, Some(b)));
        if prerelease.is_some_and(|s| !identifiers(s, true)) { return None; }
        let mut parts = core.split('.');
        let core = [parts.next()?, parts.next()?, parts.next()?];
        if parts.next().is_some() || core.iter().any(|part| !numeric(part) || (part.len() > 1 && part.starts_with('0'))) { return None; }
        Some(Self { core, prerelease })
    }
    fn compare(&self, other: &Self) -> Ordering {
        for (a, b) in self.core.iter().zip(other.core.iter()) {
            let order = numeric_order(a, b);
            if order != Ordering::Equal { return order; }
        }
        match (self.prerelease, other.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => {
                let mut a = a.split('.');
                let mut b = b.split('.');
                loop {
                    let order = match (a.next(), b.next()) {
                        (None, None) => return Ordering::Equal,
                        (None, Some(_)) => return Ordering::Less,
                        (Some(_), None) => return Ordering::Greater,
                        (Some(a), Some(b)) => match (numeric(a), numeric(b)) {
                            (true, true) => numeric_order(a, b),
                            (true, false) => Ordering::Less,
                            (false, true) => Ordering::Greater,
                            (false, false) => a.cmp(b),
                        },
                    };
                    if order != Ordering::Equal { return order; }
                }
            }
        }
    }
}
fn numeric(value: &str) -> bool { !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) }
fn numeric_order(a: &str, b: &str) -> Ordering { a.len().cmp(&b.len()).then_with(|| a.cmp(b)) }
fn identifiers(value: &str, prerelease: bool) -> bool {
    value.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !(prerelease && numeric(part) && part.len() > 1 && part.starts_with('0')))
}
