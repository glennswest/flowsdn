//! Embedded, hash-verified reference CRD schemas and owned payload projection.
//! Upstream files are provenance data, never manifests to install directly.
use crate::{Error, SCHEMA_VERSION, plan::{REGISTRATION_PLURALS, migration_registration_payload}};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const REFERENCE_COMMIT: &str = "7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc";
/// Binds this reviewed corpus manifest to the schema provenance version. Changes
/// require review of the manifest, this digest and SCHEMA_VERSION together.
pub const MANIFEST_SHA256: &str = "b7bb7921f98a7c5cedc5ba99f79add96065544fca6137d42d7b9a16c57467c3d";
pub const MANIFEST: &str = include_str!("../crds/manifest.json");
const SOURCE_PREFIX: &str = "pkg/k8s/apis/cilium.io/client/crds/";
const EMBEDDED: [(&str, &[u8]); 22] = [
    ("v2/ciliumbgpadvertisements.yaml", include_bytes!("../crds/v2/ciliumbgpadvertisements.yaml")),
    ("v2/ciliumbgpclusterconfigs.yaml", include_bytes!("../crds/v2/ciliumbgpclusterconfigs.yaml")),
    ("v2/ciliumbgpnodeconfigoverrides.yaml", include_bytes!("../crds/v2/ciliumbgpnodeconfigoverrides.yaml")),
    ("v2/ciliumbgpnodeconfigs.yaml", include_bytes!("../crds/v2/ciliumbgpnodeconfigs.yaml")),
    ("v2/ciliumbgppeerconfigs.yaml", include_bytes!("../crds/v2/ciliumbgppeerconfigs.yaml")),
    ("v2/ciliumcidrgroups.yaml", include_bytes!("../crds/v2/ciliumcidrgroups.yaml")),
    ("v2/ciliumclusterwideenvoyconfigs.yaml", include_bytes!("../crds/v2/ciliumclusterwideenvoyconfigs.yaml")),
    ("v2/ciliumclusterwidenetworkpolicies.yaml", include_bytes!("../crds/v2/ciliumclusterwidenetworkpolicies.yaml")),
    ("v2/ciliumegressgatewaypolicies.yaml", include_bytes!("../crds/v2/ciliumegressgatewaypolicies.yaml")),
    ("v2/ciliumendpoints.yaml", include_bytes!("../crds/v2/ciliumendpoints.yaml")),
    ("v2/ciliumenvoyconfigs.yaml", include_bytes!("../crds/v2/ciliumenvoyconfigs.yaml")),
    ("v2/ciliumidentities.yaml", include_bytes!("../crds/v2/ciliumidentities.yaml")),
    ("v2/ciliumloadbalancerippools.yaml", include_bytes!("../crds/v2/ciliumloadbalancerippools.yaml")),
    ("v2/ciliumlocalredirectpolicies.yaml", include_bytes!("../crds/v2/ciliumlocalredirectpolicies.yaml")),
    ("v2/ciliumnetworkpolicies.yaml", include_bytes!("../crds/v2/ciliumnetworkpolicies.yaml")),
    ("v2/ciliumnodeconfigs.yaml", include_bytes!("../crds/v2/ciliumnodeconfigs.yaml")),
    ("v2/ciliumnodes.yaml", include_bytes!("../crds/v2/ciliumnodes.yaml")),
    ("v2alpha1/ciliumdatapathplugins.yaml", include_bytes!("../crds/v2alpha1/ciliumdatapathplugins.yaml")),
    ("v2alpha1/ciliumendpointslices.yaml", include_bytes!("../crds/v2alpha1/ciliumendpointslices.yaml")),
    ("v2alpha1/ciliumgatewayclassconfigs.yaml", include_bytes!("../crds/v2alpha1/ciliumgatewayclassconfigs.yaml")),
    ("v2alpha1/ciliuml2announcementpolicies.yaml", include_bytes!("../crds/v2alpha1/ciliuml2announcementpolicies.yaml")),
    ("v2alpha1/ciliumpodippools.yaml", include_bytes!("../crds/v2alpha1/ciliumpodippools.yaml")),
];

#[derive(Clone, Debug)]
pub struct ReferenceSchema {
    pub path: &'static str,
    pub document: Value,
}

/// Verify the embedded corpus and decode all 22 reference CRDs. Runtime callers
/// do not need network access, a working directory, or an external schema file.
/// No output is returned unless the entire manifest and corpus pass validation.
pub fn reference_documents() -> Result<Vec<ReferenceSchema>, Error> {
    let manifest = verified_manifest(MANIFEST.as_bytes())?;
    let entries = manifest.get("files").and_then(Value::as_array).ok_or_else(|| error("missing schema manifest files"))?;
    if entries.len() != EMBEDDED.len() { return Err(error("schema manifest resource count mismatch")); }
    let mut seen = BTreeSet::new();
    let mut documents = Vec::with_capacity(EMBEDDED.len());
    for entry in entries {
        let path = string(entry, "path")?;
        if !seen.insert(path) { return Err(error("duplicate schema manifest path")); }
        let &(embedded_path, bytes) = EMBEDDED.iter().find(|(name, _)| *name == path).ok_or_else(|| error("unknown schema manifest path"))?;
        if string(entry, "source_path")? != format!("{SOURCE_PREFIX}{path}") { return Err(error("schema source path mismatch")); }
        verify_digest(bytes, string(entry, "sha256")?)?;
        let yaml = std::str::from_utf8(bytes).map_err(|e| Error(format!("schema UTF-8: {e}")))?;
        let values = yaml_rust2::YamlLoader::load_from_str(yaml).map_err(|e| Error(format!("schema YAML {path}: {e}")))?;
        if values.len() != 1 { return Err(error("schema must contain one YAML document")); }
        let document = yaml_value(values.first().ok_or_else(|| error("missing schema document"))?)?;
        if document.get("apiVersion").and_then(Value::as_str) != Some("apiextensions.k8s.io/v1")
            || document.get("kind").and_then(Value::as_str) != Some("CustomResourceDefinition") {
            return Err(error("schema is not a v1 CustomResourceDefinition"));
        }
        let plural = document.pointer("/spec/names/plural").and_then(Value::as_str).ok_or_else(|| error("missing schema plural"))?;
        if path.rsplit('/').next() != Some(format!("{plural}.yaml").as_str()) { return Err(error("schema filename does not match CRD identity")); }
        documents.push(ReferenceSchema { path: embedded_path, document });
    }
    Ok(documents)
}

/// Generate the complete owned registration set from verified embedded data.
/// This does not register CRDs, wait for admission, or migrate stored instances.
pub fn registration_payloads() -> Result<Vec<Value>, Error> {
    let mut seen = BTreeSet::new();
    let mut payloads = Vec::with_capacity(EMBEDDED.len());
    for schema in reference_documents()? {
        let payload = migration_registration_payload(&schema.document)?;
        let plural = payload.pointer("/spec/names/plural").and_then(Value::as_str).ok_or_else(|| error("missing projected plural"))?;
        if !seen.insert(plural.to_owned()) { return Err(error("duplicate projected CRD")); }
        payloads.push(payload);
    }
    let expected: BTreeSet<_> = REGISTRATION_PLURALS.into_iter().map(str::to_owned).collect();
    if seen != expected { return Err(error("schema bundle does not match registration catalogue")); }
    Ok(payloads)
}

fn error(message: &str) -> Error { Error(message.into()) }
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| Error(format!("missing manifest {key}")))
}
fn verify_digest(bytes: &[u8], expected: &str) -> Result<(), Error> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected { return Err(error("embedded schema SHA-256 mismatch")); }
    Ok(())
}
fn verified_manifest(bytes: &[u8]) -> Result<Value, Error> {
    verify_digest(bytes, MANIFEST_SHA256)?;
    let manifest: Value = serde_json::from_slice(bytes).map_err(|e| Error(format!("schema manifest JSON: {e}")))?;
    if string(&manifest, "repository")? != "https://github.com/cilium/cilium"
        || string(&manifest, "commit")? != REFERENCE_COMMIT
        || string(&manifest, "reference_schema_version")? != SCHEMA_VERSION
        || string(&manifest, "license")? != "Apache-2.0" {
        return Err(error("schema manifest provenance mismatch"));
    }
    Ok(manifest)
}

fn yaml_value(value: &yaml_rust2::Yaml) -> Result<Value, Error> {
    use yaml_rust2::Yaml;
    Ok(match value {
        Yaml::Null => Value::Null,
        Yaml::Boolean(v) => Value::Bool(*v),
        Yaml::Integer(v) => Value::from(*v),
        Yaml::Real(v) => {
            let number: Value = serde_json::from_str(v).map_err(|e| Error(format!("invalid schema YAML number: {e}")))?;
            if !number.is_number() { return Err(error("schema YAML real is not a number")); }
            number
        }
        Yaml::String(v) => Value::String(v.clone()),
        Yaml::Array(values) => Value::Array(values.iter().map(yaml_value).collect::<Result<_, _>>()?),
        Yaml::Hash(values) => {
            let mut object = serde_json::Map::new();
            for (key, val) in values {
                let key = key.as_str().ok_or_else(|| error("schema YAML has non-string map key"))?;
                object.insert(key.to_owned(), yaml_value(val)?);
            }
            Value::Object(object)
        }
        _ => return Err(error("unsupported schema YAML value")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tampered_bytes_and_manifest_are_rejected_before_decoding() {
        let (path, bytes) = EMBEDDED.first().expect("embedded schema");
        let manifest = verified_manifest(MANIFEST.as_bytes()).expect("manifest");
        let entry = manifest.get("files").and_then(Value::as_array).expect("files").iter().find(|entry| entry.get("path").and_then(Value::as_str) == Some(*path)).expect("entry");
        let hash = string(entry, "sha256").expect("digest");
        verify_digest(bytes, hash).expect("original");
        let (_, other) = EMBEDDED.iter().find(|(candidate, _)| candidate != path).expect("different schema");
        assert!(verify_digest(other, hash).is_err());
        let mut altered = bytes.to_vec();
        altered.push(b'\n');
        assert!(verify_digest(&altered, hash).is_err());
        let mut altered = MANIFEST.as_bytes().to_vec();
        altered.push(b' ');
        assert!(verified_manifest(&altered).is_err());
    }
}
