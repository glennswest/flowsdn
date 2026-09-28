use flowsdn_k8s::{
    plan::{DUAL_VERSION_PLURALS, REGISTRATION_PLURALS, registration_payload},
    schemas::{MANIFEST, MANIFEST_SHA256, REFERENCE_COMMIT, reference_documents, registration_payloads},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[test]
fn complete_pinned_bundle_has_expected_versions_and_owned_identities() {
    assert_eq!(format!("{:x}", Sha256::digest(MANIFEST.as_bytes())), MANIFEST_SHA256);
    assert_eq!(REFERENCE_COMMIT, "7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc");
    let sources = reference_documents().expect("verified reference bundle");
    let payloads = registration_payloads().expect("complete owned bundle");
    assert_eq!(sources.len(), 22);
    assert_eq!(payloads.len(), 22);
    let mut seen = BTreeSet::new();
    let mut dual_count = 0usize;
    for (source, owned) in sources.iter().zip(&payloads) {
        let plural = source.document.pointer("/spec/names/plural").and_then(Value::as_str).expect("reference plural");
        let versions = source.document.pointer("/spec/versions").and_then(Value::as_array).expect("reference versions");
        if DUAL_VERSION_PLURALS.contains(&plural) {
            dual_count = dual_count.saturating_add(1);
            assert_eq!(versions.len(), 2);
            assert!(versions.iter().any(|v| v.get("name") == Some(&json!("v2alpha1")) && v.get("deprecated") == Some(&json!(true)) && v.get("served") == Some(&json!(true))));
        } else { assert_eq!(versions.len(), 1); }
        let owned_plural = owned.pointer("/spec/names/plural").and_then(Value::as_str).expect("owned plural");
        assert!(seen.insert(owned_plural));
        assert!(REGISTRATION_PLURALS.contains(&owned_plural));
        assert_eq!(owned.pointer("/metadata/name"), Some(&json!(format!("{owned_plural}.flowsdn.io"))));
        assert_eq!(owned.pointer("/spec/group"), Some(&json!("flowsdn.io")));
        assert_eq!(owned.pointer("/spec/versions").and_then(Value::as_array).expect("owned versions").len(), 1);
        assert_eq!(owned.pointer("/spec/versions/0/name"), Some(&json!("v1alpha1")));
        assert!(owned.pointer("/spec/versions/0/deprecated").is_none());
        assert!(owned.pointer("/spec/versions/0/deprecationWarning").is_none());
        assert_eq!(registration_payload(owned).expect("idempotence"), *owned);
        let storage = versions.iter().find(|v| v.get("storage") == Some(&json!(true))).expect("storage version");
        for field in ["subresources", "additionalPrinterColumns"] {
            assert_eq!(owned.pointer(&format!("/spec/versions/0/{field}")), storage.get(field));
        }
    }
    assert_eq!(dual_count, 7);
}

fn find_constraints<'a>(value: &'a Value, constraint: &str, expected: &Value, found: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if map.get(constraint) == Some(expected) { found.push(value); }
            for child in map.values() { find_constraints(child, constraint, expected, found); }
        }
        Value::Array(values) => { for child in values { find_constraints(child, constraint, expected, found); } }
        _ => {}
    }
}

#[test]
fn actual_policy_kind_enums_are_owned_and_other_schema_content_is_preserved() {
    let sources = reference_documents().expect("source bundle");
    let payloads = registration_payloads().expect("owned bundle");
    let upstream = json!(["CiliumEnvoyConfig", "CiliumClusterwideEnvoyConfig"]);
    let flowsdn = json!(["FlowsdnEnvoyConfig", "FlowsdnClusterwideEnvoyConfig"]);
    let mut transformed = 0usize;
    for (source, payload) in sources.iter().zip(&payloads) {
        let mut old = Vec::new();
        let mut new = Vec::new();
        find_constraints(&source.document, "enum", &upstream, &mut old);
        find_constraints(payload, "enum", &flowsdn, &mut new);
        assert_eq!(old.len(), new.len());
        for (before, after) in old.iter().zip(&new) {
            assert_eq!(before.get("description"), after.get("description"));
            assert_eq!(before.get("type"), after.get("type"));
        }
        transformed = transformed.saturating_add(new.len());
        let mut leaked = Vec::new();
        find_constraints(payload, "enum", &upstream, &mut leaked);
        assert!(leaked.is_empty());
        // Apart from the policy identity enums, every selected storage schema
        // must survive unchanged. This also covers CEL and opaque extensions.
        let storage = source.document.pointer("/spec/versions").and_then(Value::as_array).expect("versions").iter().find(|v| v.get("storage") == Some(&json!(true))).expect("storage");
        let mut expected = storage.get("schema").expect("schema").clone();
        replace_policy_enums(&mut expected, &upstream, &flowsdn);
        assert_eq!(payload.pointer("/spec/versions/0/schema"), Some(&expected), "{}", source.path);
    }
    assert_eq!(transformed, 8);
}
fn replace_policy_enums(value: &mut Value, upstream: &Value, flowsdn: &Value) {
    match value {
        Value::Object(map) => {
            if map.get("enum") == Some(upstream) { map.insert("enum".into(), flowsdn.clone()); }
            for child in map.values_mut() { replace_policy_enums(child, upstream, flowsdn); }
        }
        Value::Array(values) => { for child in values { replace_policy_enums(child, upstream, flowsdn); } }
        _ => {}
    }
}

#[test]
fn deprecated_bgp_defaults_are_preserved_in_provenance_not_selected_as_storage() {
    let sources = reference_documents().expect("source bundle");
    let payloads = registration_payloads().expect("owned bundle");
    let mut defaults = 0usize;
    for (source, payload) in sources.iter().zip(&payloads) {
        let mut upstream_groups = Vec::new();
        let mut upstream_kinds = Vec::new();
        find_constraints(&source.document, "default", &json!("cilium.io"), &mut upstream_groups);
        find_constraints(&source.document, "default", &json!("CiliumBGPPeerConfig"), &mut upstream_kinds);
        defaults = defaults.saturating_add(upstream_groups.len());
        assert_eq!(upstream_groups.len(), upstream_kinds.len());
        let mut selected = Vec::new();
        find_constraints(payload, "default", &json!("cilium.io"), &mut selected);
        find_constraints(payload, "default", &json!("CiliumBGPPeerConfig"), &mut selected);
        assert!(selected.is_empty());
    }
    // These two deprecated-version defaults are absent from the actual v2
    // storage schemas. Synthetic projection tests cover default adaptation.
    assert_eq!(defaults, 2);
}

#[test]
fn checksum_list_agrees_with_version_bound_manifest() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("manifest JSON");
    let mut expected = String::new();
    for entry in manifest.get("files").and_then(Value::as_array).expect("files") {
        expected.push_str(entry.get("sha256").and_then(Value::as_str).expect("hash"));
        expected.push_str("  ");
        expected.push_str(entry.get("path").and_then(Value::as_str).expect("path"));
        expected.push('\n');
    }
    assert_eq!(include_str!("../crds/SHA256SUMS"), expected);
}
