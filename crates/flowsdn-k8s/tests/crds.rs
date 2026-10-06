//! The flowsdn.io CRD set (#325): vendored schemas, generated manifests,
//! examples and accept/reject validation.
use flowsdn_k8s::crd::{
    CHART_CRD_DIR, MANIFEST_DIR, OwnedCrd, REFERENCE, manifest, owned_crds, to_yaml, yaml_documents, yaml_to_json,
};
use flowsdn_k8s::plan::{REGISTRATION_PLURALS, SHORT_NAMES};
use flowsdn_k8s::schema::{cel, validate};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn repo_dir() -> PathBuf {
    crate_dir().join("../..")
}
fn crds() -> Vec<OwnedCrd> {
    owned_crds().expect("every vendored CRD projects")
}
fn schema(crd: &OwnedCrd) -> &Value {
    crd.document
        .pointer("/spec/versions/0/schema/openAPIV3Schema")
        .expect("schema")
}

#[test]
fn vendored_documents_match_sha256sums() {
    let sums = std::fs::read_to_string(crate_dir().join("crds/SHA256SUMS")).expect("SHA256SUMS");
    let listed: Vec<(&str, &str)> = sums
        .lines()
        .map(|line| line.split_once("  ").expect("sha256sum line"))
        .collect();
    assert_eq!(listed.len(), 22);
    for (sum, path) in &listed {
        let (_, text) = REFERENCE
            .iter()
            .find(|(source, _)| source == path)
            .unwrap_or_else(|| panic!("{path} is not in crd::REFERENCE"));
        assert_eq!(
            &format!("{:x}", Sha256::digest(text.as_bytes())),
            sum,
            "{path} was edited by hand; run tools/vendor-crds.sh"
        );
    }
}

#[test]
fn owned_set_is_the_registration_catalogue() {
    let crds = crds();
    let plurals: BTreeSet<String> = crds
        .iter()
        .map(|crd| {
            crd.document
                .pointer("/spec/names/plural")
                .and_then(Value::as_str)
                .expect("plural")
                .to_owned()
        })
        .collect();
    let catalogue: BTreeSet<String> = REGISTRATION_PLURALS
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    assert_eq!(plurals, catalogue);

    // Short names are flowsdn's own and never an upstream alias (ADR-0017).
    let mut upstream = BTreeSet::new();
    for (_, text) in REFERENCE {
        let doc = yaml_to_json(text).expect("reference YAML");
        for short in doc
            .pointer("/spec/names/shortNames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            upstream.insert(short.as_str().expect("short name").to_owned());
        }
    }
    let ours: BTreeSet<&str> = SHORT_NAMES.iter().map(|(_, short)| *short).collect();
    assert_eq!(ours.len(), 22, "short names are unique");
    for short in &ours {
        assert!(
            !upstream.contains(*short),
            "{short} collides with an upstream short name"
        );
    }
    for crd in &crds {
        let names = crd.document.pointer("/spec/names").expect("names");
        assert_eq!(
            names.get("categories"),
            Some(&serde_json::json!(["flowsdn"]))
        );
        assert_eq!(
            names
                .get("shortNames")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert!(
            names
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|k| k.starts_with("Flowsdn"))
        );
    }
}

/// The CRDs ship twice from one generation: the stormcos manifests and the
/// chart's `crds/` directory (Helm installs it before the templates).
#[test]
fn shipped_manifests_are_the_generated_ones() {
    let write = std::env::var_os("FLOWSDN_WRITE_CRDS").is_some();
    for dir in [MANIFEST_DIR, CHART_CRD_DIR] {
        let dir = repo_dir().join(dir);
        if write {
            std::fs::create_dir_all(&dir).expect("manifest directory");
        }
        let mut expected = BTreeSet::new();
        for crd in crds() {
            let text = manifest(&crd);
            let path = dir.join(&crd.file);
            if write {
                std::fs::write(&path, &text).expect("write manifest");
            }
            let shipped = std::fs::read_to_string(&path).unwrap_or_default();
            assert!(
                shipped == text,
                "{} differs from its generation; run FLOWSDN_WRITE_CRDS=1 cargo test -p flowsdn-k8s --test crds",
                path.display()
            );
            expected.insert(crd.file);
        }
        let present: BTreeSet<String> = std::fs::read_dir(&dir)
            .expect("manifest directory")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(present, expected, "{} holds only generated CRDs", dir.display());
    }
}

#[test]
fn yaml_rendering_round_trips() {
    for crd in crds() {
        let text = to_yaml(&crd.document);
        assert_eq!(
            yaml_to_json(&text).expect("rendered YAML parses"),
            crd.document,
            "{}",
            crd.file
        );
    }
    for (source, text) in REFERENCE {
        let reference = yaml_to_json(text).expect("reference");
        assert_eq!(
            yaml_to_json(&to_yaml(&reference)).expect("re-parse"),
            reference,
            "{source}"
        );
    }
    for tricky in [
        "",
        "yes",
        "No",
        "on",
        "null",
        "1",
        "1.5",
        "-x",
        "a: b",
        "# c",
        "line\n",
        "two\nlines",
        "\nlead",
        "trail\n\n",
        " x\ny",
        "tab\there",
        "x\n  \ny",
        "ünï\ncode",
    ] {
        let value = serde_json::json!({ "k": tricky, "l": [tricky, { "m": tricky }] });
        assert_eq!(
            yaml_to_json(&to_yaml(&value)).expect("parse"),
            value,
            "{tricky:?}"
        );
    }
}

/// Every CEL rule in the set parses in the supported subset.
#[test]
fn every_schema_rule_is_in_the_cel_subset() {
    fn rules(schema: &Value, out: &mut Vec<String>) {
        match schema {
            Value::Object(map) => {
                for rule in map
                    .get("x-kubernetes-validations")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    out.push(
                        rule.get("rule")
                            .and_then(Value::as_str)
                            .expect("rule")
                            .to_owned(),
                    );
                }
                map.values().for_each(|child| rules(child, out));
            }
            Value::Array(items) => items.iter().for_each(|child| rules(child, out)),
            _ => {}
        }
    }
    let mut all = Vec::new();
    for crd in crds() {
        rules(schema(&crd), &mut all);
    }
    assert!(!all.is_empty());
    for rule in all.iter().filter(|rule| !rule.contains("oldSelf")) {
        let result = cel::evaluate(rule, &serde_json::json!({}));
        assert!(
            !matches!(result, Err(cel::Failure::Unsupported(_))),
            "{rule}: {result:?}"
        );
    }
    let this = serde_json::json!({"a": "x", "n": 3, "m": 90});
    for (rule, expected) in [
        ("has(self.a) || has(self.b)", Ok(true)),
        ("has(self.b)", Ok(false)),
        ("self.a != 'x' || has(self.b)", Ok(false)),
        ("self.a == 'x' || !has(self.b)", Ok(true)),
        ("self.n <= self.m", Ok(true)),
        ("self.m <= self.n", Ok(false)),
        ("self.b == 'x'", Err(cel::Failure::Error)),
        ("self.b == 'x' || true", Ok(true)),
        ("self.b == 'x' && false", Ok(false)),
    ] {
        assert_eq!(cel::evaluate(rule, &this), expected, "{rule}");
    }
    assert_eq!(
        cel::evaluate("self == '' || isIP(self)", &serde_json::json!("10.0.0.1")),
        Ok(true)
    );
    assert_eq!(
        cel::evaluate("self == '' || isIP(self)", &serde_json::json!("10.0.0")),
        Ok(false)
    );
    assert_eq!(
        cel::evaluate("self == '' || isIP(self)", &serde_json::json!("")),
        Ok(true)
    );
    assert!(matches!(
        cel::evaluate("self.a.size() > 1", &this),
        Err(cel::Failure::Unsupported(_))
    ));
}

fn example_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    files
}

/// Each kind has a minimal and a realistic example the API server would
/// admit, and reject cases it would refuse with the expected reason.
#[test]
fn examples_are_admitted_and_reject_cases_refused() {
    let mut rejects = 0usize;
    for crd in crds() {
        let plural = crd
            .document
            .pointer("/spec/names/plural")
            .and_then(Value::as_str)
            .expect("plural");
        let kind = crd
            .document
            .pointer("/spec/names/kind")
            .and_then(Value::as_str)
            .expect("kind");
        let namespaced = crd.document.pointer("/spec/scope") == Some(&Value::from("Namespaced"));
        let dir = crate_dir().join("testdata/crs").join(plural);
        let files = example_files(&dir);
        let names: BTreeSet<String> = files
            .iter()
            .map(|f| f.file_name().expect("name").to_string_lossy().into_owned())
            .collect();
        assert!(
            names.contains("minimal.yaml") && names.contains("realistic.yaml"),
            "{plural}: {names:?}"
        );
        for file in files {
            let text = std::fs::read_to_string(&file).expect("example");
            let object = yaml_to_json(&text).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
            assert_eq!(
                object.get("apiVersion"),
                Some(&Value::from("flowsdn.io/v1alpha1")),
                "{}",
                file.display()
            );
            assert_eq!(
                object.get("kind"),
                Some(&Value::from(kind)),
                "{}",
                file.display()
            );
            assert!(
                object
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .is_some(),
                "{}",
                file.display()
            );
            assert_eq!(
                object.pointer("/metadata/namespace").is_some(),
                namespaced,
                "{}: metadata.namespace for a {} kind",
                file.display(),
                if namespaced { "namespaced" } else { "cluster" }
            );
            let violations = validate(schema(&crd), &object);
            let stem = file.file_stem().expect("stem").to_string_lossy();
            if stem.starts_with("reject-") {
                let expect = text
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("# expect: "))
                    .unwrap_or_else(|| {
                        panic!("{}: first line must be `# expect: ...`", file.display())
                    });
                assert!(
                    violations.iter().any(|v| v.contains(expect)),
                    "{}: expected a violation containing {expect:?}, got {violations:?}",
                    file.display()
                );
                rejects = rejects.saturating_add(1);
            } else {
                assert!(violations.is_empty(), "{}: {violations:#?}", file.display());
            }
        }
    }
    assert!(
        rejects >= 22,
        "at least one reject case per kind, found {rejects}"
    );
}

/// The validator itself, on a schema with each keyword it implements.
#[test]
fn validator_keywords() {
    let schema = serde_json::json!({
        "type": "object",
        "required": ["spec"],
        "properties": {
            "apiVersion": {"type": "string"}, "kind": {"type": "string"}, "metadata": {"type": "object"},
            "spec": {
                "type": "object",
                "required": ["cidr"],
                "properties": {
                    "cidr": {"type": "string", "format": "cidr"},
                    "mode": {"type": "string", "enum": ["a", "b"], "default": "a"},
                    "name": {"type": "string", "pattern": "^[a-z]+$", "maxLength": 5},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "format": "int32"},
                    "port2": {"x-kubernetes-int-or-string": true},
                    "set": {"type": "array", "items": {"type": "string"}, "x-kubernetes-list-type": "set", "maxItems": 2},
                    "labels": {"type": "object", "additionalProperties": {"type": "string"}},
                    "free": {"type": "object", "x-kubernetes-preserve-unknown-fields": true},
                    "one": {"type": "object", "properties": {"x": {"type": "string"}, "y": {"type": "string"}},
                            "oneOf": [{"required": ["x"]}, {"required": ["y"]}]},
                    "timers": {"type": "object", "properties": {
                        "hold": {"type": "integer", "default": 90}, "keep": {"type": "integer", "default": 30}},
                        "x-kubernetes-validations": [{"rule": "self.keep <= self.hold", "message": "keep exceeds hold"}]}
                }
            }
        }
    });
    let check = |spec: Value| {
        validate(
            &schema,
            &serde_json::json!({"apiVersion": "v", "kind": "K", "metadata": {"name": "n", "anything": 1}, "spec": spec}),
        )
    };
    assert_eq!(
        check(
            serde_json::json!({"cidr": "10.0.0.0/8", "port2": "http", "labels": {"a": "b"}, "free": {"z": [1]}, "one": {"x": "1"}, "timers": {}})
        ),
        Vec::<String>::new()
    );
    let cases = [
        (serde_json::json!({}), ".spec.cidr: required"),
        (
            serde_json::json!({"cidr": "10.0.0.0/33"}),
            "is not a valid cidr",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "mode": "c"}),
            "is not one of",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "name": "A"}),
            "does not match",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "name": "abcdef"}),
            "longer than 5",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "port": 0}),
            "below the minimum",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "port": "80"}),
            ".spec.port: expected integer",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "port2": true}),
            "expected integer or string",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "set": ["a", "a"]}),
            "duplicate entry",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "set": ["a", "b", "c"]}),
            "more than 2 items",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "labels": {"a": 1}}),
            ".spec.labels.a: expected string",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "typo": 1}),
            ".spec.typo: unknown field",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "one": {"x": "1", "y": "2"}}),
            "oneOf matched 2 of 2",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "one": {}}),
            "oneOf matched 0 of 2",
        ),
        (
            serde_json::json!({"cidr": "10.0.0.0/8", "timers": {"keep": 100}}),
            "keep exceeds hold",
        ),
    ];
    for (spec, expected) in cases {
        let violations = check(spec.clone());
        assert!(
            violations.iter().any(|v| v.contains(expected)),
            "{spec}: expected {expected:?}, got {violations:?}"
        );
    }
}

/// The agent and operator ClusterRoles name only flowsdn.io kinds that exist,
/// `/status` only where the CRD has the subresource, and the operator may
/// update exactly the 22 flowsdn.io CRDs.
#[test]
fn rbac_matches_the_crd_set() {
    let crds = crds();
    let mut allowed = BTreeSet::new();
    let mut crd_names = BTreeSet::new();
    for crd in &crds {
        let plural = crd
            .document
            .pointer("/spec/names/plural")
            .and_then(Value::as_str)
            .expect("plural");
        allowed.insert(plural.to_owned());
        if crd
            .document
            .pointer("/spec/versions/0/subresources/status")
            .is_some()
        {
            allowed.insert(format!("{plural}/status"));
        }
        crd_names.insert(format!("{plural}.flowsdn.io"));
    }
    let dir = repo_dir().join("deploy/stormcos/manifests-kubernetes");
    let mut operator_update = None;
    for file in ["60-flowsdn-rbac.yaml", "63-flowsdn-operator-rbac.yaml"] {
        let text = std::fs::read_to_string(dir.join(file)).expect("RBAC manifest");
        for doc in yaml_documents(&text).expect("RBAC YAML") {
            if doc.get("kind") != Some(&Value::from("ClusterRole")) {
                continue;
            }
            for rule in doc.get("rules").and_then(Value::as_array).expect("rules") {
                let strings = |key: &str| -> Vec<String> {
                    rule.get(key)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(|v| v.as_str().expect("string").to_owned())
                        .collect()
                };
                if strings("apiGroups").contains(&"flowsdn.io".to_owned()) {
                    for resource in strings("resources") {
                        assert!(
                            allowed.contains(&resource),
                            "{file}: {resource} is not a flowsdn.io CRD resource"
                        );
                    }
                }
                if strings("resources") == ["customresourcedefinitions"]
                    && strings("verbs") == ["update"]
                {
                    operator_update = Some(
                        strings("resourceNames")
                            .into_iter()
                            .collect::<BTreeSet<_>>(),
                    );
                }
                if strings("resources") == ["customresourcedefinitions"] && file.starts_with("60-")
                {
                    for verb in strings("verbs") {
                        assert!(
                            ["get", "list", "watch"].contains(&verb.as_str()),
                            "the agent never writes CRDs"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(
        operator_update,
        Some(crd_names),
        "operator CRD update resourceNames"
    );
}

/// The owner's rule (#294): no Cilium in flowsdn's manifests or chart: object
/// names, labels, config keys, paths, CNI types or text.
#[test]
fn no_cilium_in_shipped_manifests() {
    fn walk(dir: &Path, found: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("entry").path();
            // Manifests and chart sources; prose (README.md) may describe
            // the other stormcos edition.
            let manifest = path
                .extension()
                .is_some_and(|e| ["yaml", "yml", "tpl", "json", "txt"].contains(&e.to_str().unwrap_or_default()));
            if path.is_dir() {
                walk(&path, found);
            } else if manifest && let Ok(text) = std::fs::read_to_string(&path) {
                for (number, line) in text.lines().enumerate() {
                    if line.to_ascii_lowercase().contains("cilium") {
                        found.push(format!("{}:{}: {line}", path.display(), number.saturating_add(1)));
                    }
                }
            }
        }
    }
    let mut found = Vec::new();
    for dir in ["deploy", "install/kubernetes"] {
        walk(&repo_dir().join(dir), &mut found);
    }
    for crd in crds() {
        assert!(!manifest(&crd).to_ascii_lowercase().contains("cilium"), "{}", crd.file);
    }
    let shown: Vec<&String> = found.iter().take(20).collect();
    assert!(found.is_empty(), "{} lines name Cilium: {shown:#?}", found.len());
}
