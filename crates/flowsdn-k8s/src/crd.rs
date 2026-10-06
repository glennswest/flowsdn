//! The flowsdn.io CRD set (#325), generated from the vendored reference schemas.
//!
//! `crds/` holds the 22 reference CRD documents byte for byte (spec 13 §3.1,
//! `crds/LICENSE-CILIUM`). [`owned_crds`] projects each into its flowsdn.io
//! registration document with [`crate::plan::migration_registration_payload`]
//! (ADR-0017), and [`manifest`] renders the YAML shipped in
//! `deploy/stormcos/manifests-kubernetes/crds/`. The vendored YAML is the schema
//! artifact; the shipped files are checked against this generation by the
//! crate's tests, so the two cannot drift.
use crate::Error;
use crate::plan::migration_registration_payload;
use serde_json::Value;
use std::fmt::Write;

/// The reference commit the vendored documents were copied from.
pub const REFERENCE_COMMIT: &str = "7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc";

/// Vendored reference documents: path under `crds/` and contents.
pub const REFERENCE: [(&str, &str); 22] = [
    (
        "v2/ciliumbgpadvertisements.yaml",
        include_str!("../crds/v2/ciliumbgpadvertisements.yaml"),
    ),
    (
        "v2/ciliumbgpclusterconfigs.yaml",
        include_str!("../crds/v2/ciliumbgpclusterconfigs.yaml"),
    ),
    (
        "v2/ciliumbgpnodeconfigoverrides.yaml",
        include_str!("../crds/v2/ciliumbgpnodeconfigoverrides.yaml"),
    ),
    (
        "v2/ciliumbgpnodeconfigs.yaml",
        include_str!("../crds/v2/ciliumbgpnodeconfigs.yaml"),
    ),
    (
        "v2/ciliumbgppeerconfigs.yaml",
        include_str!("../crds/v2/ciliumbgppeerconfigs.yaml"),
    ),
    (
        "v2/ciliumcidrgroups.yaml",
        include_str!("../crds/v2/ciliumcidrgroups.yaml"),
    ),
    (
        "v2/ciliumclusterwideenvoyconfigs.yaml",
        include_str!("../crds/v2/ciliumclusterwideenvoyconfigs.yaml"),
    ),
    (
        "v2/ciliumclusterwidenetworkpolicies.yaml",
        include_str!("../crds/v2/ciliumclusterwidenetworkpolicies.yaml"),
    ),
    (
        "v2/ciliumegressgatewaypolicies.yaml",
        include_str!("../crds/v2/ciliumegressgatewaypolicies.yaml"),
    ),
    (
        "v2/ciliumendpoints.yaml",
        include_str!("../crds/v2/ciliumendpoints.yaml"),
    ),
    (
        "v2/ciliumenvoyconfigs.yaml",
        include_str!("../crds/v2/ciliumenvoyconfigs.yaml"),
    ),
    (
        "v2/ciliumidentities.yaml",
        include_str!("../crds/v2/ciliumidentities.yaml"),
    ),
    (
        "v2/ciliumloadbalancerippools.yaml",
        include_str!("../crds/v2/ciliumloadbalancerippools.yaml"),
    ),
    (
        "v2/ciliumlocalredirectpolicies.yaml",
        include_str!("../crds/v2/ciliumlocalredirectpolicies.yaml"),
    ),
    (
        "v2/ciliumnetworkpolicies.yaml",
        include_str!("../crds/v2/ciliumnetworkpolicies.yaml"),
    ),
    (
        "v2/ciliumnodeconfigs.yaml",
        include_str!("../crds/v2/ciliumnodeconfigs.yaml"),
    ),
    (
        "v2/ciliumnodes.yaml",
        include_str!("../crds/v2/ciliumnodes.yaml"),
    ),
    (
        "v2alpha1/ciliumdatapathplugins.yaml",
        include_str!("../crds/v2alpha1/ciliumdatapathplugins.yaml"),
    ),
    (
        "v2alpha1/ciliumendpointslices.yaml",
        include_str!("../crds/v2alpha1/ciliumendpointslices.yaml"),
    ),
    (
        "v2alpha1/ciliumgatewayclassconfigs.yaml",
        include_str!("../crds/v2alpha1/ciliumgatewayclassconfigs.yaml"),
    ),
    (
        "v2alpha1/ciliuml2announcementpolicies.yaml",
        include_str!("../crds/v2alpha1/ciliuml2announcementpolicies.yaml"),
    ),
    (
        "v2alpha1/ciliumpodippools.yaml",
        include_str!("../crds/v2alpha1/ciliumpodippools.yaml"),
    ),
];

/// Where the generated manifests are shipped, relative to the repository root.
pub const MANIFEST_DIR: &str = "deploy/stormcos/manifests-kubernetes/crds";
/// The same files in the standalone Helm chart (#294).
pub const CHART_CRD_DIR: &str = "install/kubernetes/flowsdn/crds";

/// One generated CRD: its file name in [`MANIFEST_DIR`], the registration
/// document, and the vendored source it came from.
#[derive(Clone, Debug, PartialEq)]
pub struct OwnedCrd {
    pub file: String,
    pub document: Value,
    pub source: &'static str,
}

/// Every flowsdn.io CRD, in vendored-path order.
///
/// Besides the identity projection, every string in the shipped documents
/// (descriptions, enum values, printer columns) is rewritten to flowsdn's
/// names by [`flowsdn_text`]: the owner's rule is no Cilium in flowsdn's
/// manifests (#294). Property names are unchanged; none carries the name.
pub fn owned_crds() -> Result<Vec<OwnedCrd>, Error> {
    REFERENCE
        .iter()
        .map(|(source, text)| {
            let reference = yaml_to_json(text).map_err(|e| Error(format!("{source}: {e}")))?;
            let mut document = migration_registration_payload(&reference)
                .map_err(|e| Error(format!("{source}: {e}")))?;
            rewrite_strings(&mut document);
            add_printer_columns(&mut document);
            let name = document
                .pointer("/spec/names/plural")
                .and_then(Value::as_str)
                .ok_or_else(|| Error(format!("{source}: projected CRD has no plural")))?;
            Ok(OwnedCrd {
                file: format!("{name}.yaml"),
                document,
                source,
            })
        })
        .collect()
}

/// flowsdn's printer columns for kinds the reference gives none (#298), so
/// `kubectl get` / `sc get` show more than a name. Each column is
/// `(name, type, jsonPath)`; `Age` is appended, as the API server only adds
/// it when a CRD defines no columns at all.
pub const EXTRA_COLUMNS: [(&str, &[(&str, &str, &str)]); 5] = [
    ("flowsdncidrgroups", &[("CIDRs", "string", ".spec.externalCIDRs")]),
    (
        "flowsdndatapathplugins",
        &[
            ("Attachment", "string", ".spec.attachmentPolicy"),
            ("Version", "string", ".spec.version"),
        ],
    ),
    (
        "flowsdnendpointslices",
        &[
            ("Namespace", "string", ".namespace"),
            ("Identities", "string", ".endpoints[*].id"),
        ],
    ),
    ("flowsdnnodeconfigs", &[("Selector", "string", ".spec.nodeSelector.matchLabels")]),
    (
        "flowsdnpodippools",
        &[
            ("IPv4", "string", ".spec.ipv4.cidrs"),
            ("IPv6", "string", ".spec.ipv6.cidrs"),
        ],
    ),
];

fn add_printer_columns(document: &mut Value) {
    let plural = document
        .pointer("/spec/names/plural")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some((_, columns)) = EXTRA_COLUMNS.iter().find(|(p, _)| *p == plural) else {
        return;
    };
    let Some(version) = document
        .pointer_mut("/spec/versions/0")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    if version.contains_key("additionalPrinterColumns") {
        return;
    }
    let mut list: Vec<Value> = columns
        .iter()
        .map(|(name, kind, path)| serde_json::json!({"name":name,"type":kind,"jsonPath":path}))
        .collect();
    list.push(serde_json::json!({"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}));
    version.insert("additionalPrinterColumns".into(), Value::Array(list));
}

fn rewrite_strings(value: &mut Value) {
    match value {
        Value::String(text) => *text = flowsdn_text(text),
        Value::Array(items) => items.iter_mut().for_each(rewrite_strings),
        Value::Object(map) => map.values_mut().for_each(rewrite_strings),
        _ => {}
    }
}

/// Reference text in flowsdn's names: `CiliumX` -> `FlowsdnX` (kinds and
/// type names), `CILIUM` -> `FLOWSDN`, and any other `Cilium`/`cilium` ->
/// `flowsdn` (`cilium.io` -> `flowsdn.io`, `io.cilium.k8s.policy` ->
/// `io.flowsdn.k8s.policy`, `cilium-agent` -> `flowsdn-agent`).
pub fn flowsdn_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(['C', 'c']) {
        let (before, from) = rest.split_at(index);
        out.push_str(before);
        let replacement = if from.starts_with("CILIUM") {
            Some(("CILIUM", "FLOWSDN"))
        } else if let Some(after) = from.strip_prefix("Cilium") {
            Some((
                "Cilium",
                if after.starts_with(|c: char| c.is_ascii_uppercase()) {
                    "Flowsdn"
                } else {
                    "flowsdn"
                },
            ))
        } else if from.starts_with("cilium") {
            Some(("cilium", "flowsdn"))
        } else {
            None
        };
        match replacement {
            Some((matched, with)) => {
                out.push_str(with);
                rest = from.get(matched.len()..).unwrap_or_default();
            }
            None => {
                let mut chars = from.chars();
                if let Some(c) = chars.next() {
                    out.push(c);
                }
                rest = chars.as_str();
            }
        }
    }
    out.push_str(rest);
    out
}

/// The shipped file for `crd`: an attribution header and the YAML document.
pub fn manifest(crd: &OwnedCrd) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Generated by flowsdn_k8s::crd from the Apache-2.0 reference schemas in"
    );
    let _ = writeln!(
        out,
        "# crates/flowsdn-k8s/crds (commit {}; attribution in NOTICE), #325.",
        REFERENCE_COMMIT.get(..10).unwrap_or(REFERENCE_COMMIT)
    );
    out.push_str("# Do not edit: FLOWSDN_WRITE_CRDS=1 cargo test -p flowsdn-k8s --test crds\n");
    out.push_str("---\n");
    out.push_str(&to_yaml(&crd.document));
    out
}

/// Parse every document in a YAML stream into JSON.
pub fn yaml_documents(text: &str) -> Result<Vec<Value>, Error> {
    yaml_rust2::YamlLoader::load_from_str(text)
        .map_err(|e| Error(e.to_string()))?
        .iter()
        .map(yaml_value)
        .collect()
}

/// Parse one YAML document (a leading `---` is allowed) into JSON.
pub fn yaml_to_json(text: &str) -> Result<Value, Error> {
    let docs = yaml_rust2::YamlLoader::load_from_str(text).map_err(|e| Error(e.to_string()))?;
    let [doc] = docs.as_slice() else {
        return Err(Error(format!(
            "expected one YAML document, got {}",
            docs.len()
        )));
    };
    yaml_value(doc)
}

fn yaml_value(value: &yaml_rust2::Yaml) -> Result<Value, Error> {
    use yaml_rust2::Yaml;
    Ok(match value {
        Yaml::Null => Value::Null,
        Yaml::Boolean(v) => Value::Bool(*v),
        Yaml::Integer(v) => Value::from(*v),
        Yaml::Real(v) => serde_json::from_str(v)
            .or_else(|_| v.parse::<f64>().map(Value::from))
            .map_err(|e| Error(format!("invalid YAML number {v}: {e}")))?,
        Yaml::String(v) => Value::String(v.clone()),
        Yaml::Array(items) => Value::Array(items.iter().map(yaml_value).collect::<Result<_, _>>()?),
        Yaml::Hash(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                let key = key
                    .as_str()
                    .ok_or_else(|| Error("non-string YAML key".into()))?;
                if out.insert(key.to_owned(), yaml_value(value)?).is_some() {
                    return Err(Error(format!("duplicate YAML key {key}")));
                }
            }
            Value::Object(out)
        }
        _ => return Err(Error("unsupported YAML value (alias or invalid)".into())),
    })
}

/// Render JSON as block YAML: keys sorted, strings plain only when no YAML 1.1
/// or 1.2 reader could take them for another type, multi-line strings as
/// literal blocks when that is exact, every other string double-quoted.
pub fn to_yaml(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Object(map) if !map.is_empty() => emit_map(&mut out, value, 0),
        Value::Array(items) if !items.is_empty() => emit_seq(&mut out, items, 0),
        _ => {
            emit_inline(&mut out, value, 0);
            out.push('\n');
        }
    }
    out
}

fn pad(out: &mut String, indent: usize) {
    out.extend(std::iter::repeat_n(' ', indent));
}

fn emit_map(out: &mut String, value: &Value, indent: usize) {
    let Value::Object(map) = value else { return };
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let Some(child) = map.get(key) else { continue };
        pad(out, indent);
        out.push_str(&scalar_string(key));
        out.push(':');
        emit_child(out, child, indent);
    }
}

/// After `key:` or `-`: a nested block on the next lines, else ` scalar`.
fn emit_child(out: &mut String, child: &Value, indent: usize) {
    let deeper = indent.saturating_add(2);
    match child {
        Value::Object(map) if !map.is_empty() => {
            out.push('\n');
            emit_map(out, child, deeper);
        }
        Value::Array(items) if !items.is_empty() => {
            out.push('\n');
            emit_seq(out, items, indent);
        }
        _ => {
            out.push(' ');
            emit_inline(out, child, deeper);
            out.push('\n');
        }
    }
}

fn emit_seq(out: &mut String, items: &[Value], indent: usize) {
    let deeper = indent.saturating_add(2);
    for item in items {
        pad(out, indent);
        out.push('-');
        match item {
            Value::Object(map) if !map.is_empty() => {
                // The first key shares the `- ` line; the rest align under it.
                let mut block = String::new();
                emit_map(&mut block, item, deeper);
                out.push(' ');
                out.push_str(block.get(deeper..).unwrap_or_default());
            }
            Value::Array(inner) if !inner.is_empty() => {
                out.push('\n');
                emit_seq(out, inner, deeper);
            }
            _ => {
                out.push(' ');
                emit_inline(out, item, deeper);
                out.push('\n');
            }
        }
    }
}

/// A scalar or empty collection; `indent` is the block-scalar content indent.
fn emit_inline(out: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            if let Some(header) = literal_header(s) {
                out.push_str(header);
                for line in s.strip_suffix('\n').unwrap_or(s).split('\n') {
                    out.push('\n');
                    if !line.is_empty() {
                        pad(out, indent);
                        out.push_str(line);
                    }
                }
            } else {
                out.push_str(&scalar_string(s));
            }
        }
        Value::Array(_) => out.push_str("[]"),
        Value::Object(_) => out.push_str("{}"),
    }
}

/// `|` or `|-` when a literal block reproduces `s` exactly, else None.
fn literal_header(s: &str) -> Option<&'static str> {
    if !s.contains('\n')
        || s.starts_with([' ', '\n'])
        || s.chars().any(|c| c != '\n' && c.is_control())
        || s.split('\n')
            .any(|line| !line.is_empty() && line.trim().is_empty())
        || s.ends_with("\n\n")
    {
        return None;
    }
    Some(if s.ends_with('\n') { "|" } else { "|-" })
}

/// A plain scalar when it can only be read as this string, else JSON quoting
/// (a valid YAML double-quoted scalar).
fn scalar_string(s: &str) -> String {
    let mut chars = s.chars();
    let plain = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-'))
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "y" | "n" | "yes" | "no" | "on" | "off" | "true" | "false" | "null"
        );
    if plain {
        s.to_owned()
    } else {
        Value::String(s.to_owned()).to_string()
    }
}
