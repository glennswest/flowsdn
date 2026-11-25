//! The flowsdn.io endpoint, identity and node kinds' Rust types against
//! their CRD schemas (#332, spec 13 §9):
//!
//! - T-CRD-3 (type ↔ schema): an instance holding every schema property
//!   round-trips through the type unchanged (no field dropped or retyped),
//!   one holding only the required properties does too (the type requires no
//!   more than the schema), and what the type writes is admitted by the
//!   schema's strict validation (it adds no field the schema lacks).
//! - T-CRD-4: every golden CR (`testdata/crs/<plural>`) round-trips field for
//!   field after schema defaults.
//! - T-CRD-5: an unknown key in every object and an unknown value in every
//!   enum still deserialize, with the known fields unchanged.
//! - T-CRD-7: random schema-valid documents (seeded, 300 per kind) round-trip
//!   and their re-serialization is still admitted; so is each type's
//!   `Kind::named` object.
use flowsdn_k8s::crd::{owned_crds, yaml_to_json};
use flowsdn_k8s::kinds::{
    API_VERSION, FlowsdnDatapathPlugin, FlowsdnEgressGatewayPolicy, FlowsdnEndpoint,
    FlowsdnEndpointSlice, FlowsdnIdentity, FlowsdnLocalRedirectPolicy, FlowsdnNode,
    FlowsdnNodeConfig, Kind,
};
use flowsdn_k8s::schema::{apply_defaults, validate};
use serde_json::{Map, Value, json};
use std::path::PathBuf;

fn schema(plural: &str) -> Value {
    owned_crds()
        .expect("CRDs")
        .into_iter()
        .find(|c| c.document.pointer("/spec/names/plural") == Some(&Value::from(plural)))
        .and_then(|c| {
            c.document
                .pointer("/spec/versions/0/schema/openAPIV3Schema")
                .cloned()
        })
        .unwrap_or_else(|| panic!("schema of {plural}"))
}

fn round<K: Kind>(value: &Value) -> Value {
    let object: K = serde_json::from_value(value.clone())
        .unwrap_or_else(|e| panic!("{}: {e}\n{value:#}", K::KIND));
    serde_json::to_value(&object).expect("serialize")
}

fn assert_round<K: Kind>(what: &str, value: &Value) {
    let back = round::<K>(value);
    assert_eq!(&back, value, "{} {what}: round trip changed it", K::KIND);
}

/// A tiny deterministic generator (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0.wrapping_shr(12);
        self.0 ^= self.0.wrapping_shl(25);
        self.0 ^= self.0.wrapping_shr(27);
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next().checked_rem(n).unwrap_or(0)
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

/// How optional parts are chosen: all, none, or at random.
enum Fill<'a> {
    Every,
    Required,
    Random(&'a mut Rng),
}

struct Generator<'a> {
    fill: Fill<'a>,
    counter: u64,
}
impl Generator<'_> {
    fn include(&mut self) -> bool {
        match &mut self.fill {
            Fill::Every => true,
            Fill::Required => false,
            Fill::Random(rng) => rng.coin(),
        }
    }
    fn count(&mut self) -> u64 {
        match &mut self.fill {
            Fill::Every => 1,
            Fill::Required => 0,
            Fill::Random(rng) => rng.below(3),
        }
    }
    fn unique(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        self.counter
    }
    fn pick(&mut self, n: usize) -> usize {
        match &mut self.fill {
            Fill::Random(rng) => usize::try_from(rng.below(n as u64)).unwrap_or(0),
            _ => 0,
        }
    }

    fn value(&mut self, schema: &Value, depth: usize) -> Value {
        if let Some(choices) = schema.get("enum").and_then(Value::as_array)
            && !choices.is_empty()
        {
            let index = self.pick(choices.len());
            return choices.get(index).cloned().unwrap_or(Value::Null);
        }
        match schema.get("type").and_then(Value::as_str) {
            Some("string") => {
                let n = self.unique();
                let octet = n.checked_rem(250).unwrap_or(0);
                match schema.get("format").and_then(Value::as_str) {
                    Some("cidr") => json!(format!("10.{octet}.0.0/16")),
                    Some("ipv4") => json!(format!("10.0.0.{octet}")),
                    Some("ipv6") => json!(format!("fd00::{octet:x}")),
                    Some("date-time") => json!("2026-11-20T08:00:00Z"),
                    // The first candidate the string's own schema admits
                    // (its pattern, CEL rules): a name first, so kinds
                    // without such rules get what they always did; then a
                    // port, IPv4 CIDR and address, IPv6 address and prefix
                    // (#336: ports, CIDRs and egress IPs).
                    _ => [
                        format!("v{n}"),
                        format!("{}", n.checked_rem(65_534).unwrap_or(0).saturating_add(1)),
                        format!("10.{octet}.0.0/16"),
                        format!("10.0.0.{octet}"),
                        format!("fd00::{octet:x}"),
                        format!("fd00:{octet:x}::/64"),
                    ]
                    .into_iter()
                    .map(|candidate| json!(candidate))
                    .find(|candidate| validate(schema, candidate).is_empty())
                    .unwrap_or_else(|| json!(format!("v{n}"))),
                }
            }
            Some("integer") => {
                let min = schema.get("minimum").and_then(Value::as_i64).unwrap_or(0);
                let max = schema
                    .get("maximum")
                    .and_then(Value::as_i64)
                    .unwrap_or(65_535);
                let span = u64::try_from(max.saturating_sub(min)).unwrap_or(0);
                let offset = i64::try_from(
                    self.unique()
                        .checked_rem(span.saturating_add(1))
                        .unwrap_or(0),
                )
                .unwrap_or(0);
                json!(min.saturating_add(offset))
            }
            Some("number") => json!(1.5),
            Some("boolean") => json!(self.unique() & 1 == 0),
            Some("array") => {
                let item = schema.get("items").cloned().unwrap_or(Value::Null);
                let n = if depth > 6 { 0 } else { self.count() };
                Value::Array(
                    (0..n)
                        .map(|_| self.value(&item, depth.saturating_add(1)))
                        .collect(),
                )
            }
            _ => self.object(schema, depth),
        }
    }

    fn object(&mut self, schema: &Value, depth: usize) -> Value {
        let mut out = Map::new();
        let names = |s: &Value| -> Vec<String> {
            s.get("required")
                .and_then(Value::as_array)
                .map(|r| r.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default()
        };
        let mut required = names(schema);
        // `oneOf` over required properties (#336: an address or a Service):
        // one branch's are written, the others' left out.
        let mut excluded: Vec<String> = Vec::new();
        if let Some(branches) = schema.get("oneOf").and_then(Value::as_array)
            && !branches.is_empty()
        {
            let pick = self.pick(branches.len());
            let keep = branches.get(pick).map(names).unwrap_or_default();
            for (index, branch) in branches.iter().enumerate() {
                if index != pick {
                    excluded.extend(names(branch).into_iter().filter(|n| !keep.contains(n)));
                }
            }
            required.extend(keep);
        }
        let required: Vec<&str> = required.iter().map(String::as_str).collect();
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, child) in properties {
                if name == "apiVersion" || name == "kind" || excluded.contains(name) {
                    continue;
                }
                if name == "metadata" && depth == 0 {
                    out.insert(name.clone(), json!({"name": "generated"}));
                    continue;
                }
                if required.contains(&name.as_str()) || self.include() {
                    let value = self.value(child, depth.saturating_add(1));
                    out.insert(name.clone(), value);
                }
            }
        } else if let Some(extra) = schema.get("additionalProperties").filter(|s| s.is_object()) {
            let n = if depth > 6 { 0 } else { self.count() };
            for _ in 0..n {
                let key = format!("k{}", self.unique());
                let value = self.value(extra, depth.saturating_add(1));
                out.insert(key, value);
            }
        }
        Value::Object(out)
    }
}

fn generate(schema: &Value, fill: Fill<'_>) -> Value {
    let mut generator = Generator { fill, counter: 0 };
    generator.object(schema, 0)
}

fn admitted(kind: &str, schema: &Value, value: &Value) {
    let problems = validate(schema, value);
    assert!(problems.is_empty(), "{kind}: {problems:?}\n{value:#}");
}

/// T-CRD-3: every property, only the required ones, and what the type writes.
fn type_matches_schema<K: Kind>(schema: &Value) {
    for (what, fill) in [
        ("every field", Fill::Every),
        ("required only", Fill::Required),
    ] {
        let value = generate(schema, fill);
        admitted(K::KIND, schema, &value);
        assert_round::<K>(what, &value);
    }
    let named = serde_json::to_value(K::named("n")).expect("serialize");
    assert_eq!(named.get("apiVersion"), Some(&json!(API_VERSION)));
    assert_eq!(named.get("kind"), Some(&json!(K::KIND)));
    admitted(K::KIND, schema, &named);
}

/// T-CRD-4: the golden CRs.
fn golden_round_trip<K: Kind>(schema: &Value) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/crs")
        .join(K::PLURAL);
    for file in ["minimal.yaml", "realistic.yaml"] {
        let text = std::fs::read_to_string(dir.join(file)).expect("golden CR");
        let mut value = yaml_to_json(&text).expect("YAML");
        apply_defaults(schema, &mut value);
        assert_round::<K>(file, &value);
    }
}

/// The schema of `key` in an object of `schema`: a property, or a map value.
fn child<'a>(schema: &'a Value, key: &str) -> Option<&'a Value> {
    schema
        .get("properties")
        .and_then(|p| p.get(key))
        .or_else(|| schema.get("additionalProperties").filter(|s| s.is_object()))
}
/// Put an unknown key into every object the schema gives properties (a
/// struct, not a map) and into `metadata`.
fn add_unknown(schema: &Value, value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if let Some(sub) = child(schema, key) {
                    add_unknown(sub, value);
                }
            }
            if schema.get("properties").is_some() {
                map.insert("zzUnknownField".into(), json!({"nested": [1, "two"]}));
            }
        }
        Value::Array(items) => {
            if let Some(item) = schema.get("items") {
                items.iter_mut().for_each(|i| add_unknown(item, i));
            }
        }
        _ => {}
    }
}
fn strip_unknown(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("zzUnknownField");
            map.values_mut().for_each(strip_unknown);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_unknown),
        _ => {}
    }
}
/// Replace every enum-valued string with a value the schema does not list.
/// The number replaced.
fn unknown_enums(schema: &Value, value: &mut Value) -> usize {
    if schema.get("enum").is_some() && value.is_string() {
        *value = json!("SomeFutureValue");
        return 1;
    }
    let mut n = 0usize;
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if let Some(sub) = child(schema, key) {
                    n = n.saturating_add(unknown_enums(sub, value));
                }
            }
        }
        Value::Array(items) => {
            if let Some(item) = schema.get("items") {
                for child in items {
                    n = n.saturating_add(unknown_enums(item, child));
                }
            }
        }
        _ => {}
    }
    n
}

/// T-CRD-5 on the golden CRs and on an every-field instance.
fn tolerates_unknowns<K: Kind>(schema: &Value) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/crs")
        .join(K::PLURAL);
    let mut documents: Vec<Value> = ["minimal.yaml", "realistic.yaml"]
        .iter()
        .map(|f| {
            yaml_to_json(&std::fs::read_to_string(dir.join(f)).expect("golden")).expect("YAML")
        })
        .collect();
    documents.push(generate(schema, Fill::Every));
    for original in documents {
        let mut noisy = original.clone();
        add_unknown(schema, &mut noisy);
        if let Some(Value::Object(meta)) = noisy.get_mut("metadata") {
            meta.insert("zzUnknownField".into(), json!(1));
        }
        let back = round::<K>(&noisy);
        let mut expected = original.clone();
        strip_unknown(&mut expected);
        assert_eq!(
            back,
            expected,
            "{}: an unknown key changed known fields",
            K::KIND
        );

        let mut future = original.clone();
        if unknown_enums(schema, &mut future) > 0 {
            assert_round::<K>("unknown enum values", &future);
        }
    }
}

/// T-CRD-7: random schema-valid documents.
fn random_documents<K: Kind>(schema: &Value, seed: u64) {
    let mut rng = Rng(seed);
    for _ in 0..300 {
        let value = generate(schema, Fill::Random(&mut rng));
        admitted(K::KIND, schema, &value);
        let back = round::<K>(&value);
        assert_eq!(back, value, "{}: random document changed", K::KIND);
        admitted(K::KIND, schema, &back);
    }
}

fn all<K: Kind>(seed: u64) {
    let schema = schema(K::PLURAL);
    type_matches_schema::<K>(&schema);
    golden_round_trip::<K>(&schema);
    tolerates_unknowns::<K>(&schema);
    random_documents::<K>(&schema, seed);
}

#[test]
fn flowsdn_endpoint() {
    all::<FlowsdnEndpoint>(0x332_0001);
}
#[test]
fn flowsdn_endpoint_slice() {
    all::<FlowsdnEndpointSlice>(0x332_0002);
}
#[test]
fn flowsdn_identity() {
    all::<FlowsdnIdentity>(0x332_0003);
}
#[test]
fn flowsdn_node() {
    all::<FlowsdnNode>(0x332_0004);
}
#[test]
fn flowsdn_node_config() {
    all::<FlowsdnNodeConfig>(0x332_0005);
}
#[test]
fn flowsdn_egress_gateway_policy() {
    all::<FlowsdnEgressGatewayPolicy>(0x336_0001);
}
#[test]
fn flowsdn_local_redirect_policy() {
    all::<FlowsdnLocalRedirectPolicy>(0x336_0002);
}
#[test]
fn flowsdn_datapath_plugin() {
    all::<FlowsdnDatapathPlugin>(0x336_0003);
}

#[test]
fn paths_follow_the_scope() {
    assert_eq!(
        FlowsdnEndpoint::path("prod", "web"),
        "/apis/flowsdn.io/v1alpha1/namespaces/prod/flowsdnendpoints/web"
    );
    assert_eq!(
        FlowsdnNode::path("ignored", "n1"),
        "/apis/flowsdn.io/v1alpha1/flowsdnnodes/n1"
    );
    assert_eq!(
        FlowsdnIdentity::collection(""),
        "/apis/flowsdn.io/v1alpha1/flowsdnidentities"
    );
}
