#![allow(clippy::unwrap_used)]

use flowsdn_config::{Class, Entry, Kind, Source, Value, Warning};
use flowsdn_config::catalogue::{self, DefaultOverride, Error, Pflag};
use std::collections::BTreeSet;

const SPEC: &str = include_str!("../../../docs/spec/00-foundation-table-config.md");

#[test]
fn every_normative_declaration_has_exact_metadata_and_unique_canonical_name() {
    let table = SPEC.split_once("### 6.4 The registry key table (539 keys)").unwrap().1.split_once("### 6.5").unwrap().0;
    let mut keys = BTreeSet::new();
    for line in table.lines().filter(|line| line.starts_with("| `")) {
        let mut fields = line.trim_matches('|').split('|').map(|field| field.trim().trim_matches('`'));
        let name = fields.next().unwrap();
        let pflag = fields.next().unwrap();
        let default = fields.next().unwrap();
        let class = fields.next().unwrap();
        assert!(fields.next().is_none());
        assert!(keys.insert(name), "duplicate normative name {name}");
        let entry = catalogue::get(name).unwrap();
        assert_eq!(entry.name, name);
        assert_eq!(entry.pflag.name(), pflag, "{name}");
        assert_eq!(entry.default_expression, default, "{name}");
        let expected = if class.contains("immutable") { Class::Immutable }
            else if class.contains("ignored") { Class::Ignored }
            else if class.contains("script") { Class::Script }
            else if class.contains("runtime") { Class::Runtime }
            else if class.contains("dynamic") { Class::Dynamic }
            else { Class::Active };
        assert_eq!(entry.class, expected, "{name}");
        let inventory_name = class.split_once("inventory row `").map(|(_, rest)| rest.split_once('`').unwrap().0);
        assert_eq!(entry.inventory_name, inventory_name, "{name}");
    }
    assert_eq!(keys.len(), 539);
    assert_eq!(catalogue::ENTRIES.len(), 539);
    assert_eq!(catalogue::ENTRIES.iter().map(|entry| entry.name).collect::<BTreeSet<_>>(), keys);
}

#[test]
fn semantic_classification_census_and_aliases_match_foundation_contract() {
    for (class, expected) in [(Class::Immutable, 41), (Class::Script, 27), (Class::Ignored, 18), (Class::Runtime, 8), (Class::Dynamic, 1)] {
        assert_eq!(catalogue::ENTRIES.iter().filter(|entry| entry.class == class).count(), expected);
    }
    assert_eq!(catalogue::get("install-iptables-rules").unwrap().class, Class::Ignored);
    assert_eq!(catalogue::get("install-no-conntrack-iptables-rules").unwrap().class, Class::Active, "this flag selects nftables notrack and must not be ignored");
    assert_eq!(catalogue::get("hive-start-timeout").unwrap().class, Class::Active);
    assert_eq!(catalogue::get("hive-log-threshold").unwrap().class, Class::Ignored);
    assert_eq!(catalogue::get("dynamic-lifecycle-config").unwrap().inventory_name, Some("ConfigKey"));
    assert!(catalogue::get("ConfigKey").is_none(), "inventory constant is not a public alias");
    assert_eq!(catalogue::get("ENABLE_IPV4").unwrap().name, "enable-ipv4");
    assert_eq!(catalogue::get("CT_GLOBAL_MAX_ENTRIES_TCP").unwrap().name, "bpf-ct-global-tcp-max");
    assert_eq!(catalogue::ENTRIES.iter().flat_map(|entry| entry.aliases()).count(), 3);
    assert_eq!(catalogue::get("monitor-aggregation").unwrap().aliases().collect::<Vec<_>>(), ["monitor-aggregation-level"]);
}

#[test]
fn literal_defaults_are_typed_and_evaluated_without_inventing_symbolic_values() {
    let coverage = catalogue::coverage();
    assert_eq!((coverage.declared, coverage.literal_defaults, coverage.unresolved_defaults.len()), (539, 488, 51));
    assert_eq!(coverage.help_metadata_missing, 539);
    assert_eq!(coverage.hidden_metadata_missing, 539);
    assert_eq!(coverage.area_validators_required.len(), 4);
    assert!(catalogue::get("bpf-lb-maglev-table-size").unwrap().default.is_none());
    assert!(catalogue::get("enable-gops").unwrap().default.is_none(), "ignored does not authorize inventing a default");
    let partial = catalogue::partial_known_defaults_registry().unwrap();
    assert_eq!(partial.omitted().len(), 51);
    let resolved = partial.resolve([]).unwrap();
    assert_eq!(resolved.values().len(), 488);
    assert_eq!(resolved.get("bpf-auth-map-max").unwrap().value, Value::Int(524_288));
    assert_eq!(resolved.get("bpf-ct-global-tcp-max").unwrap().value, Value::Int(524_288));
    assert_eq!(resolved.get("bpf-ct-global-any-max").unwrap().value, Value::Int(262_144));
    assert_eq!(resolved.get("http-request-timeout").unwrap().value, Value::UInt(3_600));
    assert_eq!(resolved.get("allocator-list-timeout").unwrap().value, Value::Duration(180_000_000_000));
    assert_eq!(resolved.get("monitor-aggregation-flags").unwrap().value, Value::List(vec!["syn".into(), "fin".into(), "rst".into()]));
    assert_eq!(resolved.get("kvstore-opt").unwrap().value, Value::Map(Default::default()));
    assert_eq!(resolved.get("debug").unwrap().class, Class::Runtime);
    assert_eq!(resolved.get("subnet-topology").unwrap().class, Class::Dynamic);
}

#[test]
fn partial_registry_rejects_omitted_known_keys_instead_of_calling_them_unknown() {
    let partial = catalogue::partial_known_defaults_registry().unwrap();
    for key in ["BPF_LB_MAGLEV_TABLE_SIZE", "MONITOR_AGGREGATION_LEVEL"] {
        assert!(matches!(partial.resolve([Entry::new(Source::Flag, key, "anything")]), Err(Error::OmittedKey(_))));
    }
    let resolved = partial.resolve([
        Entry::new(Source::Env, "INSTALL_IPTABLES_RULES", "true"),
        Entry::new(Source::Dir, "not-in-catalogue", "newer-chart"),
    ]).unwrap();
    assert!(resolved.warnings().iter().any(|warning| matches!(warning, Warning::IgnoredKey { key, .. } if key == "install-iptables-rules")));
    assert!(resolved.unknown_keys().contains("not-in-catalogue"));
    assert!(matches!(partial.resolve([Entry::new(Source::Flag, "install-iptables-rules", "not-bool")]), Err(Error::InvalidValue(_))));
}

fn fixture_resolutions() -> Vec<DefaultOverride<'static>> {
    // These are deliberately artificial schema-test values, not proposed
    // production defaults. Production resolutions must cite owning specs.
    catalogue::ENTRIES.iter().filter(|entry| entry.default.is_none()).map(|entry| DefaultOverride {
        key: entry.name,
        value: match entry.pflag {
            Pflag::Bool => "false",
            Pflag::String | Pflag::StringSlice | Pflag::StringToString | Pflag::Var => "",
            _ => "0",
        },
        provenance: "Rust schema-construction test only; not a production resolution",
    }).collect()
}

#[test]
fn complete_schema_fails_closed_then_requires_explicit_typed_resolutions() {
    assert!(matches!(catalogue::complete_registry(&[]), Err(Error::UnresolvedDefaults(gaps)) if gaps.len() == 51));
    let mut overrides = fixture_resolutions();
    let built = catalogue::complete_registry(&overrides).unwrap();
    let resolved = built.registry.resolve([]).unwrap();
    assert_eq!(resolved.values().len(), 539);
    assert!(resolved.unknown_keys().is_empty());
    assert_eq!(built.default_overrides.len(), 51);
    assert!(built.default_overrides.iter().all(|item| !item.provenance.is_empty()));
    let gops = overrides.iter_mut().find(|value| value.key == "enable-gops").unwrap();
    gops.value = "invalid";
    assert!(matches!(catalogue::complete_registry(&overrides), Err(Error::InvalidValue(error)) if error.key == "enable-gops"));
}

#[test]
fn override_validation_rejects_unknown_duplicate_and_unattributed_definitions() {
    for (overrides, error_kind) in [
        (vec![DefaultOverride { key: "not-a-key", value: "", provenance: "fixture" }], "unknown"),
        (vec![DefaultOverride { key: "agent-health-port", value: "1", provenance: "" }], "provenance"),
        (vec![DefaultOverride { key: "agent-health-port", value: "1", provenance: "fixture" }, DefaultOverride { key: "AGENT_HEALTH_PORT", value: "2", provenance: "fixture" }], "duplicate"),
    ] {
        let error = catalogue::complete_registry(&overrides).unwrap_err();
        assert!(matches!((error_kind, error), ("unknown", Error::UnknownOverride(_)) | ("provenance", Error::MissingProvenance(_)) | ("duplicate", Error::DuplicateOverride(_))));
    }
    assert_eq!(Pflag::Uint8.kind(), Kind::UInt { bits: 8 });
    assert_eq!(Pflag::Uint16.kind(), Kind::UInt { bits: 16 });
    assert_eq!(Pflag::Uint32.kind(), Kind::UInt { bits: 32 });
    assert_eq!(Pflag::Uint64.kind(), Kind::UInt { bits: 64 });
    assert_eq!(Pflag::Float32.kind(), Kind::Float { bits: 32 });
}

#[test]
fn runtime_snapshot_retains_runtime_and_dynamic_classification() {
    let built = catalogue::complete_registry(&fixture_resolutions()).unwrap();
    let resolved = built.registry.resolve([]).unwrap();
    let metadata = flowsdn_config::runtime::Metadata { version: "schema-test".into(), written_at: "2026-09-09T01:32:26Z".into() };
    let serialized = flowsdn_config::runtime::encode(&resolved, &metadata).unwrap();
    let decoded = flowsdn_config::runtime::decode(&serialized, &built.registry).unwrap();
    assert_eq!(decoded.resolved.values().len(), 512, "all 539 declarations minus 27 script keys");
    assert_eq!(decoded.resolved.get("debug").unwrap().class, Class::Runtime);
    assert_eq!(decoded.resolved.get("subnet-topology").unwrap().class, Class::Dynamic);
    assert_eq!(decoded.resolved.get("install-iptables-rules").unwrap().class, Class::Ignored);
    assert!(decoded.resolved.get("any-proto").is_none());
}
