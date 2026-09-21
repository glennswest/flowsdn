#![allow(clippy::unwrap_used)]

use flowsdn_config::{Class, Entry, KeySpec, Kind, Registry, Source, Value, Warning, catalogue};

fn registry() -> Registry {
    let mut ignored = KeySpec::new("ignored", Kind::Bool, "false");
    ignored.class = Class::Ignored;
    Registry::new([
        KeySpec::new("strict-config", Kind::Bool, "false"),
        KeySpec::new("monitor-aggregation", Kind::String, "medium"),
        ignored,
    ])
    .unwrap()
}

#[test]
fn effective_strictness_uses_all_source_layers_and_last_scalar_within_layer() {
    let layers = [Source::Default, Source::File, Source::Dir, Source::Env, Source::Flag];
    for (index, weaker) in layers.iter().enumerate() {
        for stronger in &layers[index..] {
            for enabled in [false, true] {
                let entries = [
                    Entry::new(*weaker, "strict-config", (!enabled).to_string()),
                    Entry::new(*stronger, "STRICT_CONFIG", enabled.to_string()),
                    Entry::new(Source::File, "misspelled", "secret-value"),
                ];
                let result = registry().resolve(entries);
                if enabled {
                    let error = result.unwrap_err();
                    assert_eq!(error.key, "misspelled");
                    assert!(error.message.contains("source file"));
                    assert!(!error.to_string().contains("secret-value"));
                } else {
                    let resolved = result.unwrap();
                    assert_eq!(resolved.unknown_keys().len(), 1);
                    assert_eq!(resolved.get("strict-config").unwrap().source, *stronger);
                    assert!(matches!(resolved.warnings(), [Warning::UnknownKey { .. }]));
                }
            }
        }
    }
    // Source strength wins even if the stronger layer appears first in input.
    assert!(registry().resolve([
        Entry::new(Source::Flag, "strict-config", "true"),
        Entry::new(Source::File, "strict-config", "false"),
        Entry::new(Source::Dir, "unknown", "value"),
    ]).is_err());
}

#[test]
fn permissive_default_retains_normalized_unknown_diagnostics() {
    let resolved = registry().resolve([
        Entry::new(Source::File, "FUTURE_KEY", "old"),
        Entry::new(Source::Flag, "future-key", "new"),
    ]).unwrap();
    assert_eq!(resolved.get("strict-config").unwrap().value, Value::Bool(false));
    assert_eq!(resolved.unknown_keys().len(), 1);
    assert_eq!(resolved.warnings().len(), 1);
    assert_eq!(resolved.unknown_values()["future-key"].raw, "new");
    assert_eq!(resolved.unknown_values()["future-key"].source, Source::Flag);
}

#[test]
fn strictness_rejects_lower_layer_typos_even_beside_correct_stronger_keys() {
    let error = registry().resolve([
        Entry::new(Source::File, "monitor-agregation", "none"),
        Entry::new(Source::Flag, "monitor-aggregation", "low"),
        Entry::environment("CILIUM_STRICT_CONFIG", "true").unwrap(),
    ]).unwrap_err();
    assert_eq!(error.key, "monitor-agregation");
    assert!(error.message.contains("strict-config is enabled"));

    // Sorting diagnostics by normalized name makes the first failure stable.
    let error = registry().resolve([
        Entry::new(Source::Flag, "strict-config", "true"),
        Entry::new(Source::File, "Z_UNKNOWN", "old"),
        Entry::new(Source::Env, "a_unknown", "secret"),
        Entry::new(Source::Flag, "A-UNKNOWN", "new-secret"),
    ]).unwrap_err();
    assert_eq!(error.key, "a-unknown");
    assert!(error.message.contains("source flag"));
    assert!(!error.message.contains("secret"));
}

#[test]
fn aliases_and_ignored_keys_are_known_but_invalid_shadowed_values_still_fail() {
    let resolved = registry().resolve([
        Entry::new(Source::Flag, "strict-config", "true"),
        Entry::new(Source::Env, "monitor-aggregation-level", "low"),
        Entry::new(Source::Dir, "ignored", "true"),
    ]).unwrap();
    assert!(resolved.unknown_keys().is_empty());
    assert_eq!(resolved.get("monitor-aggregation").unwrap().value, Value::String("low".into()));
    assert!(matches!(resolved.warnings(), [Warning::IgnoredKey { .. }]));
    for key in ["strict-config", "ignored"] {
        let error = registry().resolve([
            Entry::new(Source::File, key, "invalid"),
            Entry::new(Source::Flag, key, "false"),
        ]).unwrap_err();
        assert_eq!(error.key, key);
    }
}

#[test]
fn strict_config_cannot_be_registered_with_an_ineffective_kind_or_class() {
    assert!(Registry::new([KeySpec::new("strict-config", Kind::String, "true")]).is_err());
    let mut key = KeySpec::new("strict-config", Kind::Bool, "false");
    key.class = Class::Ignored;
    assert!(Registry::new([key]).is_err());
}

#[test]
fn catalogue_registers_extension_without_changing_reference_coverage() {
    assert_eq!(catalogue::ENTRIES.len(), 539);
    assert_eq!(catalogue::coverage().declared, 539);
    assert_eq!(catalogue::EXTENSIONS.len(), 2);
    let definition = catalogue::get("STRICT_CONFIG").unwrap();
    assert_eq!(definition.default, Some("false"));
    assert_eq!(definition.hidden(), Some(false));
    assert!(definition.help().unwrap().contains("unknown"));
    let registry = catalogue::partial_known_defaults_registry().unwrap();
    assert_eq!(registry.resolve([]).unwrap().get("strict-config").unwrap().value, Value::Bool(false));
    assert!(matches!(registry.resolve([
        Entry::new(Source::Dir, "strict-config", "true"),
        Entry::new(Source::File, "enable-ipv44", "false"),
    ]), Err(catalogue::Error::InvalidValue(error)) if error.key == "enable-ipv44"));
    // A known unresolved key remains an omitted-default error, not an unknown.
    assert!(matches!(registry.resolve([
        Entry::new(Source::Flag, "strict-config", "true"),
        Entry::new(Source::Flag, "enable-gops", "false"),
    ]), Err(catalogue::Error::OmittedKey(key)) if key == "enable-gops"));
}
