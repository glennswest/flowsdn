#![allow(clippy::unwrap_used)]

use flowsdn_config::{Class, Entry, Kind, KeySpec, Registry, Resolved, Source, Value};
use flowsdn_config::immutable::{self, Previous, Warning};

fn config(routing: &str, debug: &str) -> Resolved {
    let mut routing = KeySpec::new("routing-mode", Kind::String, routing);
    routing.class = Class::Immutable;
    Registry::new([routing, KeySpec::new("debug", Kind::Bool, debug)]).unwrap().resolve([]).unwrap()
}

#[test]
fn immutable_changes_refuse_only_when_restoring_existing_endpoints() {
    let previous = config("tunnel", "false");
    let current = config("native", "true");
    for (restore, endpoints) in [(false, false), (false, true), (true, false)] {
        let report = immutable::check(Previous::Parsed(&previous), &current, restore, endpoints).unwrap();
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.warnings, [Warning::ChangedWithoutRestoredEndpoints]);
        assert_eq!(report.changes.first().unwrap().key, "routing-mode");
    }
    let error = immutable::check(Previous::Parsed(&previous), &current, true, true).unwrap_err();
    assert_eq!(error.changes.first().unwrap().previous, Some(Value::String("tunnel".into())));
    assert_eq!(error.changes.first().unwrap().current, Some(Value::String("native".into())));
}

#[test]
fn runtime_values_and_source_changes_do_not_trigger_immutable_diff() {
    let previous = config("tunnel", "false");
    let current = config("tunnel", "true");
    assert!(immutable::check(Previous::Parsed(&previous), &current, true, true).unwrap().changes.is_empty());
    let mut key = KeySpec::new("routing-mode", Kind::String, "tunnel");
    key.class = Class::Immutable;
    let registry = Registry::new([key]).unwrap();
    let sourced = registry.resolve([Entry::new(Source::Flag, "routing-mode", "tunnel")]).unwrap();
    assert!(sourced.warnings().is_empty());
    assert!(immutable::check(Previous::Parsed(&previous), &sourced, true, true).unwrap().changes.is_empty());
}

#[test]
fn absent_or_unparseable_previous_configuration_never_blocks_startup() {
    let current = config("native", "false");
    let absent = immutable::check(Previous::Absent, &current, true, true).unwrap();
    assert!(absent.changes.is_empty());
    assert!(absent.warnings.is_empty());
    let malformed = immutable::check(Previous::Unparseable, &current, true, true).unwrap();
    assert!(malformed.changes.is_empty());
    assert_eq!(malformed.warnings, [Warning::PreviousUnparseable]);
}

#[test]
fn removed_new_and_reclassified_immutable_keys_are_compared() {
    let previous = config("tunnel", "false");
    let empty = Registry::new([]).unwrap().resolve([]).unwrap();
    let removed = immutable::check(Previous::Parsed(&previous), &empty, true, true).unwrap_err();
    assert_eq!(removed.changes.first().unwrap().current, None);
    let added = immutable::check(Previous::Parsed(&empty), &previous, true, true).unwrap_err();
    assert_eq!(added.changes.first().unwrap().previous, None);
    let reclassified = Registry::new([KeySpec::new("routing-mode", Kind::String, "native")]).unwrap().resolve([]).unwrap();
    assert!(immutable::check(Previous::Parsed(&previous), &reclassified, true, true).is_err());
}
