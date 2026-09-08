#![allow(clippy::unwrap_used)]

use flowsdn_config::{Class, Entry, KeySpec, Kind, Registry, Source, Value, Warning};

fn one(kind: Kind, default: &str, value: &str) -> Result<Value, flowsdn_config::Error> {
    let registry = Registry::new([KeySpec::new("key", kind, default)])?;
    Ok(registry
        .resolve([Entry::new(Source::Flag, "key", value)])?
        .get("key")
        .unwrap()
        .value
        .clone())
}

#[test]
fn precedence_is_per_key_and_independent_of_input_source_order() {
    let registry = Registry::new([
        KeySpec::new("enable-ipv4", Kind::Bool, "true"),
        KeySpec::new("name", Kind::String, "default"),
    ])
    .unwrap();
    let layers = [
        Source::Default,
        Source::File,
        Source::Dir,
        Source::Env,
        Source::Flag,
    ];
    for winning in layers {
        let entries = layers
            .into_iter()
            .rev()
            .filter(|source| *source <= winning)
            .map(|source| Entry::new(source, "NAME", source.to_string()));
        let resolved = registry.resolve(entries).unwrap();
        assert_eq!(resolved.get("name").unwrap().source, winning);
        assert_eq!(
            resolved.get("name").unwrap().value,
            Value::String(winning.to_string())
        );
        assert_eq!(
            resolved.get("enable_ipv4").unwrap().value,
            Value::Bool(true)
        );
    }
    let env = Entry::environment("CILIUM_ENABLE_IPV4", "off").unwrap();
    assert_eq!(
        registry
            .resolve([env])
            .unwrap()
            .get("ENABLE-IPV4")
            .unwrap()
            .value,
        Value::Bool(false)
    );
    assert!(Entry::environment("OTHER_ENABLE_IPV4", "false").is_none());
}

#[test]
fn canonical_input_beats_alias_but_default_does_not() {
    let registry =
        Registry::new([KeySpec::new("monitor-aggregation", Kind::String, "medium")]).unwrap();
    let alias = Entry::new(Source::Flag, "MONITOR_AGGREGATION_LEVEL", "low");
    assert_eq!(
        registry
            .resolve([alias.clone()])
            .unwrap()
            .get("monitor-aggregation")
            .unwrap()
            .value,
        Value::String("low".into())
    );
    let canonical = Entry::new(Source::File, "monitor-aggregation", "none");
    assert_eq!(
        registry
            .resolve([alias, canonical])
            .unwrap()
            .get("monitor-aggregation")
            .unwrap()
            .value,
        Value::String("none".into())
    );
    assert!(
        Registry::new([
            KeySpec::new("name", Kind::String, ""),
            KeySpec::new("NAME", Kind::String, "")
        ])
        .is_err()
    );
    assert!(Registry::new([KeySpec::new("../bad", Kind::String, "")]).is_err());
    let registry = Registry::new([
        KeySpec::new("bpf-ct-global-tcp-max", Kind::UInt { bits: 32 }, "1"),
        KeySpec::new("bpf-ct-global-any-max", Kind::UInt { bits: 32 }, "1"),
    ])
    .unwrap();
    let resolved = registry
        .resolve([
            Entry::new(Source::Dir, "ct-global-max-entries-tcp", "100"),
            Entry::new(Source::Env, "ct-global-max-entries-other", "200"),
        ])
        .unwrap();
    assert_eq!(
        resolved.get("bpf-ct-global-tcp-max").unwrap().value,
        Value::UInt(100)
    );
    assert_eq!(
        resolved.get("bpf-ct-global-any-max").unwrap().value,
        Value::UInt(200)
    );
}

#[test]
fn known_shadowed_and_ignored_values_are_still_validated() {
    let mut spec = KeySpec::new("ignored", Kind::Bool, "false");
    spec.class = Class::Ignored;
    let registry = Registry::new([spec]).unwrap();
    let error = registry
        .resolve([
            Entry::new(Source::File, "ignored", "bad"),
            Entry::new(Source::Flag, "ignored", "true"),
        ])
        .unwrap_err();
    assert!(error.to_string().starts_with("option ignored:"));
    let resolved = registry
        .resolve([
            Entry::new(Source::File, "unknown_key", "anything"),
            Entry::new(Source::Flag, "UNKNOWN-KEY", "else"),
            Entry::new(Source::Flag, "ignored", "yes"),
        ])
        .unwrap();
    assert_eq!(resolved.unknown_keys().len(), 1);
    assert_eq!(resolved.warnings().len(), 2);
    assert!(matches!(
        resolved.warnings().last(),
        Some(Warning::IgnoredKey { .. })
    ));
    assert_eq!(resolved.get("ignored").unwrap().class, Class::Ignored);
}

#[test]
fn numeric_kinds_validate_forms_widths_and_non_finite_values() {
    for raw in ["true", "TRUE", "1", "t", "yes", "ON"] {
        assert_eq!(one(Kind::Bool, "false", raw).unwrap(), Value::Bool(true));
    }
    for raw in ["false", "FALSE", "0", "f", "no", "OFF"] {
        assert_eq!(one(Kind::Bool, "false", raw).unwrap(), Value::Bool(false));
    }
    assert!(one(Kind::Bool, "false", "maybe").is_err());
    for bits in [8, 16, 32, 64] {
        assert_eq!(
            one(Kind::Int { bits }, "0", "-12").unwrap(),
            Value::Int(-12)
        );
        assert_eq!(
            one(Kind::UInt { bits }, "0", "12").unwrap(),
            Value::UInt(12)
        );
    }
    assert_eq!(
        one(Kind::Int { bits: 8 }, "0", "-128").unwrap(),
        Value::Int(-128)
    );
    for raw in ["128", "-129", "0xff", "1.0", " 1"] {
        assert!(one(Kind::Int { bits: 8 }, "0", raw).is_err());
    }
    for raw in ["256", "-1", "18446744073709551616"] {
        assert!(one(Kind::UInt { bits: 8 }, "0", raw).is_err());
    }
    for bits in [32, 64] {
        assert_eq!(
            one(Kind::Float { bits }, "0", "1.5e2").unwrap(),
            Value::Float(150.0)
        );
        for raw in ["NaN", "inf", "-inf", "1e999", "one"] {
            assert!(one(Kind::Float { bits }, "0", raw).is_err());
        }
    }
}

#[test]
fn durations_preserve_signed_nanoseconds_and_check_overflow() {
    for (raw, expected) in [
        ("0", 0),
        ("300ms", 300_000_000),
        ("1h30m", 5_400_000_000_000),
        ("-1.5s", -1_500_000_000),
        (".5µs", 500),
        ("2μs", 2_000),
        ("1.9999999999ns", 1),
        ("1.00000000000000000000000001h", 3_600_000_000_000),
        ("9223372036854775807ns", i64::MAX),
        ("-9223372036854775808ns", i64::MIN),
        ("123", 123),
    ] {
        assert_eq!(
            one(Kind::Duration, "0", raw).unwrap(),
            Value::Duration(expected),
            "{raw}"
        );
    }
    for raw in [
        "",
        "1d",
        "--1s",
        "1s2",
        "1e2s",
        "1 s",
        "9223372036854775808ns",
        "-9223372036854775809ns",
    ] {
        assert!(one(Kind::Duration, "0", raw).is_err(), "{raw}");
    }
    let registry = Registry::new([KeySpec::new("delay", Kind::Duration, "0")]).unwrap();
    let result = registry
        .resolve([Entry::new(Source::Env, "delay", "100")])
        .unwrap();
    assert_eq!(
        result.warnings(),
        &[Warning::BareDuration {
            key: "delay".into(),
            source: Source::Env
        }]
    );
}

#[test]
fn schema_validation_rejects_invalid_defaults_and_type_widths() {
    for (kind, default) in [
        (Kind::Int { bits: 7 }, "0"),
        (Kind::UInt { bits: 128 }, "0"),
        (Kind::Float { bits: 16 }, "0"),
        (Kind::Enum(vec![]), ""),
        (Kind::Bool, "bogus"),
    ] {
        assert!(Registry::new([KeySpec::new("key", kind, default)]).is_err());
    }
    assert!(Registry::new([KeySpec::new("monitor-aggregation-level", Kind::String, "")]).is_err());
    let mut script = KeySpec::new("script-flag", Kind::String, "");
    script.class = Class::Script;
    let registry = Registry::new([script]).unwrap();
    let resolved = registry
        .resolve([Entry::new(Source::Dir, "script-flag", "data")])
        .unwrap();
    assert!(matches!(resolved.warnings(), [Warning::IgnoredKey { .. }]));
    assert_eq!(resolved.get("script-flag").unwrap().class, Class::Script);
}

#[test]
fn lists_replace_layers_and_append_repeated_flags() {
    let registry = Registry::new([KeySpec::new("devices", Kind::List, "default")]).unwrap();
    let result = registry
        .resolve([
            Entry::new(Source::Env, "devices", "ignored"),
            Entry::new(Source::Flag, "devices", "foo,bar baz"),
            Entry::new(Source::Flag, "devices", "qux quux"),
        ])
        .unwrap();
    assert_eq!(
        result.get("devices").unwrap().value,
        Value::List(vec![
            "foo".into(),
            "bar baz".into(),
            "qux".into(),
            "quux".into()
        ])
    );
    assert_eq!(one(Kind::List, "", "").unwrap(), Value::List(vec![]));
    assert_eq!(
        one(Kind::String, "", " verbatim \n").unwrap(),
        Value::String(" verbatim \n".into())
    );
    assert!(
        matches!(one(Kind::Map, "", "a=1,b=x=y").unwrap(), Value::Map(map) if map.get("b") == Some(&"x=y".to_owned()))
    );
    assert!(one(Kind::Map, "", "missing-equals").is_err());
    assert!(one(Kind::Map, "", "=empty-key").is_err());
    let registry = Registry::new([KeySpec::new("map", Kind::Map, "default=1")]).unwrap();
    let resolved = registry
        .resolve([
            Entry::new(Source::File, "map", "file=2"),
            Entry::new(Source::Env, "map", "env=3"),
        ])
        .unwrap();
    assert!(
        matches!(&resolved.get("map").unwrap().value, Value::Map(map) if map.len() == 1 && map.contains_key("env"))
    );
}

#[test]
fn network_and_enum_kinds_reject_malformed_inputs() {
    assert!(one(Kind::Ip, "127.0.0.1", "::1").is_ok());
    assert!(one(Kind::Ip, "127.0.0.1", "256.0.0.1").is_err());
    for raw in ["192.0.2.1/24", "::1/128", "0.0.0.0/0"] {
        assert!(one(Kind::Cidr, "0.0.0.0/0", raw).is_ok());
    }
    for raw in ["192.0.2.1/33", "::1/129", "::1/-1", "::1", "bad/24"] {
        assert!(one(Kind::Cidr, "0.0.0.0/0", raw).is_err());
    }
    for raw in ["example.test:80", "127.0.0.1:65535", "[::1]:443"] {
        assert!(one(Kind::HostPort, "localhost:0", raw).is_ok());
    }
    for raw in [
        "::1:443",
        "[::1:443",
        "host:65536",
        "host:-1",
        ":80",
        "host name:80",
    ] {
        assert!(one(Kind::HostPort, "localhost:0", raw).is_err());
    }
    let kind = Kind::Enum(vec!["native".into(), "tunnel".into()]);
    assert_eq!(
        one(kind.clone(), "tunnel", "native").unwrap(),
        Value::Enum("native".into())
    );
    assert!(one(kind, "tunnel", "Native").is_err());
}
