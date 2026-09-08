#![allow(clippy::unwrap_used)]

use flowsdn_config::{Class, Entry, Kind, KeySpec, Registry, Resolved, Source};
use flowsdn_config::validation::{self, MapBounds};

fn config(keys: &[(&str, Kind, &str)]) -> Resolved {
    Registry::new(keys.iter().map(|(name, kind, value)| KeySpec::new(*name, kind.clone(), *value))).unwrap().resolve([]).unwrap()
}

#[test]
fn address_families_and_ndp_dependencies_are_checked() {
    for (v4, v6, ndp, device, expected) in [
        ("true", "false", "false", "", None),
        ("false", "true", "true", "eth0", None),
        ("false", "false", "false", "", Some("enable-ipv4")),
        ("true", "false", "true", "eth0", Some("enable-ipv6-ndp")),
        ("true", "true", "true", "", Some("ipv6-mcast-device")),
    ] {
        let config = config(&[
            ("enable-ipv4", Kind::Bool, v4), ("enable-ipv6", Kind::Bool, v6),
            ("enable-ipv6-ndp", Kind::Bool, ndp), ("ipv6-mcast-device", Kind::String, device),
        ]);
        assert_eq!(validation::foundation(&config).err().map(|error| error.key), expected.map(str::to_owned));
    }
    let missing = config(&[("enable-ipv4", Kind::Bool, "true")]);
    assert_eq!(validation::foundation(&missing).unwrap_err().key, "enable-ipv6");
    assert!(validation::foundation(&config(&[])).is_ok());
}

#[test]
fn enums_route_metric_and_ipv6_prefixes_have_named_errors() {
    for (key, allowed, denied) in [
        ("routing-mode", "native", "overlay"),
        ("allow-localhost", "policy", "never"),
    ] {
        assert!(validation::foundation(&config(&[(key, Kind::String, allowed)])).is_ok());
        let error = validation::foundation(&config(&[(key, Kind::String, denied)])).unwrap_err();
        assert!(error.to_string().starts_with(&format!("--{key}:")));
    }
    assert!(validation::foundation(&config(&[("route-metric", Kind::Int { bits: 64 }, "0")])).is_ok());
    assert_eq!(validation::foundation(&config(&[("route-metric", Kind::Int { bits: 64 }, "-1")])).unwrap_err().key, "route-metric");
    for prefix in ["fd00::/64", "2001:db8::1/64"] {
        assert!(validation::foundation(&config(&[("ipv6-cluster-alloc-cidr", Kind::String, prefix)])).is_ok());
        assert!(validation::foundation(&config(&[("ipv6-cluster-alloc-cidr", Kind::Cidr, prefix)])).is_ok());
    }
    for prefix in ["fd00::/96", "192.0.2.0/24", "bad"] {
        assert_eq!(validation::foundation(&config(&[("ipv6-cluster-alloc-cidr", Kind::String, prefix)])).unwrap_err().key, "ipv6-cluster-alloc-cidr");
    }
}

#[test]
fn cluster_names_and_cluster_id_boundaries_match_both_mesh_widths() {
    for name in ["a", "0", "prod-east-1", "abcdefghijklmnopqrstuvwxyz012345"] {
        assert!(validation::foundation(&config(&[("cluster-name", Kind::String, name)])).is_ok());
    }
    for name in ["", "-name", "name-", "Name", "name_name", "é", "abcdefghijklmnopqrstuvwxyz0123456"] {
        assert_eq!(validation::foundation(&config(&[("cluster-name", Kind::String, name)])).unwrap_err().key, "cluster-name");
    }
    for (max, id, valid) in [("255", "0", true), ("255", "255", true), ("255", "256", false), ("511", "511", true), ("511", "512", false), ("256", "1", false)] {
        let config = config(&[("max-connected-clusters", Kind::UInt { bits: 32 }, max), ("cluster-id", Kind::UInt { bits: 32 }, id)]);
        assert_eq!(validation::foundation(&config).is_ok(), valid, "max={max} id={id}");
    }
}

#[test]
fn map_ratio_and_inclusive_policy_bounds_reject_bad_sizes() {
    for ratio in ["0.0025", "1"] {
        assert!(validation::foundation(&config(&[("bpf-map-dynamic-size-ratio", Kind::Float { bits: 64 }, ratio)])).is_ok());
    }
    for ratio in ["0", "-0.1", "1.01"] {
        assert_eq!(validation::foundation(&config(&[("bpf-map-dynamic-size-ratio", Kind::Float { bits: 64 }, ratio)])).unwrap_err().key, "bpf-map-dynamic-size-ratio");
    }
    for (size, valid) in [("255", false), ("256", true), ("16384", true), ("65536", true), ("65537", false), ("-1", false)] {
        assert_eq!(validation::foundation(&config(&[("bpf-policy-map-max", Kind::Int { bits: 64 }, size)])).is_ok(), valid);
    }
    let config = config(&[("bpf-custom-max", Kind::UInt { bits: 64 }, "100")]);
    assert!(validation::map_sizes(&config, &[MapBounds { key: "bpf-custom-max", minimum: 10, maximum: 100 }]).is_ok());
    assert!(validation::map_sizes(&config, &[MapBounds { key: "bpf-custom-max", minimum: 10, maximum: 99 }]).is_err());
    assert!(validation::map_sizes(&config, &[MapBounds { key: "bpf-custom-max", minimum: 100, maximum: 10 }]).is_err());
}

#[test]
fn delegated_ipam_requires_routes_and_disables_health_and_masquerade() {
    for (masquerade, health, routes, valid) in [
        ("false", "false", "true", true), ("true", "false", "true", false),
        ("false", "true", "true", false), ("false", "false", "false", false),
    ] {
        let config = config(&[
            ("ipam", Kind::String, "delegated-plugin"), ("enable-ipv4-masquerade", Kind::Bool, masquerade),
            ("enable-endpoint-health-checking", Kind::Bool, health), ("enable-endpoint-routes", Kind::Bool, routes),
        ]);
        assert_eq!(validation::foundation(&config).is_ok(), valid);
    }
    assert!(validation::foundation(&config(&[("ipam", Kind::String, "delegated-plugin")])).is_err());
}

#[test]
fn vtep_and_identity_backends_check_active_dependencies() {
    for (enabled, mask, valid) in [("true", "255.255.255.0", true), ("true", "garbage", false), ("true", "::1", false), ("false", "", true)] {
        assert_eq!(validation::foundation(&config(&[("enable-vtep", Kind::Bool, enabled), ("vtep-mask", Kind::String, mask)])).is_ok(), valid);
    }
    for (mode, backend, valid) in [("crd", "", true), ("kvstore", "etcd", true), ("kvstore", "", false), ("doublewrite-readcrd", "etcd", false)] {
        assert_eq!(validation::foundation(&config(&[("identity-allocation-mode", Kind::String, mode), ("kvstore", Kind::String, backend)])).is_ok(), valid);
    }
    assert_eq!(validation::foundation(&config(&[("identity-allocation-mode", Kind::String, "kvstore")])).unwrap_err().key, "kvstore");
}

#[test]
fn misdeclared_schema_types_cannot_bypass_validation() {
    for (key, kind, value) in [
        ("enable-ipv4", Kind::String, "true"), ("route-metric", Kind::String, "-1"),
        ("cluster-name", Kind::Bool, "true"), ("bpf-map-dynamic-size-ratio", Kind::Int { bits: 64 }, "1"),
    ] { assert_eq!(validation::foundation(&config(&[(key, kind, value)])).unwrap_err().key, key); }
}

#[test]
fn ignored_and_script_values_never_activate_foundation_rules() {
    for class in [Class::Ignored, Class::Script] {
        let specs = [
            ("enable-vtep", Kind::Bool, "true"),
            ("enable-ipv4", Kind::Bool, "false"),
            ("enable-ipv6", Kind::Bool, "false"),
            ("routing-mode", Kind::String, "ignored-mode"),
            ("route-metric", Kind::Int { bits: 64 }, "-1"),
            ("bpf-policy-map-max", Kind::Int { bits: 64 }, "1"),
            ("bpf-map-dynamic-size-ratio", Kind::Float { bits: 64 }, "0"),
            ("ipv6-cluster-alloc-cidr", Kind::String, "not-a-prefix"),
        ].into_iter().map(|(name, kind, value)| {
            let mut spec = KeySpec::new(name, kind, value);
            spec.class = class;
            spec
        });
        let registry = Registry::new(specs).unwrap();
        assert!(validation::foundation(&registry.resolve([]).unwrap()).is_ok());
        assert!(registry.resolve([Entry::new(Source::Flag, "enable-vtep", "invalid-bool")]).is_err(), "ignored keys still require valid scalar types");
    }
    let mut mask = KeySpec::new("vtep-mask", Kind::String, "255.255.255.0");
    mask.class = Class::Ignored;
    let mut enabled = KeySpec::new("enable-vtep", Kind::Bool, "true");
    enabled.class = Class::Immutable;
    let resolved = Registry::new([enabled, mask]).unwrap().resolve([]).unwrap();
    assert_eq!(validation::foundation(&resolved).unwrap_err().key, "vtep-mask", "immutable settings remain active; ignored values cannot satisfy their dependencies");
}
