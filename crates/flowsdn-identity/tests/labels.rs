#![allow(clippy::unwrap_used)]
use flowsdn_identity::labels::{Label, LabelError, Labels};

#[test]
fn parsing_source_precedes_value_and_preserves_unknown_sources() {
    for (input, expected) in [
        ("app=web=blue", ("unspec", "app", "web=blue")),
        ("custom:app=web", ("custom", "app", "web")),
        ("app=host:port", ("app=host", "port", "")),
        (":app=web", ("unspec", "app", "web")),
        (" k8s: app = web ", (" k8s", " app ", " web ")),
        ("k8s:app=a:b", ("k8s", "app", "a:b")),
    ] {
        let label = Label::parse(input).unwrap();
        assert_eq!((label.source(), label.key(), label.value()), expected);
    }
}
#[test]
fn reserved_shorthand_and_empty_key_validation() {
    for input in ["$host", "reserved:host", "reserved:=host", "$=host"] {
        assert_eq!(Label::parse(input).unwrap(), Label::new("reserved", "host", "").unwrap());
    }
    let label = Label::parse("reserved:=host=extra").unwrap();
    assert_eq!(label.key(), "host=extra");
    assert_eq!(label.value(), "");
    for input in ["", "=x", ":", "$", "reserved:="] {
        assert_eq!(Label::parse(input), Err(LabelError::EmptyKey));
    }
}
#[test]
fn selectors_default_unspecified_source_to_any() {
    for text in ["app=web", "unspec:app=web", ":app=web"] {
        assert_eq!(Label::parse_selector(text).unwrap().source(), "any");
    }
    assert_eq!(Label::parse_selector("k8s:app=web").unwrap().source(), "k8s");
    assert_eq!(Label::parse_selector("$host").unwrap().source(), "reserved");
}
#[test]
fn cidr_values_are_rejected_without_claiming_prefix_validation() {
    assert_eq!(Label::parse("cidr:10.0.0.0/8=x"), Err(LabelError::CidrValue));
    assert!(Label::parse("cidr:10.0.0.0/8=").is_ok());
    assert!(Label::parse("cidr:invalid-prefix").is_ok());
}
#[test]
fn canonical_key_matches_specification_and_is_insertion_order_independent() {
    let texts = ["k8s:io.kubernetes.pod.namespace=default", "k8s:app=foo", "k8s:io.cilium.k8s.policy.cluster=default"];
    let labels: Labels = texts.iter().map(|s| Label::parse(s).unwrap()).collect();
    let reverse: Labels = texts.iter().rev().map(|s| Label::parse(s).unwrap()).collect();
    assert_eq!(labels, reverse);
    assert_eq!(labels.canonical_key(), "k8s:app=foo;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.kubernetes.pod.namespace=default;");
    let host: Labels = [Label::parse("$host").unwrap()].into_iter().collect();
    assert_eq!(host.canonical_key(), "reserved:host=;");
    assert_eq!(Labels::new().canonical_key(), "");
}
#[test]
fn key_only_identity_replacement_and_removal() {
    let mut labels = Labels::new();
    let old = Label::parse("k8s:app=old").unwrap();
    assert_eq!(labels.insert(old.clone()), None);
    assert_eq!(labels.insert(Label::parse("container:app=new").unwrap()), Some(old));
    assert_eq!(labels.len(), 1);
    assert_eq!(labels.get("app").unwrap().source(), "container");
    assert_eq!(labels.canonical_key(), "container:app=new;");
    assert!(labels.remove("app").is_some());
    assert!(labels.is_empty());
    assert!(labels.remove("app").is_none());
}
#[test]
fn unicode_keys_follow_utf8_byte_order_not_source_order() {
    let labels: Labels = ["a:é=x", "z:z=y", "q:Z="].into_iter().map(|s| Label::parse(s).unwrap()).collect();
    assert_eq!(labels.canonical_key(), "q:Z=;z:z=y;a:é=x;");
}
