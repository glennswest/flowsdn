#![cfg(feature = "filter")]
use flowsdn_identity::{
    filter::{DEFAULT_ENTRIES, FilterDiagnostic, LabelFilter, Rule},
    labels::{Label, Labels},
};

#[test]
fn perl_classes_use_ascii_and_negations_keep_unicode_complements() {
    for (positive, negative, ascii, unicode) in [
        (r"node:\d", r"node:\D", "7", "١"),
        (r"node:\w", r"node:\W", "_", "é"),
        (r"node:\s", r"node:\S", "\t", "\u{a0}"),
    ] {
        let positive = Rule::parse(positive).expect("positive class");
        let negative = Rule::parse(negative).expect("negative class");
        assert_eq!(positive.match_length(&label("node", ascii)), Some(1));
        assert_eq!(positive.match_length(&label("node", unicode)), None);
        assert_eq!(negative.match_length(&label("node", ascii)), None);
        assert_eq!(
            negative.match_length(&label("node", unicode)),
            Some(unicode.len())
        );
    }
    let spaces = Rule::parse(r"node:\s").expect("space");
    for character in [" ", "\t", "\n", "\r", "\u{c}"] {
        assert_eq!(spaces.match_length(&label("node", character)), Some(1));
    }
    assert_eq!(spaces.match_length(&label("node", "\u{b}")), None);
}

#[test]
fn bracket_classes_nested_negations_and_escaped_backslashes_are_distinct() {
    for (pattern, text, expected) in [
        (r"node:[\d_]", "١", None),
        (r"node:[\d_]", "_", Some(1)),
        (r"node:[\D]", "é", Some(2)),
        (r"node:[^\D]", "7", Some(1)),
        (r"node:[^\D]", "١", None),
        (r"node:[\w\s]", "\u{a0}", None),
        (r"node:\\d", r"\d", Some(2)),
        (r"node:[\\d]", "d", Some(1)),
        (r"node:[\\d]", "7", None),
        (r"node:\[\d\]", "[7]", Some(3)),
    ] {
        assert_eq!(
            Rule::parse(pattern)
                .expect("class fixture")
                .match_length(&label("node", text)),
            expected,
            "{pattern}"
        );
    }
}

#[test]
fn word_boundaries_are_ascii_without_changing_unicode_consumption() {
    for (pattern, text, expected) in [
        (r"node:\bé", "é", None),
        (r"node:\Bé", "é", Some(2)),
        (r"node:a\bé", "aé", Some(3)),
        (r"node:a\Bé", "aé", None),
        (r"node:é\b", "é", None),
        (r"node:é\B", "é", Some(2)),
        (r"node:\ba\b", "a", Some(1)),
        (r"node:\\b", r"\b", Some(2)),
    ] {
        assert_eq!(
            Rule::parse(pattern)
                .expect("boundary")
                .match_length(&label("node", text)),
            expected,
            "{pattern}"
        );
    }
}

#[test]
fn unicode_literals_dot_and_explicit_properties_remain_rune_based() {
    for (pattern, text, expected) in [
        ("node:é.", "é日", Some(5)),
        (r"node:\p{Greek}+", "αβ", Some(4)),
        (r"node:\pN+", "١", Some(2)),
        (r"node:[\d\p{Greek}]", "α", Some(2)),
        (r"node:[\d\p{Greek}]", "١", None),
    ] {
        assert_eq!(
            Rule::parse(pattern)
                .expect("Unicode")
                .match_length(&label("node", text)),
            expected
        );
    }
}

#[test]
fn case_insensitive_perl_classes_fold_before_negation_but_boundaries_stay_ascii() {
    // Go regexp/syntax appendGroup applies Unicode SimpleFold before negation.
    for text in ["K", "ſ"] {
        assert_eq!(
            Rule::parse(r"node:(?i)\w")
                .expect("fold")
                .match_length(&label("node", text)),
            Some(text.len())
        );
        assert_eq!(
            Rule::parse(r"node:(?i)\W")
                .expect("negated fold")
                .match_length(&label("node", text)),
            None
        );
        assert_eq!(
            Rule::parse(r"node:(?i)\b\w")
                .expect("boundary fold")
                .match_length(&label("node", text)),
            None
        );
    }
}

fn label(source: &str, key: &str) -> Label {
    Label::new(source, key, "ignored-value").expect("label fixture")
}

#[test]
fn default_includes_are_exceptions_not_a_whitelist() {
    let filter = LabelFilter::identity(&[]).expect("defaults");
    assert!(!filter.is_whitelist());
    assert_eq!(filter.rules().len(), 21);
    assert_eq!(DEFAULT_ENTRIES.first(), Some(&"reserved:.*"));
    for key in [
        "app",
        "team",
        "io.kubernetes.pod.namespace",
        "io.cilium.k8s.namespace.labels.team",
        "app.kubernetes.io/name",
    ] {
        assert!(filter.retains(&label("k8s", key)), "{key}");
    }
    for key in [
        "io.kubernetes.hidden",
        "kubernetes.io/name",
        "pod-template-hash",
        "annotation.note",
        "topology.kubernetes.io/zone",
        "x.beta.kubernetes.io/name",
    ] {
        assert!(!filter.retains(&label("k8s", key)), "{key}");
    }
    // Reserved regex consumes the full key and beats a shorter excluded prefix.
    assert!(filter.retains(&label("reserved", "io.kubernetes.extra")));
}

#[test]
fn user_include_enables_whitelist_but_preserves_default_exceptions() {
    let filter = LabelFilter::identity(&["k8s:team$"]).expect("filter");
    assert!(filter.is_whitelist());
    assert!(filter.retains(&label("k8s", "team")));
    assert!(!filter.retains(&label("container", "team")));
    assert!(!filter.retains(&label("k8s", "team-extra")));
    assert!(!filter.retains(&label("k8s", "app")));
    assert!(filter.retains(&label("reserved", "host")));
    assert!(filter.retains(&label("k8s", "io.kubernetes.pod.namespace")));
    assert!(
        !LabelFilter::identity(&["", "!private"])
            .expect("filter")
            .is_whitelist()
    );
}

#[test]
fn longest_include_shortest_exclude_and_ties_are_length_based() {
    for entries in [
        ["node:team", "node:!team.secret", "node:team.secret.allowed"],
        ["node:team.secret.allowed", "node:team", "node:!team.secret"],
    ] {
        let filter = LabelFilter::node(&entries).expect("filter");
        assert!(filter.retains(&label("node", "team.public")));
        assert!(!filter.retains(&label("node", "team.secret")));
        assert!(filter.retains(&label("node", "team.secret.allowed.child")));
    }
    let tie = LabelFilter::node(&["team", "!team"]).expect("tie");
    assert!(!tie.retains(&label("node", "team")));
    let shortest = LabelFilter::node(&["team.good", "!team", "!team.good.long"]).expect("shortest");
    assert!(shortest.retains(&label("node", "team.good.long")));
}

#[test]
fn regex_matching_is_anchored_and_reports_utf8_byte_offsets() {
    let rule = Rule::parse("node:é+").expect("regex");
    assert_eq!(rule.match_length(&label("node", "éé.rest")), Some(4));
    assert_eq!(rule.match_length(&label("node", "xéé")), None);
    assert_eq!(rule.match_length(&label("k8s", "éé")), None);
    assert_eq!(
        Rule::parse(":a|bc")
            .expect("regex")
            .match_length(&label("node", "bc-tail")),
        Some(2)
    );
    // Values never participate in key matching.
    assert_eq!(
        rule.match_length(&Label::new("node", "other", "éé").expect("label")),
        None
    );
}

#[test]
fn source_split_precedes_exclusion_and_preserves_whitespace() {
    let exclude = Rule::parse("node:!zone").expect("rule");
    assert!(exclude.is_exclusion());
    assert_eq!(exclude.source(), "node");
    let source = Rule::parse("!node:zone").expect("rule");
    assert!(!source.is_exclusion());
    assert_eq!(source.source(), "!node");
    assert_eq!(
        Rule::parse(":(?:a|b)")
            .expect("explicit empty source")
            .match_length(&label("node", "b")),
        Some(1)
    );
    assert_eq!(
        Rule::parse(" x")
            .expect("space")
            .match_length(&label("node", "x")),
        None
    );
    for invalid in ["", "node:", "[", r"(a)\1", "(?=x)"] {
        assert!(Rule::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn zero_length_regex_sentinels_keep_reference_rule_order_behavior() {
    let input = label("node", "abc");
    assert!(
        !LabelFilter::node(&["^$"])
            .expect("no match")
            .retains(&input)
    );
    assert!(
        !LabelFilter::node(&["^"])
            .expect("zero include")
            .retains(&input)
    );
    assert!(
        LabelFilter::node(&["!"])
            .expect("empty exclusion")
            .retains(&input)
    );
    assert!(
        LabelFilter::node(&["!a", "!"])
            .expect("reset exclusion")
            .retains(&input)
    );
    assert!(
        !LabelFilter::node(&["!", "!a"])
            .expect("positive exclusion last")
            .retains(&input)
    );
}

#[test]
fn node_filter_has_no_defaults_and_only_filters_node_source() {
    assert!(
        LabelFilter::node(&[])
            .expect("empty")
            .retains(&label("node", "annotation.hidden"))
    );
    let excluded = LabelFilter::node(&["!private"]).expect("exclude");
    assert!(excluded.retains(&label("node", "public")));
    assert!(!excluded.retains(&label("node", "private.x")));
    assert!(excluded.retains(&label("k8s", "private.x")));
    let sourced = LabelFilter::node(&["k8s:public"]).expect("sourced");
    assert!(!sourced.retains(&label("node", "public")));
    assert!(sourced.retains(&label("k8s", "public")));
}

#[test]
fn json_prefixes_are_literal_and_replace_defaults() {
    let json = br#"{"version":1,"valid-prefixes":[{"prefix":"a.b","source":"k8s"},{"prefix":"[","source":"k8s"}]}"#;
    let filter = LabelFilter::identity_from_json(json, &[]).expect("literal file");
    assert!(filter.is_whitelist());
    assert!(filter.rules().iter().all(Rule::is_literal));
    assert!(filter.retains(&label("k8s", "a.b.more")));
    assert!(!filter.retains(&label("k8s", "axb.more")));
    assert!(filter.retains(&label("k8s", "[literal")));
    assert!(!filter.retains(&label("reserved", "host")));
    assert_eq!(
        filter.diagnostics(),
        &[FilterDiagnostic::MissingReservedRule]
    );
}

#[test]
fn json_and_cli_keep_their_distinct_matchers_and_diagnostic_contract() {
    let file = br#"{"version":1,"valid-prefixes":[{"prefix":"team.secret","source":"k8s","invert":true}]}"#;
    let filter =
        LabelFilter::identity_from_json(file, &["k8s:team\\.secret\\.allowed", "reserved:.*"])
            .expect("mixed");
    assert!(filter.diagnostics().is_empty());
    assert!(!filter.retains(&label("k8s", "team.secret")));
    assert!(filter.retains(&label("k8s", "team.secret.allowed")));
    assert!(filter.retains(&label("reserved", "host")));
    let misleading =
        br#"{"version":1,"valid-prefixes":[{"prefix":".*","source":"reserved","invert":true}]}"#;
    let filter = LabelFilter::identity_from_json(misleading, &["k8s:team"])
        .expect("accepted diagnostic presence");
    assert!(filter.diagnostics().is_empty());
    assert!(!filter.retains(&label("reserved", "host")));
}

#[test]
fn json_rejects_bad_shapes_versions_and_empty_fields_atomically() {
    for json in [
        "[]",
        "{}",
        r#"{"version":2}"#,
        r#"{"version":1,"valid-prefixes":{}}"#,
        r#"{"version":1,"valid-prefixes":[null]}"#,
        r#"{"version":1,"valid-prefixes":[{"prefix":"","source":"k8s"}]}"#,
        r#"{"version":1,"valid-prefixes":[{"prefix":"x","source":""}]}"#,
        r#"{"version":1,"valid-prefixes":[{"prefix":"x","source":"k8s","invert":"false"}]}"#,
        r#"{"version":1} trailing"#,
    ] {
        assert!(
            LabelFilter::identity_from_json(json.as_bytes(), &[]).is_err(),
            "{json}"
        );
    }
    assert!(LabelFilter::identity_from_json(br#"{"version":1}"#, &["["]).is_err());
    for json in [
        r#"{"version":1,"future":true}"#,
        r#"{"version":1,"valid-prefixes":null}"#,
    ] {
        let filter = LabelFilter::identity_from_json(json.as_bytes(), &[]).expect("empty accepted");
        assert!(!filter.is_whitelist());
        assert!(filter.retains(&label("k8s", "app")));
    }
}

#[test]
fn partition_preserves_values_sources_and_input_canonical_key() {
    let labels: Labels = [
        Label::new("node", "team", "blue").expect("label"),
        Label::new("node", "private", "yes").expect("label"),
        Label::new("k8s", "app", "db").expect("label"),
    ]
    .into_iter()
    .collect();
    let original = labels.canonical_key();
    let (identity, information) = LabelFilter::node(&["!private"])
        .expect("filter")
        .partition(&labels);
    assert_eq!(identity.canonical_key(), "k8s:app=db;node:team=blue;");
    assert_eq!(information.canonical_key(), "node:private=yes;");
    assert_eq!(labels.canonical_key(), original);
    assert_eq!(
        identity.len().checked_add(information.len()),
        Some(labels.len())
    );
}
