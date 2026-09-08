#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{ExpansionMode, expand_text, tokenize};
use std::collections::BTreeMap;

fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("WORK".into(), "/tmp/a.b+[c](d)".into()),
        ("x".into(), "value".into()),
        ("name-with-dashes".into(), "dashed".into()),
        ("/".into(), "/".into()),
        (":".into(), ":".into()),
    ])
}

#[test]
fn variables_braces_separators_and_undefined_values() {
    let actual = expand_text(
        "$x/${x}/${missing}/$missing/$/${/}$:${:}/${name-with-dashes}",
        &environment(),
        ExpansionMode::Plain,
        1,
    )
    .unwrap();
    assert_eq!(actual, "value/value/////::/dashed");
    assert_eq!(
        expand_text("café $x ☃ $", &environment(), ExpansionMode::Plain, 1).unwrap(),
        "café value ☃ $"
    );
}

#[test]
fn quoted_fragments_and_doubled_quotes_remain_literal() {
    let tokens = tokenize("'$x'${x} '$'x 'Don''t $x' '' $missing", 7).unwrap();
    let expanded: Vec<_> = tokens
        .iter()
        .map(|token| token.expand(&environment(), ExpansionMode::Plain, 7).unwrap())
        .collect();
    assert_eq!(expanded, ["$xvalue", "$x", "Don't $x", "", ""]);
    let tokens = tokenize("$'{x}' '${broken'", 7).unwrap();
    let expanded: Vec<_> = tokens
        .iter()
        .map(|token| token.expand(&environment(), ExpansionMode::Plain, 7).unwrap())
        .collect();
    assert_eq!(expanded, ["${x}", "${broken"]);
}

#[test]
fn expansion_is_single_pass_without_word_splitting_or_shell_escapes() {
    let mut env = environment();
    env.insert("payload".into(), "a b\n# 'quoted' $x ${x}".into());
    let tokens = tokenize("$payload \\$x", 2).unwrap();
    let expanded: Vec<_> = tokens
        .iter()
        .map(|token| token.expand(&env, ExpansionMode::Plain, 2).unwrap())
        .collect();
    assert_eq!(expanded, ["a b\n# 'quoted' $x ${x}", "\\value"]);
}

#[test]
fn regex_escaping_applies_only_to_substituted_values() {
    let tokens = tokenize("^${WORK}/'($x|other)'$", 4).unwrap();
    let token = tokens.first().unwrap();
    let pattern = token.expand(&environment(), ExpansionMode::Regex, 4).unwrap();
    assert_eq!(pattern, r"^/tmp/a\.b\+\[c\]\(d\)/($x|other)$");
    let expression = regex::Regex::new(&pattern).unwrap();
    assert!(expression.is_match("/tmp/a.b+[c](d)/other"));
    assert!(!expression.is_match("/tmp/axb+[c](d)/other"));
    assert_eq!(
        token.expand(&environment(), ExpansionMode::Plain, 4).unwrap(),
        "^/tmp/a.b+[c](d)/($x|other)$"
    );
}

#[test]
fn malformed_unquoted_braces_report_source_line() {
    for input in ["${}", "before${x", "${"] {
        let error = expand_text(input, &environment(), ExpansionMode::Plain, 23).unwrap_err();
        assert_eq!(error.line, 23);
        assert!(error.message.contains("variable"));
    }
    let token = tokenize("'${}'", 23).unwrap().pop().unwrap();
    assert_eq!(token.expand(&environment(), ExpansionMode::Plain, 23).unwrap(), "${}");
}
