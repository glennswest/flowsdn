#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{Archive, Line, Status, parse_script, tokenize};

#[test]
fn archive_shapes_and_exact_round_trips() {
    for text in [
        "",
        "echo hi",
        "echo hi\n",
        "-- x --\n",
        "-- x --",
        "-- x --\nbody",
        "script\n--  nested/name  --\none\n-- x --\n-- x --\nlast",
    ] {
        let archive = Archive::parse(text).unwrap();
        assert_eq!(archive.serialize(), text);
    }
    let archive = Archive::parse("echo hi\n--  nested/name  --\n${RAW}\n-- x --\nlast").unwrap();
    assert_eq!(archive.script(), "echo hi\n");
    let names: Vec<_> = archive.files().iter().map(|file| file.name()).collect();
    let bodies: Vec<_> = archive.files().iter().map(|file| file.data()).collect();
    assert_eq!(names, ["nested/name", "x"]);
    assert_eq!(bodies, ["${RAW}\n", "last"]);
}

#[test]
fn only_exact_marker_lines_start_files() {
    let archive =
        Archive::parse(" -- wrong --\n-- wrong -- \n-- real --\n--not--\n-- next --\n").unwrap();
    assert_eq!(archive.script(), " -- wrong --\n-- wrong -- \n");
    assert_eq!(archive.files().len(), 2);
    assert_eq!(archive.files().first().unwrap().data(), "--not--\n");
}

#[test]
fn crlf_is_rejected_with_line_number_even_in_data() {
    for text in ["echo hi\nsecond\r\n", "-- x --\ndata\r\n"] {
        let error = Archive::parse(text).unwrap_err();
        assert_eq!(error.line, 2);
        assert!(error.message.contains("CRLF"));
    }
}

#[test]
fn flags_keep_runtime_variables_and_ignore_empty_entries() {
    for text in ["", "echo hi\n", "#!", "#! \n"] {
        assert!(Archive::parse(text).unwrap().flags().is_empty());
    }
    let archive = Archive::parse("#! --file=$WORK/state  --modes=a,b\necho hi\n").unwrap();
    assert_eq!(archive.flags(), ["--file=$WORK/state", "--modes=a,b"]);
    assert!(archive.script().starts_with("#!"));
}

#[test]
fn quotes_comments_empty_arguments_and_unicode() {
    let tokens = tokenize("echo\t'a''b' 'a'b '' '# literal' '$x'${x} café# ignore", 9).unwrap();
    let literal: Vec<_> = tokens.iter().map(|token| token.literal()).collect();
    assert_eq!(
        literal,
        ["echo", "a'b", "ab", "", "# literal", "$x${x}", "café"]
    );
    let mixed = tokens
        .iter()
        .find(|token| token.literal() == "$x${x}")
        .unwrap();
    assert_eq!(mixed.0.len(), 2);
    assert!(mixed.0.first().unwrap().quoted);
    assert!(!mixed.0.last().unwrap().quoted);
    assert!(
        tokens
            .iter()
            .find(|token| token.literal() == "")
            .unwrap()
            .unquoted()
            .is_none()
    );
    let error = tokenize("echo 'broken", 9).unwrap_err();
    assert_eq!(error.line, 9);
}

#[test]
fn statuses_conditions_background_and_sections() {
    let parsed = parse_script(
        "# header\n  # ignored\n\n!* [linux] [!short] [exec:ip] exec ip &\n'!' echo '&'",
    )
    .unwrap();
    assert_eq!(parsed.len(), 3);
    assert!(matches!(
        parsed.first(),
        Some(Line::Section { line: 1, .. })
    ));
    let commands: Vec<_> = parsed
        .iter()
        .filter_map(|line| match line {
            Line::Command(command) => Some(command),
            _ => None,
        })
        .collect();
    let first = commands.first().unwrap();
    assert_eq!(first.line, 4);
    assert_eq!(first.status, Status::FailureRetry);
    assert!(first.background);
    assert_eq!(first.conditions.len(), 3);
    assert!(
        first
            .conditions
            .iter()
            .any(|condition| condition.name == "short" && condition.negated)
    );
    assert_eq!(first.words.first().unwrap().literal(), "exec");
    let last = commands.last().unwrap();
    assert_eq!(last.status, Status::Success);
    assert!(!last.background);
    assert_eq!(last.words.first().unwrap().literal(), "!");
    for (prefix, expected) in [
        ("", Status::Success),
        ("! ", Status::Failure),
        ("? ", Status::SuccessOrFailure),
        ("* ", Status::SuccessRetry),
        ("!* ", Status::FailureRetry),
    ] {
        let parsed = parse_script(&format!("{prefix}echo hi")).unwrap();
        let Some(Line::Command(command)) = parsed.first() else {
            panic!("missing command")
        };
        assert_eq!(command.status, expected);
    }
}

#[test]
fn malformed_prefixes_report_the_source_line() {
    for text in [
        "! ? echo",
        "!",
        "[linux]",
        "[] echo",
        "[!] echo",
        "[linux echo",
        "&",
        "echo 'bad",
    ] {
        let error = parse_script(&format!("# header\n{text}")).unwrap_err();
        assert_eq!(error.line, 2, "{text}");
    }
}
