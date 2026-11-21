//! spec 18 §9.4, unprivileged (#473): the harvested corpus is consistent
//! with PORTED.toml, and the checks and the generator refuse what they must.
#[path = "../src/corpus.rs"]
mod corpus;

use corpus::{Corpus, include_line, stem};

const CASES: &str = include_str!("../../../tests/bpf/CASES.toml");
const PORTED: &str = include_str!("../../../tests/bpf/PORTED.toml");

fn source(stem: &str) -> Option<String> {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/{stem}.rs")),
    )
    .ok()
}

/// The repository's corpus parses, its [meta] counts are the sums of its
/// rows, every PORTED key resolves, and the report counts all 625 cases.
#[test]
fn the_harvest_is_consistent() {
    let corpus =
        Corpus::parse(CASES, PORTED, source).unwrap_or_else(|p| panic!("{}", p.join("\n")));
    assert_eq!(corpus.cases.len(), 625);
    let summary = corpus.summary();
    assert!(summary.contains("BPF test corpus coverage"), "{summary}");
    let unported = corpus
        .cases
        .iter()
        .filter(|(_, s)| {
            !matches!(
                s.as_deref(),
                Some("ported" | "retargeted" | "replaced" | "dropped")
            )
        })
        .count();
    assert!(
        summary.contains(&format!("  unported: {unported}\n")),
        "{summary}"
    );
    println!("{summary}");
}

fn cases(extra_case: &str, meta_cases: i64) -> String {
    format!(
        r#"[meta]
translation_units = 1
translation_units_compiled = 1
cases = {meta_cases}
check_sections_in_c = {meta_cases}
cases_m1 = {meta_cases}
cases_m2 = 0
cases_m3 = 0

[[file]]
path = "bpf/tests/tc_demo.c"
milestone = 1
case_count = {meta_cases}

  [[file.case]]
  name = "1_first"
  entrypoint = "from_netdev"
  milestone = 1
{extra_case}"#
    )
}

/// A ported case names its test in `tests/<stem>.rs`, which includes the
/// generated assertion: `const _: fn() = <test>;` fails the build when the
/// test is renamed.
#[test]
fn ported_cases_generate_their_assertions() {
    let ported = r#"
[[port]]
file = "bpf/tests/tc_demo.c"
name = "1_first"
status = "ported"
tier = "progrun"
rust = "tc_demo::first_case"
"#;
    let with_include = |s: &str| (s == "tc_demo").then(|| include_line("tc_demo"));
    let corpus =
        Corpus::parse(&cases("", 1), ported, with_include).unwrap_or_else(|p| panic!("{p:?}"));
    let generated = corpus.generated();
    assert_eq!(generated.len(), 1);
    assert!(
        generated
            .get("tc_demo")
            .is_some_and(|code| code.contains("const _: fn() = first_case;\n")),
        "{generated:?}"
    );
    assert!(
        corpus.summary().contains("M1: 1/1 covered"),
        "{}",
        corpus.summary()
    );
    // Without the include, or without the file, the build is refused.
    for source in [None, Some("fn first_case() {}".to_owned())] {
        let problems = Corpus::parse(&cases("", 1), ported, |_| source.clone())
            .err()
            .unwrap_or_default();
        assert!(
            problems.iter().any(|p| p.contains("tests/tc_demo.rs")),
            "{problems:?}"
        );
    }
    assert_eq!(stem("bpf/tests/tc_demo.c"), "tc_demo");
}

/// Each §9.4 check refuses what it should, with the case named.
#[test]
fn inconsistencies_are_refused() {
    let none = |_: &str| None;
    let extra = "
  [[file.case]]
  name = \"2_second\"
  entrypoint = \"to_netdev\"
  milestone = 1
";
    for (cases_text, ported, want) in [
        // [meta] counts not the sums of the rows.
        (cases(extra, 1), String::new(), "case_count"),
        (cases("", 2), String::new(), "[meta] cases is"),
        // A PORTED key that is not a case.
        (
            cases("", 1),
            "[[port]]\nfile = \"bpf/tests/tc_demo.c\"\nname = \"9_missing\"\nstatus = \"deferred\"\n".to_owned(),
            "not a CASES.toml case",
        ),
        // A retargeted case without its disposition; a bad status or tier.
        (
            cases("", 1),
            "[[port]]\nfile = \"bpf/tests/tc_demo.c\"\nname = \"1_first\"\nstatus = \"retargeted\"\n".to_owned(),
            "needs a disposition",
        ),
        (
            cases("", 1),
            "[[port]]\nfile = \"bpf/tests/tc_demo.c\"\nname = \"1_first\"\nstatus = \"done\"\n".to_owned(),
            "is not one of",
        ),
        (
            cases("", 1),
            "[[port]]\nfile = \"bpf/tests/tc_demo.c\"\nname = \"1_first\"\nstatus = \"deferred\"\ntier = \"vm\"\n".to_owned(),
            "tier",
        ),
        // A ported case without a Rust test path in its own file.
        (
            cases("", 1),
            "[[port]]\nfile = \"bpf/tests/tc_demo.c\"\nname = \"1_first\"\nstatus = \"ported\"\nrust = \"other::first\"\n".to_owned(),
            "ported needs rust",
        ),
    ] {
        let problems = Corpus::parse(&cases_text, &ported, none).err().unwrap_or_default();
        assert!(problems.iter().any(|p| p.contains(want)), "{want}: {problems:?}");
    }
    // Deferred, unlisted: counted as unported, by milestone, pipeline, file.
    let deferred =
        "[[port]]\nfile = \"bpf/tests/tc_demo.c\"\nname = \"1_first\"\nstatus = \"deferred\"\n";
    let summary = Corpus::parse(&cases("", 1), deferred, none)
        .map(|c| c.summary())
        .unwrap_or_default();
    for want in [
        "M1: 0/1 covered",
        "unported: 1",
        "by milestone: M1 1",
        "by pipeline: from_netdev 1",
        "bpf/tests/tc_demo.c (1): 1_first",
    ] {
        assert!(summary.contains(want), "{want}: {summary}");
    }
}
