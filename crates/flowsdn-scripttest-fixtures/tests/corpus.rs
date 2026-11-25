//! The corpus gate (spec 17 §3.7, §9.4; #516): every harvested script of
//! every area with a fixture runs against flowsdn, and passes, or fails
//! where its area's `DIVERGENCES.toml` says it must (XFAIL). A failure
//! anywhere else, or an expected failure that passes (XPASS: a stale entry),
//! fails the gate.
use flowsdn_scripttest::{
    Archive, State,
    report::{Outcome, classify, load, skipped},
};
use flowsdn_scripttest_fixtures::areas::{AREAS, build};
use std::{collections::BTreeSet, fs, path::Path};

#[test]
fn harvested_areas_pass_or_diverge_as_recorded() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/scripttest/corpus");
    let mut seen = BTreeSet::new();
    let mut results = Vec::new();
    for area in AREAS {
        let dir = corpus.join(area);
        let divergences = match fs::read_to_string(dir.join("DIVERGENCES.toml")) {
            Ok(text) => load(&text, area, &mut seen).unwrap_or_else(|e| panic!("{area}: {e}")),
            Err(_) => Vec::new(),
        };
        let mut scripts: Vec<String> = fs::read_dir(&dir)
            .expect("area directory")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".txtar"))
            .collect();
        scripts.sort();
        assert!(!scripts.is_empty(), "{area} has no scripts");
        for file in scripts {
            let script = format!("{area}/{file}");
            if let Some(id) = skipped(&script, &divergences) {
                results.push((script, Outcome::Skip(id)));
                continue;
            }
            let text = fs::read_to_string(dir.join(&file)).expect("script");
            let archive = Archive::parse(&text).unwrap_or_else(|e| panic!("{script}: {e}"));
            let flags: Vec<String> = archive.flags().into_iter().map(str::to_owned).collect();
            let engine = build(area, &flags).unwrap_or_else(|e| panic!("{script}: {e}"));
            let mut state = State::with_workspace(&std::env::temp_dir(), &dir).expect("workspace");
            state
                .materialize(&archive)
                .unwrap_or_else(|e| panic!("{script}: {e}"));
            let failure = engine
                .run(archive.script(), &mut state)
                .err()
                .map(|e| (e.line, format!("{}: {}", e.command, e.message)));
            let outcome = classify(&script, failure, &divergences);
            if outcome.is_failure() {
                // What the script saw, for whoever reads the failure.
                println!("--- {script}\n{}", engine.diagnostic_dump(&state));
                if let Ok(actual) = state.read_text("actual.yaml") {
                    println!("--- {script} actual.yaml\n{actual}");
                }
            }
            results.push((script.clone(), outcome));
        }
    }
    let mut failures = Vec::new();
    for (script, outcome) in &results {
        println!("{outcome:?} {script}");
        if outcome.is_failure() {
            failures.push(format!("{script}: {outcome:?}"));
        }
    }
    let count = |f: fn(&Outcome) -> bool| results.iter().filter(|(_, o)| f(o)).count();
    println!(
        "scripttest corpus: {} PASS, {} XFAIL, {} SKIP, {} FAIL, {} XPASS",
        count(|o| matches!(o, Outcome::Pass)),
        count(|o| matches!(o, Outcome::Xfail(_))),
        count(|o| matches!(o, Outcome::Skip(_))),
        count(|o| matches!(o, Outcome::Fail(_))),
        count(|o| matches!(o, Outcome::Xpass(_))),
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
