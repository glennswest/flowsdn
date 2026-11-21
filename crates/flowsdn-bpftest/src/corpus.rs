//! The harvested BPF test corpus (spec 18 §5.3, §9.4, §11.3, #473):
//! `tests/bpf/CASES.toml` (the reference's cases, generated) and
//! `tests/bpf/PORTED.toml` (flowsdn's disposition of each). [`Corpus::parse`]
//! checks them against each other (the §9.4 consistency checks),
//! [`Corpus::generated`] is the compile-time assertion per reference file
//! that its ported cases' Rust tests exist, and [`Corpus::summary`] the
//! coverage report. Included by the crate's `build.rs` (which fails the
//! build on an inconsistency and writes both), its `tests/corpus.rs`, and
//! `cargo xtask cases`.
use std::collections::{BTreeMap, BTreeSet};
use toml::{Table, Value};

/// The `PORTED.toml` statuses, and the ones §5.3 counts as covered.
const STATUSES: [&str; 5] = ["ported", "deferred", "retargeted", "replaced", "dropped"];
const COVERED: [&str; 3] = ["ported", "retargeted", "replaced"];
/// The statuses that must say why.
const EXPLAINED: [&str; 3] = ["retargeted", "replaced", "dropped"];
/// The tiers of spec 18 §10.3.
const TIERS: [&str; 4] = ["progrun", "netns", "direct", "tier0"];

/// One harvested case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Case {
    /// The reference file (`bpf/tests/<stem>.c`).
    pub file: String,
    pub name: String,
    pub milestone: i64,
    /// The pipeline: the entrypoint under test.
    pub entrypoint: String,
}

/// The checked corpus: every case and its `PORTED.toml` status, if any.
#[derive(Clone, Debug, Default)]
pub struct Corpus {
    pub cases: Vec<(Case, Option<String>)>,
    /// `status = "ported"` entries: reference file stem -> Rust test names.
    pub ported: BTreeMap<String, BTreeSet<String>>,
}

/// The file stem of a reference path: `bpf/tests/tc_nodeport.c` -> `tc_nodeport`.
pub fn stem(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.strip_suffix(".c").unwrap_or(name)
}

fn text<'a>(table: &'a Table, key: &str) -> Option<&'a str> {
    table.get(key).and_then(Value::as_str)
}
fn integer(table: &Table, key: &str) -> Option<i64> {
    table.get(key).and_then(Value::as_integer)
}
fn tables<'a>(table: &'a Table, key: &str) -> Vec<&'a Table> {
    table
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_table).collect())
        .unwrap_or_default()
}
fn count(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The line a hand-written `tests/<stem>.rs` includes its assertions with.
pub fn include_line(stem: &str) -> String {
    format!("include!(concat!(env!(\"OUT_DIR\"), \"/ported/{stem}.rs\"));")
}

impl Corpus {
    /// Parse and check `cases` and `ported` (spec 18 §9.4). `test_source`
    /// gives a ported file's `tests/<stem>.rs`, which must include its
    /// generated assertions. Every problem found is returned, one line each.
    pub fn parse(
        cases: &str,
        ported: &str,
        test_source: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, Vec<String>> {
        let mut problems = Vec::new();
        let cases: Table = cases
            .parse()
            .map_err(|e| vec![format!("CASES.toml does not parse: {e}")])?;
        let ported: Table = ported
            .parse()
            .map_err(|e| vec![format!("PORTED.toml does not parse: {e}")])?;
        let mut corpus = Self::default();
        let files = tables(&cases, "file");
        let mut keys = BTreeSet::new();
        let (mut by_milestone, mut direct) = (BTreeMap::<i64, i64>::new(), 0i64);
        for file in &files {
            let path = text(file, "path").unwrap_or_default();
            let listed = tables(file, "case");
            if integer(file, "case_count") != Some(count(listed.len())) {
                problems.push(format!(
                    "CASES.toml: {path} case_count {:?} but {} cases",
                    integer(file, "case_count"),
                    listed.len()
                ));
            }
            for case in listed {
                let name = text(case, "name").unwrap_or_default();
                let Some(milestone) = integer(case, "milestone") else {
                    problems.push(format!("CASES.toml: {path} {name} has no milestone"));
                    continue;
                };
                if !keys.insert((path.to_owned(), name.to_owned())) {
                    problems.push(format!("CASES.toml: {path} {name} is listed twice"));
                }
                let entry = by_milestone.entry(milestone).or_default();
                *entry = entry.saturating_add(1);
                if case.get("defined_in").is_none() {
                    direct = direct.saturating_add(1);
                }
                corpus.cases.push((
                    Case {
                        file: path.to_owned(),
                        name: name.to_owned(),
                        milestone,
                        entrypoint: text(case, "entrypoint").unwrap_or("unresolved").to_owned(),
                    },
                    None,
                ));
            }
        }
        // [meta] counts equal the sums of the rows.
        let meta = cases
            .get("meta")
            .and_then(Value::as_table)
            .cloned()
            .unwrap_or_default();
        let dead = files
            .iter()
            .filter(|f| f.get("upstream_dead").and_then(Value::as_bool) == Some(true))
            .count();
        let milestone = |m: i64| by_milestone.get(&m).copied().unwrap_or(0);
        for (key, want) in [
            ("translation_units", count(files.len())),
            (
                "translation_units_compiled",
                count(files.len().saturating_sub(dead)),
            ),
            ("cases", count(corpus.cases.len())),
            ("check_sections_in_c", direct),
            ("cases_m1", milestone(1)),
            ("cases_m2", milestone(2)),
            ("cases_m3", milestone(3)),
        ] {
            if integer(&meta, key) != Some(want) {
                problems.push(format!(
                    "CASES.toml: [meta] {key} is {:?}, the rows sum to {want}",
                    integer(&meta, key)
                ));
            }
        }
        // Every PORTED key resolves; statuses, tiers, Rust paths, dispositions.
        let mut statuses = BTreeMap::new();
        for port in tables(&ported, "port") {
            let (file, name) = (
                text(port, "file").unwrap_or_default(),
                text(port, "name").unwrap_or_default(),
            );
            let what = format!("PORTED.toml: {file} {name}");
            if !keys.contains(&(file.to_owned(), name.to_owned())) {
                problems.push(format!("{what} is not a CASES.toml case"));
                continue;
            }
            let status = text(port, "status").unwrap_or_default();
            if !STATUSES.contains(&status) {
                problems.push(format!("{what}: status {status:?} is not one of {STATUSES:?}"));
                continue;
            }
            if let Some(tier) = text(port, "tier")
                && !TIERS.contains(&tier)
            {
                problems.push(format!("{what}: tier {tier:?} is not one of {TIERS:?}"));
            }
            if EXPLAINED.contains(&status)
                && text(port, "disposition").is_none_or(|d| d.trim().is_empty())
            {
                problems.push(format!("{what}: {status} needs a disposition"));
            }
            if status == "ported" {
                let stem = stem(file);
                match text(port, "rust").and_then(|r| r.split_once("::")) {
                    Some((module, test)) if module == stem && !test.is_empty() => {
                        corpus
                            .ported
                            .entry(stem.to_owned())
                            .or_default()
                            .insert(test.to_owned());
                    }
                    _ => problems.push(format!(
                        "{what}: ported needs rust = \"{stem}::<test fn>\" (its test in tests/{stem}.rs)"
                    )),
                }
            }
            if statuses
                .insert((file.to_owned(), name.to_owned()), status.to_owned())
                .is_some()
            {
                problems.push(format!("{what} has two entries"));
            }
        }
        // Each file with ported cases includes its generated assertions.
        for stem in corpus.ported.keys() {
            match test_source(stem) {
                None => problems.push(format!(
                    "tests/{stem}.rs is missing: PORTED.toml names tests in it"
                )),
                Some(source) if !source.contains(&include_line(stem)) => problems.push(format!(
                    "tests/{stem}.rs does not include its ported-case assertions: {}",
                    include_line(stem)
                )),
                Some(_) => {}
            }
        }
        for (case, status) in &mut corpus.cases {
            *status = statuses.get(&(case.file.clone(), case.name.clone())).cloned();
        }
        if problems.is_empty() {
            Ok(corpus)
        } else {
            Err(problems)
        }
    }

    /// Per reference file stem with ported cases, the code that fails to
    /// compile when one of their tests is renamed or removed.
    pub fn generated(&self) -> BTreeMap<String, String> {
        self.ported
            .iter()
            .map(|(stem, tests)| {
                let mut code = format!(
                    "// Generated by flowsdn-bpftest's build.rs from tests/bpf/PORTED.toml (#473):\n// every ported case of bpf/tests/{stem}.c names a test of this file.\n"
                );
                for test in tests {
                    code.push_str(&format!("const _: fn() = {test};\n"));
                }
                (stem.clone(), code)
            })
            .collect()
    }

    /// The coverage report (spec 18 §5.3, §8.4): covered/total per
    /// milestone (cumulative), and the unported cases per milestone, file
    /// and pipeline, with their names.
    pub fn summary(&self) -> String {
        let covered = |status: &Option<String>| {
            status
                .as_deref()
                .is_some_and(|s| COVERED.contains(&s))
        };
        let dropped = |status: &Option<String>| status.as_deref() == Some("dropped");
        let unported: Vec<&Case> = self
            .cases
            .iter()
            .filter(|(_, s)| !covered(s) && !dropped(s))
            .map(|(c, _)| c)
            .collect();
        let mut out = String::from("BPF test corpus coverage (spec 18 §5.3)\n");
        for m in 1..=3 {
            let within = || self.cases.iter().filter(move |(c, _)| c.milestone <= m);
            let total = within().filter(|(_, s)| !dropped(s)).count();
            let done = within().filter(|(_, s)| covered(s)).count();
            out.push_str(&format!("  M{m}: {done}/{total} covered\n"));
        }
        out.push_str(&format!("  unported: {}\n", unported.len()));
        let group = |key: fn(&Case) -> String| {
            let mut groups: BTreeMap<String, usize> = BTreeMap::new();
            for case in &unported {
                let entry = groups.entry(key(case)).or_default();
                *entry = entry.saturating_add(1);
            }
            groups
                .into_iter()
                .map(|(k, n)| format!("{k} {n}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "  unported by milestone: {}\n",
            group(|c| format!("M{}", c.milestone))
        ));
        out.push_str(&format!(
            "  unported by pipeline: {}\n",
            group(|c| c.entrypoint.clone())
        ));
        out.push_str("  unported by file:\n");
        let mut by_file: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for case in &unported {
            by_file.entry(&case.file).or_default().push(&case.name);
        }
        for (file, names) in by_file {
            out.push_str(&format!("    {file} ({}): {}\n", names.len(), names.join(" ")));
        }
        out
    }
}
