//! Expected divergences and results (spec 17 §3.7, ADR-0005).
//!
//! A harvested script that must fail because flowsdn deliberately differs is
//! annotated beside it, never edited: `tests/scripttest/corpus/<area>/DIVERGENCES.toml`
//! lists `[[divergence]]` entries with `id`, `script` (`<area>/<file>.txtar` or
//! `<area>/*.txtar`), `adr`, `kind` (`expected-fail`, `skip`, `partial`),
//! `reason` and, for `partial`, `lines`. Every entry names an ADR; ids are
//! unique. A script with an `expected-fail` entry that passes is an XPASS,
//! which is a failure: the entry is stale.
use std::collections::BTreeSet;

/// How a divergence treats its script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    ExpectedFail,
    Skip,
    /// A failure on one of these lines is expected; any other is not.
    Partial(Vec<usize>),
}

/// One `[[divergence]]` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Divergence {
    pub id: String,
    pub script: String,
    pub adr: String,
    pub kind: Kind,
    pub reason: String,
}

impl Divergence {
    /// Whether this entry covers `script` (`<area>/<file>.txtar`).
    pub fn covers(&self, script: &str) -> bool {
        match self.script.strip_suffix("/*.txtar") {
            Some(area) => script
                .strip_prefix(area)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|file| !file.contains('/') && file.ends_with(".txtar")),
            None => self.script == script,
        }
    }
}

/// Parse an area's `DIVERGENCES.toml`. Refused: an entry without an ADR, an
/// unknown kind, a `partial` without lines, a script outside `area`, a
/// duplicate id (within the file; `seen` carries ids across areas).
pub fn load(text: &str, area: &str, seen: &mut BTreeSet<String>) -> Result<Vec<Divergence>, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("DIVERGENCES.toml: {e}"))?;
    let entries = match table.get("divergence") {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(entries)) => entries,
        Some(_) => return Err("DIVERGENCES.toml: divergence must be an array of tables".into()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let field = |name: &str| -> Result<String, String> {
            entry
                .get(name)
                .and_then(toml::Value::as_str)
                .filter(|v| !v.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("DIVERGENCES.toml: an entry has no {name}"))
        };
        let id = field("id")?;
        let script = field("script")?;
        let adr = field("adr")?;
        let reason = field("reason")?;
        if !adr.starts_with("ADR-") {
            return Err(format!("divergence {id}: adr must name an ADR (ADR-NNNN), not {adr}"));
        }
        if !script.starts_with(&format!("{area}/")) || !script.ends_with(".txtar") {
            return Err(format!("divergence {id}: script {script} is not an {area}/*.txtar"));
        }
        let kind = match field("kind")?.as_str() {
            "expected-fail" => Kind::ExpectedFail,
            "skip" => Kind::Skip,
            "partial" => {
                let lines: Vec<usize> = entry
                    .get("lines")
                    .and_then(toml::Value::as_array)
                    .map(|l| {
                        l.iter()
                            .filter_map(toml::Value::as_integer)
                            .filter_map(|n| usize::try_from(n).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                if lines.is_empty() {
                    return Err(format!("divergence {id}: partial needs lines"));
                }
                Kind::Partial(lines)
            }
            other => return Err(format!("divergence {id}: unknown kind {other}")),
        };
        if !seen.insert(id.clone()) {
            return Err(format!("divergence {id}: duplicate id"));
        }
        out.push(Divergence {
            id,
            script,
            adr,
            kind,
            reason,
        });
    }
    Ok(out)
}

/// One script's result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    Pass,
    Fail(String),
    /// Failed as a divergence says it must: its id.
    Xfail(String),
    /// Passed although a divergence says it must fail: its id (a failure).
    Xpass(String),
    Skip(String),
}

impl Outcome {
    /// A failure of the corpus gate: a real failure or a stale divergence.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Fail(_) | Self::Xpass(_))
    }
}

/// Whether `script` is skipped, before running it: the skip entry's id.
pub fn skipped(script: &str, divergences: &[Divergence]) -> Option<String> {
    divergences
        .iter()
        .find(|d| d.kind == Kind::Skip && d.covers(script))
        .map(|d| d.id.clone())
}

/// Classify a finished run of `script`: `failure` is the failing line and
/// message, None when it passed.
pub fn classify(script: &str, failure: Option<(usize, String)>, divergences: &[Divergence]) -> Outcome {
    let covering: Vec<&Divergence> = divergences.iter().filter(|d| d.covers(script)).collect();
    match failure {
        None => covering
            .iter()
            .find(|d| d.kind == Kind::ExpectedFail)
            .map_or(Outcome::Pass, |d| Outcome::Xpass(d.id.clone())),
        Some((line, message)) => {
            for d in &covering {
                match &d.kind {
                    Kind::ExpectedFail => return Outcome::Xfail(d.id.clone()),
                    Kind::Partial(lines) if lines.contains(&line) => {
                        return Outcome::Xfail(d.id.clone());
                    }
                    _ => {}
                }
            }
            Outcome::Fail(format!("line {line}: {message}"))
        }
    }
}
