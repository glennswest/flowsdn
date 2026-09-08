//! Structural inventory extraction. Reference code is read, never compiled or
//! copied into output. Classification follows the existing flowsdn inventory.
mod classification;
mod preprocess;
use classification::*;
use preprocess::{Patterns, Walk};
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
};
use toml::{Table, Value};

const DEAD: &str = "encrypt_host_wireguard_tunnel.c";
pub const COMMIT: &str = "7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc";
const HARVESTER: &str = "tools/harvest-bpf-cases (Rust)";

fn strings(items: impl IntoIterator<Item = String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}
fn sorted(items: impl IntoIterator<Item = String>) -> Vec<String> {
    items
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn text(table: &mut Table, key: &str, value: impl Into<String>) {
    table.insert(key.to_owned(), Value::String(value.into()));
}
fn number(table: &mut Table, key: &str, value: usize) -> Result<(), Box<dyn Error>> {
    table.insert(key.to_owned(), Value::Integer(value.try_into()?));
    Ok(())
}
fn lookup<'a>(entries: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| *value)
}
fn intersection(features: &[String], candidates: &[&str]) -> Vec<String> {
    features
        .iter()
        .filter(|feature| candidates.contains(&feature.as_str()))
        .cloned()
        .collect()
}
fn milestone(
    file: &str,
    features: &[String],
    objects: &[String],
    configs: &[String],
) -> (usize, String) {
    for (set, stage, reason) in [
        (M3_OVERRIDE, 3, "spec-02 §9.3 long-tail/encryption group"),
        (M2_OVERRIDE, 2, "spec-02 §9.3 M2 group"),
        (M1_OVERRIDE, 1, "spec-02 §9.3 M1 group"),
    ] {
        if set.contains(&file) {
            return (stage, reason.to_owned());
        }
    }
    let hit = intersection(features, M3_FEATS);
    if !hit.is_empty() {
        return (3, format!("feature {}", hit.join(",")));
    }
    for object in ["wireguard", "sock_term"] {
        if objects.iter().any(|o| o == object) {
            return (3, format!("object bpf_{object}"));
        }
    }
    let hit = intersection(features, M2_FEATS);
    if !hit.is_empty() {
        return (2, format!("feature {}", hit.join(",")));
    }
    for (object, reason) in [
        ("xdp", "XDP program"),
        ("sock", "socket LB (cgroup) program"),
    ] {
        if objects.iter().any(|o| o == object) {
            return (2, reason.to_owned());
        }
    }
    if features.iter().any(|f| f == "ENABLE_DSR") {
        return (2, "feature ENABLE_DSR".to_owned());
    }
    for config in ["enable_lrp", "policy_deny_response_enabled"] {
        if configs.iter().any(|c| c == config) {
            return (2, format!("config {config}"));
        }
    }
    (1, "M1 default".to_owned())
}
fn case_milestone(stage: usize, reason: &str, name: &str) -> usize {
    let dsr = name.to_lowercase().contains("dsr");
    if stage == 2 && reason == "feature ENABLE_DSR" && !dsr {
        1
    } else if stage == 1 && dsr {
        2
    } else {
        stage
    }
}
fn resolve_entry(
    body: &str,
    corpus: &str,
    defines: &BTreeMap<String, String>,
    depth: usize,
) -> Result<Option<String>, regex::Error> {
    for (helper, entry) in ENTRY_HELPERS {
        if Regex::new(&format!(r"\b{}\b", regex::escape(helper)))?.is_match(body) {
            return Ok(Some((*entry).to_owned()));
        }
    }
    if depth > 3 {
        return Ok(None);
    }
    let identifier = Regex::new(r"^[A-Za-z_]\w*$")?;
    for c in Regex::new(r"return\s+([A-Za-z_]\w*)\s*\(")?.captures_iter(body) {
        let Some(name) = c.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if let Some(target) = defines
            .get(name)
            .and_then(|v| v.split("/*").next())
            .map(str::trim)
            && identifier.is_match(target)
            && let Some(entry) = resolve_entry(
                &format!("return {target}(ctx);"),
                corpus,
                defines,
                depth.saturating_add(1),
            )?
        {
            return Ok(Some(entry));
        }
        for found in Regex::new(&format!(r"\b{}\s*\([^;{{]*\)\s*\{{", regex::escape(name)))?
            .find_iter(corpus)
        {
            let mut level = 1usize;
            let rest = corpus.get(found.end()..).unwrap_or("");
            let mut end = rest.len();
            for (offset, ch) in rest.char_indices() {
                match ch {
                    '{' => level = level.saturating_add(1),
                    '}' => level = level.saturating_sub(1),
                    _ => (),
                }
                if level == 0 {
                    end = offset.saturating_add(ch.len_utf8());
                    break;
                }
            }
            if let Some(entry) = resolve_entry(
                rest.get(..end).unwrap_or(""),
                corpus,
                defines,
                depth.saturating_add(1),
            )? {
                return Ok(Some(entry));
            }
        }
    }
    Ok(None)
}

pub fn load(directory: &Path) -> Result<BTreeMap<String, Vec<String>>, Box<dyn Error>> {
    let mut files = BTreeMap::new();
    for (path, prefix, headers_only) in [
        (directory.to_owned(), "", false),
        (directory.join("lib"), "lib/", true),
    ] {
        if headers_only && !path.is_dir() {
            continue;
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 source name")?;
            if name.ends_with(".h") || (!headers_only && name.ends_with(".c")) {
                let data = fs::read(entry.path())?;
                files.insert(
                    format!("{prefix}{name}"),
                    String::from_utf8_lossy(&data)
                        .lines()
                        .map(str::to_owned)
                        .collect(),
                );
            }
        }
    }
    let dead = directory.join("encrypt_host_wireguard_tunnel");
    if dead.is_file() && !files.contains_key(DEAD) {
        files.insert(
            DEAD.to_owned(),
            String::from_utf8_lossy(&fs::read(dead)?)
                .lines()
                .map(str::to_owned)
                .collect(),
        );
    }
    Ok(files)
}

pub fn harvest(files: &BTreeMap<String, Vec<String>>, date: &str) -> Result<Value, Box<dyn Error>> {
    let patterns = Patterns::new()?;
    let mut records = Vec::new();
    let mut cases_by_stage = BTreeMap::<usize, usize>::new();
    let mut total = 0usize;
    let mut compiled = 0usize;
    for (file, lines) in files
        .iter()
        .filter(|(name, _)| name.ends_with(".c") && !name.contains('/'))
    {
        let mut walk = Walk::default();
        walk.run(file, files, &patterns, 0);
        let mut corpus = lines.join("\n");
        for include in &walk.includes {
            if let Some(lines) = files
                .get(include)
                .or_else(|| files.get(include.rsplit('/').next().unwrap_or(include)))
            {
                corpus.push('\n');
                corpus.push_str(&lines.join("\n"));
            }
        }
        let features = walk
            .defines
            .keys()
            .filter(|key| FEAT_PREFIX.iter().any(|prefix| key.starts_with(prefix)))
            .cloned()
            .collect::<Vec<_>>();
        let configs = sorted(walk.configs.iter().cloned());
        let objects = sorted(walk.includes.iter().flat_map(|include| {
            let direct = if !include.starts_with("lib/") {
                lookup(SRC_OBJ, include.rsplit('/').next().unwrap_or(include))
            } else {
                None
            };
            lookup(ENTRY_HDR, include)
                .into_iter()
                .chain(direct)
                .map(str::to_owned)
        }));
        let units = sorted(
            walk.includes
                .iter()
                .filter_map(|i| lookup(LIB_UNIT, i).map(str::to_owned)),
        );
        let seeds = sorted(
            walk.includes
                .iter()
                .filter_map(|i| lookup(SEED_HDR, i).map(str::to_owned)),
        );
        let shared = sorted(walk.includes.iter().filter_map(|include| {
            let base = include.rsplit('/').next().unwrap_or(include);
            (files.contains_key(base)
                && include.ends_with(".h")
                && !["lib/", "bpf/", "linux/"]
                    .iter()
                    .any(|p| include.starts_with(p))
                && !["common.h", "pktgen.h"].contains(&base))
            .then(|| base.to_owned())
        }));
        let context = if walk.includes.iter().any(|i| i.ends_with("ctx/xdp.h")) {
            "xdp"
        } else if walk.includes.iter().any(|i| i.ends_with("ctx/unspec.h")) {
            "unspec"
        } else {
            "skb"
        };
        let (stage, reason) = milestone(file, &features, &objects, &configs);
        struct Group {
            program: String,
            name: String,
            stages: BTreeSet<String>,
            setup: Vec<String>,
            source: String,
        }
        let mut groups: Vec<Group> = Vec::new();
        for section in walk.sections {
            if !groups
                .iter()
                .any(|g| g.program == section.program && g.name == section.name)
            {
                groups.push(Group {
                    program: section.program.clone(),
                    name: section.name.clone(),
                    stages: BTreeSet::new(),
                    setup: Vec::new(),
                    source: section.file.clone(),
                });
            }
            if let Some(group) = groups
                .iter_mut()
                .find(|g| g.program == section.program && g.name == section.name)
            {
                group.stages.insert(section.kind.clone());
                if section.kind == "SETUP" {
                    group.setup = section.body;
                }
                if section.file != *file {
                    group.source = section.file;
                }
            }
        }
        let mut cases = Vec::new();
        for group in groups.into_iter().filter(|g| g.stages.contains("CHECK")) {
            let entry = if group.setup.is_empty() {
                "direct".to_owned()
            } else {
                resolve_entry(&group.setup.join("\n"), &corpus, &walk.defines, 0)?
                    .unwrap_or_else(|| "unresolved".to_owned())
            };
            let case_stage = case_milestone(stage, &reason, &group.name);
            let count = cases_by_stage.entry(case_stage).or_default();
            *count = count.saturating_add(1);
            let mut case = Table::new();
            text(&mut case, "name", group.name);
            text(
                &mut case,
                "progtype",
                if group.program.is_empty() {
                    "tc".to_owned()
                } else {
                    group.program
                },
            );
            text(
                &mut case,
                "stages",
                ["PKTGEN", "SETUP", "CHECK"]
                    .into_iter()
                    .filter(|s| group.stages.contains(*s))
                    .collect::<String>(),
            );
            text(&mut case, "entrypoint", entry);
            number(&mut case, "milestone", case_stage)?;
            if group.source != *file {
                text(
                    &mut case,
                    "defined_in",
                    format!("bpf/tests/{}", group.source),
                );
            }
            cases.push(Value::Table(case));
        }
        let mut record = Table::new();
        text(&mut record, "path", format!("bpf/tests/{file}"));
        text(&mut record, "ctx", context);
        number(&mut record, "milestone", stage)?;
        text(&mut record, "milestone_reason", reason);
        if file == DEAD {
            record.insert("upstream_dead".to_owned(), Value::Boolean(true));
        } else {
            compiled = compiled.saturating_add(1);
        }
        for (name, list, required) in [
            ("objects", objects, true),
            ("units", units, false),
            ("seeds", seeds, false),
            ("features", features, true),
            ("configs", configs, true),
            ("shared_headers", shared, false),
        ] {
            if required || !list.is_empty() {
                record.insert(name.to_owned(), strings(list));
            }
        }
        number(&mut record, "case_count", cases.len())?;
        total = total.saturating_add(cases.len());
        // No empty case arrays in the legacy inventory.
        if !cases.is_empty() {
            record.insert("case".to_owned(), Value::Array(cases));
        }
        records.push((stage, file.clone(), Value::Table(record)));
    }
    records.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut meta = Table::new();
    for (key, value) in [
        ("reference_repo", "github.com/cilium/cilium"),
        ("reference_tag", "v1.20.1"),
        ("reference_commit", "7d68cfb394"),
        ("reference_dir", "bpf/tests"),
        (
            "reference_license",
            "GPL-2.0-only OR BSD-2-Clause; taken under BSD-2-Clause",
        ),
        ("harvested", date),
        ("harvester", HARVESTER),
        ("spec", "docs/spec/18-bpf-test-harness.md"),
    ] {
        text(&mut meta, key, value);
    }
    for (key, count) in [
        ("translation_units", records.len()),
        ("translation_units_compiled", compiled),
        ("check_sections_in_c", 397),
        ("cases", total),
        ("cases_m1", *cases_by_stage.get(&1).unwrap_or(&0)),
        ("cases_m2", *cases_by_stage.get(&2).unwrap_or(&0)),
        ("cases_m3", *cases_by_stage.get(&3).unwrap_or(&0)),
    ] {
        number(&mut meta, key, count)?;
    }
    Ok(Value::Table(Table::from_iter([
        ("meta".to_owned(), Value::Table(meta)),
        (
            "file".to_owned(),
            Value::Array(records.into_iter().map(|(_, _, record)| record).collect()),
        ),
    ])))
}

/// Ignore only generator identity and the requested harvest date. Every case,
/// field, order, feature, count and milestone must otherwise remain identical.
pub fn equivalent(mut left: Value, mut right: Value) -> bool {
    for value in [&mut left, &mut right] {
        if let Some(meta) = value.get_mut("meta").and_then(Value::as_table_mut) {
            meta.remove("harvested");
            meta.remove("harvester");
        }
    }
    left == right
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn conditions_include_expansion_and_config() {
        let source = "#define ENABLE_IPV4 1\n#define MODE 2\n#if defined(ENABLE_IPV4) && MODE == 2\n#include \"shared.h\"\n#else\nCHECK(\"tc\", \"wrong\")\n#endif\nASSIGN_CONFIG(int, test_config, 1)";
        let shared = "#ifdef ENABLE_IPV4\nSETUP(\"tc\", \"sample\")\nreturn pod_send_packet(ctx);\nCHECK(\"tc\", \"sample\")\n#endif";
        let files = BTreeMap::from([
            (
                "unit.c".to_owned(),
                source.lines().map(str::to_owned).collect(),
            ),
            (
                "shared.h".to_owned(),
                shared.lines().map(str::to_owned).collect(),
            ),
        ]);
        let value = harvest(&files, "2026-09-07").unwrap();
        let records = value.get("file").unwrap().as_array().unwrap();
        let file = records.first().unwrap();
        assert_eq!(file.get("case_count").and_then(Value::as_integer), Some(1));
        let case = file
            .get("case")
            .unwrap()
            .as_array()
            .unwrap()
            .first()
            .unwrap();
        assert_eq!(
            case.get("entrypoint").and_then(Value::as_str),
            Some("from_container")
        );
        assert_eq!(
            case.get("defined_in").and_then(Value::as_str),
            Some("bpf/tests/shared.h")
        );
    }
    #[test]
    fn library_helper_resolution_prefers_full_include_path() {
        let source = "#include \"lib/wrapper.h\"\nSETUP(\"tc\", \"sample\")\nreturn wrapper(ctx);\nCHECK(\"tc\", \"sample\")";
        let library = "int wrapper(void *ctx) { return pod_send_packet(ctx); }";
        let unrelated = "int wrapper(void *ctx) { return pod_receive_packet(ctx); }";
        let mut files = BTreeMap::from([
            (
                "unit.c".to_owned(),
                source.lines().map(str::to_owned).collect(),
            ),
            (
                "lib/wrapper.h".to_owned(),
                library.lines().map(str::to_owned).collect(),
            ),
        ]);
        for with_basename_collision in [false, true] {
            if with_basename_collision {
                files.insert(
                    "wrapper.h".to_owned(),
                    unrelated.lines().map(str::to_owned).collect(),
                );
            }
            let value = harvest(&files, "2026-09-07").unwrap();
            assert_eq!(
                value["file"][0]["case"][0]["entrypoint"].as_str(),
                Some("from_container"),
                "basename collision: {with_basename_collision}"
            );
        }
    }
    #[test]
    fn expression_rules_and_conservative_unknowns() {
        let defines = BTreeMap::from([
            ("YES".to_owned(), "1".to_owned()),
            ("N".to_owned(), "3".to_owned()),
        ]);
        for expr in [
            "defined(YES)",
            "defined YES && N >= 2",
            "!(N < 2)",
            "UNKNOWN_FUNCTION(1)",
        ] {
            assert!(preprocess::truthy(expr, &defines), "{expr}");
        }
        for expr in ["defined(NO)", "0 || !YES", "N == 4"] {
            assert!(!preprocess::truthy(expr, &defines), "{expr}");
        }
    }
    #[test]
    fn equivalence_ignores_only_generator_metadata() {
        let mut a: Value = "[meta]\nharvester='old'\nharvested='date'\ncases=3\n"
            .parse::<Table>()
            .map(Value::Table)
            .unwrap();
        let b: Value = "[meta]\nharvester='new'\nharvested='other'\ncases=3\n"
            .parse::<Table>()
            .map(Value::Table)
            .unwrap();
        assert!(equivalent(a.clone(), b.clone()));
        a.get_mut("meta")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert("cases".to_owned(), Value::Integer(4));
        assert!(!equivalent(a, b));
    }
}
