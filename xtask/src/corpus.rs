//! Read-only naming inventory. Never executes a harvested command or rewrites
//! fixture bytes. Exact snapshot comparison exposes changes requiring review.
use flowsdn_scripttest::{Archive, Line, parse_script, tokenize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
};
fn files(root: &Path, output: &mut Vec<std::path::PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            files(&entry.path(), output)?;
        } else if kind.is_file() && entry.path().extension().is_some_and(|s| s == "txtar") {
            output.push(entry.path());
        }
    }
    Ok(())
}
fn startup_flags(script: &str) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut flags = BTreeSet::new();
    for (index, line) in script.lines().enumerate() {
        if let Some(line) = line.strip_prefix("#!") {
            for token in tokenize(line, index.saturating_add(1))? {
                let value = token.literal();
                if let Some(flag) = value.strip_prefix("--") {
                    let name = flag.split('=').next().ok_or("empty flag")?;
                    if name.is_empty() {
                        return Err("empty startup flag".into());
                    }
                    flags.insert(name.to_owned());
                }
            }
        }
    }
    Ok(flags)
}
pub fn report() -> Result<Value, Box<dyn Error>> {
    let mut paths = Vec::new();
    files(Path::new("tests/scripttest/corpus"), &mut paths)?;
    paths.sort();
    let mut flags: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut commands: BTreeSet<String> = BTreeSet::new();
    let mut names: BTreeSet<String> = BTreeSet::new();
    let symbols = regex::Regex::new(r"\bcilium_[A-Za-z0-9_]+\b")?;
    for path in &paths {
        let source = fs::read_to_string(path)?;
        let archive = Archive::parse(&source)?;
        for key in startup_flags(archive.script())? {
            flags
                .entry(key)
                .or_default()
                .insert(path.to_string_lossy().into_owned());
        }
        for line in parse_script(archive.script())? {
            if let Line::Command(command) = line {
                if let Some(name) = command.words.first() {
                    commands.insert(name.literal());
                }
            }
        }
        names.extend(symbols.find_iter(&source).map(|m| m.as_str().to_owned()));
    }
    let unknown: Vec<_> = flags
        .keys()
        .filter(|key| flowsdn_config::catalogue::get(key).is_none())
        .cloned()
        .collect();
    Ok(
        json!({"reference":"7d68cfb394", "files":paths.len(), "startup_flags":flags,
        "flags_outside_agent_catalogue":unknown,"commands":commands,"preserved_cilium_symbols":names,
        "naming_rewrites":[],"note":"Unknown startup flags require area-fixture classification, not automatic renaming. Commands are syntax-inventoried, not claimed implemented. Embedded data is preserved."}),
    )
}
pub fn run(check: bool) -> Result<(), Box<dyn Error>> {
    let report = report()?;
    if check {
        let expected: Value =
            serde_json::from_str(&fs::read_to_string("tests/scripttest/naming-audit.json")?)?;
        if expected != report {
            return Err(
                "corpus naming inventory changed; regenerate and review naming-audit.json".into(),
            );
        }
        println!("corpus naming inventory matches reviewed snapshot");
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_names_ignore_flag_values_and_embedded_data() {
        let archive=Archive::parse("#! --cluster-name=--not-a-key --metrics '+cilium_metric'\necho --command-flag\n-- data --\n#! --embedded\n").expect("archive");
        assert_eq!(
            startup_flags(archive.script()).expect("flags"),
            BTreeSet::from(["cluster-name".into(), "metrics".into()])
        );
    }
}
