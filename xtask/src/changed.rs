//! Conservative workspace change selection; dependency kinds all participate.
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    path::Path,
    process::Command,
};

#[derive(Debug)]
struct Package {
    root: String,
    dependencies: BTreeSet<String>,
}

fn graph(metadata: &Value) -> Result<BTreeMap<String, Package>, Box<dyn Error>> {
    let root = Path::new(
        metadata
            .get("workspace_root")
            .and_then(Value::as_str)
            .ok_or("missing workspace root")?,
    );
    let members: BTreeSet<_> = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or("missing members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut packages = BTreeMap::new();
    for package in metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("missing packages")?
    {
        let id = package
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing package id")?;
        if !members.contains(id) {
            continue;
        }
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or("missing package name")?;
        let manifest = Path::new(
            package
                .get("manifest_path")
                .and_then(Value::as_str)
                .ok_or("missing manifest path")?,
        );
        let directory = manifest
            .parent()
            .ok_or("manifest has no parent")?
            .strip_prefix(root)?
            .to_str()
            .ok_or("non-UTF8 package path")?
            .replace('\\', "/");
        let dependencies = package
            .get("dependencies")
            .and_then(Value::as_array)
            .ok_or("missing dependencies")?
            .iter()
            .filter(|d| d.get("path").and_then(Value::as_str).is_some())
            .filter_map(|d| d.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect();
        packages.insert(
            name.to_owned(),
            Package {
                root: directory,
                dependencies,
            },
        );
    }
    Ok(packages)
}

fn select(packages: &BTreeMap<String, Package>, files: &[String]) -> BTreeSet<String> {
    let all = || packages.keys().cloned().collect();
    let mut selected = BTreeSet::new();
    for file in files {
        // Manifests/lock/config can change dependency resolution or flags globally.
        if file == "Cargo.lock"
            || file.ends_with("Cargo.toml")
            || file.starts_with(".cargo/")
            || file.starts_with(".github/")
            || file == "rust-toolchain.toml"
            || file == "deny.toml"
            || file == "Cross.toml"
        {
            return all();
        }
        if let Some((name, _)) = packages
            .iter()
            .filter(|(_, p)| p.root.is_empty() || file.starts_with(&format!("{}/", p.root)))
            .max_by_key(|(_, p)| p.root.len())
        {
            selected.insert(name.clone());
        } else if !(file.starts_with("docs/")
            || matches!(
                file.as_str(),
                "README.md" | "CHANGELOG.md" | "CLAUDE.md" | "AGENTS.md" | "LICENSE" | "NOTICE"
            ))
        {
            // Shared fixtures, removed crates and unfamiliar inputs require all checks.
            return all();
        }
    }
    loop {
        let before = selected.len();
        for (name, package) in packages {
            if package.dependencies.iter().any(|d| selected.contains(d)) {
                selected.insert(name.clone());
            }
        }
        if selected.len() == before {
            break;
        }
    }
    selected
}

fn output(command: &mut Command) -> Result<Vec<u8>, Box<dyn Error>> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

pub fn plan(base: &str) -> Result<Vec<String>, Box<dyn Error>> {
    // Resolve to object IDs before passing revision arguments to other git commands.
    let revision = format!("{base}^{{commit}}");
    let resolved = String::from_utf8(output(Command::new("git").args([
        "rev-parse",
        "--verify",
        "--end-of-options",
        &revision,
    ]))?)?;
    let ancestor = String::from_utf8(output(Command::new("git").args([
        "merge-base",
        resolved.trim(),
        "HEAD",
    ]))?)?;
    let bytes = output(Command::new("git").args([
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        ancestor.trim(),
        "HEAD",
        "--",
    ]))?;
    let files = bytes
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8(p.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let metadata: Value = serde_json::from_slice(&output(Command::new("cargo").args([
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--no-deps",
    ]))?)?;
    Ok(select(&graph(&metadata)?, &files).into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn workspace() -> BTreeMap<String, Package> {
        [
            ("table", "crates/table", vec![]),
            ("agent", "crates/agent", vec!["table"]),
            ("cli", "tools/cli", vec!["agent"]),
            ("other", "crates/other", vec![]),
        ]
        .into_iter()
        .map(|(n, r, d)| {
            (
                n.to_owned(),
                Package {
                    root: r.to_owned(),
                    dependencies: d.into_iter().map(str::to_owned).collect(),
                },
            )
        })
        .collect()
    }
    fn chosen(files: &[&str]) -> BTreeSet<String> {
        select(
            &workspace(),
            &files.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        )
    }
    #[test]
    fn documents_and_empty_diff_skip_checks() {
        assert!(chosen(&["docs/spec/00.md", "README.md"]).is_empty());
        assert!(chosen(&[]).is_empty());
    }
    #[test]
    fn source_selects_transitive_dependents() {
        assert_eq!(
            chosen(&["crates/table/src/lib.rs"]),
            ["table", "agent", "cli"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
    }
    #[test]
    fn leaf_and_package_data_stay_scoped() {
        assert_eq!(
            chosen(&["tools/cli/README.md"]),
            BTreeSet::from(["cli".to_owned()])
        );
    }
    #[test]
    fn global_unknown_and_removed_paths_are_conservative() {
        for path in [
            "Cargo.lock",
            "crates/table/Cargo.toml",
            "tests/corpus/a.txtar",
            "crates/gone/src/lib.rs",
            ".cargo/config.toml",
        ] {
            assert_eq!(chosen(&[path]).len(), 4, "{path}");
        }
    }
    #[test]
    fn dependency_cycles_terminate() {
        let mut g = workspace();
        if let Some(p) = g.get_mut("table") {
            p.dependencies.insert("cli".to_owned());
        }
        assert_eq!(select(&g, &["crates/agent/src/lib.rs".to_owned()]).len(), 3);
    }
    #[test]
    fn metadata_uses_package_names_for_renamed_path_dependencies() -> Result<(), Box<dyn Error>> {
        let value = serde_json::json!({"workspace_root":"/project","workspace_members":["one","two"],"packages":[{"id":"one","name":"base","manifest_path":"/project/crates/base/Cargo.toml","dependencies":[]},{"id":"two","name":"app","manifest_path":"/project/app/Cargo.toml","dependencies":[{"name":"base","rename":"alias","path":"/project/crates/base","kind":"dev"}]}]});
        let g = graph(&value)?;
        assert_eq!(
            select(&g, &["crates/base/src/lib.rs".to_owned()]),
            BTreeSet::from(["app".to_owned(), "base".to_owned()])
        );
        Ok(())
    }
}
