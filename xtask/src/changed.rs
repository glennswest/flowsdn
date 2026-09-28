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
        if file.starts_with("docs/spec/")
            || file.starts_with("docs/inventory/")
            || file == "Cargo.lock"
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

type Inputs = (BTreeMap<String, Package>, Vec<String>);
fn inputs(base: &str) -> Result<Inputs, Box<dyn Error>> {
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
    Ok((graph(&metadata)?, files))
}

/// Emit a matrix containing transitive consumers and a separate excluded BPF crate.
pub fn plan(base: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let (packages, files) = inputs(base)?;
    Ok(select(&packages, &files).into_iter().collect())
}

/// Classify by resolved package IDs, so aliases and multiple crate versions do
/// not confuse the transitive system-library dependency closure. Metadata must
/// include all features and dependency kinds, matching our all-targets checks.
fn musl_selection(metadata: &Value) -> Result<BTreeMap<String, bool>, Box<dyn Error>> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("missing packages")?;
    let nodes = metadata
        .pointer("/resolve/nodes")
        .and_then(Value::as_array)
        .ok_or("missing resolved dependency graph")?;
    let mut system_tls = BTreeSet::new();
    let mut names = BTreeMap::new();
    for package in packages {
        let id = package
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing package id")?;
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or("missing package name")?;
        names.insert(id, name);
        if matches!(name, "openssl" | "openssl-sys") {
            system_tls.insert(id);
        }
    }
    let mut dependencies = BTreeMap::new();
    for node in nodes {
        let id = node
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing resolved package id")?;
        let deps = node
            .get("dependencies")
            .and_then(Value::as_array)
            .ok_or("missing resolved dependencies")?
            .iter()
            .map(|dependency| dependency.as_str().ok_or("invalid resolved dependency id"))
            .collect::<Result<Vec<_>, _>>()?;
        dependencies.insert(id, deps);
    }
    for (id, deps) in &dependencies {
        if !names.contains_key(id)
            || deps
                .iter()
                .any(|dep| !names.contains_key(dep) || !dependencies.contains_key(dep))
        {
            return Err("incomplete resolved dependency graph".into());
        }
    }
    loop {
        let before = system_tls.len();
        for (id, deps) in &dependencies {
            if deps.iter().any(|dep| system_tls.contains(dep)) {
                system_tls.insert(*id);
            }
        }
        if system_tls.len() == before {
            break;
        }
    }
    metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or("missing workspace members")?
        .iter()
        .map(|member| {
            let id = member.as_str().ok_or("invalid workspace member")?;
            if !dependencies.contains_key(id) {
                return Err("workspace member missing from resolved graph".into());
            }
            let name = names.get(id).ok_or("workspace member missing package")?;
            Ok(((*name).to_owned(), !system_tls.contains(id)))
        })
        .collect()
}

/// System OpenSSL consumers are validated natively. Keep musl compile checks
/// for every other selected workspace package, including future additions.
pub fn musl_packages(selected: Option<&[String]>) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata: Value = serde_json::from_slice(&output(Command::new("cargo").args([
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--all-features",
    ]))?)?;
    let classification = musl_selection(&metadata)?;
    if let Some(selected) = selected {
        for name in selected {
            if !classification.contains_key(name) {
                return Err(format!("selected package missing from metadata: {name}").into());
            }
        }
    }
    let mut eligible = Vec::new();
    for (name, portable) in classification {
        if selected.is_some_and(|selected| !selected.contains(&name)) {
            continue;
        }
        if portable {
            eligible.push(name);
        } else {
            println!("musl: skipping {name}: system OpenSSL dependency; native checks apply");
        }
    }
    println!("musl: selected packages: {}", eligible.join(", "));
    Ok(eligible)
}
fn bpf_changed(files: &[String]) -> bool {
    files.iter().any(|file| {
        file.starts_with("crates/flowsdn-bpf/")
            || file.starts_with("crates/flowsdn-bpf-abi/")
            || file.starts_with(".cargo/")
            || file.starts_with(".github/")
            || matches!(
                file.as_str(),
                "Cargo.toml" | "Cargo.lock" | "rust-toolchain.toml" | "bpf-objects.lock"
            )
            || !(file.starts_with("crates/")
                || file.starts_with("xtask/")
                || file.starts_with("tools/")
                || file.starts_with("docs/")
                || matches!(
                    file.as_str(),
                    "README.md" | "CHANGELOG.md" | "CLAUDE.md" | "AGENTS.md" | "LICENSE" | "NOTICE"
                ))
    })
}
pub fn ci_plan(base: &str) -> Result<(), Box<dyn Error>> {
    let (packages, files) = inputs(base)?;
    let chosen: Vec<_> = select(&packages, &files).into_iter().collect();
    let matrix = serde_json::to_string(&serde_json::json!({"package": chosen}))?;
    let bpf = bpf_changed(&files);
    let outputs = format!(
        "matrix={matrix}\nhas_packages={}\nbpf={bpf}\n",
        !chosen.is_empty()
    );
    print!("{outputs}");
    if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)?
            .write_all(outputs.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resolved_workspace() -> Value {
        // Resolved edges use IDs, not manifest aliases. The external dev helper
        // and optional all-features TLS adapter both lead to system OpenSSL.
        let entries = [
            ("agent-id", "agent", vec!["adapter-v1"]),
            ("adapter-v1", "adapter", vec!["openssl-id"]),
            ("openssl-id", "openssl", vec!["sys-id"]),
            ("sys-id", "openssl-sys", vec![]),
            ("tests-id", "test-tool", vec!["dev-helper-id"]),
            ("dev-helper-id", "dev-helper", vec!["sys-id"]),
            ("portable-id", "portable", vec!["adapter-v2"]),
            ("adapter-v2", "adapter", vec![]),
            ("cycle-a-id", "cycle-a", vec!["cycle-b-id"]),
            ("cycle-b-id", "cycle-b", vec!["cycle-a-id", "sys-id"]),
        ];
        serde_json::json!({
            "workspace_members": ["agent-id", "tests-id", "portable-id", "cycle-a-id"],
            "packages": entries.iter().map(|(id, name, _)| {
                serde_json::json!({"id": id, "name": name})
            }).collect::<Vec<_>>(),
            "resolve": {"nodes": entries.iter().map(|(id, _, dependencies)| {
                serde_json::json!({"id": id, "dependencies": dependencies})
            }).collect::<Vec<_>>()}
        })
    }
    #[test]
    fn musl_selection_tracks_external_dependencies_by_resolved_id() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            musl_selection(&resolved_workspace())?,
            BTreeMap::from([
                ("agent".to_owned(), false),
                ("test-tool".to_owned(), false),
                ("portable".to_owned(), true),
                ("cycle-a".to_owned(), false),
            ])
        );
        Ok(())
    }
    #[test]
    fn musl_selection_fails_closed_on_incomplete_metadata() -> Result<(), Box<dyn Error>> {
        let mut metadata = resolved_workspace();
        *metadata.get_mut("resolve").ok_or("missing fixture resolve")? = Value::Null;
        assert!(musl_selection(&metadata).is_err());
        let mut metadata = resolved_workspace();
        *metadata
            .pointer_mut("/resolve/nodes/0/dependencies")
            .ok_or("missing fixture dependencies")? = serde_json::json!(["missing-id"]);
        assert!(musl_selection(&metadata).is_err());
        let mut metadata = resolved_workspace();
        *metadata
            .get_mut("workspace_members")
            .ok_or("missing fixture members")? = serde_json::json!(["missing-id"]);
        assert!(musl_selection(&metadata).is_err());
        Ok(())
    }
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
    fn bpf_selection_skips_docs_and_userspace_but_tracks_shared_abi() {
        for path in [
            "README.md",
            "docs/spec/02.md",
            "crates/flowsdn-agent/src/main.rs",
        ] {
            assert!(!bpf_changed(&[path.into()]));
        }
        for path in [
            "Cargo.lock",
            "crates/flowsdn-bpf-abi/src/lib.rs",
            "crates/flowsdn-bpf/src/main.rs",
            "tests/bpf/cases.json",
        ] {
            assert!(bpf_changed(&[path.into()]));
        }
    }
    #[test]
    fn documents_and_empty_diff_skip_checks() {
        assert!(chosen(&["docs/guide.md", "README.md"]).is_empty());
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
            "docs/spec/00.md",
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
    #[test]
    fn version_dependencies_patched_to_workspace_are_included() -> Result<(), Box<dyn Error>> {
        let value = serde_json::json!({"workspace_root":"/project","workspace_members":["one","two"],"packages":[{"id":"one","name":"base","manifest_path":"/project/crates/base/Cargo.toml","dependencies":[]},{"id":"two","name":"app","manifest_path":"/project/app/Cargo.toml","dependencies":[{"name":"base","kind":null}]}]});
        let g = graph(&value)?;
        assert_eq!(
            select(&g, &["crates/base/src/lib.rs".to_owned()]),
            BTreeSet::from(["app".to_owned(), "base".to_owned()])
        );
        Ok(())
    }
}
