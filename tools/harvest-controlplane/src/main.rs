//! Restore/verify static historical fixtures against exact pinned Git objects.
//! Does not execute the upstream suite or copy executable reference source.
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};
#[derive(Debug)]
struct Row {
    tag: String,
    commit: String,
    blob: String,
    bytes: usize,
    source: String,
    fixture: String,
}
fn safe(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && (path.ends_with(".yaml") || path.ends_with(".golden"))
}
fn rows(text: &str) -> Result<Vec<Row>, Box<dyn Error>> {
    let mut lines = text.lines();
    if lines.next() != Some("tag\tcommit\tgit_blob\tbytes\tsource\tfixture") {
        return Err("invalid manifest header".into());
    }
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        let [tag, commit, blob, bytes, source, fixture] = fields.as_slice() else {
            return Err("invalid manifest row".into());
        };
        let expected = match *tag {
            "v1.16.0" => "82999990bc954699cf24853ef9747d9166ee24c8",
            "v1.17.0" => "c2bbf787eab9b7f728fcc861904d9bcf17e4ba9b",
            _ => return Err("unapproved source tag".into()),
        };
        if *commit != expected
            || blob.len() != 40
            || !blob.bytes().all(|b| b.is_ascii_hexdigit())
            || !safe(source)
            || !safe(fixture)
            || !source.starts_with("test/controlplane/")
            || !(fixture.starts_with("v1.16.0/") || fixture.starts_with("v1.17.0/"))
            || !seen.insert((tag.to_string(), source.to_string()))
        {
            return Err("invalid/duplicate provenance row".into());
        }
        rows.push(Row {
            tag: (*tag).into(),
            commit: (*commit).into(),
            blob: (*blob).into(),
            bytes: bytes.parse()?,
            source: (*source).into(),
            fixture: (*fixture).into(),
        });
    }
    if rows.is_empty() {
        return Err("empty fixture corpus".into());
    }
    Ok(rows)
}
fn git(reference: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn Error>> {
    let result = Command::new("git")
        .arg("-C")
        .arg(reference)
        .args(args)
        .output()?;
    if !result.status.success() {
        return Err(
            "reference Git object unavailable; fetch pinned tags before verification".into(),
        );
    }
    Ok(result.stdout)
}
fn no_symlink(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        match fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err("symlink output path refused".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn run() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [mode, reference, output] = args.as_slice() else {
        return Err(
            "usage: flowsdn-harvest-controlplane <--check|--restore> REFERENCE_REPO FIXTURE_DIR"
                .into(),
        );
    };
    if !matches!(mode.as_str(), "--check" | "--restore") {
        return Err("unknown mode".into());
    }
    let reference = Path::new(reference);
    let output = Path::new(output);
    no_symlink(output)?;
    let rows = rows(&fs::read_to_string(output.join("MANIFEST.tsv"))?)?;
    let mut unique = BTreeMap::new();
    let mut checked_tags = BTreeSet::new();
    // Validate all source objects before any restore write; no partial recovery
    // is published merely because a later source object is missing.
    for row in &rows {
        if checked_tags.insert(&row.tag) {
            let tag = format!("{}^{{commit}}", row.tag);
            if String::from_utf8(git(reference, &["rev-parse", "--verify", &tag])?)?.trim()
                != row.commit
            {
                return Err("tag moved from pinned commit".into());
            }
        }
        let object = format!("{}:{}", row.commit, row.source);
        if String::from_utf8(git(reference, &["rev-parse", "--verify", &object])?)?.trim()
            != row.blob
        {
            return Err("source blob hash differs from manifest".into());
        }
        let data = git(reference, &["show", &object])?;
        if data.len() != row.bytes {
            return Err("source byte count differs from manifest".into());
        }
        if let Some(previous) = unique.insert(row.fixture.clone(), data.clone())
            && previous != data
        {
            return Err("shared fixture mapping has conflicting bytes".into());
        }
    }
    // Refuse every existing unsafe destination before publishing any fixture.
    // Otherwise a later symlink could be discovered after earlier files changed.
    for fixture in unique.keys() {
        no_symlink(&output.join(fixture))?;
    }
    for (fixture, data) in &unique {
        let target = output.join(fixture);
        if mode == "--check" {
            if fs::read(&target)? != *data {
                return Err(format!("fixture differs: {fixture}").into());
            }
        } else {
            fs::create_dir_all(target.parent().ok_or("fixture parent")?)?;
            fs::write(target, data)?;
        }
    }
    println!(
        "{} {} source records / {} unique static files; runtime adapters not executed",
        if mode == "--check" {
            "Verified"
        } else {
            "Restored"
        },
        rows.len(),
        unique.len()
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_rejects_executables_traversal_and_unapproved_provenance() {
        for path in [
            "../escape.yaml",
            "/tmp/file.yaml",
            "x/test.go",
            "x/generate.sh",
            "",
        ] {
            assert!(!safe(path));
        }
        assert!(safe("v1.17.0/services/nodeport/v1.26/state1.yaml"));
        let header = "tag\tcommit\tgit_blob\tbytes\tsource\tfixture\n";
        assert!(rows(header).is_err());
        assert!(rows(&format!("{header}v1.18.0\tbad\tbad\t0\tx.yaml\tx.yaml\n")).is_err());
    }
}
