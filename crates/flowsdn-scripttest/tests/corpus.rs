//! Parse the real harvested corpus; do not interpret commands or write fixtures.
use flowsdn_scripttest::{Archive, Line, parse_script};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

fn collect(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect(&entry.path(), paths)?;
        } else if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "txtar")
        {
            paths.push(entry.path());
        }
    }
    Ok(())
}

#[test]
fn every_harvested_archive_and_command_parses() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/scripttest/corpus");
    let mut paths = Vec::new();
    collect(&root, &mut paths)?;
    paths.sort();
    assert_eq!(
        paths.len(),
        168,
        "update corpus expectations deliberately when re-harvesting"
    );
    let mut files = 0usize;
    let mut commands = 0usize;
    for path in paths {
        let text = fs::read_to_string(&path)?;
        let archive =
            Archive::parse(&text).map_err(|error| format!("{}:{error}", path.display()))?;
        assert_eq!(
            archive.serialize(),
            text,
            "{} did not round-trip",
            path.display()
        );
        let script = parse_script(archive.script())
            .map_err(|error| format!("{}:{error}", path.display()))?;
        files = files.saturating_add(archive.files().len());
        commands = commands.saturating_add(
            script
                .iter()
                .filter(|line| matches!(line, Line::Command(_)))
                .count(),
        );
    }
    // Independent harvest totals from spec 17: a broken marker parser must not
    // pass by treating the whole archive as a script or dropping embedded data.
    assert_eq!(files, 1444);
    assert!(
        commands > 2000,
        "unexpectedly few corpus commands: {commands}"
    );
    println!(
        "Parsed 168 archives, {files} embedded files and {commands} commands; no commands executed."
    );
    Ok(())
}
