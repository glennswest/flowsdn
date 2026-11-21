//! spec 18 §11.3 (#473): check the harvested corpus against PORTED.toml,
//! fail the build on an inconsistency, and write `$OUT_DIR/ported/<stem>.rs`
//! (the compile-time assertions each `tests/<stem>.rs` includes) and
//! `$OUT_DIR/coverage.txt`.
#[allow(dead_code)]
#[path = "src/corpus.rs"]
mod corpus;

use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest.join("../..");
    let cases_path = root.join("tests/bpf/CASES.toml");
    let ported_path = root.join("tests/bpf/PORTED.toml");
    println!("cargo:rerun-if-changed={}", cases_path.display());
    println!("cargo:rerun-if-changed={}", ported_path.display());
    println!("cargo:rerun-if-changed=src/corpus.rs");
    println!("cargo:rerun-if-changed=tests");
    let tests = manifest.join("tests");
    let corpus = corpus::Corpus::parse(
        &fs::read_to_string(&cases_path)?,
        &fs::read_to_string(&ported_path)?,
        |stem| fs::read_to_string(tests.join(format!("{stem}.rs"))).ok(),
    )
    .map_err(|problems| {
        format!(
            "tests/bpf corpus is inconsistent (spec 18 §9.4):\n{}",
            problems.join("\n")
        )
    })?;
    let out = PathBuf::from(env::var("OUT_DIR")?);
    let ported = out.join("ported");
    fs::create_dir_all(&ported)?;
    for (stem, code) in corpus.generated() {
        fs::write(ported.join(format!("{stem}.rs")), code)?;
    }
    fs::write(out.join("coverage.txt"), corpus.summary())?;
    Ok(())
}
