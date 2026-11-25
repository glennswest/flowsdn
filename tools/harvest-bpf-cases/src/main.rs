use flowsdn_harvest_bpf_cases::{COMMIT, equivalent, first_difference, harvest, load, render};
use std::{env, error::Error, fs, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let mut reference = None;
    let mut output = None;
    let mut check = None;
    let mut date = "2026-09-07".to_owned();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" {
            println!(
                "flowsdn-harvest-bpf-cases --reference CHECKOUT [--check CASES.toml | --output CASES.toml] [--date YYYY-MM-DD]"
            );
            return Ok(());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {arg}"))?;
        match arg.as_str() {
            "--reference" => reference = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--check" => check = Some(PathBuf::from(value)),
            "--date" => date = value,
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    if output.is_some() && check.is_some() {
        return Err("choose either --check or --output".into());
    }
    let reference = reference.ok_or("--reference is required")?;
    let revision = Command::new("git")
        .arg("-C")
        .arg(&reference)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !revision.status.success() || String::from_utf8_lossy(&revision.stdout).trim() != COMMIT {
        return Err(format!("reference must be checked out at {COMMIT}").into());
    }
    // A dirty reference would undermine the claimed provenance.
    let status = Command::new("git")
        .arg("-C")
        .arg(&reference)
        .args([
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "bpf/tests",
        ])
        .output()?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err("reference bpf/tests must be clean".into());
    }
    let inventory = harvest(&load(&reference.join("bpf/tests"))?, &date)?;
    let contents = render(&inventory)?;
    if let Some(check) = check {
        // Byte for byte (spec 18 §9.4, #544): a hand edit anywhere fails.
        let committed = fs::read_to_string(&check)?;
        if let Some((line, want, have)) = first_difference(&contents, &committed) {
            let same = committed
                .parse::<toml::Table>()
                .is_ok_and(|t| equivalent(inventory.clone(), toml::Value::Table(t)));
            let hint = if same {
                " (the same cases: regenerate it with --output)"
            } else {
                ""
            };
            return Err(format!(
                "{} is not the harvest byte for byte: line {line} is `{have}`, the harvest has `{want}`{hint}",
                check.display()
            )
            .into());
        }
        println!("Inventory matches the harvest byte for byte.");
    } else if let Some(output) = output {
        fs::write(output, contents)?;
    } else {
        print!("{contents}");
    }
    Ok(())
}
