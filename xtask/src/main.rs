//! Initial Linux build driver. Packaging and BPF commands arrive with their crates.
#[allow(dead_code)]
#[path = "../../crates/flowsdn-bpftest/src/corpus.rs"]
mod cases;
mod changed;
mod chart;
mod cloud;
mod corpus;
mod kernel;

use std::{env, error::Error, path::Path, process::Command};

fn run(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("cargo").args(args).status()?;
    if !status.success() {
        return Err(format!("cargo {} failed: {status}", args.join(" ")).into());
    }
    Ok(())
}

/// `cargo xtask cases --summary` (spec 18 §8.4, #473): the BPF test
/// corpus's coverage, after the §9.4 consistency checks.
fn print_cases() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace")?;
    let tests = root.join("crates/flowsdn-bpftest/tests");
    let corpus = cases::Corpus::parse(
        &std::fs::read_to_string(root.join("tests/bpf/CASES.toml"))?,
        &std::fs::read_to_string(root.join("tests/bpf/PORTED.toml"))?,
        |stem| std::fs::read_to_string(tests.join(format!("{stem}.rs"))).ok(),
    )
    .map_err(|problems| problems.join("\n"))?;
    print!("{}", corpus.summary());
    // The monotonic gate (spec 18 §5.3, #544), as flowsdn-bpftest's build.
    corpus
        .check_record(&std::fs::read_to_string(
            root.join("tests/bpf/COVERAGE.toml"),
        )?)
        .map_err(|problems| problems.join("\n"))?;
    println!("  coverage equals tests/bpf/COVERAGE.toml");
    Ok(())
}

/// The reference the BPF corpus is harvested from (spec 18 §9.4): Cilium
/// v1.20.1. `tools/harvest-bpf-cases` refuses any other checkout.
const REFERENCE_COMMIT: &str = "7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc";
const REFERENCE_URL: &str = "https://github.com/cilium/cilium.git";

/// `cargo xtask reharvest [--fetch]` (spec 18 §9.4, #544): re-run the
/// harvester against the pinned reference and require `tests/bpf/CASES.toml`
/// byte for byte. The reference is `$FLOWSDN_REFERENCE`, else
/// `target/reference/cilium-<commit>`; `--fetch` makes the latter (a shallow,
/// sparse clone of `bpf/tests` at the pinned commit). Without a checkout the
/// check is skipped, saying so.
fn reharvest(fetch: bool) -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace")?;
    let reference = env::var_os("FLOWSDN_REFERENCE").map_or_else(
        || {
            root.join("target/reference").join(format!(
                "cilium-{}",
                REFERENCE_COMMIT.get(..10).unwrap_or("")
            ))
        },
        std::path::PathBuf::from,
    );
    if fetch && !reference.join("bpf/tests").is_dir() {
        fetch_reference(&reference)?;
    }
    if !reference.join("bpf/tests").is_dir() {
        println!(
            "re-harvest skipped: no reference checkout at {} (set FLOWSDN_REFERENCE to a Cilium checkout at {REFERENCE_COMMIT}, or run cargo xtask reharvest --fetch)",
            reference.display()
        );
        return Ok(());
    }
    let reference = reference.to_str().ok_or("reference path is not UTF-8")?;
    let cases = root.join("tests/bpf/CASES.toml");
    let cases = cases.to_str().ok_or("workspace path is not UTF-8")?;
    run(&[
        "run",
        "--locked",
        "--quiet",
        "-p",
        "flowsdn-harvest-bpf-cases",
        "--",
        "--reference",
        reference,
        "--check",
        cases,
    ])
}
/// A shallow, sparse clone of the reference's `bpf/tests` at the pinned
/// commit into `dir`.
fn fetch_reference(dir: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(dir)?;
    let git = |args: &[&str]| -> Result<(), Box<dyn Error>> {
        let status = Command::new("git").arg("-C").arg(dir).args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("git {} failed: {status}", args.join(" ")).into())
        }
    };
    git(&["init", "--quiet"])?;
    git(&["remote", "add", "origin", REFERENCE_URL])?;
    git(&["sparse-checkout", "set", "bpf/tests"])?;
    git(&[
        "fetch",
        "--quiet",
        "--depth",
        "1",
        "--filter=blob:none",
        "origin",
        REFERENCE_COMMIT,
    ])?;
    git(&["checkout", "--quiet", "--detach", "FETCH_HEAD"])?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    if command == "help" || command == "--help" {
        println!(
            "cargo xtask <build|test|check|deny>\ncargo xtask <plan|ci-plan|check-changed> BASE\ncargo xtask audit-corpus [--check]\ncargo xtask cases [--summary]\ncargo xtask reharvest [--fetch]\ncargo xtask chart-check\ncargo xtask cloud-scan\ncargo xtask kernel-check [SUITE]\nRun build tasks on Linux; see README.md."
        );
        return Ok(());
    }
    if command == "chart-check" {
        if args.len() != 1 {
            return Err("expected chart-check".into());
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("workspace")?;
        return chart::run(root);
    }
    if command == "cloud-scan" {
        if args.len() != 1 {
            return Err("expected cloud-scan".into());
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("workspace")?;
        return cloud::scan(root);
    }
    if command == "kernel-check" {
        if args.len() > 2 {
            return Err("expected kernel-check [SUITE]".into());
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("workspace")?;
        let suite = args.get(1).map_or("medium", String::as_str);
        return kernel::run(root, suite);
    }
    if command == "cases" {
        if args.len() > 2 || args.get(1).is_some_and(|s| s != "--summary") {
            return Err("expected cases [--summary]".into());
        }
        return print_cases();
    }
    if command == "reharvest" {
        if args.len() > 2 || args.get(1).is_some_and(|s| s != "--fetch") {
            return Err("expected reharvest [--fetch]".into());
        }
        return reharvest(args.len() == 2);
    }
    if command == "audit-corpus" {
        if args.len() > 2 || args.get(1).is_some_and(|s| s != "--check") {
            return Err("expected audit-corpus [--check]".into());
        }
        env::set_current_dir(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .ok_or("workspace")?,
        )?;
        return corpus::run(args.len() == 2);
    }
    if !((args.len() == 1 && matches!(command, "build" | "test" | "check" | "deny"))
        || (args.len() == 2 && matches!(command, "plan" | "ci-plan" | "check-changed")))
    {
        return Err("expected build/test/check/deny, or plan/check-changed BASE".into());
    }
    if !cfg!(target_os = "linux") {
        return Err("build tasks require Linux".into());
    }
    env::set_current_dir(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("no workspace root")?,
    )?;
    if matches!(command, "plan" | "ci-plan" | "check-changed") {
        if command == "ci-plan" {
            return changed::ci_plan(args.get(1).ok_or("missing base revision")?);
        }
        let packages = changed::plan(args.get(1).ok_or("missing base revision")?)?;
        if command == "plan" {
            println!("{}", serde_json::to_string(&packages)?);
            return Ok(());
        }
        if packages.is_empty() {
            println!("No workspace checks required for this committed diff.");
            return Ok(());
        }
        run(&["fmt", "--all", "--", "--check"])?;
        let musl_packages = changed::musl_packages(Some(&packages))?;
        for (action, target) in [
            ("clippy", None),
            ("test", None),
            ("check", Some("x86_64-unknown-linux-musl")),
            ("check", Some("aarch64-unknown-linux-musl")),
        ] {
            let selected = if target.is_some() {
                &musl_packages
            } else {
                &packages
            };
            if selected.is_empty() {
                continue;
            }
            let mut invocation = vec![
                action.to_owned(),
                "--locked".to_owned(),
                "--all-features".to_owned(),
            ];
            for package in selected {
                invocation.extend(["-p".to_owned(), package.clone()]);
            }
            if action != "test" {
                invocation.push("--all-targets".to_owned());
            }
            if let Some(target) = target {
                invocation.extend(["--target".to_owned(), target.to_owned()]);
            }
            if action == "clippy" {
                invocation.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            }
            run(&invocation.iter().map(String::as_str).collect::<Vec<_>>())?;
        }
        return Ok(());
    }
    match command {
        "build" => run(&["build", "--workspace", "--locked"]),
        "test" => run(&["test", "--workspace", "--all-features", "--locked"]),
        "deny" => run(&["deny", "--locked", "check"]),
        "check" => {
            run(&["fmt", "--all", "--", "--check"])?;
            run(&[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ])?;
            run(&["test", "--workspace", "--all-features", "--locked"])?;
            // The BPF corpus coverage (spec 18 §8.4, #473) and its monotonic
            // gate, and the re-harvest when a reference is at hand (#544).
            print_cases()?;
            reharvest(false)?;
            let packages = changed::musl_packages(None)?;
            for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
                if packages.is_empty() {
                    continue;
                }
                let mut invocation = vec![
                    "check",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--target",
                    target,
                ];
                for package in &packages {
                    invocation.extend(["-p", package.as_str()]);
                }
                run(&invocation)?;
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}
