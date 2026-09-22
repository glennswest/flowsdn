//! Initial Linux build driver. Packaging and BPF commands arrive with their crates.
mod changed;
mod corpus;

use std::{env, error::Error, path::Path, process::Command};

fn run(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("cargo").args(args).status()?;
    if !status.success() {
        return Err(format!("cargo {} failed: {status}", args.join(" ")).into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    if command == "help" || command == "--help" {
        println!(
            "cargo xtask <build|test|check|deny>\ncargo xtask <plan|ci-plan|check-changed> BASE\ncargo xtask audit-corpus [--check]\nRun build tasks on Linux; see README.md."
        );
        return Ok(());
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
        for (action, target) in [
            ("clippy", None),
            ("test", None),
            ("check", Some("x86_64-unknown-linux-musl")),
            ("check", Some("aarch64-unknown-linux-musl")),
        ] {
            let mut invocation = vec![
                action.to_owned(),
                "--locked".to_owned(),
                "--all-features".to_owned(),
            ];
            for package in &packages {
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
            for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
                run(&[
                    "check",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--target",
                    target,
                ])?;
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}
