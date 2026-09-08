//! Initial Linux build driver. Packaging and BPF commands arrive with their crates.
use std::{env, error::Error, path::Path, process::Command};

fn run(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("cargo")
        .args(args)
        .env("CARGO_TARGET_DIR", "/build/cargo/flowsdn")
        .env("TMPDIR", "/build/tmp")
        .status()?;
    if !status.success() {
        return Err(format!("cargo {} failed: {status}", args.join(" ")).into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    if command == "help" || command == "--help" {
        println!("cargo xtask <build|test|check|deny>\nRun on dev.g8.lo; see README.md.");
        return Ok(());
    }
    if args.len() != 1 || !matches!(command, "build" | "test" | "check" | "deny") {
        return Err("expected one command: build, test, check, deny".into());
    }
    if !cfg!(target_os = "linux") {
        return Err("builds run on dev.g8.lo; see README.md for SSH bootstrap".into());
    }
    if !Path::new("/build/tmp").is_dir() {
        return Err("/build/tmp must exist on the Linux build host".into());
    }
    env::set_current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().ok_or("no workspace root")?)?;
    match command {
        "build" => run(&["build", "--workspace", "--locked"]),
        "test" => run(&["test", "--workspace", "--locked"]),
        "deny" => run(&["deny", "--locked", "check"]),
        "check" => {
            run(&["fmt", "--all", "--", "--check"])?;
            run(&["clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"])?;
            run(&["test", "--workspace", "--locked"])?;
            for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
                run(&["check", "--workspace", "--all-targets", "--locked", "--target", target])?;
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}
