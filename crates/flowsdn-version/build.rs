mod build_support;
use std::{collections::BTreeMap, env, process::Command};

fn output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    for name in build_support::INPUTS {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-env-changed=RUSTC");
    let mut values: BTreeMap<String, String> = build_support::INPUTS
        .iter()
        .filter_map(|name| {
            build_support::environment_value(name, env::var_os(name))
                .expect("invalid build metadata environment")
                .map(|value| ((*name).into(), value))
        })
        .collect();
    let development = ["FLOWSDN_VERSION", "FLOWSDN_REVISION", "SOURCE_DATE_EPOCH"]
        .iter()
        .any(|name| !values.contains_key(*name));
    if development {
        // Observe Git inputs for fallback builds; no wall-clock timestamp is sampled.
        for name in ["HEAD", "packed-refs", "refs"] {
            if let Some(path) = output("git", &["rev-parse", "--git-path", name]) {
                build_support::clean(&path).expect("Git metadata path contains control characters");
                println!("cargo:rerun-if-changed={path}");
            }
        }
        values
            .entry("FLOWSDN_VERSION".into())
            .or_insert_with(|| env::var("CARGO_PKG_VERSION").expect("Cargo package version"));
        values.entry("FLOWSDN_REVISION".into()).or_insert_with(|| {
            output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into())
        });
        values.entry("SOURCE_DATE_EPOCH".into()).or_insert_with(|| {
            output("git", &["show", "-s", "--format=%ct", "HEAD"]).unwrap_or_else(|| "0".into())
        });
    }
    values.entry("FLOWSDN_RUSTC".into()).or_insert_with(|| {
        output(&env::var("RUSTC").expect("Cargo compiler"), &["--version"])
            .expect("compiler version")
    });
    values.insert("TARGET".into(), env::var("TARGET").expect("Cargo target"));
    let values = build_support::metadata(values, development).expect("invalid build metadata");
    for (name, value) in values {
        println!("cargo:rustc-env={name}={value}");
    }
}
