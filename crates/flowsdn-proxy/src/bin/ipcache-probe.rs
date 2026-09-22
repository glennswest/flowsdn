//! Runs only against an externally supplied, pinned Cilium Envoy binary.
//! No sockets are bound, BPF maps created, or production bootstrap used.
use std::{
    env,
    error::Error,
    process::{Command, ExitCode},
};
const REVISION: &str = "766ccfb37260a43e9d228837aa84ce3faf9f64e7";
const FIXTURES: [(&str, &str, Option<&str>); 4] = [
    (
        "default",
        include_str!("../../tests/fixtures/ipcache/default.json"),
        Some("cilium_ipcache"),
    ),
    (
        "v2",
        include_str!("../../tests/fixtures/ipcache/v2.json"),
        Some("cilium_ipcache_v2"),
    ),
    (
        "sentinel",
        include_str!("../../tests/fixtures/ipcache/sentinel.json"),
        Some("flowsdn_probe_sentinel"),
    ),
    (
        "unknown-field",
        include_str!("../../tests/fixtures/ipcache/unknown-field.json"),
        None,
    ),
];
fn run() -> Result<(), Box<dyn Error>> {
    let binary = env::args_os()
        .nth(1)
        .ok_or("usage: ipcache-probe <pinned-cilium-envoy>")?;
    let version = Command::new(&binary).arg("--version").output()?;
    let version = format!("{}{}", String::from_utf8_lossy(&version.stdout), String::from_utf8_lossy(&version.stderr));
    if !version.contains(REVISION) {
        return Err(format!("wrong Envoy revision: {version}").into());
    }
    println!("revision={REVISION}");
    for (case, json, map) in FIXTURES {
        let output = Command::new(&binary)
            .args([
                "--mode",
                "validate",
                "--log-level",
                "debug",
                "--config-yaml",
                json,
            ])
            .output()?;
        let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        match map {
            Some(map) => {
                if !output.status.success() {
                    return Err(format!("{case} validation failed: {log}").into());
                }
                let expected = format!(
                    "cilium.ipcache: Cannot open ipcache at /flowsdn-ipcache-probe-not-a-bpf-root/tc/globals/{map}"
                );
                if !log.lines().any(|line| line.ends_with(&expected)) {
                    return Err(format!(
                        "{case}: missing exact filter runtime path evidence: {log}"
                    )
                    .into());
                }
                println!("PASS {case}: {expected}");
            }
            None => {
                if output.status.success() || !log.contains("flowsdn_unknown_field") {
                    return Err(format!("unknown-field rejection control failed: {log}").into());
                }
                println!("PASS unknown-field: strict schema rejected unknown input");
            }
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
