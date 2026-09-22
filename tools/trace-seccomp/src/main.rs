use flowsdn_trace_seccomp::{coverage, profile, trace};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut baseline = None;
    let mut arch = None;
    let mut caps = None;
    let mut executables = BTreeSet::new();
    let mut traces = Vec::new();
    let mut output = None;
    let mut report = None;
    while let Some(arg) = args.next() {
        let value = args.next().ok_or("every option requires a value")?;
        match arg.as_str() {
            "--baseline" => baseline = Some(PathBuf::from(value)),
            "--arch" => arch = Some(value),
            "--caps" => {
                caps = Some(
                    value
                        .split(',')
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                        .collect::<BTreeSet<_>>(),
                )
            }
            "--exe" => {
                executables.insert(value);
            }
            "--trace" => traces.push(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--report" => report = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown option: {arg}").into()),
        }
    }
    let baseline_path = baseline.ok_or("--baseline required")?;
    let output = output.ok_or("--output required")?;
    let report = report.ok_or("--report required")?;
    if output == report
        || output == baseline_path
        || report == baseline_path
        || traces.contains(&output)
        || traces.contains(&report)
    {
        return Err("input and output paths must differ".into());
    }
    if executables.is_empty() || traces.is_empty() {
        return Err("at least one --exe and --trace required".into());
    }
    let baseline = serde_json::from_slice(&std::fs::read(baseline_path)?)?;
    let arch = arch.ok_or("--arch required")?;
    let caps = caps.ok_or("--caps required (empty value means no capabilities)")?;
    if caps
        .iter()
        .any(|c| !c.starts_with("CAP_") || !c.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
    {
        return Err("invalid capability name".into());
    }
    let generated = profile(&baseline, &arch, &caps)?;
    let mut counts = BTreeMap::<String, u64>::new();
    let mut selected_execs = 0_u64;
    let mut unattributed_calls = 0_u64;
    let mut unattributed_files = 0_u64;
    let mut unique_files = BTreeSet::new();
    for path in traces {
        if !unique_files.insert(std::fs::canonicalize(&path)?) {
            return Err("duplicate trace file".into());
        }
        let parsed = trace(&std::fs::read_to_string(path)?, &executables);
        selected_execs = selected_execs.saturating_add(parsed.selected_execs);
        unattributed_calls = unattributed_calls.saturating_add(parsed.unattributed_calls);
        if parsed.selected_execs == 0 {
            unattributed_files = unattributed_files.saturating_add(1);
        }
        for (name, count) in parsed.counts {
            let total = counts.entry(name).or_default();
            *total = total.saturating_add(count);
        }
    }
    if selected_execs == 0 {
        return Err("no successful selected executable execve found".into());
    }
    let calls: BTreeMap<_, _> = counts
        .into_iter()
        .map(|(name, count)| {
            let status = coverage(&generated, &name);
            (name, json!({"count": count, "coverage": status}))
        })
        .collect();
    let summary = json!({"architecture": arch, "capabilities": caps, "selected_execs": selected_execs,
        "unattributed_calls": unattributed_calls, "unattributed_files": unattributed_files,
        "scope": "successful exact-path execve per PID; no fork/thread inheritance", "syscalls": calls});
    // create_new avoids accidentally overwriting a baseline or trace through a symlink.
    use std::io::Write;
    let mut profile_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut report_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(report)?;
    writeln!(
        profile_file,
        "{}",
        serde_json::to_string_pretty(&generated)?
    )?;
    writeln!(report_file, "{}", serde_json::to_string_pretty(&summary)?)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trace-seccomp: {error}");
        std::process::exit(1);
    }
}
