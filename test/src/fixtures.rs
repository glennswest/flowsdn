//! `medium`'s features and failure paths: the repository's privileged kernel
//! fixtures, each in anonymous namespaces of its own, against the BPF objects
//! and executables of the commit under test. Their output goes to
//! `/results/fixture-<name>.log`; a fixture's exit status is its result.
use crate::{env::Env, report::Report};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Longest a single fixture may run before it counts as hung.
const FIXTURE_LIMIT: Duration = Duration::from_secs(300);

/// (test name, fixture binary, arguments) — what each one covers is in
/// `crates/flowsdn-bpftest/README.md`. `socket-context` is left out: the
/// kernel's test-run of connect hooks is unsupported (errno 524 on 6.17), and
/// `socket-live` covers those programs with a real cgroup attachment instead.
/// The load-only kfunc probe is left out: it is destructive if run (#3).
fn fixtures(env: &Env) -> Vec<(&'static str, PathBuf, Vec<PathBuf>)> {
    let delivery = env.bpf("local-delivery");
    vec![
        ("fixture-smoke", env.fixture("flowsdn-bpftest"), vec![env.bpf("smoke")]),
        ("fixture-packet-ingress", env.fixture("packet-ingress"), vec![env.bpf("smoke")]),
        ("fixture-loader-features", env.fixture("loader-features"), vec![env.bpf("loader-features")]),
        ("fixture-uplink-ingress", env.fixture("uplink-ingress"), vec![delivery.clone()]),
        ("fixture-endpoint", env.fixture("flowsdn-endpoint-test"), vec![delivery.clone()]),
        ("fixture-native-routing", env.fixture("native-routing"), vec![delivery.clone()]),
        ("fixture-cni-runtime", env.fixture("cni-runtime"), vec![env.cni(), delivery.clone()]),
        (
            "fixture-agent-runtime",
            env.fixture("agent-runtime"),
            vec![env.cni(), env.agent(), delivery],
        ),
        ("fixture-socket-live", env.fixture("socket-live"), vec![env.bpf("socket-context")]),
    ]
}

pub fn run(report: &mut Report, env: &Env) {
    for (test, binary, args) in fixtures(env) {
        if let Some(absent) = std::iter::once(&binary).chain(&args).find(|p| !p.is_file()) {
            report.fail(test, Duration::ZERO, &format!("image incomplete: {} missing", absent.display()));
            continue;
        }
        let log = env.results.join(format!("{test}.log"));
        report.check(test, || {
            let file = fs::File::create(&log).map_err(|e| format!("{}: {e}", log.display()))?;
            let err = file.try_clone().map_err(|e| e.to_string())?;
            let mut child = Command::new(&binary)
                .args(&args)
                .stdout(file)
                .stderr(err)
                .stdin(Stdio::null())
                .spawn()
                .map_err(|e| format!("{}: {e}", binary.display()))?;
            let start = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    break status;
                }
                if start.elapsed() > FIXTURE_LIMIT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("hung: no result in {} s", FIXTURE_LIMIT.as_secs()));
                }
                thread::sleep(Duration::from_millis(100));
            };
            let output = fs::read_to_string(&log).unwrap_or_default();
            let last = output.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
            let passes = output.lines().filter(|l| l.contains("PASS")).count();
            if status.success() {
                Ok(((), format!("{passes} PASS lines; last: {last}")))
            } else {
                Err(format!("{status}: {last}"))
            }
        });
    }
}
