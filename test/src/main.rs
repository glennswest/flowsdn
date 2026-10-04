//! flowsdn's test container (stormcentral docs/test-standard.md, #303): one
//! image, started as `/test short|medium|long`.
//!
//! Every suite first probes the node's own flowsdn read-only (a skip where the
//! node is not the flowsdn flavor), then runs the datapath of the commit under
//! test (its agent, CNI and BPF objects, staged in the image) inside anonymous
//! namespaces of this privileged pod. That needs a kernel with TCX and BTF;
//! a machine without them reports skip.
mod env;
mod fixtures;
mod lab;
mod node;
mod preflight;
mod report;
mod short;
mod waves;

use preflight::Preflight;
use report::Report;
use std::{process::ExitCode, time::Duration};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "--endpoint" => lab::endpoint_worker(),
        [suite] if ["short", "medium", "long"].contains(&suite.as_str()) => run(suite),
        _ => {
            eprintln!("usage: /test short|medium|long");
            ExitCode::from(2)
        }
    }
}

fn run(suite: &str) -> ExitCode {
    let env = env::Env::from_env(suite);
    let mut report = Report::default();
    node::probe(&mut report, &env);
    match preflight::check(&env) {
        Preflight::Ready(detail) => report.pass("preflight", Duration::ZERO, &detail),
        Preflight::Skip(why) => {
            report.skip("datapath", &why);
            return report.finish();
        }
        Preflight::Infrastructure(why) => {
            report.infrastructure("preflight", &why);
            return report.finish();
        }
    }
    if let Err(e) = lab::isolate_process() {
        report.infrastructure("isolate", &format!("cannot isolate the test's namespaces: {e}"));
        return report.finish();
    }
    match env.suite.as_str() {
        "short" => short::run(&mut report, &env),
        "medium" => {
            short::run(&mut report, &env);
            fixtures::run(&mut report, &env);
        }
        _ => waves::run(&mut report, &env),
    }
    report.finish()
}
