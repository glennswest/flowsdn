//! flowsdn's network performance suite (#321), run by `/test perf` in the
//! test image, and its worker roles:
//!
//! - `flowsdn-perf run`: the `perf` suite (this pod is the client);
//! - `flowsdn-perf run-scale`: the `perf-scale` ramp (steps of 100 pods);
//! - `flowsdn-perf server`: the RR/stream/accept server a worker pod runs;
//! - `flowsdn-perf sleep`: an idle pod for the network-readiness timing.
mod dns;
mod host;
mod kube;
mod report;
mod stats;
mod suite;
mod wire;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => suite::run(false),
        Some("run-scale") => suite::run(true),
        Some("server") => match wire::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("server: {e}");
                ExitCode::from(1)
            }
        },
        Some("sleep") => loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
        _ => {
            eprintln!("usage: flowsdn-perf run|run-scale|server|sleep");
            ExitCode::from(2)
        }
    }
}
